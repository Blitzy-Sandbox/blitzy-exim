// =============================================================================
// exim-lookups/src/nmh.rs — NMH Datagram Protocol Lookup (Pure Rust)
// =============================================================================
//
// Replaces: src/src/lookups/nmh.c (377 lines)
//
// The NMH (Name Helper) lookup module communicates with an external NMH server
// via connectionless datagrams over either UNIX domain sockets (default) or UDP
// sockets. It supports add/sub/ask modes, partial matching, configurable tables,
// and per-query timeouts.
//
// C-to-Rust transformation summary:
//   - Static linked-list connection cache → HashMap<ConnectionKey, NmhSocket>
//     behind a Mutex for interior mutability (LookupDriver takes &self)
//   - mk_unix_sock() / mk_udp_sock() → create_bound_unix_datagram() /
//     make_udp_socket() using std::os::unix::net::UnixDatagram and
//     std::net::UdpSocket
//   - Abstract UNIX sockets (Linux @-prefix) supported via
//     std::os::linux::net::SocketAddrExt (stabilized Rust 1.70)
//   - poll_one_fd() timeout → socket set_read_timeout()
//   - DEBUG(D_lookup) → tracing::debug!()
//   - log_write() → tracing::warn!()
//   - nmh_lookup_info + LOOKUP_MODULE_INFO_MAGIC → inventory::submit!
//
// Per AAP §0.7.2: This file contains ZERO `unsafe` code.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::UdpSocket;
use std::os::unix::net::UnixDatagram;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;

// =============================================================================
// Constants — replaces C #define MODE_ADD/MODE_SUB/MODE_ASK
// =============================================================================

/// NMH "add" mode — request the server to add a key to the table.
const MODE_ADD: u8 = b'+';

/// NMH "subtract" mode — request the server to remove a key from the table.
const MODE_SUB: u8 = b'-';

/// NMH "ask" mode (default) — query whether a key exists in the table.
const MODE_ASK: u8 = b'?';

/// Default read timeout in seconds for datagram responses.
/// Matches C default: `int read_timeout = 5;` (nmh.c line 205).
const DEFAULT_TIMEOUT_SECS: u64 = 5;

// =============================================================================
// Connection Cache Key
// =============================================================================

/// Key identifying a unique NMH server connection in the cache.
///
/// Replaces the C `nmh_connection` linked-list node fields (proto, server, port)
/// that were used for connection cache lookup (nmh.c lines 38-44, 250-254).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ConnectionKey {
    /// Protocol type: "unix" or "udp".
    proto: String,
    /// Server address (UNIX socket path, abstract name, or hostname/IP).
    server: String,
    /// Port number for UDP (-1 for UNIX domain sockets).
    port: i32,
}

// =============================================================================
// NMH Socket Wrapper
// =============================================================================

/// Wrapper around the two supported socket types for NMH communication.
///
/// Replaces the C `int socket` field in `nmh_connection` struct (nmh.c line 43).
/// The enum unifies UNIX datagram sockets (default protocol) and UDP datagram
/// sockets (when protocol=udp or port= is specified) behind a common interface
/// for send/recv/timeout operations.
enum NmhSocket {
    /// UNIX domain datagram socket (protocol "unix", the default).
    Unix {
        /// The datagram socket connected to the NMH server.
        socket: UnixDatagram,
        /// Local socket file path for cleanup on drop (non-Linux only).
        /// On Linux, abstract sockets are used and this is always `None`.
        local_path: Option<String>,
    },
    /// UDP datagram socket (protocol "udp" or when port= is specified).
    Udp(UdpSocket),
}

impl NmhSocket {
    /// Send a datagram to the connected NMH server.
    ///
    /// Replaces C: `write(sock, s, gstring_length(g))` (nmh.c line 283).
    fn send(&self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Unix { socket, .. } => socket.send(buf),
            Self::Udp(s) => s.send(buf),
        }
    }

    /// Receive a datagram from the connected NMH server.
    ///
    /// Replaces C: `read(sock, resp, 1)` (nmh.c line 298).
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Unix { socket, .. } => socket.recv(buf),
            Self::Udp(s) => s.recv(buf),
        }
    }

    /// Set the read timeout for the socket.
    ///
    /// Replaces C: `poll_one_fd(sock, POLLIN, read_timeout * 1000)` (nmh.c line 292).
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Unix { socket, .. } => socket.set_read_timeout(dur),
            Self::Udp(s) => s.set_read_timeout(dur),
        }
    }
}

impl fmt::Debug for NmhSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unix { local_path, .. } => f
                .debug_struct("NmhSocket::Unix")
                .field("local_path", local_path)
                .finish(),
            Self::Udp(_) => f.debug_struct("NmhSocket::Udp").finish(),
        }
    }
}

impl Drop for NmhSocket {
    fn drop(&mut self) {
        // Clean up UNIX socket file on non-Linux platforms where filesystem
        // paths are used instead of abstract sockets.
        if let NmhSocket::Unix {
            local_path: Some(path),
            ..
        } = self
        {
            let _ = std::fs::remove_file(path);
        }
    }
}

// =============================================================================
// Platform-Specific UNIX Socket Helpers
// =============================================================================

/// Create a bound UNIX datagram socket with a unique abstract (Linux) or
/// filesystem-path (other UNIX) local address.
///
/// Replaces C: `mk_unix_sock()` local binding (nmh.c lines 53-76).
/// On Linux, uses abstract sockets (no filesystem cleanup needed).
/// On other platforms, uses `/tmp/.exim-nmh-<pid>-<id>` filesystem paths.
fn create_bound_unix_datagram(
    local_id: u64,
) -> Result<(UnixDatagram, Option<String>), DriverError> {
    let pid = std::process::id();
    create_bound_unix_datagram_platform(pid, local_id)
}

/// Linux implementation: bind to an abstract UNIX socket name.
///
/// Abstract sockets (prefixed with a null byte in the kernel) do not create
/// filesystem entries and are automatically cleaned up when all references
/// are closed. This matches the C behavior: `s_un.sun_path[0] = '\0';`
/// followed by `snprintf(s_un.sun_path+1, ..., "exim-nmh-%lx", pid)`.
#[cfg(target_os = "linux")]
fn create_bound_unix_datagram_platform(
    pid: u32,
    local_id: u64,
) -> Result<(UnixDatagram, Option<String>), DriverError> {
    use std::os::linux::net::SocketAddrExt;

    let name = format!("exim-nmh-{pid:x}-{local_id}");
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())
        .map_err(|e| DriverError::TempFail(format!("local abstract socket address: {e}")))?;
    let sock = UnixDatagram::bind_addr(&addr)
        .map_err(|e| DriverError::TempFail(format!("bind local socket: {e}")))?;
    // Abstract sockets have no filesystem path to clean up
    Ok((sock, None))
}

/// Non-Linux implementation: bind to a filesystem-path UNIX socket.
///
/// Creates a temporary socket file that must be cleaned up when the socket
/// is closed. The `NmhSocket::Drop` implementation handles cleanup.
#[cfg(not(target_os = "linux"))]
fn create_bound_unix_datagram_platform(
    pid: u32,
    local_id: u64,
) -> Result<(UnixDatagram, Option<String>), DriverError> {
    let path = format!("/tmp/.exim-nmh-{pid:x}-{local_id}");
    // Remove any stale socket file from a previous run
    let _ = std::fs::remove_file(&path);
    let sock = UnixDatagram::bind(&path)
        .map_err(|e| DriverError::TempFail(format!("bind '{path}': {e}")))?;
    Ok((sock, Some(path)))
}

/// Connect a UNIX datagram socket to the NMH server address.
///
/// Replaces C: `connect(fd, ...)` in mk_unix_sock() (nmh.c lines 88-111).
///
/// Handles two address formats:
///   - `@name` → abstract UNIX socket (Linux only; the `@` prefix is Exim
///     syntax for abstract names, translated to a null-byte prefix)
///   - `/path/to/socket` → filesystem-path UNIX socket
fn connect_unix_datagram_to_server(sock: &UnixDatagram, server: &str) -> Result<(), DriverError> {
    #[cfg(target_os = "linux")]
    if let Some(abstract_name) = server.strip_prefix('@') {
        use std::os::linux::net::SocketAddrExt;

        let addr = std::os::unix::net::SocketAddr::from_abstract_name(abstract_name.as_bytes())
            .map_err(|e| {
                DriverError::TempFail(format!("server abstract address '{server}': {e}"))
            })?;
        return sock.connect_addr(&addr).map_err(|e| {
            tracing::warn!(server = server, error = %e, "nmh lookup: connect failed");
            DriverError::TempFail(format!("connect '{server}': {e}"))
        });
    }

    sock.connect(server).map_err(|e| {
        tracing::warn!(server = server, error = %e, "nmh lookup: connect failed");
        DriverError::TempFail(format!("connect '{server}': {e}"))
    })
}

// =============================================================================
// NmhLookup — Main Driver Struct
// =============================================================================

/// NMH datagram protocol lookup driver.
///
/// Replaces the C `nmh_lookup_info` registration struct and all associated
/// functions (nmh_open, nmh_find, nmh_tidy, nmh_version_report) from
/// `src/src/lookups/nmh.c`.
///
/// The NMH protocol is a simple datagram-based key-value lookup. The client
/// sends a query datagram containing a table name, operation mode, and key.
/// The server responds with a single byte: `'0'` (not found), `'1'` (partial
/// match), or `'2'` (full match).
///
/// # Connection Caching
///
/// Connected sockets are cached in a `HashMap` keyed by (protocol, server, port)
/// and reused across lookups within the same process. This replaces the C static
/// linked-list `nmh_connections` (nmh.c lines 38-46).
///
/// # Supported Protocols
///
/// - `unix` (default) — UNIX domain datagram sockets
/// - `udp` — UDP datagram sockets (enabled when `port=` option is specified)
/// - `tcp` — reserved but not yet supported (returns an error)
pub struct NmhLookup {
    /// Cached socket connections, keyed by (protocol, server, port).
    /// Replaces C: `static nmh_connection * nmh_connections = NULL;`
    connections: Mutex<HashMap<ConnectionKey, NmhSocket>>,

    /// Monotonic counter for generating unique local socket names.
    /// Each UNIX domain socket gets a unique abstract/filesystem name
    /// to prevent address conflicts between concurrent lookups.
    next_local_id: AtomicU64,
}

impl fmt::Debug for NmhLookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NmhLookup").field("driver", &"nmh").finish()
    }
}

impl Default for NmhLookup {
    fn default() -> Self {
        Self::new()
    }
}

impl NmhLookup {
    /// Create a new NMH lookup driver instance with an empty connection cache.
    pub fn new() -> Self {
        Self {
            connections: Mutex::new(HashMap::new()),
            next_local_id: AtomicU64::new(0),
        }
    }

    /// Create a socket of the requested protocol type and connect it to the
    /// NMH server.
    ///
    /// Replaces C: `mk_sock()` (nmh.c lines 152-161) which dispatches to
    /// `mk_unix_sock()`, `mk_udp_sock()`, or `mk_tcp_sock()`.
    fn make_socket(&self, proto: &str, server: &str, port: i32) -> Result<NmhSocket, DriverError> {
        match proto {
            "unix" => self.make_unix_socket(server),
            "udp" => Self::make_udp_socket(server, port),
            "tcp" => Err(DriverError::TempFail(
                "tcp is not supported for nmh at this time".into(),
            )),
            _ => Err(DriverError::TempFail("bad protocol name".into())),
        }
    }

    /// Create a UNIX domain datagram socket connected to the NMH server.
    ///
    /// Replaces C: `mk_unix_sock()` (nmh.c lines 53-113).
    fn make_unix_socket(&self, server: &str) -> Result<NmhSocket, DriverError> {
        let local_id = self.next_local_id.fetch_add(1, Ordering::Relaxed);
        let (sock, local_path) = create_bound_unix_datagram(local_id)?;
        connect_unix_datagram_to_server(&sock, server)?;

        tracing::debug!(proto = "unix", server = server, "NMH UNIX socket connected");

        Ok(NmhSocket::Unix {
            socket: sock,
            local_path,
        })
    }

    /// Create a UDP datagram socket connected to the NMH server.
    ///
    /// Replaces C: `mk_udp_sock()` (nmh.c lines 115-129).
    fn make_udp_socket(server: &str, port: i32) -> Result<NmhSocket, DriverError> {
        if port <= 0 {
            return Err(DriverError::TempFail("bad port number".into()));
        }

        let server_addr = format!("{server}:{port}");

        // Choose the appropriate bind address based on the server address format.
        // IPv6 addresses contain colons; bind to [::]:0 for IPv6, 0.0.0.0:0 for IPv4.
        let bind_addr = if server.contains(':') {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };

        let sock = UdpSocket::bind(bind_addr)
            .map_err(|e| DriverError::TempFail(format!("bind UDP socket: {e}")))?;

        sock.connect(&server_addr).map_err(|e| {
            tracing::warn!(
                server = server,
                port = port,
                error = %e,
                "nmh lookup: UDP connect failed"
            );
            DriverError::TempFail(format!("connect '{server}:{port}': {e}"))
        })?;

        tracing::debug!(
            proto = "udp",
            server = server,
            port = port,
            "NMH UDP socket connected"
        );

        Ok(NmhSocket::Udp(sock))
    }
}

// =============================================================================
// LookupDriver Trait Implementation
// =============================================================================

impl LookupDriver for NmhLookup {
    /// Open entry point — returns a dummy handle.
    ///
    /// Replaces C: `nmh_open()` (nmh.c lines 176-180).
    ///
    /// The NMH lookup defers actual connection establishment to `find()` because
    /// the connection options (protocol, port, etc.) are only available at find
    /// time, not at open time. This is consistent with how query-style lookups
    /// operate in Exim — the open call is a no-op that returns a dummy handle.
    fn open(&self, _filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        // Return a dummy handle (unit type), matching C: `return (void *)(1);`
        Ok(Box::new(()))
    }

    /// Check entry point — always returns true (no check in C implementation).
    ///
    /// The C `nmh_lookup_info` struct sets `.check = NULL` (nmh.c line 363),
    /// meaning no file/permission checking is performed. We preserve this by
    /// unconditionally returning `Ok(true)`.
    fn check(
        &self,
        _handle: &LookupHandle,
        _filename: Option<&str>,
        _modemask: i32,
        _owners: &[u32],
        _owngroups: &[u32],
    ) -> Result<bool, DriverError> {
        Ok(true)
    }

    /// Find entry point — the core NMH lookup operation.
    ///
    /// Replaces C: `nmh_find()` (nmh.c lines 199-315).
    ///
    /// # Protocol
    ///
    /// 1. Parse comma-separated options to determine protocol, mode, table, etc.
    /// 2. Establish or reuse a cached datagram socket to the NMH server.
    /// 3. Send a query datagram: `table\0mode_char keystring`
    /// 4. Receive a single-byte response:
    ///    - `'0'` → not found
    ///    - `'1'` → partial match (returned as Found only if `partial` option set)
    ///    - `'2'` → full match
    ///
    /// # Parameters
    ///
    /// - `handle`: Dummy handle from `open()` (ignored).
    /// - `filename`: The NMH server address. For UNIX sockets, this is the
    ///   socket path (or `@name` for abstract). For UDP, this is the hostname.
    /// - `key_or_query`: The key to look up in the NMH server.
    /// - `options`: Comma-separated option list: `unix`, `udp`, `tcp`, `add`,
    ///   `sub`, `partial`, `table=NAME`, `tmo=SECONDS`, `port=NUMBER`.
    fn find(
        &self,
        _handle: &LookupHandle,
        filename: Option<&str>,
        key_or_query: &str,
        options: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        let server = filename.ok_or_else(|| {
            DriverError::ExecutionFailed(
                "nmh lookup requires a server address (filename parameter)".into(),
            )
        })?;

        // -----------------------------------------------------------------
        // Parse options — replaces C nmh_find() lines 215-246
        // -----------------------------------------------------------------
        let mut proto = "unix".to_string();
        let mut mode: u8 = MODE_ASK;
        let mut partial = false;
        let mut table = "default".to_string();
        let mut read_timeout: u64 = DEFAULT_TIMEOUT_SECS;
        let mut port: i32 = -1;
        let mut disable_cache = false;

        if let Some(opts) = options {
            for opt in opts.split(',') {
                let opt = opt.trim();
                if opt.is_empty() {
                    continue;
                }
                match opt {
                    "unix" | "udp" | "tcp" => {
                        proto = opt.to_string();
                    }
                    "add" => {
                        mode = MODE_ADD;
                        disable_cache = true;
                    }
                    "sub" => {
                        mode = MODE_SUB;
                        disable_cache = true;
                    }
                    "partial" => {
                        partial = true;
                    }
                    _ if opt.starts_with("table=") => {
                        table = opt[6..].to_string();
                    }
                    _ if opt.starts_with("tmo=") => {
                        let tmo_str = &opt[4..];
                        let tmo_val: u64 = tmo_str.parse().map_err(|_| {
                            DriverError::TempFail("missing value in timeout spec".into())
                        })?;
                        if tmo_val == 0 {
                            return Err(DriverError::TempFail(
                                "missing value in timeout spec".into(),
                            ));
                        }
                        read_timeout = tmo_val;
                    }
                    _ if opt.starts_with("port=") => {
                        let port_str = &opt[5..];
                        let port_val: i32 = port_str.parse().map_err(|_| {
                            DriverError::TempFail("missing port in server spec".into())
                        })?;
                        if port_val <= 0 {
                            return Err(DriverError::TempFail(
                                "missing port in server spec".into(),
                            ));
                        }
                        port = port_val;
                        proto = "udp".to_string();
                    }
                    _ => {
                        // Unknown options are silently ignored, matching C behavior
                        // where the string_nextinlist loop skips unrecognized entries.
                    }
                }
            }
        }

        tracing::debug!(
            proto = proto.as_str(),
            server = server,
            port = port,
            table = table.as_str(),
            mode = ?char::from(mode),
            partial = partial,
            timeout = read_timeout,
            "nmh lookup: options parsed"
        );

        // TCP protocol is reserved but not yet implemented, matching C behavior
        // (nmh.c lines 134-149: mk_tcp_sock returns "tcp is not supported").
        if proto == "tcp" {
            return Err(DriverError::TempFail(
                "tcp is not supported for nmh at this time".into(),
            ));
        }

        // -----------------------------------------------------------------
        // Connection cache lookup / creation — replaces C lines 248-272
        // -----------------------------------------------------------------
        let key = ConnectionKey {
            proto: proto.clone(),
            server: server.to_string(),
            port,
        };

        let mut connections = self.connections.lock().unwrap_or_else(|e| e.into_inner());

        // Check for a cached connection matching (proto, server, port)
        if connections.get(&key).is_none() {
            // No cached connection; create a new one
            let socket = self.make_socket(&proto, server, port)?;
            connections.insert(key.clone(), socket);
        } else {
            tracing::debug!("cached socket");
        }

        let socket = connections.get(&key).ok_or_else(|| {
            DriverError::ExecutionFailed("internal error: cached socket missing".into())
        })?;

        // -----------------------------------------------------------------
        // Set read timeout — replaces C poll_one_fd() (nmh.c line 292)
        // -----------------------------------------------------------------
        socket
            .set_read_timeout(Some(Duration::from_secs(read_timeout)))
            .map_err(|e| DriverError::ExecutionFailed(format!("set_read_timeout: {e}")))?;

        // -----------------------------------------------------------------
        // Build query datagram — replaces C lines 276-278
        //
        // Format: `table\0mode_char keystring`
        //   - table: the NMH table name (default: "default")
        //   - \0: null byte separator
        //   - mode_char: '+' (add), '-' (sub), or '?' (ask)
        //   - keystring: the lookup key
        // -----------------------------------------------------------------
        let mut payload = Vec::with_capacity(table.len() + 1 + 1 + key_or_query.len());
        payload.extend_from_slice(table.as_bytes());
        payload.push(0); // null separator between table name and mode+key
        payload.push(mode);
        payload.extend_from_slice(key_or_query.as_bytes());

        tracing::debug!(
            table = table.as_str(),
            mode = ?char::from(mode),
            key = key_or_query,
            payload_len = payload.len(),
            "nmh send"
        );

        // -----------------------------------------------------------------
        // Send query datagram — replaces C lines 283-288
        // -----------------------------------------------------------------
        let sent = socket
            .send(&payload)
            .map_err(|e| DriverError::ExecutionFailed(format!("error in write: {e}")))?;
        if sent != payload.len() {
            return Err(DriverError::ExecutionFailed("error in write".into()));
        }

        // -----------------------------------------------------------------
        // Read and interpret response — replaces C lines 290-314
        //
        // The NMH server responds with a single byte:
        //   '0' → no match (key not in table)
        //   '1' → partial match (key is a prefix of an entry)
        //   '2' → full match (key found in table)
        //   anything else → protocol error
        // -----------------------------------------------------------------
        let mut resp = [0u8; 1];
        match socket.recv(&mut resp) {
            Ok(1) => { /* success — continue to interpret */ }
            Ok(n) => {
                return Err(DriverError::ExecutionFailed(format!(
                    "error in read: expected 1 byte, got {n}"
                )));
            }
            Err(e)
                if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock =>
            {
                tracing::warn!(server = server, "Timeout on nmh lookup");
                return Err(DriverError::TempFail("read timed out".into()));
            }
            Err(e) => {
                return Err(DriverError::ExecutionFailed(format!("error in read: {e}")));
            }
        }

        tracing::debug!(response = ?char::from(resp[0]), "nmh recv");

        // Determine cache TTL based on mode:
        // - add/sub operations disable caching (C: `*do_cache = 0`)
        // - ask operations use default caching (C: do_cache unchanged)
        let cache_ttl = if disable_cache { Some(0) } else { None };

        match resp[0] {
            b'0' => {
                // No match — C: `*result = NULL` (nmh.c line 309)
                Ok(LookupResult::NotFound)
            }
            b'1' => {
                // Partial match — conditional on `partial` option
                // C: `*result = partial ? US"yes" : NULL` (nmh.c line 310)
                if partial {
                    Ok(LookupResult::Found {
                        value: "yes".to_string(),
                        cache_ttl,
                    })
                } else {
                    Ok(LookupResult::NotFound)
                }
            }
            b'2' => {
                // Full match — C: `*result = US"yes"` (nmh.c line 311)
                Ok(LookupResult::Found {
                    value: "yes".to_string(),
                    cache_ttl,
                })
            }
            _ => {
                // Protocol error — C: `return DEFER` (nmh.c line 312)
                Err(DriverError::TempFail("bad response value".into()))
            }
        }
    }

    /// Close entry point — no-op for NMH.
    ///
    /// The C `nmh_lookup_info` struct sets `.close = NULL` (nmh.c line 364).
    /// NMH connections are managed via the internal cache, not via handles.
    /// Use `tidy()` to close all cached connections.
    fn close(&self, _handle: LookupHandle) {
        // Handle is dropped here; NMH connections live in the cache.
    }

    /// Tidy entry point — close all cached NMH connections.
    ///
    /// Replaces C: `nmh_tidy()` (nmh.c lines 324-334).
    ///
    /// Iterates over all cached connections, logs each closure, and drops
    /// the socket objects (which closes the underlying file descriptors).
    fn tidy(&self) {
        let mut connections = self.connections.lock().unwrap_or_else(|e| e.into_inner());

        // Drain all entries, logging each connection closure.
        // Replaces C while-loop: `while ((cn = nmh_connections)) { ... close(cn->socket); }`
        for (key, _socket) in connections.drain() {
            tracing::debug!(
                server = key.server.as_str(),
                proto = key.proto.as_str(),
                port = key.port,
                "close NMH connection"
            );
            // Socket is dropped here, closing the file descriptor.
        }

        // Defensive: ensure map is fully cleared after drain
        connections.clear();
    }

    /// Quote entry point — no quoting for NMH.
    ///
    /// The C `nmh_lookup_info` struct sets `.quote = NULL` (nmh.c line 366).
    /// NMH does not require any quoting of lookup keys.
    fn quote(&self, _value: &str, _additional: Option<&str>) -> Option<String> {
        None
    }

    /// Version reporting entry point.
    ///
    /// Replaces C: `nmh_version_report()` (nmh.c lines 347-355).
    /// Reports the NMH module version (matching the crate version).
    fn version_report(&self) -> Option<String> {
        Some(format!(
            "Library version: NMH: Exim version {}",
            env!("CARGO_PKG_VERSION")
        ))
    }

    /// Lookup type — absolute file (the "filename" parameter is the server address).
    ///
    /// Replaces C: `.type = lookup_absfile` (nmh.c line 360).
    ///
    /// The `ABS_FILE` flag indicates that the `filename` parameter (the first
    /// positional argument to the lookup) is interpreted as a server address
    /// rather than a file path.
    fn lookup_type(&self) -> LookupType {
        LookupType::ABS_FILE
    }

    /// Driver name used in configuration files and diagnostics.
    ///
    /// Replaces C: `.name = US"nmh"` (nmh.c line 359).
    fn driver_name(&self) -> &str {
        "nmh"
    }
}

// =============================================================================
// Driver Registration
// =============================================================================

/// Factory function for creating NmhLookup instances.
///
/// Used by the `inventory::submit!` registration to provide a factory
/// that the driver registry calls to instantiate the NMH lookup driver.
fn create_nmh_driver() -> Box<dyn LookupDriver> {
    Box::new(NmhLookup::new())
}

// Compile-time registration of the NMH lookup driver.
//
// Replaces C: `nmh_lookup_info` struct + `_lookup_list` array +
// `nmh_lookup_module_info` (nmh.c lines 358-375) and the
// `LOOKUP_MODULE_INFO_MAGIC` validation pattern from `lookupapi.h`.
//
// The `inventory` crate collects all `submit!` entries at link time,
// enabling `DriverRegistry::find_lookup("nmh")` to discover this driver
// at runtime without requiring explicit registration calls.
inventory::submit! {
    LookupDriverFactory {
        name: "nmh",
        create: create_nmh_driver,
        lookup_type: LookupType::ABS_FILE,
        avail_string: Some("nmh (NMH datagram protocol)"),
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nmh_lookup_new() {
        let lookup = NmhLookup::new();
        assert_eq!(lookup.driver_name(), "nmh");
        assert_eq!(lookup.lookup_type(), LookupType::ABS_FILE);
    }

    #[test]
    fn test_nmh_lookup_open_returns_handle() {
        let lookup = NmhLookup::new();
        let handle = lookup.open(None);
        assert!(handle.is_ok());
    }

    #[test]
    fn test_nmh_lookup_check_always_true() {
        let lookup = NmhLookup::new();
        let handle = lookup.open(None).unwrap();
        let result = lookup.check(&handle, None, 0, &[], &[]);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_nmh_lookup_close_no_panic() {
        let lookup = NmhLookup::new();
        let handle = lookup.open(None).unwrap();
        lookup.close(handle);
        // Should not panic
    }

    #[test]
    fn test_nmh_lookup_tidy_empty_cache() {
        let lookup = NmhLookup::new();
        lookup.tidy();
        // Should not panic on empty cache
    }

    #[test]
    fn test_nmh_lookup_quote_returns_none() {
        let lookup = NmhLookup::new();
        assert!(lookup.quote("test", None).is_none());
        assert!(lookup.quote("test", Some("extra")).is_none());
    }

    #[test]
    fn test_nmh_lookup_version_report() {
        let lookup = NmhLookup::new();
        let report = lookup.version_report();
        assert!(report.is_some());
        let report_str = report.unwrap();
        assert!(report_str.starts_with("Library version: NMH:"));
    }

    #[test]
    fn test_nmh_lookup_type() {
        let lookup = NmhLookup::new();
        let lt = lookup.lookup_type();
        assert!(lt.is_abs_file());
        assert!(lt.is_single_key());
        assert!(!lt.is_query_style());
    }

    #[test]
    fn test_nmh_find_requires_server() {
        let lookup = NmhLookup::new();
        let handle = lookup.open(None).unwrap();
        // filename=None should fail — server address is required
        let result = lookup.find(&handle, None, "testkey", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_nmh_find_tcp_unsupported() {
        let lookup = NmhLookup::new();
        let handle = lookup.open(None).unwrap();
        let result = lookup.find(&handle, Some("/tmp/nmh-test"), "testkey", Some("tcp"));
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("tcp is not supported"));
    }

    #[test]
    fn test_nmh_find_bad_timeout() {
        let lookup = NmhLookup::new();
        let handle = lookup.open(None).unwrap();
        let result = lookup.find(&handle, Some("/tmp/nmh-test"), "testkey", Some("tmo=0"));
        assert!(result.is_err());
    }

    #[test]
    fn test_nmh_find_bad_port() {
        let lookup = NmhLookup::new();
        let handle = lookup.open(None).unwrap();
        let result = lookup.find(&handle, Some("localhost"), "testkey", Some("port=0"));
        assert!(result.is_err());
    }

    #[test]
    fn test_connection_key_equality() {
        let k1 = ConnectionKey {
            proto: "unix".to_string(),
            server: "/tmp/test.sock".to_string(),
            port: -1,
        };
        let k2 = ConnectionKey {
            proto: "unix".to_string(),
            server: "/tmp/test.sock".to_string(),
            port: -1,
        };
        let k3 = ConnectionKey {
            proto: "udp".to_string(),
            server: "localhost".to_string(),
            port: 8080,
        };
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
    }

    #[test]
    fn test_nmh_debug_impl() {
        let lookup = NmhLookup::new();
        let debug_str = format!("{:?}", lookup);
        assert!(debug_str.contains("NmhLookup"));
        assert!(debug_str.contains("nmh"));
    }
}
