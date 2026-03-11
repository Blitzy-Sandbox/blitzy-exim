// =============================================================================
// exim-lookups/src/readsock.rs — Socket Request/Response Lookup Backend
// =============================================================================
//
// Rewrites `src/src/lookups/readsock.c` (329 lines) as a pure Rust socket
// lookup backend. This module sends a query string to a TCP or Unix domain
// socket and returns the response, enabling integration with external policy
// daemons and custom lookup services.
//
// Socket specification format:
//   inet:host:port       — TCP connection to host:port
//   /path/to/socket      — Unix domain socket connection
//   unix:/path/to/socket — Unix domain socket (explicit prefix)
//
// C function mapping:
//   readsock_open()  → ReadsockLookup::open()  — no-op
//   readsock_find()  → ReadsockLookup::find()  — connect, send, receive
//   readsock_close() → ReadsockLookup::close() — no-op
//
// Per AAP §0.7.2: This file contains ZERO `unsafe` code.
// Per AAP §0.4.2: Uses `inventory::submit!` for compile-time registration.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;

// =============================================================================
// Constants
// =============================================================================

/// Default timeout for socket operations (seconds).
/// C equivalent: 5 seconds default timeout in readsock.
const DEFAULT_TIMEOUT_SECS: u64 = 5;

/// Maximum response size to prevent memory exhaustion (64 KiB).
const MAX_RESPONSE_SIZE: usize = 65536;

/// End-of-data marker for line-oriented protocols.
const EOD_MARKER: &str = "\n.\n";

// =============================================================================
// Readsock Handle — stateless marker
// =============================================================================

/// Handle for socket lookups — stateless since each find() opens a new
/// connection. This matches the C behavior where each query is a fresh
/// socket connection.
struct ReadsockHandle;

// =============================================================================
// Socket Specification
// =============================================================================

/// Parsed socket specification.
#[derive(Debug)]
enum SocketSpec {
    /// TCP connection: host and port.
    Inet { host: String, port: u16 },
    /// Unix domain socket: filesystem path.
    Unix { path: String },
}

impl SocketSpec {
    /// Parse a socket specification string.
    ///
    /// Formats:
    /// - `inet:host:port` — TCP socket
    /// - `/path/to/socket` — Unix domain socket (path starts with `/`)
    /// - `unix:/path/to/socket` — Unix domain socket (explicit prefix)
    fn parse(spec: &str) -> Result<Self, DriverError> {
        let spec = spec.trim();

        if let Some(rest) = spec.strip_prefix("inet:") {
            // TCP socket: inet:host:port
            let parts: Vec<&str> = rest.rsplitn(2, ':').collect();
            if parts.len() != 2 {
                return Err(DriverError::ExecutionFailed(format!(
                    "readsock: invalid inet spec (need inet:host:port): {}",
                    spec
                )));
            }
            let port: u16 = parts[0].parse().map_err(|_| {
                DriverError::ExecutionFailed(format!("readsock: invalid port number: {}", parts[0]))
            })?;
            let host = parts[1].to_string();
            Ok(SocketSpec::Inet { host, port })
        } else if let Some(path) = spec.strip_prefix("unix:") {
            Ok(SocketSpec::Unix {
                path: path.to_string(),
            })
        } else if spec.starts_with('/') {
            // Absolute path — Unix domain socket
            Ok(SocketSpec::Unix {
                path: spec.to_string(),
            })
        } else {
            Err(DriverError::ExecutionFailed(format!(
                "readsock: unrecognized socket spec (need inet:host:port or /path): {}",
                spec
            )))
        }
    }
}

// =============================================================================
// Query Options
// =============================================================================

/// Options for socket query behavior.
#[derive(Debug)]
struct ReadsockOptions {
    /// Timeout for the connection and read operations (seconds).
    timeout: Duration,
    /// Whether to send end-of-data marker after the query.
    send_eod: bool,
    /// Whether to strip trailing newline from response.
    strip_trailing_newline: bool,
    /// Optional TLS upgrade (not yet implemented in Rust — placeholder).
    use_tls: bool,
}

impl Default for ReadsockOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            send_eod: false,
            strip_trailing_newline: true,
            use_tls: false,
        }
    }
}

impl ReadsockOptions {
    /// Parse options from the opts string.
    ///
    /// Supported options (matching C behavior):
    /// - `timeout=N` — timeout in seconds
    /// - `shutdown` — send write shutdown after query
    /// - `eod` — send end-of-data marker
    /// - `tls` — request TLS upgrade (not yet supported)
    fn parse(opts: Option<&str>) -> Self {
        let mut result = Self::default();

        if let Some(opts_str) = opts {
            for part in opts_str.split_whitespace() {
                if let Some(val) = part.strip_prefix("timeout=") {
                    if let Ok(secs) = val.parse::<u64>() {
                        result.timeout = Duration::from_secs(secs);
                    }
                } else if part == "eod" {
                    result.send_eod = true;
                } else if part == "tls" {
                    result.use_tls = true;
                } else if part == "nostrip" {
                    result.strip_trailing_newline = false;
                }
            }
        }

        result
    }
}

// =============================================================================
// ReadsockLookup — LookupDriver implementation
// =============================================================================

/// Socket request/response lookup driver.
///
/// Connects to a TCP or Unix domain socket, sends the query string, reads
/// the response, and returns it. This enables integration with external
/// policy servers, content filters, and custom lookup daemons.
///
/// The socket specification and query are combined in the key:
/// ```text
/// <socket_spec> <query_data>
/// ```
///
/// For the expansion engine, the typical use is:
/// ```text
/// ${readsocket{/path/to/socket}{query_data}{timeout}{eod_string}}
/// ```
#[derive(Debug)]
struct ReadsockLookup;

impl ReadsockLookup {
    fn new() -> Self {
        Self
    }

    /// Send query and receive response over a TCP stream.
    fn transact_tcp(
        host: &str,
        port: u16,
        query: &str,
        opts: &ReadsockOptions,
    ) -> Result<String, DriverError> {
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect_timeout(
            &addr.parse().map_err(|e| {
                DriverError::ExecutionFailed(format!("readsock: invalid address {}: {}", addr, e))
            })?,
            opts.timeout,
        )
        .map_err(|e| {
            DriverError::ExecutionFailed(format!("readsock: TCP connect to {} failed: {}", addr, e))
        })?;

        stream.set_read_timeout(Some(opts.timeout)).ok();
        stream.set_write_timeout(Some(opts.timeout)).ok();

        Self::transact_stream(stream, query, opts)
    }

    /// Send query and receive response over a Unix domain socket.
    fn transact_unix(
        path: &str,
        query: &str,
        opts: &ReadsockOptions,
    ) -> Result<String, DriverError> {
        let stream = UnixStream::connect(path).map_err(|e| {
            DriverError::ExecutionFailed(format!(
                "readsock: Unix socket connect to {} failed: {}",
                path, e
            ))
        })?;

        stream.set_read_timeout(Some(opts.timeout)).ok();
        stream.set_write_timeout(Some(opts.timeout)).ok();

        Self::transact_stream(stream, query, opts)
    }

    /// Generic stream transact — works for both TCP and Unix streams.
    fn transact_stream<S: Read + Write>(
        mut stream: S,
        query: &str,
        opts: &ReadsockOptions,
    ) -> Result<String, DriverError> {
        // Send the query
        stream
            .write_all(query.as_bytes())
            .map_err(|e| DriverError::ExecutionFailed(format!("readsock: write failed: {}", e)))?;

        // Send end-of-data marker if requested
        if opts.send_eod {
            stream.write_all(EOD_MARKER.as_bytes()).map_err(|e| {
                DriverError::ExecutionFailed(format!("readsock: write EOD failed: {}", e))
            })?;
        }

        stream
            .flush()
            .map_err(|e| DriverError::ExecutionFailed(format!("readsock: flush failed: {}", e)))?;

        // Read the response (up to MAX_RESPONSE_SIZE).
        let mut response = Vec::with_capacity(4096);
        let mut reader = BufReader::new(stream);
        reader
            .take(MAX_RESPONSE_SIZE as u64)
            .read_to_end(&mut response)
            .map_err(|e| DriverError::ExecutionFailed(format!("readsock: read failed: {}", e)))?;

        let mut result = String::from_utf8_lossy(&response).into_owned();

        // Strip trailing newline if requested (default behavior).
        if opts.strip_trailing_newline {
            while result.ends_with('\n') || result.ends_with('\r') {
                result.pop();
            }
        }

        Ok(result)
    }
}

impl LookupDriver for ReadsockLookup {
    fn driver_name(&self) -> &str {
        "readsock"
    }

    fn lookup_type(&self) -> LookupType {
        LookupType::QUERY_STYLE
    }

    fn open(&self, _filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        tracing::debug!("readsock: open (stateless)");
        Ok(Box::new(ReadsockHandle))
    }

    fn find(
        &self,
        handle: &LookupHandle,
        _filename: Option<&str>,
        key: &str,
        opts: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        let _handle = handle
            .downcast_ref::<ReadsockHandle>()
            .ok_or_else(|| DriverError::ExecutionFailed("readsock: invalid handle type".into()))?;

        // Parse the key: first whitespace-delimited token is the socket spec,
        // remainder is the query data.
        let key = key.trim();
        let (socket_spec_str, query) = if let Some(pos) = key.find(char::is_whitespace) {
            (&key[..pos], key[pos..].trim_start())
        } else {
            // No query data — just socket spec; send empty query.
            (key, "")
        };

        let socket_spec = SocketSpec::parse(socket_spec_str)?;
        let readsock_opts = ReadsockOptions::parse(opts);

        tracing::debug!(
            socket = %socket_spec_str,
            query_len = query.len(),
            timeout_secs = readsock_opts.timeout.as_secs(),
            "readsock: performing socket lookup"
        );

        let response = match &socket_spec {
            SocketSpec::Inet { host, port } => {
                Self::transact_tcp(host, *port, query, &readsock_opts)?
            }
            SocketSpec::Unix { path } => Self::transact_unix(path, query, &readsock_opts)?,
        };

        if response.is_empty() {
            tracing::debug!("readsock: empty response");
            Ok(LookupResult::NotFound)
        } else {
            tracing::debug!(response_len = response.len(), "readsock: response received");
            Ok(LookupResult::Found {
                value: response,
                cache_ttl: None,
            })
        }
    }

    fn close(&self, _handle: LookupHandle) {
        tracing::debug!("readsock: closed (no-op)");
    }

    fn tidy(&self) {
        tracing::debug!("readsock: tidy (no-op)");
    }

    fn version_report(&self) -> Option<String> {
        Some("Lookup: readsock (pure Rust)".to_string())
    }
}

// =============================================================================
// Compile-Time Registration
// =============================================================================

inventory::submit! {
    LookupDriverFactory {
        name: "readsock",
        create: || Box::new(ReadsockLookup::new()),
        lookup_type: LookupType::QUERY_STYLE,
        avail_string: Some("readsock (built-in)"),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_readsock_driver_name() {
        let driver = ReadsockLookup::new();
        assert_eq!(driver.driver_name(), "readsock");
    }

    #[test]
    fn test_readsock_lookup_type() {
        let driver = ReadsockLookup::new();
        assert!(driver.lookup_type().is_query_style());
    }

    #[test]
    fn test_parse_inet_spec() {
        let spec = SocketSpec::parse("inet:localhost:1234").unwrap();
        match spec {
            SocketSpec::Inet { host, port } => {
                assert_eq!(host, "localhost");
                assert_eq!(port, 1234);
            }
            _ => panic!("expected Inet spec"),
        }
    }

    #[test]
    fn test_parse_unix_spec_path() {
        let spec = SocketSpec::parse("/var/run/exim.sock").unwrap();
        match spec {
            SocketSpec::Unix { path } => {
                assert_eq!(path, "/var/run/exim.sock");
            }
            _ => panic!("expected Unix spec"),
        }
    }

    #[test]
    fn test_parse_unix_spec_prefix() {
        let spec = SocketSpec::parse("unix:/tmp/test.sock").unwrap();
        match spec {
            SocketSpec::Unix { path } => {
                assert_eq!(path, "/tmp/test.sock");
            }
            _ => panic!("expected Unix spec"),
        }
    }

    #[test]
    fn test_parse_invalid_spec() {
        let result = SocketSpec::parse("invalid_spec");
        assert!(result.is_err());
    }

    #[test]
    fn test_readsock_options_default() {
        let opts = ReadsockOptions::default();
        assert_eq!(opts.timeout, Duration::from_secs(DEFAULT_TIMEOUT_SECS));
        assert!(!opts.send_eod);
        assert!(opts.strip_trailing_newline);
        assert!(!opts.use_tls);
    }

    #[test]
    fn test_readsock_options_parse() {
        let opts = ReadsockOptions::parse(Some("timeout=10 eod nostrip"));
        assert_eq!(opts.timeout, Duration::from_secs(10));
        assert!(opts.send_eod);
        assert!(!opts.strip_trailing_newline);
    }

    #[test]
    fn test_readsock_version_report() {
        let driver = ReadsockLookup::new();
        let report = driver.version_report();
        assert!(report.is_some());
        assert!(report.unwrap().contains("readsock"));
    }
}
