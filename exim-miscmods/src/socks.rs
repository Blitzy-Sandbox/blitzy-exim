//! SOCKS5 client connector module (RFC 1928 / RFC 1929).
//!
//! Rewrites `src/src/miscmods/socks.c` (425 lines) into safe Rust.  This module
//! implements a SOCKS5 client connector for Exim's outbound SMTP transport,
//! enabling SMTP connections to be routed through SOCKS5 proxies.
//!
//! # Protocol Support
//!
//! - **RFC 1928** — SOCKS Protocol Version 5 (method negotiation + CONNECT)
//! - **RFC 1929** — Username/Password Authentication for SOCKS V5
//!
//! # Feature Gate
//!
//! This module is compiled only when the `socks` Cargo feature is enabled,
//! replacing the C `#ifdef SUPPORT_SOCKS` preprocessor guard (socks.c line 15).
//!
//! # Architecture
//!
//! | C function / struct          | Rust replacement                        |
//! |-----------------------------|-----------------------------------------|
//! | `socks_option_defaults()`   | `SocksProxy::default()`                 |
//! | `socks_option()`            | `parse_proxy_list()` option parsing     |
//! | `socks_auth()`              | `perform_auth()`                        |
//! | `socks_get_proxy()`         | `select_proxy()`                        |
//! | `socks_sock_connect()`      | `socks_connect()`                       |
//! | `socks_errs[]`              | `SocksError::from_reply_code()`         |
//! | `socks_module_info`         | `inventory::submit!(DriverInfoBase)`    |
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` code.  All socket I/O uses safe Rust
//! standard library types ([`TcpStream`], [`Read`], [`Write`]).

use std::cell::Cell;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream, ToSocketAddrs,
};
use std::time::Duration;

use exim_drivers::{DriverError, DriverInfoBase};
use exim_store::{Clean, Tainted, TaintedString};

// =============================================================================
// SOCKS5 Protocol Constants (RFC 1928)
// =============================================================================

/// SOCKS protocol version byte.
const SOCKS_VERSION: u8 = 5;

/// SOCKS CONNECT command byte (RFC 1928 §4).
const SOCKS_CMD_CONNECT: u8 = 1;

/// Reserved byte — always 0x00 per RFC 1928.
const SOCKS_RSV: u8 = 0;

/// Address type: IPv4 (4 bytes).
const SOCKS_ATYP_IPV4: u8 = 1;

/// Address type: Domain name (length-prefixed).
const SOCKS_ATYP_DOMAIN: u8 = 3;

/// Address type: IPv6 (16 bytes).
const SOCKS_ATYP_IPV6: u8 = 4;

/// Authentication method: No authentication required (RFC 1928 §3).
const SOCKS_AUTH_NONE: u8 = 0x00;

/// Authentication method: Username/Password (RFC 1929).
const SOCKS_AUTH_USERNAME_PASSWORD: u8 = 0x02;

/// Authentication method: No acceptable methods — server rejects all offered.
const SOCKS_AUTH_NO_ACCEPTABLE: u8 = 0xFF;

/// Username/password sub-negotiation version (RFC 1929 §2).
const AUTH_NAME_VER: u8 = 1;

// =============================================================================
// Public Constants
// =============================================================================

/// Default SOCKS5 proxy port as specified in RFC 1928.
///
/// Replaces C `#define SOCKS_PORT 1080` (socks.c line 18).
pub const SOCKS_DEFAULT_PORT: u16 = 1080;

/// Default SOCKS5 connection timeout in seconds.
///
/// Replaces C `#define SOCKS_TIMEOUT 5` (socks.c line 19).
pub const SOCKS_DEFAULT_TIMEOUT: u64 = 5;

/// Default proxy weight for weighted random selection.
///
/// Replaces C `#define SOCKS_WEIGHT 1` (socks.c line 20).
const DEFAULT_WEIGHT: u16 = 1;

/// Default proxy priority (higher value = preferred).
///
/// Replaces C `#define SOCKS_PRIORITY 1` (socks.c line 21).
const DEFAULT_PRIORITY: u16 = 1;

/// Maximum number of configurable proxies per `socks_proxy` option string.
///
/// Mirrors the C `socks_opts proxies[32]` fixed-size array (socks.c line 208).
const MAX_PROXIES: usize = 32;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during SOCKS5 proxy operations.
///
/// Maps the 9 SOCKS5 reply error codes from RFC 1928 §6 (corresponding to the
/// C `socks_errs[]` array at socks.c lines 27–42) plus additional error
/// conditions for authentication, timeout, I/O, proxy configuration, and
/// protocol violations.
///
/// Each variant replaces specific C error-handling patterns:
/// - Reply codes 1–8 map to the `socks_errs[]` array entries with errno values
/// - `AuthFailed` replaces `log_write(0, LOG_MAIN|LOG_PANIC, "socks auth failed")` at line 133
/// - `Timeout` replaces `fd_ready()` timeout detection
/// - `IoError` replaces `send()/read()` failure returns with errno
/// - `InvalidProxy` replaces the proxy parsing error return at line 232
/// - `NoProxiesAvailable` replaces `socks_get_proxy()` returning -1 with `EBUSY`
/// - `ProtocolError` replaces the "unknown error code" fallback with `EPROTO`
#[derive(Debug, thiserror::Error)]
pub enum SocksError {
    /// SOCKS5 reply code 0x01: General SOCKS server failure.
    /// C errno mapping: `EIO`.
    #[error("general SOCKS server failure")]
    GeneralFailure,

    /// SOCKS5 reply code 0x02: Connection not allowed by ruleset.
    /// C errno mapping: `EACCES`.
    #[error("connection not allowed by ruleset")]
    NotAllowed,

    /// SOCKS5 reply code 0x03: Network unreachable.
    /// C errno mapping: `ENETUNREACH`.
    #[error("network unreachable")]
    NetworkUnreachable,

    /// SOCKS5 reply code 0x04: Host unreachable.
    /// C errno mapping: `EHOSTUNREACH`.
    #[error("host unreachable")]
    HostUnreachable,

    /// SOCKS5 reply code 0x05: Connection refused.
    /// C errno mapping: `ECONNREFUSED`.
    #[error("connection refused")]
    ConnectionRefused,

    /// SOCKS5 reply code 0x06: TTL expired.
    /// C errno mapping: `ECANCELED`.
    #[error("TTL expired")]
    TtlExpired,

    /// SOCKS5 reply code 0x07: Command not supported.
    /// C errno mapping: `EOPNOTSUPP`.
    #[error("command not supported")]
    CommandNotSupported,

    /// SOCKS5 reply code 0x08: Address type not supported.
    /// C errno mapping: `EAFNOSUPPORT`.
    #[error("address type not supported")]
    AddressTypeNotSupported,

    /// SOCKS5 authentication sub-negotiation failed (RFC 1929 status ≠ 0x00).
    /// Replaces C `log_write(0, LOG_MAIN|LOG_PANIC, "socks auth failed")`.
    #[error("SOCKS authentication failed")]
    AuthFailed,

    /// Connection or I/O operation timed out.
    /// Replaces C `fd_ready()` returning false when the deadline expires.
    #[error("SOCKS connection timeout")]
    Timeout,

    /// Underlying I/O error during TCP socket operations.
    /// Uses `#[from]` for automatic `From<std::io::Error>` conversion, replacing
    /// C `send()/read()` failure paths that set errno.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Invalid proxy specification string.
    /// Replaces C proxy-parsing error at socks.c line 232 (`return -1`).
    #[error("invalid proxy specification: {0}")]
    InvalidProxy(String),

    /// All configured proxies have been tried and failed.
    /// Replaces C `socks_get_proxy()` returning -1 with errno `EBUSY`.
    #[error("no proxies available — all configured proxies have failed")]
    NoProxiesAvailable,

    /// SOCKS5 protocol violation (unexpected version, unknown reply code, etc.).
    /// Replaces the C "unknown error code received" fallback with errno `EPROTO`.
    #[error("SOCKS protocol error: {0}")]
    ProtocolError(String),
}

impl SocksError {
    /// Maps a SOCKS5 reply code (RFC 1928 §6) to the corresponding error variant.
    ///
    /// Reply codes 1–8 map to the C `socks_errs[]` array (socks.c lines 27–42).
    /// Code 0 means success and returns `None`.  Unknown codes return
    /// [`ProtocolError`](SocksError::ProtocolError).
    fn from_reply_code(code: u8) -> Option<Self> {
        match code {
            0 => None,
            1 => Some(SocksError::GeneralFailure),
            2 => Some(SocksError::NotAllowed),
            3 => Some(SocksError::NetworkUnreachable),
            4 => Some(SocksError::HostUnreachable),
            5 => Some(SocksError::ConnectionRefused),
            6 => Some(SocksError::TtlExpired),
            7 => Some(SocksError::CommandNotSupported),
            8 => Some(SocksError::AddressTypeNotSupported),
            _ => Some(SocksError::ProtocolError(format!(
                "unknown SOCKS reply code: 0x{code:02x}"
            ))),
        }
    }

    /// Converts this SOCKS error to the corresponding [`std::io::ErrorKind`],
    /// preserving behavioural compatibility with the C errno mapping
    /// (socks.c lines 27–42).
    pub fn to_io_error_kind(&self) -> io::ErrorKind {
        match self {
            SocksError::GeneralFailure => io::ErrorKind::Other,
            SocksError::NotAllowed => io::ErrorKind::PermissionDenied,
            SocksError::NetworkUnreachable => io::ErrorKind::Other,
            SocksError::HostUnreachable => io::ErrorKind::Other,
            SocksError::ConnectionRefused => io::ErrorKind::ConnectionRefused,
            SocksError::TtlExpired => io::ErrorKind::Other,
            SocksError::CommandNotSupported => io::ErrorKind::Unsupported,
            SocksError::AddressTypeNotSupported => io::ErrorKind::Other,
            SocksError::AuthFailed => io::ErrorKind::Other,
            SocksError::Timeout => io::ErrorKind::TimedOut,
            SocksError::IoError(e) => e.kind(),
            SocksError::InvalidProxy(_) => io::ErrorKind::InvalidInput,
            SocksError::NoProxiesAvailable => io::ErrorKind::Other,
            SocksError::ProtocolError(_) => io::ErrorKind::Other,
        }
    }
}

/// Integration with the driver error system.
///
/// Converts SOCKS errors to [`DriverError::ExecutionFailed`] for uniform
/// error handling in the exim-drivers registry resolution chain.
impl From<SocksError> for DriverError {
    fn from(err: SocksError) -> Self {
        DriverError::ExecutionFailed(err.to_string())
    }
}

// =============================================================================
// Authentication Types
// =============================================================================

/// SOCKS5 authentication method configuration.
///
/// Replaces the C `auth_type` / `auth_name` / `auth_pwd` fields in the
/// `socks_opts` struct (socks.c lines 47–49) with a single Rust enum that
/// carries credentials inline.
///
/// - [`SocksAuth::None`] maps to C `AUTH_NONE` (0x00)
/// - [`SocksAuth::UsernamePassword`] maps to C `AUTH_NAME` (0x02, RFC 1929)
#[derive(Debug, Clone)]
pub enum SocksAuth {
    /// No authentication required (RFC 1928 method 0x00).
    ///
    /// C equivalent: `AUTH_NONE = 0`.
    None,

    /// Username/password authentication per RFC 1929.
    ///
    /// C equivalent: `AUTH_NAME = 2` with separate `auth_name` and `auth_pwd`
    /// fields in `socks_opts`.
    UsernamePassword {
        /// Username for SOCKS5 authentication (max 255 bytes per RFC 1929 §2).
        username: String,
        /// Password for SOCKS5 authentication (max 255 bytes per RFC 1929 §2).
        password: String,
    },
}

impl SocksAuth {
    /// Returns the SOCKS5 method byte for this authentication type.
    fn method_byte(&self) -> u8 {
        match self {
            SocksAuth::None => SOCKS_AUTH_NONE,
            SocksAuth::UsernamePassword { .. } => SOCKS_AUTH_USERNAME_PASSWORD,
        }
    }
}

// =============================================================================
// Proxy Configuration
// =============================================================================

/// Configuration for a single SOCKS5 proxy server.
///
/// Replaces the C `socks_opts` struct (socks.c lines 44–55) with all fields
/// translated to idiomatic Rust types.  Default values match the C constants
/// defined at socks.c lines 17–21: port = 1080, timeout = 5 s, weight = 1,
/// priority = 1.
#[derive(Debug, Clone)]
pub struct SocksProxy {
    /// Proxy server hostname or IP address.
    ///
    /// Replaces C `proxy_host` field (socks.c line 46).
    pub host: String,

    /// Proxy server port (default: [`SOCKS_DEFAULT_PORT`] = 1080).
    ///
    /// Replaces C `port` field initialised from `SOCKS_PORT`.
    pub port: u16,

    /// Authentication method and credentials.
    ///
    /// Replaces the separate C `auth_type`, `auth_name`, `auth_pwd` fields.
    pub auth: SocksAuth,

    /// Weight for weighted-random proxy selection (default: 1).
    ///
    /// Higher weight increases selection probability among proxies sharing the
    /// same priority.  Replaces C `weight` field initialised from `SOCKS_WEIGHT`.
    pub weight: u16,

    /// Priority for proxy selection (default: 1).
    ///
    /// Higher-priority proxies are tried first; lower-priority are fallbacks.
    /// Replaces C `priority` field initialised from `SOCKS_PRIORITY`.
    pub priority: u16,

    /// Connection and I/O timeout.
    ///
    /// Replaces C `timeout` field initialised from `SOCKS_TIMEOUT` (5 seconds).
    pub timeout: Duration,

    /// Whether this proxy has failed during the current connection attempt.
    ///
    /// Set to `true` after a connection failure to exclude this proxy from
    /// subsequent selection rounds within the same `socks_connect()` invocation.
    /// Replaces C `is_failed` field (socks.c line 51).
    pub is_failed: bool,
}

impl Default for SocksProxy {
    /// Creates a proxy configuration with defaults matching C
    /// `socks_option_defaults()` (socks.c lines 57–69).
    fn default() -> Self {
        Self {
            host: String::new(),
            port: SOCKS_DEFAULT_PORT,
            auth: SocksAuth::None,
            weight: DEFAULT_WEIGHT,
            priority: DEFAULT_PRIORITY,
            timeout: Duration::from_secs(SOCKS_DEFAULT_TIMEOUT),
            is_failed: false,
        }
    }
}

// =============================================================================
// Connection Result
// =============================================================================

/// Result of a successful SOCKS5 CONNECT operation.
///
/// Contains the tunnelled TCP stream and proxy-side address information (both
/// the local address used to connect to the proxy, and the external/bound
/// address the proxy reports in its CONNECT reply).
///
/// Proxy-sourced addresses are wrapped in [TaintedString] because they
/// originate from the external SOCKS proxy server (untrusted source).
#[derive(Debug)]
pub struct SocksConnectResult {
    /// The TCP stream tunnelled through the SOCKS proxy.
    pub stream: TcpStream,

    /// Local address on our side of the proxy connection (tainted).
    pub proxy_local_address: TaintedString,

    /// Local port on our side of the proxy connection.
    pub proxy_local_port: u16,

    /// External / bound address reported by the SOCKS server (BND.ADDR, RFC 1928).
    pub proxy_external_address: TaintedString,

    /// External / bound port reported by the SOCKS server (BND.PORT, RFC 1928).
    pub proxy_external_port: u16,
}

// =============================================================================
// Proxy List Parsing
// =============================================================================

/// Parses an Exim socks_proxy option string into a list of proxy configs.
///
/// Format: hostname [options...] : hostname [options...]
///
/// Supported options (matching C socks_option(), socks.c lines 71-93):
/// - auth=none|name
/// - name=USER, pass=PASS (for auth=name)
/// - port=N (default 1080)
/// - tmo=N (timeout, default 5s)
/// - pri=N (priority, default 1)
/// - weight=N (default 1)
///
/// Both : and ; are accepted as proxy separators.
pub fn parse_proxy_list(spec: &str) -> Result<Vec<SocksProxy>, SocksError> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err(SocksError::InvalidProxy(
            "empty proxy specification".to_string(),
        ));
    }

    let mut proxies = Vec::new();

    for entry in spec.split([':', ';']) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }

        if proxies.len() >= MAX_PROXIES {
            return Err(SocksError::InvalidProxy(format!(
                "too many proxies (maximum {MAX_PROXIES})"
            )));
        }

        let mut proxy = SocksProxy::default();
        let mut tokens = entry.split_whitespace();

        // First token is the hostname (positional).
        match tokens.next() {
            Some(host) => proxy.host = host.to_string(),
            None => {
                return Err(SocksError::InvalidProxy(
                    "proxy entry has no hostname".to_string(),
                ));
            }
        }

        let mut auth_name = String::new();
        let mut auth_pwd = String::new();
        let mut auth_type_name = false;

        for option in tokens {
            if let Some(val) = option.strip_prefix("auth=") {
                match val {
                    "none" => auth_type_name = false,
                    "name" => auth_type_name = true,
                    other => {
                        return Err(SocksError::InvalidProxy(format!(
                            "unrecognised auth method: {other}"
                        )));
                    }
                }
            } else if let Some(val) = option.strip_prefix("name=") {
                auth_name = val.to_string();
            } else if let Some(val) = option.strip_prefix("pass=") {
                auth_pwd = val.to_string();
            } else if let Some(val) = option.strip_prefix("port=") {
                proxy.port = val
                    .parse::<u16>()
                    .map_err(|_| SocksError::InvalidProxy(format!("invalid port value: {val}")))?;
            } else if let Some(val) = option.strip_prefix("tmo=") {
                let secs = val.parse::<u64>().map_err(|_| {
                    SocksError::InvalidProxy(format!("invalid timeout value: {val}"))
                })?;
                proxy.timeout = Duration::from_secs(secs);
            } else if let Some(val) = option.strip_prefix("pri=") {
                proxy.priority = val.parse::<u16>().map_err(|_| {
                    SocksError::InvalidProxy(format!("invalid priority value: {val}"))
                })?;
            } else if let Some(val) = option.strip_prefix("weight=") {
                proxy.weight = val.parse::<u16>().map_err(|_| {
                    SocksError::InvalidProxy(format!("invalid weight value: {val}"))
                })?;
            }
            // Unknown options silently ignored (matches C behaviour).
        }

        if auth_type_name {
            proxy.auth = SocksAuth::UsernamePassword {
                username: auth_name,
                password: auth_pwd,
            };
        }

        proxies.push(proxy);
    }

    if proxies.is_empty() {
        return Err(SocksError::InvalidProxy(
            "no valid proxies in specification".to_string(),
        ));
    }

    Ok(proxies)
}

// =============================================================================
// Pseudo-Random Number Generation (for Proxy Selection)
// =============================================================================

// Thread-local counter for hash-based PRNG entropy.
thread_local! {
    static RNG_COUNTER: Cell<u64> = const { Cell::new(0) };
}

/// Generates a pseudo-random number in `[0, max)`.
///
/// Replaces C `random_number()` wrapping POSIX `random()`. Uses a hash of
/// current time, process ID, and thread-local counter.
fn random_number(max: u64) -> u64 {
    if max == 0 {
        return 0;
    }
    let counter = RNG_COUNTER.with(|c| {
        let val = c.get().wrapping_add(1);
        c.set(val);
        val
    });
    let mut hasher = DefaultHasher::new();
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .hash(&mut hasher);
    counter.hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    hasher.finish() % max
}

// =============================================================================
// Proxy Selection
// =============================================================================

/// Selects a proxy using the priority/weight algorithm.
///
/// Replaces C `socks_get_proxy()` (socks.c lines 147-181):
/// 1. Find highest priority among non-failed proxies.
/// 2. Sum weights at that priority level.
/// 3. Weighted-random selection.
fn select_proxy(proxies: &[SocksProxy]) -> Option<usize> {
    if proxies.len() == 1 {
        return if proxies[0].is_failed { None } else { Some(0) };
    }

    let max_priority = proxies
        .iter()
        .filter(|p| !p.is_failed)
        .map(|p| p.priority)
        .max()?;

    let total_weight: u64 = proxies
        .iter()
        .filter(|p| !p.is_failed && p.priority == max_priority)
        .map(|p| u64::from(p.weight))
        .sum();

    if total_weight == 0 {
        return None;
    }

    let mut rnd = random_number(total_weight) as i64;
    for (i, proxy) in proxies.iter().enumerate() {
        if !proxy.is_failed && proxy.priority == max_priority {
            rnd -= i64::from(proxy.weight);
            if rnd < 0 {
                return Some(i);
            }
        }
    }

    tracing::error!("socks proxy selection: unexpected fallthrough");
    None
}

// =============================================================================
// SOCKS5 Authentication
// =============================================================================

/// Performs SOCKS5 authentication on an established proxy connection.
///
/// Replaces C `socks_auth()` (socks.c lines 95-137). Handles:
/// - `AUTH_NONE` (0x00): no network exchange
/// - `AUTH_NAME` (0x02): Username/password per RFC 1929
fn perform_auth(
    stream: &mut TcpStream,
    method: u8,
    auth: &SocksAuth,
    timeout: Duration,
) -> Result<(), SocksError> {
    match method {
        SOCKS_AUTH_NONE => {
            tracing::debug!("SOCKS auth: no authentication required");
            Ok(())
        }

        SOCKS_AUTH_USERNAME_PASSWORD => {
            let (username, password) = match auth {
                SocksAuth::UsernamePassword { username, password } => (username, password),
                SocksAuth::None => {
                    tracing::error!("SOCKS server requires username/password but none configured");
                    return Err(SocksError::AuthFailed);
                }
            };

            tracing::debug!(username = %username, "SOCKS auth: username/password (RFC 1929)");

            let uname_bytes = &username.as_bytes()[..username.len().min(255)];
            let passwd_bytes = &password.as_bytes()[..password.len().min(255)];

            let mut buf = Vec::with_capacity(3 + uname_bytes.len() + passwd_bytes.len());
            buf.push(AUTH_NAME_VER);
            buf.push(uname_bytes.len() as u8);
            buf.extend_from_slice(uname_bytes);
            buf.push(passwd_bytes.len() as u8);
            buf.extend_from_slice(passwd_bytes);

            tracing::debug!(len = buf.len(), "SOCKS>> auth request");

            stream.set_write_timeout(Some(timeout))?;
            stream.write_all(&buf).map_err(|e| {
                tracing::error!(error = %e, "SOCKS auth: send failed");
                SocksError::IoError(e)
            })?;

            let mut response = [0u8; 2];
            stream.set_read_timeout(Some(timeout))?;
            stream
                .read_exact(&mut response)
                .map_err(|e| map_io_timeout(e, "SOCKS auth response"))?;

            tracing::debug!(
                ver = response[0],
                status = response[1],
                "SOCKS<< auth response"
            );

            if response[0] == AUTH_NAME_VER && response[1] == 0 {
                tracing::debug!("SOCKS auth: success");
                Ok(())
            } else {
                tracing::error!(ver = response[0], status = response[1], "SOCKS auth failed");
                Err(SocksError::AuthFailed)
            }
        }

        SOCKS_AUTH_NO_ACCEPTABLE => {
            tracing::error!("SOCKS server: no acceptable authentication method");
            Err(SocksError::AuthFailed)
        }

        other => {
            tracing::error!(method = other, "SOCKS: unrecognised auth method");
            Err(SocksError::ProtocolError(format!(
                "unrecognised SOCKS auth method: 0x{other:02x}"
            )))
        }
    }
}

// =============================================================================
// SOCKS5 CONNECT Request / Response Helpers
// =============================================================================

/// Builds a SOCKS5 CONNECT request packet.
///
/// Replaces C code at socks.c lines 311-336. Detects address type
/// (IPv4 / IPv6 / domain) and encodes port in network byte order.
fn build_connect_request(target_host: &Clean<String>, target_port: u16) -> Vec<u8> {
    let host_str: &str = target_host.as_ref();
    let mut buf = Vec::with_capacity(22);

    buf.push(SOCKS_VERSION);
    buf.push(SOCKS_CMD_CONNECT);
    buf.push(SOCKS_RSV);

    if let Ok(ip) = host_str.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                buf.push(SOCKS_ATYP_IPV4);
                buf.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.push(SOCKS_ATYP_IPV6);
                buf.extend_from_slice(&v6.octets());
            }
        }
    } else {
        let domain_bytes = host_str.as_bytes();
        let len = domain_bytes.len().min(255);
        buf.push(SOCKS_ATYP_DOMAIN);
        buf.push(len as u8);
        buf.extend_from_slice(&domain_bytes[..len]);
    }

    buf.extend_from_slice(&target_port.to_be_bytes());
    buf
}

/// Reads bound address (BND.ADDR + BND.PORT) from a SOCKS5 CONNECT reply.
fn parse_bind_address(
    stream: &mut TcpStream,
    atyp: u8,
    timeout: Duration,
) -> Result<(String, u16), SocksError> {
    stream.set_read_timeout(Some(timeout))?;

    let address = match atyp {
        SOCKS_ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            stream
                .read_exact(&mut octets)
                .map_err(|e| map_io_timeout(e, "SOCKS bind address (IPv4)"))?;
            IpAddr::V4(Ipv4Addr::from(octets)).to_string()
        }
        SOCKS_ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            stream
                .read_exact(&mut octets)
                .map_err(|e| map_io_timeout(e, "SOCKS bind address (IPv6)"))?;
            IpAddr::V6(Ipv6Addr::from(octets)).to_string()
        }
        SOCKS_ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream
                .read_exact(&mut len_buf)
                .map_err(|e| map_io_timeout(e, "SOCKS bind domain length"))?;
            let len = len_buf[0] as usize;
            let mut domain = vec![0u8; len];
            stream
                .read_exact(&mut domain)
                .map_err(|e| map_io_timeout(e, "SOCKS bind domain"))?;
            String::from_utf8_lossy(&domain).into_owned()
        }
        _ => {
            return Err(SocksError::ProtocolError(format!(
                "unknown address type in CONNECT reply: 0x{atyp:02x}"
            )));
        }
    };

    let mut port_buf = [0u8; 2];
    stream
        .read_exact(&mut port_buf)
        .map_err(|e| map_io_timeout(e, "SOCKS bind port"))?;
    let port = u16::from_be_bytes(port_buf);

    Ok((address, port))
}

/// Maps an I/O error to [`SocksError::Timeout`] on timeout/would-block,
/// otherwise wraps as [`SocksError::IoError`].
fn map_io_timeout(e: io::Error, context: &str) -> SocksError {
    if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock {
        tracing::error!(context = context, "SOCKS: receive timeout");
        SocksError::Timeout
    } else {
        tracing::error!(error = %e, context = context, "SOCKS: receive error");
        SocksError::IoError(e)
    }
}

// =============================================================================
// Proxy Address Resolution
// =============================================================================

/// Resolves a proxy hostname or IP literal to a [`SocketAddr`].
///
/// Tries IPv4 parse, then IPv6 (with bracket stripping), then DNS via
/// [`ToSocketAddrs`]. Replaces C `Ustrchr(sob->proxy_host, ':')` detection
/// at socks.c line 275.
fn resolve_proxy_address(host: &str, port: u16) -> Result<SocketAddr, SocksError> {
    if let Ok(ipv4) = host.parse::<Ipv4Addr>() {
        return Ok(SocketAddr::V4(SocketAddrV4::new(ipv4, port)));
    }

    let ipv6_str = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ipv6) = ipv6_str.parse::<Ipv6Addr>() {
        return Ok(SocketAddr::V6(SocketAddrV6::new(ipv6, port, 0, 0)));
    }

    let addr_str = format!("{host}:{port}");
    addr_str
        .to_socket_addrs()
        .map_err(|e| SocksError::InvalidProxy(format!("cannot resolve proxy host '{host}': {e}")))?
        .next()
        .ok_or_else(|| {
            SocksError::InvalidProxy(format!("no addresses resolved for proxy host '{host}'"))
        })
}

// =============================================================================
// Main Connection Function
// =============================================================================

/// Connects to a target host through a SOCKS5 proxy.
///
/// Primary entry point replacing C `socks_sock_connect()` (socks.c lines 195-403).
/// On per-proxy failure, marks proxy as failed and retries with the next
/// available proxy until success or exhaustion.
pub fn socks_connect(
    target_host: &str,
    target_port: u16,
    proxy_spec: &str,
    timeout: Duration,
) -> Result<SocksConnectResult, SocksError> {
    let mut proxies = parse_proxy_list(proxy_spec)?;

    if proxies.is_empty() {
        return Err(SocksError::NoProxiesAvailable);
    }

    // Indefinite timeout if zero — C: `if (!timeout) timeout = 24*60*60;`
    let effective_timeout = if timeout.is_zero() {
        Duration::from_secs(24 * 60 * 60)
    } else {
        timeout
    };

    let clean_target = Clean::new(target_host.to_string());

    loop {
        let idx = match select_proxy(&proxies) {
            Some(i) => i,
            None => {
                tracing::warn!("SOCKS: no proxies left");
                return Err(SocksError::NoProxiesAvailable);
            }
        };

        let proxy = &proxies[idx];
        let proxy_host = proxy.host.clone();
        let proxy_port = proxy.port;
        let proxy_timeout = proxy.timeout;
        let auth = proxy.auth.clone();

        tracing::info!(
            proxy_host = %proxy_host,
            proxy_port = proxy_port,
            target = %target_host,
            target_port = target_port,
            "SOCKS: attempting connection via proxy"
        );

        match attempt_proxy_connection(
            &proxy_host,
            proxy_port,
            &auth,
            &clean_target,
            target_port,
            proxy_timeout.min(effective_timeout),
        ) {
            Ok(result) => {
                tracing::info!(
                    proxy = %proxy_host,
                    target = %target_host,
                    target_port = target_port,
                    "SOCKS: tunnel established successfully"
                );
                return Ok(result);
            }
            Err(e) => {
                tracing::warn!(
                    proxy = %proxy_host,
                    error = %e,
                    "SOCKS: proxy connection failed, marking as failed"
                );
                proxies[idx].is_failed = true;
            }
        }
    }
}

/// Attempts a full SOCKS5 connection through a single proxy.
///
/// TCP connect -> method negotiation -> auth -> CONNECT -> response.
fn attempt_proxy_connection(
    proxy_host: &str,
    proxy_port: u16,
    auth: &SocksAuth,
    target_host: &Clean<String>,
    target_port: u16,
    timeout: Duration,
) -> Result<SocksConnectResult, SocksError> {
    let proxy_addr = resolve_proxy_address(proxy_host, proxy_port)?;

    tracing::debug!(
        addr = %proxy_addr,
        timeout_ms = timeout.as_millis(),
        "SOCKS: connecting to proxy"
    );

    // TCP connect with timeout
    let mut stream = TcpStream::connect_timeout(&proxy_addr, timeout).map_err(|e| {
        if e.kind() == io::ErrorKind::TimedOut {
            SocksError::Timeout
        } else {
            SocksError::IoError(e)
        }
    })?;

    // Record local address
    let local_addr = stream.local_addr().map_err(SocksError::IoError)?;
    let proxy_local_address = Tainted::new(local_addr.ip().to_string());
    let proxy_local_port = local_addr.port();

    // Step 1: SOCKS5 Greeting — VER(0x05) + NMETHODS(1) + METHOD
    let greeting = [SOCKS_VERSION, 1u8, auth.method_byte()];

    tracing::debug!(
        "SOCKS>> method select: {:02x} {:02x} {:02x}",
        greeting[0],
        greeting[1],
        greeting[2]
    );

    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(&greeting).map_err(|e| {
        tracing::error!(error = %e, state = "method select", "SOCKS: send error");
        SocksError::IoError(e)
    })?;

    // Step 2: Read Method Selection Response — VER + METHOD
    let mut method_resp = [0u8; 2];
    stream.set_read_timeout(Some(timeout))?;
    stream
        .read_exact(&mut method_resp)
        .map_err(|e| map_io_timeout(e, "method select"))?;

    tracing::debug!(
        "SOCKS<< method response: {:02x} {:02x}",
        method_resp[0],
        method_resp[1]
    );

    if method_resp[0] != SOCKS_VERSION {
        return Err(SocksError::ProtocolError(format!(
            "unexpected SOCKS version in method response: 0x{:02x}",
            method_resp[0]
        )));
    }

    // Step 3: Authenticate
    perform_auth(&mut stream, method_resp[1], auth, timeout)?;

    // Step 4: Send CONNECT Request
    let target_str: &str = target_host.as_ref();
    let connect_req = build_connect_request(target_host, target_port);

    tracing::debug!(
        len = connect_req.len(),
        target = target_str,
        port = target_port,
        "SOCKS>> CONNECT request"
    );

    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(&connect_req).map_err(|e| {
        tracing::error!(error = %e, state = "connect", "SOCKS: send error");
        SocksError::IoError(e)
    })?;

    // Step 5: Read CONNECT Reply — VER(1) + REP(1) + RSV(1) + ATYP(1)
    let mut reply_hdr = [0u8; 4];
    stream.set_read_timeout(Some(timeout))?;
    stream
        .read_exact(&mut reply_hdr)
        .map_err(|e| map_io_timeout(e, "connect reply"))?;

    tracing::debug!(
        "SOCKS<< reply header: {:02x} {:02x} {:02x} {:02x}",
        reply_hdr[0],
        reply_hdr[1],
        reply_hdr[2],
        reply_hdr[3]
    );

    if reply_hdr[0] != SOCKS_VERSION {
        return Err(SocksError::ProtocolError(format!(
            "unexpected SOCKS version in CONNECT reply: 0x{:02x}",
            reply_hdr[0]
        )));
    }

    // Check reply status
    if let Some(err) = SocksError::from_reply_code(reply_hdr[1]) {
        tracing::error!(
            reply_code = reply_hdr[1],
            error = %err,
            "SOCKS: CONNECT request rejected"
        );
        return Err(err);
    }

    // Step 6: Parse Bound Address
    let (external_addr, external_port) = parse_bind_address(&mut stream, reply_hdr[3], timeout)?;

    let proxy_external_address = Tainted::new(external_addr.clone());
    let proxy_external_port = external_port;

    tracing::debug!(
        "SOCKS: proxy farside: [{}]:{}",
        external_addr,
        external_port
    );

    // Step 7: Clear timeouts — caller manages SMTP timing
    stream.set_read_timeout(Option::<Duration>::None)?;
    stream.set_write_timeout(Option::<Duration>::None)?;

    Ok(SocksConnectResult {
        stream,
        proxy_local_address,
        proxy_local_port,
        proxy_external_address,
        proxy_external_port,
    })
}

// =============================================================================
// Module Registration
// =============================================================================
//
// Replaces C socks_module_info static struct (socks.c lines 412-421).
// Registered at compile time via inventory::submit! (AAP section 0.7.3).

inventory::submit! {
    DriverInfoBase::new("socks")
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Error Mapping ───────────────────────────────────────────────────

    #[test]
    fn reply_code_0_is_success() {
        assert!(SocksError::from_reply_code(0).is_none());
    }

    #[test]
    fn reply_codes_1_through_8_map_correctly() {
        let expected = [
            "general SOCKS server failure",
            "connection not allowed by ruleset",
            "network unreachable",
            "host unreachable",
            "connection refused",
            "TTL expired",
            "command not supported",
            "address type not supported",
        ];
        for (code, msg) in expected.iter().enumerate() {
            let err = SocksError::from_reply_code((code + 1) as u8).unwrap();
            assert!(
                err.to_string().contains(msg),
                "code {} => expected '{}', got '{}'",
                code + 1,
                msg,
                err
            );
        }
    }

    #[test]
    fn reply_code_unknown_gives_protocol_error() {
        let err = SocksError::from_reply_code(0x09).unwrap();
        assert!(matches!(err, SocksError::ProtocolError(_)));
        assert!(err.to_string().contains("0x09"));
    }

    #[test]
    fn socks_error_to_io_error_kind_mapping() {
        assert_eq!(
            SocksError::ConnectionRefused.to_io_error_kind(),
            io::ErrorKind::ConnectionRefused
        );
        assert_eq!(
            SocksError::Timeout.to_io_error_kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            SocksError::NotAllowed.to_io_error_kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            SocksError::InvalidProxy("x".into()).to_io_error_kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn socks_error_converts_to_driver_error() {
        let socks_err = SocksError::AuthFailed;
        let driver_err: DriverError = socks_err.into();
        assert!(driver_err.to_string().contains("authentication failed"));
    }

    // ── Auth Method Byte ────────────────────────────────────────────────

    #[test]
    fn auth_none_method_byte() {
        assert_eq!(SocksAuth::None.method_byte(), 0x00);
    }

    #[test]
    fn auth_username_password_method_byte() {
        let auth = SocksAuth::UsernamePassword {
            username: "user".into(),
            password: "pass".into(),
        };
        assert_eq!(auth.method_byte(), 0x02);
    }

    // ── Proxy Parsing ───────────────────────────────────────────────────

    #[test]
    fn parse_single_proxy_defaults() {
        let proxies = parse_proxy_list("proxy1.example.com").unwrap();
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].host, "proxy1.example.com");
        assert_eq!(proxies[0].port, SOCKS_DEFAULT_PORT);
        assert_eq!(proxies[0].weight, DEFAULT_WEIGHT);
        assert_eq!(proxies[0].priority, DEFAULT_PRIORITY);
        assert!(!proxies[0].is_failed);
        assert!(matches!(proxies[0].auth, SocksAuth::None));
    }

    #[test]
    fn parse_proxy_with_all_options() {
        let spec =
            "proxy.example.com port=9050 auth=name name=alice pass=s3cret tmo=10 pri=5 weight=3";
        let proxies = parse_proxy_list(spec).unwrap();
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].host, "proxy.example.com");
        assert_eq!(proxies[0].port, 9050);
        assert_eq!(proxies[0].timeout, Duration::from_secs(10));
        assert_eq!(proxies[0].priority, 5);
        assert_eq!(proxies[0].weight, 3);
        match &proxies[0].auth {
            SocksAuth::UsernamePassword { username, password } => {
                assert_eq!(username, "alice");
                assert_eq!(password, "s3cret");
            }
            SocksAuth::None => panic!("expected UsernamePassword"),
        }
    }

    #[test]
    fn parse_multiple_proxies_colon_separated() {
        let spec = "proxy1.example.com port=1080 : proxy2.example.com port=9050";
        let proxies = parse_proxy_list(spec).unwrap();
        assert_eq!(proxies.len(), 2);
        assert_eq!(proxies[0].host, "proxy1.example.com");
        assert_eq!(proxies[0].port, 1080);
        assert_eq!(proxies[1].host, "proxy2.example.com");
        assert_eq!(proxies[1].port, 9050);
    }

    #[test]
    fn parse_multiple_proxies_semicolon_separated() {
        let spec = "p1 ; p2 ; p3";
        let proxies = parse_proxy_list(spec).unwrap();
        assert_eq!(proxies.len(), 3);
        assert_eq!(proxies[0].host, "p1");
        assert_eq!(proxies[1].host, "p2");
        assert_eq!(proxies[2].host, "p3");
    }

    #[test]
    fn parse_empty_spec_fails() {
        assert!(matches!(
            parse_proxy_list(""),
            Err(SocksError::InvalidProxy(_))
        ));
    }

    #[test]
    fn parse_whitespace_only_spec_fails() {
        assert!(matches!(
            parse_proxy_list("   "),
            Err(SocksError::InvalidProxy(_))
        ));
    }

    #[test]
    fn parse_invalid_port_fails() {
        assert!(matches!(
            parse_proxy_list("host port=abc"),
            Err(SocksError::InvalidProxy(_))
        ));
    }

    #[test]
    fn parse_invalid_auth_method_fails() {
        assert!(matches!(
            parse_proxy_list("host auth=kerberos"),
            Err(SocksError::InvalidProxy(_))
        ));
    }

    // ── Proxy Selection ─────────────────────────────────────────────────

    #[test]
    fn select_single_non_failed_proxy() {
        let proxies = vec![SocksProxy {
            host: "p1".into(),
            ..SocksProxy::default()
        }];
        assert_eq!(select_proxy(&proxies), Some(0));
    }

    #[test]
    fn select_single_failed_proxy_returns_none() {
        let proxies = vec![SocksProxy {
            host: "p1".into(),
            is_failed: true,
            ..SocksProxy::default()
        }];
        assert_eq!(select_proxy(&proxies), None);
    }

    #[test]
    fn select_prefers_higher_priority() {
        let proxies = vec![
            SocksProxy {
                host: "low".into(),
                priority: 1,
                weight: 100,
                ..SocksProxy::default()
            },
            SocksProxy {
                host: "high".into(),
                priority: 10,
                weight: 1,
                ..SocksProxy::default()
            },
        ];
        for _ in 0..20 {
            assert_eq!(select_proxy(&proxies), Some(1));
        }
    }

    #[test]
    fn select_skips_failed_proxies() {
        let proxies = vec![
            SocksProxy {
                host: "failed".into(),
                is_failed: true,
                priority: 10,
                ..SocksProxy::default()
            },
            SocksProxy {
                host: "ok".into(),
                is_failed: false,
                priority: 1,
                ..SocksProxy::default()
            },
        ];
        assert_eq!(select_proxy(&proxies), Some(1));
    }

    #[test]
    fn select_all_failed_returns_none() {
        let proxies = vec![
            SocksProxy {
                host: "f1".into(),
                is_failed: true,
                ..SocksProxy::default()
            },
            SocksProxy {
                host: "f2".into(),
                is_failed: true,
                ..SocksProxy::default()
            },
        ];
        assert_eq!(select_proxy(&proxies), None);
    }

    // ── CONNECT Request Building ────────────────────────────────────────

    #[test]
    fn connect_request_ipv4() {
        let host = Clean::new("192.168.1.1".to_string());
        let req = build_connect_request(&host, 25);
        assert_eq!(req[0], SOCKS_VERSION);
        assert_eq!(req[1], SOCKS_CMD_CONNECT);
        assert_eq!(req[2], SOCKS_RSV);
        assert_eq!(req[3], SOCKS_ATYP_IPV4);
        assert_eq!(&req[4..8], &[192, 168, 1, 1]);
        assert_eq!(&req[8..10], &25u16.to_be_bytes());
        assert_eq!(req.len(), 10);
    }

    #[test]
    fn connect_request_ipv6() {
        let host = Clean::new("::1".to_string());
        let req = build_connect_request(&host, 587);
        assert_eq!(req[3], SOCKS_ATYP_IPV6);
        assert_eq!(req.len(), 4 + 16 + 2);
        assert_eq!(req[19], 1);
        assert_eq!(&req[20..22], &587u16.to_be_bytes());
    }

    #[test]
    fn connect_request_domain() {
        let host = Clean::new("mail.example.com".to_string());
        let req = build_connect_request(&host, 25);
        assert_eq!(req[3], SOCKS_ATYP_DOMAIN);
        assert_eq!(req[4], 16);
        assert_eq!(&req[5..21], b"mail.example.com");
        assert_eq!(&req[21..23], &25u16.to_be_bytes());
    }

    // ── Address Resolution ──────────────────────────────────────────────

    #[test]
    fn resolve_ipv4_literal() {
        let addr = resolve_proxy_address("127.0.0.1", 1080).unwrap();
        assert_eq!(
            addr,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1080))
        );
    }

    #[test]
    fn resolve_ipv6_literal() {
        let addr = resolve_proxy_address("::1", 1080).unwrap();
        assert_eq!(
            addr,
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1080, 0, 0))
        );
    }

    #[test]
    fn resolve_ipv6_literal_with_brackets() {
        let addr = resolve_proxy_address("[::1]", 1080).unwrap();
        assert_eq!(
            addr,
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1080, 0, 0))
        );
    }

    // ── Constants ───────────────────────────────────────────────────────

    #[test]
    fn default_constants_match_c_source() {
        assert_eq!(SOCKS_DEFAULT_PORT, 1080);
        assert_eq!(SOCKS_DEFAULT_TIMEOUT, 5);
        assert_eq!(DEFAULT_WEIGHT, 1);
        assert_eq!(DEFAULT_PRIORITY, 1);
        assert_eq!(MAX_PROXIES, 32);
    }

    // ── SocksProxy Defaults ─────────────────────────────────────────────

    #[test]
    fn socks_proxy_default_matches_c_defaults() {
        let p = SocksProxy::default();
        assert_eq!(p.port, 1080);
        assert_eq!(p.timeout, Duration::from_secs(5));
        assert_eq!(p.weight, 1);
        assert_eq!(p.priority, 1);
        assert!(!p.is_failed);
        assert!(matches!(p.auth, SocksAuth::None));
    }

    // ── SocksError Display ──────────────────────────────────────────────

    #[test]
    fn socks_error_display_all_variants() {
        let variants: Vec<SocksError> = vec![
            SocksError::GeneralFailure,
            SocksError::NotAllowed,
            SocksError::NetworkUnreachable,
            SocksError::HostUnreachable,
            SocksError::ConnectionRefused,
            SocksError::TtlExpired,
            SocksError::CommandNotSupported,
            SocksError::AddressTypeNotSupported,
            SocksError::AuthFailed,
            SocksError::Timeout,
            SocksError::IoError(io::Error::new(io::ErrorKind::BrokenPipe, "pipe")),
            SocksError::InvalidProxy("bad".into()),
            SocksError::NoProxiesAvailable,
            SocksError::ProtocolError("bad".into()),
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty(), "empty display for {:?}", v);
        }
    }

    // ── Tainted String ──────────────────────────────────────────────────

    #[test]
    fn tainted_string_wrapping() {
        let tainted: TaintedString = Tainted::new("10.0.0.1".to_string());
        assert_eq!(tainted.as_ref(), "10.0.0.1");
    }
}
