// exim-miscmods/src/proxy.rs — HAProxy PROXY Protocol v1/v2 Handler
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Rewrites `src/src/miscmods/proxy.c` (552 lines) into safe Rust.  Implements
// the HAProxy PROXY protocol (v1 text and v2 binary formats) for Exim MTA,
// parsing proxy headers to extract real client IP addresses and ports when Exim
// sits behind a load balancer or reverse proxy.
//
// Feature-gated: this module is only compiled when `proxy` feature is enabled
// (gate applied in `lib.rs` via `#[cfg(feature = "proxy")] pub mod proxy;`).
//
// # Safety
//
// This module contains **zero** `unsafe` code.  All socket I/O is performed
// through safe `std::io::Read` trait methods.  The byte-by-byte reading
// strategy from the C implementation is preserved to maintain TLS-on-connect
// safety — reads never consume beyond the PROXY header to avoid interfering
// with a subsequent TLS handshake.
//
// # Taint Tracking
//
// All data extracted from the PROXY header is wrapped in [`Tainted<T>`] because
// it originates from an external proxy connection header — an untrusted source
// per the HAProxy PROXY protocol specification.  Addresses and ports parsed
// from the proxy header must be explicitly validated (via
// [`Tainted::sanitize()`]) before use in security-sensitive contexts.
//
// # C Source Mapping
//
// | C function / symbol             | Rust replacement                  |
// |---------------------------------|-----------------------------------|
// | `proxy_protocol_host()`         | [`proxy_protocol_host()`]         |
// | `proxy_protocol()` (dispatch)   | [`proxy_protocol_start()`]        |
// | `swallow_until_crlf()`          | [`read_until_crlf()`] (internal)  |
// | `proxy_debug()`                 | `tracing::debug!` calls           |
// | `command_timeout_handler()`     | Socket read timeout via `Read`    |
// | `proxy_module_info` (C struct)  | `inventory::submit!` registration |
// | `PROXY_PROTO_START` (slot 0)    | [`PROXY_PROTO_START`] constant    |
// | `v2sig` (12-byte signature)     | [`PROXY_V2_SIGNATURE`] constant   |

use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(target_family = "unix")]
use std::os::unix::io::{BorrowedFd, RawFd};
use std::time::Duration;

use exim_drivers::{DriverError, DriverInfoBase};
use exim_store::taint::TaintState;
use exim_store::{Clean, Tainted, TaintedString};

// =============================================================================
// Public Constants
// =============================================================================

/// PROXY protocol v2 magic signature (12 bytes).
///
/// From the HAProxy PROXY protocol specification, the v2 header begins with
/// this exact 12-byte sequence.  Replaces the C `v2sig` local constant at
/// `proxy.c` line 210: `"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"`.
pub const PROXY_V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Function table slot index for the PROXY protocol start function.
///
/// Replaces C `#define PROXY_PROTO_START 0` from `proxy_api.h` line 14.
/// Used by the exim-drivers registry to resolve the proxy module's entry point
/// by index.
pub const PROXY_PROTO_START: usize = 0;

// =============================================================================
// Internal Constants
// =============================================================================

/// Number of bytes read in the initial probe to distinguish v1 from v2.
///
/// 14 bytes suffice because the v2 signature is 12 bytes (plus 2 more gives the
/// length field), and v1 always starts with "PROXY " (6 bytes).  Reading 14
/// bytes is safe for TLS-on-connect because the shortest valid v1 header
/// ("PROXY UNKNOWN\r\n") is 15 bytes, so we never over-read.
///
/// Replaces C `PROXY_INITIAL_READ` at `proxy.c` line 203.
const PROXY_INITIAL_READ: usize = 14;

/// Full v2 header size before address-specific data.
///
/// The v2 header consists of: 12-byte signature + 1 ver/cmd + 1 fam + 2 len
/// = 16 bytes total.  After reading these 16 bytes we know how many more bytes
/// of address data follow.
///
/// Replaces C `PROXY_V2_HEADER_SIZE` at `proxy.c` line 204.
const PROXY_V2_HEADER_SIZE: usize = 16;

/// Maximum total v2 header + address data size.
///
/// Derived from the C union `hdr` which is max(108, 16+216) = 232 bytes.
/// The largest v2 payload is AF_UNIX with 216 bytes of path data.  Any header
/// claiming more than this is rejected as a potential security attack.
///
/// Replaces C `sizeof(hdr)` check at `proxy.c` line 273.
const MAX_V2_TOTAL_SIZE: usize = 232;

/// Maximum v1 header line length including "PROXY " prefix and CRLF terminator.
///
/// Replaces C `hdr.v1.line[108]` field size at `proxy.c` line 144.
const PROXY_V1_MAX_LINE: usize = 108;

/// V2 command: LOCAL — health-check / internal, no address change.
///
/// Upper nibble is version (0x2), lower nibble is command (0x0).
/// When this command is received, the connection is treated as a local/health
/// connection and the original addresses are preserved.
///
/// Replaces C `case 0x00: /* LOCAL command */` at `proxy.c` line 367.
const V2_CMD_LOCAL: u8 = 0x00;

/// V2 command: PROXY — the proxy provides real client addresses.
///
/// Replaces C `case 0x01: /* PROXY command */` at `proxy.c` line 304.
const V2_CMD_PROXY: u8 = 0x01;

/// V2 family+protocol byte for TCPv4.
///
/// Bits 7-4 = address family (0x1 = AF_INET), bits 3-0 = protocol (0x1 = TCP).
/// Replaces C `case 0x11: /* TCPv4 address type */` at `proxy.c` line 307.
const V2_FAM_TCP4: u8 = 0x11;

/// V2 family+protocol byte for TCPv6.
///
/// Bits 7-4 = address family (0x2 = AF_INET6), bits 3-0 = protocol (0x1 = TCP).
/// Replaces C `case 0x21: /* TCPv6 address type */` at `proxy.c` line 333.
const V2_FAM_TCP6: u8 = 0x21;

/// System socket address family constant for IPv4.
///
/// Referenced for documentation and verification against PROXY v2 family values.
/// The PROXY v2 protocol uses its own family numbering (1 = INET) which maps to
/// `libc::AF_INET` in the system socket API.
#[allow(dead_code)] // Used for compile-time documentation and assertions
const SYSTEM_AF_INET: i32 = libc::AF_INET;

/// System socket address family constant for IPv6.
///
/// The PROXY v2 protocol family value 2 maps to `libc::AF_INET6`.
#[allow(dead_code)] // Used for compile-time documentation and assertions
const SYSTEM_AF_INET6: i32 = libc::AF_INET6;

/// Unspecified address family for the LOCAL command.
///
/// The v2 LOCAL command (0x20) indicates no specific address family,
/// corresponding to `libc::AF_UNSPEC` in the system socket API.
#[allow(dead_code)] // Used for compile-time documentation and assertions
const SYSTEM_AF_UNSPEC: i32 = libc::AF_UNSPEC;

/// The taint state of all PROXY-sourced data.
///
/// All data extracted from a PROXY header is inherently tainted because it
/// originates from an external proxy connection — an untrusted source per
/// the HAProxy PROXY protocol specification.
pub const PROXY_DATA_TAINT: TaintState = TaintState::Tainted;

// =============================================================================
// Type Aliases
// =============================================================================

/// File descriptor type for the SMTP connection socket.
///
/// In the C codebase, this was the global `smtp_in_fd` variable (an `int`).
/// In Rust, we pass the file descriptor explicitly.  Prefer [`BorrowedFd`]
/// for safe fd handling in new code; this alias exists for API compatibility.
#[cfg(target_family = "unix")]
pub type SmtpRawFd = RawFd;

/// Borrowed file descriptor reference for the SMTP connection socket.
///
/// In the C codebase, `smtp_in_fd` was a global integer fd.  In Rust, we use
/// [`BorrowedFd`] to express that proxy protocol processing borrows the socket
/// without taking ownership — the caller retains ownership and closes it.
#[cfg(target_family = "unix")]
pub type SmtpConnectionFd<'a> = BorrowedFd<'a>;

// =============================================================================
// Error Types
// =============================================================================

/// Error type for PROXY protocol processing failures.
///
/// Replaces the C ad-hoc error handling via `log_write(0, LOG_MAIN|LOG_REJECT, ...)`
/// calls and the `goto proxyfail` pattern throughout `proxy.c`.
///
/// Each variant corresponds to a specific failure mode in the original C code:
/// - `Timeout`          → C SIGALRM handler at `proxy.c` lines 19-23
/// - `InvalidSignature` → C fallthrough at `proxy.c` lines 496-502
/// - `InvalidV1Header`  → C parse failures at `proxy.c` lines 377-495
/// - `InvalidV2Header`  → C parse failures at `proxy.c` lines 234-375
/// - `UnsupportedFamily`→ C default cases at `proxy.c` lines 359-363
/// - `IoError`          → C `read()` failures at `proxy.c` lines 226-230
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// Proxy header read timed out.
    ///
    /// The socket read timeout elapsed before a complete PROXY header was
    /// received.  Replaces C `had_command_timeout` check after SIGALRM
    /// (proxy.c lines 19-23, 515-516).
    #[error("proxy header read timeout")]
    Timeout,

    /// The initial bytes did not match either v1 or v2 proxy signatures.
    ///
    /// Replaces C "Invalid proxy protocol version negotiation" error
    /// (proxy.c line 499).
    #[error("invalid proxy protocol signature")]
    InvalidSignature,

    /// PROXY v1 text header is malformed.
    ///
    /// Replaces multiple C parse error paths in the v1 parsing block
    /// (proxy.c lines 377-495).
    #[error("invalid PROXY v1 header: {0}")]
    InvalidV1Header(String),

    /// PROXY v2 binary header is malformed.
    ///
    /// Replaces multiple C parse error paths in the v2 parsing block
    /// (proxy.c lines 234-375).
    #[error("invalid PROXY v2 header: {0}")]
    InvalidV2Header(String),

    /// Unsupported address family in v2 header.
    ///
    /// The v2 header contained an address family other than TCPv4 (0x11) or
    /// TCPv6 (0x21).  AF_UNIX (0x31) and other families are not supported.
    ///
    /// Replaces C "Unsupported PROXYv2 connection type" error
    /// (proxy.c lines 360-362).
    #[error("unsupported address family in PROXY v2 header")]
    UnsupportedFamily,

    /// I/O error during proxy header reading.
    ///
    /// Wraps `std::io::Error` for socket read failures.  Replaces C
    /// `read() == -1` error paths (proxy.c lines 226-230, 246-247, 285-286).
    #[error("I/O error reading proxy header: {0}")]
    IoError(#[from] std::io::Error),
}

/// Conversion from [`ProxyError`] to [`DriverError`] for integration with the
/// exim-drivers error handling infrastructure.
impl From<ProxyError> for DriverError {
    fn from(err: ProxyError) -> Self {
        DriverError::ExecutionFailed(err.to_string())
    }
}

// =============================================================================
// Data Structures
// =============================================================================

/// PROXY protocol version detected during header parsing.
///
/// Replaces the C `iptype` string used for debug logging and the implicit
/// version tracking through code paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyVersion {
    /// PROXY protocol v1 — text-based header format.
    /// Format: `PROXY TCP4|TCP6 srcip dstip srcport dstport\r\n`
    V1,

    /// PROXY protocol v2 — binary header format.
    /// 12-byte signature + version/command + family + length + address data.
    V2,

    /// LOCAL / UNKNOWN connection — no address change.
    /// V1 "PROXY UNKNOWN\r\n" or V2 LOCAL command (0x20).
    /// Used for health checks and local connections through the proxy.
    Local,
}

impl std::fmt::Display for ProxyVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyVersion::V1 => write!(f, "v1"),
            ProxyVersion::V2 => write!(f, "v2"),
            ProxyVersion::Local => write!(f, "local"),
        }
    }
}

/// Parsed PROXY protocol header result.
///
/// Contains the source (client) and destination (proxy-facing) addresses and
/// ports extracted from a valid PROXY protocol header.
///
/// All address fields are wrapped in [`Tainted`] because they originate from
/// an external proxy connection header — an untrusted source.  This replaces
/// the C pattern where `sender_host_address`, `proxy_local_address`, and
/// `proxy_external_address` were set via `string_copy()` without explicit
/// taint tracking (proxy.c lines 316-331 for v2 IPv4, 342-357 for v2 IPv6,
/// 447-493 for v1).
///
/// # Fields
///
/// - `src_address` — Real client IP address (replaces C `sender_host_address`
///   after proxy rewrite)
/// - `src_port` — Real client port (replaces C `sender_host_port`)
/// - `dst_address` — Proxy-facing destination address (replaces C
///   `proxy_external_address`)
/// - `dst_port` — Proxy-facing destination port (replaces C
///   `proxy_external_port`)
/// - `version` — Which PROXY protocol version was detected
#[derive(Debug, Clone)]
pub struct ProxyResult {
    /// Real client source IP address from the PROXY header.
    ///
    /// Tainted: originates from the external proxy connection.
    /// Replaces C global `sender_host_address` after proxy rewrite.
    pub src_address: TaintedString,

    /// Real client source port from the PROXY header.
    ///
    /// Replaces C global `sender_host_port` after proxy rewrite.
    pub src_port: u16,

    /// Proxy-facing destination IP address.
    ///
    /// Tainted: originates from the external proxy connection.
    /// Replaces C global `proxy_external_address`.
    pub dst_address: TaintedString,

    /// Proxy-facing destination port.
    ///
    /// Replaces C global `proxy_external_port`.
    pub dst_port: u16,

    /// PROXY protocol version that was detected and parsed.
    pub version: ProxyVersion,
}

// =============================================================================
// Internal I/O Helpers
// =============================================================================

/// Read exactly `buf.len()` bytes from the reader, handling EINTR retries and
/// timeout detection.
///
/// Replaces the C `do { ret = read(fd, ...); } while (ret == -1 && errno == EINTR)`
/// loop pattern found at proxy.c lines 220-227, 242-245, 279-284.
///
/// # Timeout Handling
///
/// The caller is expected to have configured a read timeout on the underlying
/// socket (e.g., via `TcpStream::set_read_timeout()`).  If a read times out,
/// the socket returns `ErrorKind::WouldBlock` or `ErrorKind::TimedOut`, which
/// this function converts to [`ProxyError::Timeout`].
fn read_exact_bytes<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<(), ProxyError> {
    let mut offset = 0;
    while offset < buf.len() {
        match reader.read(&mut buf[offset..]) {
            Ok(0) => {
                return Err(ProxyError::IoError(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "unexpected EOF reading proxy header (got {}/{} bytes)",
                        offset,
                        buf.len()
                    ),
                )));
            }
            Ok(n) => {
                offset += n;
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {
                // EINTR — retry the read (replaces C errno == EINTR check)
                continue;
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                return Err(ProxyError::Timeout);
            }
            Err(e) => {
                return Err(ProxyError::IoError(e));
            }
        }
    }
    Ok(())
}

/// Read one byte at a time until a CRLF terminator is found.
///
/// This byte-by-byte strategy is **critical for TLS-on-connect safety**: we
/// must not read beyond the PROXY header because the bytes following it may be
/// the start of a TLS handshake.  The C implementation has the same constraint
/// (see `swallow_until_crlf()` at proxy.c lines 73-116).
///
/// # Arguments
///
/// - `reader` — The socket reader
/// - `buf` — Buffer already containing the initial bytes; new bytes are appended
/// - `max_capacity` — Maximum total buffer size (prevents unbounded growth)
///
/// # Returns
///
/// `Ok(())` when CRLF is found, `Err` on I/O error, timeout, or overflow.
fn read_until_crlf<R: Read>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max_capacity: usize,
) -> Result<(), ProxyError> {
    // Check if the last byte already in the buffer is \r (handles the case
    // where initial_read captured up through the \r, e.g., "PROXY UNKNOWN\r")
    let mut saw_cr = buf.last() == Some(&b'\r');
    let mut single = [0u8; 1];

    while buf.len() < max_capacity {
        read_exact_bytes(reader, &mut single)?;
        buf.push(single[0]);

        if saw_cr && single[0] == b'\n' {
            return Ok(());
        }
        saw_cr = single[0] == b'\r';
    }

    // Reached max capacity without finding CRLF — protocol error
    Err(ProxyError::InvalidV1Header(
        "v1 header line exceeds maximum length without CRLF terminator".to_string(),
    ))
}

/// Check if a byte slice contains a CRLF (`\r\n`) sequence.
fn contains_crlf(data: &[u8]) -> bool {
    data.windows(2).any(|w| w == b"\r\n")
}

/// Log a hex dump of proxy protocol wire data for debugging.
///
/// Replaces C `proxy_debug()` helper at proxy.c lines 119-123 which outputs
/// a hex dump under the `D_receive` debug selector.
fn log_wire_data(label: &str, data: &[u8]) {
    if tracing::enabled!(tracing::Level::DEBUG) {
        let hex: String = data
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        tracing::debug!("PROXY<<{label}: [{len}] {hex}", len = data.len());
    }
}

// =============================================================================
// PROXY v1 Text Header Parser
// =============================================================================

/// Parse a PROXY protocol v1 text header from the given buffer.
///
/// The v1 format is a single ASCII line terminated by CRLF:
/// ```text
/// PROXY TCP4 srcip dstip srcport dstport\r\n
/// PROXY TCP6 srcip dstip srcport dstport\r\n
/// PROXY UNKNOWN\r\n
/// ```
///
/// Replaces the v1 parsing block in C `proxy_protocol()` at proxy.c lines
/// 377-495.
///
/// # Validation
///
/// - Address family must be TCP4, TCP6, or UNKNOWN
/// - Source and destination IP addresses must be valid
/// - Port numbers must be valid non-zero `u16` values
/// - Exactly 4 space-separated fields after the family tag
fn parse_proxy_v1(data: &[u8]) -> Result<ProxyResult, ProxyError> {
    // Find the CRLF terminator
    let crlf_pos = data
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or_else(|| ProxyError::InvalidV1Header("missing CRLF terminator".to_string()))?;

    // Convert to UTF-8 string (PROXY v1 is pure ASCII)
    let line = std::str::from_utf8(&data[..crlf_pos])
        .map_err(|_| ProxyError::InvalidV1Header("header contains non-UTF8 bytes".to_string()))?;

    tracing::debug!("PROXYv1 header line: {:?}", line);

    // Must start with "PROXY "
    let rest = line
        .strip_prefix("PROXY ")
        .ok_or_else(|| ProxyError::InvalidV1Header("missing 'PROXY ' prefix".to_string()))?;

    // Handle "PROXY UNKNOWN\r\n" — local/health-check with no address change
    if rest.starts_with("UNKNOWN") {
        tracing::debug!("PROXYv1 UNKNOWN — no address change (local/health-check)");
        return Ok(ProxyResult {
            src_address: Tainted::new(String::new()),
            src_port: 0,
            dst_address: Tainted::new(String::new()),
            dst_port: 0,
            version: ProxyVersion::Local,
        });
    }

    // Parse address family: TCP4 or TCP6
    let (family_label, rest) = if let Some(r) = rest.strip_prefix("TCP4 ") {
        ("IPv4", r)
    } else if let Some(r) = rest.strip_prefix("TCP6 ") {
        ("IPv6", r)
    } else {
        return Err(ProxyError::InvalidV1Header(
            "invalid address family (expected TCP4 or TCP6)".to_string(),
        ));
    };

    // Parse the 4 remaining fields: srcip dstip srcport dstport
    let parts: Vec<&str> = rest.splitn(5, ' ').collect();
    if parts.len() != 4 {
        return Err(ProxyError::InvalidV1Header(format!(
            "expected 4 space-separated fields after {family_label}, got {}",
            parts.len()
        )));
    }

    let src_ip_str = parts[0];
    let dst_ip_str = parts[1];
    let src_port_str = parts[2];
    let dst_port_str = parts[3];

    // Validate source IP address
    let _src_ip: IpAddr = src_ip_str.parse().map_err(|_| {
        ProxyError::InvalidV1Header(format!(
            "proxied src arg is not a valid {family_label} address: {src_ip_str}"
        ))
    })?;

    // Validate destination IP address
    let _dst_ip: IpAddr = dst_ip_str.parse().map_err(|_| {
        ProxyError::InvalidV1Header(format!(
            "proxied dst arg is not a valid {family_label} address: {dst_ip_str}"
        ))
    })?;

    // Validate source port (must be a non-zero u16)
    let src_port: u16 = src_port_str.parse().map_err(|_| {
        ProxyError::InvalidV1Header(format!(
            "proxied src port '{src_port_str}' is not a valid integer"
        ))
    })?;
    if src_port == 0 {
        return Err(ProxyError::InvalidV1Header(
            "proxied src port must be non-zero".to_string(),
        ));
    }

    // Validate destination port (must be a non-zero u16)
    let dst_port: u16 = dst_port_str.parse().map_err(|_| {
        ProxyError::InvalidV1Header(format!(
            "proxied dst port '{dst_port_str}' is not a valid integer"
        ))
    })?;
    if dst_port == 0 {
        return Err(ProxyError::InvalidV1Header(
            "proxied dst port must be non-zero".to_string(),
        ));
    }

    tracing::debug!(
        "PROXYv1 parsed: {family_label} src={src_ip_str}:{src_port} dst={dst_ip_str}:{dst_port}"
    );

    Ok(ProxyResult {
        src_address: Tainted::new(src_ip_str.to_string()),
        src_port,
        dst_address: Tainted::new(dst_ip_str.to_string()),
        dst_port,
        version: ProxyVersion::V1,
    })
}

// =============================================================================
// PROXY v2 Binary Header Parser
// =============================================================================

/// Parse a PROXY protocol v2 binary header from the given buffer.
///
/// The v2 format is:
/// ```text
/// [12-byte signature][ver_cmd:1][fam:1][len:2][address data: len bytes]
/// ```
///
/// - Signature: [`PROXY_V2_SIGNATURE`] (12 bytes)
/// - `ver_cmd`: upper nibble = version (must be 0x2), lower nibble = command
///   (0x0 = LOCAL, 0x1 = PROXY)
/// - `fam`: upper nibble = address family (1=INET, 2=INET6), lower nibble =
///   protocol (1=TCP, 2=UDP)
/// - `len`: network-byte-order length of the address data following the header
///
/// Replaces the v2 parsing block in C `proxy_protocol()` at proxy.c lines
/// 234-375.
///
/// # Address Data
///
/// - TCPv4 (0x11): 12 bytes — src_addr[4] + dst_addr[4] + src_port[2] +
///   dst_port[2]
/// - TCPv6 (0x21): 36 bytes — src_addr[16] + dst_addr[16] + src_port[2] +
///   dst_port[2]
fn parse_proxy_v2(data: &[u8]) -> Result<ProxyResult, ProxyError> {
    if data.len() < PROXY_V2_HEADER_SIZE {
        return Err(ProxyError::InvalidV2Header(format!(
            "header too short: need {} bytes, have {}",
            PROXY_V2_HEADER_SIZE,
            data.len()
        )));
    }

    // Verify the 12-byte signature
    if data[..12] != PROXY_V2_SIGNATURE {
        return Err(ProxyError::InvalidSignature);
    }

    // Parse version from upper nibble of byte 13 (ver_cmd)
    let ver_cmd = data[12];
    let ver = (ver_cmd & 0xf0) >> 4;
    let cmd = ver_cmd & 0x0f;

    // Version must be 0x2 (proxy.c lines 252-263)
    if ver != 0x02 {
        tracing::warn!("Invalid PROXYv2 version: {ver}");
        return Err(ProxyError::InvalidV2Header(format!(
            "invalid protocol version: {ver} (expected 2)"
        )));
    }

    // Parse address family + protocol from byte 14
    let fam = data[13];

    // Parse address data length from bytes 15-16 (network byte order)
    let addr_len = u16::from_be_bytes([data[14], data[15]]) as usize;
    let total_size = PROXY_V2_HEADER_SIZE + addr_len;

    tracing::debug!(
        "PROXYv2 header: cmd=0x{cmd:02x} fam=0x{fam:02x} addr_len={addr_len} total={total_size}"
    );

    // Verify we have enough data
    if data.len() < total_size {
        return Err(ProxyError::InvalidV2Header(format!(
            "need {total_size} bytes of data, have {}",
            data.len()
        )));
    }

    match cmd {
        V2_CMD_LOCAL => {
            // LOCAL command — health check / internal connection.
            // No address change; the original connection addresses are preserved.
            // This corresponds to libc::AF_UNSPEC in the system socket API.
            tracing::debug!(
                "PROXYv2 LOCAL command (system AF_UNSPEC={}) — no address change",
                SYSTEM_AF_UNSPEC
            );
            Ok(ProxyResult {
                src_address: Tainted::new(String::new()),
                src_port: 0,
                dst_address: Tainted::new(String::new()),
                dst_port: 0,
                version: ProxyVersion::Local,
            })
        }

        V2_CMD_PROXY => {
            // PROXY command — extract real client addresses
            let addr_data = &data[PROXY_V2_HEADER_SIZE..total_size];

            match fam {
                V2_FAM_TCP4 => parse_v2_tcp4(addr_data),
                V2_FAM_TCP6 => parse_v2_tcp6(addr_data),
                _ => {
                    tracing::warn!("Unsupported PROXYv2 connection type: 0x{fam:02x}");
                    Err(ProxyError::UnsupportedFamily)
                }
            }
        }

        _ => {
            tracing::warn!("Unsupported PROXYv2 command: 0x{cmd:02x}");
            Err(ProxyError::InvalidV2Header(format!(
                "unsupported command: 0x{cmd:02x}"
            )))
        }
    }
}

/// Parse TCPv4 address data from a PROXY v2 header.
///
/// Expects exactly 12 bytes: src_addr[4] + dst_addr[4] + src_port[2] +
/// dst_port[2].  Corresponds to `libc::AF_INET` in the system socket API
/// and proxy.c lines 258-290.
fn parse_v2_tcp4(addr_data: &[u8]) -> Result<ProxyResult, ProxyError> {
    const IPV4_ADDR_LEN: usize = 12;
    if addr_data.len() < IPV4_ADDR_LEN {
        return Err(ProxyError::InvalidV2Header(format!(
            "IPv4 address data too short: need {IPV4_ADDR_LEN}, have {}",
            addr_data.len()
        )));
    }

    tracing::debug!(
        "PROXYv2 TCPv4 (system AF_INET={}) address data",
        SYSTEM_AF_INET
    );

    // Extract source address (4 bytes at offset 0)
    let src_addr = Ipv4Addr::new(addr_data[0], addr_data[1], addr_data[2], addr_data[3]);
    // Extract destination address (4 bytes at offset 4)
    let dst_addr = Ipv4Addr::new(addr_data[4], addr_data[5], addr_data[6], addr_data[7]);
    // Extract ports (network byte order, 2 bytes each at offsets 8 and 10)
    let src_port = u16::from_be_bytes([addr_data[8], addr_data[9]]);
    let dst_port = u16::from_be_bytes([addr_data[10], addr_data[11]]);

    // Convert to string representation (replaces C inet_ntop)
    let src_str = IpAddr::V4(src_addr).to_string();
    let dst_str = IpAddr::V4(dst_addr).to_string();

    tracing::debug!("PROXYv2 IPv4: src={src_str}:{src_port} dst={dst_str}:{dst_port}");

    Ok(ProxyResult {
        src_address: Tainted::new(src_str),
        src_port,
        dst_address: Tainted::new(dst_str),
        dst_port,
        version: ProxyVersion::V2,
    })
}

/// Parse TCPv6 address data from a PROXY v2 header.
///
/// Expects exactly 36 bytes: src_addr[16] + dst_addr[16] + src_port[2] +
/// dst_port[2].  Corresponds to `libc::AF_INET6` in the system socket API
/// and proxy.c lines 292-325.
fn parse_v2_tcp6(addr_data: &[u8]) -> Result<ProxyResult, ProxyError> {
    const IPV6_ADDR_LEN: usize = 36;
    if addr_data.len() < IPV6_ADDR_LEN {
        return Err(ProxyError::InvalidV2Header(format!(
            "IPv6 address data too short: need {IPV6_ADDR_LEN}, have {}",
            addr_data.len()
        )));
    }

    tracing::debug!(
        "PROXYv2 TCPv6 (system AF_INET6={}) address data",
        SYSTEM_AF_INET6
    );

    // Extract source address (16 bytes at offset 0)
    let mut src_octets = [0u8; 16];
    src_octets.copy_from_slice(&addr_data[..16]);
    let src_addr = Ipv6Addr::from(src_octets);

    // Extract destination address (16 bytes at offset 16)
    let mut dst_octets = [0u8; 16];
    dst_octets.copy_from_slice(&addr_data[16..32]);
    let dst_addr = Ipv6Addr::from(dst_octets);

    // Extract ports (network byte order, 2 bytes each)
    let src_port = u16::from_be_bytes([addr_data[32], addr_data[33]]);
    let dst_port = u16::from_be_bytes([addr_data[34], addr_data[35]]);

    // Convert to string representation
    let src_str = IpAddr::V6(src_addr).to_string();
    let dst_str = IpAddr::V6(dst_addr).to_string();

    tracing::debug!("PROXYv2 IPv6: src={src_str}:{src_port} dst={dst_str}:{dst_port}");

    Ok(ProxyResult {
        src_address: Tainted::new(src_str),
        src_port,
        dst_address: Tainted::new(dst_str),
        dst_port,
        version: ProxyVersion::V2,
    })
}

// =============================================================================
// Public API — Main Entry Point
// =============================================================================

/// Start PROXY protocol processing on an SMTP connection.
///
/// This is the main entry point for proxy protocol handling, registered as
/// function slot [`PROXY_PROTO_START`] in the module's function table.
///
/// Reads the initial bytes from the connection to determine whether the client
/// is sending a PROXY v1 (text) or v2 (binary) header, then dispatches to the
/// appropriate parser.
///
/// # Reading Strategy
///
/// The function uses a three-read minimum strategy for safety:
/// 1. Read 14 bytes (enough to distinguish v1 from v2)
/// 2. For v2: read 2 more bytes to get the length, then read the address data
/// 3. For v1: read byte-by-byte until CRLF (critical for TLS-on-connect safety)
///
/// This matches the C implementation's reading strategy at proxy.c lines
/// 179-201.
///
/// # Timeout Handling
///
/// The `timeout` parameter specifies the maximum duration to wait for the
/// complete PROXY header.  The caller should configure the underlying socket's
/// read timeout before calling this function (e.g., via
/// `TcpStream::set_read_timeout()`).  Timeout errors from the reader are
/// converted to [`ProxyError::Timeout`].
///
/// # Arguments
///
/// - `reader` — A readable stream for the SMTP connection socket.  Must be
///   configured with an appropriate read timeout.
/// - `timeout` — Maximum duration to wait for the proxy header (used for
///   documentation and future explicit timer support).
///
/// # Returns
///
/// - `Ok(ProxyResult)` — Successfully parsed proxy header with client addresses
/// - `Err(ProxyError)` — Protocol error, timeout, or I/O failure
pub fn proxy_protocol_start<R: Read>(
    reader: &mut R,
    _timeout: Duration,
) -> Result<ProxyResult, ProxyError> {
    // Phase 1: Read initial 14 bytes to distinguish v1 vs v2
    //
    // 14 bytes is safe because:
    // - v2 signature is 12 bytes (we get the full signature)
    // - v1 always starts with "PROXY " (6 bytes) and the shortest valid v1
    //   header ("PROXY UNKNOWN\r\n") is 15 bytes, so we never over-read
    let mut initial = [0u8; PROXY_INITIAL_READ];
    read_exact_bytes(reader, &mut initial)?;

    log_wire_data("initial", &initial);

    // Phase 2: Dispatch based on header signature
    if initial[..12] == PROXY_V2_SIGNATURE {
        // --- PROXY v2 binary header ---
        tracing::debug!("Detected PROXYv2 header");

        // Read the remaining 2 bytes of the 16-byte fixed header
        // (bytes 15-16 contain the address data length)
        let mut rest_header = [0u8; PROXY_V2_HEADER_SIZE - PROXY_INITIAL_READ];
        read_exact_bytes(reader, &mut rest_header)?;
        log_wire_data("v2-hdr-rest", &rest_header);

        // Combine into the full 16-byte header
        let mut header = [0u8; PROXY_V2_HEADER_SIZE];
        header[..PROXY_INITIAL_READ].copy_from_slice(&initial);
        header[PROXY_INITIAL_READ..].copy_from_slice(&rest_header);

        // Extract address data length from bytes 15-16 (network byte order)
        let addr_len = u16::from_be_bytes([header[14], header[15]]) as usize;
        let total_size = PROXY_V2_HEADER_SIZE + addr_len;

        tracing::debug!("PROXYv2 header: total_size={total_size} (limit={MAX_V2_TOTAL_SIZE})");

        // Reject unreasonably large headers (security check)
        if total_size > MAX_V2_TOTAL_SIZE {
            tracing::error!(
                "PROXYv2 header size {total_size} unreasonably large \
                 (max {MAX_V2_TOTAL_SIZE}); possible attack?"
            );
            return Err(ProxyError::InvalidV2Header(format!(
                "header size {total_size} exceeds maximum {MAX_V2_TOTAL_SIZE}"
            )));
        }

        // Read the address data
        let mut full_buf = vec![0u8; total_size];
        full_buf[..PROXY_V2_HEADER_SIZE].copy_from_slice(&header);
        if addr_len > 0 {
            read_exact_bytes(reader, &mut full_buf[PROXY_V2_HEADER_SIZE..])?;
            log_wire_data("v2-addr", &full_buf[PROXY_V2_HEADER_SIZE..]);
        }

        let result = parse_proxy_v2(&full_buf)?;

        tracing::info!(
            "Valid PROXYv2 sender parsed: version={}, src={}:{}",
            result.version,
            result.src_address.as_ref(),
            result.src_port,
        );

        Ok(result)
    } else if initial.starts_with(b"PROXY") {
        // --- PROXY v1 text header ---
        tracing::debug!("Detected PROXYv1 header");

        // Accumulate the header line, starting with the bytes already read
        let mut buf = Vec::with_capacity(PROXY_V1_MAX_LINE);
        buf.extend_from_slice(&initial);

        // Check if we already have a complete CRLF-terminated line
        if !contains_crlf(&buf) {
            // Read byte-by-byte until CRLF — this is CRITICAL for TLS-on-connect
            // safety.  We must not read beyond the PROXY header because the next
            // bytes may be a TLS ClientHello that must be consumed by the TLS
            // library, not by us.
            read_until_crlf(reader, &mut buf, PROXY_V1_MAX_LINE)?;
        }

        log_wire_data("v1-complete", &buf);

        let result = parse_proxy_v1(&buf)?;

        tracing::info!(
            "Valid PROXYv1 sender parsed: version={}, src={}:{}",
            result.version,
            result.src_address.as_ref(),
            result.src_port,
        );

        Ok(result)
    } else {
        // Neither v1 nor v2 — invalid proxy protocol negotiation
        tracing::warn!("Invalid proxy protocol version negotiation");

        // Attempt to consume the rest of any line to avoid leaving partial data
        // in the socket buffer (best-effort cleanup)
        let mut cleanup_buf = Vec::with_capacity(PROXY_V1_MAX_LINE);
        cleanup_buf.extend_from_slice(&initial);
        let _ = read_until_crlf(reader, &mut cleanup_buf, PROXY_V1_MAX_LINE);

        Err(ProxyError::InvalidSignature)
    }
}

// =============================================================================
// Public API — Host Checking
// =============================================================================

/// Check if the connecting host is in the `hosts_proxy` list.
///
/// Determines whether the inbound host is configured to use the PROXY protocol.
/// A local connection (empty host address) cannot use proxy protocol.
///
/// Replaces C `proxy_protocol_host()` at proxy.c lines 36-49, which accessed
/// the global `sender_host_address` and `hosts_proxy` variables and called
/// `verify_check_this_host()`.
///
/// # Arguments
///
/// - `host_address` — The connecting host's IP address string (replaces C
///   global `sender_host_address`)
/// - `hosts_proxy` — Colon-separated list of allowed proxy hosts from
///   configuration (replaces C global `hosts_proxy`)
///
/// # Matching Rules
///
/// Supports the following match types (subset of Exim host list matching):
/// - Exact IP address match (e.g., `"10.0.0.1"`)
/// - CIDR notation match (e.g., `"10.0.0.0/8"`, `"::1/128"`)
/// - Wildcard `"*"` matches any host
///
/// # Returns
///
/// `true` if the host is in the proxy hosts list and proxy protocol should be
/// expected, `false` otherwise.
pub fn proxy_protocol_host(host_address: &str, hosts_proxy: &str) -> bool {
    // A local connection (no host address) cannot use proxy protocol
    if host_address.is_empty() {
        return false;
    }

    // Empty hosts_proxy means no hosts configured for proxy protocol
    if hosts_proxy.is_empty() {
        return false;
    }

    // Parse the host address for CIDR comparison
    let host_ip: Option<IpAddr> = host_address.parse().ok();

    // Split the host list into individual entries using Exim-aware parsing
    // that handles IPv6 addresses containing colons.
    let entries = split_host_list(hosts_proxy);

    for entry in &entries {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }

        // Wildcard match — any host
        if entry == "*" {
            tracing::debug!("host {} matched wildcard '*' in hosts_proxy", host_address);
            return true;
        }

        // Exact IP/hostname match
        if entry == host_address {
            tracing::debug!("host {host_address} matched exact entry '{entry}' in hosts_proxy");
            return true;
        }

        // CIDR notation match (e.g., "10.0.0.0/8", "2001:db8::/32")
        if entry.contains('/') {
            if let Some(ref ip) = host_ip {
                if matches_cidr(*ip, entry) {
                    tracing::debug!("host {host_address} matched CIDR '{entry}' in hosts_proxy");
                    return true;
                }
            }
        }
    }

    false
}

/// Validate proxy addresses by sanitizing them from [`Tainted`] to [`Clean`].
///
/// Takes the tainted proxy result addresses and validates them by parsing as
/// IP addresses.  Returns clean (validated) versions suitable for use in
/// security-sensitive contexts.
///
/// This demonstrates the taint-tracking flow: proxy-sourced data starts as
/// `Tainted<String>`, is validated, and becomes `Clean<String>`.
pub fn validate_proxy_addresses(
    result: &ProxyResult,
) -> Result<(Clean<String>, Clean<String>), ProxyError> {
    // For LOCAL/UNKNOWN, empty addresses are valid
    let src_clean = result
        .src_address
        .clone()
        .sanitize(|s| s.is_empty() || s.parse::<IpAddr>().is_ok())
        .map_err(|_| {
            ProxyError::InvalidV1Header(format!(
                "invalid source address: {}",
                result.src_address.as_ref()
            ))
        })?;

    let dst_clean = result
        .dst_address
        .clone()
        .sanitize(|s| s.is_empty() || s.parse::<IpAddr>().is_ok())
        .map_err(|_| {
            ProxyError::InvalidV1Header(format!(
                "invalid dest address: {}",
                result.dst_address.as_ref()
            ))
        })?;

    Ok((src_clean, dst_clean))
}

// =============================================================================
// Host List Parsing Helper
// =============================================================================

/// Split a host list string into individual entries, correctly handling IPv6
/// addresses that contain colons.
///
/// Exim host lists normally use colons as separators, but IPv6 addresses also
/// contain colons, creating ambiguity.  This function handles the following
/// cases:
///
/// 1. **Explicit semicolon separator** — If `list` starts with `<;`, semicolons
///    are used as the entry separator (Exim convention for IPv6 lists).
/// 2. **Single entry** — If the entire string is a valid IP, CIDR, or wildcard,
///    it is returned as-is without splitting.
/// 3. **Colon-separated list** — IPv4-only lists split normally on colons.
///
/// The function first tries to interpret the whole string as a single entry
/// (which handles IPv6 CIDR like `"2001:db8::/32"` correctly), then falls
/// back to colon-splitting for multi-entry lists.
fn split_host_list(list: &str) -> Vec<String> {
    // Case 1: Explicit semicolon separator (Exim "<;" prefix)
    if let Some(rest) = list.strip_prefix("<;") {
        return rest
            .split(';')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }

    // Case 2: Try the whole string as a single entry.
    //
    // This handles IPv6 addresses and IPv6 CIDR patterns that contain colons
    // (e.g., "2001:db8::1", "::1/128", "2001:db8::/32").  We check if the
    // whole string is:
    // - A valid IP address (v4 or v6), or
    // - A valid CIDR pattern (network/prefix where network is a valid IP), or
    // - A wildcard "*"
    if is_single_host_entry(list) {
        return vec![list.to_string()];
    }

    // Case 3: Standard colon-separated list
    list.split(':')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Determine if a string represents a single host list entry (as opposed to a
/// colon-separated list of entries).
///
/// Returns `true` if the string is:
/// - A wildcard `"*"`
/// - A negated entry (starts with `"!"`)
/// - A valid IPv4 or IPv6 address
/// - A valid CIDR pattern (IP/prefix)
fn is_single_host_entry(entry: &str) -> bool {
    let entry = entry.trim();

    // Wildcard
    if entry == "*" {
        return true;
    }

    // Negated entry
    let check = if let Some(rest) = entry.strip_prefix('!') {
        rest.trim()
    } else {
        entry
    };

    // Plain IP address
    if check.parse::<IpAddr>().is_ok() {
        return true;
    }

    // CIDR pattern: IP/prefix
    if let Some(slash_pos) = check.rfind('/') {
        let network = &check[..slash_pos];
        let prefix = &check[slash_pos + 1..];
        if network.parse::<IpAddr>().is_ok() && prefix.parse::<u32>().is_ok() {
            return true;
        }
    }

    false
}

// =============================================================================
// CIDR Matching Helper
// =============================================================================

/// Check if an IP address matches a CIDR notation pattern.
///
/// Supports both IPv4 CIDR (e.g., "10.0.0.0/8") and IPv6 CIDR (e.g.,
/// "2001:db8::/32").  Returns `false` for mixed address families (IPv4 address
/// against IPv6 CIDR and vice versa) or malformed CIDR strings.
fn matches_cidr(addr: IpAddr, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.splitn(2, '/').collect();
    if parts.len() != 2 {
        return false;
    }

    let network_addr: IpAddr = match parts[0].parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    let prefix_len: u32 = match parts[1].parse() {
        Ok(l) => l,
        Err(_) => return false,
    };

    match (addr, network_addr) {
        (IpAddr::V4(host), IpAddr::V4(net)) => {
            if prefix_len > 32 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let mask = u32::MAX.checked_shl(32 - prefix_len).unwrap_or(0);
            (u32::from(host) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(host), IpAddr::V6(net)) => {
            if prefix_len > 128 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let mask = u128::MAX.checked_shl(128 - prefix_len).unwrap_or(0);
            (u128::from(host) & mask) == (u128::from(net) & mask)
        }
        _ => {
            // Mixed address families never match
            false
        }
    }
}

// =============================================================================
// Module Registration
// =============================================================================

// Register the proxy module with the exim-drivers registry.
//
// Replaces the C `misc_module_info proxy_module_info` struct at proxy.c lines
// 539-547:
//   misc_module_info proxy_module_info = {
//     .name = US"proxy",
//     .dyn_magic = MISC_MODULE_MAGIC,
//     .functions = proxy_functions,
//     .functions_count = nelem(proxy_functions),
//   };
//
// The `inventory::submit!` macro registers this module at compile time,
// allowing runtime discovery by the driver registry when the configuration
// references `proxy` module capabilities.
inventory::submit! {
    DriverInfoBase::new("proxy")
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // =========================================================================
    // PROXY v1 Parser Tests
    // =========================================================================

    #[test]
    fn test_parse_v1_tcp4() {
        let data = b"PROXY TCP4 192.168.1.100 10.0.0.1 56324 443\r\n";
        let result = parse_proxy_v1(data).expect("should parse valid TCP4");
        assert_eq!(result.version, ProxyVersion::V1);
        assert_eq!(result.src_address.as_ref(), "192.168.1.100");
        assert_eq!(result.src_port, 56324);
        assert_eq!(result.dst_address.as_ref(), "10.0.0.1");
        assert_eq!(result.dst_port, 443);
    }

    #[test]
    fn test_parse_v1_tcp6() {
        let data = b"PROXY TCP6 2001:db8::1 ::1 12345 25\r\n";
        let result = parse_proxy_v1(data).expect("should parse valid TCP6");
        assert_eq!(result.version, ProxyVersion::V1);
        assert_eq!(result.src_address.as_ref(), "2001:db8::1");
        assert_eq!(result.src_port, 12345);
        assert_eq!(result.dst_address.as_ref(), "::1");
        assert_eq!(result.dst_port, 25);
    }

    #[test]
    fn test_parse_v1_unknown() {
        let data = b"PROXY UNKNOWN\r\n";
        let result = parse_proxy_v1(data).expect("should parse UNKNOWN");
        assert_eq!(result.version, ProxyVersion::Local);
        assert_eq!(result.src_address.as_ref(), "");
        assert_eq!(result.src_port, 0);
    }

    #[test]
    fn test_parse_v1_missing_crlf() {
        let data = b"PROXY TCP4 1.2.3.4 5.6.7.8 100 200";
        let result = parse_proxy_v1(data);
        assert!(result.is_err());
        match result.unwrap_err() {
            ProxyError::InvalidV1Header(msg) => {
                assert!(msg.contains("CRLF"), "error should mention CRLF: {msg}");
            }
            other => panic!("expected InvalidV1Header, got: {other:?}"),
        }
    }

    #[test]
    fn test_parse_v1_invalid_family() {
        let data = b"PROXY UDP4 1.2.3.4 5.6.7.8 100 200\r\n";
        let result = parse_proxy_v1(data);
        assert!(result.is_err());
        match result.unwrap_err() {
            ProxyError::InvalidV1Header(msg) => {
                assert!(msg.contains("address family"), "{msg}");
            }
            other => panic!("expected InvalidV1Header, got: {other:?}"),
        }
    }

    #[test]
    fn test_parse_v1_invalid_ip() {
        let data = b"PROXY TCP4 not.an.ip 5.6.7.8 100 200\r\n";
        let result = parse_proxy_v1(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_v1_zero_port() {
        let data = b"PROXY TCP4 1.2.3.4 5.6.7.8 0 200\r\n";
        let result = parse_proxy_v1(data);
        assert!(result.is_err());
        match result.unwrap_err() {
            ProxyError::InvalidV1Header(msg) => {
                assert!(msg.contains("non-zero"), "{msg}");
            }
            other => panic!("expected InvalidV1Header, got: {other:?}"),
        }
    }

    #[test]
    fn test_parse_v1_port_overflow() {
        let data = b"PROXY TCP4 1.2.3.4 5.6.7.8 99999 200\r\n";
        let result = parse_proxy_v1(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_v1_wrong_field_count() {
        let data = b"PROXY TCP4 1.2.3.4 5.6.7.8 100\r\n";
        let result = parse_proxy_v1(data);
        assert!(result.is_err());
        match result.unwrap_err() {
            ProxyError::InvalidV1Header(msg) => {
                assert!(msg.contains("4 space-separated"), "{msg}");
            }
            other => panic!("expected InvalidV1Header, got: {other:?}"),
        }
    }

    // =========================================================================
    // PROXY v2 Parser Tests
    // =========================================================================

    /// Build a minimal valid PROXYv2 header for testing.
    fn build_v2_header(cmd: u8, fam: u8, addr_data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&PROXY_V2_SIGNATURE);
        buf.push(0x20 | cmd); // version 2 + command
        buf.push(fam);
        let len = addr_data.len() as u16;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(addr_data);
        buf
    }

    #[test]
    fn test_parse_v2_tcp4() {
        // src: 192.168.1.1:12345, dst: 10.0.0.1:443
        let mut addr_data = Vec::new();
        addr_data.extend_from_slice(&[192, 168, 1, 1]); // src addr
        addr_data.extend_from_slice(&[10, 0, 0, 1]); // dst addr
        addr_data.extend_from_slice(&12345u16.to_be_bytes()); // src port
        addr_data.extend_from_slice(&443u16.to_be_bytes()); // dst port

        let header = build_v2_header(V2_CMD_PROXY, V2_FAM_TCP4, &addr_data);
        let result = parse_proxy_v2(&header).expect("should parse valid v2 TCP4");

        assert_eq!(result.version, ProxyVersion::V2);
        assert_eq!(result.src_address.as_ref(), "192.168.1.1");
        assert_eq!(result.src_port, 12345);
        assert_eq!(result.dst_address.as_ref(), "10.0.0.1");
        assert_eq!(result.dst_port, 443);
    }

    #[test]
    fn test_parse_v2_tcp6() {
        // src: ::1:12345, dst: ::2:25
        let mut addr_data = Vec::new();
        let src_addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let dst_addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2);
        addr_data.extend_from_slice(&src_addr.octets());
        addr_data.extend_from_slice(&dst_addr.octets());
        addr_data.extend_from_slice(&12345u16.to_be_bytes());
        addr_data.extend_from_slice(&25u16.to_be_bytes());

        let header = build_v2_header(V2_CMD_PROXY, V2_FAM_TCP6, &addr_data);
        let result = parse_proxy_v2(&header).expect("should parse valid v2 TCP6");

        assert_eq!(result.version, ProxyVersion::V2);
        assert_eq!(result.src_address.as_ref(), "::1");
        assert_eq!(result.src_port, 12345);
        assert_eq!(result.dst_address.as_ref(), "::2");
        assert_eq!(result.dst_port, 25);
    }

    #[test]
    fn test_parse_v2_local() {
        let header = build_v2_header(V2_CMD_LOCAL, 0x00, &[]);
        let result = parse_proxy_v2(&header).expect("should parse LOCAL");

        assert_eq!(result.version, ProxyVersion::Local);
        assert_eq!(result.src_address.as_ref(), "");
        assert_eq!(result.src_port, 0);
    }

    #[test]
    fn test_parse_v2_bad_signature() {
        let mut bad = vec![0u8; 16];
        bad[..12].copy_from_slice(b"NOT_A_PROXY!");
        bad[12] = 0x21; // version 2, PROXY cmd
        bad[13] = 0x11; // TCP4
        bad[14..16].copy_from_slice(&0u16.to_be_bytes());

        assert!(matches!(
            parse_proxy_v2(&bad).unwrap_err(),
            ProxyError::InvalidSignature
        ));
    }

    #[test]
    fn test_parse_v2_bad_version() {
        let mut header = build_v2_header(V2_CMD_LOCAL, 0x00, &[]);
        header[12] = 0x10 | V2_CMD_LOCAL; // version 1 instead of 2
        assert!(matches!(
            parse_proxy_v2(&header).unwrap_err(),
            ProxyError::InvalidV2Header(_)
        ));
    }

    #[test]
    fn test_parse_v2_unsupported_family() {
        // UDP4 (0x12) — unsupported
        let addr_data = vec![0u8; 12];
        let header = build_v2_header(V2_CMD_PROXY, 0x12, &addr_data);
        assert!(matches!(
            parse_proxy_v2(&header).unwrap_err(),
            ProxyError::UnsupportedFamily
        ));
    }

    #[test]
    fn test_parse_v2_truncated_addr() {
        // TCP4 but only 8 bytes of address data (need 12)
        let addr_data = vec![0u8; 8];
        let header = build_v2_header(V2_CMD_PROXY, V2_FAM_TCP4, &addr_data);
        assert!(matches!(
            parse_proxy_v2(&header).unwrap_err(),
            ProxyError::InvalidV2Header(_)
        ));
    }

    // =========================================================================
    // proxy_protocol_start Integration Tests
    // =========================================================================

    #[test]
    fn test_start_v1_from_cursor() {
        let data = b"PROXY TCP4 1.2.3.4 5.6.7.8 56324 443\r\n";
        let mut reader = Cursor::new(data.to_vec());
        let result = proxy_protocol_start(&mut reader, Duration::from_secs(5))
            .expect("should parse v1 from cursor");
        assert_eq!(result.version, ProxyVersion::V1);
        assert_eq!(result.src_address.as_ref(), "1.2.3.4");
        assert_eq!(result.src_port, 56324);
        assert_eq!(result.dst_address.as_ref(), "5.6.7.8");
        assert_eq!(result.dst_port, 443);
    }

    #[test]
    fn test_start_v2_from_cursor() {
        let mut addr_data = Vec::new();
        addr_data.extend_from_slice(&[172, 16, 0, 1]); // src
        addr_data.extend_from_slice(&[192, 168, 0, 1]); // dst
        addr_data.extend_from_slice(&8080u16.to_be_bytes()); // src port
        addr_data.extend_from_slice(&25u16.to_be_bytes()); // dst port
        let header = build_v2_header(V2_CMD_PROXY, V2_FAM_TCP4, &addr_data);

        let mut reader = Cursor::new(header);
        let result = proxy_protocol_start(&mut reader, Duration::from_secs(5))
            .expect("should parse v2 from cursor");
        assert_eq!(result.version, ProxyVersion::V2);
        assert_eq!(result.src_address.as_ref(), "172.16.0.1");
        assert_eq!(result.src_port, 8080);
        assert_eq!(result.dst_address.as_ref(), "192.168.0.1");
        assert_eq!(result.dst_port, 25);
    }

    #[test]
    fn test_start_unknown_from_cursor() {
        let data = b"PROXY UNKNOWN\r\n";
        let mut reader = Cursor::new(data.to_vec());
        let result = proxy_protocol_start(&mut reader, Duration::from_secs(5))
            .expect("should parse UNKNOWN from cursor");
        assert_eq!(result.version, ProxyVersion::Local);
    }

    #[test]
    fn test_start_invalid_signature() {
        let data = b"NOT A PROXY HEADER AT ALL\r\n";
        let mut reader = Cursor::new(data.to_vec());
        let result = proxy_protocol_start(&mut reader, Duration::from_secs(5));
        assert!(matches!(result.unwrap_err(), ProxyError::InvalidSignature));
    }

    #[test]
    fn test_start_eof_before_header() {
        let data = b"PROX"; // Only 4 bytes — not enough
        let mut reader = Cursor::new(data.to_vec());
        let result = proxy_protocol_start(&mut reader, Duration::from_secs(5));
        assert!(matches!(result.unwrap_err(), ProxyError::IoError(_)));
    }

    // =========================================================================
    // proxy_protocol_host Tests
    // =========================================================================

    #[test]
    fn test_host_exact_match() {
        assert!(proxy_protocol_host("192.168.1.1", "192.168.1.1"));
    }

    #[test]
    fn test_host_no_match() {
        assert!(!proxy_protocol_host("192.168.1.2", "192.168.1.1"));
    }

    #[test]
    fn test_host_cidr_match() {
        assert!(proxy_protocol_host("10.0.5.3", "10.0.0.0/8"));
    }

    #[test]
    fn test_host_cidr_no_match() {
        assert!(!proxy_protocol_host("192.168.1.1", "10.0.0.0/8"));
    }

    #[test]
    fn test_host_wildcard() {
        assert!(proxy_protocol_host("192.168.1.1", "*"));
    }

    #[test]
    fn test_host_colon_separated_list() {
        assert!(proxy_protocol_host(
            "10.0.0.5",
            "192.168.1.1:10.0.0.0/8:172.16.0.0/12"
        ));
    }

    #[test]
    fn test_host_empty_address() {
        assert!(!proxy_protocol_host("", "10.0.0.0/8"));
    }

    #[test]
    fn test_host_empty_list() {
        assert!(!proxy_protocol_host("10.0.0.1", ""));
    }

    #[test]
    fn test_host_ipv6_cidr() {
        assert!(proxy_protocol_host("2001:db8::1", "2001:db8::/32"));
    }

    #[test]
    fn test_host_ipv6_no_match() {
        assert!(!proxy_protocol_host("2001:db9::1", "2001:db8::/32"));
    }

    // =========================================================================
    // CIDR Matching Tests
    // =========================================================================

    #[test]
    fn test_cidr_v4_match() {
        let addr: IpAddr = "10.5.3.1".parse().unwrap();
        assert!(matches_cidr(addr, "10.0.0.0/8"));
    }

    #[test]
    fn test_cidr_v4_no_match() {
        let addr: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(!matches_cidr(addr, "10.0.0.0/8"));
    }

    #[test]
    fn test_cidr_v4_exact() {
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(matches_cidr(addr, "10.0.0.1/32"));
    }

    #[test]
    fn test_cidr_v4_zero_prefix() {
        let addr: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(matches_cidr(addr, "0.0.0.0/0"));
    }

    #[test]
    fn test_cidr_v6_match() {
        let addr: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(matches_cidr(addr, "2001:db8::/32"));
    }

    #[test]
    fn test_cidr_mixed_family_no_match() {
        let v4: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!matches_cidr(v4, "::1/128"));
    }

    #[test]
    fn test_cidr_invalid_prefix() {
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!matches_cidr(addr, "10.0.0.0/33")); // > 32 for IPv4
    }

    // =========================================================================
    // Taint and Type Tests
    // =========================================================================

    #[test]
    fn test_proxy_result_addresses_are_tainted() {
        let data = b"PROXY TCP4 1.2.3.4 5.6.7.8 100 200\r\n";
        let result = parse_proxy_v1(data).unwrap();
        // Verify that addresses are wrapped in Tainted (compile-time check)
        let _: &Tainted<String> = &result.src_address;
        let _: &Tainted<String> = &result.dst_address;
        // Access requires explicit .as_ref()
        assert_eq!(result.src_address.as_ref(), "1.2.3.4");
    }

    #[test]
    fn test_validate_proxy_addresses() {
        let data = b"PROXY TCP4 1.2.3.4 5.6.7.8 100 200\r\n";
        let result = parse_proxy_v1(data).unwrap();
        let (src_clean, dst_clean) = validate_proxy_addresses(&result).expect("should validate");
        // Clean addresses can be dereferenced directly
        assert_eq!(&*src_clean, "1.2.3.4");
        assert_eq!(&*dst_clean, "5.6.7.8");
    }

    #[test]
    fn test_taint_state_constant() {
        assert_eq!(PROXY_DATA_TAINT, TaintState::Tainted);
    }

    #[test]
    fn test_proxy_error_to_driver_error() {
        let proxy_err = ProxyError::Timeout;
        let driver_err: DriverError = proxy_err.into();
        assert!(driver_err.to_string().contains("timeout"));
    }

    #[test]
    fn test_proxy_version_display() {
        assert_eq!(ProxyVersion::V1.to_string(), "v1");
        assert_eq!(ProxyVersion::V2.to_string(), "v2");
        assert_eq!(ProxyVersion::Local.to_string(), "local");
    }

    // =========================================================================
    // Constant Verification Tests
    // =========================================================================

    #[test]
    fn test_v2_signature_length() {
        assert_eq!(PROXY_V2_SIGNATURE.len(), 12);
    }

    #[test]
    fn test_v2_signature_matches_spec() {
        // The PROXY v2 signature from the HAProxy specification
        let expected: [u8; 12] = [
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
        ];
        assert_eq!(PROXY_V2_SIGNATURE, expected);
    }

    #[test]
    fn test_proto_start_slot() {
        assert_eq!(PROXY_PROTO_START, 0);
    }

    #[test]
    fn test_system_af_constants() {
        // Verify our libc constant references are valid
        assert!(SYSTEM_AF_INET > 0, "AF_INET should be positive");
        assert!(SYSTEM_AF_INET6 > 0, "AF_INET6 should be positive");
        assert_eq!(SYSTEM_AF_UNSPEC, 0, "AF_UNSPEC should be 0");
    }
}
