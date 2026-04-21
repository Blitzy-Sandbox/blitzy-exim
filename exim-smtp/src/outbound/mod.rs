//! Outbound SMTP client implementation for the Exim Mail Transfer Agent.
//!
//! This module provides the full outbound SMTP client stack, replacing the C
//! implementation in `src/src/smtp_out.c` (924 lines) and the outbound-facing
//! struct definitions from `src/src/structs.h` (lines 815–868) and
//! `src/src/transports/smtp.h` (lines 140–230).
//!
//! # Architecture
//!
//! The outbound module is organized into four submodules:
//!
//! - [`connection`] — Socket creation, binding, connecting, TCP Fast Open,
//!   and keepalive support.
//! - [`response`] — SMTP response parsing, multi-line response assembly,
//!   pipelined command writing, and output buffer flushing.
//! - [`parallel`] — Parallel delivery dispatch, connection pooling, and
//!   delivery batch scheduling.
//! - [`tls_negotiation`] — STARTTLS initiation, TLS-on-connect, and DANE
//!   validation (feature-gated behind `tls`).
//!
//! # Shared Types
//!
//! This root module defines the shared data structures used across all
//! submodules:
//!
//! | Rust Type | C Equivalent | Source |
//! |-----------|-------------|--------|
//! | [`ClientConnCtx`] | `client_conn_ctx` | `structs.h` line 837 |
//! | [`SmtpInblock`] | `smtp_inblock` | `structs.h` line 847 |
//! | [`SmtpOutblock`] | `smtp_outblock` | `structs.h` line 859 |
//! | [`SmtpConnectArgs`] | `smtp_connect_args` | `structs.h` line 815 |
//! | [`SmtpContext`] | `smtp_context` | `transports/smtp.h` line 143 |
//! | [`CommandWriteMode`] | `SCMD_FLUSH`/`SCMD_MORE`/`SCMD_BUFFER` | `macros.h` line 905 |
//! | [`TfoState`] | `tfo_state_t` | `structs.h` line 72 |
//! | [`AddressFamily`] | `AF_INET`/`AF_INET6` | `<sys/socket.h>` |
//!
//! # Design (AAP §0.4.4 — Scoped Context Passing)
//!
//! All mutable state flows through explicit [`SmtpContext`] parameters rather
//! than the 714 C global variables in `globals.c`. Connection state (socket,
//! TLS session) is owned by [`SmtpContext`], buffer state (ptr, ptrend) is
//! owned by [`SmtpInblock`]/[`SmtpOutblock`], and connection parameters are
//! carried in [`SmtpConnectArgs`].
//!
//! # Feature Flags
//!
//! | Feature | C Equivalent | Gates |
//! |---------|-------------|-------|
//! | `tls` | `#ifndef DISABLE_TLS` | `tls_negotiation` submodule, TLS fields |
//! | `pipe-connect` | `#ifndef DISABLE_PIPE_CONNECT` | Early pipelining flags |
//! | `prdr` | `#ifndef DISABLE_PRDR` | PRDR session flag |
//! | `i18n` | `#ifdef SUPPORT_I18N` | SMTPUTF8 flag |
//! | `esmtp-limits` | `#ifndef DISABLE_ESMTP_LIMITS` | Peer limit fields |
//! | `socks` | `#ifdef SUPPORT_SOCKS` | SOCKS5 error variant |

// =============================================================================
// Submodule Declarations
// =============================================================================

/// Outbound SMTP connection management.
///
/// Provides socket creation, interface binding, port resolution, TCP Fast Open
/// support, keepalive configuration, and the high-level `smtp_connect()` entry
/// point. Replaces `smtp_get_interface()`, `smtp_get_port()`, `smtp_boundsock()`,
/// `smtp_sock_connect()`, `smtp_port_for_connect()`, and `smtp_connect()` from
/// `src/src/smtp_out.c`.
pub mod connection;

/// Parallel delivery dispatch and connection pooling.
///
/// Manages the coordination of multiple simultaneous SMTP sessions for
/// delivering to different hosts, connection reuse logic, and delivery attempt
/// scheduling. Replaces parallel delivery subprocess pool patterns from
/// `src/src/deliver.c` and connection reuse from `src/src/transports/smtp.c`.
pub mod parallel;

/// SMTP response parsing and pipelined command writing.
///
/// Implements response reading (`read_response_line`, `smtp_read_response`),
/// pipelined command writing (`smtp_write_command`), and output buffer flushing
/// (`flush_buffer`) with TLS, early-data, and plain send code paths. Replaces
/// the corresponding functions from `src/src/smtp_out.c` lines 549–920.
pub mod response;

/// STARTTLS initiation and TLS-on-connect for outbound connections.
///
/// Feature-gated behind `tls` (replacing C `#ifndef DISABLE_TLS`). Handles
/// the STARTTLS command exchange, TLS handshake via the `exim-tls` backend,
/// TLS-on-connect mode (port 465/SMTPS), DANE/TLSA validation, and encrypted
/// buffer writes.
#[cfg(feature = "tls")]
pub mod tls_negotiation;

// =============================================================================
// Imports
// =============================================================================

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::os::unix::io::RawFd;
use std::time::Duration;

use thiserror::Error;

// Feature-gated import: TlsSession struct from exim-tls for the tls_ctx field
// in ClientConnCtx. TlsSession is a data struct holding negotiated TLS session
// information (cipher, protocol version, peer DN, etc.). Replaces the C
// `void* tls_ctx` pointer in `client_conn_ctx` (structs.h line 839).
#[cfg(feature = "tls")]
use exim_tls::TlsSession;

// =============================================================================
// Re-exports from Submodules
// =============================================================================

// Connection management re-exports — top-level convenience access to the most
// commonly used connection functions, matching the C pattern where these
// functions are declared in `functions.h` as global symbols.
pub use connection::{resolve_interface, resolve_port, smtp_connect};

// Response handling re-exports — top-level access to SMTP response reading
// and command writing functions used by the transport layer.
pub use response::{flush_buffer, smtp_read_response, smtp_write_command};

// Parallel delivery re-exports — ConnectionPool is the primary public
// interface for managing concurrent outbound SMTP connections.
pub use parallel::ConnectionPool;

// =============================================================================
// Constants
// =============================================================================

/// General-purpose delivery buffer size in bytes.
///
/// Matches C `DELIVER_BUFFER_SIZE` from `transports/smtp.h` line 10.
/// Used for the response buffer in [`SmtpContext`].
pub const DELIVER_BUFFER_SIZE: usize = 4096;

/// Inbound (response) buffer size in bytes.
///
/// Matches the C `inbuffer[4096]` declaration in `transports/smtp.h` line 228.
/// Used by [`SmtpInblock`] for buffering incoming SMTP response packets.
pub const INBUFFER_SIZE: usize = 4096;

/// Outbound (command) buffer size in bytes.
///
/// Matches the C `outbuffer[4096]` declaration in `transports/smtp.h` line 229.
/// Used by [`SmtpOutblock`] for buffering pipelined SMTP commands.
pub const OUTBUFFER_SIZE: usize = 4096;

/// Sentinel value indicating no port has been assigned.
///
/// Matches C `PORT_NONE` from `macros.h` line 1044: `#define PORT_NONE (-1)`.
/// Used as the default for `host_item.port` when no explicit port is set.
pub const PORT_NONE: i32 = -1;

// =============================================================================
// Error Types
// =============================================================================

/// Error type for outbound SMTP operations.
///
/// Covers all failure modes in the outbound SMTP client: connection failures,
/// protocol errors, timeouts, buffer overflows, and feature-gated TLS/SOCKS
/// errors. Replaces the C pattern of returning integer error codes and setting
/// `errno` to custom values like `ERRNO_SMTPFORMAT` and `ERRNO_TLSFAILURE`.
#[derive(Debug, Error)]
pub enum OutboundError {
    /// TCP connection to the remote host failed.
    ///
    /// Includes the failure reason for diagnostic logging. Replaces the C
    /// pattern of `errno = ECONNREFUSED` or `ETIMEDOUT` with a structured
    /// error containing the original failure description.
    #[error("connection failed: {reason}")]
    ConnectionFailed {
        /// Human-readable description of why the connection failed.
        reason: String,
    },

    /// Configuration error (e.g., invalid interface, unresolvable port).
    ///
    /// Replaces the C pattern of setting `addr->transport_return = PANIC`
    /// and `addr->message` with configuration error details.
    #[error("configuration error: {detail}")]
    ConfigError {
        /// Description of the configuration problem.
        detail: String,
    },

    /// SMTP protocol error (unexpected response code or format).
    ///
    /// Returned when the remote server sends a response that violates RFC 5321
    /// SMTP response format (e.g., missing 3-digit reply code).
    #[error("SMTP protocol error: {message}")]
    ProtocolError {
        /// Description of the protocol violation.
        message: String,
    },

    /// Connection or command timeout exceeded.
    ///
    /// Replaces the C `ERRNO_CONNECTTIMEOUT` and read timeout paths in
    /// `smtp_out.c`. The `duration` field records the configured timeout
    /// value for diagnostic logging.
    #[error("timeout after {duration:?}")]
    Timeout {
        /// The timeout duration that was exceeded.
        duration: Duration,
    },

    /// Remote server closed the connection unexpectedly.
    ///
    /// Returned when `read()` returns 0 bytes during response reading,
    /// indicating the remote end has closed the TCP connection.
    #[error("connection closed by remote")]
    ConnectionClosed,

    /// SMTP response format error (invalid reply code syntax).
    ///
    /// Replaces C `errno = ERRNO_SMTPFORMAT`. The `line` field contains the
    /// malformed response line for diagnostic logging.
    #[error("SMTP format error: {line}")]
    FormatError {
        /// The malformed SMTP response line.
        line: String,
    },

    /// TLS negotiation or write error.
    ///
    /// Feature-gated behind `tls` (replacing C `#ifndef DISABLE_TLS`).
    /// Replaces C `errno = ERRNO_TLSFAILURE` and `tls_error()` calls.
    #[cfg(feature = "tls")]
    #[error("TLS error: {detail}")]
    TlsError {
        /// Description of the TLS failure.
        detail: String,
    },

    /// SOCKS5 proxy connection error.
    ///
    /// Feature-gated behind `socks` (replacing C `#ifdef SUPPORT_SOCKS`).
    /// Returned when the SOCKS proxy negotiation fails.
    #[cfg(feature = "socks")]
    #[error("SOCKS proxy error: {detail}")]
    SocksError {
        /// Description of the SOCKS failure.
        detail: String,
    },

    /// Output buffer overflow — command exceeds buffer capacity.
    ///
    /// Returned when a pipelined SMTP command cannot fit in the output buffer
    /// even after flushing. This indicates a command longer than
    /// [`OUTBUFFER_SIZE`] bytes, which should not occur in normal operation.
    #[error("buffer overflow")]
    BufferOverflow,

    /// Underlying I/O error from socket operations.
    ///
    /// Automatically converted from `std::io::Error` via `#[from]`, covering
    /// all `read()`, `write()`, `send()`, `connect()`, and `bind()` failures.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

// =============================================================================
// AddressFamily Enum
// =============================================================================

/// Socket address family for outbound connections.
///
/// Type-safe replacement for C `AF_INET` / `AF_INET6` integer constants.
/// Used in [`SmtpConnectArgs::host_af`] to specify IPv4 vs IPv6 for socket
/// creation and interface selection.
///
/// # C Equivalent
///
/// Replaces the `int host_af` field in `smtp_connect_args` (structs.h line
/// 819) which uses raw `AF_INET` / `AF_INET6` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    /// IPv4 address family (C `AF_INET`).
    Inet,
    /// IPv6 address family (C `AF_INET6`).
    Inet6,
}

impl From<AddressFamily> for libc::c_int {
    fn from(af: AddressFamily) -> libc::c_int {
        match af {
            AddressFamily::Inet => libc::AF_INET,
            AddressFamily::Inet6 => libc::AF_INET6,
        }
    }
}

impl TryFrom<libc::c_int> for AddressFamily {
    type Error = OutboundError;

    fn try_from(value: libc::c_int) -> Result<Self, Self::Error> {
        match value {
            libc::AF_INET => Ok(AddressFamily::Inet),
            libc::AF_INET6 => Ok(AddressFamily::Inet6),
            other => Err(OutboundError::ConfigError {
                detail: format!("unsupported address family: {other}"),
            }),
        }
    }
}

impl AddressFamily {
    /// Returns the corresponding [`IpAddr`] unspecified address for this family.
    ///
    /// Useful for creating wildcard bind addresses.
    pub fn unspecified_addr(self) -> IpAddr {
        match self {
            AddressFamily::Inet => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            AddressFamily::Inet6 => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        }
    }

    /// Determine the address family from an [`IpAddr`].
    pub fn from_ip(addr: &IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => AddressFamily::Inet,
            IpAddr::V6(_) => AddressFamily::Inet6,
        }
    }
}

// =============================================================================
// CommandWriteMode Enum
// =============================================================================

/// Mode for SMTP command writing, controlling buffer flush behaviour.
///
/// Replaces the C `SCMD_FLUSH`, `SCMD_MORE`, `SCMD_BUFFER` constants from
/// `macros.h` lines 905–908. The integer discriminant values match the C
/// constants exactly for behavioral parity.
///
/// # C Equivalent
///
/// ```c
/// enum {
///   SCMD_FLUSH = 0,   // write to kernel
///   SCMD_MORE,        // write to kernel, but likely more soon
///   SCMD_BUFFER       // stash in application cmd output buffer
/// };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum CommandWriteMode {
    /// Flush: transmit buffered commands to the kernel immediately.
    ///
    /// Used when no more commands will follow in this batch (e.g., after
    /// the final RCPT TO in a non-pipelined session).
    Flush = 0,

    /// More: transmit buffered commands but signal that more data follows.
    ///
    /// Sets `MSG_MORE` on Linux to enable TCP corking, reducing the number
    /// of small packets when pipelining multiple commands.
    More = 1,

    /// Buffer: stash the command in the application-level output buffer only.
    ///
    /// Used during SMTP pipelining to accumulate commands (MAIL FROM, RCPT TO)
    /// before transmitting them in a single batch.
    Buffer = 2,
}

// =============================================================================
// TfoState Enum
// =============================================================================

/// TCP Fast Open (TFO) diagnostic state for outbound connections.
///
/// Tracks whether TFO was attempted, and if so, whether data was included
/// in the SYN packet and whether it was acknowledged. Replaces the C
/// `tfo_state_t` enum from `structs.h` lines 72–76.
///
/// # C Equivalent
///
/// ```c
/// typedef enum {
///     TFO_NOT_USED = 0,
///     TFO_ATTEMPTED_NODATA,
///     TFO_ATTEMPTED_DATA,
///     TFO_USED_NODATA,
///     TFO_USED_DATA
/// } tfo_state_t;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TfoState {
    /// TFO was not attempted or is not supported on this platform.
    #[default]
    NotUsed,
    /// TFO SYN was sent without application data (SYN cookie only).
    AttemptedNoData,
    /// TFO SYN was sent with early application data.
    AttemptedData,
    /// TFO succeeded: SYN cookie was accepted by the remote.
    UsedNoData,
    /// TFO succeeded: early data was acknowledged in the SYN-ACK.
    UsedData,
}

// =============================================================================
// ClientConnCtx — Client Connection Context
// =============================================================================

/// Client-side connection context holding a socket and optional TLS session.
///
/// Rust replacement for the C `client_conn_ctx` struct (structs.h lines
/// 837–840). In the C code, `tls_ctx` is a `void*` pointer to an opaque TLS
/// context; here it is a type-safe `Option<TlsSession>` gated behind the
/// `tls` feature flag.
///
/// # C Equivalent
///
/// ```c
/// typedef struct {
///   int    sock;
///   void * tls_ctx;
/// } client_conn_ctx;
/// ```
///
/// # Safety
///
/// Contains no `unsafe` code. The raw file descriptor in `sock` is managed
/// through safe nix/std wrappers in the connection module.
pub struct ClientConnCtx {
    /// The raw TCP socket file descriptor.
    ///
    /// Set to `-1` when no socket is open. Managed through safe nix wrappers
    /// for `socket()`, `bind()`, `connect()`, `close()`.
    pub sock: RawFd,

    /// Optional TLS session state for this connection.
    ///
    /// `None` indicates a plaintext connection; `Some(session)` indicates an
    /// active TLS session with negotiated parameters. Feature-gated behind
    /// `tls` (replacing C `#ifndef DISABLE_TLS`).
    ///
    /// The [`TlsSession`] struct holds session metadata (cipher, protocol
    /// version, peer DN, SNI, certificate verification status, key exchange
    /// bit strength) used for logging and security decisions.
    #[cfg(feature = "tls")]
    pub tls_ctx: Option<TlsSession>,
}

impl ClientConnCtx {
    /// Create a new client connection context with the given socket.
    ///
    /// Initialises the TLS context to `None` (plaintext). The caller should
    /// upgrade to TLS via the `tls_negotiation` module after the STARTTLS
    /// exchange or for TLS-on-connect mode.
    pub fn new(sock: RawFd) -> Self {
        ClientConnCtx {
            sock,
            #[cfg(feature = "tls")]
            tls_ctx: None,
        }
    }

    /// Check whether a TLS session is currently active on this connection.
    ///
    /// Returns `true` if the `tls` feature is enabled AND a TLS session
    /// has been established AND the session reports itself as active.
    /// Returns `false` in all other cases (plaintext, TLS disabled, or
    /// session not yet established).
    ///
    /// # C Equivalent
    ///
    /// Replaces the C pattern: `if (cctx->tls_ctx)` in `smtp_out.c`.
    pub fn is_tls_active(&self) -> bool {
        #[cfg(feature = "tls")]
        {
            self.tls_ctx.as_ref().is_some_and(|session| session.active)
        }
        #[cfg(not(feature = "tls"))]
        {
            false
        }
    }
}

// Custom Debug implementation for ClientConnCtx that explicitly accesses
// TlsSession fields (active, cipher, protocol_version, bits,
// certificate_verified, peer_dn, sni) for informative diagnostics.
impl fmt::Debug for ClientConnCtx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut dbg = f.debug_struct("ClientConnCtx");
        dbg.field("sock", &self.sock);

        #[cfg(feature = "tls")]
        {
            if let Some(ref session) = self.tls_ctx {
                // Access all TlsSession fields for comprehensive debug output.
                // These fields replace the C tls_support struct members
                // (tls_in/tls_out globals from globals.c).
                dbg.field("tls_active", &session.active);
                dbg.field("tls_cipher", &session.cipher);
                dbg.field("tls_protocol", &session.protocol_version);
                dbg.field("tls_bits", &session.bits);
                dbg.field("tls_verified", &session.certificate_verified);
                dbg.field("tls_peer_dn", &session.peer_dn);
                dbg.field("tls_sni", &session.sni);
            } else {
                dbg.field("tls_ctx", &"None (plaintext)");
            }
        }

        #[cfg(not(feature = "tls"))]
        {
            dbg.field("tls", &"disabled");
        }

        dbg.finish()
    }
}

// =============================================================================
// SmtpInblock — SMTP Response Input Buffer
// =============================================================================

/// Buffered input for reading SMTP responses from a remote server.
///
/// Rust replacement for the C `smtp_inblock` struct (structs.h lines 847–853).
/// Holds incoming response data that may contain multiple SMTP response lines
/// in a single network read (pipelining / LMTP multi-status).
///
/// The connection context reference is maintained at the [`SmtpContext`] level
/// rather than duplicated here, eliminating the C raw pointer
/// `client_conn_ctx * cctx`.
///
/// # Buffer Layout
///
/// ```text
/// [0 .................. ptr .................. ptrend .............. capacity]
///  ^ already consumed    ^ next byte to read  ^ end of valid data  ^ buffer end
/// ```
///
/// # C Equivalent
///
/// ```c
/// typedef struct smtp_inblock {
///   client_conn_ctx * cctx;
///   int     buffersize;
///   uschar *ptr;
///   uschar *ptrend;
///   uschar *buffer;
/// } smtp_inblock;
/// ```
#[derive(Debug)]
pub struct SmtpInblock {
    /// Internal buffer for incoming SMTP response data.
    buffer: Vec<u8>,
    /// Current read position (byte offset from buffer start).
    ///
    /// Points to the next unconsumed byte. Advanced as response lines are
    /// extracted by `read_response_line()`.
    ptr: usize,
    /// End of valid data (byte offset from buffer start).
    ///
    /// Points one past the last byte of valid data. Data in
    /// `buffer[ptr..ptrend]` is unprocessed response content.
    ptrend: usize,
}

impl SmtpInblock {
    /// Create a new input buffer with the given capacity.
    ///
    /// # Arguments
    ///
    /// * `buffersize` — Capacity in bytes. Use [`INBUFFER_SIZE`] (4096) for
    ///   the standard SMTP response buffer matching `transports/smtp.h` line
    ///   228.
    pub fn new(buffersize: usize) -> Self {
        SmtpInblock {
            buffer: vec![0u8; buffersize],
            ptr: 0,
            ptrend: 0,
        }
    }

    /// Returns a slice of the unprocessed data currently in the buffer.
    ///
    /// This is the data between `ptr` and `ptrend` — response bytes that
    /// have been read from the socket but not yet consumed by the response
    /// parser. Returns an empty slice if no data is pending.
    pub fn remaining_data(&self) -> &[u8] {
        if self.ptr <= self.ptrend && self.ptrend <= self.buffer.len() {
            &self.buffer[self.ptr..self.ptrend]
        } else {
            &[]
        }
    }

    /// Reset the buffer state, discarding all unprocessed data.
    ///
    /// Sets both `ptr` and `ptrend` to 0. Called when starting a new
    /// response read sequence or after an error to ensure clean state.
    pub fn reset(&mut self) {
        self.ptr = 0;
        self.ptrend = 0;
    }

    /// Returns the total capacity of the buffer in bytes.
    pub fn capacity(&self) -> usize {
        self.buffer.len()
    }

    /// Returns a mutable reference to the raw buffer for socket reads.
    ///
    /// Used by the response reader to fill the buffer from the socket.
    /// After filling, the caller must update `ptrend` via [`set_ptrend`].
    pub fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    /// Returns the current read position.
    pub fn ptr_offset(&self) -> usize {
        self.ptr
    }

    /// Sets the current read position.
    pub fn set_ptr(&mut self, offset: usize) {
        self.ptr = offset.min(self.buffer.len());
    }

    /// Returns the current end-of-data position.
    pub fn ptrend_offset(&self) -> usize {
        self.ptrend
    }

    /// Sets the end-of-data position after a socket read.
    pub fn set_ptrend(&mut self, offset: usize) {
        self.ptrend = offset.min(self.buffer.len());
    }

    /// Advance the read position by `n` bytes.
    pub fn advance_ptr(&mut self, n: usize) {
        self.ptr = (self.ptr + n).min(self.ptrend);
    }
}

// =============================================================================
// SmtpOutblock — SMTP Command Output Buffer
// =============================================================================

/// Buffered output for pipelined SMTP command transmission.
///
/// Rust replacement for the C `smtp_outblock` struct (structs.h lines
/// 859–868). Accumulates SMTP commands (MAIL FROM, RCPT TO, etc.) in an
/// application-level buffer for efficient pipelined transmission.
///
/// The connection context reference is maintained at the [`SmtpContext`] level
/// rather than duplicated here, eliminating the C raw pointer
/// `client_conn_ctx * cctx`.
///
/// # C Equivalent
///
/// ```c
/// typedef struct smtp_outblock {
///   client_conn_ctx * cctx;
///   int     cmd_count;
///   int     buffersize;
///   BOOL    authenticating;
///   uschar *ptr;
///   uschar *buffer;
///   smtp_connect_args * conn_args;
/// } smtp_outblock;
/// ```
#[derive(Debug)]
pub struct SmtpOutblock {
    /// Internal buffer for outgoing SMTP commands.
    buffer: Vec<u8>,
    /// Current write position (byte offset from buffer start).
    ///
    /// All bytes in `buffer[0..ptr]` are pending transmission.
    ptr: usize,

    /// Number of SMTP commands currently buffered.
    ///
    /// Incremented by `smtp_write_command()` for each command added to the
    /// buffer, reset to 0 by `flush_buffer()` after successful transmission.
    pub cmd_count: i32,

    /// Whether the connection is currently in an AUTH exchange.
    ///
    /// When `true`, `smtp_write_command()` masks credential data in debug
    /// output to prevent passwords from appearing in logs. Replaces the C
    /// `BOOL authenticating` field.
    pub authenticating: bool,

    /// Optional deferred connection arguments for connect-with-early-data.
    ///
    /// When `Some`, `flush_buffer()` will establish the TCP connection using
    /// the buffered command data as TCP Fast Open early data, rather than
    /// sending on an existing socket. Replaces the C `smtp_connect_args *
    /// conn_args` pointer in `smtp_outblock`.
    pub conn_args: Option<SmtpConnectArgs>,
}

impl SmtpOutblock {
    /// Create a new output buffer with the given capacity.
    ///
    /// # Arguments
    ///
    /// * `buffersize` — Capacity in bytes. Use [`OUTBUFFER_SIZE`] (4096) for
    ///   the standard SMTP command buffer matching `transports/smtp.h` line
    ///   229.
    pub fn new(buffersize: usize) -> Self {
        SmtpOutblock {
            buffer: vec![0u8; buffersize],
            ptr: 0,
            cmd_count: 0,
            authenticating: false,
            conn_args: None,
        }
    }

    /// Returns the number of bytes of remaining space in the buffer.
    ///
    /// Used by `smtp_write_command()` to decide whether to flush before
    /// adding a new command.
    pub fn available_space(&self) -> usize {
        self.buffer.len().saturating_sub(self.ptr)
    }

    /// Returns the number of bytes currently buffered for transmission.
    pub fn buffered_bytes(&self) -> usize {
        self.ptr
    }

    /// Returns a slice of the currently buffered command data.
    ///
    /// The returned slice contains all pending bytes from `buffer[0..ptr]`.
    pub fn buffer_slice(&self) -> &[u8] {
        &self.buffer[..self.ptr]
    }

    /// Write bytes into the output buffer.
    ///
    /// Appends `data` to the buffer at the current write position. Returns
    /// [`OutboundError::BufferOverflow`] if the data would exceed the buffer
    /// capacity.
    ///
    /// # Errors
    ///
    /// Returns `BufferOverflow` if `data.len()` exceeds [`available_space()`].
    pub fn write_bytes(&mut self, data: &[u8]) -> Result<(), OutboundError> {
        if data.len() > self.available_space() {
            return Err(OutboundError::BufferOverflow);
        }
        self.buffer[self.ptr..self.ptr + data.len()].copy_from_slice(data);
        self.ptr += data.len();
        Ok(())
    }

    /// Reset the buffer state, discarding all buffered commands.
    ///
    /// Sets the write pointer to 0 and the command count to 0. Called after
    /// successful transmission by `flush_buffer()`.
    pub fn reset(&mut self) {
        self.ptr = 0;
        self.cmd_count = 0;
    }

    /// Returns the total capacity of the buffer in bytes.
    pub fn capacity(&self) -> usize {
        self.buffer.len()
    }

    /// Returns a mutable reference to the raw buffer for direct writes.
    ///
    /// Used internally by the response/flush modules. After writing, the
    /// caller must update the write position via [`set_ptr`].
    pub fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    /// Sets the current write position.
    pub fn set_ptr(&mut self, offset: usize) {
        self.ptr = offset.min(self.buffer.len());
    }
}

// =============================================================================
// SmtpConnectArgs — Connection Parameters
// =============================================================================

/// Connection parameters for an outbound SMTP session.
///
/// Rust replacement for the C `smtp_connect_args` struct (structs.h lines
/// 815–834). Carries all information needed to establish a TCP connection
/// to a remote SMTP server, including host identity, address family,
/// local interface binding, DANE state, and transport options.
///
/// # C Equivalent
///
/// ```c
/// typedef struct {
///   transport_instance * tblock;
///   void *               ob;
///   host_item *          host;
///   int                  host_af;
///   const uschar *       interface;
///   int                  sock;
///   uschar *             sending_ip_address;
///   const uschar *       host_lbserver;
///   BOOL                 have_lbserver:1;
///   BOOL                 dane:1;          // #ifdef SUPPORT_DANE
///   dns_answer           tlsa_dnsa;       // #ifdef SUPPORT_DANE
/// } smtp_connect_args;
/// ```
#[derive(Debug)]
pub struct SmtpConnectArgs {
    /// Remote host name (for logging, EHLO, and certificate verification).
    pub host_name: String,

    /// Remote host IP address (type-safe replacement for C `uschar*`).
    pub host_address: IpAddr,

    /// Remote host port number (host byte order).
    pub host_port: u16,

    /// Socket address family (IPv4 or IPv6).
    pub host_af: AddressFamily,

    /// Optional local interface to bind to (expanded from transport config).
    ///
    /// When `Some`, the outbound socket is bound to this specific network
    /// interface via `bind()` before connecting. When `None`, the OS selects
    /// the source interface automatically.
    pub interface: Option<String>,

    /// Socket file descriptor for a pre-bound but not yet connected socket.
    ///
    /// Set to `-1` (matching C convention) when no socket has been created
    /// yet. After `create_bound_socket()`, this holds the bound socket fd.
    pub sock: i32,

    /// Local IP address recorded after binding/connecting (for TLS resumption).
    ///
    /// Replaces C `sending_ip_address` global. Populated by `getsockname()`
    /// after a successful bind or connect.
    pub sending_ip_address: Option<String>,

    /// Local port recorded after binding (for logging).
    pub sending_port: Option<u16>,

    /// Load-balancer server hint for TLS session resumption.
    ///
    /// When a host is behind a load balancer, this identifies the actual
    /// backend server for TLS session ticket keying. Replaces C
    /// `host_lbserver` field.
    pub host_lbserver: Option<String>,

    /// Whether [`host_lbserver`] contains a valid value.
    ///
    /// Replaces C `BOOL have_lbserver:1` bitfield.
    pub have_lbserver: bool,

    /// Whether DANE/TLSA verification is required for this connection.
    ///
    /// When `true`, the TLS handshake must verify the server certificate
    /// against DNS TLSA records. Replaces C `BOOL dane:1` field from
    /// `smtp_connect_args` (gated by `SUPPORT_DANE` in C).
    pub dane: bool,

    /// Connection timeout for the TCP handshake.
    ///
    /// Replaces the C `int connect_timeout` from
    /// `smtp_transport_options_block`. The timeout is applied to the
    /// `connect()` system call.
    pub connect_timeout: Duration,

    /// Whether TCP keepalive is enabled for this connection.
    ///
    /// When `true`, `SO_KEEPALIVE` is set on the socket after a successful
    /// connection. Replaces C `BOOL keepalive` from transport options.
    pub keepalive: bool,
}

// =============================================================================
// SmtpContext — Full Outbound SMTP Session Context
// =============================================================================

/// Complete outbound SMTP session context.
///
/// Rust replacement for the C `smtp_context` struct (transports/smtp.h lines
/// 143–230). Combines the client connection, input/output buffers, connection
/// parameters, and per-session flags into a single owned struct passed
/// explicitly through all outbound SMTP call chains.
///
/// This is the fundamental architectural change from C to Rust (AAP §0.4.4):
/// instead of 714 global variables, all mutable state is carried in this
/// struct and its sub-structs.
///
/// # C Equivalent
///
/// The C `smtp_context` struct contains:
/// - `client_conn_ctx cctx` — socket + TLS context
/// - `smtp_inblock inblock` — response input buffer
/// - `smtp_outblock outblock` — command output buffer
/// - `uschar buffer[DELIVER_BUFFER_SIZE]` — general response buffer
/// - `uschar inbuffer[4096]` — raw input buffer
/// - `uschar outbuffer[4096]` — raw output buffer
/// - ~30 boolean flags for session state
/// - peer capability and limit fields
/// - session parameters (max_mail, max_rcpt, helo_data, etc.)
#[derive(Debug)]
pub struct SmtpContext {
    /// Client connection context (socket + optional TLS session).
    pub cctx: ClientConnCtx,

    /// Input buffer for reading SMTP responses.
    pub inblock: SmtpInblock,

    /// Output buffer for pipelining SMTP commands.
    pub outblock: SmtpOutblock,

    /// General-purpose response/delivery buffer.
    ///
    /// Used for assembling multi-line SMTP responses and temporary data
    /// during delivery processing. Size matches C `DELIVER_BUFFER_SIZE`.
    pub buffer: Vec<u8>,

    // ── Connection State ──────────────────────────────────────────────────
    /// Connection parameters (host, port, interface, timeouts, DANE).
    pub conn_args: SmtpConnectArgs,

    /// Active port for the current connection.
    pub port: u16,

    // ── Session Flags ─────────────────────────────────────────────────────
    /// Whether this connection is for address verification (not delivery).
    pub verify: bool,

    /// Whether this is an LMTP (RFC 2033) connection rather than SMTP.
    pub lmtp: bool,

    /// Whether this is a TLS-on-connect (SMTPS, port 465) session.
    pub smtps: bool,

    /// General success flag for the current transaction step.
    pub ok: bool,

    /// Whether the connection is still in the setup phase (before delivery).
    pub setting_up: bool,

    /// Whether the server supports ESMTP (responded with EHLO capabilities).
    pub esmtp: bool,

    /// Whether an EHLO command has been sent on this connection.
    pub esmtp_sent: bool,

    /// Whether SMTP pipelining has been used on this connection.
    pub pipelining_used: bool,

    /// Whether a MAIL FROM command is pending (buffered, not yet sent).
    pub pending_mail: bool,

    /// Whether a BDAT command is pending (buffered, not yet sent).
    pub pending_bdat: bool,

    /// Whether the server returned 452 (too many recipients) on RCPT TO.
    pub rcpt_452: bool,

    /// Whether at least one RCPT TO was accepted (2xx response).
    pub good_rcpt: bool,

    /// Whether at least one address has been successfully delivered.
    pub completed_addr: bool,

    /// Whether an RSET command should be sent before the next MAIL FROM.
    pub send_rset: bool,

    /// Whether a QUIT command should be sent before closing.
    pub send_quit: bool,

    /// Whether a TLS close-notify should be sent before closing.
    pub send_tlsclose: bool,

    // ── Feature-Gated Flags ───────────────────────────────────────────────
    /// Whether early pipelining is permitted for this connection.
    ///
    /// Feature-gated behind `pipe-connect` (replacing C
    /// `#ifndef DISABLE_PIPE_CONNECT`).
    #[cfg(feature = "pipe-connect")]
    pub early_pipe_ok: bool,

    /// Whether early pipelining is currently active.
    #[cfg(feature = "pipe-connect")]
    pub early_pipe_active: bool,

    /// Whether the server banner response is pending (early pipeline).
    #[cfg(feature = "pipe-connect")]
    pub pending_banner: bool,

    /// Whether the EHLO response is pending (early pipeline).
    #[cfg(feature = "pipe-connect")]
    pub pending_ehlo: bool,

    /// Whether Per-Recipient Data Response is active for this session.
    ///
    /// Feature-gated behind `prdr` (replacing C `#ifndef DISABLE_PRDR`).
    #[cfg(feature = "prdr")]
    pub prdr_active: bool,

    /// Whether SMTPUTF8 is needed for this message.
    ///
    /// Feature-gated behind `i18n` (replacing C `#ifdef SUPPORT_I18N`).
    #[cfg(feature = "i18n")]
    pub utf8_needed: bool,

    /// Whether DANE/TLSA verification is required by transport config.
    ///
    /// Distinct from `conn_args.dane` which is per-connection; this flag
    /// is per-session and may be set by transport configuration.
    pub dane_required: bool,

    /// Whether single-recipient-per-domain batching is enforced by peer limits.
    ///
    /// Feature-gated behind `esmtp-limits` (replacing C
    /// `#ifndef DISABLE_ESMTP_LIMITS`).
    #[cfg(feature = "esmtp-limits")]
    pub single_rcpt_domain: bool,

    // ── Peer Capabilities ─────────────────────────────────────────────────
    /// Bitmask of ESMTP capabilities offered by the remote server.
    ///
    /// Populated from EHLO response parsing. Bit positions match C
    /// `OPTION_TLS`, `OPTION_IGNQ`, `OPTION_PRDR`, `OPTION_UTF8`, etc.
    /// from `macros.h` lines 1057+.
    pub peer_offered: u32,

    /// Server-imposed maximum messages per session (ESMTP LIMITS extension).
    #[cfg(feature = "esmtp-limits")]
    pub peer_limit_mail: u32,

    /// Server-imposed maximum recipients per message (ESMTP LIMITS extension).
    #[cfg(feature = "esmtp-limits")]
    pub peer_limit_rcpt: u32,

    /// Server-imposed maximum recipients per domain (ESMTP LIMITS extension).
    #[cfg(feature = "esmtp-limits")]
    pub peer_limit_rcptdom: u32,

    // ── Session Parameters ────────────────────────────────────────────────
    /// Maximum messages to send on this connection before disconnecting.
    pub max_mail: u32,

    /// Maximum recipients per message (from transport config or peer limits).
    pub max_rcpt: i32,

    /// Count of commands sent in the current pipeline batch.
    pub cmd_count: i32,

    /// Bitmask of ESMTP options to avoid (from transport config).
    pub avoid_option: u32,

    /// HELO/EHLO data string (expanded from transport config).
    pub helo_data: Option<String>,
}

impl SmtpContext {
    /// Create a new SMTP session context with the given connection parameters.
    ///
    /// Initialises all buffers to standard sizes and all flags to their
    /// default (safe) values, matching the C initialisation pattern in
    /// `transports/smtp.c`.
    ///
    /// # Arguments
    ///
    /// * `conn_args` — Pre-populated connection parameters including host,
    ///   port, address family, interface, timeouts, and DANE settings.
    pub fn new(conn_args: SmtpConnectArgs) -> Self {
        let port = conn_args.host_port;
        let sock = if conn_args.sock >= 0 {
            conn_args.sock
        } else {
            -1
        };

        SmtpContext {
            cctx: ClientConnCtx::new(sock),
            inblock: SmtpInblock::new(INBUFFER_SIZE),
            outblock: SmtpOutblock::new(OUTBUFFER_SIZE),
            buffer: vec![0u8; DELIVER_BUFFER_SIZE],
            conn_args,
            port,
            verify: false,
            lmtp: false,
            smtps: false,
            ok: false,
            setting_up: true,
            esmtp: false,
            esmtp_sent: false,
            pipelining_used: false,
            pending_mail: false,
            pending_bdat: false,
            rcpt_452: false,
            good_rcpt: false,
            completed_addr: false,
            send_rset: false,
            send_quit: false,
            send_tlsclose: false,
            #[cfg(feature = "pipe-connect")]
            early_pipe_ok: false,
            #[cfg(feature = "pipe-connect")]
            early_pipe_active: false,
            #[cfg(feature = "pipe-connect")]
            pending_banner: false,
            #[cfg(feature = "pipe-connect")]
            pending_ehlo: false,
            #[cfg(feature = "prdr")]
            prdr_active: false,
            #[cfg(feature = "i18n")]
            utf8_needed: false,
            dane_required: false,
            #[cfg(feature = "esmtp-limits")]
            single_rcpt_domain: false,
            peer_offered: 0,
            #[cfg(feature = "esmtp-limits")]
            peer_limit_mail: 0,
            #[cfg(feature = "esmtp-limits")]
            peer_limit_rcpt: 0,
            #[cfg(feature = "esmtp-limits")]
            peer_limit_rcptdom: 0,
            max_mail: 0,
            max_rcpt: 0,
            cmd_count: 0,
            avoid_option: 0,
            helo_data: None,
        }
    }
}
