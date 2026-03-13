//! SMTP response parsing and pipelined command writing for outbound connections.
//!
//! This module implements the core SMTP client I/O functions for the outbound
//! delivery path, translating the following C functions from `src/src/smtp_out.c`:
//!
//! | Rust Function | C Function | smtp_out.c Lines | Purpose |
//! |---------------|-----------|------------------|---------|
//! | [`read_response_line`] | `read_response_line()` | 739–806 | Read one SMTP response line with timeout |
//! | [`smtp_read_response`] | `smtp_read_response()` | 835–920 | Assemble multi-line SMTP response |
//! | [`smtp_write_command`] | `smtp_write_command()` | 649–715 | Buffer/send pipelined SMTP commands |
//! | [`flush_buffer`] | `flush_buffer()` | 549–625 | Flush output buffer to socket |
//! | [`smtp_reap_early_pipe`] | early-pipe reaping | 848–870 | Reap pipe-connect early responses |
//!
//! # Design (AAP §0.4.4 — Scoped Context Passing)
//!
//! All functions accept explicit `&mut ClientConnCtx`, `&mut SmtpInblock`,
//! and/or `&mut SmtpOutblock` parameters instead of relying on global mutable
//! state.  The C patterns of `smtp_inblock` / `smtp_outblock` globals and
//! `big_buffer` are replaced with these scoped structs.
//!
//! # Feature Flags
//!
//! | Feature | C Equivalent | Gates |
//! |---------|-------------|-------|
//! | `tls` | `#ifndef DISABLE_TLS` | TLS write path detection in [`flush_buffer`] |
//! | `pipe-connect` | `#ifndef DISABLE_PIPE_CONNECT` | Early pipeline reaping |
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks (AAP §0.7.2).  All socket
//! I/O uses safe wrappers: `nix::sys::socket::{send, recv}` for data
//! transfer and `exim_ffi::fd::*` helpers for poll/setsockopt operations
//! that require `BorrowedFd`.

// =============================================================================
// Imports
// =============================================================================

use std::io;
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};

use nix::sys::socket::{self, MsgFlags};
use thiserror::Error;
use tracing::{debug, error, trace, warn};

use super::connection::{sock_connect, tfo_out_check};
use super::{ClientConnCtx, CommandWriteMode, OutboundError, SmtpInblock, SmtpOutblock, TfoState};

// =============================================================================
// Constants
// =============================================================================

/// Custom errno for SMTP format errors (invalid reply code syntax).
///
/// Matches C `ERRNO_SMTPFORMAT` from `macros.h`.  Used when the remote
/// server sends a response that does not start with three ASCII digits
/// followed by a space, dash, or NUL.
pub const ERRNO_SMTPFORMAT: i32 = -10;

/// Custom errno for TLS failures during SMTP operations.
///
/// Matches C `ERRNO_TLSFAILURE` from `macros.h`.  Set when a TLS
/// handshake fails during pipe-connect early pipeline reaping.
pub const ERRNO_TLSFAILURE: i32 = -12;

// =============================================================================
// SmtpResponseError Enum
// =============================================================================

/// Structured error type for SMTP response parsing failures.
///
/// Provides fine-grained error variants for callers that need to distinguish
/// between different response parsing failure modes.  Convertible to the
/// broader [`OutboundError`] via the `From` implementation.
///
/// # C Equivalent
///
/// Replaces the C pattern of setting `errno` to custom values
/// (`ERRNO_SMTPFORMAT`, `ERRNO_TLSFAILURE`) and returning `-1` from
/// `read_response_line()` and `smtp_read_response()`.
#[derive(Debug, Error)]
pub enum SmtpResponseError {
    /// Invalid SMTP response format (missing or malformed reply code).
    ///
    /// The `line` field contains the raw response text for diagnostic
    /// logging.  Corresponds to C `errno = ERRNO_SMTPFORMAT`.
    #[error("SMTP format error: {line}")]
    FormatError {
        /// The malformed SMTP response line.
        line: String,
    },

    /// Read timeout expired before a complete response was received.
    ///
    /// Corresponds to C `errno = ETIMEDOUT` path in `ip_recv()`.
    #[error("SMTP read timeout")]
    Timeout,

    /// Remote server closed the connection (read returned 0 bytes).
    ///
    /// Corresponds to C `read()` returning 0 in `ip_recv()`.
    #[error("connection closed by remote")]
    ConnectionClosed,

    /// Underlying I/O error from socket operations.
    #[error("I/O error: {0}")]
    IoError(#[source] io::Error),

    /// Response buffer overflow — response line exceeds buffer capacity.
    ///
    /// Corresponds to C `ERRNO_SMTPFORMAT` when the response line is
    /// longer than the output buffer minus 4 bytes of safety margin.
    #[error("response buffer overflow")]
    BufferOverflow,
}

/// Convert `SmtpResponseError` to the broader `OutboundError` for public APIs.
impl From<SmtpResponseError> for OutboundError {
    fn from(err: SmtpResponseError) -> Self {
        match err {
            SmtpResponseError::FormatError { line } => OutboundError::FormatError { line },
            SmtpResponseError::Timeout => OutboundError::Timeout {
                duration: Duration::ZERO,
            },
            SmtpResponseError::ConnectionClosed => OutboundError::ConnectionClosed,
            SmtpResponseError::IoError(e) => OutboundError::Io(e),
            SmtpResponseError::BufferOverflow => OutboundError::BufferOverflow,
        }
    }
}

// =============================================================================
// Internal Helpers
// =============================================================================

/// Receive data from a socket with a poll-based timeout.
///
/// Replaces the C `ip_recv(cctx, buffer, buffersize, timelimit)` function
/// from `ip.c`.  Uses `exim_ffi::fd::safe_poll_fd_timeout` for safe
/// readability polling and `nix::sys::socket::recv` for the actual read.
///
/// # Returns
///
/// The number of bytes read on success.
///
/// # Errors
///
/// - `Timeout` if the deadline expires before data is available.
/// - `ConnectionClosed` if the remote closes the connection (0-byte read).
/// - `IoError` for any other socket error.
fn ip_recv(sock: RawFd, buf: &mut [u8], remaining: Duration) -> Result<usize, SmtpResponseError> {
    if sock < 0 {
        return Err(SmtpResponseError::IoError(io::Error::new(
            io::ErrorKind::NotConnected,
            "socket not connected (fd < 0)",
        )));
    }

    // Poll for readability with the remaining timeout.
    let timeout_ms: i32 = remaining.as_millis().try_into().unwrap_or(i32::MAX);
    let ready = exim_ffi::fd::safe_poll_fd_timeout(sock, timeout_ms)
        .map_err(|e| SmtpResponseError::IoError(io::Error::from(e)))?;

    if ready == 0 {
        return Err(SmtpResponseError::Timeout);
    }

    // Socket is readable — perform the actual read.
    match socket::recv(sock, buf, MsgFlags::empty()) {
        Ok(0) => Err(SmtpResponseError::ConnectionClosed),
        Ok(n) => {
            trace!("read response data: size={}", n);
            Ok(n)
        }
        Err(nix::errno::Errno::EAGAIN) => {
            // Spurious wakeup from poll — treat as timeout since no data.
            // Note: on Linux, EWOULDBLOCK == EAGAIN so a single arm suffices.
            Err(SmtpResponseError::Timeout)
        }
        Err(nix::errno::Errno::EINTR) => {
            // Interrupted by signal — treat as timeout to let caller retry.
            Err(SmtpResponseError::Timeout)
        }
        Err(e) => Err(SmtpResponseError::IoError(io::Error::from(e))),
    }
}

/// Mask authentication credentials in an SMTP command for debug logging.
///
/// When the outbound connection is in an AUTH exchange, command data
/// beyond the initial "AUTH mechanism" prefix must not appear in logs.
///
/// # C Equivalent
///
/// Replaces the masking logic in `smtp_write_command()` (smtp_out.c
/// lines 693–710) which overwrites credential bytes with `'*'`.
fn mask_auth_credential(command: &str, is_auth_line: bool) -> String {
    if is_auth_line {
        // For the initial AUTH command: preserve "AUTH <mechanism>" prefix,
        // mask everything after the second space.
        if let Some(stripped) = command.strip_prefix("AUTH ") {
            if let Some(space_pos) = stripped.find(' ') {
                let mechanism = &stripped[..space_pos];
                return format!("AUTH {} ****", mechanism);
            }
            // "AUTH PLAIN" with no inline data — show as-is (safe, no credential)
            return command.to_string();
        }
    }
    // During auth continuation lines: mask the entire content.
    "****".to_string()
}

// =============================================================================
// Public API — Response Reading
// =============================================================================

/// Read a single SMTP response line from the server.
///
/// Reads one line of SMTP response from the input buffer, refilling from the
/// socket with timeout as needed.  The line is stripped of trailing whitespace
/// and CR (handling both CRLF and bare LF line endings per RFC 5321 §2.3.8).
///
/// # C Equivalent
///
/// Replaces `read_response_line()` (smtp_out.c lines 739–806).
///
/// # Arguments
///
/// * `cctx` — Client connection context (provides socket fd).
/// * `inblock` — Input buffer (may contain pipelined response data).
/// * `timeout` — Maximum time to wait for data from the socket.
///
/// # Returns
///
/// The response line as a `String` (without trailing CRLF/LF).
///
/// # Errors
///
/// - [`OutboundError::Timeout`] if the deadline expires.
/// - [`OutboundError::ConnectionClosed`] if the remote closes the connection.
/// - [`OutboundError::BufferOverflow`] if the line exceeds buffer capacity.
pub fn read_response_line(
    cctx: &mut ClientConnCtx,
    inblock: &mut SmtpInblock,
    timeout: Duration,
) -> Result<String, OutboundError> {
    let deadline = Instant::now() + timeout;
    let mut line_buf: Vec<u8> = Vec::with_capacity(256);

    loop {
        // Phase 1: Consume data already in the inblock buffer.
        let remaining = inblock.remaining_data();
        if !remaining.is_empty() {
            // Scan for the end-of-line marker (\n).
            if let Some(nl_pos) = remaining.iter().position(|&b| b == b'\n') {
                // Found newline — extract the line including the \n.
                let line_bytes = &remaining[..nl_pos + 1];
                line_buf.extend_from_slice(line_bytes);
                inblock.advance_ptr(nl_pos + 1);

                // Strip trailing whitespace and CR (matching C lines 757–760).
                while line_buf
                    .last()
                    .is_some_and(|&b| b == b'\n' || b == b'\r' || b == b' ' || b == b'\t')
                {
                    line_buf.pop();
                }

                let line = String::from_utf8_lossy(&line_buf).into_owned();
                return Ok(line);
            }

            // No newline found — copy all remaining data and read more.
            let all_remaining = remaining.to_vec();
            let advance_len = all_remaining.len();
            line_buf.extend_from_slice(&all_remaining);
            inblock.advance_ptr(advance_len);

            // Guard against buffer overflow: if we've accumulated more data
            // than the buffer capacity allows, return a format error
            // (matching C `ERRNO_SMTPFORMAT` path).
            if line_buf.len() > inblock.capacity().saturating_sub(4) {
                warn!(
                    "SMTP response line exceeds buffer capacity ({} bytes)",
                    line_buf.len()
                );
                return Err(SmtpResponseError::BufferOverflow.into());
            }
        }

        // Phase 2: Refill the inblock buffer from the socket.
        let remaining_time = deadline.saturating_duration_since(Instant::now());
        if remaining_time.is_zero() {
            warn!("SMTP read timeout waiting for response line");
            return Err(SmtpResponseError::Timeout.into());
        }

        // Reset buffer pointers for a fresh socket read.
        let buf = inblock.buffer_mut();
        let n = ip_recv(cctx.sock, buf, remaining_time)?;

        // Update inblock state: ptr=0, ptrend=n (fresh data starts at 0).
        inblock.set_ptr(0);
        inblock.set_ptrend(n);
    }
}

/// Read a complete SMTP response (possibly multi-line) from the server.
///
/// Assembles a full SMTP response by reading lines until a terminal response
/// line is found (3 digits followed by a space or NUL, as opposed to a dash
/// which indicates continuation).
///
/// # Multi-line Response Assembly
///
/// Per RFC 5321 §4.2, multi-line responses use `NNN-` for continuation lines
/// and `NNN ` (or `NNN\0`) for the terminal line.  This function assembles
/// all lines into a single string separated by `\n`.
///
/// # C Equivalent
///
/// Replaces `smtp_read_response()` (smtp_out.c lines 835–920).
///
/// # Arguments
///
/// * `cctx` — Client connection context (provides socket fd and TFO state).
/// * `inblock` — Input buffer for pipelined response reading.
/// * `buffer` — Working buffer for response assembly (provided for API
///   compatibility; the actual assembly uses an internal `String`).
/// * `timeout` — Maximum time to wait for the complete response.
///
/// # Returns
///
/// `Ok((code, text))` where `code` is the 3-digit SMTP reply code (e.g. 250)
/// and `text` is the full response text (all lines joined with `\n`).
///
/// # Errors
///
/// - [`OutboundError::FormatError`] if the response does not conform to
///   RFC 5321 format (3 digits + separator).
/// - [`OutboundError::Timeout`] if the deadline expires.
/// - [`OutboundError::ConnectionClosed`] if the remote server closes.
pub fn smtp_read_response(
    cctx: &mut ClientConnCtx,
    inblock: &mut SmtpInblock,
    _buffer: &mut [u8],
    timeout: Duration,
) -> Result<(u16, String), OutboundError> {
    let mut full_response = String::new();
    let mut response_code: u16 = 0;
    let mut is_first_line = true;

    loop {
        // Read one response line (with timeout).
        let line = read_response_line(cctx, inblock, timeout)?;

        if line.is_empty() {
            return Err(SmtpResponseError::FormatError {
                line: "(empty response)".to_string(),
            }
            .into());
        }

        // Validate SMTP response format: first 3 characters must be digits.
        let line_bytes = line.as_bytes();
        if line_bytes.len() < 3
            || !line_bytes[0].is_ascii_digit()
            || !line_bytes[1].is_ascii_digit()
            || !line_bytes[2].is_ascii_digit()
        {
            error!("SMTP format error — invalid reply code: {}", line);
            return Err(SmtpResponseError::FormatError { line }.into());
        }

        // Parse the 3-digit reply code.
        // Safety: we verified all 3 are ASCII digits; parse cannot fail.
        let code: u16 = line[..3].parse().unwrap_or(0);

        if is_first_line {
            response_code = code;
            // Debug log matching C format: "  SMTP<< {line}" for exigrep
            // compatibility (AAP §0.7.1).
            debug!("  SMTP<< {}", line);
            is_first_line = false;
        } else {
            // Continuation lines logged with aligned indentation.
            debug!("        {}", line);
        }

        // Validate the 4th character (if present): must be space, dash, or NUL.
        let separator = if line_bytes.len() > 3 {
            line_bytes[3]
        } else {
            // Line is exactly 3 digits with no separator — treat as terminal.
            b' '
        };

        match separator {
            b'-' => {
                // Continuation line — append with newline separator.
                if !full_response.is_empty() {
                    full_response.push('\n');
                }
                full_response.push_str(&line);
            }
            b' ' | b'\0' => {
                // Terminal line — append and break.
                if !full_response.is_empty() {
                    full_response.push('\n');
                }
                full_response.push_str(&line);
                break;
            }
            _ => {
                // Invalid separator character — format error.
                error!(
                    "SMTP format error — invalid separator '{}' after code: {}",
                    separator as char, line
                );
                return Err(SmtpResponseError::FormatError { line }.into());
            }
        }
    }

    // Post-read: TFO diagnostic state transition (once per process).
    // Matches C `tfo_out_check(cctx->sock)` at smtp_out.c line 913.
    tfo_out_check(cctx.sock, &mut TfoState::default());

    Ok((response_code, full_response))
}

// =============================================================================
// Public API — Command Writing
// =============================================================================

/// Write a formatted SMTP command to the output buffer.
///
/// Formats the command string, appends CRLF, and either buffers it (for
/// pipelining) or flushes immediately depending on the write mode.  When the
/// connection is in an AUTH exchange, credential data is masked in debug
/// output to prevent passwords from appearing in logs.
///
/// # C Equivalent
///
/// Replaces `smtp_write_command()` (smtp_out.c lines 649–715).
///
/// # AUTH Credential Masking
///
/// When `outblock.authenticating` is `true` (during an AUTH exchange):
/// - **AUTH command lines**: `"AUTH PLAIN dXNlcjpwYXNz"` → `"AUTH PLAIN ****"`
///   (mechanism name preserved, credential data masked)
/// - **Continuation lines**: entire content replaced with `"****"`
///
/// This prevents credentials from appearing in Exim's debug log output.
///
/// # Arguments
///
/// * `cctx` — Client connection context (provides socket fd for flushing).
/// * `outblock` — Output buffer for command accumulation.
/// * `mode` — Controls whether to buffer, transmit with `MSG_MORE`, or flush.
/// * `command` — The SMTP command to send (without trailing CRLF).
///
/// # Returns
///
/// `Ok(())` on success.  The command is buffered (if `Buffer` mode) or
/// transmitted (if `More` or `Flush` mode).
///
/// # Errors
///
/// - [`OutboundError::BufferOverflow`] if the command exceeds buffer capacity.
/// - [`OutboundError::Io`] if socket write fails during flush.
pub fn smtp_write_command(
    cctx: &mut ClientConnCtx,
    outblock: &mut SmtpOutblock,
    mode: CommandWriteMode,
    command: &str,
) -> Result<(), OutboundError> {
    // Format the command with CRLF terminator (matching SMTP wire format).
    let formatted = format!("{}\r\n", command);
    let cmd_bytes = formatted.as_bytes();

    // Verify command fits in buffer capacity (panic on overlong — matching
    // C `log_write(0, LOG_MAIN|LOG_PANIC_DIE, ...)` at smtp_out.c line 672).
    if cmd_bytes.len() > outblock.capacity() {
        error!(
            "SMTP command exceeds buffer capacity ({} > {}): {}",
            cmd_bytes.len(),
            outblock.capacity(),
            command
        );
        return Err(OutboundError::BufferOverflow);
    }

    // If the command won't fit in remaining buffer space, flush first.
    if cmd_bytes.len() > outblock.available_space() {
        flush_buffer_with_mode(cctx, outblock, CommandWriteMode::Flush)?;
    }

    // Copy command bytes into the outblock buffer.
    outblock.write_bytes(cmd_bytes)?;
    outblock.cmd_count += 1;

    // AUTH credential masking for debug output (CRITICAL security feature,
    // matching C logic at smtp_out.c lines 693–710).
    let log_command = if outblock.authenticating {
        let is_auth_line = command
            .as_bytes()
            .first()
            .is_some_and(|&b| b == b'A' || b == b'a');
        mask_auth_credential(command, is_auth_line)
    } else {
        command.to_string()
    };

    // Debug log matching C format: "  SMTP>> {cmd}" for exigrep/eximstats
    // compatibility (AAP §0.7.1).
    debug!("  SMTP>> {}", log_command);

    // Mode-based flush control.
    match mode {
        CommandWriteMode::Buffer => {
            // Buffered only — nothing transmitted yet.
            Ok(())
        }
        CommandWriteMode::More | CommandWriteMode::Flush => {
            // Transmit the buffer contents.
            flush_buffer_with_mode(cctx, outblock, mode)
        }
    }
}

// =============================================================================
// Public API — Buffer Flushing
// =============================================================================

/// Flush all buffered commands to the network.
///
/// Transmits the contents of the output buffer to the socket, handling
/// partial writes, TCP Fast Open early data, and the Linux TCP_CORK
/// workaround for performance.
///
/// This is the public API that defaults to [`CommandWriteMode::Flush`].
///
/// # C Equivalent
///
/// Replaces `flush_buffer()` (smtp_out.c lines 549–625).
///
/// # Three Code Paths
///
/// 1. **TLS detection** (feature-gated `tls`): when TLS is active, signals
///    that the transport layer must use `tls_write_buffered()` from the
///    `tls_negotiation` module directly.
/// 2. **Connect-with-early-data**: establishes connection with buffered
///    data as TFO early data.
/// 3. **Plain send**: `send()` with optional `MSG_MORE` + TCP_CORK
///    workaround for pipelining performance.
pub fn flush_buffer(
    cctx: &mut ClientConnCtx,
    outblock: &mut SmtpOutblock,
) -> Result<(), OutboundError> {
    flush_buffer_with_mode(cctx, outblock, CommandWriteMode::Flush)
}

/// Mode-aware buffer flush — internal implementation.
///
/// Supports three modes via [`CommandWriteMode`]:
/// - `Flush`: transmit immediately, clear TCP_CORK if set on Linux.
/// - `More`: transmit with `MSG_MORE` hint for pipelining.
/// - `Buffer`: no-op (gracefully handles the case).
///
/// # TLS Path
///
/// When TLS is active (detected via [`ClientConnCtx::is_tls_active`]),
/// this function returns [`OutboundError::TlsError`] to signal the caller
/// (transport layer) that writes must go through `tls_write_buffered()`
/// which has access to the `TlsBackend` trait object.  This prevents
/// silent plaintext leakage on a TLS-protected connection.
///
/// # Connect-with-Early-Data Path
///
/// When `outblock.conn_args` is `Some`, establishes the TCP connection
/// with the buffered command data as TCP Fast Open early data, matching
/// C smtp_out.c lines 575–589.
///
/// # Linux TCP_CORK Workaround
///
/// After the final send (when `!more`), clears TCP_CORK via `setsockopt`
/// to force the kernel to flush any corked data immediately.  This works
/// around a Linux kernel behaviour where small writes are delayed ~200ms
/// despite TCP_NODELAY (critical for performance parity per AAP §0.7.5,
/// matching C smtp_out.c lines 614–617).
fn flush_buffer_with_mode(
    cctx: &mut ClientConnCtx,
    outblock: &mut SmtpOutblock,
    mode: CommandWriteMode,
) -> Result<(), OutboundError> {
    let n = outblock.buffered_bytes();
    if n == 0 {
        return Ok(());
    }

    let more = mode == CommandWriteMode::More;
    debug!(
        "cmd buf flush {} bytes{}",
        n,
        if more { " (more expected)" } else { "" }
    );

    // Null connection context check — socket must be valid.
    if cctx.sock < 0 {
        error!("flush_buffer() called with no connection (sock < 0)");
        return Err(OutboundError::ConnectionFailed {
            reason: "flush_buffer() called with no connection".into(),
        });
    }

    // Extract the buffered data for transmission.
    let data = outblock.buffer_slice().to_vec();

    // ── Path 1: TLS detection ────────────────────────────────────────────
    // Feature-gated behind `tls` replacing C `#ifndef DISABLE_TLS`.
    //
    // The TLS write path requires the `TlsBackend` trait object which is
    // owned by the transport layer.  At this abstraction level (raw cctx +
    // outblock), we detect TLS and signal the caller to use the
    // `tls_write_buffered()` function from `tls_negotiation` which has
    // access to the full `SmtpContext` and `TlsBackend`.
    #[cfg(feature = "tls")]
    {
        if cctx.is_tls_active() {
            error!(
                "flush_buffer called with active TLS session — \
                 transport layer should use tls_write_buffered"
            );
            return Err(OutboundError::TlsError {
                detail: "TLS flush requires transport-level tls_write_buffered path".into(),
            });
        }
    }

    // ── Path 2: Connect-with-early-data ──────────────────────────────────
    // If outblock.conn_args is set, establish connection with the buffer
    // content as TCP Fast Open early data (matching C smtp_out.c lines
    // 575–589).
    if outblock.conn_args.is_some() {
        // Take conn_args out of the outblock (clearing it for future flushes).
        let mut conn_args = outblock.conn_args.take().unwrap();
        debug!(
            "connect-with-early-data: {} bytes to {}:{}",
            n, conn_args.host_address, conn_args.host_port
        );

        // Establish connection with early data via the connection module.
        let new_sock = sock_connect(&mut conn_args, Some(&data)).map_err(|e| {
            error!("connect-with-early-data failed: {}", e);
            e
        })?;

        // Update the connection context with the new socket.
        cctx.sock = new_sock;

        // Reset the output buffer — all data was sent as early data.
        outblock.reset();
        return Ok(());
    }

    // ── Path 3: Plain send ───────────────────────────────────────────────
    // Normal socket send with optional MSG_MORE flag for pipelined batching.

    // Build send flags: MSG_MORE hint when more commands follow (Linux).
    #[cfg(target_os = "linux")]
    let flags = if more {
        MsgFlags::from_bits_truncate(libc::MSG_MORE)
    } else {
        MsgFlags::empty()
    };

    #[cfg(not(target_os = "linux"))]
    let flags = MsgFlags::empty();

    // Send the data.  Loop to handle partial writes.
    let mut sent = 0usize;
    while sent < data.len() {
        match socket::send(cctx.sock, &data[sent..], flags) {
            Ok(n_sent) => {
                sent += n_sent;
                trace!("sent {} bytes ({}/{})", n_sent, sent, data.len());
            }
            Err(nix::errno::Errno::EINTR) => {
                // Interrupted by signal — retry immediately.
                continue;
            }
            Err(e) => {
                error!("socket send failed: {}", e);
                return Err(OutboundError::Io(io::Error::from(e)));
            }
        }
    }

    // ── Linux TCP_CORK workaround ────────────────────────────────────────
    // When `!more`, clear TCP_CORK to force the kernel to flush any
    // corked data immediately.  This works around a Linux kernel behaviour
    // where small writes are delayed ~200ms despite TCP_NODELAY when
    // TCP_CORK was previously set.
    //
    // Critical for performance parity per AAP §0.7.5 — matches C
    // smtp_out.c lines 614–617.
    #[cfg(target_os = "linux")]
    {
        if !more {
            // Use exim-ffi safe wrapper to call setsockopt(TCP_CORK, 0).
            if let Err(e) =
                exim_ffi::fd::safe_setsockopt_int(cctx.sock, libc::IPPROTO_TCP, libc::TCP_CORK, 0)
            {
                // Non-fatal: log and continue.  The data was already sent.
                trace!("failed to clear TCP_CORK: {}", e);
            }
        }
    }

    // Reset the output buffer — all data was transmitted.
    outblock.reset();
    Ok(())
}

// =============================================================================
// Public API — Pipe-Connect Early Pipeline Support (Feature-Gated)
// =============================================================================

/// Reap pending early-pipelined responses (BANNER and/or EHLO).
///
/// In pipe-connect mode, the client sends EHLO (and optionally MAIL+RCPT)
/// before receiving the server banner.  This function reads and validates
/// the pending banner and EHLO responses before the main SMTP exchange
/// begins.
///
/// # Feature Gate
///
/// This function is compiled for both `pipe-connect` enabled and disabled
/// builds.  When `pipe-connect` is disabled, it is a no-op.  This
/// maintains API compatibility for callers that conditionally invoke it
/// (replacing C `#ifndef DISABLE_PIPE_CONNECT`).
///
/// # C Equivalent
///
/// Replaces the early-pipe reaping logic in `smtp_read_response()`
/// (smtp_out.c lines 848–870).
///
/// # Arguments
///
/// * `cctx` — Client connection context.
/// * `inblock` — Input buffer for response reading.
/// * `buffer` — Working buffer for response assembly.
/// * `timeout` — Maximum time to wait for each response.
///
/// # Errors
///
/// Returns [`OutboundError::ProtocolError`] if the banner or EHLO response
/// indicates a server-side failure (4xx/5xx).
#[cfg(feature = "pipe-connect")]
pub fn smtp_reap_early_pipe(
    cctx: &mut ClientConnCtx,
    inblock: &mut SmtpInblock,
    buffer: &mut [u8],
    timeout: Duration,
) -> Result<(), OutboundError> {
    // Read the server banner (expecting 220).
    debug!("reaping early-pipelined BANNER response");
    let (banner_code, banner_text) = smtp_read_response(cctx, inblock, buffer, timeout)?;
    if banner_code / 100 != 2 {
        warn!("early-pipe BANNER failed: {} {}", banner_code, banner_text);
        return Err(OutboundError::ProtocolError {
            message: format!(
                "server banner rejected connection: {} {}",
                banner_code, banner_text
            ),
        });
    }
    debug!("early-pipe BANNER accepted: {}", banner_code);

    // Read the EHLO response (expecting 250).
    debug!("reaping early-pipelined EHLO response");
    let (ehlo_code, ehlo_text) = smtp_read_response(cctx, inblock, buffer, timeout)?;
    if ehlo_code / 100 != 2 {
        warn!("early-pipe EHLO failed: {} {}", ehlo_code, ehlo_text);
        return Err(OutboundError::ProtocolError {
            message: format!(
                "server rejected EHLO in early pipeline: {} {}",
                ehlo_code, ehlo_text
            ),
        });
    }
    debug!("early-pipe EHLO accepted: {}", ehlo_code);

    Ok(())
}

/// No-op stub for when `pipe-connect` feature is disabled.
///
/// Maintains API compatibility — callers do not need to gate their invocations
/// with `#[cfg(feature = "pipe-connect")]`.
#[cfg(not(feature = "pipe-connect"))]
pub fn smtp_reap_early_pipe(
    _cctx: &mut ClientConnCtx,
    _inblock: &mut SmtpInblock,
    _buffer: &mut [u8],
    _timeout: Duration,
) -> Result<(), OutboundError> {
    Ok(())
}
