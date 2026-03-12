//! SMTP response parsing and pipelined command writing.
//!
//! Stub module — provides type signatures for mod.rs re-exports.
//! Will be replaced by the implementation agent.

use std::fmt;
use std::time::Duration;

use super::{ClientConnCtx, CommandWriteMode, OutboundError, SmtpInblock, SmtpOutblock};

/// Custom errno for SMTP format errors (invalid reply code syntax).
///
/// Matches C `ERRNO_SMTPFORMAT` from `macros.h`.
pub const ERRNO_SMTPFORMAT: i32 = -10;

/// Custom errno for TLS failures during SMTP operations.
///
/// Matches C `ERRNO_TLSFAILURE` from `macros.h`.
pub const ERRNO_TLSFAILURE: i32 = -12;

/// Structured error for SMTP response parsing failures.
#[derive(Debug)]
pub struct SmtpResponseError {
    /// The SMTP reply code (e.g., 550, 421), or 0 if unparseable.
    pub code: u16,
    /// Whether this was an enhanced status code response.
    pub enhanced: bool,
    /// The response text following the reply code.
    pub message: String,
    /// Custom errno value for special error conditions.
    pub errno_value: i32,
}

impl fmt::Display for SmtpResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SMTP {} {}", self.code, self.message)
    }
}

impl std::error::Error for SmtpResponseError {}

/// Read a complete SMTP response (possibly multi-line) from the server.
///
/// Reads response lines from the input buffer, refilling from the socket as
/// needed, until a final response line (with space after the status code)
/// is received.
pub fn smtp_read_response(
    _cctx: &mut ClientConnCtx,
    _inblock: &mut SmtpInblock,
    _buffer: &mut [u8],
    _timeout: Duration,
) -> Result<(u16, String), OutboundError> {
    Err(OutboundError::ConnectionFailed {
        reason: "not yet implemented".into(),
    })
}

/// Write a formatted SMTP command to the output buffer.
///
/// Formats the command string, appends CRLF, and either buffers it (for
/// pipelining) or flushes immediately depending on the write mode.
pub fn smtp_write_command(
    _cctx: &mut ClientConnCtx,
    _outblock: &mut SmtpOutblock,
    _mode: CommandWriteMode,
    _command: &str,
) -> Result<(), OutboundError> {
    Err(OutboundError::ConnectionFailed {
        reason: "not yet implemented".into(),
    })
}

/// Flush all buffered commands to the network.
///
/// Transmits the contents of the output buffer to the socket (or TLS
/// session), handling partial writes and TCP Fast Open early data.
pub fn flush_buffer(
    _cctx: &mut ClientConnCtx,
    _outblock: &mut SmtpOutblock,
) -> Result<(), OutboundError> {
    Err(OutboundError::ConnectionFailed {
        reason: "not yet implemented".into(),
    })
}

/// Read a single SMTP response line from the input buffer.
pub fn read_response_line(
    _cctx: &mut ClientConnCtx,
    _inblock: &mut SmtpInblock,
    _timeout: Duration,
) -> Result<String, OutboundError> {
    Err(OutboundError::ConnectionFailed {
        reason: "not yet implemented".into(),
    })
}

/// Reap pending early-pipelined responses.
///
/// Feature-gated in the implementation behind `pipe-connect`.
pub fn smtp_reap_early_pipe(
    _cctx: &mut ClientConnCtx,
    _inblock: &mut SmtpInblock,
    _buffer: &mut [u8],
    _timeout: Duration,
) -> Result<(), OutboundError> {
    Err(OutboundError::ConnectionFailed {
        reason: "not yet implemented".into(),
    })
}
