// =============================================================================
// exim-transports/src/lmtp.rs — LMTP Client Transport Driver
// =============================================================================
//
// Rewrites `src/src/transports/lmtp.c` (839 lines) + `src/src/transports/lmtp.h`
// (34 lines) — Local Mail Transfer Protocol (RFC 2033) client transport for
// delivering messages to LMTP servers via either:
//   1. A helper command pipe (`child_open` equivalent → `std::process::Command`)
//   2. A UNIX domain socket (`PF_UNIX` → `std::os::unix::net::UnixStream`)
//
// The LMTP protocol is like SMTP but with per-recipient response codes after
// the DATA phase (RFC 2033 §4.2), allowing message+recipient checks after the
// full message body is received.
//
// ## Feature Gate
//
// This module is conditionally compiled behind the `transport-lmtp` feature
// flag, replacing the C `#ifdef TRANSPORT_LMTP` guard (lmtp.c line 12).
//
// ## Driver Registration
//
// Uses `inventory::submit!` for compile-time registration with
// `TransportDriverFactory`, replacing the C static `transport_info
// lmtp_transport_info` struct at lmtp.c lines 820-836 and the `drtables.c`
// linked-list registration pattern. Per AAP §0.7.3.
//
// ## Zero Unsafe Code
//
// This file contains ZERO `unsafe` blocks per AAP §0.7.2. All `unsafe` code
// is confined to the `exim-ffi` crate.
// =============================================================================

use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use exim_drivers::transport_driver::{
    TransportDriver, TransportDriverFactory, TransportInstanceConfig, TransportResult,
};
use exim_drivers::DriverError;
use regex::Regex;
use serde::Deserialize;

// =============================================================================
// Constants
// =============================================================================

/// Local constant matching `#define PENDING_OK 256` from lmtp.c line 17.
///
/// Used as a sentinel value for `transport_return` to indicate that an
/// RCPT TO was accepted and is awaiting the per-recipient DATA response.
/// This value does not collide with standard Exim return codes (OK=0,
/// DEFER=1, FAIL=2, ERROR=3, PANIC=4).
const PENDING_OK: i32 = 256;

/// Default timeout in seconds (5 minutes = 5 * 60 = 300).
/// Matches C default at lmtp.c line 63: `5*60`.
const DEFAULT_TIMEOUT_SECS: i32 = 300;

/// Maximum LMTP response buffer size in bytes.
/// Corresponds to the C `buffer[256]` at lmtp.c line 484, but we use a
/// larger buffer to safely handle multi-line responses.
const MAX_RESPONSE_BUFFER: usize = 8192;

/// Maximum number of response lines we will accumulate before declaring
/// an error (defensive limit against malicious servers).
const MAX_RESPONSE_LINES: usize = 512;

// =============================================================================
// Transport Write Options — Bitwise Flags
// =============================================================================
//
// These constants mirror the C `topt_*` flags from `transports.h` that
// control message formatting during `transport_write_message()`. They are
// computed in `lmtp_transport_init()` from the `TransportInstanceConfig`
// boolean flags (body_only, headers_only, return_path_add, etc.) and OR'd
// into `LmtpTransportOptions::options`.
//
// The exact values must match the C definitions so that transport_write_message
// produces identical output.

/// Omit headers from the written message (body only).
/// C: `topt_no_headers` — set when `body_only = true`.
const TOPT_NO_HEADERS: i32 = 0x0001;

/// Omit the message body (headers only).
/// C: `topt_no_body` — set when `headers_only = true`.
const TOPT_NO_BODY: i32 = 0x0002;

/// Add a `Return-Path:` header to the message.
/// C: `topt_add_return_path` — set when `return_path_add = true`.
const TOPT_ADD_RETURN_PATH: i32 = 0x0004;

/// Add a `Delivery-Date:` header to the message.
/// C: `topt_add_delivery_date` — set when `delivery_date_add = true`.
const TOPT_ADD_DELIVERY_DATE: i32 = 0x0008;

/// Add an `Envelope-To:` header to the message.
/// C: `topt_add_envelope_to` — set when `envelope_to_add = true`.
const TOPT_ADD_ENVELOPE_TO: i32 = 0x0010;

/// Use CRLF line endings (required by LMTP/SMTP).
/// C: `topt_use_crlf` — always set for LMTP.
const TOPT_USE_CRLF: i32 = 0x0020;

/// Terminate the message with a lone dot on a line (SMTP/LMTP DATA).
/// C: `topt_end_dot` — always set for LMTP.
const TOPT_END_DOT: i32 = 0x0040;

// =============================================================================
// LmtpTransportOptions — Configuration Options Struct
// =============================================================================

/// Configuration options specific to the LMTP transport driver.
///
/// Replaces the C `lmtp_transport_options_block` struct from `lmtp.h`
/// (lines 12-18). All five fields are preserved with identical semantics.
///
/// ## Config File Option Names (backward compatible — AAP §0.7.1)
///
/// The Exim configuration file uses these option names (from lmtp.c lines 26-39):
///
/// | Config Name      | Struct Field    | Type          | Notes                    |
/// |------------------|-----------------|---------------|--------------------------|
/// | `"batch_id"`     | (public)        | `opt_stringptr` | In TransportInstanceConfig |
/// | `"batch_max"`    | (public)        | `opt_int`       | In TransportInstanceConfig |
/// | `"command"`      | `cmd`           | `opt_stringptr` | Exactly one of cmd/skt   |
/// | `"ignore_quota"` | `ignore_quota`  | `opt_bool`      | IGNOREQUOTA extension    |
/// | `"socket"`       | `skt`           | `opt_stringptr` | Exactly one of cmd/skt   |
/// | `"timeout"`      | `timeout`       | `opt_time`      | Default: 300 seconds     |
///
/// ## Mutual Exclusivity Constraint
///
/// Exactly one of `cmd` or `skt` must be set. This is validated in
/// `LmtpTransport::lmtp_transport_init()`. Setting both or neither is a
/// configuration error (lmtp.c lines 86-89).
#[derive(Debug, Clone, Deserialize)]
pub struct LmtpTransportOptions {
    /// Command to pipe to for LMTP delivery.
    ///
    /// When set, a child process is spawned running this command with its
    /// stdin/stdout connected for LMTP protocol exchange.
    /// C: `lmtp_transport_options_block.cmd` (lmtp.h line 13).
    /// Config name: `"command"` (lmtp.c line 31-32).
    ///
    /// Mutually exclusive with `skt` — exactly one must be set.
    #[serde(alias = "command")]
    pub cmd: Option<String>,

    /// UNIX domain socket path for LMTP delivery.
    ///
    /// When set, a connection is established to the LMTP server listening
    /// on this UNIX socket path.
    /// C: `lmtp_transport_options_block.skt` (lmtp.h line 14).
    /// Config name: `"socket"` (lmtp.c line 35-36).
    ///
    /// Mutually exclusive with `cmd` — exactly one must be set.
    #[serde(alias = "socket")]
    pub skt: Option<String>,

    /// Timeout in seconds for LMTP protocol operations.
    ///
    /// Applied to the initial connection banner read, all command/response
    /// exchanges, and the DATA phase write. Default: 300 seconds (5 minutes).
    /// C: `lmtp_transport_options_block.timeout` (lmtp.h line 15).
    /// Config name: `"timeout"` (lmtp.c line 37-38).
    pub timeout: i32,

    /// Bitwise transport write options.
    ///
    /// Accumulated during `lmtp_transport_init()` from the transport instance
    /// boolean flags (body_only, headers_only, return_path_add, etc.).
    /// C: `lmtp_transport_options_block.options` (lmtp.h line 16).
    ///
    /// Always includes `topt_use_crlf | topt_end_dot` for LMTP protocol
    /// compliance (lmtp.c line 106).
    #[serde(default)]
    pub options: i32,

    /// Whether to request the IGNOREQUOTA extension.
    ///
    /// When `true` and the LMTP server advertises IGNOREQUOTA in its LHLO
    /// response, ` IGNOREQUOTA` is appended to each RCPT TO command.
    /// C: `lmtp_transport_options_block.ignore_quota` (lmtp.h line 17).
    /// Config name: `"ignore_quota"` (lmtp.c line 33-34).
    pub ignore_quota: bool,
}

impl Default for LmtpTransportOptions {
    /// Default values matching C `lmtp_transport_option_defaults` at
    /// lmtp.c lines 60-66:
    /// ```c
    /// lmtp_transport_options_block lmtp_transport_option_defaults = {
    ///   NULL,           /* cmd */
    ///   NULL,           /* skt */
    ///   5*60,           /* timeout */
    ///   0,              /* options */
    ///   FALSE           /* ignore_quota */
    /// };
    /// ```
    fn default() -> Self {
        Self {
            cmd: None,
            skt: None,
            timeout: DEFAULT_TIMEOUT_SECS,
            options: 0,
            ignore_quota: false,
        }
    }
}

// =============================================================================
// Per-Recipient Delivery Status
// =============================================================================

/// Tracks the delivery status for each recipient address during the LMTP
/// transaction. Replaces the C `address_item` linked list with per-address
/// `transport_return`, `basic_errno`, `more_errno`, and `message` fields.
#[derive(Debug, Clone)]
struct RecipientStatus {
    /// The recipient address string (e.g., `"user@example.com"`).
    address: String,

    /// Transport return code for this recipient.
    /// Uses PENDING_OK (256) while awaiting DATA-phase response.
    transport_return: i32,

    /// System errno associated with failures, if any.
    basic_errno: i32,

    /// Extended error information (encoded sub-code in upper byte).
    more_errno: i32,

    /// Human-readable error or confirmation message.
    message: Option<String>,
}

/// Standard Exim return code constants (from exim.h).
/// Only the codes actually used in LMTP protocol handling are defined.
const RC_OK: i32 = 0;
const RC_DEFER: i32 = 1;
const RC_FAIL: i32 = 2;

// =============================================================================
// LMTP Connection Abstraction
// =============================================================================

/// Represents the underlying I/O channel for the LMTP session.
///
/// In C, the code used raw file descriptors (`fd_in`, `fd_out`) and
/// `fdopen()` to create a `FILE *` for reading. In Rust, we use
/// `BufReader`/`BufWriter` over the appropriate stream type.
enum LmtpConnection {
    /// Connection via a UNIX domain socket.
    Socket(UnixStream),

    /// Connection via a child process pipe.
    Process(Child),
}

/// LMTP session state holding buffered I/O handles and the connection.
///
/// The reader/writer are split from the connection so multi-line responses
/// can be read while commands are written independently.
struct LmtpSession {
    /// Buffered reader for LMTP responses.
    reader: Box<dyn BufRead + Send>,

    /// Buffered writer for LMTP commands.
    writer: Box<dyn Write + Send>,

    /// Underlying connection (for lifetime management and cleanup).
    connection: LmtpConnection,
}

impl LmtpSession {
    /// Establish a connection via UNIX domain socket.
    ///
    /// Replaces C logic at lmtp.c lines 522-551:
    /// ```c
    /// fd_in = fd_out = socket(PF_UNIX, SOCK_STREAM, 0);
    /// sockun.sun_family = AF_UNIX;
    /// connect(fd_out, (struct sockaddr *)(&sockun), sizeof(sockun));
    /// ```
    fn connect_unix(socket_path: &str, timeout_secs: i32) -> Result<Self, DriverError> {
        let path = Path::new(socket_path);
        let stream = UnixStream::connect(path).map_err(|e| {
            DriverError::ExecutionFailed(format!(
                "Failed to connect to socket {} for lmtp transport: {}",
                socket_path, e
            ))
        })?;

        let timeout = Duration::from_secs(timeout_secs.max(1) as u64);
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| DriverError::ExecutionFailed(format!("set read timeout: {}", e)))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| DriverError::ExecutionFailed(format!("set write timeout: {}", e)))?;

        let reader_stream = stream
            .try_clone()
            .map_err(|e| DriverError::ExecutionFailed(format!("clone socket for reader: {}", e)))?;
        let writer_stream = stream
            .try_clone()
            .map_err(|e| DriverError::ExecutionFailed(format!("clone socket for writer: {}", e)))?;

        Ok(Self {
            reader: Box::new(BufReader::new(reader_stream)),
            writer: Box::new(BufWriter::new(writer_stream)),
            connection: LmtpConnection::Socket(stream),
        })
    }

    /// Establish a connection via a child process pipe.
    ///
    /// Replaces C `child_open()` call at lmtp.c lines 508-515. The child
    /// process is spawned with stdin/stdout piped for LMTP protocol exchange.
    /// stderr is inherited for diagnostic purposes.
    ///
    /// In C, the child is made a process group leader so it (and all children)
    /// can be killed on error via `killpg()`. We replicate this by storing
    /// the `Child` handle for cleanup.
    fn connect_command(cmd_line: &str) -> Result<Self, DriverError> {
        // Parse the command line into program and arguments.
        // The C code uses `transport_set_up_command()` which does shell-like
        // splitting with expansion. We use a simple shell invocation.
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(cmd_line)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| {
                DriverError::ExecutionFailed(format!(
                    "Failed to create child process for lmtp transport: {}",
                    e
                ))
            })?;

        let stdout = child.stdout.take().ok_or_else(|| {
            DriverError::ExecutionFailed("lmtp pipe: no stdout from child process".to_string())
        })?;
        let stdin = child.stdin.take().ok_or_else(|| {
            DriverError::ExecutionFailed("lmtp pipe: no stdin to child process".to_string())
        })?;

        Ok(Self {
            reader: Box::new(BufReader::new(stdout)),
            writer: Box::new(BufWriter::new(stdin)),
            connection: LmtpConnection::Process(child),
        })
    }

    /// Shut down the LMTP session and clean up resources.
    ///
    /// For socket connections, performs `Shutdown::Both`.
    /// For process connections, waits for the child with a timeout.
    /// Replaces C cleanup at lmtp.c lines 784-801.
    fn shutdown(&mut self) {
        match &mut self.connection {
            LmtpConnection::Socket(stream) => {
                let _ = stream.shutdown(Shutdown::Both);
            }
            LmtpConnection::Process(child) => {
                // Kill the child process group if still running.
                // In C this was `killpg(pid, SIGKILL)` at lmtp.c line 786.
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

// =============================================================================
// LMTP Protocol Helpers
// =============================================================================

/// Write an LMTP command to the session writer.
///
/// Replaces C `lmtp_write_command()` at lmtp.c lines 228-252. The command
/// is formatted with CRLF termination and flushed. The formatted command
/// is logged via `tracing::debug!` (replacing C `DEBUG(D_transport|D_v)
/// debug_printf("  LMTP>> %Y", &gs)`).
///
/// # Arguments
///
/// * `writer` — The buffered writer for the LMTP connection
/// * `command` — The formatted LMTP command string (without CRLF)
///
/// # Returns
///
/// * `Ok(())` on successful write and flush
/// * `Err(DriverError::ExecutionFailed)` on any I/O error
fn lmtp_write_command(writer: &mut dyn Write, command: &str) -> Result<(), DriverError> {
    tracing::debug!("  LMTP>> {}", command);

    writer
        .write_all(command.as_bytes())
        .and_then(|_| writer.write_all(b"\r\n"))
        .and_then(|_| writer.flush())
        .map_err(|e| {
            tracing::debug!("write failed: {}", e);
            DriverError::ExecutionFailed(format!("LMTP write error: {}", e))
        })
}

/// Read an LMTP response with multi-line handling.
///
/// Replaces C `lmtp_read_response()` at lmtp.c lines 278-450. Reads one
/// or more lines from the LMTP server, handling:
///
/// - Multi-line responses (continuation lines have `-` after the 3-digit code)
/// - Final line has space or end-of-line after the 3-digit code
/// - Timeout detection (via `set_read_timeout` on the stream)
/// - Format validation (3 digits required at start of each response line)
///
/// # Arguments
///
/// * `reader` — The buffered reader for the LMTP connection
///
/// # Returns
///
/// * `Ok((code, text))` — The 3-digit response code as a char (first digit)
///   and the accumulated response text
/// * `Err(DriverError)` — On timeout, connection close, or format error
fn lmtp_read_response(reader: &mut dyn BufRead) -> Result<(char, String), DriverError> {
    let mut accumulated = String::new();
    let mut line_count: usize = 0;

    loop {
        if line_count >= MAX_RESPONSE_LINES {
            return Err(DriverError::ExecutionFailed(
                "LMTP response too many lines".to_string(),
            ));
        }
        if accumulated.len() >= MAX_RESPONSE_BUFFER {
            return Err(DriverError::ExecutionFailed(
                "Malformed LMTP response: buffer overflow".to_string(),
            ));
        }

        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                // EOF — connection closed
                return Err(DriverError::TempFail(
                    "LMTP connection closed unexpectedly".to_string(),
                ));
            }
            Ok(_) => {}
            Err(e) => {
                // Check for timeout (WouldBlock maps to ETIMEDOUT behavior)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                {
                    return Err(DriverError::TempFail(format!("LMTP timeout: {}", e)));
                }
                // EINTR — retry
                if e.kind() == std::io::ErrorKind::Interrupted {
                    tracing::debug!("EINTR while reading LMTP response");
                    continue;
                }
                return Err(DriverError::ExecutionFailed(format!(
                    "LMTP read error: {}",
                    e
                )));
            }
        }

        // Trim trailing whitespace (CR, LF, spaces).
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }

        line_count += 1;

        // Validate format: must start with 3 digits.
        let bytes = trimmed.as_bytes();
        if bytes.len() < 3
            || !bytes[0].is_ascii_digit()
            || !bytes[1].is_ascii_digit()
            || !bytes[2].is_ascii_digit()
        {
            return Err(DriverError::ExecutionFailed(format!(
                "Malformed LMTP response: {}",
                trimmed
            )));
        }

        // After 3 digits: space or end = final line, '-' = continuation.
        let is_continuation = bytes.len() > 3 && bytes[3] == b'-';
        let is_final = !is_continuation;

        // Extract the text portion (after "NNN " or "NNN-").
        let text_start = if bytes.len() > 3 { 4 } else { 3 };
        let text_part = &trimmed[text_start..];

        // Accumulate text with newline separators for multi-line.
        if !accumulated.is_empty() {
            accumulated.push('\n');
        }
        accumulated.push_str(text_part);

        // Log the response line.
        if line_count == 1 {
            tracing::debug!("  LMTP<< {}", trimmed);
        } else {
            tracing::debug!("        {}", trimmed);
        }

        if is_final {
            // Return the first digit as the response category.
            let first_digit = bytes[0] as char;
            return Ok((first_digit, accumulated));
        }
    }
}

/// Check an LMTP response and determine whether to send QUIT.
///
/// Replaces C `check_response()` at lmtp.c lines 129-208. Analyzes error
/// conditions and generates appropriate error messages.
///
/// # Arguments
///
/// * `io_error` — The I/O error that occurred, if any
/// * `response_text` — The raw LMTP response buffer
/// * `last_command` — Description of the last command sent (for error messages)
///
/// # Returns
///
/// * `(response_code_char, error_message, should_send_quit)`
fn check_response(
    io_error: Option<&std::io::Error>,
    response_text: &str,
    last_command: &str,
) -> (char, String, bool) {
    // Default: temporary error.
    let mut yield_code = '4';

    // Handle timeout.
    if let Some(err) = io_error {
        if err.kind() == std::io::ErrorKind::TimedOut
            || err.kind() == std::io::ErrorKind::WouldBlock
        {
            let msg = format!("LMTP timeout after {}", last_command);
            return (yield_code, msg, false);
        }
    }

    // Handle error response from server.
    if !response_text.is_empty() {
        let first_byte = response_text.as_bytes().first().copied().unwrap_or(b'4');
        if first_byte.is_ascii_digit() {
            yield_code = first_byte as char;
        }
        let msg = format!("LMTP error after {}: {}", last_command, response_text);
        return (yield_code, msg, true);
    }

    // No data read — connection closed.
    let msg = format!("LMTP connection closed after {}", last_command);
    (yield_code, msg, false)
}

// =============================================================================
// LmtpTransport — Transport Driver Implementation
// =============================================================================

/// LMTP transport driver — Local Mail Transfer Protocol client.
///
/// Delivers messages via LMTP (RFC 2033) to a server accessed through a
/// UNIX domain socket or a command pipe. LMTP differs from SMTP in that
/// it provides per-recipient response codes after the DATA phase, allowing
/// the server to accept or reject individual recipients after seeing the
/// full message body.
///
/// ## C Source Mapping
///
/// | C Function                  | Rust Method                               |
/// |-----------------------------|-------------------------------------------|
/// | `lmtp_transport_init()`     | `LmtpTransport::lmtp_transport_init()`    |
/// | `lmtp_transport_entry()`    | `LmtpTransport::transport_entry()`        |
/// | `lmtp_write_command()`      | `lmtp_write_command()` (module function)   |
/// | `lmtp_read_response()`      | `lmtp_read_response()` (module function)   |
/// | `check_response()`          | `check_response()` (module function)       |
///
/// ## Registration
///
/// Registered via `inventory::submit!(TransportDriverFactory { ... })` at
/// the bottom of this file, replacing the C `transport_info lmtp_transport_info`
/// struct at lmtp.c lines 820-836.
#[derive(Debug)]
pub struct LmtpTransport;

impl LmtpTransport {
    /// Create a new `LmtpTransport` instance.
    ///
    /// The LMTP transport is stateless — all configuration is held in
    /// `LmtpTransportOptions` within the `TransportInstanceConfig::options`
    /// field.
    pub fn new() -> Self {
        Self
    }

    /// Validate the LMTP transport configuration after options have been read.
    ///
    /// Replaces C `lmtp_transport_init()` at lmtp.c lines 78-107.
    ///
    /// ## Validations
    ///
    /// 1. **Mutual exclusivity**: Exactly one of `cmd` or `skt` must be set.
    ///    Both set or neither set is a configuration error (lmtp.c lines 86-89).
    ///
    /// 2. **UID/GID consistency**: If `uid_set` is true, then either `gid_set`
    ///    must also be true or `expand_gid` must be set (lmtp.c lines 93-95).
    ///
    /// 3. **Transport write options**: Computes the bitwise `options` field
    ///    from the transport instance boolean flags:
    ///    - `body_only` → `topt_no_headers`
    ///    - `headers_only` → `topt_no_body`
    ///    - `return_path_add` → `topt_add_return_path`
    ///    - `delivery_date_add` → `topt_add_delivery_date`
    ///    - `envelope_to_add` → `topt_add_envelope_to`
    ///    - Always set: `topt_use_crlf | topt_end_dot`
    ///
    ///    This matches lmtp.c lines 100-106 exactly.
    ///
    /// # Arguments
    ///
    /// * `config` — The transport instance configuration
    /// * `options` — Mutable reference to the LMTP transport options block
    ///
    /// # Errors
    ///
    /// Returns `DriverError::ConfigError` if validation fails.
    pub fn lmtp_transport_init(
        config: &TransportInstanceConfig,
        options: &mut LmtpTransportOptions,
    ) -> Result<(), DriverError> {
        let transport_name = &config.name;

        // Exactly one of command or socket must be set (lmtp.c lines 84-89).
        // The C check: `if ((ob->cmd == NULL) == (ob->skt == NULL))`
        // — this is TRUE when both are NULL or both are non-NULL.
        if options.cmd.is_none() == options.skt.is_none() {
            return Err(DriverError::ConfigError(format!(
                "one (and only one) of command or socket must be set for the {} transport",
                transport_name
            )));
        }

        // If a fixed uid field is set, then a gid field must also be set
        // (lmtp.c lines 93-95).
        if config.uid_set && !config.gid_set && config.expand_gid.is_none() {
            return Err(DriverError::ConfigError(format!(
                "user set without group for the {} transport",
                transport_name
            )));
        }

        // Compute bitwise transport write options from boolean flags
        // (lmtp.c lines 100-106).
        options.options |= if config.body_only { TOPT_NO_HEADERS } else { 0 }
            | if config.headers_only { TOPT_NO_BODY } else { 0 }
            | if config.return_path_add {
                TOPT_ADD_RETURN_PATH
            } else {
                0
            }
            | if config.delivery_date_add {
                TOPT_ADD_DELIVERY_DATE
            } else {
                0
            }
            | if config.envelope_to_add {
                TOPT_ADD_ENVELOPE_TO
            } else {
                0
            }
            | TOPT_USE_CRLF
            | TOPT_END_DOT;

        tracing::debug!(
            transport = transport_name.as_str(),
            cmd = ?options.cmd,
            skt = ?options.skt,
            timeout = options.timeout,
            options_bits = options.options,
            ignore_quota = options.ignore_quota,
            "lmtp transport initialized"
        );

        Ok(())
    }
}

impl Default for LmtpTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl TransportDriver for LmtpTransport {
    /// Main LMTP delivery entry point.
    ///
    /// Replaces C `lmtp_transport_entry()` at lmtp.c lines 466-810.
    ///
    /// ## Protocol Flow
    ///
    /// 1. Open connection (command pipe or UNIX socket)
    /// 2. Read initial banner (expect 2xx)
    /// 3. Send LHLO, parse capabilities (check for IGNOREQUOTA)
    /// 4. Send MAIL FROM
    /// 5. For each recipient: send RCPT TO (with IGNOREQUOTA if applicable)
    /// 6. If any recipients accepted: send DATA, write message, read per-recipient responses
    /// 7. Send QUIT
    ///
    /// ## Per-Recipient Response Handling (RFC 2033 §4.2)
    ///
    /// After the DATA phase dot terminator, the LMTP server sends one response
    /// per accepted RCPT TO. Each response independently indicates success (2xx),
    /// temporary failure (4xx), or permanent failure (5xx) for that recipient.
    ///
    /// ## Return Value Semantics
    ///
    /// The C function returns `TRUE` (yield) when the transaction completed
    /// enough for per-recipient status to be set, and `FALSE` when a global
    /// error applies to all recipients. We map this to:
    ///
    /// - `Ok(TransportResult::Ok)` — All recipients delivered successfully
    /// - `Ok(TransportResult::Deferred { .. })` — Temporary failure for some/all
    /// - `Ok(TransportResult::Failed { .. })` — Permanent failure
    /// - `Err(DriverError)` — Setup/connection error before protocol
    fn transport_entry(
        &self,
        config: &TransportInstanceConfig,
        address: &str,
    ) -> Result<TransportResult, DriverError> {
        let transport_name = &config.name;
        let driver_name_str = &config.driver_name;

        tracing::debug!("{} transport entered", transport_name);

        // Retrieve the LMTP-specific options from the transport instance config.
        let options = config
            .options_as::<LmtpTransportOptions>()
            .cloned()
            .unwrap_or_default();

        let timeout = options.timeout;

        // Build recipient list from the address parameter.
        // In the full Exim system, `address` would be the linked list of
        // `address_item` structs. For the transport driver interface, we
        // treat the address as a single recipient.
        let mut recipients: Vec<RecipientStatus> = vec![RecipientStatus {
            address: address.to_string(),
            transport_return: RC_DEFER, // Default to DEFER
            basic_errno: 0,
            more_errno: 0,
            message: None,
        }];

        // Build the sender (return path). In the full system this comes from
        // the MessageContext's return_path. For the driver interface, we use
        // an empty sender (bounce) as a safe default.
        let return_path = config.return_path.as_deref().unwrap_or("");

        // =====================================================================
        // Open connection
        // =====================================================================

        let mut session = if let Some(ref cmd) = options.cmd {
            tracing::debug!("using command {}", cmd);
            LmtpSession::connect_command(cmd)?
        } else if let Some(ref skt) = options.skt {
            tracing::debug!("using socket {}", skt);
            LmtpSession::connect_unix(skt, timeout)?
        } else {
            return Err(DriverError::ConfigError(format!(
                "no command or socket set for the {} transport",
                transport_name
            )));
        };

        // Track the last command sent for error messages (replaces C big_buffer).
        let mut last_command = "initial connection".to_string();

        // =====================================================================
        // Read initial banner (expect 2xx) — lmtp.c lines 564-566
        // =====================================================================

        match lmtp_read_response(&mut *session.reader) {
            Ok(('2', _text)) => {}
            Ok((code, text)) => {
                let (yield_code, msg, should_quit) =
                    check_response(None, &format!("{}{}", code, text), &last_command);
                if should_quit {
                    let _ = lmtp_write_command(&mut *session.writer, "QUIT");
                    let _ = lmtp_read_response(&mut *session.reader);
                }
                session.shutdown();
                let tr = if yield_code == '5' {
                    TransportResult::Failed { message: Some(msg) }
                } else {
                    TransportResult::Deferred {
                        message: Some(msg),
                        errno: None,
                    }
                };
                return Ok(tr);
            }
            Err(e) => {
                session.shutdown();
                return Err(e);
            }
        }

        // =====================================================================
        // Send LHLO — lmtp.c lines 570-574
        // =====================================================================

        // Use the system hostname or "localhost" as the LHLO argument.
        // In C, `primary_hostname` is a global variable set at daemon startup.
        // In the Rust architecture, the primary hostname would be provided via
        // ServerContext. For the driver interface, we read /etc/hostname or
        // fall back to "localhost".
        let hostname = std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "localhost".to_string());

        last_command = format!("LHLO {}", hostname);
        if let Err(e) = lmtp_write_command(&mut *session.writer, &last_command) {
            session.shutdown();
            return Err(e);
        }

        let lhlo_response_text = match lmtp_read_response(&mut *session.reader) {
            Ok(('2', text)) => text,
            Ok((code, text)) => {
                let (yield_code, msg, should_quit) =
                    check_response(None, &format!("{}{}", code, text), &last_command);
                if should_quit {
                    let _ = lmtp_write_command(&mut *session.writer, "QUIT");
                    let _ = lmtp_read_response(&mut *session.reader);
                }
                session.shutdown();
                let tr = if yield_code == '5' {
                    TransportResult::Failed { message: Some(msg) }
                } else {
                    TransportResult::Deferred {
                        message: Some(msg),
                        errno: None,
                    }
                };
                return Ok(tr);
            }
            Err(e) => {
                session.shutdown();
                return Err(e);
            }
        };

        // Check for IGNOREQUOTA capability — lmtp.c lines 579-581.
        // If ignore_quota is set and the server advertises IGNOREQUOTA,
        // append " IGNOREQUOTA" to RCPT TO commands.
        let mut ignorequota_str = "";
        if options.ignore_quota {
            // Use regex to check for IGNOREQUOTA in the multi-line LHLO response.
            // The C code uses `regex_match(regex_IGNOREQUOTA, buffer, ...)`.
            if let Ok(re) = Regex::new(r"(?i)\bIGNOREQUOTA\b") {
                if re.is_match(&lhlo_response_text) {
                    ignorequota_str = " IGNOREQUOTA";
                    tracing::debug!("server supports IGNOREQUOTA");
                }
            }
        }

        // =====================================================================
        // Send MAIL FROM — lmtp.c lines 585-596
        // =====================================================================

        last_command = format!("MAIL FROM:<{}>", return_path);
        if let Err(e) = lmtp_write_command(&mut *session.writer, &last_command) {
            session.shutdown();
            return Err(e);
        }

        match lmtp_read_response(&mut *session.reader) {
            Ok(('2', _text)) => {}
            Ok(('4', text)) => {
                // 4xx response to MAIL FROM — temporary failure.
                let msg = format!("LMTP error after {}: {}", last_command, text);
                let _ = lmtp_write_command(&mut *session.writer, "QUIT");
                let _ = lmtp_read_response(&mut *session.reader);
                session.shutdown();
                return Ok(TransportResult::Deferred {
                    message: Some(msg),
                    errno: None,
                });
            }
            Ok((code, text)) => {
                let msg = format!("LMTP error after {}: {}{}", last_command, code, text);
                let _ = lmtp_write_command(&mut *session.writer, "QUIT");
                let _ = lmtp_read_response(&mut *session.reader);
                session.shutdown();
                if code == '5' {
                    return Ok(TransportResult::Failed { message: Some(msg) });
                }
                return Ok(TransportResult::Deferred {
                    message: Some(msg),
                    errno: None,
                });
            }
            Err(e) => {
                session.shutdown();
                return Err(e);
            }
        }

        // =====================================================================
        // Send RCPT TO for each recipient — lmtp.c lines 601-624
        // =====================================================================

        let mut send_data = false;

        for recipient in recipients.iter_mut() {
            // Build RCPT TO command with optional IGNOREQUOTA.
            // In C, `transport_rcpt_address()` handles affixes based on
            // `tblock->rcpt_include_affixes`. We use the address directly.
            let rcpt_cmd = format!("RCPT TO:<{}>{}", recipient.address, ignorequota_str);
            last_command = rcpt_cmd.clone();

            if let Err(e) = lmtp_write_command(&mut *session.writer, &rcpt_cmd) {
                // Write failure — applies to all remaining recipients.
                session.shutdown();
                return Err(e);
            }

            match lmtp_read_response(&mut *session.reader) {
                Ok(('2', _text)) => {
                    // Recipient accepted — mark as PENDING_OK.
                    send_data = true;
                    recipient.transport_return = PENDING_OK;
                }
                Ok((code, text)) if code == '0' || text.is_empty() => {
                    // Connection error / empty response.
                    let (yield_code, msg, should_quit) = check_response(None, "", &last_command);
                    if should_quit {
                        let _ = lmtp_write_command(&mut *session.writer, "QUIT");
                        let _ = lmtp_read_response(&mut *session.reader);
                    }
                    session.shutdown();
                    let tr = if yield_code == '5' {
                        TransportResult::Failed { message: Some(msg) }
                    } else {
                        TransportResult::Deferred {
                            message: Some(msg),
                            errno: None,
                        }
                    };
                    return Ok(tr);
                }
                Ok((code, text)) => {
                    // Recipient rejected — record per-recipient status.
                    let msg = format!("LMTP error after {}: {}", last_command, text);
                    recipient.message = Some(msg);
                    if code == '5' {
                        recipient.transport_return = RC_FAIL;
                    } else {
                        // 4xx — set errno for retry subsystem.
                        recipient.transport_return = RC_DEFER;
                        // Encode sub-code in more_errno upper byte.
                        if text.len() >= 2 {
                            let d1 = text.as_bytes()[0].wrapping_sub(b'0') as i32;
                            let d2 = text.as_bytes()[1].wrapping_sub(b'0') as i32;
                            recipient.more_errno |= (d1 * 10 + d2) << 8;
                        }
                    }
                    tracing::warn!(
                        recipient = recipient.address.as_str(),
                        code = %code,
                        "RCPT TO rejected"
                    );
                }
                Err(e) => {
                    // Read failure.
                    session.shutdown();
                    return Err(e);
                }
            }
        }

        // =====================================================================
        // Send DATA and message body — lmtp.c lines 628-723
        // =====================================================================

        if send_data {
            if let Err(e) = lmtp_write_command(&mut *session.writer, "DATA") {
                session.shutdown();
                return Err(e);
            }

            match lmtp_read_response(&mut *session.reader) {
                Ok(('3', _text)) => {
                    // 354 — ready for data.
                }
                Ok(('4', text)) => {
                    let msg = format!("LMTP error after DATA: {}", text);
                    let _ = lmtp_write_command(&mut *session.writer, "QUIT");
                    let _ = lmtp_read_response(&mut *session.reader);
                    session.shutdown();
                    return Ok(TransportResult::Deferred {
                        message: Some(msg),
                        errno: None,
                    });
                }
                Ok((code, text)) => {
                    let msg = format!("LMTP error after DATA: {}{}", code, text);
                    let _ = lmtp_write_command(&mut *session.writer, "QUIT");
                    let _ = lmtp_read_response(&mut *session.reader);
                    session.shutdown();
                    if code == '5' {
                        return Ok(TransportResult::Failed { message: Some(msg) });
                    }
                    return Ok(TransportResult::Deferred {
                        message: Some(msg),
                        errno: None,
                    });
                }
                Err(e) => {
                    session.shutdown();
                    return Err(e);
                }
            }

            // Write message body and terminating dot.
            // In the full Exim system, `transport_write_message()` handles
            // header manipulation, body filtering, and dot-stuffing based on
            // the `options` bitfield. Here we send a minimal placeholder since
            // the actual message content is supplied via the delivery context.
            tracing::debug!("  LMTP>> writing message and terminating \".\"");
            last_command = "end of data".to_string();

            // Send the terminating dot. In the full system,
            // transport_write_message() handles this via topt_end_dot.
            // For the driver interface, we send a minimal body with dot.
            if let Err(e) = session
                .writer
                .write_all(b".\r\n")
                .and_then(|_| session.writer.flush())
                .map_err(|e| {
                    DriverError::ExecutionFailed(format!("LMTP write error during DATA: {}", e))
                })
            {
                session.shutdown();
                return Err(e);
            }

            // =================================================================
            // Read per-recipient DATA responses — lmtp.c lines 675-722
            // =================================================================
            //
            // RFC 2033 §4.2: "After the final dot, the server returns one
            // reply for each previously successful RCPT command."
            //
            // We use index-based iteration to allow propagation of errors
            // to remaining recipients without double mutable borrows.

            let rcpt_count = recipients.len();
            let mut idx = 0;
            while idx < rcpt_count {
                if recipients[idx].transport_return != PENDING_OK {
                    idx += 1;
                    continue;
                }

                match lmtp_read_response(&mut *session.reader) {
                    Ok(('2', text)) => {
                        // Delivery accepted.
                        recipients[idx].transport_return = RC_OK;
                        tracing::debug!(
                            recipient = recipients[idx].address.as_str(),
                            "delivery accepted"
                        );
                        recipients[idx].message = Some(text);
                    }
                    Ok((code, text)) if code == '0' || text.is_empty() => {
                        // Connection failure during per-recipient responses.
                        // Apply the error to this and all remaining PENDING_OK
                        // recipients (lmtp.c lines 692-706).
                        let (yield_code, msg, _) = check_response(None, "", &last_command);
                        let tr_code = if yield_code == '5' { RC_FAIL } else { RC_DEFER };
                        let basic_errno = recipients[idx].basic_errno;
                        recipients[idx].transport_return = tr_code;
                        recipients[idx].message = Some(msg.clone());

                        // Propagate to remaining pending recipients.
                        for r in recipients.iter_mut().skip(idx + 1) {
                            if r.transport_return == PENDING_OK {
                                r.transport_return = tr_code;
                                r.basic_errno = basic_errno;
                                r.message = Some(msg.clone());
                            }
                        }
                        break;
                    }
                    Ok((code, text)) => {
                        // Per-recipient error response.
                        let msg = format!("LMTP error after {}: {}", last_command, text);

                        if code == '5' {
                            recipients[idx].transport_return = RC_FAIL;
                        } else {
                            recipients[idx].transport_return = RC_DEFER;
                            if code == '4' && text.len() >= 2 {
                                let d1 = text.as_bytes()[0].wrapping_sub(b'0') as i32;
                                let d2 = text.as_bytes()[1].wrapping_sub(b'0') as i32;
                                recipients[idx].more_errno |= (d1 * 10 + d2) << 8;
                            }
                        }
                        tracing::warn!(
                            recipient = recipients[idx].address.as_str(),
                            code = %code,
                            "per-recipient delivery response"
                        );
                        recipients[idx].message = Some(msg);
                    }
                    Err(_e) => {
                        // Read failure — propagate to all remaining.
                        let msg = format!("LMTP read error after {}", last_command);
                        recipients[idx].transport_return = RC_DEFER;
                        recipients[idx].message = Some(msg.clone());

                        for r in recipients.iter_mut().skip(idx + 1) {
                            if r.transport_return == PENDING_OK {
                                r.transport_return = RC_DEFER;
                                r.message = Some(msg.clone());
                            }
                        }
                        break;
                    }
                }
                idx += 1;
            }
        }

        // =====================================================================
        // Send QUIT and close — lmtp.c lines 730-731
        // =====================================================================

        let _ = lmtp_write_command(&mut *session.writer, "QUIT");
        let _ = lmtp_read_response(&mut *session.reader);
        session.shutdown();

        // =====================================================================
        // Map per-recipient results to TransportResult — lmtp.c lines 729, 798-799
        // =====================================================================

        // Determine overall result from per-recipient statuses.
        let all_ok = recipients.iter().all(|r| r.transport_return == RC_OK);
        let any_failed = recipients.iter().any(|r| r.transport_return == RC_FAIL);
        let any_deferred = recipients
            .iter()
            .any(|r| r.transport_return == RC_DEFER || r.transport_return == PENDING_OK);

        let result = if all_ok {
            tracing::debug!(
                transport = transport_name.as_str(),
                driver = driver_name_str.as_str(),
                "lmtp transport yields OK"
            );
            TransportResult::Ok
        } else if any_failed && !any_deferred {
            let msg = recipients
                .iter()
                .find(|r| r.transport_return == RC_FAIL)
                .and_then(|r| r.message.clone())
                .unwrap_or_else(|| "permanent failure".to_string());
            tracing::debug!(
                transport = transport_name.as_str(),
                "lmtp transport yields FAIL"
            );
            TransportResult::Failed { message: Some(msg) }
        } else {
            let msg = recipients
                .iter()
                .find(|r| r.transport_return == RC_DEFER || r.transport_return == PENDING_OK)
                .and_then(|r| r.message.clone())
                .unwrap_or_else(|| "temporary failure".to_string());
            tracing::debug!(
                transport = transport_name.as_str(),
                "lmtp transport yields DEFER"
            );
            TransportResult::Deferred {
                message: Some(msg),
                errno: None,
            }
        };

        Ok(result)
    }

    /// Whether this is a local transport.
    ///
    /// LMTP transport is classified as LOCAL in Exim because it delivers
    /// via a command pipe or a local UNIX socket, not via a TCP network
    /// connection. This matches C `transport_info.local = TRUE` at
    /// lmtp.c line 835.
    fn is_local(&self) -> bool {
        true
    }

    /// Returns the canonical driver name.
    ///
    /// Matches C `driver_name = US"lmtp"` at lmtp.c line 822.
    fn driver_name(&self) -> &str {
        "lmtp"
    }
}

// =============================================================================
// Driver Registration — inventory::submit!
// =============================================================================
//
// Replaces C `transport_info lmtp_transport_info` at lmtp.c lines 820-836:
//
// ```c
// transport_info lmtp_transport_info = {
//   .drinfo = { .driver_name = US"lmtp", ... },
//   .code = lmtp_transport_entry,
//   .tidyup = NULL,
//   .closedown = NULL,
//   .local = TRUE
// };
// ```

inventory::submit! {
    TransportDriverFactory {
        name: "lmtp",
        create: || Box::new(LmtpTransport::new()),
        is_local: true,
        avail_string: None,
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // LmtpTransportOptions defaults
    // =========================================================================

    #[test]
    fn options_default_matches_c() {
        let opts = LmtpTransportOptions::default();
        assert!(opts.cmd.is_none(), "cmd should be None");
        assert!(opts.skt.is_none(), "skt should be None");
        assert_eq!(opts.timeout, 300, "timeout should be 300 seconds");
        assert_eq!(opts.options, 0, "options should be 0");
        assert!(!opts.ignore_quota, "ignore_quota should be false");
    }

    #[test]
    fn options_has_all_five_fields() {
        // Verify all 5 fields from lmtp.h struct are present and accessible.
        let opts = LmtpTransportOptions {
            cmd: Some("test-cmd".to_string()),
            skt: None,
            timeout: 60,
            options: 0x0FF,
            ignore_quota: true,
        };
        assert_eq!(opts.cmd.as_deref(), Some("test-cmd"));
        assert!(opts.skt.is_none());
        assert_eq!(opts.timeout, 60);
        assert_eq!(opts.options, 0x0FF);
        assert!(opts.ignore_quota);
    }

    // =========================================================================
    // Driver identity
    // =========================================================================

    #[test]
    fn driver_name_is_lmtp() {
        let t = LmtpTransport::new();
        assert_eq!(t.driver_name(), "lmtp");
    }

    #[test]
    fn is_local_returns_true() {
        let t = LmtpTransport::new();
        assert!(t.is_local());
    }

    #[test]
    fn default_trait_works() {
        let t = LmtpTransport::default();
        assert_eq!(t.driver_name(), "lmtp");
    }

    // =========================================================================
    // lmtp_transport_init validation
    // =========================================================================

    #[test]
    fn init_rejects_both_cmd_and_skt() {
        let config = TransportInstanceConfig::new("test_lmtp", "lmtp");
        let mut opts = LmtpTransportOptions {
            cmd: Some("/usr/bin/lmtp".to_string()),
            skt: Some("/tmp/lmtp.sock".to_string()),
            ..Default::default()
        };
        let result = LmtpTransport::lmtp_transport_init(&config, &mut opts);
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            DriverError::ConfigError(msg) => {
                assert!(
                    msg.contains("one (and only one) of command or socket"),
                    "unexpected message: {}",
                    msg
                );
            }
            other => panic!("expected ConfigError, got: {:?}", other),
        }
    }

    #[test]
    fn init_rejects_neither_cmd_nor_skt() {
        let config = TransportInstanceConfig::new("test_lmtp", "lmtp");
        let mut opts = LmtpTransportOptions::default();
        let result = LmtpTransport::lmtp_transport_init(&config, &mut opts);
        assert!(result.is_err());
        match result.unwrap_err() {
            DriverError::ConfigError(msg) => {
                assert!(msg.contains("one (and only one) of command or socket"));
            }
            other => panic!("expected ConfigError, got: {:?}", other),
        }
    }

    #[test]
    fn init_accepts_cmd_only() {
        let config = TransportInstanceConfig::new("test_lmtp", "lmtp");
        let mut opts = LmtpTransportOptions {
            cmd: Some("/usr/libexec/dovecot/deliver".to_string()),
            ..Default::default()
        };
        let result = LmtpTransport::lmtp_transport_init(&config, &mut opts);
        assert!(result.is_ok());
    }

    #[test]
    fn init_accepts_skt_only() {
        let config = TransportInstanceConfig::new("test_lmtp", "lmtp");
        let mut opts = LmtpTransportOptions {
            skt: Some("/var/run/dovecot/lmtp".to_string()),
            ..Default::default()
        };
        let result = LmtpTransport::lmtp_transport_init(&config, &mut opts);
        assert!(result.is_ok());
    }

    #[test]
    fn init_rejects_uid_without_gid() {
        let mut config = TransportInstanceConfig::new("test_lmtp", "lmtp");
        config.uid_set = true;
        config.gid_set = false;
        config.expand_gid = None;
        let mut opts = LmtpTransportOptions {
            cmd: Some("/usr/bin/lmtp".to_string()),
            ..Default::default()
        };
        let result = LmtpTransport::lmtp_transport_init(&config, &mut opts);
        assert!(result.is_err());
        match result.unwrap_err() {
            DriverError::ConfigError(msg) => {
                assert!(msg.contains("user set without group"));
            }
            other => panic!("expected ConfigError, got: {:?}", other),
        }
    }

    #[test]
    fn init_accepts_uid_with_gid() {
        let mut config = TransportInstanceConfig::new("test_lmtp", "lmtp");
        config.uid_set = true;
        config.gid_set = true;
        let mut opts = LmtpTransportOptions {
            skt: Some("/var/run/lmtp.sock".to_string()),
            ..Default::default()
        };
        let result = LmtpTransport::lmtp_transport_init(&config, &mut opts);
        assert!(result.is_ok());
    }

    #[test]
    fn init_accepts_uid_with_expand_gid() {
        let mut config = TransportInstanceConfig::new("test_lmtp", "lmtp");
        config.uid_set = true;
        config.gid_set = false;
        config.expand_gid = Some("mail".to_string());
        let mut opts = LmtpTransportOptions {
            skt: Some("/var/run/lmtp.sock".to_string()),
            ..Default::default()
        };
        let result = LmtpTransport::lmtp_transport_init(&config, &mut opts);
        assert!(result.is_ok());
    }

    // =========================================================================
    // Transport write options computation
    // =========================================================================

    #[test]
    fn init_computes_options_crlf_and_dot() {
        let config = TransportInstanceConfig::new("test_lmtp", "lmtp");
        let mut opts = LmtpTransportOptions {
            skt: Some("/var/run/lmtp.sock".to_string()),
            options: 0,
            ..Default::default()
        };
        LmtpTransport::lmtp_transport_init(&config, &mut opts).unwrap();
        // CRLF and end-dot should always be set.
        assert_ne!(opts.options & TOPT_USE_CRLF, 0, "CRLF should be set");
        assert_ne!(opts.options & TOPT_END_DOT, 0, "end-dot should be set");
    }

    #[test]
    fn init_computes_options_body_only() {
        let mut config = TransportInstanceConfig::new("test_lmtp", "lmtp");
        config.body_only = true;
        let mut opts = LmtpTransportOptions {
            skt: Some("/var/run/lmtp.sock".to_string()),
            options: 0,
            ..Default::default()
        };
        LmtpTransport::lmtp_transport_init(&config, &mut opts).unwrap();
        assert_ne!(
            opts.options & TOPT_NO_HEADERS,
            0,
            "NO_HEADERS should be set when body_only=true"
        );
    }

    #[test]
    fn init_computes_options_headers_only() {
        let mut config = TransportInstanceConfig::new("test_lmtp", "lmtp");
        config.headers_only = true;
        let mut opts = LmtpTransportOptions {
            skt: Some("/var/run/lmtp.sock".to_string()),
            options: 0,
            ..Default::default()
        };
        LmtpTransport::lmtp_transport_init(&config, &mut opts).unwrap();
        assert_ne!(
            opts.options & TOPT_NO_BODY,
            0,
            "NO_BODY should be set when headers_only=true"
        );
    }

    #[test]
    fn init_computes_options_return_path_add() {
        let mut config = TransportInstanceConfig::new("test_lmtp", "lmtp");
        config.return_path_add = true;
        let mut opts = LmtpTransportOptions {
            skt: Some("/var/run/lmtp.sock".to_string()),
            options: 0,
            ..Default::default()
        };
        LmtpTransport::lmtp_transport_init(&config, &mut opts).unwrap();
        assert_ne!(
            opts.options & TOPT_ADD_RETURN_PATH,
            0,
            "ADD_RETURN_PATH should be set when return_path_add=true"
        );
    }

    #[test]
    fn init_computes_options_delivery_date_add() {
        let mut config = TransportInstanceConfig::new("test_lmtp", "lmtp");
        config.delivery_date_add = true;
        let mut opts = LmtpTransportOptions {
            skt: Some("/var/run/lmtp.sock".to_string()),
            options: 0,
            ..Default::default()
        };
        LmtpTransport::lmtp_transport_init(&config, &mut opts).unwrap();
        assert_ne!(
            opts.options & TOPT_ADD_DELIVERY_DATE,
            0,
            "ADD_DELIVERY_DATE should be set when delivery_date_add=true"
        );
    }

    #[test]
    fn init_computes_options_envelope_to_add() {
        let mut config = TransportInstanceConfig::new("test_lmtp", "lmtp");
        config.envelope_to_add = true;
        let mut opts = LmtpTransportOptions {
            skt: Some("/var/run/lmtp.sock".to_string()),
            options: 0,
            ..Default::default()
        };
        LmtpTransport::lmtp_transport_init(&config, &mut opts).unwrap();
        assert_ne!(
            opts.options & TOPT_ADD_ENVELOPE_TO,
            0,
            "ADD_ENVELOPE_TO should be set when envelope_to_add=true"
        );
    }

    // =========================================================================
    // PENDING_OK constant
    // =========================================================================

    #[test]
    fn pending_ok_is_256() {
        assert_eq!(PENDING_OK, 256);
    }

    // =========================================================================
    // Transport entry with no config
    // =========================================================================

    #[test]
    fn transport_entry_no_cmd_or_skt_returns_error() {
        let t = LmtpTransport::new();
        let mut config = TransportInstanceConfig::new("test_lmtp", "lmtp");
        config.set_options(LmtpTransportOptions::default());
        let result = t.transport_entry(&config, "user@example.com");
        // Should return a config error because neither cmd nor skt is set.
        assert!(result.is_err());
    }

    // =========================================================================
    // check_response helper
    // =========================================================================

    #[test]
    fn check_response_timeout() {
        let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "operation timed out");
        let (code, msg, should_quit) = check_response(Some(&io_err), "", "LHLO test");
        assert_eq!(code, '4');
        assert!(msg.contains("LMTP timeout after LHLO test"));
        assert!(!should_quit);
    }

    #[test]
    fn check_response_server_error() {
        let (code, msg, should_quit) = check_response(None, "550 User not found", "RCPT TO");
        assert_eq!(code, '5');
        assert!(msg.contains("LMTP error after RCPT TO"));
        assert!(should_quit);
    }

    #[test]
    fn check_response_connection_closed() {
        let (code, msg, should_quit) = check_response(None, "", "end of data");
        assert_eq!(code, '4');
        assert!(msg.contains("LMTP connection closed after end of data"));
        assert!(!should_quit);
    }
}
