// exim-auths/src/helpers/base64_io.rs — Shared Base64 I/O Functions
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Rust rewrite of:
//   - src/src/auths/get_data.c  (262 lines, 5 functions)
//   - src/src/auths/get_no64_data.c (49 lines, 1 function)
//
// These are shared authentication I/O helper functions used by ALL auth drivers
// for SMTP AUTH challenge/response exchanges.
//
// All 6 functions are implemented:
//   1. auth_read_input()    — Decode and split AUTH command initial data
//   2. auth_get_data()      — Issue base64-encoded 334 challenge + read response
//   3. auth_get_no64_data() — Issue non-base64 334 challenge + read response
//   4. auth_prompt()        — Combined challenge + decode + split
//   5. auth_client_item()   — Client-side auth item send/receive
//   6. process_caret_escapes() (internal helper for auth_client_item ^-encoding)
//
// This module is NOT feature-gated — it is always compiled because it provides
// shared functionality needed by all auth drivers.
//
// Safety: This file contains ZERO unsafe code (per AAP §0.7.2).

use std::io;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use tracing::debug;

use exim_store::taint::{Clean, Tainted};

// ============================================================================
// Constants
// ============================================================================

/// Flag for [`auth_client_item`]: this is the first item in the exchange.
///
/// When set, the AUTH command prefix (`"AUTH {mechanism} "`) is prepended to
/// the base64-encoded payload.  Replaces the C `AUTH_ITEM_FIRST` constant.
pub const AUTH_ITEM_FIRST: u32 = 0x01;

/// Flag for [`auth_client_item`]: this is the last item in the exchange.
///
/// When set and a 3xx continuation is received, the exchange is cancelled
/// with an error ("Too few items in client_send").  Replaces the C
/// `AUTH_ITEM_LAST` constant.
pub const AUTH_ITEM_LAST: u32 = 0x02;

/// Flag for [`auth_client_item`]: ignore invalid base64 in 3xx continuation.
///
/// When set and the server's 3xx continuation data fails base64 decoding, an
/// empty string is used instead of cancelling.  Replaces the C
/// `AUTH_ITEM_IGN64` constant (maps to `client_ignore_invalid_base64` option).
pub const AUTH_ITEM_IGN64: u32 = 0x04;

/// Maximum number of auth variables (`$auth1`..`$auth3`).
/// Matches the C constant `AUTH_VARS` (typically 3).
const AUTH_VARS_MAX: usize = 3;

/// Maximum number of expansion variables (`$1`..`$N`).
/// Matches the C constant `EXPAND_MAXN` (typically 20).
const EXPAND_MAXN: usize = 20;

/// Default maximum response line size in bytes.
/// Matches the C `big_buffer_size` default of 16384.
pub const DEFAULT_MAX_RESPONSE_LEN: usize = 16384;

// ============================================================================
// AuthIoResult — Result enum for auth I/O operations
// ============================================================================

/// Result of an SMTP authentication I/O operation.
///
/// Replaces the C return codes `OK`, `BAD64`, `CANCELLED`, `FAIL_SEND`,
/// `FAIL`, `ERROR`, and `DEFER` used across the auth helper functions in
/// `get_data.c` and `get_no64_data.c`.
#[derive(Debug)]
pub enum AuthIoResult {
    /// Operation succeeded.
    Ok,

    /// Response was too large for the buffer, or base64 decoding failed.
    Bad64,

    /// Client sent `"*"` to cancel the authentication exchange, or a forced
    /// expansion failure occurred in [`auth_client_item`].
    Cancelled,

    /// Error writing to the SMTP connection (transport-level write failure).
    FailSend,

    /// SMTP response indicated failure (non-2xx/non-3xx code, or a
    /// transport-level I/O error such as a timeout).
    Fail,

    /// Local error with a descriptive message (e.g., expansion failure,
    /// "Too few items in client_send").
    Error(String),

    /// More items expected in a multi-step client authentication exchange.
    /// The 3xx continuation data has been decoded and stored.
    Defer,
}

// ============================================================================
// ExpandResult — Result of string expansion
// ============================================================================

/// Result of expanding an Exim configuration string.
///
/// Replaces the C `expand_string_copy()` return value combined with
/// `f.expand_string_forcedfail` and `expand_string_message` globals.
/// Used by [`auth_client_item`] to expand `client_send` strings that may
/// contain Exim variables like `$auth1`, `$domain`, etc.
#[derive(Debug)]
pub enum ExpandResult {
    /// Expansion succeeded, producing the given string.
    Ok(String),

    /// Expansion encountered a forced failure (e.g., `${if false:...}`).
    /// This is not a real error — the caller should cancel gracefully.
    ForcedFailure,

    /// Expansion failed with an error message.
    Error(String),
}

// ============================================================================
// AuthSmtpIo — SMTP I/O abstraction trait
// ============================================================================

/// Abstraction over SMTP network I/O for authentication exchanges.
///
/// Replaces the global C functions `smtp_printf()`, `receive_getc()`,
/// `smtp_write_command()`, and `smtp_read_response()` with a trait that can be
/// implemented by both real SMTP connections and test doubles.
///
/// **Server-side** methods ([`send_line`](AuthSmtpIo::send_line),
/// [`read_line`](AuthSmtpIo::read_line)) are used by [`auth_get_data`],
/// [`auth_get_no64_data`], and [`auth_prompt`].
///
/// **Client-side** methods ([`write_command_flush`](AuthSmtpIo::write_command_flush),
/// [`read_response`](AuthSmtpIo::read_response)) are used by
/// [`auth_client_item`].
pub trait AuthSmtpIo {
    /// Send a complete line to the SMTP peer, including trailing CRLF.
    ///
    /// The `line` parameter should NOT include `\r\n`; the implementation
    /// appends it automatically.  Used for server-side `"334 ..."` challenge
    /// lines.
    fn send_line(&mut self, line: &str) -> io::Result<()>;

    /// Read a response line from the SMTP peer.
    ///
    /// Reads characters until `\n` or EOF, strips trailing `\r\n`, and returns
    /// the content wrapped in [`Tainted`] because it originated from the
    /// network.
    ///
    /// If the line exceeds `max_len` bytes before a newline is encountered,
    /// returns `Err` with [`io::ErrorKind::InvalidData`].
    fn read_line(&mut self, max_len: usize) -> io::Result<Tainted<String>>;

    /// Send an SMTP command with buffer flush (client-side).
    ///
    /// Replaces `smtp_write_command(sx, SCMD_FLUSH, ...)`.  The `command`
    /// string includes trailing `\r\n`.
    fn write_command_flush(&mut self, command: &str) -> io::Result<()>;

    /// Read an SMTP response and check the status code (client-side).
    ///
    /// Replaces `smtp_read_response(sx, buffer, buffsize, expected_code, timeout)`.
    ///
    /// Returns `Ok((matched, response))` where `matched` is `true` when the
    /// response code starts with `expected_code`, and `response` is the full
    /// response line (tainted, from the network).
    ///
    /// Returns `Err` for transport-level I/O errors or timeouts (equivalent to
    /// `errno != 0` in the C code).
    fn read_response(
        &mut self,
        expected_code: char,
        timeout: u32,
    ) -> io::Result<(bool, Tainted<String>)>;
}

// ============================================================================
// StringExpander — String expansion callback
// ============================================================================

/// Callback for expanding Exim configuration strings.
///
/// Replaces the C `expand_string_copy()` function.  Used by
/// [`auth_client_item`] to expand `client_send` strings containing Exim
/// variables (`$auth1`, `$domain`, `$host`, etc.) before encoding and sending
/// them to the remote server.
pub trait StringExpander {
    /// Expand the given string, substituting all Exim variables.
    fn expand_string(&self, input: &str) -> ExpandResult;
}

// ============================================================================
// AuthVarsContext — Auth variable storage
// ============================================================================

/// Context for storing authentication variables during SMTP AUTH exchanges.
///
/// Replaces the C global variables `auth_vars[]`, `expand_nstring[]`,
/// `expand_nlength[]`, and `expand_nmax`.  All stored values from wire input
/// are wrapped in [`Tainted<String>`] for compile-time taint tracking,
/// replacing the C runtime `is_tainted()` pointer scanning.
///
/// Auth variables are accessible in Exim configuration as `$auth1`, `$auth2`,
/// `$auth3`; expansion variables as `$1` through `$20`.
pub struct AuthVarsContext {
    /// Auth variables (`$auth1`..`$auth3`), indexed 0-based.
    /// Maximum of [`AUTH_VARS_MAX`] entries (matching C `AUTH_VARS`).
    pub auth_vars: Vec<Option<Tainted<String>>>,

    /// Expansion strings (`$1`..`$N`), indexed 1-based (index 0 is a sentinel).
    /// Up to [`EXPAND_MAXN`] entries (matching C `EXPAND_MAXN`).
    pub expand_nstring: Vec<Tainted<String>>,

    /// Lengths of expansion strings, indexed matching [`expand_nstring`].
    pub expand_nlength: Vec<usize>,

    /// Current maximum expansion variable number (0-based counter).
    /// Incremented as segments are stored.  Replaces C global `expand_nmax`.
    pub expand_nmax: usize,
}

impl AuthVarsContext {
    /// Creates a new empty context with pre-allocated capacity.
    pub fn new() -> Self {
        let mut nstring = Vec::with_capacity(EXPAND_MAXN + 1);
        let mut nlength = Vec::with_capacity(EXPAND_MAXN + 1);
        // Index 0 is a sentinel (1-based indexing for expand variables)
        nstring.push(Tainted::new(String::new()));
        nlength.push(0);
        Self {
            auth_vars: vec![None; AUTH_VARS_MAX],
            expand_nstring: nstring,
            expand_nlength: nlength,
            expand_nmax: 0,
        }
    }

    /// Stores a decoded segment in both `auth_vars` and the expansion arrays.
    ///
    /// Replicates the C pattern from `get_data.c`:
    /// ```c
    /// if (expand_nmax < AUTH_VARS) auth_vars[expand_nmax] = clear;
    /// expand_nstring[++expand_nmax] = clear;
    /// expand_nlength[expand_nmax] = len;
    /// ```
    fn store_segment(&mut self, segment: Tainted<String>) {
        if self.expand_nmax >= EXPAND_MAXN {
            return;
        }
        let len = segment.as_ref().len();

        // Store in auth_vars if within the auth variable range
        if self.expand_nmax < AUTH_VARS_MAX {
            self.auth_vars[self.expand_nmax] = Some(segment.clone());
        }

        // Increment expand_nmax (C: ++expand_nmax) then store at the new index
        self.expand_nmax += 1;

        // Grow the vectors to accommodate the new index
        while self.expand_nstring.len() <= self.expand_nmax {
            self.expand_nstring.push(Tainted::new(String::new()));
        }
        while self.expand_nlength.len() <= self.expand_nmax {
            self.expand_nlength.push(0);
        }

        self.expand_nstring[self.expand_nmax] = segment;
        self.expand_nlength[self.expand_nmax] = len;
    }
}

impl Default for AuthVarsContext {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// AuthInstanceInfo — Auth driver instance metadata
// ============================================================================

/// Metadata about an authentication driver instance.
///
/// Provides the public mechanism name and driver instance name needed by
/// [`auth_client_item`] for AUTH command construction and error messages.
///
/// Replaces access to `ablock->public_name` and `ablock->drinst.name` in the
/// C code.
pub struct AuthInstanceInfo<'a> {
    /// The SASL mechanism name advertised in EHLO (e.g., `"PLAIN"`,
    /// `"CRAM-MD5"`).
    pub public_name: &'a str,

    /// The driver instance name from the Exim configuration.
    pub driver_name: &'a str,
}

// ============================================================================
// auth_read_input — Decode and split AUTH command initial data
// ============================================================================

/// Decode and split the initial data supplied on an AUTH command.
///
/// Rust rewrite of C `auth_read_input()` from `get_data.c` lines 23–50.
///
/// If the data is the literal string `"="`, it represents a single empty
/// string — `""` is stored in `auth_vars[0]` (per RFC 4954 §4: "If the client
/// is to send data first … and the data is empty, the client sends a single
/// equals sign").
///
/// Otherwise, the data is base64-decoded and split at NUL (0x00) byte
/// boundaries.  Each segment is stored in both the auth variables (`$auth1`
/// through `$auth3`) and the expansion variables (`$1` through `$N`).
///
/// # Arguments
///
/// * `data` — The base64-encoded initial data from the AUTH command, wrapped
///   in [`Tainted`] because it originated from the SMTP wire.
/// * `ctx` — Mutable reference to the auth variables context for storing
///   decoded segments.
///
/// # Returns
///
/// * [`AuthIoResult::Ok`] on success
/// * [`AuthIoResult::Bad64`] if base64 decoding fails
pub fn auth_read_input(data: Tainted<&str>, ctx: &mut AuthVarsContext) -> AuthIoResult {
    let raw: &str = data.as_ref();

    // Special case: "=" means a single empty string (RFC 4954 §4)
    if raw == "=" {
        ctx.store_segment(Tainted::new(String::new()));
        return AuthIoResult::Ok;
    }

    // Base64-decode the data
    let decoded = match STANDARD.decode(raw.as_bytes()) {
        Result::Ok(bytes) => bytes,
        Err(_) => return AuthIoResult::Bad64,
    };

    debug!("auth input decode:");

    // Split at NUL (0x00) boundaries and store each segment.
    // The C code iterates `clear < end && expand_nmax < EXPAND_MAXN` after
    // each segment, advancing `clear` past the NUL separator.
    let len = decoded.len();
    let mut start = 0;

    loop {
        if ctx.expand_nmax >= EXPAND_MAXN {
            break;
        }

        // Find end of current segment (next NUL or end-of-data)
        let mut end_pos = start;
        while end_pos < len && decoded[end_pos] != 0 {
            end_pos += 1;
        }

        // Extract segment — use lossy UTF-8 for robustness against
        // non-UTF-8 binary data that might appear in AUTH payloads
        let segment = String::from_utf8_lossy(&decoded[start..end_pos]).into_owned();
        debug!(" '{}'", segment);
        ctx.store_segment(Tainted::new(segment));

        // Advance past the NUL separator
        start = end_pos + 1;
        if start > len {
            break;
        }
    }

    debug!("");
    AuthIoResult::Ok
}

// ============================================================================
// auth_get_data — Issue base64-encoded 334 challenge and read response
// ============================================================================

/// Issue a base64-encoded 334 challenge and read the client's response.
///
/// Rust rewrite of C `auth_get_data()` from `get_data.c` lines 76–93.
///
/// Sends `"334 {base64(challenge)}\r\n"` to the SMTP client, then reads the
/// response line.  The response is NOT base64-decoded by this function — the
/// raw response text is returned for the caller to process.
///
/// # Arguments
///
/// * `io` — SMTP I/O handle for sending the challenge and reading the response.
/// * `challenge` — The challenge data (unencoded, may be binary), wrapped in
///   [`Clean`] because it originates from server configuration/code.
/// * `max_response_len` — Maximum allowed response line length in bytes.
///
/// # Returns
///
/// A tuple of `(AuthIoResult, Option<Tainted<String>>)`:
/// * `(Ok, Some(response))` — Client responded; response is the raw line.
/// * `(Bad64, None)` — Response line exceeded `max_response_len`.
/// * `(Cancelled, None)` — Client sent `"*"` to cancel authentication.
/// * `(FailSend, None)` — Error writing the challenge to the connection.
pub fn auth_get_data(
    io: &mut dyn AuthSmtpIo,
    challenge: Clean<&[u8]>,
    max_response_len: usize,
) -> (AuthIoResult, Option<Tainted<String>>) {
    // Base64-encode the challenge and send "334 {encoded}\r\n"
    let encoded = STANDARD.encode(challenge.into_inner());
    let line = format!("334 {encoded}");

    if io.send_line(&line).is_err() {
        return (AuthIoResult::FailSend, None);
    }

    // Read the client's response line
    let response = match io.read_line(max_response_len) {
        Result::Ok(resp) => resp,
        Err(e) if e.kind() == io::ErrorKind::InvalidData => {
            // Line exceeded max_response_len — maps to C BAD64
            return (AuthIoResult::Bad64, None);
        }
        Err(_) => {
            // Other I/O errors also map to BAD64 (matching C behavior where
            // EOF / short read returns whatever was buffered)
            return (AuthIoResult::Bad64, None);
        }
    };

    debug!("SMTP<< {}", response.as_ref());

    // Check for "*" cancellation (RFC 4954 §4)
    if response.as_ref() == "*" {
        return (AuthIoResult::Cancelled, None);
    }

    (AuthIoResult::Ok, Some(response))
}

// ============================================================================
// auth_get_no64_data — Issue non-base64 334 challenge and read response
// ============================================================================

/// Issue a non-base64-encoded 334 challenge and read the client's response.
///
/// Rust rewrite of C `auth_get_no64_data()` from `get_no64_data.c` lines 31–47.
///
/// Unlike [`auth_get_data`], the challenge text is sent as-is (NOT base64-
/// encoded) on the 334 line.  Used by the SPA, Dovecot, and GSASL
/// authenticators where the challenge is already in the format expected by the
/// client.
///
/// # Arguments
///
/// * `io` — SMTP I/O handle for sending the challenge and reading the response.
/// * `challenge` — The challenge text (sent verbatim), wrapped in [`Clean`]
///   because it originates from server configuration/code.
/// * `max_response_len` — Maximum allowed response line length in bytes.
///
/// # Returns
///
/// A tuple of `(AuthIoResult, Option<Tainted<String>>)`:
/// * `(Ok, Some(response))` — Client responded with data.
/// * `(Bad64, None)` — Response line exceeded `max_response_len`.
/// * `(Cancelled, None)` — Client sent `"*"` to cancel authentication.
/// * `(FailSend, None)` — Error writing the challenge to the connection.
pub fn auth_get_no64_data(
    io: &mut dyn AuthSmtpIo,
    challenge: Clean<&str>,
    max_response_len: usize,
) -> (AuthIoResult, Option<Tainted<String>>) {
    // Send "334 {challenge}\r\n" — NOT base64-encoded
    let line = format!("334 {}", challenge.into_inner());

    if io.send_line(&line).is_err() {
        return (AuthIoResult::FailSend, None);
    }

    // Read the client's response line
    let response = match io.read_line(max_response_len) {
        Result::Ok(resp) => resp,
        Err(e) if e.kind() == io::ErrorKind::InvalidData => {
            return (AuthIoResult::Bad64, None);
        }
        Err(_) => {
            return (AuthIoResult::Bad64, None);
        }
    };

    // Check for "*" cancellation
    if response.as_ref() == "*" {
        return (AuthIoResult::Cancelled, None);
    }

    (AuthIoResult::Ok, Some(response))
}

// ============================================================================
// auth_prompt — Combined challenge + decode + split
// ============================================================================

/// Issue a challenge, read and decode the response, then split at NUL
/// boundaries.
///
/// Rust rewrite of C `auth_prompt()` from `get_data.c` lines 97–120.
///
/// This function combines [`auth_get_data`] (send challenge, read response)
/// with base64 decoding and NUL-splitting of the decoded data.  The decoded
/// segments are stored in the auth variables context.
///
/// The decode+split loop is guaranteed to execute **at least once**, even when
/// the decoded data is zero-length (producing a single empty segment).  This
/// matches the C `do { … } while (…)` loop behavior.
///
/// # Arguments
///
/// * `io` — SMTP I/O handle.
/// * `challenge` — The challenge text to base64-encode and send, wrapped in
///   [`Clean`] because it originates from configuration/code.
/// * `ctx` — Mutable reference to auth variables context for storing segments.
/// * `max_response_len` — Maximum response line length.
///
/// # Returns
///
/// * [`AuthIoResult::Ok`] on success (segments stored in `ctx`)
/// * [`AuthIoResult::Bad64`] if the response is not valid base64
/// * [`AuthIoResult::Cancelled`] if the client cancelled
pub fn auth_prompt(
    io: &mut dyn AuthSmtpIo,
    challenge: Clean<&str>,
    ctx: &mut AuthVarsContext,
    max_response_len: usize,
) -> AuthIoResult {
    // Send challenge and get response — borrow challenge via as_ref() to convert
    // Clean<&str> into Clean<&[u8]> without consuming the wrapper.
    let challenge_str: &str = challenge.as_ref();
    let challenge_bytes = Clean::new(challenge_str.as_bytes());
    let (result, response_opt) = auth_get_data(io, challenge_bytes, max_response_len);

    // Propagate non-Ok results directly
    match result {
        AuthIoResult::Ok => {}
        other => return other,
    }

    let response = match response_opt {
        Some(r) => r,
        None => return AuthIoResult::Bad64,
    };

    // Base64-decode the response
    let decoded = match STANDARD.decode(response.as_ref().as_bytes()) {
        Result::Ok(bytes) => bytes,
        Err(_) => return AuthIoResult::Bad64,
    };

    let len = decoded.len();

    // Split at NUL boundaries using do-while semantics:
    // The loop MUST run at least once, even for zero-length decoded data.
    // This matches the C code's `do { … } while (clear < end && …);`
    let mut start = 0;
    let mut first_iteration = true;

    loop {
        if ctx.expand_nmax >= EXPAND_MAXN {
            break;
        }

        // Find end of current segment
        let mut end_pos = start;
        while end_pos < len && decoded[end_pos] != 0 {
            end_pos += 1;
        }

        let segment = String::from_utf8_lossy(&decoded[start..end_pos]).into_owned();
        ctx.store_segment(Tainted::new(segment));

        // Move past NUL separator
        start = end_pos + 1;
        first_iteration = false;

        // Break after body if we've consumed everything (do-while condition)
        if start > len {
            break;
        }
    }

    // If the loop didn't execute (shouldn't happen, but defensive), store an
    // empty segment to honor the do-while guarantee
    if first_iteration {
        ctx.store_segment(Tainted::new(String::new()));
    }

    AuthIoResult::Ok
}

// ============================================================================
// process_caret_escapes — Internal helper for ^ escape processing
// ============================================================================

/// Process `^` escape sequences in an authentication payload string.
///
/// Replicates the C caret-escape processing from `get_data.c` lines 183–188.
/// The `^` character is used as an escape for binary NUL (0x00) bytes, which
/// are needed for the PLAIN SASL mechanism (RFC 4616:
/// `authzid\0authcid\0passwd`).
///
/// Escape rules:
/// - `^` followed by any character except `^` → NUL byte (0x00)
/// - `^^` → single `^`
/// - `^` at end of string → NUL byte
///
/// The parsing ambiguity of `^^^` is resolved as: `^^ → ^; ^ → NUL` — there
/// is no way to produce a leading `^` after a NUL.  This matches the C
/// behavior identically.
fn process_caret_escapes(input: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(input.len());
    let mut i = 0;

    while i < input.len() {
        if input[i] == b'^' {
            if i + 1 < input.len() && input[i + 1] == b'^' {
                // ^^ → single ^
                result.push(b'^');
                i += 2;
            } else {
                // ^ followed by non-^ or at end of string → NUL byte
                result.push(0u8);
                i += 1;
            }
        } else {
            result.push(input[i]);
            i += 1;
        }
    }

    result
}

// ============================================================================
// auth_client_item — Client-side auth item send/receive
// ============================================================================

/// Expand, encode, and send one client authentication item; read the response.
///
/// Rust rewrite of C `auth_client_item()` from `get_data.c` lines 143–259.
///
/// This function handles one step of a multi-step client-side SMTP AUTH
/// exchange.  It expands the input string (substituting Exim variables),
/// processes `^` escape sequences (for PLAIN mechanism NUL-separated fields),
/// base64-encodes the result, sends it to the server, and processes the
/// response.
///
/// # Arguments
///
/// * `io` — SMTP transport I/O handle.
/// * `expander` — String expansion engine for resolving Exim variables.
/// * `auth_info` — Auth driver instance metadata (mechanism name, driver name).
/// * `input` — The configuration string to expand and send.
/// * `flags` — Bitfield of [`AUTH_ITEM_FIRST`], [`AUTH_ITEM_LAST`],
///   [`AUTH_ITEM_IGN64`].
/// * `timeout` — Response read timeout in seconds.
/// * `buffer` — Mutable string buffer for error/response messages (replaces
///   the C `buffer` parameter for SMTP response and error text).
///
/// # Returns
///
/// A tuple of `(AuthIoResult, Option<Tainted<String>>)`:
/// * `(Ok, None)` — Server responded with 2xx success.
/// * `(Defer, Some(data))` — Server responded with 3xx; decoded continuation.
/// * `(Cancelled, None)` — Expansion forced failure or base64 decode failure.
/// * `(FailSend, None)` — Failed to write to the SMTP connection.
/// * `(Fail, None)` — Server responded with an error code or I/O error.
/// * `(Error(msg), None)` — Local error (expansion failure, too few items).
pub fn auth_client_item(
    io: &mut dyn AuthSmtpIo,
    expander: &dyn StringExpander,
    auth_info: &AuthInstanceInfo<'_>,
    input: &str,
    flags: u32,
    timeout: u32,
    buffer: &mut String,
) -> (AuthIoResult, Option<Tainted<String>>) {
    // ── Step 1: Expand the input string ─────────────────────────────────────
    //
    // On expansion failure, we must send "*\r\n" to cancel the exchange
    // (unless this is the first item, where no AUTH command was sent yet).
    // After cancellation, check whether it was a forced failure (graceful
    // cancel) or a real error.

    let expanded = match expander.expand_string(input) {
        ExpandResult::Ok(s) => s,
        ExpandResult::ForcedFailure => {
            if (flags & AUTH_ITEM_FIRST) == 0 {
                let _ = io.write_command_flush("*\r\n");
                let _ = io.read_response('2', timeout);
            }
            buffer.clear();
            return (AuthIoResult::Cancelled, None);
        }
        ExpandResult::Error(msg) => {
            if (flags & AUTH_ITEM_FIRST) == 0 {
                let _ = io.write_command_flush("*\r\n");
                let _ = io.read_response('2', timeout);
            }
            let error_msg = format!(
                "expansion of \"{}\" failed in {} authenticator: {}",
                input, auth_info.driver_name, msg
            );
            *buffer = error_msg.clone();
            return (AuthIoResult::Error(error_msg), None);
        }
    };

    // ── Step 2: Process ^ escape sequences ──────────────────────────────────
    //
    // The ^ character encodes binary NUL bytes for the PLAIN mechanism.
    // ^x → NUL (where x ≠ ^), ^^ → literal ^, ^^^ → ^ then NUL.

    let payload = process_caret_escapes(expanded.as_bytes());

    debug!(
        "auth_client_item: expanded='{}', payload_len={}",
        expanded,
        payload.len()
    );

    // ── Step 3: Base64-encode and send ──────────────────────────────────────
    //
    // The first item is prefixed with "AUTH {mechanism}" and a space before
    // the base64 data (unless the payload is empty, in which case no space
    // and no data are appended, per RFC 4954 §4).

    let encoded = STANDARD.encode(&payload);

    let command = if (flags & AUTH_ITEM_FIRST) != 0 {
        if payload.is_empty() {
            format!("AUTH {}\r\n", auth_info.public_name)
        } else {
            format!("AUTH {} {}\r\n", auth_info.public_name, encoded)
        }
    } else {
        format!("{}\r\n", encoded)
    };

    if io.write_command_flush(&command).is_err() {
        return (AuthIoResult::FailSend, None);
    }

    // ── Step 4: Read the server's response ──────────────────────────────────

    let (matched_2xx, response) = match io.read_response('2', timeout) {
        Result::Ok((matched, resp)) => (matched, resp),
        Err(_) => {
            // I/O error (equivalent to errno != 0 in C)
            return (AuthIoResult::Fail, None);
        }
    };

    // 2xx: authentication succeeded — no more data expected
    if matched_2xx {
        return (AuthIoResult::Ok, None);
    }

    // Not 2xx: check whether it's a 3xx continuation
    let resp_str: &str = response.as_ref();

    if !resp_str.starts_with('3') {
        // Not 2xx and not 3xx — this is a definitive failure
        *buffer = resp_str.to_string();
        return (AuthIoResult::Fail, None);
    }

    // ── Step 5: Handle 3xx continuation ─────────────────────────────────────

    // If this was the last item, there's no more data to send.  Cancel the
    // exchange and return ERROR ("Too few items in client_send").
    if (flags & AUTH_ITEM_LAST) != 0 {
        let _ = io.write_command_flush("*\r\n");
        let _ = io.read_response('2', timeout);
        let error_msg = format!(
            "Too few items in client_send in {} authenticator",
            auth_info.driver_name
        );
        *buffer = error_msg.clone();
        return (AuthIoResult::Error(error_msg), None);
    }

    // ── Step 6: Decode the 3xx continuation data ────────────────────────────
    //
    // The continuation data starts after the SMTP status code + space:
    //   "334 base64data" → skip "334 " (4 bytes)
    //
    // If decoding fails and AUTH_ITEM_IGN64 is set, use an empty string
    // instead of cancelling (per client_ignore_invalid_base64 option).

    let continuation_b64 = if resp_str.len() > 4 {
        &resp_str[4..]
    } else {
        ""
    };

    let decoded_continuation = match STANDARD.decode(continuation_b64.as_bytes()) {
        Result::Ok(bytes) => Tainted::new(String::from_utf8_lossy(&bytes).into_owned()),
        Err(_) => {
            if (flags & AUTH_ITEM_IGN64) != 0 {
                // Ignore invalid base64 — use empty string
                debug!(
                    "bad b64 decode for '{}'; ignoring due to client_ignore_invalid_base64",
                    resp_str
                );
                Tainted::new(String::new())
            } else {
                // Invalid base64 — cancel the exchange
                let save_bad = resp_str.to_string();
                let _ = io.write_command_flush("*\r\n");
                let _ = io.read_response('2', timeout);
                *buffer = format!("Invalid base64 string in server response \"{}\"", save_bad);
                return (AuthIoResult::Cancelled, None);
            }
        }
    };

    (AuthIoResult::Defer, Some(decoded_continuation))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    // ── Mock SMTP I/O ───────────────────────────────────────────────────────

    /// Mock implementation of [`AuthSmtpIo`] for unit testing.
    struct MockSmtpIo {
        /// Lines sent via `send_line` or `write_command_flush`.
        sent_lines: Vec<String>,
        /// Pre-loaded response lines for `read_line` calls.
        response_lines: VecDeque<String>,
        /// Pre-loaded results for `read_response` calls.
        response_results: VecDeque<io::Result<(bool, Tainted<String>)>>,
    }

    impl MockSmtpIo {
        fn new() -> Self {
            Self {
                sent_lines: Vec::new(),
                response_lines: VecDeque::new(),
                response_results: VecDeque::new(),
            }
        }

        fn with_response(mut self, line: &str) -> Self {
            self.response_lines.push_back(line.to_string());
            self
        }

        fn with_smtp_response(mut self, matched: bool, response: &str) -> Self {
            self.response_results
                .push_back(Result::Ok((matched, Tainted::new(response.to_string()))));
            self
        }
    }

    impl AuthSmtpIo for MockSmtpIo {
        fn send_line(&mut self, line: &str) -> io::Result<()> {
            self.sent_lines.push(format!("{line}\r\n"));
            Result::Ok(())
        }

        fn read_line(&mut self, max_len: usize) -> io::Result<Tainted<String>> {
            match self.response_lines.pop_front() {
                Some(line) => {
                    if line.len() > max_len {
                        Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"))
                    } else {
                        Result::Ok(Tainted::new(line))
                    }
                }
                None => Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "no more responses",
                )),
            }
        }

        fn write_command_flush(&mut self, command: &str) -> io::Result<()> {
            self.sent_lines.push(command.to_string());
            Result::Ok(())
        }

        fn read_response(
            &mut self,
            _expected_code: char,
            _timeout: u32,
        ) -> io::Result<(bool, Tainted<String>)> {
            match self.response_results.pop_front() {
                Some(result) => result,
                None => Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "no more responses",
                )),
            }
        }
    }

    // ── Mock string expander ────────────────────────────────────────────────

    struct MockExpander {
        result: ExpandResult,
    }

    impl MockExpander {
        fn ok(value: &str) -> Self {
            Self {
                result: ExpandResult::Ok(value.to_string()),
            }
        }

        fn forced_failure() -> Self {
            Self {
                result: ExpandResult::ForcedFailure,
            }
        }

        fn error(msg: &str) -> Self {
            Self {
                result: ExpandResult::Error(msg.to_string()),
            }
        }
    }

    impl StringExpander for MockExpander {
        fn expand_string(&self, _input: &str) -> ExpandResult {
            match &self.result {
                ExpandResult::Ok(s) => ExpandResult::Ok(s.clone()),
                ExpandResult::ForcedFailure => ExpandResult::ForcedFailure,
                ExpandResult::Error(s) => ExpandResult::Error(s.clone()),
            }
        }
    }

    // ── auth_read_input tests ───────────────────────────────────────────────

    #[test]
    fn test_read_input_equals_sign_means_empty_string() {
        let mut ctx = AuthVarsContext::new();
        let result = auth_read_input(Tainted::new("="), &mut ctx);
        assert!(matches!(result, AuthIoResult::Ok));
        assert_eq!(ctx.expand_nmax, 1);
        assert_eq!(
            ctx.auth_vars[0].as_ref().map(|t| t.as_ref().as_str()),
            Some("")
        );
    }

    #[test]
    fn test_read_input_simple_base64() {
        let mut ctx = AuthVarsContext::new();
        // "hello" → base64 "aGVsbG8="
        let result = auth_read_input(Tainted::new("aGVsbG8="), &mut ctx);
        assert!(matches!(result, AuthIoResult::Ok));
        assert_eq!(ctx.expand_nmax, 1);
        assert_eq!(
            ctx.auth_vars[0].as_ref().map(|t| t.as_ref().as_str()),
            Some("hello")
        );
    }

    #[test]
    fn test_read_input_nul_separated_two_fields() {
        let mut ctx = AuthVarsContext::new();
        // "user\0pass" → two segments
        let encoded = STANDARD.encode(b"user\0pass");
        let result = auth_read_input(Tainted::new(encoded.as_str()), &mut ctx);
        assert!(matches!(result, AuthIoResult::Ok));
        assert_eq!(ctx.expand_nmax, 2);
        assert_eq!(
            ctx.auth_vars[0].as_ref().map(|t| t.as_ref().as_str()),
            Some("user")
        );
        assert_eq!(
            ctx.auth_vars[1].as_ref().map(|t| t.as_ref().as_str()),
            Some("pass")
        );
    }

    #[test]
    fn test_read_input_plain_three_fields() {
        let mut ctx = AuthVarsContext::new();
        // PLAIN: "\0user\0password" → three segments
        let encoded = STANDARD.encode(b"\0user\0password");
        let result = auth_read_input(Tainted::new(encoded.as_str()), &mut ctx);
        assert!(matches!(result, AuthIoResult::Ok));
        assert_eq!(ctx.expand_nmax, 3);
        assert_eq!(
            ctx.auth_vars[0].as_ref().map(|t| t.as_ref().as_str()),
            Some("")
        );
        assert_eq!(
            ctx.auth_vars[1].as_ref().map(|t| t.as_ref().as_str()),
            Some("user")
        );
        assert_eq!(
            ctx.auth_vars[2].as_ref().map(|t| t.as_ref().as_str()),
            Some("password")
        );
    }

    #[test]
    fn test_read_input_bad_base64() {
        let mut ctx = AuthVarsContext::new();
        let result = auth_read_input(Tainted::new("!!!invalid!!!"), &mut ctx);
        assert!(matches!(result, AuthIoResult::Bad64));
    }

    // ── auth_get_data tests ─────────────────────────────────────────────────

    #[test]
    fn test_get_data_ok_response() {
        let mut io = MockSmtpIo::new().with_response("dGVzdA==");
        let challenge = Clean::new(b"challenge" as &[u8]);
        let (result, response) = auth_get_data(&mut io, challenge, DEFAULT_MAX_RESPONSE_LEN);
        assert!(matches!(result, AuthIoResult::Ok));
        assert_eq!(response.unwrap().as_ref(), "dGVzdA==");
        // Verify "334 " prefix was sent
        assert!(io.sent_lines[0].starts_with("334 "));
        assert!(io.sent_lines[0].ends_with("\r\n"));
    }

    #[test]
    fn test_get_data_cancelled_by_star() {
        let mut io = MockSmtpIo::new().with_response("*");
        let challenge = Clean::new(b"challenge" as &[u8]);
        let (result, response) = auth_get_data(&mut io, challenge, DEFAULT_MAX_RESPONSE_LEN);
        assert!(matches!(result, AuthIoResult::Cancelled));
        assert!(response.is_none());
    }

    #[test]
    fn test_get_data_line_too_long() {
        let mut io = MockSmtpIo::new().with_response("a]very long response");
        let challenge = Clean::new(b"c" as &[u8]);
        // Set max_len to 5 so the mock triggers InvalidData
        let (result, _) = auth_get_data(&mut io, challenge, 5);
        assert!(matches!(result, AuthIoResult::Bad64));
    }

    // ── auth_get_no64_data tests ────────────────────────────────────────────

    #[test]
    fn test_get_no64_data_ok() {
        let mut io = MockSmtpIo::new().with_response("response_data");
        let challenge = Clean::new("NTLMSSP");
        let (result, response) = auth_get_no64_data(&mut io, challenge, DEFAULT_MAX_RESPONSE_LEN);
        assert!(matches!(result, AuthIoResult::Ok));
        assert_eq!(response.unwrap().as_ref(), "response_data");
        // Verify challenge was sent verbatim (NOT base64-encoded)
        assert_eq!(io.sent_lines[0], "334 NTLMSSP\r\n");
    }

    #[test]
    fn test_get_no64_data_cancelled() {
        let mut io = MockSmtpIo::new().with_response("*");
        let challenge = Clean::new("challenge_text");
        let (result, _) = auth_get_no64_data(&mut io, challenge, DEFAULT_MAX_RESPONSE_LEN);
        assert!(matches!(result, AuthIoResult::Cancelled));
    }

    // ── auth_prompt tests ───────────────────────────────────────────────────

    #[test]
    fn test_prompt_ok_single_segment() {
        // Response is base64("hello") = "aGVsbG8="
        let mut io = MockSmtpIo::new().with_response("aGVsbG8=");
        let mut ctx = AuthVarsContext::new();
        let result = auth_prompt(
            &mut io,
            Clean::new("challenge_text"),
            &mut ctx,
            DEFAULT_MAX_RESPONSE_LEN,
        );
        assert!(matches!(result, AuthIoResult::Ok));
        assert_eq!(ctx.expand_nmax, 1);
        assert_eq!(
            ctx.auth_vars[0].as_ref().map(|t| t.as_ref().as_str()),
            Some("hello")
        );
    }

    #[test]
    fn test_prompt_ok_empty_response() {
        // Base64 of empty string is ""
        let mut io = MockSmtpIo::new().with_response("");
        let mut ctx = AuthVarsContext::new();
        let result = auth_prompt(
            &mut io,
            Clean::new("challenge"),
            &mut ctx,
            DEFAULT_MAX_RESPONSE_LEN,
        );
        // Empty string is not valid base64 input — but STANDARD.decode("")
        // returns Ok(vec![]), so the loop runs once with empty segment.
        assert!(matches!(result, AuthIoResult::Ok));
        assert!(ctx.expand_nmax >= 1);
    }

    #[test]
    fn test_prompt_bad_base64() {
        let mut io = MockSmtpIo::new().with_response("not!valid!base64!!!");
        let mut ctx = AuthVarsContext::new();
        let result = auth_prompt(
            &mut io,
            Clean::new("challenge"),
            &mut ctx,
            DEFAULT_MAX_RESPONSE_LEN,
        );
        assert!(matches!(result, AuthIoResult::Bad64));
    }

    // ── process_caret_escapes tests ─────────────────────────────────────────

    #[test]
    fn test_caret_no_escapes() {
        assert_eq!(process_caret_escapes(b"hello"), b"hello");
    }

    #[test]
    fn test_caret_single_caret_becomes_nul() {
        // "^x" → [NUL, 'x']
        assert_eq!(process_caret_escapes(b"^x"), vec![0u8, b'x']);
    }

    #[test]
    fn test_caret_double_caret_becomes_single() {
        // "^^" → "^"
        assert_eq!(process_caret_escapes(b"^^"), vec![b'^']);
    }

    #[test]
    fn test_caret_triple_ambiguity() {
        // "^^^" → ^^ then ^ → "^" then NUL → ['^', 0x00]
        assert_eq!(process_caret_escapes(b"^^^"), vec![b'^', 0u8]);
    }

    #[test]
    fn test_caret_at_end() {
        // "abc^" → "abc" + NUL
        assert_eq!(process_caret_escapes(b"abc^"), vec![b'a', b'b', b'c', 0u8]);
    }

    #[test]
    fn test_caret_plain_mechanism() {
        // "^user^pass" → NUL + "user" + NUL + "pass"
        let result = process_caret_escapes(b"^user^pass");
        assert_eq!(
            result,
            vec![0u8, b'u', b's', b'e', b'r', 0u8, b'p', b'a', b's', b's']
        );
    }

    #[test]
    fn test_caret_mixed() {
        // "a^^b^c" → "a" + "^" + "b" + NUL + "c"
        assert_eq!(
            process_caret_escapes(b"a^^b^c"),
            vec![b'a', b'^', b'b', 0u8, b'c']
        );
    }

    // ── auth_client_item tests ──────────────────────────────────────────────

    #[test]
    fn test_client_item_first_success() {
        let mut io = MockSmtpIo::new().with_smtp_response(true, "235 ok");
        let expander = MockExpander::ok("testuser");
        let info = AuthInstanceInfo {
            public_name: "PLAIN",
            driver_name: "plaintext_login",
        };
        let mut buffer = String::new();

        let (result, data) = auth_client_item(
            &mut io,
            &expander,
            &info,
            "$auth1",
            AUTH_ITEM_FIRST,
            30,
            &mut buffer,
        );
        assert!(matches!(result, AuthIoResult::Ok));
        assert!(data.is_none());
        // Verify AUTH command was sent
        assert!(io.sent_lines[0].starts_with("AUTH PLAIN "));
    }

    #[test]
    fn test_client_item_continuation() {
        // Server responds with 334 + base64 data
        let challenge_b64 = STANDARD.encode(b"server_challenge");
        let response = format!("334 {}", challenge_b64);
        let mut io = MockSmtpIo::new().with_smtp_response(false, &response);
        let expander = MockExpander::ok("client_data");
        let info = AuthInstanceInfo {
            public_name: "CRAM-MD5",
            driver_name: "cram_md5_driver",
        };
        let mut buffer = String::new();

        let (result, data) = auth_client_item(
            &mut io,
            &expander,
            &info,
            "$auth1",
            AUTH_ITEM_FIRST,
            30,
            &mut buffer,
        );
        assert!(matches!(result, AuthIoResult::Defer));
        assert_eq!(data.unwrap().as_ref(), "server_challenge");
    }

    #[test]
    fn test_client_item_forced_failure_first() {
        let mut io = MockSmtpIo::new();
        let expander = MockExpander::forced_failure();
        let info = AuthInstanceInfo {
            public_name: "PLAIN",
            driver_name: "test_driver",
        };
        let mut buffer = String::new();

        let (result, _) = auth_client_item(
            &mut io,
            &expander,
            &info,
            "$auth1",
            AUTH_ITEM_FIRST,
            30,
            &mut buffer,
        );
        assert!(matches!(result, AuthIoResult::Cancelled));
        // No "*\r\n" cancellation should be sent for first item
        assert!(io.sent_lines.is_empty());
    }

    #[test]
    fn test_client_item_forced_failure_not_first() {
        // Need a response for the cancel read_response
        let mut io = MockSmtpIo::new().with_smtp_response(true, "501 cancelled");
        let expander = MockExpander::forced_failure();
        let info = AuthInstanceInfo {
            public_name: "PLAIN",
            driver_name: "test_driver",
        };
        let mut buffer = String::new();

        let (result, _) = auth_client_item(&mut io, &expander, &info, "$auth1", 0, 30, &mut buffer);
        assert!(matches!(result, AuthIoResult::Cancelled));
        // "*\r\n" cancellation should be sent for non-first item
        assert_eq!(io.sent_lines[0], "*\r\n");
    }

    #[test]
    fn test_client_item_expansion_error() {
        let mut io = MockSmtpIo::new().with_smtp_response(true, "501 cancelled");
        let expander = MockExpander::error("unknown variable");
        let info = AuthInstanceInfo {
            public_name: "PLAIN",
            driver_name: "my_auth",
        };
        let mut buffer = String::new();

        let (result, _) =
            auth_client_item(&mut io, &expander, &info, "$unknown", 0, 30, &mut buffer);
        match result {
            AuthIoResult::Error(msg) => {
                assert!(msg.contains("expansion of"));
                assert!(msg.contains("my_auth"));
                assert!(msg.contains("unknown variable"));
            }
            other => panic!("expected Error, got {:?}", other),
        }
    }

    #[test]
    fn test_client_item_last_with_continuation() {
        // Server sends 3xx when we have no more data (AUTH_ITEM_LAST)
        let challenge_b64 = STANDARD.encode(b"more_data");
        let response = format!("334 {}", challenge_b64);
        let mut io = MockSmtpIo::new()
            .with_smtp_response(false, &response)
            .with_smtp_response(true, "501 cancelled");
        let expander = MockExpander::ok("data");
        let info = AuthInstanceInfo {
            public_name: "PLAIN",
            driver_name: "test_auth",
        };
        let mut buffer = String::new();

        let (result, _) = auth_client_item(
            &mut io,
            &expander,
            &info,
            "data",
            AUTH_ITEM_FIRST | AUTH_ITEM_LAST,
            30,
            &mut buffer,
        );
        match result {
            AuthIoResult::Error(msg) => {
                assert!(msg.contains("Too few items"));
                assert!(msg.contains("test_auth"));
            }
            other => panic!("expected Error, got {:?}", other),
        }
    }

    #[test]
    fn test_client_item_bad_b64_ign64() {
        // Server sends 3xx with invalid base64, but IGN64 is set
        let mut io = MockSmtpIo::new().with_smtp_response(false, "334 !!!invalid!!!");
        let expander = MockExpander::ok("data");
        let info = AuthInstanceInfo {
            public_name: "PLAIN",
            driver_name: "test_auth",
        };
        let mut buffer = String::new();

        let (result, data) = auth_client_item(
            &mut io,
            &expander,
            &info,
            "data",
            AUTH_ITEM_FIRST | AUTH_ITEM_IGN64,
            30,
            &mut buffer,
        );
        assert!(matches!(result, AuthIoResult::Defer));
        // With IGN64, invalid base64 produces empty string
        assert_eq!(data.unwrap().as_ref(), "");
    }

    #[test]
    fn test_client_item_bad_b64_cancel() {
        // Server sends 3xx with invalid base64, IGN64 NOT set
        let mut io = MockSmtpIo::new()
            .with_smtp_response(false, "334 !!!invalid!!!")
            .with_smtp_response(true, "501 ok");
        let expander = MockExpander::ok("data");
        let info = AuthInstanceInfo {
            public_name: "PLAIN",
            driver_name: "test_auth",
        };
        let mut buffer = String::new();

        let (result, _) = auth_client_item(
            &mut io,
            &expander,
            &info,
            "data",
            AUTH_ITEM_FIRST,
            30,
            &mut buffer,
        );
        assert!(matches!(result, AuthIoResult::Cancelled));
        assert!(buffer.contains("Invalid base64"));
    }

    #[test]
    fn test_client_item_caret_escapes_in_payload() {
        // Verify that ^ escapes are processed in the payload
        // "^user^pass" should produce NUL+user+NUL+pass which base64-encodes
        let mut io = MockSmtpIo::new().with_smtp_response(true, "235 ok");
        let expander = MockExpander::ok("^user^pass");
        let info = AuthInstanceInfo {
            public_name: "PLAIN",
            driver_name: "plaintext",
        };
        let mut buffer = String::new();

        let (result, _) = auth_client_item(
            &mut io,
            &expander,
            &info,
            "^user^pass",
            AUTH_ITEM_FIRST,
            30,
            &mut buffer,
        );
        assert!(matches!(result, AuthIoResult::Ok));

        // The sent AUTH command should contain base64 of [0, u, s, e, r, 0, p, a, s, s]
        let expected_payload: Vec<u8> = vec![0, b'u', b's', b'e', b'r', 0, b'p', b'a', b's', b's'];
        let expected_b64 = STANDARD.encode(&expected_payload);
        let sent = &io.sent_lines[0];
        assert!(
            sent.contains(&expected_b64),
            "Expected base64 '{}' in sent line '{}'",
            expected_b64,
            sent
        );
    }

    #[test]
    fn test_client_item_fail_response() {
        let mut io = MockSmtpIo::new().with_smtp_response(false, "535 Auth failed");
        let expander = MockExpander::ok("data");
        let info = AuthInstanceInfo {
            public_name: "PLAIN",
            driver_name: "test_auth",
        };
        let mut buffer = String::new();

        let (result, _) = auth_client_item(
            &mut io,
            &expander,
            &info,
            "data",
            AUTH_ITEM_FIRST,
            30,
            &mut buffer,
        );
        assert!(matches!(result, AuthIoResult::Fail));
        assert_eq!(buffer, "535 Auth failed");
    }

    #[test]
    fn test_client_item_empty_payload_first() {
        // Empty payload should send "AUTH MECHANISM\r\n" without trailing space+data
        let mut io = MockSmtpIo::new().with_smtp_response(true, "235 ok");
        let expander = MockExpander::ok("");
        let info = AuthInstanceInfo {
            public_name: "EXTERNAL",
            driver_name: "external_auth",
        };
        let mut buffer = String::new();

        let (result, _) = auth_client_item(
            &mut io,
            &expander,
            &info,
            "",
            AUTH_ITEM_FIRST,
            30,
            &mut buffer,
        );
        assert!(matches!(result, AuthIoResult::Ok));
        assert_eq!(io.sent_lines[0], "AUTH EXTERNAL\r\n");
    }
}
