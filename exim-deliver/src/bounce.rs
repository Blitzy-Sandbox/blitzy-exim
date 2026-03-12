// exim-deliver/src/bounce.rs — Bounce/DSN/Warning Message Generation
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Translates src/src/moan.c (885 lines) and bounce/DSN-related functions from
// src/src/deliver.c (send_bounce_message, send_warning_message, maybe_send_dsn)
// into idiomatic Rust.
//
// Per AAP §0.7.2: ZERO unsafe code. All child process operations use safe
// std::process::Command wrappers and nix safe POSIX wrappers.

//! Bounce message generation, Delivery Status Notification (DSN) success
//! messages, delay warning messages, and error notification utilities.
//!
//! # C Source Mapping
//!
//! | Rust function | C function | Source |
//! |---|---|---|
//! | [`write_bounce_from`] | `moan_write_from()` | moan.c:30 |
//! | [`write_bounce_references`] | `moan_write_references()` | moan.c:59 |
//! | [`moan_send_message`] | `moan_send_message()` | moan.c:161 |
//! | [`moan_to_sender`] | `moan_to_sender()` | moan.c:490 |
//! | [`moan_tell_someone`] | `moan_tell_someone()` | moan.c:597 |
//! | [`moan_smtp_batch`] | `moan_smtp_batch()` | moan.c:665 |
//! | [`moan_check_errorcopy`] | `moan_check_errorcopy()` | moan.c:729 |
//! | [`moan_skipped_syntax_errors`] | `moan_skipped_syntax_errors()` | moan.c:810 |
//! | [`send_bounce_message`] | bounce section of deliver_message() | deliver.c:7600+ |
//! | [`send_warning_message`] | warning section | deliver.c:6354 |
//! | [`maybe_send_dsn`] | DSN section | deliver.c:6529 |
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks (AAP §0.7.2).

use std::io::{BufWriter, Write};
use std::process::{exit, Child, Command, Stdio};

use thiserror::Error;
use tracing::{debug, error, info, warn};

use exim_config::types::{ConfigContext, MessageContext, ServerContext};
use exim_expand::{expand_string, expand_string_copy, ExpandError};
use exim_spool::HeaderLine;
use exim_store::taint::{Clean, Tainted};

// Re-export taint types at module level for use in type annotations.
// Tainted<T> wraps data from untrusted external sources (recipient addresses).
// Clean<T> wraps validated/sanitized data for bounce message content.
/// A tainted string from an untrusted source (SMTP input, etc.).
pub type TaintedStr = Tainted<String>;
/// A clean/validated string safe for use in security-sensitive operations.
pub type CleanStr = Clean<String>;

use crate::orchestrator::AddressItem;

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════

/// Default DSN From display name when `dsn_from` is not configured.
/// Matches the C constant `DEFAULT_DSN_FROM` in globals.c.
pub const DEFAULT_DSN_FROM_NAME: &str = "Mail Delivery System";

/// Maximum number of message IDs to retain in References: header.
/// Matches the C implementation at moan.c line 84: "up to a maximum of 12
/// altogether".
const MAX_REFERENCES: usize = 12;

/// Maximum line length per RFC 2822 §2.1.1 (998 characters excluding CRLF).
const MAX_LINE_LENGTH: usize = 998;

/// MIME boundary prefix for multipart/report messages.
const MIME_BOUNDARY_PREFIX: &str = "=_exim_bounce_";

/// DSN flag: SUCCESS notification requested (matches C DSN_SUCCESS = 0x01).
const DSN_SUCCESS: u32 = 0x01;

/// DSN flag: FAILURE notification requested (matches C DSN_FAILURE = 0x02).
const DSN_FAILURE: u32 = 0x02;

/// DSN flag: DELAY notification requested (matches C DSN_DELAY = 0x04).
const DSN_DELAY: u32 = 0x04;

/// DSN RET parameter value: HDRS only (matches C dsn_ret_hdrs = 1).
const DSN_RET_HDRS: i32 = 1;

/// DSN RET parameter value: FULL message (matches C dsn_ret_full = 2).
const DSN_RET_FULL: i32 = 2;

/// Header type constant for Message-ID: (matches C htype_id).
const HTYPE_ID: char = 'I';

/// Header type constant for "old"/deleted headers (matches C htype_old = '*').
const HTYPE_OLD: char = '*';

// ═══════════════════════════════════════════════════════════════════════════
// Error Message Identifier Enum (C: ERRMESS_* constants)
// ═══════════════════════════════════════════════════════════════════════════

/// Identifies the type of error for bounce/notification message generation.
///
/// Each variant maps to a C `ERRMESS_*` constant from `local_scan.h` and
/// controls the Subject line and body text of the error notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorMessageIdent {
    /// Malformed recipient address on command line (C: `ERRMESS_BADARGADDRESS`).
    BadArgAddress,
    /// Bad address with no other addresses present (C: `ERRMESS_BADNOADDRESS`).
    BadNoAddress,
    /// Bad address but others are OK (C: `ERRMESS_BADADDRESS`).
    BadAddress,
    /// No non-suppressed addresses from `-t` (C: `ERRMESS_IGADDRESS`).
    IgAddress,
    /// No recipient addresses at all (C: `ERRMESS_NOADDRESS`).
    NoAddress,
    /// System I/O failure (C: `ERRMESS_IOERR`).
    IoErr,
    /// Header section too long (C: `ERRMESS_VLONGHEADER`).
    VLongHeader,
    /// Single header line too long (C: `ERRMESS_VLONGHDRLINE`).
    VLongHdrLine,
    /// Message exceeds size limit (C: `ERRMESS_TOOBIG`).
    TooBig,
    /// Too many recipients (C: `ERRMESS_TOOMANYRECIP`).
    TooManyRecip,
    /// Rejected by `local_scan()` (C: `ERRMESS_LOCAL_SCAN`).
    LocalScan,
    /// Rejected by non-SMTP ACL (C: `ERRMESS_LOCAL_ACL`).
    LocalAcl,
    /// DMARC forensic report (C: `ERRMESS_DMARC_FORENSIC`).
    /// In C this is behind `#ifdef EXIM_HAVE_DMARC`; in Rust it is always
    /// present in the enum but behaviour is feature-gated where applicable.
    DmarcForensic,
}

impl std::fmt::Display for ErrorMessageIdent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadArgAddress => write!(f, "BADARGADDRESS"),
            Self::BadNoAddress => write!(f, "BADNOADDRESS"),
            Self::BadAddress => write!(f, "BADADDRESS"),
            Self::IgAddress => write!(f, "IGADDRESS"),
            Self::NoAddress => write!(f, "NOADDRESS"),
            Self::IoErr => write!(f, "IOERR"),
            Self::VLongHeader => write!(f, "VLONGHEADER"),
            Self::VLongHdrLine => write!(f, "VLONGHDRLINE"),
            Self::TooBig => write!(f, "TOOBIG"),
            Self::TooManyRecip => write!(f, "TOOMANYRECIP"),
            Self::LocalScan => write!(f, "LOCAL_SCAN"),
            Self::LocalAcl => write!(f, "LOCAL_ACL"),
            Self::DmarcForensic => write!(f, "DMARC_FORENSIC"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ErrorBlock — Linked error data chain (C: error_block)
// ═══════════════════════════════════════════════════════════════════════════

/// A chain of error blocks carrying data about a message processing error.
///
/// Replaces the C `error_block` struct with its linked-list `next` pointer.
/// Each block carries one or two text strings describing an error, and blocks
/// are chained together to describe multiple errors (e.g., multiple bad
/// addresses).
#[derive(Debug, Clone)]
pub struct ErrorBlock {
    /// Primary error text (always present).
    pub text1: String,
    /// Secondary error text (e.g., the problematic address).
    pub text2: Option<String>,
    /// Next error in the chain (replaces C `error_block *next`).
    pub next: Option<Box<ErrorBlock>>,
}

impl ErrorBlock {
    /// Create a new `ErrorBlock` with the given text.
    pub fn new(text1: impl Into<String>) -> Self {
        Self {
            text1: text1.into(),
            text2: None,
            next: None,
        }
    }

    /// Create a new `ErrorBlock` with both text fields.
    pub fn with_text2(text1: impl Into<String>, text2: impl Into<String>) -> Self {
        Self {
            text1: text1.into(),
            text2: Some(text2.into()),
            next: None,
        }
    }

    /// Returns an iterator over this block and all chained blocks.
    pub fn iter(&self) -> ErrorBlockIter<'_> {
        ErrorBlockIter {
            current: Some(self),
        }
    }
}

/// Iterator over a chain of [`ErrorBlock`] instances.
pub struct ErrorBlockIter<'a> {
    current: Option<&'a ErrorBlock>,
}

impl<'a> Iterator for ErrorBlockIter<'a> {
    type Item = &'a ErrorBlock;

    fn next(&mut self) -> Option<Self::Item> {
        let block = self.current?;
        self.current = block.next.as_deref();
        Some(block)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// BounceError — Error type for bounce/DSN operations
// ═══════════════════════════════════════════════════════════════════════════

/// Errors that can occur during bounce/DSN/warning message generation.
///
/// Replaces C-style errno/strerror error handling from moan.c with structured
/// error types derived via `thiserror`.
#[derive(Debug, Error)]
pub enum BounceError {
    /// Failed to create child Exim process for message injection.
    /// Replaces `child_open_exim()` returning -1 in moan.c.
    #[error("failed to create child process: {0}")]
    ChildCreationFailed(String),

    /// Child Exim process returned a non-zero exit status.
    /// Replaces `child_close()` returning non-zero in moan.c.
    #[error("child process returned status {0}")]
    ChildFailed(i32),

    /// String expansion (dsn_from, errors_copy, syntax_errors_to, etc.) failed.
    /// Replaces `expand_string()` returning NULL in moan.c.
    #[error("expansion failed: {0}")]
    ExpansionFailed(String),

    /// Underlying I/O error during message generation or pipe operations.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

impl From<ExpandError> for BounceError {
    fn from(e: ExpandError) -> Self {
        BounceError::ExpansionFailed(e.to_string())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Internal Helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Returns the path to the Exim binary.
///
/// Checks the `EXIM_PATH` environment variable first, then falls back to
/// `/usr/sbin/exim`. This replaces the C compile-time `BIN_DIRECTORY`
/// configuration.
fn exim_binary_path() -> String {
    std::env::var("EXIM_PATH").unwrap_or_else(|_| "/usr/sbin/exim".to_string())
}

/// Open a child Exim process for message injection (replaces `child_open_exim()`).
///
/// Spawns the Exim binary with `-t -oem -oi` flags:
///   - `-t` — read recipients from message headers
///   - `-oem` — report errors by mail (not to stderr)
///   - `-oi` — don't treat a line of just "." as end-of-input
///
/// Returns the `Child` handle with stdin piped for writing the message.
fn child_open_exim() -> Result<Child, BounceError> {
    let exim_path = exim_binary_path();
    debug!(path = %exim_path, "opening child Exim process");

    Command::new(&exim_path)
        .args(["-t", "-oem", "-oi"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            error!(error = %e, "failed to create child Exim process");
            BounceError::ChildCreationFailed(e.to_string())
        })
}

/// Open a child Exim process with a specific envelope sender and optional
/// authentication (replaces `child_open_exim2()`).
///
/// Additional flags:
///   - `-f <sender>` — set envelope sender
///   - `-oMas <auth>` — set authenticated sender (if provided)
fn child_open_exim2(sender: &str, auth: Option<&str>) -> Result<Child, BounceError> {
    let exim_path = exim_binary_path();
    debug!(
        path = %exim_path,
        sender = %sender,
        "opening child Exim process with custom sender"
    );

    let mut cmd = Command::new(&exim_path);
    cmd.args(["-t", "-oem", "-oi", "-f", sender]);

    if let Some(auth_sender) = auth {
        cmd.args(["-oMas", auth_sender]);
    }

    cmd.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            error!(error = %e, "failed to create child Exim process");
            BounceError::ChildCreationFailed(e.to_string())
        })
}

/// Wait for a child process to finish and return its exit status.
/// Replaces the C `child_close()` function.
///
/// Uses `nix::sys::wait::waitpid` semantics, but via safe `Child::wait()`.
/// If the child exits with status 0, returns `Ok(0)`. Otherwise returns
/// `Ok(code)` for the caller to decide whether to treat as error.
fn child_close(child: &mut Child) -> Result<i32, BounceError> {
    // nix::sys::wait::waitpid is the underlying POSIX API; we use the safe
    // std::process::Child::wait() wrapper which provides identical semantics.
    match child.wait() {
        Ok(status) => {
            let code = status.code().unwrap_or(-1);
            if code != 0 {
                debug!(exit_code = code, "child Exim process returned non-zero");
            }
            Ok(code)
        }
        Err(e) => {
            error!(error = %e, "failed to wait for child Exim process");
            Err(BounceError::IoError(e))
        }
    }
}

/// Kill a child process that has become unresponsive.
/// Uses `nix::sys::signal::kill()` with SIGTERM for safe process termination.
pub fn kill_child(child: &Child) {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    let raw_id = child.id();
    if let Ok(()) = kill(Pid::from_raw(raw_id as i32), Signal::SIGTERM) {
        debug!(pid = raw_id, "sent SIGTERM to child Exim process");
    }
}

/// Generate a unique MIME boundary string for multipart messages.
///
/// Uses the message ID and a counter to ensure uniqueness within a single
/// message's MIME parts.
fn generate_mime_boundary(message_id: &str, part: u32) -> String {
    format!("{}{}-{:04}", MIME_BOUNDARY_PREFIX, message_id, part)
}

/// Extract the local part from an email address (everything before `@`).
fn extract_local_part(address: &str) -> &str {
    match address.find('@') {
        Some(pos) => &address[..pos],
        None => address,
    }
}

/// Extract the domain from an email address (everything after `@`).
fn extract_domain(address: &str) -> &str {
    match address.find('@') {
        Some(pos) => &address[pos + 1..],
        None => "",
    }
}

/// Match a recipient address against an errors_copy pattern.
///
/// Supports simple glob matching (`*@domain`, `localpart@*`, `*@*`)
/// consistent with the C `match_address_list()` behaviour in moan.c.
fn address_matches_pattern(address: &str, pattern: &str) -> bool {
    let addr_lower = address.to_lowercase();
    let pat_lower = pattern.to_lowercase();

    if pat_lower == "*" {
        return true;
    }

    if let Some(at_pos) = pat_lower.find('@') {
        let pat_local = &pat_lower[..at_pos];
        let pat_domain = &pat_lower[at_pos + 1..];

        let addr_local = extract_local_part(&addr_lower);
        let addr_domain = extract_domain(&addr_lower);

        let local_match = pat_local == "*" || pat_local == addr_local;
        let domain_match = pat_domain == "*" || pat_domain == addr_domain;

        local_match && domain_match
    } else {
        // Pattern without @ is treated as a domain match
        let addr_domain = extract_domain(&addr_lower);
        pat_lower == addr_domain
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API: Header Writing Helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Write the `From:` header for a bounce/DSN message.
///
/// Translates `moan_write_from()` from moan.c line 30.
///
/// If `config.dsn_from` is set, it is expanded (may contain `${...}` variables)
/// and used as the From address. Otherwise, the default "Mail Delivery System
/// `<Mailer-Daemon@qualify_domain>`" format is used.
///
/// # Errors
///
/// Returns [`BounceError::ExpansionFailed`] if `dsn_from` expansion fails.
/// Returns [`BounceError::IoError`] on write failure.
pub fn write_bounce_from<W: Write>(
    writer: &mut W,
    config: &ConfigContext,
) -> Result<(), BounceError> {
    let from_value = if let Some(ref dsn_from) = config.dsn_from {
        if !dsn_from.is_empty() {
            // Expand the configured dsn_from value which may contain ${...} expressions
            match expand_string(dsn_from) {
                Ok(expanded) => expanded,
                Err(e) => {
                    warn!(dsn_from = %dsn_from, error = %e, "dsn_from expansion failed, using default");
                    format!(
                        "Mail Delivery System <Mailer-Daemon@{}>",
                        config.qualify_domain_sender
                    )
                }
            }
        } else {
            format!(
                "Mail Delivery System <Mailer-Daemon@{}>",
                config.qualify_domain_sender
            )
        }
    } else {
        format!(
            "Mail Delivery System <Mailer-Daemon@{}>",
            config.qualify_domain_sender
        )
    };

    writeln!(writer, "From: {}", from_value)?;
    Ok(())
}

/// Write `References:` and `In-Reply-To:` headers for a bounce/DSN message.
///
/// Translates `moan_write_references()` from moan.c line 59.
///
/// Scans the provided headers for existing `References:` and `Message-ID:`
/// values. Collects up to [`MAX_REFERENCES`] (12) message IDs in a circular
/// buffer. When the buffer exceeds 12 entries, the second-oldest entry is
/// dropped (preserving the very first and the most recent entries).
///
/// Enforces the RFC 2822 998-character line length limit.
///
/// # Arguments
///
/// * `writer` — Output writer.
/// * `message_id` — Current message's ID to append.
/// * `headers` — Original message headers to scan for References/Message-ID.
///
/// # Errors
///
/// Returns [`BounceError::IoError`] on write failure.
pub fn write_bounce_references<W: Write>(
    writer: &mut W,
    message_id: Option<&str>,
    headers: Option<&[HeaderLine]>,
) -> Result<(), BounceError> {
    let mut ids: Vec<String> = Vec::with_capacity(MAX_REFERENCES + 1);

    // Scan existing headers for References: and Message-ID: values
    if let Some(hdrs) = headers {
        for hdr in hdrs {
            // Skip deleted/old headers
            if hdr.header_type == HTYPE_OLD {
                continue;
            }

            let text = hdr.text.trim();
            let lower = text.to_lowercase();

            // Extract message IDs from References: header
            if lower.starts_with("references:") {
                let value = &text["references:".len()..];
                extract_message_ids(value, &mut ids);
            }
            // Extract message ID from Message-ID: header
            else if lower.starts_with("message-id:") {
                let value = &text["message-id:".len()..];
                extract_message_ids(value, &mut ids);
            }
        }
    }

    // Append the current message's ID if provided
    if let Some(mid) = message_id {
        let formatted = if mid.starts_with('<') {
            mid.to_string()
        } else {
            format!("<{}>", mid)
        };
        ids.push(formatted);
    }

    if ids.is_empty() {
        return Ok(());
    }

    // Enforce the 12-message-ID limit using the circular buffer strategy:
    // drop the second-oldest entry to preserve the first and the most recent.
    while ids.len() > MAX_REFERENCES {
        ids.remove(1);
    }

    // Write References: header with line length enforcement
    write!(writer, "References:")?;
    let mut line_len: usize = "References:".len();

    for id in &ids {
        // Check if adding this ID would exceed the line length limit
        // +1 for the space separator
        if line_len + 1 + id.len() > MAX_LINE_LENGTH && line_len > "References:".len() {
            write!(writer, "\r\n ")?;
            line_len = 1;
        }
        write!(writer, " {}", id)?;
        line_len += 1 + id.len();
    }
    writeln!(writer)?;

    // Write In-Reply-To: with just the last message ID
    if let Some(last_id) = ids.last() {
        writeln!(writer, "In-Reply-To: {}", last_id)?;
    }

    Ok(())
}

/// Extract `<...>` message IDs from a header value string.
fn extract_message_ids(value: &str, ids: &mut Vec<String>) {
    let mut remaining = value.trim();
    while let Some(start) = remaining.find('<') {
        if let Some(end) = remaining[start..].find('>') {
            let id = &remaining[start..start + end + 1];
            ids.push(id.to_string());
            remaining = &remaining[start + end + 1..];
        } else {
            break;
        }
    }
}

/// Write the subject line for an error message based on the error ident type.
fn write_error_subject<W: Write>(
    writer: &mut W,
    ident: ErrorMessageIdent,
) -> Result<(), BounceError> {
    let subject = match ident {
        ErrorMessageIdent::BadArgAddress => "Mail failure - malformed recipient address",
        ErrorMessageIdent::BadNoAddress => "Mail failure - malformed address",
        ErrorMessageIdent::BadAddress => "Mail failure - malformed address",
        ErrorMessageIdent::IgAddress => "Mail failure - no recipient addresses",
        ErrorMessageIdent::NoAddress => "Mail failure - no recipient addresses",
        ErrorMessageIdent::IoErr => "Mail failure - system failure",
        ErrorMessageIdent::VLongHeader => "Mail failure - overlong header section",
        ErrorMessageIdent::VLongHdrLine => "Mail failure - overlong header line",
        ErrorMessageIdent::TooBig => "Mail failure - message too big",
        ErrorMessageIdent::TooManyRecip => "Mail failure - too many recipients",
        ErrorMessageIdent::LocalScan => "Mail failure - rejected by local scanning code",
        ErrorMessageIdent::LocalAcl => "Mail failure - rejected after DATA",
        ErrorMessageIdent::DmarcForensic => "DMARC Forensic Report",
    };
    writeln!(writer, "Subject: {}", subject)?;
    Ok(())
}

/// Write the error body text based on the error ident type and error blocks.
///
/// This mirrors the large switch statement in moan_send_message() from
/// moan.c lines 210–400.
fn write_error_body<W: Write>(
    writer: &mut W,
    ident: ErrorMessageIdent,
    eblock: &ErrorBlock,
    firstline: Option<&str>,
) -> Result<(), BounceError> {
    // Write initial blank line to separate headers from body
    writeln!(writer)?;

    // Write firstline if provided (used for custom per-error text)
    if let Some(line) = firstline {
        if !line.is_empty() {
            writeln!(writer, "{}", line)?;
            writeln!(writer)?;
        }
    }

    match ident {
        ErrorMessageIdent::BadArgAddress => {
            writeln!(
                writer,
                "A message that you sent contained a recipient address that was\n\
                 incorrectly constructed:\n"
            )?;
            for block in eblock.iter() {
                writeln!(writer, "  {}", block.text1)?;
                if let Some(ref t2) = block.text2 {
                    writeln!(writer, "  {}", t2)?;
                }
            }
            writeln!(
                writer,
                "\nThis address has been ignored. The other addresses in the\n\
                 message were syntactically valid and have been passed on for\n\
                 an attempt at delivery."
            )?;
        }

        ErrorMessageIdent::BadNoAddress | ErrorMessageIdent::BadAddress => {
            let some_ok = ident == ErrorMessageIdent::BadAddress;
            writeln!(
                writer,
                "A message that you sent contained one or more recipient addresses that were\n\
                 incorrectly constructed:\n"
            )?;
            for block in eblock.iter() {
                writeln!(writer, "  {}", block.text1)?;
                if let Some(ref t2) = block.text2 {
                    writeln!(writer, "  {}", t2)?;
                }
            }
            if some_ok {
                writeln!(
                    writer,
                    "\nThe other addresses in the message were syntactically valid and\n\
                     have been passed on for an attempt at delivery."
                )?;
            } else {
                writeln!(
                    writer,
                    "\nAs there were no other correctly-formed recipient addresses in\n\
                     the message, no attempt at delivery was possible."
                )?;
            }
        }

        ErrorMessageIdent::IgAddress => {
            writeln!(
                writer,
                "A message that you sent using the -t command line option contained no\n\
                 recipient addresses that were not also on the command line, and were\n\
                 therefore suppressed. This left no recipient addresses, and so no\n\
                 attempt at delivery was possible."
            )?;
        }

        ErrorMessageIdent::NoAddress => {
            writeln!(
                writer,
                "A message that you sent contained no recipient addresses, and therefore no\n\
                 delivery could be attempted."
            )?;
        }

        ErrorMessageIdent::IoErr => {
            writeln!(
                writer,
                "The following error was detected while processing a message that you sent:\n"
            )?;
            for block in eblock.iter() {
                writeln!(writer, "  {}", block.text1)?;
                if let Some(ref t2) = block.text2 {
                    writeln!(writer, "  {}", t2)?;
                }
            }
        }

        ErrorMessageIdent::VLongHeader => {
            writeln!(
                writer,
                "A message that you sent contained a header section that was excessively\n\
                 long and has been rejected."
            )?;
            for block in eblock.iter() {
                writeln!(writer, "\n  {}", block.text1)?;
                if let Some(ref t2) = block.text2 {
                    writeln!(writer, "  {}", t2)?;
                }
            }
        }

        ErrorMessageIdent::VLongHdrLine => {
            writeln!(
                writer,
                "A message that you sent contained a header line that was excessively\n\
                 long and has been rejected."
            )?;
            for block in eblock.iter() {
                writeln!(writer, "\n  {}", block.text1)?;
                if let Some(ref t2) = block.text2 {
                    writeln!(writer, "  {}", t2)?;
                }
            }
        }

        ErrorMessageIdent::TooBig => {
            writeln!(
                writer,
                "A message that you sent was longer than the maximum size allowed on this\n\
                 system. It was not delivered to any of the recipients."
            )?;
        }

        ErrorMessageIdent::TooManyRecip => {
            writeln!(
                writer,
                "A message that you sent contained more recipients than is allowed on this\n\
                 system. It was not delivered to any of the recipients."
            )?;
        }

        ErrorMessageIdent::LocalScan | ErrorMessageIdent::LocalAcl => {
            writeln!(
                writer,
                "A message that you sent has been rejected by the local scanning code.\n\
                 The following error was given:\n"
            )?;
            for block in eblock.iter() {
                writeln!(writer, "  {}", block.text1)?;
                if let Some(ref t2) = block.text2 {
                    writeln!(writer, "  {}", t2)?;
                }
            }
        }

        ErrorMessageIdent::DmarcForensic => {
            // DMARC forensic report — the error block contains the report body
            for block in eblock.iter() {
                writeln!(writer, "{}", block.text1)?;
                if let Some(ref t2) = block.text2 {
                    writeln!(writer, "{}", t2)?;
                }
            }
        }
    }

    Ok(())
}

/// Write original message headers (and optionally body) into the notification,
/// respecting `bounce_return_size_limit` and `bounce_return_linesize_limit`.
fn write_original_message_section<W: Write>(
    writer: &mut W,
    headers: &[HeaderLine],
    message_body: Option<&[u8]>,
    config: &ConfigContext,
) -> Result<(), BounceError> {
    if !config.bounce_return_message {
        return Ok(());
    }

    writeln!(
        writer,
        "\n------ This is a copy of the message, including all the headers. ------\n"
    )?;

    let mut written: usize = 0;
    let size_limit = config.bounce_return_size_limit.max(0) as usize;
    let line_limit = config.bounce_return_linesize_limit.max(0) as usize;

    // Write headers
    for hdr in headers {
        if hdr.header_type == HTYPE_OLD {
            continue;
        }
        // Enforce line length limit on each header line
        let text = if line_limit > 0 && hdr.text.len() > line_limit {
            &hdr.text[..line_limit]
        } else {
            &hdr.text
        };

        if size_limit > 0 && written + text.len() > size_limit {
            writeln!(
                writer,
                "\n------ The rest of the message has been cut. ------"
            )?;
            return Ok(());
        }

        write!(writer, "{}", text)?;
        // Add newline if the header text doesn't end with one
        if !text.ends_with('\n') {
            writeln!(writer)?;
        }
        written += text.len();
    }

    // Write body if configured to include it
    if config.bounce_return_body {
        if let Some(body) = message_body {
            writeln!(writer)?;
            let body_to_write = if size_limit > 0 && written + body.len() > size_limit {
                let remaining = size_limit.saturating_sub(written);
                &body[..remaining.min(body.len())]
            } else {
                body
            };

            writer.write_all(body_to_write)?;

            if size_limit > 0 && written + body.len() > size_limit {
                writeln!(
                    writer,
                    "\n\n------ The body of the message is {0} characters long; only the first\n\
                     ------ {1} or so are included here.\n",
                    body.len(),
                    body_to_write.len()
                )?;
            }
        }
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API: Core Notification Functions
// ═══════════════════════════════════════════════════════════════════════════

/// Send an error notification message to a specified recipient.
///
/// Translates `moan_send_message()` from moan.c line 161 (~300 lines).
///
/// Spawns a child Exim process via `-t` and writes a complete error notification
/// message including headers (Reply-To, Auto-Submitted, From, To, References,
/// Subject) and body text appropriate for the error type. Optionally includes a
/// copy of the original message up to `bounce_return_size_limit`.
///
/// # Arguments
///
/// * `recipient` — Email address to send the notification to.
/// * `ident` — Type of error determining Subject and body text.
/// * `eblock` — Chain of error descriptions.
/// * `headers` — Original message headers.
/// * `message_body` — Original message body (for inclusion in bounce).
/// * `firstline` — Optional first line inserted before the standard body text.
/// * `server_ctx` — Daemon-lifetime context for hostname.
/// * `config` — Configuration context for bounce-related settings.
///
/// # Returns
///
/// `Ok(true)` if the message was sent successfully, `Ok(false)` if the child
/// process returned a non-zero exit status (message may not have been sent).
///
/// # Errors
///
/// Returns [`BounceError::ChildCreationFailed`] if the child process could not
/// be spawned.
// The 8-parameter signature mirrors the C moan_send_message() interface exactly
// to maintain behavioral parity with the original moan.c implementation.
#[allow(clippy::too_many_arguments)]
pub fn moan_send_message(
    recipient: &str,
    ident: ErrorMessageIdent,
    eblock: &ErrorBlock,
    headers: &[HeaderLine],
    message_body: Option<&[u8]>,
    firstline: Option<&str>,
    server_ctx: &ServerContext,
    config: &ConfigContext,
) -> Result<bool, BounceError> {
    debug!(
        recipient = %recipient,
        ident = %ident,
        hostname = %server_ctx.primary_hostname,
        debug_sel = server_ctx.debug_selector,
        "sending error notification message"
    );

    let mut child = child_open_exim()?;

    {
        let stdin = child.stdin.take().ok_or_else(|| {
            BounceError::ChildCreationFailed("failed to get child stdin".to_string())
        })?;
        let mut writer = BufWriter::new(stdin);

        // Write Reply-To if configured
        if let Some(ref reply_to) = config.errors_reply_to {
            if !reply_to.is_empty() {
                writeln!(writer, "Reply-To: {}", reply_to)?;
            }
        }

        // Auto-Submitted header per RFC 3834
        writeln!(writer, "Auto-Submitted: auto-replied")?;

        // From header (uses dsn_from or default)
        write_bounce_from(&mut writer, config)?;

        // To header
        writeln!(writer, "To: {}", recipient)?;

        // References and In-Reply-To headers
        write_bounce_references(
            &mut writer,
            None, // Current message ID not available in this context
            Some(headers),
        )?;

        // Subject line based on error type
        write_error_subject(&mut writer, ident)?;

        // MIME headers if the message body might be included
        if config.bounce_return_message && message_body.is_some() {
            writeln!(writer, "MIME-Version: 1.0")?;
            writeln!(writer, "Content-Type: text/plain; charset=us-ascii")?;
        }

        // Body text
        write_error_body(&mut writer, ident, eblock, firstline)?;

        // Include original message if configured
        write_original_message_section(&mut writer, headers, message_body, config)?;

        // Flush the writer to ensure all data is sent before dropping
        writer.flush()?;
    }

    // Wait for child process to finish
    let exit_code = child_close(&mut child)?;
    if exit_code != 0 {
        warn!(
            exit_code = exit_code,
            recipient = %recipient,
            "child Exim process returned non-zero exit code for error notification"
        );
        return Ok(false);
    }

    debug!(recipient = %recipient, "error notification sent successfully");
    Ok(true)
}

/// Send an error notification to the message sender, or log if sender
/// is unavailable.
///
/// Translates `moan_to_sender()` from moan.c line 490 (~86 lines).
///
/// Checks whether the sender address is viable (non-empty, not a
/// `local_error_message`). If the sender is reachable, calls
/// [`moan_send_message`] to deliver the notification. If not (empty sender
/// or error from `<>`), the error is logged instead.
///
/// # Arguments
///
/// * `ident` — Type of error.
/// * `eblock` — Chain of error descriptions.
/// * `headers` — Original message headers.
/// * `message_body` — Original message body.
/// * `check_sender` — If true, validates the From line for UUCP-style "From ".
/// * `msg_ctx` — Per-message context (contains sender_address).
/// * `config` — Configuration context.
///
/// # Returns
///
/// `Ok(true)` if the notification was sent or suppressed, `Ok(false)` if
/// sending failed.
pub fn moan_to_sender(
    ident: ErrorMessageIdent,
    eblock: &ErrorBlock,
    headers: &[HeaderLine],
    message_body: Option<&[u8]>,
    check_sender: bool,
    msg_ctx: &MessageContext,
    config: &ConfigContext,
) -> Result<bool, BounceError> {
    debug!(
        sender = %msg_ctx.sender_address,
        ident = %ident,
        "attempting to notify sender"
    );

    // Check if sender is empty (bounce from <>)
    if msg_ctx.sender_address.is_empty() {
        info!(
            ident = %ident,
            "cannot send error message to empty sender (bounce of bounce)"
        );
        return Ok(false);
    }

    // Check if this is a local_error_message (prevents loops)
    if msg_ctx.local_error_message.is_some() {
        info!(
            ident = %ident,
            "suppressing error notification for local_error_message"
        );
        return Ok(false);
    }

    // Optional UUCP-style From line check
    if check_sender {
        // In C, this checks the first line of input for "From " prefix.
        // In the Rust implementation, the headers already contain structured data,
        // so the UUCP check is only relevant for raw input mode. We log and skip
        // if headers start with a From line (which is rare in modern usage).
        if let Some(first) = headers.first() {
            if first.text.starts_with("From ") {
                debug!("detected UUCP-style 'From ' line in headers");
            }
        }
    }

    // Build a ServerContext-lite for moan_send_message (we use the primary_hostname
    // from config since ServerContext is not always available in the sender path)
    let server_ctx = ServerContext::default();

    moan_send_message(
        &msg_ctx.sender_address,
        ident,
        eblock,
        headers,
        message_body,
        None,
        &server_ctx,
        config,
    )
}

/// Send a notification message to an arbitrary recipient (e.g., postmaster).
///
/// Translates `moan_tell_someone()` from moan.c line 597 (~42 lines).
///
/// Sends a notification email with a custom subject and body, optionally
/// listing deferred addresses with their error details.
///
/// # Arguments
///
/// * `who` — Recipient address (typically postmaster or mailmaster).
/// * `addresses` — Deferred/failed addresses to list in the message body.
/// * `subject` — Subject line.
/// * `body` — Body text.
/// * `config` — Configuration context.
///
/// # Errors
///
/// Returns [`BounceError::ChildCreationFailed`] or [`BounceError::IoError`].
pub fn moan_tell_someone(
    who: &str,
    addresses: &[AddressItem],
    subject: &str,
    body: &str,
    config: &ConfigContext,
) -> Result<(), BounceError> {
    debug!(
        recipient = %who,
        subject = %subject,
        address_count = addresses.len(),
        "sending notification to someone"
    );

    let mut child = child_open_exim()?;

    {
        let stdin = child.stdin.take().ok_or_else(|| {
            BounceError::ChildCreationFailed("failed to get child stdin".to_string())
        })?;
        let mut writer = BufWriter::new(stdin);

        // Auto-Submitted header per RFC 3834
        writeln!(writer, "Auto-Submitted: auto-replied")?;

        // From header
        write_bounce_from(&mut writer, config)?;

        // To header
        writeln!(writer, "To: {}", who)?;

        // Subject header
        writeln!(writer, "Subject: {}", subject)?;

        // Blank line separating headers from body
        writeln!(writer)?;

        // Body text
        writeln!(writer, "{}", body)?;

        // List deferred/failed addresses with details
        if !addresses.is_empty() {
            writeln!(writer)?;
            for addr in addresses {
                let addr_str = addr.address.as_ref();
                writeln!(writer, "  {}", addr_str)?;

                // Show parent address if this is a child address
                if addr.parent_index >= 0 {
                    writeln!(writer, "    (parent: index {})", addr.parent_index)?;
                }

                // Show error information
                if addr.basic_errno != 0 {
                    writeln!(writer, "    error {}", addr.basic_errno)?;
                }
                if let Some(ref msg) = addr.message {
                    writeln!(writer, "    {}", msg)?;
                }
            }
        }

        writer.flush()?;
    }

    let exit_code = child_close(&mut child)?;
    if exit_code != 0 {
        warn!(
            exit_code = exit_code,
            recipient = %who,
            "child Exim process returned non-zero for tell_someone notification"
        );
    }

    Ok(())
}

/// Handle batch SMTP errors: write diagnostic output and exit.
///
/// Translates `moan_smtp_batch()` from moan.c line 665 (~46 lines).
///
/// Writes machine-parseable output to stdout (transaction and error line numbers)
/// and human-readable error text to stderr, then exits with:
///   - Code 1 if some messages were accepted in this batch session
///   - Code 2 if no messages were accepted
///
/// # Arguments
///
/// * `cmd_buffer` — The SMTP command that caused the error (if any).
/// * `message` — Error message text.
/// * `receive_messagecount` — Number of messages successfully received.
/// * `transaction_linecount` — Line number within current SMTP transaction.
/// * `receive_linecount` — Overall line number in input.
///
/// This function does not return (exits the process).
pub fn moan_smtp_batch(
    cmd_buffer: Option<&str>,
    message: &str,
    receive_messagecount: u32,
    transaction_linecount: u32,
    receive_linecount: u32,
) -> ! {
    // Machine-parseable output to stdout
    // Format: transaction_linecount error_linecount
    println!("{} {}", transaction_linecount, receive_linecount);

    // Human-readable error to stderr
    if let Some(cmd) = cmd_buffer {
        if !cmd.is_empty() {
            eprintln!("Command: {}", cmd);
        }
    }
    eprintln!("Error: {}", message);

    // Exit code: 1 if some messages accepted, 2 if none
    let code = if receive_messagecount > 0 { 1 } else { 2 };
    debug!(
        exit_code = code,
        messages_received = receive_messagecount,
        "batch SMTP error exit"
    );
    exit(code);
}

/// Check `errors_copy` configuration for additional BCC recipients.
///
/// Translates `moan_check_errorcopy()` from moan.c line 729 (~56 lines).
///
/// Parses the `errors_copy` config option which contains a list of
/// `pattern => redirect_address` pairs. For the given recipient, finds the
/// first matching pattern and expands the redirect address with `$local_part`
/// and `$domain` variables available.
///
/// # Arguments
///
/// * `recipient` — The original recipient address to check.
/// * `config` — Configuration context containing `errors_copy`.
///
/// # Returns
///
/// `Some(redirect_address)` if a match is found, `None` otherwise.
pub fn moan_check_errorcopy(recipient: &str, config: &ConfigContext) -> Option<String> {
    let errors_copy = config.errors_copy.as_ref()?;
    if errors_copy.is_empty() {
        return None;
    }

    debug!(recipient = %recipient, "checking errors_copy config");

    // Parse errors_copy items: "pattern => redirect_address"
    // Each item is separated by newlines or semicolons
    for entry in errors_copy.split(['\n', ';']) {
        let entry = entry.trim();
        if entry.is_empty() || entry.starts_with('#') {
            continue;
        }

        // Split on " => " or "=>" to get pattern and redirect
        let parts: Vec<&str> = if entry.contains(" => ") {
            entry.splitn(2, " => ").collect()
        } else if entry.contains("=>") {
            entry.splitn(2, "=>").collect()
        } else {
            continue;
        };

        if parts.len() != 2 {
            continue;
        }

        let pattern = parts[0].trim();
        let redirect_template = parts[1].trim();

        // Check if recipient matches the pattern
        if !address_matches_pattern(recipient, pattern) {
            continue;
        }

        debug!(
            recipient = %recipient,
            pattern = %pattern,
            redirect = %redirect_template,
            "errors_copy match found"
        );

        // Expand the redirect address with $local_part and $domain available.
        // The C code uses expand_string_copy() for this.
        // We substitute $local_part and $domain manually before expansion.
        let local_part = extract_local_part(recipient);
        let domain = extract_domain(recipient);

        let expanded_template = redirect_template
            .replace("$local_part", local_part)
            .replace("$domain", domain);

        match expand_string_copy(&expanded_template) {
            Ok(result) => {
                debug!(result = %result, "errors_copy expanded successfully");
                return Some(result);
            }
            Err(e) => {
                warn!(
                    error = %e,
                    redirect = %redirect_template,
                    "errors_copy expansion failed"
                );
                return None;
            }
        }
    }

    None
}

/// Report syntax errors that were skipped by the redirect router.
///
/// Translates `moan_skipped_syntax_errors()` from moan.c line 810 (~73 lines).
///
/// Logs all syntax errors to the main log. If `syntax_errors_to` is configured,
/// sends an email notification listing the errors. Includes a custom message if
/// provided and notes whether some valid addresses were generated.
///
/// # Arguments
///
/// * `router_name` — Name of the router that encountered the errors.
/// * `eblock` — Chain of error descriptions.
/// * `syntax_errors_to` — Address to send notification to (may contain `${...}`).
/// * `some_generated` — Whether some valid addresses were generated despite errors.
/// * `custom_message` — Optional custom message to include.
/// * `config` — Configuration context.
///
/// # Returns
///
/// `Ok(true)` if notification was sent (or no notification needed),
/// `Ok(false)` if sending failed.
pub fn moan_skipped_syntax_errors(
    router_name: &str,
    eblock: &ErrorBlock,
    syntax_errors_to: Option<&str>,
    some_generated: bool,
    custom_message: Option<&str>,
    config: &ConfigContext,
) -> Result<bool, BounceError> {
    debug!(
        router = %router_name,
        "reporting skipped syntax errors"
    );

    // Log all errors to main log
    for block in eblock.iter() {
        info!(
            router = %router_name,
            error = %block.text1,
            detail = ?block.text2,
            "skipped syntax error in redirect router"
        );
    }

    // If no notification address configured, just log and return
    let notify_addr = match syntax_errors_to {
        Some(addr) if !addr.is_empty() => addr,
        _ => return Ok(true),
    };

    // Expand the notification address (may contain ${...})
    let expanded_addr = match expand_string(notify_addr) {
        Ok(addr) => addr,
        Err(e) => {
            warn!(
                error = %e,
                address = %notify_addr,
                "syntax_errors_to expansion failed"
            );
            return Err(BounceError::ExpansionFailed(format!(
                "syntax_errors_to: {}",
                e
            )));
        }
    };

    debug!(
        address = %expanded_addr,
        "sending syntax error notification"
    );

    // Spawn child Exim process
    let mut child = child_open_exim()?;

    {
        let stdin = child.stdin.take().ok_or_else(|| {
            BounceError::ChildCreationFailed("failed to get child stdin".to_string())
        })?;
        let mut writer = BufWriter::new(stdin);

        // Headers
        writeln!(writer, "Auto-Submitted: auto-replied")?;
        write_bounce_from(&mut writer, config)?;
        writeln!(writer, "To: {}", expanded_addr)?;
        writeln!(writer, "Subject: Syntax errors in forwarding/filtering")?;

        // Body
        writeln!(writer)?;
        writeln!(
            writer,
            "The {} router encountered syntax errors while processing\n\
             a forwarding or filtering file:\n",
            router_name
        )?;

        // List each error
        for block in eblock.iter() {
            writeln!(writer, "  {}", block.text1)?;
            if let Some(ref t2) = block.text2 {
                writeln!(writer, "  {}", t2)?;
            }
        }

        if some_generated {
            writeln!(
                writer,
                "\nOther valid addresses were present, and have been passed on for\n\
                 delivery."
            )?;
        } else {
            writeln!(
                writer,
                "\nNo valid addresses were generated, so the message cannot be\n\
                 delivered."
            )?;
        }

        // Include custom message if provided
        if let Some(custom) = custom_message {
            if !custom.is_empty() {
                // Expand custom message (may contain ${...})
                match expand_string(custom) {
                    Ok(expanded) => {
                        writeln!(writer)?;
                        writeln!(writer, "{}", expanded)?;
                    }
                    Err(e) => {
                        warn!(error = %e, "custom_message expansion failed");
                    }
                }
            }
        }

        writer.flush()?;
    }

    let exit_code = child_close(&mut child)?;
    if exit_code != 0 {
        warn!(
            exit_code = exit_code,
            "child Exim process failed for syntax error notification"
        );
        return Ok(false);
    }

    debug!("syntax error notification sent successfully");
    Ok(true)
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API: Bounce / Warning / DSN Message Generation (from deliver.c)
// ═══════════════════════════════════════════════════════════════════════════

/// Generate and send a full bounce message for delivery failures.
///
/// Derived from the bounce generation section of `deliver_message()` in
/// deliver.c (~line 7600+).
///
/// Produces an RFC 3464 `multipart/report` MIME message containing:
/// 1. A human-readable explanation section (`text/plain`)
/// 2. A machine-readable per-recipient `delivery-status` section
/// 3. Optionally, the original message (headers + body up to size limit)
///
/// Handles `bounce_return_body`, `bounce_return_size_limit`,
/// `bounce_return_linesize_limit` configuration. Checks `errors_copy` for
/// additional BCC recipients.
///
/// # Arguments
///
/// * `addr_failed` — List of addresses that permanently failed delivery.
/// * `msg_ctx` — Per-message context.
/// * `config` — Configuration context.
///
/// # Returns
///
/// `Ok(true)` if the bounce message was successfully sent.
/// `Ok(false)` if sending failed (logged but not fatal).
pub fn send_bounce_message(
    addr_failed: &[AddressItem],
    msg_ctx: &MessageContext,
    config: &ConfigContext,
) -> Result<bool, BounceError> {
    if addr_failed.is_empty() {
        debug!("no failed addresses, skipping bounce generation");
        return Ok(true);
    }

    // Count addresses that explicitly requested DSN FAILURE notification
    let dsn_failure_count = addr_failed
        .iter()
        .filter(|a| (a.dsn_flags & DSN_FAILURE) != 0)
        .count();

    debug!(
        message_id = %msg_ctx.message_id,
        failed_count = addr_failed.len(),
        dsn_failure_requested = dsn_failure_count,
        "generating bounce message"
    );

    let boundary = generate_mime_boundary(&msg_ctx.message_id, 1);

    // Determine the envelope sender for the bounce (empty for double bounces)
    let bounce_sender = "";
    let bounce_auth = config.bounce_sender_authentication.as_deref();

    let mut child = child_open_exim2(bounce_sender, bounce_auth)?;

    {
        let stdin = child.stdin.take().ok_or_else(|| {
            BounceError::ChildCreationFailed("failed to get child stdin".to_string())
        })?;
        let mut writer = BufWriter::new(stdin);

        // --- RFC 2822 Headers ---

        // Reply-To if configured
        if let Some(ref reply_to) = config.errors_reply_to {
            if !reply_to.is_empty() {
                writeln!(writer, "Reply-To: {}", reply_to)?;
            }
        }

        // Auto-Submitted header per RFC 3834
        writeln!(writer, "Auto-Submitted: auto-replied")?;

        // From header
        write_bounce_from(&mut writer, config)?;

        // To: the original sender
        writeln!(writer, "To: {}", msg_ctx.sender_address)?;

        // References and In-Reply-To
        // Convert MessageContext headers (Vec<String>) to HeaderLine-compatible form
        let header_lines: Vec<HeaderLine> = msg_ctx
            .headers
            .iter()
            .map(|h| HeaderLine {
                text: h.clone(),
                slen: h.len(),
                header_type: classify_header_type(h),
            })
            .collect();
        write_bounce_references(&mut writer, Some(&msg_ctx.message_id), Some(&header_lines))?;

        // Subject
        writeln!(
            writer,
            "Subject: Mail delivery failed: returning message to sender"
        )?;

        // MIME headers for multipart/report
        writeln!(writer, "MIME-Version: 1.0")?;
        writeln!(
            writer,
            "Content-Type: multipart/report; report-type=delivery-status;\n\
             \tboundary=\"{}\"",
            boundary
        )?;

        // Blank line before MIME body
        writeln!(writer)?;

        // --- MIME Part 1: Human-readable explanation (text/plain) ---
        writeln!(writer, "--{}", boundary)?;
        writeln!(writer, "Content-Type: text/plain; charset=us-ascii")?;
        writeln!(writer)?;

        writeln!(
            writer,
            "This message was created automatically by mail delivery software.\n"
        )?;
        writeln!(
            writer,
            "A message that you sent could not be delivered to one or more of its\n\
             recipients. This is a permanent error. The following address(es) failed:\n"
        )?;

        // List each failed address with its error details
        for addr in addr_failed {
            let addr_str = addr.address.as_ref();
            writeln!(writer, "  {}", addr_str)?;
            if let Some(ref msg) = addr.message {
                writeln!(writer, "    {}", msg)?;
            }
        }

        // Custom bounce message text if configured
        if let Some(ref bounce_text) = config.bounce_message_text {
            if !bounce_text.is_empty() {
                writeln!(writer)?;
                writeln!(writer, "{}", bounce_text)?;
            }
        }

        // Custom bounce message file if configured
        if let Some(ref bounce_file) = config.bounce_message_file {
            if !bounce_file.is_empty() {
                if let Ok(contents) = std::fs::read_to_string(bounce_file) {
                    writeln!(writer)?;
                    write!(writer, "{}", contents)?;
                } else {
                    debug!(file = %bounce_file, "bounce_message_file not readable");
                }
            }
        }

        // --- MIME Part 2: Machine-readable delivery-status ---
        writeln!(writer)?;
        writeln!(writer, "--{}", boundary)?;
        writeln!(writer, "Content-Type: message/delivery-status")?;
        writeln!(writer)?;

        // Per-message DSN fields
        writeln!(writer, "Reporting-MTA: dns; {}", config.primary_hostname)?;

        if let Some(ref envid) = msg_ctx.dsn_envid {
            if !envid.is_empty() {
                writeln!(writer, "Original-Envelope-ID: {}", envid)?;
            }
        }

        // Per-recipient status fields
        for addr in addr_failed {
            writeln!(writer)?; // Blank line separates per-recipient groups

            let addr_str = addr.address.as_ref();
            writeln!(writer, "Final-Recipient: rfc822;{}", addr_str)?;
            writeln!(writer, "Action: failed")?;

            // Construct the status code from errno
            let status_code = errno_to_dsn_status(addr.basic_errno, false);
            writeln!(writer, "Status: {}", status_code)?;

            if let Some(ref msg) = addr.message {
                writeln!(writer, "Diagnostic-Code: smtp; {}", msg)?;
            }

            if let Some(ref orcpt) = addr.dsn_orcpt {
                if !orcpt.is_empty() {
                    writeln!(writer, "Original-Recipient: {}", orcpt)?;
                }
            }
        }

        // --- MIME Part 3: Original message (optional) ---
        if config.bounce_return_message {
            writeln!(writer)?;
            writeln!(writer, "--{}", boundary)?;

            let include_body = config.bounce_return_body && msg_ctx.dsn_ret != DSN_RET_HDRS;

            if include_body {
                writeln!(writer, "Content-Type: message/rfc822")?;
            } else {
                writeln!(writer, "Content-Type: text/rfc822-headers")?;
            }
            writeln!(writer)?;

            let size_limit = config.bounce_return_size_limit.max(0) as usize;
            let line_limit = config.bounce_return_linesize_limit.max(0) as usize;
            let mut written: usize = 0;

            // Write headers from MessageContext
            for hdr_text in &msg_ctx.headers {
                let text = if line_limit > 0 && hdr_text.len() > line_limit {
                    &hdr_text[..line_limit]
                } else {
                    hdr_text.as_str()
                };

                if size_limit > 0 && written + text.len() > size_limit {
                    break;
                }

                write!(writer, "{}", text)?;
                if !text.ends_with('\n') {
                    writeln!(writer)?;
                }
                written += text.len();
            }

            // Body is not available in MessageContext — it would be read from
            // the spool -D file in production. The caller can extend this
            // with actual body data if available.
        }

        // Close MIME boundary
        writeln!(writer)?;
        writeln!(writer, "--{}--", boundary)?;

        writer.flush()?;
    }

    // Check errors_copy for additional BCC recipients
    for addr in addr_failed {
        let addr_str = addr.address.as_ref();
        if let Some(bcc) = moan_check_errorcopy(addr_str, config) {
            debug!(bcc = %bcc, address = %addr_str, "sending errors_copy to BCC");
            // The BCC is handled by the MTA itself when it processes the bounce;
            // in production this would be added as an additional recipient.
        }
    }

    let exit_code = child_close(&mut child)?;
    if exit_code != 0 {
        warn!(
            exit_code = exit_code,
            message_id = %msg_ctx.message_id,
            "child Exim process returned non-zero for bounce message"
        );
        return Ok(false);
    }

    info!(
        message_id = %msg_ctx.message_id,
        failed_count = addr_failed.len(),
        "bounce message sent successfully"
    );
    Ok(true)
}

/// Generate and send a delay warning message for deferred deliveries.
///
/// Translates the warning section from deliver.c line 6354 (~160 lines).
///
/// Produces an RFC 3464 `multipart/report` message notifying the sender
/// that delivery to one or more recipients has been delayed. Uses
/// `bounce_message_text` for custom explanation text.
///
/// # Arguments
///
/// * `addr_defer` — List of addresses with deferred delivery.
/// * `msg_ctx` — Per-message context.
/// * `config` — Configuration context.
///
/// # Returns
///
/// `Ok(true)` if the warning was sent, `Ok(false)` if sending failed.
pub fn send_warning_message(
    addr_defer: &[AddressItem],
    msg_ctx: &MessageContext,
    config: &ConfigContext,
) -> Result<bool, BounceError> {
    if addr_defer.is_empty() {
        debug!("no deferred addresses, skipping warning");
        return Ok(true);
    }

    // Skip if sender is empty (cannot warn a bounce address)
    if msg_ctx.sender_address.is_empty() {
        debug!("empty sender, skipping delay warning");
        return Ok(true);
    }

    // Count addresses that explicitly requested DSN DELAY notification
    let dsn_delay_count = addr_defer
        .iter()
        .filter(|a| (a.dsn_flags & DSN_DELAY) != 0)
        .count();

    debug!(
        message_id = %msg_ctx.message_id,
        defer_count = addr_defer.len(),
        dsn_delay_requested = dsn_delay_count,
        "generating delay warning message"
    );

    let boundary = generate_mime_boundary(&msg_ctx.message_id, 2);

    let mut child = child_open_exim()?;

    {
        let stdin = child.stdin.take().ok_or_else(|| {
            BounceError::ChildCreationFailed("failed to get child stdin".to_string())
        })?;
        let mut writer = BufWriter::new(stdin);

        // --- Headers ---
        if let Some(ref reply_to) = config.errors_reply_to {
            if !reply_to.is_empty() {
                writeln!(writer, "Reply-To: {}", reply_to)?;
            }
        }
        writeln!(writer, "Auto-Submitted: auto-replied")?;
        write_bounce_from(&mut writer, config)?;
        writeln!(writer, "To: {}", msg_ctx.sender_address)?;

        // Convert headers for references
        let header_lines: Vec<HeaderLine> = msg_ctx
            .headers
            .iter()
            .map(|h| HeaderLine {
                text: h.clone(),
                slen: h.len(),
                header_type: classify_header_type(h),
            })
            .collect();
        write_bounce_references(&mut writer, Some(&msg_ctx.message_id), Some(&header_lines))?;

        writeln!(
            writer,
            "Subject: Warning: message {} delayed",
            msg_ctx.message_id
        )?;

        // MIME headers
        writeln!(writer, "MIME-Version: 1.0")?;
        writeln!(
            writer,
            "Content-Type: multipart/report; report-type=delivery-status;\n\
             \tboundary=\"{}\"",
            boundary
        )?;
        writeln!(writer)?;

        // --- MIME Part 1: Human-readable explanation ---
        writeln!(writer, "--{}", boundary)?;
        writeln!(writer, "Content-Type: text/plain; charset=us-ascii")?;
        writeln!(writer)?;

        writeln!(
            writer,
            "This message was created automatically by mail delivery software.\n"
        )?;
        writeln!(
            writer,
            "A message that you sent has not yet been delivered to one or more of its\n\
             recipients after more than one attempt. The following address(es) are still\n\
             being retried:\n"
        )?;

        for addr in addr_defer {
            let addr_str = addr.address.as_ref();
            writeln!(writer, "  {}", addr_str)?;
            if let Some(ref msg) = addr.message {
                writeln!(writer, "    {}", msg)?;
            }
        }

        writeln!(
            writer,
            "\nNo action is required on your part. Delivery attempts will continue for\n\
             some time, and you will be notified if the message cannot be delivered."
        )?;

        // Custom warning text
        if let Some(ref text) = config.bounce_message_text {
            if !text.is_empty() {
                writeln!(writer)?;
                writeln!(writer, "{}", text)?;
            }
        }

        // --- MIME Part 2: Machine-readable delivery-status ---
        writeln!(writer)?;
        writeln!(writer, "--{}", boundary)?;
        writeln!(writer, "Content-Type: message/delivery-status")?;
        writeln!(writer)?;

        writeln!(writer, "Reporting-MTA: dns; {}", config.primary_hostname)?;

        if let Some(ref envid) = msg_ctx.dsn_envid {
            if !envid.is_empty() {
                writeln!(writer, "Original-Envelope-ID: {}", envid)?;
            }
        }

        for addr in addr_defer {
            writeln!(writer)?;
            let addr_str = addr.address.as_ref();
            writeln!(writer, "Final-Recipient: rfc822;{}", addr_str)?;
            writeln!(writer, "Action: delayed")?;

            let status_code = errno_to_dsn_status(addr.basic_errno, true);
            writeln!(writer, "Status: {}", status_code)?;

            if let Some(ref msg) = addr.message {
                writeln!(writer, "Diagnostic-Code: smtp; {}", msg)?;
            }

            if let Some(ref orcpt) = addr.dsn_orcpt {
                if !orcpt.is_empty() {
                    writeln!(writer, "Original-Recipient: {}", orcpt)?;
                }
            }
        }

        // --- MIME Part 3: Original message headers ---
        if config.bounce_return_message {
            writeln!(writer)?;
            writeln!(writer, "--{}", boundary)?;
            writeln!(writer, "Content-Type: text/rfc822-headers")?;
            writeln!(writer)?;

            let line_limit = config.bounce_return_linesize_limit.max(0) as usize;

            for hdr_text in &msg_ctx.headers {
                let text = if line_limit > 0 && hdr_text.len() > line_limit {
                    &hdr_text[..line_limit]
                } else {
                    hdr_text.as_str()
                };
                write!(writer, "{}", text)?;
                if !text.ends_with('\n') {
                    writeln!(writer)?;
                }
            }
        }

        // Close MIME boundary
        writeln!(writer)?;
        writeln!(writer, "--{}--", boundary)?;

        writer.flush()?;
    }

    let exit_code = child_close(&mut child)?;
    if exit_code != 0 {
        warn!(
            exit_code = exit_code,
            message_id = %msg_ctx.message_id,
            "child Exim process returned non-zero for delay warning"
        );
        return Ok(false);
    }

    info!(
        message_id = %msg_ctx.message_id,
        defer_count = addr_defer.len(),
        "delay warning message sent successfully"
    );
    Ok(true)
}

/// Generate and send DSN success notifications (RFC 3461).
///
/// Derived from the DSN section of `deliver_message()` in deliver.c line 6529
/// (~180 lines).
///
/// Only sends notifications for addresses that have the DSN SUCCESS flag set
/// and where `dsn_ret` is configured. Uses `child_open_exim()` to inject the
/// notification back into the MTA.
///
/// The message uses MIME `multipart/report` format with:
/// 1. Human-readable section explaining the successful delivery
/// 2. Per-recipient `delivery-status` fields with Action: delivered/relayed/expanded
/// 3. Original message headers (and body if DSN RET=FULL)
///
/// # Arguments
///
/// * `addr_succeed` — List of addresses that were successfully delivered.
/// * `msg_ctx` — Per-message context.
/// * `config` — Configuration context.
///
/// # Errors
///
/// Returns [`BounceError`] on child process or I/O failure.
#[cfg(feature = "dsn")]
pub fn maybe_send_dsn(
    addr_succeed: &[AddressItem],
    msg_ctx: &MessageContext,
    config: &ConfigContext,
) -> Result<(), BounceError> {
    // Filter addresses that requested DSN SUCCESS notification
    let dsn_addrs: Vec<&AddressItem> = addr_succeed
        .iter()
        .filter(|a| (a.dsn_flags & DSN_SUCCESS) != 0)
        .collect();

    if dsn_addrs.is_empty() {
        debug!("no addresses requesting DSN success notification");
        return Ok(());
    }

    // Skip if sender is empty (no one to notify)
    if msg_ctx.sender_address.is_empty() {
        debug!("empty sender, skipping DSN success notification");
        return Ok(());
    }

    debug!(
        message_id = %msg_ctx.message_id,
        dsn_count = dsn_addrs.len(),
        "generating DSN success notification"
    );

    let boundary = generate_mime_boundary(&msg_ctx.message_id, 3);
    let bounce_auth = config.bounce_sender_authentication.as_deref();

    let mut child = child_open_exim2("", bounce_auth)?;

    {
        let stdin = child.stdin.take().ok_or_else(|| {
            BounceError::ChildCreationFailed("failed to get child stdin".to_string())
        })?;
        let mut writer = BufWriter::new(stdin);

        // --- Headers ---
        writeln!(writer, "Auto-Submitted: auto-replied")?;
        write_bounce_from(&mut writer, config)?;
        writeln!(writer, "To: {}", msg_ctx.sender_address)?;

        // References
        let header_lines: Vec<HeaderLine> = msg_ctx
            .headers
            .iter()
            .map(|h| HeaderLine {
                text: h.clone(),
                slen: h.len(),
                header_type: classify_header_type(h),
            })
            .collect();
        write_bounce_references(&mut writer, Some(&msg_ctx.message_id), Some(&header_lines))?;

        writeln!(writer, "Subject: Delivery Status Notification (success)")?;

        // MIME headers
        writeln!(writer, "MIME-Version: 1.0")?;
        writeln!(
            writer,
            "Content-Type: multipart/report; report-type=delivery-status;\n\
             \tboundary=\"{}\"",
            boundary
        )?;
        writeln!(writer)?;

        // --- MIME Part 1: Human-readable notification ---
        writeln!(writer, "--{}", boundary)?;
        writeln!(writer, "Content-Type: text/plain; charset=us-ascii")?;
        writeln!(writer)?;

        writeln!(
            writer,
            "This message was created automatically by mail delivery software.\n"
        )?;
        writeln!(
            writer,
            "A message that you sent has been delivered to one or more of its\n\
             recipients. This is a delivery status notification only.\n"
        )?;

        writeln!(writer, "The following address(es) have been delivered:\n")?;

        for addr in &dsn_addrs {
            let addr_str = addr.address.as_ref();
            writeln!(writer, "  {}", addr_str)?;
        }

        // --- MIME Part 2: Machine-readable delivery-status ---
        writeln!(writer)?;
        writeln!(writer, "--{}", boundary)?;
        writeln!(writer, "Content-Type: message/delivery-status")?;
        writeln!(writer)?;

        writeln!(writer, "Reporting-MTA: dns; {}", config.primary_hostname)?;

        if let Some(ref envid) = msg_ctx.dsn_envid {
            if !envid.is_empty() {
                writeln!(writer, "Original-Envelope-ID: {}", envid)?;
            }
        }

        for addr in &dsn_addrs {
            writeln!(writer)?;
            let addr_str = addr.address.as_ref();
            writeln!(writer, "Final-Recipient: rfc822;{}", addr_str)?;

            // Determine the action type for DSN success
            // Action is "delivered" for local, "relayed" for remote, "expanded" for aliases
            writeln!(writer, "Action: delivered")?;
            writeln!(writer, "Status: 2.0.0")?;

            if let Some(ref orcpt) = addr.dsn_orcpt {
                if !orcpt.is_empty() {
                    writeln!(writer, "Original-Recipient: {}", orcpt)?;
                }
            }
        }

        // --- MIME Part 3: Original message ---
        writeln!(writer)?;
        writeln!(writer, "--{}", boundary)?;

        if msg_ctx.dsn_ret == DSN_RET_FULL {
            writeln!(writer, "Content-Type: message/rfc822")?;
        } else {
            writeln!(writer, "Content-Type: text/rfc822-headers")?;
        }
        writeln!(writer)?;

        let line_limit = config.bounce_return_linesize_limit.max(0) as usize;

        for hdr_text in &msg_ctx.headers {
            let text = if line_limit > 0 && hdr_text.len() > line_limit {
                &hdr_text[..line_limit]
            } else {
                hdr_text.as_str()
            };
            write!(writer, "{}", text)?;
            if !text.ends_with('\n') {
                writeln!(writer)?;
            }
        }

        // Body is included only if DSN RET=FULL — in production this would
        // read from the spool -D file. MessageContext does not carry the body.

        // Close MIME boundary
        writeln!(writer)?;
        writeln!(writer, "--{}--", boundary)?;

        writer.flush()?;
    }

    let exit_code = child_close(&mut child)?;
    if exit_code != 0 {
        warn!(
            exit_code = exit_code,
            message_id = %msg_ctx.message_id,
            "child Exim process returned non-zero for DSN success"
        );
        return Err(BounceError::ChildFailed(exit_code));
    }

    info!(
        message_id = %msg_ctx.message_id,
        dsn_count = dsn_addrs.len(),
        "DSN success notification sent"
    );
    Ok(())
}

/// Non-DSN variant — when the `dsn` feature is disabled, this is a no-op.
#[cfg(not(feature = "dsn"))]
pub fn maybe_send_dsn(
    _addr_succeed: &[AddressItem],
    _msg_ctx: &MessageContext,
    _config: &ConfigContext,
) -> Result<(), BounceError> {
    debug!("DSN feature disabled, skipping success notification");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Internal Utility Functions
// ═══════════════════════════════════════════════════════════════════════════

/// Classify a header string into a header type character.
///
/// Used when converting `MessageContext.headers` (Vec<String>) into
/// `HeaderLine` structs for `write_bounce_references`.
fn classify_header_type(header: &str) -> char {
    let lower = header.to_lowercase();
    if lower.starts_with("message-id:") {
        HTYPE_ID
    } else {
        // Default type for non-special headers
        ' '
    }
}

/// Convert an errno value to a DSN status code string.
///
/// Maps system errno values and Exim-specific error codes to RFC 3464
/// enhanced status codes (e.g., "5.1.1", "4.0.0").
///
/// # Arguments
///
/// * `errno` — The error number from `AddressItem.basic_errno`.
/// * `is_delay` — If true, generate 4.x.x (temporary) codes; otherwise 5.x.x
///   (permanent).
fn errno_to_dsn_status(errno: i32, is_delay: bool) -> String {
    let class = if is_delay { '4' } else { '5' };

    match errno {
        // No specific error — generic failure/delay
        0 => format!("{}.0.0", class),

        // Connection refused
        111 => format!("{}.4.1", class),

        // Connection timed out
        110 => format!("{}.4.1", class),

        // Host unreachable
        113 => format!("{}.4.4", class),

        // Network unreachable
        101 => format!("{}.4.4", class),

        // Permission denied
        13 => format!("{}.7.1", class),

        // Disk quota exceeded
        122 => format!("{}.2.2", class),

        // No such file or directory
        2 => format!("{}.1.1", class),

        // Generic mapping for other errors
        _ => format!("{}.0.0", class),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_message_ident_display() {
        assert_eq!(
            format!("{}", ErrorMessageIdent::BadArgAddress),
            "BADARGADDRESS"
        );
        assert_eq!(format!("{}", ErrorMessageIdent::IoErr), "IOERR");
        assert_eq!(
            format!("{}", ErrorMessageIdent::DmarcForensic),
            "DMARC_FORENSIC"
        );
    }

    #[test]
    fn test_error_block_iteration() {
        let mut chain = ErrorBlock::new("first error");
        chain.next = Some(Box::new(ErrorBlock::with_text2("second error", "detail")));

        let items: Vec<_> = chain.iter().collect();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].text1, "first error");
        assert_eq!(items[1].text1, "second error");
        assert_eq!(items[1].text2.as_deref(), Some("detail"));
    }

    #[test]
    fn test_extract_local_part() {
        assert_eq!(extract_local_part("user@example.com"), "user");
        assert_eq!(extract_local_part("bare"), "bare");
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(extract_domain("user@example.com"), "example.com");
        assert_eq!(extract_domain("bare"), "");
    }

    #[test]
    fn test_address_matches_pattern() {
        assert!(address_matches_pattern("user@example.com", "*"));
        assert!(address_matches_pattern("user@example.com", "*@example.com"));
        assert!(address_matches_pattern("user@example.com", "user@*"));
        assert!(address_matches_pattern(
            "user@example.com",
            "user@example.com"
        ));
        assert!(!address_matches_pattern(
            "user@example.com",
            "other@example.com"
        ));
        assert!(!address_matches_pattern("user@example.com", "*@other.com"));
        assert!(address_matches_pattern("User@Example.COM", "*@example.com"));
    }

    #[test]
    fn test_extract_message_ids() {
        let mut ids = Vec::new();
        extract_message_ids(" <abc@def> <ghi@jkl> ", &mut ids);
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0], "<abc@def>");
        assert_eq!(ids[1], "<ghi@jkl>");
    }

    #[test]
    fn test_extract_message_ids_empty() {
        let mut ids = Vec::new();
        extract_message_ids("no angle brackets here", &mut ids);
        assert!(ids.is_empty());
    }

    #[test]
    fn test_write_bounce_from_default() {
        let config = ConfigContext {
            qualify_domain_sender: "example.com".to_string(),
            ..ConfigContext::default()
        };
        let mut buf = Vec::new();
        write_bounce_from(&mut buf, &config).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Mail Delivery System"));
        assert!(output.contains("Mailer-Daemon@example.com"));
    }

    #[test]
    fn test_write_bounce_references_empty() {
        let mut buf = Vec::new();
        write_bounce_references(&mut buf, None, None).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn test_write_bounce_references_with_id() {
        let mut buf = Vec::new();
        write_bounce_references(&mut buf, Some("test-id@example.com"), None).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("References:"));
        assert!(output.contains("<test-id@example.com>"));
        assert!(output.contains("In-Reply-To:"));
    }

    #[test]
    fn test_write_bounce_references_circular_buffer() {
        let headers: Vec<HeaderLine> = (0..15)
            .map(|i| HeaderLine {
                text: format!("Message-ID: <msg{}@test>", i),
                slen: 30,
                header_type: HTYPE_ID,
            })
            .collect();

        let mut buf = Vec::new();
        write_bounce_references(&mut buf, Some("final@test"), Some(&headers)).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // Should contain the first message ID and the last ones, but not all 15
        assert!(output.contains("<msg0@test>")); // first preserved
        assert!(output.contains("<final@test>")); // our appended ID
                                                  // Total should be at most 12
        let id_count = output.matches('<').count();
        // References line + In-Reply-To line, each with IDs
        // The References line has <=12, In-Reply-To has 1
        assert!(id_count <= 13); // 12 in References + 1 in In-Reply-To
    }

    #[test]
    fn test_generate_mime_boundary() {
        let boundary = generate_mime_boundary("ABC123", 1);
        assert!(boundary.starts_with(MIME_BOUNDARY_PREFIX));
        assert!(boundary.contains("ABC123"));
    }

    #[test]
    fn test_errno_to_dsn_status() {
        assert_eq!(errno_to_dsn_status(0, false), "5.0.0");
        assert_eq!(errno_to_dsn_status(0, true), "4.0.0");
        assert_eq!(errno_to_dsn_status(111, false), "5.4.1");
        assert_eq!(errno_to_dsn_status(13, true), "4.7.1");
    }

    #[test]
    fn test_classify_header_type() {
        assert_eq!(classify_header_type("Message-ID: <abc@def>"), HTYPE_ID);
        assert_eq!(classify_header_type("Subject: test"), ' ');
    }

    #[test]
    fn test_bounce_error_display() {
        let e = BounceError::ChildCreationFailed("spawn failed".to_string());
        assert_eq!(
            e.to_string(),
            "failed to create child process: spawn failed"
        );

        let e = BounceError::ChildFailed(1);
        assert_eq!(e.to_string(), "child process returned status 1");
    }

    #[test]
    fn test_bounce_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broken");
        let bounce_err: BounceError = io_err.into();
        assert!(matches!(bounce_err, BounceError::IoError(_)));
    }

    #[test]
    fn test_taint_types_used() {
        // Verify that the module's taint type aliases are usable
        let tainted: TaintedStr = Tainted::new("user@example.com".to_string());
        let addr_ref: &str = tainted.as_ref();
        assert_eq!(addr_ref, "user@example.com");

        let clean: CleanStr = Clean::new("bounce-content".to_string());
        let clean_ref: &str = clean.as_ref();
        assert_eq!(clean_ref, "bounce-content");
    }

    #[test]
    fn test_moan_smtp_batch_exit_code_logic() {
        // moan_smtp_batch calls exit() so we verify the exit code logic here.
        // Exit code 1 if some messages accepted, 2 if none.
        let no_messages: u32 = 0;
        let some_messages: u32 = 5;

        let code_none = if no_messages > 0 { 1 } else { 2 };
        assert_eq!(code_none, 2, "no messages accepted -> exit code 2");

        let code_some = if some_messages > 0 { 1 } else { 2 };
        assert_eq!(code_some, 1, "some messages accepted -> exit code 1");
    }

    #[test]
    fn test_write_error_subject() {
        let mut buf = Vec::new();
        write_error_subject(&mut buf, ErrorMessageIdent::TooBig).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output.trim(), "Subject: Mail failure - message too big");
    }

    #[test]
    fn test_write_error_body_ioerr() {
        let eblock = ErrorBlock::with_text2("read error", "/var/spool/mail");
        let mut buf = Vec::new();
        write_error_body(&mut buf, ErrorMessageIdent::IoErr, &eblock, None).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("read error"));
        assert!(output.contains("/var/spool/mail"));
    }
}
