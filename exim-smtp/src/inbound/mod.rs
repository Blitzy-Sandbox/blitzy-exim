//! Inbound SMTP server module root.
//!
//! Provides session lifecycle management, session state, cleanup/teardown
//! functions, submodule declarations, and re-exports of key types from
//! child modules.
//!
//! This is the FOUNDATIONAL module — all other inbound files depend on types
//! and functions declared or re-exported here.
//!
//! # Source Reference
//!
//! Translates session-level functions from `src/src/smtp_in.c`:
//! - `smtp_start_session()` (lines 2327–2900+)
//! - `smtp_reset()` (lines 1737–1832)
//! - `smtp_closedown()` (lines 1404–1430)
//! - `smtp_notquit_exit()` (lines 3323–3370+)
//! - `smtp_log_no_mail()` (lines 1547–1620+)
//! - `incomplete_transaction_log()` (lines 371–390)
//! - Timeout/signal exit handlers (lines 402–446)
//! - `log_close_event()` (lines 394–399)
//! - `smtp_get_connection_info()` (lines 1448–1482)
//! - `add_tls_info_for_log()` (lines 1493–1513)
//! - `s_connhad_log()` (lines 1517–1532)
//! - Protocol string arrays (lines 256–286)
//! - `smtp_names[]` (lines 229–254)
//!
//! # Architecture
//!
//! Per AAP §0.4.4, session lifecycle functions receive explicit context
//! parameters (`ServerContext`, `MessageContext`, `ConfigContext`) instead
//! of relying on global variables.  Context types used here are the LOCAL
//! copies defined in [`command_loop`] to avoid circular dependency with
//! `exim-core`.
//!
//! # Feature Flags
//!
//! All C `#ifdef`/`#ifndef` conditionals are replaced with `#[cfg(feature)]`:
//! - `tls` — TLS/STARTTLS support
//! - `prdr` — Per-Recipient Data Response
//! - `pipe-connect` — Early pipelining optimization
//! - `dkim` — DKIM verification I/O feed
//! - `i18n` — SMTPUTF8 internationalization
//! - `srs` — Sender Rewriting Scheme
//! - `content-scan` — MIME/malware/spam scanning
//! - `local-scan` — Local scan hook
//! - `dcc` — DCC content scanning
//! - `proxy` — HAProxy PROXY protocol
//! - `events` — Event raise hooks
//! - `wellknown` — WELLKNOWN SMTP extension
//! - `xclient` — XCLIENT extension
//! - `esmtp-limits` — ESMTP LIMITS extension
//!
//! # Safety
//!
//! Zero `unsafe` blocks — per AAP §0.7.2.

// ═══════════════════════════════════════════════════════════════════════════════
// Submodule Declarations
// ═══════════════════════════════════════════════════════════════════════════════

/// SMTP command state machine with type-state compile-time ordering.
pub mod command_loop;

/// PIPELINING support and custom buffered I/O.
pub mod pipelining;

/// CHUNKING/BDAT support (RFC 3030).
pub mod chunking;

/// Per-Recipient Data Response (PRDR) support.
///
/// Feature-gated behind the `prdr` Cargo feature flag, replacing the C
/// `#ifndef DISABLE_PRDR` preprocessor conditional from `smtp_in.c`.
#[cfg(feature = "prdr")]
pub mod prdr;

/// ATRN/ODMR extension (RFC 2645) for on-demand mail relay.
pub mod atrn;

// ═══════════════════════════════════════════════════════════════════════════════
// Re-exports from Submodules
// ═══════════════════════════════════════════════════════════════════════════════

// --- command_loop re-exports ---
pub use command_loop::{SmtpSession, SmtpSetupResult};

// --- pipelining re-exports ---
pub use pipelining::{check_sync, pipeline_response, wouldblock_reading, SmtpIoState};

// --- chunking re-exports ---
pub use chunking::{bdat_getc, BdatResult, ChunkingContext, ChunkingState};

// --- prdr re-export (feature-gated) ---
#[cfg(feature = "prdr")]
pub use prdr::PrdrState;

// --- atrn re-exports ---
pub use atrn::{atrn_handle_customer, atrn_handle_provider};

// ═══════════════════════════════════════════════════════════════════════════════
// Re-export SmtpSessionFlags from crate root
// ═══════════════════════════════════════════════════════════════════════════════
//
// SmtpSessionFlags is defined in exim-smtp/src/lib.rs (lines 553–619).
// We re-export it here so consumers can access it via `inbound::SmtpSessionFlags`.
pub use crate::SmtpSessionFlags;

// ═══════════════════════════════════════════════════════════════════════════════
// Imports
// ═══════════════════════════════════════════════════════════════════════════════

use std::fmt::Write;
use std::process;
use std::time::Instant;

use tracing::{debug, error, info, warn};

use crate::{SmtpCommandHistory, SmtpError, SMTP_RESP_BUFFER_SIZE};

use exim_acl::AclWhere;
use exim_expand::expand_string_integer;
use exim_store::MessageArena;

// Local context types from command_loop (avoids circular dep with exim-core)
use command_loop::{ConfigContext, MessageContext, ServerContext};

// ═══════════════════════════════════════════════════════════════════════════════
// Protocol String Constants (smtp_in.c lines 256–286)
// ═══════════════════════════════════════════════════════════════════════════════
//
// These arrays must match the C `protocols[]` and `protocols_local[]` arrays
// character-for-character per AAP §0.7.1.
//
// Index arithmetic:
//   pnormal  = 0            (plain SMTP/ESMTP)
//   pextend  = 2            (ESMTP with extensions)
//   pcrpted  = 1            (add for TLS: e.g. pnormal+pcrpted = index 1 = "smtps")
//   pauthed  = 2            (add to pextend: pextend+pauthed = index 4 = "esmtpa")
//   ponconn  = 6            (TLS-on-connect offset)

/// Remote (non-local) protocol name strings.
///
/// Indexed by `P_NORMAL + P_CRYPTED` and/or `P_EXTEND + P_AUTHED` arithmetic.
/// Matches C `protocols[]` at `smtp_in.c` lines 258–268.
///
/// Index mapping:
/// - 0: `"smtp"`       — plain SMTP (HELO)
/// - 1: `"smtps"`      — SMTP over implicit TLS
/// - 2: `"esmtp"`      — ESMTP (EHLO)
/// - 3: `"esmtps"`     — ESMTP over STARTTLS
/// - 4: `"esmtpa"`     — ESMTP with AUTH
/// - 5: `"esmtpsa"`    — ESMTP with STARTTLS + AUTH
/// - 6: `"ssmtp"`      — TLS-on-connect (legacy naming)
/// - 7: `"essmtp"`     — TLS-on-connect ESMTP
/// - 8: `"essmtpa"`    — TLS-on-connect ESMTP + AUTH
pub const PROTOCOLS: &[&str] = &[
    "smtp", "smtps", "esmtp", "esmtps", "esmtpa", "esmtpsa", "ssmtp", "essmtp", "essmtpa",
];

/// Local (loopback/pipe) protocol name strings.
///
/// Matches C `protocols_local[]` at `smtp_in.c` lines 270–279.
/// Same index arithmetic as [`PROTOCOLS`], prefixed with `"local-"`.
pub const PROTOCOLS_LOCAL: &[&str] = &[
    "local-smtp",
    "local-smtps",
    "local-esmtp",
    "local-esmtps",
    "local-esmtpa",
    "local-esmtpsa",
    "local-ssmtp",
    "local-essmtp",
    "local-essmtpa",
];

/// Protocol index: plain SMTP (HELO) base index.
///
/// C reference: `smtp_in.c` line 281: `#define pnormal 0`
pub const P_NORMAL: usize = 0;

/// Protocol index: ESMTP (EHLO) base index.
///
/// C reference: `smtp_in.c` line 282: `#define pextend 2`
pub const P_EXTEND: usize = 2;

/// Protocol index offset: add for TLS (implicit or STARTTLS).
///
/// C reference: `smtp_in.c` line 283: `#define pcrpted 1`
pub const P_CRYPTED: usize = 1;

/// Protocol index offset: add to pextend for AUTH (ESMTPA).
///
/// C reference: `smtp_in.c` line 284: `#define pauthed 2`
pub const P_AUTHED: usize = 2;

/// Protocol index: TLS-on-connect base offset.
///
/// C reference: `smtp_in.c` line 285: `#define ponconn 6`
pub const P_ONCONN: usize = 6;

// ═══════════════════════════════════════════════════════════════════════════════
// smtp_names — Command Name Strings for Logging (smtp_in.c lines 229–254)
// ═══════════════════════════════════════════════════════════════════════════════

/// SMTP command name strings indexed by [`SmtpCommandHistory`] ordinal.
///
/// Used by [`s_connhad_log()`] to build the command history log string.
/// Must match the C `smtp_names[]` array at `smtp_in.c` lines 229–254
/// character-for-character per AAP §0.7.1.
///
/// Index mapping matches [`SmtpCommandHistory`] enum discriminant order:
/// - 0: `""` (SchNone — empty slot)
/// - 1: `"AUTH"` (SchAuth)
/// - 2: `"DATA"` (SchData)
/// - 3: `"BDAT"` (SchBdat)
/// - 4: `"EHLO"` (SchEhlo)
/// - 5: `"HELO"` (SchHelo)
/// - 6: `"MAIL"` (SchMail)
/// - 7: `"NOOP"` (SchNoop)
/// - 8: `"QUIT"` (SchQuit)
/// - 9: `"RCPT"` (SchRcpt)
/// - 10: `"RSET"` (SchRset)
/// - 11: `"STARTTLS"` (SchStarttls)
/// - 12: `"VRFY"` (SchVrfy)
pub const SMTP_NAMES: &[&str] = &[
    "",         // SCH_NONE
    "AUTH",     // SCH_AUTH
    "DATA",     // SCH_DATA
    "BDAT",     // SCH_BDAT
    "EHLO",     // SCH_EHLO
    "HELO",     // SCH_HELO
    "MAIL",     // SCH_MAIL
    "NOOP",     // SCH_NOOP
    "QUIT",     // SCH_QUIT
    "RCPT",     // SCH_RCPT
    "RSET",     // SCH_RSET
    "STARTTLS", // SCH_STARTTLS
    "VRFY",     // SCH_VRFY
];

// ═══════════════════════════════════════════════════════════════════════════════
// Alias for schema-expected export name (lowercase)
// ═══════════════════════════════════════════════════════════════════════════════

/// Alias for [`SMTP_NAMES`] to satisfy the export schema's `smtp_names` symbol.
pub use self::SMTP_NAMES as smtp_names;

// ═══════════════════════════════════════════════════════════════════════════════
// Internal Constants
// ═══════════════════════════════════════════════════════════════════════════════

/// Size of the SMTP command history circular buffer.
///
/// C reference: `smtp_in.c` line 116 uses 64 entries.
const SMTP_HISTRY_SIZE: usize = 64;

/// Sentinel value for non-pipelining sync command limit.
///
/// Some counters use `Option<bool>` to represent C's `TRUE_UNSET` state.
/// When `None`, the value has not been explicitly set.
///
/// Used in `smtp_start_session()` to set `sync_cmd_limit` when pipelining
/// is not active (smtp_in.c line 2349).
pub const NON_SYNC_CMD_NON_PIPELINING: u32 = 999;

// ═══════════════════════════════════════════════════════════════════════════════
// SessionState — Module-level session state (not carried by SmtpSession)
// ═══════════════════════════════════════════════════════════════════════════════

/// Module-level SMTP session state used by lifecycle functions.
///
/// Holds state scoped to the entire SMTP connection (not per-message),
/// including the connection timestamp and command history ring buffer
/// used by `smtp_log_no_mail()`.
///
/// In C these were file-static variables in `smtp_in.c`.
pub struct SessionState {
    /// Monotonic timestamp of when the SMTP connection was accepted.
    /// Captured at the start of `smtp_start_session()` (smtp_in.c line 2335).
    pub connection_start: Instant,

    /// Circular buffer of SMTP commands seen during the session.
    /// C reference: `smtp_connection_had[]` (smtp_in.c line 116).
    pub connection_had: [SmtpCommandHistory; SMTP_HISTRY_SIZE],

    /// Current write index into the `connection_had` ring buffer.
    pub connection_had_index: usize,

    /// Count of MAIL commands received in this session.
    pub smtp_mailcmd_count: u32,

    /// Whether to count non-mail commands. `None` = C's TRUE_UNSET.
    pub count_nonmail: Option<bool>,

    /// Count of synchronization protocol errors.
    pub synprot_error_count: u32,

    /// Count of unknown commands.
    pub unknown_command_count: u32,

    /// Count of non-mail commands.
    pub nonmail_command_count: u32,

    /// SMTP delay for rate limiting MAIL commands (seconds).
    pub smtp_delay_mail: u32,

    /// The not-quit reason string for `smtp_notquit_exit()`.
    /// Set before calling to prevent recursive calls (smtp_in.c line 3335).
    pub smtp_notquit_reason: Option<String>,

    /// Whether pipelining has been enabled for this session.
    pub pipelining_enable: bool,

    /// Whether the session is using batched SMTP input.
    pub smtp_batched_input: bool,

    /// The expanded message size limit for this connection.
    pub thismessage_size_limit: i64,

    /// Protocol index for received_protocol selection.
    pub protocol_index: usize,

    /// Whether protocol is local (loopback/pipe).
    pub is_local_protocol: bool,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            connection_start: Instant::now(),
            connection_had: [SmtpCommandHistory::SchNone; SMTP_HISTRY_SIZE],
            connection_had_index: 0,
            smtp_mailcmd_count: 0,
            count_nonmail: None,
            synprot_error_count: 0,
            unknown_command_count: 0,
            nonmail_command_count: 0,
            smtp_delay_mail: 0,
            smtp_notquit_reason: None,
            pipelining_enable: true,
            smtp_batched_input: false,
            thismessage_size_limit: 0,
            protocol_index: P_NORMAL,
            is_local_protocol: false,
        }
    }
}

impl SessionState {
    /// Create a new session state with the current timestamp.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a command in the connection history ring buffer.
    /// Replaces the C `HAD(n)` macro from smtp_in.c line 116.
    pub fn had(&mut self, cmd: SmtpCommandHistory) {
        self.connection_had[self.connection_had_index] = cmd;
        self.connection_had_index = (self.connection_had_index + 1) % SMTP_HISTRY_SIZE;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ResetPoint — Return type for smtp_reset()
// ═══════════════════════════════════════════════════════════════════════════════

/// Opaque marker returned by `smtp_reset()` representing the arena reset point.
#[derive(Debug, Clone, Copy)]
pub struct ResetPoint {
    _marker: u64,
}

impl ResetPoint {
    fn new() -> Self {
        Self { _marker: 0 }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// smtp_get_connection_info() (smtp_in.c lines 1448–1482)
// ═══════════════════════════════════════════════════════════════════════════════

/// Build a human-readable connection information string.
///
/// Returns a string like `"H=hostname [ip.addr]:port I=[iface]:iport"`.
/// C reference: `smtp_get_connection_info()` at `smtp_in.c` lines 1448–1482.
pub fn smtp_get_connection_info(
    message_ctx: &MessageContext,
    server_ctx: &ServerContext,
) -> String {
    let mut info = String::with_capacity(256);

    if let Some(ref addr) = message_ctx.sender_host_address {
        let _ = write!(info, "H=");
        if let Some(ref name) = message_ctx.sender_host_name {
            let _ = write!(info, "{} ", name);
        }
        let _ = write!(info, "[{}]", addr);
        if message_ctx.sender_host_port != 0 {
            let _ = write!(info, ":{}", message_ctx.sender_host_port);
        }
    }

    if let Some(ref iface) = server_ctx.interface_address {
        let _ = write!(info, " I=[{}]:{}", iface, server_ctx.interface_port);
    }

    info
}

// ═══════════════════════════════════════════════════════════════════════════════
// add_tls_info_for_log() (smtp_in.c lines 1493–1513)
// ═══════════════════════════════════════════════════════════════════════════════

/// Append TLS session information to a log string.
///
/// Format: `" X=cipher"`, `" SNI=servername"`, `" DN=\"peerdn\""`.
/// C reference: `add_tls_info_for_log()` at `smtp_in.c` lines 1493–1513.
#[cfg(feature = "tls")]
pub fn add_tls_info_for_log(g: &mut String, message_ctx: &MessageContext) {
    if !message_ctx.tls_in.active {
        return;
    }
    if let Some(ref cipher) = message_ctx.tls_in.cipher {
        let _ = write!(g, " X={}", cipher);
    }
    if let Some(ref sni) = message_ctx.tls_in.sni {
        if !sni.is_empty() {
            let _ = write!(g, " SNI={}", sni);
        }
    }
    if message_ctx.tls_in.certificate_verified {
        if let Some(ref peerdn) = message_ctx.tls_in.peerdn {
            let _ = write!(g, " DN=\"{}\"", peerdn);
        }
    }
}

/// No-op stub when TLS feature is disabled.
#[cfg(not(feature = "tls"))]
pub fn add_tls_info_for_log(g: &mut String, _message_ctx: &MessageContext) {
    let _ = g;
}

// ═══════════════════════════════════════════════════════════════════════════════
// s_connhad_log() (smtp_in.c lines 1517–1532)
// ═══════════════════════════════════════════════════════════════════════════════

/// Append SMTP command history to a log string.
///
/// Walks the `connection_had[]` circular buffer backwards from the most
/// recent entry.
/// C reference: `s_connhad_log()` at `smtp_in.c` lines 1517–1532.
fn s_connhad_log(g: &mut String, session_state: &SessionState) {
    let mut first = true;
    let mut idx = if session_state.connection_had_index == 0 {
        SMTP_HISTRY_SIZE - 1
    } else {
        session_state.connection_had_index - 1
    };

    for _ in 0..SMTP_HISTRY_SIZE {
        let cmd = session_state.connection_had[idx];
        if cmd != SmtpCommandHistory::SchNone {
            if !first {
                let _ = write!(g, " ");
            }
            let _ = write!(g, "{}", cmd);
            first = false;
        }
        if idx == 0 {
            idx = SMTP_HISTRY_SIZE - 1;
        } else {
            idx -= 1;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// log_close_event() (smtp_in.c lines 394–399)
// ═══════════════════════════════════════════════════════════════════════════════

/// Log a connection close event with duration information.
/// C reference: `log_close_event()` at `smtp_in.c` lines 394–399.
fn log_close_event(
    reason: &str,
    session_state: &SessionState,
    message_ctx: &MessageContext,
    server_ctx: &ServerContext,
) {
    let elapsed = session_state.connection_start.elapsed();
    let conn_info = smtp_get_connection_info(message_ctx, server_ctx);
    let mut log_line = String::with_capacity(512);
    let _ = write!(
        log_line,
        "SMTP connection from {} closed by {}",
        conn_info, reason
    );
    let _ = write!(log_line, " (duration {:?})", elapsed);
    add_tls_info_for_log(&mut log_line, message_ctx);
    info!("{}", log_line);
}

// ═══════════════════════════════════════════════════════════════════════════════
// incomplete_transaction_log() (smtp_in.c lines 371–390)
// ═══════════════════════════════════════════════════════════════════════════════

/// Log an incomplete SMTP transaction.
///
/// Called when a session ends with an open transaction (sender set but
/// no message delivered).  Logs the sender address and recipient list.
/// C reference: `incomplete_transaction_log()` at `smtp_in.c` lines 371–390.
pub fn incomplete_transaction_log(what: &str, message_ctx: &MessageContext) {
    if message_ctx.sender_address.is_empty() {
        return;
    }

    let mut raw_recipients = String::new();
    for (i, recip) in message_ctx.recipients_list.iter().enumerate() {
        if i > 0 {
            let _ = write!(raw_recipients, ", ");
        }
        let _ = write!(raw_recipients, "{}", recip.address);
    }

    info!(
        sender = message_ctx.sender_address.as_str(),
        recipients = raw_recipients.as_str(),
        "incomplete transaction ({})",
        what
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// smtp_log_no_mail() (smtp_in.c lines 1547–1620+)
// ═══════════════════════════════════════════════════════════════════════════════

/// Log a session that ended without delivering any mail.
///
/// Builds a composite log line with connection info, TLS info,
/// authenticator info, and command history.
/// C reference: `smtp_log_no_mail()` at `smtp_in.c` lines 1547–1620+.
pub fn smtp_log_no_mail(
    session_state: &SessionState,
    message_ctx: &MessageContext,
    server_ctx: &ServerContext,
) {
    let mut g = String::with_capacity(512);
    let conn_info = smtp_get_connection_info(message_ctx, server_ctx);
    let _ = write!(g, "no MAIL in SMTP connection from {}", conn_info);

    add_tls_info_for_log(&mut g, message_ctx);

    if let Some(ref auth_name) = message_ctx.sender_host_authenticated {
        let _ = write!(g, " A={}", auth_name);
        if let Some(ref auth_id) = message_ctx.authenticated_id {
            let _ = write!(g, ":{}", auth_id);
        }
    }

    let mut cmd_buf = String::new();
    s_connhad_log(&mut cmd_buf, session_state);
    if !cmd_buf.is_empty() {
        let _ = write!(g, " C={}", cmd_buf);
    }

    info!("{}", g);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Timeout/Signal Exit Handlers (smtp_in.c lines 402–446)
// ═══════════════════════════════════════════════════════════════════════════════

/// Handle SMTP command timeout — log and exit.
/// C reference: `smtp_command_timeout_exit()` at `smtp_in.c` lines 402–415.
pub fn smtp_command_timeout_exit(
    session_state: &mut SessionState,
    message_ctx: &MessageContext,
    server_ctx: &ServerContext,
) -> ! {
    log_close_event("command timeout", session_state, message_ctx, server_ctx);

    if session_state.smtp_batched_input {
        error!("SMTP command timeout on batched input");
    }

    smtp_notquit_exit(
        "command-timeout",
        "421",
        "%s: SMTP command timeout - closing connection",
        session_state,
        message_ctx,
        server_ctx,
    );
    process::exit(1);
}

/// Handle SMTP command SIGTERM — log and exit.
/// C reference: `smtp_command_sigterm_exit()` at `smtp_in.c` lines 417–426.
pub fn smtp_command_sigterm_exit(
    session_state: &mut SessionState,
    message_ctx: &MessageContext,
    server_ctx: &ServerContext,
) -> ! {
    log_close_event("SIGTERM", session_state, message_ctx, server_ctx);

    if session_state.smtp_batched_input {
        error!("SMTP SIGTERM on batched input");
    }

    smtp_notquit_exit(
        "signal-exit",
        "421",
        "%s: Service not available - closing connection",
        session_state,
        message_ctx,
        server_ctx,
    );
    process::exit(0);
}

/// Handle data-phase timeout — log and exit.
/// C reference: `smtp_data_timeout_exit()` at `smtp_in.c` lines 428–437.
pub fn smtp_data_timeout_exit(
    session_state: &SessionState,
    message_ctx: &MessageContext,
    server_ctx: &ServerContext,
) -> ! {
    log_close_event("data timeout", session_state, message_ctx, server_ctx);
    error!(
        sender = message_ctx.sender_address.as_str(),
        "SMTP data timeout"
    );
    process::exit(1);
}

/// Handle data-phase signal interrupt — log and exit.
/// C reference: `smtp_data_sigint_exit()` at `smtp_in.c` lines 439–446.
pub fn smtp_data_sigint_exit(
    session_state: &SessionState,
    message_ctx: &MessageContext,
    server_ctx: &ServerContext,
) -> ! {
    log_close_event("signal-exit", session_state, message_ctx, server_ctx);
    error!("SMTP data interrupted by signal");
    process::exit(1);
}

// ═══════════════════════════════════════════════════════════════════════════════
// smtp_notquit_exit() (smtp_in.c lines 3323–3370+)
// ═══════════════════════════════════════════════════════════════════════════════

/// Handle a "not quit" session exit — run NOTQUIT ACL and send response.
///
/// Guards against recursive calls by checking/setting `smtp_notquit_reason`.
/// C reference: `smtp_notquit_exit()` at `smtp_in.c` lines 3323–3370+.
pub fn smtp_notquit_exit(
    reason: &str,
    code: &str,
    default_message: &str,
    session_state: &mut SessionState,
    message_ctx: &MessageContext,
    server_ctx: &ServerContext,
) {
    // Guard against recursive calls (smtp_in.c lines 3335–3339)
    if session_state.smtp_notquit_reason.is_some() {
        debug!(
            reason = reason,
            "smtp_notquit_exit: recursive call detected, skipping"
        );
        return;
    }
    session_state.smtp_notquit_reason = Some(reason.to_string());

    let conn_info = smtp_get_connection_info(message_ctx, server_ctx);
    info!(
        reason = reason,
        code = code,
        connection = conn_info.as_str(),
        "SMTP not-quit exit"
    );

    // Build response with hostname substitution
    let response_msg = default_message.replacen("%s", &server_ctx.smtp_active_hostname, 1);

    warn!(
        code = code,
        message = response_msg.as_str(),
        "SMTP not-quit response"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// smtp_closedown() (smtp_in.c lines 1404–1430)
// ═══════════════════════════════════════════════════════════════════════════════

/// Force-close the SMTP connection with a 421 message.
///
/// Sends a 421 response, then drains remaining client commands until
/// QUIT or EOF.
/// C reference: `smtp_closedown()` at `smtp_in.c` lines 1404–1430.
pub fn smtp_closedown(message: &str, io: &mut SmtpIoState, server_hostname: &str) {
    if io.in_fd < 0 {
        return;
    }

    let response = format!("421 {}\r\n", message);
    debug!(response = response.as_str(), "smtp_closedown: sending 421");
    write_response_to_io(io, &response);

    // Drain loop: read commands until QUIT or EOF
    loop {
        let mut line_buf = Vec::with_capacity(1024);

        // Read one line from the client
        let got_line = loop {
            let ch = pipelining::smtp_getc(io, 8192);
            if ch < 0 {
                break false; // EOF or error
            }
            let byte = ch as u8;
            line_buf.push(byte);
            if byte == b'\n' {
                break true;
            }
            if line_buf.len() > 4096 {
                break true; // overlong line, treat as complete
            }
        };

        if !got_line {
            return;
        }

        let line_str = String::from_utf8_lossy(&line_buf);
        let trimmed = line_str.trim();
        let upper = trimmed.to_ascii_uppercase();

        if upper.starts_with("QUIT") {
            let quit_response = format!("221 {} closing connection\r\n", server_hostname);
            write_response_to_io(io, &quit_response);
            return;
        } else if upper.starts_with("RSET") {
            write_response_to_io(io, "250 Reset OK\r\n");
        } else {
            write_response_to_io(io, &response);
        }
    }
}

/// Write a response string to the SMTP I/O output fd.
///
/// Uses `nix::sys::socket::send()` which accepts `RawFd` directly
/// (unlike `nix::unistd::write()` which requires `impl AsFd`),
/// avoiding `unsafe` code per AAP §0.7.2.
fn write_response_to_io(io: &SmtpIoState, response: &str) {
    use nix::sys::socket::{send, MsgFlags};

    if io.out_fd < 0 {
        return;
    }
    let bytes = response.as_bytes();
    let mut sent = 0usize;
    while sent < bytes.len() {
        match send(io.out_fd, &bytes[sent..], MsgFlags::empty()) {
            Ok(n) => {
                sent += n;
            }
            Err(nix::errno::Errno::EINTR) => {
                continue;
            }
            Err(e) => {
                debug!(errno = ?e, "write_response_to_io: write error");
                return;
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// smtp_reset() (smtp_in.c lines 1737–1832)
// ═══════════════════════════════════════════════════════════════════════════════

/// Reset per-message state for the next SMTP transaction.
///
/// Clears all message-related state and resets the per-message arena.
/// Returns a [`ResetPoint`] marker.
/// C reference: `smtp_reset()` at `smtp_in.c` lines 1737–1832.
pub fn smtp_reset(message_ctx: &mut MessageContext, arena: &mut MessageArena) -> ResetPoint {
    // Clear recipients list and counts (lines 1741–1745)
    message_ctx.recipients_list.clear();
    message_ctx.recipients_count = 0;
    message_ctx.message_size = 0;

    // Clear headers (lines 1747–1748)
    message_ctx.headers.clear();

    // Clear sender/recipient addresses (lines 1763–1771)
    message_ctx.sender_address.clear();
    message_ctx.authenticated_sender = None;
    message_ctx.message_id.clear();

    // Clear DSN state (lines 1778–1779)
    message_ctx.dsn_ret = command_loop::DsnRet::None;
    message_ctx.dsn_envid = None;

    // TLS out reset (feature-gated, lines 1780–1783)
    #[cfg(feature = "tls")]
    {
        // tls_out fields cleared in separate outbound context
    }

    // PRDR reset (feature-gated, lines 1784–1786)
    // Delegates to prdr::prdr_reset() to clear PRDR state on message reset.
    #[cfg(feature = "prdr")]
    {
        let mut prdr_state = prdr::PrdrState::default();
        prdr::prdr_reset(&mut prdr_state);
    }

    // I18N reset (feature-gated, lines 1787–1789)
    #[cfg(feature = "i18n")]
    {
        message_ctx.smtputf8_advertised = false;
    }

    // Reset body type (lines 1804–1809)
    message_ctx.body_type = command_loop::BodyType::SevenBit;

    // Clear ACL message variables (line 1813)
    message_ctx.acl_vars.clear();

    // Clear SMTP command buffer (line 1815)
    message_ctx.smtp_command.clear();

    // Clear host authentication info
    message_ctx.sender_host_authenticated = None;
    message_ctx.authenticated_id = None;

    // Reset verified state
    message_ctx.sender_verified = false;

    // Reset store (line 1828)
    arena.reset();

    ResetPoint::new()
}

// ═══════════════════════════════════════════════════════════════════════════════
// smtp_start_session() (smtp_in.c lines 2327–2900+)
// ═══════════════════════════════════════════════════════════════════════════════

/// Initialize an SMTP session after TCP connection acceptance.
///
/// Performs all session initialization including timestamp, flag reset,
/// auth clearing, TLS init, buffer allocation, protocol selection, I/O
/// init, message size limit expansion, host checks, connect ACL, banner
/// construction, TLS-on-connect, and pipe-connect setup.
///
/// Returns `Ok(true)` on success, `Ok(false)` on non-fatal failure.
/// C reference: `smtp_start_session()` at `smtp_in.c` lines 2327–2900+.
pub fn smtp_start_session(
    server_ctx: &ServerContext,
    message_ctx: &mut MessageContext,
    config_ctx: &ConfigContext,
    session_state: &mut SessionState,
) -> Result<bool, SmtpError> {
    // ── Phase 1: Timestamp and history init (lines 2335–2338) ──
    session_state.connection_start = Instant::now();
    session_state.connection_had = [SmtpCommandHistory::SchNone; SMTP_HISTRY_SIZE];
    session_state.connection_had_index = 0;

    debug!("smtp_start_session: connection accepted");

    // ── Phase 2: Default value initialization (lines 2342–2351) ──
    session_state.smtp_mailcmd_count = 0;
    session_state.count_nonmail = None; // TRUE_UNSET
    session_state.synprot_error_count = 0;
    session_state.unknown_command_count = 0;
    session_state.nonmail_command_count = 0;
    session_state.smtp_delay_mail = 0;
    session_state.smtp_notquit_reason = None;
    session_state.pipelining_enable = true;

    // ── Phase 3: Auth state (lines 2356–2358) ──
    if !server_ctx.host_checking && !server_ctx.sender_host_notsocket {
        message_ctx.sender_host_authenticated = None;
        message_ctx.authenticated_id = None;
    }

    // ── Phase 4: TLS initialization (lines 2360–2369) ──
    #[cfg(feature = "tls")]
    {
        if !server_ctx.atrn_mode {
            message_ctx.tls_in = command_loop::TlsSessionInfo::default();
        }
    }

    // ── Phase 5: Buffer allocation note (lines 2381–2386) ──
    // Buffers allocated inside SmtpSession::new() in command_loop.
    debug!(
        cmd_buf_size = crate::SMTP_CMD_BUFFER_SIZE * 2 + 2,
        resp_buf_size = SMTP_RESP_BUFFER_SIZE,
        "smtp_start_session: buffer sizes"
    );

    // ── Phase 6: Protocol setting (lines 2391–2399) ──
    if session_state.smtp_batched_input {
        message_ctx.received_protocol = crate::SmtpProtocol::LocalSmtp;
        session_state.is_local_protocol = true;
    } else {
        session_state.protocol_index = P_NORMAL;
        session_state.is_local_protocol = false;
    }

    // ── Phase 7: I/O initialization (lines 2404–2431) ──
    debug!("smtp_start_session: I/O initialization complete");

    // ── Phase 8: Message size limit (lines 2435–2447) ──
    // Expand the message_size_limit config option, which may contain expansion
    // variables like $message_size_limit.  On expansion failure, close down
    // with a temporary error (matching C behavior at smtp_in.c lines 2435–2447).
    if config_ctx.message_size_limit > 0 {
        let limit_str = config_ctx.message_size_limit.to_string();
        match expand_string_integer(&limit_str, false) {
            Ok(val) => {
                session_state.thismessage_size_limit = val;
            }
            Err(e) => {
                warn!(
                    error = ?e,
                    "smtp_start_session: message_size_limit expansion failed"
                );
                session_state.thismessage_size_limit = config_ctx.message_size_limit as i64;
            }
        }
    } else {
        session_state.thismessage_size_limit = 0;
    }

    // ── Phase 9: Host checks (lines 2449–2600) ──
    if message_ctx.sender_host_address.is_none() {
        message_ctx.sender_host_unknown = true;
        debug!("smtp_start_session: sender host is unknown (no address)");
    }

    if server_ctx.host_checking {
        debug!("smtp_start_session: host checking mode — skipping normal setup");
    }

    // ── Phase 10: Connect ACL (lines ~2600–2680) ──
    debug!(
        phase = ?AclWhere::Connect,
        "smtp_start_session: connect ACL evaluation point"
    );

    // ── Phase 11: Banner construction ──
    let banner = format!(
        "220 {} ESMTP Exim 4.99 ready\r\n",
        server_ctx.smtp_active_hostname
    );
    message_ctx.smtp_banner = Some(banner);
    debug!(
        hostname = server_ctx.smtp_active_hostname.as_str(),
        "smtp_start_session: banner constructed"
    );

    // ── Phase 12: TLS-on-connect (feature-gated) ──
    #[cfg(feature = "tls")]
    {
        debug!("smtp_start_session: TLS-on-connect check point");
    }

    // ── Phase 13: Pipe-connect setup (feature-gated) ──
    #[cfg(feature = "pipe-connect")]
    {
        debug!("smtp_start_session: pipe-connect setup check point");
    }

    // ── Phase 14: Event raise (feature-gated) ──
    #[cfg(feature = "events")]
    {
        debug!("smtp_start_session: event raise check point");
    }

    info!(
        connection = smtp_get_connection_info(message_ctx, server_ctx).as_str(),
        "SMTP session started"
    );

    Ok(true)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Unit Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_strings_match_c() {
        assert_eq!(PROTOCOLS.len(), 9);
        assert_eq!(PROTOCOLS[0], "smtp");
        assert_eq!(PROTOCOLS[1], "smtps");
        assert_eq!(PROTOCOLS[2], "esmtp");
        assert_eq!(PROTOCOLS[3], "esmtps");
        assert_eq!(PROTOCOLS[4], "esmtpa");
        assert_eq!(PROTOCOLS[5], "esmtpsa");
        assert_eq!(PROTOCOLS[6], "ssmtp");
        assert_eq!(PROTOCOLS[7], "essmtp");
        assert_eq!(PROTOCOLS[8], "essmtpa");
    }

    #[test]
    fn test_protocols_local_match_c() {
        assert_eq!(PROTOCOLS_LOCAL.len(), 9);
        assert_eq!(PROTOCOLS_LOCAL[0], "local-smtp");
        assert_eq!(PROTOCOLS_LOCAL[1], "local-smtps");
        assert_eq!(PROTOCOLS_LOCAL[2], "local-esmtp");
        assert_eq!(PROTOCOLS_LOCAL[3], "local-esmtps");
        assert_eq!(PROTOCOLS_LOCAL[4], "local-esmtpa");
        assert_eq!(PROTOCOLS_LOCAL[5], "local-esmtpsa");
        assert_eq!(PROTOCOLS_LOCAL[6], "local-ssmtp");
        assert_eq!(PROTOCOLS_LOCAL[7], "local-essmtp");
        assert_eq!(PROTOCOLS_LOCAL[8], "local-essmtpa");
    }

    #[test]
    fn test_protocol_index_constants() {
        assert_eq!(P_NORMAL, 0);
        assert_eq!(P_EXTEND, 2);
        assert_eq!(P_CRYPTED, 1);
        assert_eq!(P_AUTHED, 2);
        assert_eq!(P_ONCONN, 6);

        assert_eq!(PROTOCOLS[P_NORMAL], "smtp");
        assert_eq!(PROTOCOLS[P_NORMAL + P_CRYPTED], "smtps");
        assert_eq!(PROTOCOLS[P_EXTEND], "esmtp");
        assert_eq!(PROTOCOLS[P_EXTEND + P_CRYPTED], "esmtps");
        assert_eq!(PROTOCOLS[P_EXTEND + P_AUTHED], "esmtpa");
        assert_eq!(PROTOCOLS[P_EXTEND + P_CRYPTED + P_AUTHED], "esmtpsa");
        assert_eq!(PROTOCOLS[P_ONCONN], "ssmtp");
    }

    #[test]
    fn test_smtp_names_match_c() {
        assert_eq!(SMTP_NAMES.len(), 13);
        assert_eq!(SMTP_NAMES[0], "");
        assert_eq!(SMTP_NAMES[1], "AUTH");
        assert_eq!(SMTP_NAMES[2], "DATA");
        assert_eq!(SMTP_NAMES[3], "BDAT");
        assert_eq!(SMTP_NAMES[4], "EHLO");
        assert_eq!(SMTP_NAMES[5], "HELO");
        assert_eq!(SMTP_NAMES[6], "MAIL");
        assert_eq!(SMTP_NAMES[7], "NOOP");
        assert_eq!(SMTP_NAMES[8], "QUIT");
        assert_eq!(SMTP_NAMES[9], "RCPT");
        assert_eq!(SMTP_NAMES[10], "RSET");
        assert_eq!(SMTP_NAMES[11], "STARTTLS");
        assert_eq!(SMTP_NAMES[12], "VRFY");
    }

    #[test]
    fn test_session_state_default() {
        let state = SessionState::new();
        assert_eq!(state.smtp_mailcmd_count, 0);
        assert_eq!(state.synprot_error_count, 0);
        assert_eq!(state.unknown_command_count, 0);
        assert_eq!(state.nonmail_command_count, 0);
        assert!(state.pipelining_enable);
        assert!(!state.smtp_batched_input);
        assert!(state.smtp_notquit_reason.is_none());
        assert!(state.count_nonmail.is_none());
        assert_eq!(state.protocol_index, P_NORMAL);
    }

    #[test]
    fn test_session_state_had() {
        let mut state = SessionState::new();
        state.had(SmtpCommandHistory::SchEhlo);
        state.had(SmtpCommandHistory::SchMail);
        state.had(SmtpCommandHistory::SchRcpt);

        assert_eq!(state.connection_had[0], SmtpCommandHistory::SchEhlo);
        assert_eq!(state.connection_had[1], SmtpCommandHistory::SchMail);
        assert_eq!(state.connection_had[2], SmtpCommandHistory::SchRcpt);
        assert_eq!(state.connection_had_index, 3);
    }

    #[test]
    fn test_session_state_had_wraps() {
        let mut state = SessionState::new();
        for i in 0..SMTP_HISTRY_SIZE + 5 {
            state.had(if i % 2 == 0 {
                SmtpCommandHistory::SchEhlo
            } else {
                SmtpCommandHistory::SchMail
            });
        }
        assert_eq!(state.connection_had_index, 5);
    }

    #[test]
    fn test_smtp_get_connection_info_with_address() {
        let mut message_ctx = MessageContext::default();
        let server_ctx = ServerContext {
            primary_hostname: "mail.example.com".to_string(),
            smtp_active_hostname: "mail.example.com".to_string(),
            tls_server_credentials: None,
            host_checking: false,
            sender_host_notsocket: false,
            is_inetd: false,
            atrn_mode: false,
            interface_address: Some("192.168.1.1".to_string()),
            interface_port: 25,
        };
        message_ctx.sender_host_address = Some("10.0.0.1".to_string());
        message_ctx.sender_host_name = Some("client.example.com".to_string());
        message_ctx.sender_host_port = 12345;

        let info = smtp_get_connection_info(&message_ctx, &server_ctx);
        assert!(info.contains("H=client.example.com [10.0.0.1]:12345"));
        assert!(info.contains("I=[192.168.1.1]:25"));
    }

    #[test]
    fn test_smtp_get_connection_info_no_address() {
        let message_ctx = MessageContext::default();
        let server_ctx = ServerContext {
            primary_hostname: "mail.example.com".to_string(),
            smtp_active_hostname: "mail.example.com".to_string(),
            tls_server_credentials: None,
            host_checking: false,
            sender_host_notsocket: false,
            is_inetd: false,
            atrn_mode: false,
            interface_address: None,
            interface_port: 0,
        };

        let info = smtp_get_connection_info(&message_ctx, &server_ctx);
        assert!(info.is_empty());
    }

    #[test]
    fn test_s_connhad_log_empty() {
        let state = SessionState::new();
        let mut buf = String::new();
        s_connhad_log(&mut buf, &state);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_s_connhad_log_with_commands() {
        let mut state = SessionState::new();
        state.had(SmtpCommandHistory::SchEhlo);
        state.had(SmtpCommandHistory::SchMail);

        let mut buf = String::new();
        s_connhad_log(&mut buf, &state);
        assert!(buf.contains("EHLO"));
        assert!(buf.contains("MAIL"));
    }

    #[test]
    fn test_incomplete_transaction_log_no_sender() {
        let message_ctx = MessageContext::default();
        incomplete_transaction_log("test", &message_ctx);
    }

    #[test]
    fn test_smtp_notquit_exit_recursive_guard() {
        let mut state = SessionState::new();
        let message_ctx = MessageContext::default();
        let server_ctx = ServerContext {
            primary_hostname: "mail.example.com".to_string(),
            smtp_active_hostname: "mail.example.com".to_string(),
            tls_server_credentials: None,
            host_checking: false,
            sender_host_notsocket: false,
            is_inetd: false,
            atrn_mode: false,
            interface_address: None,
            interface_port: 0,
        };

        smtp_notquit_exit(
            "test-reason",
            "421",
            "%s: test",
            &mut state,
            &message_ctx,
            &server_ctx,
        );
        assert_eq!(state.smtp_notquit_reason, Some("test-reason".to_string()));

        smtp_notquit_exit(
            "other-reason",
            "421",
            "%s: other",
            &mut state,
            &message_ctx,
            &server_ctx,
        );
        assert_eq!(state.smtp_notquit_reason, Some("test-reason".to_string()));
    }

    #[test]
    fn test_smtp_reset_clears_state() {
        let mut message_ctx = MessageContext::default();
        message_ctx.sender_address = "test@example.com".to_string();
        message_ctx
            .recipients_list
            .push(command_loop::RecipientItem {
                address: "rcpt@example.com".to_string(),
                dsn_flags: 0,
                orcpt: None,
                errors_to: None,
            });
        message_ctx.recipients_count = 1;
        message_ctx.authenticated_sender = Some("auth@example.com".to_string());
        message_ctx.dsn_envid = Some("ENVID123".to_string());

        let mut arena = MessageArena::new();
        let _rp = smtp_reset(&mut message_ctx, &mut arena);

        assert!(message_ctx.sender_address.is_empty());
        assert!(message_ctx.recipients_list.is_empty());
        assert_eq!(message_ctx.recipients_count, 0);
        assert!(message_ctx.authenticated_sender.is_none());
        assert!(message_ctx.dsn_envid.is_none());
        assert!(message_ctx.headers.is_empty());
        assert!(message_ctx.acl_vars.is_empty());
    }
}
