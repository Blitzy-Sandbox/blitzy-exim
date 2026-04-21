//! SMTP protocol handling crate for the Exim Mail Transfer Agent.
//!
//! This crate replaces the C SMTP protocol implementation across:
//! - `src/src/smtp_in.c` (6,022 lines — inbound SMTP server: command state
//!   machine, I/O buffering, pipelining, CHUNKING/BDAT, PRDR, session lifecycle)
//! - `src/src/smtp_out.c` (924 lines — outbound SMTP client: connection
//!   management, command writing, response parsing, TFO)
//! - `src/src/atrn.c` (167 lines — ATRN/ODMR extension, RFC 2645)
//!
//! The crate is split into two public submodules:
//! - [`inbound`] — SMTP server implementation
//! - [`outbound`] — SMTP client implementation
//!
//! # Feature Flags
//!
//! Cargo feature flags replace C preprocessor conditionals:
//!
//! | Feature | C Equivalent | Description |
//! |---------|--------------|-------------|
//! | `tls` | `#ifndef DISABLE_TLS` | TLS/STARTTLS support |
//! | `prdr` | `#ifndef DISABLE_PRDR` | Per-Recipient Data Response |
//! | `pipe-connect` | `#ifndef DISABLE_PIPE_CONNECT` | Early pipelining |
//! | `dkim` | `#ifndef DISABLE_DKIM` | DKIM verification feed |
//! | `wellknown` | `#ifndef DISABLE_WELLKNOWN` | WELLKNOWN command |
//! | `esmtp-limits` | `#ifndef DISABLE_ESMTP_LIMITS` | ESMTP LIMITS extension |
//! | `events` | `#ifndef DISABLE_EVENT` | Event raise hooks |
//! | `xclient` | `#ifdef EXPERIMENTAL_XCLIENT` | XCLIENT extension |
//! | `dcc` | `#ifdef EXPERIMENTAL_DCC` | DCC content scanning |
//! | `proxy` | `#ifdef SUPPORT_PROXY` | HAProxy PROXY protocol |
//! | `i18n` | `#ifdef SUPPORT_I18N` | SMTPUTF8 internationalization |
//! | `srs` | `#ifdef SUPPORT_SRS` | Sender Rewriting Scheme |
//! | `content-scan` | `#ifdef WITH_CONTENT_SCAN` | MIME/malware/spam scanning |
//! | `local-scan` | `#ifdef HAVE_LOCAL_SCAN` | Local scan hook |
//! | `dscp` | `#ifdef SUPPORT_DSCP` | DSCP traffic marking |
//! | `socks` | `#ifdef SUPPORT_SOCKS` | SOCKS5 proxy support |
//!
//! # Architecture
//!
//! Per AAP §0.4.2, the inbound SMTP session uses a **type-state pattern**
//! to enforce valid SMTP command ordering at compile time:
//!
//! [`Connected`] → [`Greeted`] (via HELO/EHLO) → [`MailFrom`] (via MAIL FROM)
//! → [`RcptTo`] (via RCPT TO) → [`DataPhase`] (via DATA/BDAT)
//!
//! Per AAP §0.4.4, all mutable state flows through explicit context parameters
//! (`ServerContext`, `MessageContext`, `DeliveryContext`, `ConfigContext`)
//! rather than the 714 C global variables in `globals.c`.
//!
//! Per AAP §0.4.3, network input data uses `Tainted<T>` / `Clean<T>` newtypes
//! from `exim-store` for compile-time taint tracking with zero runtime cost.

#![forbid(unsafe_code)]

// ─── External imports ──────────────────────────────────────────────────────────

use std::fmt;
use thiserror::Error;

// ─── Feature-gated internal import ─────────────────────────────────────────────

#[cfg(feature = "tls")]
use exim_tls::TlsError;

// ─── Submodule declarations ────────────────────────────────────────────────────

/// Inbound SMTP server implementation.
///
/// Provides the SMTP command state machine, session lifecycle management,
/// custom buffered I/O, pipelining enforcement, CHUNKING/BDAT support,
/// PRDR (feature-gated), and ATRN/ODMR extension.
pub mod inbound;

/// Outbound SMTP client implementation.
///
/// Provides connection management, pipelined command writing, response parsing,
/// TCP Fast Open support, parallel delivery dispatch, and TLS negotiation
/// (feature-gated).
pub mod outbound;

// ─── Constants ─────────────────────────────────────────────────────────────────

/// SMTP command buffer size in bytes (from `smtp_in.c` line 27).
///
/// The total allocation is `2 * SMTP_CMD_BUFFER_SIZE + 2 = 32770` bytes,
/// split between `smtp_cmd_buffer` and `smtp_data_buffer` at offset
/// `SMTP_CMD_BUFFER_SIZE + 1`. Command buffers hold tainted network input.
pub const SMTP_CMD_BUFFER_SIZE: usize = 16384;

/// Inbound I/O buffer size for socket reads in bytes (from `smtp_in.c` line 31).
///
/// Used by the custom buffered I/O system in the pipelining module.
/// Output is flushed only when reading new input data — this is the key
/// optimization for SMTP pipelining.
pub const IN_BUFFER_SIZE: usize = 8192;

/// SMTP response buffer size in bytes (from `smtp_in.c` line 35).
///
/// Response buffers are untainted (`Clean<Vec<u8>>`) since they contain
/// server-generated data.
pub const SMTP_RESP_BUFFER_SIZE: usize = 2048;

// ─── Error Types ───────────────────────────────────────────────────────────────

/// Crate-level SMTP error type covering all protocol failure modes.
///
/// Uses `thiserror::Error` derive for automatic `Display` and `std::error::Error`
/// implementations. The [`TlsError`](SmtpError::TlsError) variant is
/// feature-gated behind `tls`.
///
/// # Variants
///
/// Each variant corresponds to a distinct class of SMTP failure:
/// - Protocol violations detected during command parsing
/// - Connection establishment or maintenance failures
/// - Command or data transfer timeouts
/// - TLS negotiation failures (feature-gated)
/// - Low-level I/O errors from socket operations
/// - SASL authentication failures
/// - Configuration expansion errors
/// - Pipelining synchronization violations
#[derive(Debug, Error)]
pub enum SmtpError {
    /// SMTP protocol violation.
    ///
    /// Generated by `synprot_error()` (smtp_in.c line 1389+) when the client
    /// sends syntactically invalid commands, violates command ordering, or
    /// sends unexpected data.
    #[error("SMTP protocol error: {message}")]
    ProtocolError {
        /// Human-readable description of the protocol violation.
        message: String,
    },

    /// Connection establishment or maintenance failure.
    ///
    /// Generated by outbound connection functions (`smtp_out.c`) when TCP
    /// connect fails, connection is refused, or the remote host is unreachable.
    #[error("connection error: {reason}")]
    ConnectionError {
        /// Human-readable description of the connection failure.
        reason: String,
    },

    /// Command or data transfer timeout.
    ///
    /// Generated by `command_timeout_handler` (smtp_in.c) when the SIGALRM
    /// fires during command read or data reception.
    #[error("timeout: {detail}")]
    TimeoutError {
        /// Human-readable description of the timeout.
        detail: String,
    },

    /// TLS negotiation failure.
    ///
    /// Only available when the `tls` Cargo feature is enabled, replacing
    /// C `#ifndef DISABLE_TLS` error handling patterns. Wraps
    /// `exim_tls::TlsError` via `#[from]` for automatic conversion from
    /// STARTTLS, TLS-on-connect, and TLS write operations.
    #[cfg(feature = "tls")]
    #[error("TLS error: {0}")]
    TlsError(#[from] TlsError),

    /// Low-level I/O error from socket read/write operations.
    ///
    /// Wraps `std::io::Error` via `#[from]` for automatic conversion from
    /// file descriptor operations throughout the SMTP protocol handling.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// SASL authentication failure.
    ///
    /// Generated when AUTH mechanism negotiation fails, credentials are
    /// rejected, or the authentication exchange encounters an error.
    #[error("authentication error: {detail}")]
    AuthError {
        /// Human-readable description of the authentication failure.
        detail: String,
    },

    /// Configuration expansion failure.
    ///
    /// Generated when `expand_string()` fails on configuration values
    /// needed for SMTP operation (e.g., `smtp_banner`, `message_size_limit`,
    /// interface/port settings in `smtp_out.c`).
    #[error("configuration error: {detail}")]
    ConfigError {
        /// Human-readable description of the configuration error.
        detail: String,
    },

    /// Pipelining synchronization violation.
    ///
    /// Generated by `check_sync()` when the client sends commands out of
    /// order relative to the pipelining rules, or sends data before the
    /// server has responded to a synchronization-required command.
    #[error("pipelining sync error: {detail}")]
    SyncError {
        /// Human-readable description of the synchronization violation.
        detail: String,
    },
}

// ─── SMTP Command Enum ─────────────────────────────────────────────────────────

/// SMTP command identifiers as parsed from the client command line.
///
/// Derived from the C `smtp_cmd_list[]` enumeration at `smtp_in.c` lines 51–110.
/// Commands are grouped by synchronization requirements for pipelining:
///
/// - **Sync-required**: Must wait for server response before client sends next
///   command (HELO, EHLO, DATA, VRFY, EXPN, NOOP, ATRN, ETRN, STARTTLS, TLS-AUTH)
/// - **Non-sync (pipelinable)**: May be sent without waiting (MAIL, RCPT, RSET)
/// - **Special**: Unique handling (BDAT, AUTH, QUIT, HELP)
/// - **Pseudo-commands**: Internal indicators for EOF, errors, and thresholds
///
/// Feature-gated variants replace C `#ifdef` preprocessor conditionals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SmtpCommand {
    // ── Sync-required commands ──
    /// HELO greeting (RFC 5321 §4.1.1.1)
    Helo,
    /// EHLO extended greeting (RFC 5321 §4.1.1.1)
    Ehlo,
    /// DATA message transmission (RFC 5321 §4.1.1.4)
    Data,
    /// VRFY verify address (RFC 5321 §4.1.1.6)
    Vrfy,
    /// EXPN expand mailing list (RFC 5321 §4.1.1.7)
    Expn,
    /// NOOP no operation (RFC 5321 §4.1.1.9)
    Noop,
    /// ATRN Authenticated TURN (RFC 2645)
    Atrn,
    /// ETRN Extended TURN (RFC 1985)
    Etrn,
    /// STARTTLS initiate TLS (RFC 3207)
    Starttls,
    /// TLS-AUTH pseudo-command for certificate-based authentication
    TlsAuth,

    // ── Feature-gated sync-required ──
    /// XCLIENT proxy info override (experimental).
    /// Gated by the `xclient` Cargo feature, replacing `#ifdef EXPERIMENTAL_XCLIENT`.
    #[cfg(feature = "xclient")]
    Xclient,

    // ── Non-sync pipelinable commands ──
    /// MAIL FROM sender specification (RFC 5321 §4.1.1.2)
    Mail,
    /// RCPT TO recipient specification (RFC 5321 §4.1.1.3)
    Rcpt,
    /// RSET reset transaction (RFC 5321 §4.1.1.5)
    Rset,

    // ── Feature-gated non-sync ──
    /// WELLKNOWN URI discovery command.
    /// Gated by the `wellknown` Cargo feature, replacing `#ifndef DISABLE_WELLKNOWN`.
    #[cfg(feature = "wellknown")]
    Wellknown,

    // ── Special commands ──
    /// BDAT binary data chunk (RFC 3030)
    Bdat,
    /// AUTH SASL authentication (RFC 4954)
    Auth,
    /// QUIT end session (RFC 5321 §4.1.1.10)
    Quit,
    /// HELP request help text (RFC 5321 §4.1.1.8)
    Help,

    // ── Feature-gated special ──
    /// Proxy protocol failure (ignored gracefully).
    /// Gated by the `proxy` Cargo feature, replacing `#ifdef SUPPORT_PROXY`.
    #[cfg(feature = "proxy")]
    ProxyFailIgnore,

    // ── Pseudo-commands (internal, not real SMTP commands) ──
    /// End-of-file: connection closed by client
    Eof,
    /// Unknown or unrecognized command
    Other,
    /// Recognized command with syntactically bad arguments
    BadArg,
    /// Command containing NUL byte characters
    BadChar,
    /// Pipelining synchronization violation detected
    BadSyn,
    /// Exceeded non-mail command threshold (`smtp_accept_max_nonmail`)
    TooManyNonMail,
}

impl fmt::Display for SmtpCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Helo => "HELO",
            Self::Ehlo => "EHLO",
            Self::Data => "DATA",
            Self::Vrfy => "VRFY",
            Self::Expn => "EXPN",
            Self::Noop => "NOOP",
            Self::Atrn => "ATRN",
            Self::Etrn => "ETRN",
            Self::Starttls => "STARTTLS",
            Self::TlsAuth => "TLS-AUTH",
            #[cfg(feature = "xclient")]
            Self::Xclient => "XCLIENT",
            Self::Mail => "MAIL",
            Self::Rcpt => "RCPT",
            Self::Rset => "RSET",
            #[cfg(feature = "wellknown")]
            Self::Wellknown => "WELLKNOWN",
            Self::Bdat => "BDAT",
            Self::Auth => "AUTH",
            Self::Quit => "QUIT",
            Self::Help => "HELP",
            #[cfg(feature = "proxy")]
            Self::ProxyFailIgnore => "PROXY-FAIL-IGNORE",
            Self::Eof => "EOF",
            Self::Other => "OTHER",
            Self::BadArg => "BADARG",
            Self::BadChar => "BADCHAR",
            Self::BadSyn => "BADSYN",
            Self::TooManyNonMail => "TOO-MANY-NONMAIL",
        };
        f.write_str(name)
    }
}

// ─── SMTP Protocol Identifier ──────────────────────────────────────────────────

/// Protocol identifier for the `Received:` header `with` clause.
///
/// Derived from C `protocols[]` (`smtp_in.c` lines 268–279) and
/// `protocols_local[]` (`smtp_in.c` lines 256–267) arrays. The 18 variants
/// encode transport type (SMTP/ESMTP/SSMTP), encryption state (`s` suffix),
/// authentication state (`a` suffix), and source locality (`local-` prefix).
///
/// Protocol selection uses index arithmetic from `smtp_in.c` lines 281–285:
/// - Base: `P_NORMAL` (0) for HELO, `P_EXTEND` (2) for EHLO
/// - Add `P_CRYPTED` (1) if TLS is active
/// - Add `P_AUTHED` (2) if authenticated
/// - `P_ONCONN` (6) for TLS-on-connect
///
/// The `Display` implementation produces strings matching the C arrays exactly,
/// which is critical for `Received:` header compatibility and `exigrep`/`eximstats`
/// log parsing (AAP §0.7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SmtpProtocol {
    // ── Remote protocol strings (from protocols[] array) ──
    /// `"smtp"` — plain SMTP via HELO
    Smtp,
    /// `"smtps"` — encrypted SMTP via HELO + TLS
    Smtps,
    /// `"esmtp"` — Extended SMTP via EHLO
    Esmtp,
    /// `"esmtps"` — ESMTP + TLS
    Esmtps,
    /// `"esmtpa"` — ESMTP + authenticated
    Esmtpa,
    /// `"esmtpsa"` — ESMTP + TLS + authenticated
    Esmtpsa,
    /// `"ssmtp"` — TLS-on-connect (implicit TLS)
    Ssmtp,
    /// `"essmtp"` — Extended + TLS-on-connect
    Essmtp,
    /// `"essmtpa"` — Extended + TLS-on-connect + authenticated
    Essmtpa,

    // ── Local protocol strings (from protocols_local[] array) ──
    /// `"local-smtp"` — local submission via HELO
    LocalSmtp,
    /// `"local-smtps"` — local + TLS
    LocalSmtps,
    /// `"local-esmtp"` — local + EHLO
    LocalEsmtp,
    /// `"local-esmtps"` — local + EHLO + TLS
    LocalEsmtps,
    /// `"local-esmtpa"` — local + EHLO + authenticated
    LocalEsmtpa,
    /// `"local-esmtpsa"` — local + EHLO + TLS + authenticated
    LocalEsmtpsa,
    /// `"local-ssmtp"` — local + TLS-on-connect
    LocalSsmtp,
    /// `"local-essmtp"` — local + Extended + TLS-on-connect
    LocalEssmtp,
    /// `"local-essmtpa"` — local + Extended + TLS-on-connect + authenticated
    LocalEssmtpa,

    /// `"local-bsmtp"` — batch SMTP input (`-bS` mode)
    ///
    /// C Exim sets this protocol string when processing batched SMTP
    /// input where no HELO/EHLO exchange occurs and commands are read
    /// from stdin without interactive responses.
    LocalBsmtp,
}

impl fmt::Display for SmtpProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Smtp => "smtp",
            Self::Smtps => "smtps",
            Self::Esmtp => "esmtp",
            Self::Esmtps => "esmtps",
            Self::Esmtpa => "esmtpa",
            Self::Esmtpsa => "esmtpsa",
            Self::Ssmtp => "ssmtp",
            Self::Essmtp => "essmtp",
            Self::Essmtpa => "essmtpa",
            Self::LocalSmtp => "local-smtp",
            Self::LocalSmtps => "local-smtps",
            Self::LocalEsmtp => "local-esmtp",
            Self::LocalEsmtps => "local-esmtps",
            Self::LocalEsmtpa => "local-esmtpa",
            Self::LocalEsmtpsa => "local-esmtpsa",
            Self::LocalSsmtp => "local-ssmtp",
            Self::LocalEssmtp => "local-essmtp",
            Self::LocalEssmtpa => "local-essmtpa",
            Self::LocalBsmtp => "local-bsmtp",
        };
        f.write_str(s)
    }
}

// ─── MAIL FROM Extension Options ───────────────────────────────────────────────

/// MAIL FROM extension parameter identifiers.
///
/// Derived from `env_mail_type_list[]` at `smtp_in.c` lines 305–319.
/// Each variant maps to an ESMTP MAIL FROM parameter keyword:
/// - `SIZE` (RFC 1870), `BODY` (RFC 6152), `AUTH` (RFC 4954)
/// - `PRDR` (feature-gated), `RET`/`ENVID` (RFC 3461 DSN)
/// - `SMTPUTF8` (RFC 6531, feature-gated as `Utf8`)
///
/// The `Null` variant serves as the sentinel terminator for the option list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnvMailOption {
    /// Sentinel / terminator for option list scanning
    Null,
    /// `SIZE=<n>` — declared message size (RFC 1870)
    Size,
    /// `BODY=<type>` — 7BIT or 8BITMIME (RFC 6152)
    Body,
    /// `AUTH=<addr>` — authenticated sender (RFC 4954)
    Auth,
    /// `PRDR` — Per-Recipient Data Response request.
    /// Gated by the `prdr` Cargo feature, replacing `#ifndef DISABLE_PRDR`.
    #[cfg(feature = "prdr")]
    Prdr,
    /// `RET=<FULL|HDRS>` — DSN return type (RFC 3461)
    Ret,
    /// `ENVID=<xtext>` — DSN envelope ID (RFC 3461)
    Envid,
    /// `SMTPUTF8` — internationalized email (RFC 6531).
    /// Gated by the `i18n` Cargo feature, replacing `#ifdef SUPPORT_I18N`.
    #[cfg(feature = "i18n")]
    Utf8,
}

/// Definition entry for a MAIL FROM extension parameter.
///
/// Derived from the C `env_mail_type_t` struct at `smtp_in.c` lines 299–304.
/// Used to build the lookup table for parsing MAIL FROM extension keywords.
#[derive(Debug, Clone)]
pub struct EnvMailOptionDef {
    /// The extension keyword string (e.g., `"SIZE"`, `"BODY"`)
    pub name: &'static str,
    /// The corresponding [`EnvMailOption`] variant
    pub value: EnvMailOption,
    /// Whether this extension requires a `=value` parameter
    pub need_value: bool,
}

/// Static lookup table for MAIL FROM extension parameters.
///
/// Derived from `env_mail_type_list[]` at `smtp_in.c` lines 305–319.
/// Feature-gated entries are included only when the corresponding feature is
/// active. The `Null` entry serves as the terminating sentinel.
pub static ENV_MAIL_TYPE_LIST: &[EnvMailOptionDef] = &[
    EnvMailOptionDef {
        name: "SIZE",
        value: EnvMailOption::Size,
        need_value: true,
    },
    EnvMailOptionDef {
        name: "BODY",
        value: EnvMailOption::Body,
        need_value: true,
    },
    EnvMailOptionDef {
        name: "AUTH",
        value: EnvMailOption::Auth,
        need_value: true,
    },
    #[cfg(feature = "prdr")]
    EnvMailOptionDef {
        name: "PRDR",
        value: EnvMailOption::Prdr,
        need_value: false,
    },
    EnvMailOptionDef {
        name: "RET",
        value: EnvMailOption::Ret,
        need_value: true,
    },
    EnvMailOptionDef {
        name: "ENVID",
        value: EnvMailOption::Envid,
        need_value: true,
    },
    #[cfg(feature = "i18n")]
    EnvMailOptionDef {
        name: "SMTPUTF8",
        value: EnvMailOption::Utf8,
        need_value: false,
    },
    EnvMailOptionDef {
        name: "NULL",
        value: EnvMailOption::Null,
        need_value: false,
    },
];

// ─── Chunking State ────────────────────────────────────────────────────────────

/// CHUNKING/BDAT protocol state machine (RFC 3030).
///
/// Derived from `chunking_states[]` at `smtp_in.c` lines 321–327.
/// Tracks the BDAT extension lifecycle:
/// - Server advertises CHUNKING in EHLO → `Offered`
/// - Client sends `BDAT <size>` → `Active`
/// - Client sends `BDAT <size> LAST` → `Last`
///
/// The `Display` implementation produces strings matching C `chunking_states[]`
/// exactly, which is critical for log compatibility (AAP §0.7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ChunkingState {
    /// CHUNKING was not advertised in EHLO
    #[default]
    NotOffered,
    /// CHUNKING was advertised but no BDAT received yet
    Offered,
    /// Currently receiving a non-LAST BDAT chunk
    Active,
    /// Currently receiving the final (LAST) BDAT chunk
    Last,
}

impl fmt::Display for ChunkingState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::NotOffered => "not-offered",
            Self::Offered => "offered",
            Self::Active => "active",
            Self::Last => "last",
        };
        f.write_str(s)
    }
}

// ─── Session Flags ─────────────────────────────────────────────────────────────

/// Per-session boolean flags for inbound SMTP sessions.
///
/// Derived from the C `fl` static struct at `smtp_in.c` lines 125–147.
/// These flags track EHLO capability advertisement state, verification
/// requirements, and session progress. Feature-gated fields replace
/// the corresponding C `#ifdef` guards.
///
/// The `Default` implementation sets `rcpt_smtp_response_same` to `true`
/// and all other flags to `false`, matching the C initializer at lines 144–147.
#[derive(Debug, Clone)]
pub struct SmtpSessionFlags {
    /// Whether AUTH mechanisms were advertised in EHLO
    pub auth_advertised: bool,
    /// Whether DSN was advertised in EHLO
    pub dsn_advertised: bool,
    /// Whether client used EHLO (vs HELO)
    pub esmtp: bool,
    /// Whether HELO/EHLO argument verification is required (hard fail)
    pub helo_verify_required: bool,
    /// Whether HELO/EHLO argument verification is attempted (soft fail)
    pub helo_verify: bool,
    /// Whether a valid HELO/EHLO has been received
    pub helo_seen: bool,
    /// Whether to accept syntactically invalid HELO arguments
    pub helo_accept_junk: bool,
    /// Whether all RCPT TO responses are the same (for optimization)
    pub rcpt_smtp_response_same: bool,
    /// Whether we are currently processing RCPT TO commands
    pub rcpt_in_progress: bool,
    /// Whether STARTTLS was advertised in EHLO.
    /// Gated by the `tls` Cargo feature.
    #[cfg(feature = "tls")]
    pub tls_advertised: bool,
    /// Whether pipe-connect (early pipelining) is acceptable.
    /// Gated by the `pipe-connect` Cargo feature.
    #[cfg(feature = "pipe-connect")]
    pub pipe_connect_acceptable: bool,
    /// Whether SMTPUTF8 was advertised in EHLO.
    /// Gated by the `i18n` Cargo feature.
    #[cfg(feature = "i18n")]
    pub smtputf8_advertised: bool,
}

impl Default for SmtpSessionFlags {
    fn default() -> Self {
        Self {
            auth_advertised: false,
            dsn_advertised: false,
            esmtp: false,
            helo_verify_required: false,
            helo_verify: false,
            helo_seen: false,
            helo_accept_junk: false,
            // Matching C initializer: TRUE (smtp_in.c line 147)
            rcpt_smtp_response_same: true,
            rcpt_in_progress: false,
            #[cfg(feature = "tls")]
            tls_advertised: false,
            #[cfg(feature = "pipe-connect")]
            pipe_connect_acceptable: false,
            #[cfg(feature = "i18n")]
            smtputf8_advertised: false,
        }
    }
}

// ─── Type-State Markers ────────────────────────────────────────────────────────

/// Type-state marker: SMTP session is connected but not yet greeted.
///
/// This is the initial state after TCP connection acceptance.
/// Valid transitions: `Connected` → [`Greeted`] via HELO/EHLO.
///
/// Part of the compile-time SMTP command ordering enforcement (AAP §0.4.2).
/// Used as a generic parameter in the inbound `SmtpSession<S>` struct.
#[derive(Debug, Clone, Copy)]
pub struct Connected;

/// Type-state marker: SMTP session has received HELO/EHLO.
///
/// Valid transitions: `Greeted` → [`MailFrom`] via MAIL FROM.
/// RSET returns to `Greeted` from any post-HELO state.
#[derive(Debug, Clone, Copy)]
pub struct Greeted;

/// Type-state marker: SMTP session has received MAIL FROM.
///
/// Valid transitions: `MailFrom` → [`RcptTo`] via RCPT TO.
#[derive(Debug, Clone, Copy)]
pub struct MailFrom;

/// Type-state marker: SMTP session has at least one RCPT TO accepted.
///
/// Valid transitions: `RcptTo` → [`DataPhase`] via DATA or BDAT.
/// Additional RCPT TO commands remain in `RcptTo` state.
#[derive(Debug, Clone, Copy)]
pub struct RcptTo;

/// Type-state marker: SMTP session is in the DATA/BDAT phase.
///
/// The session is receiving message content. After message completion,
/// the session returns to [`Greeted`] for the next transaction.
#[derive(Debug, Clone, Copy)]
pub struct DataPhase;

// ─── Command Definition ────────────────────────────────────────────────────────

/// Definition entry for an SMTP command in the command lookup table.
///
/// Derived from the C `smtp_cmd_list` struct at `smtp_in.c` lines 39–45
/// and the `cmd_list[]` array at lines 195–224. Used by `smtp_read_command()`
/// for case-insensitive command matching and synchronization classification.
///
/// # Fields
///
/// - `name`: The command keyword string (e.g., `"HELO"`, `"MAIL FROM:"`)
/// - `cmd`: The corresponding [`SmtpCommand`] variant
/// - `is_mail_cmd`: Whether this is a mail-transaction command (affects
///   non-mail command counting for `smtp_accept_max_nonmail`)
/// - `min_len`: Minimum command string length for matching (enables
///   prefix matching for commands like `"MAIL FROM:"`)
#[derive(Debug, Clone)]
pub struct SmtpCommandDef {
    /// The command keyword string for case-insensitive matching
    pub name: &'static str,
    /// The parsed [`SmtpCommand`] variant
    pub cmd: SmtpCommand,
    /// Whether this command is part of a mail transaction
    pub is_mail_cmd: bool,
    /// Minimum prefix length required for matching
    pub min_len: usize,
}

// ─── Command History ───────────────────────────────────────────────────────────

/// SMTP command history identifiers for connection logging.
///
/// Derived from `smtp_names[]` at `smtp_in.c` lines 229–254. Stored in a
/// circular buffer (`smtp_connection_had[]`) and printed by
/// `smtp_log_no_mail()` to record which commands were seen during a
/// session that ended without mail delivery.
///
/// The variant naming follows the C `SCH_*` convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SmtpCommandHistory {
    /// No command recorded (empty slot)
    #[default]
    SchNone,
    /// AUTH command was attempted
    SchAuth,
    /// DATA command was sent
    SchData,
    /// BDAT command was sent
    SchBdat,
    /// EHLO command was sent
    SchEhlo,
    /// HELO command was sent
    SchHelo,
    /// MAIL FROM command was sent
    SchMail,
    /// NOOP command was sent
    SchNoop,
    /// QUIT command was sent
    SchQuit,
    /// RCPT TO command was sent
    SchRcpt,
    /// RSET command was sent
    SchRset,
    /// STARTTLS command was sent
    SchStarttls,
    /// VRFY command was sent
    SchVrfy,
}

impl fmt::Display for SmtpCommandHistory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::SchNone => "",
            Self::SchAuth => "AUTH",
            Self::SchData => "DATA",
            Self::SchBdat => "BDAT",
            Self::SchEhlo => "EHLO",
            Self::SchHelo => "HELO",
            Self::SchMail => "MAIL",
            Self::SchNoop => "NOOP",
            Self::SchQuit => "QUIT",
            Self::SchRcpt => "RCPT",
            Self::SchRset => "RSET",
            Self::SchStarttls => "STARTTLS",
            Self::SchVrfy => "VRFY",
        };
        f.write_str(s)
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smtp_protocol_display() {
        // Remote protocols (from C protocols[] array)
        assert_eq!(SmtpProtocol::Smtp.to_string(), "smtp");
        assert_eq!(SmtpProtocol::Smtps.to_string(), "smtps");
        assert_eq!(SmtpProtocol::Esmtp.to_string(), "esmtp");
        assert_eq!(SmtpProtocol::Esmtps.to_string(), "esmtps");
        assert_eq!(SmtpProtocol::Esmtpa.to_string(), "esmtpa");
        assert_eq!(SmtpProtocol::Esmtpsa.to_string(), "esmtpsa");
        assert_eq!(SmtpProtocol::Ssmtp.to_string(), "ssmtp");
        assert_eq!(SmtpProtocol::Essmtp.to_string(), "essmtp");
        assert_eq!(SmtpProtocol::Essmtpa.to_string(), "essmtpa");
        // Local protocols (from C protocols_local[] array)
        assert_eq!(SmtpProtocol::LocalSmtp.to_string(), "local-smtp");
        assert_eq!(SmtpProtocol::LocalSmtps.to_string(), "local-smtps");
        assert_eq!(SmtpProtocol::LocalEsmtp.to_string(), "local-esmtp");
        assert_eq!(SmtpProtocol::LocalEsmtps.to_string(), "local-esmtps");
        assert_eq!(SmtpProtocol::LocalEsmtpa.to_string(), "local-esmtpa");
        assert_eq!(SmtpProtocol::LocalEsmtpsa.to_string(), "local-esmtpsa");
        assert_eq!(SmtpProtocol::LocalSsmtp.to_string(), "local-ssmtp");
        assert_eq!(SmtpProtocol::LocalEssmtp.to_string(), "local-essmtp");
        assert_eq!(SmtpProtocol::LocalEssmtpa.to_string(), "local-essmtpa");
    }

    #[test]
    fn test_chunking_state_display() {
        // Must match C chunking_states[] strings exactly
        assert_eq!(ChunkingState::NotOffered.to_string(), "not-offered");
        assert_eq!(ChunkingState::Offered.to_string(), "offered");
        assert_eq!(ChunkingState::Active.to_string(), "active");
        assert_eq!(ChunkingState::Last.to_string(), "last");
    }

    #[test]
    fn test_chunking_state_default() {
        assert_eq!(ChunkingState::default(), ChunkingState::NotOffered);
    }

    #[test]
    fn test_smtp_command_display() {
        assert_eq!(SmtpCommand::Helo.to_string(), "HELO");
        assert_eq!(SmtpCommand::Ehlo.to_string(), "EHLO");
        assert_eq!(SmtpCommand::Mail.to_string(), "MAIL");
        assert_eq!(SmtpCommand::Rcpt.to_string(), "RCPT");
        assert_eq!(SmtpCommand::Data.to_string(), "DATA");
        assert_eq!(SmtpCommand::Bdat.to_string(), "BDAT");
        assert_eq!(SmtpCommand::Auth.to_string(), "AUTH");
        assert_eq!(SmtpCommand::Quit.to_string(), "QUIT");
        assert_eq!(SmtpCommand::Rset.to_string(), "RSET");
        assert_eq!(SmtpCommand::Starttls.to_string(), "STARTTLS");
        assert_eq!(SmtpCommand::Eof.to_string(), "EOF");
        assert_eq!(SmtpCommand::BadSyn.to_string(), "BADSYN");
        assert_eq!(SmtpCommand::TooManyNonMail.to_string(), "TOO-MANY-NONMAIL");
    }

    #[test]
    fn test_smtp_command_history_display() {
        assert_eq!(SmtpCommandHistory::SchNone.to_string(), "");
        assert_eq!(SmtpCommandHistory::SchAuth.to_string(), "AUTH");
        assert_eq!(SmtpCommandHistory::SchData.to_string(), "DATA");
        assert_eq!(SmtpCommandHistory::SchBdat.to_string(), "BDAT");
        assert_eq!(SmtpCommandHistory::SchEhlo.to_string(), "EHLO");
        assert_eq!(SmtpCommandHistory::SchStarttls.to_string(), "STARTTLS");
    }

    #[test]
    fn test_smtp_command_history_default() {
        assert_eq!(SmtpCommandHistory::default(), SmtpCommandHistory::SchNone);
    }

    #[test]
    fn test_session_flags_default() {
        let flags = SmtpSessionFlags::default();
        assert!(!flags.auth_advertised);
        assert!(!flags.dsn_advertised);
        assert!(!flags.esmtp);
        assert!(!flags.helo_verify_required);
        assert!(!flags.helo_verify);
        assert!(!flags.helo_seen);
        assert!(!flags.helo_accept_junk);
        // rcpt_smtp_response_same defaults to true (matching C)
        assert!(flags.rcpt_smtp_response_same);
        assert!(!flags.rcpt_in_progress);
    }

    #[test]
    fn test_constants() {
        assert_eq!(SMTP_CMD_BUFFER_SIZE, 16384);
        assert_eq!(IN_BUFFER_SIZE, 8192);
        assert_eq!(SMTP_RESP_BUFFER_SIZE, 2048);
    }

    #[test]
    fn test_env_mail_type_list_not_empty() {
        assert!(!ENV_MAIL_TYPE_LIST.is_empty());
        // First entry is SIZE
        assert_eq!(ENV_MAIL_TYPE_LIST[0].name, "SIZE");
        assert_eq!(ENV_MAIL_TYPE_LIST[0].value, EnvMailOption::Size);
        assert!(ENV_MAIL_TYPE_LIST[0].need_value);
        // Last entry is NULL sentinel
        let last = ENV_MAIL_TYPE_LIST.last().expect("list should not be empty");
        assert_eq!(last.name, "NULL");
        assert_eq!(last.value, EnvMailOption::Null);
        assert!(!last.need_value);
    }

    #[test]
    fn test_smtp_error_display() {
        let err = SmtpError::ProtocolError {
            message: "test".to_string(),
        };
        assert!(err.to_string().contains("test"));

        let err = SmtpError::ConnectionError {
            reason: "refused".to_string(),
        };
        assert!(err.to_string().contains("refused"));

        let err = SmtpError::TimeoutError {
            detail: "30s".to_string(),
        };
        assert!(err.to_string().contains("30s"));

        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken");
        let err: SmtpError = io_err.into();
        assert!(err.to_string().contains("broken"));
    }

    #[test]
    fn test_type_state_markers_are_zero_sized() {
        assert_eq!(std::mem::size_of::<Connected>(), 0);
        assert_eq!(std::mem::size_of::<Greeted>(), 0);
        assert_eq!(std::mem::size_of::<MailFrom>(), 0);
        assert_eq!(std::mem::size_of::<RcptTo>(), 0);
        assert_eq!(std::mem::size_of::<DataPhase>(), 0);
    }

    #[test]
    fn test_smtp_command_equality() {
        assert_eq!(SmtpCommand::Helo, SmtpCommand::Helo);
        assert_ne!(SmtpCommand::Helo, SmtpCommand::Ehlo);
    }

    #[test]
    fn test_smtp_protocol_equality() {
        assert_eq!(SmtpProtocol::Smtp, SmtpProtocol::Smtp);
        assert_ne!(SmtpProtocol::Smtp, SmtpProtocol::Esmtp);
    }

    #[test]
    fn test_env_mail_option_def_fields() {
        let def = EnvMailOptionDef {
            name: "TEST",
            value: EnvMailOption::Size,
            need_value: true,
        };
        assert_eq!(def.name, "TEST");
        assert_eq!(def.value, EnvMailOption::Size);
        assert!(def.need_value);
    }

    #[test]
    fn test_smtp_command_def_fields() {
        let def = SmtpCommandDef {
            name: "HELO",
            cmd: SmtpCommand::Helo,
            is_mail_cmd: false,
            min_len: 4,
        };
        assert_eq!(def.name, "HELO");
        assert_eq!(def.cmd, SmtpCommand::Helo);
        assert!(!def.is_mail_cmd);
        assert_eq!(def.min_len, 4);
    }
}
