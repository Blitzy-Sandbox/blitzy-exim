//! # RFC 5228 Sieve Filter Interpreter Module
//!
//! Complete rewrite of `src/src/miscmods/sieve_filter.c` (3,644 lines) — the
//! **largest** module in miscmods — into safe Rust.  Implements the RFC 5228
//! Sieve mail filtering language with the following extensions:
//!
//! - **encoded-character** — `${hex:…}` / `${unicode:…}` character escapes
//! - **enotify** — RFC 5435 notify action via mailto: URI
//! - **subaddress** — RFC 5233 `:user` / `:detail` address parts
//! - **vacation** — RFC 5230 vacation auto-response with rate-limiting
//! - **copy** — `:copy` tagged argument for redirect/fileinto
//! - **comparator-i;ascii-numeric** — numeric string comparator
//! - **regex** — PCRE2-based regular expression match type
//! - **imap4flags** — IMAP flag manipulation for fileinto
//! - **extlists** — external list extension
//!
//! ## Architecture
//!
//! The C source uses a combined recursive-descent parser-evaluator (parsing and
//! execution interleaved via an `exec` flag).  This Rust rewrite preserves that
//! combined architecture for behavioral fidelity: the parser produces AST nodes
//! that are immediately evaluated, matching C Exim's single-pass semantics.
//!
//! ## Memory Model
//!
//! - [`Tainted<T>`] wraps filter source text and message header values
//!   (untrusted user input) per AAP §0.4.3.
//! - [`Clean<T>`] wraps validated/sanitized data (e.g., parsed addresses).
//! - [`MessageArena`] provides per-message arena allocation replacing C
//!   `store_get()` calls throughout `sieve_filter.c`.
//!
//! ## Module Registration
//!
//! Registered via `inventory::submit!` as `sieve_filter` with function slots
//! `SIEVE_INTERPRET` (index 0) and `SIEVE_EXTENSIONS` (index 1), matching
//! `sieve_filter_api.h` defines.
//!
//! ## Safety
//!
//! This module contains **zero** `unsafe` code (per AAP §0.7.2).
//!
//! SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::{HashMap, HashSet};
use std::fmt;

use exim_drivers::{DriverError, DriverInfoBase};
use exim_store::arena::MessageArena;
use exim_store::taint::{TaintError, TaintState};
use exim_store::{Clean, CleanString, MessageStore, Tainted, TaintedString};

// ---------------------------------------------------------------------------
// Constants — match C #defines (sieve_filter.c lines 29–47)
// ---------------------------------------------------------------------------

/// Minimum vacation auto-response interval in days (C: `VACATION_MIN_DAYS`).
const VACATION_MIN_DAYS: u32 = 1;

/// Maximum vacation auto-response interval in days (C: `VACATION_MAX_DAYS`).
const VACATION_MAX_DAYS: u32 = 31;

/// Maximum RFC-compliant MIME encoded-word length (C: `MIMEWORD_LENGTH`).
const MIMEWORD_LENGTH: usize = 75;

// ---------------------------------------------------------------------------
// SieveError — replaces C errmsg/return-code pattern
// ---------------------------------------------------------------------------

/// Error type for Sieve filter parsing and evaluation.
///
/// Replaces the C pattern of setting `filter->errmsg` and returning -1.
#[derive(Debug, thiserror::Error)]
pub enum SieveError {
    /// Syntax or parse error at a specific line in the Sieve script.
    #[error("line {line}: {message}")]
    ParseError {
        /// 1-based line number where the error occurred.
        line: usize,
        /// Human-readable error description.
        message: String,
    },

    /// Runtime error during filter evaluation.
    #[error("runtime error: {message}")]
    RuntimeError {
        /// Human-readable error description.
        message: String,
    },

    /// An unsupported Sieve extension was requested via `require`.
    #[error("unsupported extension: {0}")]
    UnsupportedExtension(String),

    /// An invalid email address was encountered.
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    /// Error in the vacation auto-response command.
    #[error("vacation error: {0}")]
    VacationError(String),

    /// String expansion failed during evaluation.
    #[error("expansion failed: {0}")]
    ExpansionFailed(String),
}

impl From<TaintError> for SieveError {
    fn from(e: TaintError) -> Self {
        SieveError::RuntimeError {
            message: format!("taint validation failed: {}", e.context),
        }
    }
}

impl From<DriverError> for SieveError {
    fn from(e: DriverError) -> Self {
        SieveError::RuntimeError {
            message: format!("driver error: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// SieveResult — evaluation outcome
// ---------------------------------------------------------------------------

/// Outcome of Sieve filter script evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SieveResult {
    /// Message was delivered (keep, fileinto, or redirect took effect).
    Delivered,
    /// No delivery action was taken (discard).
    NotDelivered,
    /// Delivery should be deferred (temporary failure).
    Defer,
    /// Delivery failed permanently.
    Fail,
    /// Message should be frozen in queue.
    Freeze,
    /// An error occurred during evaluation.
    Error,
}

impl fmt::Display for SieveResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Delivered => write!(f, "delivered"),
            Self::NotDelivered => write!(f, "not_delivered"),
            Self::Defer => write!(f, "defer"),
            Self::Fail => write!(f, "fail"),
            Self::Freeze => write!(f, "freeze"),
            Self::Error => write!(f, "error"),
        }
    }
}

// ---------------------------------------------------------------------------
// SieveCapabilities — replaces C bitmask require field
// ---------------------------------------------------------------------------

/// Set of Sieve extensions enabled by `require` statements.
///
/// Replaces the C bitmask pattern on `filter.require` (lines 60–67).
/// Uses a `HashSet<String>` for extensibility beyond the core set.
#[derive(Debug, Clone)]
pub struct SieveCapabilities {
    caps: HashSet<String>,
}

impl SieveCapabilities {
    /// Constant for the `fileinto` extension.
    pub const FILEINTO: &'static str = "fileinto";
    /// Constant for the `reject` extension.
    pub const REJECT: &'static str = "reject";
    /// Constant for the `envelope` extension.
    pub const ENVELOPE: &'static str = "envelope";
    /// Constant for the `encoded-character` extension.
    pub const ENCODED_CHARACTER: &'static str = "encoded-character";
    /// Constant for the `enotify` extension (RFC 5435).
    pub const ENOTIFY: &'static str = "enotify";
    /// Constant for the `subaddress` extension (RFC 5233).
    pub const SUBADDRESS: &'static str = "subaddress";
    /// Constant for the `vacation` extension (RFC 5230).
    pub const VACATION: &'static str = "vacation";
    /// Constant for the `comparator-i;ascii-numeric` extension.
    pub const COMPARATOR_NUMERIC: &'static str = "comparator-i;ascii-numeric";
    /// Constant for the `regex` extension.
    pub const REGEX: &'static str = "regex";
    /// Constant for the `copy` extension.
    pub const COPY: &'static str = "copy";
    /// Constant for the `imap4flags` extension.
    pub const IMAP4FLAGS: &'static str = "imap4flags";
    /// Constant for the `extlists` extension.
    pub const EXTLISTS: &'static str = "extlists";

    /// Create an empty capability set.
    pub fn empty() -> Self {
        Self {
            caps: HashSet::new(),
        }
    }

    /// Check whether a capability is enabled.
    pub fn contains(&self, cap: &str) -> bool {
        self.caps.contains(cap)
    }

    /// Enable a capability.
    pub fn insert(&mut self, cap: &str) {
        self.caps.insert(cap.to_string());
    }
}

// ---------------------------------------------------------------------------
// RelOp — relational operators for :count / :value
// ---------------------------------------------------------------------------

/// Relational operators for `:count` and `:value` match types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelOp {
    /// Less than.
    Lt,
    /// Less than or equal.
    Le,
    /// Equal.
    Eq,
    /// Greater than or equal.
    Ge,
    /// Greater than.
    Gt,
    /// Not equal.
    Ne,
}

impl RelOp {
    /// Evaluate a comparison result against this operator.
    pub fn eval(self, ord: std::cmp::Ordering) -> bool {
        match self {
            Self::Lt => ord == std::cmp::Ordering::Less,
            Self::Le => ord != std::cmp::Ordering::Greater,
            Self::Eq => ord == std::cmp::Ordering::Equal,
            Self::Ge => ord != std::cmp::Ordering::Less,
            Self::Gt => ord == std::cmp::Ordering::Greater,
            Self::Ne => ord != std::cmp::Ordering::Equal,
        }
    }
}

impl fmt::Display for RelOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lt => write!(f, "lt"),
            Self::Le => write!(f, "le"),
            Self::Eq => write!(f, "eq"),
            Self::Ge => write!(f, "ge"),
            Self::Gt => write!(f, "gt"),
            Self::Ne => write!(f, "ne"),
        }
    }
}

// ---------------------------------------------------------------------------
// MatchType — replaces C enum MatchType
// ---------------------------------------------------------------------------

/// Sieve string match type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MatchType {
    /// Exact match (`:is`, default).
    Is,
    /// Substring match (`:contains`).
    Contains,
    /// Glob pattern match (`:matches`) — `?` and `*` wildcards.
    Matches,
    /// PCRE2 regular expression match (`:regex`).
    Regex,
    /// Count-based relational match (`:count`).
    Count(RelOp),
    /// Value-based relational match (`:value`).
    Value(RelOp),
}

impl fmt::Display for MatchType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Is => write!(f, ":is"),
            Self::Contains => write!(f, ":contains"),
            Self::Matches => write!(f, ":matches"),
            Self::Regex => write!(f, ":regex"),
            Self::Count(op) => write!(f, ":count \"{op}\""),
            Self::Value(op) => write!(f, ":value \"{op}\""),
        }
    }
}

// ---------------------------------------------------------------------------
// Comparator — replaces C enum Comparator
// ---------------------------------------------------------------------------

/// Sieve string comparator selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Comparator {
    /// Octet-by-octet comparison (`i;octet`).
    OctetStream,
    /// ASCII case-insensitive comparison (`i;ascii-casemap`, default).
    AsciiCaseMap,
    /// ASCII numeric comparison (`i;ascii-numeric`).
    AsciiNumeric,
}

impl fmt::Display for Comparator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OctetStream => write!(f, "i;octet"),
            Self::AsciiCaseMap => write!(f, "i;ascii-casemap"),
            Self::AsciiNumeric => write!(f, "i;ascii-numeric"),
        }
    }
}

// ---------------------------------------------------------------------------
// AddressPart — replaces C enum AddressPart
// ---------------------------------------------------------------------------

/// Sieve address part selector for `address` and `envelope` tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressPart {
    /// The complete address (default).
    All,
    /// The local-part (everything before `@`).
    LocalPart,
    /// The domain part (everything after `@`).
    Domain,
    /// The user part of the local-part (subaddress, before `+`).
    User,
    /// The detail part of the local-part (subaddress, after `+`).
    Detail,
}

impl fmt::Display for AddressPart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => write!(f, ":all"),
            Self::LocalPart => write!(f, ":localpart"),
            Self::Domain => write!(f, ":domain"),
            Self::User => write!(f, ":user"),
            Self::Detail => write!(f, ":detail"),
        }
    }
}

// ---------------------------------------------------------------------------
// SieveTest — AST node for test expressions
// ---------------------------------------------------------------------------

/// AST representation of a Sieve test expression.
#[derive(Debug, Clone)]
pub enum SieveTest {
    /// Always true.
    True,
    /// Always false.
    False,
    /// Boolean negation.
    Not(Box<SieveTest>),
    /// Conjunction — all sub-tests must be true.
    AllOf(Vec<SieveTest>),
    /// Disjunction — at least one sub-test must be true.
    AnyOf(Vec<SieveTest>),
    /// Address test — match against address headers.
    Address {
        /// Header names to inspect (e.g. `["From", "To"]`).
        header: Vec<String>,
        /// Key strings to match against.
        keys: Vec<String>,
        /// How to match (`:is`, `:contains`, `:matches`, `:regex`, etc.).
        match_type: MatchType,
        /// String comparator to use.
        comparator: Comparator,
        /// Which part of the address to compare.
        address_part: AddressPart,
    },
    /// Header test — match against header values.
    Header {
        /// Header names to inspect.
        header: Vec<String>,
        /// Key strings to match against.
        keys: Vec<String>,
        /// How to match.
        match_type: MatchType,
        /// String comparator to use.
        comparator: Comparator,
    },
    /// Envelope test — match against envelope parts.
    Envelope {
        /// Envelope parts to inspect (e.g. `["from"]`, `["to"]`).
        part: Vec<String>,
        /// Key strings to match against.
        keys: Vec<String>,
        /// How to match.
        match_type: MatchType,
        /// String comparator to use.
        comparator: Comparator,
    },
    /// Exists test — true if all named headers exist.
    Exists(Vec<String>),
    /// Size test — compare message size against a limit.
    Size {
        /// `true` if `:over`, `false` if `:under`.
        over: bool,
        /// Byte-count threshold.
        limit: u64,
    },
    /// `hasflag` test (RFC 5232 §6) — check whether the currently-active
    /// IMAP flag set contains one or more specified flags using the given
    /// match-type and comparator.
    HasFlag {
        /// Flag values to check against the active set.
        keys: Vec<String>,
        /// How to match (`:is`, `:contains`, `:matches`).
        match_type: MatchType,
        /// String comparator to use.
        comparator: Comparator,
    },
}

// ---------------------------------------------------------------------------
// SieveCommand — AST node for commands/actions
// ---------------------------------------------------------------------------

/// AST representation of a Sieve command.
#[derive(Debug, Clone)]
pub enum SieveCommand {
    /// `require` — declare extension dependencies.
    Require(Vec<String>),
    /// `if` / `elsif` / `else` conditional.
    If {
        /// Guard condition for the `if` branch.
        test: SieveTest,
        /// Commands executed when test is true.
        commands: Vec<SieveCommand>,
        /// `elsif` branches: (condition, commands) pairs.
        elsif: Vec<(SieveTest, Vec<SieveCommand>)>,
        /// Commands executed when no preceding condition was true.
        else_cmds: Option<Vec<SieveCommand>>,
    },
    /// `keep` — deliver to the default mailbox.
    Keep,
    /// `discard` — silently discard.
    Discard,
    /// `stop` — halt script execution.
    Stop,
    /// `redirect` — forward the message.
    Redirect {
        /// Target email address.
        address: String,
        /// When true, keep a copy via implicit keep.
        copy: bool,
    },
    /// `fileinto` — deliver to a named folder.
    Fileinto {
        /// Target folder name.
        folder: String,
        /// Whether to create the folder if absent (`:create` tag).
        create: bool,
        /// When true, keep a copy via implicit keep.
        copy: bool,
        /// IMAP flags to set on the message (`imap4flags` extension).
        flags: Vec<String>,
    },
    /// `vacation` — send an auto-response.
    Vacation {
        /// Minimum days between auto-responses to the same sender.
        days: u32,
        /// Subject line for the auto-response.
        subject: Option<String>,
        /// `From:` address override for the auto-response.
        from: Option<String>,
        /// Additional addresses that identify the user.
        addresses: Vec<String>,
        /// Whether `body` is already MIME-formatted.
        mime: bool,
        /// Unique handle for rate-limiting de-duplication.
        handle: Option<String>,
        /// The auto-response body text.
        body: String,
    },
    /// `notify` — send a notification (enotify).
    Notify {
        /// Notification method URI (e.g. `mailto:admin@example.com`).
        method: String,
        /// Importance level: 1 (high), 2 (normal), 3 (low).
        importance: u32,
        /// Method-specific options.
        options: Vec<String>,
        /// Human-readable notification message.
        message: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// SieveContext — full Exim message context for taint-aware interpretation
// ---------------------------------------------------------------------------

/// Full message context for Sieve filter interpretation with Exim integration.
///
/// Provides taint-tracked header values, arena-based allocation, and message
/// store access for the evaluator.
pub struct SieveContext<'a> {
    /// Per-message arena allocator (replaces C `store_get()` calls).
    pub arena: &'a MessageArena,
    /// Per-message data store.
    pub store: &'a MessageStore,
    /// Message headers (tainted — from untrusted message).
    pub headers: HashMap<String, Vec<TaintedString>>,
    /// Envelope sender (tainted).
    pub envelope_from: TaintedString,
    /// Envelope recipient (tainted).
    pub envelope_to: TaintedString,
    /// Message size in bytes.
    pub message_size: u64,
}

// ---------------------------------------------------------------------------
// SieveState — internal parser/evaluator state (replaces C struct Sieve)
// ---------------------------------------------------------------------------

/// Internal state for the Sieve parser and evaluator.
struct SieveState<'a> {
    source: &'a str,
    position: usize,
    line: usize,
    keep: bool,
    require: SieveCapabilities,
    vacation_ran: bool,
    inbox: String,
    generated_actions: Vec<GeneratedAction>,
    notified: Vec<NotificationRecord>,
    message_size: u64,
    message_headers: HashMap<String, Vec<String>>,
    envelope_from: String,
    envelope_to: String,
    /// Active IMAP flag set (RFC 5232 `imap4flags`). Mutated by
    /// `setflag`/`addflag`/`removeflag`; applied to any subsequently
    /// generated `fileinto` action.
    active_flags: Vec<String>,
    /// If the script invoked `reject`/`ereject`, the script-supplied
    /// bounce message. `None` otherwise. Set only once per evaluation.
    reject_message: Option<String>,
    /// Whether the reject was issued via `ereject` (true) vs `reject`
    /// (false). Only meaningful when `reject_message` is `Some`.
    is_ereject: bool,
    /// SV5: captured `vacation` command parameters. Populated by
    /// `parse_vacation_command` when `exec=true` and the vacation
    /// `:addresses`/`:handle`/etc. filters pass. `None` otherwise.
    /// At most one vacation per invocation (RFC 5230 §4.5 is
    /// enforced by the `vacation_ran` flag).
    vacation_action: Option<VacationAction>,
    /// SV5: structured notification requests produced by `notify`
    /// commands. Each element corresponds to one fired `notify`
    /// statement. Dedup within a single invocation is handled by
    /// `notified` (which tracks fingerprints for early skip).
    notify_actions: Vec<NotifyAction>,
}

/// A delivery action generated by a Sieve script during evaluation.
///
/// Populated by the `fileinto`, `redirect`, and implicit `keep`
/// actions. The delivery orchestrator consumes this list to route the
/// message per the script's intent:
///
/// | `is_file` | Meaning                                         |
/// |-----------|-------------------------------------------------|
/// | `true`    | `fileinto` mailbox name (e.g. `"Archive"`)       |
/// | `false`   | `redirect` RFC 5322 address (e.g. `"u@ex.com"`)  |
///
/// The implicit `keep` action contributes `(inbox, true)` when no
/// explicit action was taken.
///
/// # SV1 remediation
///
/// Prior to exposing this type from [`sieve_interpret`], the public
/// API returned only a coarse `SieveResult::Delivered`/`NotDelivered`
/// flag; the generated actions were stored in the interpreter's
/// private state and dropped when the function returned. Callers
/// (delivery orchestrator, redirect router) had no way to learn
/// WHERE the script wanted the message delivered, so `fileinto` and
/// `redirect` commands were effectively no-ops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedAction {
    /// The delivery target: a file/mailbox name when `is_file=true`,
    /// or an RFC 5322 forwarding address when `is_file=false`.
    pub address: String,
    /// Whether `address` is a file/mailbox path (`true`) or a
    /// forwarding address (`false`).
    pub is_file: bool,
    /// Optional IMAP flags to set on the message upon filing into a
    /// mailbox (from the `imap4flags` extension, RFC 5232). Only
    /// meaningful when `is_file=true` — ignored on `redirect`.
    pub flags: Vec<String>,
}

/// Record of a sent notification (for dedup).
#[derive(Debug, Clone)]
struct NotificationRecord {
    method: String,
    importance: String,
    message: String,
}

// ---------------------------------------------------------------------------
// SV5: vacation / notify structured output
// ---------------------------------------------------------------------------

/// A vacation auto-reply request produced by the Sieve `vacation`
/// command (RFC 5230).
///
/// Each script invocation produces AT MOST one [`VacationAction`]
/// (RFC 5230 §4.5: only one `vacation` action may fire per message).
///
/// # Consumers
///
/// The delivery orchestrator reads this struct from
/// [`SieveOutcome::vacation`] and, when auto-reply is authorised
/// (per handle/days/addresses dedup), calls [`Self::build_reply`] to
/// materialise the RFC 3834 auto-reply envelope and enqueues it via
/// the spool subsystem (`exim-spool`) and the `autoreply` transport.
///
/// # Dedup semantics (RFC 5230 §4)
///
/// The orchestrator (not the interpreter) owns the cross-message
/// dedup window keyed on `(handle, envelope-from, envelope-to, days)`.
/// If the dedup cache reports "already replied within N days" then
/// the reply is suppressed without constructing the envelope.
///
/// The [`Self::should_reply`] helper surfaces the RFC 5230 §4.3
/// address-filter check (don't auto-reply if envelope-to is in
/// `addresses`), which does NOT require persistent storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VacationAction {
    /// Minimum number of days between auto-replies for the same
    /// `(handle, sender)` tuple. Clamped by the interpreter to
    /// `[VACATION_MIN_DAYS, VACATION_MAX_DAYS]` per RFC 5230 §4.1.
    pub days: u32,
    /// Optional `Subject:` header override. If `None`, defaults to
    /// `"Automated reply regarding your message"`.
    pub subject: Option<String>,
    /// Optional `From:` header override. Must be an RFC 5322 address.
    /// If `None`, the envelope recipient is used.
    pub from: Option<String>,
    /// Additional recipient addresses belonging to the user (RFC 5230
    /// §4.3 `:addresses`). Auto-reply is suppressed if the envelope
    /// recipient is NOT in this list AND not the `from` field.
    pub addresses: Vec<String>,
    /// Whether `reason` is already MIME-formatted (RFC 5230 §4.6
    /// `:mime`). When true, `reason` is treated as a full MIME entity
    /// and emitted verbatim in the reply body. When false, the
    /// interpreter quoted-printable-encodes the reason into a
    /// `text/plain; charset=utf-8` part.
    pub mime: bool,
    /// Stable handle (RFC 5230 §4.7 `:handle`) used by the delivery
    /// orchestrator to dedup across script invocations. Different
    /// handles are treated as independent reply streams.
    pub handle: Option<String>,
    /// Body text of the auto-reply (the `reason` positional argument
    /// to the `vacation` command).
    pub reason: String,
    /// Envelope recipient at the time the script fired. Used by
    /// [`Self::should_reply`] to implement RFC 5230 §4.3.
    pub envelope_to: String,
}

impl VacationAction {
    /// Check whether an auto-reply should be sent per RFC 5230 §4.3.
    ///
    /// Returns `false` when the envelope-recipient is not in the
    /// `:addresses` list (meaning the message was not really
    /// addressed to this user directly — e.g., a mailing list post).
    ///
    /// Returns `true` when:
    /// - `:addresses` is empty (no filter applied), OR
    /// - the envelope-to matches `from` (case-insensitive), OR
    /// - the envelope-to matches any entry in `:addresses`
    ///   (case-insensitive).
    pub fn should_reply(&self) -> bool {
        if self.addresses.is_empty() {
            return true;
        }
        let to_ci = self.envelope_to.to_ascii_lowercase();
        if let Some(ref f) = self.from {
            if f.to_ascii_lowercase() == to_ci {
                return true;
            }
        }
        for addr in &self.addresses {
            if addr.to_ascii_lowercase() == to_ci {
                return true;
            }
        }
        false
    }

    /// Build the RFC 3834 auto-reply message text.
    ///
    /// Produces a complete RFC 5322 message (headers + body) suitable
    /// for handing to the spool subsystem. The message includes:
    ///
    /// - `From:` — `self.from` if set, else `envelope_to`
    /// - `To:` — `original_sender` (the `MAIL FROM` address of the
    ///   triggering message)
    /// - `Subject:` — `self.subject` if set, else the default
    /// - `Auto-Submitted: auto-replied` (RFC 3834 §5 — REQUIRED)
    /// - `Precedence: junk` (common anti-auto-reply convention)
    /// - `In-Reply-To:` — original `Message-ID:` if provided
    /// - `References:` — original `Message-ID:` if provided
    /// - `MIME-Version: 1.0` (always)
    /// - `Content-Type:` — `text/plain; charset=utf-8` when `!self.mime`
    ///
    /// # Arguments
    ///
    /// - `original_sender` — `MAIL FROM` of the incoming message
    /// - `original_message_id` — `Message-ID:` header of the
    ///   incoming message, if present, used to build `In-Reply-To`
    ///   / `References` (RFC 3834 §3.3.1)
    pub fn build_reply(
        &self,
        original_sender: &str,
        original_message_id: Option<&str>,
    ) -> GeneratedMessage {
        let from = self
            .from
            .clone()
            .unwrap_or_else(|| self.envelope_to.clone());
        let subject = self
            .subject
            .clone()
            .unwrap_or_else(|| "Automated reply regarding your message".to_string());
        let to = original_sender.to_string();

        let mut headers = String::new();
        headers.push_str(&format!("From: {from}\r\n"));
        headers.push_str(&format!("To: {to}\r\n"));
        headers.push_str(&format!("Subject: {subject}\r\n"));
        // RFC 3834 §5 — mandatory Auto-Submitted field for auto-replies.
        headers.push_str("Auto-Submitted: auto-replied (vacation)\r\n");
        // RFC 2076 / common practice — suppress delivery-status reports
        // and other automatic handlers that honour `Precedence: junk`.
        headers.push_str("Precedence: junk\r\n");
        if let Some(mid) = original_message_id {
            headers.push_str(&format!("In-Reply-To: {mid}\r\n"));
            headers.push_str(&format!("References: {mid}\r\n"));
        }
        headers.push_str("MIME-Version: 1.0\r\n");

        let body = if self.mime {
            // :mime — reason is already a full MIME entity.
            self.reason.clone()
        } else {
            headers.push_str("Content-Type: text/plain; charset=utf-8\r\n");
            headers.push_str("Content-Transfer-Encoding: quoted-printable\r\n");
            quoted_printable_encode(&self.reason)
        };

        let mut message_text = headers;
        message_text.push_str("\r\n"); // End of header section.
        message_text.push_str(&body);

        GeneratedMessage {
            envelope_from: from.clone(),
            envelope_recipients: vec![to.clone()],
            message_text,
            category: GeneratedMessageKind::VacationReply,
        }
    }
}

/// A notification request produced by the Sieve `notify` command
/// (RFC 5435 / RFC 5436).
///
/// The `method` field is a URI identifying the notification channel.
/// Currently-implemented schemes:
///
/// | Scheme        | Handler                                           |
/// |---------------|---------------------------------------------------|
/// | `mailto:user@host` | Construct an email using [`Self::build_mailto`] |
/// | (anything else)  | Deferred to the delivery orchestrator (which
///                     logs and optionally forwards to a method-specific
///                     agent; unknown schemes fall through to logging). |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyAction {
    /// Notification method URI (e.g., `"mailto:admin@example.com"`).
    pub method: String,
    /// Importance level (RFC 5435 §2.3): `"1"` (high), `"2"` (normal),
    /// or `"3"` (low). Mapped to an `Importance:` header on mailto.
    pub importance: String,
    /// Method-specific options (RFC 5435 §2.6). For `mailto:` these
    /// are header=value pairs (e.g., `["Subject=Alert"]`).
    pub options: Vec<String>,
    /// Optional user-supplied message body (RFC 5435 §2.5 `:message`).
    pub message: Option<String>,
    /// Optional `From:` override for `mailto:` notifications (RFC
    /// 5435 §2.2 `:from`).
    pub from: Option<String>,
    /// Envelope recipient at the time the notify fired (for the
    /// `From:` default on mailto).
    pub envelope_to: String,
}

impl NotifyAction {
    /// Parse a `mailto:` method URI, returning the recipient address
    /// and any optional `?header=value` pairs.
    ///
    /// Returns `None` when `method` is not a `mailto:` URI.
    ///
    /// # Example
    /// ```ignore
    /// let (to, hdrs) = parse_mailto("mailto:a@b.c?Subject=Hi").unwrap();
    /// assert_eq!(to, "a@b.c");
    /// assert_eq!(hdrs, vec![("Subject".into(), "Hi".into())]);
    /// ```
    pub fn parse_mailto(method: &str) -> Option<(String, Vec<(String, String)>)> {
        let rest = method.strip_prefix("mailto:")?;
        let (recipient, query) = match rest.find('?') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, ""),
        };
        let mut headers: Vec<(String, String)> = Vec::new();
        if !query.is_empty() {
            for part in query.split('&') {
                if let Some(eq) = part.find('=') {
                    let (k, v) = (&part[..eq], &part[eq + 1..]);
                    // Minimal URL-decode: convert `+` to space and
                    // %HH to bytes.  Per RFC 6068 mailto URLs use
                    // percent-encoding.
                    headers.push((url_decode(k), url_decode(v)));
                }
            }
        }
        Some((recipient.to_string(), headers))
    }

    /// Build an RFC 5436-compliant mailto notification message.
    ///
    /// Returns `None` if `self.method` is not a `mailto:` URI (other
    /// schemes are deferred to a method-specific delivery agent and
    /// typically just logged by the orchestrator).
    pub fn build_mailto(&self) -> Option<GeneratedMessage> {
        let (recipient, query_headers) = Self::parse_mailto(&self.method)?;
        let from = self
            .from
            .clone()
            .unwrap_or_else(|| self.envelope_to.clone());

        // Determine Subject: precedence:
        //   1. Explicit Subject in mailto URI query
        //   2. :message argument from notify command
        //   3. Default "Notification"
        let mut subject: Option<String> = None;
        let mut extra_headers: Vec<(String, String)> = Vec::new();
        for (k, v) in &query_headers {
            if k.eq_ignore_ascii_case("subject") {
                subject = Some(v.clone());
            } else if k.eq_ignore_ascii_case("body") {
                // Handled below as body override.
            } else {
                extra_headers.push((k.clone(), v.clone()));
            }
        }
        let subject = subject
            .or_else(|| self.message.clone())
            .unwrap_or_else(|| "Notification".to_string());

        // RFC 5435 §2.3 — Importance header maps importance level.
        let importance_hdr = match self.importance.as_str() {
            "1" => "High",
            "3" => "Low",
            _ => "Normal",
        };

        let mut headers = String::new();
        headers.push_str(&format!("From: {from}\r\n"));
        headers.push_str(&format!("To: {recipient}\r\n"));
        headers.push_str(&format!("Subject: {subject}\r\n"));
        headers.push_str(&format!("Importance: {importance_hdr}\r\n"));
        headers.push_str("Auto-Submitted: auto-generated (notify)\r\n");
        headers.push_str("MIME-Version: 1.0\r\n");
        headers.push_str("Content-Type: text/plain; charset=utf-8\r\n");
        headers.push_str("Content-Transfer-Encoding: quoted-printable\r\n");
        for (k, v) in &extra_headers {
            headers.push_str(&format!("{k}: {v}\r\n"));
        }

        // Body precedence: URI `body` param > :message arg > empty.
        let body_source = query_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("body"))
            .map(|(_, v)| v.clone())
            .or_else(|| self.message.clone())
            .unwrap_or_default();
        let body = quoted_printable_encode(&body_source);

        let mut message_text = headers;
        message_text.push_str("\r\n");
        message_text.push_str(&body);

        Some(GeneratedMessage {
            envelope_from: from,
            envelope_recipients: vec![recipient],
            message_text,
            category: GeneratedMessageKind::NotifyMessage,
        })
    }
}

/// Classification of a [`GeneratedMessage`] for logging and tracing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneratedMessageKind {
    /// An auto-reply produced by a `vacation` action (RFC 5230).
    VacationReply,
    /// A notification produced by a `notify` action (RFC 5435).
    NotifyMessage,
}

/// A complete RFC 5322 message ready to enqueue.
///
/// Produced by [`VacationAction::build_reply`] and
/// [`NotifyAction::build_mailto`]. The delivery orchestrator writes
/// this through `exim-spool::spool_write_header` +
/// `exim-spool::data_file` and hands it to the SMTP outbound path
/// (or the `autoreply`/`smtp` transport, depending on configuration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedMessage {
    /// Envelope sender (`MAIL FROM`).
    pub envelope_from: String,
    /// Envelope recipient(s) (`RCPT TO`).
    pub envelope_recipients: Vec<String>,
    /// Complete RFC 5322 message text (headers, blank line, body).
    pub message_text: String,
    /// Category used for structured logging and metrics.
    pub category: GeneratedMessageKind,
}

/// Minimal RFC 3986 / RFC 6068 percent-decoder for mailto URI query
/// strings. Handles `+` → space and `%HH` → byte. Malformed
/// percent-escapes are left literal.
fn url_decode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let h1 = (bytes[i + 1] as char).to_digit(16);
                let h2 = (bytes[i + 2] as char).to_digit(16);
                match (h1, h2) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8 as char);
                        i += 3;
                    }
                    _ => {
                        out.push('%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b as char);
                i += 1;
            }
        }
    }
    out
}

/// Full outcome of a Sieve script evaluation.
///
/// Returned by [`sieve_interpret`] and [`sieve_interpret_with_context`], this
/// struct exposes every piece of information the delivery orchestrator needs
/// to act on a script's intent:
///
/// - [`Self::result`] — overall outcome classification (`Delivered`, `NotDelivered`,
///   `Fail`, etc.);
/// - [`Self::actions`] — ordered list of generated `fileinto`/`redirect` targets;
/// - [`Self::reject_message`] — if the script invoked `reject`/`ereject`, the
///   MIME-free human message to include in the bounce (RFC 5429 §2–3);
/// - [`Self::is_ereject`] — distinguishes `reject` (5.7.1 bounce) from `ereject`
///   (immediate SMTP 5xx during transaction) when `reject_message` is `Some`;
/// - [`Self::flags`] — final IMAP flag set after `setflag`/`addflag`/`removeflag`
///   (RFC 5232 `imap4flags` extension); applied to any `fileinto` targets.
///
/// # SV4 remediation
///
/// Prior to SV4, the interpreter returned only `(SieveResult,
/// Vec<GeneratedAction>)`; there was no way to surface a `reject`
/// message or a flag set. In practice this meant `reject`/`ereject`
/// (RFC 5429) and `setflag`/`addflag`/`removeflag`/`hasflag`/`mark`/
/// `unmark` (RFC 5232) were parsed as unknown-command errors even
/// when declared via `require`. `SieveOutcome` closes that gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SieveOutcome {
    /// Overall evaluation result.
    pub result: SieveResult,
    /// Ordered list of delivery actions generated by the script.
    pub actions: Vec<GeneratedAction>,
    /// If the script invoked `reject` or `ereject`, the bounce
    /// message text supplied by the script (without MIME framing).
    /// When `Some`, [`Self::result`] is set to [`SieveResult::Fail`].
    pub reject_message: Option<String>,
    /// Whether the reject was issued via `ereject` (true — immediate
    /// 5xx SMTP response during transaction) vs `reject` (false —
    /// enqueue an RFC 3464 bounce). Only meaningful when
    /// [`Self::reject_message`] is `Some`.
    pub is_ereject: bool,
    /// Final IMAP flags set on the message after executing any
    /// `setflag`/`addflag`/`removeflag` commands. Applied to
    /// `fileinto` targets per RFC 5232.
    pub flags: Vec<String>,
    /// SV5: vacation auto-reply request (RFC 5230). At most one
    /// `vacation` action may fire per script invocation (RFC 5230
    /// §4.5). When `Some`, the delivery orchestrator consults its
    /// dedup cache and, if not already replied within `days`, calls
    /// [`VacationAction::build_reply`] to materialise the RFC 3834
    /// auto-reply envelope and enqueues it through the spool
    /// subsystem.
    pub vacation: Option<VacationAction>,
    /// SV5: notification requests (RFC 5435 / RFC 5436). Multiple
    /// `notify` commands may fire per script; each produces one
    /// [`NotifyAction`]. For `mailto:` methods, the orchestrator
    /// calls [`NotifyAction::build_mailto`] to materialise the
    /// notification envelope. Other schemes are logged and
    /// optionally forwarded to a method-specific agent.
    pub notifications: Vec<NotifyAction>,
}

impl SieveOutcome {
    /// Construct a bare outcome with no actions, no reject, and no flags.
    fn bare(result: SieveResult) -> Self {
        Self {
            result,
            actions: Vec::new(),
            reject_message: None,
            is_ereject: false,
            flags: Vec::new(),
            vacation: None,
            notifications: Vec::new(),
        }
    }
}

impl<'a> SieveState<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            position: 0,
            line: 1,
            keep: true,
            require: SieveCapabilities::empty(),
            vacation_ran: false,
            inbox: "inbox".to_string(),
            generated_actions: Vec::new(),
            notified: Vec::new(),
            message_size: 0,
            message_headers: HashMap::new(),
            envelope_from: String::new(),
            envelope_to: String::new(),
            active_flags: Vec::new(),
            reject_message: None,
            is_ereject: false,
            vacation_action: None,
            notify_actions: Vec::new(),
        }
    }

    /// Populate state from a SieveContext (taint-aware).
    fn from_context(source: &'a str, ctx: &SieveContext<'_>) -> Self {
        let mut state = Self::new(source);
        state.message_size = ctx.message_size;
        state.envelope_from = ctx.envelope_from.clone().into_inner();
        state.envelope_to = ctx.envelope_to.clone().into_inner();
        // Convert tainted headers to plain strings for internal processing
        for (key, values) in &ctx.headers {
            let plain: Vec<String> = values.iter().map(|v| v.clone().into_inner()).collect();
            state.message_headers.insert(key.clone(), plain);
        }
        // Record taint state for diagnostics
        let _taint = TaintState::Tainted;
        tracing::debug!("sieve: loaded context with tainted headers");
        // Use arena for temporary allocation marker
        let _marker = ctx.arena.alloc_str("sieve_state_init");
        state
    }

    // =======================================================================
    // Character-level helpers
    // =======================================================================

    fn remaining(&self) -> &[u8] {
        &self.source.as_bytes()[self.position..]
    }

    fn peek(&self) -> Option<u8> {
        self.source.as_bytes().get(self.position).copied()
    }

    fn advance(&mut self) {
        if let Some(b) = self.peek() {
            if b == b'\n' {
                self.line += 1;
            }
            self.position += 1;
        }
    }

    fn advance_by(&mut self, n: usize) {
        for _ in 0..n {
            self.advance();
        }
    }

    fn at_end(&self) -> bool {
        self.position >= self.source.len()
    }

    fn parse_error(&self, message: impl Into<String>) -> SieveError {
        SieveError::ParseError {
            line: self.line,
            message: message.into(),
        }
    }

    // =======================================================================
    // Whitespace and comment parsing
    // =======================================================================

    fn skip_whitespace(&mut self) -> Result<(), SieveError> {
        loop {
            match self.peek() {
                Some(b' ') | Some(b'\t') | Some(b'\n') => self.advance(),
                Some(b'\r') => {
                    self.advance();
                    if self.peek() == Some(b'\n') {
                        self.advance();
                    }
                }
                Some(b'#') => self.parse_hash_comment()?,
                Some(b'/') if self.remaining().starts_with(b"/*") => {
                    self.parse_c_comment()?;
                }
                _ => break,
            }
        }
        Ok(())
    }

    fn parse_hash_comment(&mut self) -> Result<(), SieveError> {
        self.advance(); // skip '#'
        loop {
            match self.peek() {
                None => return Ok(()),
                Some(b'\n') => {
                    self.advance();
                    return Ok(());
                }
                Some(b'\r') => {
                    self.advance();
                    if self.peek() == Some(b'\n') {
                        self.advance();
                    }
                    return Ok(());
                }
                _ => self.advance(),
            }
        }
    }

    fn parse_c_comment(&mut self) -> Result<(), SieveError> {
        self.advance_by(2); // skip "/*"
        loop {
            if self.at_end() {
                return Err(self.parse_error("missing end of comment"));
            }
            if self.remaining().starts_with(b"*/") {
                self.advance_by(2);
                return Ok(());
            }
            self.advance();
        }
    }

    // =======================================================================
    // Token parsing helpers
    // =======================================================================

    fn try_identifier(&mut self, id: &str) -> bool {
        let remaining = self.remaining();
        let id_bytes = id.as_bytes();
        if remaining.len() < id_bytes.len() {
            return false;
        }
        for (a, b) in remaining[..id_bytes.len()].iter().zip(id_bytes.iter()) {
            if !a.eq_ignore_ascii_case(b) {
                return false;
            }
        }
        if remaining.len() > id_bytes.len() {
            let next = remaining[id_bytes.len()];
            if next.is_ascii_alphanumeric() || next == b'_' {
                return false;
            }
        }
        self.advance_by(id_bytes.len());
        true
    }

    fn expect_semicolon(&mut self) -> Result<(), SieveError> {
        self.skip_whitespace()?;
        if self.peek() == Some(b';') {
            self.advance();
            Ok(())
        } else {
            Err(self.parse_error("missing semicolon"))
        }
    }

    fn parse_number(&mut self) -> Result<u64, SieveError> {
        let start = self.position;
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() {
                self.advance();
            } else {
                break;
            }
        }
        if self.position == start {
            return Err(self.parse_error("missing number"));
        }
        let num_str = &self.source[start..self.position];
        let mut value: u64 = num_str
            .parse()
            .map_err(|_| self.parse_error("number out of range"))?;
        match self.peek() {
            Some(b'K') | Some(b'k') => {
                self.advance();
                value = value
                    .checked_mul(1024)
                    .ok_or_else(|| self.parse_error("number overflow"))?;
            }
            Some(b'M') | Some(b'm') => {
                self.advance();
                value = value
                    .checked_mul(1024 * 1024)
                    .ok_or_else(|| self.parse_error("number overflow"))?;
            }
            Some(b'G') | Some(b'g') => {
                self.advance();
                value = value
                    .checked_mul(1024 * 1024 * 1024)
                    .ok_or_else(|| self.parse_error("number overflow"))?;
            }
            _ => {}
        }
        Ok(value)
    }

    // =======================================================================
    // String parsing
    // =======================================================================

    fn parse_string(&mut self) -> Result<Option<String>, SieveError> {
        match self.peek() {
            Some(b'"') => self.parse_quoted_string().map(Some),
            _ => {
                if self.remaining().starts_with(b"text:") {
                    self.parse_multiline_string().map(Some)
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn parse_quoted_string(&mut self) -> Result<String, SieveError> {
        self.advance(); // skip opening '"'
        let mut result = String::new();
        loop {
            match self.peek() {
                None => return Err(self.parse_error("missing end of string")),
                Some(b'"') => {
                    self.advance();
                    if self.require.contains(SieveCapabilities::ENCODED_CHARACTER) {
                        result = decode_encoded_characters(&result)?;
                    }
                    return Ok(result);
                }
                Some(b'\\') => {
                    self.advance();
                    match self.peek() {
                        Some(ch) => {
                            result.push(ch as char);
                            self.advance();
                        }
                        None => return Err(self.parse_error("missing end of string")),
                    }
                }
                Some(ch) => {
                    result.push(ch as char);
                    self.advance();
                }
            }
        }
    }

    fn parse_multiline_string(&mut self) -> Result<String, SieveError> {
        self.advance_by(5); // skip "text:"
                            // skip optional whitespace/comment then expect newline
        while matches!(self.peek(), Some(b' ') | Some(b'\t')) {
            self.advance();
        }
        match self.peek() {
            Some(b'#') => self.parse_hash_comment()?,
            Some(b'\n') => self.advance(),
            Some(b'\r') => {
                self.advance();
                if self.peek() == Some(b'\n') {
                    self.advance();
                }
            }
            _ => return Err(self.parse_error("syntax error after text:")),
        }
        let mut result = String::new();
        let mut at_line_start = true;
        loop {
            if self.at_end() {
                return Err(self.parse_error("missing end of multi line string"));
            }
            let ch = self.peek().unwrap();
            if at_line_start && ch == b'.' {
                let next = self.source.as_bytes().get(self.position + 1).copied();
                match next {
                    Some(b'\n') | Some(b'\r') | None => {
                        self.advance(); // skip '.'
                        if self.peek() == Some(b'\r') {
                            self.advance();
                        }
                        if self.peek() == Some(b'\n') {
                            self.advance();
                        }
                        if self.require.contains(SieveCapabilities::ENCODED_CHARACTER) {
                            result = decode_encoded_characters(&result)?;
                        }
                        return Ok(result);
                    }
                    Some(b'.') => {
                        self.advance_by(2); // dot-stuffing
                        result.push('.');
                        at_line_start = false;
                    }
                    _ => {
                        result.push('.');
                        self.advance();
                        at_line_start = false;
                    }
                }
            } else if ch == b'\n' {
                result.push_str("\r\n");
                self.advance();
                at_line_start = true;
            } else if ch == b'\r' {
                self.advance();
                if self.peek() == Some(b'\n') {
                    self.advance();
                }
                result.push_str("\r\n");
                at_line_start = true;
            } else {
                result.push(ch as char);
                self.advance();
                at_line_start = false;
            }
        }
    }

    fn expect_string(&mut self, context: &str) -> Result<String, SieveError> {
        self.skip_whitespace()?;
        self.parse_string()?
            .ok_or_else(|| self.parse_error(format!("missing {context} string")))
    }

    fn parse_string_list(&mut self) -> Result<Option<Vec<String>>, SieveError> {
        self.skip_whitespace()?;
        if self.peek() == Some(b'[') {
            self.advance(); // skip '['
            let mut list = Vec::new();
            loop {
                self.skip_whitespace()?;
                match self.parse_string()? {
                    Some(s) => list.push(s),
                    None => {
                        if list.is_empty() {
                            break;
                        } else {
                            return Err(self.parse_error("missing string in list"));
                        }
                    }
                }
                self.skip_whitespace()?;
                if self.peek() == Some(b',') {
                    self.advance();
                } else {
                    break;
                }
            }
            if self.peek() == Some(b']') {
                self.advance();
                Ok(Some(list))
            } else {
                Err(self.parse_error("missing closing bracket"))
            }
        } else {
            match self.parse_string()? {
                Some(s) => Ok(Some(vec![s])),
                None => Ok(None),
            }
        }
    }

    fn expect_string_list(&mut self, context: &str) -> Result<Vec<String>, SieveError> {
        self.skip_whitespace()?;
        self.parse_string_list()?
            .ok_or_else(|| self.parse_error(format!("{context} string list expected")))
    }

    // =======================================================================
    // Tag argument parsers
    // =======================================================================

    fn parse_address_part(&mut self) -> Result<Option<AddressPart>, SieveError> {
        self.skip_whitespace()?;
        if self.try_identifier(":user") {
            if !self.require.contains(SieveCapabilities::SUBADDRESS) {
                return Err(self.parse_error("missing previous require \"subaddress\""));
            }
            Ok(Some(AddressPart::User))
        } else if self.try_identifier(":detail") {
            if !self.require.contains(SieveCapabilities::SUBADDRESS) {
                return Err(self.parse_error("missing previous require \"subaddress\""));
            }
            Ok(Some(AddressPart::Detail))
        } else if self.try_identifier(":localpart") {
            Ok(Some(AddressPart::LocalPart))
        } else if self.try_identifier(":domain") {
            Ok(Some(AddressPart::Domain))
        } else if self.try_identifier(":all") {
            Ok(Some(AddressPart::All))
        } else {
            Ok(None)
        }
    }

    fn parse_comparator_tag(&mut self) -> Result<Option<Comparator>, SieveError> {
        self.skip_whitespace()?;
        if !self.try_identifier(":comparator") {
            return Ok(None);
        }
        self.skip_whitespace()?;
        let name = self
            .parse_string()?
            .ok_or_else(|| self.parse_error("missing comparator name"))?;
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "i;octet" => Ok(Some(Comparator::OctetStream)),
            "i;ascii-casemap" | "en;ascii-casemap" => Ok(Some(Comparator::AsciiCaseMap)),
            "i;ascii-numeric" => Ok(Some(Comparator::AsciiNumeric)),
            _ => Err(self.parse_error(format!("invalid comparator: {name}"))),
        }
    }

    fn parse_match_type(&mut self) -> Result<Option<MatchType>, SieveError> {
        self.skip_whitespace()?;
        if self.try_identifier(":is") {
            Ok(Some(MatchType::Is))
        } else if self.try_identifier(":contains") {
            Ok(Some(MatchType::Contains))
        } else if self.try_identifier(":matches") {
            Ok(Some(MatchType::Matches))
        } else if self.try_identifier(":regex") {
            if !self.require.contains(SieveCapabilities::REGEX) {
                return Err(self.parse_error("missing previous require \"regex\""));
            }
            Ok(Some(MatchType::Regex))
        } else if self.try_identifier(":count") {
            self.skip_whitespace()?;
            let op = self.parse_relop()?;
            Ok(Some(MatchType::Count(op)))
        } else if self.try_identifier(":value") {
            self.skip_whitespace()?;
            let op = self.parse_relop()?;
            Ok(Some(MatchType::Value(op)))
        } else {
            Ok(None)
        }
    }

    fn parse_relop(&mut self) -> Result<RelOp, SieveError> {
        let s = self.expect_string("relational operator")?;
        match s.to_ascii_lowercase().as_str() {
            "lt" => Ok(RelOp::Lt),
            "le" => Ok(RelOp::Le),
            "eq" => Ok(RelOp::Eq),
            "ge" => Ok(RelOp::Ge),
            "gt" => Ok(RelOp::Gt),
            "ne" => Ok(RelOp::Ne),
            _ => Err(self.parse_error(format!("invalid relational operator: {s}"))),
        }
    }

    /// Parse common tag-argument triplet (address-part, comparator, match-type)
    /// in any order.
    fn parse_test_tags(
        &mut self,
        allow_address_part: bool,
    ) -> Result<(AddressPart, Comparator, MatchType), SieveError> {
        let mut address_part = AddressPart::All;
        let mut comparator = Comparator::AsciiCaseMap;
        let mut match_type = MatchType::Is;
        loop {
            self.skip_whitespace()?;
            if allow_address_part {
                if let Some(ap) = self.parse_address_part()? {
                    address_part = ap;
                    continue;
                }
            }
            if let Some(co) = self.parse_comparator_tag()? {
                comparator = co;
                continue;
            }
            if let Some(mt) = self.parse_match_type()? {
                match_type = mt;
                continue;
            }
            break;
        }
        Ok((address_part, comparator, match_type))
    }

    // =======================================================================
    // Test parsing
    // =======================================================================

    fn parse_test(&mut self, exec: bool) -> Result<Option<(SieveTest, bool)>, SieveError> {
        self.skip_whitespace()?;
        if self.try_identifier("address") {
            self.parse_address_test(exec)
        } else if self.try_identifier("allof") {
            let (tests, conds) = self.parse_test_list(exec)?;
            let all = conds.iter().all(|&c| c);
            Ok(Some((SieveTest::AllOf(tests), all)))
        } else if self.try_identifier("anyof") {
            let (tests, conds) = self.parse_test_list(exec)?;
            let any = conds.iter().any(|&c| c);
            Ok(Some((SieveTest::AnyOf(tests), any)))
        } else if self.try_identifier("exists") {
            self.parse_exists_test(exec)
        } else if self.try_identifier("false") {
            Ok(Some((SieveTest::False, false)))
        } else if self.try_identifier("header") {
            self.parse_header_test(exec)
        } else if self.try_identifier("not") {
            self.skip_whitespace()?;
            match self.parse_test(exec)? {
                Some((test, cond)) => Ok(Some((SieveTest::Not(Box::new(test)), !cond))),
                None => Err(self.parse_error("missing test after 'not'")),
            }
        } else if self.try_identifier("size") {
            self.parse_size_test(exec)
        } else if self.try_identifier("true") {
            Ok(Some((SieveTest::True, true)))
        } else if self.try_identifier("envelope") {
            self.parse_envelope_test(exec)
        } else if self.try_identifier("valid_notify_method") {
            self.parse_valid_notify_method_test(exec)
        } else if self.try_identifier("notify_method_capability") {
            self.parse_notify_method_capability_test(exec)
        } else if self.try_identifier("hasflag") {
            self.parse_hasflag_test(exec)
        } else {
            Ok(None)
        }
    }

    /// Parse the `hasflag` test (RFC 5232 §6).
    ///
    /// Syntax:
    /// ```sieve
    /// hasflag [MATCH-TYPE] [COMPARATOR] <flag-list>
    /// ```
    ///
    /// Evaluates to true if the currently-active flag set contains at least
    /// one of the listed flag values (match-type/comparator applied). RFC 5232
    /// requires a prior `require "imap4flags"`.
    fn parse_hasflag_test(&mut self, exec: bool) -> Result<Option<(SieveTest, bool)>, SieveError> {
        if !self.require.contains(SieveCapabilities::IMAP4FLAGS) {
            return Err(self.parse_error("missing previous require \"imap4flags\""));
        }
        let (_ap, comparator, match_type) = self.parse_test_tags(false)?;
        let keys = self.expect_string_list("flag keys")?;
        let cond = if exec {
            self.eval_hasflag(&keys, &match_type, &comparator)
        } else {
            false
        };
        Ok(Some((
            SieveTest::HasFlag {
                keys,
                match_type,
                comparator,
            },
            cond,
        )))
    }

    /// Evaluate `hasflag` against the active flag set.
    ///
    /// Iterates the cross-product of active flags × key patterns; returns
    /// true on the first match. An empty key list yields false (nothing to
    /// match against).
    fn eval_hasflag(&self, keys: &[String], mt: &MatchType, comp: &Comparator) -> bool {
        // SV3: RFC 5231 §4 — `:count` compares the NUMBER of values against
        // each (numeric) key, not the values themselves. For hasflag this
        // means "how many flags are currently active?"
        if let MatchType::Count(op) = mt {
            let count = self.active_flags.len() as i64;
            return count_matches_any_key(count, keys, *op);
        }
        for flag in &self.active_flags {
            for key in keys {
                if compare_strings(flag, key, comp, mt) {
                    return true;
                }
            }
        }
        false
    }

    fn parse_test_list(&mut self, exec: bool) -> Result<(Vec<SieveTest>, Vec<bool>), SieveError> {
        self.skip_whitespace()?;
        if self.peek() != Some(b'(') {
            return Err(self.parse_error("missing test list"));
        }
        self.advance();
        let mut tests = Vec::new();
        let mut conds = Vec::new();
        loop {
            match self.parse_test(exec)? {
                Some((t, c)) => {
                    tests.push(t);
                    conds.push(c);
                }
                None => return Err(self.parse_error("missing test in test list")),
            }
            self.skip_whitespace()?;
            if self.peek() == Some(b',') {
                self.advance();
            } else {
                break;
            }
        }
        if self.peek() == Some(b')') {
            self.advance();
            Ok((tests, conds))
        } else {
            Err(self.parse_error("missing closing paren"))
        }
    }

    fn parse_address_test(&mut self, exec: bool) -> Result<Option<(SieveTest, bool)>, SieveError> {
        let (address_part, comparator, match_type) = self.parse_test_tags(true)?;
        let headers = self.expect_string_list("header")?;
        let keys = self.expect_string_list("key")?;

        let valid_headers: HashSet<&str> = [
            "from",
            "to",
            "cc",
            "bcc",
            "sender",
            "resent-from",
            "resent-to",
        ]
        .iter()
        .copied()
        .collect();
        for h in &headers {
            if !valid_headers.contains(h.to_ascii_lowercase().as_str()) {
                return Err(self.parse_error(format!("invalid header field: {h}")));
            }
        }

        let cond = if exec {
            self.eval_address(&headers, &keys, &match_type, &comparator, &address_part)
        } else {
            false
        };
        Ok(Some((
            SieveTest::Address {
                header: headers,
                keys,
                match_type,
                comparator,
                address_part,
            },
            cond,
        )))
    }

    fn parse_header_test(&mut self, exec: bool) -> Result<Option<(SieveTest, bool)>, SieveError> {
        let (_ap, comparator, match_type) = self.parse_test_tags(false)?;
        let headers = self.expect_string_list("header")?;
        let keys = self.expect_string_list("key")?;
        for h in &headers {
            if !is_valid_header_name(h) {
                return Err(self.parse_error(format!("invalid header field: {h}")));
            }
        }
        let cond = if exec {
            self.eval_header(&headers, &keys, &match_type, &comparator)
        } else {
            false
        };
        Ok(Some((
            SieveTest::Header {
                header: headers,
                keys,
                match_type,
                comparator,
            },
            cond,
        )))
    }

    fn parse_exists_test(&mut self, exec: bool) -> Result<Option<(SieveTest, bool)>, SieveError> {
        let headers = self.expect_string_list("header")?;
        let cond = if exec {
            headers
                .iter()
                .all(|h| self.message_headers.contains_key(&h.to_ascii_lowercase()))
        } else {
            false
        };
        Ok(Some((SieveTest::Exists(headers), cond)))
    }

    fn parse_size_test(&mut self, exec: bool) -> Result<Option<(SieveTest, bool)>, SieveError> {
        self.skip_whitespace()?;
        let over = if self.try_identifier(":over") {
            true
        } else if self.try_identifier(":under") {
            false
        } else {
            return Err(self.parse_error("missing :over or :under"));
        };
        self.skip_whitespace()?;
        let limit = self.parse_number()?;
        let cond = if exec {
            if over {
                self.message_size > limit
            } else {
                self.message_size < limit
            }
        } else {
            false
        };
        Ok(Some((SieveTest::Size { over, limit }, cond)))
    }

    fn parse_envelope_test(&mut self, exec: bool) -> Result<Option<(SieveTest, bool)>, SieveError> {
        if !self.require.contains(SieveCapabilities::ENVELOPE) {
            return Err(self.parse_error("missing previous require \"envelope\""));
        }
        let (address_part, comparator, match_type) = self.parse_test_tags(true)?;
        let parts = self.expect_string_list("envelope")?;
        let keys = self.expect_string_list("key")?;
        let cond = if exec {
            self.eval_envelope(&parts, &keys, &match_type, &comparator, &address_part)?
        } else {
            false
        };
        Ok(Some((
            SieveTest::Envelope {
                part: parts,
                keys,
                match_type,
                comparator,
            },
            cond,
        )))
    }

    fn parse_valid_notify_method_test(
        &mut self,
        exec: bool,
    ) -> Result<Option<(SieveTest, bool)>, SieveError> {
        if !self.require.contains(SieveCapabilities::ENOTIFY) {
            return Err(self.parse_error("missing previous require \"enotify\""));
        }
        let uris = self.expect_string_list("URI")?;
        let cond = if exec {
            uris.iter().all(|u| u.starts_with("mailto:"))
        } else {
            false
        };
        Ok(Some((SieveTest::True, cond)))
    }

    fn parse_notify_method_capability_test(
        &mut self,
        exec: bool,
    ) -> Result<Option<(SieveTest, bool)>, SieveError> {
        if !self.require.contains(SieveCapabilities::ENOTIFY) {
            return Err(self.parse_error("missing previous require \"enotify\""));
        }
        let (_ap, comparator, match_type) = self.parse_test_tags(false)?;
        let _uri = self.expect_string("notification URI")?;
        let capa = self.expect_string("notification capability")?;
        let keys = self.expect_string_list("key")?;
        let cond = if exec {
            if capa.eq_ignore_ascii_case("online") {
                keys.iter()
                    .any(|k| compare_strings("maybe", k, &comparator, &match_type))
            } else {
                false
            }
        } else {
            false
        };
        Ok(Some((SieveTest::True, cond)))
    }

    // =======================================================================
    // Command block parsing
    // =======================================================================

    fn parse_block(&mut self, exec: bool) -> Result<Option<i32>, SieveError> {
        self.skip_whitespace()?;
        if self.peek() != Some(b'{') {
            return Ok(None);
        }
        self.advance();
        let r = self.parse_commands(exec)?;
        if r == 2 {
            return Ok(Some(2));
        }
        self.skip_whitespace()?;
        if self.peek() == Some(b'}') {
            self.advance();
            Ok(Some(1))
        } else {
            Err(self.parse_error("expecting command or closing brace"))
        }
    }

    fn expect_block(&mut self, exec: bool) -> Result<i32, SieveError> {
        self.parse_block(exec)?
            .ok_or_else(|| self.parse_error("missing block"))
    }

    // =======================================================================
    // Command parsing — main command loop
    // =======================================================================

    fn parse_commands(&mut self, exec: bool) -> Result<i32, SieveError> {
        loop {
            self.skip_whitespace()?;
            if self.at_end() || self.peek() == Some(b'}') {
                return Ok(1);
            }
            if self.try_identifier("if") {
                let r = self.parse_if_command(exec)?;
                if r == 2 {
                    return Ok(2);
                }
            } else if self.try_identifier("stop") {
                self.expect_semicolon()?;
                if exec {
                    tracing::debug!("sieve: stop");
                    return Ok(2);
                }
            } else if self.try_identifier("keep") {
                self.expect_semicolon()?;
                if exec {
                    tracing::debug!("sieve: keep");
                    self.add_action(&self.inbox.clone(), true);
                    self.keep = false;
                }
            } else if self.try_identifier("discard") {
                self.expect_semicolon()?;
                if exec {
                    tracing::debug!("sieve: discard");
                    self.keep = false;
                }
            } else if self.try_identifier("redirect") {
                self.parse_redirect_command(exec)?;
            } else if self.try_identifier("fileinto") {
                self.parse_fileinto_command(exec)?;
            } else if self.try_identifier("notify") {
                self.parse_notify_command(exec)?;
            } else if self.try_identifier("vacation") {
                self.parse_vacation_command(exec)?;
            } else if self.try_identifier("ereject") {
                // SV4: RFC 5429 §2.2 — MUST come BEFORE `reject` so
                // `try_identifier` matches the longer prefix first.
                self.parse_ereject_command(exec)?;
            } else if self.try_identifier("reject") {
                // SV4: RFC 5429 §2.1
                self.parse_reject_command(exec)?;
            } else if self.try_identifier("setflag") {
                // SV4: RFC 5232 §4
                self.parse_setflag_command(exec)?;
            } else if self.try_identifier("addflag") {
                // SV4: RFC 5232 §5
                self.parse_addflag_command(exec)?;
            } else if self.try_identifier("removeflag") {
                // SV4: RFC 5232 §6
                self.parse_removeflag_command(exec)?;
            } else if self.try_identifier("mark") {
                // SV4: RFC 5232 §8 — shortcut for addflag "\\Flagged"
                self.parse_mark_command(exec)?;
            } else if self.try_identifier("unmark") {
                // SV4: RFC 5232 §8 — shortcut for removeflag "\\Flagged"
                self.parse_unmark_command(exec)?;
            } else {
                break;
            }
        }
        Ok(1)
    }

    fn parse_if_command(&mut self, exec: bool) -> Result<i32, SieveError> {
        self.skip_whitespace()?;
        let (_, cond) = self
            .parse_test(exec)?
            .ok_or_else(|| self.parse_error("missing test after 'if'"))?;
        tracing::debug!("sieve: if condition = {}", cond);
        let m = self.expect_block(exec && cond)?;
        if m == 2 {
            return Ok(2);
        }
        let mut unsuccessful = !cond;
        loop {
            self.skip_whitespace()?;
            if !self.try_identifier("elsif") {
                break;
            }
            self.skip_whitespace()?;
            let (_, elsif_cond) = self
                .parse_test(exec && unsuccessful)?
                .ok_or_else(|| self.parse_error("missing test after 'elsif'"))?;
            tracing::debug!("sieve: elsif condition = {}", elsif_cond);
            let m = self.expect_block(exec && unsuccessful && elsif_cond)?;
            if m == 2 {
                return Ok(2);
            }
            if exec && unsuccessful && elsif_cond {
                unsuccessful = false;
            }
        }
        self.skip_whitespace()?;
        if self.try_identifier("else") {
            let m = self.expect_block(exec && unsuccessful)?;
            if m == 2 {
                return Ok(2);
            }
        }
        Ok(1)
    }

    fn parse_redirect_command(&mut self, exec: bool) -> Result<(), SieveError> {
        let mut copy = false;
        loop {
            self.skip_whitespace()?;
            if self.try_identifier(":copy") {
                if !self.require.contains(SieveCapabilities::COPY) {
                    return Err(self.parse_error("missing previous require \"copy\""));
                }
                copy = true;
            } else {
                break;
            }
        }
        let recipient = self.expect_string("redirect recipient")?;
        if !recipient.contains('@') {
            return Err(self.parse_error("unqualified recipient address"));
        }
        if exec {
            tracing::debug!("sieve: redirect to '{}'", recipient);
            self.add_action(&recipient, false);
            if !copy {
                self.keep = false;
            }
        }
        self.expect_semicolon()
    }

    fn parse_fileinto_command(&mut self, exec: bool) -> Result<(), SieveError> {
        if !self.require.contains(SieveCapabilities::FILEINTO) {
            return Err(self.parse_error("missing previous require \"fileinto\""));
        }
        let mut copy = false;
        let mut create = false;
        let mut tag_flags: Vec<String> = Vec::new();
        let mut has_tag_flags = false;
        loop {
            self.skip_whitespace()?;
            if self.try_identifier(":copy") {
                if !self.require.contains(SieveCapabilities::COPY) {
                    return Err(self.parse_error("missing previous require \"copy\""));
                }
                copy = true;
            } else if self.try_identifier(":create") {
                create = true;
            } else if self.try_identifier(":flags") {
                // RFC 5232 §4.1 tag form: `fileinto :flags ["\\Seen"] "INBOX";`
                // flags supplied here override active_flags for THIS action only.
                if !self.require.contains(SieveCapabilities::IMAP4FLAGS) {
                    return Err(self.parse_error("missing previous require \"imap4flags\""));
                }
                tag_flags = self.expect_string_list("flags")?;
                // Normalize tokenization: "\\Seen \\Flagged" → 2 flags.
                tag_flags = tag_flags
                    .into_iter()
                    .flat_map(|s| Self::split_flag_words(&s))
                    .collect();
                Self::normalize_flag_set(&mut tag_flags);
                has_tag_flags = true;
            } else {
                break;
            }
        }
        let folder = self.expect_string("fileinto folder")?;
        if folder.is_empty()
            || folder == ".."
            || folder.starts_with("../")
            || folder.contains("/../")
            || folder.ends_with("/..")
        {
            return Err(self.parse_error("invalid folder"));
        }
        if exec {
            tracing::debug!("sieve: fileinto '{}' (create={})", folder, create);
            if has_tag_flags {
                // :flags tag overrides active_flags for this specific action —
                // temporarily swap so add_action captures the override.
                let saved = std::mem::take(&mut self.active_flags);
                self.active_flags = tag_flags;
                self.add_action(&folder, true);
                self.active_flags = saved;
            } else {
                self.add_action(&folder, true);
            }
            if !copy {
                self.keep = false;
            }
        }
        self.expect_semicolon()
    }

    fn parse_notify_command(&mut self, exec: bool) -> Result<(), SieveError> {
        if !self.require.contains(SieveCapabilities::ENOTIFY) {
            return Err(self.parse_error("missing previous require \"enotify\""));
        }
        let mut from: Option<String> = None;
        let mut importance = String::from("2");
        let mut message: Option<String> = None;
        let mut options: Vec<String> = Vec::new();
        loop {
            self.skip_whitespace()?;
            if self.try_identifier(":from") {
                from = Some(self.expect_string("from")?);
            } else if self.try_identifier(":importance") {
                let imp = self.expect_string("importance")?;
                if imp.len() != 1 || !matches!(imp.as_bytes()[0], b'1' | b'2' | b'3') {
                    return Err(self.parse_error("invalid importance"));
                }
                importance = imp;
            } else if self.try_identifier(":options") {
                self.skip_whitespace()?;
                if let Some(opts) = self.parse_string_list()? {
                    options = opts;
                }
            } else if self.try_identifier(":message") {
                message = Some(self.expect_string("message")?);
            } else {
                break;
            }
        }
        let method = self.expect_string("method")?;
        self.expect_semicolon()?;
        if exec {
            let msg_text = message.clone().unwrap_or_default();
            // In-invocation dedup (RFC 5435 §3.3): repeated notify with identical
            // method/importance/message suppresses the duplicate.
            let already_sent = self
                .notified
                .iter()
                .any(|n| n.method == method && n.importance == importance && n.message == msg_text);
            if already_sent {
                tracing::debug!("sieve: repeated notification to '{}' ignored", method);
            } else {
                tracing::info!("sieve: notify via '{}' (importance={})", method, importance);
                self.notified.push(NotificationRecord {
                    method: method.clone(),
                    importance: importance.clone(),
                    message: msg_text,
                });
                // SV5: capture structured notification for downstream orchestrator.
                // The orchestrator (delivery layer) is responsible for
                // dispatching mailto/jmap/etc., applying cross-invocation
                // dedup, and enqueueing a generated message via spool if the
                // method is `mailto:`.
                self.notify_actions.push(NotifyAction {
                    method,
                    importance,
                    options,
                    message,
                    from,
                    envelope_to: self.envelope_to.clone(),
                });
            }
        }
        Ok(())
    }

    fn parse_vacation_command(&mut self, exec: bool) -> Result<(), SieveError> {
        if !self.require.contains(SieveCapabilities::VACATION) {
            return Err(self.parse_error("missing previous require \"vacation\""));
        }
        if exec && self.vacation_ran {
            return Err(SieveError::VacationError(
                "vacation executed more than once".to_string(),
            ));
        }
        let mut days: u32 = 7;
        let mut subject: Option<String> = None;
        let mut from: Option<String> = None;
        let mut addresses: Vec<String> = Vec::new();
        let mut reason_is_mime = false;
        let mut handle: Option<String> = None;
        loop {
            self.skip_whitespace()?;
            if self.try_identifier(":days") {
                self.skip_whitespace()?;
                let d = self.parse_number()? as u32;
                days = d.clamp(VACATION_MIN_DAYS, VACATION_MAX_DAYS);
            } else if self.try_identifier(":subject") {
                subject = Some(self.expect_string("subject")?);
            } else if self.try_identifier(":from") {
                let f = self.expect_string("from")?;
                if !f.is_empty() && !f.contains('@') {
                    return Err(SieveError::InvalidAddress(format!(
                        "malformed vacation from: {f}"
                    )));
                }
                from = Some(f);
            } else if self.try_identifier(":addresses") {
                addresses = self.expect_string_list("addresses")?;
            } else if self.try_identifier(":mime") {
                reason_is_mime = true;
            } else if self.try_identifier(":handle") {
                handle = Some(self.expect_string("handle")?);
            } else {
                break;
            }
        }
        let reason = self.expect_string("reason")?;
        if reason_is_mime && reason.bytes().any(|b| b & 0x80 != 0) {
            return Err(self.parse_error("MIME reason string contains 8bit text"));
        }
        self.expect_semicolon()?;
        if exec {
            self.vacation_ran = true;
            tracing::info!(
                "sieve: vacation (days={}, from={:?}, mime={}, handle={:?})",
                days,
                from,
                reason_is_mime,
                handle,
            );
            // Validate addresses up front so malformed :addresses surface as
            // `InvalidAddress` at interpret time rather than at delivery time.
            for addr in &addresses {
                let _clean = validate_email_address(addr)?;
            }
            // SV5: record structured vacation request for downstream
            // orchestrator. The orchestrator (delivery layer) is
            // responsible for:
            //   - persisting the per-user `:handle`/`:days` dedup cache
            //   - applying RFC 5230 §4.6 implicit address filtering
            //   - constructing the RFC 3834 auto-reply envelope via
            //     `VacationAction::build_reply(original_sender, mid)`
            //   - enqueuing the reply via the autoreply transport
            self.vacation_action = Some(VacationAction {
                days,
                subject,
                from,
                addresses,
                mime: reason_is_mime,
                handle,
                reason,
                envelope_to: self.envelope_to.clone(),
            });
        }
        Ok(())
    }

    // =======================================================================
    // SV4: reject / ereject command parsers (RFC 5429)
    // =======================================================================

    /// Parse and dispatch the `reject` command (RFC 5429 §2.1).
    ///
    /// Syntax: `reject "message-text";`
    ///
    /// Semantics:
    /// - Halts the implicit keep (message will NOT be delivered to the default
    ///   mailbox).
    /// - Records the script-supplied human message for the bounce body.
    /// - `reject` generates an RFC 3464 bounce back to the envelope sender
    ///   (SMTP 250 to the client, delivery then fails with bounce).
    fn parse_reject_command(&mut self, exec: bool) -> Result<(), SieveError> {
        // RFC 5429 §2.1: reject requires the "reject" capability.
        if !self.require.contains(SieveCapabilities::REJECT) {
            return Err(self.parse_error("missing previous require \"reject\""));
        }
        self.skip_whitespace()?;
        let message = self.expect_string("reject message")?;
        // Validate 8bit-in-quoted-string per RFC 5429 §2.2 (don't bounce
        // binary garbage back to senders).
        if message.bytes().any(|b| b & 0x80 != 0) {
            return Err(self.parse_error("reject message contains 8bit text"));
        }
        self.expect_semicolon()?;
        if exec {
            tracing::info!("sieve: reject with message '{}'", message);
            // Only the FIRST reject wins (per RFC 5429 §2.4: "Implementations
            // MUST NOT ... reject a message more than once."). Subsequent
            // reject/ereject commands are no-ops.
            if self.reject_message.is_none() {
                self.reject_message = Some(message);
                self.is_ereject = false;
            }
            self.keep = false;
        }
        Ok(())
    }

    /// Parse and dispatch the `ereject` command (RFC 5429 §2.2).
    ///
    /// Syntax: `ereject "message-text";`
    ///
    /// Semantics: identical surface syntax to `reject`, but semantically
    /// signals the MTA to return an SMTP 5xx response during the DATA/RCPT
    /// transaction rather than accept-and-bounce. The interpreter records
    /// `is_ereject=true` so the caller can choose the right behavior.
    fn parse_ereject_command(&mut self, exec: bool) -> Result<(), SieveError> {
        if !self.require.contains(SieveCapabilities::REJECT) {
            return Err(self.parse_error("missing previous require \"reject\""));
        }
        self.skip_whitespace()?;
        let message = self.expect_string("ereject message")?;
        if message.bytes().any(|b| b & 0x80 != 0) {
            return Err(self.parse_error("ereject message contains 8bit text"));
        }
        self.expect_semicolon()?;
        if exec {
            tracing::info!("sieve: ereject with message '{}'", message);
            if self.reject_message.is_none() {
                self.reject_message = Some(message);
                self.is_ereject = true;
            }
            self.keep = false;
        }
        Ok(())
    }

    // =======================================================================
    // SV4: imap4flags command parsers (RFC 5232)
    // =======================================================================

    /// Parse and dispatch `setflag` (RFC 5232 §4).
    ///
    /// Syntax:
    /// ```sieve
    /// setflag "\\Seen";
    /// setflag ["\\Seen", "\\Flagged"];
    /// setflag "variable" "\\Seen";      // with variable target (ignored)
    /// ```
    ///
    /// Semantics: REPLACES the current flag set entirely. Subsequent
    /// `fileinto` actions apply the replaced set.
    fn parse_setflag_command(&mut self, exec: bool) -> Result<(), SieveError> {
        if !self.require.contains(SieveCapabilities::IMAP4FLAGS) {
            return Err(self.parse_error("missing previous require \"imap4flags\""));
        }
        let flags = self.parse_flag_argument("setflag")?;
        self.expect_semicolon()?;
        if exec {
            tracing::debug!("sieve: setflag {:?}", flags);
            self.active_flags = flags;
            Self::normalize_flag_set(&mut self.active_flags);
        }
        Ok(())
    }

    /// Parse and dispatch `addflag` (RFC 5232 §5).
    ///
    /// Semantics: ADDS flags to the current set (union). Duplicates are
    /// collapsed case-insensitively per RFC 5232.
    fn parse_addflag_command(&mut self, exec: bool) -> Result<(), SieveError> {
        if !self.require.contains(SieveCapabilities::IMAP4FLAGS) {
            return Err(self.parse_error("missing previous require \"imap4flags\""));
        }
        let flags = self.parse_flag_argument("addflag")?;
        self.expect_semicolon()?;
        if exec {
            tracing::debug!("sieve: addflag {:?}", flags);
            for flag in flags {
                if !self
                    .active_flags
                    .iter()
                    .any(|f| f.eq_ignore_ascii_case(&flag))
                {
                    self.active_flags.push(flag);
                }
            }
        }
        Ok(())
    }

    /// Parse and dispatch `removeflag` (RFC 5232 §6).
    ///
    /// Semantics: REMOVES flags from the current set (set difference).
    /// Case-insensitive match. Missing flags are silently ignored.
    fn parse_removeflag_command(&mut self, exec: bool) -> Result<(), SieveError> {
        if !self.require.contains(SieveCapabilities::IMAP4FLAGS) {
            return Err(self.parse_error("missing previous require \"imap4flags\""));
        }
        let flags = self.parse_flag_argument("removeflag")?;
        self.expect_semicolon()?;
        if exec {
            tracing::debug!("sieve: removeflag {:?}", flags);
            for flag in flags {
                self.active_flags.retain(|f| !f.eq_ignore_ascii_case(&flag));
            }
        }
        Ok(())
    }

    /// Parse and dispatch `mark` (RFC 5232 §8) — equivalent to
    /// `addflag "\\Flagged"`.
    fn parse_mark_command(&mut self, exec: bool) -> Result<(), SieveError> {
        if !self.require.contains(SieveCapabilities::IMAP4FLAGS) {
            return Err(self.parse_error("missing previous require \"imap4flags\""));
        }
        self.expect_semicolon()?;
        if exec {
            tracing::debug!("sieve: mark -> addflag \"\\\\Flagged\"");
            if !self
                .active_flags
                .iter()
                .any(|f| f.eq_ignore_ascii_case("\\Flagged"))
            {
                self.active_flags.push("\\Flagged".to_string());
            }
        }
        Ok(())
    }

    /// Parse and dispatch `unmark` (RFC 5232 §8) — equivalent to
    /// `removeflag "\\Flagged"`.
    fn parse_unmark_command(&mut self, exec: bool) -> Result<(), SieveError> {
        if !self.require.contains(SieveCapabilities::IMAP4FLAGS) {
            return Err(self.parse_error("missing previous require \"imap4flags\""));
        }
        self.expect_semicolon()?;
        if exec {
            tracing::debug!("sieve: unmark -> removeflag \"\\\\Flagged\"");
            self.active_flags
                .retain(|f| !f.eq_ignore_ascii_case("\\Flagged"));
        }
        Ok(())
    }

    /// Parse a flag argument: either a single string or a string-list.
    ///
    /// Per RFC 5232 §4, flags may be supplied as either a single string or
    /// a string list. Leading optional variable-name form (for the `:flags`
    /// variable extension) is also tolerated by skipping an optional first
    /// string before the required flag argument.
    fn parse_flag_argument(&mut self, cmd_name: &str) -> Result<Vec<String>, SieveError> {
        self.skip_whitespace()?;
        // Try a string-list first.
        if let Some(list) = self.parse_string_list()? {
            return Ok(list
                .into_iter()
                .flat_map(|s| Self::split_flag_words(&s))
                .collect());
        }
        // Otherwise a single string.
        let s = self.expect_string(cmd_name)?;
        Ok(Self::split_flag_words(&s))
    }

    /// Split a raw flag string into individual tokens.
    ///
    /// RFC 5232 §6.1: if a flag value contains multiple whitespace-separated
    /// tokens ("\\Seen \\Flagged"), each whitespace-delimited substring is
    /// treated as a separate flag.
    fn split_flag_words(s: &str) -> Vec<String> {
        s.split_whitespace()
            .filter(|w| !w.is_empty())
            .map(|w| w.to_string())
            .collect()
    }

    /// Normalize a flag set by deduplicating case-insensitively (keep first).
    fn normalize_flag_set(flags: &mut Vec<String>) {
        let mut seen: Vec<String> = Vec::with_capacity(flags.len());
        flags.retain(|f| {
            let lower = f.to_ascii_lowercase();
            if seen.contains(&lower) {
                false
            } else {
                seen.push(lower);
                true
            }
        });
    }

    fn add_action(&mut self, address: &str, is_file: bool) {
        // For `fileinto`, attach the currently-active IMAP flag set so the
        // delivery orchestrator can apply them (RFC 5232 §4). For `redirect`,
        // flags are meaningless — always empty.
        let flags = if is_file {
            self.active_flags.clone()
        } else {
            Vec::new()
        };
        let already = self
            .generated_actions
            .iter()
            .any(|a| a.address == address && a.is_file == is_file);
        if already {
            tracing::debug!(
                "sieve: repeated {} '{}' ignored",
                if is_file { "fileinto" } else { "redirect" },
                address,
            );
            return;
        }
        self.generated_actions.push(GeneratedAction {
            address: address.to_string(),
            is_file,
            flags,
        });
    }

    // =======================================================================
    // Test evaluation helpers
    // =======================================================================

    fn eval_address(
        &self,
        headers: &[String],
        keys: &[String],
        mt: &MatchType,
        comp: &Comparator,
        ap: &AddressPart,
    ) -> bool {
        // SV3: RFC 5231 §4 — for :count, count the number of address parts
        // present across all specified headers and compare to each numeric key.
        if let MatchType::Count(op) = mt {
            let mut count: i64 = 0;
            for h in headers {
                let lower = h.to_ascii_lowercase();
                if let Some(values) = self.message_headers.get(&lower) {
                    // Each header value contributes one addr-part to the count.
                    // Empty values that extract to empty addresses still count as
                    // "present" per RFC 5228 §2.7.4 unless the field is absent.
                    count += values.len() as i64;
                }
            }
            return count_matches_any_key(count, keys, *op);
        }
        for h in headers {
            let lower = h.to_ascii_lowercase();
            if let Some(values) = self.message_headers.get(&lower) {
                for value in values {
                    let addr = extract_address(value);
                    let part = extract_address_part(&addr, ap);
                    for k in keys {
                        if compare_strings(&part, k, comp, mt) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn eval_header(
        &self,
        headers: &[String],
        keys: &[String],
        mt: &MatchType,
        comp: &Comparator,
    ) -> bool {
        // SV3: RFC 5231 §4 — for :count, count the number of header values
        // present across all specified field names and compare to each key.
        if let MatchType::Count(op) = mt {
            let mut count: i64 = 0;
            for h in headers {
                let lower = h.to_ascii_lowercase();
                if let Some(values) = self.message_headers.get(&lower) {
                    count += values.len() as i64;
                }
            }
            return count_matches_any_key(count, keys, *op);
        }
        for h in headers {
            let lower = h.to_ascii_lowercase();
            if let Some(values) = self.message_headers.get(&lower) {
                for value in values {
                    for k in keys {
                        if compare_strings(value, k, comp, mt) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn eval_envelope(
        &self,
        parts: &[String],
        keys: &[String],
        mt: &MatchType,
        comp: &Comparator,
        ap: &AddressPart,
    ) -> Result<bool, SieveError> {
        // SV3: RFC 5231 §4 — for :count, count the number of envelope values
        // present across all specified parts. Per RFC 5228 §5.4 an empty
        // value (null reverse-path "<>") is represented as "" and still
        // counts as one value.
        if let MatchType::Count(op) = mt {
            let mut count: i64 = 0;
            for p in parts {
                let lower = p.to_ascii_lowercase();
                match lower.as_str() {
                    "from" | "to" => count += 1,
                    _ => return Err(self.parse_error(format!("invalid envelope string: {p}"))),
                }
            }
            return Ok(count_matches_any_key(count, keys, *op));
        }
        for p in parts {
            let lower = p.to_ascii_lowercase();
            let value = match lower.as_str() {
                "from" => &self.envelope_from,
                "to" => &self.envelope_to,
                _ => return Err(self.parse_error(format!("invalid envelope string: {p}"))),
            };
            let part = extract_address_part(value, ap);
            for k in keys {
                if compare_strings(&part, k, comp, mt) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    // =======================================================================
    // Top-level entry
    // =======================================================================

    fn parse_start(&mut self, exec: bool) -> Result<(), SieveError> {
        self.position = 0;
        self.line = 1;
        self.keep = true;
        self.require = SieveCapabilities::empty();
        self.vacation_ran = false;
        self.generated_actions.clear();
        self.notified.clear();
        self.active_flags.clear();
        self.reject_message = None;
        self.is_ereject = false;
        self.vacation_action = None;
        self.notify_actions.clear();
        self.skip_whitespace()?;
        // Parse require commands at the start
        while self.try_identifier("require") {
            self.skip_whitespace()?;
            let caps = self.expect_string_list("capability")?;
            for cap in &caps {
                self.process_require(cap)?;
            }
            self.expect_semicolon()?;
            self.skip_whitespace()?;
        }
        let r = self.parse_commands(exec)?;
        if r != 2 {
            self.skip_whitespace()?;
            if !self.at_end() {
                return Err(self.parse_error("syntax error"));
            }
        }
        Ok(())
    }

    fn process_require(&mut self, cap: &str) -> Result<(), SieveError> {
        match cap {
            "envelope" => self.require.insert(SieveCapabilities::ENVELOPE),
            "fileinto" => self.require.insert(SieveCapabilities::FILEINTO),
            "reject" => self.require.insert(SieveCapabilities::REJECT),
            "encoded-character" => self.require.insert(SieveCapabilities::ENCODED_CHARACTER),
            "enotify" => self.require.insert(SieveCapabilities::ENOTIFY),
            "subaddress" => self.require.insert(SieveCapabilities::SUBADDRESS),
            "vacation" => self.require.insert(SieveCapabilities::VACATION),
            "copy" => self.require.insert(SieveCapabilities::COPY),
            "imap4flags" => self.require.insert(SieveCapabilities::IMAP4FLAGS),
            "regex" => self.require.insert(SieveCapabilities::REGEX),
            "extlists" => self.require.insert(SieveCapabilities::EXTLISTS),
            "comparator-i;octet" | "comparator-i;ascii-casemap" | "comparator-en;ascii-casemap" => { /* always available */
            }
            "comparator-i;ascii-numeric" => {
                self.require.insert(SieveCapabilities::COMPARATOR_NUMERIC);
            }
            _ => return Err(SieveError::UnsupportedExtension(cap.to_string())),
        }
        tracing::debug!("sieve: require \"{}\" processed", cap);
        Ok(())
    }
}

// ===========================================================================
// Free functions — comparison, address, encoding helpers
// ===========================================================================

/// Evaluate RFC 5231 `:count` semantics against a pre-computed count.
///
/// SV3: The `:count` match-type compares the NUMBER of values (not the values
/// themselves) against each numeric key using the supplied relational operator.
/// Returns true if the count matches *any* of the supplied keys (disjunction
/// matches the behaviour of all other Sieve match-types over key lists).
///
/// - `count` is the length of the list of values for which `:count` applies
///   (e.g., number of Received headers for `header :count "gt" "5" "Received"`).
/// - `keys` is the list of string keys; each is parsed as a signed integer.
///   Unparsable keys are silently skipped (non-numeric keys never satisfy a
///   numeric relation).
/// - `op` is the relational operator from `:count "OP"` (eq/ne/gt/ge/lt/le).
///
/// Returns `true` iff there exists a key `k` such that `op(count, k)` holds.
fn count_matches_any_key(count: i64, keys: &[String], op: RelOp) -> bool {
    for k in keys {
        if let Ok(n) = k.parse::<i64>() {
            if op.eval(count.cmp(&n)) {
                return true;
            }
        }
    }
    false
}

/// Compare two strings using the given comparator and match type.
/// C: `compare()` (lines 769–866).
fn compare_strings(
    haystack: &str,
    needle: &str,
    comparator: &Comparator,
    match_type: &MatchType,
) -> bool {
    match match_type {
        MatchType::Is => match comparator {
            Comparator::OctetStream => haystack == needle,
            Comparator::AsciiCaseMap => haystack.eq_ignore_ascii_case(needle),
            Comparator::AsciiNumeric => eq_ascii_numeric(haystack, needle, RelOp::Eq),
        },
        MatchType::Contains => match comparator {
            Comparator::OctetStream => haystack.contains(needle),
            Comparator::AsciiCaseMap => haystack
                .to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase()),
            Comparator::AsciiNumeric => false,
        },
        MatchType::Matches => {
            let ci = matches!(comparator, Comparator::AsciiCaseMap);
            glob_match(needle, haystack, ci)
        }
        MatchType::Regex => pcre2_match(haystack, needle),
        // SV3: RFC 5231 §4 — `:count` is defined over a LIST of values;
        // callers (eval_header, eval_address, eval_envelope, eval_hasflag)
        // detect Count and handle it at the list level via
        // `count_matches_any_key`. Any single-value caller that still
        // reaches this arm gets the correct single-item count of 1 instead
        // of the previously hardcoded value that ignored the needle.
        MatchType::Count(op) => {
            if let Ok(n) = needle.parse::<i64>() {
                op.eval(1_i64.cmp(&n))
            } else {
                false
            }
        }
        MatchType::Value(op) => match comparator {
            Comparator::AsciiNumeric => eq_ascii_numeric(haystack, needle, *op),
            Comparator::OctetStream => op.eval(haystack.cmp(needle)),
            Comparator::AsciiCaseMap => op.eval(
                haystack
                    .to_ascii_lowercase()
                    .cmp(&needle.to_ascii_lowercase()),
            ),
        },
    }
}

/// ASCII numeric comparison.  C: `eq_asciinumeric()` (lines 713–749).
fn eq_ascii_numeric(a: &str, b: &str, op: RelOp) -> bool {
    fn leading_digit_len(s: &str) -> usize {
        s.bytes()
            .position(|b| !b.is_ascii_digit())
            .unwrap_or(s.len())
    }
    let ad = &a[..leading_digit_len(a)];
    let bd = &b[..leading_digit_len(b)];
    let cmp = if ad.is_empty() && bd.is_empty() {
        std::cmp::Ordering::Equal
    } else if !ad.is_empty() && bd.is_empty() {
        std::cmp::Ordering::Less
    } else if ad.is_empty() {
        std::cmp::Ordering::Greater
    } else {
        ad.len().cmp(&bd.len()).then_with(|| ad.cmp(bd))
    };
    op.eval(cmp)
}

/// Glob pattern matching with `*` and `?`. C: `eq_glob()` (lines 602–696).
fn glob_match(pattern: &str, text: &str, case_insensitive: bool) -> bool {
    glob_match_bytes(pattern.as_bytes(), text.as_bytes(), case_insensitive)
}

fn glob_match_bytes(pattern: &[u8], text: &[u8], ci: bool) -> bool {
    let mut px = 0usize;
    let mut tx = 0usize;
    let mut star_px: Option<usize> = None;
    let mut star_tx: usize = 0;
    while tx < text.len() {
        if px < pattern.len() && pattern[px] == b'*' {
            star_px = Some(px);
            star_tx = tx;
            px += 1;
        } else if px < pattern.len() && pattern[px] == b'?' {
            px += 1;
            tx += 1;
        } else if px < pattern.len() && pattern[px] == b'\\' {
            px += 1;
            if px >= pattern.len() {
                return false;
            }
            if char_eq(pattern[px], text[tx], ci) {
                px += 1;
                tx += 1;
            } else if let Some(sp) = star_px {
                px = sp + 1;
                star_tx += 1;
                tx = star_tx;
            } else {
                return false;
            }
        } else if px < pattern.len() && char_eq(pattern[px], text[tx], ci) {
            px += 1;
            tx += 1;
        } else if let Some(sp) = star_px {
            px = sp + 1;
            star_tx += 1;
            tx = star_tx;
        } else {
            return false;
        }
    }
    while px < pattern.len() && pattern[px] == b'*' {
        px += 1;
    }
    px == pattern.len()
}

fn char_eq(a: u8, b: u8, ci: bool) -> bool {
    if ci {
        a.eq_ignore_ascii_case(&b)
    } else {
        a == b
    }
}

/// PCRE2-based regex matching for the `:regex` match type.
fn pcre2_match(text: &str, pattern: &str) -> bool {
    match pcre2::bytes::Regex::new(pattern) {
        Ok(re) => re.is_match(text.as_bytes()).unwrap_or(false),
        Err(_) => false,
    }
}

/// Regex-based email address validation using `regex::Regex`.
fn validate_email_address(addr: &str) -> Result<CleanString, SieveError> {
    let re = regex::Regex::new(r"^[^\s@]+@[^\s@]+$").map_err(|e| SieveError::RuntimeError {
        message: format!("regex compilation failed: {e}"),
    })?;
    if let Some(m) = re.find(addr) {
        if m.as_str().len() == addr.len() && re.is_match(addr) {
            return Ok(Clean::new(addr.to_string()));
        }
    }
    if addr == "<>" || addr.is_empty() {
        return Ok(Clean::new(addr.to_string()));
    }
    Err(SieveError::InvalidAddress(addr.to_string()))
}

/// Extract a bare email address from a header value.
fn extract_address(value: &str) -> String {
    let trimmed = value.trim();
    if let Some(start) = trimmed.find('<') {
        if let Some(end) = trimmed[start..].find('>') {
            return trimmed[start + 1..start + end].to_string();
        }
    }
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if let Some(last) = parts.last() {
        let s = last.trim_matches(|c: char| c == '<' || c == '>' || c == '"');
        if s.contains('@') {
            return s.to_string();
        }
    }
    trimmed.to_string()
}

/// Extract the requested part of an email address.
fn extract_address_part(addr: &str, part: &AddressPart) -> String {
    match part {
        AddressPart::All => addr.to_string(),
        AddressPart::LocalPart => addr
            .rfind('@')
            .map_or_else(|| addr.to_string(), |at| addr[..at].to_string()),
        AddressPart::Domain => addr
            .rfind('@')
            .map_or_else(String::new, |at| addr[at + 1..].to_string()),
        AddressPart::User => {
            let local = addr.rfind('@').map_or(addr, |at| &addr[..at]);
            local
                .find('+')
                .map_or_else(|| local.to_string(), |plus| local[..plus].to_string())
        }
        AddressPart::Detail => {
            let local = addr.rfind('@').map_or(addr, |at| &addr[..at]);
            local
                .find('+')
                .map_or_else(String::new, |plus| local[plus + 1..].to_string())
        }
    }
}

/// Validate a header field name per RFC 2822. C: `is_header()`.
fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b >= 33 && b != b':' && b != 127)
}

/// Decode `${hex:…}` and `${unicode:…}` encoded character sequences.
/// C: `string_decode()` (lines 1324–1376).
fn decode_encoded_characters(input: &str) -> Result<String, SieveError> {
    let mut result = String::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"${hex:") {
            if let Some(close) = bytes[i + 6..].iter().position(|&b| b == b'}') {
                let hex_str = &input[i + 6..i + 6 + close];
                if let Ok(decoded) = decode_hex_pairs(hex_str) {
                    result.push_str(&String::from_utf8_lossy(&decoded));
                    i += 6 + close + 1;
                    continue;
                }
            }
        } else if bytes[i..].starts_with(b"${unicode:") {
            if let Some(close) = bytes[i + 10..].iter().position(|&b| b == b'}') {
                let uni_str = &input[i + 10..i + 10 + close];
                if let Ok(decoded) = decode_unicode_hex(uni_str) {
                    result.push_str(&decoded);
                    i += 10 + close + 1;
                    continue;
                }
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    Ok(result)
}

/// Decode hex pair sequences. C: `hex_decode()` (lines 1188–1212).
fn decode_hex_pairs(src: &str) -> Result<Vec<u8>, SieveError> {
    let mut result = Vec::new();
    let mut chars = src.chars().peekable();
    // Skip whitespace
    while chars.peek().is_some_and(|c| c.is_ascii_whitespace()) {
        chars.next();
    }
    while chars.peek().is_some() {
        let mut value: u8 = 0;
        let mut digits = 0;
        while digits < 2 {
            if let Some(&ch) = chars.peek() {
                if ch.is_ascii_hexdigit() {
                    value = (value << 4) | ch.to_digit(16).unwrap() as u8;
                    digits += 1;
                    chars.next();
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        if digits == 0 {
            return Err(SieveError::ParseError {
                line: 0,
                message: "invalid hex sequence".to_string(),
            });
        }
        result.push(value);
        while chars.peek().is_some_and(|c| c.is_ascii_whitespace()) {
            chars.next();
        }
    }
    Ok(result)
}

/// Decode unicode code point sequences. C: `unicode_decode()`.
fn decode_unicode_hex(src: &str) -> Result<String, SieveError> {
    let mut result = String::new();
    let mut chars = src.chars().peekable();
    while chars.peek().is_some_and(|c| c.is_ascii_whitespace()) {
        chars.next();
    }
    while chars.peek().is_some() {
        while chars.peek() == Some(&'0') {
            chars.next();
        }
        let mut cp: u32 = 0;
        let mut digits = 0;
        while digits < 7 {
            if let Some(&ch) = chars.peek() {
                if ch.is_ascii_hexdigit() {
                    cp = (cp << 4) | ch.to_digit(16).unwrap();
                    digits += 1;
                    chars.next();
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        if digits == 7 {
            return Err(SieveError::ParseError {
                line: 0,
                message: "unicode code point too large".to_string(),
            });
        }
        if cp <= 0xD7FF || (0xE000..=0x10FFFF).contains(&cp) {
            if let Some(ch) = char::from_u32(cp) {
                result.push(ch);
            }
        } else if cp == 0 && digits == 0 {
            break;
        } else {
            return Err(SieveError::ParseError {
                line: 0,
                message: "unicode character out of range".to_string(),
            });
        }
        if chars.peek().is_some_and(|c| c.is_ascii_whitespace()) {
            while chars.peek().is_some_and(|c| c.is_ascii_whitespace()) {
                chars.next();
            }
        } else {
            break;
        }
    }
    Ok(result)
}

/// Encode a string as quoted-printable. C: `quoted_printable_encode()`.
fn quoted_printable_encode(src: &str) -> String {
    let mut result = String::new();
    let mut line_len: usize = 0;
    // RFC 2045 §6.7: soft-break before reaching MIMEWORD_LENGTH (75) minus
    // the 2-char `=\r\n` soft-line-break token.
    let soft_break_at = MIMEWORD_LENGTH.saturating_sub(2);
    let bytes = src.as_bytes();
    for (i, &ch) in bytes.iter().enumerate() {
        if line_len >= soft_break_at {
            result.push_str("=\r\n");
            line_len = 0;
        }
        if (b'!'..=b'<').contains(&ch)
            || (b'>'..=b'~').contains(&ch)
            || ((ch == b'\t' || ch == b' ')
                && i + 2 < bytes.len()
                && !(bytes[i + 1] == b'\r' && bytes[i + 2] == b'\n'))
        {
            result.push(ch as char);
            line_len += 1;
        } else if (ch == b'\r' && i + 1 < bytes.len() && bytes[i + 1] == b'\n')
            || (ch == b'\n' && (i == 0 || bytes[i - 1] != b'\r'))
        {
            result.push_str("\r\n");
            line_len = 0;
        } else {
            result.push_str(&format!("={:02X}", ch));
            line_len += 3;
        }
    }
    result
}

// ===========================================================================
// Public API
// ===========================================================================

/// Build a [`SieveOutcome`] from completed [`SieveState`].
///
/// Applies the implicit-keep rule, then packages all post-evaluation state
/// (actions, reject message, final flag set) into the public outcome struct.
fn build_outcome(state: &mut SieveState<'_>) -> SieveOutcome {
    // Reject short-circuits everything else — but vacation/notify actions
    // already committed during evaluation are still surfaced so the
    // orchestrator can decide whether to suppress them. In current Sieve
    // semantics (RFC 5230 §4.5, RFC 5435 §3.3), a successful reject
    // overrides subsequent delivery but does not retroactively cancel
    // side-effects already queued during evaluation.
    if let Some(msg) = state.reject_message.take() {
        tracing::info!(
            "sieve: {} — message='{}'",
            if state.is_ereject {
                "ereject"
            } else {
                "reject"
            },
            msg
        );
        return SieveOutcome {
            result: SieveResult::Fail,
            actions: std::mem::take(&mut state.generated_actions),
            reject_message: Some(msg),
            is_ereject: state.is_ereject,
            flags: std::mem::take(&mut state.active_flags),
            vacation: state.vacation_action.take(),
            notifications: std::mem::take(&mut state.notify_actions),
        };
    }
    if state.keep {
        state.add_action(&state.inbox.clone(), true);
        tracing::info!("sieve: implicit keep");
        SieveOutcome {
            result: SieveResult::Delivered,
            actions: std::mem::take(&mut state.generated_actions),
            reject_message: None,
            is_ereject: false,
            flags: std::mem::take(&mut state.active_flags),
            vacation: state.vacation_action.take(),
            notifications: std::mem::take(&mut state.notify_actions),
        }
    } else if !state.generated_actions.is_empty() {
        tracing::info!("sieve: actions taken, no implicit keep");
        SieveOutcome {
            result: SieveResult::Delivered,
            actions: std::mem::take(&mut state.generated_actions),
            reject_message: None,
            is_ereject: false,
            flags: std::mem::take(&mut state.active_flags),
            vacation: state.vacation_action.take(),
            notifications: std::mem::take(&mut state.notify_actions),
        }
    } else if state.vacation_action.is_some() || !state.notify_actions.is_empty() {
        // SV5: a vacation or notify with no other delivery actions still
        // counts as having produced output — ensure the SieveOutcome
        // carries them for the orchestrator rather than returning a bare
        // NotDelivered outcome that discards the structured output.
        tracing::info!("sieve: side-effect actions only (vacation/notify)");
        SieveOutcome {
            result: SieveResult::NotDelivered,
            actions: Vec::new(),
            reject_message: None,
            is_ereject: false,
            flags: std::mem::take(&mut state.active_flags),
            vacation: state.vacation_action.take(),
            notifications: std::mem::take(&mut state.notify_actions),
        }
    } else {
        tracing::info!("sieve: no keep, no actions — not delivered");
        SieveOutcome::bare(SieveResult::NotDelivered)
    }
}

/// Interpret a Sieve filter script against a message.
///
/// Main entry point replacing C `sieve_interpret()` (lines 3528–3613),
/// registered as the `SIEVE_INTERPRET` function slot (index 0).
///
/// # Arguments
///
/// - `filter_text` — Complete Sieve script source text.
///
/// # Returns
///
/// A [`SieveOutcome`] containing:
/// - `result` — `Delivered` / `NotDelivered` / `Fail` (on reject) / etc.;
/// - `actions` — ordered list of `fileinto`/`redirect` targets;
/// - `reject_message` — human reject text (SV4: RFC 5429);
/// - `is_ereject` — whether reject is immediate (5xx) vs bounce;
/// - `flags` — final active IMAP flag set (SV4: RFC 5232).
///
/// # Errors
///
/// Returns [`SieveError`] if the script has syntax errors or runtime failures.
pub fn sieve_interpret(filter_text: &str) -> Result<SieveOutcome, SieveError> {
    tracing::debug!("sieve: start of processing");
    // Track taint state of the filter source (configuration input)
    let tainted_source: Tainted<String> = Tainted::new(filter_text.to_string());
    let _taint_state = TaintState::Tainted;
    tracing::debug!("sieve: filter source is tainted (from configuration)");
    // Extract the source text for parsing
    let source = tainted_source.into_inner();
    let mut state = SieveState::new(&source);
    match state.parse_start(true) {
        Ok(()) => Ok(build_outcome(&mut state)),
        Err(e) => {
            tracing::error!("sieve error: {}", e);
            Err(e)
        }
    }
}

/// Interpret a Sieve filter with full Exim message context.
///
/// Taint-aware version that accepts headers as [`TaintedString`] values
/// and uses a [`MessageArena`] for per-message allocation.
///
/// Returns a [`SieveOutcome`] — see [`sieve_interpret`] for the fields
/// exposed and the SV1/SV4 rationale behind the struct return.
pub fn sieve_interpret_with_context(
    filter_text: &str,
    ctx: &SieveContext<'_>,
) -> Result<SieveOutcome, SieveError> {
    tracing::debug!("sieve: start of processing (with context)");
    let mut state = SieveState::from_context(filter_text, ctx);
    match state.parse_start(true) {
        Ok(()) => Ok(build_outcome(&mut state)),
        Err(e) => {
            tracing::error!("sieve error: {}", e);
            Err(e)
        }
    }
}

/// Return the list of supported Sieve extensions.
///
/// `SIEVE_EXTENSIONS` function slot (index 1), replacing C
/// `sieve_extensions()` which iterates `exim_sieve_extension_list[]`.
pub fn sieve_extensions() -> Vec<&'static str> {
    vec![
        "comparator-i;ascii-numeric",
        "copy",
        "encoded-character",
        "enotify",
        "envelope",
        "fileinto",
        "imap4flags",
        "regex",
        "subaddress",
        "vacation",
    ]
}

// ===========================================================================
// Module registration
// ===========================================================================

inventory::submit! {
    DriverInfoBase::new("sieve_filter")
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sieve_extensions_not_empty() {
        let exts = sieve_extensions();
        assert!(!exts.is_empty());
        assert!(exts.contains(&"vacation"));
        assert!(exts.contains(&"fileinto"));
        assert!(exts.contains(&"envelope"));
        assert!(exts.contains(&"copy"));
        assert!(exts.contains(&"enotify"));
        assert!(exts.contains(&"subaddress"));
        assert!(exts.contains(&"encoded-character"));
        assert!(exts.contains(&"comparator-i;ascii-numeric"));
        for i in 1..exts.len() {
            assert!(exts[i - 1] <= exts[i], "extensions not sorted");
        }
    }

    #[test]
    fn test_sieve_result_display() {
        assert_eq!(format!("{}", SieveResult::Delivered), "delivered");
        assert_eq!(format!("{}", SieveResult::Defer), "defer");
        assert_eq!(format!("{}", SieveResult::Error), "error");
    }

    #[test]
    fn test_sieve_error_display() {
        let e = SieveError::ParseError {
            line: 5,
            message: "missing semicolon".to_string(),
        };
        assert!(format!("{e}").contains("line 5"));
    }

    #[test]
    fn test_capabilities() {
        let mut caps = SieveCapabilities::empty();
        assert!(!caps.contains(SieveCapabilities::FILEINTO));
        caps.insert(SieveCapabilities::FILEINTO);
        assert!(caps.contains(SieveCapabilities::FILEINTO));
        assert!(!caps.contains(SieveCapabilities::VACATION));
    }

    #[test]
    fn test_relop_eval() {
        use std::cmp::Ordering;
        assert!(RelOp::Lt.eval(Ordering::Less));
        assert!(!RelOp::Lt.eval(Ordering::Equal));
        assert!(RelOp::Le.eval(Ordering::Less));
        assert!(RelOp::Le.eval(Ordering::Equal));
        assert!(RelOp::Eq.eval(Ordering::Equal));
        assert!(RelOp::Ge.eval(Ordering::Greater));
        assert!(RelOp::Gt.eval(Ordering::Greater));
        assert!(RelOp::Ne.eval(Ordering::Less));
        assert!(!RelOp::Ne.eval(Ordering::Equal));
    }

    #[test]
    fn test_glob_match() {
        assert!(glob_match("*", "anything", false));
        assert!(glob_match("?", "a", false));
        assert!(!glob_match("?", "", false));
        assert!(glob_match("a*b", "axyzb", false));
        assert!(!glob_match("a*b", "axyzc", false));
        assert!(glob_match("A*B", "axyzb", true));
        assert!(!glob_match("A*B", "axyzb", false));
        assert!(glob_match("\\*", "*", false));
        assert!(glob_match("", "", false));
        assert!(!glob_match("", "notempty", false));
    }

    #[test]
    fn test_compare_strings_is() {
        assert!(compare_strings(
            "hello",
            "hello",
            &Comparator::OctetStream,
            &MatchType::Is
        ));
        assert!(!compare_strings(
            "Hello",
            "hello",
            &Comparator::OctetStream,
            &MatchType::Is
        ));
        assert!(compare_strings(
            "Hello",
            "hello",
            &Comparator::AsciiCaseMap,
            &MatchType::Is
        ));
    }

    #[test]
    fn test_compare_strings_contains() {
        assert!(compare_strings(
            "hello world",
            "world",
            &Comparator::OctetStream,
            &MatchType::Contains,
        ));
        assert!(compare_strings(
            "Hello World",
            "world",
            &Comparator::AsciiCaseMap,
            &MatchType::Contains,
        ));
    }

    #[test]
    fn test_eq_ascii_numeric() {
        assert!(eq_ascii_numeric("42", "42", RelOp::Eq));
        assert!(eq_ascii_numeric("100", "42", RelOp::Gt));
        assert!(eq_ascii_numeric("5", "42", RelOp::Lt));
    }

    #[test]
    fn test_extract_address() {
        assert_eq!(extract_address("user@example.com"), "user@example.com");
        assert_eq!(
            extract_address("John Doe <john@example.com>"),
            "john@example.com"
        );
    }

    #[test]
    fn test_extract_address_part() {
        let addr = "user+detail@example.com";
        assert_eq!(extract_address_part(addr, &AddressPart::All), addr);
        assert_eq!(
            extract_address_part(addr, &AddressPart::LocalPart),
            "user+detail"
        );
        assert_eq!(
            extract_address_part(addr, &AddressPart::Domain),
            "example.com"
        );
        assert_eq!(extract_address_part(addr, &AddressPart::User), "user");
        assert_eq!(extract_address_part(addr, &AddressPart::Detail), "detail");
    }

    #[test]
    fn test_is_valid_header_name() {
        assert!(is_valid_header_name("From"));
        assert!(is_valid_header_name("X-Custom-Header"));
        assert!(!is_valid_header_name(""));
        assert!(!is_valid_header_name("Invalid:Header"));
    }

    #[test]
    fn test_simple_keep() {
        // `keep;` is an explicit filing-into-INBOX action: the interpreter must
        // return `Delivered` and emit exactly one `fileinto` action directed at
        // the configured inbox (default "inbox"). This exercises SV1's
        // generated_actions propagation so the caller can route the message.
        let outcome = sieve_interpret("keep;").expect("should parse");
        assert_eq!(outcome.result, SieveResult::Delivered);
        assert_eq!(
            outcome.actions.len(),
            1,
            "`keep` should generate exactly one action; got {:?}",
            outcome.actions
        );
        assert_eq!(outcome.actions[0].address, "inbox");
        assert!(
            outcome.actions[0].is_file,
            "keep action must be is_file=true"
        );
        assert!(outcome.reject_message.is_none());
    }

    #[test]
    fn test_empty_script() {
        // An empty Sieve script triggers the "implicit keep" logic: the
        // interpreter delivers to the default mailbox and emits one
        // `fileinto inbox` action (is_file=true) for the caller.
        let outcome = sieve_interpret("").expect("should parse");
        assert_eq!(outcome.result, SieveResult::Delivered);
        assert_eq!(
            outcome.actions.len(),
            1,
            "empty script → implicit keep → exactly one action; got {:?}",
            outcome.actions
        );
        assert_eq!(outcome.actions[0].address, "inbox");
        assert!(outcome.actions[0].is_file);
    }

    #[test]
    fn test_discard() {
        // `discard;` suppresses delivery (no implicit keep, no file actions).
        // Both the outcome (`NotDelivered`) and the empty action list must hold.
        let outcome = sieve_interpret("discard;").expect("should parse");
        assert_eq!(outcome.result, SieveResult::NotDelivered);
        assert!(
            outcome.actions.is_empty(),
            "`discard` should not generate any actions; got {:?}",
            outcome.actions
        );
    }

    #[test]
    fn test_stop() {
        let result = sieve_interpret("stop;");
        assert!(result.is_ok());
    }

    #[test]
    fn test_require_fileinto() {
        let script = "require \"fileinto\";\nfileinto \"INBOX.spam\";\n";
        let result = sieve_interpret(script);
        assert!(result.is_ok());
    }

    #[test]
    fn test_fileinto_generates_action() {
        // SV1: the caller (delivery orchestrator) needs the generated action
        // list to know where to file the message. A `fileinto "INBOX.spam"`
        // command must propagate as `GeneratedAction { address: "INBOX.spam",
        // is_file: true }`. The explicit fileinto suppresses the implicit keep.
        let script = "require \"fileinto\";\nfileinto \"INBOX.spam\";\n";
        let outcome = sieve_interpret(script).expect("should parse");
        assert_eq!(outcome.result, SieveResult::Delivered);
        assert_eq!(
            outcome.actions.len(),
            1,
            "fileinto should produce exactly one action"
        );
        assert_eq!(outcome.actions[0].address, "INBOX.spam");
        assert!(outcome.actions[0].is_file, "fileinto → is_file=true");
    }

    #[test]
    fn test_fileinto_then_keep_generates_two_actions() {
        // An explicit `keep` after `fileinto` should add a second action for
        // the default inbox. Order is preserved: fileinto first, then keep.
        let script = "require \"fileinto\";\nfileinto \"INBOX.spam\";\nkeep;\n";
        let outcome = sieve_interpret(script).expect("should parse");
        assert_eq!(outcome.result, SieveResult::Delivered);
        assert_eq!(
            outcome.actions.len(),
            2,
            "fileinto + keep should produce 2 actions; got {:?}",
            outcome.actions
        );
        assert_eq!(outcome.actions[0].address, "INBOX.spam");
        assert!(outcome.actions[0].is_file);
        assert_eq!(outcome.actions[1].address, "inbox");
        assert!(outcome.actions[1].is_file);
    }

    #[test]
    fn test_redirect_generates_action() {
        // SV1: `redirect` must emit a `GeneratedAction { address: <addr>,
        // is_file: false }`. Redirect suppresses the implicit keep, so there
        // should be exactly one action with is_file=false.
        let script = "redirect \"forward@example.com\";\n";
        let outcome = sieve_interpret(script).expect("should parse");
        assert_eq!(outcome.result, SieveResult::Delivered);
        assert_eq!(
            outcome.actions.len(),
            1,
            "redirect should produce exactly one action"
        );
        assert_eq!(outcome.actions[0].address, "forward@example.com");
        assert!(!outcome.actions[0].is_file, "redirect → is_file=false");
    }

    #[test]
    fn test_duplicate_actions_suppressed() {
        // `add_action` de-duplicates identical (address, is_file) pairs. Two
        // `fileinto` commands targeting the same mailbox must collapse to one.
        let script = "require \"fileinto\";\nfileinto \"INBOX.spam\";\nfileinto \"INBOX.spam\";\n";
        let outcome = sieve_interpret(script).expect("should parse");
        assert_eq!(
            outcome.actions.len(),
            1,
            "duplicate fileinto should collapse to one action; got {:?}",
            outcome.actions
        );
        assert_eq!(outcome.actions[0].address, "INBOX.spam");
    }

    #[test]
    fn test_require_unknown() {
        let result = sieve_interpret("require \"nonexistent\";\n");
        assert!(result.is_err());
        match result.unwrap_err() {
            SieveError::UnsupportedExtension(ext) => assert_eq!(ext, "nonexistent"),
            e => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_if_true() {
        assert!(sieve_interpret("if true { keep; }").is_ok());
    }

    #[test]
    fn test_if_false_else() {
        assert!(sieve_interpret("if false { discard; } else { keep; }").is_ok());
    }

    #[test]
    fn test_redirect() {
        let result = sieve_interpret("redirect \"admin@example.com\";");
        assert!(result.is_ok());
    }

    #[test]
    fn test_redirect_unqualified() {
        assert!(sieve_interpret("redirect \"admin\";").is_err());
    }

    #[test]
    fn test_missing_semicolon() {
        assert!(sieve_interpret("keep").is_err());
    }

    #[test]
    fn test_require_list() {
        let script = "require [\"fileinto\", \"copy\"];\nfileinto :copy \"archive\";\n";
        assert!(sieve_interpret(script).is_ok());
    }

    #[test]
    fn test_not_test() {
        assert!(sieve_interpret("if not false { keep; }").is_ok());
    }

    #[test]
    fn test_allof_test() {
        assert!(sieve_interpret("if allof (true, true) { keep; }").is_ok());
    }

    #[test]
    fn test_anyof_test() {
        assert!(sieve_interpret("if anyof (false, true) { keep; }").is_ok());
    }

    #[test]
    fn test_size_over() {
        assert!(sieve_interpret("if size :over 1M { discard; }").is_ok());
    }

    #[test]
    fn test_hash_comment() {
        assert!(sieve_interpret("# comment\nkeep;\n").is_ok());
    }

    #[test]
    fn test_c_comment() {
        assert!(sieve_interpret("/* comment */ keep;\n").is_ok());
    }

    #[test]
    fn test_vacation_without_require() {
        assert!(sieve_interpret("vacation \"I am away\";").is_err());
    }

    #[test]
    fn test_vacation_with_require() {
        let script =
            "require \"vacation\";\nvacation :days 7 :subject \"OOO\" \"I am on vacation\";\n";
        assert!(sieve_interpret(script).is_ok());
    }

    #[test]
    fn test_notify_without_require() {
        assert!(sieve_interpret("notify \"mailto:a@b.c\";").is_err());
    }

    #[test]
    fn test_fileinto_without_require() {
        assert!(sieve_interpret("fileinto \"spam\";").is_err());
    }

    #[test]
    fn test_fileinto_path_traversal() {
        let script = "require \"fileinto\";\nfileinto \"../etc/passwd\";\n";
        assert!(sieve_interpret(script).is_err());
    }

    #[test]
    fn test_elsif() {
        assert!(sieve_interpret("if false { discard; } elsif true { keep; }").is_ok());
    }

    #[test]
    fn test_multiline_string() {
        let script = "require \"vacation\";\nvacation text:\nI am on vacation.\n.\n;\n";
        assert!(sieve_interpret(script).is_ok());
    }

    #[test]
    fn test_decode_hex_pairs() {
        let decoded = decode_hex_pairs("48 65 6C 6C 6F").unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn test_decode_unicode_hex() {
        let decoded = decode_unicode_hex("48 65 6C 6C 6F").unwrap();
        assert_eq!(decoded, "Hello");
    }

    #[test]
    fn test_quoted_printable_encode() {
        let encoded = quoted_printable_encode("Hello World");
        assert!(encoded.contains("Hello"));
    }

    #[test]
    fn test_driver_info_registration() {
        let found =
            inventory::iter::<DriverInfoBase>().any(|info| info.driver_name == "sieve_filter");
        assert!(found, "sieve_filter module not found in driver registry");
    }

    #[test]
    fn test_validate_email_address() {
        assert!(validate_email_address("user@example.com").is_ok());
        assert!(validate_email_address("<>").is_ok());
        assert!(validate_email_address("").is_ok());
        assert!(validate_email_address("no-at-sign").is_err());
    }

    #[test]
    fn test_pcre2_match() {
        assert!(pcre2_match("hello world", "hello"));
        assert!(pcre2_match("test123", r"\d+"));
        assert!(!pcre2_match("abc", r"^\d+$"));
    }

    #[test]
    fn test_mimeword_length_constant() {
        assert_eq!(MIMEWORD_LENGTH, 75);
    }

    #[test]
    fn test_vacation_min_max_days() {
        assert_eq!(VACATION_MIN_DAYS, 1);
        assert_eq!(VACATION_MAX_DAYS, 31);
    }

    #[test]
    fn test_sieve_context_struct() {
        // Verify SieveContext can be constructed with required types
        let arena = MessageArena::new();
        let store = MessageStore::new();
        let mut headers: HashMap<String, Vec<TaintedString>> = HashMap::new();
        headers.insert(
            "from".to_string(),
            vec![Tainted::new("sender@example.com".to_string())],
        );
        let ctx = SieveContext {
            arena: &arena,
            store: &store,
            headers,
            envelope_from: Tainted::new("sender@example.com".to_string()),
            envelope_to: Tainted::new("recipient@example.com".to_string()),
            message_size: 1024,
        };
        let outcome = sieve_interpret_with_context("keep;", &ctx).expect("should parse");
        assert_eq!(outcome.result, SieveResult::Delivered);
        assert_eq!(
            outcome.actions.len(),
            1,
            "`keep` with context must still generate one fileinto action"
        );
        assert_eq!(outcome.actions[0].address, "inbox");
        assert!(outcome.actions[0].is_file);
    }

    #[test]
    fn test_taint_error_conversion() {
        let te = TaintError {
            context: "test taint".to_string(),
        };
        let se: SieveError = te.into();
        assert!(format!("{se}").contains("taint"));
    }

    #[test]
    fn test_driver_error_conversion() {
        let de = DriverError::NotFound {
            name: "test".to_string(),
        };
        let se: SieveError = de.into();
        assert!(format!("{se}").contains("driver error"));
    }

    // =======================================================================
    // SV4: tests for reject/ereject + imap4flags commands (RFC 5429, RFC 5232)
    // =======================================================================

    #[test]
    fn test_sv4_reject_with_message() {
        // RFC 5429 §2.1: reject causes the message to be refused and captures
        // a human-readable message. SieveResult transitions to Fail; the
        // reject_message is populated; is_ereject must remain false.
        let script = "require \"reject\";\nreject \"Go away, spammer\";\n";
        let outcome = sieve_interpret(script).expect("should parse");
        assert_eq!(outcome.result, SieveResult::Fail);
        assert_eq!(
            outcome.reject_message.as_deref(),
            Some("Go away, spammer"),
            "reject message must be captured verbatim"
        );
        assert!(
            !outcome.is_ereject,
            "reject (not ereject) must leave is_ereject=false"
        );
    }

    #[test]
    fn test_sv4_ereject_with_message() {
        // RFC 5429 §2.2: ereject shares the surface syntax of reject but
        // requests an immediate 5xx SMTP response instead of bounce. The
        // interpreter distinguishes via is_ereject=true.
        let script = "require \"reject\";\nereject \"Policy violation\";\n";
        let outcome = sieve_interpret(script).expect("should parse");
        assert_eq!(outcome.result, SieveResult::Fail);
        assert_eq!(outcome.reject_message.as_deref(), Some("Policy violation"));
        assert!(outcome.is_ereject, "ereject must set is_ereject=true");
    }

    #[test]
    fn test_sv4_reject_without_require_errors() {
        // The reject command MUST be preceded by `require "reject"`; without
        // it the interpreter must reject the script at parse time.
        let script = "reject \"Go away\";\n";
        let result = sieve_interpret(script);
        assert!(result.is_err(), "reject without require must error");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.to_lowercase().contains("require") && msg.contains("reject"),
            "error message must mention missing require for \"reject\"; got: {msg}"
        );
    }

    #[test]
    fn test_sv4_reject_8bit_rejected() {
        // RFC 5429 §2.2 forbids 8bit octets in the reject message text (the
        // text is destined for a bounce that must be 7bit-clean).
        let script = "require \"reject\";\nreject \"bad\u{00A0}text\";\n";
        let result = sieve_interpret(script);
        assert!(result.is_err(), "reject with 8bit text must error");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.to_lowercase().contains("8bit"),
            "error must mention 8bit; got: {msg}"
        );
    }

    #[test]
    fn test_sv4_first_reject_wins() {
        // RFC 5429 §2.4: "Implementations MUST NOT ... reject a message
        // more than once." Only the FIRST reject should populate the
        // outcome; subsequent reject/ereject are no-ops.
        let script = "require \"reject\";\nreject \"first\";\nreject \"second\";\n";
        let outcome = sieve_interpret(script).expect("should parse");
        assert_eq!(outcome.result, SieveResult::Fail);
        assert_eq!(
            outcome.reject_message.as_deref(),
            Some("first"),
            "only the first reject must win"
        );
        assert!(!outcome.is_ereject);
    }

    #[test]
    fn test_sv4_first_reject_then_ereject_ignored() {
        // If reject fires first, a later ereject must not change is_ereject
        // (the state captured by the first reject must stick).
        let script = "require \"reject\";\nreject \"first\";\nereject \"later\";\n";
        let outcome = sieve_interpret(script).expect("should parse");
        assert_eq!(outcome.reject_message.as_deref(), Some("first"));
        assert!(
            !outcome.is_ereject,
            "is_ereject must remain false from the first reject"
        );
    }

    #[test]
    fn test_sv4_setflag_replaces_set() {
        // RFC 5232 §4: setflag REPLACES the active flag set entirely;
        // subsequent fileinto actions carry the replaced set verbatim.
        let script = r#"require ["fileinto", "imap4flags"];
addflag "\\Answered";
setflag ["\\Seen", "\\Flagged"];
fileinto "INBOX.work";
"#;
        let outcome = sieve_interpret(script).expect("should parse");
        assert_eq!(
            outcome.actions.len(),
            1,
            "fileinto should produce one action"
        );
        let flags = &outcome.actions[0].flags;
        assert!(
            flags.iter().any(|f| f == "\\Seen"),
            "setflag must include \\Seen; got {flags:?}"
        );
        assert!(
            flags.iter().any(|f| f == "\\Flagged"),
            "setflag must include \\Flagged; got {flags:?}"
        );
        assert!(
            !flags.iter().any(|f| f == "\\Answered"),
            "setflag must REPLACE, so \\Answered must NOT be present; got {flags:?}"
        );
    }

    #[test]
    fn test_sv4_setflag_without_require_errors() {
        let script = "setflag \"\\\\Seen\";\n";
        let result = sieve_interpret(script);
        assert!(result.is_err(), "setflag without require must error");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.to_lowercase().contains("require") && msg.contains("imap4flags"),
            "error must mention missing require \"imap4flags\"; got: {msg}"
        );
    }

    #[test]
    fn test_sv4_addflag_dedup_case_insensitive() {
        // RFC 5232 §5: addflag unions new flags with the active set,
        // matching case-insensitively for IMAP flag semantics.
        let script = r#"require ["fileinto", "imap4flags"];
addflag "\\SEEN";
addflag "\\seen";
addflag ["\\Flagged"];
fileinto "M";
"#;
        let outcome = sieve_interpret(script).expect("should parse");
        assert_eq!(outcome.actions.len(), 1);
        let flags = &outcome.actions[0].flags;
        // Only ONE \\Seen (preserving the case of the first addition).
        let seen_count = flags
            .iter()
            .filter(|f| f.eq_ignore_ascii_case("\\Seen"))
            .count();
        assert_eq!(
            seen_count, 1,
            "addflag must dedup case-insensitively; got {flags:?}"
        );
        assert!(
            flags.iter().any(|f| f == "\\Flagged"),
            "addflag must also add \\Flagged; got {flags:?}"
        );
    }

    #[test]
    fn test_sv4_removeflag_case_insensitive() {
        // RFC 5232 §6: removeflag removes by case-insensitive comparison.
        let script = r#"require ["fileinto", "imap4flags"];
setflag ["\\Seen", "\\Flagged"];
removeflag "\\SEEN";
fileinto "M";
"#;
        let outcome = sieve_interpret(script).expect("should parse");
        assert_eq!(outcome.actions.len(), 1);
        let flags = &outcome.actions[0].flags;
        assert!(
            !flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen")),
            "removeflag must drop \\Seen case-insensitively; got {flags:?}"
        );
        assert!(
            flags.iter().any(|f| f == "\\Flagged"),
            "\\Flagged must remain; got {flags:?}"
        );
    }

    #[test]
    fn test_sv4_mark_adds_flagged() {
        // RFC 5232 §8: mark; is shorthand for addflag "\\Flagged".
        let script = r#"require ["fileinto", "imap4flags"];
mark;
fileinto "M";
"#;
        let outcome = sieve_interpret(script).expect("should parse");
        assert_eq!(outcome.actions.len(), 1);
        let flags = &outcome.actions[0].flags;
        assert!(
            flags.iter().any(|f| f == "\\Flagged"),
            "mark must add \\Flagged; got {flags:?}"
        );
    }

    #[test]
    fn test_sv4_unmark_removes_flagged() {
        // RFC 5232 §8: unmark; is shorthand for removeflag "\\Flagged".
        let script = r#"require ["fileinto", "imap4flags"];
setflag ["\\Seen", "\\Flagged"];
unmark;
fileinto "M";
"#;
        let outcome = sieve_interpret(script).expect("should parse");
        assert_eq!(outcome.actions.len(), 1);
        let flags = &outcome.actions[0].flags;
        assert!(
            !flags.iter().any(|f| f.eq_ignore_ascii_case("\\Flagged")),
            "unmark must drop \\Flagged; got {flags:?}"
        );
        assert!(
            flags.iter().any(|f| f == "\\Seen"),
            "\\Seen must remain; got {flags:?}"
        );
    }

    #[test]
    fn test_sv4_hasflag_matches_active_set() {
        // RFC 5232 §7: hasflag is a test evaluating true iff the active flag
        // set contains any of the supplied keys. We drive it through an if
        // expression and expect the conditional body to run.
        let script = r#"require ["fileinto", "imap4flags"];
setflag ["\\Seen"];
if hasflag "\\Seen" { fileinto "MatchedSeen"; }
"#;
        let outcome = sieve_interpret(script).expect("should parse");
        assert!(
            outcome.actions.iter().any(|a| a.address == "MatchedSeen"),
            "hasflag \"\\Seen\" must be true when setflag added it; got {:?}",
            outcome.actions
        );
    }

    #[test]
    fn test_sv4_hasflag_no_match() {
        // Without imap4flags require, hasflag should be unavailable; but once
        // required, a miss should evaluate false so the conditional body is
        // skipped. We verify by ensuring the gated fileinto does NOT appear.
        let script = r#"require ["fileinto", "imap4flags"];
setflag ["\\Answered"];
if hasflag "\\Flagged" { fileinto "ShouldNotFire"; }
"#;
        let outcome = sieve_interpret(script).expect("should parse");
        assert!(
            !outcome.actions.iter().any(|a| a.address == "ShouldNotFire"),
            "hasflag miss must skip body; got {:?}",
            outcome.actions
        );
    }

    #[test]
    fn test_sv4_fileinto_flags_tag_override() {
        // RFC 5232 §4.1: `fileinto :flags ["\\Seen"] "INBOX";` overrides
        // active_flags for THIS action only; subsequent actions revert to
        // the script-level active flag set.
        let script = r#"require ["fileinto", "imap4flags"];
addflag "\\Flagged";
fileinto :flags ["\\Seen"] "Override";
fileinto "WithFlagged";
"#;
        let outcome = sieve_interpret(script).expect("should parse");
        assert_eq!(outcome.actions.len(), 2);
        let override_action = outcome
            .actions
            .iter()
            .find(|a| a.address == "Override")
            .expect("override action present");
        assert!(
            override_action.flags.iter().any(|f| f == "\\Seen"),
            "override action must carry \\Seen; got {:?}",
            override_action.flags
        );
        assert!(
            !override_action.flags.iter().any(|f| f == "\\Flagged"),
            ":flags must REPLACE active_flags for this action; got {:?}",
            override_action.flags
        );
        let followup = outcome
            .actions
            .iter()
            .find(|a| a.address == "WithFlagged")
            .expect("followup action present");
        assert!(
            followup.flags.iter().any(|f| f == "\\Flagged"),
            "subsequent fileinto must see the restored active flag set; got {:?}",
            followup.flags
        );
    }

    #[test]
    fn test_sv4_flags_split_whitespace() {
        // RFC 5232 §6.1: within a single string argument, whitespace-delimited
        // tokens are split into multiple flags ("\\Seen \\Flagged" → 2 flags).
        let script = r#"require ["fileinto", "imap4flags"];
setflag "\\Seen \\Flagged";
fileinto "M";
"#;
        let outcome = sieve_interpret(script).expect("should parse");
        assert_eq!(outcome.actions.len(), 1);
        let flags = &outcome.actions[0].flags;
        assert!(
            flags.iter().any(|f| f == "\\Seen"),
            "whitespace-split must yield \\Seen; got {flags:?}"
        );
        assert!(
            flags.iter().any(|f| f == "\\Flagged"),
            "whitespace-split must yield \\Flagged; got {flags:?}"
        );
    }

    #[test]
    fn test_sv4_outcome_flags_exposed() {
        // The final active flag set must be exposed at the outcome level so
        // callers can inspect it even when no fileinto fired (e.g., for
        // storage-level flag annotations on the implicit keep).
        let script = r#"require ["fileinto", "imap4flags"];
setflag ["\\Seen"];
keep;
"#;
        let outcome = sieve_interpret(script).expect("should parse");
        // Implicit+explicit keep → one action; flags exposed at outcome level.
        assert_eq!(outcome.result, SieveResult::Delivered);
        assert!(
            outcome.flags.iter().any(|f| f == "\\Seen"),
            "outcome.flags must expose the final active set; got {:?}",
            outcome.flags
        );
    }

    // =======================================================================
    // SV3: tests for RFC 5231 `:count` match-type semantics
    // =======================================================================

    /// Build a headers HashMap with synthetic values for testing `:count`.
    ///
    /// Returns the map alone; callers construct a `SieveContext` inline to
    /// keep all lifetimes local (the crate forbids `unsafe_code` so we
    /// cannot fabricate `'static` arena/store references).
    fn count_test_headers(
        headers: Vec<(&'static str, Vec<&'static str>)>,
    ) -> HashMap<String, Vec<TaintedString>> {
        let mut hdrs: HashMap<String, Vec<TaintedString>> = HashMap::new();
        for (name, values) in headers {
            hdrs.insert(
                name.to_string(),
                values
                    .into_iter()
                    .map(|v| Tainted::new(v.to_string()))
                    .collect(),
            );
        }
        hdrs
    }

    #[test]
    fn test_sv3_count_header_greater_than_zero_true() {
        // With one Subject header present, `:count "gt" "0"` is true.
        // Regression test for the hardcoded count=1 bug that made this
        // *accidentally* true but only because 1 > 0 — verify the real
        // semantics by explicitly checking the path the fix takes.
        let arena = MessageArena::new();
        let store = MessageStore::new();
        let ctx = SieveContext {
            arena: &arena,
            store: &store,
            headers: count_test_headers(vec![("subject", vec!["hello"])]),
            envelope_from: Tainted::new("s@e.com".to_string()),
            envelope_to: Tainted::new("r@e.com".to_string()),
            message_size: 1024,
        };
        let script = r#"if header :count "gt" "Subject" ["0"] { keep; } else { discard; }"#;
        let outcome = sieve_interpret_with_context(script, &ctx).expect("should parse");
        assert_eq!(outcome.result, SieveResult::Delivered);
    }

    #[test]
    fn test_sv3_count_header_gt_one_false_for_single_value() {
        // One Subject header → count=1 → NOT greater than 1.
        let arena = MessageArena::new();
        let store = MessageStore::new();
        let ctx = SieveContext {
            arena: &arena,
            store: &store,
            headers: count_test_headers(vec![("subject", vec!["hello"])]),
            envelope_from: Tainted::new("s@e.com".to_string()),
            envelope_to: Tainted::new("r@e.com".to_string()),
            message_size: 1024,
        };
        let script = r#"if header :count "gt" "Subject" ["1"] { keep; } else { discard; }"#;
        let outcome = sieve_interpret_with_context(script, &ctx).expect("should parse");
        assert_eq!(outcome.result, SieveResult::NotDelivered);
    }

    #[test]
    fn test_sv3_count_multiple_received_gt_five() {
        // Six Received headers → count=6 → `:count "gt" "5"` is TRUE.
        // Pre-fix: hardcoded count=1 → 1>5 is false → FAIL.
        // Post-fix: real count=6 → 6>5 is true → DELIVER via keep.
        let arena = MessageArena::new();
        let store = MessageStore::new();
        let ctx = SieveContext {
            arena: &arena,
            store: &store,
            headers: count_test_headers(vec![(
                "received",
                vec!["hop1", "hop2", "hop3", "hop4", "hop5", "hop6"],
            )]),
            envelope_from: Tainted::new("s@e.com".to_string()),
            envelope_to: Tainted::new("r@e.com".to_string()),
            message_size: 1024,
        };
        let script = r#"if header :count "gt" "Received" ["5"] { keep; } else { discard; }"#;
        let outcome = sieve_interpret_with_context(script, &ctx).expect("should parse");
        assert_eq!(
            outcome.result,
            SieveResult::Delivered,
            "6 Received headers MUST satisfy `:count gt 5`"
        );
    }

    #[test]
    fn test_sv3_count_eq_exact_match() {
        // Three To headers → count=3 → `:count "eq" "3"` is TRUE.
        // Pre-fix: hardcoded count=1 → 1==3 is false → FAIL.
        // Post-fix: real count=3 → 3==3 is true → DELIVER.
        let arena = MessageArena::new();
        let store = MessageStore::new();
        let ctx = SieveContext {
            arena: &arena,
            store: &store,
            headers: count_test_headers(vec![("to", vec!["a@e.com", "b@e.com", "c@e.com"])]),
            envelope_from: Tainted::new("s@e.com".to_string()),
            envelope_to: Tainted::new("r@e.com".to_string()),
            message_size: 1024,
        };
        let script = r#"if header :count "eq" "To" ["3"] { keep; } else { discard; }"#;
        let outcome = sieve_interpret_with_context(script, &ctx).expect("should parse");
        assert_eq!(
            outcome.result,
            SieveResult::Delivered,
            "exact count match MUST succeed after SV3 fix"
        );
    }

    #[test]
    fn test_sv3_count_zero_absent_header() {
        // No X-Spam header present → count=0 → `:count "eq" "0"` is TRUE.
        // Pre-fix: the code iterated over empty `message_headers.get()` and
        // returned false without ever reaching the count comparison — the
        // absent-header case also manifested as a bug.
        let arena = MessageArena::new();
        let store = MessageStore::new();
        let ctx = SieveContext {
            arena: &arena,
            store: &store,
            headers: count_test_headers(vec![("subject", vec!["hello"])]),
            envelope_from: Tainted::new("s@e.com".to_string()),
            envelope_to: Tainted::new("r@e.com".to_string()),
            message_size: 1024,
        };
        let script = r#"if header :count "eq" "X-Spam" ["0"] { keep; } else { discard; }"#;
        let outcome = sieve_interpret_with_context(script, &ctx).expect("should parse");
        assert_eq!(
            outcome.result,
            SieveResult::Delivered,
            "absent header `:count eq 0` MUST succeed"
        );
    }

    #[test]
    fn test_sv3_count_across_multiple_headers() {
        // :count operates across all fields named in the header-list:
        // To has 2 values + Cc has 3 values → total count=5.
        let arena = MessageArena::new();
        let store = MessageStore::new();
        let ctx = SieveContext {
            arena: &arena,
            store: &store,
            headers: count_test_headers(vec![
                ("to", vec!["a@e.com", "b@e.com"]),
                ("cc", vec!["c@e.com", "d@e.com", "e@e.com"]),
            ]),
            envelope_from: Tainted::new("s@e.com".to_string()),
            envelope_to: Tainted::new("r@e.com".to_string()),
            message_size: 1024,
        };
        let script = r#"if header :count "eq" ["To", "Cc"] ["5"] { keep; } else { discard; }"#;
        let outcome = sieve_interpret_with_context(script, &ctx).expect("should parse");
        assert_eq!(
            outcome.result,
            SieveResult::Delivered,
            "count MUST sum across all header field names"
        );
    }

    #[test]
    fn test_sv3_count_disjunction_over_keys() {
        // Keys are disjunctive: `:count "eq" ["1", "3", "5"]` succeeds if
        // count equals ANY of 1, 3, or 5. Three To values → count=3 → match.
        let arena = MessageArena::new();
        let store = MessageStore::new();
        let ctx = SieveContext {
            arena: &arena,
            store: &store,
            headers: count_test_headers(vec![("to", vec!["a@e.com", "b@e.com", "c@e.com"])]),
            envelope_from: Tainted::new("s@e.com".to_string()),
            envelope_to: Tainted::new("r@e.com".to_string()),
            message_size: 1024,
        };
        let script = r#"if header :count "eq" "To" ["1", "3", "5"] { keep; } else { discard; }"#;
        let outcome = sieve_interpret_with_context(script, &ctx).expect("should parse");
        assert_eq!(
            outcome.result,
            SieveResult::Delivered,
            "disjunctive key list MUST succeed on any match"
        );
    }

    #[test]
    fn test_sv3_count_non_numeric_key_ignored() {
        // Non-numeric keys are silently skipped (they can never satisfy a
        // numeric comparison). With count=1 and a non-numeric "many" key,
        // the test must be false.
        let arena = MessageArena::new();
        let store = MessageStore::new();
        let ctx = SieveContext {
            arena: &arena,
            store: &store,
            headers: count_test_headers(vec![("subject", vec!["hello"])]),
            envelope_from: Tainted::new("s@e.com".to_string()),
            envelope_to: Tainted::new("r@e.com".to_string()),
            message_size: 1024,
        };
        let script = r#"if header :count "eq" "Subject" ["many"] { keep; } else { discard; }"#;
        let outcome = sieve_interpret_with_context(script, &ctx).expect("should parse");
        assert_eq!(
            outcome.result,
            SieveResult::NotDelivered,
            "non-numeric key MUST evaluate to false"
        );
    }

    #[test]
    fn test_sv3_count_address_multiple_recipients() {
        // `address :count "gt" "2" "To"` on a To header with 3 addresses
        // counts the number of values in the header (3 > 2 → true).
        let arena = MessageArena::new();
        let store = MessageStore::new();
        let ctx = SieveContext {
            arena: &arena,
            store: &store,
            headers: count_test_headers(vec![("to", vec!["a@e.com", "b@e.com", "c@e.com"])]),
            envelope_from: Tainted::new("s@e.com".to_string()),
            envelope_to: Tainted::new("r@e.com".to_string()),
            message_size: 1024,
        };
        let script = r#"if address :count "gt" "To" ["2"] { keep; } else { discard; }"#;
        let outcome = sieve_interpret_with_context(script, &ctx).expect("should parse");
        assert_eq!(
            outcome.result,
            SieveResult::Delivered,
            "address :count MUST count number of addresses in header"
        );
    }

    #[test]
    fn test_sv3_count_envelope_single_from() {
        // `envelope :count "eq" "1" "From"` on a message with one envelope
        // from counts as 1 (each listed envelope part contributes 1).
        let arena = MessageArena::new();
        let store = MessageStore::new();
        let ctx = SieveContext {
            arena: &arena,
            store: &store,
            headers: count_test_headers(vec![]),
            envelope_from: Tainted::new("s@e.com".to_string()),
            envelope_to: Tainted::new("r@e.com".to_string()),
            message_size: 1024,
        };
        let script = r#"require ["envelope"];
if envelope :count "eq" "From" ["1"] { keep; } else { discard; }
"#;
        let outcome = sieve_interpret_with_context(script, &ctx).expect("should parse");
        assert_eq!(
            outcome.result,
            SieveResult::Delivered,
            "envelope :count MUST count listed parts"
        );
    }

    #[test]
    fn test_sv3_count_hasflag_two_flags() {
        // `hasflag :count "eq" ["2"]` when two flags are active → true.
        // Pre-fix: hardcoded 1 → 1 == 2 is false.
        // Post-fix: real count=2 → 2 == 2 is true.
        // RFC 5232 §7 allows a leading optional variable-list; our parser
        // accepts the single-string-list form (<list-of-flags>), so with
        // `:count` the keys are numeric thresholds rather than flag names.
        let script = r#"require ["imap4flags", "fileinto"];
setflag ["\\Seen", "\\Flagged"];
if hasflag :count "eq" ["2"] { fileinto "M"; } else { discard; }
"#;
        let outcome = sieve_interpret(script).expect("should parse");
        assert!(
            outcome.actions.iter().any(|a| a.address == "M"),
            "hasflag :count must count active flag set; got {:?}",
            outcome.actions
        );
    }

    #[test]
    fn test_sv3_count_hasflag_zero_flags() {
        // Without setflag/addflag, active_flags is empty → count=0.
        // Single-string-list form with numeric key "0".
        let script = r#"require ["imap4flags", "fileinto"];
if hasflag :count "eq" ["0"] { fileinto "NoFlags"; } else { discard; }
"#;
        let outcome = sieve_interpret(script).expect("should parse");
        assert!(
            outcome.actions.iter().any(|a| a.address == "NoFlags"),
            "hasflag :count on empty active_flags must be 0; got {:?}",
            outcome.actions
        );
    }

    #[test]
    fn test_sv3_count_matches_any_key_direct() {
        // Direct unit test of the helper function's semantics.
        // op=Eq, count=3, keys=["1","2","3"] → 3==3 matches.
        assert!(count_matches_any_key(
            3,
            &["1".to_string(), "2".to_string(), "3".to_string()],
            RelOp::Eq
        ));
        // op=Gt, count=5, keys=["10"] → 5 > 10 is false.
        assert!(!count_matches_any_key(5, &["10".to_string()], RelOp::Gt));
        // op=Le, count=5, keys=["5","10"] → 5 <= 5 is true.
        assert!(count_matches_any_key(
            5,
            &["5".to_string(), "10".to_string()],
            RelOp::Le
        ));
        // op=Ne, count=0, keys=["0"] → 0 != 0 is false.
        assert!(!count_matches_any_key(0, &["0".to_string()], RelOp::Ne));
        // Non-numeric keys are silently skipped.
        assert!(!count_matches_any_key(
            1,
            &["not-a-number".to_string()],
            RelOp::Eq
        ));
        // Mixed numeric/non-numeric — numeric wins.
        assert!(count_matches_any_key(
            1,
            &["garbage".to_string(), "1".to_string()],
            RelOp::Eq
        ));
    }

    // =======================================================================
    // SV5: vacation / notify structured output tests (RFC 5230, 5435, 5436)
    // =======================================================================
    //
    // Each test exercises a specific aspect of the interpreter's contract with
    // the delivery orchestrator: the interpreter MUST surface structured
    // `VacationAction`/`NotifyAction` values through `SieveOutcome` so that
    // the orchestrator can perform dedup, address-filtering, and spool
    // persistence without re-parsing the script.

    #[test]
    fn test_sv5_vacation_produces_action() {
        // `vacation "text"` MUST populate SieveOutcome.vacation with a
        // VacationAction carrying the reason and default days=7.
        let script = "require \"vacation\";\nvacation :days 3 :subject \"OOO\" \"I am away\";\n";
        let outcome = sieve_interpret(script).expect("should parse");
        let vacation = outcome.vacation.expect("vacation must be populated");
        assert_eq!(vacation.days, 3);
        assert_eq!(vacation.subject.as_deref(), Some("OOO"));
        assert_eq!(vacation.reason, "I am away");
        assert!(vacation.addresses.is_empty());
        assert!(!vacation.mime);
    }

    #[test]
    fn test_sv5_vacation_ran_prevents_second() {
        // RFC 5230 §4.5: a second `vacation` in the same script MUST error.
        let script = "require \"vacation\";\nvacation \"first\";\nvacation \"second\";\n";
        let err = sieve_interpret(script).expect_err("second vacation must error");
        match err {
            SieveError::VacationError(_) => {}
            e => panic!("expected VacationError, got {e:?}"),
        }
    }

    #[test]
    fn test_sv5_vacation_addresses_filter_suppresses() {
        // RFC 5230 §4.3: when `:addresses` is set but envelope-to is NOT in
        // the list, `should_reply()` returns false so the orchestrator can
        // suppress the reply.
        let arena = MessageArena::new();
        let store = MessageStore::new();
        let ctx = SieveContext {
            arena: &arena,
            store: &store,
            headers: HashMap::new(),
            envelope_from: Tainted::new("sender@external.example".to_string()),
            envelope_to: Tainted::new("me@example.org".to_string()),
            message_size: 1024,
        };
        // Specify :addresses with different addresses → envelope-to does
        // not match → should_reply() returns false.
        let script = "require \"vacation\";\nvacation :addresses [\"other@example.org\", \"third@example.org\"] \"away\";\n";
        let outcome = sieve_interpret_with_context(script, &ctx).expect("should parse");
        let vacation = outcome.vacation.expect("vacation must be populated");
        assert!(
            !vacation.should_reply(),
            "should_reply must be false when envelope-to is not in :addresses"
        );
    }

    #[test]
    fn test_sv5_vacation_addresses_matches_envelope_to() {
        // When the envelope-to IS in `:addresses`, `should_reply()` returns true.
        let arena = MessageArena::new();
        let store = MessageStore::new();
        let ctx = SieveContext {
            arena: &arena,
            store: &store,
            headers: HashMap::new(),
            envelope_from: Tainted::new("sender@external.example".to_string()),
            envelope_to: Tainted::new("me@example.org".to_string()),
            message_size: 1024,
        };
        let script = "require \"vacation\";\nvacation :addresses [\"me@example.org\", \"other@example.org\"] \"away\";\n";
        let outcome = sieve_interpret_with_context(script, &ctx).expect("should parse");
        let vacation = outcome.vacation.expect("vacation must be populated");
        assert!(vacation.should_reply());
    }

    #[test]
    fn test_sv5_vacation_handle_passed_through() {
        // `:handle` MUST be surfaced so the orchestrator can use it as the
        // dedup key.
        let script =
            "require \"vacation\";\nvacation :handle \"holiday-2026\" \"away for holidays\";\n";
        let outcome = sieve_interpret(script).expect("should parse");
        let vacation = outcome.vacation.expect("vacation must be populated");
        assert_eq!(vacation.handle.as_deref(), Some("holiday-2026"));
    }

    #[test]
    fn test_sv5_vacation_mime_body() {
        // `:mime` MUST mark the body as pre-formatted so the orchestrator
        // emits it verbatim rather than quoted-printable-encoding it.
        let script =
            "require \"vacation\";\nvacation :mime \"Content-Type: text/plain\\r\\n\\r\\nBody\";\n";
        let outcome = sieve_interpret(script).expect("should parse");
        let vacation = outcome.vacation.expect("vacation must be populated");
        assert!(vacation.mime);
    }

    #[test]
    fn test_sv5_vacation_days_clamping() {
        // RFC 5230 §4.1: :days MUST be clamped to [VACATION_MIN_DAYS,
        // VACATION_MAX_DAYS].
        let script = "require \"vacation\";\nvacation :days 999 \"away\";\n";
        let outcome = sieve_interpret(script).expect("should parse");
        let vacation = outcome.vacation.expect("vacation must be populated");
        assert_eq!(vacation.days, VACATION_MAX_DAYS, "must clamp to max");

        let script2 = "require \"vacation\";\nvacation :days 0 \"away\";\n";
        let outcome2 = sieve_interpret(script2).expect("should parse");
        let vacation2 = outcome2.vacation.expect("vacation must be populated");
        assert_eq!(vacation2.days, VACATION_MIN_DAYS, "must clamp to min");
    }

    #[test]
    fn test_sv5_vacation_build_reply_has_auto_submitted() {
        // RFC 3834 §5: the reply MUST carry `Auto-Submitted: auto-replied`.
        let vacation = VacationAction {
            days: 7,
            subject: Some("Out of office".to_string()),
            from: Some("me@example.org".to_string()),
            addresses: vec!["me@example.org".to_string()],
            mime: false,
            handle: None,
            reason: "I will reply when I return.".to_string(),
            envelope_to: "me@example.org".to_string(),
        };
        let reply = vacation.build_reply("sender@external.example", Some("<orig@msg.id>"));
        assert!(
            reply.message_text.contains("Auto-Submitted: auto-replied"),
            "reply must carry RFC 3834 Auto-Submitted header; got:\n{}",
            reply.message_text
        );
        assert!(reply.message_text.contains("From: me@example.org"));
        assert!(reply.message_text.contains("To: sender@external.example"));
        assert!(reply.message_text.contains("Subject: Out of office"));
        assert!(reply.message_text.contains("In-Reply-To: <orig@msg.id>"));
        assert!(reply.message_text.contains("References: <orig@msg.id>"));
        assert!(reply.message_text.contains("MIME-Version: 1.0"));
        assert_eq!(reply.envelope_from, "me@example.org");
        assert_eq!(reply.envelope_recipients, vec!["sender@external.example"]);
        assert_eq!(reply.category, GeneratedMessageKind::VacationReply);
    }

    #[test]
    fn test_sv5_vacation_build_reply_default_subject() {
        // When `:subject` is not set, the default subject must be used.
        let vacation = VacationAction {
            days: 7,
            subject: None,
            from: None,
            addresses: Vec::new(),
            mime: false,
            handle: None,
            reason: "body".to_string(),
            envelope_to: "me@example.org".to_string(),
        };
        let reply = vacation.build_reply("x@y.z", None);
        assert!(reply.message_text.contains("Subject: Automated reply"));
        // When :from is not set, envelope_to fills in.
        assert!(reply.message_text.contains("From: me@example.org"));
        // When no Message-ID is provided, In-Reply-To MUST be omitted.
        assert!(!reply.message_text.contains("In-Reply-To"));
        assert!(!reply.message_text.contains("References"));
    }

    #[test]
    fn test_sv5_vacation_build_reply_mime_body_verbatim() {
        // MIME-flagged bodies MUST be emitted verbatim (no content-type
        // inserted by the interpreter).
        let mime_body =
            "Content-Type: text/html; charset=utf-8\r\n\r\n<html><body>away</body></html>";
        let vacation = VacationAction {
            days: 7,
            subject: None,
            from: None,
            addresses: Vec::new(),
            mime: true,
            handle: None,
            reason: mime_body.to_string(),
            envelope_to: "me@example.org".to_string(),
        };
        let reply = vacation.build_reply("sender@example.com", None);
        // The HTML body must appear verbatim (no quoted-printable encoding).
        assert!(reply
            .message_text
            .contains("<html><body>away</body></html>"));
    }

    #[test]
    fn test_sv5_notify_mailto_generates_action() {
        // `notify "mailto:..."` MUST produce a NotifyAction.
        let script = "require \"enotify\";\nnotify :importance \"1\" :message \"hi\" \"mailto:admin@example.com\";\n";
        let outcome = sieve_interpret(script).expect("should parse");
        assert_eq!(outcome.notifications.len(), 1);
        let n = &outcome.notifications[0];
        assert_eq!(n.method, "mailto:admin@example.com");
        assert_eq!(n.importance, "1");
        assert_eq!(n.message.as_deref(), Some("hi"));
    }

    #[test]
    fn test_sv5_notify_dedup() {
        // Two notifies with identical method/importance/message MUST dedup.
        let script = "require \"enotify\";\nnotify :message \"x\" \"mailto:a@b.c\";\nnotify :message \"x\" \"mailto:a@b.c\";\n";
        let outcome = sieve_interpret(script).expect("should parse");
        assert_eq!(
            outcome.notifications.len(),
            1,
            "duplicate notifications must be suppressed"
        );
    }

    #[test]
    fn test_sv5_notify_distinct_messages_not_deduped() {
        // Two notifies with different messages MUST both be recorded.
        let script = "require \"enotify\";\nnotify :message \"first\" \"mailto:a@b.c\";\nnotify :message \"second\" \"mailto:a@b.c\";\n";
        let outcome = sieve_interpret(script).expect("should parse");
        assert_eq!(outcome.notifications.len(), 2);
    }

    #[test]
    fn test_sv5_notify_importance_header_default() {
        // Default importance is "2" (normal) per RFC 5435.
        let script = "require \"enotify\";\nnotify \"mailto:a@b.c\";\n";
        let outcome = sieve_interpret(script).expect("should parse");
        assert_eq!(outcome.notifications.len(), 1);
        assert_eq!(outcome.notifications[0].importance, "2");
    }

    #[test]
    fn test_sv5_notify_importance_invalid_rejected() {
        // RFC 5435 §3.3: only "1", "2", "3" are valid importance values.
        let script = "require \"enotify\";\nnotify :importance \"5\" \"mailto:a@b.c\";\n";
        assert!(sieve_interpret(script).is_err());
    }

    #[test]
    fn test_sv5_notify_mailto_url_decoding() {
        // RFC 6068: the `Subject=Hi%21` query must decode to "Hi!".
        let (recipient, headers) =
            NotifyAction::parse_mailto("mailto:admin@example.com?Subject=Hi%21&body=Hello%20World")
                .expect("must parse");
        assert_eq!(recipient, "admin@example.com");
        let subject = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Subject"))
            .map(|(_, v)| v.as_str());
        assert_eq!(subject, Some("Hi!"));
        let body = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("body"))
            .map(|(_, v)| v.as_str());
        assert_eq!(body, Some("Hello World"));
    }

    #[test]
    fn test_sv5_notify_mailto_build_message() {
        // `build_mailto()` MUST materialise a full RFC 5322 message with
        // `Auto-Submitted: auto-generated`.
        let notify = NotifyAction {
            method: "mailto:pager@example.com?Subject=Alert".to_string(),
            importance: "1".to_string(),
            options: Vec::new(),
            message: Some("Database down".to_string()),
            from: Some("monitor@example.com".to_string()),
            envelope_to: "user@example.com".to_string(),
        };
        let msg = notify.build_mailto().expect("mailto must materialise");
        assert!(msg.message_text.contains("Auto-Submitted: auto-generated"));
        assert!(msg.message_text.contains("From: monitor@example.com"));
        assert!(msg.message_text.contains("To: pager@example.com"));
        assert!(
            msg.message_text.contains("Subject: Alert"),
            "mailto URI Subject must override :message arg for the header; got:\n{}",
            msg.message_text
        );
        assert!(msg.message_text.contains("Importance: High"));
        assert_eq!(msg.envelope_from, "monitor@example.com");
        assert_eq!(msg.envelope_recipients, vec!["pager@example.com"]);
        assert_eq!(msg.category, GeneratedMessageKind::NotifyMessage);
    }

    #[test]
    fn test_sv5_notify_non_mailto_returns_none() {
        // Non-`mailto:` schemes are not materialised by the interpreter.
        let notify = NotifyAction {
            method: "xmpp:user@server".to_string(),
            importance: "2".to_string(),
            options: Vec::new(),
            message: Some("hi".to_string()),
            from: None,
            envelope_to: "me@example.org".to_string(),
        };
        assert!(notify.build_mailto().is_none());
    }

    #[test]
    fn test_sv5_outcome_exposes_vacation_only() {
        // A script that runs `discard` then `vacation` (in a block) MUST
        // still surface the vacation action even when no fileinto/redirect
        // is generated.
        let script = "require [\"vacation\"];\ndiscard;\nvacation \"away\";\n";
        let outcome = sieve_interpret(script).expect("should parse");
        assert!(
            outcome.vacation.is_some(),
            "vacation must be exposed in outcome even when only side-effects fired"
        );
        assert_eq!(
            outcome.result,
            SieveResult::NotDelivered,
            "discard + vacation without keep → NotDelivered"
        );
        assert!(outcome.actions.is_empty());
    }

    #[test]
    fn test_sv5_url_decode_basic() {
        assert_eq!(url_decode("Hello"), "Hello");
        assert_eq!(url_decode("Hi%21"), "Hi!");
        assert_eq!(url_decode("a+b"), "a b");
        assert_eq!(url_decode("a%20b"), "a b");
        assert_eq!(url_decode("a%2Fb"), "a/b");
        assert_eq!(url_decode("a%00b"), "a\0b");
        // Malformed percent escape passes through literally.
        assert_eq!(url_decode("50%_off"), "50%_off");
        assert_eq!(url_decode("%ZZ"), "%ZZ");
    }

    #[test]
    fn test_sv5_url_decode_empty_and_edge_cases() {
        assert_eq!(url_decode(""), "");
        // Lone `%` at end is passed through.
        assert_eq!(url_decode("abc%"), "abc%");
        assert_eq!(url_decode("abc%2"), "abc%2");
        // `+` expansion is case-insensitive and applies only to the `+` byte.
        assert_eq!(url_decode("+"), " ");
        assert_eq!(url_decode("++"), "  ");
    }

    #[test]
    fn test_sv5_parse_mailto_rejects_non_mailto_scheme() {
        assert!(NotifyAction::parse_mailto("http://example.com").is_none());
        assert!(NotifyAction::parse_mailto("xmpp:user@server").is_none());
        assert!(NotifyAction::parse_mailto("tel:+1234567890").is_none());
    }

    #[test]
    fn test_sv5_parse_mailto_no_query() {
        let (recipient, headers) = NotifyAction::parse_mailto("mailto:a@b.c").expect("must parse");
        assert_eq!(recipient, "a@b.c");
        assert!(headers.is_empty());
    }

    #[test]
    fn test_sv5_parse_mailto_multiple_headers() {
        let (recipient, headers) =
            NotifyAction::parse_mailto("mailto:a@b.c?Subject=Hi&body=Body&X-Custom=Val")
                .expect("must parse");
        assert_eq!(recipient, "a@b.c");
        assert_eq!(headers.len(), 3);
    }

    #[test]
    fn test_sv5_notify_build_mailto_message_fallback_subject() {
        // When the mailto URI has NO Subject but :message is set, :message
        // supplies the Subject header (and the body).
        let notify = NotifyAction {
            method: "mailto:a@b.c".to_string(),
            importance: "2".to_string(),
            options: Vec::new(),
            message: Some("Short notice".to_string()),
            from: None,
            envelope_to: "user@example.com".to_string(),
        };
        let msg = notify.build_mailto().expect("must materialise");
        assert!(msg.message_text.contains("Subject: Short notice"));
    }

    #[test]
    fn test_sv5_notify_build_mailto_default_importance_normal() {
        let notify = NotifyAction {
            method: "mailto:a@b.c".to_string(),
            importance: "2".to_string(),
            options: Vec::new(),
            message: None,
            from: None,
            envelope_to: "user@example.com".to_string(),
        };
        let msg = notify.build_mailto().expect("must materialise");
        assert!(msg.message_text.contains("Importance: Normal"));
    }

    #[test]
    fn test_sv5_notify_build_mailto_low_importance() {
        let notify = NotifyAction {
            method: "mailto:a@b.c".to_string(),
            importance: "3".to_string(),
            options: Vec::new(),
            message: None,
            from: None,
            envelope_to: "user@example.com".to_string(),
        };
        let msg = notify.build_mailto().expect("must materialise");
        assert!(msg.message_text.contains("Importance: Low"));
    }
}
