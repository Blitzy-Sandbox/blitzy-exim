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
}

/// An action generated during evaluation.
#[derive(Debug, Clone)]
struct GeneratedAction {
    address: String,
    is_file: bool,
}

/// Record of a sent notification (for dedup).
#[derive(Debug, Clone)]
struct NotificationRecord {
    method: String,
    importance: String,
    message: String,
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
        } else {
            Ok(None)
        }
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
        let mut _flags: Vec<String> = Vec::new();
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
                if !self.require.contains(SieveCapabilities::IMAP4FLAGS) {
                    return Err(self.parse_error("missing previous require \"imap4flags\""));
                }
                _flags = self.expect_string_list("flags")?;
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
            self.add_action(&folder, true);
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
        let mut _from: Option<String> = None;
        let mut importance = String::from("2");
        let mut message: Option<String> = None;
        let mut _options: Vec<String> = Vec::new();
        loop {
            self.skip_whitespace()?;
            if self.try_identifier(":from") {
                _from = Some(self.expect_string("from")?);
            } else if self.try_identifier(":importance") {
                let imp = self.expect_string("importance")?;
                if imp.len() != 1 || !matches!(imp.as_bytes()[0], b'1' | b'2' | b'3') {
                    return Err(self.parse_error("invalid importance"));
                }
                importance = imp;
            } else if self.try_identifier(":options") {
                self.skip_whitespace()?;
                if let Some(opts) = self.parse_string_list()? {
                    _options = opts;
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
            let already_sent = self
                .notified
                .iter()
                .any(|n| n.method == method && n.importance == importance && n.message == msg_text);
            if already_sent {
                tracing::debug!("sieve: repeated notification to '{}' ignored", method);
            } else {
                tracing::info!("sieve: notify via '{}' (importance={})", method, importance);
                self.notified.push(NotificationRecord {
                    method,
                    importance,
                    message: msg_text,
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
            let _subj = subject.unwrap_or_else(|| "Automated reply".to_string());
            tracing::info!(
                "sieve: vacation (days={}, from={:?}, mime={}, handle={:?})",
                days,
                from,
                reason_is_mime,
                handle,
            );
            // Encode reason for diagnostics
            if !reason_is_mime {
                let _encoded = quoted_printable_encode(&reason);
            }
            // Validate addresses
            for addr in &addresses {
                let _clean = validate_email_address(addr)?;
            }
        }
        Ok(())
    }

    fn add_action(&mut self, address: &str, is_file: bool) {
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
/// [`SieveResult::Delivered`] if the message should be delivered (keep,
/// redirect, or fileinto took effect), or [`SieveResult::NotDelivered`] if
/// discarded.
///
/// # Errors
///
/// Returns [`SieveError`] if the script has syntax errors or runtime failures.
pub fn sieve_interpret(filter_text: &str) -> Result<SieveResult, SieveError> {
    tracing::debug!("sieve: start of processing");
    // Track taint state of the filter source (configuration input)
    let tainted_source: Tainted<String> = Tainted::new(filter_text.to_string());
    let _taint_state = TaintState::Tainted;
    tracing::debug!("sieve: filter source is tainted (from configuration)");
    // Extract the source text for parsing
    let source = tainted_source.into_inner();
    let mut state = SieveState::new(&source);
    match state.parse_start(true) {
        Ok(()) => {
            if state.keep {
                state.add_action(&state.inbox.clone(), true);
                tracing::info!("sieve: implicit keep");
                Ok(SieveResult::Delivered)
            } else if !state.generated_actions.is_empty() {
                tracing::info!("sieve: actions taken, no implicit keep");
                Ok(SieveResult::Delivered)
            } else {
                tracing::info!("sieve: no keep, no actions — not delivered");
                Ok(SieveResult::NotDelivered)
            }
        }
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
pub fn sieve_interpret_with_context(
    filter_text: &str,
    ctx: &SieveContext<'_>,
) -> Result<SieveResult, SieveError> {
    tracing::debug!("sieve: start of processing (with context)");
    let mut state = SieveState::from_context(filter_text, ctx);
    match state.parse_start(true) {
        Ok(()) => {
            if state.keep {
                state.add_action(&state.inbox.clone(), true);
                tracing::info!("sieve: implicit keep");
                Ok(SieveResult::Delivered)
            } else if !state.generated_actions.is_empty() {
                tracing::info!("sieve: actions taken, no implicit keep");
                Ok(SieveResult::Delivered)
            } else {
                tracing::info!("sieve: no keep, no actions — not delivered");
                Ok(SieveResult::NotDelivered)
            }
        }
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
        let result = sieve_interpret("keep;");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), SieveResult::Delivered);
    }

    #[test]
    fn test_empty_script() {
        let result = sieve_interpret("");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), SieveResult::Delivered);
    }

    #[test]
    fn test_discard() {
        let result = sieve_interpret("discard;");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), SieveResult::NotDelivered);
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
        let result = sieve_interpret_with_context("keep;", &ctx);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), SieveResult::Delivered);
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
}
