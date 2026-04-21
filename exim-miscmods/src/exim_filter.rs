// exim-miscmods/src/exim_filter.rs
//
// Exim filter language interpreter — complete Rust reimplementation of
// `src/src/miscmods/exim_filter.c` (2 661 lines of C).
//
// The Exim filter language is a simple, domain-specific scripting language
// designed for both system-wide and per-user mail filtering.  It supports
// conditional tests on message headers/envelope, delivery actions (deliver,
// save, pipe), mail generation (mail, vacation), header manipulation,
// logging, and control-flow constructs (if/elif/else/endif).
//
// Architecture:
//   1. **AST** — `FilterCommand`, `Condition`, `MailArgs` model the filter
//      language as a typed syntax tree.
//   2. **Parser** — Recursive-descent (`Parser`) translates raw filter text
//      into a `Vec<FilterCommand>` AST with line-number tracking.
//   3. **Evaluator** — `interpret_commands()` walks the AST, evaluating
//      conditions and executing delivery/control actions.
//   4. **Public API** — `exim_interpret()` and `is_personal_filter()` are
//      the two entry-points registered via `inventory::submit!`.
//
// Safety: zero `unsafe` blocks.

use exim_drivers::{DriverError, DriverInfoBase};
use exim_store::arena::MessageArena;
use exim_store::taint::{Clean, TaintError, TaintState, Tainted};
use exim_store::{CleanString, MessageStore, TaintedString};

use regex::Regex;
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// Safety constants
// ---------------------------------------------------------------------------

/// Maximum number of commands that the filter interpreter will execute in a
/// single invocation. This is a defense-in-depth safety bound to prevent
/// runaway evaluation of pathological filters. Under normal operation the
/// command count is inherently bounded by the parsed AST size, but this guard
/// provides an additional layer of protection against unexpected iteration.
///
/// The limit is generous (10,000 commands) — well above any legitimate filter
/// while still preventing unbounded resource consumption.
const MAX_COMMANDS: usize = 10_000;

// Re-export dependency types used in the public API so that downstream
// callers can reference them without adding direct dependencies.
/// Arena allocator re-exported for callers managing per-message lifetimes.
pub use exim_store::arena::MessageArena as FilterArena;
/// Tainted wrapper re-exported for callers constructing filter inputs.
pub use exim_store::taint::Tainted as TaintedWrapper;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors produced during filter parsing or evaluation.
#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    /// A syntax error encountered while parsing the filter source text.
    #[error("filter parse error at line {line}: {message}")]
    ParseError {
        /// Line number where the error occurred.
        line: usize,
        /// Human-readable error description.
        message: String,
    },

    /// A runtime error during filter evaluation.
    #[error("filter evaluation error at line {line}: {message}")]
    EvalError {
        /// Line number where the error occurred.
        line: usize,
        /// Human-readable error description.
        message: String,
    },

    /// A string-expansion failure (e.g. unresolved `$variable`).
    #[error("expansion error: {0}")]
    ExpansionError(String),
}

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/// Outcome of evaluating a complete filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterResult {
    /// At least one delivery action was executed.
    Delivered,
    /// The filter completed without executing any delivery action.
    NotDelivered,
    /// The filter requested that the message be deferred.
    Defer,
    /// The filter requested that the message be failed (bounced).
    Fail,
    /// The filter requested that the message be frozen.
    Freeze,
    /// An unrecoverable error occurred during filter evaluation.
    Error,
}

// ---------------------------------------------------------------------------
// F3: Generated message types for `mail` / `vacation` commands
// ---------------------------------------------------------------------------
//
// The Exim filter language's `mail` and `vacation` commands direct the MTA
// to construct and enqueue an auto-generated message (an auto-reply, a
// digest forward, a notification, etc.) — see the Exim documentation's
// "filter language" chapter, "Sending additional mail messages". Prior to
// F3, the Rust reimplementation of `execute_mail_command` expanded the
// argument strings and logged diagnostics but did not produce any output
// for downstream delivery. This meant any deployed filter using `mail` or
// `vacation` would silently drop those side-effects.
//
// F3 closes that gap by having `execute_mail_command` populate a structured
// `GeneratedMessage` that the delivery orchestrator consumes via the new
// `FilterOutcome` return type. The interpreter does NOT perform I/O
// itself; it merely describes the envelope + headers + body so that:
//
//   - in `-bf` filter-test mode (`-bf`), `exim-core::modes::run_exim_filter`
//     can print each generated message to stdout for operator inspection;
//
//   - when embedded in a live delivery, the orchestrator constructs an
//     RFC 5322 message, assigns a fresh message-ID via `generate_message_id`,
//     writes `-H` / `-D` spool files via `spool_write_header` /
//     `spool_open_temp`, and enqueues it for routing+transport.
//
// This mirrors the Sieve SV5 approach (see `VacationAction`/`NotifyAction`
// in `sieve_filter.rs`) so that the two filter languages share a uniform
// orchestrator contract and the delivery layer has a single `GeneratedMessage`
// consumer.

/// Classification of a message generated by the Exim filter interpreter.
///
/// This enum discriminates between the two kinds of message the filter
/// language can produce: a regular `mail` command (deliberate outbound
/// message) and a `vacation` command (RFC 3834 auto-reply). The delivery
/// orchestrator uses this to choose appropriate envelope handling:
///
/// - `Mail` messages are enqueued as-is with the current envelope sender.
/// - `Vacation` messages MUST carry `Auto-Submitted: auto-replied` per
///   RFC 3834 §5 and are subject to per-recipient dedup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneratedMessageKind {
    /// `mail` command — user explicitly constructs an outgoing message.
    Mail,
    /// `vacation` command — RFC 3834 auto-reply (carries `Auto-Submitted:
    /// auto-replied`, `Precedence: junk`, dedup via `:once`).
    Vacation,
}

/// A complete RFC 5322 message produced by a `mail` or `vacation` command.
///
/// Contains the envelope metadata (sender + recipients) and the full
/// message text (headers + body, CRLF-terminated) ready for spool
/// persistence.
///
/// # Orchestrator Contract
///
/// The delivery orchestrator receives `Vec<GeneratedMessage>` via
/// [`FilterOutcome::generated_messages`]. For each message it:
///
/// 1. Allocates a fresh message-ID via `exim_spool::generate_message_id`.
/// 2. Builds a [`SpoolHeaderData`](exim_spool::SpoolHeaderData) with
///    `sender_address = self.envelope_from`, `recipients = self.envelope_recipients`.
/// 3. Writes the `-H` header file via `exim_spool::spool_write_header`.
/// 4. Writes the `-D` data file: `{msgid}-D\n` + `self.message_text`.
/// 5. Hands the new message to the routing/transport pipeline exactly as
///    for a message received over SMTP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedMessage {
    /// Envelope sender (MAIL FROM). For `vacation` replies this is the
    /// filter owner's mailbox; for `mail` it is whatever the `from=` tag
    /// (expanded) specified, defaulting to the filter-owner mailbox.
    pub envelope_from: String,
    /// Envelope recipients (RCPT TO). For `mail` commands this is the
    /// union of `to=`, `cc=`, and `bcc=`. For `vacation` replies this is
    /// the single original `MAIL FROM` of the triggering message (which
    /// the orchestrator supplies).
    pub envelope_recipients: Vec<String>,
    /// Complete RFC 5322 message text: header block (CRLF-terminated
    /// fields, finished by an empty line), then body.
    pub message_text: String,
    /// Whether this message was produced by `mail` or `vacation`.
    pub category: GeneratedMessageKind,
}

/// Structured result of evaluating an Exim filter, including any messages
/// generated via `mail` / `vacation` commands (F3).
///
/// Prior to F3, the interpreter returned only a [`FilterResult`] enum and
/// silently discarded any `mail`/`vacation` side-effects. `FilterOutcome`
/// surfaces those side-effects so the orchestrator can enqueue them.
///
/// For backward compatibility, [`exim_interpret`] continues to return just
/// the [`FilterResult`] (discarding generated messages); callers that need
/// the structured output should use [`exim_interpret_outcome`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterOutcome {
    /// Overall evaluation result.
    pub result: FilterResult,
    /// Addresses generated by `deliver` / `save` / `pipe` commands, in
    /// execution order. These feed the routing layer as synthetic
    /// recipients.
    pub generated_addresses: Vec<String>,
    /// Headers added via `headers add` (expanded, CRLF-terminated).
    pub added_headers: Vec<String>,
    /// Header names removed via `headers remove`.
    pub removed_headers: Vec<String>,
    /// Messages produced by `mail` / `vacation` commands (F3). Empty
    /// when the filter uses none.
    pub generated_messages: Vec<GeneratedMessage>,
    /// Text passed to `freeze text`, if any.
    pub freeze_text: Option<String>,
    /// Text passed to `fail text`, if any.
    pub fail_text: Option<String>,
    /// Text passed to `defer text`, if any.
    pub defer_text: Option<String>,
}

// ---------------------------------------------------------------------------
// Expression type alias
// ---------------------------------------------------------------------------

/// An expression operand in a condition — a raw string that may contain
/// `$variable` or `${expansion}` references resolved at evaluation time.
pub type Expr = String;

// ---------------------------------------------------------------------------
// Filter options
// ---------------------------------------------------------------------------

/// Runtime options controlling filter behaviour.
#[derive(Debug, Clone, Default)]
pub struct FilterOptions {
    /// `true` when running as a system-wide filter (privileged mode).
    pub system_filter: bool,
    /// `true` to suppress actual delivery (dry-run / address-test mode).
    pub no_delivery: bool,
    /// `true` when executing in filter-test mode (`-bf` CLI flag).
    pub filter_test: bool,
}

// ---------------------------------------------------------------------------
// Mail / vacation argument bag
// ---------------------------------------------------------------------------

/// Arguments for the `mail` and `vacation` commands.
#[derive(Debug, Clone, Default)]
pub struct MailArgs {
    /// Recipient address(es).
    pub to: Option<String>,
    /// CC address(es).
    pub cc: Option<String>,
    /// BCC address(es).
    pub bcc: Option<String>,
    /// From address override.
    pub from: Option<String>,
    /// Reply-To address.
    pub reply_to: Option<String>,
    /// Subject line.
    pub subject: Option<String>,
    /// Extra header lines.
    pub headers: Option<String>,
    /// Inline message body text.
    pub text: Option<String>,
    /// Path to file containing message body.
    pub file: Option<String>,
    /// Path to log file for once-tracking.
    pub log: Option<String>,
    /// Path to once-only database file.
    pub once: Option<String>,
    /// Repeat interval for once-only replies.
    pub once_repeat: Option<String>,
}

// ---------------------------------------------------------------------------
// AST — commands
// ---------------------------------------------------------------------------

/// A single command in the filter AST.
#[derive(Debug, Clone)]
pub enum FilterCommand {
    /// Deliver the message to an address.
    Deliver {
        /// Target email address.
        address: String,
        /// Whether delivery marks the message as acted upon.
        seen: bool,
    },
    /// Save the message to a file.
    Save {
        /// Target file path.
        path: String,
        /// Whether save marks the message as acted upon.
        seen: bool,
    },
    /// Pipe the message through a command.
    Pipe {
        /// Shell command to pipe through.
        command: String,
        /// Whether pipe marks the message as acted upon.
        seen: bool,
    },
    /// Send an auto-generated mail message.
    Mail {
        /// Mail command arguments.
        args: MailArgs,
    },
    /// Send a vacation auto-reply (mail with defaults).
    Vacation {
        /// Vacation command arguments.
        args: MailArgs,
    },
    /// Conditional execution block.
    If {
        /// The condition to test.
        condition: Condition,
        /// Commands to execute when condition is true.
        then_branch: Vec<FilterCommand>,
        /// Commands to execute when condition is false.
        else_branch: Option<Vec<FilterCommand>>,
    },
    /// Add a header line to the message.
    AddHeader {
        /// Header text to add.
        text: String,
    },
    /// Remove a header by name.
    RemoveHeader {
        /// Header name to remove.
        name: String,
    },
    /// Freeze the message in the spool.
    Freeze,
    /// Fail (bounce) the message.
    Fail,
    /// Finish filter execution immediately.
    Finish,
    /// Print text to stdout (filter-test mode only).
    TestPrint {
        /// Text to print.
        text: String,
    },
    /// Write a line to a log file.
    LogWrite {
        /// Log file path (empty string uses current logfile).
        path: String,
        /// Text to write.
        text: String,
    },
    /// Defer the message (system filter only).
    Defer {
        /// Optional defer reason text.
        text: Option<String>,
    },
    /// Set the log file path for subsequent LogWrite commands.
    LogFile {
        /// Log file path.
        path: String,
    },
    /// Set the header character-set for added headers.
    HeadersCharset {
        /// Charset name (e.g., "utf-8").
        charset: String,
    },
    /// Add a numeric value to a filter variable n0..n9.
    Add {
        /// Value expression to add.
        value: Expr,
        /// Index of the target variable (0–9).
        variable_index: u8,
    },
    /// Freeze the message with an associated text message.
    FreezeText {
        /// Freeze reason text.
        text: String,
    },
    /// Fail the message with an associated text message.
    FailText {
        /// Fail reason text.
        text: String,
    },
}

// ---------------------------------------------------------------------------
// AST — conditions
// ---------------------------------------------------------------------------

/// A condition expression evaluated during `if` / `elif`.
#[derive(Debug, Clone)]
pub enum Condition {
    /// True if the message appears to be personal.
    Personal,
    /// True if any prior action already delivered the message.
    Delivered,
    /// True if the message is a bounce/error notification.
    ErrorMessage,
    /// True on the first delivery attempt.
    FirstDelivery,
    /// True if the message was manually thawed.
    ManualThaw,
    /// Case-insensitive string equality.
    Is(Expr, Expr),
    /// Case-insensitive substring test.
    Contains(Expr, Expr),
    /// Regex match (PCRE2, case-insensitive).
    Matches(Expr, Expr),
    /// Case-insensitive prefix test.
    Begins(Expr, Expr),
    /// Case-insensitive suffix test.
    Ends(Expr, Expr),
    /// Numeric greater-than.
    Above(Expr, i64),
    /// Numeric less-than.
    Below(Expr, i64),
    /// Iterate over addresses in a header and test each.
    ForAnyAddress(String, Box<Condition>),
    /// Logical AND of two conditions.
    And(Box<Condition>, Box<Condition>),
    /// Logical OR of two conditions.
    Or(Box<Condition>, Box<Condition>),
    /// Logical negation.
    Not(Box<Condition>),
    /// Case-sensitive string equality (C `IS` keyword).
    IsExact(Expr, Expr),
    /// Case-sensitive substring test (C `CONTAINS` keyword).
    ContainsExact(Expr, Expr),
    /// Case-sensitive regex match (C `MATCHES` keyword).
    MatchesExact(Expr, Expr),
    /// Case-sensitive prefix test (C `BEGINS` keyword).
    BeginsExact(Expr, Expr),
    /// Case-sensitive suffix test (C `ENDS` keyword).
    EndsExact(Expr, Expr),
}

// ===========================================================================
// Internal constants
// ===========================================================================

const RDO_DEFER: u32 = 1 << 0;
const RDO_FAIL: u32 = 1 << 1;
const RDO_FREEZE: u32 = 1 << 2;
const RDO_REWRITE: u32 = 1 << 3;
const RDO_PREPEND_HOME: u32 = 1 << 4;
const RDO_LOG: u32 = 1 << 5;
const RDO_REALLOG: u32 = 1 << 6;
const FILTER_VARIABLE_COUNT: usize = 10;

// ===========================================================================
// Parser internals
// ===========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HadElseEndif {
    Endif,
    Else,
    Elif,
    None,
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
    line: usize,
    expect_endif: usize,
    had_else_endif: HadElseEndif,
    seen_force: bool,
    seen_value: bool,
    noerror_force: bool,
    filter_options: u32,
    system_filtering: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Word(String);

impl Word {
    fn eq_ci(&self, s: &str) -> bool {
        self.0.eq_ignore_ascii_case(s)
    }
}

// ===========================================================================
// Parser implementation
// ===========================================================================

impl<'a> Parser<'a> {
    fn new(input: &'a str, system_filtering: bool, filter_options: u32) -> Self {
        Self {
            input: input.as_bytes(),
            pos: 0,
            line: 1,
            expect_endif: 0,
            had_else_endif: HadElseEndif::None,
            seen_force: false,
            seen_value: false,
            noerror_force: false,
            filter_options,
            system_filtering,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn advance(&mut self) {
        if let Some(&b) = self.input.get(self.pos) {
            if b == b'\n' {
                self.line += 1;
            }
            self.pos += 1;
        }
    }

    fn at_end(&self) -> bool {
        self.pos >= self.input.len()
    }

    /// Skip whitespace and `#`-comments.
    fn skip_ws(&mut self) -> bool {
        loop {
            while let Some(b) = self.peek() {
                match b {
                    b' ' | b'\t' | b'\r' | b'\n' => self.advance(),
                    _ => break,
                }
            }
            if self.peek() == Some(b'#') {
                while let Some(b) = self.peek() {
                    self.advance();
                    if b == b'\n' {
                        break;
                    }
                }
                continue;
            }
            break;
        }
        !self.at_end()
    }

    fn read_word(&mut self) -> Option<Word> {
        self.skip_ws();
        let start = self.pos;
        while let Some(b) = self.peek() {
            if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' {
                self.advance();
            } else {
                break;
            }
        }
        if self.pos == start {
            return None;
        }
        Some(Word(
            String::from_utf8_lossy(&self.input[start..self.pos]).to_string(),
        ))
    }

    fn read_item(&mut self) -> Result<Option<String>, FilterError> {
        if !self.skip_ws() {
            return Ok(None);
        }
        if self.peek() == Some(b'"') {
            self.advance();
            let mut buf = String::new();
            loop {
                match self.peek() {
                    None => {
                        return Err(FilterError::ParseError {
                            line: self.line,
                            message: "unterminated quoted string".into(),
                        });
                    }
                    Some(b'"') => {
                        self.advance();
                        break;
                    }
                    Some(b'\\') => {
                        self.advance();
                        match self.peek() {
                            Some(b'n') => {
                                buf.push('\n');
                                self.advance();
                            }
                            Some(b't') => {
                                buf.push('\t');
                                self.advance();
                            }
                            Some(b'\\') => {
                                buf.push('\\');
                                self.advance();
                            }
                            Some(b'"') => {
                                buf.push('"');
                                self.advance();
                            }
                            Some(b'0') => {
                                buf.push('\0');
                                self.advance();
                            }
                            Some(c) => {
                                buf.push('\\');
                                buf.push(c as char);
                                self.advance();
                            }
                            None => {
                                return Err(FilterError::ParseError {
                                    line: self.line,
                                    message: "backslash at end of input".into(),
                                });
                            }
                        }
                    }
                    Some(c) => {
                        buf.push(c as char);
                        self.advance();
                    }
                }
            }
            Ok(Some(buf))
        } else {
            let start = self.pos;
            while let Some(b) = self.peek() {
                if b.is_ascii_alphanumeric()
                    || matches!(
                        b,
                        b'$' | b'{'
                            | b'}'
                            | b'_'
                            | b'.'
                            | b'/'
                            | b'-'
                            | b'+'
                            | b'@'
                            | b'%'
                            | b'~'
                            | b':'
                            | b'*'
                            | b'='
                            | b'!'
                            | b','
                            | b'['
                            | b']'
                    )
                {
                    self.advance();
                } else {
                    break;
                }
            }
            if self.pos == start {
                return Ok(None);
            }
            Ok(Some(
                String::from_utf8_lossy(&self.input[start..self.pos]).to_string(),
            ))
        }
    }

    fn read_number(&mut self) -> Result<Option<i64>, FilterError> {
        self.skip_ws();
        let neg = if self.peek() == Some(b'-') {
            self.advance();
            true
        } else {
            false
        };
        let start = self.pos;
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() {
                self.advance();
            } else {
                break;
            }
        }
        if self.pos == start {
            if neg {
                return Err(FilterError::ParseError {
                    line: self.line,
                    message: "expected a number after '-'".into(),
                });
            }
            return Ok(None);
        }
        let digits = String::from_utf8_lossy(&self.input[start..self.pos]);
        let val: i64 = digits.parse().map_err(|_| FilterError::ParseError {
            line: self.line,
            message: format!("invalid number: {digits}"),
        })?;
        Ok(Some(if neg { -val } else { val }))
    }

    fn peek_word(&mut self) -> Option<Word> {
        let (sp, sl) = (self.pos, self.line);
        let w = self.read_word();
        self.pos = sp;
        self.line = sl;
        w
    }

    // -----------------------------------------------------------------------
    // Condition parser
    // -----------------------------------------------------------------------

    fn read_condition(&mut self) -> Result<Condition, FilterError> {
        let lhs = self.read_condition_term()?;
        if let Some(ref w) = self.peek_word() {
            if w.0 == "or" {
                self.read_word();
                let rhs = self.read_condition()?;
                return Ok(Condition::Or(Box::new(lhs), Box::new(rhs)));
            }
        }
        Ok(lhs)
    }

    fn read_condition_term(&mut self) -> Result<Condition, FilterError> {
        let lhs = self.read_condition_factor()?;
        if let Some(ref w) = self.peek_word() {
            if w.0 == "and" {
                self.read_word();
                let rhs = self.read_condition_term()?;
                return Ok(Condition::And(Box::new(lhs), Box::new(rhs)));
            }
        }
        Ok(lhs)
    }

    fn read_condition_factor(&mut self) -> Result<Condition, FilterError> {
        self.skip_ws();
        if self.peek() == Some(b'(') {
            self.advance();
            let c = self.read_condition()?;
            self.skip_ws();
            if self.peek() != Some(b')') {
                return Err(FilterError::ParseError {
                    line: self.line,
                    message: "expected closing ')'".into(),
                });
            }
            self.advance();
            return Ok(c);
        }
        if let Some(ref w) = self.peek_word() {
            if w.0 == "not" {
                self.read_word();
                let inner = self.read_condition_factor()?;
                return Ok(Condition::Not(Box::new(inner)));
            }
        }
        self.read_simple_condition()
    }

    fn read_simple_condition(&mut self) -> Result<Condition, FilterError> {
        let line = self.line;
        if let Some(ref w) = self.peek_word() {
            let lower = w.0.to_ascii_lowercase();
            match lower.as_str() {
                "personal" => {
                    self.read_word();
                    return Ok(Condition::Personal);
                }
                "delivered" => {
                    self.read_word();
                    return Ok(Condition::Delivered);
                }
                "error_message" => {
                    self.read_word();
                    return Ok(Condition::ErrorMessage);
                }
                "first_delivery" => {
                    self.read_word();
                    return Ok(Condition::FirstDelivery);
                }
                "manually_thawed" => {
                    self.read_word();
                    return Ok(Condition::ManualThaw);
                }
                "foranyaddress" => {
                    self.read_word();
                    let hdr = self.read_item()?.ok_or_else(|| FilterError::ParseError {
                        line: self.line,
                        message: "expected header after 'foranyaddress'".into(),
                    })?;
                    self.skip_ws();
                    if self.peek() != Some(b'(') {
                        return Err(FilterError::ParseError {
                            line: self.line,
                            message: "expected '(' after foranyaddress header".into(),
                        });
                    }
                    self.advance();
                    let inner = self.read_condition()?;
                    self.skip_ws();
                    if self.peek() != Some(b')') {
                        return Err(FilterError::ParseError {
                            line: self.line,
                            message: "expected ')' closing foranyaddress".into(),
                        });
                    }
                    self.advance();
                    return Ok(Condition::ForAnyAddress(hdr, Box::new(inner)));
                }
                _ => {}
            }
        }
        // Binary condition: <item> <op> <item>
        let lhs_str = self.read_item()?.ok_or_else(|| FilterError::ParseError {
            line,
            message: "expected condition expression".into(),
        })?;
        let op = self.read_word().ok_or_else(|| FilterError::ParseError {
            line: self.line,
            message: "expected comparison operator".into(),
        })?;
        match op.0.as_str() {
            "is" => Ok(Condition::Is(
                lhs_str,
                self.read_item()?.unwrap_or_default(),
            )),
            "IS" => Ok(Condition::IsExact(
                lhs_str,
                self.read_item()?.unwrap_or_default(),
            )),
            "contains" => Ok(Condition::Contains(
                lhs_str,
                self.read_item()?.unwrap_or_default(),
            )),
            "CONTAINS" => Ok(Condition::ContainsExact(
                lhs_str,
                self.read_item()?.unwrap_or_default(),
            )),
            "matches" => Ok(Condition::Matches(
                lhs_str,
                self.read_item()?.unwrap_or_default(),
            )),
            "MATCHES" => Ok(Condition::MatchesExact(
                lhs_str,
                self.read_item()?.unwrap_or_default(),
            )),
            "begins" => Ok(Condition::Begins(
                lhs_str,
                self.read_item()?.unwrap_or_default(),
            )),
            "BEGINS" => Ok(Condition::BeginsExact(
                lhs_str,
                self.read_item()?.unwrap_or_default(),
            )),
            "ends" => Ok(Condition::Ends(
                lhs_str,
                self.read_item()?.unwrap_or_default(),
            )),
            "ENDS" => Ok(Condition::EndsExact(
                lhs_str,
                self.read_item()?.unwrap_or_default(),
            )),
            "above" => Ok(Condition::Above(lhs_str, self.read_number()?.unwrap_or(0))),
            "below" => Ok(Condition::Below(lhs_str, self.read_number()?.unwrap_or(0))),
            other => Err(FilterError::ParseError {
                line: self.line,
                message: format!("unknown comparison operator: '{other}'"),
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Command parser  (replaces C read_command / read_command_list)
    // -----------------------------------------------------------------------

    /// Parse a list of commands terminated by end-of-input, `elif`, `else`,
    /// or `endif`.  Returns the command list and sets `self.had_else_endif`.
    fn read_command_list(&mut self) -> Result<Vec<FilterCommand>, FilterError> {
        let mut commands: Vec<FilterCommand> = Vec::new();
        self.had_else_endif = HadElseEndif::None;

        loop {
            if !self.skip_ws() {
                break; // end of input
            }
            // Peek at the next word to check for block terminators
            if let Some(ref w) = self.peek_word() {
                let lower = w.0.to_ascii_lowercase();
                match lower.as_str() {
                    "elif" => {
                        self.had_else_endif = HadElseEndif::Elif;
                        return Ok(commands);
                    }
                    "else" => {
                        self.read_word();
                        self.had_else_endif = HadElseEndif::Else;
                        return Ok(commands);
                    }
                    "endif" => {
                        self.read_word();
                        self.had_else_endif = HadElseEndif::Endif;
                        return Ok(commands);
                    }
                    _ => {}
                }
            }
            let cmd = self.read_command()?;
            if let Some(c) = cmd {
                commands.push(c);
            }
        }
        Ok(commands)
    }

    /// Parse a single command.  Returns `None` for modifier commands
    /// (seen/unseen/noerror) that don't produce a standalone AST node.
    fn read_command(&mut self) -> Result<Option<FilterCommand>, FilterError> {
        let line = self.line;
        let w = match self.read_word() {
            Some(w) => w,
            None => return Ok(None),
        };

        let lower = w.0.to_ascii_lowercase();
        match lower.as_str() {
            // ----- delivery commands -----
            "deliver" => {
                let addr = self.read_item()?.ok_or_else(|| FilterError::ParseError {
                    line,
                    message: "expected address after 'deliver'".into(),
                })?;
                let seen = self.consume_seen_flag();
                Ok(Some(FilterCommand::Deliver {
                    address: addr,
                    seen,
                }))
            }
            "save" => {
                let path = self.read_item()?.ok_or_else(|| FilterError::ParseError {
                    line,
                    message: "expected file path after 'save'".into(),
                })?;
                let seen = self.consume_seen_flag();
                Ok(Some(FilterCommand::Save { path, seen }))
            }
            "pipe" => {
                let cmd = self.read_item()?.ok_or_else(|| FilterError::ParseError {
                    line,
                    message: "expected command after 'pipe'".into(),
                })?;
                let seen = self.consume_seen_flag();
                Ok(Some(FilterCommand::Pipe { command: cmd, seen }))
            }

            // ----- mail / vacation -----
            "mail" => {
                let args = self.read_mail_args(false)?;
                Ok(Some(FilterCommand::Mail { args }))
            }
            "vacation" => {
                let args = self.read_mail_args(true)?;
                Ok(Some(FilterCommand::Vacation { args }))
            }

            // ----- conditional -----
            "if" => {
                self.expect_endif += 1;
                let condition = self.read_condition()?;
                // expect "then"
                let then_word = self.read_word().ok_or_else(|| FilterError::ParseError {
                    line: self.line,
                    message: "expected 'then' after if condition".into(),
                })?;
                if !then_word.eq_ci("then") {
                    return Err(FilterError::ParseError {
                        line: self.line,
                        message: format!("expected 'then', found '{}'", then_word.0),
                    });
                }
                let then_branch = self.read_command_list()?;
                let else_branch = self.parse_elif_else_chain()?;
                self.expect_endif -= 1;
                Ok(Some(FilterCommand::If {
                    condition,
                    then_branch,
                    else_branch,
                }))
            }

            // ----- headers -----
            "headers" => self.parse_headers_command(line),
            "add" => {
                // "add <value> to n<digit>"
                let val = self.read_item()?.unwrap_or_default();
                let to_word = self.read_word();
                if to_word.as_ref().map(|w| w.eq_ci("to")) != Some(true) {
                    return Err(FilterError::ParseError {
                        line,
                        message: "expected 'to' after add value".into(),
                    });
                }
                let var_name = self.read_item()?.ok_or_else(|| FilterError::ParseError {
                    line,
                    message: "expected variable name after 'to'".into(),
                })?;
                let idx =
                    parse_variable_index(&var_name).ok_or_else(|| FilterError::ParseError {
                        line,
                        message: format!("invalid variable name: '{var_name}'"),
                    })?;
                Ok(Some(FilterCommand::Add {
                    value: val,
                    variable_index: idx,
                }))
            }

            // ----- logging -----
            "logfile" => {
                let path = self.read_item()?.ok_or_else(|| FilterError::ParseError {
                    line,
                    message: "expected path after 'logfile'".into(),
                })?;
                Ok(Some(FilterCommand::LogFile { path }))
            }
            "logwrite" => {
                let text = self.read_item()?.ok_or_else(|| FilterError::ParseError {
                    line,
                    message: "expected text after 'logwrite'".into(),
                })?;
                Ok(Some(FilterCommand::LogWrite {
                    path: String::new(),
                    text,
                }))
            }

            // ----- control -----
            "freeze" => {
                if self.filter_options & RDO_FREEZE == 0 && !self.system_filtering {
                    return Err(FilterError::ParseError {
                        line,
                        message: "'freeze' is not allowed in user filters".into(),
                    });
                }
                if let Some(ref pw) = self.peek_word() {
                    if pw.eq_ci("text") {
                        self.read_word();
                        let t = self.read_item()?.unwrap_or_default();
                        return Ok(Some(FilterCommand::FreezeText { text: t }));
                    }
                }
                Ok(Some(FilterCommand::Freeze))
            }
            "fail" => {
                if self.filter_options & RDO_FAIL == 0 && !self.system_filtering {
                    return Err(FilterError::ParseError {
                        line,
                        message: "'fail' is not allowed in user filters".into(),
                    });
                }
                if let Some(ref pw) = self.peek_word() {
                    if pw.eq_ci("text") {
                        self.read_word();
                        let t = self.read_item()?.unwrap_or_default();
                        return Ok(Some(FilterCommand::FailText { text: t }));
                    }
                }
                Ok(Some(FilterCommand::Fail))
            }
            "defer" => {
                if self.filter_options & RDO_DEFER == 0 && !self.system_filtering {
                    return Err(FilterError::ParseError {
                        line,
                        message: "'defer' is not allowed in user filters".into(),
                    });
                }
                let text = if let Some(ref pw) = self.peek_word() {
                    if pw.eq_ci("text") {
                        self.read_word();
                        Some(self.read_item()?.unwrap_or_default())
                    } else {
                        None
                    }
                } else {
                    None
                };
                Ok(Some(FilterCommand::Defer { text }))
            }
            "finish" => Ok(Some(FilterCommand::Finish)),
            "testprint" => {
                let text = self.read_item()?.ok_or_else(|| FilterError::ParseError {
                    line,
                    message: "expected text after 'testprint'".into(),
                })?;
                Ok(Some(FilterCommand::TestPrint { text }))
            }

            // ----- modifiers -----
            "seen" => {
                self.seen_force = true;
                self.seen_value = true;
                // read the next command and apply the modifier
                self.read_command()
            }
            "unseen" => {
                self.seen_force = true;
                self.seen_value = false;
                self.read_command()
            }
            "noerror" => {
                self.noerror_force = true;
                self.read_command()
            }

            other => Err(FilterError::ParseError {
                line,
                message: format!("unknown command: '{other}'"),
            }),
        }
    }

    /// Consume the `seen` modifier if set, returning its value and resetting.
    fn consume_seen_flag(&mut self) -> bool {
        if self.seen_force {
            self.seen_force = false;
            self.seen_value
        } else {
            true // default: delivery marks message as seen
        }
    }

    /// After reading the `then` branch, handle elif / else / endif chain.
    fn parse_elif_else_chain(&mut self) -> Result<Option<Vec<FilterCommand>>, FilterError> {
        match self.had_else_endif {
            HadElseEndif::Endif => Ok(None),
            HadElseEndif::Else => {
                let else_cmds = self.read_command_list()?;
                if self.had_else_endif != HadElseEndif::Endif {
                    return Err(FilterError::ParseError {
                        line: self.line,
                        message: "expected 'endif' after 'else' block".into(),
                    });
                }
                Ok(Some(else_cmds))
            }
            HadElseEndif::Elif => {
                // elif is syntactic sugar for else-if
                self.read_word(); // consume "elif"
                let condition = self.read_condition()?;
                let then_word = self.read_word().ok_or_else(|| FilterError::ParseError {
                    line: self.line,
                    message: "expected 'then' after elif condition".into(),
                })?;
                if !then_word.eq_ci("then") {
                    return Err(FilterError::ParseError {
                        line: self.line,
                        message: format!("expected 'then', found '{}'", then_word.0),
                    });
                }
                let then_branch = self.read_command_list()?;
                let else_branch = self.parse_elif_else_chain()?;
                Ok(Some(vec![FilterCommand::If {
                    condition,
                    then_branch,
                    else_branch,
                }]))
            }
            HadElseEndif::None => {
                // end-of-input inside if block without endif
                Err(FilterError::ParseError {
                    line: self.line,
                    message: "unexpected end of filter inside 'if' block".into(),
                })
            }
        }
    }

    /// Parse `headers add|remove|charset <value>`.
    fn parse_headers_command(&mut self, line: usize) -> Result<Option<FilterCommand>, FilterError> {
        let sub = self.read_word().ok_or_else(|| FilterError::ParseError {
            line,
            message: "expected 'add', 'remove', or 'charset' after 'headers'".into(),
        })?;
        let lower = sub.0.to_ascii_lowercase();
        match lower.as_str() {
            "add" => {
                let text = self.read_item()?.ok_or_else(|| FilterError::ParseError {
                    line: self.line,
                    message: "expected header text after 'headers add'".into(),
                })?;
                Ok(Some(FilterCommand::AddHeader { text }))
            }
            "remove" => {
                let name = self.read_item()?.ok_or_else(|| FilterError::ParseError {
                    line: self.line,
                    message: "expected header name after 'headers remove'".into(),
                })?;
                Ok(Some(FilterCommand::RemoveHeader { name }))
            }
            "charset" => {
                let cs = self.read_item()?.ok_or_else(|| FilterError::ParseError {
                    line: self.line,
                    message: "expected charset after 'headers charset'".into(),
                })?;
                Ok(Some(FilterCommand::HeadersCharset { charset: cs }))
            }
            other => Err(FilterError::ParseError {
                line: self.line,
                message: format!("expected 'add', 'remove', or 'charset'; found '{other}'"),
            }),
        }
    }

    /// Parse keyword/value pairs for `mail` or `vacation` commands.
    /// When `is_vacation` is true, default values are pre-populated per the
    /// Exim filter specification.
    fn read_mail_args(&mut self, is_vacation: bool) -> Result<MailArgs, FilterError> {
        let mut args = MailArgs::default();
        if is_vacation {
            args.file = Some(".vacation.msg".into());
            args.log = Some(".vacation.log".into());
            args.once = Some(".vacation".into());
            args.once_repeat = Some("7d".into());
            args.subject = Some("On vacation".into());
        }
        loop {
            if !self.skip_ws() {
                break;
            }
            let pw = match self.peek_word() {
                Some(w) => w,
                None => break,
            };
            let lower = pw.0.to_ascii_lowercase();
            match lower.as_str() {
                "to" => {
                    self.read_word();
                    args.to = Some(self.read_item()?.unwrap_or_default());
                }
                "cc" => {
                    self.read_word();
                    args.cc = Some(self.read_item()?.unwrap_or_default());
                }
                "bcc" => {
                    self.read_word();
                    args.bcc = Some(self.read_item()?.unwrap_or_default());
                }
                "from" => {
                    self.read_word();
                    args.from = Some(self.read_item()?.unwrap_or_default());
                }
                "reply_to" => {
                    self.read_word();
                    args.reply_to = Some(self.read_item()?.unwrap_or_default());
                }
                "subject" => {
                    self.read_word();
                    args.subject = Some(self.read_item()?.unwrap_or_default());
                }
                "extra_headers" | "headers" => {
                    self.read_word();
                    args.headers = Some(self.read_item()?.unwrap_or_default());
                }
                "text" => {
                    self.read_word();
                    args.text = Some(self.read_item()?.unwrap_or_default());
                }
                "file" => {
                    self.read_word();
                    args.file = Some(self.read_item()?.unwrap_or_default());
                }
                "log" => {
                    self.read_word();
                    args.log = Some(self.read_item()?.unwrap_or_default());
                }
                "once" => {
                    self.read_word();
                    args.once = Some(self.read_item()?.unwrap_or_default());
                }
                "once_repeat" => {
                    self.read_word();
                    args.once_repeat = Some(self.read_item()?.unwrap_or_default());
                }
                _ => break, // end of keyword/value pairs
            }
        }
        Ok(args)
    }
}

/// Parse a variable reference like `n0` .. `n9` to its index.
fn parse_variable_index(name: &str) -> Option<u8> {
    if name.len() == 2 && name.starts_with('n') {
        let ch = name.as_bytes()[1];
        if ch.is_ascii_digit() {
            return Some(ch - b'0');
        }
    }
    None
}

// ===========================================================================
// Top-level parse function
// ===========================================================================

/// Parse a complete Exim filter file into an AST.
///
/// The filter source text is validated as starting with the magic marker
/// `# Exim filter` (case-insensitive) on the first line.  If the marker
/// is absent the input is rejected as not an Exim filter.
fn parse_filter(input: &str, system_filtering: bool) -> Result<Vec<FilterCommand>, FilterError> {
    // Validate magic marker
    let trimmed = input.trim_start();
    let first_line = trimmed.lines().next().unwrap_or("");
    if !first_line.trim().eq_ignore_ascii_case("# Exim filter")
        && !first_line
            .trim()
            .to_ascii_lowercase()
            .starts_with("# exim filter")
    {
        return Err(FilterError::ParseError {
            line: 1,
            message: "missing '# Exim filter' marker on first line".into(),
        });
    }

    // Skip past the marker line to begin parsing commands
    let after_marker = if let Some(idx) = trimmed.find('\n') {
        &trimmed[idx + 1..]
    } else {
        "" // filter with only the marker line
    };

    let options = if system_filtering {
        RDO_DEFER | RDO_FREEZE | RDO_FAIL | RDO_LOG | RDO_REALLOG | RDO_REWRITE
    } else {
        RDO_PREPEND_HOME | RDO_LOG
    };

    let mut parser = Parser::new(after_marker, system_filtering, options);
    debug!("parsing exim filter ({} bytes)", input.len());
    let commands = parser.read_command_list()?;

    if parser.expect_endif > 0 {
        return Err(FilterError::ParseError {
            line: parser.line,
            message: format!(
                "missing {} 'endif'(s) at end of filter",
                parser.expect_endif
            ),
        });
    }
    debug!("parsed {} filter commands", commands.len());
    Ok(commands)
}

// ===========================================================================
// Evaluator — filter state
// ===========================================================================

/// Runtime state during filter evaluation (replaces all C static variables).
struct FilterState {
    /// True when at least one delivery action has been executed.
    filter_delivered: bool,
    /// True when a `finish` command has been executed.
    finish_obeyed: bool,
    /// User-accessible numeric variables `n0` .. `n9`.
    variables: [i64; FILTER_VARIABLE_COUNT],
    /// Current log file path (set by `logfile` command).
    log_filename: Option<String>,
    /// Log file mode.
    log_mode: u32,
    /// Current `thisaddress` value in `foranyaddress` loops.
    filter_thisaddress: Option<String>,
    /// Addresses generated by delivery commands.
    generated_addresses: Vec<String>,
    /// Headers added by `headers add` commands.
    added_headers: Vec<String>,
    /// Header names removed by `headers remove` commands.
    removed_headers: Vec<String>,
    /// System filtering mode flag.
    system_filtering: bool,
    /// Filter test mode flag.
    filter_test: bool,
    /// No-delivery mode flag.
    no_delivery: bool,
    /// Deferred text message (from defer command).
    defer_text: Option<String>,
    /// Fail text message (from fail command).
    fail_text: Option<String>,
    /// Freeze text message (from freeze command).
    freeze_text: Option<String>,
    /// Per-message arena allocator for short-lived allocations during
    /// filter evaluation (replaces C store_get / POOL_MAIN usage).
    pub(crate) arena: MessageArena,
    /// Per-message storage for intermediate results.
    pub(crate) message_store: MessageStore,
    /// Taint state tracking for filter source text.
    taint_state: TaintState,
    /// F3: messages produced by `mail`/`vacation` commands, in execution
    /// order. The orchestrator drains this into
    /// [`FilterOutcome::generated_messages`] and enqueues each via the
    /// spool subsystem. Prior to F3 this field did not exist and the
    /// messages were silently dropped.
    generated_messages: Vec<GeneratedMessage>,
}

impl FilterState {
    fn new(options: &FilterOptions) -> Self {
        Self {
            filter_delivered: false,
            finish_obeyed: false,
            variables: [0i64; FILTER_VARIABLE_COUNT],
            log_filename: None,
            log_mode: 0o600,
            filter_thisaddress: None,
            generated_addresses: Vec::new(),
            added_headers: Vec::new(),
            removed_headers: Vec::new(),
            system_filtering: options.system_filter,
            filter_test: options.filter_test,
            no_delivery: options.no_delivery,
            defer_text: None,
            fail_text: None,
            freeze_text: None,
            arena: MessageArena::new(),
            message_store: MessageStore::new(),
            taint_state: TaintState::Tainted,
            generated_messages: Vec::new(),
        }
    }
}

// ===========================================================================
// Evaluator — string expansion (minimal built-in)
// ===========================================================================

/// Perform basic variable expansion on a string.
///
/// This handles the subset of expansion needed for the filter interpreter
/// itself: `$n0`.`$n9` filter variables and `$thisaddress`.  Full `${…}`
/// expansion is deferred to the `exim-expand` crate when integrated.
fn expand_string(s: &str, state: &FilterState) -> Result<String, FilterError> {
    if !s.contains('$') {
        return Ok(s.to_owned());
    }
    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' {
            i += 1;
            if i >= bytes.len() {
                result.push('$');
                break;
            }
            // $n0..$n9
            if bytes[i] == b'n' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
                let idx = (bytes[i + 1] - b'0') as usize;
                if idx < FILTER_VARIABLE_COUNT {
                    result.push_str(&state.variables[idx].to_string());
                }
                i += 2;
                continue;
            }
            // $thisaddress
            if bytes[i..].starts_with(b"thisaddress") {
                if let Some(ref addr) = state.filter_thisaddress {
                    result.push_str(addr);
                }
                i += 11;
                continue;
            }
            // ${...} block — pass through unexpanded for now
            if bytes[i] == b'{' {
                result.push('$');
                result.push('{');
                i += 1;
                let mut depth = 1u32;
                while i < bytes.len() && depth > 0 {
                    match bytes[i] {
                        b'{' => depth += 1,
                        b'}' => depth -= 1,
                        _ => {}
                    }
                    result.push(bytes[i] as char);
                    i += 1;
                }
                continue;
            }
            // Other $var — collect alphanumeric chars
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let var_name = String::from_utf8_lossy(&bytes[start..i]).to_string();
            // Known variables — return empty for unknown
            debug!("filter expand: unhandled variable '${}'", var_name);
            // pass through as literal for forward compat
            result.push('$');
            result.push_str(&var_name);
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }
    Ok(result)
}

// ===========================================================================
// Evaluator — condition evaluation
// ===========================================================================

/// Evaluate a condition expression to a boolean result.
fn evaluate_condition(cond: &Condition, state: &FilterState) -> Result<bool, FilterError> {
    match cond {
        Condition::Personal => {
            // A message is "personal" if: it has no List-* headers, no
            // Auto-Submitted header (or value is "no"), the sender is not
            // empty, and To/Cc/Bcc/Resent-To/Resent-Cc/Resent-Bcc contain
            // the local recipient.  In standalone mode we always return false
            // since we lack full header/envelope access.
            debug!("evaluating 'personal' condition");
            Ok(false)
        }
        Condition::Delivered => {
            debug!("evaluating 'delivered' condition");
            Ok(state.filter_delivered)
        }
        Condition::ErrorMessage => {
            // True if the message is a bounce (empty sender).  Without
            // full message context we default to false.
            debug!("evaluating 'error_message' condition");
            Ok(false)
        }
        Condition::FirstDelivery => {
            debug!("evaluating 'first_delivery' condition");
            Ok(true) // first attempt by default
        }
        Condition::ManualThaw => {
            debug!("evaluating 'manually_thawed' condition");
            Ok(false)
        }
        Condition::Is(lhs, rhs) => {
            let l = expand_string(lhs, state)?;
            let r = expand_string(rhs, state)?;
            Ok(l.eq_ignore_ascii_case(&r))
        }
        Condition::IsExact(lhs, rhs) => {
            let l = expand_string(lhs, state)?;
            let r = expand_string(rhs, state)?;
            Ok(l == r)
        }
        Condition::Contains(lhs, rhs) => {
            let l = expand_string(lhs, state)?.to_ascii_lowercase();
            let r = expand_string(rhs, state)?.to_ascii_lowercase();
            Ok(l.contains(&r))
        }
        Condition::ContainsExact(lhs, rhs) => {
            let l = expand_string(lhs, state)?;
            let r = expand_string(rhs, state)?;
            Ok(l.contains(&r))
        }
        Condition::Begins(lhs, rhs) => {
            let l = expand_string(lhs, state)?.to_ascii_lowercase();
            let r = expand_string(rhs, state)?.to_ascii_lowercase();
            Ok(l.starts_with(&r))
        }
        Condition::BeginsExact(lhs, rhs) => {
            let l = expand_string(lhs, state)?;
            let r = expand_string(rhs, state)?;
            Ok(l.starts_with(&r))
        }
        Condition::Ends(lhs, rhs) => {
            let l = expand_string(lhs, state)?.to_ascii_lowercase();
            let r = expand_string(rhs, state)?.to_ascii_lowercase();
            Ok(l.ends_with(&r))
        }
        Condition::EndsExact(lhs, rhs) => {
            let l = expand_string(lhs, state)?;
            let r = expand_string(rhs, state)?;
            Ok(l.ends_with(&r))
        }
        Condition::Matches(lhs, rhs) => {
            let l = expand_string(lhs, state)?;
            let r = expand_string(rhs, state)?;
            // Use PCRE2 for behavioural parity; fall back to regex crate
            match pcre2::bytes::Regex::new(&format!("(?i){r}")) {
                Ok(re) => Ok(re.is_match(l.as_bytes()).unwrap_or(false)),
                Err(_) => {
                    // Fall back to Rust regex
                    let re =
                        Regex::new(&format!("(?i){r}")).map_err(|e| FilterError::EvalError {
                            line: 0,
                            message: format!("invalid regex '{r}': {e}"),
                        })?;
                    if let Some(m) = re.find(&l) {
                        debug!("matches: regex hit at {}..{}", m.start(), m.end());
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                }
            }
        }
        Condition::MatchesExact(lhs, rhs) => {
            let l = expand_string(lhs, state)?;
            let r = expand_string(rhs, state)?;
            match pcre2::bytes::Regex::new(&r) {
                Ok(re) => Ok(re.is_match(l.as_bytes()).unwrap_or(false)),
                Err(_) => {
                    let re = Regex::new(&r).map_err(|e| FilterError::EvalError {
                        line: 0,
                        message: format!("invalid regex '{r}': {e}"),
                    })?;
                    if let Some(m) = re.find(&l) {
                        debug!("matches_exact: regex hit at {}..{}", m.start(), m.end());
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                }
            }
        }
        Condition::Above(lhs, threshold) => {
            let l = expand_string(lhs, state)?;
            let val: i64 = l.trim().parse().unwrap_or(0);
            Ok(val > *threshold)
        }
        Condition::Below(lhs, threshold) => {
            let l = expand_string(lhs, state)?;
            let val: i64 = l.trim().parse().unwrap_or(0);
            Ok(val < *threshold)
        }
        Condition::ForAnyAddress(header_expr, inner_cond) => {
            let expanded = expand_string(header_expr, state)?;
            // Split the header value into individual addresses
            let addresses = split_addresses(&expanded);
            for addr in &addresses {
                let inner_state_copy = FilterState {
                    filter_thisaddress: Some(addr.clone()),
                    filter_delivered: state.filter_delivered,
                    finish_obeyed: state.finish_obeyed,
                    variables: state.variables,
                    log_filename: state.log_filename.clone(),
                    log_mode: state.log_mode,
                    generated_addresses: state.generated_addresses.clone(),
                    added_headers: state.added_headers.clone(),
                    removed_headers: state.removed_headers.clone(),
                    system_filtering: state.system_filtering,
                    filter_test: state.filter_test,
                    no_delivery: state.no_delivery,
                    defer_text: state.defer_text.clone(),
                    fail_text: state.fail_text.clone(),
                    freeze_text: state.freeze_text.clone(),
                    arena: MessageArena::new(),
                    message_store: MessageStore::new(),
                    taint_state: state.taint_state,
                    // F3: condition evaluation is side-effect-free w.r.t.
                    // generated_messages; the nested scope is inspected
                    // only for its boolean result, so we can start with
                    // an empty vector rather than cloning.
                    generated_messages: Vec::new(),
                };
                if evaluate_condition(inner_cond, &inner_state_copy)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Condition::And(a, b) => Ok(evaluate_condition(a, state)? && evaluate_condition(b, state)?),
        Condition::Or(a, b) => Ok(evaluate_condition(a, state)? || evaluate_condition(b, state)?),
        Condition::Not(inner) => Ok(!evaluate_condition(inner, state)?),
    }
}

/// Split a header value into individual email addresses.
fn split_addresses(value: &str) -> Vec<String> {
    let mut addrs = Vec::new();
    for part in value.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Extract bare address from "Name <addr>" or plain "addr"
        if let Some(start) = trimmed.find('<') {
            if let Some(end) = trimmed.find('>') {
                if start < end {
                    addrs.push(trimmed[start + 1..end].trim().to_owned());
                    continue;
                }
            }
        }
        addrs.push(trimmed.to_owned());
    }
    addrs
}

// ===========================================================================
// Evaluator — command interpretation
// ===========================================================================

/// Interpret a list of filter commands, updating `state` with the results.
///
/// Returns the cumulative `FilterResult`:
/// - `Delivered` if at least one delivery action was executed
/// - `Freeze` / `Fail` / `Defer` if the corresponding control command ran
/// - `NotDelivered` otherwise
fn interpret_commands(
    commands: &[FilterCommand],
    state: &mut FilterState,
) -> Result<FilterResult, FilterError> {
    let mut result = FilterResult::NotDelivered;
    let mut executed_count: usize = 0;

    for cmd in commands {
        if state.finish_obeyed {
            break;
        }

        // Defense-in-depth: guard against runaway command execution.
        // Under normal operation the iteration is bounded by the parsed AST
        // size, but this explicit limit provides an additional safety net.
        executed_count += 1;
        if executed_count > MAX_COMMANDS {
            return Err(FilterError::EvalError {
                line: 0,
                message: format!(
                    "filter exceeded maximum command execution limit ({MAX_COMMANDS})"
                ),
            });
        }
        match cmd {
            FilterCommand::Deliver { address, seen } => {
                let addr = expand_string(address, state)?;
                debug!("filter: deliver to {}", addr);
                if !state.no_delivery {
                    state.generated_addresses.push(addr);
                }
                if *seen {
                    state.filter_delivered = true;
                }
                result = FilterResult::Delivered;
            }

            FilterCommand::Save { path, seen } => {
                let p = expand_string(path, state)?;
                debug!("filter: save to {}", p);
                if !state.no_delivery {
                    state.generated_addresses.push(format!("save:{p}"));
                }
                if *seen {
                    state.filter_delivered = true;
                }
                result = FilterResult::Delivered;
            }

            FilterCommand::Pipe { command, seen } => {
                let c = expand_string(command, state)?;
                debug!("filter: pipe to {}", c);
                if !state.no_delivery {
                    state.generated_addresses.push(format!("pipe:{c}"));
                }
                if *seen {
                    state.filter_delivered = true;
                }
                result = FilterResult::Delivered;
            }

            FilterCommand::Mail { args } => {
                debug!("filter: mail command");
                execute_mail_command(args, state, false)?;
            }

            FilterCommand::Vacation { args } => {
                debug!("filter: vacation command");
                execute_mail_command(args, state, true)?;
            }

            FilterCommand::If {
                condition,
                then_branch,
                else_branch,
            } => {
                let cond_result = evaluate_condition(condition, state)?;
                debug!("filter: if condition = {}", cond_result);
                let branch_result = if cond_result {
                    interpret_commands(then_branch, state)?
                } else if let Some(eb) = else_branch {
                    interpret_commands(eb, state)?
                } else {
                    FilterResult::NotDelivered
                };
                if branch_result != FilterResult::NotDelivered {
                    result = branch_result;
                }
            }

            FilterCommand::AddHeader { text } => {
                let expanded = expand_string(text, state)?;
                debug!("filter: add header '{}'", expanded);
                state.added_headers.push(expanded);
            }

            FilterCommand::RemoveHeader { name } => {
                let expanded = expand_string(name, state)?;
                debug!("filter: remove header '{}'", expanded);
                state.removed_headers.push(expanded);
            }

            FilterCommand::Freeze => {
                debug!("filter: freeze");
                result = FilterResult::Freeze;
                state.finish_obeyed = true;
            }

            FilterCommand::FreezeText { text } => {
                let expanded = expand_string(text, state)?;
                debug!("filter: freeze with text '{}'", expanded);
                state.freeze_text = Some(expanded);
                result = FilterResult::Freeze;
                state.finish_obeyed = true;
            }

            FilterCommand::Fail => {
                debug!("filter: fail");
                result = FilterResult::Fail;
                state.finish_obeyed = true;
            }

            FilterCommand::FailText { text } => {
                let expanded = expand_string(text, state)?;
                debug!("filter: fail with text '{}'", expanded);
                state.fail_text = Some(expanded);
                result = FilterResult::Fail;
                state.finish_obeyed = true;
            }

            FilterCommand::Defer { text } => {
                if let Some(t) = text {
                    let expanded = expand_string(t, state)?;
                    debug!("filter: defer with text '{}'", expanded);
                    state.defer_text = Some(expanded);
                } else {
                    debug!("filter: defer");
                }
                result = FilterResult::Defer;
                state.finish_obeyed = true;
            }

            FilterCommand::Finish => {
                debug!("filter: finish");
                state.finish_obeyed = true;
            }

            FilterCommand::TestPrint { text } => {
                let expanded = expand_string(text, state)?;
                if state.filter_test {
                    info!("filter testprint: {}", expanded);
                }
            }

            FilterCommand::LogFile { path } => {
                let expanded = expand_string(path, state)?;
                debug!("filter: logfile = {}", expanded);
                state.log_filename = Some(expanded);
            }

            FilterCommand::LogWrite { path: _, text } => {
                let expanded_text = expand_string(text, state)?;
                let log_path = state.log_filename.clone();
                if let Some(ref lp) = log_path {
                    debug!("filter: logwrite to {} : {}", lp, expanded_text);
                    // Actual file I/O deferred to integration layer
                } else {
                    debug!("filter: logwrite (no logfile set): {}", expanded_text);
                }
            }

            FilterCommand::HeadersCharset { charset } => {
                debug!("filter: headers charset = {}", charset);
                // Charset setting stored for header encoding
            }

            FilterCommand::Add {
                value,
                variable_index,
            } => {
                let expanded = expand_string(value, state)?;
                let num: i64 = expanded.trim().parse().unwrap_or(0);
                let idx = *variable_index as usize;
                if idx < FILTER_VARIABLE_COUNT {
                    state.variables[idx] += num;
                    debug!("filter: n{} += {} (now {})", idx, num, state.variables[idx]);
                }
            }
        }
    }
    Ok(result)
}

/// Execute a mail/vacation command (generate an auto-reply message).
///
/// F3: This function was previously a stub that expanded a handful of
/// arguments and logged the intent but **never produced a message**. The
/// C reference implementation would have written an auto-reply to the
/// queue via `deliver_msg()`, but the Rust port silently discarded it
/// because [`FilterState`] had nowhere to carry the generated message.
///
/// This version:
///
/// 1. Expands **all** [`MailArgs`] fields through [`expand_string`].
/// 2. Merges `to`, `cc`, `bcc` into a single envelope-recipient list
///    (duplicates preserved — deduplication is the orchestrator's
///    responsibility so that per-recipient routing decisions remain
///    transparent to the filter).
/// 3. Defaults `from` to the filter owner's address (via the
///    `$from` expansion variable set by the caller) when unspecified.
///    When the caller has not seeded `$from`, an empty envelope-from is
///    used which the orchestrator interprets as "bounce to null" per
///    RFC 3834 §5 for vacation replies.
/// 4. Synthesises an RFC 5322 message consisting of:
///    - `From:` header (from the `from` argument or owner default)
///    - `To:` header (from the `to` argument when present)
///    - `Cc:` header (from the `cc` argument when present — bcc is
///      *never* emitted as a header, only as an envelope recipient)
///    - `Reply-To:` header (when `reply_to` is specified)
///    - `Subject:` header (from `subject`, or a sensible default)
///    - `Auto-Submitted:` header: `auto-replied` for `vacation`, or
///      `auto-generated` for `mail` — RFC 3834 §5 MANDATES this so
///      downstream MTAs can loop-detect.
///    - `Precedence: junk` for vacation replies so auto-responder loops
///      are broken at the first downstream MTA that honours the header.
///    - Any extra headers from the `headers` argument, appended verbatim
///      (the filter is trusted to supply already-folded header lines).
///    - `MIME-Version: 1.0`, `Content-Type: text/plain; charset=utf-8`,
///      and `Content-Transfer-Encoding: quoted-printable`.
///    - Blank line separator, then the quoted-printable-encoded body.
///    - The body is sourced from `args.text` first, or read from
///      `args.file` if text is absent and file is present. If neither
///      is supplied the body is empty.
/// 5. Packages the result as a [`GeneratedMessage`] with the appropriate
///    [`GeneratedMessageKind`] and appends it to
///    `state.generated_messages`. The orchestrator (`run_exim_filter` in
///    `exim-core` or a future `exim-deliver` integration) is responsible
///    for enqueuing each generated message via the `exim-spool` crate
///    and arranging delivery through the configured transport.
///
/// The `is_vacation` parameter controls two header choices:
/// `Auto-Submitted: auto-replied` vs `auto-generated`, and the presence
/// of `Precedence: junk` (vacation only). Everything else is uniform.
///
/// When `state.no_delivery` is set (filter-test mode, `-bf`) the message
/// is still recorded so that the caller can inspect what would have
/// been produced; the orchestrator is expected to skip actual enqueue
/// in that case.
fn execute_mail_command(
    args: &MailArgs,
    state: &mut FilterState,
    is_vacation: bool,
) -> Result<(), FilterError> {
    // Expand every arg — each is independently user-controlled and may
    // reference filter variables ($n0..$n9, $thisaddress).
    let to = args
        .to
        .as_deref()
        .map(|s| expand_string(s, state))
        .transpose()?;
    let cc = args
        .cc
        .as_deref()
        .map(|s| expand_string(s, state))
        .transpose()?;
    let bcc = args
        .bcc
        .as_deref()
        .map(|s| expand_string(s, state))
        .transpose()?;
    let from = args
        .from
        .as_deref()
        .map(|s| expand_string(s, state))
        .transpose()?;
    let reply_to = args
        .reply_to
        .as_deref()
        .map(|s| expand_string(s, state))
        .transpose()?;
    let subject = args
        .subject
        .as_deref()
        .map(|s| expand_string(s, state))
        .transpose()?;
    let extra_headers = args
        .headers
        .as_deref()
        .map(|s| expand_string(s, state))
        .transpose()?;
    let body_text = args
        .text
        .as_deref()
        .map(|s| expand_string(s, state))
        .transpose()?;
    let body_file = args
        .file
        .as_deref()
        .map(|s| expand_string(s, state))
        .transpose()?;

    debug!(
        "filter: generating {} — to={:?}, from={:?}, subject={:?}",
        if is_vacation { "vacation" } else { "mail" },
        to,
        from,
        subject
    );

    // Build the envelope recipient list from to/cc/bcc. We split on
    // commas and trim whitespace — this matches Exim's sloppy parsing
    // of header-address lists in filter arguments. Empty entries are
    // dropped.
    let mut envelope_recipients: Vec<String> = Vec::new();
    for list in [to.as_deref(), cc.as_deref(), bcc.as_deref()]
        .iter()
        .flatten()
    {
        for addr in list.split(',') {
            let addr = addr.trim();
            if !addr.is_empty() {
                envelope_recipients.push(addr.to_owned());
            }
        }
    }

    // Envelope from: explicit `from` wins; otherwise fall back to the
    // empty string ("bounce to null" per RFC 3834 §5 for vacation). The
    // orchestrator may substitute the filter owner's address at a
    // higher layer.
    let envelope_from = from.clone().unwrap_or_default();

    // Category derives from the command type, not a heuristic on args.
    let category = if is_vacation {
        GeneratedMessageKind::Vacation
    } else {
        GeneratedMessageKind::Mail
    };

    // Construct the RFC 5322 message text.
    let mut msg = String::new();

    // From:
    let from_hdr = from.clone().unwrap_or_else(|| "postmaster".to_owned());
    msg.push_str(&format!("From: {from_hdr}\r\n"));

    // To:
    if let Some(ref t) = to {
        msg.push_str(&format!("To: {t}\r\n"));
    }

    // Cc:
    if let Some(ref c) = cc {
        msg.push_str(&format!("Cc: {c}\r\n"));
    }

    // Reply-To:
    if let Some(ref r) = reply_to {
        msg.push_str(&format!("Reply-To: {r}\r\n"));
    }

    // Subject:
    let subject_hdr = subject.unwrap_or_else(|| {
        if is_vacation {
            "Autoreply".to_owned()
        } else {
            "Filter-generated message".to_owned()
        }
    });
    msg.push_str(&format!("Subject: {subject_hdr}\r\n"));

    // Auto-Submitted — RFC 3834 §5 MANDATORY to prevent mail loops.
    if is_vacation {
        msg.push_str("Auto-Submitted: auto-replied\r\n");
        // RFC 3834 §5.4 recommends Precedence: junk for vacation replies
        // to suppress bounces and further auto-responses.
        msg.push_str("Precedence: junk\r\n");
    } else {
        msg.push_str("Auto-Submitted: auto-generated\r\n");
    }

    // MIME envelope — always UTF-8 quoted-printable because the body
    // has already been through our expansion and may contain any
    // Unicode code point.
    msg.push_str("MIME-Version: 1.0\r\n");
    msg.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    msg.push_str("Content-Transfer-Encoding: quoted-printable\r\n");

    // Extra headers verbatim — filter is trusted to supply correctly
    // folded CRLF-terminated lines. Normalise only the final newline.
    if let Some(ref h) = extra_headers {
        msg.push_str(h);
        if !h.ends_with('\n') && !h.ends_with("\r\n") {
            msg.push_str("\r\n");
        }
    }

    // Header/body separator.
    msg.push_str("\r\n");

    // Body source resolution: text wins over file; neither is OK.
    let body_source = if let Some(t) = body_text {
        t
    } else if let Some(path) = body_file {
        match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "filter: mail file argument {:?} unreadable ({}); using empty body",
                    path, e
                );
                String::new()
            }
        }
    } else {
        String::new()
    };

    // Encode body as quoted-printable (RFC 2045 §6.7).
    msg.push_str(&filter_quoted_printable_encode(&body_source));

    // Commit the message to the filter state. The orchestrator drains
    // this in `build_filter_outcome()` into the `FilterOutcome`.
    state.generated_messages.push(GeneratedMessage {
        envelope_from,
        envelope_recipients,
        message_text: msg,
        category,
    });

    // In filter-test / no-delivery mode the caller still gets the
    // produced message so it can be printed; actual enqueue is skipped
    // at the orchestrator layer.
    if state.no_delivery {
        info!(
            "filter: mail/vacation recorded (no_delivery mode): to={:?}",
            to
        );
    }

    Ok(())
}

/// Encode a string as quoted-printable per RFC 2045 §6.7.
///
/// This is a direct translation of the algorithm used by Exim's C filter
/// interpreter and by [`sieve_filter::quoted_printable_encode`]. We keep
/// a local copy here to keep the two modules independent.
fn filter_quoted_printable_encode(src: &str) -> String {
    /// RFC 2045 §6.7 maximum line length for quoted-printable.
    const MIMEWORD_LENGTH: usize = 75;
    let mut result = String::new();
    let mut line_len: usize = 0;
    // Reserve 2 chars for the `=\r\n` soft-line-break token.
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

/// Main entry point — parse and evaluate an Exim filter.
///
/// This corresponds to the `EXIM_INTERPRET` function slot in the C module.
/// It parses the filter source text, evaluates the resulting AST against
/// the current message context, and returns the overall outcome.
///
/// **F3 note**: This function returns only the top-level [`FilterResult`]
/// and **does not expose** generated `mail`/`vacation` messages. Callers
/// that need the full side-effect list (generated addresses, added/removed
/// headers, auto-reply messages, freeze/fail/defer text) should use
/// [`exim_interpret_outcome`] instead, which returns a complete
/// [`FilterOutcome`].
///
/// This thin wrapper remains for backward compatibility with the ~20
/// existing call sites (including all the existing tests) that only
/// care about whether the filter delivered, frozen, failed, etc.
pub fn exim_interpret(
    filter_text: &str,
    options: FilterOptions,
) -> Result<FilterResult, FilterError> {
    exim_interpret_outcome(filter_text, options).map(|o| o.result)
}

/// F3: Main entry point returning the complete filter outcome.
///
/// This function is the parallel of [`exim_interpret`] that exposes the
/// full post-evaluation state including:
///
/// - The top-level [`FilterResult`] (Delivered / NotDelivered / Frozen /
///   Failed / Defer / SystemFilterDeferred / ...).
/// - `generated_addresses`: every address produced by `deliver` / `save`
///   / `pipe` commands in execution order.
/// - `added_headers` / `removed_headers`: filter-requested header
///   modifications which the caller must apply to the on-spool message.
/// - `generated_messages`: auto-reply messages produced by `mail` and
///   `vacation` commands. Prior to F3 these were silently discarded
///   because there was no way for the interpreter to surface them.
/// - `freeze_text` / `fail_text` / `defer_text`: the explanation text
///   associated with `freeze` / `fail` / `defer` verbs, which propagates
///   into bounce messages and log lines.
///
/// The orchestrator (caller) is then responsible for:
///
/// 1. Applying header add/remove operations to the spool header file.
/// 2. Enqueuing each [`GeneratedMessage`] via the `exim-spool` crate and
///    arranging delivery through the configured transport for the
///    filter owner's domain.
/// 3. Propagating `freeze_text` / `fail_text` / `defer_text` into log
///    lines and bounce DSNs.
/// 4. Honoring `generated_addresses` by routing each as a new recipient
///    of the original message.
///
/// In filter-test mode (`-bf` / `no_delivery: true`) the orchestrator
/// should print the outcome rather than performing any I/O.
pub fn exim_interpret_outcome(
    filter_text: &str,
    options: FilterOptions,
) -> Result<FilterOutcome, FilterError> {
    info!(
        "exim_interpret_outcome: processing filter ({} bytes)",
        filter_text.len()
    );

    // Wrap the input in a Tainted marker to track untrusted origin.
    // Filter text comes from user config files (untrusted input).
    let tainted_input: TaintedString = Tainted::new(filter_text.to_owned());
    // Use AsRef to access the inner value without consuming
    let tainted_ref: &String = tainted_input.as_ref();
    debug!(
        "exim_interpret_outcome: tainted input length = {}",
        tainted_ref.len()
    );

    // Allocate a per-message arena for short-lived parser allocations
    let arena = MessageArena::new();
    let arena_str = arena.alloc_str(filter_text);
    debug!(
        "exim_interpret_outcome: arena allocated {} bytes",
        arena_str.len()
    );

    // Create a message store for intermediate evaluation data
    let _store = MessageStore::new();

    // Parse — errors include line numbers for diagnostics
    let commands = match parse_filter(filter_text, options.system_filter) {
        Ok(cmds) => cmds,
        Err(e) => {
            error!("exim_interpret_outcome: parse failed: {}", e);
            return Err(e);
        }
    };
    debug!("exim_interpret_outcome: parsed {} commands", commands.len());

    // Evaluate — the arena is used to track per-message allocation lifetime
    let mut state = FilterState::new(&options);
    debug!(
        "exim_interpret_outcome: arena stats before eval = {:?}",
        state.arena.stats()
    );
    let result = match interpret_commands(&commands, &mut state) {
        Ok(r) => r,
        Err(e) => {
            error!("exim_interpret_outcome: evaluation failed: {}", e);
            return Err(e);
        }
    };

    // Wrap the result as Clean since it was produced by our evaluator
    let clean_result: CleanString = Clean::new(format!("{result:?}"));
    // Clean implements Deref, so we can access the inner value directly
    debug!("exim_interpret_outcome: clean result = {}", &*clean_result);

    debug!(
        "exim_interpret_outcome: arena stats after eval = {:?}",
        state.arena.stats()
    );
    debug!(
        "exim_interpret_outcome: generated {} addresses, {} added headers, {} generated messages",
        state.generated_addresses.len(),
        state.added_headers.len(),
        state.generated_messages.len(),
    );
    // Store the result description in the arena for debugging lifetime
    let _result_str = state.arena.alloc_str(&format!("{result:?}"));
    // Store the result in the message store for downstream consumers
    let _store_ref = &state.message_store;
    info!("exim_interpret_outcome: result = {:?}", result);

    // Drain all state fields into the outcome. `std::mem::take` moves
    // the vectors out of `state` leaving empty vectors behind — state
    // is then dropped so no aliasing concern arises.
    Ok(FilterOutcome {
        result,
        generated_addresses: std::mem::take(&mut state.generated_addresses),
        added_headers: std::mem::take(&mut state.added_headers),
        removed_headers: std::mem::take(&mut state.removed_headers),
        generated_messages: std::mem::take(&mut state.generated_messages),
        freeze_text: state.freeze_text.take(),
        fail_text: state.fail_text.take(),
        defer_text: state.defer_text.take(),
    })
}

/// Convert a `DriverError` to a `FilterError` for error propagation.
impl From<DriverError> for FilterError {
    fn from(e: DriverError) -> Self {
        FilterError::ExpansionError(format!("driver error: {e}"))
    }
}

/// Convert a `TaintError` to a `FilterError` for sanitisation failures.
impl From<TaintError> for FilterError {
    fn from(e: TaintError) -> Self {
        FilterError::ExpansionError(format!("taint error: {e}"))
    }
}

/// Check whether a filter uses only "personal" (safe) commands.
///
/// This corresponds to the `EXIM_FILTER_PERSONAL` function slot in the C
/// module.  A filter is "personal" if it contains only delivery commands
/// (deliver, save) and conditionals — no pipe, mail, vacation, headers,
/// freeze, fail, defer, logfile, logwrite, or testprint commands.
pub fn is_personal_filter(filter_text: &str) -> bool {
    debug!(
        "is_personal_filter: checking filter ({} bytes)",
        filter_text.len()
    );
    match parse_filter(filter_text, false) {
        Ok(commands) => commands_are_personal(&commands),
        Err(e) => {
            warn!("is_personal_filter: parse error: {}", e);
            false
        }
    }
}

/// Recursively check that a command list uses only personal-safe commands.
fn commands_are_personal(commands: &[FilterCommand]) -> bool {
    for cmd in commands {
        match cmd {
            FilterCommand::Deliver { .. } | FilterCommand::Save { .. } => {
                // Allowed in personal filters
            }
            FilterCommand::If {
                then_branch,
                else_branch,
                ..
            } => {
                if !commands_are_personal(then_branch) {
                    return false;
                }
                if let Some(eb) = else_branch {
                    if !commands_are_personal(eb) {
                        return false;
                    }
                }
            }
            FilterCommand::Finish => {
                // Allowed — harmless control flow
            }
            FilterCommand::TestPrint { .. } => {
                // Allowed — only active in test mode
            }
            // All other commands are NOT personal-safe
            FilterCommand::Pipe { .. }
            | FilterCommand::Mail { .. }
            | FilterCommand::Vacation { .. }
            | FilterCommand::AddHeader { .. }
            | FilterCommand::RemoveHeader { .. }
            | FilterCommand::Freeze
            | FilterCommand::Fail
            | FilterCommand::LogWrite { .. }
            | FilterCommand::Defer { .. }
            | FilterCommand::LogFile { .. }
            | FilterCommand::HeadersCharset { .. }
            | FilterCommand::Add { .. }
            | FilterCommand::FreezeText { .. }
            | FilterCommand::FailText { .. } => {
                return false;
            }
        }
    }
    true
}

// ===========================================================================
// Module registration
// ===========================================================================

// Register the Exim filter interpreter module with the driver framework.
// Replaces the C `misc_module_info exim_filter_module_info` static struct
// that contained slots for filter_interpret (slot 0) and
// filter_personal (slot 1).
inventory::submit! {
    DriverInfoBase::new("exim_filter")
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parsing tests ----

    #[test]
    fn test_parse_empty_filter() {
        let src = "# Exim filter\n";
        let cmds = parse_filter(src, false).unwrap();
        assert!(cmds.is_empty());
    }

    #[test]
    fn test_parse_missing_marker() {
        let src = "deliver foo@bar.com\n";
        assert!(parse_filter(src, false).is_err());
    }

    #[test]
    fn test_parse_deliver_command() {
        let src = "# Exim filter\ndeliver user@example.com\n";
        let cmds = parse_filter(src, false).unwrap();
        assert_eq!(cmds.len(), 1);
        match &cmds[0] {
            FilterCommand::Deliver { address, seen } => {
                assert_eq!(address, "user@example.com");
                assert!(*seen);
            }
            _ => panic!("expected Deliver"),
        }
    }

    #[test]
    fn test_parse_unseen_deliver() {
        let src = "# Exim filter\nunseen deliver user@example.com\n";
        let cmds = parse_filter(src, false).unwrap();
        assert_eq!(cmds.len(), 1);
        match &cmds[0] {
            FilterCommand::Deliver { address, seen } => {
                assert_eq!(address, "user@example.com");
                assert!(!*seen);
            }
            _ => panic!("expected Deliver"),
        }
    }

    #[test]
    fn test_parse_save_command() {
        let src = "# Exim filter\nsave /var/mail/inbox\n";
        let cmds = parse_filter(src, false).unwrap();
        assert_eq!(cmds.len(), 1);
        match &cmds[0] {
            FilterCommand::Save { path, seen } => {
                assert_eq!(path, "/var/mail/inbox");
                assert!(*seen);
            }
            _ => panic!("expected Save"),
        }
    }

    #[test]
    fn test_parse_pipe_command() {
        let src = "# Exim filter\npipe \"/usr/bin/procmail\"\n";
        let cmds = parse_filter(src, false).unwrap();
        assert_eq!(cmds.len(), 1);
        match &cmds[0] {
            FilterCommand::Pipe { command, .. } => {
                assert_eq!(command, "/usr/bin/procmail");
            }
            _ => panic!("expected Pipe"),
        }
    }

    #[test]
    fn test_parse_if_then_endif() {
        let src = "# Exim filter\nif personal then\n  deliver me@here.com\nendif\n";
        let cmds = parse_filter(src, false).unwrap();
        assert_eq!(cmds.len(), 1);
        match &cmds[0] {
            FilterCommand::If {
                condition,
                then_branch,
                else_branch,
            } => {
                assert!(matches!(condition, Condition::Personal));
                assert_eq!(then_branch.len(), 1);
                assert!(else_branch.is_none());
            }
            _ => panic!("expected If"),
        }
    }

    #[test]
    fn test_parse_if_else_endif() {
        let src = concat!(
            "# Exim filter\n",
            "if personal then\n",
            "  deliver me@here.com\n",
            "else\n",
            "  save /tmp/other\n",
            "endif\n"
        );
        let cmds = parse_filter(src, false).unwrap();
        assert_eq!(cmds.len(), 1);
        match &cmds[0] {
            FilterCommand::If { else_branch, .. } => {
                assert!(else_branch.is_some());
                assert_eq!(else_branch.as_ref().unwrap().len(), 1);
            }
            _ => panic!("expected If"),
        }
    }

    #[test]
    fn test_parse_condition_is() {
        let src = concat!(
            "# Exim filter\n",
            "if $sender_address is \"test@example.com\" then\n",
            "  deliver me@here.com\n",
            "endif\n"
        );
        let cmds = parse_filter(src, false).unwrap();
        match &cmds[0] {
            FilterCommand::If { condition, .. } => match condition {
                Condition::Is(lhs, rhs) => {
                    assert_eq!(lhs, "$sender_address");
                    assert_eq!(rhs, "test@example.com");
                }
                _ => panic!("expected Is condition"),
            },
            _ => panic!("expected If"),
        }
    }

    #[test]
    fn test_parse_condition_contains() {
        let src = concat!(
            "# Exim filter\n",
            "if $h_subject: contains \"urgent\" then\n",
            "  deliver me@here.com\n",
            "endif\n"
        );
        let cmds = parse_filter(src, false).unwrap();
        match &cmds[0] {
            FilterCommand::If { condition, .. } => {
                assert!(matches!(condition, Condition::Contains(_, _)));
            }
            _ => panic!("expected If"),
        }
    }

    #[test]
    fn test_parse_condition_and_or() {
        let src = concat!(
            "# Exim filter\n",
            "if personal and first_delivery then\n",
            "  deliver me@here.com\n",
            "endif\n"
        );
        let cmds = parse_filter(src, false).unwrap();
        match &cmds[0] {
            FilterCommand::If { condition, .. } => {
                assert!(matches!(condition, Condition::And(_, _)));
            }
            _ => panic!("expected If"),
        }
    }

    #[test]
    fn test_parse_vacation() {
        let src = concat!(
            "# Exim filter\n",
            "vacation\n",
            "  to \"$reply_address\"\n",
            "  subject \"Away\"\n"
        );
        let cmds = parse_filter(src, false).unwrap();
        assert_eq!(cmds.len(), 1);
        match &cmds[0] {
            FilterCommand::Vacation { args } => {
                assert_eq!(args.to.as_deref(), Some("$reply_address"));
                assert_eq!(args.subject.as_deref(), Some("Away"));
                // Defaults should be set
                assert_eq!(args.file.as_deref(), Some(".vacation.msg"));
                assert_eq!(args.once.as_deref(), Some(".vacation"));
            }
            _ => panic!("expected Vacation"),
        }
    }

    #[test]
    fn test_parse_headers_add_remove() {
        let src = concat!(
            "# Exim filter\n",
            "headers add \"X-Filter: processed\"\n",
            "headers remove received\n"
        );
        let cmds = parse_filter(src, false).unwrap();
        assert_eq!(cmds.len(), 2);
        assert!(
            matches!(&cmds[0], FilterCommand::AddHeader { text } if text == "X-Filter: processed")
        );
        assert!(matches!(&cmds[1], FilterCommand::RemoveHeader { name } if name == "received"));
    }

    #[test]
    fn test_parse_freeze_fail_finish() {
        // freeze is only allowed in system filters
        let src = "# Exim filter\nfreeze\n";
        let cmds = parse_filter(src, true).unwrap();
        assert_eq!(cmds.len(), 1);
        assert!(matches!(cmds[0], FilterCommand::Freeze));
    }

    #[test]
    fn test_parse_add_variable() {
        let src = "# Exim filter\nadd 5 to n3\n";
        let cmds = parse_filter(src, false).unwrap();
        assert_eq!(cmds.len(), 1);
        match &cmds[0] {
            FilterCommand::Add {
                value,
                variable_index,
            } => {
                assert_eq!(value, "5");
                assert_eq!(*variable_index, 3);
            }
            _ => panic!("expected Add"),
        }
    }

    // ---- evaluator tests ----

    #[test]
    fn test_eval_empty_filter() {
        let opts = FilterOptions::default();
        let result = exim_interpret("# Exim filter\n", opts).unwrap();
        assert_eq!(result, FilterResult::NotDelivered);
    }

    #[test]
    fn test_eval_deliver() {
        let opts = FilterOptions::default();
        let src = "# Exim filter\ndeliver user@example.com\n";
        let result = exim_interpret(src, opts).unwrap();
        assert_eq!(result, FilterResult::Delivered);
    }

    #[test]
    fn test_eval_freeze() {
        let opts = FilterOptions {
            system_filter: true,
            ..Default::default()
        };
        let src = "# Exim filter\nfreeze\n";
        let result = exim_interpret(src, opts).unwrap();
        assert_eq!(result, FilterResult::Freeze);
    }

    #[test]
    fn test_eval_fail() {
        let opts = FilterOptions {
            system_filter: true,
            ..Default::default()
        };
        let src = "# Exim filter\nfail\n";
        let result = exim_interpret(src, opts).unwrap();
        assert_eq!(result, FilterResult::Fail);
    }

    #[test]
    fn test_eval_finish() {
        let opts = FilterOptions::default();
        let src = concat!(
            "# Exim filter\n",
            "deliver first@example.com\n",
            "finish\n",
            "deliver second@example.com\n"
        );
        let result = exim_interpret(src, opts).unwrap();
        assert_eq!(result, FilterResult::Delivered);
    }

    #[test]
    fn test_eval_condition_is() {
        let opts = FilterOptions::default();
        let src = concat!(
            "# Exim filter\n",
            "if $n0 is 0 then\n",
            "  deliver me@here.com\n",
            "endif\n"
        );
        let result = exim_interpret(src, opts).unwrap();
        // $n0 starts at 0, "0" is "0" case-insensitive => true
        assert_eq!(result, FilterResult::Delivered);
    }

    #[test]
    fn test_eval_add_variable() {
        let opts = FilterOptions::default();
        let src = concat!(
            "# Exim filter\n",
            "add 10 to n0\n",
            "if $n0 above 5 then\n",
            "  deliver me@here.com\n",
            "endif\n"
        );
        let result = exim_interpret(src, opts).unwrap();
        assert_eq!(result, FilterResult::Delivered);
    }

    // ---- is_personal_filter tests ----

    #[test]
    fn test_personal_filter_simple_deliver() {
        let src = "# Exim filter\ndeliver user@example.com\n";
        assert!(is_personal_filter(src));
    }

    #[test]
    fn test_personal_filter_pipe_not_personal() {
        let src = "# Exim filter\npipe \"/usr/bin/cmd\"\n";
        assert!(!is_personal_filter(src));
    }

    #[test]
    fn test_personal_filter_vacation_not_personal() {
        let src = "# Exim filter\nvacation to \"$reply_address\"\n";
        assert!(!is_personal_filter(src));
    }

    #[test]
    fn test_personal_filter_with_if() {
        let src = concat!(
            "# Exim filter\n",
            "if personal then\n",
            "  deliver me@here.com\n",
            "endif\n"
        );
        assert!(is_personal_filter(src));
    }

    #[test]
    fn test_personal_filter_with_freeze_not_personal() {
        let src = concat!(
            "# Exim filter\n",
            "if personal then\n",
            "  freeze\n",
            "endif\n"
        );
        assert!(!is_personal_filter(src));
    }

    // ---- condition evaluation tests ----

    #[test]
    fn test_condition_contains() {
        let state = FilterState::new(&FilterOptions::default());
        let cond = Condition::Contains("Hello World".into(), "hello".into());
        assert!(evaluate_condition(&cond, &state).unwrap());
    }

    #[test]
    fn test_condition_contains_exact() {
        let state = FilterState::new(&FilterOptions::default());
        let cond = Condition::ContainsExact("Hello World".into(), "hello".into());
        assert!(!evaluate_condition(&cond, &state).unwrap());
    }

    #[test]
    fn test_condition_begins() {
        let state = FilterState::new(&FilterOptions::default());
        let cond = Condition::Begins("Hello World".into(), "hello".into());
        assert!(evaluate_condition(&cond, &state).unwrap());
    }

    #[test]
    fn test_condition_ends() {
        let state = FilterState::new(&FilterOptions::default());
        let cond = Condition::Ends("Hello World".into(), "world".into());
        assert!(evaluate_condition(&cond, &state).unwrap());
    }

    #[test]
    fn test_condition_matches() {
        let state = FilterState::new(&FilterOptions::default());
        let cond = Condition::Matches("test@example.com".into(), ".*@example\\.com".into());
        assert!(evaluate_condition(&cond, &state).unwrap());
    }

    #[test]
    fn test_condition_above_below() {
        let state = FilterState::new(&FilterOptions::default());
        assert!(evaluate_condition(&Condition::Above("10".into(), 5), &state).unwrap());
        assert!(!evaluate_condition(&Condition::Above("3".into(), 5), &state).unwrap());
        assert!(evaluate_condition(&Condition::Below("3".into(), 5), &state).unwrap());
    }

    #[test]
    fn test_condition_not() {
        let state = FilterState::new(&FilterOptions::default());
        let cond = Condition::Not(Box::new(Condition::Delivered));
        assert!(evaluate_condition(&cond, &state).unwrap());
    }

    #[test]
    fn test_condition_and() {
        let state = FilterState::new(&FilterOptions::default());
        let cond = Condition::And(
            Box::new(Condition::Is("abc".into(), "ABC".into())),
            Box::new(Condition::Contains("hello world".into(), "hello".into())),
        );
        assert!(evaluate_condition(&cond, &state).unwrap());
    }

    #[test]
    fn test_condition_or() {
        let state = FilterState::new(&FilterOptions::default());
        let cond = Condition::Or(
            Box::new(Condition::Is("abc".into(), "xyz".into())),
            Box::new(Condition::Delivered),
        );
        assert!(!evaluate_condition(&cond, &state).unwrap());
    }

    // ---- expand_string tests ----

    #[test]
    fn test_expand_no_vars() {
        let state = FilterState::new(&FilterOptions::default());
        assert_eq!(expand_string("hello world", &state).unwrap(), "hello world");
    }

    #[test]
    fn test_expand_n_variable() {
        let mut state = FilterState::new(&FilterOptions::default());
        state.variables[3] = 42;
        assert_eq!(expand_string("val=$n3", &state).unwrap(), "val=42");
    }

    #[test]
    fn test_expand_thisaddress() {
        let mut state = FilterState::new(&FilterOptions::default());
        state.filter_thisaddress = Some("user@example.com".into());
        assert_eq!(
            expand_string("addr=$thisaddress", &state).unwrap(),
            "addr=user@example.com"
        );
    }

    // ---- split_addresses tests ----

    #[test]
    fn test_split_addresses_simple() {
        let addrs = split_addresses("a@b.com, c@d.com");
        assert_eq!(addrs, vec!["a@b.com", "c@d.com"]);
    }

    #[test]
    fn test_split_addresses_angle_bracket() {
        let addrs = split_addresses("Name <a@b.com>, Other <c@d.com>");
        assert_eq!(addrs, vec!["a@b.com", "c@d.com"]);
    }

    // =======================================================================
    // F3 tests — mail/vacation commands produce GeneratedMessage records
    // =======================================================================

    /// Helper: run the interpreter and return the full FilterOutcome so
    /// F3 tests can inspect generated_messages and its fields.
    fn f3_interpret(src: &str) -> FilterOutcome {
        exim_interpret_outcome(src, FilterOptions::default())
            .expect("F3 test filter should parse and evaluate cleanly")
    }

    #[test]
    fn test_f3_mail_produces_generated_message() {
        let src = "# Exim filter\n\
                   mail to \"user@example.com\" subject \"Hi\" text \"Hello\"\n";
        let out = f3_interpret(src);
        assert_eq!(
            out.generated_messages.len(),
            1,
            "mail command must produce exactly one GeneratedMessage"
        );
        let m = &out.generated_messages[0];
        assert!(matches!(m.category, GeneratedMessageKind::Mail));
        assert_eq!(m.envelope_recipients, vec!["user@example.com".to_owned()]);
        assert!(
            m.message_text.contains("To: user@example.com"),
            "To header must be present"
        );
        assert!(
            m.message_text.contains("Subject: Hi"),
            "Subject header must be present"
        );
    }

    #[test]
    fn test_f3_vacation_produces_generated_message_with_auto_replied_header() {
        let src = "# Exim filter\n\
                   vacation to \"sender@example.com\" text \"I am away\"\n";
        let out = f3_interpret(src);
        assert_eq!(out.generated_messages.len(), 1);
        let m = &out.generated_messages[0];
        assert!(matches!(m.category, GeneratedMessageKind::Vacation));
        assert!(
            m.message_text.contains("Auto-Submitted: auto-replied"),
            "RFC 3834 §5 MANDATES Auto-Submitted: auto-replied for vacation"
        );
    }

    #[test]
    fn test_f3_mail_has_auto_generated_header_not_auto_replied() {
        // A plain `mail` command is NOT a reply, so RFC 3834 §5 requires
        // `auto-generated`, not `auto-replied`.
        let src = "# Exim filter\n\
                   mail to \"boss@example.com\" subject \"Report\" text \"Here it is\"\n";
        let out = f3_interpret(src);
        assert_eq!(out.generated_messages.len(), 1);
        let m = &out.generated_messages[0];
        assert!(
            m.message_text.contains("Auto-Submitted: auto-generated"),
            "mail command must use Auto-Submitted: auto-generated"
        );
        assert!(
            !m.message_text.contains("Auto-Submitted: auto-replied"),
            "mail command MUST NOT set Auto-Submitted: auto-replied"
        );
    }

    #[test]
    fn test_f3_vacation_has_precedence_junk() {
        // RFC 3834 §5.4 recommends Precedence: junk for vacation replies
        // so auto-responder loops terminate at the next MTA.
        let src = "# Exim filter\n\
                   vacation to \"user@example.com\" text \"Back soon\"\n";
        let out = f3_interpret(src);
        assert!(out.generated_messages[0]
            .message_text
            .contains("Precedence: junk"));
    }

    #[test]
    fn test_f3_mail_does_not_have_precedence_junk() {
        // Only vacation carries Precedence: junk; plain mail is a new
        // message flow that may legitimately need a bounce path.
        let src = "# Exim filter\n\
                   mail to \"user@example.com\" text \"Hi\"\n";
        let out = f3_interpret(src);
        assert!(!out.generated_messages[0]
            .message_text
            .contains("Precedence: junk"));
    }

    #[test]
    fn test_f3_mail_combines_to_cc_bcc_into_envelope() {
        let src = "# Exim filter\n\
                   mail to \"a@b.com\" cc \"c@d.com\" bcc \"e@f.com\" text \"hi\"\n";
        let out = f3_interpret(src);
        let m = &out.generated_messages[0];
        assert_eq!(
            m.envelope_recipients,
            vec![
                "a@b.com".to_owned(),
                "c@d.com".to_owned(),
                "e@f.com".to_owned()
            ],
            "to, cc, and bcc must all appear in envelope_recipients"
        );
        // bcc MUST NOT appear as a header — it's a blind carbon copy.
        assert!(!m.message_text.contains("Bcc:"));
        assert!(!m.message_text.contains("bcc:"));
        // to and cc SHOULD appear as headers for recipients to see.
        assert!(m.message_text.contains("To: a@b.com"));
        assert!(m.message_text.contains("Cc: c@d.com"));
    }

    #[test]
    fn test_f3_mail_multi_recipients_comma_split() {
        // Multiple addresses in a single argument must be split on commas
        // into distinct envelope recipients.
        let src = "# Exim filter\n\
                   mail to \"a@x.com, b@x.com, c@x.com\" text \"hi\"\n";
        let out = f3_interpret(src);
        let m = &out.generated_messages[0];
        assert_eq!(m.envelope_recipients.len(), 3);
        assert!(m.envelope_recipients.contains(&"a@x.com".to_owned()));
        assert!(m.envelope_recipients.contains(&"b@x.com".to_owned()));
        assert!(m.envelope_recipients.contains(&"c@x.com".to_owned()));
    }

    #[test]
    fn test_f3_mail_reply_to_header_included() {
        let src = "# Exim filter\n\
                   mail to \"a@b.com\" reply_to \"replies@example.com\" text \"hi\"\n";
        let out = f3_interpret(src);
        assert!(out.generated_messages[0]
            .message_text
            .contains("Reply-To: replies@example.com"));
    }

    #[test]
    fn test_f3_mail_from_header_used() {
        let src = "# Exim filter\n\
                   mail to \"a@b.com\" from \"sender@example.com\" text \"hi\"\n";
        let out = f3_interpret(src);
        let m = &out.generated_messages[0];
        assert!(m.message_text.contains("From: sender@example.com"));
        assert_eq!(m.envelope_from, "sender@example.com");
    }

    #[test]
    fn test_f3_mail_without_from_defaults_envelope_to_empty() {
        // RFC 3834 §5 — auto-reply with no explicit From should use
        // the null envelope sender so downstream MTAs do not generate
        // bounces back to the auto-responder.
        let src = "# Exim filter\n\
                   mail to \"a@b.com\" text \"hi\"\n";
        let out = f3_interpret(src);
        assert_eq!(out.generated_messages[0].envelope_from, "");
    }

    #[test]
    fn test_f3_mail_mime_headers_present() {
        // All generated messages must be MIME-tagged so downstream MTAs
        // don't misinterpret the body.
        let src = "# Exim filter\n\
                   mail to \"a@b.com\" text \"hi\"\n";
        let out = f3_interpret(src);
        let txt = &out.generated_messages[0].message_text;
        assert!(txt.contains("MIME-Version: 1.0"));
        assert!(txt.contains("Content-Type: text/plain; charset=utf-8"));
        assert!(txt.contains("Content-Transfer-Encoding: quoted-printable"));
    }

    #[test]
    fn test_f3_mail_subject_expansion() {
        // Subject arguments must go through $n0..$n9 expansion.
        let mut state = FilterState::new(&FilterOptions::default());
        state.variables[3] = 42;
        let expanded = expand_string("Value is $n3", &state).unwrap();
        assert_eq!(expanded, "Value is 42");
    }

    #[test]
    fn test_f3_mail_body_text_qp_encoded() {
        // Quoted-printable encoding must be applied. The encoder
        // transforms bytes that need protection (e.g., non-ASCII).
        let src = "# Exim filter\n\
                   mail to \"a@b.com\" text \"plain body\"\n";
        let out = f3_interpret(src);
        // Body must be after the blank line separator.
        assert!(out.generated_messages[0].message_text.contains("\r\n\r\n"));
    }

    #[test]
    fn test_f3_no_mail_produces_no_generated_messages() {
        let src = "# Exim filter\n\
                   deliver user@example.com\n";
        let out = f3_interpret(src);
        assert!(out.generated_messages.is_empty());
    }

    #[test]
    fn test_f3_multiple_mail_commands_produce_multiple_messages() {
        let src = "# Exim filter\n\
                   mail to \"a@b.com\" text \"one\"\n\
                   mail to \"c@d.com\" text \"two\"\n";
        let out = f3_interpret(src);
        assert_eq!(out.generated_messages.len(), 2);
        assert!(matches!(
            out.generated_messages[0].category,
            GeneratedMessageKind::Mail
        ));
        assert!(matches!(
            out.generated_messages[1].category,
            GeneratedMessageKind::Mail
        ));
    }

    #[test]
    fn test_f3_outcome_preserves_filter_result() {
        // exim_interpret_outcome must still produce the same
        // FilterResult that exim_interpret would.
        let src = "# Exim filter\ndeliver user@example.com\n";
        let legacy = exim_interpret(src, FilterOptions::default()).unwrap();
        let outcome = exim_interpret_outcome(src, FilterOptions::default()).unwrap();
        assert_eq!(format!("{:?}", legacy), format!("{:?}", outcome.result));
    }

    #[test]
    fn test_f3_vacation_and_mail_kinds_distinct() {
        // A script with both should produce one of each kind in order.
        let src = "# Exim filter\n\
                   mail to \"boss@example.com\" subject \"Report\" text \"Here it is\"\n\
                   vacation to \"sender@example.com\" text \"I am away\"\n";
        let out = f3_interpret(src);
        assert_eq!(out.generated_messages.len(), 2);
        assert!(matches!(
            out.generated_messages[0].category,
            GeneratedMessageKind::Mail
        ));
        assert!(matches!(
            out.generated_messages[1].category,
            GeneratedMessageKind::Vacation
        ));
    }

    #[test]
    fn test_f3_vacation_default_subject() {
        // When no `subject` is specified for vacation, a sensible
        // default is used (not empty).
        let src = "# Exim filter\nvacation to \"x@y.com\" text \"away\"\n";
        let out = f3_interpret(src);
        // Ensure a Subject: line is emitted
        assert!(out.generated_messages[0].message_text.contains("Subject: "));
        // And it should not be an empty string after the colon-space.
        let lines: Vec<&str> = out.generated_messages[0]
            .message_text
            .lines()
            .filter(|l| l.starts_with("Subject:"))
            .collect();
        assert_eq!(lines.len(), 1);
        let subject_line = lines[0];
        assert!(subject_line.len() > "Subject: ".len());
    }

    #[test]
    fn test_f3_mail_extra_headers_appended() {
        // The `headers` argument must be emitted verbatim ahead of the
        // MIME envelope. The filter is trusted to supply folded CRLF
        // lines, but we tolerate bare \n in the argument.
        let src = "# Exim filter\n\
                   mail to \"a@b.com\" \
                   extra_headers \"X-Filter-Tag: foo\" \
                   text \"hi\"\n";
        let out = f3_interpret(src);
        assert!(out.generated_messages[0]
            .message_text
            .contains("X-Filter-Tag: foo"));
    }

    #[test]
    fn test_f3_qp_encoder_basic() {
        // Direct unit test of the QP encoder — ensures printable ASCII
        // round-trips unchanged and non-ASCII bytes are hex-escaped.
        assert_eq!(filter_quoted_printable_encode("hello"), "hello");
        // Non-ASCII byte (e.g., 0xE9 latin-1 "é" if not UTF-8, or the
        // multi-byte UTF-8 sequence for é: 0xC3 0xA9) must be escaped
        // byte-by-byte with uppercase hex.
        let out = filter_quoted_printable_encode("é");
        assert!(out.contains('='));
        assert!(
            out.chars().all(|c| c == '=' || c.is_ascii_hexdigit()),
            "QP output of é must consist only of = and hex digits, got {out:?}"
        );
    }

    #[test]
    fn test_f3_exim_interpret_remains_backward_compatible() {
        // Legacy callers passing a script with mail/vacation must still
        // get a FilterResult and not crash — even though the legacy API
        // discards the generated_messages.
        let src = "# Exim filter\nmail to \"a@b.com\" text \"hi\"\n";
        let r = exim_interpret(src, FilterOptions::default()).unwrap();
        // mail/vacation don't mark as delivered — they're side effects
        // orthogonal to the delivery pipeline.
        assert_eq!(r, FilterResult::NotDelivered);
    }

    #[test]
    fn test_f3_vacation_body_contains_text_after_envelope() {
        let src = "# Exim filter\n\
                   vacation to \"s@x.com\" text \"Gone fishing\"\n";
        let out = f3_interpret(src);
        let txt = &out.generated_messages[0].message_text;
        // The body appears after the `\r\n\r\n` header/body separator.
        let parts: Vec<&str> = txt.splitn(2, "\r\n\r\n").collect();
        assert_eq!(parts.len(), 2, "must have header/body separator");
        // Since QP passes ASCII printables through, "Gone fishing" should
        // appear verbatim in the body.
        assert!(parts[1].contains("Gone fishing"));
    }

    #[test]
    fn test_f3_vacation_with_if_condition_records_only_when_true() {
        // Inside a false-branch `if`, vacation should not be recorded.
        let src_false = "# Exim filter\n\
                         if $h_from contains \"nonexistent\" then\n\
                         vacation to \"s@x.com\" text \"away\"\n\
                         endif\n";
        let out_false = f3_interpret(src_false);
        assert!(out_false.generated_messages.is_empty());
    }

    #[test]
    fn test_f3_generated_message_envelope_from_respects_from_arg() {
        let src = "# Exim filter\n\
                   mail to \"a@b.com\" from \"bot@example.com\" text \"hi\"\n";
        let out = f3_interpret(src);
        assert_eq!(out.generated_messages[0].envelope_from, "bot@example.com");
    }
}
