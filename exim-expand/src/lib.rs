// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! Public API for the Exim string expansion engine.
//!
//! This crate replaces the monolithic `src/src/expand.c` (9,210 lines)
//! with a modular tokenizer → parser → evaluator pipeline.  The public
//! API functions exposed here are consumed by `exim-core`, `exim-acl`,
//! `exim-config`, and other workspace crates that need to expand Exim
//! configuration strings containing `${…}` expressions.
//!
//! # Architecture
//!
//! The expansion pipeline is split into three phases:
//!
//! 1. **Tokenizer** ([`tokenizer`]) — lexical analysis converting the
//!    raw string into a stream of [`Token`] values.
//! 2. **Parser** ([`parser`]) — recursive-descent construction of an
//!    [`AstNode`] tree from the token stream.
//! 3. **Evaluator** ([`evaluator`]) — tree-walking evaluation that
//!    produces the expanded result string.
//!
//! Supporting modules handle variable substitution, condition evaluation,
//! lookup integration, string transforms, external-program execution,
//! dynamic-function loading, and embedded Perl.
//!
//! # Safety
//!
//! This crate contains **zero `unsafe` blocks** (enforced by
//! `#![deny(unsafe_code)]`).  All FFI interactions are routed through
//! the `exim-ffi` crate.

// ── Crate-level lint configuration ──────────────────────────────────────
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::all)]

// ── Submodule declarations ──────────────────────────────────────────────

/// Lexical analysis of `${…}` expansion expressions.
pub mod tokenizer;

/// Recursive-descent parser producing an AST from the token stream.
pub mod parser;

/// Tree-walking evaluator that computes the expanded result string.
pub mod evaluator;

/// Variable substitution: `$local_part`, `$domain`, `$sender_address`, etc.
pub mod variables;

/// `${if …}` conditional logic and boolean condition evaluation.
pub mod conditions;

/// `${lookup …}` integration bridge to the `exim-lookups` crate.
pub mod lookups;

/// String transformation operators: `${lc:…}`, `${uc:…}`, `${hash:…}`, etc.
pub mod transforms;

/// `${run …}` expansion item — executes external commands via
/// `std::process::Command`.
#[cfg(feature = "run")]
pub mod run;

/// `${dlfunc …}` expansion item — dynamic shared-library function calls.
/// Gated behind the `dlfunc` Cargo feature (replaces `#ifdef EXPAND_DLFUNC`
/// from expand.c line 7138).
#[cfg(feature = "dlfunc")]
pub mod dlfunc;

/// `${perl …}` expansion item — embedded Perl integration via `exim-ffi`.
/// Gated behind the `perl` Cargo feature (replaces `#ifndef EXIM_PERL`
/// from expand.c line 5377).
#[cfg(feature = "perl")]
pub mod perl;

// ── External crate imports ──────────────────────────────────────────────
use rand::RngExt;

// ── Re-exports from submodules ──────────────────────────────────────────

pub use evaluator::Evaluator;
pub use parser::AstNode;
pub use tokenizer::Token;

// ── Re-exports from exim-store for taint tracking ───────────────────────
//
// These newtypes enforce compile-time taint tracking, replacing the C
// runtime `is_tainted()` / `die_tainted()` system from store.c/store.h
// (AAP §0.4.3).

pub use exim_store::{Clean, CleanString, Tainted, TaintedString};

// ═══════════════════════════════════════════════════════════════════════
//  Error types
// ═══════════════════════════════════════════════════════════════════════

/// Errors that can occur during string expansion.
///
/// Replaces the C global `expand_string_message` (error text) and
/// `f.expand_string_forcedfail` (forced-failure flag) with an idiomatic
/// Rust `Result`-based error model.
///
/// # Variants
///
/// | Variant | C Equivalent |
/// |---------|-------------|
/// | [`Failed`](Self::Failed) | `expand_string_message` set to descriptive text |
/// | [`ForcedFail`](Self::ForcedFail) | `f.expand_string_forcedfail = TRUE` |
/// | [`TaintedInput`](Self::TaintedInput) | `die_tainted()` call in expand path |
/// | [`IntegerError`](Self::IntegerError) | `strtoll` overflow / bad format |
/// | [`LookupDefer`](Self::LookupDefer) | `search_find_defer = TRUE` |
#[derive(Debug, thiserror::Error)]
pub enum ExpandError {
    /// General expansion failure with a descriptive message.
    #[error("expansion failed: {message}")]
    Failed {
        /// Human-readable description of the failure.
        message: String,
    },

    /// Expansion was explicitly forced to fail via `${if …{fail}}` or
    /// similar construct.  This is a non-error control-flow signal that
    /// callers may choose to handle differently from [`Failed`](Self::Failed).
    #[error("forced failure")]
    ForcedFail,

    /// A tainted (untrusted) string was used in a context that requires
    /// a clean (trusted) value.
    #[error("tainted string expansion attempt: {0}")]
    TaintedInput(String),

    /// The expanded string could not be interpreted as an integer.
    #[error("integer interpretation error: {0}")]
    IntegerError(String),

    /// A lookup operation deferred (temporary failure) during expansion.
    #[error("lookup deferred")]
    LookupDefer,
}

// ═══════════════════════════════════════════════════════════════════════
//  Expansion state-indicator flags (EsiFlags)
// ═══════════════════════════════════════════════════════════════════════

/// Expansion state-indicator flags controlling the behaviour of the
/// expansion pipeline.
///
/// This is a newtype around `u32` providing bitflag-like operations.
/// It replaces the C `esi_flags` typedef from expand.c lines 21–26:
///
/// ```c
/// typedef unsigned esi_flags;
/// #define ESI_NOFLAGS       0
/// #define ESI_BRACE_ENDS    BIT(0)
/// #define ESI_HONOR_DOLLAR  BIT(1)
/// #define ESI_SKIPPING      BIT(2)
/// #define ESI_EXISTS_ONLY   BIT(3)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EsiFlags(u32);

impl EsiFlags {
    /// No flags set — default expansion mode.
    pub const ESI_NONE: Self = Self(0);

    /// Expansion should stop when an unescaped closing brace `}` is
    /// encountered at the current nesting level.
    pub const ESI_BRACE_ENDS: Self = Self(1 << 0);

    /// The dollar sign `$` is meaningful and triggers variable/item
    /// expansion.  When not set, `$` is treated as a literal character.
    pub const ESI_HONOR_DOLLAR: Self = Self(1 << 1);

    /// The expansion result will not be used — the engine is in
    /// "skipping" mode for the false branch of a conditional.  Allows
    /// short-circuiting of expensive operations.
    pub const ESI_SKIPPING: Self = Self(1 << 2);

    /// Only the *existence* (non-emptiness) of the expansion result
    /// matters — the actual value is not needed.  Enables early exit
    /// optimisations.
    pub const ESI_EXISTS_ONLY: Self = Self(1 << 3);

    /// Create flags from a raw `u32` bitmask.
    #[inline]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Return the underlying `u32` bitmask.
    #[inline]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Test whether `self` contains all bits set in `other`.
    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Test whether no flags are set.
    #[inline]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for EsiFlags {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for EsiFlags {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for EsiFlags {
    type Output = Self;
    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl std::ops::BitAndAssign for EsiFlags {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl std::ops::Not for EsiFlags {
    type Output = Self;
    #[inline]
    fn not(self) -> Self {
        Self(!self.0)
    }
}

impl Default for EsiFlags {
    #[inline]
    fn default() -> Self {
        Self::ESI_NONE
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Expansion-forbid flags (RDO_*)
// ═══════════════════════════════════════════════════════════════════════

/// Forbid `${lookup …}` during expansion.
///
/// Checked at expand.c line 5209 before dispatching a lookup item.
/// When set in the evaluator's `expand_forbid` bitmask, any attempt to
/// use `${lookup …}` causes an immediate expansion failure.
pub const RDO_LOOKUP: u32 = 1 << 0;

/// Forbid `${run …}` during expansion.
///
/// Checked at expand.c line 5824 before executing an external command.
/// Prevents command execution in restricted expansion contexts (e.g.
/// during address verification).
pub const RDO_RUN: u32 = 1 << 1;

/// Forbid `${dlfunc …}` during expansion.
///
/// Checked at expand.c line 7151 before loading a dynamic function.
/// Prevents arbitrary shared-library code execution in restricted
/// contexts.
pub const RDO_DLFUNC: u32 = 1 << 2;

/// Forbid `${perl …}` during expansion.
///
/// Checked at expand.c line 5388 before invoking the embedded Perl
/// interpreter.  Prevents Perl code execution in restricted contexts.
pub const RDO_PERL: u32 = 1 << 3;

// ═══════════════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════════════

/// Size of the file-read buffer used by [`expand_file_big_buffer`].
///
/// Matches the C `big_buffer_size` default of 16 KiB.
const BIG_BUFFER_SIZE: usize = 16_384;

/// Database-related keywords whose presence in an error message causes
/// [`expand_hide_passwords`] to mask the message.
const DB_KEYWORDS: &[&str] = &[
    "mysql", "pgsql", "redis", "sqlite", "ldap", "ldaps", "ldapi",
];

// ═══════════════════════════════════════════════════════════════════════
//  Primary expansion functions
// ═══════════════════════════════════════════════════════════════════════

/// Expand an Exim configuration string containing `${…}` expressions.
///
/// This is the main expansion entry point, consumed by virtually every
/// subsystem in the Exim MTA.  It replaces the C `expand_string()`
/// macro which wraps `expand_string_2()`.
///
/// # Fast path
///
/// If the input contains no `$` or `\` characters the string is
/// returned unchanged (matching the C optimisation at expand.c
/// line 8736: `Ustrpbrk(string, "$\\") != NULL`).
///
/// # Errors
///
/// Returns [`ExpandError`] on expansion failure, forced failure,
/// tainted input, or lookup deferral.
///
/// # Examples
///
/// ```ignore
/// let result = exim_expand::expand_string("plain text")?;
/// assert_eq!(result, "plain text");
/// ```
pub fn expand_string(string: &str) -> Result<String, ExpandError> {
    tracing::debug!(input = %string, "expand_string entry");
    let mut textonly = false;
    let result = expand_string_2(string, &mut textonly);
    tracing::debug!(textonly = textonly, "expand_string exit");
    result
}

/// Expand an Exim configuration string with text-only detection.
///
/// Behaves identically to [`expand_string`] but additionally sets
/// `*textonly` to `true` when the expansion produced no dynamic
/// content (i.e. the result is identical to the input).  This enables
/// callers to cache the result and skip future re-expansion.
///
/// Replaces the C function at expand.c lines 8732–8748.
///
/// # Arguments
///
/// * `string`   — The raw expansion string.
/// * `textonly` — Set to `true` if no dynamic expansion was performed.
///
/// # Errors
///
/// Same as [`expand_string`].
pub fn expand_string_2(string: &str, textonly: &mut bool) -> Result<String, ExpandError> {
    // Fast path: no expansion characters → return input unchanged.
    if !string.contains('$') && !string.contains('\\') {
        *textonly = true;
        return Ok(string.to_owned());
    }

    *textonly = false;

    // Full expansion pipeline: tokenize → parse → evaluate.
    let mut parser_inst = parser::Parser::new(string);
    let ast = parser_inst.parse()?;

    let mut eval = evaluator::Evaluator::new();
    let flags = EsiFlags::ESI_HONOR_DOLLAR;
    eval.evaluate(&ast, flags)
}

/// Return whether `string` expands to a non-empty value.
///
/// Uses [`EsiFlags::ESI_EXISTS_ONLY`] to short-circuit expansion once
/// any non-empty output is detected.  Replaces the C function at
/// expand.c lines 8753–8761.
///
/// # Returns
///
/// `true` if the expansion produces at least one character of output.
pub fn expand_string_nonempty(string: &str) -> bool {
    // Fast path: literal non-empty string without expansion chars.
    if !string.contains('$') && !string.contains('\\') {
        return !string.is_empty();
    }

    let mut parser_inst = parser::Parser::new(string);
    let ast = match parser_inst.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    let mut eval = evaluator::Evaluator::new();
    let flags = EsiFlags::ESI_HONOR_DOLLAR | EsiFlags::ESI_EXISTS_ONLY;
    match eval.evaluate(&ast, flags) {
        Ok(s) => !s.is_empty(),
        Err(_) => false,
    }
}

/// Expand a string and guarantee a new owned copy is returned.
///
/// Unlike [`expand_string`] (which could theoretically return a
/// reference into a cache), this function always allocates a fresh
/// `String`.  In the Rust implementation this is effectively identical
/// to [`expand_string`] since Rust strings are always owned, but the
/// function is preserved for API compatibility with C callers that
/// relied on the guarantee.
///
/// Replaces the C function at expand.c lines 8778–8783.
///
/// # Errors
///
/// Same as [`expand_string`].
pub fn expand_string_copy(string: &str) -> Result<String, ExpandError> {
    let result = expand_string(string)?;
    // In Rust, `expand_string` already returns an owned String.
    // Clone to ensure the caller has a fully independent copy.
    Ok(result)
}

/// Expand a string and interpret the result as an integer.
///
/// Delegates to [`expand_string`] followed by
/// [`expanded_string_integer`].  Replaces the C function at expand.c
/// lines 8803–8807.
///
/// # Arguments
///
/// * `string`  — The expansion string to evaluate.
/// * `is_plus` — If `true`, negative values are rejected.
///
/// # Errors
///
/// Returns [`ExpandError::IntegerError`] if the expanded string is
/// not a valid integer, or propagates any error from [`expand_string`].
pub fn expand_string_integer(string: &str, is_plus: bool) -> Result<i64, ExpandError> {
    tracing::debug!(input = %string, is_plus = is_plus, "expand_string_integer");
    let expanded = expand_string(string)?;
    expanded_string_integer(&expanded, is_plus)
}

// ═══════════════════════════════════════════════════════════════════════
//  Condition checking
// ═══════════════════════════════════════════════════════════════════════

/// Expand a condition string and evaluate it as a boolean.
///
/// The expanded result is considered `true` if it is non-empty **and**
/// does not match `"0"`, `"no"`, or `"false"` (case-insensitive).
///
/// `m1` and `m2` are descriptive label arguments used for error
/// messages (typically the option name and driver name).
///
/// Replaces the C function at expand.c lines 1000–1014.
///
/// # Arguments
///
/// * `condition` — The expansion string to evaluate as a boolean.
/// * `m1`        — First descriptive label (e.g. option name) for
///   error messages.
/// * `m2`        — Second descriptive label (e.g. driver name) for
///   error messages.
///
/// # Returns
///
/// `true` if the condition evaluates to a truthy value.
pub fn expand_check_condition(condition: &str, m1: &str, m2: &str) -> bool {
    tracing::debug!(
        condition = %condition,
        m1 = %m1,
        m2 = %m2,
        "expand_check_condition"
    );

    let expanded = match expand_string(condition) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                error = %e,
                m1 = %m1,
                m2 = %m2,
                "condition expansion failed"
            );
            return false;
        }
    };

    is_truthy(&expanded)
}

// ═══════════════════════════════════════════════════════════════════════
//  Integer interpretation
// ═══════════════════════════════════════════════════════════════════════

/// Interpret an already-expanded string as a 64-bit signed integer.
///
/// Handles the following formats (matching the C implementation at
/// expand.c lines 8828–8895):
///
/// * **Whitespace-only / empty** → `0`
/// * **Decimal** (`[+-]?[0-9]+`)
/// * **Hexadecimal** (`0x[0-9a-fA-F]+`)
/// * **Suffixes**: `K` (×1024), `M` (×1024²), `G` (×1024³)
///
/// # Arguments
///
/// * `s`       — The string to parse.
/// * `is_plus` — If `true`, negative results are rejected.
///
/// # Errors
///
/// Returns [`ExpandError::IntegerError`] on:
/// * Invalid characters
/// * Overflow beyond `i64::MAX` / below `i64::MIN`
/// * Negative value when `is_plus` is `true`
pub fn expanded_string_integer(s: &str, is_plus: bool) -> Result<i64, ExpandError> {
    let trimmed = s.trim();

    // Empty / whitespace-only → 0  (matches C: "treat as 0" when
    // string is entirely spaces).
    if trimmed.is_empty() {
        return Ok(0);
    }

    // Detect optional sign.
    let (negative, digits_start) = if let Some(rest) = trimmed.strip_prefix('-') {
        (true, rest)
    } else if let Some(rest) = trimmed.strip_prefix('+') {
        (false, rest)
    } else {
        (false, trimmed)
    };

    if digits_start.is_empty() {
        return Err(ExpandError::IntegerError(format!(
            "no digits after sign in \"{}\"",
            s
        )));
    }

    // Detect hex prefix.
    let (radix, raw_digits) = if digits_start.starts_with("0x") || digits_start.starts_with("0X") {
        (16u32, &digits_start[2..])
    } else {
        (10u32, digits_start)
    };

    if raw_digits.is_empty() {
        return Err(ExpandError::IntegerError(format!(
            "no digits after hex prefix in \"{}\"",
            s
        )));
    }

    // Split off an optional K/M/G suffix.
    let (digit_part, multiplier) = parse_suffix(raw_digits, s)?;

    // Parse the numeric portion.
    let abs_value = i64_from_str_radix(digit_part, radix, s)?;

    // Apply sign.
    let signed_value = if negative {
        abs_value.checked_neg().ok_or_else(|| {
            ExpandError::IntegerError(format!("integer overflow (negation) in \"{}\"", s))
        })?
    } else {
        abs_value
    };

    // Apply multiplier.
    let result = signed_value.checked_mul(multiplier).ok_or_else(|| {
        ExpandError::IntegerError(format!("integer overflow (suffix multiplier) in \"{}\"", s))
    })?;

    // Reject negative when caller expects non-negative.
    if is_plus && result < 0 {
        return Err(ExpandError::IntegerError(format!(
            "non-negative integer expected, got \"{}\"",
            s
        )));
    }

    Ok(result)
}

/// Parse an optional K/M/G suffix from the end of a digit string.
///
/// Returns `(digit_slice, multiplier)`.
fn parse_suffix<'a>(raw: &'a str, original: &str) -> Result<(&'a str, i64), ExpandError> {
    if raw.is_empty() {
        return Err(ExpandError::IntegerError(format!(
            "empty digit portion in \"{}\"",
            original
        )));
    }

    let last = raw.as_bytes()[raw.len() - 1];
    match last {
        b'K' | b'k' => Ok((&raw[..raw.len() - 1], 1024)),
        b'M' | b'm' => Ok((&raw[..raw.len() - 1], 1_048_576)),
        b'G' | b'g' => Ok((&raw[..raw.len() - 1], 1_073_741_824)),
        _ => Ok((raw, 1)),
    }
}

/// Parse a string of digits in the given radix to `i64`, with overflow
/// detection.
fn i64_from_str_radix(digits: &str, radix: u32, original: &str) -> Result<i64, ExpandError> {
    if digits.is_empty() {
        return Err(ExpandError::IntegerError(format!(
            "no digits in \"{}\"",
            original
        )));
    }

    i64::from_str_radix(digits, radix).map_err(|e| {
        ExpandError::IntegerError(format!(
            "cannot parse \"{}\" as base-{} integer: {}",
            original, radix, e
        ))
    })
}

// ═══════════════════════════════════════════════════════════════════════
//  Boolean option expansion
// ═══════════════════════════════════════════════════════════════════════

/// Expand a boolean driver option, returning `Ok(true)` or
/// `Ok(false)`.
///
/// If the option has a string value that needs expansion, it is
/// expanded and then tested against the recognised boolean tokens:
///
/// * **truthy**: `"true"`, `"yes"` (case-insensitive)
/// * **falsy**:  `"false"`, `"no"` (case-insensitive)
///
/// If no string value is provided, the pre-set `bvalue` is returned
/// directly.
///
/// Replaces the C function `exp_bool()` at expand.c lines 8916–8955.
///
/// # Arguments
///
/// * `module_type` — Driver module category (e.g. `"transport"`).
/// * `module_name` — Driver instance name (e.g. `"remote_smtp"`).
/// * `option_name` — The option being expanded (for error messages).
/// * `bvalue`      — The pre-parsed boolean default.
/// * `svalue`      — Optional string value to expand.
///
/// # Errors
///
/// Returns [`ExpandError::Failed`] if expansion fails or the expanded
/// string is not a recognised boolean token.
pub fn exp_bool(
    module_type: &str,
    module_name: &str,
    option_name: &str,
    bvalue: bool,
    svalue: Option<&str>,
) -> Result<bool, ExpandError> {
    // If no string value, use the pre-parsed boolean default.
    let sval = match svalue {
        Some(s) => s,
        None => return Ok(bvalue),
    };

    // Expand the string value.
    let expanded = match expand_string(sval) {
        Ok(s) => s,
        Err(ExpandError::ForcedFail) => return Ok(bvalue),
        Err(e) => {
            return Err(ExpandError::Failed {
                message: format!(
                    "{} {} option {} expansion failed: {}",
                    module_type, module_name, option_name, e
                ),
            });
        }
    };

    // Interpret the expanded value as boolean.
    let lower = expanded.trim().to_ascii_lowercase();
    match lower.as_str() {
        "true" | "yes" => Ok(true),
        "false" | "no" => Ok(false),
        _ => Err(ExpandError::Failed {
            message: format!(
                "{} {} option {}: \"{}\" is not a recognised boolean value",
                module_type, module_name, option_name, expanded
            ),
        }),
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Password hiding
// ═══════════════════════════════════════════════════════════════════════

/// Replace an expansion-error message with a generic text when it
/// may contain database credentials.
///
/// Scans the error string for indicators of an expansion-related error
/// (`"failed to expand"` or `"expansion of "`) **and** a database
/// keyword (`mysql`, `pgsql`, `redis`, `sqlite`, `ldap`, `ldaps`,
/// `ldapi`).  When both are found the original message is replaced
/// with `"Temporary internal error"` to prevent credential leakage
/// in log files or SMTP error responses.
///
/// Replaces the C function at expand.c lines 8961–8978.
///
/// # Arguments
///
/// * `error_msg` — The original error message.
///
/// # Returns
///
/// Either the original message (if it is safe) or the generic
/// replacement string.
pub fn expand_hide_passwords(error_msg: &str) -> String {
    let lower = error_msg.to_ascii_lowercase();

    let has_expansion_prefix =
        lower.contains("failed to expand") || lower.contains("expansion of ");

    if !has_expansion_prefix {
        return error_msg.to_owned();
    }

    let has_db_keyword = DB_KEYWORDS.iter().any(|kw| lower.contains(kw));

    if has_db_keyword {
        "Temporary internal error".to_owned()
    } else {
        error_msg.to_owned()
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  File reading
// ═══════════════════════════════════════════════════════════════════════

/// Read the contents of a file into a buffer, returning the result as
/// a `String`.
///
/// Opens `filename` for reading, reads up to [`BIG_BUFFER_SIZE`]
/// bytes, and returns the resulting buffer.  On I/O error the function
/// returns [`ExpandError::Failed`].
///
/// Replaces the C function `expand_file_big_buffer()` at expand.c
/// lines 8990–9017.
///
/// # Arguments
///
/// * `filename` — Path of the file to read.
///
/// # Errors
///
/// Returns [`ExpandError::Failed`] if the file cannot be opened or
/// read.
pub fn expand_file_big_buffer(filename: &str) -> Result<String, ExpandError> {
    use std::io::Read;

    let mut file = std::fs::File::open(filename).map_err(|e| ExpandError::Failed {
        message: format!("cannot open file \"{}\": {}", filename, e),
    })?;

    let mut buffer = vec![0u8; BIG_BUFFER_SIZE];
    let bytes_read = file.read(&mut buffer).map_err(|e| ExpandError::Failed {
        message: format!("cannot read file \"{}\": {}", filename, e),
    })?;

    buffer.truncate(bytes_read);

    String::from_utf8(buffer).map_err(|e| ExpandError::Failed {
        message: format!("file \"{}\" contains invalid UTF-8: {}", filename, e),
    })
}

// ═══════════════════════════════════════════════════════════════════════
//  Random number generation
// ═══════════════════════════════════════════════════════════════════════

/// Generate a pseudo-random integer in the range `[0, max)`.
///
/// Uses the `rand` crate's thread-local CSPRNG, replacing the C
/// implementation at expand.c lines 1042–1089 which used
/// `arc4random()` / `srandom()` / `random()` fallback chain.
///
/// # Arguments
///
/// * `max` — Exclusive upper bound.  Must be positive.
///
/// # Returns
///
/// A uniformly-distributed random integer in `[0, max)`.  If `max`
/// is ≤ 0, returns `0`.
pub fn vaguely_random_number(max: i32) -> i32 {
    if max <= 0 {
        tracing::debug!(max = max, "vaguely_random_number: max <= 0, returning 0");
        return 0;
    }

    let mut rng = rand::rng();
    let value = rng.random_range(0..max);
    tracing::debug!(max = max, result = value, "vaguely_random_number");
    value
}

// ═══════════════════════════════════════════════════════════════════════
//  Internal helpers
// ═══════════════════════════════════════════════════════════════════════

/// Test whether an expanded string represents a "truthy" value.
///
/// A string is truthy if it is non-empty and does **not** match `"0"`,
/// `"no"`, or `"false"` (case-insensitive).  This matches the C
/// semantics used in `expand_check_condition()`.
fn is_truthy(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let lower = s.trim().to_ascii_lowercase();
    lower != "0" && lower != "no" && lower != "false"
}

// ═══════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── EsiFlags ────────────────────────────────────────────────────

    #[test]
    fn esi_flags_none_is_zero() {
        assert_eq!(EsiFlags::ESI_NONE.bits(), 0);
        assert!(EsiFlags::ESI_NONE.is_empty());
    }

    #[test]
    fn esi_flags_bitor_combines() {
        let combined = EsiFlags::ESI_HONOR_DOLLAR | EsiFlags::ESI_SKIPPING;
        assert!(combined.contains(EsiFlags::ESI_HONOR_DOLLAR));
        assert!(combined.contains(EsiFlags::ESI_SKIPPING));
        assert!(!combined.contains(EsiFlags::ESI_BRACE_ENDS));
    }

    #[test]
    fn esi_flags_bitand_intersects() {
        let all = EsiFlags::ESI_BRACE_ENDS
            | EsiFlags::ESI_HONOR_DOLLAR
            | EsiFlags::ESI_SKIPPING
            | EsiFlags::ESI_EXISTS_ONLY;
        let masked = all & EsiFlags::ESI_SKIPPING;
        assert!(masked.contains(EsiFlags::ESI_SKIPPING));
        assert!(!masked.contains(EsiFlags::ESI_HONOR_DOLLAR));
    }

    #[test]
    fn esi_flags_not_inverts() {
        let flags = EsiFlags::ESI_BRACE_ENDS;
        let inverted = !flags;
        assert!(!inverted.contains(EsiFlags::ESI_BRACE_ENDS));
    }

    #[test]
    fn esi_flags_default_is_none() {
        assert_eq!(EsiFlags::default(), EsiFlags::ESI_NONE);
    }

    // ── ExpandError ─────────────────────────────────────────────────

    #[test]
    fn expand_error_display_failed() {
        let e = ExpandError::Failed {
            message: "missing brace".into(),
        };
        assert_eq!(format!("{}", e), "expansion failed: missing brace");
    }

    #[test]
    fn expand_error_display_forced_fail() {
        let e = ExpandError::ForcedFail;
        assert_eq!(format!("{}", e), "forced failure");
    }

    #[test]
    fn expand_error_display_tainted() {
        let e = ExpandError::TaintedInput("bad data".into());
        assert_eq!(
            format!("{}", e),
            "tainted string expansion attempt: bad data"
        );
    }

    #[test]
    fn expand_error_display_integer() {
        let e = ExpandError::IntegerError("not a number".into());
        assert_eq!(
            format!("{}", e),
            "integer interpretation error: not a number"
        );
    }

    #[test]
    fn expand_error_display_lookup_defer() {
        let e = ExpandError::LookupDefer;
        assert_eq!(format!("{}", e), "lookup deferred");
    }

    // ── RDO constants ───────────────────────────────────────────────

    #[test]
    fn rdo_constants_are_distinct_bits() {
        assert_eq!(RDO_LOOKUP, 1);
        assert_eq!(RDO_RUN, 2);
        assert_eq!(RDO_DLFUNC, 4);
        assert_eq!(RDO_PERL, 8);
        assert_eq!(RDO_LOOKUP & RDO_RUN, 0);
        assert_eq!(RDO_DLFUNC & RDO_PERL, 0);
    }

    // ── expand_string ───────────────────────────────────────────────

    #[test]
    fn expand_string_literal_passthrough() {
        let result = expand_string("hello world").unwrap();
        assert_eq!(result, "hello world");
    }

    #[test]
    fn expand_string_empty() {
        let result = expand_string("").unwrap();
        assert_eq!(result, "");
    }

    // ── expand_string_2 ─────────────────────────────────────────────

    #[test]
    fn expand_string_2_textonly_for_literal() {
        let mut textonly = false;
        let result = expand_string_2("no dollars here", &mut textonly).unwrap();
        assert_eq!(result, "no dollars here");
        assert!(textonly);
    }

    #[test]
    fn expand_string_2_not_textonly_for_dollar() {
        let mut textonly = true;
        let _result = expand_string_2("$variable", &mut textonly);
        assert!(!textonly);
    }

    // ── expand_string_nonempty ──────────────────────────────────────

    #[test]
    fn expand_string_nonempty_true_for_literal() {
        assert!(expand_string_nonempty("some text"));
    }

    #[test]
    fn expand_string_nonempty_false_for_empty() {
        assert!(!expand_string_nonempty(""));
    }

    // ── expand_string_copy ──────────────────────────────────────────

    #[test]
    fn expand_string_copy_returns_owned() {
        let result = expand_string_copy("copy me").unwrap();
        assert_eq!(result, "copy me");
    }

    // ── expanded_string_integer ─────────────────────────────────────

    #[test]
    fn expanded_string_integer_decimal() {
        assert_eq!(expanded_string_integer("42", false).unwrap(), 42);
    }

    #[test]
    fn expanded_string_integer_negative() {
        assert_eq!(expanded_string_integer("-7", false).unwrap(), -7);
    }

    #[test]
    fn expanded_string_integer_hex() {
        assert_eq!(expanded_string_integer("0xFF", false).unwrap(), 255);
    }

    #[test]
    fn expanded_string_integer_suffix_k() {
        assert_eq!(expanded_string_integer("10K", false).unwrap(), 10_240);
    }

    #[test]
    fn expanded_string_integer_suffix_m() {
        assert_eq!(expanded_string_integer("2M", false).unwrap(), 2_097_152);
    }

    #[test]
    fn expanded_string_integer_suffix_g() {
        assert_eq!(expanded_string_integer("1G", false).unwrap(), 1_073_741_824);
    }

    #[test]
    fn expanded_string_integer_whitespace_only() {
        assert_eq!(expanded_string_integer("   ", false).unwrap(), 0);
    }

    #[test]
    fn expanded_string_integer_empty() {
        assert_eq!(expanded_string_integer("", false).unwrap(), 0);
    }

    #[test]
    fn expanded_string_integer_rejects_negative_when_plus() {
        assert!(expanded_string_integer("-5", true).is_err());
    }

    #[test]
    fn expanded_string_integer_overflow() {
        // A very large number that overflows i64
        assert!(expanded_string_integer("99999999999999999999", false).is_err());
    }

    // ── expand_check_condition ──────────────────────────────────────

    #[test]
    fn expand_check_condition_true_for_text() {
        assert!(expand_check_condition("yes", "opt", "drv"));
    }

    #[test]
    fn expand_check_condition_false_for_zero() {
        assert!(!expand_check_condition("0", "opt", "drv"));
    }

    #[test]
    fn expand_check_condition_false_for_no() {
        assert!(!expand_check_condition("no", "opt", "drv"));
    }

    #[test]
    fn expand_check_condition_false_for_false_str() {
        assert!(!expand_check_condition("false", "opt", "drv"));
    }

    #[test]
    fn expand_check_condition_false_for_empty() {
        assert!(!expand_check_condition("", "opt", "drv"));
    }

    // ── expand_string_integer ───────────────────────────────────────

    #[test]
    fn expand_string_integer_literal() {
        assert_eq!(expand_string_integer("100", false).unwrap(), 100);
    }

    // ── exp_bool ────────────────────────────────────────────────────

    #[test]
    fn exp_bool_returns_default_when_no_string() {
        assert!(exp_bool("transport", "smtp", "opt", true, None).unwrap());
        assert!(!exp_bool("transport", "smtp", "opt", false, None).unwrap());
    }

    #[test]
    fn exp_bool_true_string() {
        assert!(exp_bool("transport", "smtp", "opt", false, Some("true")).unwrap());
    }

    #[test]
    fn exp_bool_yes_string() {
        assert!(exp_bool("transport", "smtp", "opt", false, Some("yes")).unwrap());
    }

    #[test]
    fn exp_bool_false_string() {
        assert!(!exp_bool("transport", "smtp", "opt", true, Some("false")).unwrap());
    }

    #[test]
    fn exp_bool_no_string() {
        assert!(!exp_bool("transport", "smtp", "opt", true, Some("no")).unwrap());
    }

    #[test]
    fn exp_bool_invalid_string() {
        assert!(exp_bool("transport", "smtp", "opt", true, Some("maybe")).is_err());
    }

    // ── expand_hide_passwords ───────────────────────────────────────

    #[test]
    fn hide_passwords_plain_message() {
        let msg = "some random error";
        assert_eq!(expand_hide_passwords(msg), msg);
    }

    #[test]
    fn hide_passwords_with_mysql() {
        let msg = "failed to expand mysql query with password";
        assert_eq!(expand_hide_passwords(msg), "Temporary internal error");
    }

    #[test]
    fn hide_passwords_with_pgsql() {
        let msg = "expansion of pgsql connection string";
        assert_eq!(expand_hide_passwords(msg), "Temporary internal error");
    }

    #[test]
    fn hide_passwords_expansion_without_db() {
        let msg = "failed to expand some option";
        assert_eq!(expand_hide_passwords(msg), msg);
    }

    #[test]
    fn hide_passwords_db_without_expansion_prefix() {
        let msg = "mysql connection failed";
        assert_eq!(expand_hide_passwords(msg), msg);
    }

    #[test]
    fn hide_passwords_ldaps() {
        let msg = "failed to expand ldaps://server query";
        assert_eq!(expand_hide_passwords(msg), "Temporary internal error");
    }

    // ── expand_file_big_buffer ──────────────────────────────────────

    #[test]
    fn expand_file_big_buffer_nonexistent() {
        let result = expand_file_big_buffer("/nonexistent/path/to/file");
        assert!(result.is_err());
    }

    #[test]
    fn expand_file_big_buffer_reads_file() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let path = dir.join("exim_expand_test_read.txt");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"hello from file").unwrap();
        }
        let result = expand_file_big_buffer(path.to_str().unwrap()).unwrap();
        assert_eq!(result, "hello from file");
        let _ = std::fs::remove_file(&path);
    }

    // ── vaguely_random_number ───────────────────────────────────────

    #[test]
    fn vaguely_random_number_within_range() {
        for _ in 0..100 {
            let v = vaguely_random_number(10);
            assert!((0..10).contains(&v));
        }
    }

    #[test]
    fn vaguely_random_number_zero_max() {
        assert_eq!(vaguely_random_number(0), 0);
    }

    #[test]
    fn vaguely_random_number_negative_max() {
        assert_eq!(vaguely_random_number(-5), 0);
    }

    #[test]
    fn vaguely_random_number_one() {
        // Only possible value is 0.
        assert_eq!(vaguely_random_number(1), 0);
    }

    // ── is_truthy ───────────────────────────────────────────────────

    #[test]
    fn is_truthy_accepts_nonzero() {
        assert!(is_truthy("1"));
        assert!(is_truthy("yes"));
        assert!(is_truthy("hello"));
    }

    #[test]
    fn is_truthy_rejects_falsy() {
        assert!(!is_truthy(""));
        assert!(!is_truthy("0"));
        assert!(!is_truthy("no"));
        assert!(!is_truthy("false"));
        assert!(!is_truthy("NO"));
        assert!(!is_truthy("FALSE"));
    }

    // ── Token re-export ─────────────────────────────────────────────

    #[test]
    fn token_reexport_accessible() {
        let _tok = Token::Eof;
        let _tok2 = Token::Literal("test".into());
        let _tok3 = Token::Dollar;
    }

    // ── AstNode re-export ───────────────────────────────────────────

    #[test]
    fn ast_node_reexport_accessible() {
        let _node = AstNode::Literal("text".into());
        let _seq = AstNode::Sequence(vec![]);
    }

    // ── Evaluator re-export ─────────────────────────────────────────

    #[test]
    fn evaluator_reexport_accessible() {
        let eval = Evaluator::new();
        assert_eq!(eval.expand_level, 0);
        assert_eq!(eval.expand_forbid, 0);
        assert!(!eval.forced_fail);
        assert!(!eval.search_find_defer);
    }

    // ── Taint type re-exports ───────────────────────────────────────

    #[test]
    fn taint_reexports_accessible() {
        let _t: Tainted<&str> = Tainted::new("data");
        let _c: Clean<&str> = Clean::new("safe");
    }
}
