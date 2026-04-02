// Copyright (c) The Exim Maintainers 2020 - 2025
// Copyright (c) University of Cambridge 1995 - 2018
// SPDX-License-Identifier: GPL-2.0-or-later

//! # ACL Verb Definitions and Evaluation Semantics
//!
//! This module defines the 7 ACL verbs and their evaluation semantics. It
//! translates the verb table, `msgcond[]` bitmap, verb name array, and per-verb
//! result handling logic from `src/src/acl.c`.
//!
//! ## Source Mapping (from `acl.c`)
//!
//! | C Source                  | Rust Equivalent                              |
//! |---------------------------|----------------------------------------------|
//! | Lines 26–29: ACL verb enum | [`AclVerb`] enum (7 variants, `#[repr(u8)]`) |
//! | Lines 33–41: `verbs[]`    | [`AclVerb::name()`]                          |
//! | Lines 48–56: `msgcond[]`  | [`AclVerb::message_condition_bits()`]        |
//! | Lines 1208–1283: `acl_warn()` | [`acl_warn()`]                           |
//! | Lines 4660–4758: dispatch | [`AclVerb::on_conditions_pass()`] and friends |
//!
//! ## Result Code Bitmap Constants
//!
//! The `BIT_*` constants represent bitmask positions for [`AclResult`] variants.
//! They are used in the `msgcond[]` bitmap to control which result codes trigger
//! `message=` and `log_message=` modifier expansion for each verb.
//!
//! [`AclResult`]: crate::AclResult

use std::fmt;
use std::str::FromStr;

use crate::phases::AclWhere;
use crate::{AclResult, MessageContext};

// =============================================================================
// BIT_* Constants — AclResult Bitmask Positions
// =============================================================================
//
// These constants are used in the msgcond[] bitmap (see message_condition_bits).
// Each constant represents a single bit position corresponding to an AclResult
// variant's discriminant value: BIT_X = 1 << (AclResult::X as u8).
//
// In C, these are expressed as BIT(OK), BIT(FAIL), etc., where BIT(n) = (1<<n).

/// Bitmask for [`AclResult::Ok`] (discriminant 0).
/// C equivalent: `BIT(OK)` where `OK = 0`.
pub const BIT_OK: u32 = 1 << (AclResult::Ok as u8);

/// Bitmask for [`AclResult::Defer`] (discriminant 1).
/// C equivalent: `BIT(DEFER)` where `DEFER = 1`.
pub const BIT_DEFER: u32 = 1 << (AclResult::Defer as u8);

/// Bitmask for [`AclResult::Fail`] (discriminant 2).
/// C equivalent: `BIT(FAIL)` where `FAIL = 2`.
pub const BIT_FAIL: u32 = 1 << (AclResult::Fail as u8);

/// Bitmask for [`AclResult::Discard`] (discriminant 3).
/// C equivalent: `BIT(DISCARD)` where `DISCARD = 3`.
pub const BIT_DISCARD: u32 = 1 << (AclResult::Discard as u8);

/// Bitmask for [`AclResult::Error`] (discriminant 4).
/// C equivalent: `BIT(ERROR)` where `ERROR = 4`.
pub const BIT_ERROR: u32 = 1 << (AclResult::Error as u8);

/// Bitmask for [`AclResult::FailDrop`] (discriminant 5).
/// C equivalent: `BIT(FAIL_DROP)` where `FAIL_DROP = 5`.
pub const BIT_FAIL_DROP: u32 = 1 << (AclResult::FailDrop as u8);

// =============================================================================
// Static Verb Array — All Verbs in Discriminant Order
// =============================================================================

/// All 7 ACL verbs in discriminant order, matching the C `verbs[]` array
/// index positions (acl.c lines 33–41).
static ALL_VERBS: &[AclVerb] = &[
    AclVerb::Accept,
    AclVerb::Defer,
    AclVerb::Deny,
    AclVerb::Discard,
    AclVerb::Drop,
    AclVerb::Require,
    AclVerb::Warn,
];

// =============================================================================
// AclVerb Enum — The 7 ACL Verbs
// =============================================================================

/// The 7 ACL verbs that can appear in ACL definitions.
///
/// Replaces the C positional constants `ACL_ACCEPT` through `ACL_WARN`
/// (acl.c lines 26–29). Each verb defines how the ACL evaluation engine
/// should interpret the result of its condition checks.
///
/// # Discriminant Values
///
/// The `#[repr(u8)]` attribute with explicit discriminant assignments ensures
/// stable values matching the C enum positions:
///
/// | Variant   | Value | C Constant    |
/// |-----------|-------|---------------|
/// | `Accept`  | 0     | `ACL_ACCEPT`  |
/// | `Defer`   | 1     | `ACL_DEFER`   |
/// | `Deny`    | 2     | `ACL_DENY`    |
/// | `Discard` | 3     | `ACL_DISCARD` |
/// | `Drop`    | 4     | `ACL_DROP`    |
/// | `Require` | 5     | `ACL_REQUIRE` |
/// | `Warn`    | 6     | `ACL_WARN`    |
///
/// # Verb Semantics Summary
///
/// | Verb      | On Conditions Pass     | On Conditions Fail (after endpass) |
/// |-----------|------------------------|------------------------------------|
/// | `Accept`  | Return OK (or DISCARD) | Return FAIL                        |
/// | `Defer`   | Return DEFER           | Skip to next verb                  |
/// | `Deny`    | Return FAIL            | Skip to next verb                  |
/// | `Discard` | Return DISCARD         | Return FAIL                        |
/// | `Drop`    | Return FAIL_DROP       | Skip to next verb                  |
/// | `Require` | Continue to next verb  | Return FAIL                        |
/// | `Warn`    | Call `acl_warn()`, continue | Skip to next verb              |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AclVerb {
    /// Accept the message/connection if all conditions pass.
    ///
    /// When conditions evaluate to OK, the ACL returns OK. If a nested ACL
    /// previously set the discard flag (cond == DISCARD), the result is
    /// propagated as DISCARD.
    ///
    /// After an `endpass` marker, condition failure causes the ACL to return
    /// FAIL instead of continuing to the next verb.
    Accept = 0,

    /// Temporarily reject if all conditions pass.
    ///
    /// Returns DEFER (4xx SMTP response) with an optional custom message.
    /// The `message=` modifier allows customizing the rejection text.
    Defer = 1,

    /// Permanently reject if all conditions pass.
    ///
    /// Returns FAIL (5xx SMTP response) with an optional custom message.
    /// The `message=` modifier allows customizing the rejection text.
    Deny = 2,

    /// Silently discard the message if all conditions pass.
    ///
    /// Returns DISCARD — the message is accepted from the sender's perspective
    /// but is not delivered to any recipient. After `endpass`, condition failure
    /// causes the ACL to return FAIL.
    Discard = 3,

    /// Permanently reject AND close the SMTP connection if all conditions pass.
    ///
    /// Returns FAIL_DROP — a 5xx response is sent and the connection is
    /// immediately closed. Used for serious policy violations.
    Drop = 4,

    /// All conditions must pass for ACL evaluation to continue.
    ///
    /// If any condition fails, the ACL returns FAIL. Unlike `accept` and
    /// `discard`, `require` does not need an `endpass` marker — it always
    /// terminates on condition failure.
    Require = 5,

    /// Execute side effects (headers, logging) if conditions pass, then continue.
    ///
    /// Never terminates ACL evaluation — always proceeds to the next verb.
    /// Side effects are handled by [`acl_warn()`]:
    /// - `log_message=` → write to main log (with per-connection deduplication)
    /// - `message=` → add as header (deprecated; use `add_header` instead)
    Warn = 6,
}

// =============================================================================
// AclVerb — Name Mapping and Parsing
// =============================================================================

impl AclVerb {
    /// Returns the verb name string matching the C `verbs[]` array
    /// (acl.c lines 33–41).
    ///
    /// # Log Format Compatibility
    ///
    /// These strings MUST match the C source exactly for log format
    /// compatibility per AAP §0.7.1. The C array contains lowercase ASCII
    /// strings used in debug output and error messages throughout `acl.c`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use exim_acl::verbs::AclVerb;
    /// assert_eq!(AclVerb::Accept.name(), "accept");
    /// assert_eq!(AclVerb::Warn.name(), "warn");
    /// ```
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Defer => "defer",
            Self::Deny => "deny",
            Self::Discard => "discard",
            Self::Drop => "drop",
            Self::Require => "require",
            Self::Warn => "warn",
        }
    }

    /// Parses a verb name string into an [`AclVerb`] variant.
    ///
    /// Performs **case-insensitive** matching against all 7 verb names.
    /// Returns `None` if the name does not match any known verb.
    ///
    /// This mirrors the C code's linear search through the `verbs[]` array
    /// during ACL parsing in `acl_read()`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use exim_acl::verbs::AclVerb;
    /// assert_eq!(AclVerb::from_name("accept"), Some(AclVerb::Accept));
    /// assert_eq!(AclVerb::from_name("DENY"), Some(AclVerb::Deny));
    /// assert_eq!(AclVerb::from_name("Accept"), Some(AclVerb::Accept));
    /// assert_eq!(AclVerb::from_name("unknown"), None);
    /// ```
    pub fn from_name(name: &str) -> Option<AclVerb> {
        // Linear search with case-insensitive comparison, matching the C
        // code's approach of iterating through the verbs[] array.
        ALL_VERBS
            .iter()
            .find(|verb| verb.name().eq_ignore_ascii_case(name))
            .copied()
    }
}

// =============================================================================
// Display Trait — Log-Compatible String Representation
// =============================================================================

impl fmt::Display for AclVerb {
    /// Formats the verb as its lowercase name string.
    ///
    /// Delegates to [`AclVerb::name()`] to ensure log format compatibility
    /// with C Exim's `verbs[]` array (AAP §0.7.1).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// =============================================================================
// FromStr Trait — Configuration File Parsing
// =============================================================================

impl FromStr for AclVerb {
    type Err = AclVerbParseError;

    /// Parses a verb name from configuration text.
    ///
    /// Delegates to [`AclVerb::from_name()`] for case-insensitive matching.
    /// Returns an error if the string does not match any known verb.
    ///
    /// # Examples
    ///
    /// ```
    /// # use exim_acl::verbs::AclVerb;
    /// let verb: AclVerb = "accept".parse().unwrap();
    /// assert_eq!(verb, AclVerb::Accept);
    ///
    /// let result: Result<AclVerb, _> = "invalid".parse();
    /// assert!(result.is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        AclVerb::from_name(s).ok_or_else(|| AclVerbParseError { name: s.to_owned() })
    }
}

/// Error returned when parsing an invalid ACL verb name.
///
/// Contains the invalid name string for diagnostic purposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclVerbParseError {
    /// The invalid verb name that was encountered.
    pub name: String,
}

impl fmt::Display for AclVerbParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown ACL verb: '{}'", self.name)
    }
}

impl std::error::Error for AclVerbParseError {}

// =============================================================================
// AclVerb — Message Condition Bitmap (msgcond[])
// =============================================================================

impl AclVerb {
    /// Returns the bitmap of result codes that trigger `message=` and
    /// `log_message=` modifier expansion for this verb.
    ///
    /// Replaces the C `msgcond[]` array (acl.c lines 48–56). The bitmap uses
    /// [`AclResult`] variant discriminants as bit positions. A set bit means:
    /// if the condition evaluation returns that result code, then the `message=`
    /// and `log_message=` modifiers should be string-expanded.
    ///
    /// # C Source Values
    ///
    /// ```c
    /// static int msgcond[] = {
    ///   [ACL_ACCEPT]  = BIT(OK) | BIT(FAIL) | BIT(FAIL_DROP),
    ///   [ACL_DEFER]   = BIT(OK),
    ///   [ACL_DENY]    = BIT(OK),
    ///   [ACL_DISCARD] = BIT(OK) | BIT(FAIL) | BIT(FAIL_DROP),
    ///   [ACL_DROP]    = BIT(OK),
    ///   [ACL_REQUIRE] = BIT(FAIL) | BIT(FAIL_DROP),
    ///   [ACL_WARN]    = BIT(OK)
    /// };
    /// ```
    ///
    /// # Notes
    ///
    /// - `Accept` and `Discard` expand messages on OK, FAIL, and FAIL_DROP
    ///   because after `endpass`, their failure path produces FAIL or FAIL_DROP
    ///   results that need custom messages.
    /// - `Require` expands only on FAIL and FAIL_DROP (not OK) because OK means
    ///   conditions passed and no message is needed.
    /// - `Defer`, `Deny`, `Drop`, and `Warn` expand only on OK because that is
    ///   when these verbs trigger their respective actions.
    pub const fn message_condition_bits(&self) -> u32 {
        match self {
            Self::Accept => BIT_OK | BIT_FAIL | BIT_FAIL_DROP,
            Self::Defer => BIT_OK,
            Self::Deny => BIT_OK,
            Self::Discard => BIT_OK | BIT_FAIL | BIT_FAIL_DROP,
            Self::Drop => BIT_OK,
            Self::Require => BIT_FAIL | BIT_FAIL_DROP,
            Self::Warn => BIT_OK,
        }
    }
}

// =============================================================================
// AclVerb — Per-Verb Result Semantics
// =============================================================================

impl AclVerb {
    /// Determines the ACL return value when this verb's conditions all pass
    /// (condition evaluation result = OK or DISCARD).
    ///
    /// This encodes the per-verb semantics from `acl_check_internal()`
    /// (acl.c lines 4660–4758). The `discard_flag` parameter indicates whether
    /// a nested ACL returned DISCARD, which propagates through `accept` verbs.
    ///
    /// # Per-Verb Behavior
    ///
    /// | Verb      | `discard_flag=false` | `discard_flag=true` |
    /// |-----------|----------------------|---------------------|
    /// | Accept    | `Ok`                 | `Discard`           |
    /// | Defer     | `Defer`              | `Defer`             |
    /// | Deny      | `Fail`               | `Fail`              |
    /// | Discard   | `Discard`            | `Discard`           |
    /// | Drop      | `FailDrop`           | `FailDrop`          |
    /// | Require   | `Ok`                 | `Ok`                |
    /// | Warn      | `Ok`                 | `Ok`                |
    ///
    /// # C Source Reference
    ///
    /// - `ACL_ACCEPT`: returns `cond` directly (OK or DISCARD from nested ACL)
    /// - `ACL_DEFER`: returns `DEFER` (acl.c line 4685)
    /// - `ACL_DENY`: returns `FAIL` (acl.c line 4694)
    /// - `ACL_DISCARD`: returns `DISCARD` always (acl.c line 4703)
    /// - `ACL_DROP`: returns `FAIL_DROP` (acl.c line 4718)
    /// - `ACL_REQUIRE`: continues (break) on success
    /// - `ACL_WARN`: calls `acl_warn()` then continues
    pub const fn on_conditions_pass(&self, discard_flag: bool) -> AclResult {
        match self {
            Self::Accept => {
                if discard_flag {
                    AclResult::Discard
                } else {
                    AclResult::Ok
                }
            }
            Self::Defer => AclResult::Defer,
            Self::Deny => AclResult::Fail,
            Self::Discard => AclResult::Discard,
            Self::Drop => AclResult::FailDrop,
            // Require: conditions passed, continue evaluating next verb
            Self::Require => AclResult::Ok,
            // Warn: side effects handled separately, continue evaluating
            Self::Warn => AclResult::Ok,
        }
    }

    /// Determines the ACL return value when conditions fail (condition returned
    /// FAIL) and we are past the `endpass` marker.
    ///
    /// The `endpass` marker changes the behavior of `accept` and `discard`
    /// verbs: without endpass, condition failure simply skips to the next verb;
    /// with endpass, condition failure terminates the ACL with FAIL.
    ///
    /// For `require`, condition failure **always** terminates (no endpass needed).
    ///
    /// # Return Values
    ///
    /// | Verb      | Result                                        |
    /// |-----------|-----------------------------------------------|
    /// | Accept    | `Fail` — deny access after endpass             |
    /// | Discard   | `Fail` — deny access after endpass             |
    /// | Require   | `Fail` — always fails on condition failure     |
    /// | Defer     | `Ok` — skip to next verb                       |
    /// | Deny      | `Ok` — skip to next verb                       |
    /// | Drop      | `Ok` — skip to next verb                       |
    /// | Warn      | `Ok` — skip to next verb                       |
    ///
    /// # C Source Reference
    ///
    /// - `ACL_ACCEPT` with `endpass_seen`: returns `cond` (acl.c lines 4672–4676)
    /// - `ACL_DISCARD` with `endpass_seen`: returns `cond` (acl.c lines 4705–4710)
    /// - `ACL_REQUIRE`: returns `cond` always (acl.c lines 4722–4728)
    pub const fn on_conditions_fail_after_endpass(&self) -> AclResult {
        match self {
            Self::Accept => AclResult::Fail,
            Self::Discard => AclResult::Fail,
            Self::Require => AclResult::Fail,
            Self::Defer => AclResult::Ok,
            Self::Deny => AclResult::Ok,
            Self::Drop => AclResult::Ok,
            Self::Warn => AclResult::Ok,
        }
    }

    /// Whether this verb terminates ACL evaluation when conditions pass.
    ///
    /// Most verbs terminate ACL evaluation when their conditions are
    /// satisfied:
    /// - `Accept` → returns OK (accept the message)
    /// - `Deny` → returns FAIL (deny the message)
    /// - `Defer` → returns DEFER (temporary failure)
    /// - `Discard` → returns DISCARD (silently discard)
    /// - `Drop` → returns FAIL_DROP (deny + drop connection)
    ///
    /// Two verbs do **not** terminate on success:
    /// - `Warn` → executes side effects (logging, header addition) and
    ///   continues to the next verb.
    /// - `Require` → a passing `require` is a gate: the condition was
    ///   satisfied, so continue evaluating subsequent verbs.  Only condition
    ///   **failure** terminates a `require` (with FAIL).  This matches C
    ///   Exim's `ACL_REQUIRE` case which just does `break` from the switch
    ///   on success (acl.c ~line 4719).
    pub const fn terminates_on_pass(&self) -> bool {
        !matches!(self, Self::Warn | Self::Require)
    }

    /// Whether this verb terminates ACL evaluation when conditions fail
    /// and the `endpass` marker has been seen.
    ///
    /// - `Accept` and `Discard`: terminate on failure only after `endpass`
    /// - `Require`: always terminates on failure (regardless of endpass)
    /// - All others: never terminate on failure (they just skip to next verb)
    ///
    /// # C Source Reference
    ///
    /// In C, the `endpass_seen` flag gates this behavior for `accept` and
    /// `discard` (acl.c lines 4672, 4705). `require` always returns on
    /// failure (line 4723).
    pub const fn terminates_on_fail_after_endpass(&self) -> bool {
        matches!(self, Self::Accept | Self::Discard | Self::Require)
    }
}

// =============================================================================
// AclVerb — Count, Iteration, and Index Conversion
// =============================================================================

impl AclVerb {
    /// Returns the total number of ACL verb types (always 7).
    ///
    /// This matches the size of the C `verbs[]` array and is useful for
    /// bounds checking when working with verb-indexed arrays.
    pub const fn count() -> usize {
        7
    }

    /// Returns a static slice of all 7 ACL verbs in discriminant order.
    ///
    /// The ordering matches the C `verbs[]` array: accept, defer, deny,
    /// discard, drop, require, warn.
    ///
    /// # Examples
    ///
    /// ```
    /// # use exim_acl::verbs::AclVerb;
    /// let all = AclVerb::all();
    /// assert_eq!(all.len(), 7);
    /// assert_eq!(all[0], AclVerb::Accept);
    /// assert_eq!(all[6], AclVerb::Warn);
    /// ```
    pub const fn all() -> &'static [AclVerb] {
        ALL_VERBS
    }

    /// Converts a `u8` discriminant index to an [`AclVerb`] variant.
    ///
    /// Returns `None` if the index is out of range (≥ 7).
    ///
    /// # Examples
    ///
    /// ```
    /// # use exim_acl::verbs::AclVerb;
    /// assert_eq!(AclVerb::from_index(0), Some(AclVerb::Accept));
    /// assert_eq!(AclVerb::from_index(6), Some(AclVerb::Warn));
    /// assert_eq!(AclVerb::from_index(7), None);
    /// assert_eq!(AclVerb::from_index(255), None);
    /// ```
    pub const fn from_index(index: u8) -> Option<AclVerb> {
        match index {
            0 => Some(Self::Accept),
            1 => Some(Self::Defer),
            2 => Some(Self::Deny),
            3 => Some(Self::Discard),
            4 => Some(Self::Drop),
            5 => Some(Self::Require),
            6 => Some(Self::Warn),
            _ => None,
        }
    }
}

// =============================================================================
// acl_warn() — Warn Verb Side Effects
// =============================================================================

/// Handle side effects for the `warn` verb when conditions pass.
///
/// Replaces the C `acl_warn()` function (acl.c lines 1227–1283). This function
/// is called by the ACL evaluation engine when a `warn` verb's conditions
/// evaluate to OK.
///
/// # Side Effects
///
/// 1. **Log message** (`log_msg` parameter): If present (and different from
///    `user_msg`), the message is written to the main log with per-connection
///    deduplication. The same log message will not be repeated within the same
///    SMTP connection. Format: `"{host_ident} Warning: {log_msg}"`.
///
/// 2. **User message** (`user_msg` parameter): If present, treated as a header
///    line to add to the message. This is a **deprecated feature** — the
///    `add_header` modifier should be used instead. If the string does not
///    look like a valid header (missing `:`), it is prefixed with
///    `"X-ACL-Warn: "`.
///
/// # Phase Restriction
///
/// User messages (header additions) are only allowed in message-phase ACLs
/// (phases with discriminant ≤ `AclWhere::NotSmtp`). If a user message is
/// provided in a non-message ACL, a warning is logged and the message is
/// ignored.
///
/// # Arguments
///
/// * `ctx` — Mutable message context for header and log state
/// * `user_msg` — Optional message text (deprecated header addition via `message=`)
/// * `log_msg` — Optional log message text (via `log_message=`)
/// * `where_phase` — The ACL phase where the warn verb is executing
///
/// # C Source Reference
///
/// The C function accesses these globals:
/// - `host_and_ident(TRUE)` → `ctx.host_and_ident`
/// - `acl_warn_logged` → `ctx.acl_warn_logged`
/// - `acl_added_headers` via `setup_header()` → `ctx.acl_added_headers`
/// - `acl_wherenames[where]` → `where_phase.name()`
pub fn acl_warn(
    ctx: &mut MessageContext,
    user_msg: Option<&str>,
    log_msg: Option<&str>,
    where_phase: AclWhere,
) {
    // --- Part 1: Handle log_message (acl.c lines 1230–1262) ---
    //
    // Log the message to the main log with per-connection deduplication.
    // In C, deduplication uses a malloc'd linked list (acl_warn_logged).
    // In Rust, we use a HashSet for O(1) lookup.
    if let Some(log_text) = log_msg {
        // Only process if log_msg is different from user_msg (matching C check
        // at line 1230: `if (log_message && log_message != user_message)`)
        let should_log = match user_msg {
            Some(user_text) => !std::ptr::eq(log_text, user_text) && log_text != user_text,
            None => true,
        };

        if should_log {
            // Format the log message with host identification, matching C:
            // `text = string_sprintf("%s Warning: %s", host_and_ident(TRUE),
            //     string_printing(log_message));`
            let formatted = format!("{} Warning: {}", ctx.host_and_ident, log_text);

            // Per-connection deduplication: check if this exact formatted
            // message has already been logged during this connection.
            // C uses a linear search through acl_warn_logged linked list
            // (acl.c lines 1249–1250).
            if !ctx.acl_warn_logged.contains(&formatted) {
                // Log the warning using the tracing framework, replacing
                // C `log_write(0, LOG_MAIN, "%s", text)` (line 1255).
                tracing::warn!("{}", formatted);

                // Record this message to prevent duplicate logging within
                // the same connection (acl.c lines 1256–1261).
                ctx.acl_warn_logged.insert(formatted);
            }
        }
    }

    // --- Part 2: Handle user_message (acl.c lines 1264–1283) ---
    //
    // The "message" modifier on a warn verb is a deprecated way to add headers.
    // The modern approach is the "add_header" modifier.
    if let Some(user_text) = user_msg {
        // Check if we are in a message-phase ACL where headers can be added.
        // In C: `if (where > ACL_WHERE_NOTSMTP)` (line 1271).
        // Phases with discriminant > NotSmtp are non-message phases.
        if (where_phase as u8) > (AclWhere::NotSmtp as u8) {
            // Cannot add headers in a non-message ACL. Log a warning.
            // C: log_write(0, LOG_MAIN|LOG_PANIC, ...) (lines 1273-1276).
            tracing::warn!(
                "ACL \"warn\" with \"message\" setting found in a non-message \
                 ({}) ACL: cannot specify header lines here: message ignored",
                where_phase.name()
            );
            return;
        }

        // The user_message text should be treated as a header line to add.
        // This mirrors the C `setup_header(user_message)` call at line 1282.
        //
        // Header validation: if the text doesn't contain a colon (which
        // separates header name from value), prepend "X-ACL-Warn: " to
        // make it a valid header.
        let header_line = if user_text.contains(':') {
            // Text looks like a valid header (has name: value format).
            // Use it as-is, trimming any trailing whitespace/newlines.
            user_text.trim_end().to_owned()
        } else {
            // Text doesn't look like a header — prepend the default header name.
            // This matches the behavior of C's `setup_header()` which prepends
            // "X-ACL-Warn: " for non-header-formatted text.
            format!("X-ACL-Warn: {}", user_text.trim_end())
        };

        tracing::debug!("ACL warn: adding header \"{}\"", header_line);

        // Add the header to the message context's added-headers list.
        // In C, this goes through setup_header() into acl_added_headers.
        ctx.acl_added_headers.push(header_line);
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Enum Basics ──────────────────────────────────────────────────────

    #[test]
    fn test_verb_discriminant_values() {
        assert_eq!(AclVerb::Accept as u8, 0);
        assert_eq!(AclVerb::Defer as u8, 1);
        assert_eq!(AclVerb::Deny as u8, 2);
        assert_eq!(AclVerb::Discard as u8, 3);
        assert_eq!(AclVerb::Drop as u8, 4);
        assert_eq!(AclVerb::Require as u8, 5);
        assert_eq!(AclVerb::Warn as u8, 6);
    }

    #[test]
    fn test_verb_count() {
        assert_eq!(AclVerb::count(), 7);
    }

    #[test]
    fn test_all_verbs() {
        let all = AclVerb::all();
        assert_eq!(all.len(), 7);
        assert_eq!(all[0], AclVerb::Accept);
        assert_eq!(all[1], AclVerb::Defer);
        assert_eq!(all[2], AclVerb::Deny);
        assert_eq!(all[3], AclVerb::Discard);
        assert_eq!(all[4], AclVerb::Drop);
        assert_eq!(all[5], AclVerb::Require);
        assert_eq!(all[6], AclVerb::Warn);
    }

    // ── Name Mapping ─────────────────────────────────────────────────────

    #[test]
    fn test_verb_names_match_c_array() {
        // These must match the C verbs[] array exactly (acl.c lines 33-41)
        assert_eq!(AclVerb::Accept.name(), "accept");
        assert_eq!(AclVerb::Defer.name(), "defer");
        assert_eq!(AclVerb::Deny.name(), "deny");
        assert_eq!(AclVerb::Discard.name(), "discard");
        assert_eq!(AclVerb::Drop.name(), "drop");
        assert_eq!(AclVerb::Require.name(), "require");
        assert_eq!(AclVerb::Warn.name(), "warn");
    }

    #[test]
    fn test_from_name_exact() {
        assert_eq!(AclVerb::from_name("accept"), Some(AclVerb::Accept));
        assert_eq!(AclVerb::from_name("defer"), Some(AclVerb::Defer));
        assert_eq!(AclVerb::from_name("deny"), Some(AclVerb::Deny));
        assert_eq!(AclVerb::from_name("discard"), Some(AclVerb::Discard));
        assert_eq!(AclVerb::from_name("drop"), Some(AclVerb::Drop));
        assert_eq!(AclVerb::from_name("require"), Some(AclVerb::Require));
        assert_eq!(AclVerb::from_name("warn"), Some(AclVerb::Warn));
    }

    #[test]
    fn test_from_name_case_insensitive() {
        assert_eq!(AclVerb::from_name("ACCEPT"), Some(AclVerb::Accept));
        assert_eq!(AclVerb::from_name("Deny"), Some(AclVerb::Deny));
        assert_eq!(AclVerb::from_name("WARN"), Some(AclVerb::Warn));
        assert_eq!(AclVerb::from_name("dEfEr"), Some(AclVerb::Defer));
    }

    #[test]
    fn test_from_name_invalid() {
        assert_eq!(AclVerb::from_name(""), None);
        assert_eq!(AclVerb::from_name("unknown"), None);
        assert_eq!(AclVerb::from_name("ACCEPT "), None);
        assert_eq!(AclVerb::from_name("acc"), None);
    }

    // ── Display and FromStr ──────────────────────────────────────────────

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", AclVerb::Accept), "accept");
        assert_eq!(format!("{}", AclVerb::Drop), "drop");
        assert_eq!(format!("{}", AclVerb::Warn), "warn");
    }

    #[test]
    fn test_from_str() {
        let verb: AclVerb = "accept".parse().unwrap();
        assert_eq!(verb, AclVerb::Accept);

        let verb: AclVerb = "WARN".parse().unwrap();
        assert_eq!(verb, AclVerb::Warn);

        let result: Result<AclVerb, _> = "invalid".parse();
        assert!(result.is_err());
    }

    // ── Index Conversion ─────────────────────────────────────────────────

    #[test]
    fn test_from_index_valid() {
        for (i, expected) in AclVerb::all().iter().enumerate() {
            assert_eq!(
                AclVerb::from_index(i as u8),
                Some(*expected),
                "from_index({}) should return {:?}",
                i,
                expected
            );
        }
    }

    #[test]
    fn test_from_index_invalid() {
        assert_eq!(AclVerb::from_index(7), None);
        assert_eq!(AclVerb::from_index(100), None);
        assert_eq!(AclVerb::from_index(255), None);
    }

    // ── Message Condition Bitmap ─────────────────────────────────────────

    #[test]
    fn test_message_condition_bits_match_c_msgcond() {
        // Must match C msgcond[] array (acl.c lines 48-56) exactly.
        assert_eq!(
            AclVerb::Accept.message_condition_bits(),
            BIT_OK | BIT_FAIL | BIT_FAIL_DROP
        );
        assert_eq!(AclVerb::Defer.message_condition_bits(), BIT_OK);
        assert_eq!(AclVerb::Deny.message_condition_bits(), BIT_OK);
        assert_eq!(
            AclVerb::Discard.message_condition_bits(),
            BIT_OK | BIT_FAIL | BIT_FAIL_DROP
        );
        assert_eq!(AclVerb::Drop.message_condition_bits(), BIT_OK);
        assert_eq!(
            AclVerb::Require.message_condition_bits(),
            BIT_FAIL | BIT_FAIL_DROP
        );
        assert_eq!(AclVerb::Warn.message_condition_bits(), BIT_OK);
    }

    #[test]
    fn test_bit_constants() {
        assert_eq!(BIT_OK, 1); // 1 << 0
        assert_eq!(BIT_DEFER, 2); // 1 << 1
        assert_eq!(BIT_FAIL, 4); // 1 << 2
        assert_eq!(BIT_DISCARD, 8); // 1 << 3
        assert_eq!(BIT_ERROR, 16); // 1 << 4
        assert_eq!(BIT_FAIL_DROP, 32); // 1 << 5
    }

    // ── Per-Verb Result Semantics ────────────────────────────────────────

    #[test]
    fn test_on_conditions_pass_without_discard_flag() {
        assert_eq!(AclVerb::Accept.on_conditions_pass(false), AclResult::Ok);
        assert_eq!(AclVerb::Defer.on_conditions_pass(false), AclResult::Defer);
        assert_eq!(AclVerb::Deny.on_conditions_pass(false), AclResult::Fail);
        assert_eq!(
            AclVerb::Discard.on_conditions_pass(false),
            AclResult::Discard
        );
        assert_eq!(AclVerb::Drop.on_conditions_pass(false), AclResult::FailDrop);
        assert_eq!(AclVerb::Require.on_conditions_pass(false), AclResult::Ok);
        assert_eq!(AclVerb::Warn.on_conditions_pass(false), AclResult::Ok);
    }

    #[test]
    fn test_on_conditions_pass_with_discard_flag() {
        // Only Accept is affected by the discard flag
        assert_eq!(AclVerb::Accept.on_conditions_pass(true), AclResult::Discard);
        // All others remain the same
        assert_eq!(AclVerb::Defer.on_conditions_pass(true), AclResult::Defer);
        assert_eq!(AclVerb::Deny.on_conditions_pass(true), AclResult::Fail);
        assert_eq!(
            AclVerb::Discard.on_conditions_pass(true),
            AclResult::Discard
        );
        assert_eq!(AclVerb::Drop.on_conditions_pass(true), AclResult::FailDrop);
    }

    #[test]
    fn test_on_conditions_fail_after_endpass() {
        // Accept, Discard, and Require return Fail
        assert_eq!(
            AclVerb::Accept.on_conditions_fail_after_endpass(),
            AclResult::Fail
        );
        assert_eq!(
            AclVerb::Discard.on_conditions_fail_after_endpass(),
            AclResult::Fail
        );
        assert_eq!(
            AclVerb::Require.on_conditions_fail_after_endpass(),
            AclResult::Fail
        );
        // Others return Ok (skip to next verb)
        assert_eq!(
            AclVerb::Defer.on_conditions_fail_after_endpass(),
            AclResult::Ok
        );
        assert_eq!(
            AclVerb::Deny.on_conditions_fail_after_endpass(),
            AclResult::Ok
        );
        assert_eq!(
            AclVerb::Drop.on_conditions_fail_after_endpass(),
            AclResult::Ok
        );
        assert_eq!(
            AclVerb::Warn.on_conditions_fail_after_endpass(),
            AclResult::Ok
        );
    }

    #[test]
    fn test_terminates_on_pass() {
        // All verbs except Warn terminate on pass
        assert!(AclVerb::Accept.terminates_on_pass());
        assert!(AclVerb::Defer.terminates_on_pass());
        assert!(AclVerb::Deny.terminates_on_pass());
        assert!(AclVerb::Discard.terminates_on_pass());
        assert!(AclVerb::Drop.terminates_on_pass());
        // Require does NOT terminate on pass — it continues to the
        // next statement (C Exim: require only terminates on FAIL).
        assert!(!AclVerb::Require.terminates_on_pass());
        assert!(!AclVerb::Warn.terminates_on_pass());
    }

    #[test]
    fn test_terminates_on_fail_after_endpass() {
        // Accept, Discard, and Require terminate on fail after endpass
        assert!(AclVerb::Accept.terminates_on_fail_after_endpass());
        assert!(AclVerb::Discard.terminates_on_fail_after_endpass());
        assert!(AclVerb::Require.terminates_on_fail_after_endpass());
        // Others do not
        assert!(!AclVerb::Defer.terminates_on_fail_after_endpass());
        assert!(!AclVerb::Deny.terminates_on_fail_after_endpass());
        assert!(!AclVerb::Drop.terminates_on_fail_after_endpass());
        assert!(!AclVerb::Warn.terminates_on_fail_after_endpass());
    }

    // ── acl_warn() ───────────────────────────────────────────────────────

    #[test]
    fn test_acl_warn_log_message_basic() {
        let mut ctx = MessageContext::default();
        ctx.host_and_ident = "[127.0.0.1]".to_owned();

        acl_warn(&mut ctx, None, Some("test warning"), AclWhere::Rcpt);

        // Should be recorded in the dedup set
        assert!(ctx
            .acl_warn_logged
            .contains("[127.0.0.1] Warning: test warning"));
    }

    #[test]
    fn test_acl_warn_log_message_dedup() {
        let mut ctx = MessageContext::default();
        ctx.host_and_ident = "[127.0.0.1]".to_owned();

        // Log the same message twice
        acl_warn(&mut ctx, None, Some("dup msg"), AclWhere::Rcpt);
        acl_warn(&mut ctx, None, Some("dup msg"), AclWhere::Rcpt);

        // Should only be recorded once
        assert_eq!(ctx.acl_warn_logged.len(), 1);
    }

    #[test]
    fn test_acl_warn_user_message_header_with_colon() {
        let mut ctx = MessageContext::default();

        acl_warn(&mut ctx, Some("X-Custom: value"), None, AclWhere::Rcpt);

        assert_eq!(ctx.acl_added_headers.len(), 1);
        assert_eq!(ctx.acl_added_headers[0], "X-Custom: value");
    }

    #[test]
    fn test_acl_warn_user_message_no_colon() {
        let mut ctx = MessageContext::default();

        acl_warn(&mut ctx, Some("just some text"), None, AclWhere::Rcpt);

        assert_eq!(ctx.acl_added_headers.len(), 1);
        assert_eq!(ctx.acl_added_headers[0], "X-ACL-Warn: just some text");
    }

    #[test]
    fn test_acl_warn_user_message_non_message_phase() {
        let mut ctx = MessageContext::default();

        // Connect phase is after NotSmtp in discriminant order, so it's
        // a non-message phase where headers cannot be added.
        acl_warn(&mut ctx, Some("X-Header: value"), None, AclWhere::Connect);

        // No header should be added in a non-message phase
        assert!(ctx.acl_added_headers.is_empty());
    }

    #[test]
    fn test_acl_warn_both_messages() {
        let mut ctx = MessageContext::default();
        ctx.host_and_ident = "H=test [10.0.0.1]".to_owned();

        acl_warn(
            &mut ctx,
            Some("X-Warn: suspicious"),
            Some("sender looks suspicious"),
            AclWhere::Data,
        );

        // Log message should be recorded
        assert!(ctx
            .acl_warn_logged
            .contains("H=test [10.0.0.1] Warning: sender looks suspicious"));

        // Header should be added
        assert_eq!(ctx.acl_added_headers.len(), 1);
        assert_eq!(ctx.acl_added_headers[0], "X-Warn: suspicious");
    }

    // ── Roundtrip ────────────────────────────────────────────────────────

    #[test]
    fn test_name_from_name_roundtrip() {
        for verb in AclVerb::all() {
            let name = verb.name();
            let parsed = AclVerb::from_name(name);
            assert_eq!(parsed, Some(*verb), "roundtrip failed for {:?}", verb);
        }
    }

    #[test]
    fn test_index_from_index_roundtrip() {
        for verb in AclVerb::all() {
            let idx = *verb as u8;
            let parsed = AclVerb::from_index(idx);
            assert_eq!(parsed, Some(*verb), "roundtrip failed for {:?}", verb);
        }
    }
}
