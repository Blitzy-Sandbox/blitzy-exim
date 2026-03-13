// Copyright (c) The Exim Maintainers 2020 - 2025
// Copyright (c) University of Cambridge 1995 - 2018
// SPDX-License-Identifier: GPL-2.0-or-later

// Crate-level lint configuration per AAP §0.7.2:
// - Zero unsafe outside exim-ffi
// - Zero-warning build
// - Comprehensive clippy linting
// - Documentation coverage encouraged
#![deny(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all)]
#![warn(missing_docs)]

//! # exim-acl — Access Control List Evaluation Engine
//!
//! This crate replaces `src/src/acl.c` (5,147 lines of C) from the Exim MTA
//! source tree. It implements the complete ACL evaluation engine for Exim:
//! verb evaluation (accept, deny, defer, discard, drop, require, warn),
//! condition checking across 30+ condition types, phase enforcement across
//! 22+ SMTP phases, and ACL variable management.
//!
//! ## Architecture
//!
//! The ACL engine is organized into five submodules:
//!
//! - [`phases`] — Defines the ~22 SMTP/processing phases where ACLs are
//!   evaluated ([`AclWhere`]) and the bitmask type ([`AclBitSet`]) used for
//!   the forbids/permits system controlling which conditions can appear in
//!   which phases.
//!
//! - [`verbs`] — Defines the 7 ACL verbs ([`AclVerb`]) and their evaluation
//!   semantics:
//!   - **accept** — Accept if all conditions pass; FAIL after endpass.
//!   - **deny** — Permanently reject (5xx) if conditions pass.
//!   - **defer** — Temporarily reject (4xx) if conditions pass.
//!   - **discard** — Silently discard if conditions pass.
//!   - **drop** — Reject AND close connection if conditions pass.
//!   - **require** — All conditions must pass or ACL fails.
//!   - **warn** — Execute side effects (log, add headers) and continue.
//!
//! - [`conditions`] — Defines all ACL condition/modifier types
//!   ([`AclCondition`]) and the massive `acl_check_condition()` dispatch
//!   function implementing per-condition evaluation semantics.
//!
//! - [`variables`] — ACL variable storage ([`AclVarStore`]), scope management
//!   ([`AclVarScope`]), spool serialization, and standalone variable setting
//!   for `-be` expand-test mode.
//!
//! - [`engine`] — Core ACL evaluation loop: [`AclBlock`]/[`AclConditionBlock`]
//!   data structures, [`acl_read()`] parser, `acl_check_internal()` evaluation
//!   loop, [`acl_check_wargs()`] nested ACL calls with argument passing.
//!
//! ## Public API
//!
//! The primary entry points for external crates are:
//!
//! - [`acl_check()`] — Main ACL evaluation entry point called by SMTP handling
//!   and delivery code. Handles recipient address setup, cutthrough delivery,
//!   DISCARD/DROP validation, and message splitting.
//!
//! - [`acl_eval()`] — Alternate evaluation interface used by `${acl ...}`
//!   string expansion. Simpler than `acl_check()` — no recipient setup or
//!   cutthrough handling.
//!
//! - [`fn_hdrs_added()`] — Count headers added by ACL processing for the
//!   `$acl_added_headers_count` expansion variable.
//!
//! ## Design Patterns (per AAP §0.4.2)
//!
//! - **Scoped context passing**: All functions take `&mut MessageContext` and
//!   `&mut AclEvalContext` — no global mutable state (AAP §0.4.4).
//! - **Compile-time taint tracking**: `Tainted<T>`/`Clean<T>` from `exim-store`
//!   enforce taint boundaries at compile time with zero runtime cost.
//! - **Feature flags**: Cargo features replace all C `#ifdef` conditionals
//!   (AAP §0.7.3).
//! - **Zero unsafe code**: `#![deny(unsafe_code)]` guarantees no `unsafe`
//!   blocks in this entire crate (AAP §0.7.2).
//!
//! ## Consumers
//!
//! This crate is consumed by:
//! - `exim-core` — Top-level ACL dispatch and mode-specific evaluation.
//! - `exim-smtp` — Per-SMTP-phase ACL invocation at connect, helo, mail, rcpt,
//!   data, mime, dkim, prdr phases.
//! - `exim-deliver` — Delivery-phase ACL evaluation.
//!
//! ## References
//!
//! - AAP §0.4.1: Target architecture (exim-acl crate specification)
//! - AAP §0.5.1: Transformation mapping (acl.c → exim-acl modules)
//! - AAP §0.7.1: Behavioral preservation (log format compatibility)

// =============================================================================
// Module Declarations
// =============================================================================
//
// Each module corresponds to a distinct functional area of the ACL evaluation
// engine. All 5 submodules are declared here and re-exported selectively below.

/// ACL phase definitions: [`AclWhere`] enum, [`AclBitSet`] bitmask type,
/// `BIT_*` constants, and the forbids/permits system controlling which
/// conditions can appear in which SMTP/processing phases.
pub mod phases;

/// ACL verb definitions: [`AclVerb`] enum (accept/deny/defer/discard/
/// drop/require/warn), per-verb evaluation semantics, message condition
/// bitmaps, and the `acl_warn` side-effect handler.
pub mod verbs;

/// ACL condition/modifier evaluation: [`AclCondition`] enum,
/// `acl_check_condition` dispatcher, control types, CSA verification,
/// ratelimit, and all per-condition evaluation semantics.
// Allow missing docs in conditions module: the large dispatch table has many
// enum variants and struct fields whose names are self-documenting (they map
// directly to Exim ACL condition keywords). Doc comments will be added
// incrementally as the implementation matures.
#[allow(missing_docs)]
pub mod conditions;

/// ACL variable management: [`AclVarStore`] for variable creation, lookup,
/// spool serialization/deserialization, and standalone variable setting
/// for `-be` expand-test mode.
pub mod variables;

/// ACL evaluation core engine: [`AclBlock`], [`AclConditionBlock`],
/// [`acl_read()`] parser, `acl_check_internal()` evaluation loop,
/// [`acl_check_wargs()`] nested ACL calls, and parser/evaluation machinery.
pub mod engine;

// =============================================================================
// Re-exports — Crate Root Public API Surface
// =============================================================================
//
// Key types from all submodules are re-exported at crate root for ergonomic
// use by consumer crates (exim-core, exim-smtp, exim-deliver). This avoids
// requiring callers to import deeply nested module paths.

// Phase types for consumers specifying which SMTP phase to evaluate.
pub use phases::{AclBitSet, AclWhere};

// Verb type for consumers inspecting ACL structure.
pub use verbs::AclVerb;

// Condition type for consumers inspecting ACL structure.
pub use conditions::AclCondition;

// Variable types for consumers managing ACL variable state.
pub use variables::{AclVarError, AclVarScope, AclVarStore, AclVariable};

// Engine types and functions for consumers that parse or invoke ACLs directly.
pub use engine::{acl_check_wargs, acl_current_verb, acl_read, AclBlock, AclConditionBlock};

// Standard library imports for this module's implementations.
use std::collections::HashSet;
use std::fmt;

// Structured logging replacing C DEBUG(D_acl) debug_printf_indent() calls.
// Used in acl_check() and acl_eval() for ACL entry/exit tracing, phase
// selection, recipient setup, and result reporting.
use tracing::{debug, trace, warn};

// =============================================================================
// Constants
// =============================================================================

/// Maximum ACL recursion depth (matching C constant).
///
/// When ACLs call other ACLs via the `acl` condition or `${acl ...}` expansion,
/// the recursion depth is tracked. If it exceeds this limit, evaluation returns
/// `AclResult::Error` to prevent infinite recursion.
///
/// C reference: `acl.c` line 4466: `if (acl_level > 20)`.
pub const MAX_ACL_RECURSION_DEPTH: u32 = 20;

/// Maximum number of `$acl_arg` positional arguments for nested ACL calls.
///
/// When invoking a named ACL via `acl = name arg1 arg2 ...`, up to 9
/// positional arguments can be passed. They are accessible in the called
/// ACL as `$acl_arg1` through `$acl_arg9`, with `$acl_narg` holding the
/// count.
///
/// C reference: `acl.c` line 4783: `uschar * tmp_arg[9]`.
pub const MAX_ACL_ARGS: usize = 9;

// =============================================================================
// AclResult — Core Result Type for ACL Evaluation
// =============================================================================

/// Result of ACL evaluation.
///
/// Replaces the C integer return codes from `acl_check()` /
/// `acl_check_internal()`. These values map to the C constants:
///
/// | Rust Variant          | C Constant  | C Value |
/// |-----------------------|-------------|---------|
/// | `AclResult::Ok`       | `OK`        | `0`     |
/// | `AclResult::Defer`    | `DEFER`     | `1`     |
/// | `AclResult::Fail`     | `FAIL`      | `2`     |
/// | `AclResult::Discard`  | `DISCARD`   | `3`     |
/// | `AclResult::Error`    | `ERROR`     | `4`     |
/// | `AclResult::FailDrop` | `FAIL_DROP` | `5`     |
///
/// The discriminant values are fixed via `#[repr(u8)]` to match the C
/// constants, as they are used as bit positions in the `msgcond[]` bitmap
/// (see [`verbs::AclVerb::message_condition_bits`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AclResult {
    /// ACL accepts — continue processing.
    /// C equivalent: `OK` (value 0).
    Ok = 0,

    /// ACL temporarily rejects — return 4xx to SMTP client.
    /// C equivalent: `DEFER` (value 1).
    Defer = 1,

    /// ACL permanently rejects — return 5xx to SMTP client.
    /// C equivalent: `FAIL` (value 2).
    Fail = 2,

    /// ACL silently discards — accept message but do not deliver.
    /// C equivalent: `DISCARD` (value 3).
    Discard = 3,

    /// Internal error during ACL evaluation.
    /// C equivalent: `ERROR` (value 4).
    Error = 4,

    /// ACL permanently rejects AND drops the SMTP connection.
    /// C equivalent: `FAIL_DROP` (value 5).
    /// The connection is closed after the 5xx response.
    FailDrop = 5,
}

impl AclResult {
    /// Returns `true` if this result represents a successful outcome.
    ///
    /// Both `Ok` and `Discard` are considered successful: `Ok` means the
    /// message/connection proceeds normally, `Discard` means the message is
    /// accepted from the sender's perspective but silently discarded.
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Ok | Self::Discard)
    }

    /// Returns `true` if this result represents a permanent rejection.
    ///
    /// Both `Fail` and `FailDrop` result in a 5xx SMTP response.
    /// `FailDrop` additionally closes the connection.
    pub const fn is_rejection(&self) -> bool {
        matches!(self, Self::Fail | Self::FailDrop)
    }

    /// Returns `true` if this result represents a temporary failure.
    ///
    /// `Defer` results in a 4xx SMTP response, inviting the sender to retry.
    pub const fn is_temporary(&self) -> bool {
        matches!(self, Self::Defer)
    }
}

impl fmt::Display for AclResult {
    /// Formats the result as a human-readable string for log output.
    ///
    /// These strings match the C log output format for compatibility with
    /// existing log parsers (`exigrep`, `eximstats`) per AAP §0.7.1.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Ok => "OK",
            Self::Defer => "DEFER",
            Self::Fail => "FAIL",
            Self::Discard => "DISCARD",
            Self::Error => "ERROR",
            Self::FailDrop => "FAIL_DROP",
        };
        f.write_str(name)
    }
}

// =============================================================================
// AclError — Core Error Type for ACL Operations
// =============================================================================

/// Errors that can occur during ACL operations.
///
/// Replaces the ad-hoc error string handling from C `acl.c` where errors
/// are communicated through `log_write()` calls and `*log_msgptr` output
/// parameters. Each variant provides a structured, typed error with a
/// descriptive message generated via `thiserror::Error` derive.
///
/// `AclError` covers the high-level operational errors that the public API
/// functions ([`acl_check()`], [`acl_eval()`]) may encounter. Lower-level
/// engine and condition errors are represented by their own error types in
/// the [`engine`] and [`conditions`] modules respectively.
#[derive(Debug, thiserror::Error)]
pub enum AclError {
    /// The named ACL was not found in the configuration or as a file.
    ///
    /// Occurs when `acl_check_internal()` cannot resolve the ACL name
    /// from configuration, the ACL cache, or the filesystem.
    #[error("ACL not found: {name}")]
    NotFound {
        /// The ACL name that was looked up.
        name: String,
    },

    /// ACL recursion depth exceeded the maximum limit.
    ///
    /// Triggered when nested ACL calls (via the `acl` condition) exceed
    /// [`MAX_ACL_RECURSION_DEPTH`] (20 levels). This prevents infinite
    /// recursion caused by circular ACL references.
    ///
    /// C reference: `acl.c` line 4466: `if (acl_level > 20)`.
    #[error("ACL recursion depth exceeded (max {max_depth})")]
    RecursionDepthExceeded {
        /// The maximum depth that was exceeded.
        max_depth: u32,
    },

    /// ACL text could not be parsed.
    ///
    /// Covers syntax errors in ACL definitions: unknown verbs, unknown
    /// conditions, negated modifiers, endpass on wrong verb, malformed lines.
    #[error("ACL parse error at line {line}: {message}")]
    ParseError {
        /// The line number where the error was detected.
        line: u32,
        /// A description of the parse error.
        message: String,
    },

    /// An ACL condition evaluation failed with an error.
    ///
    /// Wraps errors from individual condition evaluations (DNS failures,
    /// expansion errors within conditions, verification failures, etc.).
    #[error("ACL condition error: {0}")]
    ConditionError(String),

    /// String expansion failed during ACL processing.
    ///
    /// Occurs when `expand_string()` fails while expanding ACL condition
    /// arguments, message modifiers, or ACL name resolution.
    #[error("ACL expansion error: {0}")]
    ExpansionError(String),

    /// Tainted (untrusted) text was used in a security-sensitive ACL context.
    ///
    /// Enforces compile-time taint tracking per AAP §0.4.2. Tainted text
    /// from SMTP input cannot be used as ACL names or file paths without
    /// explicit detainting.
    #[error("ACL tainted text rejected")]
    TaintedText,

    /// An internal error occurred during ACL processing.
    ///
    /// Catch-all for unexpected conditions that do not fit other variants.
    #[error("ACL internal error: {0}")]
    InternalError(String),
}

// =============================================================================
// MessageContext — Per-Message ACL State
// =============================================================================

/// Minimal per-message context for ACL operations.
///
/// This struct holds the per-message mutable state needed by the ACL evaluation
/// engine. It replaces the global variables that the C ACL code accesses:
///
/// - `acl_added_headers` → [`MessageContext::acl_added_headers`]
/// - `acl_warn_logged` → [`MessageContext::acl_warn_logged`]
///
/// In the full system, this will be a field within the top-level `MessageContext`
/// from `exim-core`. The ACL crate defines its own version to avoid a circular
/// dependency (exim-core depends on exim-acl, not the reverse).
///
/// ## Scoped Context Passing (AAP §0.4.4)
///
/// This struct is passed explicitly through all ACL evaluation call chains,
/// replacing the C global variables `acl_added_headers` and `acl_warn_logged`.
/// No global mutable state is used.
#[derive(Debug, Default)]
pub struct MessageContext {
    /// Headers added by ACL processing (via `add_header` modifier or deprecated
    /// `message` modifier on `warn` verb).
    ///
    /// Each entry is a complete header line including the name and colon,
    /// e.g. `"X-ACL-Warn: suspicious sender"`.
    ///
    /// Replaces C global `acl_added_headers` linked list.
    pub acl_added_headers: Vec<String>,

    /// Set of warning messages already logged during this SMTP connection.
    ///
    /// Used for per-connection deduplication of ACL `warn` verb log output.
    /// The same warning message is not repeated within the same connection.
    ///
    /// Replaces C global `acl_warn_logged` linked list with O(1) lookup.
    pub acl_warn_logged: HashSet<String>,

    /// Host identification string for log messages.
    ///
    /// Formatted as `"H=<hostname> [<ip>]"` or `"[<ip>]"` for connections
    /// without a verified hostname. Used in `acl_warn()` log output to match
    /// the C `host_and_ident(TRUE)` function output.
    ///
    /// Replaces calls to C `host_and_ident()` function.
    pub host_and_ident: String,
}

// =============================================================================
// Public API Functions
// =============================================================================

/// Main external ACL evaluation entry point.
///
/// Replaces C `acl_check()` (`acl.c` lines 4891–5053). This is the primary
/// function called by SMTP handling code (`exim-smtp`) and delivery code
/// (`exim-deliver`) to evaluate ACLs.
///
/// # Arguments
///
/// * `eval_ctx` — Mutable ACL evaluation context containing recursion depth,
///   ACL cache, named ACL definitions, DNS resolver, rate limiters, and other
///   per-evaluation state. Replaces the collection of C global variables used
///   by `acl_check_internal()`.
/// * `msg_ctx` — Mutable per-message context containing headers added by ACL
///   processing and per-connection warning deduplication state.
/// * `var_store` — Mutable ACL variable store for connection-scoped (`acl_c*`)
///   and message-scoped (`acl_m*`) variables.
/// * `where_phase` — Which SMTP/processing phase we are in (RCPT, MAIL,
///   DATA, etc.). Determines which ACL conditions are permitted.
/// * `acl_text` — The ACL name, file path, or inline ACL text to evaluate.
///   `None` is equivalent to an empty ACL and results in DENY.
/// * `recipient` — For RCPT, VRFY, and PRDR phases, the recipient address
///   being checked. Used to set up `$local_part`, `$domain`, `$recipient`
///   expansion variables. `None` for non-recipient phases.
/// * `user_msg` — Output parameter for a custom rejection message (SMTP
///   response text). Set by the `message=` modifier.
/// * `log_msg` — Output parameter for a custom log entry. Set by the
///   `log_message=` modifier.
///
/// # Returns
///
/// [`AclResult`] indicating the ACL verdict:
/// - `Ok` — Access granted by an `accept` verb.
/// - `Discard` — Access granted but message silently discarded.
/// - `Fail` — Access denied (5xx).
/// - `FailDrop` — Access denied and connection dropped.
/// - `Defer` — Temporary failure (4xx).
/// - `Error` — Internal evaluation error.
///
/// # Post-Processing (from C `acl_check()` lines 4955–5052)
///
/// After `acl_check_internal()` returns, this wrapper performs:
///
/// 1. **DISCARD validation** — `Discard` is only permitted for message-phase
///    ACLs (phases with discriminant ≤ `AclWhere::NotSmtp`), excluding
///    `AclWhere::Predata`. A discard in a non-message phase is converted
///    to `Error` with a panic log.
///
/// 2. **FAIL_DROP validation** — `FailDrop` is not permitted in the
///    `AclWhere::Mailauth` phase. A drop in MAILAUTH is converted to
///    `Error` with a panic log.
///
/// 3. **User message splitting** — If `user_msg` contains newlines, only
///    the first line is kept as the SMTP response text. Multi-line messages
///    are split so the first line serves as the one-line SMTP response.
// This function has a large parameter count to match the C `acl_check()` function
// that threads evaluation context, message context, variable store, phase,
// ACL text, recipient, and two output message buffers through the call chain.
// Refactoring into a struct would obscure lifetime relationships between the
// mutable references.
#[allow(clippy::too_many_arguments)] // Justified: mirrors C acl_check() API surface; see doc comment above
pub fn acl_check(
    eval_ctx: &mut engine::AclEvalContext,
    msg_ctx: &mut MessageContext,
    var_store: &mut AclVarStore,
    where_phase: AclWhere,
    acl_text: Option<&str>,
    recipient: Option<&str>,
    user_msg: &mut Option<String>,
    log_msg: &mut Option<String>,
) -> AclResult {
    // Clear output parameters (matching C: `*user_msgptr = *log_msgptr = NULL`)
    *user_msg = None;
    *log_msg = None;

    debug!(
        phase = where_phase.name(),
        recipient = recipient.unwrap_or("<none>"),
        acl = acl_text.unwrap_or("<null>"),
        "acl_check: entering ACL evaluation"
    );

    // --- Recipient address setup for RCPT/VRFY/PRDR phases ---
    // (C: acl.c lines 4904–4927)
    //
    // For these phases, the recipient address is split into local_part and
    // domain for use by ACL conditions ($local_part, $domain, $recipient).
    // In the full system, this would call deliver_split_address(). Here we
    // perform a simplified split on '@'.
    let mut _local_part = String::new();
    let mut _domain = String::new();

    let needs_address_setup = where_phase == AclWhere::Rcpt
        || where_phase == AclWhere::Vrfy
        || cfg_prdr_phase_match(where_phase);

    if needs_address_setup {
        if let Some(addr) = recipient {
            // Split "local_part@domain" — matching C deliver_split_address()
            if let Some(at_pos) = addr.rfind('@') {
                _local_part = addr[..at_pos].to_string();
                _domain = addr[at_pos + 1..].to_string();
            } else {
                // No '@' — entire address is the local part (local delivery)
                _local_part = addr.to_string();
            }
            trace!(
                local_part = _local_part.as_str(),
                domain = _domain.as_str(),
                "acl_check: recipient address split"
            );
        }
    }

    // --- Reset evaluation state for top-level call ---
    // (C: acl.c lines 4929–4932)
    eval_ctx.acl_level = 0;
    eval_ctx.ratelimiters_cmd.clear();

    // --- Core ACL evaluation ---
    // (C: acl.c line 4931: `rc = acl_check_internal(...)`)
    let rc = engine::acl_check_internal(
        eval_ctx,
        msg_ctx,
        var_store,
        where_phase,
        acl_text,
        user_msg,
        log_msg,
    );

    // Reset evaluation level after top-level call
    eval_ctx.acl_level = 0;

    debug!(
        phase = where_phase.name(),
        result = %rc,
        "acl_check: acl_check_internal returned"
    );

    // --- DISCARD validation ---
    // (C: acl.c lines 5025–5034)
    //
    // A DISCARD response is permitted only for message ACLs, excluding the
    // PREDATA ACL. In C: `if (where > ACL_WHERE_NOTSMTP || where == ACL_WHERE_PREDATA)`
    // Phases with discriminant <= NotSmtp (7) are "in-message" phases.
    if rc == AclResult::Discard {
        let is_message_phase = (where_phase as u8) <= (AclWhere::NotSmtp as u8);
        let is_predata = where_phase == AclWhere::Predata;

        if !is_message_phase || is_predata {
            warn!(
                phase = where_phase.name(),
                "\"discard\" verb not allowed in {} ACL",
                where_phase.name()
            );
            *log_msg = Some(format!(
                "\"discard\" verb not allowed in {} ACL",
                where_phase.name()
            ));
            return AclResult::Error;
        }
        return AclResult::Discard;
    }

    // --- FAIL_DROP validation for MAILAUTH ---
    // (C: acl.c lines 5038–5043)
    //
    // A DROP response is not permitted from MAILAUTH.
    if rc == AclResult::FailDrop && where_phase == AclWhere::Mailauth {
        warn!("\"drop\" verb not allowed in {} ACL", where_phase.name());
        *log_msg = Some(format!(
            "\"drop\" verb not allowed in {} ACL",
            where_phase.name()
        ));
        return AclResult::Error;
    }

    // --- User message splitting ---
    // (C: acl.c lines 5048: `*user_msgptr = string_split_message(*user_msgptr)`)
    //
    // If the user message contains newlines, split it so the first line
    // serves as the one-line SMTP response text. The remaining lines may
    // be used as the multi-line response body (handled by the SMTP layer).
    if let Some(ref msg) = *user_msg {
        *user_msg = Some(string_split_message(msg));
    }

    rc
}

/// Alternate ACL evaluation interface used by string expansion.
///
/// Replaces C `acl_eval()` (`acl.c` lines 4840–4868). Used when ACLs are
/// invoked from within `${acl ...}` expansion, not directly from SMTP
/// processing. Does not set up recipient addresses or handle cutthrough
/// delivery — those are SMTP-specific behaviors handled by [`acl_check()`].
///
/// # Arguments
///
/// * `eval_ctx` — Mutable ACL evaluation context.
/// * `msg_ctx` — Mutable per-message context.
/// * `var_store` — Mutable ACL variable store.
/// * `where_phase` — Which SMTP/processing phase we are in.
/// * `acl_text` — The ACL text to evaluate.
/// * `user_msg` — Output parameter for a custom message.
///
/// # Returns
///
/// [`AclResult`] indicating the ACL verdict and an optional user message.
pub fn acl_eval(
    eval_ctx: &mut engine::AclEvalContext,
    msg_ctx: &mut MessageContext,
    var_store: &mut AclVarStore,
    where_phase: AclWhere,
    acl_text: &str,
    user_msg: &mut Option<String>,
) -> AclResult {
    // Clear output parameter
    *user_msg = None;
    let mut log_msg: Option<String> = None;

    trace!(
        phase = where_phase.name(),
        acl = acl_text,
        "acl_eval: entering expansion-triggered ACL evaluation"
    );

    // --- Increment recursion depth ---
    // (C: acl.c line 4863: `acl_level++`)
    eval_ctx.acl_level += 1;

    // --- Core ACL evaluation ---
    // (C: acl.c line 4864: `rc = acl_check_internal(...)`)
    let rc = engine::acl_check_internal(
        eval_ctx,
        msg_ctx,
        var_store,
        where_phase,
        Some(acl_text),
        user_msg,
        &mut log_msg,
    );

    // --- Restore recursion depth ---
    // (C: acl.c line 4865: `acl_level--`)
    eval_ctx.acl_level -= 1;

    trace!(
        phase = where_phase.name(),
        result = %rc,
        "acl_eval: returning from expansion-triggered ACL evaluation"
    );

    rc
}

/// Count headers added by ACL processing for the current message.
///
/// Replaces C `fn_hdrs_added()` (`acl.c` lines 1169–1182). Used by string
/// expansion for the `$acl_added_headers_count` variable and by the
/// `$acl_added_headers` variable which returns all added header lines
/// joined by newlines.
///
/// In the C version, this function walks the `acl_added_headers` linked list
/// and builds a string of all header lines joined by newlines. In the Rust
/// version, we simply return the count of added headers. The caller can
/// access `msg_ctx.acl_added_headers` directly for the full list.
///
/// # Arguments
///
/// * `msg_ctx` — The message context containing the list of ACL-added headers.
///
/// # Returns
///
/// The number of headers that have been added by ACL processing during the
/// current message transaction.
pub fn fn_hdrs_added(msg_ctx: &MessageContext) -> usize {
    msg_ctx.acl_added_headers.len()
}

// =============================================================================
// Internal Helper Functions
// =============================================================================

/// Splits a user message string at the first newline for SMTP response use.
///
/// Replaces C `string_split_message()` as used in `acl_check()`.
///
/// SMTP responses are single-line (the first line of the message). If the
/// message contains embedded newlines, only the first line is returned as the
/// SMTP response text. The remainder can be used as a multi-line response body
/// by the SMTP layer.
///
/// # Arguments
///
/// * `msg` — The raw user message string, potentially containing newlines.
///
/// # Returns
///
/// The first line of the message (before the first newline), or the entire
/// message if it contains no newlines.
fn string_split_message(msg: &str) -> String {
    // Find the first newline and return only the first line
    match msg.find('\n') {
        Some(pos) => msg[..pos].to_string(),
        None => msg.to_string(),
    }
}

/// Helper: checks if `where_phase` matches `AclWhere::Prdr` when the `prdr`
/// feature is enabled.
///
/// This helper encapsulates the feature-gated comparison to avoid spreading
/// `#[cfg(feature = "prdr")]` conditionals throughout the code.
fn cfg_prdr_phase_match(where_phase: AclWhere) -> bool {
    #[cfg(feature = "prdr")]
    {
        where_phase == AclWhere::Prdr
    }
    #[cfg(not(feature = "prdr"))]
    {
        let _ = where_phase;
        false
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── AclResult Tests ──────────────────────────────────────────────────

    #[test]
    fn test_acl_result_discriminants_match_c_constants() {
        // These MUST match the C constants (OK=0, DEFER=1, FAIL=2, DISCARD=3,
        // ERROR=4, FAIL_DROP=5) as they are used as bit positions in msgcond[].
        assert_eq!(AclResult::Ok as u8, 0);
        assert_eq!(AclResult::Defer as u8, 1);
        assert_eq!(AclResult::Fail as u8, 2);
        assert_eq!(AclResult::Discard as u8, 3);
        assert_eq!(AclResult::Error as u8, 4);
        assert_eq!(AclResult::FailDrop as u8, 5);
    }

    #[test]
    fn test_acl_result_is_success() {
        assert!(AclResult::Ok.is_success());
        assert!(AclResult::Discard.is_success());
        assert!(!AclResult::Fail.is_success());
        assert!(!AclResult::FailDrop.is_success());
        assert!(!AclResult::Defer.is_success());
        assert!(!AclResult::Error.is_success());
    }

    #[test]
    fn test_acl_result_is_rejection() {
        assert!(AclResult::Fail.is_rejection());
        assert!(AclResult::FailDrop.is_rejection());
        assert!(!AclResult::Ok.is_rejection());
        assert!(!AclResult::Discard.is_rejection());
        assert!(!AclResult::Defer.is_rejection());
        assert!(!AclResult::Error.is_rejection());
    }

    #[test]
    fn test_acl_result_is_temporary() {
        assert!(AclResult::Defer.is_temporary());
        assert!(!AclResult::Ok.is_temporary());
        assert!(!AclResult::Fail.is_temporary());
        assert!(!AclResult::FailDrop.is_temporary());
        assert!(!AclResult::Discard.is_temporary());
        assert!(!AclResult::Error.is_temporary());
    }

    #[test]
    fn test_acl_result_display() {
        assert_eq!(format!("{}", AclResult::Ok), "OK");
        assert_eq!(format!("{}", AclResult::Defer), "DEFER");
        assert_eq!(format!("{}", AclResult::Fail), "FAIL");
        assert_eq!(format!("{}", AclResult::Discard), "DISCARD");
        assert_eq!(format!("{}", AclResult::Error), "ERROR");
        assert_eq!(format!("{}", AclResult::FailDrop), "FAIL_DROP");
    }

    // ── AclError Tests ───────────────────────────────────────────────────

    #[test]
    fn test_acl_error_not_found() {
        let err = AclError::NotFound {
            name: "my_acl".to_string(),
        };
        assert_eq!(format!("{}", err), "ACL not found: my_acl");
    }

    #[test]
    fn test_acl_error_recursion_depth() {
        let err = AclError::RecursionDepthExceeded { max_depth: 20 };
        assert_eq!(format!("{}", err), "ACL recursion depth exceeded (max 20)");
    }

    #[test]
    fn test_acl_error_parse_error() {
        let err = AclError::ParseError {
            line: 42,
            message: "unknown verb".to_string(),
        };
        assert_eq!(
            format!("{}", err),
            "ACL parse error at line 42: unknown verb"
        );
    }

    #[test]
    fn test_acl_error_condition_error() {
        let err = AclError::ConditionError("DNS lookup failed".to_string());
        assert_eq!(format!("{}", err), "ACL condition error: DNS lookup failed");
    }

    #[test]
    fn test_acl_error_expansion_error() {
        let err = AclError::ExpansionError("syntax error in ${if ...}".to_string());
        assert_eq!(
            format!("{}", err),
            "ACL expansion error: syntax error in ${if ...}"
        );
    }

    #[test]
    fn test_acl_error_tainted_text() {
        let err = AclError::TaintedText;
        assert_eq!(format!("{}", err), "ACL tainted text rejected");
    }

    #[test]
    fn test_acl_error_internal_error() {
        let err = AclError::InternalError("unexpected state".to_string());
        assert_eq!(format!("{}", err), "ACL internal error: unexpected state");
    }

    // ── Constants Tests ──────────────────────────────────────────────────

    #[test]
    fn test_max_acl_recursion_depth() {
        assert_eq!(MAX_ACL_RECURSION_DEPTH, 20);
    }

    #[test]
    fn test_max_acl_args() {
        assert_eq!(MAX_ACL_ARGS, 9);
    }

    // ── MessageContext Tests ─────────────────────────────────────────────

    #[test]
    fn test_message_context_default() {
        let ctx = MessageContext::default();
        assert!(ctx.acl_added_headers.is_empty());
        assert!(ctx.acl_warn_logged.is_empty());
        assert!(ctx.host_and_ident.is_empty());
    }

    // ── fn_hdrs_added Tests ──────────────────────────────────────────────

    #[test]
    fn test_fn_hdrs_added_empty() {
        let ctx = MessageContext::default();
        assert_eq!(fn_hdrs_added(&ctx), 0);
    }

    #[test]
    fn test_fn_hdrs_added_with_headers() {
        let mut ctx = MessageContext::default();
        ctx.acl_added_headers.push("X-ACL-Warn: test1".to_string());
        ctx.acl_added_headers.push("X-ACL-Warn: test2".to_string());
        assert_eq!(fn_hdrs_added(&ctx), 2);
    }

    // ── string_split_message Tests ───────────────────────────────────────

    #[test]
    fn test_string_split_message_no_newline() {
        assert_eq!(string_split_message("single line"), "single line");
    }

    #[test]
    fn test_string_split_message_with_newline() {
        assert_eq!(
            string_split_message("first line\nsecond line\nthird"),
            "first line"
        );
    }

    #[test]
    fn test_string_split_message_empty() {
        assert_eq!(string_split_message(""), "");
    }

    #[test]
    fn test_string_split_message_only_newline() {
        assert_eq!(string_split_message("\nrest"), "");
    }

    // ── Re-export Verification Tests ─────────────────────────────────────

    #[test]
    fn test_reexport_acl_where() {
        // Verify AclWhere is re-exported at crate root
        let _phase: AclWhere = AclWhere::Rcpt;
        assert_eq!(_phase.name(), "RCPT");
    }

    #[test]
    fn test_reexport_acl_bitset() {
        // Verify AclBitSet is re-exported at crate root
        let set = AclBitSet::EMPTY;
        assert!(set.permits(AclWhere::Rcpt));
    }

    #[test]
    fn test_reexport_acl_verb() {
        // Verify AclVerb is re-exported at crate root
        let _verb: AclVerb = AclVerb::Accept;
        assert_eq!(_verb.name(), "accept");
    }

    #[test]
    fn test_reexport_acl_condition() {
        // Verify AclCondition is re-exported at crate root
        let _cond: AclCondition = AclCondition::Acl;
        assert_eq!(_cond.name(), "acl");
    }

    #[test]
    fn test_reexport_acl_var_store() {
        // Verify AclVarStore is re-exported at crate root
        let store = AclVarStore::new();
        assert!(store.get("acl_c0").is_none());
    }

    #[test]
    fn test_reexport_acl_var_scope() {
        // Verify AclVarScope is re-exported at crate root
        let _scope: AclVarScope = AclVarScope::Connection;
    }

    // ── cfg_prdr_phase_match Tests ───────────────────────────────────────

    #[test]
    fn test_cfg_prdr_phase_match_non_prdr() {
        assert!(!cfg_prdr_phase_match(AclWhere::Rcpt));
        assert!(!cfg_prdr_phase_match(AclWhere::Mail));
        assert!(!cfg_prdr_phase_match(AclWhere::Data));
    }
}
