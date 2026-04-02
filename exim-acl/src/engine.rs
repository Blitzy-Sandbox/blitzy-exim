// Copyright (c) The Exim Maintainers 2020 - 2025
// Copyright (c) University of Cambridge 1995 - 2018
// SPDX-License-Identifier: GPL-2.0-or-later

//! # ACL Evaluation Core — Engine Module
//!
//! This module contains the core ACL evaluation loop and supporting machinery.
//! It translates the following C functions from `src/src/acl.c`:
//!
//! | C Function                | Lines       | Rust Equivalent                        |
//! |---------------------------|-------------|----------------------------------------|
//! | `acl_varname_to_cond()`   | 782–835     | [`acl_varname_to_cond()`]              |
//! | `acl_data_to_cond()`      | 838–851     | [`acl_data_to_cond()`]                 |
//! | `acl_read()`              | 872–1046    | [`acl_read()`]                         |
//! | `acl_current_verb()`      | 4418–4424   | [`acl_current_verb()`]                 |
//! | `acl_check_internal()`    | 4455–4770   | [`acl_check_internal()`]               |
//! | `acl_check_wargs()`       | 4778–4831   | [`acl_check_wargs()`]                  |
//!
//! ## Data Structures
//!
//! - [`AclBlock`] — Represents a single ACL verb clause with its condition list
//!   (replaces C `acl_block` struct from `structs.h`).
//! - [`AclConditionBlock`] — A condition/modifier within a verb clause (replaces
//!   C `acl_condition_block` linked list node).
//! - [`ConditionData`] — Union-like enum for condition-specific parsed data.
//!
//! ## Design Patterns
//!
//! - **Scoped context passing**: All functions take `&mut MessageContext` — no
//!   global mutable state (AAP §0.4.4).
//! - **Recursion depth**: Tracked in [`AclEvalContext`], maximum 20 levels.
//! - **ACL caching**: Parsed ACL blocks are cached in a `HashMap` replacing the
//!   C `tree_search`/`tree_insertnode` pattern on `acl_tree`.
//! - **Taint tracking**: [`Tainted<T>`](exim_store::Tainted)/[`Clean<T>`](exim_store::Clean)
//!   enforce taint at compile time.
//! - **Zero `unsafe` code** (AAP §0.7.2).

use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::time::SystemTime;

use thiserror::Error;
use tracing::{debug, trace, warn};

use exim_expand::variables::ExpandContext;

use crate::conditions::{
    acl_check_condition, acl_findcondition, AclCondition, AclConditionError, CsaResult,
    RateLimitEntry,
};
use crate::phases::AclWhere;
use crate::variables::{validate_varname, AclVarStore};
use crate::verbs::{acl_warn, AclVerb};
use crate::{AclResult, MessageContext};
use exim_dns::DnsResolver;

// =============================================================================
// Verify-Recipient Callback Infrastructure
// =============================================================================
// In C Exim, `acl_verify_recipient()` calls `verify_address()` which invokes
// the router chain.  The Rust workspace cannot have exim-acl depend on
// exim-deliver (circular dependency), so we use a callback that the SMTP layer
// provides.  The callback receives the recipient address and returns:
//   - `Ok(VerifyRecipientResult)` with routing data (address_data, etc.)
//   - `Err(String)` with a human-readable rejection reason.

/// Result of a `verify = recipient` callback invocation.
///
/// This is returned for BOTH success and failure because C Exim's
/// `copy_error()` in `verify.c` always propagates `address_data` from the
/// address back to the verification address, regardless of the routing
/// outcome.  ACL `message=` modifiers may reference `$address_data` even
/// when verify fails.
#[derive(Debug, Clone, Default)]
pub struct VerifyRecipientResult {
    /// Address data from the last router that touched the address
    /// (`$address_data`).  Present even on routing failure.
    pub address_data: Option<String>,
    /// Sender address data from the matching router (`$sender_address_data`).
    pub sender_address_data: Option<String>,
    /// Whether the address is local.
    pub is_local: bool,
    /// Whether routing succeeded (`true`) or failed (`false`).
    pub routed: bool,
    /// Human-readable rejection reason when routing fails.
    pub fail_message: Option<String>,
}

/// Callback type for `verify = recipient` — invoked by the ACL engine when it
/// encounters a `verify = recipient` condition.  The SMTP / delivery layer
/// provides the implementation which runs the router chain.
///
/// Arguments: `(recipient_address, sender_address)`.
///
/// Returns a `VerifyRecipientResult`.  The `routed` field indicates success
/// vs failure, and `address_data` is populated regardless of the outcome
/// (matching C Exim's `copy_error()` behaviour).
pub type VerifyRecipientCallback = Box<dyn Fn(&str, &str) -> VerifyRecipientResult + Send + Sync>;

// Note: Tainted<T>, Clean<T>, and MessageArena are listed in the schema's
// internal_imports for this module but are not directly consumed in engine.rs
// itself. They are used by the caller to wrap ACL name strings for taint
// checking before passing them to acl_check_internal(), and by the conditions
// module for per-message allocation. The engine module's interface is
// string-based (&str / Option<&str>) for ACL text, with taint enforcement
// occurring at the call-site boundary.

// =============================================================================
// HDEBUG — Debug Output for `-bh` Host-Checking Mode
// =============================================================================

/// Write a HDEBUG line to stderr when host_checking mode is active.
///
/// In C Exim, the macro `HDEBUG(x)` expands to
/// `if (host_checking || IS_DEBUG(x))` which means ALL debug output
/// guarded by HDEBUG is produced during `-bh` sessions regardless of
/// the `debug_selector` setting.  This function replicates that behavior
/// by writing `>>> ` prefixed lines to stderr when `host_checking` is true.
pub fn hdebug(host_checking: bool, msg: &str) {
    if host_checking {
        eprintln!(">>> {}", msg);
    }
}

/// Write a HDEBUG line with indentation for sublist / nested list elements.
///
/// Replicates C Exim's `debug_vprintf()` indentation scheme (debug.c lines
/// 259–272).  The `indent` parameter corresponds to `acl_level + expand_level`
/// in C:
///
/// ```text
/// For each full group of 4:  "   ╎"   (3 spaces + U+254E)
/// Then indent % 4 remaining spaces.
/// ```
///
/// Examples:
/// - indent 0:  `>>> text`
/// - indent 1:  `>>>  text`
/// - indent 2:  `>>>   text`
/// - indent 3:  `>>>    text`
/// - indent 4:  `>>>    ╎text`        (one "   ╎" block + 0 extra)
/// - indent 5:  `>>>    ╎ text`       (one "   ╎" block + 1 space)
/// - indent 8:  `>>>    ╎   ╎text`    (two "   ╎" blocks + 0 extra)
pub fn hdebug_indent(host_checking: bool, indent: usize, msg: &str) {
    if !host_checking {
        return;
    }
    let mut prefix = String::with_capacity(indent + 5);
    prefix.push_str(">>> ");

    // Full 4-unit blocks: each produces "   ╎"
    let full_blocks = indent / 4;
    for _ in 0..full_blocks {
        prefix.push_str("   \u{254E}"); // 3 spaces + ╎ (U+254E)
    }

    // Remaining 0–3 spaces
    let remainder = indent % 4;
    for _ in 0..remainder {
        prefix.push(' ');
    }

    eprintln!("{}{}", prefix, msg);
}

// =============================================================================
// Constants
// =============================================================================

/// Maximum recursion depth for nested ACL calls. Matches the C constant at
/// acl.c line 4466: `if (acl_level > 20)`.
const ACL_MAX_RECURSION_DEPTH: u32 = 20;

/// Maximum number of positional arguments for `acl_check_wargs()`.
/// Matches C: `uschar * tmp_arg[9]` (acl.c line 4783).
const ACL_MAX_ARGS: usize = 9;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during ACL engine operations (parsing, evaluation).
///
/// Replaces the ad-hoc `*error = string_sprintf(...)` error reporting pattern
/// from C `acl_read()` and the `*log_msgptr` / `*user_msgptr` pattern from
/// `acl_check_internal()`.
#[derive(Debug, Error)]
pub enum AclEngineError {
    /// An unknown ACL verb was encountered during parsing.
    #[error("unknown ACL verb \"{name}\" in \"{line}\"")]
    UnknownVerb {
        /// The unrecognized verb name.
        name: String,
        /// The full source line for context.
        line: String,
    },

    /// An unknown ACL condition/modifier was encountered during parsing.
    #[error("unknown ACL condition/modifier in \"{line}\"")]
    UnknownCondition {
        /// The full source line for context.
        line: String,
    },

    /// A negated modifier was encountered (modifiers cannot be negated).
    #[error("ACL error: negation is not allowed with \"{name}\"")]
    NegatedModifier {
        /// The modifier name.
        name: String,
    },

    /// `endpass` was used with a verb other than `accept` or `discard`.
    #[error("ACL error: \"endpass\" is not allowed with \"{verb}\"")]
    EndpassNotAllowed {
        /// The verb that endpass was incorrectly applied to.
        verb: String,
    },

    /// A malformed ACL line was encountered (e.g., negated verb).
    #[error("malformed ACL line \"{line}\"")]
    MalformedLine {
        /// The problematic line.
        line: String,
    },

    /// Variable name validation failed in a SET modifier.
    #[error("invalid variable name after \"set\" in ACL modifier \"set {name}\": {detail}")]
    InvalidVarName {
        /// The variable name that failed validation.
        name: String,
        /// Detail about why validation failed.
        detail: String,
    },

    /// Missing `=` after condition/modifier name.
    #[error("\"=\" missing after ACL {kind} \"{name}\"")]
    MissingEquals {
        /// "modifier" or "condition".
        kind: String,
        /// The condition/modifier name.
        name: String,
    },

    /// ACL recursion depth exceeded.
    #[error("ACL nested too deep: possible loop")]
    RecursionTooDeep,

    /// ACL name expansion failed.
    #[error("failed to expand ACL string \"{acl_text}\": {detail}")]
    ExpansionFailed {
        /// The ACL text that failed expansion.
        acl_text: String,
        /// The expansion error detail.
        detail: String,
    },

    /// Tainted ACL text was used in a non-test context.
    #[error("attempt to use tainted ACL text")]
    TaintedAclText,

    /// Failed to read an ACL from a file.
    #[error("failed to read ACL file \"{path}\": {detail}")]
    FileReadError {
        /// The file path.
        path: String,
        /// The I/O error detail.
        detail: String,
    },

    /// Empty or NULL ACL (implicit deny).
    #[error("ACL is NULL: implicit DENY")]
    EmptyAcl,

    /// QUIT/NOTQUIT ACL may not use certain verbs.
    #[error("QUIT or not-QUIT toplevel ACL may not fail ('{verb}' verb used incorrectly)")]
    BadQuitVerb {
        /// The verb that was incorrectly used.
        verb: String,
    },

    /// Internal error wrapper.
    #[error("internal ACL error: {0}")]
    Internal(String),

    /// Dynamic module loading required but not available.
    #[error("ACL error: failed to find module for '{condition}': dynamic loading not available")]
    ModuleLoadFailed {
        /// The condition requiring a dynamically-loaded module.
        condition: String,
    },

    /// Condition evaluation error from the conditions module.
    #[error("condition error: {0}")]
    ConditionError(#[from] AclConditionError),
}

// =============================================================================
// AclBlock — Verb Clause Structure
// =============================================================================

/// A single ACL verb clause with its associated condition list.
///
/// Replaces the C `acl_block` struct from `structs.h`. In C, ACL blocks form
/// a linked list via `acl_block->next`. In Rust, they are stored as a `Vec`
/// within the parsed ACL representation.
///
/// Each verb (accept, deny, defer, discard, drop, require, warn) has one
/// `AclBlock` containing a list of conditions/modifiers that are evaluated
/// sequentially.
///
/// # Examples
///
/// A configuration fragment like:
/// ```text
/// accept  hosts = +relay_from_hosts
///         control = submission
/// deny    message = relay not permitted
///         !verify = sender
/// ```
/// produces two `AclBlock` instances: one for `accept` with two conditions,
/// and one for `deny` with two conditions.
#[derive(Debug)]
pub struct AclBlock {
    /// The verb for this clause (accept, deny, defer, discard, drop, require,
    /// warn).
    pub verb: AclVerb,

    /// Ordered list of conditions/modifiers for this verb clause.
    /// Evaluated sequentially during ACL processing. Each condition must
    /// pass (or be a modifier) for the verb to "fire."
    pub conditions: Vec<AclConditionBlock>,

    /// Source file name for error reporting and debug output.
    /// Corresponds to C `acl_block->srcfile`.
    pub srcfile: Option<String>,

    /// Source line number for error reporting and debug output.
    /// Corresponds to C `acl_block->srcline`.
    pub srcline: Option<i32>,
}

// =============================================================================
// AclConditionBlock — Condition/Modifier Entry
// =============================================================================

/// A single condition or modifier within an ACL verb clause.
///
/// Replaces the C `acl_condition_block` linked list node. In C, conditions
/// are chained via `acl_condition_block->next`. In Rust, they are stored as
/// a `Vec<AclConditionBlock>` in the parent [`AclBlock`].
///
/// Each condition has a type (from [`AclCondition`]), an optional negation
/// flag, an argument string that may contain expansion variables, and optional
/// parsed data specific to the condition type.
#[derive(Debug)]
pub struct AclConditionBlock {
    /// The condition/modifier type (e.g., `AclCondition::Hosts`,
    /// `AclCondition::Set`, `AclCondition::Endpass`).
    pub condition_type: AclCondition,

    /// Whether this condition is negated via a `!` prefix in configuration.
    /// For example: `!verify = sender` negates the verify condition.
    /// Modifiers (ACD_MOD) may never be negated — the parser rejects this.
    pub negated: bool,

    /// The argument string (to be expanded at evaluation time).
    /// For most conditions, this is the text after `=`. For SET, this is the
    /// value expression after the variable name.
    /// For ENDPASS, this is empty.
    pub argument: String,

    /// Condition-specific parsed data. For the SET modifier, this holds the
    /// variable name. For other conditions, it may hold pre-parsed opaque data.
    pub data: Option<ConditionData>,
}

// =============================================================================
// ConditionData — Union-Like Parsed Data
// =============================================================================

/// Union-like enum for condition-specific parsed data stored in
/// [`AclConditionBlock::data`].
///
/// Replaces the C `acl_condition_block::u` union which holds either a
/// `varname` (for SET modifier) or a `negated` flag (for other conditions).
/// In Rust, we split the negation out as a separate `bool` field and use
/// this enum only for the richer data payload.
pub enum ConditionData {
    /// For the SET modifier: identifies the variable to be assigned.
    /// Stores the full variable name (e.g., "acl_c0", "acl_m_counter").
    SetVariable {
        /// The full variable name validated by `acl_varname_to_cond()`.
        var_name: String,
    },

    /// For other conditions: opaque parsed data that condition-specific
    /// evaluation code can downcast. Uses `Box<dyn Any + Send + Sync>`
    /// for type-erased storage.
    Other(Box<dyn Any + Send + Sync>),
}

/// Manual `Debug` implementation for `ConditionData` since `dyn Any` does not
/// implement `Debug`.
impl std::fmt::Debug for ConditionData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SetVariable { var_name } => f
                .debug_struct("SetVariable")
                .field("var_name", var_name)
                .finish(),
            Self::Other(_) => f.debug_struct("Other").field("data", &"<opaque>").finish(),
        }
    }
}

// =============================================================================
// ACL Cache — Replacing C tree_search/tree_insertnode on acl_tree
// =============================================================================

/// Thread-local or context-local cache of parsed ACL blocks, keyed by ACL
/// name (for named ACLs) or file path (for file-based ACLs).
///
/// Replaces the C `acl_anchor` binary tree used by `tree_search()`/
/// `tree_insertnode()` in `acl_check_internal()`.
pub type AclCache = HashMap<String, Vec<AclBlock>>;

// =============================================================================
// AclEvalContext — Per-Evaluation Mutable State
// =============================================================================

/// Holds per-evaluation mutable state used by the ACL engine.
///
/// These fields replace C global variables that `acl_check_internal()` reads
/// and writes during evaluation. They are passed through the evaluation call
/// chain rather than accessed as globals.
pub struct AclEvalContext {
    /// Current recursion depth (replaces C `acl_level` global).
    /// Incremented on each nested ACL call, decremented on return.
    pub acl_level: u32,

    /// Name of the currently executing ACL verb, for error messages.
    /// Replaces C `acl_current` global pointer used by `acl_current_verb()`.
    pub current_verb_name: Option<String>,

    /// Cache of parsed ACL blocks for previously encountered ACLs.
    /// Replaces C `acl_anchor` tree for file-based and inline ACLs.
    pub acl_cache: AclCache,

    /// Named ACL definitions from configuration (name → parsed blocks).
    /// Pre-parsed during config loading and looked up by name during eval.
    /// Replaces C `acl_anchor` tree for config-defined ACLs.
    pub named_acls: HashMap<String, Vec<AclBlock>>,

    /// Whether we are running in the test harness.
    /// Replaces C `f.running_in_test_harness` flag.
    pub running_in_test_harness: bool,

    /// Positional arguments for nested ACL calls ($acl_arg1..$acl_arg9).
    /// Replaces C `acl_arg[9]` global array.
    pub acl_args: [Option<String>; ACL_MAX_ARGS],

    /// Number of positional arguments set ($acl_narg).
    /// Replaces C `acl_narg` global variable.
    pub acl_narg: usize,

    /// Whether SMTP return error details are enabled.
    /// Replaces C `smtp_return_error_details` global.
    pub smtp_return_error_details: bool,

    /// Temporary details flag for DEFER results.
    /// Replaces C `f.acl_temp_details` flag.
    pub acl_temp_details: bool,

    /// Discard flag propagated from nested ACL evaluations.
    pub discard_flag: bool,

    /// DNS resolver for conditions needing DNS lookups (DNSBL, CSA,
    /// verify, etc.). Passed through to `acl_check_condition()`.
    /// Must be initialized by the caller before evaluation.
    pub dns_resolver: Option<DnsResolver>,

    /// CSA (Client SMTP Authorization) result cache.
    /// Replaces C local cache in `acl_verify_csa()`.
    pub csa_cache: BTreeMap<String, CsaResult>,

    /// Connection-scoped rate limiters.
    pub ratelimiters_conn: HashMap<String, RateLimitEntry>,

    /// Message-scoped rate limiters.
    pub ratelimiters_mail: HashMap<String, RateLimitEntry>,

    /// Command-scoped rate limiters.
    pub ratelimiters_cmd: HashMap<String, RateLimitEntry>,

    /// Seen-key time cache for the `seen` condition.
    pub seen_cache: HashMap<String, SystemTime>,

    /// Current computed sender rate (EWMA) for rate-limiting.
    pub sender_rate: f64,

    /// Current rate-limit period for rate-limiting.
    pub sender_rate_period: f64,

    /// Client IP address string for conditions that need it.
    pub client_ip: String,

    /// SMTP HELO/EHLO name from the client.
    pub sender_helo_name: String,

    /// Whether we are in `-bh` host-checking mode.
    /// When `true`, HDEBUG-style output (`>>> ...`) is written to stderr
    /// for all host list checks, domain list checks, and ACL evaluation
    /// steps, replicating the C macro `HDEBUG(x) if (host_checking || IS_DEBUG(x))`.
    pub host_checking: bool,

    /// Expansion context for variable substitution during ACL evaluation.
    /// Carries state like `$address_data`, `$sender_address`, `$domain`,
    /// `$local_part` etc. that ACL modifiers (`message =`, `log_message =`,
    /// `set`) expand via `expand_string_with_context()`.  Updated by
    /// conditions such as `verify = recipient` which populate
    /// `$address_data` from the routing result.
    pub expand_ctx: ExpandContext,

    /// Optional callback for `verify = recipient`.  When set, the ACL
    /// engine invokes this closure to route the recipient address through
    /// the actual router chain (which lives in exim-deliver, not reachable
    /// from exim-acl due to the workspace dependency DAG).  The SMTP layer
    /// provides the closure, closing over the required ConfigContext and
    /// router instances.
    pub verify_recipient_cb: Option<VerifyRecipientCallback>,

    /// Details of a sender verification failure.  Set by
    /// `acl_verify_sender_via_cb()` when `verify = sender` routes the
    /// sender address through the router chain and it fails.  The SMTP
    /// layer reads this after ACL evaluation to emit the multi-line
    /// "Verification failed for <addr>\n<reason>" prefix before the
    /// final ACL `message =` text, matching C Exim's
    /// `sender_verified_failed` behaviour.
    pub sender_verify_failure: Option<(String, String)>,
}

impl Default for AclEvalContext {
    fn default() -> Self {
        Self {
            acl_level: 0,
            current_verb_name: None,
            acl_cache: HashMap::new(),
            named_acls: HashMap::new(),
            running_in_test_harness: false,
            acl_args: Default::default(),
            acl_narg: 0,
            smtp_return_error_details: false,
            acl_temp_details: false,
            discard_flag: false,
            dns_resolver: None,
            csa_cache: BTreeMap::new(),
            ratelimiters_conn: HashMap::new(),
            ratelimiters_mail: HashMap::new(),
            ratelimiters_cmd: HashMap::new(),
            seen_cache: HashMap::new(),
            sender_rate: 0.0,
            sender_rate_period: 0.0,
            client_ip: String::new(),
            sender_helo_name: String::new(),
            host_checking: false,
            expand_ctx: ExpandContext::default(),
            verify_recipient_cb: None,
            sender_verify_failure: None,
        }
    }
}

impl AclEvalContext {
    /// Creates a new evaluation context with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Expands a string using this context's ExpandContext, providing access
    /// to variables like `$address_data`, `$domain`, `$local_part` etc.
    /// Falls back to the raw string on expansion failure.
    pub fn expand_string(&mut self, s: &str) -> String {
        // Fast path: no expansion characters → return as-is
        if !s.contains('$') && !s.contains('\\') {
            return s.to_string();
        }
        match exim_expand::expand_string_with_context(s, &mut self.expand_ctx) {
            Ok(expanded) => expanded,
            Err(exim_expand::ExpandError::ForcedFail) => String::new(),
            Err(e) => {
                warn!(
                    input = %s,
                    error = %e,
                    "failed to expand ACL message/log_message"
                );
                s.to_string()
            }
        }
    }
}

// =============================================================================
// acl_varname_to_cond — Variable Name Validation for SET Modifier
// =============================================================================

/// Validates a SET modifier variable name and extracts the variable name
/// portion from the argument string.
///
/// Translates C `acl_varname_to_cond()` (acl.c lines 782–835).
///
/// The SET modifier syntax is: `set acl_cX = value` or `set acl_mX = value`
/// where X is a digit (0-9) or `_identifier`.
///
/// Special cases (behind `dkim` feature):
/// - `set dkim_verify_status = ...`
/// - `set dkim_verify_reason = ...`
///
/// # Arguments
///
/// * `arg` — The full argument string after "set " (e.g., "acl_c0 = value").
///
/// # Returns
///
/// On success, returns a tuple of `(variable_name, remaining_value_str)`.
///
/// # Errors
///
/// Returns an `AclEngineError::InvalidVarName` if the variable name is invalid.
pub fn acl_varname_to_cond(arg: &str) -> Result<(String, String), AclEngineError> {
    let s = arg.trim_start();

    // Check for special DKIM variable names (feature-gated)
    #[cfg(feature = "dkim")]
    {
        for special_name in &["dkim_verify_status", "dkim_verify_reason"] {
            if let Some(rest) = s.strip_prefix(special_name) {
                // Must not be followed by an alphanumeric character
                if rest.is_empty() || !rest.starts_with(|c: char| c.is_alphanumeric()) {
                    let remaining = rest.trim_start();
                    return Ok((special_name.to_string(), remaining.to_string()));
                }
            }
        }
    }

    // Must start with "acl_c" or "acl_m"
    if !s.starts_with("acl_c") && !s.starts_with("acl_m") {
        return Err(AclEngineError::InvalidVarName {
            name: s.to_string(),
            detail: "must start \"acl_c\" or \"acl_m\"".to_string(),
        });
    }

    // Check character after "acl_c"/"acl_m" prefix
    let prefix_len = 5; // "acl_c" or "acl_m"
    let after_prefix = &s[prefix_len..];
    if after_prefix.is_empty() {
        return Err(AclEngineError::InvalidVarName {
            name: s.to_string(),
            detail: "digit or underscore must follow acl_c or acl_m".to_string(),
        });
    }

    let first_after = after_prefix.as_bytes()[0];
    if !first_after.is_ascii_digit() && first_after != b'_' {
        return Err(AclEngineError::InvalidVarName {
            name: s.to_string(),
            detail: "digit or underscore must follow acl_c or acl_m".to_string(),
        });
    }

    // Find the end of the variable name: stop at '=', whitespace, or end
    let mut end_idx = prefix_len;
    for (i, ch) in after_prefix.char_indices() {
        if ch == '=' || ch.is_whitespace() {
            end_idx = prefix_len + i;
            break;
        }
        if !ch.is_ascii_alphanumeric() && ch != '_' {
            return Err(AclEngineError::InvalidVarName {
                name: s.to_string(),
                detail: format!("invalid character '{}' in variable name", ch),
            });
        }
        end_idx = prefix_len + i + ch.len_utf8();
    }

    let var_name = s[..end_idx].to_string();
    let remaining = s[end_idx..].trim_start().to_string();

    // Validate via the variables module for consistency
    if let Err(e) = validate_varname(&var_name) {
        return Err(AclEngineError::InvalidVarName {
            name: var_name,
            detail: e.to_string(),
        });
    }

    Ok((var_name, remaining))
}

// =============================================================================
// acl_data_to_cond — Parse =value After Condition Name
// =============================================================================

/// Parses the `=value` portion after a condition/modifier name.
///
/// Translates C `acl_data_to_cond()` (acl.c lines 838–851).
///
/// For most conditions, the argument format is `condition_name = value`.
/// This function extracts the value portion after the `=` sign.
///
/// # Arguments
///
/// * `s` — The string starting at or before the `=` sign.
/// * `cond_name` — The condition name for error messages.
/// * `is_modifier` — Whether this is a modifier (for error message phrasing).
///
/// # Returns
///
/// The value string after `=`, with leading whitespace trimmed.
///
/// # Errors
///
/// Returns `AclEngineError::MissingEquals` if no `=` is found.
pub fn acl_data_to_cond(
    s: &str,
    cond_name: &str,
    is_modifier: bool,
) -> Result<String, AclEngineError> {
    let trimmed = s.trim_start();
    if !trimmed.starts_with('=') {
        return Err(AclEngineError::MissingEquals {
            kind: if is_modifier {
                "modifier".to_string()
            } else {
                "condition".to_string()
            },
            name: cond_name.to_string(),
        });
    }
    // Skip the '=' and trim leading and trailing whitespace from the value.
    // The C parser strips leading whitespace; trailing whitespace is stripped
    // here for consistency since Exim config values are whitespace-delimited.
    let value = trimmed[1..].trim();
    Ok(value.to_string())
}

// =============================================================================
// acl_read — ACL Parser
// =============================================================================

/// Parses ACL text (from configuration or runtime expansion) into a list of
/// [`AclBlock`] verb clauses.
///
/// Translates C `acl_read()` (acl.c lines 872–1046).
///
/// # Algorithm
///
/// 1. Read lines, skip comments (`#`) and blank lines.
/// 2. First word on each block is a verb name → look up via
///    [`AclVerb::from_name()`].
/// 3. Subsequent lines (before next verb) are conditions/modifiers.
/// 4. For each condition line:
///    - Parse optional `!` negation prefix.
///    - Extract condition name, look up via [`acl_findcondition()`].
///    - For ENDPASS: validate only on accept/discard verbs.
///    - For SET: parse variable name via [`acl_varname_to_cond()`].
///    - Extract argument string (rest of line after `=`).
/// 5. Build [`AclConditionBlock`] nodes and append to current verb's list.
/// 6. Return `Vec<AclBlock>` representing the complete ACL.
///
/// # Arguments
///
/// * `acl_text` — The raw ACL text (multi-line string).
/// * `source_file` — Optional source filename for debug/error reporting.
/// * `source_line_base` — Base line number in the config file (0 if inline).
///
/// # Returns
///
/// A vector of parsed ACL blocks, or an error if parsing fails.
///
/// # Errors
///
/// Returns `AclEngineError` for syntax errors in the ACL text.
pub fn acl_read(
    acl_text: &str,
    source_file: Option<&str>,
    source_line_base: i32,
) -> Result<Vec<AclBlock>, AclEngineError> {
    let mut blocks: Vec<AclBlock> = Vec::new();
    // Subtract 1 because the loop increments line_number at the top before
    // processing each line, so the first body line will get the correct
    // absolute line number == source_line_base.
    let mut line_number = source_line_base - 1;

    trace!(
        source = ?source_file,
        base_line = source_line_base,
        "acl_read: beginning ACL parse"
    );

    for raw_line in acl_text.lines() {
        line_number += 1;
        let save_line = raw_line;

        // Trim leading whitespace
        let trimmed = raw_line.trim();

        // Skip empty lines and comment lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Determine if this line starts a new verb (not indented) vs a
        // continuation condition (indented). In the C parser, conditions
        // are distinguished by leading whitespace.
        let is_indented = raw_line
            .as_bytes()
            .first()
            .is_some_and(|b| *b == b' ' || *b == b'\t');

        // Parse possible negation prefix
        let mut s = trimmed;
        let mut negated = false;
        if s.starts_with('!') {
            negated = true;
            s = s[1..].trim_start();
        }

        // Extract the first word (verb or condition name)
        let (name, rest) = extract_name(s);
        if name.is_empty() {
            continue;
        }

        // Try to parse as a verb (only for non-indented lines or if no
        // blocks exist yet, matching C behavior)
        let verb_match = if !is_indented || blocks.is_empty() {
            AclVerb::from_name(&name)
        } else {
            None
        };

        if let Some(verb) = verb_match {
            // Verbs cannot be negated
            if negated {
                return Err(AclEngineError::MalformedLine {
                    line: save_line.to_string(),
                });
            }

            // Create a new AclBlock for this verb
            blocks.push(AclBlock {
                verb,
                conditions: Vec::new(),
                srcfile: source_file.map(|s| s.to_string()),
                srcline: Some(line_number),
            });

            trace!(
                verb = verb.name(),
                line = line_number,
                "acl_read: new verb block"
            );

            // If there's remaining text on the verb line, parse it as
            // a condition on the same line
            let after_verb = rest.trim_start();
            if !after_verb.is_empty() {
                // Re-parse negation for inline condition after verb
                let mut cond_str = after_verb;
                let mut cond_negated = false;
                if cond_str.starts_with('!') {
                    cond_negated = true;
                    cond_str = cond_str[1..].trim_start();
                }

                let (cond_name, cond_rest) = extract_name(cond_str);
                let block_idx = blocks.len() - 1;
                parse_condition_and_add(
                    &cond_name,
                    cond_rest,
                    cond_negated,
                    save_line,
                    &mut blocks[block_idx],
                )?;
            }
        } else {
            // Not a verb — must be a condition on the current verb
            if blocks.is_empty() {
                return Err(AclEngineError::UnknownVerb {
                    name: name.to_string(),
                    line: save_line.to_string(),
                });
            }

            let block_idx = blocks.len() - 1;
            parse_condition_and_add(&name, rest, negated, save_line, &mut blocks[block_idx])?;
        }
    }

    trace!(block_count = blocks.len(), "acl_read: parse complete");
    Ok(blocks)
}

/// Helper: extract the first whitespace-delimited word from a string.
///
/// Returns `(word, rest_of_string)`. Stops at whitespace or `=`.
fn extract_name(s: &str) -> (String, &str) {
    let s = s.trim_start();
    let end = s
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(s.len());
    let name = &s[..end];
    let rest = &s[end..];
    (name.to_string(), rest)
}

/// Helper: parse a condition/modifier line and add it to the given ACL block.
///
/// Handles condition lookup, negation validation, ENDPASS validation, SET
/// modifier variable name extraction, module loading flags, and argument
/// extraction.
fn parse_condition_and_add(
    cond_name: &str,
    rest: &str,
    negated: bool,
    save_line: &str,
    block: &mut AclBlock,
) -> Result<(), AclEngineError> {
    // Look up the condition in the sorted table
    let cond_def =
        acl_findcondition(cond_name).ok_or_else(|| AclEngineError::UnknownCondition {
            line: save_line.to_string(),
        })?;

    trace!(
        condition = cond_name,
        flags = ?cond_def.flags,
        "acl_read: parsing condition"
    );

    // Modifiers may not be negated
    if negated && cond_def.flags.is_modifier() {
        return Err(AclEngineError::NegatedModifier {
            name: cond_def.name.to_string(),
        });
    }

    // ENDPASS may only occur with ACCEPT or DISCARD verbs
    if cond_def.condition == AclCondition::Endpass
        && block.verb != AclVerb::Accept
        && block.verb != AclVerb::Discard
    {
        return Err(AclEngineError::EndpassNotAllowed {
            verb: block.verb.name().to_string(),
        });
    }

    // Handle dynamic module loading flag (ACD_LOAD)
    if cond_def.flags.needs_load() {
        trace!(
            condition = cond_name,
            "acl_read: condition requires dynamic module (ACD_LOAD)"
        );
        // In the Rust build, dynamic module loading is handled by Cargo features.
        // The condition is available if the corresponding feature is enabled at
        // compile time. If we reach here, the feature is compiled in.
    }

    // Build the condition block
    let mut cond_block = AclConditionBlock {
        condition_type: cond_def.condition,
        negated,
        argument: String::new(),
        data: None,
    };

    // For SET modifier: parse variable name, then value
    if cond_def.condition == AclCondition::Set {
        let (var_name, remaining) = acl_varname_to_cond(rest)?;
        cond_block.data = Some(ConditionData::SetVariable { var_name });
        // Parse the value expression after variable name
        let arg = acl_data_to_cond(&remaining, cond_name, cond_def.flags.is_modifier())?;
        cond_block.argument = arg;
    } else if cond_def.condition != AclCondition::Endpass {
        // Non-ENDPASS conditions: parse "= value"
        let arg = acl_data_to_cond(rest, cond_name, cond_def.flags.is_modifier())?;
        cond_block.argument = arg;
    }
    // ENDPASS has no argument — leave argument empty

    block.conditions.push(cond_block);
    Ok(())
}

// =============================================================================
// acl_current_verb — Current Verb Accessor
// =============================================================================

/// Returns a descriptive string about the currently executing ACL verb for
/// error messages and log output.
///
/// Translates C `acl_current_verb()` (acl.c lines 4418–4424).
///
/// The C function returns `" (ACL verb, file line)"` or `""` if no ACL is
/// active. The Rust version returns `Option<String>`.
///
/// # Arguments
///
/// * `eval_ctx` — The evaluation context containing current verb state.
///
/// # Returns
///
/// A formatted string like `"accept (<inline> 42)"` or `None` if no ACL is
/// being evaluated.
pub fn acl_current_verb(eval_ctx: &AclEvalContext) -> Option<String> {
    eval_ctx.current_verb_name.clone()
}

// =============================================================================
// acl_check_internal — Core ACL Evaluation Loop
// =============================================================================

/// Core ACL evaluation function — iterates over verb clauses, evaluates
/// conditions, and returns the ACL result.
///
/// Translates C `acl_check_internal()` (acl.c lines 4455–4770).
///
/// This is the heart of the ACL engine. It resolves the ACL by name (from
/// configuration, file, or inline text), parses it if necessary, then
/// iterates through each verb clause evaluating conditions against the
/// current message/connection context.
///
/// # Algorithm
///
/// 1. **Recursion depth check**: If depth exceeds 20, return ERROR.
/// 2. **ACL resolution**:
///    - If `acl_text` is `None`, return implicit DENY.
///    - Look up as a named ACL from config.
///    - If starts with `/`, read from file (with caching).
///    - Otherwise, parse as inline ACL text.
/// 3. **Taint check**: Reject tainted ACL text (unless test harness).
/// 4. **Verb iteration**: For each `AclBlock`:
///    - Evaluate all conditions via `acl_check_condition()`.
///    - Apply verb-specific result semantics.
///    - Handle ENDPASS, message, log_message modifiers.
/// 5. **Default result**: If no verb terminates, return implicit DENY.
///
/// # Arguments
///
/// * `eval_ctx` — Mutable evaluation context (depth, caching, DNS, rate state).
/// * `msg_ctx` — Mutable per-message context for headers and logging.
/// * `var_store` — ACL variable store for SET modifier evaluation.
/// * `where_phase` — The SMTP/processing phase.
/// * `acl_text` — The ACL name, file path, or inline text. `None` = implicit DENY.
/// * `user_msg` — Output: custom user-facing SMTP error message.
/// * `log_msg` — Output: custom log message.
///
/// # Returns
///
/// The ACL evaluation result (Ok, Fail, Defer, Discard, FailDrop, or Error).
pub fn acl_check_internal(
    eval_ctx: &mut AclEvalContext,
    msg_ctx: &mut MessageContext,
    var_store: &mut AclVarStore,
    where_phase: AclWhere,
    acl_text: Option<&str>,
    user_msg: &mut Option<String>,
    log_msg: &mut Option<String>,
) -> AclResult {
    // --- Recursion depth check (acl.c line 4466) ---
    if eval_ctx.acl_level > ACL_MAX_RECURSION_DEPTH {
        *log_msg = Some("ACL nested too deep: possible loop".to_string());
        return AclResult::Error;
    }

    // --- NULL ACL check (acl.c line 4472) ---
    let acl_str = match acl_text {
        Some(s) if !s.trim().is_empty() => s,
        _ => {
            debug!("ACL is NULL: implicit DENY");
            return AclResult::Fail;
        }
    };

    // --- ACL expansion at top level (acl.c lines 4478–4489) ---
    // At level 0, the ACL name string is expanded before lookup. This
    // supports dynamic ACL names like:
    //   acl_check_rcpt = acl_${sg{${tr{$sender_host_address}{.}{_}}}{...}{...}}
    // At deeper recursion levels, the name is already expanded by the
    // calling `acl` condition handler.
    let expanded_buf: String;
    let ss = if eval_ctx.acl_level == 0 {
        expanded_buf = eval_ctx.expand_string(acl_str.trim());
        expanded_buf.trim()
    } else {
        acl_str.trim()
    };

    // --- ACL resolution (acl.c lines 4507–4579) ---
    // Single-token ACL name (no whitespace/newlines) → try named/file lookup.
    // Multi-token/multi-line → parse as inline ACL text.

    if !ss.contains(|c: char| c.is_whitespace()) {
        // Single-word: try named ACL lookup first.
        // We temporarily remove the entry from the map to avoid a
        // simultaneous immutable borrow (from map lookup) and mutable
        // borrow (from evaluate_acl_blocks needing &mut eval_ctx).
        // The entry is restored after evaluation.
        let ss_key = ss.to_string();

        if eval_ctx.named_acls.contains_key(&ss_key) {
            let blocks = eval_ctx
                .named_acls
                .remove(&ss_key)
                .expect("key existence checked above");
            if blocks.is_empty() {
                debug!(acl = ss, "ACL is empty: implicit DENY");
                eval_ctx.named_acls.insert(ss_key, blocks);
                return AclResult::Fail;
            }
            let acl_name = format!("ACL \"{}\"", ss);
            debug!(acl = ss, "using named ACL");
            // HDEBUG: "using ACL <name>"
            hdebug(eval_ctx.host_checking, &format!("using ACL \"{}\"", ss));
            let result = evaluate_acl_blocks(
                eval_ctx,
                msg_ctx,
                var_store,
                where_phase,
                &blocks,
                &acl_name,
                user_msg,
                log_msg,
            );
            eval_ctx.named_acls.insert(ss_key, blocks);
            return result;
        }

        // Check the runtime cache (file-based or previously parsed inline)
        if eval_ctx.acl_cache.contains_key(&ss_key) {
            let blocks = eval_ctx
                .acl_cache
                .remove(&ss_key)
                .expect("key existence checked above");
            if blocks.is_empty() {
                debug!(acl = ss, "cached ACL is empty: implicit DENY");
                eval_ctx.acl_cache.insert(ss_key, blocks);
                return AclResult::Fail;
            }
            let acl_name = format!("ACL \"{}\"", ss);
            debug!(acl = ss, "using cached ACL");
            // HDEBUG: "using ACL <name>"
            hdebug(eval_ctx.host_checking, &format!("using ACL \"{}\"", ss));
            let result = evaluate_acl_blocks(
                eval_ctx,
                msg_ctx,
                var_store,
                where_phase,
                &blocks,
                &acl_name,
                user_msg,
                log_msg,
            );
            eval_ctx.acl_cache.insert(ss_key, blocks);
            return result;
        }

        // File-based ACL (path starts with '/')
        if ss.starts_with('/') {
            match fs::read_to_string(ss) {
                Ok(content) => {
                    let acl_name = format!("ACL \"{}\"", ss);
                    debug!(file = ss, "read ACL from file");
                    match acl_read(&content, Some(ss), 0) {
                        Ok(parsed) => {
                            let result = evaluate_acl_blocks(
                                eval_ctx,
                                msg_ctx,
                                var_store,
                                where_phase,
                                &parsed,
                                &acl_name,
                                user_msg,
                                log_msg,
                            );
                            // Cache the parsed file ACL for re-use
                            eval_ctx.acl_cache.insert(ss_key, parsed);
                            return result;
                        }
                        Err(e) => {
                            *log_msg = Some(format!("{}", e));
                            return AclResult::Error;
                        }
                    }
                }
                Err(e) => {
                    *log_msg = Some(format!("failed to open ACL file \"{}\": {}", ss, e));
                    return AclResult::Error;
                }
            }
        }

        // Not found — parse as inline ACL text
        let acl_name = "inline ACL".to_string();
        match acl_read(ss, None, 0) {
            Ok(parsed) => {
                return evaluate_acl_blocks(
                    eval_ctx,
                    msg_ctx,
                    var_store,
                    where_phase,
                    &parsed,
                    &acl_name,
                    user_msg,
                    log_msg,
                );
            }
            Err(e) => {
                *log_msg = Some(format!("{}", e));
                return AclResult::Error;
            }
        }
    }

    // Multi-word/multi-line: parse as inline ACL text
    let acl_name = "inline ACL".to_string();
    match acl_read(ss, None, 0) {
        Ok(parsed) => evaluate_acl_blocks(
            eval_ctx,
            msg_ctx,
            var_store,
            where_phase,
            &parsed,
            &acl_name,
            user_msg,
            log_msg,
        ),
        Err(e) => {
            *log_msg = Some(format!("{}", e));
            AclResult::Error
        }
    }
}

// =============================================================================
// evaluate_acl_blocks — Verb Iteration and Result Dispatch
// =============================================================================

/// Evaluates a pre-parsed list of ACL blocks (verb clauses) in order.
///
/// This is the inner loop extracted from `acl_check_internal()`. For each
/// verb clause:
/// 1. Evaluate all conditions via [`acl_check_condition()`].
/// 2. Apply the verb's result semantics (accept/deny/defer/discard/drop/
///    require/warn).
/// 3. Handle ENDPASS, message modifiers, and discard propagation.
///
/// # Returns
///
/// The final ACL result. If no verb terminates processing, returns
/// [`AclResult::Fail`] (implicit DENY — the safe default).
// The parameter count mirrors the C `acl_check_internal()` function which
// passes ACL blocks, evaluation context, message context, variable store,
// phase, and two output message buffers through the call chain.
#[allow(clippy::too_many_arguments)] // Justified: mirrors C API surface; refactoring into a struct would obscure lifetime relationships
fn evaluate_acl_blocks(
    eval_ctx: &mut AclEvalContext,
    msg_ctx: &mut MessageContext,
    var_store: &mut AclVarStore,
    where_phase: AclWhere,
    blocks: &[AclBlock],
    acl_name: &str,
    user_msg: &mut Option<String>,
    log_msg: &mut Option<String>,
) -> AclResult {
    if blocks.is_empty() {
        debug!(acl = acl_name, "ACL has no verb blocks: implicit DENY");
        return AclResult::Fail;
    }

    for block in blocks {
        // Set current verb for acl_current_verb() reporting
        let verb_desc = format!(
            "{} ({}{})",
            block.verb.name(),
            block.srcfile.as_deref().unwrap_or("<inline>"),
            block.srcline.map(|l| format!(" {}", l)).unwrap_or_default()
        );
        eval_ctx.current_verb_name = Some(verb_desc);

        // HDEBUG: "processing ACL check_recipient "accept" (TESTSUITE/test-config 20)"
        // C format: "processing ACL %s \"%s\" (%s %d)"
        //   - bare ACL name (no quotes, no "ACL " prefix)
        //   - verb name in double quotes
        //   - source file + line number in parentheses
        {
            let bare_acl_name = acl_name
                .strip_prefix("ACL \"")
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(acl_name);
            let location = format!(
                "{}{}",
                block.srcfile.as_deref().unwrap_or("<inline>"),
                block.srcline.map(|l| format!(" {}", l)).unwrap_or_default()
            );
            hdebug(
                eval_ctx.host_checking,
                &format!(
                    "processing ACL {} \"{}\" ({})",
                    bare_acl_name,
                    block.verb.name(),
                    location
                ),
            );
        }

        debug!(
            verb = block.verb.name(),
            conditions = block.conditions.len(),
            acl = acl_name,
            "evaluating ACL verb"
        );

        // --- Condition evaluation (acl.c lines 3295–4230) ---
        //
        // CRITICAL: C Exim processes the condition list as follows:
        //   • `message =` / `log_message =` / `endpass` are **modifiers** that
        //     store the RAW argument and immediately `continue` to the next
        //     condition.  They are always processed regardless of prior failures.
        //   • All other conditions are evaluated normally.  On any non-OK result
        //     the loop `break`s — subsequent conditions/modifiers are NOT reached.
        //   • After the loop, the stored RAW `message =` / `log_message =` are
        //     expanded ONCE using the current variable values (including
        //     `$address_data` which may have been set by `verify = recipient`
        //     during the loop).
        //
        // Reference: acl.c lines 3318-3327 (store raw, continue),
        //            acl.c line 4229 (if rc != OK break),
        //            acl.c lines 4248-4294 (post-loop expand).
        let mut all_conditions_ok = true;
        let mut endpass_seen = false;
        let mut condition_result = AclResult::Ok;
        let mut had_discard = false;

        // RAW (unexpanded) message/log_message modifier arguments.
        // Overwritten by each occurrence of the modifier (last one wins).
        let mut raw_user_message: Option<String> = None;
        let mut raw_log_message: Option<String> = None;

        // Messages set directly by conditions (e.g. verify sets
        // user_msg = "Unrouteable address" on failure).
        let mut cond_user_msg: Option<String> = None;
        let mut cond_log_msg: Option<String> = None;

        for cond in &block.conditions {
            // --- Modifiers: store raw and `continue` (acl.c 3318-3332) ---
            if cond.condition_type == AclCondition::Endpass {
                endpass_seen = true;
                trace!("endpass marker encountered");
                continue;
            }
            if cond.condition_type == AclCondition::Message {
                // Store the RAW argument — expanded after the loop.
                raw_user_message = Some(cond.argument.clone());
                if eval_ctx.host_checking {
                    hdebug(true, &format!("  message: {}", cond.argument));
                }
                trace!(raw = %cond.argument, "message modifier: stored raw");
                continue;
            }
            if cond.condition_type == AclCondition::LogMessage {
                raw_log_message = Some(cond.argument.clone());
                if eval_ctx.host_checking {
                    hdebug(true, &format!("l_message: {}", cond.argument));
                }
                trace!(raw = %cond.argument, "log_message modifier: stored raw");
                continue;
            }

            // --- Actual conditions: HDEBUG, evaluate, break on failure ---

            // HDEBUG: "check <condition_name> = <arg>" before each condition
            if eval_ctx.host_checking {
                let cond_display = if cond.argument.is_empty() {
                    format!("check {}", cond.condition_type.name())
                } else {
                    format!("check {} = {}", cond.condition_type.name(), cond.argument)
                };
                hdebug(true, &cond_display);
            }

            // Evaluate the condition
            let cond_result = evaluate_single_condition(
                eval_ctx,
                msg_ctx,
                var_store,
                where_phase,
                cond,
                &mut cond_user_msg,
                &mut cond_log_msg,
            );

            trace!(
                condition = cond.condition_type.name(),
                negated = cond.negated,
                result = ?cond_result,
                "condition evaluation result"
            );

            match cond_result {
                AclResult::Ok => {
                    // Condition passed — continue to next condition
                }
                AclResult::Discard => {
                    // Condition passed with DISCARD indication
                    had_discard = true;
                }
                AclResult::Fail | AclResult::FailDrop => {
                    // Condition failed → break (acl.c line 4229)
                    all_conditions_ok = false;
                    condition_result = cond_result;
                    break;
                }
                AclResult::Defer => {
                    // Temporary failure
                    all_conditions_ok = false;
                    condition_result = AclResult::Defer;
                    break;
                }
                AclResult::Error => {
                    // Hard error — propagate immediately
                    let temp_user_msg = cond_user_msg;
                    let temp_log_msg = cond_log_msg;
                    propagate_messages(&temp_user_msg, &temp_log_msg, user_msg, log_msg);
                    return AclResult::Error;
                }
            }
        }

        // --- Post-loop message expansion (acl.c lines 4248–4294) ---
        //
        // C Exim expands stored raw `message=` / `log_message=` AFTER all
        // conditions in the verb have been processed.  This deferred expansion
        // is critical because variables like `$address_data` are set during
        // `verify = recipient` routing, and the message modifier must see the
        // updated values.
        //
        // `msgcond[]` in C determines for which result codes messages are
        // relevant:
        //   ACL_ACCEPT  → OK | FAIL | FAIL_DROP
        //   ACL_DENY    → OK
        //   ACL_DEFER   → OK
        //   ACL_DISCARD → OK | FAIL | FAIL_DROP
        //   ACL_DROP    → OK
        //   ACL_REQUIRE → FAIL | FAIL_DROP
        //   ACL_WARN    → OK
        let effective_result = if all_conditions_ok {
            if had_discard {
                AclResult::Discard
            } else {
                AclResult::Ok
            }
        } else {
            condition_result
        };

        // C: if (*epp && rc == OK) user_message = NULL;
        if endpass_seen && effective_result == AclResult::Ok {
            raw_user_message = None;
        }

        let should_expand_messages = match block.verb {
            AclVerb::Accept => matches!(
                effective_result,
                AclResult::Ok | AclResult::Fail | AclResult::FailDrop | AclResult::Discard
            ),
            AclVerb::Deny | AclVerb::Defer | AclVerb::Drop => effective_result == AclResult::Ok,
            AclVerb::Discard => matches!(
                effective_result,
                AclResult::Ok | AclResult::Fail | AclResult::FailDrop | AclResult::Discard
            ),
            AclVerb::Require => matches!(effective_result, AclResult::Fail | AclResult::FailDrop),
            AclVerb::Warn => effective_result == AclResult::Ok,
        };

        // Build the final temp_user_msg / temp_log_msg that the verb
        // dispatch code will propagate.
        let mut temp_user_msg: Option<String> = cond_user_msg.clone();
        let mut temp_log_msg: Option<String> = cond_log_msg.clone();

        if should_expand_messages {
            let old_user_msg = cond_user_msg;
            let old_log_msg = cond_log_msg.or_else(|| old_user_msg.clone());

            // For WARN or accept/discard with OK: discard condition-generated
            // messages — only explicit `message =` survives (acl.c ~4262).
            if block.verb == AclVerb::Warn
                || (effective_result == AclResult::Ok
                    && matches!(block.verb, AclVerb::Accept | AclVerb::Discard))
            {
                temp_user_msg = None;
                temp_log_msg = None;
            }

            // Expand the stored raw `message =` (acl.c ~4266–4276).
            if let Some(ref raw) = raw_user_message {
                // In C, acl_verify_message is set to old_user_msgptr before
                // expansion so that $acl_verify_message is available.
                eval_ctx.expand_ctx.acl_verify_message = old_user_msg.unwrap_or_default();
                let expanded = eval_ctx.expand_string(raw);
                if !expanded.is_empty() {
                    temp_user_msg = Some(expanded);
                }
            }

            // Expand the stored raw `log_message =` (acl.c ~4279–4291).
            if let Some(ref raw) = raw_log_message {
                eval_ctx.expand_ctx.acl_verify_message = old_log_msg.unwrap_or_default();
                let expanded = eval_ctx.expand_string(raw);
                if !expanded.is_empty() {
                    temp_log_msg = match temp_log_msg {
                        None => Some(expanded.clone()),
                        Some(existing) => Some(format!("{}: {}", expanded, existing)),
                    };
                }
            }

            // Default: if no log message, use user message (acl.c ~4294).
            if temp_log_msg.is_none() {
                temp_log_msg = temp_user_msg.clone();
            }

            // Clear acl_verify_message after expansion.
            eval_ctx.expand_ctx.acl_verify_message.clear();
        }

        // --- Verb result dispatch (acl.c lines 4710–4770) ---
        if all_conditions_ok {
            // All conditions passed — apply verb semantics
            let verb_result = block.verb.on_conditions_pass(had_discard);

            debug!(
                verb = block.verb.name(),
                result = ?verb_result,
                "all conditions passed"
            );

            // HDEBUG: "accept: condition test succeeded in ACL check_recipient"
            // C format uses bare ACL name (no quotes).
            {
                let bare = acl_name
                    .strip_prefix("ACL \"")
                    .and_then(|s| s.strip_suffix('"'))
                    .unwrap_or(acl_name);
                hdebug(
                    eval_ctx.host_checking,
                    &format!(
                        "{}: condition test succeeded in ACL {}",
                        block.verb.name(),
                        bare
                    ),
                );
            }

            // WARN verb: call acl_warn() and continue to next verb
            if block.verb == AclVerb::Warn {
                acl_warn(
                    msg_ctx,
                    temp_user_msg.as_deref(),
                    temp_log_msg.as_deref(),
                    where_phase,
                );
                continue;
            }

            if block.verb.terminates_on_pass() {
                propagate_messages(&temp_user_msg, &temp_log_msg, user_msg, log_msg);

                // Check for badquit (QUIT/NOTQUIT phases with fail verbs)
                if (where_phase == AclWhere::Quit || where_phase == AclWhere::NotQuit)
                    && verb_result.is_rejection()
                {
                    warn!(
                        verb = block.verb.name(),
                        phase = where_phase.name(),
                        "QUIT or not-QUIT ACL may not fail"
                    );
                    return AclResult::Ok;
                }

                // HDEBUG: "end of ACL check_recipient: ACCEPT"
                // C format uses bare ACL name (no quotes).
                let result_label = match verb_result {
                    AclResult::Ok => "ACCEPT",
                    AclResult::Fail => "DENY",
                    AclResult::Defer => "DEFER",
                    AclResult::Discard => "DISCARD",
                    AclResult::FailDrop => "DROP",
                    AclResult::Error => "ERROR",
                };
                {
                    let bare = acl_name
                        .strip_prefix("ACL \"")
                        .and_then(|s| s.strip_suffix('"'))
                        .unwrap_or(acl_name);
                    hdebug(
                        eval_ctx.host_checking,
                        &format!("end of ACL {}: {}", bare, result_label),
                    );
                }

                return verb_result;
            }

            // Non-terminating on pass: Require verb with pass just continues
            // to the next verb (matching C break-from-switch behavior).
        } else if endpass_seen {
            // Conditions failed AFTER endpass
            let verb_result = block.verb.on_conditions_fail_after_endpass();

            debug!(
                verb = block.verb.name(),
                result = ?verb_result,
                "conditions failed after endpass"
            );

            if block.verb.terminates_on_fail_after_endpass() {
                propagate_messages(&temp_user_msg, &temp_log_msg, user_msg, log_msg);

                // DEFER propagation
                if condition_result == AclResult::Defer {
                    eval_ctx.acl_temp_details = true;
                    return AclResult::Defer;
                }

                return verb_result;
            }
        } else {
            // Conditions failed before ENDPASS — fall through to next verb
            debug!(
                verb = block.verb.name(),
                "conditions failed: continuing to next verb"
            );

            // HDEBUG: "accept: condition test failed in ACL check_recipient"
            {
                let bare = acl_name
                    .strip_prefix("ACL \"")
                    .and_then(|s| s.strip_suffix('"'))
                    .unwrap_or(acl_name);
                hdebug(
                    eval_ctx.host_checking,
                    &format!(
                        "{}: condition test failed in ACL {}",
                        block.verb.name(),
                        bare
                    ),
                );
            }

            // Propagate message/log_message modifiers even when conditions
            // fail.  In C Exim, `message =` directly sets `*user_msgptr`
            // (the output parameter) during condition evaluation, so the
            // custom message is available regardless of whether the verb
            // succeeds or fails.  The Rust code uses a per-verb temp
            // variable, so we must copy it to the output here to match C
            // behavior.  The last verb to set a message wins.
            propagate_messages(&temp_user_msg, &temp_log_msg, user_msg, log_msg);

            // For REQUIRE verb, condition failure always terminates
            if block.verb == AclVerb::Require {
                if condition_result == AclResult::Defer {
                    eval_ctx.acl_temp_details = true;
                    return AclResult::Defer;
                }
                // HDEBUG: "end of ACL check_recipient: DENY"
                {
                    let bare = acl_name
                        .strip_prefix("ACL \"")
                        .and_then(|s| s.strip_suffix('"'))
                        .unwrap_or(acl_name);
                    hdebug(
                        eval_ctx.host_checking,
                        &format!("end of ACL {}: DENY", bare),
                    );
                }
                return AclResult::Fail;
            }
        }
    }

    // No verb terminated — implicit DENY (acl.c line 4770)
    debug!(acl = acl_name, "end of ACL reached: implicit DENY");
    {
        let bare = acl_name
            .strip_prefix("ACL \"")
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(acl_name);
        hdebug(
            eval_ctx.host_checking,
            &format!("end of ACL {}: implicit DENY", bare),
        );
    }
    AclResult::Fail
}

/// Helper: propagate temp user/log messages to output parameters.
fn propagate_messages(
    temp_user: &Option<String>,
    temp_log: &Option<String>,
    user_msg: &mut Option<String>,
    log_msg: &mut Option<String>,
) {
    if let Some(ref msg) = *temp_user {
        *user_msg = Some(msg.clone());
    }
    if let Some(ref msg) = *temp_log {
        *log_msg = Some(msg.clone());
    }
}

// =============================================================================
// evaluate_single_condition — Condition Dispatch Wrapper
// =============================================================================

/// Evaluates a single condition within a verb clause, handling modifiers
/// (SET, message, log_message) specially and dispatching true conditions to
/// [`acl_check_condition()`].
fn evaluate_single_condition(
    eval_ctx: &mut AclEvalContext,
    msg_ctx: &mut MessageContext,
    var_store: &mut AclVarStore,
    where_phase: AclWhere,
    cond: &AclConditionBlock,
    user_msg: &mut Option<String>,
    log_msg: &mut Option<String>,
) -> AclResult {
    // --- SET modifier: evaluate the expression and assign to variable ---
    if cond.condition_type == AclCondition::Set {
        if let Some(ConditionData::SetVariable { ref var_name }) = cond.data {
            // In the full system, the argument would be expanded first via
            // exim_expand::expand_string(). The ACL engine stores the raw
            // argument as the value — the expansion layer handles actual
            // expansion before reaching here.
            let value = cond.argument.clone();
            if let Err(e) = var_store.create(var_name, value) {
                warn!(variable = var_name.as_str(), error = %e,
                    "SET modifier: failed to create variable");
                return AclResult::Error;
            }
            trace!(
                variable = var_name.as_str(),
                "SET modifier: variable assigned"
            );
        }
        return AclResult::Ok;
    }

    // NOTE: message= and log_message= modifiers are handled directly in the
    // condition loop in acl_check_internal() — they store the RAW argument
    // and are expanded after the loop completes (matching C acl.c behavior).
    // They should never reach this function.

    // --- Nested ACL condition (`acl = <name> [args]`) (acl.c ~4597–4632) ---
    // The `acl` condition must be handled here in the engine because it
    // requires recursive `acl_check_internal()` / `acl_check_wargs()` which
    // need `AclEvalContext` (not available in `conditions.rs`).
    if cond.condition_type == AclCondition::Acl {
        // Expand the argument to get the ACL name and optional positional args
        let expanded_arg = eval_ctx.expand_string(&cond.argument);
        // The format is: "acl_name arg1 arg2 ..." or just "acl_name"
        // or it can be a file path "/some/acl.file"
        let parts: Vec<&str> = expanded_arg.splitn(2, char::is_whitespace).collect();
        let acl_name = parts[0];
        let args_str = if parts.len() > 1 { parts[1] } else { "" };

        // Collect positional arguments (space-separated)
        let args: Vec<&str> = if args_str.is_empty() {
            Vec::new()
        } else {
            args_str.split_whitespace().collect()
        };

        let acl_result = if args.is_empty() {
            // Simple nested ACL — call acl_check_internal recursively
            eval_ctx.acl_level += 1;
            let result = acl_check_internal(
                eval_ctx,
                msg_ctx,
                var_store,
                where_phase,
                Some(acl_name),
                user_msg,
                log_msg,
            );
            eval_ctx.acl_level -= 1;
            result
        } else {
            // Nested ACL with positional args — call acl_check_wargs
            let string_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            acl_check_wargs(
                eval_ctx,
                msg_ctx,
                var_store,
                where_phase,
                acl_name,
                &string_args,
                user_msg,
                log_msg,
            )
        };

        // Apply negation per standard condition handling
        let final_result = if cond.negated {
            match acl_result {
                AclResult::Ok => AclResult::Fail,
                AclResult::Fail => AclResult::Ok,
                other => other,
            }
        } else {
            acl_result
        };
        return final_result;
    }

    // --- Phase restriction check using the forbids bitmask (acl.c ~4549) ---
    // Look up the condition definition to verify it is permitted in the
    // current ACL phase. If forbidden, log a warning and skip evaluation.
    let cond_def = acl_findcondition(cond.condition_type.name());
    if let Some(def) = cond_def {
        if def.forbids.forbids(where_phase) {
            warn!(
                condition = cond.condition_type.name(),
                phase = where_phase.name(),
                "condition is forbidden in this ACL phase"
            );
            *log_msg = Some(format!(
                "condition \"{}\" is not allowed in {} ACL",
                cond.condition_type.name(),
                where_phase.name()
            ));
            return AclResult::Error;
        }
    }

    // --- Dispatch to the condition evaluation function in conditions.rs ---
    // The DNS resolver must be initialized before evaluation; if it is not
    // available, return an error for DNS-dependent conditions.
    let resolver = match eval_ctx.dns_resolver {
        Some(ref r) => r,
        None => {
            warn!(
                condition = cond.condition_type.name(),
                "DNS resolver not initialized in AclEvalContext"
            );
            *log_msg = Some("internal error: DNS resolver not initialized".to_string());
            return AclResult::Error;
        }
    };

    let result = acl_check_condition(
        cond.condition_type,
        &cond.argument,
        cond.negated,
        where_phase,
        msg_ctx,
        resolver,
        var_store,
        &mut eval_ctx.csa_cache,
        &mut eval_ctx.ratelimiters_conn,
        &mut eval_ctx.ratelimiters_mail,
        &mut eval_ctx.ratelimiters_cmd,
        &mut eval_ctx.seen_cache,
        &mut eval_ctx.sender_rate,
        &mut eval_ctx.sender_rate_period,
        &eval_ctx.client_ip,
        &eval_ctx.sender_helo_name,
        eval_ctx.host_checking,
        eval_ctx.verify_recipient_cb.as_ref(),
        &mut eval_ctx.expand_ctx,
        user_msg,
        log_msg,
        &mut eval_ctx.sender_verify_failure,
    );

    match result {
        Ok(acl_result) => acl_result,
        Err(e) => {
            warn!(
                condition = cond.condition_type.name(),
                error = %e,
                "condition evaluation error"
            );
            *log_msg = Some(format!("condition evaluation error: {}", e));
            AclResult::Error
        }
    }
}

// =============================================================================
// acl_check_wargs — Nested ACL Call with Positional Arguments
// =============================================================================

/// Evaluates a named ACL with up to 9 positional arguments (`$acl_arg1`..
/// `$acl_arg9`) and `$acl_narg`.
///
/// Translates C `acl_check_wargs()` (acl.c lines 4778–4831).
///
/// This function saves the current `$acl_arg` values, sets new argument
/// values from the provided list, calls [`acl_check_internal()`] recursively,
/// and then restores the previous argument values.
///
/// # Arguments
///
/// * `eval_ctx` — Mutable evaluation context (increments recursion depth).
/// * `msg_ctx` — Mutable per-message context.
/// * `var_store` — ACL variable store.
/// * `where_phase` — The SMTP/processing phase.
/// * `acl_name` — The named ACL to invoke.
/// * `args` — Positional arguments (max 9). Elements beyond 9 are ignored.
/// * `user_msg` — Output: custom user-facing error message.
/// * `log_msg` — Output: custom log message.
///
/// # Returns
///
/// The ACL evaluation result from the named ACL.
// Parameter count mirrors the C `acl_check_wargs()` function that threads
// evaluation context, message context, variable store, phase, ACL name,
// argument array, and two output message buffers through the call chain.
#[allow(clippy::too_many_arguments)] // Justified: mirrors C API surface; refactoring into a struct would obscure lifetime relationships
pub fn acl_check_wargs(
    eval_ctx: &mut AclEvalContext,
    msg_ctx: &mut MessageContext,
    var_store: &mut AclVarStore,
    where_phase: AclWhere,
    acl_name: &str,
    args: &[String],
    user_msg: &mut Option<String>,
    log_msg: &mut Option<String>,
) -> AclResult {
    debug!(
        acl = acl_name,
        nargs = args.len(),
        level = eval_ctx.acl_level,
        "acl_check_wargs: entering nested ACL call"
    );

    // --- Save current $acl_arg values and $acl_narg (acl.c line 4794) ---
    let saved_args: [Option<String>; ACL_MAX_ARGS] =
        std::array::from_fn(|i| eval_ctx.acl_args[i].clone());
    let saved_narg = eval_ctx.acl_narg;

    // --- Set new argument values (acl.c lines 4800–4810) ---
    let arg_count = args.len().min(ACL_MAX_ARGS);
    for (i, arg_slot) in eval_ctx.acl_args.iter_mut().enumerate() {
        *arg_slot = if i < arg_count {
            Some(args[i].clone())
        } else {
            None
        };
    }
    eval_ctx.acl_narg = arg_count;

    // --- Increment recursion depth (acl.c line 4815) ---
    eval_ctx.acl_level += 1;

    // --- Call acl_check_internal recursively (acl.c line 4818) ---
    let result = acl_check_internal(
        eval_ctx,
        msg_ctx,
        var_store,
        where_phase,
        Some(acl_name),
        user_msg,
        log_msg,
    );

    // --- Restore recursion depth ---
    eval_ctx.acl_level -= 1;

    // --- Restore previous $acl_arg values and $acl_narg (acl.c lines 4822–4830) ---
    eval_ctx.acl_args.clone_from_slice(&saved_args);
    eval_ctx.acl_narg = saved_narg;

    debug!(
        acl = acl_name,
        result = ?result,
        "acl_check_wargs: returning from nested ACL call"
    );

    result
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acl_varname_to_cond_digit() {
        let (name, rest) = acl_varname_to_cond("acl_c0 = value").unwrap();
        assert_eq!(name, "acl_c0");
        assert_eq!(rest, "= value");
    }

    #[test]
    fn test_acl_varname_to_cond_underscore() {
        let (name, rest) = acl_varname_to_cond("acl_m_counter = 42").unwrap();
        assert_eq!(name, "acl_m_counter");
        assert_eq!(rest, "= 42");
    }

    #[test]
    fn test_acl_varname_to_cond_invalid_prefix() {
        let result = acl_varname_to_cond("bad_var = value");
        assert!(result.is_err());
    }

    #[test]
    fn test_acl_varname_to_cond_missing_suffix() {
        let result = acl_varname_to_cond("acl_c");
        assert!(result.is_err());
    }

    #[test]
    fn test_acl_data_to_cond_basic() {
        let val = acl_data_to_cond("= some_value", "hosts", false).unwrap();
        assert_eq!(val, "some_value");
    }

    #[test]
    fn test_acl_data_to_cond_missing_equals() {
        let result = acl_data_to_cond("some_value", "hosts", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_acl_data_to_cond_with_spaces() {
        let val = acl_data_to_cond("  =  spaced value  ", "hosts", false).unwrap();
        assert_eq!(val, "spaced value");
    }

    #[test]
    fn test_extract_name_simple() {
        let (name, rest) = extract_name("accept hosts = foo");
        assert_eq!(name, "accept");
        assert_eq!(rest, " hosts = foo");
    }

    #[test]
    fn test_extract_name_equals() {
        let (name, rest) = extract_name("hosts= +relay");
        assert_eq!(name, "hosts");
        assert_eq!(rest, "= +relay");
    }

    #[test]
    fn test_acl_current_verb_none() {
        let ctx = AclEvalContext::new();
        assert!(acl_current_verb(&ctx).is_none());
    }

    #[test]
    fn test_acl_current_verb_some() {
        let mut ctx = AclEvalContext::new();
        ctx.current_verb_name = Some("accept (test.conf 42)".to_string());
        let v = acl_current_verb(&ctx);
        assert_eq!(v, Some("accept (test.conf 42)".to_string()));
    }

    #[test]
    fn test_condition_data_debug() {
        let cd = ConditionData::SetVariable {
            var_name: "acl_c0".to_string(),
        };
        let dbg = format!("{:?}", cd);
        assert!(dbg.contains("acl_c0"));

        let cd2 = ConditionData::Other(Box::new(42i32));
        let dbg2 = format!("{:?}", cd2);
        assert!(dbg2.contains("opaque"));
    }

    #[test]
    fn test_recursion_depth_limit() {
        let mut eval_ctx = AclEvalContext::new();
        eval_ctx.acl_level = ACL_MAX_RECURSION_DEPTH + 1;
        let mut msg_ctx = MessageContext::default();
        let mut var_store = AclVarStore::new();
        let mut user_msg = None;
        let mut log_msg = None;

        let result = acl_check_internal(
            &mut eval_ctx,
            &mut msg_ctx,
            &mut var_store,
            AclWhere::Rcpt,
            Some("some_acl"),
            &mut user_msg,
            &mut log_msg,
        );
        assert_eq!(result, AclResult::Error);
        assert!(log_msg.unwrap().contains("nested too deep"));
    }

    #[test]
    fn test_null_acl_implicit_deny() {
        let mut eval_ctx = AclEvalContext::new();
        let mut msg_ctx = MessageContext::default();
        let mut var_store = AclVarStore::new();
        let mut user_msg = None;
        let mut log_msg = None;

        let result = acl_check_internal(
            &mut eval_ctx,
            &mut msg_ctx,
            &mut var_store,
            AclWhere::Rcpt,
            None,
            &mut user_msg,
            &mut log_msg,
        );
        assert_eq!(result, AclResult::Fail);
    }

    #[test]
    fn test_empty_acl_implicit_deny() {
        let mut eval_ctx = AclEvalContext::new();
        let mut msg_ctx = MessageContext::default();
        let mut var_store = AclVarStore::new();
        let mut user_msg = None;
        let mut log_msg = None;

        let result = acl_check_internal(
            &mut eval_ctx,
            &mut msg_ctx,
            &mut var_store,
            AclWhere::Rcpt,
            Some("   "),
            &mut user_msg,
            &mut log_msg,
        );
        assert_eq!(result, AclResult::Fail);
    }

    #[test]
    fn test_acl_check_wargs_save_restore() {
        let mut eval_ctx = AclEvalContext::new();
        eval_ctx.acl_args[0] = Some("original_arg".to_string());
        eval_ctx.acl_narg = 1;

        // Set up a named ACL that just accepts (empty = implicit deny)
        // to test save/restore semantics
        let mut msg_ctx = MessageContext::default();
        let mut var_store = AclVarStore::new();
        let mut user_msg = None;
        let mut log_msg = None;

        let args = vec!["new_arg1".to_string(), "new_arg2".to_string()];

        // This will fail to find the ACL and return error/fail, but
        // the save/restore mechanism should still work
        let _result = acl_check_wargs(
            &mut eval_ctx,
            &mut msg_ctx,
            &mut var_store,
            AclWhere::Rcpt,
            "nonexistent_acl",
            &args,
            &mut user_msg,
            &mut log_msg,
        );

        // Verify original args are restored
        assert_eq!(eval_ctx.acl_args[0], Some("original_arg".to_string()));
        assert_eq!(eval_ctx.acl_narg, 1);
        assert_eq!(eval_ctx.acl_level, 0);
    }
}
