#![forbid(unsafe_code)]
// Copyright (c) The Exim Maintainers 2020 - 2025
// Copyright (c) University of Cambridge 1995 - 2018
// SPDX-License-Identifier: GPL-2.0-or-later

//! # exim-acl — Access Control List Evaluation Engine
//!
//! This crate replaces `src/src/acl.c` (5,147 lines of C) from the Exim MTA source tree.
//! It implements the complete ACL evaluation engine for Exim: verb evaluation (accept,
//! deny, defer, discard, drop, require, warn), condition checking across 30+ condition
//! types, phase enforcement across 22+ SMTP phases, and ACL variable management.
//!
//! The ACL engine is consumed by `exim-core` (for top-level ACL dispatch) and
//! `exim-smtp` (for per-SMTP-phase ACL invocation at connect, helo, mail, rcpt,
//! data, mime, dkim, prdr phases).

// Submodule declarations — each module corresponds to a distinct functional area
// of the ACL evaluation engine.

/// ACL phase definitions: [`AclWhere`](phases::AclWhere) enum, [`AclBitSet`](phases::AclBitSet)
/// bitmask type, `BIT_*` constants, and the forbids/permits system.
pub mod phases;

/// ACL verb definitions: [`AclVerb`](verbs::AclVerb) enum (accept/deny/defer/discard/
/// drop/require/warn), per-verb evaluation semantics, message condition bitmaps,
/// and the [`acl_warn`](verbs::acl_warn) side-effect handler.
pub mod verbs;

/// ACL variable management: [`AclVarStore`](variables::AclVarStore) for variable
/// creation, lookup, spool serialization/deserialization, and standalone variable
/// setting for `-be` expand-test mode.
pub mod variables;

/// ACL condition/modifier evaluation: [`AclCondition`](conditions::AclCondition) enum,
/// [`acl_check_condition`](conditions::acl_check_condition) dispatcher, control types,
/// CSA verification, ratelimit, and all per-condition evaluation semantics.
pub mod conditions;

// Re-export key variable types for convenient access by dependent crates.
pub use variables::{AclVarError, AclVarScope, AclVarStore, AclVariable};

// Re-export verb types for convenient access by dependent crates.
pub use verbs::AclVerb;

use std::collections::HashSet;
use std::fmt;

// =============================================================================
// AclResult — Core Result Type for ACL Evaluation
// =============================================================================

/// Result of ACL evaluation.
///
/// Replaces the C integer return codes from `acl_check()` / `acl_check_internal()`.
/// These values map to the C constants:
///
/// | Rust Variant        | C Constant | C Value |
/// |---------------------|------------|---------|
/// | `AclResult::Ok`     | `OK`       | `0`     |
/// | `AclResult::Defer`  | `DEFER`    | `1`     |
/// | `AclResult::Fail`   | `FAIL`     | `2`     |
/// | `AclResult::Discard` | `DISCARD` | `3`     |
/// | `AclResult::Error`  | `ERROR`    | `4`     |
/// | `AclResult::FailDrop` | `FAIL_DROP` | `5`  |
///
/// The discriminant values are fixed to match the C constants, as they are used
/// as bit positions in the `msgcond[]` bitmap (see [`verbs::AclVerb::message_condition_bits`]).
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
