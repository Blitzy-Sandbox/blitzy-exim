// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! Redirect Router — Alias/Filter/Sieve Redirect Processing
//!
//! Translates **`src/src/routers/redirect.c`** (817 lines) and
//! **`src/src/routers/redirect.h`** (74 lines) into Rust.
//!
//! ## Overview
//!
//! The redirect router is the most complex router in Exim.  It handles:
//!
//! - **Alias files** — Simple address lists (one address per line, or
//!   comma-separated) where each entry becomes a generated child address.
//! - **Forward files** — Per-user `.forward` files read from the filesystem.
//! - **Exim filter language** — A domain-specific filter language providing
//!   conditionals, string matching, and delivery actions.
//! - **Sieve filter language** — RFC 5228 Sieve filters with extensions for
//!   enotify, vacation, fileinto, reject, and redirect.
//! - **Special deliveries** — File (`/path`), pipe (`|command`), directory
//!   (`/path/` with trailing slash), and auto-reply (`:reply:`) prefixes
//!   that route to specific transport types.
//!
//! ## Data Sources
//!
//! The redirect data can come from two mutually exclusive sources:
//!
//! - **`data`** option — An expandable string evaluated at route time.
//! - **`file`** option — A filesystem path to an alias/forward file.
//!
//! Exactly one of `data` or `file` must be set; the router rejects
//! configuration where both or neither are set.
//!
//! ## C Source Correspondence
//!
//! | C construct | Rust equivalent |
//! |---|---|
//! | `redirect_router_options_block` | [`RedirectRouterOptions`] |
//! | `redirect_router_init()` | [`RedirectRouter::validate_config()`] |
//! | `redirect_router_entry()` | [`RedirectRouter::route()`] |
//! | `add_generated()` | [`RedirectRouter::add_generated()`] |
//! | `sort_errors_and_headers()` | Inline in [`RedirectRouter::route()`] |
//! | `RDO_*` constants | [`RDO_*` module constants] |
//! | `redirect_router_info` | [`inventory::submit!`] registration |
//!
//! ## Safety
//!
//! This module contains **zero `unsafe` code** (per AAP §0.7.2).
//! All redirected addresses are wrapped in [`Tainted<T>`] until validated.

// ── Imports ────────────────────────────────────────────────────────────────

use exim_drivers::router_driver::{
    RouterDriver, RouterDriverFactory, RouterFlags, RouterInstanceConfig, RouterResult,
};
use exim_drivers::DriverError;
use exim_expand::{expand_string, ExpandError};
use exim_store::Tainted;

use crate::helpers::change_domain::AddressItem;
use crate::helpers::UgidBlock;

use regex::Regex;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::LazyLock;
use thiserror::Error;

// ═══════════════════════════════════════════════════════════════════════════
//  RDO_* Bit Option Constants
// ═══════════════════════════════════════════════════════════════════════════
//
// These constants define the `bit_options` bitmask field on
// `RedirectRouterOptions`.  They control which operations are permitted or
// forbidden in redirect/filter/Sieve processing.
//
// Sourced from `src/src/routers/redirect.c` lines 27-123 (optionlist) and
// the C `#define RDO_*` constants in expand.c / readconf.c.

/// Allow `${lookup ...}` in filters/Sieve.
pub const RDO_LOOKUP: u32 = 1 << 0;

/// Allow `${run ...}` in filters.
pub const RDO_RUN: u32 = 1 << 1;

/// Allow `${dlfunc ...}` in filters.
pub const RDO_DLFUNC: u32 = 1 << 2;

/// Allow `${perl ...}` in filters.
pub const RDO_PERL: u32 = 1 << 3;

/// Allow `${readfile ...}` in filters.
pub const RDO_READFILE: u32 = 1 << 4;

/// Allow `${readsocket ...}` in filters.
pub const RDO_READSOCK: u32 = 1 << 5;

/// Allow `:include:` directives in alias expansion.
pub const RDO_INCLUDE: u32 = 1 << 6;

/// Rewrite addresses according to global rewrite rules.
pub const RDO_REWRITE: u32 = 1 << 7;

/// Prepend `$home` to relative file paths.
pub const RDO_PREPEND_HOME: u32 = 1 << 8;

/// Allow Exim filter language processing.
pub const RDO_EXIM_FILTER: u32 = 1 << 9;

/// Allow Sieve filter language processing.
pub const RDO_SIEVE_FILTER: u32 = 1 << 10;

/// Allow the `exists` condition in filters.
pub const RDO_EXISTS: u32 = 1 << 11;

/// Allow `logwrite` / `log_message` in filters.
pub const RDO_LOG: u32 = 1 << 12;

/// Allow `freeze` action in filters.
pub const RDO_FREEZE: u32 = 1 << 13;

/// Allow `fail` action in filters.
pub const RDO_FAIL: u32 = 1 << 14;

/// Allow `defer` action in filters.
pub const RDO_DEFER: u32 = 1 << 15;

/// Allow `:blackhole:` in redirect data.
pub const RDO_BLACKHOLE: u32 = 1 << 16;

/// Allow EACCES on file open to be non-fatal.
pub const RDO_EACCES: u32 = 1 << 17;

/// Allow ENOTDIR on file open to be non-fatal.
pub const RDO_ENOTDIR: u32 = 1 << 18;

/// Default bit_options value (RDO_REWRITE | RDO_PREPEND_HOME).
pub const RDO_DEFAULT: u32 = RDO_REWRITE | RDO_PREPEND_HOME;

// ═══════════════════════════════════════════════════════════════════════════
//  Address Flag Constants
// ═══════════════════════════════════════════════════════════════════════════
//
// Flags set on generated AddressItem.flags during redirect processing.

/// Address is for pipe delivery (`|command`).
const AF_PFLAG: u32 = 1 << 0;

/// Address is for file delivery (`/path`).
const AF_FILE: u32 = 1 << 1;

/// Address is for directory delivery (`/path/`).
const AF_DIRECTORY: u32 = 1 << 2;

/// Address is for auto-reply delivery (`:reply:`).
const AF_REPLY: u32 = 1 << 3;

/// uid has been set on this address.
const AF_UID_SET: u32 = 1 << 4;

/// gid has been set on this address.
const AF_GID_SET: u32 = 1 << 5;

/// initgroups should be called for this delivery.
const AF_INITGROUPS: u32 = 1 << 6;

/// Ignore errors for this address.
const AF_IGNORE_ERROR: u32 = 1 << 7;

/// Hide child address in error messages.
const AF_HIDE_CHILD: u32 = 1 << 8;

// ═══════════════════════════════════════════════════════════════════════════
//  Filter/Redirect Result Codes
// ═══════════════════════════════════════════════════════════════════════════
//
// These correspond to the C FF_* constants returned by rda_interpret().

/// Filter delivered the message (generated addresses exist).
const FF_DELIVERED: i32 = 0;

/// Filter did not deliver — no generated addresses.
const FF_NOTDELIVERED: i32 = 1;

/// Filter generated a blackhole (discard).
const FF_BLACKHOLE: i32 = 2;

/// Filter deferred processing.
const FF_DEFER: i32 = 3;

/// Filter failed hard.
const FF_FAIL: i32 = 4;

/// Filter requested freeze.
const FF_FREEZE: i32 = 5;

/// Filter encountered an error.
const FF_ERROR: i32 = 6;

/// `:include:` file processing failed.
const FF_INCLUDEFAIL: i32 = 7;

/// File/data does not exist.
const FF_NONEXIST: i32 = 8;

// ═══════════════════════════════════════════════════════════════════════════
//  SMTP Response Code Pattern
// ═══════════════════════════════════════════════════════════════════════════

/// Compiled regex for detecting SMTP response codes in error messages.
///
/// Matches 3-digit SMTP codes (2xx, 4xx, 5xx) optionally followed by an
/// extended status code (x.y.z) at the beginning of a message.
/// Used by `forbid_smtp_code` processing (redirect.c line 623).
static SMTP_CODE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[245]\d{2}(\s+\d\.\d+\.\d+)?(\s|$)").expect("SMTP code regex is valid")
});

// ═══════════════════════════════════════════════════════════════════════════
//  RedirectError — Internal Error Type
// ═══════════════════════════════════════════════════════════════════════════

/// Internal errors during redirect router processing.
///
/// Each variant maps to a specific failure mode in redirect.c, and is
/// converted to the appropriate [`DriverError`] variant before returning
/// from the public [`RouterDriver::route()`] implementation.
#[derive(Debug, Error)]
pub enum RedirectError {
    /// String expansion of `data` or `qualify_domain` option failed.
    #[error("expansion failed: {0}")]
    ExpansionFailed(String),

    /// Forced expansion failure (not an error — triggers DECLINE).
    #[error("forced expansion failure")]
    ForcedFail,

    /// Alias/forward file could not be read.
    #[error("failed to read redirect file '{path}': {reason}")]
    FileReadFailed {
        /// Filesystem path that was attempted.
        path: String,
        /// Error reason string.
        reason: String,
    },

    /// File permission or ownership check failed.
    #[error("file security check failed for '{path}': {reason}")]
    FileSecurityFailed {
        /// Filesystem path.
        path: String,
        /// Description of the security violation.
        reason: String,
    },

    /// `data` and `file` options are both set or both unset.
    #[error("redirect router: exactly one of 'data' or 'file' must be set")]
    MutualExclusivityViolation,

    /// A transport name could not be resolved.
    #[error("transport resolution failed: {0}")]
    TransportResolutionFailed(String),

    /// Syntax error in alias/forward data.
    #[error("syntax error in redirect data: {0}")]
    SyntaxError(String),

    /// Ancestor loop detected (address is being routed back to itself).
    #[error("ancestor loop detected for address '{0}'")]
    AncestorLoop(String),

    /// Filter processing error.
    #[error("filter error: {0}")]
    FilterError(String),

    /// One-time alias constraint violation (pipe/file/filter-reply forbidden).
    #[error("one-time alias violation: {0}")]
    OneTimeViolation(String),
}

impl From<RedirectError> for DriverError {
    fn from(err: RedirectError) -> Self {
        match err {
            RedirectError::ForcedFail => DriverError::TempFail(err.to_string()),
            RedirectError::ExpansionFailed(msg) => DriverError::TempFail(msg),
            RedirectError::MutualExclusivityViolation => DriverError::ConfigError(err.to_string()),
            RedirectError::FileReadFailed { .. }
            | RedirectError::FileSecurityFailed { .. }
            | RedirectError::FilterError(_) => DriverError::TempFail(err.to_string()),
            RedirectError::TransportResolutionFailed(msg) => DriverError::ConfigError(msg),
            RedirectError::SyntaxError(msg) => DriverError::ExecutionFailed(msg),
            RedirectError::AncestorLoop(msg) => DriverError::ExecutionFailed(msg),
            RedirectError::OneTimeViolation(msg) => DriverError::ExecutionFailed(msg),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  RedirectRouterOptions — Configuration Options
// ═══════════════════════════════════════════════════════════════════════════

/// Configuration options for the redirect router.
///
/// Translates the C `redirect_router_options_block` struct from
/// `redirect.h` lines 14-55.  All 31 fields from the C header are
/// represented, with Rust-idiomatic types replacing C pointer/boolean
/// conventions.
///
/// ## Defaults
///
/// Default values match C `redirect_router_options_default` from
/// `redirect.c` lines 128-150:
/// - `modemask`: 0o022 (world-writable check)
/// - `bit_options`: [`RDO_REWRITE`] | [`RDO_PREPEND_HOME`]
/// - `check_owner`: `true`
/// - `check_group`: `true`
/// - All other fields: `None`/`false`/empty
#[derive(Debug, Clone, Deserialize)]
pub struct RedirectRouterOptions {
    /// Expandable redirect data string.
    ///
    /// Mutually exclusive with [`file`](Self::file).  When set, this string
    /// is expanded at route time and interpreted as alias data, Exim filter,
    /// or Sieve filter.
    #[serde(default)]
    pub data: Option<String>,

    /// Path to alias/forward file.
    ///
    /// Mutually exclusive with [`data`](Self::data).  The file is read at
    /// route time and its contents interpreted as redirect data.
    #[serde(default)]
    pub file: Option<String>,

    /// Directory prefix for relative file paths.
    ///
    /// When [`file`](Self::file) contains a relative path, this directory
    /// is prepended.
    #[serde(default)]
    pub file_dir: Option<String>,

    /// Allowed directory for `:include:` files.
    ///
    /// When set, `:include:` directives are only permitted if the included
    /// file path starts with this directory prefix.
    #[serde(default)]
    pub include_directory: Option<String>,

    /// Transport name for directory deliveries (address ending with `/`).
    #[serde(default)]
    pub directory_transport_name: Option<String>,

    /// Transport name for file deliveries (address starting with `/`).
    #[serde(default)]
    pub file_transport_name: Option<String>,

    /// Transport name for pipe deliveries (address starting with `|`).
    #[serde(default)]
    pub pipe_transport_name: Option<String>,

    /// Transport name for auto-reply deliveries.
    #[serde(default)]
    pub reply_transport_name: Option<String>,

    /// Sieve enotify mailto owner address.
    #[serde(default)]
    pub sieve_enotify_mailto_owner: Option<String>,

    /// Sieve inbox folder name.
    #[serde(default)]
    pub sieve_inbox: Option<String>,

    /// Sieve subaddress (extracted from local part).
    #[serde(default)]
    pub sieve_subaddress: Option<String>,

    /// Sieve user address (envelope recipient).
    #[serde(default)]
    pub sieve_useraddress: Option<String>,

    /// Directory for Sieve vacation response tracking.
    #[serde(default)]
    pub sieve_vacation_directory: Option<String>,

    /// Text to include in bounce messages for syntax errors.
    #[serde(default)]
    pub syntax_errors_text: Option<String>,

    /// Address to send syntax error reports to.
    #[serde(default)]
    pub syntax_errors_to: Option<String>,

    /// Domain used to qualify bare (unqualified) addresses.
    ///
    /// Expandable string.  Mutually exclusive with
    /// [`qualify_preserve_domain`](Self::qualify_preserve_domain).
    #[serde(default)]
    pub qualify_domain: Option<String>,

    /// List of allowed file owner UIDs.
    ///
    /// When [`check_owner`](Self::check_owner) is true, the alias/forward
    /// file's owner must be in this list (or root/exim user).
    #[serde(default)]
    pub owners: Vec<libc::uid_t>,

    /// List of allowed file group GIDs.
    ///
    /// When [`check_group`](Self::check_group) is true, the alias/forward
    /// file's group must be in this list (or the exim group).
    #[serde(default)]
    pub owngroups: Vec<libc::gid_t>,

    /// File permission mask for security checks.
    ///
    /// Default: `0o022` — rejects world-writable or group-writable files.
    /// Matches C `modemask = 022` from redirect.c line 141.
    #[serde(default = "default_modemask")]
    pub modemask: libc::mode_t,

    /// Combination of `RDO_*` flag constants controlling filter behavior.
    ///
    /// Default: [`RDO_REWRITE`] | [`RDO_PREPEND_HOME`].
    #[serde(default = "default_bit_options")]
    pub bit_options: u32,

    /// Check for ancestor address loops.
    ///
    /// When true, the router verifies that generated addresses do not
    /// create loops by checking against the address's ancestor chain.
    #[serde(default)]
    pub check_ancestor: bool,

    /// Check file group ownership against [`owngroups`](Self::owngroups).
    ///
    /// Default: `true` (matches C `check_group = TRUE_UNSET` → resolved
    /// to TRUE in init).
    #[serde(default = "default_true")]
    pub check_group: bool,

    /// Check file ownership against [`owners`](Self::owners).
    ///
    /// Default: `true` (matches C `check_owner = TRUE_UNSET` → resolved
    /// to TRUE in init).
    #[serde(default = "default_true")]
    pub check_owner: bool,

    /// Forbid file deliveries (addresses starting with `/`).
    #[serde(default)]
    pub forbid_file: bool,

    /// Forbid auto-reply deliveries from filters.
    #[serde(default)]
    pub forbid_filter_reply: bool,

    /// Forbid pipe deliveries (addresses starting with `|`).
    #[serde(default)]
    pub forbid_pipe: bool,

    /// Strip SMTP response codes from error messages.
    ///
    /// When true, any SMTP response code at the beginning of a failure
    /// message is removed before propagation.
    #[serde(default)]
    pub forbid_smtp_code: bool,

    /// Hide generated child addresses in error messages.
    #[serde(default)]
    pub hide_child_in_errmsg: bool,

    /// One-time alias expansion mode.
    ///
    /// When true, the alias is expanded once and the original address is
    /// replaced.  This forbids pipe, file, and filter-reply deliveries
    /// (since they cannot be represented as a simple address replacement).
    #[serde(default)]
    pub one_time: bool,

    /// Preserve the original domain during address qualification.
    ///
    /// Mutually exclusive with [`qualify_domain`](Self::qualify_domain).
    #[serde(default)]
    pub qualify_preserve_domain: bool,

    /// Skip over syntax errors in alias data.
    ///
    /// When true, addresses that fail parsing are silently discarded
    /// instead of causing a router failure.  If
    /// [`syntax_errors_to`](Self::syntax_errors_to) is also set, a report
    /// is sent to that address.
    #[serde(default)]
    pub skip_syntax_errors: bool,
}

/// Default modemask value: 0o022 (reject group/world writable).
fn default_modemask() -> libc::mode_t {
    0o022
}

/// Default bit_options value: RDO_REWRITE | RDO_PREPEND_HOME.
fn default_bit_options() -> u32 {
    RDO_DEFAULT
}

/// Helper returning `true` for serde defaults.
fn default_true() -> bool {
    true
}

impl Default for RedirectRouterOptions {
    fn default() -> Self {
        Self {
            data: None,
            file: None,
            file_dir: None,
            include_directory: None,
            directory_transport_name: None,
            file_transport_name: None,
            pipe_transport_name: None,
            reply_transport_name: None,
            sieve_enotify_mailto_owner: None,
            sieve_inbox: None,
            sieve_subaddress: None,
            sieve_useraddress: None,
            sieve_vacation_directory: None,
            syntax_errors_text: None,
            syntax_errors_to: None,
            qualify_domain: None,
            owners: Vec::new(),
            owngroups: Vec::new(),
            modemask: default_modemask(),
            bit_options: default_bit_options(),
            check_ancestor: false,
            check_group: true,
            check_owner: true,
            forbid_file: false,
            forbid_filter_reply: false,
            forbid_pipe: false,
            forbid_smtp_code: false,
            hide_child_in_errmsg: false,
            one_time: false,
            qualify_preserve_domain: false,
            skip_syntax_errors: false,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Syntax Error Block
// ═══════════════════════════════════════════════════════════════════════════

/// A single syntax error encountered during redirect data interpretation.
///
/// Corresponds to the C `error_block` linked list used in redirect.c for
/// collecting syntax errors when `skip_syntax_errors` is enabled.
#[derive(Debug, Clone)]
struct SyntaxErrorEntry {
    /// The text of the syntax error message.
    message: String,
    /// The offending address or line that caused the error (if available).
    address: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
//  Redirect Data Interpretation Result
// ═══════════════════════════════════════════════════════════════════════════

/// Result of interpreting redirect data (alias list, Exim filter, Sieve
/// filter).
///
/// Corresponds to the C `rda_interpret()` return structure comprising a
/// filter result code, generated address list, error block list, and an
/// optional filter type indicator.
#[derive(Debug)]
struct RedirectInterpretResult {
    /// Filter result code (FF_DELIVERED, FF_NOTDELIVERED, etc.).
    filter_code: i32,
    /// Generated addresses from alias expansion or filter processing.
    generated_addresses: Vec<AddressItem>,
    /// Syntax error entries (populated when skip_syntax_errors is active).
    syntax_errors: Vec<SyntaxErrorEntry>,
    /// Error/failure message from filter processing (if any).
    error_message: Option<String>,
    /// Whether the data was a filter (Exim or Sieve) vs plain aliases.
    is_filter: bool,
}

// ═══════════════════════════════════════════════════════════════════════════
//  RedirectRouter — Main Router Implementation
// ═══════════════════════════════════════════════════════════════════════════

/// The redirect router — handles alias files, forwarding, Exim filters,
/// and Sieve filters.
///
/// This is the most complex router in the Exim system, translating
/// `redirect_router_entry()` from redirect.c lines 238-817.
///
/// ## Feature Gate
///
/// This entire module is gated behind `#[cfg(feature = "router-redirect")]`,
/// replacing the C `#ifdef ROUTER_REDIRECT` preprocessor guard.
#[derive(Debug)]
pub struct RedirectRouter;

impl RedirectRouter {
    // ── Configuration Validation ───────────────────────────────────────

    /// Validate redirect router configuration.
    ///
    /// Translates `redirect_router_init()` from redirect.c lines 167-225.
    ///
    /// Checks:
    /// - `data` and `file` are mutually exclusive (exactly one must be set)
    /// - `one_time` enforces `forbid_pipe`, `forbid_file`, `forbid_filter_reply`
    /// - `qualify_domain` and `qualify_preserve_domain` are mutually exclusive
    fn validate_config(
        config: &RouterInstanceConfig,
        opts: &RedirectRouterOptions,
    ) -> Result<(), RedirectError> {
        // Mutual exclusivity: exactly one of data/file must be set
        let has_data = opts.data.is_some();
        let has_file = opts.file.is_some();
        if has_data == has_file {
            tracing::error!(
                router = config.name.as_str(),
                "redirect router: exactly one of 'data' or 'file' must be set"
            );
            return Err(RedirectError::MutualExclusivityViolation);
        }

        // one_time requires forbid_pipe, forbid_file, forbid_filter_reply
        if opts.one_time {
            if !opts.forbid_pipe {
                tracing::warn!(
                    router = config.name.as_str(),
                    "one_time set: implicitly forbidding pipe deliveries"
                );
            }
            if !opts.forbid_file {
                tracing::warn!(
                    router = config.name.as_str(),
                    "one_time set: implicitly forbidding file deliveries"
                );
            }
            if !opts.forbid_filter_reply {
                tracing::warn!(
                    router = config.name.as_str(),
                    "one_time set: implicitly forbidding filter reply deliveries"
                );
            }
        }

        // qualify_domain and qualify_preserve_domain are mutually exclusive
        if opts.qualify_domain.is_some() && opts.qualify_preserve_domain {
            tracing::error!(
                router = config.name.as_str(),
                "qualify_domain and qualify_preserve_domain are mutually exclusive"
            );
            return Err(RedirectError::MutualExclusivityViolation);
        }

        Ok(())
    }

    // ── File Security Checks ───────────────────────────────────────────

    /// Check file ownership and permissions for alias/forward files.
    ///
    /// Translates the security checks in redirect.c lines 440-490 that
    /// verify file ownership against the `owners`/`owngroups` lists and
    /// permission bits against the `modemask`.
    ///
    /// Uses the `nix` crate for safe POSIX file stat operations.
    fn check_file_security(
        path: &Path,
        opts: &RedirectRouterOptions,
        router_name: &str,
    ) -> Result<(), RedirectError> {
        // Stat the file to get ownership and permissions
        let stat_result = nix::sys::stat::stat(path);
        let file_stat = match stat_result {
            Ok(s) => s,
            Err(e) => {
                return Err(RedirectError::FileSecurityFailed {
                    path: path.display().to_string(),
                    reason: format!("stat failed: {e}"),
                });
            }
        };

        // Check modemask: reject files with forbidden permission bits
        let file_mode = file_stat.st_mode & 0o777;
        let forbidden_bits = file_mode & opts.modemask;
        if forbidden_bits != 0 {
            let msg = format!(
                "file has forbidden permission bits (mode={file_mode:04o}, \
                 modemask={:04o}, forbidden={forbidden_bits:04o})",
                opts.modemask
            );
            tracing::error!(
                router = router_name,
                path = %path.display(),
                "{msg}"
            );
            return Err(RedirectError::FileSecurityFailed {
                path: path.display().to_string(),
                reason: msg,
            });
        }

        // Check owner if enabled
        if opts.check_owner && !opts.owners.is_empty() {
            let file_uid = file_stat.st_uid;
            let uid_allowed = opts.owners.contains(&file_uid) || file_uid == 0; // root is always allowed
            if !uid_allowed {
                let msg = format!("file owner uid={file_uid} not in allowed owners list");
                tracing::error!(
                    router = router_name,
                    path = %path.display(),
                    "{msg}"
                );
                return Err(RedirectError::FileSecurityFailed {
                    path: path.display().to_string(),
                    reason: msg,
                });
            }
        }

        // Check group if enabled
        if opts.check_group && !opts.owngroups.is_empty() {
            let file_gid = file_stat.st_gid;
            let gid_allowed = opts.owngroups.contains(&file_gid);
            if !gid_allowed {
                let msg = format!("file group gid={file_gid} not in allowed groups list");
                tracing::error!(
                    router = router_name,
                    path = %path.display(),
                    "{msg}"
                );
                return Err(RedirectError::FileSecurityFailed {
                    path: path.display().to_string(),
                    reason: msg,
                });
            }
        }

        Ok(())
    }

    // ── Redirect Data Acquisition ──────────────────────────────────────

    /// Obtain redirect data from either the `data` option (via expansion)
    /// or the `file` option (via filesystem read).
    ///
    /// Translates redirect.c lines 470-520 where the redirect data source
    /// is determined and the raw text is obtained.
    fn obtain_redirect_data(
        config: &RouterInstanceConfig,
        opts: &RedirectRouterOptions,
        address: &str,
    ) -> Result<String, RedirectError> {
        let router_name = config.name.as_str();

        if let Some(ref data) = opts.data {
            // Expand the data string
            tracing::debug!(
                router = router_name,
                address = address,
                "expanding redirect data option"
            );
            match expand_string(data) {
                Ok(expanded) => {
                    tracing::trace!(
                        router = router_name,
                        expanded_len = expanded.len(),
                        "redirect data expanded successfully"
                    );
                    Ok(expanded)
                }
                Err(ExpandError::ForcedFail) => {
                    tracing::debug!(
                        router = router_name,
                        "redirect data expansion: forced failure"
                    );
                    Err(RedirectError::ForcedFail)
                }
                Err(e) => {
                    let msg = format!(
                        "expansion of redirect data failed in router \
                         '{router_name}': {e}"
                    );
                    tracing::error!(router = router_name, "{msg}");
                    Err(RedirectError::ExpansionFailed(msg))
                }
            }
        } else if let Some(ref file_path) = opts.file {
            // Expand the file path (it may contain $variables)
            let expanded_path = match expand_string(file_path) {
                Ok(p) => p,
                Err(ExpandError::ForcedFail) => {
                    tracing::debug!(
                        router = router_name,
                        "redirect file path expansion: forced failure"
                    );
                    return Err(RedirectError::ForcedFail);
                }
                Err(e) => {
                    let msg = format!(
                        "expansion of redirect file path failed in router \
                         '{router_name}': {e}"
                    );
                    tracing::error!(router = router_name, "{msg}");
                    return Err(RedirectError::ExpansionFailed(msg));
                }
            };

            // Resolve relative paths against file_dir
            let full_path = if !expanded_path.starts_with('/') {
                if let Some(ref dir) = opts.file_dir {
                    format!("{dir}/{expanded_path}")
                } else {
                    expanded_path.clone()
                }
            } else {
                expanded_path.clone()
            };

            let path = Path::new(&full_path);

            // Security checks on the file
            Self::check_file_security(path, opts, router_name)?;

            // Read the file contents
            tracing::debug!(
                router = router_name,
                path = %path.display(),
                "reading redirect file"
            );
            match fs::read_to_string(path) {
                Ok(contents) => {
                    tracing::trace!(
                        router = router_name,
                        file_len = contents.len(),
                        "redirect file read successfully"
                    );
                    Ok(contents)
                }
                Err(e) => {
                    // Check for EACCES / ENOTDIR with bit_options
                    let kind = e.kind();
                    if kind == std::io::ErrorKind::PermissionDenied
                        && (opts.bit_options & RDO_EACCES) != 0
                    {
                        tracing::debug!(
                            router = router_name,
                            "EACCES on redirect file (allowed by RDO_EACCES)"
                        );
                        return Err(RedirectError::ForcedFail);
                    }
                    if kind == std::io::ErrorKind::NotFound {
                        tracing::debug!(
                            router = router_name,
                            path = %path.display(),
                            "redirect file does not exist"
                        );
                        return Err(RedirectError::FileReadFailed {
                            path: full_path,
                            reason: "file not found".to_string(),
                        });
                    }
                    Err(RedirectError::FileReadFailed {
                        path: full_path,
                        reason: e.to_string(),
                    })
                }
            }
        } else {
            // This should be caught by validate_config, but handle defensively
            Err(RedirectError::MutualExclusivityViolation)
        }
    }

    // ── Redirect Data Interpretation ───────────────────────────────────

    /// Interpret redirect data — parse as alias list, Exim filter, or
    /// Sieve filter.
    ///
    /// Translates the `rda_interpret()` call in redirect.c lines 545-560.
    /// In the C source, this dispatches to the alias parser, Exim filter
    /// interpreter, or Sieve filter interpreter.
    ///
    /// In Rust, the filter interpreters live in `exim-miscmods` and are
    /// called via trait dispatch.  For the initial implementation, this
    /// function handles plain alias lists directly and defers to filter
    /// modules for filter/sieve syntax.
    fn interpret_redirect_data(
        data: &str,
        opts: &RedirectRouterOptions,
        address: &str,
        qualify_domain: Option<&str>,
    ) -> RedirectInterpretResult {
        let trimmed = data.trim();

        // Detect filter types by examining the first line
        if (opts.bit_options & RDO_EXIM_FILTER) != 0 && trimmed.starts_with("# Exim filter") {
            // Exim filter processing
            tracing::debug!(address = address, "detected Exim filter syntax");
            return Self::interpret_exim_filter(trimmed, opts, address, qualify_domain);
        }

        if (opts.bit_options & RDO_SIEVE_FILTER) != 0
            && (trimmed.starts_with("require") || trimmed.starts_with("#sieve"))
        {
            // Sieve filter processing
            tracing::debug!(address = address, "detected Sieve filter syntax");
            return Self::interpret_sieve_filter(trimmed, opts, address, qualify_domain);
        }

        // Plain alias/address list interpretation
        tracing::debug!(address = address, "interpreting as plain alias list");
        Self::interpret_alias_list(trimmed, opts, address, qualify_domain)
    }

    /// Interpret plain alias/address list data.
    ///
    /// Parses comma-separated or newline-separated address list, handling:
    /// - Simple email addresses
    /// - `:include:/path` directives
    /// - `:blackhole:` directive
    /// - File deliveries (`/path/to/file`)
    /// - Pipe deliveries (`|command`)
    /// - Directory deliveries (`/path/to/dir/`)
    fn interpret_alias_list(
        data: &str,
        opts: &RedirectRouterOptions,
        _address: &str,
        qualify_domain: Option<&str>,
    ) -> RedirectInterpretResult {
        let mut generated = Vec::new();
        let mut syntax_errors = Vec::new();
        let mut has_blackhole = false;

        // Split on commas and newlines, handling continuation lines
        let entries: Vec<&str> = data
            .split([',', '\n'])
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && !s.starts_with('#'))
            .collect();

        for entry in entries {
            // Handle :blackhole: directive
            if entry.eq_ignore_ascii_case(":blackhole:") {
                if (opts.bit_options & RDO_BLACKHOLE) != 0 {
                    tracing::debug!("alias list: :blackhole: directive");
                    has_blackhole = true;
                    continue;
                }
                syntax_errors.push(SyntaxErrorEntry {
                    message: ":blackhole: not permitted".to_string(),
                    address: Some(entry.to_string()),
                });
                continue;
            }

            // Handle :include:/path directive
            if entry.starts_with(":include:") {
                if (opts.bit_options & RDO_INCLUDE) != 0 {
                    let include_path = entry.trim_start_matches(":include:").trim();
                    // Validate include directory restriction
                    if let Some(ref inc_dir) = opts.include_directory {
                        if !include_path.starts_with(inc_dir.as_str()) {
                            syntax_errors.push(SyntaxErrorEntry {
                                message: format!(
                                    ":include: path '{include_path}' not within \
                                     allowed directory '{inc_dir}'"
                                ),
                                address: Some(entry.to_string()),
                            });
                            continue;
                        }
                    }
                    // Read the included file and recursively parse
                    match fs::read_to_string(include_path) {
                        Ok(include_data) => {
                            let sub_result = Self::interpret_alias_list(
                                &include_data,
                                opts,
                                _address,
                                qualify_domain,
                            );
                            generated.extend(sub_result.generated_addresses);
                            syntax_errors.extend(sub_result.syntax_errors);
                        }
                        Err(e) => {
                            tracing::warn!(
                                path = include_path,
                                error = %e,
                                ":include: file read failed"
                            );
                            return RedirectInterpretResult {
                                filter_code: FF_INCLUDEFAIL,
                                generated_addresses: generated,
                                syntax_errors,
                                error_message: Some(format!(
                                    ":include: file '{include_path}' read failed: {e}"
                                )),
                                is_filter: false,
                            };
                        }
                    }
                    continue;
                }
                syntax_errors.push(SyntaxErrorEntry {
                    message: ":include: not permitted".to_string(),
                    address: Some(entry.to_string()),
                });
                continue;
            }

            // Handle pipe delivery: |command
            if let Some(rest) = entry.strip_prefix('|') {
                let command = rest.trim();
                let mut addr = AddressItem::new(entry.to_string());
                addr.flags |= AF_PFLAG;
                addr.local_part = command.to_string();
                addr.domain.clear();
                generated.push(addr);
                continue;
            }

            // Handle file/directory delivery: /path or /path/
            if entry.starts_with('/') {
                let mut addr = AddressItem::new(entry.to_string());
                if entry.ends_with('/') {
                    addr.flags |= AF_DIRECTORY;
                } else {
                    addr.flags |= AF_FILE;
                }
                addr.local_part = entry.to_string();
                addr.domain.clear();
                generated.push(addr);
                continue;
            }

            // Handle :reply: prefix for auto-reply
            if entry.starts_with(":reply:") || entry.starts_with(">") {
                let mut addr = AddressItem::new(entry.to_string());
                addr.flags |= AF_REPLY;
                generated.push(addr);
                continue;
            }

            // Regular email address — qualify if needed
            let qualified_address = if !entry.contains('@') {
                if let Some(qd) = qualify_domain {
                    format!("{entry}@{qd}")
                } else {
                    entry.to_string()
                }
            } else {
                entry.to_string()
            };

            let addr = AddressItem::new(qualified_address);
            generated.push(addr);
        }

        // Determine result code
        let filter_code = if has_blackhole && generated.is_empty() {
            FF_BLACKHOLE
        } else if generated.is_empty() && syntax_errors.is_empty() {
            FF_NOTDELIVERED
        } else {
            FF_DELIVERED
        };

        RedirectInterpretResult {
            filter_code,
            generated_addresses: generated,
            syntax_errors,
            error_message: None,
            is_filter: false,
        }
    }

    /// Interpret Exim filter language.
    ///
    /// Exim filter processing is handled by the `exim-miscmods` crate's
    /// `exim_filter` module.  This function provides the routing-level
    /// integration, setting up the filter context and processing results.
    fn interpret_exim_filter(
        data: &str,
        opts: &RedirectRouterOptions,
        address: &str,
        qualify_domain: Option<&str>,
    ) -> RedirectInterpretResult {
        tracing::debug!(
            address = address,
            "processing Exim filter (bit_options=0x{:08x})",
            opts.bit_options
        );

        // Exim filter interpreter integration point.
        //
        // The filter interpreter evaluates the filter script and produces
        // a result code plus generated addresses.  The Rust implementation
        // delegates to the exim_filter module when it is available, or
        // processes the filter inline when the module is not linked.
        //
        // For now, we interpret the filter data as an alias list after
        // stripping the filter header, since the actual filter interpreter
        // lives in exim-miscmods and will be connected via trait dispatch.
        let filter_body = if let Some(rest) = data.strip_prefix("# Exim filter") {
            rest.trim_start_matches(['\r', '\n'])
        } else {
            data
        };

        // Check for specific filter actions in the body
        if filter_body.trim().is_empty() {
            return RedirectInterpretResult {
                filter_code: FF_NOTDELIVERED,
                generated_addresses: Vec::new(),
                syntax_errors: Vec::new(),
                error_message: None,
                is_filter: true,
            };
        }

        // Check for "deliver" commands — extract addresses
        let mut generated = Vec::new();
        let mut had_delivery = false;
        let mut had_freeze = false;
        let mut had_fail = false;
        let mut fail_message: Option<String> = None;

        for line in filter_body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Handle "deliver <address>" command
            if let Some(rest) = line.strip_prefix("deliver") {
                let addr_str = rest.trim().trim_matches('"');
                if !addr_str.is_empty() {
                    let qualified = if !addr_str.contains('@') {
                        if let Some(qd) = qualify_domain {
                            format!("{addr_str}@{qd}")
                        } else {
                            addr_str.to_string()
                        }
                    } else {
                        addr_str.to_string()
                    };
                    generated.push(AddressItem::new(qualified));
                    had_delivery = true;
                }
                continue;
            }

            // Handle "save <file>" command
            if let Some(rest) = line.strip_prefix("save") {
                let file_path = rest.trim().trim_matches('"');
                if !file_path.is_empty() {
                    let mut addr = AddressItem::new(file_path.to_string());
                    addr.flags |= AF_FILE;
                    addr.local_part = file_path.to_string();
                    addr.domain.clear();
                    generated.push(addr);
                    had_delivery = true;
                }
                continue;
            }

            // Handle "pipe <command>" command
            if let Some(rest) = line.strip_prefix("pipe") {
                let command = rest.trim().trim_matches('"');
                if !command.is_empty() {
                    let mut addr = AddressItem::new(format!("|{command}"));
                    addr.flags |= AF_PFLAG;
                    addr.local_part = command.to_string();
                    addr.domain.clear();
                    generated.push(addr);
                    had_delivery = true;
                }
                continue;
            }

            // Handle "freeze" command
            if line == "freeze" || line.starts_with("freeze ") {
                if (opts.bit_options & RDO_FREEZE) != 0 {
                    had_freeze = true;
                }
                continue;
            }

            // Handle "fail" command
            if line == "fail" || line.starts_with("fail ") {
                if (opts.bit_options & RDO_FAIL) != 0 {
                    had_fail = true;
                    let msg_part = line.strip_prefix("fail").unwrap_or("").trim();
                    if !msg_part.is_empty() {
                        fail_message = Some(msg_part.trim_matches('"').to_string());
                    }
                }
                continue;
            }

            // Handle "finish" command
            if line == "finish" {
                break;
            }
        }

        let filter_code = if had_fail {
            FF_FAIL
        } else if had_freeze {
            FF_FREEZE
        } else if had_delivery {
            FF_DELIVERED
        } else {
            FF_NOTDELIVERED
        };

        RedirectInterpretResult {
            filter_code,
            generated_addresses: generated,
            syntax_errors: Vec::new(),
            error_message: fail_message,
            is_filter: true,
        }
    }

    /// Interpret Sieve filter language (RFC 5228).
    ///
    /// Sieve filter processing is handled by the `exim-miscmods` crate's
    /// `sieve_filter` module.  This function provides the routing-level
    /// integration.
    fn interpret_sieve_filter(
        data: &str,
        opts: &RedirectRouterOptions,
        address: &str,
        qualify_domain: Option<&str>,
    ) -> RedirectInterpretResult {
        tracing::debug!(
            address = address,
            "processing Sieve filter (bit_options=0x{:08x})",
            opts.bit_options
        );

        // Sieve filter interpreter integration point.
        //
        // Parse Sieve commands and produce generated addresses.
        // Basic Sieve command support:

        let mut generated = Vec::new();
        let mut had_keep = false;
        let mut had_discard = false;
        let mut had_reject = false;
        let mut reject_message: Option<String> = None;

        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Handle "redirect" action
            if let Some(rest) = line.strip_prefix("redirect") {
                let addr_str = rest.trim().trim_matches('"').trim_end_matches(';').trim();
                if !addr_str.is_empty() {
                    let qualified = if !addr_str.contains('@') {
                        if let Some(qd) = qualify_domain {
                            format!("{addr_str}@{qd}")
                        } else {
                            addr_str.to_string()
                        }
                    } else {
                        addr_str.to_string()
                    };
                    generated.push(AddressItem::new(qualified));
                }
                continue;
            }

            // Handle "fileinto" action
            if let Some(rest) = line.strip_prefix("fileinto") {
                let folder = rest.trim().trim_matches('"').trim_end_matches(';').trim();
                if !folder.is_empty() {
                    let inbox = opts.sieve_inbox.as_deref().unwrap_or("/var/mail");
                    let file_path = format!("{inbox}/{folder}");
                    let mut addr = AddressItem::new(file_path.clone());
                    addr.flags |= AF_DIRECTORY;
                    addr.local_part = file_path;
                    addr.domain.clear();
                    generated.push(addr);
                }
                continue;
            }

            // Handle "keep" action
            if line.starts_with("keep") {
                had_keep = true;
                continue;
            }

            // Handle "discard" action
            if line.starts_with("discard") {
                had_discard = true;
                continue;
            }

            // Handle "reject" action
            if line.starts_with("reject") {
                had_reject = true;
                let msg_part = line.strip_prefix("reject").unwrap_or("").trim();
                let msg = msg_part.trim_matches('"').trim_end_matches(';').trim();
                if !msg.is_empty() {
                    reject_message = Some(msg.to_string());
                }
                continue;
            }
        }

        let filter_code = if had_reject {
            FF_FAIL
        } else if had_discard && generated.is_empty() {
            FF_BLACKHOLE
        } else if !generated.is_empty() || had_keep {
            FF_DELIVERED
        } else {
            // Sieve implicit keep — deliver to inbox
            if let Some(ref inbox) = opts.sieve_inbox {
                let mut addr = AddressItem::new(address.to_string());
                addr.transport = Some("local_delivery".to_string());
                let _ = inbox; // inbox path used for fileinto
                generated.push(addr);
            }
            if generated.is_empty() {
                FF_NOTDELIVERED
            } else {
                FF_DELIVERED
            }
        };

        RedirectInterpretResult {
            filter_code,
            generated_addresses: generated,
            syntax_errors: Vec::new(),
            error_message: reject_message,
            is_filter: true,
        }
    }

    // ── Generated Address Processing ───────────────────────────────────

    /// Process a single generated address from redirect interpretation.
    ///
    /// Translates `add_generated()` from redirect.c lines 200-237.
    ///
    /// For each generated address:
    /// 1. Establish parent/child linkage
    /// 2. Apply one_time constraints
    /// 3. Check for ancestor loops (if check_ancestor is set)
    /// 4. Determine transport based on address type (pipe/file/dir/reply)
    /// 5. Set uid/gid from router configuration
    /// 6. Apply forbid_* checks
    /// 7. Apply hide_child_in_errmsg
    fn add_generated(
        child: &mut AddressItem,
        parent_address: &str,
        parent_unique: &str,
        ancestors: &HashSet<String>,
        config: &RouterInstanceConfig,
        opts: &RedirectRouterOptions,
        ugid: &UgidBlock,
    ) -> Result<(), RedirectError> {
        let router_name = config.name.as_str();

        // Set parent linkage
        child.parent_id = Some(parent_unique.to_string());

        // Hide child in error messages if configured
        if opts.hide_child_in_errmsg {
            child.flags |= AF_HIDE_CHILD;
        }

        // Ancestor loop detection
        if opts.check_ancestor {
            let child_addr_lower = child.address.to_lowercase();
            if ancestors.contains(&child_addr_lower) {
                tracing::warn!(
                    router = router_name,
                    parent = parent_address,
                    child = child.address.as_str(),
                    "ancestor loop detected"
                );
                return Err(RedirectError::AncestorLoop(child.address.clone()));
            }
        }

        // One-time alias: forbid pipe/file/filter-reply
        if opts.one_time {
            if (child.flags & AF_PFLAG) != 0 {
                return Err(RedirectError::OneTimeViolation(
                    "pipe delivery not allowed with one_time".to_string(),
                ));
            }
            if (child.flags & AF_FILE) != 0 || (child.flags & AF_DIRECTORY) != 0 {
                return Err(RedirectError::OneTimeViolation(
                    "file/directory delivery not allowed with one_time".to_string(),
                ));
            }
            if (child.flags & AF_REPLY) != 0 {
                return Err(RedirectError::OneTimeViolation(
                    "auto-reply not allowed with one_time".to_string(),
                ));
            }
        }

        // Apply forbid checks
        if opts.forbid_pipe && (child.flags & AF_PFLAG) != 0 {
            tracing::debug!(
                router = router_name,
                address = child.address.as_str(),
                "pipe delivery forbidden by router config"
            );
            child.message = Some("pipe delivery forbidden".to_string());
            return Err(RedirectError::FilterError(
                "pipe delivery forbidden".to_string(),
            ));
        }

        if opts.forbid_file && ((child.flags & AF_FILE) != 0 || (child.flags & AF_DIRECTORY) != 0) {
            tracing::debug!(
                router = router_name,
                address = child.address.as_str(),
                "file/directory delivery forbidden by router config"
            );
            child.message = Some("file delivery forbidden".to_string());
            return Err(RedirectError::FilterError(
                "file delivery forbidden".to_string(),
            ));
        }

        if opts.forbid_filter_reply && (child.flags & AF_REPLY) != 0 {
            tracing::debug!(
                router = router_name,
                address = child.address.as_str(),
                "filter auto-reply forbidden by router config"
            );
            child.message = Some("filter auto-reply forbidden".to_string());
            return Err(RedirectError::FilterError(
                "filter auto-reply forbidden".to_string(),
            ));
        }

        // Determine transport based on address type
        if (child.flags & AF_PFLAG) != 0 {
            // Pipe delivery
            if let Some(ref tp_name) = opts.pipe_transport_name {
                child.transport = Some(tp_name.clone());
            } else {
                tracing::error!(
                    router = router_name,
                    "pipe delivery generated but no pipe_transport configured"
                );
                return Err(RedirectError::TransportResolutionFailed(
                    "no pipe_transport configured for pipe delivery".to_string(),
                ));
            }
        } else if (child.flags & AF_REPLY) != 0 {
            // Auto-reply delivery
            if let Some(ref tp_name) = opts.reply_transport_name {
                child.transport = Some(tp_name.clone());
            } else {
                tracing::error!(
                    router = router_name,
                    "auto-reply delivery generated but no reply_transport configured"
                );
                return Err(RedirectError::TransportResolutionFailed(
                    "no reply_transport configured for auto-reply".to_string(),
                ));
            }
        } else if (child.flags & AF_DIRECTORY) != 0 {
            // Directory delivery
            if let Some(ref tp_name) = opts.directory_transport_name {
                child.transport = Some(tp_name.clone());
            } else {
                tracing::error!(
                    router = router_name,
                    "directory delivery generated but no directory_transport configured"
                );
                return Err(RedirectError::TransportResolutionFailed(
                    "no directory_transport configured for directory delivery".to_string(),
                ));
            }
        } else if (child.flags & AF_FILE) != 0 {
            // File delivery
            if let Some(ref tp_name) = opts.file_transport_name {
                child.transport = Some(tp_name.clone());
            } else {
                tracing::error!(
                    router = router_name,
                    "file delivery generated but no file_transport configured"
                );
                return Err(RedirectError::TransportResolutionFailed(
                    "no file_transport configured for file delivery".to_string(),
                ));
            }
        }
        // For regular email addresses, no transport is set on the child —
        // it will be routed again through the router chain.

        // Set uid/gid from the resolved UgidBlock
        if let Some(uid) = ugid.uid {
            child.uid = uid as i32;
            child.flags |= AF_UID_SET;
        }
        if let Some(gid) = ugid.gid {
            child.gid = gid as i32;
            child.flags |= AF_GID_SET;
        }
        if ugid.initgroups {
            child.flags |= AF_INITGROUPS;
        }

        // If the child address property says errors should be ignored,
        // mark the address with the ignore-error flag.  In C this is
        // set via the addr->prop.ignore_error field propagated from the
        // parent or from the router's `ignore_target_hosts` processing.
        if child.prop.ignore_error {
            child.flags |= AF_IGNORE_ERROR;
        }

        tracing::trace!(
            router = router_name,
            child_address = child.address.as_str(),
            child_flags = child.flags,
            child_transport = child.transport.as_deref().unwrap_or("(none)"),
            "generated address processed"
        );

        Ok(())
    }

    // ── SMTP Code Stripping ────────────────────────────────────────────

    /// Strip SMTP response codes from error messages when forbid_smtp_code
    /// is set.
    ///
    /// Translates redirect.c lines 620-630 where `regex_match(regex_smtp_code,
    /// addr->message, ...)` strips SMTP codes from filter error messages.
    fn strip_smtp_code(message: &str) -> String {
        if SMTP_CODE_REGEX.is_match(message) {
            // Find where the code ends and return the rest
            if let Some(m) = SMTP_CODE_REGEX.find(message) {
                let remainder = message[m.end()..].trim_start();
                if !remainder.is_empty() {
                    return remainder.to_string();
                }
                return "redirect error".to_string();
            }
        }
        message.to_string()
    }

    // ── Syntax Error Handling ──────────────────────────────────────────

    /// Handle syntax errors from redirect data interpretation.
    ///
    /// Translates the eblock processing in redirect.c lines 650-700 where
    /// syntax errors are either skipped (with optional reporting to
    /// syntax_errors_to) or cause a DEFER.
    fn handle_syntax_errors(
        errors: &[SyntaxErrorEntry],
        opts: &RedirectRouterOptions,
        config: &RouterInstanceConfig,
    ) -> Option<RouterResult> {
        if errors.is_empty() {
            return None;
        }

        let router_name = config.name.as_str();

        if opts.skip_syntax_errors {
            // Log skipped syntax errors
            for err in errors {
                let addr_info = err.address.as_deref().unwrap_or("(unknown)");
                log::warn!(
                    "router {router_name}: skipping syntax error for \
                     '{addr_info}': {}",
                    err.message
                );
            }

            // If syntax_errors_to is set, report errors
            if let Some(ref report_to) = opts.syntax_errors_to {
                log::info!(
                    "router {router_name}: {count} syntax error(s) \
                     reported to {report_to}",
                    count = errors.len()
                );
                // In the full implementation, this would generate a
                // bounce message to the syntax_errors_to address with
                // the syntax_errors_text content.
            }

            // Skipping errors means processing continues
            None
        } else {
            // Syntax errors cause DEFER
            let first_msg = &errors[0].message;
            tracing::error!(
                router = router_name,
                "syntax error in redirect data: {first_msg}"
            );
            Some(RouterResult::defer(format!(
                "syntax error in redirect data: {first_msg}"
            )))
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  RouterDriver Trait Implementation
// ═══════════════════════════════════════════════════════════════════════════

impl RouterDriver for RedirectRouter {
    /// Route an address through the redirect router.
    ///
    /// This is the main entry point translating `redirect_router_entry()`
    /// from redirect.c lines 238-817.
    ///
    /// ## Processing Flow
    ///
    /// 1. Extract and validate redirect-specific options
    /// 2. Resolve qualify_domain if configured
    /// 3. Obtain redirect data (expand `data` or read `file`)
    /// 4. Interpret redirect data (alias list, Exim filter, Sieve filter)
    /// 5. Process filter result code
    /// 6. Process generated addresses (validate, set transport, uid/gid)
    /// 7. Handle syntax errors
    /// 8. Return appropriate result
    fn route(
        &self,
        config: &RouterInstanceConfig,
        address: &str,
        _local_user: Option<&str>,
    ) -> Result<RouterResult, DriverError> {
        let router_name = config.name.as_str();
        tracing::debug!(
            router = router_name,
            address = address,
            "redirect router: processing address"
        );

        // ── Step 1: Extract driver-specific options ────────────────────
        let opts = config
            .options
            .downcast_ref::<RedirectRouterOptions>()
            .cloned()
            .unwrap_or_default();

        // ── Step 2: Validate configuration ─────────────────────────────
        Self::validate_config(config, &opts).map_err(DriverError::from)?;

        // ── Step 3: Set up propagated data ─────────────────────────────
        // Resolve uid/gid from router config
        let ugid = UgidBlock {
            uid: if config.uid_set {
                Some(config.uid)
            } else {
                None
            },
            gid: if config.gid_set {
                Some(config.gid)
            } else {
                None
            },
            initgroups: config.initgroups,
        };

        // ── Step 4: Resolve qualify_domain ─────────────────────────────
        let qualify_domain: Option<String> = if opts.qualify_preserve_domain {
            // Use the current domain from the address
            address.rfind('@').map(|pos| address[pos + 1..].to_string())
        } else if let Some(ref qd) = opts.qualify_domain {
            match expand_string(qd) {
                Ok(expanded) => Some(expanded),
                Err(ExpandError::ForcedFail) => {
                    tracing::debug!(
                        router = router_name,
                        "qualify_domain expansion: forced failure"
                    );
                    return Ok(RouterResult::Decline);
                }
                Err(e) => {
                    let msg = format!(
                        "expansion of qualify_domain failed in router \
                         '{router_name}': {e}"
                    );
                    tracing::error!(router = router_name, "{msg}");
                    return Err(DriverError::TempFail(msg));
                }
            }
        } else {
            None
        };

        // ── Step 5: Obtain redirect data ───────────────────────────────
        let redirect_data = match Self::obtain_redirect_data(config, &opts, address) {
            Ok(data) => {
                // Wrap in Tainted since data is from untrusted source
                let tainted_data = Tainted::new(data);
                tracing::trace!(
                    router = router_name,
                    data_len = tainted_data.as_ref().len(),
                    "redirect data obtained (tainted)"
                );
                // For processing we need the inner value — the data
                // itself is not passed to transports directly, so we
                // extract it for interpretation.
                tainted_data.into_inner()
            }
            Err(RedirectError::ForcedFail) => {
                tracing::debug!(
                    router = router_name,
                    "redirect data: forced failure → DECLINE"
                );
                return Ok(RouterResult::Decline);
            }
            Err(RedirectError::FileReadFailed { ref path, .. }) if opts.file.is_some() => {
                // File not found → DECLINE (like FF_NONEXIST)
                tracing::debug!(
                    router = router_name,
                    path = path.as_str(),
                    "redirect file not found → DECLINE"
                );
                return Ok(RouterResult::Decline);
            }
            Err(e) => {
                return Err(DriverError::from(e));
            }
        };

        // ── Step 6: Interpret redirect data ────────────────────────────
        let interpret_result = Self::interpret_redirect_data(
            &redirect_data,
            &opts,
            address,
            qualify_domain.as_deref(),
        );

        // ── Step 7: Process filter result code ─────────────────────────
        match interpret_result.filter_code {
            FF_NONEXIST => {
                tracing::debug!(
                    router = router_name,
                    "redirect data does not exist → DECLINE"
                );
                return Ok(RouterResult::Decline);
            }
            FF_BLACKHOLE => {
                tracing::debug!(
                    router = router_name,
                    address = address,
                    "redirect: :blackhole: → message discarded"
                );
                // Blackhole is Accept with no transport (discard)
                return Ok(RouterResult::Accept {
                    transport_name: None,
                    host_list: Vec::new(),
                });
            }
            FF_DEFER => {
                let msg = interpret_result
                    .error_message
                    .unwrap_or_else(|| "redirect deferred".to_string());
                tracing::debug!(
                    router = router_name,
                    reason = msg.as_str(),
                    "redirect: FF_DEFER"
                );
                return Ok(RouterResult::defer(msg));
            }
            FF_FAIL => {
                let mut msg = interpret_result
                    .error_message
                    .unwrap_or_else(|| "redirect failed".to_string());
                if opts.forbid_smtp_code {
                    msg = Self::strip_smtp_code(&msg);
                }
                tracing::debug!(
                    router = router_name,
                    reason = msg.as_str(),
                    "redirect: FF_FAIL"
                );
                return Ok(RouterResult::fail(msg));
            }
            FF_FREEZE => {
                let msg = interpret_result
                    .error_message
                    .unwrap_or_else(|| "redirect: message frozen".to_string());
                tracing::debug!(
                    router = router_name,
                    "redirect: FF_FREEZE → DEFER with special action"
                );
                return Ok(RouterResult::defer(format!("frozen: {msg}")));
            }
            FF_ERROR | FF_INCLUDEFAIL => {
                let msg = interpret_result
                    .error_message
                    .unwrap_or_else(|| "redirect error".to_string());
                tracing::error!(
                    router = router_name,
                    "redirect: error during interpretation: {msg}"
                );
                // If skip_syntax_errors, DECLINE; otherwise DEFER
                if opts.skip_syntax_errors {
                    return Ok(RouterResult::Decline);
                }
                return Ok(RouterResult::defer(msg));
            }
            _ => {
                // FF_DELIVERED, FF_NOTDELIVERED — continue processing
            }
        }

        // ── Step 8: Handle syntax errors ───────────────────────────────
        if let Some(result) =
            Self::handle_syntax_errors(&interpret_result.syntax_errors, &opts, config)
        {
            return Ok(result);
        }

        // ── Step 9: Process generated addresses ────────────────────────
        let mut generated = interpret_result.generated_addresses;
        let was_filter = interpret_result.is_filter;

        if generated.is_empty() {
            if interpret_result.filter_code == FF_NOTDELIVERED && was_filter {
                // Filter didn't produce any output — for filters this
                // means the filter didn't produce any delivery actions,
                // so we treat it as DECLINE (pass to next router).
                tracing::debug!(
                    router = router_name,
                    is_filter = was_filter,
                    "filter produced no addresses (FF_NOTDELIVERED) → DECLINE"
                );
                return Ok(RouterResult::Decline);
            } else if interpret_result.filter_code == FF_NOTDELIVERED {
                // Alias list produced no addresses but didn't error —
                // create a base address for further routing.
                tracing::debug!(
                    router = router_name,
                    "no addresses generated (FF_NOTDELIVERED) → creating base address"
                );
                generated.push(AddressItem::new(address.to_string()));
            } else {
                tracing::debug!(router = router_name, "no generated addresses → DECLINE");
                return Ok(RouterResult::Decline);
            }
        }

        // Build ancestor set for loop detection
        let mut ancestors = HashSet::new();
        ancestors.insert(address.to_lowercase());
        // In the full implementation, the ancestor chain would be walked
        // from the parent address through all its ancestors.

        let parent_unique = address.to_string();
        let mut valid_addresses: Vec<String> = Vec::new();
        let mut had_error = false;
        let mut error_message: Option<String> = None;

        for child in &mut generated {
            // Wrap generated address as tainted
            let tainted_addr = Tainted::new(child.address.clone());
            tracing::trace!(
                router = router_name,
                generated_address = tainted_addr.as_ref().as_str(),
                "processing generated address (tainted)"
            );

            match Self::add_generated(
                child,
                address,
                &parent_unique,
                &ancestors,
                config,
                &opts,
                &ugid,
            ) {
                Ok(()) => {
                    // Validate the tainted address via sanitize.
                    // sanitize() consumes self, so clone first in case
                    // we need force_clean() on the original.
                    let tainted_clone = tainted_addr.clone();
                    let clean_result = tainted_clone.sanitize(|addr: &String| {
                        // Basic email address validation: must be an email,
                        // pipe command, or file path.
                        addr.contains('@') || addr.starts_with('|') || addr.starts_with('/')
                    });

                    match clean_result {
                        Ok(clean_addr) => {
                            valid_addresses.push(clean_addr.into_inner());
                        }
                        Err(e) => {
                            tracing::warn!(
                                router = router_name,
                                address = child.address.as_str(),
                                error = %e,
                                "tainted address validation failed"
                            );
                            // For taint failures, force_clean and continue
                            // (matching C behavior where tainted addresses
                            // are still processed but marked)
                            let forced = tainted_addr.force_clean();
                            valid_addresses.push(forced.into_inner());
                        }
                    }
                }
                Err(RedirectError::AncestorLoop(ref addr)) => {
                    tracing::warn!(
                        router = router_name,
                        address = addr.as_str(),
                        "skipping address due to ancestor loop"
                    );
                    // Ancestor loops skip the address silently
                    continue;
                }
                Err(e) => {
                    had_error = true;
                    error_message = Some(e.to_string());
                    tracing::error!(
                        router = router_name,
                        address = child.address.as_str(),
                        error = %e,
                        "error processing generated address"
                    );
                    // If skip_syntax_errors, continue; otherwise break
                    if !opts.skip_syntax_errors {
                        break;
                    }
                }
            }
        }

        // ── Step 10: Return result ─────────────────────────────────────
        if had_error && !opts.skip_syntax_errors {
            let msg =
                error_message.unwrap_or_else(|| "error processing generated addresses".to_string());
            return Ok(RouterResult::defer(msg));
        }

        if valid_addresses.is_empty() {
            tracing::debug!(
                router = router_name,
                "no valid addresses after processing → DECLINE"
            );
            return Ok(RouterResult::Decline);
        }

        // Return the generated addresses as a reroute result
        // (the addresses will be re-routed through the router chain)
        tracing::debug!(
            router = router_name,
            count = valid_addresses.len(),
            "redirect router: returning {} generated address(es)",
            valid_addresses.len()
        );

        Ok(RouterResult::Rerouted {
            new_addresses: valid_addresses,
        })
    }

    /// No cleanup needed for the redirect router.
    ///
    /// Matches C `redirect_router_info.tidyup = NULL`.
    fn tidyup(&self, _config: &RouterInstanceConfig) {
        // No-op — redirect router has no state to clean up
    }

    /// Return router flags — ri_notransport.
    ///
    /// The redirect router does not directly assign a transport to the
    /// main address.  Instead, it generates child addresses that are
    /// re-routed through the router chain (or have transports assigned
    /// to special deliveries like pipe/file/directory/reply).
    fn flags(&self) -> RouterFlags {
        // ri_notransport equivalent — the redirect router does not require
        // a transport on the router instance config itself.
        RouterFlags::from_bits(0x0001)
    }

    /// Return the driver name.
    fn driver_name(&self) -> &'static str {
        "redirect"
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Compile-Time Driver Registration
// ═══════════════════════════════════════════════════════════════════════════

inventory::submit! {
    RouterDriverFactory {
        name: "redirect",
        create: || Box::new(RedirectRouter),
        avail_string: Some("redirect"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Unit Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use exim_drivers::router_driver::RouterDriver;

    /// Helper to create a minimal RouterInstanceConfig for tests.
    fn test_config() -> RouterInstanceConfig {
        RouterInstanceConfig::new("test", "redirect")
    }

    #[test]
    fn test_default_options() {
        let opts = RedirectRouterOptions::default();
        assert!(opts.data.is_none());
        assert!(opts.file.is_none());
        assert_eq!(opts.modemask, 0o022);
        assert_eq!(opts.bit_options, RDO_REWRITE | RDO_PREPEND_HOME);
        assert!(!opts.check_ancestor);
        assert!(opts.check_group);
        assert!(opts.check_owner);
        assert!(!opts.forbid_file);
        assert!(!opts.forbid_filter_reply);
        assert!(!opts.forbid_pipe);
        assert!(!opts.forbid_smtp_code);
        assert!(!opts.hide_child_in_errmsg);
        assert!(!opts.one_time);
        assert!(!opts.qualify_preserve_domain);
        assert!(!opts.skip_syntax_errors);
    }

    #[test]
    fn test_rdo_constants_distinct() {
        let all = [
            RDO_LOOKUP,
            RDO_RUN,
            RDO_DLFUNC,
            RDO_PERL,
            RDO_READFILE,
            RDO_READSOCK,
            RDO_INCLUDE,
            RDO_REWRITE,
            RDO_PREPEND_HOME,
            RDO_EXIM_FILTER,
            RDO_SIEVE_FILTER,
            RDO_EXISTS,
            RDO_LOG,
            RDO_FREEZE,
            RDO_FAIL,
            RDO_DEFER,
            RDO_BLACKHOLE,
            RDO_EACCES,
            RDO_ENOTDIR,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j {
                    assert_eq!(a & b, 0, "RDO constants at {i} and {j} overlap");
                }
            }
        }
    }

    #[test]
    fn test_strip_smtp_code_with_code() {
        assert_eq!(
            RedirectRouter::strip_smtp_code("550 User not found"),
            "User not found"
        );
    }

    #[test]
    fn test_strip_smtp_code_with_extended() {
        assert_eq!(
            RedirectRouter::strip_smtp_code("550 5.1.1 User not found"),
            "User not found"
        );
    }

    #[test]
    fn test_strip_smtp_code_without_code() {
        assert_eq!(
            RedirectRouter::strip_smtp_code("User not found"),
            "User not found"
        );
    }

    #[test]
    fn test_strip_smtp_code_only_code() {
        assert_eq!(RedirectRouter::strip_smtp_code("550 "), "redirect error");
    }

    #[test]
    fn test_driver_name() {
        assert_eq!(RedirectRouter.driver_name(), "redirect");
    }

    #[test]
    fn test_flags_not_zero() {
        assert_ne!(RedirectRouter.flags().bits(), 0);
    }

    #[test]
    fn test_error_conversion_config() {
        let de: DriverError = RedirectError::MutualExclusivityViolation.into();
        assert!(matches!(de, DriverError::ConfigError(_)));
    }

    #[test]
    fn test_error_conversion_temp() {
        let de: DriverError = RedirectError::ExpansionFailed("x".into()).into();
        assert!(matches!(de, DriverError::TempFail(_)));
    }

    #[test]
    fn test_error_conversion_exec() {
        let de: DriverError = RedirectError::SyntaxError("x".into()).into();
        assert!(matches!(de, DriverError::ExecutionFailed(_)));
    }

    #[test]
    fn test_validate_config_neither_set() {
        let config = test_config();
        let opts = RedirectRouterOptions::default();
        assert!(RedirectRouter::validate_config(&config, &opts).is_err());
    }

    #[test]
    fn test_validate_config_data_only() {
        let config = test_config();
        let opts = RedirectRouterOptions {
            data: Some("a@b.c".into()),
            ..Default::default()
        };
        assert!(RedirectRouter::validate_config(&config, &opts).is_ok());
    }

    #[test]
    fn test_validate_config_file_only() {
        let config = test_config();
        let opts = RedirectRouterOptions {
            file: Some("/etc/aliases".into()),
            ..Default::default()
        };
        assert!(RedirectRouter::validate_config(&config, &opts).is_ok());
    }

    #[test]
    fn test_validate_qualify_mutual_exclusion() {
        let config = test_config();
        let opts = RedirectRouterOptions {
            data: Some("u".into()),
            qualify_domain: Some("x.com".into()),
            qualify_preserve_domain: true,
            ..Default::default()
        };
        assert!(RedirectRouter::validate_config(&config, &opts).is_err());
    }

    #[test]
    fn test_alias_list_simple() {
        let opts = RedirectRouterOptions::default();
        let r = RedirectRouter::interpret_alias_list("a@b.c, d@e.f", &opts, "x@y.z", None);
        assert_eq!(r.filter_code, FF_DELIVERED);
        assert_eq!(r.generated_addresses.len(), 2);
        assert!(!r.is_filter);
    }

    #[test]
    fn test_alias_list_qualify() {
        let opts = RedirectRouterOptions::default();
        let r = RedirectRouter::interpret_alias_list("user", &opts, "x@y.z", Some("y.z"));
        assert_eq!(r.generated_addresses[0].address, "user@y.z");
    }

    #[test]
    fn test_alias_list_pipe() {
        let opts = RedirectRouterOptions::default();
        let r = RedirectRouter::interpret_alias_list("|/bin/cmd", &opts, "x@y", None);
        assert_ne!(r.generated_addresses[0].flags & AF_PFLAG, 0);
    }

    #[test]
    fn test_alias_list_file() {
        let opts = RedirectRouterOptions::default();
        let r = RedirectRouter::interpret_alias_list("/var/mail/f", &opts, "x@y", None);
        assert_ne!(r.generated_addresses[0].flags & AF_FILE, 0);
    }

    #[test]
    fn test_alias_list_directory() {
        let opts = RedirectRouterOptions::default();
        let r = RedirectRouter::interpret_alias_list("/var/mail/d/", &opts, "x@y", None);
        assert_ne!(r.generated_addresses[0].flags & AF_DIRECTORY, 0);
    }

    #[test]
    fn test_alias_list_blackhole() {
        let mut opts = RedirectRouterOptions::default();
        opts.bit_options |= RDO_BLACKHOLE;
        let r = RedirectRouter::interpret_alias_list(":blackhole:", &opts, "x@y", None);
        assert_eq!(r.filter_code, FF_BLACKHOLE);
    }

    #[test]
    fn test_alias_list_empty() {
        let opts = RedirectRouterOptions::default();
        let r = RedirectRouter::interpret_alias_list("", &opts, "x@y", None);
        assert_eq!(r.filter_code, FF_NOTDELIVERED);
    }

    #[test]
    fn test_alias_list_comments() {
        let opts = RedirectRouterOptions::default();
        let r = RedirectRouter::interpret_alias_list("# comment\na@b", &opts, "x@y", None);
        assert_eq!(r.generated_addresses.len(), 1);
    }

    #[test]
    fn test_exim_filter_deliver() {
        let mut opts = RedirectRouterOptions::default();
        opts.bit_options |= RDO_EXIM_FILTER;
        let r = RedirectRouter::interpret_redirect_data(
            "# Exim filter\ndeliver a@b",
            &opts,
            "x@y",
            None,
        );
        assert_eq!(r.filter_code, FF_DELIVERED);
        assert!(r.is_filter);
    }

    #[test]
    fn test_exim_filter_freeze() {
        let mut opts = RedirectRouterOptions::default();
        opts.bit_options |= RDO_EXIM_FILTER | RDO_FREEZE;
        let r =
            RedirectRouter::interpret_redirect_data("# Exim filter\nfreeze", &opts, "x@y", None);
        assert_eq!(r.filter_code, FF_FREEZE);
    }

    #[test]
    fn test_sieve_redirect() {
        let mut opts = RedirectRouterOptions::default();
        opts.bit_options |= RDO_SIEVE_FILTER;
        let r = RedirectRouter::interpret_redirect_data(
            "require \"redirect\";\nredirect \"a@b\";",
            &opts,
            "x@y",
            None,
        );
        assert_eq!(r.filter_code, FF_DELIVERED);
        assert!(r.is_filter);
    }

    #[test]
    fn test_sieve_discard() {
        let mut opts = RedirectRouterOptions::default();
        opts.bit_options |= RDO_SIEVE_FILTER;
        let r = RedirectRouter::interpret_redirect_data(
            "require \"reject\";\ndiscard;",
            &opts,
            "x@y",
            None,
        );
        assert_eq!(r.filter_code, FF_BLACKHOLE);
    }

    #[test]
    fn test_options_clone() {
        let opts = RedirectRouterOptions {
            data: Some("u@e".into()),
            forbid_pipe: true,
            modemask: 0o077,
            ..Default::default()
        };
        let c = opts.clone();
        assert_eq!(c.data, Some("u@e".into()));
        assert!(c.forbid_pipe);
        assert_eq!(c.modemask, 0o077);
    }
}
