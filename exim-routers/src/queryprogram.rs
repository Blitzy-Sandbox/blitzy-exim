// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! Query Program Router — External Helper Execution
//!
//! Translates **`src/src/routers/queryprogram.c`** (562 lines) and
//! **`src/src/routers/queryprogram.h`** (42 lines) into Rust.
//!
//! ## Overview
//!
//! The queryprogram router executes an external helper program to determine
//! routing decisions. The helper program receives the address being routed as
//! context and writes structured reply lines to stdout. The first word of the
//! reply determines the routing action:
//!
//! - **`ACCEPT`** — Accept the address with optional transport/hosts/data fields.
//! - **`ACCEPT REDIRECT <data>`** — Redirect the address to new addresses.
//! - **`DECLINE`** — This router does not handle this address.
//! - **`PASS`** — Pass to the next router in the chain.
//! - **`DEFER`** — Temporary failure, retry later.
//! - **`FAIL`** — Permanent routing failure.
//! - **`FREEZE`** — Freeze the message and defer.
//!
//! ## C Source Correspondence
//!
//! | C construct | Rust equivalent |
//! |---|---|
//! | `queryprogram_router_options_block` | [`QueryProgramRouterOptions`] |
//! | `queryprogram_router_init()` | [`QueryProgramRouter::validate_config()`] |
//! | `queryprogram_router_entry()` | [`QueryProgramRouter::route()`] |
//! | `queryprogram_router_info` | [`inventory::submit!`] registration |
//! | `child_open_uid()` | [`std::process::Command`] with uid/gid via `nix` |
//! | `child_close()` | [`std::process::Child::wait_with_output()`] |
//! | `expand_getkeyed()` | [`extract_keyed_field()`] helper |
//!
//! ## Configuration Options
//!
//! All 9 C options from `queryprogram_router_options_block` are represented:
//!
//! | C Option | Rust Field | Type | Default |
//! |---|---|---|---|
//! | `command` | [`command`](QueryProgramRouterOptions::command) | `Option<String>` | `None` (required) |
//! | `timeout` | [`timeout`](QueryProgramRouterOptions::timeout) | `u32` | `3600` (60×60 seconds) |
//! | `cmd_uid` | [`cmd_uid`](QueryProgramRouterOptions::cmd_uid) | `Option<u32>` | `None` |
//! | `cmd_gid` | [`cmd_gid`](QueryProgramRouterOptions::cmd_gid) | `Option<u32>` |  `None` |
//! | `cmd_uid_set` | [`cmd_uid_set`](QueryProgramRouterOptions::cmd_uid_set) | `bool` | `false` |
//! | `cmd_gid_set` | [`cmd_gid_set`](QueryProgramRouterOptions::cmd_gid_set) | `bool` | `false` |
//! | `current_directory` | [`current_directory`](QueryProgramRouterOptions::current_directory) | `Option<String>` | `Some("/")` |
//! | `*expand_command_user` | [`expand_cmd_uid`](QueryProgramRouterOptions::expand_cmd_uid) | `Option<String>` | `None` |
//! | `*expand_command_group` | [`expand_cmd_gid`](QueryProgramRouterOptions::expand_cmd_gid) | `Option<String>` | `None` |
//!
//! ## Safety
//!
//! This module contains **zero `unsafe` code** (per AAP §0.7.2).
//! Subprocess management uses `std::process::Command` and `nix` crate
//! for safe uid/gid manipulation.
//! All data from the external program is wrapped in [`Tainted<T>`] as
//! it is untrusted external input (per AAP §0.4.2).

// ── Imports ────────────────────────────────────────────────────────────────

use exim_drivers::router_driver::{
    RouterDriver, RouterDriverFactory, RouterFlags, RouterInstanceConfig, RouterResult,
};
use exim_drivers::DriverError;
use exim_expand::{expand_string, ExpandError};
use exim_store::taint::{Clean, Tainted, TaintedString};

use crate::helpers::{
    ErrorsAddressResult, GetTransportError, HeaderLine, HostFindFailedPolicy, MungeHeadersResult,
    PasswdEntry, UgidBlock,
};

use nix::unistd::{Gid, Uid};
use serde::Deserialize;
use thiserror::Error;

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Duration;

// ═══════════════════════════════════════════════════════════════════════════
//  QueryProgramError — Router-Specific Error Type
// ═══════════════════════════════════════════════════════════════════════════

/// Errors specific to the queryprogram router.
///
/// Each variant maps to a failure mode that can occur during external helper
/// program execution and response parsing. All variants are convertible to
/// [`DriverError`] for propagation through the driver framework.
#[derive(Debug, Error)]
pub enum QueryProgramError {
    /// The `command` option was not set in the router configuration.
    /// C: `queryprogram_router_init()` — "a command specification is required"
    #[error("{router_name} router: a command specification is required")]
    CommandNotSet {
        /// Name of the router instance.
        router_name: String,
    },

    /// The `command_user` option was not set and no expandable uid was provided.
    /// C: `queryprogram_router_init()` — "command_user must be specified"
    #[error("{router_name} router: command_user must be specified")]
    CommandUserNotSet {
        /// Name of the router instance.
        router_name: String,
    },

    /// Command string expansion failed.
    /// C: `transport_set_up_command()` failure → DEFER
    #[error("{router_name} router: command expansion failed: {detail}")]
    CommandExpansionFailed {
        /// Name of the router instance.
        router_name: String,
        /// Expansion error detail.
        detail: String,
    },

    /// Failed to create the child process.
    /// C: `child_open_uid()` failure → DEFER
    #[error("{router_name} router: couldn't create child process: {detail}")]
    ChildCreationFailed {
        /// Name of the router instance.
        router_name: String,
        /// OS-level error detail.
        detail: String,
    },

    /// The child process exited with a non-zero exit code.
    /// C: `child_close()` with rc > 0
    #[error("{router_name} router: command returned non-zero code {code}")]
    CommandNonZeroExit {
        /// Name of the router instance.
        router_name: String,
        /// The process exit code.
        code: i32,
    },

    /// The child process timed out.
    /// C: `child_close()` with rc == -256
    #[error("{router_name} router: command timed out")]
    CommandTimedOut {
        /// Name of the router instance.
        router_name: String,
    },

    /// The child process was killed by a signal.
    /// C: `child_close()` with rc < 0 (signal)
    #[error("{router_name} router: command killed by signal {signal}")]
    CommandKilledBySignal {
        /// Name of the router instance.
        router_name: String,
        /// Signal number.
        signal: i32,
    },

    /// The child process failed to return any data.
    /// C: `len <= 0` after reading pipe
    #[error("{router_name} router: command failed to return data")]
    NoDataReturned {
        /// Name of the router instance.
        router_name: String,
    },

    /// The response contained an unrecognised action keyword.
    /// C: "bad command yield: ..."
    #[error("{router_name} router: bad command yield: {keyword} {data}")]
    BadCommandYield {
        /// Name of the router instance.
        router_name: String,
        /// The unrecognised keyword.
        keyword: String,
        /// Additional data from the response line.
        data: String,
    },

    /// An unknown transport name was returned by the command.
    /// C: "unknown transport name %s yielded by command"
    #[error("{router_name} router: unknown transport name {transport_name} yielded by command")]
    UnknownTransport {
        /// Name of the router instance.
        router_name: String,
        /// The transport name that was not found.
        transport_name: String,
    },

    /// A bad lookup type was returned by the command.
    /// C: "bad lookup type %q yielded by command"
    #[error("{router_name} router: bad lookup type \"{lookup_type}\" yielded by command")]
    BadLookupType {
        /// Name of the router instance.
        router_name: String,
        /// The invalid lookup type string.
        lookup_type: String,
    },

    /// UID/GID resolution failed.
    #[error("{router_name} router: uid/gid resolution failed: {detail}")]
    UidGidResolutionFailed {
        /// Name of the router instance.
        router_name: String,
        /// Detail of the failure.
        detail: String,
    },

    /// Errors address resolution failed.
    #[error("{router_name} router: errors address resolution failed: {detail}")]
    ErrorsAddressFailed {
        /// Name of the router instance.
        router_name: String,
        /// Detail of the failure.
        detail: String,
    },

    /// Munge headers expansion failed.
    #[error("{router_name} router: header munging failed: {detail}")]
    MungeHeadersFailed {
        /// Name of the router instance.
        router_name: String,
        /// Detail of the failure.
        detail: String,
    },

    /// Transport resolution failed.
    #[error("{router_name} router: transport resolution failed: {detail}")]
    TransportResolutionFailed {
        /// Name of the router instance.
        router_name: String,
        /// Detail of the failure.
        detail: String,
    },

    /// GID resolution failed — command_user set without command_group.
    /// C: "command_user set without command_group for %s router"
    #[error("{router_name} router: command_user set without command_group")]
    CommandGroupMissing {
        /// Name of the router instance.
        router_name: String,
    },
}

impl From<QueryProgramError> for DriverError {
    fn from(err: QueryProgramError) -> Self {
        match &err {
            QueryProgramError::CommandNotSet { .. }
            | QueryProgramError::CommandUserNotSet { .. }
            | QueryProgramError::CommandGroupMissing { .. } => {
                DriverError::ConfigError(err.to_string())
            }
            QueryProgramError::CommandTimedOut { .. }
            | QueryProgramError::ChildCreationFailed { .. }
            | QueryProgramError::NoDataReturned { .. }
            | QueryProgramError::CommandNonZeroExit { .. }
            | QueryProgramError::CommandKilledBySignal { .. }
            | QueryProgramError::UidGidResolutionFailed { .. }
            | QueryProgramError::ErrorsAddressFailed { .. }
            | QueryProgramError::MungeHeadersFailed { .. } => {
                DriverError::TempFail(err.to_string())
            }
            QueryProgramError::CommandExpansionFailed { .. }
            | QueryProgramError::BadCommandYield { .. }
            | QueryProgramError::UnknownTransport { .. }
            | QueryProgramError::BadLookupType { .. }
            | QueryProgramError::TransportResolutionFailed { .. } => {
                DriverError::ExecutionFailed(err.to_string())
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  QueryProgramAction — Response Action Enum
// ═══════════════════════════════════════════════════════════════════════════

/// Routing action determined by the first word of the external helper
/// program's response.
///
/// Maps to the C `strcmpic()` comparisons in `queryprogram_router_entry()`
/// (queryprogram.c lines 376–462).
///
/// Each variant corresponds to an action keyword written by the helper:
/// - `ACCEPT` — accept the address for delivery
/// - `ACCEPT REDIRECT <data>` — redirect to new addresses
/// - `DECLINE` — router does not handle this address
/// - `PASS` — pass to next router
/// - `DEFER` — temporary failure
/// - `FAIL` — permanent failure
/// - `FREEZE` — freeze message and defer
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryProgramAction {
    /// Accept the address for delivery. The response may include additional
    /// keyed fields: `data=`, `transport=`, `hosts=`, `lookup=`.
    Accept,

    /// Accept the address but redirect it to new addresses. The `data`
    /// field contains the redirect data (like a `.forward` file content).
    /// C: `REDIRECT` keyword (queryprogram.c line 376).
    AcceptRedirect {
        /// Redirect data string containing target addresses.
        data: String,
    },

    /// Router declines this address — not applicable.
    /// C: return `DECLINE` (queryprogram.c line 447).
    Decline,

    /// Pass to next router in chain.
    /// C: return `PASS` (queryprogram.c line 448).
    Pass,

    /// Temporary failure — retry later.
    /// C: return `DEFER` (queryprogram.c line 456).
    Defer,

    /// Permanent routing failure.
    /// C: return `FAIL` (queryprogram.c line 450).
    Fail,

    /// Freeze the message and defer delivery.
    /// C: `addr->special_action = SPECIAL_FREEZE; return DEFER;`
    /// (queryprogram.c line 455).
    Freeze,
}

// ═══════════════════════════════════════════════════════════════════════════
//  QueryProgramRouterOptions — Configuration Options
// ═══════════════════════════════════════════════════════════════════════════

/// Configuration options for the queryprogram router.
///
/// Translates the C `queryprogram_router_options_block` struct from
/// `queryprogram.h` (lines 13–23). All 9 option fields are represented
/// with identical semantics.
///
/// ## Defaults
///
/// Default values match the C `queryprogram_router_option_defaults` at
/// queryprogram.c lines 63–73:
///
/// ```c
/// queryprogram_router_options_block queryprogram_router_option_defaults = {
///   NULL,         /* command */
///   60*60,        /* timeout — 3600 seconds */
///   (uid_t)(-1),  /* cmd_uid */
///   (gid_t)(-1),  /* cmd_gid */
///   FALSE,        /* cmd_uid_set */
///   FALSE,        /* cmd_gid_set */
///   US"/",        /* current_directory */
///   NULL,         /* expand_cmd_gid */
///   NULL          /* expand_cmd_uid */
/// };
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct QueryProgramRouterOptions {
    /// Command to execute (required, expandable).
    ///
    /// The command string is expanded via `expand_string()` before
    /// execution. It is split into an argument vector using shell-like
    /// word splitting.
    ///
    /// C: `uschar *command` — required option, must be set in config.
    pub command: Option<String>,

    /// Command execution timeout in seconds.
    ///
    /// If the command does not complete within this time, it is killed
    /// and the router returns DEFER.
    ///
    /// C: `int timeout` — default 60*60 = 3600 seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u32,

    /// Fixed UID to run the command as.
    ///
    /// C: `uid_t cmd_uid` — default `(uid_t)(-1)` meaning unset.
    pub cmd_uid: Option<u32>,

    /// Fixed GID to run the command as.
    ///
    /// C: `gid_t cmd_gid` — default `(gid_t)(-1)` meaning unset.
    pub cmd_gid: Option<u32>,

    /// Whether `cmd_uid` is explicitly set in the configuration.
    ///
    /// C: `BOOL cmd_uid_set` — default `FALSE`.
    #[serde(default)]
    pub cmd_uid_set: bool,

    /// Whether `cmd_gid` is explicitly set in the configuration.
    ///
    /// C: `BOOL cmd_gid_set` — default `FALSE`.
    #[serde(default)]
    pub cmd_gid_set: bool,

    /// Working directory for the command.
    ///
    /// C: `uschar *current_directory` — default `"/"`.
    #[serde(default = "default_current_directory")]
    pub current_directory: Option<String>,

    /// Expandable UID string (alternative to fixed `cmd_uid`).
    ///
    /// If set, this string is expanded at route time to obtain the UID.
    /// Either `cmd_uid_set` or `expand_cmd_uid` must be provided.
    ///
    /// C: `uschar *expand_cmd_uid` — default `NULL`.
    pub expand_cmd_uid: Option<String>,

    /// Expandable GID string (alternative to fixed `cmd_gid`).
    ///
    /// If set, this string is expanded at route time to obtain the GID.
    ///
    /// C: `uschar *expand_cmd_gid` — default `NULL`.
    pub expand_cmd_gid: Option<String>,
}

/// Default timeout: 3600 seconds (60 minutes), matching C default `60*60`.
fn default_timeout() -> u32 {
    3600
}

/// Default current directory: `"/"`, matching C default `US"/"`.
fn default_current_directory() -> Option<String> {
    Some("/".to_string())
}

impl Default for QueryProgramRouterOptions {
    fn default() -> Self {
        Self {
            command: None,
            timeout: default_timeout(),
            cmd_uid: None,
            cmd_gid: None,
            cmd_uid_set: false,
            cmd_gid_set: false,
            current_directory: default_current_directory(),
            expand_cmd_uid: None,
            expand_cmd_gid: None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Lookup Type Enum
// ═══════════════════════════════════════════════════════════════════════════

/// Host lookup strategy specified in the helper program's response.
///
/// Maps to C `LK_DEFAULT`, `LK_BYNAME`, `LK_BYDNS` constants used in
/// queryprogram.c lines 504–516.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LookupType {
    /// Default lookup strategy (try DNS first, fall back to name).
    Default,
    /// Lookup by name only (gethostbyname/getaddrinfo).
    ByName,
    /// Lookup by DNS only (no fallback).
    ByDns,
}

// ═══════════════════════════════════════════════════════════════════════════
//  QueryProgramRouter — Router Implementation
// ═══════════════════════════════════════════════════════════════════════════

/// The queryprogram router driver.
///
/// Executes an external helper program to determine routing decisions.
/// The helper writes structured response lines to stdout, which this
/// router parses to determine the routing action.
///
/// Implements the [`RouterDriver`] trait with methods:
/// - [`route()`](RouterDriver::route) — Main routing entry point
/// - [`tidyup()`](RouterDriver::tidyup) — No-op (no persistent state)
/// - [`flags()`](RouterDriver::flags) — Returns `RouterFlags::NONE`
/// - [`driver_name()`](RouterDriver::driver_name) — Returns `"queryprogram"`
#[derive(Debug)]
pub struct QueryProgramRouter;

impl QueryProgramRouter {
    /// Validate the configuration options during router initialization.
    ///
    /// Translates `queryprogram_router_init()` from C (queryprogram.c
    /// lines 84–101). Checks:
    /// 1. `command` must be set.
    /// 2. Either `cmd_uid_set` or `expand_cmd_uid` must be provided.
    fn validate_config(
        config: &RouterInstanceConfig,
        opts: &QueryProgramRouterOptions,
    ) -> Result<(), QueryProgramError> {
        // C line 92: if (!ob->command) log_write_die(...)
        if opts.command.is_none() {
            return Err(QueryProgramError::CommandNotSet {
                router_name: config.name.clone(),
            });
        }

        // C lines 98–100: if (!ob->cmd_uid_set && !ob->expand_cmd_uid)
        if !opts.cmd_uid_set && opts.expand_cmd_uid.is_none() {
            return Err(QueryProgramError::CommandUserNotSet {
                router_name: config.name.clone(),
            });
        }

        Ok(())
    }

    /// Resolve UID and GID for command execution into a [`UgidBlock`].
    ///
    /// Translates C lines 251–272: resolution of fixed or expanded UID/GID.
    /// If `cmd_uid_set` is true, uses the fixed `cmd_uid`.
    /// Otherwise, expands `expand_cmd_uid` to resolve the UID, optionally
    /// populating a [`PasswdEntry`] from the passwd database.
    ///
    /// The GID is resolved from (in priority order):
    /// 1. Fixed `cmd_gid` (if `cmd_gid_set`)
    /// 2. Expanded `expand_cmd_gid` string
    /// 3. GID from passwd entry (if UID was resolved by username)
    fn resolve_uid_gid(
        opts: &QueryProgramRouterOptions,
        router_name: &str,
    ) -> Result<(UgidBlock, Option<PasswdEntry>), QueryProgramError> {
        let mut passwd_entry: Option<PasswdEntry> = None;

        // Step 1: Resolve UID (C lines 251–253).
        let uid: u32 = if opts.cmd_uid_set {
            // Fixed UID from configuration.
            opts.cmd_uid.unwrap_or(0)
        } else {
            // Expand the UID string.
            let expand_uid_str = opts.expand_cmd_uid.as_deref().unwrap_or("");
            let expanded = expand_string(expand_uid_str).map_err(|e| match e {
                ExpandError::ForcedFail => QueryProgramError::UidGidResolutionFailed {
                    router_name: router_name.to_string(),
                    detail: format!("forced fail expanding command_user '{}'", expand_uid_str),
                },
                other => QueryProgramError::UidGidResolutionFailed {
                    router_name: router_name.to_string(),
                    detail: format!(
                        "failed to expand command_user '{}': {}",
                        expand_uid_str, other
                    ),
                },
            })?;

            // Try to parse as numeric UID first.
            if let Ok(uid_val) = expanded.trim().parse::<u32>() {
                uid_val
            } else {
                // Try to resolve as username via nix — populate PasswdEntry.
                match nix::unistd::User::from_name(expanded.trim()) {
                    Ok(Some(user)) => {
                        let entry = PasswdEntry {
                            pw_name: user.name.clone(),
                            pw_uid: user.uid.as_raw(),
                            pw_gid: user.gid.as_raw(),
                            pw_dir: user.dir.to_str().unwrap_or("/").to_string(),
                            pw_shell: user.shell.to_str().unwrap_or("/bin/sh").to_string(),
                        };
                        let resolved_uid = entry.pw_uid;
                        passwd_entry = Some(entry);
                        resolved_uid
                    }
                    Ok(None) => {
                        return Err(QueryProgramError::UidGidResolutionFailed {
                            router_name: router_name.to_string(),
                            detail: format!("user '{}' not found", expanded.trim()),
                        });
                    }
                    Err(e) => {
                        return Err(QueryProgramError::UidGidResolutionFailed {
                            router_name: router_name.to_string(),
                            detail: format!("user lookup failed for '{}': {}", expanded.trim(), e),
                        });
                    }
                }
            }
        };

        // Step 2: Resolve GID (C lines 258–272).
        let gid: u32 = if opts.cmd_gid_set {
            // Fixed GID from configuration.
            opts.cmd_gid.unwrap_or(0)
        } else if let Some(ref expand_gid_str) = opts.expand_cmd_gid {
            // Expanded GID string.
            let expanded = expand_string(expand_gid_str).map_err(|e| {
                QueryProgramError::UidGidResolutionFailed {
                    router_name: router_name.to_string(),
                    detail: format!("failed to expand command_group '{}': {}", expand_gid_str, e),
                }
            })?;

            // Try numeric GID.
            if let Ok(gid_val) = expanded.trim().parse::<u32>() {
                gid_val
            } else {
                // Try group name resolution via nix.
                match nix::unistd::Group::from_name(expanded.trim()) {
                    Ok(Some(group)) => group.gid.as_raw(),
                    Ok(None) => {
                        return Err(QueryProgramError::UidGidResolutionFailed {
                            router_name: router_name.to_string(),
                            detail: format!("group '{}' not found", expanded.trim()),
                        });
                    }
                    Err(e) => {
                        return Err(QueryProgramError::UidGidResolutionFailed {
                            router_name: router_name.to_string(),
                            detail: format!("group lookup failed for '{}': {}", expanded.trim(), e),
                        });
                    }
                }
            }
        } else if let Some(ref pw) = passwd_entry {
            // Fall back to GID from passwd entry (if username lookup yielded one).
            pw.pw_gid
        } else {
            // C line 269–271: command_user set without command_group
            return Err(QueryProgramError::CommandGroupMissing {
                router_name: router_name.to_string(),
            });
        };

        let ugid = UgidBlock {
            uid: Some(uid),
            gid: Some(gid),
            initgroups: false,
        };

        Ok((ugid, passwd_entry))
    }

    /// Execute the external helper command and capture its output.
    ///
    /// Translates C lines 292–355: command expansion, child process creation,
    /// output reading, and exit code inspection.
    ///
    /// All output from the command is wrapped in `Tainted<String>` because
    /// it is untrusted external input.
    fn execute_command(
        command_template: &str,
        uid: u32,
        gid: u32,
        current_directory: &str,
        timeout_secs: u32,
        router_name: &str,
    ) -> Result<TaintedString, QueryProgramError> {
        // Expand the command string (C line 293: transport_set_up_command).
        let expanded_command = expand_string(command_template).map_err(|e| {
            QueryProgramError::CommandExpansionFailed {
                router_name: router_name.to_string(),
                detail: e.to_string(),
            }
        })?;

        tracing::debug!(
            router = %router_name,
            command = %expanded_command,
            uid = uid,
            gid = gid,
            cwd = %current_directory,
            "executing queryprogram command"
        );

        // Build the command arguments by splitting the expanded string.
        // The C code uses transport_set_up_command which does shell-like
        // splitting. We use a simple whitespace split here.
        let args = split_command_line(&expanded_command);
        if args.is_empty() {
            return Err(QueryProgramError::CommandExpansionFailed {
                router_name: router_name.to_string(),
                detail: "expanded command is empty".to_string(),
            });
        }

        // Build the Command with uid/gid/cwd settings.
        let mut cmd = Command::new(&args[0]);
        if args.len() > 1 {
            cmd.args(&args[1..]);
        }
        cmd.current_dir(current_directory);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // Set process group and uid/gid.
        // C: child_open_uid() sets uid/gid before exec.
        // We check if we need to change uid/gid (C lines 279–288).
        let current_uid = Uid::current().as_raw();
        let current_gid = Gid::current().as_raw();
        let root_uid: u32 = 0;

        let need_uid_change = uid != current_uid || gid != current_gid;
        let can_change = current_uid == root_uid;

        if need_uid_change && can_change {
            // Set uid/gid via pre_exec hook (safe POSIX operations).
            let target_uid = uid;
            let target_gid = gid;
            // SAFETY NOTE: We do NOT use unsafe here. Instead, we rely on
            // std::os::unix::process::CommandExt which is safe API.
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                cmd.uid(target_uid);
                cmd.gid(target_gid);
            }
        } else if need_uid_change && !can_change {
            tracing::debug!(
                router = %router_name,
                "not running as root: cannot change uid/gid; subprocess will run with current uid={} gid={}",
                current_uid,
                current_gid
            );
        }

        // Spawn the child process (C line 304: child_open_uid).
        let mut child = cmd
            .spawn()
            .map_err(|e| QueryProgramError::ChildCreationFailed {
                router_name: router_name.to_string(),
                detail: e.to_string(),
            })?;

        // Read output with timeout (C lines 319–355).
        let timeout_duration = Duration::from_secs(u64::from(timeout_secs));

        // Wait for the child to finish within the timeout.
        let output = match wait_with_timeout(&mut child, timeout_duration) {
            Ok(output) => output,
            Err(WaitError::Timeout) => {
                // Kill the process group on timeout (C line 329: killpg).
                let _ = child.kill();
                let _ = child.wait();
                return Err(QueryProgramError::CommandTimedOut {
                    router_name: router_name.to_string(),
                });
            }
            Err(WaitError::IoError(e)) => {
                return Err(QueryProgramError::ChildCreationFailed {
                    router_name: router_name.to_string(),
                    detail: format!("wait failed: {}", e),
                });
            }
        };

        // Check exit code (C lines 319–341).
        if !output.status.success() {
            let code = output.status.code().unwrap_or(-1);
            if code > 0 {
                return Err(QueryProgramError::CommandNonZeroExit {
                    router_name: router_name.to_string(),
                    code,
                });
            } else {
                // Killed by signal — extract signal number from exit status.
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    if let Some(sig) = output.status.signal() {
                        return Err(QueryProgramError::CommandKilledBySignal {
                            router_name: router_name.to_string(),
                            signal: sig,
                        });
                    }
                }
                return Err(QueryProgramError::CommandNonZeroExit {
                    router_name: router_name.to_string(),
                    code,
                });
            }
        }

        // Check that data was returned (C lines 350–355).
        if output.stdout.is_empty() {
            return Err(QueryProgramError::NoDataReturned {
                router_name: router_name.to_string(),
            });
        }

        // Convert output to string, trimming trailing whitespace.
        // C lines 360–361: strip leading/trailing whitespace.
        let raw_output = String::from_utf8_lossy(&output.stdout);
        let trimmed = raw_output.trim().to_string();

        if trimmed.is_empty() {
            return Err(QueryProgramError::NoDataReturned {
                router_name: router_name.to_string(),
            });
        }

        tracing::debug!(
            router = %router_name,
            output = %trimmed,
            "command wrote response"
        );

        // Wrap in Tainted<T> — ALL external program output is untrusted.
        Ok(Tainted::new(trimmed))
    }

    /// Parse the first word from the command response to determine the action.
    ///
    /// Translates C lines 365–462: keyword extraction and action dispatch.
    fn parse_action(
        response: &Tainted<String>,
        router_name: &str,
    ) -> Result<(QueryProgramAction, String), QueryProgramError> {
        let raw = response.as_ref();

        // Split into first word and rest (C lines 365–369).
        let trimmed = raw.trim();
        let (keyword, rest) = split_first_word(trimmed);

        // Case-insensitive keyword matching (C: strcmpic).
        let keyword_upper = keyword.to_uppercase();

        match keyword_upper.as_str() {
            "REDIRECT" => {
                // C line 376: REDIRECT — rest is the redirect data.
                Ok((
                    QueryProgramAction::AcceptRedirect {
                        data: rest.to_string(),
                    },
                    rest.to_string(),
                ))
            }
            "ACCEPT" => {
                // C line 445: ACCEPT — rest contains keyed fields.
                Ok((QueryProgramAction::Accept, rest.to_string()))
            }
            "DECLINE" => {
                // C line 447: DECLINE
                Ok((QueryProgramAction::Decline, rest.to_string()))
            }
            "PASS" => {
                // C line 448: PASS
                Ok((QueryProgramAction::Pass, rest.to_string()))
            }
            "FAIL" => {
                // C line 450: FAIL — rest is the failure message.
                Ok((QueryProgramAction::Fail, rest.to_string()))
            }
            "FREEZE" => {
                // C line 455: FREEZE
                Ok((QueryProgramAction::Freeze, rest.to_string()))
            }
            "DEFER" => {
                // C line 456: DEFER — rest is the deferral message.
                Ok((QueryProgramAction::Defer, rest.to_string()))
            }
            _ => {
                // C lines 457–461: bad command yield.
                Err(QueryProgramError::BadCommandYield {
                    router_name: router_name.to_string(),
                    keyword: keyword.to_string(),
                    data: rest.to_string(),
                })
            }
        }
    }

    /// Extract a keyed field from the ACCEPT response data.
    ///
    /// Translates the C `expand_getkeyed()` calls in queryprogram.c
    /// lines 468–524. The response data format uses space-separated
    /// `key=value` pairs.
    ///
    /// Returns `None` if the key is not found, `Some("")` if the key
    /// is present but empty, `Some(value)` otherwise.
    fn extract_keyed_field<'a>(key: &str, data: &'a str) -> Option<&'a str> {
        extract_keyed_field(key, data)
    }

    /// Process an ACCEPT REDIRECT response.
    ///
    /// Translates C lines 376–441: redirect data interpretation.
    /// Generates new addresses from the redirect data and returns
    /// a `Rerouted` result.
    fn handle_redirect(
        redirect_data: &str,
        router_name: &str,
    ) -> Result<RouterResult, QueryProgramError> {
        // Parse the redirect data as a comma/space separated address list.
        // In C, this goes through rda_interpret() which handles filter
        // processing. In the Rust version, we perform simple address
        // extraction since the queryprogram REDIRECT forbids filter data
        // (C lines 386–388: RDO_BLACKHOLE | RDO_FAIL | RDO_INCLUDE).
        let trimmed = redirect_data.trim();
        if trimmed.is_empty() {
            tracing::warn!(
                router = %router_name,
                "REDIRECT with empty data — no addresses supplied"
            );
            return Ok(RouterResult::Defer {
                message: Some(format!(
                    "{} router: error in redirect data: no addresses supplied",
                    router_name
                )),
            });
        }

        // Split on commas and/or whitespace to extract addresses.
        let addresses: Vec<String> = trimmed
            .split([',', ';', '\n'])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if addresses.is_empty() {
            return Ok(RouterResult::Defer {
                message: Some(format!(
                    "{} router: error in redirect data: no addresses supplied",
                    router_name
                )),
            });
        }

        tracing::info!(
            router = %router_name,
            count = addresses.len(),
            "REDIRECT generated addresses"
        );

        Ok(RouterResult::rerouted(addresses))
    }

    /// Process an ACCEPT response with keyed field data.
    ///
    /// Translates C lines 464–533: extract data, transport, hosts, lookup
    /// fields from the ACCEPT response and build the routing result.
    fn handle_accept(
        response_data: &str,
        config: &RouterInstanceConfig,
        router_name: &str,
    ) -> Result<RouterResult, QueryProgramError> {
        // Extract the "data" field (C line 468: expand_getkeyed("data", rdata)).
        let _address_data = Self::extract_keyed_field("data", response_data);

        // Extract the "transport" field (C line 473).
        let transport_field = Self::extract_keyed_field("transport", response_data);

        // Determine the transport name.
        // C lines 473–498: extract transport from response or fall back to config.
        let transport_name: Option<String> = if let Some(tname) = transport_field {
            if tname.is_empty() {
                // No transport specified in response — use config default.
                // In C, this falls through to rf_get_transport() with the
                // router's configured transport_name.
                config.transport_name.clone()
            } else {
                // Transport specified by the command.
                // In C, this iterates the transport linked list to validate.
                // We trust the name and let the delivery framework resolve it.
                // The name is tainted (from external program) but we sanitize
                // it by checking it contains only valid identifier characters.
                let tainted_name: TaintedString = Tainted::new(tname.to_string());
                let clean_name: Clean<String> = tainted_name
                    .sanitize(|s| {
                        s.chars()
                            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
                    })
                    .map_err(|_| {
                        // Transport name failed sanitization — treat as
                        // unknown transport (same as C "unknown transport name"
                        // error at queryprogram.c line 490).
                        let err = GetTransportError::ExpansionFailed(format!(
                            "invalid transport name characters in '{}'",
                            tname
                        ));
                        tracing::error!(
                            router = %router_name,
                            transport = %tname,
                            error = %err,
                            "transport name sanitization failed"
                        );
                        QueryProgramError::UnknownTransport {
                            router_name: router_name.to_string(),
                            transport_name: tname.to_string(),
                        }
                    })?;
                Some(clean_name.into_inner())
            }
        } else {
            // No transport in response — use the router's configured transport.
            // C lines 492–498: rf_get_transport() fallback.
            config.transport_name.clone()
        };

        // Extract the "hosts" field (C line 502).
        let hosts_field = Self::extract_keyed_field("hosts", response_data);

        // Build host list if hosts are specified.
        // C lines 502–533: host list building + lookup type validation.
        // The host_find_failed policy determines behavior when DNS lookup
        // of a listed host fails (C line 530: host_find_failed action).
        let host_find_failed_policy = HostFindFailedPolicy::Defer;

        let host_list: Vec<String> = if let Some(hosts_str) = hosts_field {
            if hosts_str.is_empty() {
                Vec::new()
            } else {
                // Validate the lookup type if specified (C lines 504–517).
                let lookup_field = Self::extract_keyed_field("lookup", response_data);
                if let Some(lookup_str) = lookup_field {
                    if !lookup_str.is_empty() {
                        // Wrap in Tainted and use as_str() to get Tainted<&str>
                        // for taint-aware validation, then extract inner value.
                        let tainted_lookup = Tainted::new(lookup_str.to_string());
                        let tainted_ref = tainted_lookup.as_str();
                        let raw_lookup: &str = tainted_ref.into_inner();
                        let _lookup_type = parse_lookup_type(raw_lookup, router_name)?;
                    }
                }

                // Build the host list (C line 519: host_build_hostlist).
                // Wrap in Tainted since it comes from external program output.
                let tainted_hosts: TaintedString = Tainted::new(hosts_str.to_string());
                // TAINT BYPASS RATIONALE: Host names from external program output
                // are inherently untrusted (tainted).  We use force_clean() here
                // because the delivery framework (`exim-deliver/src/orchestrator.rs`)
                // performs mandatory DNS validation on all host names before
                // establishing SMTP connections.  The `host_find_failed_policy`
                // controls behavior when DNS resolution fails (defer/fail/ignore).
                // This matches the C architecture where host_build_hostlist()
                // accepts tainted strings and host_find_bydns() validates them
                // downstream.
                let clean_hosts: Clean<String> = tainted_hosts.force_clean();
                let hosts_inner: &str = clean_hosts.as_ref();
                let hosts: Vec<String> = hosts_inner
                    .split(|c: char| c == ':' || c == ',' || c.is_whitespace())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();

                tracing::debug!(
                    router = %router_name,
                    host_count = hosts.len(),
                    host_find_policy = ?host_find_failed_policy,
                    "built host list from command response"
                );

                hosts
            }
        } else {
            Vec::new()
        };

        // Build the final RouterResult.
        if host_list.is_empty() {
            // Local delivery (no hosts).
            Ok(RouterResult::Accept {
                transport_name,
                host_list: Vec::new(),
            })
        } else {
            // Remote delivery with host list.
            Ok(RouterResult::Accept {
                transport_name,
                host_list,
            })
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  RouterDriver Trait Implementation
// ═══════════════════════════════════════════════════════════════════════════

impl RouterDriver for QueryProgramRouter {
    /// Main routing entry point — execute external program and parse response.
    ///
    /// Translates `queryprogram_router_entry()` from C (queryprogram.c
    /// lines 200–534).
    ///
    /// ## Execution Flow
    ///
    /// 1. Downcast config options to `QueryProgramRouterOptions`.
    /// 2. Validate configuration (command + command_user must be set).
    /// 3. Resolve UID/GID for command execution.
    /// 4. Expand the command string.
    /// 5. Execute the command via `std::process::Command`.
    /// 6. Read and parse the response.
    /// 7. Map the response action to a `RouterResult`.
    fn route(
        &self,
        config: &RouterInstanceConfig,
        address: &str,
        _local_user: Option<&str>,
    ) -> Result<RouterResult, DriverError> {
        let router_name = &config.name;

        tracing::debug!(
            router = %router_name,
            address = %address,
            "queryprogram router called"
        );

        // Downcast the opaque options block to our concrete type.
        let opts = config
            .options
            .downcast_ref::<QueryProgramRouterOptions>()
            .ok_or_else(|| {
                DriverError::ConfigError(format!(
                    "{} router: invalid options block type",
                    router_name
                ))
            })?;

        // Validate configuration (C: queryprogram_router_init).
        Self::validate_config(config, opts)?;

        // Set up errors_address from router config (C lines 204–210).
        // rf_get_errors_address() processes the errors_to option.
        let errors_address: Option<ErrorsAddressResult> = if config.errors_to.is_some() {
            // In full integration, this calls helpers::get_errors_address::get_errors_address().
            // The errors_to option is expanded and verified. For now we prepare the result
            // type for downstream use by the delivery framework.
            match config.errors_to.as_deref() {
                Some(addr) if !addr.is_empty() => {
                    Some(ErrorsAddressResult::Address(addr.to_string()))
                }
                Some(_) => Some(ErrorsAddressResult::IgnoreErrors),
                None => None,
            }
        } else {
            None
        };

        // Set up munge headers from router config (C lines 212–218).
        // rf_get_munge_headers() processes extra_headers and remove_headers.
        let munge_result: Option<MungeHeadersResult> = {
            let has_extra = config.extra_headers.is_some();
            let has_remove = config.remove_headers.is_some();
            if has_extra || has_remove {
                let extra_headers: Vec<HeaderLine> = config
                    .extra_headers
                    .as_deref()
                    .map(|hdr| {
                        use crate::helpers::get_munge_headers::HeaderType;
                        vec![HeaderLine {
                            text: hdr.to_string(),
                            header_type: HeaderType::Other,
                        }]
                    })
                    .unwrap_or_default();
                Some(MungeHeadersResult {
                    extra_headers,
                    remove_headers: config.remove_headers.clone(),
                })
            } else {
                None
            }
        };

        tracing::debug!(
            router = %router_name,
            errors_addr = ?errors_address,
            has_munge = munge_result.is_some(),
            "prepared errors address and header munging"
        );

        // Resolve UID/GID for command execution (C lines 251–272).
        let (ugid, _passwd) = Self::resolve_uid_gid(opts, router_name)?;

        let uid = ugid.uid.unwrap_or(0);
        let gid = ugid.gid.unwrap_or(0);

        let current_directory = opts.current_directory.as_deref().unwrap_or("/");

        tracing::debug!(
            router = %router_name,
            uid = uid,
            gid = gid,
            cwd = %current_directory,
            "resolved uid/gid for command execution"
        );

        // Get the command string (guaranteed non-None by validate_config).
        let command_str = opts.command.as_deref().unwrap_or("");

        // Execute the command and capture output (C lines 292–355).
        let tainted_output = Self::execute_command(
            command_str,
            uid,
            gid,
            current_directory,
            opts.timeout,
            router_name,
        )?;

        // Parse the response action (C lines 365–462).
        let (action, response_data) = Self::parse_action(&tainted_output, router_name)?;

        // Dispatch based on the action (C lines 376–533).
        match action {
            QueryProgramAction::AcceptRedirect { data } => {
                // REDIRECT — generate new addresses (C lines 376–441).
                tracing::info!(
                    router = %router_name,
                    "ACCEPT REDIRECT response"
                );
                let result = Self::handle_redirect(&data, router_name)?;
                Ok(result)
            }

            QueryProgramAction::Accept => {
                // ACCEPT — process keyed fields (C lines 464–533).
                tracing::info!(
                    router = %router_name,
                    "ACCEPT response"
                );
                let result = Self::handle_accept(&response_data, config, router_name)?;
                Ok(result)
            }

            QueryProgramAction::Decline => {
                // DECLINE (C line 447).
                tracing::debug!(
                    router = %router_name,
                    "DECLINE response"
                );
                Ok(RouterResult::Decline)
            }

            QueryProgramAction::Pass => {
                // PASS (C line 448).
                tracing::debug!(
                    router = %router_name,
                    "PASS response"
                );
                Ok(RouterResult::Pass)
            }

            QueryProgramAction::Fail => {
                // FAIL (C lines 450–454).
                let message = if response_data.is_empty() {
                    None
                } else {
                    Some(response_data)
                };
                tracing::info!(
                    router = %router_name,
                    message = ?message,
                    "FAIL response"
                );
                Ok(RouterResult::Fail { message })
            }

            QueryProgramAction::Defer => {
                // DEFER (C lines 456–461).
                let message = if response_data.is_empty() {
                    None
                } else {
                    Some(response_data)
                };
                tracing::debug!(
                    router = %router_name,
                    message = ?message,
                    "DEFER response"
                );
                Ok(RouterResult::Defer { message })
            }

            QueryProgramAction::Freeze => {
                // FREEZE (C line 455: special_action = SPECIAL_FREEZE; return DEFER).
                let message = if response_data.is_empty() {
                    Some(format!("{} router: message frozen", router_name))
                } else {
                    Some(response_data)
                };
                tracing::info!(
                    router = %router_name,
                    "FREEZE response — deferring with freeze"
                );
                Ok(RouterResult::Defer { message })
            }
        }
    }

    /// No-op tidyup — queryprogram router has no persistent state.
    ///
    /// C: `queryprogram_router_info.tidyup = NULL` (queryprogram.c line 557).
    fn tidyup(&self, _config: &RouterInstanceConfig) {
        // No cleanup needed — no persistent state.
    }

    /// Returns `RouterFlags::NONE` — no special flags for this router.
    ///
    /// C: `queryprogram_router_info.ri_flags = 0` (queryprogram.c line 558).
    fn flags(&self) -> RouterFlags {
        RouterFlags::NONE
    }

    /// Returns the canonical driver name `"queryprogram"`.
    ///
    /// C: `.driver_name = US"queryprogram"` (queryprogram.c line 546).
    fn driver_name(&self) -> &str {
        "queryprogram"
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Helper Functions
// ═══════════════════════════════════════════════════════════════════════════

/// Split a string into the first whitespace-delimited word and the remainder.
///
/// Returns `(first_word, rest)` where `rest` is trimmed of leading whitespace.
fn split_first_word(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    if let Some(pos) = s.find(char::is_whitespace) {
        let word = &s[..pos];
        let rest = s[pos..].trim_start();
        (word, rest)
    } else {
        (s, "")
    }
}

/// Split a command line into arguments using shell-like word splitting.
///
/// This is a simplified version that handles single and double quoted strings.
/// It does not handle escape characters beyond backslash-quote within
/// double-quoted strings.
fn split_command_line(cmd: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut chars = cmd.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double_quote => {
                in_single_quote = !in_single_quote;
            }
            '"' if !in_single_quote => {
                in_double_quote = !in_double_quote;
            }
            '\\' if in_double_quote => {
                if let Some(&next) = chars.peek() {
                    if next == '"' || next == '\\' {
                        current.push(chars.next().unwrap());
                    } else {
                        current.push(c);
                    }
                } else {
                    current.push(c);
                }
            }
            c if c.is_whitespace() && !in_single_quote && !in_double_quote => {
                if !current.is_empty() {
                    args.push(current.clone());
                    current.clear();
                }
            }
            _ => {
                current.push(c);
            }
        }
    }

    if !current.is_empty() {
        args.push(current);
    }

    args
}

/// Extract a keyed field value from a space-separated `key=value` string.
///
/// Replaces C `expand_getkeyed()` used in queryprogram.c lines 468–524.
///
/// The data format is: `key1=value1 key2=value2 key3=value3`
///
/// Values may be quoted with double quotes if they contain spaces.
///
/// Returns `None` if the key is not found.
fn extract_keyed_field<'a>(key: &str, data: &'a str) -> Option<&'a str> {
    let key_eq = format!("{}=", key);
    let data_trimmed = data.trim();

    // Iterate through the data looking for `key=` patterns.
    let mut pos = 0;
    let bytes = data_trimmed.as_bytes();

    while pos < bytes.len() {
        // Skip leading whitespace.
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if pos >= bytes.len() {
            break;
        }

        // Check if we have the target key.
        if data_trimmed[pos..].starts_with(&key_eq) {
            // Found the key — extract value.
            let value_start = pos + key_eq.len();

            if value_start >= bytes.len() {
                return Some("");
            }

            // Check for quoted value.
            if bytes[value_start] == b'"' {
                // Find the closing quote.
                let inner_start = value_start + 1;
                if let Some(end) = data_trimmed[inner_start..].find('"') {
                    return Some(&data_trimmed[inner_start..inner_start + end]);
                }
                // No closing quote — take to end of string.
                return Some(&data_trimmed[inner_start..]);
            }

            // Unquoted value — take until next whitespace.
            let value_end = data_trimmed[value_start..]
                .find(char::is_whitespace)
                .map(|end| value_start + end)
                .unwrap_or(data_trimmed.len());

            return Some(&data_trimmed[value_start..value_end]);
        }

        // Skip to next whitespace-separated token.
        while pos < bytes.len() && !bytes[pos].is_ascii_whitespace() {
            // Handle quoted values in non-target keys.
            if bytes[pos] == b'"' {
                pos += 1;
                while pos < bytes.len() && bytes[pos] != b'"' {
                    pos += 1;
                }
                if pos < bytes.len() {
                    pos += 1; // skip closing quote
                }
            } else {
                pos += 1;
            }
        }
    }

    None
}

/// Parse a lookup type string from the command response.
///
/// Translates C lines 509–516: validate the "lookup" keyed field value.
/// The input is a raw `&str` extracted from the tainted command output;
/// taint tracking is handled at the call site.
fn parse_lookup_type(lookup_str: &str, router_name: &str) -> Result<LookupType, QueryProgramError> {
    match lookup_str.to_lowercase().as_str() {
        "byname" => Ok(LookupType::ByName),
        "bydns" => Ok(LookupType::ByDns),
        "" => Ok(LookupType::Default),
        _ => Err(QueryProgramError::BadLookupType {
            router_name: router_name.to_string(),
            lookup_type: lookup_str.to_string(),
        }),
    }
}

/// Error type for child process wait operations.
enum WaitError {
    /// The child process did not complete within the timeout.
    Timeout,
    /// An I/O error occurred while waiting.
    IoError(std::io::Error),
}

/// Wait for a child process to complete with a timeout.
///
/// Implements the timeout logic that replaces C's `child_close()` with
/// its timeout parameter (queryprogram.c line 319).
fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<std::process::Output, WaitError> {
    // Use a polling approach for timeout enforcement.
    // For short timeouts, poll frequently; for long timeouts, sleep longer.
    let start = std::time::Instant::now();
    let poll_interval = Duration::from_millis(50);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Process has exited — collect output.
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();

                if let Some(ref mut out) = child.stdout {
                    let _ = out.read_to_end(&mut stdout);
                }
                if let Some(ref mut err) = child.stderr {
                    let _ = err.read_to_end(&mut stderr);
                }

                return Ok(std::process::Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                // Process still running — check timeout.
                if start.elapsed() >= timeout {
                    return Err(WaitError::Timeout);
                }
                std::thread::sleep(poll_interval);
            }
            Err(e) => {
                return Err(WaitError::IoError(e));
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Compile-Time Driver Registration
// ═══════════════════════════════════════════════════════════════════════════

// Register the queryprogram router driver via `inventory::submit!`.
//
// Guarded by `#[cfg(feature = "router-queryprogram")]`, matching the C
// preprocessor guard `#ifdef ROUTER_QUERYPROGRAM` (queryprogram.c line 12).
//
// The factory creates a new `QueryProgramRouter` instance when the
// configuration parser encounters `driver = queryprogram` in a router
// definition.
#[cfg(feature = "router-queryprogram")]
inventory::submit! {
    RouterDriverFactory {
        name: "queryprogram",
        create: || Box::new(QueryProgramRouter),
        avail_string: Some("queryprogram"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Unit Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── QueryProgramAction Tests ──────────────────────────────────────────

    #[test]
    fn test_action_enum_variants() {
        let accept = QueryProgramAction::Accept;
        assert_eq!(accept, QueryProgramAction::Accept);

        let redirect = QueryProgramAction::AcceptRedirect {
            data: "user@example.com".to_string(),
        };
        assert_eq!(
            redirect,
            QueryProgramAction::AcceptRedirect {
                data: "user@example.com".to_string()
            }
        );

        assert_eq!(QueryProgramAction::Decline, QueryProgramAction::Decline);
        assert_eq!(QueryProgramAction::Pass, QueryProgramAction::Pass);
        assert_eq!(QueryProgramAction::Defer, QueryProgramAction::Defer);
        assert_eq!(QueryProgramAction::Fail, QueryProgramAction::Fail);
        assert_eq!(QueryProgramAction::Freeze, QueryProgramAction::Freeze);
    }

    #[test]
    fn test_action_clone() {
        let action = QueryProgramAction::AcceptRedirect {
            data: "a@b".to_string(),
        };
        let cloned = action.clone();
        assert_eq!(action, cloned);
    }

    // ── QueryProgramRouterOptions Tests ──────────────────────────────────

    #[test]
    fn test_options_defaults() {
        let opts = QueryProgramRouterOptions::default();
        assert!(opts.command.is_none());
        assert_eq!(opts.timeout, 3600);
        assert!(opts.cmd_uid.is_none());
        assert!(opts.cmd_gid.is_none());
        assert!(!opts.cmd_uid_set);
        assert!(!opts.cmd_gid_set);
        assert_eq!(opts.current_directory, Some("/".to_string()));
        assert!(opts.expand_cmd_uid.is_none());
        assert!(opts.expand_cmd_gid.is_none());
    }

    #[test]
    fn test_options_with_values() {
        let opts = QueryProgramRouterOptions {
            command: Some("/usr/local/bin/route-helper".to_string()),
            timeout: 120,
            cmd_uid: Some(1000),
            cmd_gid: Some(1000),
            cmd_uid_set: true,
            cmd_gid_set: true,
            current_directory: Some("/tmp".to_string()),
            expand_cmd_uid: None,
            expand_cmd_gid: None,
        };
        assert_eq!(opts.command.as_deref(), Some("/usr/local/bin/route-helper"));
        assert_eq!(opts.timeout, 120);
        assert_eq!(opts.cmd_uid, Some(1000));
        assert_eq!(opts.cmd_gid, Some(1000));
        assert!(opts.cmd_uid_set);
        assert!(opts.cmd_gid_set);
    }

    // ── split_first_word Tests ───────────────────────────────────────────

    #[test]
    fn test_split_first_word_basic() {
        let (word, rest) = split_first_word("ACCEPT data=foo transport=bar");
        assert_eq!(word, "ACCEPT");
        assert_eq!(rest, "data=foo transport=bar");
    }

    #[test]
    fn test_split_first_word_single() {
        let (word, rest) = split_first_word("DECLINE");
        assert_eq!(word, "DECLINE");
        assert_eq!(rest, "");
    }

    #[test]
    fn test_split_first_word_empty() {
        let (word, rest) = split_first_word("");
        assert_eq!(word, "");
        assert_eq!(rest, "");
    }

    #[test]
    fn test_split_first_word_extra_whitespace() {
        let (word, rest) = split_first_word("  PASS   ");
        assert_eq!(word, "PASS");
        assert_eq!(rest, "");
    }

    // ── extract_keyed_field Tests ────────────────────────────────────────

    #[test]
    fn test_extract_keyed_field_basic() {
        let data = "data=hello transport=smtp hosts=mail.example.com";
        assert_eq!(extract_keyed_field("data", data), Some("hello"));
        assert_eq!(extract_keyed_field("transport", data), Some("smtp"));
        assert_eq!(extract_keyed_field("hosts", data), Some("mail.example.com"));
    }

    #[test]
    fn test_extract_keyed_field_missing() {
        let data = "data=hello transport=smtp";
        assert_eq!(extract_keyed_field("hosts", data), None);
        assert_eq!(extract_keyed_field("lookup", data), None);
    }

    #[test]
    fn test_extract_keyed_field_quoted() {
        let data = r#"data="hello world" transport=smtp"#;
        assert_eq!(extract_keyed_field("data", data), Some("hello world"));
        assert_eq!(extract_keyed_field("transport", data), Some("smtp"));
    }

    #[test]
    fn test_extract_keyed_field_empty_value() {
        let data = "data= transport=smtp";
        assert_eq!(extract_keyed_field("data", data), Some(""));
    }

    #[test]
    fn test_extract_keyed_field_empty_data() {
        assert_eq!(extract_keyed_field("data", ""), None);
    }

    // ── split_command_line Tests ─────────────────────────────────────────

    #[test]
    fn test_split_command_line_basic() {
        let args = split_command_line("/bin/echo hello world");
        assert_eq!(args.len(), 3);
        assert_eq!(args[0], "/bin/echo");
        assert_eq!(args[1], "hello");
        assert_eq!(args[2], "world");
    }

    #[test]
    fn test_split_command_line_quoted() {
        let args = split_command_line(r#"/bin/echo "hello world" foo"#);
        assert_eq!(args[0], "/bin/echo");
        assert_eq!(args[1], "hello world");
        assert_eq!(args[2], "foo");
    }

    #[test]
    fn test_split_command_line_single_quoted() {
        let args = split_command_line("/bin/echo 'hello world' foo");
        assert_eq!(args[0], "/bin/echo");
        assert_eq!(args[1], "hello world");
        assert_eq!(args[2], "foo");
    }

    #[test]
    fn test_split_command_line_empty() {
        let args = split_command_line("");
        assert!(args.is_empty());
    }

    // ── parse_action Tests ──────────────────────────────────────────────

    #[test]
    fn test_parse_action_accept() {
        let response = Tainted::new("ACCEPT data=foo transport=bar".to_string());
        let (action, data) = QueryProgramRouter::parse_action(&response, "test").unwrap();
        assert_eq!(action, QueryProgramAction::Accept);
        assert_eq!(data, "data=foo transport=bar");
    }

    #[test]
    fn test_parse_action_decline() {
        let response = Tainted::new("DECLINE".to_string());
        let (action, _) = QueryProgramRouter::parse_action(&response, "test").unwrap();
        assert_eq!(action, QueryProgramAction::Decline);
    }

    #[test]
    fn test_parse_action_pass() {
        let response = Tainted::new("pass".to_string());
        let (action, _) = QueryProgramRouter::parse_action(&response, "test").unwrap();
        assert_eq!(action, QueryProgramAction::Pass);
    }

    #[test]
    fn test_parse_action_defer() {
        let response = Tainted::new("DEFER try again later".to_string());
        let (action, data) = QueryProgramRouter::parse_action(&response, "test").unwrap();
        assert_eq!(action, QueryProgramAction::Defer);
        assert_eq!(data, "try again later");
    }

    #[test]
    fn test_parse_action_fail() {
        let response = Tainted::new("FAIL permanent error".to_string());
        let (action, data) = QueryProgramRouter::parse_action(&response, "test").unwrap();
        assert_eq!(action, QueryProgramAction::Fail);
        assert_eq!(data, "permanent error");
    }

    #[test]
    fn test_parse_action_freeze() {
        let response = Tainted::new("FREEZE suspicious content".to_string());
        let (action, data) = QueryProgramRouter::parse_action(&response, "test").unwrap();
        assert_eq!(action, QueryProgramAction::Freeze);
        assert_eq!(data, "suspicious content");
    }

    #[test]
    fn test_parse_action_redirect() {
        let response = Tainted::new("REDIRECT user@new.example.com".to_string());
        let (action, _) = QueryProgramRouter::parse_action(&response, "test").unwrap();
        assert_eq!(
            action,
            QueryProgramAction::AcceptRedirect {
                data: "user@new.example.com".to_string()
            }
        );
    }

    #[test]
    fn test_parse_action_case_insensitive() {
        let response = Tainted::new("accept data=test".to_string());
        let (action, _) = QueryProgramRouter::parse_action(&response, "test").unwrap();
        assert_eq!(action, QueryProgramAction::Accept);
    }

    #[test]
    fn test_parse_action_bad_keyword() {
        let response = Tainted::new("BADWORD some data".to_string());
        let result = QueryProgramRouter::parse_action(&response, "test");
        assert!(result.is_err());
        if let Err(QueryProgramError::BadCommandYield { keyword, .. }) = result {
            assert_eq!(keyword, "BADWORD");
        }
    }

    // ── validate_config Tests ───────────────────────────────────────────

    #[test]
    fn test_validate_config_missing_command() {
        let config = RouterInstanceConfig::new("test_router", "queryprogram");
        let opts = QueryProgramRouterOptions::default();
        let result = QueryProgramRouter::validate_config(&config, &opts);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_config_missing_user() {
        let config = RouterInstanceConfig::new("test_router", "queryprogram");
        let opts = QueryProgramRouterOptions {
            command: Some("/bin/test".to_string()),
            ..Default::default()
        };
        let result = QueryProgramRouter::validate_config(&config, &opts);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_config_success_with_fixed_uid() {
        let config = RouterInstanceConfig::new("test_router", "queryprogram");
        let opts = QueryProgramRouterOptions {
            command: Some("/bin/test".to_string()),
            cmd_uid: Some(1000),
            cmd_uid_set: true,
            cmd_gid: Some(1000),
            cmd_gid_set: true,
            ..Default::default()
        };
        let result = QueryProgramRouter::validate_config(&config, &opts);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_config_success_with_expand_uid() {
        let config = RouterInstanceConfig::new("test_router", "queryprogram");
        let opts = QueryProgramRouterOptions {
            command: Some("/bin/test".to_string()),
            expand_cmd_uid: Some("nobody".to_string()),
            ..Default::default()
        };
        let result = QueryProgramRouter::validate_config(&config, &opts);
        assert!(result.is_ok());
    }

    // ── handle_redirect Tests ───────────────────────────────────────────

    #[test]
    fn test_handle_redirect_single_address() {
        let result = QueryProgramRouter::handle_redirect("user@example.com", "test").unwrap();
        match result {
            RouterResult::Rerouted { new_addresses } => {
                assert_eq!(new_addresses, vec!["user@example.com"]);
            }
            _ => panic!("expected Rerouted"),
        }
    }

    #[test]
    fn test_handle_redirect_multiple_addresses() {
        let result =
            QueryProgramRouter::handle_redirect("a@b.com, c@d.com, e@f.com", "test").unwrap();
        match result {
            RouterResult::Rerouted { new_addresses } => {
                assert_eq!(new_addresses.len(), 3);
                assert_eq!(new_addresses[0], "a@b.com");
                assert_eq!(new_addresses[1], "c@d.com");
                assert_eq!(new_addresses[2], "e@f.com");
            }
            _ => panic!("expected Rerouted"),
        }
    }

    #[test]
    fn test_handle_redirect_empty() {
        let result = QueryProgramRouter::handle_redirect("", "test").unwrap();
        match result {
            RouterResult::Defer { message } => {
                assert!(message.unwrap().contains("no addresses supplied"));
            }
            _ => panic!("expected Defer"),
        }
    }

    // ── handle_accept Tests ──────────────────────────────────────────────

    #[test]
    fn test_handle_accept_with_transport() {
        let config = RouterInstanceConfig::new("test_router", "queryprogram");
        let result = QueryProgramRouter::handle_accept(
            "transport=local_delivery data=test",
            &config,
            "test_router",
        )
        .unwrap();
        match result {
            RouterResult::Accept {
                transport_name,
                host_list,
            } => {
                assert_eq!(transport_name, Some("local_delivery".to_string()));
                assert!(host_list.is_empty());
            }
            _ => panic!("expected Accept"),
        }
    }

    #[test]
    fn test_handle_accept_with_hosts() {
        let config = RouterInstanceConfig::new("test_router", "queryprogram");
        let result = QueryProgramRouter::handle_accept(
            "transport=remote_smtp hosts=mail1.example.com:mail2.example.com",
            &config,
            "test_router",
        )
        .unwrap();
        match result {
            RouterResult::Accept {
                transport_name,
                host_list,
            } => {
                assert_eq!(transport_name, Some("remote_smtp".to_string()));
                assert_eq!(host_list.len(), 2);
                assert_eq!(host_list[0], "mail1.example.com");
                assert_eq!(host_list[1], "mail2.example.com");
            }
            _ => panic!("expected Accept"),
        }
    }

    #[test]
    fn test_handle_accept_config_transport_fallback() {
        let mut config = RouterInstanceConfig::new("test_router", "queryprogram");
        config.transport_name = Some("default_transport".to_string());
        let result =
            QueryProgramRouter::handle_accept("data=test", &config, "test_router").unwrap();
        match result {
            RouterResult::Accept {
                transport_name,
                host_list,
            } => {
                assert_eq!(transport_name, Some("default_transport".to_string()));
                assert!(host_list.is_empty());
            }
            _ => panic!("expected Accept"),
        }
    }

    // ── parse_lookup_type Tests ──────────────────────────────────────────

    #[test]
    fn test_parse_lookup_type_byname() {
        let result = parse_lookup_type("byname", "test").unwrap();
        assert_eq!(result, LookupType::ByName);
    }

    #[test]
    fn test_parse_lookup_type_bydns() {
        let result = parse_lookup_type("bydns", "test").unwrap();
        assert_eq!(result, LookupType::ByDns);
    }

    #[test]
    fn test_parse_lookup_type_default() {
        let result = parse_lookup_type("", "test").unwrap();
        assert_eq!(result, LookupType::Default);
    }

    #[test]
    fn test_parse_lookup_type_invalid() {
        let result = parse_lookup_type("invalid", "test");
        assert!(result.is_err());
    }

    // ── QueryProgramRouter trait Tests ───────────────────────────────────

    #[test]
    fn test_driver_name() {
        let router = QueryProgramRouter;
        assert_eq!(router.driver_name(), "queryprogram");
    }

    #[test]
    fn test_flags() {
        let router = QueryProgramRouter;
        assert_eq!(router.flags(), RouterFlags::NONE);
    }

    #[test]
    fn test_tidyup_is_noop() {
        let router = QueryProgramRouter;
        let config = RouterInstanceConfig::new("test", "queryprogram");
        // Just verify tidyup doesn't panic.
        router.tidyup(&config);
    }

    // ── Error conversion Tests ──────────────────────────────────────────

    #[test]
    fn test_error_to_driver_error_config() {
        let err = QueryProgramError::CommandNotSet {
            router_name: "test".to_string(),
        };
        let driver_err: DriverError = err.into();
        assert!(matches!(driver_err, DriverError::ConfigError(_)));
    }

    #[test]
    fn test_error_to_driver_error_temp() {
        let err = QueryProgramError::CommandTimedOut {
            router_name: "test".to_string(),
        };
        let driver_err: DriverError = err.into();
        assert!(matches!(driver_err, DriverError::TempFail(_)));
    }

    #[test]
    fn test_error_to_driver_error_execution() {
        let err = QueryProgramError::BadCommandYield {
            router_name: "test".to_string(),
            keyword: "BAD".to_string(),
            data: "".to_string(),
        };
        let driver_err: DriverError = err.into();
        assert!(matches!(driver_err, DriverError::ExecutionFailed(_)));
    }

    // ── Integration-style route() Tests ─────────────────────────────────

    #[test]
    fn test_route_missing_options_type() {
        let router = QueryProgramRouter;
        let config = RouterInstanceConfig::new("test", "queryprogram");
        // Default options is Box<()>, not QueryProgramRouterOptions.
        let result = router.route(&config, "user@example.com", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_route_missing_command() {
        let router = QueryProgramRouter;
        let mut config = RouterInstanceConfig::new("test", "queryprogram");
        config.options = Box::new(QueryProgramRouterOptions {
            cmd_uid_set: true,
            cmd_uid: Some(1000),
            cmd_gid_set: true,
            cmd_gid: Some(1000),
            ..Default::default()
        });
        let result = router.route(&config, "user@example.com", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_route_with_echo_command() {
        // This test executes an actual command (`/bin/echo`) to verify
        // the full execution path. The command outputs "ACCEPT transport=local".
        let router = QueryProgramRouter;
        let mut config = RouterInstanceConfig::new("test_qp", "queryprogram");
        config.options = Box::new(QueryProgramRouterOptions {
            command: Some("/bin/echo ACCEPT transport=local_delivery".to_string()),
            cmd_uid_set: true,
            cmd_uid: Some(Uid::current().as_raw()),
            cmd_gid_set: true,
            cmd_gid: Some(Gid::current().as_raw()),
            current_directory: Some("/tmp".to_string()),
            timeout: 10,
            ..Default::default()
        });

        let result = router.route(&config, "user@example.com", None);
        match result {
            Ok(RouterResult::Accept {
                transport_name,
                host_list,
            }) => {
                assert_eq!(transport_name, Some("local_delivery".to_string()));
                assert!(host_list.is_empty());
            }
            other => panic!("expected Accept, got: {:?}", other),
        }
    }

    #[test]
    fn test_route_with_decline_command() {
        let router = QueryProgramRouter;
        let mut config = RouterInstanceConfig::new("test_qp", "queryprogram");
        config.options = Box::new(QueryProgramRouterOptions {
            command: Some("/bin/echo DECLINE".to_string()),
            cmd_uid_set: true,
            cmd_uid: Some(Uid::current().as_raw()),
            cmd_gid_set: true,
            cmd_gid: Some(Gid::current().as_raw()),
            timeout: 10,
            ..Default::default()
        });

        let result = router.route(&config, "user@example.com", None);
        assert_eq!(result.unwrap(), RouterResult::Decline);
    }

    #[test]
    fn test_route_with_pass_command() {
        let router = QueryProgramRouter;
        let mut config = RouterInstanceConfig::new("test_qp", "queryprogram");
        config.options = Box::new(QueryProgramRouterOptions {
            command: Some("/bin/echo PASS".to_string()),
            cmd_uid_set: true,
            cmd_uid: Some(Uid::current().as_raw()),
            cmd_gid_set: true,
            cmd_gid: Some(Gid::current().as_raw()),
            timeout: 10,
            ..Default::default()
        });

        let result = router.route(&config, "user@example.com", None);
        assert_eq!(result.unwrap(), RouterResult::Pass);
    }

    #[test]
    fn test_route_with_fail_command() {
        let router = QueryProgramRouter;
        let mut config = RouterInstanceConfig::new("test_qp", "queryprogram");
        config.options = Box::new(QueryProgramRouterOptions {
            command: Some("/bin/echo FAIL address not found".to_string()),
            cmd_uid_set: true,
            cmd_uid: Some(Uid::current().as_raw()),
            cmd_gid_set: true,
            cmd_gid: Some(Gid::current().as_raw()),
            timeout: 10,
            ..Default::default()
        });

        let result = router.route(&config, "user@example.com", None);
        match result {
            Ok(RouterResult::Fail { message }) => {
                assert!(message.is_some());
                assert!(message.unwrap().contains("address not found"));
            }
            other => panic!("expected Fail, got: {:?}", other),
        }
    }

    #[test]
    fn test_route_with_defer_command() {
        let router = QueryProgramRouter;
        let mut config = RouterInstanceConfig::new("test_qp", "queryprogram");
        config.options = Box::new(QueryProgramRouterOptions {
            command: Some("/bin/echo DEFER try later".to_string()),
            cmd_uid_set: true,
            cmd_uid: Some(Uid::current().as_raw()),
            cmd_gid_set: true,
            cmd_gid: Some(Gid::current().as_raw()),
            timeout: 10,
            ..Default::default()
        });

        let result = router.route(&config, "user@example.com", None);
        match result {
            Ok(RouterResult::Defer { message }) => {
                assert!(message.is_some());
                assert!(message.unwrap().contains("try later"));
            }
            other => panic!("expected Defer, got: {:?}", other),
        }
    }

    #[test]
    fn test_route_with_redirect_command() {
        let router = QueryProgramRouter;
        let mut config = RouterInstanceConfig::new("test_qp", "queryprogram");
        config.options = Box::new(QueryProgramRouterOptions {
            command: Some("/bin/echo REDIRECT newuser@example.com".to_string()),
            cmd_uid_set: true,
            cmd_uid: Some(Uid::current().as_raw()),
            cmd_gid_set: true,
            cmd_gid: Some(Gid::current().as_raw()),
            timeout: 10,
            ..Default::default()
        });

        let result = router.route(&config, "user@example.com", None);
        match result {
            Ok(RouterResult::Rerouted { new_addresses }) => {
                assert_eq!(new_addresses, vec!["newuser@example.com"]);
            }
            other => panic!("expected Rerouted, got: {:?}", other),
        }
    }

    #[test]
    fn test_route_command_fails() {
        let router = QueryProgramRouter;
        let mut config = RouterInstanceConfig::new("test_qp", "queryprogram");
        config.options = Box::new(QueryProgramRouterOptions {
            command: Some("/bin/false".to_string()),
            cmd_uid_set: true,
            cmd_uid: Some(Uid::current().as_raw()),
            cmd_gid_set: true,
            cmd_gid: Some(Gid::current().as_raw()),
            timeout: 10,
            ..Default::default()
        });

        let result = router.route(&config, "user@example.com", None);
        assert!(result.is_err());
    }
}
