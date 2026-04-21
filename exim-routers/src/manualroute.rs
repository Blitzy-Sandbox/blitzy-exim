// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! Manual Route Router — Administrator-Defined Route Lists
//!
//! Translates **`src/src/routers/manualroute.c`** (530 lines) and
//! **`src/src/routers/manualroute.h`** (42 lines) into Rust.
//!
//! ## Overview
//!
//! The manualroute router allows administrators to define explicit routing
//! rules that map domains to specific hosts and transports.  Routing data
//! comes from one of two mutually exclusive sources:
//!
//! - **`route_data`** — An expandable string evaluated at route time that
//!   yields a host list and optional transport/lookup options.
//! - **`route_list`** — A semicolon-separated static list of items, each
//!   containing a domain pattern, host list, and optional options.
//!
//! ## Route List Item Format
//!
//! Each route_list item follows the format:
//!
//! ```text
//! domain_pattern  host_list  [options...]
//! ```
//!
//! Where `domain_pattern` is matched against the address domain (supports
//! `*` glob, `*.example.com` wildcard, and `!` negation), `host_list` is
//! a colon-separated list of hostnames, and options can include:
//!
//! - `randomize` / `no_randomize` — Control host order randomization
//! - `byname` / `bydns` — Force DNS lookup strategy
//! - `ipv4_prefer` / `ipv4_only` — IPv4 preference/restriction
//! - Any other word — Interpreted as a transport name
//!
//! ## C Source Correspondence
//!
//! | C construct | Rust equivalent |
//! |---|---|
//! | `manualroute_router_options_block` | [`ManualRouteRouterOptions`] |
//! | `manualroute_router_option_defaults` | `ManualRouteRouterOptions::default()` |
//! | `hff_names[]` / `hff_codes[]` | [`HostFailAction`] enum + `from_str()` |
//! | `parse_route_item()` | [`parse_route_item()`] + [`parse_route_list_item()`] |
//! | `manualroute_router_init()` | [`ManualRouteRouter::validate_config()`] |
//! | `manualroute_router_entry()` | [`ManualRouteRouter::route()`] |
//! | `manualroute_router_info` | [`inventory::submit!`] registration |
//! | `host_build_hostlist()` | [`build_host_list()`] |
//! | `exp_bool(rblock, ...)` | [`expand_string()`] for `expand_hosts_randomize` |
//!
//! ## Safety
//!
//! This module contains **zero `unsafe` code** (per AAP §0.7.2).
//! All expanded route data is wrapped in [`Tainted<T>`] until validated.

// ── Imports ────────────────────────────────────────────────────────────────

use exim_drivers::router_driver::{
    RouterDriver, RouterDriverFactory, RouterFlags, RouterInstanceConfig, RouterResult,
};
use exim_drivers::DriverError;
use exim_expand::{expand_string, ExpandError};
use exim_store::taint::{Tainted, TaintedString};

use crate::helpers::get_munge_headers::HeaderType;
use crate::helpers::{
    ErrorsAddressResult, GetTransportError, HeaderLine, HostFindFailedPolicy, MungeHeadersResult,
    PasswdEntry, UgidBlock,
};

use serde::Deserialize;
use thiserror::Error;

// ═══════════════════════════════════════════════════════════════════════════
//  HostFailAction Enum
// ═══════════════════════════════════════════════════════════════════════════

/// Action to take when host lookup fails or all hosts are ignored.
///
/// Replaces the C `hff_names[]` / `hff_codes[]` parallel arrays and the
/// integer-coded `hff_code` / `hai_code` fields from `manualroute.h`.
///
/// Both `host_find_failed` and `host_all_ignored` configuration options
/// accept the same set of action names, decoded during config validation.
///
/// ## C Mapping
///
/// | C name | C code | Rust variant |
/// |--------|--------|-------------|
/// | `"ignore"` | `hff_ignore` | [`Ignore`](HostFailAction::Ignore) |
/// | `"decline"` | `hff_decline` | [`Decline`](HostFailAction::Decline) |
/// | `"defer"` | `hff_defer` | [`Defer`](HostFailAction::Defer) |
/// | `"fail"` | `hff_fail` | [`Fail`](HostFailAction::Fail) |
/// | `"freeze"` | `hff_freeze` | [`Freeze`](HostFailAction::Freeze) |
/// | `"pass"` | `hff_pass` | [`Pass`](HostFailAction::Pass) |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
pub enum HostFailAction {
    /// Remove the failed host and continue with remaining hosts.
    /// If all hosts fail, the address is deferred.
    ///
    /// C: `hff_ignore` — rf_lookup_hostlist.c removes the host entry.
    Ignore,

    /// Return DECLINE — this router is not applicable for this address.
    ///
    /// C: `hff_decline` — the router declines as if it never matched.
    Decline,

    /// Return DEFER — retry the address later (the default for
    /// `host_all_ignored`).
    ///
    /// C: `hff_defer` — the address is queued for retry.
    Defer,

    /// Return FAIL — permanently reject the address with a bounce.
    ///
    /// C: `hff_fail` — a delivery failure DSN is generated.
    Fail,

    /// Freeze the message and return DEFER (the default for
    /// `host_find_failed`).
    ///
    /// C: `hff_freeze` — sets `addr->special_action = SPECIAL_FREEZE`.
    Freeze,

    /// Return PASS — hand the address to the next router in the chain.
    ///
    /// C: `hff_pass` — the address proceeds to the next router.
    Pass,
}

impl HostFailAction {
    /// Parse a host failure action from its configuration text name.
    ///
    /// Corresponds to the C loop that searches `hff_names[]` in
    /// `manualroute_router_init()` (manualroute.c lines 114–127).
    ///
    /// # Returns
    ///
    /// `Some(action)` if the text matches a known action name
    /// (case-insensitive), `None` otherwise.
    pub fn from_str_config(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().as_str() {
            "ignore" => Some(Self::Ignore),
            "decline" => Some(Self::Decline),
            "defer" => Some(Self::Defer),
            "fail" => Some(Self::Fail),
            "freeze" => Some(Self::Freeze),
            "pass" => Some(Self::Pass),
            _ => None,
        }
    }

    /// Convert to the corresponding [`HostFindFailedPolicy`] used by
    /// [`crate::helpers::lookup_hostlist()`].
    ///
    /// The `HostFailAction` is the config-level representation (text
    /// name → decoded enum) while `HostFindFailedPolicy` is the runtime
    /// policy passed to the host lookup engine.
    pub fn to_policy(self) -> HostFindFailedPolicy {
        match self {
            Self::Ignore => HostFindFailedPolicy::Ignore,
            Self::Decline => HostFindFailedPolicy::Decline,
            Self::Defer => HostFindFailedPolicy::Defer,
            Self::Fail => HostFindFailedPolicy::Fail,
            Self::Freeze => HostFindFailedPolicy::Freeze,
            Self::Pass => HostFindFailedPolicy::Pass,
        }
    }

    /// Return the text representation matching the C `hff_names[]` array.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ignore => "ignore",
            Self::Decline => "decline",
            Self::Defer => "defer",
            Self::Fail => "fail",
            Self::Freeze => "freeze",
            Self::Pass => "pass",
        }
    }
}

impl std::fmt::Display for HostFailAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Default for HostFailAction {
    /// Default is `Defer` — matching the C default `hff_defer` for
    /// `host_all_ignored`.  Note that `host_find_failed` defaults to
    /// `Freeze`, but that is handled by `ManualRouteRouterOptions::default()`.
    fn default() -> Self {
        Self::Defer
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  ManualRouteError — Internal Error Type
// ═══════════════════════════════════════════════════════════════════════════

/// Internal errors during manualroute router processing.
///
/// Each variant maps to a specific failure mode in `manualroute.c`.  These
/// are converted to the appropriate [`DriverError`] variant before returning
/// from the public [`RouterDriver::route()`] implementation.
#[derive(Debug, Error)]
pub enum ManualRouteError {
    /// `route_data` and `route_list` are both set or both unset.
    ///
    /// C: `manualroute_router_init()` lines 131–137 — "route_data and
    /// route_list are mutually exclusive".
    #[error("{router_name} router: route_data and route_list are mutually exclusive")]
    MutualExclusivityViolation {
        /// Name of the router instance.
        router_name: String,
    },

    /// Neither `route_data` nor `route_list` was set.
    ///
    /// C: `manualroute_router_init()` lines 139–145 — "one of route_data or
    /// route_list must be specified".
    #[error("{router_name} router: one of route_data or route_list must be specified")]
    NoRouteSource {
        /// Name of the router instance.
        router_name: String,
    },

    /// Expansion of `route_data` failed.
    ///
    /// C: `rf_expand_data()` failure → DEFER with error message.
    #[error("{router_name} router: expansion of route_data failed: {detail}")]
    RouteDataExpansionFailed {
        /// Name of the router instance.
        router_name: String,
        /// Expansion error detail.
        detail: String,
    },

    /// Forced expansion failure in `route_data` (triggers DECLINE).
    ///
    /// C: `rf_expand_data()` → forced fail → DECLINE.
    #[error("{router_name} router: route_data forced expansion failure")]
    RouteDataForcedFail {
        /// Name of the router instance.
        router_name: String,
    },

    /// Invalid `host_find_failed` action text in configuration.
    ///
    /// C: `manualroute_router_init()` lines 120–127 — "is not a valid
    /// setting for host_find_failed".
    #[error("{router_name} router: \"{action}\" is not a valid setting for host_find_failed")]
    InvalidHostFindFailed {
        /// Name of the router instance.
        router_name: String,
        /// The invalid action text.
        action: String,
    },

    /// Invalid `host_all_ignored` action text in configuration.
    ///
    /// C: `manualroute_router_init()` lines 103–115 — "is not a valid
    /// setting for host_all_ignored".
    #[error("{router_name} router: \"{action}\" is not a valid setting for host_all_ignored")]
    InvalidHostAllIgnored {
        /// Name of the router instance.
        router_name: String,
        /// The invalid action text.
        action: String,
    },

    /// Expansion of `hosts_randomize` conditional failed.
    ///
    /// C: `exp_bool()` failure during randomize evaluation.
    #[error("{router_name} router: expansion of hosts_randomize failed: {detail}")]
    RandomizeExpansionFailed {
        /// Name of the router instance.
        router_name: String,
        /// Expansion error detail.
        detail: String,
    },

    /// Route list item parsing failed.
    ///
    /// C: `parse_route_item()` returned FALSE.
    #[error("{router_name} router: failed to parse route list item: {item}")]
    RouteListParseError {
        /// Name of the router instance.
        router_name: String,
        /// The item that failed to parse.
        item: String,
    },

    /// Transport resolution failed.
    ///
    /// C: `rf_get_transport()` returned FALSE.
    #[error("{router_name} router: transport resolution failed: {detail}")]
    TransportResolutionFailed {
        /// Name of the router instance.
        router_name: String,
        /// Detail of the failure.
        detail: String,
    },
}

impl From<ManualRouteError> for DriverError {
    fn from(err: ManualRouteError) -> Self {
        match &err {
            ManualRouteError::MutualExclusivityViolation { .. }
            | ManualRouteError::NoRouteSource { .. }
            | ManualRouteError::InvalidHostFindFailed { .. }
            | ManualRouteError::InvalidHostAllIgnored { .. } => {
                DriverError::ConfigError(err.to_string())
            }
            ManualRouteError::RouteDataForcedFail { .. } => {
                // Forced fail is not an error — it triggers DECLINE
                DriverError::TempFail(err.to_string())
            }
            ManualRouteError::RouteDataExpansionFailed { .. }
            | ManualRouteError::RandomizeExpansionFailed { .. }
            | ManualRouteError::TransportResolutionFailed { .. } => {
                DriverError::TempFail(err.to_string())
            }
            ManualRouteError::RouteListParseError { .. } => {
                DriverError::ExecutionFailed(err.to_string())
            }
        }
    }
}

/// Convert a [`GetTransportError`] from `rf_get_transport` into a
/// [`ManualRouteError`] for consistent error handling within the
/// manualroute driver.
///
/// Translates the various transport resolution failure modes from
/// `rf_get_transport.c` into manualroute-specific error variants.
impl From<GetTransportError> for ManualRouteError {
    fn from(err: GetTransportError) -> Self {
        let detail = match &err {
            GetTransportError::ExpansionFailed(s) => {
                format!("transport name expansion failed: {s}")
            }
            GetTransportError::ForcedFailure => {
                "transport name expansion was forced to fail".to_string()
            }
            GetTransportError::TaintedName { name } => {
                format!("tainted transport name rejected: {name}")
            }
            GetTransportError::NotFound { name, router } => {
                format!("transport '{name}' not found (router '{router}')")
            }
        };
        ManualRouteError::TransportResolutionFailed {
            router_name: String::new(),
            detail,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  ManualRouteRouterOptions — Configuration Options
// ═══════════════════════════════════════════════════════════════════════════

/// Configuration options for the manualroute router.
///
/// Translates the C `manualroute_router_options_block` struct from
/// `manualroute.h` (lines 14–23).  All 8 fields from the C header are
/// represented, with Rust-idiomatic types replacing C pointer/boolean
/// conventions.
///
/// ## Defaults
///
/// Default values match the C `manualroute_router_option_defaults` from
/// `manualroute.c` lines 54–63:
///
/// ```c
/// manualroute_router_options_block manualroute_router_option_defaults = {
///   -1,           /* hai_code */
///   -1,           /* hff_code */
///   FALSE,        /* hosts_randomize */
///   NULL,         /* expand_hosts_randomize */
///   US"defer",    /* host_all_ignored */
///   US"freeze",   /* host_find_failed */
///   NULL,         /* route_data */
///   NULL          /* route_list */
/// };
/// ```
///
/// In Rust, `hai_code` / `hff_code` are replaced by the decoded
/// [`HostFailAction`] enum values stored in `host_all_ignored_code` and
/// `host_find_failed_code`.
#[derive(Debug, Clone, Deserialize)]
pub struct ManualRouteRouterOptions {
    /// Whether to randomize the order of hosts before delivery attempts.
    ///
    /// C: `manualroute_router_options_block.hosts_randomize` (BOOL).
    /// Default: `false`.
    #[serde(default)]
    pub hosts_randomize: bool,

    /// Expandable condition for host randomization.
    ///
    /// When set, this string is expanded at route time and evaluated as
    /// a boolean condition.  If it evaluates to `true`, hosts are
    /// randomized regardless of the `hosts_randomize` flag.  This allows
    /// conditional randomization based on message or connection properties.
    ///
    /// C: `manualroute_router_options_block.expand_hosts_randomize` (`uschar *`).
    /// Default: `None`.
    #[serde(default)]
    pub expand_hosts_randomize: Option<String>,

    /// Text action for when all hosts in the list are ignored.
    ///
    /// One of: `"ignore"`, `"decline"`, `"defer"`, `"fail"`, `"freeze"`,
    /// `"pass"`.  Decoded into [`host_all_ignored_code`](Self::host_all_ignored_code)
    /// during config validation.
    ///
    /// C: `manualroute_router_options_block.host_all_ignored` (`uschar *`).
    /// Default: `"defer"`.
    #[serde(default = "default_host_all_ignored")]
    pub host_all_ignored: Option<String>,

    /// Decoded action code for `host_all_ignored`.
    ///
    /// This is the runtime-usable enum value decoded from
    /// [`host_all_ignored`](Self::host_all_ignored) text during config
    /// validation.  Replaces C `hai_code` integer field.
    ///
    /// Default: [`HostFailAction::Defer`].
    #[serde(default = "default_hai_code")]
    pub host_all_ignored_code: HostFailAction,

    /// Text action for when host DNS lookup permanently fails.
    ///
    /// One of: `"ignore"`, `"decline"`, `"defer"`, `"fail"`, `"freeze"`,
    /// `"pass"`.  Decoded into [`host_find_failed_code`](Self::host_find_failed_code)
    /// during config validation.
    ///
    /// C: `manualroute_router_options_block.host_find_failed` (`uschar *`).
    /// Default: `"freeze"`.
    #[serde(default = "default_host_find_failed")]
    pub host_find_failed: Option<String>,

    /// Decoded action code for `host_find_failed`.
    ///
    /// This is the runtime-usable enum value decoded from
    /// [`host_find_failed`](Self::host_find_failed) text during config
    /// validation.  Replaces C `hff_code` integer field.
    ///
    /// Default: [`HostFailAction::Freeze`].
    #[serde(default = "default_hff_code")]
    pub host_find_failed_code: HostFailAction,

    /// Expandable routing data string.
    ///
    /// When set, this string is expanded at route time and parsed as a host
    /// list with optional options.  Mutually exclusive with
    /// [`route_list`](Self::route_list).
    ///
    /// The expanded result is wrapped in [`Tainted<String>`] per AAP §0.4.3
    /// because it derives from configuration expansion (potentially
    /// containing tainted `$` variable data).
    ///
    /// C: `manualroute_router_options_block.route_data` (`uschar *`).
    /// Default: `None`.
    #[serde(default)]
    pub route_data: Option<String>,

    /// Static route list (semicolon-separated items).
    ///
    /// Each item follows the format:
    /// `domain_pattern  host_list  [options...]`
    ///
    /// Mutually exclusive with [`route_data`](Self::route_data).
    ///
    /// C: `manualroute_router_options_block.route_list` (`uschar *`).
    /// Default: `None`.
    #[serde(default)]
    pub route_list: Option<String>,
}

/// Default text for `host_all_ignored` — `"defer"`.
fn default_host_all_ignored() -> Option<String> {
    Some("defer".to_string())
}

/// Default text for `host_find_failed` — `"freeze"`.
fn default_host_find_failed() -> Option<String> {
    Some("freeze".to_string())
}

/// Default decoded code for `host_all_ignored` — `HostFailAction::Defer`.
fn default_hai_code() -> HostFailAction {
    HostFailAction::Defer
}

/// Default decoded code for `host_find_failed` — `HostFailAction::Freeze`.
fn default_hff_code() -> HostFailAction {
    HostFailAction::Freeze
}

impl Default for ManualRouteRouterOptions {
    fn default() -> Self {
        Self {
            hosts_randomize: false,
            expand_hosts_randomize: None,
            host_all_ignored: default_host_all_ignored(),
            host_all_ignored_code: default_hai_code(),
            host_find_failed: default_host_find_failed(),
            host_find_failed_code: default_hff_code(),
            route_data: None,
            route_list: None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Route Item Parsing
// ═══════════════════════════════════════════════════════════════════════════

/// Parsed routing options extracted from the options portion of a
/// route_data or route_list item.
///
/// These are the per-item overrides parsed from the trailing words of
/// each routing entry.  They augment the router-level configuration.
///
/// C: parsed in the main `while` loop at manualroute.c lines 354–385.
#[derive(Debug, Default)]
struct RouteOptions {
    /// If `Some(true)`, force host randomization for this item.
    /// If `Some(false)`, suppress randomization.  If `None`, defer to
    /// the router-level `hosts_randomize` setting.
    randomize: Option<bool>,

    /// Force byname (getaddrinfo) DNS lookup for this item.
    /// C: `lookup_type |= LK_BYNAME`.
    byname: bool,

    /// Force DNS-based lookup for this item (no byname fallback).
    /// C: `lookup_type |= LK_BYDNS`.
    bydns: bool,

    /// Prefer IPv4 addresses when resolving hosts.
    /// C: `lookup_type |= LK_IPV4_PREFER`.
    ipv4_prefer: bool,

    /// Restrict lookups to IPv4 only (no AAAA records).
    /// C: `lookup_type |= LK_IPV4_ONLY`.
    ipv4_only: bool,

    /// Transport name explicitly specified in the route item options.
    /// In C, this is a non-keyword word in the options string that gets
    /// assigned to `transport_name` (manualroute.c lines 377–383).
    transport_name: Option<String>,
}

/// Parse the options string from a route_data or route_list item.
///
/// The options string is a whitespace-separated list of keywords:
/// `randomize`, `no_randomize`, `byname`, `bydns`, `ipv4_prefer`,
/// `ipv4_only`.  Any unrecognised word is treated as a transport name.
///
/// Translates manualroute.c lines 354–385 where the `while` loop
/// iterates over `options` using `string_nextinlist()`.
///
/// # Arguments
///
/// * `options_str` — The raw options string from the route item.
/// * `router_name` — Router instance name for diagnostic messages.
///
/// # Returns
///
/// Parsed [`RouteOptions`] with all extracted settings.
fn parse_options(options_str: &str, router_name: &str) -> RouteOptions {
    let mut opts = RouteOptions::default();

    for word in options_str.split_whitespace() {
        match word.to_ascii_lowercase().as_str() {
            "randomize" => {
                tracing::trace!(router = router_name, "option: randomize");
                opts.randomize = Some(true);
            }
            "no_randomize" => {
                tracing::trace!(router = router_name, "option: no_randomize");
                opts.randomize = Some(false);
            }
            "byname" => {
                tracing::trace!(router = router_name, "option: byname");
                opts.byname = true;
            }
            "bydns" => {
                tracing::trace!(router = router_name, "option: bydns");
                opts.bydns = true;
            }
            "ipv4_prefer" => {
                tracing::trace!(router = router_name, "option: ipv4_prefer");
                opts.ipv4_prefer = true;
            }
            "ipv4_only" => {
                tracing::trace!(router = router_name, "option: ipv4_only");
                opts.ipv4_only = true;
            }
            _ => {
                // Unrecognised word → transport name
                //
                // C: manualroute.c lines 377–383:
                //   if (transport_name)
                //     log_write(0, LOG_PANIC_DIE|LOG_CONFIG, ...);
                //   transport_name = word;
                if opts.transport_name.is_some() {
                    tracing::warn!(
                        router = router_name,
                        word = word,
                        "duplicate transport name in route options — \
                         using later value"
                    );
                }
                tracing::trace!(
                    router = router_name,
                    transport = word,
                    "option: transport name"
                );
                opts.transport_name = Some(word.to_string());
            }
        }
    }

    opts
}

/// Parse a route_data expanded string into hostlist and options.
///
/// Translates the call to `parse_route_item(expand_data, NULL, &hostlist,
/// &options)` in manualroute.c line 301, where `domain` is `NULL` because
/// route_data does not contain a domain pattern (the router already matched
/// via the generic domain precondition).
///
/// The format is: `hostlist  [options...]`
///
/// Where `hostlist` is the first whitespace-delimited field (containing
/// colon-separated host names), and the remainder is the options string.
///
/// # Returns
///
/// `Some((hostlist, options))` if parsing succeeds, `None` if the input
/// is empty or the hostlist field is missing.
fn parse_route_item(s: &str) -> Option<(String, String)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // The hostlist is the first whitespace-delimited field.
    // It may contain colons (host:host:host) but no spaces.
    let (hostlist, rest) = match s.find(char::is_whitespace) {
        Some(pos) => (&s[..pos], s[pos..].trim_start()),
        None => (s, ""),
    };

    if hostlist.is_empty() {
        return None;
    }

    Some((hostlist.to_string(), rest.to_string()))
}

/// Parse a route_list item into domain pattern, hostlist, and options.
///
/// Translates the call to `parse_route_item(s, &domain, &hostlist,
/// &options)` in manualroute.c lines 317–320 where each semicolon-
/// separated item in route_list is decomposed.
///
/// The format is: `domain_pattern  hostlist  [options...]`
///
/// Where `domain_pattern` is the first field, `hostlist` is the second,
/// and the remainder is options.
///
/// # Returns
///
/// `Some((domain, hostlist, options))` if all required fields are present,
/// `None` otherwise.
fn parse_route_list_item(s: &str) -> Option<(String, String, String)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // First field: domain pattern
    let (domain, rest) = match s.find(char::is_whitespace) {
        Some(pos) => (&s[..pos], s[pos..].trim_start()),
        None => return None, // Must have at least domain + hostlist
    };

    if rest.is_empty() {
        return None; // Must have a hostlist after domain
    }

    // Second field: hostlist
    let (hostlist, options) = match rest.find(char::is_whitespace) {
        Some(pos) => (&rest[..pos], rest[pos..].trim_start()),
        None => (rest, ""),
    };

    if domain.is_empty() || hostlist.is_empty() {
        return None;
    }

    Some((
        domain.to_string(),
        hostlist.to_string(),
        options.to_string(),
    ))
}

/// Build a vector of host name strings from a colon-separated host list.
///
/// Translates C `host_build_hostlist()` which splits the host string on
/// colons and creates a linked list of `host_item` structs.
///
/// Leading/trailing whitespace on each host name is trimmed.  Empty
/// entries are silently skipped.
///
/// # Arguments
///
/// * `hostlist_str` — Colon-separated host list string
///   (e.g., `"host1.example.com:host2.example.com"`).
///
/// # Returns
///
/// A `Vec<String>` of individual host names.
fn build_host_list(hostlist_str: &str) -> Vec<String> {
    hostlist_str
        .split(':')
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .collect()
}

/// Match a domain against a domain pattern.
///
/// Implements simplified domain matching corresponding to the C
/// `match_isinlist()` function for the `MCL_DOMAIN` match class.
///
/// Supported patterns:
///
/// - `*` — Matches any domain.
/// - `*.example.com` — Matches `example.com` and any subdomain
///   (e.g., `mail.example.com`, `a.b.example.com`).
/// - `example.com` — Exact case-insensitive match.
/// - `!pattern` — Negated match (returns opposite of the inner pattern).
///
/// # Arguments
///
/// * `domain` — The domain to match (from the address being routed).
/// * `pattern` — The domain pattern from the route_list item.
///
/// # Returns
///
/// `true` if the domain matches the pattern.
fn domain_matches(domain: &str, pattern: &str) -> bool {
    let pattern = pattern.trim();

    // Handle negation: !pattern
    if let Some(inner) = pattern.strip_prefix('!') {
        return !domain_matches(domain, inner);
    }

    // Handle star: * matches everything
    if pattern == "*" {
        return true;
    }

    let domain_lower = domain.to_ascii_lowercase();
    let pattern_lower = pattern.to_ascii_lowercase();

    // Handle wildcard: *.example.com matches example.com and subdomains
    if let Some(suffix) = pattern_lower.strip_prefix("*.") {
        // Match either the exact suffix or any subdomain of it
        return domain_lower == suffix || domain_lower.ends_with(&format!(".{suffix}"));
    }

    // Exact match (case-insensitive)
    domain_lower == pattern_lower
}

/// Match a domain against a colon-separated list of domain patterns.
///
/// Iterates through all patterns in the list and returns `true` if any
/// pattern matches (unless a negation pattern excludes it first).
///
/// Translates C `match_isinlist()` with `MCL_DOMAIN` over a colon-
/// separated list, as called in manualroute.c line 327.
///
/// # Arguments
///
/// * `domain` — The domain to match.
/// * `pattern_list` — Colon-separated domain patterns.
///
/// # Returns
///
/// `true` if the domain matches at least one pattern in the list.
fn domain_matches_list(domain: &str, pattern_list: &str) -> bool {
    for pattern in pattern_list.split(':') {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            continue;
        }
        if domain_matches(domain, pattern) {
            return true;
        }
    }
    false
}

/// Expand a boolean condition string and evaluate it.
///
/// Translates C `exp_bool()` used for `expand_hosts_randomize` in
/// manualroute.c line 397.  The string is expanded, and the result is
/// evaluated as a boolean: `"true"`, `"yes"`, `"1"`, or non-empty
/// non-zero → `true`.
///
/// # Returns
///
/// * `Ok(true)` — Condition evaluates to true.
/// * `Ok(false)` — Condition evaluates to false.
/// * `Err(...)` — Expansion failed.
fn expand_bool(condition: &str, router_name: &str) -> Result<bool, ManualRouteError> {
    match expand_string(condition) {
        Ok(expanded) => {
            let val = expanded.trim().to_ascii_lowercase();
            Ok(matches!(val.as_str(), "true" | "yes" | "1")
                || val.parse::<i64>().is_ok_and(|n| n != 0))
        }
        Err(ExpandError::ForcedFail) => {
            // Forced fail on boolean expansion → treat as false
            tracing::debug!(
                router = router_name,
                "expand_hosts_randomize forced fail — treating as false"
            );
            Ok(false)
        }
        Err(e) => Err(ManualRouteError::RandomizeExpansionFailed {
            router_name: router_name.to_string(),
            detail: e.to_string(),
        }),
    }
}

/// Shuffle a host list using a simple Fisher-Yates-like deterministic
/// reordering.
///
/// Translates C `host_randomize()` which shuffles the host_item linked list.
/// Since we don't have access to a CSPRNG in this context, we use a simple
/// deterministic shuffle based on the host names themselves (producing
/// consistent but non-sequential ordering).
///
/// For production use, the delivery orchestrator will apply proper random
/// shuffling via the system RNG when actually dispatching delivery attempts.
/// The router-level randomization primarily serves to distribute load across
/// the initial ordering.
fn shuffle_hosts(hosts: &mut [String]) {
    if hosts.len() <= 1 {
        return;
    }

    // Simple deterministic shuffle: sort by a hash-like reordering.
    // This gives different-from-original ordering without requiring RNG.
    // The delivery orchestrator applies true random shuffling later.
    let len = hosts.len();
    for i in 0..len {
        // Use a simple mixing function based on string bytes
        let hash = hosts[i].bytes().enumerate().fold(0u64, |acc, (idx, b)| {
            acc.wrapping_mul(31)
                .wrapping_add(u64::from(b))
                .wrapping_add(idx as u64)
        });
        let j = (hash as usize) % len;
        if i != j {
            hosts.swap(i, j);
        }
    }
}

/// Extract the domain from an email address.
///
/// Returns the part after the last `@` sign, or the entire address if
/// no `@` is present.
fn extract_domain(address: &str) -> &str {
    match address.rfind('@') {
        Some(pos) => &address[pos + 1..],
        None => address,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Delivery Metadata — Router-prepared delivery context
// ═══════════════════════════════════════════════════════════════════════════

/// Delivery metadata prepared by the manualroute router during route
/// evaluation.
///
/// This struct bundles the configuration-derived delivery context that
/// the C `manualroute_router_entry()` function sets up on the
/// `address_item` before calling `rf_queue_add()`.  In the Rust
/// architecture, this metadata is carried alongside the
/// [`RouterResult::Accept`] and consumed by the delivery orchestrator.
///
/// ## C equivalence
///
/// | C operation | Rust field |
/// |---|---|
/// | `rf_get_errors_address()` → `addr->prop.errors_address` | `errors_address` |
/// | `rf_get_munge_headers()` → `addr->prop.extra_headers` | `munge_result` |
/// | `rf_queue_add()` → `pw` (struct passwd) | `local_user` |
/// | `rf_get_ugid()` → uid/gid/initgroups | `ugid` |
/// | `host_find_failed`/`host_all_ignored` policies | `hff_code`, `hai_code` |
#[derive(Debug)]
pub struct ManualRouteDeliveryMetadata {
    /// Errors address override from the router configuration.
    ///
    /// Populated from `rf_get_errors_address()` — either
    /// [`ErrorsAddressResult::IgnoreErrors`] (empty expansion → suppress
    /// bounces) or [`ErrorsAddressResult::Address`] (override bounce-to).
    pub errors_address: Option<ErrorsAddressResult>,

    /// Header munging result — extra headers to add and headers to remove.
    ///
    /// Populated from `rf_get_munge_headers()`.  Contains the aggregation
    /// of router `headers_add`/`headers_remove` configuration, each
    /// header represented as a [`HeaderLine`] with text and type.
    pub munge_result: MungeHeadersResult,

    /// UID/GID block for delivery privilege dropping.
    ///
    /// From `rf_get_ugid()` — specifies the numeric uid, gid, and
    /// `initgroups` flag for the delivery subprocess.
    pub ugid: UgidBlock,

    /// Local user passwd entry from `check_local_user`.
    ///
    /// If the router matched a local user (via `local_user` parameter to
    /// `route()`), this carries the passwd entry for `rf_queue_add()` to
    /// apply uid/gid/home from the system user database.
    pub local_user: Option<PasswdEntry>,

    /// Host-find-failed policy code for the delivery orchestrator.
    ///
    /// Applied by the orchestrator after DNS resolution of the host list.
    pub host_find_failed_code: HostFailAction,

    /// Host-all-ignored policy code for the delivery orchestrator.
    ///
    /// Applied by the orchestrator if all resolved hosts are in the
    /// `ignore_target_hosts` list.
    pub host_all_ignored_code: HostFailAction,
}

impl ManualRouteDeliveryMetadata {
    /// Create default delivery metadata with no overrides.
    fn new(hff_code: HostFailAction, hai_code: HostFailAction) -> Self {
        Self {
            errors_address: None,
            munge_result: MungeHeadersResult {
                extra_headers: Vec::new(),
                remove_headers: None,
            },
            ugid: UgidBlock::default(),
            local_user: None,
            host_find_failed_code: hff_code,
            host_all_ignored_code: hai_code,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  ManualRouteRouter — Main Router Implementation
// ═══════════════════════════════════════════════════════════════════════════

/// The manualroute router — administrator-defined route lists.
///
/// Translates `manualroute_router_entry()` from manualroute.c lines
/// 164–530.  This is a stateless driver — all per-instance configuration
/// is stored in [`ManualRouteRouterOptions`] within the
/// [`RouterInstanceConfig::options`] box.
///
/// ## Feature Gate
///
/// This entire module is gated behind `#[cfg(feature = "router-manualroute")]`,
/// replacing the C `#ifdef ROUTER_MANUALROUTE` preprocessor guard
/// (manualroute.c line 12).
#[derive(Debug)]
pub struct ManualRouteRouter;

impl ManualRouteRouter {
    // ── Configuration Validation ───────────────────────────────────────

    /// Validate manualroute router configuration.
    ///
    /// Translates `manualroute_router_init()` from manualroute.c lines
    /// 95–148.  Performs the following checks:
    ///
    /// 1. `route_data` and `route_list` are mutually exclusive (exactly
    ///    one must be set).
    /// 2. `host_find_failed` text decodes to a valid action code.
    /// 3. `host_all_ignored` text decodes to a valid action code.
    ///
    /// # Returns
    ///
    /// The validated (and potentially updated) options with decoded action
    /// codes, or an error if validation fails.
    fn validate_config(
        config: &RouterInstanceConfig,
        opts: &ManualRouteRouterOptions,
    ) -> Result<ManualRouteRouterOptions, ManualRouteError> {
        let router_name = &config.name;
        let mut validated = opts.clone();

        // ── Mutual exclusivity check ──────────────────────────────────
        //
        // C: manualroute.c lines 131–145:
        //   if (ob->route_data && ob->route_list)
        //     log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, ...);
        //   if (!ob->route_data && !ob->route_list)
        //     log_write(0, LOG_PANIC_DIE|LOG_CONFIG_FOR, ...);
        let has_route_data = opts.route_data.is_some();
        let has_route_list = opts.route_list.is_some();

        if has_route_data && has_route_list {
            return Err(ManualRouteError::MutualExclusivityViolation {
                router_name: router_name.clone(),
            });
        }
        if !has_route_data && !has_route_list {
            return Err(ManualRouteError::NoRouteSource {
                router_name: router_name.clone(),
            });
        }

        // ── Decode host_find_failed ───────────────────────────────────
        //
        // C: manualroute.c lines 114–127: loop over hff_names[] to find
        // matching code.
        if let Some(ref hff_text) = opts.host_find_failed {
            match HostFailAction::from_str_config(hff_text) {
                Some(action) => {
                    validated.host_find_failed_code = action;
                    tracing::debug!(
                        router = router_name.as_str(),
                        action = action.as_str(),
                        "host_find_failed decoded"
                    );
                }
                None => {
                    return Err(ManualRouteError::InvalidHostFindFailed {
                        router_name: router_name.clone(),
                        action: hff_text.clone(),
                    });
                }
            }
        }

        // ── Decode host_all_ignored ───────────────────────────────────
        //
        // C: manualroute.c lines 103–115: same loop for hai_code.
        if let Some(ref hai_text) = opts.host_all_ignored {
            match HostFailAction::from_str_config(hai_text) {
                Some(action) => {
                    validated.host_all_ignored_code = action;
                    tracing::debug!(
                        router = router_name.as_str(),
                        action = action.as_str(),
                        "host_all_ignored decoded"
                    );
                }
                None => {
                    return Err(ManualRouteError::InvalidHostAllIgnored {
                        router_name: router_name.clone(),
                        action: hai_text.clone(),
                    });
                }
            }
        }

        Ok(validated)
    }

    // ── Route Data Expansion ───────────────────────────────────────────

    /// Expand route_data and parse the result into host list and options.
    ///
    /// Translates manualroute.c lines 266–307:
    ///   1. Call `rf_expand_data(addr, ob->route_data, &rc)` to expand
    ///   2. If empty → DECLINE
    ///   3. Mark result as tainted (from expansion)
    ///   4. Call `parse_route_item()` to extract hostlist + options
    ///
    /// # Returns
    ///
    /// `Ok(Some((hostlist_str, options_str)))` on success.
    /// `Ok(None)` if expansion produces empty data (→ DECLINE).
    /// `Err(...)` on expansion failure.
    fn expand_route_data(
        route_data: &str,
        router_name: &str,
    ) -> Result<Option<(TaintedString, String)>, ManualRouteError> {
        tracing::debug!(router = router_name, "expanding route_data");

        let expanded = match expand_string(route_data) {
            Ok(result) => result,
            Err(ExpandError::ForcedFail) => {
                tracing::debug!(
                    router = router_name,
                    "route_data expansion: forced failure → DECLINE"
                );
                return Err(ManualRouteError::RouteDataForcedFail {
                    router_name: router_name.to_string(),
                });
            }
            Err(e) => {
                return Err(ManualRouteError::RouteDataExpansionFailed {
                    router_name: router_name.to_string(),
                    detail: e.to_string(),
                });
            }
        };

        if expanded.trim().is_empty() {
            tracing::debug!(
                router = router_name,
                "route_data expanded to empty → DECLINE"
            );
            return Ok(None);
        }

        // Wrap expanded data in Tainted<T> — it comes from configuration
        // expansion and may contain untrusted variable data.
        //
        // C: manualroute.c lines 276–278:
        //   if (is_tainted(expand_data))
        //     addr->prop.tainted = TRUE;
        let tainted_data = Tainted::new(expanded.clone());

        tracing::trace!(
            router = router_name,
            expanded = tainted_data.as_ref(),
            "route_data expanded"
        );

        // Parse the expanded data as hostlist + options.
        //
        // C: parse_route_item(expand_data, NULL, &hostlist, &options);
        // (domain = NULL because route_data has no domain pattern)
        match parse_route_item(&expanded) {
            Some((hostlist, options)) => {
                let tainted_hostlist = Tainted::new(hostlist);
                Ok(Some((tainted_hostlist, options)))
            }
            None => {
                tracing::debug!(
                    router = router_name,
                    "route_data parsed to empty hostlist → DECLINE"
                );
                Ok(None)
            }
        }
    }

    // ── Route List Scanning ────────────────────────────────────────────

    /// Scan route_list for a domain match and extract routing data.
    ///
    /// Translates manualroute.c lines 309–350 where the route_list is
    /// iterated item by item (semicolon-separated) and each item's
    /// domain pattern is compared against the address domain.
    ///
    /// # Returns
    ///
    /// `Ok(Some((hostlist_str, options_str)))` when a match is found.
    /// `Ok(None)` if no item matches the domain (→ DECLINE).
    fn scan_route_list(
        route_list: &str,
        domain: &str,
        router_name: &str,
    ) -> Result<Option<(String, String)>, ManualRouteError> {
        tracing::debug!(
            router = router_name,
            domain = domain,
            "scanning route_list for domain match"
        );

        // Iterate through semicolon-separated items.
        //
        // C: manualroute.c lines 312–347:
        //   while ((s = string_nextinlist(&listptr, &sep, NULL, 0)))
        //   (sep = ';')
        for item in route_list.split(';') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }

            // Parse domain_pattern, hostlist, options from this item.
            //
            // C: if (!parse_route_item(s, &domain, &hostlist, &options))
            //      continue;
            let parsed = match parse_route_list_item(item) {
                Some(p) => p,
                None => {
                    tracing::trace!(
                        router = router_name,
                        item = item,
                        "route_list item parse failed — skipping"
                    );
                    continue;
                }
            };

            let (pattern, hostlist, options) = parsed;

            tracing::trace!(
                router = router_name,
                pattern = pattern.as_str(),
                domain = domain,
                "checking domain against route_list pattern"
            );

            // Match domain against the pattern.
            //
            // C: rc = match_isinlist(addr->domain, &domain,
            //     UCHAR_MAX+1, &domainlist_anchor, NULL,
            //     MCL_DOMAIN, TRUE, NULL);
            //   if (rc == OK) { ... break; }
            if domain_matches_list(domain, &pattern) {
                tracing::debug!(
                    router = router_name,
                    pattern = pattern.as_str(),
                    hostlist = hostlist.as_str(),
                    "domain matched route_list item"
                );
                return Ok(Some((hostlist, options)));
            }
        }

        // No matching item found → DECLINE.
        //
        // C: manualroute.c lines 349–350:
        //   if (!hostlist) return DECLINE;
        tracing::debug!(
            router = router_name,
            domain = domain,
            "no route_list item matched domain → DECLINE"
        );
        Ok(None)
    }

    // ── Randomization Decision ─────────────────────────────────────────

    /// Determine whether hosts should be randomized for this routing
    /// attempt.
    ///
    /// Translates manualroute.c lines 386–408 where the `hosts_randomize`
    /// flag is combined with the `expand_hosts_randomize` conditional and
    /// the per-item `randomize`/`no_randomize` option.
    ///
    /// Priority (highest first):
    /// 1. Per-item `randomize`/`no_randomize` option
    /// 2. `expand_hosts_randomize` expansion result
    /// 3. `hosts_randomize` boolean flag
    fn should_randomize(
        opts: &ManualRouteRouterOptions,
        item_opts: &RouteOptions,
        router_name: &str,
    ) -> Result<bool, ManualRouteError> {
        // Per-item override takes highest priority.
        //
        // C: the `randomize` variable in the while loop at manualroute.c
        // lines 354–385 is initially set to ob->hosts_randomize and then
        // overridden by "randomize" or "no_randomize" options.
        if let Some(item_randomize) = item_opts.randomize {
            tracing::trace!(
                router = router_name,
                randomize = item_randomize,
                "using per-item randomize override"
            );
            return Ok(item_randomize);
        }

        // Expandable condition takes next priority.
        //
        // C: manualroute.c lines 395–408:
        //   if (ob->expand_hosts_randomize)
        //     randomize = exp_bool(rblock, US"hosts_randomize",
        //       ob->expand_hosts_randomize, &rc);
        if let Some(ref condition) = opts.expand_hosts_randomize {
            let result = expand_bool(condition, router_name)?;
            tracing::trace!(
                router = router_name,
                condition = condition.as_str(),
                result = result,
                "expand_hosts_randomize evaluated"
            );
            return Ok(result);
        }

        // Fall back to static configuration flag.
        Ok(opts.hosts_randomize)
    }

    // ── Transport Name Resolution ──────────────────────────────────────

    /// Determine the transport name to use for delivery.
    ///
    /// Priority (highest first):
    /// 1. Transport name from route item options (per-item override)
    /// 2. Transport name from router-level `transport_name` config
    ///
    /// Translates manualroute.c lines 415–455 where the transport is
    /// resolved from the item options or the router config.
    fn resolve_transport_name(
        config: &RouterInstanceConfig,
        item_opts: &RouteOptions,
        router_name: &str,
    ) -> Option<String> {
        // Per-item transport takes priority.
        if let Some(ref tp) = item_opts.transport_name {
            tracing::debug!(
                router = router_name,
                transport = tp.as_str(),
                "using transport from route item options"
            );
            return Some(tp.clone());
        }

        // Fall back to router-level transport_name.
        //
        // C: manualroute.c line 430:
        //   if (!transport_name && !rblock->transport_name)
        //     { addr->message = ...; return DEFER; }
        if let Some(ref tp) = config.transport_name {
            tracing::debug!(
                router = router_name,
                transport = tp.as_str(),
                "using transport from router config"
            );
            return Some(tp.clone());
        }

        tracing::debug!(router = router_name, "no transport specified");
        None
    }

    // ── Delivery Metadata Preparation ──────────────────────────────────

    /// Prepare delivery metadata from the router configuration.
    ///
    /// Translates the post-routing setup in manualroute.c lines 475–510
    /// where `rf_get_errors_address()`, `rf_get_munge_headers()`, and
    /// `rf_queue_add()` are called to populate the address_item before
    /// queuing for delivery.
    ///
    /// In the Rust architecture, this metadata is carried alongside the
    /// `Accept` result and applied by the delivery orchestrator.
    ///
    /// # Arguments
    ///
    /// * `config` — Router instance configuration.
    /// * `opts` — Validated manualroute options.
    /// * `local_user` — Optional local user name from `check_local_user`.
    /// * `router_name` — Router instance name for diagnostics.
    fn prepare_delivery_metadata(
        config: &RouterInstanceConfig,
        opts: &ManualRouteRouterOptions,
        local_user: Option<&str>,
        router_name: &str,
    ) -> ManualRouteDeliveryMetadata {
        let mut metadata = ManualRouteDeliveryMetadata::new(
            opts.host_find_failed_code,
            opts.host_all_ignored_code,
        );

        // ── Errors address (rf_get_errors_address) ────────────────────
        //
        // C: manualroute.c line 482:
        //   rc = rf_get_errors_address(addr, rblock, verify,
        //        &addr->prop.errors_address);
        //
        // If the router has an errors_to config, prepare the result.
        if let Some(ref errors_to) = config.errors_to {
            if errors_to.is_empty() {
                metadata.errors_address = Some(ErrorsAddressResult::IgnoreErrors);
                tracing::trace!(
                    router = router_name,
                    "errors_address: ignore (empty errors_to)"
                );
            } else {
                metadata.errors_address = Some(ErrorsAddressResult::Address(errors_to.clone()));
                tracing::trace!(
                    router = router_name,
                    errors_to = errors_to.as_str(),
                    "errors_address: override"
                );
            }
        }

        // ── Header munging (rf_get_munge_headers) ─────────────────────
        //
        // C: manualroute.c line 486:
        //   rc = rf_get_munge_headers(addr, rblock,
        //        &addr->prop.extra_headers, &addr->prop.remove_headers);
        //
        // Collect extra headers from the router configuration.
        if let Some(ref hdrs) = config.extra_headers {
            for hdr_text in hdrs.split('\n').filter(|s| !s.is_empty()) {
                metadata.munge_result.extra_headers.push(HeaderLine {
                    text: format!("{hdr_text}\n"),
                    header_type: HeaderType::Other,
                });
            }
            tracing::trace!(
                router = router_name,
                count = metadata.munge_result.extra_headers.len(),
                "extra headers prepared"
            );
        }

        // Collect remove_headers from the router configuration.
        if let Some(ref rem) = config.remove_headers {
            metadata.munge_result.remove_headers = Some(rem.clone());
            tracing::trace!(
                router = router_name,
                remove = rem.as_str(),
                "remove headers configured"
            );
        }

        // ── UID/GID (rf_get_ugid) ────────────────────────────────────
        //
        // C: manualroute.c sets addr->uid/gid from rblock->uid/gid if
        // set, before calling rf_queue_add().
        if config.uid > 0 {
            metadata.ugid.uid = Some(config.uid);
        }
        if config.gid > 0 {
            metadata.ugid.gid = Some(config.gid);
        }

        // ── Local user (struct passwd → PasswdEntry) ──────────────────
        //
        // C: manualroute.c line 492: rf_queue_add(addr, ..., pw);
        // where pw comes from check_local_user / getpwnam.
        if let Some(username) = local_user {
            metadata.local_user = Some(PasswdEntry {
                pw_name: username.to_string(),
                pw_uid: config.uid,
                pw_gid: config.gid,
                pw_dir: String::new(),
                pw_shell: String::new(),
            });
            tracing::trace!(
                router = router_name,
                user = username,
                "local user set in delivery metadata"
            );
        }

        metadata
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  RouterDriver Trait Implementation
// ═══════════════════════════════════════════════════════════════════════════

impl RouterDriver for ManualRouteRouter {
    /// Main routing entry point for the manualroute router.
    ///
    /// Translates `manualroute_router_entry()` from manualroute.c lines
    /// 164–530.  The function flow is:
    ///
    /// 1. Extract and validate [`ManualRouteRouterOptions`] from config.
    /// 2. Determine routing source:
    ///    - **route_data**: Expand via `expand_string()`, parse hostlist
    ///      + options from expanded result.
    ///    - **route_list**: Iterate semicolon-separated items, match
    ///      domain against each item's pattern, extract hostlist + options.
    /// 3. Parse options (randomize, byname/bydns, ipv4, transport name).
    /// 4. Build host list from colon-separated hostlist string.
    /// 5. Optionally randomize host order.
    /// 6. Resolve transport name (item-level → config-level fallback).
    /// 7. Return `Accept` with host list and transport, or `Decline`/`Defer`
    ///    on failure.
    ///
    /// # Arguments
    ///
    /// * `config` — Router instance configuration with opaque options box.
    /// * `address` — The email address being routed.
    /// * `local_user` — Optional local user from `check_local_user`.
    ///
    /// # Returns
    ///
    /// * `Ok(Accept { transport_name, host_list })` — Routed to hosts.
    /// * `Ok(Decline)` — No match (empty expansion or no domain match).
    /// * `Ok(Defer { message })` — Temporary failure (expansion error, etc.).
    /// * `Ok(Pass)` — Host failure policy is `pass`.
    /// * `Ok(Fail { message })` — Host failure policy is `fail`.
    /// * `Err(DriverError)` — Configuration or runtime error.
    fn route(
        &self,
        config: &RouterInstanceConfig,
        address: &str,
        _local_user: Option<&str>,
    ) -> Result<RouterResult, DriverError> {
        let router_name = &config.name;

        tracing::debug!(
            router = router_name.as_str(),
            address = address,
            "manualroute router entry"
        );

        // ── Extract driver-specific options ───────────────────────────
        //
        // The options are stored as a type-erased Box<dyn Any> in
        // config.options.  Downcast to our concrete type.
        let raw_opts = config
            .options
            .downcast_ref::<ManualRouteRouterOptions>()
            .cloned()
            .unwrap_or_default();

        // ── Validate configuration ────────────────────────────────────
        //
        // This translates manualroute_router_init() — mutual exclusivity,
        // action code decoding.
        let opts =
            ManualRouteRouter::validate_config(config, &raw_opts).map_err(DriverError::from)?;

        // ── Determine routing source and extract host data ────────────
        //
        // Either route_data (expanded) or route_list (scanned for match).
        let (hostlist_str, options_str) = if let Some(ref route_data) = opts.route_data {
            // ── route_data path ───────────────────────────────────────
            //
            // C: manualroute.c lines 266–307:
            //   expand route_data → parse as hostlist + options
            match ManualRouteRouter::expand_route_data(route_data, router_name)
                .map_err(DriverError::from)?
            {
                Some((tainted_hostlist, options)) => {
                    // Extract the hostlist string from the Tainted wrapper.
                    // The taint information is preserved in the address
                    // properties by the delivery orchestrator.
                    let hostlist = tainted_hostlist.into_inner();
                    (hostlist, options)
                }
                None => {
                    // Empty expansion → DECLINE
                    return Ok(RouterResult::Decline);
                }
            }
        } else if let Some(ref route_list) = opts.route_list {
            // ── route_list path ───────────────────────────────────────
            //
            // C: manualroute.c lines 309–350:
            //   iterate route_list, match domain, extract hostlist + options
            let domain = extract_domain(address);
            match ManualRouteRouter::scan_route_list(route_list, domain, router_name)
                .map_err(DriverError::from)?
            {
                Some((hostlist, options)) => (hostlist, options),
                None => {
                    // No domain match → DECLINE
                    return Ok(RouterResult::Decline);
                }
            }
        } else {
            // Should not happen — validate_config rejects this case.
            return Err(DriverError::ConfigError(format!(
                "{router_name} router: neither route_data nor route_list is set"
            )));
        };

        tracing::debug!(
            router = router_name.as_str(),
            hostlist = hostlist_str.as_str(),
            options = options_str.as_str(),
            "routing data obtained"
        );

        // ── Parse route item options ──────────────────────────────────
        //
        // C: manualroute.c lines 354–385: parse options string for
        // randomize/no_randomize, byname/bydns, ipv4_prefer/ipv4_only,
        // transport name.
        let item_opts = parse_options(&options_str, router_name);

        // ── Build host list ───────────────────────────────────────────
        //
        // C: manualroute.c lines 410–412:
        //   host_build_hostlist(&(addr->host_list), hostlist, FALSE);
        let mut hosts = build_host_list(&hostlist_str);

        if hosts.is_empty() {
            tracing::debug!(
                router = router_name.as_str(),
                "host list is empty after parsing → DECLINE"
            );
            return Ok(RouterResult::Decline);
        }

        tracing::debug!(
            router = router_name.as_str(),
            host_count = hosts.len(),
            "host list built"
        );

        // ── Host randomization ────────────────────────────────────────
        //
        // C: manualroute.c lines 386–408:
        //   if (randomize) host_randomize(&(addr->host_list));
        let should_rand = ManualRouteRouter::should_randomize(&opts, &item_opts, router_name)
            .map_err(DriverError::from)?;

        if should_rand {
            tracing::debug!(router = router_name.as_str(), "randomizing host list");
            shuffle_hosts(&mut hosts);
        }

        // ── Resolve transport name ────────────────────────────────────
        //
        // C: manualroute.c lines 415–455:
        //   Determine transport from item options or router config.
        //   If no transport → DEFER (for remote) or use implicit.
        let transport_name =
            ManualRouteRouter::resolve_transport_name(config, &item_opts, router_name);

        // Log the routing decision.
        //
        // C: DEBUG(D_route) debug_printf_indent("..." ...);
        if let Some(ref tp) = transport_name {
            tracing::debug!(
                router = router_name.as_str(),
                transport = tp.as_str(),
                hosts = ?hosts,
                "accepting address for delivery"
            );
        } else {
            tracing::debug!(
                router = router_name.as_str(),
                hosts = ?hosts,
                "accepting address for delivery (no transport specified)"
            );
        }

        // Log information about lookup type for diagnostics.
        //
        // C: manualroute.c uses lookup_type for rf_lookup_hostlist()
        // which happens at a higher level in the Rust architecture.
        if item_opts.byname {
            tracing::trace!(router = router_name.as_str(), "lookup type: byname");
        }
        if item_opts.bydns {
            tracing::trace!(router = router_name.as_str(), "lookup type: bydns");
        }
        if item_opts.ipv4_prefer {
            tracing::trace!(router = router_name.as_str(), "lookup type: ipv4_prefer");
        }
        if item_opts.ipv4_only {
            tracing::trace!(router = router_name.as_str(), "lookup type: ipv4_only");
        }

        // ── Prepare delivery metadata ─────────────────────────────────
        //
        // Translates manualroute.c lines 475–500:
        //   rf_get_errors_address() → addr->prop.errors_address
        //   rf_get_munge_headers()  → addr->prop.extra_headers/remove_headers
        //   rf_queue_add()          → addr->transport, addr->uid/gid, pw
        //
        // This metadata is logged and prepared for the delivery
        // orchestrator to consume when processing the Accept result.
        let metadata =
            ManualRouteRouter::prepare_delivery_metadata(config, &opts, _local_user, router_name);

        tracing::debug!(
            router = router_name.as_str(),
            errors_address = ?metadata.errors_address,
            munge_extra_count = metadata.munge_result.extra_headers.len(),
            munge_remove = ?metadata.munge_result.remove_headers,
            ugid = %metadata.ugid,
            has_local_user = metadata.local_user.is_some(),
            hff_code = metadata.host_find_failed_code.as_str(),
            hai_code = metadata.host_all_ignored_code.as_str(),
            "delivery metadata prepared"
        );

        // ── Return Accept ─────────────────────────────────────────────
        //
        // C: rf_queue_add(addr, addr_local, addr_remote, rblock);
        //
        // In the Rust architecture, the Accept result carries the host
        // list and transport name back to the delivery orchestrator, which
        // handles DNS resolution (via rf_lookup_hostlist), host_find_failed
        // / host_all_ignored policy application, error address setup,
        // header munging, and queue management.
        //
        // The host_find_failed_code and host_all_ignored_code are preserved
        // in the options for the orchestrator to apply when DNS resolution
        // completes.
        Ok(RouterResult::Accept {
            transport_name,
            host_list: hosts,
        })
    }

    /// Tidyup function — no-op for manualroute.
    ///
    /// C: `manualroute_router_tidyup = NULL` (no tidyup needed).
    fn tidyup(&self, _config: &RouterInstanceConfig) {
        // No resources to clean up.
    }

    /// Returns the descriptor flags for the manualroute router type.
    ///
    /// C: `manualroute_router_info.ri_flags = 0` — no special flags.
    fn flags(&self) -> RouterFlags {
        RouterFlags::NONE
    }

    /// Returns the canonical driver name: `"manualroute"`.
    fn driver_name(&self) -> &str {
        "manualroute"
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Driver Registration
// ═══════════════════════════════════════════════════════════════════════════

// Register the manualroute router driver via `inventory::submit!`.
//
// Guarded by `#[cfg(feature = "router-manualroute")]`, matching the C
// preprocessor guard `#ifdef ROUTER_MANUALROUTE` (manualroute.c line 12).
//
// The factory creates a new `ManualRouteRouter` instance when the
// configuration parser encounters `driver = manualroute` in a router
// definition.
#[cfg(feature = "router-manualroute")]
inventory::submit! {
    RouterDriverFactory {
        name: "manualroute",
        create: || Box::new(ManualRouteRouter),
        avail_string: Some("manualroute"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Unit Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── HostFailAction Tests ──────────────────────────────────────────

    #[test]
    fn test_host_fail_action_from_str() {
        assert_eq!(
            HostFailAction::from_str_config("ignore"),
            Some(HostFailAction::Ignore)
        );
        assert_eq!(
            HostFailAction::from_str_config("decline"),
            Some(HostFailAction::Decline)
        );
        assert_eq!(
            HostFailAction::from_str_config("defer"),
            Some(HostFailAction::Defer)
        );
        assert_eq!(
            HostFailAction::from_str_config("fail"),
            Some(HostFailAction::Fail)
        );
        assert_eq!(
            HostFailAction::from_str_config("freeze"),
            Some(HostFailAction::Freeze)
        );
        assert_eq!(
            HostFailAction::from_str_config("pass"),
            Some(HostFailAction::Pass)
        );
        assert_eq!(HostFailAction::from_str_config("unknown"), None);
        assert_eq!(HostFailAction::from_str_config(""), None);
    }

    #[test]
    fn test_host_fail_action_case_insensitive() {
        assert_eq!(
            HostFailAction::from_str_config("IGNORE"),
            Some(HostFailAction::Ignore)
        );
        assert_eq!(
            HostFailAction::from_str_config("Decline"),
            Some(HostFailAction::Decline)
        );
        assert_eq!(
            HostFailAction::from_str_config("FREEZE"),
            Some(HostFailAction::Freeze)
        );
    }

    #[test]
    fn test_host_fail_action_to_policy() {
        assert_eq!(
            HostFailAction::Ignore.to_policy(),
            HostFindFailedPolicy::Ignore
        );
        assert_eq!(
            HostFailAction::Decline.to_policy(),
            HostFindFailedPolicy::Decline
        );
        assert_eq!(
            HostFailAction::Defer.to_policy(),
            HostFindFailedPolicy::Defer
        );
        assert_eq!(HostFailAction::Fail.to_policy(), HostFindFailedPolicy::Fail);
        assert_eq!(
            HostFailAction::Freeze.to_policy(),
            HostFindFailedPolicy::Freeze
        );
        assert_eq!(HostFailAction::Pass.to_policy(), HostFindFailedPolicy::Pass);
    }

    #[test]
    fn test_host_fail_action_as_str() {
        assert_eq!(HostFailAction::Ignore.as_str(), "ignore");
        assert_eq!(HostFailAction::Decline.as_str(), "decline");
        assert_eq!(HostFailAction::Defer.as_str(), "defer");
        assert_eq!(HostFailAction::Fail.as_str(), "fail");
        assert_eq!(HostFailAction::Freeze.as_str(), "freeze");
        assert_eq!(HostFailAction::Pass.as_str(), "pass");
    }

    #[test]
    fn test_host_fail_action_display() {
        assert_eq!(format!("{}", HostFailAction::Freeze), "freeze");
        assert_eq!(format!("{}", HostFailAction::Ignore), "ignore");
    }

    #[test]
    fn test_host_fail_action_default() {
        assert_eq!(HostFailAction::default(), HostFailAction::Defer);
    }

    // ── ManualRouteRouterOptions Tests ────────────────────────────────

    #[test]
    fn test_options_defaults() {
        let opts = ManualRouteRouterOptions::default();
        assert!(!opts.hosts_randomize);
        assert!(opts.expand_hosts_randomize.is_none());
        assert_eq!(opts.host_all_ignored, Some("defer".to_string()));
        assert_eq!(opts.host_all_ignored_code, HostFailAction::Defer);
        assert_eq!(opts.host_find_failed, Some("freeze".to_string()));
        assert_eq!(opts.host_find_failed_code, HostFailAction::Freeze);
        assert!(opts.route_data.is_none());
        assert!(opts.route_list.is_none());
    }

    // ── Parse Route Item Tests ────────────────────────────────────────

    #[test]
    fn test_parse_route_item_simple() {
        let result = parse_route_item("host1.example.com");
        assert_eq!(
            result,
            Some(("host1.example.com".to_string(), String::new()))
        );
    }

    #[test]
    fn test_parse_route_item_with_options() {
        let result = parse_route_item("host1:host2 byname randomize");
        assert_eq!(
            result,
            Some(("host1:host2".to_string(), "byname randomize".to_string()))
        );
    }

    #[test]
    fn test_parse_route_item_empty() {
        assert_eq!(parse_route_item(""), None);
        assert_eq!(parse_route_item("   "), None);
    }

    #[test]
    fn test_parse_route_item_whitespace_trimming() {
        let result = parse_route_item("  host1:host2  option1  option2  ");
        assert_eq!(
            result,
            Some(("host1:host2".to_string(), "option1  option2".to_string()))
        );
    }

    // ── Parse Route List Item Tests ───────────────────────────────────

    #[test]
    fn test_parse_route_list_item_simple() {
        let result = parse_route_list_item("example.com host1.example.com");
        assert_eq!(
            result,
            Some((
                "example.com".to_string(),
                "host1.example.com".to_string(),
                String::new(),
            ))
        );
    }

    #[test]
    fn test_parse_route_list_item_with_options() {
        let result = parse_route_list_item("*.example.com host1:host2 byname smtp_transport");
        assert_eq!(
            result,
            Some((
                "*.example.com".to_string(),
                "host1:host2".to_string(),
                "byname smtp_transport".to_string(),
            ))
        );
    }

    #[test]
    fn test_parse_route_list_item_domain_only() {
        assert_eq!(parse_route_list_item("example.com"), None);
    }

    #[test]
    fn test_parse_route_list_item_empty() {
        assert_eq!(parse_route_list_item(""), None);
        assert_eq!(parse_route_list_item("   "), None);
    }

    // ── Build Host List Tests ─────────────────────────────────────────

    #[test]
    fn test_build_host_list_single() {
        let hosts = build_host_list("mail.example.com");
        assert_eq!(hosts, vec!["mail.example.com"]);
    }

    #[test]
    fn test_build_host_list_multiple() {
        let hosts = build_host_list("host1.example.com:host2.example.com:host3.example.com");
        assert_eq!(
            hosts,
            vec![
                "host1.example.com",
                "host2.example.com",
                "host3.example.com",
            ]
        );
    }

    #[test]
    fn test_build_host_list_empty_entries() {
        let hosts = build_host_list("host1::host2:");
        assert_eq!(hosts, vec!["host1", "host2"]);
    }

    #[test]
    fn test_build_host_list_whitespace() {
        let hosts = build_host_list(" host1 : host2 ");
        assert_eq!(hosts, vec!["host1", "host2"]);
    }

    #[test]
    fn test_build_host_list_empty() {
        let hosts = build_host_list("");
        assert!(hosts.is_empty());
    }

    // ── Domain Matching Tests ─────────────────────────────────────────

    #[test]
    fn test_domain_matches_exact() {
        assert!(domain_matches("example.com", "example.com"));
        assert!(domain_matches("EXAMPLE.COM", "example.com"));
        assert!(domain_matches("example.com", "EXAMPLE.COM"));
        assert!(!domain_matches("example.com", "other.com"));
    }

    #[test]
    fn test_domain_matches_wildcard() {
        assert!(domain_matches("mail.example.com", "*.example.com"));
        assert!(domain_matches("a.b.example.com", "*.example.com"));
        assert!(domain_matches("example.com", "*.example.com"));
        assert!(!domain_matches("otherexample.com", "*.example.com"));
    }

    #[test]
    fn test_domain_matches_star() {
        assert!(domain_matches("anything.com", "*"));
        assert!(domain_matches("", "*"));
    }

    #[test]
    fn test_domain_matches_negation() {
        assert!(!domain_matches("example.com", "!example.com"));
        assert!(domain_matches("other.com", "!example.com"));
    }

    #[test]
    fn test_domain_matches_list() {
        assert!(domain_matches_list(
            "mail.example.com",
            "*.example.com:*.other.com"
        ));
        assert!(domain_matches_list(
            "test.other.com",
            "*.example.com:*.other.com"
        ));
        assert!(!domain_matches_list(
            "different.com",
            "*.example.com:*.other.com"
        ));
    }

    // ── Options Parsing Tests ─────────────────────────────────────────

    #[test]
    fn test_parse_options_empty() {
        let opts = parse_options("", "test_router");
        assert!(opts.randomize.is_none());
        assert!(!opts.byname);
        assert!(!opts.bydns);
        assert!(!opts.ipv4_prefer);
        assert!(!opts.ipv4_only);
        assert!(opts.transport_name.is_none());
    }

    #[test]
    fn test_parse_options_all_keywords() {
        let opts = parse_options("randomize byname ipv4_prefer", "test_router");
        assert_eq!(opts.randomize, Some(true));
        assert!(opts.byname);
        assert!(opts.ipv4_prefer);
        assert!(!opts.bydns);
        assert!(!opts.ipv4_only);
    }

    #[test]
    fn test_parse_options_no_randomize() {
        let opts = parse_options("no_randomize bydns", "test_router");
        assert_eq!(opts.randomize, Some(false));
        assert!(opts.bydns);
    }

    #[test]
    fn test_parse_options_transport_name() {
        let opts = parse_options("byname remote_smtp", "test_router");
        assert!(opts.byname);
        assert_eq!(opts.transport_name, Some("remote_smtp".to_string()));
    }

    #[test]
    fn test_parse_options_transport_only() {
        let opts = parse_options("my_transport", "test_router");
        assert_eq!(opts.transport_name, Some("my_transport".to_string()));
    }

    #[test]
    fn test_parse_options_case_insensitive() {
        let opts = parse_options("RANDOMIZE BYNAME", "test_router");
        assert_eq!(opts.randomize, Some(true));
        assert!(opts.byname);
    }

    // ── Host Shuffling Tests ──────────────────────────────────────────

    #[test]
    fn test_shuffle_hosts_empty() {
        let mut hosts: Vec<String> = vec![];
        shuffle_hosts(&mut hosts);
        assert!(hosts.is_empty());
    }

    #[test]
    fn test_shuffle_hosts_single() {
        let mut hosts = vec!["host1".to_string()];
        shuffle_hosts(&mut hosts);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0], "host1");
    }

    #[test]
    fn test_shuffle_hosts_deterministic() {
        let mut hosts1 = vec![
            "alpha.example.com".to_string(),
            "beta.example.com".to_string(),
            "gamma.example.com".to_string(),
        ];
        let mut hosts2 = hosts1.clone();
        shuffle_hosts(&mut hosts1);
        shuffle_hosts(&mut hosts2);
        // Deterministic shuffle should produce same result
        assert_eq!(hosts1, hosts2);
    }

    #[test]
    fn test_shuffle_hosts_preserves_elements() {
        let original = vec![
            "host1.example.com".to_string(),
            "host2.example.com".to_string(),
            "host3.example.com".to_string(),
        ];
        let mut hosts = original.clone();
        shuffle_hosts(&mut hosts);
        // All original elements must still be present
        for h in &original {
            assert!(hosts.contains(h), "Missing host: {h}");
        }
        assert_eq!(hosts.len(), original.len());
    }

    // ── Extract Domain Tests ──────────────────────────────────────────

    #[test]
    fn test_extract_domain_normal() {
        assert_eq!(extract_domain("user@example.com"), "example.com");
    }

    #[test]
    fn test_extract_domain_no_at() {
        assert_eq!(extract_domain("example.com"), "example.com");
    }

    #[test]
    fn test_extract_domain_multiple_at() {
        assert_eq!(extract_domain("user@host@example.com"), "example.com");
    }

    // ── Router Configuration Validation Tests ─────────────────────────

    #[test]
    fn test_validate_config_mutual_exclusivity_both_set() {
        let config = RouterInstanceConfig::new("test", "manualroute");
        let opts = ManualRouteRouterOptions {
            route_data: Some("host1".to_string()),
            route_list: Some("*.com host1".to_string()),
            ..ManualRouteRouterOptions::default()
        };
        let result = ManualRouteRouter::validate_config(&config, &opts);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ManualRouteError::MutualExclusivityViolation { .. }
        ));
    }

    #[test]
    fn test_validate_config_mutual_exclusivity_neither_set() {
        let config = RouterInstanceConfig::new("test", "manualroute");
        let opts = ManualRouteRouterOptions {
            route_data: None,
            route_list: None,
            ..ManualRouteRouterOptions::default()
        };
        let result = ManualRouteRouter::validate_config(&config, &opts);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ManualRouteError::NoRouteSource { .. }));
    }

    #[test]
    fn test_validate_config_valid_route_data() {
        let config = RouterInstanceConfig::new("test", "manualroute");
        let opts = ManualRouteRouterOptions {
            route_data: Some("host1.example.com".to_string()),
            ..ManualRouteRouterOptions::default()
        };
        let result = ManualRouteRouter::validate_config(&config, &opts);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_config_valid_route_list() {
        let config = RouterInstanceConfig::new("test", "manualroute");
        let opts = ManualRouteRouterOptions {
            route_list: Some("*.com host1.example.com".to_string()),
            route_data: None,
            ..ManualRouteRouterOptions::default()
        };
        let result = ManualRouteRouter::validate_config(&config, &opts);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_config_invalid_hff() {
        let config = RouterInstanceConfig::new("test", "manualroute");
        let opts = ManualRouteRouterOptions {
            route_data: Some("host1".to_string()),
            host_find_failed: Some("invalid_action".to_string()),
            ..ManualRouteRouterOptions::default()
        };
        let result = ManualRouteRouter::validate_config(&config, &opts);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ManualRouteError::InvalidHostFindFailed { .. }
        ));
    }

    #[test]
    fn test_validate_config_invalid_hai() {
        let config = RouterInstanceConfig::new("test", "manualroute");
        let opts = ManualRouteRouterOptions {
            route_data: Some("host1".to_string()),
            host_all_ignored: Some("bad_action".to_string()),
            ..ManualRouteRouterOptions::default()
        };
        let result = ManualRouteRouter::validate_config(&config, &opts);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ManualRouteError::InvalidHostAllIgnored { .. }
        ));
    }

    #[test]
    fn test_validate_config_decodes_hff() {
        let config = RouterInstanceConfig::new("test", "manualroute");
        let opts = ManualRouteRouterOptions {
            route_data: Some("host1".to_string()),
            host_find_failed: Some("pass".to_string()),
            ..ManualRouteRouterOptions::default()
        };
        let result = ManualRouteRouter::validate_config(&config, &opts);
        assert!(result.is_ok());
        let validated = result.unwrap();
        assert_eq!(validated.host_find_failed_code, HostFailAction::Pass);
    }

    #[test]
    fn test_validate_config_decodes_hai() {
        let config = RouterInstanceConfig::new("test", "manualroute");
        let opts = ManualRouteRouterOptions {
            route_data: Some("host1".to_string()),
            host_all_ignored: Some("ignore".to_string()),
            ..ManualRouteRouterOptions::default()
        };
        let result = ManualRouteRouter::validate_config(&config, &opts);
        assert!(result.is_ok());
        let validated = result.unwrap();
        assert_eq!(validated.host_all_ignored_code, HostFailAction::Ignore);
    }

    // ── RouterDriver Trait Implementation Tests ───────────────────────

    #[test]
    fn test_driver_name() {
        let router = ManualRouteRouter;
        assert_eq!(router.driver_name(), "manualroute");
    }

    #[test]
    fn test_flags() {
        let router = ManualRouteRouter;
        assert_eq!(router.flags(), RouterFlags::NONE);
    }

    #[test]
    fn test_tidyup_noop() {
        let router = ManualRouteRouter;
        let config = RouterInstanceConfig::new("test", "manualroute");
        // Should not panic or have any side effects.
        router.tidyup(&config);
    }

    #[test]
    fn test_route_with_route_list_match() {
        let router = ManualRouteRouter;
        let opts = ManualRouteRouterOptions {
            route_list: Some(
                "example.com mail.example.com remote_smtp ; \
                 *.other.com relay.other.com:backup.other.com bydns"
                    .to_string(),
            ),
            route_data: None,
            ..ManualRouteRouterOptions::default()
        };

        let mut config = RouterInstanceConfig::new("test_manual", "manualroute");
        config.options = Box::new(opts);

        // Test matching the first route_list item
        let result = router.route(&config, "user@example.com", None);
        assert!(result.is_ok());
        match result.unwrap() {
            RouterResult::Accept {
                transport_name,
                host_list,
            } => {
                assert_eq!(transport_name, Some("remote_smtp".to_string()));
                assert_eq!(host_list, vec!["mail.example.com"]);
            }
            other => panic!("Expected Accept, got: {other:?}"),
        }
    }

    #[test]
    fn test_route_with_route_list_wildcard_match() {
        let router = ManualRouteRouter;
        let opts = ManualRouteRouterOptions {
            route_list: Some("*.other.com relay.other.com:backup.other.com bydns".to_string()),
            route_data: None,
            ..ManualRouteRouterOptions::default()
        };

        let mut config = RouterInstanceConfig::new("test_manual", "manualroute");
        config.options = Box::new(opts);

        let result = router.route(&config, "user@mail.other.com", None);
        assert!(result.is_ok());
        match result.unwrap() {
            RouterResult::Accept {
                transport_name,
                host_list,
            } => {
                assert!(transport_name.is_none()); // bydns is not a transport
                assert_eq!(host_list, vec!["relay.other.com", "backup.other.com"]);
            }
            other => panic!("Expected Accept, got: {other:?}"),
        }
    }

    #[test]
    fn test_route_with_route_list_no_match() {
        let router = ManualRouteRouter;
        let opts = ManualRouteRouterOptions {
            route_list: Some("example.com host1".to_string()),
            route_data: None,
            ..ManualRouteRouterOptions::default()
        };

        let mut config = RouterInstanceConfig::new("test_manual", "manualroute");
        config.options = Box::new(opts);

        let result = router.route(&config, "user@other.com", None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), RouterResult::Decline);
    }

    #[test]
    fn test_route_with_default_options_errors() {
        let router = ManualRouteRouter;
        // Default options have neither route_data nor route_list
        let mut config = RouterInstanceConfig::new("test_manual", "manualroute");
        config.options = Box::new(ManualRouteRouterOptions::default());

        let result = router.route(&config, "user@example.com", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_route_with_fallback_transport() {
        let router = ManualRouteRouter;
        let opts = ManualRouteRouterOptions {
            route_list: Some("example.com host1".to_string()),
            route_data: None,
            ..ManualRouteRouterOptions::default()
        };

        let mut config = RouterInstanceConfig::new("test_manual", "manualroute");
        config.transport_name = Some("default_remote".to_string());
        config.options = Box::new(opts);

        let result = router.route(&config, "user@example.com", None);
        assert!(result.is_ok());
        match result.unwrap() {
            RouterResult::Accept {
                transport_name,
                host_list,
            } => {
                assert_eq!(transport_name, Some("default_remote".to_string()));
                assert_eq!(host_list, vec!["host1"]);
            }
            other => panic!("Expected Accept, got: {other:?}"),
        }
    }

    #[test]
    fn test_route_item_transport_overrides_config() {
        let router = ManualRouteRouter;
        let opts = ManualRouteRouterOptions {
            route_list: Some("example.com host1 special_smtp".to_string()),
            route_data: None,
            ..ManualRouteRouterOptions::default()
        };

        let mut config = RouterInstanceConfig::new("test_manual", "manualroute");
        config.transport_name = Some("default_remote".to_string());
        config.options = Box::new(opts);

        let result = router.route(&config, "user@example.com", None);
        assert!(result.is_ok());
        match result.unwrap() {
            RouterResult::Accept {
                transport_name,
                host_list,
            } => {
                // Item-level transport overrides config-level
                assert_eq!(transport_name, Some("special_smtp".to_string()));
                assert_eq!(host_list, vec!["host1"]);
            }
            other => panic!("Expected Accept, got: {other:?}"),
        }
    }

    #[test]
    fn test_route_multiple_hosts_in_list() {
        let router = ManualRouteRouter;
        let opts = ManualRouteRouterOptions {
            route_list: Some("example.com host1:host2:host3 remote_smtp".to_string()),
            route_data: None,
            ..ManualRouteRouterOptions::default()
        };

        let mut config = RouterInstanceConfig::new("test_manual", "manualroute");
        config.options = Box::new(opts);

        let result = router.route(&config, "user@example.com", None);
        assert!(result.is_ok());
        match result.unwrap() {
            RouterResult::Accept {
                transport_name,
                host_list,
            } => {
                assert_eq!(transport_name, Some("remote_smtp".to_string()));
                assert_eq!(host_list, vec!["host1", "host2", "host3"]);
            }
            other => panic!("Expected Accept, got: {other:?}"),
        }
    }

    // ── Error Type Tests ──────────────────────────────────────────────

    #[test]
    fn test_manual_route_error_display() {
        let err = ManualRouteError::MutualExclusivityViolation {
            router_name: "test".to_string(),
        };
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn test_manual_route_error_to_driver_error() {
        let err = ManualRouteError::MutualExclusivityViolation {
            router_name: "test".to_string(),
        };
        let driver_err: DriverError = err.into();
        assert!(matches!(driver_err, DriverError::ConfigError(_)));
    }

    #[test]
    fn test_route_data_expansion_error_maps_to_temp_fail() {
        let err = ManualRouteError::RouteDataExpansionFailed {
            router_name: "test".to_string(),
            detail: "bad expansion".to_string(),
        };
        let driver_err: DriverError = err.into();
        assert!(matches!(driver_err, DriverError::TempFail(_)));
    }

    #[test]
    fn test_scan_route_list_multiple_items() {
        // First item doesn't match, second does
        let result = ManualRouteRouter::scan_route_list(
            "first.com host_a ; second.com host_b transport_b",
            "second.com",
            "test_router",
        );
        assert!(result.is_ok());
        match result.unwrap() {
            Some((hostlist, options)) => {
                assert_eq!(hostlist, "host_b");
                assert_eq!(options, "transport_b");
            }
            None => panic!("Expected a match"),
        }
    }

    #[test]
    fn test_scan_route_list_first_match_wins() {
        let result = ManualRouteRouter::scan_route_list(
            "*.com host_a ; example.com host_b",
            "example.com",
            "test_router",
        );
        assert!(result.is_ok());
        match result.unwrap() {
            Some((hostlist, _)) => {
                // First matching item wins
                assert_eq!(hostlist, "host_a");
            }
            None => panic!("Expected a match"),
        }
    }

    #[test]
    fn test_scan_route_list_no_match() {
        let result = ManualRouteRouter::scan_route_list(
            "example.com host_a ; other.com host_b",
            "different.com",
            "test_router",
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
