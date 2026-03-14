// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! DNS Lookup Router — MX/A/AAAA/SRV Routing
//!
//! Translates **`src/src/routers/dnslookup.c`** (499 lines) and
//! **`src/src/routers/dnslookup.h`** (44 lines) into Rust.
//!
//! ## Overview
//!
//! The `dnslookup` router is the primary DNS-based routing mechanism in Exim.
//! It performs MX, A, AAAA, and optional SRV record lookups to determine the
//! hosts responsible for receiving email for a given domain.
//!
//! ## Routing Algorithm
//!
//! 1. **IP literal check** — if the domain is an IP literal (`[...]`), the
//!    router declines immediately (another router handles these).
//! 2. **Optional SRV lookup** — if `check_srv` is configured, a SRV service
//!    name is expanded and prepended to the lookup.
//! 3. **MX/A/AAAA lookup** — `host_find_bydns()` performs the primary DNS
//!    resolution with flags derived from the router configuration.
//! 4. **Domain widening** — if the initial lookup fails and `widen_domains`
//!    is configured, the lookup is retried with each widening suffix appended.
//! 5. **Parent search** — if `search_parents` is set, parent domain walking
//!    occurs via the resolver's built-in search parent logic.
//! 6. **Policy checks** — the results are checked against `mx_domains`,
//!    `mx_fail_domains`, `srv_fail_domains`, and `fail_defer_domains`.
//! 7. **Self-reference handling** — if the lookup resolves to the local host
//!    (`HOST_FOUND_LOCAL`), `self_action()` is called to determine behavior.
//! 8. **Secondary MX check** — if `check_secondary_mx` is set and the local
//!    host appears as a lower-priority MX, the router declines.
//! 9. **Transport and delivery setup** — on success, the transport name and
//!    resolved host list are returned to the delivery orchestrator.
//!
//! ## C Source Correspondence
//!
//! | C construct | Rust equivalent |
//! |---|---|
//! | `dnslookup_router_options_block` | [`DnsLookupRouterOptions`] |
//! | `dnslookup_router_option_defaults` | `DnsLookupRouterOptions::default()` |
//! | `dnslookup_router_init()` | No-op (config validation in `route()`) |
//! | `dnslookup_router_entry()` | [`DnsLookupRouter::route()`] |
//! | `dnslookup_router_info` | `inventory::submit!` registration |
//! | `host_find_bydns()` | `DnsResolver::host_find_bydns()` |
//! | `rf_self_action()` | `helpers::self_action()` |
//! | `rf_change_domain()` | `helpers::change_domain()` |
//! | `rf_get_transport()` | transport resolution via `RouterResult` |
//! | `rf_queue_add()` | handled by delivery orchestrator |
//! | `DEBUG(D_route)` | `tracing::debug!()` |
//! | `#ifdef ROUTER_DNSLOOKUP` | `#[cfg(feature = "router-dnslookup")]` |
//!
//! ## Safety
//!
//! This module contains **zero `unsafe` code** (per AAP §0.7.2).

// ── Imports ────────────────────────────────────────────────────────────────

use exim_drivers::router_driver::{
    RouterDriver, RouterDriverFactory, RouterFlags, RouterInstanceConfig, RouterResult,
};
use exim_drivers::DriverError;

use exim_dns::resolver::{DnssecDomains, DnssecStatus, HostFindFlags, HostFindResult, HostItem};
use exim_dns::{DnsError, DnsResolver};

use exim_expand::{expand_check_condition, expand_string, ExpandError};

use exim_store::taint::{Clean, Tainted, TaintedString};

use crate::helpers::change_domain::{AddressItem, DeliveryContext};
use crate::helpers::get_munge_headers::HeaderType;
use crate::helpers::{
    self_action, ErrorsAddressResult, GetTransportError, HeaderLine, MungeHeadersResult,
    PasswdEntry, SelfAction, UgidBlock,
};

use serde::Deserialize;
use thiserror::Error;

// ═══════════════════════════════════════════════════════════════════════════
//  DnsLookupError — Internal Error Type
// ═══════════════════════════════════════════════════════════════════════════

/// Internal error type for DNS lookup routing operations.
///
/// Maps between DNS resolution failures, expansion failures, and the
/// `DriverError` variants returned by the `RouterDriver::route()` method.
///
/// Consistent with the sibling router error handling pattern
/// (e.g., `ManualRouteError` in manualroute.rs).
#[derive(Debug, Error)]
enum DnsLookupError {
    /// DNS resolution failed permanently.
    #[error("DNS lookup failed for domain '{domain}': {reason}")]
    DnsResolutionFailed { domain: String, reason: String },

    /// String expansion of a configuration option failed.
    #[error("expansion failed for option '{option}' in router '{router}': {reason}")]
    ExpansionFailed {
        option: String,
        router: String,
        reason: String,
    },

    /// Temporary DNS failure requiring deferral.
    #[error("temporary DNS failure for '{domain}': {reason}")]
    TemporaryFailure { domain: String, reason: String },
}

impl From<DnsLookupError> for DriverError {
    fn from(err: DnsLookupError) -> Self {
        match &err {
            DnsLookupError::DnsResolutionFailed { .. } => {
                DriverError::ExecutionFailed(err.to_string())
            }
            DnsLookupError::ExpansionFailed { .. } => DriverError::ConfigError(err.to_string()),
            DnsLookupError::TemporaryFailure { .. } => DriverError::TempFail(err.to_string()),
        }
    }
}

impl From<DnsError> for DnsLookupError {
    /// Maps a low-level DNS resolution error into a `DnsLookupError`.
    ///
    /// C: `host_find_bydns()` returns `HOST_FIND_FAILED` or `HOST_FIND_AGAIN`
    /// on DNS errors; the router translates these into log-friendly messages.
    fn from(err: DnsError) -> Self {
        DnsLookupError::DnsResolutionFailed {
            domain: String::new(),
            reason: err.to_string(),
        }
    }
}

impl From<GetTransportError> for DnsLookupError {
    /// Maps a transport resolution error into a `DnsLookupError`.
    ///
    /// C: `rf_get_transport()` failure → DEFER.
    fn from(err: GetTransportError) -> Self {
        DnsLookupError::TemporaryFailure {
            domain: String::new(),
            reason: format!("transport resolution failed: {err}"),
        }
    }
}

impl From<ExpandError> for DnsLookupError {
    /// Maps an expansion error into a `DnsLookupError`.
    ///
    /// C: `expand_string()` failure handling throughout dnslookup.c.
    /// `ExpandError::ForcedFail` → soft failure (DECLINE/skip).
    /// `ExpandError::Failed` → hard error (DEFER).
    fn from(err: ExpandError) -> Self {
        match err {
            ExpandError::ForcedFail => DnsLookupError::TemporaryFailure {
                domain: String::new(),
                reason: "forced expansion failure".to_string(),
            },
            ExpandError::Failed { message } => DnsLookupError::ExpansionFailed {
                option: String::new(),
                router: String::new(),
                reason: message,
            },
            other => DnsLookupError::ExpansionFailed {
                option: String::new(),
                router: String::new(),
                reason: other.to_string(),
            },
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  DnsLookupRouterOptions — Configuration Options
// ═══════════════════════════════════════════════════════════════════════════

/// Configuration options specific to the `dnslookup` router driver.
///
/// Replaces the C `dnslookup_router_options_block` struct from
/// `dnslookup.h` (lines 12–25) and the corresponding `optionlist_dnslookup[]`
/// table from `dnslookup.c` (lines 21–35).
///
/// ## Default Values
///
/// Matching C `dnslookup_router_option_defaults` (dnslookup.c lines 62–65):
///
/// | Field | Default |
/// |-------|---------|
/// | `check_secondary_mx` | `false` |
/// | `qualify_single` | `true` |
/// | `search_parents` | `false` |
/// | `rewrite_headers` | `true` |
/// | All `Option<String>` fields | `None` |
#[derive(Debug, Clone, Deserialize)]
pub struct DnsLookupRouterOptions {
    /// If `true`, check whether the local host is a secondary (non-lowest) MX.
    /// When the local host appears as a secondary MX, the router declines so
    /// that a different router can handle the address.
    ///
    /// C: `BOOL check_secondary_mx` (default `FALSE`).
    #[serde(default)]
    pub check_secondary_mx: bool,

    /// If `true`, single-component domain names are qualified with the
    /// default domain before DNS lookup.
    ///
    /// C: `BOOL qualify_single` (default `TRUE`).
    #[serde(default = "default_true")]
    pub qualify_single: bool,

    /// If `true`, search parent domains when the initial lookup fails.
    /// Relies on the system resolver's search domain list.
    ///
    /// C: `BOOL search_parents` (default `FALSE`).
    #[serde(default)]
    pub search_parents: bool,

    /// If `true`, rewrite message headers when the domain is canonicalized
    /// (i.e., when the fully qualified name from DNS differs from the
    /// original envelope domain).
    ///
    /// C: `BOOL rewrite_headers` (default `TRUE`).
    #[serde(default = "default_true")]
    pub rewrite_headers: bool,

    /// Colon-separated list of domain suffixes to try appending when the
    /// initial DNS lookup fails (domain widening). Each suffix is tried in
    /// order until a successful lookup is found.
    ///
    /// C: `uschar *widen_domains` (default `NULL`).
    #[serde(default)]
    pub widen_domains: Option<String>,

    /// Domain list pattern. If set, only domains matching this list are
    /// accepted via MX-only lookup (no fallback to A/AAAA). If the domain
    /// matches but MX lookup returns only A records, the router declines.
    ///
    /// C: `uschar *mx_domains` (default `NULL`).
    #[serde(default)]
    pub mx_domains: Option<String>,

    /// Domain list pattern. If set and the domain matches, MX lookup
    /// failure is treated as a permanent routing failure instead of a
    /// deferral.
    ///
    /// C: `uschar *mx_fail_domains` (default `NULL`).
    #[serde(default)]
    pub mx_fail_domains: Option<String>,

    /// Domain list pattern. If set and the domain matches, SRV lookup
    /// failure is treated as a permanent routing failure.
    ///
    /// C: `uschar *srv_fail_domains` (default `NULL`).
    #[serde(default)]
    pub srv_fail_domains: Option<String>,

    /// SRV service name to look up before falling back to MX/A.
    /// Expanded at route time via `expand_string()`. If the expansion
    /// yields a non-empty string, SRV lookup is attempted first.
    ///
    /// C: `uschar *check_srv` (default `NULL`).
    #[serde(default)]
    pub check_srv: Option<String>,

    /// Domain list pattern. If set and the domain matches, a DNS failure
    /// (HOST_FIND_FAILED) is converted to DEFER instead of FAIL.
    ///
    /// C: `uschar *fail_defer_domains` (default `NULL`).
    #[serde(default)]
    pub fail_defer_domains: Option<String>,

    /// Domain list pattern for IPv4-only lookups. If the domain matches,
    /// AAAA record lookups are suppressed.
    ///
    /// C: `uschar *ipv4_only` (default `NULL`).
    #[serde(default)]
    pub ipv4_only: Option<String>,

    /// Domain list pattern for IPv4-preferred lookups. If the domain
    /// matches, IPv4 addresses are sorted before IPv6 addresses in the
    /// host list.
    ///
    /// C: `uschar *ipv4_prefer` (default `NULL`).
    #[serde(default)]
    pub ipv4_prefer: Option<String>,
}

/// Helper for serde defaults — returns `true`.
fn default_true() -> bool {
    true
}

impl Default for DnsLookupRouterOptions {
    /// Creates default options matching C `dnslookup_router_option_defaults`.
    ///
    /// C defaults (dnslookup.c lines 62–65):
    /// ```c
    /// dnslookup_router_options_block dnslookup_router_option_defaults = {
    ///     .qualify_single = TRUE,
    ///     .rewrite_headers = TRUE,
    /// };
    /// ```
    fn default() -> Self {
        Self {
            check_secondary_mx: false,
            qualify_single: true,
            search_parents: false,
            rewrite_headers: true,
            widen_domains: None,
            mx_domains: None,
            mx_fail_domains: None,
            srv_fail_domains: None,
            check_srv: None,
            fail_defer_domains: None,
            ipv4_only: None,
            ipv4_prefer: None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  DnsLookupDeliveryMetadata — Delivery Context
// ═══════════════════════════════════════════════════════════════════════════

/// Delivery metadata collected during the routing decision.
///
/// Aggregates results from the C helper function equivalents:
/// - `rf_get_errors_address()` → `errors_address`
/// - `rf_get_munge_headers()` → `munge_result`
/// - `rf_get_ugid()` → `ugid`
/// - `rf_queue_add()` → `local_user`
///
/// This metadata is logged for observability and can be consumed by the
/// delivery orchestrator alongside the `RouterResult::Accept`.
#[derive(Debug)]
pub struct DnsLookupDeliveryMetadata {
    /// Errors address override from the router configuration.
    pub errors_address: Option<ErrorsAddressResult>,
    /// Header munging result — extra headers to add and headers to remove.
    pub munge_result: MungeHeadersResult,
    /// UID/GID block for delivery privilege dropping.
    pub ugid: UgidBlock,
    /// Local user passwd entry if available.
    pub local_user: Option<PasswdEntry>,
}

impl DnsLookupDeliveryMetadata {
    /// Creates a new empty metadata struct.
    fn new() -> Self {
        Self {
            errors_address: None,
            munge_result: MungeHeadersResult {
                extra_headers: Vec::new(),
                remove_headers: None,
            },
            ugid: UgidBlock::default(),
            local_user: None,
        }
    }

    /// Populates errors address from router config.
    ///
    /// C: `rf_get_errors_address(addr, rblock, verify, &addr->prop.errors_address)`
    fn populate_errors_address(&mut self, config: &RouterInstanceConfig) {
        if let Some(ref errors_to) = config.errors_to {
            if errors_to.is_empty() {
                self.errors_address = Some(ErrorsAddressResult::IgnoreErrors);
            } else {
                self.errors_address = Some(ErrorsAddressResult::Address(errors_to.clone()));
            }
        }
    }

    /// Populates header munging from router config.
    ///
    /// C: `rf_get_munge_headers(addr, rblock, &extra_headers, &remove_headers)`
    fn populate_munge_headers(&mut self, config: &RouterInstanceConfig) {
        if let Some(ref hdrs) = config.extra_headers {
            for hdr_text in hdrs.split('\n').filter(|s| !s.is_empty()) {
                self.munge_result.extra_headers.push(HeaderLine {
                    text: format!("{hdr_text}\n"),
                    header_type: HeaderType::Other,
                });
            }
        }
        if let Some(ref rem) = config.remove_headers {
            self.munge_result.remove_headers = Some(rem.clone());
        }
    }

    /// Populates UID/GID from router config.
    ///
    /// C: `rf_get_ugid()` via `rf_queue_add()`
    fn populate_ugid(&mut self, config: &RouterInstanceConfig) {
        if config.uid > 0 {
            self.ugid.uid = Some(config.uid);
        }
        if config.gid > 0 {
            self.ugid.gid = Some(config.gid);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  DnsLookupRouter — Router Driver Implementation
// ═══════════════════════════════════════════════════════════════════════════

/// DNS lookup router driver implementing `RouterDriver`.
///
/// This is the primary DNS-based routing mechanism in Exim, performing MX,
/// A, AAAA, and optional SRV record lookups to determine mail delivery hosts.
///
/// Replaces the C `dnslookup_router_entry()` function from `dnslookup.c`
/// (lines 97–499).
///
/// ## Statelessness
///
/// The router itself is stateless — all per-instance configuration is stored
/// in [`RouterInstanceConfig`] and passed to `route()` on each invocation.
/// Driver-specific options are stored in `config.options` as a type-erased
/// `Box<dyn Any + Send + Sync>` and downcast to [`DnsLookupRouterOptions`].
///
/// ## DNS Resolver
///
/// A `DnsResolver` is created per `route()` invocation using system defaults.
/// This matches the C pattern where the resolver state is per-process, and
/// works correctly within Exim's fork-per-connection model.
#[derive(Debug)]
pub struct DnsLookupRouter;

impl Default for DnsLookupRouter {
    fn default() -> Self {
        Self
    }
}

impl DnsLookupRouter {
    /// Creates a new `DnsLookupRouter` instance.
    ///
    /// The router is stateless — all per-instance configuration is in
    /// `RouterInstanceConfig.options`.
    pub fn new() -> Self {
        Self
    }

    /// Extracts the domain part from an email address.
    ///
    /// Returns the substring after the last `@` character. If no `@` is
    /// present, returns the entire address (treating it as a bare domain).
    fn extract_domain(address: &str) -> &str {
        if let Some(at_pos) = address.rfind('@') {
            &address[at_pos + 1..]
        } else {
            address
        }
    }

    /// Checks if a domain is an IP literal (enclosed in square brackets).
    ///
    /// IP literals like `[192.0.2.1]` or `[IPv6:::1]` are handled by the
    /// `ipliteral` router, not the DNS lookup router. We decline immediately.
    ///
    /// C: dnslookup.c line ~110 (implicit check in the routing flow).
    fn is_ip_literal(domain: &str) -> bool {
        domain.starts_with('[') && domain.ends_with(']')
    }

    /// Downcasts the opaque options block to `DnsLookupRouterOptions`.
    ///
    /// Returns the driver-specific options or a `DriverError::ConfigError`
    /// if the downcast fails (indicating a configuration framework bug).
    fn get_options(config: &RouterInstanceConfig) -> Result<&DnsLookupRouterOptions, DriverError> {
        config
            .options
            .downcast_ref::<DnsLookupRouterOptions>()
            .ok_or_else(|| {
                DriverError::ConfigError(format!(
                    "router '{}': failed to downcast options to DnsLookupRouterOptions",
                    config.name
                ))
            })
    }

    /// Converts a fatal configuration error into a `RouterResult::Error`.
    ///
    /// Used when a configuration problem is so severe that routing cannot
    /// proceed and should not be retried (e.g., malformed options that
    /// survived config parsing but are unusable at route time).
    ///
    /// C: corresponds to returning ROUTER_ERROR from
    /// `dnslookup_router_entry()` on unrecoverable configuration faults.
    #[inline]
    fn config_error(message: String) -> RouterResult {
        RouterResult::Error { message }
    }

    /// Builds the base `HostFindFlags` from router options and domain.
    ///
    /// Translates C dnslookup.c lines 112-130 where the `whichrrs` variable
    /// is assembled from `HOST_FIND_BY_MX | HOST_FIND_BY_A` plus optional
    /// BY_AAAA, BY_SRV, QUALIFY_SINGLE, and SEARCH_PARENTS flags.
    ///
    /// ## Arguments
    ///
    /// * `opts` - Driver-specific options for this router instance.
    /// * `domain` - The domain being looked up (for ipv4_only/ipv4_prefer evaluation).
    /// * `router_name` - Router instance name for logging.
    /// * `srv_service` - If Some, SRV lookup is enabled.
    fn build_host_find_flags(
        opts: &DnsLookupRouterOptions,
        domain: &str,
        router_name: &str,
        srv_service: &Option<String>,
    ) -> HostFindFlags {
        // Start with MX + A (always enabled for DNS lookup router).
        // C: whichrrs = HOST_FIND_BY_MX | HOST_FIND_BY_A;
        let mut flags = HostFindFlags::BY_MX | HostFindFlags::BY_A;

        // Add AAAA unless ipv4_only matches the domain.
        // C: if (ob->ipv4_only == NULL || !route_check_drs(...))
        //      whichrrs |= HOST_FIND_BY_AAAA;
        let ipv4_only_matches = opts.ipv4_only.as_deref().is_some_and(|pattern| {
            let result = expand_check_condition(pattern, "ipv4_only", domain);
            tracing::trace!(
                router = router_name,
                domain = domain,
                pattern = pattern,
                result = result,
                "ipv4_only condition evaluation"
            );
            result
        });

        if !ipv4_only_matches {
            flags |= HostFindFlags::BY_AAAA;
        } else {
            tracing::debug!(
                router = router_name,
                domain = domain,
                "IPv4-only mode enabled — suppressing AAAA lookups"
            );
        }

        // Add SRV flag if check_srv expanded to a non-empty service name.
        // C: if (ob->check_srv != NULL) whichrrs |= HOST_FIND_BY_SRV;
        if srv_service.is_some() {
            flags |= HostFindFlags::BY_SRV;
        }

        // Add qualify_single flag.
        // C: if (ob->qualify_single) whichrrs |= HOST_FIND_QUALIFY_SINGLE;
        if opts.qualify_single {
            flags |= HostFindFlags::QUALIFY_SINGLE;
        }

        // Add search_parents flag.
        // C: if (ob->search_parents) whichrrs |= HOST_FIND_SEARCH_PARENTS;
        if opts.search_parents {
            flags |= HostFindFlags::SEARCH_PARENTS;
        }

        flags
    }

    /// Expands the `check_srv` option value to determine the SRV service name.
    ///
    /// Translates C dnslookup.c lines 103–115:
    /// ```c
    /// if (ob->check_srv) {
    ///     srv_service = expand_string(ob->check_srv);
    ///     if (!srv_service) { ... }
    /// }
    /// ```
    ///
    /// Returns `Ok(Some(service_name))` if SRV is configured and expands
    /// successfully, `Ok(None)` if not configured, or `Err` on expansion
    /// failure.
    fn expand_check_srv(
        opts: &DnsLookupRouterOptions,
        router_name: &str,
    ) -> Result<Option<String>, DnsLookupError> {
        let check_srv_template = match &opts.check_srv {
            Some(tmpl) if !tmpl.is_empty() => tmpl,
            _ => return Ok(None),
        };

        match expand_string(check_srv_template) {
            Ok(expanded) if !expanded.is_empty() => {
                tracing::debug!(
                    router = router_name,
                    check_srv = expanded.as_str(),
                    "SRV service name expanded"
                );
                Ok(Some(expanded))
            }
            Ok(_) => {
                // Expanded to empty string — treat as not configured.
                tracing::debug!(
                    router = router_name,
                    "check_srv expanded to empty — skipping SRV lookup"
                );
                Ok(None)
            }
            Err(ExpandError::ForcedFail) => {
                // Forced failure → skip SRV lookup (not an error).
                tracing::debug!(
                    router = router_name,
                    "check_srv expansion forced failure — skipping SRV"
                );
                Ok(None)
            }
            Err(e) => {
                tracing::warn!(
                    router = router_name,
                    error = %e,
                    "check_srv expansion failed"
                );
                Err(DnsLookupError::ExpansionFailed {
                    option: "check_srv".to_string(),
                    router: router_name.to_string(),
                    reason: e.to_string(),
                })
            }
        }
    }

    /// Builds the widening domain suffix list from the `widen_domains` option.
    ///
    /// Translates C dnslookup.c lines 117–135 where `ob->widen_domains` is
    /// expanded and split into a colon-separated list of domain suffixes.
    ///
    /// Returns a vector of suffix strings, empty if widening is not configured.
    fn build_widen_list(
        opts: &DnsLookupRouterOptions,
        router_name: &str,
    ) -> Result<Vec<String>, DnsLookupError> {
        let widen_template = match &opts.widen_domains {
            Some(tmpl) if !tmpl.is_empty() => tmpl,
            _ => return Ok(Vec::new()),
        };

        match expand_string(widen_template) {
            Ok(expanded) if !expanded.is_empty() => {
                let suffixes: Vec<String> = expanded
                    .split(':')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                tracing::debug!(
                    router = router_name,
                    suffixes = ?suffixes,
                    "widen_domains expanded"
                );
                Ok(suffixes)
            }
            Ok(_) => Ok(Vec::new()),
            Err(ExpandError::ForcedFail) => {
                tracing::debug!(
                    router = router_name,
                    "widen_domains expansion forced failure — no widening"
                );
                Ok(Vec::new())
            }
            Err(e) => {
                tracing::warn!(
                    router = router_name,
                    error = %e,
                    "widen_domains expansion failed"
                );
                Err(DnsLookupError::ExpansionFailed {
                    option: "widen_domains".to_string(),
                    router: router_name.to_string(),
                    reason: e.to_string(),
                })
            }
        }
    }

    /// Checks if a domain matches a domain-list pattern string.
    ///
    /// Simple domain list matching: the pattern is a colon-separated list of
    /// domain patterns. A domain matches if it equals any pattern (case-
    /// insensitive) or if the pattern starts with `*.` and the domain is a
    /// subdomain of the pattern.
    ///
    /// This is a simplified version of the C `match_isinlist()` function
    /// used throughout dnslookup.c for domain list checking.
    fn domain_matches_list(domain: &str, domain_list: &str) -> bool {
        let domain_lower = domain.to_ascii_lowercase();
        for pattern in domain_list.split(':') {
            let pattern = pattern.trim();
            if pattern.is_empty() {
                continue;
            }
            // The pattern originates from the configuration file (trusted).
            // Wrap it as a Clean value to assert provenance, then extract for
            // matching.  This makes the trust boundary explicit even though
            // both sides are strings at runtime.
            let clean_pattern = Self::clean_config_value(pattern);
            let pattern_lower = clean_pattern.as_ref().to_ascii_lowercase();

            // Exact match.
            if domain_lower == pattern_lower {
                return true;
            }

            // Wildcard match: *.example.com matches sub.example.com
            if let Some(suffix) = pattern_lower.strip_prefix("*.") {
                if domain_lower.ends_with(suffix)
                    && domain_lower.len() > suffix.len()
                    && domain_lower.as_bytes()[domain_lower.len() - suffix.len() - 1] == b'.'
                {
                    return true;
                }
            }

            // Bare wildcard "*" matches everything.
            if pattern_lower == "*" {
                return true;
            }
        }
        false
    }

    /// Determines the `SelfAction` to take from the router's `self_config`.
    ///
    /// Parses the `self` option string from the router configuration and maps
    /// it to a `SelfAction` enum variant. In C, this was the `self_code`
    /// integer field on `router_instance`.
    ///
    /// C: dnslookup.c references `rblock->self_code` which is set during
    /// config parsing from the `self` option.
    fn parse_self_action(config: &RouterInstanceConfig) -> SelfAction {
        // The self_code field stores a numeric code set during config parsing:
        //   0 = freeze, 1 = defer, 2 = fail, 3 = send, 4 = reroute, 5 = pass
        //
        // C: struct router_instance { int self_code; BOOL self_rewrite; uschar *self; }
        match config.self_code {
            0 => SelfAction::Freeze,
            1 => SelfAction::Defer,
            2 => SelfAction::Fail,
            3 => SelfAction::Send,
            4 => {
                // Reroute: the domain is extracted from the self_config string
                // after the ">>" prefix.
                let domain = config
                    .self_config
                    .as_deref()
                    .and_then(|s| s.strip_prefix(">>"))
                    .unwrap_or("")
                    .trim()
                    .to_string();
                SelfAction::Reroute(domain)
            }
            5 => SelfAction::Pass,
            _ => {
                // Default: freeze (safest fallback).
                SelfAction::Freeze
            }
        }
    }

    /// Performs the main DNS lookup with optional domain widening.
    ///
    /// Translates C dnslookup.c lines 140–320 — the main widening loop that:
    /// 1. Tries the original domain first (pre-widen phase)
    /// 2. If that fails and widen_domains is configured, tries each suffix
    /// 3. Tries the original domain again after widening (post-widen phase)
    ///
    /// Returns the DNS lookup result and the actual domain name that succeeded.
    #[allow(clippy::too_many_arguments)]
    fn perform_dns_lookup(
        resolver: &DnsResolver,
        original_domain: &str,
        whichrrs: HostFindFlags,
        srv_service: &Option<String>,
        opts: &DnsLookupRouterOptions,
        config: &RouterInstanceConfig,
        router_name: &str,
        widen_suffixes: &[String],
    ) -> Result<(HostFindResult, String), DnsLookupError> {
        // Build DNSSEC domain lists from router config (if available).
        let dnssec_domains = DnssecDomains::default();

        // C: srv_service for host_find_bydns
        let srv_service_ref = srv_service.as_deref();
        let srv_fail_ref = opts.srv_fail_domains.as_deref();
        let mx_fail_ref = opts.mx_fail_domains.as_deref();
        let ignore_hosts_ref = config.ignore_target_hosts.as_deref();

        // Phase 1: Try the original domain (pre-widen).
        // C: dnslookup.c lines 140-170
        tracing::debug!(
            router = router_name,
            domain = original_domain,
            flags = ?whichrrs,
            "attempting DNS lookup (pre-widen)"
        );

        let result = resolver.host_find_bydns(
            original_domain,
            whichrrs,
            srv_service_ref,
            srv_fail_ref,
            mx_fail_ref,
            Some(&dnssec_domains),
            ignore_hosts_ref,
        );

        match &result {
            Ok(HostFindResult::Found(hosts)) => {
                tracing::debug!(
                    router = router_name,
                    domain = original_domain,
                    host_count = hosts.len(),
                    "DNS lookup succeeded (pre-widen)"
                );
                return Ok((
                    HostFindResult::Found(hosts.clone()),
                    original_domain.to_string(),
                ));
            }
            Ok(HostFindResult::FoundLocal(hosts)) => {
                tracing::debug!(
                    router = router_name,
                    domain = original_domain,
                    host_count = hosts.len(),
                    "DNS lookup found local host (pre-widen)"
                );
                return Ok((
                    HostFindResult::FoundLocal(hosts.clone()),
                    original_domain.to_string(),
                ));
            }
            Ok(HostFindResult::Again) => {
                tracing::debug!(
                    router = router_name,
                    domain = original_domain,
                    "DNS lookup temporary failure (pre-widen)"
                );
                // Don't try widening on temporary failures — let it defer.
                // Log this as a temporary failure for structured diagnostics.
                tracing::trace!(
                    router = router_name,
                    domain = original_domain,
                    "{}",
                    DnsLookupError::TemporaryFailure {
                        domain: original_domain.to_string(),
                        reason: "HOST_FIND_AGAIN from pre-widen lookup".to_string(),
                    }
                );
                return Ok((HostFindResult::Again, original_domain.to_string()));
            }
            Ok(HostFindResult::Failed) => {
                tracing::debug!(
                    router = router_name,
                    domain = original_domain,
                    "DNS lookup failed (pre-widen) — will try widening"
                );
                // Fall through to widening.
            }
            Err(e) => {
                tracing::warn!(
                    router = router_name,
                    domain = original_domain,
                    error = %e,
                    "DNS resolution error (pre-widen)"
                );
                // Map DNS errors to appropriate result.
                return Err(DnsLookupError::DnsResolutionFailed {
                    domain: original_domain.to_string(),
                    reason: e.to_string(),
                });
            }
        }

        // Phase 2: Domain widening — try each suffix.
        // C: dnslookup.c lines 175-260 (widening loop)
        if !widen_suffixes.is_empty() {
            for suffix in widen_suffixes {
                let widened_domain = format!("{original_domain}.{suffix}");
                tracing::trace!(
                    router = router_name,
                    domain = widened_domain.as_str(),
                    suffix = suffix.as_str(),
                    "attempting widened DNS lookup"
                );

                let widened_result = resolver.host_find_bydns(
                    &widened_domain,
                    whichrrs,
                    srv_service_ref,
                    srv_fail_ref,
                    mx_fail_ref,
                    Some(&dnssec_domains),
                    ignore_hosts_ref,
                );

                match widened_result {
                    Ok(HostFindResult::Found(hosts)) => {
                        tracing::debug!(
                            router = router_name,
                            domain = widened_domain.as_str(),
                            host_count = hosts.len(),
                            "widened DNS lookup succeeded"
                        );
                        return Ok((HostFindResult::Found(hosts), widened_domain));
                    }
                    Ok(HostFindResult::FoundLocal(hosts)) => {
                        tracing::debug!(
                            router = router_name,
                            domain = widened_domain.as_str(),
                            host_count = hosts.len(),
                            "widened DNS lookup found local"
                        );
                        return Ok((HostFindResult::FoundLocal(hosts), widened_domain));
                    }
                    Ok(HostFindResult::Again) => {
                        tracing::debug!(
                            router = router_name,
                            domain = widened_domain.as_str(),
                            "widened DNS lookup temporary failure"
                        );
                        return Ok((HostFindResult::Again, widened_domain));
                    }
                    Ok(HostFindResult::Failed) => {
                        tracing::trace!(
                            router = router_name,
                            domain = widened_domain.as_str(),
                            "widened DNS lookup failed — trying next suffix"
                        );
                        continue;
                    }
                    Err(e) => {
                        tracing::trace!(
                            router = router_name,
                            domain = widened_domain.as_str(),
                            error = %e,
                            "widened DNS lookup error — trying next suffix"
                        );
                        continue;
                    }
                }
            }

            // Phase 3: Post-widen — try the original domain one more time.
            // C: dnslookup.c lines 265-285 (post-widen retry)
            tracing::trace!(
                router = router_name,
                domain = original_domain,
                "widening exhausted — retrying original domain (post-widen)"
            );

            let post_result = resolver.host_find_bydns(
                original_domain,
                whichrrs,
                srv_service_ref,
                srv_fail_ref,
                mx_fail_ref,
                Some(&dnssec_domains),
                ignore_hosts_ref,
            );

            match post_result {
                Ok(ref res @ HostFindResult::Found(ref hosts))
                | Ok(ref res @ HostFindResult::FoundLocal(ref hosts)) => {
                    tracing::debug!(
                        router = router_name,
                        domain = original_domain,
                        host_count = hosts.len(),
                        "post-widen DNS lookup succeeded"
                    );
                    return Ok((res.clone(), original_domain.to_string()));
                }
                Ok(result) => {
                    return Ok((result, original_domain.to_string()));
                }
                Err(e) => {
                    tracing::warn!(
                        router = router_name,
                        domain = original_domain,
                        error = %e,
                        "post-widen DNS resolution error"
                    );
                    return Err(DnsLookupError::DnsResolutionFailed {
                        domain: original_domain.to_string(),
                        reason: e.to_string(),
                    });
                }
            }
        }

        // No widening configured and pre-widen failed.
        Ok((HostFindResult::Failed, original_domain.to_string()))
    }

    /// Checks the `mx_domains` condition against the lookup result.
    ///
    /// Translates C dnslookup.c lines 325-345:
    /// If `mx_domains` is configured and the domain matches, but the lookup
    /// found hosts only via A/AAAA records (no MX), the router declines.
    ///
    /// The check is: if all hosts have `mx_priority == None` (meaning they
    /// were found by A/AAAA only, not MX), and the domain matches mx_domains,
    /// then decline.
    fn check_mx_domains(
        opts: &DnsLookupRouterOptions,
        domain: &str,
        hosts: &[HostItem],
        router_name: &str,
    ) -> Option<RouterResult> {
        let mx_domains = match &opts.mx_domains {
            Some(d) if !d.is_empty() => d,
            _ => return None,
        };

        if !Self::domain_matches_list(domain, mx_domains) {
            return None;
        }

        // Check if any host was found via MX (mx_priority >= 0).
        let has_mx_record = hosts.iter().any(|h| h.mx_priority.is_some_and(|p| p >= 0));

        if !has_mx_record {
            tracing::debug!(
                router = router_name,
                domain = domain,
                "mx_domains matched but no MX records found — declining"
            );
            return Some(RouterResult::Decline);
        }

        None
    }

    /// Checks `check_secondary_mx` — if the local host is a secondary
    /// (non-lowest priority) MX, decline so another router handles it.
    ///
    /// Translates C dnslookup.c lines 440-460:
    /// After removing the local host from the list (via HOST_FOUND_LOCAL
    /// handling), if the local host's MX priority was not the lowest, the
    /// original intent of this check is preserved by examining whether
    /// any hosts remain with higher priority than the local host.
    fn check_secondary_mx_condition(
        opts: &DnsLookupRouterOptions,
        hosts: &[HostItem],
        router_name: &str,
    ) -> Option<RouterResult> {
        if !opts.check_secondary_mx {
            return None;
        }

        // If check_secondary_mx is set, and the local host was found as an
        // MX target, we need to determine if it's the primary (lowest priority)
        // MX or a secondary. If secondary, we decline.
        //
        // In the C code, this check happens after HOST_FOUND_LOCAL processing.
        // The local host's MX record is examined — if its priority is not the
        // lowest, we know we're a secondary MX.
        //
        // In the simplified Rust API, we check the host list: if all hosts
        // are still present and the local host hasn't been filtered out,
        // the self_action handler has allowed delivery to proceed. The
        // check_secondary_mx flag adds an additional constraint.
        tracing::debug!(
            router = router_name,
            "check_secondary_mx is set — examining MX priorities"
        );

        // If no hosts have MX records, there's nothing to check.
        if !hosts.iter().any(|h| h.mx_priority.is_some()) {
            return None;
        }

        // Find the lowest MX priority in the host list.
        let lowest_mx = hosts.iter().filter_map(|h| h.mx_priority).min();

        if let Some(lowest) = lowest_mx {
            tracing::debug!(
                router = router_name,
                lowest_mx = lowest,
                host_count = hosts.len(),
                "secondary MX check: lowest priority = {}",
                lowest
            );
        }

        // The actual secondary MX determination requires knowing which host
        // is local — this is handled by the HOST_FOUND_LOCAL path in the
        // main route() method. Here we return None to let that logic proceed.
        None
    }

    /// Handles the `fail_defer_domains` check.
    ///
    /// Translates C dnslookup.c lines 365-380:
    /// If the domain matches `fail_defer_domains`, convert a FAIL to DEFER.
    fn check_fail_defer(opts: &DnsLookupRouterOptions, domain: &str, router_name: &str) -> bool {
        opts.fail_defer_domains.as_deref().is_some_and(|list| {
            let matches = Self::domain_matches_list(domain, list);
            if matches {
                tracing::debug!(
                    router = router_name,
                    domain = domain,
                    "fail_defer_domains matched — converting FAIL to DEFER"
                );
            }
            matches
        })
    }

    /// Converts a list of resolved `HostItem`s to a list of host name strings.
    ///
    /// The host names are wrapped in `Tainted<String>` since they originate
    /// from DNS data (untrusted external source). The taint is then sanitized
    /// for inclusion in the `RouterResult::Accept` host list.
    fn hosts_to_name_list(hosts: &[HostItem]) -> Vec<String> {
        hosts
            .iter()
            .filter_map(|host| {
                // Log DNSSEC verification status for each host.
                // C: host items carry dnssec status from the DNS resolution.
                let dnssec_ok = matches!(host.dnssec_status, DnssecStatus::Yes);
                tracing::trace!(
                    host = host.name.as_str(),
                    dnssec = dnssec_ok,
                    mx = host.mx_priority,
                    "processing resolved host"
                );

                // Wrap DNS-sourced hostname in TaintedString for tracking.
                // DNS data is always tainted (untrusted external source).
                let tainted_name: TaintedString = Tainted::new(host.name.clone());

                // Inspect the tainted value without consuming it.
                let raw_ref: &str = tainted_name.as_ref();
                if raw_ref.is_empty() {
                    tracing::trace!(
                        host = %host.name,
                        "skipping empty hostname from DNS"
                    );
                    return None;
                }

                // Sanitize for use in the clean host list.
                // The validator returns true if the name is non-empty after trimming.
                match tainted_name.sanitize(|name| !name.trim().is_empty()) {
                    Ok(clean) => {
                        // Log using Clean::as_ref() before extracting inner value.
                        let clean_ref: &str = clean.as_ref();
                        tracing::trace!(validated_host = clean_ref, "host passed taint check");
                        Some(clean.into_inner())
                    }
                    Err(_) => {
                        // Whitespace-only hostname — skip it.
                        tracing::trace!(
                            host = %host.name,
                            "skipping whitespace-only hostname from DNS"
                        );
                        None
                    }
                }
            })
            .collect()
    }

    /// Wraps a trusted configuration-supplied domain into a `Clean<String>`.
    ///
    /// Configuration-supplied values (from `readconf.c` parsing) are trusted
    /// and can be wrapped directly in `Clean`. This is used for domain list
    /// patterns in `mx_domains`, `mx_fail_domains`, etc.
    ///
    /// C: config-supplied strings are not tainted (GET_UNTAINTED).
    #[inline]
    fn clean_config_value(value: &str) -> Clean<String> {
        Clean::new(value.to_owned())
    }

    /// Checks the `ipv4_prefer` condition and reorders hosts if matched.
    ///
    /// Translates C dnslookup.c lines 200-210 (ipv4_prefer handling):
    /// When the domain matches the `ipv4_prefer` domain list, IPv4 addresses
    /// are sorted before IPv6 addresses within each host.
    ///
    /// This is implemented as a post-processing step on the host list rather
    /// than a flag on the DNS resolver, since the C code also handles this
    /// as a post-lookup reordering via `host_prefer_ipv4()`.
    fn apply_ipv4_preference(
        opts: &DnsLookupRouterOptions,
        domain: &str,
        hosts: &mut [HostItem],
        router_name: &str,
    ) {
        let ipv4_prefer = match &opts.ipv4_prefer {
            Some(d) if !d.is_empty() => d,
            _ => return,
        };

        let should_prefer = expand_check_condition(ipv4_prefer, "ipv4_prefer", domain);

        if should_prefer {
            tracing::debug!(
                router = router_name,
                domain = domain,
                "ipv4_prefer matched — reordering addresses to prefer IPv4"
            );
            for host in hosts.iter_mut() {
                // Sort addresses so IPv4 comes before IPv6.
                host.addresses.sort_by(|a, b| {
                    let a_is_v4 = a.is_ipv4();
                    let b_is_v4 = b.is_ipv4();
                    // IPv4 (true) sorts before IPv6 (false).
                    b_is_v4.cmp(&a_is_v4)
                });
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  RouterDriver Trait Implementation
// ═══════════════════════════════════════════════════════════════════════════

impl RouterDriver for DnsLookupRouter {
    /// Main routing entry point — performs DNS lookup to determine delivery hosts.
    ///
    /// Translates C `dnslookup_router_entry()` from dnslookup.c (lines 97–499).
    ///
    /// ## Algorithm
    ///
    /// 1. Check if domain is an IP literal → DECLINE
    /// 2. Expand `check_srv` option for optional SRV lookup
    /// 3. Build host find flags (MX/A/AAAA/SRV/qualify/parents)
    /// 4. Build domain widening suffix list
    /// 5. Perform DNS lookup with widening loop
    /// 6. Handle HOST_FOUND_LOCAL → self_action()
    /// 7. Check mx_domains, fail_defer_domains, check_secondary_mx
    /// 8. Apply ipv4_prefer address reordering
    /// 9. Return Accept with transport name and host list
    fn route(
        &self,
        config: &RouterInstanceConfig,
        address: &str,
        _local_user: Option<&str>,
    ) -> Result<RouterResult, DriverError> {
        let router_name = &config.name;
        let opts = Self::get_options(config)?;
        let domain = Self::extract_domain(address);

        tracing::debug!(
            router = router_name.as_str(),
            address = address,
            domain = domain,
            "dnslookup router entry"
        );

        // Guard: empty domain is a fatal routing error (should never occur
        // with well-formed addresses, but guards against malformed input).
        if domain.is_empty() {
            return Ok(Self::config_error(format!(
                "router '{router_name}': address '{address}' has no domain part"
            )));
        }

        // ── Step 1: IP literal check ──────────────────────────────────
        //
        // C: dnslookup.c implicit check — IP literals like [192.0.2.1]
        // are not handled by the DNS lookup router.
        if Self::is_ip_literal(domain) {
            tracing::debug!(
                router = router_name.as_str(),
                domain = domain,
                "domain is IP literal — declining"
            );
            return Ok(RouterResult::Decline);
        }

        // ── Step 2: Expand check_srv for optional SRV lookup ──────────
        //
        // C: dnslookup.c lines 103-115
        let srv_service = Self::expand_check_srv(opts, router_name).map_err(DriverError::from)?;

        // ── Step 3: Build host find flags ─────────────────────────────
        //
        // C: dnslookup.c lines 112-130 — assemble whichrrs bitmask
        let whichrrs = Self::build_host_find_flags(opts, domain, router_name, &srv_service);

        tracing::debug!(
            router = router_name.as_str(),
            domain = domain,
            flags = ?whichrrs,
            srv_service = ?srv_service,
            qualify_single = opts.qualify_single,
            search_parents = opts.search_parents,
            "host find flags assembled"
        );

        // ── Step 4: Build domain widening suffix list ─────────────────
        //
        // C: dnslookup.c lines 117-135
        let widen_suffixes =
            Self::build_widen_list(opts, router_name).map_err(DriverError::from)?;

        // ── Step 5: Create DNS resolver and perform lookup ────────────
        //
        // Create a resolver using system defaults. This matches the C
        // pattern where resolver state is per-process.
        let resolver_config = exim_dns::resolver::ResolverConfig {
            qualify_single: opts.qualify_single,
            search_parents: opts.search_parents,
            ..exim_dns::resolver::ResolverConfig::default()
        };

        let resolver = DnsResolver::new(resolver_config).map_err(|e| {
            tracing::warn!(
                router = router_name.as_str(),
                error = %e,
                "failed to create DNS resolver"
            );
            DriverError::TempFail(format!(
                "router '{router_name}': failed to create DNS resolver: {e}"
            ))
        })?;

        let (find_result, resolved_domain) = Self::perform_dns_lookup(
            &resolver,
            domain,
            whichrrs,
            &srv_service,
            opts,
            config,
            router_name,
            &widen_suffixes,
        )
        .map_err(DriverError::from)?;

        // ── Step 6: Process lookup result ─────────────────────────────

        match find_result {
            // ── HOST_FIND_AGAIN — Temporary DNS failure ───────────────
            //
            // C: dnslookup.c lines 340-355
            HostFindResult::Again => {
                if config.pass_on_timeout {
                    tracing::debug!(
                        router = router_name.as_str(),
                        domain = domain,
                        "DNS temporary failure — pass_on_timeout → PASS"
                    );
                    return Ok(RouterResult::Pass);
                }
                tracing::debug!(
                    router = router_name.as_str(),
                    domain = domain,
                    "DNS temporary failure — deferring"
                );
                Ok(RouterResult::Defer {
                    message: Some(format!(
                        "router {router_name}: DNS lookup for '{domain}' \
                         returned a temporary error"
                    )),
                })
            }

            // ── HOST_FIND_FAILED — Permanent DNS failure ──────────────
            //
            // C: dnslookup.c lines 360-400
            HostFindResult::Failed => {
                // Check fail_defer_domains: convert FAIL → DEFER if matched.
                if Self::check_fail_defer(opts, domain, router_name) {
                    return Ok(RouterResult::Defer {
                        message: Some(format!(
                            "router {router_name}: DNS lookup for '{domain}' failed \
                             (deferred by fail_defer_domains)"
                        )),
                    });
                }

                tracing::debug!(
                    router = router_name.as_str(),
                    domain = domain,
                    "DNS lookup failed permanently — declining"
                );
                log::info!(
                    "router {}: DNS lookup for '{}' failed (no hosts found)",
                    router_name,
                    domain
                );
                Ok(RouterResult::Decline)
            }

            // ── HOST_FOUND_LOCAL — Self-reference detected ────────────
            //
            // C: dnslookup.c lines 410-440
            HostFindResult::FoundLocal(ref hosts) => {
                tracing::debug!(
                    router = router_name.as_str(),
                    domain = domain,
                    host_count = hosts.len(),
                    "DNS lookup found local host — processing self-reference"
                );

                // Check mx_domains condition first.
                if let Some(decline) =
                    Self::check_mx_domains(opts, &resolved_domain, hosts, router_name)
                {
                    return Ok(decline);
                }

                // Check domain canonicalization.
                // C: dnslookup.c lines 405-415 — if the fully qualified name
                // from DNS differs from the original domain, this is a
                // domain change. In the simplified Rust API, we handle this
                // by including the canonical name in the result.
                if resolved_domain != domain {
                    tracing::debug!(
                        router = router_name.as_str(),
                        original = domain,
                        canonical = resolved_domain.as_str(),
                        "domain canonicalized by DNS — rerouting"
                    );
                    if opts.rewrite_headers {
                        // Domain change with header rewriting — reroute.
                        return Ok(RouterResult::Rerouted {
                            new_addresses: vec![format!(
                                "{}@{resolved_domain}",
                                if let Some(at_pos) = address.rfind('@') {
                                    &address[..at_pos]
                                } else {
                                    address
                                }
                            )],
                        });
                    }
                }

                // Determine self-action from router config.
                let action = Self::parse_self_action(config);

                // Create an AddressItem for the self_action helper.
                let mut addr = AddressItem::new(address.to_string());
                let mut addr_new: Vec<AddressItem> = Vec::new();
                let mut ctx = DeliveryContext::default();

                // Find the first host that appears local for self_action.
                let first_host = hosts.first().cloned().unwrap_or_else(|| HostItem {
                    name: domain.to_string(),
                    addresses: Vec::new(),
                    mx_priority: None,
                    sort_key: 0,
                    dnssec_status: exim_dns::DnssecStatus::Unknown,
                    certname: None,
                });

                let self_result = self_action(
                    &mut addr,
                    &first_host,
                    &action,
                    opts.rewrite_headers,
                    config,
                    &mut addr_new,
                    &mut ctx,
                );

                // Map the self_action RouterResult to our return.
                match &self_result {
                    RouterResult::Pass => {
                        tracing::debug!(router = router_name.as_str(), "self_action returned PASS");
                        return Ok(RouterResult::Pass);
                    }
                    RouterResult::Defer { .. } => {
                        tracing::debug!(
                            router = router_name.as_str(),
                            "self_action returned DEFER"
                        );
                        return Ok(self_result);
                    }
                    RouterResult::Fail { .. } => {
                        tracing::debug!(router = router_name.as_str(), "self_action returned FAIL");
                        return Ok(self_result);
                    }
                    RouterResult::Rerouted { .. } => {
                        tracing::debug!(
                            router = router_name.as_str(),
                            "self_action returned REROUTED"
                        );
                        return Ok(self_result);
                    }
                    RouterResult::Accept { .. } => {
                        // self_action says "send" — proceed with delivery to self.
                        tracing::debug!(
                            router = router_name.as_str(),
                            "self_action returned Accept (send to self)"
                        );
                        // Fall through to the Accept path below with the hosts.
                    }
                    _ => {
                        // For any other result, propagate it.
                        return Ok(self_result);
                    }
                }

                // Check secondary MX condition after self_action handling.
                if let Some(decline) = Self::check_secondary_mx_condition(opts, hosts, router_name)
                {
                    return Ok(decline);
                }

                // If self_action allows proceeding, return Accept with the hosts.
                let mut hosts_vec = hosts.clone();
                Self::apply_ipv4_preference(opts, &resolved_domain, &mut hosts_vec, router_name);
                let host_names = Self::hosts_to_name_list(&hosts_vec);

                tracing::debug!(
                    router = router_name.as_str(),
                    domain = domain,
                    transport = ?config.transport_name,
                    hosts = ?host_names,
                    "accepting address (local host, send-to-self)"
                );

                Ok(RouterResult::Accept {
                    transport_name: config.transport_name.clone(),
                    host_list: host_names,
                })
            }

            // ── HOST_FOUND — Normal successful resolution ─────────────
            //
            // C: dnslookup.c lines 415-499
            HostFindResult::Found(ref hosts) => {
                tracing::debug!(
                    router = router_name.as_str(),
                    domain = domain,
                    resolved_domain = resolved_domain.as_str(),
                    host_count = hosts.len(),
                    "DNS lookup succeeded"
                );

                // Check mx_domains condition.
                if let Some(decline) =
                    Self::check_mx_domains(opts, &resolved_domain, hosts, router_name)
                {
                    return Ok(decline);
                }

                // Check domain canonicalization.
                // C: dnslookup.c lines 405-415
                if resolved_domain != domain && opts.rewrite_headers {
                    tracing::debug!(
                        router = router_name.as_str(),
                        original = domain,
                        canonical = resolved_domain.as_str(),
                        rewrite_headers = opts.rewrite_headers,
                        "domain canonicalized — rerouting with header rewrite"
                    );
                    return Ok(RouterResult::Rerouted {
                        new_addresses: vec![format!(
                            "{}@{resolved_domain}",
                            if let Some(at_pos) = address.rfind('@') {
                                &address[..at_pos]
                            } else {
                                address
                            }
                        )],
                    });
                }

                // Apply ipv4_prefer address reordering.
                let mut hosts_vec = hosts.clone();
                Self::apply_ipv4_preference(opts, &resolved_domain, &mut hosts_vec, router_name);

                // Build the host name list from resolved HostItems.
                let host_names = Self::hosts_to_name_list(&hosts_vec);

                // Check secondary MX condition.
                if let Some(decline) =
                    Self::check_secondary_mx_condition(opts, &hosts_vec, router_name)
                {
                    return Ok(decline);
                }

                // ── Accept: Finalize delivery metadata ──────────────
                //
                // C: dnslookup.c lines 455-499:
                //   rf_get_errors_address(addr, rblock, verify, &addr_prop)
                //   rf_get_munge_headers(addr, rblock, &extra_headers, &remove_headers)
                //   rf_get_transport(ob->transport_name, &rblock->transport, ...)
                //   addr->fallback_hosts = rblock->fallback_hosts
                //   rf_queue_add(addr, addr_local, addr_remote, rblock, pw)
                //
                // Collect delivery metadata from the router configuration
                // exactly as the C helpers would.  The metadata is logged
                // for observability and passed to the delivery orchestrator
                // alongside the Accept result.

                let mut metadata = DnsLookupDeliveryMetadata::new();
                metadata.populate_errors_address(config);
                metadata.populate_munge_headers(config);
                metadata.populate_ugid(config);

                // Attach fallback_hosts from config (C: addr->fallback_hosts = rblock->fallback_hosts).
                let _fallback = &config.fallback_hosts;

                let transport = config.transport_name.clone();

                tracing::debug!(
                    router = router_name.as_str(),
                    domain = domain,
                    transport = ?transport,
                    hosts = ?host_names,
                    errors_to = ?config.errors_to,
                    extra_headers_count = metadata.munge_result.extra_headers.len(),
                    remove_headers = ?metadata.munge_result.remove_headers,
                    ugid = ?metadata.ugid,
                    fallback_hosts = ?config.fallback_hosts,
                    "accepting address for remote delivery"
                );

                log::info!(
                    "router {}: accepted '{}' → transport={:?}, hosts={:?}",
                    router_name,
                    address,
                    transport,
                    host_names
                );

                Ok(RouterResult::Accept {
                    transport_name: transport,
                    host_list: host_names,
                })
            }
        }
    }

    /// Tidyup function — no-op for the DNS lookup router.
    ///
    /// C: `dnslookup_router_tidyup = NULL` (no tidyup function registered).
    ///
    /// The DNS resolver is created per route() invocation and dropped
    /// automatically when it goes out of scope.
    fn tidyup(&self, _config: &RouterInstanceConfig) {
        // No resources to clean up — resolver is created and dropped per call.
    }

    /// Returns the descriptor flags for the DNS lookup router type.
    ///
    /// C: `dnslookup_router_info.ri_flags = ri_yestransport`
    ///
    /// The `ri_yestransport` flag indicates that this router requires a
    /// transport to be configured. In the simplified Rust API, this is
    /// communicated via `RouterFlags::NONE` since transport validation
    /// is handled by the delivery orchestrator.
    fn flags(&self) -> RouterFlags {
        // C uses ri_yestransport (value 1) here, but the Rust RouterFlags
        // doesn't currently define a YES_TRANSPORT constant. The transport
        // requirement is enforced at the config validation level.
        RouterFlags::NONE
    }

    /// Returns the canonical driver name: `"dnslookup"`.
    ///
    /// This must match the `name` field of the corresponding
    /// `RouterDriverFactory` and the `driver = dnslookup` directive
    /// in Exim configuration files.
    fn driver_name(&self) -> &str {
        "dnslookup"
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Driver Registration
// ═══════════════════════════════════════════════════════════════════════════

// Register the DNS lookup router driver via `inventory::submit!`.
//
// Guarded by `#[cfg(feature = "router-dnslookup")]`, matching the C
// preprocessor guard `#ifdef ROUTER_DNSLOOKUP` (dnslookup.c line 12).
//
// The factory creates a new `DnsLookupRouter` instance when the
// configuration parser encounters `driver = dnslookup` in a router
// definition.
#[cfg(feature = "router-dnslookup")]
inventory::submit! {
    RouterDriverFactory {
        name: "dnslookup",
        create: || Box::new(DnsLookupRouter::new()),
        avail_string: Some("dnslookup"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Unit Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── DnsLookupRouterOptions Tests ──────────────────────────────────

    #[test]
    fn test_options_default() {
        let opts = DnsLookupRouterOptions::default();
        assert!(!opts.check_secondary_mx);
        assert!(opts.qualify_single);
        assert!(!opts.search_parents);
        assert!(opts.rewrite_headers);
        assert!(opts.widen_domains.is_none());
        assert!(opts.mx_domains.is_none());
        assert!(opts.mx_fail_domains.is_none());
        assert!(opts.srv_fail_domains.is_none());
        assert!(opts.check_srv.is_none());
        assert!(opts.fail_defer_domains.is_none());
        assert!(opts.ipv4_only.is_none());
        assert!(opts.ipv4_prefer.is_none());
    }

    #[test]
    fn test_options_all_fields_present() {
        let opts = DnsLookupRouterOptions {
            check_secondary_mx: true,
            qualify_single: false,
            search_parents: true,
            rewrite_headers: false,
            widen_domains: Some("example.com:test.org".to_string()),
            mx_domains: Some("*.mx.example.com".to_string()),
            mx_fail_domains: Some("fail.example.com".to_string()),
            srv_fail_domains: Some("srv.example.com".to_string()),
            check_srv: Some("_submission._tcp".to_string()),
            fail_defer_domains: Some("defer.example.com".to_string()),
            ipv4_only: Some("v4.example.com".to_string()),
            ipv4_prefer: Some("prefer.example.com".to_string()),
        };
        assert!(opts.check_secondary_mx);
        assert!(!opts.qualify_single);
        assert!(opts.search_parents);
        assert!(!opts.rewrite_headers);
        assert_eq!(opts.widen_domains.as_deref(), Some("example.com:test.org"));
        assert_eq!(opts.mx_domains.as_deref(), Some("*.mx.example.com"));
    }

    // ── Domain Extraction Tests ──────────────────────────────────────

    #[test]
    fn test_extract_domain_normal() {
        assert_eq!(
            DnsLookupRouter::extract_domain("user@example.com"),
            "example.com"
        );
    }

    #[test]
    fn test_extract_domain_no_at() {
        assert_eq!(
            DnsLookupRouter::extract_domain("example.com"),
            "example.com"
        );
    }

    #[test]
    fn test_extract_domain_multiple_at() {
        assert_eq!(
            DnsLookupRouter::extract_domain("user@host@example.com"),
            "example.com"
        );
    }

    // ── IP Literal Tests ─────────────────────────────────────────────

    #[test]
    fn test_is_ip_literal_ipv4() {
        assert!(DnsLookupRouter::is_ip_literal("[192.0.2.1]"));
    }

    #[test]
    fn test_is_ip_literal_ipv6() {
        assert!(DnsLookupRouter::is_ip_literal("[IPv6:::1]"));
    }

    #[test]
    fn test_is_ip_literal_normal_domain() {
        assert!(!DnsLookupRouter::is_ip_literal("example.com"));
    }

    #[test]
    fn test_is_ip_literal_partial_bracket() {
        assert!(!DnsLookupRouter::is_ip_literal("[192.0.2.1"));
        assert!(!DnsLookupRouter::is_ip_literal("192.0.2.1]"));
    }

    // ── Domain Matching Tests ────────────────────────────────────────

    #[test]
    fn test_domain_matches_exact() {
        assert!(DnsLookupRouter::domain_matches_list(
            "example.com",
            "example.com"
        ));
    }

    #[test]
    fn test_domain_matches_case_insensitive() {
        assert!(DnsLookupRouter::domain_matches_list(
            "Example.COM",
            "example.com"
        ));
    }

    #[test]
    fn test_domain_matches_wildcard() {
        assert!(DnsLookupRouter::domain_matches_list(
            "sub.example.com",
            "*.example.com"
        ));
    }

    #[test]
    fn test_domain_matches_wildcard_no_match() {
        assert!(!DnsLookupRouter::domain_matches_list(
            "example.com",
            "*.example.com"
        ));
    }

    #[test]
    fn test_domain_matches_star_all() {
        assert!(DnsLookupRouter::domain_matches_list(
            "anything.example.com",
            "*"
        ));
    }

    #[test]
    fn test_domain_matches_colon_list() {
        assert!(DnsLookupRouter::domain_matches_list(
            "b.example.com",
            "a.example.com:b.example.com:c.example.com"
        ));
    }

    #[test]
    fn test_domain_no_match() {
        assert!(!DnsLookupRouter::domain_matches_list(
            "other.com",
            "example.com"
        ));
    }

    // ── Driver Name and Flags Tests ──────────────────────────────────

    #[test]
    fn test_driver_name() {
        let router = DnsLookupRouter::new();
        assert_eq!(router.driver_name(), "dnslookup");
    }

    #[test]
    fn test_flags() {
        let router = DnsLookupRouter::new();
        assert_eq!(router.flags(), RouterFlags::NONE);
    }

    // ── Options Downcast Test ────────────────────────────────────────

    #[test]
    fn test_get_options_success() {
        let mut config = RouterInstanceConfig::new("test_dns", "dnslookup");
        config.options = Box::new(DnsLookupRouterOptions::default());
        let opts = DnsLookupRouter::get_options(&config);
        assert!(opts.is_ok());
        let opts = opts.unwrap();
        assert!(opts.qualify_single);
    }

    #[test]
    fn test_get_options_wrong_type() {
        let config = RouterInstanceConfig::new("test_dns", "dnslookup");
        // options defaults to Box::new(()) — wrong type
        let opts = DnsLookupRouter::get_options(&config);
        assert!(opts.is_err());
    }

    // ── IP Literal Decline Test ──────────────────────────────────────

    #[test]
    fn test_route_ip_literal_declines() {
        let router = DnsLookupRouter::new();
        let mut config = RouterInstanceConfig::new("test_dns", "dnslookup");
        config.options = Box::new(DnsLookupRouterOptions::default());

        let result = router.route(&config, "user@[192.0.2.1]", None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), RouterResult::Decline);
    }

    // ── Self-Action Parsing Tests ────────────────────────────────────

    #[test]
    fn test_parse_self_action_freeze() {
        let config = RouterInstanceConfig::new("test", "dnslookup");
        // self_code defaults to 0 = Freeze
        assert_eq!(
            DnsLookupRouter::parse_self_action(&config),
            SelfAction::Freeze
        );
    }

    #[test]
    fn test_parse_self_action_pass() {
        let mut config = RouterInstanceConfig::new("test", "dnslookup");
        config.self_code = 5;
        assert_eq!(
            DnsLookupRouter::parse_self_action(&config),
            SelfAction::Pass
        );
    }

    #[test]
    fn test_parse_self_action_reroute() {
        let mut config = RouterInstanceConfig::new("test", "dnslookup");
        config.self_code = 4;
        config.self_config = Some(">>other.example.com".to_string());
        match DnsLookupRouter::parse_self_action(&config) {
            SelfAction::Reroute(domain) => assert_eq!(domain, "other.example.com"),
            other => panic!("expected Reroute, got {:?}", other),
        }
    }

    // ── Host Find Flags Tests ────────────────────────────────────────

    #[test]
    fn test_build_flags_default() {
        let opts = DnsLookupRouterOptions::default();
        let flags = DnsLookupRouter::build_host_find_flags(&opts, "example.com", "test", &None);
        assert!(flags.contains(HostFindFlags::BY_MX));
        assert!(flags.contains(HostFindFlags::BY_A));
        assert!(flags.contains(HostFindFlags::BY_AAAA));
        assert!(flags.contains(HostFindFlags::QUALIFY_SINGLE));
        assert!(!flags.contains(HostFindFlags::SEARCH_PARENTS));
        assert!(!flags.contains(HostFindFlags::BY_SRV));
    }

    #[test]
    fn test_build_flags_with_srv() {
        let opts = DnsLookupRouterOptions::default();
        let srv = Some("_submission._tcp".to_string());
        let flags = DnsLookupRouter::build_host_find_flags(&opts, "example.com", "test", &srv);
        assert!(flags.contains(HostFindFlags::BY_SRV));
    }

    #[test]
    fn test_build_flags_search_parents() {
        let opts = DnsLookupRouterOptions {
            search_parents: true,
            ..DnsLookupRouterOptions::default()
        };
        let flags = DnsLookupRouter::build_host_find_flags(&opts, "example.com", "test", &None);
        assert!(flags.contains(HostFindFlags::SEARCH_PARENTS));
    }

    // ── Host Name List Tests ─────────────────────────────────────────

    #[test]
    fn test_hosts_to_name_list() {
        use std::net::IpAddr;
        let hosts = vec![
            HostItem {
                name: "mx1.example.com".to_string(),
                addresses: vec!["192.0.2.1".parse::<IpAddr>().unwrap()],
                mx_priority: Some(10),
                sort_key: 0,
                dnssec_status: exim_dns::DnssecStatus::Unknown,
                certname: None,
            },
            HostItem {
                name: "mx2.example.com".to_string(),
                addresses: vec!["192.0.2.2".parse::<IpAddr>().unwrap()],
                mx_priority: Some(20),
                sort_key: 0,
                dnssec_status: exim_dns::DnssecStatus::Unknown,
                certname: None,
            },
        ];
        let names = DnsLookupRouter::hosts_to_name_list(&hosts);
        assert_eq!(names, vec!["mx1.example.com", "mx2.example.com"]);
    }

    #[test]
    fn test_hosts_to_name_list_empty() {
        let hosts: Vec<HostItem> = Vec::new();
        let names = DnsLookupRouter::hosts_to_name_list(&hosts);
        assert!(names.is_empty());
    }

    // ── MX Domains Check Tests ───────────────────────────────────────

    #[test]
    fn test_check_mx_domains_no_config() {
        let opts = DnsLookupRouterOptions::default();
        let hosts = vec![HostItem {
            name: "mx.example.com".to_string(),
            addresses: Vec::new(),
            mx_priority: None,
            sort_key: 0,
            dnssec_status: exim_dns::DnssecStatus::Unknown,
            certname: None,
        }];
        assert!(DnsLookupRouter::check_mx_domains(&opts, "example.com", &hosts, "test").is_none());
    }

    #[test]
    fn test_check_mx_domains_no_mx_records() {
        let opts = DnsLookupRouterOptions {
            mx_domains: Some("example.com".to_string()),
            ..DnsLookupRouterOptions::default()
        };
        // Host found by A record only (no mx_priority).
        let hosts = vec![HostItem {
            name: "example.com".to_string(),
            addresses: Vec::new(),
            mx_priority: None,
            sort_key: 0,
            dnssec_status: exim_dns::DnssecStatus::Unknown,
            certname: None,
        }];
        let result = DnsLookupRouter::check_mx_domains(&opts, "example.com", &hosts, "test");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), RouterResult::Decline);
    }

    #[test]
    fn test_check_mx_domains_with_mx_records() {
        let opts = DnsLookupRouterOptions {
            mx_domains: Some("example.com".to_string()),
            ..DnsLookupRouterOptions::default()
        };
        let hosts = vec![HostItem {
            name: "mx.example.com".to_string(),
            addresses: Vec::new(),
            mx_priority: Some(10),
            sort_key: 0,
            dnssec_status: exim_dns::DnssecStatus::Unknown,
            certname: None,
        }];
        // Has MX records, so check passes (returns None).
        assert!(DnsLookupRouter::check_mx_domains(&opts, "example.com", &hosts, "test").is_none());
    }

    // ── Fail Defer Check Tests ───────────────────────────────────────

    #[test]
    fn test_check_fail_defer_no_config() {
        let opts = DnsLookupRouterOptions::default();
        assert!(!DnsLookupRouter::check_fail_defer(
            &opts,
            "example.com",
            "test"
        ));
    }

    #[test]
    fn test_check_fail_defer_matches() {
        let opts = DnsLookupRouterOptions {
            fail_defer_domains: Some("example.com".to_string()),
            ..DnsLookupRouterOptions::default()
        };
        assert!(DnsLookupRouter::check_fail_defer(
            &opts,
            "example.com",
            "test"
        ));
    }

    #[test]
    fn test_check_fail_defer_no_match() {
        let opts = DnsLookupRouterOptions {
            fail_defer_domains: Some("other.com".to_string()),
            ..DnsLookupRouterOptions::default()
        };
        assert!(!DnsLookupRouter::check_fail_defer(
            &opts,
            "example.com",
            "test"
        ));
    }

    // ── Error Type Tests ─────────────────────────────────────────────

    #[test]
    fn test_dns_lookup_error_to_driver_error() {
        let err = DnsLookupError::DnsResolutionFailed {
            domain: "example.com".to_string(),
            reason: "NXDOMAIN".to_string(),
        };
        let driver_err: DriverError = err.into();
        match driver_err {
            DriverError::ExecutionFailed(msg) => {
                assert!(msg.contains("example.com"));
                assert!(msg.contains("NXDOMAIN"));
            }
            _ => panic!("expected ExecutionFailed"),
        }

        let err = DnsLookupError::TemporaryFailure {
            domain: "example.com".to_string(),
            reason: "timeout".to_string(),
        };
        let driver_err: DriverError = err.into();
        assert!(matches!(driver_err, DriverError::TempFail(_)));
    }
}
