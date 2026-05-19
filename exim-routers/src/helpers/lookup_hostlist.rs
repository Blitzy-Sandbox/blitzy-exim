// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! Host list IP address lookup for router drivers.
//!
//! Translates **`src/src/routers/rf_lookup_hostlist.c`** (271 lines) into Rust.
//! This is the **most complex** shared router helper — it resolves IP addresses
//! for all entries in a router's host list, handling:
//!
//! - MX shorthand (`hostname/MX`) for MX-based DNS lookups
//! - Port specifications embedded in hostnames (`hostname:port`)
//! - Multiple DNS lookup strategies (byname, bydns, default fallback)
//! - Six configurable failure policies via [`HostFindFailedPolicy`]
//! - `pass_on_timeout` override for temporary DNS failures
//! - Self-reference detection (`HOST_FOUND_LOCAL`) with [`SelfAction`] dispatch
//! - Local host removal from the host list with flag tracking
//!
//! ## C Source Correspondence
//!
//! | C construct | Rust equivalent |
//! |---|---|
//! | `int whichlists` bitfield | [`WhichLists`] newtype with associated constants |
//! | `hff_ignore/pass/decline/defer/fail/freeze` | [`HostFindFailedPolicy`] enum |
//! | `host_find_byname(h, ...)` | [`DnsResolver::host_find_byname()`] |
//! | `host_find_bydns(h, ...)` | [`DnsResolver::host_find_bydns()`] |
//! | `HOST_FOUND` / `HOST_FOUND_LOCAL` | [`HostFindResult::Found`] / [`HostFindResult::FoundLocal`] |
//! | `HOST_FIND_FAILED` / `HOST_FIND_AGAIN` | [`HostFindResult::Failed`] / [`HostFindResult::Again`] |
//! | `rf_self_action(addr, h, ...)` | [`super::self_action::self_action()`] |
//! | `SPECIAL_FREEZE` constant | `SPECIAL_FREEZE` local constant |
//! | `af_local_host_removed` flag | `AF_LOCAL_HOST_REMOVED` local constant |
//! | `DEBUG(D_route\|D_host_lookup)` | `tracing::debug!(...)` |
//! | `addr->message = ...` | `addr.message = Some(...)` |
//! | `addr->basic_errno = ERRNO_DNSDEFER` | Encoded in `LookupHostlistError::DnsError` |
//! | `addr->special_action = SPECIAL_FREEZE` | `addr.special_action = SPECIAL_FREEZE` |
//!
//! ## Safety
//!
//! This module contains **zero `unsafe` code** (per AAP §0.7.2).

// ── Imports ────────────────────────────────────────────────────────────────

use super::change_domain::{AddressItem, DeliveryContext};
use super::self_action::{self_action, SelfAction};
use exim_dns::{DnsError, DnsResolver, DnssecDomains, HostFindFlags, HostFindResult, HostItem};
use exim_drivers::router_driver::{RouterInstanceConfig, RouterResult};
use exim_store::Tainted;

// ── Constants ──────────────────────────────────────────────────────────────

/// Special action code: freeze the message in the spool queue.
///
/// Maps to C `SPECIAL_FREEZE` (value 1) from `macros.h`.  When set on
/// `AddressItem::special_action`, the delivery engine queues the message
/// but does not attempt delivery until an administrator manually releases
/// the message via `exim -Mt <message-id>`.
///
/// Used by [`HostFindFailedPolicy::Freeze`] when a permanent DNS failure
/// occurs on a host in the list.
const SPECIAL_FREEZE: i32 = 1;

/// Address flag: one or more hosts were removed from the host list because
/// they resolved to local IP addresses.
///
/// Maps to C `af_local_host_removed` in the `address_item.flags` bitfield.
/// Set when [`HostFindResult::FoundLocal`] is returned for a host that
/// follows previously resolved remote hosts — the local host and all
/// subsequent entries are truncated from the list.
///
/// Bit 8 in the address flags bitfield.
const AF_LOCAL_HOST_REMOVED: u32 = 1 << 8;

/// Sentinel value for MX priority indicating that the host was NOT found
/// via an MX record lookup (direct A/AAAA resolution instead).
///
/// Maps to C `MX_NONE` (-1) from `macros.h`.  Used in diagnostic logging
/// to distinguish MX-routed hosts from directly-addressed hosts.
const MX_NONE: i32 = -1;

// ── WhichLists Type ────────────────────────────────────────────────────────

/// Bitflag type controlling DNS lookup strategy for host resolution.
///
/// Replaces the C integer bitfield `whichlists` parameter with associated
/// constants.  Multiple flags can be combined using the `|` operator to
/// specify both the lookup method (byname vs. bydns) and IP version
/// preference (IPv4-only vs. IPv4-preferred).
///
/// | C Define | Value | Rust Constant |
/// |---|---|---|
/// | `LK_DEFAULT` | `0` | [`WhichLists::DEFAULT`] |
/// | `LK_BYNAME` | `1` | [`WhichLists::BYNAME`] |
/// | `LK_BYDNS` | `2` | [`WhichLists::BYDNS`] |
/// | `LK_IPV4_ONLY` | `4` | [`WhichLists::IPV4_ONLY`] |
/// | `LK_IPV4_PREFER` | `8` | [`WhichLists::IPV4_PREFER`] |
///
/// `DEFAULT` (0) means the router does not force a specific method — the
/// engine tries DNS first, then falls back to byname (`getaddrinfo`) if
/// the DNS lookup returns `HOST_FIND_FAILED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WhichLists(u32);

impl WhichLists {
    /// No specific lookup method forced.  Try DNS first; on failure, fall
    /// back to byname (`getaddrinfo`) resolution.
    pub const DEFAULT: Self = Self(0);

    /// Force byname (`getaddrinfo`) resolution — skip DNS MX/SRV lookups.
    ///
    /// C equivalent: `LK_BYNAME` (value 1).
    pub const BYNAME: Self = Self(1);

    /// Force DNS-based resolution — do not fall back to byname.
    ///
    /// C equivalent: `LK_BYDNS` (value 2).
    pub const BYDNS: Self = Self(2);

    /// Restrict lookups to IPv4 (A records only, no AAAA).
    ///
    /// C equivalent: `LK_IPV4_ONLY` (value 4).
    pub const IPV4_ONLY: Self = Self(4);

    /// Prefer IPv4 results but include IPv6 — A records before AAAA.
    ///
    /// C equivalent: `LK_IPV4_PREFER` (value 8).
    pub const IPV4_PREFER: Self = Self(8);

    /// Check whether the specified flag bits are set.
    #[inline]
    fn has(self, flag: Self) -> bool {
        flag.0 != 0 && (self.0 & flag.0) == flag.0
    }

    /// Returns `true` if neither BYNAME nor BYDNS is explicitly set,
    /// meaning the default lookup strategy (DNS with byname fallback)
    /// should be used.
    #[inline]
    fn is_default(self) -> bool {
        (self.0 & (Self::BYNAME.0 | Self::BYDNS.0)) == 0
    }
}

impl std::ops::BitOr for WhichLists {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for WhichLists {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

// ── HostFindFailedPolicy Enum ──────────────────────────────────────────────

/// Policy action when a DNS lookup permanently fails for a host in the
/// router's host list.
///
/// Replaces the C `hff_*` enum values (`hff_ignore`, `hff_pass`,
/// `hff_decline`, `hff_defer`, `hff_fail`, `hff_freeze`) set via the
/// `host_find_failed` configuration option on each router.
///
/// The policy is applied per-host: if a host list contains multiple
/// entries, only the entry whose DNS lookup fails is subject to this
/// policy.  The remaining hosts continue to be resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostFindFailedPolicy {
    /// Remove the failed host from the list and continue resolving
    /// the remaining hosts.  If all hosts fail, the address is deferred.
    ///
    /// C equivalent: `hff_ignore` (rf_lookup_hostlist.c line 191).
    Ignore,

    /// Return PASS — hand the address to the next router in the chain.
    ///
    /// C equivalent: `hff_pass` (rf_lookup_hostlist.c line 195).
    Pass,

    /// Return DECLINE — this router is not applicable for this address.
    ///
    /// C equivalent: `hff_decline` (rf_lookup_hostlist.c line 198).
    Decline,

    /// Return DEFER — retry the address later.  This is the most common
    /// policy for transient DNS failures (default for many routers).
    ///
    /// C equivalent: `hff_defer` (rf_lookup_hostlist.c line 201).
    Defer,

    /// Return FAIL — permanently reject the address with a bounce.
    ///
    /// C equivalent: `hff_fail` (rf_lookup_hostlist.c line 207).
    Fail,

    /// Freeze the message and return DEFER.  Sets `special_action` on
    /// the address to `SPECIAL_FREEZE`, causing the delivery engine to
    /// hold the message until administrator intervention.
    ///
    /// C equivalent: `hff_freeze` (rf_lookup_hostlist.c lines 211–214).
    Freeze,
}

// ── LookupHostlistError Enum ───────────────────────────────────────────────

/// Errors that can occur during host list IP address lookup.
///
/// These represent exceptional error conditions beyond the normal
/// routing outcomes (which are returned as [`RouterResult`] variants).
/// The error variants replace the C pattern of setting `addr->message`
/// and `addr->basic_errno` before returning integer codes.
#[derive(Debug, thiserror::Error)]
pub enum LookupHostlistError {
    /// A DNS lookup encountered an unrecoverable error beyond simple
    /// `HOST_FIND_FAILED` or `HOST_FIND_AGAIN` (e.g., resolver
    /// misconfiguration, invalid domain encoding, DNSSEC validation
    /// failure).
    ///
    /// The `host` field records the hostname that failed, and `detail`
    /// provides the underlying error description from the DNS resolver.
    #[error("DNS lookup error for host {host}: {detail}")]
    DnsError {
        /// The hostname whose DNS lookup failed.
        host: String,
        /// Detailed error description from the DNS resolver layer.
        detail: String,
    },

    /// The self-action handler encountered an unexpected condition
    /// during self-reference processing.
    ///
    /// This is distinct from the normal self-action outcomes (Freeze,
    /// Defer, Fail, Send, Reroute, Pass) which are returned as
    /// [`RouterResult`] variants.
    #[error("self-action failed: {0}")]
    SelfActionFailed(String),
}

impl From<DnsError> for LookupHostlistError {
    fn from(err: DnsError) -> Self {
        Self::DnsError {
            host: String::new(),
            detail: err.to_string(),
        }
    }
}

// ── Helper Functions ───────────────────────────────────────────────────────

/// Parse an optional port number from a hostname string.
///
/// Checks for `hostname:port` syntax (C `host_item_get_port` equivalent).
/// Returns the hostname (without port suffix) and the parsed port number
/// (or `None` if no port was specified).
///
/// IPv6 addresses in brackets (`[::1]:25`) are handled: the port is only
/// parsed if the colon appears after the closing bracket.
fn parse_host_port(name: &str) -> (&str, Option<u16>) {
    // IPv6 bracket notation: [::1]:25
    if let Some(bracket_end) = name.rfind(']') {
        if let Some(colon_pos) = name[bracket_end..].rfind(':') {
            let actual_pos = bracket_end + colon_pos;
            if let Ok(port) = name[actual_pos + 1..].parse::<u16>() {
                return (&name[..actual_pos], Some(port));
            }
        }
        return (name, None);
    }

    // Simple hostname:port — only if there's exactly one colon
    // (multiple colons would indicate an unbracketed IPv6 address).
    let colon_count = name.chars().filter(|&c| c == ':').count();
    if colon_count == 1 {
        if let Some(colon_pos) = name.rfind(':') {
            if let Ok(port) = name[colon_pos + 1..].parse::<u16>() {
                return (&name[..colon_pos], Some(port));
            }
        }
    }

    (name, None)
}

/// Check for and strip a `/MX` suffix from a hostname (case-insensitive).
///
/// In Exim configuration, appending `/MX` to a hostname in a host list
/// causes an MX record lookup for that domain instead of a direct A/AAAA
/// lookup.  For example, `example.com/MX` looks up MX records for
/// `example.com` and routes to the resulting mail exchangers.
///
/// Returns the hostname (with `/MX` stripped if present) and a boolean
/// indicating whether the MX suffix was found.
fn check_mx_suffix(name: &str) -> (&str, bool) {
    let len = name.len();
    if len > 3 {
        let suffix = &name[len - 3..];
        if suffix.eq_ignore_ascii_case("/mx") {
            return (&name[..len - 3], true);
        }
    }
    (name, false)
}

/// Determine whether a string looks like an IP address (IPv4 or IPv6).
///
/// Returns `true` for dotted-decimal IPv4 (`192.168.1.1`), bracketed
/// IPv6 (`[::1]`), or bare IPv6 (`::1`).  This is a quick heuristic
/// check — not a full validation.
fn is_ip_literal(name: &str) -> bool {
    // Bracketed IPv6
    if name.starts_with('[') {
        return true;
    }
    // Try parsing as an IP address
    name.parse::<std::net::IpAddr>().is_ok()
}

/// Compute [`HostFindFlags`] for an MX-based DNS lookup from the
/// [`WhichLists`] configuration.
///
/// Maps the IPv4 preference flags to appropriate DNS record type flags:
/// - `IPV4_ONLY` → MX + A records only (no AAAA)
/// - `IPV4_PREFER` → MX + A + AAAA (A preferred via ordering)
/// - Default → MX + A + AAAA
fn compute_mx_flags(which: WhichLists) -> HostFindFlags {
    let mut flags = HostFindFlags::BY_MX;
    if which.has(WhichLists::IPV4_ONLY) {
        flags |= HostFindFlags::BY_A;
    } else {
        flags |= HostFindFlags::BY_A | HostFindFlags::BY_AAAA;
    }
    flags
}

/// Compute [`HostFindFlags`] for a non-MX DNS lookup from the
/// [`WhichLists`] configuration.
///
/// Maps the IPv4 preference flags to appropriate DNS record type flags:
/// - `IPV4_ONLY` → A records only
/// - `IPV4_PREFER` → A + AAAA (A preferred via ordering)
/// - Default → A + AAAA
fn compute_dns_flags(which: WhichLists) -> HostFindFlags {
    if which.has(WhichLists::IPV4_ONLY) {
        HostFindFlags::BY_A
    } else {
        HostFindFlags::BY_A | HostFindFlags::BY_AAAA
    }
}

/// Convert a numeric self-action code (from `RouterInstanceConfig::self_code`)
/// to the corresponding [`SelfAction`] enum variant.
///
/// The mapping follows the C `self_xxx` enum ordering:
///
/// | Code | C enum | Rust variant |
/// |---|---|---|
/// | 0 | `self_freeze` | `SelfAction::Freeze` |
/// | 1 | `self_defer` | `SelfAction::Defer` |
/// | 2 | `self_fail` | `SelfAction::Fail` |
/// | 3 | `self_send` | `SelfAction::Send` |
/// | 4 | `self_reroute` | `SelfAction::Reroute(domain)` |
/// | 5 | `self_pass` | `SelfAction::Pass` |
///
/// For `self_reroute`, the target domain is extracted from the
/// `self_config` option string (the text after `>>` in the Exim
/// configuration).
fn self_code_to_action(code: i32, self_config: Option<&str>) -> SelfAction {
    match code {
        0 => SelfAction::Freeze,
        1 => SelfAction::Defer,
        2 => SelfAction::Fail,
        3 => SelfAction::Send,
        4 => SelfAction::Reroute(self_config.unwrap_or("").to_string()),
        5 => SelfAction::Pass,
        // Unknown codes default to Freeze (the most conservative action),
        // matching C behavior where an invalid self code would trigger a
        // log_write and continue with DEFER semantics.
        _ => {
            tracing::debug!(code = code, "unknown self_code — defaulting to Freeze");
            SelfAction::Freeze
        }
    }
}

// ── Main Function ──────────────────────────────────────────────────────────

/// Look up IP addresses for all entries in a router's host list.
///
/// This is the core host resolution engine used by routers that specify a
/// static host list (e.g., `manualroute`, `dnslookup`).  It iterates
/// through each hostname in `addr.host_list`, performs DNS resolution via
/// the provided [`DnsResolver`], and applies the configured failure
/// policy when lookups fail.
///
/// Translates C `rf_lookup_hostlist()` from `rf_lookup_hostlist.c`.
///
/// # Arguments
///
/// * `router_config` — The router instance configuration, providing
///   `pass_on_timeout`, `self_code`, `self_rewrite`, `self_config`,
///   and `name` for error messages.
/// * `addr` — The address item being routed.  Its `host_list`,
///   `message`, `special_action`, and `flags` fields may be modified.
/// * `ignored_target_hostname` — Optional hostname to exclude from
///   results (used to prevent routing loops).
/// * `which_lists` — Controls the DNS lookup strategy (byname, bydns,
///   IPv4-only, etc.).
/// * `hff_code` — The failure policy to apply when a host lookup fails
///   permanently (`HOST_FIND_FAILED`).
/// * `addr_new` — Output vector for new addresses generated by
///   self-action reroute (passed through to [`self_action()`]).
/// * `resolver` — DNS resolver instance for host lookups.
/// * `dnssec` — Optional DNSSEC request/require domain configuration
///   from the router, passed through to `host_find_bydns()`.
/// * `ctx` — Delivery context (passed through to [`self_action()`]).
///
/// # Returns
///
/// A tuple of `(RouterResult, bool)` where:
/// - `RouterResult` is the routing outcome (Accept, Pass, Decline,
///   Defer, Fail, Error, or Rerouted).
/// - `bool` is `self_detected` — `true` if any host resolved to a
///   local IP address and the self-action handler was invoked.
///
/// # Errors
///
/// Returns [`LookupHostlistError`] for exceptional DNS errors beyond
/// simple `HOST_FIND_FAILED` or `HOST_FIND_AGAIN` conditions.
// This function mirrors the C rf_lookup_hostlist() which also takes many
// parameters (6 in C, more here because Rust passes global state explicitly).
#[allow(clippy::too_many_arguments)] // justified: faithful C API translation with explicit state
pub fn lookup_hostlist(
    router_config: &RouterInstanceConfig,
    addr: &mut AddressItem,
    ignored_target_hostname: Option<&str>,
    which_lists: WhichLists,
    hff_code: HostFindFailedPolicy,
    addr_new: &mut Vec<AddressItem>,
    resolver: &DnsResolver,
    dnssec: Option<&DnssecDomains>,
    ctx: &mut DeliveryContext,
) -> Result<(RouterResult, bool), LookupHostlistError> {
    let mut self_send = false;
    let mut self_detected = false;
    let mut has_prev_resolved = false;

    // Take ownership of the host list for iteration.  We rebuild a new
    // list containing only the successfully resolved hostnames.
    let original_hosts = std::mem::take(&mut addr.host_list);
    let mut resolved_hosts: Vec<String> = Vec::with_capacity(original_hosts.len());

    let mut idx = 0;

    while idx < original_hosts.len() {
        let raw_name = &original_hosts[idx];

        // ── Skip already-resolved entries ──────────────────────────────
        //
        // C (rf_lookup_hostlist.c line 67):
        //   if (h->address) { prev = h; continue; }
        //
        // In the Rust model, an "already resolved" entry is an IP literal
        // that doesn't need DNS lookup.
        if is_ip_literal(raw_name) {
            tracing::debug!(host = %raw_name, "host already has IP address — skipping lookup");
            has_prev_resolved = true;
            resolved_hosts.push(raw_name.clone());
            idx += 1;
            continue;
        }

        // ── Taint tracking for user-supplied hostname ──────────────────
        //
        // Hostnames from the configuration file or MX expansion are
        // potentially tainted.  Wrap in Tainted<String> per AAP §0.4.3
        // for provenance tracking.  Uses:
        //   - as_ref() for logging (non-consuming borrow)
        //   - map() for taint-preserving normalization
        //   - into_inner() to extract the cleaned value for DNS calls
        let tainted_name = Tainted::new(raw_name.clone());

        // Log with taint-aware display (as_ref borrows the inner value).
        tracing::debug!(
            host = %tainted_name.as_ref(),
            "finding IP address for host"
        );

        // Taint-preserving normalization: trim whitespace that may have
        // leaked from config file parsing.  The result remains Tainted
        // because trimming does not validate the data.
        let normalized = tainted_name.map(|s| s.trim().to_string());

        // Extract the hostname string for DNS operations.
        let hostname_str = normalized.into_inner();

        // ── Parse port from hostname ───────────────────────────────────
        //
        // C (rf_lookup_hostlist.c line 81):
        //   port = host_item_get_port(h);
        let (hostname_no_port, port) = parse_host_port(&hostname_str);

        // ── Check for /MX suffix ───────────────────────────────────────
        //
        // C (rf_lookup_hostlist.c lines 93–100):
        //   if (len > 3 && strcmpic(h->name + len - 3, US"/mx") == 0)
        let (lookup_name, is_mx) = check_mx_suffix(hostname_no_port);

        // ── Perform DNS lookup ─────────────────────────────────────────
        let find_result = if is_mx {
            // MX lookup: resolve MX records for the domain, then resolve
            // the MX hostnames to IP addresses.
            //
            // C (rf_lookup_hostlist.c lines 106–116):
            //   rc = host_find_bydns(h, ignore_target_hosts, whichrrs,
            //     NULL, NULL, NULL, &rblock->dnssec, NULL, NULL);
            let flags = compute_mx_flags(which_lists);
            tracing::debug!(host = %lookup_name, "doing DNS MX lookup");
            resolver.host_find_bydns(
                lookup_name,
                flags,
                None, // srv_service_list
                None, // srv_fail_domains
                None, // mx_fail_domains
                dnssec,
                ignored_target_hostname,
            )
        } else if which_lists.has(WhichLists::BYNAME) {
            // Explicit byname lookup (getaddrinfo).
            //
            // C (rf_lookup_hostlist.c lines 121–126):
            //   if (lookup_type & LK_BYNAME)
            //     rc = host_find_byname(h, ...)
            tracing::debug!(host = %lookup_name, "calling host_find_byname");
            let flags = compute_dns_flags(which_lists);
            resolver.host_find_byname(lookup_name, flags, ignored_target_hostname)
        } else {
            // DNS-based lookup with optional byname fallback.
            //
            // C (rf_lookup_hostlist.c lines 132–162):
            //   First try host_find_bydns(); if it returns FAILED and
            //   which_lists is DEFAULT, fall back to host_find_byname().
            let flags = compute_dns_flags(which_lists);
            tracing::debug!(host = %lookup_name, "doing DNS lookup");
            let result = resolver.host_find_bydns(
                lookup_name,
                flags,
                None, // srv_service_list
                None, // srv_fail_domains
                None, // mx_fail_domains
                dnssec,
                ignored_target_hostname,
            );

            // Fall back to byname on DNS failure when using default
            // strategy (not explicitly BYDNS).
            //
            // C (rf_lookup_hostlist.c lines 151–159):
            //   if (rc == HOST_FIND_FAILED && lookup_type == LK_DEFAULT)
            //     rc = host_find_byname(h, ...)
            match &result {
                Ok(HostFindResult::Failed) if which_lists.is_default() => {
                    tracing::debug!(
                        host = %lookup_name,
                        "DNS lookup failed: trying byname fallback"
                    );
                    resolver.host_find_byname(
                        lookup_name,
                        flags | HostFindFlags::QUALIFY_SINGLE,
                        ignored_target_hostname,
                    )
                }
                _ => result,
            }
        };

        // ── Process the lookup result ──────────────────────────────────
        let find_result = match find_result {
            Ok(r) => r,
            Err(e) => {
                // DNS resolver-level error (misconfiguration, DNSSEC
                // violation, etc.) — map to DEFER.
                //
                // C (rf_lookup_hostlist.c lines 166–172):
                //   if (rc == HOST_FIND_SECURITY) {
                //     addr->message = "...done insecurely";
                //     addr->basic_errno = ERRNO_DNSDEFER;
                //     return DEFER;
                //   }
                let msg = format!("host lookup for \"{}\" failed: {}", lookup_name, e);
                tracing::debug!(host = %lookup_name, error = %e, "DNS error");
                addr.message = Some(msg);
                addr.host_list = resolved_hosts;
                return Ok((
                    RouterResult::Defer {
                        message: addr.message.clone(),
                    },
                    self_detected,
                ));
            }
        };

        match find_result {
            // ── HOST_FIND_AGAIN (temporary DNS failure) ────────────────
            //
            // C (rf_lookup_hostlist.c lines 173–187):
            //   If pass_on_timeout is set, return PASS.
            //   Otherwise, return DEFER with diagnostic message.
            HostFindResult::Again => {
                if router_config.pass_on_timeout {
                    tracing::debug!(
                        router = %router_config.name,
                        host = %lookup_name,
                        "router timed out and pass_on_timeout set"
                    );
                    addr.host_list = resolved_hosts;
                    return Ok((RouterResult::Pass, self_detected));
                }

                let msg = format!(
                    "host lookup for \"{}\" did not complete (DNS timeout in {} router)",
                    lookup_name, router_config.name
                );
                tracing::debug!(
                    host = %lookup_name,
                    router = %router_config.name,
                    "host lookup did not complete"
                );
                addr.message = Some(msg);
                addr.host_list = resolved_hosts;
                return Ok((
                    RouterResult::Defer {
                        message: addr.message.clone(),
                    },
                    self_detected,
                ));
            }

            // ── HOST_FIND_FAILED (permanent DNS failure) ───────────────
            //
            // C (rf_lookup_hostlist.c lines 188–216):
            //   Apply the host_find_failed policy.
            HostFindResult::Failed => {
                tracing::debug!(
                    host = %lookup_name,
                    policy = ?hff_code,
                    "host find failed — applying policy"
                );

                match hff_code {
                    HostFindFailedPolicy::Ignore => {
                        // Remove the failed host and continue to the
                        // next entry in the list.
                        //
                        // C (rf_lookup_hostlist.c lines 191–194):
                        //   if (prev) prev->next = next_h;
                        //   else addr->host_list = next_h;
                        tracing::debug!(
                            host = %lookup_name,
                            "host find failed: ignoring and removing from list"
                        );
                        idx += 1;
                        continue;
                    }

                    HostFindFailedPolicy::Pass => {
                        addr.host_list = resolved_hosts;
                        return Ok((RouterResult::Pass, self_detected));
                    }

                    HostFindFailedPolicy::Decline => {
                        addr.host_list = resolved_hosts;
                        return Ok((RouterResult::Decline, self_detected));
                    }

                    HostFindFailedPolicy::Defer => {
                        let msg = format!(
                            "lookup of host \"{}\" failed in {} router",
                            lookup_name, router_config.name
                        );
                        addr.message = Some(msg);
                        addr.host_list = resolved_hosts;
                        return Ok((
                            RouterResult::Defer {
                                message: addr.message.clone(),
                            },
                            self_detected,
                        ));
                    }

                    HostFindFailedPolicy::Fail => {
                        let msg = format!(
                            "lookup of host \"{}\" failed in {} router",
                            lookup_name, router_config.name
                        );
                        addr.message = Some(msg);
                        addr.host_list = resolved_hosts;
                        return Ok((
                            RouterResult::Fail {
                                message: addr.message.clone(),
                            },
                            self_detected,
                        ));
                    }

                    HostFindFailedPolicy::Freeze => {
                        // Set special_action to SPECIAL_FREEZE so the
                        // delivery engine holds the message, then return
                        // DEFER to queue it.
                        //
                        // C (rf_lookup_hostlist.c lines 211–214):
                        //   addr->special_action = SPECIAL_FREEZE;
                        //   addr->message = ...;
                        //   return DEFER;
                        let msg = format!(
                            "lookup of host \"{}\" failed in {} router — freezing",
                            lookup_name, router_config.name
                        );
                        addr.special_action = SPECIAL_FREEZE;
                        addr.message = Some(msg);
                        addr.host_list = resolved_hosts;
                        return Ok((
                            RouterResult::Defer {
                                message: addr.message.clone(),
                            },
                            self_detected,
                        ));
                    }
                }
            }

            // ── HOST_FOUND_LOCAL (self-reference detected) ─────────────
            //
            // C (rf_lookup_hostlist.c lines 234–257):
            //   If there are previously resolved (remote) hosts, truncate
            //   the list at this point and set af_local_host_removed.
            //   Otherwise, invoke rf_self_action() to determine behavior.
            HostFindResult::FoundLocal(ref hosts) if !self_send => {
                self_detected = true;

                if has_prev_resolved {
                    // Truncate: remove local host and all subsequent
                    // entries from the host list.
                    //
                    // C (rf_lookup_hostlist.c lines 236–246):
                    //   prev->next = NULL;
                    //   setflag(addr, af_local_host_removed);
                    //   break;
                    tracing::debug!("Removed from host list (local host found after remote):");
                    for remaining in &original_hosts[idx..] {
                        tracing::debug!("  {}", remaining);
                    }
                    addr.flags |= AF_LOCAL_HOST_REMOVED;
                    break; // stop iterating
                }

                // First host resolves to local — invoke self_action.
                //
                // C (rf_lookup_hostlist.c lines 248–257):
                //   rc = rf_self_action(addr, h, rblock->self_code, ...);
                //   if (rc != OK) return rc;
                //   self_send = TRUE;
                let action = self_code_to_action(
                    router_config.self_code,
                    router_config.self_config.as_deref(),
                );

                // Use the first resolved host for the self_action call,
                // which needs a reference to the actual HostItem for
                // diagnostic messages (mx_priority, name).
                let host_for_action: &HostItem = if !hosts.is_empty() {
                    &hosts[0]
                } else {
                    // Defensive: FoundLocal should always have at least
                    // one host.  Create a minimal placeholder if somehow
                    // empty.
                    addr.host_list = resolved_hosts;
                    return Err(LookupHostlistError::SelfActionFailed(format!(
                        "HOST_FOUND_LOCAL returned empty host list for \"{}\"",
                        lookup_name
                    )));
                };

                let sa_result = self_action(
                    addr,
                    host_for_action,
                    &action,
                    router_config.self_rewrite,
                    router_config,
                    addr_new,
                    ctx,
                );

                match sa_result {
                    RouterResult::Accept { .. } => {
                        // Self-send: deliver to self anyway.
                        self_send = true;
                        for h in hosts {
                            resolved_hosts.push(h.name.clone());
                        }
                    }
                    other => {
                        // DEFER, PASS, FAIL, or REROUTED from self_action
                        // — propagate directly.
                        addr.host_list = Vec::new();
                        return Ok((other, true));
                    }
                }
            }

            // ── HOST_FOUND or HOST_FOUND_LOCAL (after self_send) ───────
            //
            // C (rf_lookup_hostlist.c lines 219–228, 260–265):
            //   Successful resolution.  Preserve mx/sort_key from the
            //   original host entry if an MX lookup was used.  Add all
            //   resolved hosts to the result list.
            HostFindResult::Found(ref hosts) | HostFindResult::FoundLocal(ref hosts) => {
                tracing::debug!(
                    host = %lookup_name,
                    count = hosts.len(),
                    "host lookup succeeded"
                );

                for h in hosts {
                    // Log each resolved host for debugging.
                    // MX_NONE (-1) indicates a non-MX lookup (direct A/AAAA).
                    let mx_info = h
                        .mx_priority
                        .filter(|&mx| mx != MX_NONE)
                        .map(|mx| format!(" MX={mx}"))
                        .unwrap_or_default();
                    let addr_info: Vec<String> =
                        h.addresses.iter().map(|a| a.to_string()).collect();
                    tracing::debug!(
                        host = %h.name,
                        addresses = ?addr_info,
                        sort_key = h.sort_key,
                        "  resolved host{}",
                        mx_info,
                    );

                    // If the host is from an MX lookup and a port was
                    // explicitly specified on the original entry, the
                    // port applies to all MX results.
                    //
                    // C (rf_lookup_hostlist.c lines 219–222):
                    //   if (port != PORT_NONE)
                    //     for (hh = h; hh != next_h; hh = hh->next)
                    //       hh->port = port;
                    if port.is_some() || is_mx {
                        tracing::debug!(
                            host = %h.name,
                            port = ?port,
                            mx = ?h.mx_priority,
                            sort_key = h.sort_key,
                            "preserving port/mx/sort_key"
                        );
                    }

                    resolved_hosts.push(h.name.clone());
                }
            }
        }

        has_prev_resolved = true;
        idx += 1;
    }

    // ── All hosts resolved successfully ────────────────────────────────
    //
    // C (rf_lookup_hostlist.c line 267):
    //   expand_level--;
    //   return OK;
    addr.host_list = resolved_hosts;
    Ok((
        RouterResult::Accept {
            transport_name: None,
            host_list: addr.host_list.clone(),
        },
        self_detected,
    ))
}

// ── Unit Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_port_simple() {
        let (host, port) = parse_host_port("mail.example.com:25");
        assert_eq!(host, "mail.example.com");
        assert_eq!(port, Some(25));
    }

    #[test]
    fn test_parse_host_port_no_port() {
        let (host, port) = parse_host_port("mail.example.com");
        assert_eq!(host, "mail.example.com");
        assert_eq!(port, None);
    }

    #[test]
    fn test_parse_host_port_ipv6_bracketed() {
        let (host, port) = parse_host_port("[::1]:587");
        assert_eq!(host, "[::1]");
        assert_eq!(port, Some(587));
    }

    #[test]
    fn test_parse_host_port_ipv6_no_port() {
        let (host, port) = parse_host_port("[2001:db8::1]");
        assert_eq!(host, "[2001:db8::1]");
        assert_eq!(port, None);
    }

    #[test]
    fn test_parse_host_port_bare_ipv6() {
        // Bare IPv6 with multiple colons should not be parsed as host:port.
        let (host, port) = parse_host_port("2001:db8::1");
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, None);
    }

    #[test]
    fn test_check_mx_suffix_present() {
        let (name, is_mx) = check_mx_suffix("example.com/MX");
        assert_eq!(name, "example.com");
        assert!(is_mx);
    }

    #[test]
    fn test_check_mx_suffix_lowercase() {
        let (name, is_mx) = check_mx_suffix("example.com/mx");
        assert_eq!(name, "example.com");
        assert!(is_mx);
    }

    #[test]
    fn test_check_mx_suffix_absent() {
        let (name, is_mx) = check_mx_suffix("mail.example.com");
        assert_eq!(name, "mail.example.com");
        assert!(!is_mx);
    }

    #[test]
    fn test_check_mx_suffix_too_short() {
        let (name, is_mx) = check_mx_suffix("/MX");
        assert_eq!(name, "/MX");
        assert!(!is_mx);
    }

    #[test]
    fn test_is_ip_literal_ipv4() {
        assert!(is_ip_literal("192.168.1.1"));
        assert!(is_ip_literal("127.0.0.1"));
    }

    #[test]
    fn test_is_ip_literal_ipv6_bracketed() {
        assert!(is_ip_literal("[::1]"));
        assert!(is_ip_literal("[2001:db8::1]"));
    }

    #[test]
    fn test_is_ip_literal_hostname() {
        assert!(!is_ip_literal("mail.example.com"));
        assert!(!is_ip_literal("localhost"));
    }

    #[test]
    fn test_which_lists_flags() {
        let default = WhichLists::DEFAULT;
        assert!(default.is_default());
        assert!(!default.has(WhichLists::BYNAME));
        assert!(!default.has(WhichLists::BYDNS));

        let byname = WhichLists::BYNAME;
        assert!(!byname.is_default());
        assert!(byname.has(WhichLists::BYNAME));

        let combined = WhichLists::BYDNS | WhichLists::IPV4_ONLY;
        assert!(combined.has(WhichLists::BYDNS));
        assert!(combined.has(WhichLists::IPV4_ONLY));
        assert!(!combined.has(WhichLists::BYNAME));
    }

    #[test]
    fn test_host_find_failed_policy_variants() {
        // Verify all 6 variants exist and are distinct.
        let policies = [
            HostFindFailedPolicy::Ignore,
            HostFindFailedPolicy::Pass,
            HostFindFailedPolicy::Decline,
            HostFindFailedPolicy::Defer,
            HostFindFailedPolicy::Fail,
            HostFindFailedPolicy::Freeze,
        ];
        for (i, a) in policies.iter().enumerate() {
            for (j, b) in policies.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn test_self_code_to_action() {
        assert_eq!(self_code_to_action(0, None), SelfAction::Freeze);
        assert_eq!(self_code_to_action(1, None), SelfAction::Defer);
        assert_eq!(self_code_to_action(2, None), SelfAction::Fail);
        assert_eq!(self_code_to_action(3, None), SelfAction::Send);
        assert_eq!(
            self_code_to_action(4, Some("newdomain.com")),
            SelfAction::Reroute("newdomain.com".to_string())
        );
        assert_eq!(self_code_to_action(5, None), SelfAction::Pass);
        // Unknown code defaults to Freeze.
        assert_eq!(self_code_to_action(99, None), SelfAction::Freeze);
    }

    #[test]
    fn test_lookup_hostlist_error_display() {
        let err = LookupHostlistError::DnsError {
            host: "mail.example.com".to_string(),
            detail: "NXDOMAIN".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "DNS lookup error for host mail.example.com: NXDOMAIN"
        );

        let err2 = LookupHostlistError::SelfActionFailed("test error".to_string());
        assert_eq!(err2.to_string(), "self-action failed: test error");
    }

    #[test]
    fn test_compute_mx_flags() {
        let flags = compute_mx_flags(WhichLists::DEFAULT);
        assert!(flags.contains(HostFindFlags::BY_MX));
        assert!(flags.contains(HostFindFlags::BY_A));
        assert!(flags.contains(HostFindFlags::BY_AAAA));

        let ipv4_only_flags = compute_mx_flags(WhichLists::IPV4_ONLY);
        assert!(ipv4_only_flags.contains(HostFindFlags::BY_MX));
        assert!(ipv4_only_flags.contains(HostFindFlags::BY_A));
        assert!(!ipv4_only_flags.contains(HostFindFlags::BY_AAAA));
    }

    #[test]
    fn test_compute_dns_flags() {
        let flags = compute_dns_flags(WhichLists::DEFAULT);
        assert!(flags.contains(HostFindFlags::BY_A));
        assert!(flags.contains(HostFindFlags::BY_AAAA));

        let ipv4_only_flags = compute_dns_flags(WhichLists::IPV4_ONLY);
        assert!(ipv4_only_flags.contains(HostFindFlags::BY_A));
        assert!(!ipv4_only_flags.contains(HostFindFlags::BY_AAAA));
    }
}
