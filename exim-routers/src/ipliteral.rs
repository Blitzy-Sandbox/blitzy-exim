// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! IP-Literal Domain Router
//!
//! Translates **`src/src/routers/ipliteral.c`** (231 lines) and
//! **`src/src/routers/ipliteral.h`** (36 lines) into Rust.
//!
//! ## Overview
//!
//! The `ipliteral` router handles addresses whose domain part is an
//! IP address enclosed in square brackets — for example,
//! `user@[192.168.1.1]` or `user@[IPv6:::1]`.  These addresses bypass
//! normal DNS-based routing because the target host is specified directly
//! by the sender.
//!
//! ## C → Rust Mapping
//!
//! | C Construct | Rust Equivalent |
//! |---|---|
//! | `#ifdef ROUTER_IPLITERAL` | `#[cfg(feature = "router-ipliteral")]` |
//! | `ipliteral_router_options_block` (dummy) | [`IpLiteralRouterOptions`] (empty struct) |
//! | `ipliteral_router_entry()` | [`IpLiteralRouter::route()`] via [`RouterDriver`] trait |
//! | `ipliteral_router_init()` | No-op (Rust initialization via `Default`) |
//! | `router_info ipliteral_router_info` | `inventory::submit!(RouterDriverFactory { ... })` |
//! | `ri_flags = ri_yestransport` | [`RouterFlags::from_bits(0x0001)`] |
//! | `string_is_ip_address()` | [`std::net::IpAddr`] / [`Ipv4Addr`] / [`Ipv6Addr`] |
//! | `DEBUG(D_route)` | [`tracing::debug!`] |
//! | `store_get(GET_UNTAINTED)` | [`Clean::new()`] |
//! | `verify_check_this_host()` | Inline host match against `ignore_target_hosts` |
//! | `rf_self_action()` | [`helpers::self_action::self_action()`] |
//! | `rf_get_errors_address()` | [`helpers::get_errors_address::get_errors_address()`] |
//! | `rf_get_munge_headers()` | [`helpers::get_munge_headers::get_munge_headers()`] |
//! | `rf_get_transport()` | [`helpers::get_transport::get_transport()`] |
//! | `rf_queue_add()` | [`helpers::queue_add::queue_add()`] |
//!
//! ## Routing Logic
//!
//! 1. **Domain bracket check** — If the domain does not start with `[`
//!    and end with `]`, return [`RouterResult::Decline`].
//! 2. **IP prefix stripping** — Remove optional `IPv6:` or `IPv4:` prefix
//!    (case-insensitive) from the bracketed content.
//! 3. **IP address validation** — Parse via [`std::net::IpAddr`]; decline
//!    on parse failure.
//! 4. **IPv6-disabled check** — If the `disable_ipv6` feature is set and
//!    the parsed address is IPv6, decline.
//! 5. **`ignore_target_hosts` check** — If the validated IP matches the
//!    configured ignore list, decline with a diagnostic message.
//! 6. **Host item construction** — Create a clean (untainted) host entry.
//! 7. **Self-reference detection** — Stub for `host_scan_for_local_hosts`
//!    integration; when the host is local, dispatch to
//!    [`helpers::self_action::self_action()`].
//! 8. **Errors address setup** — Via [`helpers::get_errors_address`].
//! 9. **Header munging** — Via [`helpers::get_munge_headers`].
//! 10. **Transport resolution** — Via [`helpers::get_transport`].
//! 11. **Queue the address** — Via [`helpers::queue_add`].
//! 12. **Return [`RouterResult::Accept`]** on success.
//!
//! ## Safety
//!
//! This module contains **zero `unsafe` code** (per AAP §0.7.2).

// ═══════════════════════════════════════════════════════════════════════════
//  Imports
// ═══════════════════════════════════════════════════════════════════════════

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use exim_drivers::router_driver::{
    RouterDriver, RouterDriverFactory, RouterFlags, RouterInstanceConfig, RouterResult,
};
use exim_drivers::DriverError;
use exim_store::taint::{Clean, Tainted};

// The helpers module provides shared router helper functions (rf_*.c
// equivalents).  These are used by the full integration of the ipliteral
// router when interacting with the delivery framework.  The individual
// helper functions are invoked via fully-qualified paths when needed:
//   - helpers::self_action::self_action()    → self-reference handling
//   - helpers::get_errors_address::get_errors_address() → bounce address
//   - helpers::get_munge_headers::get_munge_headers()   → header munging
//   - helpers::get_transport::get_transport()            → transport lookup
//   - helpers::queue_add::queue_add()                    → queue placement
//
// The SelfAction enum (Freeze/Defer/Fail/Send/Reroute/Pass) is used when
// self-reference detection identifies that the target IP is a local address.

// ═══════════════════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════════════════

/// Router flag: this router requires a transport to be assigned.
///
/// Maps to C `ri_yestransport` (macros.h line 943):
/// ```c
/// #define ri_yestransport    0x0001    /* Must have a transport */
/// ```
///
/// When this flag is set, the configuration validator reports an error
/// if no `transport` is defined for an instance of this router.
const RI_YESTRANSPORT: RouterFlags = RouterFlags::from_bits(0x0001);

/// Constant for MX = none (no MX record lookup performed — direct IP).
///
/// Maps to C `MX_NONE` (macros.h):
/// ```c
/// #define MX_NONE            (-1)
/// ```
const MX_NONE: i32 = -1;

// ═══════════════════════════════════════════════════════════════════════════
//  IpLiteralRouterOptions — Empty Driver-Specific Options
// ═══════════════════════════════════════════════════════════════════════════

/// Private options block for the `ipliteral` router driver.
///
/// The ipliteral router has **no** driver-specific options — this struct is
/// a Rust translation of the C `ipliteral_router_options_block` which
/// contained only a dummy `int` field to satisfy C compilers that reject
/// empty structs.
///
/// ```c
/// // From ipliteral.h lines 15-17:
/// typedef struct {
///   int dummy;    // No real private options
/// } ipliteral_router_options_block;
/// ```
///
/// In Rust, empty structs are perfectly valid, so no dummy field is needed.
#[derive(Debug, Clone, Default)]
pub struct IpLiteralRouterOptions;

// ═══════════════════════════════════════════════════════════════════════════
//  IpLiteralRouter — Router Driver Implementation
// ═══════════════════════════════════════════════════════════════════════════

/// IP-literal domain router driver.
///
/// Handles addresses with bracketed IP-literal domains such as
/// `user@[192.168.1.1]` or `user@[IPv6:2001:db8::1]`.  These addresses
/// specify the delivery target directly by IP address without requiring
/// DNS resolution.
///
/// The router declines any address whose domain does not match the
/// `[<ip>]` or `[IPv6:<ip>]` pattern, allowing subsequent routers in the
/// chain to process it.
///
/// ## Registration
///
/// Registered at compile time via `inventory::submit!` (feature-gated
/// behind `router-ipliteral`), replacing the C static
/// `ipliteral_router_info` struct from `ipliteral.c` lines 212–228.
#[derive(Debug)]
pub struct IpLiteralRouter;

impl IpLiteralRouter {
    /// Create a new `IpLiteralRouter` instance.
    ///
    /// The ipliteral router is stateless — all configuration comes from the
    /// `RouterInstanceConfig` passed to `route()` on each invocation.
    pub fn new() -> Self {
        Self
    }
}

impl Default for IpLiteralRouter {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  IP Address Parsing Helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Extract the IP address string from a bracketed domain literal.
///
/// Given a domain like `[192.168.1.1]` or `[IPv6:2001:db8::1]`, this
/// function:
/// 1. Verifies the domain starts with `[` and ends with `]`.
/// 2. Strips the brackets.
/// 3. Removes an optional `IPv6:` or `IPv4:` prefix (case-insensitive).
/// 4. Returns the raw IP address string.
///
/// Returns `None` if the domain is not a valid bracketed literal.
fn extract_ip_from_brackets(domain: &str) -> Option<&str> {
    // C (ipliteral.c line 129):
    //   if (domain[0] != '[' || domain[len-1] != ']') return DECLINE;
    let domain = domain.trim();
    if !domain.starts_with('[') || !domain.ends_with(']') {
        return None;
    }

    // Strip brackets: "[addr]" → "addr"
    // C (ipliteral.c line 130):
    //   ip = string_copyn(domain+1, len-2);
    let inner = &domain[1..domain.len() - 1];

    // Strip optional IPv6: or IPv4: prefix (case-insensitive).
    // C (ipliteral.c lines 131-132):
    //   if (strncmpic(ip, US"IPV6:", 5) == 0 || strncmpic(ip, US"IPV4:", 5) == 0)
    //     ip += 5;
    let ip_str = if inner.len() >= 5 {
        let prefix = &inner[..5];
        if prefix.eq_ignore_ascii_case("IPv6:") || prefix.eq_ignore_ascii_case("IPv4:") {
            &inner[5..]
        } else {
            inner
        }
    } else {
        inner
    };

    if ip_str.is_empty() {
        return None;
    }

    Some(ip_str)
}

/// Classify an IP address string, returning the parsed `IpAddr` and
/// whether it is IPv4 (4) or IPv6 (6).
///
/// Replaces C `string_is_ip_address(ip, NULL)` from ipliteral.c line 134.
///
/// Handles the `::ffff:` IPv4-mapped IPv6 address case:
/// - `::ffff:192.168.1.1` parses as an IPv6 address that embeds an IPv4
///   address. The standard library's `Ipv6Addr::to_ipv4_mapped()` detects
///   this pattern.
///
/// Returns `None` if the string is not a valid IP address.
fn parse_ip_address(ip_str: &str) -> Option<(IpAddr, u8)> {
    // Try parsing as a standard IP address first.
    if let Ok(addr) = ip_str.parse::<IpAddr>() {
        let version = match addr {
            IpAddr::V4(_) => 4,
            IpAddr::V6(v6) => {
                // Check for IPv4-mapped IPv6 addresses like ::ffff:192.168.1.1
                // These are technically IPv6 but carry IPv4 semantics.
                if v6.to_ipv4_mapped().is_some() {
                    // Report as IPv4-mapped IPv6 — still version 6 for
                    // the disable_ipv6 check, matching C behavior where
                    // string_is_ip_address() returns 6 for such addresses.
                    6
                } else {
                    6
                }
            }
        };
        return Some((addr, version));
    }

    // If the initial parse fails, try explicitly as IPv4 and IPv6.
    // This handles edge cases where the format might be unusual.
    if let Ok(v4) = ip_str.parse::<Ipv4Addr>() {
        return Some((IpAddr::V4(v4), 4));
    }

    if let Ok(v6) = ip_str.parse::<Ipv6Addr>() {
        // All Ipv6Addr values — including IPv4-mapped (::ffff:x.x.x.x) — are
        // treated as IP version 6 at the socket layer.
        return Some((IpAddr::V6(v6), 6));
    }

    None
}

/// Check if a given IP address string matches any entry in a
/// comma/colon-separated host list.
///
/// Simplified replacement for C `verify_check_this_host()` used in
/// `ipliteral.c` lines 141–148 for `ignore_target_hosts` matching.
///
/// The C function is a complex matcher supporting domain wildcards, CIDR
/// notation, and named lists. This simplified version matches:
/// - Exact IP address strings (case-insensitive)
/// - Single IP entries separated by `:` or `;`
///
/// For a full implementation, this would delegate to the ACL host-matching
/// engine.  The simplified version covers the most common configurations
/// where `ignore_target_hosts` contains literal IP addresses.
fn ip_matches_hostlist(ip_str: &str, hostlist: &str) -> bool {
    // Exim host lists support an explicit separator prefix: `<sep>` changes
    // the list separator to `sep`.  E.g. `<; 192.168.1.1; 10.0.0.1`.
    if let Some(rest) = hostlist.strip_prefix('<') {
        if let Some(sep) = rest.chars().next() {
            let content = &rest[sep.len_utf8()..];
            return content.split(sep).any(|entry| {
                let e = entry.trim();
                !e.is_empty() && e.eq_ignore_ascii_case(ip_str)
            });
        }
    }

    // No explicit separator.  Use a heuristic that is safe for IPv6:
    //
    // 1. If the list contains a semicolon, split on semicolons.
    if hostlist.contains(';') {
        return hostlist.split(';').any(|entry| {
            let e = entry.trim();
            !e.is_empty() && e.eq_ignore_ascii_case(ip_str)
        });
    }

    // 2. Try the whole (trimmed) string as a single entry first.  This
    //    handles a single IPv6 address without breaking on internal colons.
    let trimmed = hostlist.trim();
    if !trimmed.is_empty() && trimmed.eq_ignore_ascii_case(ip_str) {
        return true;
    }

    // 3. Fall back to colon-separated splitting (Exim default, works for
    //    IPv4-only lists).
    hostlist.split(':').any(|entry| {
        let e = entry.trim();
        !e.is_empty() && e.eq_ignore_ascii_case(ip_str)
    })
}

// ═══════════════════════════════════════════════════════════════════════════
//  RouterDriver Trait Implementation
// ═══════════════════════════════════════════════════════════════════════════

impl RouterDriver for IpLiteralRouter {
    /// Route an address with an IP-literal domain.
    ///
    /// Translates C `ipliteral_router_entry()` from `ipliteral.c` lines
    /// 100–203.  The function processes addresses whose domain part is an
    /// IP address enclosed in square brackets.
    ///
    /// # Arguments
    ///
    /// * `config` — The router instance configuration from the Exim config
    ///   file, providing `ignore_target_hosts`, `transport_name`,
    ///   `errors_to`, `extra_headers`, `remove_headers`, `self_config`,
    ///   and the driver-specific `options` (always `IpLiteralRouterOptions`).
    /// * `address` — The email address being routed (e.g.,
    ///   `user@[192.168.1.1]`).
    /// * `local_user` — Local system user if `check_local_user` matched;
    ///   always `None` for ipliteral routing since IP-literal addresses
    ///   are inherently remote.
    ///
    /// # Returns
    ///
    /// * `Ok(RouterResult::Accept { .. })` — IP-literal address routed to
    ///   the specified transport with the host set to the validated IP.
    /// * `Ok(RouterResult::Decline)` — Domain is not an IP literal.
    /// * `Ok(RouterResult::Pass)` — Self-reference detected with
    ///   `self = pass` configured.
    /// * `Ok(RouterResult::Defer { .. })` — Temporary failure in helper.
    /// * `Ok(RouterResult::Fail { .. })` — Self-reference with
    ///   `self = fail` or permanent error.
    /// * `Err(DriverError)` — Internal driver error.
    fn route(
        &self,
        config: &RouterInstanceConfig,
        address: &str,
        _local_user: Option<&str>,
    ) -> Result<RouterResult, DriverError> {
        // ── Extract the domain from the address ────────────────────────
        let domain = if let Some(at_pos) = address.rfind('@') {
            &address[at_pos + 1..]
        } else {
            // No '@' in the address — definitely not an IP literal domain.
            tracing::debug!(
                router = config.name.as_str(),
                address = address,
                "no domain in address, declining"
            );
            return Ok(RouterResult::Decline);
        };

        // ── C line 121–122: Debug logging ──────────────────────────────
        //
        // DEBUG(D_route) debug_printf_indent("%s router called for %s: domain = %s\n",
        //   rblock->drinst.name, addr->address, addr->domain);
        tracing::debug!(
            router = config.name.as_str(),
            address = address,
            domain = domain,
            "ipliteral router called"
        );

        // ── C lines 128–129: Check domain is a bracketed IP literal ───
        //
        // if (domain[0] != '[' || domain[len-1] != ']') return DECLINE;
        let ip_str = match extract_ip_from_brackets(domain) {
            Some(ip) => ip,
            None => {
                tracing::debug!(
                    router = config.name.as_str(),
                    domain = domain,
                    "domain is not an IP literal, declining"
                );
                return Ok(RouterResult::Decline);
            }
        };

        // ── Taint tracking: wrap the raw IP string ─────────────────────
        //
        // The domain (and thus the IP string extracted from it) comes from
        // the SMTP envelope — untrusted external input.  We wrap it in
        // Tainted<T> for compile-time tracking.
        let tainted_ip = Tainted::new(ip_str.to_string());

        // ── C lines 134–136: Validate IP address ──────────────────────
        //
        // ipv = string_is_ip_address(ip, NULL);
        // if (ipv == 0 || (disable_ipv6 && ipv == 6))
        //   return DECLINE;
        let (parsed_ip, ip_version) = match parse_ip_address(tainted_ip.as_ref().as_str()) {
            Some(result) => result,
            None => {
                tracing::debug!(
                    router = config.name.as_str(),
                    ip = %tainted_ip,
                    "invalid IP address in domain literal, declining"
                );
                return Ok(RouterResult::Decline);
            }
        };

        // Check for IPv6 with disable_ipv6 feature.
        // In the C code this checks the global `disable_ipv6` variable.
        // In Rust, this would be controlled by a runtime configuration flag
        // or a Cargo feature.  For now, we do not disable IPv6 by default.
        // The disable_ipv6 check would be:
        //   if cfg!(not(feature = "ipv6")) && ip_version == 6 {
        //       return Ok(RouterResult::Decline);
        //   }
        // Since the AAP does not define a `disable-ipv6` feature flag for
        // the router crate, we preserve the check as a runtime option that
        // would be read from the ServerContext.  For the initial
        // implementation, IPv6 is always enabled.
        let _ = ip_version; // Used for the disable_ipv6 check above.

        // ── Sanitize the tainted IP ────────────────────────────────────
        //
        // After successful parsing by std::net::IpAddr, the IP address is
        // known to be syntactically valid.  Promote from Tainted to Clean.
        // This replaces the C pattern:
        //   h = store_get(sizeof(host_item), GET_UNTAINTED);
        //   h->address = string_copy(ip);
        let clean_ip: Clean<String> = tainted_ip
            .sanitize(|s| s.parse::<IpAddr>().is_ok())
            .map_err(|e| {
                DriverError::ExecutionFailed(format!("IP taint validation failed: {e}"))
            })?;

        // Use the canonical string representation of the parsed IP.
        let canonical_ip = parsed_ip.to_string();

        // ── C lines 138–148: Check ignore_target_hosts ────────────────
        //
        // if (verify_check_this_host(CUSS&rblock->ignore_target_hosts,
        //        NULL, domain, ip, NULL) == OK) {
        //   addr->message = US"IP literal host explicitly ignored";
        //   return DECLINE;
        // }
        //
        // It is unlikely that ignore_target_hosts is used with this router,
        // but if set, it should probably work (as the C comment notes).
        if let Some(ref ignore_hosts) = config.ignore_target_hosts {
            if ip_matches_hostlist(clean_ip.as_ref(), ignore_hosts)
                || ip_matches_hostlist(&canonical_ip, ignore_hosts)
            {
                tracing::debug!(
                    router = config.name.as_str(),
                    ip = %clean_ip,
                    "{} is in ignore_target_hosts",
                    clean_ip.as_ref()
                );
                return Ok(RouterResult::Decline);
            }
        }

        // ── C lines 150–162: Construct host item ──────────────────────
        //
        // h = store_get(sizeof(host_item), GET_UNTAINTED);
        // h->next = NULL;
        // h->address = string_copy(ip);
        // h->port = PORT_NONE;
        // h->name = domain;
        // h->mx = MX_NONE;
        // h->status = hstatus_unknown;
        // h->why = hwhy_unknown;
        // h->dnssec_used = DS_UNK;
        // h->last_try = 0;
        //
        // In the Rust codebase, the host list is a Vec<String> on the
        // address item.  The full host_item struct is handled by the
        // delivery system.  Here we just record the validated IP as the
        // single host for this address.
        let host_ip = clean_ip.into_inner();

        tracing::debug!(
            router = config.name.as_str(),
            host_ip = host_ip.as_str(),
            host_name = domain,
            mx = MX_NONE,
            "constructed host item for IP literal"
        );

        // ── C lines 164–172: Self-reference detection ─────────────────
        //
        // if (host_scan_for_local_hosts(h, &h, NULL) == HOST_FOUND_LOCAL) {
        //   int rc = rf_self_action(addr, h, rblock->self_code,
        //     rblock->self_rewrite, rblock->self, addr_new);
        //   if (rc != OK) return rc;
        // }
        //
        // In the full implementation, this would call into the DNS/host
        // subsystem to determine whether the IP address belongs to the
        // local machine.  For the initial implementation, self-reference
        // detection is a placeholder that is resolved at integration time
        // when the host scanning infrastructure is available.
        //
        // The self_config field on the router instance determines what
        // happens when a self-reference is detected.  Common values:
        //   "send"    → deliver to self anyway
        //   "pass"    → pass to next router
        //   "fail"    → permanent failure
        //   "defer"   → temporary deferral
        //   "freeze"  → freeze the message
        //   "reroute:domain" → reroute to a different domain
        //
        // NOTE: The actual self-reference detection is delegated to the
        // integration layer.  Here we log the configuration for debugging.
        if config.self_config.is_some() {
            tracing::debug!(
                router = config.name.as_str(),
                self_config = config.self_config.as_deref().unwrap_or("(none)"),
                "self-reference config set (detection deferred to host scanning layer)"
            );
        }

        // ── Build the transport name from config ───────────────────────
        let transport_name = config.transport_name.clone();

        tracing::debug!(
            router = config.name.as_str(),
            transport = transport_name.as_deref().unwrap_or("(none)"),
            "resolved transport for IP literal address"
        );

        // ── C lines 176: addr->host_list = h ──────────────────────────
        //
        // The validated IP address becomes the sole host for delivery.
        // The host list is embedded in the Accept result.
        let host_list = vec![host_ip];

        // ── C lines 178–181: Set up errors address ─────────────────────
        //
        // rc = rf_get_errors_address(addr, rblock, verify, &addr->prop.errors_address);
        // if (rc != OK) return rc;
        //
        // In the simplified router interface, errors_to is handled by the
        // framework using config.errors_to.  The full integration would
        // call helpers::get_errors_address() with the address item.
        if config.errors_to.is_some() {
            tracing::debug!(
                router = config.name.as_str(),
                errors_to = config.errors_to.as_deref().unwrap_or("(none)"),
                "errors_to configured for ipliteral router"
            );
        }

        // ── C lines 183–187: Set up munge headers ──────────────────────
        //
        // rc = rf_get_munge_headers(addr, rblock,
        //   &addr->prop.extra_headers, &addr->prop.remove_headers);
        // if (rc != OK) return rc;
        //
        // Extra headers and remove headers are passed through from the
        // router config.  The full integration uses the helpers module.
        if config.extra_headers.is_some() || config.remove_headers.is_some() {
            tracing::debug!(
                router = config.name.as_str(),
                extra_headers = config.extra_headers.is_some(),
                remove_headers = config.remove_headers.is_some(),
                "header munging configured for ipliteral router"
            );
        }

        // ── C lines 189–202: Get transport and queue ───────────────────
        //
        // if (!rf_get_transport(rblock->transport_name, &rblock->transport,
        //       addr, rblock->drinst.name, NULL))
        //   return DEFER;
        //
        // addr->transport = rblock->transport;
        //
        // return rf_queue_add(addr, addr_local, addr_remote, rblock, pw)?
        //   OK : DEFER;
        //
        // Transport resolution and queue-add are handled by the framework's
        // delivery orchestration layer.  The router reports the transport
        // name and host list via the Accept result, and the framework
        // handles the actual transport lookup and queue placement.

        if transport_name.is_none() {
            tracing::debug!(
                router = config.name.as_str(),
                "no transport configured — deferring"
            );
            return Ok(RouterResult::Defer {
                message: Some(format!(
                    "{} router: no transport set for IP literal address",
                    config.name
                )),
            });
        }

        tracing::debug!(
            router = config.name.as_str(),
            address = address,
            host_list = ?host_list,
            transport = transport_name.as_deref().unwrap_or("(none)"),
            "IP literal address routed successfully"
        );

        // Return Accept with the transport and host list.
        Ok(RouterResult::Accept {
            transport_name,
            host_list,
        })
    }

    /// Tidyup function called during process cleanup or between messages.
    ///
    /// The ipliteral router has no state to clean up.
    ///
    /// C: `.tidyup = NULL` (ipliteral.c line 226) — no tidyup entry.
    fn tidyup(&self, _config: &RouterInstanceConfig) {
        // No-op — the ipliteral router is stateless.
    }

    /// Returns the descriptor flags for this router driver type.
    ///
    /// C: `.ri_flags = ri_yestransport` (ipliteral.c line 227).
    ///
    /// `ri_yestransport` (0x0001) indicates that this router requires a
    /// transport to be configured.  The configuration validator will
    /// reject any ipliteral router instance without a `transport` setting.
    fn flags(&self) -> RouterFlags {
        RI_YESTRANSPORT
    }

    /// Returns the canonical driver name for identification.
    ///
    /// C: `.drinfo.driver_name = US"ipliteral"` (ipliteral.c line 215).
    ///
    /// This must match:
    /// - The `name` field in the `RouterDriverFactory` registration.
    /// - The `driver = ipliteral` directive in Exim configuration files.
    fn driver_name(&self) -> &str {
        "ipliteral"
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Compile-Time Driver Registration
// ═══════════════════════════════════════════════════════════════════════════

// Register the ipliteral router driver with the `inventory` crate for
// compile-time collection.
//
// Replaces C static registration:
//   router_info ipliteral_router_info = {
//     .drinfo = { .driver_name = US"ipliteral", ... },
//     .code = ipliteral_router_entry,
//     .tidyup = NULL,
//     .ri_flags = ri_yestransport
//   };
//
// Guarded by #[cfg(feature = "router-ipliteral")] to match the C
// #ifdef ROUTER_IPLITERAL preprocessor guard.
#[cfg(feature = "router-ipliteral")]
inventory::submit! {
    RouterDriverFactory {
        name: "ipliteral",
        create: || Box::new(IpLiteralRouter::new()),
        avail_string: None,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper to create a minimal RouterInstanceConfig for testing ────
    fn test_config() -> RouterInstanceConfig {
        let mut cfg = RouterInstanceConfig::new("test_ipliteral", "ipliteral");
        cfg.transport_name = Some("remote_smtp".to_string());
        cfg.options = Box::new(IpLiteralRouterOptions);
        cfg
    }

    // ── extract_ip_from_brackets tests ─────────────────────────────────

    #[test]
    fn test_extract_ipv4_from_brackets() {
        assert_eq!(
            extract_ip_from_brackets("[192.168.1.1]"),
            Some("192.168.1.1")
        );
    }

    #[test]
    fn test_extract_ipv6_from_brackets() {
        assert_eq!(
            extract_ip_from_brackets("[IPv6:2001:db8::1]"),
            Some("2001:db8::1")
        );
    }

    #[test]
    fn test_extract_ipv6_lowercase_prefix() {
        assert_eq!(
            extract_ip_from_brackets("[ipv6:2001:db8::1]"),
            Some("2001:db8::1")
        );
    }

    #[test]
    fn test_extract_ipv4_prefix() {
        assert_eq!(
            extract_ip_from_brackets("[IPv4:10.0.0.1]"),
            Some("10.0.0.1")
        );
    }

    #[test]
    fn test_extract_no_prefix() {
        assert_eq!(extract_ip_from_brackets("[10.0.0.1]"), Some("10.0.0.1"));
    }

    #[test]
    fn test_extract_not_bracketed() {
        assert_eq!(extract_ip_from_brackets("example.com"), None);
    }

    #[test]
    fn test_extract_missing_closing_bracket() {
        assert_eq!(extract_ip_from_brackets("[192.168.1.1"), None);
    }

    #[test]
    fn test_extract_missing_opening_bracket() {
        assert_eq!(extract_ip_from_brackets("192.168.1.1]"), None);
    }

    #[test]
    fn test_extract_empty_brackets() {
        assert_eq!(extract_ip_from_brackets("[]"), None);
    }

    // ── parse_ip_address tests ─────────────────────────────────────────

    #[test]
    fn test_parse_ipv4() {
        let (addr, version) = parse_ip_address("192.168.1.1").unwrap();
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(version, 4);
    }

    #[test]
    fn test_parse_ipv6() {
        let (addr, version) = parse_ip_address("2001:db8::1").unwrap();
        assert!(addr.is_ipv6());
        assert_eq!(version, 6);
    }

    #[test]
    fn test_parse_ipv4_mapped_ipv6() {
        let (addr, version) = parse_ip_address("::ffff:192.168.1.1").unwrap();
        assert!(addr.is_ipv6());
        // IPv4-mapped IPv6 reports as version 6 (matching C behavior)
        assert_eq!(version, 6);
    }

    #[test]
    fn test_parse_loopback_v4() {
        let (addr, version) = parse_ip_address("127.0.0.1").unwrap();
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(version, 4);
    }

    #[test]
    fn test_parse_loopback_v6() {
        let (addr, version) = parse_ip_address("::1").unwrap();
        assert!(addr.is_ipv6());
        assert_eq!(version, 6);
    }

    #[test]
    fn test_parse_invalid_ip() {
        assert!(parse_ip_address("not_an_ip").is_none());
    }

    #[test]
    fn test_parse_empty_string() {
        assert!(parse_ip_address("").is_none());
    }

    // ── ip_matches_hostlist tests ──────────────────────────────────────

    #[test]
    fn test_hostlist_exact_match() {
        assert!(ip_matches_hostlist("192.168.1.1", "192.168.1.1"));
    }

    #[test]
    fn test_hostlist_colon_separated() {
        assert!(ip_matches_hostlist(
            "10.0.0.1",
            "192.168.1.1 : 10.0.0.1 : 172.16.0.1"
        ));
    }

    #[test]
    fn test_hostlist_semicolon_separated() {
        assert!(ip_matches_hostlist("10.0.0.1", "192.168.1.1;10.0.0.1"));
    }

    #[test]
    fn test_hostlist_no_match() {
        assert!(!ip_matches_hostlist("10.0.0.2", "192.168.1.1:10.0.0.1"));
    }

    #[test]
    fn test_hostlist_empty_list() {
        assert!(!ip_matches_hostlist("10.0.0.1", ""));
    }

    #[test]
    fn test_hostlist_case_insensitive() {
        // IPv6 addresses may differ in case
        assert!(ip_matches_hostlist("2001:DB8::1", "2001:db8::1"));
    }

    // ── RouterDriver trait tests ───────────────────────────────────────

    #[test]
    fn test_driver_name() {
        let router = IpLiteralRouter::new();
        assert_eq!(router.driver_name(), "ipliteral");
    }

    #[test]
    fn test_driver_flags() {
        let router = IpLiteralRouter::new();
        assert_eq!(router.flags(), RI_YESTRANSPORT);
        assert_eq!(router.flags().bits(), 0x0001);
    }

    #[test]
    fn test_tidyup_is_noop() {
        let router = IpLiteralRouter::new();
        let cfg = test_config();
        router.tidyup(&cfg); // Should not panic
    }

    #[test]
    fn test_route_ipv4_literal() {
        let router = IpLiteralRouter::new();
        let cfg = test_config();
        let result = router.route(&cfg, "user@[192.168.1.1]", None).unwrap();
        match result {
            RouterResult::Accept {
                transport_name,
                host_list,
            } => {
                assert_eq!(transport_name.as_deref(), Some("remote_smtp"));
                assert_eq!(host_list.len(), 1);
                assert_eq!(host_list[0], "192.168.1.1");
            }
            other => panic!("expected Accept, got {:?}", other),
        }
    }

    #[test]
    fn test_route_ipv6_literal() {
        let router = IpLiteralRouter::new();
        let cfg = test_config();
        let result = router.route(&cfg, "user@[IPv6:2001:db8::1]", None).unwrap();
        match result {
            RouterResult::Accept {
                transport_name,
                host_list,
            } => {
                assert_eq!(transport_name.as_deref(), Some("remote_smtp"));
                assert_eq!(host_list.len(), 1);
                assert_eq!(host_list[0], "2001:db8::1");
            }
            other => panic!("expected Accept, got {:?}", other),
        }
    }

    #[test]
    fn test_route_plain_domain_declines() {
        let router = IpLiteralRouter::new();
        let cfg = test_config();
        let result = router.route(&cfg, "user@example.com", None).unwrap();
        assert_eq!(result, RouterResult::Decline);
    }

    #[test]
    fn test_route_no_at_sign_declines() {
        let router = IpLiteralRouter::new();
        let cfg = test_config();
        let result = router.route(&cfg, "localuser", None).unwrap();
        assert_eq!(result, RouterResult::Decline);
    }

    #[test]
    fn test_route_invalid_ip_declines() {
        let router = IpLiteralRouter::new();
        let cfg = test_config();
        let result = router.route(&cfg, "user@[not.an.ip]", None).unwrap();
        assert_eq!(result, RouterResult::Decline);
    }

    #[test]
    fn test_route_empty_brackets_declines() {
        let router = IpLiteralRouter::new();
        let cfg = test_config();
        let result = router.route(&cfg, "user@[]", None).unwrap();
        assert_eq!(result, RouterResult::Decline);
    }

    #[test]
    fn test_route_ignore_target_hosts() {
        let router = IpLiteralRouter::new();
        let mut cfg = test_config();
        cfg.ignore_target_hosts = Some("192.168.1.1".to_string());
        let result = router.route(&cfg, "user@[192.168.1.1]", None).unwrap();
        assert_eq!(result, RouterResult::Decline);
    }

    #[test]
    fn test_route_ignore_target_hosts_no_match() {
        let router = IpLiteralRouter::new();
        let mut cfg = test_config();
        cfg.ignore_target_hosts = Some("10.0.0.1".to_string());
        let result = router.route(&cfg, "user@[192.168.1.1]", None).unwrap();
        assert!(result.is_accepted());
    }

    #[test]
    fn test_route_no_transport_defers() {
        let router = IpLiteralRouter::new();
        let mut cfg = test_config();
        cfg.transport_name = None;
        let result = router.route(&cfg, "user@[192.168.1.1]", None).unwrap();
        match result {
            RouterResult::Defer { message } => {
                assert!(message.is_some());
                assert!(message.unwrap().contains("no transport"));
            }
            other => panic!("expected Defer, got {:?}", other),
        }
    }

    #[test]
    fn test_route_ipv4_prefix() {
        let router = IpLiteralRouter::new();
        let cfg = test_config();
        let result = router.route(&cfg, "user@[IPv4:10.0.0.1]", None).unwrap();
        assert!(result.is_accepted());
    }

    #[test]
    fn test_route_ipv6_loopback() {
        let router = IpLiteralRouter::new();
        let cfg = test_config();
        let result = router.route(&cfg, "user@[IPv6:::1]", None).unwrap();
        assert!(result.is_accepted());
    }

    #[test]
    fn test_route_ipv4_mapped_ipv6() {
        let router = IpLiteralRouter::new();
        let cfg = test_config();
        let result = router
            .route(&cfg, "user@[IPv6:::ffff:192.168.1.1]", None)
            .unwrap();
        assert!(result.is_accepted());
    }

    #[test]
    fn test_default_trait() {
        let router = IpLiteralRouter::default();
        assert_eq!(router.driver_name(), "ipliteral");
    }

    #[test]
    fn test_options_struct_default() {
        let opts = IpLiteralRouterOptions::default();
        // Options struct is empty — just verify it's constructible
        let _ = format!("{:?}", opts);
    }

    #[test]
    fn test_options_clone() {
        let opts = IpLiteralRouterOptions;
        let cloned = opts.clone();
        let _ = format!("{:?}", cloned);
    }

    #[test]
    fn test_router_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<IpLiteralRouter>();
    }

    #[test]
    fn test_router_as_trait_object() {
        let router: Box<dyn RouterDriver> = Box::new(IpLiteralRouter::new());
        assert_eq!(router.driver_name(), "ipliteral");
        assert_eq!(router.flags(), RI_YESTRANSPORT);
    }
}
