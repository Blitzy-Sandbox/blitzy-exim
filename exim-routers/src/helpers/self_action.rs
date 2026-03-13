// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! Self-reference detection action handler for router drivers.
//!
//! Translates **`src/src/routers/rf_self_action.c`** (126 lines) into Rust.
//!
//! ## Overview
//!
//! When a router performs a DNS lookup on a host list and discovers that one
//! of the listed hosts resolves to an IP address belonging to the local
//! machine (`HOST_FOUND_LOCAL`), it calls [`self_action()`] to determine
//! what to do.  The action is configured per router via the `self` option
//! in the Exim configuration file.
//!
//! The six possible actions are represented by the [`SelfAction`] enum:
//!
//! | Action | C enum | Effect |
//! |--------|--------|--------|
//! | [`SelfAction::Freeze`] | `self_freeze` | Log, freeze the message, return DEFER |
//! | [`SelfAction::Defer`]  | `self_defer`  | Set diagnostic, return DEFER |
//! | [`SelfAction::Fail`]   | `self_fail`   | Set diagnostic, set `af_pass_message`, return FAIL |
//! | [`SelfAction::Send`]   | `self_send`   | Proceed with delivery to self anyway (return OK) |
//! | [`SelfAction::Reroute`]| `self_reroute`| Rewrite domain via [`change_domain()`], return REROUTED |
//! | [`SelfAction::Pass`]   | `self_pass`   | Set `self_hostname`, pass to next router |
//!
//! ## C Source Correspondence
//!
//! | C construct | Rust equivalent |
//! |---|---|
//! | `int code` (self_freeze, self_defer, …) | [`SelfAction`] enum |
//! | `addr->message = msg` | `addr.message = Some(msg.to_string())` |
//! | `addr->special_action = SPECIAL_FREEZE` | `addr.special_action = SPECIAL_FREEZE` |
//! | `addr->self_hostname = string_copy(host->name)` | `addr.self_hostname = Some(host.name.clone())` |
//! | `setflag(addr, af_pass_message)` | `addr.flags \|= AF_PASS_MESSAGE` |
//! | `rf_change_domain(addr, new, rewrite, addr_new)` | `change_domain(addr, new_domain, rewrite, addr_new, ctx)` |
//! | `host->mx >= 0` | `host.mx_priority.is_some_and(\|mx\| mx >= 0)` |
//! | `DEBUG(D_route)` | `tracing::debug!(…)` |
//! | `log_write(0, LOG_MAIN, …)` | `tracing::warn!(…)` |
//!
//! ## Safety
//!
//! This module contains **zero `unsafe` code** (per AAP §0.7.2).

// ── Imports ────────────────────────────────────────────────────────────────

use super::change_domain::{AddressItem, DeliveryContext};
use exim_dns::HostItem;
use exim_drivers::router_driver::{RouterInstanceConfig, RouterResult};

// ── Constants ──────────────────────────────────────────────────────────────

/// Special action code: freeze the message (queue it but do not attempt
/// delivery until manually released by an administrator).
///
/// Maps to C `SPECIAL_FREEZE` (value 1) from the `macros.h` enum:
/// ```c
/// enum { SPECIAL_NONE, SPECIAL_FREEZE, SPECIAL_FAIL, SPECIAL_WARN };
/// ```
const SPECIAL_FREEZE: i32 = 1;

/// Address flag: pass the address-level message string through to the
/// bounce message so the remote server's response is visible to the
/// original sender.
///
/// Maps to C `af_pass_message` — the 27th bit (0-indexed: bit 26) in the
/// `address_item.flags` bitfield in `structs.h`:
///
/// ```c
/// BOOL af_pass_message:1;  /* pass message in bounces */
/// ```
///
/// Counted from `af_allow_file` (bit 0) through to `af_pass_message`
/// (bit 26) in the order they appear in the C struct.
const AF_PASS_MESSAGE: u32 = 1 << 26;

// ── SelfAction Enum ────────────────────────────────────────────────────────

/// Action to take when a host lookup resolves to the local machine.
///
/// Replaces the C `self_xxx` enum values (`self_freeze`, `self_defer`,
/// `self_fail`, `self_send`, `self_reroute`, `self_pass`) used by the
/// `self` configuration option on each router.
///
/// The `Reroute` variant carries the target domain as a `String`, which
/// in C was stored in a separate `uschar *new` parameter extracted from
/// the router's `self` option string after the `>>` prefix.  In Rust,
/// this is pre-parsed by the configuration parser into `SelfAction::Reroute(domain)`.
#[derive(Debug, Clone, PartialEq)]
pub enum SelfAction {
    /// Freeze the message — log the incident to the main log, set
    /// `special_action = SPECIAL_FREEZE` on the address, and return DEFER.
    ///
    /// This is the most severe self-reference handling: the message is
    /// frozen in the spool and requires administrator intervention to
    /// release.  The main log entry provides context about why the freeze
    /// occurred (address verification vs. normal routing).
    ///
    /// C equivalent: `self_freeze` (rf_self_action.c lines 71–90).
    Freeze,

    /// Defer delivery — set a diagnostic message on the address and
    /// return DEFER.  The message will be retried according to the retry
    /// rules.
    ///
    /// C equivalent: `self_defer` (rf_self_action.c lines 92–94).
    Defer,

    /// Fail delivery permanently — set a diagnostic message and the
    /// `af_pass_message` flag on the address, and return FAIL.  This
    /// generates a bounce/DSN message to the sender.
    ///
    /// C equivalent: `self_fail` (rf_self_action.c lines 114–119).
    Fail,

    /// Send to self anyway — ignore the self-reference and proceed with
    /// delivery.  This makes sense when the local SMTP listener is a
    /// differently-configured MTA (e.g., a content scanner or
    /// relay-through-self architecture).
    ///
    /// C equivalent: `self_send` (rf_self_action.c lines 102–105).
    Send,

    /// Reroute to a different domain — rewrite the address domain using
    /// [`change_domain()`] and return REROUTED.  The inner `String` is
    /// the new target domain (extracted from the `self = reroute:domain`
    /// or `self = reroute:rewrite:domain` configuration option).
    ///
    /// C equivalent: `self_reroute` (rf_self_action.c lines 96–100).
    Reroute(String),

    /// Pass to the next router — set a diagnostic message and the
    /// `self_hostname` field on the address, then return PASS.  This is
    /// a "soft failure" that allows subsequent routers in the chain to
    /// handle the address, overriding the `no_more` setting.
    ///
    /// C equivalent: `self_pass` (rf_self_action.c lines 107–112).
    Pass,
}

// ── Primary Public API ─────────────────────────────────────────────────────

/// Handles self-reference detection when a host lookup returns the local machine.
///
/// Translates C `rf_self_action()` from `rf_self_action.c` (126 lines).
///
/// Called by the `lookup_hostlist` helper (and other routers) when a DNS
/// lookup for a host in the host list returns `HOST_FOUND_LOCAL` — meaning
/// the resolved IP address belongs to the local machine.
///
/// The function determines a diagnostic message based on whether the host
/// was found via MX record lookup or direct A/AAAA lookup:
///
/// - If `host.mx_priority` is `Some(mx)` where `mx >= 0`, the message is
///   `"lowest numbered MX record points to local host"`.
/// - Otherwise, the message is `"remote host address is the local host"`.
///
/// It then dispatches on the [`SelfAction`] variant to update the address
/// item and return the appropriate [`RouterResult`].
///
/// # Arguments
///
/// * `addr` — The address being routed.  Updated in-place with diagnostic
///   messages, special actions, or flags depending on the action taken.
/// * `host` — The host that resolved to the local machine, providing the
///   hostname and MX priority for diagnostics.
/// * `action` — The configured self-reference action to execute.
/// * `rewrite` — If `true` and action is `Reroute`, message headers are
///   rewritten to reflect the new domain.
/// * `_router_config` — Router instance configuration (reserved for future
///   use; the C function accepted `router_instance *rblock` but only used
///   it to extract the reroute domain, which is now embedded in
///   `SelfAction::Reroute`).
/// * `addr_new` — Vector to which child addresses are appended for the
///   `Reroute` case (via [`change_domain()`]).
/// * `ctx` — Mutable delivery context for header rewriting in the
///   `Reroute` case.
///
/// # Returns
///
/// A [`RouterResult`] indicating the outcome:
///
/// | Action | Return |
/// |--------|--------|
/// | `Freeze` | `RouterResult::Defer { message }` |
/// | `Defer`  | `RouterResult::Defer { message }` |
/// | `Fail`   | `RouterResult::Fail { message }` |
/// | `Send`   | `RouterResult::Accept { .. }` |
/// | `Reroute`| `RouterResult::Rerouted { .. }` |
/// | `Pass`   | `RouterResult::Pass` |
///
/// # C Correspondence
///
/// ```c
/// int rf_self_action(address_item *addr, host_item *host, int code,
///                    BOOL rewrite, uschar *new, address_item **addr_new)
/// ```
///
/// Note: The C function signature included `uschar *new` for the reroute
/// domain, which is now embedded in `SelfAction::Reroute(String)`.
///
/// # Example
///
/// ```rust,ignore
/// use exim_routers::helpers::self_action::{SelfAction, self_action};
///
/// let action = SelfAction::Defer;
/// let result = self_action(&mut addr, &host, &action, false, &config, &mut vec![], &mut ctx);
/// // result == RouterResult::Defer { message: Some("...") }
/// ```
pub fn self_action(
    addr: &mut AddressItem,
    host: &HostItem,
    action: &SelfAction,
    rewrite: bool,
    _router_config: &RouterInstanceConfig,
    addr_new: &mut Vec<AddressItem>,
    ctx: &mut DeliveryContext,
) -> RouterResult {
    // ── Determine the diagnostic message ───────────────────────────────
    //
    // C (rf_self_action.c lines 65–67):
    //   uschar * msg = host->mx >= 0
    //     ? US"lowest numbered MX record points to local host"
    //     : US"remote host address is the local host";
    //
    // In Rust, `host.mx_priority` is `Option<i32>`. A value of
    // `Some(mx)` where `mx >= 0` indicates the host was found via MX
    // record lookup. `None` or `Some(mx)` where `mx < 0` indicates a
    // direct A/AAAA record lookup (C uses mx == -1 for non-MX hosts).
    let msg = if host.mx_priority.is_some_and(|mx| mx >= 0) {
        "lowest numbered MX record points to local host"
    } else {
        "remote host address is the local host"
    };

    match action {
        // ── Freeze ─────────────────────────────────────────────────────
        //
        // C (rf_self_action.c lines 71–90):
        //   Logs to main log, sets addr->message and addr->special_action,
        //   returns DEFER.
        //
        // The C code emits a LOG_MAIN entry (not a debug-only entry) with
        // contextual detail depending on whether this is an address
        // verification or a normal delivery routing.  In Rust, we use
        // `tracing::warn!` for main-log-level messages (visible to
        // operators) to distinguish from `tracing::debug!` (D_route).
        SelfAction::Freeze => {
            tracing::warn!(
                host = %host.name,
                domain = %addr.domain,
                address = %addr.address,
                "{}: {} — freezing message",
                msg,
                addr.domain,
            );

            addr.message = Some(msg.to_string());
            addr.special_action = SPECIAL_FREEZE;

            RouterResult::Defer {
                message: Some(msg.to_string()),
            }
        }

        // ── Defer ──────────────────────────────────────────────────────
        //
        // C (rf_self_action.c lines 92–94):
        //   addr->message = msg;
        //   return DEFER;
        //
        // No debug output in the C source for this case — only the
        // message is set on the address.  We add a debug trace for
        // observability.
        SelfAction::Defer => {
            tracing::debug!(
                host = %host.name,
                domain = %addr.domain,
                "{}: {} — deferring delivery",
                msg,
                addr.domain,
            );

            addr.message = Some(msg.to_string());

            RouterResult::Defer {
                message: Some(msg.to_string()),
            }
        }

        // ── Reroute ────────────────────────────────────────────────────
        //
        // C (rf_self_action.c lines 96–100):
        //   DEBUG(D_route) debug_printf_indent(
        //       "%s: %s: domain changed to %s\n", msg, addr->domain, new);
        //   rf_change_domain(addr, new, rewrite, addr_new);
        //   return REROUTED;
        //
        // The new domain is pre-parsed into SelfAction::Reroute(domain)
        // by the configuration parser (in C, extracted from the router's
        // `self` option string after the ">>" prefix).
        SelfAction::Reroute(new_domain) => {
            tracing::debug!(
                host = %host.name,
                domain = %addr.domain,
                new_domain = %new_domain,
                "{}: {}: domain changed to {}",
                msg,
                addr.domain,
                new_domain,
            );

            super::change_domain::change_domain(addr, new_domain, rewrite, addr_new, ctx);

            RouterResult::Rerouted {
                new_addresses: Vec::new(),
            }
        }

        // ── Send ───────────────────────────────────────────────────────
        //
        // C (rf_self_action.c lines 102–105):
        //   DEBUG(D_route) debug_printf_indent(
        //       "%s: %s: configured to try delivery anyway\n", msg, addr->domain);
        //   return OK;
        //
        // The address is accepted for delivery to self.  This makes sense
        // when the local SMTP listener is a differently-configured MTA.
        SelfAction::Send => {
            tracing::debug!(
                host = %host.name,
                domain = %addr.domain,
                "{}: {}: configured to try delivery anyway",
                msg,
                addr.domain,
            );

            RouterResult::Accept {
                transport_name: None,
                host_list: Vec::new(),
            }
        }

        // ── Pass ───────────────────────────────────────────────────────
        //
        // C (rf_self_action.c lines 107–112):
        //   DEBUG(D_route) debug_printf_indent(
        //       "%s: %s: passed to next router (self = pass)\n",
        //       msg, addr->domain);
        //   addr->message = msg;
        //   addr->self_hostname = string_copy(host->name);
        //   return PASS;
        //
        // This is a "soft failure" — the address is passed to the next
        // router in the chain, overriding the `no_more` setting.  The
        // `self_hostname` field records which host triggered the self-
        // reference detection so that subsequent routers can avoid
        // repeating the lookup.
        SelfAction::Pass => {
            tracing::debug!(
                host = %host.name,
                domain = %addr.domain,
                "{}: {}: passed to next router (self = pass)",
                msg,
                addr.domain,
            );

            addr.message = Some(msg.to_string());
            addr.self_hostname = Some(host.name.clone());

            RouterResult::Pass
        }

        // ── Fail ───────────────────────────────────────────────────────
        //
        // C (rf_self_action.c lines 114–119):
        //   DEBUG(D_route) debug_printf_indent(
        //       "%s: %s: address failed (self = fail)\n", msg, addr->domain);
        //   addr->message = msg;
        //   setflag(addr, af_pass_message);
        //   return FAIL;
        //
        // The `af_pass_message` flag causes the diagnostic message to be
        // included in the bounce message, giving the sender visibility
        // into why delivery failed.
        SelfAction::Fail => {
            tracing::debug!(
                host = %host.name,
                domain = %addr.domain,
                "{}: {}: address failed (self = fail)",
                msg,
                addr.domain,
            );

            addr.message = Some(msg.to_string());
            addr.flags |= AF_PASS_MESSAGE;

            RouterResult::Fail {
                message: Some(msg.to_string()),
            }
        }
    }
}

// ── Unit Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use exim_dns::HostItem;
    use exim_drivers::router_driver::RouterInstanceConfig;

    /// Helper to create a test address item.
    fn make_test_addr(address: &str) -> AddressItem {
        AddressItem::new(address.to_string())
    }

    /// Helper to create a test host item with a given name and MX priority.
    fn make_test_host(name: &str, mx: Option<i32>) -> HostItem {
        HostItem {
            name: name.to_string(),
            addresses: Vec::new(),
            mx_priority: mx,
            sort_key: 0,
            dnssec_status: exim_dns::DnssecStatus::Unknown,
            certname: None,
        }
    }

    /// Helper to create a minimal router config.
    fn make_test_config() -> RouterInstanceConfig {
        RouterInstanceConfig::new("test_router", "dnslookup")
    }

    #[test]
    fn test_self_action_freeze_with_mx() {
        let mut addr = make_test_addr("user@example.com");
        let host = make_test_host("mail.example.com", Some(10));
        let config = make_test_config();
        let mut addr_new = Vec::new();
        let mut ctx = DeliveryContext::default();

        let result = self_action(
            &mut addr,
            &host,
            &SelfAction::Freeze,
            false,
            &config,
            &mut addr_new,
            &mut ctx,
        );

        assert!(matches!(result, RouterResult::Defer { .. }));
        assert_eq!(addr.special_action, SPECIAL_FREEZE);
        assert_eq!(
            addr.message.as_deref(),
            Some("lowest numbered MX record points to local host")
        );
    }

    #[test]
    fn test_self_action_freeze_without_mx() {
        let mut addr = make_test_addr("user@example.com");
        let host = make_test_host("mail.example.com", None);
        let config = make_test_config();
        let mut addr_new = Vec::new();
        let mut ctx = DeliveryContext::default();

        let result = self_action(
            &mut addr,
            &host,
            &SelfAction::Freeze,
            false,
            &config,
            &mut addr_new,
            &mut ctx,
        );

        assert!(matches!(result, RouterResult::Defer { .. }));
        assert_eq!(addr.special_action, SPECIAL_FREEZE);
        assert_eq!(
            addr.message.as_deref(),
            Some("remote host address is the local host")
        );
    }

    #[test]
    fn test_self_action_defer() {
        let mut addr = make_test_addr("user@example.com");
        let host = make_test_host("mail.example.com", Some(5));
        let config = make_test_config();
        let mut addr_new = Vec::new();
        let mut ctx = DeliveryContext::default();

        let result = self_action(
            &mut addr,
            &host,
            &SelfAction::Defer,
            false,
            &config,
            &mut addr_new,
            &mut ctx,
        );

        assert!(matches!(result, RouterResult::Defer { .. }));
        assert!(addr.message.is_some());
        // special_action should NOT be set (only Freeze sets it)
        assert_eq!(addr.special_action, 0);
    }

    #[test]
    fn test_self_action_fail() {
        let mut addr = make_test_addr("user@example.com");
        let host = make_test_host("mail.example.com", Some(0));
        let config = make_test_config();
        let mut addr_new = Vec::new();
        let mut ctx = DeliveryContext::default();

        let result = self_action(
            &mut addr,
            &host,
            &SelfAction::Fail,
            false,
            &config,
            &mut addr_new,
            &mut ctx,
        );

        assert!(matches!(result, RouterResult::Fail { .. }));
        assert!(addr.message.is_some());
        // af_pass_message flag should be set
        assert_ne!(addr.flags & AF_PASS_MESSAGE, 0);
    }

    #[test]
    fn test_self_action_send() {
        let mut addr = make_test_addr("user@example.com");
        let host = make_test_host("mail.example.com", Some(10));
        let config = make_test_config();
        let mut addr_new = Vec::new();
        let mut ctx = DeliveryContext::default();

        let result = self_action(
            &mut addr,
            &host,
            &SelfAction::Send,
            false,
            &config,
            &mut addr_new,
            &mut ctx,
        );

        assert!(matches!(
            result,
            RouterResult::Accept {
                transport_name: None,
                ..
            }
        ));
    }

    #[test]
    fn test_self_action_reroute() {
        let mut addr = make_test_addr("user@old.example.com");
        let host = make_test_host("mail.old.example.com", Some(10));
        let config = make_test_config();
        let mut addr_new = Vec::new();
        let mut ctx = DeliveryContext::default();

        let result = self_action(
            &mut addr,
            &host,
            &SelfAction::Reroute("new.example.com".to_string()),
            false,
            &config,
            &mut addr_new,
            &mut ctx,
        );

        assert!(matches!(result, RouterResult::Rerouted { .. }));
        // change_domain should have added a child address
        assert_eq!(addr_new.len(), 1);
        assert_eq!(addr_new[0].domain, "new.example.com");
        assert_eq!(addr_new[0].local_part, "user");
    }

    #[test]
    fn test_self_action_reroute_with_rewrite() {
        let mut addr = make_test_addr("user@old.example.com");
        let host = make_test_host("mail.old.example.com", Some(10));
        let config = make_test_config();
        let mut addr_new = Vec::new();
        let mut ctx = DeliveryContext::default();

        let result = self_action(
            &mut addr,
            &host,
            &SelfAction::Reroute("new.example.com".to_string()),
            true, // rewrite = true
            &config,
            &mut addr_new,
            &mut ctx,
        );

        assert!(matches!(result, RouterResult::Rerouted { .. }));
        assert_eq!(addr_new.len(), 1);
        assert_eq!(addr_new[0].domain, "new.example.com");
    }

    #[test]
    fn test_self_action_pass() {
        let mut addr = make_test_addr("user@example.com");
        let host = make_test_host("mail.example.com", Some(10));
        let config = make_test_config();
        let mut addr_new = Vec::new();
        let mut ctx = DeliveryContext::default();

        let result = self_action(
            &mut addr,
            &host,
            &SelfAction::Pass,
            false,
            &config,
            &mut addr_new,
            &mut ctx,
        );

        assert!(matches!(result, RouterResult::Pass));
        assert!(addr.message.is_some());
        assert_eq!(addr.self_hostname.as_deref(), Some("mail.example.com"));
    }

    #[test]
    fn test_self_action_negative_mx_uses_non_mx_message() {
        let mut addr = make_test_addr("user@example.com");
        let host = make_test_host("direct.example.com", Some(-1));
        let config = make_test_config();
        let mut addr_new = Vec::new();
        let mut ctx = DeliveryContext::default();

        let result = self_action(
            &mut addr,
            &host,
            &SelfAction::Defer,
            false,
            &config,
            &mut addr_new,
            &mut ctx,
        );

        assert!(matches!(result, RouterResult::Defer { .. }));
        assert_eq!(
            addr.message.as_deref(),
            Some("remote host address is the local host")
        );
    }

    #[test]
    fn test_self_action_enum_equality() {
        assert_eq!(SelfAction::Freeze, SelfAction::Freeze);
        assert_eq!(SelfAction::Defer, SelfAction::Defer);
        assert_eq!(SelfAction::Fail, SelfAction::Fail);
        assert_eq!(SelfAction::Send, SelfAction::Send);
        assert_eq!(SelfAction::Pass, SelfAction::Pass);
        assert_eq!(
            SelfAction::Reroute("a.com".to_string()),
            SelfAction::Reroute("a.com".to_string())
        );
        assert_ne!(
            SelfAction::Reroute("a.com".to_string()),
            SelfAction::Reroute("b.com".to_string())
        );
        assert_ne!(SelfAction::Freeze, SelfAction::Defer);
    }

    #[test]
    fn test_self_action_enum_debug_format() {
        let freeze = format!("{:?}", SelfAction::Freeze);
        assert_eq!(freeze, "Freeze");

        let reroute = format!("{:?}", SelfAction::Reroute("test.com".to_string()));
        assert!(reroute.contains("Reroute"));
        assert!(reroute.contains("test.com"));
    }

    #[test]
    fn test_self_action_enum_clone() {
        let original = SelfAction::Reroute("domain.com".to_string());
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }
}
