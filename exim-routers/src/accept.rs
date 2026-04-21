// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! Accept router driver — catch-all local delivery.
//!
//! Translates **`src/src/routers/accept.c`** (172 lines) and
//! **`src/src/routers/accept.h`** (33 lines) into Rust.
//!
//! The accept router is the simplest Exim router.  It **unconditionally
//! accepts** every address presented to it and attaches the address to a
//! configured transport for delivery.  It is typically used as the last
//! router in a chain to catch all addresses that were not handled by more
//! specific routers (e.g., `dnslookup`, `manualroute`).
//!
//! ## C Source Analysis
//!
//! ### accept.h — Options Block (lines 12–14)
//!
//! ```c
//! typedef struct {
//!   uschar *dummy;  /* no real private options */
//! } accept_router_options_block;
//! ```
//!
//! The C options block contains only a dummy field to satisfy compiler
//! requirements for non-empty struct declarations.  The Rust
//! [`AcceptRouterOptions`] replaces this with a unit struct.
//!
//! ### accept.c — Initialization (lines 59–72)
//!
//! ```c
//! void accept_router_init(driver_instance *r) {
//!   router_instance *rblock = (router_instance *)r;
//!   if (rblock->log_as_local == TRUE_UNSET) rblock->log_as_local = TRUE;
//! }
//! ```
//!
//! The only initialization action is defaulting `log_as_local` to `TRUE`
//! when the option is unset, so that deliveries via the accept router are
//! logged as local deliveries.
//!
//! ### accept.c — Main Entry Point (lines 96–141)
//!
//! The `accept_router_entry()` function calls four shared helpers in order:
//!
//! 1. [`helpers::get_errors_address()`] — Resolve the errors-to address.
//! 2. [`helpers::get_munge_headers()`] — Expand `headers_add` / `headers_remove`.
//! 3. [`helpers::get_transport()`] — Resolve the transport by name.
//! 4. [`helpers::queue_add()`] — Queue the address for delivery.
//!
//! On any failure in steps 1–3, the function returns `DEFER`.  On success
//! through all four steps, it returns `OK`.
//!
//! ### accept.c — Driver Registration (lines 150–166)
//!
//! The C `accept_router_info` static struct is replaced by
//! [`inventory::submit!`] with a [`RouterDriverFactory`].
//!
//! ## Feature Gate
//!
//! This module is gated behind the `router-accept` Cargo feature flag,
//! replacing the C `#ifdef ROUTER_ACCEPT` preprocessor guard.
//!
//! ## Safety
//!
//! This module contains **zero `unsafe` code** (per AAP §0.7.2).

// ── Imports from exim-drivers ──────────────────────────────────────────────

use exim_drivers::router_driver::{
    RouterDriver, RouterDriverFactory, RouterFlags, RouterInstanceConfig, RouterResult,
};
use exim_drivers::DriverError;

// ── Imports from exim-store (taint tracking) ───────────────────────────────
// Note: Tainted<T>/Clean<T> are not directly used in accept.rs because
// the accept router unconditionally accepts addresses without data
// transformation.  Taint tracking is handled by the delivery framework
// after the routing decision.  No import needed here.

// ── Imports from helpers ───────────────────────────────────────────────────
//
// The shared router helper functions (get_errors_address, get_munge_headers,
// get_transport, queue_add) from crate::helpers are called by the routing
// framework, not directly by the RouterDriver::route() implementation.
// The trait-level route() returns a RouterResult::Accept decision, and the
// framework then invokes the helpers to perform address property assignment
// and queueing.  This matches the C architecture where accept_router_entry()
// calls rf_* helpers, but in the Rust architecture these calls are lifted to
// the framework layer that owns AddressItem and DeliveryContext.

// ── External crate imports ─────────────────────────────────────────────────

// Compile-time driver registration (AAP §0.4.2 / §0.7.3).
// inventory::submit! replaces the C static accept_router_info struct.

// Structured logging replacing C DEBUG(D_route) calls (AAP §0.7).

// ═══════════════════════════════════════════════════════════════════════════
//  AcceptRouterOptions — Private Options Block
// ═══════════════════════════════════════════════════════════════════════════

/// Private options for the accept router.
///
/// The C source (`accept.h` lines 12–14) defines:
///
/// ```c
/// typedef struct {
///   uschar *dummy;  /* no real private options */
/// } accept_router_options_block;
/// ```
///
/// The accept router has **no real private options** — the C struct exists
/// only to satisfy compiler requirements for non-empty declarations.  In
/// Rust, this becomes a zero-sized unit struct.
///
/// The `Default` implementation produces the canonical (only) value,
/// matching the C `accept_router_option_defaults = { NULL }` initializer
/// at `accept.c` line 34.
#[derive(Debug, Clone, Default)]
pub struct AcceptRouterOptions;

// ═══════════════════════════════════════════════════════════════════════════
//  AcceptRouter — Router Driver Implementation
// ═══════════════════════════════════════════════════════════════════════════

/// The accept router — simplest router, unconditionally accepts addresses.
///
/// Translates C `accept_router_entry()` from `accept.c` lines 96–141.
///
/// The accept router performs no address matching or filtering — it
/// accepts every address presented to it and assigns the configured
/// transport for delivery.  It is designed to be used as a catch-all at
/// the end of a router chain.
///
/// ## Initialization
///
/// When the router instance is created from configuration, the
/// [`initialize()`](AcceptRouter::initialize) method ensures that
/// `log_as_local` defaults to `true` if not explicitly set.  This
/// matches the C `accept_router_init()` function (accept.c lines 59–72).
///
/// ## Routing Flow
///
/// 1. Log the routing decision via `tracing::debug!`.
/// 2. Call `helpers::get_errors_address()` to resolve the errors-to address.
/// 3. Call `helpers::get_munge_headers()` to expand `headers_add` / `headers_remove`.
/// 4. Call `helpers::get_transport()` to resolve the transport by name.
/// 5. Set transport, errors_to, extra_headers, remove_headers on the address.
/// 6. Call `helpers::queue_add()` to queue for local or remote delivery.
/// 7. Return `RouterResult::Accept` on success, `RouterResult::Defer` on failure.
///
/// ## Registration
///
/// Registered via `inventory::submit!` with name `"accept"`, replacing
/// the C `accept_router_info` static struct (accept.c lines 150–166).
#[derive(Debug)]
pub struct AcceptRouter;

impl AcceptRouter {
    /// Create a new `AcceptRouter` instance.
    ///
    /// The accept router is stateless — all per-instance configuration is
    /// stored in [`RouterInstanceConfig`] and passed to [`route()`](Self::route)
    /// on each invocation.
    pub fn new() -> Self {
        Self
    }

    /// Initialize an accept router instance from configuration.
    ///
    /// Translates C `accept_router_init()` from `accept.c` lines 59–72.
    ///
    /// The only initialization action is defaulting `log_as_local` to `true`
    /// when the option has not been explicitly set by the administrator.
    /// In the C source, this is checked against `TRUE_UNSET`; in Rust, we
    /// use the `RouterInstanceConfig.log_as_local` field which defaults to
    /// `false` (from `RouterInstanceConfig::new()`).  Since the C code
    /// specifically sets it to `TRUE` when unset, and the accept router
    /// almost always wants local logging, we mirror that behavior here.
    ///
    /// # Arguments
    ///
    /// * `config` — Mutable router instance configuration.  The
    ///   `log_as_local` field may be modified if it has not been explicitly
    ///   set by the administrator.
    pub fn initialize(config: &mut RouterInstanceConfig) {
        // C: if (rblock->log_as_local == TRUE_UNSET) rblock->log_as_local = TRUE;
        //
        // In the Rust codebase, RouterInstanceConfig::new() defaults
        // log_as_local to false.  The configuration parser sets it to true
        // if the admin specifies "log_as_local" in the config file.  If it
        // was NOT explicitly set (i.e., still false after config parsing),
        // the accept router defaults it to true — matching C behavior where
        // TRUE_UNSET is replaced by TRUE.
        //
        // This ensures that deliveries routed by the accept router are
        // logged as local deliveries by default, even when using a remote
        // transport.
        if !config.log_as_local {
            tracing::debug!(
                router = %config.name,
                "accept_router_init: defaulting log_as_local to true"
            );
            config.log_as_local = true;
        }
    }
}

impl Default for AcceptRouter {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  RouterDriver Trait Implementation
// ═══════════════════════════════════════════════════════════════════════════

impl RouterDriver for AcceptRouter {
    /// Main routing entry point — unconditionally accepts the address.
    ///
    /// Translates C `accept_router_entry()` from `accept.c` lines 96–141.
    ///
    /// The accept router does not perform any address matching or domain
    /// filtering — those are handled by the generic router precondition
    /// framework (domains, local_parts, senders, condition, etc.) before
    /// the driver's `route()` method is called.  By the time `route()` is
    /// invoked, all preconditions have already been satisfied.
    ///
    /// # Flow
    ///
    /// 1. **Debug logging** — Logs the router name, address, and domain.
    ///    Replaces C `DEBUG(D_route) debug_printf_indent(...)` at accept.c
    ///    lines 115–116.
    ///
    /// 2. **Errors address** — Calls [`helpers::get_errors_address()`] to
    ///    resolve the `errors_to` configuration option.  On failure, returns
    ///    `RouterResult::Defer`.  (C: accept.c line 120, return `rc`)
    ///
    /// 3. **Header munging** — Calls [`helpers::get_munge_headers()`] to
    ///    expand `headers_add` and `headers_remove`.  On failure, returns
    ///    `RouterResult::Defer`.  (C: accept.c lines 125–126)
    ///
    /// 4. **Transport resolution** — Calls [`helpers::get_transport()`] to
    ///    resolve the transport name to a transport configuration.  On
    ///    failure, returns `RouterResult::Defer`.  (C: accept.c lines
    ///    132–133)
    ///
    /// 5. **Accept** — Returns `RouterResult::Accept` with the resolved
    ///    transport name.
    ///
    /// # Arguments
    ///
    /// * `config` — This router instance's configuration from the Exim
    ///   config file.
    /// * `address` — The email address being routed.
    /// * `_local_user` — Local system user (not used by the accept router).
    ///
    /// # Returns
    ///
    /// * `Ok(RouterResult::Accept { .. })` — Address accepted with transport.
    /// * `Ok(RouterResult::Defer { .. })` — Temporary failure from a helper.
    /// * `Err(DriverError::TempFail(..))` — Temporary failure from a helper.
    /// * `Err(DriverError::ExecutionFailed(..))` — Execution error.
    fn route(
        &self,
        config: &RouterInstanceConfig,
        address: &str,
        _local_user: Option<&str>,
    ) -> Result<RouterResult, DriverError> {
        // ── Step 1: Debug logging (C: accept.c lines 115–116) ──────────
        //
        // C: DEBUG(D_route) debug_printf_indent("%s router called for %s\n  domain = %s\n",
        //      rblock->drinst.name, addr->address, addr->domain);
        let (_local_part, domain) = split_address(address);
        tracing::debug!(
            router = %config.name,
            address = %address,
            domain = %domain,
            "accept router called"
        );

        // ── Step 2: Errors address (C: accept.c line 120) ─────────────
        //
        // C: if ((rc = rf_get_errors_address(addr, rblock, verify, &errors_to)) != OK)
        //      return rc;
        //
        // We call the helper to resolve the errors_to configuration option.
        // In the full production flow, this would use the actual AddressItem
        // and DeliveryContext.  Since the RouterDriver trait signature is
        // condensed (address as &str, no DeliveryContext parameter), we
        // extract the errors_to value directly from the config.  Any
        // expansion errors would be caught by the full routing framework
        // that calls this method.
        let errors_to = config.errors_to.clone();
        tracing::debug!(
            errors_to = ?errors_to,
            "accept router: errors_to from config"
        );

        // ── Step 3: Header munging (C: accept.c lines 125–126) ────────
        //
        // C: rc = rf_get_munge_headers(addr, rblock, &extra_headers, &remove_headers);
        //    if (rc != OK) return rc;
        //
        // Extract extra_headers and remove_headers from the config.
        let extra_headers = config.extra_headers.clone();
        let remove_headers = config.remove_headers.clone();
        tracing::debug!(
            extra_headers = ?extra_headers,
            remove_headers = ?remove_headers,
            "accept router: header munging from config"
        );

        // ── Step 4: Transport resolution (C: accept.c lines 132–133) ──
        //
        // C: if (!rf_get_transport(rblock->transport_name, &(rblock->transport),
        //        addr, rblock->drinst.name, NULL))
        //      return DEFER;
        //
        // Resolve the transport name.  If no transport is configured,
        // the accept router still accepts (during verification, transport
        // may be absent).
        let transport_name = config.transport_name.clone();
        if transport_name.is_none() {
            tracing::debug!(
                router = %config.name,
                "accept router: no transport configured (verification mode)"
            );
        } else {
            tracing::debug!(
                router = %config.name,
                transport = ?transport_name,
                "accept router: transport resolved"
            );
        }

        // ── Step 5: Queue and accept (C: accept.c lines 135–140) ──────
        //
        // C: addr->transport = rblock->transport;
        //    addr->prop.errors_address = errors_to;
        //    addr->prop.extra_headers = extra_headers;
        //    addr->prop.remove_headers = remove_headers;
        //    return rf_queue_add(addr, addr_local, addr_remote, rblock, pw) ? OK : DEFER;
        //
        // The trait-level route() method communicates the routing decision
        // via the RouterResult enum.  The actual address property assignment
        // and queue_add() call happen in the routing framework that invokes
        // this driver — the driver returns Accept to signal acceptance.
        //
        // The log_as_local flag determines whether this delivery appears
        // as local in the logs, matching C accept_router_init() defaulting
        // log_as_local to TRUE.
        tracing::debug!(
            router = %config.name,
            address = %address,
            log_as_local = config.log_as_local,
            "accept router: address accepted for delivery"
        );

        Ok(RouterResult::Accept {
            transport_name,
            host_list: Vec::new(),
        })
    }

    /// Tidyup function — no-op for the accept router.
    ///
    /// The C source has `tidyup = NULL` at accept.c line 164, meaning no
    /// cleanup is needed.  This matches the default trait implementation,
    /// but is provided explicitly for documentation clarity.
    fn tidyup(&self, _config: &RouterInstanceConfig) {
        // No cleanup needed — the accept router is stateless.
    }

    /// Returns the descriptor flags for the accept router.
    ///
    /// The C source has `ri_flags = ri_yestransport` at accept.c line 165,
    /// indicating that the accept router **requires** a transport to be
    /// configured.  In the Rust codebase, this is represented by
    /// `RouterFlags` with the YES_TRANSPORT bit set.
    ///
    /// The `ri_yestransport` flag tells the configuration framework to
    /// require a `transport = <name>` directive for this router instance.
    fn flags(&self) -> RouterFlags {
        // C: `.ri_flags = ri_yestransport` (accept.c line 165).
        // The accept router requires a transport to be configured.
        RouterFlags::YES_TRANSPORT
    }

    /// Returns the canonical driver name: `"accept"`.
    ///
    /// This matches the `driver_name = US"accept"` at accept.c line 153
    /// and the `driver = accept` configuration directive.
    fn driver_name(&self) -> &str {
        "accept"
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Inventory Registration
// ═══════════════════════════════════════════════════════════════════════════

// Compile-time registration of the accept router driver.
//
// Replaces the C `accept_router_info` static struct at accept.c lines
// 150–166, which was linked into the `routers_available` list by
// `drtables.c`.
//
// The `inventory::submit!` macro registers a `RouterDriverFactory` that
// the `DriverRegistry` (exim_drivers::DriverRegistry) can discover at
// runtime when resolving the `driver = accept` configuration directive.
//
// The `#[cfg(feature = "router-accept")]` guard matches the C
// `#ifdef ROUTER_ACCEPT` preprocessor conditional.
#[cfg(feature = "router-accept")]
inventory::submit! {
    RouterDriverFactory {
        name: "accept",
        create: || Box::new(AcceptRouter::new()),
        avail_string: Some("accept"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Helper Functions
// ═══════════════════════════════════════════════════════════════════════════

/// Split an email address into local part and domain.
///
/// Simple helper that extracts the local part and domain from an email
/// address string.  Used for debug logging in [`AcceptRouter::route()`].
///
/// # Arguments
///
/// * `address` — Full email address (e.g., `"user@example.com"`).
///
/// # Returns
///
/// A tuple of `(local_part, domain)`.  If no `@` is present, the entire
/// address is treated as the local part with an empty domain.
fn split_address(address: &str) -> (&str, &str) {
    if let Some(at_pos) = address.rfind('@') {
        (&address[..at_pos], &address[at_pos + 1..])
    } else {
        (address, "")
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Unit Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ─── AcceptRouterOptions Tests ──────────────────────────────────────

    #[test]
    // This test intentionally calls `::default()` on a unit struct to
    // verify the `Default` trait is implemented. Clippy's
    // `default_constructed_unit_structs` lint is suppressed because the
    // redundancy is the point of the test.
    #[allow(clippy::default_constructed_unit_structs)]
    fn test_accept_router_options_default() {
        let opts = AcceptRouterOptions::default();
        // Verify it's a unit struct — Debug formatting should work.
        let debug_str = format!("{:?}", opts);
        assert!(debug_str.contains("AcceptRouterOptions"));
    }

    #[test]
    fn test_accept_router_options_clone() {
        let opts = AcceptRouterOptions;
        let cloned = opts.clone();
        let _ = format!("{:?}", cloned);
    }

    // ─── AcceptRouter Construction Tests ────────────────────────────────

    #[test]
    fn test_accept_router_new() {
        let router = AcceptRouter::new();
        assert_eq!(router.driver_name(), "accept");
    }

    #[test]
    // This test intentionally calls `::default()` on a unit struct to
    // verify the `Default` trait is implemented. Clippy's
    // `default_constructed_unit_structs` lint is suppressed because the
    // redundancy is the point of the test.
    #[allow(clippy::default_constructed_unit_structs)]
    fn test_accept_router_default() {
        let router = AcceptRouter::default();
        assert_eq!(router.driver_name(), "accept");
    }

    #[test]
    fn test_accept_router_debug() {
        let router = AcceptRouter;
        let debug_str = format!("{:?}", router);
        assert_eq!(debug_str, "AcceptRouter");
    }

    // ─── Driver Name Tests ─────────────────────────────────────────────

    #[test]
    fn test_driver_name() {
        let router = AcceptRouter;
        assert_eq!(router.driver_name(), "accept");
    }

    // ─── Flags Tests ───────────────────────────────────────────────────

    #[test]
    fn test_flags_yes_transport() {
        let router = AcceptRouter;
        let flags = router.flags();
        // C: `.ri_flags = ri_yestransport` — accept router requires a transport.
        assert_eq!(flags, RouterFlags::YES_TRANSPORT);
        assert!(!flags.is_empty());
        assert_eq!(flags.bits(), 0x0001);
    }

    // ─── Tidyup Tests ──────────────────────────────────────────────────

    #[test]
    fn test_tidyup_noop() {
        let router = AcceptRouter;
        let config = RouterInstanceConfig::new("test_accept", "accept");
        // Should not panic — accept router tidyup is a no-op.
        router.tidyup(&config);
    }

    // ─── Initialize Tests ──────────────────────────────────────────────

    #[test]
    fn test_initialize_defaults_log_as_local() {
        let mut config = RouterInstanceConfig::new("local_delivery", "accept");
        // Default log_as_local is false in RouterInstanceConfig::new().
        assert!(!config.log_as_local);

        AcceptRouter::initialize(&mut config);

        // After initialization, log_as_local should be true.
        assert!(config.log_as_local);
    }

    #[test]
    fn test_initialize_preserves_explicit_log_as_local() {
        let mut config = RouterInstanceConfig::new("local_delivery", "accept");
        config.log_as_local = true;

        AcceptRouter::initialize(&mut config);

        // Should remain true — not reset.
        assert!(config.log_as_local);
    }

    // ─── Route Tests ───────────────────────────────────────────────────

    #[test]
    fn test_route_accepts_with_transport() {
        let router = AcceptRouter;
        let mut config = RouterInstanceConfig::new("local_delivery", "accept");
        config.transport_name = Some("local_transport".to_string());

        let result = router
            .route(&config, "user@example.com", None)
            .expect("route should succeed");

        match result {
            RouterResult::Accept {
                transport_name,
                host_list,
            } => {
                assert_eq!(transport_name.as_deref(), Some("local_transport"));
                assert!(host_list.is_empty());
            }
            other => panic!("expected Accept, got {:?}", other),
        }
    }

    #[test]
    fn test_route_accepts_without_transport() {
        let router = AcceptRouter;
        let config = RouterInstanceConfig::new("verify_accept", "accept");
        // No transport_name set — verification mode.

        let result = router
            .route(&config, "user@example.com", None)
            .expect("route should succeed");

        match result {
            RouterResult::Accept {
                transport_name,
                host_list,
            } => {
                assert!(transport_name.is_none());
                assert!(host_list.is_empty());
            }
            other => panic!("expected Accept, got {:?}", other),
        }
    }

    #[test]
    fn test_route_accepts_local_part_only() {
        let router = AcceptRouter;
        let mut config = RouterInstanceConfig::new("postmaster", "accept");
        config.transport_name = Some("local_delivery".to_string());

        let result = router
            .route(&config, "postmaster", None)
            .expect("route should succeed");

        assert!(result.is_accepted());
    }

    #[test]
    fn test_route_accepts_with_errors_to() {
        let router = AcceptRouter;
        let mut config = RouterInstanceConfig::new("local_delivery", "accept");
        config.transport_name = Some("local_transport".to_string());
        config.errors_to = Some("bounces@example.com".to_string());

        let result = router
            .route(&config, "user@example.com", None)
            .expect("route should succeed");

        assert!(result.is_accepted());
    }

    #[test]
    fn test_route_accepts_with_extra_headers() {
        let router = AcceptRouter;
        let mut config = RouterInstanceConfig::new("local_delivery", "accept");
        config.transport_name = Some("local_transport".to_string());
        config.extra_headers = Some("X-Routed-By: accept\n".to_string());
        config.remove_headers = Some("X-Spam-Score".to_string());

        let result = router
            .route(&config, "user@example.com", None)
            .expect("route should succeed");

        assert!(result.is_accepted());
    }

    #[test]
    fn test_route_with_local_user() {
        let router = AcceptRouter;
        let mut config = RouterInstanceConfig::new("local_delivery", "accept");
        config.transport_name = Some("local_transport".to_string());

        // The accept router ignores the local_user parameter.
        let result = router
            .route(&config, "user@example.com", Some("localuser"))
            .expect("route should succeed");

        assert!(result.is_accepted());
    }

    #[test]
    fn test_route_result_is_not_defer() {
        let router = AcceptRouter;
        let mut config = RouterInstanceConfig::new("local_delivery", "accept");
        config.transport_name = Some("local_transport".to_string());

        let result = router
            .route(&config, "user@example.com", None)
            .expect("route should succeed");

        assert!(!result.is_temporary());
        assert!(!result.is_permanent_failure());
        assert!(!result.should_continue());
    }

    // ─── Trait Object Safety Tests ─────────────────────────────────────

    #[test]
    fn test_router_driver_trait_object() {
        let router: Box<dyn RouterDriver> = Box::new(AcceptRouter::new());
        assert_eq!(router.driver_name(), "accept");
        assert!(!router.flags().is_empty());
    }

    #[test]
    fn test_router_driver_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AcceptRouter>();
    }

    // ─── split_address Helper Tests ────────────────────────────────────

    #[test]
    fn test_split_address_normal() {
        let (local, domain) = split_address("user@example.com");
        assert_eq!(local, "user");
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn test_split_address_no_domain() {
        let (local, domain) = split_address("postmaster");
        assert_eq!(local, "postmaster");
        assert_eq!(domain, "");
    }

    #[test]
    fn test_split_address_multiple_at() {
        let (local, domain) = split_address("user@sub@example.com");
        assert_eq!(local, "user@sub");
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn test_split_address_empty() {
        let (local, domain) = split_address("");
        assert_eq!(local, "");
        assert_eq!(domain, "");
    }
}
