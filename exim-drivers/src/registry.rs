// =============================================================================
// exim-drivers/src/registry.rs — Inventory-Based Compile-Time Registration
// =============================================================================
//
// Implements compile-time driver collection using the `inventory` crate,
// replacing the C `drtables.c` registration machinery. In C, drivers were
// registered via linked-list heads (`auths_available`, `routers_available`,
// `transports_available`) and a tree (`lookups_tree`). The Rust replacement
// uses `inventory::collect!` for compile-time collection and provides runtime
// resolution by name from config.
//
// Per AAP §0.7.3: "Driver registration via `inventory` crate — each driver
// implementation uses `inventory::submit!` for compile-time collection; runtime
// driver resolution by name from config."
//
// This file contains ZERO unsafe code (per AAP §0.7.2).

use crate::auth_driver::AuthDriverFactory;
use crate::lookup_driver::LookupDriverFactory;
use crate::router_driver::RouterDriverFactory;
use crate::transport_driver::TransportDriverFactory;

// =============================================================================
// Inventory Collection Declarations
// =============================================================================
// These macros declare compile-time collection points for each driver factory type.
// Driver implementation crates register their factories using `inventory::submit!`.

inventory::collect!(AuthDriverFactory);
inventory::collect!(RouterDriverFactory);
inventory::collect!(TransportDriverFactory);
inventory::collect!(LookupDriverFactory);

// =============================================================================
// DriverRegistry
// =============================================================================

/// Central registry providing runtime driver resolution by name.
///
/// Replaces C global variables from `drtables.c`:
///   - `auths_available`      → `DriverRegistry::find_auth()`
///   - `routers_available`    → `DriverRegistry::find_router()`
///   - `transports_available` → `DriverRegistry::find_transport()`
///   - `lookups_tree`         → `DriverRegistry::find_lookup()`
///
/// This struct is stateless — all data comes from the `inventory` crate's
/// compile-time collection, which is inherently thread-safe and requires no
/// mutable global state.
pub struct DriverRegistry;

impl DriverRegistry {
    // =========================================================================
    // Auth Driver Resolution
    // =========================================================================

    /// Find an auth driver factory by name.
    ///
    /// Replaces C's linear search of the `auths_available` linked list.
    ///
    /// # Arguments
    /// - `name` — The driver name to look up (e.g., "cram_md5", "plaintext").
    ///
    /// # Returns
    /// A reference to the factory if found, `None` otherwise.
    pub fn find_auth(name: &str) -> Option<&'static AuthDriverFactory> {
        inventory::iter::<AuthDriverFactory>().find(|f| f.name == name)
    }

    /// List all available auth drivers.
    ///
    /// Replaces C's iteration of the `auths_available` linked list.
    pub fn list_auths() -> impl Iterator<Item = &'static AuthDriverFactory> {
        inventory::iter::<AuthDriverFactory>()
    }

    // =========================================================================
    // Router Driver Resolution
    // =========================================================================

    /// Find a router driver factory by name.
    ///
    /// Replaces C's linear search of the `routers_available` linked list.
    ///
    /// # Arguments
    /// - `name` — The driver name to look up (e.g., "accept", "dnslookup").
    ///
    /// # Returns
    /// A reference to the factory if found, `None` otherwise.
    pub fn find_router(name: &str) -> Option<&'static RouterDriverFactory> {
        inventory::iter::<RouterDriverFactory>().find(|f| f.name == name)
    }

    /// List all available router drivers.
    ///
    /// Replaces C's iteration of the `routers_available` linked list.
    pub fn list_routers() -> impl Iterator<Item = &'static RouterDriverFactory> {
        inventory::iter::<RouterDriverFactory>()
    }

    // =========================================================================
    // Transport Driver Resolution
    // =========================================================================

    /// Find a transport driver factory by name.
    ///
    /// Replaces C's linear search of the `transports_available` linked list.
    ///
    /// # Arguments
    /// - `name` — The driver name to look up (e.g., "appendfile", "smtp", "pipe").
    ///
    /// # Returns
    /// A reference to the factory if found, `None` otherwise.
    pub fn find_transport(name: &str) -> Option<&'static TransportDriverFactory> {
        inventory::iter::<TransportDriverFactory>().find(|f| f.name == name)
    }

    /// List all available transport drivers.
    ///
    /// Replaces C's iteration of the `transports_available` linked list.
    pub fn list_transports() -> impl Iterator<Item = &'static TransportDriverFactory> {
        inventory::iter::<TransportDriverFactory>()
    }

    // =========================================================================
    // Lookup Driver Resolution
    // =========================================================================

    /// Find a lookup driver factory by name.
    ///
    /// Replaces C's `lookup_find()` function from drtables.c lines 243-252,
    /// which searched the `lookups_tree` by name.
    ///
    /// # Arguments
    /// - `name` — The lookup type name (e.g., "lsearch", "mysql", "redis").
    ///
    /// # Returns
    /// A reference to the factory if found, `None` otherwise.
    pub fn find_lookup(name: &str) -> Option<&'static LookupDriverFactory> {
        inventory::iter::<LookupDriverFactory>().find(|f| f.name == name)
    }

    /// List all available lookup drivers.
    ///
    /// Replaces C's traversal of `lookups_tree`.
    pub fn list_lookups() -> impl Iterator<Item = &'static LookupDriverFactory> {
        inventory::iter::<LookupDriverFactory>()
    }

    // =========================================================================
    // Show-Supported Functions
    // =========================================================================

    /// Format available authenticators for display.
    ///
    /// Replaces C: `auth_show_supported()` in drtables.c lines 58-63.
    /// Produces output like: `Authenticators (built-in): cram_md5 plaintext dovecot`
    pub fn auth_show_supported() -> String {
        let names: Vec<&str> = Self::list_auths()
            .map(|f| f.avail_string.unwrap_or(f.name))
            .collect();
        if names.is_empty() {
            String::new()
        } else {
            format!("Authenticators (built-in): {}", names.join(" "))
        }
    }

    /// Format available routers for display.
    ///
    /// Replaces C: `route_show_supported()` in drtables.c lines 65-70.
    /// Produces output like: `Routers (built-in): accept dnslookup manualroute redirect`
    pub fn route_show_supported() -> String {
        let names: Vec<&str> = Self::list_routers()
            .map(|f| f.avail_string.unwrap_or(f.name))
            .collect();
        if names.is_empty() {
            String::new()
        } else {
            format!("Routers (built-in): {}", names.join(" "))
        }
    }

    /// Format available transports for display.
    ///
    /// Replaces C: `transport_show_supported()` in drtables.c lines 72-77.
    /// Produces output like: `Transports (built-in): appendfile smtp pipe`
    pub fn transport_show_supported() -> String {
        let names: Vec<&str> = Self::list_transports()
            .map(|f| f.avail_string.unwrap_or(f.name))
            .collect();
        if names.is_empty() {
            String::new()
        } else {
            format!("Transports (built-in): {}", names.join(" "))
        }
    }

    /// Format available lookups for display.
    ///
    /// Replaces C: `lookup_dynamic_supported()` in drtables.c lines 256-293.
    /// Produces output like: `Lookups (built-in): lsearch mysql redis sqlite`
    pub fn lookup_show_supported() -> String {
        let names: Vec<&str> = Self::list_lookups()
            .map(|f| f.avail_string.unwrap_or(f.name))
            .collect();
        if names.is_empty() {
            String::new()
        } else {
            format!("Lookups (built-in): {}", names.join(" "))
        }
    }

    // =========================================================================
    // Initialization
    // =========================================================================

    /// Initialize the driver registry and log counts.
    ///
    /// Replaces C: `init_lookup_list()` and `init_misc_mod_list()` from drtables.c.
    /// Logs the number of registered drivers of each type for diagnostic purposes.
    pub fn init() {
        let auth_count = Self::list_auths().count();
        let router_count = Self::list_routers().count();
        let transport_count = Self::list_transports().count();
        let lookup_count = Self::list_lookups().count();
        tracing::info!(
            auth_count,
            router_count,
            transport_count,
            lookup_count,
            "Driver registry initialized"
        );
    }
}
