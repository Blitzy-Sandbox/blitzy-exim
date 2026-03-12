// =============================================================================
// exim-lookups/src/whoson.rs — WHOSON Dynamic IP Lookup Backend (FFI)
// =============================================================================
//
// Rewrites `src/src/lookups/whoson.c` (92 lines) as a Rust module that
// delegates WHOSON queries to the `exim_ffi::whoson` safe FFI wrapper.
//
// WHOSON (WHO iS ONline) is a protocol for tracking authenticated users by
// their dynamically assigned IP addresses. An ISP or network operator runs a
// WHOSON daemon that maps currently-online IP addresses to the user name that
// authenticated on that IP. Exim uses this lookup to determine whether an
// incoming SMTP connection originates from an authenticated user, enabling
// relay authorization without requiring SMTP AUTH on every message.
//
// This is a **query-style** lookup — the key is an IP address (IPv4 or IPv6)
// and the result (if found) is the user name associated with that IP session.
//
// C function mapping:
//   whoson_open()           → WhosonLookup::open()           — stateless marker
//   whoson_find()           → WhosonLookup::find()           — wso_query() via FFI
//   check (NULL in C)       → WhosonLookup::check()          — always true (query-style)
//   close (NULL in C)       → WhosonLookup::close()          — no-op
//   tidy  (NULL in C)       → WhosonLookup::tidy()           — no-op
//   quote (NULL in C)       → WhosonLookup::quote()          — no quoting needed
//   whoson_version_report() → WhosonLookup::version_report() — wso_version() via FFI
//   .name  = "whoson"       → WhosonLookup::driver_name()    — "whoson"
//   .type  = lookup_querystyle → WhosonLookup::lookup_type() — QUERY_STYLE
//
// Registration:
//   C: `whoson_lookup_info` + `whoson_lookup_module_info` in static tables
//   Rust: `inventory::submit!(LookupDriverFactory { ... })` for compile-time
//         collection via the `exim-drivers` registry (AAP §0.7.3).
//
// Per AAP §0.7.2: This file contains ZERO `unsafe` code. All FFI calls are
// made through the safe public API of `exim_ffi::whoson`.
// Per AAP §0.4.2: Uses `inventory::submit!` for compile-time registration.
//
// SPDX-License-Identifier: GPL-2.0-or-later

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;

// =============================================================================
// WHOSON Handle — Stateless Marker
// =============================================================================

/// Handle for WHOSON lookups — stateless since each query is independent.
///
/// In the C code (`whoson.c` line 27), `whoson_open()` returns `(void *)(1)` —
/// a non-null marker indicating the lookup is "open". We use a unit struct as
/// the Rust equivalent, stored inside a [`LookupHandle`] (`Box<dyn Any>`).
///
/// The WHOSON protocol is inherently stateless: each `wso_query()` call is an
/// independent datagram exchange with the WHOSON daemon. No persistent
/// connection or file descriptor is held between queries.
#[derive(Debug)]
struct WhosonHandle;

// =============================================================================
// WhosonLookup — LookupDriver Implementation
// =============================================================================

/// WHOSON (WHO iS ONline) lookup driver.
///
/// Queries the WHOSON daemon to check if an IP address has an authenticated
/// user session. If the IP is found in the WHOSON database, returns the
/// associated user name; otherwise returns `NotFound`.
///
/// The key is the IP address to query (IPv4 or IPv6 string representation).
///
/// # Configuration Example
///
/// In an Exim ACL:
/// ```text
/// # Allow relay if the client IP is in the WHOSON database
/// accept  condition = ${lookup{$sender_host_address}whoson{yes}{no}}
/// ```
///
/// # Thread Safety
///
/// `WhosonLookup` is both `Send` and `Sync` since it holds no mutable state.
/// Each `find()` call is an independent query to the WHOSON daemon via the
/// `exim_ffi::whoson` safe wrapper.
#[derive(Debug)]
pub struct WhosonLookup;

impl WhosonLookup {
    /// Create a new `WhosonLookup` driver instance.
    ///
    /// This is called once during driver initialization via the
    /// `LookupDriverFactory::create` function pointer.
    fn new() -> Self {
        Self
    }
}

impl LookupDriver for WhosonLookup {
    /// Return the driver name: `"whoson"`.
    ///
    /// Matches the C `_lookup_info.name = US"whoson"` field (whoson.c line 74).
    /// Used for configuration file matching and diagnostic output.
    fn driver_name(&self) -> &str {
        "whoson"
    }

    /// Return the lookup type: query-style.
    ///
    /// Matches the C `_lookup_info.type = lookup_querystyle` (whoson.c line 75).
    /// Query-style lookups receive a query string (the IP address) rather than
    /// a file path + key pair.
    fn lookup_type(&self) -> LookupType {
        LookupType::QUERY_STYLE
    }

    /// Open a WHOSON lookup — returns a stateless marker handle.
    ///
    /// Replaces C `whoson_open()` (whoson.c lines 24-28):
    /// ```c
    /// static void *whoson_open(const uschar *filename, uschar **errmsg) {
    ///     return (void *)(1);    /* Just return something non-null */
    /// }
    /// ```
    ///
    /// The `filename` parameter is ignored for query-style lookups.
    fn open(&self, _filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        tracing::debug!("WHOSON: open (stateless — no persistent connection)");
        Ok(Box::new(WhosonHandle))
    }

    /// Check a WHOSON lookup handle — always returns `true`.
    ///
    /// Replaces C `_lookup_info.check = NULL` (whoson.c line 78). When the C
    /// check function pointer is NULL, the lookup framework treats the check
    /// as always passing. We replicate that behavior by returning `Ok(true)`.
    ///
    /// For query-style lookups there is no file to verify permissions on, so
    /// all permission parameters are ignored.
    fn check(
        &self,
        _handle: &LookupHandle,
        _filename: Option<&str>,
        _modemask: i32,
        _owners: &[u32],
        _owngroups: &[u32],
    ) -> Result<bool, DriverError> {
        // Query-style lookup — no file to check permissions on.
        Ok(true)
    }

    /// Query the WHOSON daemon for an IP address.
    ///
    /// Replaces C `whoson_find()` (whoson.c lines 37-56):
    /// ```c
    /// switch (wso_query(CS query, CS buffer, sizeof(buffer))) {
    ///   case 0:  *result = string_copy(buffer); return OK;
    ///   case +1: return FAIL;
    ///   default: *errmsg = ...; return DEFER;
    /// }
    /// ```
    ///
    /// Maps C return codes to Rust `LookupResult` variants:
    ///   - `0` (OK)    → `Found { value: username, cache_ttl: None }`
    ///   - `1` (FAIL)  → `NotFound`
    ///   - other        → `Err(DriverError::TempFail(...))`
    fn find(
        &self,
        handle: &LookupHandle,
        _filename: Option<&str>,
        key_or_query: &str,
        _options: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        // Validate that we received the correct handle type. This is a defensive
        // check — in normal operation, the handle always comes from our open().
        let _whoson_handle = handle
            .downcast_ref::<WhosonHandle>()
            .ok_or_else(|| DriverError::ExecutionFailed("WHOSON: invalid handle type".into()))?;

        tracing::debug!(query = %key_or_query, "WHOSON: querying WHOSON daemon");

        // Call the safe FFI wrapper — all unsafe code is confined to exim-ffi.
        match exim_ffi::whoson::wso_query(key_or_query) {
            Ok(exim_ffi::whoson::WhosonQueryResult::Found(username)) => {
                tracing::debug!(
                    query = %key_or_query,
                    user = %username,
                    "WHOSON: IP found in database"
                );
                Ok(LookupResult::Found {
                    value: username,
                    cache_ttl: None,
                })
            }
            Ok(exim_ffi::whoson::WhosonQueryResult::NotFound) => {
                tracing::debug!(
                    query = %key_or_query,
                    "WHOSON: IP not in database"
                );
                Ok(LookupResult::NotFound)
            }
            Err(e) => {
                // C code: *errmsg = string_sprintf("WHOSON: failed to complete: %s", buffer);
                //         return DEFER;
                let message = format!("WHOSON: failed to complete: {}", e);
                tracing::warn!(
                    query = %key_or_query,
                    error = %e,
                    "WHOSON: query failed — deferring"
                );
                Err(DriverError::TempFail(message))
            }
        }
    }

    /// Close a WHOSON lookup handle — no-op.
    ///
    /// Replaces C `_lookup_info.close = NULL` (whoson.c line 79). The WHOSON
    /// protocol is stateless so there is nothing to close. The handle is
    /// simply dropped (consumed by this method).
    fn close(&self, _handle: LookupHandle) {
        // Stateless — handle is dropped, no resources to release.
        tracing::debug!("WHOSON: close (no-op — stateless)");
    }

    /// Tidy up WHOSON lookup resources — no-op.
    ///
    /// Replaces C `_lookup_info.tidy = NULL` (whoson.c line 80). Called during
    /// periodic cleanup between message processing cycles. The WHOSON driver
    /// holds no cached connections or file handles, so there is nothing to tidy.
    fn tidy(&self) {
        tracing::debug!("WHOSON: tidy (no-op — no cached resources)");
    }

    /// Quote a string for WHOSON lookups — no quoting needed.
    ///
    /// Replaces C `_lookup_info.quote = NULL` (whoson.c line 81). The WHOSON
    /// protocol does not require any special escaping of query strings (they
    /// are plain IP addresses).
    fn quote(&self, _value: &str, _additional: Option<&str>) -> Option<String> {
        None
    }

    /// Report the WHOSON library version for `-bV` output.
    ///
    /// Replaces C `whoson_version_report()` (whoson.c lines 66-71):
    /// ```c
    /// return string_fmt_append(g,
    ///   "Library version: Whoson: Runtime: %s\n", wso_version());
    /// ```
    ///
    /// The output format is preserved byte-for-byte for compatibility with
    /// existing log parsers and administrative tools (AAP §0.7.1).
    fn version_report(&self) -> Option<String> {
        let version = exim_ffi::whoson::wso_version();
        tracing::debug!(version = %version, "WHOSON: version report");
        Some(format!("Library version: Whoson: Runtime: {}", version))
    }
}

// =============================================================================
// Compile-Time Registration
// =============================================================================
//
// Register the WHOSON lookup driver with the inventory-based driver registry.
// This replaces the C static `whoson_lookup_info` + `whoson_lookup_module_info`
// pattern from whoson.c lines 73-90 and the `_lookup_list[]` array.
//
// At link time, inventory collects all submitted `LookupDriverFactory` entries
// from all lookup backend crates. The `DriverRegistry` then iterates over
// them to build the lookup type resolution table used by `search_findtype()`.

inventory::submit! {
    LookupDriverFactory {
        name: "whoson",
        create: || Box::new(WhosonLookup::new()),
        lookup_type: LookupType::QUERY_STYLE,
        avail_string: Some("whoson (FFI, libwhoson)"),
    }
}

// =============================================================================
// Tests
// =============================================================================
//
// Unit tests exercise the WhosonLookup driver logic WITHOUT requiring the
// WHOSON daemon to be running. Tests validate struct creation, trait method
// contracts, driver name/type, and handle management.
//
// Integration tests against a live WHOSON daemon are covered by the existing
// Exim test suite (test/runtest) which runs against the built binary.

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the driver name matches the C registration.
    #[test]
    fn test_whoson_driver_name() {
        let driver = WhosonLookup::new();
        assert_eq!(driver.driver_name(), "whoson");
    }

    /// Verify the lookup type is query-style (matching C `lookup_querystyle`).
    #[test]
    fn test_whoson_lookup_type_is_query_style() {
        let driver = WhosonLookup::new();
        let lt = driver.lookup_type();
        assert!(lt.is_query_style());
        assert!(!lt.is_single_key());
        assert!(!lt.is_abs_file());
        assert_eq!(lt, LookupType::QUERY_STYLE);
    }

    /// Verify open() returns a valid handle (stateless marker).
    #[test]
    fn test_whoson_open_returns_handle() {
        let driver = WhosonLookup::new();
        let handle = driver.open(None);
        assert!(
            handle.is_ok(),
            "open() should succeed for query-style lookup"
        );
        let handle = handle.unwrap();
        // Verify the handle contains our WhosonHandle marker.
        assert!(
            handle.downcast_ref::<WhosonHandle>().is_some(),
            "handle should contain WhosonHandle"
        );
    }

    /// Verify open() ignores filename for query-style lookups.
    #[test]
    fn test_whoson_open_ignores_filename() {
        let driver = WhosonLookup::new();
        let handle = driver.open(Some("/some/path"));
        assert!(
            handle.is_ok(),
            "open() should succeed even with a filename for query-style lookup"
        );
    }

    /// Verify check() always returns true for query-style lookups.
    #[test]
    fn test_whoson_check_always_true() {
        let driver = WhosonLookup::new();
        let handle = driver.open(None).expect("open should succeed");
        let result = driver.check(&handle, None, 0o022, &[], &[]);
        assert!(result.is_ok());
        assert!(
            result.unwrap(),
            "check() must return true for query-style lookups"
        );
    }

    /// Verify check() returns true regardless of permission parameters.
    #[test]
    fn test_whoson_check_ignores_permissions() {
        let driver = WhosonLookup::new();
        let handle = driver.open(None).expect("open should succeed");
        let result = driver.check(&handle, Some("/etc/shadow"), 0o077, &[0, 1000], &[0, 1000]);
        assert!(result.is_ok());
        assert!(
            result.unwrap(),
            "check() must return true regardless of modemask/owners/groups"
        );
    }

    /// Verify close() does not panic (no-op).
    #[test]
    fn test_whoson_close_is_noop() {
        let driver = WhosonLookup::new();
        let handle = driver.open(None).expect("open should succeed");
        // close() takes ownership — should not panic.
        driver.close(handle);
    }

    /// Verify tidy() does not panic (no-op).
    #[test]
    fn test_whoson_tidy_is_noop() {
        let driver = WhosonLookup::new();
        // tidy() should not panic even without any prior open().
        driver.tidy();
    }

    /// Verify quote() returns None (no quoting needed for WHOSON).
    #[test]
    fn test_whoson_quote_returns_none() {
        let driver = WhosonLookup::new();
        assert_eq!(driver.quote("192.168.1.1", None), None);
        assert_eq!(driver.quote("test'value", Some("extra")), None);
    }

    /// Verify find() rejects an invalid handle type.
    #[test]
    fn test_whoson_find_rejects_wrong_handle_type() {
        let driver = WhosonLookup::new();
        // Create a handle with the wrong inner type.
        let wrong_handle: LookupHandle = Box::new(42u32);
        let result = driver.find(&wrong_handle, None, "192.168.1.1", None);
        assert!(result.is_err(), "find() must reject wrong handle type");
        let err = result.unwrap_err();
        let err_msg = format!("{}", err);
        assert!(
            err_msg.contains("invalid handle type"),
            "error should mention invalid handle type, got: {}",
            err_msg
        );
    }

    /// Verify version_report() returns a formatted string matching C output.
    /// Note: This test cannot call the actual FFI function without libwhoson,
    /// so we only verify the method returns Some(...) with the expected prefix.
    /// The integration test suite verifies the actual version string.
    #[cfg(feature = "lookup-whoson")]
    #[test]
    fn test_whoson_version_report_format() {
        let driver = WhosonLookup::new();
        let report = driver.version_report();
        assert!(report.is_some(), "version_report should return Some");
        let report = report.unwrap();
        assert!(
            report.starts_with("Library version: Whoson: Runtime: "),
            "version report should match C format, got: {}",
            report
        );
    }

    /// Verify that WhosonLookup implements Debug.
    #[test]
    fn test_whoson_debug_impl() {
        let driver = WhosonLookup::new();
        let debug_str = format!("{:?}", driver);
        assert!(
            debug_str.contains("WhosonLookup"),
            "debug output should contain struct name"
        );
    }

    /// Verify that WhosonLookup is Send + Sync (required by LookupDriver).
    #[test]
    fn test_whoson_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WhosonLookup>();
    }

    /// Verify that WhosonHandle is Send + Sync (required for LookupHandle).
    #[test]
    fn test_whoson_handle_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WhosonHandle>();
    }
}
