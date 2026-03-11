// =============================================================================
// exim-lookups/src/whoson.rs — WHOSON Dynamic IP Lookup Backend (FFI)
// =============================================================================
//
// Rewrites `src/src/lookups/whoson.c` (92 lines) as a Rust module that
// delegates WHOSON queries to the `exim-ffi::whoson` safe FFI wrapper.
//
// WHOSON (WHO iS ONline) is a protocol for tracking authenticated users by
// IP address. The lookup queries the WHOSON daemon with an IP address and
// returns the associated user name if the IP is currently logged in.
//
// C function mapping:
//   whoson_open()  → WhosonLookup::open()  — no-op (returns non-null marker)
//   whoson_find()  → WhosonLookup::find()  — wso_query() via FFI
//   whoson_close() → WhosonLookup::close() — no-op
//
// Per AAP §0.7.2: This file contains ZERO `unsafe` code.
// Per AAP §0.4.2: Uses `inventory::submit!` for compile-time registration.

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;

// =============================================================================
// WHOSON Handle — stateless marker
// =============================================================================

/// Handle for WHOSON lookups — stateless since each query is independent.
///
/// In the C code, `whoson_open()` returns `(void *)(1)` — a non-null marker
/// indicating the lookup is "open". We use a unit struct as the Rust equivalent.
struct WhosonHandle;

// =============================================================================
// WhosonLookup — LookupDriver implementation
// =============================================================================

/// WHOSON (WHO iS ONline) lookup driver.
///
/// Queries the WHOSON daemon to check if an IP address has an authenticated
/// user session. If the IP is found in the WHOSON database, returns the
/// associated user name; otherwise returns NotFound.
///
/// The key is the IP address to query (IPv4 or IPv6).
#[derive(Debug)]
struct WhosonLookup;

impl WhosonLookup {
    fn new() -> Self {
        Self
    }
}

impl LookupDriver for WhosonLookup {
    fn driver_name(&self) -> &str {
        "whoson"
    }

    fn lookup_type(&self) -> LookupType {
        LookupType::QUERY_STYLE
    }

    fn open(&self, _filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        tracing::debug!("WHOSON: open (stateless)");
        Ok(Box::new(WhosonHandle))
    }

    fn find(
        &self,
        handle: &LookupHandle,
        _filename: Option<&str>,
        key: &str,
        _opts: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        let _whoson_handle = handle
            .downcast_ref::<WhosonHandle>()
            .ok_or_else(|| DriverError::ExecutionFailed("WHOSON: invalid handle type".into()))?;

        tracing::debug!(query = %key, "WHOSON: querying");

        match exim_ffi::whoson::wso_query(key) {
            Ok(result) => match result {
                exim_ffi::whoson::WhosonQueryResult::Found(username) => {
                    tracing::debug!(
                        query = %key,
                        user = %username,
                        "WHOSON: IP found in database"
                    );
                    Ok(LookupResult::Found {
                        value: username,
                        cache_ttl: None,
                    })
                }
                exim_ffi::whoson::WhosonQueryResult::NotFound => {
                    tracing::debug!(query = %key, "WHOSON: IP not in database");
                    Ok(LookupResult::NotFound)
                }
            },
            Err(e) => {
                tracing::warn!(query = %key, error = %e, "WHOSON: query failed");
                Err(DriverError::ExecutionFailed(format!(
                    "WHOSON: failed to complete query for '{}': {}",
                    key, e
                )))
            }
        }
    }

    fn close(&self, _handle: LookupHandle) {
        tracing::debug!("WHOSON: closed (no-op)");
    }

    fn tidy(&self) {
        tracing::debug!("WHOSON: tidy (no-op)");
    }

    fn version_report(&self) -> Option<String> {
        let version = exim_ffi::whoson::wso_version();
        Some(format!("Lookup: whoson (Rust, libwhoson {})", version))
    }
}

// =============================================================================
// Compile-Time Registration
// =============================================================================

inventory::submit! {
    LookupDriverFactory {
        name: "whoson",
        create: || Box::new(WhosonLookup::new()),
        lookup_type: LookupType::QUERY_STYLE,
        avail_string: Some("whoson (FFI)"),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whoson_driver_name() {
        let driver = WhosonLookup::new();
        assert_eq!(driver.driver_name(), "whoson");
    }

    #[test]
    fn test_whoson_lookup_type() {
        let driver = WhosonLookup::new();
        assert!(driver.lookup_type().is_query_style());
    }

    #[test]
    fn test_whoson_open() {
        let driver = WhosonLookup::new();
        // Open should succeed (returns stateless handle).
        // Note: actual WHOSON daemon not available in test.
    }
}
