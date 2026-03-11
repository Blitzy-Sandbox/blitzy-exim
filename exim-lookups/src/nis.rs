// =============================================================================
// exim-lookups/src/nis.rs — NIS (Yellow Pages) Lookup Backend (FFI)
// =============================================================================
//
// Rewrites `src/src/lookups/nis.c` (143 lines) as a Rust module that delegates
// all NIS/YP operations to the `exim-ffi::nis` safe FFI wrapper. Provides two
// lookup variants: `nis` (key without null terminator) and `nis0` (key with
// null terminator included in length).
//
// C function mapping:
//   nis_open()  → NisLookup::open()  — get default NIS domain
//   nis_find()  → NisLookup::find()  — yp_match without null
//   nis0_find() → Nis0Lookup::find() — yp_match with null terminator in key
//   nis_close() → NisLookup::close() — no-op (stateless)
//
// Per AAP §0.7.2: This file contains ZERO `unsafe` code.
// Per AAP §0.4.2: Uses `inventory::submit!` for compile-time registration.

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;

// =============================================================================
// NIS Handle
// =============================================================================

/// Handle for NIS lookups — stores the default NIS domain name.
///
/// In the C code, `nis_open()` calls `yp_get_default_domain()` and stores
/// the domain name as the returned handle. We store it as a String.
struct NisHandle {
    /// The NIS domain name obtained from `yp_get_default_domain()`.
    domain: String,
}

// =============================================================================
// NIS Lookup Drivers
// =============================================================================

/// NIS (Yellow Pages) lookup driver — standard key (no trailing null).
///
/// The key is looked up in the specified NIS map using `yp_match()`.
/// The map name is provided as the filename parameter in the lookup
/// specification: `${lookup nis{map}{key}}`.
#[derive(Debug)]
struct NisLookup;

/// NIS lookup driver — null-terminated key variant.
///
/// Same as NisLookup but includes the null terminator in the key length
/// passed to `yp_match()`. Some NIS maps store keys with null terminators.
#[derive(Debug)]
struct Nis0Lookup;

impl NisLookup {
    fn new() -> Self {
        Self
    }
}

impl Nis0Lookup {
    fn new() -> Self {
        Self
    }
}

/// Shared implementation for both NIS variants.
fn nis_find_impl(
    handle: &LookupHandle,
    filename: Option<&str>,
    key: &str,
    include_nul: bool,
) -> Result<LookupResult, DriverError> {
    let nis_handle = handle
        .downcast_ref::<NisHandle>()
        .ok_or_else(|| DriverError::ExecutionFailed("NIS: invalid handle type".into()))?;

    let map = filename.ok_or_else(|| {
        DriverError::ExecutionFailed("NIS: map name (filename) is required".into())
    })?;

    // Build the key bytes. For nis0, include the trailing null byte.
    let key_bytes: Vec<u8> = if include_nul {
        let mut kb = key.as_bytes().to_vec();
        kb.push(0);
        kb
    } else {
        key.as_bytes().to_vec()
    };

    tracing::debug!(
        domain = %nis_handle.domain,
        map = %map,
        key = %key,
        include_nul = include_nul,
        "NIS: performing yp_match lookup"
    );

    match exim_ffi::nis::yp_match_query(&nis_handle.domain, map, &key_bytes) {
        Ok(value_bytes) => {
            // Convert result to UTF-8 string, trimming any trailing null/newline.
            let mut value = String::from_utf8_lossy(&value_bytes).into_owned();
            // NIS results often have trailing newlines — trim them.
            while value.ends_with('\n') || value.ends_with('\0') {
                value.pop();
            }
            tracing::debug!(
                key = %key,
                value_len = value.len(),
                "NIS: key found"
            );
            Ok(LookupResult::Found {
                value,
                cache_ttl: None,
            })
        }
        Err(e) => {
            // Check if it's a "key not found" error vs a real failure.
            let err_str = format!("{}", e);
            if err_str.contains("key not found") || err_str.contains("No such key") {
                tracing::debug!(key = %key, "NIS: key not found");
                Ok(LookupResult::NotFound)
            } else {
                tracing::warn!(key = %key, error = %e, "NIS: lookup error");
                Err(DriverError::ExecutionFailed(format!(
                    "NIS: yp_match failed for key '{}' in map '{}': {}",
                    key, map, e
                )))
            }
        }
    }
}

impl LookupDriver for NisLookup {
    fn driver_name(&self) -> &str {
        "nis"
    }

    fn lookup_type(&self) -> LookupType {
        LookupType::SINGLE_KEY
    }

    fn open(&self, _filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        tracing::debug!("NIS: opening — getting default domain");
        let domain = exim_ffi::nis::get_default_domain().map_err(|e| {
            DriverError::ExecutionFailed(format!("NIS: failed to get default NIS domain: {}", e))
        })?;
        tracing::debug!(domain = %domain, "NIS: default domain obtained");
        Ok(Box::new(NisHandle { domain }))
    }

    fn find(
        &self,
        handle: &LookupHandle,
        filename: Option<&str>,
        key: &str,
        _opts: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        nis_find_impl(handle, filename, key, false)
    }

    fn close(&self, _handle: LookupHandle) {
        tracing::debug!("NIS: closed (no-op)");
    }

    fn tidy(&self) {
        tracing::debug!("NIS: tidy (no-op)");
    }

    fn version_report(&self) -> Option<String> {
        Some("Lookup: nis (Rust, FFI to libnsl)".to_string())
    }
}

impl LookupDriver for Nis0Lookup {
    fn driver_name(&self) -> &str {
        "nis0"
    }

    fn lookup_type(&self) -> LookupType {
        LookupType::SINGLE_KEY
    }

    fn open(&self, _filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        tracing::debug!("NIS0: opening — getting default domain");
        let domain = exim_ffi::nis::get_default_domain().map_err(|e| {
            DriverError::ExecutionFailed(format!("NIS0: failed to get default NIS domain: {}", e))
        })?;
        Ok(Box::new(NisHandle { domain }))
    }

    fn find(
        &self,
        handle: &LookupHandle,
        filename: Option<&str>,
        key: &str,
        _opts: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        nis_find_impl(handle, filename, key, true)
    }

    fn close(&self, _handle: LookupHandle) {
        tracing::debug!("NIS0: closed (no-op)");
    }

    fn tidy(&self) {
        tracing::debug!("NIS0: tidy (no-op)");
    }

    fn version_report(&self) -> Option<String> {
        Some("Lookup: nis0 (Rust, FFI to libnsl)".to_string())
    }
}

// =============================================================================
// Compile-Time Registration
// =============================================================================

inventory::submit! {
    LookupDriverFactory {
        name: "nis",
        create: || Box::new(NisLookup::new()),
        lookup_type: LookupType::SINGLE_KEY,
        avail_string: Some("nis (FFI)"),
    }
}

inventory::submit! {
    LookupDriverFactory {
        name: "nis0",
        create: || Box::new(Nis0Lookup::new()),
        lookup_type: LookupType::SINGLE_KEY,
        avail_string: Some("nis0 (FFI)"),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nis_driver_name() {
        let driver = NisLookup::new();
        assert_eq!(driver.driver_name(), "nis");
    }

    #[test]
    fn test_nis0_driver_name() {
        let driver = Nis0Lookup::new();
        assert_eq!(driver.driver_name(), "nis0");
    }

    #[test]
    fn test_nis_lookup_type() {
        let driver = NisLookup::new();
        assert!(driver.lookup_type().is_single_key());
    }

    #[test]
    fn test_nis_version_report() {
        let driver = NisLookup::new();
        let report = driver.version_report();
        assert!(report.is_some());
        assert!(report.unwrap().contains("nis"));
    }

    #[test]
    fn test_nis0_version_report() {
        let driver = Nis0Lookup::new();
        let report = driver.version_report();
        assert!(report.is_some());
        assert!(report.unwrap().contains("nis0"));
    }
}
