// =============================================================================
// exim-lookups/src/nisplus.rs — NIS+ Lookup Backend (FFI)
// =============================================================================
//
// Rewrites `src/src/lookups/nisplus.c` (295 lines) as a Rust module that
// delegates all NIS+ operations to the `exim-ffi::nisplus` safe FFI wrapper.
//
// NIS+ (Network Information Service Plus) provides hierarchical directory
// service lookups. The lookup key format is a fully-qualified NIS+ indexed
// name such as `[name=value],table.org_dir.domain.`.
//
// C function mapping:
//   nisplus_open()  → NisplusLookup::open()  — no-op (connectionless)
//   nisplus_find()  → NisplusLookup::find()  — nis_list() with indexed name
//   nisplus_close() → NisplusLookup::close() — no-op
//
// Per AAP §0.7.2: This file contains ZERO `unsafe` code.
// Per AAP §0.4.2: Uses `inventory::submit!` for compile-time registration.

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;

// =============================================================================
// NIS+ Handle — stateless marker
// =============================================================================

/// Handle for NIS+ lookups — stateless since NIS+ is session-less.
struct NisplusHandle;

// =============================================================================
// NisplusLookup — LookupDriver implementation
// =============================================================================

/// NIS+ directory service lookup driver.
///
/// Performs NIS+ table lookups using indexed names. The key is an NIS+
/// indexed name that specifies the table, search criteria, and columns:
///
/// ```text
/// [name=value,name=value,...],table.org_dir.domain.
/// ```
///
/// Results are formatted with columns separated by spaces and rows
/// separated by newlines, matching the C behavior.
#[derive(Debug)]
struct NisplusLookup;

impl NisplusLookup {
    fn new() -> Self {
        Self
    }
}

impl LookupDriver for NisplusLookup {
    fn driver_name(&self) -> &str {
        "nisplus"
    }

    fn lookup_type(&self) -> LookupType {
        LookupType::QUERY_STYLE
    }

    fn open(&self, _filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        tracing::debug!("NIS+: open (connectionless)");
        Ok(Box::new(NisplusHandle))
    }

    fn find(
        &self,
        handle: &LookupHandle,
        _filename: Option<&str>,
        key: &str,
        _opts: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        let _nisplus_handle = handle
            .downcast_ref::<NisplusHandle>()
            .ok_or_else(|| DriverError::ExecutionFailed("NIS+: invalid handle type".into()))?;

        if key.is_empty() {
            return Err(DriverError::ExecutionFailed(
                "NIS+: empty key (indexed name required)".into(),
            ));
        }

        tracing::debug!(key = %key, "NIS+: performing table lookup");

        // Delegate to the FFI layer. The key is the full NIS+ indexed name.
        match exim_ffi::nisplus::nis_list_query(key) {
            Ok(result) => {
                match result {
                    exim_ffi::nisplus::NisplusQueryResult::Found(entries) => {
                        if entries.is_empty() {
                            tracing::debug!(key = %key, "NIS+: no entries found");
                            return Ok(LookupResult::NotFound);
                        }

                        // Format results: space-separated columns, newline-separated rows.
                        let mut output = String::new();
                        for (i, entry) in entries.iter().enumerate() {
                            if i > 0 {
                                output.push('\n');
                            }
                            // Each entry has columns; join with spaces.
                            let cols: Vec<&str> =
                                entry.columns.iter().map(|c| c.value.as_str()).collect();
                            output.push_str(&cols.join(" "));
                        }

                        tracing::debug!(
                            key = %key,
                            entry_count = entries.len(),
                            "NIS+: entries found"
                        );

                        Ok(LookupResult::Found {
                            value: output,
                            cache_ttl: None,
                        })
                    }
                    exim_ffi::nisplus::NisplusQueryResult::NotFound => {
                        tracing::debug!(key = %key, "NIS+: not found");
                        Ok(LookupResult::NotFound)
                    }
                }
            }
            Err(e) => {
                tracing::warn!(key = %key, error = %e, "NIS+: lookup error");
                Err(DriverError::ExecutionFailed(format!(
                    "NIS+: table lookup failed for '{}': {}",
                    key, e
                )))
            }
        }
    }

    fn close(&self, _handle: LookupHandle) {
        tracing::debug!("NIS+: closed (no-op)");
    }

    fn tidy(&self) {
        tracing::debug!("NIS+: tidy (no-op)");
    }

    fn version_report(&self) -> Option<String> {
        Some("Lookup: nisplus (Rust, FFI to libnsl)".to_string())
    }
}

// =============================================================================
// Compile-Time Registration
// =============================================================================

inventory::submit! {
    LookupDriverFactory {
        name: "nisplus",
        create: || Box::new(NisplusLookup::new()),
        lookup_type: LookupType::QUERY_STYLE,
        avail_string: Some("nisplus (FFI)"),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nisplus_driver_name() {
        let driver = NisplusLookup::new();
        assert_eq!(driver.driver_name(), "nisplus");
    }

    #[test]
    fn test_nisplus_lookup_type() {
        let driver = NisplusLookup::new();
        assert!(driver.lookup_type().is_query_style());
    }

    #[test]
    fn test_nisplus_version_report() {
        let driver = NisplusLookup::new();
        let report = driver.version_report();
        assert!(report.is_some());
        assert!(report.unwrap().contains("nisplus"));
    }
}
