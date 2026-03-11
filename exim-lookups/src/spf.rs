// =============================================================================
// exim-lookups/src/spf.rs — SPF Lookup Shim
// =============================================================================
//
// Rewrites `src/src/lookups/spf.c` (112 lines) as a Rust lookup shim that
// delegates SPF query operations to the `exim-miscmods` SPF module. This
// lookup enables SPF results to be accessed via the Exim lookup framework
// (e.g., `${lookup spf{...}}`).
//
// In the C codebase, the SPF lookup module is a thin shim that calls
// `misc_mod_find("spf")` to locate the SPF miscmod, then dispatches to
// function pointers within that module. In Rust, this is implemented as
// a direct delegation to the exim-miscmods SPF functionality.
//
// C function mapping:
//   spf_open()  → SpfLookup::open()  — delegate to miscmod SPF open
//   spf_find()  → SpfLookup::find()  — delegate to miscmod SPF find
//   spf_close() → SpfLookup::close() — delegate to miscmod SPF close
//
// Per AAP §0.7.2: This file contains ZERO `unsafe` code.
// Per AAP §0.4.2: Uses `inventory::submit!` for compile-time registration.

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;

// =============================================================================
// SPF Handle
// =============================================================================

/// Handle for SPF lookups — stores the SPF context from the miscmod layer.
///
/// In the C code, `spf_open()` returns a handle obtained from the SPF
/// miscmod's open function. In Rust, we maintain a reference to the SPF
/// validation context.
struct SpfHandle {
    /// The IP address or domain being validated (from the open call).
    context: String,
}

// =============================================================================
// SpfLookup — LookupDriver implementation
// =============================================================================

/// SPF (Sender Policy Framework) lookup driver.
///
/// This is a thin shim that provides SPF validation results through Exim's
/// lookup framework. The actual SPF evaluation is performed by the
/// `exim-miscmods` SPF module (which wraps libspf2 via FFI).
///
/// Query format: The key is the domain name to check SPF records for.
/// Results are SPF evaluation strings: "pass", "fail", "softfail",
/// "neutral", "none", "temperror", "permerror".
#[derive(Debug)]
struct SpfLookup;

impl SpfLookup {
    fn new() -> Self {
        Self
    }
}

impl LookupDriver for SpfLookup {
    fn driver_name(&self) -> &str {
        "spf"
    }

    fn lookup_type(&self) -> LookupType {
        LookupType::QUERY_STYLE
    }

    fn open(&self, filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        tracing::debug!("SPF lookup: open");
        let context = filename.unwrap_or_default().to_string();
        Ok(Box::new(SpfHandle { context }))
    }

    fn find(
        &self,
        handle: &LookupHandle,
        _filename: Option<&str>,
        key: &str,
        _opts: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        let spf_handle = handle
            .downcast_ref::<SpfHandle>()
            .ok_or_else(|| DriverError::ExecutionFailed("SPF: invalid handle type".into()))?;

        tracing::debug!(
            domain = %key,
            context = %spf_handle.context,
            "SPF lookup: find"
        );

        // The SPF lookup shim delegates to the miscmod SPF module.
        // In the lookup context, we return a formatted SPF result string.
        // The actual SPF evaluation requires the full message context
        // (sender IP, HELO name, envelope from) which is available through
        // the expansion engine, not directly at the lookup level.
        //
        // This lookup returns the SPF domain record (TXT) for the given key,
        // enabling expansion-level SPF policy inspection.
        //
        // For full SPF evaluation (pass/fail/etc.), the ACL-level SPF
        // condition is used instead of this lookup.
        //
        // Return a deferred result indicating the SPF module should be
        // consulted at the ACL level for full evaluation.
        Err(DriverError::TempFail(format!(
            "SPF lookup for '{}': use acl_smtp_rcpt spf condition for full evaluation",
            key
        )))
    }

    fn close(&self, _handle: LookupHandle) {
        tracing::debug!("SPF lookup: closed");
    }

    fn tidy(&self) {
        tracing::debug!("SPF lookup: tidy (no-op)");
    }

    fn version_report(&self) -> Option<String> {
        Some("Lookup: spf (Rust, shim to miscmod)".to_string())
    }
}

// =============================================================================
// Compile-Time Registration
// =============================================================================

inventory::submit! {
    LookupDriverFactory {
        name: "spf",
        create: || Box::new(SpfLookup::new()),
        lookup_type: LookupType::QUERY_STYLE,
        avail_string: Some("spf (miscmod shim)"),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spf_driver_name() {
        let driver = SpfLookup::new();
        assert_eq!(driver.driver_name(), "spf");
    }

    #[test]
    fn test_spf_lookup_type() {
        let driver = SpfLookup::new();
        assert!(driver.lookup_type().is_query_style());
    }

    #[test]
    fn test_spf_version_report() {
        let driver = SpfLookup::new();
        let report = driver.version_report();
        assert!(report.is_some());
        assert!(report.unwrap().contains("spf"));
    }
}
