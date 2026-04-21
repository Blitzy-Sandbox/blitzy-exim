// =============================================================================
// exim-lookups/src/spf.rs — SPF Lookup Shim (Delegates to exim-miscmods)
// =============================================================================
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Rewrites `src/src/lookups/spf.c` (113 lines) as a Rust lookup shim that
// delegates SPF query operations to the `exim-miscmods` SPF module.  This
// lookup enables SPF results to be accessed via the Exim lookup framework
// (e.g., `${lookup spf{...}}`).
//
// In the C codebase, the SPF lookup module was a thin shim that called
// `misc_mod_find("spf")` to locate the SPF miscmod at runtime, then
// dispatched to function pointers within that module's function table.
//
// In Rust, the same pattern is implemented using a [`SpfDelegate`] trait and
// a process-global [`OnceLock`] registration point.  The `exim-miscmods` SPF
// module registers its delegate at startup via [`register_spf_delegate`], and
// the [`SpfLookup`] driver forwards all trait method calls to that delegate.
// When the miscmod is not loaded/available, operations return appropriate
// errors matching the C behavior (NULL / FAIL).
//
// C function mapping:
//   spf_open()           → SpfLookup::open()           — delegate to miscmod
//   spf_find()           → SpfLookup::find()           — delegate to miscmod
//   spf_close()          → SpfLookup::close()          — delegate to miscmod
//   spf_version_report() → SpfLookup::version_report() — delegate to miscmod
//   (no check in C)      → SpfLookup::check()          — always Ok(true)
//   (no tidy in C)       → SpfLookup::tidy()           — no-op
//   (no quote in C)      → SpfLookup::quote()          — default None
//
// Per AAP §0.7.2: This file contains ZERO `unsafe` code.
// Per AAP §0.4.2: Uses `inventory::submit!` for compile-time registration.

use std::sync::OnceLock;

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;

use crate::LookupError;

// =============================================================================
// SPF Miscmod Delegate Interface
// =============================================================================

/// Trait defining the delegation interface for the SPF miscmod.
///
/// The SPF lookup module is a thin shim — all actual SPF evaluation logic
/// resides in the `exim-miscmods` crate (which wraps `libspf2` via FFI).
/// This trait defines the operations that the miscmod must implement and
/// register for the lookup shim to function.
///
/// In C, these corresponded to entries in the `misc_module_info::functions`
/// array at indices `SPF_OPEN`, `SPF_FIND`, and `SPF_CLOSE`.
///
/// # Registration
///
/// The miscmod registers its delegate at program startup by calling
/// [`register_spf_delegate`] with a boxed implementation.  Only the first
/// registration succeeds; subsequent calls are silently ignored.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` because the delegate is stored in a
/// process-global `OnceLock` and may be accessed from multiple child processes
/// after fork.
pub trait SpfDelegate: Send + Sync + 'static {
    /// Open an SPF lookup context.
    ///
    /// C equivalent: `((fn_t *) mi->functions)[SPF_OPEN](filename, errmsg)`
    fn open(&self, filename: Option<&str>) -> Result<LookupHandle, DriverError>;

    /// Execute an SPF lookup / evaluation for the given query.
    ///
    /// C equivalent: `((fn_t *) mi->functions)[SPF_FIND](handle, filename,
    ///                keystring, key_len, result, errmsg, do_cache, opts)`
    fn find(
        &self,
        handle: &LookupHandle,
        filename: Option<&str>,
        key_or_query: &str,
        options: Option<&str>,
    ) -> Result<LookupResult, DriverError>;

    /// Close an SPF lookup handle, releasing associated resources.
    ///
    /// C equivalent: `((fn_t *) mi->functions)[SPF_CLOSE](handle)`
    fn close(&self, handle: LookupHandle);

    /// Return version information from the underlying SPF library.
    ///
    /// C equivalent: `mi->lib_vers_report(g)` — delegates to the miscmod's
    /// library version reporting function, if present.
    fn version_report(&self) -> Option<String>;
}

// =============================================================================
// Global Delegate Registration
// =============================================================================

/// Process-global storage for the registered SPF miscmod delegate.
///
/// Set once at program startup by the miscmod initialization code via
/// [`register_spf_delegate`].  Read by all subsequent SPF lookup operations.
/// Using `OnceLock` ensures thread-safe initialization without runtime cost
/// on subsequent reads.
static SPF_DELEGATE: OnceLock<Box<dyn SpfDelegate>> = OnceLock::new();

/// Register the SPF miscmod delegate for lookup shim operations.
///
/// This function is called by the `exim-miscmods` SPF module during program
/// initialization to provide the actual SPF evaluation implementation.  It
/// can only be called successfully once — subsequent calls return `false` and
/// the new delegate is discarded.
///
/// # Arguments
///
/// * `delegate` — Boxed implementation of [`SpfDelegate`] providing SPF
///   evaluation via `libspf2` or equivalent.
///
/// # Returns
///
/// `true` if registration succeeded (first call), `false` if a delegate was
/// already registered.
///
/// # Example
///
/// ```ignore
/// // In exim-miscmods SPF initialization:
/// use exim_lookups::spf::{register_spf_delegate, SpfDelegate};
///
/// struct LibSpf2Delegate;
/// impl SpfDelegate for LibSpf2Delegate { /* ... */ }
///
/// register_spf_delegate(Box::new(LibSpf2Delegate));
/// ```
pub fn register_spf_delegate(delegate: Box<dyn SpfDelegate>) -> bool {
    SPF_DELEGATE.set(delegate).is_ok()
}

/// Retrieve the registered SPF miscmod delegate, if any.
///
/// Returns `None` if [`register_spf_delegate`] has not been called yet,
/// meaning the SPF miscmod is not loaded/available.
///
/// C equivalent: `misc_mod_find(US"spf", errmsg)` returning NULL when the
/// module is not loaded.
fn get_spf_delegate() -> Option<&'static dyn SpfDelegate> {
    SPF_DELEGATE.get().map(|d| d.as_ref())
}

// =============================================================================
// SpfLookup — LookupDriver Implementation
// =============================================================================

/// SPF (Sender Policy Framework) lookup driver — thin shim to miscmod.
///
/// This struct implements the [`LookupDriver`] trait as a delegation shim.
/// All actual SPF operations (open, find, close, version reporting) are
/// forwarded to the SPF miscmod registered via [`register_spf_delegate`].
/// When the miscmod is not available, operations return appropriate errors:
///
/// - `open()` → `DriverError::NotFound` (C returned NULL)
/// - `find()` → `DriverError::ExecutionFailed` (C returned FAIL)
/// - `close()` → silent no-op (C was also a no-op when miscmod absent)
/// - `version_report()` → `None` (C returned input gstring unchanged)
///
/// # C Source
///
/// Replaces `src/src/lookups/spf.c` (113 lines) which contained:
/// - `spf_open()` — delegated via `misc_mod_find("spf")->functions[SPF_OPEN]`
/// - `spf_find()` — delegated via `misc_mod_find("spf")->functions[SPF_FIND]`
/// - `spf_close()` — delegated via `misc_mod_find("spf")->functions[SPF_CLOSE]`
/// - `spf_version_report()` — delegated via `mi->lib_vers_report`
/// - `spf_lookup_info` — static struct with `.type = 0`, `.name = "spf"`
///
/// # Registration
///
/// Registered at compile time via `inventory::submit!` as the `"spf"` lookup
/// type with query-style semantics.
#[derive(Debug)]
pub struct SpfLookup;

impl SpfLookup {
    /// Create a new SPF lookup driver instance.
    ///
    /// The instance is stateless — all per-query state is maintained in the
    /// [`LookupHandle`] returned by `open()`, which is managed by the
    /// registered SPF miscmod delegate.
    pub fn new() -> Self {
        Self
    }
}

impl Default for SpfLookup {
    fn default() -> Self {
        Self::new()
    }
}

impl LookupDriver for SpfLookup {
    /// Open an SPF lookup context by delegating to the SPF miscmod.
    ///
    /// C equivalent: `spf_open()` in `spf.c` lines 34-45.
    ///
    /// If the SPF miscmod is not loaded, returns `DriverError::NotFound`
    /// (matching C behavior where `misc_mod_find()` returns NULL and
    /// `spf_open()` returns NULL to the caller).
    fn open(&self, filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        tracing::debug!("spf lookup spf_open");

        match get_spf_delegate() {
            Some(delegate) => delegate.open(filename),
            None => {
                // SPF miscmod not loaded/available — create internal error
                // for context, then return DriverError for the trait interface.
                let lookup_err = LookupError::OpenFailed(
                    "SPF miscmod not loaded — ensure the spf module is enabled".to_string(),
                );
                tracing::warn!("{}", lookup_err);
                Err(DriverError::NotFound {
                    name: "spf".to_string(),
                })
            }
        }
    }

    /// Check an SPF lookup source for validity — always passes.
    ///
    /// C equivalent: `.check = NULL` in `spf_lookup_info` — no check function
    /// was defined for the SPF lookup.  Since SPF is a query-style shim with
    /// no associated file or resource to validate, this always returns
    /// `Ok(true)`.
    fn check(
        &self,
        _handle: &LookupHandle,
        _filename: Option<&str>,
        _modemask: i32,
        _owners: &[u32],
        _owngroups: &[u32],
    ) -> Result<bool, DriverError> {
        Ok(true)
    }

    /// Perform an SPF lookup by delegating to the SPF miscmod.
    ///
    /// C equivalent: `spf_find()` in `spf.c` lines 60-75.
    ///
    /// The query string (`key_or_query`) is passed through to the miscmod's
    /// find function along with the handle and optional lookup options.
    ///
    /// If the SPF miscmod is not loaded, returns `DriverError::ExecutionFailed`
    /// (matching C behavior where `spf_find()` returns `FAIL` when
    /// `misc_mod_find()` returns NULL).
    fn find(
        &self,
        handle: &LookupHandle,
        filename: Option<&str>,
        key_or_query: &str,
        options: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        tracing::debug!(key = %key_or_query, "spf lookup spf_find");

        match get_spf_delegate() {
            Some(delegate) => {
                let result = delegate.find(handle, filename, key_or_query, options)?;

                // Log the result for diagnostic visibility, matching the C
                // DEBUG(D_lookup) pattern for lookup troubleshooting.
                match &result {
                    LookupResult::Found { value, .. } => {
                        tracing::debug!(value = %value, "SPF lookup: found result");
                    }
                    LookupResult::NotFound => {
                        tracing::debug!("SPF lookup: key not found");
                    }
                    LookupResult::Deferred { message } => {
                        tracing::debug!(reason = %message, "SPF lookup: deferred");
                    }
                }

                Ok(result)
            }
            None => {
                // C returns FAIL when miscmod not found
                tracing::warn!("SPF lookup find: miscmod not available");
                Err(DriverError::ExecutionFailed(
                    "SPF miscmod not available for find operation".to_string(),
                ))
            }
        }
    }

    /// Close an SPF lookup handle by delegating to the SPF miscmod.
    ///
    /// C equivalent: `spf_close()` in `spf.c` lines 48-57.
    ///
    /// If the SPF miscmod is not loaded, the handle is silently dropped
    /// (matching C behavior where `spf_close()` is a no-op when
    /// `misc_mod_find()` returns NULL — Rust's `Drop` handles cleanup).
    fn close(&self, handle: LookupHandle) {
        tracing::debug!("spf lookup: close");
        if let Some(delegate) = get_spf_delegate() {
            delegate.close(handle);
        }
        // If no delegate, the handle is dropped here — Rust's Drop trait
        // ensures any resources owned by the handle are properly released.
    }

    /// Tidy up SPF lookup resources — no-op for this shim.
    ///
    /// C equivalent: `.tidy = NULL` in `spf_lookup_info` — no tidy function
    /// was defined for the SPF lookup.  The miscmod manages its own resources
    /// independently of the lookup shim layer.
    fn tidy(&self) {
        // Intentionally empty — matches C NULL tidy function pointer.
    }

    // `quote()` uses the default trait implementation (returns `None`).
    // C equivalent: `.quote = NULL` in `spf_lookup_info`.

    /// Report SPF library version information by delegating to the miscmod.
    ///
    /// C equivalent: `spf_version_report()` in `spf.c` lines 84-89.
    ///
    /// If the SPF miscmod is loaded and provides a version report function
    /// (`lib_vers_report`), returns that report.  Otherwise returns `None`
    /// (matching C behavior where the input `gstring` was returned unchanged).
    fn version_report(&self) -> Option<String> {
        match get_spf_delegate() {
            Some(delegate) => {
                tracing::debug!("SPF lookup: requesting version report from miscmod");
                delegate.version_report()
            }
            None => None,
        }
    }

    /// SPF lookup type — query-style.
    ///
    /// C equivalent: `.type = 0` in `spf_lookup_info`.
    ///
    /// In the Rust architecture, SPF is classified as query-style since it
    /// accepts a query (domain/IP to evaluate) rather than a file+key pair.
    fn lookup_type(&self) -> LookupType {
        LookupType::QUERY_STYLE
    }

    /// Driver name for configuration file matching.
    ///
    /// C equivalent: `.name = US"spf"` in `spf_lookup_info`.
    fn driver_name(&self) -> &str {
        "spf"
    }
}

// =============================================================================
// Compile-Time Registration via inventory
// =============================================================================
//
// Replaces the C `spf_lookup_module_info` exported symbol and the
// `LOOKUP_MODULE_INFO_MAGIC` registration pattern from `lookupapi.h`.
// The submitted factory is collected by `inventory::collect!(LookupDriverFactory)`
// in `exim-drivers/src/registry.rs` for runtime driver resolution by name.

inventory::submit! {
    LookupDriverFactory {
        name: "spf",
        create: || Box::new(SpfLookup::new()),
        lookup_type: LookupType::QUERY_STYLE,
        avail_string: Some("spf (miscmod shim)"),
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Driver metadata tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_spf_driver_name() {
        let driver = SpfLookup::new();
        assert_eq!(driver.driver_name(), "spf");
    }

    #[test]
    fn test_spf_lookup_type_is_query_style() {
        let driver = SpfLookup::new();
        assert_eq!(driver.lookup_type(), LookupType::QUERY_STYLE);
        assert!(driver.lookup_type().is_query_style());
        assert!(!driver.lookup_type().is_single_key());
    }

    // -------------------------------------------------------------------------
    // Check always passes (no check function in C)
    // -------------------------------------------------------------------------

    #[test]
    fn test_spf_check_always_passes() {
        let driver = SpfLookup::new();
        let handle: LookupHandle = Box::new(());
        let result = driver.check(&handle, None, 0, &[], &[]);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_spf_check_with_modemask_still_passes() {
        let driver = SpfLookup::new();
        let handle: LookupHandle = Box::new(());
        let result = driver.check(&handle, Some("/etc/spf.conf"), 0o022, &[0], &[0]);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    // -------------------------------------------------------------------------
    // Behavior without delegate (miscmod not loaded)
    // -------------------------------------------------------------------------

    #[test]
    fn test_spf_open_without_delegate_returns_not_found() {
        let driver = SpfLookup::new();
        let result = driver.open(None);
        assert!(result.is_err());
        match result.unwrap_err() {
            DriverError::NotFound { name } => assert_eq!(name, "spf"),
            other => panic!("Expected DriverError::NotFound, got: {other:?}"),
        }
    }

    #[test]
    fn test_spf_find_without_delegate_returns_execution_failed() {
        let driver = SpfLookup::new();
        let handle: LookupHandle = Box::new(());
        let result = driver.find(&handle, None, "example.com", None);
        assert!(result.is_err());
        match result.unwrap_err() {
            DriverError::ExecutionFailed(msg) => {
                assert!(msg.contains("miscmod not available"));
            }
            other => panic!("Expected DriverError::ExecutionFailed, got: {other:?}"),
        }
    }

    #[test]
    fn test_spf_close_without_delegate_does_not_panic() {
        let driver = SpfLookup::new();
        let handle: LookupHandle = Box::new(String::from("test handle"));
        // Should not panic — just drops the handle silently
        driver.close(handle);
    }

    // -------------------------------------------------------------------------
    // Tidy and quote (no-ops)
    // -------------------------------------------------------------------------

    #[test]
    fn test_spf_tidy_is_noop() {
        let driver = SpfLookup::new();
        // Should not panic
        driver.tidy();
    }

    #[test]
    fn test_spf_quote_returns_none() {
        let driver = SpfLookup::new();
        assert!(driver.quote("test@example.com", None).is_none());
        assert!(driver.quote("test", Some("extra")).is_none());
    }

    // -------------------------------------------------------------------------
    // Version report without delegate
    // -------------------------------------------------------------------------

    #[test]
    fn test_spf_version_report_without_delegate_returns_none() {
        let driver = SpfLookup::new();
        assert!(driver.version_report().is_none());
    }

    // -------------------------------------------------------------------------
    // Constructor and Debug
    // -------------------------------------------------------------------------

    #[test]
    fn test_spf_lookup_debug_format() {
        let driver = SpfLookup::new();
        let debug_str = format!("{:?}", driver);
        assert_eq!(debug_str, "SpfLookup");
    }

    #[test]
    fn test_spf_lookup_send_sync() {
        // Verify SpfLookup satisfies Send + Sync bounds required by LookupDriver
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SpfLookup>();
    }
}
