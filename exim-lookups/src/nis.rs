// =============================================================================
// exim-lookups/src/nis.rs — NIS (Yellow Pages) Lookup Backend (FFI)
// =============================================================================
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Rewrites `src/src/lookups/nis.c` (143 lines) as a Rust module that delegates
// all NIS/YP operations to the `exim_ffi::nis` safe FFI wrapper.  Provides two
// lookup variants registered as separate factories:
//
//   - **`nis`**  — key length *excludes* the null terminator (standard behaviour)
//   - **`nis0`** — key length *includes* the null terminator (for maps that
//                   store keys with trailing NUL bytes)
//
// Both variants share the same `NisLookup` struct, differing only in the
// `NisVariant` field that controls key-length calculation during `find()`.
//
// ## C Function Mapping
//
// | C Function / Struct       | Rust Equivalent                          |
// |---------------------------|------------------------------------------|
// | `nis_open()`              | `NisLookup::open()`  — get_default_domain|
// | `nis_find()`              | `NisLookup::find()` (variant = Nis)      |
// | `nis0_find()`             | `NisLookup::find()` (variant = Nis0)     |
// | `.check  = NULL`          | `NisLookup::check()` — always Ok(true)   |
// | `.close  = NULL`          | `NisLookup::close()` — no-op             |
// | `.tidy   = NULL`          | `NisLookup::tidy()`  — no-op             |
// | `.quote  = NULL`          | `NisLookup::quote()` — returns None       |
// | `nis_version_report()`    | `NisLookup::version_report()` (nis only) |
// | `.type   = 0`             | `LookupType::NONE`                       |
// | `.name   = "nis"/"nis0"`  | `NisLookup::driver_name()`               |
// | `nis_lookup_info`         | `inventory::submit!` for "nis"           |
// | `nis0_lookup_info`        | `inventory::submit!` for "nis0"          |
// | `nis_lookup_module_info`  | Replaced by two `LookupDriverFactory`    |
//
// ## Error Mapping (C return codes → Rust types)
//
// | C Return Code     | NisError Variant      | Rust Mapping                           |
// |-------------------|-----------------------|----------------------------------------|
// | `OK`     (0)      | —                     | `Ok(LookupResult::Found { .. })`       |
// | `FAIL`   (YPERR_KEY) | `KeyNotFound`      | `Ok(LookupResult::NotFound)`           |
// | `FAIL`   (YPERR_MAP) | `MapNotFound(..)`  | `Ok(LookupResult::NotFound)`           |
// | `DEFER`  (other)  | `SystemError { .. }`  | `Err(DriverError::TempFail(..))`       |
// | open() failure    | `DomainNotBound(..)`  | `Err(DriverError::InitFailed(..))`     |
//
// ## Safety
//
// Per AAP §0.7.2: This file contains **ZERO** `unsafe` code.  All NIS/YP FFI
// calls are delegated to the safe public API in `exim_ffi::nis`.
//
// ## Registration
//
// Per AAP §0.4.2 / §0.7.3: Two `LookupDriverFactory` instances are registered
// via `inventory::submit!` at compile time, replacing the C static
// `nis_lookup_info` / `nis0_lookup_info` structs and the
// `nis_lookup_module_info` module descriptor.
//
// ## Feature Gate
//
// This module is compiled only when `feature = "lookup-nis"` is enabled in
// `exim-lookups/Cargo.toml`, which in turn activates `exim-ffi/ffi-nis`.
// The feature gate is applied at the `mod nis;` declaration in `lib.rs`.

#![deny(unsafe_code)]

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;

// =============================================================================
// NIS Variant Enum
// =============================================================================

/// Discriminates between the two NIS lookup modes.
///
/// Both modes use the same `yp_match()` call; the only difference is whether
/// the trailing null byte is included in the key length passed to the NIS
/// server.  Some NIS maps store keys with trailing NUL bytes — the `nis0`
/// variant handles this case.
///
/// C equivalent:
///   - `nis`  → `nis_find()`  passes `length`     (= `strlen(keystring)`)
///   - `nis0` → `nis0_find()` passes `length + 1` (includes NUL terminator)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NisVariant {
    /// Standard NIS lookup — key length excludes null terminator.
    ///
    /// C: `yp_match(domain, map, key, strlen(key), &result, &resultlen)`
    Nis,

    /// NIS0 variant — key length includes null terminator.
    ///
    /// C: `yp_match(domain, map, key, strlen(key) + 1, &result, &resultlen)`
    Nis0,
}

// =============================================================================
// NIS Handle
// =============================================================================

/// Handle for NIS lookups — stores the default NIS domain name.
///
/// In the C code, `nis_open()` calls `yp_get_default_domain()` and returns
/// the domain name pointer as the opaque `void *` handle.  In Rust, the
/// domain is stored as an owned `String` inside a `Box<NisHandle>` which is
/// stored as the `LookupHandle` (`Box<dyn Any + Send + Sync>`).
///
/// Both the `nis` and `nis0` variants share the same handle; the only
/// difference is how `find()` constructs the key bytes.
#[derive(Debug)]
struct NisHandle {
    /// The NIS domain name obtained from `yp_get_default_domain()`.
    ///
    /// C equivalent: the `char *nis_domain` local in `nis_open()` (nis.c line 26),
    /// returned as the lookup handle.
    domain: String,
}

// =============================================================================
// NisLookup Driver
// =============================================================================

/// NIS (Yellow Pages) lookup driver implementation.
///
/// A single struct that handles both the `nis` and `nis0` lookup variants
/// via the [`NisVariant`] discriminator.  Each variant is registered as a
/// separate [`LookupDriverFactory`] through `inventory::submit!`.
///
/// The lookup operates in two phases:
///   1. **`open()`** — Retrieves the default NIS domain name via
///      `exim_ffi::nis::get_default_domain()` and stores it in a
///      [`NisHandle`].
///   2. **`find()`** — Calls `exim_ffi::nis::yp_match_query()` with the
///      stored domain, the map name (from the `filename` parameter), and
///      the key.  For the `nis0` variant, a trailing null byte is appended
///      to the key.
///
/// This is a stateless lookup beyond the cached domain name:
///   - `close()` and `tidy()` are no-ops (C: both set to NULL)
///   - `check()` always returns `Ok(true)` (C: `.check = NULL`)
///   - `quote()` returns `None` (C: `.quote = NULL`)
///
/// # Examples
///
/// ```ignore
/// use exim_lookups::nis::NisLookup;
/// use exim_drivers::lookup_driver::LookupDriver;
///
/// // Created by the registry via LookupDriverFactory
/// let driver = NisLookup::new_nis();
/// let handle = driver.open(None).unwrap();
/// let result = driver.find(&handle, Some("passwd.byname"), "root", None);
/// ```
#[derive(Debug)]
pub struct NisLookup {
    /// Which NIS key-length variant this instance represents.
    variant: NisVariant,
}

impl NisLookup {
    /// Create a new NIS lookup driver for the standard `nis` variant.
    ///
    /// Key length passed to `yp_match` excludes the null terminator.
    fn new_nis() -> Self {
        Self {
            variant: NisVariant::Nis,
        }
    }

    /// Create a new NIS lookup driver for the `nis0` variant.
    ///
    /// Key length passed to `yp_match` includes the null terminator.
    fn new_nis0() -> Self {
        Self {
            variant: NisVariant::Nis0,
        }
    }
}

// =============================================================================
// LookupDriver Trait Implementation
// =============================================================================

impl LookupDriver for NisLookup {
    /// Open the NIS lookup — retrieves the default NIS domain.
    ///
    /// Replaces C `nis_open()` (nis.c lines 23–33):
    /// ```c
    /// char *nis_domain;
    /// if (yp_get_default_domain(&nis_domain) != 0) {
    ///   *errmsg = US"failed to get default NIS domain";
    ///   return NULL;
    /// }
    /// return nis_domain;
    /// ```
    ///
    /// The domain name is cached in the returned handle for use by
    /// subsequent `find()` calls.  This function is called once per
    /// lookup specification in the Exim configuration.
    fn open(&self, _filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        tracing::debug!(
            variant = self.driver_name(),
            "NIS: opening — retrieving default NIS domain"
        );

        let domain = exim_ffi::nis::get_default_domain().map_err(|e| {
            tracing::warn!(
                variant = self.driver_name(),
                error = %e,
                "NIS: failed to get default NIS domain"
            );
            DriverError::InitFailed(format!("failed to get default NIS domain: {e}"))
        })?;

        tracing::debug!(
            variant = self.driver_name(),
            domain = %domain,
            "NIS: default domain obtained"
        );

        Ok(Box::new(NisHandle { domain }))
    }

    /// Check file validity — always succeeds for NIS lookups.
    ///
    /// NIS lookups do not operate on local files, so file permission and
    /// ownership checks are not applicable.  The C implementation sets
    /// `.check = NULL` for both `nis_lookup_info` and `nis0_lookup_info`
    /// (nis.c lines 116, 128), which the dispatcher treats as unconditional
    /// success.
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

    /// Look up a key in a NIS map via `yp_match`.
    ///
    /// Replaces C `nis_find()` (nis.c lines 45–62) and `nis0_find()` (nis.c
    /// lines 72–89).  The two C functions are merged into a single Rust
    /// method that branches on the `NisVariant`:
    ///
    /// - **`Nis`** variant: key bytes = `key.as_bytes()` (no NUL),
    ///   matching C `yp_match(..., length, ...)`.
    /// - **`Nis0`** variant: key bytes = `key.as_bytes()` + `\0`,
    ///   matching C `yp_match(..., length + 1, ...)`.
    ///
    /// ## Parameters
    ///
    /// - `handle`: The [`NisHandle`] returned by `open()`, containing the
    ///   NIS domain name.
    /// - `filename`: The NIS map name (e.g., `"passwd.byname"`,
    ///   `"hosts.byaddr"`).  Required for single-key lookups.
    /// - `key_or_query`: The key to search for in the NIS map.
    /// - `options`: Ignored — NIS does not support per-query options.
    ///
    /// ## Returns
    ///
    /// - `Ok(Found { value, cache_ttl: None })` — key matched, value returned
    ///   with trailing newline(s) stripped (matching C behaviour).
    /// - `Ok(NotFound)` — key or map not found (C: `FAIL` for YPERR_KEY
    ///   or YPERR_MAP).
    /// - `Err(DriverError::TempFail(..))` — NIS service error (C: `DEFER`
    ///   for all other YPERR_* codes).
    /// - `Err(DriverError::ExecutionFailed(..))` — internal error (invalid
    ///   handle, missing map name).
    fn find(
        &self,
        handle: &LookupHandle,
        filename: Option<&str>,
        key_or_query: &str,
        _options: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        // Downcast the opaque handle to our NisHandle.
        let nis_handle = handle.downcast_ref::<NisHandle>().ok_or_else(|| {
            DriverError::ExecutionFailed("NIS: invalid handle type (expected NisHandle)".into())
        })?;

        // The NIS map name is passed via the `filename` parameter in
        // single-key lookups: `${lookup nis{/etc/passwd.byname}{key}}`.
        // The C code receives it as the `filename` argument to find().
        let map = filename.ok_or_else(|| {
            DriverError::ExecutionFailed(
                "NIS: map name (filename) is required for single-key lookup".into(),
            )
        })?;

        // Build the key byte slice.  For the nis0 variant, append a
        // trailing null byte so that the key length includes the NUL,
        // matching C `yp_match(..., length + 1, ...)` in nis0_find().
        let key_bytes: Vec<u8> = match self.variant {
            NisVariant::Nis => key_or_query.as_bytes().to_vec(),
            NisVariant::Nis0 => {
                let mut kb = key_or_query.as_bytes().to_vec();
                kb.push(0);
                kb
            }
        };

        tracing::debug!(
            variant = self.driver_name(),
            domain = %nis_handle.domain,
            map = %map,
            key = %key_or_query,
            key_len = key_bytes.len(),
            "NIS: performing yp_match lookup"
        );

        // Delegate to the safe FFI wrapper in exim-ffi.
        match exim_ffi::nis::yp_match_query(&nis_handle.domain, map, &key_bytes) {
            Ok(result_bytes) => {
                // Convert the raw bytes to a UTF-8 string.  NIS data is
                // typically ASCII/UTF-8, but we use lossy conversion to
                // handle any non-UTF-8 bytes gracefully.
                let mut value = String::from_utf8_lossy(&result_bytes).into_owned();

                // Strip trailing newline — the C code does:
                //   (*result)[nis_data_length] = 0;  /* remove final '\n' */
                // which replaces the character at the end of the result
                // buffer with a null terminator, effectively removing the
                // trailing newline that NIS appends to map values.
                // We strip all trailing newlines and null bytes to match.
                while value.ends_with('\n') || value.ends_with('\0') {
                    value.pop();
                }

                tracing::debug!(
                    variant = self.driver_name(),
                    key = %key_or_query,
                    value_len = value.len(),
                    "NIS: key found"
                );

                Ok(LookupResult::Found {
                    value,
                    cache_ttl: None,
                })
            }
            Err(exim_ffi::nis::NisError::KeyNotFound) => {
                // C: `return (rc == YPERR_KEY || ...) ? FAIL : DEFER;`
                // YPERR_KEY → FAIL → NotFound
                tracing::debug!(
                    variant = self.driver_name(),
                    key = %key_or_query,
                    map = %map,
                    "NIS: key not found in map"
                );
                Ok(LookupResult::NotFound)
            }
            Err(exim_ffi::nis::NisError::MapNotFound(ref detail)) => {
                // C: `return (... || rc == YPERR_MAP) ? FAIL : DEFER;`
                // YPERR_MAP → FAIL → NotFound
                tracing::debug!(
                    variant = self.driver_name(),
                    map = %map,
                    detail = %detail,
                    "NIS: map not found"
                );
                Ok(LookupResult::NotFound)
            }
            Err(exim_ffi::nis::NisError::DomainNotBound(ref msg)) => {
                // Domain became unbound after open() — transient failure.
                // C: other YPERR_* → DEFER
                tracing::warn!(
                    variant = self.driver_name(),
                    error = %msg,
                    "NIS: domain not bound during find()"
                );
                Err(DriverError::TempFail(format!(
                    "NIS domain not bound during lookup in map '{}': {}",
                    map, msg
                )))
            }
            Err(exim_ffi::nis::NisError::SystemError { code, ref message }) => {
                // C: all YPERR_* codes other than KEY and MAP → DEFER
                // This covers RPC failures, resource exhaustion, server
                // errors, and all other transient NIS conditions.
                //
                // In C, find() returns DEFER (1) which maps directly to
                // LookupResult::Deferred — a temporary failure that should
                // be retried.  This is NOT a fatal error; the caller should
                // retry the lookup later (e.g., on the next delivery attempt).
                tracing::warn!(
                    variant = self.driver_name(),
                    key = %key_or_query,
                    map = %map,
                    nis_code = code,
                    error = %message,
                    "NIS: system error during yp_match (DEFER)"
                );
                Ok(LookupResult::Deferred {
                    message: format!(
                        "NIS yp_match failed for key '{}' in map '{}' (code {}): {}",
                        key_or_query, map, code, message
                    ),
                })
            }
        }
    }

    /// Close an open NIS lookup handle — no-op.
    ///
    /// NIS lookups are stateless beyond the cached domain name; there are no
    /// file descriptors, connections, or resources to release.  The C
    /// implementation sets `.close = NULL` for both variants (nis.c lines
    /// 118, 130).
    ///
    /// The `NisHandle` is simply dropped when the `LookupHandle` box goes
    /// out of scope.
    fn close(&self, _handle: LookupHandle) {
        // No-op: the boxed NisHandle is dropped automatically.
    }

    /// Tidy up NIS lookup resources — no-op.
    ///
    /// NIS lookups maintain no cached state between lookups.  The C
    /// implementation sets `.tidy = NULL` for both variants (nis.c lines
    /// 119, 131).
    fn tidy(&self) {
        // No-op: no cached connections or handles to clean up.
    }

    /// Quote a string for NIS lookups — not applicable.
    ///
    /// NIS does not require any special quoting or escaping of key values.
    /// The C implementation sets `.quote = NULL` for both variants (nis.c
    /// lines 120, 132).
    fn quote(&self, _value: &str, _additional: Option<&str>) -> Option<String> {
        None
    }

    /// Diagnostic version reporting for `-bV` output.
    ///
    /// Only the `nis` variant reports version information; the `nis0`
    /// variant returns `None` (C: `nis0_lookup_info.version_report = NULL`
    /// at nis.c line 133, marked "no version reporting (redundant)").
    ///
    /// The `nis` variant reports a string matching the format used by
    /// the C version (nis.c lines 101–109):
    /// ```c
    /// g = string_fmt_append(g, "Library version: NIS: Exim version %s\n",
    ///                       EXIM_VERSION_STR);
    /// ```
    fn version_report(&self) -> Option<String> {
        match self.variant {
            NisVariant::Nis => {
                let report = "Library version: NIS: Exim version (Rust rewrite)".to_string();
                tracing::debug!(report = %report, "NIS: version report");
                Some(report)
            }
            NisVariant::Nis0 => {
                // C: nis0_lookup_info.version_report = NULL
                // "no version reporting (redundant)" — the nis variant already reports.
                None
            }
        }
    }

    /// Lookup type flags — basic single-key lookup.
    ///
    /// NIS uses a map name (filename) and a key, so it is a single-key
    /// lookup with no special flags.  C: `.type = 0` for both variants
    /// (nis.c lines 114, 126).
    ///
    /// `LookupType::NONE` = type 0 = not query-style, not abs-file.
    fn lookup_type(&self) -> LookupType {
        LookupType::NONE
    }

    /// Driver name for configuration file matching.
    ///
    /// Returns `"nis"` or `"nis0"` depending on the variant.
    /// C: `.name = US"nis"` (line 113) / `.name = US"nis0"` (line 125).
    fn driver_name(&self) -> &str {
        match self.variant {
            NisVariant::Nis => "nis",
            NisVariant::Nis0 => "nis0",
        }
    }
}

// =============================================================================
// Compile-Time Driver Registration
// =============================================================================
//
// Per AAP §0.4.2 / §0.7.3: Replace C static `nis_lookup_info` /
// `nis0_lookup_info` structs and `nis_lookup_module_info` with
// `inventory::submit!` registrations.
//
// The C module registered two lookup types in one module:
//   static lookup_info *_lookup_list[] = { &nis_lookup_info, &nis0_lookup_info };
//   lookup_module_info nis_lookup_module_info = {
//       LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 2
//   };
//
// In Rust, each lookup type gets its own LookupDriverFactory entry.

inventory::submit! {
    LookupDriverFactory {
        name: "nis",
        create: || Box::new(NisLookup::new_nis()),
        lookup_type: LookupType::NONE,
        avail_string: Some("nis (NIS/YP via FFI)"),
    }
}

inventory::submit! {
    LookupDriverFactory {
        name: "nis0",
        create: || Box::new(NisLookup::new_nis0()),
        lookup_type: LookupType::NONE,
        avail_string: Some("nis0 (NIS/YP via FFI, NUL-inclusive key)"),
    }
}

// =============================================================================
// Unit Tests
// =============================================================================
//
// These tests verify the driver interface contract, variant behaviour, and
// error path coverage.  They do NOT call the real NIS FFI functions (which
// require a running NIS server); instead they exercise the pure-Rust logic
// (type construction, name/type queries, version reporting, and handle
// validation).

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Construction and Identification
    // =========================================================================

    #[test]
    fn nis_driver_name_is_nis() {
        let driver = NisLookup::new_nis();
        assert_eq!(driver.driver_name(), "nis");
    }

    #[test]
    fn nis0_driver_name_is_nis0() {
        let driver = NisLookup::new_nis0();
        assert_eq!(driver.driver_name(), "nis0");
    }

    #[test]
    fn nis_lookup_type_is_single_key() {
        let driver = NisLookup::new_nis();
        let lt = driver.lookup_type();
        assert!(lt.is_single_key(), "NIS should be single-key (type=0)");
        assert!(!lt.is_query_style(), "NIS should not be query-style");
        assert!(!lt.is_abs_file(), "NIS should not require absolute file");
        assert_eq!(lt, LookupType::NONE);
    }

    #[test]
    fn nis0_lookup_type_is_single_key() {
        let driver = NisLookup::new_nis0();
        let lt = driver.lookup_type();
        assert!(lt.is_single_key(), "NIS0 should be single-key (type=0)");
        assert_eq!(lt, LookupType::NONE);
    }

    // =========================================================================
    // Version Reporting
    // =========================================================================

    #[test]
    fn nis_version_report_returns_some() {
        let driver = NisLookup::new_nis();
        let report = driver.version_report();
        assert!(report.is_some(), "nis variant should have version report");
        let text = report.unwrap();
        assert!(
            text.contains("NIS"),
            "version report should mention NIS: got '{}'",
            text
        );
    }

    #[test]
    fn nis0_version_report_returns_none() {
        let driver = NisLookup::new_nis0();
        let report = driver.version_report();
        assert!(
            report.is_none(),
            "nis0 variant should not have version report (redundant)"
        );
    }

    // =========================================================================
    // Check Method — Always Succeeds
    // =========================================================================

    #[test]
    fn check_always_returns_true() {
        let driver = NisLookup::new_nis();
        // Create a dummy handle (NisHandle with empty domain) for check().
        let handle: LookupHandle = Box::new(NisHandle {
            domain: "test.domain".to_string(),
        });
        let result = driver.check(&handle, Some("passwd.byname"), 0o022, &[], &[]);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    // =========================================================================
    // Quote Method — Returns None
    // =========================================================================

    #[test]
    fn quote_returns_none() {
        let driver = NisLookup::new_nis();
        assert!(driver.quote("some_key", None).is_none());
        assert!(driver.quote("some_key", Some("extra")).is_none());
    }

    // =========================================================================
    // Close and Tidy — No-ops (Should Not Panic)
    // =========================================================================

    #[test]
    fn close_does_not_panic() {
        let driver = NisLookup::new_nis();
        let handle: LookupHandle = Box::new(NisHandle {
            domain: "test.domain".to_string(),
        });
        driver.close(handle);
        // No assertion needed — just verifying no panic.
    }

    #[test]
    fn tidy_does_not_panic() {
        let driver = NisLookup::new_nis();
        driver.tidy();
        // No assertion needed — just verifying no panic.
    }

    // =========================================================================
    // Find — Invalid Handle
    // =========================================================================

    #[test]
    fn find_with_invalid_handle_returns_execution_error() {
        let driver = NisLookup::new_nis();
        // Create a handle with the wrong type (not NisHandle).
        let bad_handle: LookupHandle = Box::new(42_u32);
        let result = driver.find(&bad_handle, Some("passwd.byname"), "root", None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DriverError::ExecutionFailed(_)),
            "expected ExecutionFailed, got: {:?}",
            err
        );
    }

    #[test]
    fn find_without_filename_returns_execution_error() {
        let driver = NisLookup::new_nis();
        let handle: LookupHandle = Box::new(NisHandle {
            domain: "test.domain".to_string(),
        });
        let result = driver.find(&handle, None, "root", None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DriverError::ExecutionFailed(_)),
            "expected ExecutionFailed for missing filename, got: {:?}",
            err
        );
    }

    // =========================================================================
    // Variant Equality
    // =========================================================================

    #[test]
    fn variant_enum_equality() {
        assert_eq!(NisVariant::Nis, NisVariant::Nis);
        assert_eq!(NisVariant::Nis0, NisVariant::Nis0);
        assert_ne!(NisVariant::Nis, NisVariant::Nis0);
    }

    // =========================================================================
    // Debug Trait
    // =========================================================================

    #[test]
    fn nis_lookup_debug_output() {
        let driver = NisLookup::new_nis();
        let debug_str = format!("{:?}", driver);
        assert!(
            debug_str.contains("NisLookup"),
            "Debug output should contain struct name"
        );
        assert!(
            debug_str.contains("Nis"),
            "Debug output should contain variant name"
        );
    }
}
