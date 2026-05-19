//! Synthetic test lookup backends for the Exim lookup framework.
//!
//! This module provides three test lookup variants (`testdb`, `testdb2`,
//! `testdb_nq`) used by the Exim test suite to exercise the lookup dispatcher
//! without requiring external dependencies. Rewritten from
//! `src/src/lookups/testdb.c` (140 lines).
//!
//! All three variants are query-style lookups that echo the query string back
//! as the result, with special handling for the queries `"fail"`, `"defer"`,
//! and `"nocache"`.
//!
//! # Variant Differences
//!
//! | Variant    | Name          | Quote | Version Report |
//! |------------|---------------|-------|----------------|
//! | `Testdb`   | `"testdb"`    | Yes   | Yes            |
//! | `Testdb2`  | `"testdb2"`   | Yes   | No             |
//! | `TestdbNq` | `"testdb_nq"` | No    | No             |
//!
//! # Registration
//!
//! Three [`LookupDriverFactory`] instances are registered at compile time via
//! [`inventory::submit!`], replacing the C `testdb_lookup_info`,
//! `testdb2_lookup_info`, `testdb3_lookup_info` static structs and the
//! `testdb_lookup_module_info` module registration from `testdb.c`.

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;

/// Identifies which of the three test lookup variants this instance represents.
///
/// The variant controls the driver name returned by [`TestdbLookup::driver_name`],
/// whether [`TestdbLookup::quote`] returns an identity copy of the input (or
/// `None`), and whether [`TestdbLookup::version_report`] emits a version string
/// (or `None`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestdbVariant {
    /// Primary test backend: supports quoting and version reporting.
    /// Registered as `"testdb"`.
    Testdb,

    /// Secondary test backend: supports quoting but no version reporting.
    /// Registered as `"testdb2"`.
    Testdb2,

    /// No-quote test backend: no quoting, no version reporting.
    /// Registered as `"testdb_nq"`.
    TestdbNq,
}

/// Synthetic test lookup driver implementing [`LookupDriver`].
///
/// This driver echoes the query string back as the lookup result, with
/// special handling for the following reserved queries:
///
/// - `"fail"` — Returns a forced FAIL error via [`DriverError::ExecutionFailed`]
/// - `"defer"` — Returns a forced DEFER error via [`DriverError::TempFail`]
/// - `"nocache"` — Returns the query with `cache_ttl = Some(0)` to disable caching
/// - Any other query — Returns the query as-is with default caching (`cache_ttl = None`)
///
/// Three instances are registered via [`inventory::submit!`]:
/// - `"testdb"` (with quote + version_report)
/// - `"testdb2"` (with quote, no version_report)
/// - `"testdb_nq"` (no quote, no version_report)
#[derive(Debug)]
pub struct TestdbLookup {
    /// Which test variant this instance represents.
    variant: TestdbVariant,
}

impl TestdbLookup {
    /// Creates a new `TestdbLookup` with the specified variant.
    fn new(variant: TestdbVariant) -> Self {
        Self { variant }
    }
}

impl LookupDriver for TestdbLookup {
    /// Returns a dummy handle.
    ///
    /// The testdb driver is stateless — the handle is a boxed unit value `()`,
    /// serving only to satisfy the [`LookupDriver`] trait contract. This mirrors
    /// the C `testdb_open()` which returns `(void *)(1)` as a non-null sentinel.
    fn open(&self, _filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        Ok(Box::new(()))
    }

    /// Always returns `Ok(true)` — testdb has no file to validate.
    ///
    /// Query-style lookups do not operate on files, so credential/type
    /// validation is not applicable. This matches the C behavior where
    /// testdb does not register a `check` function pointer.
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

    /// Processes the query string and returns a lookup result.
    ///
    /// Behavior matches `testdb_find()` from `testdb.c` exactly:
    ///
    /// - `"fail"` → `Err(DriverError::ExecutionFailed("testdb lookup forced FAIL"))`
    ///   — maps to C `FAIL` return with `*errmsg` set
    /// - `"defer"` → `Err(DriverError::TempFail("testdb lookup forced DEFER"))`
    ///   — maps to C `DEFER` return with `*errmsg` set
    /// - `"nocache"` → `Ok(LookupResult::Found { value: "nocache", cache_ttl: Some(0) })`
    ///   — maps to C `OK` return with `*do_cache = 0`
    /// - Any other string → `Ok(LookupResult::Found { value: <query>, cache_ttl: None })`
    ///   — maps to C `OK` return with default caching
    fn find(
        &self,
        _handle: &LookupHandle,
        _filename: Option<&str>,
        key_or_query: &str,
        _options: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        match key_or_query {
            "fail" => {
                tracing::debug!("testdb lookup forced FAIL");
                Err(DriverError::ExecutionFailed(
                    "testdb lookup forced FAIL".into(),
                ))
            }
            "defer" => {
                tracing::debug!("testdb lookup forced DEFER");
                Err(DriverError::TempFail("testdb lookup forced DEFER".into()))
            }
            "nocache" => {
                tracing::debug!("testdb nocache mode activated");
                Ok(LookupResult::Found {
                    value: key_or_query.to_string(),
                    cache_ttl: Some(0),
                })
            }
            _ => {
                tracing::debug!(query = %key_or_query, "testdb echo query result");
                Ok(LookupResult::Found {
                    value: key_or_query.to_string(),
                    cache_ttl: None,
                })
            }
        }
    }

    /// No-op close — the dummy handle requires no cleanup.
    ///
    /// Matches the C behavior where testdb does not register a `close` function.
    fn close(&self, _handle: LookupHandle) {
        // No resources to release.
    }

    /// No-op tidy — no cached state to clear.
    ///
    /// Matches the C behavior where testdb does not register a `tidy` function.
    fn tidy(&self) {
        // No persistent state to clean up.
    }

    /// Returns an identity-quoted copy of the input for `Testdb` and `Testdb2`,
    /// or `None` for `TestdbNq`.
    ///
    /// The C `testdb_quote()` copies the input string unchanged via
    /// `store_get_quoted()` + `memcpy()`. The `testdb_nq` variant does not
    /// register a quote function at all, so we return `None` in that case.
    fn quote(&self, value: &str, _additional: Option<&str>) -> Option<String> {
        match self.variant {
            TestdbVariant::Testdb | TestdbVariant::Testdb2 => Some(value.to_string()),
            TestdbVariant::TestdbNq => None,
        }
    }

    /// Returns a version report string for the `Testdb` variant only.
    ///
    /// The C `testdb_version_report()` emits:
    ///   `"Library version: TestDB: Exim version <VERSION>"`
    /// Only the primary `testdb` lookup type registers this function; `testdb2`
    /// and `testdb_nq` return `None`.
    fn version_report(&self) -> Option<String> {
        match self.variant {
            TestdbVariant::Testdb => Some(format!(
                "Library version: TestDB: Exim version {}",
                env!("CARGO_PKG_VERSION")
            )),
            TestdbVariant::Testdb2 | TestdbVariant::TestdbNq => None,
        }
    }

    /// All testdb variants are query-style lookups.
    ///
    /// This matches the C `lookup_querystyle` flag set for all three
    /// `lookup_info` registrations in `testdb.c`.
    fn lookup_type(&self) -> LookupType {
        LookupType::QUERY_STYLE
    }

    /// Returns the driver name corresponding to this variant.
    ///
    /// - `Testdb` → `"testdb"`
    /// - `Testdb2` → `"testdb2"`
    /// - `TestdbNq` → `"testdb_nq"`
    fn driver_name(&self) -> &str {
        match self.variant {
            TestdbVariant::Testdb => "testdb",
            TestdbVariant::Testdb2 => "testdb2",
            TestdbVariant::TestdbNq => "testdb_nq",
        }
    }
}

// ── Compile-time driver registration ────────────────────────────────────
//
// Three `LookupDriverFactory` instances are registered via `inventory::submit!`,
// replacing the C `testdb_lookup_info`, `testdb2_lookup_info`, and
// `testdb3_lookup_info` static structs plus the `testdb_lookup_module_info`
// module registration from `testdb.c` lines 91–138.

inventory::submit! {
    LookupDriverFactory {
        name: "testdb",
        create: || Box::new(TestdbLookup::new(TestdbVariant::Testdb)),
        lookup_type: LookupType::QUERY_STYLE,
        avail_string: None,
    }
}

inventory::submit! {
    LookupDriverFactory {
        name: "testdb2",
        create: || Box::new(TestdbLookup::new(TestdbVariant::Testdb2)),
        lookup_type: LookupType::QUERY_STYLE,
        avail_string: None,
    }
}

inventory::submit! {
    LookupDriverFactory {
        name: "testdb_nq",
        create: || Box::new(TestdbLookup::new(TestdbVariant::TestdbNq)),
        lookup_type: LookupType::QUERY_STYLE,
        avail_string: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variant_driver_names() {
        let testdb = TestdbLookup::new(TestdbVariant::Testdb);
        assert_eq!(testdb.driver_name(), "testdb");

        let testdb2 = TestdbLookup::new(TestdbVariant::Testdb2);
        assert_eq!(testdb2.driver_name(), "testdb2");

        let testdb_nq = TestdbLookup::new(TestdbVariant::TestdbNq);
        assert_eq!(testdb_nq.driver_name(), "testdb_nq");
    }

    #[test]
    fn test_all_variants_query_style() {
        for variant in &[
            TestdbVariant::Testdb,
            TestdbVariant::Testdb2,
            TestdbVariant::TestdbNq,
        ] {
            let lookup = TestdbLookup::new(*variant);
            assert_eq!(lookup.lookup_type(), LookupType::QUERY_STYLE);
        }
    }

    #[test]
    fn test_open_returns_handle() {
        let lookup = TestdbLookup::new(TestdbVariant::Testdb);
        let handle = lookup.open(None);
        assert!(handle.is_ok());
    }

    #[test]
    fn test_check_always_true() {
        let lookup = TestdbLookup::new(TestdbVariant::Testdb);
        let handle = lookup.open(None).unwrap();
        let result = lookup.check(&handle, None, 0, &[], &[]);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_find_echo() {
        let lookup = TestdbLookup::new(TestdbVariant::Testdb);
        let handle = lookup.open(None).unwrap();
        let result = lookup.find(&handle, None, "hello world", None);
        assert!(result.is_ok());
        match result.unwrap() {
            LookupResult::Found { value, cache_ttl } => {
                assert_eq!(value, "hello world");
                assert_eq!(cache_ttl, None);
            }
            LookupResult::NotFound => panic!("Expected Found, got NotFound"),
            LookupResult::Deferred { .. } => panic!("Expected Found, got Deferred"),
        }
    }

    #[test]
    fn test_find_fail() {
        let lookup = TestdbLookup::new(TestdbVariant::Testdb);
        let handle = lookup.open(None).unwrap();
        let result = lookup.find(&handle, None, "fail", None);
        assert!(result.is_err());
        match result.unwrap_err() {
            DriverError::ExecutionFailed(msg) => {
                assert_eq!(msg, "testdb lookup forced FAIL");
            }
            _ => panic!("Expected DriverError::ExecutionFailed"),
        }
    }

    #[test]
    fn test_find_defer() {
        let lookup = TestdbLookup::new(TestdbVariant::Testdb);
        let handle = lookup.open(None).unwrap();
        let result = lookup.find(&handle, None, "defer", None);
        assert!(result.is_err());
        match result.unwrap_err() {
            DriverError::TempFail(msg) => {
                assert_eq!(msg, "testdb lookup forced DEFER");
            }
            _ => panic!("Expected DriverError::TempFail"),
        }
    }

    #[test]
    fn test_find_nocache() {
        let lookup = TestdbLookup::new(TestdbVariant::Testdb);
        let handle = lookup.open(None).unwrap();
        let result = lookup.find(&handle, None, "nocache", None);
        assert!(result.is_ok());
        match result.unwrap() {
            LookupResult::Found { value, cache_ttl } => {
                assert_eq!(value, "nocache");
                assert_eq!(cache_ttl, Some(0));
            }
            LookupResult::NotFound => panic!("Expected Found, got NotFound"),
            LookupResult::Deferred { .. } => panic!("Expected Found, got Deferred"),
        }
    }

    #[test]
    fn test_quote_testdb_copies_string() {
        let lookup = TestdbLookup::new(TestdbVariant::Testdb);
        assert_eq!(lookup.quote("hello", None), Some("hello".to_string()));
    }

    #[test]
    fn test_quote_testdb2_copies_string() {
        let lookup = TestdbLookup::new(TestdbVariant::Testdb2);
        assert_eq!(lookup.quote("hello", None), Some("hello".to_string()));
    }

    #[test]
    fn test_quote_testdb_nq_returns_none() {
        let lookup = TestdbLookup::new(TestdbVariant::TestdbNq);
        assert_eq!(lookup.quote("hello", None), None);
    }

    #[test]
    fn test_version_report_testdb() {
        let lookup = TestdbLookup::new(TestdbVariant::Testdb);
        let report = lookup.version_report();
        assert!(report.is_some());
        let report = report.unwrap();
        assert!(report.starts_with("Library version: TestDB: Exim version "));
    }

    #[test]
    fn test_version_report_testdb2_none() {
        let lookup = TestdbLookup::new(TestdbVariant::Testdb2);
        assert!(lookup.version_report().is_none());
    }

    #[test]
    fn test_version_report_testdb_nq_none() {
        let lookup = TestdbLookup::new(TestdbVariant::TestdbNq);
        assert!(lookup.version_report().is_none());
    }

    #[test]
    fn test_find_empty_string() {
        let lookup = TestdbLookup::new(TestdbVariant::Testdb);
        let handle = lookup.open(None).unwrap();
        let result = lookup.find(&handle, None, "", None);
        assert!(result.is_ok());
        match result.unwrap() {
            LookupResult::Found { value, cache_ttl } => {
                assert_eq!(value, "");
                assert_eq!(cache_ttl, None);
            }
            LookupResult::NotFound => panic!("Expected Found, got NotFound"),
            LookupResult::Deferred { .. } => panic!("Expected Found, got Deferred"),
        }
    }

    #[test]
    fn test_close_is_noop() {
        let lookup = TestdbLookup::new(TestdbVariant::Testdb);
        let handle = lookup.open(None).unwrap();
        // close should not panic
        lookup.close(handle);
    }

    #[test]
    fn test_tidy_is_noop() {
        let lookup = TestdbLookup::new(TestdbVariant::Testdb);
        // tidy should not panic
        lookup.tidy();
    }

    #[test]
    fn test_all_variants_find_behavior_identical() {
        // All three variants share the same find() behavior
        for variant in &[
            TestdbVariant::Testdb,
            TestdbVariant::Testdb2,
            TestdbVariant::TestdbNq,
        ] {
            let lookup = TestdbLookup::new(*variant);
            let handle = lookup.open(None).unwrap();

            // Echo behavior
            match lookup.find(&handle, None, "test_value", None).unwrap() {
                LookupResult::Found { value, .. } => assert_eq!(value, "test_value"),
                LookupResult::NotFound => panic!("Expected Found, got NotFound"),
                LookupResult::Deferred { .. } => panic!("Expected Found, got Deferred"),
            }

            // Fail behavior
            assert!(matches!(
                lookup.find(&handle, None, "fail", None).unwrap_err(),
                DriverError::ExecutionFailed(_)
            ));

            // Defer behavior
            assert!(matches!(
                lookup.find(&handle, None, "defer", None).unwrap_err(),
                DriverError::TempFail(_)
            ));

            // Nocache behavior
            match lookup.find(&handle, None, "nocache", None).unwrap() {
                LookupResult::Found { cache_ttl, .. } => assert_eq!(cache_ttl, Some(0)),
                LookupResult::NotFound => panic!("Expected Found, got NotFound"),
                LookupResult::Deferred { .. } => panic!("Expected Found, got Deferred"),
            }
        }
    }
}
