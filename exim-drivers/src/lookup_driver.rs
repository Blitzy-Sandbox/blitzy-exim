// =============================================================================
// exim-drivers/src/lookup_driver.rs — LookupDriver Trait Definition
// =============================================================================
//
// Defines the `LookupDriver` trait that replaces the C `lookup_info` struct
// from `lookupapi.h`. All 7 C function pointers are faithfully mapped to
// trait methods: open, check, find, close, tidy, quote, version_report.
//
// This file contains ZERO unsafe code (per AAP §0.7.2).

use crate::DriverError;

// =============================================================================
// Lookup Type Flags
// =============================================================================

/// Lookup type flags — replaces C bit-flag constants from lookupapi.h lines 12-18.
///
/// The C "type" field is a set of bit flags:
///   - `lookup_querystyle` → this is a query-style lookup
///   - `lookup_absfile`    → an absolute file name is required
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LookupType(u32);

impl LookupType {
    /// Query-style lookup (e.g., SQL, LDAP, DNS).
    /// C: `lookup_querystyle`
    pub const QUERY_STYLE: Self = Self(1);

    /// Single-key lookup with absolute file path required.
    /// C: `lookup_absfile`
    pub const ABS_FILE: Self = Self(2);

    /// No flags — basic single-key lookup.
    pub const NONE: Self = Self(0);

    /// Check if this is a query-style lookup.
    pub fn is_query_style(self) -> bool {
        self.0 & Self::QUERY_STYLE.0 != 0
    }

    /// Check if an absolute file path is required.
    pub fn is_abs_file(self) -> bool {
        self.0 & Self::ABS_FILE.0 != 0
    }

    /// Single-key style (not query-style).
    pub fn is_single_key(self) -> bool {
        !self.is_query_style()
    }
}

impl std::ops::BitOr for LookupType {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

// =============================================================================
// Lookup Result Enum
// =============================================================================

/// Result of a lookup `find()` operation.
///
/// Maps to C `find()` return codes: OK(0), FAIL(2), DEFER(1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupResult {
    /// Lookup found a value.
    /// C: OK (0)
    Found {
        /// The value found by the lookup.
        value: String,
        /// Cache TTL in seconds (0 = no cache, `None` = use default).
        cache_ttl: Option<u32>,
    },
    /// Key not found — this is not an error.
    /// C: FAIL (2) for "not found"
    NotFound,
    /// Temporary failure — lookup should be retried.
    /// C: DEFER (1)
    Deferred {
        /// Reason for the deferral.
        message: String,
    },
}

// =============================================================================
// Lookup Handle Type
// =============================================================================

/// Opaque handle for an open lookup connection/file.
///
/// Replaces C `void *` handle parameter in lookup function pointers.
/// Each lookup implementation stores its own state inside this.
pub type LookupHandle = Box<dyn std::any::Any + Send + Sync>;

// =============================================================================
// LookupDriver Trait
// =============================================================================

/// Trait for lookup driver implementations.
///
/// Replaces C `lookup_info` struct function pointers (lookupapi.h lines 20-58).
/// All 7 function pointers from the C struct are represented as trait methods.
///
/// Each lookup backend (lsearch, mysql, ldap, redis, etc.) implements this trait.
/// Per AAP §0.7.3: The trait interface itself is synchronous; individual lookup
/// implementations that use async APIs bridge via `tokio::runtime::Runtime::block_on()`.
pub trait LookupDriver: Send + Sync + std::fmt::Debug {
    /// Open a lookup source (file or connection).
    ///
    /// Replaces C: `void *(*open)(const uschar *, uschar **)`
    ///
    /// For file-based lookups: opens the file.
    /// For query-style lookups: establishes connection (or may be no-op).
    /// Returns a handle used by subsequent operations.
    fn open(&self, filename: Option<&str>) -> Result<LookupHandle, DriverError>;

    /// Check a lookup file for validity/accessibility.
    ///
    /// Replaces C: `BOOL (*check)(void *, const uschar *, int, uid_t *, gid_t *, uschar **)`
    ///
    /// For file-based lookups: checks file permissions, ownership.
    /// For query-style lookups: typically returns `Ok(true)`.
    fn check(
        &self,
        handle: &LookupHandle,
        filename: Option<&str>,
        modemask: i32,
        owners: &[u32],
        owngroups: &[u32],
    ) -> Result<bool, DriverError>;

    /// Find a value by key or query.
    ///
    /// Replaces C: `int (*find)(void *, const uschar *, const uschar *, int, uschar **, uschar **, uint *, const uschar *)`
    ///
    /// This is the primary lookup operation.
    /// For single-key lookups: `filename` + `key_or_query`.
    /// For query-style lookups: `filename` is `None`, `key_or_query` contains the query.
    fn find(
        &self,
        handle: &LookupHandle,
        filename: Option<&str>,
        key_or_query: &str,
        options: Option<&str>,
    ) -> Result<LookupResult, DriverError>;

    /// Close an open lookup handle.
    ///
    /// Replaces C: `void (*close)(void *)`
    fn close(&self, handle: LookupHandle);

    /// Tidy up all resources associated with this lookup type.
    ///
    /// Replaces C: `void (*tidy)(void)`
    /// Called during periodic cleanup.
    fn tidy(&self);

    /// Quote a string for safe use in this lookup type.
    ///
    /// Replaces C: `uschar *(*quote)(uschar *, uschar *, unsigned)`
    ///
    /// Returns the quoted string, or `None` if no quoting is needed.
    fn quote(&self, _value: &str, _additional: Option<&str>) -> Option<String> {
        None
    }

    /// Diagnostic version reporting.
    ///
    /// Replaces C: `gstring * (*version_report)(gstring *)`
    fn version_report(&self) -> Option<String> {
        None
    }

    /// The lookup type (query-style vs single-key, abs-file requirement).
    fn lookup_type(&self) -> LookupType;

    /// Driver name for identification (e.g., "lsearch", "mysql", "ldap").
    fn driver_name(&self) -> &str;
}

// =============================================================================
// LookupDriverFactory
// =============================================================================

/// Factory for creating `LookupDriver` instances. Registered via `inventory::submit!`.
///
/// Replaces C `lookup_module_info` struct (lookupapi.h lines 69-73).
/// In C, a single module could provide multiple lookup types (e.g., lsearch provides
/// lsearch, wildlsearch, nwildlsearch). In Rust, each type gets its own factory entry.
pub struct LookupDriverFactory {
    /// Name of the lookup type (e.g., "lsearch", "mysql", "ldap").
    pub name: &'static str,
    /// Factory function that creates a lookup driver instance.
    pub create: fn() -> Box<dyn LookupDriver>,
    /// Lookup type flags.
    pub lookup_type: LookupType,
    /// Optional display string.
    pub avail_string: Option<&'static str>,
}

// =============================================================================
// Lookup Module Info
// =============================================================================

/// Information about a lookup module that may provide multiple lookup types.
///
/// Replaces C `lookup_module_info` struct (lookupapi.h lines 69-73).
/// For example, the lsearch module provides lsearch, wildlsearch, and nwildlsearch.
pub struct LookupModuleInfo {
    /// Module name.
    pub module_name: &'static str,
    /// Names of lookup types provided by this module.
    pub lookup_names: &'static [&'static str],
}
