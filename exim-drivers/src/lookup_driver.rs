// =============================================================================
// exim-drivers/src/lookup_driver.rs — LookupDriver Trait Definition
// =============================================================================
//
// Defines the `LookupDriver` trait that replaces the C `lookup_info` struct
// from `lookupapi.h` (76 lines). This is the most precisely specified driver
// trait since `lookupapi.h` is a compact header defining the complete lookup
// plugin API with 7 function pointers, type flags, and a module-info struct.
//
// The Rust trait faithfully translates each C function pointer into a trait
// method while adding Rust-idiomatic patterns (Result types, Option types,
// owned String values instead of raw pointers).
//
// C function pointers mapped to trait methods:
//   1. open()           → LookupDriver::open()
//   2. check()          → LookupDriver::check()
//   3. find()           → LookupDriver::find()
//   4. close()          → LookupDriver::close()
//   5. tidy()           → LookupDriver::tidy()
//   6. quote()          → LookupDriver::quote()
//   7. version_report() → LookupDriver::version_report()
//
// Additional trait methods (replacing struct fields):
//   8. lookup_type()    → replaces `type` field (bit flags)
//   9. driver_name()    → replaces `name` field
//
// Per AAP §0.7.2: This file contains ZERO `unsafe` code.
// Per AAP §0.7.3: The trait interface is synchronous. Individual lookup
// implementations that use async APIs bridge via
// `tokio::runtime::Runtime::block_on()`.

use crate::DriverError;
use std::fmt;

// =============================================================================
// Lookup Type Flags
// =============================================================================

/// Lookup type flags — replaces C bit-flag constants from `lookupapi.h` lines 12-18.
///
/// The C `type` field in `lookup_info` is a set of bit flags that describe the
/// lookup's behavior:
///   - `lookup_querystyle` → query-style lookup (SQL, LDAP, DNS, etc.)
///   - `lookup_absfile`    → an absolute file name is required (single-key only)
///
/// A lookup with neither flag set is a basic single-key lookup that uses a
/// relative file path (e.g., `lsearch`). Flags can be combined via bitwise OR.
///
/// # Examples
///
/// ```
/// use exim_drivers::lookup_driver::LookupType;
///
/// // A query-style lookup (like MySQL)
/// let mysql_type = LookupType::QUERY_STYLE;
/// assert!(mysql_type.is_query_style());
/// assert!(!mysql_type.is_single_key());
///
/// // A single-key lookup with absolute file (like CDB)
/// let cdb_type = LookupType::ABS_FILE;
/// assert!(cdb_type.is_abs_file());
/// assert!(cdb_type.is_single_key());
///
/// // A basic single-key lookup (like lsearch)
/// let lsearch_type = LookupType::NONE;
/// assert!(lsearch_type.is_single_key());
/// assert!(!lsearch_type.is_abs_file());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LookupType(u32);

impl LookupType {
    /// Query-style lookup (e.g., SQL, LDAP, DNS).
    ///
    /// Query-style lookups receive a query string rather than a file+key pair.
    /// They do not support partial matching or `*`/`*@` defaults.
    ///
    /// C equivalent: `lookup_querystyle` (bit 0)
    pub const QUERY_STYLE: Self = Self(1);

    /// Single-key lookup requiring an absolute file path.
    ///
    /// This flag is only meaningful for single-key (non-query) lookups. When set,
    /// the lookup requires an absolute file path rather than a relative one.
    ///
    /// C equivalent: `lookup_absfile` (bit 1)
    pub const ABS_FILE: Self = Self(2);

    /// No flags set — basic single-key lookup with relative file path.
    ///
    /// This is the default for lookups like `lsearch` that use a relative file
    /// path and a simple key.
    pub const NONE: Self = Self(0);

    /// Construct a `LookupType` from a raw bit-flag value.
    ///
    /// This is provided for interoperability with C code during migration. Prefer
    /// using the named constants (`QUERY_STYLE`, `ABS_FILE`, `NONE`) in new code.
    #[inline]
    pub const fn from_raw(value: u32) -> Self {
        Self(value)
    }

    /// Return the raw bit-flag value.
    ///
    /// This is provided for interoperability with C code during migration and
    /// for serialization purposes.
    #[inline]
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Check if this is a query-style lookup.
    ///
    /// Query-style lookups (SQL, LDAP, DNS, etc.) do not use a file path; instead
    /// they receive a query string directly. Partial matching and `*`/`*@` defaults
    /// are not permitted for query-style lookups.
    ///
    /// C equivalent: `mac_islookup(li, lookup_querystyle)`
    #[inline]
    pub const fn is_query_style(self) -> bool {
        self.0 & Self::QUERY_STYLE.0 != 0
    }

    /// Check if an absolute file path is required.
    ///
    /// Only meaningful for single-key (non-query) lookups. When true, the lookup
    /// expects a fully qualified file system path.
    ///
    /// C equivalent: checking `lookup_absfile` bit in the type field
    #[inline]
    pub const fn is_abs_file(self) -> bool {
        self.0 & Self::ABS_FILE.0 != 0
    }

    /// Check if this is a single-key style lookup (not query-style).
    ///
    /// Single-key lookups use a file path (relative or absolute) and a key to
    /// perform the lookup. They support partial matching and `*`/`*@` defaults.
    #[inline]
    pub const fn is_single_key(self) -> bool {
        !self.is_query_style()
    }

    /// Check if any flag in `other` is set in `self`.
    ///
    /// Equivalent to `(self & other) != NONE`.
    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

impl std::ops::BitOr for LookupType {
    type Output = Self;

    /// Combine two lookup type flag sets.
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for LookupType {
    /// Accumulate lookup type flags.
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for LookupType {
    type Output = Self;

    /// Intersect two lookup type flag sets.
    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl Default for LookupType {
    /// Default is `LookupType::NONE` — a basic single-key lookup.
    #[inline]
    fn default() -> Self {
        Self::NONE
    }
}

impl fmt::Display for LookupType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_query_style() {
            write!(f, "query-style")?;
        } else if self.is_abs_file() {
            write!(f, "single-key(abs-file)")?;
        } else {
            write!(f, "single-key")?;
        }
        Ok(())
    }
}

// =============================================================================
// Lookup Result Enum
// =============================================================================

/// Result of a lookup `find()` operation.
///
/// Maps to C `find()` return codes:
///   - `OK`    (0) → `Found` — lookup succeeded, value returned
///   - `DEFER` (1) → `Deferred` — temporary failure, should be retried
///   - `FAIL`  (2) → `NotFound` — key not found (this is not an error)
///
/// The C implementation returns these as integer codes with separate out-parameters
/// for the result value, error message, and cache TTL. The Rust enum encapsulates
/// all associated data in each variant.
///
/// # Examples
///
/// ```
/// use exim_drivers::lookup_driver::LookupResult;
///
/// let found = LookupResult::Found {
///     value: "user@example.com".to_string(),
///     cache_ttl: Some(3600),
/// };
/// assert!(matches!(found, LookupResult::Found { .. }));
///
/// let not_found = LookupResult::NotFound;
/// assert!(matches!(not_found, LookupResult::NotFound));
///
/// let deferred = LookupResult::Deferred {
///     message: "database connection timeout".to_string(),
/// };
/// assert!(matches!(deferred, LookupResult::Deferred { .. }));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupResult {
    /// Lookup found a value.
    ///
    /// C equivalent: `find()` returns `OK` (0) with the answer in the `uschar **`
    /// out-parameter and the cache TTL in the `uint *` out-parameter.
    Found {
        /// The value found by the lookup operation.
        value: String,

        /// Cache TTL in seconds. `None` means use the system default cache
        /// behavior. `Some(0)` means do not cache this result. Any positive
        /// value specifies the number of seconds to cache the result.
        ///
        /// C: `uint *` cache TTL parameter (Version 3+ of the lookup API —
        /// changed from boolean non/cache to TTL in seconds).
        cache_ttl: Option<u32>,
    },

    /// Key not found — this is not an error condition.
    ///
    /// C equivalent: `find()` returns `FAIL` (2). No answer or error message
    /// is set. The caller should try alternate lookup strategies or report
    /// a "not found" condition.
    NotFound,

    /// Temporary failure — the lookup should be retried later.
    ///
    /// C equivalent: `find()` returns `DEFER` (1) with an error message in
    /// the `uschar **` error out-parameter. This typically indicates a
    /// transient issue (database connection failure, DNS timeout, file lock
    /// contention, etc.).
    Deferred {
        /// Human-readable description of the reason for deferral, suitable
        /// for logging. This replaces the C error message out-parameter.
        message: String,
    },
}

impl LookupResult {
    /// Returns `true` if the lookup found a value.
    #[inline]
    pub fn is_found(&self) -> bool {
        matches!(self, Self::Found { .. })
    }

    /// Returns `true` if the key was not found.
    #[inline]
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound)
    }

    /// Returns `true` if the lookup was deferred (temporary failure).
    #[inline]
    pub fn is_deferred(&self) -> bool {
        matches!(self, Self::Deferred { .. })
    }

    /// Extract the found value, if any.
    ///
    /// Returns `Some(&str)` if the result is `Found`, `None` otherwise.
    pub fn value(&self) -> Option<&str> {
        match self {
            Self::Found { value, .. } => Some(value.as_str()),
            _ => None,
        }
    }

    /// Extract the cache TTL, if the result is `Found`.
    ///
    /// Returns the cache TTL in seconds, or `None` if the result is not `Found`
    /// or if the TTL was not specified.
    pub fn cache_ttl(&self) -> Option<u32> {
        match self {
            Self::Found { cache_ttl, .. } => *cache_ttl,
            _ => None,
        }
    }

    /// Convert to the corresponding C-style return code.
    ///
    /// - `Found`    → 0 (`OK`)
    /// - `Deferred` → 1 (`DEFER`)
    /// - `NotFound` → 2 (`FAIL`)
    pub fn to_c_code(&self) -> i32 {
        match self {
            Self::Found { .. } => 0,
            Self::Deferred { .. } => 1,
            Self::NotFound => 2,
        }
    }
}

impl fmt::Display for LookupResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Found { value, cache_ttl } => {
                write!(f, "Found({value:?}")?;
                if let Some(ttl) = cache_ttl {
                    write!(f, ", ttl={ttl}s")?;
                }
                write!(f, ")")
            }
            Self::NotFound => write!(f, "NotFound"),
            Self::Deferred { message } => write!(f, "Deferred({message})"),
        }
    }
}

// =============================================================================
// Lookup Handle Type
// =============================================================================

/// Opaque handle for an open lookup connection or file.
///
/// Replaces the C `void *` handle parameter used in all lookup function pointers.
/// Each lookup implementation stores its own internal state (file descriptor, database
/// connection, parsed data structures, etc.) inside this boxed `Any` trait object.
///
/// The `Send + Sync` bounds ensure that lookup handles can be safely shared across
/// threads (required for the fork-per-connection model where a parent process may
/// hold handles that child processes need access to).
///
/// # Usage
///
/// Lookup driver implementations create handles via their `open()` method:
/// ```ignore
/// fn open(&self, filename: Option<&str>) -> Result<LookupHandle, DriverError> {
///     let state = MyLookupState::new(filename)?;
///     Ok(Box::new(state))
/// }
/// ```
///
/// And downcast them in `find()`, `check()`, and `close()`:
/// ```ignore
/// fn find(&self, handle: &LookupHandle, ...) -> Result<LookupResult, DriverError> {
///     let state = handle.downcast_ref::<MyLookupState>()
///         .ok_or_else(|| DriverError::ExecutionFailed("invalid handle type".into()))?;
///     // ... use state ...
/// }
/// ```
pub type LookupHandle = Box<dyn std::any::Any + Send + Sync>;

// =============================================================================
// LookupDriver Trait
// =============================================================================

/// Trait for lookup driver implementations.
///
/// Replaces the C `lookup_info` struct function pointers from `lookupapi.h`
/// lines 20-58. All 7 function pointers from the C struct are faithfully
/// represented as trait methods, plus 2 additional methods replacing struct
/// fields (`name` and `type`).
///
/// Each lookup backend (lsearch, mysql, ldap, redis, cdb, sqlite, etc.)
/// implements this trait. The trait is object-safe, allowing dynamic dispatch
/// via `Box<dyn LookupDriver>` and `&dyn LookupDriver`.
///
/// # Thread Safety
///
/// The `Send + Sync` bounds are required because:
///   - `Send`: Lookup driver instances may be moved between threads during
///     configuration parsing and daemon startup.
///   - `Sync`: Multiple child processes may hold references to the same driver
///     instance after fork (via `Arc<dyn LookupDriver>`).
///
/// # Async Bridging
///
/// Per AAP §0.7.3: The trait interface is synchronous. Individual lookup
/// implementations that need async I/O (e.g., `mysql_async`, `tokio-postgres`)
/// create a scoped `tokio::runtime::Runtime` and bridge via `block_on()`. The
/// tokio runtime MUST NOT be used for the main daemon event loop.
///
/// # C Function Pointer Mapping
///
/// | C Function Pointer     | Rust Trait Method     | Notes                          |
/// |------------------------|-----------------------|--------------------------------|
/// | `void *(*open)(...)`   | `fn open(...)`        | Returns `LookupHandle`         |
/// | `BOOL (*check)(...)`   | `fn check(...)`       | Returns `Result<bool, ...>`    |
/// | `int (*find)(...)`     | `fn find(...)`        | Returns `LookupResult`         |
/// | `void (*close)(...)`   | `fn close(...)`       | Takes ownership of handle      |
/// | `void (*tidy)(void)`   | `fn tidy(&self)`      | Cleanup all resources          |
/// | `uschar *(*quote)(...)` | `fn quote(...)`      | Default impl returns `None`    |
/// | `gstring *(*version_report)(...)` | `fn version_report(...)` | Default impl returns `None` |
pub trait LookupDriver: Send + Sync + fmt::Debug {
    /// Open a lookup source (file or connection).
    ///
    /// Replaces C: `void *(*open)(const uschar *, uschar **)`
    ///
    /// For file-based (single-key) lookups: opens the specified file and returns
    /// a handle containing the file descriptor or parsed file contents.
    ///
    /// For query-style lookups: establishes a connection to the external service
    /// (database, LDAP server, etc.) or may be a no-op if connections are
    /// established on-demand in `find()`.
    ///
    /// # Parameters
    ///
    /// - `filename`: The file to open. `Some(path)` for file-based lookups,
    ///   `None` for query-style lookups that don't use files.
    ///
    /// # Returns
    ///
    /// A boxed opaque handle on success, or a `DriverError` on failure. The
    /// handle is passed to subsequent `check()`, `find()`, and `close()` calls.
    fn open(&self, filename: Option<&str>) -> Result<LookupHandle, DriverError>;

    /// Check a lookup file for validity and accessibility.
    ///
    /// Replaces C: `BOOL (*check)(void *, const uschar *, int, uid_t *, gid_t *, uschar **)`
    ///
    /// For file-based lookups: verifies that the file exists, is readable, and
    /// has acceptable permissions and ownership. This prevents information
    /// leakage through world-readable lookup files in sensitive configurations.
    ///
    /// For query-style lookups: typically returns `Ok(true)` since there is no
    /// file to check.
    ///
    /// # Parameters
    ///
    /// - `handle`: The handle returned by a prior `open()` call.
    /// - `filename`: The file name to check (may differ from the one used in
    ///   `open()` if the lookup supports multiple files per handle).
    /// - `modemask`: Bitmask of file permission bits that must NOT be set. For
    ///   example, `0o022` rejects group- and world-writable files.
    ///   C: `int modemask` parameter.
    /// - `owners`: Allowed owner UIDs. Empty slice means any owner is acceptable.
    ///   C: `uid_t *` parameter.
    /// - `owngroups`: Allowed owner GIDs. Empty slice means any group is acceptable.
    ///   C: `gid_t *` parameter.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the file passes all checks, `Ok(false)` if it fails a
    /// check (but the failure is not an error condition), or `Err(DriverError)`
    /// if an unexpected error occurred during checking.
    fn check(
        &self,
        handle: &LookupHandle,
        filename: Option<&str>,
        modemask: i32,
        owners: &[u32],
        owngroups: &[u32],
    ) -> Result<bool, DriverError>;

    /// Find a value by key or query — the primary lookup operation.
    ///
    /// Replaces C: `int (*find)(void *, const uschar *, const uschar *, int,
    ///              uschar **, uschar **, uint *, const uschar *)`
    ///
    /// For single-key lookups: looks up `key_or_query` in the file identified
    /// by `filename` (or the file associated with `handle`).
    ///
    /// For query-style lookups: executes `key_or_query` as a query against the
    /// backend service. `filename` is `None`.
    ///
    /// # Parameters
    ///
    /// - `handle`: The handle returned by a prior `open()` call.
    /// - `filename`: The file to search. `Some(path)` for single-key lookups,
    ///   `None` for query-style lookups.
    /// - `key_or_query`: The key to look up (single-key) or query to execute
    ///   (query-style). The C API passes length separately; in Rust, the string
    ///   slice carries its length.
    /// - `options`: Optional lookup-specific options string (comma-separated).
    ///   C: `const uschar *` options parameter.
    ///
    /// # Returns
    ///
    /// A `LookupResult` on success:
    ///   - `Found { value, cache_ttl }` — key/query matched, value returned
    ///   - `NotFound` — key/query did not match (not an error)
    ///   - `Deferred { message }` — temporary failure, should retry
    ///
    /// Returns `Err(DriverError)` for unexpected errors that prevent the lookup
    /// from completing (e.g., malformed query, protocol error).
    fn find(
        &self,
        handle: &LookupHandle,
        filename: Option<&str>,
        key_or_query: &str,
        options: Option<&str>,
    ) -> Result<LookupResult, DriverError>;

    /// Close an open lookup handle, releasing associated resources.
    ///
    /// Replaces C: `void (*close)(void *)`
    ///
    /// Takes ownership of the handle and drops it, ensuring that file descriptors,
    /// database connections, and other resources are properly cleaned up. This is
    /// called when a cached open file/connection is evicted from the LRU cache
    /// or when `tidy()` is called.
    ///
    /// # Parameters
    ///
    /// - `handle`: The handle to close. Ownership is transferred to this method;
    ///   the handle is consumed and cannot be used afterward.
    fn close(&self, handle: LookupHandle);

    /// Tidy up all resources associated with this lookup type.
    ///
    /// Replaces C: `void (*tidy)(void)`
    ///
    /// Called during periodic cleanup (e.g., between message processing cycles)
    /// to release cached connections, file handles, and memory. After this call,
    /// any previously opened handles for this lookup type are invalid.
    ///
    /// Implementations should close all open connections, flush caches, and
    /// reset internal state to a clean baseline.
    fn tidy(&self);

    /// Quote a string for safe use in this lookup type.
    ///
    /// Replaces C: `uschar *(*quote)(uschar *, uschar *, unsigned)`
    ///
    /// For SQL-based lookups: performs SQL escaping (e.g., doubling single quotes).
    /// For LDAP lookups: performs LDAP filter escaping.
    /// For file-based lookups: typically returns `None` (no quoting needed).
    ///
    /// The default implementation returns `None`, indicating that no
    /// lookup-type-specific quoting is required.
    ///
    /// # Parameters
    ///
    /// - `value`: The string to quote/escape.
    /// - `additional`: Additional context data from the quote name specifier.
    ///   In C, this was `uschar *` additional data; most implementations ignore it.
    ///
    /// # Returns
    ///
    /// `Some(quoted_string)` if quoting was performed, `None` if the input
    /// does not need quoting or this lookup type does not support quoting.
    fn quote(&self, _value: &str, _additional: Option<&str>) -> Option<String> {
        None
    }

    /// Diagnostic version reporting for `-bV` output.
    ///
    /// Replaces C: `gstring * (*version_report)(gstring *)`
    ///
    /// Returns an optional string containing version and configuration
    /// information about the lookup backend. This is displayed when Exim is
    /// run with `-bV` (version information mode).
    ///
    /// The default implementation returns `None`, indicating no additional
    /// version information is available.
    ///
    /// # Returns
    ///
    /// `Some(report)` with version details (e.g., "Library version: libpq 16.2"),
    /// or `None` if no report is available.
    fn version_report(&self) -> Option<String> {
        None
    }

    /// The lookup type flags (query-style vs single-key, abs-file requirement).
    ///
    /// Replaces C: `int type` field in `lookup_info`.
    ///
    /// This determines how the lookup framework treats this backend:
    ///   - Query-style lookups receive a query string directly
    ///   - Single-key lookups receive a file path + key
    ///   - Abs-file lookups require an absolute file path
    fn lookup_type(&self) -> LookupType;

    /// Driver name for identification and configuration file matching.
    ///
    /// Replaces C: `uschar *name` field in `lookup_info`.
    ///
    /// This is the name used in Exim configuration files to reference this
    /// lookup type (e.g., "lsearch", "mysql", "ldap", "redis", "cdb").
    /// It must be unique across all registered lookup drivers.
    fn driver_name(&self) -> &str;
}

// =============================================================================
// LookupDriverFactory
// =============================================================================

/// Factory for creating `LookupDriver` instances.
///
/// Registered at compile time via `inventory::submit!()`. The driver registry
/// collects all submitted factories and uses them to create driver instances
/// when referenced in the Exim configuration.
///
/// Replaces the C `lookup_module_info` struct (lookupapi.h lines 69-73) and
/// the `add_lookup_to_tree()` / `addlookupmodule()` registration functions
/// from `drtables.c` lines 80-100.
///
/// In C, a single module could provide multiple lookup types (e.g., the lsearch
/// module provides `lsearch`, `wildlsearch`, and `nwildlsearch`). In Rust,
/// each lookup type gets its own factory entry registered individually.
///
/// # Examples
///
/// ```ignore
/// use exim_drivers::lookup_driver::{LookupDriverFactory, LookupType};
///
/// inventory::submit! {
///     LookupDriverFactory {
///         name: "lsearch",
///         create: || Box::new(LsearchDriver::new()),
///         lookup_type: LookupType::NONE,
///         avail_string: Some("lsearch (built-in)"),
///     }
/// }
/// ```
pub struct LookupDriverFactory {
    /// Name of the lookup type (e.g., "lsearch", "mysql", "ldap").
    ///
    /// Must be unique across all registered factories. This name is used for:
    ///   - Configuration file matching (`${lookup TYPE { ... } }`)
    ///   - Registry resolution in `drtables.c` equivalent code
    ///   - Error messages and diagnostic output
    pub name: &'static str,

    /// Factory function that creates a new lookup driver instance.
    ///
    /// Called once per lookup type during initialization. The returned trait
    /// object is stored in the registry and reused for all lookups of this type.
    pub create: fn() -> Box<dyn LookupDriver>,

    /// Lookup type flags for this lookup backend.
    ///
    /// Determines whether this is a query-style or single-key lookup and
    /// whether an absolute file path is required.
    pub lookup_type: LookupType,

    /// Optional display string shown in `-bV` version output.
    ///
    /// When `Some`, this string is displayed instead of the raw `name` in
    /// `lookup_show_supported()` output. When `None`, the `name` is used.
    ///
    /// C equivalent: `avail_string` in `driver_info` base struct.
    pub avail_string: Option<&'static str>,
}

// Implement Debug manually since function pointers don't implement Debug by default.
impl fmt::Debug for LookupDriverFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LookupDriverFactory")
            .field("name", &self.name)
            .field("lookup_type", &self.lookup_type)
            .field("avail_string", &self.avail_string)
            .finish_non_exhaustive()
    }
}

// NOTE: `inventory::collect!(LookupDriverFactory)` is declared in `registry.rs`
// to centralize all collection declarations. This enables
// `inventory::iter::<LookupDriverFactory>()` to iterate over all factories
// submitted by driver implementation crates.

// =============================================================================
// Lookup Module Info
// =============================================================================

/// Information about a lookup module that may provide multiple lookup types.
///
/// Replaces C `lookup_module_info` struct (lookupapi.h lines 69-73):
/// ```c
/// typedef struct lookup_module_info {
///   uint          magic;              // LOOKUP_MODULE_INFO_MAGIC (0x4c4d4936)
///   lookup_info **lookups;            // array of lookup_info pointers
///   uint          lookupcount;        // number of lookups in this module
/// } lookup_module_info;
/// ```
///
/// In the Rust architecture, the `magic` field is not needed (Rust's type system
/// prevents ABI mismatches). The `lookups` array and `lookupcount` are replaced
/// by `lookup_names`, which lists the names of all lookup types provided by this
/// module. The actual lookup types are registered individually via
/// `LookupDriverFactory` entries.
///
/// # Purpose
///
/// This struct exists for documentation and diagnostic purposes. It allows
/// the system to report which lookup types belong to which module (e.g.,
/// "the lsearch module provides: lsearch, wildlsearch, nwildlsearch").
///
/// # Examples
///
/// ```
/// use exim_drivers::lookup_driver::LookupModuleInfo;
///
/// static LSEARCH_MODULE: LookupModuleInfo = LookupModuleInfo {
///     module_name: "lsearch",
///     lookup_names: &["lsearch", "wildlsearch", "nwildlsearch"],
/// };
/// assert_eq!(LSEARCH_MODULE.module_name, "lsearch");
/// assert_eq!(LSEARCH_MODULE.lookup_names.len(), 3);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LookupModuleInfo {
    /// Name of the lookup module.
    ///
    /// This is the module-level identifier (e.g., "lsearch", "mysql", "ldap").
    /// It may differ from the individual lookup type names provided by the
    /// module (e.g., the "lsearch" module provides "lsearch", "wildlsearch",
    /// and "nwildlsearch" lookup types).
    pub module_name: &'static str,

    /// Names of all lookup types provided by this module.
    ///
    /// Each name in this slice corresponds to a `LookupDriverFactory` entry
    /// that has been registered via `inventory::submit!`. The names must match
    /// the `name` field of the corresponding `LookupDriverFactory`.
    pub lookup_names: &'static [&'static str],
}

impl fmt::Display for LookupModuleInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(", self.module_name)?;
        for (i, name) in self.lookup_names.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{name}")?;
        }
        write!(f, ")")
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // LookupType tests
    // =========================================================================

    #[test]
    fn test_lookup_type_query_style() {
        let lt = LookupType::QUERY_STYLE;
        assert!(lt.is_query_style());
        assert!(!lt.is_single_key());
        assert!(!lt.is_abs_file());
    }

    #[test]
    fn test_lookup_type_abs_file() {
        let lt = LookupType::ABS_FILE;
        assert!(!lt.is_query_style());
        assert!(lt.is_single_key());
        assert!(lt.is_abs_file());
    }

    #[test]
    fn test_lookup_type_none() {
        let lt = LookupType::NONE;
        assert!(!lt.is_query_style());
        assert!(lt.is_single_key());
        assert!(!lt.is_abs_file());
        assert_eq!(lt.raw(), 0);
    }

    #[test]
    fn test_lookup_type_default() {
        let lt = LookupType::default();
        assert_eq!(lt, LookupType::NONE);
    }

    #[test]
    fn test_lookup_type_bitor() {
        let lt = LookupType::QUERY_STYLE | LookupType::ABS_FILE;
        assert!(lt.is_query_style());
        assert!(lt.is_abs_file());
        assert_eq!(lt.raw(), 3);
    }

    #[test]
    fn test_lookup_type_bitor_assign() {
        let mut lt = LookupType::NONE;
        lt |= LookupType::QUERY_STYLE;
        assert!(lt.is_query_style());
        lt |= LookupType::ABS_FILE;
        assert!(lt.is_abs_file());
    }

    #[test]
    fn test_lookup_type_bitand() {
        let lt = LookupType::QUERY_STYLE | LookupType::ABS_FILE;
        let masked = lt & LookupType::QUERY_STYLE;
        assert_eq!(masked, LookupType::QUERY_STYLE);
    }

    #[test]
    fn test_lookup_type_contains() {
        let lt = LookupType::QUERY_STYLE | LookupType::ABS_FILE;
        assert!(lt.contains(LookupType::QUERY_STYLE));
        assert!(lt.contains(LookupType::ABS_FILE));

        let single = LookupType::NONE;
        assert!(!single.contains(LookupType::QUERY_STYLE));
    }

    #[test]
    fn test_lookup_type_from_raw() {
        let lt = LookupType::from_raw(1);
        assert_eq!(lt, LookupType::QUERY_STYLE);

        let lt = LookupType::from_raw(2);
        assert_eq!(lt, LookupType::ABS_FILE);

        let lt = LookupType::from_raw(3);
        assert!(lt.is_query_style());
        assert!(lt.is_abs_file());
    }

    #[test]
    fn test_lookup_type_display() {
        assert_eq!(LookupType::QUERY_STYLE.to_string(), "query-style");
        assert_eq!(LookupType::ABS_FILE.to_string(), "single-key(abs-file)");
        assert_eq!(LookupType::NONE.to_string(), "single-key");
    }

    #[test]
    fn test_lookup_type_equality() {
        assert_eq!(LookupType::QUERY_STYLE, LookupType::QUERY_STYLE);
        assert_ne!(LookupType::QUERY_STYLE, LookupType::ABS_FILE);
        assert_ne!(LookupType::QUERY_STYLE, LookupType::NONE);
    }

    #[test]
    fn test_lookup_type_clone_copy() {
        let lt = LookupType::QUERY_STYLE;
        let lt2 = lt;
        assert_eq!(lt, lt2);
    }

    #[test]
    fn test_lookup_type_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(LookupType::QUERY_STYLE);
        set.insert(LookupType::ABS_FILE);
        set.insert(LookupType::QUERY_STYLE); // duplicate
        assert_eq!(set.len(), 2);
    }

    // =========================================================================
    // LookupResult tests
    // =========================================================================

    #[test]
    fn test_lookup_result_found() {
        let result = LookupResult::Found {
            value: "test_value".to_string(),
            cache_ttl: Some(3600),
        };
        assert!(result.is_found());
        assert!(!result.is_not_found());
        assert!(!result.is_deferred());
        assert_eq!(result.value(), Some("test_value"));
        assert_eq!(result.cache_ttl(), Some(3600));
        assert_eq!(result.to_c_code(), 0);
    }

    #[test]
    fn test_lookup_result_found_no_ttl() {
        let result = LookupResult::Found {
            value: "value".to_string(),
            cache_ttl: None,
        };
        assert!(result.is_found());
        assert_eq!(result.value(), Some("value"));
        assert_eq!(result.cache_ttl(), None);
    }

    #[test]
    fn test_lookup_result_not_found() {
        let result = LookupResult::NotFound;
        assert!(!result.is_found());
        assert!(result.is_not_found());
        assert!(!result.is_deferred());
        assert_eq!(result.value(), None);
        assert_eq!(result.cache_ttl(), None);
        assert_eq!(result.to_c_code(), 2);
    }

    #[test]
    fn test_lookup_result_deferred() {
        let result = LookupResult::Deferred {
            message: "connection timeout".to_string(),
        };
        assert!(!result.is_found());
        assert!(!result.is_not_found());
        assert!(result.is_deferred());
        assert_eq!(result.value(), None);
        assert_eq!(result.cache_ttl(), None);
        assert_eq!(result.to_c_code(), 1);
    }

    #[test]
    fn test_lookup_result_display() {
        let found = LookupResult::Found {
            value: "val".to_string(),
            cache_ttl: Some(60),
        };
        let display = found.to_string();
        assert!(display.contains("Found"));
        assert!(display.contains("val"));
        assert!(display.contains("ttl=60s"));

        let found_no_ttl = LookupResult::Found {
            value: "val2".to_string(),
            cache_ttl: None,
        };
        let display = found_no_ttl.to_string();
        assert!(display.contains("Found"));
        assert!(!display.contains("ttl"));

        assert_eq!(LookupResult::NotFound.to_string(), "NotFound");

        let deferred = LookupResult::Deferred {
            message: "timeout".to_string(),
        };
        let display = deferred.to_string();
        assert!(display.contains("Deferred"));
        assert!(display.contains("timeout"));
    }

    #[test]
    fn test_lookup_result_equality() {
        let a = LookupResult::Found {
            value: "x".to_string(),
            cache_ttl: Some(10),
        };
        let b = LookupResult::Found {
            value: "x".to_string(),
            cache_ttl: Some(10),
        };
        assert_eq!(a, b);

        let c = LookupResult::Found {
            value: "y".to_string(),
            cache_ttl: Some(10),
        };
        assert_ne!(a, c);

        assert_eq!(LookupResult::NotFound, LookupResult::NotFound);
        assert_ne!(
            LookupResult::NotFound,
            LookupResult::Deferred {
                message: "err".to_string(),
            }
        );
    }

    #[test]
    fn test_lookup_result_clone() {
        let original = LookupResult::Found {
            value: "cloned".to_string(),
            cache_ttl: Some(120),
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    // =========================================================================
    // LookupDriverFactory tests
    // =========================================================================

    /// A minimal mock LookupDriver for testing factory creation.
    #[derive(Debug)]
    struct MockLookupDriver {
        name: &'static str,
        lt: LookupType,
    }

    impl LookupDriver for MockLookupDriver {
        fn open(&self, _filename: Option<&str>) -> Result<LookupHandle, DriverError> {
            Ok(Box::new(42_u32))
        }

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

        fn find(
            &self,
            _handle: &LookupHandle,
            _filename: Option<&str>,
            key_or_query: &str,
            _options: Option<&str>,
        ) -> Result<LookupResult, DriverError> {
            if key_or_query == "existing_key" {
                Ok(LookupResult::Found {
                    value: "found_value".to_string(),
                    cache_ttl: Some(300),
                })
            } else {
                Ok(LookupResult::NotFound)
            }
        }

        fn close(&self, _handle: LookupHandle) {}

        fn tidy(&self) {}

        fn lookup_type(&self) -> LookupType {
            self.lt
        }

        fn driver_name(&self) -> &str {
            self.name
        }
    }

    #[test]
    fn test_lookup_driver_factory_create() {
        let factory = LookupDriverFactory {
            name: "mock_lsearch",
            create: || {
                Box::new(MockLookupDriver {
                    name: "mock_lsearch",
                    lt: LookupType::NONE,
                })
            },
            lookup_type: LookupType::NONE,
            avail_string: Some("mock lsearch (test)"),
        };

        assert_eq!(factory.name, "mock_lsearch");
        assert_eq!(factory.lookup_type, LookupType::NONE);
        assert_eq!(factory.avail_string, Some("mock lsearch (test)"));

        let driver = (factory.create)();
        assert_eq!(driver.driver_name(), "mock_lsearch");
        assert!(driver.lookup_type().is_single_key());
    }

    #[test]
    fn test_lookup_driver_factory_debug() {
        let factory = LookupDriverFactory {
            name: "test_driver",
            create: || {
                Box::new(MockLookupDriver {
                    name: "test_driver",
                    lt: LookupType::QUERY_STYLE,
                })
            },
            lookup_type: LookupType::QUERY_STYLE,
            avail_string: None,
        };

        let debug_str = format!("{factory:?}");
        assert!(debug_str.contains("test_driver"));
        assert!(debug_str.contains("LookupDriverFactory"));
    }

    // =========================================================================
    // LookupModuleInfo tests
    // =========================================================================

    #[test]
    fn test_lookup_module_info() {
        let module = LookupModuleInfo {
            module_name: "lsearch",
            lookup_names: &["lsearch", "wildlsearch", "nwildlsearch"],
        };
        assert_eq!(module.module_name, "lsearch");
        assert_eq!(module.lookup_names.len(), 3);
        assert_eq!(module.lookup_names[0], "lsearch");
        assert_eq!(module.lookup_names[1], "wildlsearch");
        assert_eq!(module.lookup_names[2], "nwildlsearch");
    }

    #[test]
    fn test_lookup_module_info_display() {
        let module = LookupModuleInfo {
            module_name: "lsearch",
            lookup_names: &["lsearch", "wildlsearch", "nwildlsearch"],
        };
        assert_eq!(
            module.to_string(),
            "lsearch(lsearch, wildlsearch, nwildlsearch)"
        );
    }

    #[test]
    fn test_lookup_module_info_single_lookup() {
        let module = LookupModuleInfo {
            module_name: "redis",
            lookup_names: &["redis"],
        };
        assert_eq!(module.to_string(), "redis(redis)");
    }

    #[test]
    fn test_lookup_module_info_equality() {
        let a = LookupModuleInfo {
            module_name: "mysql",
            lookup_names: &["mysql"],
        };
        let b = LookupModuleInfo {
            module_name: "mysql",
            lookup_names: &["mysql"],
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_lookup_module_info_copy() {
        let original = LookupModuleInfo {
            module_name: "pgsql",
            lookup_names: &["pgsql"],
        };
        let copied = original;
        assert_eq!(original, copied);
    }

    // =========================================================================
    // LookupDriver trait object tests
    // =========================================================================

    #[test]
    fn test_mock_lookup_driver_open_and_find() {
        let driver = MockLookupDriver {
            name: "test_lookup",
            lt: LookupType::NONE,
        };

        let handle = driver.open(Some("/etc/aliases")).unwrap();
        let result = driver
            .find(&handle, Some("/etc/aliases"), "existing_key", None)
            .unwrap();
        assert!(matches!(
            result,
            LookupResult::Found {
                ref value,
                cache_ttl: Some(300)
            } if value == "found_value"
        ));

        let result = driver
            .find(&handle, Some("/etc/aliases"), "missing_key", None)
            .unwrap();
        assert_eq!(result, LookupResult::NotFound);

        driver.close(handle);
    }

    #[test]
    fn test_mock_lookup_driver_check() {
        let driver = MockLookupDriver {
            name: "test_check",
            lt: LookupType::ABS_FILE,
        };

        let handle = driver.open(Some("/etc/aliases")).unwrap();
        let ok = driver
            .check(&handle, Some("/etc/aliases"), 0o022, &[], &[])
            .unwrap();
        assert!(ok);
        driver.close(handle);
    }

    #[test]
    fn test_mock_lookup_driver_default_quote() {
        let driver = MockLookupDriver {
            name: "test_quote",
            lt: LookupType::NONE,
        };
        assert_eq!(driver.quote("test'value", None), None);
    }

    #[test]
    fn test_mock_lookup_driver_default_version_report() {
        let driver = MockLookupDriver {
            name: "test_version",
            lt: LookupType::NONE,
        };
        assert_eq!(driver.version_report(), None);
    }

    #[test]
    fn test_mock_lookup_driver_tidy() {
        let driver = MockLookupDriver {
            name: "test_tidy",
            lt: LookupType::NONE,
        };
        driver.tidy(); // Should not panic
    }

    #[test]
    fn test_lookup_driver_as_trait_object() {
        let driver: Box<dyn LookupDriver> = Box::new(MockLookupDriver {
            name: "boxed_lookup",
            lt: LookupType::QUERY_STYLE,
        });

        assert_eq!(driver.driver_name(), "boxed_lookup");
        assert!(driver.lookup_type().is_query_style());

        let handle = driver.open(None).unwrap();
        let result = driver.find(&handle, None, "existing_key", None).unwrap();
        assert!(result.is_found());
        driver.close(handle);
    }

    #[test]
    fn test_lookup_driver_debug_trait() {
        let driver = MockLookupDriver {
            name: "debug_test",
            lt: LookupType::NONE,
        };
        let debug_str = format!("{driver:?}");
        assert!(debug_str.contains("MockLookupDriver"));
        assert!(debug_str.contains("debug_test"));
    }

    // =========================================================================
    // inventory collection verification
    // =========================================================================

    #[test]
    fn test_inventory_iter_compiles() {
        // Verify that inventory::iter::<LookupDriverFactory>() compiles.
        // In a unit test context, no factories are submitted, so the iterator
        // should yield zero items.
        let count = inventory::iter::<LookupDriverFactory>.into_iter().count();
        // We don't assert a specific count because other test binaries may
        // have submitted factories. In isolation, this is 0.
        assert!(count < 1000, "sanity check: unreasonable factory count");
    }
}
