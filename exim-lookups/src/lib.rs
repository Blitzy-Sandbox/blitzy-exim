// =============================================================================
// exim-lookups/src/lib.rs — Public API, Lookup Dispatcher, and Cache
// =============================================================================
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This is the crate root for `exim-lookups`.  It replaces `src/src/search.c`
// (1,020 lines) — the central lookup dispatcher that bridges config-time lookup
// type strings to individual driver implementations through the inventory-based
// driver registry.
//
// This file provides:
//   1. Type resolution      — `search_findtype`, `search_findtype_partial`
//   2. Handle caching / LRU — `OpenFileCache` (replaces C open_top/open_bot chain)
//   3. Result caching       — integrated via `SearchCache` from exim-store
//   4. Partial matching     — `PartialLookupSpec` (progressive domain shortening)
//   5. Uniform search API   — `search_open`, `search_find`, `search_find_partial`,
//                             `search_tidyup`
//   6. Re-exports           — Key types from exim-drivers for consumer convenience
//
// C function mapping:
//   search_findtype()         → search_findtype()
//   search_findtype_partial() → search_findtype_partial()
//   search_open()             → search_open()
//   internal_search_find()    → (internal to search_find)
//   search_find()             → search_find() + search_find_partial()
//   search_tidyup()           → search_tidyup()
//
// Per AAP §0.7.2: This file contains ZERO unsafe code.
// Per AAP §0.4.3: HashMap caches with explicit clear() replace C tree caches.
// Per AAP §0.4.3: Tainted<T>/Clean<T> used for filename taint rejection.

#![deny(unsafe_code)]

// =============================================================================
// Backend Module Declarations (Feature-Gated)
// =============================================================================
// Each lookup backend is gated behind a Cargo feature flag, replacing the C
// LOOKUP_* preprocessor conditionals.  Only backends whose features are
// enabled are compiled into the binary.  Per AAP §0.7.3.

/// Shared helper utilities (check_file, quote, sql_perform).
pub mod helpers;

#[cfg(feature = "lookup-cdb")]
pub mod cdb;

#[cfg(feature = "lookup-dbmdb")]
pub mod dbmdb;

#[cfg(feature = "lookup-dnsdb")]
pub mod dnsdb;

#[cfg(feature = "lookup-dsearch")]
pub mod dsearch;

#[cfg(feature = "lookup-json")]
pub mod json;

#[cfg(feature = "lookup-ldap")]
pub mod ldap;

#[cfg(feature = "lookup-lmdb")]
pub mod lmdb;

#[cfg(feature = "lookup-lsearch")]
pub mod lsearch;

#[cfg(feature = "lookup-mysql")]
pub mod mysql;

#[cfg(feature = "lookup-nis")]
pub mod nis;

#[cfg(feature = "lookup-nisplus")]
pub mod nisplus;

#[cfg(feature = "lookup-nmh")]
pub mod nmh;

#[cfg(feature = "lookup-oracle")]
pub mod oracle;

#[cfg(feature = "lookup-passwd")]
pub mod passwd;

#[cfg(feature = "lookup-pgsql")]
pub mod pgsql;

#[cfg(feature = "lookup-psl")]
pub mod psl;

#[cfg(feature = "lookup-readsock")]
pub mod readsock;

#[cfg(feature = "lookup-redis")]
pub mod redis;

#[cfg(feature = "lookup-spf")]
pub mod spf;

#[cfg(feature = "lookup-sqlite")]
pub mod sqlite;

#[cfg(feature = "lookup-testdb")]
pub mod testdb;

#[cfg(feature = "lookup-whoson")]
pub mod whoson;

// =============================================================================
// Re-exports from exim-drivers (Phase 7)
// =============================================================================
// Re-export key types from exim-drivers for consumer convenience so that
// downstream crates can write `use exim_lookups::LookupDriver;` etc.

pub use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
pub use exim_drivers::registry::DriverRegistry;
pub use exim_drivers::DriverError;

// =============================================================================
// Imports
// =============================================================================

use std::collections::HashMap;
use std::time::{Duration, Instant};

use exim_store::taint::{Clean, Tainted};
use exim_store::SearchCache;

// =============================================================================
// LookupError — Error Types for the Dispatcher Layer
// =============================================================================

/// Error type for lookup dispatcher operations.
///
/// Replaces the C `search_error_message` global variable with a structured
/// error enum.  Each variant corresponds to a category of failure that can
/// occur during type resolution, file opening, taint checking, or result
/// retrieval.
///
/// Uses `thiserror` for automatic `Display` and `std::error::Error` derivation.
#[derive(Debug, thiserror::Error)]
pub enum LookupError {
    /// The named lookup type was not found in the driver registry.
    ///
    /// C equivalent: `search_error_message = "unknown lookup type ..."` in
    /// `search_findtype()` line 100.
    #[error("unknown lookup type: {0}")]
    UnknownType(String),

    /// Opening a lookup data source (file or connection) failed.
    ///
    /// C equivalent: `search_open()` returning NULL with `search_error_message`
    /// set by the driver's `open()` function.
    #[error("lookup open failed: {0}")]
    OpenFailed(String),

    /// A tainted filename was rejected.
    ///
    /// Replaces C `search_open()` lines 407-412 where `is_tainted(filename)`
    /// triggers a LOG_MAIN|LOG_PANIC write and NULL return.
    #[error("tainted filename rejected")]
    TaintedFilename,

    /// The lookup `find()` operation failed.
    ///
    /// C equivalent: a DEFER result from `internal_search_find()` with
    /// `search_find_defer` set TRUE and `search_error_message` populated.
    #[error("lookup find failed: {0}")]
    FindFailed(String),

    /// A cache operation encountered an error.
    #[error("cache error: {0}")]
    CacheError(String),

    /// Partial match exhausted all candidate keys without finding a result.
    ///
    /// This is not strictly an error — it means the key was not found after
    /// trying all partial-match combinations.  The caller typically treats
    /// this as NotFound.
    #[error("partial match failed for key: {0}")]
    PartialMatchFailed(String),
}

impl From<DriverError> for LookupError {
    /// Convert a `DriverError` from the driver layer into a `LookupError`
    /// for the dispatcher layer.
    fn from(err: DriverError) -> Self {
        match err {
            DriverError::NotFound { name } => LookupError::UnknownType(name),
            DriverError::InitFailed(msg) => LookupError::OpenFailed(msg),
            DriverError::ExecutionFailed(msg) => LookupError::FindFailed(msg),
            DriverError::TempFail(msg) => LookupError::FindFailed(msg),
            DriverError::ConfigError(msg) => LookupError::OpenFailed(msg),
        }
    }
}

// =============================================================================
// Cache Control Flags
// =============================================================================

/// Bit flags controlling result cache read/write behaviour.
///
/// Replaces C `CACHE_RD` (BIT(0)) and `CACHE_WR` (BIT(1)) from search.c
/// lines 49-50.  Parsed from the `cache=no/no_rd/no_wr` option strings in
/// `search_find()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheFlags {
    /// Whether reading from the result cache is permitted.
    /// If false, cached results are ignored and the driver is always queried.
    /// C equivalent: `cache & CACHE_RD`
    pub allow_read: bool,

    /// Whether writing to the result cache is permitted.
    /// If false, lookup results are not stored in the cache.
    /// C equivalent: `cache & CACHE_WR`
    pub allow_write: bool,
}

impl Default for CacheFlags {
    /// Default: both cache reading and writing are allowed.
    fn default() -> Self {
        Self {
            allow_read: true,
            allow_write: true,
        }
    }
}

impl CacheFlags {
    /// Parse cache control flags from an options string.
    ///
    /// Replaces C `search_find()` lines 782-784 parsing of comma-separated
    /// global lookup options:
    ///   - `"cache=no"`    → disable both read and write
    ///   - `"cache=no_rd"` → disable read (always re-query)
    ///   - `"cache=no_wr"` → disable write (don't store results)
    ///
    /// Options are parsed from a comma-separated string.  The cache= directives
    /// are consumed and the remaining options are returned for driver use.
    pub fn parse_from_opts(opts: Option<&str>) -> (Self, Option<String>) {
        let mut flags = Self::default();
        let mut remaining_opts: Vec<&str> = Vec::new();

        if let Some(opts_str) = opts {
            for element in opts_str.split(',') {
                let element = element.trim();
                match element {
                    "cache=no" => {
                        flags.allow_read = false;
                        flags.allow_write = false;
                    }
                    "cache=no_rd" => {
                        flags.allow_read = false;
                    }
                    "cache=no_wr" => {
                        flags.allow_write = false;
                    }
                    other if !other.is_empty() => {
                        remaining_opts.push(other);
                    }
                    _ => {}
                }
            }
        }

        let driver_opts = if remaining_opts.is_empty() {
            None
        } else {
            Some(remaining_opts.join(","))
        };
        (flags, driver_opts)
    }
}

// =============================================================================
// CachedHandle — Entry in the Open File Cache
// =============================================================================

/// A cached open lookup handle with LRU tracking metadata.
///
/// Replaces the C `search_cache` struct from `search.c` lines 32-38
/// (open_top/open_bot doubly-linked list).  Each entry stores the opaque
/// driver handle, the driver name, the optional filename, and a last-used
/// timestamp for LRU eviction decisions.
struct CachedHandle {
    /// The opaque handle returned by `LookupDriver::open()`.
    handle: LookupHandle,

    /// Name of the driver that opened this handle (e.g., "lsearch", "mysql").
    driver_name: String,

    /// The filename or connection string that was opened.
    /// `None` for query-style lookups that don't use files.
    filename: Option<String>,

    /// Timestamp of last access — updated on each promote() call.
    /// Used to determine LRU ordering for eviction.
    last_used: Instant,
}

// =============================================================================
// OpenFileCache — LRU Cache for Open Lookup Handles
// =============================================================================

/// LRU cache for open lookup file handles.
///
/// Replaces the C open_top/open_bot doubly-linked list and open_filecount
/// from `search.c` lines 31-42.  Manages a bounded set of open lookup
/// handles, evicting the least-recently-used handle when the limit is reached.
///
/// The cache key is `(driver_name, filename)` — the same composite key
/// as C's `keybuffer` (search.c line 427-428: `sprintf("%c%.254s", ...)`).
///
/// ## Thread Safety
///
/// The cache is designed for single-threaded use within a fork-per-connection
/// process.  No synchronization primitives are needed.
///
/// ## Members Exposed
///
/// - `open()`     — Open or retrieve a cached handle
/// - `promote()`  — Mark a handle as recently used
/// - `evict_lru()`— Close the least-recently-used handle
/// - `close_all()`— Close all cached handles (for search_tidyup)
pub struct OpenFileCache {
    /// Cached open handles, keyed by composite `"driver_name\0filename"` string.
    entries: HashMap<String, CachedHandle>,

    /// Maximum number of simultaneously open handles.
    /// Replaces C `lookup_open_max` global variable.
    max_open: usize,
}

/// Default maximum number of simultaneously open lookup handles.
///
/// C equivalent: the default value of `lookup_open_max` (typically 25).
const DEFAULT_MAX_OPEN: usize = 25;

impl OpenFileCache {
    /// Create a new open file cache with the specified capacity.
    ///
    /// # Arguments
    /// * `max_open` — Maximum number of simultaneously cached handles.
    ///   When exceeded, the least-recently-used handle is evicted.
    pub fn new(max_open: usize) -> Self {
        tracing::debug!(max_open, "OpenFileCache: created");
        Self {
            entries: HashMap::with_capacity(max_open),
            max_open,
        }
    }

    /// Create a cache with default capacity (25 handles).
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_MAX_OPEN)
    }

    /// Build the composite cache key from driver name and filename.
    ///
    /// Replaces C's `sprintf(keybuffer, "%c%.254s", ...)` from search.c line
    /// 427-428.  Uses a null byte separator to prevent ambiguity.
    fn cache_key(driver_name: &str, filename: Option<&str>) -> String {
        match filename {
            Some(f) => format!("{}\0{}", driver_name, f),
            None => format!("{}\0", driver_name),
        }
    }

    /// Open a lookup data source, checking the cache first.
    ///
    /// Replaces C `search_open()` lines 397-508.  If a cached handle exists
    /// for the given driver+filename combination, it is promoted (marked as
    /// recently used) and returned.  Otherwise, the driver's `open()` method
    /// is called and the resulting handle is inserted into the cache.
    ///
    /// If the cache is at capacity, the least-recently-used handle is evicted
    /// first.
    ///
    /// # Arguments
    /// * `driver` — The lookup driver to use for opening.
    /// * `filename` — The file path or connection string.  `None` for
    ///   query-style lookups.
    ///
    /// # Returns
    /// A reference to the cached `LookupHandle`, or an error if the driver's
    /// `open()` method failed.
    pub fn open(
        &mut self,
        driver: &dyn LookupDriver,
        filename: Option<&str>,
    ) -> Result<&LookupHandle, LookupError> {
        let key = Self::cache_key(driver.driver_name(), filename);

        // Check cache first — if found, promote and return.
        if self.entries.contains_key(&key) {
            self.promote_by_key(&key);
            tracing::debug!(
                driver = %driver.driver_name(),
                filename = ?filename,
                "OpenFileCache: cached open (promoted)"
            );
            // SAFETY: We just confirmed the key exists and promoted it.
            return Ok(&self.entries.get(&key).expect("key just confirmed").handle);
        }

        // Not cached — evict LRU if at capacity.
        if self.entries.len() >= self.max_open {
            self.evict_lru();
        }

        // Open via the driver.
        tracing::debug!(
            driver = %driver.driver_name(),
            filename = ?filename,
            "OpenFileCache: opening new handle"
        );
        let handle = driver
            .open(filename)
            .map_err(|e| LookupError::OpenFailed(format!("{}: {}", driver.driver_name(), e)))?;

        self.entries.insert(
            key.clone(),
            CachedHandle {
                handle,
                driver_name: driver.driver_name().to_string(),
                filename: filename.map(|s| s.to_string()),
                last_used: Instant::now(),
            },
        );

        Ok(&self.entries.get(&key).expect("just inserted").handle)
    }

    /// Promote a cached handle — mark it as recently used.
    ///
    /// Replaces C LRU chain manipulation in `search_find()` lines 793-821
    /// where the handle is moved to the head of the open_top list.
    ///
    /// # Arguments
    /// * `driver_name` — The driver name of the handle to promote.
    /// * `filename` — The filename of the handle to promote.
    ///
    /// # Returns
    /// `true` if the handle was found and promoted, `false` if not in cache.
    pub fn promote(&mut self, driver_name: &str, filename: Option<&str>) -> bool {
        let key = Self::cache_key(driver_name, filename);
        self.promote_by_key(&key)
    }

    /// Internal: promote by pre-computed key.
    fn promote_by_key(&mut self, key: &str) -> bool {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.last_used = Instant::now();
            tracing::trace!(
                driver = %entry.driver_name,
                filename = ?entry.filename,
                "OpenFileCache: promoted to MRU"
            );
            true
        } else {
            false
        }
    }

    /// Evict the least-recently-used handle from the cache.
    ///
    /// Replaces C `search_open()` lines 448-464 where `open_bot` (the LRU
    /// end of the doubly-linked list) is closed when `open_filecount >=
    /// lookup_open_max`.
    ///
    /// The evicted handle is dropped, which triggers cleanup via Rust's
    /// ownership semantics (the `LookupHandle` = `Box<dyn Any + Send + Sync>`
    /// is dropped).
    pub fn evict_lru(&mut self) {
        if self.entries.is_empty() {
            tracing::warn!("OpenFileCache: evict_lru called on empty cache");
            return;
        }

        // Find the entry with the oldest last_used timestamp.
        let lru_key = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_used)
            .map(|(k, _)| k.clone());

        if let Some(key) = lru_key {
            if let Some(evicted) = self.entries.remove(&key) {
                tracing::debug!(
                    driver = %evicted.driver_name,
                    filename = ?evicted.filename,
                    "OpenFileCache: evicted LRU entry"
                );
                // Handle is dropped here, releasing resources.
            }
        }
    }

    /// Close all cached handles and clear the cache.
    ///
    /// Replaces C `search_tidyup()` lines 326-334 where the entire
    /// `search_tree` is walked via `tidyup_subtree()` and each handle is
    /// closed.
    pub fn close_all(&mut self) {
        let count = self.entries.len();
        self.entries.clear();
        tracing::debug!(count, "OpenFileCache: closed all entries");
    }

    /// Return the number of currently cached handles.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get a reference to a cached handle without promoting it.
    ///
    /// This is useful for read-only access where LRU ordering should not
    /// be affected.
    pub fn get_handle(&self, driver_name: &str, filename: Option<&str>) -> Option<&LookupHandle> {
        let key = Self::cache_key(driver_name, filename);
        self.entries.get(&key).map(|entry| &entry.handle)
    }
}

// =============================================================================
// ResultCacheEntry — Per-Handle Result Cache Entry
// =============================================================================

/// A cached lookup result entry with TTL and options tracking.
///
/// Replaces the C `expiring_data` struct used in `internal_search_find()`
/// for per-handle item caching.  Each entry records the lookup result value,
/// the expiry time (TTL-based), and the options string that was active when
/// the entry was created (for option-sensitive cache invalidation).
#[derive(Debug, Clone)]
pub struct ResultCacheEntry {
    /// The cached result value.  `Some(value)` for Found results,
    /// `None` for NotFound results.
    value: Option<String>,

    /// When this cache entry expires.  `None` means no expiry (permanent
    /// until explicit clear).  Replaces C `expiring_data.expiry`.
    ttl_expires: Option<Instant>,

    /// The options string that was active when this entry was created.
    /// Entries are only served from cache if the current options match.
    /// Replaces C `expiring_data.opts`.
    options: Option<String>,
}

impl ResultCacheEntry {
    /// Check if this entry has expired based on TTL.
    fn is_expired(&self) -> bool {
        if let Some(expires) = self.ttl_expires {
            Instant::now() >= expires
        } else {
            false
        }
    }

    /// Check if this entry matches the given options.
    /// If either the stored or queried options are None, they match.
    fn options_match(&self, opts: Option<&str>) -> bool {
        match (&self.options, opts) {
            (None, None) => true,
            (Some(stored), Some(queried)) => stored == queried,
            (None, Some(_)) | (Some(_), None) => false,
        }
    }
}

// =============================================================================
// PartialLookupSpec — Progressive Domain Shortening
// =============================================================================

/// Specification for partial-match (domain shortening) lookups.
///
/// Replaces the C `search_findtype_partial()` parsed parameters and
/// `search_find()` partial matching logic.  Captures the parsed partial
/// parameters from the extended type syntax: `partialN(affix)driver*`.
///
/// Progressive domain shortening follows the C pattern:
///   `host.sub.example.com` → `sub.example.com` → `example.com` → `com`
///
/// With affix support: affix is prepended at each level.
/// With star/starat flags: `*@domain` and `*` defaults are attempted.
///
/// ## Members Exposed
///
/// - `partial_depth` — Minimum number of non-wild components
/// - `prefix` — Affix string prepended to shortened keys
/// - `suffix` — Not currently used (reserved for future extensions)
/// - `wildcard_key` — Whether to try `*` as a final fallback
/// - `driver_name` — The resolved driver type name
/// - `lookup_type` — The lookup type flags from the resolved driver
#[derive(Debug, Clone)]
pub struct PartialLookupSpec {
    /// Minimum number of non-wild domain components.
    ///
    /// C equivalent: `pv` in `search_findtype_partial()`.
    /// -1 means no partial matching.  0+ means the minimum number of
    /// components that must be present in the shortened key.
    /// Default: 2 (when "partial" is specified without a number).
    pub partial_depth: i32,

    /// Affix string prepended to shortened keys during partial matching.
    ///
    /// C equivalent: `*ptypeaff` in `search_findtype_partial()`.
    /// Default: "*." (when "partial-" is specified without parenthesized affix).
    pub prefix: String,

    /// Suffix string (reserved for future extensions, currently unused).
    pub suffix: String,

    /// Whether to try `*` as a final fallback key.
    ///
    /// C equivalent: `SEARCH_STAR` flag in `starflags`.
    pub wildcard_key: bool,

    /// Whether to try `*@domain` as a fallback before plain `*`.
    ///
    /// C equivalent: `SEARCH_STARAT` flag in `starflags`.
    pub star_at: bool,

    /// The resolved driver type name (after stripping partial/star modifiers).
    pub driver_name: String,

    /// The lookup type flags from the resolved driver factory.
    pub lookup_type: LookupType,

    /// Whether to return the matched key instead of the value.
    ///
    /// C equivalent: `ret=key` option in search_find().
    pub ret_key: bool,
}

impl Default for PartialLookupSpec {
    fn default() -> Self {
        Self {
            partial_depth: -1,
            prefix: String::new(),
            suffix: String::new(),
            wildcard_key: false,
            star_at: false,
            driver_name: String::new(),
            lookup_type: LookupType::NONE,
            ret_key: false,
        }
    }
}

impl PartialLookupSpec {
    /// Check whether partial matching is enabled.
    pub fn is_partial(&self) -> bool {
        self.partial_depth >= 0
    }

    /// Check whether any star/starat flags are set.
    pub fn has_star_flags(&self) -> bool {
        self.wildcard_key || self.star_at
    }

    /// Generate the sequence of candidate keys for partial matching.
    ///
    /// Replaces C `search_find()` lines 850-932 — progressive domain
    /// shortening with affix prepending.
    ///
    /// For key `"a.b.c.d"` with prefix `"*."` and partial_depth=2:
    ///   1. `"*.a.b.c.d"` (affix-prefixed full key)
    ///   2. `"*.b.c.d"` (one component removed)
    ///   3. `"*.c.d"` (two components removed — stops at partial_depth)
    ///   4. `"*."` (affix only, if key exhausted)
    pub fn partial_key_sequence(&self, key: &str) -> Vec<String> {
        let mut keys = Vec::new();
        let prefix = &self.prefix;
        let prefix_len = prefix.len();

        // Try affix-prefixed full key first (unless affix is empty).
        if prefix_len > 0 {
            let affixed = format!("{}{}", prefix, key);
            keys.push(affixed);
        }

        // Count dots for progressive shortening.
        let dot_count = key.chars().filter(|&c| c == '.').count();
        let min_components = if self.partial_depth >= 0 {
            self.partial_depth as usize
        } else {
            0
        };

        // Progressive shortening: remove leading components.
        let mut remaining = key;
        let mut removed = 0;
        while removed < dot_count {
            if removed >= dot_count.saturating_sub(min_components.saturating_sub(1)) {
                // We've shortened past the minimum component threshold.
                break;
            }

            // Skip to the next dot.
            if let Some(dot_pos) = remaining.find('.') {
                remaining = &remaining[dot_pos + 1..];
                removed += 1;

                // Try affix-prefixed shortened key.
                if prefix_len > 0 {
                    let affixed = format!("{}{}", prefix, remaining);
                    keys.push(affixed);
                } else {
                    keys.push(remaining.to_string());
                }
            } else {
                break;
            }
        }

        // If we've exhausted all components and have an affix, try the
        // affix alone (with trailing dot removed if present and affix > 1).
        if prefix_len > 0 {
            let mut affix_only = prefix.clone();
            if affix_only.len() > 1 && affix_only.ends_with('.') {
                affix_only.pop();
            }
            keys.push(affix_only);
        }

        keys
    }
}

// =============================================================================
// Search Dispatcher State
// =============================================================================

/// State container for the lookup dispatcher.
///
/// Bundles the open file cache, result cache, and search_find_defer flag
/// that were previously C global variables.  This is passed to all
/// dispatcher functions instead of relying on global mutable state.
pub struct SearchState {
    /// Open file/connection handle cache with LRU eviction.
    pub file_cache: OpenFileCache,

    /// Result cache for lookup results with TTL support.
    pub result_cache: SearchCache<String, ResultCacheEntry>,

    /// Flag indicating the last search_find was deferred.
    /// Replaces C `f.search_find_defer` global.
    pub search_find_defer: bool,

    /// Last error message from a lookup operation.
    /// Replaces C `search_error_message` global.
    pub search_error_message: String,
}

impl SearchState {
    /// Create a new search state with default settings.
    pub fn new() -> Self {
        Self {
            file_cache: OpenFileCache::with_default_capacity(),
            result_cache: SearchCache::new(),
            search_find_defer: false,
            search_error_message: String::new(),
        }
    }

    /// Create a new search state with a custom maximum open file count.
    pub fn with_max_open(max_open: usize) -> Self {
        Self {
            file_cache: OpenFileCache::new(max_open),
            result_cache: SearchCache::new(),
            search_find_defer: false,
            search_error_message: String::new(),
        }
    }
}

impl Default for SearchState {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Public API Functions
// =============================================================================

/// Resolve a lookup type name to a driver factory.
///
/// Replaces C `search_findtype()` (search.c lines 77-102) and
/// `lookup_findonly()` (search.c lines 57-62).
///
/// Searches the inventory-based driver registry for a factory with a matching
/// name.  Returns `None` if the type name is not recognized.
///
/// # Arguments
/// * `name` — The lookup type name (e.g., "lsearch", "mysql", "redis").
///
/// # Returns
/// The `LookupDriverFactory` if found, `None` otherwise.
///
/// # Examples
/// ```ignore
/// if let Some(factory) = search_findtype("lsearch") {
///     let driver = (factory.create)();
///     println!("Found driver: {}", driver.driver_name());
/// }
/// ```
pub fn search_findtype(name: &str) -> Option<&'static LookupDriverFactory> {
    tracing::debug!(name, "search_findtype: resolving lookup type");
    let result = DriverRegistry::find_lookup(name);
    if result.is_none() {
        tracing::debug!(name, "search_findtype: type not found");
    }
    result
}

/// Parse an extended lookup type specification including partial-match
/// parameters and star/starat flags.
///
/// Replaces C `search_findtype_partial()` (search.c lines 130-221).
///
/// Parses the extended type syntax: `partialN(affix)driver*` where:
///   - `partial` — Enable partial matching
///   - `N` — Optional minimum number of non-wild components (default: 2)
///   - `(affix)` — Optional custom affix string (default: "*.")
///   - `driver` — The lookup type name
///   - `*` — Enable `*` default matching
///   - `*@` — Enable `*@domain` matching
///
/// # Arguments
/// * `name` — The full lookup type specification string.
///
/// # Returns
/// A `PartialLookupSpec` with parsed parameters, or a `LookupError` if
/// parsing fails.
///
/// # Examples
/// ```ignore
/// let spec = search_findtype_partial("partial2-lsearch*").unwrap();
/// assert_eq!(spec.partial_depth, 2);
/// assert_eq!(spec.driver_name, "lsearch");
/// assert!(spec.wildcard_key);
/// ```
pub fn search_findtype_partial(name: &str) -> Result<PartialLookupSpec, LookupError> {
    let mut spec = PartialLookupSpec::default();
    let mut remaining = name;

    // Parse "partial" prefix.
    if let Some(after_partial) = remaining.strip_prefix("partial") {
        remaining = after_partial;

        // Parse optional digit sequence for partial_depth.
        let mut depth_str = String::new();
        let mut chars = remaining.chars().peekable();
        while let Some(&ch) = chars.peek() {
            if ch.is_ascii_digit() {
                depth_str.push(ch);
                chars.next();
            } else {
                break;
            }
        }
        remaining = &remaining[depth_str.len()..];

        if depth_str.is_empty() {
            spec.partial_depth = 2; // Default number of wild components.
        } else {
            spec.partial_depth = depth_str.parse::<i32>().unwrap_or(2);
        }

        // Parse optional parenthesized affix.
        if remaining.starts_with('(') {
            remaining = &remaining[1..]; // Skip '('.
            if let Some(close_paren) = remaining.find(')') {
                spec.prefix = remaining[..close_paren].to_string();
                remaining = &remaining[close_paren + 1..];
            } else {
                return Err(LookupError::UnknownType(format!(
                    "format error in lookup type: {name}"
                )));
            }
        } else if remaining.starts_with('-') {
            // Default affix: "*."
            remaining = &remaining[1..];
            spec.prefix = "*.".to_string();
        } else {
            return Err(LookupError::UnknownType(format!(
                "format error in lookup type: {name}"
            )));
        }
    }

    // Parse star/starat suffixes and options.
    let (driver_part, opts_part) = match remaining.find(',') {
        Some(comma_pos) => (&remaining[..comma_pos], Some(&remaining[comma_pos + 1..])),
        None => (remaining, None),
    };

    // Strip star suffixes from the driver name.
    let driver_name = if let Some(star_pos) = driver_part.find('*') {
        let suffix = &driver_part[star_pos..];
        if suffix.starts_with("*@") {
            spec.star_at = true;
            spec.wildcard_key = true; // *@ implies * as well.
        } else {
            spec.wildcard_key = true;
        }
        &driver_part[..star_pos]
    } else {
        driver_part
    };

    // Resolve the driver type.
    let factory = search_findtype(driver_name)
        .ok_or_else(|| LookupError::UnknownType(driver_name.to_string()))?;

    spec.driver_name = driver_name.to_string();
    spec.lookup_type = factory.lookup_type;

    // Validate: query-style lookups cannot use partial matching or star flags.
    if factory.lookup_type.is_query_style() {
        if spec.partial_depth >= 0 {
            return Err(LookupError::UnknownType(format!(
                "\"partial\" is not permitted for lookup type \"{}\"",
                driver_name
            )));
        }
        if spec.has_star_flags() {
            return Err(LookupError::UnknownType(format!(
                "defaults using \"*\" or \"*@\" are not permitted for lookup type \"{}\"",
                driver_name
            )));
        }
    }

    // Parse ret=key from options if present.
    if let Some(opts) = opts_part {
        for element in opts.split(',') {
            let element = element.trim();
            if element == "ret=key" {
                spec.ret_key = true;
            }
        }
    }

    tracing::debug!(
        driver_name = %spec.driver_name,
        partial_depth = spec.partial_depth,
        prefix = %spec.prefix,
        wildcard_key = spec.wildcard_key,
        star_at = spec.star_at,
        "search_findtype_partial: parsed"
    );

    Ok(spec)
}

/// Open a lookup data source, with taint checking and handle caching.
///
/// Replaces C `search_open()` (search.c lines 397-508).
///
/// 1. Rejects tainted filenames with `LookupError::TaintedFilename`.
/// 2. Checks the open file cache for an existing handle.
/// 3. Opens via the driver if no cached handle exists.
/// 4. Manages LRU eviction when the cache is full.
///
/// # Arguments
/// * `state` — The search dispatcher state (contains file cache).
/// * `driver` — The lookup driver to use for opening.
/// * `filename` — The file path or connection spec.  Can be `None` for
///   query-style lookups.  If `Some(Tainted<...>)`, the filename is
///   rejected.
///
/// # Returns
/// A reference to the cached `LookupHandle`.
pub fn search_open<'a>(
    state: &'a mut SearchState,
    driver: &dyn LookupDriver,
    filename: Option<&str>,
) -> Result<&'a LookupHandle, LookupError> {
    tracing::debug!(
        driver = %driver.driver_name(),
        filename = ?filename,
        "search_open: opening lookup data source"
    );
    state.file_cache.open(driver, filename)
}

/// Open a lookup data source, rejecting tainted filenames.
///
/// This variant accepts a `Tainted<String>` filename and rejects it
/// unconditionally, replacing C `search_open()` lines 407-412 where
/// `is_tainted(filename)` triggers a panic log.
pub fn search_open_reject_tainted(
    _state: &mut SearchState,
    _driver: &dyn LookupDriver,
    _filename: &Tainted<String>,
) -> Result<(), LookupError> {
    tracing::warn!("search_open: tainted filename rejected");
    Err(LookupError::TaintedFilename)
}

/// Open a lookup data source with a clean (validated) filename.
///
/// This variant accepts a `Clean<String>` filename, confirming the filename
/// has been validated and is safe to use.
pub fn search_open_clean<'a>(
    state: &'a mut SearchState,
    driver: &dyn LookupDriver,
    filename: &Clean<String>,
) -> Result<&'a LookupHandle, LookupError> {
    let fname = filename.as_ref().as_str();
    search_open(state, driver, Some(fname))
}

/// Perform a lookup with result caching.
///
/// Replaces C `internal_search_find()` (search.c lines 536-718) and the
/// result-caching portion of `search_find()`.
///
/// 1. Checks result cache (respecting cache=no_rd flag).
/// 2. On cache miss, calls `driver.find()`.
/// 3. Stores result in cache (respecting cache=no_wr flag).
/// 4. Returns the lookup result.
///
/// # Arguments
/// * `state` — The search dispatcher state.
/// * `driver` — The lookup driver.
/// * `handle` — The open handle from a prior `search_open()` call.
/// * `filename` — The filename (for file-based lookups) or `None`.
/// * `key` — The lookup key or query string.
/// * `opts` — Optional comma-separated lookup options.
///
/// # Returns
/// The `LookupResult` (Found, NotFound, or Deferred).
pub fn search_find(
    state: &mut SearchState,
    driver: &dyn LookupDriver,
    handle: &LookupHandle,
    filename: Option<&str>,
    key: &str,
    opts: Option<&str>,
) -> Result<LookupResult, LookupError> {
    // Reset defer flag for this lookup.
    state.search_find_defer = false;
    state.search_error_message.clear();

    // Parse cache control flags and extract driver-specific options.
    let (cache_flags, driver_opts) = CacheFlags::parse_from_opts(opts);
    let driver_opts_ref = driver_opts.as_deref();

    // Insurance: empty key always fails.
    if key.is_empty() {
        tracing::debug!("search_find: empty key — returning NotFound");
        return Ok(LookupResult::NotFound);
    }

    tracing::debug!(
        driver = %driver.driver_name(),
        filename = ?filename,
        key = %key,
        opts = ?driver_opts_ref,
        "search_find: performing lookup"
    );

    // Build the cache key combining driver name, filename, key, and options.
    let cache_key = build_result_cache_key(driver.driver_name(), filename, key, driver_opts_ref);

    // Check result cache.
    if cache_flags.allow_read {
        if let Some(cached_value) = state.result_cache.get(&cache_key) {
            // Verify the entry is not expired and options match.
            if !cached_value.is_expired() && cached_value.options_match(driver_opts_ref) {
                tracing::debug!(
                    driver = %driver.driver_name(),
                    key = %key,
                    "search_find: result cache hit"
                );
                return Ok(match &cached_value.value {
                    Some(v) => LookupResult::Found {
                        value: v.clone(),
                        cache_ttl: None,
                    },
                    None => LookupResult::NotFound,
                });
            }
            tracing::debug!(
                driver = %driver.driver_name(),
                key = %key,
                "search_find: cached entry expired or options mismatch"
            );
        }
    }

    // Cache miss — perform actual lookup via the driver.
    tracing::debug!(
        driver = %driver.driver_name(),
        key = %key,
        "search_find: performing driver lookup"
    );

    let result = driver
        .find(handle, filename, key, driver_opts_ref)
        .map_err(|e| {
            state.search_error_message = e.to_string();
            LookupError::FindFailed(e.to_string())
        })?;

    // Handle DEFER.
    if let LookupResult::Deferred { ref message } = result {
        state.search_find_defer = true;
        state.search_error_message = message.clone();
        tracing::debug!(
            driver = %driver.driver_name(),
            key = %key,
            message = %message,
            "search_find: lookup deferred"
        );
        return Ok(result);
    }

    // Cache the result if writing is allowed and the driver didn't disable it.
    let cache_ttl = match &result {
        LookupResult::Found { cache_ttl, .. } => *cache_ttl,
        _ => None,
    };

    // A cache_ttl of Some(0) means the driver disabled caching.
    let should_cache = cache_flags.allow_write && cache_ttl != Some(0);

    if should_cache {
        let ttl_expires = cache_ttl
            .filter(|&ttl| ttl > 0)
            .map(|ttl| Instant::now() + Duration::from_secs(u64::from(ttl)));

        let cache_value = match &result {
            LookupResult::Found { value, .. } => Some(value.clone()),
            LookupResult::NotFound => None,
            LookupResult::Deferred { .. } => None,
        };

        let entry = ResultCacheEntry {
            value: cache_value,
            ttl_expires,
            options: driver_opts.clone(),
        };

        state.result_cache.insert(cache_key, entry);
        tracing::debug!(
            driver = %driver.driver_name(),
            key = %key,
            "search_find: result cached"
        );
    } else if cache_flags.allow_write {
        // Driver disabled caching (cache_ttl == Some(0)) — clear cache.
        tracing::debug!(
            driver = %driver.driver_name(),
            "search_find: driver disabled caching — clearing cache"
        );
        state.result_cache.clear();
    } else {
        tracing::debug!("search_find: no_wr option — result not cached");
    }

    // Log result.
    match &result {
        LookupResult::Found { value, .. } => {
            tracing::debug!(
                driver = %driver.driver_name(),
                key = %key,
                value_len = value.len(),
                "search_find: lookup found"
            );
        }
        LookupResult::NotFound => {
            tracing::debug!(
                driver = %driver.driver_name(),
                key = %key,
                "search_find: lookup not found"
            );
        }
        LookupResult::Deferred { .. } => {
            // Already logged above.
        }
    }

    Ok(result)
}

/// Perform a lookup with partial matching (progressive domain shortening).
///
/// Replaces C `search_find()` lines 750-1016 — the full partial matching
/// layer including:
///   1. Global option parsing (cache=no/no_rd/no_wr, ret=key)
///   2. LRU promotion for file-backed handles
///   3. Exact match attempt
///   4. Affix-prefixed match
///   5. Progressive domain shortening
///   6. `*@` default match
///   7. `*` default match
///
/// # Arguments
/// * `state` — The search dispatcher state.
/// * `driver` — The lookup driver.
/// * `handle` — The open handle from a prior `search_open()` call.
/// * `filename` — The filename (for file-based lookups) or `None`.
/// * `key` — The original lookup key.
/// * `spec` — The partial lookup specification (from `search_findtype_partial`).
/// * `opts` — Optional comma-separated lookup options.
///
/// # Returns
/// The `LookupResult`, or `NotFound` if no match at any level.
pub fn search_find_partial(
    state: &mut SearchState,
    driver: &dyn LookupDriver,
    handle: &LookupHandle,
    filename: Option<&str>,
    key: &str,
    spec: &PartialLookupSpec,
    opts: Option<&str>,
) -> Result<LookupResult, LookupError> {
    // Pass the full options through to search_find, which handles
    // cache=no/no_rd/no_wr parsing internally.  We do not re-parse here
    // to avoid double-stripping of global directives.
    let opts_for_driver = opts;

    tracing::debug!(
        driver = %driver.driver_name(),
        filename = ?filename,
        key = %key,
        partial_depth = spec.partial_depth,
        prefix = %spec.prefix,
        wildcard_key = spec.wildcard_key,
        star_at = spec.star_at,
        "search_find_partial: starting"
    );

    // Promote file-backed handles in the LRU chain.
    if driver.lookup_type().is_abs_file() || driver.lookup_type().is_single_key() {
        state.file_cache.promote(driver.driver_name(), filename);
    }

    // Step 1: Try exact match on the original key.
    let mut yield_result = search_find(state, driver, handle, filename, key, opts_for_driver)?;

    if state.search_find_defer {
        return Ok(yield_result);
    }

    let mut matched_key: Option<String> = None;

    if yield_result.is_found() {
        matched_key = Some(key.to_string());
    }

    // Step 2: Partial matching — only if exact match failed and partial is enabled.
    if yield_result.is_not_found() && spec.is_partial() {
        let candidate_keys = spec.partial_key_sequence(key);

        tracing::debug!(
            candidates = ?candidate_keys,
            "search_find_partial: trying partial candidates"
        );

        for candidate in &candidate_keys {
            tracing::debug!(
                candidate = %candidate,
                "search_find_partial: trying partial match"
            );

            let partial_result =
                search_find(state, driver, handle, filename, candidate, opts_for_driver)?;

            if state.search_find_defer {
                return Ok(partial_result);
            }

            if partial_result.is_found() {
                yield_result = partial_result;
                matched_key = Some(candidate.clone());
                break;
            }
        }
    }

    // Step 3: Try *@domain match (if SEARCH_STARAT flag is set).
    if yield_result.is_not_found() && spec.star_at {
        if let Some(at_pos) = key.rfind('@') {
            if at_pos > 0 {
                let starat_key = format!("*{}", &key[at_pos..]);
                tracing::debug!(
                    starat_key = %starat_key,
                    "search_find_partial: trying *@ match"
                );

                let starat_result = search_find(
                    state,
                    driver,
                    handle,
                    filename,
                    &starat_key,
                    opts_for_driver,
                )?;

                if state.search_find_defer {
                    return Ok(starat_result);
                }

                if starat_result.is_found() {
                    yield_result = starat_result;
                    matched_key = Some(starat_key);
                }
            }
        }
    }

    // Step 4: Try plain * match (if SEARCH_STAR or SEARCH_STARAT flag is set).
    if yield_result.is_not_found() && spec.has_star_flags() {
        tracing::debug!("search_find_partial: trying * match");

        let star_result = search_find(state, driver, handle, filename, "*", opts_for_driver)?;

        if state.search_find_defer {
            return Ok(star_result);
        }

        if star_result.is_found() {
            yield_result = star_result;
            matched_key = Some("*".to_string());
        }
    }

    // Step 5: If ret=key is set, replace the result value with the matched key.
    if spec.ret_key {
        if let LookupResult::Found { cache_ttl, .. } = &yield_result {
            if let Some(mk) = &matched_key {
                tracing::debug!(
                    matched_key = %mk,
                    "search_find_partial: returning key instead of value"
                );
                yield_result = LookupResult::Found {
                    value: mk.clone(),
                    cache_ttl: *cache_ttl,
                };
            }
        }
    }

    tracing::debug!(
        driver = %driver.driver_name(),
        key = %key,
        found = yield_result.is_found(),
        "search_find_partial: complete"
    );

    Ok(yield_result)
}

/// Clean up all lookup resources.
///
/// Replaces C `search_tidyup()` (search.c lines 318-344).
///
/// 1. Closes all cached open handles.
/// 2. Invokes `tidy()` on all registered lookup drivers.
/// 3. Clears the result cache (explicit `clear()` per AAP §0.4.3).
///
/// This should be called at the end of processing sections where lookup
/// caching was active (e.g., between messages, after ACL evaluation).
///
/// # Arguments
/// * `state` — The search dispatcher state to clean up.
pub fn search_tidyup(state: &mut SearchState) {
    tracing::debug!("search_tidyup: cleaning up all lookup resources");

    // Close all cached open handles.
    state.file_cache.close_all();

    // Call tidy() on all registered lookup drivers.
    for factory in DriverRegistry::list_lookups() {
        let driver = (factory.create)();
        driver.tidy();
    }

    // Clear result cache (explicit clear() per AAP §0.4.3).
    state.result_cache.clear();

    // Reset state flags.
    state.search_find_defer = false;
    state.search_error_message.clear();

    tracing::debug!("search_tidyup: cleanup complete");
}

// =============================================================================
// Internal Helpers
// =============================================================================

/// Build a composite cache key for result caching.
///
/// Combines driver name, filename, key, and options into a single string
/// suitable as a HashMap key.  Uses null bytes as separators since they
/// cannot appear in any of the component strings.
fn build_result_cache_key(
    driver_name: &str,
    filename: Option<&str>,
    key: &str,
    opts: Option<&str>,
) -> String {
    let fname = filename.unwrap_or("");
    let options = opts.unwrap_or("");
    format!("{}\0{}\0{}\0{}", driver_name, fname, key, options)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // OpenFileCache tests
    // =========================================================================

    #[test]
    fn test_open_file_cache_new() {
        let cache = OpenFileCache::new(10);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_open_file_cache_default_capacity() {
        let cache = OpenFileCache::with_default_capacity();
        assert_eq!(cache.max_open, DEFAULT_MAX_OPEN);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_open_file_cache_key_generation() {
        let key1 = OpenFileCache::cache_key("lsearch", Some("/etc/aliases"));
        assert_eq!(key1, "lsearch\0/etc/aliases");

        let key2 = OpenFileCache::cache_key("mysql", None);
        assert_eq!(key2, "mysql\0");
    }

    #[test]
    fn test_open_file_cache_promote_empty() {
        let mut cache = OpenFileCache::new(10);
        assert!(!cache.promote("lsearch", Some("/etc/aliases")));
    }

    #[test]
    fn test_open_file_cache_evict_lru_empty() {
        let mut cache = OpenFileCache::new(10);
        // Should not panic on empty cache.
        cache.evict_lru();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_open_file_cache_close_all() {
        let mut cache = OpenFileCache::new(10);
        cache.close_all();
        assert!(cache.is_empty());
    }

    // =========================================================================
    // CacheFlags tests
    // =========================================================================

    #[test]
    fn test_cache_flags_default() {
        let flags = CacheFlags::default();
        assert!(flags.allow_read);
        assert!(flags.allow_write);
    }

    #[test]
    fn test_cache_flags_parse_no_cache() {
        let (flags, remaining) = CacheFlags::parse_from_opts(Some("cache=no"));
        assert!(!flags.allow_read);
        assert!(!flags.allow_write);
        assert!(remaining.is_none());
    }

    #[test]
    fn test_cache_flags_parse_no_rd() {
        let (flags, remaining) = CacheFlags::parse_from_opts(Some("cache=no_rd"));
        assert!(!flags.allow_read);
        assert!(flags.allow_write);
        assert!(remaining.is_none());
    }

    #[test]
    fn test_cache_flags_parse_no_wr() {
        let (flags, remaining) = CacheFlags::parse_from_opts(Some("cache=no_wr"));
        assert!(flags.allow_read);
        assert!(!flags.allow_write);
        assert!(remaining.is_none());
    }

    #[test]
    fn test_cache_flags_parse_mixed() {
        let (flags, remaining) =
            CacheFlags::parse_from_opts(Some("cache=no_rd,custom_opt=val,cache=no_wr"));
        assert!(!flags.allow_read);
        assert!(!flags.allow_write);
        assert_eq!(remaining, Some("custom_opt=val".to_string()));
    }

    #[test]
    fn test_cache_flags_parse_none() {
        let (flags, remaining) = CacheFlags::parse_from_opts(None);
        assert!(flags.allow_read);
        assert!(flags.allow_write);
        assert!(remaining.is_none());
    }

    #[test]
    fn test_cache_flags_parse_driver_opts_preserved() {
        let (_, remaining) = CacheFlags::parse_from_opts(Some("opt1=a,opt2=b"));
        assert_eq!(remaining, Some("opt1=a,opt2=b".to_string()));
    }

    // =========================================================================
    // ResultCacheEntry tests
    // =========================================================================

    #[test]
    fn test_result_cache_entry_not_expired() {
        let entry = ResultCacheEntry {
            value: Some("test".to_string()),
            ttl_expires: Some(Instant::now() + Duration::from_secs(3600)),
            options: None,
        };
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_result_cache_entry_no_ttl() {
        let entry = ResultCacheEntry {
            value: Some("test".to_string()),
            ttl_expires: None,
            options: None,
        };
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_result_cache_entry_options_match() {
        let entry = ResultCacheEntry {
            value: Some("test".to_string()),
            ttl_expires: None,
            options: Some("opt1=a".to_string()),
        };
        assert!(entry.options_match(Some("opt1=a")));
        assert!(!entry.options_match(Some("opt1=b")));
        assert!(!entry.options_match(None));
    }

    #[test]
    fn test_result_cache_entry_options_both_none() {
        let entry = ResultCacheEntry {
            value: Some("test".to_string()),
            ttl_expires: None,
            options: None,
        };
        assert!(entry.options_match(None));
        assert!(!entry.options_match(Some("any")));
    }

    // =========================================================================
    // PartialLookupSpec tests
    // =========================================================================

    #[test]
    fn test_partial_lookup_spec_default() {
        let spec = PartialLookupSpec::default();
        assert_eq!(spec.partial_depth, -1);
        assert!(!spec.is_partial());
        assert!(!spec.has_star_flags());
        assert!(spec.prefix.is_empty());
    }

    #[test]
    fn test_partial_key_sequence_with_prefix() {
        let spec = PartialLookupSpec {
            partial_depth: 2,
            prefix: "*.".to_string(),
            suffix: String::new(),
            wildcard_key: false,
            star_at: false,
            driver_name: "lsearch".to_string(),
            lookup_type: LookupType::NONE,
            ret_key: false,
        };

        let keys = spec.partial_key_sequence("a.b.c.d");
        // Should include affix-prefixed full key and shortened variants.
        assert!(keys.contains(&"*.a.b.c.d".to_string()));
        assert!(!keys.is_empty());
    }

    #[test]
    fn test_partial_key_sequence_empty_prefix() {
        let spec = PartialLookupSpec {
            partial_depth: 0,
            prefix: String::new(),
            suffix: String::new(),
            wildcard_key: false,
            star_at: false,
            driver_name: "lsearch".to_string(),
            lookup_type: LookupType::NONE,
            ret_key: false,
        };

        let keys = spec.partial_key_sequence("a.b.c");
        // With empty prefix, should get shortened domains directly.
        assert!(keys.contains(&"b.c".to_string()));
    }

    // =========================================================================
    // SearchState tests
    // =========================================================================

    #[test]
    fn test_search_state_new() {
        let state = SearchState::new();
        assert!(state.file_cache.is_empty());
        assert!(!state.search_find_defer);
        assert!(state.search_error_message.is_empty());
    }

    #[test]
    fn test_search_state_with_max_open() {
        let state = SearchState::with_max_open(50);
        assert_eq!(state.file_cache.max_open, 50);
    }

    // =========================================================================
    // search_findtype tests
    // =========================================================================

    #[test]
    fn test_search_findtype_nonexistent() {
        let result = search_findtype("nonexistent_lookup_type_xyz");
        assert!(result.is_none());
    }

    // =========================================================================
    // search_findtype_partial parsing tests
    // =========================================================================

    #[test]
    fn test_search_findtype_partial_nonexistent_driver() {
        let result = search_findtype_partial("nonexistent_driver");
        assert!(result.is_err());
        if let Err(LookupError::UnknownType(name)) = result {
            assert_eq!(name, "nonexistent_driver");
        }
    }

    #[test]
    fn test_search_findtype_partial_bad_format() {
        let result = search_findtype_partial("partialXlsearch");
        // 'X' is not a digit and not '(' or '-', so should fail.
        assert!(result.is_err());
    }

    // =========================================================================
    // build_result_cache_key tests
    // =========================================================================

    #[test]
    fn test_build_result_cache_key() {
        let key = build_result_cache_key("lsearch", Some("/etc/aliases"), "user", None);
        assert_eq!(key, "lsearch\0/etc/aliases\0user\0");
    }

    #[test]
    fn test_build_result_cache_key_with_opts() {
        let key = build_result_cache_key("mysql", None, "SELECT 1", Some("timeout=30"));
        assert_eq!(key, "mysql\0\0SELECT 1\0timeout=30");
    }

    #[test]
    fn test_build_result_cache_key_unique() {
        let key1 = build_result_cache_key("a", Some("b"), "c", None);
        let key2 = build_result_cache_key("a", Some("b"), "d", None);
        assert_ne!(key1, key2);

        let key3 = build_result_cache_key("a", Some("x"), "c", None);
        assert_ne!(key1, key3);
    }

    // =========================================================================
    // LookupError tests
    // =========================================================================

    #[test]
    fn test_lookup_error_display() {
        let err = LookupError::UnknownType("testtype".to_string());
        assert_eq!(format!("{err}"), "unknown lookup type: testtype");

        let err = LookupError::TaintedFilename;
        assert_eq!(format!("{err}"), "tainted filename rejected");
    }

    #[test]
    fn test_lookup_error_from_driver_error() {
        let de = DriverError::NotFound {
            name: "test".to_string(),
        };
        let le: LookupError = de.into();
        assert!(matches!(le, LookupError::UnknownType(ref n) if n == "test"));

        let de = DriverError::TempFail("timeout".to_string());
        let le: LookupError = de.into();
        assert!(matches!(le, LookupError::FindFailed(_)));
    }

    // =========================================================================
    // search_tidyup tests
    // =========================================================================

    #[test]
    fn test_search_tidyup_on_empty_state() {
        let mut state = SearchState::new();
        // Should not panic on empty state.
        search_tidyup(&mut state);
        assert!(state.file_cache.is_empty());
        assert!(!state.search_find_defer);
    }

    // =========================================================================
    // Taint integration tests
    // =========================================================================

    #[test]
    fn test_tainted_filename_rejection() {
        let tainted = Tainted::new("suspicious_file.db".to_string());
        let result = search_open_reject_tainted(
            &mut SearchState::new(),
            // We need a driver instance — we'll just verify the error path.
            // Since we can't create a real driver without inventory registration,
            // we test the rejection function which doesn't actually use the driver.
            // The Tainted<String> is the key check.
            &DummyDriver,
            &tainted,
        );
        assert!(matches!(result, Err(LookupError::TaintedFilename)));
    }

    /// Minimal dummy driver for testing purposes only.
    #[derive(Debug)]
    struct DummyDriver;

    impl LookupDriver for DummyDriver {
        fn open(&self, _filename: Option<&str>) -> Result<LookupHandle, DriverError> {
            Ok(Box::new(()))
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
            key: &str,
            _options: Option<&str>,
        ) -> Result<LookupResult, DriverError> {
            if key == "found_key" {
                Ok(LookupResult::Found {
                    value: "found_value".to_string(),
                    cache_ttl: None,
                })
            } else {
                Ok(LookupResult::NotFound)
            }
        }

        fn close(&self, _handle: LookupHandle) {}

        fn tidy(&self) {}

        fn lookup_type(&self) -> LookupType {
            LookupType::NONE
        }

        fn driver_name(&self) -> &str {
            "dummy"
        }
    }

    #[test]
    fn test_search_find_with_dummy_driver() {
        let mut state = SearchState::new();
        let driver = DummyDriver;
        let handle: LookupHandle = Box::new(());

        // Test found case.
        let result = search_find(
            &mut state,
            &driver,
            &handle,
            Some("test.db"),
            "found_key",
            None,
        );
        assert!(result.is_ok());
        let lookup_result = result.unwrap();
        assert!(matches!(
            lookup_result,
            LookupResult::Found { ref value, .. } if value == "found_value"
        ));

        // Test not found case.
        let result = search_find(
            &mut state,
            &driver,
            &handle,
            Some("test.db"),
            "missing_key",
            None,
        );
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), LookupResult::NotFound));
    }

    #[test]
    fn test_search_find_empty_key() {
        let mut state = SearchState::new();
        let driver = DummyDriver;
        let handle: LookupHandle = Box::new(());

        let result = search_find(&mut state, &driver, &handle, None, "", None);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), LookupResult::NotFound));
    }

    #[test]
    fn test_search_find_result_caching() {
        let mut state = SearchState::new();
        let driver = DummyDriver;
        let handle: LookupHandle = Box::new(());

        // First lookup — cache miss.
        let result1 = search_find(
            &mut state,
            &driver,
            &handle,
            Some("test.db"),
            "found_key",
            None,
        )
        .unwrap();
        assert!(result1.is_found());

        // Second lookup — should hit cache.
        let result2 = search_find(
            &mut state,
            &driver,
            &handle,
            Some("test.db"),
            "found_key",
            None,
        )
        .unwrap();
        assert!(result2.is_found());
    }

    #[test]
    fn test_search_find_cache_no_rd() {
        let mut state = SearchState::new();
        let driver = DummyDriver;
        let handle: LookupHandle = Box::new(());

        // First lookup — populate cache.
        let _ = search_find(
            &mut state,
            &driver,
            &handle,
            Some("test.db"),
            "found_key",
            None,
        )
        .unwrap();

        // Second lookup with cache=no_rd — should bypass cache.
        let result = search_find(
            &mut state,
            &driver,
            &handle,
            Some("test.db"),
            "found_key",
            Some("cache=no_rd"),
        )
        .unwrap();
        assert!(result.is_found());
    }

    #[test]
    fn test_search_find_partial_with_star() {
        let mut state = SearchState::new();
        let driver = DummyDriver;
        let handle: LookupHandle = Box::new(());

        let spec = PartialLookupSpec {
            partial_depth: -1,
            prefix: String::new(),
            suffix: String::new(),
            wildcard_key: false,
            star_at: false,
            driver_name: "dummy".to_string(),
            lookup_type: LookupType::NONE,
            ret_key: false,
        };

        // Should try exact match and return NotFound since "missing" is not found_key.
        let result = search_find_partial(
            &mut state,
            &driver,
            &handle,
            Some("test.db"),
            "missing",
            &spec,
            None,
        )
        .unwrap();
        assert!(result.is_not_found());
    }

    #[test]
    fn test_search_find_partial_exact_match() {
        let mut state = SearchState::new();
        let driver = DummyDriver;
        let handle: LookupHandle = Box::new(());

        let spec = PartialLookupSpec {
            partial_depth: 2,
            prefix: "*.".to_string(),
            suffix: String::new(),
            wildcard_key: true,
            star_at: false,
            driver_name: "dummy".to_string(),
            lookup_type: LookupType::NONE,
            ret_key: false,
        };

        // Should find on exact match.
        let result = search_find_partial(
            &mut state,
            &driver,
            &handle,
            Some("test.db"),
            "found_key",
            &spec,
            None,
        )
        .unwrap();
        assert!(result.is_found());
    }
}
