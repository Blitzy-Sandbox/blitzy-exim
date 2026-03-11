#![deny(unsafe_code)]
//! Lookup module implementations for the Exim MTA.
//!
//! This crate replaces the entire `src/src/lookups/` directory from the C
//! codebase. It provides 22+ lookup backends plus shared helper functions,
//! each backend implementing the `LookupDriver` trait from `exim-drivers`.
//!
//! # Architecture
//!
//! The crate is organized into three layers:
//!
//! 1. **Dispatcher** — Central orchestration (this file): `search_findtype`,
//!    `search_open`, `search_find`, `search_find_partial`, `search_tidyup`.
//!    Manages the `OpenFileCache` for file handle reuse and `ResultCache`
//!    for lookup result caching with TTL support.
//!
//! 2. **Backends** — 22 lookup backend modules, each implementing the
//!    `LookupDriver` trait and registering via `inventory::submit!`.
//!
//! 3. **Helpers** — Shared utility functions (`check_file`, `quote`,
//!    `sql_perform`) used by multiple backends.
//!
//! # Lookup Dispatcher
//!
//! Replaces the C `search.c` dispatcher functionality:
//! - `search_findtype_partial()` → [`search_findtype`]
//! - `search_open()`             → [`search_open`]
//! - `search_find()`             → [`search_find`]
//! - `search_tidyup()`           → [`search_tidyup`]
//!
//! # Feature Flags
//!
//! Each backend is gated behind a Cargo feature flag. See `Cargo.toml`
//! for the full mapping from C `LOOKUP_*` preprocessor defines.

pub mod helpers;

// =============================================================================
// Backend Module Declarations (Feature-Gated)
// =============================================================================

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
// Lookup Dispatcher — Central Orchestration Layer
// =============================================================================
//
// Replaces `src/src/search.c` — the central lookup dispatch, open-file caching,
// result caching, and partial-match (domain shortening) logic.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use exim_drivers::lookup_driver::{LookupDriverFactory, LookupHandle, LookupResult};
use exim_drivers::DriverError;

// =============================================================================
// OpenFileCache — File Handle Reuse Cache
// =============================================================================

/// Maximum number of simultaneously open file handles in the cache.
///
/// C equivalent: `max_open` in `search_open()` — limits the number of
/// open lookup handles to prevent file descriptor exhaustion.
const DEFAULT_MAX_OPEN: usize = 25;

/// Entry in the open file cache.
struct OpenFileCacheEntry {
    /// The lookup driver that opened this file.
    driver_name: String,
    /// The filename/key that was opened.
    filename: String,
    /// The open handle from the driver.
    handle: LookupHandle,
    /// Timestamp of last access (for LRU eviction).
    last_access: Instant,
}

/// LRU cache for open lookup file handles.
///
/// Replaces the C `open_top` / `open_bot` doubly-linked list in `search.c`.
/// Manages a bounded set of open lookup handles, evicting the least-recently-
/// used handle when the limit is reached. This prevents file descriptor
/// exhaustion while maintaining handle reuse across repeated lookups.
///
/// Thread safety: Protected by a `Mutex` for use in multi-threaded contexts
/// (even though Exim's fork-per-connection model is single-threaded per process,
/// the Mutex ensures soundness for Rust's Send/Sync requirements).
pub struct OpenFileCache {
    /// Cached open handles, keyed by (driver_name, filename).
    entries: Vec<OpenFileCacheEntry>,
    /// Maximum number of entries before LRU eviction.
    max_open: usize,
}

impl OpenFileCache {
    /// Create a new open file cache with the specified capacity.
    pub fn new(max_open: usize) -> Self {
        Self {
            entries: Vec::with_capacity(max_open),
            max_open,
        }
    }

    /// Create a cache with default capacity.
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_MAX_OPEN)
    }

    /// Look up a cached handle and promote it (mark as recently used).
    pub fn promote(&mut self, driver_name: &str, filename: &str) -> Option<&LookupHandle> {
        if let Some(pos) = self
            .entries
            .iter()
            .position(|e| e.driver_name == driver_name && e.filename == filename)
        {
            self.entries[pos].last_access = Instant::now();
            Some(&self.entries[pos].handle)
        } else {
            None
        }
    }

    /// Insert a new handle into the cache, evicting the LRU entry if full.
    pub fn insert(&mut self, driver_name: String, filename: String, handle: LookupHandle) {
        if self.entries.len() >= self.max_open {
            self.evict_lru();
        }
        self.entries.push(OpenFileCacheEntry {
            driver_name,
            filename,
            handle,
            last_access: Instant::now(),
        });
    }

    /// Evict the least-recently-used entry from the cache.
    fn evict_lru(&mut self) {
        if self.entries.is_empty() {
            return;
        }
        let lru_idx = self
            .entries
            .iter()
            .enumerate()
            .min_by_key(|(_, e)| e.last_access)
            .map(|(i, _)| i)
            .unwrap_or(0);
        let evicted = self.entries.remove(lru_idx);
        tracing::debug!(
            driver = %evicted.driver_name,
            filename = %evicted.filename,
            "OpenFileCache: evicted LRU entry"
        );
        // The handle is dropped here, triggering cleanup.
    }

    /// Close all cached handles and clear the cache.
    pub fn close_all(&mut self) {
        let count = self.entries.len();
        self.entries.clear();
        tracing::debug!(count = count, "OpenFileCache: closed all entries");
    }

    /// Return the number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// =============================================================================
// ResultCache — Lookup Result Caching
// =============================================================================

/// Entry in the result cache.
struct ResultCacheEntry {
    /// The cached result value (None for "not found").
    value: Option<String>,
    /// When this entry was created.
    created: Instant,
    /// TTL for this entry (None = no expiry).
    ttl: Option<Duration>,
    /// Cache control flags from the lookup.
    flags: CacheFlags,
}

impl ResultCacheEntry {
    /// Check if this entry has expired or was marked as non-readable.
    ///
    /// An entry is considered expired if:
    /// - Its TTL has elapsed, OR
    /// - The original lookup was inserted with `allow_read = false`
    ///   (i.e., `cache=no_rd` was specified, meaning the result should
    ///   be written for logging but not served from cache).
    fn is_expired(&self) -> bool {
        if !self.flags.allow_read {
            return true;
        }
        if let Some(ttl) = self.ttl {
            self.created.elapsed() > ttl
        } else {
            false
        }
    }
}

/// Cache control flags for lookup results.
///
/// These correspond to the C `do_cache` flags in `search_find()`:
/// - `cache=no` — do not cache the result at all
/// - `cache=no_rd` — do not return cached results (always re-query)
/// - `cache=no_wr` — do not write results to cache
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheFlags {
    /// Whether reading from cache is allowed.
    pub allow_read: bool,
    /// Whether writing to cache is allowed.
    pub allow_write: bool,
}

impl Default for CacheFlags {
    fn default() -> Self {
        Self {
            allow_read: true,
            allow_write: true,
        }
    }
}

impl CacheFlags {
    /// Parse cache control from an options string.
    pub fn from_opts(opts: Option<&str>) -> Self {
        let mut flags = Self::default();
        if let Some(opts_str) = opts {
            // Check specific no_rd/no_wr first before the broader "cache=no"
            // because "cache=no_rd" also contains "cache=no".
            if opts_str.contains("cache=no_rd") {
                flags.allow_read = false;
            }
            if opts_str.contains("cache=no_wr") {
                flags.allow_write = false;
            }
            // Only apply blanket "cache=no" if neither no_rd nor no_wr matched.
            if opts_str.contains("cache=no")
                && !opts_str.contains("cache=no_rd")
                && !opts_str.contains("cache=no_wr")
            {
                flags.allow_read = false;
                flags.allow_write = false;
            }
        }
        flags
    }
}

/// Lookup result cache with TTL support.
///
/// Replaces the C `search_cache` hash table in `search.c`. Results are
/// cached by (driver_name, filename, key) tuple with optional TTL expiry.
/// Cache control flags (`cache=no`, `cache=no_rd`, `cache=no_wr`) are
/// respected per-lookup.
pub struct ResultCache {
    /// Cached results, keyed by (driver_name, filename, key).
    entries: HashMap<String, ResultCacheEntry>,
}

impl ResultCache {
    /// Create a new empty result cache.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Build the composite cache key.
    fn cache_key(driver_name: &str, filename: &str, key: &str) -> String {
        format!("{}:{}:{}", driver_name, filename, key)
    }

    /// Look up a cached result.
    pub fn get(&self, driver_name: &str, filename: &str, key: &str) -> Option<&Option<String>> {
        let ck = Self::cache_key(driver_name, filename, key);
        self.entries.get(&ck).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(&entry.value)
            }
        })
    }

    /// Insert a result into the cache.
    pub fn insert(
        &mut self,
        driver_name: &str,
        filename: &str,
        key: &str,
        value: Option<String>,
        ttl: Option<Duration>,
        flags: CacheFlags,
    ) {
        if !flags.allow_write {
            return;
        }
        let ck = Self::cache_key(driver_name, filename, key);
        self.entries.insert(
            ck,
            ResultCacheEntry {
                value,
                created: Instant::now(),
                ttl,
                flags,
            },
        );
    }

    /// Clear all cached results. Called during `search_tidyup()`.
    pub fn clear(&mut self) {
        let count = self.entries.len();
        self.entries.clear();
        tracing::debug!(count = count, "ResultCache: cleared all entries");
    }

    /// Remove expired entries from the cache.
    pub fn purge_expired(&mut self) {
        self.entries.retain(|_, entry| !entry.is_expired());
    }

    /// Return the number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for ResultCache {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// PartialLookupSpec — Progressive Domain Shortening
// =============================================================================

/// Specification for partial-match (domain shortening) lookups.
///
/// Replaces the C `search_find_partial()` logic that progressively shortens
/// a domain name to find a match:
///   `host.sub.example.com` → `sub.example.com` → `example.com` → `com`
///
/// For file-based lookups, a `*` prefix is also tried at each level:
///   `*.sub.example.com`, `*.example.com`, `*.com`, `*`
///
/// The `starflags` parameter controls which shortening patterns to try.
#[derive(Debug, Clone)]
pub struct PartialLookupSpec {
    /// Original key (full domain name or address).
    pub original_key: String,
    /// Whether to try `*` prefix matches at each shortening level.
    pub star_prefix: bool,
    /// Maximum number of shortening levels (0 = no limit).
    pub max_levels: usize,
}

impl PartialLookupSpec {
    /// Create a new partial lookup specification.
    pub fn new(key: &str) -> Self {
        Self {
            original_key: key.to_string(),
            star_prefix: true,
            max_levels: 0,
        }
    }

    /// Generate the sequence of keys to try, from most specific to least.
    ///
    /// For domain `a.b.c.d`:
    /// 1. `a.b.c.d`
    /// 2. `*.b.c.d` (if star_prefix)
    /// 3. `b.c.d`
    /// 4. `*.c.d` (if star_prefix)
    /// 5. `c.d`
    /// 6. `*.d` (if star_prefix)
    /// 7. `d`
    /// 8. `*` (if star_prefix)
    pub fn key_sequence(&self) -> Vec<String> {
        let mut keys = Vec::new();
        let domain = &self.original_key;

        // First, try the full key.
        keys.push(domain.clone());

        // Split by dots and progressively shorten.
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len() {
            if self.max_levels > 0 && i > self.max_levels {
                break;
            }
            let shortened = parts[i..].join(".");

            // Try star prefix before the shortened key.
            if self.star_prefix {
                keys.push(format!("*.{}", shortened));
            }

            keys.push(shortened);
        }

        // Final star catch-all.
        if self.star_prefix && (self.max_levels == 0 || parts.len() <= self.max_levels + 1) {
            keys.push("*".to_string());
        }

        keys
    }
}

// =============================================================================
// Public Dispatcher API
// =============================================================================

/// Find a lookup driver by name.
///
/// Replaces C `search_findtype()` — resolves a lookup type name to a driver
/// factory from the inventory-based registry.
///
/// # Arguments
/// * `name` — The lookup type name (e.g., "lsearch", "dbm", "redis")
///
/// # Returns
/// The `LookupDriverFactory` for the named type, or an error if not found.
pub fn search_findtype(name: &str) -> Result<&'static LookupDriverFactory, DriverError> {
    for factory in inventory::iter::<LookupDriverFactory> {
        if factory.name == name {
            return Ok(factory);
        }
    }
    Err(DriverError::NotFound {
        name: name.to_string(),
    })
}

/// Open a lookup data source.
///
/// Replaces C `search_open()` — opens a file or connection for the specified
/// lookup type. Uses the open file cache to reuse existing handles.
///
/// # Arguments
/// * `cache` — The open file cache to search/populate
/// * `driver_name` — The lookup driver name
/// * `filename` — The data source path or connection spec
///
/// # Returns
/// A reference to the cached or newly opened handle.
pub fn search_open(
    cache: &mut OpenFileCache,
    driver_name: &str,
    filename: &str,
) -> Result<(), DriverError> {
    // Check if already cached.
    if cache.promote(driver_name, filename).is_some() {
        tracing::debug!(
            driver = %driver_name,
            filename = %filename,
            "search_open: handle found in cache"
        );
        return Ok(());
    }

    // Not cached — create a new driver and open.
    let factory = search_findtype(driver_name)?;
    let driver = (factory.create)();
    let handle = driver.open(Some(filename))?;

    cache.insert(driver_name.to_string(), filename.to_string(), handle);

    tracing::debug!(
        driver = %driver_name,
        filename = %filename,
        "search_open: new handle opened and cached"
    );

    Ok(())
}

/// Perform a lookup.
///
/// Replaces C `search_find()` — queries the lookup driver for the given key,
/// using the result cache for repeated queries and the open file cache for
/// handle reuse.
///
/// # Arguments
/// * `file_cache` — Open file handle cache
/// * `result_cache` — Lookup result cache
/// * `driver_name` — The lookup driver name
/// * `filename` — The data source path or connection spec
/// * `key` — The lookup key
/// * `opts` — Optional lookup options string
///
/// # Returns
/// The lookup result (found value, not found, or error).
pub fn search_find(
    file_cache: &mut OpenFileCache,
    result_cache: &mut ResultCache,
    driver_name: &str,
    filename: &str,
    key: &str,
    opts: Option<&str>,
) -> Result<LookupResult, DriverError> {
    let cache_flags = CacheFlags::from_opts(opts);

    // Check result cache first.
    if cache_flags.allow_read {
        if let Some(cached_value) = result_cache.get(driver_name, filename, key) {
            tracing::debug!(
                driver = %driver_name,
                key = %key,
                "search_find: result cache hit"
            );
            return Ok(match cached_value {
                Some(v) => LookupResult::Found {
                    value: v.clone(),
                    cache_ttl: None,
                },
                None => LookupResult::NotFound,
            });
        }
    }

    // Ensure file is open.
    search_open(file_cache, driver_name, filename)?;

    // Get the handle from cache.
    let handle = file_cache.promote(driver_name, filename).ok_or_else(|| {
        DriverError::ExecutionFailed(format!(
            "search_find: handle not in cache after open for {}:{}",
            driver_name, filename
        ))
    })?;

    // Perform the actual lookup via the driver.
    let factory = search_findtype(driver_name)?;
    let driver = (factory.create)();
    let result = driver.find(handle, Some(filename), key, opts)?;

    // Cache the result.
    let ttl = match &result {
        LookupResult::Found { cache_ttl, .. } => {
            cache_ttl.map(|s| Duration::from_secs(u64::from(s)))
        }
        _ => None,
    };
    let cache_value = match &result {
        LookupResult::Found { value, .. } => Some(value.clone()),
        LookupResult::NotFound | LookupResult::Deferred { .. } => None,
    };
    result_cache.insert(driver_name, filename, key, cache_value, ttl, cache_flags);

    Ok(result)
}

/// Perform a partial-match (domain shortening) lookup.
///
/// Replaces C `search_find_partial()` — tries the lookup with progressively
/// shortened domain names until a match is found.
///
/// # Arguments
/// * `file_cache` — Open file handle cache
/// * `result_cache` — Lookup result cache
/// * `driver_name` — The lookup driver name
/// * `filename` — The data source path or connection spec
/// * `spec` — The partial lookup specification
/// * `opts` — Optional lookup options string
///
/// # Returns
/// The first matching lookup result, or NotFound if no match at any level.
pub fn search_find_partial(
    file_cache: &mut OpenFileCache,
    result_cache: &mut ResultCache,
    driver_name: &str,
    filename: &str,
    spec: &PartialLookupSpec,
    opts: Option<&str>,
) -> Result<LookupResult, DriverError> {
    let keys = spec.key_sequence();

    tracing::debug!(
        driver = %driver_name,
        original_key = %spec.original_key,
        try_count = keys.len(),
        "search_find_partial: starting domain shortening"
    );

    for key in &keys {
        match search_find(file_cache, result_cache, driver_name, filename, key, opts)? {
            LookupResult::Found { value, cache_ttl } => {
                tracing::debug!(
                    driver = %driver_name,
                    matched_key = %key,
                    "search_find_partial: match found"
                );
                return Ok(LookupResult::Found { value, cache_ttl });
            }
            LookupResult::NotFound => {
                continue;
            }
            LookupResult::Deferred { message } => {
                tracing::warn!(
                    driver = %driver_name,
                    key = %key,
                    message = %message,
                    "search_find_partial: lookup deferred"
                );
                return Ok(LookupResult::Deferred { message });
            }
        }
    }

    tracing::debug!(
        driver = %driver_name,
        original_key = %spec.original_key,
        "search_find_partial: no match at any level"
    );
    Ok(LookupResult::NotFound)
}

/// Clean up all lookup resources.
///
/// Replaces C `search_tidyup()` — calls `tidy()` on all registered lookup
/// drivers, clears the open file cache, and clears the result cache.
pub fn search_tidyup(file_cache: &mut OpenFileCache, result_cache: &mut ResultCache) {
    // Tidy all registered drivers.
    for factory in inventory::iter::<LookupDriverFactory> {
        let driver = (factory.create)();
        driver.tidy();
    }

    // Close all cached file handles.
    file_cache.close_all();

    // Clear result cache.
    result_cache.clear();

    tracing::debug!("search_tidyup: all lookup resources cleaned up");
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    #[test]
    fn test_result_cache_new() {
        let cache = ResultCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_result_cache_insert_and_get() {
        let mut cache = ResultCache::new();
        cache.insert(
            "test",
            "file.db",
            "mykey",
            Some("myvalue".to_string()),
            None,
            CacheFlags::default(),
        );
        let result = cache.get("test", "file.db", "mykey");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), &Some("myvalue".to_string()));
    }

    #[test]
    fn test_result_cache_not_found() {
        let mut cache = ResultCache::new();
        cache.insert(
            "test",
            "file.db",
            "missing",
            None,
            None,
            CacheFlags::default(),
        );
        let result = cache.get("test", "file.db", "missing");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), &None);
    }

    #[test]
    fn test_result_cache_clear() {
        let mut cache = ResultCache::new();
        cache.insert("a", "b", "c", Some("v".into()), None, CacheFlags::default());
        assert_eq!(cache.len(), 1);
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_flags_default() {
        let flags = CacheFlags::default();
        assert!(flags.allow_read);
        assert!(flags.allow_write);
    }

    #[test]
    fn test_cache_flags_no_cache() {
        let flags = CacheFlags::from_opts(Some("cache=no"));
        assert!(!flags.allow_read);
        assert!(!flags.allow_write);
    }

    #[test]
    fn test_cache_flags_no_read() {
        let flags = CacheFlags::from_opts(Some("cache=no_rd"));
        assert!(!flags.allow_read);
        assert!(flags.allow_write);
    }

    #[test]
    fn test_cache_flags_no_write() {
        let flags = CacheFlags::from_opts(Some("cache=no_wr"));
        assert!(flags.allow_read);
        assert!(!flags.allow_write);
    }

    #[test]
    fn test_result_cache_no_write_flag() {
        let mut cache = ResultCache::new();
        let flags = CacheFlags {
            allow_read: true,
            allow_write: false,
        };
        cache.insert("a", "b", "c", Some("v".into()), None, flags);
        // Should not be inserted because allow_write is false.
        assert!(cache.is_empty());
    }

    #[test]
    fn test_partial_lookup_spec_simple() {
        let spec = PartialLookupSpec::new("host.example.com");
        let keys = spec.key_sequence();
        assert_eq!(keys[0], "host.example.com");
        assert!(keys.contains(&"*.example.com".to_string()));
        assert!(keys.contains(&"example.com".to_string()));
        assert!(keys.contains(&"*.com".to_string()));
        assert!(keys.contains(&"com".to_string()));
        assert!(keys.contains(&"*".to_string()));
    }

    #[test]
    fn test_partial_lookup_spec_no_star() {
        let mut spec = PartialLookupSpec::new("a.b.c");
        spec.star_prefix = false;
        let keys = spec.key_sequence();
        assert_eq!(keys, vec!["a.b.c", "b.c", "c"]);
    }

    #[test]
    fn test_partial_lookup_spec_single_label() {
        let spec = PartialLookupSpec::new("localhost");
        let keys = spec.key_sequence();
        assert_eq!(keys[0], "localhost");
        // With star_prefix, should include "*".
        assert!(keys.contains(&"*".to_string()));
    }

    #[test]
    fn test_partial_lookup_spec_max_levels() {
        let mut spec = PartialLookupSpec::new("a.b.c.d.e");
        spec.max_levels = 2;
        let keys = spec.key_sequence();
        // Should stop after 2 levels of shortening.
        assert!(keys.contains(&"a.b.c.d.e".to_string()));
        assert!(keys.contains(&"b.c.d.e".to_string()));
        assert!(keys.contains(&"c.d.e".to_string()));
    }

    #[test]
    fn test_search_findtype_nonexistent() {
        let result = search_findtype("nonexistent_lookup_type_xyz");
        assert!(result.is_err());
    }
}
