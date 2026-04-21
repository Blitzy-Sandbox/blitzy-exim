// exim-store/src/search_cache.rs — HashMap-Based Search/Lookup Cache
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Replaces Exim's `POOL_SEARCH` (and `POOL_TAINT_SEARCH`) stacking allocator
// pool with a generic `HashMap`-based lookup cache supporting explicit clearing.
//
// Source origins:
//   - store.h lines 20, 28: POOL_SEARCH and POOL_TAINT_SEARCH pool definitions
//   - store.c: Pool management for POOL_SEARCH — allocations that persist until
//     search_tidyup() is called
//   - search.c lines 319–344: search_tidyup() — closes lookup handles, resets
//     POOL_SEARCH via store_reset()
//   - search.c lines 398–508: search_open() — opens lookup files and caches
//     handles in POOL_SEARCH
//   - search.c lines 537–700+: internal_search_find() — looks up data using
//     cached handles with item_cache tree
//
// Per AAP §0.4.3 Memory Model:
//   POOL_SEARCH (+ taint) → HashMap with explicit clear()
//
// In the C codebase, POOL_SEARCH is a stacking allocator pool used exclusively
// for lookup caching. The `search_cache` C struct holds: handle, filename, key
// data, and result trees (binary search trees for item caching). Allocations
// into POOL_SEARCH persist across lookups within a message processing cycle but
// are bulk-freed when `search_tidyup()` calls `store_reset()` on the pool.
//
// The Rust replacement uses `HashMap` for O(1) key lookups (replacing the C
// tree-based O(log n) lookups) with an explicit `clear()` method that replaces
// the C bulk-free pattern. An optional maximum entry count provides LRU-like
// eviction by removing the oldest entry (by insertion timestamp) when the cache
// is full.
//
// Hit/miss statistics are tracked via `Cell<u64>` interior mutability, allowing
// immutable `get()` calls to update counters without requiring `&mut self`.
// This mirrors the C `DEBUG(D_lookup)` debug output with `tracing::trace!`.

use std::cell::Cell;
use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use std::time::Instant;

// ---------------------------------------------------------------------------
// CacheEntry<V> — Cached lookup result with metadata
// ---------------------------------------------------------------------------

/// A cached lookup result entry holding the value and insertion timestamp.
///
/// Each entry in a [`SearchCache`] is wrapped in a `CacheEntry` that records
/// when the entry was inserted or last updated. The timestamp enables LRU-like
/// eviction when the cache reaches its maximum capacity.
///
/// This replaces the C `search_cache` struct's `item_cache` tree nodes in
/// `search.c`, which stored cached lookup results with expiration data
/// (the `expiring_data` struct with `expiry` and `data` fields).
///
/// # Fields
///
/// - `value` — The cached lookup result data.
/// - `timestamp` — The [`Instant`] when this entry was inserted or last updated,
///   used for LRU eviction ordering.
///
/// # Examples
///
/// ```rust
/// use std::time::Instant;
/// use exim_store::CacheEntry;
///
/// let entry = CacheEntry {
///     value: "lookup result".to_string(),
///     timestamp: Instant::now(),
/// };
/// assert_eq!(entry.value, "lookup result");
/// ```
#[derive(Debug, Clone)]
pub struct CacheEntry<V> {
    /// The cached lookup result data.
    pub value: V,

    /// The timestamp when this entry was inserted or last updated.
    /// Used for LRU-like eviction when the cache reaches its maximum
    /// entry count.
    pub timestamp: Instant,
}

// ---------------------------------------------------------------------------
// SearchCacheStats — Statistics snapshot
// ---------------------------------------------------------------------------

/// A point-in-time statistics snapshot for a [`SearchCache`] instance.
///
/// Provides observability into cache behaviour, replacing the C `DEBUG(D_lookup)`
/// output from `search.c`'s `internal_search_find()` function which logged
/// cache hits ("cached data used for lookup") and misses ("file/database lookup
/// required").
///
/// # Fields
///
/// - `entry_count` — Number of entries currently in the cache.
/// - `hit_count` — Cumulative count of successful cache lookups since creation
///   or the last [`clear()`](SearchCache::clear).
/// - `miss_count` — Cumulative count of cache lookups where the key was not found.
///
/// # Examples
///
/// ```rust
/// use exim_store::SearchCache;
///
/// let cache: SearchCache<String, String> = SearchCache::new();
/// let stats = cache.stats();
/// assert_eq!(stats.entry_count, 0);
/// assert_eq!(stats.hit_count, 0);
/// assert_eq!(stats.miss_count, 0);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchCacheStats {
    /// Number of entries currently stored in the cache.
    pub entry_count: usize,

    /// Cumulative number of cache hits (successful lookups via
    /// [`get()`](SearchCache::get) or [`get_mut()`](SearchCache::get_mut)).
    pub hit_count: u64,

    /// Cumulative number of cache misses (lookups where the requested key
    /// was not found in the cache).
    pub miss_count: u64,
}

// ---------------------------------------------------------------------------
// SearchCache<K, V> — The main lookup cache
// ---------------------------------------------------------------------------

/// A generic HashMap-based search/lookup cache replacing Exim's `POOL_SEARCH`
/// stacking allocator pool.
///
/// `SearchCache` provides O(1) key-value lookups with:
///
/// - **Explicit clearing** via [`clear()`](Self::clear) — replaces the C
///   `search_tidyup()` → `store_reset(POOL_SEARCH)` bulk-free pattern.
/// - **Optional size limiting** via [`with_max_entries()`](Self::with_max_entries)
///   — when the cache reaches capacity, the oldest entry (by insertion
///   timestamp) is evicted before inserting a new one.
/// - **Hit/miss tracking** for observability — counters use [`Cell<u64>`]
///   interior mutability so that immutable [`get()`](Self::get) calls can
///   update statistics without requiring `&mut self`.
/// - **Structured tracing** via `tracing::trace!` — replaces the C
///   `DEBUG(D_lookup) debug_printf_indent(...)` output from `search.c`.
///
/// # Type Parameters
///
/// - `K` — Cache key type. Must implement [`Eq`] + [`Hash`]. Defaults to
///   [`String`] for the common case of filename/query-based lookup caching.
/// - `V` — Cached value type. Defaults to [`String`] for the common case of
///   lookup result strings.
///
/// # Memory Model
///
/// Per AAP §0.4.3:
///
/// | C Store Pool | Rust Replacement | Semantics |
/// |-------------|-----------------|-----------|
/// | `POOL_SEARCH (+ taint)` | `SearchCache` (`HashMap`) | Lookup cache with explicit `clear()` |
///
/// In the C codebase, `POOL_SEARCH` allocations persist across lookups within
/// a message processing cycle and are bulk-freed when `search_tidyup()` calls
/// `store_reset()` on the pool. This Rust replacement provides the same
/// lifecycle semantics: entries persist until [`clear()`](Self::clear) is
/// called, which drops all entries and resets hit/miss counters.
///
/// # Examples
///
/// ```rust
/// use exim_store::SearchCache;
///
/// // Create a cache with no size limit
/// let mut cache: SearchCache = SearchCache::new();
///
/// // Insert a lookup result
/// cache.insert("dns:example.com".into(), "93.184.216.34".into());
///
/// // Retrieve the cached result
/// assert_eq!(cache.get(&"dns:example.com".into()), Some(&"93.184.216.34".into()));
///
/// // Clear the cache (equivalent to C search_tidyup)
/// cache.clear();
/// assert!(cache.is_empty());
/// ```
pub struct SearchCache<K = String, V = String>
where
    K: Eq + Hash,
{
    /// The underlying hash map storing cache entries keyed by lookup key.
    entries: HashMap<K, CacheEntry<V>>,

    /// Optional maximum number of entries. When set and the cache is at
    /// capacity, the oldest entry (by insertion timestamp) is evicted before
    /// a new entry is inserted.
    max_entries: Option<usize>,

    /// Cumulative cache hit counter. Uses [`Cell`] for interior mutability
    /// so that `get(&self, ...)` can update the counter without `&mut self`.
    hit_count: Cell<u64>,

    /// Cumulative cache miss counter. Uses [`Cell`] for interior mutability
    /// so that `get(&self, ...)` can update the counter without `&mut self`.
    miss_count: Cell<u64>,
}

// ---------------------------------------------------------------------------
// Core implementation
// ---------------------------------------------------------------------------

impl<K, V> SearchCache<K, V>
where
    K: Eq + Hash,
{
    /// Creates a new, empty `SearchCache` with no size limit.
    ///
    /// The cache starts with zero entries and zero hit/miss counters. There is
    /// no upper bound on the number of entries; the cache grows as needed.
    ///
    /// This is the primary constructor for the common case where the lookup
    /// system manages tidyup timing via explicit [`clear()`](Self::clear)
    /// calls rather than relying on a size cap.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::SearchCache;
    ///
    /// let cache: SearchCache<String, String> = SearchCache::new();
    /// assert!(cache.is_empty());
    /// assert_eq!(cache.len(), 0);
    /// ```
    pub fn new() -> Self {
        tracing::trace!("SearchCache created (unbounded)");
        Self {
            entries: HashMap::new(),
            max_entries: None,
            hit_count: Cell::new(0),
            miss_count: Cell::new(0),
        }
    }

    /// Creates a new, empty `SearchCache` with a maximum entry count.
    ///
    /// When the number of entries reaches `max`, inserting a new key that is
    /// not already present triggers eviction of the oldest entry (the one with
    /// the earliest insertion timestamp). Updating an existing key does **not**
    /// trigger eviction.
    ///
    /// This provides LRU-like behaviour similar to the C `lookup_open_max`
    /// limit in `search.c` line 448 which closed the least-recently-used
    /// cached open file when too many were open simultaneously.
    ///
    /// # Arguments
    ///
    /// * `max` — Maximum number of entries the cache may hold. Must be at
    ///   least 1.
    ///
    /// # Panics
    ///
    /// Panics if `max` is 0 (a zero-capacity cache is nonsensical).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::SearchCache;
    ///
    /// let cache: SearchCache<String, String> = SearchCache::with_max_entries(100);
    /// assert!(cache.is_empty());
    /// ```
    pub fn with_max_entries(max: usize) -> Self {
        assert!(max > 0, "SearchCache max_entries must be at least 1");
        tracing::trace!(max_entries = max, "SearchCache created (bounded)");
        Self {
            entries: HashMap::new(),
            max_entries: Some(max),
            hit_count: Cell::new(0),
            miss_count: Cell::new(0),
        }
    }

    /// Inserts a key-value pair into the cache, or updates the value if the
    /// key already exists.
    ///
    /// If the key is new and the cache has a maximum entry limit that has been
    /// reached, the oldest entry (by insertion timestamp) is evicted first to
    /// make room. This LRU-like eviction mirrors the C behaviour in `search.c`
    /// lines 448–464 where the least-recently-used cached file was closed when
    /// `open_filecount >= lookup_open_max`.
    ///
    /// The entry's timestamp is always set to [`Instant::now()`] regardless of
    /// whether this is an insert or an update.
    ///
    /// # Arguments
    ///
    /// * `key` — The lookup key to cache.
    /// * `value` — The lookup result to cache.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::SearchCache;
    ///
    /// let mut cache: SearchCache = SearchCache::new();
    /// cache.insert("key1".into(), "value1".into());
    /// assert_eq!(cache.len(), 1);
    ///
    /// // Updating an existing key replaces the value
    /// cache.insert("key1".into(), "updated_value".into());
    /// assert_eq!(cache.len(), 1);
    /// assert_eq!(cache.get(&"key1".into()), Some(&"updated_value".into()));
    /// ```
    pub fn insert(&mut self, key: K, value: V) {
        // Evict the oldest entry if we are at capacity and the key is new.
        if let Some(max) = self.max_entries {
            if self.entries.len() >= max && !self.entries.contains_key(&key) {
                self.evict_oldest_entry();
            }
        }

        let entry = CacheEntry {
            value,
            timestamp: Instant::now(),
        };
        self.entries.insert(key, entry);

        tracing::trace!(
            entry_count = self.entries.len(),
            max_entries = ?self.max_entries,
            "search cache: entry inserted"
        );
    }

    /// Looks up a cached value by key, returning an immutable reference.
    ///
    /// On a cache hit, the internal hit counter is incremented and a reference
    /// to the cached value is returned. On a cache miss, the miss counter is
    /// incremented and `None` is returned.
    ///
    /// This replaces the cache-check logic in `search.c` lines 569–579
    /// (`internal_search_find`) where the item cache tree was searched before
    /// performing an actual lookup:
    ///
    /// ```c
    /// if ((t = tree_search(c->item_cache, keystring)) && ...)
    ///   { /* cache hit — use cached data */ }
    /// else
    ///   { /* cache miss — perform lookup */ }
    /// ```
    ///
    /// # Arguments
    ///
    /// * `key` — The lookup key to search for.
    ///
    /// # Returns
    ///
    /// - `Some(&V)` if the key is present in the cache (hit).
    /// - `None` if the key is not found (miss).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::SearchCache;
    ///
    /// let mut cache: SearchCache = SearchCache::new();
    /// cache.insert("key".into(), "value".into());
    ///
    /// assert_eq!(cache.get(&"key".into()), Some(&"value".into()));
    /// assert_eq!(cache.get(&"nonexistent".into()), None);
    ///
    /// let stats = cache.stats();
    /// assert_eq!(stats.hit_count, 1);
    /// assert_eq!(stats.miss_count, 1);
    /// ```
    pub fn get(&self, key: &K) -> Option<&V> {
        match self.entries.get(key) {
            Some(entry) => {
                self.hit_count.set(self.hit_count.get() + 1);
                tracing::trace!("search cache: hit");
                Some(&entry.value)
            }
            None => {
                self.miss_count.set(self.miss_count.get() + 1);
                tracing::trace!("search cache: miss");
                None
            }
        }
    }

    /// Looks up a cached value by key, returning a mutable reference.
    ///
    /// Behaves identically to [`get()`](Self::get) but returns a mutable
    /// reference, allowing in-place modification of cached values. Hit/miss
    /// counters are updated in the same way.
    ///
    /// # Arguments
    ///
    /// * `key` — The lookup key to search for.
    ///
    /// # Returns
    ///
    /// - `Some(&mut V)` if the key is present in the cache (hit).
    /// - `None` if the key is not found (miss).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::SearchCache;
    ///
    /// let mut cache: SearchCache = SearchCache::new();
    /// cache.insert("key".into(), "old_value".into());
    ///
    /// if let Some(val) = cache.get_mut(&"key".into()) {
    ///     *val = "new_value".into();
    /// }
    /// assert_eq!(cache.get(&"key".into()), Some(&"new_value".into()));
    /// ```
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        // Use `&mut self` so we can directly increment counters without Cell.
        // However, for consistency, we still use Cell counters so the struct
        // definition remains uniform.
        match self.entries.get_mut(key) {
            Some(entry) => {
                self.hit_count.set(self.hit_count.get() + 1);
                tracing::trace!("search cache: hit (mutable)");
                Some(&mut entry.value)
            }
            None => {
                self.miss_count.set(self.miss_count.get() + 1);
                tracing::trace!("search cache: miss (mutable)");
                None
            }
        }
    }

    /// Checks whether the cache contains an entry for the given key.
    ///
    /// This is a lightweight existence check that does **not** affect the
    /// hit/miss counters (it is not considered a lookup operation).
    ///
    /// # Arguments
    ///
    /// * `key` — The lookup key to check.
    ///
    /// # Returns
    ///
    /// `true` if the key is present, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::SearchCache;
    ///
    /// let mut cache: SearchCache = SearchCache::new();
    /// cache.insert("key".into(), "value".into());
    ///
    /// assert!(cache.contains_key(&"key".into()));
    /// assert!(!cache.contains_key(&"other".into()));
    /// ```
    pub fn contains_key(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    /// Removes a specific entry from the cache, returning its value if present.
    ///
    /// The hit/miss counters are **not** affected by remove operations. If the
    /// key is not found, `None` is returned and the cache is unchanged.
    ///
    /// # Arguments
    ///
    /// * `key` — The lookup key to remove.
    ///
    /// # Returns
    ///
    /// - `Some(V)` containing the removed value if the key was present.
    /// - `None` if the key was not found.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::SearchCache;
    ///
    /// let mut cache: SearchCache = SearchCache::new();
    /// cache.insert("key".into(), "value".into());
    ///
    /// let removed = cache.remove(&"key".into());
    /// assert_eq!(removed, Some("value".into()));
    /// assert!(cache.is_empty());
    /// ```
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let result = self.entries.remove(key).map(|entry| entry.value);
        if result.is_some() {
            tracing::trace!(
                entry_count = self.entries.len(),
                "search cache: entry removed"
            );
        }
        result
    }

    /// Removes all entries from the cache, replacing the C `search_tidyup()`
    /// → `store_reset(POOL_SEARCH)` bulk-free pattern.
    ///
    /// This is the **critical** tidyup method that replaces the C behaviour of
    /// resetting the `POOL_SEARCH` stacking pool. In the C codebase,
    /// `search_tidyup()` (search.c lines 318–344) performs:
    ///
    /// 1. Closes all cached open lookup handles via `tidyup_subtree()`
    /// 2. Sets `search_tree = NULL`
    /// 3. Calls `store_reset(search_reset_point)` to bulk-free all
    ///    POOL_SEARCH allocations
    ///
    /// The Rust equivalent simply clears the HashMap, which drops all entries
    /// and their associated data. The hit/miss counters are also reset to zero
    /// for a clean statistical baseline.
    ///
    /// **Callers**: This method is intended to be called by the lookup tidyup
    /// code in `exim-lookups` at the end of processing sections where lookup
    /// caching was active.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::SearchCache;
    ///
    /// let mut cache: SearchCache = SearchCache::new();
    /// cache.insert("k1".into(), "v1".into());
    /// cache.insert("k2".into(), "v2".into());
    /// let _ = cache.get(&"k1".into()); // hit
    /// let _ = cache.get(&"missing".into()); // miss
    ///
    /// cache.clear();
    /// assert!(cache.is_empty());
    /// assert_eq!(cache.stats().hit_count, 0);
    /// assert_eq!(cache.stats().miss_count, 0);
    /// ```
    pub fn clear(&mut self) {
        let prev_count = self.entries.len();
        let prev_hits = self.hit_count.get();
        let prev_misses = self.miss_count.get();

        self.entries.clear();
        self.hit_count.set(0);
        self.miss_count.set(0);

        tracing::trace!(
            previous_entries = prev_count,
            previous_hits = prev_hits,
            previous_misses = prev_misses,
            "search cache cleared (tidyup) — all entries and counters reset"
        );
    }

    /// Returns the number of entries currently stored in the cache.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::SearchCache;
    ///
    /// let mut cache: SearchCache = SearchCache::new();
    /// assert_eq!(cache.len(), 0);
    ///
    /// cache.insert("key".into(), "value".into());
    /// assert_eq!(cache.len(), 1);
    /// ```
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the cache contains no entries.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::SearchCache;
    ///
    /// let cache: SearchCache<String, String> = SearchCache::new();
    /// assert!(cache.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns a point-in-time statistics snapshot for this cache.
    ///
    /// The returned [`SearchCacheStats`] captures the current entry count and
    /// the cumulative hit/miss counters. This replaces the C `DEBUG(D_lookup)`
    /// debug output from `search.c`'s `internal_search_find()`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::SearchCache;
    ///
    /// let mut cache: SearchCache = SearchCache::new();
    /// cache.insert("key".into(), "value".into());
    /// let _ = cache.get(&"key".into());     // hit
    /// let _ = cache.get(&"other".into());   // miss
    ///
    /// let stats = cache.stats();
    /// assert_eq!(stats.entry_count, 1);
    /// assert_eq!(stats.hit_count, 1);
    /// assert_eq!(stats.miss_count, 1);
    /// ```
    pub fn stats(&self) -> SearchCacheStats {
        SearchCacheStats {
            entry_count: self.entries.len(),
            hit_count: self.hit_count.get(),
            miss_count: self.miss_count.get(),
        }
    }

    /// Returns an iterator over the cached key-value pairs.
    ///
    /// The iterator yields `(&K, &V)` pairs in arbitrary order (HashMap
    /// iteration order is not guaranteed). Only the values are exposed; the
    /// [`CacheEntry`] metadata (timestamp) is not included in the iteration.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::SearchCache;
    ///
    /// let mut cache: SearchCache = SearchCache::new();
    /// cache.insert("a".into(), "1".into());
    /// cache.insert("b".into(), "2".into());
    ///
    /// let pairs: Vec<_> = cache.iter().collect();
    /// assert_eq!(pairs.len(), 2);
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries.iter().map(|(k, entry)| (k, &entry.value))
    }

    /// Returns an iterator over the cached keys.
    ///
    /// The iterator yields `&K` references in arbitrary order.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::SearchCache;
    ///
    /// let mut cache: SearchCache = SearchCache::new();
    /// cache.insert("a".into(), "1".into());
    /// cache.insert("b".into(), "2".into());
    ///
    /// let keys: Vec<_> = cache.keys().collect();
    /// assert_eq!(keys.len(), 2);
    /// ```
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.entries.keys()
    }

    // ── Private helpers ─────────────────────────────────────────────────

    /// Evicts the oldest entry (by insertion timestamp) from the cache.
    ///
    /// Uses `HashMap::retain` to remove exactly one entry — the one with the
    /// earliest `timestamp`. This is O(n) over the number of entries, which
    /// is acceptable because eviction only occurs when the cache is at its
    /// configured maximum capacity (a relatively infrequent event in Exim's
    /// lookup caching lifecycle).
    fn evict_oldest_entry(&mut self) {
        if self.entries.is_empty() {
            return;
        }

        // Find the minimum timestamp across all entries.
        let oldest_ts = self
            .entries
            .values()
            .map(|entry| entry.timestamp)
            .min()
            .expect("entries confirmed non-empty above");

        // Remove exactly one entry matching the oldest timestamp.
        let mut evicted = false;
        self.entries.retain(|_key, entry| {
            if !evicted && entry.timestamp == oldest_ts {
                evicted = true;
                false // remove this entry
            } else {
                true // keep this entry
            }
        });

        if evicted {
            tracing::trace!(
                remaining_entries = self.entries.len(),
                "search cache: evicted oldest entry to make room"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Trait implementations
// ---------------------------------------------------------------------------

/// Default creates an empty, unbounded cache (equivalent to [`SearchCache::new()`]).
impl<K, V> Default for SearchCache<K, V>
where
    K: Eq + Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Debug representation showing cache metadata without requiring `K: Debug` or
/// `V: Debug` bounds. Displays entry count, capacity limit, and hit/miss
/// statistics.
impl<K, V> fmt::Debug for SearchCache<K, V>
where
    K: Eq + Hash,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SearchCache")
            .field("entry_count", &self.entries.len())
            .field("max_entries", &self.max_entries)
            .field("hit_count", &self.hit_count.get())
            .field("miss_count", &self.miss_count.get())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_creates_empty_cache() {
        let cache: SearchCache<String, String> = SearchCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        let stats = cache.stats();
        assert_eq!(stats.entry_count, 0);
        assert_eq!(stats.hit_count, 0);
        assert_eq!(stats.miss_count, 0);
    }

    #[test]
    fn test_with_max_entries() {
        let cache: SearchCache<String, String> = SearchCache::with_max_entries(5);
        assert!(cache.is_empty());
        assert_eq!(cache.max_entries, Some(5));
    }

    #[test]
    #[should_panic(expected = "SearchCache max_entries must be at least 1")]
    fn test_with_max_entries_zero_panics() {
        let _cache: SearchCache<String, String> = SearchCache::with_max_entries(0);
    }

    #[test]
    fn test_insert_and_get() {
        let mut cache: SearchCache = SearchCache::new();
        cache.insert("key1".into(), "value1".into());

        assert_eq!(cache.get(&"key1".into()), Some(&"value1".into()));
        assert_eq!(cache.len(), 1);

        let stats = cache.stats();
        assert_eq!(stats.hit_count, 1);
        assert_eq!(stats.miss_count, 0);
    }

    #[test]
    fn test_get_miss() {
        let cache: SearchCache = SearchCache::new();
        assert_eq!(cache.get(&"nonexistent".into()), None);

        let stats = cache.stats();
        assert_eq!(stats.hit_count, 0);
        assert_eq!(stats.miss_count, 1);
    }

    #[test]
    fn test_insert_updates_existing() {
        let mut cache: SearchCache = SearchCache::new();
        cache.insert("key".into(), "old".into());
        cache.insert("key".into(), "new".into());

        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&"key".into()), Some(&"new".into()));
    }

    #[test]
    fn test_get_mut() {
        let mut cache: SearchCache = SearchCache::new();
        cache.insert("key".into(), "original".into());

        if let Some(val) = cache.get_mut(&"key".into()) {
            *val = "modified".into();
        }

        assert_eq!(cache.get(&"key".into()), Some(&"modified".into()));
        // 1 hit from get_mut + 1 hit from get
        assert_eq!(cache.stats().hit_count, 2);
    }

    #[test]
    fn test_get_mut_miss() {
        let mut cache: SearchCache = SearchCache::new();
        assert!(cache.get_mut(&"nonexistent".into()).is_none());
        assert_eq!(cache.stats().miss_count, 1);
    }

    #[test]
    fn test_contains_key() {
        let mut cache: SearchCache = SearchCache::new();
        cache.insert("present".into(), "value".into());

        assert!(cache.contains_key(&"present".into()));
        assert!(!cache.contains_key(&"absent".into()));

        // contains_key does not affect hit/miss counters
        assert_eq!(cache.stats().hit_count, 0);
        assert_eq!(cache.stats().miss_count, 0);
    }

    #[test]
    fn test_remove() {
        let mut cache: SearchCache = SearchCache::new();
        cache.insert("key".into(), "value".into());

        let removed = cache.remove(&"key".into());
        assert_eq!(removed, Some("value".into()));
        assert!(cache.is_empty());
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut cache: SearchCache = SearchCache::new();
        assert_eq!(cache.remove(&"nonexistent".into()), None);
    }

    #[test]
    fn test_clear_drops_all_entries_and_resets_counters() {
        let mut cache: SearchCache = SearchCache::new();
        cache.insert("a".into(), "1".into());
        cache.insert("b".into(), "2".into());
        let _ = cache.get(&"a".into()); // hit
        let _ = cache.get(&"missing".into()); // miss

        assert_eq!(cache.len(), 2);
        assert_eq!(cache.stats().hit_count, 1);
        assert_eq!(cache.stats().miss_count, 1);

        cache.clear();

        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.stats().hit_count, 0);
        assert_eq!(cache.stats().miss_count, 0);
    }

    #[test]
    fn test_eviction_when_max_entries_reached() {
        let mut cache: SearchCache = SearchCache::with_max_entries(2);

        cache.insert("first".into(), "1".into());
        // Small delay to ensure distinct timestamps
        std::thread::sleep(std::time::Duration::from_millis(1));
        cache.insert("second".into(), "2".into());
        std::thread::sleep(std::time::Duration::from_millis(1));

        // This insert should evict "first" (oldest)
        cache.insert("third".into(), "3".into());

        assert_eq!(cache.len(), 2);
        assert!(!cache.contains_key(&"first".into()));
        assert!(cache.contains_key(&"second".into()));
        assert!(cache.contains_key(&"third".into()));
    }

    #[test]
    fn test_no_eviction_on_update() {
        let mut cache: SearchCache = SearchCache::with_max_entries(2);
        cache.insert("a".into(), "1".into());
        cache.insert("b".into(), "2".into());

        // Updating an existing key should NOT trigger eviction
        cache.insert("a".into(), "updated".into());
        assert_eq!(cache.len(), 2);
        assert!(cache.contains_key(&"a".into()));
        assert!(cache.contains_key(&"b".into()));
        assert_eq!(cache.get(&"a".into()), Some(&"updated".into()));
    }

    #[test]
    fn test_iter() {
        let mut cache: SearchCache = SearchCache::new();
        cache.insert("a".into(), "1".into());
        cache.insert("b".into(), "2".into());

        let mut pairs: Vec<_> = cache.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        pairs.sort();
        assert_eq!(
            pairs,
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "2".to_string()),
            ]
        );
    }

    #[test]
    fn test_keys() {
        let mut cache: SearchCache = SearchCache::new();
        cache.insert("alpha".into(), "1".into());
        cache.insert("beta".into(), "2".into());

        let mut keys: Vec<_> = cache.keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, vec!["alpha".to_string(), "beta".to_string()]);
    }

    #[test]
    fn test_default() {
        let cache: SearchCache<String, String> = SearchCache::default();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_debug_format() {
        let mut cache: SearchCache = SearchCache::new();
        cache.insert("key".into(), "value".into());
        let debug_str = format!("{:?}", cache);
        assert!(debug_str.contains("SearchCache"));
        assert!(debug_str.contains("entry_count: 1"));
    }

    #[test]
    fn test_generic_with_integer_keys() {
        let mut cache: SearchCache<u64, Vec<u8>> = SearchCache::new();
        cache.insert(42, vec![1, 2, 3]);
        cache.insert(99, vec![4, 5, 6]);

        assert_eq!(cache.get(&42), Some(&vec![1, 2, 3]));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_stats_snapshot_is_consistent() {
        let mut cache: SearchCache = SearchCache::new();
        cache.insert("x".into(), "y".into());
        let _ = cache.get(&"x".into()); // hit
        let _ = cache.get(&"z".into()); // miss

        let stats = cache.stats();
        assert_eq!(stats.entry_count, 1);
        assert_eq!(stats.hit_count, 1);
        assert_eq!(stats.miss_count, 1);
    }

    #[test]
    fn test_cache_entry_fields_accessible() {
        let entry = CacheEntry {
            value: "test_value".to_string(),
            timestamp: Instant::now(),
        };
        assert_eq!(entry.value, "test_value");
        // Timestamp should be very recent
        assert!(entry.timestamp.elapsed().as_secs() < 1);
    }

    #[test]
    fn test_search_cache_stats_fields_accessible() {
        let stats = SearchCacheStats {
            entry_count: 10,
            hit_count: 50,
            miss_count: 5,
        };
        assert_eq!(stats.entry_count, 10);
        assert_eq!(stats.hit_count, 50);
        assert_eq!(stats.miss_count, 5);
    }

    #[test]
    fn test_multiple_evictions() {
        let mut cache: SearchCache = SearchCache::with_max_entries(1);

        cache.insert("a".into(), "1".into());
        std::thread::sleep(std::time::Duration::from_millis(1));
        cache.insert("b".into(), "2".into());
        std::thread::sleep(std::time::Duration::from_millis(1));
        cache.insert("c".into(), "3".into());

        assert_eq!(cache.len(), 1);
        assert!(cache.contains_key(&"c".into()));
        assert!(!cache.contains_key(&"a".into()));
        assert!(!cache.contains_key(&"b".into()));
    }

    #[test]
    fn test_clear_then_reuse() {
        let mut cache: SearchCache = SearchCache::new();
        cache.insert("old".into(), "data".into());
        let _ = cache.get(&"old".into());

        cache.clear();

        // Cache should be fully reusable after clear
        cache.insert("new".into(), "data".into());
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&"new".into()), Some(&"data".into()));
        assert_eq!(cache.stats().hit_count, 1);
    }
}
