// exim-store/src/message_store.rs — Scoped Per-Message Store (POOL_MESSAGE replacement)
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Replaces Exim's POOL_MESSAGE (and POOL_TAINT_MESSAGE) from store.h lines 21, 29
// and the message_start() / message_tidyup() functions in store.c lines 1294–1317.
//
// In the C codebase, POOL_MESSAGE is a stacking allocator pool used for
// "medium-lifetime objects; within a single message transaction but needed for
// longer than the use of the main pool permits" (store.c lines 41–44).
// Currently used for: receive-time DKIM information and continued-transport
// tree_unusable information.
//
// Key difference from MessageArena (arena.rs / POOL_MAIN):
//   - MessageArena → short-lived per-allocation data (POOL_MAIN), reset frequently
//   - MessageStore → medium-lifetime data persisting for the entire message
//     transaction (POOL_MESSAGE), then dropped at transaction end
//
// Per AAP §0.4.3 Memory Model:
//   POOL_MESSAGE (+ taint) → Scoped struct dropped at end of message transaction
//
// This module uses Rust's RAII (Resource Acquisition Is Initialization) pattern:
// when the MessageStore goes out of scope, all stored data is automatically
// dropped, replacing the C pattern of explicit message_tidyup() calls.
//
// Type-erased storage via std::any::Any enables safe downcasting without unsafe
// code, and the Send bound on stored data ensures fork safety in Exim's
// fork-per-connection concurrency model.

use std::any::Any;
use std::collections::HashMap;

/// Scoped per-message store replacing Exim's `POOL_MESSAGE` stacking pool.
///
/// `MessageStore` holds medium-lifetime per-message data that persists for the
/// entire duration of a single message transaction. This includes:
///
/// - **DKIM state**: Verification and signing data populated during message
///   reception and consumed during delivery (replaces receive-time DKIM
///   information stored in `POOL_MESSAGE`).
///
/// - **Transport state**: Continued-connection tracking and unusable-tree
///   information for transport drivers (replaces `tree_unusable` data stored
///   in `POOL_MESSAGE`).
///
/// - **Extension data**: Generic key-value storage for any other medium-lifetime
///   data that subsystems may need across a message transaction.
///
/// # Lifecycle
///
/// The lifecycle mirrors the C `message_start()` / `message_tidyup()` pattern:
///
/// | C Function           | Rust Equivalent                              |
/// |----------------------|----------------------------------------------|
/// | `message_start()`    | `MessageStore::new()`                        |
/// | `message_tidyup()`   | `MessageStore::reset()` or drop              |
/// | `message_reset_point != NULL` | `MessageStore::is_initialized()`    |
///
/// When the `MessageStore` is dropped (goes out of scope), all stored data is
/// automatically freed via Rust's RAII semantics.
///
/// # Type Safety
///
/// Stored data uses `std::any::Any` for type-erased storage with safe
/// downcasting. The `Send` bound on all stored values ensures compatibility
/// with Exim's fork-per-connection concurrency model.
///
/// # Examples
///
/// ```rust
/// use exim_store::MessageStore;
///
/// // Create a new message store at the start of a message transaction
/// let mut store = MessageStore::new();
/// assert!(store.is_initialized());
///
/// // Store DKIM verification data
/// store.set_dkim_data("dkim-signature-data".to_string());
/// assert_eq!(
///     store.get_dkim_data::<String>(),
///     Some(&"dkim-signature-data".to_string())
/// );
///
/// // Store arbitrary extension data
/// store.insert("custom_key", 42u64);
/// assert_eq!(store.get::<u64>("custom_key"), Some(&42u64));
///
/// // Reset clears all data (like C message_tidyup)
/// store.reset();
/// assert!(!store.is_initialized());
/// ```
pub struct MessageStore {
    /// DKIM verification/signing state populated during message reception and
    /// consumed during delivery. Replaces the receive-time DKIM information
    /// that was previously allocated in `POOL_MESSAGE`.
    ///
    /// The stored type is erased via `Any` to allow different DKIM
    /// implementations to store their own state types. Retrieve with
    /// [`get_dkim_data`](Self::get_dkim_data) using the concrete type parameter.
    dkim_data: Option<Box<dyn Any + Send>>,

    /// Transport state tracking for continued connections and unusable-tree
    /// information. Replaces the `tree_unusable` data previously allocated
    /// in `POOL_MESSAGE`.
    ///
    /// The stored type is erased via `Any` to allow different transport drivers
    /// to store their own state types. Retrieve with
    /// [`get_transport_state`](Self::get_transport_state) using the concrete
    /// type parameter.
    transport_state: Option<Box<dyn Any + Send>>,

    /// Generic key-value store for other medium-lifetime per-message data that
    /// subsystems may need across a message transaction. Each value is
    /// type-erased and can be retrieved with safe downcasting.
    extensions: HashMap<String, Box<dyn Any + Send>>,

    /// Whether this store has been initialized and contains valid state.
    /// Replaces the C `message_reset_point != NULL` check used to determine
    /// if `message_start()` has been called for the current transaction.
    initialized: bool,
}

impl MessageStore {
    /// Creates a new, empty `MessageStore` for a message transaction.
    ///
    /// This replaces the C `message_start()` function from `store.c` lines
    /// 1299–1306, which switched to `POOL_MESSAGE` and called `store_mark()`
    /// to establish a reset point.
    ///
    /// The newly created store is marked as initialized and ready to receive
    /// per-message data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::MessageStore;
    ///
    /// let store = MessageStore::new();
    /// assert!(store.is_initialized());
    /// assert_eq!(store.entry_count(), 0);
    /// ```
    pub fn new() -> Self {
        tracing::trace!("MessageStore created for new message transaction");
        Self {
            dkim_data: None,
            transport_state: None,
            extensions: HashMap::new(),
            initialized: true,
        }
    }

    /// Resets the message store, clearing all stored data.
    ///
    /// This replaces the C `message_tidyup()` function from `store.c` lines
    /// 1308–1317, which switched to `POOL_MESSAGE` and called `store_reset()`
    /// to free all allocations back to the mark point.
    ///
    /// After calling `reset()`:
    /// - All DKIM data is dropped
    /// - All transport state is dropped
    /// - All extension data is dropped
    /// - `is_initialized()` returns `false`
    ///
    /// The store can be reused for a subsequent message transaction by calling
    /// the setter methods, which will re-initialize it.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::MessageStore;
    ///
    /// let mut store = MessageStore::new();
    /// store.insert("key", "value".to_string());
    /// assert_eq!(store.entry_count(), 1);
    ///
    /// store.reset();
    /// assert!(!store.is_initialized());
    /// assert_eq!(store.entry_count(), 0);
    /// ```
    pub fn reset(&mut self) {
        let prev_count = self.entry_count();
        self.dkim_data = None;
        self.transport_state = None;
        self.extensions.clear();
        self.initialized = false;
        tracing::trace!(
            previous_entries = prev_count,
            "MessageStore reset — all per-message data cleared"
        );
    }

    /// Returns whether this store has been initialized for a message transaction.
    ///
    /// This replaces the C `message_reset_point != NULL` check used in
    /// `message_tidyup()` (store.c line 1312) to determine whether the
    /// message pool has been marked.
    ///
    /// Returns `true` after [`new()`](Self::new) and before [`reset()`](Self::reset).
    /// Returns `false` after [`reset()`](Self::reset) has been called.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::MessageStore;
    ///
    /// let mut store = MessageStore::new();
    /// assert!(store.is_initialized());
    ///
    /// store.reset();
    /// assert!(!store.is_initialized());
    /// ```
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // ── Typed DKIM Data Access ───────────────────────────────────────────

    /// Stores DKIM verification/signing state for the current message transaction.
    ///
    /// The data type is erased via `std::any::Any`, allowing any `'static + Send`
    /// type to be stored. This replaces DKIM information that was previously
    /// allocated into `POOL_MESSAGE` during message reception.
    ///
    /// If DKIM data was already stored, it is replaced and the previous value
    /// is dropped.
    ///
    /// Calling this method on an uninitialized store (after `reset()`) will
    /// re-initialize the store.
    ///
    /// # Type Parameters
    ///
    /// - `T` — The concrete DKIM state type. Must be `'static + Send` to
    ///   support type-erased storage and fork safety.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::MessageStore;
    ///
    /// #[derive(Debug, PartialEq)]
    /// struct DkimVerifyResult {
    ///     domain: String,
    ///     passed: bool,
    /// }
    ///
    /// let mut store = MessageStore::new();
    /// store.set_dkim_data(DkimVerifyResult {
    ///     domain: "example.com".into(),
    ///     passed: true,
    /// });
    ///
    /// let result = store.get_dkim_data::<DkimVerifyResult>().unwrap();
    /// assert!(result.passed);
    /// ```
    pub fn set_dkim_data<T: 'static + Send>(&mut self, data: T) {
        self.initialized = true;
        self.dkim_data = Some(Box::new(data));
        tracing::trace!(
            type_name = std::any::type_name::<T>(),
            "MessageStore: DKIM data stored"
        );
    }

    /// Retrieves a reference to the stored DKIM data, downcasted to the
    /// requested concrete type.
    ///
    /// Returns `None` if no DKIM data has been stored, or if the stored data
    /// is not of type `T`.
    ///
    /// # Type Parameters
    ///
    /// - `T` — The expected concrete DKIM state type. Must be `'static` to
    ///   support `Any` downcasting.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::MessageStore;
    ///
    /// let mut store = MessageStore::new();
    /// store.set_dkim_data(42u64);
    ///
    /// // Correct type succeeds
    /// assert_eq!(store.get_dkim_data::<u64>(), Some(&42u64));
    ///
    /// // Wrong type returns None
    /// assert_eq!(store.get_dkim_data::<String>(), None);
    /// ```
    pub fn get_dkim_data<T: 'static>(&self) -> Option<&T> {
        self.dkim_data
            .as_ref()
            .and_then(|boxed| boxed.downcast_ref::<T>())
    }

    // ── Typed Transport State Access ─────────────────────────────────────

    /// Stores transport state tracking data for the current message transaction.
    ///
    /// This replaces the continued-transport `tree_unusable` information that
    /// was previously allocated into `POOL_MESSAGE`. Transport drivers use this
    /// to track which connections are reusable across delivery attempts within
    /// the same message.
    ///
    /// If transport state was already stored, it is replaced and the previous
    /// value is dropped.
    ///
    /// Calling this method on an uninitialized store (after `reset()`) will
    /// re-initialize the store.
    ///
    /// # Type Parameters
    ///
    /// - `T` — The concrete transport state type. Must be `'static + Send` to
    ///   support type-erased storage and fork safety.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::MessageStore;
    ///
    /// #[derive(Debug)]
    /// struct TransportState {
    ///     unusable_hosts: Vec<String>,
    /// }
    ///
    /// let mut store = MessageStore::new();
    /// store.set_transport_state(TransportState {
    ///     unusable_hosts: vec!["mail.bad.example".into()],
    /// });
    ///
    /// let state = store.get_transport_state::<TransportState>().unwrap();
    /// assert_eq!(state.unusable_hosts.len(), 1);
    /// ```
    pub fn set_transport_state<T: 'static + Send>(&mut self, state: T) {
        self.initialized = true;
        self.transport_state = Some(Box::new(state));
        tracing::trace!(
            type_name = std::any::type_name::<T>(),
            "MessageStore: transport state stored"
        );
    }

    /// Retrieves a reference to the stored transport state, downcasted to the
    /// requested concrete type.
    ///
    /// Returns `None` if no transport state has been stored, or if the stored
    /// data is not of type `T`.
    ///
    /// # Type Parameters
    ///
    /// - `T` — The expected concrete transport state type. Must be `'static`
    ///   to support `Any` downcasting.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::MessageStore;
    ///
    /// let mut store = MessageStore::new();
    /// store.set_transport_state("active".to_string());
    ///
    /// assert_eq!(
    ///     store.get_transport_state::<String>(),
    ///     Some(&"active".to_string())
    /// );
    /// ```
    pub fn get_transport_state<T: 'static>(&self) -> Option<&T> {
        self.transport_state
            .as_ref()
            .and_then(|boxed| boxed.downcast_ref::<T>())
    }

    // ── Generic Extension Storage ────────────────────────────────────────

    /// Inserts arbitrary extension data into the message store under a string key.
    ///
    /// This provides a generic key-value storage mechanism for subsystems that
    /// need to persist medium-lifetime data across a message transaction without
    /// dedicated fields in the `MessageStore` struct.
    ///
    /// If an entry with the given key already exists, it is replaced and the
    /// previous value is dropped.
    ///
    /// Calling this method on an uninitialized store (after `reset()`) will
    /// re-initialize the store.
    ///
    /// # Type Parameters
    ///
    /// - `T` — The value type. Must be `'static + Send` to support type-erased
    ///   storage and fork safety.
    ///
    /// # Arguments
    ///
    /// - `key` — A string key identifying this extension data.
    /// - `value` — The value to store.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::MessageStore;
    ///
    /// let mut store = MessageStore::new();
    /// store.insert("spam_score", 4.5f64);
    /// store.insert("scan_result", "clean".to_string());
    ///
    /// assert_eq!(store.entry_count(), 2);
    /// assert_eq!(store.get::<f64>("spam_score"), Some(&4.5f64));
    /// ```
    pub fn insert<T: 'static + Send>(&mut self, key: &str, value: T) {
        self.initialized = true;
        tracing::trace!(
            key = key,
            type_name = std::any::type_name::<T>(),
            "MessageStore: extension data inserted"
        );
        self.extensions.insert(key.to_owned(), Box::new(value));
    }

    /// Retrieves a reference to extension data stored under the given key,
    /// downcasted to the requested concrete type.
    ///
    /// Returns `None` if no data exists for the key, or if the stored data is
    /// not of type `T`.
    ///
    /// # Type Parameters
    ///
    /// - `T` — The expected value type. Must be `'static` for `Any` downcasting.
    ///
    /// # Arguments
    ///
    /// - `key` — The string key to look up.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::MessageStore;
    ///
    /// let mut store = MessageStore::new();
    /// store.insert("counter", 100u32);
    ///
    /// // Correct type succeeds
    /// assert_eq!(store.get::<u32>("counter"), Some(&100u32));
    ///
    /// // Wrong type returns None
    /// assert_eq!(store.get::<String>("counter"), None);
    ///
    /// // Missing key returns None
    /// assert_eq!(store.get::<u32>("nonexistent"), None);
    /// ```
    pub fn get<T: 'static>(&self, key: &str) -> Option<&T> {
        self.extensions
            .get(key)
            .and_then(|boxed| boxed.downcast_ref::<T>())
    }

    /// Removes extension data stored under the given key.
    ///
    /// Returns `true` if data was present and removed, `false` if no data
    /// existed for the key.
    ///
    /// # Arguments
    ///
    /// - `key` — The string key to remove.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::MessageStore;
    ///
    /// let mut store = MessageStore::new();
    /// store.insert("temp_data", vec![1u8, 2, 3]);
    ///
    /// assert!(store.remove("temp_data"));
    /// assert!(!store.remove("temp_data")); // already removed
    /// assert!(!store.contains("temp_data"));
    /// ```
    pub fn remove(&mut self, key: &str) -> bool {
        let removed = self.extensions.remove(key).is_some();
        if removed {
            tracing::trace!(key = key, "MessageStore: extension data removed");
        }
        removed
    }

    /// Checks whether extension data exists for the given key.
    ///
    /// This does not check the type of the stored data — it only verifies
    /// that an entry exists under the key.
    ///
    /// # Arguments
    ///
    /// - `key` — The string key to check.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::MessageStore;
    ///
    /// let mut store = MessageStore::new();
    /// assert!(!store.contains("key"));
    ///
    /// store.insert("key", 42i32);
    /// assert!(store.contains("key"));
    /// ```
    pub fn contains(&self, key: &str) -> bool {
        self.extensions.contains_key(key)
    }

    // ── Statistics ────────────────────────────────────────────────────────

    /// Returns the total number of entries stored in the message store.
    ///
    /// The count includes:
    /// - 1 if DKIM data is stored
    /// - 1 if transport state is stored
    /// - The number of extension data entries
    ///
    /// # Examples
    ///
    /// ```rust
    /// use exim_store::MessageStore;
    ///
    /// let mut store = MessageStore::new();
    /// assert_eq!(store.entry_count(), 0);
    ///
    /// store.set_dkim_data("dkim".to_string());
    /// assert_eq!(store.entry_count(), 1);
    ///
    /// store.set_transport_state("state".to_string());
    /// assert_eq!(store.entry_count(), 2);
    ///
    /// store.insert("ext1", 1u32);
    /// store.insert("ext2", 2u32);
    /// assert_eq!(store.entry_count(), 4);
    /// ```
    pub fn entry_count(&self) -> usize {
        let dkim_count = usize::from(self.dkim_data.is_some());
        let transport_count = usize::from(self.transport_state.is_some());
        dkim_count + transport_count + self.extensions.len()
    }
}

/// Implement `Default` for `MessageStore` to allow default construction.
///
/// The default `MessageStore` is identical to one created via [`MessageStore::new()`],
/// providing an initialized, empty store ready for use.
impl Default for MessageStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Automatic cleanup when the `MessageStore` goes out of scope.
///
/// This implements Rust's RAII pattern: when the message transaction ends and
/// the `MessageStore` is dropped, all stored data (DKIM state, transport state,
/// and extension data) is automatically freed.
///
/// This replaces the explicit `message_tidyup()` call pattern from the C
/// codebase (`store.c` lines 1308–1317), where the caller was responsible for
/// remembering to call tidyup. With Rust's ownership semantics, cleanup is
/// guaranteed even in the presence of early returns or panics.
impl Drop for MessageStore {
    fn drop(&mut self) {
        let count = self.entry_count();
        if count > 0 || self.initialized {
            tracing::trace!(
                entries = count,
                initialized = self.initialized,
                "MessageStore dropped — RAII cleanup of per-message data"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_creates_initialized_empty_store() {
        let store = MessageStore::new();
        assert!(store.is_initialized());
        assert_eq!(store.entry_count(), 0);
    }

    #[test]
    fn test_default_creates_initialized_empty_store() {
        let store = MessageStore::default();
        assert!(store.is_initialized());
        assert_eq!(store.entry_count(), 0);
    }

    #[test]
    fn test_reset_clears_all_data() {
        let mut store = MessageStore::new();
        store.set_dkim_data("dkim_info".to_string());
        store.set_transport_state(vec![1u32, 2, 3]);
        store.insert("ext_key", 42u64);
        assert_eq!(store.entry_count(), 3);
        assert!(store.is_initialized());

        store.reset();

        assert!(!store.is_initialized());
        assert_eq!(store.entry_count(), 0);
        assert!(store.get_dkim_data::<String>().is_none());
        assert!(store.get_transport_state::<Vec<u32>>().is_none());
        assert!(!store.contains("ext_key"));
    }

    #[test]
    fn test_is_initialized_tracks_lifecycle() {
        let mut store = MessageStore::new();
        assert!(store.is_initialized());

        store.reset();
        assert!(!store.is_initialized());

        // Re-initialization via setters
        store.set_dkim_data(true);
        assert!(store.is_initialized());
    }

    #[test]
    fn test_set_and_get_dkim_data() {
        let mut store = MessageStore::new();

        #[derive(Debug, PartialEq)]
        struct DkimResult {
            domain: String,
            passed: bool,
        }

        store.set_dkim_data(DkimResult {
            domain: "example.com".into(),
            passed: true,
        });

        let result = store.get_dkim_data::<DkimResult>().unwrap();
        assert_eq!(result.domain, "example.com");
        assert!(result.passed);
    }

    #[test]
    fn test_get_dkim_data_wrong_type_returns_none() {
        let mut store = MessageStore::new();
        store.set_dkim_data(42u64);

        assert!(store.get_dkim_data::<String>().is_none());
        assert_eq!(store.get_dkim_data::<u64>(), Some(&42u64));
    }

    #[test]
    fn test_get_dkim_data_empty_returns_none() {
        let store = MessageStore::new();
        assert!(store.get_dkim_data::<String>().is_none());
    }

    #[test]
    fn test_set_dkim_data_replaces_previous() {
        let mut store = MessageStore::new();
        store.set_dkim_data("first".to_string());
        store.set_dkim_data("second".to_string());

        assert_eq!(store.get_dkim_data::<String>(), Some(&"second".to_string()));
        assert_eq!(store.entry_count(), 1);
    }

    #[test]
    fn test_set_and_get_transport_state() {
        let mut store = MessageStore::new();

        #[derive(Debug, PartialEq)]
        struct TransportState {
            unusable: Vec<String>,
        }

        store.set_transport_state(TransportState {
            unusable: vec!["host1.example".into(), "host2.example".into()],
        });

        let state = store.get_transport_state::<TransportState>().unwrap();
        assert_eq!(state.unusable.len(), 2);
    }

    #[test]
    fn test_get_transport_state_wrong_type_returns_none() {
        let mut store = MessageStore::new();
        store.set_transport_state(99i32);

        assert!(store.get_transport_state::<String>().is_none());
        assert_eq!(store.get_transport_state::<i32>(), Some(&99i32));
    }

    #[test]
    fn test_get_transport_state_empty_returns_none() {
        let store = MessageStore::new();
        assert!(store.get_transport_state::<String>().is_none());
    }

    #[test]
    fn test_set_transport_state_replaces_previous() {
        let mut store = MessageStore::new();
        store.set_transport_state(1u32);
        store.set_transport_state(2u32);

        assert_eq!(store.get_transport_state::<u32>(), Some(&2u32));
        assert_eq!(store.entry_count(), 1);
    }

    #[test]
    fn test_insert_and_get_extension() {
        let mut store = MessageStore::new();
        store.insert("spam_score", 4.5f64);

        assert_eq!(store.get::<f64>("spam_score"), Some(&4.5f64));
    }

    #[test]
    fn test_get_extension_wrong_type_returns_none() {
        let mut store = MessageStore::new();
        store.insert("key", 42u32);

        assert!(store.get::<String>("key").is_none());
    }

    #[test]
    fn test_get_extension_missing_key_returns_none() {
        let store = MessageStore::new();
        assert!(store.get::<u32>("nonexistent").is_none());
    }

    #[test]
    fn test_insert_replaces_existing_key() {
        let mut store = MessageStore::new();
        store.insert("key", "first".to_string());
        store.insert("key", "second".to_string());

        assert_eq!(store.get::<String>("key"), Some(&"second".to_string()));
        // extensions count should be 1, not 2
        assert_eq!(store.extensions.len(), 1);
    }

    #[test]
    fn test_remove_existing_key() {
        let mut store = MessageStore::new();
        store.insert("key", 42u32);

        assert!(store.remove("key"));
        assert!(!store.contains("key"));
        assert_eq!(store.entry_count(), 0);
    }

    #[test]
    fn test_remove_nonexistent_key() {
        let mut store = MessageStore::new();
        assert!(!store.remove("nonexistent"));
    }

    #[test]
    fn test_contains_key() {
        let mut store = MessageStore::new();
        assert!(!store.contains("key"));

        store.insert("key", true);
        assert!(store.contains("key"));

        store.remove("key");
        assert!(!store.contains("key"));
    }

    #[test]
    fn test_entry_count_comprehensive() {
        let mut store = MessageStore::new();
        assert_eq!(store.entry_count(), 0);

        store.set_dkim_data("dkim".to_string());
        assert_eq!(store.entry_count(), 1);

        store.set_transport_state("transport".to_string());
        assert_eq!(store.entry_count(), 2);

        store.insert("ext1", 1u32);
        assert_eq!(store.entry_count(), 3);

        store.insert("ext2", 2u32);
        assert_eq!(store.entry_count(), 4);

        // Replacing existing extension doesn't change count
        store.insert("ext1", 10u32);
        assert_eq!(store.entry_count(), 4);

        // Removing reduces count
        store.remove("ext2");
        assert_eq!(store.entry_count(), 3);
    }

    #[test]
    fn test_reinitialize_after_reset_via_dkim() {
        let mut store = MessageStore::new();
        store.reset();
        assert!(!store.is_initialized());

        store.set_dkim_data(true);
        assert!(store.is_initialized());
    }

    #[test]
    fn test_reinitialize_after_reset_via_transport() {
        let mut store = MessageStore::new();
        store.reset();
        assert!(!store.is_initialized());

        store.set_transport_state(42u64);
        assert!(store.is_initialized());
    }

    #[test]
    fn test_reinitialize_after_reset_via_insert() {
        let mut store = MessageStore::new();
        store.reset();
        assert!(!store.is_initialized());

        store.insert("key", "value".to_string());
        assert!(store.is_initialized());
    }

    #[test]
    fn test_multiple_extension_types() {
        let mut store = MessageStore::new();
        store.insert("string_val", "hello".to_string());
        store.insert("int_val", 42u64);
        store.insert("bool_val", true);
        store.insert("vec_val", vec![1u8, 2, 3]);

        assert_eq!(
            store.get::<String>("string_val"),
            Some(&"hello".to_string())
        );
        assert_eq!(store.get::<u64>("int_val"), Some(&42u64));
        assert_eq!(store.get::<bool>("bool_val"), Some(&true));
        assert_eq!(store.get::<Vec<u8>>("vec_val"), Some(&vec![1u8, 2, 3]));
    }

    #[test]
    fn test_store_is_send() {
        // Compile-time verification that MessageStore is Send
        fn assert_send<T: Send>() {}
        assert_send::<MessageStore>();
    }

    #[test]
    fn test_reset_on_empty_store() {
        let mut store = MessageStore::new();
        // Resetting an empty (but initialized) store should not panic
        store.reset();
        assert!(!store.is_initialized());
        assert_eq!(store.entry_count(), 0);
    }

    #[test]
    fn test_double_reset() {
        let mut store = MessageStore::new();
        store.set_dkim_data(42u64);
        store.reset();
        // Second reset on already-reset store should not panic
        store.reset();
        assert!(!store.is_initialized());
    }

    #[test]
    fn test_complex_dkim_type() {
        let mut store = MessageStore::new();

        #[derive(Debug, PartialEq)]
        struct ComplexDkim {
            signatures: Vec<String>,
            body_hash: [u8; 32],
            canonicalization: String,
        }

        let dkim = ComplexDkim {
            signatures: vec!["sig1".into(), "sig2".into()],
            body_hash: [0xAB; 32],
            canonicalization: "relaxed/simple".into(),
        };

        store.set_dkim_data(dkim);

        let retrieved = store.get_dkim_data::<ComplexDkim>().unwrap();
        assert_eq!(retrieved.signatures.len(), 2);
        assert_eq!(retrieved.body_hash, [0xAB; 32]);
        assert_eq!(retrieved.canonicalization, "relaxed/simple");
    }

    #[test]
    fn test_entry_count_after_dkim_replace() {
        let mut store = MessageStore::new();
        store.set_dkim_data(1u32);
        assert_eq!(store.entry_count(), 1);

        // Replacing DKIM data should not increase count
        store.set_dkim_data(2u32);
        assert_eq!(store.entry_count(), 1);
    }

    #[test]
    fn test_entry_count_after_transport_replace() {
        let mut store = MessageStore::new();
        store.set_transport_state(1u32);
        assert_eq!(store.entry_count(), 1);

        // Replacing transport state should not increase count
        store.set_transport_state(2u32);
        assert_eq!(store.entry_count(), 1);
    }
}
