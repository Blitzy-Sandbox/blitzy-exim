// exim-store/src/config_store.rs — Arc<Config> Frozen-After-Parse Configuration Store
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Replaces Exim's `POOL_CONFIG` (and `POOL_TAINT_CONFIG`) with a Rust
// `Arc<Config>` pattern that builds configuration mutably during parsing,
// then freezes it into a shared immutable reference.
//
// C source equivalences:
//   - `store.c` lines 369–377: `store_writeprotect(POOL_CONFIG)` used `mprotect(PROT_READ)`
//     to make config blocks read-only → replaced by `Arc<T>` immutability (compile-time)
//   - `store.c` lines 440–451: `pool_get()` with `posix_memalign` for page-aligned config
//     blocks → not needed (Arc handles alignment)
//   - `store.h` lines 19, 27: `POOL_CONFIG` / `POOL_TAINT_CONFIG` pool enum values
//
// Per AAP §0.4.3: `POOL_CONFIG (+taint)` → `Arc<Config> frozen after parse`
// Per AAP §0.4.4: `ConfigContext` — all options, driver instances, ACL definitions
// Per AAP §0.7.3: Config data stored in `Arc<Config>`, immutable after parsing

use std::fmt;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// ConfigData — Placeholder for parsed configuration fields
// ---------------------------------------------------------------------------

/// Placeholder struct representing parsed Exim configuration data.
///
/// This type serves as the default generic parameter for [`ConfigBuilder`] and
/// [`ConfigStore`].  The actual configuration fields — encompassing all 714+
/// global variables from the C `globals.c`/`globals.h`, all driver instance
/// lists, ACL definitions, and rewrite rules — will be defined by the
/// `exim-config` crate's `ConfigContext` type in `exim-config/src/types.rs`.
///
/// Because both [`ConfigBuilder`] and [`ConfigStore`] are generic over `T`,
/// downstream crates specialise with their own concrete config type:
///
/// ```rust,ignore
/// use exim_store::config_store::{ConfigBuilder, ConfigStore};
/// // In exim-config:
/// let builder: ConfigBuilder<ConfigContext> = ConfigBuilder::with_data(ctx);
/// let store: ConfigStore<ConfigContext> = builder.freeze();
/// ```
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConfigData {
    // Intentionally empty — all configuration fields are defined by the
    // downstream `exim-config` crate.  This placeholder enables the
    // `exim-store` crate to compile and test independently of the config
    // schema.
    _private: (),
}

// ---------------------------------------------------------------------------
// ConfigBuilder — Mutable build phase (replaces POOL_CONFIG allocation)
// ---------------------------------------------------------------------------

/// Mutable builder used during configuration file parsing.
///
/// `ConfigBuilder<T>` holds the configuration data mutably while the parser
/// (implemented in the `exim-config` crate) populates it field by field.  Once
/// parsing completes, [`ConfigBuilder::freeze`] consumes the builder via move
/// semantics and produces an immutable [`ConfigStore<T>`] backed by `Arc<T>`.
///
/// This pattern replaces the C runtime enforcement of immutability, where
/// `store_writeprotect(POOL_CONFIG)` called `mprotect(PROT_READ)` on every
/// block allocated from `POOL_CONFIG`.  In Rust, immutability is enforced at
/// **compile time**: after `freeze()`, no `&mut T` reference can be obtained.
///
/// # Type Parameter
///
/// * `T` — The concrete configuration type.  Defaults to [`ConfigData`] (a
///   minimal placeholder).  Downstream crates use their own `ConfigContext`:
///
/// ```rust,ignore
/// let builder = ConfigBuilder::<MyConfigContext>::new();
/// ```
///
/// # Lifecycle
///
/// ```text
///   ConfigBuilder::new()      →  mutable build phase (&mut access)
///        ↓
///   builder.freeze()          →  ConfigStore (immutable, Arc-wrapped)
///        ↓                        ↓
///   builder is consumed        ConfigStore can be cheaply cloned
///   (cannot be used again)     and shared across threads/processes
/// ```
pub struct ConfigBuilder<T = ConfigData> {
    /// The mutable configuration data being constructed.
    data: T,
}

impl<T: Default> ConfigBuilder<T> {
    /// Creates a new `ConfigBuilder` with default-initialised configuration.
    ///
    /// This is the primary entry point when building configuration from
    /// scratch (i.e. starting a fresh parse of the config file).
    ///
    /// # Examples
    ///
    /// ```
    /// use exim_store::config_store::ConfigBuilder;
    /// let builder = ConfigBuilder::<exim_store::config_store::ConfigData>::new();
    /// ```
    pub fn new() -> Self {
        tracing::debug!("ConfigBuilder: initialising new mutable configuration");
        Self { data: T::default() }
    }
}

impl<T> ConfigBuilder<T> {
    /// Creates a `ConfigBuilder` pre-populated with the given configuration data.
    ///
    /// Use this when the configuration data has already been constructed
    /// externally and just needs to be wrapped in the builder lifecycle.
    ///
    /// # Arguments
    ///
    /// * `data` — The pre-built configuration data to wrap.
    pub fn with_data(data: T) -> Self {
        tracing::debug!("ConfigBuilder: initialising with pre-built configuration data");
        Self { data }
    }

    /// Returns a shared reference to the configuration data being built.
    ///
    /// This allows read access to partially-built config for validation or
    /// cross-referencing during the parse phase, without granting mutation.
    pub fn data(&self) -> &T {
        &self.data
    }

    /// Returns a mutable reference to the configuration data being built.
    ///
    /// This is the primary interface used by the configuration parser to
    /// populate fields during the mutable build phase.  Once [`freeze`] is
    /// called, no further mutation is possible.
    ///
    /// [`freeze`]: ConfigBuilder::freeze
    pub fn data_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Freezes the configuration, consuming the builder and producing an
    /// immutable [`ConfigStore<T>`].
    ///
    /// This is the Rust replacement for `store_writeprotect(POOL_CONFIG)` from
    /// `store.c` line 370.  In the C implementation, `mprotect(PROT_READ)` was
    /// called on every block allocated from `POOL_CONFIG` to enforce read-only
    /// access at runtime (writes caused `SIGSEGV`).  In Rust, the builder is
    /// **consumed** by this method (move semantics), so the compiler statically
    /// prevents any further mutation — zero runtime cost, compile-time safety.
    ///
    /// The returned `ConfigStore` wraps the data in an `Arc<T>`, enabling cheap
    /// cloning for sharing across forked child processes in Exim's
    /// fork-per-connection concurrency model.
    ///
    /// # Panics
    ///
    /// This method does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use exim_store::config_store::{ConfigBuilder, ConfigStore, ConfigData};
    ///
    /// let mut builder = ConfigBuilder::<ConfigData>::new();
    /// // ... populate builder.data_mut() during parsing ...
    /// let store: ConfigStore<ConfigData> = builder.freeze();
    /// assert!(store.is_frozen());
    /// ```
    pub fn freeze(self) -> ConfigStore<T>
    where
        T: Send + Sync,
    {
        tracing::debug!(
            "ConfigBuilder::freeze: configuration is now immutable \
             (replaces store_writeprotect POOL_CONFIG)"
        );

        // Log the size of the config data being frozen for observability.
        // This replaces the C `DEBUG(D_memory)` output that logged pool block
        // counts and byte totals for POOL_CONFIG.
        let config_size = std::mem::size_of::<T>();
        tracing::debug!(
            config_type_size_bytes = config_size,
            "ConfigBuilder::freeze: Arc<Config> created, type size = {} bytes",
            config_size
        );

        ConfigStore {
            inner: Arc::new(self.data),
        }
    }
}

impl<T: Default> Default for ConfigBuilder<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: fmt::Debug> fmt::Debug for ConfigBuilder<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigBuilder")
            .field("data", &self.data)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// ConfigStore — Immutable frozen phase (replaces mprotect'd POOL_CONFIG)
// ---------------------------------------------------------------------------

/// Immutable, reference-counted configuration store.
///
/// `ConfigStore<T>` wraps the parsed configuration in an `Arc<T>`, providing:
///
/// - **Immutability** — Only `&self` (shared reference) access is available.
///   There is no method to obtain `&mut T` from a `ConfigStore`.
/// - **Cheap cloning** — `Clone` increments the `Arc` reference count (a single
///   atomic operation), making it efficient to share config across Exim's
///   forked child processes.
/// - **Thread safety** — `ConfigStore<T>` is `Send + Sync` when `T` is
///   `Send + Sync`, guaranteed by `Arc<T>`.
///
/// In Exim's fork-per-connection model, each forked child inherits a clone of
/// the parent's `ConfigStore`.  After `fork()`, the `Arc` reference count is
/// effectively 1 per process (since `fork()` duplicates the address space
/// rather than sharing it), so there is no contention on the atomic counter.
///
/// # Type Parameter
///
/// * `T` — The concrete configuration type.  Defaults to [`ConfigData`].
///   In production, this will be `ConfigContext` from the `exim-config` crate.
///
/// # Relationship to C Code
///
/// | C Mechanism | Rust Replacement |
/// |---|---|
/// | `POOL_CONFIG` allocation pool | Data owned by `Arc<T>` inside `ConfigStore` |
/// | `store_writeprotect(POOL_CONFIG)` | Builder consumed by `freeze()` — compile-time |
/// | `mprotect(PROT_READ)` runtime guard | `Arc<T>` provides only `&T` — no `&mut T` |
/// | SIGSEGV on post-freeze write | Compile error on post-freeze mutation |
pub struct ConfigStore<T = ConfigData> {
    /// The frozen configuration data, wrapped in `Arc` for reference-counted
    /// sharing.  `Arc` guarantees that the inner `T` cannot be mutated
    /// through the shared reference (barring interior mutability, which we
    /// do not use).
    inner: Arc<T>,
}

impl<T> ConfigStore<T> {
    /// Returns a shared reference to the frozen configuration data.
    ///
    /// This is the primary read-access method.  The returned reference has
    /// the same lifetime as `&self`, ensuring the `Arc` is not dropped while
    /// the reference is live.
    ///
    /// # Examples
    ///
    /// ```
    /// use exim_store::config_store::{ConfigBuilder, ConfigData};
    ///
    /// let store = ConfigBuilder::<ConfigData>::new().freeze();
    /// let config: &ConfigData = store.get();
    /// ```
    pub fn get(&self) -> &T {
        &self.inner
    }

    /// Returns a clone of the inner `Arc<T>`, incrementing the reference count.
    ///
    /// Use this when you need to pass the configuration to another subsystem
    /// or thread that will hold its own long-lived reference.  The `Arc` clone
    /// is a single atomic increment — extremely cheap.
    ///
    /// # Examples
    ///
    /// ```
    /// use exim_store::config_store::{ConfigBuilder, ConfigData};
    /// use std::sync::Arc;
    ///
    /// let store = ConfigBuilder::<ConfigData>::new().freeze();
    /// let arc: Arc<ConfigData> = store.arc();
    /// assert!(Arc::strong_count(&arc) >= 1);
    /// ```
    pub fn arc(&self) -> Arc<T> {
        Arc::clone(&self.inner)
    }

    /// Returns `true`, confirming that this `ConfigStore` holds frozen
    /// (immutable) configuration.
    ///
    /// This method always returns `true` because a `ConfigStore` can only be
    /// created via [`ConfigBuilder::freeze`], which enforces immutability at
    /// the type level.  The method exists for API symmetry and to make the
    /// frozen status explicit in call sites (e.g. assertions in tests or
    /// debug logging).
    ///
    /// In the C codebase, checking whether config was frozen required testing
    /// a flag or relying on the SIGSEGV from `mprotect`.  Here, the type
    /// system guarantees it.
    pub fn is_frozen(&self) -> bool {
        true
    }

    /// Returns the current `Arc` strong reference count.
    ///
    /// Useful for debugging and observability — e.g. verifying that after
    /// `fork()`, each process holds its own reference.
    ///
    /// # Note
    ///
    /// The value returned by this method is inherently racy when multiple
    /// threads are involved.  It should be used for logging/debugging only,
    /// never for synchronisation decisions.
    pub fn strong_count(&self) -> usize {
        Arc::strong_count(&self.inner)
    }
}

impl<T> Clone for ConfigStore<T> {
    /// Clones the `ConfigStore` by incrementing the `Arc` reference count.
    ///
    /// This is an O(1) atomic operation — the underlying configuration data
    /// is **not** copied.  Every clone shares the same heap allocation.
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for ConfigStore<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigStore")
            .field("inner", &self.inner)
            .field("strong_count", &Arc::strong_count(&self.inner))
            .finish()
    }
}

impl<T: PartialEq> PartialEq for ConfigStore<T> {
    /// Two `ConfigStore` instances are equal if their inner data is equal.
    ///
    /// This compares by **value**, not by `Arc` pointer identity.  For pointer
    /// identity comparison, use [`Arc::ptr_eq`] on the results of [`arc()`].
    ///
    /// [`arc()`]: ConfigStore::arc
    fn eq(&self, other: &Self) -> bool {
        *self.inner == *other.inner
    }
}

impl<T: Eq> Eq for ConfigStore<T> {}

// ---------------------------------------------------------------------------
// Thread-safety static assertions
// ---------------------------------------------------------------------------

// These trait-bound assertions verify at compile time that ConfigStore<ConfigData>
// is Send + Sync, required for sharing across forked processes and (future)
// threaded contexts.  They cost nothing at runtime — the compiler checks the
// bounds and the code is optimised away entirely.
//
// Using a trait-bound approach rather than function-call approach to avoid
// dead-code warnings under `RUSTFLAGS="-D warnings"`.

/// Compile-time assertion: `ConfigStore<ConfigData>` is `Send + Sync`.
const _: fn() = || {
    fn must_be_send_sync<T: Send + Sync>() {}
    must_be_send_sync::<ConfigStore<ConfigData>>();
};

/// Compile-time assertion: `ConfigBuilder<ConfigData>` is `Send`.
/// (ConfigBuilder only needs `Send` — it is moved to the parser, not shared.)
const _: fn() = || {
    fn must_be_send<T: Send>() {}
    must_be_send::<ConfigBuilder<ConfigData>>();
};

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `ConfigBuilder::new()` creates a builder with default data.
    #[test]
    fn test_builder_new_creates_default() {
        let builder = ConfigBuilder::<ConfigData>::new();
        assert_eq!(*builder.data(), ConfigData::default());
    }

    /// Verify that `ConfigBuilder::with_data()` stores the provided data.
    #[test]
    fn test_builder_with_data() {
        let data = ConfigData::default();
        let builder = ConfigBuilder::with_data(data.clone());
        assert_eq!(*builder.data(), data);
    }

    /// Verify mutable access via `data_mut()`.
    #[test]
    fn test_builder_data_mut_provides_mutable_access() {
        let mut builder = ConfigBuilder::<ConfigData>::new();
        let _data_ref: &mut ConfigData = builder.data_mut();
        // Mutable reference obtained successfully — compile-time check.
    }

    /// Verify that `freeze()` produces a `ConfigStore` and consumes the builder.
    #[test]
    fn test_freeze_produces_config_store() {
        let builder = ConfigBuilder::<ConfigData>::new();
        let store = builder.freeze();
        // builder is consumed — using it here would be a compile error.
        assert!(store.is_frozen());
    }

    /// Verify that `ConfigStore::get()` returns a reference to the inner data.
    #[test]
    fn test_store_get_returns_reference() {
        let store = ConfigBuilder::<ConfigData>::new().freeze();
        let config: &ConfigData = store.get();
        assert_eq!(*config, ConfigData::default());
    }

    /// Verify that `ConfigStore::arc()` returns an `Arc` to the same data.
    #[test]
    fn test_store_arc_returns_arc() {
        let store = ConfigBuilder::<ConfigData>::new().freeze();
        let arc = store.arc();
        assert_eq!(*arc, ConfigData::default());
        // The strong count should be at least 2: one in `store`, one in `arc`.
        assert!(Arc::strong_count(&arc) >= 2);
    }

    /// Verify that `is_frozen()` always returns true.
    #[test]
    fn test_store_is_always_frozen() {
        let store = ConfigBuilder::<ConfigData>::new().freeze();
        assert!(store.is_frozen());
    }

    /// Verify that `Clone` for `ConfigStore` is cheap (Arc ref-count).
    #[test]
    fn test_store_clone_increments_refcount() {
        let store = ConfigBuilder::<ConfigData>::new().freeze();
        let clone = store.clone();
        assert_eq!(store.strong_count(), 2);
        assert_eq!(clone.strong_count(), 2);
        // Both point to the same data.
        assert!(Arc::ptr_eq(&store.arc(), &clone.arc()));
    }

    /// Verify that dropping a clone decrements the reference count.
    #[test]
    fn test_store_drop_decrements_refcount() {
        let store = ConfigBuilder::<ConfigData>::new().freeze();
        let clone = store.clone();
        assert_eq!(store.strong_count(), 2);
        drop(clone);
        assert_eq!(store.strong_count(), 1);
    }

    /// Verify Debug formatting works for ConfigStore.
    #[test]
    fn test_store_debug_format() {
        let store = ConfigBuilder::<ConfigData>::new().freeze();
        let debug_str = format!("{:?}", store);
        assert!(debug_str.contains("ConfigStore"));
        assert!(debug_str.contains("strong_count"));
    }

    /// Verify Debug formatting works for ConfigBuilder.
    #[test]
    fn test_builder_debug_format() {
        let builder = ConfigBuilder::<ConfigData>::new();
        let debug_str = format!("{:?}", builder);
        assert!(debug_str.contains("ConfigBuilder"));
    }

    /// Verify PartialEq for ConfigStore compares by value.
    #[test]
    fn test_store_equality_by_value() {
        let store1 = ConfigBuilder::<ConfigData>::new().freeze();
        let store2 = ConfigBuilder::<ConfigData>::new().freeze();
        // Both hold default ConfigData, so they should be equal by value.
        assert_eq!(store1, store2);
        // But they are backed by different Arc allocations.
        assert!(!Arc::ptr_eq(&store1.arc(), &store2.arc()));
    }

    /// Verify ConfigBuilder Default trait.
    #[test]
    fn test_builder_default() {
        let builder: ConfigBuilder<ConfigData> = ConfigBuilder::default();
        assert_eq!(*builder.data(), ConfigData::default());
    }

    /// Verify generic ConfigStore works with a custom type.
    #[test]
    fn test_generic_config_store_with_custom_type() {
        #[derive(Debug, Default, Clone, PartialEq)]
        struct CustomConfig {
            max_connections: u32,
            hostname: String,
        }

        let mut builder = ConfigBuilder::with_data(CustomConfig {
            max_connections: 100,
            hostname: "mail.example.com".to_string(),
        });

        // Mutate during build phase.
        builder.data_mut().max_connections = 200;

        let store = builder.freeze();
        assert_eq!(store.get().max_connections, 200);
        assert_eq!(store.get().hostname, "mail.example.com");
        assert!(store.is_frozen());
    }

    /// Verify that `strong_count()` reports correctly.
    #[test]
    fn test_strong_count_reporting() {
        let store = ConfigBuilder::<ConfigData>::new().freeze();
        assert_eq!(store.strong_count(), 1);
        let _clone1 = store.clone();
        assert_eq!(store.strong_count(), 2);
        let _clone2 = store.clone();
        assert_eq!(store.strong_count(), 3);
    }
}
