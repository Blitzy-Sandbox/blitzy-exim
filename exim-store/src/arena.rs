// exim-store/src/arena.rs — Per-Message Arena Allocator (bumpalo::Bump)
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Replaces Exim's POOL_MAIN stacking pool allocator with a Rust `bumpalo::Bump`
// arena that provides per-message allocation with efficient bulk deallocation.
//
// C Equivalence Map:
//
//   C Function (store.c)           Rust Replacement
//   ─────────────────────────────  ─────────────────────────────────────────
//   pool_init() [lines 221–227]   MessageArena::new()
//   pool_get()  [lines 381–486]   MessageArena::alloc() / alloc_str() / …
//   store_get_3() [lines 508–551] MessageArena::alloc() (typed, safe)
//   store_mark_3() [lines 1034–1057] Not needed — arena lifecycle replaces
//   store_reset_3() [lines 939–954]  MessageArena::reset()
//   store_extend_3() [lines 745–792] MessageArena::new_vec() (Vec::push)
//   store_newblock_3() [lines 1137–1154] bumpalo::collections::Vec::reserve()
//   store_release_above_3() [lines 969–1030] Not needed — arena manages
//   message_start() [lines 1299–1306]  MessageArena::new()
//   message_tidyup() [lines 1309–1317] Drop the MessageArena
//   store_exit() [lines 1263–1291]     MessageArena::stats() + tracing

//! Per-message arena allocator wrapping [`bumpalo::Bump`].
//!
//! This module replaces Exim's `POOL_MAIN` stacking pool allocator (defined in
//! `store.c` / `store.h`) with a safe Rust arena that provides efficient bump
//! allocation with bulk deallocation at message completion.
//!
//! # C Store Pool Replacement
//!
//! In the original C code, `POOL_MAIN` uses a linked list of `storeblock`
//! structs with a bump pointer (`next_yield`) and remaining capacity
//! (`yield_length`).  Blocks double in size on each allocation
//! (`STORE_BLOCK_SIZE(order)` at store.c line 162).  The arena here replaces
//! that entire mechanism:
//!
//! - **Allocation** — `store_get_3()` is replaced by type-safe
//!   [`MessageArena::alloc()`] and friends, eliminating `void *` casts.
//! - **Extension** — `store_extend_3()` and `store_newblock_3()` are replaced
//!   by [`MessageArena::new_vec()`] returning a growable
//!   [`bumpalo::collections::Vec`] that manages resizing internally.
//! - **Mark / Reset** — The C `store_mark_3()` / `store_reset_3()` watermark
//!   pattern is replaced by arena-lifetime scoping: the borrow checker
//!   enforces at compile time that allocations cannot outlive the arena.
//!   [`MessageArena::reset()`] provides explicit reuse without deallocation.
//! - **Lifecycle** — `message_start()` maps to [`MessageArena::new()`] and
//!   `message_tidyup()` maps to dropping the arena (its [`Drop`] impl logs
//!   lifecycle events via [`tracing::trace!`]).
//!
//! # Ownership Model
//!
//! [`MessageArena`] owns a [`bumpalo::Bump`] arena.  All allocations borrow
//! from the arena and cannot outlive it.  Rust's borrow checker enforces
//! this at compile time — there is no runtime mark/reset bookkeeping and
//! no possibility of use-after-free.
//!
//! When the arena is dropped (at message completion), **all** allocations
//! are freed in bulk with no per-object destructor overhead.
//!
//! # Example
//!
//! ```
//! use exim_store::arena::MessageArena;
//!
//! let arena = MessageArena::new();
//!
//! // Type-safe allocation (replaces store_get + cast)
//! let counter = arena.alloc(0u64);
//! *counter += 1;
//! assert_eq!(*counter, 1);
//!
//! // String allocation (replaces store_get + memcpy)
//! let greeting = arena.alloc_str("Hello, Exim!");
//! assert_eq!(greeting, "Hello, Exim!");
//!
//! // Growable vector (replaces store_extend / store_newblock)
//! let mut recipients = arena.new_vec();
//! recipients.push("user@example.com");
//! recipients.push("admin@example.com");
//! assert_eq!(recipients.len(), 2);
//!
//! // All memory freed when `arena` goes out of scope
//! ```

use bumpalo::collections;
use bumpalo::Bump;

// ---------------------------------------------------------------------------
// ArenaStats
// ---------------------------------------------------------------------------

/// Statistics about a [`MessageArena`]'s memory usage.
///
/// Returned by [`MessageArena::stats()`] for debugging and monitoring.
/// Replaces the C `pooldesc` stats fields (`nbytes`, `maxbytes`, `nblocks`,
/// `maxblocks`) from `store.c` lines 124–128, and the `store_exit()` debug
/// output at lines 1263–1291.
///
/// # Example
///
/// ```
/// use exim_store::arena::MessageArena;
///
/// let mut arena = MessageArena::new();
/// let _ = arena.alloc([0u8; 1024]);
/// let stats = arena.stats();
/// assert!(stats.allocated_bytes >= 1024);
/// assert!(stats.chunks_count >= 1);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArenaStats {
    /// Total bytes allocated by the underlying arena's backing chunks.
    ///
    /// Includes both used and unused (padding/alignment) bytes within all
    /// allocated chunks.  Corresponds to the C `pooldesc.nbytes` field
    /// (store.c line 124).
    ///
    /// This value grows as new chunks are allocated and remains unchanged
    /// after [`MessageArena::reset()`] because backing memory is retained
    /// for reuse.
    pub allocated_bytes: usize,

    /// Number of backing memory chunks held by the arena.
    ///
    /// The arena allocates memory in chunks of increasing size (similar to
    /// the C `STORE_BLOCK_SIZE(order)` doubling strategy at store.c line
    /// 162).  This count represents the total number of such chunks.
    /// Corresponds to the C `pooldesc.nblocks` field (store.c line 126).
    ///
    /// Obtained via [`bumpalo::Bump::iter_allocated_chunks()`], which
    /// requires `&mut self` on the underlying `Bump`.
    pub chunks_count: usize,
}

// ---------------------------------------------------------------------------
// MessageArena
// ---------------------------------------------------------------------------

/// Per-message arena allocator wrapping [`bumpalo::Bump`].
///
/// Replaces Exim's `POOL_MAIN` stacking pool for short-lived per-message
/// allocations.  The arena is created at message start and dropped at message
/// completion, providing efficient bulk deallocation of all per-message data.
///
/// # Lifecycle
///
/// 1. **Create** — `MessageArena::new()` at message start (replaces
///    `pool_init()` + `message_start()` from store.c).
/// 2. **Allocate** — Call [`alloc()`](Self::alloc), [`alloc_str()`](Self::alloc_str),
///    [`new_vec()`](Self::new_vec), etc. during message processing.
/// 3. **Drop** — The arena is dropped at message completion.  All
///    allocations are freed in bulk (replaces `message_tidyup()` +
///    `store_reset()` from store.c).
///
/// Alternatively, [`reset()`](Self::reset) can be used to reclaim all
/// allocations while retaining backing memory for reuse within the same
/// message processing context.
///
/// # Replacing the C Mark / Reset Pattern
///
/// The C codebase uses `store_mark()` to capture a watermark and
/// `store_reset()` to free everything allocated since that mark.  In Rust,
/// this pattern is replaced by arena lifetime scoping:
///
/// ```
/// use exim_store::arena::MessageArena;
///
/// fn process_message() {
///     let arena = MessageArena::new();
///     let data = arena.alloc_str("message data");
///     // `data` borrows from `arena` — borrow checker ensures
///     // `data` cannot outlive `arena`.
///     assert_eq!(data, "message data");
/// }   // `arena` dropped here — all allocations freed
/// ```
///
/// # Thread Safety
///
/// `MessageArena` is `Send` but not `Sync`.  Each message-processing
/// fork gets its own arena — no cross-thread sharing is needed in
/// Exim's fork-per-connection model.
pub struct MessageArena {
    /// The underlying bump arena from the `bumpalo` crate.
    ///
    /// All allocation methods delegate to this arena.  When this struct
    /// is dropped, `Bump`'s own `Drop` implementation frees all backing
    /// memory chunks.
    arena: Bump,
}

// ---------------------------------------------------------------------------
// Constructors and Lifecycle
// ---------------------------------------------------------------------------

impl MessageArena {
    /// Creates a new, empty `MessageArena`.
    ///
    /// Replaces `pool_init()` (store.c lines 221–227) and `message_start()`
    /// (store.c lines 1299–1306).  The arena starts with no pre-allocated
    /// memory; the first allocation triggers a backing chunk allocation.
    ///
    /// # Example
    ///
    /// ```
    /// use exim_store::arena::MessageArena;
    ///
    /// let arena = MessageArena::new();
    /// assert_eq!(arena.allocated_bytes(), 0);
    /// ```
    pub fn new() -> Self {
        tracing::trace!("MessageArena created (default capacity)");
        Self { arena: Bump::new() }
    }

    /// Creates a new `MessageArena` with an initial capacity hint.
    ///
    /// Pre-allocates at least `capacity` bytes of backing memory, reducing
    /// the number of chunk allocations during initial message processing.
    /// This is analogous to the C `STORE_BLOCK_SIZE(order)` doubling
    /// strategy (store.c line 162) but allows callers to specify an
    /// expected message size upfront.
    ///
    /// # Arguments
    ///
    /// * `capacity` — Minimum number of bytes to pre-allocate.  The arena
    ///   may allocate more than this to satisfy internal alignment and
    ///   metadata requirements.
    ///
    /// # Example
    ///
    /// ```
    /// use exim_store::arena::MessageArena;
    ///
    /// // Pre-allocate ~64 KiB for a large message
    /// let arena = MessageArena::with_capacity(65_536);
    /// assert!(arena.allocated_bytes() >= 65_536);
    /// ```
    pub fn with_capacity(capacity: usize) -> Self {
        tracing::trace!(
            capacity_bytes = capacity,
            "MessageArena created with capacity hint"
        );
        Self {
            arena: Bump::with_capacity(capacity),
        }
    }

    /// Resets the arena, deallocating all current allocations while
    /// retaining the backing memory for reuse.
    ///
    /// After reset, the arena is empty but previously allocated chunks
    /// remain available for new allocations, avoiding repeated system-level
    /// memory allocation.  This replaces `store_reset_3()` (store.c lines
    /// 939–954) which freed blocks back to a watermark.
    ///
    /// # Safety Guarantee
    ///
    /// All references to data allocated before the reset become invalid.
    /// This is enforced at compile time by Rust's borrow checker: any
    /// outstanding borrows from the arena prevent calling `reset()` because
    /// it requires `&mut self`.
    ///
    /// # Example
    ///
    /// ```
    /// use exim_store::arena::MessageArena;
    ///
    /// let mut arena = MessageArena::new();
    /// let _ = arena.alloc(42u32);
    /// assert!(arena.allocated_bytes() > 0);
    ///
    /// arena.reset();
    /// // Arena retains backing memory but is logically empty.
    /// // New allocations will reuse the existing chunks.
    /// ```
    pub fn reset(&mut self) {
        let bytes_before = self.arena.allocated_bytes();
        self.arena.reset();
        tracing::trace!(
            bytes_before_reset = bytes_before,
            "MessageArena reset (backing memory retained for reuse)"
        );
    }
}

// ---------------------------------------------------------------------------
// Allocation Methods
// ---------------------------------------------------------------------------

impl MessageArena {
    /// Allocates a value of type `T` in the arena, returning a mutable
    /// reference bound to the arena's lifetime.
    ///
    /// Replaces `store_get_3()` (store.c lines 508–551) for typed data
    /// allocation.  Unlike the C version which returns `void *` requiring
    /// manual casting, this method is fully type-safe.
    ///
    /// The returned reference borrows from the arena and cannot outlive it,
    /// replacing the C `rmark` / `store_reset()` pattern with compile-time
    /// lifetime enforcement.
    ///
    /// # Arguments
    ///
    /// * `val` — The value to move into the arena.
    ///
    /// # Returns
    ///
    /// A mutable reference to the arena-allocated value, with a lifetime
    /// tied to the arena.
    ///
    /// # Example
    ///
    /// ```
    /// use exim_store::arena::MessageArena;
    ///
    /// let arena = MessageArena::new();
    /// let n = arena.alloc(99u64);
    /// assert_eq!(*n, 99);
    /// *n = 100;
    /// assert_eq!(*n, 100);
    /// ```
    #[inline]
    pub fn alloc<T>(&self, val: T) -> &mut T {
        self.arena.alloc(val)
    }

    /// Allocates a copy of the given string slice in the arena.
    ///
    /// Returns a string slice reference pointing to the arena-allocated
    /// copy.  This replaces the C pattern of `store_get(len + 1)` followed
    /// by `memcpy()` for string duplication.
    ///
    /// # Arguments
    ///
    /// * `s` — The string slice to copy into the arena.
    ///
    /// # Returns
    ///
    /// A string slice reference to the arena-allocated copy, with a
    /// lifetime tied to the arena.  The returned `&str` is immutable
    /// because arena-allocated strings are typically read-only after
    /// creation.
    ///
    /// # Example
    ///
    /// ```
    /// use exim_store::arena::MessageArena;
    ///
    /// let arena = MessageArena::new();
    /// let domain = arena.alloc_str("example.com");
    /// assert_eq!(domain, "example.com");
    /// ```
    #[inline]
    pub fn alloc_str(&self, s: &str) -> &str {
        // bumpalo::Bump::alloc_str returns &mut str; the implicit coercion
        // to &str provides a more natural read-only API for callers.
        self.arena.alloc_str(s)
    }

    /// Allocates a copy of the given slice in the arena.
    ///
    /// Copies all elements from `slice` into arena-allocated memory and
    /// returns a mutable reference to the new slice.  Requires `T: Copy`
    /// to ensure elements can be bitwise-copied safely.
    ///
    /// Replaces the C pattern of `store_get(n * sizeof(T))` followed by
    /// `memcpy()` for array/buffer duplication.
    ///
    /// # Arguments
    ///
    /// * `slice` — The slice to copy into the arena.
    ///
    /// # Returns
    ///
    /// A mutable slice reference to the arena-allocated copy, with a
    /// lifetime tied to the arena.
    ///
    /// # Example
    ///
    /// ```
    /// use exim_store::arena::MessageArena;
    ///
    /// let arena = MessageArena::new();
    /// let data = arena.alloc_slice(&[10u8, 20, 30, 40]);
    /// assert_eq!(data, &[10, 20, 30, 40]);
    /// data[0] = 99;
    /// assert_eq!(data[0], 99);
    /// ```
    #[inline]
    pub fn alloc_slice<T: Copy>(&self, slice: &[T]) -> &mut [T] {
        self.arena.alloc_slice_copy(slice)
    }

    /// Allocates a value computed lazily by the given closure.
    ///
    /// The closure `f` is called to produce the value, which is then
    /// stored in the arena.  This is useful when constructing the value
    /// involves computation that should only occur after the allocation
    /// decision is made.
    ///
    /// # Arguments
    ///
    /// * `f` — A closure that produces the value to allocate.
    ///
    /// # Returns
    ///
    /// A mutable reference to the arena-allocated value.
    ///
    /// # Example
    ///
    /// ```
    /// use exim_store::arena::MessageArena;
    ///
    /// let arena = MessageArena::new();
    /// let computed = arena.alloc_with(|| {
    ///     let base = 10u64;
    ///     base * base + 1
    /// });
    /// assert_eq!(*computed, 101);
    /// ```
    #[inline]
    pub fn alloc_with<T>(&self, f: impl FnOnce() -> T) -> &mut T {
        self.arena.alloc_with(f)
    }
}

// ---------------------------------------------------------------------------
// Collection Support (replacing store_extend / store_newblock)
// ---------------------------------------------------------------------------

impl MessageArena {
    /// Creates a new, empty growable vector allocated in this arena.
    ///
    /// Replaces `store_extend_3()` (store.c lines 745–792) which extended
    /// the most recent allocation in-place, and `store_newblock_3()`
    /// (store.c lines 1137–1154) which copied and grew allocations.
    ///
    /// The returned [`bumpalo::collections::Vec`] grows within the arena,
    /// using bump allocation for its backing storage.  When the arena is
    /// dropped, the vector's memory is reclaimed along with all other
    /// arena allocations.
    ///
    /// # Type Parameters
    ///
    /// * `T` — The element type for the vector.
    ///
    /// # Returns
    ///
    /// An empty [`bumpalo::collections::Vec`] that allocates from this arena.
    ///
    /// # Example
    ///
    /// ```
    /// use exim_store::arena::MessageArena;
    ///
    /// let arena = MessageArena::new();
    /// let mut headers = arena.new_vec();
    /// headers.push("From: sender@example.com");
    /// headers.push("To: recipient@example.com");
    /// headers.push("Subject: Test");
    /// assert_eq!(headers.len(), 3);
    /// ```
    #[inline]
    pub fn new_vec<T>(&self) -> collections::Vec<'_, T> {
        collections::Vec::new_in(&self.arena)
    }

    /// Creates a new, empty growable string allocated in this arena.
    ///
    /// Replaces the C pattern of `store_get()` followed by `string_cat()`
    /// used extensively in `expand.c` and `string.c` for building strings
    /// incrementally.  The returned [`bumpalo::collections::String`]
    /// provides a familiar `String`-like API with arena-backed allocation.
    ///
    /// # Returns
    ///
    /// An empty [`bumpalo::collections::String`] that allocates from this
    /// arena.
    ///
    /// # Example
    ///
    /// ```
    /// use exim_store::arena::MessageArena;
    ///
    /// let arena = MessageArena::new();
    /// let mut expanded = arena.new_string();
    /// expanded.push_str("${lookup ");
    /// expanded.push_str("dnsdb");
    /// expanded.push_str("{a=example.com}}");
    /// assert!(expanded.starts_with("${lookup"));
    /// ```
    #[inline]
    pub fn new_string(&self) -> collections::String<'_> {
        collections::String::new_in(&self.arena)
    }
}

// ---------------------------------------------------------------------------
// Statistics and Debugging (replacing store_exit debug output)
// ---------------------------------------------------------------------------

impl MessageArena {
    /// Returns the total number of bytes allocated by the arena's backing
    /// chunks.
    ///
    /// This includes both used and unused (padding/alignment) bytes within
    /// all allocated chunks.  Corresponds to the C `pooldesc.nbytes` field
    /// (store.c line 124).
    ///
    /// Wraps [`bumpalo::Bump::allocated_bytes()`].
    ///
    /// # Example
    ///
    /// ```
    /// use exim_store::arena::MessageArena;
    ///
    /// let arena = MessageArena::new();
    /// assert_eq!(arena.allocated_bytes(), 0);
    ///
    /// let _ = arena.alloc([0u8; 512]);
    /// assert!(arena.allocated_bytes() >= 512);
    /// ```
    #[inline]
    pub fn allocated_bytes(&self) -> usize {
        self.arena.allocated_bytes()
    }

    /// Returns statistics about the arena's current memory usage.
    ///
    /// Provides diagnostic information suitable for structured logging,
    /// replacing the C `store_exit()` debug output (store.c lines
    /// 1263–1291) which printed per-pool max bytes, block counts, and
    /// block orders.
    ///
    /// # Note on `&mut self`
    ///
    /// This method requires `&mut self` because
    /// [`bumpalo::Bump::iter_allocated_chunks()`] requires mutable access
    /// to safely iterate over backing chunks.  Allocation methods
    /// ([`alloc()`](Self::alloc), etc.) take `&self` via interior
    /// mutability, so any outstanding allocation references must be
    /// released before calling `stats()`.
    ///
    /// # Returns
    ///
    /// An [`ArenaStats`] struct containing current allocation metrics.
    ///
    /// # Example
    ///
    /// ```
    /// use exim_store::arena::MessageArena;
    ///
    /// let mut arena = MessageArena::new();
    /// let _ = arena.alloc([0u8; 2048]);
    /// let stats = arena.stats();
    /// assert!(stats.allocated_bytes >= 2048);
    /// assert!(stats.chunks_count >= 1);
    /// ```
    pub fn stats(&mut self) -> ArenaStats {
        let allocated_bytes = self.arena.allocated_bytes();
        let chunks_count = self.arena.iter_allocated_chunks().count();
        ArenaStats {
            allocated_bytes,
            chunks_count,
        }
    }
}

// ---------------------------------------------------------------------------
// Trait Implementations
// ---------------------------------------------------------------------------

impl Default for MessageArena {
    /// Creates a default `MessageArena` with no pre-allocated capacity.
    ///
    /// Equivalent to [`MessageArena::new()`].
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for MessageArena {
    /// Logs arena deallocation metrics before the underlying `Bump` is
    /// dropped.
    ///
    /// Replaces the C `DEBUG(D_memory)` logging in `store_reset_3()`
    /// (store.c lines 927–931) and `store_exit()` (store.c lines
    /// 1263–1291).  The `tracing::trace!` macro provides zero-overhead
    /// structured logging that is compiled out when the `trace` level
    /// is not active.
    ///
    /// After this method returns, Rust drops the `arena` field, which
    /// invokes `bumpalo::Bump::drop()` to free all backing memory chunks.
    fn drop(&mut self) {
        let allocated_bytes = self.arena.allocated_bytes();
        tracing::trace!(
            allocated_bytes = allocated_bytes,
            "MessageArena dropped (all backing memory freed)"
        );
        // bumpalo::Bump's own Drop impl handles the actual chunk deallocation
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_arena_starts_empty() {
        let arena = MessageArena::new();
        assert_eq!(arena.allocated_bytes(), 0);
    }

    #[test]
    fn with_capacity_preallocates() {
        let arena = MessageArena::with_capacity(4096);
        // bumpalo allocates at least the requested capacity
        assert!(arena.allocated_bytes() >= 4096);
    }

    #[test]
    fn alloc_single_value() {
        let arena = MessageArena::new();
        let val = arena.alloc(42u64);
        assert_eq!(*val, 42);
        *val = 100;
        assert_eq!(*val, 100);
    }

    #[test]
    fn alloc_str_copies_content() {
        let arena = MessageArena::new();
        let original = "user@example.com";
        let allocated = arena.alloc_str(original);
        assert_eq!(allocated, original);
        // Allocated string is a separate copy in the arena
        assert!(!std::ptr::eq(original.as_ptr(), allocated.as_ptr()));
    }

    #[test]
    fn alloc_str_empty() {
        let arena = MessageArena::new();
        let allocated = arena.alloc_str("");
        assert_eq!(allocated, "");
    }

    #[test]
    fn alloc_slice_copies_content() {
        let arena = MessageArena::new();
        let original: &[u32] = &[1, 2, 3, 4, 5];
        let allocated = arena.alloc_slice(original);
        assert_eq!(allocated, original);
        allocated[0] = 99;
        assert_eq!(allocated[0], 99);
    }

    #[test]
    fn alloc_slice_empty() {
        let arena = MessageArena::new();
        let allocated = arena.alloc_slice::<u8>(&[]);
        assert!(allocated.is_empty());
    }

    #[test]
    fn alloc_with_lazy_evaluation() {
        let arena = MessageArena::new();
        let val = arena.alloc_with(|| 7u32 * 6);
        assert_eq!(*val, 42);
    }

    #[test]
    fn new_vec_grows() {
        let arena = MessageArena::new();
        let mut v = arena.new_vec();
        for i in 0..100u32 {
            v.push(i);
        }
        assert_eq!(v.len(), 100);
        assert_eq!(v[0], 0);
        assert_eq!(v[99], 99);
    }

    #[test]
    fn new_string_grows() {
        let arena = MessageArena::new();
        let mut s = arena.new_string();
        s.push_str("Hello");
        s.push_str(", ");
        s.push_str("Exim!");
        assert_eq!(s.as_str(), "Hello, Exim!");
    }

    #[test]
    fn reset_allows_reuse() {
        let mut arena = MessageArena::new();
        let _ = arena.alloc([0u8; 1024]);
        let bytes_after_alloc = arena.allocated_bytes();
        assert!(bytes_after_alloc >= 1024);

        arena.reset();
        // After reset, backing memory is retained
        let bytes_after_reset = arena.allocated_bytes();
        assert!(bytes_after_reset >= bytes_after_alloc);

        // New allocations reuse the retained memory
        let _ = arena.alloc([0u8; 512]);
    }

    #[test]
    fn stats_reports_chunks() {
        let mut arena = MessageArena::new();
        let _ = arena.alloc([0u8; 4096]);
        let stats = arena.stats();
        assert!(stats.allocated_bytes >= 4096);
        assert!(stats.chunks_count >= 1);
    }

    #[test]
    fn stats_empty_arena() {
        let mut arena = MessageArena::new();
        let stats = arena.stats();
        assert_eq!(stats.allocated_bytes, 0);
        // An empty arena may have zero chunks
        assert_eq!(stats.chunks_count, 0);
    }

    #[test]
    fn default_same_as_new() {
        let arena = MessageArena::default();
        assert_eq!(arena.allocated_bytes(), 0);
    }

    #[test]
    fn multiple_allocations_coexist() {
        let arena = MessageArena::new();
        let a = arena.alloc(1u32);
        let b = arena.alloc(2u32);
        let c = arena.alloc(3u32);
        let s = arena.alloc_str("test");
        let sl = arena.alloc_slice(&[10u8, 20, 30]);

        // All allocations are independently accessible
        assert_eq!(*a, 1);
        assert_eq!(*b, 2);
        assert_eq!(*c, 3);
        assert_eq!(s, "test");
        assert_eq!(sl, &[10, 20, 30]);
    }

    #[test]
    fn arena_stats_derive_traits() {
        let stats_a = ArenaStats {
            allocated_bytes: 1024,
            chunks_count: 2,
        };
        let stats_b = stats_a;
        assert_eq!(stats_a, stats_b);

        // Debug formatting
        let debug = format!("{stats_a:?}");
        assert!(debug.contains("1024"));
        assert!(debug.contains("2"));

        // Clone
        let stats_c = stats_a.clone();
        assert_eq!(stats_a, stats_c);
    }

    #[test]
    fn large_allocation() {
        let arena = MessageArena::new();
        // 1 MiB allocation — exercises chunk allocation for large blocks
        let big = arena.alloc_slice(&vec![0xFFu8; 1_048_576]);
        assert_eq!(big.len(), 1_048_576);
        assert_eq!(big[0], 0xFF);
        assert_eq!(big[1_048_575], 0xFF);
        assert!(arena.allocated_bytes() >= 1_048_576);
    }

    #[test]
    fn vec_and_string_with_arena() {
        let arena = MessageArena::new();

        // Multiple collections coexist in the same arena
        let mut v1 = arena.new_vec::<u32>();
        let mut v2 = arena.new_vec::<String>();
        let mut s1 = arena.new_string();

        v1.push(42);
        v2.push(String::from("hello"));
        s1.push_str("world");

        assert_eq!(v1[0], 42);
        assert_eq!(v2[0], "hello");
        assert_eq!(s1.as_str(), "world");
    }

    #[test]
    fn alloc_struct() {
        #[derive(Debug, PartialEq)]
        struct Header {
            name: &'static str,
            value: &'static str,
        }

        let arena = MessageArena::new();
        let hdr = arena.alloc(Header {
            name: "From",
            value: "test@example.com",
        });
        assert_eq!(hdr.name, "From");
        assert_eq!(hdr.value, "test@example.com");
    }

    #[test]
    fn allocated_bytes_increases_monotonically() {
        let arena = MessageArena::new();

        let mut prev = arena.allocated_bytes();
        for _ in 0..10 {
            let _ = arena.alloc([0u8; 256]);
            let current = arena.allocated_bytes();
            assert!(current >= prev);
            prev = current;
        }
    }
}
