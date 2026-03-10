//! # exim-store — Rust Memory Management Crate
//!
//! This crate replaces Exim's custom stacking memory allocator (`store.c` —
//! 1,336 lines, `store.h` — 92 lines) with Rust-native memory management
//! primitives, eliminating all manual memory management through zero-cost
//! abstractions enforced at compile time.
//!
//! It is a **foundational crate** depended upon by every other workspace member.
//! Other crates import key types directly from the crate root:
//!
//! ```rust
//! use exim_store::{MessageArena, Tainted, Clean};
//! use exim_store::{ConfigStore, ConfigBuilder, SearchCache};
//! ```
//!
//! ## Memory Model Replacement (AAP §0.4.3)
//!
//! The C codebase uses a custom stacking memory allocator (`store.c`) with five
//! named pool types, each paired with a tainted counterpart (10 pools total).
//! This crate replaces all ten pools with safe Rust types:
//!
//! | C Store Pool | Rust Replacement | Semantics |
//! |---|---|---|
//! | `POOL_MAIN` (+taint) | [`MessageArena`] (`bumpalo::Bump`) | Per-message short-lived allocations |
//! | `POOL_PERM` (+taint) | Owned `String`/`Vec`/structs | Permanent data, freed at exit |
//! | `POOL_CONFIG` (+taint) | [`ConfigStore`] (`Arc<Config>`) | Immutable config, shared across threads |
//! | `POOL_SEARCH` (+taint) | [`SearchCache`] (`HashMap`) | Lookup cache with explicit `clear()` |
//! | `POOL_MESSAGE` (+taint) | [`MessageStore`] | Medium-lifetime per-message data |
//!
//! ### Note on `POOL_PERM`
//!
//! Permanent allocations (`POOL_PERM` in C) use standard Rust `String`, `Vec`,
//! and owned structs with process lifetime.  No dedicated wrapper struct is
//! needed because Rust's ownership model handles this naturally — owned values
//! live as long as their owning scope and are freed when dropped.  This is a
//! direct consequence of Rust's RAII (Resource Acquisition Is Initialization)
//! semantics replacing the C pattern of `store_get_perm()` followed by manual
//! lifetime tracking.
//!
//! ## Taint Tracking
//!
//! The C codebase tracks taint at **runtime** by duplicating every memory pool
//! (`POOL_TAINT_MAIN`, `POOL_TAINT_PERM`, etc. — `store.h` lines 23–31) and
//! scanning pointers via `is_tainted_fn()` — an O(n) traversal of all tainted
//! pool blocks (`store.c` lines 298–325).  The `die_tainted()` function
//! terminates the process on taint mismatch (`store.c` lines 328–333).
//!
//! This crate replaces runtime taint tracking with **compile-time** enforcement
//! using [`Tainted<T>`] and [`Clean<T>`] newtype wrappers:
//!
//! - [`Tainted<T>`] wraps values from untrusted sources (SMTP input, DNS
//!   responses, file reads).  It intentionally does **not** implement `Deref`,
//!   forcing callers to explicitly handle tainted data.
//! - [`Clean<T>`] wraps validated or trusted values.  It implements
//!   `Deref<Target = T>` for transparent use in security-sensitive contexts.
//! - Conversion from [`Tainted<T>`] to [`Clean<T>`] requires explicit
//!   validation via [`Tainted::sanitize()`] or the escape-hatch
//!   [`Tainted::force_clean()`].
//! - `#[repr(transparent)]` on both types ensures **zero runtime cost** — the
//!   wrappers have identical memory layout to `T`.
//!
//! Convenience type aliases [`TaintedString`] and [`CleanString`] are provided
//! for the common case of tainted/clean owned strings.
//!
//! ## Safety
//!
//! This crate contains **no `unsafe` code**.  The `#![deny(unsafe_code)]`
//! crate-level attribute enforces this guarantee at compile time.  All `unsafe`
//! operations in the Exim Rust workspace are confined exclusively to the
//! `exim-ffi` crate (per AAP §0.7.2).

// SPDX-License-Identifier: GPL-2.0-or-later

// ---------------------------------------------------------------------------
// Crate-level attributes
// ---------------------------------------------------------------------------

// Compile-time guarantee that this crate contains zero unsafe code.
// All unsafe operations are confined to the exim-ffi crate (AAP §0.7.2).
#![deny(unsafe_code)]
// Encourage comprehensive documentation on all public items.
#![warn(missing_docs)]
// Comprehensive clippy lint enforcement for code quality.
#![deny(clippy::all)]

// ---------------------------------------------------------------------------
// Submodule declarations
// ---------------------------------------------------------------------------

/// Per-message arena allocator wrapping [`bumpalo::Bump`].
///
/// Replaces Exim's `POOL_MAIN` stacking pool (`store.c` lines 221–486) for
/// short-lived per-message allocations.  The arena is created at message start
/// and dropped at message completion, providing efficient bulk deallocation of
/// all per-message data.
///
/// Key types: [`MessageArena`], [`ArenaStats`].
pub mod arena;

/// `Arc<Config>` frozen-after-parse configuration store.
///
/// Replaces Exim's `POOL_CONFIG` (`store.c` lines 369–377) with a builder
/// pattern that mutably constructs configuration during parsing, then freezes
/// it into an immutable `Arc<T>` — replacing the C `mprotect(PROT_READ)`
/// runtime guard with compile-time immutability.
///
/// Key types: [`ConfigStore`], [`ConfigBuilder`], [`ConfigData`].
pub mod config_store;

/// HashMap-based search/lookup cache with explicit clearing.
///
/// Replaces Exim's `POOL_SEARCH` stacking pool with an O(1) `HashMap`-based
/// cache supporting explicit `clear()` for lookup tidyup, optional maximum
/// entry count with LRU-like eviction, and hit/miss statistics tracking.
///
/// Key types: [`SearchCache`], [`CacheEntry`], [`SearchCacheStats`].
pub mod search_cache;

/// Scoped per-message store for medium-lifetime data.
///
/// Replaces Exim's `POOL_MESSAGE` (`store.c` lines 1294–1317) for data that
/// persists across a single message transaction — DKIM verification state,
/// transport continuation tracking, and other per-message metadata that
/// outlives the main arena but is dropped at transaction end.
///
/// Key type: [`MessageStore`].
pub mod message_store;

/// Compile-time taint tracking newtypes.
///
/// Replaces Exim's runtime `is_tainted()` / `die_tainted()` system (`store.c`
/// lines 298–333, `store.h` lines 82–83) with zero-cost [`Tainted<T>`] and
/// [`Clean<T>`] wrappers that enforce taint boundaries at compile time.
///
/// Key types: [`Tainted`], [`Clean`], [`TaintState`], [`TaintError`],
/// [`TaintedString`], [`CleanString`].
pub mod taint;

// ---------------------------------------------------------------------------
// Key type re-exports for ergonomic crate-root imports
// ---------------------------------------------------------------------------
//
// Per AAP §0.5.2, other workspace crates use:
//   use exim_store::{MessageArena, Tainted, Clean};
//
// All re-exports below enable this pattern by surfacing the most commonly
// used types at the crate root level.

// Arena module — per-message allocator (POOL_MAIN replacement)
pub use arena::{ArenaStats, MessageArena};

// Config store module — frozen configuration (POOL_CONFIG replacement)
pub use config_store::{ConfigBuilder, ConfigData, ConfigStore};

// Search cache module — lookup cache (POOL_SEARCH replacement)
pub use search_cache::{CacheEntry, SearchCache, SearchCacheStats};

// Message store module — per-message medium-lifetime data (POOL_MESSAGE replacement)
pub use message_store::MessageStore;

// Taint module — compile-time taint tracking (replaces runtime is_tainted/die_tainted)
pub use taint::{Clean, CleanString, TaintError, TaintState, Tainted, TaintedString};
