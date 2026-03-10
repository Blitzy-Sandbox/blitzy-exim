// exim-store/src/lib.rs — Public API for exim-store Crate
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Replaces Exim's custom stacking memory allocator (store.c / store.h) with
// Rust-native memory management primitives. This is a foundational crate
// depended upon by every other workspace member.
//
// Memory Model Replacement (AAP §0.4.3):
//
//   C Store Pool           Rust Replacement
//   ───────────────────    ──────────────────────────────────────────────────
//   POOL_MAIN (+taint)     bumpalo::Bump arena, dropped at message completion
//   POOL_PERM (+taint)     Owned String / Vec / structs with process lifetime
//   POOL_CONFIG (+taint)   Arc<Config> frozen after parse
//   POOL_SEARCH (+taint)   HashMap with explicit clear() on lookup tidyup
//   POOL_MESSAGE (+taint)  Scoped struct dropped at end of message transaction
//   Taint tracking         Tainted<T> / Clean<T> newtypes (zero runtime cost)

pub mod arena;
pub mod config_store;
pub mod message_store;
pub mod search_cache;
pub mod taint;

pub use arena::{ArenaStats, MessageArena};
pub use config_store::{ConfigBuilder, ConfigData, ConfigStore};
pub use message_store::MessageStore;
pub use search_cache::{CacheEntry, SearchCache, SearchCacheStats};
pub use taint::{Clean, CleanString, TaintError, TaintState, Tainted, TaintedString};
