// =============================================================================
// exim-routers/src/helpers/mod.rs — Shared Router Helper Functions
// =============================================================================
//
// This module provides shared helper functions used by all 7 router drivers.
// It translates the C `rf_*.c` files from `src/src/routers/` into Rust modules.
//
// The helpers module is NOT feature-gated because any enabled router may use
// any helper function.
//
// C source files translated:
//   rf_queue_add.c         → queue_add submodule
//   rf_self_action.c       → self_action submodule
//   rf_change_domain.c     → change_domain submodule
//   rf_expand_data.c       → expand_data submodule
//   rf_get_transport.c     → get_transport submodule
//   rf_get_errors_address.c → get_errors_address submodule
//   rf_get_munge_headers.c → get_munge_headers submodule
//   rf_lookup_hostlist.c   → lookup_hostlist submodule
//   rf_get_ugid.c + rf_set_ugid.c → ugid submodule
//
// This file contains ZERO unsafe code (per AAP §0.7.2).

/// UID/GID resolution and assignment helpers.
///
/// Translates `rf_get_ugid()` and `rf_set_ugid()` from C `src/src/routers/rf_get_ugid.c`
/// and `src/src/routers/rf_set_ugid.c`. These functions handle resolving uid/gid
/// values for router instances (from fixed config values or expandable strings)
/// and copying them onto address items for use by local transports.
pub mod ugid;

// Re-export primary types from ugid for ergonomic access by router drivers.
pub use ugid::UgidBlock;
pub use ugid::UgidError;
