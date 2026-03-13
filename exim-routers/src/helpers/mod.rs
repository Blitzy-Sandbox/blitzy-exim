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

/// Domain rewriting helper for router drivers.
///
/// Translates `rf_change_domain()` from C `src/src/routers/rf_change_domain.c`.
/// Creates child addresses with a new domain, preserving propagated properties,
/// and optionally rewrites message headers.
pub mod change_domain;

/// String expansion wrapper for router drivers.
///
/// Translates `rf_expand_data()` from C `src/src/routers/rf_expand_data.c`.
/// Thin wrapper around `expand_string()` that maps forced failure → DECLINE
/// and other expansion failures → DEFER with formatted error message.
pub mod expand_data;

/// Transport resolution by name for router drivers.
///
/// Translates `rf_get_transport()` from C `src/src/routers/rf_get_transport.c`.
/// Resolves a transport by name (with optional string expansion), validates that
/// the name is not tainted, and looks up the transport instance configuration.
pub mod get_transport;

/// Header add/remove processing for router drivers.
///
/// Translates `rf_get_munge_headers()` from C `src/src/routers/rf_get_munge_headers.c`.
/// Expands `headers_add` (newline-separated list → header chain) and
/// `headers_remove` (colon-separated list → aggregated string) from router
/// configuration. Handles forced failure (ignore) and expansion error (DEFER)
/// paths for both options.
pub mod get_munge_headers;

/// UID/GID resolution and assignment helpers.
///
/// Translates `rf_get_ugid()` and `rf_set_ugid()` from C `src/src/routers/rf_get_ugid.c`
/// and `src/src/routers/rf_set_ugid.c`. These functions handle resolving uid/gid
/// values for router instances (from fixed config values or expandable strings)
/// and copying them onto address items for use by local transports.
pub mod ugid;

/// Queue an address for local or remote transport delivery.
///
/// Translates `rf_queue_add()` from C `src/src/routers/rf_queue_add.c`.
/// After a router has made its routing decision and selected a transport,
/// this helper copies propagating data (domain/localpart expansion results),
/// resolves uid/gid for local transports, sets up fallback hosts for remote
/// transports, and appends the address to the appropriate delivery queue.
pub mod queue_add;

// Re-export the change_domain function for ergonomic access by router drivers.
pub use change_domain::change_domain;

// Re-export expand_data function and error type for ergonomic access.
pub use expand_data::expand_data;
pub use expand_data::ExpandDataError;

// Re-export get_transport function and error type for ergonomic access.
pub use get_transport::get_transport;
pub use get_transport::GetTransportError;

// Re-export get_munge_headers function and types for ergonomic access.
pub use get_munge_headers::get_munge_headers;
pub use get_munge_headers::GetMungeHeadersError;
pub use get_munge_headers::MungeHeadersResult;

/// Self-reference detection action handler for router drivers.
///
/// Translates `rf_self_action()` from C `src/src/routers/rf_self_action.c`.
/// Handles self-reference detection when a host lookup returns the local
/// machine (`HOST_FOUND_LOCAL`). Dispatches on the configured `self` action
/// (freeze, defer, fail, send, reroute, pass) and updates the address item
/// and delivery context accordingly.
pub mod self_action;

/// Errors-to address resolution for router drivers.
///
/// Translates `rf_get_errors_address()` from C `src/src/routers/rf_get_errors_address.c`.
/// Expands and verifies the router's `errors_to` setting to determine the
/// bounce/error recipient address.  Handles forced failure (ignore), empty
/// expansion (ignore errors), verify mode (skip verification), and address
/// verification (format validation) paths.
pub mod get_errors_address;

// Re-export primary types from ugid for ergonomic access by router drivers.
pub use ugid::GetUgidError;
pub use ugid::UgidBlock;

// Re-export queue_add function and types for ergonomic access.
pub use queue_add::queue_add;
pub use queue_add::PasswdEntry;
pub use queue_add::QueueAddError;

// Re-export self_action function and enum for ergonomic access by router drivers.
pub use self_action::self_action;
pub use self_action::SelfAction;

// Re-export get_errors_address function and types for ergonomic access.
pub use get_errors_address::get_errors_address;
pub use get_errors_address::ErrorsAddressResult;
pub use get_errors_address::GetErrorsAddressError;
pub use get_errors_address::VerifyMode;

/// Host list IP address lookup for router drivers.
///
/// Translates `rf_lookup_hostlist()` from C `src/src/routers/rf_lookup_hostlist.c`.
/// Resolves IP addresses for all entries in a router's host list, handling MX
/// shorthand (`/MX`), port specifications, DNS failure policies, `pass_on_timeout`,
/// and self-reference detection with `rf_self_action` dispatch.
pub mod lookup_hostlist;

// Re-export lookup_hostlist function and types for ergonomic access.
pub use lookup_hostlist::lookup_hostlist;
pub use lookup_hostlist::HostFindFailedPolicy;
pub use lookup_hostlist::LookupHostlistError;
pub use lookup_hostlist::WhichLists;
