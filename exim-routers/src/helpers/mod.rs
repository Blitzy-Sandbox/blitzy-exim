// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! Shared router helper functions.
//!
//! This module contains helper functions used by multiple router driver
//! implementations. These translate the `rf_*.c` helper files from the
//! C Exim source tree (`src/src/routers/rf_*.c`).
//!
//! All helpers take explicit context parameters rather than relying on
//! global state. They use `Tainted<T>`/`Clean<T>` newtypes for taint
//! tracking and `tracing` for debug logging, replacing C's
//! `DEBUG(D_route)` macro.
//!
//! # Module Mapping
//!
//! The C header `src/src/routers/rf_functions.h` declares 11 helper
//! functions. Ten of these are translated into 9 Rust modules (two
//! related UID/GID functions are combined into a single `ugid` module).
//! `rf_add_generated` is not in the AAP scope — it is used only
//! internally by `redirect.rs`.
//!
//! | C Function | Rust Module |
//! |---|---|
//! | `rf_change_domain()` | [`change_domain`] |
//! | `rf_expand_data()` | [`expand_data`] |
//! | `rf_get_errors_address()` | [`get_errors_address`] |
//! | `rf_get_munge_headers()` | [`get_munge_headers`] |
//! | `rf_get_transport()` | [`get_transport`] |
//! | `rf_get_ugid()` | [`ugid`] (combined) |
//! | `rf_set_ugid()` | [`ugid`] (combined) |
//! | `rf_lookup_hostlist()` | [`lookup_hostlist`] |
//! | `rf_queue_add()` | [`queue_add`] |
//! | `rf_self_action()` | [`self_action`] |
//!
//! # Architecture Notes
//!
//! - This module is **NOT** feature-gated — any enabled router may use
//!   any helper function.
//! - All 9 submodules are declared unconditionally (no conditional
//!   compilation for helpers).
//! - The parent `exim-routers/src/lib.rs` declares `pub mod helpers;`.
//! - All 7 router driver files (`accept.rs` through `redirect.rs`)
//!   depend on this module.
//! - Helpers use types from `exim-drivers` (router/transport config),
//!   `exim-store` (taint tracking), `exim-expand` (string expansion),
//!   and `exim-dns` (DNS resolver).
//!
//! # Safety
//!
//! This module and all submodules contain **zero `unsafe` code**
//! (per AAP §0.7.2).

// ═══════════════════════════════════════════════════════════════════════════
//  Submodule Declarations
// ═══════════════════════════════════════════════════════════════════════════

/// Domain rewriting helper for router drivers.
///
/// Translates `rf_change_domain()` from C `src/src/routers/rf_change_domain.c`.
/// Creates child addresses with a new domain, preserving propagated properties,
/// establishes parent–child linkage, and optionally rewrites message headers.
pub mod change_domain;

/// String expansion wrapper for router drivers.
///
/// Translates `rf_expand_data()` from C `src/src/routers/rf_expand_data.c`.
/// Thin wrapper around [`exim_expand::expand_string()`] that maps forced
/// failure to DECLINE and other expansion failures to DEFER with a formatted
/// error message.
pub mod expand_data;

/// Errors-to address resolution for router drivers.
///
/// Translates `rf_get_errors_address()` from C
/// `src/src/routers/rf_get_errors_address.c`. Expands and verifies the
/// router's `errors_to` setting to determine the bounce/error recipient
/// address.
pub mod get_errors_address;

/// Header add/remove processing for router drivers.
///
/// Translates `rf_get_munge_headers()` from C
/// `src/src/routers/rf_get_munge_headers.c`. Expands `headers_add`
/// (newline-separated list → header chain) and `headers_remove`
/// (colon-separated list → aggregated string) from router configuration.
pub mod get_munge_headers;

/// Transport resolution by name for router drivers.
///
/// Translates `rf_get_transport()` from C
/// `src/src/routers/rf_get_transport.c`. Resolves a transport by name (with
/// optional string expansion), validates that the name is not tainted, and
/// looks up the transport instance configuration.
pub mod get_transport;

/// Host list IP address lookup for router drivers.
///
/// Translates `rf_lookup_hostlist()` from C
/// `src/src/routers/rf_lookup_hostlist.c`. The most complex shared helper:
/// resolves IP addresses for all entries in a router's host list, handling
/// MX shorthand (`/MX`), port specifications, DNS failure policies,
/// `pass_on_timeout`, and self-reference detection.
pub mod lookup_hostlist;

/// Queue an address for local or remote transport delivery.
///
/// Translates `rf_queue_add()` from C `src/src/routers/rf_queue_add.c`.
/// After a router has made its routing decision and selected a transport,
/// this helper copies propagating data, resolves uid/gid for local
/// transports, sets up fallback hosts for remote transports, and appends
/// the address to the appropriate delivery queue.
pub mod queue_add;

/// Self-reference detection action handler for router drivers.
///
/// Translates `rf_self_action()` from C `src/src/routers/rf_self_action.c`.
/// Handles self-reference detection when a host lookup returns the local
/// machine (`HOST_FOUND_LOCAL`), dispatching on the configured `self` action
/// (freeze, defer, fail, send, reroute, pass).
pub mod self_action;

/// UID/GID resolution and assignment helpers for router drivers.
///
/// Translates both `rf_get_ugid()` from C `src/src/routers/rf_get_ugid.c`
/// and `rf_set_ugid()` from `src/src/routers/rf_set_ugid.c`. Resolves
/// uid/gid values from router configuration (fixed or expandable) and
/// copies resolved values onto address items.
pub mod ugid;

// ═══════════════════════════════════════════════════════════════════════════
//  Convenience Re-exports — Primary Public Types
// ═══════════════════════════════════════════════════════════════════════════
//
// Re-export key types at the `helpers` module level so that router
// implementations can access commonly used types without qualifying
// the full submodule path.
//
// Example: `use crate::helpers::UgidBlock;` instead of
//          `use crate::helpers::ugid::UgidBlock;`

// ── ugid module types ─────────────────────────────────────────────────────

/// Re-export [`ugid::UgidBlock`] — UID/GID configuration block for router
/// delivery.
pub use self::ugid::UgidBlock;

/// Re-export [`ugid::GetUgidError`] — error enum for UID/GID resolution
/// failures.
pub use self::ugid::GetUgidError;

// ── self_action module types ──────────────────────────────────────────────

/// Re-export [`self_action::SelfAction`] — action enum for self-reference
/// detection (Freeze/Defer/Fail/Send/Reroute/Pass).
pub use self::self_action::SelfAction;

// ── lookup_hostlist module types ──────────────────────────────────────────

/// Re-export [`lookup_hostlist::HostFindFailedPolicy`] — policy enum for
/// DNS lookup failure handling (Ignore/Decline/Defer/Fail/Freeze/Pass).
pub use self::lookup_hostlist::HostFindFailedPolicy;

/// Re-export [`lookup_hostlist::LookupHostlistError`] — error enum for
/// host list lookup failures.
pub use self::lookup_hostlist::LookupHostlistError;

/// Re-export [`lookup_hostlist::WhichLists`] — bitflag type controlling
/// DNS lookup strategy (byname/bydns/ipv4-only/ipv4-prefer).
pub use self::lookup_hostlist::WhichLists;

// ── get_munge_headers module types ────────────────────────────────────────

/// Re-export [`get_munge_headers::HeaderLine`] — a single header line to
/// be added during routing.
pub use self::get_munge_headers::HeaderLine;

/// Re-export [`get_munge_headers::MungeHeadersResult`] — combined header
/// add/remove result from router configuration expansion.
pub use self::get_munge_headers::MungeHeadersResult;

/// Re-export [`get_munge_headers::GetMungeHeadersError`] — error enum for
/// header munging expansion failures.
pub use self::get_munge_headers::GetMungeHeadersError;

// ── get_errors_address module types ───────────────────────────────────────

/// Re-export [`get_errors_address::ErrorsAddressResult`] — result enum for
/// errors-to address resolution (IgnoreErrors/Address).
pub use self::get_errors_address::ErrorsAddressResult;

/// Re-export [`get_errors_address::GetErrorsAddressError`] — error enum
/// for errors-to address expansion/verification failures.
pub use self::get_errors_address::GetErrorsAddressError;

/// Re-export [`get_errors_address::VerifyMode`] — enum for address
/// verification mode (None/Recipient/Sender/Expn).
pub use self::get_errors_address::VerifyMode;

// ── get_transport module types ────────────────────────────────────────────

/// Re-export [`get_transport::GetTransportError`] — error enum for
/// transport resolution failures (ExpansionFailed/ForcedFailure/
/// TaintedName/NotFound).
pub use self::get_transport::GetTransportError;

// ── queue_add module types ────────────────────────────────────────────────

/// Re-export [`queue_add::PasswdEntry`] — POSIX passwd entry information
/// for local delivery uid/gid/home resolution.
pub use self::queue_add::PasswdEntry;

/// Re-export [`queue_add::QueueAddError`] — error enum for queue-add
/// failures (UgidFailed/FallbackHostsExpansionFailed).
pub use self::queue_add::QueueAddError;

// ── expand_data module types ──────────────────────────────────────────────

/// Re-export [`expand_data::ExpandDataError`] — error enum for string
/// expansion failures during router option processing.
pub use self::expand_data::ExpandDataError;

// ═══════════════════════════════════════════════════════════════════════════
//  Convenience Re-exports — Primary Public Functions
// ═══════════════════════════════════════════════════════════════════════════
//
// Re-export the primary entry-point function from each submodule so that
// router implementations can call them directly from the `helpers` namespace.
//
// Example: `helpers::change_domain(...)` instead of
//          `helpers::change_domain::change_domain(...)`

/// Re-export [`change_domain::change_domain()`] — create a child address
/// with a rewritten domain.
pub use self::change_domain::change_domain;

/// Re-export [`expand_data::expand_data()`] — expand a configuration
/// string with router-specific error mapping.
pub use self::expand_data::expand_data;

/// Re-export [`get_errors_address::get_errors_address()`] — resolve the
/// errors-to address from router configuration.
pub use self::get_errors_address::get_errors_address;

/// Re-export [`get_munge_headers::get_munge_headers()`] — expand and
/// collect header add/remove directives from router configuration.
pub use self::get_munge_headers::get_munge_headers;

/// Re-export [`get_transport::get_transport()`] — resolve a transport by
/// name with taint checking.
pub use self::get_transport::get_transport;

/// Re-export [`lookup_hostlist::lookup_hostlist()`] — resolve IP addresses
/// for all hosts in a router's host list.
pub use self::lookup_hostlist::lookup_hostlist;

/// Re-export [`queue_add::queue_add()`] — queue an address for local or
/// remote transport delivery.
pub use self::queue_add::queue_add;

/// Re-export [`self_action::self_action()`] — handle self-reference
/// detection for a host that resolved to the local machine.
pub use self::self_action::self_action;
