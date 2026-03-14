// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! # exim-routers
//!
//! Router driver implementations for the Exim Mail Transfer Agent.
//!
//! This crate provides **7 router drivers** that implement the
//! [`RouterDriver`](exim_drivers::router_driver::RouterDriver) trait
//! from [`exim-drivers`](exim_drivers).  Each router is gated behind a
//! Cargo feature flag, replacing the C preprocessor `#ifdef ROUTER_*`
//! guards that previously controlled conditional compilation in
//! `src/src/routers/`.
//!
//! ## Router Drivers
//!
//! | Router | Feature Flag | C Source | Description |
//! |--------|-------------|----------|-------------|
//! | [`AcceptRouter`] | `router-accept` | `accept.c` | Catch-all local delivery — unconditionally accepts addresses |
//! | [`DnsLookupRouter`] | `router-dnslookup` | `dnslookup.c` | DNS MX/A/AAAA/SRV routing for outbound delivery |
//! | [`IpLiteralRouter`] | `router-ipliteral` | `ipliteral.c` | IP-literal domain routing (e.g., `user@[192.168.1.1]`) |
//! | [`IpLookupRouter`] | `router-iplookup` | `iplookup.c` | External host query via UDP/TCP sockets |
//! | [`ManualRouteRouter`] | `router-manualroute` | `manualroute.c` | Administrator-defined route lists |
//! | [`QueryProgramRouter`] | `router-queryprogram` | `queryprogram.c` | External helper program routing |
//! | [`RedirectRouter`] | `router-redirect` | `redirect.c` | Alias/forward/filter/Sieve redirect routing |
//!
//! ## Architecture
//!
//! Every router implementation follows the same pattern:
//!
//! 1. **Trait implementation** — Each router struct implements the
//!    [`RouterDriver`](exim_drivers::router_driver::RouterDriver) trait,
//!    providing [`route()`](exim_drivers::router_driver::RouterDriver::route),
//!    [`tidyup()`](exim_drivers::router_driver::RouterDriver::tidyup),
//!    [`flags()`](exim_drivers::router_driver::RouterDriver::flags), and
//!    [`driver_name()`](exim_drivers::router_driver::RouterDriver::driver_name)
//!    methods.
//!
//! 2. **Compile-time registration** — Each router registers itself via
//!    [`inventory::submit!`](inventory::submit) with a
//!    [`RouterDriverFactory`](exim_drivers::router_driver::RouterDriverFactory),
//!    replacing the C `drtables.c` static registration tables.  The
//!    [`exim-config`](exim_config) crate resolves router names from
//!    configuration to registered implementations at parse time.
//!
//! 3. **Feature-gated compilation** — Each router module is conditionally
//!    compiled via `#[cfg(feature = "router-*")]` attributes, mapping
//!    directly to the C `#ifdef ROUTER_*` preprocessor conditionals.
//!    All 7 features are enabled by default.
//!
//! ## Shared Helper Functions
//!
//! The [`helpers`] module contains 9 submodules translating the C
//! `rf_*.c` shared helper files from `src/src/routers/`.  These helpers
//! are used across all router implementations and are **NOT**
//! feature-gated — any enabled router may call any helper.
//!
//! | Helper | C Origin | Purpose |
//! |--------|----------|---------|
//! | [`helpers::change_domain`] | `rf_change_domain.c` | Domain rewriting for child addresses |
//! | [`helpers::expand_data`] | `rf_expand_data.c` | Router option string expansion |
//! | [`helpers::get_errors_address`] | `rf_get_errors_address.c` | Bounce/errors-to address resolution |
//! | [`helpers::get_munge_headers`] | `rf_get_munge_headers.c` | Header add/remove processing |
//! | [`helpers::get_transport`] | `rf_get_transport.c` | Transport lookup by name |
//! | [`helpers::lookup_hostlist`] | `rf_lookup_hostlist.c` | Host list DNS resolution |
//! | [`helpers::queue_add`] | `rf_queue_add.c` | Address queueing for delivery |
//! | [`helpers::self_action`] | `rf_self_action.c` | Self-reference detection handling |
//! | [`helpers::ugid`] | `rf_get_ugid.c` + `rf_set_ugid.c` | UID/GID resolution and assignment |
//!
//! ## C Source Origin
//!
//! This crate replaces the entire `src/src/routers/` directory:
//!
//! - **7 router driver C files** (`accept.c` through `redirect.c`) →
//!   7 Rust modules
//! - **10 `rf_*.c` shared helper files** → 9 Rust helper submodules
//!   (two UID/GID helpers combined into [`helpers::ugid`])
//! - **`rf_functions.h`** — Shared helper declarations → Rust module
//!   re-exports in [`helpers`]
//! - **`routers/Makefile`** — Static library build → Cargo crate
//!   compilation
//!
//! ## Safety
//!
//! This crate contains **zero `unsafe` code** (per AAP §0.7.2).  The
//! `#![deny(unsafe_code)]` attribute is applied crate-wide to enforce
//! this invariant at compile time.

// Forbid all unsafe code in this crate — AAP §0.7.2 requires zero
// unsafe blocks outside the exim-ffi crate.
#![deny(unsafe_code)]

// ═══════════════════════════════════════════════════════════════════════════
//  Shared Helpers Module (always available — NOT feature-gated)
// ═══════════════════════════════════════════════════════════════════════════

/// Shared router helper functions, translating `rf_*.c` files from C.
///
/// This module is **NOT** feature-gated because any enabled router may
/// use any helper function.  It contains 9 submodules providing domain
/// rewriting, string expansion, transport resolution, host list lookup,
/// address queueing, self-reference handling, header manipulation,
/// errors-to address resolution, and UID/GID management.
///
/// See the [module documentation](helpers) for the full list of helper
/// functions and their C source origins.
pub mod helpers;

// ═══════════════════════════════════════════════════════════════════════════
//  Feature-Gated Router Modules
// ═══════════════════════════════════════════════════════════════════════════
//
// Each router module is conditionally compiled based on its Cargo feature
// flag.  Feature names use kebab-case and map directly to the C
// preprocessor guards:
//
//   C: #ifdef ROUTER_ACCEPT       →  Rust: #[cfg(feature = "router-accept")]
//   C: #ifdef ROUTER_DNSLOOKUP    →  Rust: #[cfg(feature = "router-dnslookup")]
//   C: #ifdef ROUTER_IPLITERAL    →  Rust: #[cfg(feature = "router-ipliteral")]
//   C: #ifdef ROUTER_IPLOOKUP     →  Rust: #[cfg(feature = "router-iplookup")]
//   C: #ifdef ROUTER_MANUALROUTE  →  Rust: #[cfg(feature = "router-manualroute")]
//   C: #ifdef ROUTER_QUERYPROGRAM →  Rust: #[cfg(feature = "router-queryprogram")]
//   C: #ifdef ROUTER_REDIRECT     →  Rust: #[cfg(feature = "router-redirect")]

/// Accept router — catch-all local delivery.
///
/// Unconditionally accepts every address presented to it and assigns the
/// configured transport for delivery.  Typically placed last in the
/// router chain to catch addresses not handled by more specific routers.
///
/// Replaces C `src/src/routers/accept.c` (~172 lines).
///
/// Gated behind the `router-accept` feature flag, replacing
/// `#ifdef ROUTER_ACCEPT`.
#[cfg(feature = "router-accept")]
pub mod accept;

/// DNS lookup router — MX/A/AAAA/SRV routing.
///
/// Performs DNS record lookups to determine the mail delivery hosts for a
/// given domain.  Supports MX preference ordering, domain widening,
/// parent domain searching, and secondary MX detection.
///
/// Replaces C `src/src/routers/dnslookup.c` (~499 lines).
///
/// Gated behind the `router-dnslookup` feature flag, replacing
/// `#ifdef ROUTER_DNSLOOKUP`.
#[cfg(feature = "router-dnslookup")]
pub mod dnslookup;

/// IP-literal domain router.
///
/// Handles addresses whose domain part is an IP address enclosed in
/// square brackets (e.g., `user@[192.168.1.1]` or `user@[IPv6:::1]`).
/// These addresses bypass DNS-based routing because the target host is
/// specified directly.
///
/// Replaces C `src/src/routers/ipliteral.c` (~231 lines).
///
/// Gated behind the `router-ipliteral` feature flag, replacing
/// `#ifdef ROUTER_IPLITERAL`.
#[cfg(feature = "router-ipliteral")]
pub mod ipliteral;

/// IP lookup router — external host query via UDP/TCP sockets.
///
/// Queries one or more external hosts via UDP or TCP to obtain routing
/// decisions.  The external host receives a query string and returns
/// routing information including a new domain, local part, and optional
/// host list.
///
/// Replaces C `src/src/routers/iplookup.c` (~447 lines).
///
/// Gated behind the `router-iplookup` feature flag, replacing
/// `#ifdef ROUTER_IPLOOKUP`.
#[cfg(feature = "router-iplookup")]
pub mod iplookup;

/// Manual route router — administrator-defined route lists.
///
/// Maps domains to specific hosts and transports via explicit routing
/// rules defined by the administrator.  Supports both `route_data`
/// (expandable string) and `route_list` (static semicolon-separated
/// items) as data sources.
///
/// Replaces C `src/src/routers/manualroute.c` (~530 lines).
///
/// Gated behind the `router-manualroute` feature flag, replacing
/// `#ifdef ROUTER_MANUALROUTE`.
#[cfg(feature = "router-manualroute")]
pub mod manualroute;

/// Query program router — external helper program routing.
///
/// Executes an external helper program via pipe to determine routing
/// decisions.  The program receives address context and writes structured
/// reply lines (ACCEPT, DECLINE, PASS, DEFER, FAIL, FREEZE) to stdout.
///
/// Replaces C `src/src/routers/queryprogram.c` (~562 lines).
///
/// Gated behind the `router-queryprogram` feature flag, replacing
/// `#ifdef ROUTER_QUERYPROGRAM`.
#[cfg(feature = "router-queryprogram")]
pub mod queryprogram;

/// Redirect router — alias/forward/filter/Sieve processing.
///
/// The most complex router in Exim.  Handles alias file lookups,
/// per-user `.forward` file processing, Exim filter language
/// interpretation, and RFC 5228 Sieve filter evaluation.  Supports
/// special delivery prefixes for file, pipe, directory, and auto-reply
/// destinations.
///
/// Replaces C `src/src/routers/redirect.c` (~817 lines).
///
/// Gated behind the `router-redirect` feature flag, replacing
/// `#ifdef ROUTER_REDIRECT`.
#[cfg(feature = "router-redirect")]
pub mod redirect;

// ═══════════════════════════════════════════════════════════════════════════
//  Public Re-exports — Router Types
// ═══════════════════════════════════════════════════════════════════════════
//
// Re-export the primary router struct from each feature-gated module at
// the crate root for ergonomic access by consumers:
//
//   use exim_routers::AcceptRouter;
//
// instead of:
//
//   use exim_routers::accept::AcceptRouter;
//
// Each re-export is gated behind the same feature flag as its source
// module, so the re-export is only available when the router is compiled.

/// Re-export [`AcceptRouter`](accept::AcceptRouter) — catch-all local
/// delivery router.
#[cfg(feature = "router-accept")]
pub use accept::AcceptRouter;

/// Re-export [`DnsLookupRouter`](dnslookup::DnsLookupRouter) — DNS
/// MX/A/AAAA/SRV routing.
#[cfg(feature = "router-dnslookup")]
pub use dnslookup::DnsLookupRouter;

/// Re-export [`IpLiteralRouter`](ipliteral::IpLiteralRouter) — IP-literal
/// domain routing.
#[cfg(feature = "router-ipliteral")]
pub use ipliteral::IpLiteralRouter;

/// Re-export [`IpLookupRouter`](iplookup::IpLookupRouter) — external host
/// query routing.
#[cfg(feature = "router-iplookup")]
pub use iplookup::IpLookupRouter;

/// Re-export [`ManualRouteRouter`](manualroute::ManualRouteRouter) —
/// administrator-defined route lists.
#[cfg(feature = "router-manualroute")]
pub use manualroute::ManualRouteRouter;

/// Re-export [`QueryProgramRouter`](queryprogram::QueryProgramRouter) —
/// external helper program routing.
#[cfg(feature = "router-queryprogram")]
pub use queryprogram::QueryProgramRouter;

/// Re-export [`RedirectRouter`](redirect::RedirectRouter) — alias/filter/
/// Sieve redirect routing.
#[cfg(feature = "router-redirect")]
pub use redirect::RedirectRouter;
