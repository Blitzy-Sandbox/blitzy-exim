#![deny(unsafe_code)]
// =============================================================================
// exim-routers — Router Driver Implementations for Exim MTA
// =============================================================================
//
// This crate provides 7 router drivers that implement the `RouterDriver` trait
// from `exim-drivers`. Each router is gated behind a Cargo feature flag,
// replacing the C preprocessor `#ifdef ROUTER_*` guards.
//
// Routers (feature-gated, created by respective implementation agents):
//   - accept        — Catch-all local delivery router
//   - dnslookup     — DNS MX/A/AAAA/SRV routing
//   - ipliteral     — IP-literal domain routing
//   - iplookup      — External host query via UDP/TCP sockets
//   - manualroute   — Administrator-defined route lists
//   - queryprogram  — External helper program routing
//   - redirect      — Alias/filter/Sieve redirect routing
//
// Shared helpers (always available, not feature-gated) translate the C rf_*.c
// helper functions used across all router implementations.
//
// Source: src/src/routers/ (7 .c drivers + 10 rf_*.c helpers + 8 .h headers)
// This crate contains ZERO unsafe code (per AAP §0.7.2).

// ── Shared helpers module (always available) ────────────────────────────────

/// Shared router helper functions, translating `rf_*.c` files from C.
/// These are used across all router implementations and are NOT feature-gated.
pub mod helpers;

// ── Feature-gated router modules ────────────────────────────────────────────

#[cfg(feature = "router-queryprogram")]
pub mod queryprogram;

#[cfg(feature = "router-redirect")]
pub mod redirect;
