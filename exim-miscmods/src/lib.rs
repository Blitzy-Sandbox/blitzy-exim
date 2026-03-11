//! # exim-miscmods — Optional Policy, Authentication, and Filter Modules
//!
//! This crate provides all optional modules for the Exim Mail Transfer Agent,
//! replacing the `miscmods.a` static library from the C build system's
//! `src/src/miscmods/Makefile`. Each module is gated behind a Cargo feature flag,
//! replacing the C preprocessor conditionals (`#ifdef`/`#ifndef`) used in the
//! original `src/src/miscmods/` directory.
//!
//! ## Module Categories
//!
//! - **Mail authentication/policy**: DKIM, ARC, SPF, DMARC, DMARC-native
//! - **Filter interpreters**: Exim filter, Sieve filter (RFC 5228)
//! - **Connectivity/proxy**: HAProxy PROXY protocol, SOCKS5, XCLIENT
//! - **Authentication helpers**: PAM, RADIUS, Perl
//! - **Traffic marking**: DSCP
//!
//! ## Feature Flags
//!
//! Default features: `dkim`, `exim-filter`, `sieve-filter`.
//!
//! Feature dependencies enforce the same compile-time prerequisites as the C
//! source's `#error` guards:
//! - `arc` requires `dkim` (ARC is built atop DKIM primitives)
//! - `dmarc` requires `spf` + `dkim` (alignment checking)
//! - `dmarc-native` requires `spf` + `dkim` (alignment checking)
//! - `dmarc` and `dmarc-native` are mutually exclusive
//! - `spf-perl` requires `spf` + `perl`
//!
//! ## Driver Registration
//!
//! Each feature-gated module registers itself with the `exim-drivers` registry
//! via `inventory::submit!` in its own file. The `lib.rs` does not aggregate
//! registrations — `inventory` handles collection at link time automatically.

// Per AAP §0.7.2: zero unsafe code outside exim-ffi.
#![deny(unsafe_code)]
// Enforce documentation on all public items.
#![warn(missing_docs)]

// ============================================================================
// Mutual Exclusivity Guard
// ============================================================================
//
// The C build enforces this via `#ifdef SUPPORT_DMARC` → `#error` in
// dmarc_native.c line 12-13: "Build cannot support both libopendmarc and
// native DMARC modules". We replicate this with compile_error!.

#[cfg(all(feature = "dmarc", feature = "dmarc-native"))]
compile_error!(
    "Cannot enable both 'dmarc' (libopendmarc FFI) and 'dmarc-native' (pure Rust) \
     features simultaneously. These are mutually exclusive DMARC implementations. \
     Choose one: 'dmarc' for the libopendmarc-backed implementation, or \
     'dmarc-native' for the experimental pure-Rust parser."
);

// ============================================================================
// Feature-Gated Module Declarations
// ============================================================================
//
// Modules are organized into logical groups matching the AAP §0.4.1 ordering:
// 1. Mail authentication/policy: dkim, arc, spf, dmarc, dmarc-native
// 2. Filter interpreters: exim-filter, sieve-filter
// 3. Connectivity/proxy: proxy, socks, xclient
// 4. Auth helpers: pam, radius, perl
// 5. Traffic: dscp
//
// Feature names use hyphens in Cargo.toml but underscores in Rust module names.
// Cargo normalizes hyphens to underscores for cfg(feature = "...") checks.

// ── Mail authentication / policy modules ─────────────────────────────────────

/// DKIM (DomainKeys Identified Mail) verify/sign module with in-tree PDKIM library.
///
/// Replaces C `#ifndef DISABLE_DKIM` guard from `dkim.c` (1,837 lines).
/// Includes: DKIM verification, signing, transport integration, and the PDKIM
/// streaming parser with crypto backend abstraction.
///
/// Submodule structure: `dkim/mod.rs`, `dkim/transport.rs`,
/// `dkim/pdkim/mod.rs`, `dkim/pdkim/signing.rs`.
#[cfg(feature = "dkim")]
pub mod dkim;

/// ARC (Authenticated Received Chain) verify/sign module (RFC 8617).
///
/// Replaces C `#ifdef EXPERIMENTAL_ARC` guard from `arc.c` (2,179 lines).
/// Requires the `dkim` feature because ARC is built atop DKIM primitives
/// (arc.c line 14: `#if defined DISABLE_DKIM` → `#error`).
#[cfg(feature = "arc")]
pub mod arc;

/// SPF (Sender Policy Framework) validation module.
///
/// Replaces C `#ifdef SUPPORT_SPF` guard from `spf.c` (627 lines).
/// Uses libspf2 via `exim-ffi` for SPF record processing and DNS integration.
/// The Perl-based SPF alternative (`spf_perl.c`) is incorporated under
/// `#[cfg(all(feature = "spf", feature = "perl"))]` within this module.
#[cfg(feature = "spf")]
pub mod spf;

/// DMARC validation via libopendmarc FFI.
///
/// Replaces C `#ifdef SUPPORT_DMARC` guard from `dmarc.c` (478 lines) and
/// shared helpers from `dmarc_common.c` (531 lines).
/// Requires SPF and DKIM features for alignment checking.
/// **Mutually exclusive** with the `dmarc-native` feature.
#[cfg(feature = "dmarc")]
pub mod dmarc;

/// Native DMARC parser — experimental pure-Rust implementation.
///
/// Replaces C `#ifdef EXPERIMENTAL_DMARC_NATIVE` guard from
/// `dmarc_native.c` (686 lines) and shared helpers from `dmarc_common.c`.
/// Does not require libopendmarc; parses DMARC DNS records directly.
/// Requires SPF and DKIM features, plus PSL lookups for organizational domains.
/// **Mutually exclusive** with the `dmarc` feature.
#[cfg(feature = "dmarc-native")]
pub mod dmarc_native;

// ── Filter interpreters ──────────────────────────────────────────────────────

/// Exim legacy filter language interpreter.
///
/// Always compiled in C (no preprocessor guard); Rust feature `exim-filter`
/// defaults to ON. Interprets Exim-format `.forward` filter files for both
/// user filters and system filters.
///
/// Source: `exim_filter.c` (2,661 lines).
#[cfg(feature = "exim-filter")]
pub mod exim_filter;

/// RFC 5228 Sieve filter interpreter with extensions.
///
/// Always compiled in C (no preprocessor guard); Rust feature `sieve-filter`
/// defaults to ON. Implements Sieve mail filtering with extensions:
/// encoded-character, enotify, subaddress, vacation, regex, copy, imap4flags.
///
/// Source: `sieve_filter.c` (3,644 lines — largest module in miscmods).
#[cfg(feature = "sieve-filter")]
pub mod sieve_filter;

// ── Connectivity / proxy modules ─────────────────────────────────────────────

/// HAProxy PROXY protocol v1/v2 handler.
///
/// Replaces C `#ifdef SUPPORT_PROXY` guard from `proxy.c` (552 lines).
/// Parses proxy headers to extract real client IP addresses and ports.
/// Supports both v1 text format and v2 binary format.
#[cfg(feature = "proxy")]
pub mod proxy;

/// SOCKS5 client connector (RFC 1928/1929).
///
/// Replaces C `#ifdef SUPPORT_SOCKS` guard from `socks.c` (425 lines).
/// Routes outbound SMTP connections through SOCKS5 proxies with support
/// for username/password authentication per RFC 1929.
#[cfg(feature = "socks")]
pub mod socks;

/// Postfix XCLIENT SMTP extension handler.
///
/// Replaces C `#ifdef EXPERIMENTAL_XCLIENT` guard from `xclient.c` (356 lines).
/// Accepts proxy-provided connection information (IP, hostname, port, login)
/// from trusted proxies. Implements XCLIENT V2 protocol.
#[cfg(feature = "xclient")]
pub mod xclient;

// ── Auth helper modules ──────────────────────────────────────────────────────

/// PAM (Pluggable Authentication Modules) authentication.
///
/// Replaces C `#ifdef SUPPORT_PAM` guard from `pam.c` (224 lines).
/// Uses libpam via `exim-ffi` for system authentication with PAM conversation
/// callback support.
#[cfg(feature = "pam")]
pub mod pam;

/// RADIUS authentication.
///
/// Replaces C `RADIUS_CONFIG_FILE` guard from `radius.c` (243 lines).
/// Uses libradius/radiusclient via `exim-ffi`. Supports both `radlib` and
/// `radiusclient` library variants.
#[cfg(feature = "radius")]
pub mod radius;

/// Embedded Perl interpreter.
///
/// Replaces C `EXIM_PERL` guard from `perl.c` (345 lines).
/// Provides `${perl{...}}` expansion and `perl_startup` configuration.
/// Uses libperl via `exim-ffi` for safe Perl embedding.
#[cfg(feature = "perl")]
pub mod perl;

// ── Traffic marking ──────────────────────────────────────────────────────────

/// DSCP (Differentiated Services Code Point) traffic marking.
///
/// Replaces C `#ifdef SUPPORT_DSCP` guard from `dscp.c` (278 lines).
/// Applies DSCP tags to inbound ACL and outbound transport sockets via
/// `setsockopt()` with `IP_TOS`/`IPV6_TCLASS`.
#[cfg(feature = "dscp")]
pub mod dscp;

// ============================================================================
// Convenience Re-exports
// ============================================================================
//
// Re-export primary public API types and functions from each module at the
// crate root for ergonomic access. Only key types are re-exported; internal
// implementation details remain accessible only through the module path.

// ── DKIM re-exports ──────────────────────────────────────────────────────────

#[cfg(feature = "dkim")]
pub use dkim::{
    acl_entry, authres_dkim, dkim_sign, expand_query, query_dns_txt, set_var, sign_init,
    smtp_reset, verify_feed, verify_finish, verify_init, verify_log_all, verify_pause, DkimError,
    DkimQueryCode, DkimState,
};

// ── ARC re-exports ───────────────────────────────────────────────────────────

#[cfg(feature = "arc")]
pub use arc::{
    arc_header_feed, arc_set_info, arc_sign, arc_sign_init, arc_verify, ArcCV, ArcError, ArcLine,
    ArcSet, ArcSignOptions, ArcState,
};

// ── SPF re-exports ───────────────────────────────────────────────────────────

#[cfg(feature = "spf")]
pub use spf::{
    spf_close, spf_conn_init, spf_find, spf_process, spf_reset, spf_version_report, SpfError,
    SpfResult, SpfState,
};

// ── DMARC re-exports ─────────────────────────────────────────────────────────

#[cfg(feature = "dmarc")]
pub use dmarc::{
    dmarc_init, dmarc_msg_init, dmarc_process, dmarc_result_inlist, DmarcAlignment, DmarcError,
    DmarcPolicy, DmarcState,
};

// ── DMARC-native re-exports ──────────────────────────────────────────────────
// Note: dmarc and dmarc-native are mutually exclusive (enforced by compile_error!
// above), so re-exporting types with the same base names is safe. However, we
// use distinct aliases to make crate-root usage unambiguous if a consumer
// references both via module paths.

#[cfg(feature = "dmarc-native")]
pub use dmarc_native::{
    dmarc_process as dmarc_native_process, dmarc_result_inlist as dmarc_native_result_inlist,
    DmarcAlignment as DmarcNativeAlignment, DmarcError as DmarcNativeError,
    DmarcPolicy as DmarcNativePolicy, DmarcRecord,
};

// ── Exim filter re-exports ───────────────────────────────────────────────────

#[cfg(feature = "exim-filter")]
pub use exim_filter::{
    exim_interpret, is_personal_filter, FilterCommand, FilterError, FilterOptions, FilterResult,
};

// ── Sieve filter re-exports ─────────────────────────────────────────────────

#[cfg(feature = "sieve-filter")]
pub use sieve_filter::{
    sieve_extensions, sieve_interpret, Comparator, MatchType, SieveCapabilities, SieveCommand,
    SieveError, SieveResult, SieveTest,
};

// ── Proxy re-exports ─────────────────────────────────────────────────────────

#[cfg(feature = "proxy")]
pub use proxy::{proxy_protocol_host, proxy_protocol_start, ProxyError, ProxyResult, ProxyVersion};

// ── SOCKS re-exports ─────────────────────────────────────────────────────────

#[cfg(feature = "socks")]
pub use socks::{socks_connect, SocksAuth, SocksError, SocksProxy};

// ── XCLIENT re-exports ───────────────────────────────────────────────────────

#[cfg(feature = "xclient")]
pub use xclient::{
    xclient_advertise, xclient_start, XclientCapabilities, XclientCommand, XclientError,
    XclientResponse,
};

// ── PAM re-exports ───────────────────────────────────────────────────────────

#[cfg(feature = "pam")]
pub use pam::{pam_auth_call, PamAuthenticator, PamError};

// ── RADIUS re-exports ────────────────────────────────────────────────────────

#[cfg(feature = "radius")]
pub use radius::{radius_auth_call, RadiusError};

// ── Perl re-exports ──────────────────────────────────────────────────────────

#[cfg(feature = "perl")]
pub use perl::{perl_addblock, perl_cat, perl_startup, PerlError, PerlInterpreter};

// ── DSCP re-exports ──────────────────────────────────────────────────────────

#[cfg(feature = "dscp")]
pub use dscp::{dscp_keywords, dscp_lookup, dscp_set, DscpConfig, DscpError};

// ============================================================================
// Unified Error Type
// ============================================================================

/// Unified error type for all miscellaneous modules.
///
/// Wraps per-module error types into a single enum, enabling callers to use
/// `MiscModError` as a generic error type when working with multiple modules.
/// Each variant is feature-gated to match its module's availability.
///
/// Uses `#[from]` for ergonomic conversion from per-module errors via the
/// `?` operator. When no features are enabled, `MiscModError` is an
/// uninhabited enum that can never be constructed.
///
/// # Examples
///
/// ```rust,ignore
/// use exim_miscmods::MiscModError;
///
/// fn handle_mail_auth() -> Result<(), MiscModError> {
///     // Per-module errors automatically convert via From/Into:
///     #[cfg(feature = "dkim")]
///     {
///         let state = exim_miscmods::dkim::verify_init()?;
///         // DkimError → MiscModError::Dkim automatically
///     }
///     Ok(())
/// }
/// ```
#[derive(Debug, thiserror::Error)]
pub enum MiscModError {
    /// DKIM verification or signing error.
    #[cfg(feature = "dkim")]
    #[error("DKIM error: {0}")]
    Dkim(#[from] dkim::DkimError),

    /// ARC chain verification or signing error.
    #[cfg(feature = "arc")]
    #[error("ARC error: {0}")]
    Arc(#[from] arc::ArcError),

    /// SPF validation error.
    #[cfg(feature = "spf")]
    #[error("SPF error: {0}")]
    Spf(#[from] spf::SpfError),

    /// DMARC (libopendmarc) validation error.
    #[cfg(feature = "dmarc")]
    #[error("DMARC error: {0}")]
    Dmarc(#[from] dmarc::DmarcError),

    /// DMARC native parser error.
    #[cfg(feature = "dmarc-native")]
    #[error("DMARC native error: {0}")]
    DmarcNative(#[from] dmarc_native::DmarcError),

    /// Exim filter interpreter error.
    #[cfg(feature = "exim-filter")]
    #[error("Exim filter error: {0}")]
    EximFilter(#[from] exim_filter::FilterError),

    /// Sieve filter interpreter error.
    #[cfg(feature = "sieve-filter")]
    #[error("Sieve filter error: {0}")]
    SieveFilter(#[from] sieve_filter::SieveError),

    /// HAProxy PROXY protocol error.
    #[cfg(feature = "proxy")]
    #[error("Proxy protocol error: {0}")]
    Proxy(#[from] proxy::ProxyError),

    /// SOCKS5 client error.
    #[cfg(feature = "socks")]
    #[error("SOCKS error: {0}")]
    Socks(#[from] socks::SocksError),

    /// XCLIENT protocol error.
    #[cfg(feature = "xclient")]
    #[error("XCLIENT error: {0}")]
    Xclient(#[from] xclient::XclientError),

    /// PAM authentication error.
    #[cfg(feature = "pam")]
    #[error("PAM error: {0}")]
    Pam(#[from] pam::PamError),

    /// RADIUS authentication error.
    #[cfg(feature = "radius")]
    #[error("RADIUS error: {0}")]
    Radius(#[from] radius::RadiusError),

    /// Embedded Perl interpreter error.
    #[cfg(feature = "perl")]
    #[error("Perl error: {0}")]
    Perl(#[from] perl::PerlError),

    /// DSCP traffic marking error.
    #[cfg(feature = "dscp")]
    #[error("DSCP error: {0}")]
    Dscp(#[from] dscp::DscpError),
}
