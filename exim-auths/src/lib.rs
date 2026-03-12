// SPDX-License-Identifier: GPL-2.0-or-later

//! # exim-auths — Authentication Driver Implementations for Exim MTA
//!
//! This crate provides all 9 Exim SMTP authenticator driver implementations,
//! rewritten from C to Rust. Each driver implements the `AuthDriver` trait
//! from `exim-drivers` and registers via `inventory::submit!` for compile-time
//! discovery by the driver registry (replacing the C `drtables.c` linked-list
//! registration pattern).
//!
//! ## Feature Flags
//!
//! Each driver is individually feature-gated, replacing the C `AUTH_*`
//! preprocessor macros (per AAP §0.7.3). The feature flag names use hyphens
//! (Cargo convention), while the corresponding Rust module names use
//! underscores (Rust naming convention).
//!
//! | Feature | Driver | C Macro | Type |
//! |---------|--------|---------|------|
//! | `auth-cram-md5` | CRAM-MD5 HMAC challenge/response | `AUTH_CRAM_MD5` | Pure Rust |
//! | `auth-cyrus-sasl` | Cyrus SASL (via libsasl2 FFI) | `AUTH_CYRUS_SASL` | FFI |
//! | `auth-dovecot` | Dovecot socket auth protocol | `AUTH_DOVECOT` | Pure Rust |
//! | `auth-external` | SASL EXTERNAL (RFC 4422 §A) | `AUTH_EXTERNAL` | Pure Rust |
//! | `auth-gsasl` | GNU SASL / SCRAM (via libgsasl FFI) | `AUTH_GSASL` | FFI |
//! | `auth-heimdal-gssapi` | Kerberos GSSAPI (via libkrb5 FFI) | `AUTH_HEIMDAL_GSSAPI` | FFI |
//! | `auth-plaintext` | PLAIN/LOGIN mechanisms | `AUTH_PLAINTEXT` | Pure Rust |
//! | `auth-spa` | SPA/NTLM with built-in MD4/DES | `AUTH_SPA` | Pure Rust |
//! | `auth-tls` | TLS client certificate auth | `AUTH_TLS` | Pure Rust |
//!
//! **Default features:** `auth-cram-md5`, `auth-plaintext`
//!
//! ## Shared Helpers
//!
//! The [`helpers`] module is **always compiled** (not feature-gated) and
//! provides shared utility functions used across all auth driver
//! implementations:
//!
//! - [`helpers::base64_io`] — SMTP AUTH base64 challenge/response I/O
//!   (replaces `get_data.c` + `get_no64_data.c`)
//! - [`helpers::server_condition`] — Server condition authorization evaluation
//!   (replaces `check_serv_cond.c`)
//! - [`helpers::saslauthd`] — Cyrus saslauthd/pwcheck daemon integration
//!   (replaces `call_saslauthd.c` + `pwcheck.c`)
//!
//! These three helper sub-modules are re-exported at the crate root for
//! convenience.
//!
//! ## Driver Registration
//!
//! Per AAP §0.4.2, each driver uses `inventory::submit!` for compile-time
//! registration. The `inventory` crate automatically collects all submitted
//! `AuthDriverFactory` instances at link time — no explicit registration code
//! is needed in this file.
//!
//! ## Safety
//!
//! This crate contains **zero** `unsafe` code (per AAP §0.7.2). All
//! interactions with C libraries (libsasl2, libgsasl, libkrb5) are confined
//! to the `exim-ffi` crate and accessed through safe wrapper APIs.

// Enforce zero unsafe code in this crate (AAP §0.7.2).
#![deny(unsafe_code)]

// ---------------------------------------------------------------------------
// Shared helper modules — always compiled, not feature-gated.
// These provide common functionality used by all/most auth drivers.
// ---------------------------------------------------------------------------

/// Shared authentication helper functions used across multiple auth driver
/// implementations. Provides base64 I/O for SMTP AUTH exchanges, server
/// condition evaluation for authorization, and saslauthd socket integration.
///
/// This module is always compiled regardless of which auth driver features
/// are enabled, since its functionality is shared across all 9 drivers.
pub mod helpers;

// ---------------------------------------------------------------------------
// Convenience re-exports from the helpers module.
//
// These allow callers to access helper sub-modules directly from the crate
// root without navigating into the helpers module:
//
//   use exim_auths::base64_io;
//   use exim_auths::server_condition;
//   use exim_auths::saslauthd;
//
// instead of:
//
//   use exim_auths::helpers::base64_io;
//   use exim_auths::helpers::server_condition;
//   use exim_auths::helpers::saslauthd;
// ---------------------------------------------------------------------------

/// Re-export of [`helpers::base64_io`] — SMTP AUTH base64 challenge/response
/// I/O functions. Provides [`base64_io::auth_read_input`],
/// [`base64_io::auth_get_data`], [`base64_io::auth_get_no64_data`],
/// [`base64_io::auth_prompt`], [`base64_io::auth_client_item`], and the
/// [`base64_io::AuthIoResult`] enum plus flag constants
/// ([`base64_io::AUTH_ITEM_FIRST`], [`base64_io::AUTH_ITEM_LAST`],
/// [`base64_io::AUTH_ITEM_IGN64`]).
pub use helpers::base64_io;

/// Re-export of [`helpers::server_condition`] — server condition evaluation
/// for authorization. Provides [`server_condition::auth_check_serv_cond`],
/// [`server_condition::auth_check_some_cond`], and the
/// [`server_condition::AuthConditionResult`] enum.
pub use helpers::server_condition;

/// Re-export of [`helpers::saslauthd`] — Cyrus saslauthd/pwcheck daemon
/// integration. Provides [`saslauthd::auth_call_saslauthd`],
/// [`saslauthd::saslauthd_verify_password`], and the result enums
/// [`saslauthd::PwCheckResult`] and [`saslauthd::SaslauthdResult`].
pub use helpers::saslauthd;

// ---------------------------------------------------------------------------
// Feature-gated auth driver modules.
//
// Each module is conditionally compiled behind its Cargo feature flag,
// replacing the C `#ifdef AUTH_*` preprocessor conditionals (AAP §0.7.3).
//
// Feature flag names use hyphens (Cargo convention):  auth-cram-md5
// Module names use underscores (Rust convention):     cram_md5
//
// Each driver module contains:
//   - An Options struct (driver-specific configuration fields)
//   - A Driver struct implementing AuthDriver trait from exim-drivers
//   - An inventory::submit! call registering an AuthDriverFactory
// ---------------------------------------------------------------------------

/// CRAM-MD5 HMAC challenge/response authenticator driver (RFC 2195).
///
/// Pure Rust implementation using the RustCrypto `hmac` + `md-5` crates.
/// Both server-side challenge verification and client-side response
/// generation are supported.
///
/// Replaces C `src/src/auths/cram_md5.c` (383 lines) + `cram_md5.h`.
#[cfg(feature = "auth-cram-md5")]
pub mod cram_md5;

/// Cyrus SASL authenticator driver (generic, mechanism-independent).
///
/// Delegates server-side SASL authentication to the Cyrus SASL library
/// (libsasl2) via `exim-ffi`. Supports all mechanisms installed as libsasl2
/// plugins (PLAIN, LOGIN, CRAM-MD5, DIGEST-MD5, SCRAM, GSSAPI, etc.).
/// Client-side auth is a stub (not implemented in C either).
///
/// Replaces C `src/src/auths/cyrus_sasl.c` (536 lines) + `cyrus_sasl.h`.
#[cfg(feature = "auth-cyrus-sasl")]
pub mod cyrus_sasl;

/// Dovecot auth-client protocol authenticator driver.
///
/// Server-only auth that speaks Dovecot's TAB-delimited auth-client protocol
/// over a Unix domain socket, relaying SASL exchanges to the Dovecot
/// authentication daemon. Pure Rust implementation using
/// `std::os::unix::net::UnixStream`.
///
/// Replaces C `src/src/auths/dovecot.c` (581 lines) + `dovecot.h`.
#[cfg(feature = "auth-dovecot")]
pub mod dovecot;

/// SASL EXTERNAL mechanism authenticator driver (RFC 4422 Appendix A).
///
/// Server side parses the initial response into `$authN` variables, expands
/// `server_param2`/`server_param3`, and evaluates `server_condition`. Client
/// side sends `AUTH EXTERNAL` with an expanded initial response.
///
/// Replaces C `src/src/auths/external.c` (186 lines) + `external.h`.
#[cfg(feature = "auth-external")]
pub mod external;

/// GNU SASL authenticator driver (SCRAM, channel-binding, etc.).
///
/// The largest auth driver, supporting SCRAM mechanisms, channel-binding,
/// and extensive SASL configuration via libgsasl through `exim-ffi`. Both
/// server and client sides are implemented with a callback-based property
/// exchange model.
///
/// Replaces C `src/src/auths/gsasl.c` (1088 lines) + `gsasl.h`.
#[cfg(feature = "auth-gsasl")]
pub mod gsasl;

/// Heimdal GSSAPI (Kerberos) authenticator driver.
///
/// Server-side Kerberos GSSAPI authentication via Heimdal/MIT libraries
/// through `exim-ffi`. Implements multi-step token exchange with
/// security-layer negotiation.
///
/// Replaces C `src/src/auths/heimdal_gssapi.c` (640 lines) +
/// `heimdal_gssapi.h`.
#[cfg(feature = "auth-heimdal-gssapi")]
pub mod heimdal_gssapi;

/// PLAIN/LOGIN mechanism authenticator driver.
///
/// The most commonly deployed authenticator, handling both PLAIN (RFC 4616)
/// and LOGIN SASL mechanisms. Server side uses configurable prompt lists;
/// client side uses configurable send lists with `^`-to-NUL encoding for
/// PLAIN mechanism.
///
/// Replaces C `src/src/auths/plaintext.c` (208 lines) + `plaintext.h`.
#[cfg(feature = "auth-plaintext")]
pub mod plaintext;

/// SPA/NTLM authenticator driver with built-in cryptographic primitives.
///
/// Full NTLM protocol implementation with server and client sides. Uses
/// the RustCrypto `md4` and `des` crates for NTLM password hashing and
/// challenge/response computation, replacing the inline MD4/DES in
/// C `auth-spa.c`.
///
/// Replaces C `src/src/auths/spa.c` (403 lines) + `spa.h` +
/// `auth-spa.c` (1501 lines) + `auth-spa.h`.
#[cfg(feature = "auth-spa")]
pub mod spa;

/// TLS client certificate authenticator driver.
///
/// Server-only auth based on TLS client certificate parameters. The simplest
/// auth driver — expands `server_param1..3` into auth variables and
/// evaluates `server_condition`. No SMTP AUTH challenge/response exchange
/// occurs; authentication is purely based on TLS session state.
///
/// Replaces C `src/src/auths/tls.c` (122 lines) + `tls.h`.
#[cfg(feature = "auth-tls")]
pub mod tls_auth;
