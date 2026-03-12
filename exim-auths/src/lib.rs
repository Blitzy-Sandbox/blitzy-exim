#![deny(unsafe_code)]
// SPDX-License-Identifier: GPL-2.0-or-later
//
//! # exim-auths — Authentication Driver Implementations for Exim MTA
//!
//! This crate provides Rust implementations of all 9 Exim authenticator
//! drivers plus shared helper functions, replacing the entire `src/src/auths/`
//! directory from the C codebase.

pub mod helpers;

/// TLS client certificate authenticator driver.
/// Replaces C `src/src/auths/tls.c` + `tls.h` — server-only auth based on
/// TLS client certificate parameters.
#[cfg(feature = "auth-tls")]
pub mod tls_auth;

/// PLAIN/LOGIN mechanism authenticator driver.
/// Replaces C `src/src/auths/plaintext.c` + `plaintext.h` — the most commonly
/// deployed authenticator, handling both PLAIN (RFC 4616) and LOGIN SASL mechanisms.
#[cfg(feature = "auth-plaintext")]
pub mod plaintext;

/// SPA/NTLM authenticator driver.
/// Replaces C `src/src/auths/spa.c` + `spa.h` + `auth-spa.c` + `auth-spa.h` —
/// full NTLM protocol with built-in MD4/DES crypto.
#[cfg(feature = "auth-spa")]
pub mod spa;

/// Heimdal GSSAPI (Kerberos) authenticator driver.
/// Replaces C `src/src/auths/heimdal_gssapi.c` + `heimdal_gssapi.h` —
/// server-side Kerberos GSSAPI authentication via Heimdal/MIT libraries
/// through `exim-ffi`.
#[cfg(feature = "auth-heimdal-gssapi")]
pub mod heimdal_gssapi;

/// GNU SASL authenticator driver.
/// Replaces C `src/src/auths/gsasl.c` + `gsasl.h` — the largest auth driver,
/// supporting SCRAM mechanisms, channel-binding, and extensive SASL
/// configuration via libgsasl through `exim-ffi`.
#[cfg(feature = "auth-gsasl")]
pub mod gsasl;

/// SASL EXTERNAL mechanism authenticator driver.
/// Replaces C `src/src/auths/external.c` + `external.h` — implements
/// RFC 4422 Appendix A with both server and client sides.  Server side
/// parses initial response into $authN variables, expands server_param2/3,
/// and evaluates server_condition.  Client side sends AUTH EXTERNAL
/// with an expanded initial response.
#[cfg(feature = "auth-external")]
pub mod external;

/// Dovecot auth-client protocol authenticator driver.
/// Replaces C `src/src/auths/dovecot.c` + `dovecot.h` — server-only auth
/// that speaks Dovecot's TAB-delimited auth-client protocol over a Unix
/// domain socket, relaying SASL exchanges to the Dovecot authentication daemon.
#[cfg(feature = "auth-dovecot")]
pub mod dovecot;

/// CRAM-MD5 HMAC challenge/response authenticator driver.
/// Replaces C `src/src/auths/cram_md5.c` + `cram_md5.h` — RFC 2195 CRAM-MD5
/// authentication using HMAC-MD5 from the RustCrypto ecosystem (hmac + md-5).
/// Both server-side challenge verification and client-side response generation.
#[cfg(feature = "auth-cram-md5")]
pub mod cram_md5;

/// Cyrus SASL authenticator driver (generic, mechanism-independent).
/// Replaces C `src/src/auths/cyrus_sasl.c` + `cyrus_sasl.h` — delegates
/// server-side SASL authentication to the Cyrus SASL library (libsasl2) via
/// `exim-ffi`. Supports all mechanisms installed as libsasl2 plugins
/// (PLAIN, LOGIN, CRAM-MD5, DIGEST-MD5, SCRAM, GSSAPI, etc.).
/// Client-side auth is explicitly a stub (not implemented in C either).
#[cfg(feature = "auth-cyrus-sasl")]
pub mod cyrus_sasl;
