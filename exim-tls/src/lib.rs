#![deny(unsafe_code)]
// exim-tls — TLS abstraction crate for Exim MTA
//
// This crate provides a unified TLS abstraction layer with pluggable backends
// (rustls default, openssl optional), DANE/TLSA, OCSP, SNI, client cert
// verification, and TLS session resumption.

/// Server Name Indication (SNI) support for TLS virtual hosting.
///
/// Enables different TLS certificates, keys, and OCSP responses per server
/// name. Always compiled regardless of TLS backend selection.
pub mod sni;

/// Client certificate extraction and verification.
///
/// Implements X.509 client certificate verification for TLS connections,
/// supporting both optional and required verification modes. Always compiled
/// regardless of TLS backend selection.
pub mod client_cert;

/// DANE/TLSA Support — RFC 6698/7672 TLSA record processing and certificate
/// verification. Feature-gated behind `dane` (replaces C `#ifdef SUPPORT_DANE`).
#[cfg(feature = "dane")]
pub mod dane;

/// OCSP stapling — server-side response loading and client-side verification.
/// Feature-gated behind `ocsp` (replaces C `#ifndef DISABLE_OCSP`).
#[cfg(feature = "ocsp")]
pub mod ocsp;

/// TLS session resumption — session ticket management and client session cache.
/// Feature-gated behind `tls-resume` (replaces C `#ifndef DISABLE_TLS_RESUME`).
#[cfg(feature = "tls-resume")]
pub mod session_cache;

/// OpenSSL TLS backend — optional backend using the `openssl` 0.10.75 crate.
/// Feature-gated behind `tls-openssl` (replaces C `#ifdef USE_OPENSSL`).
#[cfg(feature = "tls-openssl")]
pub mod openssl_backend;

/// Rustls TLS backend — default backend using the `rustls` 0.23.37 crate.
/// Feature-gated behind `tls-rustls` (replaces C `#ifdef USE_GNUTLS`).
/// This is the default backend per AAP §0.4.2, providing a memory-safe TLS
/// implementation with the `ring` crypto provider.
#[cfg(feature = "tls-rustls")]
pub mod rustls_backend;
