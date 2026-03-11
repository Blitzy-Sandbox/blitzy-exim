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

/// TLS session resumption — session ticket management and client session cache.
/// Feature-gated behind `tls-resume` (replaces C `#ifndef DISABLE_TLS_RESUME`).
#[cfg(feature = "tls-resume")]
pub mod session_cache;
