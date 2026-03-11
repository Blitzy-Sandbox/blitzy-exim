// exim-tls — TLS abstraction crate for Exim MTA
//
// This crate provides a unified TLS abstraction layer with pluggable backends
// (rustls default, openssl optional), DANE/TLSA, OCSP, SNI, client cert
// verification, and TLS session resumption.

/// TLS session resumption — session ticket management and client session cache.
/// Feature-gated behind `tls-resume` (replaces C `#ifndef DISABLE_TLS_RESUME`).
#[cfg(feature = "tls-resume")]
pub mod session_cache;
