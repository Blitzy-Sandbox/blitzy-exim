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
