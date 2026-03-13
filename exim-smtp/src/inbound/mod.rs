//! Inbound SMTP server implementation.
//!
//! Provides the SMTP command state machine, session lifecycle management,
//! custom buffered I/O, pipelining enforcement, CHUNKING/BDAT support,
//! PRDR (feature-gated), and ATRN/ODMR extension.
//!
//! # Submodules
//!
//! - [`pipelining`] — PIPELINING support and custom buffered I/O
//! - [`chunking`] — CHUNKING/BDAT support (RFC 3030)
//! - [`prdr`] — Per-Recipient Data Response (feature-gated behind `prdr`)

pub mod chunking;
pub mod command_loop;
pub mod pipelining;

/// Per-Recipient Data Response (PRDR) support.
///
/// Feature-gated behind the `prdr` Cargo feature flag, replacing the C
/// `#ifndef DISABLE_PRDR` preprocessor conditional from `smtp_in.c`.
/// When the `prdr` feature is disabled, this module is not compiled.
#[cfg(feature = "prdr")]
pub mod prdr;
