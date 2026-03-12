//! Inbound SMTP server implementation.
//!
//! Provides the SMTP command state machine, session lifecycle management,
//! custom buffered I/O, pipelining enforcement, CHUNKING/BDAT support,
//! PRDR (feature-gated), and ATRN/ODMR extension.
//!
//! # Submodules
//!
//! - [`pipelining`] — PIPELINING support and custom buffered I/O

pub mod pipelining;
