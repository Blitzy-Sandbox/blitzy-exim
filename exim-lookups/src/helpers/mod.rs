//! Shared utility functions used across multiple lookup backends.
//!
//! This module provides helper functions factored out to avoid code duplication
//! across the 22+ lookup backend modules. It replaces the C `lf_*.c` helper
//! files from `src/src/lookups/`.
//!
//! # Helpers
//!
//! - [`check_file`] — File credential/type/mode validation
//!   (replaces `lf_check_file.c`)
//! - [`quote`] — Name=value quoting for multi-column lookup results
//!   (replaces `lf_quote.c`)
//! - [`sql_perform`] — Multi-server SQL failover loop
//!   (replaces `lf_sqlperform.c`)

pub mod check_file;
pub mod quote;
pub mod sql_perform;

// Re-export the primary function and types for convenient access.
pub use check_file::{
    check_file as check_file_fn, CheckFileError, CheckFileTarget, ExpectedFileType,
};
pub use quote::{lf_quote, lf_quote_bytes, lf_quote_to_string};
pub use sql_perform::{sql_perform as sql_perform_fn, SqlPerformError, SqlPerformResult};
