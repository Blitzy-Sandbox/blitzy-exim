//! Shared utility functions used across multiple lookup backends.
//!
//! This module provides common helper functions factored out to avoid code
//! duplication across the 22+ lookup backend modules in the `exim-lookups`
//! crate. It replaces the C `lf_*.c` helper files and the shared header
//! `src/src/lookups/lf_functions.h` from the original C source tree.
//!
//! # Helpers
//!
//! ## [`check_file`] — File credential and type validation
//!
//! Replaces `src/src/lookups/lf_check_file.c`. Performs `stat()`/`fstat()`-based
//! validation of file type (regular file vs directory), forbidden permission mode
//! bits, owner UID allowlists, and group GID allowlists for file-backed lookup
//! drivers. Consumed by `cdb.rs`, `lsearch.rs`, `json.rs`, `dbmdb.rs`, and
//! `dsearch.rs`.
//!
//! Key types: [`CheckFileError`] (6 error variants: `StatFailed`, `NotRegular`,
//! `NotDirectory`, `BadMode`, `BadOwner`, `BadGroup`), [`ExpectedFileType`]
//! (`Regular`/`Directory`), and [`CheckFileTarget`] (`Fd`/`Path` for stat
//! source).
//!
//! ## [`lf_quote`] — Name=value quoting for multi-column results
//!
//! Replaces `src/src/lookups/lf_quote.c`. Provides consistent `name=value`
//! formatting with automatic quoting for values containing whitespace, empty
//! values, or values starting with a double-quote character. Used by SQL lookup
//! backends (`sqlite.rs`, `mysql.rs`, `pgsql.rs`, `oracle.rs`) and `ldap.rs`
//! for multi-column result formatting. Also provides [`lf_quote_to_string`] as
//! a convenience wrapper that returns a new `String`.
//!
//! ## [`sql_perform`] — Multi-server SQL failover loop
//!
//! Replaces `src/src/lookups/lf_sqlperform.c`. Orchestrates multi-server
//! iteration with taint rejection, automatic failover on `DEFER`, hostname
//! resolution against configured server lists, and error accumulation. Used by
//! `mysql.rs`, `pgsql.rs`, `oracle.rs`, and `sqlite.rs` for multi-server query
//! execution.
//!
//! Key types: [`SqlPerformResult`] (`Found`/`NotFound`/`Deferred` callback
//! return type) and [`SqlPerformError`] (7 error variants for
//! parsing/taint/failover errors).
//!
//! # Design Principles
//!
//! - All helpers use `Tainted<T>` / `Clean<T>` from `exim-store` for
//!   compile-time taint tracking (AAP §0.4.3).
//! - Zero `unsafe` code — all system calls are made through safe Rust standard
//!   library APIs or delegated to the `exim-ffi` crate (AAP §0.7.2).
//! - Structured logging via `tracing::debug!` replaces C `DEBUG(D_lookup)`
//!   output for consistent observability across all helper functions.

// ---------------------------------------------------------------------------
// Submodule declarations
// ---------------------------------------------------------------------------

/// File credential and type validation for file-backed lookup drivers.
///
/// Replaces `src/src/lookups/lf_check_file.c`.
pub mod check_file;

/// Name=value quoting helper for multi-column lookup results.
///
/// Replaces `src/src/lookups/lf_quote.c`.
pub mod quote;

/// Multi-server SQL failover loop for SQL lookup backends.
///
/// Replaces `src/src/lookups/lf_sqlperform.c`.
pub mod sql_perform;

// ---------------------------------------------------------------------------
// Re-exports — flat access via `use crate::helpers::*`
// ---------------------------------------------------------------------------

// From check_file: primary validation function and all public types.
pub use check_file::{check_file, CheckFileError, CheckFileTarget, ExpectedFileType};

// From quote: quoting functions for multi-column result formatting.
pub use quote::{lf_quote, lf_quote_to_string};

// From sql_perform: failover function and result/error types.
pub use sql_perform::{sql_perform, SqlPerformError, SqlPerformResult};
