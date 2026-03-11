//! Hints database FFI backend module.
//!
//! Provides safe Rust wrappers around C database libraries used for Exim's
//! persistent hints key-value storage. The hints database stores retry information,
//! callout cache, rate-limiting data, and other operational state.
//!
//! ## Backends
//!
//! Four C library backends are supported, each gated behind a Cargo feature flag:
//!
//! | Feature | Backend | Library | Lockfiles | Transactions |
//! |---------|---------|---------|-----------|-------------|
//! | `hintsdb-bdb` | Berkeley DB 3.x–5.x | `<db.h>` | Yes | No |
//! | `hintsdb-gdbm` | GNU DBM | `<gdbm.h>` | Yes | No |
//! | `hintsdb-ndbm` | New DBM | `<ndbm.h>` | Yes | No |
//! | `hintsdb-tdb` | Trivial DB | `<tdb.h>` | No | Yes |
//!
//! ## SQLite
//!
//! The SQLite hints database backend is **not** in this module. It uses the
//! pure-Rust `rusqlite` crate and lives in `exim-lookups` instead, requiring
//! no FFI bindings.
//!
//! ## Common API
//!
//! All backends implement the [`HintsDb`] trait, providing a uniform interface
//! for open/get/put/delete/scan/close operations.
//!
//! ## Replaces C Preprocessor Conditionals
//!
//! ```text
//! C Preprocessor         → Cargo Feature
//! ──────────────────────────────────────
//! USE_DB                 → hintsdb-bdb
//! USE_GDBM               → hintsdb-gdbm
//! USE_NDBM               → hintsdb-ndbm
//! USE_TDB                → hintsdb-tdb
//! ```

use std::fmt;

// =============================================================================
// Feature-gated backend modules
// =============================================================================
//
// Each backend wraps a different C database library. The module is only
// compiled when its corresponding Cargo feature is enabled, replacing the
// C preprocessor #ifdef pattern from the original Exim source.

/// Berkeley DB (BDB) hints database backend.
/// Source: src/src/hintsdb/hints_bdb.h — replaces USE_DB preprocessor conditional
#[cfg(feature = "hintsdb-bdb")]
pub mod bdb;

/// GDBM (GNU Database Manager) hints database backend.
/// Source: src/src/hintsdb/hints_gdbm.h — replaces USE_GDBM preprocessor conditional
#[cfg(feature = "hintsdb-gdbm")]
pub mod gdbm;

/// NDBM (New Database Manager) hints database backend.
/// Source: src/src/hintsdb/hints_ndbm.h — replaces USE_NDBM preprocessor conditional
#[cfg(feature = "hintsdb-ndbm")]
pub mod ndbm;

/// TDB (Trivial Database) hints database backend.
/// Source: src/src/hintsdb/hints_tdb.h — replaces USE_TDB preprocessor conditional
#[cfg(feature = "hintsdb-tdb")]
pub mod tdb;

// =============================================================================
// Feature-gated re-exports for convenience
// =============================================================================

/// Re-export Berkeley DB backend for `use exim_ffi::hintsdb::BdbHintsDb`.
#[cfg(feature = "hintsdb-bdb")]
pub use bdb::BdbHintsDb;

/// Re-export GDBM backend for `use exim_ffi::hintsdb::GdbmHintsDb`.
#[cfg(feature = "hintsdb-gdbm")]
pub use gdbm::GdbmHintsDb;

/// Re-export NDBM backend for `use exim_ffi::hintsdb::NdbmHintsDb`.
#[cfg(feature = "hintsdb-ndbm")]
pub use ndbm::NdbmHintsDb;

/// Re-export TDB backend for `use exim_ffi::hintsdb::TdbHintsDb`.
#[cfg(feature = "hintsdb-tdb")]
pub use tdb::TdbHintsDb;

// =============================================================================
// Common constants
// =============================================================================

/// Maximum record limit for hints database operations.
///
/// All backends use the same value of 150.
/// From C: `#define EXIM_DB_RLIMIT 150`
pub const EXIM_DB_RLIMIT: usize = 150;

// =============================================================================
// HintsDbError — common error type
// =============================================================================

/// Error type for hints database operations.
///
/// Used by all backend implementations to report failures from the underlying
/// C database libraries. Implements [`std::fmt::Display`] and
/// [`std::error::Error`] to integrate with Rust's error handling ecosystem.
#[derive(Debug, Clone)]
pub struct HintsDbError {
    /// Human-readable error message.
    message: String,
}

impl HintsDbError {
    /// Create a new error with the given message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }

    /// Create an error from an OS errno value.
    ///
    /// Converts the numeric errno into a human-readable message using
    /// [`std::io::Error::from_raw_os_error`], prefixed with a descriptive
    /// label for hints database context.
    pub fn from_errno(errno: i32) -> Self {
        Self {
            message: format!(
                "hints database error: {}",
                std::io::Error::from_raw_os_error(errno)
            ),
        }
    }
}

impl fmt::Display for HintsDbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for HintsDbError {}

// =============================================================================
// HintsDbDatum — common key/value datum type
// =============================================================================

/// A datum (key or value) for hints database operations.
///
/// Wraps an owned byte buffer. When reading from the database, data is copied
/// from C-allocated memory into this Rust-owned buffer, and the C memory is freed
/// immediately. When writing, the data slice is passed to the C API.
///
/// This type maps directly to the C `TDB_DATA`/`datum`/`DBT` structures used
/// by the various backends, but owns its data to prevent dangling references
/// into C library internals.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HintsDbDatum {
    data: Vec<u8>,
}

impl HintsDbDatum {
    /// Create a new datum from a byte slice (copies the bytes).
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            data: bytes.to_vec(),
        }
    }

    /// Create an empty datum with zero bytes.
    pub fn empty() -> Self {
        Self { data: Vec::new() }
    }

    /// Return the datum contents as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Return the length in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Return whether the datum is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Consume the datum and return the inner `Vec<u8>`.
    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }
}

impl From<&[u8]> for HintsDbDatum {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes)
    }
}

impl From<&str> for HintsDbDatum {
    fn from(s: &str) -> Self {
        Self::new(s.as_bytes())
    }
}

impl From<Vec<u8>> for HintsDbDatum {
    fn from(data: Vec<u8>) -> Self {
        Self { data }
    }
}

// =============================================================================
// PutResult — normalized put_no_overwrite return type
// =============================================================================

/// Result of a non-overwriting put operation.
///
/// Normalizes the backend-specific return codes into a portable enum:
///
/// - BDB: `EXIM_DBPUTB_DUP = DB_KEYEXIST` (positive value)
/// - GDBM: `EXIM_DBPUTB_DUP = 1`
/// - NDBM: `EXIM_DBPUTB_DUP = 1`
/// - TDB: `EXIM_DBPUTB_DUP = -1` (negative!)
///
/// This enum abstracts those differences away, providing a clean API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutResult {
    /// Key-value pair stored successfully.
    Ok,
    /// Key already exists (duplicate).
    Duplicate,
}

// =============================================================================
// OpenFlags — database open mode configuration
// =============================================================================

/// Open flags for hints database operations.
///
/// Maps to POSIX `O_CREAT`, `O_RDONLY`, `O_RDWR` flags used by the C backends.
/// Provides named constructors for the three common open modes.
#[derive(Debug, Clone, Copy)]
pub struct OpenFlags {
    /// Whether to create the database if it doesn't exist.
    pub create: bool,
    /// Whether to open read-only.
    pub read_only: bool,
}

impl OpenFlags {
    /// Open for reading and writing, creating if necessary.
    ///
    /// Maps to POSIX `O_RDWR | O_CREAT`.
    pub fn read_write_create() -> Self {
        Self {
            create: true,
            read_only: false,
        }
    }

    /// Open for reading only (database must exist).
    ///
    /// Maps to POSIX `O_RDONLY`.
    pub fn read_only() -> Self {
        Self {
            create: false,
            read_only: true,
        }
    }

    /// Open for reading and writing (database must exist).
    ///
    /// Maps to POSIX `O_RDWR`.
    pub fn read_write() -> Self {
        Self {
            create: false,
            read_only: false,
        }
    }
}

// =============================================================================
// HintsDb trait — core abstraction for all backends
// =============================================================================

/// Common trait for hints database backends.
///
/// Provides a uniform interface for Exim's persistent key-value hints storage.
/// Each backend (BDB, GDBM, NDBM, TDB) implements this trait, wrapping the
/// corresponding C library API.
///
/// ## Lifecycle
///
/// 1. `open()` to create a database handle (some backends start transactions here)
/// 2. `get()` / `put()` / `delete()` for CRUD operations
/// 3. `scan_first()` + `scan_next()` for sequential iteration
/// 4. `close()` to finalize (commits transactions if applicable)
///
/// ## Lockfiles vs Transactions
///
/// Most backends (BDB, GDBM, NDBM) require Exim's external lockfiles for
/// concurrency control. TDB is unique in using native transactions instead.
/// Use [`lockfile_needed`](HintsDb::lockfile_needed) to determine the
/// concurrency model for a given backend.
///
/// ## Send Bound
///
/// The `Send` bound is required because database handles may be passed across
/// fork boundaries in Exim's process model, where each child process has
/// exclusive access to its database handle.
pub trait HintsDb: Send {
    /// Whether this backend requires Exim-managed external lockfiles.
    ///
    /// Returns `true` for BDB, GDBM, NDBM.
    /// Returns `false` for TDB (uses transactions instead).
    fn lockfile_needed(&self) -> bool;

    /// Get the database type name string (e.g., `"gdbm"`, `"tdb"`, `"db (v4.1+)"`).
    fn db_type(&self) -> &'static str;

    /// Retrieve a value by key.
    ///
    /// Returns `Ok(Some(datum))` if the key exists, `Ok(None)` if not found.
    fn get(&self, key: &HintsDbDatum) -> Result<Option<HintsDbDatum>, HintsDbError>;

    /// Store a key-value pair, replacing any existing value for the key.
    fn put(&mut self, key: &HintsDbDatum, data: &HintsDbDatum) -> Result<(), HintsDbError>;

    /// Store a key-value pair only if the key does not already exist.
    ///
    /// Returns [`PutResult::Ok`] on success, [`PutResult::Duplicate`] if the
    /// key already exists.
    fn put_no_overwrite(
        &mut self,
        key: &HintsDbDatum,
        data: &HintsDbDatum,
    ) -> Result<PutResult, HintsDbError>;

    /// Delete a key-value pair by key.
    fn delete(&mut self, key: &HintsDbDatum) -> Result<(), HintsDbError>;

    /// Begin sequential scanning of all keys.
    ///
    /// Returns the first key-value pair, or `None` if the database is empty.
    fn scan_first(&mut self) -> Result<Option<(HintsDbDatum, HintsDbDatum)>, HintsDbError>;

    /// Continue sequential scanning.
    ///
    /// Returns the next key-value pair, or `None` if no more entries.
    /// Must be called after [`scan_first`](HintsDb::scan_first).
    fn scan_next(&mut self) -> Result<Option<(HintsDbDatum, HintsDbDatum)>, HintsDbError>;

    /// Close the database handle.
    ///
    /// For TDB, this commits the active transaction before closing.
    /// For other backends, this simply closes the handle.
    /// Consumes `self` to prevent use-after-close.
    fn close(self) -> Result<(), HintsDbError>;

    /// Start a transaction (TDB only).
    ///
    /// Returns `true` on success, `false` if transactions are not supported
    /// or the transaction could not be started.
    ///
    /// Default implementation returns `false` (not supported).
    fn transaction_start(&mut self) -> bool {
        false
    }

    /// Commit the current transaction (TDB only).
    ///
    /// Default implementation is a no-op for backends without transaction
    /// support.
    fn transaction_commit(&mut self) {
        // No-op for backends without transaction support
    }
}
