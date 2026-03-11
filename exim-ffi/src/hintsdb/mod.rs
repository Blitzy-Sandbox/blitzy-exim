//! Hints database abstraction layer for Exim.
//!
//! Provides a common [`HintsDb`] trait and supporting types that all hints
//! database backends (TDB, GDBM, NDBM, BDB) implement. This module defines
//! the portable interface used by the rest of the Exim Rust codebase to
//! interact with the persistent key-value storage used for retry hints,
//! rate-limiting state, callout cache, and other operational data.
//!
//! # Backend Selection
//!
//! Each backend is gated behind a Cargo feature flag:
//!
//! | Feature        | Backend | Transaction Support | Lockfile Needed |
//! |----------------|---------|--------------------:|:----------------|
//! | `hintsdb-tdb`  | TDB     | Yes                 | No              |
//! | `hintsdb-gdbm` | GDBM    | No                  | Yes             |
//! | `hintsdb-ndbm` | NDBM    | No                  | Yes             |
//! | `hintsdb-bdb`  | BDB     | No                  | Yes             |
//!
//! Only one backend should be enabled at a time in a production build.

use std::fmt;

// Feature-gated backend modules.
#[cfg(feature = "hintsdb-tdb")]
pub mod tdb;

#[cfg(feature = "hintsdb-gdbm")]
pub mod gdbm;

#[cfg(feature = "hintsdb-ndbm")]
pub mod ndbm;

#[cfg(feature = "hintsdb-bdb")]
pub mod bdb;

// Re-export backend structs for convenience.
#[cfg(feature = "hintsdb-tdb")]
pub use tdb::TdbHintsDb;

/// Maximum file descriptor budget for hints databases.
/// All backends use the same limit (150), matching `EXIM_DB_RLIMIT` in the
/// C source headers.
pub const EXIM_DB_RLIMIT: usize = 150;

/// Common trait for all hints database backends.
///
/// Each backend implements this trait to provide a uniform interface for
/// key-value operations, scanning, and optional transaction support.
///
/// The `Send` bound is required because database handles may be passed
/// across fork boundaries in Exim's process model.
pub trait HintsDb: Send {
    /// Whether this backend requires external lockfiles for concurrency control.
    ///
    /// Returns `false` only for TDB (which uses transactions instead).
    /// All other backends return `true`.
    fn lockfile_needed(&self) -> bool;

    /// Returns the database type identifier string (e.g., `"tdb"`, `"gdbm"`).
    fn db_type(&self) -> &'static str;

    /// Fetch a value by key.
    ///
    /// Returns `Ok(None)` if the key is not found.
    fn get(&self, key: &HintsDbDatum) -> Result<Option<HintsDbDatum>, HintsDbError>;

    /// Store a key-value pair, replacing any existing value.
    fn put(&mut self, key: &HintsDbDatum, data: &HintsDbDatum) -> Result<(), HintsDbError>;

    /// Store a key-value pair only if the key does not already exist.
    ///
    /// Returns [`PutResult::Ok`] on success, [`PutResult::Duplicate`] if
    /// the key already exists.
    fn put_no_overwrite(
        &mut self,
        key: &HintsDbDatum,
        data: &HintsDbDatum,
    ) -> Result<PutResult, HintsDbError>;

    /// Delete a key-value pair.
    fn delete(&mut self, key: &HintsDbDatum) -> Result<(), HintsDbError>;

    /// Begin scanning from the first key. Returns the first key-value pair,
    /// or `None` if the database is empty.
    fn scan_first(&mut self) -> Result<Option<(HintsDbDatum, HintsDbDatum)>, HintsDbError>;

    /// Continue scanning to the next key. Must be called after [`scan_first`].
    /// Returns `None` when iteration is exhausted.
    fn scan_next(&mut self) -> Result<Option<(HintsDbDatum, HintsDbDatum)>, HintsDbError>;

    /// Close the database handle, committing any active transaction.
    /// Consumes `self` to prevent use-after-close.
    fn close(self) -> Result<(), HintsDbError>;

    /// Start a new transaction. Returns `true` on success.
    ///
    /// Default implementation returns `false` (unsupported). Only TDB
    /// overrides this with real transaction support.
    fn transaction_start(&mut self) -> bool {
        false
    }

    /// Commit the current transaction.
    ///
    /// Default implementation is a no-op. Only TDB overrides this.
    fn transaction_commit(&mut self) {}
}

/// A datum (key or value) for hints database operations.
///
/// Wraps a `Vec<u8>` providing a byte-oriented interface that maps directly
/// to the C `TDB_DATA`/`datum`/`DBT` structures used by the various backends.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Error type for hints database operations.
#[derive(Debug)]
pub struct HintsDbError {
    /// Human-readable error message.
    message: String,
}

impl HintsDbError {
    /// Create a new error with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Create an error from an errno value.
    pub fn from_errno(errno: i32) -> Self {
        Self {
            message: format!(
                "errno {}: {}",
                errno,
                std::io::Error::from_raw_os_error(errno)
            ),
        }
    }
}

impl fmt::Display for HintsDbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HintsDbError: {}", self.message)
    }
}

impl std::error::Error for HintsDbError {}

/// Result of a `put_no_overwrite` operation.
///
/// Normalizes the backend-specific return codes into a portable enum.
/// TDB returns -1 for duplicate, GDBM/NDBM return 1, BDB returns
/// `DB_KEYEXIST`. This enum abstracts those differences away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutResult {
    /// The key-value pair was stored successfully.
    Ok,
    /// The key already existed and was NOT overwritten.
    Duplicate,
}

/// Flags controlling how a hints database is opened.
///
/// Maps to POSIX `open()` flags (`O_RDONLY`, `O_RDWR`, `O_CREAT`) used by
/// the underlying C database libraries.
#[derive(Debug, Clone)]
pub struct OpenFlags {
    /// Whether to create the database file if it does not exist.
    pub create: bool,
    /// Whether to open in read-only mode.
    pub read_only: bool,
}

impl OpenFlags {
    /// Open for reading and writing, creating the file if needed.
    pub fn read_write_create() -> Self {
        Self {
            create: true,
            read_only: false,
        }
    }

    /// Open in read-only mode.
    pub fn read_only() -> Self {
        Self {
            create: false,
            read_only: true,
        }
    }

    /// Open for reading and writing (file must exist).
    pub fn read_write() -> Self {
        Self {
            create: false,
            read_only: false,
        }
    }
}
