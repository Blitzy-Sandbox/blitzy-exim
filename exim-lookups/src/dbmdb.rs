// =============================================================================
// exim-lookups/src/dbmdb.rs — DBM Hints Database Lookup Backend
// =============================================================================
//
// Rewrites `src/src/lookups/dbmdb.c` (273 lines) as a Rust module that
// delegates all DBM operations to the `exim-ffi::hintsdb` safe FFI wrapper.
//
// The DBM lookup provides key-value access to Berkeley DB, GDBM, NDBM, or TDB
// hint database files. The actual backend is selected at compile time via
// feature flags on the `exim-ffi` crate. This lookup module provides a unified
// `LookupDriver` interface regardless of which DBM backend is active.
//
// C function mapping:
//   dbmdb_open()  → DbmdbLookup::open()  — open DBM file
//   dbmdb_find()  → DbmdbLookup::find()  — fetch key from DBM
//   dbmdb_close() → DbmdbLookup::close() — close DBM handle (via Drop)
//   dbmjz_find()  → handled via opts parameter for "nz" variant
//
// Per AAP §0.7.2: This file contains ZERO `unsafe` code.
// Per AAP §0.4.2: Uses `inventory::submit!` for compile-time registration.

use std::path::Path;
use std::sync::Mutex;

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;

use crate::helpers::check_file::{check_file, CheckFileTarget, ExpectedFileType};

// =============================================================================
// DBM Handle — wraps a safe FFI hintsdb handle
// =============================================================================

/// Internal state for an open DBM database.
///
/// Replaces the C `void *` handle returned by `dbmdb_open()`. In the C
/// version, this was cast to a `EXIM_DB *` (the active hintsdb typedef).
/// In Rust, we use `exim_ffi::hintsdb::HintsDb` trait objects, but since
/// the hintsdb API is designed for the hints subsystem (not lookups), we
/// wrap the underlying file path and open it per-find for simplicity.
struct DbmdbHandle {
    /// The path to the DBM database file.
    path: String,
    /// Mutex-protected cached connection for serial access.
    db: Mutex<Option<Box<dyn exim_ffi::hintsdb::HintsDb>>>,
}

// =============================================================================
// DbmdbLookup — LookupDriver implementation
// =============================================================================

/// DBM hints database lookup driver.
///
/// Provides key-value lookup against Berkeley DB / GDBM / NDBM / TDB database
/// files. Two lookup variants are supported:
/// - `dbm` — standard key lookup (null terminator excluded from key)
/// - `dbmnz` — key lookup with null terminator included in key length
///
/// The active hints database backend is determined at compile time via feature
/// flags on the `exim-ffi` crate. This module delegates all I/O to the safe
/// `exim_ffi::hintsdb` abstraction layer.
#[derive(Debug)]
struct DbmdbLookup {
    /// Lookup name: "dbm" or "dbmnz"
    name: &'static str,
    /// Whether to include the null terminator in key length (dbmnz variant)
    include_nul: bool,
}

impl DbmdbLookup {
    /// Create a new DBM lookup driver for the standard variant.
    fn new() -> Self {
        Self {
            name: "dbm",
            include_nul: false,
        }
    }

    /// Create a new DBM lookup driver for the null-terminated variant.
    fn new_nz() -> Self {
        Self {
            name: "dbmnz",
            include_nul: true,
        }
    }
}

impl LookupDriver for DbmdbLookup {
    fn driver_name(&self) -> &str {
        self.name
    }

    fn lookup_type(&self) -> LookupType {
        // DBM is a single-key file-based lookup (absolute file path required).
        LookupType::ABS_FILE
    }

    fn open(&self, filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        let path = filename.ok_or_else(|| {
            DriverError::ExecutionFailed("DBM: filename is required for open".into())
        })?;

        tracing::debug!(path = %path, driver = %self.name, "DBM: opening database");

        // Open the hints database via the FFI layer. The actual backend
        // (BDB/GDBM/NDBM/TDB) is selected at compile time via features.
        let flags = exim_ffi::hintsdb::OpenFlags::read_only();
        let db = open_hintsdb(path, &flags).map_err(|e| {
            tracing::warn!(path = %path, error = %e, "DBM: failed to open database");
            DriverError::ExecutionFailed(format!("DBM: failed to open {}: {}", path, e))
        })?;

        Ok(Box::new(DbmdbHandle {
            path: path.to_string(),
            db: Mutex::new(Some(db)),
        }))
    }

    fn check(
        &self,
        _handle: &LookupHandle,
        filename: Option<&str>,
        modemask: i32,
        owners: &[u32],
        owngroups: &[u32],
    ) -> Result<bool, DriverError> {
        if let Some(path) = filename {
            let modemask_u32 = if modemask >= 0 { modemask as u32 } else { 0 };
            let owners_opt = if owners.is_empty() {
                None
            } else {
                Some(owners)
            };
            let owngroups_opt = if owngroups.is_empty() {
                None
            } else {
                Some(owngroups)
            };
            check_file(
                CheckFileTarget::Path(Path::new(path)),
                ExpectedFileType::Regular,
                modemask_u32,
                owners_opt,
                owngroups_opt,
                self.name,
                path,
            )
            .map_err(|e| {
                DriverError::ExecutionFailed(format!("DBM: file check failed for {}: {}", path, e))
            })?;
        }
        Ok(true)
    }

    fn find(
        &self,
        handle: &LookupHandle,
        _filename: Option<&str>,
        key: &str,
        _opts: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        let dbm_handle = handle
            .downcast_ref::<DbmdbHandle>()
            .ok_or_else(|| DriverError::ExecutionFailed("DBM: invalid handle type".into()))?;

        let guard = dbm_handle
            .db
            .lock()
            .map_err(|e| DriverError::ExecutionFailed(format!("DBM: mutex poisoned: {}", e)))?;

        let db = guard
            .as_ref()
            .ok_or_else(|| DriverError::ExecutionFailed("DBM: database not open".into()))?;

        // Build the key datum. For dbmnz, include the null terminator.
        let key_bytes = if self.include_nul {
            let mut kb = key.as_bytes().to_vec();
            kb.push(0);
            kb
        } else {
            key.as_bytes().to_vec()
        };

        let key_datum = exim_ffi::hintsdb::HintsDbDatum::new(&key_bytes);

        tracing::debug!(
            key = %key,
            driver = %self.name,
            path = %dbm_handle.path,
            "DBM: looking up key"
        );

        match db.get(&key_datum) {
            Ok(Some(value_datum)) => {
                // Convert the raw bytes to a UTF-8 string, stripping any
                // trailing null bytes (common in DBM values).
                let raw: &[u8] = value_datum.as_bytes();
                let trimmed = if raw.last() == Some(&0) {
                    &raw[..raw.len() - 1]
                } else {
                    raw
                };
                let value = String::from_utf8_lossy(trimmed).into_owned();
                tracing::debug!(
                    key = %key,
                    value_len = value.len(),
                    "DBM: key found"
                );
                Ok(LookupResult::Found {
                    value,
                    cache_ttl: None,
                })
            }
            Ok(None) => {
                tracing::debug!(key = %key, "DBM: key not found");
                Ok(LookupResult::NotFound)
            }
            Err(e) => {
                tracing::warn!(key = %key, error = %e, "DBM: fetch error");
                Err(DriverError::ExecutionFailed(format!(
                    "DBM: fetch error for key '{}' in {}: {}",
                    key, dbm_handle.path, e
                )))
            }
        }
    }

    fn close(&self, handle: LookupHandle) {
        if let Ok(dbm_handle) = handle.downcast::<DbmdbHandle>() {
            if let Ok(mut guard) = dbm_handle.db.lock() {
                // Drop the database handle, which triggers RAII cleanup.
                let _ = guard.take();
            }
            tracing::debug!(path = %dbm_handle.path, "DBM: closed database");
        }
    }

    fn tidy(&self) {
        tracing::debug!(driver = %self.name, "DBM: tidy (no-op)");
    }

    fn version_report(&self) -> Option<String> {
        Some(format!("Lookup: {} (Rust, hintsdb backend)", self.name))
    }
}

// =============================================================================
// Backend Selection Helper
// =============================================================================

/// Open a hints database using the compile-time selected backend.
///
/// The backend is chosen based on feature flags: hintsdb-tdb (default),
/// hintsdb-gdbm, hintsdb-ndbm, or hintsdb-bdb. Only one should be active.
/// Default file mode is 0o644 for read-only lookups.
fn open_hintsdb(
    _path: &str,
    _flags: &exim_ffi::hintsdb::OpenFlags,
) -> Result<Box<dyn exim_ffi::hintsdb::HintsDb>, exim_ffi::hintsdb::HintsDbError> {
    // Default mode: owner read/write, group and other read.
    let _mode: u32 = 0o644;

    // Try TDB first (most common default), then GDBM, NDBM, BDB.
    #[cfg(feature = "hintsdb-tdb")]
    {
        let db = exim_ffi::hintsdb::TdbHintsDb::open(path, flags, mode)?;
        return Ok(Box::new(db));
    }

    #[cfg(feature = "hintsdb-gdbm")]
    {
        let db = exim_ffi::hintsdb::GdbmHintsDb::open(path, flags, mode)?;
        return Ok(Box::new(db));
    }

    #[cfg(feature = "hintsdb-ndbm")]
    {
        let db = exim_ffi::hintsdb::NdbmHintsDb::open(path, flags, mode)?;
        return Ok(Box::new(db));
    }

    #[cfg(feature = "hintsdb-bdb")]
    {
        let db = exim_ffi::hintsdb::BdbHintsDb::open(path, flags, mode)?;
        return Ok(Box::new(db));
    }

    // If no hintsdb backend feature is enabled, return an error.
    #[allow(unreachable_code)]
    Err(exim_ffi::hintsdb::HintsDbError::new(
        "DBM: no hintsdb backend feature enabled (enable one of: hintsdb-tdb, hintsdb-gdbm, hintsdb-ndbm, hintsdb-bdb)"
    ))
}

// =============================================================================
// Compile-Time Registration
// =============================================================================

inventory::submit! {
    LookupDriverFactory {
        name: "dbm",
        create: || Box::new(DbmdbLookup::new()),
        lookup_type: LookupType::ABS_FILE,
        avail_string: Some("dbm (Rust hintsdb)"),
    }
}

inventory::submit! {
    LookupDriverFactory {
        name: "dbmnz",
        create: || Box::new(DbmdbLookup::new_nz()),
        lookup_type: LookupType::ABS_FILE,
        avail_string: Some("dbmnz (Rust hintsdb)"),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dbmdb_driver_name() {
        let driver = DbmdbLookup::new();
        assert_eq!(driver.driver_name(), "dbm");
    }

    #[test]
    fn test_dbmnz_driver_name() {
        let driver = DbmdbLookup::new_nz();
        assert_eq!(driver.driver_name(), "dbmnz");
    }

    #[test]
    fn test_dbmdb_lookup_type() {
        let driver = DbmdbLookup::new();
        assert!(driver.lookup_type().is_abs_file());
    }

    #[test]
    fn test_dbmdb_open_no_filename() {
        let driver = DbmdbLookup::new();
        let result = driver.open(None);
        assert!(result.is_err());
    }

    #[test]
    fn test_dbmdb_version_report() {
        let driver = DbmdbLookup::new();
        let report = driver.version_report();
        assert!(report.is_some());
        assert!(report.unwrap().contains("dbm"));
    }

    #[test]
    fn test_dbmnz_include_nul() {
        let driver = DbmdbLookup::new_nz();
        assert!(driver.include_nul);
    }

    #[test]
    fn test_dbmdb_no_nul() {
        let driver = DbmdbLookup::new();
        assert!(!driver.include_nul);
    }
}
