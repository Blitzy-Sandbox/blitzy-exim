// =============================================================================
// exim-lookups/src/lmdb.rs — LMDB Key-Value Lookup Backend
// =============================================================================
//
// Rewrites `src/src/lookups/lmdb.c` (~161 lines) using the heed crate, a fully
// typed safe Rust LMDB wrapper. This module provides read-only LMDB database
// access for Exim's lookup framework.
//
// C-to-Rust Mapping:
//   lmdb_open()           → LmdbLookup::open()     — open LMDB environment
//   lmdb_find()           → LmdbLookup::find()     — begin read txn, get by key
//   lmdb_close()          → LmdbLookup::close()    — close environment (via Drop)
//   lmdb_version_report() → LmdbLookup::version_report() — LMDB version info
//   lmdb_lookup_info      → inventory::submit! registration
//   Lmdbstrct             → LmdbHandle (stores heed::Env)
//
// Key Design Decision:
//   The C code opens a long-lived read transaction in lmdb_open() and reuses it
//   for all find() calls. In Rust, we store only the Env in the handle and create
//   a fresh read-only transaction per find() call. This avoids self-referential
//   struct issues (RoTxn borrows Env) and actually provides better concurrency
//   behavior — each find() sees the latest committed state and releases its
//   read lock between operations.
//
// Safety:
//   The `unsafe` heed::EnvOpenOptions::open() call has been moved into
//   exim-ffi/src/lmdb.rs as a safe wrapper (exim_ffi::lmdb::open_env_readonly).
//   This file is now 100% safe Rust — zero `unsafe` blocks, per AAP §0.7.2.
//
// Per AAP §0.7.2: Zero `unsafe` outside exim-ffi crate.
// Per AAP §0.7.3: No tokio or async — all operations are synchronous.

use std::path::Path;

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;

// =============================================================================
// Internal Handle
// =============================================================================

/// Internal state for an open LMDB environment.
///
/// Replaces the C `Lmdbstrct` struct that stored `MDB_txn *txn` and
/// `MDB_dbi db_dbi`. In the C version, a read transaction was opened in
/// `lmdb_open()` and kept alive until `lmdb_close()`. In Rust, we store only
/// the environment handle and create per-find read-only transactions to avoid
/// self-referential struct issues (heed's `RoTxn<'a>` borrows `Env`).
///
/// The `Env` is `Send + Sync`, satisfying the `LookupHandle` requirements.
/// Dropping the `LmdbHandle` (and thus the `Env`) properly closes the LMDB
/// environment, releasing the memory map and lock file.
struct LmdbHandle {
    /// The open LMDB environment. Corresponds to `MDB_env *` in C.
    /// Opened in read-only mode with `MDB_NOSUBDIR | MDB_RDONLY`.
    env: heed::Env,
}

// =============================================================================
// LmdbLookup Driver
// =============================================================================

/// LMDB key-value lookup driver implementation.
///
/// Provides read-only access to LMDB databases for Exim's `${lookup{key}lmdb{/path}}`
/// expansion syntax. Each LMDB file is treated as a single-key, absolute-file-path
/// lookup source.
///
/// The C equivalent is `lmdb_lookup_info` registered via `lmdb_lookup_module_info`
/// in `src/src/lookups/lmdb.c`. In Rust, registration is handled by
/// `inventory::submit!` at compile time.
///
/// # Lookup Type
///
/// `lookup_absfile` (single-key, absolute file path required) — the caller
/// provides an absolute path to the LMDB file and a key to look up.
///
/// # Thread Safety
///
/// `LmdbLookup` is stateless and trivially `Send + Sync`. Per-lookup state
/// (the LMDB environment) is stored in the `LmdbHandle` returned by `open()`.
#[derive(Debug)]
pub struct LmdbLookup;

impl LookupDriver for LmdbLookup {
    /// Open an LMDB environment in read-only mode.
    ///
    /// Replaces C `lmdb_open()` which called `mdb_env_create()`, `mdb_env_open()`
    /// with `MDB_NOSUBDIR | MDB_RDONLY`, then `mdb_txn_begin()` and `mdb_open()`.
    ///
    /// In the Rust version, we only open the environment here. The transaction
    /// and database handle are created per-find() call to avoid self-referential
    /// struct issues.
    ///
    /// # Parameters
    ///
    /// - `filename`: Must be `Some(path)` containing the absolute path to the
    ///   LMDB database file. `None` is rejected since LMDB is a file-based lookup.
    ///
    /// # Errors
    ///
    /// Returns `DriverError::ExecutionFailed` if:
    /// - `filename` is `None`
    /// - The LMDB environment cannot be created or opened (file not found,
    ///   permission denied, corrupt database, etc.)
    fn open(&self, filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        let path = filename.ok_or_else(|| {
            DriverError::ExecutionFailed(
                "LMDB: filename is required for open (lookup_absfile type)".into(),
            )
        })?;

        tracing::debug!(path = %path, "LMDB: opening environment");

        // Delegate the unsafe heed::EnvOpenOptions::open() call to the
        // exim-ffi crate's safe wrapper, keeping this file 100% safe Rust
        // per AAP §0.7.2.
        let env = exim_ffi::lmdb::open_env_readonly(Path::new(path)).map_err(|e| {
            tracing::warn!(
                path = %path,
                error = %e,
                "LMDB: unable to open environment"
            );
            DriverError::ExecutionFailed(format!(
                "LMDB: Unable to open environment with {}: {}",
                path, e
            ))
        })?;

        tracing::debug!(path = %path, "LMDB: environment opened successfully");
        Ok(Box::new(LmdbHandle { env }))
    }

    /// Check file accessibility — not implemented for LMDB.
    ///
    /// The C `lmdb_lookup_info.check` function pointer is `NULL`, indicating
    /// no file checking is performed for LMDB lookups. The environment open
    /// in `open()` already validates file accessibility.
    fn check(
        &self,
        _handle: &LookupHandle,
        _filename: Option<&str>,
        _modemask: i32,
        _owners: &[u32],
        _owngroups: &[u32],
    ) -> Result<bool, DriverError> {
        Ok(true)
    }

    /// Look up a key in an open LMDB environment.
    ///
    /// Replaces C `lmdb_find()` which used the pre-opened transaction and DBI
    /// from the handle to call `mdb_get()`. In the Rust version, we:
    ///   1. Begin a new read-only transaction
    ///   2. Open the default unnamed database
    ///   3. Get the value by key
    ///   4. Transaction is automatically aborted when dropped
    ///
    /// # Parameters
    ///
    /// - `handle`: The `LmdbHandle` returned by `open()`.
    /// - `filename`: Ignored (the file was opened in `open()`).
    /// - `key_or_query`: The key to look up in the LMDB database.
    /// - `options`: Ignored (LMDB does not support lookup options).
    ///
    /// # Returns
    ///
    /// - `Ok(Found { value, cache_ttl: None })` — key found, value returned as
    ///   a UTF-8 string (with lossy conversion for non-UTF-8 data).
    /// - `Ok(NotFound)` — key not present in the database (C: `FAIL`).
    /// - `Ok(Deferred { message })` — LMDB error during lookup (C: `DEFER`).
    /// - `Err(DriverError::TempFail)` — transaction or database open failure.
    fn find(
        &self,
        handle: &LookupHandle,
        _filename: Option<&str>,
        key_or_query: &str,
        _options: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        let lmdb_handle = handle.downcast_ref::<LmdbHandle>().ok_or_else(|| {
            DriverError::ExecutionFailed("LMDB: invalid handle type — expected LmdbHandle".into())
        })?;

        tracing::debug!(key = %key_or_query, "LMDB: lookup key");

        // Begin a read-only transaction.
        // In the C code, this transaction was opened once in lmdb_open() and
        // reused. Here we create a fresh transaction per find() to avoid
        // lifetime issues and provide up-to-date snapshots.
        let rtxn = lmdb_handle.env.read_txn().map_err(|e| {
            tracing::warn!(error = %e, "LMDB: unable to start read transaction");
            DriverError::TempFail(format!("LMDB: unable to start transaction: {}", e))
        })?;

        // Open the default unnamed database (equivalent to mdb_open(txn, NULL, 0, &dbi)
        // in the C code). The type parameters <Bytes, Bytes> give us raw byte access,
        // matching the C code's MDB_val byte-level semantics.
        let db: heed::Database<heed::types::Bytes, heed::types::Bytes> = lmdb_handle
            .env
            .open_database(&rtxn, None)
            .map_err(|e| {
                tracing::warn!(error = %e, "LMDB: unable to open database");
                DriverError::TempFail(format!("LMDB: unable to open database: {}", e))
            })?
            .ok_or_else(|| {
                DriverError::ExecutionFailed("LMDB: default unnamed database not found".into())
            })?;

        // Look up the key. The key is converted from &str to &[u8] to match
        // the C code's byte-level MDB_val semantics:
        //   dbkey.mv_data = CS keystring;
        //   dbkey.mv_size = length;
        match db.get(&rtxn, key_or_query.as_bytes()) {
            Ok(Some(value_bytes)) => {
                // C: *result = string_copyn(US data.mv_data, data.mv_size);
                // We use lossy UTF-8 conversion to handle arbitrary byte data
                // stored in LMDB, matching C Exim's behavior of treating values
                // as uschar* (unsigned char strings).
                let value = String::from_utf8_lossy(value_bytes).into_owned();
                tracing::debug!(result = %value, "LMDB: lookup result");
                Ok(LookupResult::Found {
                    value,
                    cache_ttl: None,
                })
            }
            Ok(None) => {
                // C: ret == MDB_NOTFOUND → FAIL
                tracing::debug!("LMDB: lookup, no data found");
                Ok(LookupResult::NotFound)
            }
            Err(e) => {
                // C: any other mdb_get error → DEFER
                let message = format!("LMDB: lookup error: {}", e);
                tracing::debug!("{}", message);
                Ok(LookupResult::Deferred { message })
            }
        }
        // Transaction is automatically aborted when `rtxn` is dropped here,
        // equivalent to the C code's implicit cleanup path.
    }

    /// Close an open LMDB environment.
    ///
    /// Replaces C `lmdb_close()` which called `mdb_txn_abort()` and
    /// `mdb_env_close()`. In Rust, dropping the `LmdbHandle` (and its contained
    /// `heed::Env`) automatically closes the environment, releases the memory
    /// map, and removes the lock file reference.
    fn close(&self, handle: LookupHandle) {
        if handle.downcast_ref::<LmdbHandle>().is_some() {
            tracing::debug!("LMDB: closing environment");
        }
        // The handle (and contained Env) is dropped when this function returns.
        // heed::Env's Drop implementation calls mdb_env_close() automatically.
        drop(handle);
    }

    /// Tidy up all LMDB resources — no-op.
    ///
    /// The C `lmdb_lookup_info.tidy` function pointer is `NULL`. Each LMDB
    /// environment is independently managed by its handle; there are no shared
    /// global resources to clean up.
    fn tidy(&self) {
        // No global LMDB resources to tidy.
    }

    /// Quote a string for LMDB lookup — not applicable.
    ///
    /// The C `lmdb_lookup_info.quote` function pointer is `NULL`. LMDB keys
    /// are raw bytes and do not require escaping or quoting.
    fn quote(&self, _value: &str, _additional: Option<&str>) -> Option<String> {
        None
    }

    /// Report LMDB library version for `-bV` output.
    ///
    /// Replaces C `lmdb_version_report()` which reported both compile-time
    /// and runtime LMDB version strings using `MDB_VERSION_MAJOR/MINOR/PATCH`
    /// macros and `mdb_version()` respectively.
    ///
    /// With heed, `heed::version()` returns the linked LMDB library version,
    /// which serves as both compile-time and runtime version since we link
    /// against the system LMDB library.
    fn version_report(&self) -> Option<String> {
        let version_info = heed::lmdb_version();
        Some(format!(
            "Library version: LMDB: Compile: {}.{}.{}\n\
             {}Runtime: {}",
            version_info.major,
            version_info.minor,
            version_info.patch,
            "                       ",
            version_info.string,
        ))
    }

    /// Return the lookup type flags.
    ///
    /// LMDB is a single-key lookup requiring an absolute file path
    /// (`lookup_absfile` in the C code). The caller provides
    /// `${lookup{key}lmdb{/absolute/path/to/database}}`.
    fn lookup_type(&self) -> LookupType {
        LookupType::ABS_FILE
    }

    /// Return the driver name for configuration file matching.
    ///
    /// This is the name used in Exim configuration: `${lookup{key}lmdb{...}}`.
    /// Matches the C `lmdb_lookup_info.name = US"lmdb"`.
    fn driver_name(&self) -> &str {
        "lmdb"
    }
}

// =============================================================================
// Compile-Time Driver Registration
// =============================================================================

// Register the LMDB lookup driver at compile time via the `inventory` crate.
//
// Replaces the C static registration:
//   static lookup_info lmdb_lookup_info = { .name = US"lmdb", ... };
//   static lookup_info *_lookup_list[] = { &lmdb_lookup_info };
//   lookup_module_info lmdb_lookup_module_info = {
//       LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1
//   };
//
// The `inventory::submit!` macro causes this factory to be collected at link
// time, allowing the driver registry to discover it without explicit
// registration calls in `drtables.c`.
inventory::submit! {
    LookupDriverFactory {
        name: "lmdb",
        create: || Box::new(LmdbLookup),
        lookup_type: LookupType::ABS_FILE,
        avail_string: Some("lmdb (heed)"),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that LmdbLookup can be constructed and implements the expected
    /// trait methods.
    #[test]
    fn test_driver_name() {
        let driver = LmdbLookup;
        assert_eq!(driver.driver_name(), "lmdb");
    }

    /// Verify the lookup type is ABS_FILE (single-key with absolute file path).
    #[test]
    fn test_lookup_type() {
        let driver = LmdbLookup;
        let lt = driver.lookup_type();
        assert!(lt.is_abs_file());
        assert!(lt.is_single_key());
        assert!(!lt.is_query_style());
    }

    /// Verify that version_report returns a non-empty report string with
    /// expected formatting.
    #[test]
    fn test_version_report() {
        let driver = LmdbLookup;
        let report = driver.version_report();
        assert!(report.is_some());
        let report = report.expect("version report should be present");
        assert!(
            report.contains("Library version: LMDB:"),
            "version report should contain LMDB header"
        );
        assert!(
            report.contains("Compile:"),
            "version report should contain compile version"
        );
        assert!(
            report.contains("Runtime:"),
            "version report should contain runtime version"
        );
    }

    /// Verify that quote() returns None (LMDB does not need quoting).
    #[test]
    fn test_quote_returns_none() {
        let driver = LmdbLookup;
        assert!(driver.quote("test-key", None).is_none());
        assert!(driver.quote("test-key", Some("extra")).is_none());
    }

    /// Verify that tidy() does not panic (no-op).
    #[test]
    fn test_tidy_no_panic() {
        let driver = LmdbLookup;
        driver.tidy(); // Should not panic
    }

    /// Verify that check() returns Ok(true) (always passes).
    #[test]
    fn test_check_always_passes() {
        let driver = LmdbLookup;
        // Create a dummy handle (not an LmdbHandle, but check() doesn't use it)
        let handle: LookupHandle = Box::new(());
        let result = driver.check(&handle, Some("/dummy/path"), 0o022, &[], &[]);
        assert!(result.is_ok());
        assert!(result.expect("check should succeed"));
    }

    /// Verify that open() with None filename returns an error.
    #[test]
    fn test_open_requires_filename() {
        let driver = LmdbLookup;
        let result = driver.open(None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("filename is required"),
            "error should mention filename requirement: {}",
            err
        );
    }

    /// Verify that open() with a non-existent file returns an error.
    #[test]
    fn test_open_nonexistent_file() {
        let driver = LmdbLookup;
        let result = driver.open(Some("/nonexistent/path/to/lmdb.db"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("LMDB"),
            "error should reference LMDB: {}",
            err
        );
    }

    /// Verify that find() with an invalid handle returns an error.
    #[test]
    fn test_find_invalid_handle() {
        let driver = LmdbLookup;
        let handle: LookupHandle = Box::new(42_u32); // Not an LmdbHandle
        let result = driver.find(&handle, None, "test-key", None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("invalid handle type"),
            "error should mention invalid handle: {}",
            err
        );
    }

    /// Verify that close() with a non-LmdbHandle does not panic.
    #[test]
    fn test_close_non_lmdb_handle() {
        let driver = LmdbLookup;
        let handle: LookupHandle = Box::new(String::from("dummy"));
        // Should not panic even with wrong handle type
        driver.close(handle);
    }

    /// Verify that LmdbLookup implements Debug.
    #[test]
    fn test_debug_impl() {
        let driver = LmdbLookup;
        let debug_str = format!("{:?}", driver);
        assert_eq!(debug_str, "LmdbLookup");
    }
}
