// =============================================================================
// exim-lookups/src/sqlite.rs — SQLite Lookup via rusqlite
// =============================================================================
//
// Rewrites `src/src/lookups/sqlite.c` (209 lines) using the `rusqlite` crate.
//
// This module implements the `LookupDriver` trait for SQLite databases. It
// supports both absolute-file and query-style lookups (the query contains the
// database path followed by SQL). This corresponds to the C `lookup_absfilequery`
// type flag.
//
// C API Mapping:
//   - `sqlite_open()`           → `SqliteLookup::open()`
//   - `sqlite_find()`           → `SqliteLookup::find()`
//   - `sqlite_close()`          → `SqliteLookup::close()`
//   - `sqlite_quote()`          → `SqliteLookup::quote()`
//   - `sqlite_version_report()` → `SqliteLookup::version_report()`
//   - `sqlite_callback()`       → Inlined as closure in `find()`
//   - Module registration       → `inventory::submit!`
//
// Security:
//   - Absolute path enforcement (rejects relative paths — C lines 36-37)
//   - SQL quoting via single-quote doubling (C lines 138-159)
//   - Busy timeout to handle database lock contention (C line 47)
//
// Per AAP §0.7.2: This file contains ZERO `unsafe` code.
// Per AAP §0.6.1: Uses rusqlite 0.38.0.

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;

use crate::helpers::quote::lf_quote;

use rusqlite::{Connection, OpenFlags};
use std::sync::Mutex;
use std::time::Duration;
use tracing::{debug, warn};

// =============================================================================
// Constants
// =============================================================================

/// Default busy timeout in seconds when a SQLite database is locked.
///
/// Replaces C `sqlite_lock_timeout` static variable (default value 5 seconds).
/// The C code multiplies by 1000 to convert to milliseconds for
/// `sqlite3_busy_timeout()`. We store in seconds and convert at use site.
const DEFAULT_LOCK_TIMEOUT_SECS: u32 = 5;

// =============================================================================
// SqliteHandle — Send+Sync Wrapper for rusqlite::Connection
// =============================================================================

/// Wrapper around `rusqlite::Connection` that satisfies `Send + Sync` via
/// `Mutex`. This is required because `LookupHandle` is
/// `Box<dyn Any + Send + Sync>` but `rusqlite::Connection` only implements
/// `Send` (not `Sync`, due to internal `RefCell` for statement cache).
///
/// Since Exim's fork-per-connection model means each connection is used by
/// a single thread at a time, the `Mutex` contention is zero in practice.
#[derive(Debug)]
struct SqliteHandle {
    conn: Mutex<Connection>,
}

impl SqliteHandle {
    /// Wrap a `rusqlite::Connection` in a thread-safe handle.
    fn new(conn: Connection) -> Self {
        SqliteHandle {
            conn: Mutex::new(conn),
        }
    }

    /// Lock and access the inner connection.
    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

// =============================================================================
// SqliteLookup — Driver Implementation
// =============================================================================

/// SQLite lookup driver implementing `LookupDriver`.
///
/// Replaces the C `sqlite_lookup_info` registration and associated function
/// pointers from `src/src/lookups/sqlite.c`. Each `open()` call creates a
/// `rusqlite::Connection` stored inside a `LookupHandle` (boxed `dyn Any`).
///
/// # Query Format
///
/// For query-style usage, the query string is pure SQL executed against the
/// already-opened database connection. The database file path is provided
/// at `open()` time.
///
/// # Result Formatting
///
/// - **Single column**: The raw value is returned directly.
/// - **Multiple columns**: Each column is formatted as `name=value ` using
///   `lf_quote()`, matching the C `sqlite_callback()` behavior at lines 68-79.
/// - **Multiple rows**: Rows are joined with newline characters, matching the
///   C behavior at lines 65-66.
/// - **NULL values**: Replaced with `<NULL>` string, matching C lines 73 and 79.
#[derive(Debug)]
pub struct SqliteLookup;

impl Default for SqliteLookup {
    fn default() -> Self {
        Self::new()
    }
}

impl SqliteLookup {
    /// Create a new `SqliteLookup` instance.
    ///
    /// The driver is stateless between calls — all connection state is stored
    /// in the `LookupHandle` returned by `open()`.
    pub fn new() -> Self {
        SqliteLookup
    }

    /// Downcast a `LookupHandle` to the inner `SqliteHandle`.
    ///
    /// Used by `find()` to extract the `SqliteHandle` wrapper from the
    /// opaque boxed trait object.
    fn get_handle(handle: &LookupHandle) -> Result<&SqliteHandle, DriverError> {
        handle.downcast_ref::<SqliteHandle>().ok_or_else(|| {
            DriverError::ExecutionFailed(
                "sqlite: invalid handle type — expected SqliteHandle".into(),
            )
        })
    }
}

impl LookupDriver for SqliteLookup {
    /// Open a SQLite database file.
    ///
    /// Replaces C `sqlite_open()` (lines 25-49). Enforces absolute path
    /// requirement for security (C lines 36-37), opens the database via
    /// `rusqlite::Connection::open_with_flags()`, and sets the busy timeout.
    ///
    /// # Parameters
    ///
    /// - `filename`: The absolute path to the SQLite database file. `None` or
    ///   relative paths are rejected with a `DriverError::ConfigError`.
    ///
    /// # Returns
    ///
    /// A `LookupHandle` wrapping the `rusqlite::Connection` on success.
    fn open(&self, filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        let path = match filename {
            Some(p) if !p.is_empty() => p,
            _ => {
                warn!("sqlite: no filename provided for open");
                return Err(DriverError::ConfigError(
                    "absolute file name expected for \"sqlite\" lookup".into(),
                ));
            }
        };

        // Security: enforce absolute path (C line 36: *filename != '/')
        if !path.starts_with('/') {
            warn!(path = %path, "sqlite: rejecting relative path");
            return Err(DriverError::ConfigError(
                "absolute file name expected for \"sqlite\" lookup".into(),
            ));
        }

        debug!(path = %path, "sqlite: opening database");

        // Open with read-write and create flags, matching C sqlite3_open()
        // default behavior. The flags also enable URI filenames for
        // compatibility with configurations that use URI-style paths.
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(|e| {
            let msg = format!("sqlite: failed to open database '{}': {}", path, e);
            debug!("{}", msg);
            DriverError::InitFailed(msg)
        })?;

        // Set busy timeout (C line 47: sqlite3_busy_timeout(db, 1000 * sqlite_lock_timeout))
        let timeout_ms = DEFAULT_LOCK_TIMEOUT_SECS * 1000;
        conn.busy_timeout(Duration::from_millis(u64::from(timeout_ms)))
            .map_err(|e| {
                DriverError::InitFailed(format!("sqlite: failed to set busy timeout: {}", e))
            })?;

        debug!(
            timeout_secs = DEFAULT_LOCK_TIMEOUT_SECS,
            "sqlite: busy timeout configured"
        );

        Ok(Box::new(SqliteHandle::new(conn)))
    }

    /// Check a SQLite file for validity.
    ///
    /// The C implementation has `check = NULL` (line 192), meaning no check
    /// is performed. This implementation returns `Ok(true)` unconditionally.
    fn check(
        &self,
        _handle: &LookupHandle,
        _filename: Option<&str>,
        _modemask: i32,
        _owners: &[u32],
        _owngroups: &[u32],
    ) -> Result<bool, DriverError> {
        // C sqlite.c line 192: .check = NULL — no check function
        Ok(true)
    }

    /// Execute a SQL query against the open SQLite database.
    ///
    /// Replaces C `sqlite_find()` (lines 87-106) and the `sqlite_callback()`
    /// function (lines 58-84). The query is executed via
    /// `Connection::prepare()` + `Statement::query_map()`, replacing the
    /// C `sqlite3_exec()` callback pattern.
    ///
    /// # Result Formatting
    ///
    /// Multi-column results use `lf_quote()` for `name=value` formatting.
    /// Single-column results return the raw value. Multiple rows are joined
    /// with newlines. NULL values are rendered as `<NULL>`.
    ///
    /// # Cache Behavior
    ///
    /// If the query returns no rows, the result has `cache_ttl = Some(0)`
    /// to disable caching (matching C line 102: `*do_cache = 0`).
    fn find(
        &self,
        handle: &LookupHandle,
        _filename: Option<&str>,
        key_or_query: &str,
        _options: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        let sqlite_handle = Self::get_handle(handle)?;
        let conn = sqlite_handle.lock();

        debug!(query = %key_or_query, "sqlite: executing query");

        // Prepare the SQL statement (replaces C sqlite3_exec at line 95)
        let mut stmt = conn.prepare(key_or_query).map_err(|e| {
            let msg = format!("sqlite: prepare failed: {}", e);
            debug!("{}", msg);
            DriverError::ExecutionFailed(msg)
        })?;

        // Get column names before executing (needed for multi-column formatting)
        let column_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let column_count = column_names.len();

        // Execute query and collect results (replaces C sqlite_callback pattern)
        let rows_result = stmt.query_map([], |row| {
            // Build a vector of (column_name, value_string) pairs for this row
            let mut values: Vec<(String, String)> = Vec::with_capacity(column_count);
            for (i, col_name) in column_names.iter().enumerate() {
                // Get the value as a string, handling NULL → "<NULL>"
                // (C lines 73, 79: argv[i] ? argv[i] : "<NULL>")
                let val: String = match row.get::<_, Option<String>>(i) {
                    Ok(Some(v)) => v,
                    Ok(None) => "<NULL>".to_string(),
                    Err(_) => {
                        // For non-text types, attempt raw value extraction
                        // and fall back to <NULL> on failure
                        match row.get::<_, Option<Vec<u8>>>(i) {
                            Ok(Some(bytes)) => {
                                String::from_utf8(bytes).unwrap_or_else(|_| "<NULL>".to_string())
                            }
                            _ => "<NULL>".to_string(),
                        }
                    }
                };
                values.push((col_name.clone(), val));
            }
            Ok(values)
        });

        let rows = rows_result.map_err(|e| {
            let msg = format!("sqlite: query execution failed: {}", e);
            debug!("{}", msg);
            // Check if this is a busy/locked error → TempFail (DEFER)
            if is_busy_error(&e) {
                return DriverError::TempFail(msg);
            }
            DriverError::ExecutionFailed(msg)
        })?;

        // Format results: join rows with newlines, format columns per C callback
        let mut result_parts: Vec<String> = Vec::new();

        for row_result in rows {
            let row_values = row_result.map_err(|e| {
                let msg = format!("sqlite: row extraction failed: {}", e);
                debug!("{}", msg);
                if is_busy_error(&e) {
                    return DriverError::TempFail(msg);
                }
                DriverError::ExecutionFailed(msg)
            })?;

            if row_values.is_empty() {
                continue;
            }

            let formatted = if column_count > 1 {
                // Multi-column: format each column as name=value using lf_quote
                // (C lines 68-75: for multiple fields, include field name)
                let mut row_buf = String::new();
                for (col_name, val) in &row_values {
                    lf_quote(col_name, Some(val.as_str()), &mut row_buf);
                }
                row_buf
            } else {
                // Single column: return raw value directly
                // (C line 79: res = string_cat(res, argv[0] ? ...)
                row_values
                    .first()
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default()
            };

            result_parts.push(formatted);
        }

        // If no rows were returned, disable caching (C line 102: *do_cache = 0)
        if result_parts.is_empty() {
            debug!("sqlite: query returned no rows — disabling cache");
            return Ok(LookupResult::Found {
                value: String::new(),
                cache_ttl: Some(0),
            });
        }

        // Join multiple rows with newlines (C line 66: string_catn(res, "\n", 1))
        let value = result_parts.join("\n");

        debug!(
            rows = result_parts.len(),
            result_len = value.len(),
            "sqlite: query completed successfully"
        );

        Ok(LookupResult::Found {
            value,
            cache_ttl: None,
        })
    }

    /// Close an open SQLite connection.
    ///
    /// Replaces C `sqlite_close()` (lines 116-119). Takes ownership of the
    /// handle and drops it, which causes `rusqlite::Connection::drop()` to
    /// call `sqlite3_close()` internally.
    fn close(&self, handle: LookupHandle) {
        // Dropping the handle will close the rusqlite::Connection, which
        // calls sqlite3_close() internally. We explicitly consume the handle
        // to make this clear.
        debug!("sqlite: closing database connection");
        drop(handle);
    }

    /// Tidy up all SQLite resources.
    ///
    /// The C implementation has `tidy = NULL` (line 194), meaning no global
    /// tidy is performed. Individual connections are closed via `close()`.
    fn tidy(&self) {
        // C sqlite.c line 194: .tidy = NULL — no tidy function
        // No global state to clean up; each connection is managed individually.
        debug!("sqlite: tidy called (no-op)");
    }

    /// Quote a string for safe use in SQLite SQL queries.
    ///
    /// Replaces C `sqlite_quote()` (lines 138-159). The only character that
    /// needs quoting for SQLite is the single quote (`'`), which is doubled
    /// (i.e., `'` becomes `''`).
    ///
    /// # Parameters
    ///
    /// - `value`: The string to quote/escape.
    /// - `additional`: Additional option text. If `Some(_)`, returns `None`
    ///   since no options are recognized (C line 144: `if (opt) return NULL`).
    ///
    /// # Returns
    ///
    /// `Some(quoted_string)` with single quotes doubled, or `None` if an
    /// unrecognized option was provided.
    fn quote(&self, value: &str, additional: Option<&str>) -> Option<String> {
        // C line 144: if (opt) return NULL — no options recognized
        if additional.is_some() {
            return None;
        }

        // Count single quotes for pre-allocation (C lines 146-147)
        let quote_count = value.chars().filter(|&c| c == '\'').count();

        if quote_count == 0 {
            // Fast path: no quoting needed, return as-is
            return Some(value.to_string());
        }

        // Pre-allocate with exact size: original length + extra quotes
        let mut quoted = String::with_capacity(value.len() + quote_count);

        // Double single quotes (C lines 151-155)
        for ch in value.chars() {
            if ch == '\'' {
                quoted.push('\'');
            }
            quoted.push(ch);
        }

        Some(quoted)
    }

    /// Report SQLite library version information.
    ///
    /// Replaces C `sqlite_version_report()` (lines 169-177). Reports both
    /// compile-time and runtime SQLite versions for diagnostic output via
    /// the `-bV` flag.
    ///
    /// The compile-time version comes from `rusqlite::version()` which
    /// wraps `sqlite3_libversion()`. Since rusqlite bundles SQLite, the
    /// compile-time and runtime versions are typically identical.
    fn version_report(&self) -> Option<String> {
        let runtime_version = rusqlite::version();
        let report = format!(
            "Library version: SQLite: Compile: {}\n\
             \x20                        Runtime: {}",
            runtime_version, runtime_version,
        );
        debug!(version = %runtime_version, "sqlite: version report");
        Some(report)
    }

    /// Return the lookup type flags for SQLite.
    ///
    /// SQLite uses `lookup_absfilequery` in C (line 189), which combines
    /// `ABS_FILE | QUERY_STYLE` — the query starts with a database file
    /// path followed by SQL.
    fn lookup_type(&self) -> LookupType {
        LookupType::ABS_FILE | LookupType::QUERY_STYLE
    }

    /// Return the driver name for configuration file matching.
    ///
    /// C line 188: `.name = US"sqlite"`
    fn driver_name(&self) -> &str {
        "sqlite"
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Check if a rusqlite error indicates a busy/locked database condition.
///
/// Maps to SQLite error codes SQLITE_BUSY and SQLITE_LOCKED, which should
/// result in DEFER (temporary failure) rather than a permanent error.
fn is_busy_error(err: &rusqlite::Error) -> bool {
    match err {
        rusqlite::Error::SqliteFailure(ffi_err, _) => {
            // SQLITE_BUSY = 5, SQLITE_LOCKED = 6
            matches!(
                ffi_err.code,
                rusqlite::ffi::ErrorCode::DatabaseBusy | rusqlite::ffi::ErrorCode::DatabaseLocked
            )
        }
        _ => false,
    }
}

// =============================================================================
// Compile-Time Driver Registration
// =============================================================================

// Register the SQLite lookup driver with the inventory system.
//
// Replaces C registration pattern at sqlite.c lines 187-207:
//   static lookup_info _lookup_info = { .name = US"sqlite", ... };
//   static lookup_info *_lookup_list[] = { &_lookup_info };
//   lookup_module_info sqlite_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, ... };
//
// The inventory::submit! macro ensures this factory is collected at link time,
// enabling DriverRegistry::find_lookup("sqlite") to discover the driver.
//
// LookupType::from_raw(3) = ABS_FILE(2) | QUERY_STYLE(1) — pre-computed
// because the BitOr impl is not const.
inventory::submit! {
    LookupDriverFactory {
        name: "sqlite",
        create: || Box::new(SqliteLookup::new()),
        lookup_type: LookupType::from_raw(
            LookupType::ABS_FILE.raw() | LookupType::QUERY_STYLE.raw()
        ),
        avail_string: Some("sqlite (rusqlite bundled)"),
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Quote function tests ──────────────────────────────────────────────

    #[test]
    fn test_quote_no_quotes_needed() {
        let driver = SqliteLookup::new();
        let result = driver.quote("hello world", None);
        assert_eq!(result, Some("hello world".to_string()));
    }

    #[test]
    fn test_quote_single_quotes_doubled() {
        let driver = SqliteLookup::new();
        let result = driver.quote("it's a test", None);
        assert_eq!(result, Some("it''s a test".to_string()));
    }

    #[test]
    fn test_quote_multiple_single_quotes() {
        let driver = SqliteLookup::new();
        let result = driver.quote("O'Brien's 'data'", None);
        assert_eq!(result, Some("O''Brien''s ''data''".to_string()));
    }

    #[test]
    fn test_quote_empty_string() {
        let driver = SqliteLookup::new();
        let result = driver.quote("", None);
        assert_eq!(result, Some(String::new()));
    }

    #[test]
    fn test_quote_with_option_returns_none() {
        let driver = SqliteLookup::new();
        let result = driver.quote("test", Some("some_option"));
        assert_eq!(result, None);
    }

    #[test]
    fn test_quote_only_single_quotes() {
        let driver = SqliteLookup::new();
        let result = driver.quote("'''", None);
        assert_eq!(result, Some("''''''".to_string()));
    }

    // ── Driver metadata tests ─────────────────────────────────────────────

    #[test]
    fn test_driver_name() {
        let driver = SqliteLookup::new();
        assert_eq!(driver.driver_name(), "sqlite");
    }

    #[test]
    fn test_lookup_type_is_abs_file_and_query_style() {
        let driver = SqliteLookup::new();
        let lt = driver.lookup_type();
        assert!(lt.is_abs_file());
        assert!(lt.is_query_style());
    }

    #[test]
    fn test_version_report_contains_sqlite() {
        let driver = SqliteLookup::new();
        let report = driver.version_report();
        assert!(report.is_some());
        let text = report.unwrap();
        assert!(text.contains("SQLite"));
        assert!(text.contains("Compile:"));
        assert!(text.contains("Runtime:"));
    }

    #[test]
    fn test_check_always_true() {
        let driver = SqliteLookup::new();
        // Create a dummy handle (won't be used since check is a no-op)
        let handle: LookupHandle = Box::new(());
        let result = driver.check(&handle, None, 0, &[], &[]);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_tidy_no_panic() {
        let driver = SqliteLookup::new();
        driver.tidy(); // Should not panic
    }

    // ── Open function tests ───────────────────────────────────────────────

    #[test]
    fn test_open_rejects_none_filename() {
        let driver = SqliteLookup::new();
        let result = driver.open(None);
        assert!(result.is_err());
        match result.unwrap_err() {
            DriverError::ConfigError(msg) => {
                assert!(msg.contains("absolute file name expected"));
            }
            other => panic!("Expected ConfigError, got: {:?}", other),
        }
    }

    #[test]
    fn test_open_rejects_empty_filename() {
        let driver = SqliteLookup::new();
        let result = driver.open(Some(""));
        assert!(result.is_err());
        match result.unwrap_err() {
            DriverError::ConfigError(msg) => {
                assert!(msg.contains("absolute file name expected"));
            }
            other => panic!("Expected ConfigError, got: {:?}", other),
        }
    }

    #[test]
    fn test_open_rejects_relative_path() {
        let driver = SqliteLookup::new();
        let result = driver.open(Some("relative/path.db"));
        assert!(result.is_err());
        match result.unwrap_err() {
            DriverError::ConfigError(msg) => {
                assert!(msg.contains("absolute file name expected"));
            }
            other => panic!("Expected ConfigError, got: {:?}", other),
        }
    }

    #[test]
    fn test_open_succeeds_with_absolute_path() {
        let driver = SqliteLookup::new();
        // Use a temporary file with absolute path
        let tmp = std::env::temp_dir().join("exim_sqlite_test_open.db");
        let result = driver.open(Some(tmp.to_str().unwrap()));
        assert!(result.is_ok());
        // Clean up
        let handle = result.unwrap();
        driver.close(handle);
        let _ = std::fs::remove_file(&tmp);
    }

    // ── Find function tests ───────────────────────────────────────────────

    /// Helper: access the inner Connection from a LookupHandle for test setup.
    fn setup_conn(handle: &LookupHandle) -> std::sync::MutexGuard<'_, Connection> {
        handle
            .downcast_ref::<SqliteHandle>()
            .expect("test: expected SqliteHandle")
            .lock()
    }

    #[test]
    fn test_find_single_column() {
        let driver = SqliteLookup::new();
        let tmp = std::env::temp_dir().join("exim_sqlite_test_find_single.db");
        let handle = driver.open(Some(tmp.to_str().unwrap())).unwrap();

        // Set up test data
        {
            let conn = setup_conn(&handle);
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS test (value TEXT);
                 INSERT INTO test (value) VALUES ('hello');",
            )
            .unwrap();
        }

        let result = driver
            .find(&handle, None, "SELECT value FROM test", None)
            .unwrap();
        match result {
            LookupResult::Found { value, .. } => {
                assert_eq!(value, "hello");
            }
            other => panic!("Expected Found, got: {:?}", other),
        }

        driver.close(handle);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_find_multi_column() {
        let driver = SqliteLookup::new();
        let tmp = std::env::temp_dir().join("exim_sqlite_test_find_multi.db");
        let handle = driver.open(Some(tmp.to_str().unwrap())).unwrap();

        // Set up test data
        {
            let conn = setup_conn(&handle);
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS users (name TEXT, email TEXT);
                 INSERT INTO users (name, email) VALUES ('Alice', 'alice@example.com');",
            )
            .unwrap();
        }

        let result = driver
            .find(&handle, None, "SELECT name, email FROM users", None)
            .unwrap();
        match result {
            LookupResult::Found { value, .. } => {
                // Multi-column: should use lf_quote formatting
                assert!(value.contains("name=Alice"));
                assert!(value.contains("email=alice@example.com"));
            }
            other => panic!("Expected Found, got: {:?}", other),
        }

        driver.close(handle);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_find_multiple_rows() {
        let driver = SqliteLookup::new();
        let tmp = std::env::temp_dir().join("exim_sqlite_test_find_rows.db");
        let handle = driver.open(Some(tmp.to_str().unwrap())).unwrap();

        // Set up test data
        {
            let conn = setup_conn(&handle);
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS vals (v TEXT);
                 INSERT INTO vals (v) VALUES ('one');
                 INSERT INTO vals (v) VALUES ('two');
                 INSERT INTO vals (v) VALUES ('three');",
            )
            .unwrap();
        }

        let result = driver
            .find(&handle, None, "SELECT v FROM vals ORDER BY v", None)
            .unwrap();
        match result {
            LookupResult::Found { value, .. } => {
                let lines: Vec<&str> = value.split('\n').collect();
                assert_eq!(lines.len(), 3);
                assert_eq!(lines[0], "one");
                assert_eq!(lines[1], "three");
                assert_eq!(lines[2], "two");
            }
            other => panic!("Expected Found, got: {:?}", other),
        }

        driver.close(handle);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_find_null_values() {
        let driver = SqliteLookup::new();
        let tmp = std::env::temp_dir().join("exim_sqlite_test_find_null.db");
        let handle = driver.open(Some(tmp.to_str().unwrap())).unwrap();

        // Set up test data with NULL
        {
            let conn = setup_conn(&handle);
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS test (v TEXT);
                 INSERT INTO test (v) VALUES (NULL);",
            )
            .unwrap();
        }

        let result = driver
            .find(&handle, None, "SELECT v FROM test", None)
            .unwrap();
        match result {
            LookupResult::Found { value, .. } => {
                assert_eq!(value, "<NULL>");
            }
            other => panic!("Expected Found, got: {:?}", other),
        }

        driver.close(handle);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_find_empty_result_disables_cache() {
        let driver = SqliteLookup::new();
        let tmp = std::env::temp_dir().join("exim_sqlite_test_find_empty.db");
        let handle = driver.open(Some(tmp.to_str().unwrap())).unwrap();

        // Set up empty table
        {
            let conn = setup_conn(&handle);
            conn.execute_batch("CREATE TABLE IF NOT EXISTS test (v TEXT);")
                .unwrap();
        }

        let result = driver
            .find(&handle, None, "SELECT v FROM test", None)
            .unwrap();
        match result {
            LookupResult::Found { value, cache_ttl } => {
                assert!(value.is_empty());
                assert_eq!(cache_ttl, Some(0)); // Cache disabled for empty results
            }
            other => panic!("Expected Found with cache disabled, got: {:?}", other),
        }

        driver.close(handle);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_find_invalid_sql_returns_error() {
        let driver = SqliteLookup::new();
        let tmp = std::env::temp_dir().join("exim_sqlite_test_find_bad_sql.db");
        let handle = driver.open(Some(tmp.to_str().unwrap())).unwrap();

        let result = driver.find(&handle, None, "NOT VALID SQL !@#", None);
        assert!(result.is_err());

        driver.close(handle);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_find_multi_column_with_null() {
        let driver = SqliteLookup::new();
        let tmp = std::env::temp_dir().join("exim_sqlite_test_find_multi_null.db");
        let handle = driver.open(Some(tmp.to_str().unwrap())).unwrap();

        {
            let conn = setup_conn(&handle);
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS test (a TEXT, b TEXT);
                 INSERT INTO test (a, b) VALUES ('val', NULL);",
            )
            .unwrap();
        }

        let result = driver
            .find(&handle, None, "SELECT a, b FROM test", None)
            .unwrap();
        match result {
            LookupResult::Found { value, .. } => {
                assert!(value.contains("a=val"));
                assert!(value.contains("b=<NULL>"));
            }
            other => panic!("Expected Found, got: {:?}", other),
        }

        driver.close(handle);
        let _ = std::fs::remove_file(&tmp);
    }

    // ── Close function tests ──────────────────────────────────────────────

    #[test]
    fn test_close_does_not_panic() {
        let driver = SqliteLookup::new();
        let tmp = std::env::temp_dir().join("exim_sqlite_test_close.db");
        let handle = driver.open(Some(tmp.to_str().unwrap())).unwrap();
        driver.close(handle); // Should not panic
        let _ = std::fs::remove_file(&tmp);
    }
}

// End of lookups/sqlite.rs
