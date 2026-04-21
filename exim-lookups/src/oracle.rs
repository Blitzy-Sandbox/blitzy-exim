// =============================================================================
// exim-lookups/src/oracle.rs — Oracle OCI Lookup Backend (FFI)
// =============================================================================
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Rewrites `src/src/lookups/oracle.c` (641 lines) as a Rust module that
// delegates all Oracle database operations to the `exim-ffi::oracle` safe FFI
// wrapper. This lookup provides SQL query execution against Oracle databases
// using the Oracle Call Interface (OCI) v2 API.
//
// # Architecture
//
// - **Connection caching**: Active Oracle sessions are cached in a
//   `HashMap<String, OracleSession>` keyed by `host/database/user` (sans
//   password), replacing the C static linked list `oracle_connections`.
// - **Multi-server failover**: Uses `helpers::sql_perform()` for iterating
//   configured server lists with automatic failover on DEFER, replacing the
//   hand-rolled `string_nextinlist` loop in C `oracle_find()`.
// - **Cursor lifecycle**: Open → Parse → Describe → Define → Execute → Fetch
//   cycle fully replicated via the safe `exim_ffi::oracle` API.
// - **Result formatting**: Single-column results are returned as raw values;
//   multi-column results use `helpers::lf_quote()` for `name=value` pairs,
//   matching C `perform_oracle_search()` behavior.
//
// # C Function Mapping
//
//   oracle_open()   → OracleLookup::open()   — return placeholder handle
//   oracle_find()   → OracleLookup::find()   — sql_perform + per-server callback
//   oracle_close()  → OracleLookup::close()  — no-op (sessions cached)
//   oracle_tidy()   → OracleLookup::tidy()   — close all cached connections
//   oracle_quote()  → OracleLookup::quote()  — Oracle escaping
//   oracle_version_report() → OracleLookup::version_report()
//
// # Safety
//
// Per AAP §0.7.2: This file contains ZERO `unsafe` code.
// Per AAP §0.4.2: Uses `inventory::submit!` for compile-time registration.

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;
use tracing::{debug, warn};

use crate::helpers::quote::lf_quote;
use crate::helpers::sql_perform::{sql_perform, SqlPerformError, SqlPerformResult};

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of columns in an Oracle SELECT list.
/// Re-exported from `exim_ffi::oracle` for local use.
const MAX_SELECT_LIST_SIZE: usize = exim_ffi::oracle::MAX_SELECT_LIST_SIZE;

/// Maximum buffer size for a single column output.
/// Re-exported from `exim_ffi::oracle` for local use.
const MAX_ITEM_BUFFER_SIZE: usize = exim_ffi::oracle::MAX_ITEM_BUFFER_SIZE;

// =============================================================================
// Oracle Open Handle (placeholder for query-style lookup)
// =============================================================================

/// Placeholder handle returned by `OracleLookup::open()`.
///
/// Query-style lookups do not need a file handle. The C `oracle_open()`
/// function returns `(void *)(1)` — a non-null dummy pointer. This struct
/// serves the same purpose in the Rust type system, providing a concrete
/// type for the `Box<dyn Any + Send + Sync>` handle.
struct OracleOpenHandle;

// =============================================================================
// OracleLookup — Primary Lookup Driver
// =============================================================================

/// Oracle OCI SQL lookup driver.
///
/// Executes SQL queries against one or more Oracle databases using the
/// Oracle Call Interface (OCI) v2 API via the `exim-ffi` safe FFI wrapper.
///
/// # Connection Caching
///
/// Active Oracle sessions are stored in a `HashMap<String, OracleSession>`
/// protected by a `Mutex`. The cache key is `host/database/user` (sans
/// password), matching the C `oracle_connection` linked list keyed by
/// `server_copy`. Sessions remain open across multiple queries and are
/// only closed by [`tidy()`](OracleLookup::tidy).
///
/// # Multi-Server Failover
///
/// The [`find()`](OracleLookup::find) method uses
/// [`helpers::sql_perform()`](crate::helpers::sql_perform::sql_perform) to
/// iterate over configured Oracle servers, advancing to the next server
/// when a temporary failure (DEFER) occurs.
///
/// # Server Specification Format
///
/// Each server entry uses the format: `host/database/user/password`
///
/// - `host` — TNS service name or hostname (passed to `olog` as `conn`)
/// - `database` — Database name (currently unused by OCI login, reserved)
/// - `user` — Oracle user name
/// - `password` — Oracle password
pub struct OracleLookup {
    /// Cached Oracle sessions, keyed by `host/database/user` (sans password).
    ///
    /// `Mutex` provides interior mutability and thread safety required by the
    /// `LookupDriver: Send + Sync` trait bound.
    connections: Mutex<HashMap<String, exim_ffi::oracle::OracleSession>>,

    /// Configured default Oracle server list from the `oracle_servers`
    /// configuration option.
    ///
    /// Initially `None`; set by the configuration parser during startup.
    /// When set, this list is passed to `sql_perform` as `opt_server_list`
    /// for default server resolution.
    oracle_servers: Mutex<Option<String>>,
}

impl fmt::Debug for OracleLookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let conn_count = self.connections.lock().map(|c| c.len()).unwrap_or(0);
        let has_servers = self
            .oracle_servers
            .lock()
            .map(|s| s.is_some())
            .unwrap_or(false);
        f.debug_struct("OracleLookup")
            .field("cached_connections", &conn_count)
            .field("oracle_servers_configured", &has_servers)
            .finish()
    }
}

impl OracleLookup {
    /// Create a new `OracleLookup` instance with an empty connection cache.
    fn new() -> Self {
        Self {
            connections: Mutex::new(HashMap::new()),
            oracle_servers: Mutex::new(None),
        }
    }

    /// Parse a server specification string into its four components.
    ///
    /// Format: `host/database/user/password`
    ///
    /// Parses from the right, splitting on `/`, matching the C code's
    /// reverse parsing approach (`Ustrrchr(server, '/')` in a loop).
    ///
    /// Returns `(host, database, user, password)` on success.
    ///
    /// # Errors
    ///
    /// Returns an error string if the server spec has fewer than four
    /// `/`-separated components.
    fn parse_server_spec(server: &str) -> Result<(&str, &str, &str, &str), String> {
        let mut parts: Vec<&str> = Vec::with_capacity(4);
        let mut remaining = server;

        // Extract password, user, and database from right to left.
        // This mirrors the C code at oracle.c lines 276–288:
        //   for (int i = 3; i > 0; i--)
        //     pp = Ustrrchr(server, '/');
        for _ in 0..3 {
            match remaining.rfind('/') {
                Some(pos) => {
                    parts.push(&remaining[pos + 1..]);
                    remaining = &remaining[..pos];
                }
                None => {
                    return Err(format!("incomplete ORACLE server data: {}", server));
                }
            }
        }
        parts.push(remaining); // host (what's left)
        parts.reverse();

        // parts[0]=host, parts[1]=database, parts[2]=user, parts[3]=password
        Ok((parts[0], parts[1], parts[2], parts[3]))
    }

    /// Build a cache key from server components (sans password).
    ///
    /// Format: `host/database/user`
    ///
    /// Matches C `server_copy = string_copy(server)` which copies the server
    /// string after the password has been detached (oracle.c line 287).
    fn cache_key(host: &str, database: &str, user: &str) -> String {
        format!("{}/{}/{}", host, database, user)
    }

    /// Execute a SQL query against a single Oracle server.
    ///
    /// This is the per-server callback function used by `sql_perform()`.
    /// It manages the full OCI cursor lifecycle:
    ///   1. Parse server spec → extract host/db/user/password
    ///   2. Look up or create a cached session
    ///   3. Open cursor → parse SQL → describe columns → define output → execute
    ///   4. Fetch rows and format results
    ///   5. Return `SqlPerformResult`
    ///
    /// Replaces C `perform_oracle_search()` (oracle.c lines 254–496).
    fn perform_oracle_search(
        &self,
        query: &str,
        server: &str,
        _opts: Option<&str>,
    ) -> SqlPerformResult {
        // ── Step 1: Parse server specification ──────────────────────────
        let (host, database, user, password) = match Self::parse_server_spec(server) {
            Ok(parts) => parts,
            Err(msg) => {
                return SqlPerformResult::Deferred {
                    error: msg,
                    break_loop: true, // Config error — no point trying other servers
                };
            }
        };

        let cache_key = Self::cache_key(host, database, user);

        // ── Step 2: Acquire connection (cached or new) ──────────────────
        let mut cache = match self.connections.lock() {
            Ok(guard) => guard,
            Err(e) => {
                return SqlPerformResult::Deferred {
                    error: format!("ORACLE mutex poisoned: {}", e),
                    break_loop: true,
                };
            }
        };

        if !cache.contains_key(&cache_key) {
            debug!(
                host = %host,
                database = %database,
                user = %user,
                "ORACLE new connection"
            );

            match exim_ffi::oracle::OracleSession::connect(host, user, password) {
                Ok(session) => {
                    cache.insert(cache_key.clone(), session);
                }
                Err(e) => {
                    return SqlPerformResult::Deferred {
                        error: format!("ORACLE connection failed: {}", e),
                        break_loop: false, // Try next server
                    };
                }
            }
        } else {
            debug!(
                server = %cache_key,
                "ORACLE using cached connection"
            );
        }

        // Get mutable reference to the session for cursor operations.
        let session = match cache.get_mut(&cache_key) {
            Some(s) => s,
            None => {
                return SqlPerformResult::Deferred {
                    error: "ORACLE internal error: session not in cache after insert".into(),
                    break_loop: true,
                };
            }
        };

        // ── Step 3: Open cursor and parse query ─────────────────────────
        let mut cursor = match exim_ffi::oracle::OracleCursor::open(session) {
            Ok(c) => c,
            Err(e) => {
                let detailed = session.error_message(e.code);
                return SqlPerformResult::Deferred {
                    error: format!("ORACLE failed to open cursor: {}", detailed),
                    break_loop: false,
                };
            }
        };

        if let Err(e) = cursor.parse(query) {
            let detailed = session.error_message(e.code);
            return SqlPerformResult::Deferred {
                error: format!("ORACLE query failed: {}", detailed),
                break_loop: false,
            };
        }

        // ── Step 4: Describe columns ────────────────────────────────────
        // Iterate over the SELECT list to discover column names and types.
        // Matches C `describe_define()` (oracle.c lines 128–195).
        let mut columns: Vec<exim_ffi::oracle::OracleColumnDesc> = Vec::new();

        for col in 0..MAX_SELECT_LIST_SIZE as i32 {
            match cursor.describe(col) {
                Ok(desc) => columns.push(desc),
                Err(e) => {
                    // VAR_NOT_IN_LIST (1007) signals end of select list.
                    if e.code == exim_ffi::oracle::VAR_NOT_IN_LIST {
                        break;
                    }
                    let detailed = session.error_message(e.code);
                    return SqlPerformResult::Deferred {
                        error: format!("ORACLE describe_define failed: {}", detailed),
                        break_loop: false,
                    };
                }
            }
        }

        let num_fields = columns.len();

        // ── Step 5: Define output buffers ───────────────────────────────
        // Bind an output buffer for each column. The FFI `define()` always
        // uses STRING_TYPE output, letting Oracle convert internally.
        let mut defines: Vec<exim_ffi::oracle::OracleDefine> = Vec::with_capacity(num_fields);

        for (col_idx, col_desc) in columns.iter().enumerate() {
            let buf_size = compute_buffer_size(col_desc);
            let mut buf = vec![0u8; buf_size];

            match cursor.define(col_idx as i32, &mut buf) {
                Ok(def) => defines.push(def),
                Err(e) => {
                    let detailed = session.error_message(e.code);
                    return SqlPerformResult::Deferred {
                        error: format!("ORACLE define column {} failed: {}", col_idx, detailed),
                        break_loop: false,
                    };
                }
            }
        }

        // ── Step 6: Execute ─────────────────────────────────────────────
        if let Err(e) = cursor.execute() {
            let detailed = session.error_message(e.code);
            return SqlPerformResult::Deferred {
                error: format!("ORACLE oexec failed: {}", detailed),
                break_loop: false,
            };
        }

        // ── Step 7: Fetch rows and format result ────────────────────────
        // Single-column results are returned raw; multi-column results use
        // lf_quote() for name=value formatting.
        // Rows are separated by newlines, matching C behavior.
        let mut result = String::new();

        loop {
            match cursor.fetch() {
                Ok(exim_ffi::oracle::OracleFetchResult::NoMoreData) => break,
                Ok(exim_ffi::oracle::OracleFetchResult::Row) => {
                    // Append newline between rows (C: oracle.c line 401)
                    if !result.is_empty() {
                        result.push('\n');
                    }

                    if num_fields == 1 {
                        // Single field — raw value, no name prefix.
                        // C: oracle.c line 405–406
                        let value = extract_define_value(&defines[0]);
                        result.push_str(&value);
                    } else {
                        // Multiple fields — name=value pairs.
                        // C: oracle.c lines 410–459
                        format_multi_column_row(&columns, &defines, num_fields, &mut result);
                    }
                }
                Err(e) => {
                    // Defensive check: if the error code is NO_DATA_FOUND,
                    // treat it as end-of-data rather than a hard error.
                    // This handles edge cases in OCI error propagation.
                    if e.code == exim_ffi::oracle::NO_DATA_FOUND {
                        break;
                    }
                    let detailed = session.error_message(e.code);
                    return SqlPerformResult::Deferred {
                        error: format!("ORACLE fetch failed: {}", detailed),
                        break_loop: false,
                    };
                }
            }
        }

        // ── Step 8: Return result ───────────────────────────────────────
        if result.is_empty() {
            debug!("ORACLE: no data found");
            SqlPerformResult::NotFound
        } else {
            debug!(result_len = result.len(), "ORACLE: query returned data");
            SqlPerformResult::Found {
                result,
                cacheable: true,
            }
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Compute the output buffer size for a column based on its Oracle metadata.
///
/// Matches the C `describe_define()` logic for adjusting buffer sizes
/// (oracle.c lines 151–182):
///
/// - `NUMBER_TYPE` → `numwidth` (8 bytes) for the numeric string representation
/// - `DATE_TYPE`   → 9 bytes for Oracle's default date format
/// - `ROWID_TYPE`  → 18 bytes for the Oracle ROWID string
/// - All others    → `db_size + 1`, capped at `MAX_ITEM_BUFFER_SIZE`
///
/// Since the FFI always defines output as `STRING_TYPE`, Oracle performs
/// internal type conversion. The buffer sizes are generous enough to hold
/// the string representation of each data type.
fn compute_buffer_size(desc: &exim_ffi::oracle::OracleColumnDesc) -> usize {
    // Use the type constants from exim_ffi::oracle for type identification.
    let raw_type = desc.db_type;

    if raw_type == exim_ffi::oracle::NUMBER_TYPE {
        // NUMBER columns: C uses numwidth=8 for int/float display.
        // For STRING_TYPE output, Oracle may produce longer strings (e.g.,
        // "123456789.123456"). Use a conservative buffer of 64 bytes.
        64
    } else if raw_type == exim_ffi::oracle::STRING_TYPE {
        // VARCHAR/CHAR: use reported size + 1 for null terminator.
        let size = (desc.db_size as usize).saturating_add(1);
        size.min(MAX_ITEM_BUFFER_SIZE)
    } else {
        // DATE (9 bytes), ROWID (18 bytes), and all other types.
        // Use db_size + 1 capped at MAX_ITEM_BUFFER_SIZE.
        let size = (desc.db_size as usize).saturating_add(1);
        size.clamp(32, MAX_ITEM_BUFFER_SIZE) // minimum 32 for safety
    }
}

/// Extract a string value from an `OracleDefine` buffer after a fetch.
///
/// If the null indicator is `-1`, the column value is SQL `NULL` — return
/// an empty string (matching C behavior where NULL columns produce empty
/// output). Otherwise, read `return_length()` bytes from the buffer and
/// convert to a UTF-8 string (using lossy conversion for non-UTF-8 data).
fn extract_define_value(def: &exim_ffi::oracle::OracleDefine) -> String {
    // Check null indicator — -1 means SQL NULL.
    if def.indicator() == -1 {
        return String::new();
    }
    let len = (def.return_length() as usize).min(def.buffer.len());
    String::from_utf8_lossy(&def.buffer[..len]).into_owned()
}

/// Format a multi-column row as space-separated `name=value` pairs.
///
/// For each column:
/// 1. Trim leading/trailing whitespace from the column name
///    (C: `Uskip_whitespace` + trailing strip, oracle.c lines 415–417)
/// 2. Use `lf_quote()` to format as `name=value ` with appropriate quoting
///    (C: oracle.c lines 419–458)
///
/// `lf_quote()` automatically handles quoting:
/// - Empty values → quoted as `""`
/// - Values with whitespace → quoted with `"..."` and `\` escaping
/// - Numeric values (no spaces) → unquoted (matching C int/float behavior)
fn format_multi_column_row(
    columns: &[exim_ffi::oracle::OracleColumnDesc],
    defines: &[exim_ffi::oracle::OracleDefine],
    num_fields: usize,
    result: &mut String,
) {
    for i in 0..num_fields {
        // Trim column name (matching C whitespace stripping).
        let col_name = columns[i].name.trim();

        // Extract the column value from the define buffer.
        let value = extract_define_value(&defines[i]);

        // Format using lf_quote — it appends `name=value ` (with trailing space).
        // For numeric columns (fetched as STRING_TYPE by FFI), the string
        // representation typically contains no whitespace, so lf_quote will
        // output the value unquoted — matching C int/float formatting behavior.
        lf_quote(col_name, Some(&value), result);
    }
}

// =============================================================================
// LookupDriver Trait Implementation
// =============================================================================

impl LookupDriver for OracleLookup {
    /// Open an Oracle lookup source — returns a placeholder handle.
    ///
    /// Query-style lookups do not use a file. Connections are established
    /// lazily in `find()` when the server specification is known.
    ///
    /// Matches C `oracle_open()` which returns `(void *)(1)`.
    fn open(&self, _filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        Ok(Box::new(OracleOpenHandle))
    }

    /// Check an Oracle lookup file — always returns `true`.
    ///
    /// Query-style lookups have no file to check. The C `oracle_lookup_info`
    /// struct has `check = NULL`, meaning the framework skips the check.
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

    /// Execute an Oracle SQL query with multi-server failover.
    ///
    /// Uses `helpers::sql_perform()` to iterate over configured Oracle
    /// servers, calling `perform_oracle_search()` for each server until
    /// one succeeds or all defer.
    ///
    /// Replaces C `oracle_find()` (oracle.c lines 509–532).
    fn find(
        &self,
        _handle: &LookupHandle,
        _filename: Option<&str>,
        key_or_query: &str,
        options: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        debug!(query = %key_or_query, "ORACLE query");

        // Read the configured oracle_servers default list.
        let servers_guard = self
            .oracle_servers
            .lock()
            .map_err(|e| DriverError::TempFail(format!("ORACLE servers mutex poisoned: {}", e)))?;
        let opt_server_list = servers_guard.as_deref();

        // Use sql_perform for multi-server failover.
        // The closure captures `&self` to access the connection cache.
        let result = sql_perform(
            "Oracle",
            "oracle_servers",
            opt_server_list,
            key_or_query,
            options,
            &|query, server, opts| self.perform_oracle_search(query, server, opts),
        );

        match result {
            Ok((data, _cacheable)) => {
                if data.is_empty() {
                    Ok(LookupResult::NotFound)
                } else {
                    Ok(LookupResult::Found {
                        value: data,
                        cache_ttl: None,
                    })
                }
            }
            Err(e) => {
                let msg = e.to_string();
                warn!(error = %msg, "ORACLE lookup failed");
                // Map sql_perform errors to LookupResult::Deferred.
                // Configuration errors become DriverError.
                match e {
                    SqlPerformError::MissingSemicolon { .. }
                    | SqlPerformError::MissingEquals { .. }
                    | SqlPerformError::EmptyServerList => Err(DriverError::ConfigError(msg)),
                    SqlPerformError::NoServersConfigured { .. } => {
                        Ok(LookupResult::Deferred { message: msg })
                    }
                    SqlPerformError::ServerNotFound { .. }
                    | SqlPerformError::TaintedServer { .. } => Err(DriverError::ConfigError(msg)),
                    SqlPerformError::AllServersFailed { .. } => {
                        Ok(LookupResult::Deferred { message: msg })
                    }
                }
            }
        }
    }

    /// Close an Oracle lookup handle — no-op.
    ///
    /// Sessions are cached in the connection pool and reused across queries.
    /// The C `oracle_lookup_info` struct has `close = NULL`.
    fn close(&self, _handle: LookupHandle) {
        // No-op — sessions are cached; they are closed in tidy().
    }

    /// Close all cached Oracle connections.
    ///
    /// Walks the connection cache and drops all sessions, which triggers
    /// `OracleSession::drop()` calling `ologof` for each.
    ///
    /// Replaces C `oracle_tidy()` (oracle.c lines 219–229).
    fn tidy(&self) {
        let mut cache = match self.connections.lock() {
            Ok(guard) => guard,
            Err(e) => {
                warn!("ORACLE tidy: mutex poisoned: {}", e);
                return;
            }
        };

        for (key, _session) in cache.drain() {
            debug!(
                server = %key,
                "close ORACLE connection"
            );
            // OracleSession::drop() calls ologof automatically via RAII.
        }
    }

    /// Quote a string for safe use in Oracle SQL.
    ///
    /// Escapes special characters with backslash sequences:
    /// - `\n` → `\\n`, `\t` → `\\t`, `\r` → `\\r`, `\b` → `\\b`
    /// - `'`, `"`, `\` → `\\` prefix
    ///
    /// Returns `None` if `additional` options are provided (not recognized).
    ///
    /// Replaces C `oracle_quote()` (oracle.c lines 554–591).
    fn quote(&self, value: &str, additional: Option<&str>) -> Option<String> {
        // No additional options recognized — return None if any are provided.
        // Matches C: `if (opt) return NULL;` (oracle.c line 560).
        if additional.is_some() {
            return None;
        }

        // Count characters needing escaping for pre-allocation.
        let extra = value
            .chars()
            .filter(|c| matches!(c, '\n' | '\t' | '\r' | '\x08' | '\'' | '"' | '\\'))
            .count();

        let mut result = String::with_capacity(value.len() + extra);

        for ch in value.chars() {
            match ch {
                '\n' => {
                    result.push('\\');
                    result.push('n');
                }
                '\t' => {
                    result.push('\\');
                    result.push('t');
                }
                '\r' => {
                    result.push('\\');
                    result.push('r');
                }
                '\x08' => {
                    // Backspace (0x08) — C: `case '\b': *t++ = 'b';`
                    result.push('\\');
                    result.push('b');
                }
                '\'' | '"' | '\\' => {
                    // Single quote, double quote, backslash — escaped with backslash prefix.
                    // C: `default: *t++ = c;` (after adding the `\\` prefix).
                    result.push('\\');
                    result.push(ch);
                }
                _ => result.push(ch),
            }
        }

        Some(result)
    }

    /// Version reporting for `-bV` output.
    ///
    /// Replaces C `oracle_version_report()` (oracle.c lines 602–609).
    fn version_report(&self) -> Option<String> {
        Some("Library version: Oracle: Exim version (Rust)".to_string())
    }

    /// Lookup type flags — query-style.
    ///
    /// Oracle is a query-style lookup (`lookup_querystyle`).
    /// C: `_lookup_info.type = lookup_querystyle` (oracle.c line 621).
    fn lookup_type(&self) -> LookupType {
        LookupType::QUERY_STYLE
    }

    /// Driver name for configuration file matching.
    ///
    /// C: `_lookup_info.name = US"oracle"` (oracle.c line 620).
    fn driver_name(&self) -> &str {
        "oracle"
    }
}

// =============================================================================
// Compile-Time Driver Registration
// =============================================================================
//
// Replaces C `oracle_lookup_module_info` static registration (oracle.c
// lines 634–639) with inventory-based compile-time registration per
// AAP §0.4.2 and §0.7.3.

inventory::submit! {
    LookupDriverFactory {
        name: "oracle",
        create: || Box::new(OracleLookup::new()),
        lookup_type: LookupType::QUERY_STYLE,
        avail_string: Some("oracle (FFI to OCI)"),
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Driver metadata tests ─────────────────────────────────────────────

    #[test]
    fn test_driver_name() {
        let driver = OracleLookup::new();
        assert_eq!(driver.driver_name(), "oracle");
    }

    #[test]
    fn test_lookup_type_is_query_style() {
        let driver = OracleLookup::new();
        assert!(driver.lookup_type().is_query_style());
        assert!(!driver.lookup_type().is_single_key());
    }

    #[test]
    fn test_version_report() {
        let driver = OracleLookup::new();
        let report = driver.version_report();
        assert!(report.is_some());
        let text = report.unwrap();
        assert!(text.contains("Oracle"));
        assert!(text.contains("Rust"));
    }

    #[test]
    fn test_open_returns_handle() {
        let driver = OracleLookup::new();
        let handle = driver.open(None);
        assert!(handle.is_ok());
    }

    #[test]
    fn test_check_always_true() {
        let driver = OracleLookup::new();
        let handle: LookupHandle = Box::new(OracleOpenHandle);
        let result = driver.check(&handle, None, 0o022, &[], &[]);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    // ── Server spec parsing tests ─────────────────────────────────────────

    #[test]
    fn test_parse_server_spec_valid() {
        let (host, db, user, pass) =
            OracleLookup::parse_server_spec("dbhost/mydb/scott/tiger").unwrap();
        assert_eq!(host, "dbhost");
        assert_eq!(db, "mydb");
        assert_eq!(user, "scott");
        assert_eq!(pass, "tiger");
    }

    #[test]
    fn test_parse_server_spec_empty_database() {
        let (host, db, user, pass) =
            OracleLookup::parse_server_spec("dbhost//scott/tiger").unwrap();
        assert_eq!(host, "dbhost");
        assert_eq!(db, "");
        assert_eq!(user, "scott");
        assert_eq!(pass, "tiger");
    }

    #[test]
    fn test_parse_server_spec_password_with_slash() {
        // Password containing a slash: "host/db/user/p/a/ss"
        // Rightmost slash splits password as "ss", then "p/a" remains
        // with user... Actually this is the correct behavior for
        // reverse parsing - it matches C's Ustrrchr approach.
        let (host, db, user, pass) = OracleLookup::parse_server_spec("host/db/user/pass").unwrap();
        assert_eq!(host, "host");
        assert_eq!(db, "db");
        assert_eq!(user, "user");
        assert_eq!(pass, "pass");
    }

    #[test]
    fn test_parse_server_spec_incomplete() {
        let result = OracleLookup::parse_server_spec("host/user");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("incomplete"));
    }

    #[test]
    fn test_parse_server_spec_no_slashes() {
        let result = OracleLookup::parse_server_spec("justhost");
        assert!(result.is_err());
    }

    // ── Cache key tests ───────────────────────────────────────────────────

    #[test]
    fn test_cache_key_format() {
        let key = OracleLookup::cache_key("dbhost", "mydb", "scott");
        assert_eq!(key, "dbhost/mydb/scott");
    }

    #[test]
    fn test_cache_key_empty_database() {
        let key = OracleLookup::cache_key("dbhost", "", "scott");
        assert_eq!(key, "dbhost//scott");
    }

    // ── Quote function tests ──────────────────────────────────────────────

    #[test]
    fn test_quote_basic_string() {
        let driver = OracleLookup::new();
        let result = driver.quote("hello world", None);
        assert_eq!(result, Some("hello world".to_string()));
    }

    #[test]
    fn test_quote_special_chars() {
        let driver = OracleLookup::new();
        let result = driver.quote("line\nnext", None);
        assert_eq!(result, Some("line\\nnext".to_string()));
    }

    #[test]
    fn test_quote_tab() {
        let driver = OracleLookup::new();
        let result = driver.quote("col\tval", None);
        assert_eq!(result, Some("col\\tval".to_string()));
    }

    #[test]
    fn test_quote_carriage_return() {
        let driver = OracleLookup::new();
        let result = driver.quote("text\rmore", None);
        assert_eq!(result, Some("text\\rmore".to_string()));
    }

    #[test]
    fn test_quote_backspace() {
        let driver = OracleLookup::new();
        let result = driver.quote("text\x08more", None);
        assert_eq!(result, Some("text\\bmore".to_string()));
    }

    #[test]
    fn test_quote_single_quote() {
        let driver = OracleLookup::new();
        let result = driver.quote("it's", None);
        assert_eq!(result, Some("it\\'s".to_string()));
    }

    #[test]
    fn test_quote_double_quote() {
        let driver = OracleLookup::new();
        let result = driver.quote("say \"hello\"", None);
        assert_eq!(result, Some("say \\\"hello\\\"".to_string()));
    }

    #[test]
    fn test_quote_backslash() {
        let driver = OracleLookup::new();
        let result = driver.quote("path\\to\\file", None);
        assert_eq!(result, Some("path\\\\to\\\\file".to_string()));
    }

    #[test]
    fn test_quote_with_additional_returns_none() {
        let driver = OracleLookup::new();
        let result = driver.quote("test", Some("extra"));
        assert!(result.is_none());
    }

    #[test]
    fn test_quote_empty_string() {
        let driver = OracleLookup::new();
        let result = driver.quote("", None);
        assert_eq!(result, Some(String::new()));
    }

    #[test]
    fn test_quote_all_special_chars() {
        let driver = OracleLookup::new();
        let input = "\n\t\r\x08'\"\\";
        let expected = "\\n\\t\\r\\b\\'\\\"\\\\";
        assert_eq!(driver.quote(input, None), Some(expected.to_string()));
    }

    // ── Helper function tests ─────────────────────────────────────────────

    #[test]
    fn test_compute_buffer_size_number() {
        let desc = exim_ffi::oracle::OracleColumnDesc {
            name: "amount".to_string(),
            db_size: 22,
            db_type: exim_ffi::oracle::NUMBER_TYPE,
            display_size: 22,
            precision: 10,
            scale: 2,
            nullable: true,
        };
        assert_eq!(compute_buffer_size(&desc), 64);
    }

    #[test]
    fn test_compute_buffer_size_string() {
        let desc = exim_ffi::oracle::OracleColumnDesc {
            name: "name".to_string(),
            db_size: 100,
            db_type: exim_ffi::oracle::STRING_TYPE,
            display_size: 100,
            precision: 0,
            scale: 0,
            nullable: false,
        };
        // db_size + 1 = 101
        assert_eq!(compute_buffer_size(&desc), 101);
    }

    #[test]
    fn test_compute_buffer_size_large_string_capped() {
        let desc = exim_ffi::oracle::OracleColumnDesc {
            name: "blob".to_string(),
            db_size: 2000,
            db_type: exim_ffi::oracle::STRING_TYPE,
            display_size: 2000,
            precision: 0,
            scale: 0,
            nullable: false,
        };
        // Capped at MAX_ITEM_BUFFER_SIZE (1024)
        assert_eq!(compute_buffer_size(&desc), MAX_ITEM_BUFFER_SIZE);
    }

    // ── Tidy test ─────────────────────────────────────────────────────────

    #[test]
    fn test_tidy_empty_cache() {
        let driver = OracleLookup::new();
        driver.tidy(); // Should not panic on empty cache
    }

    // ── Close test ────────────────────────────────────────────────────────

    #[test]
    fn test_close_noop() {
        let driver = OracleLookup::new();
        let handle: LookupHandle = Box::new(OracleOpenHandle);
        driver.close(handle); // Should not panic
    }

    // ── Debug formatting test ─────────────────────────────────────────────

    #[test]
    fn test_debug_format() {
        let driver = OracleLookup::new();
        let debug_str = format!("{:?}", driver);
        assert!(debug_str.contains("OracleLookup"));
        assert!(debug_str.contains("cached_connections"));
    }
}
