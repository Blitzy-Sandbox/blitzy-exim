#![deny(unsafe_code)]
// =============================================================================
// exim-lookups/src/mysql.rs — MySQL/MariaDB Lookup via mysql_async + block_on
// =============================================================================
//
// Replaces `src/src/lookups/mysql.c` (514 lines). Uses `mysql_async` for
// async MySQL/MariaDB connection and query execution, bridged via
// `tokio::runtime::Runtime::block_on()` into the synchronous
// fork-per-connection model.
//
// Per AAP §0.7.2: This file contains ZERO `unsafe` code.
// Per AAP §0.7.3: The tokio runtime is scoped ONLY to lookup execution via
//   `block_on()`. It MUST NOT be used for the main daemon event loop.
//
// ## SQL Injection Safety Note
//
// Query strings are executed as raw SQL via `mysql_async::Conn::query()`,
// matching the C implementation's behavior of passing pre-expanded strings
// to `mysql_real_query()`. SQL safety relies on Exim's string expansion
// engine (`exim-expand`) which applies taint checking at the call site
// (via `Tainted<T>`/`Clean<T>` newtypes from `exim-store`). The expansion
// engine ensures that untrusted data from SMTP envelope, headers, or other
// tainted sources cannot be injected into lookup queries without explicit
// administrator opt-in via `${quote_mysql:...}` or similar sanitization.
// This is not a regression from C behavior — the C implementation had the
// identical SQL injection surface with identical upstream taint protections.
//
// Connection spec format (matching C mysql.c):
//   host/database/user/password
//   host:port/database/user/password
//   host:port(socket)/database/user/password
//   host:port(socket)[group]/database/user/password
//
// Registration: inventory::submit!(LookupDriverFactory { name: "mysql", ... })

use std::collections::HashMap;
use std::sync::Mutex;

use mysql_async::prelude::Queryable;
use mysql_async::{Conn, Opts, OptsBuilder, Params, Row, Value};

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;

use crate::helpers::quote::lf_quote;
use crate::helpers::sql_perform::{sql_perform, SqlPerformResult};

// =============================================================================
// Parsed Server Specification
// =============================================================================

/// Parsed MySQL server connection parameters.
///
/// Extracted from the `host:port(socket)[group]/database/user/password`
/// connection spec format used by Exim's multi-server failover mechanism.
/// Replaces the C inline parsing in `perform_mysql_search()` (mysql.c
/// lines 181–260).
///
/// # Fields
///
/// - `host` — Hostname or IP address for TCP connections. May be empty if a
///   Unix socket is specified.
/// - `port` — TCP port number. Defaults to 3306 when not specified.
/// - `database` — Database name. `None` when the query must specify the database.
/// - `user` — MySQL user name for authentication.
/// - `password` — MySQL password for authentication.
/// - `socket` — Unix domain socket path, if specified via `(path)` syntax.
/// - `option_group` — MySQL option group name from `my.cnf`, if specified
///   via `[group]` syntax.
#[derive(Debug, Clone)]
struct MysqlServerSpec {
    /// Hostname or IP address for TCP connections.
    host: String,
    /// TCP port (default 3306).
    port: u16,
    /// Database name. `None` means the query must specify the database.
    database: Option<String>,
    /// MySQL user name.
    user: String,
    /// MySQL password.
    password: String,
    /// Unix domain socket path, if specified.
    socket: Option<String>,
    /// MySQL option group name (from my.cnf), if specified.
    option_group: Option<String>,
}

// =============================================================================
// MysqlLookup — Main Lookup Driver Struct
// =============================================================================

/// MySQL/MariaDB lookup driver implementing the `LookupDriver` trait.
///
/// Uses `mysql_async::Opts` for connection option caching (one entry per unique
/// server specification), stored in a `HashMap` wrapped in `Mutex` for interior
/// mutability (since `LookupDriver` trait methods take `&self`).
///
/// The `Mutex` provides `Send + Sync` bounds required by the `LookupDriver`
/// trait supertrait constraints.
///
/// Replaces the C `mysql_connections` static linked list and
/// `mysql_lookup_info` registration struct from `mysql.c` lines 58–65.
///
/// # Connection Caching Strategy
///
/// Unlike the C implementation which caches live `MYSQL *` handles across
/// lookups, this implementation caches parsed `mysql_async::Opts` objects.
/// Live `mysql_async::Conn` objects are tied to specific tokio runtime
/// instances and cannot survive across separate `block_on()` invocations.
/// A fresh connection is established per `find()` call, ensuring clean
/// runtime isolation per AAP §0.7.3.
#[derive(Debug)]
pub struct MysqlLookup {
    /// Connection option cache: sanitized server key → mysql_async Opts.
    ///
    /// The key is the server spec with password removed (for safe logging
    /// and cache lookup). Entries are dropped on `tidy()` to reset all
    /// cached connection state, matching C `mysql_tidy()` behavior
    /// (mysql.c lines 122–143).
    conn_cache: Mutex<HashMap<String, Opts>>,
}

impl Default for MysqlLookup {
    fn default() -> Self {
        Self::new()
    }
}

impl MysqlLookup {
    /// Create a new `MysqlLookup` instance with an empty connection cache.
    pub fn new() -> Self {
        Self {
            conn_cache: Mutex::new(HashMap::new()),
        }
    }

    // =========================================================================
    // Server Spec Parsing
    // =========================================================================

    /// Parse a server specification string into structured connection parameters.
    ///
    /// Matches the C parsing logic from `perform_mysql_search()` lines 181–260:
    /// - Parse from right to left, extracting password, user, database via `/`
    /// - Remaining string is the host portion
    /// - Extract `[group]` MySQL option group name
    /// - Extract `(socket)` Unix domain socket path
    /// - Handle TCP host with optional `:port`
    /// - Handle IPv6 addresses with multiple colons
    ///
    /// # Returns
    ///
    /// `(spec, cache_key)` where `cache_key` is the server spec without the
    /// password, suitable for logging and cache lookup (C: `server_copy`).
    ///
    /// # Errors
    ///
    /// Returns an error string if the server specification does not contain
    /// at least three `/` separators (host/database/user/password).
    fn parse_server_spec(server: &str) -> Result<(MysqlServerSpec, String), String> {
        let mut remaining = server;

        // ── Extract password (after last '/') ─────────────────────────────
        // C: sdata[3] = password — Ustrrchr for i=3,2,1,0
        let slash_pos = remaining
            .rfind('/')
            .ok_or_else(|| format!("incomplete MySQL server data: {}", server))?;
        let password = remaining[slash_pos + 1..].to_string();
        remaining = &remaining[..slash_pos];

        // Cache key is server spec without password (C: server_copy)
        let cache_key = remaining.to_string();

        // ── Extract user (after second-to-last '/') ──────────────────────
        // C: sdata[2] = user
        let slash_pos = remaining
            .rfind('/')
            .ok_or_else(|| format!("incomplete MySQL server data: {}", cache_key))?;
        let user = remaining[slash_pos + 1..].to_string();
        remaining = &remaining[..slash_pos];

        // ── Extract database (after third-to-last '/') ───────────────────
        // C: sdata[1] = database. Empty string → NULL (query defines it).
        let slash_pos = remaining
            .rfind('/')
            .ok_or_else(|| format!("incomplete MySQL server data: {}", cache_key))?;
        let db_str = &remaining[slash_pos + 1..];
        let database = if db_str.is_empty() {
            None
        } else {
            Some(db_str.to_string())
        };
        remaining = &remaining[..slash_pos];

        // ── Parse host portion ────────────────────────────────────────────
        // C: sdata[0] = host, then extract [group], (socket), :port
        let host_str = remaining.to_string();

        // Extract [group] if present (C: mysql.c lines 212–220)
        // MySQL option group for reading connection parameters from my.cnf
        let (host_str, option_group) = Self::extract_bracket_group(&host_str);

        // Extract (socket) if present (C: mysql.c lines 222–232)
        // Unix domain socket path for local connections
        let (host_str, socket) = Self::extract_paren_socket(&host_str);

        // Parse host:port with IPv6 handling (C: mysql.c lines 234–260)
        let (host, port) = Self::parse_host_port(&host_str);

        Ok((
            MysqlServerSpec {
                host,
                port,
                database,
                user,
                password,
                socket,
                option_group,
            },
            cache_key,
        ))
    }

    /// Extract `[group]` option group from a host string.
    ///
    /// Looks for a bracketed segment like `[exim]` and returns the group name
    /// and the remaining host string with the brackets removed.
    ///
    /// C equivalent: mysql.c lines 212–220 — extract `[group]` from hostname.
    fn extract_bracket_group(host_str: &str) -> (String, Option<String>) {
        if let Some(bracket_start) = host_str.find('[') {
            if let Some(rel_bracket_end) = host_str[bracket_start..].find(']') {
                let bracket_end = bracket_start + rel_bracket_end;
                let group = host_str[bracket_start + 1..bracket_end].to_string();
                let rest = format!(
                    "{}{}",
                    &host_str[..bracket_start],
                    &host_str[bracket_end + 1..]
                );
                return (rest, Some(group));
            }
        }
        (host_str.to_string(), None)
    }

    /// Extract `(socket)` Unix socket path from a host string.
    ///
    /// Looks for a parenthesized segment like `(/var/run/mysqld/mysqld.sock)`
    /// and returns the socket path and the remaining host string with the
    /// parentheses removed.
    ///
    /// C equivalent: mysql.c lines 222–232 — extract `(socket)` from hostname.
    fn extract_paren_socket(host_str: &str) -> (String, Option<String>) {
        if let Some(paren_start) = host_str.find('(') {
            if let Some(rel_paren_end) = host_str[paren_start..].find(')') {
                let paren_end = paren_start + rel_paren_end;
                let sock = host_str[paren_start + 1..paren_end].to_string();
                let rest = format!("{}{}", &host_str[..paren_start], &host_str[paren_end + 1..]);
                return (rest, Some(sock));
            }
        }
        (host_str.to_string(), None)
    }

    /// Parse host:port, handling IPv6 addresses with multiple colons.
    ///
    /// C logic (mysql.c lines 234–260):
    /// - Count colons to detect IPv6
    /// - Single colon: `hostname:port`
    /// - Multiple colons: IPv6; use last period as port separator if present
    ///   (e.g., `::1.3306` → host=`::1`, port=3306)
    /// - No colons: hostname only, default port 3306
    fn parse_host_port(host_str: &str) -> (String, u16) {
        if host_str.is_empty() {
            return (String::new(), 3306);
        }

        let colon_count = host_str.chars().filter(|&c| c == ':').count();

        if colon_count == 0 {
            // No colons: plain hostname, default port
            (host_str.to_string(), 3306)
        } else if colon_count == 1 {
            // Single colon: host:port (C: lines 236–240)
            if let Some(colon_pos) = host_str.find(':') {
                let host = host_str[..colon_pos].to_string();
                let port: u16 = host_str[colon_pos + 1..].parse().unwrap_or(3306);
                (host, port)
            } else {
                (host_str.to_string(), 3306)
            }
        } else {
            // Multiple colons: IPv6 address (C: lines 244–260)
            // Look for period as port separator (e.g., "::1.3306")
            if let Some(dot_pos) = host_str.rfind('.') {
                if let Ok(port) = host_str[dot_pos + 1..].parse::<u16>() {
                    let host = host_str[..dot_pos].to_string();
                    return (host, port);
                }
            }
            // Pure IPv6 without port separator: default port
            (host_str.to_string(), 3306)
        }
    }

    // =========================================================================
    // Connection Option Management
    // =========================================================================

    /// Get cached or create new MySQL connection options for a server.
    ///
    /// Replaces C connection caching logic at mysql.c lines 181–260 where
    /// cached `MYSQL *` handles are stored in a static linked list keyed by
    /// `server_copy` (host/database/user, sans password).
    ///
    /// Caches `mysql_async::Opts` (parsed connection options) rather than live
    /// connections, since `mysql_async::Conn` objects are tied to specific
    /// tokio runtime instances and cannot survive across `block_on()` calls.
    fn get_or_create_opts(&self, cache_key: &str, spec: &MysqlServerSpec) -> Result<Opts, String> {
        let mut cache = self
            .conn_cache
            .lock()
            .map_err(|e| format!("MySQL connection cache lock poisoned: {}", e))?;

        // Check cache first (C: linked list traversal at lines 181–190)
        if cache.contains_key(cache_key) {
            tracing::debug!("MySQL using cached connection options for {}", cache_key);
            if let Some(opts) = cache.get(cache_key) {
                return Ok(opts.clone());
            }
        }

        // Log new connection details (C: debug_printf at lines 264–270)
        tracing::debug!(
            "MySQL new connection: host={} port={} database={} user={} socket={}",
            spec.host,
            spec.port,
            spec.database.as_deref().unwrap_or("<query>"),
            spec.user,
            spec.socket.as_deref().unwrap_or("<none>"),
        );

        if let Some(ref group) = spec.option_group {
            tracing::debug!("MySQL option group: [{}]", group);
        }

        // Build connection options using mysql_async::OptsBuilder
        let mut builder = OptsBuilder::default()
            .user(Some(&spec.user))
            .pass(Some(&spec.password))
            .tcp_port(spec.port);

        // Set hostname for TCP connections
        if !spec.host.is_empty() {
            builder = builder.ip_or_hostname(&spec.host);
        }

        // Set database if specified (C: empty db → NULL → query defines it)
        if let Some(ref db) = spec.database {
            builder = builder.db_name(Some(db));
        }

        // Set Unix socket if specified (C: mysql_real_connect socket param)
        if let Some(ref sock) = spec.socket {
            builder = builder.socket(Some(sock));
        }

        let opts: Opts = builder.into();
        cache.insert(cache_key.to_string(), opts.clone());

        Ok(opts)
    }

    // =========================================================================
    // Value Extraction
    // =========================================================================

    /// Convert a `mysql_async::Value` to an `Option<String>`.
    ///
    /// Handles all MySQL column types, converting each to its string
    /// representation. `NULL` values are returned as `None`.
    ///
    /// For text protocol queries (`query_iter`), most values arrive as
    /// `Value::Bytes` (MySQL's text encoding). For prepared statement queries
    /// (`exec_iter` with [`Params`]), values arrive in their native typed
    /// variants which are formatted to match MySQL's text representation.
    ///
    /// Replaces C `mysql_fetch_row()` value access where `NULL` → skip
    /// (mysql.c lines 310–340).
    fn value_to_string(val: &Value) -> Option<String> {
        match val {
            Value::NULL => None,
            Value::Bytes(ref b) => Some(String::from_utf8_lossy(b).into_owned()),
            Value::Int(i) => Some(i.to_string()),
            Value::UInt(u) => Some(u.to_string()),
            Value::Float(f) => Some(f.to_string()),
            Value::Double(d) => Some(d.to_string()),
            Value::Date(y, m, d, h, mi, s, us) => {
                if *h == 0 && *mi == 0 && *s == 0 && *us == 0 {
                    // Date only: YYYY-MM-DD
                    Some(format!("{y:04}-{m:02}-{d:02}"))
                } else if *us == 0 {
                    // Date + time without microseconds: YYYY-MM-DD HH:MM:SS
                    Some(format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02}"))
                } else {
                    // Full precision: YYYY-MM-DD HH:MM:SS.ffffff
                    Some(format!(
                        "{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02}.{us:06}"
                    ))
                }
            }
            Value::Time(neg, days, h, mi, s, us) => {
                let sign = if *neg { "-" } else { "" };
                let total_hours = *days * 24 + u32::from(*h);
                if *us == 0 {
                    Some(format!("{sign}{total_hours:02}:{mi:02}:{s:02}"))
                } else {
                    Some(format!("{sign}{total_hours:02}:{mi:02}:{s:02}.{us:06}"))
                }
            }
        }
    }

    /// Safely extract a value from a `Row` at the given column index.
    ///
    /// Returns `None` for out-of-bounds indices and NULL values.
    /// Replaces C `row[i]` access with NULL check at mysql.c lines 310–330.
    fn extract_value(row: &Row, idx: usize) -> Option<String> {
        if idx >= row.len() {
            return None;
        }
        Self::value_to_string(&row[idx])
    }

    // =========================================================================
    // Per-Server Query Execution
    // =========================================================================

    /// Execute a MySQL query against a single server.
    ///
    /// This is the per-server callback for `helpers::sql_perform()`, replacing
    /// the C `perform_mysql_search()` function (mysql.c lines 160–400).
    ///
    /// The `runtime` parameter is a reference to the tokio `Runtime` created
    /// in `find()`, used to bridge async `mysql_async` operations into the
    /// synchronous callback via `block_on()`.
    fn perform_search(
        &self,
        query: &str,
        server: &str,
        _opts: Option<&str>,
        runtime: &tokio::runtime::Runtime,
    ) -> SqlPerformResult {
        // ── Parse server specification ────────────────────────────────────
        let (spec, cache_key) = match Self::parse_server_spec(server) {
            Ok(parsed) => parsed,
            Err(e) => {
                return SqlPerformResult::Deferred {
                    error: e,
                    break_loop: true,
                };
            }
        };

        // ── Get or create connection options ──────────────────────────────
        let opts = match self.get_or_create_opts(&cache_key, &spec) {
            Ok(o) => o,
            Err(e) => {
                return SqlPerformResult::Deferred {
                    error: format!("MySQL connection setup failed: {}", e),
                    break_loop: false,
                };
            }
        };

        // ── Execute query within tokio runtime via block_on() ─────────────
        // Per AAP §0.7.3: tokio runtime scoped to lookup execution only.
        runtime.block_on(async {
            // Establish connection to MySQL server
            // C: mysql_real_connect() at mysql.c lines 262–280
            let mut conn = match Conn::new(opts).await {
                Ok(c) => c,
                Err(e) => {
                    return SqlPerformResult::Deferred {
                        error: format!("MySQL connection failed for {}: {}", cache_key, e),
                        break_loop: false,
                    };
                }
            };

            tracing::debug!("MySQL executing query: {}", query);

            // Execute query using the prepared statement protocol with empty
            // parameters. Params::Empty indicates no parameter bindings are
            // needed, matching the C mysql_real_query() behavior for plain SQL.
            // C: mysql_query(mysql_handle, query) at mysql.c line 285
            let mut query_result = match conn.exec_iter(query, Params::Empty).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("MySQL query error for {}: {}", cache_key, e);
                    return SqlPerformResult::Deferred {
                        error: format!("MySQL: query failed: {} ({})", e, query),
                        break_loop: false,
                    };
                }
            };

            // ── Process query results ─────────────────────────────────────
            let result = Self::process_query_result(&mut query_result).await;

            // Drop query result to release the connection borrow
            drop(query_result);

            // Gracefully disconnect. In C, the connection stays cached in the
            // static linked list. Here, we create fresh connections per query
            // since Conn objects are tied to the tokio runtime instance.
            let _ = conn.disconnect().await;

            result
        })
    }

    /// Process query results into a `SqlPerformResult`.
    ///
    /// Handles both SELECT (row-returning) and DML (non-row) queries:
    ///
    /// - **Columns present** → SELECT: format multi-column results via
    ///   `lf_quote()`, single-column results as raw values. Multiple rows
    ///   separated by `\n`. (C: mysql.c lines 295–360)
    ///
    /// - **No columns** → DML (INSERT/UPDATE/DELETE): return affected row
    ///   count as string, disable caching. (C: mysql.c lines 275–290,
    ///   `*do_cache = 0`)
    ///
    /// - **No columns and zero affected rows** → Return NotFound.
    ///
    /// This function is generic over the MySQL protocol type to support both
    /// text protocol (`query_iter`) and binary protocol (`exec_iter`) results.
    async fn process_query_result<'a, 'b, P: mysql_async::prelude::Protocol>(
        query_result: &mut mysql_async::QueryResult<'a, 'b, P>,
    ) -> SqlPerformResult {
        // Get column definitions for the current result set
        // C: mysql_num_fields(mysql_result) and mysql_fetch_fields()
        let columns = query_result.columns_ref();

        if columns.is_empty() {
            // ── DML statement (INSERT/UPDATE/DELETE) ──────────────────────
            // C: mysql_field_count(mysql_handle) == 0 → data-changing stmt
            // (mysql.c lines 275–290)
            let affected = query_result.affected_rows();
            if affected > 0 {
                tracing::debug!(
                    "MySQL: command does not return data but was successful. \
                     Rows affected: {}",
                    affected
                );
                // C: *do_cache = 0 — disable caching for data-changing stmts
                SqlPerformResult::Found {
                    result: affected.to_string(),
                    cacheable: false,
                }
            } else {
                SqlPerformResult::NotFound
            }
        } else {
            // ── SELECT statement ─────────────────────────────────────────
            // Collect column names (C: mysql_fetch_fields at lines 295–300)
            let column_names: Vec<String> =
                columns.iter().map(|c| c.name_str().to_string()).collect();
            let num_columns = column_names.len();

            // Collect all rows from the result set
            // C: mysql_fetch_row() loop at lines 305–360
            let rows: Vec<Row> = match query_result.collect().await {
                Ok(r) => r,
                Err(e) => {
                    return SqlPerformResult::Deferred {
                        error: format!("MySQL: result collection failed: {}", e),
                        break_loop: false,
                    };
                }
            };

            tracing::debug!(
                "MySQL: query returned {} rows, {} columns",
                rows.len(),
                num_columns
            );

            // C: mysql_num_rows == 0 → FAIL (NotFound)
            if rows.is_empty() {
                return SqlPerformResult::NotFound;
            }

            let mut result = String::new();
            let mut has_data = false;

            for (row_idx, row) in rows.iter().enumerate() {
                // Separate multiple rows with newline (C: line 340)
                if row_idx > 0 {
                    result.push('\n');
                }

                if num_columns == 1 {
                    // ── Single column: return raw value ───────────────────
                    // C: mysql.c lines 310–320 — NULL → nothing appended
                    if let Some(val) = Self::extract_value(row, 0) {
                        has_data = true;
                        result.push_str(&val);
                    }
                } else {
                    // ── Multiple columns: format via lf_quote ─────────────
                    // C: mysql.c lines 325–340 — lf_quote(name, value, ...)
                    for (col_idx, name) in column_names.iter().enumerate() {
                        let val = Self::extract_value(row, col_idx);
                        lf_quote(name, val.as_deref(), &mut result);
                        has_data = true;
                    }
                }
            }

            if has_data {
                SqlPerformResult::Found {
                    result,
                    cacheable: true,
                }
            } else {
                SqlPerformResult::NotFound
            }
        }
    }
}

// =============================================================================
// LookupDriver Trait Implementation
// =============================================================================

impl LookupDriver for MysqlLookup {
    /// Open a MySQL lookup connection.
    ///
    /// Returns a dummy handle since MySQL is a query-style lookup and actual
    /// connections are established on-demand in `find()`.
    ///
    /// C equivalent: `mysql_open()` (mysql.c lines 74–78) returns
    /// `(void *)(1)`.
    fn open(&self, _filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        Ok(Box::new(()))
    }

    /// Check is a no-op for query-style lookups.
    ///
    /// C equivalent: `check` function pointer is NULL in the `lookup_info`
    /// struct.
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

    /// Execute a MySQL query with multi-server failover.
    ///
    /// Replaces C `mysql_find()` (mysql.c lines 396–420) which delegates to
    /// `lf_sqlperform()` with `perform_mysql_search` as the callback.
    ///
    /// Creates a scoped `tokio::runtime::Runtime` per invocation to bridge
    /// async `mysql_async` operations into the synchronous LookupDriver
    /// interface (per AAP §0.7.3).
    fn find(
        &self,
        _handle: &LookupHandle,
        _filename: Option<&str>,
        key_or_query: &str,
        options: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        // Create a scoped tokio runtime for this lookup invocation.
        // Per AAP §0.7.3: "A tokio Runtime is created per find() invocation
        // to bridge mysql_async async Conn operations into the synchronous
        // fork-per-connection model. MUST NOT be used for daemon event loop."
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| DriverError::TempFail(format!("failed to create tokio runtime: {}", e)))?;

        // Build the per-server callback closure that captures both `self`
        // (for connection cache access) and `runtime` (for block_on bridging).
        let callback = |query: &str, server: &str, opts: Option<&str>| -> SqlPerformResult {
            self.perform_search(query, server, opts, &runtime)
        };

        // Delegate to sql_perform() for multi-server failover iteration.
        // C: lf_sqlperform(US"MySQL", US"mysql_servers",
        //                   mysql_servers, query, ...)
        //
        // Note: `opt_server_list` is None because the global `mysql_servers`
        // configuration value is not available at the lookup driver level.
        // Server lists come from the query itself (legacy inline syntax) or
        // the `options` parameter (modern `servers=...` syntax).
        match sql_perform(
            "MySQL",
            "mysql_servers",
            None,
            key_or_query,
            options,
            &callback,
        ) {
            Ok((result, cacheable)) => {
                if result.is_empty() {
                    // sql_perform returns empty string for NotFound
                    Ok(LookupResult::NotFound)
                } else {
                    // Determine cache TTL: None = default caching,
                    // Some(0) = do not cache (for DML command results)
                    let cache_ttl = if cacheable { None } else { Some(0) };
                    Ok(LookupResult::Found {
                        value: result,
                        cache_ttl,
                    })
                }
            }
            Err(e) => {
                // All servers failed or configuration error → DEFER
                Ok(LookupResult::Deferred {
                    message: e.to_string(),
                })
            }
        }
    }

    /// Close is a no-op — connections are created per-query.
    ///
    /// C equivalent: `close` function pointer is NULL (mysql.c line 495).
    fn close(&self, _handle: LookupHandle) {
        // No-op: connections are created per-query within block_on() and
        // disconnected at the end of each perform_search() call.
    }

    /// Close all cached MySQL connection options.
    ///
    /// Replaces C `mysql_tidy()` (mysql.c lines 122–143) which iterates the
    /// static linked list calling `mysql_close()` on each cached connection.
    ///
    /// Clears the `HashMap`, dropping all cached `Opts` entries. Subsequent
    /// lookups will re-parse server specs and create fresh options.
    fn tidy(&self) {
        match self.conn_cache.lock() {
            Ok(mut cache) => {
                for key in cache.keys() {
                    tracing::debug!("close MySQL connection: {}", key);
                }
                cache.clear();
            }
            Err(e) => {
                tracing::warn!("MySQL tidy: failed to lock connection cache: {}", e);
            }
        }
    }

    /// Quote a string for safe use in MySQL queries.
    ///
    /// Replaces C `mysql_quote()` (mysql.c lines 430–470):
    /// - Newline: `\n` → `\\n`
    /// - Tab: `\t` → `\\t`
    /// - Carriage return: `\r` → `\\r`
    /// - Backspace: `\b` → `\\b`
    /// - Single quote: `'` → `\'` (MySQL-style backslash escaping)
    /// - Double quote: `"` → `\"`
    /// - Backslash: `\` → `\\`
    /// - All other characters pass through unchanged
    ///
    /// Returns `None` if `additional` is `Some` (no options recognized),
    /// matching C behavior where `if (opt) return NULL;` (line 432).
    ///
    /// Note: MySQL uses backslash-escaping for single quotes (`'` → `\'`),
    /// which differs from PostgreSQL which doubles them (`'` → `''`).
    fn quote(&self, value: &str, additional: Option<&str>) -> Option<String> {
        // C: if (opt != NULL) return NULL; — no options recognized
        if additional.is_some() {
            return None;
        }

        let mut result = String::with_capacity(value.len() * 2);

        for ch in value.chars() {
            match ch {
                // C: mysql.c lines 440–465 — character-by-character escaping
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
                    // Backspace (\b) — ASCII 0x08
                    result.push('\\');
                    result.push('b');
                }
                '\'' => {
                    // MySQL-specific: backslash-escape single quotes
                    result.push('\\');
                    result.push('\'');
                }
                '"' => {
                    result.push('\\');
                    result.push('"');
                }
                '\\' => {
                    result.push('\\');
                    result.push('\\');
                }
                _ => result.push(ch),
            }
        }

        Some(result)
    }

    /// Report the MySQL library version for `-bV` output.
    ///
    /// Replaces C `mysql_version_report()` (mysql.c lines 490–510) which
    /// calls `mysql_get_client_info()` to report the runtime libmysqlclient
    /// version.
    ///
    /// Since the Rust implementation uses `mysql_async` (a native Rust MySQL
    /// client) instead of `libmysqlclient`, we report the crate version.
    fn version_report(&self) -> Option<String> {
        // C: string_fmt_append(g, "Library version: MySQL: Compile: %s [%s]\n",
        //                       MYSQL_SERVER_VERSION, MYSQL_COMPILATION_COMMENT);
        //    string_fmt_append(g, "                       Runtime: %s\n",
        //                       mysql_get_client_info());
        Some("Library version: MySQL: mysql_async (Rust native client)\n".to_string())
    }

    /// Return the lookup type flags.
    ///
    /// MySQL is a query-style lookup (C: `lookup_querystyle` at mysql.c
    /// line 490).
    fn lookup_type(&self) -> LookupType {
        LookupType::QUERY_STYLE
    }

    /// Return the driver name for configuration file matching.
    ///
    /// C: `US"mysql"` at mysql.c line 489.
    fn driver_name(&self) -> &str {
        "mysql"
    }
}

// =============================================================================
// Compile-Time Driver Registration
// =============================================================================

// Register the MySQL lookup driver with the inventory-based driver registry
// at compile time.
//
// Replaces C module registration at mysql.c lines 489–510:
//   static lookup_info _lookup_info = {
//     .name = US"mysql",
//     .type = lookup_querystyle,
//     .open = mysql_open, ...
//   };
//   lookup_module_info mysql_lookup_module_info = {
//     LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1
//   };
inventory::submit! {
    LookupDriverFactory {
        name: "mysql",
        create: || Box::new(MysqlLookup::new()),
        lookup_type: LookupType::QUERY_STYLE,
        avail_string: Some("mysql (MySQL/MariaDB via mysql_async)"),
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constructor Tests ─────────────────────────────────────────────────

    #[test]
    fn test_new_creates_empty_cache() {
        let lookup = MysqlLookup::new();
        let cache = lookup.conn_cache.lock().unwrap();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_default_is_same_as_new() {
        let lookup = MysqlLookup::default();
        assert_eq!(lookup.driver_name(), "mysql");
    }

    // ── Driver Metadata Tests ─────────────────────────────────────────────

    #[test]
    fn test_driver_name() {
        let lookup = MysqlLookup::new();
        assert_eq!(lookup.driver_name(), "mysql");
    }

    #[test]
    fn test_lookup_type_is_query_style() {
        let lookup = MysqlLookup::new();
        assert!(lookup.lookup_type().is_query_style());
        assert!(!lookup.lookup_type().is_single_key());
    }

    #[test]
    fn test_version_report() {
        let lookup = MysqlLookup::new();
        let report = lookup.version_report();
        assert!(report.is_some());
        let text = report.unwrap();
        assert!(text.contains("MySQL"));
        assert!(text.contains("mysql_async"));
    }

    // ── Open/Check/Close Tests ────────────────────────────────────────────

    #[test]
    fn test_open_returns_handle() {
        let lookup = MysqlLookup::new();
        let handle = lookup.open(None);
        assert!(handle.is_ok());
    }

    #[test]
    fn test_check_returns_true() {
        let lookup = MysqlLookup::new();
        let handle = lookup.open(None).unwrap();
        let result = lookup.check(&handle, None, 0, &[], &[]);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_close_is_noop() {
        let lookup = MysqlLookup::new();
        let handle = lookup.open(None).unwrap();
        // Should not panic
        lookup.close(handle);
    }

    // ── Tidy Tests ────────────────────────────────────────────────────────

    #[test]
    fn test_tidy_clears_cache() {
        let lookup = MysqlLookup::new();
        // Insert a dummy entry into the cache
        {
            let mut cache = lookup.conn_cache.lock().unwrap();
            let dummy_opts: Opts = OptsBuilder::default().into();
            cache.insert("test/db/user".to_string(), dummy_opts);
            assert_eq!(cache.len(), 1);
        }
        lookup.tidy();
        let cache = lookup.conn_cache.lock().unwrap();
        assert!(cache.is_empty());
    }

    // ── Quote Tests ───────────────────────────────────────────────────────

    #[test]
    fn test_quote_simple_string() {
        let lookup = MysqlLookup::new();
        let result = lookup.quote("hello", None);
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn test_quote_with_single_quotes() {
        let lookup = MysqlLookup::new();
        let result = lookup.quote("it's", None);
        // MySQL uses backslash-escaping: ' → \'
        assert_eq!(result, Some("it\\'s".to_string()));
    }

    #[test]
    fn test_quote_with_double_quotes() {
        let lookup = MysqlLookup::new();
        let result = lookup.quote("say \"hello\"", None);
        assert_eq!(result, Some("say \\\"hello\\\"".to_string()));
    }

    #[test]
    fn test_quote_with_backslash() {
        let lookup = MysqlLookup::new();
        let result = lookup.quote("path\\to\\file", None);
        assert_eq!(result, Some("path\\\\to\\\\file".to_string()));
    }

    #[test]
    fn test_quote_with_control_chars() {
        let lookup = MysqlLookup::new();
        let result = lookup.quote("line1\nline2\ttab\r\x08back", None);
        assert_eq!(result, Some("line1\\nline2\\ttab\\r\\bback".to_string()));
    }

    #[test]
    fn test_quote_empty_string() {
        let lookup = MysqlLookup::new();
        let result = lookup.quote("", None);
        assert_eq!(result, Some(String::new()));
    }

    #[test]
    fn test_quote_returns_none_with_options() {
        let lookup = MysqlLookup::new();
        let result = lookup.quote("hello", Some("opt"));
        assert!(result.is_none());
    }

    // ── Server Spec Parsing Tests ─────────────────────────────────────────

    #[test]
    fn test_parse_simple_spec() {
        let (spec, key) = MysqlLookup::parse_server_spec("localhost/mydb/user/pass").unwrap();
        assert_eq!(spec.host, "localhost");
        assert_eq!(spec.port, 3306);
        assert_eq!(spec.database, Some("mydb".to_string()));
        assert_eq!(spec.user, "user");
        assert_eq!(spec.password, "pass");
        assert!(spec.socket.is_none());
        assert!(spec.option_group.is_none());
        assert_eq!(key, "localhost/mydb/user");
    }

    #[test]
    fn test_parse_spec_with_port() {
        let (spec, _key) =
            MysqlLookup::parse_server_spec("myhost:3307/testdb/admin/secret").unwrap();
        assert_eq!(spec.host, "myhost");
        assert_eq!(spec.port, 3307);
        assert_eq!(spec.database, Some("testdb".to_string()));
        assert_eq!(spec.user, "admin");
        assert_eq!(spec.password, "secret");
    }

    #[test]
    fn test_parse_spec_with_socket() {
        let (spec, _key) =
            MysqlLookup::parse_server_spec("localhost(/var/run/mysqld/mysqld.sock)/mydb/user/pass")
                .unwrap();
        assert_eq!(spec.host, "localhost");
        assert_eq!(spec.socket, Some("/var/run/mysqld/mysqld.sock".to_string()));
        assert_eq!(spec.database, Some("mydb".to_string()));
    }

    #[test]
    fn test_parse_spec_with_group() {
        let (spec, _key) =
            MysqlLookup::parse_server_spec("localhost[exim]/mydb/user/pass").unwrap();
        assert_eq!(spec.host, "localhost");
        assert_eq!(spec.option_group, Some("exim".to_string()));
    }

    #[test]
    fn test_parse_spec_with_socket_and_group() {
        let (spec, _key) =
            MysqlLookup::parse_server_spec("myhost:3307(/tmp/mysql.sock)[mygroup]/db/usr/pw")
                .unwrap();
        assert_eq!(spec.host, "myhost");
        assert_eq!(spec.port, 3307);
        assert_eq!(spec.socket, Some("/tmp/mysql.sock".to_string()));
        assert_eq!(spec.option_group, Some("mygroup".to_string()));
        assert_eq!(spec.database, Some("db".to_string()));
        assert_eq!(spec.user, "usr");
        assert_eq!(spec.password, "pw");
    }

    #[test]
    fn test_parse_spec_empty_database() {
        let (spec, _key) = MysqlLookup::parse_server_spec("localhost//user/pass").unwrap();
        assert!(spec.database.is_none());
    }

    #[test]
    fn test_parse_spec_ipv6() {
        let (spec, _key) = MysqlLookup::parse_server_spec("::1.3306/mydb/user/pass").unwrap();
        assert_eq!(spec.host, "::1");
        assert_eq!(spec.port, 3306);
    }

    #[test]
    fn test_parse_spec_ipv6_no_port() {
        let (spec, _key) = MysqlLookup::parse_server_spec("::1/mydb/user/pass").unwrap();
        assert_eq!(spec.host, "::1");
        assert_eq!(spec.port, 3306);
    }

    #[test]
    fn test_parse_spec_incomplete() {
        let result = MysqlLookup::parse_server_spec("localhost/mydb");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_spec_no_slashes() {
        let result = MysqlLookup::parse_server_spec("localhost");
        assert!(result.is_err());
    }

    // ── Host:Port Parsing Tests ───────────────────────────────────────────

    #[test]
    fn test_parse_host_port_plain() {
        let (host, port) = MysqlLookup::parse_host_port("myhost");
        assert_eq!(host, "myhost");
        assert_eq!(port, 3306);
    }

    #[test]
    fn test_parse_host_port_with_port() {
        let (host, port) = MysqlLookup::parse_host_port("myhost:3307");
        assert_eq!(host, "myhost");
        assert_eq!(port, 3307);
    }

    #[test]
    fn test_parse_host_port_ipv6_with_period_port() {
        let (host, port) = MysqlLookup::parse_host_port("::1.3307");
        assert_eq!(host, "::1");
        assert_eq!(port, 3307);
    }

    #[test]
    fn test_parse_host_port_ipv6_no_port() {
        let (host, port) = MysqlLookup::parse_host_port("fe80::1");
        assert_eq!(host, "fe80::1");
        assert_eq!(port, 3306);
    }

    #[test]
    fn test_parse_host_port_empty() {
        let (host, port) = MysqlLookup::parse_host_port("");
        assert!(host.is_empty());
        assert_eq!(port, 3306);
    }

    // ── Value Conversion Tests ────────────────────────────────────────────

    #[test]
    fn test_value_to_string_null() {
        assert!(MysqlLookup::value_to_string(&Value::NULL).is_none());
    }

    #[test]
    fn test_value_to_string_bytes() {
        let val = Value::Bytes(b"hello world".to_vec());
        assert_eq!(
            MysqlLookup::value_to_string(&val),
            Some("hello world".to_string())
        );
    }

    #[test]
    fn test_value_to_string_int() {
        let val = Value::Int(-42);
        assert_eq!(MysqlLookup::value_to_string(&val), Some("-42".to_string()));
    }

    #[test]
    fn test_value_to_string_uint() {
        let val = Value::UInt(12345);
        assert_eq!(
            MysqlLookup::value_to_string(&val),
            Some("12345".to_string())
        );
    }

    #[test]
    fn test_value_to_string_float() {
        let val = Value::Float(3.14);
        let result = MysqlLookup::value_to_string(&val);
        assert!(result.is_some());
        let text = result.unwrap();
        assert!(text.starts_with("3.14"));
    }

    #[test]
    fn test_value_to_string_double() {
        let val = Value::Double(2.718281828);
        let result = MysqlLookup::value_to_string(&val);
        assert!(result.is_some());
        let text = result.unwrap();
        assert!(text.starts_with("2.718281828"));
    }

    #[test]
    fn test_value_to_string_date_only() {
        let val = Value::Date(2024, 1, 15, 0, 0, 0, 0);
        assert_eq!(
            MysqlLookup::value_to_string(&val),
            Some("2024-01-15".to_string())
        );
    }

    #[test]
    fn test_value_to_string_datetime() {
        let val = Value::Date(2024, 6, 30, 14, 30, 0, 0);
        assert_eq!(
            MysqlLookup::value_to_string(&val),
            Some("2024-06-30 14:30:00".to_string())
        );
    }

    #[test]
    fn test_value_to_string_datetime_with_micros() {
        let val = Value::Date(2024, 12, 25, 23, 59, 59, 123456);
        assert_eq!(
            MysqlLookup::value_to_string(&val),
            Some("2024-12-25 23:59:59.123456".to_string())
        );
    }

    #[test]
    fn test_value_to_string_time() {
        let val = Value::Time(false, 0, 12, 30, 45, 0);
        assert_eq!(
            MysqlLookup::value_to_string(&val),
            Some("12:30:45".to_string())
        );
    }

    #[test]
    fn test_value_to_string_time_negative() {
        let val = Value::Time(true, 0, 1, 30, 0, 0);
        assert_eq!(
            MysqlLookup::value_to_string(&val),
            Some("-01:30:00".to_string())
        );
    }

    #[test]
    fn test_value_to_string_time_with_days() {
        let val = Value::Time(false, 2, 5, 0, 0, 0);
        // 2 days * 24 + 5 = 53 hours
        assert_eq!(
            MysqlLookup::value_to_string(&val),
            Some("53:00:00".to_string())
        );
    }

    #[test]
    fn test_value_to_string_time_with_micros() {
        let val = Value::Time(false, 0, 10, 20, 30, 500000);
        assert_eq!(
            MysqlLookup::value_to_string(&val),
            Some("10:20:30.500000".to_string())
        );
    }

    // ── Bracket/Paren Extraction Tests ────────────────────────────────────

    #[test]
    fn test_extract_bracket_group_present() {
        let (rest, group) = MysqlLookup::extract_bracket_group("localhost[mygroup]");
        assert_eq!(rest, "localhost");
        assert_eq!(group, Some("mygroup".to_string()));
    }

    #[test]
    fn test_extract_bracket_group_absent() {
        let (rest, group) = MysqlLookup::extract_bracket_group("localhost");
        assert_eq!(rest, "localhost");
        assert!(group.is_none());
    }

    #[test]
    fn test_extract_paren_socket_present() {
        let (rest, socket) = MysqlLookup::extract_paren_socket("localhost(/tmp/mysql.sock)");
        assert_eq!(rest, "localhost");
        assert_eq!(socket, Some("/tmp/mysql.sock".to_string()));
    }

    #[test]
    fn test_extract_paren_socket_absent() {
        let (rest, socket) = MysqlLookup::extract_paren_socket("localhost");
        assert_eq!(rest, "localhost");
        assert!(socket.is_none());
    }

    // ── Connection Option Cache Tests ─────────────────────────────────────

    #[test]
    fn test_get_or_create_opts_caches_entry() {
        let lookup = MysqlLookup::new();
        let spec = MysqlServerSpec {
            host: "localhost".to_string(),
            port: 3306,
            database: Some("testdb".to_string()),
            user: "testuser".to_string(),
            password: "testpass".to_string(),
            socket: None,
            option_group: None,
        };

        let result = lookup.get_or_create_opts("localhost/testdb/testuser", &spec);
        assert!(result.is_ok());

        // Verify it's cached
        let cache = lookup.conn_cache.lock().unwrap();
        assert!(cache.contains_key("localhost/testdb/testuser"));
    }

    #[test]
    fn test_get_or_create_opts_returns_cached() {
        let lookup = MysqlLookup::new();
        let spec = MysqlServerSpec {
            host: "localhost".to_string(),
            port: 3306,
            database: Some("db".to_string()),
            user: "usr".to_string(),
            password: "pw".to_string(),
            socket: None,
            option_group: None,
        };

        // First call creates
        let opts1 = lookup.get_or_create_opts("localhost/db/usr", &spec);
        assert!(opts1.is_ok());

        // Second call uses cache
        let opts2 = lookup.get_or_create_opts("localhost/db/usr", &spec);
        assert!(opts2.is_ok());

        // Cache should still have exactly one entry
        let cache = lookup.conn_cache.lock().unwrap();
        assert_eq!(cache.len(), 1);
    }

    // ── DriverError Variant Usage Tests ───────────────────────────────────

    #[test]
    fn test_driver_error_temp_fail() {
        let err = DriverError::TempFail("tokio runtime failed".to_string());
        assert!(err.to_string().contains("tokio runtime failed"));
    }

    #[test]
    fn test_driver_error_execution_failed() {
        let err = DriverError::ExecutionFailed("query syntax error".to_string());
        assert!(err.to_string().contains("query syntax error"));
    }

    #[test]
    fn test_driver_error_config_error() {
        let err = DriverError::ConfigError("bad server spec".to_string());
        assert!(err.to_string().contains("bad server spec"));
    }
}
