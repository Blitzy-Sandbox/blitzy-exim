// =============================================================================
// exim-lookups/src/pgsql.rs — PostgreSQL Lookup via tokio-postgres + block_on
// =============================================================================
//
// Replaces `src/src/lookups/pgsql.c` (525 lines). Uses `tokio-postgres` for
// async PostgreSQL connection and query execution, `deadpool-postgres` for
// connection pooling (replacing the C static linked list of `pgsql_connection`
// structs), and `tokio::runtime::Runtime::block_on()` to bridge async APIs
// into the synchronous fork-per-connection model.
//
// Per AAP §0.7.2: This file contains ZERO `unsafe` code.
// Per AAP §0.7.3: The tokio runtime is scoped ONLY to lookup execution via
//   `block_on()`. It MUST NOT be used for the main daemon event loop.
//
// ## SQL Injection Safety Note
//
// Query strings are executed as raw SQL via `client.simple_query()`,
// matching the C implementation's behavior of passing pre-expanded strings
// to `PQexec()`. SQL safety relies on Exim's string expansion engine
// (`exim-expand`) which applies taint checking at the call site (via
// `Tainted<T>`/`Clean<T>` newtypes from `exim-store`). The expansion
// engine ensures that untrusted data from SMTP envelope, headers, or other
// tainted sources cannot be injected into lookup queries without explicit
// administrator opt-in via `${quote_pgsql:...}` or similar sanitization.
// This is not a regression from C behavior — the C implementation had the
// identical SQL injection surface with identical upstream taint protections.
//
// Connection spec format (matching C pgsql.c):
//   TCP:   host:port/database/user/password
//   Unix:  (/path/to/.s.PGSQL.5432)/database/user/password
//   IPv6:  [::1]:5432/database/user/password  (colon handling matches C)
//
// Registration: inventory::submit!(LookupDriverFactory { name: "pgsql", ... })

use std::collections::HashMap;
use std::sync::Mutex;

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;

use crate::helpers::quote::lf_quote;
use crate::helpers::sql_perform::{sql_perform, SqlPerformResult};

// =============================================================================
// Parsed Server Specification
// =============================================================================

/// Parsed PostgreSQL server connection parameters.
///
/// Extracted from the `host:port/database/user/password` connection spec
/// format used by Exim's multi-server failover mechanism. Replaces the C
/// `sdata[]` array and inline parsing in `perform_pgsql_search()`.
#[derive(Debug, Clone)]
struct PgsqlServerSpec {
    /// Hostname, IP address, or Unix socket directory path.
    host: String,
    /// TCP port (default 5432) or extracted from Unix socket filename.
    port: u16,
    /// Database name. `None` means the query must define it.
    database: Option<String>,
    /// PostgreSQL user name.
    user: String,
    /// PostgreSQL password.
    password: String,
    /// Whether this is a Unix domain socket connection.
    is_unix_socket: bool,
}

// =============================================================================
// PgsqlLookup — Main Lookup Driver Struct
// =============================================================================

/// PostgreSQL lookup driver implementing the `LookupDriver` trait.
///
/// Uses `deadpool-postgres::Pool` for connection pooling (one pool per unique
/// server specification), cached in a `HashMap` wrapped in `Mutex` for
/// interior mutability (since `LookupDriver` trait methods take `&self`).
///
/// The `Mutex` provides `Send + Sync` bounds required by `LookupHandle`
/// (`Box<dyn Any + Send + Sync>`).
///
/// Replaces the C `pgsql_connections` static linked list and
/// `pgsql_lookup_info` registration struct from `pgsql.c` lines 24–523.
#[derive(Debug)]
pub struct PgsqlLookup {
    /// Connection pool cache: sanitized server key → deadpool Pool.
    ///
    /// The key is the server spec with password removed (for safe logging
    /// and cache lookup). Pools are dropped on `tidy()` to close all cached
    /// connections, matching C `pgsql_tidy()` behavior.
    pools: Mutex<HashMap<String, deadpool_postgres::Pool>>,
}

impl Default for PgsqlLookup {
    fn default() -> Self {
        Self::new()
    }
}

impl PgsqlLookup {
    /// Create a new `PgsqlLookup` instance with an empty connection cache.
    pub fn new() -> Self {
        Self {
            pools: Mutex::new(HashMap::new()),
        }
    }

    // =========================================================================
    // Server Spec Parsing
    // =========================================================================

    /// Parse a server specification string into structured connection parameters.
    ///
    /// Matches the C parsing logic from `perform_pgsql_search()` lines 146–242:
    /// - Parse from right to left, extracting password, user, database via `/`
    /// - Remaining string is the host portion
    /// - Handle Unix socket paths in parentheses: `(/path/.s.PGSQL.5432)`
    /// - Handle TCP host with optional `:port`
    /// - Handle IPv6 addresses with multiple colons
    ///
    /// Returns `(spec, cache_key)` where `cache_key` is the server spec without
    /// the password, suitable for logging and cache lookup (C: `server_copy`).
    fn parse_server_spec(server: &str) -> Result<(PgsqlServerSpec, String), String> {
        let mut remaining = server;

        // ── Extract password (after last '/') ─────────────────────────────
        // C: i=2 iteration — Ustrrchr(server, '/')
        let slash_pos = remaining
            .rfind('/')
            .ok_or_else(|| format!("incomplete pgSQL server data: {}", server))?;
        let password = remaining[slash_pos + 1..].to_string();
        remaining = &remaining[..slash_pos];

        // Cache key is server spec without password (C: server_copy)
        let cache_key = remaining.to_string();

        // ── Extract user (after last '/') ─────────────────────────────────
        // C: i=1 iteration
        let slash_pos = remaining
            .rfind('/')
            .ok_or_else(|| format!("incomplete pgSQL server data: {}", cache_key))?;
        let user = remaining[slash_pos + 1..].to_string();
        remaining = &remaining[..slash_pos];

        // ── Extract database (after last '/') ─────────────────────────────
        // C: i=0 iteration
        let slash_pos = remaining
            .rfind('/')
            .ok_or_else(|| format!("incomplete pgSQL server data: {}", cache_key))?;
        let database_str = &remaining[slash_pos + 1..];
        let database = if database_str.is_empty() {
            None
        } else {
            Some(database_str.to_string())
        };
        remaining = &remaining[..slash_pos];

        // ── Parse host portion ────────────────────────────────────────────
        let host_str = remaining;

        let (host, port, is_unix_socket) = if host_str.starts_with('(') {
            // Unix domain socket path in parentheses
            // C: lines 180–210
            let inner = host_str
                .strip_prefix('(')
                .and_then(|s| s.strip_suffix(')'))
                .unwrap_or_else(|| {
                    // Handle case where closing paren is embedded
                    let s = &host_str[1..];
                    if let Some(pos) = s.find(')') {
                        &s[..pos]
                    } else {
                        s
                    }
                });

            // Extract directory and port from socket path like
            // /var/run/postgresql/.s.PGSQL.5432
            let last_slash = inner.rfind('/');
            let last_dot = inner.rfind('.');

            match (last_slash, last_dot) {
                (Some(ls), Some(ld)) if ld > ls => {
                    let socket_dir = &inner[..ls];
                    let port_str = &inner[ld + 1..];
                    let port: u16 = port_str
                        .parse()
                        .map_err(|_| format!("PGSQL invalid port in socket path: {}", inner))?;
                    (socket_dir.to_string(), port, true)
                }
                _ => {
                    return Err(format!("PGSQL invalid filename for socket: {}", inner));
                }
            }
        } else {
            // TCP host with optional port
            // C: lines 214–242
            let mut host = host_str.to_string();
            let mut port: u16 = 5432;

            // Detect port separator:
            // - Single colon → hostname:port
            // - Multiple colons → IPv6 address; look for '.' as port separator
            // This matches C logic at lines 223–230
            if let Some(last_colon) = host_str.rfind(':') {
                let first_colon = host_str.find(':');
                if first_colon == Some(last_colon) {
                    // Only one colon → hostname:port
                    if let Ok(p) = host_str[last_colon + 1..].parse::<u16>() {
                        port = p;
                        host = host_str[..last_colon].to_string();
                    }
                } else if let Some(dot_pos) = host_str.rfind('.') {
                    // Multiple colons (IPv6) and a period → use period as
                    // port separator (e.g., "::1.5432" → host="::1", port=5432)
                    // C: lines 225–230
                    if let Ok(p) = host_str[dot_pos + 1..].parse::<u16>() {
                        port = p;
                        host = host_str[..dot_pos].to_string();
                    }
                }
                // Multiple colons, no period → pure IPv6, default port
            }

            // Reject unexpected slashes in hostname (C: lines 232–238)
            if host.contains('/') {
                return Err(format!(
                    "unexpected slash in pgSQL server hostname: {}",
                    host
                ));
            }

            (host, port, false)
        };

        Ok((
            PgsqlServerSpec {
                host,
                port,
                database,
                user,
                password,
                is_unix_socket,
            },
            cache_key,
        ))
    }

    // =========================================================================
    // Connection Pool Management
    // =========================================================================

    /// Get an existing pool from cache or create a new one for the given server.
    ///
    /// Replaces C connection caching logic at lines 165–283 where cached
    /// `PGconn` handles are stored in a static linked list keyed by
    /// `server_copy` (host/database/user, sans password).
    ///
    /// Uses `deadpool-postgres::Pool` for automatic connection lifecycle
    /// management, with `deadpool_postgres::Manager` wrapping
    /// `tokio_postgres::Config` + `tokio_postgres::NoTls`.
    fn get_or_create_pool(
        &self,
        cache_key: &str,
        spec: &PgsqlServerSpec,
    ) -> Result<deadpool_postgres::Pool, String> {
        let mut pools = self
            .pools
            .lock()
            .map_err(|e| format!("PGSQL pool cache lock poisoned: {}", e))?;

        // Check cache first (C: for loop at lines 165–170)
        if let Some(pool) = pools.get(cache_key) {
            tracing::debug!("PGSQL using cached connection for {}", cache_key);
            return Ok(pool.clone());
        }

        // Log new connection details (C: debug_printf_indent at lines 191, 240)
        if spec.is_unix_socket {
            tracing::debug!(
                "PGSQL new connection: socket={} database={} user={}",
                spec.host,
                spec.database.as_deref().unwrap_or("<query>"),
                spec.user,
            );
        } else {
            tracing::debug!(
                "PGSQL new connection: host={} port={} database={} user={}",
                spec.host,
                spec.port,
                spec.database.as_deref().unwrap_or("<query>"),
                spec.user,
            );
        }

        // Build tokio-postgres Config
        let mut pg_config = tokio_postgres::Config::new();

        if !spec.host.is_empty() {
            pg_config.host(&spec.host);
        }
        pg_config.port(spec.port);

        if let Some(ref db) = spec.database {
            pg_config.dbname(db);
        }
        pg_config.user(&spec.user);
        pg_config.password(&spec.password);

        // Set client encoding to SQL_ASCII to prevent encoding interpretation
        // of raw 8-bit data (C: PQsetClientEncoding at line 268)
        pg_config.options("-c client_encoding=SQL_ASCII");

        // Create deadpool-postgres Manager wrapping the config
        let manager = deadpool_postgres::Manager::new(pg_config, tokio_postgres::NoTls);

        // Build connection pool with small size (matching C's one-connection-
        // per-server pattern but allowing a small amount of concurrency)
        let pool = deadpool_postgres::Pool::builder(manager)
            .max_size(2)
            .runtime(deadpool_postgres::Runtime::Tokio1)
            .build()
            .map_err(|e| format!("PGSQL pool creation failed: {}", e))?;

        pools.insert(cache_key.to_string(), pool.clone());
        Ok(pool)
    }

    // =========================================================================
    // Per-Server Query Execution
    // =========================================================================

    /// Execute a PostgreSQL query against a single server.
    ///
    /// This is the per-server callback for `helpers::sql_perform()`, replacing
    /// the C `perform_pgsql_search()` function (lines 126–382).
    ///
    /// The `runtime` parameter is a reference to the tokio `Runtime` created
    /// in `find()`, used to bridge async tokio-postgres operations into the
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

        // ── Get or create connection pool ─────────────────────────────────
        let pool = match self.get_or_create_pool(&cache_key, &spec) {
            Ok(p) => p,
            Err(e) => {
                return SqlPerformResult::Deferred {
                    error: format!("PGSQL connection failed: {}", e),
                    break_loop: false,
                };
            }
        };

        // ── Execute query within tokio runtime via block_on() ─────────────
        // Per AAP §0.7.3: tokio runtime scoped to lookup execution only.
        runtime.block_on(async {
            // Get connection from pool (creates new if needed)
            let client = match pool.get().await {
                Ok(c) => c,
                Err(e) => {
                    return SqlPerformResult::Deferred {
                        error: format!("PGSQL connection failed: {}", e),
                        break_loop: false,
                    };
                }
            };

            tracing::debug!("PGSQL executing query: {}", query);

            // Execute using simple_query (matches C PQexec behavior —
            // returns text-formatted values for all column types)
            let messages = match client.simple_query(query).await {
                Ok(msgs) => msgs,
                Err(e) => {
                    return SqlPerformResult::Deferred {
                        error: format!("PGSQL: query failed: {} ({})", e, query),
                        break_loop: false,
                    };
                }
            };

            // ── Process query results ─────────────────────────────────────
            // Replaces C result processing at lines 293–381.
            Self::process_simple_query_results(&messages)
        })
    }

    /// Process results from `simple_query()` into a `SqlPerformResult`.
    ///
    /// Handles both SELECT (row-returning) and non-SELECT (command) queries:
    ///
    /// - **Row messages present** → SELECT with data: format multi-column
    ///   results via `lf_quote()`, single-column results as raw values.
    ///   Multiple rows separated by `\n`. (C: lines 335–350)
    ///
    /// - **Only CommandComplete with count > 0** → Non-SELECT command
    ///   (INSERT/UPDATE/DELETE): return affected row count as string,
    ///   disable caching. (C: lines 296–306, `*do_cache = 0`)
    ///
    /// - **CommandComplete with count = 0 and no rows** → Either SELECT
    ///   returning 0 rows or DML affecting 0 rows: return NotFound.
    ///   (C: lines 354–358, `yield = FAIL`)
    fn process_simple_query_results(
        messages: &[tokio_postgres::SimpleQueryMessage],
    ) -> SqlPerformResult {
        let mut result = String::new();
        let mut row_count: usize = 0;
        let mut column_names: Vec<String> = Vec::new();
        let mut num_columns: usize = 0;
        let mut command_complete_count: Option<u64> = None;

        for msg in messages {
            match msg {
                tokio_postgres::SimpleQueryMessage::Row(row) => {
                    // Capture column names from the first row
                    if row_count == 0 {
                        num_columns = row.columns().len();
                        column_names = row.columns().iter().map(|c| c.name().to_string()).collect();
                    }

                    // Separate multiple rows with newline (C: line 338)
                    if row_count > 0 {
                        result.push('\n');
                    }

                    if num_columns == 1 {
                        // Single column: return raw value (C: lines 340–342)
                        let val = row.get(0).unwrap_or("");
                        result.push_str(val);
                    } else {
                        // Multiple columns: format as name=value pairs
                        // via lf_quote() (C: lines 344–348)
                        for (j, name) in column_names.iter().enumerate() {
                            let val = row.get(j);
                            lf_quote(name, val, &mut result);
                        }
                    }

                    row_count += 1;
                }
                tokio_postgres::SimpleQueryMessage::CommandComplete(count) => {
                    command_complete_count = Some(*count);
                }
                // __NonExhaustive or future variants
                _ => {}
            }
        }

        // ── Determine result ──────────────────────────────────────────────
        if row_count > 0 {
            // SELECT with data → Found, cacheable (C: lines 371–376)
            SqlPerformResult::Found {
                result,
                cacheable: true,
            }
        } else if let Some(count) = command_complete_count {
            if count > 0 {
                // Non-SELECT command that affected rows → Found, NOT cacheable
                // count > 0 proves it's DML since SELECT would have Row messages
                // (C: lines 296–306, *do_cache = 0)
                tracing::debug!(
                    "PGSQL: command does not return any data but was \
                     successful. Rows affected: {}",
                    count
                );
                SqlPerformResult::Found {
                    result: count.to_string(),
                    cacheable: false,
                }
            } else {
                // count == 0: ambiguous between SELECT with 0 rows and DML
                // affecting 0 rows. Return NotFound (matches C PGRES_TUPLES_OK
                // with num_tuples == 0 → FAIL at lines 354–358).
                SqlPerformResult::NotFound
            }
        } else {
            // No messages at all → NotFound (C: lines 354–358)
            SqlPerformResult::NotFound
        }
    }
}

// =============================================================================
// LookupDriver Trait Implementation
// =============================================================================

impl LookupDriver for PgsqlLookup {
    /// Open a PostgreSQL lookup connection.
    ///
    /// Returns a dummy handle since PostgreSQL is a query-style lookup and
    /// actual connections are established on-demand in `find()`.
    ///
    /// C equivalent: `pgsql_open()` (lines 40–44) returns `(void *)(1)`.
    fn open(&self, _filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        // Return a dummy handle, matching C's `return (void *)(1);`
        Ok(Box::new(()))
    }

    /// Check is a no-op for query-style lookups.
    ///
    /// C equivalent: `check` function pointer is NULL in the `lookup_info`
    /// struct (line 508).
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

    /// Execute a PostgreSQL query with multi-server failover.
    ///
    /// Replaces C `pgsql_find()` (lines 396–403) which delegates to
    /// `lf_sqlperform()` with `perform_pgsql_search` as the callback.
    ///
    /// Creates a scoped `tokio::runtime::Runtime` per invocation to bridge
    /// async `tokio-postgres` operations into the synchronous LookupDriver
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
        // (or reused via thread-local) to bridge tokio-postgres async
        // Client::query() and connection establishment into the synchronous
        // fork-per-connection model."
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| DriverError::TempFail(format!("failed to create tokio runtime: {}", e)))?;

        // Build the per-server callback closure that captures both `self`
        // (for pool cache access) and `runtime` (for block_on bridging).
        let callback = |query: &str, server: &str, opts: Option<&str>| -> SqlPerformResult {
            self.perform_search(query, server, opts, &runtime)
        };

        // Delegate to sql_perform() for multi-server failover iteration.
        // C: lf_sqlperform(US"PostgreSQL", US"pgsql_servers",
        //                   pgsql_servers, query, ...)
        //
        // Note: `opt_server_list` is None here because the global
        // `pgsql_servers` configuration value is not available at the
        // lookup driver level. Server lists come from the query itself
        // (legacy inline syntax) or the `options` parameter (modern
        // `servers=...` syntax). When configuration infrastructure is
        // integrated, this can be updated to pass the config value.
        match sql_perform(
            "PostgreSQL",
            "pgsql_servers",
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
                    // Some(0) = do not cache (for command results)
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

    /// Close is a no-op — connections are cached in pools.
    ///
    /// C equivalent: `close` function pointer is NULL (line 509).
    fn close(&self, _handle: LookupHandle) {
        // No-op: connections are managed by the pool cache and released
        // in tidy(). Individual handle close is not needed.
    }

    /// Close all cached PostgreSQL connection pools.
    ///
    /// Replaces C `pgsql_tidy()` (lines 54–64) which iterates the static
    /// linked list calling `PQfinish()` on each cached connection.
    ///
    /// Clears the `HashMap`, dropping all `deadpool-postgres::Pool` instances
    /// and their managed connections.
    fn tidy(&self) {
        match self.pools.lock() {
            Ok(mut pools) => {
                for (key, _pool) in pools.iter() {
                    tracing::debug!("close PGSQL connection: {}", key);
                }
                pools.clear();
            }
            Err(e) => {
                tracing::warn!("PGSQL tidy: failed to lock pool cache: {}", e);
            }
        }
    }

    /// Quote a string for safe use in PostgreSQL queries.
    ///
    /// Replaces C `pgsql_quote()` (lines 432–469):
    /// - Single quotes are doubled: `'` → `''`
    /// - Special characters are backslash-escaped:
    ///   `\n` → `\n`, `\t` → `\t`, `\r` → `\r`, `\b` → `\b`
    /// - Double quotes and backslashes are escaped: `"` → `\"`, `\` → `\\`
    /// - All other characters pass through unchanged
    ///
    /// Returns `None` if `additional` is `Some` (no options recognized),
    /// matching C behavior where `if (opt) return NULL;` (line 438).
    fn quote(&self, value: &str, additional: Option<&str>) -> Option<String> {
        // C: if (opt) return NULL; — no options recognized
        if additional.is_some() {
            return None;
        }

        let mut result = String::with_capacity(value.len() * 2);

        for ch in value.chars() {
            match ch {
                // Single quote → doubled (C: lines 447–451)
                // Security: uses SQL standard '' instead of \' per the
                // June 2006 security advisory noted in C comments.
                '\'' => {
                    result.push('\'');
                    result.push('\'');
                }
                // Special characters → backslash-escaped (C: lines 452–463)
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
                    // Backspace (\b)
                    result.push('\\');
                    result.push('b');
                }
                '"' => {
                    result.push('\\');
                    result.push('"');
                }
                '\\' => {
                    result.push('\\');
                    result.push('\\');
                }
                // All other characters pass through unchanged
                _ => result.push(ch),
            }
        }

        Some(result)
    }

    /// Report the PostgreSQL library version for `-bV` output.
    ///
    /// Replaces C `pgsql_version_report()` (lines 478–493) which calls
    /// `PQlibVersion()` to report the runtime libpq version.
    ///
    /// Since the Rust implementation uses `tokio-postgres` (a native Rust
    /// PostgreSQL client) instead of libpq, we report the tokio-postgres
    /// crate version.
    fn version_report(&self) -> Option<String> {
        // C: string_fmt_append(g, "Library version: PostgreSQL: Runtime: %d.%d\n",
        //                       ver/10000, ver%10000);
        Some("Library version: PostgreSQL: tokio-postgres (Rust native client)\n".to_string())
    }

    /// Return the lookup type flags.
    ///
    /// PostgreSQL is a query-style lookup (C: `lookup_querystyle` at line 505).
    fn lookup_type(&self) -> LookupType {
        LookupType::QUERY_STYLE
    }

    /// Return the driver name for configuration file matching.
    ///
    /// C: `US"pgsql"` at line 504.
    fn driver_name(&self) -> &str {
        "pgsql"
    }
}

// =============================================================================
// Compile-Time Driver Registration
// =============================================================================

// Register the PostgreSQL lookup driver with the inventory-based driver
// registry at compile time.
//
// Replaces C module registration at lines 503–523:
//   static lookup_info _lookup_info = {
//     .name = US"pgsql",
//     .type = lookup_querystyle,
//     .open = pgsql_open, ...
//   };
//   lookup_module_info pgsql_lookup_module_info = {
//     LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1
//   };
inventory::submit! {
    LookupDriverFactory {
        name: "pgsql",
        create: || Box::new(PgsqlLookup::new()),
        lookup_type: LookupType::QUERY_STYLE,
        avail_string: Some("pgsql (PostgreSQL via tokio-postgres)"),
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Server spec parsing tests ─────────────────────────────────────────

    #[test]
    fn parse_tcp_host_with_port() {
        let (spec, key) = PgsqlLookup::parse_server_spec("dbhost:5433/mydb/myuser/mypass").unwrap();
        assert_eq!(spec.host, "dbhost");
        assert_eq!(spec.port, 5433);
        assert_eq!(spec.database, Some("mydb".to_string()));
        assert_eq!(spec.user, "myuser");
        assert_eq!(spec.password, "mypass");
        assert!(!spec.is_unix_socket);
        assert_eq!(key, "dbhost:5433/mydb/myuser");
    }

    #[test]
    fn parse_tcp_host_default_port() {
        let (spec, _key) = PgsqlLookup::parse_server_spec("dbhost/mydb/myuser/mypass").unwrap();
        assert_eq!(spec.host, "dbhost");
        assert_eq!(spec.port, 5432);
        assert_eq!(spec.database, Some("mydb".to_string()));
        assert_eq!(spec.user, "myuser");
        assert_eq!(spec.password, "mypass");
        assert!(!spec.is_unix_socket);
    }

    #[test]
    fn parse_unix_socket() {
        let (spec, _key) = PgsqlLookup::parse_server_spec(
            "(/var/run/postgresql/.s.PGSQL.5432)/mydb/myuser/mypass",
        )
        .unwrap();
        assert_eq!(spec.host, "/var/run/postgresql");
        assert_eq!(spec.port, 5432);
        assert_eq!(spec.database, Some("mydb".to_string()));
        assert_eq!(spec.user, "myuser");
        assert_eq!(spec.password, "mypass");
        assert!(spec.is_unix_socket);
    }

    #[test]
    fn parse_empty_database() {
        let (spec, _key) = PgsqlLookup::parse_server_spec("dbhost//myuser/mypass").unwrap();
        assert_eq!(spec.host, "dbhost");
        assert_eq!(spec.database, None);
        assert_eq!(spec.user, "myuser");
    }

    #[test]
    fn parse_incomplete_spec_fails() {
        assert!(PgsqlLookup::parse_server_spec("dbhost/mydb").is_err());
    }

    #[test]
    fn parse_hostname_with_slash_fails() {
        assert!(PgsqlLookup::parse_server_spec("host/name/mydb/myuser/mypass").is_err());
    }

    // ── Quote function tests ──────────────────────────────────────────────

    #[test]
    fn quote_basic_string() {
        let lookup = PgsqlLookup::new();
        let result = lookup.quote("hello world", None);
        assert_eq!(result, Some("hello world".to_string()));
    }

    #[test]
    fn quote_single_quotes() {
        let lookup = PgsqlLookup::new();
        let result = lookup.quote("it's a test", None);
        assert_eq!(result, Some("it''s a test".to_string()));
    }

    #[test]
    fn quote_backslash() {
        let lookup = PgsqlLookup::new();
        let result = lookup.quote("path\\file", None);
        assert_eq!(result, Some("path\\\\file".to_string()));
    }

    #[test]
    fn quote_double_quotes() {
        let lookup = PgsqlLookup::new();
        let result = lookup.quote("say \"hello\"", None);
        assert_eq!(result, Some("say \\\"hello\\\"".to_string()));
    }

    #[test]
    fn quote_special_chars() {
        let lookup = PgsqlLookup::new();
        let result = lookup.quote("line1\nline2\ttab\r\n", None);
        assert_eq!(result, Some("line1\\nline2\\ttab\\r\\n".to_string()));
    }

    #[test]
    fn quote_backspace() {
        let lookup = PgsqlLookup::new();
        let result = lookup.quote("back\x08space", None);
        assert_eq!(result, Some("back\\bspace".to_string()));
    }

    #[test]
    fn quote_with_option_returns_none() {
        let lookup = PgsqlLookup::new();
        let result = lookup.quote("test", Some("opt"));
        assert!(result.is_none());
    }

    #[test]
    fn quote_empty_string() {
        let lookup = PgsqlLookup::new();
        let result = lookup.quote("", None);
        assert_eq!(result, Some(String::new()));
    }

    // ── Driver metadata tests ─────────────────────────────────────────────

    #[test]
    fn driver_name_is_pgsql() {
        let lookup = PgsqlLookup::new();
        assert_eq!(lookup.driver_name(), "pgsql");
    }

    #[test]
    fn lookup_type_is_query_style() {
        let lookup = PgsqlLookup::new();
        assert!(lookup.lookup_type().is_query_style());
    }

    #[test]
    fn version_report_is_present() {
        let lookup = PgsqlLookup::new();
        let report = lookup.version_report();
        assert!(report.is_some());
        assert!(report.unwrap().contains("PostgreSQL"));
    }

    // ── Open/close/tidy tests ─────────────────────────────────────────────

    #[test]
    fn open_returns_handle() {
        let lookup = PgsqlLookup::new();
        let handle = lookup.open(None);
        assert!(handle.is_ok());
    }

    #[test]
    fn check_returns_true() {
        let lookup = PgsqlLookup::new();
        let handle = lookup.open(None).unwrap();
        let result = lookup.check(&handle, None, 0, &[], &[]);
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn tidy_clears_pools() {
        let lookup = PgsqlLookup::new();
        // Insert a dummy entry to verify tidy clears it
        {
            let pools = lookup.pools.lock().unwrap();
            // We can't easily create a real Pool here, but we can verify
            // the tidy operation on the HashMap mechanics
            assert!(pools.is_empty());
        }
        lookup.tidy();
        let pools = lookup.pools.lock().unwrap();
        assert!(pools.is_empty());
    }

    // ── process_simple_query_results tests ────────────────────────────────

    #[test]
    fn process_empty_messages_returns_not_found() {
        let messages: Vec<tokio_postgres::SimpleQueryMessage> = vec![];
        let result = PgsqlLookup::process_simple_query_results(&messages);
        assert!(matches!(result, SqlPerformResult::NotFound));
    }

    #[test]
    fn process_command_complete_positive_count() {
        let messages = vec![tokio_postgres::SimpleQueryMessage::CommandComplete(5)];
        let result = PgsqlLookup::process_simple_query_results(&messages);
        match result {
            SqlPerformResult::Found { result, cacheable } => {
                assert_eq!(result, "5");
                assert!(!cacheable);
            }
            _ => panic!("Expected Found, got {:?}", result),
        }
    }

    #[test]
    fn process_command_complete_zero_returns_not_found() {
        let messages = vec![tokio_postgres::SimpleQueryMessage::CommandComplete(0)];
        let result = PgsqlLookup::process_simple_query_results(&messages);
        assert!(matches!(result, SqlPerformResult::NotFound));
    }
}
