#![deny(unsafe_code)]
// =============================================================================
// exim-lookups/src/redis.rs — Redis Lookup via redis crate
// =============================================================================
//
// Replaces `src/src/lookups/redis.c` (470 lines). Uses the Rust `redis` crate
// (version 1.0.5) for synchronous Redis connection and command execution,
// replacing the C hiredis library (redisContext, redisCommand, redisReply).
//
// Per AAP §0.7.2: This file contains ZERO `unsafe` code.
// Per AAP §0.4.3: Connection caching uses HashMap with explicit clear() on
//   tidy(), replacing the C static linked list of redis_connection structs.
//
// Connection spec format (matching C redis.c):
//   host/dbnumber/password
//   host:port/dbnumber/password
//   host(socket)/dbnumber/password
//
// Registration: inventory::submit!(LookupDriverFactory { name: "redis", ... })
//
// Key C-to-Rust transformations:
//   - C `redisContext` + static linked list  → `redis::Connection` + `HashMap`
//   - C `redisCommand()`/`redisCommandArgv()` → `redis::cmd().arg().query()`
//   - C `redisReply` type switch             → `redis::Value` enum match
//   - C `DEBUG(D_lookup)` macros             → `tracing::debug!()` calls
//   - C `MOVED` string prefix check          → `ServerErrorKind::Moved` match
//   - C `redis_quote()` backslash escaping   → `RedisLookup::quote()`
//   - C `redis_version_report()`             → `RedisLookup::version_report()`

use std::collections::HashMap;
use std::sync::Mutex;

use redis::{Client, Cmd, Value};

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;

// =============================================================================
// RedisConnection — Cached connection wrapper
// =============================================================================

/// Holds a live Redis connection along with its server metadata.
///
/// Replaces the C `redis_connection` struct (redis.c lines 21-25):
/// ```c
/// typedef struct redis_connection {
///   struct redis_connection *next;
///   uschar  *server;
///   redisContext    *handle;
/// } redis_connection;
/// ```
///
/// The linked-list `next` pointer is replaced by `HashMap` storage in
/// `RedisLookup`. The `server` field is the HashMap key. The `handle`
/// field is replaced by `redis::Connection`.
struct RedisConnection {
    /// Live Redis connection handle.
    ///
    /// Uses the synchronous `redis::Connection` type for blocking I/O,
    /// matching the C fork-per-connection model.
    conn: redis::Connection,
}

// Manual Debug implementation because redis::Connection does not implement Debug.
impl std::fmt::Debug for RedisConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisConnection")
            .field("conn", &"<redis::Connection>")
            .finish()
    }
}

// =============================================================================
// Parsed Server Specification
// =============================================================================

/// Parsed Redis server connection parameters.
///
/// Extracted from the `host:port/dbnumber/password` connection spec format
/// used by Exim's multi-server failover mechanism. Replaces the C inline
/// parsing in `perform_redis_search()` (redis.c lines 89-110).
///
/// The server string is parsed right-to-left by splitting on '/' separators:
///   1. password (rightmost segment)
///   2. dbnumber (middle segment)
///   3. host[:port] or host(socket) (leftmost segment)
///
/// Empty password or dbnumber fields are treated as absent (None).
#[derive(Debug, Clone)]
struct RedisServerSpec {
    /// Hostname or IP address for TCP connections.
    host: String,
    /// TCP port (default 6379).
    port: u16,
    /// Unix domain socket path, if specified via `(path)` syntax.
    socket: Option<String>,
    /// Redis database number (0-15 typically). `None` means use default (0).
    dbnumber: Option<String>,
    /// Redis AUTH password. `None` means no authentication.
    password: Option<String>,
}

// =============================================================================
// RedisLookup — Main Lookup Driver Struct
// =============================================================================

/// Redis lookup driver implementing the `LookupDriver` trait.
///
/// Uses `redis::Connection` for synchronous command execution, stored in a
/// `HashMap` connection cache wrapped in `Mutex` for interior mutability
/// (since `LookupDriver` trait methods take `&self`).
///
/// The `Mutex` provides `Send + Sync` bounds required by the `LookupDriver`
/// trait supertrait constraints.
///
/// Replaces the C `redis_connections` static linked list and
/// `redis_lookup_info` registration struct from `redis.c` lines 27, 447-460.
///
/// # Connection Caching Strategy
///
/// Live `redis::Connection` objects are cached per server specification
/// (host:port/dbnumber without password, matching C `server_copy`). Connections
/// persist across multiple `find()` calls until `tidy()` is invoked, which
/// clears the entire cache. This matches the C behavior where connections
/// are cached in the static linked list and freed only in `redis_tidy()`.
#[derive(Debug)]
pub struct RedisLookup {
    /// Connection cache: sanitized server key → RedisConnection.
    ///
    /// The key is the server spec without the password (for safe logging
    /// and cache lookup). Entries are dropped on `tidy()` to close all
    /// cached connections, matching C `redis_tidy()` behavior
    /// (redis.c lines 38-53).
    ///
    /// Per AAP §0.4.3: "HashMap with explicit clear() replacing
    /// POOL_SEARCH".
    conn_cache: Mutex<HashMap<String, RedisConnection>>,
}

impl Default for RedisLookup {
    fn default() -> Self {
        Self::new()
    }
}

impl RedisLookup {
    /// Create a new `RedisLookup` instance with an empty connection cache.
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
    /// Matches the C parsing logic from `perform_redis_search()` lines 89-110:
    /// - Parse from right to left, splitting on '/' separators
    /// - Extract password (rightmost), dbnumber (middle), host[:port] (leftmost)
    /// - Empty dbnumber or password → None
    /// - Extract `(socket)` Unix domain socket path from host portion
    /// - Parse host:port with default port 6379
    ///
    /// # Returns
    ///
    /// `(spec, cache_key)` where `cache_key` is the server spec without the
    /// password, suitable for logging and cache lookup (C: `server_copy`).
    ///
    /// # Errors
    ///
    /// Returns a `DriverError::ConfigError` if the server specification does not
    /// contain at least two '/' separators (host/dbnumber/password).
    fn parse_server_spec(server: &str) -> Result<(RedisServerSpec, String), DriverError> {
        let mut remaining = server;

        // ── Extract password (after last '/') ─────────────────────────────
        // C: sdata[2] = pp (after last '/')
        let slash_pos = remaining.rfind('/').ok_or_else(|| {
            DriverError::ConfigError(format!("incomplete Redis server data: {}", server))
        })?;
        let password_str = &remaining[slash_pos + 1..];
        remaining = &remaining[..slash_pos];

        // Cache key is server spec without password (C: server_copy)
        let cache_key = remaining.to_string();

        // ── Extract dbnumber (after second-to-last '/') ──────────────────
        // C: sdata[1] = pp (after second-to-last '/')
        let slash_pos = remaining.rfind('/').ok_or_else(|| {
            DriverError::ConfigError(format!("incomplete Redis server data: {}", cache_key))
        })?;
        let db_str = &remaining[slash_pos + 1..];
        remaining = &remaining[..slash_pos];

        // C: if (sdata[1][0] == 0) sdata[1] = NULL;
        let dbnumber = if db_str.is_empty() {
            None
        } else {
            Some(db_str.to_string())
        };

        // C: if (sdata[2][0] == 0) sdata[2] = NULL;
        let password = if password_str.is_empty() {
            None
        } else {
            Some(password_str.to_string())
        };

        // ── Parse host portion (sdata[0]) ─────────────────────────────────
        // C: remaining is sdata[0], the host[:port] or host(socket) part
        let host_str = remaining;

        // Extract (socket) if present FIRST (C: redis.c lines 132-138)
        // This must happen before the slash check because the socket path
        // (e.g., "/tmp/redis.sock") may contain '/' characters.
        let (host_str, socket) = Self::extract_paren_socket(host_str);

        // Check for unexpected slashes in the hostname AFTER socket extraction
        // C: if (Ustrchr(server, '/')) → error
        // At this point in C, the socket has been extracted and the '(' has
        // been replaced with '\0', so only the hostname remains.
        if host_str.contains('/') {
            return Err(DriverError::ConfigError(format!(
                "unexpected slash in Redis server hostname: {}",
                host_str
            )));
        }

        // Parse host:port (C: redis.c lines 140-146)
        let (host, port) = Self::parse_host_port(&host_str);

        Ok((
            RedisServerSpec {
                host,
                port,
                socket,
                dbnumber,
                password,
            },
            cache_key,
        ))
    }

    /// Extract `(socket)` Unix socket path from a host string.
    ///
    /// Looks for a parenthesized segment like `(/var/run/redis/redis.sock)`
    /// and returns the socket path and the remaining host string with the
    /// parentheses removed.
    ///
    /// C equivalent: redis.c lines 132-138 — extract `(socket)` from hostname.
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

    /// Parse host and optional port from a host string.
    ///
    /// Handles both `host:port` and plain `host` formats. Default port is 6379
    /// (standard Redis port), matching C: `port = Uatoi("6379")`.
    ///
    /// C equivalent: redis.c lines 140-146.
    fn parse_host_port(host_str: &str) -> (String, u16) {
        if let Some(colon_pos) = host_str.rfind(':') {
            let host = host_str[..colon_pos].to_string();
            let port_str = &host_str[colon_pos + 1..];
            let port = port_str.parse::<u16>().unwrap_or(6379);
            (host, port)
        } else {
            (host_str.to_string(), 6379)
        }
    }

    // =========================================================================
    // Connection Management
    // =========================================================================

    /// Get an existing cached connection or create a new one for the given
    /// server specification.
    ///
    /// Replaces the C linear search of `redis_connections` linked list
    /// (redis.c lines 118-179). On cache miss, creates a new `redis::Client`,
    /// obtains a synchronous `Connection`, runs AUTH and SELECT if needed,
    /// and caches the connection.
    ///
    /// # Parameters
    ///
    /// - `cache_key`: Server spec without password (for cache lookup/logging).
    /// - `spec`: Parsed server specification with full connection details.
    ///
    /// # Returns
    ///
    /// Mutable reference to the cached `RedisConnection`, or a `DriverError`
    /// on connection failure.
    fn get_or_create_connection<'a>(
        cache: &'a mut HashMap<String, RedisConnection>,
        cache_key: &str,
        spec: &RedisServerSpec,
    ) -> Result<&'a mut RedisConnection, DriverError> {
        if cache.contains_key(cache_key) {
            tracing::debug!("REDIS using cached connection for {}", cache_key);
            return Ok(cache.get_mut(cache_key).expect("checked above"));
        }

        // ── Create new connection ─────────────────────────────────────────
        // C: redis_handle = socket ? redisConnectUnix(socket) : redisConnect(host, port);
        tracing::debug!(
            "REDIS new connection: host={} port={} socket={:?} database={:?}",
            spec.host,
            spec.port,
            spec.socket,
            spec.dbnumber
        );

        let connection_url = if let Some(ref socket_path) = spec.socket {
            // Unix socket connection: redis+unix:///path
            format!("redis+unix:///{}", socket_path)
        } else {
            // TCP connection: redis://host:port
            format!("redis://{}:{}", spec.host, spec.port)
        };

        let client = Client::open(connection_url.as_str())
            .map_err(|e| DriverError::TempFail(format!("REDIS connection failed: {}", e)))?;

        let mut conn = client
            .get_connection()
            .map_err(|e| DriverError::TempFail(format!("REDIS connection failed: {}", e)))?;

        // ── Authenticate if there is a password ──────────────────────────
        // C: if(sdata[2]) redisCommand(handle, "AUTH %s", sdata[2])
        if let Some(ref password) = spec.password {
            tracing::debug!("REDIS: AUTH ***");
            let auth_result: Result<Value, _> = Cmd::new()
                .arg("AUTH")
                .arg(password.as_str())
                .query(&mut conn);
            auth_result.map_err(|e| {
                DriverError::TempFail(format!("REDIS Authentication failed: {}", e))
            })?;
        }

        // ── Select database if there is a dbnumber ───────────────────────
        // C: if(sdata[1]) redisCommand(handle, "SELECT %s", sdata[1])
        if let Some(ref dbnumber) = spec.dbnumber {
            tracing::debug!("REDIS: Selecting database={}", dbnumber);
            let select_result: Result<Value, _> = Cmd::new()
                .arg("SELECT")
                .arg(dbnumber.as_str())
                .query(&mut conn);
            select_result.map_err(|e| {
                DriverError::TempFail(format!(
                    "REDIS: Selecting database={} failed: {}",
                    dbnumber, e
                ))
            })?;
        }

        // ── Add to cache ─────────────────────────────────────────────────
        // C: cn = store_get(sizeof(redis_connection), GET_UNTAINTED);
        //    cn->server = server_copy; cn->handle = redis_handle;
        //    cn->next = redis_connections; redis_connections = cn;
        cache.insert(cache_key.to_string(), RedisConnection { conn });

        Ok(cache.get_mut(cache_key).expect("just inserted"))
    }

    // =========================================================================
    // Command Parsing
    // =========================================================================

    /// Parse a command string into an argv array with backslash escaping.
    ///
    /// Replaces the C argv splitting logic from `perform_redis_search()`
    /// (redis.c lines 202-232). Splits the command on whitespace, with
    /// backslash acting as an escape character for the next character
    /// (allowing whitespace and literal backslashes in arguments).
    ///
    /// This is NOT a Redis protocol feature but rather Exim's own argument
    /// splitting mechanism to allow multi-word arguments in the Redis command
    /// string from the configuration file.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Simple command
    /// assert_eq!(parse_command_argv("GET mykey"), vec!["GET", "mykey"]);
    ///
    /// // Backslash-escaped whitespace
    /// assert_eq!(parse_command_argv("SET my\\ key value"), vec!["SET", "my key", "value"]);
    /// ```
    fn parse_command_argv(command: &str) -> Vec<String> {
        let mut argv: Vec<String> = Vec::new();
        let chars: Vec<char> = command.chars().collect();
        let len = chars.len();
        let mut pos = 0;

        // Skip leading whitespace
        // C: Uskip_whitespace(&s);
        while pos < len && chars[pos].is_whitespace() {
            pos += 1;
        }

        // Parse arguments up to a reasonable limit (C uses 32)
        while pos < len && argv.len() < 32 {
            let mut arg = String::new();

            // Build argument character by character
            // C: for (g = NULL; (c = *s) && !isspace(c); s++)
            //      if (c != '\\' || *++s) g = string_catn(g, s, 1);
            while pos < len && !chars[pos].is_whitespace() {
                if chars[pos] == '\\' {
                    pos += 1;
                    // Backslash protects next character
                    if pos < len {
                        arg.push(chars[pos]);
                        pos += 1;
                    }
                } else {
                    arg.push(chars[pos]);
                    pos += 1;
                }
            }

            if !arg.is_empty() {
                tracing::debug!("REDIS: argv[{}] '{}'", argv.len(), arg);
                argv.push(arg);
            }

            // Skip whitespace between arguments
            // C: Uskip_whitespace(&s);
            while pos < len && chars[pos].is_whitespace() {
                pos += 1;
            }
        }

        argv
    }

    // =========================================================================
    // Reply Formatting
    // =========================================================================

    /// Format a Redis reply value into a string result.
    ///
    /// Replaces the C reply type switch from `perform_redis_search()`
    /// (redis.c lines 235-328). Maps Redis value types to string
    /// representations:
    ///
    /// | Redis Type      | C Type                | Rust Value Variant  | Formatting          |
    /// |-----------------|-----------------------|---------------------|---------------------|
    /// | String          | REDIS_REPLY_STRING    | BulkString          | Direct UTF-8 decode |
    /// | Status          | REDIS_REPLY_STATUS    | SimpleString/Okay   | Direct string       |
    /// | Integer         | REDIS_REPLY_INTEGER   | Int                 | "true"/"false"      |
    /// | Array           | REDIS_REPLY_ARRAY     | Array               | Newline-joined      |
    /// | Nil             | REDIS_REPLY_NIL       | Nil                 | Empty (no cache)    |
    /// | Error           | REDIS_REPLY_ERROR     | (RedisError)        | Error handling      |
    ///
    /// Note: The C code formats integers as "true"/"false" (non-zero/zero).
    /// This matches `redis.c` line 266: `redis_reply->integer != 0 ? "true" : "false"`.
    fn format_reply_value(value: &Value) -> Option<String> {
        match value {
            // C: case REDIS_REPLY_STRING/REDIS_REPLY_STATUS:
            //    result = string_catn(result, redis_reply->str, redis_reply->len);
            Value::BulkString(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),

            // C: case REDIS_REPLY_STATUS (simple string / OK responses)
            Value::SimpleString(s) => Some(s.clone()),
            Value::Okay => Some("OK".to_string()),

            // C: case REDIS_REPLY_INTEGER:
            //    result = redis_reply->integer != 0 ? US"true" : US"false";
            Value::Int(i) => {
                if *i != 0 {
                    Some("true".to_string())
                } else {
                    Some("false".to_string())
                }
            }

            // C: case REDIS_REPLY_ARRAY: newline-joined elements with one
            //    level of nesting support (redis.c lines 274-327)
            Value::Array(elements) => Self::format_array_reply(elements),

            // C: case REDIS_REPLY_NIL: return empty with do_cache=0
            Value::Nil => None,

            // Handle other value types that don't exist in the C code but
            // are present in the redis crate's Value enum
            Value::Double(d) => Some(d.to_string()),
            Value::Boolean(b) => {
                if *b {
                    Some("true".to_string())
                } else {
                    Some("false".to_string())
                }
            }
            Value::Map(pairs) => {
                // Format map entries as newline-joined key-value pairs
                let mut parts: Vec<String> = Vec::new();
                for (k, v) in pairs {
                    if let Some(ks) = Self::format_scalar_value(k) {
                        parts.push(ks);
                    }
                    if let Some(vs) = Self::format_scalar_value(v) {
                        parts.push(vs);
                    }
                }
                if parts.is_empty() {
                    None
                } else {
                    Some(parts.join("\n"))
                }
            }
            Value::Set(elements) => Self::format_array_reply(elements),
            Value::BigNumber(s) => Some(s.to_string()),
            Value::VerbatimString { text, .. } => Some(text.clone()),
            Value::ServerError(err) => {
                tracing::warn!("REDIS: server error in reply: {}", err);
                None
            }
            // For Push and Attribute types, extract what data we can
            Value::Push { data, .. } => Self::format_array_reply(data),
            Value::Attribute { data, .. } => Self::format_reply_value(data),
            // Catch-all for any future Value variants added to the
            // non-exhaustive redis::Value enum
            _ => {
                tracing::debug!("REDIS: unknown reply value type. Ignoring!");
                None
            }
        }
    }

    /// Format a single scalar Redis value to a string.
    ///
    /// Used for formatting individual elements within arrays and maps.
    fn format_scalar_value(value: &Value) -> Option<String> {
        match value {
            Value::BulkString(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
            Value::SimpleString(s) => Some(s.clone()),
            Value::Okay => Some("OK".to_string()),
            Value::Int(i) => Some(i.to_string()),
            Value::Double(d) => Some(d.to_string()),
            Value::Boolean(b) => Some(b.to_string()),
            Value::BigNumber(s) => Some(s.to_string()),
            Value::VerbatimString { text, .. } => Some(text.clone()),
            Value::Nil => None,
            _ => {
                tracing::debug!("REDIS: result has unsupported nested type. Ignoring!");
                None
            }
        }
    }

    /// Format an array reply into a newline-joined string.
    ///
    /// Supports one level of nesting, matching C behavior (redis.c lines
    /// 274-327). At the top level, elements are joined by newlines. Nested
    /// arrays (one level deep) are flattened with newline separators. Arrays
    /// nested more than one level deep are logged and ignored.
    fn format_array_reply(elements: &[Value]) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();

        for entry in elements {
            match entry {
                // C: case REDIS_REPLY_INTEGER (within array):
                //    result = string_fmt_append(result, "%d", entry->integer);
                Value::Int(i) => {
                    parts.push(i.to_string());
                }

                // C: case REDIS_REPLY_STRING (within array):
                //    result = string_catn(result, entry->str, entry->len);
                Value::BulkString(bytes) => {
                    parts.push(String::from_utf8_lossy(bytes).into_owned());
                }

                Value::SimpleString(s) => {
                    parts.push(s.clone());
                }

                Value::Okay => {
                    parts.push("OK".to_string());
                }

                Value::Double(d) => {
                    parts.push(d.to_string());
                }

                Value::Boolean(b) => {
                    parts.push(b.to_string());
                }

                Value::BigNumber(s) => {
                    parts.push(s.to_string());
                }

                Value::VerbatimString { text, .. } => {
                    parts.push(text.clone());
                }

                // C: case REDIS_REPLY_ARRAY (nested, one level supported):
                //    for (n = 0; n < entry->elements; n++) { ... }
                Value::Array(nested) => {
                    for tentry in nested {
                        match tentry {
                            Value::Int(i) => {
                                parts.push(i.to_string());
                            }
                            Value::BulkString(bytes) => {
                                parts.push(String::from_utf8_lossy(bytes).into_owned());
                            }
                            Value::SimpleString(s) => {
                                parts.push(s.clone());
                            }
                            Value::Double(d) => {
                                parts.push(d.to_string());
                            }
                            Value::Array(_) => {
                                // C: "REDIS: result has nesting of arrays which
                                //     is not supported. Ignoring!"
                                tracing::debug!(
                                    "REDIS: result has nesting of arrays which \
                                     is not supported. Ignoring!"
                                );
                            }
                            Value::Nil => {
                                // Skip nil entries in nested arrays
                            }
                            _ => {
                                tracing::debug!("REDIS: result has unsupported type. Ignoring!");
                            }
                        }
                    }
                }

                Value::Set(nested) => {
                    // Treat sets like arrays for formatting
                    for tentry in nested {
                        if let Some(s) = Self::format_scalar_value(tentry) {
                            parts.push(s);
                        }
                    }
                }

                Value::Nil => {
                    // Skip nil entries at top level
                }

                _ => {
                    // C: "REDIS: query returned unsupported type"
                    tracing::debug!("REDIS: query returned unsupported type");
                }
            }
        }

        if parts.is_empty() {
            None
        } else {
            Some(parts.join("\n"))
        }
    }

    // =========================================================================
    // MOVED Detection
    // =========================================================================

    /// Check if a Redis error represents a MOVED cluster redirect.
    ///
    /// Replaces C detection logic (redis.c lines 241-249):
    /// ```c
    /// if (Ustrncmp(redis_reply->str, "MOVED", 5) == 0) {
    ///     DEBUG(D_lookup)
    ///         debug_printf_indent("REDIS: cluster redirect %s\n", redis_reply->str);
    ///     *defer_break = FALSE;
    ///     return DEFER;
    /// }
    /// ```
    ///
    /// In the `redis` crate, MOVED errors are represented as
    /// `ErrorKind::Server(ServerErrorKind::Moved)` or can be detected by
    /// inspecting the error description string.
    fn is_moved_error(err: &redis::RedisError) -> bool {
        // Check via the structured error kind
        if let redis::ErrorKind::Server(server_kind) = err.kind() {
            return server_kind == redis::ServerErrorKind::Moved;
        }
        // Fallback: check the error message string for "MOVED" prefix
        // (defensive programming — the structured check should be sufficient)
        let desc = format!("{}", err);
        desc.starts_with("MOVED") || desc.contains("MOVED")
    }

    // =========================================================================
    // Core Search Implementation
    // =========================================================================

    /// Execute a Redis command against a single server.
    ///
    /// Replaces `perform_redis_search()` (redis.c lines 75-358). This is the
    /// core search implementation that:
    /// 1. Parses the server specification
    /// 2. Gets or creates a cached connection
    /// 3. Runs AUTH and SELECT if needed (handled by get_or_create_connection)
    /// 4. Parses the command string into argv
    /// 5. Executes the command
    /// 6. Formats the reply
    ///
    /// # Parameters
    ///
    /// - `command`: The Redis command string (e.g., "GET mykey", "HGET hash field")
    /// - `server`: Server specification string (host:port/dbnumber/password)
    ///
    /// # Returns
    ///
    /// A `LookupResult` variant:
    /// - `Found` — command succeeded with data
    /// - `NotFound` — command returned no data (NIL reply)
    /// - `Deferred` — temporary failure (connection error, MOVED redirect)
    fn perform_search(&self, command: &str, server: &str) -> Result<LookupResult, DriverError> {
        // ── Parse server spec ─────────────────────────────────────────────
        let (spec, cache_key) = Self::parse_server_spec(server)?;

        // ── Get/create connection ─────────────────────────────────────────
        let mut cache = self.conn_cache.lock().map_err(|e| {
            DriverError::TempFail(format!("REDIS: failed to lock connection cache: {}", e))
        })?;

        // Attempt to get or create a connection
        let redis_conn = Self::get_or_create_connection(&mut cache, &cache_key, &spec)?;

        // ── Parse command into argv ───────────────────────────────────────
        let argv = Self::parse_command_argv(command);
        if argv.is_empty() {
            return Err(DriverError::ExecutionFailed(
                "REDIS: empty command".to_string(),
            ));
        }

        // ── Execute command ───────────────────────────────────────────────
        // C: redis_reply = redisCommandArgv(redis_handle, i, argv, NULL)
        let mut cmd = Cmd::new();
        for arg in &argv {
            cmd.arg(arg.as_str());
        }

        let result: Result<Value, redis::RedisError> = cmd.query(&mut redis_conn.conn);

        match result {
            Ok(value) => {
                // ── Format the reply ──────────────────────────────────────
                match Self::format_reply_value(&value) {
                    Some(formatted) => {
                        // Check for NIL-like responses (empty value)
                        if formatted.is_empty() {
                            // C: REDIS_REPLY_NIL → empty result with do_cache=0
                            Ok(LookupResult::Found {
                                value: formatted,
                                cache_ttl: Some(0),
                            })
                        } else {
                            Ok(LookupResult::Found {
                                value: formatted,
                                cache_ttl: None,
                            })
                        }
                    }
                    None => {
                        // NIL reply or empty array → no data found
                        // C: redis.c lines 257-263: REDIS_REPLY_NIL with do_cache=0
                        tracing::debug!("REDIS: query was not one that returned any data");
                        // C: do_cache = 0 for NIL results, and yield = FAIL
                        // if result is NULL after processing
                        Ok(LookupResult::NotFound)
                    }
                }
            }
            Err(err) => {
                // ── Handle Redis errors ───────────────────────────────────

                // Check for MOVED cluster redirect
                // C: if (Ustrncmp(redis_reply->str, "MOVED", 5) == 0)
                if Self::is_moved_error(&err) {
                    tracing::debug!("REDIS: cluster redirect: {}", err);
                    // C: defer_break = FALSE, return DEFER
                    // Return Deferred to allow trying next server
                    return Ok(LookupResult::Deferred {
                        message: format!("REDIS: cluster redirect: {}", err),
                    });
                }

                // Remove cached connection on error — it may be stale
                // C: "NOTE: Required to close connection since it needs to be reopened"
                tracing::warn!("REDIS: query failed: {}", err);
                cache.remove(&cache_key);

                Err(DriverError::ExecutionFailed(format!(
                    "REDIS: lookup result failed: {}",
                    err
                )))
            }
        }
    }
}

// =============================================================================
// LookupDriver Trait Implementation
// =============================================================================

impl LookupDriver for RedisLookup {
    /// Open a Redis lookup handle.
    ///
    /// Replaces C `redis_open()` (redis.c lines 30-34):
    /// ```c
    /// static void *redis_open(...) { return (void *)(1); }
    /// ```
    ///
    /// For Redis (query-style lookup), this is essentially a no-op. The actual
    /// connection is established lazily in `find()` when a server specification
    /// is available. Returns a dummy handle (unit type boxed) to satisfy the
    /// trait interface.
    fn open(&self, _filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        // C: return (void *)(1); — dummy non-NULL handle
        Ok(Box::new(()))
    }

    /// Check a Redis lookup file — always succeeds for query-style lookups.
    ///
    /// Redis is a query-style lookup with no associated file, so this always
    /// returns `Ok(true)`. C equivalent: `check` function pointer is NULL
    /// (redis.c line 452).
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

    /// Find a value by executing a Redis command.
    ///
    /// Replaces C `redis_find()` (redis.c lines 373-381) which delegates to
    /// `lf_sqlperform()` for multi-server iteration. In this Rust
    /// implementation, multi-server failover is handled by iterating over
    /// servers extracted from the query's `servers=` option.
    ///
    /// The `key_or_query` parameter contains the Redis command to execute.
    /// Server specifications are extracted from `options` (modern
    /// `servers=host/db/pw` syntax) or from the query itself.
    ///
    /// # Reply Formatting
    ///
    /// Redis replies are formatted as follows:
    /// - **String** → direct UTF-8 string
    /// - **Integer** → "true" (non-zero) / "false" (zero)
    /// - **Array** → elements joined by newlines (one level of nesting)
    /// - **Nil** → not found (cache disabled)
    /// - **Error** → MOVED triggers retry; other errors → execution failure
    fn find(
        &self,
        _handle: &LookupHandle,
        _filename: Option<&str>,
        key_or_query: &str,
        options: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        // Extract servers from options (modern syntax: servers=host/db/pw)
        // C: lf_sqlperform() handles server list iteration. In the Rust
        // implementation, we parse the server list from options and iterate.
        let servers = Self::extract_servers(key_or_query, options);

        if servers.is_empty() {
            return Err(DriverError::ConfigError(
                "REDIS: no server specified in options or query".to_string(),
            ));
        }

        // Extract the actual command (strip any servers= prefix from query)
        let command = Self::extract_command(key_or_query);

        // ── Multi-server failover iteration ───────────────────────────────
        // C: lf_sqlperform() tries each server in order, advancing on DEFER
        let mut last_error: Option<String> = None;

        for server in &servers {
            match self.perform_search(&command, server) {
                Ok(LookupResult::Found { value, cache_ttl }) => {
                    return Ok(LookupResult::Found { value, cache_ttl });
                }
                Ok(LookupResult::NotFound) => {
                    // NotFound is definitive — don't try other servers
                    return Ok(LookupResult::NotFound);
                }
                Ok(LookupResult::Deferred { message }) => {
                    // Deferred (e.g., MOVED) — try next server
                    tracing::warn!("REDIS: deferring to next server: {}", message);
                    last_error = Some(message);
                    continue;
                }
                Err(e) => {
                    // Connection or execution failure — try next server
                    tracing::warn!("REDIS: server {} failed: {}", server, e);
                    last_error = Some(e.to_string());
                    continue;
                }
            }
        }

        // All servers failed
        Ok(LookupResult::Deferred {
            message: last_error.unwrap_or_else(|| "REDIS: all servers failed".to_string()),
        })
    }

    /// Close a Redis lookup handle — no-op since connections are cached.
    ///
    /// C equivalent: `close` function pointer is NULL (redis.c line 453).
    /// Connections are managed by the connection cache and freed in `tidy()`.
    fn close(&self, _handle: LookupHandle) {
        // No-op: connections are cached in conn_cache and freed in tidy().
    }

    /// Close all cached Redis connections and clear the connection cache.
    ///
    /// Replaces C `redis_tidy()` (redis.c lines 38-53):
    /// ```c
    /// while ((cn = redis_connections)) {
    ///   redis_connections = cn->next;
    ///   DEBUG(D_lookup) debug_printf_indent("close REDIS connection: %s\n", cn->server);
    ///   redisFree(cn->handle);
    /// }
    /// ```
    ///
    /// Per AAP §0.4.3: "HashMap with explicit clear() replacing POOL_SEARCH".
    fn tidy(&self) {
        match self.conn_cache.lock() {
            Ok(mut cache) => {
                for key in cache.keys() {
                    tracing::debug!("close REDIS connection: {}", key);
                }
                cache.clear();
            }
            Err(e) => {
                tracing::warn!("REDIS tidy: failed to lock connection cache: {}", e);
            }
        }
    }

    /// Quote a string for safe use in Redis commands.
    ///
    /// Replaces C `redis_quote()` (redis.c lines 402-423). Prefixes any
    /// whitespace or backslash character with a backslash. This is NOT a
    /// Redis protocol feature — it supports Exim's argv-splitting mechanism
    /// which splits on whitespace and uses backslash as an escape character.
    ///
    /// Returns `None` if `additional` is `Some` (no options recognized),
    /// matching C behavior: `if (opt) return NULL;` (line 408).
    fn quote(&self, value: &str, additional: Option<&str>) -> Option<String> {
        // C: if (opt) return NULL; — no options recognized
        if additional.is_some() {
            return None;
        }

        // C: count whitespace and backslash characters for pre-allocation
        let extra = value
            .chars()
            .filter(|c| c.is_whitespace() || *c == '\\')
            .count();

        let mut result = String::with_capacity(value.len() + extra);

        // C: while ((c = *s++)) {
        //      if (isspace(c) || c == '\\') *t++ = '\\';
        //      *t++ = c;
        //    }
        for ch in value.chars() {
            if ch.is_whitespace() || ch == '\\' {
                result.push('\\');
            }
            result.push(ch);
        }

        Some(result)
    }

    /// Report the Redis library version for `-bV` output.
    ///
    /// Replaces C `redis_version_report()` (redis.c lines 430-435):
    /// ```c
    /// return string_fmt_append(g,
    ///     "Library version: REDIS: Compile: %d.%d.%d\n",
    ///     HIREDIS_MAJOR, HIREDIS_MINOR, HIREDIS_PATCH);
    /// ```
    ///
    /// Since the Rust implementation uses the `redis` crate instead of
    /// hiredis, we report the crate information.
    fn version_report(&self) -> Option<String> {
        tracing::info!("Library version: REDIS: redis crate (Rust native client)");
        Some("Library version: REDIS: redis crate 1.0.5 (Rust native client)\n".to_string())
    }

    /// Return the lookup type flags — Redis is a query-style lookup.
    ///
    /// C: `lookup_querystyle` at redis.c line 449.
    fn lookup_type(&self) -> LookupType {
        LookupType::QUERY_STYLE
    }

    /// Return the driver name for configuration file matching.
    ///
    /// C: `US"redis"` at redis.c line 448.
    fn driver_name(&self) -> &str {
        "redis"
    }
}

// =============================================================================
// Server List Extraction Helpers
// =============================================================================

impl RedisLookup {
    /// Extract the list of server specifications from query and options.
    ///
    /// Supports two formats:
    /// 1. Modern options syntax: `options` contains `servers=host/db/pw`
    /// 2. Legacy inline syntax: `key_or_query` starts with `servers=host/db/pw;command`
    ///
    /// C: `lf_sqlperform()` handles both server sources. In the Rust
    /// implementation, we parse the server list from both sources.
    fn extract_servers(key_or_query: &str, options: Option<&str>) -> Vec<String> {
        let mut servers = Vec::new();

        // Check options for servers= parameter
        if let Some(opts) = options {
            for part in opts.split_whitespace() {
                if let Some(server_list) = part.strip_prefix("servers=") {
                    // Server list may be colon-separated
                    for server in server_list.split(':') {
                        let trimmed = server.trim();
                        if !trimmed.is_empty() {
                            servers.push(trimmed.to_string());
                        }
                    }
                }
            }
        }

        // Check query for legacy inline servers= prefix
        if servers.is_empty() {
            if let Some(rest) = key_or_query.strip_prefix("servers=") {
                // Format: servers=host/db/pw;actual_command
                if let Some(semi_pos) = rest.find(';') {
                    let server_part = &rest[..semi_pos];
                    for server in server_part.split(':') {
                        let trimmed = server.trim();
                        if !trimmed.is_empty() {
                            servers.push(trimmed.to_string());
                        }
                    }
                }
            }
        }

        servers
    }

    /// Extract the actual command from a query string, stripping any
    /// `servers=...;` prefix.
    ///
    /// If the query starts with `servers=host/db/pw;command`, returns
    /// just the `command` portion. Otherwise returns the full query.
    fn extract_command(key_or_query: &str) -> String {
        if let Some(rest) = key_or_query.strip_prefix("servers=") {
            if let Some(semi_pos) = rest.find(';') {
                return rest[semi_pos + 1..].trim().to_string();
            }
        }
        key_or_query.to_string()
    }
}

// =============================================================================
// Compile-Time Driver Registration
// =============================================================================

// Register the Redis lookup driver with the inventory-based driver registry
// at compile time.
//
// Replaces C module registration at redis.c lines 447-467:
//   static lookup_info redis_lookup_info = {
//     .name = US"redis",
//     .type = lookup_querystyle,
//     .open = redis_open, ...
//   };
//   lookup_module_info redis_lookup_module_info = {
//     LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1
//   };
inventory::submit! {
    LookupDriverFactory {
        name: "redis",
        create: || Box::new(RedisLookup::new()),
        lookup_type: LookupType::QUERY_STYLE,
        avail_string: Some("redis (Redis via redis crate)"),
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
        let lookup = RedisLookup::new();
        let cache = lookup.conn_cache.lock().unwrap();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_default_is_same_as_new() {
        let lookup = RedisLookup::default();
        assert_eq!(lookup.driver_name(), "redis");
    }

    // ── Driver Metadata Tests ─────────────────────────────────────────────

    #[test]
    fn test_driver_name() {
        let lookup = RedisLookup::new();
        assert_eq!(lookup.driver_name(), "redis");
    }

    #[test]
    fn test_lookup_type_is_query_style() {
        let lookup = RedisLookup::new();
        assert!(lookup.lookup_type().is_query_style());
        assert!(!lookup.lookup_type().is_single_key());
    }

    #[test]
    fn test_version_report() {
        let lookup = RedisLookup::new();
        let report = lookup.version_report();
        assert!(report.is_some());
        let text = report.unwrap();
        assert!(text.contains("REDIS"));
        assert!(text.contains("redis crate"));
    }

    // ── Open/Close/Check Tests ────────────────────────────────────────────

    #[test]
    fn test_open_returns_handle() {
        let lookup = RedisLookup::new();
        let handle = lookup.open(None);
        assert!(handle.is_ok());
    }

    #[test]
    fn test_check_always_true() {
        let lookup = RedisLookup::new();
        let handle = lookup.open(None).unwrap();
        let result = lookup.check(&handle, None, 0, &[], &[]);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_close_is_noop() {
        let lookup = RedisLookup::new();
        let handle = lookup.open(None).unwrap();
        // Should not panic
        lookup.close(handle);
    }

    // ── Tidy Tests ────────────────────────────────────────────────────────

    #[test]
    fn test_tidy_clears_cache() {
        let lookup = RedisLookup::new();
        // Manually insert a dummy entry to test clearing
        // (We can't insert a real connection without a Redis server)
        // Just verify tidy doesn't panic on empty cache
        lookup.tidy();
        let cache = lookup.conn_cache.lock().unwrap();
        assert!(cache.is_empty());
    }

    // ── Server Spec Parsing Tests ─────────────────────────────────────────

    #[test]
    fn test_parse_server_spec_full() {
        let (spec, cache_key) =
            RedisLookup::parse_server_spec("localhost:6379/1/mypassword").unwrap();
        assert_eq!(spec.host, "localhost");
        assert_eq!(spec.port, 6379);
        assert_eq!(spec.dbnumber, Some("1".to_string()));
        assert_eq!(spec.password, Some("mypassword".to_string()));
        assert!(spec.socket.is_none());
        assert_eq!(cache_key, "localhost:6379/1");
    }

    #[test]
    fn test_parse_server_spec_no_password() {
        let (spec, cache_key) =
            RedisLookup::parse_server_spec("redis.example.com:6380/0/").unwrap();
        assert_eq!(spec.host, "redis.example.com");
        assert_eq!(spec.port, 6380);
        assert_eq!(spec.dbnumber, Some("0".to_string()));
        assert!(spec.password.is_none());
        assert_eq!(cache_key, "redis.example.com:6380/0");
    }

    #[test]
    fn test_parse_server_spec_no_db() {
        let (spec, cache_key) = RedisLookup::parse_server_spec("localhost//secret").unwrap();
        assert_eq!(spec.host, "localhost");
        assert_eq!(spec.port, 6379);
        assert!(spec.dbnumber.is_none());
        assert_eq!(spec.password, Some("secret".to_string()));
        assert_eq!(cache_key, "localhost/");
    }

    #[test]
    fn test_parse_server_spec_socket() {
        let (spec, _cache_key) =
            RedisLookup::parse_server_spec("localhost(/tmp/redis.sock)/2/pass").unwrap();
        assert_eq!(spec.socket, Some("/tmp/redis.sock".to_string()));
        assert_eq!(spec.dbnumber, Some("2".to_string()));
        assert_eq!(spec.password, Some("pass".to_string()));
    }

    #[test]
    fn test_parse_server_spec_default_port() {
        let (spec, _) = RedisLookup::parse_server_spec("myhost/3/").unwrap();
        assert_eq!(spec.host, "myhost");
        assert_eq!(spec.port, 6379);
        assert_eq!(spec.dbnumber, Some("3".to_string()));
    }

    #[test]
    fn test_parse_server_spec_incomplete() {
        let result = RedisLookup::parse_server_spec("localhost");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_server_spec_single_slash() {
        let result = RedisLookup::parse_server_spec("localhost/password");
        // Only one slash — should fail because we need host/db/pass format
        assert!(result.is_err());
    }

    // ── Command Argv Parsing Tests ────────────────────────────────────────

    #[test]
    fn test_parse_simple_command() {
        let argv = RedisLookup::parse_command_argv("GET mykey");
        assert_eq!(argv, vec!["GET", "mykey"]);
    }

    #[test]
    fn test_parse_multi_arg_command() {
        let argv = RedisLookup::parse_command_argv("HGET myhash myfield");
        assert_eq!(argv, vec!["HGET", "myhash", "myfield"]);
    }

    #[test]
    fn test_parse_backslash_escaped_space() {
        let argv = RedisLookup::parse_command_argv("SET my\\ key my\\ value");
        assert_eq!(argv, vec!["SET", "my key", "my value"]);
    }

    #[test]
    fn test_parse_backslash_escaped_backslash() {
        let argv = RedisLookup::parse_command_argv("SET key with\\\\slash");
        assert_eq!(argv, vec!["SET", "key", "with\\slash"]);
    }

    #[test]
    fn test_parse_leading_trailing_whitespace() {
        let argv = RedisLookup::parse_command_argv("  GET   mykey  ");
        assert_eq!(argv, vec!["GET", "mykey"]);
    }

    #[test]
    fn test_parse_empty_command() {
        let argv = RedisLookup::parse_command_argv("");
        assert!(argv.is_empty());
    }

    #[test]
    fn test_parse_whitespace_only() {
        let argv = RedisLookup::parse_command_argv("   ");
        assert!(argv.is_empty());
    }

    // ── Quote Tests ───────────────────────────────────────────────────────

    #[test]
    fn test_quote_no_special_chars() {
        let lookup = RedisLookup::new();
        let result = lookup.quote("hello", None);
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn test_quote_with_spaces() {
        let lookup = RedisLookup::new();
        let result = lookup.quote("hello world", None);
        assert_eq!(result, Some("hello\\ world".to_string()));
    }

    #[test]
    fn test_quote_with_backslash() {
        let lookup = RedisLookup::new();
        let result = lookup.quote("back\\slash", None);
        assert_eq!(result, Some("back\\\\slash".to_string()));
    }

    #[test]
    fn test_quote_with_tab() {
        let lookup = RedisLookup::new();
        let result = lookup.quote("tab\there", None);
        assert_eq!(result, Some("tab\\\there".to_string()));
    }

    #[test]
    fn test_quote_with_option_returns_none() {
        let lookup = RedisLookup::new();
        let result = lookup.quote("hello", Some("opt"));
        assert!(result.is_none());
    }

    #[test]
    fn test_quote_mixed_special_chars() {
        let lookup = RedisLookup::new();
        let result = lookup.quote("a b\\c", None);
        assert_eq!(result, Some("a\\ b\\\\c".to_string()));
    }

    // ── Reply Formatting Tests ────────────────────────────────────────────

    #[test]
    fn test_format_bulk_string() {
        let val = Value::BulkString(b"hello".to_vec());
        assert_eq!(
            RedisLookup::format_reply_value(&val),
            Some("hello".to_string())
        );
    }

    #[test]
    fn test_format_simple_string() {
        let val = Value::SimpleString("OK".to_string());
        assert_eq!(
            RedisLookup::format_reply_value(&val),
            Some("OK".to_string())
        );
    }

    #[test]
    fn test_format_okay() {
        let val = Value::Okay;
        assert_eq!(
            RedisLookup::format_reply_value(&val),
            Some("OK".to_string())
        );
    }

    #[test]
    fn test_format_integer_nonzero() {
        let val = Value::Int(42);
        assert_eq!(
            RedisLookup::format_reply_value(&val),
            Some("true".to_string())
        );
    }

    #[test]
    fn test_format_integer_zero() {
        let val = Value::Int(0);
        assert_eq!(
            RedisLookup::format_reply_value(&val),
            Some("false".to_string())
        );
    }

    #[test]
    fn test_format_nil() {
        let val = Value::Nil;
        assert_eq!(RedisLookup::format_reply_value(&val), None);
    }

    #[test]
    fn test_format_array_strings() {
        let val = Value::Array(vec![
            Value::BulkString(b"one".to_vec()),
            Value::BulkString(b"two".to_vec()),
            Value::BulkString(b"three".to_vec()),
        ]);
        assert_eq!(
            RedisLookup::format_reply_value(&val),
            Some("one\ntwo\nthree".to_string())
        );
    }

    #[test]
    fn test_format_array_integers() {
        let val = Value::Array(vec![Value::Int(1), Value::Int(2), Value::Int(3)]);
        assert_eq!(
            RedisLookup::format_reply_value(&val),
            Some("1\n2\n3".to_string())
        );
    }

    #[test]
    fn test_format_array_mixed() {
        let val = Value::Array(vec![Value::BulkString(b"key".to_vec()), Value::Int(42)]);
        assert_eq!(
            RedisLookup::format_reply_value(&val),
            Some("key\n42".to_string())
        );
    }

    #[test]
    fn test_format_nested_array() {
        let val = Value::Array(vec![
            Value::BulkString(b"outer".to_vec()),
            Value::Array(vec![Value::BulkString(b"inner1".to_vec()), Value::Int(99)]),
        ]);
        assert_eq!(
            RedisLookup::format_reply_value(&val),
            Some("outer\ninner1\n99".to_string())
        );
    }

    #[test]
    fn test_format_empty_array() {
        let val = Value::Array(vec![]);
        assert_eq!(RedisLookup::format_reply_value(&val), None);
    }

    #[test]
    fn test_format_double() {
        let val = Value::Double(3.14);
        let result = RedisLookup::format_reply_value(&val);
        assert!(result.is_some());
        assert!(result.unwrap().starts_with("3.14"));
    }

    #[test]
    fn test_format_boolean_true() {
        let val = Value::Boolean(true);
        assert_eq!(
            RedisLookup::format_reply_value(&val),
            Some("true".to_string())
        );
    }

    #[test]
    fn test_format_boolean_false() {
        let val = Value::Boolean(false);
        assert_eq!(
            RedisLookup::format_reply_value(&val),
            Some("false".to_string())
        );
    }

    // ── Server Extraction Tests ───────────────────────────────────────────

    #[test]
    fn test_extract_servers_from_options() {
        let servers = RedisLookup::extract_servers("GET mykey", Some("servers=localhost/0/pass"));
        assert_eq!(servers, vec!["localhost/0/pass"]);
    }

    #[test]
    fn test_extract_servers_from_options_multiple() {
        let servers =
            RedisLookup::extract_servers("GET mykey", Some("servers=host1/0/p1:host2/0/p2"));
        assert_eq!(servers, vec!["host1/0/p1", "host2/0/p2"]);
    }

    #[test]
    fn test_extract_servers_from_query() {
        let servers = RedisLookup::extract_servers("servers=localhost/0/pass;GET mykey", None);
        assert_eq!(servers, vec!["localhost/0/pass"]);
    }

    #[test]
    fn test_extract_servers_none() {
        let servers = RedisLookup::extract_servers("GET mykey", None);
        assert!(servers.is_empty());
    }

    #[test]
    fn test_extract_command_with_servers_prefix() {
        let cmd = RedisLookup::extract_command("servers=localhost/0/pass;GET mykey");
        assert_eq!(cmd, "GET mykey");
    }

    #[test]
    fn test_extract_command_plain() {
        let cmd = RedisLookup::extract_command("GET mykey");
        assert_eq!(cmd, "GET mykey");
    }

    // ── Host:Port Parsing Tests ───────────────────────────────────────────

    #[test]
    fn test_parse_host_port_with_port() {
        let (host, port) = RedisLookup::parse_host_port("redis.example.com:6380");
        assert_eq!(host, "redis.example.com");
        assert_eq!(port, 6380);
    }

    #[test]
    fn test_parse_host_port_without_port() {
        let (host, port) = RedisLookup::parse_host_port("redis.example.com");
        assert_eq!(host, "redis.example.com");
        assert_eq!(port, 6379);
    }

    #[test]
    fn test_parse_host_port_invalid_port() {
        let (host, port) = RedisLookup::parse_host_port("redis.example.com:notaport");
        assert_eq!(host, "redis.example.com");
        assert_eq!(port, 6379); // Falls back to default
    }

    // ── Socket Extraction Tests ───────────────────────────────────────────

    #[test]
    fn test_extract_paren_socket_present() {
        let (rest, socket) = RedisLookup::extract_paren_socket("localhost(/tmp/redis.sock)");
        assert_eq!(rest, "localhost");
        assert_eq!(socket, Some("/tmp/redis.sock".to_string()));
    }

    #[test]
    fn test_extract_paren_socket_absent() {
        let (rest, socket) = RedisLookup::extract_paren_socket("localhost");
        assert_eq!(rest, "localhost");
        assert!(socket.is_none());
    }

    // ── DriverError Variant Usage Tests ───────────────────────────────────

    #[test]
    fn test_driver_error_temp_fail() {
        let err = DriverError::TempFail("connection refused".to_string());
        assert!(err.to_string().contains("connection refused"));
    }

    #[test]
    fn test_driver_error_execution_failed() {
        let err = DriverError::ExecutionFailed("MOVED 3999 127.0.0.1:6380".to_string());
        assert!(err.to_string().contains("MOVED"));
    }

    #[test]
    fn test_driver_error_config_error() {
        let err = DriverError::ConfigError("bad server spec".to_string());
        assert!(err.to_string().contains("bad server spec"));
    }

    // ── Find with no servers Tests ────────────────────────────────────────

    #[test]
    fn test_find_no_servers_returns_error() {
        let lookup = RedisLookup::new();
        let handle = lookup.open(None).unwrap();
        let result = lookup.find(&handle, None, "GET mykey", None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DriverError::ConfigError(_)));
    }
}
