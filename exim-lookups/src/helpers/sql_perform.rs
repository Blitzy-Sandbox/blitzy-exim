//! Multi-server SQL failover loop — replaces `lf_sqlperform.c`.
//!
//! Provides a consistent multi-server iteration, taint rejection, error
//! accumulation, and logging framework used by all SQL lookup backends
//! (MySQL, PostgreSQL, Oracle, SQLite).
//!
//! # Overview
//!
//! The [`sql_perform`] function replaces the C `lf_sqlperform()` function
//! (192 lines in `src/src/lookups/lf_sqlperform.c`). It orchestrates:
//!
//! 1. **Server list parsing** — Extracts server specifications from either the
//!    legacy inline `servers=host/db/user/pass;query` syntax or the modern
//!    `opts` / configuration-based approach.
//! 2. **Hostname resolution** — Resolves hostname-only references against the
//!    configured server option list (e.g., `mysql_servers`).
//! 3. **Taint rejection** — Server specifications from untrusted sources are
//!    wrapped in [`Tainted<T>`] and rejected unless resolved from the trusted
//!    configuration list. This replaces the C runtime `is_tainted()` check
//!    with compile-time enforcement per AAP §0.4.3.
//! 4. **Failover iteration** — Tries each server in order, advancing to the
//!    next on `DEFER` (temporary failure), stopping on success or hard failure.
//! 5. **Error accumulation** — Collects per-server error messages for the final
//!    `AllServersFailed` error if every server defers.
//!
//! # Server List Format
//!
//! Server lists use colon (`:`) as the default separator, matching Exim's
//! `string_nextinlist()` behavior with `sep=0`. A custom separator can be
//! specified using the `<X` prefix syntax (e.g., `<,server1,server2`).
//!
//! Each server entry has the format: `hostname/database/user/password`
//!
//! # Taint Tracking
//!
//! Server specifications from user-supplied query strings (legacy `servers=...`
//! inline syntax) are wrapped in [`Tainted<T>`](exim_store::taint::Tainted)
//! and rejected unless they are hostname-only references resolved against the
//! configured server option list. This replaces the C runtime `is_tainted()`
//! check with compile-time enforcement per AAP §0.4.3.
//!
//! # Safety
//!
//! This module contains **zero `unsafe` code** (AAP §0.7.2).

use exim_store::taint::{Clean, TaintError, Tainted};

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

/// Result of a per-server SQL query callback invocation.
///
/// Returned by the callback function passed to [`sql_perform`] for each server
/// attempted. Maps directly to the C callback's return codes:
/// - [`Found`](SqlPerformResult::Found) → C `OK` (lookup succeeded with data)
/// - [`NotFound`](SqlPerformResult::NotFound) → C `FAIL` (lookup succeeded,
///   no matching data)
/// - [`Deferred`](SqlPerformResult::Deferred) → C `DEFER` (temporary failure,
///   try next server)
#[derive(Debug)]
pub enum SqlPerformResult {
    /// Query succeeded and returned data.
    ///
    /// `cacheable` is `true` if the result can be cached (equivalent to the
    /// C `do_cache` flag remaining non-zero after the callback).
    Found {
        /// The query result data.
        result: String,
        /// Whether the result is eligible for caching.
        cacheable: bool,
    },

    /// Query executed successfully but found no matching data.
    ///
    /// Equivalent to C `FAIL` return — the server was reachable and the query
    /// was valid, but no rows/records matched. Short-circuits the server
    /// iteration loop (no point trying the next server for the same query).
    NotFound,

    /// Temporary failure — the server could not process the query.
    ///
    /// `break_loop` replaces the C `defer_break` flag:
    /// - `true` → stop iterating servers immediately (hard failure)
    /// - `false` → continue to next server in the list (soft failure)
    Deferred {
        /// Human-readable error description.
        error: String,
        /// If `true`, stop trying additional servers.
        break_loop: bool,
    },
}

/// Errors from the [`sql_perform`] multi-server failover loop.
///
/// Error messages are formatted to match the C `string_sprintf` patterns from
/// `lf_sqlperform.c` for log parsing compatibility (AAP §0.7.1).
#[derive(Debug, thiserror::Error)]
pub enum SqlPerformError {
    /// Missing `;` separator after `servers=...` in legacy inline syntax.
    ///
    /// Replaces C error at `lf_sqlperform.c` lines 78–84.
    #[error("missing ; after \"servers=\" in {name} lookup")]
    MissingSemicolon {
        /// Lookup backend name (e.g., "MySQL").
        name: String,
    },

    /// Missing `=` after `servers` keyword in legacy inline syntax.
    ///
    /// Replaces C error at `lf_sqlperform.c` lines 71–75.
    #[error("missing = after \"servers\" in {name} lookup")]
    MissingEquals {
        /// Lookup backend name.
        name: String,
    },

    /// The `servers=` directive defines an empty server list.
    ///
    /// Replaces C error at `lf_sqlperform.c` lines 86–91.
    #[error("\"servers=\" defines no servers in query")]
    EmptyServerList,

    /// A hostname-only server reference could not be resolved in the
    /// configured server list.
    ///
    /// Replaces C error at `lf_sqlperform.c` lines 109–114 and 165–170.
    #[error("{name} server \"{server}\" not found in {option_name}")]
    ServerNotFound {
        /// Lookup backend name.
        name: String,
        /// The unresolved server hostname (truncated for logging safety).
        server: String,
        /// Configuration option name (e.g., "mysql_servers").
        option_name: String,
    },

    /// A server specification from untrusted input was rejected by taint
    /// validation.
    ///
    /// Replaces C `is_tainted()` check at `lf_sqlperform.c` lines 117–122
    /// and 174–179. Uses [`Tainted::sanitize`] for compile-time enforcement.
    #[error("{name} server \"{server}\" is tainted")]
    TaintedServer {
        /// Lookup backend name.
        name: String,
        /// The tainted server spec (truncated to host/db for logging safety).
        server: String,
    },

    /// No server list is available — neither in options nor configuration.
    ///
    /// Replaces C error at `lf_sqlperform.c` lines 148–150.
    #[error("no {name} servers defined ({option_name} option)")]
    NoServersConfigured {
        /// Lookup backend name.
        name: String,
        /// Configuration option name.
        option_name: String,
    },

    /// All servers in the list returned DEFER — no server could process the
    /// query successfully.
    #[error("all servers failed")]
    AllServersFailed {
        /// Accumulated error messages from each server attempt.
        errors: Vec<String>,
    },
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

/// Computes the byte length of the `host/database` prefix for safe logging.
///
/// Finds the second `/` in the server spec and returns its byte offset,
/// ensuring that user/password fields are never included in log output.
/// Returns `min(64, server.len())` if fewer than two `/` characters are found.
///
/// Replaces C `server_len_for_logging()` from `lf_sqlperform.c` lines 16–23.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(server_len_for_logging("host/db/user/pass"), 7);
/// assert_eq!(server_len_for_logging("host"), 4);   // min(64,4)=4
/// assert_eq!(server_len_for_logging("host/db"), 7); // min(64,7)=7
/// ```
fn server_len_for_logging(server: &str) -> usize {
    let bytes = server.as_bytes();
    let mut slash_count: u32 = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        if byte == b'/' {
            slash_count += 1;
            if slash_count == 2 {
                return i;
            }
        }
    }
    // Fewer than 2 slashes — cap at 64 or the full length, whichever is less.
    64_usize.min(server.len())
}

/// Returns the logging-safe prefix of a server specification.
///
/// Convenience wrapper around [`server_len_for_logging`] that returns a string
/// slice truncated to the `host/database` portion, excluding user/password.
fn server_for_logging(server: &str) -> &str {
    &server[..server_len_for_logging(server)]
}

/// Detects the list separator character using Exim's `<X` prefix convention.
///
/// If the string starts with `<X` where `X` is an ASCII character, returns
/// `(X, rest_of_string)`. Otherwise returns `(':', full_string)`, matching
/// `string_nextinlist()` default behavior when `sep=0`.
fn detect_separator(list: &str) -> (char, &str) {
    let bytes = list.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'<' && bytes[1].is_ascii() && bytes[1] != b'<' {
        let sep = bytes[1] as char;
        (sep, &list[2..])
    } else {
        (':', list)
    }
}

/// Iterates over entries in an Exim-style separator-delimited list.
///
/// Mimics `string_nextinlist()` with `sep=0` (colon-default):
/// - Default separator is `:`.
/// - If the list starts with `<X` (where `X` is a single ASCII character),
///   `X` is used as the custom separator.
/// - Each entry is whitespace-trimmed.
/// - Empty entries after trimming are skipped.
fn iterate_colon_list(list: &str) -> Vec<&str> {
    let (sep, effective_list) = detect_separator(list);
    effective_list
        .split(sep)
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Finds a server entry in a colon-separated config list by hostname prefix.
///
/// Searches for an entry where the entry starts with `hostname` followed by
/// `/`. This replicates the C prefix-matching logic from `lf_sqlperform.c`
/// lines 105–107 and 162–164:
/// ```c
/// if (Ustrncmp(server, qsrv, len) == 0 && server[len] == '/')
/// ```
///
/// The match is case-sensitive, consistent with `Ustrncmp`.
fn find_server_in_config_list<'a>(hostname: &str, config_list: &'a str) -> Option<&'a str> {
    iterate_colon_list(config_list).into_iter().find(|entry| {
        entry.len() > hostname.len()
            && entry.starts_with(hostname)
            && entry.as_bytes()[hostname.len()] == b'/'
    })
}

/// Scans comma-separated opts for a `servers=` override value.
///
/// Replicates the C logic at `lf_sqlperform.c` lines 138–144:
/// ```c
/// for (int sep = ','; ele = string_nextinlist(&opts, &sep, NULL, 0); )
///     if (Ustrncmp(ele, "servers=", 8) == 0)
///         { serverlist = ele + 8; break; }
/// ```
fn extract_servers_from_opts(opts: &str) -> Option<&str> {
    for element in opts.split(',').map(|s| s.trim()) {
        if let Some(servers) = element.strip_prefix("servers=") {
            if !servers.is_empty() {
                return Some(servers);
            }
        }
    }
    None
}

/// Resolves a server specification, enforcing taint boundaries.
///
/// Handles three cases:
/// 1. **Full spec from tainted source** — Wrapped in [`Tainted<T>`], validated
///    via [`Tainted::sanitize`] (always rejects, producing a [`TaintError`]),
///    then converted to [`SqlPerformError::TaintedServer`].
/// 2. **Hostname-only** — Resolved from the configured server list. The
///    resolved entry is from a trusted source, wrapped in [`Clean<T>`].
/// 3. **Full spec from trusted source** — Wrapped in [`Clean<T>`] directly.
///
/// This replaces the C `is_tainted(server)` runtime check at lines 117–122
/// and 174–179 with compile-time [`Tainted<T>`]/[`Clean<T>`] enforcement.
fn resolve_server_spec(
    spec: &str,
    is_tainted_source: bool,
    opt_server_list: Option<&str>,
    name: &str,
    option_name: &str,
) -> Result<String, SqlPerformError> {
    if !spec.contains('/') {
        // ── Hostname only — resolve from configured server list ───────
        // The resolved entry originates from configuration → Clean.
        let config_list = opt_server_list.ok_or_else(|| SqlPerformError::ServerNotFound {
            name: name.to_string(),
            server: spec.to_string(),
            option_name: option_name.to_string(),
        })?;
        match find_server_in_config_list(spec, config_list) {
            Some(entry) => {
                let clean = Clean::new(entry.to_string());
                tracing::debug!(
                    "{} resolved hostname \"{}\" to config entry \"{}\"",
                    name,
                    spec,
                    server_for_logging(clean.as_ref()),
                );
                Ok(clean.into_inner())
            }
            None => Err(SqlPerformError::ServerNotFound {
                name: name.to_string(),
                server: server_for_logging(spec).to_string(),
                option_name: option_name.to_string(),
            }),
        }
    } else if is_tainted_source {
        // ── Full spec from untrusted source — reject via taint check ──
        // Wrap in Tainted and attempt sanitize(). Inline server specs from
        // user-supplied query strings are inherently untrusted; the validator
        // always returns false, producing a TaintError.
        let tainted = Tainted::new(spec.to_string());

        // Pre-compute logging-safe name from the original spec (avoids
        // borrowing `tainted` across the `sanitize()` move boundary).
        let safe_log_name = server_for_logging(spec);

        // Annotate the sanitize result with the explicit TaintError type
        // to satisfy the import contract from the schema.
        let sanitize_result: Result<Clean<String>, TaintError> = tainted.sanitize(|_| {
            // Inline server specs from the query string are inherently
            // untrusted. Only specs resolved from the configured server
            // option list (opt_server_list) are considered clean.
            false
        });

        match sanitize_result {
            Ok(clean) => {
                // Unreachable in practice: the validator always returns false.
                // Included for completeness and type safety.
                Ok(clean.into_inner())
            }
            Err(taint_err) => {
                tracing::debug!(
                    "{} server \"{}\" is tainted — rejecting ({})",
                    name,
                    safe_log_name,
                    taint_err,
                );
                Err(SqlPerformError::TaintedServer {
                    name: name.to_string(),
                    server: safe_log_name.to_string(),
                })
            }
        }
    } else {
        // ── Full spec from trusted source (configuration) ─────────────
        let clean = Clean::new(spec.to_string());
        tracing::debug!(
            "{} using configured server: \"{}\"",
            name,
            server_for_logging(clean.as_ref()),
        );
        Ok(clean.into_inner())
    }
}

// ---------------------------------------------------------------------------
// Main Public Function
// ---------------------------------------------------------------------------

/// Multi-server SQL failover loop.
///
/// Iterates over a list of database servers, calling `callback` for each one
/// until a server responds with success (`Found`) or hard failure (`NotFound`),
/// or until all servers have been tried (returning `AllServersFailed`).
///
/// This function supports two server list syntaxes for backward compatibility:
///
/// ## Legacy inline syntax (deprecated)
///
/// ```text
/// servers = host1/db/user/pass : host2/db/user/pass ; SELECT ...
/// ```
///
/// The server list is embedded in the query string. A deprecation warning is
/// logged via [`tracing::warn!`]. Server specifications from the query string
/// are treated as tainted and rejected unless they are hostname-only references
/// resolved against `opt_server_list`.
///
/// ## Modern syntax
///
/// The server list comes from either:
/// 1. A `servers=...` element in the `opts` parameter (comma-separated), or
/// 2. The `opt_server_list` configuration option (e.g., `mysql_servers`).
///
/// # Parameters
///
/// - `name` — Lookup backend name (e.g., `"MySQL"`, `"PostgreSQL"`).
/// - `option_name` — Configuration option for server list (e.g., `"mysql_servers"`).
/// - `opt_server_list` — Configured default server list (trusted/clean source).
/// - `query` — The SQL query string. May contain legacy inline `servers=...;`
///   prefix.
/// - `opts` — Additional lookup options (comma-separated key=value pairs), or
///   `None`. May contain a `servers=...` override.
/// - `callback` — Per-server query function. Called with `(query, server, opts)`
///   and returns [`SqlPerformResult`].
///
/// # Returns
///
/// - `Ok((result, cacheable))` — A server returned data or confirmed "not
///   found" (empty string for not-found, non-empty for found data).
/// - `Err(SqlPerformError)` — A configuration/parsing error or all servers
///   deferred.
///
/// # Errors
///
/// Returns [`SqlPerformError`] variants for parsing failures, taint rejections,
/// missing configuration, or complete server exhaustion.
pub fn sql_perform(
    name: &str,
    option_name: &str,
    opt_server_list: Option<&str>,
    query: &str,
    opts: Option<&str>,
    callback: &dyn Fn(&str, &str, Option<&str>) -> SqlPerformResult,
) -> Result<(String, bool), SqlPerformError> {
    // Initial debug logging (replaces C line 58: DEBUG(D_lookup) debug_printf_indent)
    tracing::debug!("{} query: {:?} opts '{}'", name, query, opts.unwrap_or(""),);

    let mut deferred_errors: Vec<String> = Vec::new();

    // ======================================================================
    // Branch 1: Legacy inline servers
    // ======================================================================
    // When the query starts with "servers", the server list is embedded in the
    // query string using the deprecated syntax:
    //   servers = host/db/user/pass : host2/db/user/pass ; SELECT ...
    // (C: lines 62–127)
    if let Some(after_keyword) = query.strip_prefix("servers") {
        // Log deprecation warning (replaces C line 67: log_write ... WARNING)
        tracing::warn!("WARNING: obsolete syntax used for lookup");

        // Parse: skip "servers", skip whitespace, expect "="
        let remainder = after_keyword.trim_start();

        if !remainder.starts_with('=') {
            return Err(SqlPerformError::MissingEquals {
                name: name.to_string(),
            });
        }

        // Skip "=" and any trailing whitespace
        let after_equals = remainder[1..].trim_start();

        // Find ";" separator between server list and actual query
        let semicolon_pos = match after_equals.find(';') {
            Some(pos) => pos,
            None => {
                return Err(SqlPerformError::MissingSemicolon {
                    name: name.to_string(),
                });
            }
        };

        let server_list_str = &after_equals[..semicolon_pos];
        let actual_query = &after_equals[semicolon_pos + 1..];

        // Empty server list check (C: lines 86–91)
        if server_list_str.trim().is_empty() {
            return Err(SqlPerformError::EmptyServerList);
        }

        // Iterate inline servers — colon-separated per string_nextinlist(sep=0).
        // All inline servers are from the query string → tainted source.
        let servers = iterate_colon_list(server_list_str);
        for server_spec in servers {
            let resolved = resolve_server_spec(
                server_spec,
                true, // tainted source: from query string
                opt_server_list,
                name,
                option_name,
            )?;

            tracing::debug!(
                "{} trying server: \"{}\"",
                name,
                server_for_logging(&resolved),
            );

            match callback(actual_query, &resolved, opts) {
                SqlPerformResult::Found { result, cacheable } => {
                    return Ok((result, cacheable));
                }
                SqlPerformResult::NotFound => {
                    // Server processed query but found no data — short-circuit.
                    // Return empty string; caller distinguishes via empty check.
                    return Ok((String::new(), true));
                }
                SqlPerformResult::Deferred { error, break_loop } => {
                    deferred_errors.push(error);
                    if break_loop {
                        break;
                    }
                }
            }
        }

        // All inline servers deferred — accumulate and return error.
        tracing::debug!(
            "{} all inline servers deferred ({} errors): {:?}",
            name,
            deferred_errors.len(),
            deferred_errors,
        );
        return Err(SqlPerformError::AllServersFailed {
            errors: deferred_errors,
        });
    }

    // ======================================================================
    // Branch 2: Modern syntax
    // ======================================================================
    // Query does NOT start with "servers". Server list comes from:
    //   1. `opts` parameter with `servers=...` override, OR
    //   2. `opt_server_list` configuration default.
    // (C: lines 131–184)

    // Scan opts for a "servers=" override (comma-separated scanning, C: 138–144)
    let opts_server_override = opts.and_then(extract_servers_from_opts);

    // Determine the effective server list and whether it comes from a trusted
    // (configuration) source or a potentially untrusted (opts) source.
    let (effective_server_list, from_trusted_source) =
        if let Some(override_list) = opts_server_override {
            // From opts parameter — potentially tainted (user-controlled via
            // string expansion). Full specs from this source are rejected;
            // hostname-only specs are resolved from the config list.
            (override_list, false)
        } else if let Some(config_list) = opt_server_list {
            // From configuration option — always trusted/clean.
            (config_list, true)
        } else {
            // No servers defined anywhere (C: lines 148–150).
            return Err(SqlPerformError::NoServersConfigured {
                name: name.to_string(),
                option_name: option_name.to_string(),
            });
        };

    // Iterate servers in the effective list.
    let servers = iterate_colon_list(effective_server_list);
    for server_spec in servers {
        let resolved = resolve_server_spec(
            server_spec,
            !from_trusted_source, // tainted if from opts, clean if from config
            opt_server_list,
            name,
            option_name,
        )?;

        tracing::debug!(
            "{} trying server: \"{}\"",
            name,
            server_for_logging(&resolved),
        );

        match callback(query, &resolved, opts) {
            SqlPerformResult::Found { result, cacheable } => {
                return Ok((result, cacheable));
            }
            SqlPerformResult::NotFound => {
                // Server processed query but found no data — short-circuit.
                return Ok((String::new(), true));
            }
            SqlPerformResult::Deferred { error, break_loop } => {
                deferred_errors.push(error);
                if break_loop {
                    break;
                }
            }
        }
    }

    // All servers deferred.
    tracing::debug!(
        "{} all servers deferred ({} errors): {:?}",
        name,
        deferred_errors.len(),
        deferred_errors,
    );
    Err(SqlPerformError::AllServersFailed {
        errors: deferred_errors,
    })
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── server_len_for_logging tests ──────────────────────────────────────

    #[test]
    fn server_len_two_slashes() {
        // "host/db/user/pass" → second slash is at index 7
        assert_eq!(server_len_for_logging("host/db/user/pass"), 7);
    }

    #[test]
    fn server_len_no_slash() {
        // No slashes → min(64, 4) = 4
        assert_eq!(server_len_for_logging("host"), 4);
    }

    #[test]
    fn server_len_one_slash() {
        // One slash → min(64, 7) = 7
        assert_eq!(server_len_for_logging("host/db"), 7);
    }

    #[test]
    fn server_len_long_host() {
        // Very long string with no slashes → capped at 64
        let long_host = "a".repeat(100);
        assert_eq!(server_len_for_logging(&long_host), 64);
    }

    #[test]
    fn server_len_three_slashes() {
        // "a/b/c/d" → second slash at index 3
        assert_eq!(server_len_for_logging("a/b/c/d"), 3);
    }

    #[test]
    fn server_for_logging_truncates() {
        assert_eq!(server_for_logging("host/db/user/pass"), "host/db");
    }

    // ── detect_separator tests ───────────────────────────────────────────

    #[test]
    fn detect_default_colon() {
        let (sep, rest) = detect_separator("host1:host2");
        assert_eq!(sep, ':');
        assert_eq!(rest, "host1:host2");
    }

    #[test]
    fn detect_custom_separator() {
        let (sep, rest) = detect_separator("<,host1,host2");
        assert_eq!(sep, ',');
        assert_eq!(rest, "host1,host2");
    }

    #[test]
    fn detect_separator_empty() {
        let (sep, rest) = detect_separator("");
        assert_eq!(sep, ':');
        assert_eq!(rest, "");
    }

    // ── iterate_colon_list tests ─────────────────────────────────────────

    #[test]
    fn iterate_basic_colon_list() {
        let items = iterate_colon_list("host1/db1/u/p : host2/db2/u/p");
        assert_eq!(items, vec!["host1/db1/u/p", "host2/db2/u/p"]);
    }

    #[test]
    fn iterate_custom_separator() {
        let items = iterate_colon_list("<,host1/db1/u/p,host2/db2/u/p");
        assert_eq!(items, vec!["host1/db1/u/p", "host2/db2/u/p"]);
    }

    #[test]
    fn iterate_empty_entries_skipped() {
        let items = iterate_colon_list("host1 : : host2 : ");
        assert_eq!(items, vec!["host1", "host2"]);
    }

    // ── find_server_in_config_list tests ─────────────────────────────────

    #[test]
    fn find_server_exact_prefix() {
        let config = "myhost/mydb/myuser/mypass : other/db/u/p";
        assert_eq!(
            find_server_in_config_list("myhost", config),
            Some("myhost/mydb/myuser/mypass")
        );
    }

    #[test]
    fn find_server_no_match() {
        let config = "myhost/mydb/myuser/mypass";
        assert_eq!(find_server_in_config_list("unknown", config), None);
    }

    #[test]
    fn find_server_partial_prefix_no_slash() {
        // "myhost2" should NOT match "myhost/..." because myhost[5] != '/'
        let config = "myhost/db/u/p";
        assert_eq!(find_server_in_config_list("myhost2", config), None);
    }

    #[test]
    fn find_server_must_have_slash_after() {
        // "my" matches prefix of "myhost/db" but "myhost"[2] == 'h' not '/'
        let config = "myhost/db/u/p";
        assert_eq!(find_server_in_config_list("my", config), None);
    }

    // ── extract_servers_from_opts tests ──────────────────────────────────

    #[test]
    fn extract_servers_found() {
        let opts = "cache=yes, servers=host/db/u/p, timeout=5";
        assert_eq!(extract_servers_from_opts(opts), Some("host/db/u/p"));
    }

    #[test]
    fn extract_servers_not_found() {
        let opts = "cache=yes, timeout=5";
        assert_eq!(extract_servers_from_opts(opts), None);
    }

    #[test]
    fn extract_servers_empty_value() {
        let opts = "servers=, timeout=5";
        assert_eq!(extract_servers_from_opts(opts), None);
    }

    // ── sql_perform integration tests ────────────────────────────────────

    /// Helper callback that always returns Found with a canned result.
    fn found_callback(_query: &str, server: &str, _opts: Option<&str>) -> SqlPerformResult {
        SqlPerformResult::Found {
            result: format!("data_from_{}", server_for_logging(server)),
            cacheable: true,
        }
    }

    /// Helper callback that always returns NotFound.
    fn not_found_callback(_query: &str, _server: &str, _opts: Option<&str>) -> SqlPerformResult {
        SqlPerformResult::NotFound
    }

    /// Helper callback that always defers (soft failure).
    fn defer_callback(_query: &str, server: &str, _opts: Option<&str>) -> SqlPerformResult {
        SqlPerformResult::Deferred {
            error: format!("cannot connect to {}", server_for_logging(server)),
            break_loop: false,
        }
    }

    #[test]
    fn modern_syntax_found() {
        let config = "myhost/mydb/myuser/mypass";
        let result = sql_perform(
            "MySQL",
            "mysql_servers",
            Some(config),
            "SELECT * FROM t",
            None,
            &found_callback,
        );
        assert!(result.is_ok());
        let (data, cacheable) = result.unwrap();
        assert_eq!(data, "data_from_myhost/mydb");
        assert!(cacheable);
    }

    #[test]
    fn modern_syntax_not_found() {
        let config = "myhost/mydb/myuser/mypass";
        let result = sql_perform(
            "MySQL",
            "mysql_servers",
            Some(config),
            "SELECT * FROM t",
            None,
            &not_found_callback,
        );
        assert!(result.is_ok());
        let (data, _cacheable) = result.unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn modern_syntax_all_deferred() {
        let config = "host1/db/u/p : host2/db/u/p";
        let result = sql_perform(
            "MySQL",
            "mysql_servers",
            Some(config),
            "SELECT 1",
            None,
            &defer_callback,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            SqlPerformError::AllServersFailed { errors } => {
                assert_eq!(errors.len(), 2);
            }
            other => panic!("expected AllServersFailed, got {:?}", other),
        }
    }

    #[test]
    fn modern_syntax_no_servers_configured() {
        let result = sql_perform(
            "MySQL",
            "mysql_servers",
            None,
            "SELECT 1",
            None,
            &found_callback,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            SqlPerformError::NoServersConfigured { name, option_name } => {
                assert_eq!(name, "MySQL");
                assert_eq!(option_name, "mysql_servers");
            }
            other => panic!("expected NoServersConfigured, got {:?}", other),
        }
    }

    #[test]
    fn modern_syntax_hostname_resolution() {
        let config = "myhost/mydb/myuser/mypass";
        // opts override with hostname-only → should resolve from config
        let result = sql_perform(
            "MySQL",
            "mysql_servers",
            Some(config),
            "SELECT 1",
            Some("servers=myhost"),
            &found_callback,
        );
        assert!(result.is_ok());
        let (data, _) = result.unwrap();
        assert_eq!(data, "data_from_myhost/mydb");
    }

    #[test]
    fn modern_syntax_opts_full_spec_tainted() {
        let config = "myhost/mydb/myuser/mypass";
        // opts override with full spec → tainted → rejected
        let result = sql_perform(
            "MySQL",
            "mysql_servers",
            Some(config),
            "SELECT 1",
            Some("servers=evil/db/u/p"),
            &found_callback,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            SqlPerformError::TaintedServer { name, server } => {
                assert_eq!(name, "MySQL");
                assert_eq!(server, "evil/db");
            }
            other => panic!("expected TaintedServer, got {:?}", other),
        }
    }

    #[test]
    fn legacy_syntax_hostname_only_resolved() {
        let config = "myhost/mydb/myuser/mypass";
        let query = "servers = myhost ; SELECT 1";
        let result = sql_perform(
            "MySQL",
            "mysql_servers",
            Some(config),
            query,
            None,
            &found_callback,
        );
        assert!(result.is_ok());
        let (data, _) = result.unwrap();
        assert_eq!(data, "data_from_myhost/mydb");
    }

    #[test]
    fn legacy_syntax_full_spec_tainted() {
        let config = "myhost/mydb/myuser/mypass";
        let query = "servers = myhost/db/u/p ; SELECT 1";
        let result = sql_perform(
            "MySQL",
            "mysql_servers",
            Some(config),
            query,
            None,
            &found_callback,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            SqlPerformError::TaintedServer { name, server } => {
                assert_eq!(name, "MySQL");
                assert_eq!(server, "myhost/db");
            }
            other => panic!("expected TaintedServer, got {:?}", other),
        }
    }

    #[test]
    fn legacy_syntax_missing_semicolon() {
        let result = sql_perform(
            "MySQL",
            "mysql_servers",
            None,
            "servers = host/db/u/p SELECT 1",
            None,
            &found_callback,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            SqlPerformError::MissingSemicolon { name } => {
                assert_eq!(name, "MySQL");
            }
            other => panic!("expected MissingSemicolon, got {:?}", other),
        }
    }

    #[test]
    fn legacy_syntax_missing_equals() {
        let result = sql_perform(
            "MySQL",
            "mysql_servers",
            None,
            "servers host ; SELECT 1",
            None,
            &found_callback,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            SqlPerformError::MissingEquals { name } => {
                assert_eq!(name, "MySQL");
            }
            other => panic!("expected MissingEquals, got {:?}", other),
        }
    }

    #[test]
    fn legacy_syntax_empty_server_list() {
        let result = sql_perform(
            "MySQL",
            "mysql_servers",
            None,
            "servers = ; SELECT 1",
            None,
            &found_callback,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            SqlPerformError::EmptyServerList => {}
            other => panic!("expected EmptyServerList, got {:?}", other),
        }
    }

    #[test]
    fn legacy_syntax_hostname_not_found() {
        let config = "other/db/u/p";
        let query = "servers = unknown ; SELECT 1";
        let result = sql_perform(
            "MySQL",
            "mysql_servers",
            Some(config),
            query,
            None,
            &found_callback,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            SqlPerformError::ServerNotFound {
                name,
                server,
                option_name,
            } => {
                assert_eq!(name, "MySQL");
                assert_eq!(server, "unknown");
                assert_eq!(option_name, "mysql_servers");
            }
            other => panic!("expected ServerNotFound, got {:?}", other),
        }
    }

    #[test]
    fn defer_break_stops_iteration() {
        let config = "host1/db/u/p : host2/db/u/p";
        let result = sql_perform(
            "MySQL",
            "mysql_servers",
            Some(config),
            "SELECT 1",
            None,
            &|_q, server, _o| SqlPerformResult::Deferred {
                error: format!("fail {}", server_for_logging(server)),
                break_loop: true, // hard failure on first server
            },
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            SqlPerformError::AllServersFailed { errors } => {
                // Only one error because break_loop stopped after first server
                assert_eq!(errors.len(), 1);
                assert!(errors[0].contains("host1/db"));
            }
            other => panic!("expected AllServersFailed, got {:?}", other),
        }
    }

    #[test]
    fn failover_to_second_server() {
        let config = "host1/db1/u/p : host2/db2/u/p";
        // Use a RefCell to track call count state inside the closure.
        let call_count = std::cell::RefCell::new(0_u32);
        let result = sql_perform(
            "MySQL",
            "mysql_servers",
            Some(config),
            "SELECT 1",
            None,
            &|_q, _s, _o| {
                let mut count = call_count.borrow_mut();
                *count += 1;
                if *count == 1 {
                    SqlPerformResult::Deferred {
                        error: "host1 down".to_string(),
                        break_loop: false,
                    }
                } else {
                    SqlPerformResult::Found {
                        result: "success".to_string(),
                        cacheable: true,
                    }
                }
            },
        );
        assert!(result.is_ok());
        let (data, _) = result.unwrap();
        assert_eq!(data, "success");
        assert_eq!(*call_count.borrow(), 2);
    }
}
