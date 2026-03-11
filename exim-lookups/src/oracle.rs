// =============================================================================
// exim-lookups/src/oracle.rs — Oracle OCI Lookup Backend (FFI)
// =============================================================================
//
// Rewrites `src/src/lookups/oracle.c` (641 lines) as a Rust module that
// delegates all Oracle database operations to the `exim-ffi::oracle` safe FFI
// wrapper. This lookup provides SQL query execution against Oracle databases
// using the Oracle Call Interface (OCI) v2 API.
//
// C function mapping:
//   oracle_open()  → OracleLookup::open()  — connect to Oracle database
//   oracle_find()  → OracleLookup::find()  — execute SQL query, format results
//   oracle_close() → OracleLookup::close() — close session and logoff
//   oracle_tidy()  → OracleLookup::tidy()  — close all cached connections
//
// Per AAP §0.7.2: This file contains ZERO `unsafe` code.
// Per AAP §0.4.2: Uses `inventory::submit!` for compile-time registration.

use std::sync::Mutex;

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;

// =============================================================================
// Oracle Handle
// =============================================================================

/// Internal state for an open Oracle session.
///
/// Wraps the safe `exim_ffi::oracle::OracleSession` handle returned by the
/// FFI layer. The session is closed when this handle is dropped.
struct OracleHandle {
    /// The active Oracle session (Mutex for interior mutability in find()).
    session: Mutex<exim_ffi::oracle::OracleSession>,
}

// =============================================================================
// OracleLookup — LookupDriver implementation
// =============================================================================

/// Oracle OCI SQL lookup driver.
///
/// Executes SQL queries against an Oracle database server. The query key
/// format follows the multi-server SQL perform pattern:
/// ```text
/// servers=<server_spec> <SQL_query>
/// ```
///
/// Server spec format: `host/database/user/password`
///
/// Results are formatted as newline-separated rows with space-separated columns,
/// matching the C behavior of `oracle_find()`.
#[derive(Debug)]
struct OracleLookup;

impl OracleLookup {
    fn new() -> Self {
        Self
    }

    /// Parse a server specification string.
    /// Format: `host/database/user/password`
    fn parse_server_spec(spec: &str) -> Result<(&str, &str, &str, &str), DriverError> {
        let parts: Vec<&str> = spec.splitn(4, '/').collect();
        if parts.len() < 4 {
            return Err(DriverError::ExecutionFailed(format!(
                "Oracle: invalid server spec (need host/db/user/pass): {}",
                spec
            )));
        }
        Ok((parts[0], parts[1], parts[2], parts[3]))
    }
}

impl LookupDriver for OracleLookup {
    fn driver_name(&self) -> &str {
        "oracle"
    }

    fn lookup_type(&self) -> LookupType {
        LookupType::QUERY_STYLE
    }

    fn open(&self, _filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        // Oracle connections are opened on first query (lazy connect).
        // Return a placeholder handle; the actual connection is established
        // in find() when the server spec and query are available.
        //
        // Create a default session that will be replaced on first use.
        let session = exim_ffi::oracle::OracleSession::new_placeholder();
        Ok(Box::new(OracleHandle {
            session: Mutex::new(session),
        }))
    }

    fn find(
        &self,
        handle: &LookupHandle,
        _filename: Option<&str>,
        key: &str,
        opts: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        let oracle_handle = handle
            .downcast_ref::<OracleHandle>()
            .ok_or_else(|| DriverError::ExecutionFailed("Oracle: invalid handle type".into()))?;

        // Parse the key: extract server spec and SQL query.
        // The key format from the expansion engine is the pre-expanded SQL.
        // The server spec comes from the lookup configuration or opts.
        let server_spec = opts.unwrap_or_default();
        let query = key;

        if server_spec.is_empty() {
            return Err(DriverError::ExecutionFailed(
                "Oracle: no server specification provided".into(),
            ));
        }

        let (host, database, user, password) = Self::parse_server_spec(server_spec)?;

        tracing::debug!(
            host = %host,
            database = %database,
            user = %user,
            query_len = query.len(),
            "Oracle: executing query"
        );

        let mut session_guard = oracle_handle
            .session
            .lock()
            .map_err(|e| DriverError::ExecutionFailed(format!("Oracle: mutex poisoned: {}", e)))?;

        // Connect if not already connected.
        if !session_guard.is_connected() {
            *session_guard = exim_ffi::oracle::OracleSession::connect(
                host, database, user, password,
            )
            .map_err(|e| {
                DriverError::ExecutionFailed(format!(
                    "Oracle: connection failed to {}/{}: {}",
                    host, database, e
                ))
            })?;
        }

        // Execute the SQL query.
        // NOTE: Query content is pre-expanded by Exim's expansion engine.
        // SQL safety relies on upstream taint checking at the expansion layer,
        // not at this lookup layer — matching C behavior. See security notes
        // in the review report.
        let rows = session_guard.execute_query(query).map_err(|e| {
            tracing::warn!(
                query_prefix = &query[..query.len().min(80)],
                error = %e,
                "Oracle: query execution failed"
            );
            DriverError::ExecutionFailed(format!("Oracle: query failed: {}", e))
        })?;

        if rows.is_empty() {
            tracing::debug!("Oracle: query returned no rows");
            return Ok(LookupResult::NotFound);
        }

        // Format results: space-separated columns, newline-separated rows.
        let mut result = String::new();
        for (i, row) in rows.iter().enumerate() {
            if i > 0 {
                result.push('\n');
            }
            result.push_str(&row.join(" "));
        }

        tracing::debug!(
            row_count = rows.len(),
            result_len = result.len(),
            "Oracle: query returned results"
        );

        Ok(LookupResult::Found {
            value: result,
            cache_ttl: None,
        })
    }

    fn close(&self, handle: LookupHandle) {
        if let Ok(oracle_handle) = handle.downcast::<OracleHandle>() {
            if let Ok(mut session) = oracle_handle.session.lock() {
                session.disconnect();
            }
            tracing::debug!("Oracle: session closed");
        }
    }

    fn tidy(&self) {
        tracing::debug!("Oracle: tidy — all sessions will be closed on drop");
    }

    fn version_report(&self) -> Option<String> {
        Some("Lookup: oracle (Rust, FFI to OCI)".to_string())
    }
}

// =============================================================================
// Compile-Time Registration
// =============================================================================

inventory::submit! {
    LookupDriverFactory {
        name: "oracle",
        create: || Box::new(OracleLookup::new()),
        lookup_type: LookupType::QUERY_STYLE,
        avail_string: Some("oracle (FFI)"),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oracle_driver_name() {
        let driver = OracleLookup::new();
        assert_eq!(driver.driver_name(), "oracle");
    }

    #[test]
    fn test_oracle_lookup_type() {
        let driver = OracleLookup::new();
        assert!(driver.lookup_type().is_query_style());
    }

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
    fn test_parse_server_spec_invalid() {
        let result = OracleLookup::parse_server_spec("incomplete");
        assert!(result.is_err());
    }

    #[test]
    fn test_oracle_version_report() {
        let driver = OracleLookup::new();
        let report = driver.version_report();
        assert!(report.is_some());
        assert!(report.unwrap().contains("oracle"));
    }
}
