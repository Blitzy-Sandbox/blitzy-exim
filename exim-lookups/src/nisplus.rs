// =============================================================================
// exim-lookups/src/nisplus.rs — NIS+ Lookup Backend (FFI)
// =============================================================================
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Rewrites `src/src/lookups/nisplus.c` (296 lines) as a Rust module that
// delegates all NIS+ operations to the `exim_ffi::nisplus` safe FFI wrapper.
//
// NIS+ (Network Information Service Plus) is a directory service for network
// administration data. The lookup key format is a NIS+ "indexed name":
//
//   [field=value,...],table-name
//   [field=value,...],table-name:result-field-name
//
// The optional `:result-field-name` suffix restricts output to a single column.
// Without it, all columns are concatenated as `name=value` pairs separated by
// spaces, with quoting applied to values that are empty or contain spaces.
//
// C function mapping:
//   nisplus_open()           → NisplusLookup::open()           — no-op (connectionless)
//   nisplus_find()           → NisplusLookup::find()           — query + format
//   (check = NULL)           → NisplusLookup::check()          — always Ok(true)
//   (close = NULL)           → NisplusLookup::close()          — no-op
//   (tidy = NULL)            → NisplusLookup::tidy()           — no-op
//   nisplus_quote()          → NisplusLookup::quote()          — double double-quotes
//   nisplus_version_report() → NisplusLookup::version_report() — version string
//   .type = lookup_querystyle→ NisplusLookup::lookup_type()    — QUERY_STYLE
//   .name = "nisplus"        → NisplusLookup::driver_name()    — "nisplus"
//
// Registration:
//   C: `_lookup_info` + `_lookup_list` + `nisplus_lookup_module_info`
//   Rust: `inventory::submit!(LookupDriverFactory { ... })`
//
// Per AAP §0.7.2: This file contains ZERO `unsafe` code.
//   All NIS+ C FFI calls are confined to `exim-ffi/src/nisplus.rs`.
// Per AAP §0.4.2: Uses `inventory::submit!` for compile-time registration.
// Per AAP §0.7.3: Cargo feature `lookup-nisplus` replaces C `LOOKUP_NISPLUS`.

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;

// NIS+ status codes used for error classification — matches the C constants
// from <rpcsvc/nis.h> (NIS_NOTFOUND = 2, NIS_NOSUCHTABLE = 23).
// These are used to distinguish permanent failures (not-found) from temporary
// failures (network error, permission error, etc.) when `nis_lookup_table()`
// returns an error.
const NIS_NOTFOUND_STATUS: i32 = 2;
const NIS_NOSUCHTABLE_STATUS: i32 = 23;

// =============================================================================
// NIS+ Handle — stateless marker
// =============================================================================

/// Opaque handle for NIS+ lookups.
///
/// NIS+ is a connectionless directory service (each operation is a standalone
/// RPC call), so the handle carries no state. It serves as a type-safe marker
/// for handle validation in `find()` and `close()`.
///
/// Replaces C: `nisplus_open()` returning `(void *)(1)` (line 25 of nisplus.c).
struct NisplusHandle;

// =============================================================================
// NisplusLookup — LookupDriver implementation
// =============================================================================

/// NIS+ directory service lookup driver.
///
/// Performs NIS+ table lookups using indexed names. The query is a NIS+
/// indexed name that specifies the search criteria and table:
///
/// ```text
/// [column=value,...],table_name.org_dir.domain.
/// ```
///
/// An optional result-field suffix restricts output to a single column:
///
/// ```text
/// [column=value,...],table_name.org_dir.domain.:field_name
/// ```
///
/// Without the suffix, all columns are concatenated as space-separated
/// `name=value` pairs, with quoting applied to values that are empty or
/// contain spaces (matching C `nisplus_find()` behavior exactly).
///
/// This driver is query-style: it does not use file-based keys. The `open()`
/// and `close()` methods are no-ops since NIS+ uses connectionless RPC.
///
/// # Registration
///
/// Registered at compile time via `inventory::submit!(LookupDriverFactory)`
/// with the name `"nisplus"` and type `LookupType::QUERY_STYLE`, replacing
/// the C static `_lookup_info` struct and `nisplus_lookup_module_info`.
///
/// # Feature Gate
///
/// This module is compiled only when the `lookup-nisplus` Cargo feature is
/// enabled (replacing C `#ifdef LOOKUP_NISPLUS`). The feature also enables
/// `exim-ffi/ffi-nisplus` for the NIS+ FFI bindings.
#[derive(Debug)]
pub struct NisplusLookup;

impl NisplusLookup {
    /// Create a new NIS+ lookup driver instance.
    pub fn new() -> Self {
        Self
    }
}

impl Default for NisplusLookup {
    fn default() -> Self {
        Self::new()
    }
}

impl LookupDriver for NisplusLookup {
    /// Return the driver name for configuration file matching.
    ///
    /// C: `.name = US"nisplus"` (nisplus.c line 277).
    fn driver_name(&self) -> &str {
        "nisplus"
    }

    /// Return the lookup type — NIS+ is a query-style lookup.
    ///
    /// C: `.type = lookup_querystyle` (nisplus.c line 278).
    fn lookup_type(&self) -> LookupType {
        LookupType::QUERY_STYLE
    }

    /// Open a NIS+ lookup handle — no-op since NIS+ is connectionless.
    ///
    /// Returns a stateless `NisplusHandle` marker to satisfy the trait contract.
    ///
    /// C: `nisplus_open()` returns `(void *)(1)` (nisplus.c line 25).
    fn open(&self, _filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        tracing::debug!("nisplus: open (connectionless — no-op)");
        Ok(Box::new(NisplusHandle))
    }

    /// Check a lookup file for validity — always succeeds for NIS+.
    ///
    /// NIS+ is a query-style lookup with no associated file, so all checks
    /// pass unconditionally.
    ///
    /// C: `.check = NULL` (nisplus.c line 281) — null check function.
    fn check(
        &self,
        _handle: &LookupHandle,
        _filename: Option<&str>,
        _modemask: i32,
        _owners: &[u32],
        _owngroups: &[u32],
    ) -> Result<bool, DriverError> {
        // Query-style lookups have no file to check.
        Ok(true)
    }

    /// Perform a NIS+ table lookup.
    ///
    /// Faithfully translates the 165-line `nisplus_find()` function from
    /// nisplus.c (lines 46–216), following the same logic flow:
    ///
    /// 1. Parse the query for an optional `:result-field-name` suffix
    /// 2. Extract the table name after the last `,` in the query
    /// 3. Look up the table via `nis_lookup_table()` to get column metadata
    /// 4. Query entries via `nis_query_entries()` with the indexed name
    /// 5. Validate exactly one entry was returned
    /// 6. Format the result:
    ///    - With field name: return just that column's value
    ///    - Without field name: concatenate all columns as `name=value ` pairs
    ///
    /// Error mapping matches C behavior:
    /// - C `DEFER` → `LookupResult::Deferred` or `DriverError::TempFail`
    /// - C `FAIL`  → `LookupResult::NotFound`
    /// - C `OK`    → `LookupResult::Found`
    fn find(
        &self,
        handle: &LookupHandle,
        _filename: Option<&str>,
        key_or_query: &str,
        _options: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        // Validate handle type.
        let _handle = handle
            .downcast_ref::<NisplusHandle>()
            .ok_or_else(|| DriverError::ExecutionFailed("nisplus: invalid handle type".into()))?;

        if key_or_query.is_empty() {
            return Err(DriverError::ExecutionFailed(
                "nisplus: empty query (indexed name required)".into(),
            ));
        }

        // Step 1: Parse the query for an optional result-field-name suffix.
        // C: search backwards for ':' (nisplus.c lines 66-76).
        let (query, field_name) = parse_query_field(key_or_query);

        // Step 2: Extract the table name after the last ','.
        // C: search backwards for ',' (nisplus.c lines 81-87).
        // If no comma found, the query is malformed → DEFER.
        let table_name = extract_table_name(query)?;

        tracing::debug!(
            query = %query,
            table = %table_name,
            field = ?field_name,
            "nisplus: performing table lookup"
        );

        // Step 3: Look up the NIS+ table to get column metadata.
        // C: nis_lookup(table_name, EXPAND_NAME | NO_CACHE) (nisplus.c line 93).
        let table_info = match exim_ffi::nisplus::nis_lookup_table(table_name) {
            Ok(info) => {
                tracing::debug!(
                    table = %table_name,
                    columns = ?info.column_names,
                    "nisplus: table metadata retrieved"
                );
                info
            }
            Err(e) => {
                // C: if status != NIS_NOTFOUND && status != NIS_NOSUCHTABLE
                //        error_error = DEFER;   (nisplus.c line 98-99)
                let error_msg = format!(
                    "NIS+ error accessing {} table: {}",
                    table_name,
                    exim_ffi::nisplus::nis_error_string(e.status)
                );

                if e.status == NIS_NOTFOUND_STATUS || e.status == NIS_NOSUCHTABLE_STATUS {
                    // Permanent failure — table does not exist.
                    tracing::warn!(
                        table = %table_name,
                        status = e.status,
                        "nisplus: table not found"
                    );
                    return Ok(LookupResult::NotFound);
                }

                // Temporary failure — network/permission/other transient error.
                tracing::warn!(
                    table = %table_name,
                    status = e.status,
                    error = %e,
                    "nisplus: table lookup deferred"
                );
                return Ok(LookupResult::Deferred { message: error_msg });
            }
        };

        // Step 4: Query entries in the table.
        // C: nis_list(query, EXPAND_NAME, NULL, NULL) (nisplus.c line 113).
        let entries = match exim_ffi::nisplus::nis_query_entries(query) {
            Ok(exim_ffi::nisplus::NisplusQueryResult::Found(entries)) => entries,
            Ok(exim_ffi::nisplus::NisplusQueryResult::NotFound) => {
                // C: nre->status != NIS_SUCCESS → errmsg set, return FAIL
                tracing::debug!(query = %query, "nisplus: no matching entries");
                return Ok(LookupResult::NotFound);
            }
            Ok(exim_ffi::nisplus::NisplusQueryResult::NoSuchTable) => {
                // C: treated as FAIL (not DEFER) for entry queries.
                tracing::warn!(
                    query = %query,
                    "nisplus: table not found during entry query"
                );
                return Ok(LookupResult::NotFound);
            }
            Err(e) => {
                // C: entry query error → FAIL (error_error stays FAIL).
                // Note: unlike table lookup, entry query errors are NOT DEFER.
                let error_msg = format!(
                    "NIS+ error accessing entry {}: {}",
                    query,
                    exim_ffi::nisplus::nis_error_string(e.status)
                );
                tracing::warn!(
                    query = %query,
                    status = e.status,
                    "nisplus: entry query failed: {}",
                    error_msg
                );
                return Ok(LookupResult::NotFound);
            }
        };

        // Step 5: Validate entry count — C expects exactly 1 object.
        // C: objects_len > 1 → "returned more than one object" (line 120-124)
        // C: objects_len < 1 → "returned no data" (line 126-129)
        if entries.len() > 1 {
            tracing::warn!(
                query = %query,
                count = entries.len(),
                "nisplus: returned more than one object"
            );
            return Ok(LookupResult::NotFound);
        }
        if entries.is_empty() {
            tracing::warn!(query = %query, "nisplus: returned no data");
            return Ok(LookupResult::NotFound);
        }

        let entry = &entries[0];

        // Step 6: Format the result based on table column metadata.
        // C: nisplus.c lines 142-201 — column iteration with field matching.
        match format_entry_result(&table_info, entry, field_name) {
            FormatResult::Found(value) => {
                tracing::debug!(query = %query, "nisplus: lookup succeeded");
                Ok(LookupResult::Found {
                    value,
                    cache_ttl: None,
                })
            }
            FormatResult::FieldNotFound(fname) => {
                // C: "NIS+ field %s not found for %s" → return FAIL
                tracing::warn!(
                    query = %query,
                    field = %fname,
                    "nisplus: field not found in entry"
                );
                Ok(LookupResult::NotFound)
            }
            FormatResult::Empty => {
                // All columns were empty — should not normally happen.
                tracing::debug!(query = %query, "nisplus: all columns empty");
                Ok(LookupResult::NotFound)
            }
        }
    }

    /// Close a NIS+ handle — no-op since NIS+ is connectionless.
    ///
    /// C: `.close = NULL` (nisplus.c line 282).
    fn close(&self, _handle: LookupHandle) {
        tracing::debug!("nisplus: close (no-op)");
    }

    /// Tidy up NIS+ resources — no-op since NIS+ is connectionless.
    ///
    /// C: `.tidy = NULL` (nisplus.c line 283).
    fn tidy(&self) {
        tracing::debug!("nisplus: tidy (no-op)");
    }

    /// Quote a string for safe use in NIS+ queries.
    ///
    /// The only quoting needed for NIS+ is to double every double-quote
    /// character (`"` → `""`). No options are recognized; if `additional`
    /// is provided, returns `None` to signal a bad option (matching C
    /// behavior where `opt != NULL` returns NULL).
    ///
    /// C: `nisplus_quote()` (nisplus.c lines 235–255).
    fn quote(&self, value: &str, additional: Option<&str>) -> Option<String> {
        // C: if (opt) return NULL;  (no options recognized)
        if additional.is_some() {
            return None;
        }

        // Double every double-quote character.
        // C: while (*s) { *t++ = *s; if (*s++ == '"') *t++ = '"'; }
        let quote_count = value.bytes().filter(|&b| b == b'"').count();
        let mut result = String::with_capacity(value.len() + quote_count);
        for ch in value.chars() {
            result.push(ch);
            if ch == '"' {
                result.push('"');
            }
        }
        Some(result)
    }

    /// Version report for `-bV` output.
    ///
    /// C: `nisplus_version_report()` (nisplus.c lines 266–273).
    /// The C version only outputs under `#ifdef DYNLOOKUP`.
    fn version_report(&self) -> Option<String> {
        Some("Library version: NIS+: Exim version (Rust rewrite)".to_string())
    }
}

// =============================================================================
// Compile-Time Registration
// =============================================================================
//
// Replaces C: _lookup_info + _lookup_list + nisplus_lookup_module_info
// (nisplus.c lines 276-293).
//
// Per AAP §0.7.3: inventory::submit! replaces preprocessor-driven driver
// tables. The registry collects all submitted LookupDriverFactory entries
// at link time, enabling DriverRegistry::find_lookup("nisplus") at runtime.

inventory::submit! {
    LookupDriverFactory {
        name: "nisplus",
        create: || Box::new(NisplusLookup::new()),
        lookup_type: LookupType::QUERY_STYLE,
        avail_string: Some("nisplus (FFI to libnsl)"),
    }
}

// =============================================================================
// Internal Helper Functions
// =============================================================================

/// Result of formatting a NIS+ entry for output.
///
/// Distinguishes between success, field-not-found, and empty-result cases
/// to provide appropriate error messages matching the C implementation.
enum FormatResult {
    /// Successfully formatted result string.
    Found(String),
    /// A specific field name was requested but not found in the entry.
    /// Contains the field name for error reporting.
    FieldNotFound(String),
    /// All columns produced empty output (edge case).
    Empty,
}

/// Parse a NIS+ query for an optional result-field-name suffix.
///
/// NIS+ queries have the format:
///   `[field=value,...],table-name`           — all columns
///   `[field=value,...],table-name:field-name` — single column
///
/// This function searches backwards from the end of the query for a `:`
/// character. If found, the part after `:` is the field name and the part
/// before `:` is the query to pass to `nis_list()`.
///
/// C: nisplus.c lines 63-76 — backwards search for colon.
///
/// # Returns
///
/// A tuple of `(query_without_field, optional_field_name)`.
fn parse_query_field(query: &str) -> (&str, Option<&str>) {
    // C: while (p > query && p[-1] != ':') p--;
    //    if (p > query) { field_name = p; query = query up to colon; }
    if let Some(colon_pos) = query.rfind(':') {
        let field = &query[colon_pos + 1..];
        let base_query = &query[..colon_pos];
        (base_query, Some(field))
    } else {
        (query, None)
    }
}

/// Extract the NIS+ table name from the query.
///
/// The table name is the portion after the last `,` in the query. If no
/// comma is found, the query is malformed and the C code returns DEFER.
///
/// C: nisplus.c lines 78-87 — backwards search for comma.
///
/// # Errors
///
/// Returns `DriverError::TempFail` if no comma is found (matching C DEFER).
fn extract_table_name(query: &str) -> Result<&str, DriverError> {
    // C: while (p > query && p[-1] != ',') p--;
    //    if (p <= query) { *errmsg = "NIS+ query malformed"; error_error = DEFER; }
    if let Some(comma_pos) = query.rfind(',') {
        Ok(&query[comma_pos + 1..])
    } else {
        Err(DriverError::TempFail("NIS+ query malformed".into()))
    }
}

/// Trim trailing whitespace and null bytes from a column value.
///
/// NIS+ column values may have trailing null bytes and whitespace that
/// should be stripped before presentation.
///
/// C: nisplus.c lines 156-157:
///   `while (len > 0 && (value[len-1] == 0 || isspace(value[len-1]))) len--;`
fn trim_column_value(raw: &[u8]) -> &[u8] {
    let mut len = raw.len();
    while len > 0 && (raw[len - 1] == 0 || raw[len - 1].is_ascii_whitespace()) {
        len -= 1;
    }
    &raw[..len]
}

/// Format a NIS+ entry result based on table column metadata.
///
/// When `field_name` is `Some(name)`: searches for the named column and
/// returns just its trimmed value (C: nisplus.c lines 187-191).
///
/// When `field_name` is `None`: concatenates all columns as space-separated
/// `name=value` pairs. Values that are empty or contain spaces are quoted
/// with backslash-escaped `"` and `\` characters (C: nisplus.c lines 159-183).
///
/// # Parameters
///
/// * `table_info` — Column metadata from `nis_lookup_table()`.
/// * `entry` — The single entry from `nis_query_entries()`.
/// * `field_name` — Optional specific field to extract.
fn format_entry_result(
    table_info: &exim_ffi::nisplus::NisplusTableInfo,
    entry: &exim_ffi::nisplus::NisplusEntry,
    field_name: Option<&str>,
) -> FormatResult {
    // Iterate over columns, using the minimum of table column count and
    // entry column count (they should match, but defensive programming).
    let num_cols = entry.columns.len().min(table_info.column_names.len());

    if let Some(target_field) = field_name {
        // Field-specific extraction: find the column matching the requested
        // field name and return just its value.
        // C: nisplus.c lines 187-191 — Ustrcmp(field_name, tc->tc_name).
        for i in 0..num_cols {
            if table_info.column_names[i] == target_field {
                let trimmed = trim_column_value(&entry.columns[i].value);
                let value = String::from_utf8_lossy(trimmed).into_owned();
                return FormatResult::Found(value);
            }
        }
        // C: "NIS+ field %s not found for %s" → return FAIL (nisplus.c lines 197-199).
        FormatResult::FieldNotFound(target_field.to_string())
    } else {
        // All-column concatenation: build "name1=value1 name2=value2 ..." string.
        // C: nisplus.c lines 159-183.
        let mut output = String::new();

        for i in 0..num_cols {
            let col_name = &table_info.column_names[i];
            let trimmed = trim_column_value(&entry.columns[i].value);
            let value_str = String::from_utf8_lossy(trimmed);

            // Append column name and equals sign.
            // C: string_cat(yield, tc->tc_name); string_catn(yield, "=", 1);
            output.push_str(col_name);
            output.push('=');

            // Quote the value if it is empty or contains spaces.
            // C: if (value[0] == 0 || Ustrchr(value, ' ') != NULL)
            if value_str.is_empty() || value_str.contains(' ') {
                // Open quote.
                output.push('"');
                // Escape double-quotes and backslashes within the value.
                // C: if (value[j] == '"' || value[j] == '\\')
                //        string_catn(yield, "\\", 1);
                for ch in value_str.chars() {
                    if ch == '"' || ch == '\\' {
                        output.push('\\');
                    }
                    output.push(ch);
                }
                // Close quote.
                output.push('"');
            } else {
                output.push_str(&value_str);
            }

            // Trailing space after each column.
            // C: string_catn(yield, " ", 1);
            output.push(' ');
        }

        if output.is_empty() {
            FormatResult::Empty
        } else {
            FormatResult::Found(output)
        }
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Driver metadata tests
    // =========================================================================

    #[test]
    fn test_driver_name() {
        let driver = NisplusLookup::new();
        assert_eq!(driver.driver_name(), "nisplus");
    }

    #[test]
    fn test_lookup_type_is_query_style() {
        let driver = NisplusLookup::new();
        let lt = driver.lookup_type();
        assert!(lt.is_query_style());
        assert!(!lt.is_single_key());
        assert_eq!(lt, LookupType::QUERY_STYLE);
    }

    #[test]
    fn test_version_report_contains_nisplus() {
        let driver = NisplusLookup::new();
        let report = driver.version_report();
        assert!(report.is_some());
        let text = report.unwrap();
        assert!(text.contains("NIS+"));
    }

    // =========================================================================
    // Handle tests
    // =========================================================================

    #[test]
    fn test_open_returns_ok() {
        let driver = NisplusLookup::new();
        let result = driver.open(None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_always_true() {
        let driver = NisplusLookup::new();
        let handle = driver.open(None).unwrap();
        let result = driver.check(&handle, None, 0, &[], &[]);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_close_succeeds() {
        let driver = NisplusLookup::new();
        let handle = driver.open(None).unwrap();
        // close() takes ownership — just verify it doesn't panic.
        driver.close(handle);
    }

    #[test]
    fn test_tidy_succeeds() {
        let driver = NisplusLookup::new();
        // tidy() is a no-op — verify it doesn't panic.
        driver.tidy();
    }

    // =========================================================================
    // find() error handling tests
    // =========================================================================

    #[test]
    fn test_find_empty_query_fails() {
        let driver = NisplusLookup::new();
        let handle = driver.open(None).unwrap();
        let result = driver.find(&handle, None, "", None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DriverError::ExecutionFailed(_)));
    }

    #[test]
    fn test_find_invalid_handle_type() {
        let driver = NisplusLookup::new();
        // Create a handle of wrong type.
        let bad_handle: LookupHandle = Box::new(42u32);
        let result = driver.find(&bad_handle, None, "[name=test],table", None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DriverError::ExecutionFailed(_)));
    }

    // =========================================================================
    // Query parsing tests
    // =========================================================================

    #[test]
    fn test_parse_query_field_no_colon() {
        let (query, field) = parse_query_field("[name=test],table.org_dir.example.com.");
        assert_eq!(query, "[name=test],table.org_dir.example.com.");
        assert!(field.is_none());
    }

    #[test]
    fn test_parse_query_field_with_colon() {
        let (query, field) = parse_query_field("[name=test],table.org_dir.example.com.:username");
        assert_eq!(query, "[name=test],table.org_dir.example.com.");
        assert_eq!(field, Some("username"));
    }

    #[test]
    fn test_parse_query_field_empty_field() {
        let (query, field) = parse_query_field("[name=test],table:");
        assert_eq!(query, "[name=test],table");
        assert_eq!(field, Some(""));
    }

    #[test]
    fn test_parse_query_field_colon_at_start() {
        // Edge case: colon at position 0.
        let (query, field) = parse_query_field(":field");
        assert_eq!(query, "");
        assert_eq!(field, Some("field"));
    }

    // =========================================================================
    // Table name extraction tests
    // =========================================================================

    #[test]
    fn test_extract_table_name_normal() {
        let result = extract_table_name("[name=test],table.org_dir.example.com.");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "table.org_dir.example.com.");
    }

    #[test]
    fn test_extract_table_name_no_comma() {
        let result = extract_table_name("no_comma_query");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DriverError::TempFail(_)));
    }

    #[test]
    fn test_extract_table_name_trailing_comma() {
        // Comma at end → empty table name (will fail at FFI level).
        let result = extract_table_name("[name=test],");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }

    // =========================================================================
    // Column value trimming tests
    // =========================================================================

    #[test]
    fn test_trim_column_value_normal() {
        let trimmed = trim_column_value(b"hello");
        assert_eq!(trimmed, b"hello");
    }

    #[test]
    fn test_trim_column_value_trailing_null() {
        let trimmed = trim_column_value(b"hello\0\0");
        assert_eq!(trimmed, b"hello");
    }

    #[test]
    fn test_trim_column_value_trailing_whitespace() {
        let trimmed = trim_column_value(b"hello  \t\n");
        assert_eq!(trimmed, b"hello");
    }

    #[test]
    fn test_trim_column_value_trailing_mixed() {
        let trimmed = trim_column_value(b"hello \0 \0");
        assert_eq!(trimmed, b"hello");
    }

    #[test]
    fn test_trim_column_value_empty() {
        let trimmed = trim_column_value(b"");
        assert_eq!(trimmed, b"");
    }

    #[test]
    fn test_trim_column_value_all_nulls() {
        let trimmed = trim_column_value(b"\0\0\0");
        assert_eq!(trimmed, b"");
    }

    // =========================================================================
    // Quote tests
    // =========================================================================

    #[test]
    fn test_quote_no_options_no_quotes() {
        let driver = NisplusLookup::new();
        let result = driver.quote("hello world", None);
        assert_eq!(result, Some("hello world".to_string()));
    }

    #[test]
    fn test_quote_doubles_double_quotes() {
        let driver = NisplusLookup::new();
        let result = driver.quote(r#"say "hello""#, None);
        assert_eq!(result, Some(r#"say ""hello"""#.to_string()));
    }

    #[test]
    fn test_quote_with_options_returns_none() {
        let driver = NisplusLookup::new();
        let result = driver.quote("hello", Some("extra"));
        assert!(result.is_none());
    }

    #[test]
    fn test_quote_empty_string() {
        let driver = NisplusLookup::new();
        let result = driver.quote("", None);
        assert_eq!(result, Some(String::new()));
    }

    #[test]
    fn test_quote_all_double_quotes() {
        let driver = NisplusLookup::new();
        // Input: two double-quote chars → output: four double-quote chars.
        let input = "\"\""; // 2 double-quotes
        let result = driver.quote(input, None);
        let expected = "\"\"\"\""; // 4 double-quotes (each doubled)
        assert_eq!(result, Some(expected.to_string()));
    }

    // =========================================================================
    // Result formatting tests
    // =========================================================================

    #[test]
    fn test_format_entry_all_columns() {
        let table_info = exim_ffi::nisplus::NisplusTableInfo {
            column_names: vec!["name".into(), "uid".into(), "shell".into()],
        };
        let entry = exim_ffi::nisplus::NisplusEntry {
            columns: vec![
                exim_ffi::nisplus::NisplusColumn {
                    value: b"testuser".to_vec(),
                    len: 8,
                },
                exim_ffi::nisplus::NisplusColumn {
                    value: b"1001".to_vec(),
                    len: 4,
                },
                exim_ffi::nisplus::NisplusColumn {
                    value: b"/bin/bash".to_vec(),
                    len: 9,
                },
            ],
        };

        let result = format_entry_result(&table_info, &entry, None);
        match result {
            FormatResult::Found(s) => {
                assert_eq!(s, "name=testuser uid=1001 shell=/bin/bash ");
            }
            _ => panic!("expected FormatResult::Found"),
        }
    }

    #[test]
    fn test_format_entry_specific_field() {
        let table_info = exim_ffi::nisplus::NisplusTableInfo {
            column_names: vec!["name".into(), "uid".into(), "shell".into()],
        };
        let entry = exim_ffi::nisplus::NisplusEntry {
            columns: vec![
                exim_ffi::nisplus::NisplusColumn {
                    value: b"testuser".to_vec(),
                    len: 8,
                },
                exim_ffi::nisplus::NisplusColumn {
                    value: b"1001".to_vec(),
                    len: 4,
                },
                exim_ffi::nisplus::NisplusColumn {
                    value: b"/bin/bash".to_vec(),
                    len: 9,
                },
            ],
        };

        let result = format_entry_result(&table_info, &entry, Some("uid"));
        match result {
            FormatResult::Found(s) => assert_eq!(s, "1001"),
            _ => panic!("expected FormatResult::Found"),
        }
    }

    #[test]
    fn test_format_entry_field_not_found() {
        let table_info = exim_ffi::nisplus::NisplusTableInfo {
            column_names: vec!["name".into()],
        };
        let entry = exim_ffi::nisplus::NisplusEntry {
            columns: vec![exim_ffi::nisplus::NisplusColumn {
                value: b"test".to_vec(),
                len: 4,
            }],
        };

        let result = format_entry_result(&table_info, &entry, Some("nonexistent"));
        match result {
            FormatResult::FieldNotFound(f) => assert_eq!(f, "nonexistent"),
            _ => panic!("expected FormatResult::FieldNotFound"),
        }
    }

    #[test]
    fn test_format_entry_quoted_value_with_spaces() {
        let table_info = exim_ffi::nisplus::NisplusTableInfo {
            column_names: vec!["name".into()],
        };
        let entry = exim_ffi::nisplus::NisplusEntry {
            columns: vec![exim_ffi::nisplus::NisplusColumn {
                value: b"John Doe".to_vec(),
                len: 8,
            }],
        };

        let result = format_entry_result(&table_info, &entry, None);
        match result {
            FormatResult::Found(s) => {
                // Value with spaces gets quoted.
                assert_eq!(s, r#"name="John Doe" "#);
            }
            _ => panic!("expected FormatResult::Found"),
        }
    }

    #[test]
    fn test_format_entry_quoted_empty_value() {
        let table_info = exim_ffi::nisplus::NisplusTableInfo {
            column_names: vec!["name".into()],
        };
        let entry = exim_ffi::nisplus::NisplusEntry {
            columns: vec![exim_ffi::nisplus::NisplusColumn {
                value: Vec::new(),
                len: 0,
            }],
        };

        let result = format_entry_result(&table_info, &entry, None);
        match result {
            FormatResult::Found(s) => {
                // Empty value gets quoted as "".
                assert_eq!(s, r#"name="" "#);
            }
            _ => panic!("expected FormatResult::Found"),
        }
    }

    #[test]
    fn test_format_entry_escaped_quotes_in_value() {
        let table_info = exim_ffi::nisplus::NisplusTableInfo {
            column_names: vec!["desc".into()],
        };
        let entry = exim_ffi::nisplus::NisplusEntry {
            columns: vec![exim_ffi::nisplus::NisplusColumn {
                value: b"say \"hi\" now".to_vec(),
                len: 12,
            }],
        };

        let result = format_entry_result(&table_info, &entry, None);
        match result {
            FormatResult::Found(s) => {
                // Value with spaces AND quotes: spaces trigger quoting,
                // internal quotes and backslashes get escaped.
                assert_eq!(s, r#"desc="say \"hi\" now" "#);
            }
            _ => panic!("expected FormatResult::Found"),
        }
    }

    #[test]
    fn test_format_entry_trailing_null_trimmed() {
        let table_info = exim_ffi::nisplus::NisplusTableInfo {
            column_names: vec!["val".into()],
        };
        let entry = exim_ffi::nisplus::NisplusEntry {
            columns: vec![exim_ffi::nisplus::NisplusColumn {
                value: b"hello\0\0".to_vec(),
                len: 7,
            }],
        };

        let result = format_entry_result(&table_info, &entry, None);
        match result {
            FormatResult::Found(s) => {
                assert_eq!(s, "val=hello ");
            }
            _ => panic!("expected FormatResult::Found"),
        }
    }

    #[test]
    fn test_format_entry_empty_no_columns() {
        let table_info = exim_ffi::nisplus::NisplusTableInfo {
            column_names: Vec::new(),
        };
        let entry = exim_ffi::nisplus::NisplusEntry {
            columns: Vec::new(),
        };

        let result = format_entry_result(&table_info, &entry, None);
        assert!(matches!(result, FormatResult::Empty));
    }
}
