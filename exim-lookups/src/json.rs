// =============================================================================
// exim-lookups/src/json.rs — JSON Traversal Lookup via serde_json
// =============================================================================
//
// Replaces `src/src/lookups/json.c` (~188 lines) — Jansson-backed JSON file
// lookup rewritten with `serde_json`. Provides file-based JSON traversal using
// dot-separated path keys, with type-to-string conversion matching the original
// C Jansson behavior exactly.
//
// C source: src/src/lookups/json.c
// Registration: inventory::submit! replaces C json_lookup_info + module info
// Feature gate: compiled only when "lookup-json" feature is enabled
//
// # Path Traversal
//
// The lookup key is a dot-separated path where each component is either:
//   - An object key (if it contains any non-digit character)
//   - An array index (if it consists entirely of ASCII digits)
//
// This matches the C implementation's use of `json_object_get()` for
// non-numeric keys and `json_array_get()` for all-digit keys.
//
// # Type Conversion (matches C Jansson behavior)
//
//   | JSON type    | Rust output             | C equivalent                    |
//   |-------------|-------------------------|---------------------------------|
//   | null        | "" (empty string)        | *result = NULL → expanded ""    |
//   | true        | "true"                   | JSON_TRUE → US"true"            |
//   | false       | "false"                  | JSON_FALSE → US"false"          |
//   | integer     | decimal string           | JSON_INTEGER_FORMAT ("%lld")    |
//   | real/float  | 6 decimal places         | "%f" (C default precision)      |
//   | string      | string content           | json_string_value()             |
//   | object      | JSON serialization       | json_dumps(j, 0)                |
//   | array       | JSON serialization       | json_dumps(j, 0)                |
//
// # Behavioral Parity Notes
//
// - The JSON file is re-parsed on every `find()` call, matching the C
//   implementation which calls `rewind(f)` + `json_loadf()` each time.
// - Numeric keys attempt array index access ONLY (not object key fallback),
//   matching C `json_array_get()` behavior.
// - Non-numeric keys attempt object key access ONLY, matching C
//   `json_object_get()` behavior.
//
// Per AAP §0.7.2: This file contains ZERO `unsafe` code.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;

use crate::helpers::check_file::{check_file, CheckFileTarget, ExpectedFileType};

// =============================================================================
// JSON Lookup Handle — Internal State
// =============================================================================

/// Internal state for an open JSON lookup handle.
///
/// Stores the filesystem path to the JSON file so it can be re-opened and
/// re-parsed on each `find()` call. This replaces the C `FILE *` handle that
/// was kept open and rewound via `rewind()` before each `json_loadf()`.
///
/// The re-open-on-find approach is chosen because:
/// 1. It avoids keeping file descriptors open between lookups.
/// 2. It preserves behavioral parity — the file is re-read each time.
/// 3. It simplifies the Send + Sync requirements for the handle.
#[derive(Debug)]
struct JsonHandle {
    /// Absolute path to the JSON file, stored from the `open()` call.
    filepath: String,
}

// =============================================================================
// JsonLookup — Public Driver Struct
// =============================================================================

/// JSON traversal lookup driver.
///
/// Implements the [`LookupDriver`] trait for JSON file lookups using
/// [`serde_json`]. Replaces the C `json_lookup_info` struct and associated
/// functions (`json_open`, `json_check`, `json_find`, `json_close`,
/// `json_version_report`) from `src/src/lookups/json.c`.
///
/// # Usage
///
/// The driver is registered at compile time via `inventory::submit!` and
/// discovered by the Exim driver registry. Configuration files reference it
/// as:
///
/// ```text
/// ${lookup json {/path/to/file.json} {key.subkey.0.field}}
/// ```
///
/// # Thread Safety
///
/// `JsonLookup` is stateless (`Send + Sync`). All per-lookup state is stored
/// in [`JsonHandle`] instances returned by `open()`.
#[derive(Debug)]
pub struct JsonLookup;

impl JsonLookup {
    /// Create a new `JsonLookup` driver instance.
    ///
    /// The driver is stateless — this constructor simply returns a new unit
    /// struct. All per-lookup state lives in the [`LookupHandle`] returned
    /// by `open()`.
    pub fn new() -> Self {
        Self
    }
}

impl Default for JsonLookup {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// LookupDriver Trait Implementation
// =============================================================================

impl LookupDriver for JsonLookup {
    /// Open a JSON file for lookup operations.
    ///
    /// Replaces C `json_open()` (lines 44–54 of json.c). The C version opens
    /// the file with `Ufopen()` and returns the `FILE *`. The Rust version
    /// verifies the file is accessible, then stores the path in a
    /// [`JsonHandle`] for re-opening on each `find()` call.
    ///
    /// The C version also set custom Jansson allocators to route memory through
    /// Exim's `POOL_SEARCH`. In Rust, serde_json uses the standard allocator,
    /// and memory management is handled by Rust's ownership system.
    ///
    /// # Parameters
    ///
    /// - `filename`: Must be `Some(path)` — JSON is a file-based lookup.
    ///
    /// # Errors
    ///
    /// - `DriverError::ExecutionFailed` if `filename` is `None`.
    /// - `DriverError::TempFail` if the file cannot be opened.
    fn open(&self, filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        let path = filename.ok_or_else(|| {
            DriverError::ExecutionFailed("json lookup requires a filename".into())
        })?;

        // Verify the file is accessible (replaces C Ufopen check).
        // The file is opened to validate accessibility, then closed.
        // It will be re-opened on each find() call for behavioral parity.
        File::open(path)
            .map_err(|e| DriverError::TempFail(format!("{} for json search: {}", path, e)))?;

        tracing::debug!(filename = %path, "json: file opened for lookup");

        Ok(Box::new(JsonHandle {
            filepath: path.to_string(),
        }))
    }

    /// Check JSON file credentials (type, permissions, ownership).
    ///
    /// Replaces C `json_check()` (lines 62–68 of json.c). Delegates to
    /// [`check_file`] with `ExpectedFileType::Regular` (matching the C
    /// `S_IFREG` parameter).
    ///
    /// The C version used `fileno()` on the open `FILE *` handle for
    /// `fstat()`-based checking. The Rust version uses a path-based `stat()`
    /// since we don't keep the file descriptor open.
    fn check(
        &self,
        handle: &LookupHandle,
        filename: Option<&str>,
        modemask: i32,
        owners: &[u32],
        owngroups: &[u32],
    ) -> Result<bool, DriverError> {
        // Determine the file path: prefer the explicit filename parameter,
        // fall back to the path stored in the handle from open().
        let filepath = match filename {
            Some(f) => f,
            None => {
                let json_handle = handle.downcast_ref::<JsonHandle>().ok_or_else(|| {
                    DriverError::ExecutionFailed("json check: invalid handle type".into())
                })?;
                json_handle.filepath.as_str()
            }
        };

        // Convert empty slices to None for the check_file API, matching the
        // C convention where NULL pointer means "any owner/group is acceptable".
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

        match check_file(
            CheckFileTarget::Path(Path::new(filepath)),
            ExpectedFileType::Regular,
            modemask as u32,
            owners_opt,
            owngroups_opt,
            "json",
            filepath,
        ) {
            Ok(()) => {
                tracing::debug!(filename = %filepath, "json: file check passed");
                Ok(true)
            }
            Err(e) => {
                tracing::warn!(
                    filename = %filepath,
                    error = %e,
                    "json: file check failed"
                );
                Ok(false)
            }
        }
    }

    /// Find a value by dot-separated path key in a JSON file.
    ///
    /// Replaces C `json_find()` (lines 78–136 of json.c). This is the primary
    /// lookup operation:
    ///
    /// 1. Re-open and re-parse the JSON file (matching C `rewind()` +
    ///    `json_loadf()` pattern — the file is not cached between calls).
    /// 2. Split the key into dot-separated path tokens.
    /// 3. For each token, traverse the JSON value tree:
    ///    - All-digit tokens: array index access (C `json_array_get`)
    ///    - Other tokens: object key access (C `json_object_get`)
    /// 4. Convert the final value to a string matching C Jansson type
    ///    conversion rules.
    ///
    /// # Parameters
    ///
    /// - `handle`: The handle from `open()`, containing the file path.
    /// - `_filename`: Ignored (path is stored in handle).
    /// - `key_or_query`: Dot-separated path (e.g., `"data.users.0.name"`).
    /// - `_options`: Ignored for JSON lookups.
    ///
    /// # Returns
    ///
    /// - `Ok(Found { value, .. })` — value found and converted to string.
    /// - `Ok(NotFound)` — a path component does not exist in the JSON tree.
    /// - `Err(DriverError::TempFail)` — file I/O error.
    /// - `Err(DriverError::ExecutionFailed)` — JSON parse error.
    fn find(
        &self,
        handle: &LookupHandle,
        _filename: Option<&str>,
        key_or_query: &str,
        _options: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        let json_handle = handle
            .downcast_ref::<JsonHandle>()
            .ok_or_else(|| DriverError::ExecutionFailed("json find: invalid handle type".into()))?;

        // Step 1: Re-open and parse the JSON file.
        // Replaces C: rewind(f); j = json_loadf(f, 0, &jerr);
        let file = File::open(&json_handle.filepath).map_err(|e| {
            DriverError::TempFail(format!("json: cannot read {}: {}", json_handle.filepath, e))
        })?;
        let reader = BufReader::new(file);
        let root: serde_json::Value = serde_json::from_reader(reader)
            .map_err(|e| DriverError::ExecutionFailed(format!("json error on open: {}\n", e)))?;

        // Step 2: Traverse the JSON value tree using dot-separated path tokens.
        // Replaces C: for (k=1; key = string_nextinlist(&keystring, &sep, ...); k++)
        let mut current = &root;
        let mut step: usize = 0;

        for token in key_or_query.split('.') {
            // Skip empty tokens (from leading/trailing/consecutive dots).
            if token.is_empty() {
                continue;
            }
            step += 1;

            // Determine if the token is purely numeric (all ASCII digits).
            // Replaces C: for (s = key; *s; s++) if (!isdigit(*s)) { numeric = FALSE; break; }
            let is_numeric = !token.is_empty() && token.bytes().all(|b| b.is_ascii_digit());

            if is_numeric {
                // Array index access — replaces C json_array_get().
                // Numeric tokens ONLY attempt array access, matching C behavior.
                let index: usize = token.parse().map_err(|_| {
                    DriverError::ExecutionFailed(format!(
                        "json: array index overflow for '{}'",
                        token
                    ))
                })?;

                match current.as_array() {
                    Some(arr) => match arr.get(index) {
                        Some(val) => {
                            tracing::debug!(
                                step = step,
                                index = index,
                                "json: array index traversal"
                            );
                            current = val;
                        }
                        None => {
                            tracing::debug!(
                                step = step,
                                key = %token,
                                "bad index, or not json array"
                            );
                            return Ok(LookupResult::NotFound);
                        }
                    },
                    None => {
                        tracing::debug!(
                            step = step,
                            key = %token,
                            "bad index, or not json array"
                        );
                        return Ok(LookupResult::NotFound);
                    }
                }
            } else {
                // Object key access — replaces C json_object_get().
                // Non-numeric tokens ONLY attempt object access, matching C behavior.
                match current.get(token) {
                    Some(val) => {
                        tracing::debug!(
                            step = step,
                            key = %token,
                            "json: object key traversal"
                        );
                        current = val;
                    }
                    None => {
                        tracing::debug!(
                            step = step,
                            key = %token,
                            "no such key, or not json object"
                        );
                        return Ok(LookupResult::NotFound);
                    }
                }
            }
        }

        // Step 3: Convert the final JSON value to a string.
        let value = json_value_to_string(current);
        tracing::debug!(
            key = %key_or_query,
            result = %value,
            "json: lookup complete"
        );

        Ok(LookupResult::Found {
            value,
            cache_ttl: None,
        })
    }

    /// Close an open JSON lookup handle.
    ///
    /// Replaces C `json_close()` (lines 146–150 of json.c). The C version
    /// called `fclose()` on the open `FILE *`. The Rust version drops the
    /// `JsonHandle`, releasing the stored path string. No file descriptor
    /// cleanup is needed since we don't keep files open between operations.
    fn close(&self, handle: LookupHandle) {
        // Log the close operation before the handle is dropped.
        if let Some(json_handle) = handle.downcast_ref::<JsonHandle>() {
            tracing::debug!(
                filename = %json_handle.filepath,
                "json: lookup handle closed"
            );
        }
        // handle is dropped here, releasing all resources.
    }

    /// Tidy up JSON lookup resources.
    ///
    /// The JSON lookup driver has no persistent cached state (the file is
    /// re-parsed on every `find()` call), so this is a no-op. Matches the
    /// C `json_lookup_info.tidy = NULL` setting.
    fn tidy(&self) {
        // No cached state to clean up — JSON files are re-parsed each lookup.
    }

    /// Report the JSON lookup library version for `-bV` output.
    ///
    /// Replaces C `json_version_report()` (lines 160–165 of json.c) which
    /// reported `"Jansonn version X.Y"`. The Rust version reports serde_json
    /// as the backing library.
    fn version_report(&self) -> Option<String> {
        Some("Library version: json: serde_json (Rust)".to_string())
    }

    /// Return the lookup type flags.
    ///
    /// JSON is a single-key file-based lookup requiring an absolute file path.
    /// Replaces C: `.type = lookup_absfile` in `json_lookup_info`.
    fn lookup_type(&self) -> LookupType {
        LookupType::ABS_FILE
    }

    /// Return the driver name for configuration file matching.
    ///
    /// Replaces C: `.name = US"json"` in `json_lookup_info`.
    fn driver_name(&self) -> &str {
        "json"
    }
}

// =============================================================================
// JSON Value to String Conversion
// =============================================================================

/// Convert a [`serde_json::Value`] to a string, matching C Jansson behavior.
///
/// This function replicates the type-based `switch (json_typeof(j))` from
/// C `json_find()` lines 118–133, producing identical string output for all
/// JSON value types.
///
/// # Conversion Rules
///
/// | JSON type  | Output                                       | C equivalent              |
/// |-----------|----------------------------------------------|---------------------------|
/// | null      | `""` (empty string)                           | `*result = NULL` → `""`   |
/// | true      | `"true"`                                      | `US"true"`                |
/// | false     | `"false"`                                     | `US"false"`               |
/// | integer   | Decimal representation (e.g., `"42"`)         | `JSON_INTEGER_FORMAT`     |
/// | float     | 6 decimal places (e.g., `"3.140000"`)         | `printf("%f", ...)`       |
/// | string    | The string content itself                     | `json_string_value()`     |
/// | object    | Compact JSON serialization                    | `json_dumps(j, 0)`        |
/// | array     | Compact JSON serialization                    | `json_dumps(j, 0)`        |
fn json_value_to_string(value: &serde_json::Value) -> String {
    match value {
        // JSON null → empty string (C: *result = NULL, which Exim expands to "")
        serde_json::Value::Null => String::new(),

        // JSON boolean → lowercase string (C: JSON_TRUE → "true", JSON_FALSE → "false")
        serde_json::Value::Bool(b) => {
            if *b {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }

        // JSON number → decimal string representation.
        // serde_json distinguishes integers from floats internally:
        //   - as_i64() succeeds for integers fitting i64 (C: JSON_INTEGER)
        //   - as_u64() succeeds for unsigned integers fitting u64
        //   - as_f64() succeeds for all numbers (C: JSON_REAL)
        // Priority: try i64 → u64 → f64 to match C's JSON_INTEGER vs JSON_REAL.
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                // Integer: matches C `string_sprintf("%" JSON_INTEGER_FORMAT, ...)`
                // where JSON_INTEGER_FORMAT is "%lld" — plain decimal integer.
                format!("{}", i)
            } else if let Some(u) = n.as_u64() {
                // Large unsigned integer that doesn't fit in i64.
                format!("{}", u)
            } else if let Some(f) = n.as_f64() {
                // Floating point: matches C `string_sprintf("%f", ...)`
                // C's %f defaults to 6 decimal places.
                format!("{:.6}", f)
            } else {
                // Fallback: should not occur with well-formed JSON, but handle
                // gracefully by using serde_json's own string representation.
                n.to_string()
            }
        }

        // JSON string → the string content (C: json_string_value())
        serde_json::Value::String(s) => s.clone(),

        // JSON object or array → compact JSON serialization (C: json_dumps(j, 0))
        // serde_json::Value::to_string() produces compact JSON without whitespace,
        // which matches Jansson's json_dumps with flags=0.
        other => other.to_string(),
    }
}

// =============================================================================
// Compile-Time Driver Registration
// =============================================================================

// Register the JSON lookup driver with the global driver registry via
// inventory::submit!. This replaces the C `json_lookup_info` struct and
// `json_lookup_module_info` registration from json.c lines 168–186.
//
// The factory is collected at link time by `inventory::iter::<LookupDriverFactory>()`
// in the exim-drivers registry module, eliminating the need for manual
// registration tables (C drtables.c).
inventory::submit! {
    LookupDriverFactory {
        name: "json",
        create: || Box::new(JsonLookup::new()),
        lookup_type: LookupType::ABS_FILE,
        avail_string: Some("json (serde_json)"),
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // JsonLookup construction tests
    // =========================================================================

    #[test]
    fn test_json_lookup_new() {
        let driver = JsonLookup::new();
        assert_eq!(driver.driver_name(), "json");
        assert_eq!(driver.lookup_type(), LookupType::ABS_FILE);
        assert!(driver.lookup_type().is_abs_file());
        assert!(driver.lookup_type().is_single_key());
        assert!(!driver.lookup_type().is_query_style());
    }

    #[test]
    fn test_json_lookup_version_report() {
        let driver = JsonLookup::new();
        let report = driver.version_report();
        assert!(report.is_some());
        let report_str = report.unwrap();
        assert!(report_str.contains("json"));
        assert!(report_str.contains("serde_json"));
    }

    #[test]
    fn test_json_lookup_tidy() {
        let driver = JsonLookup::new();
        // tidy() is a no-op for JSON — should not panic.
        driver.tidy();
    }

    #[test]
    fn test_json_lookup_quote() {
        let driver = JsonLookup::new();
        // JSON lookup does not implement quoting — default returns None.
        assert_eq!(driver.quote("test", None), None);
    }

    // =========================================================================
    // json_value_to_string conversion tests
    // =========================================================================

    #[test]
    fn test_value_null_to_string() {
        let val = serde_json::Value::Null;
        assert_eq!(json_value_to_string(&val), "");
    }

    #[test]
    fn test_value_true_to_string() {
        let val = serde_json::Value::Bool(true);
        assert_eq!(json_value_to_string(&val), "true");
    }

    #[test]
    fn test_value_false_to_string() {
        let val = serde_json::Value::Bool(false);
        assert_eq!(json_value_to_string(&val), "false");
    }

    #[test]
    fn test_value_integer_to_string() {
        let val = serde_json::json!(42);
        assert_eq!(json_value_to_string(&val), "42");
    }

    #[test]
    fn test_value_negative_integer_to_string() {
        let val = serde_json::json!(-17);
        assert_eq!(json_value_to_string(&val), "-17");
    }

    #[test]
    fn test_value_zero_to_string() {
        let val = serde_json::json!(0);
        assert_eq!(json_value_to_string(&val), "0");
    }

    #[test]
    fn test_value_float_to_string() {
        let val = serde_json::json!(3.14);
        // C %f produces 6 decimal places: "3.140000"
        let result = json_value_to_string(&val);
        assert!(result.starts_with("3.14"), "got: {}", result);
        // Verify 6 decimal places
        let parts: Vec<&str> = result.split('.').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1].len(), 6);
    }

    #[test]
    fn test_value_float_zero_to_string() {
        let val = serde_json::json!(0.0);
        let result = json_value_to_string(&val);
        assert_eq!(result, "0.000000");
    }

    #[test]
    fn test_value_string_to_string() {
        let val = serde_json::json!("hello world");
        assert_eq!(json_value_to_string(&val), "hello world");
    }

    #[test]
    fn test_value_empty_string_to_string() {
        let val = serde_json::json!("");
        assert_eq!(json_value_to_string(&val), "");
    }

    #[test]
    fn test_value_object_to_string() {
        let val = serde_json::json!({"key": "val"});
        let result = json_value_to_string(&val);
        // Should be compact JSON serialization
        assert!(result.contains("\"key\""));
        assert!(result.contains("\"val\""));
    }

    #[test]
    fn test_value_array_to_string() {
        let val = serde_json::json!([1, 2, 3]);
        let result = json_value_to_string(&val);
        assert_eq!(result, "[1,2,3]");
    }

    #[test]
    fn test_value_large_integer_to_string() {
        let val = serde_json::json!(9_223_372_036_854_775_807_i64); // i64::MAX
        assert_eq!(json_value_to_string(&val), "9223372036854775807");
    }

    // =========================================================================
    // open() error handling tests
    // =========================================================================

    #[test]
    fn test_open_requires_filename() {
        let driver = JsonLookup::new();
        let result = driver.open(None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("requires a filename"), "got: {}", msg);
    }

    #[test]
    fn test_open_nonexistent_file() {
        let driver = JsonLookup::new();
        let result = driver.open(Some("/nonexistent/path/to/file.json"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("json search"), "got: {}", msg);
    }

    // =========================================================================
    // find() path traversal tests (using temp files)
    // =========================================================================

    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Atomic counter to generate unique temp file names across test threads.
    static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// Helper: write JSON content to a temporary file and return the path.
    /// The caller is responsible for cleaning up the file.
    fn write_temp_json(content: &str) -> String {
        use std::io::Write;
        let id = TEMP_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let path = format!("/tmp/blitzy_json_test_{}_{}.json", pid, id);
        let mut f = File::create(&path).expect("create temp json file");
        f.write_all(content.as_bytes()).expect("write temp json");
        f.flush().expect("flush temp json");
        path
    }

    /// Helper: remove a temp file if it exists.
    fn cleanup_temp(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_find_simple_object_key() {
        let json = r#"{"name": "Alice", "age": 30}"#;
        let path = write_temp_json(json);
        let driver = JsonLookup::new();
        let handle = driver.open(Some(&path)).unwrap();

        let result = driver.find(&handle, None, "name", None).unwrap();
        assert!(matches!(
            result,
            LookupResult::Found { ref value, .. } if value == "Alice"
        ));

        let result = driver.find(&handle, None, "age", None).unwrap();
        assert!(matches!(
            result,
            LookupResult::Found { ref value, .. } if value == "30"
        ));

        driver.close(handle);
        cleanup_temp(&path);
    }

    #[test]
    fn test_find_nested_object() {
        let json = r#"{"user": {"name": "Bob", "email": "bob@example.com"}}"#;
        let path = write_temp_json(json);
        let driver = JsonLookup::new();
        let handle = driver.open(Some(&path)).unwrap();

        let result = driver.find(&handle, None, "user.name", None).unwrap();
        assert!(matches!(
            result,
            LookupResult::Found { ref value, .. } if value == "Bob"
        ));

        let result = driver.find(&handle, None, "user.email", None).unwrap();
        assert!(matches!(
            result,
            LookupResult::Found { ref value, .. } if value == "bob@example.com"
        ));

        driver.close(handle);
        cleanup_temp(&path);
    }

    #[test]
    fn test_find_array_index() {
        let json = r#"{"items": ["first", "second", "third"]}"#;
        let path = write_temp_json(json);
        let driver = JsonLookup::new();
        let handle = driver.open(Some(&path)).unwrap();

        let result = driver.find(&handle, None, "items.0", None).unwrap();
        assert!(matches!(
            result,
            LookupResult::Found { ref value, .. } if value == "first"
        ));

        let result = driver.find(&handle, None, "items.2", None).unwrap();
        assert!(matches!(
            result,
            LookupResult::Found { ref value, .. } if value == "third"
        ));

        driver.close(handle);
        cleanup_temp(&path);
    }

    #[test]
    fn test_find_mixed_path() {
        let json = r#"{"data": {"users": [{"name": "Eve"}, {"name": "Dan"}]}}"#;
        let path = write_temp_json(json);
        let driver = JsonLookup::new();
        let handle = driver.open(Some(&path)).unwrap();

        let result = driver
            .find(&handle, None, "data.users.1.name", None)
            .unwrap();
        assert!(matches!(
            result,
            LookupResult::Found { ref value, .. } if value == "Dan"
        ));

        driver.close(handle);
        cleanup_temp(&path);
    }

    #[test]
    fn test_find_not_found_missing_key() {
        let json = r#"{"a": 1}"#;
        let path = write_temp_json(json);
        let driver = JsonLookup::new();
        let handle = driver.open(Some(&path)).unwrap();

        let result = driver.find(&handle, None, "b", None).unwrap();
        assert_eq!(result, LookupResult::NotFound);

        driver.close(handle);
        cleanup_temp(&path);
    }

    #[test]
    fn test_find_not_found_array_out_of_bounds() {
        let json = r#"{"arr": [1, 2]}"#;
        let path = write_temp_json(json);
        let driver = JsonLookup::new();
        let handle = driver.open(Some(&path)).unwrap();

        let result = driver.find(&handle, None, "arr.5", None).unwrap();
        assert_eq!(result, LookupResult::NotFound);

        driver.close(handle);
        cleanup_temp(&path);
    }

    #[test]
    fn test_find_numeric_key_on_object_returns_not_found() {
        // Numeric keys only try array access, not object key access.
        // An object with numeric string key "0" should NOT be found via
        // a numeric path component — matching C json_array_get behavior.
        let json = r#"{"0": "zero_value"}"#;
        let path = write_temp_json(json);
        let driver = JsonLookup::new();
        let handle = driver.open(Some(&path)).unwrap();

        let result = driver.find(&handle, None, "0", None).unwrap();
        // C: json_array_get on an object returns NULL → FAIL
        assert_eq!(result, LookupResult::NotFound);

        driver.close(handle);
        cleanup_temp(&path);
    }

    #[test]
    fn test_find_null_value() {
        let json = r#"{"key": null}"#;
        let path = write_temp_json(json);
        let driver = JsonLookup::new();
        let handle = driver.open(Some(&path)).unwrap();

        let result = driver.find(&handle, None, "key", None).unwrap();
        assert!(matches!(
            result,
            LookupResult::Found { ref value, .. } if value.is_empty()
        ));

        driver.close(handle);
        cleanup_temp(&path);
    }

    #[test]
    fn test_find_boolean_values() {
        let json = r#"{"yes": true, "no": false}"#;
        let path = write_temp_json(json);
        let driver = JsonLookup::new();
        let handle = driver.open(Some(&path)).unwrap();

        let result = driver.find(&handle, None, "yes", None).unwrap();
        assert!(matches!(
            result,
            LookupResult::Found { ref value, .. } if value == "true"
        ));

        let result = driver.find(&handle, None, "no", None).unwrap();
        assert!(matches!(
            result,
            LookupResult::Found { ref value, .. } if value == "false"
        ));

        driver.close(handle);
        cleanup_temp(&path);
    }

    #[test]
    fn test_find_object_value_serialization() {
        let json = r#"{"nested": {"a": 1, "b": 2}}"#;
        let path = write_temp_json(json);
        let driver = JsonLookup::new();
        let handle = driver.open(Some(&path)).unwrap();

        let result = driver.find(&handle, None, "nested", None).unwrap();
        if let LookupResult::Found { value, .. } = result {
            // Result should be a compact JSON serialization of the object
            assert!(value.contains("\"a\""));
            assert!(value.contains("\"b\""));
        } else {
            panic!("expected Found, got {:?}", result);
        }

        driver.close(handle);
        cleanup_temp(&path);
    }

    #[test]
    fn test_find_array_value_serialization() {
        let json = r#"{"list": [10, 20, 30]}"#;
        let path = write_temp_json(json);
        let driver = JsonLookup::new();
        let handle = driver.open(Some(&path)).unwrap();

        let result = driver.find(&handle, None, "list", None).unwrap();
        if let LookupResult::Found { value, .. } = result {
            assert_eq!(value, "[10,20,30]");
        } else {
            panic!("expected Found, got {:?}", result);
        }

        driver.close(handle);
        cleanup_temp(&path);
    }

    #[test]
    fn test_find_empty_key_returns_root() {
        let json = r#"{"x": 1}"#;
        let path = write_temp_json(json);
        let driver = JsonLookup::new();
        let handle = driver.open(Some(&path)).unwrap();

        // Empty key: no tokens after split → returns root value serialized
        let result = driver.find(&handle, None, "", None).unwrap();
        if let LookupResult::Found { value, .. } = result {
            assert!(value.contains("\"x\""));
        } else {
            panic!("expected Found for empty key, got {:?}", result);
        }

        driver.close(handle);
        cleanup_temp(&path);
    }

    #[test]
    fn test_find_invalid_json() {
        let json = "not valid json {{{";
        let path = write_temp_json(json);
        let driver = JsonLookup::new();
        let handle = driver.open(Some(&path)).unwrap();

        let result = driver.find(&handle, None, "key", None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("json error"), "got: {}", msg);

        driver.close(handle);
        cleanup_temp(&path);
    }

    #[test]
    fn test_find_float_value() {
        let json = r#"{"pi": 3.14159}"#;
        let path = write_temp_json(json);
        let driver = JsonLookup::new();
        let handle = driver.open(Some(&path)).unwrap();

        let result = driver.find(&handle, None, "pi", None).unwrap();
        if let LookupResult::Found { value, .. } = result {
            // Should have 6 decimal places matching C %f
            assert!(value.starts_with("3.14159"), "got: {}", value);
            let parts: Vec<&str> = value.split('.').collect();
            assert_eq!(parts[1].len(), 6);
        } else {
            panic!("expected Found, got {:?}", result);
        }

        driver.close(handle);
        cleanup_temp(&path);
    }

    #[test]
    fn test_find_re_reads_file() {
        use std::io::Write;

        // Create a temp file with initial content
        let path = write_temp_json(r#"{"val": "first"}"#);

        let driver = JsonLookup::new();
        let handle = driver.open(Some(&path)).unwrap();

        // First lookup
        let result = driver.find(&handle, None, "val", None).unwrap();
        assert!(matches!(
            result,
            LookupResult::Found { ref value, .. } if value == "first"
        ));

        // Overwrite the file with new content
        {
            let mut f = File::create(&path).expect("overwrite");
            write!(f, r#"{{"val": "second"}}"#).expect("write new");
            f.sync_all().expect("sync");
        }

        // Second lookup should see the new content
        let result = driver.find(&handle, None, "val", None).unwrap();
        assert!(matches!(
            result,
            LookupResult::Found { ref value, .. } if value == "second"
        ));

        driver.close(handle);
        cleanup_temp(&path);
    }
}
