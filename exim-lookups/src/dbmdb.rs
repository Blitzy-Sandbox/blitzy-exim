// exim-lookups/src/dbmdb.rs — DBM hints database glue (via exim-ffi)
//
// Rewrites `src/src/lookups/dbmdb.c` (273 lines) as a Rust module providing
// three key-value lookup variants against Berkeley DB / GDBM / NDBM / TDB
// database files:
//
//   - **`dbm`**  — standard lookup; the key includes a trailing NUL byte in
//     the datum passed to the backend (matching the C convention where keys
//     are stored NUL-terminated).
//   - **`dbmnz`** — "no zero"; the key is the raw byte string without a
//     trailing NUL, for databases written by non-Exim tools that omit the
//     terminator.
//   - **`dbmjz`** — "join zero"; the input is an Exim colon-separated list
//     whose items are concatenated with NUL byte separators to form a
//     compound key, for multi-part lookup databases.
//
// All FFI interaction is delegated to the `exim-ffi` crate's `hintsdb`
// module — this file contains **zero** `unsafe` code per AAP §0.7.2.
//
// The concrete hintsdb backend (TDB, GDBM, NDBM, or BDB) is selected at
// compile time via Cargo feature flags (`hintsdb-tdb`, `hintsdb-gdbm`,
// `hintsdb-ndbm`, `hintsdb-bdb`).  When none is enabled the lookup
// compiles but returns `TempFail` at runtime.
//
// Three `LookupDriverFactory` instances are registered at link time via
// `inventory::submit!`, replacing the C `dbm_lookup_info`,
// `dbmz_lookup_info`, and `dbmjz_lookup_info` static registration tables.

#![deny(unsafe_code)]

use std::path::Path;

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;

use crate::helpers::check_file::{check_file, CheckFileTarget, ExpectedFileType};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Discriminates the three DBM lookup variants.
///
/// Each variant determines how the lookup key is constructed from the raw
/// key string supplied by the Exim expansion engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DbmdbVariant {
    /// Standard key: raw bytes **plus** a trailing NUL byte.
    Dbm,
    /// No-zero key: raw bytes only, **without** a trailing NUL.
    Dbmnz,
    /// Join-zero key: Exim colon-list items joined by NUL separators.
    Dbmjz,
}

/// Internal handle stored inside `LookupHandle` (`Box<dyn Any + Send + Sync>`).
///
/// Stores only the database file path.  Each `find()` call opens the
/// backend, performs the lookup, and lets the backend `Drop` to close —
/// this avoids HintsDb trait-object lifetime issues while remaining
/// functionally correct.  The search framework caches the *handle* (not
/// the database descriptor), so repeated lookups on the same file reuse
/// this path efficiently.
#[derive(Debug)]
struct DbmdbHandle {
    /// Absolute path to the DBM database file (without backend extension).
    path: String,
}

/// DBM hints database lookup driver.
///
/// Implements the [`LookupDriver`] trait for all three variants (`dbm`,
/// `dbmnz`, `dbmjz`).  Registered via [`inventory::submit!`] below.
#[derive(Debug)]
pub struct DbmdbLookup {
    /// Which variant this instance represents.
    variant: DbmdbVariant,
}

impl DbmdbLookup {
    /// Create a new `dbm` (standard, NUL-terminated key) lookup driver.
    fn new_dbm() -> Self {
        Self {
            variant: DbmdbVariant::Dbm,
        }
    }

    /// Create a new `dbmnz` (no NUL terminator) lookup driver.
    fn new_dbmnz() -> Self {
        Self {
            variant: DbmdbVariant::Dbmnz,
        }
    }

    /// Create a new `dbmjz` (NUL-joined compound key) lookup driver.
    fn new_dbmjz() -> Self {
        Self {
            variant: DbmdbVariant::Dbmjz,
        }
    }
}

// ---------------------------------------------------------------------------
// LookupDriver trait implementation
// ---------------------------------------------------------------------------

impl LookupDriver for DbmdbLookup {
    /// Return the canonical name of this lookup variant.
    fn driver_name(&self) -> &str {
        match self.variant {
            DbmdbVariant::Dbm => "dbm",
            DbmdbVariant::Dbmnz => "dbmnz",
            DbmdbVariant::Dbmjz => "dbmjz",
        }
    }

    /// All DBM variants use absolute file paths.
    fn lookup_type(&self) -> LookupType {
        LookupType::ABS_FILE
    }

    /// Open a DBM database file and return an opaque handle.
    ///
    /// The handle stores only the file path; the actual backend descriptor
    /// is opened lazily inside [`find()`].  This mirrors the C `dbmdb_open`
    /// semantics where the handle is an opaque reference.
    fn open(&self, filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        let path = filename.ok_or_else(|| {
            DriverError::InitFailed("dbm: absolute file path required for open".to_string())
        })?;

        tracing::debug!(
            path = %path,
            variant = self.driver_name(),
            "dbm: opening database handle"
        );

        // Return a handle containing just the file path.
        // Actual database open happens per-find().
        let handle = DbmdbHandle {
            path: path.to_string(),
        };
        Ok(Box::new(handle))
    }

    /// Validate file permissions and ownership for the database file.
    ///
    /// For single-file backends (BDB, TDB, GDBM) the base filename is
    /// checked directly.  For NDBM (or when no specific backend is known)
    /// the legacy extension pattern is used: try `.db` first, then fall
    /// back to checking both `.dir` and `.pag`.
    fn check(
        &self,
        _handle: &LookupHandle,
        filename: Option<&str>,
        modemask: i32,
        owners: &[u32],
        owngroups: &[u32],
    ) -> Result<bool, DriverError> {
        let path = match filename {
            Some(p) => p,
            None => return Ok(true), // Nothing to check
        };

        let modemask_u32 = if modemask >= 0 { modemask as u32 } else { 0 };
        let owners_opt: Option<&[u32]> = if owners.is_empty() {
            None
        } else {
            Some(owners)
        };
        let owngroups_opt: Option<&[u32]> = if owngroups.is_empty() {
            None
        } else {
            Some(owngroups)
        };

        tracing::debug!(
            path = %path,
            variant = self.driver_name(),
            "dbm: checking file permissions"
        );

        check_dbm_file(path, modemask_u32, owners_opt, owngroups_opt)
    }

    /// Look up a key in the DBM database.
    ///
    /// The key construction depends on the variant:
    ///
    /// - **`dbm`** — appends a NUL byte to the raw key string.
    /// - **`dbmnz`** — uses the raw key string bytes without NUL.
    /// - **`dbmjz`** — parses the key as an Exim colon-list and joins
    ///   items with NUL byte separators to form a compound key.
    fn find(
        &self,
        handle: &LookupHandle,
        _filename: Option<&str>,
        key_or_query: &str,
        _options: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        let dbm_handle = handle
            .downcast_ref::<DbmdbHandle>()
            .ok_or_else(|| DriverError::ExecutionFailed("dbm: invalid handle type".to_string()))?;

        // Build key bytes according to variant semantics.
        let key_bytes = match self.variant {
            DbmdbVariant::Dbm => {
                // Standard: include trailing NUL terminator in the key datum.
                let mut kb = Vec::with_capacity(key_or_query.len() + 1);
                kb.extend_from_slice(key_or_query.as_bytes());
                kb.push(0);
                kb
            }
            DbmdbVariant::Dbmnz => {
                // No-zero: raw key bytes without NUL terminator.
                key_or_query.as_bytes().to_vec()
            }
            DbmdbVariant::Dbmjz => {
                // Join-zero: parse colon-list, join items with NUL separators.
                build_nul_joined_key(key_or_query)
                    .map_err(|msg| DriverError::ExecutionFailed(format!("dbmjz: {}", msg)))?
            }
        };

        tracing::debug!(
            key = %key_or_query,
            variant = self.driver_name(),
            key_len = key_bytes.len(),
            path = %dbm_handle.path,
            "dbm: looking up key"
        );

        // Open the database, perform the lookup, return the result.
        // The backend descriptor is dropped (closed) when it goes out of scope.
        match open_and_get(&dbm_handle.path, &key_bytes) {
            Ok(Some(value_bytes)) => {
                // Convert raw bytes to a UTF-8 string, replacing invalid sequences.
                let value = String::from_utf8_lossy(&value_bytes).into_owned();
                tracing::debug!(
                    key = %key_or_query,
                    value_len = value.len(),
                    "dbm: key found"
                );
                Ok(LookupResult::Found {
                    value,
                    cache_ttl: None,
                })
            }
            Ok(None) => {
                tracing::debug!(key = %key_or_query, "dbm: key not found");
                Ok(LookupResult::NotFound)
            }
            Err(e) => {
                tracing::warn!(
                    key = %key_or_query,
                    path = %dbm_handle.path,
                    error = %e,
                    "dbm: lookup error"
                );
                Err(e)
            }
        }
    }

    /// Close the DBM handle.
    ///
    /// Since the handle only stores a path string (the actual backend is
    /// opened and closed within each `find()`), this simply logs and drops.
    fn close(&self, handle: LookupHandle) {
        if let Ok(h) = handle.downcast::<DbmdbHandle>() {
            tracing::debug!(path = %h.path, "dbm: closing handle");
        }
        // Handle is dropped here, freeing the path string.
    }

    /// Per-message cleanup hook.
    ///
    /// No persistent resources are held across calls (each `find()` opens
    /// and closes the backend), so this is a no-op.
    fn tidy(&self) {
        // No resources to tidy — backend is opened/closed per-find().
    }

    /// Optional key quoting.
    ///
    /// DBM lookups do not require special key quoting.  Returns `None` to
    /// indicate the key should be used as-is.
    fn quote(&self, _key: &str, _options: Option<&str>) -> Option<String> {
        None
    }

    /// Return a human-readable version/backend report string.
    ///
    /// Only the primary `dbm` variant reports version information, matching
    /// the C behaviour where `dbmz_lookup_info.version_report` and
    /// `dbmjz_lookup_info.version_report` are NULL.
    fn version_report(&self) -> Option<String> {
        if self.variant == DbmdbVariant::Dbm {
            let backend = hintsdb_backend_name();
            Some(format!(
                "Lookup: dbm (Rust implementation, {} backend)",
                backend,
            ))
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Backend-specific helpers — compile-time selected via Cargo features
// ---------------------------------------------------------------------------

/// Return the name of the compiled hintsdb backend.
///
/// Exactly one function body is compiled depending on which `hintsdb-*`
/// feature is active.  If none is active, returns `"none"`.
#[cfg(feature = "hintsdb-tdb")]
fn hintsdb_backend_name() -> &'static str {
    "tdb"
}

#[cfg(all(feature = "hintsdb-gdbm", not(feature = "hintsdb-tdb")))]
fn hintsdb_backend_name() -> &'static str {
    "gdbm"
}

#[cfg(all(
    feature = "hintsdb-ndbm",
    not(feature = "hintsdb-tdb"),
    not(feature = "hintsdb-gdbm")
))]
fn hintsdb_backend_name() -> &'static str {
    "ndbm"
}

#[cfg(all(
    feature = "hintsdb-bdb",
    not(feature = "hintsdb-tdb"),
    not(feature = "hintsdb-gdbm"),
    not(feature = "hintsdb-ndbm")
))]
fn hintsdb_backend_name() -> &'static str {
    "bdb"
}

#[cfg(not(any(
    feature = "hintsdb-tdb",
    feature = "hintsdb-gdbm",
    feature = "hintsdb-ndbm",
    feature = "hintsdb-bdb"
)))]
fn hintsdb_backend_name() -> &'static str {
    "none"
}

// -- open_and_get: open the hintsdb, fetch a key, drop the descriptor -------

/// TDB backend: open, get, drop.
#[cfg(feature = "hintsdb-tdb")]
fn open_and_get(path: &str, key_bytes: &[u8]) -> Result<Option<Vec<u8>>, DriverError> {
    use exim_ffi::hintsdb::{HintsDb, HintsDbDatum, OpenFlags, TdbHintsDb};

    let flags = OpenFlags::read_only();
    let db = TdbHintsDb::open(path, &flags, 0o644)
        .map_err(|e| DriverError::InitFailed(format!("tdb open failed: {}", e)))?;
    let key_datum = HintsDbDatum::new(key_bytes);
    let result = db
        .get(&key_datum)
        .map_err(|e| DriverError::ExecutionFailed(format!("tdb get failed: {}", e)))?;
    Ok(result.map(|d: HintsDbDatum| d.into_vec()))
    // `db` is dropped here — TdbHintsDb::drop() closes the TDB handle.
}

/// GDBM backend: open, get, drop.
#[cfg(all(feature = "hintsdb-gdbm", not(feature = "hintsdb-tdb")))]
fn open_and_get(path: &str, key_bytes: &[u8]) -> Result<Option<Vec<u8>>, DriverError> {
    use exim_ffi::hintsdb::{GdbmHintsDb, HintsDbDatum, OpenFlags};

    let flags = OpenFlags::read_only();
    let db = GdbmHintsDb::open(path, flags, 0o644)
        .map_err(|e| DriverError::InitFailed(format!("gdbm open failed: {}", e)))?;
    let key_datum = HintsDbDatum::new(key_bytes);
    let result = db
        .get(&key_datum)
        .map_err(|e| DriverError::ExecutionFailed(format!("gdbm get failed: {}", e)))?;
    Ok(result.map(|d| d.into_vec()))
}

/// NDBM backend: open, get, drop.
#[cfg(all(
    feature = "hintsdb-ndbm",
    not(feature = "hintsdb-tdb"),
    not(feature = "hintsdb-gdbm")
))]
fn open_and_get(path: &str, key_bytes: &[u8]) -> Result<Option<Vec<u8>>, DriverError> {
    use exim_ffi::hintsdb::{HintsDbDatum, NdbmHintsDb, OpenFlags};

    let flags = OpenFlags::read_only();
    let db = NdbmHintsDb::open(path, flags, 0o644)
        .map_err(|e| DriverError::InitFailed(format!("ndbm open failed: {}", e)))?;
    let key_datum = HintsDbDatum::new(key_bytes);
    let result = db
        .get(&key_datum)
        .map_err(|e| DriverError::ExecutionFailed(format!("ndbm get failed: {}", e)))?;
    Ok(result.map(|d| d.into_vec()))
}

/// BDB backend: open, get, drop.
#[cfg(all(
    feature = "hintsdb-bdb",
    not(feature = "hintsdb-tdb"),
    not(feature = "hintsdb-gdbm"),
    not(feature = "hintsdb-ndbm")
))]
fn open_and_get(path: &str, key_bytes: &[u8]) -> Result<Option<Vec<u8>>, DriverError> {
    use exim_ffi::hintsdb::{BdbHintsDb, HintsDbDatum, OpenFlags};

    let flags = OpenFlags::read_only();
    let db = BdbHintsDb::open(path, flags, 0o644)
        .map_err(|e| DriverError::InitFailed(format!("bdb open failed: {}", e)))?;
    let key_datum = HintsDbDatum::new(key_bytes);
    let result = db
        .get(&key_datum)
        .map_err(|e| DriverError::ExecutionFailed(format!("bdb get failed: {}", e)))?;
    Ok(result.map(|d| d.into_vec()))
}

/// No backend enabled: always returns `TempFail`.
#[cfg(not(any(
    feature = "hintsdb-tdb",
    feature = "hintsdb-gdbm",
    feature = "hintsdb-ndbm",
    feature = "hintsdb-bdb"
)))]
fn open_and_get(_path: &str, _key_bytes: &[u8]) -> Result<Option<Vec<u8>>, DriverError> {
    Err(DriverError::TempFail(
        "dbm: no hintsdb backend feature is enabled; \
         enable one of: hintsdb-tdb, hintsdb-gdbm, hintsdb-ndbm, hintsdb-bdb"
            .to_string(),
    ))
}

// -- check_dbm_file: validate file permissions using backend-aware logic ----

/// Single-file backend check (BDB, TDB, GDBM).
///
/// These backends store the entire database in one file, so we stat and
/// validate the base filename directly.
#[cfg(any(
    feature = "hintsdb-bdb",
    feature = "hintsdb-tdb",
    feature = "hintsdb-gdbm"
))]
fn check_dbm_file(
    path: &str,
    modemask: u32,
    owners: Option<&[u32]>,
    owngroups: Option<&[u32]>,
) -> Result<bool, DriverError> {
    tracing::debug!(path = %path, "dbm: checking single-file backend");
    check_file(
        CheckFileTarget::Path(Path::new(path)),
        ExpectedFileType::Regular,
        modemask,
        owners,
        owngroups,
        "dbm",
        path,
    )
    .map(|()| true)
    .map_err(|e| {
        DriverError::ExecutionFailed(format!("dbm: file check failed for {}: {}", path, e))
    })
}

/// Legacy extension check (NDBM or no backend).
///
/// NDBM creates two files (`basename.dir` and `basename.pag`).  Some
/// backends add a `.db` extension instead.  The check logic mirrors the C
/// implementation: try `basename.db` first; if stat fails, try
/// `basename.dir` and (if that passes) `basename.pag`.
#[cfg(not(any(
    feature = "hintsdb-bdb",
    feature = "hintsdb-tdb",
    feature = "hintsdb-gdbm"
)))]
fn check_dbm_file(
    path: &str,
    modemask: u32,
    owners: Option<&[u32]>,
    owngroups: Option<&[u32]>,
) -> Result<bool, DriverError> {
    use crate::helpers::check_file::CheckFileError;
    tracing::debug!(path = %path, "dbm: checking legacy extension patterns");

    // --- Attempt 1: try basename.db ---
    let db_path = format!("{}.db", path);
    let db_result = check_file(
        CheckFileTarget::Path(Path::new(&db_path)),
        ExpectedFileType::Regular,
        modemask,
        owners,
        owngroups,
        "dbm",
        &db_path,
    );

    match db_result {
        Ok(()) => return Ok(true),
        Err(CheckFileError::StatFailed { .. }) => {
            tracing::debug!(
                db_path = %db_path,
                "dbm: .db stat failed, trying .dir/.pag pattern"
            );
            // Fall through to .dir/.pag check
        }
        Err(e) => {
            return Err(DriverError::ExecutionFailed(format!(
                "dbm: file check failed for {}: {}",
                db_path, e
            )));
        }
    }

    // --- Attempt 2: try basename.dir ---
    let dir_path = format!("{}.dir", path);
    check_file(
        CheckFileTarget::Path(Path::new(&dir_path)),
        ExpectedFileType::Regular,
        modemask,
        owners,
        owngroups,
        "dbm",
        &dir_path,
    )
    .map_err(|e| {
        DriverError::ExecutionFailed(format!("dbm: file check failed for {}: {}", dir_path, e))
    })?;

    // --- Attempt 3: .dir passed, now check basename.pag ---
    let pag_path = format!("{}.pag", path);
    check_file(
        CheckFileTarget::Path(Path::new(&pag_path)),
        ExpectedFileType::Regular,
        modemask,
        owners,
        owngroups,
        "dbm",
        &pag_path,
    )
    .map_err(|e| {
        DriverError::ExecutionFailed(format!("dbm: file check failed for {}: {}", pag_path, e))
    })?;

    Ok(true)
}

// ---------------------------------------------------------------------------
// NUL-joined key construction (for the `dbmjz` variant)
// ---------------------------------------------------------------------------

/// Build a compound lookup key by joining Exim colon-list items with NUL
/// byte separators.
///
/// Replicates the C `dbmjz_find` key construction logic:
///
///  1. Parse the input string as an Exim colon-separated list.
///  2. Concatenate each item's bytes with a NUL separator between items.
///  3. Empty items are represented faithfully: an empty first item produces
///     two leading NUL bytes; subsequent empty items produce a single NUL.
///  4. The final key does **not** include a trailing NUL.
///
/// # Errors
///
/// Returns an error string if the list produces an empty key.
fn build_nul_joined_key(input: &str) -> Result<Vec<u8>, String> {
    let (sep, list_str) = detect_list_separator(input);
    let items: Vec<&str> = list_str.split(sep).collect();

    // Guard against completely empty input.
    if items.is_empty() {
        return Err("empty list key".to_string());
    }

    let mut key = Vec::with_capacity(input.len() + 3);
    let mut first = true;

    for item in &items {
        // Trim leading whitespace from each item, matching the C
        // string_nextinlist behaviour.
        let trimmed = item.trim_start();

        if trimmed.is_empty() {
            if first {
                // First item is empty: emit two NUL bytes (the item itself
                // is empty, so its "content" is zero bytes, plus we need
                // the separator NUL that will follow).
                key.push(0);
                key.push(0);
            } else {
                // Subsequent empty item: reuses the trailing NUL from the
                // previous item as its own "content", then adds one NUL as
                // the separator.
                key.push(0);
            }
        } else {
            // Non-empty item: write the item bytes followed by a NUL.
            key.extend_from_slice(trimmed.as_bytes());
            key.push(0);
        }
        first = false;
    }

    if key.is_empty() {
        return Err("empty list key".to_string());
    }

    // Remove the trailing NUL — the C code passes key_item_len-1 to
    // dbmdb_find which then adds 1, yielding exactly the bytes up to
    // (but not including) the final NUL.
    key.pop();

    tracing::debug!(
        nul_joined_key_len = key.len(),
        "dbmjz: NUL-joined key length"
    );

    Ok(key)
}

/// Detect a custom list separator from the Exim `<c` prefix notation.
///
/// If the input starts with `<` followed by a non-`<` character, that
/// character becomes the separator and the remainder of the string (after
/// an optional space) is the list body.  A `<<` prefix is treated as a
/// literal `<` with the default colon separator.
fn detect_list_separator(input: &str) -> (char, &str) {
    let bytes = input.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'<' {
        if bytes[1] == b'<' {
            // `<<` — literal `<`, use default colon separator.
            // Skip the first `<`, keep the second as part of the list.
            (':', &input[1..])
        } else {
            // `<c` — custom separator.
            let sep_char = bytes[1] as char;
            let skip = 2; // `<` + separator character
            let remaining = &input[skip..];
            // Skip an optional space after the separator declaration.
            let trimmed = remaining.strip_prefix(' ').unwrap_or(remaining);
            (sep_char, trimmed)
        }
    } else {
        // Default: colon separator.
        (':', input)
    }
}

// ---------------------------------------------------------------------------
// Driver registration — three factory instances via inventory::submit!
// ---------------------------------------------------------------------------

inventory::submit! {
    LookupDriverFactory {
        name: "dbm",
        create: || Box::new(DbmdbLookup::new_dbm()),
        lookup_type: LookupType::ABS_FILE,
        avail_string: Some("dbm (Rust hintsdb)"),
    }
}

inventory::submit! {
    LookupDriverFactory {
        name: "dbmnz",
        create: || Box::new(DbmdbLookup::new_dbmnz()),
        lookup_type: LookupType::ABS_FILE,
        avail_string: Some("dbmnz (Rust hintsdb)"),
    }
}

inventory::submit! {
    LookupDriverFactory {
        name: "dbmjz",
        create: || Box::new(DbmdbLookup::new_dbmjz()),
        lookup_type: LookupType::ABS_FILE,
        avail_string: Some("dbmjz (Rust hintsdb)"),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Variant construction --

    #[test]
    fn test_new_dbm_variant() {
        let lookup = DbmdbLookup::new_dbm();
        assert_eq!(lookup.variant, DbmdbVariant::Dbm);
        assert_eq!(lookup.driver_name(), "dbm");
    }

    #[test]
    fn test_new_dbmnz_variant() {
        let lookup = DbmdbLookup::new_dbmnz();
        assert_eq!(lookup.variant, DbmdbVariant::Dbmnz);
        assert_eq!(lookup.driver_name(), "dbmnz");
    }

    #[test]
    fn test_new_dbmjz_variant() {
        let lookup = DbmdbLookup::new_dbmjz();
        assert_eq!(lookup.variant, DbmdbVariant::Dbmjz);
        assert_eq!(lookup.driver_name(), "dbmjz");
    }

    // -- Lookup type --

    #[test]
    fn test_lookup_type_is_abs_file() {
        for lookup in [
            DbmdbLookup::new_dbm(),
            DbmdbLookup::new_dbmnz(),
            DbmdbLookup::new_dbmjz(),
        ] {
            assert_eq!(lookup.lookup_type(), LookupType::ABS_FILE);
        }
    }

    // -- Version report --

    #[test]
    fn test_version_report_dbm_returns_some() {
        let lookup = DbmdbLookup::new_dbm();
        let report = lookup.version_report();
        assert!(
            report.is_some(),
            "dbm variant should produce a version report"
        );
        let text = report.unwrap();
        assert!(text.contains("dbm"), "version report should mention 'dbm'");
    }

    #[test]
    fn test_version_report_dbmnz_returns_none() {
        let lookup = DbmdbLookup::new_dbmnz();
        assert!(
            lookup.version_report().is_none(),
            "dbmnz should not produce a version report"
        );
    }

    #[test]
    fn test_version_report_dbmjz_returns_none() {
        let lookup = DbmdbLookup::new_dbmjz();
        assert!(
            lookup.version_report().is_none(),
            "dbmjz should not produce a version report"
        );
    }

    // -- Key quoting --

    #[test]
    fn test_quote_returns_none() {
        let lookup = DbmdbLookup::new_dbm();
        assert!(lookup.quote("some key", None).is_none());
    }

    // -- Open requires filename --

    #[test]
    fn test_open_requires_filename() {
        let lookup = DbmdbLookup::new_dbm();
        let result = lookup.open(None);
        assert!(result.is_err());
    }

    #[test]
    fn test_open_succeeds_with_path() {
        let lookup = DbmdbLookup::new_dbm();
        let result = lookup.open(Some("/tmp/test_dbm"));
        assert!(result.is_ok());
    }

    // -- Handle downcast --

    #[test]
    fn test_handle_stores_path() {
        let lookup = DbmdbLookup::new_dbm();
        let handle = lookup.open(Some("/my/database")).unwrap();
        let inner = handle.downcast_ref::<DbmdbHandle>().unwrap();
        assert_eq!(inner.path, "/my/database");
    }

    // -- NUL-joined key construction --

    #[test]
    fn test_nul_joined_key_simple() {
        let key = build_nul_joined_key("a:b:c").unwrap();
        // Expected: a \0 b \0 c  (5 bytes, no trailing NUL)
        assert_eq!(key, b"a\0b\0c");
    }

    #[test]
    fn test_nul_joined_key_single_item() {
        let key = build_nul_joined_key("hello").unwrap();
        // Expected: hello  (5 bytes, no NUL at all)
        assert_eq!(key, b"hello");
    }

    #[test]
    fn test_nul_joined_key_empty_first_item() {
        let key = build_nul_joined_key(":b").unwrap();
        // Expected: \0 \0 b  (3 bytes — two NULs for empty first item)
        assert_eq!(key, b"\0\0b");
    }

    #[test]
    fn test_nul_joined_key_empty_trailing_item() {
        let key = build_nul_joined_key("a:").unwrap();
        // Expected: a \0  (2 bytes — item + separator NUL for empty trailing)
        assert_eq!(key, b"a\0");
    }

    #[test]
    fn test_nul_joined_key_empty_middle_item() {
        let key = build_nul_joined_key("a::b").unwrap();
        // Expected: a \0 \0 b  (4 bytes — NUL after "a", NUL for empty, then "b")
        assert_eq!(key, b"a\0\0b");
    }

    #[test]
    fn test_nul_joined_key_all_empty() {
        let key = build_nul_joined_key("::").unwrap();
        // Three empty items: \0 \0 \0  (3 bytes)
        assert_eq!(key, b"\0\0\0");
    }

    #[test]
    fn test_nul_joined_key_custom_separator() {
        let key = build_nul_joined_key("<; x;y;z").unwrap();
        // Separator is ';', items are "x", "y", "z"
        assert_eq!(key, b"x\0y\0z");
    }

    #[test]
    fn test_nul_joined_key_escaped_angle_bracket() {
        let key = build_nul_joined_key("<<stuff:here").unwrap();
        // `<<` means literal '<', separator is ':', items are "<stuff", "here"
        assert_eq!(key, b"<stuff\0here");
    }

    // -- Separator detection --

    #[test]
    fn test_detect_separator_default() {
        let (sep, rest) = detect_list_separator("a:b:c");
        assert_eq!(sep, ':');
        assert_eq!(rest, "a:b:c");
    }

    #[test]
    fn test_detect_separator_custom_semicolon() {
        let (sep, rest) = detect_list_separator("<; a;b;c");
        assert_eq!(sep, ';');
        assert_eq!(rest, "a;b;c");
    }

    #[test]
    fn test_detect_separator_escaped_angle() {
        let (sep, rest) = detect_list_separator("<<foo:bar");
        assert_eq!(sep, ':');
        assert_eq!(rest, "<foo:bar");
    }

    // -- Close and tidy (no-panic checks) --

    #[test]
    fn test_close_does_not_panic() {
        let lookup = DbmdbLookup::new_dbm();
        let handle = lookup.open(Some("/tmp/test")).unwrap();
        lookup.close(handle);
    }

    #[test]
    fn test_tidy_does_not_panic() {
        let lookup = DbmdbLookup::new_dbm();
        lookup.tidy();
    }

    // -- Backend name --

    #[test]
    fn test_hintsdb_backend_name_is_valid() {
        let name = hintsdb_backend_name();
        assert!(
            ["tdb", "gdbm", "ndbm", "bdb", "none"].contains(&name),
            "unexpected backend name: {}",
            name,
        );
    }
}
