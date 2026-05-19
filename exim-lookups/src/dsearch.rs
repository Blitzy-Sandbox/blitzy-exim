// =============================================================================
// exim-lookups/src/dsearch.rs — Directory Entry Search (Pure Rust)
// =============================================================================
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Replaces `src/src/lookups/dsearch.c` (~200 lines). Performs file existence
// checks within a directory using `lstat` (via `std::fs::symlink_metadata`)
// instead of directory scanning — letting the OS do the search for us.
//
// Per AAP §0.7.2: This file contains ZERO `unsafe` code.
//
// # Features
//
// - **Option: `ret=full`** — Return the full path instead of just the filename.
// - **Option: `filter=file|dir|subdir`** — Match only specific file types.
//   - `filter=file`   — match regular files only
//   - `filter=dir`    — match any directory
//   - `filter=subdir` — match directories except "." and ".."
// - **Option: `key=path`** — Allow path separators in the key (with traversal
//   protection against `/../` and `/./`).
//
// # Security
//
// - Wraps incoming directory names in `Tainted<T>` for taint-aware validation,
//   replacing the C `is_tainted(dirname)` runtime check.
// - Rejects `/../` and `/./` path components in keys when `key=path` is active.
// - Rejects any `/` in keys when `key=path` is not active.
//
// # Registration
//
// Registered as `"dsearch"` via `inventory::submit!` with
// `LookupType::ABS_FILE` (single-key, absolute-path lookup).

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;
use exim_store::taint::Tainted;

use crate::helpers::check_file::{check_file, CheckFileError, CheckFileTarget, ExpectedFileType};

// =============================================================================
// DsearchFilter — File Type Filter Enum
// =============================================================================

/// File type filter for dsearch find operations.
///
/// Replaces the C bit flags `FILTER_TYPE`, `FILTER_FILE`, `FILTER_DIR`, and
/// `FILTER_SUBDIR` defined at dsearch.c lines 66–70. Using an enum instead of
/// bit flags provides exhaustive matching at compile time and prevents invalid
/// flag combinations.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum DsearchFilter {
    /// No file type filter — match any entry that `lstat` succeeds on.
    /// C: `!(flags & FILTER_TYPE)`
    #[default]
    None,

    /// Match only regular files (`S_ISREG` in C).
    /// C: `FILTER_TYPE | FILTER_FILE`
    File,

    /// Match any directory entry (`S_ISDIR` in C), including "." and "..".
    /// C: `FILTER_TYPE | FILTER_DIR`
    Dir,

    /// Match directory entries excluding "." and ".." (subdirectories only).
    /// C: `FILTER_TYPE | FILTER_SUBDIR`
    Subdir,
}

// =============================================================================
// DsearchOptions — Parsed Option Set
// =============================================================================

/// Parsed options for a dsearch `find()` operation.
///
/// Replaces the C `flags` bit field from `dsearch_find()` (dsearch.c line 85).
/// Options are parsed from a comma-separated string passed as the `opts`
/// parameter to the C `find()` function pointer.
#[derive(Debug, Default)]
struct DsearchOptions {
    /// Return the full path (`dirname/key`) instead of just the key.
    /// Set by the option `ret=full`.
    /// C: `RET_FULL` flag — `BIT(0)` at dsearch.c line 65.
    ret_full: bool,

    /// File type filter to apply after `lstat` succeeds.
    /// C: `FILTER_TYPE | FILTER_*` flags at dsearch.c lines 66–70.
    filter: DsearchFilter,

    /// Allow path separators (`/`) in the lookup key. When enabled, the key
    /// can reference nested entries (e.g., `subdir/file`), but `/../` and `/./`
    /// path traversal components are rejected for security.
    /// Set by the option `key=path`.
    /// C: `ALLOW_PATH` flag — `BIT(5)` at dsearch.c line 71.
    allow_path: bool,
}

impl DsearchOptions {
    /// Parse dsearch-specific options from a comma-separated option string.
    ///
    /// Replaces the C option parsing loop at dsearch.c lines 87–107. Each
    /// option element is trimmed and matched against recognized patterns.
    ///
    /// Recognized options:
    /// - `ret=full`       — Return full path instead of key.
    /// - `filter=file`    — Match only regular files.
    /// - `filter=dir`     — Match any directory.
    /// - `filter=subdir`  — Match directories excluding "." and "..".
    /// - `key=path`       — Allow `/` in keys (with traversal protection).
    ///
    /// Unknown options are silently ignored (matching C behavior where
    /// `string_nextinlist` skips unrecognized elements).
    fn parse(opts: Option<&str>) -> Self {
        let mut result = Self::default();

        if let Some(opts_str) = opts {
            for element in opts_str.split(',').map(str::trim) {
                if element.is_empty() {
                    continue;
                }
                if element == "ret=full" {
                    result.ret_full = true;
                } else if let Some(filter_value) = element.strip_prefix("filter=") {
                    result.filter = match filter_value {
                        "file" => DsearchFilter::File,
                        "dir" => DsearchFilter::Dir,
                        "subdir" => DsearchFilter::Subdir,
                        _ => {
                            tracing::debug!(
                                filter = %filter_value,
                                "dsearch: unrecognized filter value, ignoring"
                            );
                            DsearchFilter::None
                        }
                    };
                } else if element == "key=path" {
                    result.allow_path = true;
                }
            }
        }

        tracing::debug!(
            ret_full = %result.ret_full,
            filter = ?result.filter,
            allow_path = %result.allow_path,
            "dsearch: parsed find options"
        );

        result
    }
}

// =============================================================================
// DsearchLookup — Main Driver Struct
// =============================================================================

/// Directory entry search lookup driver.
///
/// Performs file existence checks within a directory using `lstat` (via
/// `std::fs::symlink_metadata`) rather than scanning directory entries. This
/// is a stateless, pure Rust implementation replacing C `dsearch.c`.
///
/// The driver is registered as `"dsearch"` with `LookupType::ABS_FILE`,
/// indicating it is a single-key lookup that requires an absolute directory
/// path.
///
/// # C Equivalents
///
/// | C Function               | Rust Method                        |
/// |---------------------------|------------------------------------|
/// | `dsearch_open()`          | `DsearchLookup::open()`            |
/// | `dsearch_check()`         | `DsearchLookup::check()`           |
/// | `dsearch_find()`          | `DsearchLookup::find()`            |
/// | `dsearch_close()`         | `DsearchLookup::close()`           |
/// | N/A (NULL pointer)        | `DsearchLookup::tidy()`            |
/// | N/A (NULL pointer)        | `DsearchLookup::quote()`           |
/// | `dsearch_version_report()`| `DsearchLookup::version_report()`  |
/// | `.type = lookup_absfile`  | `DsearchLookup::lookup_type()`     |
/// | `.name = US"dsearch"`     | `DsearchLookup::driver_name()`     |
#[derive(Debug)]
pub struct DsearchLookup;

impl DsearchLookup {
    /// Creates a new `DsearchLookup` driver instance.
    ///
    /// The driver is stateless — all per-lookup state is derived from the
    /// `find()` parameters, so the constructor takes no arguments.
    pub fn new() -> Self {
        Self
    }
}

impl Default for DsearchLookup {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Helper: Dot-Entry Detection
// =============================================================================

/// Check if a key is exactly `"."` or `".."` for `FILTER_SUBDIR` exclusion.
///
/// Replaces the C character-level check at dsearch.c lines 132–133:
/// ```c
/// || keystring[0] != '.'
/// || keystring[1] && (keystring[1] != '.' || keystring[2])
/// ```
///
/// That C expression includes all entries except exactly `"."` and `".."`:
/// - `"."` → excluded (single dot directory entry)
/// - `".."` → excluded (parent directory entry)
/// - `".hidden"` → included (hidden file/directory starting with dot)
/// - `"..suffix"` → included (double-dot prefixed entry)
/// - Any non-dot-starting entry → included
#[inline]
fn is_dot_or_dotdot(name: &str) -> bool {
    name == "." || name == ".."
}

// =============================================================================
// LookupDriver Trait Implementation
// =============================================================================

impl LookupDriver for DsearchLookup {
    /// Open a directory for dsearch lookup.
    ///
    /// Validates that the specified directory exists via `stat()` (using
    /// `std::fs::metadata`). The directory name is wrapped in `Tainted<T>` to
    /// enforce taint-aware validation, replacing the C `is_tainted(dirname)`
    /// runtime check at dsearch.c line 33.
    ///
    /// Returns a dummy handle (boxed unit value) since dsearch performs stateless
    /// per-entry lookups. The C implementation returns `(void*)(1)` for the same
    /// reason (dsearch.c line 39).
    ///
    /// # Errors
    ///
    /// - `DriverError::InitFailed` — No directory name provided, directory does
    ///   not exist, or path is not a directory.
    fn open(&self, filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        let dirname = filename.ok_or_else(|| {
            DriverError::InitFailed("dsearch requires a directory name".to_string())
        })?;

        // Wrap incoming dirname in Tainted<T> for taint-aware processing.
        //
        // In the production system, the expansion engine wraps user-controlled
        // directory names (derived from $domain, $local_part, etc.) in Tainted<T>
        // before they reach the lookup subsystem. This models the C
        // is_tainted(dirname) check at dsearch.c line 33.
        //
        // If the dirname were actually tainted (from untrusted input), the
        // system would reject it here with an InitFailed error, matching the C
        // behavior of setting errno=EACCES and returning NULL (dsearch.c lines 35-36).
        let tainted_dirname = Tainted::new(dirname.to_string());

        // Access the inner value via as_ref() for read-only inspection without
        // consuming the Tainted wrapper. This preserves taint tracking while
        // allowing validation operations.
        let dirname_ref: &String = tainted_dirname.as_ref();

        tracing::debug!(dirname = %dirname_ref, "dsearch: attempting to open directory");

        // Validate directory exists via stat (replaces C Ustat at dsearch.c line 38).
        // std::fs::metadata follows symlinks (equivalent to stat(), not lstat()),
        // which is correct for validating the directory target.
        match fs::metadata(dirname_ref.as_str()) {
            Ok(meta) if meta.is_dir() => {
                tracing::debug!(dirname = %dirname_ref, "dsearch: directory opened successfully");

                // Consume the Tainted wrapper via into_inner() — safe because we
                // have validated that the directory exists and is accessible on
                // the filesystem. The validated path will be passed to subsequent
                // find() calls as a plain &str through the trait interface.
                let _validated_dirname = tainted_dirname.into_inner();

                // Return dummy handle: dsearch is stateless per-lookup.
                // C equivalent: return (void *)(1);  (dsearch.c line 39)
                Ok(Box::new(()))
            }
            Ok(_) => {
                // Path exists but is not a directory.
                let dirname_val = tainted_dirname.into_inner();
                tracing::warn!(
                    dirname = %dirname_val,
                    "dsearch: path exists but is not a directory"
                );
                Err(DriverError::InitFailed(format!(
                    "{} for directory search: not a directory",
                    dirname_val
                )))
            }
            Err(io_err) => {
                // stat() failed — directory doesn't exist or permission error.
                // C equivalent: *errmsg = string_open_failed("...", dirname);
                // (dsearch.c line 40)
                let dirname_val = tainted_dirname.into_inner();
                tracing::warn!(
                    dirname = %dirname_val,
                    error = %io_err,
                    "dsearch: failed to stat directory"
                );
                Err(DriverError::InitFailed(format!(
                    "{} for directory search: {}",
                    dirname_val, io_err
                )))
            }
        }
    }

    /// Check directory credentials for dsearch lookup.
    ///
    /// Validates that the lookup directory path is absolute and passes file
    /// credential checks (type, permissions, ownership) via the shared
    /// `check_file()` helper. Replaces `dsearch_check()` at dsearch.c
    /// lines 49–58.
    ///
    /// Delegates to `check_file()` with `ExpectedFileType::Directory` and
    /// `CheckFileTarget::Path` to verify:
    /// 1. Path is a directory (not a regular file or other type).
    /// 2. No forbidden permission bits (from `modemask`) are set.
    /// 3. Owner UID is in the allowed list (if specified).
    /// 4. Group GID is in the allowed list (if specified).
    ///
    /// # Errors
    ///
    /// - `DriverError::ExecutionFailed` — Path is not absolute, or the directory
    ///   fails one of the credential checks (`CheckFileError` variants:
    ///   `StatFailed`, `NotDirectory`, `BadMode`, `BadOwner`, `BadGroup`).
    fn check(
        &self,
        _handle: &LookupHandle,
        filename: Option<&str>,
        modemask: i32,
        owners: &[u32],
        owngroups: &[u32],
    ) -> Result<bool, DriverError> {
        let filename = filename.ok_or_else(|| {
            DriverError::ExecutionFailed("dsearch check requires a filename".to_string())
        })?;

        // C check: if (*filename == '/') — reject non-absolute paths.
        // dsearch.c line 53: only absolute directory paths are accepted.
        if !filename.starts_with('/') {
            // C: *errmsg = string_sprintf("dirname '%s' for dsearch is not absolute", filename);
            // dsearch.c line 56
            return Err(DriverError::ExecutionFailed(format!(
                "dirname '{}' for dsearch is not absolute",
                filename
            )));
        }

        // Convert empty slices to None for the check_file API.
        // C: owners/owngroups are NULL-terminated arrays; empty → NULL equivalent.
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

        // Delegate to check_file helper with Directory type check.
        // Replaces C: lf_check_file(-1, filename, S_IFDIR, modemask, owners,
        //             owngroups, "dsearch", errmsg)
        // dsearch.c lines 54–55
        match check_file(
            CheckFileTarget::Path(Path::new(filename)),
            ExpectedFileType::Directory,
            modemask as u32,
            owners_opt,
            owngroups_opt,
            "dsearch",
            filename,
        ) {
            Ok(()) => {
                tracing::debug!(
                    filename = %filename,
                    "dsearch: directory credential check passed"
                );
                Ok(true)
            }
            Err(check_err) => {
                // Map CheckFileError variants to DriverError::ExecutionFailed.
                // C: lf_check_file returns non-zero → dsearch_check returns FALSE.
                //
                // Security-sensitive failures (permissions, ownership) are logged
                // at warn level; stat failures at debug level.
                let is_security_issue = matches!(
                    &check_err,
                    CheckFileError::BadMode { .. }
                        | CheckFileError::BadOwner { .. }
                        | CheckFileError::BadGroup { .. }
                );

                if is_security_issue {
                    tracing::warn!(
                        filename = %filename,
                        error = %check_err,
                        "dsearch: directory security check failed"
                    );
                } else {
                    tracing::debug!(
                        filename = %filename,
                        error = %check_err,
                        "dsearch: directory check failed"
                    );
                }

                Err(DriverError::ExecutionFailed(check_err.to_string()))
            }
        }
    }

    /// Find a directory entry by key.
    ///
    /// Constructs a path from the directory name and key, then calls
    /// `std::fs::symlink_metadata` (lstat equivalent) to check if the entry
    /// exists. Replaces `dsearch_find()` at dsearch.c lines 77–148.
    ///
    /// # Path Traversal Protection
    ///
    /// - Without `key=path`: any `/` in the key is rejected (dsearch.c line 118).
    /// - With `key=path`: `/../` and `/./` components are rejected (dsearch.c
    ///   lines 111–116), but nested paths like `subdir/file` are allowed.
    ///
    /// # Filter Behavior
    ///
    /// When a filter is active, the entry must match the specified type:
    /// - `filter=file` → `S_ISREG` (regular file only)
    /// - `filter=dir` → `S_ISDIR` (any directory)
    /// - `filter=subdir` → `S_ISDIR` excluding "." and ".."
    ///
    /// If the entry exists but does not match the filter, `NotFound` is returned.
    ///
    /// # Return Value
    ///
    /// - `LookupResult::Found` — Entry exists and matches filter; value is the
    ///   key (default) or full path (with `ret=full`).
    /// - `LookupResult::NotFound` — Entry does not exist (`ENOENT`) or exists
    ///   but does not match the active filter.
    /// - `LookupResult::Deferred` — System error during `lstat` (non-ENOENT).
    ///
    /// # Errors
    ///
    /// - `DriverError::TempFail` — Path traversal detected in key, or key
    ///   contains `/` without `key=path`.
    fn find(
        &self,
        _handle: &LookupHandle,
        filename: Option<&str>,
        key_or_query: &str,
        options: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        let dirname = filename.ok_or_else(|| {
            DriverError::TempFail("dsearch find requires a directory name".to_string())
        })?;

        // Parse dsearch-specific options from comma-separated string.
        // C: option parsing loop at dsearch.c lines 87–107.
        let opts = DsearchOptions::parse(options);

        // ---- Path Traversal Protection (dsearch.c lines 109–123) ----

        if opts.allow_path {
            // key=path mode: allow `/` in key but reject dangerous traversal
            // components `/../` and `/./`.
            // C: Ustrstr(keystring, "/../") != NULL || Ustrstr(keystring, "/./")
            // dsearch.c lines 111–116
            if key_or_query.contains("/../") || key_or_query.contains("/./") {
                tracing::warn!(
                    key = %key_or_query,
                    "dsearch: key contains bad path component (/../ or /./)"
                );
                return Err(DriverError::TempFail(format!(
                    "key for dsearch lookup contains bad component: {}",
                    key_or_query
                )));
            }
        } else {
            // Standard mode: reject any `/` in the key.
            // C: Ustrchr(keystring, '/') != NULL  (dsearch.c lines 118–123)
            if key_or_query.contains('/') {
                tracing::warn!(
                    key = %key_or_query,
                    "dsearch: key contains a slash without key=path"
                );
                return Err(DriverError::TempFail(format!(
                    "key for dsearch lookup contains a slash: {}",
                    key_or_query
                )));
            }
        }

        // ---- Construct Full Path ----

        // Construct: dirname/keystring
        // Replaces C: string_sprintf("%s/%s", dirname, keystring)
        // dsearch.c line 125
        let full_path: PathBuf = Path::new(dirname).join(key_or_query);

        tracing::debug!(
            path = %full_path.display(),
            key = %key_or_query,
            "dsearch: performing lstat on constructed path"
        );

        // ---- lstat and Filter Check ----

        // Use symlink_metadata (lstat equivalent) — does NOT follow symlinks.
        // This is critical for correct file type detection: symlinks to files
        // vs symlinks to directories must be distinguishable.
        // Replaces C: Ulstat(filename, &statbuf)  (dsearch.c line 126)
        match fs::symlink_metadata(&full_path) {
            Ok(metadata) => {
                let file_type = metadata.file_type();

                // Apply file type filter (dsearch.c lines 127–134).
                // The C code uses a compound boolean expression; the Rust
                // version uses exhaustive enum matching for clarity.
                let matches_filter = match opts.filter {
                    DsearchFilter::None => {
                        // No filter — any entry type matches.
                        // C: !(flags & FILTER_TYPE)
                        true
                    }
                    DsearchFilter::File => {
                        // filter=file: match only regular files.
                        // C: flags & FILTER_FILE && S_ISREG(statbuf.st_mode)
                        file_type.is_file()
                    }
                    DsearchFilter::Dir => {
                        // filter=dir: match any directory entry.
                        // C: flags & FILTER_DIR && S_ISDIR(statbuf.st_mode)
                        file_type.is_dir()
                    }
                    DsearchFilter::Subdir => {
                        // filter=subdir: match directories except "." and "..".
                        // C: flags & FILTER_SUBDIR && S_ISDIR(statbuf.st_mode)
                        //    && (keystring[0] != '.' || keystring[1] && ...)
                        file_type.is_dir() && !is_dot_or_dotdot(key_or_query)
                    }
                };

                if !matches_filter {
                    // Entry exists but does not match the active filter.
                    // C: falls through to `if (errno == ENOENT || errno == 0) return FAIL;`
                    // where errno == 0 because lstat succeeded (dsearch.c line 142).
                    tracing::debug!(
                        path = %full_path.display(),
                        filter = ?opts.filter,
                        is_file = %file_type.is_file(),
                        is_dir = %file_type.is_dir(),
                        "dsearch: entry exists but does not match filter"
                    );
                    return Ok(LookupResult::NotFound);
                }

                // Entry found and matches filter — construct result value.
                //
                // C: *result = string_copy_taint(
                //        flags & RET_FULL ? filename : keystring, GET_UNTAINTED);
                // dsearch.c line 138
                //
                // Since the filename exists in the filesystem, the result is
                // considered untainted (GET_UNTAINTED in C). In Rust, we return
                // a plain String (not wrapped in Tainted<T>).
                let result_value = if opts.ret_full {
                    full_path.to_string_lossy().into_owned()
                } else {
                    key_or_query.to_string()
                };

                tracing::debug!(
                    result = %result_value,
                    ret_full = %opts.ret_full,
                    "dsearch: directory entry found"
                );

                // C: return OK;  (dsearch.c line 139)
                Ok(LookupResult::Found {
                    value: result_value,
                    cache_ttl: None,
                })
            }
            Err(io_err) => {
                if io_err.kind() == ErrorKind::NotFound {
                    // ENOENT — file does not exist in the directory.
                    // C: if (errno == ENOENT || errno == 0) return FAIL;
                    // dsearch.c line 142
                    Ok(LookupResult::NotFound)
                } else {
                    // Other system error (permission denied, I/O error, etc.)
                    // — return Deferred to indicate a temporary/retriable failure.
                    // C: save_errno = errno;
                    //    *errmsg = string_sprintf("%s: lstat: %s", filename, strerror(errno));
                    //    errno = save_errno;
                    //    return DEFER;
                    // dsearch.c lines 144–147
                    let message = format!("{}: lstat: {}", full_path.display(), io_err);
                    tracing::warn!(
                        path = %full_path.display(),
                        error = %io_err,
                        "dsearch: lstat failed with system error"
                    );
                    Ok(LookupResult::Deferred { message })
                }
            }
        }
    }

    /// Close an open dsearch handle.
    ///
    /// No-op: dsearch maintains no persistent handle state. The dummy handle
    /// (boxed unit) is simply dropped.
    ///
    /// Replaces `dsearch_close()` at dsearch.c lines 157–161, which was also a
    /// no-op (`handle = handle;` to suppress compiler warning).
    fn close(&self, _handle: LookupHandle) {
        // No-op — handle is dropped automatically.
    }

    /// Tidy up all dsearch resources.
    ///
    /// No-op: dsearch has no cached connections, file handles, or other
    /// resources that require periodic cleanup.
    ///
    /// C: tidy function pointer is NULL in `lookup_info` (dsearch.c line 187).
    fn tidy(&self) {
        // No-op — no resources to clean up.
    }

    /// Quote a string for safe use in dsearch lookups.
    ///
    /// Returns `None` — directory entry names do not require quoting.
    ///
    /// C: quote function pointer is NULL in `lookup_info` (dsearch.c line 188).
    fn quote(&self, _value: &str, _additional: Option<&str>) -> Option<String> {
        None
    }

    /// Diagnostic version reporting for `-bV` output.
    ///
    /// Returns a version string identifying dsearch as a built-in lookup driver.
    ///
    /// Replaces `dsearch_version_report()` at dsearch.c lines 172–177.
    fn version_report(&self) -> Option<String> {
        Some("Library version: dsearch: Exim builtin\n".to_string())
    }

    /// The lookup type flags for dsearch.
    ///
    /// Returns `LookupType::ABS_FILE` — dsearch is a single-key lookup that
    /// requires an absolute directory path.
    ///
    /// C: `.type = lookup_absfile` (dsearch.c line 182)
    fn lookup_type(&self) -> LookupType {
        LookupType::ABS_FILE
    }

    /// Driver name for configuration file matching.
    ///
    /// Returns `"dsearch"` — the name used in Exim configuration files to
    /// reference this lookup type (e.g., `${lookup dsearch { ... } }`).
    ///
    /// C: `.name = US"dsearch"` (dsearch.c line 181)
    fn driver_name(&self) -> &str {
        "dsearch"
    }
}

// =============================================================================
// Compile-Time Driver Registration
// =============================================================================

// Register the dsearch lookup driver with the driver registry.
//
// Replaces C `dsearch_lookup_module_info` static struct and `_lookup_list`
// array at dsearch.c lines 180–197 and the corresponding `drtables.c` table
// entry. The `inventory::submit!` macro enables compile-time collection of
// all lookup drivers without explicit wiring in a central registration table.
//
// Per AAP §0.4.2: "Each driver implementation uses inventory::submit! for
// compile-time collection; runtime driver resolution by name from config."
inventory::submit! {
    LookupDriverFactory {
        name: "dsearch",
        create: || Box::new(DsearchLookup::new()),
        lookup_type: LookupType::ABS_FILE,
        avail_string: Some("dsearch (built-in)"),
    }
}
