//! File credential and type validation for file-backed lookup drivers.
//!
//! This module provides filesystem security validation used by all file-backed
//! lookup backends (CDB, lsearch, JSON, DBM, dsearch, etc.) before opening
//! data files for query operations.
//!
//! # Replaces
//!
//! `src/src/lookups/lf_check_file.c` (~115 lines) — the C `lf_check_file()`
//! function that performed `stat()`/`fstat()` validation of file type, forbidden
//! permission mode bits, owner UID allowlists, and owner GID allowlists.
//!
//! # Checks Performed
//!
//! 1. **stat/fstat** — Obtains file metadata via path or open file descriptor.
//! 2. **File type** — Verifies the file is a regular file or directory as expected.
//! 3. **Mode mask** — Ensures no forbidden permission bits are set (e.g., group/other
//!    write).
//! 4. **Owner UID** — If an allowlist is provided, verifies the file owner UID is in
//!    the list.
//! 5. **Owner GID** — If an allowlist is provided, verifies the file group GID is in
//!    the list.
//!
//! # Error Types
//!
//! The [`CheckFileError`] enum replaces the C `ERRNO_BADUGID`, `ERRNO_NOTREGULAR`,
//! `ERRNO_NOTDIRECTORY`, and `ERRNO_BADMODE` errno side-effects with proper Rust
//! error variants. Error message format strings match the original C
//! `string_sprintf` patterns for log parsing compatibility.
//!
//! # Consumers
//!
//! - `cdb.rs` — CDB file security check
//! - `lsearch.rs` — lsearch file security check
//! - `json.rs` — JSON file security check
//! - `dbmdb.rs` — DBM file security check
//! - `dsearch.rs` — directory entry search security check

use std::fs::{self, File, Metadata};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

/// Specifies the expected file type for validation.
///
/// Replaces the C `S_IFREG` / `S_IFDIR` integer constants passed as `s_type`
/// to `lf_check_file()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedFileType {
    /// The target must be a regular file (`S_IFREG` in C).
    Regular,
    /// The target must be a directory (`S_IFDIR` in C).
    Directory,
}

/// Specifies the target to validate — either an already-open file or a
/// filesystem path.
///
/// Replaces the C dual-parameter pattern where `fd >= 0` triggers `fstat()`
/// and `fd < 0` triggers `stat()` on the `filename` parameter.
pub enum CheckFileTarget<'a> {
    /// An open file reference — metadata is obtained via `File::metadata()`
    /// (equivalent to `fstat()`).
    Fd(&'a File),
    /// A filesystem path — metadata is obtained via `std::fs::metadata()`
    /// (equivalent to `stat()`).
    Path(&'a Path),
}

/// Errors returned by [`check_file`] when a validation check fails.
///
/// Each variant corresponds to a specific failure mode from the original C
/// `lf_check_file()` function. The `#[error(...)]` format strings match the
/// C `string_sprintf` patterns to preserve log parsing compatibility
/// (AAP §0.7.1).
#[derive(Debug, thiserror::Error)]
pub enum CheckFileError {
    /// `stat()` or `fstat()` system call failed.
    ///
    /// Replaces C return value `-1` with preserved errno. The `source` field
    /// wraps the underlying `std::io::Error` containing the OS error code.
    #[error("{filename}: stat failed: {source}")]
    StatFailed {
        /// Display name of the file that failed to stat.
        filename: String,
        /// Underlying OS error from `stat()` / `fstat()`.
        source: std::io::Error,
    },

    /// The file is not a regular file when one was expected.
    ///
    /// Replaces C `ERRNO_NOTREGULAR` errno side-effect.
    #[error("{filename} is not a regular file ({lookup_type} lookup)")]
    NotRegular {
        /// Display name of the file.
        filename: String,
        /// Name of the lookup type (e.g., "cdb", "lsearch").
        lookup_type: String,
    },

    /// The path is not a directory when one was expected.
    ///
    /// Replaces C `ERRNO_NOTDIRECTORY` errno side-effect.
    #[error("{filename} is not a directory ({lookup_type} lookup)")]
    NotDirectory {
        /// Display name of the path.
        filename: String,
        /// Name of the lookup type (e.g., "dsearch").
        lookup_type: String,
    },

    /// Forbidden permission bits are set on the file.
    ///
    /// Replaces C `ERRNO_BADMODE` errno side-effect. The `actual_mode` and
    /// `forbidden_bits` fields are formatted in octal to match the C
    /// `"%.4o"` format specifier.
    #[error("{filename} ({lookup_type} lookup): file mode {actual_mode:04o} should not contain {forbidden_bits:04o}")]
    BadMode {
        /// Display name of the file.
        filename: String,
        /// Name of the lookup type.
        lookup_type: String,
        /// The file's actual permission mode bits (masked to `0o7777`).
        actual_mode: u32,
        /// The subset of forbidden bits that were found set.
        forbidden_bits: u32,
    },

    /// The file owner UID is not in the allowed owners list.
    ///
    /// Replaces C `ERRNO_BADUGID` errno side-effect for UID mismatch.
    #[error("{filename} ({lookup_type} lookup): file has wrong owner")]
    BadOwner {
        /// Display name of the file.
        filename: String,
        /// Name of the lookup type.
        lookup_type: String,
    },

    /// The file group GID is not in the allowed groups list.
    ///
    /// Replaces C `ERRNO_BADUGID` errno side-effect for GID mismatch.
    #[error("{filename} ({lookup_type} lookup): file has wrong group")]
    BadGroup {
        /// Display name of the file.
        filename: String,
        /// Name of the lookup type.
        lookup_type: String,
    },
}

/// Validates file credentials (type, permissions, ownership) for a lookup
/// data file or directory.
///
/// This is the Rust equivalent of the C `lf_check_file()` function from
/// `src/src/lookups/lf_check_file.c`. It performs five sequential checks:
///
/// 1. Obtain file metadata via `stat()` (path) or `fstat()` (open file).
/// 2. Verify the file type matches `expected_type`.
/// 3. Verify no forbidden permission bits from `modemask` are set.
/// 4. If `owners` is provided, verify the file UID is in the allowlist.
/// 5. If `owngroups` is provided, verify the file GID is in the allowlist.
///
/// # Parameters
///
/// - `file` — The validation target: either a reference to an open
///   [`std::fs::File`] or a [`Path`].
/// - `expected_type` — Whether the target should be a regular file or a
///   directory.
/// - `modemask` — A bitmask of permission bits that must NOT be set. For
///   example, `0o022` forbids group-write and other-write.
/// - `owners` — An optional slice of allowed UIDs. If `Some`, the file's
///   owner UID must appear in this slice.
/// - `owngroups` — An optional slice of allowed GIDs. If `Some`, the file's
///   group GID must appear in this slice.
/// - `lookup_type` — The name of the calling lookup backend (e.g., `"cdb"`,
///   `"lsearch"`), used in error messages.
/// - `filename` — The display name of the file for error messages.
///
/// # Returns
///
/// - `Ok(())` if all checks pass.
/// - `Err(CheckFileError)` with the specific failure variant.
///
/// # Platform Notes
///
/// Mode, UID, and GID checks use Unix-specific APIs from
/// `std::os::unix::fs::{MetadataExt, PermissionsExt}` and are gated behind
/// `#[cfg(unix)]`. On non-Unix platforms these checks are skipped (Exim is
/// a Unix-only MTA).
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use exim_lookups::helpers::check_file::{
///     check_file, CheckFileTarget, ExpectedFileType,
/// };
///
/// // Validate a CDB file: must be regular, no group/other write, any owner
/// let result = check_file(
///     CheckFileTarget::Path(Path::new("/etc/mail/aliases.cdb")),
///     ExpectedFileType::Regular,
///     0o022,
///     None,
///     None,
///     "cdb",
///     "/etc/mail/aliases.cdb",
/// );
/// ```
pub fn check_file(
    file: CheckFileTarget<'_>,
    expected_type: ExpectedFileType,
    modemask: u32,
    owners: Option<&[u32]>,
    owngroups: Option<&[u32]>,
    lookup_type: &str,
    filename: &str,
) -> Result<(), CheckFileError> {
    // Step 1: Obtain file metadata (replaces C stat/fstat at lines 49–55).
    let metadata = obtain_metadata(&file, filename)?;

    // Step 2: Validate file type (replaces C lines 57–72).
    check_file_type(&metadata, expected_type, lookup_type, filename)?;

    // Step 3: Validate permission mode bits (replaces C lines 74–81).
    // Step 4: Validate owner UID (replaces C lines 83–95).
    // Step 5: Validate owner GID (replaces C lines 97–109).
    // These checks are Unix-only; on non-Unix platforms they are skipped.
    #[cfg(unix)]
    {
        check_mode(&metadata, modemask, lookup_type, filename)?;
        check_owner(&metadata, owners, lookup_type, filename)?;
        check_group(&metadata, owngroups, lookup_type, filename)?;
    }

    // Silence unused-variable warnings on non-Unix platforms where the
    // mode/owner/group parameters are not consumed by any check function.
    #[cfg(not(unix))]
    {
        let _ = modemask;
        let _ = owners;
        let _ = owngroups;
    }

    tracing::debug!(
        filename = %filename,
        lookup_type = %lookup_type,
        "file credential check passed"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helper functions
// ---------------------------------------------------------------------------

/// Obtains file [`Metadata`] from either a path or an open file descriptor.
///
/// Replaces C lines 49–55:
/// ```c
/// if ((fd < 0 ? Ustat(filename, &statbuf) : fstat(fd, &statbuf)) != 0) { ... }
/// ```
fn obtain_metadata(file: &CheckFileTarget<'_>, filename: &str) -> Result<Metadata, CheckFileError> {
    match file {
        CheckFileTarget::Path(path) => {
            fs::metadata(path).map_err(|source| CheckFileError::StatFailed {
                filename: filename.to_owned(),
                source,
            })
        }
        CheckFileTarget::Fd(f) => f.metadata().map_err(|source| CheckFileError::StatFailed {
            filename: filename.to_owned(),
            source,
        }),
    }
}

/// Validates the file type against the expected type.
///
/// Replaces C lines 57–72:
/// ```c
/// if ((statbuf.st_mode & S_IFMT) != s_type) { ... }
/// ```
fn check_file_type(
    metadata: &Metadata,
    expected_type: ExpectedFileType,
    lookup_type: &str,
    filename: &str,
) -> Result<(), CheckFileError> {
    let file_type = metadata.file_type();

    let type_ok = match expected_type {
        ExpectedFileType::Regular => file_type.is_file(),
        ExpectedFileType::Directory => file_type.is_dir(),
    };

    if type_ok {
        tracing::debug!(
            filename = %filename,
            expected = ?expected_type,
            "file type check passed"
        );
        return Ok(());
    }

    match expected_type {
        ExpectedFileType::Regular => {
            tracing::debug!(
                filename = %filename,
                lookup_type = %lookup_type,
                "file type check failed: not a regular file"
            );
            Err(CheckFileError::NotRegular {
                filename: filename.to_owned(),
                lookup_type: lookup_type.to_owned(),
            })
        }
        ExpectedFileType::Directory => {
            tracing::debug!(
                filename = %filename,
                lookup_type = %lookup_type,
                "file type check failed: not a directory"
            );
            Err(CheckFileError::NotDirectory {
                filename: filename.to_owned(),
                lookup_type: lookup_type.to_owned(),
            })
        }
    }
}

/// Validates that no forbidden permission bits from `modemask` are set.
///
/// Replaces C lines 74–81:
/// ```c
/// if ((statbuf.st_mode & modemask) != 0) { ... }
/// ```
///
/// Uses `std::os::unix::fs::PermissionsExt::mode()` to read the raw Unix
/// permission bits. Only the lower 12 bits (`0o7777`) representing the
/// standard permission/setuid/setgid/sticky bits are considered.
#[cfg(unix)]
fn check_mode(
    metadata: &Metadata,
    modemask: u32,
    lookup_type: &str,
    filename: &str,
) -> Result<(), CheckFileError> {
    let raw_mode = metadata.permissions().mode();
    // Extract permission bits only (rwxrwxrwx + setuid/setgid/sticky).
    let mode = raw_mode & 0o7777;
    let forbidden_bits = mode & modemask;

    tracing::debug!(
        filename = %filename,
        mode = format_args!("{:04o}", mode),
        modemask = format_args!("{:04o}", modemask),
        forbidden_bits = format_args!("{:04o}", forbidden_bits),
        "mode mask check"
    );

    if forbidden_bits != 0 {
        return Err(CheckFileError::BadMode {
            filename: filename.to_owned(),
            lookup_type: lookup_type.to_owned(),
            actual_mode: mode,
            forbidden_bits,
        });
    }

    Ok(())
}

/// Validates the file owner UID against an optional allowlist.
///
/// Replaces C lines 83–95:
/// ```c
/// if (owners) {
///     BOOL uid_ok = FALSE;
///     for (int i = 1; i <= (int)owners[0]; i++)
///         if (owners[i] == statbuf.st_uid) { uid_ok = TRUE; break; }
///     if (!uid_ok) { ... }
/// }
/// ```
///
/// Unlike the C version which stores the count in `owners[0]`, the Rust
/// version receives a plain slice containing only the allowed UIDs.
#[cfg(unix)]
fn check_owner(
    metadata: &Metadata,
    owners: Option<&[u32]>,
    lookup_type: &str,
    filename: &str,
) -> Result<(), CheckFileError> {
    let allowed = match owners {
        Some(list) => list,
        None => return Ok(()),
    };

    let file_uid = metadata.uid();

    let uid_ok = allowed.contains(&file_uid);

    tracing::debug!(
        filename = %filename,
        file_uid = file_uid,
        allowed_uids = ?allowed,
        uid_ok = uid_ok,
        "owner UID check"
    );

    if !uid_ok {
        return Err(CheckFileError::BadOwner {
            filename: filename.to_owned(),
            lookup_type: lookup_type.to_owned(),
        });
    }

    Ok(())
}

/// Validates the file group GID against an optional allowlist.
///
/// Replaces C lines 97–109:
/// ```c
/// if (owngroups) {
///     BOOL gid_ok = FALSE;
///     for (int i = 1; i <= (int)owngroups[0]; i++)
///         if (owngroups[i] == statbuf.st_gid) { gid_ok = TRUE; break; }
///     if (!gid_ok) { ... }
/// }
/// ```
///
/// Unlike the C version which stores the count in `owngroups[0]`, the Rust
/// version receives a plain slice containing only the allowed GIDs.
#[cfg(unix)]
fn check_group(
    metadata: &Metadata,
    owngroups: Option<&[u32]>,
    lookup_type: &str,
    filename: &str,
) -> Result<(), CheckFileError> {
    let allowed = match owngroups {
        Some(list) => list,
        None => return Ok(()),
    };

    let file_gid = metadata.gid();

    let gid_ok = allowed.contains(&file_gid);

    tracing::debug!(
        filename = %filename,
        file_gid = file_gid,
        allowed_gids = ?allowed,
        gid_ok = gid_ok,
        "owner GID check"
    );

    if !gid_ok {
        return Err(CheckFileError::BadGroup {
            filename: filename.to_owned(),
            lookup_type: lookup_type.to_owned(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Helper: create a temporary file and return its path.
    fn create_temp_file(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("exim_check_file_tests");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join(name);
        let mut f = File::create(&path).expect("create temp file");
        f.write_all(b"test content").expect("write temp file");
        path
    }

    /// Helper: create a temporary directory and return its path.
    fn create_temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir()
            .join("exim_check_file_tests")
            .join(name);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn test_regular_file_passes() {
        let path = create_temp_file("test_regular.txt");
        let result = check_file(
            CheckFileTarget::Path(&path),
            ExpectedFileType::Regular,
            0,
            None,
            None,
            "test",
            path.to_str().unwrap(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_directory_passes() {
        let path = create_temp_dir("test_dir_ok");
        let result = check_file(
            CheckFileTarget::Path(&path),
            ExpectedFileType::Directory,
            0,
            None,
            None,
            "test",
            path.to_str().unwrap(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_stat_failed_nonexistent() {
        let path = Path::new("/nonexistent/path/to/file.cdb");
        let result = check_file(
            CheckFileTarget::Path(path),
            ExpectedFileType::Regular,
            0,
            None,
            None,
            "cdb",
            "/nonexistent/path/to/file.cdb",
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        match &err {
            CheckFileError::StatFailed { filename, .. } => {
                assert_eq!(filename, "/nonexistent/path/to/file.cdb");
            }
            other => panic!("expected StatFailed, got: {other}"),
        }
        // Verify the Display output matches the expected format.
        let msg = err.to_string();
        assert!(msg.contains("/nonexistent/path/to/file.cdb: stat failed:"));
    }

    #[test]
    fn test_not_regular_file() {
        let path = create_temp_dir("test_not_regular");
        let result = check_file(
            CheckFileTarget::Path(&path),
            ExpectedFileType::Regular,
            0,
            None,
            None,
            "lsearch",
            path.to_str().unwrap(),
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            CheckFileError::NotRegular { lookup_type, .. } => {
                assert_eq!(lookup_type, "lsearch");
            }
            other => panic!("expected NotRegular, got: {other}"),
        }
    }

    #[test]
    fn test_not_directory() {
        let path = create_temp_file("test_not_dir.txt");
        let result = check_file(
            CheckFileTarget::Path(&path),
            ExpectedFileType::Directory,
            0,
            None,
            None,
            "dsearch",
            path.to_str().unwrap(),
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            CheckFileError::NotDirectory { lookup_type, .. } => {
                assert_eq!(lookup_type, "dsearch");
            }
            other => panic!("expected NotDirectory, got: {other}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_bad_mode() {
        use std::os::unix::fs::PermissionsExt;
        let path = create_temp_file("test_bad_mode.txt");
        // Set group-write + other-write bits (0o022 mask).
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
            .expect("set permissions");
        let result = check_file(
            CheckFileTarget::Path(&path),
            ExpectedFileType::Regular,
            0o022,
            None,
            None,
            "cdb",
            path.to_str().unwrap(),
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            CheckFileError::BadMode {
                actual_mode,
                forbidden_bits,
                ..
            } => {
                assert_eq!(actual_mode, 0o666);
                assert_eq!(forbidden_bits, 0o022);
            }
            other => panic!("expected BadMode, got: {other}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_mode_ok_when_no_forbidden_bits() {
        use std::os::unix::fs::PermissionsExt;
        let path = create_temp_file("test_mode_ok.txt");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("set permissions");
        let result = check_file(
            CheckFileTarget::Path(&path),
            ExpectedFileType::Regular,
            0o022,
            None,
            None,
            "cdb",
            path.to_str().unwrap(),
        );
        assert!(result.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_bad_owner() {
        let path = create_temp_file("test_bad_owner.txt");
        // Use a UID that definitely doesn't match the file's owner.
        let result = check_file(
            CheckFileTarget::Path(&path),
            ExpectedFileType::Regular,
            0,
            Some(&[99999]),
            None,
            "lsearch",
            path.to_str().unwrap(),
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            CheckFileError::BadOwner { .. } => {}
            other => panic!("expected BadOwner, got: {other}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_owner_in_allowlist() {
        let path = create_temp_file("test_owner_ok.txt");
        let meta = std::fs::metadata(&path).expect("metadata");
        let uid = meta.uid();
        let result = check_file(
            CheckFileTarget::Path(&path),
            ExpectedFileType::Regular,
            0,
            Some(&[99999, uid]),
            None,
            "cdb",
            path.to_str().unwrap(),
        );
        assert!(result.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_bad_group() {
        let path = create_temp_file("test_bad_group.txt");
        let result = check_file(
            CheckFileTarget::Path(&path),
            ExpectedFileType::Regular,
            0,
            None,
            Some(&[99999]),
            "json",
            path.to_str().unwrap(),
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            CheckFileError::BadGroup { .. } => {}
            other => panic!("expected BadGroup, got: {other}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_group_in_allowlist() {
        let path = create_temp_file("test_group_ok.txt");
        let meta = std::fs::metadata(&path).expect("metadata");
        let gid = meta.gid();
        let result = check_file(
            CheckFileTarget::Path(&path),
            ExpectedFileType::Regular,
            0,
            None,
            Some(&[99999, gid]),
            "json",
            path.to_str().unwrap(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_fd_target_regular_file() {
        let path = create_temp_file("test_fd_target.txt");
        let f = File::open(&path).expect("open file");
        let result = check_file(
            CheckFileTarget::Fd(&f),
            ExpectedFileType::Regular,
            0,
            None,
            None,
            "cdb",
            path.to_str().unwrap(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_error_display_format() {
        // Verify that error Display output matches the C string_sprintf patterns.
        let err = CheckFileError::NotRegular {
            filename: "/tmp/data".to_owned(),
            lookup_type: "cdb".to_owned(),
        };
        assert_eq!(
            err.to_string(),
            "/tmp/data is not a regular file (cdb lookup)"
        );

        let err = CheckFileError::NotDirectory {
            filename: "/tmp/data".to_owned(),
            lookup_type: "dsearch".to_owned(),
        };
        assert_eq!(
            err.to_string(),
            "/tmp/data is not a directory (dsearch lookup)"
        );

        let err = CheckFileError::BadMode {
            filename: "/tmp/data".to_owned(),
            lookup_type: "cdb".to_owned(),
            actual_mode: 0o666,
            forbidden_bits: 0o022,
        };
        assert_eq!(
            err.to_string(),
            "/tmp/data (cdb lookup): file mode 0666 should not contain 0022"
        );

        let err = CheckFileError::BadOwner {
            filename: "/tmp/data".to_owned(),
            lookup_type: "lsearch".to_owned(),
        };
        assert_eq!(
            err.to_string(),
            "/tmp/data (lsearch lookup): file has wrong owner"
        );

        let err = CheckFileError::BadGroup {
            filename: "/tmp/data".to_owned(),
            lookup_type: "json".to_owned(),
        };
        assert_eq!(
            err.to_string(),
            "/tmp/data (json lookup): file has wrong group"
        );
    }
}
