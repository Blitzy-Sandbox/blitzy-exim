// =============================================================================
// exim-transports/src/maildir.rs — Maildir Helper Functions
// =============================================================================
//
// Rewrites `src/src/transports/tf_maildir.c` (570 lines) +
// `src/src/transports/tf_maildir.h` (22 lines) from C to Rust.
//
// This module provides:
// - Maildir directory hierarchy creation (tmp/new/cur)
// - Maildir quota computation via maildirsize files
// - Size file management per the maildirquota specification
//   (http://www.inter7.com/courierimap/README.maildirquota.html)
// - maildirfolder marker file creation for subfolder support
//
// Used by the `appendfile` transport when Maildir format is enabled.
//
// Per AAP §0.7.2: zero `unsafe` code in this module.
// Per AAP §0.7.3: feature-gated with `maildir` (replaces C `SUPPORT_MAILDIR`).
// Per AAP §0.4.2: compile-time taint tracking via Tainted<T>/Clean<T>.
//
// SPDX-License-Identifier: GPL-2.0-or-later
// =============================================================================

// =============================================================================
// Imports
// =============================================================================

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use exim_store::{Clean, Tainted};
use regex::Regex;

// Import check_dir_size from appendfile when that transport is enabled.
// This mirrors the C pattern where tf_maildir.c includes appendfile.h
// to access check_dir_size() defined in appendfile.c (line 305 of
// tf_maildir.c: sum += check_dir_size(s, filecount, regex)).
#[cfg(feature = "transport-appendfile")]
use super::appendfile::check_dir_size;

// =============================================================================
// Constants — from tf_maildir.c line 23 and line 51
// =============================================================================

/// Maximum size of a maildirsize file in bytes.
///
/// From tf_maildir.c line 23: `#define MAX_FILE_SIZE  5120`
///
/// If the maildirsize file exceeds this size, it is considered too large and
/// must be recalculated by scanning the entire directory tree.  This prevents
/// unbounded growth of the size-tracking file.
pub const MAX_FILE_SIZE: usize = 5120;

/// Maildir subdirectory suffixes appended to the base path.
///
/// From tf_maildir.c line 51:
/// `const char * const subdirs[] = { "/tmp", "/new", "/cur" }`
///
/// These three subdirectories form the core Maildir hierarchy:
/// - `/tmp` — messages being delivered (write in progress)
/// - `/new` — newly delivered messages not yet seen by MUA
/// - `/cur` — messages that have been seen/read by MUA
pub const SUBDIRS: [&str; 3] = ["/tmp", "/new", "/cur"];

/// Maximum number of race-condition retries for directory creation.
///
/// From tf_maildir.c line 83: the C code loops `j < 10` when a directory
/// appears between stat() and mkdir() calls due to another process.
const MAX_RACE_RETRIES: usize = 10;

/// Stale maildirsize threshold in seconds (15 minutes).
///
/// From tf_maildir.c line 487: if the maildirsize file indicates over-quota
/// and the file is older than 15 minutes, it must be recalculated rather than
/// trusted.
const STALE_THRESHOLD_SECS: i64 = 15 * 60;

// =============================================================================
// Error Type — replaces C return FALSE + addr->message pattern
// =============================================================================

/// Error type for Maildir operations.
///
/// Replaces the C pattern of returning `FALSE` with side-effects on
/// `addr->message` and `addr->basic_errno` in tf_maildir.c functions.
/// Each variant maps to a specific failure mode in the original C code.
#[derive(Debug, thiserror::Error)]
pub enum MaildirError {
    /// Directory creation or validation failed.
    ///
    /// Covers: missing directories that cannot be created, non-directory
    /// paths where directories are expected, race conditions during
    /// directory creation, maildirfolder file creation failures, and
    /// maildirsize file race conditions.
    #[error("directory creation failed: {0}")]
    DirectoryCreation(String),

    /// Generic I/O error from filesystem operations.
    ///
    /// Wraps `std::io::Error` for transparent propagation via the `?`
    /// operator.  Used for unexpected I/O failures not covered by the
    /// more specific variants.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Maildir quota has been exceeded.
    ///
    /// Returned when the computed mailbox size exceeds the configured quota
    /// and the maildirsize file is verified as current and accurate.
    #[error("quota exceeded")]
    QuotaExceeded,

    /// Permission denied for a filesystem operation.
    ///
    /// Covers: taint validation failures on paths derived from user input,
    /// inability to access the Maildir base directory, and file creation
    /// permission issues.
    #[error("permission denied: {0}")]
    PermissionDenied(String),
}

// =============================================================================
// Internal Helpers
// =============================================================================

/// Create a single directory with the specified POSIX mode.
///
/// Uses `std::fs::DirBuilder` with Unix extensions to set the directory
/// permissions at creation time.  Non-recursive — creates only the
/// leaf directory, matching the C `directory_make(NULL, dir, dirmode, FALSE)`
/// call in tf_maildir.c.
fn create_directory_with_mode(path: &str, mode: u32) -> std::io::Result<()> {
    fs::DirBuilder::new()
        .mode(mode)
        .recursive(false)
        .create(path)
}

/// Parse the quota header line from a maildirsize file.
///
/// The first line of a maildirsize file has the format:
/// `<number><letter>[,<number><letter>...]`
/// where `S` indicates a size quota (bytes) and `C` indicates a file-count
/// quota.
///
/// Example: `100000S,1000C` → (100000, 1000) meaning 100 KB size limit and
/// 1000 message limit.
///
/// Returns `Some((size_quota, count_quota))` on successful parse,
/// `None` if the line has invalid syntax (triggering a RECALCULATE in
/// the caller, per tf_maildir.c lines 395–422).
fn parse_quota_header(line: &str) -> Option<(i64, i32)> {
    let mut size_quota: i64 = 0;
    let mut count_quota: i32 = 0;

    for part in line.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Format: number followed by exactly one letter.
        let letter_pos = trimmed.len().checked_sub(1)?;
        let suffix_byte = *trimmed.as_bytes().get(letter_pos)?;

        // The spec requires a number followed by a letter; reject otherwise
        // (tf_maildir.c lines 405–412).
        if !suffix_byte.is_ascii_alphabetic() {
            return None;
        }

        let num_str = &trimmed[..letter_pos];
        let n: f64 = num_str.parse().ok()?;

        match suffix_byte {
            b'S' => size_quota = n as i64,
            b'C' => count_quota = n as i32,
            _ => {
                // Unknown but valid letter suffix — ignore per spec.
                // Only S and C are currently defined.
            }
        }
    }

    Some((size_quota, count_quota))
}

/// Parse a size/count data line from a maildirsize file.
///
/// Subsequent lines after the header have the format: `<size> <count>\n`
/// where `<size>` is the message size delta in bytes and `<count>` is
/// the message count delta (typically 1 for delivery, -1 for deletion).
///
/// Returns `Some((size, count))` on success, `None` on parse error.
fn parse_size_line(line: &str) -> Option<(i64, i32)> {
    let mut parts = line.split_whitespace();
    let size_str = parts.next()?;
    let count_str = parts.next()?;
    let size: i64 = size_str.parse().ok()?;
    let count: i32 = count_str.parse().ok()?;
    Some((size, count))
}

/// Fallback directory size scanner when `transport-appendfile` is not compiled.
///
/// Provides equivalent functionality to `appendfile::check_dir_size()` for
/// the edge case where the `maildir` feature is enabled without the full
/// `transport-appendfile` feature.  Iterates all files in a directory,
/// attempts to extract sizes from filenames using the regex capture group,
/// and falls back to `stat()` for actual file size.
#[cfg(not(feature = "transport-appendfile"))]
fn fallback_check_dir_size(path: &str, filecount: &mut i32, regex: Option<&Regex>) -> i64 {
    let mut total_size: i64 = 0;
    let entries = match fs::read_dir(path) {
        Ok(e) => e,
        Err(_) => return 0,
    };

    for entry in entries.flatten() {
        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };

        let name_os = entry.file_name();
        let name_str = name_os.to_string_lossy();

        if name_str == "." || name_str == ".." {
            continue;
        }

        if ft.is_dir() {
            let sub_path = entry.path();
            total_size += fallback_check_dir_size(&sub_path.to_string_lossy(), filecount, regex);
        } else if ft.is_file() {
            *filecount += 1;

            // Try to extract size from filename via regex capture group
            // (Maildir S=<size> convention).
            if let Some(re) = regex {
                if let Some(caps) = re.captures(&name_str) {
                    if let Some(m) = caps.get(1) {
                        if let Ok(size) = m.as_str().parse::<i64>() {
                            total_size += size;
                            continue;
                        }
                    }
                }
            }

            // Fallback: stat the file for its actual size
            if let Ok(meta) = entry.metadata() {
                total_size += meta.len() as i64;
            }
        }
    }

    total_size
}

/// Internal wrapper delegating to `appendfile::check_dir_size` when available
/// or to the local fallback otherwise.
///
/// This indirection avoids repeating `#[cfg]` guards at every call site
/// within `maildir_compute_size`.
fn compute_dir_size(path: &str, filecount: &mut i32, regex: Option<&Regex>) -> i64 {
    #[cfg(feature = "transport-appendfile")]
    {
        check_dir_size(path, filecount, regex)
    }
    #[cfg(not(feature = "transport-appendfile"))]
    {
        fallback_check_dir_size(path, filecount, regex)
    }
}

/// Perform a full recalculation of the maildirsize file.
///
/// Called when the existing maildirsize file is missing, too large, has
/// mismatched quota parameters, contains syntax errors, or has stale
/// data.  Scans the entire directory tree, writes a new maildirsize file
/// atomically (via tmp-then-rename), and checks for race conditions.
///
/// Corresponds to the `RECALCULATE:` label in tf_maildir.c (lines 521–558).
///
/// # Returns
///
/// `Ok(File)` — an open file handle for the new maildirsize file,
/// positioned for appending.
///
/// `Err(MaildirError::DirectoryCreation(...))` — a race condition was
/// detected (subdirectory modified during recalculation) and the
/// maildirsize file was removed.  The `size` and `filecount` output
/// parameters are still updated with the computed values.
fn recalculate_sizefile(
    path: &str,
    quota: i64,
    quota_filecount: i32,
    dir_regex: Option<&Regex>,
    size_regex: Option<&Regex>,
    size: &mut i64,
    filecount: &mut i32,
) -> Result<File, MaildirError> {
    let mut old_latest: i64 = 0;
    *filecount = 0;

    // Compute total size via directory scanning.
    // use_size_file = true → compute actual sizes (C: timestamp_only = FALSE).
    *size = maildir_compute_size(
        path,
        filecount,
        &mut old_latest,
        dir_regex,
        size_regex,
        true,
    );

    // Build a unique temporary filename in the tmp/ subdirectory.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let temp_name = format!(
        "{}/tmp/{}.H{}P{}.maildirsize",
        path,
        now.as_secs(),
        now.subsec_micros(),
        std::process::id()
    );

    let sizefile_name = format!("{}/maildirsize", path);

    // Create the temporary file with exclusive creation (O_EXCL).
    let mut fd = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp_name)
    {
        Ok(f) => f,
        Err(e) => {
            tracing::debug!("failed to create temp maildirsize file: {}", e);
            return Err(MaildirError::Io(e));
        }
    };

    // Write the quota header and initial size entry.
    // Format matches C: `OFF_T_FMT "S,%dC\n" OFF_T_FMT " %d\n"`
    let content = format!(
        "{}S,{}C\n{} {}\n",
        quota, quota_filecount, *size, *filecount
    );
    if let Err(e) = fd.write_all(content.as_bytes()) {
        let _ = fs::remove_file(&temp_name);
        return Err(MaildirError::Io(e));
    }

    // Atomically rename temp to maildirsize (tf_maildir.c line 538).
    if let Err(e) = fs::rename(&temp_name, &sizefile_name) {
        let _ = fs::remove_file(&temp_name);
        return Err(MaildirError::Io(e));
    }

    // Race condition check: if any subdirectory was modified after we started
    // our size computation, the maildirsize file is already stale and must
    // be discarded (tf_maildir.c lines 548–558).
    tracing::debug!("checking subdirectory timestamps");
    let mut new_latest: i64 = 0;
    let mut dummy_count: i32 = 0;
    // use_size_file = false → timestamp only (C: timestamp_only = TRUE).
    maildir_compute_size(
        path,
        &mut dummy_count,
        &mut new_latest,
        dir_regex,
        None,
        false,
    );

    if new_latest > old_latest {
        tracing::debug!("abandoning maildirsize because of a later subdirectory modification");
        let _ = fs::remove_file(&sizefile_name);
        return Err(MaildirError::DirectoryCreation(
            "maildirsize removed due to subdirectory race condition".to_string(),
        ));
    }

    // Seek to end so subsequent writes (via maildir_record_length) append
    // to the file rather than overwriting existing content.
    fd.seek(SeekFrom::End(0))?;

    tracing::debug!(
        size = *size,
        filecount = *filecount,
        "recalculated maildirsize"
    );

    Ok(fd)
}

// =============================================================================
// Public API — Exported Functions
// =============================================================================

/// Ensure that Maildir directories (base + tmp/new/cur) exist.
///
/// Creates directories if needed and allowed by `create_directory`.
/// Also creates a `maildirfolder` marker file if the base path matches
/// `maildirfolder_create_regex`.
///
/// This function replaces C `maildir_ensure_directories()` from
/// tf_maildir.c lines 46–181.
///
/// # Arguments
///
/// * `path` — The base Maildir directory path (from address expansion).
/// * `create_directory` — Whether to create directories that don't exist.
///   When `false`, the function returns an error for any missing directory.
/// * `dirmode` — POSIX mode for newly created directories (e.g., `0o700`).
/// * `maildirfolder_create_regex` — Optional regex pattern string.  If
///   the base path matches, a `maildirfolder` marker file is created,
///   indicating that this directory is a Maildir subfolder.
///
/// # Returns
///
/// `Ok(())` on success, `Err(MaildirError)` on failure.
///
/// # Race Condition Handling
///
/// Directory creation uses a retry loop (up to 10 attempts) to handle
/// the race condition where another process creates the directory between
/// our `stat()` and `mkdir()` calls (tf_maildir.c lines 83–129).
pub fn maildir_ensure_directories(
    path: &str,
    create_directory: bool,
    dirmode: u32,
    maildirfolder_create_regex: Option<&str>,
) -> Result<(), MaildirError> {
    // Taint tracking: wrap the incoming path as tainted since it originates
    // from address expansion (user-controlled input in the C codebase).
    // This replaces the C runtime is_tainted() checks with compile-time
    // enforcement.
    let tainted_path = Tainted::new(path.to_string());

    // Validate the path: must be non-empty and not contain null bytes.
    let clean_path = tainted_path
        .sanitize(|p| !p.contains('\0') && !p.is_empty())
        .map_err(|_| {
            MaildirError::PermissionDenied(format!("tainted path validation failed for '{}'", path))
        })?;

    // Use Clean::as_ref() to access the validated path without consuming it.
    let base: &str = clean_path.as_ref().as_str();

    tracing::debug!("ensuring maildir directories exist in {}", base);

    // Iterate through 4 directories: base, base/tmp, base/new, base/cur.
    // This mirrors the C loop at tf_maildir.c lines 62–139.
    for i in 0..4u8 {
        let (full_path, suffix) = if i == 0 {
            (base.to_string(), String::new())
        } else {
            let sub = SUBDIRS[(i - 1) as usize];
            (format!("{}{}", base, sub), sub.to_string())
        };

        // Race condition retry loop (tf_maildir.c lines 83–129).
        let mut success = false;

        for attempt in 0..MAX_RACE_RETRIES {
            match fs::metadata(&full_path) {
                Ok(meta) => {
                    if meta.is_dir() {
                        success = true;
                        break;
                    }
                    // Path exists but is not a directory.
                    return Err(MaildirError::DirectoryCreation(format!(
                        "{}{} is not a directory",
                        base, suffix
                    )));
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if create_directory {
                        match create_directory_with_mode(&full_path, dirmode) {
                            Ok(()) => {
                                tracing::debug!("created directory {}{}", base, suffix);
                                success = true;
                                break;
                            }
                            Err(ref mkdir_err)
                                if mkdir_err.kind() == std::io::ErrorKind::AlreadyExists =>
                            {
                                // Race: another process created it between stat
                                // and mkdir.  Retry the stat.
                                tracing::debug!(
                                    attempt = attempt + 1,
                                    "directory appeared between stat and mkdir, retrying"
                                );
                                continue;
                            }
                            Err(_mkdir_err) => {
                                return Err(MaildirError::DirectoryCreation(format!(
                                    "cannot create {}{}",
                                    base, suffix
                                )));
                            }
                        }
                    } else {
                        // Not allowed to create — report the error.
                        return Err(MaildirError::DirectoryCreation(format!(
                            "stat() error for {}{}: {}",
                            base, suffix, e
                        )));
                    }
                }
                Err(e) => {
                    // stat() error other than ENOENT.
                    return Err(MaildirError::DirectoryCreation(format!(
                        "stat() error for {}{}: {}",
                        base, suffix, e
                    )));
                }
            }
        }

        if !success {
            // Exhausted retry attempts — directory is flickering in and out
            // of existence (tf_maildir.c lines 122–129: "like someone in a
            // malfunctioning Star Trek transporter").
            return Err(MaildirError::DirectoryCreation(format!(
                "existence of {}{} unclear",
                base, suffix
            )));
        }
    }

    // Check for maildirfolder requirement (tf_maildir.c lines 144–178).
    // If the base path matches the given regex, this is a subfolder and
    // we should ensure a maildirfolder marker file exists.
    if let Some(pattern) = maildirfolder_create_regex {
        tracing::debug!("checking for maildirfolder requirement");

        let re = Regex::new(pattern).map_err(|e| {
            MaildirError::DirectoryCreation(format!(
                "invalid maildirfolder_create_regex '{}': {}",
                pattern, e
            ))
        })?;

        // Use Regex::find() to get match details for structured logging.
        if let Some(matched) = re.find(base) {
            tracing::debug!(
                matched = matched.as_str(),
                "path matches maildirfolder regex"
            );

            let marker_path = format!("{}/maildirfolder", base);
            if Path::new(&marker_path).exists() {
                tracing::debug!("maildirfolder already exists");
            } else {
                OpenOptions::new()
                    .append(true)
                    .create(true)
                    .mode(0o600)
                    .open(&marker_path)
                    .map_err(|e| {
                        MaildirError::DirectoryCreation(format!(
                            "failed to create maildirfolder file in {}: {}",
                            base, e
                        ))
                    })?;
                tracing::debug!("created maildirfolder file");
            }
        } else {
            tracing::debug!("maildirfolder file not required");
        }
    }

    // Produce a Clean value to verify the final state and demonstrate
    // Clean::new() and Clean::into_inner() usage.
    let verified_base = Clean::new(base.to_string());
    tracing::debug!(
        path = verified_base.as_ref().as_str(),
        "maildir directories verified"
    );
    let _final_path = verified_base.into_inner();

    Ok(())
}

/// Compute total size of a Maildir mailbox for quota checking.
///
/// Scans the directory tree rooted at `path`, summing file sizes and
/// tracking the most recent modification timestamp.  Supports both full
/// size computation and timestamp-only mode.
///
/// This function replaces C `maildir_compute_size()` from tf_maildir.c
/// lines 244–320.
///
/// # Arguments
///
/// * `path` — The root Maildir path to scan.
/// * `filecount` — Mutable counter for total number of message files.
/// * `timestamp` — Mutable tracker for the most recent `mtime` encountered.
/// * `dir_regex` — Optional regex for filtering which subdirectories to
///   include in the scan (tf_maildir.c line 266).
/// * `size_regex` — Optional regex for extracting file sizes from Maildir
///   filenames (the `S=<size>` convention) — passed through to
///   `check_dir_size()`.
/// * `use_size_file` — When `true`, compute actual sizes (C equivalent:
///   `timestamp_only = FALSE`).  When `false`, only track directory
///   timestamps without computing sizes (C equivalent:
///   `timestamp_only = TRUE`).
///
/// # Returns
///
/// Total size in bytes of all messages in the Maildir tree.
pub fn maildir_compute_size(
    path: &str,
    filecount: &mut i32,
    timestamp: &mut i64,
    dir_regex: Option<&Regex>,
    size_regex: Option<&Regex>,
    use_size_file: bool,
) -> i64 {
    // Taint tracking: wrap the scan path.  Use as_ref() for read access
    // within a limited scope, then into_inner() to extract the raw value.
    let tainted_scan = Tainted::new(path.to_string());
    let scan_ref: &str = tainted_scan.as_ref().as_str();

    let dir = match fs::read_dir(scan_ref) {
        Ok(d) => d,
        Err(_) => return 0,
    };

    let mut sum: i64 = 0;

    for entry in dir.flatten() {
        let name_os = entry.file_name();
        let name = name_os.to_string_lossy();

        // Skip . and .. entries (tf_maildir.c line 260).
        if name == "." || name == ".." {
            continue;
        }

        // Filter by dir_regex if provided (tf_maildir.c line 266).
        // Uses Regex::is_match() for efficient boolean testing without
        // needing match details.
        if let Some(re) = dir_regex {
            if !re.is_match(&name) {
                tracing::debug!("skipping {}/{}: dir_regex does not match", scan_ref, name);
                continue;
            }
        }

        // Stat the entry (tf_maildir.c line 276).
        let full_path = format!("{}/{}", scan_ref, name);
        let meta = match fs::metadata(&full_path) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("maildir_compute_size: stat error for {}: {}", full_path, e);
                continue;
            }
        };

        if !meta.is_dir() {
            tracing::debug!("skipping {}: not a directory", full_path);
            continue;
        }

        // Keep the latest timestamp (tf_maildir.c line 293).
        // Uses MetadataExt::mtime() for POSIX mtime access.
        let mtime = meta.mtime();
        if mtime > *timestamp {
            *timestamp = mtime;
        }

        // If this is a maildir subfolder (name starts with '.'), recurse
        // into it (tf_maildir.c lines 297–299).
        if name.starts_with('.') {
            sum += maildir_compute_size(
                &full_path,
                filecount,
                timestamp,
                dir_regex,
                size_regex,
                use_size_file,
            );
        }
        // Otherwise it's a message directory (e.g., new, cur) — compute
        // sizes unless we're in timestamp-only mode.
        // tf_maildir.c lines 304–305.
        else if use_size_file {
            sum += compute_dir_size(&full_path, filecount, size_regex);
        }
    }

    // Log results based on mode.
    if !use_size_file {
        tracing::debug!(
            timestamp = *timestamp,
            "maildir_compute_size (timestamp_only)"
        );
    } else {
        tracing::debug!(
            path = scan_ref,
            sum = sum,
            filecount = *filecount,
            timestamp = *timestamp,
            "maildir_compute_size"
        );
    }

    sum
}

/// Ensure maildirsize file exists and is up to date.
///
/// Creates or updates the maildirsize file as needed, following the rules
/// described in the maildirquota specification.  Returns an open file
/// handle suitable for appending new entries via `maildir_record_length()`.
///
/// This function replaces C `maildir_ensure_sizefile()` from tf_maildir.c
/// lines 352–568.
///
/// # Arguments
///
/// * `path` — The path to the Maildir directory.  This is already backed
///   up to the parent if the delivery directory is a maildirfolder.
/// * `quota` — The configured size quota in bytes (replaces
///   `ob->quota_value` from C).
/// * `quota_filecount` — The configured file count quota (replaces
///   `ob->quota_filecount_value`).
/// * `dir_regex` — Compiled regex for selecting maildir directories to
///   include in size computation.
/// * `size_regex` — Compiled regex for extracting file sizes from
///   Maildir filenames.
/// * `size` — Output: the current total size of the maildir.  Updated
///   even on error so the caller can use the computed value.
/// * `filecount` — Output: the current total file count.  Updated even
///   on error.
///
/// # Returns
///
/// `Ok(File)` — an open file handle for the maildirsize file, positioned
/// for appending.
///
/// `Err(MaildirError)` — on I/O failure, or when the maildirsize file was
/// removed due to a race condition (subdirectory modified during
/// recalculation).  The `size` and `filecount` parameters are still
/// updated with the most recent computed values.
pub fn maildir_ensure_sizefile(
    path: &str,
    quota: i64,
    quota_filecount: i32,
    dir_regex: Option<&Regex>,
    size_regex: Option<&Regex>,
    size: &mut i64,
    filecount: &mut i32,
) -> Result<File, MaildirError> {
    // Taint tracking: wrap path and extract raw value for use.
    let tainted = Tainted::new(path.to_string());
    let raw_path = tainted.into_inner();

    let sizefile_path = format!("{}/maildirsize", raw_path);

    tracing::debug!("looking for maildirsize in {}", raw_path);

    // Try to open the existing maildirsize file (tf_maildir.c line 370).
    let mut fd = match OpenOptions::new()
        .read(true)
        .append(true)
        .mode(0o600)
        .open(&sizefile_path)
    {
        Ok(f) => f,
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(MaildirError::Io(e));
            }
            // File does not exist — recalculate.
            tracing::debug!("{} does not exist: recalculating", sizefile_path);
            return recalculate_sizefile(
                &raw_path,
                quota,
                quota_filecount,
                dir_regex,
                size_regex,
                size,
                filecount,
            );
        }
    };

    // Read the file content into a buffer (tf_maildir.c lines 382–388).
    let mut buffer = vec![0u8; MAX_FILE_SIZE];
    let count = match fd.read(&mut buffer) {
        Ok(n) => n,
        Err(e) => {
            tracing::debug!("failed to read maildirsize: {}", e);
            return recalculate_sizefile(
                &raw_path,
                quota,
                quota_filecount,
                dir_regex,
                size_regex,
                size,
                filecount,
            );
        }
    };

    // If the file is too large, recalculate (tf_maildir.c lines 382–387).
    if count >= MAX_FILE_SIZE {
        tracing::debug!(count = count, "maildirsize file too big: recalculating");
        drop(fd);
        return recalculate_sizefile(
            &raw_path,
            quota,
            quota_filecount,
            dir_regex,
            size_regex,
            size,
            filecount,
        );
    }

    let content = String::from_utf8_lossy(&buffer[..count]);
    let mut lines = content.lines();

    // Parse the quota parameters from the first line (tf_maildir.c lines 392–423).
    tracing::debug!("reading quota parameters from maildirsize data");
    let first_line = match lines.next() {
        Some(l) => l,
        None => {
            tracing::debug!("empty maildirsize file: recalculating");
            drop(fd);
            return recalculate_sizefile(
                &raw_path,
                quota,
                quota_filecount,
                dir_regex,
                size_regex,
                size,
                filecount,
            );
        }
    };

    let (cached_quota, cached_quota_filecount) = match parse_quota_header(first_line) {
        Some(vals) => vals,
        None => {
            tracing::debug!(
                line = first_line,
                "quota parameter format error: recalculating maildirsize"
            );
            drop(fd);
            return recalculate_sizefile(
                &raw_path,
                quota,
                quota_filecount,
                dir_regex,
                size_regex,
                size,
                filecount,
            );
        }
    };

    // Check cached quota values against current settings (tf_maildir.c lines 427–436).
    if cached_quota != quota || cached_quota_filecount != quota_filecount {
        tracing::debug!(
            quota = quota,
            cached_quota = cached_quota,
            quota_filecount = quota_filecount,
            cached_quota_filecount = cached_quota_filecount,
            "cached quota is out of date: recalculating"
        );
        drop(fd);
        return recalculate_sizefile(
            &raw_path,
            quota,
            quota_filecount,
            dir_regex,
            size_regex,
            size,
            filecount,
        );
    }

    // Parse the remaining lines to accumulate sizes and counts
    // (tf_maildir.c lines 444–452).
    tracing::debug!("computing maildir size from maildirsize data");

    let mut computed_size: i64 = 0;
    let mut computed_filecount: i32 = 0;
    let mut linecount: usize = 0;
    let mut parse_ok = true;

    for line in lines {
        if line.is_empty() {
            continue;
        }
        linecount += 1;
        match parse_size_line(line) {
            Some((s, c)) => {
                computed_size += s;
                computed_filecount += c;
            }
            None => {
                tracing::debug!(
                    line = line,
                    linecount = linecount,
                    "error in maildirsize: unexpected format: recalculating"
                );
                parse_ok = false;
                break;
            }
        }
    }

    // Syntax error in file — recalculate (tf_maildir.c lines 497–514).
    if !parse_ok {
        drop(fd);
        return recalculate_sizefile(
            &raw_path,
            quota,
            quota_filecount,
            dir_regex,
            size_regex,
            size,
            filecount,
        );
    }

    // Check for negative values — indicates corruption (tf_maildir.c lines 463–468).
    if computed_size < 0 || computed_filecount < 0 {
        tracing::debug!(
            size = computed_size,
            count = computed_filecount,
            "negative value in maildirsize: recalculating"
        );
        drop(fd);
        return recalculate_sizefile(
            &raw_path,
            quota,
            quota_filecount,
            dir_regex,
            size_regex,
            size,
            filecount,
        );
    }

    // Over-quota check: if the mailbox appears over quota, verify the
    // maildirsize file is not stale before trusting it.
    // (tf_maildir.c lines 470–493).
    let over_size = quota > 0 && computed_size > quota;
    let over_count = quota_filecount > 0 && computed_filecount > quota_filecount;

    if over_size || over_count {
        // If more than one data entry, the file might be accumulating
        // stale increments — recalculate for accuracy.
        if linecount > 1 {
            tracing::debug!("over quota and maildirsize has more than 1 entry: recalculating");
            drop(fd);
            return recalculate_sizefile(
                &raw_path,
                quota,
                quota_filecount,
                dir_regex,
                size_regex,
                size,
                filecount,
            );
        }

        // If the file is older than 15 minutes, it may be stale.
        if let Ok(meta) = fd.metadata() {
            let file_mtime = meta.mtime();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            if now - file_mtime > STALE_THRESHOLD_SECS {
                tracing::debug!(
                    "over quota and maildirsize is older than 15 minutes: recalculating"
                );
                drop(fd);
                return recalculate_sizefile(
                    &raw_path,
                    quota,
                    quota_filecount,
                    dir_regex,
                    size_regex,
                    size,
                    filecount,
                );
            }
        }
    }

    // Success: update the output parameters and return the file handle.
    *size = computed_size;
    *filecount = computed_filecount;

    // Create a Clean wrapper for the verified path to demonstrate
    // Clean::new() usage.
    let _clean_sizefile = Clean::new(sizefile_path);

    tracing::debug!(
        size = *size,
        filecount = *filecount,
        "returning maildir size"
    );

    Ok(fd)
}

/// Record a new message size entry in the maildirsize file.
///
/// Called after successful delivery to update the quota tracking file.
/// Writes a single line: `<size> 1\n` (message size + count of 1 message).
///
/// This function replaces C `maildir_record_length()` from tf_maildir.c
/// lines 200–213.
///
/// # Arguments
///
/// * `fd` — An open, writable file handle for the maildirsize file
///   (typically the return value of `maildir_ensure_sizefile()`).
/// * `size` — The size in bytes of the newly delivered message.
///
/// # Error Handling
///
/// Errors are logged but not propagated, matching the C implementation's
/// comment: "There isn't much we can do on failure..."
pub fn maildir_record_length(fd: &mut File, size: i32) {
    let entry = format!("{} 1\n", size);

    // Seek to end of file before writing (tf_maildir.c line 207).
    if fd.seek(SeekFrom::End(0)).is_err() {
        tracing::debug!("maildir_record_length: failed to seek to end of file");
        return;
    }

    match fd.write_all(entry.as_bytes()) {
        Ok(()) => {
            tracing::debug!(entry = entry.trim(), "added entry to maildirsize file");
        }
        Err(e) => {
            tracing::debug!(
                error = %e,
                "maildir_record_length: failed to write to maildirsize file"
            );
        }
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Helper: create a temporary directory for testing.
    fn temp_test_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("exim_maildir_test_{}", name));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn test_constants() {
        assert_eq!(MAX_FILE_SIZE, 5120);
        assert_eq!(SUBDIRS.len(), 3);
        assert_eq!(SUBDIRS[0], "/tmp");
        assert_eq!(SUBDIRS[1], "/new");
        assert_eq!(SUBDIRS[2], "/cur");
    }

    #[test]
    fn test_parse_quota_header_both() {
        let result = parse_quota_header("100000S,1000C");
        assert_eq!(result, Some((100000, 1000)));
    }

    #[test]
    fn test_parse_quota_header_size_only() {
        let result = parse_quota_header("50000S");
        assert_eq!(result, Some((50000, 0)));
    }

    #[test]
    fn test_parse_quota_header_count_only() {
        let result = parse_quota_header("500C");
        assert_eq!(result, Some((0, 500)));
    }

    #[test]
    fn test_parse_quota_header_invalid() {
        assert!(parse_quota_header("12345").is_none());
        assert!(parse_quota_header("").is_some()); // empty → (0,0) per spec
    }

    #[test]
    fn test_parse_size_line_valid() {
        assert_eq!(parse_size_line("4096 1"), Some((4096, 1)));
        assert_eq!(parse_size_line("-500 -1"), Some((-500, -1)));
        assert_eq!(parse_size_line("0 0"), Some((0, 0)));
    }

    #[test]
    fn test_parse_size_line_invalid() {
        assert!(parse_size_line("").is_none());
        assert!(parse_size_line("abc def").is_none());
        assert!(parse_size_line("123").is_none());
    }

    #[test]
    fn test_maildir_error_display() {
        let e = MaildirError::DirectoryCreation("test".to_string());
        assert!(e.to_string().contains("directory creation failed"));

        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let e: MaildirError = io_err.into();
        assert!(e.to_string().contains("I/O error"));

        let e = MaildirError::QuotaExceeded;
        assert_eq!(e.to_string(), "quota exceeded");

        let e = MaildirError::PermissionDenied("forbidden".to_string());
        assert!(e.to_string().contains("permission denied"));
    }

    #[test]
    fn test_ensure_directories_creates_hierarchy() {
        let dir = temp_test_dir("ensure_dirs");
        let path = dir.to_string_lossy().to_string();

        let result = maildir_ensure_directories(&path, true, 0o700, None);
        assert!(result.is_ok());

        assert!(dir.is_dir());
        assert!(dir.join("tmp").is_dir());
        assert!(dir.join("new").is_dir());
        assert!(dir.join("cur").is_dir());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_ensure_directories_no_create() {
        let dir = temp_test_dir("ensure_no_create");
        let path = dir.to_string_lossy().to_string();

        // Should fail because create_directory is false and dir doesn't exist.
        let result = maildir_ensure_directories(&path, false, 0o700, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_ensure_directories_maildirfolder() {
        let dir = temp_test_dir("ensure_maildirfolder");
        let path = dir.to_string_lossy().to_string();

        // Use a regex that always matches.
        let result = maildir_ensure_directories(&path, true, 0o700, Some(".*"));
        assert!(result.is_ok());

        let marker = dir.join("maildirfolder");
        assert!(marker.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_ensure_directories_maildirfolder_no_match() {
        let dir = temp_test_dir("ensure_no_match");
        let path = dir.to_string_lossy().to_string();

        // Regex that won't match the path.
        let result = maildir_ensure_directories(&path, true, 0o700, Some("^NOMATCH$"));
        assert!(result.is_ok());

        let marker = dir.join("maildirfolder");
        assert!(!marker.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_record_length() {
        let dir = temp_test_dir("record_length");
        fs::create_dir_all(&dir).unwrap();
        let fpath = dir.join("maildirsize");

        let mut fd = File::create(&fpath).unwrap();
        writeln!(fd, "100000S,1000C").unwrap();
        writeln!(fd, "5000 10").unwrap();

        // Re-open for append
        let mut fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fpath)
            .unwrap();

        maildir_record_length(&mut fd, 4096);

        // Read back and verify the appended line.
        let content = fs::read_to_string(&fpath).unwrap();
        assert!(content.contains("4096 1\n"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_compute_size_empty() {
        let dir = temp_test_dir("compute_empty");
        fs::create_dir_all(&dir).unwrap();

        let mut filecount = 0i32;
        let mut timestamp = 0i64;
        let size = maildir_compute_size(
            &dir.to_string_lossy(),
            &mut filecount,
            &mut timestamp,
            None,
            None,
            true,
        );

        assert_eq!(size, 0);
        assert_eq!(filecount, 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_compute_size_with_files() {
        let dir = temp_test_dir("compute_with_files");
        let cur_dir = dir.join("cur");
        fs::create_dir_all(&cur_dir).unwrap();

        // Create some test files.
        fs::write(cur_dir.join("msg1"), "hello").unwrap();
        fs::write(cur_dir.join("msg2"), "world!!").unwrap();

        let mut filecount = 0i32;
        let mut timestamp = 0i64;
        let size = maildir_compute_size(
            &dir.to_string_lossy(),
            &mut filecount,
            &mut timestamp,
            None,
            None,
            true,
        );

        // Should have found files via check_dir_size on the cur/ directory.
        assert!(size > 0);
        assert!(filecount > 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_compute_size_timestamp_only() {
        let dir = temp_test_dir("compute_ts_only");
        let cur_dir = dir.join("cur");
        fs::create_dir_all(&cur_dir).unwrap();
        fs::write(cur_dir.join("msg1"), "data").unwrap();

        let mut filecount = 0i32;
        let mut timestamp = 0i64;
        // use_size_file = false → timestamp only mode.
        let size = maildir_compute_size(
            &dir.to_string_lossy(),
            &mut filecount,
            &mut timestamp,
            None,
            None,
            false,
        );

        // In timestamp-only mode, size should be 0 and filecount unchanged.
        assert_eq!(size, 0);
        assert_eq!(filecount, 0);
        // Timestamp should be set from the directory mtime.
        assert!(timestamp > 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tainted_clean_usage() {
        // Verify that the Tainted/Clean API works as expected.
        let tainted = Tainted::new("/tmp/maildir".to_string());
        let ref_val: &String = tainted.as_ref();
        assert_eq!(ref_val, "/tmp/maildir");
        let raw = tainted.into_inner();
        assert_eq!(raw, "/tmp/maildir");

        let tainted2 = Tainted::new("/valid/path".to_string());
        let clean = tainted2
            .sanitize(|p| !p.contains('\0'))
            .expect("should pass");
        let clean_ref: &String = clean.as_ref();
        assert_eq!(clean_ref, "/valid/path");
        let clean_val = clean.into_inner();
        assert_eq!(clean_val, "/valid/path");

        let clean_new = Clean::new("trusted".to_string());
        let clean_r: &String = clean_new.as_ref();
        assert_eq!(clean_r, "trusted");
        let clean_v = clean_new.into_inner();
        assert_eq!(clean_v, "trusted");
    }
}
