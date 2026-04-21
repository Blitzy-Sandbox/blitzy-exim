//! Spool -D Data File Operations
//!
//! Implements -D (message body data) file operations with byte-level
//! compatibility between C Exim and Rust Exim.  Handles opening, locking,
//! reading data files, temporary file creation, message moving between
//! queues, and MBOX materialization for content scanning.
//!
//! **CRITICAL (AAP §0.7.1):** The -D file format MUST be identical between
//! C and Rust Exim.  The data start offset calculation is format-dependent
//! (old vs new message ID format).
//!
//! **CRITICAL (AAP §0.7.2):** Zero `unsafe` blocks in this module.
//!
//! # File Format
//!
//! A `-D` spool file has the following structure:
//!
//! 1. **Identity line**: `{message_id}-D\n`
//! 2. **Message body data**: raw bytes starting at the data start offset
//!
//! The data start offset is `MESSAGE_ID_LENGTH + 3` bytes (26 for current
//! format, 19 for legacy format), defined by [`format::spool_data_start_offset`].
//!
//! # Source Origins
//!
//! - `src/src/spool_in.c` lines 38–127 — `spool_open_datafile()`
//! - `src/src/spool_out.c` lines 37–58 — `spool_write_error()`
//! - `src/src/spool_out.c` lines 73–105 — `spool_open_temp()`
//! - `src/src/spool_out.c` lines 458–507 — `make_link()` / `break_link()`
//! - `src/src/spool_out.c` lines 529–573 — `spool_move_message()`
//! - `src/src/spool_mbox.c` lines 32–198 — `spool_mbox()` (content-scan)
//! - `src/src/spool_mbox.c` lines 205–245 — `unspool_mbox()` (content-scan)

use std::fs::{self, File, OpenOptions};
use std::io;
#[cfg(feature = "content-scan")]
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::format::{
    set_subdir_str, spool_data_start_offset, spool_fname, spool_q_fname, spool_q_sname,
    SpoolWriteContext, INPUT_DIRECTORY_MODE, SPOOL_MODE,
};
use crate::SpoolError;

// Re-export taint types for use in spool data operations (AAP §0.4.3).
#[allow(unused_imports)]
use exim_store::{Clean, ConfigData, Tainted};

// =============================================================================
// Configuration and Context Types
// =============================================================================
//
// These types capture the configuration and per-message state needed by spool
// data file operations.  They will be replaced with the concrete types from
// `exim-core/src/context.rs` and `exim-config/src/types.rs` once those crates
// are fully implemented.  Until then, these local definitions provide the
// required interface for compilation and testing.

/// Configuration data required by spool data file operations.
///
/// This struct holds the subset of Exim configuration fields that are accessed
/// during spool -D file operations, temporary file creation, and message
/// movement between queues.
///
/// In the C codebase, these values are global variables scattered across
/// `globals.c` / `globals.h`.  In the Rust codebase (AAP §0.4.4), they are
/// part of the `ConfigContext` struct passed explicitly through call chains.
#[derive(Debug, Clone)]
pub struct Config {
    /// Base spool directory path (e.g., `/var/spool/exim`).
    ///
    /// Source: C global `spool_directory` — `globals.c`.
    pub spool_directory: String,

    /// Queue name for the current operation; empty string for the default queue.
    ///
    /// Source: C global `queue_name` — `globals.c`.
    pub queue_name: String,

    /// Whether the spool directory is split into 62 single-character
    /// subdirectories (one per base-62 digit).
    ///
    /// Source: C global `split_spool_directory` — `globals.c`.
    pub split_spool_directory: bool,

    /// The UID under which Exim runs.
    ///
    /// Source: C global `exim_uid` — `globals.c`.
    pub exim_uid: u32,

    /// The GID under which Exim runs.
    ///
    /// Source: C global `exim_gid` — `globals.c`.
    pub exim_gid: u32,

    /// Destination queue name for message move operations.  When `Some`, the
    /// message is moved to this queue instead of the current `queue_name`.
    ///
    /// Source: C global `queue_name_dest` — `globals.c`.
    pub queue_name_dest: Option<String>,

    /// Whether Exim is currently running as a queue runner.  Controls the
    /// verbosity of "not found" messages in `spool_open_datafile`.
    ///
    /// Source: C global `f.queue_running` — `globals.c`.
    pub queue_running: bool,
}

/// Per-message context used by spool data file operations.
///
/// This struct holds the per-message state that is populated during spool
/// operations.  In the C codebase, these are global variables; in the Rust
/// codebase (AAP §0.4.4), they are part of `MessageContext`.
#[derive(Debug)]
pub struct MessageContext {
    /// The message ID (e.g., `"1pBnKl-003F4x-Tw"`).
    pub message_id: String,

    /// Size of the message body in bytes (file size minus data start offset).
    pub message_body_size: u64,

    /// Size of the message including the newline before data.
    pub message_size: u64,

    /// The current message subdirectory (single character or empty).
    pub message_subdir: String,

    /// Whether the MBOX file has already been created for content scanning.
    #[cfg(feature = "content-scan")]
    pub spool_mbox_ok: bool,

    /// Whether to suppress MBOX cleanup on message completion.
    #[cfg(feature = "content-scan")]
    pub no_mbox_unspool: bool,

    /// The message ID of the currently spooled MBOX file.
    #[cfg(feature = "content-scan")]
    pub spooled_message_id: String,

    /// Reference to the currently open spool data file, if held by the main
    /// receive process (which holds the lock).
    pub spool_data_file: Option<File>,

    /// Whether the spool file uses wire format (CRLF line endings).
    pub spool_file_wireformat: bool,

    /// Sender address for MBOX envelope generation.
    #[cfg(feature = "content-scan")]
    pub sender_address: Option<String>,

    /// Return path for MBOX `From ` line generation.
    #[cfg(feature = "content-scan")]
    pub return_path: Option<String>,

    /// Comma-separated recipient list for MBOX `X-Envelope-To:` header.
    #[cfg(feature = "content-scan")]
    pub recipients: Option<String>,

    /// List of RFC 2822 headers for MBOX generation.
    #[cfg(feature = "content-scan")]
    pub header_list: Vec<crate::HeaderLine>,

    /// Whether spam scanning has completed OK.
    #[cfg(feature = "content-scan")]
    pub spam_ok: bool,

    /// Whether malware scanning has completed OK.
    #[cfg(feature = "content-scan")]
    pub malware_ok: bool,
}

// =============================================================================
// Internal Helpers
// =============================================================================

/// Construct a spool write error with context-specific messaging.
///
/// This is the Rust equivalent of `spool_write_error()` from
/// `src/src/spool_out.c` lines 37–58.  In the C version, this function
/// optionally panic-dies or sets an error message pointer.  The Rust version
/// always returns a `SpoolError` (the caller decides severity).
///
/// # Arguments
///
/// * `where_ctx` — The spool write context (Receiving, Delivering, Modifying).
/// * `s` — Description string to include in the error message.
/// * `temp_name` — Optional temporary file to unlink on error.
/// * `error` — The underlying I/O error.
///
/// # Returns
///
/// A [`SpoolError::FormatError`] with a context-specific message.
pub fn spool_write_error(
    where_ctx: SpoolWriteContext,
    s: &str,
    temp_name: Option<&Path>,
    error: io::Error,
) -> SpoolError {
    let context_str = match where_ctx {
        SpoolWriteContext::Receiving => "receiving",
        SpoolWriteContext::Delivering => "delivering",
        SpoolWriteContext::Modifying => "modifying",
    };

    let msg = format!("spool file {} error while {}: {}", s, context_str, error);

    tracing::error!("{}", msg);

    // Clean up temporary file if provided (best-effort).
    if let Some(path) = temp_name {
        if let Err(e) = fs::remove_file(path) {
            tracing::warn!(
                "failed to unlink temp file {} during error cleanup: {}",
                path.display(),
                e
            );
        }
    }

    SpoolError::FormatError { context: msg }
}

/// Create a hard link from `from_path` to `to_path`.
///
/// This is the Rust equivalent of `make_link()` from `src/src/spool_out.c`
/// lines 458–471.
///
/// # Arguments
///
/// * `dir` — Base directory name (`"input"` or `"msglog"`).
/// * `dest_queue` — Destination queue name.
/// * `subdir` — Subdirectory within the base directory.
/// * `id` — Message ID.
/// * `suffix` — File suffix (`"-D"`, `"-H"`, or `""`).
/// * `from` — Source directory prefix.
/// * `to` — Destination directory prefix.
/// * `spool_directory` — Base spool directory path.
/// * `queue_name` — Current queue name (for source path construction).
/// * `noentok` — If `true`, treat ENOENT (file not found) as non-fatal.
///
/// # Errors
///
/// Returns `SpoolError::Io` on hard link failure (unless `noentok` is `true`
/// and the error is `ENOENT`).
// Mirrors C `make_link()` parameter list (spool_out.c:458) for behavioral
// fidelity; all parameters are simple &str references with distinct purpose.
#[allow(clippy::too_many_arguments)]
fn make_link(
    dir: &str,
    dest_queue: &str,
    subdir: &str,
    id: &str,
    suffix: &str,
    from: &str,
    to: &str,
    spool_directory: &str,
    queue_name: &str,
    noentok: bool,
) -> Result<(), SpoolError> {
    // Construct source path: {spool_directory}/{queue_name}/{from}{dir}/{subdir}/{id}{suffix}
    let from_dir = format!("{}{}", from, dir);
    let fname = spool_fname(spool_directory, queue_name, &from_dir, subdir, id, suffix);

    // Construct destination path: {spool_directory}/{dest_queue}/{to}{dir}/{subdir}/{id}{suffix}
    let to_dir = format!("{}{}", to, dir);
    let tname = spool_q_fname(spool_directory, &to_dir, dest_queue, subdir, id, suffix);

    tracing::trace!("make_link: {} -> {}", fname.display(), tname.display());

    match fs::hard_link(&fname, &tname) {
        Ok(()) => Ok(()),
        Err(e) if noentok && e.kind() == io::ErrorKind::NotFound => {
            tracing::trace!(
                "make_link: source {} not found (noentok=true, ignoring)",
                fname.display()
            );
            Ok(())
        }
        Err(e) => {
            tracing::error!(
                "link({}, {}) failed while moving message: {}",
                fname.display(),
                tname.display(),
                e
            );
            Err(SpoolError::Io(e))
        }
    }
}

/// Remove a file (break a hard link).
///
/// This is the Rust equivalent of `break_link()` from `src/src/spool_out.c`
/// lines 495–507.
///
/// # Arguments
///
/// * `dir` — Base directory name (`"input"` or `"msglog"`).
/// * `subdir` — Subdirectory within the base directory.
/// * `id` — Message ID.
/// * `suffix` — File suffix (`"-D"`, `"-H"`, or `""`).
/// * `from` — Source directory prefix.
/// * `spool_directory` — Base spool directory path.
/// * `queue_name` — Current queue name.
/// * `noentok` — If `true`, treat ENOENT as non-fatal.
///
/// # Errors
///
/// Returns `SpoolError::Io` on unlink failure (unless `noentok` is `true`
/// and the error is `ENOENT`).
// Mirrors C `break_link()` parameter list (spool_out.c:495) for behavioral
// fidelity; all parameters are simple &str references with distinct purpose.
#[allow(clippy::too_many_arguments)]
fn break_link(
    dir: &str,
    subdir: &str,
    id: &str,
    suffix: &str,
    from: &str,
    spool_directory: &str,
    queue_name: &str,
    noentok: bool,
) -> Result<(), SpoolError> {
    let from_dir = format!("{}{}", from, dir);
    let fname = spool_fname(spool_directory, queue_name, &from_dir, subdir, id, suffix);

    tracing::trace!("break_link: {}", fname.display());

    match fs::remove_file(&fname) {
        Ok(()) => Ok(()),
        Err(e) if noentok && e.kind() == io::ErrorKind::NotFound => {
            tracing::trace!(
                "break_link: {} not found (noentok=true, ignoring)",
                fname.display()
            );
            Ok(())
        }
        Err(e) => {
            tracing::error!(
                "unlink({}) failed while moving message: {}",
                fname.display(),
                e
            );
            Err(SpoolError::Io(e))
        }
    }
}

// =============================================================================
// Public API — spool_open_datafile
// =============================================================================

/// Open and lock a spool -D data file.
///
/// Opens the data file for a given message ID with `O_RDWR | O_APPEND`,
/// applies a POSIX record lock on the first line (the identity line),
/// and computes the message body size from the file metadata.
///
/// The data file is the one used for locking because the header file can be
/// replaced during delivery due to header rewriting.  The file is opened with
/// write access for exclusive locking, but in practice it will not be written
/// to.  Append mode is used as a safety measure.
///
/// ## Split Spool Directory Search Order
///
/// If `split_spool_directory` is set:
///   1. First look in the split subdirectory (derived from the message ID)
///   2. Then fall back to the root input directory
///
/// If `split_spool_directory` is not set:
///   1. First look in the root input directory
///   2. Then fall back to the split subdirectory
///
/// This dual-pass strategy handles messages left over from toggling the
/// `split_spool_directory` setting.
///
/// ## Source
///
/// `src/src/spool_in.c` lines 38–127.
///
/// # Arguments
///
/// * `id` — The message ID to open.
/// * `config` — Configuration providing spool directory, queue name, etc.
/// * `ctx` — Message context; updated with `message_body_size`, `message_size`,
///   and `message_subdir` on success.
///
/// # Returns
///
/// The opened and locked `File` on success.
///
/// # Errors
///
/// * [`SpoolError::NotFound`] — The data file was not found.
/// * [`SpoolError::Locked`] — The file is locked by another process.
/// * [`SpoolError::Io`] — Other I/O errors.
pub fn spool_open_datafile(
    id: &str,
    config: &Config,
    ctx: &mut MessageContext,
) -> Result<File, SpoolError> {
    // Try two search passes: first the preferred location, then the fallback.
    // The search order depends on whether split_spool_directory is configured.
    for i in 0..2usize {
        let subdir = set_subdir_str(id, i, config.split_spool_directory);
        let fname = spool_fname(
            &config.spool_directory,
            &config.queue_name,
            "input",
            &subdir,
            id,
            "-D",
        );

        tracing::debug!("Trying spool file {}", fname.display());

        // Open with O_RDWR | O_APPEND, plus O_CLOEXEC and O_NOFOLLOW for
        // security (symlink attack protection, fd leak protection on exec).
        let open_result = OpenOptions::new()
            .read(true)
            .append(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&fname);

        match open_result {
            Ok(file) => {
                // Successfully opened — record the subdirectory.
                ctx.message_subdir = subdir;

                // Apply POSIX record lock on the first line only (identity line).
                // This is for Cygwin compatibility: on real Unix systems, the lock
                // range doesn't matter as long as Exim is consistent.
                let lock_data = libc::flock {
                    l_type: libc::F_WRLCK as libc::c_short,
                    l_whence: libc::SEEK_SET as libc::c_short,
                    l_start: 0,
                    l_len: spool_data_start_offset(id) as libc::off_t,
                    l_pid: 0,
                };

                // Use as_raw_fd() to get the descriptor for the libc::flock
                // struct construction, then pass &file (which implements AsFd)
                // to the nix fcntl wrapper.
                let lock_result =
                    nix::fcntl::fcntl(&file, nix::fcntl::FcntlArg::F_SETLK(&lock_data));

                if lock_result.is_err() {
                    tracing::warn!(
                        "Spool file for {} is locked \
                         (another process is handling this message)",
                        id
                    );
                    // File is dropped here, closing the fd.
                    return Err(SpoolError::Locked);
                }

                // Get file size and compute body size.
                let metadata = file.metadata().map_err(SpoolError::Io)?;
                let file_size = metadata.len();
                let offset = spool_data_start_offset(id) as u64;

                if file_size >= offset {
                    ctx.message_body_size = file_size - offset;
                    // Add 1 for the newline before data (C: message_size = message_body_size + 1).
                    ctx.message_size = ctx.message_body_size + 1;
                } else {
                    ctx.message_body_size = 0;
                    ctx.message_size = 1;
                }

                return Ok(file);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if i == 0 {
                    // First attempt failed with ENOENT — try the fallback path.
                    continue;
                }
                // Second attempt also failed — the file truly doesn't exist.
                if !config.queue_running {
                    tracing::warn!(
                        "Spool{}{} file {}-D not found",
                        if config.queue_name.is_empty() {
                            ""
                        } else {
                            " Q="
                        },
                        config.queue_name,
                        id
                    );
                } else {
                    tracing::debug!(
                        "Spool{}{} file {}-D not found",
                        if config.queue_name.is_empty() {
                            ""
                        } else {
                            " Q="
                        },
                        config.queue_name,
                        id
                    );
                }
                return Err(SpoolError::NotFound {
                    path: fname.display().to_string(),
                });
            }
            Err(e) => {
                tracing::error!("Spool error for {}: {}", fname.display(), e);
                return Err(SpoolError::Io(e));
            }
        }
    }

    // This should be unreachable, but handle it gracefully.
    Err(SpoolError::NotFound {
        path: format!("{}-D", id),
    })
}

// =============================================================================
// Public API — spool_open_temp
// =============================================================================

/// Open a file under a temporary name with a single retry on EEXIST.
///
/// Creates a new file with `O_RDWR | O_CREAT | O_EXCL` and `SPOOL_MODE`
/// (0o640) permissions.  If the file already exists (leftover from a crash),
/// it is unlinked and the open is retried once.
///
/// After successful creation, the file ownership is set to
/// `exim_uid:exim_gid` and permissions are double-checked via `fchmod`,
/// because group settings may not always be applied automatically.
///
/// ## Source
///
/// `src/src/spool_out.c` lines 73–105.
///
/// # Arguments
///
/// * `temp_name` — The full path for the temporary spool file.
/// * `config` — Configuration providing `exim_uid` and `exim_gid`.
///
/// # Returns
///
/// The opened `File` on success.
///
/// # Errors
///
/// * [`SpoolError::Io`] — File creation, ownership, or permission setting failed.
pub fn spool_open_temp(temp_name: &Path, config: &Config) -> Result<File, SpoolError> {
    // First attempt: create exclusively.
    let open_file = || -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(SPOOL_MODE)
            .open(temp_name)
    };

    let file = match open_file() {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            // The file already exists — likely a leftover from a crash.
            // Unlink and retry once.
            tracing::debug!("{} exists: unlinking", temp_name.display());
            if let Err(unlink_err) = fs::remove_file(temp_name) {
                tracing::warn!(
                    "failed to unlink existing temp file {}: {}",
                    temp_name.display(),
                    unlink_err
                );
            }
            // Retry.
            open_file().map_err(SpoolError::Io)?
        }
        Err(e) => return Err(SpoolError::Io(e)),
    };

    // Set ownership to exim_uid:exim_gid.
    // Set file mode to SPOOL_MODE (double-check, because the group setting
    // doesn't always get applied automatically by the kernel).
    let chown_result = nix::unistd::fchown(
        &file,
        Some(nix::unistd::Uid::from_raw(config.exim_uid)),
        Some(nix::unistd::Gid::from_raw(config.exim_gid)),
    );

    let chmod_result = nix::sys::stat::fchmod(
        &file,
        nix::sys::stat::Mode::from_bits_truncate(SPOOL_MODE as nix::sys::stat::mode_t),
    );

    if chown_result.is_err() || chmod_result.is_err() {
        tracing::debug!("failed setting perms on {}", temp_name.display());
        // Close the file (drop) and unlink.
        drop(file);
        let _ = fs::remove_file(temp_name);
        return Err(SpoolError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "failed to set ownership/permissions on {}",
                temp_name.display()
            ),
        )));
    }

    Ok(file)
}

// =============================================================================
// Public API — spool_move_message
// =============================================================================

/// Move message files (-H, -D, and msglog) between spool directories.
///
/// Creates hard links in the destination directory, then removes the original
/// links.  The link creation and removal order is critical for safety:
///
/// **Creation order** (last link signals "message is ready"):
///   1. `msglog/{subdir}/{id}` (noentok — msglog may not exist)
///   2. `input/{subdir}/{id}-D`
///   3. `input/{subdir}/{id}-H` (**LAST** — tells Exim a message exists)
///
/// **Removal order** (first removal signals "message is gone"):
///   1. `input/{subdir}/{id}-H` (**FIRST** — tells Exim message is gone)
///   2. `input/{subdir}/{id}-D`
///   3. `msglog/{subdir}/{id}` (noentok — msglog may not exist)
///
/// ## Source
///
/// `src/src/spool_out.c` lines 529–573.
///
/// # Arguments
///
/// * `id` — The message ID to move.
/// * `subdir` — The subdirectory name (single character or empty).
/// * `from` — Source directory prefix (e.g., `""` for default queue).
/// * `to` — Destination directory prefix.
/// * `config` — Configuration providing spool directory and queue names.
///
/// # Errors
///
/// Returns `SpoolError::Io` if any link creation or removal fails.
pub fn spool_move_message(
    id: &str,
    subdir: &str,
    from: &str,
    to: &str,
    config: &Config,
) -> Result<(), SpoolError> {
    // Determine the destination queue name.
    let dest_qname = config
        .queue_name_dest
        .as_deref()
        .unwrap_or(&config.queue_name);

    // Create output directories (best-effort, like C's directory_make with TRUE).
    let input_dir = spool_q_sname(&format!("{}input", to), dest_qname, subdir);
    let input_path = PathBuf::from(&config.spool_directory).join(&input_dir);
    if let Err(e) = fs::create_dir_all(&input_path) {
        tracing::warn!(
            "failed to create directory {}: {} (continuing)",
            input_path.display(),
            e
        );
    } else {
        // Set directory permissions to INPUT_DIRECTORY_MODE (0o750).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(
                &input_path,
                fs::Permissions::from_mode(INPUT_DIRECTORY_MODE),
            );
        }
    }

    let msglog_dir = spool_q_sname(&format!("{}msglog", to), dest_qname, subdir);
    let msglog_path = PathBuf::from(&config.spool_directory).join(&msglog_dir);
    if let Err(e) = fs::create_dir_all(&msglog_path) {
        tracing::warn!(
            "failed to create directory {}: {} (continuing)",
            msglog_path.display(),
            e
        );
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(
                &msglog_path,
                fs::Permissions::from_mode(INPUT_DIRECTORY_MODE),
            );
        }
    }

    // Create hard links in safety order (-H LAST on create).
    make_link(
        "msglog",
        dest_qname,
        subdir,
        id,
        "",
        from,
        to,
        &config.spool_directory,
        &config.queue_name,
        true, // noentok
    )?;
    make_link(
        "input",
        dest_qname,
        subdir,
        id,
        "-D",
        from,
        to,
        &config.spool_directory,
        &config.queue_name,
        false,
    )?;
    make_link(
        "input",
        dest_qname,
        subdir,
        id,
        "-H",
        from,
        to,
        &config.spool_directory,
        &config.queue_name,
        false,
    )?;

    // Remove old links in safety order (-H FIRST on delete).
    break_link(
        "input",
        subdir,
        id,
        "-H",
        from,
        &config.spool_directory,
        &config.queue_name,
        false,
    )?;
    break_link(
        "input",
        subdir,
        id,
        "-D",
        from,
        &config.spool_directory,
        &config.queue_name,
        false,
    )?;
    break_link(
        "msglog",
        subdir,
        id,
        "",
        from,
        &config.spool_directory,
        &config.queue_name,
        true, // noentok
    )?;

    // Log the move.
    tracing::debug!(
        "moved from {}{}{}{}input, {}msglog to {}{}{}{}input, {}msglog",
        if config.queue_name.is_empty() {
            ""
        } else {
            "("
        },
        config.queue_name,
        if config.queue_name.is_empty() {
            ""
        } else {
            ") "
        },
        from,
        from,
        if dest_qname.is_empty() { "" } else { "(" },
        dest_qname,
        if dest_qname.is_empty() { "" } else { ") " },
        to,
        to,
    );

    Ok(())
}

// =============================================================================
// Public API — spool_mbox (content-scan feature)
// =============================================================================

/// Create an MBOX-style message file from the spooled message data.
///
/// Materializes an RFC 4155 MBOX file at `{spool_directory}/scan/{id}/{id}.eml`
/// for use by content scanning engines (SpamAssassin, ClamAV, etc.).  The
/// generated file contains:
///
/// 1. MBOX `From ` envelope line
/// 2. `X-Envelope-From:` header (if sender address is available)
/// 3. `X-Envelope-To:` header (if recipients are available)
/// 4. All non-deleted message headers
/// 5. Blank line separator
/// 6. Message body (with optional CRLF → LF conversion for wire format)
///
/// If the MBOX file has already been created (`spool_mbox_ok` flag), the
/// existing file is reopened without re-creation.
///
/// ## Source
///
/// `src/src/spool_mbox.c` lines 32–198.
///
/// # Arguments
///
/// * `source_file_override` — Optional alternative source file for the body
///   data (used by re-scanning after modification).
/// * `ctx` — Message context providing headers, sender, recipients, etc.
/// * `config` — Configuration providing spool directory.
///
/// # Returns
///
/// A tuple of `(file, size, path)` where:
///   - `file` — The .eml file opened for reading.
///   - `size` — The size of the .eml file in bytes.
///   - `path` — The full path to the .eml file.
///
/// # Errors
///
/// Returns `SpoolError` on I/O or format errors.
#[cfg(feature = "content-scan")]
pub fn spool_mbox(
    source_file_override: Option<&Path>,
    ctx: &mut MessageContext,
    config: &Config,
) -> Result<(File, u64, PathBuf), SpoolError> {
    let mbox_path = PathBuf::from(format!(
        "{}/scan/{}/{}.eml",
        config.spool_directory, ctx.message_id, ctx.message_id
    ));

    // Skip creation if already spooled as mbox file.
    if !ctx.spool_mbox_ok {
        // Create scan directory: {spool_directory}/scan/{message_id}
        let scan_dir = PathBuf::from(format!(
            "{}/scan/{}",
            config.spool_directory, ctx.message_id
        ));
        fs::create_dir_all(&scan_dir).map_err(|e| {
            tracing::error!(
                "failed to create scan directory {}: {}",
                scan_dir.display(),
                e
            );
            SpoolError::Io(e)
        })?;

        // Set directory permissions to 0o750.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&scan_dir, fs::Permissions::from_mode(0o750));
        }

        // Open .eml file for writing with SPOOL_MODE permissions.
        let mbox_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(SPOOL_MODE)
            .open(&mbox_path)
            .map_err(|e| {
                tracing::error!("failed to open scan file {}: {}", mbox_path.display(), e);
                SpoolError::Io(e)
            })?;

        let mut writer = BufWriter::new(mbox_file);

        // Generate MBOX envelope headers.
        // From {return_path_or_MAILER-DAEMON} {bsd_time}
        let return_path = ctx
            .return_path
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("MAILER-DAEMON");

        // Use a simplified BSD time format for the From_ line.
        let bsd_time = chrono_free_bsd_time();

        writeln!(writer, "From {} {}", return_path, bsd_time).map_err(|e| {
            tracing::error!(
                "Error/short write while writing mailbox headers to {}",
                mbox_path.display()
            );
            SpoolError::Io(e)
        })?;

        // X-Envelope-From: <{sender_address}>
        if let Some(ref sender) = ctx.sender_address {
            if !sender.is_empty() {
                writeln!(writer, "X-Envelope-From: <{}>", sender).map_err(|e| {
                    tracing::error!(
                        "Error/short write while writing mailbox headers to {}",
                        mbox_path.display()
                    );
                    SpoolError::Io(e)
                })?;
            }
        }

        // X-Envelope-To: {recipients}
        if let Some(ref recipients) = ctx.recipients {
            if !recipients.is_empty() {
                writeln!(writer, "X-Envelope-To: {}", recipients).map_err(|e| {
                    tracing::error!(
                        "Error/short write while writing mailbox headers to {}",
                        mbox_path.display()
                    );
                    SpoolError::Io(e)
                })?;
            }
        }

        // Write all non-deleted header lines (type != '*').
        for header in &ctx.header_list {
            if header.header_type != '*' {
                writer.write_all(header.text.as_bytes()).map_err(|e| {
                    tracing::error!(
                        "Error/short write while writing message headers to {}",
                        mbox_path.display()
                    );
                    SpoolError::Io(e)
                })?;
            }
        }

        // End headers: blank line separator.
        writer.write_all(b"\n").map_err(|e| {
            tracing::error!(
                "Error/short write while writing message headers to {}",
                mbox_path.display()
            );
            SpoolError::Io(e)
        })?;

        // Copy body from the -D file.
        copy_body_to_mbox(&mut writer, source_file_override, ctx, config, &mbox_path)?;

        // Flush and close the mbox file.
        writer.flush().map_err(|e| {
            tracing::error!("Error flushing mbox file {}", mbox_path.display());
            SpoolError::Io(e)
        })?;
        drop(writer);

        // Record the spooled message ID and set the mbox_ok flag.
        ctx.spooled_message_id = ctx.message_id.clone();
        ctx.spool_mbox_ok = true;
    }

    // Reopen the .eml file for reading and get its size.
    let yield_file = File::open(&mbox_path).map_err(|e| {
        tracing::error!("failed to open scan file {}: {}", mbox_path.display(), e);
        SpoolError::Io(e)
    })?;

    let metadata = yield_file.metadata().map_err(SpoolError::Io)?;
    let mbox_file_size = metadata.len();

    Ok((yield_file, mbox_file_size, mbox_path))
}

/// Copy the message body from the -D data file to the MBOX writer.
///
/// Handles three source cases:
/// 1. `source_file_override` — an explicitly provided alternative source file
/// 2. `ctx.spool_data_file` — the currently open spool data file (held by the
///    main receive process which holds the lock)
/// 3. Fallback — open the -D file from disk using the dual-pass directory search
///
/// When the source is the spool data file (cases 2 and 3), the reader seeks
/// past the data start offset before copying.  If `spool_file_wireformat` is
/// set, CRLF line endings are converted to LF.
#[cfg(feature = "content-scan")]
fn copy_body_to_mbox(
    writer: &mut BufWriter<File>,
    source_file_override: Option<&Path>,
    ctx: &MessageContext,
    config: &Config,
    mbox_path: &Path,
) -> Result<(), SpoolError> {
    // Determine the data source.
    if let Some(override_path) = source_file_override {
        // Case 1: Use the override file directly (no offset skip, no CRLF conversion).
        let src_file = File::open(override_path).map_err(|e| {
            tracing::error!(
                "Could not open override data file {}: {}",
                override_path.display(),
                e
            );
            SpoolError::Io(e)
        })?;
        let mut reader = BufReader::new(src_file);
        copy_stream(&mut reader, writer, false, mbox_path)?;
    } else {
        // Determine which file to read from.
        // We need a mutable reference to seek, but we cannot take the file
        // from ctx (it's borrowed immutably for content-scan).  Instead, we
        // open the -D file from disk.
        let data_file = open_data_file_for_mbox(&ctx.message_id, config)?;
        let mut reader = BufReader::new(data_file);

        // Seek past the data start offset (identity line: "{id}-D\n").
        let offset = spool_data_start_offset(&ctx.message_id) as u64;
        reader
            .seek(SeekFrom::Start(offset))
            .map_err(SpoolError::Io)?;

        // Copy with optional CRLF→LF conversion.
        copy_stream(&mut reader, writer, ctx.spool_file_wireformat, mbox_path)?;
    }

    Ok(())
}

/// Open the -D data file from disk using the dual-pass directory search.
///
/// Tries both split and unsplit directories to locate the file.
#[cfg(feature = "content-scan")]
fn open_data_file_for_mbox(message_id: &str, config: &Config) -> Result<File, SpoolError> {
    for i in 0..2usize {
        let subdir = set_subdir_str(message_id, i, config.split_spool_directory);
        let path = spool_fname(
            &config.spool_directory,
            &config.queue_name,
            "input",
            &subdir,
            message_id,
            "-D",
        );
        match File::open(&path) {
            Ok(f) => return Ok(f),
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(SpoolError::Io(e)),
        }
    }
    Err(SpoolError::NotFound {
        path: format!("data file for message {}", message_id),
    })
}

/// Copy data from a reader to a writer, optionally converting CRLF to LF.
///
/// When `wireformat` is `true`, performs line-by-line reading with CRLF→LF
/// conversion.  This matches the C behavior at `spool_mbox.c` lines 149–164.
///
/// When `wireformat` is `false`, performs a simple bulk copy.
#[cfg(feature = "content-scan")]
fn copy_stream(
    reader: &mut BufReader<File>,
    writer: &mut BufWriter<File>,
    wireformat: bool,
    mbox_path: &Path,
) -> Result<(), SpoolError> {
    if !wireformat {
        // Simple bulk copy.
        let mut buffer = [0u8; 16384];
        loop {
            let n = reader.read(&mut buffer).map_err(SpoolError::Io)?;
            if n == 0 {
                break;
            }
            writer.write_all(&buffer[..n]).map_err(|e| {
                tracing::error!(
                    "Error/short write while writing message body to {}",
                    mbox_path.display()
                );
                SpoolError::Io(e)
            })?;
        }
    } else {
        // Wire format: CRLF → LF conversion.
        // Read line by line using BufRead, converting \r\n to \n.
        let mut line_buf = String::new();
        loop {
            line_buf.clear();
            let bytes_read =
                io::BufRead::read_line(reader, &mut line_buf).map_err(SpoolError::Io)?;
            if bytes_read == 0 {
                break;
            }

            // Convert CRLF to LF: if line ends with \r\n, strip the \r.
            let output = if line_buf.ends_with("\r\n") {
                // Replace trailing \r\n with \n.
                &line_buf[..line_buf.len() - 2]
            } else if line_buf.ends_with('\r') {
                // Bare \r at end — the next read may have the \n.
                // Write without the trailing \r for now.
                &line_buf[..line_buf.len() - 1]
            } else {
                line_buf.as_str()
            };

            writer.write_all(output.as_bytes()).map_err(|e| {
                tracing::error!(
                    "Error/short write while writing message body to {}",
                    mbox_path.display()
                );
                SpoolError::Io(e)
            })?;

            // If we stripped \r\n, write the \n.
            if line_buf.ends_with("\r\n") {
                writer.write_all(b"\n").map_err(|e| {
                    tracing::error!(
                        "Error/short write while writing message body to {}",
                        mbox_path.display()
                    );
                    SpoolError::Io(e)
                })?;
            }
        }
    }

    Ok(())
}

/// Generate a simplified BSD-format timestamp for the MBOX `From ` line.
///
/// This produces a timestamp like `"Thu Jan  1 00:00:00 1970"` using only
/// the standard library (no external chrono dependency).
#[cfg(feature = "content-scan")]
fn chrono_free_bsd_time() -> String {
    // Use system time to get seconds since epoch, then format as BSD mailbox
    // time.  This is a simplified implementation; the C version uses
    // `tod_bsdinbox` which formats via `strftime("%a %b %d %H:%M:%S %Y")`.
    use std::time::SystemTime;

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;

    // Manual time decomposition (no external crate required).
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Compute year/month/day from days since epoch.
    let (year, month, day, weekday) = days_to_date(days);

    let weekday_names = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    let month_names = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let wday_idx = ((weekday % 7) + 7) % 7;
    let mon_idx = (month as usize).saturating_sub(1).min(11);

    format!(
        "{} {} {:2} {:02}:{:02}:{:02} {}",
        weekday_names[wday_idx as usize], month_names[mon_idx], day, hours, minutes, seconds, year
    )
}

/// Convert days since Unix epoch to (year, month, day, weekday).
///
/// Weekday: 0 = Thursday (Jan 1 1970 was a Thursday).
#[cfg(feature = "content-scan")]
fn days_to_date(days: i64) -> (i64, i64, i64, i64) {
    // Weekday: Jan 1 1970 was Thursday (day 0 = Thursday).
    let weekday = days % 7;

    // Civil calendar algorithm.
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    (year, m, d, weekday)
}

// =============================================================================
// Public API — unspool_mbox (content-scan feature)
// =============================================================================

/// Remove the MBOX spool file and its containing scan directory.
///
/// Resets the `spam_ok` and `malware_ok` flags, then — if an MBOX file was
/// previously created and `no_mbox_unspool` is not set — removes all files
/// in the scan directory and the directory itself.
///
/// ## Source
///
/// `src/src/spool_mbox.c` lines 205–245.
///
/// # Arguments
///
/// * `ctx` — Message context; `spool_mbox_ok`, `spam_ok`, and `malware_ok`
///   flags are reset.
/// * `config` — Configuration providing the spool directory path.
#[cfg(feature = "content-scan")]
pub fn unspool_mbox(ctx: &mut MessageContext, config: &Config) {
    // Reset scanning flags.
    ctx.spam_ok = false;
    ctx.malware_ok = false;

    if ctx.spool_mbox_ok && !ctx.no_mbox_unspool {
        let mbox_dir = format!("{}/scan/{}", config.spool_directory, ctx.spooled_message_id);
        let mbox_path = PathBuf::from(&mbox_dir);

        // Open directory and iterate entries, unlinking each file.
        match fs::read_dir(&mbox_path) {
            Ok(entries) => {
                for entry_result in entries {
                    match entry_result {
                        Ok(entry) => {
                            let name = entry.file_name();
                            let name_str = name.to_string_lossy();
                            if name_str == "." || name_str == ".." {
                                continue;
                            }
                            let file_path = mbox_path.join(&name);
                            tracing::debug!("unspool_mbox(): unlinking '{}'", file_path.display());
                            if let Err(e) = fs::remove_file(&file_path) {
                                tracing::error!("unlink({}): {}", file_path.display(), e);
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "error reading directory entry in {}: {}",
                                mbox_path.display(),
                                e
                            );
                        }
                    }
                }
            }
            Err(e) => {
                tracing::debug!("Unable to opendir({}): {}", mbox_path.display(), e);
                // Just in case we still can, try to remove the directory.
                let _ = fs::remove_dir(&mbox_path);
                ctx.spool_mbox_ok = false;
                return;
            }
        }

        // Remove the scan directory.
        if let Err(e) = fs::remove_dir(&mbox_path) {
            tracing::error!("rmdir({}): {}", mbox_path.display(), e);
        }
    }

    ctx.spool_mbox_ok = false;
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    /// Helper to create a test Config.
    fn test_config(spool_dir: &str) -> Config {
        Config {
            spool_directory: spool_dir.to_string(),
            queue_name: String::new(),
            split_spool_directory: false,
            exim_uid: nix::unistd::getuid().as_raw(),
            exim_gid: nix::unistd::getgid().as_raw(),
            queue_name_dest: None,
            queue_running: false,
        }
    }

    /// Helper to create a test MessageContext.
    fn test_message_context(id: &str) -> MessageContext {
        MessageContext {
            message_id: id.to_string(),
            message_body_size: 0,
            message_size: 0,
            message_subdir: String::new(),
            spool_data_file: None,
            spool_file_wireformat: false,
            #[cfg(feature = "content-scan")]
            spool_mbox_ok: false,
            #[cfg(feature = "content-scan")]
            no_mbox_unspool: false,
            #[cfg(feature = "content-scan")]
            spooled_message_id: String::new(),
            #[cfg(feature = "content-scan")]
            sender_address: None,
            #[cfg(feature = "content-scan")]
            return_path: None,
            #[cfg(feature = "content-scan")]
            recipients: None,
            #[cfg(feature = "content-scan")]
            header_list: Vec::new(),
            #[cfg(feature = "content-scan")]
            spam_ok: false,
            #[cfg(feature = "content-scan")]
            malware_ok: false,
        }
    }

    #[test]
    fn test_spool_write_error_receiving() {
        let err = spool_write_error(
            SpoolWriteContext::Receiving,
            "test-file",
            None,
            io::Error::other("disk full"),
        );
        match err {
            SpoolError::FormatError { context } => {
                assert!(context.contains("receiving"));
                assert!(context.contains("test-file"));
                assert!(context.contains("disk full"));
            }
            other => panic!("expected FormatError, got {:?}", other),
        }
    }

    #[test]
    fn test_spool_write_error_delivering() {
        let err = spool_write_error(
            SpoolWriteContext::Delivering,
            "deliver-file",
            None,
            io::Error::other("io error"),
        );
        match err {
            SpoolError::FormatError { context } => {
                assert!(context.contains("delivering"));
            }
            other => panic!("expected FormatError, got {:?}", other),
        }
    }

    #[test]
    fn test_spool_write_error_modifying() {
        let err = spool_write_error(
            SpoolWriteContext::Modifying,
            "mod-file",
            None,
            io::Error::other("fail"),
        );
        match err {
            SpoolError::FormatError { context } => {
                assert!(context.contains("modifying"));
            }
            other => panic!("expected FormatError, got {:?}", other),
        }
    }

    #[test]
    fn test_spool_write_error_with_temp_unlink() {
        let tmp = TempDir::new().unwrap();
        let temp_file = tmp.path().join("temp_to_unlink");
        fs::write(&temp_file, b"data").unwrap();
        assert!(temp_file.exists());

        let _err = spool_write_error(
            SpoolWriteContext::Receiving,
            "test",
            Some(&temp_file),
            io::Error::other("err"),
        );
        // The temp file should be cleaned up.
        assert!(!temp_file.exists());
    }

    #[test]
    fn test_spool_open_datafile_not_found() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path().to_str().unwrap());
        let mut ctx = test_message_context("1pBnKl-003F4x-Tw");

        let result = spool_open_datafile("1pBnKl-003F4x-Tw", &config, &mut ctx);
        assert!(result.is_err());
        match result.err().unwrap() {
            SpoolError::NotFound { .. } => {}
            other => panic!("expected NotFound, got {:?}", other),
        }
    }

    #[test]
    fn test_spool_open_datafile_success() {
        let tmp = TempDir::new().unwrap();
        let spool_dir = tmp.path().to_str().unwrap();
        let config = test_config(spool_dir);
        let mut ctx = test_message_context("1pBnKl-003F4x-Tw");

        // spool_fname produces "{spool_dir}//input//1pBnKl-003F4x-Tw-D"
        // (empty queue_name and empty subdir → double slashes, normalized by OS).
        // We must create the file at the same normalized path.
        let d_file_path = PathBuf::from(format!("{}/input/1pBnKl-003F4x-Tw-D", spool_dir));
        fs::create_dir_all(d_file_path.parent().unwrap()).unwrap();

        let mut f = File::create(&d_file_path).unwrap();
        writeln!(f, "1pBnKl-003F4x-Tw-D").unwrap();
        write!(f, "Hello, World!").unwrap();
        drop(f);

        let result = spool_open_datafile("1pBnKl-003F4x-Tw", &config, &mut ctx);
        assert!(result.is_ok(), "open failed: {:?}", result.err());

        // Verify body size calculation.
        let offset = spool_data_start_offset("1pBnKl-003F4x-Tw");
        let file_meta = fs::metadata(&d_file_path).unwrap();
        let expected_body = file_meta.len() - offset as u64;
        assert_eq!(ctx.message_body_size, expected_body);
        assert_eq!(ctx.message_size, expected_body + 1);
    }

    #[test]
    fn test_spool_open_temp_success() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path().to_str().unwrap());
        let temp_path = tmp.path().join("hdr.test_temp");

        let result = spool_open_temp(&temp_path, &config);
        assert!(result.is_ok(), "open_temp failed: {:?}", result.err());
        assert!(temp_path.exists());
    }

    #[test]
    fn test_spool_open_temp_eexist_retry() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path().to_str().unwrap());
        let temp_path = tmp.path().join("hdr.existing_temp");

        // Create the file first to trigger EEXIST.
        fs::write(&temp_path, b"old data").unwrap();

        let result = spool_open_temp(&temp_path, &config);
        assert!(result.is_ok(), "retry failed: {:?}", result.err());
    }

    #[test]
    fn test_make_link_and_break_link() {
        let tmp = TempDir::new().unwrap();
        let spool_dir = tmp.path().to_str().unwrap();

        // spool_fname(spool_dir, queue_name="", purpose="input", subdir="",
        //   fname="testid", suffix="-D") → "{spool_dir}//input//testid-D"
        // which the OS normalizes to "{spool_dir}/input/testid-D".
        let src_path = PathBuf::from(format!("{}/input/testid-D", spool_dir));
        fs::create_dir_all(src_path.parent().unwrap()).unwrap();
        fs::write(&src_path, b"data").unwrap();

        // make_link builds destination via spool_q_fname with
        // to="new" prepended to dir "input", so purpose="newinput":
        // "{spool_dir}//newinput//testid-D" → "{spool_dir}/newinput/testid-D"
        let dst_path = PathBuf::from(format!("{}/newinput/testid-D", spool_dir));
        fs::create_dir_all(dst_path.parent().unwrap()).unwrap();

        let result = make_link(
            "input", "", "", "testid", "-D", "", "new", spool_dir, "", false,
        );
        assert!(result.is_ok(), "make_link failed: {:?}", result.err());
        assert!(
            dst_path.exists(),
            "hard link not created at {}",
            dst_path.display()
        );

        // Break the source link.
        let result = break_link("input", "", "testid", "-D", "", spool_dir, "", false);
        assert!(result.is_ok(), "break_link failed: {:?}", result.err());
        assert!(!src_path.exists());
    }

    #[test]
    fn test_break_link_noentok() {
        let tmp = TempDir::new().unwrap();
        let spool_dir = tmp.path().to_str().unwrap();

        // Create directory but not the file.
        // break_link builds "{spool_dir}//msglog//nonexistent" → "{spool_dir}/msglog/nonexistent"
        let dir = PathBuf::from(format!("{}/msglog", spool_dir));
        fs::create_dir_all(&dir).unwrap();

        // Should succeed with noentok=true.
        let result = break_link("msglog", "", "nonexistent", "", "", spool_dir, "", true);
        assert!(result.is_ok());

        // Should fail with noentok=false.
        let result = break_link("msglog", "", "nonexistent", "", "", spool_dir, "", false);
        assert!(result.is_err());
    }

    #[cfg(feature = "content-scan")]
    #[test]
    fn test_chrono_free_bsd_time() {
        let time_str = chrono_free_bsd_time();
        // Should contain a 3-letter weekday, month, and year.
        assert!(time_str.len() > 20, "time string too short: {}", time_str);
        // Should contain a colon (time separator).
        assert!(
            time_str.contains(':'),
            "time string missing colon: {}",
            time_str
        );
    }

    #[cfg(feature = "content-scan")]
    #[test]
    fn test_days_to_date_epoch() {
        let (year, month, day, weekday) = days_to_date(0);
        assert_eq!(year, 1970);
        assert_eq!(month, 1);
        assert_eq!(day, 1);
        assert_eq!(weekday, 0); // Thursday
    }
}
