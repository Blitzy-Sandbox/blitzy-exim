//! # Journal File Management and Crash Recovery
//!
//! This module implements journal file management for crash recovery during
//! delivery processing. The journal file (`-J` suffix in spool) records
//! successfully completed deliveries as they happen, so that if Exim crashes
//! mid-delivery, the information about already-completed deliveries isn't lost.
//! On the next delivery attempt, the journal is read, and previously delivered
//! addresses are added to the nonrecipients tree, preventing duplicate delivery.
//!
//! ## C Source Mapping
//!
//! Translates journal-related code from `src/src/deliver.c`:
//!
//! | Rust type / function             | C origin (deliver.c)                           |
//! |----------------------------------|-------------------------------------------------|
//! | `JournalState`                   | `journal_fd` global + `remove_journal` static   |
//! | `JournalState::open_or_create()` | Journal creation (lines 8302–8346)              |
//! | `JournalState::write_delivery()` | Journal writing (lines 2532–2564)               |
//! | `JournalState::fsync_journal()`  | `EXIMfsync(journal_fd)` (lines 2560–2564)       |
//! | `JournalState::recover_from_journal()` | Journal recovery (lines 6867–6918)        |
//! | `JournalState::close_and_remove()` | Journal removal (lines 8918–8946)             |
//! | `JournalState::close_without_remove()` | Close without unlink (lines 8347–8351)    |
//! | `JournalState::set_remove_on_close()` | `remove_journal = FALSE` (line 4204)       |
//! | `JournalState::recover_and_update_spool()` | Combined recovery + spool update       |
//!
//! ## Design Patterns (AAP §0.4.2)
//!
//! - **Scoped context passing**: Recovery functions receive explicit context
//!   parameters (`MessageContext`, `ConfigContext`).
//! - **Spool integration**: Coordinates with `exim-spool` crate for header
//!   file updates during crash recovery.
//! - **RAII file descriptor management**: `OwnedFd` ensures the journal fd
//!   is closed on drop, preventing resource leaks.
//! - **O_APPEND atomicity**: Multiple delivery subprocesses can safely write
//!   to the journal concurrently (POSIX guarantees atomicity for small writes
//!   on O_APPEND files).
//!
//! ## Safety (AAP §0.7.2)
//!
//! This module contains **zero** `unsafe` code. All POSIX system calls are
//! performed through the `nix` crate's safe wrappers.

// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::io::OwnedFd;
use std::path::PathBuf;

use nix::fcntl::{open, OFlag};
use nix::sys::stat::{fchmod, Mode};
use nix::unistd::{dup, fchown, fsync, lseek, unlink, Whence};
use thiserror::Error;
use tracing::{debug, error};

use crate::orchestrator::AddressItem;
use exim_config::types::{ConfigContext, MessageContext};
use exim_spool::{spool_write_header, SpoolHeaderData, TreeNode, SPOOL_MODE};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Homonymous address flag — indicates an ancestor has the same address.
///
/// Matches the C `af_homonym` bitfield flag from `structs.h` line 620. When
/// set, journal entries include the transport name as a disambiguator:
/// `"{unique}/{transport_name}\n"` instead of `"{unique}\n"`.
///
/// This constant is defined locally because `AddressFlags` in the orchestrator
/// module does not yet export all C flag constants. The bit position (0x0400)
/// is the next available slot after the 10 flags already defined in
/// `AddressFlags` (0x0001 through 0x0200).
const AF_HOMONYM: u32 = 0x0000_0400;

// ---------------------------------------------------------------------------
// Error Type
// ---------------------------------------------------------------------------

/// Errors that can occur during journal file operations.
///
/// Each variant maps to a specific failure mode in the journal lifecycle:
/// creation, permission setting, writing, syncing, reading, removal, and
/// spool header update. This replaces the C-style `errno`/`strerror()` error
/// handling patterns found in `deliver.c` journal operations.
#[derive(Debug, Error)]
pub enum JournalError {
    /// Failed to create the journal file at the specified path.
    ///
    /// Typically caused by a missing spool directory, permission issues, or
    /// the file already existing (O_EXCL).
    #[error("failed to create journal file {path}: {source}")]
    CreateFailed {
        /// The journal file path that could not be created.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// Failed to set ownership or permissions on the journal file.
    ///
    /// After this error, the partially created journal file is unlinked to
    /// prevent leaving a file with incorrect permissions in the spool.
    #[error("failed to set permissions on journal file {path}: {source}")]
    PermissionFailed {
        /// The journal file path where permissions could not be set.
        path: String,
        /// The underlying I/O error from fchown or fchmod.
        source: std::io::Error,
    },

    /// Failed to write a delivery entry to the journal file.
    ///
    /// In C, this is logged as a panic-worthy error but delivery continues
    /// because it may still be possible to update the spool header later.
    #[error("failed to write to journal: {0}")]
    WriteFailed(std::io::Error),

    /// Failed to fsync the journal file to disk.
    ///
    /// Data written to the journal may not be durable after this error.
    #[error("failed to fsync journal: {0}")]
    FsyncFailed(std::io::Error),

    /// Failed to read from the journal file during crash recovery.
    #[error("failed to read journal: {0}")]
    ReadFailed(std::io::Error),

    /// Failed to remove (unlink) the journal file after delivery completion.
    ///
    /// ENOENT is handled gracefully (the file may have already been removed);
    /// other errors are propagated as this variant.
    #[error("failed to remove journal file: {0}")]
    RemoveFailed(std::io::Error),

    /// The spool header update after journal recovery failed.
    ///
    /// This means the recovered nonrecipient addresses could not be persisted
    /// to the `-H` file, and the next delivery attempt may re-deliver.
    #[error("spool header update failed: {0}")]
    SpoolUpdateFailed(String),
}

// ---------------------------------------------------------------------------
// JournalState
// ---------------------------------------------------------------------------

/// State manager for the per-message journal file.
///
/// The journal file is created when delivery begins and records each
/// successfully completed delivery address. If the delivery process crashes,
/// the journal file survives and is read on the next attempt to prevent
/// duplicate delivery.
///
/// ## File Descriptor Lifecycle
///
/// The journal fd is wrapped in `Option<OwnedFd>` for RAII management:
/// - `None` — no journal file is open
/// - `Some(fd)` — journal file is open and ready for writing
///
/// When the `OwnedFd` is dropped (via `take()` or struct drop), the fd is
/// automatically closed. The `Drop` impl on `OwnedFd` handles this.
///
/// ## Concurrency
///
/// The journal is opened with `O_APPEND`, which guarantees atomicity for
/// writes smaller than `PIPE_BUF` (typically 4096 bytes on Linux). Since
/// journal entries are short address lines (< 512 bytes), concurrent writes
/// from multiple delivery subprocesses are safe.
pub struct JournalState {
    /// The journal file descriptor, if the journal is currently open.
    /// Uses `OwnedFd` for RAII — the fd is closed when this field is
    /// set to `None` or when the `JournalState` is dropped.
    fd: Option<OwnedFd>,

    /// Whether to remove the journal file when closing.
    ///
    /// Defaults to `true`. Set to `false` when a delivery subprocess fails
    /// to pass back information (C: `remove_journal = FALSE` at deliver.c
    /// line 4204), preserving the journal for the next delivery attempt.
    remove_on_close: bool,

    /// Filesystem path to the current journal file.
    ///
    /// Set when the journal is opened (either created or opened for recovery).
    /// Used for unlink operations during close.
    path: Option<PathBuf>,
}

impl Default for JournalState {
    fn default() -> Self {
        Self::new()
    }
}

impl JournalState {
    /// Create a new `JournalState` with no open journal.
    ///
    /// The journal starts in a closed state with `remove_on_close` defaulting
    /// to `true`, matching the C initialization at deliver.c line 6791:
    /// `remove_journal = TRUE`.
    pub fn new() -> Self {
        Self {
            fd: None,
            remove_on_close: true,
            path: None,
        }
    }

    /// Create or open the journal file for a message delivery attempt.
    ///
    /// Translates C journal creation logic from deliver.c lines 8302–8346.
    ///
    /// The file is created with:
    /// - `O_WRONLY | O_APPEND | O_CREAT | O_EXCL` — write-only, append mode,
    ///   create new (fail if exists)
    /// - `O_CLOEXEC` — close on exec to prevent fd leaks to child processes
    /// - `O_NOFOLLOW` — refuse to follow symlinks (security hardening)
    /// - Mode `SPOOL_MODE` (0640) — owner read/write, group read
    /// - Ownership set to `exim_uid:exim_gid` via `fchown()`
    ///
    /// On permission failure (fchown or fchmod), the partially created file is
    /// unlinked before returning the error.
    ///
    /// # Arguments
    ///
    /// * `message_id` — The message ID (e.g., `"1pBnKl-003F4x-Tw"`).
    /// * `message_subdir` — The spool subdirectory (empty string if not split).
    /// * `spool_directory` — The base spool directory path.
    /// * `exim_uid` — The Exim user ID for file ownership.
    /// * `exim_gid` — The Exim group ID for file ownership.
    pub fn open_or_create(
        &mut self,
        message_id: &str,
        message_subdir: &str,
        spool_directory: &str,
        exim_uid: u32,
        exim_gid: u32,
    ) -> Result<(), JournalError> {
        let path = journal_path(spool_directory, message_subdir, message_id);
        let path_str = path.display().to_string();

        // Open flags matching C: EXIM_CLOEXEC | O_WRONLY|O_APPEND|O_CREAT|O_EXCL
        // Plus O_NOFOLLOW for security hardening
        let oflags = OFlag::O_WRONLY
            | OFlag::O_APPEND
            | OFlag::O_CREAT
            | OFlag::O_EXCL
            | OFlag::O_CLOEXEC
            | OFlag::O_NOFOLLOW;

        let mode = Mode::from_bits_truncate(SPOOL_MODE);

        let fd = open(&path, oflags, mode).map_err(|e| {
            let io_err = io_error_from_nix(e);
            error!(path = %path_str, error = %io_err, "couldn't open journal file");
            JournalError::CreateFailed {
                path: path_str.clone(),
                source: io_err,
            }
        })?;

        debug!(path = %path_str, "created journal file");

        // Set ownership to exim_uid:exim_gid (C: exim_fchown at line 8330)
        let uid = nix::unistd::Uid::from_raw(exim_uid);
        let gid = nix::unistd::Gid::from_raw(exim_gid);

        if let Err(e) = fchown(&fd, Some(uid), Some(gid)) {
            // On permission failure, unlink the created file and return error
            // (C: Uunlink(fname) at line 8337)
            let _ = unlink(&path);
            let io_err = io_error_from_nix(e);
            error!(
                path = %path_str,
                error = %io_err,
                "couldn't set perms on journal file"
            );
            return Err(JournalError::PermissionFailed {
                path: path_str,
                source: io_err,
            });
        }

        // Set mode explicitly — group setting doesn't always propagate
        // (C: fchmod(journal_fd, SPOOL_MODE) at line 8331)
        if let Err(e) = fchmod(&fd, mode) {
            let _ = unlink(&path);
            let io_err = io_error_from_nix(e);
            error!(
                path = %path_str,
                error = %io_err,
                "couldn't set perms on journal file"
            );
            return Err(JournalError::PermissionFailed {
                path: path_str,
                source: io_err,
            });
        }

        self.fd = Some(fd);
        self.path = Some(path);
        self.remove_on_close = true;

        Ok(())
    }

    /// Record a successful delivery to the journal file.
    ///
    /// Translates C journal writing from deliver.c lines 2532–2564.
    ///
    /// ## Entry Format
    ///
    /// - Normal addresses: `"{unique_address}\n"`
    /// - Homonymous addresses (af_homonym flag set):
    ///   `"{unique_address}/{transport_name}\n"`
    ///
    /// The homonym format appends the transport name as a disambiguator when
    /// multiple addresses in the same domain resolve to the same unique value
    /// but are delivered by different transports.
    ///
    /// ## Atomicity
    ///
    /// The journal was opened with `O_APPEND`, so writes are atomic for
    /// entries smaller than `PIPE_BUF` (typically 4096 bytes). Journal entries
    /// are always short (< 512 bytes), so concurrent writes from parallel
    /// delivery subprocesses are safe.
    ///
    /// # Arguments
    ///
    /// * `addr` — The address item that was successfully delivered.
    /// * `transport_name` — Name of the transport that completed delivery.
    pub fn write_delivery(
        &self,
        addr: &AddressItem,
        transport_name: &str,
    ) -> Result<(), JournalError> {
        let fd = match &self.fd {
            Some(fd) => fd,
            None => {
                // No journal open — this can happen if all addresses were
                // deferred at routing/directing stage. Silently return.
                return Ok(());
            }
        };

        // Format the journal entry:
        // - Homonymous addresses: "{unique}/{transport_name}\n"
        //   (C: sprintf(CS big_buffer, "%.500s/%s\n", addr2->unique + 3, trname))
        // - Normal addresses: "{unique}\n"
        //   (C: sprintf(CS big_buffer, "%.500s\n", addr2->unique))
        let entry = if addr.flags.contains(AF_HOMONYM) {
            format!("{}/{}\n", addr.unique, transport_name)
        } else {
            format!("{}\n", addr.unique)
        };

        // Log the journal write (C: DEBUG(D_deliver) debug_printf("journalling %s"))
        debug!(address = %entry.trim_end(), "journalling");

        // Write to journal fd. O_APPEND guarantees atomicity for small writes.
        let bytes = entry.as_bytes();
        let written = nix::unistd::write(fd, bytes).map_err(|e| {
            let io_err = io_error_from_nix(e);
            error!(
                entry = %entry.trim_end(),
                error = %io_err,
                "failed to update journal"
            );
            JournalError::WriteFailed(io_err)
        })?;

        // Verify complete write
        if written != bytes.len() {
            let err = std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                format!(
                    "short write to journal: {} of {} bytes",
                    written,
                    bytes.len()
                ),
            );
            error!(
                written = written,
                expected = bytes.len(),
                "short write to journal"
            );
            return Err(JournalError::WriteFailed(err));
        }

        Ok(())
    }

    /// Flush the journal file to disk for durability.
    ///
    /// Translates C: `EXIMfsync(journal_fd)` from deliver.c lines 2560–2564.
    ///
    /// Called after writing delivery results for a batch of local deliveries
    /// to ensure the data is durable on disk before proceeding. Without fsync,
    /// a system crash could lose journal entries that were written to the page
    /// cache but not yet flushed to stable storage.
    pub fn fsync_journal(&self) -> Result<(), JournalError> {
        if let Some(fd) = &self.fd {
            fsync(fd).map_err(|e| {
                let io_err = io_error_from_nix(e);
                error!(error = %io_err, "failed to fsync journal");
                JournalError::FsyncFailed(io_err)
            })?;
        }
        Ok(())
    }

    /// Read previously delivered addresses from the journal file.
    ///
    /// Translates C journal recovery from deliver.c lines 6867–6918.
    ///
    /// If a previous delivery attempt crashed before updating the spool `-H`
    /// file, the journal file contains the list of addresses that were
    /// successfully delivered. This function reads those addresses so the
    /// caller can add them to the nonrecipients tree to prevent re-delivery.
    ///
    /// After reading, the journal file remains open in append mode so that
    /// new deliveries in the current attempt can be recorded.
    ///
    /// ## ENOENT Handling
    ///
    /// If the journal file does not exist (`ENOENT`), this is not an error —
    /// it simply means this is the first delivery attempt. An empty `Vec` is
    /// returned.
    ///
    /// # Arguments
    ///
    /// * `message_id` — The message ID.
    /// * `message_subdir` — The spool subdirectory.
    /// * `spool_directory` — The base spool directory path.
    ///
    /// # Returns
    ///
    /// A `Vec<String>` of previously delivered addresses read from the journal.
    /// Each entry is a complete address (or `address/transport` for homonyms).
    pub fn recover_from_journal(
        &mut self,
        message_id: &str,
        message_subdir: &str,
        spool_directory: &str,
    ) -> Result<Vec<String>, JournalError> {
        let path = journal_path(spool_directory, message_subdir, message_id);

        // Open with O_RDWR | O_APPEND for both reading existing entries and
        // appending new ones. O_CLOEXEC and O_NOFOLLOW for security.
        // (C: Uopen(fname, O_RDWR|O_APPEND | EXIM_CLOEXEC | EXIM_NOFOLLOW, SPOOL_MODE))
        let oflags = OFlag::O_RDWR | OFlag::O_APPEND | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW;

        let mode = Mode::from_bits_truncate(SPOOL_MODE);

        let fd = match open(&path, oflags, mode) {
            Ok(fd) => fd,
            Err(nix::errno::Errno::ENOENT) => {
                // No journal file — first delivery attempt, not an error
                return Ok(Vec::new());
            }
            Err(e) => {
                let io_err = io_error_from_nix(e);
                error!(
                    path = %path.display(),
                    error = %io_err,
                    "attempt to open journal for reading gave error"
                );
                return Err(JournalError::ReadFailed(io_err));
            }
        };

        // Seek to beginning for reading
        // (C: lseek(journal_fd, 0, SEEK_SET) at line 6882)
        lseek(&fd, 0, Whence::SeekSet)
            .map_err(|e| JournalError::ReadFailed(io_error_from_nix(e)))?;

        // Dup the fd for reading — we need to create a File for BufReader,
        // but File::from(OwnedFd) would consume the fd. So we dup first,
        // keeping the original fd for continued appends.
        // (C: journal_fd = dup(fileno(jread)) at line 6895)
        let read_fd = dup(&fd).map_err(|e| JournalError::ReadFailed(io_error_from_nix(e)))?;

        // Seek the dup'd fd to the beginning for reading
        lseek(&read_fd, 0, Whence::SeekSet)
            .map_err(|e| JournalError::ReadFailed(io_error_from_nix(e)))?;

        // Convert the dup'd OwnedFd to a File for BufReader.
        // OwnedFd -> File is a safe conversion via From trait.
        let read_file = std::fs::File::from(read_fd);
        let reader = BufReader::new(read_file);

        // Read line by line: each line is a previously delivered address
        // (C: while (Ufgets(big_buffer, big_buffer_size, jread)) at line 6886)
        let mut addresses = Vec::new();
        for line_result in reader.lines() {
            let line = line_result.map_err(JournalError::ReadFailed)?;
            // Strip trailing whitespace (the newline was already removed by lines())
            let trimmed = line.trim_end();
            if !trimmed.is_empty() {
                addresses.push(trimmed.to_string());
            }
        }
        // read_file is dropped here, closing the dup'd fd

        // Store the original fd for continued appends in this delivery attempt
        self.fd = Some(fd);
        self.path = Some(path);

        Ok(addresses)
    }

    /// Perform combined journal recovery and spool header update.
    ///
    /// This is a high-level function that combines journal reading with spool
    /// file persistence. It is called during delivery initialization to recover
    /// from a previous crash.
    ///
    /// ## Steps
    ///
    /// 1. Call [`recover_from_journal()`](Self::recover_from_journal) to read
    ///    previously delivered addresses.
    /// 2. Add each recovered address to the `nonrecipients` set (equivalent to
    ///    C `tree_add_nonrecipient()`).
    /// 3. Log each recovered address at debug level.
    /// 4. Call `spool_write_header()` via `exim-spool` to update the `-H` file
    ///    with the new nonrecipient entries.
    /// 5. The journal remains open for continued appends during this delivery
    ///    attempt.
    ///
    /// # Arguments
    ///
    /// * `message_id` — The message ID.
    /// * `message_subdir` — The spool subdirectory.
    /// * `spool_directory` — The base spool directory path.
    /// * `nonrecipients` — Mutable set of nonrecipient addresses to update.
    /// * `msg_ctx` — Per-message context providing header/recipient data.
    /// * `config` — Configuration context providing spool directory settings.
    pub fn recover_and_update_spool(
        &mut self,
        message_id: &str,
        message_subdir: &str,
        spool_directory: &str,
        nonrecipients: &mut HashSet<String>,
        msg_ctx: &mut MessageContext,
        config: &ConfigContext,
    ) -> Result<(), JournalError> {
        // Step 1: Read journal entries
        let addresses = self.recover_from_journal(message_id, message_subdir, spool_directory)?;

        if addresses.is_empty() {
            return Ok(());
        }

        // Step 2 & 3: Add each address to nonrecipients and log
        for addr in &addresses {
            nonrecipients.insert(addr.clone());
            debug!(
                address = %addr,
                "Previously delivered address taken from journal file"
            );
        }

        // Step 4: Write updated spool header
        // Build a TreeNode BST from the nonrecipients set for the spool header.
        let tree = build_nonrecipient_tree(nonrecipients);

        // Construct SpoolHeaderData from available message context.
        // The SpoolWriteContext::Delivering indicates we are updating during
        // delivery (C: SW_DELIVERING at line 6901).
        let mut header_data = SpoolHeaderData {
            message_id: message_id.to_string(),
            originator_login: String::new(),
            sender_address: msg_ctx.sender_address.clone(),
            received_time_sec: 0,
            headers: Vec::new(),
            recipients: Vec::new(),
            non_recipients_tree: tree,
            host_address: None,
            host_name: None,
            interface_address: None,
            received_protocol: None,
            sender_ident: None,
        };

        // Populate recipients from message context
        for recip in &msg_ctx.recipients {
            header_data.recipients.push(exim_spool::RecipientItem {
                address: recip.clone(),
                pno: -1,
                errors_to: None,
                orcpt: None,
                dsn_flags: 0,
            });
        }

        // Populate headers from message context
        for hdr_text in &msg_ctx.headers {
            header_data.headers.push(exim_spool::HeaderLine {
                text: hdr_text.clone(),
                slen: hdr_text.len(),
                header_type: ' ',
            });
        }

        // Write the updated header to the -H file path
        let h_path = build_spool_header_path(&config.spool_directory, message_subdir, message_id);

        // Write to a temp file first, then rename for atomicity
        let temp_path = h_path.with_extension("H.new");

        let temp_file = fs::File::create(&temp_path).map_err(|e| {
            JournalError::SpoolUpdateFailed(format!(
                "failed to create temp spool header {}: {}",
                temp_path.display(),
                e
            ))
        })?;

        spool_write_header(&header_data, temp_file).map_err(|e| {
            // Clean up temp file on failure
            let _ = fs::remove_file(&temp_path);
            JournalError::SpoolUpdateFailed(format!("failed to write spool header: {}", e))
        })?;

        // Atomic rename: temp file -> actual -H file
        fs::rename(&temp_path, &h_path).map_err(|e| {
            let _ = fs::remove_file(&temp_path);
            JournalError::SpoolUpdateFailed(format!(
                "failed to rename spool header {} -> {}: {}",
                temp_path.display(),
                h_path.display(),
                e
            ))
        })?;

        debug!(
            message_id = %message_id,
            recovered_count = addresses.len(),
            "updated spool header after journal recovery"
        );

        // Step 5: Journal remains open for continued appends
        Ok(())
    }

    /// Close the journal file and optionally remove it.
    ///
    /// Translates C journal removal from deliver.c lines 8918–8946.
    ///
    /// The journal fd is closed first (via `OwnedFd` drop). If
    /// `remove_on_close` is `true`, the journal file is unlinked. ENOENT
    /// during unlink is silently ignored (the file may not exist if no
    /// deliveries were journalled).
    ///
    /// On other unlink errors, this function returns an error (matching the
    /// C `log_write_die` behavior at line 8937).
    ///
    /// When the journal is NOT removed (due to a subprocess communication
    /// failure), the frozen message also should not be moved off spool —
    /// this is handled by the caller.
    pub fn close_and_remove(&mut self) -> Result<(), JournalError> {
        // Close the fd first by taking ownership (OwnedFd drop closes it)
        // (C: close(journal_fd) at line 8930)
        let _ = self.fd.take();

        if self.remove_on_close {
            if let Some(path) = &self.path {
                // Unlink the journal file
                // (C: Uunlink(fname) at line 8936)
                match unlink(path) {
                    Ok(()) => {
                        debug!(path = %path.display(), "removed journal file");
                    }
                    Err(nix::errno::Errno::ENOENT) => {
                        // File doesn't exist — that's fine, it may never have
                        // been created if all addresses were deferred at routing
                    }
                    Err(e) => {
                        let io_err = io_error_from_nix(e);
                        error!(
                            path = %path.display(),
                            error = %io_err,
                            "failed to unlink journal file"
                        );
                        return Err(JournalError::RemoveFailed(io_err));
                    }
                }

                // Handle move-frozen feature: if the message is frozen and
                // move_frozen_messages is configured, move it off the main spool.
                // (C: #ifdef SUPPORT_MOVE_FROZEN_MESSAGES at line 8942)
                // This is delegated to the caller via the return value; the
                // caller checks deliver_freeze && move_frozen_messages and calls
                // spool_move_message() as needed.
            }
        }

        // Reset state
        self.path = None;
        self.remove_on_close = true;

        Ok(())
    }

    /// Close the journal file without removing it.
    ///
    /// Translates C logic from deliver.c lines 8347–8351. Used when no
    /// deliveries were needed (no local or remote addresses to deliver) but
    /// the journal file was opened from a previous recovery.
    ///
    /// The journal fd is closed via `OwnedFd` drop but the file is preserved
    /// on disk.
    pub fn close_without_remove(&mut self) {
        // Close the fd (C: close(journal_fd); journal_fd = -1)
        let _ = self.fd.take();
        // Do NOT remove the file and do NOT reset path or remove_on_close
    }

    /// Control whether the journal file is removed on close.
    ///
    /// Set to `false` when a delivery subprocess fails to pass back delivery
    /// information (C: `remove_journal = FALSE` at deliver.c line 4204). When
    /// the subprocess exits abnormally, we cannot know whether deliveries
    /// actually succeeded, so the journal must be preserved for the next
    /// delivery attempt to read.
    ///
    /// # Arguments
    ///
    /// * `remove` — `true` to remove journal on close (default), `false` to
    ///   preserve it for crash recovery.
    pub fn set_remove_on_close(&mut self, remove: bool) {
        self.remove_on_close = remove;
        if !remove {
            debug!("journal removal disabled — will be preserved for next attempt");
        }
    }
}

// ---------------------------------------------------------------------------
// Path Helper
// ---------------------------------------------------------------------------

/// Construct the filesystem path for a journal file.
///
/// Produces: `{spool_directory}/input/{message_subdir}/{message_id}-J`
///
/// If `message_subdir` is empty (non-split spool), the path omits the
/// subdirectory component: `{spool_directory}/input/{message_id}-J`
///
/// This matches the C `spool_fname(US"input", message_subdir, id, US"-J")`
/// call pattern used throughout deliver.c.
fn journal_path(spool_directory: &str, message_subdir: &str, message_id: &str) -> PathBuf {
    let mut path = PathBuf::from(spool_directory);
    path.push("input");
    if !message_subdir.is_empty() {
        path.push(message_subdir);
    }
    path.push(format!("{}-J", message_id));
    path
}

/// Construct the filesystem path for a spool header (-H) file.
///
/// Produces: `{spool_directory}/input/{message_subdir}/{message_id}-H`
fn build_spool_header_path(
    spool_directory: &str,
    message_subdir: &str,
    message_id: &str,
) -> PathBuf {
    let mut path = PathBuf::from(spool_directory);
    path.push("input");
    if !message_subdir.is_empty() {
        path.push(message_subdir);
    }
    path.push(format!("{}-H", message_id));
    path
}

// ---------------------------------------------------------------------------
// Nonrecipient Tree Builder
// ---------------------------------------------------------------------------

/// Build a balanced binary tree of nonrecipient addresses from a `HashSet`.
///
/// The Exim spool `-H` file stores nonrecipients as a binary tree. This
/// function converts the flat `HashSet<String>` (used for O(1) membership
/// checks during delivery) into a `TreeNode` structure suitable for spool
/// serialization.
///
/// The addresses are first sorted to produce a balanced BST via recursive
/// median splitting, which is the same strategy used by the C `tree_add`
/// function when addresses are added in a favorable order.
fn build_nonrecipient_tree(nonrecipients: &HashSet<String>) -> Option<TreeNode> {
    if nonrecipients.is_empty() {
        return None;
    }

    let mut sorted: Vec<&String> = nonrecipients.iter().collect();
    sorted.sort();

    Some(build_balanced_tree(&sorted))
}

/// Recursively build a balanced BST from a sorted slice of addresses.
fn build_balanced_tree(sorted: &[&String]) -> TreeNode {
    if sorted.len() == 1 {
        return TreeNode::leaf(sorted[0].as_str());
    }

    let mid = sorted.len() / 2;
    let left_slice = &sorted[..mid];
    let right_slice = &sorted[mid + 1..];

    let left = if left_slice.is_empty() {
        None
    } else {
        Some(Box::new(build_balanced_tree(left_slice)))
    };

    let right = if right_slice.is_empty() {
        None
    } else {
        Some(Box::new(build_balanced_tree(right_slice)))
    };

    TreeNode {
        name: sorted[mid].clone(),
        left,
        right,
    }
}

// ---------------------------------------------------------------------------
// Nix-to-io error conversion helper
// ---------------------------------------------------------------------------

/// Convert a `nix::errno::Errno` into a `std::io::Error`.
///
/// This helper bridges the gap between the `nix` crate's error type and the
/// standard library's `io::Error`, allowing journal error variants to wrap
/// `std::io::Error` consistently.
fn io_error_from_nix(errno: nix::errno::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(errno as i32)
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_journal_path_with_subdir() {
        let path = journal_path("/var/spool/exim", "ab", "1pBnKl-003F4x-Tw");
        assert_eq!(
            path,
            PathBuf::from("/var/spool/exim/input/ab/1pBnKl-003F4x-Tw-J")
        );
    }

    #[test]
    fn test_journal_path_without_subdir() {
        let path = journal_path("/var/spool/exim", "", "1pBnKl-003F4x-Tw");
        assert_eq!(
            path,
            PathBuf::from("/var/spool/exim/input/1pBnKl-003F4x-Tw-J")
        );
    }

    #[test]
    fn test_spool_header_path() {
        let path = build_spool_header_path("/var/spool/exim", "ab", "1pBnKl-003F4x-Tw");
        assert_eq!(
            path,
            PathBuf::from("/var/spool/exim/input/ab/1pBnKl-003F4x-Tw-H")
        );
    }

    #[test]
    fn test_journal_state_new() {
        let state = JournalState::new();
        assert!(state.fd.is_none());
        assert!(state.remove_on_close);
        assert!(state.path.is_none());
    }

    #[test]
    fn test_set_remove_on_close() {
        let mut state = JournalState::new();
        assert!(state.remove_on_close);
        state.set_remove_on_close(false);
        assert!(!state.remove_on_close);
        state.set_remove_on_close(true);
        assert!(state.remove_on_close);
    }

    #[test]
    fn test_close_without_remove_noop() {
        let mut state = JournalState::new();
        // Closing with no fd should be a no-op
        state.close_without_remove();
        assert!(state.fd.is_none());
    }

    #[test]
    fn test_close_and_remove_noop() {
        let mut state = JournalState::new();
        // Closing with no fd and no path should be a no-op
        let result = state.close_and_remove();
        assert!(result.is_ok());
        assert!(state.fd.is_none());
        assert!(state.path.is_none());
    }

    #[test]
    fn test_write_delivery_no_fd() {
        let state = JournalState::new();
        let addr = create_test_address("user@example.com", false);
        // Writing with no fd should silently succeed
        let result = state.write_delivery(&addr, "smtp");
        assert!(result.is_ok());
    }

    #[test]
    fn test_recover_from_journal_enoent() {
        let mut state = JournalState::new();
        // Recovery with non-existent journal should return empty Vec
        let result =
            state.recover_from_journal("nonexistent-msg", "", "/tmp/nonexistent-spool-dir-xxxyyy");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_build_nonrecipient_tree_empty() {
        let set = HashSet::new();
        let tree = build_nonrecipient_tree(&set);
        assert!(tree.is_none());
    }

    #[test]
    fn test_build_nonrecipient_tree_single() {
        let mut set = HashSet::new();
        set.insert("user@example.com".to_string());
        let tree = build_nonrecipient_tree(&set);
        assert!(tree.is_some());
        let node = tree.unwrap();
        assert_eq!(node.name, "user@example.com");
        assert!(node.left.is_none());
        assert!(node.right.is_none());
    }

    #[test]
    fn test_build_nonrecipient_tree_multiple() {
        let mut set = HashSet::new();
        set.insert("alpha@example.com".to_string());
        set.insert("beta@example.com".to_string());
        set.insert("gamma@example.com".to_string());
        let tree = build_nonrecipient_tree(&set);
        assert!(tree.is_some());
        let root = tree.unwrap();
        // The root should be the median of sorted addresses
        assert_eq!(root.name, "beta@example.com");
        assert!(root.left.is_some());
        assert!(root.right.is_some());
    }

    #[test]
    fn test_journal_error_display() {
        let err = JournalError::CreateFailed {
            path: "/tmp/test-J".to_string(),
            source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("failed to create journal file"));
        assert!(msg.contains("/tmp/test-J"));

        let err = JournalError::WriteFailed(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "broken",
        ));
        let msg = format!("{}", err);
        assert!(msg.contains("failed to write to journal"));

        let err = JournalError::SpoolUpdateFailed("test failure".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("spool header update failed"));
    }

    /// Helper to create a test AddressItem for unit testing.
    fn create_test_address(address: &str, homonym: bool) -> AddressItem {
        use crate::orchestrator::{AddressFlags, AddressProperties};
        use exim_store::Tainted;

        let (local_part, domain) = if let Some(at) = address.rfind('@') {
            (
                address[..at].to_string(),
                address[at + 1..].to_ascii_lowercase(),
            )
        } else {
            (address.to_string(), String::new())
        };

        let mut flags = AddressFlags::default();
        if homonym {
            flags.set(AF_HOMONYM);
        }

        AddressItem {
            address: Tainted::new(address.to_string()),
            domain,
            local_part,
            home_dir: None,
            current_dir: None,
            errors_address: None,
            host_list: Vec::new(),
            router: None,
            transport: None,
            prop: AddressProperties::default(),
            flags,
            message: None,
            basic_errno: 0,
            more_errno: 0,
            dsn_flags: 0,
            dsn_orcpt: None,
            dsn_aware: 0,
            return_path: None,
            uid: 0,
            gid: 0,
            unique: address.to_ascii_lowercase(),
            parent_index: -1,
            children: Vec::new(),
            prefix: None,
            suffix: None,
            onetime_parent: None,
        }
    }
}
