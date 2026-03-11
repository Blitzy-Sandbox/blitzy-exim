//! Queuefile transport — experimental spool file mover.
//!
//! Copies existing spool `-H` (header) and `-D` (data) files into a target
//! directory. This is the simplest transport driver in Exim. Feature-gated
//! behind `transport-queuefile` (NOT in default features).
//!
//! Faithfully rewrites `src/src/transports/queuefile.c` (313 lines) and
//! `src/src/transports/queuefile.h` (31 lines) from C to Rust.
//!
//! # Safety model
//!
//! All directory and file operations use `nix` crate safe wrappers for
//! POSIX `openat`, `linkat`, `fstat`, and `fchmod` — there is zero `unsafe`
//! code in this module, per AAP §0.7.2.
//!
//! # Cross-filesystem handling
//!
//! On same-filesystem scenarios (detected by comparing `st_dev` from `fstat`),
//! the transport attempts `linkat()` for an atomic hard link. If the
//! directories reside on different filesystems — or `linkat()` fails for any
//! other reason — it falls back to `openat()` + buffered copy with a 16 384-byte
//! buffer, matching the C implementation exactly.
//!
//! # Cleanup on partial failure
//!
//! If the data file copy fails after the header file has already been placed,
//! the already-created header is removed from the destination directory to
//! avoid leaving partial state.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsFd;
use std::path::Path;

use nix::fcntl::{self, AtFlags, OFlag};
use nix::sys::stat::{fchmod, fstat, Mode};
use nix::unistd::linkat;

use serde::Deserialize;
use tracing::{debug, error, warn};

use exim_drivers::transport_driver::{
    TransportDriver, TransportDriverFactory, TransportInstanceConfig, TransportResult,
};
use exim_drivers::DriverError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Buffer size for the file copy fallback path (matches C `buffer[16384]`).
const COPY_BUFFER_SIZE: usize = 16_384;

/// Spool file permission bits (0640 — owner rw, group r).
/// Matches `SPOOL_MODE` from the C Exim codebase.
const SPOOL_MODE: u32 = 0o640;

// ---------------------------------------------------------------------------
// Configuration options
// ---------------------------------------------------------------------------

/// Configuration options for the queuefile transport.
///
/// Maps to C `queuefile_transport_options_block` from `queuefile.h`.
/// The single config-file option `"directory"` maps to the `dirname` field.
///
/// Two additional runtime fields (`message_id` and `spool_directory`) are set
/// by the delivery orchestrator before invoking `transport_entry`. They carry
/// per-message context that was previously accessed via C globals.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct QueuefileTransportOptions {
    /// Target directory for spool file copies.
    ///
    /// Set from the Exim configuration file via the `"directory"` option name.
    /// **Required** — validated during transport init; a missing value triggers
    /// a `DriverError::ConfigError`.
    #[serde(alias = "directory")]
    pub dirname: Option<String>,

    /// Runtime: message ID of the message currently being processed.
    ///
    /// Set by the delivery orchestrator before calling `transport_entry`.
    /// Not deserialized from the config file.
    #[serde(skip)]
    pub message_id: Option<String>,

    /// Runtime: spool directory path (e.g., `/var/spool/exim`).
    ///
    /// Set by the delivery orchestrator before calling `transport_entry`.
    /// Not deserialized from the config file.
    #[serde(skip)]
    pub spool_directory: Option<String>,
}

// ---------------------------------------------------------------------------
// Transport struct
// ---------------------------------------------------------------------------

/// Queuefile transport driver.
///
/// An experimental transport that copies spool files (`-H` header and `-D`
/// data) into a named target directory. This is a *local* transport — no
/// network I/O is involved.
///
/// Registered via `inventory::submit!` for compile-time discovery by the
/// driver registry, replacing the C `queuefile_transport_info` struct from
/// `drtables.c`.
#[derive(Debug, Default)]
pub struct QueuefileTransport;

impl QueuefileTransport {
    /// Create a new `QueuefileTransport` instance with default (empty) options.
    ///
    /// The actual dirname will be configured through the config parser which
    /// populates `QueuefileTransportOptions` and attaches it to a
    /// `TransportInstanceConfig`.
    pub fn new() -> Self {
        Self
    }
}

// ---------------------------------------------------------------------------
// TransportDriver trait implementation
// ---------------------------------------------------------------------------

impl TransportDriver for QueuefileTransport {
    /// Main transport entry point — copies spool files to the target directory.
    ///
    /// Mirrors `queuefile_transport_entry()` from `queuefile.c` lines 178-313.
    ///
    /// # Algorithm
    ///
    /// 1. Extract and validate `dirname` from the transport options.
    /// 2. Retrieve `message_id` and `spool_directory` from runtime options.
    /// 3. Open source (spool input) and destination directories with
    ///    `O_RDONLY | O_DIRECTORY | O_NOFOLLOW` for symlink safety.
    /// 4. `fstat` both directories to compare `st_dev` (filesystem device).
    /// 5. Copy the header file (`{message_id}-H`):
    ///    - Same filesystem → attempt `linkat()` first.
    ///    - Different filesystem or link failure → `openat()` + buffered copy.
    /// 6. Copy the data file (`{message_id}-D`) with the same strategy.
    /// 7. On data-file failure, clean up the already-created header file.
    ///
    /// # Errors
    ///
    /// Returns `DriverError::ConfigError` if dirname is not set or empty.
    /// Returns `DriverError::ExecutionFailed` if any file operation fails.
    fn transport_entry(
        &self,
        config: &TransportInstanceConfig,
        address: &str,
    ) -> Result<TransportResult, DriverError> {
        // ── Extract and validate options ─────────────────────────────────
        let opts = config
            .options
            .downcast_ref::<QueuefileTransportOptions>()
            .ok_or_else(|| {
                DriverError::ConfigError("queuefile transport: invalid options type".to_string())
            })?;

        let dirname = validate_dirname(opts, &config.name)?;

        debug!(
            transport = config.name.as_str(),
            address = address,
            directory = dirname,
            "queuefile transport: entry"
        );

        // ── Retrieve runtime message context ─────────────────────────────
        let message_id = opts.message_id.as_deref().ok_or_else(|| {
            DriverError::ExecutionFailed(
                "queuefile transport: message_id not set in runtime context".to_string(),
            )
        })?;

        let spool_directory = opts.spool_directory.as_deref().ok_or_else(|| {
            DriverError::ExecutionFailed(
                "queuefile transport: spool_directory not set in runtime context".to_string(),
            )
        })?;

        // ── Construct source and destination directory paths ─────────────
        let src_dir_path = Path::new(spool_directory).join("input");
        let dst_dir_path = Path::new(dirname);

        debug!(
            src_dir = %src_dir_path.display(),
            dst_dir = %dst_dir_path.display(),
            message_id = message_id,
            "queuefile transport: directories"
        );

        // ── Open directories with safety flags ───────────────────────────
        // O_DIRECTORY ensures the path is a directory.
        // O_NOFOLLOW prevents following symlinks at the last component.
        let dir_flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW;

        let src_dir_fd =
            fcntl::open(src_dir_path.as_path(), dir_flags, Mode::empty()).map_err(|e| {
                DriverError::ExecutionFailed(format!(
                    "queuefile transport: failed to open source spool directory {}: {}",
                    src_dir_path.display(),
                    e
                ))
            })?;

        let dst_dir_fd = fcntl::open(dst_dir_path, dir_flags, Mode::empty()).map_err(|e| {
            DriverError::ExecutionFailed(format!(
                "queuefile transport: failed to open destination directory {}: {}",
                dst_dir_path.display(),
                e
            ))
        })?;

        // ── Detect same-filesystem for linkat optimisation ───────────────
        let src_stat = fstat(src_dir_fd.as_fd()).map_err(|e| {
            DriverError::ExecutionFailed(format!(
                "queuefile transport: fstat source directory: {}",
                e
            ))
        })?;
        let dst_stat = fstat(dst_dir_fd.as_fd()).map_err(|e| {
            DriverError::ExecutionFailed(format!(
                "queuefile transport: fstat destination directory: {}",
                e
            ))
        })?;
        let same_fs = src_stat.st_dev == dst_stat.st_dev;

        debug!(
            same_filesystem = same_fs,
            src_dev = src_stat.st_dev,
            dst_dev = dst_stat.st_dev,
            "queuefile transport: filesystem check"
        );

        // ── Build spool file names ───────────────────────────────────────
        let header_name = format!("{message_id}-H");
        let data_name = format!("{message_id}-D");

        // ── Copy header file ─────────────────────────────────────────────
        copy_spool_file_to_dest(&src_dir_fd, &dst_dir_fd, &header_name, same_fs).map_err(|e| {
            error!(
                file = header_name.as_str(),
                error = %e,
                "queuefile transport: failed to copy header file"
            );
            DriverError::ExecutionFailed(format!(
                "queuefile transport: failed to copy header file {}: {}",
                header_name, e
            ))
        })?;

        // ── Copy data file ───────────────────────────────────────────────
        if let Err(e) = copy_spool_file_to_dest(&src_dir_fd, &dst_dir_fd, &data_name, same_fs) {
            error!(
                file = data_name.as_str(),
                error = %e,
                "queuefile transport: failed to copy data file"
            );

            // Clean up: remove the already-created header from destination.
            // Mirrors C: Uunlink(string_sprintf("%s/%s-H", dstdir, message_id))
            let dst_header_path = dst_dir_path.join(&header_name);
            if let Err(cleanup_err) = fs::remove_file(&dst_header_path) {
                warn!(
                    path = %dst_header_path.display(),
                    error = %cleanup_err,
                    "queuefile transport: failed to clean up partial header copy"
                );
            } else {
                debug!(
                    path = %dst_header_path.display(),
                    "queuefile transport: cleaned up partial header copy"
                );
            }

            return Err(DriverError::ExecutionFailed(format!(
                "queuefile transport: failed to copy data file {}: {}",
                data_name, e
            )));
        }

        debug!(
            message_id = message_id,
            address = address,
            directory = dirname,
            "queuefile transport: spool files copied successfully"
        );

        Ok(TransportResult::Ok)
    }

    /// This is a local transport — no network I/O.
    ///
    /// Matches C: `queuefile_transport_info.local = TRUE`.
    fn is_local(&self) -> bool {
        true
    }

    /// Driver name used for configuration matching and logging.
    ///
    /// Matches C: `queuefile_transport_info.driver_name = US"queuefile"`.
    fn driver_name(&self) -> &str {
        "queuefile"
    }
}

// ---------------------------------------------------------------------------
// Internal helper: dirname validation
// ---------------------------------------------------------------------------

/// Validate that the `dirname` option is set, non-empty, and absolute.
///
/// Mirrors `queuefile_transport_init()` from `queuefile.c` lines 61-68.
fn validate_dirname<'a>(
    opts: &'a QueuefileTransportOptions,
    transport_name: &str,
) -> Result<&'a str, DriverError> {
    let dirname = opts.dirname.as_deref().ok_or_else(|| {
        DriverError::ConfigError(format!(
            "directory must be set for the {} transport",
            transport_name
        ))
    })?;

    if dirname.is_empty() {
        return Err(DriverError::ConfigError(format!(
            "directory must be set for the {} transport",
            transport_name
        )));
    }

    // The C code checks that the expanded dirname starts with '/'
    if !dirname.starts_with('/') {
        return Err(DriverError::ConfigError(format!(
            "{} transport: directory path must be absolute: {}",
            transport_name, dirname
        )));
    }

    Ok(dirname)
}

// ---------------------------------------------------------------------------
// Internal helper: spool file copy
// ---------------------------------------------------------------------------

/// Copy a single spool file from the source directory to the destination
/// directory using directory-relative operations.
///
/// Mirrors `copy_spool_files()` from `queuefile.c` lines 114-168.
///
/// # Strategy
///
/// 1. If `try_link` is `true` (same filesystem), attempt `linkat()` for an
///    atomic hard link. On success, return immediately.
/// 2. If linking fails (or `try_link` is `false`), fall back to:
///    - `openat()` source with `O_RDONLY`
///    - `openat()` destination with `O_RDWR | O_CREAT | O_EXCL` and `SPOOL_MODE`
///    - `fchmod()` to ensure correct permissions
///    - Buffered copy via `copy_spool_file_content()`
fn copy_spool_file_to_dest(
    src_dir_fd: &std::os::fd::OwnedFd,
    dst_dir_fd: &std::os::fd::OwnedFd,
    filename: &str,
    try_link: bool,
) -> Result<(), io::Error> {
    // ── Attempt linkat if same filesystem ─────────────────────────────
    if try_link {
        debug!(
            file = filename,
            "attempting linkat for same-filesystem copy"
        );

        match linkat(
            src_dir_fd.as_fd(),
            filename,
            dst_dir_fd.as_fd(),
            filename,
            AtFlags::empty(),
        ) {
            Ok(()) => {
                debug!(file = filename, "linkat succeeded");
                return Ok(());
            }
            Err(e) => {
                debug!(
                    file = filename,
                    error = %e,
                    "linkat failed, falling back to copy"
                );
                // Fall through to copy path
            }
        }
    }

    // ── Open source file for reading ─────────────────────────────────
    let src_fd = fcntl::openat(src_dir_fd.as_fd(), filename, OFlag::O_RDONLY, Mode::empty())
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("openat source {}: {}", filename, e),
            )
        })?;

    // ── Create destination file with O_CREAT | O_EXCL ────────────────
    // Matches C: openat(ddfd, filename, O_RDWR|O_CREAT|O_EXCL, SPOOL_MODE)
    let spool_mode = Mode::from_bits_truncate(SPOOL_MODE);
    let dst_fd = fcntl::openat(
        dst_dir_fd.as_fd(),
        filename,
        OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL,
        spool_mode,
    )
    .map_err(|e| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("openat dest {}: {}", filename, e),
        )
    })?;

    // ── Set permissions explicitly (fchmod) ───────────────────────────
    // Matches C: fchmod(dfd, SPOOL_MODE)
    fchmod(dst_fd.as_fd(), spool_mode).map_err(|e| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("fchmod {}: {}", filename, e),
        )
    })?;

    // ── Convert OwnedFd → std::fs::File for buffered I/O ────────────
    // This conversion is safe (no `unsafe` needed): std::fs::File
    // implements From<OwnedFd> since Rust 1.63.
    let mut src_file = File::from(src_fd);
    let mut dst_file = File::from(dst_fd);

    // ── Perform the byte copy ────────────────────────────────────────
    copy_spool_file_content(&mut dst_file, &mut src_file)
        .map_err(|e| io::Error::new(e.kind(), format!("copy content {}: {}", filename, e)))?;

    debug!(file = filename, "file copy completed");
    Ok(())
}

/// Low-level file copy: seeks the source to the beginning, then copies all
/// bytes to the destination using a 16 384-byte buffer.
///
/// Mirrors `copy_spool_file()` from `queuefile.c` lines 79-97 exactly:
/// - `lseek(sfd, 0, SEEK_SET)`
/// - `read(sfd, buffer, sizeof(buffer))` in a loop
/// - `write(dfd, buffer, n)` for each chunk
///
/// The buffer size (`COPY_BUFFER_SIZE = 16 384`) matches the C `buffer[16384]`.
fn copy_spool_file_content(dst: &mut File, src: &mut File) -> Result<(), io::Error> {
    // Seek source to beginning (mirrors C: lseek(sfd, 0, SEEK_SET))
    src.seek(SeekFrom::Start(0))?;

    // Manual read/write loop with 16 384-byte buffer, matching C exactly.
    let mut buffer = [0u8; COPY_BUFFER_SIZE];
    loop {
        let bytes_read = src.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        dst.write_all(&buffer[..bytes_read])?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Driver registration
// ---------------------------------------------------------------------------

// Compile-time registration of the queuefile transport driver.
//
// Replaces the C `queuefile_transport_info` struct in `drtables.c`.
// The `inventory::submit!` macro makes this discoverable by the driver
// registry without any runtime initialization code.
inventory::submit! {
    TransportDriverFactory {
        name: "queuefile",
        create: || -> Box<dyn TransportDriver> { Box::new(QueuefileTransport::new()) },
        is_local: true,
        avail_string: Some("transport-queuefile"),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_options_default() {
        let opts = QueuefileTransportOptions::default();
        assert!(opts.dirname.is_none());
        assert!(opts.message_id.is_none());
        assert!(opts.spool_directory.is_none());
    }

    #[test]
    fn test_options_with_dirname() {
        let opts = QueuefileTransportOptions {
            dirname: Some("/var/spool/exim/queuefile".to_string()),
            ..Default::default()
        };
        assert_eq!(opts.dirname.as_deref(), Some("/var/spool/exim/queuefile"));
        // Runtime fields must be None when constructed from config defaults
        assert!(opts.message_id.is_none());
        assert!(opts.spool_directory.is_none());
    }

    #[test]
    fn test_options_clone() {
        let opts = QueuefileTransportOptions {
            dirname: Some("/tmp/queue".to_string()),
            message_id: Some("1abCDE-000001-XX".to_string()),
            spool_directory: Some("/var/spool/exim".to_string()),
        };
        let cloned = opts.clone();
        assert_eq!(cloned.dirname, opts.dirname);
        assert_eq!(cloned.message_id, opts.message_id);
        assert_eq!(cloned.spool_directory, opts.spool_directory);
    }

    #[test]
    fn test_transport_driver_name() {
        let t = QueuefileTransport::new();
        assert_eq!(t.driver_name(), "queuefile");
    }

    #[test]
    fn test_transport_is_local() {
        let t = QueuefileTransport::new();
        assert!(t.is_local());
    }

    #[test]
    fn test_validate_dirname_none() {
        let opts = QueuefileTransportOptions::default();
        let result = validate_dirname(&opts, "test_transport");
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            DriverError::ConfigError(msg) => {
                assert!(msg.contains("directory must be set"));
                assert!(msg.contains("test_transport"));
            }
            _ => panic!("expected ConfigError, got {:?}", err),
        }
    }

    #[test]
    fn test_validate_dirname_empty() {
        let opts = QueuefileTransportOptions {
            dirname: Some(String::new()),
            ..Default::default()
        };
        let result = validate_dirname(&opts, "test_transport");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_dirname_relative_path() {
        let opts = QueuefileTransportOptions {
            dirname: Some("relative/path".to_string()),
            ..Default::default()
        };
        let result = validate_dirname(&opts, "test_transport");
        assert!(result.is_err());
        match result.unwrap_err() {
            DriverError::ConfigError(msg) => {
                assert!(msg.contains("absolute"));
            }
            _ => panic!("expected ConfigError for relative path"),
        }
    }

    #[test]
    fn test_validate_dirname_valid() {
        let opts = QueuefileTransportOptions {
            dirname: Some("/var/spool/exim/queue".to_string()),
            ..Default::default()
        };
        let result = validate_dirname(&opts, "test_transport");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "/var/spool/exim/queue");
    }

    #[test]
    fn test_transport_entry_missing_options_type() {
        let t = QueuefileTransport::new();

        // Construct a config with wrong options type
        let mut config = TransportInstanceConfig::new("test", "queuefile");
        config.options = Box::new(42_u32); // Wrong type

        let result = t.transport_entry(&config, "user@example.com");
        assert!(result.is_err());
        match result.unwrap_err() {
            DriverError::ConfigError(msg) => {
                assert!(msg.contains("invalid options type"));
            }
            other => panic!("expected ConfigError, got {:?}", other),
        }
    }

    #[test]
    fn test_transport_entry_missing_dirname() {
        let t = QueuefileTransport::new();

        let mut config = TransportInstanceConfig::new("qf_test", "queuefile");
        config.options = Box::new(QueuefileTransportOptions::default());

        let result = t.transport_entry(&config, "user@example.com");
        assert!(result.is_err());
        match result.unwrap_err() {
            DriverError::ConfigError(msg) => {
                assert!(msg.contains("directory must be set"));
            }
            other => panic!("expected ConfigError, got {:?}", other),
        }
    }

    #[test]
    fn test_transport_entry_missing_message_id() {
        let t = QueuefileTransport::new();

        let opts = QueuefileTransportOptions {
            dirname: Some("/tmp/queuetest".to_string()),
            message_id: None,
            spool_directory: Some("/var/spool/exim".to_string()),
        };
        let mut config = TransportInstanceConfig::new("qf_test", "queuefile");
        config.options = Box::new(opts);

        let result = t.transport_entry(&config, "user@example.com");
        assert!(result.is_err());
        match result.unwrap_err() {
            DriverError::ExecutionFailed(msg) => {
                assert!(msg.contains("message_id not set"));
            }
            other => panic!("expected ExecutionFailed, got {:?}", other),
        }
    }

    #[test]
    fn test_transport_entry_missing_spool_directory() {
        let t = QueuefileTransport::new();

        let opts = QueuefileTransportOptions {
            dirname: Some("/tmp/queuetest".to_string()),
            message_id: Some("1abCDE-000001-XX".to_string()),
            spool_directory: None,
        };
        let mut config = TransportInstanceConfig::new("qf_test", "queuefile");
        config.options = Box::new(opts);

        let result = t.transport_entry(&config, "user@example.com");
        assert!(result.is_err());
        match result.unwrap_err() {
            DriverError::ExecutionFailed(msg) => {
                assert!(msg.contains("spool_directory not set"));
            }
            other => panic!("expected ExecutionFailed, got {:?}", other),
        }
    }

    /// Integration-style test that exercises the full copy path using temp dirs.
    #[test]
    fn test_copy_spool_file_content() {
        use std::io::Write;

        // Create a source file with known content
        let dir = std::env::temp_dir().join("queuefile_test_copy");
        let _ = fs::create_dir_all(&dir);
        let src_path = dir.join("test_src");
        let dst_path = dir.join("test_dst");

        // Write test data
        let test_data = b"Hello, this is test spool data\nLine 2\nLine 3\n";
        {
            let mut f = File::create(&src_path).unwrap();
            f.write_all(test_data).unwrap();
        }

        // Perform copy
        {
            let mut src = File::open(&src_path).unwrap();
            let mut dst = File::create(&dst_path).unwrap();
            copy_spool_file_content(&mut dst, &mut src).unwrap();
        }

        // Verify content
        let copied = fs::read(&dst_path).unwrap();
        assert_eq!(copied, test_data);

        // Cleanup
        let _ = fs::remove_file(&src_path);
        let _ = fs::remove_file(&dst_path);
        let _ = fs::remove_dir(&dir);
    }
}
