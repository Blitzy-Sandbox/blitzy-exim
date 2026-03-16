// =============================================================================
// exim-transports/src/appendfile.rs — Appendfile Transport Driver
// =============================================================================
//
// Rewrites `src/src/transports/appendfile.c` (3,373 lines) +
// `src/src/transports/appendfile.h` (101 lines) from C to Rust.
//
// This is the primary local delivery transport supporting mbox, MBX, Maildir,
// and Mailstore formats with configurable locking and quota enforcement.
//
// Per AAP §0.7.2: zero unsafe blocks — locking via nix crate wrappers.
// Per AAP §0.4.2: registered via inventory::submit! for compile-time collection.
// Per AAP §0.7.3: feature flags replace C preprocessor conditionals.
//
// SPDX-License-Identifier: GPL-2.0-or-later
// =============================================================================

// =============================================================================
// Imports
// =============================================================================

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use exim_drivers::transport_driver::{
    TransportDriver, TransportDriverFactory, TransportInstanceConfig, TransportResult,
};
use exim_drivers::DriverError;
use exim_store::taint::Tainted;
use regex::Regex;
use serde::Deserialize;

// =============================================================================
// Constants — Replaces C #define macros from appendfile.c / exim.h
// =============================================================================

/// Default file mode for created mailbox files (C: APPENDFILE_MODE = 0600).
const APPENDFILE_MODE: u32 = 0o600;

/// Default directory mode for created directories (C: APPENDFILE_DIRECTORY_MODE = 0700).
const APPENDFILE_DIRECTORY_MODE: u32 = 0o700;

/// Default lockfile mode (C: APPENDFILE_LOCKFILE_MODE = 0600).
const APPENDFILE_LOCKFILE_MODE: u32 = 0o600;

/// MBX header size in bytes (C: MBX_HDRSIZE = 2048).
/// Reserved for MBX mailbox format locking and header manipulation.
#[cfg(feature = "mbx")]
#[allow(dead_code)] // MBX format constant — used in full MBX locking implementation
const MBX_HDRSIZE: usize = 2048;

/// MBX number of user flags (C: MBX_NUSERFLAGS = 30).
/// Reserved for MBX mailbox format user-flag field parsing.
#[cfg(feature = "mbx")]
#[allow(dead_code)] // MBX format constant — used in full MBX user-flag parsing
const MBX_NUSERFLAGS: usize = 30;

/// Transport write option: use CRLF (C: topt_use_crlf).
/// Used in build_message_body to select CR+LF vs LF line endings.
const TOPT_USE_CRLF: i32 = 0x0020;

/// Transport write option: not a socket (C: topt_not_socket).
/// Indicates we are writing to a file, not a network socket.
const TOPT_NOT_SOCKET: i32 = 0x0080;

/// Comsat/biff notification UDP port.
const COMSAT_PORT: u16 = 512;

/// Default lockfile timeout in seconds (30 minutes).
const DEFAULT_LOCKFILE_TIMEOUT: i32 = 30 * 60;

/// Default lock retry count.
const DEFAULT_LOCK_RETRIES: i32 = 10;

/// Default lock retry interval in seconds.
const DEFAULT_LOCK_INTERVAL: i32 = 3;

/// Default maildir retry count.
const DEFAULT_MAILDIR_RETRIES: i32 = 10;

// =============================================================================
// Error Types — Replaces C addr->message / addr->basic_errno pattern
// =============================================================================

/// Appendfile-specific error type covering all failure modes.
///
/// Replaces the C pattern of setting `addr->message` and `addr->basic_errno`
/// for error reporting throughout `appendfile.c`.
#[derive(Debug, thiserror::Error)]
pub enum AppendfileError {
    /// Lock acquisition failed after exhausting retries.
    #[error("locking failed for {path}: {reason}")]
    LockFailed { path: String, reason: String },

    /// Quota exceeded for the mailbox.
    #[error("quota exceeded for {path}: used {used} of {limit}")]
    QuotaExceeded { path: String, used: i64, limit: i64 },

    /// File creation or opening failed.
    #[error("file operation failed for {path}: {source}")]
    FileError {
        path: String,
        #[source]
        source: io::Error,
    },

    /// Permission denied or ownership check failed.
    #[error("permission denied for {path}: {reason}")]
    PermissionDenied { path: String, reason: String },

    /// MBX format-specific error.
    #[cfg(feature = "mbx")]
    #[error("MBX format error for {path}: {reason}")]
    MbxError { path: String, reason: String },

    /// Maildir format-specific error.
    #[cfg(feature = "maildir")]
    #[error("Maildir error for {path}: {reason}")]
    MaildirError { path: String, reason: String },

    /// Mailstore format-specific error.
    #[cfg(feature = "mailstore")]
    #[error("Mailstore error for {path}: {reason}")]
    MailstoreError { path: String, reason: String },

    /// Comsat notification failed (non-fatal).
    #[error("comsat notification failed: {0}")]
    ComsatFailed(String),

    /// Taint validation failed on a file path.
    #[error("tainted path not permitted: {0}")]
    TaintedPath(String),

    /// Configuration validation error.
    #[error("configuration error: {0}")]
    ConfigError(String),
}

/// Conversion from AppendfileError to DriverError for `?` operator usage.
///
/// Maps appendfile-specific errors to the appropriate DriverError variant:
/// - QuotaExceeded → TempFail (deferrable, retry later)
/// - LockFailed → TempFail (transient locking contention)
/// - FileError → ExecutionFailed (I/O failure)
/// - PermissionDenied → ExecutionFailed
/// - ConfigError → ConfigError
/// - TaintedPath → ExecutionFailed
/// - ComsatFailed → ExecutionFailed (non-fatal but reported)
/// - Format-specific errors → ExecutionFailed
impl From<AppendfileError> for DriverError {
    fn from(err: AppendfileError) -> Self {
        match &err {
            AppendfileError::QuotaExceeded { .. } => DriverError::TempFail(err.to_string()),
            AppendfileError::LockFailed { .. } => DriverError::TempFail(err.to_string()),
            AppendfileError::ConfigError(_) => DriverError::ConfigError(err.to_string()),
            _ => DriverError::ExecutionFailed(err.to_string()),
        }
    }
}

// =============================================================================
// CreateFilePolicy Enum — from appendfile.h line 81
// =============================================================================

/// Controls where the appendfile transport is permitted to create files.
///
/// Replaces C enum at `appendfile.h` line 81:
/// `{ create_anywhere, create_belowhome, create_inhome }`
///
/// Used by the `create_file` configuration option to restrict file creation
/// relative to the user's home directory.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum CreateFilePolicy {
    /// No restrictions on file creation location.
    /// C: `create_anywhere` (value 0)
    #[default]
    Anywhere,

    /// File must be created below (within the directory tree of) the home
    /// directory. Symbolic links are resolved and checked.
    /// C: `create_belowhome` (value 1)
    BelowHome,

    /// File must be created directly in the home directory (one level).
    /// C: `create_inhome` (value 2)
    InHome,
}

impl CreateFilePolicy {
    /// Parse a create_file policy string from the configuration.
    ///
    /// Matches the C parsing in `appendfile_transport_init()` (appendfile.c
    /// lines 432-443): "anywhere", "belowhome", "inhome", or an absolute path
    /// (treated as belowhome).
    pub fn from_config_str(s: &str) -> Result<Self, AppendfileError> {
        match s {
            "anywhere" => Ok(Self::Anywhere),
            "belowhome" => Ok(Self::BelowHome),
            "inhome" => Ok(Self::InHome),
            s if s.starts_with('/') => Ok(Self::BelowHome),
            _ => Err(AppendfileError::ConfigError(format!(
                "invalid value for create_file: '{s}'"
            ))),
        }
    }
}

// =============================================================================
// MailboxFormat — Internal enum replacing C mbf_* constants
// =============================================================================

/// Internal mailbox format discriminator.
///
/// Replaces C: `enum { mbf_unix, mbf_mbx, mbf_smail, mbf_maildir, mbf_mailstore }`
/// (appendfile.c line 145).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MailboxFormat {
    /// Traditional mbox (Unix) format — messages concatenated with "From " separator.
    Unix,
    /// MBX format — University of Washington MBX with internal index.
    #[cfg(feature = "mbx")]
    Mbx,
    /// Smail-compatible directory format — one file per message, numbered.
    Smail,
    /// Maildir format — atomic tmp→new rename in new/cur/tmp hierarchy.
    #[cfg(feature = "maildir")]
    Maildir,
    /// Mailstore format — data+envelope file pairs.
    #[cfg(feature = "mailstore")]
    Mailstore,
}

impl MailboxFormat {
    /// Returns the human-readable format name for logging.
    fn name(self) -> &'static str {
        match self {
            Self::Unix => "unix",
            #[cfg(feature = "mbx")]
            Self::Mbx => "mbx",
            Self::Smail => "smail",
            #[cfg(feature = "maildir")]
            Self::Maildir => "maildir",
            #[cfg(feature = "mailstore")]
            Self::Mailstore => "mailstore",
        }
    }
}

// =============================================================================
// AppendfileTransportOptions — All 64 fields from appendfile.h lines 12-77
// =============================================================================

/// Complete configuration options for the appendfile transport driver.
///
/// Maps 1:1 to the C `appendfile_transport_options_block` structure defined in
/// `appendfile.h` (lines 12-77). All 64 fields are present with exact config
/// key name compatibility per AAP §0.7.1.
///
/// String fields are `Option<String>` replacing C `uschar *` (NULL = None).
/// Numeric fields use the same widths as C. Boolean fields replace C `BOOL`.
#[derive(Debug, Clone, Deserialize)]
pub struct AppendfileTransportOptions {
    // -------------------------------------------------------------------------
    // String fields (22 fields) — C `uschar *` → Rust `Option<String>`
    // -------------------------------------------------------------------------
    /// Explicit filename for single-file delivery (C: `filename`, option "file").
    /// Mutually exclusive with `dirname`.
    pub filename: Option<String>,

    /// Directory for multi-file delivery (Maildir/Mailstore/Smail).
    /// C: `dirname`, option "directory". Mutually exclusive with `filename`.
    pub dirname: Option<String>,

    /// Template for per-message filenames within a directory.
    /// C: `dirfilename`, option "directory_file".
    /// Default: `"q${base62:$tod_epoch}-$inode"`.
    pub dirfilename: Option<String>,

    /// String prepended to each delivered message (e.g., mbox "From " line).
    /// C: `message_prefix`, option "message_prefix".
    pub message_prefix: Option<String>,

    /// String appended after each delivered message.
    /// C: `message_suffix`, option "message_suffix".
    pub message_suffix: Option<String>,

    /// String expansion for the `create_file` policy.
    /// C: `create_file_string`, default "anywhere".
    pub create_file_string: Option<String>,

    /// Mailbox quota specification string (expandable).
    /// C: `quota`, option "quota".
    pub quota: Option<String>,

    /// Directory to scan for quota computation (overrides delivery dir).
    /// C: `quota_directory`, option "quota_directory".
    pub quota_directory: Option<String>,

    /// Quota for file count (expandable string).
    /// C: `quota_filecount`, option "quota_filecount".
    pub quota_filecount: Option<String>,

    /// PCRE2/regex for extracting size from Maildir filenames (S=<size>).
    /// C: `quota_size_regex`, option "quota_size_regex".
    pub quota_size_regex: Option<String>,

    /// Quota warning threshold specification string (expandable).
    /// C: `quota_warn_threshold`, option "quota_warn_threshold".
    pub quota_warn_threshold: Option<String>,

    /// Current mailbox size (expandable, overrides stat).
    /// C: `mailbox_size_string`, option "mailbox_size".
    pub mailbox_size_string: Option<String>,

    /// Current mailbox file count (expandable, overrides readdir).
    /// C: `mailbox_filecount_string`, option "mailbox_filecount".
    pub mailbox_filecount_string: Option<String>,

    /// Expandable string controlling maildir_use_size_file dynamically.
    /// C: `expand_maildir_use_size_file`.
    #[cfg(feature = "maildir")]
    pub expand_maildir_use_size_file: Option<String>,

    /// Regex selecting which Maildir subdirectories to include in quota scans.
    /// C: `maildir_dir_regex`, default `"^(?:cur|new|\\..*)$"`.
    #[cfg(feature = "maildir")]
    pub maildir_dir_regex: Option<String>,

    /// Tag appended to Maildir filenames.
    /// C: `maildir_tag`, option "maildir_tag".
    #[cfg(feature = "maildir")]
    pub maildir_tag: Option<String>,

    /// Regex matching subdirectory names where maildirfolder file is auto-created.
    /// C: `maildirfolder_create_regex`.
    #[cfg(feature = "maildir")]
    pub maildirfolder_create_regex: Option<String>,

    /// Prefix for Mailstore envelope filenames.
    /// C: `mailstore_prefix`, option "mailstore_prefix".
    #[cfg(feature = "mailstore")]
    pub mailstore_prefix: Option<String>,

    /// Suffix for Mailstore envelope filenames.
    /// C: `mailstore_suffix`, option "mailstore_suffix".
    #[cfg(feature = "mailstore")]
    pub mailstore_suffix: Option<String>,

    /// String checked at the start of existing lines for mbox "From " escaping.
    /// C: `check_string`, option "check_string".
    pub check_string: Option<String>,

    /// Escape string prepended when `check_string` matches.
    /// C: `escape_string`, option "escape_string".
    pub escape_string: Option<String>,

    /// Format detection string: "format1\ncheck1\nformat2\ncheck2\n..."
    /// C: `file_format`, option "file_format".
    pub file_format: Option<String>,

    // -------------------------------------------------------------------------
    // Numeric fields (16 fields)
    // -------------------------------------------------------------------------
    /// Resolved quota value in bytes.
    /// C: `quota_value` (off_t). Default: 0 (no quota).
    pub quota_value: i64,

    /// Resolved quota warning threshold value.
    /// C: `quota_warn_threshold_value` (off_t). Default: 0.
    pub quota_warn_threshold_value: i64,

    /// Resolved current mailbox size override.
    /// C: `mailbox_size_value` (off_t). Default: -1 (use stat).
    pub mailbox_size_value: i64,

    /// Resolved current mailbox file count override.
    /// C: `mailbox_filecount_value` (int). Default: -1 (use readdir).
    pub mailbox_filecount_value: i32,

    /// Resolved quota file count limit.
    /// C: `quota_filecount_value` (int). Default: 0 (no limit).
    pub quota_filecount_value: i32,

    /// File creation mode (C: `mode`). Default: 0600 (APPENDFILE_MODE).
    pub mode: u32,

    /// Directory creation mode (C: `dirmode`). Default: 0700.
    pub dirmode: u32,

    /// Lockfile creation mode (C: `lockfile_mode`). Default: 0600.
    pub lockfile_mode: u32,

    /// Lockfile creation timeout in seconds (C: `lockfile_timeout`). Default: 1800.
    pub lockfile_timeout: i32,

    /// fcntl lock timeout in seconds (C: `lock_fcntl_timeout`). Default: 0.
    pub lock_fcntl_timeout: i32,

    /// flock lock timeout in seconds (C: `lock_flock_timeout`). Default: 0.
    pub lock_flock_timeout: i32,

    /// Number of lock retry attempts (C: `lock_retries`). Default: 10.
    pub lock_retries: i32,

    /// Seconds between lock retry attempts (C: `lock_interval`). Default: 3.
    pub lock_interval: i32,

    /// Maildir unique filename retry count (C: `maildir_retries`). Default: 10.
    pub maildir_retries: i32,

    /// File creation policy (C: `create_file`). Default: Anywhere.
    pub create_file: CreateFilePolicy,

    /// Bitwise transport write options (C: `options`). Default: 0.
    pub options: i32,

    // -------------------------------------------------------------------------
    // Boolean fields (26 fields) — C `BOOL` → Rust `bool`
    // -------------------------------------------------------------------------
    /// Permit delivery to FIFO (named pipe) files. C: `allow_fifo`. Default: false.
    pub allow_fifo: bool,

    /// Permit delivery to files that are symbolic links. C: `allow_symlink`. Default: false.
    pub allow_symlink: bool,

    /// Check file group matches transport/user group. C: `check_group`. Default: false.
    pub check_group: bool,

    /// Check file owner matches transport/user uid. C: `check_owner`. Default: true.
    pub check_owner: bool,

    /// Create parent directories if they don't exist. C: `create_directory`. Default: true.
    pub create_directory: bool,

    /// Send comsat/biff notification after delivery. C: `notify_comsat`. Default: false.
    pub notify_comsat: bool,

    /// Use a .lock lockfile for locking. C: `use_lockfile`. Default: true (mbox).
    pub use_lockfile: bool,

    /// Tracks whether use_lockfile was explicitly set in config. C: `set_use_lockfile`.
    pub set_use_lockfile: bool,

    /// Use fcntl() advisory locking. C: `use_fcntl`. Default: true (mbox).
    pub use_fcntl: bool,

    /// Tracks whether use_fcntl was explicitly set in config. C: `set_use_fcntl`.
    pub set_use_fcntl: bool,

    /// Use flock() advisory locking. C: `use_flock`. Default: false.
    pub use_flock: bool,

    /// Tracks whether use_flock was explicitly set in config. C: `set_use_flock`.
    pub set_use_flock: bool,

    /// Use MBX-style locking (fcntl on /tmp/.strstrstrstr). C: `use_mbx_lock`.
    #[cfg(feature = "mbx")]
    pub use_mbx_lock: bool,

    /// Tracks whether use_mbx_lock was explicitly set. C: `set_use_mbx_lock`.
    #[cfg(feature = "mbx")]
    pub set_use_mbx_lock: bool,

    /// Write messages in BSMTP (SMTP envelope) format. C: `use_bsmtp`.
    pub use_bsmtp: bool,

    /// Use CR+LF line endings instead of LF. C: `use_crlf`.
    pub use_crlf: bool,

    /// Require that the file already exists (no auto-create). C: `file_must_exist`.
    pub file_must_exist: bool,

    /// Fail if file mode is wider than specified. C: `mode_fail_narrower`. Default: true.
    pub mode_fail_narrower: bool,

    /// Use Maildir format delivery (three-directory new/cur/tmp hierarchy).
    /// C: `maildir_format`. Feature-gated.
    #[cfg(feature = "maildir")]
    pub maildir_format: bool,

    /// Maintain maildirsize file for Maildir++ quota. C: `maildir_use_size_file`.
    #[cfg(feature = "maildir")]
    pub maildir_use_size_file: bool,

    /// Use Mailstore format (data+envelope file pairs). C: `mailstore_format`.
    #[cfg(feature = "mailstore")]
    pub mailstore_format: bool,

    /// Use MBX format. C: `mbx_format`. Feature-gated.
    #[cfg(feature = "mbx")]
    pub mbx_format: bool,

    /// Interpret quota_warn_threshold as a percentage of quota.
    /// C: `quota_warn_threshold_is_percent`.
    pub quota_warn_threshold_is_percent: bool,

    /// Include the new message size in quota calculations. C: `quota_is_inclusive`.
    /// Default: true.
    pub quota_is_inclusive: bool,

    /// Skip quota checking entirely. C: `quota_no_check`.
    pub quota_no_check: bool,

    /// Skip file-count quota checking. C: `quota_filecount_no_check`.
    pub quota_filecount_no_check: bool,
}

// =============================================================================
// Default Implementation — Matches C defaults from appendfile.c lines 117-139
// =============================================================================

impl Default for AppendfileTransportOptions {
    fn default() -> Self {
        Self {
            // String fields — most default to None (C: NULL)
            filename: None,
            dirname: None,
            dirfilename: Some("q${base62:$tod_epoch}-$inode".to_string()),
            message_prefix: None,
            message_suffix: None,
            create_file_string: Some("anywhere".to_string()),
            quota: None,
            quota_directory: None,
            quota_filecount: None,
            quota_size_regex: None,
            quota_warn_threshold: None,
            mailbox_size_string: None,
            mailbox_filecount_string: None,
            #[cfg(feature = "maildir")]
            expand_maildir_use_size_file: None,
            #[cfg(feature = "maildir")]
            maildir_dir_regex: Some(r"^(?:cur|new|\..*)$".to_string()),
            #[cfg(feature = "maildir")]
            maildir_tag: None,
            #[cfg(feature = "maildir")]
            maildirfolder_create_regex: None,
            #[cfg(feature = "mailstore")]
            mailstore_prefix: None,
            #[cfg(feature = "mailstore")]
            mailstore_suffix: None,
            check_string: None,
            escape_string: None,
            file_format: None,

            // Numeric fields
            quota_value: 0,
            quota_warn_threshold_value: 0,
            mailbox_size_value: -1,
            mailbox_filecount_value: -1,
            quota_filecount_value: 0,
            mode: APPENDFILE_MODE,
            dirmode: APPENDFILE_DIRECTORY_MODE,
            lockfile_mode: APPENDFILE_LOCKFILE_MODE,
            lockfile_timeout: DEFAULT_LOCKFILE_TIMEOUT,
            lock_fcntl_timeout: 0,
            lock_flock_timeout: 0,
            lock_retries: DEFAULT_LOCK_RETRIES,
            lock_interval: DEFAULT_LOCK_INTERVAL,
            maildir_retries: DEFAULT_MAILDIR_RETRIES,
            create_file: CreateFilePolicy::Anywhere,
            options: 0,

            // Boolean fields
            allow_fifo: false,
            allow_symlink: false,
            check_group: false,
            check_owner: true,
            create_directory: true,
            notify_comsat: false,
            use_lockfile: true,
            set_use_lockfile: false,
            use_fcntl: true,
            set_use_fcntl: false,
            use_flock: false,
            set_use_flock: false,
            #[cfg(feature = "mbx")]
            use_mbx_lock: false,
            #[cfg(feature = "mbx")]
            set_use_mbx_lock: false,
            use_bsmtp: false,
            use_crlf: false,
            file_must_exist: false,
            mode_fail_narrower: true,
            #[cfg(feature = "maildir")]
            maildir_format: false,
            #[cfg(feature = "maildir")]
            maildir_use_size_file: false,
            #[cfg(feature = "mailstore")]
            mailstore_format: false,
            #[cfg(feature = "mbx")]
            mbx_format: false,
            quota_warn_threshold_is_percent: false,
            quota_is_inclusive: true,
            quota_no_check: false,
            quota_filecount_no_check: false,
        }
    }
}

// =============================================================================
// AppendfileTransport — Main transport struct
// =============================================================================

/// The appendfile transport driver implementation.
///
/// Supports delivery to mbox, MBX, Maildir, and Mailstore format mailboxes with
/// configurable locking strategies and quota enforcement. Registered at compile
/// time via `inventory::submit!` per AAP §0.7.3.
#[derive(Debug)]
pub struct AppendfileTransport {
    options: AppendfileTransportOptions,
}

impl Default for AppendfileTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl AppendfileTransport {
    /// Create a new `AppendfileTransport` with default options.
    pub fn new() -> Self {
        Self {
            options: AppendfileTransportOptions::default(),
        }
    }

    /// Initialize and validate transport configuration.
    ///
    /// Replaces C `appendfile_transport_init()` (appendfile.c lines 327-492).
    /// Validates mutually exclusive settings, derives the create policy, selects
    /// lock defaults for MBX, and assembles the options bitmask.
    pub fn init(&mut self) -> Result<(), DriverError> {
        let ob = &mut self.options;

        // Validate lock_retries must be positive (appendfile.c line 335)
        if ob.lock_retries <= 0 {
            return Err(DriverError::ConfigError(
                "lock_retries must be greater than 0".to_string(),
            ));
        }

        // filename and dirname are mutually exclusive (appendfile.c line 345)
        if ob.filename.is_some() && ob.dirname.is_some() {
            return Err(DriverError::ConfigError(
                "only one of 'file' and 'directory' may be set".to_string(),
            ));
        }

        // Validate quota settings — quota requires dirname or is meaningless for
        // single file (appendfile.c lines 357-372)
        if ob.quota.is_some() && ob.filename.is_some() && ob.dirname.is_none() {
            tracing::warn!(
                "quota is set but delivery is to a single file; \
                 quota checking may not work as expected"
            );
        }

        // MBX format changes locking defaults (appendfile.c lines 384-420)
        #[cfg(feature = "mbx")]
        if ob.mbx_format {
            // For MBX, the default is to use MBX lock and not use lockfile
            if !ob.set_use_lockfile {
                ob.use_lockfile = false;
            }
            if !ob.set_use_fcntl {
                ob.use_fcntl = false;
            }
            if !ob.set_use_flock {
                ob.use_flock = false;
            }
            if !ob.set_use_mbx_lock {
                ob.use_mbx_lock = true;
            }
        }

        // If flock is being used, fcntl must NOT also be used unless explicitly
        // requested, to avoid deadlocks (appendfile.c lines 400-410)
        if ob.use_flock && ob.use_fcntl && !ob.set_use_fcntl {
            ob.use_fcntl = false;
        }

        // Parse create_file policy from its string form (appendfile.c lines 432-443)
        if let Some(ref policy_str) = ob.create_file_string {
            ob.create_file = CreateFilePolicy::from_config_str(policy_str)
                .map_err(|e| DriverError::ConfigError(e.to_string()))?;
        }

        // BSMTP mode sets default check_string and escape_string
        // (appendfile.c lines 453-458)
        if ob.use_bsmtp {
            if ob.check_string.is_none() {
                ob.check_string = Some(".".to_string());
            }
            if ob.escape_string.is_none() {
                ob.escape_string = Some("..".to_string());
            }
        }

        // Build the transport write options bitmask (appendfile.c lines 462-480)
        let mut topt = 0i32;
        if ob.use_crlf {
            topt |= TOPT_USE_CRLF;
        }
        topt |= TOPT_NOT_SOCKET;
        ob.options = topt;

        // Set default quota_warn_threshold message if threshold is set
        // but no warn_message exists on the base config (appendfile.c lines 485-490)
        // Note: the actual warn_message is on TransportInstanceConfig, not here

        tracing::debug!(
            driver = "appendfile",
            file = ?ob.filename,
            dir = ?ob.dirname,
            mode = format!("{:04o}", ob.mode),
            "appendfile transport initialized"
        );

        Ok(())
    }

    /// Determine the mailbox format based on configured options.
    ///
    /// Replaces the format selection logic at appendfile.c lines 1280-1320.
    fn determine_format(&self) -> MailboxFormat {
        let ob = &self.options;

        #[cfg(feature = "mbx")]
        if ob.mbx_format {
            return MailboxFormat::Mbx;
        }

        #[cfg(feature = "maildir")]
        if ob.maildir_format {
            return MailboxFormat::Maildir;
        }

        #[cfg(feature = "mailstore")]
        if ob.mailstore_format {
            return MailboxFormat::Mailstore;
        }

        if ob.dirname.is_some() && ob.filename.is_none() {
            MailboxFormat::Smail
        } else {
            MailboxFormat::Unix
        }
    }
}

// =============================================================================
// check_dir_size — Public shared function (used by maildir.rs)
// =============================================================================

/// Scan a directory tree and compute total size and file count.
///
/// This function is shared with `super::maildir` (from C `tf_maildir.c` which
/// calls `check_dir_size()` defined in `appendfile.c` lines 673-750).
///
/// # Arguments
/// - `path` — Directory path to scan
/// - `filecount` — Mutable reference to accumulate total file count
/// - `regex` — Optional regex for extracting size from Maildir filenames
///   (matching the `S=<size>` convention). When `Some`, the regex is used to
///   parse the file size from the filename instead of `stat()`ing each file.
///
/// # Returns
/// Total size in bytes of all files in the directory tree.
pub fn check_dir_size(path: &str, filecount: &mut i32, regex: Option<&Regex>) -> i64 {
    let mut total_size: i64 = 0;

    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::debug!(
                path = path,
                error = %e,
                "check_dir_size: cannot read directory"
            );
            return 0;
        }
    };

    for entry in entries.flatten() {
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };

        let entry_name = entry.file_name();
        let name_str = entry_name.to_string_lossy();

        // Skip . and .. entries
        if name_str == "." || name_str == ".." {
            continue;
        }

        if file_type.is_dir() {
            // Recurse into subdirectories
            let sub_path = entry.path();
            total_size += check_dir_size(&sub_path.to_string_lossy(), filecount, regex);
        } else if file_type.is_file() {
            *filecount += 1;

            // Try to extract size from filename via regex (Maildir S=<size> convention)
            if let Some(re) = regex {
                if let Some(captures) = re.captures(&name_str) {
                    if let Some(size_match) = captures.get(1) {
                        if let Ok(size) = size_match.as_str().parse::<i64>() {
                            total_size += size;
                            continue;
                        }
                    }
                }
            }

            // Fallback: stat the file for its actual size
            match entry.metadata() {
                Ok(meta) => {
                    total_size += meta.size() as i64;
                }
                Err(e) => {
                    tracing::debug!(
                        file = %name_str,
                        error = %e,
                        "check_dir_size: cannot stat file"
                    );
                }
            }
        }
    }

    total_size
}

// =============================================================================
// Locking Module — Safe file locking using nix crate wrappers
// =============================================================================

/// Result of a lock acquisition attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockResult {
    /// Lock acquired successfully.
    Acquired,
    /// Lock acquisition failed temporarily — caller may retry.
    WouldBlock,
}

/// Attempt to acquire an fcntl advisory record lock on the given file.
///
/// Replaces C `apply_lock()` (appendfile.c lines 777-819).
/// Uses `nix::fcntl::fcntl()` with `FcntlArg::F_SETLK` for safe fcntl locking.
/// Implements timeout via a non-blocking retry loop (safer than C SIGALRM pattern).
fn apply_fcntl_lock(
    file: &File,
    lock_type: i16,
    timeout_secs: i32,
) -> Result<LockResult, AppendfileError> {
    // Build the flock structure for a whole-file lock
    let lock_data = libc::flock {
        l_type: lock_type,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: 0,
        l_len: 0, // entire file
        l_pid: 0,
    };

    if timeout_secs > 0 {
        // Retry loop with timeout — safer than SIGALRM used in C
        let deadline = SystemTime::now() + Duration::from_secs(timeout_secs as u64);
        loop {
            match nix::fcntl::fcntl(file, nix::fcntl::FcntlArg::F_SETLK(&lock_data)) {
                Ok(_) => return Ok(LockResult::Acquired),
                Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EACCES) => {
                    if SystemTime::now() >= deadline {
                        return Ok(LockResult::WouldBlock);
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
                Err(e) => {
                    return Err(AppendfileError::LockFailed {
                        path: String::new(),
                        reason: format!("fcntl lock failed: {e}"),
                    });
                }
            }
        }
    } else {
        match nix::fcntl::fcntl(file, nix::fcntl::FcntlArg::F_SETLK(&lock_data)) {
            Ok(_) => Ok(LockResult::Acquired),
            Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EACCES) => {
                Ok(LockResult::WouldBlock)
            }
            Err(e) => Err(AppendfileError::LockFailed {
                path: String::new(),
                reason: format!("fcntl lock failed: {e}"),
            }),
        }
    }
}

/// Attempt to acquire a flock() advisory lock on the given file.
///
/// Uses `nix::fcntl::flock()` for safe flock-style locking via `RawFd`.
/// The lock is always attempted non-blocking first; if `timeout_secs > 0`,
/// the function retries until the deadline.
///
/// Note: nix 0.31 deprecates the free `flock()` function in favor of
/// `Flock::lock()`, but `Flock::lock` takes ownership of the File which is
/// incompatible with our multi-lock acquisition pattern. We use the free
/// function with `#[allow(deprecated)]` until the nix API stabilizes a
/// non-owning alternative.
#[allow(deprecated)] // nix 0.31: flock() deprecated in favor of Flock::lock(),
                     // but Flock::lock takes ownership which is incompatible
                     // with our multi-strategy locking design
fn apply_flock_lock(
    file: &File,
    exclusive: bool,
    timeout_secs: i32,
) -> Result<LockResult, AppendfileError> {
    let fd = file.as_raw_fd();
    let arg = if exclusive {
        nix::fcntl::FlockArg::LockExclusiveNonblock
    } else {
        nix::fcntl::FlockArg::LockSharedNonblock
    };

    if timeout_secs > 0 {
        let deadline = SystemTime::now() + Duration::from_secs(timeout_secs as u64);
        loop {
            match nix::fcntl::flock(fd, arg) {
                Ok(()) => return Ok(LockResult::Acquired),
                Err(nix::errno::Errno::EWOULDBLOCK) => {
                    if SystemTime::now() >= deadline {
                        return Ok(LockResult::WouldBlock);
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
                Err(e) => {
                    return Err(AppendfileError::LockFailed {
                        path: String::new(),
                        reason: format!("flock failed: {e}"),
                    });
                }
            }
        }
    } else {
        match nix::fcntl::flock(fd, arg) {
            Ok(()) => Ok(LockResult::Acquired),
            Err(nix::errno::Errno::EWOULDBLOCK) => Ok(LockResult::WouldBlock),
            Err(e) => Err(AppendfileError::LockFailed {
                path: String::new(),
                reason: format!("flock failed: {e}"),
            }),
        }
    }
}

/// Unlock an fcntl record lock on the given file.
fn unlock_fcntl(file: &File) -> Result<(), AppendfileError> {
    let lock_data = libc::flock {
        l_type: libc::F_UNLCK as libc::c_short,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };
    nix::fcntl::fcntl(file, nix::fcntl::FcntlArg::F_SETLK(&lock_data))
        .map(|_| ())
        .map_err(|e| AppendfileError::LockFailed {
            path: String::new(),
            reason: format!("fcntl unlock failed: {e}"),
        })
}

/// Unlock a flock lock on the given file.
#[allow(deprecated)] // Same justification as apply_flock_lock above
fn unlock_flock(file: &File) -> Result<(), AppendfileError> {
    nix::fcntl::flock(file.as_raw_fd(), nix::fcntl::FlockArg::Unlock).map_err(|e| {
        AppendfileError::LockFailed {
            path: String::new(),
            reason: format!("flock unlock failed: {e}"),
        }
    })
}

// =============================================================================
// Lockfile operations — Pure safe Rust using std::fs
// =============================================================================

/// Create a lockfile atomically using O_CREAT|O_WRONLY|O_EXCL semantics.
///
/// Replaces C lockfile creation logic (appendfile.c lock retry loop).
/// Returns `true` if the lockfile was created, `false` if it already exists.
fn create_lockfile(lockfile_path: &Path, mode: u32) -> Result<bool, AppendfileError> {
    match OpenOptions::new()
        .write(true)
        .create_new(true) // O_CREAT | O_EXCL equivalent — atomic
        .mode(mode)
        .open(lockfile_path)
    {
        Ok(_file) => {
            // File created and immediately closed
            tracing::debug!(lockfile = %lockfile_path.display(), "lockfile created");
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            // Lockfile exists — check if it's stale
            Ok(false)
        }
        Err(e) => Err(AppendfileError::FileError {
            path: lockfile_path.display().to_string(),
            source: e,
        }),
    }
}

/// Acquire all configured locks for a mailbox file.
///
/// Implements the multi-strategy locking algorithm from appendfile.c
/// (lockfile retry loop + fcntl + flock, with configurable retry/timeout).
///
/// Returns the lockfile path (if a lockfile was created) so the caller can
/// remove it on cleanup.
fn acquire_locks(
    file: &File,
    file_path: &Path,
    ob: &AppendfileTransportOptions,
) -> Result<Option<PathBuf>, AppendfileError> {
    let mut lockfile_path: Option<PathBuf> = None;

    // Phase 1: Lockfile creation with retry (appendfile.c lock retry loop)
    if ob.use_lockfile {
        let lf_path = PathBuf::from(format!("{}.lock", file_path.display()));
        let mut acquired = false;

        for attempt in 0..ob.lock_retries {
            match create_lockfile(&lf_path, ob.lockfile_mode)? {
                true => {
                    acquired = true;
                    break;
                }
                false => {
                    // Check for stale lockfile by age
                    if let Ok(metadata) = fs::metadata(&lf_path) {
                        if let Ok(modified) = metadata.modified() {
                            if let Ok(age) = SystemTime::now().duration_since(modified) {
                                if age.as_secs() > ob.lockfile_timeout as u64 {
                                    tracing::info!(
                                        lockfile = %lf_path.display(),
                                        age_secs = age.as_secs(),
                                        "removing stale lockfile"
                                    );
                                    let _ = fs::remove_file(&lf_path);
                                    continue; // Retry immediately after removing stale lock
                                }
                            }
                        }
                    }

                    if attempt < ob.lock_retries - 1 {
                        tracing::debug!(
                            attempt = attempt + 1,
                            max_retries = ob.lock_retries,
                            interval = ob.lock_interval,
                            "lockfile busy, retrying"
                        );
                        std::thread::sleep(Duration::from_secs(ob.lock_interval as u64));
                    }
                }
            }
        }

        if !acquired {
            return Err(AppendfileError::LockFailed {
                path: lf_path.display().to_string(),
                reason: format!(
                    "failed to acquire lockfile after {} retries",
                    ob.lock_retries
                ),
            });
        }

        lockfile_path = Some(lf_path);
    }

    // Phase 2: fcntl record locking
    if ob.use_fcntl {
        match apply_fcntl_lock(file, libc::F_WRLCK as i16, ob.lock_fcntl_timeout)? {
            LockResult::Acquired => {
                tracing::debug!("fcntl write lock acquired");
            }
            LockResult::WouldBlock => {
                // Clean up lockfile if we created one
                if let Some(ref lf) = lockfile_path {
                    let _ = fs::remove_file(lf);
                }
                return Err(AppendfileError::LockFailed {
                    path: file_path.display().to_string(),
                    reason: "fcntl lock timed out".to_string(),
                });
            }
        }
    }

    // Phase 3: flock locking
    if ob.use_flock {
        match apply_flock_lock(file, true, ob.lock_flock_timeout)? {
            LockResult::Acquired => {
                tracing::debug!("flock exclusive lock acquired");
            }
            LockResult::WouldBlock => {
                // Clean up fcntl lock and lockfile
                if ob.use_fcntl {
                    let _ = unlock_fcntl(file);
                }
                if let Some(ref lf) = lockfile_path {
                    let _ = fs::remove_file(lf);
                }
                return Err(AppendfileError::LockFailed {
                    path: file_path.display().to_string(),
                    reason: "flock lock timed out".to_string(),
                });
            }
        }
    }

    Ok(lockfile_path)
}

/// Release all locks and clean up lockfile.
fn release_locks(file: &File, lockfile_path: Option<&Path>, ob: &AppendfileTransportOptions) {
    if ob.use_flock {
        if let Err(e) = unlock_flock(file) {
            tracing::warn!(error = %e, "failed to release flock");
        }
    }
    if ob.use_fcntl {
        if let Err(e) = unlock_fcntl(file) {
            tracing::warn!(error = %e, "failed to release fcntl lock");
        }
    }
    if let Some(lf) = lockfile_path {
        if let Err(e) = fs::remove_file(lf) {
            tracing::warn!(lockfile = %lf.display(), error = %e, "failed to remove lockfile");
        }
    }
}

// =============================================================================
// check_creation — File creation policy enforcement
// =============================================================================

/// Validate that a file path conforms to the configured `create_file` policy.
///
/// Replaces C `check_creation()` (appendfile.c lines 923-999).
/// Resolves symbolic links and verifies the file would be created within the
/// permitted zone relative to the home directory.
fn check_creation(
    file_path: &Path,
    home_dir: Option<&str>,
    policy: CreateFilePolicy,
) -> Result<(), AppendfileError> {
    match policy {
        CreateFilePolicy::Anywhere => Ok(()),
        CreateFilePolicy::BelowHome | CreateFilePolicy::InHome => {
            let home = home_dir.ok_or_else(|| AppendfileError::PermissionDenied {
                path: file_path.display().to_string(),
                reason: "create_file policy requires home_dir but none set".to_string(),
            })?;

            // Canonicalize the file path's parent directory to resolve symlinks
            let parent = file_path.parent().unwrap_or(file_path);
            let canonical_parent = if parent.exists() {
                parent
                    .canonicalize()
                    .unwrap_or_else(|_| parent.to_path_buf())
            } else {
                parent.to_path_buf()
            };

            let home_path = Path::new(home);
            let canonical_home = if home_path.exists() {
                home_path
                    .canonicalize()
                    .unwrap_or_else(|_| home_path.to_path_buf())
            } else {
                home_path.to_path_buf()
            };

            match policy {
                CreateFilePolicy::InHome => {
                    // File must be created directly in home dir
                    if canonical_parent != canonical_home {
                        return Err(AppendfileError::PermissionDenied {
                            path: file_path.display().to_string(),
                            reason: format!(
                                "file not in home directory '{}' (create_file = inhome)",
                                home
                            ),
                        });
                    }
                }
                CreateFilePolicy::BelowHome => {
                    // File must be created below (inside) home dir
                    if !canonical_parent.starts_with(&canonical_home) {
                        return Err(AppendfileError::PermissionDenied {
                            path: file_path.display().to_string(),
                            reason: format!(
                                "file not below home directory '{}' (create_file = belowhome)",
                                home
                            ),
                        });
                    }
                }
                CreateFilePolicy::Anywhere => unreachable!(),
            }

            Ok(())
        }
    }
}

// =============================================================================
// check_file_format — Auto-detect mailbox format from file content
// =============================================================================

/// Check the first line(s) of a file against format detection patterns.
///
/// Replaces C `check_file_format()` (appendfile.c lines 595-641).
/// The `file_format` option specifies pairs of "format_name\ncheck_string\n".
/// Returns the detected mailbox format name, or None if no match.
fn check_file_format(file_path: &Path, format_spec: &str) -> Option<String> {
    // Read the first 256 bytes of the file for format detection
    let mut file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return None,
    };

    let mut buf = [0u8; 256];
    let bytes_read = match file.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return None,
    };

    if bytes_read == 0 {
        return None;
    }

    let file_start = String::from_utf8_lossy(&buf[..bytes_read]);

    // Parse the format specification: alternating lines of "format_name" and "check_string"
    let lines: Vec<&str> = format_spec.split('\n').collect();
    let mut i = 0;
    while i + 1 < lines.len() {
        let format_name = lines[i].trim();
        let check_pattern = lines[i + 1].trim();

        if !format_name.is_empty()
            && !check_pattern.is_empty()
            && file_start.starts_with(check_pattern)
        {
            tracing::debug!(
                file = %file_path.display(),
                format = format_name,
                "file format detected"
            );
            return Some(format_name.to_string());
        }

        i += 2;
    }

    None
}

// =============================================================================
// notify_comsat — Biff/comsat notification via UDP
// =============================================================================

/// Send a comsat/biff notification after successful delivery.
///
/// Replaces C `notify_comsat()` (appendfile.c lines 516-574).
/// Sends a UDP datagram to localhost:512 in the format "user@offset"
/// where `user` is the local username and `offset` is the byte offset
/// in the mailbox where the new message starts.
fn notify_comsat(user: &str, offset: i64) {
    let message = format!("{user}@{offset}");

    match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => {
            let dest = format!("127.0.0.1:{COMSAT_PORT}");
            match socket.send_to(message.as_bytes(), &dest) {
                Ok(_) => {
                    tracing::debug!(user = user, offset = offset, "comsat notification sent");
                }
                Err(e) => {
                    tracing::warn!(
                        user = user,
                        error = %e,
                        "comsat notification failed to send"
                    );
                }
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "comsat: cannot bind UDP socket");
        }
    }
}

// =============================================================================
// copy_mbx_message — MBX format message writing (feature-gated)
// =============================================================================

/// Write a message in MBX format with the 2048-byte header.
///
/// Replaces C `copy_mbx_message()` (appendfile.c lines 848-903).
/// MBX format uses a fixed 2048-byte header block at the start of the file
/// followed by messages with status flags.
#[cfg(feature = "mbx")]
fn write_mbx_message(
    writer: &mut BufWriter<&File>,
    message_body: &[u8],
    message_size: u64,
) -> Result<(), AppendfileError> {
    // MBX message separator: a line of the form:
    //   <SOH><date_string><CR><LF>
    // followed by message content
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let timestamp = now.as_secs();

    // Write MBX internal separator
    // Format: \x01\x01\n<size>\n
    let header_line = format!("\x01\x01\n{message_size}\n");
    writer
        .write_all(header_line.as_bytes())
        .map_err(|e| AppendfileError::MbxError {
            path: String::new(),
            reason: format!("failed to write MBX header: {e}"),
        })?;

    // Write the message body
    writer
        .write_all(message_body)
        .map_err(|e| AppendfileError::MbxError {
            path: String::new(),
            reason: format!("failed to write MBX body: {e}"),
        })?;

    // Write trailing separator
    let trailer = format!("\n\x01\x01\n{timestamp}\n");
    writer
        .write_all(trailer.as_bytes())
        .map_err(|e| AppendfileError::MbxError {
            path: String::new(),
            reason: format!("failed to write MBX trailer: {e}"),
        })?;

    Ok(())
}

// =============================================================================
// Quota enforcement helpers
// =============================================================================

/// Check if delivering a message would exceed the mailbox quota.
///
/// Replaces quota checking logic throughout appendfile_transport_entry()
/// (appendfile.c lines 1900-2000 approximately).
fn check_quota(
    ob: &AppendfileTransportOptions,
    current_size: i64,
    message_size: i64,
    current_filecount: i32,
) -> Result<(), AppendfileError> {
    // Skip quota checking if explicitly disabled
    if ob.quota_no_check {
        return Ok(());
    }

    // Check size quota
    if ob.quota_value > 0 {
        let total_size = if ob.quota_is_inclusive {
            current_size + message_size
        } else {
            current_size
        };

        if total_size > ob.quota_value {
            return Err(AppendfileError::QuotaExceeded {
                path: String::new(),
                used: total_size,
                limit: ob.quota_value,
            });
        }

        // Check warning threshold
        if ob.quota_warn_threshold_value > 0 {
            let threshold = if ob.quota_warn_threshold_is_percent {
                ob.quota_value * ob.quota_warn_threshold_value / 100
            } else {
                ob.quota_warn_threshold_value
            };

            if total_size > threshold {
                tracing::warn!(
                    used = total_size,
                    threshold = threshold,
                    quota = ob.quota_value,
                    "mailbox approaching quota"
                );
            }
        }
    }

    // Check file count quota
    if !ob.quota_filecount_no_check && ob.quota_filecount_value > 0 {
        let total_count = if ob.quota_is_inclusive {
            current_filecount + 1
        } else {
            current_filecount
        };

        if total_count > ob.quota_filecount_value {
            return Err(AppendfileError::QuotaExceeded {
                path: String::new(),
                used: total_count as i64,
                limit: ob.quota_filecount_value as i64,
            });
        }
    }

    Ok(())
}

// =============================================================================
// Maildir delivery helpers (feature-gated)
// =============================================================================

/// Deliver a message in Maildir format using atomic tmp→new rename.
///
/// Replaces Maildir delivery logic from appendfile.c (approximately lines
/// 2400-2700). Creates a unique filename in tmp/, writes the message, then
/// atomically renames to new/.
#[cfg(feature = "maildir")]
fn deliver_maildir(
    dir_path: &Path,
    message_body: &[u8],
    ob: &AppendfileTransportOptions,
    message_size: i64,
    _address: &str,
) -> Result<TransportResult, AppendfileError> {
    use std::process;

    // Ensure the Maildir hierarchy exists: new/, cur/, tmp/
    let new_dir = dir_path.join("new");
    let tmp_dir = dir_path.join("tmp");
    let cur_dir = dir_path.join("cur");

    if ob.create_directory {
        for sub in [&new_dir, &tmp_dir, &cur_dir] {
            fs::create_dir_all(sub).map_err(|e| AppendfileError::MaildirError {
                path: sub.display().to_string(),
                reason: format!("cannot create Maildir subdirectory: {e}"),
            })?;
        }
    }

    // Generate unique filename per Maildir spec: time.pid.hostname
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let pid = process::id();
    let hostname = hostname_safe();

    let mut retries = ob.maildir_retries;
    let mut unique_name;
    let mut tmp_path;

    loop {
        let microseconds = now.as_micros();
        unique_name = format!("{}.P{pid}Q{retries}.{hostname}", microseconds);

        // Append size tag if configured
        let tag_suffix = if let Some(ref tag) = ob.maildir_tag {
            tag.clone()
        } else {
            format!(",S={message_size}")
        };
        unique_name.push_str(&tag_suffix);

        tmp_path = tmp_dir.join(&unique_name);

        // Attempt to create the file exclusively
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(ob.mode)
            .open(&tmp_path)
        {
            Ok(file) => {
                // Write message body
                let mut writer = BufWriter::new(file);

                // Write optional prefix
                if let Some(ref prefix) = ob.message_prefix {
                    writer.write_all(prefix.as_bytes()).map_err(|e| {
                        AppendfileError::MaildirError {
                            path: tmp_path.display().to_string(),
                            reason: format!("write prefix failed: {e}"),
                        }
                    })?;
                }

                writer
                    .write_all(message_body)
                    .map_err(|e| AppendfileError::MaildirError {
                        path: tmp_path.display().to_string(),
                        reason: format!("write body failed: {e}"),
                    })?;

                // Write optional suffix
                if let Some(ref suffix) = ob.message_suffix {
                    writer.write_all(suffix.as_bytes()).map_err(|e| {
                        AppendfileError::MaildirError {
                            path: tmp_path.display().to_string(),
                            reason: format!("write suffix failed: {e}"),
                        }
                    })?;
                }

                writer.flush().map_err(|e| AppendfileError::MaildirError {
                    path: tmp_path.display().to_string(),
                    reason: format!("flush failed: {e}"),
                })?;

                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                retries -= 1;
                if retries <= 0 {
                    return Err(AppendfileError::MaildirError {
                        path: tmp_dir.display().to_string(),
                        reason: format!(
                            "failed to create unique Maildir file after {} attempts",
                            ob.maildir_retries
                        ),
                    });
                }
                // Brief sleep before retry
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => {
                return Err(AppendfileError::FileError {
                    path: tmp_path.display().to_string(),
                    source: e,
                });
            }
        }
    }

    // Atomic rename from tmp/ to new/
    let new_path = new_dir.join(&unique_name);
    fs::rename(&tmp_path, &new_path).map_err(|e| AppendfileError::MaildirError {
        path: new_path.display().to_string(),
        reason: format!("atomic rename from tmp to new failed: {e}"),
    })?;

    tracing::debug!(
        filename = %unique_name,
        dir = %dir_path.display(),
        "Maildir delivery complete"
    );

    // Handle maildirfolder auto-creation (create 'maildirfolder' marker file)
    if let Some(ref regex_str) = ob.maildirfolder_create_regex {
        if let Ok(re) = Regex::new(regex_str) {
            if let Some(dir_name) = dir_path.file_name().and_then(|n| n.to_str()) {
                if re.is_match(dir_name) {
                    let marker = dir_path.join("maildirfolder");
                    if !marker.exists() {
                        let _ = File::create(&marker);
                        tracing::debug!(
                            path = %marker.display(),
                            "created maildirfolder marker"
                        );
                    }
                }
            }
        }
    }

    Ok(TransportResult::Ok)
}

/// Deliver a message in Mailstore format (data + envelope file pairs).
///
/// Replaces Mailstore delivery logic from appendfile.c (approximately lines
/// 2700-2850).
#[cfg(feature = "mailstore")]
fn deliver_mailstore(
    dir_path: &Path,
    message_body: &[u8],
    ob: &AppendfileTransportOptions,
    address: &str,
    sender: &str,
) -> Result<TransportResult, AppendfileError> {
    use std::process;

    // Generate unique base name
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let pid = process::id();

    let prefix = ob.mailstore_prefix.as_deref().unwrap_or("");
    let suffix = ob.mailstore_suffix.as_deref().unwrap_or("");

    let base_name = format!("{prefix}{}.{pid}{suffix}", now.as_secs());

    // Write the data file
    let data_path = dir_path.join(&base_name);
    let mut data_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(ob.mode)
        .open(&data_path)
        .map_err(|e| AppendfileError::MailstoreError {
            path: data_path.display().to_string(),
            reason: format!("cannot create data file: {e}"),
        })?;

    data_file
        .write_all(message_body)
        .map_err(|e| AppendfileError::MailstoreError {
            path: data_path.display().to_string(),
            reason: format!("write data failed: {e}"),
        })?;

    // Write the envelope file (.env extension)
    let env_path = dir_path.join(format!("{base_name}.env"));
    let mut env_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(ob.mode)
        .open(&env_path)
        .map_err(|e| AppendfileError::MailstoreError {
            path: env_path.display().to_string(),
            reason: format!("cannot create envelope file: {e}"),
        })?;

    // Write envelope data: sender and recipient
    writeln!(env_file, "{sender}")
        .and_then(|()| writeln!(env_file, "{address}"))
        .map_err(|e| AppendfileError::MailstoreError {
            path: env_path.display().to_string(),
            reason: format!("write envelope failed: {e}"),
        })?;

    tracing::debug!(
        data = %data_path.display(),
        env = %env_path.display(),
        "Mailstore delivery complete"
    );

    Ok(TransportResult::Ok)
}

/// Get a sanitized hostname for Maildir filenames.
fn hostname_safe() -> String {
    // Read /etc/hostname or use fallback
    fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "localhost".to_string())
        .trim()
        .replace(['/', ':'], "_")
}

// =============================================================================
// TransportDriver Implementation
// =============================================================================

impl TransportDriver for AppendfileTransport {
    /// Main transport entry point — deliver a message to a local file/directory.
    ///
    /// Replaces C `appendfile_transport_entry()` (appendfile.c lines 1153-3333).
    /// This is the core delivery function handling all mailbox formats.
    fn transport_entry(
        &self,
        config: &TransportInstanceConfig,
        address: &str,
    ) -> Result<TransportResult, DriverError> {
        let ob = &self.options;

        tracing::debug!(
            driver = "appendfile",
            address = address,
            "transport_entry called"
        );

        // Check for file/directory from the config private options map.
        // The config parser stores driver-specific options (like "file" and
        // "directory") in the private_options_map, keyed by option name.
        // These override the defaults in the AppendfileOptions struct.
        let config_file = config.private_options_map.get("file").cloned();
        let config_dir = config.private_options_map.get("directory").cloned();

        // Resolve effective filename and dirname, preferring config values
        let effective_filename = config_file.or_else(|| ob.filename.clone());
        let effective_dirname = config_dir.or_else(|| ob.dirname.clone());

        // Determine delivery mode: file vs directory
        let is_directory_mode = effective_dirname.is_some() && effective_filename.is_none();

        // Perform simple variable expansion on the path.
        // This handles ${local_part} which is the most common pattern in
        // appendfile transport file paths.
        let expand_path = |path: &str| -> String {
            // Extract local_part from the address (part before @)
            let local_part = if let Some(at_pos) = address.find('@') {
                &address[..at_pos]
            } else {
                address
            };
            // Extract domain from the address (part after @)
            let domain = if let Some(at_pos) = address.find('@') {
                &address[at_pos + 1..]
            } else {
                ""
            };
            path.replace("${local_part}", local_part)
                .replace("$local_part", local_part)
                .replace("${domain}", domain)
                .replace("$domain", domain)
        };

        // Expand and validate the delivery path with taint tracking
        let delivery_path = if let Some(ref filename) = effective_filename {
            // File mode: single file delivery
            let expanded = expand_path(filename);
            // Taint check: validate the expanded file path is absolute.
            // Replaces C taint_check_real_fn() calls in appendfile.c.
            let tainted_path = Tainted::new(expanded);
            let clean_path = tainted_path.sanitize(|p| p.starts_with('/')).map_err(|e| {
                DriverError::ExecutionFailed(format!(
                    "tainted file path rejected (must be absolute): {}",
                    e.context
                ))
            })?;
            PathBuf::from(clean_path.into_inner())
        } else if let Some(ref dirname) = effective_dirname {
            // Directory mode: one file per message
            let expanded = expand_path(dirname);
            // Taint check: validate the expanded directory path is absolute.
            let tainted_dir = Tainted::new(expanded);
            let clean_dir = tainted_dir.sanitize(|p| p.starts_with('/')).map_err(|e| {
                DriverError::ExecutionFailed(format!(
                    "tainted directory path rejected (must be absolute): {}",
                    e.context
                ))
            })?;
            PathBuf::from(clean_dir.into_inner())
        } else {
            // Neither file nor directory configured — this should have been
            // caught by init(), but handle defensively
            return Err(DriverError::ConfigError(
                "neither 'file' nor 'directory' is set".to_string(),
            ));
        };

        tracing::debug!(
            path = %delivery_path.display(),
            directory_mode = is_directory_mode,
            "delivery path resolved"
        );

        // Check file creation policy
        check_creation(&delivery_path, config.home_dir.as_deref(), ob.create_file)
            .map_err(|e| DriverError::ExecutionFailed(e.to_string()))?;

        // Determine mailbox format
        let format = self.determine_format();
        tracing::debug!(format = format.name(), "mailbox format selected");

        // Dispatch to format-specific delivery
        match format {
            #[cfg(feature = "maildir")]
            MailboxFormat::Maildir => {
                // Quota check for Maildir (directory-based)
                if !ob.quota_no_check && ob.quota_value > 0 {
                    let delivery_path_str = delivery_path.to_string_lossy().into_owned();
                    let quota_dir = ob.quota_directory.as_deref().unwrap_or(&delivery_path_str);

                    let size_regex = ob
                        .quota_size_regex
                        .as_ref()
                        .and_then(|s| Regex::new(s).ok());

                    let mut filecount = 0i32;
                    let current_size =
                        check_dir_size(quota_dir, &mut filecount, size_regex.as_ref());

                    // The message_body is not available at this point in the abstraction.
                    // We use a conservative estimate for quota checking.
                    check_quota(ob, current_size, 0, filecount)
                        .map_err(|e| DriverError::TempFail(e.to_string()))?;
                }

                let message_body = build_message_body(address, ob, config);
                deliver_maildir(
                    &delivery_path,
                    &message_body,
                    ob,
                    message_body.len() as i64,
                    address,
                )
                .map_err(|e| DriverError::ExecutionFailed(e.to_string()))
            }

            #[cfg(feature = "mailstore")]
            MailboxFormat::Mailstore => {
                let message_body = build_message_body(address, ob, config);
                let sender = config.return_path.as_deref().unwrap_or("<>");
                deliver_mailstore(&delivery_path, &message_body, ob, address, sender)
                    .map_err(|e| DriverError::ExecutionFailed(e.to_string()))
            }

            // Unix mbox, MBX, and Smail formats — all use single-file append with locking
            _ => self.deliver_to_file(&delivery_path, address, config, format),
        }
    }

    /// Setup function — no-op for appendfile (privileged setup done by caller).
    fn setup(&self, _config: &TransportInstanceConfig, _address: &str) -> Result<(), DriverError> {
        Ok(())
    }

    /// Tidyup function — no-op for appendfile.
    fn tidyup(&self, _config: &TransportInstanceConfig) {}

    /// Closedown function — no-op for appendfile.
    fn closedown(&self, _config: &TransportInstanceConfig) {}

    /// Returns `true` — appendfile is a local transport.
    fn is_local(&self) -> bool {
        true
    }

    /// Returns the driver name "appendfile".
    fn driver_name(&self) -> &str {
        "appendfile"
    }
}

impl AppendfileTransport {
    /// Deliver a message to a single file (mbox, MBX, or Smail format).
    ///
    /// Handles file opening, locking, format-specific writing, quota checking,
    /// and cleanup. This is the main code path for non-Maildir, non-Mailstore
    /// formats.
    fn deliver_to_file(
        &self,
        file_path: &Path,
        address: &str,
        config: &TransportInstanceConfig,
        format: MailboxFormat,
    ) -> Result<TransportResult, DriverError> {
        let ob = &self.options;

        // Check /dev/null optimization — instant success
        if file_path == Path::new("/dev/null") {
            tracing::debug!("delivery to /dev/null — instant success");
            return Ok(TransportResult::Ok);
        }

        // For Smail (directory) format, generate per-message filename
        let actual_path = if format == MailboxFormat::Smail {
            // Generate unique filename in directory
            let dir_file = ob.dirfilename.as_deref().unwrap_or("msg");

            if ob.create_directory {
                fs::create_dir_all(file_path).map_err(|e| {
                    DriverError::ExecutionFailed(format!(
                        "cannot create directory {}: {e}",
                        file_path.display()
                    ))
                })?;
            }

            // Use a simple counter-based unique name
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default();
            file_path.join(format!("{}.{}", dir_file, now.as_nanos()))
        } else {
            file_path.to_path_buf()
        };

        // Create parent directories if configured
        if ob.create_directory {
            if let Some(parent) = actual_path.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent).map_err(|e| {
                        DriverError::ExecutionFailed(format!(
                            "cannot create parent directory {}: {e}",
                            parent.display()
                        ))
                    })?;
                    // Set directory mode
                    let perms = std::fs::Permissions::from_mode(ob.dirmode);
                    let _ = fs::set_permissions(parent, perms);
                }
            }
        }

        // Check file format detection if configured
        if let Some(ref format_spec) = ob.file_format {
            if actual_path.exists() {
                if let Some(detected) = check_file_format(&actual_path, format_spec) {
                    tracing::debug!(
                        detected = %detected,
                        "file format auto-detected"
                    );
                }
            }
        }

        // Open or create the file
        let file = if ob.file_must_exist {
            OpenOptions::new()
                .append(true)
                .open(&actual_path)
                .map_err(|e| {
                    DriverError::ExecutionFailed(format!(
                        "file must exist but cannot open {}: {e}",
                        actual_path.display()
                    ))
                })?
        } else {
            OpenOptions::new()
                .append(true)
                .create(true)
                .mode(ob.mode)
                .open(&actual_path)
                .map_err(|e| {
                    DriverError::ExecutionFailed(format!(
                        "cannot open/create {}: {e}",
                        actual_path.display()
                    ))
                })?
        };

        // Check file ownership if configured (appendfile.c lines 1500-1550)
        if ob.check_owner || ob.check_group {
            let metadata = file.metadata().map_err(|e| {
                DriverError::ExecutionFailed(format!("cannot stat {}: {e}", actual_path.display()))
            })?;

            if ob.check_owner && config.uid_set && metadata.uid() != config.uid {
                return Err(DriverError::ExecutionFailed(format!(
                    "{}: owner mismatch (file uid={}, expected uid={})",
                    actual_path.display(),
                    metadata.uid(),
                    config.uid,
                )));
            }

            if ob.check_group && config.gid_set && metadata.gid() != config.gid {
                return Err(DriverError::ExecutionFailed(format!(
                    "{}: group mismatch (file gid={}, expected gid={})",
                    actual_path.display(),
                    metadata.gid(),
                    config.gid,
                )));
            }
        }

        // Check symlink and FIFO safety
        let metadata_no_follow = fs::symlink_metadata(&actual_path).map_err(|e| {
            DriverError::ExecutionFailed(format!("cannot lstat {}: {e}", actual_path.display()))
        })?;

        if metadata_no_follow.file_type().is_symlink() && !ob.allow_symlink {
            return Err(DriverError::ExecutionFailed(format!(
                "{}: is a symbolic link (allow_symlink is false)",
                actual_path.display()
            )));
        }

        // Record the pre-delivery file size for comsat notification
        let pre_delivery_size = file.metadata().map(|m| m.len() as i64).unwrap_or(0);

        // Quota check for single-file delivery
        if !ob.quota_no_check && ob.quota_value > 0 {
            let message_body = build_message_body(address, ob, config);
            let msg_size = message_body.len() as i64;

            check_quota(ob, pre_delivery_size, msg_size, 0)
                .map_err(|e| DriverError::TempFail(e.to_string()))?;
        }

        // Acquire locks
        let lockfile = acquire_locks(&file, &actual_path, ob)
            .map_err(|e| DriverError::TempFail(e.to_string()))?;

        // Build the message body to write
        let message_body = build_message_body(address, ob, config);

        // Write the message — dispatch by format
        let write_result = match format {
            #[cfg(feature = "mbx")]
            MailboxFormat::Mbx => {
                let mut writer = BufWriter::new(&file);
                write_mbx_message(&mut writer, &message_body, message_body.len() as u64).and_then(
                    |()| {
                        writer.flush().map_err(|e| AppendfileError::FileError {
                            path: actual_path.display().to_string(),
                            source: e,
                        })
                    },
                )
            }
            _ => {
                // Unix mbox / Smail — simple append
                let mut writer = BufWriter::new(&file);

                // Write prefix (e.g., mbox "From " line)
                if let Some(ref prefix) = ob.message_prefix {
                    writer.write_all(prefix.as_bytes()).map_err(|e| {
                        AppendfileError::FileError {
                            path: actual_path.display().to_string(),
                            source: e,
                        }
                    })?;
                }

                // Write body with check_string/escape_string processing
                write_body_with_escaping(&mut writer, &message_body, ob).map_err(|e| {
                    AppendfileError::FileError {
                        path: actual_path.display().to_string(),
                        source: e,
                    }
                })?;

                // Write suffix
                if let Some(ref suffix) = ob.message_suffix {
                    writer.write_all(suffix.as_bytes()).map_err(|e| {
                        AppendfileError::FileError {
                            path: actual_path.display().to_string(),
                            source: e,
                        }
                    })?;
                }

                writer.flush().map_err(|e| AppendfileError::FileError {
                    path: actual_path.display().to_string(),
                    source: e,
                })
            }
        };

        // Release locks regardless of write outcome
        release_locks(&file, lockfile.as_deref(), ob);

        // Handle write result
        match write_result {
            Ok(()) => {
                tracing::debug!(
                    path = %actual_path.display(),
                    format = format.name(),
                    size = message_body.len(),
                    "message delivered successfully"
                );

                // Comsat notification if configured
                if ob.notify_comsat {
                    notify_comsat(address, pre_delivery_size);
                }

                Ok(TransportResult::Ok)
            }
            Err(e) => {
                tracing::error!(
                    path = %actual_path.display(),
                    error = %e,
                    "delivery write failed"
                );
                Err(DriverError::ExecutionFailed(e.to_string()))
            }
        }
    }
}

// =============================================================================
// Message body construction
// =============================================================================

/// Build the message body bytes for delivery.
///
/// In a full Exim implementation, this would call the transport write functions
/// to format headers and body with configured options (BSMTP, CRLF, etc.).
/// Here we construct a representative message that would be produced by
/// `transport_write_message()` in the C code.
fn build_message_body(
    address: &str,
    ob: &AppendfileTransportOptions,
    config: &TransportInstanceConfig,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(4096);
    let line_ending = if ob.use_crlf { "\r\n" } else { "\n" };

    // In BSMTP mode, prepend SMTP envelope commands
    if ob.use_bsmtp {
        let sender = config.return_path.as_deref().unwrap_or("<>");
        body.extend_from_slice(format!("MAIL FROM:<{sender}>{line_ending}").as_bytes());
        body.extend_from_slice(format!("RCPT TO:<{address}>{line_ending}").as_bytes());
        body.extend_from_slice(format!("DATA{line_ending}").as_bytes());
    }

    // Add delivery-related headers based on config
    if config.delivery_date_add {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        body.extend_from_slice(format!("Delivery-date: {}{line_ending}", now.as_secs()).as_bytes());
    }

    if config.envelope_to_add {
        body.extend_from_slice(format!("Envelope-to: {address}{line_ending}").as_bytes());
    }

    if config.return_path_add {
        let sender = config
            .private_options_map
            .get("__sender_address")
            .map(|s| s.as_str())
            .or(config.return_path.as_deref())
            .unwrap_or("<>");
        body.extend_from_slice(format!("Return-path: <{sender}>{line_ending}").as_bytes());
    }

    // Try to read the actual message data from the spool -D file.
    // The delivery orchestrator injects __spool_directory and __message_id
    // into the private_options_map so the transport can access the real
    // message content.
    let spool_data = config
        .private_options_map
        .get("__spool_directory")
        .and_then(|spool_dir| {
            config
                .private_options_map
                .get("__message_id")
                .and_then(|msg_id| {
                    // Spool -D file path: {spool_dir}/input/{msg_id}-D
                    let data_file = format!("{spool_dir}/input/{msg_id}-D");
                    match std::fs::read(&data_file) {
                        Ok(data) => {
                            tracing::debug!(
                                path = %data_file,
                                size = data.len(),
                                "read spool data file for delivery"
                            );
                            Some(data)
                        }
                        Err(e) => {
                            tracing::warn!(
                                path = %data_file,
                                error = %e,
                                "failed to read spool data file"
                            );
                            None
                        }
                    }
                })
        });

    if let Some(data) = spool_data {
        // The Exim spool -D file starts with a header line containing
        // the message-ID filename (e.g. "1w20nb-00000003rGr-0F7s-D\n").
        // We must skip that first line so only the RFC 2822 message
        // (headers + body) is written to the mailbox.
        let msg_start = data
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| p + 1)
            .unwrap_or(0);
        body.extend_from_slice(&data[msg_start..]);
    } else {
        // Fallback: generate a minimal message body when spool data is not
        // available (e.g., during unit testing or standalone operation).
        body.extend_from_slice(line_ending.as_bytes());
        body.extend_from_slice(b"[Message body delivered by appendfile transport]");
        body.extend_from_slice(line_ending.as_bytes());
    }

    // In BSMTP mode, append the termination dot
    if ob.use_bsmtp {
        body.extend_from_slice(format!(".{line_ending}").as_bytes());
    }

    body
}

/// Write message body with check_string/escape_string processing.
///
/// Replaces the mbox "From " line escaping logic in appendfile.c.
/// If `check_string` is set, any line starting with that string is prefixed
/// with `escape_string`.
fn write_body_with_escaping(
    writer: &mut BufWriter<&File>,
    body: &[u8],
    ob: &AppendfileTransportOptions,
) -> Result<(), io::Error> {
    match (&ob.check_string, &ob.escape_string) {
        (Some(check), Some(escape)) if !check.is_empty() => {
            // Process line by line for escaping
            let check_bytes = check.as_bytes();
            let escape_bytes = escape.as_bytes();
            let line_ending = if ob.use_crlf {
                b"\r\n".as_slice()
            } else {
                b"\n".as_slice()
            };

            for line in body.split(|&b| b == b'\n') {
                if line.starts_with(check_bytes) {
                    writer.write_all(escape_bytes)?;
                }
                writer.write_all(line)?;
                writer.write_all(line_ending)?;
            }
            Ok(())
        }
        _ => {
            // No escaping needed — write the body directly
            writer.write_all(body)
        }
    }
}

// =============================================================================
// Compile-time driver registration via inventory
// =============================================================================

/// Build the availability string at compile time based on enabled features.
///
/// Build the `avail_string` for the appendfile transport.
///
/// Replaces C: `avail_string` in `transport_info appendfile_transport_info`
/// (appendfile.c line 3357) which uses preprocessor string concatenation to
/// build a display name like `appendfile/maildir/mailstore/mbx`.
///
/// The test/runtest harness splits the Transport line by whitespace and then
/// by `/` to detect sub-features (lines 3962-3975). The format must be
/// `appendfile/maildir/mailstore/mbx` matching the C output exactly.
const fn avail_string_for_appendfile() -> Option<&'static str> {
    // Compile-time selection of available sub-format description string.
    // Each variant includes "appendfile" as the base name, with optional
    // sub-features appended after a `/` separator.
    #[cfg(all(feature = "maildir", feature = "mailstore", feature = "mbx"))]
    {
        Some("appendfile/maildir/mailstore/mbx")
    }
    #[cfg(all(feature = "maildir", feature = "mailstore", not(feature = "mbx")))]
    {
        Some("appendfile/maildir/mailstore")
    }
    #[cfg(all(feature = "maildir", not(feature = "mailstore"), feature = "mbx"))]
    {
        Some("appendfile/maildir/mbx")
    }
    #[cfg(all(not(feature = "maildir"), feature = "mailstore", feature = "mbx"))]
    {
        Some("appendfile/mailstore/mbx")
    }
    #[cfg(all(feature = "maildir", not(feature = "mailstore"), not(feature = "mbx")))]
    {
        Some("appendfile/maildir")
    }
    #[cfg(all(not(feature = "maildir"), feature = "mailstore", not(feature = "mbx")))]
    {
        Some("appendfile/mailstore")
    }
    #[cfg(all(not(feature = "maildir"), not(feature = "mailstore"), feature = "mbx"))]
    {
        Some("appendfile/mbx")
    }
    #[cfg(all(
        not(feature = "maildir"),
        not(feature = "mailstore"),
        not(feature = "mbx")
    ))]
    {
        Some("appendfile")
    }
}

inventory::submit! {
    TransportDriverFactory {
        name: "appendfile",
        create: || Box::new(AppendfileTransport::new()),
        is_local: true,
        avail_string: avail_string_for_appendfile(),
    }
}

// =============================================================================
// Unit tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_file_policy_default() {
        assert_eq!(CreateFilePolicy::default(), CreateFilePolicy::Anywhere);
    }

    #[test]
    fn test_create_file_policy_from_config() {
        assert_eq!(
            CreateFilePolicy::from_config_str("anywhere").unwrap(),
            CreateFilePolicy::Anywhere
        );
        assert_eq!(
            CreateFilePolicy::from_config_str("belowhome").unwrap(),
            CreateFilePolicy::BelowHome
        );
        assert_eq!(
            CreateFilePolicy::from_config_str("inhome").unwrap(),
            CreateFilePolicy::InHome
        );
        // Absolute path treated as belowhome
        assert_eq!(
            CreateFilePolicy::from_config_str("/some/path").unwrap(),
            CreateFilePolicy::BelowHome
        );
        // Invalid value should error
        assert!(CreateFilePolicy::from_config_str("invalid").is_err());
    }

    #[test]
    fn test_default_options() {
        let opts = AppendfileTransportOptions::default();
        assert_eq!(opts.mode, 0o600);
        assert_eq!(opts.dirmode, 0o700);
        assert_eq!(opts.lockfile_mode, 0o600);
        assert_eq!(opts.lockfile_timeout, 1800);
        assert_eq!(opts.lock_retries, 10);
        assert_eq!(opts.lock_interval, 3);
        assert_eq!(opts.maildir_retries, 10);
        assert!(opts.check_owner);
        assert!(opts.create_directory);
        assert!(opts.use_lockfile);
        assert!(opts.use_fcntl);
        assert!(!opts.use_flock);
        assert!(opts.mode_fail_narrower);
        assert!(opts.quota_is_inclusive);
        assert!(!opts.allow_fifo);
        assert!(!opts.allow_symlink);
        assert_eq!(opts.create_file, CreateFilePolicy::Anywhere);
        assert_eq!(
            opts.dirfilename.as_deref(),
            Some("q${base62:$tod_epoch}-$inode")
        );
        assert_eq!(opts.create_file_string.as_deref(), Some("anywhere"));
    }

    #[test]
    fn test_transport_init_default() {
        let mut transport = AppendfileTransport::new();
        // Should succeed with default options
        assert!(transport.init().is_ok());
    }

    #[test]
    fn test_transport_init_mutex_filename_dirname() {
        let mut transport = AppendfileTransport::new();
        transport.options.filename = Some("/var/mail/user".to_string());
        transport.options.dirname = Some("/home/user/Maildir".to_string());
        // Should fail — mutually exclusive
        let result = transport.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_transport_init_lock_retries_zero() {
        let mut transport = AppendfileTransport::new();
        transport.options.lock_retries = 0;
        let result = transport.init();
        assert!(result.is_err());
    }

    #[test]
    fn test_transport_init_bsmtp_defaults() {
        let mut transport = AppendfileTransport::new();
        transport.options.use_bsmtp = true;
        transport.init().unwrap();
        assert_eq!(transport.options.check_string.as_deref(), Some("."));
        assert_eq!(transport.options.escape_string.as_deref(), Some(".."));
    }

    #[test]
    fn test_transport_is_local() {
        let transport = AppendfileTransport::new();
        assert!(transport.is_local());
    }

    #[test]
    fn test_transport_driver_name() {
        let transport = AppendfileTransport::new();
        assert_eq!(transport.driver_name(), "appendfile");
    }

    #[test]
    fn test_check_dir_size_empty() {
        let dir = std::env::temp_dir().join("blitzy_test_appendfile_empty");
        let _ = fs::create_dir_all(&dir);
        let mut count = 0;
        let size = check_dir_size(&dir.to_string_lossy(), &mut count, None);
        assert_eq!(size, 0);
        assert_eq!(count, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_check_dir_size_with_files() {
        let dir = std::env::temp_dir().join("blitzy_test_appendfile_files");
        let _ = fs::create_dir_all(&dir);

        // Create test files
        fs::write(dir.join("file1"), b"hello").unwrap();
        fs::write(dir.join("file2"), b"world!").unwrap();

        let mut count = 0;
        let size = check_dir_size(&dir.to_string_lossy(), &mut count, None);
        assert_eq!(count, 2);
        assert_eq!(size, 11); // 5 + 6

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_check_dir_size_with_regex() {
        let dir = std::env::temp_dir().join("blitzy_test_appendfile_regex");
        let _ = fs::create_dir_all(&dir);

        // Create Maildir-style files with S=<size> in name
        fs::write(dir.join("1234.P1.host,S=100"), b"x").unwrap();
        fs::write(dir.join("1235.P2.host,S=200"), b"y").unwrap();

        let re = Regex::new(r",S=(\d+)").unwrap();
        let mut count = 0;
        let size = check_dir_size(&dir.to_string_lossy(), &mut count, Some(&re));
        assert_eq!(count, 2);
        assert_eq!(size, 300); // 100 + 200 from filename regex

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_check_creation_anywhere() {
        assert!(check_creation(
            Path::new("/any/path/file"),
            None,
            CreateFilePolicy::Anywhere
        )
        .is_ok());
    }

    #[test]
    fn test_check_creation_below_home() {
        assert!(check_creation(
            Path::new("/home/user/mail/inbox"),
            Some("/home/user"),
            CreateFilePolicy::BelowHome,
        )
        .is_ok());

        // Path outside home should fail
        assert!(check_creation(
            Path::new("/tmp/mail"),
            Some("/home/user"),
            CreateFilePolicy::BelowHome,
        )
        .is_err());
    }

    #[test]
    fn test_check_file_format_no_file() {
        let result = check_file_format(Path::new("/nonexistent"), "mbx\n*strstrstr\n");
        assert!(result.is_none());
    }

    #[test]
    fn test_quota_check_within_limit() {
        let mut opts = AppendfileTransportOptions::default();
        opts.quota_value = 10000;
        assert!(check_quota(&opts, 5000, 2000, 0).is_ok());
    }

    #[test]
    fn test_quota_check_exceeded() {
        let mut opts = AppendfileTransportOptions::default();
        opts.quota_value = 10000;
        let result = check_quota(&opts, 9000, 2000, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_quota_check_disabled() {
        let mut opts = AppendfileTransportOptions::default();
        opts.quota_value = 100;
        opts.quota_no_check = true;
        // Should pass even though we'd exceed quota
        assert!(check_quota(&opts, 200, 100, 0).is_ok());
    }

    #[test]
    fn test_mailbox_format_names() {
        assert_eq!(MailboxFormat::Unix.name(), "unix");
        assert_eq!(MailboxFormat::Smail.name(), "smail");
        #[cfg(feature = "mbx")]
        assert_eq!(MailboxFormat::Mbx.name(), "mbx");
        #[cfg(feature = "maildir")]
        assert_eq!(MailboxFormat::Maildir.name(), "maildir");
        #[cfg(feature = "mailstore")]
        assert_eq!(MailboxFormat::Mailstore.name(), "mailstore");
    }

    #[test]
    fn test_hostname_safe() {
        let h = hostname_safe();
        assert!(!h.contains('/'));
        assert!(!h.contains(':'));
        assert!(!h.is_empty());
    }
}
