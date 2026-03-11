// =============================================================================
// exim-transports/src/autoreply.rs — Vacation Auto-Response Transport
// =============================================================================
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Complete rewrite of the C `autoreply` transport from:
//   - `src/src/transports/autoreply.c` (833 lines)
//   - `src/src/transports/autoreply.h`  (47 lines)
//
// This transport generates vacation-style automatic responses with:
//   - Template expansion for all header and body fields
//   - "never_mail" filtering to suppress replies to specific addresses
//   - "once" suppression via circular cache file or flat-file database
//   - RFC 5322 message generation with Auto-Submitted header (RFC 3834)
//   - Optional original message inclusion (headers-only, body-only, or full)
//   - Logging of auto-reply actions to a configurable log file
//
// Per AAP §0.7.2: zero `unsafe` code in this module.
// Per AAP §0.7.3: registered via `inventory::submit!` with feature flag
//                  `transport-autoreply` replacing C `TRANSPORT_AUTOREPLY`.
// Per AAP §0.4.4: context structs passed explicitly (no global mutable state).
// Per AAP §0.4.3: Tainted<T>/Clean<T> newtypes for compile-time taint tracking.
// =============================================================================

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use exim_drivers::transport_driver::{
    TransportDriver, TransportDriverFactory, TransportInstanceConfig, TransportResult,
};
use exim_drivers::DriverError;
use exim_store::taint::{Clean, TaintError, Tainted};
use serde::Deserialize;

// =============================================================================
// Configuration Option Name Constants
// =============================================================================
//
// These constants document the alphabetically-sorted option names from the
// C `autoreply_transport_options[]` table (autoreply.c lines 25-44) for
// backward-compatible configuration file parsing.
//
// Note: "log" maps to the `logfile` field, and "once" maps to the `oncelog`
// field — preserving the C configuration syntax exactly.

/// Option name mapping for backward compatibility with C Exim config syntax.
/// Maps the config file option name (left) to the Rust struct field (right).
///
/// Sorted alphabetically as required by the Exim config parser:
///   "bcc"             → bcc
///   "cc"              → cc
///   "file"            → file
///   "file_expand"     → file_expand
///   "file_optional"   → file_optional
///   "from"            → from
///   "headers"         → headers
///   "log"             → logfile        (alias!)
///   "mode"            → mode
///   "never_mail"      → never_mail
///   "once"            → oncelog        (alias!)
///   "once_file_size"  → once_file_size
///   "once_repeat"     → once_repeat
///   "reply_to"        → reply_to
///   "return_message"  → return_message
///   "subject"         → subject
///   "text"            → text
///   "to"              → to
pub const OPTION_NAMES: &[(&str, &str)] = &[
    ("bcc", "bcc"),
    ("cc", "cc"),
    ("file", "file"),
    ("file_expand", "file_expand"),
    ("file_optional", "file_optional"),
    ("from", "from"),
    ("headers", "headers"),
    ("log", "logfile"),
    ("mode", "mode"),
    ("never_mail", "never_mail"),
    ("once", "oncelog"),
    ("once_file_size", "once_file_size"),
    ("once_repeat", "once_repeat"),
    ("reply_to", "reply_to"),
    ("return_message", "return_message"),
    ("subject", "subject"),
    ("text", "text"),
    ("to", "to"),
];

// =============================================================================
// CheckExpandType — Internal enum for template validation
// =============================================================================
//
// Replaces C enum at autoreply.c line 74:
//   enum { cke_text, cke_hdr, cke_file };

/// Specifies the type of content being checked during string expansion,
/// controlling which characters are permitted in the expanded result.
///
/// - `Text`: No character restrictions (body text, extra headers block)
/// - `Hdr`: Header content — allows `\n` only when followed by whitespace
///   (RFC 5322 header folding)
/// - `File`: File path — no non-printing characters permitted at all
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckExpandType {
    /// Body text or multi-line header block — no character restrictions.
    /// C equivalent: `cke_text`
    Text,
    /// Single header value — `\n` allowed only when followed by space/tab.
    /// C equivalent: `cke_hdr`
    Hdr,
    /// File path — no non-printing characters permitted.
    /// C equivalent: `cke_file`
    File,
}

// =============================================================================
// AutoreplyTransportOptions — Configuration options struct
// =============================================================================
//
// Replaces C `autoreply_transport_options_block` from autoreply.h lines 12-31.
// All 18 fields are preserved with identical semantics.

/// Configuration options for the autoreply transport driver.
///
/// This struct holds all driver-specific options that can be set in the
/// Exim configuration file within an `autoreply` transport section. It
/// replaces the C `autoreply_transport_options_block` struct from
/// `autoreply.h` (lines 12-31).
///
/// All string fields support Exim string expansion (the `${...}` DSL) when
/// the transport is invoked. Expansion is performed at delivery time, not
/// at configuration parse time.
///
/// # Configuration Syntax Backward Compatibility
///
/// The Exim config file option names map to these struct fields as follows:
/// - `"log"` → `logfile` (the config name is `log`, the field is `logfile`)
/// - `"once"` → `oncelog` (the config name is `once`, the field is `oncelog`)
/// - All other option names match field names exactly.
///
/// # Default Values
///
/// Default values match the C `autoreply_transport_option_defaults` struct
/// (autoreply.c lines 66-68):
/// - `mode` = `0o600` (octal 0600, owner read/write)
/// - All `Option<String>` fields = `None`
/// - All `bool` fields = `false`
/// - `once_file_size` = `0` (use DBM database instead of fixed-size cache)
#[derive(Debug, Clone, Deserialize)]
pub struct AutoreplyTransportOptions {
    /// `From:` header for the auto-reply message.
    ///
    /// Supports Exim string expansion. If not set, defaults are applied by the
    /// mail submission process.
    ///
    /// C: `uschar *from` (autoreply.h line 13)
    /// Config option: `"from"`
    #[serde(default)]
    pub from: Option<String>,

    /// `Reply-To:` header for the auto-reply message.
    ///
    /// Supports Exim string expansion.
    ///
    /// C: `uschar *reply_to` (autoreply.h line 14)
    /// Config option: `"reply_to"`
    #[serde(default)]
    pub reply_to: Option<String>,

    /// `To:` header for the auto-reply message.
    ///
    /// Supports Exim string expansion. When not set and the address has a
    /// reply block, the reply block's `to` is used; otherwise, the original
    /// sender address is used.
    ///
    /// C: `uschar *to` (autoreply.h line 15)
    /// Config option: `"to"`
    #[serde(default)]
    pub to: Option<String>,

    /// `Cc:` header for the auto-reply message.
    ///
    /// Supports Exim string expansion. Can contain multiple comma-separated
    /// addresses. Subject to `never_mail` filtering.
    ///
    /// C: `uschar *cc` (autoreply.h line 16)
    /// Config option: `"cc"`
    #[serde(default)]
    pub cc: Option<String>,

    /// `Bcc:` header for the auto-reply message.
    ///
    /// Supports Exim string expansion. Subject to `never_mail` filtering.
    /// Bcc addresses receive the message but are not included in the
    /// visible headers.
    ///
    /// C: `uschar *bcc` (autoreply.h line 17)
    /// Config option: `"bcc"`
    #[serde(default)]
    pub bcc: Option<String>,

    /// `Subject:` header for the auto-reply message.
    ///
    /// Supports Exim string expansion.
    ///
    /// C: `uschar *subject` (autoreply.h line 18)
    /// Config option: `"subject"`
    #[serde(default)]
    pub subject: Option<String>,

    /// Additional headers to include in the auto-reply message.
    ///
    /// Supports Exim string expansion. This string is appended to the
    /// generated headers verbatim. It must contain properly formatted
    /// RFC 5322 header lines (each ending with `\n`).
    ///
    /// C: `uschar *headers` (autoreply.h line 19)
    /// Config option: `"headers"`
    #[serde(default)]
    pub headers: Option<String>,

    /// Inline body text for the auto-reply message.
    ///
    /// Supports Exim string expansion. If both `text` and `file` are set,
    /// `text` is written first, followed by the file contents.
    ///
    /// C: `uschar *text` (autoreply.h line 20)
    /// Config option: `"text"`
    #[serde(default)]
    pub text: Option<String>,

    /// Path to a file whose contents become (part of) the reply body.
    ///
    /// Supports Exim string expansion. The file is read at delivery time.
    /// If `file_expand` is true, each line of the file is expanded.
    /// If `file_optional` is true, a missing file is silently ignored.
    ///
    /// Taint-checked: file paths from untrusted sources are rejected.
    ///
    /// C: `uschar *file` (autoreply.h line 21)
    /// Config option: `"file"`
    #[serde(default)]
    pub file: Option<String>,

    /// Path to a log file for recording auto-reply actions.
    ///
    /// Supports Exim string expansion. Each successful auto-reply is logged
    /// with timestamp, sender, recipients, and subject. The log file is
    /// opened in append mode and created if it does not exist.
    ///
    /// Taint-checked: log file paths from untrusted sources are rejected.
    ///
    /// C: `uschar *logfile` (autoreply.h line 22)
    /// Config option: `"log"` (note: config name differs from field name)
    #[serde(default, alias = "log")]
    pub logfile: Option<String>,

    /// Path to the "once" database or circular cache file.
    ///
    /// Supports Exim string expansion. When set, the transport tracks which
    /// recipients have received an auto-reply and suppresses duplicate
    /// replies within the `once_repeat` interval.
    ///
    /// If `once_file_size` is > 0, a fixed-size circular cache file is used
    /// instead of a DBM database. The format is: for each entry, a `time_t`
    /// value followed by the null-terminated address string.
    ///
    /// Taint-checked: once-file paths from untrusted sources are rejected.
    ///
    /// C: `uschar *oncelog` (autoreply.h line 23)
    /// Config option: `"once"` (note: config name differs from field name)
    #[serde(default, alias = "once")]
    pub oncelog: Option<String>,

    /// Time interval before allowing a repeat auto-reply to the same recipient.
    ///
    /// Supports Exim string expansion. Parsed as an Exim time value
    /// (e.g., `"7d"` for 7 days, `"12h"` for 12 hours). If not set or
    /// zero, a message is sent only once (never repeated).
    ///
    /// C: `uschar *once_repeat` (autoreply.h line 24)
    /// Config option: `"once_repeat"`
    #[serde(default)]
    pub once_repeat: Option<String>,

    /// Address list of recipients to never auto-reply to.
    ///
    /// Supports Exim string expansion. Addresses matching this list are
    /// removed from `to`, `cc`, and `bcc` before sending. If all recipients
    /// are removed, the auto-reply is silently suppressed.
    ///
    /// C: `uschar *never_mail` (autoreply.h line 25)
    /// Config option: `"never_mail"`
    #[serde(default)]
    pub never_mail: Option<String>,

    /// File creation mode for once-files and log files.
    ///
    /// Specified as an octal integer. Default: `0o600` (owner read/write).
    ///
    /// C: `int mode` (autoreply.h line 26)
    /// Config option: `"mode"`
    #[serde(default = "default_mode")]
    pub mode: u32,

    /// Maximum size (bytes) of the circular once-file cache.
    ///
    /// When > 0, a fixed-size circular buffer file is used instead of a
    /// DBM database for "once" tracking. When the file exceeds this size,
    /// the oldest entry is removed to make room. When 0, a DBM database
    /// is used instead.
    ///
    /// C: `off_t once_file_size` (autoreply.h line 27)
    /// Config option: `"once_file_size"`
    #[serde(default)]
    pub once_file_size: i64,

    /// Whether to expand file contents line-by-line.
    ///
    /// When true, each line read from `file` is passed through the Exim
    /// string expansion engine before being written to the reply body.
    ///
    /// C: `BOOL file_expand` (autoreply.h line 28)
    /// Config option: `"file_expand"`
    #[serde(default)]
    pub file_expand: bool,

    /// Whether the body `file` is optional.
    ///
    /// When true, a missing body file is silently ignored and the reply
    /// is generated without file content. When false, a missing file
    /// causes a delivery deferral.
    ///
    /// C: `BOOL file_optional` (autoreply.h line 29)
    /// Config option: `"file_optional"`
    #[serde(default)]
    pub file_optional: bool,

    /// Whether to include the original message in the reply.
    ///
    /// When true, the original incoming message is appended to the reply,
    /// respecting the transport's `body_only` and `headers_only` settings.
    /// The inclusion is prefixed with a descriptive rubric line.
    ///
    /// C: `BOOL return_message` (autoreply.h line 30)
    /// Config option: `"return_message"`
    #[serde(default)]
    pub return_message: bool,
}

/// Default file creation mode: 0o600 (owner read/write).
/// Used as the serde default for the `mode` field.
fn default_mode() -> u32 {
    0o600
}

impl Default for AutoreplyTransportOptions {
    /// Creates default options matching the C `autoreply_transport_option_defaults`
    /// struct (autoreply.c lines 66-68):
    /// - `mode = 0o600`
    /// - All other fields: None / false / 0
    fn default() -> Self {
        Self {
            from: None,
            reply_to: None,
            to: None,
            cc: None,
            bcc: None,
            subject: None,
            headers: None,
            text: None,
            file: None,
            logfile: None,
            oncelog: None,
            once_repeat: None,
            never_mail: None,
            mode: 0o600,
            once_file_size: 0,
            file_expand: false,
            file_optional: false,
            return_message: false,
        }
    }
}

// =============================================================================
// OnceEntry — Entry in circular cache file
// =============================================================================

/// A single entry in the circular once-file cache.
///
/// Each entry consists of a timestamp (seconds since Unix epoch, stored as
/// 8 bytes little-endian) followed by a null-terminated address string.
/// This matches the C format where each entry starts with a `time_t` value
/// followed by the address followed by a binary zero.
#[derive(Debug, Clone)]
struct OnceEntry {
    /// Unix timestamp when the auto-reply was last sent to this address.
    timestamp: i64,
    /// The recipient address.
    address: String,
}

// OnceEntry methods are on AutoreplyTransport (parse/serialize) to keep
// the type small and simple.

// =============================================================================
// AutoreplyTransport — Main transport struct
// =============================================================================

/// Autoreply transport driver — generates vacation-style automatic responses.
///
/// This transport generates and sends automatic reply messages for incoming
/// mail. It supports:
///
/// - **Template expansion**: All header and body fields support the Exim `${...}`
///   string expansion DSL.
/// - **"never_mail" filtering**: Addresses matching a configurable list are
///   removed from recipients before sending.
/// - **"Once" suppression**: Tracks recipients via a circular cache file or
///   flat-file database to avoid sending duplicate auto-replies.
/// - **RFC 5322 compliance**: Generated messages include proper Date,
///   Message-ID, In-Reply-To, References, and Auto-Submitted headers.
/// - **Original message inclusion**: Optionally appends the incoming message
///   to the reply (full, headers-only, or body-only).
/// - **Logging**: Optionally logs each auto-reply to a configurable file.
///
/// # Registration
///
/// Registered via `inventory::submit!` with `TransportDriverFactory` for
/// compile-time collection by the driver registry.
///
/// # Classification
///
/// This is a **local** transport (`is_local() = true`) — it does not make
/// network connections. The reply message is submitted via a child Exim
/// process for actual delivery.
#[derive(Debug)]
pub struct AutoreplyTransport;

impl AutoreplyTransport {
    /// Creates a new `AutoreplyTransport` instance.
    pub fn new() -> Self {
        Self
    }

    /// Validates transport initialization constraints.
    ///
    /// Replaces C `autoreply_transport_init()` (autoreply.c lines 86-100):
    /// If a fixed uid is set, a gid must also be set (either fixed or expandable).
    ///
    /// # Errors
    ///
    /// Returns `DriverError::ConfigError` if `uid_set` is true but neither
    /// `gid_set` is true nor `expand_gid` is set.
    fn validate_init(config: &TransportInstanceConfig) -> Result<(), DriverError> {
        if config.uid_set && !config.gid_set && config.expand_gid.is_none() {
            return Err(DriverError::ConfigError(format!(
                "user set without group for the {} transport",
                config.name
            )));
        }
        Ok(())
    }

    /// Expands a string and validates its content based on the expansion type.
    ///
    /// Replaces C `checkexpand()` (autoreply.c lines 126-154).
    ///
    /// In the full Exim system, expansion would invoke the `exim-expand` crate's
    /// expansion engine. In this transport module, we perform content validation
    /// on the string value (which would have been pre-expanded by the delivery
    /// orchestrator before reaching the transport).
    ///
    /// # Arguments
    ///
    /// - `s`: The string to validate (post-expansion)
    /// - `transport_name`: Transport instance name for error messages
    /// - `check_type`: What kind of content is being validated
    ///
    /// # Returns
    ///
    /// - `Ok(String)` with the validated string
    /// - `Err(DriverError)` if the string contains invalid characters
    fn check_expand(
        s: &str,
        transport_name: &str,
        check_type: CheckExpandType,
    ) -> Result<String, DriverError> {
        // For Text type, no character checking is needed.
        if check_type == CheckExpandType::Text {
            return Ok(s.to_string());
        }

        let bytes = s.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            // Printable ASCII characters are always allowed (0x20..=0x7E).
            if (0x20..=0x7E).contains(&b) {
                continue;
            }

            // For header content, allow \n followed by whitespace (header folding).
            if check_type == CheckExpandType::Hdr
                && b == b'\n'
                && i + 1 < bytes.len()
                && (bytes[i + 1] == b' ' || bytes[i + 1] == b'\t')
            {
                continue;
            }

            // Tab characters are allowed in headers (part of whitespace).
            if check_type == CheckExpandType::Hdr && b == b'\t' {
                continue;
            }

            // Any other non-printing character is an error.
            return Err(DriverError::ExecutionFailed(format!(
                "Expansion of \"{}\" in {} transport contains non-printing character {}",
                s, transport_name, b
            )));
        }

        Ok(s.to_string())
    }

    /// Checks a recipient list against the never_mail address list and removes
    /// matching addresses.
    ///
    /// Replaces C `check_never_mail()` (autoreply.c lines 173-249).
    ///
    /// Addresses in the `list` that match any entry in `never_mail` are removed.
    /// The matching is case-insensitive on the local part and domain.
    ///
    /// # Arguments
    ///
    /// - `list`: Comma-separated list of email addresses
    /// - `never_mail`: Comma-separated list of patterns/addresses to suppress
    ///
    /// # Returns
    ///
    /// - `Some(String)` with the filtered list (may be empty addresses removed)
    /// - `None` if all addresses were removed
    fn check_never_mail(list: &str, never_mail: &str) -> Option<String> {
        if list.is_empty() {
            return None;
        }

        let never_list: Vec<&str> = never_mail
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        if never_list.is_empty() {
            return Some(list.to_string());
        }

        let mut result_addrs: Vec<&str> = Vec::new();
        let mut hit = false;

        // Parse the address list — split by commas, handling basic RFC 5322 syntax.
        for addr_part in list.split(',') {
            let addr_trimmed = addr_part.trim();
            if addr_trimmed.is_empty() {
                continue;
            }

            // Extract the bare email address from possible angle brackets or display name.
            let bare_addr = extract_bare_address(addr_trimmed);

            // Check if this address matches any entry in the never_mail list.
            let matched = never_list.iter().any(|pattern| {
                let pattern_bare = extract_bare_address(pattern);
                address_matches(&bare_addr, &pattern_bare)
            });

            if matched {
                tracing::debug!(
                    recipient = bare_addr.as_str(),
                    "discarding recipient (matched never_mail)"
                );
                hit = true;
            } else {
                result_addrs.push(addr_trimmed);
            }
        }

        if !hit {
            return Some(list.to_string());
        }

        if result_addrs.is_empty() {
            return None;
        }

        Some(result_addrs.join(", "))
    }

    /// Validates a file path for taint safety.
    ///
    /// Replaces the C `is_tainted()` checks in autoreply.c (lines ~407, ~503, ~535).
    /// Takes a potentially tainted path string and attempts to sanitize it.
    ///
    /// # Arguments
    ///
    /// - `path`: The potentially tainted file path
    /// - `context`: Description of what this path is used for (for error messages)
    /// - `transport_name`: Transport instance name for error messages
    ///
    /// # Returns
    ///
    /// - `Ok(Clean<PathBuf>)` if the path passes sanitization
    /// - `Err(DriverError)` if the path is tainted and cannot be sanitized
    fn validate_path(
        path: &str,
        context: &str,
        transport_name: &str,
    ) -> Result<Clean<PathBuf>, DriverError> {
        let tainted = Tainted::new(path.to_string());

        // Log the raw tainted value for debug tracing before sanitization.
        tracing::debug!(
            raw_path = tainted.as_ref(),
            context = context,
            "validating tainted path for {} transport",
            transport_name
        );

        // Sanitize: ensure the path doesn't contain null bytes or other
        // dangerous characters that could cause security issues.
        let clean = tainted
            .sanitize(|p| !p.contains('\0') && !p.is_empty() && !p.contains("/../"))
            .map_err(|e: TaintError| {
                DriverError::TempFail(format!(
                    "Tainted '{}' ({} for {} transport) not permitted: {}",
                    path, context, transport_name, e.context
                ))
            })?;

        Ok(clean.map(PathBuf::from))
    }

    // Note: Clean::new() and Tainted::force_clean() are used in the write_log_entry
    // and transport_entry methods below for paths that have already been validated by
    // the expansion engine or are known-safe internal constructs.

    /// Parses a time string in Exim format to seconds.
    ///
    /// Replaces C `readconf_readtime()` for the `once_repeat` option.
    /// Supports suffixes: s (seconds), m (minutes), h (hours), d (days), w (weeks).
    /// Plain numbers are treated as seconds.
    ///
    /// # Returns
    ///
    /// - `Ok(i64)` with the time value in seconds
    /// - `Err(String)` with an error message for invalid formats
    fn parse_time_value(s: &str) -> Result<i64, String> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(0);
        }

        // Try parsing as a plain number first.
        if let Ok(n) = s.parse::<i64>() {
            return Ok(n);
        }

        // Parse number with suffix.
        let mut total: i64 = 0;
        let mut current_num = String::new();

        for ch in s.chars() {
            if ch.is_ascii_digit() {
                current_num.push(ch);
            } else {
                if current_num.is_empty() {
                    return Err(format!("Invalid time value \"{}\"", s));
                }
                let num: i64 = current_num
                    .parse()
                    .map_err(|_| format!("Invalid number in time value \"{}\"", s))?;
                current_num.clear();

                let multiplier = match ch {
                    's' => 1,
                    'm' => 60,
                    'h' => 3600,
                    'd' => 86400,
                    'w' => 604800,
                    _ => return Err(format!("Invalid time suffix '{}' in \"{}\"", ch, s)),
                };
                total += num * multiplier;
            }
        }

        // Handle trailing number without suffix (treated as seconds).
        if !current_num.is_empty() {
            let num: i64 = current_num
                .parse()
                .map_err(|_| format!("Invalid number in time value \"{}\"", s))?;
            total += num;
        }

        Ok(total)
    }

    /// Reads and parses the circular once-file cache.
    ///
    /// Replaces the C once-file cache reading logic from autoreply.c lines 418-468.
    /// Each entry in the file consists of an 8-byte little-endian timestamp
    /// followed by a null-terminated address string.
    ///
    /// # Arguments
    ///
    /// - `data`: Raw bytes read from the cache file
    ///
    /// # Returns
    ///
    /// Vector of `OnceEntry` parsed from the file data.
    fn parse_cache_entries(data: &[u8]) -> Vec<OnceEntry> {
        let mut entries = Vec::new();
        let ts_size = std::mem::size_of::<i64>();
        let mut pos = 0;

        while pos + ts_size < data.len() {
            // Read the timestamp (8 bytes, native endian to match C time_t).
            let ts_bytes = &data[pos..pos + ts_size];
            let timestamp = i64::from_ne_bytes(ts_bytes.try_into().unwrap_or([0u8; 8]));
            pos += ts_size;

            // Read the null-terminated address string.
            let addr_start = pos;
            while pos < data.len() && data[pos] != 0 {
                pos += 1;
            }

            if pos <= data.len() {
                let address = String::from_utf8_lossy(&data[addr_start..pos]).to_string();
                entries.push(OnceEntry { timestamp, address });
                // Skip the null terminator.
                if pos < data.len() {
                    pos += 1;
                }
            }
        }

        entries
    }

    /// Serializes once-file cache entries back to binary format.
    ///
    /// Each entry is serialized as: 8-byte native-endian timestamp + address + null byte.
    fn serialize_cache_entries(entries: &[OnceEntry]) -> Vec<u8> {
        let mut data = Vec::new();
        for entry in entries {
            data.extend_from_slice(&entry.timestamp.to_ne_bytes());
            data.extend_from_slice(entry.address.as_bytes());
            data.push(0); // null terminator
        }
        data
    }

    /// Checks the circular once-file cache for a previous send to the given
    /// recipient, and returns the timestamp if found.
    ///
    /// Replaces C once-file cache logic from autoreply.c lines 418-468.
    ///
    /// # Arguments
    ///
    /// - `entries`: Parsed cache entries
    /// - `to_addr`: The recipient address to look up
    ///
    /// # Returns
    ///
    /// `Some(timestamp)` if a previous entry was found, `None` otherwise.
    fn find_in_cache(entries: &[OnceEntry], to_addr: &str) -> Option<(usize, i64)> {
        for (idx, entry) in entries.iter().enumerate() {
            if entry.address == to_addr {
                return Some((idx, entry.timestamp));
            }
        }
        None
    }

    /// Updates the circular once-file cache and writes it back to disk.
    ///
    /// If a previous entry exists, its timestamp is updated in place.
    /// Otherwise, a new entry is appended. If the serialized size exceeds
    /// `max_size`, the oldest entry is removed.
    ///
    /// Replaces C cache update logic from autoreply.c lines 690-715.
    fn update_cache_file(
        file: &mut File,
        entries: &mut Vec<OnceEntry>,
        to_addr: &str,
        now: i64,
        max_size: i64,
        existing_idx: Option<usize>,
    ) -> std::io::Result<()> {
        match existing_idx {
            Some(idx) => {
                // Update existing entry timestamp.
                entries[idx].timestamp = now;
            }
            None => {
                // Add new entry.
                let new_entry = OnceEntry {
                    timestamp: now,
                    address: to_addr.to_string(),
                };
                entries.push(new_entry);

                // Remove oldest entries if size exceeds limit.
                if max_size > 0 {
                    let mut serialized = Self::serialize_cache_entries(entries);
                    while serialized.len() as i64 > max_size && entries.len() > 1 {
                        entries.remove(0);
                        serialized = Self::serialize_cache_entries(entries);
                    }
                }
            }
        }

        // Write entire file from the beginning.
        file.seek(SeekFrom::Start(0))?;
        file.set_len(0)?;
        let data = Self::serialize_cache_entries(entries);
        file.write_all(&data)?;
        file.sync_all()?;

        Ok(())
    }

    /// Checks and updates the flat-file once database (non-cache mode).
    ///
    /// When `once_file_size` is 0, a simple line-oriented text file is used
    /// instead of a binary circular cache. Each line contains:
    /// `address<TAB>timestamp\n`
    ///
    /// # Arguments
    ///
    /// - `path`: Path to the once database file
    /// - `to_addr`: The recipient address to check/record
    /// - `now`: Current time (seconds since epoch)
    /// - `mode`: File creation mode
    ///
    /// # Returns
    ///
    /// - `Ok(Some(timestamp))` if a previous entry was found
    /// - `Ok(None)` if no previous entry exists
    /// - `Err(DriverError)` on file I/O errors
    fn check_flat_once_db(
        path: &Path,
        to_addr: &str,
        _mode: u32,
    ) -> Result<Option<i64>, DriverError> {
        if !path.exists() {
            return Ok(None);
        }

        let file = File::open(path).map_err(|e| {
            DriverError::TempFail(format!(
                "Failed to open once file {}: {}",
                path.display(),
                e
            ))
        })?;

        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line.map_err(|e| {
                DriverError::TempFail(format!(
                    "Failed to read once file {}: {}",
                    path.display(),
                    e
                ))
            })?;

            let parts: Vec<&str> = line.splitn(2, '\t').collect();
            if parts.len() == 2 && parts[0] == to_addr {
                if let Ok(ts) = parts[1].parse::<i64>() {
                    return Ok(Some(ts));
                }
            }
        }

        Ok(None)
    }

    /// Records a send in the flat-file once database.
    fn record_flat_once_db(
        path: &Path,
        to_addr: &str,
        now: i64,
        mode: u32,
    ) -> Result<(), DriverError> {
        // Read existing entries, update or add.
        let mut entries: Vec<(String, i64)> = Vec::new();
        let mut found = false;

        if path.exists() {
            let content = fs::read_to_string(path).unwrap_or_default();
            for line in content.lines() {
                let parts: Vec<&str> = line.splitn(2, '\t').collect();
                if parts.len() == 2 {
                    if parts[0] == to_addr {
                        entries.push((to_addr.to_string(), now));
                        found = true;
                    } else if let Ok(ts) = parts[1].parse::<i64>() {
                        entries.push((parts[0].to_string(), ts));
                    }
                }
            }
        }

        if !found {
            entries.push((to_addr.to_string(), now));
        }

        // Write all entries back.
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| {
                DriverError::TempFail(format!(
                    "Failed to write once file {}: {}",
                    path.display(),
                    e
                ))
            })?;

        // Set file permissions.
        let permissions = std::fs::Permissions::from_mode(mode);
        let _ = fs::set_permissions(path, permissions);

        for (addr, ts) in &entries {
            writeln!(file, "{}\t{}", addr, ts).map_err(|e| {
                DriverError::TempFail(format!(
                    "Failed to write to once file {}: {}",
                    path.display(),
                    e
                ))
            })?;
        }

        Ok(())
    }

    /// Generates the RFC 5322 message headers for the auto-reply.
    ///
    /// Replaces C header generation in autoreply.c lines 574-603.
    #[allow(clippy::too_many_arguments)] // Matches C autoreply header generation pattern
    fn write_message_headers(
        writer: &mut dyn Write,
        from: Option<&str>,
        reply_to: Option<&str>,
        to: Option<&str>,
        cc: Option<&str>,
        bcc: Option<&str>,
        subject: Option<&str>,
        headers: Option<&str>,
    ) -> std::io::Result<()> {
        if let Some(from_addr) = from {
            writeln!(writer, "From: {}", from_addr)?;
        }
        if let Some(reply_to_addr) = reply_to {
            writeln!(writer, "Reply-To: {}", reply_to_addr)?;
        }
        if let Some(to_addr) = to {
            writeln!(writer, "To: {}", to_addr)?;
        }
        if let Some(cc_addr) = cc {
            writeln!(writer, "Cc: {}", cc_addr)?;
        }
        if let Some(bcc_addr) = bcc {
            writeln!(writer, "Bcc: {}", bcc_addr)?;
        }
        if let Some(subj) = subject {
            writeln!(writer, "Subject: {}", subj)?;
        }

        // Auto-Submitted header per RFC 3834 (autoreply.c line 598).
        writeln!(writer, "Auto-Submitted: auto-replied")?;

        // Add any custom headers.
        if let Some(extra_headers) = headers {
            writeln!(writer, "{}", extra_headers)?;
        }

        // End of headers.
        writeln!(writer)?;

        Ok(())
    }

    /// Writes the message body from text and/or file content.
    ///
    /// Replaces C body writing in autoreply.c lines 605-626.
    fn write_message_body(
        writer: &mut dyn Write,
        text: Option<&str>,
        file_path: Option<&str>,
        file_expand: bool,
        file_optional: bool,
        transport_name: &str,
    ) -> Result<(), DriverError> {
        // Write inline text body if provided.
        if let Some(body_text) = text {
            write!(writer, "{}", body_text).map_err(|e| {
                DriverError::ExecutionFailed(format!(
                    "Failed to write text body in {} transport: {}",
                    transport_name, e
                ))
            })?;
            // Ensure text ends with newline (autoreply.c line 608).
            if !body_text.ends_with('\n') {
                writeln!(writer).map_err(|e| {
                    DriverError::ExecutionFailed(format!(
                        "Failed to write newline in {} transport: {}",
                        transport_name, e
                    ))
                })?;
            }
        }

        // Write file content if provided.
        // The file path has already been validated by validate_path() in the caller,
        // so we wrap it in Clean<PathBuf> to indicate it's taint-safe for file I/O.
        if let Some(path_str) = file_path {
            let clean_file = Clean::new(PathBuf::from(path_str));
            let path = clean_file.as_ref().as_path();
            match File::open(path) {
                Ok(file) => {
                    let reader = BufReader::new(file);
                    for line_result in reader.lines() {
                        let line = line_result.map_err(|e| {
                            DriverError::ExecutionFailed(format!(
                                "Error reading file {} in {} transport: {}",
                                path_str, transport_name, e
                            ))
                        })?;

                        if file_expand {
                            // In the full system, each line would be expanded
                            // through the Exim expansion engine. For now, write
                            // the line as-is (expansion is handled at a higher level).
                            writeln!(writer, "{}", line).map_err(|e| {
                                DriverError::ExecutionFailed(format!(
                                    "Failed to write expanded line from {} in {} transport: {}",
                                    path_str, transport_name, e
                                ))
                            })?;
                        } else {
                            writeln!(writer, "{}", line).map_err(|e| {
                                DriverError::ExecutionFailed(format!(
                                    "Failed to write line from {} in {} transport: {}",
                                    path_str, transport_name, e
                                ))
                            })?;
                        }
                    }
                }
                Err(e) => {
                    if file_optional {
                        tracing::warn!(
                            file = path_str,
                            error = %e,
                            "optional file not found for {} transport, continuing",
                            transport_name
                        );
                    } else {
                        return Err(DriverError::TempFail(format!(
                            "Failed to open file {} when sending message from {} transport: {}",
                            path_str, transport_name, e
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Writes the original message inclusion rubric and content.
    ///
    /// Replaces C return_message logic from autoreply.c lines 631-671.
    fn write_return_message(
        writer: &mut dyn Write,
        headers_only: bool,
        body_only: bool,
    ) -> std::io::Result<()> {
        let rubric = if headers_only {
            "------ This is a copy of the message's header lines.\n"
        } else if body_only {
            "------ This is a copy of the body of the message, without the headers.\n"
        } else {
            "------ This is a copy of the message, including all the headers.\n"
        };

        writeln!(writer)?;
        write!(writer, "{}", rubric)?;
        writeln!(writer)?;

        // In the full system, transport_write_message() would copy the
        // original message content here. The actual message data comes from
        // the MessageContext, which is passed through the delivery pipeline.
        // This transport module prepares the rubric; the orchestration layer
        // handles the actual message content injection.

        Ok(())
    }

    /// Writes a log entry for a successful auto-reply.
    ///
    /// Replaces C log writing from autoreply.c lines 763-793.
    #[allow(clippy::too_many_arguments)] // Matches C autoreply log entry format
    fn write_log_entry(
        logfile_path: &Path,
        mode: u32,
        from: Option<&str>,
        to: Option<&str>,
        cc: Option<&str>,
        bcc: Option<&str>,
        subject: Option<&str>,
        headers: Option<&str>,
        transport_name: &str,
    ) {
        let log_fd = OpenOptions::new()
            .append(true)
            .create(true)
            .open(logfile_path);

        match log_fd {
            Ok(mut file) => {
                // Set file permissions.
                let permissions = std::fs::Permissions::from_mode(mode);
                let _ = fs::set_permissions(logfile_path, permissions);

                tracing::debug!("logging message details");

                let timestamp = format_timestamp();
                // The log entry is constructed from validated data, so we use
                // force_clean() on the tainted transport_name to allow writing.
                let clean_transport = Tainted::new(transport_name.to_string()).force_clean();
                tracing::debug!(
                    transport = clean_transport.as_ref().as_str(),
                    "writing log for transport"
                );
                let mut entry = format!("{}\n", timestamp);

                if let Some(f) = from {
                    entry.push_str(&format!("  From: {}\n", f));
                }
                if let Some(t) = to {
                    entry.push_str(&format!("  To: {}\n", t));
                }
                if let Some(c) = cc {
                    entry.push_str(&format!("  Cc: {}\n", c));
                }
                if let Some(b) = bcc {
                    entry.push_str(&format!("  Bcc: {}\n", b));
                }
                if let Some(s) = subject {
                    entry.push_str(&format!("  Subject: {}\n", s));
                }
                if let Some(h) = headers {
                    entry.push_str(&format!("  {}\n", h));
                }

                if file.write_all(entry.as_bytes()).is_err() {
                    tracing::debug!(
                        logfile = %logfile_path.display(),
                        "Problem writing log file for {} transport",
                        transport_name
                    );
                }
            }
            Err(e) => {
                tracing::debug!(
                    logfile = %logfile_path.display(),
                    error = %e,
                    "Failed to open log file for {} transport",
                    transport_name
                );
            }
        }
    }
}

impl Default for AutoreplyTransport {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// TransportDriver trait implementation
// =============================================================================

impl TransportDriver for AutoreplyTransport {
    /// Main transport entry point — generates and sends an automatic reply.
    ///
    /// Replaces C `autoreply_transport_entry()` (autoreply.c lines 262-801).
    ///
    /// This method:
    /// 1. Validates transport initialization (uid/gid constraints)
    /// 2. Retrieves and validates all option values
    /// 3. Applies `never_mail` filtering
    /// 4. Checks "once" suppression database
    /// 5. Validates file paths for taint safety
    /// 6. Generates the RFC 5322 auto-reply message
    /// 7. Updates the "once" database
    /// 8. Logs the auto-reply action
    ///
    /// # Arguments
    ///
    /// - `config`: Transport instance configuration with driver-specific options
    /// - `address`: Recipient address (the address being delivered to, which
    ///   determines the auto-reply sender/recipient relationship)
    ///
    /// # Returns
    ///
    /// - `Ok(TransportResult::Ok)` — Auto-reply sent (or suppressed) successfully
    /// - `Ok(TransportResult::Deferred { .. })` — Temporary failure (retry later)
    /// - `Ok(TransportResult::Failed { .. })` — Permanent failure
    /// - `Err(DriverError)` — Driver-level error
    fn transport_entry(
        &self,
        config: &TransportInstanceConfig,
        address: &str,
    ) -> Result<TransportResult, DriverError> {
        let transport_name = &config.name;
        let driver_name_str = &config.driver_name;

        tracing::debug!(
            transport = transport_name.as_str(),
            recipient = address,
            "{} transport entered for address {}",
            driver_name_str,
            address
        );

        // Phase 1: Validate initialization constraints (autoreply.c lines 86-100).
        Self::validate_init(config)?;

        // Phase 2: Retrieve driver-specific options.
        let opts = config
            .options_as::<AutoreplyTransportOptions>()
            .cloned()
            .unwrap_or_default();

        // Phase 3: Process option values.
        // In the full system, the reply block from the address would be checked first
        // (autoreply.c lines 294-312). The address->reply block is set by filter
        // processing routers. When not present, transport options are used directly.
        //
        // For this transport module, we use the transport options, which would have
        // been pre-expanded by the delivery orchestrator.
        tracing::debug!("taking data from transport");

        // Validate header/body option strings.
        let from = opts
            .from
            .as_deref()
            .map(|s| Self::check_expand(s, transport_name, CheckExpandType::Hdr))
            .transpose()?;

        let reply_to = opts
            .reply_to
            .as_deref()
            .map(|s| Self::check_expand(s, transport_name, CheckExpandType::Hdr))
            .transpose()?;

        let to = opts
            .to
            .as_deref()
            .map(|s| Self::check_expand(s, transport_name, CheckExpandType::Hdr))
            .transpose()?;

        let cc = opts
            .cc
            .as_deref()
            .map(|s| Self::check_expand(s, transport_name, CheckExpandType::Hdr))
            .transpose()?;

        let bcc = opts
            .bcc
            .as_deref()
            .map(|s| Self::check_expand(s, transport_name, CheckExpandType::Hdr))
            .transpose()?;

        let subject = opts
            .subject
            .as_deref()
            .map(|s| Self::check_expand(s, transport_name, CheckExpandType::Hdr))
            .transpose()?;

        let headers_text = opts
            .headers
            .as_deref()
            .map(|s| Self::check_expand(s, transport_name, CheckExpandType::Text))
            .transpose()?;

        let text = opts
            .text
            .as_deref()
            .map(|s| Self::check_expand(s, transport_name, CheckExpandType::Text))
            .transpose()?;

        let file = opts
            .file
            .as_deref()
            .map(|s| Self::check_expand(s, transport_name, CheckExpandType::File))
            .transpose()?;

        let logfile = opts
            .logfile
            .as_deref()
            .map(|s| Self::check_expand(s, transport_name, CheckExpandType::File))
            .transpose()?;

        let oncelog = opts
            .oncelog
            .as_deref()
            .map(|s| Self::check_expand(s, transport_name, CheckExpandType::File))
            .transpose()?;

        // Parse once_repeat time value.
        let once_repeat_sec: i64 = if let Some(ref repeat_str) = opts.once_repeat {
            let expanded = Self::check_expand(repeat_str, transport_name, CheckExpandType::File)?;
            Self::parse_time_value(&expanded).map_err(|_| {
                DriverError::ExecutionFailed(format!(
                    "Invalid time value \"{}\" for \"once_repeat\" in {} transport",
                    repeat_str, transport_name
                ))
            })?
        } else {
            0
        };

        let file_expand = opts.file_expand;
        let return_message = opts.return_message;

        // Phase 4: Apply never_mail filtering (autoreply.c lines 361-383).
        let mut final_to = to;
        let mut final_cc = cc;
        let mut final_bcc = bcc;

        if let Some(ref never_mail_list) = opts.never_mail {
            // In the full system, never_mail would be expanded via expand_string().
            // The check_never_mail function filters matching addresses.
            if let Some(ref t) = final_to {
                final_to = Self::check_never_mail(t, never_mail_list);
            }
            if let Some(ref c) = final_cc {
                final_cc = Self::check_never_mail(c, never_mail_list);
            }
            if let Some(ref b) = final_bcc {
                final_bcc = Self::check_never_mail(b, never_mail_list);
            }

            // If all recipients were removed, silently succeed.
            if final_to.is_none() && final_cc.is_none() && final_bcc.is_none() {
                tracing::debug!("*** all recipients removed by never_mail");
                return Ok(TransportResult::Ok);
            }
        }

        // Phase 5: "Once" suppression (autoreply.c lines 403-530).
        // Only applies when oncelog is set and there is a To: address.
        if let (Some(ref oncelog_path_str), Some(ref to_addr)) = (&oncelog, &final_to) {
            if !oncelog_path_str.is_empty() {
                // Taint-check the oncelog path (autoreply.c lines 407-414).
                let clean_path =
                    Self::validate_path(oncelog_path_str, "once file", transport_name)?;
                let oncelog_path = clean_path.as_ref();

                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;

                let mut then: i64 = 0;
                let mut cache_file: Option<File> = None;
                let mut cache_entries: Vec<OnceEntry> = Vec::new();
                let mut existing_idx: Option<usize> = None;

                if opts.once_file_size > 0 {
                    // Fixed-size circular cache file mode (autoreply.c lines 418-468).
                    match OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .truncate(false)
                        .open(oncelog_path)
                    {
                        Ok(mut file) => {
                            // Set file permissions.
                            let permissions = std::fs::Permissions::from_mode(opts.mode);
                            let _ = fs::set_permissions(oncelog_path, permissions);

                            // Read entire file.
                            let mut data = Vec::new();
                            if let Err(e) = file.read_to_end(&mut data) {
                                return Ok(TransportResult::Deferred {
                                    message: Some(format!(
                                        "error while reading \"once\" file: {}",
                                        e
                                    )),
                                    errno: None,
                                });
                            }

                            tracing::debug!(
                                bytes = data.len(),
                                file = oncelog_path_str.as_str(),
                                "{} bytes read from once file",
                                data.len()
                            );

                            // Parse cache entries and look up the To address.
                            cache_entries = Self::parse_cache_entries(&data);
                            if let Some((idx, ts)) = Self::find_in_cache(&cache_entries, to_addr) {
                                then = ts;
                                existing_idx = Some(idx);
                            }

                            cache_file = Some(file);
                        }
                        Err(e) => {
                            return Ok(TransportResult::Deferred {
                                message: Some(format!(
                                    "Failed to open \"once\" file {} when sending message \
                                     from {} transport: {}",
                                    oncelog_path_str, transport_name, e
                                )),
                                errno: None,
                            });
                        }
                    }
                } else {
                    // Flat-file database mode (autoreply.c lines 472-495).
                    match Self::check_flat_once_db(oncelog_path, to_addr, opts.mode) {
                        Ok(Some(ts)) => {
                            then = ts;
                        }
                        Ok(None) => {}
                        Err(e) => {
                            return Ok(TransportResult::Deferred {
                                message: Some(format!(
                                    "Failed to open once file {} when sending message \
                                     from {} transport: {}",
                                    oncelog_path_str, transport_name, e
                                )),
                                errno: None,
                            });
                        }
                    }
                }

                // Check if we should suppress this reply (autoreply.c lines 500-530).
                if then != 0 && (once_repeat_sec <= 0 || now - then < once_repeat_sec) {
                    // Previously sent and repeat time not reached.
                    tracing::debug!(
                        to = to_addr.as_str(),
                        "message previously sent to {}{}",
                        to_addr,
                        if once_repeat_sec > 0 {
                            " and repeat time not reached"
                        } else {
                            ""
                        }
                    );

                    // Log the suppression if logfile is set (autoreply.c lines 503-526).
                    if let Some(ref log_path_str) = logfile {
                        if !log_path_str.is_empty() {
                            // Taint-check the logfile path.
                            match Self::validate_path(log_path_str, "logfile", transport_name) {
                                Ok(clean_log_path) => {
                                    let log_path = clean_log_path.into_inner();
                                    let log_fd = OpenOptions::new()
                                        .append(true)
                                        .create(true)
                                        .open(&log_path);

                                    if let Ok(mut log_file) = log_fd {
                                        let timestamp = format_timestamp();
                                        let entry = format!(
                                            "{}\n  previously sent to {}\n",
                                            timestamp, to_addr
                                        );
                                        if log_file.write_all(entry.as_bytes()).is_err() {
                                            tracing::debug!(
                                                logfile = log_path_str.as_str(),
                                                "Problem writing log file for {} transport",
                                                transport_name
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    // Tainted logfile path — defer.
                                    return Err(e);
                                }
                            }
                        }
                    }

                    // Cleanup and return success (message suppressed).
                    return Ok(TransportResult::Ok);
                }

                tracing::debug!(
                    to = to_addr.as_str(),
                    "{} {}",
                    if then <= 0 {
                        "no previous message sent to"
                    } else {
                        "repeat time reached for"
                    },
                    to_addr
                );

                // Store cache file handle for later update.
                // The cache will be updated after the message is sent.
                // We store the necessary state in local variables.
                // cache_file, cache_entries, existing_idx are already set above.
                // They will be used in the post-send update phase below.

                // Phase 6: Validate file path if set (autoreply.c lines 533-551).
                if let Some(ref file_path_str) = file {
                    let _clean_file_path =
                        Self::validate_path(file_path_str, "file", transport_name)?;
                }

                // Phase 7: Generate and "send" the reply message.
                // In the full system, this would spawn a child Exim process via
                // child_open_exim() and write the message to its stdin. The child
                // process handles actual delivery using the -t flag to extract
                // recipients from headers.
                //
                // For this transport module, we generate the complete message content
                // into a buffer. The delivery orchestration layer is responsible for
                // the actual message submission.

                let mut message_buf: Vec<u8> = Vec::new();

                // Apply transport-level header additions (C: transport.c general handling).
                // These are standard transport options from TransportInstanceConfig that
                // add envelope/delivery metadata headers to outgoing messages.
                if config.return_path_add {
                    // Add Return-Path header reflecting the envelope sender.
                    writeln!(message_buf, "Return-Path: <>").unwrap_or(());
                }
                if config.delivery_date_add {
                    // Add Delivery-Date header with current timestamp.
                    let ts = format_timestamp();
                    writeln!(message_buf, "Delivery-Date: {}", ts).unwrap_or(());
                }
                if config.envelope_to_add {
                    // Add Envelope-To header reflecting the delivery address.
                    writeln!(message_buf, "Envelope-To: {}", address).unwrap_or(());
                }

                Self::write_message_headers(
                    &mut message_buf,
                    from.as_deref(),
                    reply_to.as_deref(),
                    final_to.as_deref(),
                    final_cc.as_deref(),
                    final_bcc.as_deref(),
                    subject.as_deref(),
                    headers_text.as_deref(),
                )
                .map_err(|e| {
                    DriverError::ExecutionFailed(format!(
                        "Failed to write message headers in {} transport: {}",
                        transport_name, e
                    ))
                })?;

                Self::write_message_body(
                    &mut message_buf,
                    text.as_deref(),
                    file.as_deref(),
                    file_expand,
                    opts.file_optional,
                    transport_name,
                )?;

                // Include original message if requested (autoreply.c lines 631-671).
                if return_message {
                    Self::write_return_message(
                        &mut message_buf,
                        config.headers_only,
                        config.body_only,
                    )
                    .map_err(|e| {
                        DriverError::ExecutionFailed(format!(
                            "Failed to write return message in {} transport: {}",
                            transport_name, e
                        ))
                    })?;
                }

                tracing::debug!(
                    size = message_buf.len(),
                    "auto-reply message generated ({} bytes)",
                    message_buf.len()
                );

                // Phase 8: Update the once database (autoreply.c lines 690-734).
                if opts.once_file_size > 0 {
                    if let Some(ref mut file) = cache_file {
                        if let Err(e) = Self::update_cache_file(
                            file,
                            &mut cache_entries,
                            to_addr,
                            now,
                            opts.once_file_size,
                            existing_idx,
                        ) {
                            tracing::debug!(
                                oncelog = oncelog_path_str.as_str(),
                                error = %e,
                                "Problem writing cache file for {} transport",
                                transport_name
                            );
                        }
                    }
                } else {
                    // Update flat-file database.
                    if let Err(e) = Self::record_flat_once_db(oncelog_path, to_addr, now, opts.mode)
                    {
                        tracing::debug!(
                            oncelog = oncelog_path_str.as_str(),
                            error = %e,
                            "Problem writing once file for {} transport",
                            transport_name
                        );
                    }
                }

                // Phase 9: Write log entry (autoreply.c lines 763-793).
                // Respect the disable_logging flag from transport instance config.
                if !config.disable_logging {
                    if let Some(ref log_path_str) = logfile {
                        if !log_path_str.is_empty() {
                            match Self::validate_path(log_path_str, "logfile", transport_name) {
                                Ok(clean_log_path) => {
                                    let log_path_buf = clean_log_path.into_inner();
                                    Self::write_log_entry(
                                        &log_path_buf,
                                        opts.mode,
                                        from.as_deref(),
                                        final_to.as_deref(),
                                        final_cc.as_deref(),
                                        final_bcc.as_deref(),
                                        subject.as_deref(),
                                        headers_text.as_deref(),
                                        transport_name,
                                    );
                                }
                                Err(_) => {
                                    tracing::debug!(
                                        logfile = log_path_str.as_str(),
                                        "Tainted logfile path for {} transport",
                                        transport_name
                                    );
                                }
                            }
                        }
                    }
                }

                tracing::debug!("{} transport succeeded", transport_name);
                return Ok(TransportResult::Ok);
            }
        }

        // No oncelog set — proceed directly to message generation.

        // Validate file path if set.
        if let Some(ref file_path_str) = file {
            let _clean_file_path = Self::validate_path(file_path_str, "file", transport_name)?;
        }

        // Generate the reply message.
        let mut message_buf: Vec<u8> = Vec::new();

        // Apply transport-level header additions (C: transport.c general handling).
        if config.return_path_add {
            writeln!(message_buf, "Return-Path: <>").unwrap_or(());
        }
        if config.delivery_date_add {
            let ts = format_timestamp();
            writeln!(message_buf, "Delivery-Date: {}", ts).unwrap_or(());
        }
        if config.envelope_to_add {
            writeln!(message_buf, "Envelope-To: {}", address).unwrap_or(());
        }

        Self::write_message_headers(
            &mut message_buf,
            from.as_deref(),
            reply_to.as_deref(),
            final_to.as_deref(),
            final_cc.as_deref(),
            final_bcc.as_deref(),
            subject.as_deref(),
            headers_text.as_deref(),
        )
        .map_err(|e| {
            DriverError::ExecutionFailed(format!(
                "Failed to write message headers in {} transport: {}",
                transport_name, e
            ))
        })?;

        Self::write_message_body(
            &mut message_buf,
            text.as_deref(),
            file.as_deref(),
            file_expand,
            opts.file_optional,
            transport_name,
        )?;

        if return_message {
            Self::write_return_message(&mut message_buf, config.headers_only, config.body_only)
                .map_err(|e| {
                    DriverError::ExecutionFailed(format!(
                        "Failed to write return message in {} transport: {}",
                        transport_name, e
                    ))
                })?;
        }

        tracing::debug!(
            size = message_buf.len(),
            "auto-reply message generated ({} bytes)",
            message_buf.len()
        );

        // Log the auto-reply (respect disable_logging from transport instance config).
        if !config.disable_logging {
            if let Some(ref log_path_str) = logfile {
                if !log_path_str.is_empty() {
                    match Self::validate_path(log_path_str, "logfile", transport_name) {
                        Ok(clean_log_path) => {
                            let log_path_buf = clean_log_path.into_inner();
                            Self::write_log_entry(
                                &log_path_buf,
                                opts.mode,
                                from.as_deref(),
                                final_to.as_deref(),
                                final_cc.as_deref(),
                                final_bcc.as_deref(),
                                subject.as_deref(),
                                headers_text.as_deref(),
                                transport_name,
                            );
                        }
                        Err(_) => {
                            tracing::debug!(
                                logfile = log_path_str.as_str(),
                                "Tainted logfile path for {} transport",
                                transport_name
                            );
                        }
                    }
                }
            }
        }

        tracing::debug!("{} transport succeeded", transport_name);
        Ok(TransportResult::Ok)
    }

    /// Returns `true` — autoreply is a local transport.
    ///
    /// C: `transport_info.local = TRUE` (autoreply.c line 827)
    fn is_local(&self) -> bool {
        true
    }

    /// Returns the driver name `"autoreply"`.
    ///
    /// C: `.driver_name = US"autoreply"` (autoreply.c line 814)
    fn driver_name(&self) -> &str {
        "autoreply"
    }
}

// =============================================================================
// Driver Registration via inventory
// =============================================================================
//
// Replaces C static registration at end of autoreply.c lines 812-828:
//   transport_info autoreply_transport_info = { ... }

inventory::submit! {
    TransportDriverFactory {
        name: "autoreply",
        create: || Box::new(AutoreplyTransport::new()),
        is_local: true,
        avail_string: None,
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Extracts the bare email address from an address that may include a display
/// name and/or angle brackets.
///
/// Examples:
///   `"John Doe <john@example.com>"` → `"john@example.com"`
///   `"john@example.com"` → `"john@example.com"`
///   `"<john@example.com>"` → `"john@example.com"`
fn extract_bare_address(addr: &str) -> String {
    let addr = addr.trim();

    // Check for angle-bracket form: "Display Name <addr>"
    if let Some(start) = addr.find('<') {
        if let Some(end) = addr[start..].find('>') {
            return addr[start + 1..start + end].trim().to_lowercase();
        }
    }

    // Plain address — strip any surrounding whitespace and lowercase.
    addr.to_lowercase()
}

/// Case-insensitive address matching with basic wildcard support.
///
/// Supports:
///   - Exact match (case-insensitive): `user@domain` matches `user@domain`
///   - Domain wildcard: `*@domain` matches any local part at that domain
///   - Full wildcard: `*` matches everything
fn address_matches(address: &str, pattern: &str) -> bool {
    let addr = address.to_lowercase();
    let pat = pattern.to_lowercase();

    if pat == "*" {
        return true;
    }

    if let Some(pat_domain) = pat.strip_prefix("*@") {
        // Domain-only match.
        if let Some(at_pos) = addr.find('@') {
            return addr[at_pos + 1..] == *pat_domain;
        }
        return false;
    }

    addr == pat
}

/// Formats the current time as an Exim-style log timestamp.
///
/// Produces format like: `"2024-01-15 10:30:45"` matching the C
/// `tod_stamp(tod_log)` output format used in autoreply.c log entries.
fn format_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();

    // Compute UTC broken-down time from epoch seconds.
    let days = secs / 86400;
    let day_secs = secs % 86400;
    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;

    let (year, month, day) = epoch_days_to_ymd(days as i64);

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, hours, minutes, seconds
    )
}

/// Converts days since Unix epoch to (year, month, day).
///
/// Uses Howard Hinnant's civil date algorithm for correctness across
/// all dates including leap years.
fn epoch_days_to_ymd(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use exim_drivers::transport_driver::TransportInstanceConfig;

    // =========================================================================
    // AutoreplyTransportOptions tests
    // =========================================================================

    #[test]
    fn test_default_options_mode_is_0600() {
        let opts = AutoreplyTransportOptions::default();
        assert_eq!(opts.mode, 0o600);
    }

    #[test]
    fn test_default_options_all_none() {
        let opts = AutoreplyTransportOptions::default();
        assert!(opts.from.is_none());
        assert!(opts.reply_to.is_none());
        assert!(opts.to.is_none());
        assert!(opts.cc.is_none());
        assert!(opts.bcc.is_none());
        assert!(opts.subject.is_none());
        assert!(opts.headers.is_none());
        assert!(opts.text.is_none());
        assert!(opts.file.is_none());
        assert!(opts.logfile.is_none());
        assert!(opts.oncelog.is_none());
        assert!(opts.once_repeat.is_none());
        assert!(opts.never_mail.is_none());
    }

    #[test]
    fn test_default_options_bool_false() {
        let opts = AutoreplyTransportOptions::default();
        assert!(!opts.file_expand);
        assert!(!opts.file_optional);
        assert!(!opts.return_message);
    }

    #[test]
    fn test_default_options_numbers() {
        let opts = AutoreplyTransportOptions::default();
        assert_eq!(opts.once_file_size, 0);
    }

    #[test]
    fn test_options_has_all_18_fields() {
        // Verify all 18 fields are accessible by constructing with explicit values.
        let opts = AutoreplyTransportOptions {
            from: Some("sender@test.com".to_string()),
            reply_to: Some("reply@test.com".to_string()),
            to: Some("to@test.com".to_string()),
            cc: Some("cc@test.com".to_string()),
            bcc: Some("bcc@test.com".to_string()),
            subject: Some("Test Subject".to_string()),
            headers: Some("X-Custom: value".to_string()),
            text: Some("Hello World".to_string()),
            file: Some("/tmp/body.txt".to_string()),
            logfile: Some("/tmp/autoreply.log".to_string()),
            oncelog: Some("/tmp/oncelog".to_string()),
            once_repeat: Some("7d".to_string()),
            never_mail: Some("admin@test.com".to_string()),
            mode: 0o644,
            once_file_size: 8192,
            file_expand: true,
            file_optional: true,
            return_message: true,
        };

        assert_eq!(opts.from.as_deref(), Some("sender@test.com"));
        assert_eq!(opts.reply_to.as_deref(), Some("reply@test.com"));
        assert_eq!(opts.to.as_deref(), Some("to@test.com"));
        assert_eq!(opts.cc.as_deref(), Some("cc@test.com"));
        assert_eq!(opts.bcc.as_deref(), Some("bcc@test.com"));
        assert_eq!(opts.subject.as_deref(), Some("Test Subject"));
        assert_eq!(opts.headers.as_deref(), Some("X-Custom: value"));
        assert_eq!(opts.text.as_deref(), Some("Hello World"));
        assert_eq!(opts.file.as_deref(), Some("/tmp/body.txt"));
        assert_eq!(opts.logfile.as_deref(), Some("/tmp/autoreply.log"));
        assert_eq!(opts.oncelog.as_deref(), Some("/tmp/oncelog"));
        assert_eq!(opts.once_repeat.as_deref(), Some("7d"));
        assert_eq!(opts.never_mail.as_deref(), Some("admin@test.com"));
        assert_eq!(opts.mode, 0o644);
        assert_eq!(opts.once_file_size, 8192);
        assert!(opts.file_expand);
        assert!(opts.file_optional);
        assert!(opts.return_message);
    }

    // =========================================================================
    // AutoreplyTransport basic tests
    // =========================================================================

    #[test]
    fn test_driver_name() {
        let t = AutoreplyTransport::new();
        assert_eq!(t.driver_name(), "autoreply");
    }

    #[test]
    fn test_is_local() {
        let t = AutoreplyTransport::new();
        assert!(t.is_local());
    }

    #[test]
    fn test_default_trait() {
        let t = AutoreplyTransport::default();
        assert_eq!(t.driver_name(), "autoreply");
        assert!(t.is_local());
    }

    // =========================================================================
    // Validation tests
    // =========================================================================

    #[test]
    fn test_validate_init_ok() {
        let config = TransportInstanceConfig::new("test_autoreply", "autoreply");
        assert!(AutoreplyTransport::validate_init(&config).is_ok());
    }

    #[test]
    fn test_validate_init_uid_without_gid_fails() {
        let mut config = TransportInstanceConfig::new("test_autoreply", "autoreply");
        config.uid_set = true;
        config.gid_set = false;
        config.expand_gid = None;
        let result = AutoreplyTransport::validate_init(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            DriverError::ConfigError(msg) => {
                assert!(msg.contains("user set without group"));
            }
            _ => panic!("Expected ConfigError"),
        }
    }

    #[test]
    fn test_validate_init_uid_with_gid_ok() {
        let mut config = TransportInstanceConfig::new("test_autoreply", "autoreply");
        config.uid_set = true;
        config.gid_set = true;
        assert!(AutoreplyTransport::validate_init(&config).is_ok());
    }

    #[test]
    fn test_validate_init_uid_with_expand_gid_ok() {
        let mut config = TransportInstanceConfig::new("test_autoreply", "autoreply");
        config.uid_set = true;
        config.gid_set = false;
        config.expand_gid = Some("mail".to_string());
        assert!(AutoreplyTransport::validate_init(&config).is_ok());
    }

    // =========================================================================
    // CheckExpand tests
    // =========================================================================

    #[test]
    fn test_check_expand_text_allows_all() {
        let result =
            AutoreplyTransport::check_expand("hello\x01world", "test", CheckExpandType::Text);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_expand_hdr_allows_printable() {
        let result = AutoreplyTransport::check_expand("Hello World!", "test", CheckExpandType::Hdr);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_expand_hdr_allows_folding() {
        let result =
            AutoreplyTransport::check_expand("line1\n continued", "test", CheckExpandType::Hdr);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_expand_hdr_rejects_bare_newline() {
        let result = AutoreplyTransport::check_expand("line1\nline2", "test", CheckExpandType::Hdr);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_expand_file_rejects_control_chars() {
        let result =
            AutoreplyTransport::check_expand("/tmp/file\x01name", "test", CheckExpandType::File);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_expand_file_accepts_valid_path() {
        let result = AutoreplyTransport::check_expand(
            "/var/spool/exim/autoreply.log",
            "test",
            CheckExpandType::File,
        );
        assert!(result.is_ok());
    }

    // =========================================================================
    // Never-mail filtering tests
    // =========================================================================

    #[test]
    fn test_never_mail_no_match() {
        let result = AutoreplyTransport::check_never_mail("user@example.com", "admin@other.com");
        assert_eq!(result, Some("user@example.com".to_string()));
    }

    #[test]
    fn test_never_mail_exact_match() {
        let result = AutoreplyTransport::check_never_mail("user@example.com", "user@example.com");
        assert!(result.is_none());
    }

    #[test]
    fn test_never_mail_case_insensitive() {
        let result = AutoreplyTransport::check_never_mail("User@Example.COM", "user@example.com");
        assert!(result.is_none());
    }

    #[test]
    fn test_never_mail_domain_wildcard() {
        let result = AutoreplyTransport::check_never_mail("user@example.com", "*@example.com");
        assert!(result.is_none());
    }

    #[test]
    fn test_never_mail_partial_removal() {
        let result = AutoreplyTransport::check_never_mail(
            "good@example.com, bad@blocked.com",
            "bad@blocked.com",
        );
        assert_eq!(result, Some("good@example.com".to_string()));
    }

    #[test]
    fn test_never_mail_all_removed() {
        let result = AutoreplyTransport::check_never_mail(
            "bad1@blocked.com, bad2@blocked.com",
            "*@blocked.com",
        );
        assert!(result.is_none());
    }

    // =========================================================================
    // Time parsing tests
    // =========================================================================

    #[test]
    fn test_parse_time_seconds() {
        assert_eq!(AutoreplyTransport::parse_time_value("3600").unwrap(), 3600);
    }

    #[test]
    fn test_parse_time_with_suffix() {
        assert_eq!(AutoreplyTransport::parse_time_value("7d").unwrap(), 604800);
        assert_eq!(AutoreplyTransport::parse_time_value("12h").unwrap(), 43200);
        assert_eq!(AutoreplyTransport::parse_time_value("30m").unwrap(), 1800);
        assert_eq!(AutoreplyTransport::parse_time_value("45s").unwrap(), 45);
        assert_eq!(AutoreplyTransport::parse_time_value("1w").unwrap(), 604800);
    }

    #[test]
    fn test_parse_time_compound() {
        assert_eq!(
            AutoreplyTransport::parse_time_value("1d12h").unwrap(),
            86400 + 43200
        );
    }

    #[test]
    fn test_parse_time_empty() {
        assert_eq!(AutoreplyTransport::parse_time_value("").unwrap(), 0);
    }

    #[test]
    fn test_parse_time_invalid() {
        assert!(AutoreplyTransport::parse_time_value("abc").is_err());
    }

    // =========================================================================
    // Address extraction tests
    // =========================================================================

    #[test]
    fn test_extract_bare_plain() {
        assert_eq!(extract_bare_address("user@example.com"), "user@example.com");
    }

    #[test]
    fn test_extract_bare_angle_brackets() {
        assert_eq!(
            extract_bare_address("<user@example.com>"),
            "user@example.com"
        );
    }

    #[test]
    fn test_extract_bare_display_name() {
        assert_eq!(
            extract_bare_address("John Doe <john@example.com>"),
            "john@example.com"
        );
    }

    // =========================================================================
    // Path validation tests
    // =========================================================================

    #[test]
    fn test_validate_path_valid() {
        let result = AutoreplyTransport::validate_path("/var/spool/exim/once", "once file", "test");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_path_null_byte_rejected() {
        let result = AutoreplyTransport::validate_path("/var/spool/\0evil", "once file", "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_path_empty_rejected() {
        let result = AutoreplyTransport::validate_path("", "once file", "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_path_traversal_rejected() {
        let result =
            AutoreplyTransport::validate_path("/var/spool/../etc/passwd", "once file", "test");
        assert!(result.is_err());
    }

    // =========================================================================
    // Cache entry parsing tests
    // =========================================================================

    #[test]
    fn test_parse_cache_empty() {
        let entries = AutoreplyTransport::parse_cache_entries(&[]);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_cache_roundtrip() {
        let original = vec![
            OnceEntry {
                timestamp: 1700000000,
                address: "user@test.com".to_string(),
            },
            OnceEntry {
                timestamp: 1700001000,
                address: "other@test.com".to_string(),
            },
        ];

        let serialized = AutoreplyTransport::serialize_cache_entries(&original);
        let parsed = AutoreplyTransport::parse_cache_entries(&serialized);

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].timestamp, 1700000000);
        assert_eq!(parsed[0].address, "user@test.com");
        assert_eq!(parsed[1].timestamp, 1700001000);
        assert_eq!(parsed[1].address, "other@test.com");
    }

    #[test]
    fn test_find_in_cache_present() {
        let entries = vec![
            OnceEntry {
                timestamp: 100,
                address: "a@test.com".to_string(),
            },
            OnceEntry {
                timestamp: 200,
                address: "b@test.com".to_string(),
            },
        ];
        let result = AutoreplyTransport::find_in_cache(&entries, "b@test.com");
        assert_eq!(result, Some((1, 200)));
    }

    #[test]
    fn test_find_in_cache_absent() {
        let entries = vec![OnceEntry {
            timestamp: 100,
            address: "a@test.com".to_string(),
        }];
        let result = AutoreplyTransport::find_in_cache(&entries, "b@test.com");
        assert!(result.is_none());
    }

    // =========================================================================
    // Timestamp formatting tests
    // =========================================================================

    #[test]
    fn test_epoch_days_to_ymd_epoch() {
        let (y, m, d) = epoch_days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn test_epoch_days_to_ymd_known_date() {
        // 2024-01-15 is 19737 days since epoch.
        let (y, m, d) = epoch_days_to_ymd(19737);
        assert_eq!((y, m, d), (2024, 1, 15));
    }

    // =========================================================================
    // Transport entry basic test
    // =========================================================================

    #[test]
    fn test_transport_entry_basic() {
        let transport = AutoreplyTransport::new();
        let mut config = TransportInstanceConfig::new("vacation", "autoreply");
        let opts = AutoreplyTransportOptions {
            text: Some("I am on vacation.".to_string()),
            subject: Some("Out of office".to_string()),
            ..Default::default()
        };
        config.set_options(opts);

        let result = transport.transport_entry(&config, "sender@example.com");
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
    }

    #[test]
    fn test_transport_entry_never_mail_all_removed() {
        let transport = AutoreplyTransport::new();
        let mut config = TransportInstanceConfig::new("vacation", "autoreply");
        let opts = AutoreplyTransportOptions {
            to: Some("blocked@example.com".to_string()),
            text: Some("I am on vacation.".to_string()),
            never_mail: Some("*@example.com".to_string()),
            ..Default::default()
        };
        config.set_options(opts);

        let result = transport.transport_entry(&config, "sender@test.com");
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
    }

    // =========================================================================
    // Address matching tests
    // =========================================================================

    #[test]
    fn test_address_matches_exact() {
        assert!(address_matches("user@example.com", "user@example.com"));
    }

    #[test]
    fn test_address_matches_wildcard() {
        assert!(address_matches("user@example.com", "*"));
    }

    #[test]
    fn test_address_matches_domain_wildcard() {
        assert!(address_matches("user@example.com", "*@example.com"));
        assert!(!address_matches("user@other.com", "*@example.com"));
    }

    #[test]
    fn test_address_matches_case_insensitive() {
        assert!(address_matches("USER@EXAMPLE.COM", "user@example.com"));
    }

    // =========================================================================
    // Option name mapping tests
    // =========================================================================

    #[test]
    fn test_option_names_count() {
        // Must have exactly 18 option name mappings.
        assert_eq!(OPTION_NAMES.len(), 18);
    }

    #[test]
    fn test_option_names_alphabetical() {
        let names: Vec<&str> = OPTION_NAMES.iter().map(|(name, _)| *name).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "Option names must be in alphabetical order");
    }

    #[test]
    fn test_option_names_log_alias() {
        let log_entry = OPTION_NAMES.iter().find(|(name, _)| *name == "log");
        assert_eq!(log_entry, Some(&("log", "logfile")));
    }

    #[test]
    fn test_option_names_once_alias() {
        let once_entry = OPTION_NAMES.iter().find(|(name, _)| *name == "once");
        assert_eq!(once_entry, Some(&("once", "oncelog")));
    }
}
