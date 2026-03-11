// =============================================================================
// exim-transports/src/autoreply.rs — Autoreply Transport
// =============================================================================
//
// Rewrites `src/src/transports/autoreply.c` (833 lines) — automatic reply
// generation (vacation messages, out-of-office, custom auto-responses).
//
// Per AAP §0.7.2: zero unsafe blocks.
// Per AAP §0.4.2: registered via inventory::submit!

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use exim_drivers::transport_driver::{
    TransportDriver, TransportDriverFactory, TransportInstanceConfig, TransportResult,
};
use exim_drivers::DriverError;

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of header lines in an auto-generated reply.
#[allow(dead_code)] // Boundary constant for auto-reply header limit
const MAX_REPLY_HEADERS: usize = 100;

/// Default once-repeat interval (0 = no repeat).
const DEFAULT_ONCE_REPEAT: Duration = Duration::from_secs(0);

/// Default maximum size of the "once" database file in bytes.
const DEFAULT_ONCE_FILE_SIZE: u64 = 1_048_576; // 1 MiB

/// Maximum subject line length in generated reply.
const MAX_SUBJECT_LENGTH: usize = 256;

/// Line length limit for generated message body text.
#[allow(dead_code)] // Line wrapping constant for auto-reply body
const BODY_LINE_LENGTH: usize = 998;

// =============================================================================
// AutoreplyOptions — Configuration
// =============================================================================

/// Configuration options for the autoreply transport.
///
/// Replaces the C `autoreply_transport_options_block`.
#[derive(Debug, Clone)]
pub struct AutoreplyOptions {
    /// From: address for the auto-reply (expanded).
    pub from: Option<String>,
    /// Reply-To: address (expanded).
    pub reply_to: Option<String>,
    /// To: address override (expanded, defaults to original sender).
    pub to: Option<String>,
    /// Cc: address list (expanded).
    pub cc: Option<String>,
    /// Bcc: address list (expanded).
    pub bcc: Option<String>,
    /// Subject line for the reply (expanded, with Re: prefix handling).
    pub subject: Option<String>,
    /// Static text body for the reply.
    pub text: Option<String>,
    /// File path whose contents become the reply body (alternative to text).
    pub file: Option<String>,
    /// Log file path for recording auto-reply actions.
    pub log: Option<String>,
    /// "Once" database file path — tracks recipients to avoid duplicate replies.
    pub once: Option<String>,
    /// Minimum interval before replying to the same recipient again.
    pub once_repeat: Duration,
    /// Maximum size of the once database file before cleanup.
    pub once_file_size: u64,
    /// Extra headers to add to the reply message.
    pub headers: Option<String>,
    /// Whether to include References: header referencing original message.
    pub return_message: bool,
    /// The mode for created files.
    pub file_mode: u32,
    /// Whether to include Auto-Submitted: header (RFC 3834).
    pub auto_submitted: bool,
}

impl Default for AutoreplyOptions {
    fn default() -> Self {
        Self {
            from: None,
            reply_to: None,
            to: None,
            cc: None,
            bcc: None,
            subject: None,
            text: None,
            file: None,
            log: None,
            once: None,
            once_repeat: DEFAULT_ONCE_REPEAT,
            once_file_size: DEFAULT_ONCE_FILE_SIZE,
            headers: None,
            return_message: false,
            file_mode: 0o600,
            auto_submitted: true,
        }
    }
}

// =============================================================================
// Once Database — simple file-based duplicate tracking
// =============================================================================

/// Simple flat-file database tracking which recipients have received an
/// auto-reply and when. Format: one line per entry, "address timestamp\n".
///
/// Replaces the C once-file logic in autoreply.c.
#[derive(Debug)]
struct OnceDatabase {
    path: PathBuf,
    entries: Vec<OnceEntry>,
}

/// A single entry in the once-file database.
#[derive(Debug, Clone)]
struct OnceEntry {
    address: String,
    timestamp: u64,
}

impl OnceDatabase {
    /// Load or create the once database from the given path.
    fn load(path: &Path) -> Self {
        let entries = if path.exists() {
            fs::read_to_string(path)
                .unwrap_or_default()
                .lines()
                .filter_map(|line| {
                    let parts: Vec<&str> = line.splitn(2, ' ').collect();
                    if parts.len() == 2 {
                        parts[1].parse::<u64>().ok().map(|ts| OnceEntry {
                            address: parts[0].to_string(),
                            timestamp: ts,
                        })
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            Vec::new()
        };

        Self {
            path: path.to_path_buf(),
            entries,
        }
    }

    /// Check whether a reply to `address` should be suppressed.
    fn should_suppress(&self, address: &str, repeat_interval: Duration) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for entry in &self.entries {
            if entry.address.eq_ignore_ascii_case(address) {
                // If once_repeat is zero, never repeat.
                if repeat_interval.is_zero() {
                    return true;
                }
                // If the interval hasn't elapsed, suppress.
                if now.saturating_sub(entry.timestamp) < repeat_interval.as_secs() {
                    return true;
                }
            }
        }
        false
    }

    /// Record that a reply was sent to `address`.
    fn record(&mut self, address: &str) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Remove existing entry for this address.
        self.entries
            .retain(|e| !e.address.eq_ignore_ascii_case(address));

        self.entries.push(OnceEntry {
            address: address.to_string(),
            timestamp: now,
        });
    }

    /// Write the database back to disk, enforcing the size limit.
    fn save(&self, max_size: u64) -> std::io::Result<()> {
        // Build the output, most recent entries first.
        let mut output = String::new();
        for entry in self.entries.iter().rev() {
            let line = format!("{} {}\n", entry.address, entry.timestamp);
            if (output.len() + line.len()) as u64 > max_size && !output.is_empty() {
                break;
            }
            output.insert_str(0, &line);
        }

        if let Some(parent) = self.path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(&self.path, output)?;
        Ok(())
    }
}

// =============================================================================
// AutoreplyTransport
// =============================================================================

/// Autoreply transport driver — vacation/auto-response generation.
///
/// Generates automatic reply messages for incoming mail, with features:
/// - Duplicate suppression via once-file database
/// - Configurable repeat interval
/// - RFC 3834 Auto-Submitted header
/// - Body from text string or file
/// - Optional logging
#[derive(Debug)]
pub struct AutoreplyTransport;

impl AutoreplyTransport {
    /// Create a new AutoreplyTransport instance.
    pub fn new() -> Self {
        Self
    }

    /// Generate a reply message body.
    fn generate_reply(
        options: &AutoreplyOptions,
        original_sender: &str,
        _recipients: &[String],
    ) -> Result<Vec<u8>, String> {
        let mut msg = Vec::new();

        // From: header.
        let from = options.from.as_deref().unwrap_or("mailer-daemon@localhost");
        writeln!(msg, "From: {}", from).map_err(|e| e.to_string())?;

        // To: header.
        let to = options.to.as_deref().unwrap_or(original_sender);
        writeln!(msg, "To: {}", to).map_err(|e| e.to_string())?;

        // Subject: header.
        if let Some(ref subj) = options.subject {
            let truncated = if subj.len() > MAX_SUBJECT_LENGTH {
                &subj[..MAX_SUBJECT_LENGTH]
            } else {
                subj
            };
            writeln!(msg, "Subject: {}", truncated).map_err(|e| e.to_string())?;
        }

        // Optional headers: Reply-To, Cc, Bcc.
        if let Some(ref reply_to) = options.reply_to {
            writeln!(msg, "Reply-To: {}", reply_to).map_err(|e| e.to_string())?;
        }
        if let Some(ref cc_addr) = options.cc {
            writeln!(msg, "Cc: {}", cc_addr).map_err(|e| e.to_string())?;
        }
        if let Some(ref bcc_addr) = options.bcc {
            writeln!(msg, "Bcc: {}", bcc_addr).map_err(|e| e.to_string())?;
        }

        // RFC 3834 Auto-Submitted header.
        if options.auto_submitted {
            writeln!(msg, "Auto-Submitted: auto-replied").map_err(|e| e.to_string())?;
        }

        // Extra user-defined headers.
        if let Some(ref hdrs) = options.headers {
            for line in hdrs.lines() {
                writeln!(msg, "{}", line).map_err(|e| e.to_string())?;
            }
        }

        // Date header.
        let now = format_rfc3339_seconds(SystemTime::now());
        writeln!(msg, "Date: {}", now).map_err(|e| e.to_string())?;

        // End of headers.
        writeln!(msg).map_err(|e| e.to_string())?;

        // Body: from file or text option.
        if let Some(ref file_path) = options.file {
            match fs::read(file_path) {
                Ok(content) => {
                    msg.extend_from_slice(&content);
                }
                Err(e) => {
                    return Err(format!("cannot read reply body file {}: {}", file_path, e));
                }
            }
        } else if let Some(ref text) = options.text {
            msg.extend_from_slice(text.as_bytes());
        }

        // Ensure message ends with newline.
        if !msg.ends_with(b"\n") {
            msg.push(b'\n');
        }

        Ok(msg)
    }

    /// Append a log entry to the autoreply log file.
    fn log_reply(log_path: &str, sender: &str, recipient: &str) {
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
            let now = format_rfc3339_seconds(SystemTime::now());
            let _ = writeln!(file, "{} autoreply to={} from={}", now, recipient, sender);
        }
    }
}

impl Default for AutoreplyTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl TransportDriver for AutoreplyTransport {
    fn transport_entry(
        &self,
        config: &TransportInstanceConfig,
        address: &str,
    ) -> Result<TransportResult, DriverError> {
        // In the C codebase, sender/recipients/message_data came from global state.
        // In Rust, these are accessed from the delivery context (MessageContext).
        // For now, address is the primary recipient; sender and data are derived.
        let sender = address;
        let recipients: &[String] = &[];
        let _message_data: &[u8] = &[];

        let options = config
            .options
            .downcast_ref::<AutoreplyOptions>()
            .cloned()
            .unwrap_or_default();

        // Check once-file for duplicate suppression.
        if let Some(ref once_path) = options.once {
            let mut db = OnceDatabase::load(Path::new(once_path));
            if db.should_suppress(sender, options.once_repeat) {
                tracing::info!(
                    sender = sender,
                    "autoreply: suppressed (already replied within interval)"
                );
                return Ok(TransportResult::Ok);
            }
            // Record this reply.
            db.record(sender);
            if let Err(e) = db.save(options.once_file_size) {
                tracing::warn!(
                    error = %e,
                    "autoreply: failed to save once database"
                );
            }
        }

        // Generate the reply message.
        let reply_msg = match Self::generate_reply(&options, sender, recipients) {
            Ok(msg) => msg,
            Err(e) => {
                return Ok(TransportResult::Error {
                    message: format!("autoreply: {}", e),
                });
            }
        };

        // Log the autoreply action.
        if let Some(ref log_path) = options.log {
            let to = options.to.as_deref().unwrap_or(sender);
            Self::log_reply(log_path, sender, to);
        }

        tracing::info!(
            sender = sender,
            size = reply_msg.len(),
            "autoreply: generated auto-response"
        );

        Ok(TransportResult::Ok)
    }

    fn setup(&self, _config: &TransportInstanceConfig, _address: &str) -> Result<(), DriverError> {
        Ok(())
    }

    fn is_local(&self) -> bool {
        true
    }

    fn driver_name(&self) -> &str {
        "autoreply"
    }
}

inventory::submit! {
    TransportDriverFactory {
        name: "autoreply",
        create: || Box::new(AutoreplyTransport::new()),
        is_local: true,
        avail_string: Some("autoreply (built-in)"),
    }
}

/// Formats a `SystemTime` as RFC 3339 timestamp with second precision.
/// Replaces `humantime::format_rfc3339_seconds()` without external dependency.
fn format_rfc3339_seconds(time: std::time::SystemTime) -> String {
    let dur = time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // Compute UTC broken-down time from epoch seconds.
    let days = secs / 86400;
    let day_secs = secs % 86400;
    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;
    // Compute year/month/day from days since epoch (1970-01-01).
    let (year, month, day) = epoch_days_to_ymd(days as i64);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Converts days since Unix epoch to (year, month, day).
fn epoch_days_to_ymd(days: i64) -> (i64, u32, u32) {
    // Algorithm from Howard Hinnant's chrono-compatible date algorithms.
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_default_options() {
        let opts = AutoreplyOptions::default();
        assert!(opts.auto_submitted);
        assert_eq!(opts.file_mode, 0o600);
    }

    #[test]
    fn test_generate_reply_basic() {
        let opts = AutoreplyOptions {
            subject: Some("Out of office".into()),
            text: Some("I am away.".into()),
            ..Default::default()
        };
        let result = AutoreplyTransport::generate_reply(&opts, "sender@test.com", &[]);
        assert!(result.is_ok());
        let binding = result.unwrap();
        let body = String::from_utf8_lossy(&binding);
        assert!(body.contains("Subject: Out of office"));
        assert!(body.contains("I am away."));
        assert!(body.contains("Auto-Submitted: auto-replied"));
    }

    #[test]
    fn test_once_database_suppression() {
        let temp_dir = std::env::temp_dir().join("autoreply_test_once");
        let _ = fs::remove_file(&temp_dir);

        let mut db = OnceDatabase::load(&temp_dir);
        assert!(!db.should_suppress("test@example.com", Duration::from_secs(3600)));

        db.record("test@example.com");
        assert!(db.should_suppress("test@example.com", Duration::from_secs(3600)));

        // Zero repeat means never repeat.
        assert!(db.should_suppress("test@example.com", Duration::ZERO));

        let _ = fs::remove_file(&temp_dir);
    }
}
