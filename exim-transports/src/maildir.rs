// =============================================================================
// exim-transports/src/maildir.rs — Maildir Helper
// =============================================================================
//
// Rewrites `src/src/transports/tf_maildir.c` (570 lines) — Maildir quota
// management and directory hierarchy helper used by the appendfile transport.
//
// Per AAP §0.7.2: zero unsafe blocks.
// Per AAP §0.4.2: this is a helper module, not registered independently.

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

// =============================================================================
// Constants
// =============================================================================

/// Default Maildir quota limit (0 = no limit).
#[allow(dead_code)] // Default Maildir quota
const DEFAULT_QUOTA: u64 = 0;

/// Maildir quota filename (maildirsize).
const MAILDIRSIZE_FILENAME: &str = "maildirsize";

/// Maximum number of lines in maildirsize before recalculation.
const MAILDIRSIZE_MAX_LINES: usize = 512;

/// Maildir subdirectories required by the specification.
const MAILDIR_SUBDIRS: [&str; 3] = ["new", "cur", "tmp"];

/// Maximum filename length for unique Maildir filenames.
const MAX_FILENAME_LENGTH: usize = 255;

/// Default directory permissions (0700).
#[allow(dead_code)] // Default Maildir directory mode
const DEFAULT_DIR_MODE: u32 = 0o700;

/// Default file permissions (0600).
#[allow(dead_code)] // Default Maildir file mode
const DEFAULT_FILE_MODE: u32 = 0o600;

/// Temporary file prefix for atomic operations.
#[allow(dead_code)] // Maildir tmp subdirectory prefix
const TMP_PREFIX: &str = "tmp";

// =============================================================================
// MaildirQuota — Quota tracking and enforcement
// =============================================================================

/// Maildir quota information and enforcement.
///
/// Implements the Maildir++ quota specification using the `maildirsize`
/// file for efficient quota tracking without requiring a full directory
/// traversal for each delivery.
#[derive(Debug, Clone, Default)]
pub struct MaildirQuota {
    /// Maximum total size in bytes (0 = unlimited).
    pub size_limit: u64,
    /// Maximum number of messages (0 = unlimited).
    pub count_limit: u64,
    /// Current total size from maildirsize.
    pub current_size: u64,
    /// Current message count from maildirsize.
    pub current_count: u64,
}

impl MaildirQuota {
    /// Parse a Maildir++ quota specification string.
    ///
    /// Format: "100000000S,10000C" (100MB size, 10000 messages).
    pub fn parse_quota_spec(spec: &str) -> Self {
        let mut quota = Self::default();

        for part in spec.split(',') {
            let trimmed = part.trim();
            if trimmed.ends_with('S') || trimmed.ends_with('s') {
                if let Ok(val) = trimmed[..trimmed.len() - 1].parse::<u64>() {
                    quota.size_limit = val;
                }
            } else if trimmed.ends_with('C') || trimmed.ends_with('c') {
                if let Ok(val) = trimmed[..trimmed.len() - 1].parse::<u64>() {
                    quota.count_limit = val;
                }
            }
        }

        quota
    }

    /// Check whether delivering a message of `size` bytes would exceed quota.
    pub fn would_exceed(&self, size: u64) -> bool {
        if self.size_limit > 0 && (self.current_size + size) > self.size_limit {
            return true;
        }
        if self.count_limit > 0 && (self.current_count + 1) > self.count_limit {
            return true;
        }
        false
    }

    /// Read the current quota usage from the maildirsize file.
    pub fn read_maildirsize(maildir: &Path) -> io::Result<Self> {
        let size_file = maildir.join(MAILDIRSIZE_FILENAME);
        if !size_file.exists() {
            return Ok(Self::default());
        }

        let file = File::open(&size_file)?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        // First line is the quota specification.
        let mut quota = if let Some(Ok(first_line)) = lines.next() {
            Self::parse_quota_spec(&first_line)
        } else {
            Self::default()
        };

        // Subsequent lines are size adjustments: "size count\n".
        let mut total_size: i64 = 0;
        let mut total_count: i64 = 0;

        for line in lines.map_while(Result::ok) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let (Ok(size), Ok(count)) = (parts[0].parse::<i64>(), parts[1].parse::<i64>()) {
                    total_size += size;
                    total_count += count;
                }
            }
        }

        quota.current_size = total_size.max(0) as u64;
        quota.current_count = total_count.max(0) as u64;

        Ok(quota)
    }

    /// Update the maildirsize file after a successful delivery.
    pub fn update_maildirsize(maildir: &Path, size: i64, count: i64) -> io::Result<()> {
        let size_file = maildir.join(MAILDIRSIZE_FILENAME);

        // Check if the file needs recalculation (too many lines).
        if size_file.exists() {
            let line_count = BufReader::new(File::open(&size_file)?).lines().count();
            if line_count >= MAILDIRSIZE_MAX_LINES {
                // Recalculate by scanning the directory.
                recalculate_maildirsize(maildir)?;
                return Ok(());
            }
        }

        // Append the size adjustment line.
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&size_file)?;

        writeln!(file, "{} {}", size, count)?;
        file.flush()?;

        Ok(())
    }

    /// Recalculate quota by scanning the Maildir directory.
    pub fn recalculate(maildir: &Path) -> io::Result<Self> {
        recalculate_maildirsize(maildir)
    }
}

// =============================================================================
// Directory Management
// =============================================================================

/// Ensure the Maildir directory hierarchy exists.
///
/// Creates the Maildir root and required subdirectories (new, cur, tmp)
/// if they do not already exist.
pub fn ensure_maildir_hierarchy(maildir: &Path) -> io::Result<()> {
    if !maildir.exists() {
        fs::create_dir_all(maildir)?;
    }

    for subdir in &MAILDIR_SUBDIRS {
        let sub_path = maildir.join(subdir);
        if !sub_path.exists() {
            fs::create_dir_all(&sub_path)?;
        }
    }

    Ok(())
}

/// Generate a unique filename for Maildir delivery.
///
/// Follows the Maildir convention: `time.pid_count.hostname`
///
/// The filename is guaranteed to be unique within the `tmp/` directory
/// when combined with the hostname and PID.
pub fn generate_maildir_filename(hostname: &str, tag: Option<&str>) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let pid = std::process::id();

    // Use microseconds as delivery sequence number.
    let seq = now.subsec_micros();

    let mut filename = format!("{}.{}_{}.{}", now.as_secs(), pid, seq, hostname);

    // Add optional tag (e.g., ":2,S" for Maildir flags).
    if let Some(t) = tag {
        filename.push_str(t);
    }

    // Truncate if necessary.
    if filename.len() > MAX_FILENAME_LENGTH {
        filename.truncate(MAX_FILENAME_LENGTH);
    }

    filename
}

/// Check if a Maildir folder exists as a proper Maildir structure.
pub fn is_valid_maildir(path: &Path) -> bool {
    if !path.is_dir() {
        return false;
    }

    MAILDIR_SUBDIRS.iter().all(|sub| path.join(sub).is_dir())
}

/// Get the size of a file from its Maildir filename.
///
/// If the filename contains a size indicator (`,S=NNNN`), return that value.
/// Otherwise, return None, requiring a stat() call.
pub fn size_from_filename(filename: &str) -> Option<u64> {
    // Look for ",S=" pattern in the filename.
    if let Some(pos) = filename.find(",S=") {
        let rest = &filename[pos + 3..];
        // Read digits until non-digit.
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        digits.parse::<u64>().ok()
    } else {
        None
    }
}

/// Clean up stale files from the Maildir tmp/ directory.
///
/// Files older than 36 hours in tmp/ are considered stale and are removed.
/// This follows the Maildir specification.
pub fn cleanup_tmp(maildir: &Path) -> io::Result<u32> {
    let tmp_dir = maildir.join("tmp");
    if !tmp_dir.exists() {
        return Ok(0);
    }

    let stale_threshold = Duration::from_secs(36 * 3600); // 36 hours
    let now = SystemTime::now();
    let mut cleaned = 0u32;

    for entry in fs::read_dir(&tmp_dir)? {
        let entry = entry?;
        if let Ok(metadata) = entry.metadata() {
            if let Ok(modified) = metadata.modified() {
                if let Ok(age) = now.duration_since(modified) {
                    if age > stale_threshold {
                        if let Err(e) = fs::remove_file(entry.path()) {
                            tracing::warn!(
                                path = %entry.path().display(),
                                error = %e,
                                "maildir: failed to remove stale tmp file"
                            );
                        } else {
                            cleaned += 1;
                        }
                    }
                }
            }
        }
    }

    Ok(cleaned)
}

// =============================================================================
// Internal helpers
// =============================================================================

use std::time::Duration;

/// Recalculate the maildirsize file by scanning the Maildir directory.
fn recalculate_maildirsize(maildir: &Path) -> io::Result<MaildirQuota> {
    let mut total_size: u64 = 0;
    let mut total_count: u64 = 0;

    for subdir in &["new", "cur"] {
        let sub_path = maildir.join(subdir);
        if !sub_path.exists() {
            continue;
        }

        for entry in fs::read_dir(&sub_path)? {
            let entry = entry?;
            let filename = entry.file_name().to_string_lossy().to_string();

            // Try to get size from filename first.
            let size = if let Some(s) = size_from_filename(&filename) {
                s
            } else {
                entry.metadata()?.len()
            };

            total_size += size;
            total_count += 1;
        }
    }

    // Read the quota spec from the existing maildirsize first line.
    let size_file = maildir.join(MAILDIRSIZE_FILENAME);
    let mut quota = if size_file.exists() {
        let content = fs::read_to_string(&size_file)?;
        if let Some(first_line) = content.lines().next() {
            MaildirQuota::parse_quota_spec(first_line)
        } else {
            MaildirQuota::default()
        }
    } else {
        MaildirQuota::default()
    };

    quota.current_size = total_size;
    quota.current_count = total_count;

    // Rewrite the maildirsize file.
    let mut file = File::create(&size_file)?;
    if quota.size_limit > 0 || quota.count_limit > 0 {
        let mut spec = String::new();
        if quota.size_limit > 0 {
            spec.push_str(&format!("{}S", quota.size_limit));
        }
        if quota.count_limit > 0 {
            if !spec.is_empty() {
                spec.push(',');
            }
            spec.push_str(&format!("{}C", quota.count_limit));
        }
        writeln!(file, "{}", spec)?;
    }
    writeln!(file, "{} {}", total_size, total_count)?;
    file.flush()?;

    Ok(quota)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_quota_spec() {
        let q = MaildirQuota::parse_quota_spec("100000000S,10000C");
        assert_eq!(q.size_limit, 100_000_000);
        assert_eq!(q.count_limit, 10000);
    }

    #[test]
    fn test_parse_quota_spec_size_only() {
        let q = MaildirQuota::parse_quota_spec("50000000S");
        assert_eq!(q.size_limit, 50_000_000);
        assert_eq!(q.count_limit, 0);
    }

    #[test]
    fn test_would_exceed() {
        let q = MaildirQuota {
            size_limit: 1000,
            count_limit: 10,
            current_size: 900,
            current_count: 9,
        };
        assert!(!q.would_exceed(50));
        assert!(q.would_exceed(200));
    }

    #[test]
    fn test_would_exceed_count() {
        let q = MaildirQuota {
            size_limit: 10000,
            count_limit: 10,
            current_size: 100,
            current_count: 10,
        };
        assert!(q.would_exceed(1));
    }

    #[test]
    fn test_generate_filename() {
        let name = generate_maildir_filename("testhost", None);
        assert!(!name.is_empty());
        assert!(name.contains("testhost"));
    }

    #[test]
    fn test_generate_filename_with_tag() {
        let name = generate_maildir_filename("testhost", Some(":2,S"));
        assert!(name.contains(":2,S"));
    }

    #[test]
    fn test_size_from_filename() {
        assert_eq!(size_from_filename("1234.5678.host,S=4096:2,S"), Some(4096));
        assert_eq!(size_from_filename("1234.5678.host"), None);
        assert_eq!(size_from_filename("1234.5678.host,S=0"), Some(0));
    }

    #[test]
    fn test_is_valid_maildir() {
        let temp_dir = std::env::temp_dir().join("maildir_test_valid");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        assert!(!is_valid_maildir(&temp_dir));

        for sub in &MAILDIR_SUBDIRS {
            fs::create_dir_all(temp_dir.join(sub)).unwrap();
        }
        assert!(is_valid_maildir(&temp_dir));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_ensure_hierarchy() {
        let temp_dir = std::env::temp_dir().join("maildir_test_hierarchy");
        let _ = fs::remove_dir_all(&temp_dir);

        ensure_maildir_hierarchy(&temp_dir).unwrap();
        assert!(is_valid_maildir(&temp_dir));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_quota_unlimited() {
        let q = MaildirQuota::default();
        assert!(!q.would_exceed(1_000_000_000));
    }
}
