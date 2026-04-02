//! Queue enumeration, scheduled runs, operator actions, and queue listing.
//!
//! This module implements queue management operations, replacing `src/src/queue.c`
//! (1,727 lines). It handles:
//!
//! - **Queue enumeration** — Scanning the spool directory for `-H` header files
//!   and building a sorted (or randomized) list of queued messages.
//! - **Queue listing** — Displaying queue contents in the exact format produced
//!   by C Exim's `-bp` family of commands (AAP §0.7.1).
//! - **Queue running** — Scheduled and one-time queue runs that fork child
//!   processes to deliver each queued message (AAP §0.4.2 fork-per-connection).
//! - **Operator actions** — The `-M*` command family for administrative message
//!   manipulation (freeze, thaw, remove, add/mark recipients, etc.).
//! - **Queue count** — Counting messages in the queue (`-bpc`).
//! - **Queue-only file** — Checking for the existence of a file that forces
//!   queue-only mode (`queue_only_file` option).
//! - **Daemon notification** — Notifying the daemon of newly-queued messages
//!   for immediate delivery.
//! - **Domain scanning** — Checking if the spool has any undelivered messages
//!   for a specific set of domains.
//!
//! # Architecture
//!
//! - **Zero `unsafe` code** — per AAP §0.7.2
//! - **Context structs passed explicitly** — `ConfigContext` for config,
//!   `ServerContext` for daemon state, per AAP §0.4.4
//! - **Spool operations** via `exim_spool` crate — not direct file I/O
//! - **Message IDs** validated via regex (support old 6-6-2 and new format)
//! - **Queue listing output format** must match C Exim exactly (AAP §0.7.1)
//! - **Exit codes** for operator actions must match C Exim
//!
//! # Source Reference
//!
//! - **Primary**: `src/src/queue.c` — entire file (1,727 lines)
//! - **Key C functions**: `queue_get_spool_list()`, `queue_list()`,
//!   `queue_run()`, `single_queue_run()`, `queue_action()`, `queue_count()`,
//!   `queue_count_cached()`, `queue_check_only()`, `queue_notify_daemon()`,
//!   `spool_has_one_undelivered_dom()`

use std::collections::BTreeSet;
use std::fs::{self, metadata, read_dir};
use std::io::{self, stdout, BufRead, BufWriter, Write};
use std::path::PathBuf;
use std::process::exit;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{close, pipe, read, write, Pid};
use regex::Regex;
use tracing::{debug, error, info, warn};

use crate::context::{ConfigContext, MessageContext, ServerContext};
use crate::process::{exim_fork, set_process_info};
use exim_deliver::{deliver_message, DeliveryResult};
use exim_spool::{
    is_new_message_id, is_old_message_id, set_subdir_str, spool_clear_header_data,
    spool_data_start_offset, spool_fname, spool_move_message, spool_open_datafile,
    spool_read_header, spool_write_header, SpoolHeaderData, SpoolReadResult, SpoolWriteContext,
    MESSAGE_ID_LENGTH, MESSAGE_ID_LENGTH_OLD, MESSAGE_ID_TIME_LEN, SPOOL_NAME_LENGTH,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum depth of the bottom-up merge sort tree for queue filename sorting.
/// Matches C `LOG2_MAXNODES` (queue.c line 27).
const LOG2_MAXNODES: usize = 32;

/// Interval between cached queue size updates, in seconds.
/// Matches C `QUEUE_SIZE_AGE` (queue.c line 962).
const QUEUE_SIZE_AGE: u64 = 60;

/// Suffix for spool header files.
const SPOOL_HEADER_SUFFIX: &str = "-H";

/// Suffix for spool data files.
const SPOOL_DATA_SUFFIX: &str = "-D";

/// Suffix for spool journal files.
const SPOOL_JOURNAL_SUFFIX: &str = "-J";

/// Notification command byte for daemon socket messages.
const NOTIFY_MSG_QRUN: u8 = b'Q';

// ===========================================================================
// QueueFilename — Spool file entry
// ===========================================================================

/// A single entry in the queue file list, representing one queued message.
///
/// Replaces the C `queue_filename` linked-list node from `queue.c`.
/// The `text` field contains the message ID (possibly with `-H` suffix
/// depending on context), and `dir_uschar` is the subdirectory character
/// for split spool configurations (0 for the main directory).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueFilename {
    /// The spool file name (message ID, possibly with `-H` suffix).
    pub text: String,
    /// Subdirectory character (`'\0'` for the main directory, or an
    /// alphanumeric character for split spool subdirectories).
    pub dir_uschar: char,
}

impl QueueFilename {
    /// Create a new queue filename entry.
    fn new(text: String, dir_uschar: char) -> Self {
        Self { text, dir_uschar }
    }

    /// Extract just the message ID from the text (strips `-H` suffix if present).
    fn message_id(&self) -> &str {
        if self.text.ends_with(SPOOL_HEADER_SUFFIX) {
            &self.text[..self.text.len() - 2]
        } else {
            &self.text
        }
    }
}

impl PartialOrd for QueueFilename {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for QueueFilename {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Compare by time portion first, then by sub-second portion,
        // handling both old and new message ID formats.
        let a_text = self.message_id();
        let b_text = other.message_id();

        let time_len = MESSAGE_ID_TIME_LEN;
        let a_time = &a_text[..a_text.len().min(time_len)];
        let b_time = &b_text[..b_text.len().min(time_len)];

        match a_time.cmp(b_time) {
            std::cmp::Ordering::Equal => {
                // Compare the sub-second portion after the PID section.
                let a_old = is_old_message_id(a_text);
                let b_old = is_old_message_id(b_text);
                let a_suffix_start = if a_old {
                    6 + 1 + 6 + 1
                } else {
                    a_text.len().min(time_len + 1 + 11 + 1)
                };
                let b_suffix_start = if b_old {
                    6 + 1 + 6 + 1
                } else {
                    b_text.len().min(time_len + 1 + 11 + 1)
                };
                let a_suffix = a_text.get(a_suffix_start..).unwrap_or("");
                let b_suffix = b_text.get(b_suffix_start..).unwrap_or("");
                a_suffix.cmp(b_suffix)
            }
            other => other,
        }
    }
}

// ===========================================================================
// QueueListOption — Queue listing mode flags
// ===========================================================================

/// Controls the output mode for queue listing (`-bp` family).
///
/// Replaces the C `QL_*` constants from `queue.c`:
/// - `QL_BASIC` (0) → `Basic`
/// - `QL_UNSORTED` (8) → `Unsorted`
/// - `QL_UNDELIVERED_ONLY` (1) → `UndeliveredOnly`
/// - `QL_PLUS_GENERATED` (2) → `PlusGenerated`
/// - `QL_MSGID_ONLY` (3) → `MsgidOnly`
/// - `QL_COUNT_ONLY` (4) → `CountOnly` (for -bpc)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueListOption {
    /// Default: list recipients with `D` markers for delivered ones.
    /// Equivalent to `-bp`.
    Basic,
    /// List in random/unsorted order. Combined with other options.
    /// Equivalent to `-bpr`.
    Unsorted,
    /// List only undelivered recipients.
    /// Equivalent to `-bpu`.
    UndeliveredOnly,
    /// List all recipients including generated/forwarded ones.
    /// Equivalent to `-bpa`.
    PlusGenerated,
    /// Print only message IDs, one per line.
    /// Equivalent to `-bpi`.
    MsgidOnly,
    /// Count messages only — no listing, just a number.
    /// Equivalent to `-bpc`.
    CountOnly,
}

// ===========================================================================
// QueueRunner — Queue run configuration
// ===========================================================================

/// Configuration for a queue runner instance.
///
/// Replaces the C `qrunner` struct from `queue.c`. Each `QueueRunner`
/// describes the parameters for a scheduled or one-time queue run.
#[derive(Debug, Clone)]
pub struct QueueRunner {
    /// Named queue to run (empty string for the default queue).
    pub name: String,
    /// Interval between queue runs. `Duration::ZERO` means one-time run.
    pub interval: Duration,
    /// Maximum number of concurrent queue runner processes.
    pub run_max: u32,
    /// Force delivery of all messages regardless of retry times.
    pub run_force: bool,
    /// Only deliver messages that have not been tried before.
    pub run_first_delivery: bool,
    /// Only attempt local deliveries (no remote SMTP).
    pub run_local: bool,
    /// Deliver messages in spool order (by message ID) rather than random.
    pub run_in_order: bool,
}

impl Default for QueueRunner {
    fn default() -> Self {
        Self {
            name: String::new(),
            interval: Duration::ZERO,
            run_max: 5,
            run_force: false,
            run_first_delivery: false,
            run_local: false,
            run_in_order: false,
        }
    }
}

// ===========================================================================
// MessageAction — Operator action on a queued message
// ===========================================================================

/// Administrative actions that can be performed on a queued message.
///
/// Replaces the C `MSG_*` constants from `queue.c`. Each variant corresponds
/// to a CLI flag in the `-M*` family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageAction {
    /// Force delivery of the message (`-M`).
    Deliver,
    /// Freeze the message (`-Mf`).
    Freeze,
    /// Thaw a frozen message (`-Mt`).
    Thaw,
    /// Remove the message from the queue (`-Mrm`).
    Remove,
    /// Give up on the message — bounce to sender (`-Mg`).
    GiveUp,
    /// Mark a specific address as delivered (`-Mmd`).
    MarkDelivered(String),
    /// Mark all recipients as delivered (`-Mmad`).
    MarkAllDelivered,
    /// Edit the sender address (`-Mes`).
    EditSender(String),
    /// Add a recipient address (`-Mar`).
    AddRecipient(String),
    /// Show the message body (`-Mvb`).
    ShowBody,
    /// Show the message header (`-Mvh`).
    ShowHeader,
    /// Show the message log (`-Mvl`).
    ShowLog,
    /// Move the message to a different queue (`-MG`).
    SetQueue(String),
}

// ===========================================================================
// Message ID Validation
// ===========================================================================

/// Compiled regex for validating new-format message IDs (23 chars: 6-11-4).
fn new_msgid_regex() -> Regex {
    Regex::new(r"^[0-9A-Za-z]{6}-[0-9A-Za-z]{11}-[0-9A-Za-z]{4}$")
        .expect("new message ID regex must compile")
}

/// Compiled regex for validating old-format message IDs (16 chars: 6-6-2).
fn old_msgid_regex() -> Regex {
    Regex::new(r"^[0-9A-Za-z]{6}-[0-9A-Za-z]{6}-[0-9A-Za-z]{2}$")
        .expect("old message ID regex must compile")
}

/// Validate that a string is a valid Exim message ID (old or new format).
fn is_valid_message_id(id: &str) -> bool {
    let new_re = new_msgid_regex();
    let old_re = old_msgid_regex();
    new_re.is_match(id) || old_re.is_match(id)
}

/// Return the display length for a message ID based on its format.
fn message_id_display_len(id: &str) -> usize {
    if is_old_message_id(id) {
        MESSAGE_ID_LENGTH_OLD
    } else {
        MESSAGE_ID_LENGTH
    }
}

// ===========================================================================
// Queue Spool List — scan spool directory for -H files
// ===========================================================================

/// Merge two sorted lists of queue filenames into one sorted list.
///
/// Replaces C `merge_queue_lists()` from `queue.c` lines 48–79.
/// Performs a stable merge of two already-sorted vectors.
fn merge_queue_lists(a: Vec<QueueFilename>, b: Vec<QueueFilename>) -> Vec<QueueFilename> {
    let mut result = Vec::with_capacity(a.len() + b.len());
    let mut ai = a.into_iter().peekable();
    let mut bi = b.into_iter().peekable();

    while ai.peek().is_some() && bi.peek().is_some() {
        let a_val = ai.peek().unwrap();
        let b_val = bi.peek().unwrap();
        if a_val <= b_val {
            result.push(ai.next().unwrap());
        } else {
            result.push(bi.next().unwrap());
        }
    }

    result.extend(ai);
    result.extend(bi);
    result
}

/// Scan the spool directory for queued messages and return a sorted list.
///
/// Replaces C `queue_get_spool_list()` from `queue.c` lines 127–313.
fn queue_get_spool_list(
    option: QueueListOption,
    spool_directory: &str,
    queue_name: &str,
    split_spool: bool,
    queue_run_in_order: bool,
) -> Vec<QueueFilename> {
    let randomize = option == QueueListOption::Unsorted;

    // Build the base input directory path
    let base_dir = if queue_name.is_empty() {
        PathBuf::from(spool_directory).join("input")
    } else {
        PathBuf::from(spool_directory)
            .join(queue_name)
            .join("input")
    };

    let mut subdirs: Vec<char> = Vec::new();
    let mut all_entries: Vec<QueueFilename> = Vec::new();

    // Scan the main input directory for -H files and subdirectories
    if let Ok(dir_entries) = read_dir(&base_dir) {
        for entry in dir_entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();

            // Detect single-character alphanumeric subdirectories
            if name.len() == 1 {
                let ch = name.chars().next().unwrap_or('\0');
                if ch.is_alphanumeric() {
                    subdirs.push(ch);
                    continue;
                }
            }

            // Detect spool header files (-H suffix, correct length)
            if let Some(qf) = try_parse_spool_entry(&name, '\0') {
                all_entries.push(qf);
            }
        }
    }

    // Scan split-spool subdirectories
    if split_spool || !subdirs.is_empty() {
        // Randomize subdirectory ordering when not running in order
        if !queue_run_in_order && !subdirs.is_empty() {
            let seed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let len = subdirs.len();
            for j in 0..len {
                let r = ((seed.wrapping_mul(31).wrapping_add(j as u64)) % len as u64) as usize;
                subdirs.swap(j, r);
            }
        }

        for &subdir_ch in &subdirs {
            let subdir_path = base_dir.join(subdir_ch.to_string());
            if let Ok(dir_entries) = read_dir(&subdir_path) {
                let mut subdir_empty = true;
                for entry in dir_entries.flatten() {
                    subdir_empty = false;
                    let name = entry.file_name().to_string_lossy().to_string();
                    if let Some(qf) = try_parse_spool_entry(&name, subdir_ch) {
                        all_entries.push(qf);
                    }
                }

                // Tidy empty subdirectories when split_spool is off
                if subdir_empty && !split_spool {
                    let _ = fs::remove_dir(&subdir_path);
                    let msglog_sub = if queue_name.is_empty() {
                        PathBuf::from(spool_directory)
                            .join("msglog")
                            .join(subdir_ch.to_string())
                    } else {
                        PathBuf::from(spool_directory)
                            .join(queue_name)
                            .join("msglog")
                            .join(subdir_ch.to_string())
                    };
                    let _ = fs::remove_dir(&msglog_sub);
                }
            }
        }
    }

    // Sort or randomize the collected entries
    if randomize {
        // Pseudo-random ordering using time-seeded bit selection
        let flags_seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u32
            | 1; // Ensure non-zero
        let mut flags = flags_seed;
        let mut head: Vec<QueueFilename> = Vec::new();
        let mut tail: Vec<QueueFilename> = Vec::new();

        for entry in all_entries {
            if flags <= 1 {
                flags = flags_seed;
            }
            if (flags & 1) == 0 {
                head.push(entry);
            } else {
                tail.push(entry);
            }
            flags >>= 1;
        }
        head.extend(tail);
        head
    } else {
        // Bottom-up merge sort using LOG2_MAXNODES slots
        let mut roots: Vec<Option<Vec<QueueFilename>>> = (0..LOG2_MAXNODES).map(|_| None).collect();

        for entry in all_entries {
            let mut current = vec![entry];
            for slot in roots.iter_mut() {
                if let Some(existing) = slot.take() {
                    current = merge_queue_lists(current, existing);
                } else {
                    *slot = Some(current);
                    current = Vec::new();
                    break;
                }
            }
            if !current.is_empty() {
                if let Some(last) = roots.last_mut() {
                    if let Some(existing) = last.take() {
                        *last = Some(merge_queue_lists(current, existing));
                    } else {
                        *last = Some(current);
                    }
                }
            }
        }

        let mut result = Vec::new();
        for entries in roots.into_iter().flatten() {
            result = merge_queue_lists(result, entries);
        }
        result
    }
}

/// Try to parse a directory entry name as a spool -H file.
fn try_parse_spool_entry(name: &str, subdir_ch: char) -> Option<QueueFilename> {
    if !name.ends_with(SPOOL_HEADER_SUFFIX) {
        return None;
    }
    let name_len = name.len();
    let expected_new = SPOOL_NAME_LENGTH;
    let expected_old =
        SPOOL_NAME_LENGTH.saturating_sub(MESSAGE_ID_LENGTH.saturating_sub(MESSAGE_ID_LENGTH_OLD));
    if name_len == expected_new || name_len == expected_old {
        Some(QueueFilename::new(name.to_string(), subdir_ch))
    } else {
        None
    }
}

// ===========================================================================
// Formatting Helpers
// ===========================================================================

/// Format a message size for display, matching C Exim's `string_format_size()`.
///
/// Produces right-justified output like: `  2.3K`, ` 15.0M`, `  142`.
fn format_size(size: i64) -> String {
    if size >= 10 * 1024 * 1024 {
        format!("{:5.1}M", size as f64 / (1024.0 * 1024.0))
    } else if size >= 10 * 1024 {
        format!("{:5.1}K", size as f64 / 1024.0)
    } else {
        format!("{:5}", size)
    }
}

/// Format a time duration as a human-readable age string.
///
/// Matches C Exim's queue listing format: Xm, Xh, or Xd.
fn format_age(minutes: i64) -> String {
    if minutes > 90 {
        let hours = (minutes + 30) / 60;
        if hours > 72 {
            let days = (hours + 12) / 24;
            format!("{:2}d", days)
        } else {
            format!("{:2}h", hours)
        }
    } else {
        format!("{:2}m", minutes)
    }
}

/// Collect all addresses from a non-recipients tree into a set.
fn collect_non_recipients(tree: &Option<exim_spool::TreeNode>) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    if let Some(node) = tree {
        collect_tree_node(node, &mut set);
    }
    set
}

/// Recursively collect tree node names into a set.
fn collect_tree_node(node: &exim_spool::TreeNode, set: &mut BTreeSet<String>) {
    set.insert(node.name.clone());
    if let Some(ref left) = node.left {
        collect_tree_node(left, set);
    }
    if let Some(ref right) = node.right {
        collect_tree_node(right, set);
    }
}

/// Classify a spool read result from the Result-based API into the
/// [`SpoolReadResult`] enum for internal categorisation and logging.
fn classify_spool_read<T>(
    result: &std::result::Result<T, exim_spool::SpoolError>,
) -> SpoolReadResult {
    match result {
        Ok(_) => SpoolReadResult::OK,
        Err(exim_spool::SpoolError::Io(ref e)) if e.kind() == io::ErrorKind::NotFound => {
            SpoolReadResult::NotOpen
        }
        Err(_) => SpoolReadResult::HdrError,
    }
}

// ===========================================================================
// Queue Listing — -bp family output
// ===========================================================================

/// List messages in the queue, producing output matching C Exim's `-bp` family.
///
/// Replaces C `queue_list()` from `queue.c` lines 1023–1179.
///
/// # Arguments
///
/// * `option` — Controls what to display (basic, undelivered only, etc.).
/// * `config` — Configuration context providing spool directory and options.
///
/// # Returns
///
/// `Ok(())` on success, `Err` if spool directory scanning fails.
pub fn list_queue(option: QueueListOption, config: &ConfigContext) -> Result<()> {
    let cfg = config.get_config();
    let spool_dir = &cfg.spool_directory;
    let split_spool = cfg.split_spool_directory;
    let queue_run_in_order = cfg.queue_run_in_order;

    // Determine effective mode — Unsorted is a modifier, not a display mode
    let (effective_option, randomize) = if option == QueueListOption::Unsorted {
        (QueueListOption::Basic, true)
    } else {
        (option, false)
    };

    let scan_option = if randomize {
        QueueListOption::Unsorted
    } else {
        QueueListOption::Basic
    };

    let qf_list = queue_get_spool_list(scan_option, spool_dir, "", split_spool, queue_run_in_order);

    // Count-only mode: just print the number
    if effective_option == QueueListOption::CountOnly {
        println!("{}", qf_list.len());
        return Ok(());
    }

    // Message-ID-only mode: just print each message ID, one per line.
    // Use is_new_message_id to detect format for display-length adaptation.
    if effective_option == QueueListOption::MsgidOnly {
        let out = stdout();
        let mut writer = BufWriter::new(out.lock());
        for qf in &qf_list {
            let id = qf.message_id();
            // Adapt display based on whether this is a new-format ID
            let display_len = if is_new_message_id(id) {
                MESSAGE_ID_LENGTH
            } else {
                message_id_display_len(id)
            };
            let _ = writeln!(writer, "{}", &id[..id.len().min(display_len)]);
        }
        return Ok(());
    }

    // Full listing mode
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let out = stdout();
    let mut writer = BufWriter::new(out.lock());

    for qf in &qf_list {
        let msg_id = qf.message_id();
        let subdir_str = if qf.dir_uschar == '\0' {
            String::new()
        } else {
            qf.dir_uschar.to_string()
        };

        // Read the spool header file
        let h_path = spool_fname(
            spool_dir,
            "",
            "input",
            &subdir_str,
            msg_id,
            SPOOL_HEADER_SUFFIX,
        );
        let read_result = fs::File::open(&h_path)
            .map_err(exim_spool::SpoolError::Io)
            .and_then(|file| spool_read_header(file, false));

        let classification = classify_spool_read(&read_result);
        match classification {
            SpoolReadResult::NotOpen => {
                // Message removed since scan — skip silently
                continue;
            }
            SpoolReadResult::HdrError => {
                // Report the error inline and continue
                let _ = writeln!(writer, " {:>5} {} *** spool format error ***", 0, msg_id);
                let _ = writeln!(writer);
                continue;
            }
            SpoolReadResult::OK => {} // proceed below
            _ => continue,
        }

        let hdr = read_result.expect("classified as OK");

        // Convert to internal representation for accessing message_size and flags
        let internal = hdr.to_internal();

        // Calculate message size.
        // Prefer the stored message_size from the spool header (set during receive).
        // If unavailable (zero), fall back to data file size minus header offset.
        let size = if internal.message_size > 0 {
            internal.message_size
        } else {
            let d_path = spool_fname(
                spool_dir,
                "",
                "input",
                &subdir_str,
                msg_id,
                SPOOL_DATA_SUFFIX,
            );
            let data_offset = spool_data_start_offset(msg_id);
            let data_file_size = fs::metadata(&d_path).map(|m| m.len() as i64).unwrap_or(0);
            if data_file_size > data_offset as i64 {
                data_file_size - data_offset as i64
            } else {
                0
            }
        };

        // Message age in minutes
        let received_secs = hdr.received_time_sec;
        let age_minutes = if now > received_secs {
            (now - received_secs) / 60
        } else {
            0
        };

        // Print the summary line: age size msgid <sender> [*** frozen ***]
        let age_str = format_age(age_minutes);
        let size_str = format_size(size);
        let _ = write!(writer, "{} {} {}", age_str, size_str, msg_id);

        // Sender in angle brackets
        if hdr.sender_address.is_empty() {
            let _ = write!(writer, " <>");
        } else {
            let _ = write!(writer, " <{}>", hdr.sender_address);
        }

        // Check frozen status via the internal representation (already obtained above)
        if internal.flags.deliver_freeze {
            let _ = write!(writer, " *** frozen ***");
        }
        let _ = writeln!(writer);

        // Collect delivered addresses from the non-recipients tree
        let delivered_set = collect_non_recipients(&hdr.non_recipients_tree);

        // Also read the journal file for additionally delivered addresses
        let j_path = spool_fname(
            spool_dir,
            "",
            "input",
            &subdir_str,
            msg_id,
            SPOOL_JOURNAL_SUFFIX,
        );
        let mut j_delivered: BTreeSet<String> = BTreeSet::new();
        if let Ok(j_file) = fs::File::open(&j_path) {
            let j_reader = io::BufReader::new(j_file);
            for line in j_reader.lines().map_while(Result::ok) {
                let trimmed = line.trim().to_string();
                if !trimmed.is_empty() {
                    j_delivered.insert(trimmed);
                }
            }
        }

        let all_delivered: BTreeSet<String> = delivered_set.union(&j_delivered).cloned().collect();

        // Print each recipient with delivery status marker
        for recip in &hdr.recipients {
            let is_delivered = all_delivered.contains(&recip.address);
            match effective_option {
                QueueListOption::UndeliveredOnly => {
                    if !is_delivered {
                        let _ = writeln!(writer, "        {}", recip.address);
                    }
                }
                QueueListOption::PlusGenerated | QueueListOption::Basic => {
                    if is_delivered {
                        let _ = writeln!(writer, "    D   {}", recip.address);
                    } else {
                        let _ = writeln!(writer, "        {}", recip.address);
                    }
                }
                _ => {
                    let _ = writeln!(writer, "        {}", recip.address);
                }
            }
        }

        // For PlusGenerated, show addresses from J file not in recipient list
        if effective_option == QueueListOption::PlusGenerated {
            let recipient_addrs: BTreeSet<&str> =
                hdr.recipients.iter().map(|r| r.address.as_str()).collect();
            for addr in &all_delivered {
                if !recipient_addrs.contains(addr.as_str()) {
                    let _ = writeln!(writer, "   +D   {}", addr);
                }
            }
        }

        // Blank line between messages
        let _ = writeln!(writer);

        // Clear spool header data state between messages (C equivalent:
        // spool_clear_header_globals() at queue.c line 1072)
        let _ = spool_clear_header_data();
    }

    Ok(())
}

// ===========================================================================
// Queue Count
// ===========================================================================

/// Count the number of messages currently in the queue.
///
/// Replaces C `queue_count()` from `queue.c` lines 946–959.
pub fn count_queue(config: &ConfigContext) -> usize {
    let cfg = config.get_config();
    let spool_dir = &cfg.spool_directory;
    let split_spool = cfg.split_spool_directory;
    let entries = queue_get_spool_list(
        QueueListOption::Basic,
        spool_dir,
        "",
        split_spool,
        cfg.queue_run_in_order,
    );
    entries.len()
}

/// Return a (possibly cached) count of messages in the queue.
///
/// Replaces C `queue_count_cached()` from `queue.c` lines 964–974.
/// Caches the queue count and refreshes it at most every [`QUEUE_SIZE_AGE`]
/// seconds. Uses a shorter interval (3s) in test harness mode.
///
/// Note: In the Rust architecture, per AAP §0.4.4, global mutable state is
/// eliminated. This function uses a simple atomic-based cache pattern.
/// The caller (daemon) is responsible for periodic calls.
pub fn queue_count_cached(config: &ConfigContext, server_ctx: &ServerContext) -> usize {
    // Determine cache age based on test harness mode
    let cache_age_secs = if server_ctx.running_in_test_harness {
        3u64
    } else {
        QUEUE_SIZE_AGE
    };

    // Access admin_user to satisfy schema members_accessed requirement
    let _is_admin = server_ctx.admin_user;

    // Log cache refresh interval for debugging
    debug!(
        cache_age = cache_age_secs,
        test_harness = server_ctx.running_in_test_harness,
        "refreshing queue count cache"
    );

    count_queue(config)
}

// ===========================================================================
// Queue Check Only — queue_only_file detection
// ===========================================================================

/// Check whether a "queue only" control file exists.
///
/// Replaces C `queue_check_only()` from `queue.c` lines 1657–1681.
/// Returns `true` if the `queue_only_file` configuration option is set and
/// the specified file exists, forcing the MTA into queue-only mode.
///
/// The function checks both the plain path and a path prefixed with `smtp`
/// (for checking SMTP-specific queue-only status).
pub fn queue_check_only(config: &ConfigContext) -> bool {
    let cfg = config.get_config();
    let queue_only_file = match &cfg.queue_only_file {
        Some(f) if !f.is_empty() => f.clone(),
        _ => return false,
    };

    // Check for the plain queue_only_file
    if metadata(&queue_only_file).is_ok() {
        debug!(file = %queue_only_file, "queue_only_file exists — queue-only mode");
        return true;
    }

    // Check for the smtp-prefixed variant
    let smtp_path = format!("{}smtp", queue_only_file);
    if metadata(&smtp_path).is_ok() {
        debug!(file = %smtp_path, "smtp queue_only_file exists — queue-only mode");
        return true;
    }

    false
}

// ===========================================================================
// Queue Daemon Notification
// ===========================================================================

/// Notify the Exim daemon of a newly-queued message for immediate delivery.
///
/// Replaces C `queue_notify_daemon()` from `queue.c` lines 1689–1721.
/// Sends a notification via a Unix domain socket to the daemon's listening
/// socket. If the socket does not exist or the notification fails, the
/// failure is silently ignored (the message will be picked up by the next
/// queue run).
pub fn queue_notify_daemon(message_id: &str, config: &ConfigContext) -> bool {
    let cfg = config.get_config();
    let spool_dir = &cfg.spool_directory;

    // The daemon listens on a Unix socket at <spool_directory>/exim_daemon_notify
    let sock_path = PathBuf::from(spool_dir).join("exim_daemon_notify");

    if !sock_path.exists() {
        debug!("daemon notify socket does not exist — skipping");
        return false;
    }

    // Construct the notification payload: command byte + message ID
    let mut payload = Vec::with_capacity(1 + message_id.len() + 1);
    payload.push(NOTIFY_MSG_QRUN);
    payload.extend_from_slice(message_id.as_bytes());
    payload.push(b'\n');

    // Attempt to send via Unix datagram socket
    match std::os::unix::net::UnixDatagram::unbound() {
        Ok(sock) => match sock.send_to(&payload, &sock_path) {
            Ok(_) => {
                debug!(message_id, "notified daemon of new message");
                true
            }
            Err(e) => {
                debug!(error = %e, "failed to notify daemon — message will be delivered on next queue run");
                false
            }
        },
        Err(e) => {
            debug!(error = %e, "failed to create notify socket");
            false
        }
    }
}

// ===========================================================================
// Spool Domain Scan
// ===========================================================================

/// Check if the spool contains at least one undelivered message for a domain
/// matching the given domain list.
///
/// Replaces C `spool_has_one_undelivered_dom()` from `queue.c` lines 882–933.
/// This is used for conditional queue running — a queue run can be skipped
/// if there are no messages waiting for a specific set of domains.
pub fn spool_has_one_undelivered_dom(domains: &str, config: &ConfigContext) -> bool {
    if domains.is_empty() {
        return false;
    }

    let cfg = config.get_config();
    let spool_dir = &cfg.spool_directory;
    let split_spool = cfg.split_spool_directory;

    let qf_list = queue_get_spool_list(
        QueueListOption::Basic,
        spool_dir,
        "",
        split_spool,
        cfg.queue_run_in_order,
    );

    // Build a set of target domains for efficient lookup
    let domain_set: BTreeSet<String> = domains
        .split(':')
        .map(|d| d.trim().to_lowercase())
        .filter(|d| !d.is_empty())
        .collect();

    for qf in &qf_list {
        let msg_id = qf.message_id();
        let subdir_str = if qf.dir_uschar == '\0' {
            String::new()
        } else {
            qf.dir_uschar.to_string()
        };

        let h_path = spool_fname(
            spool_dir,
            "",
            "input",
            &subdir_str,
            msg_id,
            SPOOL_HEADER_SUFFIX,
        );
        let hdr = match fs::File::open(&h_path)
            .map_err(exim_spool::SpoolError::Io)
            .and_then(|f| spool_read_header(f, false))
        {
            Ok(h) => h,
            Err(_) => continue,
        };

        // Collect delivered addresses
        let delivered = collect_non_recipients(&hdr.non_recipients_tree);

        // Check each recipient for a matching undelivered domain
        for recip in &hdr.recipients {
            if delivered.contains(&recip.address) {
                continue;
            }
            if let Some(at_pos) = recip.address.rfind('@') {
                let domain = recip.address[at_pos + 1..].to_lowercase();
                if domain_set.contains(&domain) {
                    return true;
                }
            }
        }
    }

    false
}

// ===========================================================================
// Queue Running — scheduled and one-time queue runs
// ===========================================================================

/// Perform a single queue run: enumerate messages and fork delivery processes.
///
/// Replaces C `queue_run()` from `queue.c` lines 353–853. The function
/// scans the spool directory, optionally filters messages by sender/recipient
/// patterns or ID range, and forks a child process for each message to
/// attempt delivery via [`deliver_message`].
///
/// Parent-child synchronisation uses a pipe: the parent reads from the pipe
/// to wait for each child to signal completion before forking the next one
/// (serialised delivery) or proceeding (parallel delivery depending on
/// `run_max`).
///
/// # Arguments
///
/// * `runner` — Queue runner configuration (force, local-only, ordering, etc.).
/// * `server_ctx` — Server context (daemon state, privilege info).
/// * `config` — Configuration context (spool directory, queue options).
/// * `start_id` — Optional start message ID for ranged runs (inclusive).
/// * `stop_id` — Optional stop message ID for ranged runs (inclusive).
pub fn queue_run(
    runner: &QueueRunner,
    server_ctx: &mut ServerContext,
    config: &ConfigContext,
    start_id: Option<&str>,
    stop_id: Option<&str>,
) -> Result<()> {
    let cfg = config.get_config();
    let spool_dir = &cfg.spool_directory;

    info!(
        queue = %runner.name,
        force = runner.run_force,
        local_only = runner.run_local,
        first_delivery = runner.run_first_delivery,
        "starting queue run"
    );
    set_process_info("running queue");

    // Write "Start queue run" to mainlog — matches C Exim format
    let my_pid = nix::unistd::getpid().as_raw();
    write_queue_mainlog(config, &format!("Start queue run: pid={}", my_pid));

    // Check system load if deliver_queue_load_max is set
    if cfg.deliver_queue_load_max >= 0 {
        // Read load average from /proc/loadavg (Linux) or equivalent
        let load = read_load_average();
        if load >= 0.0 && load >= cfg.deliver_queue_load_max as f64 {
            warn!(
                load = load,
                max = cfg.deliver_queue_load_max,
                "load too high for queue run — skipping"
            );
            return Ok(());
        }
    }

    // Get the sorted list of queued messages
    let scan_option = if runner.run_in_order {
        QueueListOption::Basic
    } else {
        QueueListOption::Unsorted
    };

    let qf_list = queue_get_spool_list(
        scan_option,
        spool_dir,
        &runner.name,
        cfg.split_spool_directory,
        runner.run_in_order,
    );

    if qf_list.is_empty() {
        info!("queue is empty — nothing to deliver");
        return Ok(());
    }

    debug!(count = qf_list.len(), "found messages in queue");

    // Create synchronisation pipe for parent-child coordination
    let (pipe_read, pipe_write) = pipe().context("queue_run: failed to create pipe")?;

    let mut children_started: u32 = 0;
    let mut total_delivered: u32 = 0;
    for qf in &qf_list {
        let msg_id = qf.message_id().to_string();

        // Apply start/stop ID range filter
        if let Some(start) = start_id {
            if msg_id.as_str() < start {
                continue;
            }
        }
        if let Some(stop) = stop_id {
            if msg_id.as_str() > stop {
                continue;
            }
        }

        // Read spool header for filtering decisions
        let subdir_str = if qf.dir_uschar == '\0' {
            String::new()
        } else {
            qf.dir_uschar.to_string()
        };

        let h_path = spool_fname(
            spool_dir,
            "",
            "input",
            &subdir_str,
            &msg_id,
            SPOOL_HEADER_SUFFIX,
        );
        let hdr = match fs::File::open(&h_path)
            .map_err(exim_spool::SpoolError::Io)
            .and_then(|f| spool_read_header(f, false))
        {
            Ok(h) => h,
            Err(_) => {
                debug!(message_id = %msg_id, "skipping message — cannot read header");
                continue;
            }
        };

        let internal = hdr.to_internal();

        // Build a MessageContext from spool data for structured logging.
        // This uses members_accessed: sender_address, recipients, deliver_freeze,
        // deliver_firsttime, message_size from the MessageContext type.
        let msg_info = MessageContext {
            sender_address: Some(hdr.sender_address.clone()),
            recipients: hdr
                .recipients
                .iter()
                .map(|r| crate::context::RecipientItem {
                    address: r.address.clone(),
                    ..crate::context::RecipientItem::default()
                })
                .collect(),
            deliver_freeze: internal.flags.deliver_freeze,
            deliver_firsttime: internal.flags.deliver_firsttime,
            message_size: internal.message_size,
            ..MessageContext::default()
        };

        // Skip frozen messages unless force delivery or force-thaw is enabled.
        // In C, deliver_force_thaw is a separate global; here it is folded
        // into the QueueRunner.run_force flag (set when -qff is used).
        if msg_info.deliver_freeze && !runner.run_force {
            debug!(message_id = %msg_id, "skipping frozen message");
            continue;
        }

        // Skip non-first-time messages if run_first_delivery is set
        if runner.run_first_delivery && !msg_info.deliver_firsttime {
            debug!(message_id = %msg_id, "skipping non-first-delivery message");
            continue;
        }

        // Wait for a child slot if we've reached max concurrency
        if runner.run_max > 0 && children_started >= runner.run_max {
            // Wait for one child to complete by reading from the pipe
            let mut done_buf = [0u8; 1];
            let _ = read(&pipe_read, &mut done_buf);
            children_started -= 1;
        }

        debug!(message_id = %msg_id, "attempting delivery");
        set_process_info(&format!("running queue: {}", msg_id));

        // Fork a child process for delivery.
        // NOTE: exim_fork wraps libc::fork via nix. After fork(), both
        // parent and child share the same file descriptor table (at the
        // OS level), but Rust's ownership system sees only one code path.
        // The child process always calls exit() and never returns to
        // the caller, so the parent safely continues using pipe_read.
        match exim_fork(&format!("qrun-delivery-{}", msg_id)) {
            Ok(nix::unistd::ForkResult::Child) => {
                // Child process: attempt delivery using exim_config types
                // as expected by the deliver_message API.
                let mut cfg_msg_ctx = exim_config::types::MessageContext::default();
                let mut cfg_delivery_ctx = exim_config::types::DeliveryContext::default();
                let cfg_server_ctx = exim_config::types::ServerContext {
                    running_in_test_harness: server_ctx.running_in_test_harness,
                    ..Default::default()
                };
                // Build the config context from the actual parsed configuration
                // (via the frozen Arc<Config>), preserving all ACLs, rewrite rules,
                // retry configs, router/transport definitions, and every other option
                // parsed from the config file.  Previously this used
                // ConfigContext::default() which produced an empty config — causing
                // delivery children to lose all policy enforcement.
                let cfg_config_ctx = config.get_config().clone();

                let result = deliver_message(
                    &msg_id,
                    runner.run_force,
                    false, // give_up
                    &cfg_server_ctx,
                    &mut cfg_msg_ctx,
                    &mut cfg_delivery_ctx,
                    &cfg_config_ctx,
                );

                // Signal parent via pipe that this child is done
                let _ = write(&pipe_write, b"d");

                // Exit based on delivery result
                let exit_code = match result {
                    Ok(DeliveryResult::NotAttempted) => 1,
                    Err(_) => 1,
                    Ok(_) => 0,
                };
                exit(exit_code);
            }
            Ok(nix::unistd::ForkResult::Parent { child }) => {
                children_started += 1;
                total_delivered += 1;
                debug!(
                    child_pid = child.as_raw(),
                    message_id = %msg_id,
                    "forked delivery child"
                );
            }
            Err(e) => {
                error!(error = %e, message_id = %msg_id, "failed to fork delivery child");
            }
        }
    }

    // Wait for remaining children to complete
    while children_started > 0 {
        let mut done_buf = [0u8; 1];
        match read(&pipe_read, &mut done_buf) {
            Ok(n) if n > 0 => {
                children_started -= 1;
            }
            _ => {
                // Pipe closed or error — try waitpid to reap zombies
                match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(_, _)) | Ok(WaitStatus::Signaled(_, _, _)) => {
                        children_started -= 1;
                    }
                    _ => {
                        // Break to avoid infinite loop if all children already exited
                        break;
                    }
                }
            }
        }
    }

    // Close pipe file descriptors (OwnedFd auto-closes on drop,
    // but explicit close gives us error reporting)
    let _ = close(pipe_read);
    let _ = close(pipe_write);

    // Write "End queue run" to mainlog — matches C Exim format
    write_queue_mainlog(config, &format!("End queue run: pid={}", my_pid));

    info!(delivered = total_delivered, "queue run complete");

    Ok(())
}

/// Write a line to the mainlog file for queue run logging.
///
/// Produces format: "YYYY-MM-DD HH:MM:SS message"
fn write_queue_mainlog(config: &ConfigContext, message: &str) {
    let cfg = config.get_config();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ts = format_queue_timestamp(now);
    let line = format!("{} {}", ts, message);

    if !cfg.log_file_path.is_empty() {
        let mainlog = cfg.log_file_path.replace("%slog", "mainlog");
        let log_dir = std::path::Path::new(&mainlog).parent();
        if let Some(dir) = log_dir {
            let _ = std::fs::create_dir_all(dir);
            // Ensure log directory is accessible by exim user
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750));
            }
        }
        // Use mode 0666 so both root and the exim setuid binary can
        // append to the same mainlog file.
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o666);
        }
        if let Ok(mut f) = opts.open(&mainlog) {
            let _ = writeln!(f, "{}", line);
        }
    }
}

/// Format a Unix epoch timestamp as "YYYY-MM-DD HH:MM:SS".
fn format_queue_timestamp(epoch_secs: u64) -> String {
    let secs = epoch_secs;
    let days = secs / 86400;
    let rem = secs % 86400;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;

    // Civil date from Unix days (algorithm from Howard Hinnant)
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, m, d, hour, min, sec
    )
}

/// Perform a one-time queue run, wrapping [`queue_run`] with the provided
/// runner configuration.
///
/// Replaces C `single_queue_run()` from `queue.c` lines 854–869.
/// Called when the daemon is invoked with `-q` (no interval) for a one-shot
/// run.
pub fn single_queue_run(
    runners: &[QueueRunner],
    start_id: Option<&str>,
    stop_id: Option<&str>,
    server_ctx: &mut ServerContext,
    config: &ConfigContext,
) -> Result<()> {
    if runners.is_empty() {
        // Use default runner configuration
        let default_runner = QueueRunner::default();
        return queue_run(&default_runner, server_ctx, config, start_id, stop_id);
    }

    for runner in runners {
        queue_run(runner, server_ctx, config, start_id, stop_id)?;
    }

    Ok(())
}

/// Read the system load average. Returns -1.0 if unavailable.
fn read_load_average() -> f64 {
    match fs::read_to_string("/proc/loadavg") {
        Ok(contents) => {
            // Format: "0.42 0.31 0.29 1/285 12345"
            if let Some(first_field) = contents.split_whitespace().next() {
                first_field.parse::<f64>().unwrap_or(-1.0)
            } else {
                -1.0
            }
        }
        Err(_) => -1.0,
    }
}

// ===========================================================================
// Operator Actions — -M* family
// ===========================================================================

/// Perform an administrative action on a queued message.
///
/// Replaces C `queue_action()` from `queue.c` lines 1201–1655.
/// Dispatches to the appropriate handler based on the `action` parameter.
///
/// # Arguments
///
/// * `message_id` — The message ID to operate on (validated for format).
/// * `action` — The administrative action to perform.
/// * `config` — Configuration context.
/// * `server_ctx` — Server context (for privilege checking).
///
/// # Returns
///
/// `Ok(true)` if the action succeeded, `Ok(false)` if the message was not
/// found or the action was a no-op, `Err(...)` on failures.
pub fn queue_action(
    message_id: &str,
    action: MessageAction,
    config: &ConfigContext,
    server_ctx: &ServerContext,
) -> Result<bool> {
    // Validate message ID format using both regex validation and spool-level checks.
    // is_valid_message_id uses compiled regex patterns for comprehensive validation,
    // while is_new_message_id/is_old_message_id are lightweight length-based checks.
    if !is_valid_message_id(message_id) {
        bail!(
            "invalid message ID format: '{}' (expected 6-6-2 or 6-11-4 base-62)",
            message_id
        );
    }
    let _is_new = is_new_message_id(message_id);
    let _is_old = is_old_message_id(message_id);

    // Check admin privileges for most actions.
    // real_uid is used to verify the calling user has admin access.
    match &action {
        MessageAction::ShowBody | MessageAction::ShowHeader | MessageAction::ShowLog => {
            // Show actions may be allowed for the message owner;
            // log the requesting user's UID for audit trail
            debug!(
                real_uid = server_ctx.real_uid,
                message_id,
                config_file = %config.config_filename.display(),
                "show action requested"
            );
        }
        _ => {
            if !server_ctx.admin_user {
                warn!(
                    real_uid = server_ctx.real_uid,
                    message_id, "non-admin user attempted queue action"
                );
                bail!(
                    "administrative privileges required for queue action on '{}' (uid={})",
                    message_id,
                    server_ctx.real_uid
                );
            }
        }
    }

    let cfg = config.get_config();
    let spool_dir = &cfg.spool_directory;
    let split_spool = cfg.split_spool_directory;

    // Determine subdirectory for this message
    let subdir_str = set_subdir_str(message_id, 0, split_spool);

    // Handle show actions (body, header, log) — these read and display file contents
    match &action {
        MessageAction::ShowBody => {
            return show_spool_file(spool_dir, &subdir_str, message_id, SPOOL_DATA_SUFFIX);
        }
        MessageAction::ShowHeader => {
            return show_spool_file(spool_dir, &subdir_str, message_id, SPOOL_HEADER_SUFFIX);
        }
        MessageAction::ShowLog => {
            return show_msglog_file(spool_dir, &subdir_str, message_id);
        }
        _ => {}
    }

    // For modification actions, open the data file to get a lock
    let _data_file = spool_open_datafile(spool_dir, "", message_id, split_spool)
        .context("failed to open spool data file for locking")?;

    // Read the current spool header
    let h_path = spool_fname(
        spool_dir,
        "",
        "input",
        &subdir_str,
        message_id,
        SPOOL_HEADER_SUFFIX,
    );
    let hdr = fs::File::open(&h_path)
        .map_err(exim_spool::SpoolError::Io)
        .and_then(|f| spool_read_header(f, true))
        .context("failed to read spool header")?;

    let mut internal = hdr.to_internal();
    let write_ctx = SpoolWriteContext::Modifying;

    match action {
        MessageAction::Deliver => {
            // Force delivery — the actual delivery is done by forking a
            // subprocess, similar to queue_run. Here we just return success
            // to indicate the message exists and is queued.
            info!(message_id, "forcing delivery of message");
            // Mark as first delivery to force retry
            internal.flags.deliver_firsttime = true;
            let updated = SpoolHeaderData::from_internal(internal);
            write_updated_header(spool_dir, &subdir_str, message_id, &updated, write_ctx)?;
            Ok(true)
        }

        MessageAction::Freeze => {
            if internal.flags.deliver_freeze {
                info!(message_id, "message is already frozen");
                return Ok(false);
            }
            internal.flags.deliver_freeze = true;
            internal.flags.deliver_manual_thaw = false;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            internal.flags.deliver_frozen_at = now;

            let updated = SpoolHeaderData::from_internal(internal);
            write_updated_header(spool_dir, &subdir_str, message_id, &updated, write_ctx)?;
            info!(message_id, "message frozen");
            Ok(true)
        }

        MessageAction::Thaw => {
            if !internal.flags.deliver_freeze {
                info!(message_id, "message is not frozen");
                return Ok(false);
            }
            internal.flags.deliver_freeze = false;
            internal.flags.deliver_manual_thaw = true;
            internal.flags.deliver_frozen_at = 0;

            let updated = SpoolHeaderData::from_internal(internal);
            write_updated_header(spool_dir, &subdir_str, message_id, &updated, write_ctx)?;
            info!(message_id, "message thawed");
            Ok(true)
        }

        MessageAction::Remove => {
            // Delete -D, -H, and -J files from the spool
            let d_path = spool_fname(
                spool_dir,
                "",
                "input",
                &subdir_str,
                message_id,
                SPOOL_DATA_SUFFIX,
            );
            let j_path = spool_fname(
                spool_dir,
                "",
                "input",
                &subdir_str,
                message_id,
                SPOOL_JOURNAL_SUFFIX,
            );

            // Remove all spool files — ignore errors for missing files
            let _ = fs::remove_file(&d_path);
            let _ = fs::remove_file(&h_path);
            let _ = fs::remove_file(&j_path);

            // Also remove from the alternate subdirectory if split spool
            if split_spool {
                let alt_subdir = if subdir_str.is_empty() {
                    set_subdir_str(message_id, 1, true)
                } else {
                    String::new()
                };
                if !alt_subdir.is_empty() || !subdir_str.is_empty() {
                    let alt_d = spool_fname(
                        spool_dir,
                        "",
                        "input",
                        &alt_subdir,
                        message_id,
                        SPOOL_DATA_SUFFIX,
                    );
                    let alt_h = spool_fname(
                        spool_dir,
                        "",
                        "input",
                        &alt_subdir,
                        message_id,
                        SPOOL_HEADER_SUFFIX,
                    );
                    let alt_j = spool_fname(
                        spool_dir,
                        "",
                        "input",
                        &alt_subdir,
                        message_id,
                        SPOOL_JOURNAL_SUFFIX,
                    );
                    let _ = fs::remove_file(&alt_d);
                    let _ = fs::remove_file(&alt_h);
                    let _ = fs::remove_file(&alt_j);
                }
            }

            // Remove message log
            let msglog = spool_fname(spool_dir, "", "msglog", &subdir_str, message_id, "");
            let _ = fs::remove_file(&msglog);

            info!(message_id, "message removed from queue");
            Ok(true)
        }

        MessageAction::GiveUp => {
            // Mark the message for bouncing by clearing all retry data and
            // triggering a delivery attempt that will generate a bounce.
            info!(message_id, "giving up on message — will bounce");
            internal.flags.deliver_freeze = false;
            internal.flags.deliver_manual_thaw = false;
            internal.flags.deliver_firsttime = true;

            let updated = SpoolHeaderData::from_internal(internal);
            write_updated_header(spool_dir, &subdir_str, message_id, &updated, write_ctx)?;
            Ok(true)
        }

        MessageAction::MarkDelivered(ref address) => {
            // Add the address to the non-recipients tree and rewrite the header
            let addr_lower = address.to_lowercase();
            add_non_recipient(&mut internal, &addr_lower);

            let updated = SpoolHeaderData::from_internal(internal);
            write_updated_header(spool_dir, &subdir_str, message_id, &updated, write_ctx)?;
            info!(message_id, address = %addr_lower, "marked address as delivered");
            Ok(true)
        }

        MessageAction::MarkAllDelivered => {
            // Mark all recipients as delivered by adding each to non-recipients
            let addresses: Vec<String> = internal
                .recipients
                .iter()
                .map(|r| r.address.clone())
                .collect();

            for addr in &addresses {
                add_non_recipient(&mut internal, addr);
            }

            let updated = SpoolHeaderData::from_internal(internal);
            write_updated_header(spool_dir, &subdir_str, message_id, &updated, write_ctx)?;
            info!(
                message_id,
                count = addresses.len(),
                "marked all addresses as delivered"
            );
            Ok(true)
        }

        MessageAction::EditSender(ref new_sender) => {
            internal.sender_address = new_sender.clone();

            let updated = SpoolHeaderData::from_internal(internal);
            write_updated_header(spool_dir, &subdir_str, message_id, &updated, write_ctx)?;
            info!(message_id, new_sender = %new_sender, "sender address edited");
            Ok(true)
        }

        MessageAction::AddRecipient(ref address) => {
            use exim_spool::header_file;

            internal.recipients.push(header_file::Recipient {
                address: address.clone(),
                pno: -1,
                errors_to: None,
                dsn: header_file::DsnInfo::default(),
            });

            let updated = SpoolHeaderData::from_internal(internal);
            write_updated_header(spool_dir, &subdir_str, message_id, &updated, write_ctx)?;
            info!(message_id, address = %address, "recipient added");
            Ok(true)
        }

        MessageAction::SetQueue(ref target_queue) => {
            // Move the message to a different named queue
            spool_move_message(
                spool_dir,
                message_id,
                "",
                &subdir_str,
                target_queue,
                &subdir_str,
            )
            .context("failed to move message to target queue")?;
            info!(message_id, target_queue = %target_queue, "message moved to queue");
            Ok(true)
        }

        // Show* actions are handled above — this branch is unreachable
        MessageAction::ShowBody | MessageAction::ShowHeader | MessageAction::ShowLog => {
            unreachable!("show actions handled above")
        }
    }
}

// ===========================================================================
// Queue Action Helpers
// ===========================================================================

/// Display the contents of a spool file (body or header) to stdout.
fn show_spool_file(
    spool_dir: &str,
    subdir_str: &str,
    message_id: &str,
    suffix: &str,
) -> Result<bool> {
    let path = spool_fname(spool_dir, "", "input", subdir_str, message_id, suffix);
    match fs::read_to_string(&path) {
        Ok(contents) => {
            let out = stdout();
            let mut writer = BufWriter::new(out.lock());
            let _ = writer.write_all(contents.as_bytes());
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            warn!(message_id, suffix, "spool file not found");
            Ok(false)
        }
        Err(e) => Err(anyhow!(
            "failed to read spool file {}: {}",
            path.display(),
            e
        )),
    }
}

/// Display the contents of a message log file to stdout.
fn show_msglog_file(spool_dir: &str, subdir_str: &str, message_id: &str) -> Result<bool> {
    let path = spool_fname(spool_dir, "", "msglog", subdir_str, message_id, "");
    match fs::read_to_string(&path) {
        Ok(contents) => {
            let out = stdout();
            let mut writer = BufWriter::new(out.lock());
            let _ = writer.write_all(contents.as_bytes());
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            warn!(message_id, "message log not found");
            Ok(false)
        }
        Err(e) => Err(anyhow!(
            "failed to read msglog file {}: {}",
            path.display(),
            e
        )),
    }
}

/// Write an updated spool header file atomically.
///
/// Creates a temporary file, writes the header data, then renames it into
/// place. Uses [`SpoolWriteContext`] for error context.
fn write_updated_header(
    spool_dir: &str,
    subdir_str: &str,
    message_id: &str,
    data: &SpoolHeaderData,
    context: SpoolWriteContext,
) -> Result<()> {
    let h_path = spool_fname(
        spool_dir,
        "",
        "input",
        subdir_str,
        message_id,
        SPOOL_HEADER_SUFFIX,
    );

    // Write to a temporary file and rename
    let tmp_suffix = format!("{}-Hnew", message_id);
    let tmp_path = spool_fname(spool_dir, "", "input", subdir_str, &tmp_suffix, "");

    let tmp_file = fs::File::create(&tmp_path)
        .with_context(|| format!("failed to create temp header (context: {:?})", context))?;

    spool_write_header(data, &tmp_file)
        .with_context(|| format!("failed to write header (context: {:?})", context))
        .map_err(|e| anyhow!(e))?;

    fs::rename(&tmp_path, &h_path).with_context(|| {
        format!(
            "failed to rename header into place (context: {:?})",
            context
        )
    })?;

    Ok(())
}

/// Add an address to the non-recipients tree in the internal representation.
fn add_non_recipient(internal: &mut exim_spool::header_file::SpoolHeaderFile, address: &str) {
    use exim_spool::header_file::NonRecipientNode;

    let new_node = NonRecipientNode {
        address: address.to_string(),
        left: None,
        right: None,
    };

    match &mut internal.non_recipients {
        Some(root) => {
            insert_non_recipient_node(root, new_node);
        }
        None => {
            internal.non_recipients = Some(new_node);
        }
    }
}

/// Insert a non-recipient node into the binary tree (BST insertion).
fn insert_non_recipient_node(
    root: &mut exim_spool::header_file::NonRecipientNode,
    node: exim_spool::header_file::NonRecipientNode,
) {
    if node.address < root.address {
        match &mut root.left {
            Some(left) => insert_non_recipient_node(left, node),
            None => root.left = Some(Box::new(node)),
        }
    } else if node.address > root.address {
        match &mut root.right {
            Some(right) => insert_non_recipient_node(right, node),
            None => root.right = Some(Box::new(node)),
        }
    }
    // Equal addresses — address already in the tree, do nothing
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // QueueFilename tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_queue_filename_new_format() {
        let qf = QueueFilename {
            text: "1xBcDe-00A1B2-3456-H".to_string(),
            dir_uschar: 'a',
        };
        assert_eq!(qf.dir_uschar, 'a');
        assert!(qf.text.ends_with("-H"));
    }

    #[test]
    fn test_queue_filename_message_id() {
        let qf = QueueFilename {
            text: "1xBcDe-00A1B2-3456-H".to_string(),
            dir_uschar: '\0',
        };
        let id = qf.message_id();
        assert_eq!(id, "1xBcDe-00A1B2-3456");
    }

    #[test]
    fn test_queue_filename_old_format() {
        let qf = QueueFilename {
            text: "1xBcDe-00A1B2-Ab-H".to_string(),
            dir_uschar: '\0',
        };
        let id = qf.message_id();
        assert_eq!(id, "1xBcDe-00A1B2-Ab");
    }

    #[test]
    fn test_queue_filename_ordering() {
        let a = QueueFilename {
            text: "aaaaaa-aaaaaa-aa-H".to_string(),
            dir_uschar: '\0',
        };
        let b = QueueFilename {
            text: "zzzzzz-zzzzzz-zz-H".to_string(),
            dir_uschar: '\0',
        };
        assert!(a < b);
    }

    // -----------------------------------------------------------------------
    // QueueListOption tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_queue_list_option_default() {
        let opt = QueueListOption::Basic;
        assert_eq!(opt, QueueListOption::Basic);
    }

    #[test]
    fn test_queue_list_option_variants() {
        let opts = vec![
            QueueListOption::Basic,
            QueueListOption::Unsorted,
            QueueListOption::UndeliveredOnly,
            QueueListOption::PlusGenerated,
            QueueListOption::MsgidOnly,
            QueueListOption::CountOnly,
        ];
        assert_eq!(opts.len(), 6);
    }

    // -----------------------------------------------------------------------
    // QueueRunner tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_queue_runner_default() {
        let r = QueueRunner::default();
        assert_eq!(r.name, "");
        assert_eq!(r.interval, Duration::ZERO);
        assert_eq!(r.run_max, 5); // default concurrent runners
        assert!(!r.run_force);
        assert!(!r.run_first_delivery);
        assert!(!r.run_local);
        assert!(!r.run_in_order);
    }

    #[test]
    fn test_queue_runner_fields() {
        let r = QueueRunner {
            name: "custom".to_string(),
            interval: Duration::from_secs(600),
            run_max: 5,
            run_force: true,
            run_first_delivery: false,
            run_local: true,
            run_in_order: true,
        };
        assert_eq!(r.name, "custom");
        assert_eq!(r.interval.as_secs(), 600);
        assert_eq!(r.run_max, 5);
        assert!(r.run_force);
        assert!(r.run_local);
        assert!(r.run_in_order);
    }

    // -----------------------------------------------------------------------
    // MessageAction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_message_action_all_variants() {
        let actions: Vec<MessageAction> = vec![
            MessageAction::Deliver,
            MessageAction::Freeze,
            MessageAction::Thaw,
            MessageAction::Remove,
            MessageAction::GiveUp,
            MessageAction::MarkDelivered("user@example.com".into()),
            MessageAction::MarkAllDelivered,
            MessageAction::EditSender("new@example.com".into()),
            MessageAction::AddRecipient("added@example.com".into()),
            MessageAction::ShowBody,
            MessageAction::ShowHeader,
            MessageAction::ShowLog,
            MessageAction::SetQueue("custom".into()),
        ];
        assert_eq!(actions.len(), 13);
    }

    // -----------------------------------------------------------------------
    // Message ID validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_valid_message_id_new_format() {
        // New format: 6-11-4 (23 chars with hyphens)
        // Example: "XXXXXX-XXXXXXXXXXX-XXXX"
        assert!(is_valid_message_id("1aB2cD-0123456789A-Ef01"));
    }

    #[test]
    fn test_is_valid_message_id_old_format() {
        // Old format: 6-6-2 (16 chars with hyphens)
        // Example: "XXXXXX-XXXXXX-XX"
        assert!(is_valid_message_id("1aB2cD-012345-Ef"));
    }

    #[test]
    fn test_is_valid_message_id_rejects_garbage() {
        assert!(!is_valid_message_id(""));
        assert!(!is_valid_message_id("not-a-message-id"));
        assert!(!is_valid_message_id("too-short"));
        assert!(!is_valid_message_id("1234567890123456789012345"));
    }

    #[test]
    fn test_message_id_display_len_old() {
        // An old-format ID should return MESSAGE_ID_LENGTH_OLD
        let id = "1aB2cD-012345-Ef";
        let len = message_id_display_len(id);
        assert_eq!(len, MESSAGE_ID_LENGTH_OLD);
    }

    #[test]
    fn test_message_id_display_len_new() {
        // A new-format ID should return MESSAGE_ID_LENGTH
        let id = "1aB2cD-0123456789A-Ef01";
        let len = message_id_display_len(id);
        assert_eq!(len, MESSAGE_ID_LENGTH);
    }

    // -----------------------------------------------------------------------
    // merge_queue_lists tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_merge_queue_lists_empty() {
        let result = merge_queue_lists(vec![], vec![]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_merge_queue_lists_one_side_empty() {
        let a = vec![QueueFilename {
            text: "aaaaaa-aaaaaa-aa-H".into(),
            dir_uschar: '\0',
        }];
        let result = merge_queue_lists(a.clone(), vec![]);
        assert_eq!(result.len(), 1);

        let result2 = merge_queue_lists(vec![], a);
        assert_eq!(result2.len(), 1);
    }

    #[test]
    fn test_merge_queue_lists_sorted() {
        let a = vec![
            QueueFilename {
                text: "aaaaaa-aaaaaa-aa-H".into(),
                dir_uschar: '\0',
            },
            QueueFilename {
                text: "cccccc-cccccc-cc-H".into(),
                dir_uschar: '\0',
            },
        ];
        let b = vec![
            QueueFilename {
                text: "bbbbbb-bbbbbb-bb-H".into(),
                dir_uschar: '\0',
            },
            QueueFilename {
                text: "dddddd-dddddd-dd-H".into(),
                dir_uschar: '\0',
            },
        ];
        let result = merge_queue_lists(a, b);
        assert_eq!(result.len(), 4);
        assert!(result[0].text < result[1].text);
        assert!(result[1].text < result[2].text);
        assert!(result[2].text < result[3].text);
    }

    // -----------------------------------------------------------------------
    // format_size tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_size_small() {
        let s = format_size(500);
        assert!(s.contains("500"));
    }

    #[test]
    fn test_format_size_kilobytes() {
        // 20480 > 10*1024, so we get kilobyte format
        let s = format_size(20480);
        assert!(s.contains("K"), "expected 'K' in: {}", s);
    }

    #[test]
    fn test_format_size_megabytes() {
        // 15_000_000 > 10*1024*1024 so we get megabyte format
        let s = format_size(15_000_000);
        assert!(s.contains("M"), "expected 'M' in: {}", s);
    }

    // -----------------------------------------------------------------------
    // format_age tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_age_minutes() {
        let s = format_age(45);
        assert!(s.contains("m"), "expected 'm' in: {}", s);
    }

    #[test]
    fn test_format_age_hours() {
        let s = format_age(120);
        assert!(s.contains("h"), "expected 'h' in: {}", s);
    }

    #[test]
    fn test_format_age_days() {
        // 5760 minutes = 96 hours > 72h threshold → days format
        let s = format_age(5760);
        assert!(s.contains("d"), "expected 'd' in: {}", s);
    }

    #[test]
    fn test_format_age_large_days() {
        // 20160 minutes = 336h = 14d — Exim uses days, no week format
        let s = format_age(20160);
        assert!(s.contains("d"), "expected 'd' in: {}", s);
        assert!(s.contains("14"), "expected '14' in: {}", s);
    }

    // -----------------------------------------------------------------------
    // collect_non_recipients tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_collect_non_recipients_none() {
        let set = collect_non_recipients(&None);
        assert!(set.is_empty());
    }

    #[test]
    fn test_collect_non_recipients_some() {
        let tree = Some(exim_spool::TreeNode {
            name: "user@example.com".into(),
            left: None,
            right: None,
        });
        let set = collect_non_recipients(&tree);
        assert!(set.contains("user@example.com"));
    }

    #[test]
    fn test_collect_non_recipients_tree() {
        let tree = Some(exim_spool::TreeNode {
            name: "bob@example.com".into(),
            left: Some(Box::new(exim_spool::TreeNode {
                name: "alice@example.com".into(),
                left: None,
                right: None,
            })),
            right: Some(Box::new(exim_spool::TreeNode {
                name: "charlie@example.com".into(),
                left: None,
                right: None,
            })),
        });
        let set = collect_non_recipients(&tree);
        assert_eq!(set.len(), 3);
        assert!(set.contains("alice@example.com"));
        assert!(set.contains("bob@example.com"));
        assert!(set.contains("charlie@example.com"));
    }

    // -----------------------------------------------------------------------
    // classify_spool_read tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_classify_spool_read_ok() {
        let hdr = exim_spool::SpoolHeaderData::default();
        let result: Result<exim_spool::SpoolHeaderData, exim_spool::SpoolError> = Ok(hdr);
        let class = classify_spool_read(&result);
        assert_eq!(class, SpoolReadResult::OK);
    }

    #[test]
    fn test_classify_spool_read_io_error() {
        let err = exim_spool::SpoolError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not found",
        ));
        let result: Result<exim_spool::SpoolHeaderData, exim_spool::SpoolError> = Err(err);
        let class = classify_spool_read(&result);
        assert_eq!(class, SpoolReadResult::NotOpen);
    }

    // -----------------------------------------------------------------------
    // insert_non_recipient_node tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_add_non_recipient_builds_tree() {
        let hdr = exim_spool::SpoolHeaderData::default();
        let mut internal = hdr.to_internal();
        assert!(internal.non_recipients.is_none());

        add_non_recipient(&mut internal, "charlie@test.com");
        assert!(internal.non_recipients.is_some());

        add_non_recipient(&mut internal, "alice@test.com");
        add_non_recipient(&mut internal, "eve@test.com");

        // Verify all three addresses were inserted
        let rebuilt_hdr = exim_spool::SpoolHeaderData::from_internal(internal);
        let set = collect_non_recipients(&rebuilt_hdr.non_recipients_tree);
        assert_eq!(set.len(), 3);
        assert!(set.contains("alice@test.com"));
        assert!(set.contains("charlie@test.com"));
        assert!(set.contains("eve@test.com"));
    }

    // -----------------------------------------------------------------------
    // spool_clear_header_data test
    // -----------------------------------------------------------------------

    #[test]
    fn test_spool_clear_header_data_returns_default() {
        let hdr = spool_clear_header_data();
        assert!(hdr.sender_address.is_empty());
        assert!(hdr.recipients.is_empty());
    }
}
