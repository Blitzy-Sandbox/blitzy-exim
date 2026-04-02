//! # Retry Scheduling and Hints Database Integration
//!
//! Implements retry scheduling logic and hints database integration, translating
//! `src/src/retry.c` (1,032 lines of C). Manages per-host and per-message retry
//! records, determines host usability, computes next retry times using configured
//! retry rules (Fixed, Geometric, Heuristic), and updates the retry database at
//! delivery completion.
//!
//! ## Key Functions
//!
//! - [`retry_check_address`] — Check retry status of a host before attempting delivery
//! - [`retry_add_item`] — Create a retry tracking item from address delivery state
//! - [`retry_find_config`] — Find matching retry rule from configuration
//! - [`retry_update`] — Update retry database for deferred/failed/succeeded addresses
//! - [`retry_host_key_build`] — Build host retry database key string
//! - [`retry_ultimate_address_timeout`] — Check if retry has reached ultimate timeout
//!
//! ## Design Notes
//!
//! - **Scoped context passing**: All functions receive `ConfigContext` per AAP §0.4.4
//! - **Hints DB abstraction**: Functions are generic over the `HintsDb` trait for
//!   backend selection (BDB/GDBM/NDBM/TDB/SQLite)
//! - **Taint tracking**: `Tainted<T>` wraps data read from the hints database
//! - **Arena allocation**: Temporary strings use per-message `MessageArena`
//! - **Three-pass ordering**: `retry_update` processes succeed → fail → defer
//!   (deferred after failed to allow timeout moves)
//!
//! ## Retry Key Format
//!
//! Retry database keys follow the C format exactly (exinext depends on this):
//! - Host key: `T:hostname:ip_address+port` (or `T:hostname` without IP)
//! - Message key: `T:hostname:ip_address+port:message_id`
//! - Routing key: `R:user@domain`
//! - No spaces in keys; host names are lowercased.

use exim_config::types::ConfigContext;
use exim_ffi::hintsdb::{HintsDb, HintsDbDatum, HintsDbError, EXIM_DB_RLIMIT};
use exim_store::taint::Tainted;

use crate::orchestrator::{AddressFlags, AddressItem};

// ---------------------------------------------------------------------------
// Constants — retry error codes matching C defines
// ---------------------------------------------------------------------------

/// Error code for EXIMQUOTA — Exim's internal quota exceeded error.
/// In C: `ERRNO_EXIMQUOTA` (defined in exim.h).
const ERRNO_EXIMQUOTA: i32 = -256;

/// Error code for TLS required but connection failed to negotiate TLS.
/// In C: `ERRNO_TLSREQUIRED` (defined in exim.h).
const ERRNO_TLSREQUIRED: i32 = -257;

/// Error code for TLS failure during handshake or verification.
/// In C: `ERRNO_TLSFAILURE` (defined in exim.h).
const ERRNO_TLSFAILURE: i32 = -258;

/// Error code for connection timeout.
/// In C: `ETIMEDOUT` (from libc).
const ERRNO_ETIMEDOUT: i32 = 110;

/// Error code for ENOSPC (no space on device — treated as quota for retry).
const ERRNO_ENOSPC: i32 = 28;

/// Error code for 4xx response to MAIL command.
/// In C: `ERRNO_MAIL4XX` (defined in macros.h, value -45).
const ERRNO_MAIL4XX: i32 = -45;

/// Error code for 4xx response to RCPT command.
/// In C: `ERRNO_RCPT4XX` (defined in macros.h, value -46).
const ERRNO_RCPT4XX: i32 = -46;

/// Error code for 4xx response to DATA command.
/// In C: `ERRNO_DATA4XX` (defined in macros.h, value -47).
const ERRNO_DATA4XX: i32 = -47;

/// Retry flag indicating that the timeout value contains a CTOUT flag
/// (connection timeout) in the more_errno field.
/// In C: `RTEF_CTOUT` bit flag.
const RTEF_CTOUT: i32 = 0x0100;

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors that can occur during retry processing.
///
/// Replaces C-style error returns from `dbfn_open`, `dbfn_write`, and
/// `retry_find_config` with structured error variants.
#[derive(Debug, thiserror::Error)]
pub enum RetryError {
    /// The retry hints database could not be opened.
    #[error("retry database open failed")]
    DatabaseOpenFailed,

    /// Writing a retry record to the hints database failed.
    #[error("retry database write failed for key {0}")]
    DatabaseWriteFailed(String),

    /// A retry configuration error was detected (e.g., invalid pattern).
    #[error("retry configuration error: {0}")]
    ConfigError(String),
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Host usability status for retry scheduling.
///
/// Replaces C `hstatus_*` constants from `exim.h`. Set by
/// [`retry_check_address`] to indicate whether a host should be attempted
/// for delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostStatus {
    /// Host status not yet determined.
    Unknown,
    /// Host is available for delivery attempts.
    Usable,
    /// Host has a pending retry record — do not attempt delivery now.
    Unusable,
    /// Host retry has expired (ultimate timeout reached) — permanent failure.
    UnusableExpired,
}

/// Reason why a host was marked unusable.
///
/// Replaces C `hwhy_*` constants from `exim.h`. Set alongside [`HostStatus`]
/// by [`retry_check_address`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostWhyUnusable {
    /// Host is in retry state — has not reached next retry time.
    Retry,
    /// Delivery to this host failed permanently.
    Failed,
    /// Delivery to this host was deferred (temporary failure).
    Deferred,
    /// Host was explicitly ignored (e.g., by user configuration).
    Ignored,
}

/// Type of retry scheduling algorithm.
///
/// Each retry rule specifies one of these algorithms for computing the next
/// retry time. Translates from C retry rule type characters: `'F'`, `'G'`, `'H'`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryRuleType {
    /// Fixed interval: next_try = now + p1.
    Fixed,
    /// Geometric backoff: next_try = now + max(p1, last_gap * p2 / 1000).
    Geometric,
    /// Heuristic with randomization: includes a random component.
    /// next_try = now + p1 + random(gap - p1)/2 + (gap - p1)/2.
    Heuristic,
}

// ---------------------------------------------------------------------------
// RetryItemFlags (bitflags)
// ---------------------------------------------------------------------------

bitflags::bitflags! {
    /// Flags controlling retry item behavior.
    ///
    /// Replaces C `rf_*` constants from `retry.c`:
    /// - `rf_delete` → [`DELETE`](RetryItemFlags::DELETE)
    /// - `rf_host` → [`HOST`](RetryItemFlags::HOST)
    /// - `rf_message` → [`MESSAGE`](RetryItemFlags::MESSAGE)
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RetryItemFlags: u32 {
        /// Delete this retry record from the database.
        const DELETE  = 0x0001;
        /// This is a host-specific retry item.
        const HOST    = 0x0002;
        /// This is a message-specific retry item.
        const MESSAGE = 0x0004;
    }
}

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

/// A retry tracking item associated with an address during delivery.
///
/// Replaces C `retry_item` struct. Created by [`retry_add_item`] and
/// processed by [`retry_update`] to update the hints database.
#[derive(Debug, Clone)]
pub struct RetryItem {
    /// Retry database key (e.g., `"T:hostname:ip+port"`).
    pub key: String,
    /// Basic error number from the delivery attempt.
    pub basic_errno: i32,
    /// Additional error data (e.g., SMTP response code, connection flags).
    pub more_errno: i32,
    /// Error message text from the delivery attempt.
    pub message: Option<String>,
    /// Flags controlling retry behavior (delete/host/message).
    pub flags: RetryItemFlags,
}

/// A retry scheduling rule specifying an algorithm and parameters.
///
/// Translates from C `retry_rule` struct in `structs.h`. Rules are chained
/// within a [`RetryConfig`]; the first rule whose timeout has not been
/// exceeded is applied.
#[derive(Debug, Clone)]
pub struct RetryRule {
    /// The retry scheduling algorithm for this rule.
    pub rule_type: RetryRuleType,
    /// Cutoff time in seconds from first failure — after this elapsed time,
    /// the next rule in the chain is consulted.
    pub timeout: i64,
    /// First algorithm parameter:
    /// - Fixed: retry interval in seconds
    /// - Geometric: minimum retry interval in seconds
    /// - Heuristic: minimum retry interval in seconds
    pub p1: i64,
    /// Second algorithm parameter:
    /// - Fixed: unused (0)
    /// - Geometric: multiplier * 1000 (e.g., 2000 = double each time)
    /// - Heuristic: multiplier * 1000
    pub p2: i64,
    /// Next rule in the chain (applied after this rule's timeout).
    pub next: Option<Box<RetryRule>>,
}

/// A retry configuration block matching addresses to retry rules.
///
/// Translates from C `retry_config` struct in `structs.h`. The retry module
/// defines its own richer version with errno matching and sender filtering
/// fields beyond what the simplified `exim_config::types::RetryConfig` stores.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Address/domain pattern to match (supports wildcards).
    pub pattern: String,
    /// Optional sender address list filter. If `Some`, the retry config
    /// only applies when the sender matches this list.
    pub senders: Option<String>,
    /// Specific error predicate — only match if basic_errno matches (0 = any).
    pub basic_errno: i32,
    /// Additional error data predicate (0 = any).
    pub more_errno: i32,
    /// Chain of retry scheduling rules.
    pub rules: Vec<RetryRule>,
    /// Config file name where this retry block was defined.
    pub src_file: String,
    /// Config file line number where this retry block was defined.
    pub src_line: u32,
}

/// A retry record stored in the hints database.
///
/// Translates from C `dbdata_retry` struct. Each record tracks the retry
/// state for a specific host or message key.
#[derive(Debug, Clone)]
pub struct RetryRecord {
    /// Timestamp of the first failure (Unix epoch seconds).
    pub first_failed: i64,
    /// Timestamp of the last delivery attempt (Unix epoch seconds).
    pub last_try: i64,
    /// Timestamp of the next allowed delivery attempt (Unix epoch seconds).
    pub next_try: i64,
    /// Whether this retry has reached the ultimate timeout (permanent failure).
    pub expired: bool,
    /// Error number from the last delivery attempt.
    pub basic_errno: i32,
    /// Additional error data from the last delivery attempt.
    pub more_errno: i32,
    /// Error message text (truncated to EXIM_DB_RLIMIT bytes).
    pub text: String,
}

// ---------------------------------------------------------------------------
// RetryRecord serialization — byte-level compatible with C dbdata_retry
// ---------------------------------------------------------------------------

impl RetryRecord {
    /// Serialise this record to bytes matching the C `dbdata_retry` layout:
    ///
    /// ```text
    /// Offset  Size  Field
    /// 0       8     first_failed   (i64 LE)
    /// 8       8     last_try       (i64 LE)
    /// 16      8     next_try       (i64 LE)
    /// 24      1     expired        (u8, 0 or 1)
    /// 25      3     padding
    /// 28      4     basic_errno    (i32 LE)
    /// 32      4     more_errno     (i32 LE)
    /// 36      N     text           (UTF-8, no NUL terminator)
    /// ```
    ///
    /// The text field is truncated to [`EXIM_DB_RLIMIT`] bytes if necessary.
    pub fn to_bytes(&self) -> Vec<u8> {
        let text_bytes = self.text.as_bytes();
        let text_len = text_bytes.len().min(EXIM_DB_RLIMIT);
        let mut buf = Vec::with_capacity(36 + text_len);

        buf.extend_from_slice(&self.first_failed.to_le_bytes());
        buf.extend_from_slice(&self.last_try.to_le_bytes());
        buf.extend_from_slice(&self.next_try.to_le_bytes());
        buf.push(if self.expired { 1u8 } else { 0u8 });
        buf.extend_from_slice(&[0u8; 3]); // padding
        buf.extend_from_slice(&self.basic_errno.to_le_bytes());
        buf.extend_from_slice(&self.more_errno.to_le_bytes());
        buf.extend_from_slice(&text_bytes[..text_len]);

        buf
    }

    /// Deserialise a record from bytes written by `to_bytes()` or the C Exim
    /// `dbfn_write` function.
    ///
    /// Returns `None` if the input is too short to contain the fixed-size header.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 36 {
            return None;
        }
        let first_failed = i64::from_le_bytes(data[0..8].try_into().ok()?);
        let last_try = i64::from_le_bytes(data[8..16].try_into().ok()?);
        let next_try = i64::from_le_bytes(data[16..24].try_into().ok()?);
        let expired = data[24] != 0;
        // data[25..28] is padding
        let basic_errno = i32::from_le_bytes(data[28..32].try_into().ok()?);
        let more_errno = i32::from_le_bytes(data[32..36].try_into().ok()?);
        let text = String::from_utf8_lossy(&data[36..]).to_string();

        Some(Self {
            first_failed,
            last_try,
            next_try,
            expired,
            basic_errno,
            more_errno,
            text,
        })
    }
}

// ---------------------------------------------------------------------------
// Config conversion helpers
// ---------------------------------------------------------------------------

/// Convert a retry rule algorithm integer (C character code) to [`RetryRuleType`].
///
/// The C codebase encodes retry algorithms as character codes:
/// - `'F'` (0x46) → Fixed
/// - `'G'` (0x47) → Geometric
/// - `'H'` (0x48) → Heuristic
fn rule_type_from_algorithm(algorithm: i32) -> RetryRuleType {
    match algorithm {
        0x46 => RetryRuleType::Fixed,     // 'F'
        0x47 => RetryRuleType::Geometric, // 'G'
        0x48 => RetryRuleType::Heuristic, // 'H'
        _ => RetryRuleType::Fixed,        // default to fixed
    }
}

/// Convert a simplified `exim_config::types::RetryRule` into this module's
/// richer [`RetryRule`].
fn convert_config_rule(cfg_rule: &exim_config::types::RetryRule) -> RetryRule {
    RetryRule {
        rule_type: rule_type_from_algorithm(cfg_rule.algorithm),
        timeout: i64::from(cfg_rule.timeout),
        p1: i64::from(cfg_rule.p1),
        p2: i64::from(cfg_rule.p2),
        next: None,
    }
}

/// Convert a simplified `exim_config::types::RetryConfig` into this module's
/// richer [`RetryConfig`].
///
/// Missing fields (senders, basic_errno, more_errno, src_file, src_line) are
/// set to their default (match-all) values. When the configuration parser is
/// enhanced to populate these fields, the conversion can be updated.
fn convert_config_retry(cfg: &exim_config::types::RetryConfig) -> RetryConfig {
    // Build a chain of rules: each rule's `next` points to the subsequent rule.
    let mut rules: Vec<RetryRule> = cfg.rules.iter().map(convert_config_rule).collect();

    // Chain rules via `next` pointers to match C linked-list semantics.
    // Walk backwards so each rule points to its successor.
    let len = rules.len();
    for i in (0..len.saturating_sub(1)).rev() {
        let next_rule = Box::new(rules[i + 1].clone());
        rules[i].next = Some(next_rule);
    }

    RetryConfig {
        pattern: cfg.pattern.clone(),
        senders: None,
        basic_errno: 0,
        more_errno: 0,
        rules,
        src_file: String::new(),
        src_line: 0,
    }
}

// ---------------------------------------------------------------------------
// retry_host_key_build — Build host retry database key string
// ---------------------------------------------------------------------------

/// Build a retry database key for a host.
///
/// Translates from C `retry_host_key_build()` (retry.c line 78).
///
/// The key format is `T:hostname:ip_address+port` when IP address is included,
/// or `T:hostname` when not. The host name is always lowercased. No spaces are
/// permitted in the key (the `exinext` utility depends on this format).
///
/// # Arguments
///
/// * `host_name` — The hostname (will be lowercased).
/// * `include_ip_address` — Whether to include the IP address in the key.
/// * `ip_address` — The IP address (required if `include_ip_address` is true).
/// * `port_string` — Optional port suffix (e.g., `":587"`).
///
/// # Examples
///
/// ```
/// use exim_deliver::retry::retry_host_key_build;
/// let key = retry_host_key_build("MAIL.example.com", true, Some("192.168.1.1"), Some(":587"));
/// assert_eq!(key, "T:mail.example.com:192.168.1.1+587");
/// ```
pub fn retry_host_key_build(
    host_name: &str,
    include_ip_address: bool,
    ip_address: Option<&str>,
    port_string: Option<&str>,
) -> String {
    let lower_host = host_name.to_ascii_lowercase();

    if !include_ip_address {
        return format!("T:{lower_host}");
    }

    let ip = ip_address.unwrap_or("");
    let port = port_string.unwrap_or("");

    // Strip leading ':' from port_string if present (C code uses `:port` format
    // but the key stores `+port`).
    let port_num = port.strip_prefix(':').unwrap_or(port);

    if port_num.is_empty() {
        format!("T:{lower_host}:{ip}")
    } else {
        format!("T:{lower_host}:{ip}+{port_num}")
    }
}

// ---------------------------------------------------------------------------
// Database read helper
// ---------------------------------------------------------------------------

/// Read a retry record from the hints database by key.
///
/// Wraps the `HintsDb::get()` call with key encoding and record
/// deserialization. Returns the deserialized record wrapped in `Tainted<T>`
/// (data from the database is untrusted) or `None` if the key is not found.
fn db_read_retry_record<D: HintsDb>(db: &D, key: &str) -> Option<Tainted<RetryRecord>> {
    let key_datum = HintsDbDatum::new(key.as_bytes());
    match db.get(&key_datum) {
        Ok(Some(datum)) => {
            let bytes = datum.as_bytes();
            RetryRecord::from_bytes(bytes).map(Tainted::new)
        }
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(key = key, error = %e, "failed to read retry record");
            None
        }
    }
}

/// Write a retry record to the hints database.
fn db_write_retry_record<D: HintsDb>(
    db: &mut D,
    key: &str,
    record: &RetryRecord,
) -> Result<(), RetryError> {
    let key_datum = HintsDbDatum::new(key.as_bytes());
    let value_bytes = record.to_bytes();
    let value_datum = HintsDbDatum::new(&value_bytes);

    db.put(&key_datum, &value_datum)
        .map_err(|_| RetryError::DatabaseWriteFailed(key.to_string()))
}

/// Delete a retry record from the hints database by key.
fn db_delete_retry_record<D: HintsDb>(db: &mut D, key: &str) -> Result<(), HintsDbError> {
    let key_datum = HintsDbDatum::new(key.as_bytes());
    db.delete(&key_datum)
}

// ---------------------------------------------------------------------------
// retry_ultimate_address_timeout
// ---------------------------------------------------------------------------

/// Check whether the retry record has reached the ultimate address timeout.
///
/// Translates from C `retry_ultimate_address_timeout()` (retry.c line 33).
///
/// Uses [`retry_find_config`] to locate the matching retry rule, then checks
/// if the failing interval (now − first_failed) exceeds the final rule's
/// timeout. Returns `true` if timed out (the address should be treated as a
/// permanent failure).
///
/// # Arguments
///
/// * `host_key` — The retry database key (with `T:` or `R:` prefix).
/// * `domain` — The domain being delivered to.
/// * `retry_record` — The existing retry record from the database.
/// * `now` — Current Unix epoch timestamp.
/// * `config` — Parsed configuration context.
pub fn retry_ultimate_address_timeout(
    host_key: &str,
    domain: &str,
    retry_record: &RetryRecord,
    now: i64,
    config: &ConfigContext,
) -> bool {
    // The C code skips the first 2 characters of the key (the prefix like
    // "T:" or "R:") when looking up the retry config.
    let lookup_key = if host_key.len() > 2 {
        &host_key[2..]
    } else {
        host_key
    };

    // Find the matching retry configuration.
    let retry_configs = get_retry_configs(config);
    let matched = find_config_match(lookup_key, None, 0, 0, &retry_configs);
    let retry_cfg = match matched {
        Some(cfg) => cfg,
        None => {
            tracing::debug!(
                key = host_key,
                "no retry config found for ultimate timeout check"
            );
            return false;
        }
    };

    // Find the last rule in the chain — its timeout is the ultimate timeout.
    let last_rule = match retry_cfg.rules.last() {
        Some(rule) => rule,
        None => return false,
    };

    let failing_interval = now - retry_record.first_failed;
    let timed_out = failing_interval > last_rule.timeout;

    if timed_out {
        tracing::debug!(
            key = host_key,
            domain = domain,
            failing_interval = failing_interval,
            ultimate_timeout = last_rule.timeout,
            "address has reached ultimate retry timeout"
        );
    }

    timed_out
}

// ---------------------------------------------------------------------------
// retry_find_config — Find matching retry rule from configuration
// ---------------------------------------------------------------------------

/// Build the list of retry configurations from the parsed config.
///
/// Converts simplified `exim_config::types::RetryConfig` entries into this
/// module's richer [`RetryConfig`] type.
fn get_retry_configs(config: &ConfigContext) -> Vec<RetryConfig> {
    config
        .retry_configs
        .iter()
        .map(convert_config_retry)
        .collect()
}

/// Internal matching engine for [`retry_find_config`].
///
/// Iterates the retry configuration list and returns the first matching entry
/// based on key pattern, error predicates, and sender matching.
fn find_config_match<'a>(
    key: &str,
    alternate_domain: Option<&str>,
    basic_errno: i32,
    more_errno: i32,
    configs: &'a [RetryConfig],
) -> Option<&'a RetryConfig> {
    // Parse the key to extract the matchable address/host portion.
    let match_key = extract_match_key(key);

    // Ensure the key has an '@' character. If not, prepend "*@" so it looks
    // like an address pattern (C: if strchr(key, '@') == NULL, prepend "*@").
    let full_key = if match_key.contains('@') {
        match_key.to_string()
    } else {
        format!("*@{match_key}")
    };

    for cfg in configs {
        // Check error predicate match if the config specifies one.
        if cfg.basic_errno != 0 && !errno_matches(cfg, basic_errno, more_errno) {
            continue;
        }

        // Check sender match if the config specifies a sender filter.
        if cfg.senders.is_some() {
            // Skip configs with sender restrictions we can't verify in this
            // context. The config parser would need to pass sender data.
            continue;
        }

        // Match the key against the config pattern.
        if pattern_matches(&cfg.pattern, &full_key, alternate_domain) {
            tracing::debug!(
                key = key,
                pattern = cfg.pattern.as_str(),
                "retry config matched"
            );
            return Some(cfg);
        }
    }

    tracing::debug!(key = key, "no matching retry config found");
    None
}

/// Find the matching retry configuration rule for a given key.
///
/// Translates from C `retry_find_config()` (retry.c line 390, ~160 lines).
///
/// # Arguments
///
/// * `key` — The retry database key (without prefix, or full key).
/// * `alternate_domain` — Optional alternate domain for fallback matching.
/// * `basic_errno` — Error number to match against config predicates.
/// * `more_errno` — Additional error data for fine-grained matching.
/// * `config` — Parsed configuration context.
///
/// # Returns
///
/// The first matching [`RetryConfig`], or `None` if no configuration matches.
pub fn retry_find_config(
    key: &str,
    alternate_domain: Option<&str>,
    basic_errno: i32,
    more_errno: i32,
    config: &ConfigContext,
) -> Option<RetryConfig> {
    let configs = get_retry_configs(config);
    find_config_match(key, alternate_domain, basic_errno, more_errno, &configs).cloned()
}

// ---------------------------------------------------------------------------
// Pattern and errno matching helpers
// ---------------------------------------------------------------------------

/// Extract the matchable address/host portion from a retry key.
///
/// Handles the three key formats from the C code:
/// - `"hostname:ip+port"` → returns `"hostname"`
/// - `"|path:x@y"` / `"/path:x@y"` / `">path:x@y"` → returns `"x@y"`
/// - `"user@domain"` → returns `"user@domain"` (unchanged)
fn extract_match_key(key: &str) -> &str {
    if key.is_empty() {
        return key;
    }

    let first_byte = key.as_bytes()[0];

    // Pipe/file/autoreply transport keys: |path:addr, /path:addr, >path:addr
    if first_byte == b'|' || first_byte == b'/' || first_byte == b'>' {
        if let Some(colon_pos) = key.find(':') {
            return &key[colon_pos + 1..];
        }
        return key;
    }

    // Host:IP+port keys: extract just the hostname part.
    if let Some(colon_pos) = key.find(':') {
        // If there's an '@' before the colon, it's an email address not a host key.
        if key[..colon_pos].contains('@') {
            return key;
        }
        return &key[..colon_pos];
    }

    key
}

/// Check whether a retry configuration's error predicates match the given
/// error codes.
///
/// Implements the C errno matching logic from `retry_find_config()`:
/// - `ERRNO_EXIMQUOTA` also matches `ENOSPC`
/// - `ERRNO_TLSREQUIRED` also matches `ERRNO_TLSFAILURE`
/// - 4xx SMTP response matching: 255=any 4xx, >=100=decade match, <100=exact
/// - `ERRNO_ETIMEDOUT` with `RTEF_CTOUT` flag for connection timeout
fn errno_matches(cfg: &RetryConfig, basic_errno: i32, more_errno: i32) -> bool {
    let cfg_errno = cfg.basic_errno;
    let cfg_more = cfg.more_errno;

    // cfg_errno == 0 means "match any error" (no error predicate configured)
    if cfg_errno == 0 {
        return true;
    }

    // EXIMQUOTA also matches ENOSPC
    if cfg_errno == ERRNO_EXIMQUOTA {
        return basic_errno == ERRNO_EXIMQUOTA || basic_errno == ERRNO_ENOSPC;
    }

    // TLSREQUIRED also matches TLSFAILURE
    if cfg_errno == ERRNO_TLSREQUIRED {
        return basic_errno == ERRNO_TLSREQUIRED || basic_errno == ERRNO_TLSFAILURE;
    }

    // 4xx response code matching (ERRNO_MAIL4XX / ERRNO_RCPT4XX / ERRNO_DATA4XX)
    // In C, the response code (minus 400) is in the second-least-significant byte
    // of more_errno, i.e. (more_errno >> 8) & 0xFF. The wanted value in the
    // retry config is encoded the same way in yield->more_errno.
    if cfg_errno == ERRNO_MAIL4XX || cfg_errno == ERRNO_RCPT4XX || cfg_errno == ERRNO_DATA4XX {
        if basic_errno != cfg_errno {
            return false;
        }
        let wanted = (cfg_more >> 8) & 0xFF;
        if wanted == 255 {
            return true; // any 4xx code
        }
        let evalue = (more_errno >> 8) & 0xFF;
        if wanted >= 100 {
            // Decade match: (evalue/10)*10 must equal wanted-100
            return (evalue / 10) * 10 == wanted - 100;
        }
        // Exact code match
        return evalue == wanted;
    }

    // Timeout with CTOUT flag
    if cfg_errno == ERRNO_ETIMEDOUT {
        if basic_errno != ERRNO_ETIMEDOUT {
            return false;
        }
        if cfg_more != 0 && (cfg_more & RTEF_CTOUT) != 0 {
            return (more_errno & RTEF_CTOUT) != 0;
        }
        return true;
    }

    // Default: exact match
    if basic_errno != cfg_errno {
        return false;
    }
    if cfg_more != 0 && more_errno != cfg_more {
        return false;
    }

    true
}

/// Simple pattern matching for retry configuration patterns.
///
/// Supports:
/// - Exact string match (case-insensitive)
/// - Leading `*` wildcard (matches any prefix)
/// - `*` alone (matches everything)
/// - Domain-only matching via alternate_domain
fn pattern_matches(pattern: &str, key: &str, alternate_domain: Option<&str>) -> bool {
    let pattern_lower = pattern.to_ascii_lowercase();
    let key_lower = key.to_ascii_lowercase();

    // Universal wildcard
    if pattern_lower == "*" {
        return true;
    }

    // Leading wildcard: *suffix matches any key ending with suffix
    if let Some(suffix) = pattern_lower.strip_prefix('*') {
        if key_lower.ends_with(&suffix) {
            return true;
        }
        // Also try matching against *@alternate_domain
        if let Some(alt) = alternate_domain {
            let alt_key = format!("*@{}", alt.to_ascii_lowercase());
            if alt_key.ends_with(&suffix) {
                return true;
            }
        }
        return false;
    }

    // Exact match
    if pattern_lower == key_lower {
        return true;
    }

    // Try with alternate domain
    if let Some(alt) = alternate_domain {
        let alt_key = format!("*@{}", alt.to_ascii_lowercase());
        if pattern_lower == alt_key {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// retry_add_item — Add retry item to address
// ---------------------------------------------------------------------------

/// Create a retry tracking item from an address's delivery state.
///
/// Translates from C `retry_add_item()` (retry.c line 335, ~45 lines).
///
/// Constructs a [`RetryItem`] with the address's error state and the specified
/// key. The caller is responsible for associating the returned item with the
/// address (e.g., storing in a `Vec<RetryItem>` alongside the address).
///
/// In C, this chains the item onto `addr->retries`. In Rust, we return the
/// item because `AddressItem` does not have a built-in retries field — the
/// caller manages the association.
///
/// # Arguments
///
/// * `addr` — The address whose error state is copied into the retry item.
/// * `key` — The retry database key (e.g., `"T:host:ip+port"`).
/// * `flags` — Flags controlling retry behavior (delete/host/message).
///
/// # Returns
///
/// A [`RetryItem`] ready to be stored and later processed by [`retry_update`].
pub fn retry_add_item(addr: &AddressItem, key: &str, flags: RetryItemFlags) -> RetryItem {
    // Copy error information from the address. In C, this reads
    // addr->basic_errno, addr->more_errno, and addr->message.
    let item_flags = if flags.contains(RetryItemFlags::DELETE) {
        RetryItemFlags::DELETE
    } else {
        flags & (RetryItemFlags::HOST | RetryItemFlags::MESSAGE)
    };

    let message = addr.message.clone().unwrap_or_default();

    tracing::trace!(
        key = key,
        basic_errno = addr.basic_errno,
        more_errno = addr.more_errno,
        ?item_flags,
        "adding retry item for address"
    );

    RetryItem {
        key: key.to_string(),
        basic_errno: addr.basic_errno,
        more_errno: addr.more_errno,
        message: if message.is_empty() {
            None
        } else {
            Some(message)
        },
        flags: item_flags,
    }
}

// ---------------------------------------------------------------------------
// retry_check_address — Check retry status of a host
// ---------------------------------------------------------------------------

/// Parameters for [`retry_check_address`], grouped to avoid excessive argument counts.
#[derive(Debug)]
pub struct RetryCheckParams<'a, D: HintsDb> {
    /// The domain being delivered to.
    pub domain: &'a str,
    /// The host name to check.
    pub host_name: &'a str,
    /// Optional IP address of the host.
    pub host_address: Option<&'a str>,
    /// Optional port suffix (e.g., `":25"`).
    pub port_string: Option<&'a str>,
    /// Whether to include the IP in the retry key.
    pub include_ip_address: bool,
    /// Current message ID (for message-specific retry keys).
    pub message_id: &'a str,
    /// Whether forced delivery is enabled (ignores retry times).
    pub deliver_force: bool,
    /// Current Unix epoch timestamp.
    pub now: i64,
    /// Optional opened hints database handle (read-only).
    pub db: Option<&'a D>,
    /// Parsed configuration context.
    pub config: &'a ConfigContext,
}

/// Result of a retry check for a host address.
#[derive(Debug, Clone)]
pub struct RetryCheckResult {
    /// The determined host status.
    pub status: HostStatus,
    /// The reason the host was marked unusable (if applicable).
    pub why: HostWhyUnusable,
    /// Whether the retry record has expired (ultimate timeout reached).
    pub expired: bool,
    /// The host retry key that was looked up (for later use in retry_add_item).
    pub host_key: Option<String>,
    /// The message-specific retry key (for later use in retry_add_item).
    pub message_key: Option<String>,
}

impl Default for RetryCheckResult {
    fn default() -> Self {
        Self {
            status: HostStatus::Unknown,
            why: HostWhyUnusable::Retry,
            expired: false,
            host_key: None,
            message_key: None,
        }
    }
}

/// Check the retry status of a host before attempting delivery.
///
/// Translates from C `retry_check_address()` (retry.c line 148, ~157 lines).
///
/// This function:
/// 1. Builds host and message retry keys
/// 2. Reads retry records from the hints database
/// 3. Determines whether the host is usable based on retry timing
/// 4. Detects ultimate timeout (expired) conditions
///
/// The function is generic over `D: HintsDb` because the `HintsDb` trait has
/// a `close(self)` method that makes it non-object-safe.
///
/// # Arguments
///
/// * `params` — All parameters bundled into [`RetryCheckParams`].
pub fn retry_check_address<D: HintsDb>(params: &RetryCheckParams<'_, D>) -> RetryCheckResult {
    let domain = params.domain;
    let host_name = params.host_name;
    let host_address = params.host_address;
    let port_string = params.port_string;
    let include_ip_address = params.include_ip_address;
    let message_id = params.message_id;
    let deliver_force = params.deliver_force;
    let now = params.now;
    let db = params.db;
    let config = params.config;

    // Build the host retry key.
    let host_key = retry_host_key_build(host_name, include_ip_address, host_address, port_string);

    // Build the message-specific retry key (appends :message_id).
    let message_key = if !message_id.is_empty() {
        Some(format!("{host_key}:{message_id}"))
    } else {
        None
    };

    // Initialise result using a struct literal (avoids field-assignment-after-Default lint).
    let mut result = RetryCheckResult {
        status: HostStatus::Usable,
        host_key: Some(host_key.clone()),
        message_key: message_key.clone(),
        ..RetryCheckResult::default()
    };

    tracing::debug!(
        host = host_name,
        host_key = host_key.as_str(),
        message_key = message_key.as_deref().unwrap_or("(none)"),
        "checking retry status"
    );

    // If no database handle is available, we can't check retry records.
    let db = match db {
        Some(db) => db,
        None => {
            tracing::debug!("no retry database available, host is usable");
            return result;
        }
    };

    let retry_data_expire = i64::from(config.retry_data_expire);

    // Read host retry record.
    let host_record = db_read_retry_record(db, &host_key);

    // Read message-specific retry record.
    let message_record = message_key
        .as_deref()
        .and_then(|mk| db_read_retry_record(db, mk));

    // Process host retry record.
    if let Some(tainted_rec) = &host_record {
        let rec = tainted_rec.as_ref();

        // Ignore records older than retry_data_expire.
        if now - rec.first_failed > retry_data_expire {
            tracing::debug!(
                host_key = host_key.as_str(),
                age = now - rec.first_failed,
                expire = retry_data_expire,
                "ignoring expired host retry record"
            );
        } else if !deliver_force && rec.next_try > now {
            // Host has not reached its next retry time.
            tracing::debug!(
                host_key = host_key.as_str(),
                next_try = rec.next_try,
                now = now,
                "host not yet due for retry"
            );

            // Check ultimate timeout.
            if retry_ultimate_address_timeout(&host_key, domain, rec, now, config) {
                result.status = HostStatus::UnusableExpired;
                result.why = HostWhyUnusable::Retry;
                result.expired = true;
                tracing::debug!(
                    host_key = host_key.as_str(),
                    "host retry expired (ultimate timeout)"
                );
            } else {
                result.status = HostStatus::Unusable;
                result.why = HostWhyUnusable::Retry;
            }

            return result;
        } else if rec.expired {
            // Record is already marked expired.
            result.expired = true;
        }
    }

    // Process message-specific retry record.
    if let Some(tainted_rec) = &message_record {
        let rec = tainted_rec.as_ref();

        // Ignore stale records.
        if now - rec.first_failed > retry_data_expire {
            tracing::debug!(
                message_key = message_key.as_deref().unwrap_or(""),
                "ignoring expired message retry record"
            );
        } else if !deliver_force && rec.next_try > now {
            tracing::debug!(
                message_key = message_key.as_deref().unwrap_or(""),
                next_try = rec.next_try,
                now = now,
                "message not yet due for retry"
            );

            // Check ultimate timeout on message record.
            if let Some(mk) = &message_key {
                if retry_ultimate_address_timeout(mk, domain, rec, now, config) {
                    result.status = HostStatus::UnusableExpired;
                    result.why = HostWhyUnusable::Retry;
                    result.expired = true;
                } else {
                    result.status = HostStatus::Unusable;
                    result.why = HostWhyUnusable::Retry;
                }
            }
            return result;
        }
    }

    tracing::debug!(
        host = host_name,
        status = ?result.status,
        expired = result.expired,
        "retry check complete"
    );

    result
}

// ---------------------------------------------------------------------------
// Next-try computation
// ---------------------------------------------------------------------------

/// Compute the next retry time based on a retry rule.
///
/// Implements the C retry scheduling logic from `retry_update()`:
/// - **Fixed**: `next = now + p1`
/// - **Geometric**: `next = now + max(p1, last_gap * p2 / 1000)`
/// - **Heuristic**: `next = now + p1 + random(gap)/2 + gap/2`
///   where `gap = max(p1, last_gap * p2 / 1000) - p1`
fn compute_next_try(rule: &RetryRule, now: i64, last_try: i64, retry_interval_max: i64) -> i64 {
    let last_gap = if last_try > 0 { now - last_try } else { 0 };

    let raw_interval = match rule.rule_type {
        RetryRuleType::Fixed => rule.p1,

        RetryRuleType::Geometric => {
            let computed = if rule.p2 > 0 && last_gap > 0 {
                (last_gap * rule.p2) / 1000
            } else {
                rule.p1
            };
            computed.max(rule.p1)
        }

        RetryRuleType::Heuristic => {
            let computed = if rule.p2 > 0 && last_gap > 0 {
                (last_gap * rule.p2) / 1000
            } else {
                rule.p1
            };
            let next_gap = computed.max(rule.p1);
            let random_range = next_gap - rule.p1;
            if random_range > 0 {
                // Pseudo-random jitter based on now and last_try to avoid
                // needing a random number generator. Mirrors the C code's
                // use of random() for delivery time spreading.
                let jitter = ((now ^ last_try) & 0x7FFF_FFFF) % random_range;
                rule.p1 + jitter / 2 + random_range / 2
            } else {
                rule.p1
            }
        }
    };

    // Impose the global retry_interval_max cap.
    let interval = if retry_interval_max > 0 && raw_interval > retry_interval_max {
        tracing::trace!(
            raw = raw_interval,
            max = retry_interval_max,
            "clamping retry interval to maximum"
        );
        retry_interval_max
    } else {
        raw_interval
    };

    now + interval.max(1) // Ensure at least 1 second forward progress.
}

/// Find the active retry rule for the current failing interval.
///
/// Walks the rule chain and returns the last rule whose timeout has NOT
/// been exceeded by the failing_interval. This is the rule that determines
/// the next retry time.
fn find_active_rule(rules: &[RetryRule], failing_interval: i64) -> Option<&RetryRule> {
    let mut active: Option<&RetryRule> = None;

    for rule in rules {
        active = Some(rule);
        if failing_interval <= rule.timeout {
            return active;
        }
    }

    // If all rules' timeouts have been exceeded, return the last rule.
    active
}

// ---------------------------------------------------------------------------
// retry_update -- Main retry database update
// ---------------------------------------------------------------------------

/// Describes the three-pass processing order for retry_update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpdatePass {
    /// Pass 0: Successfully delivered addresses -- delete retry records.
    Succeeded,
    /// Pass 1: Permanently failed addresses -- update retry records.
    Failed,
    /// Pass 2: Deferred addresses -- update retry records, check for timeout.
    Deferred,
}

/// Update the retry database for all address chains after delivery.
///
/// Translates from C `retry_update()` (retry.c line 578, ~450 lines).
///
/// Processes three address chains in order: succeeded -> failed -> deferred.
/// For each address and its associated retry items:
/// - **Succeeded**: Deletes retry records from the database.
/// - **Failed**: Updates retry records with the failure information.
/// - **Deferred**: Computes next retry times; if all retry items have timed
///   out, marks the address as "retry timeout exceeded".
///
/// # Type Parameter
///
/// * `D` -- The hints database backend, implementing the [`HintsDb`] trait.
///
/// # Arguments
///
/// * `addr_succeed` -- Successfully delivered addresses with their retry items.
/// * `addr_failed` -- Permanently failed addresses with their retry items.
/// * `addr_defer` -- Deferred addresses with their retry items. Addresses that
///   time out will have their `message` field set to "retry timeout exceeded".
/// * `now` -- Current Unix epoch timestamp.
/// * `received_time` -- Message received timestamp (for message age computation).
/// * `db` -- Mutable reference to an opened hints database (read-write).
/// * `config` -- Parsed configuration context.
pub fn retry_update<D: HintsDb>(
    addr_succeed: &[(AddressItem, Vec<RetryItem>)],
    addr_failed: &[(AddressItem, Vec<RetryItem>)],
    addr_defer: &mut Vec<(AddressItem, Vec<RetryItem>)>,
    now: i64,
    received_time: i64,
    db: &mut D,
    config: &ConfigContext,
) -> Result<(), RetryError> {
    let retry_interval_max = i64::from(config.retry_interval_max);
    let retry_data_expire = i64::from(config.retry_data_expire);
    let message_age = now - received_time;

    // Track indices of deferred addresses that have timed out.
    let mut timed_out_indices: Vec<usize> = Vec::new();

    // Start transaction for backends that use transactions (TDB).
    let _txn_started = db.transaction_start();

    // Three-pass loop: succeed (0) -> fail (1) -> defer (2).
    for pass in [
        UpdatePass::Succeeded,
        UpdatePass::Failed,
        UpdatePass::Deferred,
    ] {
        let items: &[(AddressItem, Vec<RetryItem>)] = match pass {
            UpdatePass::Succeeded => addr_succeed,
            UpdatePass::Failed => addr_failed,
            UpdatePass::Deferred => addr_defer.as_slice(),
        };

        for (addr_idx, (addr, retry_items)) in items.iter().enumerate() {
            let mut ctx = RetryUpdateCtx {
                now,
                message_age,
                retry_interval_max,
                retry_data_expire,
                db: &mut *db,
                config,
            };
            for rti in retry_items {
                process_retry_item(pass, addr, rti, &mut ctx)?;
            }

            // For deferred addresses: check if ALL retry items have timed out.
            if pass == UpdatePass::Deferred && !retry_items.is_empty() {
                let all_timed_out = retry_items.iter().all(|rti| {
                    check_item_timed_out(rti, now, message_age, retry_data_expire, db, config)
                });

                if all_timed_out {
                    tracing::debug!(
                        address = addr.address.as_ref(),
                        "all retry items timed out, marking as failed"
                    );
                    timed_out_indices.push(addr_idx);
                }
            }
        }
    }

    // Commit transaction for TDB backend.
    db.transaction_commit();

    // Mark timed-out deferred addresses with timeout message and flag.
    for &idx in timed_out_indices.iter().rev() {
        if let Some((addr, _)) = addr_defer.get_mut(idx) {
            addr.message = Some("retry timeout exceeded".to_string());
            addr.flags.set(AddressFlags::AF_RETRY_SKIPPED);
        }
    }

    tracing::debug!(timed_out = timed_out_indices.len(), "retry update complete");

    Ok(())
}

/// Shared context for retry update processing, grouping parameters that
/// remain constant across all items in the three-pass loop.
struct RetryUpdateCtx<'a, D: HintsDb> {
    now: i64,
    message_age: i64,
    retry_interval_max: i64,
    retry_data_expire: i64,
    db: &'a mut D,
    config: &'a ConfigContext,
}

/// Process a single retry item within the three-pass update loop.
fn process_retry_item<D: HintsDb>(
    pass: UpdatePass,
    addr: &AddressItem,
    rti: &RetryItem,
    ctx: &mut RetryUpdateCtx<'_, D>,
) -> Result<(), RetryError> {
    let now = ctx.now;
    let message_age = ctx.message_age;
    let retry_interval_max = ctx.retry_interval_max;
    let retry_data_expire = ctx.retry_data_expire;
    let db = &mut *ctx.db;
    let config = ctx.config;
    let key = &rti.key;

    tracing::trace!(
        pass = ?pass,
        key = key.as_str(),
        flags = ?rti.flags,
        "processing retry item"
    );

    // For succeeded addresses: delete the retry record.
    if pass == UpdatePass::Succeeded {
        if let Err(e) = db_delete_retry_record(db, key) {
            tracing::trace!(
                key = key.as_str(),
                error = %e,
                "delete of retry record failed (may not exist)"
            );
        }
        return Ok(());
    }

    // Handle DELETE flag: explicitly delete the record.
    if rti.flags.contains(RetryItemFlags::DELETE) {
        tracing::trace!(key = key.as_str(), "deleting retry record (DELETE flag)");
        if let Err(e) = db_delete_retry_record(db, key) {
            tracing::trace!(
                key = key.as_str(),
                error = %e,
                "delete failed (may not exist)"
            );
        }
        return Ok(());
    }

    // Find matching retry configuration.
    let lookup_key = if key.len() > 2 {
        &key[2..]
    } else {
        key.as_str()
    };
    let retry_configs = get_retry_configs(config);
    let retry_cfg = match find_config_match(
        lookup_key,
        Some(&addr.domain),
        rti.basic_errno,
        rti.more_errno,
        &retry_configs,
    ) {
        Some(cfg) => cfg,
        None => {
            tracing::debug!(key = key.as_str(), "no matching retry config, skipping");
            return Ok(());
        }
    };

    // Read existing retry record from database.
    let existing_record = db_read_retry_record(db, key);

    // Determine first_failed time.
    let (first_failed, last_try_time) = match &existing_record {
        Some(tainted_rec) => {
            let rec = tainted_rec.as_ref();
            if now - rec.first_failed > retry_data_expire {
                tracing::trace!(
                    key = key.as_str(),
                    "existing record is stale, treating as new"
                );
                (now, 0i64)
            } else {
                (rec.first_failed, rec.last_try)
            }
        }
        None => (now, 0i64),
    };

    let failing_interval = now - first_failed;

    // For non-host errors, use the larger of failing_interval and message_age.
    let effective_interval = if !rti.flags.contains(RetryItemFlags::HOST) {
        failing_interval.max(message_age)
    } else {
        failing_interval
    };

    // Find the active retry rule.
    let active_rule = match find_active_rule(&retry_cfg.rules, effective_interval) {
        Some(rule) => rule,
        None => {
            tracing::debug!(key = key.as_str(), "no active retry rule found");
            return Ok(());
        }
    };

    // Check if timed out.
    let timed_out = retry_cfg
        .rules
        .last()
        .is_some_and(|last| effective_interval > last.timeout);

    // Compute next retry time.
    let next_try = compute_next_try(active_rule, now, last_try_time, retry_interval_max);

    // Build the updated retry record with text truncated to EXIM_DB_RLIMIT.
    let error_text: String = rti
        .message
        .as_deref()
        .unwrap_or("")
        .chars()
        .take(EXIM_DB_RLIMIT)
        .collect();

    let updated_record = RetryRecord {
        first_failed,
        last_try: now,
        next_try,
        expired: timed_out,
        basic_errno: rti.basic_errno,
        more_errno: rti.more_errno,
        text: error_text,
    };

    tracing::debug!(
        key = key.as_str(),
        first_failed = first_failed,
        next_try = next_try,
        expired = timed_out,
        rule = ?active_rule.rule_type,
        "writing retry record"
    );

    db_write_retry_record(db, key, &updated_record)
}

/// Check whether a single retry item has timed out.
fn check_item_timed_out<D: HintsDb>(
    rti: &RetryItem,
    now: i64,
    message_age: i64,
    retry_data_expire: i64,
    db: &D,
    config: &ConfigContext,
) -> bool {
    if rti.flags.contains(RetryItemFlags::DELETE) {
        return true;
    }

    let key = &rti.key;
    let lookup_key = if key.len() > 2 {
        &key[2..]
    } else {
        key.as_str()
    };

    let retry_configs = get_retry_configs(config);
    let retry_cfg = match find_config_match(
        lookup_key,
        None,
        rti.basic_errno,
        rti.more_errno,
        &retry_configs,
    ) {
        Some(cfg) => cfg,
        None => return false,
    };

    let first_failed = match db_read_retry_record(db, key) {
        Some(tainted_rec) => {
            let rec = tainted_rec.as_ref();
            if now - rec.first_failed > retry_data_expire {
                now
            } else {
                rec.first_failed
            }
        }
        None => now,
    };

    let failing_interval = now - first_failed;
    let effective_interval = if !rti.flags.contains(RetryItemFlags::HOST) {
        failing_interval.max(message_age)
    } else {
        failing_interval
    };

    retry_cfg
        .rules
        .last()
        .is_some_and(|last| effective_interval > last.timeout)
}

// ===========================================================================
// Unit tests
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // retry_host_key_build tests
    // -----------------------------------------------------------------------

    #[test]
    fn host_key_simple_hostname() {
        let key = retry_host_key_build("mail.example.com", false, None, None);
        assert_eq!(key, "T:mail.example.com");
    }

    #[test]
    fn host_key_with_ip() {
        let key = retry_host_key_build("mail.example.com", true, Some("192.168.1.1"), None);
        assert_eq!(key, "T:mail.example.com:192.168.1.1");
    }

    #[test]
    fn host_key_with_ip_and_port() {
        let key = retry_host_key_build("mail.example.com", true, Some("192.168.1.1"), Some(":587"));
        // Port has leading ':' stripped and uses '+' separator
        assert_eq!(key, "T:mail.example.com:192.168.1.1+587");
    }

    #[test]
    fn host_key_uppercase_lowered() {
        let key = retry_host_key_build("Mail.Example.COM", false, None, None);
        assert_eq!(key, "T:mail.example.com");
    }

    #[test]
    fn host_key_include_ip_false_ignores_address() {
        let key = retry_host_key_build("host.test", false, Some("10.0.0.1"), Some(":25"));
        assert_eq!(key, "T:host.test");
    }

    #[test]
    fn host_key_ipv6() {
        let key = retry_host_key_build("host.test", true, Some("2001:db8::1"), None);
        assert_eq!(key, "T:host.test:2001:db8::1");
    }

    // -----------------------------------------------------------------------
    // RetryRecord serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn retry_record_roundtrip() {
        let record = RetryRecord {
            first_failed: 1_700_000_000,
            last_try: 1_700_001_000,
            next_try: 1_700_002_000,
            expired: false,
            basic_errno: 110,
            more_errno: 0,
            text: "Connection timed out".to_string(),
        };
        let bytes = record.to_bytes();
        let decoded = RetryRecord::from_bytes(&bytes).expect("roundtrip decode");
        assert_eq!(decoded.first_failed, record.first_failed);
        assert_eq!(decoded.last_try, record.last_try);
        assert_eq!(decoded.next_try, record.next_try);
        assert_eq!(decoded.expired, record.expired);
        assert_eq!(decoded.basic_errno, record.basic_errno);
        assert_eq!(decoded.more_errno, record.more_errno);
        assert_eq!(decoded.text, record.text);
    }

    #[test]
    fn retry_record_roundtrip_expired() {
        let record = RetryRecord {
            first_failed: 1_600_000_000,
            last_try: 1_600_100_000,
            next_try: 0,
            expired: true,
            basic_errno: 111,
            more_errno: 25,
            text: "Connection refused".to_string(),
        };
        let bytes = record.to_bytes();
        let decoded = RetryRecord::from_bytes(&bytes).expect("roundtrip decode");
        assert!(decoded.expired);
        assert_eq!(decoded.basic_errno, 111);
        assert_eq!(decoded.text, "Connection refused");
    }

    #[test]
    fn retry_record_from_short_bytes() {
        assert!(RetryRecord::from_bytes(&[0u8; 10]).is_none());
    }

    #[test]
    fn retry_record_empty_text() {
        let record = RetryRecord {
            first_failed: 100,
            last_try: 200,
            next_try: 300,
            expired: false,
            basic_errno: 0,
            more_errno: 0,
            text: String::new(),
        };
        let bytes = record.to_bytes();
        let decoded = RetryRecord::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.text, "");
    }

    // -----------------------------------------------------------------------
    // RetryRuleType tests
    // -----------------------------------------------------------------------

    #[test]
    fn rule_type_conversion() {
        assert_eq!(rule_type_from_algorithm(b'F' as i32), RetryRuleType::Fixed);
        assert_eq!(
            rule_type_from_algorithm(b'G' as i32),
            RetryRuleType::Geometric
        );
        assert_eq!(
            rule_type_from_algorithm(b'H' as i32),
            RetryRuleType::Heuristic
        );
        assert_eq!(rule_type_from_algorithm(999), RetryRuleType::Fixed);
    }

    // -----------------------------------------------------------------------
    // RetryItemFlags tests
    // -----------------------------------------------------------------------

    #[test]
    fn retry_item_flags_basic() {
        let flags = RetryItemFlags::HOST | RetryItemFlags::MESSAGE;
        assert!(flags.contains(RetryItemFlags::HOST));
        assert!(flags.contains(RetryItemFlags::MESSAGE));
        assert!(!flags.contains(RetryItemFlags::DELETE));
    }

    #[test]
    fn retry_item_flags_empty() {
        let flags = RetryItemFlags::empty();
        assert!(!flags.contains(RetryItemFlags::HOST));
        assert!(!flags.contains(RetryItemFlags::MESSAGE));
        assert!(!flags.contains(RetryItemFlags::DELETE));
    }

    // -----------------------------------------------------------------------
    // compute_next_try tests
    // -----------------------------------------------------------------------

    #[test]
    fn compute_next_try_fixed() {
        let rule = RetryRule {
            rule_type: RetryRuleType::Fixed,
            timeout: 3600,
            p1: 900, // 15 minutes
            p2: 0,
            next: None,
        };
        let now = 1_700_000_000;
        let result = compute_next_try(&rule, now, now - 600, i64::MAX);
        assert_eq!(result, now + 900);
    }

    #[test]
    fn compute_next_try_geometric_initial() {
        let rule = RetryRule {
            rule_type: RetryRuleType::Geometric,
            timeout: 7200,
            p1: 300,  // 5 min minimum
            p2: 2000, // 2x multiplier
            next: None,
        };
        let now = 1_700_000_000;
        // First attempt — last_try == 0, so last_gap == 0, geometric base = 0,
        // result = max(p1, 0) = p1 = 300
        let result = compute_next_try(&rule, now, 0, i64::MAX);
        assert_eq!(result, now + 300);
    }

    #[test]
    fn compute_next_try_geometric_growth() {
        let rule = RetryRule {
            rule_type: RetryRuleType::Geometric,
            timeout: 7200,
            p1: 300,
            p2: 2000, // 2x
            next: None,
        };
        let now = 1_700_000_000;
        let last_try = now - 600; // last_gap = 600
                                  // geometric_base = 600 * 2000 / 1000 = 1200
                                  // max(300, 1200) = 1200
        let result = compute_next_try(&rule, now, last_try, i64::MAX);
        assert_eq!(result, now + 1200);
    }

    #[test]
    fn compute_next_try_capped() {
        let rule = RetryRule {
            rule_type: RetryRuleType::Fixed,
            timeout: 86400,
            p1: 50000,
            p2: 0,
            next: None,
        };
        let now = 1_700_000_000;
        let max_interval = 3600; // cap at 1 hour
        let result = compute_next_try(&rule, now, now - 100, max_interval);
        assert_eq!(result, now + max_interval);
    }

    #[test]
    fn compute_next_try_heuristic() {
        let rule = RetryRule {
            rule_type: RetryRuleType::Heuristic,
            timeout: 7200,
            p1: 300,
            p2: 2000,
            next: None,
        };
        let now = 1_700_000_000;
        let last_try = now - 600;
        let result = compute_next_try(&rule, now, last_try, i64::MAX);
        // Heuristic should be >= now + p1 (minimum) and bounded
        assert!(result >= now + 300);
        // Heuristic adds randomized jitter, so upper bound is geometric + margin
        assert!(result <= now + 1500);
    }

    // -----------------------------------------------------------------------
    // find_active_rule tests
    // -----------------------------------------------------------------------

    #[test]
    fn find_active_rule_single() {
        let rules = vec![RetryRule {
            rule_type: RetryRuleType::Fixed,
            timeout: 3600,
            p1: 900,
            p2: 0,
            next: None,
        }];
        let result = find_active_rule(&rules, 1800);
        assert!(result.is_some());
        assert_eq!(result.unwrap().p1, 900);
    }

    #[test]
    fn find_active_rule_multi_selects_first_valid() {
        let rules = vec![
            RetryRule {
                rule_type: RetryRuleType::Fixed,
                timeout: 1800,
                p1: 300,
                p2: 0,
                next: None,
            },
            RetryRule {
                rule_type: RetryRuleType::Geometric,
                timeout: 7200,
                p1: 600,
                p2: 2000,
                next: None,
            },
        ];
        // failing_interval = 2000 > first rule's timeout (1800), so use second
        let result = find_active_rule(&rules, 2000);
        assert!(result.is_some());
        assert_eq!(result.unwrap().p1, 600);
        assert_eq!(result.unwrap().rule_type, RetryRuleType::Geometric);
    }

    #[test]
    fn find_active_rule_all_expired_returns_last() {
        let rules = vec![
            RetryRule {
                rule_type: RetryRuleType::Fixed,
                timeout: 100,
                p1: 10,
                p2: 0,
                next: None,
            },
            RetryRule {
                rule_type: RetryRuleType::Fixed,
                timeout: 200,
                p1: 20,
                p2: 0,
                next: None,
            },
        ];
        let result = find_active_rule(&rules, 99999);
        assert!(result.is_some());
        assert_eq!(result.unwrap().p1, 20);
    }

    #[test]
    fn find_active_rule_empty() {
        let rules: Vec<RetryRule> = vec![];
        assert!(find_active_rule(&rules, 100).is_none());
    }

    // -----------------------------------------------------------------------
    // extract_match_key tests
    // -----------------------------------------------------------------------

    #[test]
    fn extract_match_key_pipe_path() {
        assert_eq!(
            extract_match_key("|/usr/bin/forward:user@example.com"),
            "user@example.com"
        );
    }

    #[test]
    fn extract_match_key_slash_path() {
        assert_eq!(
            extract_match_key("/var/mail/box:alice@test.org"),
            "alice@test.org"
        );
    }

    #[test]
    fn extract_match_key_gt_path() {
        assert_eq!(
            extract_match_key(">transport:bob@example.net"),
            "bob@example.net"
        );
    }

    #[test]
    fn extract_match_key_host_ip() {
        // For "hostname:ip+port", extract just "hostname"
        assert_eq!(
            extract_match_key("mx.example.com:1.2.3.4+25"),
            "mx.example.com"
        );
    }

    #[test]
    fn extract_match_key_ipv6_brackets() {
        // For "[ipv6]:port", the '[' is not a special prefix, so find
        // first ':' and return text before it
        assert_eq!(extract_match_key("[2001:db8::1]:80"), "[2001");
    }

    #[test]
    fn extract_match_key_plain() {
        assert_eq!(extract_match_key("user@domain.com"), "user@domain.com");
    }

    // -----------------------------------------------------------------------
    // errno_matches tests
    // -----------------------------------------------------------------------

    #[test]
    fn errno_matches_any() {
        let cfg = RetryConfig {
            pattern: "*".to_string(),
            senders: None,
            basic_errno: 0,
            more_errno: 0,
            rules: vec![],
            src_file: String::new(),
            src_line: 0,
        };
        // basic_errno == 0 means "match any"
        assert!(errno_matches(&cfg, 111, 0));
        assert!(errno_matches(&cfg, 0, 0));
    }

    #[test]
    fn errno_matches_specific() {
        let cfg = RetryConfig {
            pattern: "*".to_string(),
            senders: None,
            basic_errno: 111,
            more_errno: 0,
            rules: vec![],
            src_file: String::new(),
            src_line: 0,
        };
        assert!(errno_matches(&cfg, 111, 0));
        assert!(!errno_matches(&cfg, 110, 0));
    }

    #[test]
    fn errno_matches_quota_includes_enospc() {
        let cfg = RetryConfig {
            pattern: "*".to_string(),
            senders: None,
            basic_errno: ERRNO_EXIMQUOTA,
            more_errno: 0,
            rules: vec![],
            src_file: String::new(),
            src_line: 0,
        };
        assert!(errno_matches(&cfg, ERRNO_EXIMQUOTA, 0));
        assert!(errno_matches(&cfg, ERRNO_ENOSPC, 0));
        assert!(!errno_matches(&cfg, 110, 0));
    }

    #[test]
    fn errno_matches_4xx_wildcard() {
        // 255 in 2nd byte = any 4xx code
        let cfg = RetryConfig {
            pattern: "*".to_string(),
            senders: None,
            basic_errno: ERRNO_MAIL4XX,
            more_errno: 255 << 8, // wanted=255 (any 4xx) in 2nd byte
            rules: vec![],
            src_file: String::new(),
            src_line: 0,
        };
        // Response code 421 → evalue = 21 in 2nd byte
        assert!(errno_matches(&cfg, ERRNO_MAIL4XX, 21 << 8));
        // Response code 450 → evalue = 50 in 2nd byte
        assert!(errno_matches(&cfg, ERRNO_MAIL4XX, 50 << 8));
    }

    #[test]
    fn errno_matches_4xx_decade() {
        // Decade match for 450-459: wanted=150 (150 >= 100, 150-100=50)
        let cfg = RetryConfig {
            pattern: "*".to_string(),
            senders: None,
            basic_errno: ERRNO_MAIL4XX,
            more_errno: 150 << 8, // decade 50 → codes 450-459
            rules: vec![],
            src_file: String::new(),
            src_line: 0,
        };
        // Response 450 → evalue=50, (50/10)*10=50, wanted-100=50 → match
        assert!(errno_matches(&cfg, ERRNO_MAIL4XX, 50 << 8));
        // Response 459 → evalue=59, (59/10)*10=50, wanted-100=50 → match
        assert!(errno_matches(&cfg, ERRNO_MAIL4XX, 59 << 8));
        // Response 440 → evalue=40, (40/10)*10=40, wanted-100=50 → no match
        assert!(!errno_matches(&cfg, ERRNO_MAIL4XX, 40 << 8));
    }

    // -----------------------------------------------------------------------
    // pattern_matches tests
    // -----------------------------------------------------------------------

    #[test]
    fn pattern_matches_wildcard() {
        assert!(pattern_matches("*", "anything@example.com", None));
    }

    #[test]
    fn pattern_matches_domain_wildcard() {
        assert!(pattern_matches("*@example.com", "user@example.com", None));
    }

    #[test]
    fn pattern_matches_exact() {
        assert!(pattern_matches(
            "admin@example.com",
            "admin@example.com",
            None
        ));
        assert!(!pattern_matches(
            "admin@example.com",
            "user@example.com",
            None
        ));
    }

    #[test]
    fn pattern_matches_alternate_domain() {
        assert!(pattern_matches(
            "*@alt.example.com",
            "user@primary.com",
            Some("alt.example.com")
        ));
    }

    // -----------------------------------------------------------------------
    // retry_add_item tests
    // -----------------------------------------------------------------------

    fn make_test_address() -> AddressItem {
        use crate::orchestrator::AddressProperties;
        AddressItem {
            address: Tainted::new("test@example.com".to_string()),
            domain: "example.com".to_string(),
            local_part: "test".to_string(),
            home_dir: None,
            current_dir: None,
            errors_address: None,
            host_list: vec!["mx.example.com".to_string()],
            router: None,
            transport: None,
            prop: AddressProperties::default(),
            flags: AddressFlags::default(),
            message: Some("Connection timed out".to_string()),
            basic_errno: 110,
            more_errno: 25,
            dsn_flags: 0,
            dsn_orcpt: None,
            dsn_aware: 0,
            return_path: None,
            uid: 0,
            gid: 0,
            unique: "test@example.com".to_string(),
            parent_index: -1,
            children: vec![],
            prefix: None,
            suffix: None,
            onetime_parent: None,
        }
    }

    #[test]
    fn retry_add_item_basic() {
        let addr = make_test_address();
        let item = retry_add_item(&addr, "T:mx.example.com:1.2.3.4+:25", RetryItemFlags::HOST);
        assert_eq!(item.key, "T:mx.example.com:1.2.3.4+:25");
        assert_eq!(item.basic_errno, 110);
        assert_eq!(item.more_errno, 25);
        assert_eq!(item.message.as_deref(), Some("Connection timed out"));
        assert!(item.flags.contains(RetryItemFlags::HOST));
        assert!(!item.flags.contains(RetryItemFlags::DELETE));
    }

    #[test]
    fn retry_add_item_delete_flag() {
        let addr = make_test_address();
        let item = retry_add_item(&addr, "T:host", RetryItemFlags::DELETE);
        assert!(item.flags.contains(RetryItemFlags::DELETE));
        assert!(!item.flags.contains(RetryItemFlags::HOST));
    }

    // -----------------------------------------------------------------------
    // HostStatus / HostWhyUnusable tests
    // -----------------------------------------------------------------------

    #[test]
    fn host_status_default() {
        let result = RetryCheckResult::default();
        assert_eq!(result.status, HostStatus::Unknown);
        assert_eq!(result.why, HostWhyUnusable::Retry);
        assert!(!result.expired);
    }

    #[test]
    fn host_status_equality() {
        assert_ne!(HostStatus::Usable, HostStatus::Unusable);
        assert_ne!(HostStatus::Unusable, HostStatus::UnusableExpired);
        assert_eq!(HostStatus::Unknown, HostStatus::Unknown);
    }

    // -----------------------------------------------------------------------
    // RetryConfig conversion tests
    // -----------------------------------------------------------------------

    #[test]
    fn convert_config_retry_basic() {
        let cfg_rule = exim_config::types::RetryRule {
            algorithm: b'F' as i32,
            timeout: 3600,
            p1: 900,
            p2: 0,
            next_try: 0,
        };
        let cfg = exim_config::types::RetryConfig {
            pattern: "*.example.com".to_string(),
            rules: vec![cfg_rule],
        };
        let converted = convert_config_retry(&cfg);
        assert_eq!(converted.pattern, "*.example.com");
        assert_eq!(converted.rules.len(), 1);
        assert_eq!(converted.rules[0].rule_type, RetryRuleType::Fixed);
        assert_eq!(converted.rules[0].timeout, 3600);
        assert_eq!(converted.rules[0].p1, 900);
    }

    #[test]
    fn convert_config_retry_chain() {
        let rules = vec![
            exim_config::types::RetryRule {
                algorithm: b'F' as i32,
                timeout: 1800,
                p1: 300,
                p2: 0,
                next_try: 0,
            },
            exim_config::types::RetryRule {
                algorithm: b'G' as i32,
                timeout: 7200,
                p1: 600,
                p2: 2000,
                next_try: 0,
            },
        ];
        let cfg = exim_config::types::RetryConfig {
            pattern: "*".to_string(),
            rules,
        };
        let converted = convert_config_retry(&cfg);
        assert_eq!(converted.rules.len(), 2);
        // First rule should have next pointing to second
        assert!(converted.rules[0].next.is_some());
        let next = converted.rules[0].next.as_ref().unwrap();
        assert_eq!(next.rule_type, RetryRuleType::Geometric);
        assert_eq!(next.p1, 600);
        // Second rule's next should be None
        assert!(converted.rules[1].next.is_none());
    }

    // -----------------------------------------------------------------------
    // RetryError tests
    // -----------------------------------------------------------------------

    #[test]
    fn retry_error_display() {
        let err = RetryError::DatabaseOpenFailed;
        assert_eq!(format!("{err}"), "retry database open failed");

        let err = RetryError::DatabaseWriteFailed("T:host:1.2.3.4".to_string());
        assert!(format!("{err}").contains("T:host:1.2.3.4"));

        let err = RetryError::ConfigError("bad pattern".to_string());
        assert!(format!("{err}").contains("bad pattern"));
    }
}
