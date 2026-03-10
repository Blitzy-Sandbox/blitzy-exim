//! Configuration type definitions for the `exim-config` crate.
//!
//! This module provides the foundational types used throughout the Exim MTA
//! Rust workspace. It replaces:
//!
//! - 714 global variables from `globals.c` / `globals.h` → scoped context structs
//! - Supporting types from `structs.h` (`rewrite_rule`, `retry_config`,
//!   `retry_rule`, `macro_item`, `namedlist_block`)
//! - Custom allocator pool semantics from `store.c` → `Arc<Config>` frozen wrapper
//!
//! Per AAP §0.4.4, four scoped context structs replace all mutable global state:
//! - [`ConfigContext`] — parsed configuration (all options, driver instances, ACL defs)
//! - [`ServerContext`] — daemon-lifetime state (sockets, process table, signals)
//! - [`MessageContext`] — per-message state (sender, recipients, headers, ACL vars)
//! - [`DeliveryContext`] — per-delivery-attempt state (address, router/transport results)
//!
//! Per AAP §0.7.3, after parsing the configuration is frozen into an
//! [`Arc<Config>`](Config) and shared immutably. No mutable shared config state
//! exists after parsing.

use std::collections::BTreeMap;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use serde::Serialize;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during Exim configuration parsing and validation.
///
/// Each variant maps to a distinct failure mode in the configuration lifecycle,
/// from file discovery through parsing, macro expansion, driver instantiation,
/// and final validation.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The specified configuration file could not be found on disk.
    #[error("configuration file not found: {0}")]
    FileNotFound(String),

    /// A syntax or semantic error encountered during configuration parsing.
    /// Includes the source file path and line number for diagnostic precision.
    #[error("configuration parse error at {file}:{line}: {message}")]
    ParseError {
        /// Path to the configuration file containing the error.
        file: String,
        /// Line number (1-based) where the error was detected.
        line: u32,
        /// Human-readable description of the parse error.
        message: String,
    },

    /// A configuration option name was not recognized in the current context.
    #[error("unknown option: {0}")]
    UnknownOption(String),

    /// A configuration option was set more than once without being permitted
    /// for repeated assignment (e.g., via `opt_rep_con` or `opt_rep_str`).
    #[error("option set twice: {0}")]
    DuplicateOption(String),

    /// A driver name referenced in a configuration block is not registered
    /// in the driver registry.
    #[error("unknown driver: {0}")]
    UnknownDriver(String),

    /// Two driver instances were given the same name.
    #[error("duplicate driver name: {0}")]
    DuplicateDriver(String),

    /// An error occurred during macro expansion (`.define`, `$MACRO`, etc.).
    #[error("macro error: {0}")]
    MacroError(String),

    /// A `.ifdef`/`.ifndef`/`.else`/`.endif` conditional block is improperly
    /// nested or has a missing/extra terminator.
    #[error("conditional nesting error: {0}")]
    ConditionalError(String),

    /// A post-parse validation check failed (e.g., missing required option,
    /// conflicting settings, unreachable driver).
    #[error("validation error: {0}")]
    ValidationError(String),

    /// An underlying I/O error (file read, directory traversal, etc.).
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// Rewrite rule types (from structs.h `rewrite_rule`)
// ---------------------------------------------------------------------------

/// A header or envelope rewrite rule parsed from the `rewrite` configuration
/// section.
///
/// Translates from the C `rewrite_rule` linked-list struct in `structs.h`.
/// In C these are chained via a `next` pointer; in Rust they are collected
/// into a `Vec<RewriteRule>` in [`ConfigContext::rewrite_rules`].
#[derive(Debug, Clone, Serialize)]
pub struct RewriteRule {
    /// The pattern to match (may contain expansion variables).
    pub key: String,
    /// The replacement string (may contain expansion variables).
    pub replacement: String,
    /// Bitfield of rewrite flags controlling which headers are affected
    /// and the matching mode. Corresponds to the C `flags` field encoding.
    pub flags: u32,
}

// ---------------------------------------------------------------------------
// Retry rule types (from structs.h `retry_config` / `retry_rule`)
// ---------------------------------------------------------------------------

/// A single retry rule within a retry configuration block.
///
/// Translates from the C `retry_rule` struct in `structs.h`. Each rule
/// specifies a retry algorithm (e.g., fixed, exponential) with its parameters
/// and a timeout after which the rule is no longer applied.
#[derive(Debug, Clone, Serialize)]
pub struct RetryRule {
    /// Retry algorithm identifier. In C this is `rule` — an integer encoding
    /// of `F` (fixed), `G` (growing/exponential), or other algorithm codes.
    pub algorithm: i32,
    /// First algorithm parameter. For exponential backoff this is the initial
    /// retry interval in seconds; for fixed retry this is the interval.
    pub p1: i32,
    /// Second algorithm parameter. For exponential backoff this is the
    /// multiplier factor (times 1000); for fixed retry this is unused (0).
    pub p2: i32,
    /// Maximum elapsed time (in seconds) for which this rule applies.
    /// After this timeout the next rule in the chain is consulted.
    pub timeout: i32,
    /// Computed time for the next retry attempt (seconds from first failure).
    /// This is set during retry processing and defaults to 0.
    pub next_try: i32,
}

/// A retry configuration block parsed from the `retry` configuration section.
///
/// Translates from the C `retry_config` struct in `structs.h`. Each block
/// associates a pattern (and optional errno/senders filter) with a chain of
/// [`RetryRule`]s that control retry scheduling.
#[derive(Debug, Clone, Serialize)]
pub struct RetryConfig {
    /// Matching pattern for the domain/host/address this retry config applies
    /// to. Supports wildcards (`*`) and other Exim pattern syntax.
    pub pattern: String,
    /// Ordered list of retry rules. Rules are evaluated in order; the first
    /// rule whose timeout has not been exceeded is used.
    pub rules: Vec<RetryRule>,
}

// ---------------------------------------------------------------------------
// Named list types (from structs.h `namedlist_block` / globals.c anchors)
// ---------------------------------------------------------------------------

/// A named list entry — one of domain_list, host_list, address_list, or
/// localpart_list as defined in the configuration file.
///
/// Translates from the C `namedlist_block` / tree-based storage in `globals.c`.
#[derive(Debug, Clone, Serialize)]
pub struct NamedList {
    /// The list name as declared in configuration.
    pub name: String,
    /// The list value (colon-separated items, may contain expansion variables).
    pub value: String,
    /// If `true`, the list is "hidden" (the `hide` option was used), meaning
    /// its contents are not displayed with `-bP`.
    pub hide: bool,
}

/// Container for the four categories of named lists that Exim supports.
///
/// In C these are stored as four separate tree anchors
/// (`domainlist_anchor`, `hostlist_anchor`, `addresslist_anchor`,
/// `localpartlist_anchor`) with integer counters. In Rust they are collected
/// into sorted maps for deterministic iteration order.
#[derive(Debug, Clone, Default, Serialize)]
pub struct NamedLists {
    /// Named domain lists (`domainlist_anchor` in C).
    pub domain_lists: BTreeMap<String, NamedList>,
    /// Named host lists (`hostlist_anchor` in C).
    pub host_lists: BTreeMap<String, NamedList>,
    /// Named address lists (`addresslist_anchor` in C).
    pub address_lists: BTreeMap<String, NamedList>,
    /// Named local-part lists (`localpartlist_anchor` in C).
    pub localpart_lists: BTreeMap<String, NamedList>,
}

// ---------------------------------------------------------------------------
// Syslog facility enum (from readconf.c `syslog_list[]`)
// ---------------------------------------------------------------------------

/// Syslog facility values supported by Exim's `syslog_facility` configuration
/// option.
///
/// Maps to the C `syslog_list[]` array in `readconf.c` (lines 628–644) and
/// the POSIX `<syslog.h>` facility constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SyslogFacility {
    /// `LOG_MAIL` — mail system (default).
    Mail,
    /// `LOG_USER` — random user-level messages.
    User,
    /// `LOG_NEWS` — network news subsystem.
    News,
    /// `LOG_UUCP` — UUCP subsystem.
    Uucp,
    /// `LOG_LOCAL0` — reserved for local use.
    Local0,
    /// `LOG_LOCAL1` — reserved for local use.
    Local1,
    /// `LOG_LOCAL2` — reserved for local use.
    Local2,
    /// `LOG_LOCAL3` — reserved for local use.
    Local3,
    /// `LOG_LOCAL4` — reserved for local use.
    Local4,
    /// `LOG_LOCAL5` — reserved for local use.
    Local5,
    /// `LOG_LOCAL6` — reserved for local use.
    Local6,
    /// `LOG_LOCAL7` — reserved for local use.
    Local7,
    /// `LOG_DAEMON` — system daemon.
    Daemon,
}

impl SyslogFacility {
    /// Convert to the numeric POSIX syslog facility code.
    ///
    /// These values match the `LOG_*` constants from `<syslog.h>` on Linux
    /// (and are consistent across all major POSIX platforms).
    pub fn to_facility_code(self) -> i32 {
        match self {
            Self::Mail => 2 << 3,    // LOG_MAIL   = 16
            Self::User => 1 << 3,    // LOG_USER   = 8
            Self::News => 7 << 3,    // LOG_NEWS   = 56
            Self::Uucp => 8 << 3,    // LOG_UUCP   = 64
            Self::Local0 => 16 << 3, // LOG_LOCAL0 = 128
            Self::Local1 => 17 << 3, // LOG_LOCAL1 = 136
            Self::Local2 => 18 << 3, // LOG_LOCAL2 = 144
            Self::Local3 => 19 << 3, // LOG_LOCAL3 = 152
            Self::Local4 => 20 << 3, // LOG_LOCAL4 = 160
            Self::Local5 => 21 << 3, // LOG_LOCAL5 = 168
            Self::Local6 => 22 << 3, // LOG_LOCAL6 = 176
            Self::Local7 => 23 << 3, // LOG_LOCAL7 = 184
            Self::Daemon => 3 << 3,  // LOG_DAEMON = 24
        }
    }
}

impl FromStr for SyslogFacility {
    type Err = ConfigError;

    /// Parse a syslog facility name from its string representation.
    ///
    /// Matching is case-insensitive and supports the standard POSIX names
    /// as used in Exim's `syslog_list[]` (readconf.c).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "mail" => Ok(Self::Mail),
            "user" => Ok(Self::User),
            "news" => Ok(Self::News),
            "uucp" => Ok(Self::Uucp),
            "local0" => Ok(Self::Local0),
            "local1" => Ok(Self::Local1),
            "local2" => Ok(Self::Local2),
            "local3" => Ok(Self::Local3),
            "local4" => Ok(Self::Local4),
            "local5" => Ok(Self::Local5),
            "local6" => Ok(Self::Local6),
            "local7" => Ok(Self::Local7),
            "daemon" => Ok(Self::Daemon),
            _ => Err(ConfigError::UnknownOption(format!(
                "unknown syslog facility: {s}"
            ))),
        }
    }
}

impl Default for SyslogFacility {
    /// Default syslog facility is `Mail` (matching C `LOG_MAIL` default).
    fn default() -> Self {
        Self::Mail
    }
}

impl std::fmt::Display for SyslogFacility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Mail => "mail",
            Self::User => "user",
            Self::News => "news",
            Self::Uucp => "uucp",
            Self::Local0 => "local0",
            Self::Local1 => "local1",
            Self::Local2 => "local2",
            Self::Local3 => "local3",
            Self::Local4 => "local4",
            Self::Local5 => "local5",
            Self::Local6 => "local6",
            Self::Local7 => "local7",
            Self::Daemon => "daemon",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/// Snapshot of a macro definition stored for `-bP` config printing.
///
/// Translates from the C `macro_item` struct in `structs.h` (lines 41–48).
/// The linked-list structure is flattened into `Vec<MacroItemSnapshot>` in
/// [`ConfigContext::macros`].
#[derive(Debug, Clone, Serialize)]
pub struct MacroItemSnapshot {
    /// The macro name (including the leading uppercase letter convention).
    pub name: String,
    /// The macro replacement text.
    pub replacement: String,
    /// `true` if the macro was defined on the command line (`-D`).
    pub command_line: bool,
}

/// An ACL (Access Control List) block as parsed from the `begin acl` section.
///
/// At the `exim-config` level, ACL blocks are stored as raw definition strings.
/// The full parsed representation (verb chains, conditions, etc.) is provided
/// by the `exim-acl` crate when the ACL is evaluated at runtime.
#[derive(Debug, Clone, Serialize)]
pub struct AclBlock {
    /// The raw ACL definition text exactly as it appears in the config file.
    /// This is preserved verbatim for `-bP` printing and lazy evaluation.
    pub raw_definition: String,
}

/// TLS connection state snapshot used in [`MessageContext`] to record
/// inbound TLS properties for the current message.
///
/// Replaces the C `tls_support` struct from `globals.h`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct TlsInfo {
    /// Whether TLS is active for this connection.
    pub active: bool,
    /// Negotiated cipher suite name.
    pub cipher: Option<String>,
    /// Standardized cipher name (RFC notation).
    pub cipher_stdname: Option<String>,
    /// TLS protocol version string (e.g., "TLSv1.3").
    pub ver: Option<String>,
    /// Whether the peer certificate was verified.
    pub certificate_verified: bool,
    /// Peer's Distinguished Name from the certificate.
    pub peerdn: Option<String>,
    /// Server Name Indication value.
    pub sni: Option<String>,
    /// Number of bits used in the TLS session.
    pub bits: i32,
}

// ---------------------------------------------------------------------------
// ConfigContext — the comprehensive parsed configuration
// ---------------------------------------------------------------------------

/// The parsed Exim configuration context, replacing all config-related global
/// variables from `globals.c` / `globals.h`.
///
/// Per AAP §0.4.4, this struct holds:
/// - All parsed configuration options (from `optionlist_config[]`)
/// - Driver instances (auth, router, transport chains)
/// - ACL definitions
/// - Rewrite rules and retry rules
/// - Named lists (domain, host, address, localpart)
/// - Macro definitions (for `-bP` printing)
///
/// After parsing, a `ConfigContext` is frozen into an [`Arc<Config>`](Config)
/// via [`Config::freeze()`] and shared immutably (AAP §0.7.3).
#[derive(Debug, Clone, Serialize)]
pub struct ConfigContext {
    // ── File metadata ───────────────────────────────────────────────────
    /// The configuration file path being processed
    /// (C: `config_main_filename`).
    pub config_filename: String,

    /// The directory containing the main configuration file
    /// (C: `config_main_directory`).
    pub config_directory: String,

    // ── Core path options ───────────────────────────────────────────────
    /// Spool directory path (C: `spool_directory`, default: compile-time SPOOL_DIRECTORY).
    pub spool_directory: String,

    /// Log file path template (C: `log_file_path`, default: compile-time LOG_FILE_PATH).
    pub log_file_path: String,

    /// PID file path (C: `pid_file_path`, default: compile-time PID_FILE_PATH).
    pub pid_file_path: String,

    /// Primary hostname of this machine (C: `primary_hostname`, default: auto-detected).
    pub primary_hostname: String,

    /// Domain to qualify unqualified sender addresses
    /// (C: `qualify_domain_sender`, default: primary hostname).
    pub qualify_domain_sender: String,

    /// Domain to qualify unqualified recipient addresses
    /// (C: `qualify_domain_recipient`, default: qualify_domain_sender).
    pub qualify_domain_recipient: String,

    // ── ACL definitions ─────────────────────────────────────────────────
    /// Named ACL definitions from the `begin acl` section (C: `acl_anchor` tree).
    pub acl_definitions: BTreeMap<String, AclBlock>,

    /// ACL for non-SMTP messages (C: `acl_not_smtp`).
    pub acl_not_smtp: Option<String>,

    /// ACL for SMTP AUTH command (C: `acl_smtp_auth`).
    pub acl_smtp_auth: Option<String>,

    /// ACL for SMTP connection establishment (C: `acl_smtp_connect`).
    pub acl_smtp_connect: Option<String>,

    /// ACL for SMTP DATA acceptance (C: `acl_smtp_data`).
    pub acl_smtp_data: Option<String>,

    /// ACL for SMTP ETRN command (C: `acl_smtp_etrn`).
    pub acl_smtp_etrn: Option<String>,

    /// ACL for SMTP EXPN command (C: `acl_smtp_expn`).
    pub acl_smtp_expn: Option<String>,

    /// ACL for SMTP HELO/EHLO command (C: `acl_smtp_helo`).
    pub acl_smtp_helo: Option<String>,

    /// ACL for SMTP MAIL FROM command (C: `acl_smtp_mail`).
    pub acl_smtp_mail: Option<String>,

    /// ACL for SMTP RCPT TO command (C: `acl_smtp_rcpt`).
    pub acl_smtp_rcpt: Option<String>,

    /// ACL for SMTP VRFY command (C: `acl_smtp_vrfy`).
    pub acl_smtp_vrfy: Option<String>,

    /// ACL for SMTP STARTTLS command (C: `acl_smtp_starttls`).
    #[cfg(feature = "tls")]
    pub acl_smtp_starttls: Option<String>,

    /// ACL for SMTP DATA in PRDR mode (C: `acl_smtp_data_prdr`, default: "accept").
    #[cfg(feature = "prdr")]
    pub acl_smtp_data_prdr: Option<String>,

    /// ACL for DKIM verification (C: `acl_smtp_dkim`).
    #[cfg(feature = "dkim")]
    pub acl_smtp_dkim: Option<String>,

    /// ACL for MIME parts of non-SMTP messages (C: `acl_not_smtp_mime`).
    #[cfg(feature = "content-scan")]
    pub acl_not_smtp_mime: Option<String>,

    /// ACL for MIME parts of SMTP messages (C: `acl_smtp_mime`).
    #[cfg(feature = "content-scan")]
    pub acl_smtp_mime: Option<String>,

    /// ACL for WELLKNOWN SMTP extension (C: `acl_smtp_wellknown`).
    #[cfg(feature = "wellknown")]
    pub acl_smtp_wellknown: Option<String>,

    /// ACL for non-SMTP session start (C: `acl_not_smtp_start`).
    pub acl_not_smtp_start: Option<String>,

    /// ACL for SMTP MAIL AUTH (C: `acl_smtp_mailauth`).
    pub acl_smtp_mailauth: Option<String>,

    /// ACL for disconnects (C: `acl_smtp_notquit`).
    pub acl_smtp_notquit: Option<String>,

    /// ACL for SMTP PREDATA phase (C: `acl_smtp_predata`).
    pub acl_smtp_predata: Option<String>,

    /// ACL for SMTP QUIT command (C: `acl_smtp_quit`).
    pub acl_smtp_quit: Option<String>,

    /// ACL for SMTP ATRN command (C: `acl_smtp_atrn`).
    pub acl_smtp_atrn: Option<String>,

    // ── Named lists ─────────────────────────────────────────────────────
    /// Named lists (domain, host, address, localpart) from configuration.
    pub named_lists: NamedLists,

    // ── Driver instances ────────────────────────────────────────────────
    /// Instantiated authenticator driver chain (C: `auths` linked list).
    /// Elements are type-erased driver instances populated by `driver_init`.
    /// Uses `Arc` for shared ownership compatible with `Clone`.
    #[serde(skip)]
    pub auth_instances: Vec<Arc<dyn std::any::Any + Send + Sync>>,

    /// Instantiated router driver chain (C: `routers` linked list).
    #[serde(skip)]
    pub router_instances: Vec<Arc<dyn std::any::Any + Send + Sync>>,

    /// Instantiated transport driver chain (C: `transports` linked list).
    #[serde(skip)]
    pub transport_instances: Vec<Arc<dyn std::any::Any + Send + Sync>>,

    // ── Rewrite and retry rules ─────────────────────────────────────────
    /// Rewrite rules from the `rewrite` config section (C: `global_rewrite_rules`).
    pub rewrite_rules: Vec<RewriteRule>,

    /// Retry rules from the `retry` config section (C: `retries`).
    pub retry_configs: Vec<RetryConfig>,

    // ── Boolean config flags ────────────────────────────────────────────
    // These replace the `BOOL` global variables and `global_flags` struct
    // fields from globals.c that are configuration options.
    /// Allow 8BITMIME in incoming messages (C: `accept_8bitmime`, default: TRUE).
    pub accept_8bitmime: bool,

    /// Allow domain literals `[ip]` in addresses (C: `allow_domain_literals`, default: FALSE).
    pub allow_domain_literals: bool,

    /// Allow MX records pointing to IP addresses (C: `allow_mx_to_ip`, default: FALSE).
    pub allow_mx_to_ip: bool,

    /// Include the message body in bounce messages (C: `bounce_return_body`, default: TRUE).
    pub bounce_return_body: bool,

    /// Include the original message in bounce messages
    /// (C: `bounce_return_message`, default: TRUE).
    pub bounce_return_message: bool,

    /// Allow UTF-8 in domain names (C: `allow_utf8_domains`, default: FALSE).
    #[cfg(feature = "i18n")]
    pub allow_utf8_domains: bool,

    /// Check RFC 2047 encoded string lengths (C: `check_rfc2047_length`, default: TRUE).
    pub check_rfc2047_length: bool,

    /// Require admin privilege for command-line checks
    /// (C: `commandline_checks_require_admin`, default: FALSE).
    pub commandline_checks_require_admin: bool,

    /// Remove Delivery-Date headers (C: `delivery_date_remove`, default: TRUE).
    pub delivery_date_remove: bool,

    /// Remove Envelope-To headers (C: `envelope_to_remove`, default: TRUE).
    pub envelope_to_remove: bool,

    /// Local From check enabled (C: `local_from_check`, default: TRUE).
    pub local_from_check: bool,

    /// Retain Sender: header (C: `local_sender_retain`, default: FALSE).
    pub local_sender_retain: bool,

    /// Include timezone in log lines (C: `log_timezone`, default: FALSE).
    pub log_timezone: bool,

    /// Write per-message log files (C: `message_logs`, default: TRUE).
    pub message_logs: bool,

    /// Preserve message log files (C: `preserve_message_logs`, default: FALSE).
    pub preserve_message_logs: bool,

    /// Treat top-bit characters as printing (C: `print_topbitchars`, default: FALSE).
    pub print_topbitchars: bool,

    /// Require admin for production commands (C: `prod_requires_admin`, default: TRUE).
    pub prod_requires_admin: bool,

    /// Require admin for queue listing (C: `queue_list_requires_admin`, default: TRUE).
    pub queue_list_requires_admin: bool,

    /// Queue-only mode (C: `queue_only`, default: FALSE).
    pub queue_only: bool,

    /// Latch queue_only when load is high (C: `queue_only_load_latch`, default: TRUE).
    pub queue_only_load_latch: bool,

    /// Allow queue_only to be overridden (C: `queue_only_override`, default: TRUE).
    pub queue_only_override: bool,

    /// Deliver queue in order (C: `queue_run_in_order`, default: FALSE).
    pub queue_run_in_order: bool,

    /// Reject whole message if recipients_max exceeded
    /// (C: `recipients_max_reject`, default: FALSE).
    pub recipients_max_reject: bool,

    /// Remove Return-Path headers (C: `return_path_remove`, default: TRUE).
    pub return_path_remove: bool,

    /// Enable TCP keepalive on accepted connections
    /// (C: `smtp_accept_keepalive`, default: TRUE).
    pub smtp_accept_keepalive: bool,

    /// Check spool space against SIZE value (C: `smtp_check_spool_space`, default: TRUE).
    pub smtp_check_spool_space: bool,

    /// Enforce SMTP synchronization (C: `smtp_enforce_sync`, default: TRUE).
    pub smtp_enforce_sync: bool,

    /// Serialize ETRN requests (C: `smtp_etrn_serialize`, default: TRUE).
    pub smtp_etrn_serialize: bool,

    /// Return error details in SMTP responses
    /// (C: `smtp_return_error_details`, default: FALSE).
    pub smtp_return_error_details: bool,

    /// Use split spool directory (C: `split_spool_directory`, default: FALSE).
    pub split_spool_directory: bool,

    /// Strict ACL variable checking (C: `strict_acl_vars`, default: FALSE).
    pub strict_acl_vars: bool,

    /// Strip excess angle brackets (C: `strip_excess_angle_brackets`, default: FALSE).
    pub strip_excess_angle_brackets: bool,

    /// Strip trailing dot from domains (C: `strip_trailing_dot`, default: FALSE).
    pub strip_trailing_dot: bool,

    /// Duplicate syslog lines to stderr (C: `syslog_duplication`, default: TRUE).
    pub syslog_duplication: bool,

    /// Include PID in syslog messages (C: `syslog_pid`, default: TRUE).
    pub syslog_pid: bool,

    /// Include timestamp in syslog messages (C: `syslog_timestamp`, default: TRUE).
    pub syslog_timestamp: bool,

    /// Enable TCP_NODELAY on connections (C: `tcp_nodelay`, default: TRUE).
    pub tcp_nodelay: bool,

    /// Write to the reject log (C: `write_rejectlog`, default: TRUE).
    pub write_rejectlog: bool,

    /// Disable IPv6 (C: `disable_ipv6`, default: FALSE).
    pub disable_ipv6: bool,

    /// Use DNS CSA reverse lookups (C: `dns_csa_use_reverse`, default: TRUE).
    pub dns_csa_use_reverse: bool,

    /// Ignore fromline in local messages (C: `ignore_fromline_local`, default: FALSE).
    pub ignore_fromline_local: bool,

    /// Include newlines in message_body variable
    /// (C: `message_body_newlines`, default: FALSE).
    pub message_body_newlines: bool,

    /// Deliver without privilege drop (C: `deliver_drop_privilege`, default: FALSE).
    pub deliver_drop_privilege: bool,

    /// Extract addresses and remove arguments (C: `extract_addresses_remove_arguments`, default: TRUE).
    pub extract_addresses_remove_arguments: bool,

    /// Enable pipelining advertising (C: `pipelining_enable` in flags, default: TRUE).
    pub pipelining_enable: bool,

    /// Use spool wireformat (C: `spool_wireformat`, default: FALSE).
    pub spool_wireformat: bool,

    /// Use timestamps in UTC (C: `timestamps_utc` in flags, default: FALSE).
    pub timestamps_utc: bool,

    // ── Integer/time config options ─────────────────────────────────────
    /// Auto-thaw interval in seconds (C: `auto_thaw`, default: 0).
    pub auto_thaw: i32,

    /// Max messages per SMTP connection (C: `connection_max_messages`, default: -1 = unlimited).
    pub connection_max_messages: i32,

    /// Max line length returned in bounces (C: `bounce_return_linesize_limit`, default: 998).
    pub bounce_return_linesize_limit: i32,

    /// Max bytes of original message in bounce (C: `bounce_return_size_limit`, default: 102400).
    pub bounce_return_size_limit: i32,

    /// Positive domain callout cache expiry in seconds (C default: 7 days).
    pub callout_cache_domain_positive_expire: i32,

    /// Negative domain callout cache expiry in seconds (C default: 3 hours).
    pub callout_cache_domain_negative_expire: i32,

    /// Positive callout cache expiry in seconds (C default: 24 hours).
    pub callout_cache_positive_expire: i32,

    /// Negative callout cache expiry in seconds (C default: 2 hours).
    pub callout_cache_negative_expire: i32,

    /// Minimum log filesystem inodes (C: `check_log_inodes`, default: 100).
    pub check_log_inodes: i32,

    /// Minimum log filesystem space in KB (C: `check_log_space`, default: 10240).
    pub check_log_space: i64,

    /// Minimum spool filesystem inodes (C: `check_spool_inodes`, default: 100).
    pub check_spool_inodes: i32,

    /// Minimum spool filesystem space in KB (C: `check_spool_space`, default: 10240).
    pub check_spool_space: i64,

    /// Daemon startup retries (C: `daemon_startup_retries`, default: 9).
    pub daemon_startup_retries: i32,

    /// Daemon startup sleep between retries in seconds (C: `daemon_startup_sleep`, default: 30).
    pub daemon_startup_sleep: i32,

    /// Max header size in bytes (C: `header_maxsize`, default: HEADER_MAXSIZE).
    pub header_maxsize: i32,

    /// Max header insert size (C: `header_insert_maxlen`, default: 65536).
    pub header_insert_maxlen: i32,

    /// Max individual header line size (C: `header_line_maxsize`, default: 0 = unlimited).
    pub header_line_maxsize: i32,

    /// Ignore bounce errors after this many seconds (C default: 10 weeks).
    pub ignore_bounce_errors_after: i32,

    /// Keep malformed messages for this many seconds (C default: 4 days).
    pub keep_malformed: i32,

    /// Max open lookup files to cache (C: `lookup_open_max`, default: 25).
    pub lookup_open_max: i32,

    /// Visible bytes of message body in $message_body (C: `message_body_visible`, default: 500).
    pub message_body_visible: i32,

    /// Max received headers before rejection (C: `received_headers_max`, default: 30).
    pub received_headers_max: i32,

    /// Max parallel remote deliveries (C: `remote_max_parallel`, default: 6).
    pub remote_max_parallel: i32,

    /// Retry data expiry in seconds (C: `retry_data_expire`, default: 7 days).
    pub retry_data_expire: i32,

    /// Max retry interval in seconds (C: `retry_interval_max`, default: 24 hours).
    pub retry_interval_max: i32,

    /// SMTP accept queue threshold (C: `smtp_accept_queue`, default: 0 = disabled).
    pub smtp_accept_queue: i32,

    /// SMTP accept queue per-connection threshold
    /// (C: `smtp_accept_queue_per_connection`, default: 10).
    pub smtp_accept_queue_per_connection: i32,

    /// SMTP accept reserve slots (C: `smtp_accept_reserve`, default: 0).
    pub smtp_accept_reserve: i32,

    /// Max SMTP connections (C: `smtp_accept_max`, default: 20).
    pub smtp_accept_max: i32,

    /// Max non-mail commands in one connection (C: `smtp_accept_max_nonmail`, default: 10).
    pub smtp_accept_max_nonmail: i32,

    /// Max syntax/protocol errors before disconnect
    /// (C: `smtp_max_synprot_errors`, default: 3).
    pub smtp_max_synprot_errors: i32,

    /// Max unknown SMTP commands before disconnect
    /// (C: `smtp_max_unknown_commands`, default: 3).
    pub smtp_max_unknown_commands: i32,

    /// SMTP receive timeout in seconds (C: `smtp_receive_timeout`, default: 300).
    pub smtp_receive_timeout: i32,

    /// SMTP connect backlog (C: `smtp_connect_backlog`, default: 20).
    pub smtp_connect_backlog: i32,

    /// Non-SMTP receive timeout in seconds (C: `receive_timeout`, default: 0).
    pub receive_timeout: i32,

    /// Queue running interval in seconds (C: `queue_interval`, default: -1).
    pub queue_interval: i32,

    /// Timeout for frozen messages in seconds (C: `timeout_frozen_after`, default: 0).
    pub timeout_frozen_after: i32,

    /// DNS CSA search depth limit (C: `dns_csa_search_limit`, default: 5).
    pub dns_csa_search_limit: i32,

    /// DNS CNAME following depth (C: `dns_cname_loops`, default: 1).
    pub dns_cname_loops: i32,

    /// DNS retransmission interval (C: `dns_retrans`, default: 0 = system).
    pub dns_retrans: i32,

    /// DNS retry count (C: `dns_retry`, default: 0 = system).
    pub dns_retry: i32,

    /// RFC 1413 ident query timeout in seconds (C: `rfc1413_query_timeout`, default: 0).
    pub rfc1413_query_timeout: i32,

    /// SMTP load reserve threshold (C: `smtp_load_reserve`, default: -1).
    pub smtp_load_reserve: i32,

    /// Queue-only load threshold (C: `queue_only_load`, default: -1).
    pub queue_only_load: i32,

    /// Deliver queue load max (C: `deliver_queue_load_max`, default: -1).
    pub deliver_queue_load_max: i32,

    // ── String config options ───────────────────────────────────────────
    /// Hosts to advertise AUTH to (C: `auth_advertise_hosts`, default: "*").
    pub auth_advertise_hosts: Option<String>,

    /// Bounce message template file (C: `bounce_message_file`, default: None).
    pub bounce_message_file: Option<String>,

    /// Bounce message text (C: `bounce_message_text`, default: None).
    pub bounce_message_text: Option<String>,

    /// Bounce sender authentication (C: `bounce_sender_authentication`, default: None).
    pub bounce_sender_authentication: Option<String>,

    /// Callout random local part for verification
    /// (C default: "$primary_hostname-$tod_epoch-testing").
    pub callout_random_local_part: Option<String>,

    /// DNS name syntax check pattern (C: `check_dns_names_pattern`).
    pub check_dns_names_pattern: Option<String>,

    /// Hosts for CHUNKING advertisement (C: `chunking_advertise_hosts`, default: "*").
    pub chunking_advertise_hosts: Option<String>,

    /// SMTP daemon port(s) (C: `daemon_smtp_port`, default: "smtp").
    pub daemon_smtp_port: Option<String>,

    /// Delay warning condition (C: `delay_warning_condition`).
    pub delay_warning_condition: Option<String>,

    /// DNS IPv4-only lookup domains (C: `dns_ipv4_lookup`, default: None).
    pub dns_ipv4_lookup: Option<String>,

    /// DNS trust AA as AD (C: `dns_trust_aa`, default: None).
    pub dns_trust_aa: Option<String>,

    /// DSN originator (C: `dsn_from`, default: DEFAULT_DSN_FROM).
    pub dsn_from: Option<String>,

    /// DSN advertise hosts (C: `dsn_advertise_hosts`, default: None).
    pub dsn_advertise_hosts: Option<String>,

    /// Extra local (non-listening) interfaces (C: `extra_local_interfaces`, default: None).
    pub extra_local_interfaces: Option<String>,

    /// Message to send when freezing (C: `freeze_tell`, default: None).
    pub freeze_tell: Option<String>,

    /// GECOS name expansion (C: `gecos_name`, default: None).
    pub gecos_name: Option<String>,

    /// GECOS pattern matching (C: `gecos_pattern`, default: None).
    pub gecos_pattern: Option<String>,

    /// HELO junk hosts (C: `helo_accept_junk_hosts`, default: None).
    pub helo_accept_junk_hosts: Option<String>,

    /// Extra chars allowed in HELO (C: `helo_allow_chars`, default: "").
    pub helo_allow_chars: Option<String>,

    /// HELO lookup domains (C: `helo_lookup_domains`, default: "@ : @[]").
    pub helo_lookup_domains: Option<String>,

    /// HELO try-verify hosts (C: `helo_try_verify_hosts`, default: None).
    pub helo_try_verify_hosts: Option<String>,

    /// HELO hard-verify hosts (C: `helo_verify_hosts`, default: None).
    pub helo_verify_hosts: Option<String>,

    /// Hold delivery to these domains (C: `hold_domains`, default: None).
    pub hold_domains: Option<String>,

    /// Host lookup pattern (C: `host_lookup`, default: None).
    pub host_lookup: Option<String>,

    /// Host lookup order (C: `host_lookup_order`, default: "bydns:byaddr").
    pub host_lookup_order: Option<String>,

    /// Hosts to reject connections from (C: `host_reject_connection`, default: None).
    pub host_reject_connection: Option<String>,

    /// Hosts requiring HELO (C: `hosts_require_helo`, default: "*").
    pub hosts_require_helo: Option<String>,

    /// Hosts treated as local (C: `hosts_treat_as_local`, default: None).
    pub hosts_treat_as_local: Option<String>,

    /// Hosts without connection logging (C: `hosts_connection_nolog`, default: None).
    pub hosts_connection_nolog: Option<String>,

    /// Environment variables to keep (C: `keep_environment`, default: None).
    pub keep_environment: Option<String>,

    /// Environment variables to add (C: `add_environment`, default: None).
    pub add_environment: Option<String>,

    /// Local interfaces for binding (C: `local_interfaces`).
    pub local_interfaces: Option<String>,

    /// Local from prefix (C: `local_from_prefix`, default: None).
    pub local_from_prefix: Option<String>,

    /// Local from suffix (C: `local_from_suffix`, default: None).
    pub local_from_suffix: Option<String>,

    /// Log selector string (C: `log_selector_string`, default: None).
    pub log_selector_string: Option<String>,

    /// Message size limit (C: `message_size_limit`, default: "50M").
    pub message_size_limit: Option<String>,

    /// Max recipients (C: `recipients_max`, default: "50000").
    pub recipients_max: Option<String>,

    /// Max queue runners (C: `queue_run_max`, default: "5").
    pub queue_run_max: Option<String>,

    /// Queue domains (C: `queue_domains`, default: None).
    pub queue_domains: Option<String>,

    /// Queue SMTP domains (C: `queue_smtp_domains`, default: None).
    pub queue_smtp_domains: Option<String>,

    /// Queue-only file (C: `queue_only_file`, default: None).
    pub queue_only_file: Option<String>,

    /// Notifier socket path (C: `notifier_socket`).
    pub notifier_socket: Option<String>,

    /// Percent hack domains (C: `percent_hack_domains`, default: None).
    pub percent_hack_domains: Option<String>,

    /// Pipelining advertise hosts (C: `pipelining_advertise_hosts`, default: "*").
    pub pipelining_advertise_hosts: Option<String>,

    /// Received header text template (C: `received_header_text`).
    pub received_header_text: Option<String>,

    /// Hosts allowed to send unqualified recipients (C default: None).
    pub recipient_unqualified_hosts: Option<String>,

    /// Remote sort domains (C: `remote_sort_domains`, default: None).
    pub remote_sort_domains: Option<String>,

    /// RFC 1413 ident hosts (C: `rfc1413_hosts`, default: "@[]").
    pub rfc1413_hosts: Option<String>,

    /// Hosts allowed to send unqualified senders (C default: None).
    pub sender_unqualified_hosts: Option<String>,

    /// SMTP active hostname (C: `smtp_active_hostname`, default: None → primary_hostname).
    pub smtp_active_hostname: Option<String>,

    /// SMTP banner template (C: `smtp_banner`).
    pub smtp_banner: Option<String>,

    /// SMTP accept max per connection (C default: "1000").
    pub smtp_accept_max_per_connection: Option<String>,

    /// SMTP accept max per host (C default: None).
    pub smtp_accept_max_per_host: Option<String>,

    /// SMTP accept max nonmail hosts (C default: "*").
    pub smtp_accept_max_nonmail_hosts: Option<String>,

    /// SMTP ETRN command (C default: None).
    pub smtp_etrn_command: Option<String>,

    /// SMTP ratelimit hosts (C default: None).
    pub smtp_ratelimit_hosts: Option<String>,

    /// SMTP ratelimit mail params (C default: None).
    pub smtp_ratelimit_mail: Option<String>,

    /// SMTP ratelimit rcpt params (C default: None).
    pub smtp_ratelimit_rcpt: Option<String>,

    /// SMTP receive timeout string (C default: None).
    pub smtp_receive_timeout_s: Option<String>,

    /// SMTP reserve hosts (C default: None).
    pub smtp_reserve_hosts: Option<String>,

    /// System filter file (C default: None).
    pub system_filter: Option<String>,

    /// System filter directory transport (C default: None).
    pub system_filter_directory_transport: Option<String>,

    /// System filter file transport (C default: None).
    pub system_filter_file_transport: Option<String>,

    /// System filter pipe transport (C default: None).
    pub system_filter_pipe_transport: Option<String>,

    /// System filter reply transport (C default: None).
    pub system_filter_reply_transport: Option<String>,

    /// Syslog process name (C default: "exim").
    pub syslog_processname: Option<String>,

    /// TLS advertise hosts (C default: "*" when TLS enabled).
    pub tls_advertise_hosts: Option<String>,

    /// TLS certificate file (C default: None).
    #[cfg(feature = "tls")]
    pub tls_certificate: Option<String>,

    /// TLS private key file (C default: None).
    #[cfg(feature = "tls")]
    pub tls_privatekey: Option<String>,

    /// TLS verify certificates path (C default: "system").
    #[cfg(feature = "tls")]
    pub tls_verify_certificates: Option<String>,

    /// TLS CRL file (C default: None).
    #[cfg(feature = "tls")]
    pub tls_crl: Option<String>,

    /// TLS required ciphers (C default: None).
    #[cfg(feature = "tls")]
    pub tls_require_ciphers: Option<String>,

    /// TLS try verify hosts (C default: None).
    #[cfg(feature = "tls")]
    pub tls_try_verify_hosts: Option<String>,

    /// TLS mandatory verify hosts (C default: None).
    #[cfg(feature = "tls")]
    pub tls_verify_hosts: Option<String>,

    /// Bi-directional pipe command (C default: None).
    pub bi_command: Option<String>,

    /// Daemon modules to preload (C default: None).
    pub daemon_modules_load: Option<String>,

    /// Errors copy list (C default: None).
    pub errors_copy: Option<String>,

    /// Errors reply-to (C default: None).
    pub errors_reply_to: Option<String>,

    /// DNS domains that "again" means nonexistent (C default: None).
    pub dns_again_means_nonexist: Option<String>,

    /// Ignore fromline hosts (C default: None).
    pub ignore_fromline_hosts: Option<String>,

    // ── Content scanning (feature-gated) ────────────────────────────────
    /// Antivirus scanner configuration (C: `av_scanner`).
    #[cfg(feature = "content-scan")]
    pub av_scanner: Option<String>,

    /// SpamAssassin daemon address (C default: "127.0.0.1 783").
    #[cfg(feature = "content-scan")]
    pub spamd_address: Option<String>,

    // ── Syslog ──────────────────────────────────────────────────────────
    /// Syslog facility (C: `syslog_facility`, default: LOG_MAIL).
    pub syslog_facility: SyslogFacility,

    // ── Macros ──────────────────────────────────────────────────────────
    /// Stored macro definitions for `-bP` config printing.
    pub macros: Vec<MacroItemSnapshot>,
}

/// Default values for [`ConfigContext`] match the C `globals.c` initializers
/// exactly to preserve behavioral parity (AAP §0.7.1).
impl Default for ConfigContext {
    fn default() -> Self {
        tracing::trace!("initializing ConfigContext with C-compatible defaults");
        Self {
            // File metadata
            config_filename: String::new(),
            config_directory: String::new(),

            // Core paths — empty until parsed or auto-detected
            spool_directory: String::new(),
            log_file_path: String::new(),
            pid_file_path: String::new(),
            primary_hostname: String::new(),
            qualify_domain_sender: String::new(),
            qualify_domain_recipient: String::new(),

            // ACL definitions
            acl_definitions: BTreeMap::new(),
            acl_not_smtp: None,
            acl_smtp_auth: None,
            acl_smtp_connect: None,
            acl_smtp_data: None,
            acl_smtp_etrn: None,
            acl_smtp_expn: None,
            acl_smtp_helo: None,
            acl_smtp_mail: None,
            acl_smtp_rcpt: None,
            acl_smtp_vrfy: None,
            #[cfg(feature = "tls")]
            acl_smtp_starttls: None,
            #[cfg(feature = "prdr")]
            acl_smtp_data_prdr: None,
            #[cfg(feature = "dkim")]
            acl_smtp_dkim: None,
            #[cfg(feature = "content-scan")]
            acl_not_smtp_mime: None,
            #[cfg(feature = "content-scan")]
            acl_smtp_mime: None,
            #[cfg(feature = "wellknown")]
            acl_smtp_wellknown: None,
            acl_not_smtp_start: None,
            acl_smtp_mailauth: None,
            acl_smtp_notquit: None,
            acl_smtp_predata: None,
            acl_smtp_quit: None,
            acl_smtp_atrn: None,

            // Named lists
            named_lists: NamedLists::default(),

            // Driver instances — populated by driver_init
            auth_instances: Vec::new(),
            router_instances: Vec::new(),
            transport_instances: Vec::new(),

            // Rewrite and retry rules
            rewrite_rules: Vec::new(),
            retry_configs: Vec::new(),

            // Boolean config flags — C globals.c defaults
            accept_8bitmime: true, // C: TRUE (deliberately not RFC-compliant)
            allow_domain_literals: false, // C: FALSE
            allow_mx_to_ip: false, // C: FALSE
            bounce_return_body: true, // C: TRUE
            bounce_return_message: true, // C: TRUE
            #[cfg(feature = "i18n")]
            allow_utf8_domains: false, // C: FALSE
            check_rfc2047_length: true, // C: TRUE
            commandline_checks_require_admin: false, // C: FALSE
            delivery_date_remove: true, // C: TRUE
            envelope_to_remove: true, // C: TRUE
            local_from_check: true, // C: TRUE
            local_sender_retain: false, // C: FALSE
            log_timezone: false,   // C: FALSE
            message_logs: true,    // C: TRUE
            preserve_message_logs: false, // C: FALSE
            print_topbitchars: false, // C: FALSE
            prod_requires_admin: true, // C: TRUE
            queue_list_requires_admin: true, // C: TRUE
            queue_only: false,     // C: FALSE
            queue_only_load_latch: true, // C: TRUE
            queue_only_override: true, // C: TRUE
            queue_run_in_order: false, // C: FALSE
            recipients_max_reject: false, // C: FALSE
            return_path_remove: true, // C: TRUE
            smtp_accept_keepalive: true, // C: TRUE
            smtp_check_spool_space: true, // C: TRUE
            smtp_enforce_sync: true, // C: TRUE
            smtp_etrn_serialize: true, // C: TRUE
            smtp_return_error_details: false, // C: FALSE
            split_spool_directory: false, // C: FALSE
            strict_acl_vars: false, // C: FALSE
            strip_excess_angle_brackets: false, // C: FALSE
            strip_trailing_dot: false, // C: FALSE
            syslog_duplication: true, // C: TRUE
            syslog_pid: true,      // C: TRUE
            syslog_timestamp: true, // C: TRUE
            tcp_nodelay: true,     // C: TRUE
            write_rejectlog: true, // C: TRUE
            disable_ipv6: false,   // C: FALSE
            dns_csa_use_reverse: true, // C: TRUE
            ignore_fromline_local: false, // C: FALSE
            message_body_newlines: false, // C: FALSE
            deliver_drop_privilege: false, // C: FALSE
            extract_addresses_remove_arguments: true, // C: TRUE
            pipelining_enable: true, // C: TRUE (global flag)
            spool_wireformat: false, // C: FALSE
            timestamps_utc: false, // C: FALSE

            // Integer/time config options — C globals.c defaults
            auto_thaw: 0,                                           // C: 0
            connection_max_messages: -1,                            // C: -1 (unlimited)
            bounce_return_linesize_limit: 998,                      // C: 998
            bounce_return_size_limit: 100 * 1024,                   // C: 100*1024 (100 KB)
            callout_cache_domain_positive_expire: 7 * 24 * 60 * 60, // C: 7d
            callout_cache_domain_negative_expire: 3 * 60 * 60,      // C: 3h
            callout_cache_positive_expire: 24 * 60 * 60,            // C: 24h
            callout_cache_negative_expire: 2 * 60 * 60,             // C: 2h
            check_log_inodes: 100,                                  // C: 100
            check_log_space: 10 * 1024,                             // C: 10*1024 (10 MB in KB)
            check_spool_inodes: 100,                                // C: 100
            check_spool_space: 10 * 1024,                           // C: 10*1024 (10 MB in KB)
            daemon_startup_retries: 9,                              // C: 9
            daemon_startup_sleep: 30,                               // C: 30
            header_maxsize: 1024 * 1024, // C: HEADER_MAXSIZE (1 MB typical)
            header_insert_maxlen: 64 * 1024, // C: 64*1024
            header_line_maxsize: 0,      // C: 0 (unlimited)
            ignore_bounce_errors_after: 10 * 7 * 24 * 60 * 60, // C: 10 weeks
            keep_malformed: 4 * 24 * 60 * 60, // C: 4 days
            lookup_open_max: 25,         // C: 25
            message_body_visible: 500,   // C: 500
            received_headers_max: 30,    // C: 30
            remote_max_parallel: 6,      // C: 6
            retry_data_expire: 7 * 24 * 60 * 60, // C: 7 days
            retry_interval_max: 24 * 60 * 60, // C: 24 hours
            smtp_accept_queue: 0,        // C: 0
            smtp_accept_queue_per_connection: 10, // C: 10
            smtp_accept_reserve: 0,      // C: 0
            smtp_accept_max: 20,         // C: 20
            smtp_accept_max_nonmail: 10, // C: 10
            smtp_max_synprot_errors: 3,  // C: 3
            smtp_max_unknown_commands: 3, // C: 3
            smtp_receive_timeout: 5 * 60, // C: 5*60 (5 minutes)
            smtp_connect_backlog: 20,    // C: 20
            receive_timeout: 0,          // C: 0
            queue_interval: -1,          // C: -1
            timeout_frozen_after: 0,     // C: 0
            dns_csa_search_limit: 5,     // C: 5
            dns_cname_loops: 1,          // C: 1
            dns_retrans: 0,              // C: 0 (system default)
            dns_retry: 0,                // C: 0 (system default)
            rfc1413_query_timeout: 0,    // C: 0
            smtp_load_reserve: -1,       // C: -1
            queue_only_load: -1,         // C: -1
            deliver_queue_load_max: -1,  // C: -1

            // String config options
            auth_advertise_hosts: Some("*".to_string()), // C: US"*"
            bounce_message_file: None,
            bounce_message_text: None,
            bounce_sender_authentication: None,
            callout_random_local_part: None,
            check_dns_names_pattern: None,
            chunking_advertise_hosts: Some("*".to_string()), // C: US"*"
            daemon_smtp_port: Some("smtp".to_string()),
            delay_warning_condition: None,
            dns_ipv4_lookup: None,
            dns_trust_aa: None,
            dsn_from: None,
            dsn_advertise_hosts: None,
            extra_local_interfaces: None,
            freeze_tell: None,
            gecos_name: None,
            gecos_pattern: None,
            helo_accept_junk_hosts: None,
            helo_allow_chars: Some(String::new()),
            helo_lookup_domains: Some("@ : @[]".to_string()),
            helo_try_verify_hosts: None,
            helo_verify_hosts: None,
            hold_domains: None,
            host_lookup: None,
            host_lookup_order: Some("bydns:byaddr".to_string()),
            host_reject_connection: None,
            hosts_require_helo: Some("*".to_string()),
            hosts_treat_as_local: None,
            hosts_connection_nolog: None,
            keep_environment: None,
            add_environment: None,
            local_interfaces: None,
            local_from_prefix: None,
            local_from_suffix: None,
            log_selector_string: None,
            message_size_limit: Some("50M".to_string()), // C: US"50M"
            recipients_max: Some("50000".to_string()),
            queue_run_max: Some("5".to_string()),
            queue_domains: None,
            queue_smtp_domains: None,
            queue_only_file: None,
            notifier_socket: None,
            percent_hack_domains: None,
            pipelining_advertise_hosts: Some("*".to_string()), // C: US"*"
            received_header_text: None,
            recipient_unqualified_hosts: None,
            remote_sort_domains: None,
            rfc1413_hosts: Some("@[]".to_string()),
            sender_unqualified_hosts: None,
            smtp_active_hostname: None,
            smtp_banner: None,
            smtp_accept_max_per_connection: Some("1000".to_string()),
            smtp_accept_max_per_host: None,
            smtp_accept_max_nonmail_hosts: Some("*".to_string()),
            smtp_etrn_command: None,
            smtp_ratelimit_hosts: None,
            smtp_ratelimit_mail: None,
            smtp_ratelimit_rcpt: None,
            smtp_receive_timeout_s: None,
            smtp_reserve_hosts: None,
            system_filter: None,
            system_filter_directory_transport: None,
            system_filter_file_transport: None,
            system_filter_pipe_transport: None,
            system_filter_reply_transport: None,
            syslog_processname: Some("exim".to_string()),
            tls_advertise_hosts: Some("*".to_string()),
            #[cfg(feature = "tls")]
            tls_certificate: None,
            #[cfg(feature = "tls")]
            tls_privatekey: None,
            #[cfg(feature = "tls")]
            tls_verify_certificates: Some("system".to_string()),
            #[cfg(feature = "tls")]
            tls_crl: None,
            #[cfg(feature = "tls")]
            tls_require_ciphers: None,
            #[cfg(feature = "tls")]
            tls_try_verify_hosts: None,
            #[cfg(feature = "tls")]
            tls_verify_hosts: None,
            bi_command: None,
            daemon_modules_load: None,
            errors_copy: None,
            errors_reply_to: None,
            dns_again_means_nonexist: None,
            ignore_fromline_hosts: None,

            // Content scanning (feature-gated)
            #[cfg(feature = "content-scan")]
            av_scanner: None,
            #[cfg(feature = "content-scan")]
            spamd_address: Some("127.0.0.1 783".to_string()),

            // Syslog
            syslog_facility: SyslogFacility::Mail, // C: LOG_MAIL

            // Macros
            macros: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Config — Immutable configuration wrapper (AAP §0.4.4, §0.7.3)
// ---------------------------------------------------------------------------

/// Immutable configuration wrapper.
///
/// `Config` is created by freezing a [`ConfigContext`] via [`Config::freeze()`].
/// After freezing, the configuration is shared immutably via `Arc<Config>`
/// across all subsystems. This guarantees no mutable shared config state after
/// parsing (AAP §0.7.3).
///
/// The `Deref` implementation allows direct field access through `Arc<Config>`
/// without calling `.get()` explicitly.
///
/// # Example
/// ```ignore
/// let ctx = ConfigContext::default();
/// let config: Arc<Config> = Config::freeze(ctx);
/// assert!(config.accept_8bitmime); // Deref to ConfigContext
/// ```
#[derive(Debug)]
pub struct Config {
    inner: ConfigContext,
}

impl Config {
    /// Freeze a [`ConfigContext`] into an immutable `Arc<Config>`.
    ///
    /// After this call, the configuration cannot be modified. This enforces
    /// the "config data stored in `Arc<Config>` made immutable after parsing"
    /// rule (AAP §0.7.3).
    pub fn freeze(ctx: ConfigContext) -> Arc<Config> {
        tracing::debug!("freezing configuration into immutable Arc<Config>");
        Arc::new(Config { inner: ctx })
    }

    /// Access the underlying [`ConfigContext`] immutably.
    pub fn get(&self) -> &ConfigContext {
        &self.inner
    }
}

impl Deref for Config {
    type Target = ConfigContext;

    fn deref(&self) -> &ConfigContext {
        &self.inner
    }
}

// ---------------------------------------------------------------------------
// ServerContext — Daemon-lifetime state (AAP §0.4.4)
// ---------------------------------------------------------------------------

/// Daemon-lifetime server state, replacing daemon-related global variables
/// from `globals.c` / `globals.h`.
///
/// Per AAP §0.4.4, `ServerContext` holds: listening sockets, process table,
/// signal state, TLS credentials, and daemon-wide settings.
///
/// This struct is NOT frozen into `Arc` — it is owned by the daemon process
/// and mutated during operation (e.g., process table updates, connection
/// acceptance counting).
#[derive(Debug, Clone, Serialize)]
pub struct ServerContext {
    /// File descriptors for listening sockets (C: `daemon_listen_sockets`).
    pub listening_sockets: Vec<i32>,

    /// Active child process PIDs (C: `smtp_slots` array).
    pub process_table: Vec<u32>,

    /// Current number of accepted SMTP connections (C: `smtp_accept_count`).
    pub smtp_accept_count: i32,

    /// Max simultaneous SMTP connections (from config) (C: `smtp_accept_max`).
    pub smtp_accept_max: i32,

    /// TLS server credentials handle (opaque — actual type depends on TLS backend).
    /// `None` if TLS is not configured. Uses `Arc` for shared ownership.
    #[serde(skip)]
    pub tls_server_creds: Option<Arc<dyn std::any::Any + Send + Sync>>,

    /// Primary hostname for this server (C: `primary_hostname`).
    pub primary_hostname: String,

    /// Exim version string (C: `version_string`).
    pub version_string: String,

    /// Daemon process ID (C: getpid() result).
    pub pid: u32,

    /// Whether running inside the test harness (C: `f.running_in_test_harness`).
    pub running_in_test_harness: bool,

    /// Timestamp when the daemon was started.
    pub daemon_started: Option<SystemTime>,

    /// Timestamp for the start of the current connection.
    pub connection_start: Option<SystemTime>,

    /// Debug output selector bitmask (C: `debug_selector`).
    pub debug_selector: u64,

    /// Log output selector bitmask (C: `log_selector`).
    pub log_selector: u64,
}

impl Default for ServerContext {
    fn default() -> Self {
        Self {
            listening_sockets: Vec::new(),
            process_table: Vec::new(),
            smtp_accept_count: 0,
            smtp_accept_max: 20, // C: smtp_accept_max default
            tls_server_creds: None,
            primary_hostname: String::new(),
            version_string: String::from("Exim 4.99"),
            pid: 0,
            running_in_test_harness: false,
            daemon_started: None,
            connection_start: None,
            debug_selector: 0,
            log_selector: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// MessageContext — Per-message state (AAP §0.4.4)
// ---------------------------------------------------------------------------

/// Per-message state, replacing message-related global variables from
/// `globals.c` / `globals.h`.
///
/// Per AAP §0.4.4, `MessageContext` holds: sender, recipients, headers,
/// body reference, message ID, ACL variables, and per-message TLS state.
///
/// A new `MessageContext` is created for each message received. It is dropped
/// when message processing completes (analogous to the per-message arena in
/// the C allocator).
#[derive(Debug, Clone, Default, Serialize)]
pub struct MessageContext {
    /// Sender address of the current message (C: `sender_address`).
    pub sender_address: String,

    /// List of recipient addresses (C: `recipients_list` array).
    pub recipients: Vec<String>,

    /// Message headers as raw lines (C: `header_list` linked list).
    pub headers: Vec<String>,

    /// Unique message identifier (C: `message_id`, base-62 encoded).
    pub message_id: String,

    /// Message size in bytes (C: `message_size`).
    pub message_size: i64,

    /// Number of lines in the message body (C: `body_linecount`).
    pub body_linecount: i64,

    /// Authenticated user ID (C: `authenticated_id`).
    pub authenticated_id: Option<String>,

    /// Authenticated sender address (C: `authenticated_sender`).
    pub authenticated_sender: Option<String>,

    /// Sender host IP address (C: `sender_host_address`).
    pub sender_host_address: Option<String>,

    /// Sender host port (C: `sender_host_port`).
    pub sender_host_port: i32,

    /// Sender host name from reverse DNS (C: `sender_host_name`).
    pub sender_host_name: Option<String>,

    /// HELO/EHLO name presented by client (C: `sender_helo_name`).
    pub sender_helo_name: Option<String>,

    /// Protocol string (C: `received_protocol`, e.g., "esmtp", "esmtps").
    pub received_protocol: Option<String>,

    /// Inbound TLS state for this message (C: `tls_in` struct).
    pub tls_in: TlsInfo,

    /// ACL variables ($acl_c0..$acl_c9, $acl_m0..$acl_m9, etc.)
    /// (C: `acl_var_c[]` and `acl_var_m[]`).
    pub acl_vars: BTreeMap<String, String>,

    /// DSN envelope ID (C: `dsn_envid`).
    pub dsn_envid: Option<String>,

    /// DSN RET parameter (C: `dsn_ret`, 0 = not set, 1 = HDRS, 2 = FULL).
    pub dsn_ret: i32,

    /// Error message for local errors (C: `errmsg`).
    pub local_error_message: Option<String>,

    /// Reference to the message body data file path or spool location
    /// (C: `spool_data_file`, typically a file descriptor in C).
    pub message_reference: Option<String>,
}

// ---------------------------------------------------------------------------
// DeliveryContext — Per-delivery-attempt state (AAP §0.4.4)
// ---------------------------------------------------------------------------

/// Per-delivery-attempt state, replacing delivery-related global variables
/// from `globals.c` / `globals.h`.
///
/// Per AAP §0.4.4, `DeliveryContext` holds: current address, router/transport
/// results, retry data, and delivery-attempt-specific settings.
///
/// A new `DeliveryContext` is created for each address delivery attempt.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DeliveryContext {
    /// Local part of the current delivery address (C: `deliver_localpart`).
    pub deliver_localpart: String,

    /// Domain of the current delivery address (C: `deliver_domain`).
    pub deliver_domain: String,

    /// Original local part before any rewriting (C: `deliver_localpart_orig`).
    pub deliver_localpart_orig: String,

    /// Original domain before any rewriting (C: `deliver_domain_orig`).
    pub deliver_domain_orig: String,

    /// Delivery host name for remote delivery (C: `deliver_host`).
    pub deliver_host: Option<String>,

    /// Delivery host IP address (C: `deliver_host_address`).
    pub deliver_host_address: Option<String>,

    /// Delivery host port (C: `deliver_host_port`, default: 25).
    pub deliver_host_port: i32,

    /// Name of the transport being used (C: `transport_name`).
    pub transport_name: Option<String>,

    /// Name of the router that handled this address (C: `router_name`).
    pub router_name: Option<String>,

    /// Whether the message is frozen (C: `deliver_freeze`).
    pub deliver_freeze: bool,

    /// Force delivery even if frozen (C: `deliver_force`).
    pub deliver_force: bool,

    /// Force thaw of frozen message (C: `deliver_force_thaw`).
    pub deliver_force_thaw: bool,

    /// Message was manually thawed (C: `deliver_manual_thaw`).
    pub deliver_manual_thaw: bool,

    /// Data from router's local-part expansion (C: `deliver_localpart_data`).
    pub deliver_localpart_data: Option<String>,

    /// Data from router's domain expansion (C: `deliver_domain_data`).
    pub deliver_domain_data: Option<String>,

    /// Recipient-specific data from router (C: `deliver_address_data`).
    pub recipient_data: Option<String>,

    /// Sender-specific data (C: `sender_data`).
    pub sender_data: Option<String>,

    /// Lookup result value (C: `lookup_value`).
    pub lookup_value: Option<String>,

    /// Next retry interval in seconds (C: `retry_interval`).
    pub retry_interval: i32,

    /// Retry data key (C: `retry_key`).
    pub retry_data: Option<String>,

    /// Source IP address for sending (C: `sending_ip_address`).
    pub sending_ip_address: Option<String>,

    /// Source port for sending (C: `sending_port`).
    pub sending_port: i32,

    /// Home directory for the delivery user (C: `deliver_home`).
    pub deliver_home: Option<String>,
}
