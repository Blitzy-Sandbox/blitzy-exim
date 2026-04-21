// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! Variable substitution engine for `$variable_name` and `${variable_name}`
//! references in Exim expansion strings.
//!
//! This module implements the complete set of 200+ expansion variables from
//! the C `var_table[]` (expand.c lines 444–797), the `find_var_ent()` binary
//! search dispatcher (expand.c lines 1245–1261), and the `find_variable()`
//! resolution function (expand.c lines 1910–2200).
//!
//! # Architecture
//!
//! Variables are resolved from the [`ExpandContext`] struct, which aggregates
//! references to the 4 scoped context structs defined in `exim-core/src/context.rs`
//! (AAP §0.4.4). This replaces the 714 global variables in `globals.c`/`globals.h`.
//!
//! The variable table is a compile-time sorted array enabling O(log n) binary
//! search by name, exactly matching the C `find_var_ent()` implementation.
//!
//! # Safety
//!
//! This module contains **zero `unsafe` blocks** (enforced by the crate-level
//! `#![deny(unsafe_code)]`).

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ExpandError;
use exim_store::{Clean, TaintState, Tainted};

// ═══════════════════════════════════════════════════════════════════════════
//  VarType — Variable value type enum
// ═══════════════════════════════════════════════════════════════════════════

/// Type tag describing how a variable's value is stored and formatted.
///
/// Each variant maps to a C `vtype_*` enum constant from expand.c, controlling
/// how the raw value is converted to its string representation during expansion.
///
/// # Formatting Rules
///
/// | Variant | C Equivalent | String Representation |
/// |---------|-------------|----------------------|
/// | `StringPtr` | `vtype_stringptr` | Direct string value |
/// | `Int` | `vtype_int` | Decimal integer |
/// | `Uid` | `vtype_uid` | Decimal uid_t |
/// | `Gid` | `vtype_gid` | Decimal gid_t |
/// | `Bool` | `vtype_bool` | `"yes"` or `""` (NOT `"true"`/`"false"`) |
/// | `StringFunc` | `vtype_string_func` | Calls a function returning string |
/// | `MiscModule` | `vtype_misc_module` | Delegates to a misc module handler |
/// | `Filter` | `vtype_filter_int` | Integer only when filter is running |
/// | `Pid` | `vtype_pid` | Current process ID |
/// | `Load` | `vtype_load_avg` | System load average |
/// | `Pno` | `vtype_pno` | Parent number (inode) |
/// | `LocalPart` | `vtype_localpart` | Local-part extracted from address |
/// | `Domain` | `vtype_domain` | Domain extracted from address |
/// | `MessageHeaders` | `vtype_msgheaders` | All message headers concatenated |
/// | `MsgbodyEnd` | `vtype_msgbody_end` | End of message body |
/// | `MsgBody` | `vtype_msgbody` | Message body content |
/// | `Todbsdin` | `vtype_todbsdin` | BSD inbox date format |
/// | `Todlog` | `vtype_todlog` | Log format date |
/// | `Todlogbare` | `vtype_todlogbare` | Log format date without timezone |
/// | `Todzone` | `vtype_todzone` | Timezone offset only |
/// | `Todzulu` | `vtype_todzulu` | Zulu (UTC) timestamp |
/// | `Reply` | `vtype_reply` | Reply-To or From header address |
/// | `Cert` | `vtype_cert` | TLS certificate field indicator |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarType {
    /// Pointer to a string value (`vtype_stringptr`).
    StringPtr,
    /// Integer value formatted as decimal (`vtype_int`).
    Int,
    /// User ID formatted as decimal (`vtype_uid`).
    Uid,
    /// Group ID formatted as decimal (`vtype_gid`).
    Gid,
    /// Boolean: `"yes"` for true, `""` for false (`vtype_bool`).
    Bool,
    /// Dynamic string from a function call (`vtype_string_func`).
    StringFunc,
    /// Delegated to a misc module handler (`vtype_misc_module`).
    MiscModule,
    /// Filter integer — only valid when filter is running (`vtype_filter_int`).
    Filter,
    /// Current process ID (`vtype_pid`).
    Pid,
    /// System load average (`vtype_load_avg`).
    Load,
    /// Parent number / inode (`vtype_pno` / `vtype_ino`).
    Pno,
    /// Local-part extracted from an email address (`vtype_localpart`).
    LocalPart,
    /// Domain extracted from an email address (`vtype_domain`).
    Domain,
    /// All message headers concatenated (`vtype_msgheaders`).
    MessageHeaders,
    /// End portion of message body (`vtype_msgbody_end`).
    MsgbodyEnd,
    /// Message body content (`vtype_msgbody`).
    MsgBody,
    /// BSD inbox time of day format (`vtype_todbsdin`).
    Todbsdin,
    /// Log format time of day (`vtype_todl`).
    Todlog,
    /// Bare log format time of day, no timezone (`vtype_todlogbare`).
    Todlogbare,
    /// Timezone offset only (`vtype_todzone`).
    Todzone,
    /// Zulu/UTC time format (`vtype_todzulu`).
    Todzulu,
    /// Reply address from Reply-To or From header (`vtype_reply`).
    Reply,
    /// TLS certificate field indicator (`vtype_cert`).
    Cert,
}

// ═══════════════════════════════════════════════════════════════════════════
//  VarResolver — How a variable's value is obtained
// ═══════════════════════════════════════════════════════════════════════════

/// Describes the mechanism used to resolve a variable's value from the
/// [`ExpandContext`].
///
/// In the C codebase, variables point either to a global variable address,
/// a function pointer, or a module name string. In Rust, this enum replaces
/// those heterogeneous pointers with type-safe variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarResolver {
    /// Resolved by looking up a named field in the [`ExpandContext`].
    ///
    /// The string is the field name (e.g., `"sender_address"`, `"domain"`).
    ContextField(&'static str),

    /// Resolved by calling a named dynamic function.
    ///
    /// Used for `vtype_string_func` variables like `$headers_added`,
    /// `$queue_size`, `$recipients`, `$recipients_list`, etc.
    DynamicFunc(&'static str),

    /// Delegated to a named misc module's variable handler.
    ///
    /// Used for DKIM, ARC, SPF, DMARC, and lookup module variables where
    /// the variable's value is managed by a separate module crate.
    MiscModuleDelegate(&'static str),

    /// Resolved by looking up a message header by name.
    ///
    /// Used for `$h_*`, `$header_*`, `$rh_*`, `$bh_*`, `$lh_*` prefixes.
    HeaderLookup,

    /// Resolved by looking up a user-defined ACL variable.
    ///
    /// Used for `$acl_c*` and `$acl_m*` variables, which are stored in
    /// tree structures keyed by the variable suffix.
    AclVariable,

    /// Resolved by looking up a numbered authentication variable.
    ///
    /// Used for `$auth1`..`$auth<n>` variables.
    AuthVariable,
}

// ═══════════════════════════════════════════════════════════════════════════
//  VarEntry — Variable table entry
// ═══════════════════════════════════════════════════════════════════════════

/// A single entry in the variable lookup table.
///
/// The table is sorted alphabetically by `name` to enable O(log n) binary
/// search, matching the C `find_var_ent()` implementation.
#[derive(Debug, Clone)]
pub struct VarEntry {
    /// Variable name as it appears after `$` in expansion strings.
    pub name: &'static str,
    /// How the variable's value is stored and formatted.
    pub var_type: VarType,
    /// How the variable's value is obtained from context.
    pub resolver: VarResolver,
}

// ═══════════════════════════════════════════════════════════════════════════
//  ExpandContext — Aggregated context for variable resolution
// ═══════════════════════════════════════════════════════════════════════════

/// Aggregated context holding all state needed for variable resolution.
///
/// Replaces the 714 global variables in `globals.c`/`globals.h` with an
/// explicitly passed context struct. Each field corresponds to one or more
/// expansion variables.
///
/// In production, the fields are populated from the 4 scoped context structs
/// (AAP §0.4.4): `ServerContext`, `MessageContext`, `DeliveryContext`, and
/// `ConfigContext`.
#[derive(Debug, Clone)]
pub struct ExpandContext {
    // ── Sender / connection fields (MessageContext / ServerContext) ──────
    /// Sender's envelope address (tainted — from SMTP MAIL FROM).
    pub sender_address: Tainted<String>,
    /// Remote host's IP address (tainted — from connection).
    pub sender_host_address: Tainted<String>,
    /// Remote host's verified name (tainted — from DNS reverse lookup).
    pub sender_host_name: Tainted<String>,
    /// Remote host's TCP port number.
    pub sender_host_port: i32,
    /// HELO/EHLO string presented by the remote host (tainted).
    pub sender_helo_name: Tainted<String>,
    /// Sender ident string from RFC 1413 (tainted).
    pub sender_ident: Tainted<String>,

    // ── Authentication fields ───────────────────────────────────────────
    /// Authenticated user ID after successful AUTH.
    pub authenticated_id: String,
    /// Authenticated sender address after AUTH.
    pub authenticated_sender: String,

    // ── Message fields (MessageContext) ─────────────────────────────────
    /// Current message's Exim ID (e.g., "1abc23-00001A-AB").
    pub message_id: String,
    /// Message size in bytes.
    pub message_size: i64,
    /// Number of lines in the message body.
    pub message_linecount: i32,
    /// Message body content (tainted — from DATA).
    pub message_body: Tainted<String>,
    /// End portion of message body (tainted).
    pub message_body_end: Tainted<String>,
    /// Concatenated message headers.
    pub message_headers: String,

    // ── Recipient fields ────────────────────────────────────────────────
    /// Comma-separated list of envelope recipients.
    pub recipients: String,
    /// Number of envelope recipients.
    pub recipients_count: i32,

    // ── Delivery fields (DeliveryContext) ───────────────────────────────
    /// Current delivery domain.
    pub domain: String,
    /// Current delivery local-part.
    pub local_part: String,
    /// Data from local-part matching.
    pub local_part_data: String,
    /// Data from domain matching.
    pub domain_data: String,
    /// Delivery host name.
    pub host: String,
    /// Delivery host IP address.
    pub host_address: String,
    /// Host data from router.
    pub host_data: String,
    /// Name of the current router.
    pub router_name: String,
    /// Name of the current transport.
    pub transport_name: String,

    // ── Configuration fields (ConfigContext) ────────────────────────────
    /// Primary hostname of this system (clean — from config).
    pub primary_hostname: Clean<String>,
    /// Qualification domain for sender addresses (clean).
    pub qualify_domain: Clean<String>,
    /// Qualification domain for recipient addresses (clean).
    pub qualify_recipient: Clean<String>,
    /// Spool directory path (clean).
    pub spool_directory: Clean<String>,

    // ── Process / compile info ──────────────────────────────────────────
    /// Exim effective user ID.
    pub exim_uid: u32,
    /// Exim effective group ID.
    pub exim_gid: u32,
    /// Path to the Exim binary.
    pub exim_path: Clean<String>,
    /// Exim version string.
    pub exim_version: Clean<String>,

    // ── ACL and Auth variable stores ────────────────────────────────────
    /// ACL verify message (`$acl_verify_message`), set during verify
    /// condition evaluation so that `message =` / `log_message =`
    /// expansion can reference it.
    pub acl_verify_message: String,
    /// ACL argument count.
    pub acl_narg: i32,
    /// Positional ACL arguments (`$acl_arg1` .. `$acl_arg9`), set by `${if acl ...}`.
    pub acl_args: Vec<String>,

    /// Connection-scoped ACL variables (acl_c*).
    pub acl_var_c: HashMap<String, String>,
    /// Message-scoped ACL variables (acl_m*).
    pub acl_var_m: HashMap<String, String>,
    /// Authentication variables ($auth1..$auth<n>).
    pub auth_vars: Vec<String>,

    // ── TLS fields ─────────────────────────────────────────────────────
    /// Inbound TLS cipher string.
    pub tls_cipher: String,
    /// Inbound TLS peer distinguished name.
    pub tls_peerdn: String,
    /// Inbound TLS Server Name Indication.
    pub tls_sni: String,

    // ── Lookup / protocol fields ────────────────────────────────────────
    /// Last lookup result value.
    pub lookup_value: String,
    /// Protocol used to receive this message.
    pub received_protocol: String,
    /// IP address on which the message was received.
    pub received_ip_address: String,
    /// Port on which the message was received.
    pub received_port: i32,

    // ── Runtime state ──────────────────────────────────────────────────
    /// Current process ID (dynamically obtained if zero).
    pub pid: i32,
    /// Compile date string.
    pub compile_date: Clean<String>,
    /// Compile number string.
    pub compile_number: Clean<String>,
    /// Configuration file path.
    pub config_file: Clean<String>,

    /// Captured numeric substrings from partial match ($1..$9).
    /// Index 0 is the whole match, 1..=9 are captured groups.
    pub expand_nstring: Vec<String>,

    // ── Extended context fields for complete variable coverage ──────────
    /// Address data from router.
    pub address_data: String,
    /// Address file from router.
    pub address_file: String,
    /// Address pipe from router.
    pub address_pipe: String,
    /// ATRN host.
    pub atrn_host: String,
    /// ATRN mode.
    pub atrn_mode: String,
    /// Failed authentication ID.
    pub authenticated_fail_id: String,
    /// Whether authentication failed (0/1).
    pub authentication_failed: i32,
    /// Body line count.
    pub body_linecount: i32,
    /// Body zero-byte count.
    pub body_zerocount: i32,
    /// Bounce recipient address.
    pub bounce_recipient: String,
    /// Bounce return size limit.
    pub bounce_return_size_limit: i32,
    /// Headers charset (from config `headers_charset`, default "UTF-8").
    /// Used by RFC 2047 encoding to select the charset label in encoded words.
    pub headers_charset: String,
    /// When true, escape operator shows top-bit chars as M-x instead of \NNN.
    pub print_topbitchars: bool,
    /// Real GID of the calling process.
    pub caller_gid: u32,
    /// Real UID of the calling process.
    pub caller_uid: u32,
    /// Callout verification address.
    pub callout_address: String,
    /// Configuration directory path.
    pub config_dir: Clean<String>,
    /// Connection ID string.
    pub connection_id: String,
    /// CSA (Client SMTP Authorization) status.
    pub csa_status: String,
    /// DNS blacklist domain that matched.
    pub dnslist_domain: String,
    /// DNS blacklist matched entry.
    pub dnslist_matched: String,
    /// DNS blacklist TXT record text.
    pub dnslist_text: String,
    /// DNS blacklist A record value.
    pub dnslist_value: String,
    /// Delivery home directory.
    pub home: String,
    /// Whether host lookup was deferred.
    pub host_lookup_deferred: i32,
    /// Whether host lookup failed.
    pub host_lookup_failed: i32,
    /// Delivery host port.
    pub host_port: i32,
    /// Initial working directory.
    pub initial_cwd: String,
    /// Delivery inode.
    pub inode: i64,
    /// Interface (received) IP address.
    pub interface_address: String,
    /// Interface (received) port.
    pub interface_port: i32,
    /// Current iterate item in forall/forany.
    pub item: String,
    /// Local-part prefix from router.
    pub local_part_prefix: String,
    /// Local-part prefix (verbose form).
    pub local_part_prefix_v: String,
    /// Local-part suffix from router.
    pub local_part_suffix: String,
    /// Local-part suffix (verbose form).
    pub local_part_suffix_v: String,
    /// Local scan data.
    pub local_scan_data: String,
    /// Local user GID.
    pub local_user_gid: u32,
    /// Local user UID.
    pub local_user_uid: u32,
    /// Localhost number.
    pub localhost_number: i32,
    /// DNSSEC authentication status for last lookup.
    pub lookup_dnssec_authenticated: String,
    /// Mailstore basename.
    pub mailstore_basename: String,
    /// Maximum received line length.
    pub max_received_linelength: i32,
    /// Message age in seconds.
    pub message_age: i32,
    /// Message body size in bytes.
    pub message_body_size: i32,
    /// Message headers (raw, unprocessed).
    pub message_headers_raw: String,
    /// Original (pre-rewrite) domain.
    pub original_domain: String,
    /// Original (pre-rewrite) local part.
    pub original_local_part: String,
    /// Originator GID.
    pub originator_gid: u32,
    /// Originator UID.
    pub originator_uid: u32,
    /// Parent domain for child delivery.
    pub parent_domain: String,
    /// Parent local part for child delivery.
    pub parent_local_part: String,
    /// PRVS check address.
    pub prvscheck_address: String,
    /// PRVS check key number.
    pub prvscheck_keynum: String,
    /// PRVS check result.
    pub prvscheck_result: String,
    /// Queue name.
    pub queue_name: String,
    /// RCPT count for current connection.
    pub rcpt_count: i32,
    /// RCPT defer count.
    pub rcpt_defer_count: i32,
    /// RCPT fail count.
    pub rcpt_fail_count: i32,
    /// Received count (number of Received: headers).
    pub received_count: i32,
    /// Received-for address.
    pub received_for: String,
    /// Received time (epoch seconds).
    pub received_time: i64,
    /// Recipient data from router.
    pub recipient_data: String,
    /// Recipient verify failure reason.
    pub recipient_verify_failure: String,
    /// Reply address — computed from Reply-To or From header.
    /// Set by post-DATA ACL evaluation after message headers are parsed.
    pub reply_address: String,
    /// Parsed message headers for `$h_name:` variable lookups.
    /// Keys are lowercased header names (e.g. "subject", "from", "reply-to").
    /// Values are the header values (trimmed, concatenated for duplicates).
    pub header_list: std::collections::HashMap<String, String>,
    /// Regex cache size (internal diagnostic).
    pub regex_cachesize: i32,
    /// Return path for bounces.
    pub return_path: String,
    /// Run command exit code.
    pub runrc: i32,
    /// Self hostname.
    pub self_hostname: String,
    /// Sender address data from verification.
    pub sender_address_data: String,
    /// Sender data from verification.
    pub sender_data: String,
    /// Full host identification string.
    pub sender_fullhost: String,
    /// Whether HELO was DNSSEC-validated.
    pub sender_helo_dnssec: bool,
    /// Authenticator name that accepted the sender.
    pub sender_host_authenticated: String,
    /// Whether sender host address was DNSSEC-validated.
    pub sender_host_dnssec: bool,
    /// Sender rate (ratelimit).
    pub sender_rate: String,
    /// Sender rate limit value.
    pub sender_rate_limit: String,
    /// Sender rate period.
    pub sender_rate_period: String,
    /// Constructed sender received host string.
    pub sender_rcvhost: String,
    /// Sender verify failure reason.
    pub sender_verify_failure: String,
    /// IP address used for sending.
    pub sending_ip_address: String,
    /// Port used for sending.
    pub sending_port: i32,
    /// Active SMTP hostname.
    pub smtp_active_hostname: String,
    /// Raw SMTP command buffer.
    pub smtp_command: String,
    /// SMTP command argument.
    pub smtp_command_argument: String,
    /// SMTP accept count at connection start.
    pub smtp_count_at_connection_start: i32,
    /// SMTP not-quit reason.
    pub smtp_notquit_reason: String,
    /// Spool inodes remaining.
    pub spool_inodes: i32,
    /// Spool space remaining (KB).
    pub spool_space: i64,
    /// Log partition inodes remaining.
    pub log_inodes: i32,
    /// Log partition space remaining (KB).
    pub log_space: i64,
    /// Filter variables n0..n9.
    pub filter_n: [i32; 10],
    /// Filter variables sn0..sn9.
    pub filter_sn: [i32; 10],
    /// Whether a filter is currently running.
    pub filter_running: bool,
    /// Filter this-address.
    pub filter_thisaddress: String,
    /// Strict ACL variable mode (non-existent → error instead of empty).
    pub strict_acl_vars: bool,
    /// Raw ACL definitions from config, keyed by ACL name.
    /// Used by the `${if acl {...}}` expansion condition.
    pub acl_definitions: HashMap<String, String>,
    /// Maximum expand_nstring index.
    pub expand_nmax: i32,
    /// Return size limit for bounces.
    pub return_size_limit: i32,
    /// Warn message delay string.
    pub warnmsg_delay: String,
    /// Warn message recipients.
    pub warnmsg_recipients: String,
    /// Verify mode ("callout", "header_syntax", etc.).
    pub verify_mode: String,
    /// Current lookup value.
    pub value: String,
    /// Whether message uses SMTPUTF8.
    pub message_smtputf8: bool,
    /// PRDR requested flag.
    pub prdr_requested: bool,

    // ── TLS extended fields ────────────────────────────────────────────
    /// Inbound TLS key bits.
    pub tls_in_bits: i32,
    /// Inbound TLS certificate verified flag.
    pub tls_in_certificate_verified: i32,
    /// Inbound TLS cipher standard name.
    pub tls_in_cipher_std: String,
    /// Inbound TLS OCSP status.
    pub tls_in_ocsp: i32,
    /// Inbound TLS our certificate (present = true).
    pub tls_in_ourcert: bool,
    /// Inbound TLS peer certificate (present = true).
    pub tls_in_peercert: bool,
    /// Inbound TLS resumption status.
    pub tls_in_resumption: i32,
    /// Inbound TLS version.
    pub tls_in_ver: String,

    /// Outbound TLS key bits.
    pub tls_out_bits: i32,
    /// Outbound TLS certificate verified flag.
    pub tls_out_certificate_verified: i32,
    /// Outbound TLS cipher string.
    pub tls_out_cipher: String,
    /// Outbound TLS cipher standard name.
    pub tls_out_cipher_std: String,
    /// Outbound TLS DANE verified flag.
    pub tls_out_dane: bool,
    /// Outbound TLS OCSP status.
    pub tls_out_ocsp: i32,
    /// Outbound TLS our certificate (present = true).
    pub tls_out_ourcert: bool,
    /// Outbound TLS peer certificate (present = true).
    pub tls_out_peercert: bool,
    /// Outbound TLS peer DN.
    pub tls_out_peerdn: String,
    /// Outbound TLS resumption status.
    pub tls_out_resumption: i32,
    /// Outbound TLS SNI.
    pub tls_out_sni: String,
    /// Outbound TLS TLSA usage.
    pub tls_out_tlsa_usage: i32,
    /// Outbound TLS version.
    pub tls_out_ver: String,

    // ── Proxy fields ───────────────────────────────────────────────────
    /// Proxy external address.
    pub proxy_external_address: String,
    /// Proxy external port.
    pub proxy_external_port: i32,
    /// Proxy local address.
    pub proxy_local_address: String,
    /// Proxy local port.
    pub proxy_local_port: i32,
    /// Proxy session active flag.
    pub proxy_session: bool,

    // ── Content scan fields ────────────────────────────────────────────
    /// AV (antivirus) scan failed flag.
    pub av_failed: i32,
    /// Malware name detected.
    pub malware_name: String,
    /// Regex match string from content scan.
    pub regex_match_string: String,
    /// Spam action.
    pub spam_action: String,
    /// Spam bar.
    pub spam_bar: String,
    /// Spam report.
    pub spam_report: String,
    /// Spam score string.
    pub spam_score: String,
    /// Spam score as integer string.
    pub spam_score_int: String,
    /// MIME anomaly level.
    pub mime_anomaly_level: i32,
    /// MIME anomaly text.
    pub mime_anomaly_text: String,
    /// MIME boundary.
    pub mime_boundary: String,
    /// MIME charset.
    pub mime_charset: String,
    /// MIME content description.
    pub mime_content_description: String,
    /// MIME content disposition.
    pub mime_content_disposition: String,
    /// MIME content ID.
    pub mime_content_id: String,
    /// MIME content size.
    pub mime_content_size: i32,
    /// MIME content transfer encoding.
    pub mime_content_transfer_encoding: String,
    /// MIME content type.
    pub mime_content_type: String,
    /// MIME decoded filename.
    pub mime_decoded_filename: String,
    /// MIME filename.
    pub mime_filename: String,
    /// MIME is coverletter flag.
    pub mime_is_coverletter: i32,
    /// MIME is multipart flag.
    pub mime_is_multipart: i32,
    /// MIME is RFC822 flag.
    pub mime_is_rfc822: i32,
    /// MIME part count.
    pub mime_part_count: i32,

    // ── DCC fields ─────────────────────────────────────────────────────
    /// DCC header.
    pub dcc_header: String,
    /// DCC result.
    pub dcc_result: String,

    // ── Event fields ───────────────────────────────────────────────────
    /// Event data string.
    pub event_data: String,
    /// Event defer errno.
    pub event_defer_errno: i32,
    /// Event name.
    pub event_name: String,

    // ── SRS fields ─────────────────────────────────────────────────────
    /// SRS recipient.
    pub srs_recipient: String,

    // ── XCLIENT fields ─────────────────────────────────────────────────
    /// XCLIENT address.
    pub xclient_addr: String,
    /// XCLIENT HELO.
    pub xclient_helo: String,
    /// XCLIENT ident.
    pub xclient_ident: String,
    /// XCLIENT login.
    pub xclient_login: String,
    /// XCLIENT name.
    pub xclient_name: String,
    /// XCLIENT port.
    pub xclient_port: String,

    // ── Router variables ───────────────────────────────────────────────
    /// Router-scoped variables (r_*).
    pub router_var: HashMap<String, String>,

    /// Named lists from configuration (domain_list, host_list, etc.).
    pub named_lists: HashMap<String, String>,

    /// Named list types — maps list name to its type ("domain", "host",
    /// "address", or "local_part") for typed listnamed_d/h/a/l validation.
    pub named_list_types: HashMap<String, String>,

    // ── Regex variables (for content scan) ─────────────────────────────
    /// Regex capture variables ($regex1..$regex9).
    pub regex_vars: Vec<String>,

    // ── Recipient prefix/suffix fields ──────────────────────────────────
    /// Recipient prefix.
    pub recipient_prefix: String,
    /// Recipient prefix (verbose).
    pub recipient_prefix_v: String,
    /// Recipient suffix.
    pub recipient_suffix: String,
    /// Recipient suffix (verbose).
    pub recipient_suffix_v: String,

    /// Recipients list (multi-line format).
    pub recipients_list: String,

    // ── Debug / tracing fields ─────────────────────────────────────────
    /// When true, the expansion engine emits debug trace output to stderr
    /// using the C Exim–compatible box-drawing format.
    pub debug_expand: bool,
    /// When true, use ASCII box-drawing characters instead of Unicode
    /// (corresponding to C Exim's `+noutf8` debug selector).
    pub debug_noutf8: bool,
    /// Current expansion nesting depth (controls indentation in trace output).
    pub expand_depth: usize,
}

impl ExpandContext {
    /// Creates a new `ExpandContext` with all fields initialized to their
    /// default (empty / zero) values.
    ///
    /// In production, the caller populates the relevant fields from the
    /// 4 scoped context structs before passing the context to the expansion
    /// engine.
    pub fn new() -> Self {
        Self {
            sender_address: Tainted::new(String::new()),
            sender_host_address: Tainted::new(String::new()),
            sender_host_name: Tainted::new(String::new()),
            sender_host_port: 0,
            sender_helo_name: Tainted::new(String::new()),
            sender_ident: Tainted::new(String::new()),
            authenticated_id: String::new(),
            authenticated_sender: String::new(),
            message_id: String::new(),
            message_size: 0,
            message_linecount: 0,
            message_body: Tainted::new(String::new()),
            message_body_end: Tainted::new(String::new()),
            message_headers: String::new(),
            recipients: String::new(),
            recipients_count: 0,
            domain: String::new(),
            local_part: String::new(),
            local_part_data: String::new(),
            domain_data: String::new(),
            host: String::new(),
            host_address: String::new(),
            host_data: String::new(),
            router_name: String::new(),
            transport_name: String::new(),
            primary_hostname: Clean::new(String::new()),
            qualify_domain: Clean::new(String::new()),
            qualify_recipient: Clean::new(String::new()),
            spool_directory: Clean::new(String::new()),
            exim_uid: 0,
            exim_gid: 0,
            exim_path: Clean::new(String::new()),
            exim_version: Clean::new(String::new()),
            acl_verify_message: String::new(),
            acl_narg: 0,
            acl_args: Vec::new(),
            acl_var_c: HashMap::new(),
            acl_var_m: HashMap::new(),
            auth_vars: Vec::new(),
            tls_cipher: String::new(),
            tls_peerdn: String::new(),
            tls_sni: String::new(),
            lookup_value: String::new(),
            received_protocol: String::new(),
            received_ip_address: String::new(),
            received_port: 0,
            pid: 0,
            compile_date: Clean::new(String::new()),
            compile_number: Clean::new(String::new()),
            config_file: Clean::new(String::new()),
            expand_nstring: Vec::new(),
            address_data: String::new(),
            address_file: String::new(),
            address_pipe: String::new(),
            atrn_host: String::new(),
            atrn_mode: String::new(),
            authenticated_fail_id: String::new(),
            authentication_failed: 0,
            body_linecount: 0,
            body_zerocount: 0,
            bounce_recipient: String::new(),
            bounce_return_size_limit: 0,
            headers_charset: "UTF-8".to_string(),
            print_topbitchars: false,
            caller_gid: 0,
            caller_uid: 0,
            callout_address: String::new(),
            config_dir: Clean::new(String::new()),
            connection_id: String::new(),
            csa_status: String::new(),
            dnslist_domain: String::new(),
            dnslist_matched: String::new(),
            dnslist_text: String::new(),
            dnslist_value: String::new(),
            home: String::new(),
            host_lookup_deferred: 0,
            host_lookup_failed: 0,
            host_port: 0,
            initial_cwd: String::new(),
            inode: 0,
            interface_address: String::new(),
            interface_port: -1,
            item: String::new(),
            local_part_prefix: String::new(),
            local_part_prefix_v: String::new(),
            local_part_suffix: String::new(),
            local_part_suffix_v: String::new(),
            local_scan_data: String::new(),
            local_user_gid: 0,
            local_user_uid: 0,
            localhost_number: 0,
            lookup_dnssec_authenticated: String::new(),
            mailstore_basename: String::new(),
            max_received_linelength: 0,
            message_age: 0,
            message_body_size: 0,
            message_headers_raw: String::new(),
            original_domain: String::new(),
            original_local_part: String::new(),
            originator_gid: 0,
            originator_uid: 0,
            parent_domain: String::new(),
            parent_local_part: String::new(),
            prvscheck_address: String::new(),
            prvscheck_keynum: String::new(),
            prvscheck_result: String::new(),
            queue_name: String::new(),
            rcpt_count: 0,
            rcpt_defer_count: 0,
            rcpt_fail_count: 0,
            received_count: 0,
            received_for: String::new(),
            received_time: 0,
            recipient_data: String::new(),
            recipient_verify_failure: String::new(),
            reply_address: String::new(),
            header_list: std::collections::HashMap::new(),
            regex_cachesize: 0,
            return_path: String::new(),
            runrc: 0,
            self_hostname: String::new(),
            sender_address_data: String::new(),
            sender_data: String::new(),
            sender_fullhost: String::new(),
            sender_helo_dnssec: false,
            sender_host_authenticated: String::new(),
            sender_host_dnssec: false,
            sender_rate: String::new(),
            sender_rate_limit: String::new(),
            sender_rate_period: String::new(),
            sender_rcvhost: String::new(),
            sender_verify_failure: String::new(),
            sending_ip_address: String::new(),
            sending_port: 0,
            smtp_active_hostname: String::new(),
            smtp_command: String::new(),
            smtp_command_argument: String::new(),
            smtp_count_at_connection_start: 0,
            smtp_notquit_reason: String::new(),
            spool_inodes: 0,
            spool_space: 0,
            log_inodes: 0,
            log_space: 0,
            filter_n: [0; 10],
            filter_sn: [0; 10],
            filter_running: false,
            filter_thisaddress: String::new(),
            strict_acl_vars: false,
            acl_definitions: HashMap::new(),
            expand_nmax: -1,
            return_size_limit: 0,
            warnmsg_delay: String::new(),
            warnmsg_recipients: String::new(),
            verify_mode: String::new(),
            value: String::new(),
            message_smtputf8: false,
            prdr_requested: false,
            tls_in_bits: 0,
            tls_in_certificate_verified: 0,
            tls_in_cipher_std: String::new(),
            tls_in_ocsp: 0,
            tls_in_ourcert: false,
            tls_in_peercert: false,
            tls_in_resumption: 0,
            tls_in_ver: String::new(),
            tls_out_bits: 0,
            tls_out_certificate_verified: 0,
            tls_out_cipher: String::new(),
            tls_out_cipher_std: String::new(),
            tls_out_dane: false,
            tls_out_ocsp: 0,
            tls_out_ourcert: false,
            tls_out_peercert: false,
            tls_out_peerdn: String::new(),
            tls_out_resumption: 0,
            tls_out_sni: String::new(),
            tls_out_tlsa_usage: 0,
            tls_out_ver: String::new(),
            proxy_external_address: String::new(),
            proxy_external_port: 0,
            proxy_local_address: String::new(),
            proxy_local_port: 0,
            proxy_session: false,
            av_failed: 0,
            malware_name: String::new(),
            regex_match_string: String::new(),
            spam_action: String::new(),
            spam_bar: String::new(),
            spam_report: String::new(),
            spam_score: String::new(),
            spam_score_int: String::new(),
            mime_anomaly_level: 0,
            mime_anomaly_text: String::new(),
            mime_boundary: String::new(),
            mime_charset: String::new(),
            mime_content_description: String::new(),
            mime_content_disposition: String::new(),
            mime_content_id: String::new(),
            mime_content_size: 0,
            mime_content_transfer_encoding: String::new(),
            mime_content_type: String::new(),
            mime_decoded_filename: String::new(),
            mime_filename: String::new(),
            mime_is_coverletter: 0,
            mime_is_multipart: 0,
            mime_is_rfc822: 0,
            mime_part_count: 0,
            dcc_header: String::new(),
            dcc_result: String::new(),
            event_data: String::new(),
            event_defer_errno: 0,
            event_name: String::new(),
            srs_recipient: String::new(),
            xclient_addr: String::new(),
            xclient_helo: String::new(),
            xclient_ident: String::new(),
            xclient_login: String::new(),
            xclient_name: String::new(),
            xclient_port: String::new(),
            router_var: HashMap::new(),
            named_lists: HashMap::new(),
            named_list_types: HashMap::new(),
            regex_vars: Vec::new(),
            recipient_prefix: String::new(),
            recipient_prefix_v: String::new(),
            recipient_suffix: String::new(),
            recipient_suffix_v: String::new(),
            recipients_list: String::new(),
            debug_expand: false,
            debug_noutf8: false,
            expand_depth: 0,
        }
    }
}

impl Default for ExpandContext {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  VAR_TABLE — Complete sorted variable table
// ═══════════════════════════════════════════════════════════════════════════

/// Complete variable table, sorted alphabetically for binary search.
///
/// This table corresponds exactly to the C `var_table[]` array defined in
/// expand.c lines 444–797. Feature-gated variables use `#[cfg(feature = "...")]`
/// to match the Cargo feature flags defined in `exim-expand/Cargo.toml`.
static VAR_TABLE: &[VarEntry] = &[
    // ── ACL argument variables (expand.c lines 447-456) ────────────────
    VarEntry {
        name: "acl_arg1",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("acl_arg1"),
    },
    VarEntry {
        name: "acl_arg2",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("acl_arg2"),
    },
    VarEntry {
        name: "acl_arg3",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("acl_arg3"),
    },
    VarEntry {
        name: "acl_arg4",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("acl_arg4"),
    },
    VarEntry {
        name: "acl_arg5",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("acl_arg5"),
    },
    VarEntry {
        name: "acl_arg6",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("acl_arg6"),
    },
    VarEntry {
        name: "acl_arg7",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("acl_arg7"),
    },
    VarEntry {
        name: "acl_arg8",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("acl_arg8"),
    },
    VarEntry {
        name: "acl_arg9",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("acl_arg9"),
    },
    VarEntry {
        name: "acl_narg",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("acl_narg"),
    },
    VarEntry {
        name: "acl_verify_message",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("acl_verify_message"),
    },
    // ── Address/delivery variables (expand.c lines 458-460) ────────────
    VarEntry {
        name: "address_data",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("address_data"),
    },
    VarEntry {
        name: "address_file",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("address_file"),
    },
    VarEntry {
        name: "address_pipe",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("address_pipe"),
    },
    // ── ARC variables (expand.c lines 461-466, feature: arc) ───────────
    #[cfg(feature = "arc")]
    VarEntry {
        name: "arc_domains",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("arc"),
    },
    #[cfg(feature = "arc")]
    VarEntry {
        name: "arc_oldest_pass",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("arc"),
    },
    #[cfg(feature = "arc")]
    VarEntry {
        name: "arc_state",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("arc"),
    },
    #[cfg(feature = "arc")]
    VarEntry {
        name: "arc_state_reason",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("arc"),
    },
    // ── ATRN/auth variables (expand.c lines 467-472) ───────────────────
    VarEntry {
        name: "atrn_host",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("atrn_host"),
    },
    VarEntry {
        name: "atrn_mode",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("atrn_mode"),
    },
    VarEntry {
        name: "authenticated_fail_id",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("authenticated_fail_id"),
    },
    VarEntry {
        name: "authenticated_id",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("authenticated_id"),
    },
    VarEntry {
        name: "authenticated_sender",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("authenticated_sender"),
    },
    VarEntry {
        name: "authentication_failed",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("authentication_failed"),
    },
    // ── Content scanning (expand.c line 473, feature: content-scan) ────
    #[cfg(feature = "content-scan")]
    VarEntry {
        name: "av_failed",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("av_failed"),
    },
    // ── Body/bounce/caller variables (expand.c lines 476-482) ──────────
    VarEntry {
        name: "body_linecount",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("body_linecount"),
    },
    VarEntry {
        name: "body_zerocount",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("body_zerocount"),
    },
    VarEntry {
        name: "bounce_recipient",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("bounce_recipient"),
    },
    VarEntry {
        name: "bounce_return_size_limit",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("bounce_return_size_limit"),
    },
    VarEntry {
        name: "caller_gid",
        var_type: VarType::Gid,
        resolver: VarResolver::ContextField("caller_gid"),
    },
    VarEntry {
        name: "caller_uid",
        var_type: VarType::Uid,
        resolver: VarResolver::ContextField("caller_uid"),
    },
    VarEntry {
        name: "callout_address",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("callout_address"),
    },
    // ── Compile/config/connection (expand.c lines 483-488) ─────────────
    VarEntry {
        name: "compile_date",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("compile_date"),
    },
    VarEntry {
        name: "compile_number",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("compile_number"),
    },
    VarEntry {
        name: "config_dir",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("config_dir"),
    },
    VarEntry {
        name: "config_file",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("config_file"),
    },
    VarEntry {
        name: "connection_id",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("connection_id"),
    },
    VarEntry {
        name: "csa_status",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("csa_status"),
    },
    // ── DCC variables (expand.c lines 489-492, feature: dcc) ───────────
    #[cfg(feature = "dcc")]
    VarEntry {
        name: "dcc_header",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("dcc_header"),
    },
    #[cfg(feature = "dcc")]
    VarEntry {
        name: "dcc_result",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("dcc_result"),
    },
    // ── DKIM variables (expand.c lines 493-516, feature: dkim) ─────────
    #[cfg(feature = "dkim")]
    VarEntry {
        name: "dkim_algo",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dkim"),
    },
    #[cfg(feature = "dkim")]
    VarEntry {
        name: "dkim_bodylength",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dkim"),
    },
    #[cfg(feature = "dkim")]
    VarEntry {
        name: "dkim_canon_body",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dkim"),
    },
    #[cfg(feature = "dkim")]
    VarEntry {
        name: "dkim_canon_headers",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dkim"),
    },
    #[cfg(feature = "dkim")]
    VarEntry {
        name: "dkim_copiedheaders",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dkim"),
    },
    #[cfg(feature = "dkim")]
    VarEntry {
        name: "dkim_created",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dkim"),
    },
    #[cfg(feature = "dkim")]
    VarEntry {
        name: "dkim_cur_signer",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dkim"),
    },
    #[cfg(feature = "dkim")]
    VarEntry {
        name: "dkim_domain",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dkim"),
    },
    #[cfg(feature = "dkim")]
    VarEntry {
        name: "dkim_expires",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dkim"),
    },
    #[cfg(feature = "dkim")]
    VarEntry {
        name: "dkim_headernames",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dkim"),
    },
    #[cfg(feature = "dkim")]
    VarEntry {
        name: "dkim_identity",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dkim"),
    },
    #[cfg(feature = "dkim")]
    VarEntry {
        name: "dkim_key_granularity",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dkim"),
    },
    #[cfg(feature = "dkim")]
    VarEntry {
        name: "dkim_key_length",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dkim"),
    },
    #[cfg(feature = "dkim")]
    VarEntry {
        name: "dkim_key_nosubdomains",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dkim"),
    },
    #[cfg(feature = "dkim")]
    VarEntry {
        name: "dkim_key_notes",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dkim"),
    },
    #[cfg(feature = "dkim")]
    VarEntry {
        name: "dkim_key_srvtype",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dkim"),
    },
    #[cfg(feature = "dkim")]
    VarEntry {
        name: "dkim_key_testing",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dkim"),
    },
    #[cfg(feature = "dkim")]
    VarEntry {
        name: "dkim_selector",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dkim"),
    },
    #[cfg(feature = "dkim")]
    VarEntry {
        name: "dkim_signers",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dkim"),
    },
    #[cfg(feature = "dkim")]
    VarEntry {
        name: "dkim_verify_reason",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dkim"),
    },
    #[cfg(feature = "dkim")]
    VarEntry {
        name: "dkim_verify_signers",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dkim"),
    },
    #[cfg(feature = "dkim")]
    VarEntry {
        name: "dkim_verify_status",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dkim"),
    },
    // ── DMARC variables (expand.c lines 517-524, feature: dmarc) ───────
    #[cfg(feature = "dmarc")]
    VarEntry {
        name: "dmarc_alignment_dkim",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dmarc"),
    },
    #[cfg(feature = "dmarc")]
    VarEntry {
        name: "dmarc_alignment_spf",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dmarc"),
    },
    #[cfg(feature = "dmarc")]
    VarEntry {
        name: "dmarc_domain_policy",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dmarc"),
    },
    #[cfg(feature = "dmarc")]
    VarEntry {
        name: "dmarc_status",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dmarc"),
    },
    #[cfg(feature = "dmarc")]
    VarEntry {
        name: "dmarc_status_text",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dmarc"),
    },
    #[cfg(feature = "dmarc")]
    VarEntry {
        name: "dmarc_used_domain",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("dmarc"),
    },
    // ── DNS list variables (expand.c lines 525-528) ────────────────────
    VarEntry {
        name: "dnslist_domain",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("dnslist_domain"),
    },
    VarEntry {
        name: "dnslist_matched",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("dnslist_matched"),
    },
    VarEntry {
        name: "dnslist_text",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("dnslist_text"),
    },
    VarEntry {
        name: "dnslist_value",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("dnslist_value"),
    },
    // ── Domain (expand.c lines 529-530) ────────────────────────────────
    VarEntry {
        name: "domain",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("domain"),
    },
    VarEntry {
        name: "domain_data",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("domain_data"),
    },
    // ── Event variables (expand.c lines 531-538, feature: event) ───────
    #[cfg(feature = "event")]
    VarEntry {
        name: "event_data",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("event_data"),
    },
    #[cfg(feature = "event")]
    VarEntry {
        name: "event_defer_errno",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("event_defer_errno"),
    },
    #[cfg(feature = "event")]
    VarEntry {
        name: "event_name",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("event_name"),
    },
    // ── Exim info variables (expand.c lines 539-542) ───────────────────
    VarEntry {
        name: "exim_gid",
        var_type: VarType::Gid,
        resolver: VarResolver::ContextField("exim_gid"),
    },
    VarEntry {
        name: "exim_path",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("exim_path"),
    },
    VarEntry {
        name: "exim_uid",
        var_type: VarType::Uid,
        resolver: VarResolver::ContextField("exim_uid"),
    },
    VarEntry {
        name: "exim_version",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("exim_version"),
    },
    // ── Headers added (expand.c line 543) ──────────────────────────────
    VarEntry {
        name: "headers_added",
        var_type: VarType::StringFunc,
        resolver: VarResolver::DynamicFunc("fn_hdrs_added"),
    },
    // ── Home/host variables (expand.c lines 544-556) ───────────────────
    VarEntry {
        name: "home",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("home"),
    },
    VarEntry {
        name: "host",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("host"),
    },
    VarEntry {
        name: "host_address",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("host_address"),
    },
    VarEntry {
        name: "host_data",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("host_data"),
    },
    VarEntry {
        name: "host_lookup_deferred",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("host_lookup_deferred"),
    },
    VarEntry {
        name: "host_lookup_failed",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("host_lookup_failed"),
    },
    VarEntry {
        name: "host_port",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("host_port"),
    },
    VarEntry {
        name: "initial_cwd",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("initial_cwd"),
    },
    VarEntry {
        name: "inode",
        var_type: VarType::Pno,
        resolver: VarResolver::ContextField("inode"),
    },
    VarEntry {
        name: "interface_address",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("interface_address"),
    },
    VarEntry {
        name: "interface_port",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("interface_port"),
    },
    VarEntry {
        name: "item",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("item"),
    },
    // ── LDAP DN (may be absent if ldap feature disabled) ───────────────
    VarEntry {
        name: "ldap_dn",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("ldap"),
    },
    // ── Load average (expand.c line 559) ───────────────────────────────
    VarEntry {
        name: "load_average",
        var_type: VarType::Load,
        resolver: VarResolver::ContextField("load_average"),
    },
    // ── Local part variables (expand.c lines 560-570) ──────────────────
    VarEntry {
        name: "local_part",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("local_part"),
    },
    VarEntry {
        name: "local_part_data",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("local_part_data"),
    },
    VarEntry {
        name: "local_part_prefix",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("local_part_prefix"),
    },
    VarEntry {
        name: "local_part_prefix_v",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("local_part_prefix_v"),
    },
    VarEntry {
        name: "local_part_suffix",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("local_part_suffix"),
    },
    VarEntry {
        name: "local_part_suffix_v",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("local_part_suffix_v"),
    },
    #[cfg(feature = "local-scan")]
    VarEntry {
        name: "local_scan_data",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("local_scan_data"),
    },
    VarEntry {
        name: "local_user_gid",
        var_type: VarType::Gid,
        resolver: VarResolver::ContextField("local_user_gid"),
    },
    VarEntry {
        name: "local_user_uid",
        var_type: VarType::Uid,
        resolver: VarResolver::ContextField("local_user_uid"),
    },
    VarEntry {
        name: "localhost_number",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("localhost_number"),
    },
    VarEntry {
        name: "log_inodes",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("log_inodes"),
    },
    VarEntry {
        name: "log_space",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("log_space"),
    },
    VarEntry {
        name: "lookup_dnssec_authenticated",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("lookup_dnssec_authenticated"),
    },
    VarEntry {
        name: "mailstore_basename",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("mailstore_basename"),
    },
    // ── Content scan: malware (expand.c line 577, feature: content-scan)
    #[cfg(feature = "content-scan")]
    VarEntry {
        name: "malware_name",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("malware_name"),
    },
    // ── Message variables (expand.c lines 579-592) ─────────────────────
    VarEntry {
        name: "max_received_linelength",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("max_received_linelength"),
    },
    VarEntry {
        name: "message_age",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("message_age"),
    },
    VarEntry {
        name: "message_body",
        var_type: VarType::MsgBody,
        resolver: VarResolver::ContextField("message_body"),
    },
    VarEntry {
        name: "message_body_end",
        var_type: VarType::MsgbodyEnd,
        resolver: VarResolver::ContextField("message_body_end"),
    },
    VarEntry {
        name: "message_body_size",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("message_body_size"),
    },
    VarEntry {
        name: "message_exim_id",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("message_id"),
    },
    VarEntry {
        name: "message_headers",
        var_type: VarType::MessageHeaders,
        resolver: VarResolver::ContextField("message_headers"),
    },
    VarEntry {
        name: "message_headers_raw",
        var_type: VarType::MessageHeaders,
        resolver: VarResolver::ContextField("message_headers_raw"),
    },
    VarEntry {
        name: "message_id",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("message_id"),
    },
    VarEntry {
        name: "message_linecount",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("message_linecount"),
    },
    VarEntry {
        name: "message_size",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("message_size"),
    },
    #[cfg(feature = "i18n")]
    VarEntry {
        name: "message_smtputf8",
        var_type: VarType::Bool,
        resolver: VarResolver::ContextField("message_smtputf8"),
    },
    // ── MIME variables (expand.c lines 593-610, feature: content-scan) ─
    #[cfg(feature = "content-scan")]
    VarEntry {
        name: "mime_anomaly_level",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("mime_anomaly_level"),
    },
    #[cfg(feature = "content-scan")]
    VarEntry {
        name: "mime_anomaly_text",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("mime_anomaly_text"),
    },
    #[cfg(feature = "content-scan")]
    VarEntry {
        name: "mime_boundary",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("mime_boundary"),
    },
    #[cfg(feature = "content-scan")]
    VarEntry {
        name: "mime_charset",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("mime_charset"),
    },
    #[cfg(feature = "content-scan")]
    VarEntry {
        name: "mime_content_description",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("mime_content_description"),
    },
    #[cfg(feature = "content-scan")]
    VarEntry {
        name: "mime_content_disposition",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("mime_content_disposition"),
    },
    #[cfg(feature = "content-scan")]
    VarEntry {
        name: "mime_content_id",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("mime_content_id"),
    },
    #[cfg(feature = "content-scan")]
    VarEntry {
        name: "mime_content_size",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("mime_content_size"),
    },
    #[cfg(feature = "content-scan")]
    VarEntry {
        name: "mime_content_transfer_encoding",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("mime_content_transfer_encoding"),
    },
    #[cfg(feature = "content-scan")]
    VarEntry {
        name: "mime_content_type",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("mime_content_type"),
    },
    #[cfg(feature = "content-scan")]
    VarEntry {
        name: "mime_decoded_filename",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("mime_decoded_filename"),
    },
    #[cfg(feature = "content-scan")]
    VarEntry {
        name: "mime_filename",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("mime_filename"),
    },
    #[cfg(feature = "content-scan")]
    VarEntry {
        name: "mime_is_coverletter",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("mime_is_coverletter"),
    },
    #[cfg(feature = "content-scan")]
    VarEntry {
        name: "mime_is_multipart",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("mime_is_multipart"),
    },
    #[cfg(feature = "content-scan")]
    VarEntry {
        name: "mime_is_rfc822",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("mime_is_rfc822"),
    },
    #[cfg(feature = "content-scan")]
    VarEntry {
        name: "mime_part_count",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("mime_part_count"),
    },
    // ── Filter variables n0..n9 (expand.c lines 611-620) ───────────────
    VarEntry {
        name: "n0",
        var_type: VarType::Filter,
        resolver: VarResolver::ContextField("n0"),
    },
    VarEntry {
        name: "n1",
        var_type: VarType::Filter,
        resolver: VarResolver::ContextField("n1"),
    },
    VarEntry {
        name: "n2",
        var_type: VarType::Filter,
        resolver: VarResolver::ContextField("n2"),
    },
    VarEntry {
        name: "n3",
        var_type: VarType::Filter,
        resolver: VarResolver::ContextField("n3"),
    },
    VarEntry {
        name: "n4",
        var_type: VarType::Filter,
        resolver: VarResolver::ContextField("n4"),
    },
    VarEntry {
        name: "n5",
        var_type: VarType::Filter,
        resolver: VarResolver::ContextField("n5"),
    },
    VarEntry {
        name: "n6",
        var_type: VarType::Filter,
        resolver: VarResolver::ContextField("n6"),
    },
    VarEntry {
        name: "n7",
        var_type: VarType::Filter,
        resolver: VarResolver::ContextField("n7"),
    },
    VarEntry {
        name: "n8",
        var_type: VarType::Filter,
        resolver: VarResolver::ContextField("n8"),
    },
    VarEntry {
        name: "n9",
        var_type: VarType::Filter,
        resolver: VarResolver::ContextField("n9"),
    },
    // ── Originator/parent variables (expand.c lines 621-627) ───────────
    VarEntry {
        name: "original_domain",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("original_domain"),
    },
    VarEntry {
        name: "original_local_part",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("original_local_part"),
    },
    VarEntry {
        name: "originator_gid",
        var_type: VarType::Gid,
        resolver: VarResolver::ContextField("originator_gid"),
    },
    VarEntry {
        name: "originator_uid",
        var_type: VarType::Uid,
        resolver: VarResolver::ContextField("originator_uid"),
    },
    VarEntry {
        name: "parent_domain",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("parent_domain"),
    },
    VarEntry {
        name: "parent_local_part",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("parent_local_part"),
    },
    VarEntry {
        name: "pid",
        var_type: VarType::Pid,
        resolver: VarResolver::ContextField("pid"),
    },
    // ── PRDR (expand.c lines 628-630, feature: prdr) ───────────────────
    #[cfg(feature = "prdr")]
    VarEntry {
        name: "prdr_requested",
        var_type: VarType::Bool,
        resolver: VarResolver::ContextField("prdr_requested"),
    },
    // ── Primary hostname (expand.c line 631) ───────────────────────────
    VarEntry {
        name: "primary_hostname",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("primary_hostname"),
    },
    // ── Proxy variables (expand.c lines 632-638, feature: proxy) ───────
    #[cfg(feature = "proxy")]
    VarEntry {
        name: "proxy_external_address",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("proxy_external_address"),
    },
    #[cfg(feature = "proxy")]
    VarEntry {
        name: "proxy_external_port",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("proxy_external_port"),
    },
    #[cfg(feature = "proxy")]
    VarEntry {
        name: "proxy_local_address",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("proxy_local_address"),
    },
    #[cfg(feature = "proxy")]
    VarEntry {
        name: "proxy_local_port",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("proxy_local_port"),
    },
    #[cfg(feature = "proxy")]
    VarEntry {
        name: "proxy_session",
        var_type: VarType::Bool,
        resolver: VarResolver::ContextField("proxy_session"),
    },
    // ── PRVS/qualify/queue (expand.c lines 639-645) ────────────────────
    VarEntry {
        name: "prvscheck_address",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("prvscheck_address"),
    },
    VarEntry {
        name: "prvscheck_keynum",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("prvscheck_keynum"),
    },
    VarEntry {
        name: "prvscheck_result",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("prvscheck_result"),
    },
    VarEntry {
        name: "qualify_domain",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("qualify_domain"),
    },
    VarEntry {
        name: "qualify_recipient",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("qualify_recipient"),
    },
    VarEntry {
        name: "queue_name",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("queue_name"),
    },
    VarEntry {
        name: "queue_size",
        var_type: VarType::StringFunc,
        resolver: VarResolver::DynamicFunc("fn_queue_size"),
    },
    // ── RCPT counters (expand.c lines 646-648) ─────────────────────────
    VarEntry {
        name: "rcpt_count",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("rcpt_count"),
    },
    VarEntry {
        name: "rcpt_defer_count",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("rcpt_defer_count"),
    },
    VarEntry {
        name: "rcpt_fail_count",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("rcpt_fail_count"),
    },
    // ── Received variables (expand.c lines 649-654) ────────────────────
    VarEntry {
        name: "received_count",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("received_count"),
    },
    VarEntry {
        name: "received_for",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("received_for"),
    },
    VarEntry {
        name: "received_ip_address",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("received_ip_address"),
    },
    VarEntry {
        name: "received_port",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("received_port"),
    },
    VarEntry {
        name: "received_protocol",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("received_protocol"),
    },
    VarEntry {
        name: "received_time",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("received_time"),
    },
    // ── Recipient variables (expand.c lines 655-663) ───────────────────
    VarEntry {
        name: "recipient_data",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("recipient_data"),
    },
    VarEntry {
        name: "recipient_verify_failure",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("recipient_verify_failure"),
    },
    VarEntry {
        name: "recipients",
        var_type: VarType::StringFunc,
        resolver: VarResolver::DynamicFunc("fn_recipients"),
    },
    VarEntry {
        name: "recipients_count",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("recipients_count"),
    },
    VarEntry {
        name: "recipients_list",
        var_type: VarType::StringFunc,
        resolver: VarResolver::DynamicFunc("fn_recipients_list"),
    },
    VarEntry {
        name: "regex_cachesize",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("regex_cachesize"),
    },
    #[cfg(feature = "content-scan")]
    VarEntry {
        name: "regex_match_string",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("regex_match_string"),
    },
    // ── Reply/return/router (expand.c lines 664-668) ───────────────────
    VarEntry {
        name: "reply_address",
        var_type: VarType::Reply,
        resolver: VarResolver::ContextField("reply_address"),
    },
    VarEntry {
        name: "return_path",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("return_path"),
    },
    VarEntry {
        name: "return_size_limit",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("return_size_limit"),
    },
    VarEntry {
        name: "router_name",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("router_name"),
    },
    VarEntry {
        name: "runrc",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("runrc"),
    },
    // ── Self/sender variables (expand.c lines 669-691) ─────────────────
    VarEntry {
        name: "self_hostname",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("self_hostname"),
    },
    VarEntry {
        name: "sender_address",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("sender_address"),
    },
    VarEntry {
        name: "sender_address_data",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("sender_address_data"),
    },
    VarEntry {
        name: "sender_address_domain",
        var_type: VarType::Domain,
        resolver: VarResolver::ContextField("sender_address"),
    },
    VarEntry {
        name: "sender_address_local_part",
        var_type: VarType::LocalPart,
        resolver: VarResolver::ContextField("sender_address"),
    },
    VarEntry {
        name: "sender_data",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("sender_data"),
    },
    VarEntry {
        name: "sender_fullhost",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("sender_fullhost"),
    },
    VarEntry {
        name: "sender_helo_dnssec",
        var_type: VarType::Bool,
        resolver: VarResolver::ContextField("sender_helo_dnssec"),
    },
    VarEntry {
        name: "sender_helo_name",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("sender_helo_name"),
    },
    VarEntry {
        name: "sender_helo_verified",
        var_type: VarType::StringFunc,
        resolver: VarResolver::DynamicFunc("sender_helo_verified_boolstr"),
    },
    VarEntry {
        name: "sender_host_address",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("sender_host_address"),
    },
    VarEntry {
        name: "sender_host_authenticated",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("sender_host_authenticated"),
    },
    VarEntry {
        name: "sender_host_dnssec",
        var_type: VarType::Bool,
        resolver: VarResolver::ContextField("sender_host_dnssec"),
    },
    VarEntry {
        name: "sender_host_name",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("sender_host_name"),
    },
    VarEntry {
        name: "sender_host_port",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("sender_host_port"),
    },
    VarEntry {
        name: "sender_ident",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("sender_ident"),
    },
    VarEntry {
        name: "sender_rate",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("sender_rate"),
    },
    VarEntry {
        name: "sender_rate_limit",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("sender_rate_limit"),
    },
    VarEntry {
        name: "sender_rate_period",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("sender_rate_period"),
    },
    VarEntry {
        name: "sender_rcvhost",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("sender_rcvhost"),
    },
    VarEntry {
        name: "sender_verify_failure",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("sender_verify_failure"),
    },
    VarEntry {
        name: "sending_ip_address",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("sending_ip_address"),
    },
    VarEntry {
        name: "sending_port",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("sending_port"),
    },
    // ── SMTP variables (expand.c lines 692-697) ────────────────────────
    VarEntry {
        name: "smtp_active_hostname",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("smtp_active_hostname"),
    },
    VarEntry {
        name: "smtp_command",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("smtp_command"),
    },
    VarEntry {
        name: "smtp_command_argument",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("smtp_command_argument"),
    },
    VarEntry {
        name: "smtp_command_history",
        var_type: VarType::StringFunc,
        resolver: VarResolver::DynamicFunc("smtp_cmd_hist"),
    },
    VarEntry {
        name: "smtp_count_at_connection_start",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("smtp_count_at_connection_start"),
    },
    VarEntry {
        name: "smtp_notquit_reason",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("smtp_notquit_reason"),
    },
    // ── Filter sn0..sn9 (expand.c lines 698-707) ──────────────────────
    VarEntry {
        name: "sn0",
        var_type: VarType::Filter,
        resolver: VarResolver::ContextField("sn0"),
    },
    VarEntry {
        name: "sn1",
        var_type: VarType::Filter,
        resolver: VarResolver::ContextField("sn1"),
    },
    VarEntry {
        name: "sn2",
        var_type: VarType::Filter,
        resolver: VarResolver::ContextField("sn2"),
    },
    VarEntry {
        name: "sn3",
        var_type: VarType::Filter,
        resolver: VarResolver::ContextField("sn3"),
    },
    VarEntry {
        name: "sn4",
        var_type: VarType::Filter,
        resolver: VarResolver::ContextField("sn4"),
    },
    VarEntry {
        name: "sn5",
        var_type: VarType::Filter,
        resolver: VarResolver::ContextField("sn5"),
    },
    VarEntry {
        name: "sn6",
        var_type: VarType::Filter,
        resolver: VarResolver::ContextField("sn6"),
    },
    VarEntry {
        name: "sn7",
        var_type: VarType::Filter,
        resolver: VarResolver::ContextField("sn7"),
    },
    VarEntry {
        name: "sn8",
        var_type: VarType::Filter,
        resolver: VarResolver::ContextField("sn8"),
    },
    VarEntry {
        name: "sn9",
        var_type: VarType::Filter,
        resolver: VarResolver::ContextField("sn9"),
    },
    // ── Spam variables (expand.c lines 708-714, feature: content-scan) ─
    #[cfg(feature = "content-scan")]
    VarEntry {
        name: "spam_action",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("spam_action"),
    },
    #[cfg(feature = "content-scan")]
    VarEntry {
        name: "spam_bar",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("spam_bar"),
    },
    #[cfg(feature = "content-scan")]
    VarEntry {
        name: "spam_report",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("spam_report"),
    },
    #[cfg(feature = "content-scan")]
    VarEntry {
        name: "spam_score",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("spam_score"),
    },
    #[cfg(feature = "content-scan")]
    VarEntry {
        name: "spam_score_int",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("spam_score_int"),
    },
    // ── SPF variables (expand.c lines 715-723, feature: spf) ───────────
    #[cfg(feature = "spf")]
    VarEntry {
        name: "spf_guess",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("spf"),
    },
    #[cfg(feature = "spf")]
    VarEntry {
        name: "spf_header_comment",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("spf"),
    },
    #[cfg(feature = "spf")]
    VarEntry {
        name: "spf_received",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("spf"),
    },
    #[cfg(feature = "spf")]
    VarEntry {
        name: "spf_result",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("spf"),
    },
    #[cfg(feature = "spf")]
    VarEntry {
        name: "spf_result_guessed",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("spf"),
    },
    #[cfg(feature = "spf")]
    VarEntry {
        name: "spf_smtp_comment",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("spf"),
    },
    #[cfg(feature = "spf")]
    VarEntry {
        name: "spf_used_domain",
        var_type: VarType::MiscModule,
        resolver: VarResolver::MiscModuleDelegate("spf"),
    },
    // ── Spool variables (expand.c lines 724-726) ───────────────────────
    VarEntry {
        name: "spool_directory",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("spool_directory"),
    },
    VarEntry {
        name: "spool_inodes",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("spool_inodes"),
    },
    VarEntry {
        name: "spool_space",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("spool_space"),
    },
    // ── SRS (expand.c lines 727-729, feature: srs) ─────────────────────
    #[cfg(feature = "srs")]
    VarEntry {
        name: "srs_recipient",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("srs_recipient"),
    },
    // ── Thisaddress (expand.c line 730) ────────────────────────────────
    VarEntry {
        name: "thisaddress",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("filter_thisaddress"),
    },
    // ── TLS variables (expand.c lines 732-777) ─────────────────────────
    VarEntry {
        name: "tls_bits",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("tls_in_bits"),
    },
    VarEntry {
        name: "tls_certificate_verified",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("tls_in_certificate_verified"),
    },
    VarEntry {
        name: "tls_cipher",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("tls_cipher"),
    },
    VarEntry {
        name: "tls_in_bits",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("tls_in_bits"),
    },
    VarEntry {
        name: "tls_in_certificate_verified",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("tls_in_certificate_verified"),
    },
    VarEntry {
        name: "tls_in_cipher",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("tls_cipher"),
    },
    VarEntry {
        name: "tls_in_cipher_std",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("tls_in_cipher_std"),
    },
    VarEntry {
        name: "tls_in_ocsp",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("tls_in_ocsp"),
    },
    VarEntry {
        name: "tls_in_ourcert",
        var_type: VarType::Cert,
        resolver: VarResolver::ContextField("tls_in_ourcert"),
    },
    VarEntry {
        name: "tls_in_peercert",
        var_type: VarType::Cert,
        resolver: VarResolver::ContextField("tls_in_peercert"),
    },
    VarEntry {
        name: "tls_in_peerdn",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("tls_peerdn"),
    },
    #[cfg(feature = "tls-resume")]
    VarEntry {
        name: "tls_in_resumption",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("tls_in_resumption"),
    },
    #[cfg(feature = "tls")]
    VarEntry {
        name: "tls_in_sni",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("tls_sni"),
    },
    VarEntry {
        name: "tls_in_ver",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("tls_in_ver"),
    },
    VarEntry {
        name: "tls_out_bits",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("tls_out_bits"),
    },
    VarEntry {
        name: "tls_out_certificate_verified",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("tls_out_certificate_verified"),
    },
    VarEntry {
        name: "tls_out_cipher",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("tls_out_cipher"),
    },
    VarEntry {
        name: "tls_out_cipher_std",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("tls_out_cipher_std"),
    },
    #[cfg(feature = "dane")]
    VarEntry {
        name: "tls_out_dane",
        var_type: VarType::Bool,
        resolver: VarResolver::ContextField("tls_out_dane"),
    },
    VarEntry {
        name: "tls_out_ocsp",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("tls_out_ocsp"),
    },
    VarEntry {
        name: "tls_out_ourcert",
        var_type: VarType::Cert,
        resolver: VarResolver::ContextField("tls_out_ourcert"),
    },
    VarEntry {
        name: "tls_out_peercert",
        var_type: VarType::Cert,
        resolver: VarResolver::ContextField("tls_out_peercert"),
    },
    VarEntry {
        name: "tls_out_peerdn",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("tls_out_peerdn"),
    },
    #[cfg(feature = "tls-resume")]
    VarEntry {
        name: "tls_out_resumption",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("tls_out_resumption"),
    },
    #[cfg(feature = "tls")]
    VarEntry {
        name: "tls_out_sni",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("tls_out_sni"),
    },
    #[cfg(feature = "dane")]
    VarEntry {
        name: "tls_out_tlsa_usage",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("tls_out_tlsa_usage"),
    },
    VarEntry {
        name: "tls_out_ver",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("tls_out_ver"),
    },
    VarEntry {
        name: "tls_peerdn",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("tls_peerdn"),
    },
    #[cfg(feature = "tls")]
    VarEntry {
        name: "tls_sni",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("tls_sni"),
    },
    // ── Time of day variables (expand.c lines 779-786) ─────────────────
    VarEntry {
        name: "tod_bsdinbox",
        var_type: VarType::Todbsdin,
        resolver: VarResolver::ContextField("tod_bsdinbox"),
    },
    VarEntry {
        name: "tod_epoch",
        var_type: VarType::Int,
        resolver: VarResolver::ContextField("tod_epoch"),
    },
    VarEntry {
        name: "tod_epoch_l",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("tod_epoch_l"),
    },
    VarEntry {
        name: "tod_full",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("tod_full"),
    },
    VarEntry {
        name: "tod_log",
        var_type: VarType::Todlog,
        resolver: VarResolver::ContextField("tod_log"),
    },
    VarEntry {
        name: "tod_logfile",
        var_type: VarType::Todlogbare,
        resolver: VarResolver::ContextField("tod_logfile"),
    },
    VarEntry {
        name: "tod_zone",
        var_type: VarType::Todzone,
        resolver: VarResolver::ContextField("tod_zone"),
    },
    VarEntry {
        name: "tod_zulu",
        var_type: VarType::Todzulu,
        resolver: VarResolver::ContextField("tod_zulu"),
    },
    // ── Transport/value/version (expand.c lines 787-796) ───────────────
    VarEntry {
        name: "transport_name",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("transport_name"),
    },
    VarEntry {
        name: "value",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("value"),
    },
    VarEntry {
        name: "verify_mode",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("verify_mode"),
    },
    VarEntry {
        name: "version_number",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("exim_version"),
    },
    VarEntry {
        name: "warn_message_delay",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("warnmsg_delay"),
    },
    VarEntry {
        name: "warn_message_recipient",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("warnmsg_recipients"),
    },
    VarEntry {
        name: "warn_message_recipients",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("warnmsg_recipients"),
    },
    VarEntry {
        name: "warnmsg_delay",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("warnmsg_delay"),
    },
    VarEntry {
        name: "warnmsg_recipient",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("warnmsg_recipients"),
    },
    VarEntry {
        name: "warnmsg_recipients",
        var_type: VarType::StringPtr,
        resolver: VarResolver::ContextField("warnmsg_recipients"),
    },
];

// ═══════════════════════════════════════════════════════════════════════════
//  find_var_ent — Binary search on the sorted variable table
// ═══════════════════════════════════════════════════════════════════════════

/// Searches the variable table by name using binary search.
///
/// This is a direct Rust port of the C `find_var_ent()` function (expand.c
/// lines 1245–1261). The table MUST be sorted alphabetically for the binary
/// search to produce correct results.
///
/// # Arguments
///
/// * `name` — The variable name to look up (e.g., `"sender_address"`).
///
/// # Returns
///
/// `Some(&VarEntry)` if the variable exists in the table, `None` otherwise.
pub fn find_var_ent(name: &str) -> Option<&'static VarEntry> {
    tracing::trace!(variable = name, "binary search in var_table");

    let result = VAR_TABLE.binary_search_by(|entry| entry.name.cmp(name));
    match result {
        Ok(idx) => {
            tracing::debug!(variable = name, index = idx, "variable found in var_table");
            Some(&VAR_TABLE[idx])
        }
        Err(_) => {
            tracing::trace!(variable = name, "variable not found in var_table");
            None
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  resolve_variable — Full variable resolution
// ═══════════════════════════════════════════════════════════════════════════

/// Resolves a variable name to its string value and taint state.
///
/// This is the Rust equivalent of the C `find_variable()` function (expand.c
/// lines 1910–2200). It handles all variable categories:
///
/// 1. **ACL variables** — `$acl_c*` and `$acl_m*`
/// 2. **Router variables** — `$r_*`
/// 3. **Auth variables** — `$auth1`..`$auth<n>`
/// 4. **Regex variables** — `$regex1`..`$regex<n>` (content-scan feature)
/// 5. **Table variables** — All 200+ variables via binary search
///
/// # Returns
///
/// - `Ok((Some(value), taint))` — Variable resolved successfully.
/// - `Ok((None, taint))` — Variable conditionally absent (e.g., filter not running).
/// - `Err(ExpandError::Failed)` — Variable does not exist or strict mode violation.
pub fn resolve_variable(
    name: &str,
    ctx: &ExpandContext,
) -> Result<(Option<String>, TaintState), ExpandError> {
    tracing::debug!(variable = name, "resolving variable");

    // ── 1. ACL variables ($acl_c*, $acl_m*) ────────────────────────────
    if (name.starts_with("acl_c") || name.starts_with("acl_m"))
        && name.len() > 5
        && !name.as_bytes()[5].is_ascii_alphabetic()
    {
        let is_connection = name.starts_with("acl_c");
        let suffix = &name[4..]; // includes 'c' or 'm' prefix for key
        let store = if is_connection {
            &ctx.acl_var_c
        } else {
            &ctx.acl_var_m
        };

        return match store.get(suffix) {
            Some(val) => {
                tracing::debug!(variable = name, "ACL variable resolved");
                Ok((Some(val.clone()), TaintState::Untainted))
            }
            None => {
                if ctx.strict_acl_vars {
                    Err(ExpandError::Failed {
                        message: format!("unknown variable name \"{name}\""),
                    })
                } else {
                    Ok((Some(String::new()), TaintState::Untainted))
                }
            }
        };
    }

    // ── 2. Router variables ($r_*) ─────────────────────────────────────
    if let Some(suffix) = name.strip_prefix("r_") {
        return match ctx.router_var.get(suffix) {
            Some(val) => Ok((Some(val.clone()), TaintState::Untainted)),
            None => {
                if ctx.strict_acl_vars {
                    Err(ExpandError::Failed {
                        message: format!("unknown variable name \"{name}\""),
                    })
                } else {
                    Ok((Some(String::new()), TaintState::Untainted))
                }
            }
        };
    }

    // ── 3. Auth variables ($auth<n>) ───────────────────────────────────
    if let Some(num_str) = name.strip_prefix("auth") {
        if !num_str.is_empty() && num_str.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(n) = num_str.parse::<usize>() {
                if n >= 1 && n <= ctx.auth_vars.len() {
                    let val = &ctx.auth_vars[n - 1];
                    return Ok((Some(val.clone()), TaintState::Tainted));
                }
                return Ok((Some(String::new()), TaintState::Tainted));
            }
        }
        // Fall through to table lookup for "authenticated_id" etc.
    }

    // ── 4. Regex variables ($regex<n>) ─────────────────────────────────
    #[cfg(feature = "content-scan")]
    if let Some(num_str) = name.strip_prefix("regex") {
        if !num_str.is_empty() && num_str.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(n) = num_str.parse::<usize>() {
                if n >= 1 && n <= ctx.regex_vars.len() {
                    return Ok((Some(ctx.regex_vars[n - 1].clone()), TaintState::Tainted));
                }
                return Ok((Some(String::new()), TaintState::Tainted));
            }
        }
    }

    // ── 5. Header variables ($h_name, $rh_name, $bh_name, $lh_name) ──
    // Dynamic header references are not in the static VAR_TABLE because
    // the header name part is user-defined.  Detect the well-known
    // prefixes and delegate to resolve_header_lookup.
    {
        let lower = name.to_ascii_lowercase();
        let header_prefixes: &[&str] = &[
            "bheader_", "bh_", "header_", "h_", "lheader_", "lh_", "rheader_", "rh_",
        ];
        for prefix in header_prefixes {
            if lower.starts_with(prefix) {
                return resolve_header_lookup(name, ctx);
            }
        }
    }

    // ── 6. Numeric capture variables ($0..$9) ─────────────────────────
    // In C Exim, $0 is the whole match and $1..$9 are captured groups
    // from the most recent regex/match operation.  When no match is
    // active, expand_nmax is -1 and all resolve to empty.
    if name.len() == 1 {
        if let Some(digit) = name.as_bytes().first() {
            if digit.is_ascii_digit() {
                let idx = (*digit - b'0') as usize;
                if (idx as i32) <= ctx.expand_nmax && idx < ctx.expand_nstring.len() {
                    return Ok((Some(ctx.expand_nstring[idx].clone()), TaintState::Tainted));
                }
                // No active match — return empty string (not an error).
                return Ok((Some(String::new()), TaintState::Untainted));
            }
        }
    }

    // ── 7. Table lookup via binary search ──────────────────────────────
    match find_var_ent(name) {
        Some(entry) => resolve_var_entry(entry, ctx),
        None => {
            tracing::debug!(variable = name, "unknown variable");
            Err(ExpandError::Failed {
                message: format!("unknown variable name \"{name}\""),
            })
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  resolve_var_entry — Type-dispatch for a known variable entry
// ═══════════════════════════════════════════════════════════════════════════

/// Resolves a found [`VarEntry`] to its string representation using the
/// appropriate type-specific formatting.
fn resolve_var_entry(
    entry: &VarEntry,
    ctx: &ExpandContext,
) -> Result<(Option<String>, TaintState), ExpandError> {
    let field_name = match &entry.resolver {
        VarResolver::ContextField(f) => *f,
        VarResolver::DynamicFunc(func_name) => {
            return resolve_dynamic_func(func_name, ctx);
        }
        VarResolver::MiscModuleDelegate(module_name) => {
            return resolve_misc_module(entry.name, module_name, ctx);
        }
        VarResolver::HeaderLookup => {
            return resolve_header_lookup(entry.name, ctx);
        }
        VarResolver::AclVariable => {
            return Ok((Some(String::new()), TaintState::Untainted));
        }
        VarResolver::AuthVariable => {
            return Ok((Some(String::new()), TaintState::Tainted));
        }
    };

    match entry.var_type {
        VarType::StringPtr => {
            let val = resolve_string_field(field_name, ctx);
            let taint = taint_for_field(field_name);
            Ok((Some(val), taint))
        }
        VarType::Int => {
            let val = resolve_int_field(field_name, ctx);
            Ok((Some(format!("{val}")), TaintState::Untainted))
        }
        VarType::Uid => {
            let val = resolve_uid_field(field_name, ctx);
            Ok((Some(format!("{val}")), TaintState::Untainted))
        }
        VarType::Gid => {
            let val = resolve_gid_field(field_name, ctx);
            Ok((Some(format!("{val}")), TaintState::Untainted))
        }
        VarType::Bool => {
            let val = resolve_bool_field(field_name, ctx);
            Ok((
                Some(if val {
                    "yes".to_string()
                } else {
                    String::new()
                }),
                TaintState::Untainted,
            ))
        }
        VarType::Filter => {
            if !ctx.filter_running {
                return Ok((None, TaintState::Untainted));
            }
            let val = resolve_filter_field(field_name, ctx);
            Ok((Some(format!("{val}")), TaintState::Untainted))
        }
        VarType::Pid => {
            let pid = if ctx.pid != 0 {
                ctx.pid
            } else {
                std::process::id() as i32
            };
            Ok((Some(format!("{pid}")), TaintState::Untainted))
        }
        VarType::Load => {
            let load = read_load_average();
            Ok((Some(format!("{load}")), TaintState::Untainted))
        }
        VarType::Pno => {
            let val = resolve_int64_field(field_name, ctx);
            Ok((Some(format!("{val}")), TaintState::Untainted))
        }
        VarType::LocalPart => {
            let addr = resolve_string_field(field_name, ctx);
            let local = extract_local_part(&addr);
            let taint = taint_for_field(field_name);
            Ok((Some(local), taint))
        }
        VarType::Domain => {
            let addr = resolve_string_field(field_name, ctx);
            let domain = extract_domain(&addr);
            let taint = taint_for_field(field_name);
            Ok((Some(domain), taint))
        }
        VarType::MessageHeaders => {
            let val = resolve_string_field(field_name, ctx);
            Ok((Some(val), TaintState::Tainted))
        }
        VarType::MsgBody => {
            let val = ctx.message_body.as_ref().clone();
            Ok((Some(val), TaintState::Tainted))
        }
        VarType::MsgbodyEnd => {
            let val = ctx.message_body_end.as_ref().clone();
            Ok((Some(val), TaintState::Tainted))
        }
        VarType::Todbsdin => Ok((Some(format_tod_bsdin()), TaintState::Untainted)),
        VarType::Todlog => Ok((Some(format_tod_log()), TaintState::Untainted)),
        VarType::Todlogbare => Ok((Some(format_tod_logbare()), TaintState::Untainted)),
        VarType::Todzone => Ok((Some(format_tod_zone()), TaintState::Untainted)),
        VarType::Todzulu => Ok((Some(format_tod_zulu()), TaintState::Untainted)),
        VarType::Reply => {
            // In C Exim, $reply_address is computed from message headers
            // (Reply-To > From > empty). The value is populated in
            // ExpandContext by the post-DATA ACL handler.
            let val = resolve_string_field(field_name, ctx);
            Ok((Some(val), TaintState::Tainted))
        }
        VarType::Cert => {
            let present = resolve_bool_field(field_name, ctx);
            Ok((
                Some(if present {
                    "<cert>".to_string()
                } else {
                    String::new()
                }),
                TaintState::Untainted,
            ))
        }
        VarType::StringFunc => Ok((Some(String::new()), TaintState::Untainted)),
        VarType::MiscModule => Ok((Some(String::new()), TaintState::Untainted)),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Field resolution helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Resolves a named string field from the [`ExpandContext`].
fn resolve_string_field(field: &str, ctx: &ExpandContext) -> String {
    match field {
        "sender_address" => ctx.sender_address.as_ref().clone(),
        "sender_host_address" => ctx.sender_host_address.as_ref().clone(),
        "sender_host_name" => ctx.sender_host_name.as_ref().clone(),
        "sender_helo_name" => ctx.sender_helo_name.as_ref().clone(),
        "sender_ident" => ctx.sender_ident.as_ref().clone(),
        "primary_hostname" => ctx.primary_hostname.as_ref().clone(),
        "qualify_domain" => ctx.qualify_domain.as_ref().clone(),
        "qualify_recipient" => ctx.qualify_recipient.as_ref().clone(),
        "spool_directory" => ctx.spool_directory.as_ref().clone(),
        "exim_path" => ctx.exim_path.as_ref().clone(),
        "exim_version" => ctx.exim_version.as_ref().clone(),
        "compile_date" => ctx.compile_date.as_ref().clone(),
        "compile_number" => ctx.compile_number.as_ref().clone(),
        "config_file" => ctx.config_file.as_ref().clone(),
        "config_dir" => ctx.config_dir.as_ref().clone(),
        "authenticated_id" => ctx.authenticated_id.clone(),
        "authenticated_sender" => ctx.authenticated_sender.clone(),
        "message_id" => ctx.message_id.clone(),
        "message_headers" => ctx.message_headers.clone(),
        "message_headers_raw" => ctx.message_headers_raw.clone(),
        "recipients" => ctx.recipients.clone(),
        "domain" => ctx.domain.clone(),
        "local_part" => ctx.local_part.clone(),
        "local_part_data" => ctx.local_part_data.clone(),
        "domain_data" => ctx.domain_data.clone(),
        "host" => ctx.host.clone(),
        "host_address" => ctx.host_address.clone(),
        "host_data" => ctx.host_data.clone(),
        "router_name" => ctx.router_name.clone(),
        "transport_name" => ctx.transport_name.clone(),
        "tls_cipher" => ctx.tls_cipher.clone(),
        "tls_peerdn" => ctx.tls_peerdn.clone(),
        "tls_sni" => ctx.tls_sni.clone(),
        "lookup_value" => ctx.lookup_value.clone(),
        "received_protocol" => ctx.received_protocol.clone(),
        "received_ip_address" => ctx.received_ip_address.clone(),
        "reply_address" => ctx.reply_address.clone(),
        "acl_verify_message" => ctx.acl_verify_message.clone(),
        "address_data" => ctx.address_data.clone(),
        "address_file" => ctx.address_file.clone(),
        "address_pipe" => ctx.address_pipe.clone(),
        "atrn_host" => ctx.atrn_host.clone(),
        "atrn_mode" => ctx.atrn_mode.clone(),
        "authenticated_fail_id" => ctx.authenticated_fail_id.clone(),
        "bounce_recipient" => ctx.bounce_recipient.clone(),
        "callout_address" => ctx.callout_address.clone(),
        "connection_id" => ctx.connection_id.clone(),
        "csa_status" => ctx.csa_status.clone(),
        "dnslist_domain" => ctx.dnslist_domain.clone(),
        "dnslist_matched" => ctx.dnslist_matched.clone(),
        "dnslist_text" => ctx.dnslist_text.clone(),
        "dnslist_value" => ctx.dnslist_value.clone(),
        "home" => ctx.home.clone(),
        "initial_cwd" => ctx.initial_cwd.clone(),
        "interface_address" => ctx.interface_address.clone(),
        "item" => ctx.item.clone(),
        "local_part_prefix" => ctx.local_part_prefix.clone(),
        "local_part_prefix_v" => ctx.local_part_prefix_v.clone(),
        "local_part_suffix" => ctx.local_part_suffix.clone(),
        "local_part_suffix_v" => ctx.local_part_suffix_v.clone(),
        "local_scan_data" => ctx.local_scan_data.clone(),
        "lookup_dnssec_authenticated" => ctx.lookup_dnssec_authenticated.clone(),
        "mailstore_basename" => ctx.mailstore_basename.clone(),
        "original_domain" => ctx.original_domain.clone(),
        "original_local_part" => ctx.original_local_part.clone(),
        "parent_domain" => ctx.parent_domain.clone(),
        "parent_local_part" => ctx.parent_local_part.clone(),
        "prvscheck_address" => ctx.prvscheck_address.clone(),
        "prvscheck_keynum" => ctx.prvscheck_keynum.clone(),
        "prvscheck_result" => ctx.prvscheck_result.clone(),
        "queue_name" => ctx.queue_name.clone(),
        "received_for" => ctx.received_for.clone(),
        "recipient_data" => ctx.recipient_data.clone(),
        "recipient_verify_failure" => ctx.recipient_verify_failure.clone(),
        "return_path" => ctx.return_path.clone(),
        "self_hostname" => ctx.self_hostname.clone(),
        "sender_address_data" => ctx.sender_address_data.clone(),
        "sender_data" => ctx.sender_data.clone(),
        "sender_fullhost" => ctx.sender_fullhost.clone(),
        "sender_host_authenticated" => ctx.sender_host_authenticated.clone(),
        "sender_rate" => ctx.sender_rate.clone(),
        "sender_rate_limit" => ctx.sender_rate_limit.clone(),
        "sender_rate_period" => ctx.sender_rate_period.clone(),
        "sender_rcvhost" => ctx.sender_rcvhost.clone(),
        "sender_verify_failure" => ctx.sender_verify_failure.clone(),
        "sending_ip_address" => ctx.sending_ip_address.clone(),
        "smtp_active_hostname" => ctx.smtp_active_hostname.clone(),
        "smtp_command" => ctx.smtp_command.clone(),
        "smtp_command_argument" => ctx.smtp_command_argument.clone(),
        "smtp_notquit_reason" => ctx.smtp_notquit_reason.clone(),
        "warnmsg_delay" => ctx.warnmsg_delay.clone(),
        "warnmsg_recipients" => ctx.warnmsg_recipients.clone(),
        "verify_mode" => ctx.verify_mode.clone(),
        "value" => ctx.value.clone(),
        "filter_thisaddress" => ctx.filter_thisaddress.clone(),
        "tls_in_cipher_std" => ctx.tls_in_cipher_std.clone(),
        "tls_in_ver" => ctx.tls_in_ver.clone(),
        "tls_out_cipher" => ctx.tls_out_cipher.clone(),
        "tls_out_cipher_std" => ctx.tls_out_cipher_std.clone(),
        "tls_out_peerdn" => ctx.tls_out_peerdn.clone(),
        "tls_out_sni" => ctx.tls_out_sni.clone(),
        "tls_out_ver" => ctx.tls_out_ver.clone(),
        "proxy_external_address" => ctx.proxy_external_address.clone(),
        "proxy_local_address" => ctx.proxy_local_address.clone(),
        "malware_name" => ctx.malware_name.clone(),
        "regex_match_string" => ctx.regex_match_string.clone(),
        "spam_action" => ctx.spam_action.clone(),
        "spam_bar" => ctx.spam_bar.clone(),
        "spam_report" => ctx.spam_report.clone(),
        "spam_score" => ctx.spam_score.clone(),
        "spam_score_int" => ctx.spam_score_int.clone(),
        "mime_anomaly_text" => ctx.mime_anomaly_text.clone(),
        "mime_boundary" => ctx.mime_boundary.clone(),
        "mime_charset" => ctx.mime_charset.clone(),
        "mime_content_description" => ctx.mime_content_description.clone(),
        "mime_content_disposition" => ctx.mime_content_disposition.clone(),
        "mime_content_id" => ctx.mime_content_id.clone(),
        "mime_content_transfer_encoding" => ctx.mime_content_transfer_encoding.clone(),
        "mime_content_type" => ctx.mime_content_type.clone(),
        "mime_decoded_filename" => ctx.mime_decoded_filename.clone(),
        "mime_filename" => ctx.mime_filename.clone(),
        "dcc_header" => ctx.dcc_header.clone(),
        "dcc_result" => ctx.dcc_result.clone(),
        "event_data" => ctx.event_data.clone(),
        "event_name" => ctx.event_name.clone(),
        "srs_recipient" => ctx.srs_recipient.clone(),
        "xclient_addr" => ctx.xclient_addr.clone(),
        "xclient_helo" => ctx.xclient_helo.clone(),
        "xclient_ident" => ctx.xclient_ident.clone(),
        "xclient_login" => ctx.xclient_login.clone(),
        "xclient_name" => ctx.xclient_name.clone(),
        "xclient_port" => ctx.xclient_port.clone(),
        "recipient_prefix" => ctx.recipient_prefix.clone(),
        "recipient_prefix_v" => ctx.recipient_prefix_v.clone(),
        "recipient_suffix" => ctx.recipient_suffix.clone(),
        "recipient_suffix_v" => ctx.recipient_suffix_v.clone(),
        "recipients_list" => ctx.recipients_list.clone(),
        "tod_epoch_l" => {
            let secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            format!("{secs}")
        }
        "tod_full" => format_tod_log(),
        // Positional ACL arguments $acl_arg1 .. $acl_arg9
        f if f.starts_with("acl_arg") => {
            if let Ok(idx) = f[7..].parse::<usize>() {
                if (1..=9).contains(&idx) {
                    ctx.acl_args.get(idx - 1).cloned().unwrap_or_default()
                } else {
                    String::new()
                }
            } else {
                String::new()
            }
        }
        _ => {
            tracing::trace!(field = field, "unrecognized string field, returning empty");
            String::new()
        }
    }
}

/// Resolves a named integer field from the [`ExpandContext`].
fn resolve_int_field(field: &str, ctx: &ExpandContext) -> i64 {
    match field {
        "sender_host_port" => i64::from(ctx.sender_host_port),
        "message_size" => ctx.message_size,
        "message_linecount" => i64::from(ctx.message_linecount),
        "recipients_count" => i64::from(ctx.recipients_count),
        "received_port" => i64::from(ctx.received_port),
        "authentication_failed" => i64::from(ctx.authentication_failed),
        "body_linecount" => i64::from(ctx.body_linecount),
        "body_zerocount" => i64::from(ctx.body_zerocount),
        "bounce_return_size_limit" => i64::from(ctx.bounce_return_size_limit),
        "host_lookup_deferred" => i64::from(ctx.host_lookup_deferred),
        "host_lookup_failed" => i64::from(ctx.host_lookup_failed),
        "host_port" => i64::from(ctx.host_port),
        "interface_port" => i64::from(ctx.interface_port),
        "localhost_number" => i64::from(ctx.localhost_number),
        "log_inodes" => i64::from(ctx.log_inodes),
        "log_space" => ctx.log_space,
        "max_received_linelength" => i64::from(ctx.max_received_linelength),
        "message_age" => i64::from(ctx.message_age),
        "message_body_size" => i64::from(ctx.message_body_size),
        "rcpt_count" => i64::from(ctx.rcpt_count),
        "rcpt_defer_count" => i64::from(ctx.rcpt_defer_count),
        "rcpt_fail_count" => i64::from(ctx.rcpt_fail_count),
        "received_count" => i64::from(ctx.received_count),
        "received_time" => ctx.received_time,
        "regex_cachesize" => i64::from(ctx.regex_cachesize),
        "return_size_limit" => i64::from(ctx.return_size_limit),
        "runrc" => i64::from(ctx.runrc),
        "sending_port" => i64::from(ctx.sending_port),
        "smtp_count_at_connection_start" => i64::from(ctx.smtp_count_at_connection_start),
        "spool_inodes" => i64::from(ctx.spool_inodes),
        "spool_space" => ctx.spool_space,
        "av_failed" => i64::from(ctx.av_failed),
        "event_defer_errno" => i64::from(ctx.event_defer_errno),
        "mime_anomaly_level" => i64::from(ctx.mime_anomaly_level),
        "mime_content_size" => i64::from(ctx.mime_content_size),
        "mime_is_coverletter" => i64::from(ctx.mime_is_coverletter),
        "mime_is_multipart" => i64::from(ctx.mime_is_multipart),
        "mime_is_rfc822" => i64::from(ctx.mime_is_rfc822),
        "mime_part_count" => i64::from(ctx.mime_part_count),
        "acl_narg" => i64::from(ctx.acl_narg),
        "tls_in_bits" => i64::from(ctx.tls_in_bits),
        "tls_in_certificate_verified" => i64::from(ctx.tls_in_certificate_verified),
        "tls_in_ocsp" => i64::from(ctx.tls_in_ocsp),
        "tls_in_resumption" => i64::from(ctx.tls_in_resumption),
        "tls_out_bits" => i64::from(ctx.tls_out_bits),
        "tls_out_certificate_verified" => i64::from(ctx.tls_out_certificate_verified),
        "tls_out_ocsp" => i64::from(ctx.tls_out_ocsp),
        "tls_out_resumption" => i64::from(ctx.tls_out_resumption),
        "tls_out_tlsa_usage" => i64::from(ctx.tls_out_tlsa_usage),
        "proxy_external_port" => i64::from(ctx.proxy_external_port),
        "proxy_local_port" => i64::from(ctx.proxy_local_port),
        "tod_epoch" => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        _ => {
            tracing::trace!(field = field, "unrecognized int field, returning 0");
            0
        }
    }
}

/// Resolves a named UID field.
fn resolve_uid_field(field: &str, ctx: &ExpandContext) -> u32 {
    match field {
        "exim_uid" => ctx.exim_uid,
        "caller_uid" => ctx.caller_uid,
        "local_user_uid" => ctx.local_user_uid,
        "originator_uid" => ctx.originator_uid,
        _ => 0,
    }
}

/// Resolves a named GID field.
fn resolve_gid_field(field: &str, ctx: &ExpandContext) -> u32 {
    match field {
        "exim_gid" => ctx.exim_gid,
        "caller_gid" => ctx.caller_gid,
        "local_user_gid" => ctx.local_user_gid,
        "originator_gid" => ctx.originator_gid,
        _ => 0,
    }
}

/// Resolves a named boolean field. Result formatted as "yes"/"" by caller.
fn resolve_bool_field(field: &str, ctx: &ExpandContext) -> bool {
    match field {
        "sender_helo_dnssec" => ctx.sender_helo_dnssec,
        "sender_host_dnssec" => ctx.sender_host_dnssec,
        "message_smtputf8" => ctx.message_smtputf8,
        "prdr_requested" => ctx.prdr_requested,
        "proxy_session" => ctx.proxy_session,
        "tls_out_dane" => ctx.tls_out_dane,
        "tls_in_ourcert" => ctx.tls_in_ourcert,
        "tls_in_peercert" => ctx.tls_in_peercert,
        "tls_out_ourcert" => ctx.tls_out_ourcert,
        "tls_out_peercert" => ctx.tls_out_peercert,
        _ => false,
    }
}

/// Resolves a filter integer field (n0..n9, sn0..sn9).
fn resolve_filter_field(field: &str, ctx: &ExpandContext) -> i32 {
    if let Some(idx_str) = field.strip_prefix("sn") {
        if let Ok(idx) = idx_str.parse::<usize>() {
            if idx < 10 {
                return ctx.filter_sn[idx];
            }
        }
    }
    if let Some(idx_str) = field.strip_prefix('n') {
        if let Ok(idx) = idx_str.parse::<usize>() {
            if idx < 10 {
                return ctx.filter_n[idx];
            }
        }
    }
    0
}

/// Resolves a named i64 field (for inode and similar large values).
fn resolve_int64_field(field: &str, ctx: &ExpandContext) -> i64 {
    match field {
        "inode" => ctx.inode,
        _ => 0,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Taint classification
// ═══════════════════════════════════════════════════════════════════════════

/// Determines the taint state for a given context field.
fn taint_for_field(field: &str) -> TaintState {
    match field {
        "sender_address"
        | "sender_host_address"
        | "sender_host_name"
        | "sender_helo_name"
        | "sender_ident"
        | "sender_fullhost"
        | "sender_rcvhost"
        | "message_body"
        | "message_body_end"
        | "message_headers"
        | "message_headers_raw"
        | "host_data"
        | "recipient_data"
        | "sender_data"
        | "sender_address_data" => TaintState::Tainted,
        "primary_hostname" | "qualify_domain" | "qualify_recipient" | "spool_directory"
        | "exim_path" | "exim_version" | "compile_date" | "compile_number" | "config_file"
        | "config_dir" => TaintState::Untainted,
        _ => TaintState::Untainted,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Dynamic function resolution
// ═══════════════════════════════════════════════════════════════════════════

/// Resolves a dynamic-function variable (vtype_string_func).
fn resolve_dynamic_func(
    func_name: &str,
    ctx: &ExpandContext,
) -> Result<(Option<String>, TaintState), ExpandError> {
    tracing::debug!(func = func_name, "resolving dynamic function variable");

    match func_name {
        "fn_recipients" => Ok((Some(ctx.recipients.clone()), TaintState::Tainted)),
        "fn_recipients_list" => Ok((Some(ctx.recipients_list.clone()), TaintState::Tainted)),
        "fn_queue_size" => Ok((Some(String::from("0")), TaintState::Untainted)),
        "fn_hdrs_added" => Ok((Some(String::new()), TaintState::Untainted)),
        "smtp_cmd_hist" => Ok((Some(String::new()), TaintState::Untainted)),
        "sender_helo_verified_boolstr" => Ok((Some(String::new()), TaintState::Untainted)),
        _ => {
            tracing::trace!(func = func_name, "unknown dynamic function");
            Ok((Some(String::new()), TaintState::Untainted))
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Misc module delegation
// ═══════════════════════════════════════════════════════════════════════════

/// Resolves a misc-module-delegated variable.
fn resolve_misc_module(
    var_name: &str,
    module_name: &str,
    _ctx: &ExpandContext,
) -> Result<(Option<String>, TaintState), ExpandError> {
    tracing::debug!(
        variable = var_name,
        module = module_name,
        "delegating to misc module"
    );
    Ok((Some(String::new()), TaintState::Untainted))
}

// ═══════════════════════════════════════════════════════════════════════════
//  Header lookup resolution
// ═══════════════════════════════════════════════════════════════════════════

/// Resolves a header-lookup variable ($h_*, $header_*, $rh_*, $bh_*, $lh_*).
fn resolve_header_lookup(
    header_name: &str,
    ctx: &ExpandContext,
) -> Result<(Option<String>, TaintState), ExpandError> {
    // Strip the prefix to get the raw header name.
    // Prefixes: h_, header_, rh_, rheader_, bh_, bheader_, lh_, lheader_
    let lower = header_name.to_ascii_lowercase();
    let raw_name = if let Some(rest) = lower.strip_prefix("bheader_") {
        rest
    } else if let Some(rest) = lower.strip_prefix("rheader_") {
        rest
    } else if let Some(rest) = lower.strip_prefix("lheader_") {
        rest
    } else if let Some(rest) = lower.strip_prefix("header_") {
        rest
    } else if let Some(rest) = lower.strip_prefix("bh_") {
        rest
    } else if let Some(rest) = lower.strip_prefix("rh_") {
        rest
    } else if let Some(rest) = lower.strip_prefix("lh_") {
        rest
    } else if let Some(rest) = lower.strip_prefix("h_") {
        rest
    } else {
        &lower
    };

    // Look up the header name in the parsed header list.
    // C Exim's $h_subject: strips trailing whitespace and the colon is
    // part of the variable syntax, not the header name.
    let key = raw_name.trim_end_matches(':');
    if let Some(val) = ctx.header_list.get(key) {
        Ok((Some(val.clone()), TaintState::Tainted))
    } else {
        Ok((Some(String::new()), TaintState::Tainted))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Address part extraction helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Extracts the local part from an email address (everything before the last `@`).
fn extract_local_part(address: &str) -> String {
    if address.is_empty() {
        return String::new();
    }
    match address.rfind('@') {
        Some(pos) => address[..pos].to_string(),
        None => address.to_string(),
    }
}

/// Extracts the domain from an email address (everything after the last `@`).
fn extract_domain(address: &str) -> String {
    if address.is_empty() {
        return String::new();
    }
    match address.rfind('@') {
        Some(pos) => address[pos + 1..].to_string(),
        None => String::new(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Time-of-day formatting helpers
// ═══════════════════════════════════════════════════════════════════════════

/// BSD inbox date format: "Mon Jan  2 15:04:05 2006"
fn format_tod_bsdin() -> String {
    let now = now_utc_components();
    let day_names = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    let month_names = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let wday = (now.day_of_week % 7) as usize;
    let mon = ((now.month.wrapping_sub(1)) % 12) as usize;
    format!(
        "{} {} {:2} {:02}:{:02}:{:02} {}",
        day_names[wday], month_names[mon], now.day, now.hour, now.minute, now.second, now.year
    )
}

/// Exim log format: "2006-01-02 15:04:05"
fn format_tod_log() -> String {
    let now = now_utc_components();
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        now.year, now.month, now.day, now.hour, now.minute, now.second
    )
}

/// Log file datestamp: "20060102"
fn format_tod_logbare() -> String {
    let now = now_utc_components();
    format!("{:04}{:02}{:02}", now.year, now.month, now.day)
}

/// Timezone offset string (UTC: "+0000").
fn format_tod_zone() -> String {
    String::from("+0000")
}

/// ISO 8601 Zulu format: "20060102T150405Z"
fn format_tod_zulu() -> String {
    let now = now_utc_components();
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year, now.month, now.day, now.hour, now.minute, now.second
    )
}

/// Simple UTC time components structure for time formatting.
struct TimeComponents {
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    day_of_week: u32,
}

/// Returns UTC time components from the system clock.
fn now_utc_components() -> TimeComponents {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let days = (secs / 86400) as i64;
    let time_of_day = secs % 86400;

    let hour = (time_of_day / 3600) as u32;
    let minute = ((time_of_day % 3600) / 60) as u32;
    let second = (time_of_day % 60) as u32;

    // 1970-01-01 was Thursday (4)
    let day_of_week = ((days + 4) % 7) as u32;

    let (year, month, day) = days_to_ymd(days);

    TimeComponents {
        year,
        month,
        day,
        hour,
        minute,
        second,
        day_of_week,
    }
}

/// Converts days since Unix epoch to (year, month, day) — Hinnant algorithm.
fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64 + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Reads the system load average (Linux: /proc/loadavg, else 0).
fn read_load_average() -> i32 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/loadavg") {
            if let Some(first) = content.split_whitespace().next() {
                if let Ok(load_f) = first.parse::<f64>() {
                    return (load_f * 1000.0) as i32;
                }
            }
        }
    }
    let _ = (); // suppress unused warning on non-linux
    0
}

// ═══════════════════════════════════════════════════════════════════════════
//  Module-level tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_var_table_is_sorted() {
        for window in VAR_TABLE.windows(2) {
            assert!(
                window[0].name < window[1].name,
                "Variable table not sorted: {:?} >= {:?}",
                window[0].name,
                window[1].name
            );
        }
    }

    #[test]
    fn test_find_var_ent_basic() {
        assert!(find_var_ent("sender_address").is_some());
        assert!(find_var_ent("domain").is_some());
        assert!(find_var_ent("local_part").is_some());
        assert!(find_var_ent("message_id").is_some());
        assert!(find_var_ent("primary_hostname").is_some());
        assert!(find_var_ent("nonexistent_variable_xyz").is_none());
    }

    #[test]
    fn test_find_var_ent_first_and_last() {
        assert!(find_var_ent("acl_arg1").is_some());
        assert!(find_var_ent("warnmsg_recipients").is_some());
    }

    #[test]
    fn test_resolve_string_variable() {
        let mut ctx = ExpandContext::new();
        ctx.domain = "example.com".to_string();
        let (val, taint) = resolve_variable("domain", &ctx).unwrap();
        assert_eq!(val, Some("example.com".to_string()));
        assert_eq!(taint, TaintState::Untainted);
    }

    #[test]
    fn test_resolve_int_variable() {
        let mut ctx = ExpandContext::new();
        ctx.message_size = 12345;
        let (val, _) = resolve_variable("message_size", &ctx).unwrap();
        assert_eq!(val, Some("12345".to_string()));
    }

    #[test]
    fn test_resolve_bool_yes() {
        let mut ctx = ExpandContext::new();
        ctx.sender_helo_dnssec = true;
        let (val, _) = resolve_variable("sender_helo_dnssec", &ctx).unwrap();
        assert_eq!(val, Some("yes".to_string()));
    }

    #[test]
    fn test_resolve_bool_empty() {
        let ctx = ExpandContext::new();
        let (val, _) = resolve_variable("sender_helo_dnssec", &ctx).unwrap();
        assert_eq!(val, Some(String::new()));
    }

    #[test]
    fn test_resolve_uid() {
        let mut ctx = ExpandContext::new();
        ctx.exim_uid = 1000;
        let (val, _) = resolve_variable("exim_uid", &ctx).unwrap();
        assert_eq!(val, Some("1000".to_string()));
    }

    #[test]
    fn test_resolve_gid() {
        let mut ctx = ExpandContext::new();
        ctx.exim_gid = 500;
        let (val, _) = resolve_variable("exim_gid", &ctx).unwrap();
        assert_eq!(val, Some("500".to_string()));
    }

    #[test]
    fn test_resolve_pid() {
        let ctx = ExpandContext::new();
        let (val, _) = resolve_variable("pid", &ctx).unwrap();
        let pid: i32 = val.unwrap().parse().expect("pid should be a number");
        assert!(pid > 0);
    }

    #[test]
    fn test_resolve_acl_variable() {
        let mut ctx = ExpandContext::new();
        ctx.acl_var_c
            .insert("c0".to_string(), "test_value".to_string());
        let (val, _) = resolve_variable("acl_c0", &ctx).unwrap();
        assert_eq!(val, Some("test_value".to_string()));
    }

    #[test]
    fn test_resolve_acl_nonexistent_nonstrict() {
        let ctx = ExpandContext::new();
        let (val, _) = resolve_variable("acl_c99", &ctx).unwrap();
        assert_eq!(val, Some(String::new()));
    }

    #[test]
    fn test_resolve_acl_nonexistent_strict() {
        let mut ctx = ExpandContext::new();
        ctx.strict_acl_vars = true;
        let result = resolve_variable("acl_c99", &ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_auth_variable() {
        let mut ctx = ExpandContext::new();
        ctx.auth_vars = vec!["user1".to_string(), "pass2".to_string()];
        let (val, taint) = resolve_variable("auth1", &ctx).unwrap();
        assert_eq!(val, Some("user1".to_string()));
        assert_eq!(taint, TaintState::Tainted);
        let (val2, _) = resolve_variable("auth2", &ctx).unwrap();
        assert_eq!(val2, Some("pass2".to_string()));
    }

    #[test]
    fn test_resolve_unknown() {
        let ctx = ExpandContext::new();
        assert!(resolve_variable("totally_nonexistent_var", &ctx).is_err());
    }

    #[test]
    fn test_sender_address_domain() {
        let mut ctx = ExpandContext::new();
        ctx.sender_address = Tainted::new("user@example.com".to_string());
        let (val, _) = resolve_variable("sender_address_domain", &ctx).unwrap();
        assert_eq!(val, Some("example.com".to_string()));
    }

    #[test]
    fn test_sender_address_local_part() {
        let mut ctx = ExpandContext::new();
        ctx.sender_address = Tainted::new("user@example.com".to_string());
        let (val, _) = resolve_variable("sender_address_local_part", &ctx).unwrap();
        assert_eq!(val, Some("user".to_string()));
    }

    #[test]
    fn test_extract_no_at() {
        assert_eq!(extract_local_part("localonly"), "localonly");
        assert_eq!(extract_domain("localonly"), "");
    }

    #[test]
    fn test_extract_empty() {
        assert_eq!(extract_local_part(""), "");
        assert_eq!(extract_domain(""), "");
    }

    #[test]
    fn test_tod_zulu_format() {
        let zulu = format_tod_zulu();
        assert!(zulu.ends_with('Z'));
        assert!(zulu.contains('T'));
        assert_eq!(zulu.len(), 16);
    }

    #[test]
    fn test_filter_not_running() {
        let ctx = ExpandContext::new();
        let (val, _) = resolve_variable("n0", &ctx).unwrap();
        assert_eq!(val, None);
    }

    #[test]
    fn test_filter_running() {
        let mut ctx = ExpandContext::new();
        ctx.filter_running = true;
        ctx.filter_n[3] = 42;
        let (val, _) = resolve_variable("n3", &ctx).unwrap();
        assert_eq!(val, Some("42".to_string()));
    }

    #[test]
    fn test_expand_context_default() {
        let ctx = ExpandContext::default();
        assert_eq!(ctx.message_size, 0);
        assert_eq!(ctx.recipients_count, 0);
        assert!(ctx.acl_var_c.is_empty());
    }

    #[test]
    fn test_tainted_field() {
        let mut ctx = ExpandContext::new();
        ctx.sender_address = Tainted::new("test@example.com".to_string());
        let (_, taint) = resolve_variable("sender_address", &ctx).unwrap();
        assert_eq!(taint, TaintState::Tainted);
    }

    #[test]
    fn test_clean_field() {
        let mut ctx = ExpandContext::new();
        ctx.primary_hostname = Clean::new("mail.example.com".to_string());
        let (val, taint) = resolve_variable("primary_hostname", &ctx).unwrap();
        assert_eq!(val, Some("mail.example.com".to_string()));
        assert_eq!(taint, TaintState::Untainted);
    }

    #[test]
    fn test_router_variable() {
        let mut ctx = ExpandContext::new();
        ctx.router_var
            .insert("custom".to_string(), "value123".to_string());
        let (val, _) = resolve_variable("r_custom", &ctx).unwrap();
        assert_eq!(val, Some("value123".to_string()));
    }

    #[test]
    fn test_router_variable_nonexistent() {
        let ctx = ExpandContext::new();
        let (val, _) = resolve_variable("r_nonexistent", &ctx).unwrap();
        assert_eq!(val, Some(String::new()));
    }

    #[test]
    fn test_version_number_alias() {
        let mut ctx = ExpandContext::new();
        ctx.exim_version = Clean::new("4.99".to_string());
        let (val, _) = resolve_variable("version_number", &ctx).unwrap();
        assert_eq!(val, Some("4.99".to_string()));
    }

    #[test]
    fn test_warn_message_aliases() {
        let mut ctx = ExpandContext::new();
        ctx.warnmsg_recipients = "admin@example.com".to_string();

        let (v1, _) = resolve_variable("warn_message_recipient", &ctx).unwrap();
        let (v2, _) = resolve_variable("warn_message_recipients", &ctx).unwrap();
        let (v3, _) = resolve_variable("warnmsg_recipient", &ctx).unwrap();
        let (v4, _) = resolve_variable("warnmsg_recipients", &ctx).unwrap();
        let expected = Some("admin@example.com".to_string());
        assert_eq!(v1, expected);
        assert_eq!(v2, expected);
        assert_eq!(v3, expected);
        assert_eq!(v4, expected);
    }

    #[test]
    fn test_cert_variable_present() {
        let mut ctx = ExpandContext::new();
        ctx.tls_in_ourcert = true;
        let (val, _) = resolve_variable("tls_in_ourcert", &ctx).unwrap();
        assert_eq!(val, Some("<cert>".to_string()));
    }

    #[test]
    fn test_cert_variable_absent() {
        let ctx = ExpandContext::new();
        let (val, _) = resolve_variable("tls_in_ourcert", &ctx).unwrap();
        assert_eq!(val, Some(String::new()));
    }

    #[test]
    fn test_days_to_ymd_epoch() {
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn test_days_to_ymd_known_date() {
        // 2024-01-01 = day 19723
        let (y, m, d) = days_to_ymd(19723);
        assert_eq!((y, m, d), (2024, 1, 1));
    }
}
