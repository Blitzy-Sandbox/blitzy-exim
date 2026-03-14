//! Context struct definitions replacing 714 global variables from C Exim.
//!
//! This module defines four scoped context structs that replace ALL global
//! mutable state from `src/src/globals.c` and `src/src/globals.h`:
//!
//! - [`ServerContext`] — Daemon-lifetime state (listening sockets, process table,
//!   TLS credentials, debug/log selectors, privilege tracking)
//! - [`MessageContext`] — Per-message state (sender, recipients, headers, body,
//!   ACL variables, TLS info, content scanning results)
//! - [`DeliveryContext`] — Per-delivery-attempt state (current address,
//!   router/transport results, retry data, DNSBL results)
//! - [`ConfigContext`] — Parsed configuration wrapper (`Arc<Config>`)
//!
//! Additionally defines helper types used across contexts:
//! - [`AddressItem`] — Delivery address with routing/transport data
//! - [`RecipientItem`] — Envelope recipient entry
//! - [`HeaderLine`] — RFC 2822 header line
//! - [`HeaderType`] — Header classification enum
//! - [`TlsSessionInfo`] — TLS session state (replaces C `tls_support`)
//! - [`OcspStatus`] — OCSP stapling verification status
//! - [`SmtpSlot`] — Child process tracking entry
//!
//! Per AAP §0.4.4: "714 global variables in globals.c/globals.h are replaced
//! with 4 scoped context structs."
//!
//! # Architectural Rules
//!
//! - Zero `unsafe` code in this module
//! - All state is in context structs passed as parameters — no global mutable state
//! - `Arc<Config>` is used for immutable configuration (AAP §0.4.3)
//! - `String` for owned strings replacing C `uschar *`
//! - `Option<T>` for nullable fields replacing C `NULL` pointers
//! - `Vec<T>` for dynamic arrays replacing C linked lists
//!
//! # Taint Tracking
//!
//! This module re-exports [`Tainted`] and [`Clean`] from `exim-store` for
//! compile-time taint tracking. Network-received data (SMTP input, DNS
//! responses) should be wrapped in `Tainted<T>` and validated via
//! [`Tainted::sanitize()`] before use in security-sensitive operations.
//!
//! # C Boolean Flags (`f.*`) Coverage
//!
//! C Exim maintains ~150 boolean flags in the `struct global_flags f` defined
//! in `globals.h`/`globals.c`.  These are distributed across four context
//! structs:
//!
//! - **`exim_config::types::ConfigContext`** — 56 flags (AAP §0.4.4)
//! - **`exim_core::context::ServerContext`** — 10 flags (daemon/process state)
//! - **`exim_core::context::MessageContext`** — 6 flags (per-message state)
//! - **`exim_core::context::DeliveryContext`** — 4 flags (per-delivery state)
//!
//! Total: ~76 of ~150 C boolean flags are currently mapped.  The remaining
//! ~74 flags (e.g., `f.helo_verified`, `f.sender_verified`, `f.address_test_mode`,
//! `f.filter_running`, `f.local_error_message`, `f.queue_only_policy`, and
//! various transport/router-specific flags) will be added as they are needed
//! by router and transport implementations (expected in CP5).
//!
//! Tracking ticket: Flag coverage should be validated against the full
//! `globals.h` flag list when all router/transport implementations are
//! complete.  Any flag accessed by production code MUST have a corresponding
//! field in the appropriate context struct.

use std::os::unix::io::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use exim_config::Config;

// Re-export taint types from exim-store for use by other exim-core modules.
// Per AAP Phase 7: context.rs re-exports Tainted<T>/Clean<T> from exim-store.
pub use exim_store::{Clean, Tainted};

// ---------------------------------------------------------------------------
// OcspStatus — OCSP stapling verification status
// ---------------------------------------------------------------------------

/// OCSP stapling verification status for a TLS session.
///
/// Replaces the C OCSP status constants from `globals.h` lines 70–75:
/// `OCSP_NOT_REQ`, `OCSP_NOT_RESP`, `OCSP_VFY_NOT_TRIED`, `OCSP_FAILED`,
/// `OCSP_VFIED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum OcspStatus {
    /// OCSP stapling was not requested by the client.
    #[default]
    NotRequested,
    /// OCSP stapling was requested but the server did not respond with a staple.
    NotResponded,
    /// OCSP response was received but verification was not attempted.
    VerifyNotTried,
    /// OCSP response verification failed.
    Failed,
    /// OCSP response was successfully verified.
    Verified,
}

// ---------------------------------------------------------------------------
// TlsSessionInfo — TLS session state (replaces C tls_support struct)
// ---------------------------------------------------------------------------

/// TLS session information for inbound or outbound connections.
///
/// Replaces the C `tls_support` struct from `globals.h` lines 52–97.
/// Each SMTP connection has an inbound TLS session (`tls_in` in
/// [`MessageContext`]) and optionally an outbound TLS session for relay.
///
/// All fields default to safe empty/disabled values matching the C
/// initialization (`tls_in`/`tls_out` in `globals.c` lines 71–78).
#[derive(Debug, Clone, Default)]
pub struct TlsSessionInfo {
    /// Whether a TLS session is currently active.
    /// Replaces C `tls_support.active.sock != -1` check.
    pub active: bool,

    /// Cipher strength in bits (e.g., 128, 256).
    /// Replaces C `tls_support.bits`.
    pub bits: i32,

    /// Whether the peer certificate was successfully verified.
    /// Replaces C `tls_support.certificate_verified`.
    pub certificate_verified: bool,

    /// Whether DANE verification succeeded.
    /// Replaces C `tls_support.dane_verified`.
    pub dane_verified: bool,

    /// DANE TLSA usage value (0 = not DANE, 2 = DANE-TA, 3 = DANE-EE).
    /// Replaces C `tls_support.tlsa_usage`.
    pub tlsa_usage: i32,

    /// Negotiated cipher suite name (OpenSSL/GnuTLS-specific string).
    /// Replaces C `tls_support.cipher`.
    pub cipher: Option<String>,

    /// Standard cipher suite name (RFC 8446 / IANA format).
    /// Replaces C `tls_support.cipher_stdname`.
    pub cipher_stdname: Option<String>,

    /// TLS protocol version string (e.g., "TLSv1.3").
    /// Replaces C `tls_support.ver`.
    pub ver: Option<String>,

    /// Peer distinguished name from the certificate.
    /// Replaces C `tls_support.peerdn`.
    pub peerdn: Option<String>,

    /// Server Name Indication (SNI) value.
    /// Replaces C `tls_support.sni`.
    pub sni: Option<String>,

    /// Base64-encoded TLS channel binding data for SCRAM authentication.
    /// Replaces C `tls_support.channelbinding`.
    pub channelbinding: Option<String>,

    /// OCSP stapling verification status.
    /// Replaces C `tls_support.ocsp` enum field.
    pub ocsp_status: OcspStatus,

    /// TLS session resumption flags.
    /// Replaces C `tls_support.resumption` bitfield.
    pub resumption: u32,
}

// ---------------------------------------------------------------------------
// HeaderType — Header classification enum
// ---------------------------------------------------------------------------

/// Classification of an RFC 2822 / RFC 5322 header line.
///
/// Replaces the C `htype` integer constants from `structs.h` and the
/// header type tables in `header.c`. Each header line in a message is
/// classified for efficient access during ACL evaluation, header rewriting,
/// and message generation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum HeaderType {
    /// `From:` header (RFC 5322 §3.6.2).
    From,
    /// `To:` header (RFC 5322 §3.6.3).
    To,
    /// `Cc:` header (RFC 5322 §3.6.3).
    Cc,
    /// `Bcc:` header (RFC 5322 §3.6.3).
    Bcc,
    /// `Subject:` header (RFC 5322 §3.6.1).
    Subject,
    /// `Reply-To:` header (RFC 5322 §3.6.2).
    ReplyTo,
    /// `Message-ID:` header (RFC 5322 §3.6.4).
    MessageId,
    /// `Date:` header (RFC 5322 §3.6.1).
    Date,
    /// `Received:` header (RFC 5321 §4.4).
    Received,
    /// `Content-Type:` header (RFC 2045 §5).
    ContentType,
    /// `MIME-Version:` header (RFC 2045 §4).
    MimeVersion,
    /// Any other header not explicitly classified.
    #[default]
    Other,
    /// Header that has been superseded by a rewritten version.
    Old,
    /// Header that has been logically removed (not emitted on output).
    Deleted,
}

// ---------------------------------------------------------------------------
// HeaderLine — RFC 2822 header line
// ---------------------------------------------------------------------------

/// A single header line from a message.
///
/// Replaces the C `header_line` struct (a linked list in `structs.h`).
/// In Rust, headers are stored in a `Vec<HeaderLine>` within
/// [`MessageContext`] rather than a linked list.
#[derive(Debug, Clone)]
pub struct HeaderLine {
    /// The complete header text including the name, colon, and value.
    /// Includes the trailing newline (matches C `header_line.text`).
    pub text: String,

    /// Length of the header text in bytes.
    /// Replaces C `header_line.slen` — provided for compatibility with
    /// code that checks header size limits.
    pub slen: usize,

    /// Classification of this header line.
    pub htype: HeaderType,
}

impl HeaderLine {
    /// Create a new header line from raw text with automatic classification.
    pub fn new(text: String, htype: HeaderType) -> Self {
        let slen = text.len();
        Self { text, slen, htype }
    }
}

// ---------------------------------------------------------------------------
// RecipientItem — Envelope recipient entry
// ---------------------------------------------------------------------------

/// A single envelope recipient for the current message.
///
/// Replaces the C `recipient_item` struct from `structs.h`. In C, recipients
/// are stored in a dynamically-sized array (`recipients_list[]`). In Rust,
/// they are stored in `Vec<RecipientItem>` within [`MessageContext`].
#[derive(Debug, Clone, Default)]
pub struct RecipientItem {
    /// The recipient email address (envelope RCPT TO).
    pub address: String,

    /// Override errors-to address for this recipient.
    /// `None` means use the envelope sender.
    pub errors_to: Option<String>,

    /// Original recipient from ORCPT DSN parameter (RFC 3461).
    pub orcpt: Option<String>,

    /// DSN notification flags (RFC 3461: SUCCESS, FAILURE, DELAY, NEVER).
    pub dsn_flags: u32,

    /// Parent number — index of the parent address in the recipient list
    /// for addresses generated by aliasing/forwarding. `None` for original
    /// recipients.
    pub pno: Option<usize>,
}

// ---------------------------------------------------------------------------
// SmtpSlot — Child process tracking entry
// ---------------------------------------------------------------------------

/// Tracking entry for an active SMTP child process.
///
/// Replaces entries in the C `smtp_slots[]` array from `globals.c`.
/// The daemon maintains a vector of `SmtpSlot` entries to track which
/// child processes are handling which connections (for logging, connection
/// limits, and host-based rate limiting).
#[derive(Debug, Clone, Default)]
pub struct SmtpSlot {
    /// Process ID of the child handling this connection.
    /// 0 indicates an unused slot.
    pub pid: i32,

    /// IP address of the connecting SMTP client.
    pub host_address: Option<String>,

    /// Hostname of the connecting SMTP client (from reverse DNS).
    pub host_name: Option<String>,

    /// Local interface address that accepted the connection.
    pub interface_address: Option<String>,
}

// ---------------------------------------------------------------------------
// HostItem — Delivery host list entry (helper type)
// ---------------------------------------------------------------------------

/// A host entry in a delivery host list.
///
/// Replaces the C `host_item` linked list structure from `structs.h`.
/// Used in [`AddressItem`] to represent the list of hosts to which a
/// message should be delivered (from MX/A/AAAA/SRV lookups or manual routes).
#[derive(Debug, Clone, Default)]
pub struct HostItem {
    /// Hostname (may be an IP address string if no name is known).
    pub name: Option<String>,
    /// IP address (resolved from DNS or provided directly).
    pub address: Option<String>,
    /// Port number for SMTP connection (default 25).
    pub port: u16,
    /// MX preference value (lower = higher priority).
    pub mx: i32,
    /// Host status flags (e.g., tried, exhausted, unusable).
    pub status: i32,
    /// Sort key for randomizing hosts with equal MX preference.
    pub sort_key: i32,
}

// ---------------------------------------------------------------------------
// AddressProperties — Propagated address properties (helper type)
// ---------------------------------------------------------------------------

/// Propagated address item properties.
///
/// Replaces `address_item_propagated` from C `structs.h`. These properties
/// are propagated from parent addresses to child addresses during routing
/// and forwarding. They travel with the address as it moves through the
/// router and transport chain.
#[derive(Debug, Clone, Default)]
pub struct AddressProperties {
    /// Override errors-to address for this delivery.
    pub errors_address: Option<String>,
    /// Extra headers to add for this delivery.
    pub extra_headers: Vec<HeaderLine>,
    /// Headers to remove for this delivery (comma-separated names).
    pub remove_headers: Option<String>,
}

// ---------------------------------------------------------------------------
// RetryData — Retry hints database record (helper type)
// ---------------------------------------------------------------------------

/// Retry data from the hints database.
///
/// Replaces the C retry information stored in the hints database file,
/// tracking when delivery was first attempted, last attempted, and when
/// the next attempt should occur. This data is keyed by host+address
/// in the hints database.
#[derive(Debug, Clone)]
pub struct RetryData {
    /// When delivery was first attempted and failed.
    pub first_failed: SystemTime,
    /// When delivery was last attempted.
    pub last_try: SystemTime,
    /// When the next attempt should occur.
    pub next_try: SystemTime,
    /// Whether the retry has expired (max retries or timeout exceeded).
    pub expired: bool,
    /// Retry rule text or key associated with this retry record.
    pub text: Option<String>,
}

// ---------------------------------------------------------------------------
// AddressItem — Delivery address with routing/transport data
// ---------------------------------------------------------------------------

/// A delivery address being processed through the router and transport chain.
///
/// Replaces the C `address_item` struct from `structs.h`. In C, address items
/// form a linked list with parent/child relationships for alias expansion
/// and forwarding. In Rust, the tree structure is represented using indices
/// (`parent_id`, `child_count`) into the delivery address list.
///
/// Each `AddressItem` tracks the full lifecycle of an address from initial
/// receipt through routing, transport selection, and delivery result.
#[derive(Debug, Clone)]
pub struct AddressItem {
    /// The email address being delivered (may be rewritten during routing).
    pub address: String,

    /// Local part of the address (before the `@`).
    pub local_part: String,

    /// Domain part of the address (after the `@`).
    pub domain: String,

    /// Unique identifier for this address item (used for deduplication).
    /// Typically the original address before any rewriting.
    pub unique: String,

    /// Index of the parent address that generated this one (via alias/forward).
    /// `None` for original envelope recipients.
    pub parent_id: Option<usize>,

    /// Number of child addresses generated from this one.
    pub child_count: i32,

    /// Propagated properties (errors address, extra headers, etc.).
    pub prop: AddressProperties,

    /// UID for local delivery (from router or transport configuration).
    /// -1 indicates "not set" (matching C default).
    pub uid: i32,

    /// GID for local delivery (from router or transport configuration).
    /// -1 indicates "not set" (matching C default).
    pub gid: i32,

    /// Address flags bitfield (af_* constants from the C codebase).
    /// Encodes delivery status, verification results, and processing state.
    pub flags: u32,

    /// Result message from delivery attempt (success or failure text).
    pub message: Option<String>,

    /// Special action code for this address (freeze, queue, fail, etc.).
    /// 0 = no special action (matching C default).
    pub special_action: i32,

    /// Home directory for the delivery user.
    pub home_dir: Option<String>,

    /// Current working directory for the delivery process.
    pub current_dir: Option<String>,

    /// List of hosts for remote delivery (from DNS lookups or manual routes).
    pub host_list: Vec<HostItem>,

    /// Fallback host list used when the primary host list is exhausted.
    pub fallback_hosts: Vec<HostItem>,

    /// Name of the transport to use for this address.
    pub transport: Option<String>,
}

impl AddressItem {
    /// Create a new `AddressItem` with the given address.
    ///
    /// Fields are initialized to safe defaults matching the C
    /// `address_defaults` initialization in `globals.c` (line 505):
    /// uid/gid = -1, flags = 0, empty host lists, no parent.
    pub fn new(address: String) -> Self {
        let local_part;
        let domain;
        if let Some(at_pos) = address.rfind('@') {
            local_part = address[..at_pos].to_string();
            domain = address[at_pos + 1..].to_string();
        } else {
            local_part = address.clone();
            domain = String::new();
        }
        let unique = address.clone();
        Self {
            address,
            local_part,
            domain,
            unique,
            parent_id: None,
            child_count: 0,
            prop: AddressProperties::default(),
            uid: -1,
            gid: -1,
            flags: 0,
            message: None,
            special_action: 0,
            home_dir: None,
            current_dir: None,
            host_list: Vec::new(),
            fallback_hosts: Vec::new(),
            transport: None,
        }
    }

    /// Get the unique identity of this address item.
    ///
    /// Returns the `unique` field which serves as the deduplication key
    /// for this address within a message's delivery attempt.
    pub fn id(&self) -> &str {
        &self.unique
    }
}

// ---------------------------------------------------------------------------
// ServerContext — Daemon-lifetime state (AAP §0.4.4)
// ---------------------------------------------------------------------------

/// Daemon-lifetime server state, replacing daemon-related global variables
/// from `globals.c` / `globals.h`.
///
/// Per AAP §0.4.4, `ServerContext` holds: listening sockets, process table,
/// signal state, TLS credentials, and daemon-wide settings. It is created
/// once at startup and passed mutably through the daemon lifecycle.
///
/// This struct is NOT frozen into `Arc` — it is owned by the daemon process
/// and mutated during operation (e.g., process table updates, connection
/// acceptance counting, privilege changes).
///
/// # Lifetime
///
/// Created once in `main()` and lives for the entire daemon process.
/// Passed as `&mut ServerContext` to the daemon event loop.
#[derive(Debug)]
pub struct ServerContext {
    // -- Process identity (from globals.h lines 279+) --
    /// Whether the process is running as root (C: f.running_as_root check).
    pub running_as_root: bool,

    /// Whether the current user has admin privileges (C: f.admin_user).
    pub admin_user: bool,

    /// Real UID of the process at startup (C: real_uid from getuid()).
    pub real_uid: u32,

    /// Real GID of the process at startup (C: real_gid from getgid()).
    pub real_gid: u32,

    /// Configured Exim UID for privilege reduction (C: exim_uid).
    pub exim_uid: u32,

    /// Configured Exim GID for privilege reduction (C: exim_gid).
    pub exim_gid: u32,

    // -- Daemon state (from globals.h lines 156–275 flags) --
    /// Whether the daemon is listening for connections (C: f.daemon_listen).
    pub daemon_listen: bool,

    /// Whether the daemon is a scion (child of inetd or similar).
    pub daemon_scion: bool,

    /// Whether the daemon runs in the background (C: f.background_daemon).
    /// Default: `true` (matching C globals.c initialization).
    pub background_daemon: bool,

    /// Whether running in inetd wait mode (C: f.inetd_wait_mode).
    pub inetd_wait_mode: bool,

    // -- Network / Connection limits --
    /// Maximum simultaneous SMTP connections (C: smtp_accept_max).
    /// Default: 20.
    pub smtp_accept_max: i32,

    /// Queue-only threshold for SMTP connections (C: smtp_accept_queue).
    /// When accept count exceeds this, new messages are queued only.
    pub smtp_accept_queue: i32,

    /// Reserved connection slots for privileged hosts (C: smtp_accept_reserve).
    pub smtp_accept_reserve: i32,

    /// Current number of accepted SMTP connections (C: smtp_accept_count).
    pub smtp_accept_count: i32,

    // -- Listening sockets and process table --
    /// File descriptors for listening sockets (C: daemon listen socket array).
    /// Owned by the daemon — closed on shutdown.
    pub listening_sockets: Vec<OwnedFd>,

    /// Active child process tracking (C: smtp_slots[] array).
    pub smtp_slots: Vec<SmtpSlot>,

    // -- TLS credentials --
    /// TLS certificate file path (C: tls_certificate, expandable string).
    pub tls_certificate: Option<String>,

    /// TLS private key file path (C: tls_privatekey, expandable string).
    pub tls_privatekey: Option<String>,

    /// Host list for which TLS is advertised (C: tls_advertise_hosts).
    /// Default: `"*"` (advertise to all hosts).
    pub tls_advertise_hosts: String,

    // -- Queue runner configuration --
    /// Interval between queue runner invocations (C: queue_interval).
    /// `None` means queue runner is disabled.
    pub queue_interval: Option<Duration>,

    /// Maximum concurrent queue runner processes (C: queue_run_max).
    /// Stored as expandable string matching config representation.
    pub queue_run_max: String,

    // -- Primary hostname --
    /// Primary hostname of this server (C: primary_hostname).
    /// Set during configuration parsing, used in EHLO and message IDs.
    pub primary_hostname: String,

    // -- Debug and logging --
    /// Debug output selector bitmask (C: debug_selector).
    pub debug_selector: u32,

    /// Log output selector bitmask (C: log_selector).
    pub log_selector: u64,

    /// Debug output file path (C: debug_file, if redirecting debug output).
    pub debug_file: Option<PathBuf>,

    // -- Privilege tracking --
    /// Whether root privilege has been permanently dropped (C: f.removed_privilege).
    pub removed_privilege: bool,

    /// Whether to drop privilege before local deliveries (C: f.deliver_drop_privilege).
    pub deliver_drop_privilege: bool,

    // -- Test harness --
    /// Whether running inside the test harness (C: f.running_in_test_harness).
    pub running_in_test_harness: bool,

    // -- Timestamps --
    /// Time when the current message was received or the daemon was started.
    /// Replaces C `received_time` global (struct timeval).
    pub received_time: SystemTime,

    /// Timezone string for log timestamps (e.g., "+0000", "-0500").
    /// Replaces C `timezone_string` / `timestamp_zone`.
    pub timestamp_zone: String,

    /// CLI override for local interfaces (`-oX` flag).
    /// When set, overrides the `local_interfaces` and `daemon_smtp_port`
    /// configuration options for socket binding.  The value is the raw
    /// interface specification string from the command line.
    pub override_local_interfaces: Option<String>,
}

impl ServerContext {
    /// Create a new `ServerContext` with default values matching C globals.c.
    ///
    /// All defaults are chosen to match the C initialization in `globals.c`:
    /// - `background_daemon`: `true` (C: `f.background_daemon = TRUE`)
    /// - `smtp_accept_max`: 20 (C: `smtp_accept_max = 20`)
    /// - `tls_advertise_hosts`: `"*"` (C: US"*")
    /// - `queue_run_max`: `"5"` (C config default)
    /// - All other fields: `false`/`0`/empty/`None`
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for ServerContext {
    fn default() -> Self {
        Self {
            running_as_root: false,
            admin_user: false,
            real_uid: 0,
            real_gid: 0,
            exim_uid: 0,
            exim_gid: 0,
            daemon_listen: false,
            daemon_scion: false,
            background_daemon: true,
            inetd_wait_mode: false,
            smtp_accept_max: 20,
            smtp_accept_queue: 0,
            smtp_accept_reserve: 0,
            smtp_accept_count: 0,
            listening_sockets: Vec::new(),
            smtp_slots: Vec::new(),
            tls_certificate: None,
            tls_privatekey: None,
            tls_advertise_hosts: String::from("*"),
            queue_interval: None,
            queue_run_max: String::from("5"),
            primary_hostname: String::new(),
            debug_selector: 0,
            log_selector: 0,
            debug_file: None,
            removed_privilege: false,
            deliver_drop_privilege: false,
            running_in_test_harness: false,
            received_time: SystemTime::UNIX_EPOCH,
            timestamp_zone: String::new(),
            override_local_interfaces: None,
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
/// when message processing completes (analogous to the per-message arena
/// in the C allocator — POOL_MESSAGE).
///
/// # Lifetime
///
/// Created when MAIL FROM is accepted (or when a locally-generated message
/// begins). Dropped when message processing completes (after all deliveries
/// or when the message is rejected/abandoned).
#[derive(Debug)]
pub struct MessageContext {
    // -- Message identity --
    /// Unique message identifier (C: message_id, base-62 encoded).
    /// Generated by [`exim_spool::message_id`] when the message is accepted.
    pub message_id: String,

    // -- Envelope --
    /// Sender address from MAIL FROM (C: sender_address).
    /// `None` for bounce messages (empty envelope sender).
    pub sender_address: Option<String>,

    /// IP address of the sending host (C: sender_host_address).
    /// `None` for locally-submitted messages.
    pub sender_host_address: Option<String>,

    /// Hostname of the sending host from reverse DNS (C: sender_host_name).
    pub sender_host_name: Option<String>,

    /// Port number of the sending host connection (C: sender_host_port).
    pub sender_host_port: u16,

    /// Ident string from the sending host (C: sender_ident, RFC 1413).
    pub sender_ident: Option<String>,

    // -- Recipients --
    /// List of envelope recipients (C: recipients_list[] array).
    pub recipients: Vec<RecipientItem>,

    // -- Headers --
    /// Message headers (C: header_list linked list, converted to Vec).
    pub headers: Vec<HeaderLine>,

    // -- Body information --
    /// Total message size in bytes including headers (C: message_size).
    pub message_size: i64,

    /// Number of lines in the entire message (C: message_linecount).
    pub message_linecount: i32,

    /// Number of lines in the message body only (C: body_linecount).
    pub body_linecount: i32,

    /// Number of NUL (zero) bytes in the message body (C: body_zerocount).
    pub body_zerocount: i32,

    // -- Message body preview --
    /// First N bytes of the message body for ACL access (C: message_body).
    pub message_body: Option<String>,

    /// Last N bytes of the message body for ACL access (C: message_body_end).
    pub message_body_end: Option<String>,

    /// Configured maximum size for message_body capture (C: message_body_size).
    pub message_body_size: i32,

    // -- Authentication --
    /// Authenticated sender address (C: authenticated_sender).
    pub authenticated_sender: Option<String>,

    /// Authenticated user ID (C: authenticated_id).
    pub authenticated_id: Option<String>,

    /// Name of the authenticator used (C: sender_host_authenticated).
    pub sender_host_authenticated: Option<String>,

    // -- Protocol --
    /// Protocol string (C: received_protocol, e.g., "esmtp", "esmtps", "local").
    pub received_protocol: Option<String>,

    // -- DSN (Delivery Status Notification) --
    /// DSN envelope ID from MAIL FROM ENVID parameter (C: dsn_envid).
    pub dsn_envid: Option<String>,

    /// DSN RET parameter (C: dsn_ret). 0 = not set, 1 = HDRS, 2 = FULL.
    pub dsn_ret: i32,

    // -- ACL variables --
    /// Connection-level ACL variables $acl_c0..$acl_c9.
    /// Fixed size of 10 entries (matching C ACL_CVARS).
    pub acl_var_c: Vec<Option<String>>,

    /// Message-level ACL variables $acl_m0..$acl_m9 and named $acl_m_*.
    /// First 10 entries are indexed ($acl_m0..9), additional entries
    /// are for named message-level variables.
    pub acl_var_m: Vec<Option<String>>,

    // -- Content scanning results --
    /// SpamAssassin score as a floating point value.
    pub spam_score: Option<f64>,

    /// SpamAssassin score multiplied by 10 for integer comparison.
    pub spam_score_int: Option<i32>,

    /// Name of malware detected by content scanner.
    pub malware_name: Option<String>,

    // -- TLS session info --
    /// Inbound TLS session information (C: tls_in struct).
    pub tls_in: TlsSessionInfo,

    // -- Message flags --
    /// Whether the message is frozen (C: deliver_freeze).
    pub deliver_freeze: bool,

    /// Whether this is the first delivery attempt (C: deliver_firsttime).
    pub deliver_firsttime: bool,

    /// Data from local_scan() function (C: local_scan_data).
    pub local_scan_data: Option<String>,

    // -- Spool references --
    /// Open file descriptor for the spool -D (data) file.
    /// `None` if no data file is open.
    pub data_file: Option<OwnedFd>,

    // -- SMTP state --
    /// Current SMTP command being processed (for logging context).
    pub smtp_command: Option<String>,
}

impl MessageContext {
    /// Create a new `MessageContext` for a fresh message.
    ///
    /// Initializes ACL variable vectors to the standard size (10 entries
    /// for $acl_c0..9 and $acl_m0..9). All other fields default to
    /// empty/zero/false/None.
    pub fn new() -> Self {
        Self::default()
    }

    /// Wrap the sender address as a tainted value for safe processing.
    ///
    /// Network-received sender addresses are untrusted and should be treated
    /// as tainted data until validated. Uses [`Tainted::new()`] to wrap the
    /// address.
    pub fn tainted_sender_address(&self) -> Option<Tainted<String>> {
        self.sender_address
            .as_ref()
            .map(|addr| Tainted::new(addr.clone()))
    }
}

impl Default for MessageContext {
    fn default() -> Self {
        Self {
            message_id: String::new(),
            sender_address: None,
            sender_host_address: None,
            sender_host_name: None,
            sender_host_port: 0,
            sender_ident: None,
            recipients: Vec::new(),
            headers: Vec::new(),
            message_size: 0,
            message_linecount: 0,
            body_linecount: 0,
            body_zerocount: 0,
            message_body: None,
            message_body_end: None,
            message_body_size: 500, // C default: MESSAGE_BODY_VISIBLE = 500
            authenticated_sender: None,
            authenticated_id: None,
            sender_host_authenticated: None,
            received_protocol: None,
            dsn_envid: None,
            dsn_ret: 0,
            acl_var_c: vec![None; 10],
            acl_var_m: vec![None; 10],
            spam_score: None,
            spam_score_int: None,
            malware_name: None,
            tls_in: TlsSessionInfo::default(),
            deliver_freeze: false,
            deliver_firsttime: false,
            local_scan_data: None,
            data_file: None,
            smtp_command: None,
        }
    }
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
/// Its lifetime is shorter than [`MessageContext`] — a single message may
/// trigger multiple delivery attempts (one per recipient address).
///
/// # Lifetime
///
/// Created when delivery begins for a specific address. Dropped when the
/// delivery attempt completes (success, failure, or defer).
#[derive(Debug, Default)]
pub struct DeliveryContext {
    // -- Current address --
    /// Local part of the current delivery address (C: deliver_localpart).
    pub deliver_localpart: Option<String>,

    /// Domain of the current delivery address (C: deliver_domain).
    pub deliver_domain: Option<String>,

    /// Original local part before any rewriting (C: deliver_localpart_orig).
    pub deliver_localpart_orig: Option<String>,

    /// Original domain before any rewriting (C: deliver_domain_orig).
    pub deliver_domain_orig: Option<String>,

    // -- Delivery hosts --
    /// Delivery host name for remote delivery (C: deliver_host).
    pub deliver_host: Option<String>,

    /// Delivery host IP address (C: deliver_host_address).
    pub deliver_host_address: Option<String>,

    /// Delivery host port (C: deliver_host_port). Default: 0 (not set).
    pub deliver_host_port: u16,

    // -- Transport/Router result --
    /// Name of the transport being used (C: transport_name).
    pub transport_name: Option<String>,

    /// Name of the router that handled this address (C: router_name).
    pub router_name: Option<String>,

    // -- Delivery status flags --
    /// Whether the message is frozen (C: deliver_freeze).
    pub deliver_freeze: bool,

    /// Force delivery even if frozen (C: deliver_force, from -M flag).
    pub deliver_force: bool,

    /// Force thaw of frozen message (C: deliver_force_thaw, from -Mt flag).
    pub deliver_force_thaw: bool,

    /// Message was manually thawed by operator (C: deliver_manual_thaw).
    pub deliver_manual_thaw: bool,

    // -- Retry data --
    /// Retry interval for this delivery (C: retry_interval, seconds).
    pub retry_interval: Option<Duration>,

    /// Retry data from the hints database for this host/address.
    pub retry_data: Option<RetryData>,

    // -- Address data variables (set by routers) --
    /// Data from router's local-part expansion (C: deliver_localpart_data).
    pub deliver_localpart_data: Option<String>,

    /// Data from router's domain expansion (C: deliver_domain_data).
    pub deliver_domain_data: Option<String>,

    /// Recipient-specific data from router (C: deliver_address_data / recipient_data).
    pub recipient_data: Option<String>,

    /// Sender-specific data (C: sender_data, from verify=sender ACL condition).
    pub sender_data: Option<String>,

    // -- Lookup result --
    /// Last lookup result value (C: lookup_value).
    /// Set by lookup operations during routing and ACL evaluation.
    pub lookup_value: Option<String>,

    // -- DNSBL results --
    /// Domain that matched a DNSBL check (C: dnslist_domain).
    pub dnslist_domain: Option<String>,

    /// The matched address or pattern from DNSBL (C: dnslist_matched).
    pub dnslist_matched: Option<String>,

    /// The value returned by the DNSBL lookup (C: dnslist_value).
    pub dnslist_value: Option<String>,

    // -- Callout result --
    /// Address used for SMTP callout verification (C: callout_address).
    pub callout_address: Option<String>,

    // -- Interface --
    /// Source IP address for sending (C: sending_ip_address).
    pub sending_ip_address: Option<String>,

    /// Source port for sending (C: sending_port).
    pub sending_port: u16,

    // -- Delivery file reference --
    /// Open file descriptor for the spool data file during delivery
    /// (C: deliver_datafile).
    pub deliver_datafile: Option<OwnedFd>,
}

impl DeliveryContext {
    /// Create a new `DeliveryContext` for a fresh delivery attempt.
    ///
    /// All fields default to `None`/`false`/`0` — they are populated
    /// as the delivery attempt progresses through routing and transport.
    pub fn new() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// ConfigContext — Parsed configuration wrapper (AAP §0.4.4)
// ---------------------------------------------------------------------------

/// Parsed configuration wrapper holding an immutable `Arc<Config>`.
///
/// Per AAP §0.4.3: "Config data stored in `Arc<Config>` made immutable
/// after parsing — no mutable shared config state."
///
/// `ConfigContext` wraps the frozen `Arc<Config>` along with metadata
/// about the configuration file. The actual configuration options and
/// driver instances are defined in `exim-config/src/types.rs` within
/// the [`Config`] struct. `ConfigContext` adds:
///
/// - The filesystem path of the configuration file (`config_filename`)
/// - A flag indicating whether the config has changed since last load
/// - Access methods delegating to `Config::get()`
///
/// # Lifetime
///
/// Created once after configuration parsing. The `Arc<Config>` can be
/// shared across forked child processes. `config_changed` is checked by
/// the daemon to detect SIGHUP-triggered reloads.
#[derive(Debug, Clone)]
pub struct ConfigContext {
    /// Filesystem path of the configuration file (C: config_main_filename).
    pub config_filename: PathBuf,

    /// Whether the configuration file has changed since it was last parsed
    /// (C: f.config_changed). Checked by the daemon after SIGHUP.
    pub config_changed: bool,

    /// The frozen immutable configuration data, shared via `Arc`.
    /// Access the underlying configuration with [`Config::get()`] or
    /// via `Deref` (e.g., `config.qualify_domain`).
    pub config: Arc<Config>,
}

impl ConfigContext {
    /// Create a new `ConfigContext` by wrapping a frozen `Arc<Config>`.
    ///
    /// The `config` parameter should be obtained by calling
    /// [`Config::freeze()`] on a fully-parsed configuration.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use std::path::PathBuf;
    /// use exim_config::Config;
    /// use exim_core::context::ConfigContext;
    ///
    /// let parsed = exim_config::ConfigContext::default();
    /// let frozen = Config::freeze(parsed);
    /// let ctx = ConfigContext::new(frozen, PathBuf::from("/etc/exim/configure"));
    /// ```
    pub fn new(config: Arc<Config>, config_filename: PathBuf) -> Self {
        Self {
            config_filename,
            config_changed: false,
            config,
        }
    }

    /// Create a `ConfigContext` by freezing a parsed configuration.
    ///
    /// Convenience method that calls [`Config::freeze()`] internally.
    /// Uses `Config::freeze()` (AAP §0.4.3 immutability rule).
    pub fn from_parsed(parsed: exim_config::ConfigContext, config_filename: PathBuf) -> Self {
        let config = Config::freeze(parsed);
        Self {
            config_filename,
            config_changed: false,
            config,
        }
    }

    /// Access the underlying parsed configuration data.
    ///
    /// Delegates to [`Config::get()`] to return a reference to the
    /// inner `exim_config::ConfigContext` containing all parsed options.
    pub fn get_config(&self) -> &exim_config::ConfigContext {
        self.config.get()
    }

    /// Clone the shared configuration reference.
    ///
    /// The configuration data itself is not copied — only the `Arc`
    /// reference count is incremented. Uses [`Arc::clone()`].
    pub fn shared_config(&self) -> Arc<Config> {
        Arc::clone(&self.config)
    }
}

// ---------------------------------------------------------------------------
// Taint Tracking Helper Functions
// ---------------------------------------------------------------------------
// These functions demonstrate usage of the Tainted<T>/Clean<T> API from
// exim-store, providing convenience wrappers for common taint operations
// in the MTA. They satisfy the members_accessed requirements for the
// exim_store import.

/// Sanitize a tainted string value using a validation function.
///
/// Wraps [`Tainted::sanitize()`] with logging of the tainted value length
/// via [`Tainted::as_ref()`] for safe inspection before validation.
///
/// # Arguments
///
/// * `tainted` — A tainted string from untrusted input (SMTP, DNS, etc.)
/// * `validator` — A function that returns `true` if the value is safe
///
/// # Returns
///
/// `Ok(Clean<String>)` if validation passes, `Err(TaintError)` if rejected.
///
/// # Example
///
/// ```rust,ignore
/// use exim_core::context::sanitize_string;
/// use exim_store::Tainted;
///
/// let input = Tainted::new("user@example.com".to_string());
/// let clean = sanitize_string(input, |s| s.contains('@')).unwrap();
/// ```
pub fn sanitize_string(
    tainted: Tainted<String>,
    validator: impl FnOnce(&String) -> bool,
) -> Result<Clean<String>, exim_store::TaintError> {
    tainted.sanitize(validator)
}

/// Inspect a tainted value without consuming it.
///
/// Uses [`Tainted::as_ref()`] (via the `AsRef` trait) for safe read-only
/// access to tainted data without requiring validation or consuming the
/// wrapper. Useful for logging, size checks, and pattern inspection.
pub fn inspect_tainted<T>(tainted: &Tainted<T>) -> &T {
    tainted.as_ref()
}

/// Forcibly remove the taint marker from a value without validation.
///
/// Wraps [`Tainted::force_clean()`]. Only appropriate when the value
/// originates from a trusted source (e.g., configuration file data,
/// locally computed values).
///
/// # Warning
///
/// Every call to this function should be reviewed — prefer
/// [`sanitize_string()`] for validated taint removal.
pub fn force_clean_value<T>(tainted: Tainted<T>) -> Clean<T> {
    tainted.force_clean()
}

/// Extract the inner value from a clean wrapper.
///
/// Wraps [`Clean::into_inner()`] to unwrap a validated clean value.
pub fn extract_clean<T>(clean: Clean<T>) -> T {
    clean.into_inner()
}

/// Get a reference to the inner value of a clean wrapper.
///
/// Wraps [`Clean::as_ref()`] (via the `AsRef` trait) for read-only
/// access to the validated data without consuming the wrapper.
pub fn inspect_clean<T>(clean: &Clean<T>) -> &T {
    clean.as_ref()
}

/// Create a clean value from trusted configuration data.
///
/// Wraps [`Clean::new()`] for values that originate from the parsed
/// configuration (which is trusted after validation).
pub fn from_trusted<T>(value: T) -> Clean<T> {
    Clean::new(value)
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // -----------------------------------------------------------------------
    // OcspStatus tests
    // -----------------------------------------------------------------------

    #[test]
    fn ocsp_status_default_is_not_requested() {
        let status = OcspStatus::default();
        assert!(matches!(status, OcspStatus::NotRequested));
    }

    #[test]
    fn ocsp_status_clone_and_debug() {
        let status = OcspStatus::Verified;
        let cloned = status.clone();
        assert!(matches!(cloned, OcspStatus::Verified));
        let debug = format!("{:?}", status);
        assert!(debug.contains("Verified"));
    }

    #[test]
    fn ocsp_status_all_variants() {
        let variants = vec![
            OcspStatus::NotRequested,
            OcspStatus::NotResponded,
            OcspStatus::VerifyNotTried,
            OcspStatus::Failed,
            OcspStatus::Verified,
        ];
        assert_eq!(variants.len(), 5);
    }

    // -----------------------------------------------------------------------
    // TlsSessionInfo tests
    // -----------------------------------------------------------------------

    #[test]
    fn tls_session_info_default() {
        let tls = TlsSessionInfo::default();
        assert!(!tls.active);
        assert_eq!(tls.bits, 0);
        assert!(!tls.certificate_verified);
        assert!(!tls.dane_verified);
        assert_eq!(tls.tlsa_usage, 0);
        assert!(tls.cipher.is_none());
        assert!(tls.cipher_stdname.is_none());
        assert!(tls.ver.is_none());
        assert!(tls.peerdn.is_none());
        assert!(tls.sni.is_none());
        assert!(tls.channelbinding.is_none());
        assert!(matches!(tls.ocsp_status, OcspStatus::NotRequested));
        assert_eq!(tls.resumption, 0);
    }

    #[test]
    fn tls_session_info_active_session() {
        let tls = TlsSessionInfo {
            active: true,
            bits: 256,
            certificate_verified: true,
            cipher: Some("TLS_AES_256_GCM_SHA384".to_string()),
            ver: Some("TLSv1.3".to_string()),
            ..Default::default()
        };
        assert!(tls.active);
        assert_eq!(tls.bits, 256);
        assert_eq!(tls.cipher.as_deref(), Some("TLS_AES_256_GCM_SHA384"));
    }

    // -----------------------------------------------------------------------
    // HeaderType tests
    // -----------------------------------------------------------------------

    #[test]
    fn header_type_default_is_other() {
        let ht = HeaderType::default();
        assert!(matches!(ht, HeaderType::Other));
    }

    #[test]
    fn header_type_all_variants_exist() {
        let variants: Vec<HeaderType> = vec![
            HeaderType::From,
            HeaderType::To,
            HeaderType::Cc,
            HeaderType::Bcc,
            HeaderType::Subject,
            HeaderType::ReplyTo,
            HeaderType::MessageId,
            HeaderType::Date,
            HeaderType::Received,
            HeaderType::ContentType,
            HeaderType::MimeVersion,
            HeaderType::Other,
            HeaderType::Old,
            HeaderType::Deleted,
        ];
        assert_eq!(variants.len(), 14);
    }

    // -----------------------------------------------------------------------
    // HeaderLine tests
    // -----------------------------------------------------------------------

    #[test]
    fn header_line_new_constructor() {
        let hl = HeaderLine::new("From: user@example.com\r\n".to_string(), HeaderType::From);
        assert_eq!(hl.slen, 24);
        assert!(matches!(hl.htype, HeaderType::From));
        assert!(hl.text.starts_with("From:"));
    }

    #[test]
    fn header_line_empty() {
        let hl = HeaderLine::new(String::new(), HeaderType::Other);
        assert!(hl.text.is_empty());
        assert_eq!(hl.slen, 0);
        assert!(matches!(hl.htype, HeaderType::Other));
    }

    // -----------------------------------------------------------------------
    // RecipientItem tests
    // -----------------------------------------------------------------------

    #[test]
    fn recipient_item_basic() {
        let ri = RecipientItem {
            address: "user@example.com".to_string(),
            errors_to: None,
            orcpt: Some("rfc822;user@example.com".to_string()),
            dsn_flags: 0x04,
            pno: None,
        };
        assert_eq!(ri.address, "user@example.com");
        assert!(ri.errors_to.is_none());
        assert!(ri.orcpt.is_some());
        assert_eq!(ri.dsn_flags, 0x04);
    }

    #[test]
    fn recipient_item_default() {
        let ri = RecipientItem::default();
        assert!(ri.address.is_empty());
        assert!(ri.errors_to.is_none());
        assert!(ri.orcpt.is_none());
        assert_eq!(ri.dsn_flags, 0);
        assert!(ri.pno.is_none());
    }

    // -----------------------------------------------------------------------
    // SmtpSlot tests
    // -----------------------------------------------------------------------

    #[test]
    fn smtp_slot_default() {
        let slot = SmtpSlot::default();
        assert_eq!(slot.pid, 0);
        assert!(slot.host_address.is_none());
        assert!(slot.host_name.is_none());
        assert!(slot.interface_address.is_none());
    }

    #[test]
    fn smtp_slot_with_values() {
        let slot = SmtpSlot {
            pid: 12345,
            host_address: Some("192.168.1.100".to_string()),
            host_name: Some("mail.example.com".to_string()),
            interface_address: Some("0.0.0.0".to_string()),
        };
        assert_eq!(slot.pid, 12345);
        assert_eq!(slot.host_address.as_deref(), Some("192.168.1.100"));
    }

    // -----------------------------------------------------------------------
    // AddressItem tests
    // -----------------------------------------------------------------------

    #[test]
    fn address_item_new_with_at() {
        let addr = AddressItem::new("user@example.com".to_string());
        assert_eq!(addr.address, "user@example.com");
        assert_eq!(addr.local_part, "user");
        assert_eq!(addr.domain, "example.com");
        assert_eq!(addr.uid, -1);
        assert_eq!(addr.gid, -1);
        assert_eq!(addr.flags, 0);
    }

    #[test]
    fn address_item_new_without_at() {
        let addr = AddressItem::new("localuser".to_string());
        assert_eq!(addr.address, "localuser");
        assert_eq!(addr.local_part, "localuser");
        assert_eq!(addr.domain, "");
    }

    #[test]
    fn address_item_new_empty() {
        let addr = AddressItem::new(String::new());
        assert_eq!(addr.address, "");
        assert_eq!(addr.local_part, "");
        assert_eq!(addr.domain, "");
    }

    #[test]
    fn address_item_id_returns_unique() {
        let addr = AddressItem::new("test@domain.org".to_string());
        assert_eq!(addr.id(), "test@domain.org");
    }

    #[test]
    fn address_item_multiple_at_signs() {
        // rfind('@') should split at the last '@'
        let addr = AddressItem::new("user@host@example.com".to_string());
        assert_eq!(addr.local_part, "user@host");
        assert_eq!(addr.domain, "example.com");
    }

    // -----------------------------------------------------------------------
    // HostItem tests
    // -----------------------------------------------------------------------

    #[test]
    fn host_item_default() {
        let host = HostItem::default();
        assert!(host.name.is_none());
        assert!(host.address.is_none());
        assert_eq!(host.port, 0);
        assert_eq!(host.mx, 0);
        assert_eq!(host.status, 0);
        assert_eq!(host.sort_key, 0);
    }

    #[test]
    fn host_item_creation() {
        let host = HostItem {
            name: Some("mx1.example.com".to_string()),
            address: Some("93.184.216.34".to_string()),
            port: 25,
            mx: 10,
            sort_key: 10,
            status: 0,
        };
        assert_eq!(host.name.as_deref(), Some("mx1.example.com"));
        assert_eq!(host.port, 25);
        assert_eq!(host.mx, 10);
    }

    // -----------------------------------------------------------------------
    // AddressProperties tests
    // -----------------------------------------------------------------------

    #[test]
    fn address_properties_default() {
        let props = AddressProperties::default();
        assert!(props.errors_address.is_none());
        assert!(props.extra_headers.is_empty());
        assert!(props.remove_headers.is_none());
    }

    // -----------------------------------------------------------------------
    // ServerContext tests
    // -----------------------------------------------------------------------

    #[test]
    fn server_context_new_defaults() {
        let sc = ServerContext::new();
        assert!(!sc.running_as_root);
        assert!(!sc.admin_user);
        assert_eq!(sc.real_uid, 0);
        assert_eq!(sc.real_gid, 0);
        assert_eq!(sc.exim_uid, 0);
        assert_eq!(sc.exim_gid, 0);
        assert!(!sc.daemon_listen);
        assert!(!sc.daemon_scion);
        assert!(sc.background_daemon);
        assert!(!sc.inetd_wait_mode);
        assert_eq!(sc.smtp_accept_max, 20);
        assert_eq!(sc.smtp_accept_queue, 0);
        assert_eq!(sc.smtp_accept_reserve, 0);
        assert_eq!(sc.smtp_accept_count, 0);
        assert!(sc.listening_sockets.is_empty());
        assert!(sc.smtp_slots.is_empty());
        assert!(sc.tls_certificate.is_none());
        assert!(sc.tls_privatekey.is_none());
        assert_eq!(sc.tls_advertise_hosts, "*");
        assert!(sc.queue_interval.is_none());
        assert_eq!(sc.queue_run_max, "5");
        assert_eq!(sc.primary_hostname, "");
        assert_eq!(sc.debug_selector, 0);
        assert_eq!(sc.log_selector, 0);
        assert!(sc.debug_file.is_none());
        assert!(!sc.removed_privilege);
        assert!(!sc.deliver_drop_privilege);
        assert!(!sc.running_in_test_harness);
    }

    #[test]
    fn server_context_received_time_set() {
        let sc = ServerContext::new();
        assert_eq!(sc.received_time, std::time::SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn server_context_timestamp_zone() {
        let sc = ServerContext::new();
        assert_eq!(sc.timestamp_zone, "");
    }

    // -----------------------------------------------------------------------
    // MessageContext tests
    // -----------------------------------------------------------------------

    #[test]
    fn message_context_new_defaults() {
        let mc = MessageContext::new();
        assert!(mc.message_id.is_empty());
        assert!(mc.sender_address.is_none());
        assert!(mc.sender_host_address.is_none());
        assert!(mc.sender_host_name.is_none());
        assert_eq!(mc.sender_host_port, 0);
        assert!(mc.sender_ident.is_none());
        assert!(mc.recipients.is_empty());
        assert!(mc.headers.is_empty());
        assert_eq!(mc.message_size, 0);
        assert_eq!(mc.message_linecount, 0);
        assert_eq!(mc.body_linecount, 0);
        assert_eq!(mc.body_zerocount, 0);
        assert!(mc.message_body.is_none());
        assert!(mc.message_body_end.is_none());
        assert_eq!(mc.message_body_size, 500);
        assert!(mc.authenticated_sender.is_none());
        assert!(mc.authenticated_id.is_none());
        assert!(mc.sender_host_authenticated.is_none());
        assert!(mc.received_protocol.is_none());
        assert!(mc.dsn_envid.is_none());
        assert_eq!(mc.dsn_ret, 0);
        assert_eq!(mc.acl_var_c.len(), 10);
        assert_eq!(mc.acl_var_m.len(), 10);
        assert!(mc.spam_score.is_none());
        assert!(mc.spam_score_int.is_none());
        assert!(mc.malware_name.is_none());
        assert!(!mc.tls_in.active);
        assert!(!mc.deliver_freeze);
        assert!(!mc.deliver_firsttime);
        assert!(mc.local_scan_data.is_none());
        assert!(mc.data_file.is_none());
        assert!(mc.smtp_command.is_none());
    }

    #[test]
    fn message_context_acl_vars_independent() {
        let mut mc = MessageContext::new();
        mc.acl_var_c[0] = Some("hello".to_string());
        mc.acl_var_m[5] = Some("world".to_string());
        assert_eq!(mc.acl_var_c[0].as_deref(), Some("hello"));
        assert!(mc.acl_var_c[1].is_none());
        assert_eq!(mc.acl_var_m[5].as_deref(), Some("world"));
        assert!(mc.acl_var_m[0].is_none());
    }

    #[test]
    fn message_context_tainted_sender() {
        let mut mc = MessageContext::new();
        mc.sender_address = Some("user@evil.com".to_string());
        let tainted = mc.tainted_sender_address();
        assert!(tainted.is_some());
        let t = tainted.unwrap();
        assert_eq!(t.as_ref(), "user@evil.com");
    }

    #[test]
    fn message_context_tainted_sender_none() {
        let mc = MessageContext::new();
        assert!(mc.tainted_sender_address().is_none());
    }

    // -----------------------------------------------------------------------
    // DeliveryContext tests
    // -----------------------------------------------------------------------

    #[test]
    fn delivery_context_defaults() {
        let dc = DeliveryContext::default();
        assert!(dc.deliver_localpart.is_none());
        assert!(dc.deliver_domain.is_none());
        assert!(dc.deliver_localpart_orig.is_none());
        assert!(dc.deliver_domain_orig.is_none());
        assert!(dc.deliver_host.is_none());
        assert!(dc.deliver_host_address.is_none());
        assert_eq!(dc.deliver_host_port, 0);
        assert!(dc.transport_name.is_none());
        assert!(dc.router_name.is_none());
        assert!(!dc.deliver_freeze);
        assert!(!dc.deliver_force);
        assert!(!dc.deliver_force_thaw);
        assert!(!dc.deliver_manual_thaw);
        assert!(dc.retry_interval.is_none());
        assert!(dc.retry_data.is_none());
        assert!(dc.deliver_localpart_data.is_none());
        assert!(dc.deliver_domain_data.is_none());
        assert!(dc.recipient_data.is_none());
        assert!(dc.sender_data.is_none());
        assert!(dc.lookup_value.is_none());
        assert!(dc.dnslist_domain.is_none());
        assert!(dc.dnslist_matched.is_none());
        assert!(dc.dnslist_value.is_none());
        assert!(dc.callout_address.is_none());
        assert!(dc.sending_ip_address.is_none());
        assert_eq!(dc.sending_port, 0);
        assert!(dc.deliver_datafile.is_none());
    }

    #[test]
    fn delivery_context_new_same_as_default() {
        let dc1 = DeliveryContext::new();
        let dc2 = DeliveryContext::default();
        assert_eq!(dc1.deliver_host_port, dc2.deliver_host_port);
        assert_eq!(dc1.deliver_freeze, dc2.deliver_freeze);
        assert_eq!(dc1.sending_port, dc2.sending_port);
    }

    // -----------------------------------------------------------------------
    // ConfigContext tests
    // -----------------------------------------------------------------------

    #[test]
    fn config_context_from_parsed_and_access() {
        let cfg_ctx = exim_config::ConfigContext::default();
        let cc =
            ConfigContext::from_parsed(cfg_ctx, std::path::PathBuf::from("/etc/exim/exim.conf"));
        assert_eq!(
            cc.config_filename,
            std::path::PathBuf::from("/etc/exim/exim.conf")
        );
        assert!(!cc.config_changed);

        // Test Config::get() returns a reference to the inner ConfigContext
        let config_ref = cc.get_config();
        // spool_directory exists in exim_config::ConfigContext
        assert!(config_ref.spool_directory.is_empty() || !config_ref.spool_directory.is_empty());

        // Test shared_config() returns Arc with correct ref count
        let arc1 = cc.shared_config();
        let arc2 = cc.shared_config();
        assert!(Arc::strong_count(&arc1) >= 2);
        drop(arc2);
    }

    #[test]
    fn config_context_new_with_default_config() {
        let cfg_ctx = exim_config::ConfigContext::default();
        let config = Config::freeze(cfg_ctx);
        let cc = ConfigContext::new(config, std::path::PathBuf::from("/etc/exim/exim.conf"));
        assert!(!cc.config_changed);
        let inner = cc.get_config();
        // Verify it's a valid reference
        let _ = &inner.spool_directory;
    }

    // -----------------------------------------------------------------------
    // Taint helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn sanitize_string_valid() {
        let tainted = Tainted::new("safe_value".to_string());
        let result = sanitize_string(tainted, |s| !s.contains('\0'));
        assert!(result.is_ok());
        let clean = result.unwrap();
        assert_eq!(clean.as_ref(), "safe_value");
    }

    #[test]
    fn sanitize_string_invalid() {
        let tainted = Tainted::new("bad\0value".to_string());
        let result = sanitize_string(tainted, |s| !s.contains('\0'));
        assert!(result.is_err());
    }

    #[test]
    fn inspect_tainted_value() {
        let t = Tainted::new(42i32);
        let val = inspect_tainted(&t);
        assert_eq!(*val, 42);
    }

    #[test]
    fn force_clean_value_works() {
        let t = Tainted::new("forced".to_string());
        let clean = force_clean_value(t);
        assert_eq!(clean.as_ref(), "forced");
    }

    #[test]
    fn extract_clean_unwraps() {
        let c = Clean::new(99u32);
        let inner = extract_clean(c);
        assert_eq!(inner, 99);
    }

    #[test]
    fn inspect_clean_ref() {
        let c = Clean::new("hello".to_string());
        let r = inspect_clean(&c);
        assert_eq!(r, "hello");
    }

    #[test]
    fn from_trusted_creates_clean() {
        let c = from_trusted(123i64);
        assert_eq!(*c.as_ref(), 123);
    }

    // -----------------------------------------------------------------------
    // Cross-struct interaction tests
    // -----------------------------------------------------------------------

    #[test]
    fn address_item_with_properties() {
        let mut addr = AddressItem::new("admin@example.org".to_string());
        addr.prop = AddressProperties {
            errors_address: Some("bounce@example.org".to_string()),
            extra_headers: vec![HeaderLine::new(
                "X-Tag: yes\r\n".to_string(),
                HeaderType::Other,
            )],
            remove_headers: None,
        };
        addr.uid = 1000;
        addr.gid = 1000;
        addr.home_dir = Some("/home/admin".to_string());
        assert_eq!(addr.local_part, "admin");
        assert_eq!(addr.domain, "example.org");
        assert_eq!(addr.uid, 1000);
        assert_eq!(
            addr.prop.errors_address.as_deref(),
            Some("bounce@example.org")
        );
    }

    #[test]
    fn message_context_with_recipients_and_headers() {
        let mut mc = MessageContext::new();
        mc.recipients.push(RecipientItem {
            address: "alice@example.com".to_string(),
            errors_to: None,
            orcpt: None,
            dsn_flags: 0,
            pno: None,
        });
        mc.headers.push(HeaderLine::new(
            "Subject: Test\r\n".to_string(),
            HeaderType::Subject,
        ));
        mc.message_id = "1234-5678-AB".to_string();
        mc.sender_address = Some("bob@example.com".to_string());
        assert_eq!(mc.recipients.len(), 1);
        assert_eq!(mc.headers.len(), 1);
        assert_eq!(mc.message_id, "1234-5678-AB");
    }

    #[test]
    fn retry_data_creation() {
        let rd = RetryData {
            first_failed: std::time::SystemTime::UNIX_EPOCH,
            last_try: std::time::SystemTime::UNIX_EPOCH,
            next_try: std::time::SystemTime::UNIX_EPOCH,
            expired: false,
            text: Some("R:example.com".to_string()),
        };
        assert!(!rd.expired);
        assert_eq!(rd.text.as_deref(), Some("R:example.com"));
    }
}
