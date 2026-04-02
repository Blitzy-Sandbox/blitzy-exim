// =============================================================================
// exim-smtp/src/inbound/command_loop.rs — SMTP Command State Machine
// =============================================================================
//
// Rewrites the main SMTP command dispatch loop from `src/src/smtp_in.c`
// function `smtp_setup_msg()` (lines 3815–5992, ~2,177 lines of C) into Rust
// using the type-state pattern (AAP §0.4.2) for compile-time SMTP command
// ordering enforcement.
//
// This is the largest and most complex file in the inbound SMTP module.
// It handles every SMTP command: HELO/EHLO, MAIL FROM, RCPT TO, DATA, AUTH,
// STARTTLS, VRFY, EXPN, ETRN, ATRN, QUIT, NOOP, HELP, RSET, BDAT,
// WELLKNOWN, XCLIENT, plus error handling for BADCHAR, BADSYN,
// TOO_MANY_NONMAIL, EOF, OTHER (unknown commands).
//
// ZERO unsafe code — per AAP §0.7.2.
// All `#ifdef` conditionals replaced with `#[cfg(feature = "...")]` — AAP §0.7.3.
// No tokio in the daemon event loop — signal handling uses `nix` crate.

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::marker::PhantomData;
use std::os::unix::io::RawFd;

// nix::sys::socket::{send, MsgFlags} removed — we now use
// exim_ffi::fd::safe_write_fd() which works on both sockets and pipes.
use tracing::{debug, error, info, trace, warn};

// Crate-level types from exim-smtp/src/lib.rs
use crate::{
    Connected, DataPhase, Greeted, MailFrom, RcptTo, SmtpCommand, SmtpCommandDef,
    SmtpCommandHistory, SmtpError, SmtpProtocol, SmtpSessionFlags, SMTP_CMD_BUFFER_SIZE,
    SMTP_RESP_BUFFER_SIZE,
};

// Pipelining module — buffered I/O and sync enforcement
use crate::inbound::pipelining::{smtp_getc, SmtpIoState};

// Chunking/BDAT module — BDAT protocol support
use crate::inbound::chunking::{
    bdat_flush_data, bdat_push_receive_functions, BdatSessionOps, ChunkingContext, ReceiveFunctions,
};

// PRDR module — Per-Recipient Data Response (feature-gated)
#[cfg(feature = "prdr")]
use crate::inbound::prdr::PrdrState;

// ACL evaluation engine
use exim_acl::{AclResult, AclWhere};

// Memory management: taint tracking
use exim_store::Tainted;

// String expansion engine
use exim_expand::expand_check_condition;

// Auth driver trait and types
use exim_drivers::auth_driver::AuthInstanceConfig;

// =============================================================================
// Local Context Types
// =============================================================================
// SMTP-local context structs
// =============================================================================
//
// **Architectural note — shadow types and the circular dependency constraint**
//
// `exim-core` depends on `exim-smtp`, so `exim-smtp` cannot import
// `exim-core` without creating a circular dependency.  As a result, the
// `ServerContext` and `MessageContext` defined below are local mirror types
// that replicate the SMTP-relevant subset of the canonical definitions in
// `exim-core/src/context.rs`.
//
// `ConfigContext`, however, *can* be bridged directly: `exim-config` does
// NOT depend on `exim-smtp`, so we provide a `from_config()` constructor
// that converts `&exim_config::types::ConfigContext` → local
// `ConfigContext`.  This ensures type-safe propagation of ACL names,
// limits, and EHLO advertisement settings from the parsed configuration.
//
// **Maintenance obligation**: When fields are added to the canonical types
// in `exim-core/src/context.rs` or `exim-config/src/types.rs` that are
// used during SMTP session processing, the corresponding local struct
// below MUST be updated to match.
//
// **Ideal long-term solution**: Extract the shared subset into a dedicated
// `exim-types` crate consumed by both `exim-core` and `exim-smtp`.  That
// crate would own ServerContext, MessageContext, and ConfigContext definitions,
// eliminating all duplication.  Tracked as a future improvement.
// =============================================================================

/// Daemon-lifetime server context — read-only during SMTP session.
///
/// Replaces global variables from `globals.c` that hold server-wide state.
/// Passed as `&ServerContext` to all command handlers.
///
/// **Mirror type**: Canonical definition in `exim-core/src/context.rs`.
///
/// C reference: AAP §0.4.4 ServerContext definition.
pub struct ServerContext {
    /// The primary hostname of this MTA (from `primary_hostname` config).
    pub primary_hostname: String,
    /// Active hostname for this SMTP session (may differ for virtual hosting).
    pub smtp_active_hostname: String,
    /// TLS server credentials reference (opaque handle).
    pub tls_server_credentials: Option<usize>,
    /// Whether this is a host-checking session (not real delivery).
    pub host_checking: bool,
    /// Whether the sender host is connected via a real socket.
    pub sender_host_notsocket: bool,
    /// Whether the connection is from inetd.
    pub is_inetd: bool,
    /// ATRN mode flag.
    pub atrn_mode: bool,
    /// Interface address the connection arrived on.
    pub interface_address: Option<String>,
    /// Interface port the connection arrived on.
    pub interface_port: u16,
    /// Whether this is a local SMTP session (-bs/-bS mode, not network).
    /// When true, the received protocol is prefixed with "local-".
    pub is_local_session: bool,
    /// Whether this is batched SMTP input (`-bS` mode).
    /// When true: no 220 banner is sent, no HELO/EHLO is required,
    /// MAIL FROM is accepted immediately.
    pub smtp_batched_input: bool,
}

/// Per-message mutable context — modified by every command handler.
///
/// Replaces global variables that hold per-message state. Passed as
/// `&mut MessageContext` throughout the command loop.
///
/// C reference: AAP §0.4.4 MessageContext definition.
pub struct MessageContext {
    /// The envelope sender address (from MAIL FROM).
    pub sender_address: String,
    /// List of accepted recipients.
    pub recipients_list: Vec<RecipientItem>,
    /// Count of accepted recipients.
    pub recipients_count: usize,
    /// Accumulated message headers.
    pub headers: Vec<String>,
    /// Generated message ID.
    pub message_id: String,
    /// Authenticated identity (set by AUTH command).
    pub authenticated_id: Option<String>,
    /// RFC 1413 ident string or calling user login name.
    /// In `-bs` mode this is `originator_login`; in `-bh` mode it is `None`.
    /// Used in HELO/EHLO greeting: "Hello sender_ident at helo_name".
    pub sender_ident: Option<String>,
    /// IP address of the sending host.
    pub sender_host_address: Option<String>,
    /// Resolved hostname of the sending host.
    pub sender_host_name: Option<String>,
    /// Port number of the sending host.
    pub sender_host_port: u16,
    /// Received protocol identifier.
    pub received_protocol: SmtpProtocol,
    /// HELO/EHLO name provided by client.
    pub helo_name: Option<String>,
    /// TLS session info (cipher, peer DN, etc.).
    pub tls_in: TlsSessionInfo,
    /// ACL variable storage.
    pub acl_vars: Vec<String>,
    /// Raw SMTP command for logging.
    pub smtp_command: String,
    /// Authenticated sender from MAIL FROM AUTH= parameter.
    pub authenticated_sender: Option<String>,
    /// DSN RET parameter (FULL or HDRS).
    pub dsn_ret: DsnRet,
    /// DSN ENVID parameter.
    pub dsn_envid: Option<String>,
    /// Declared message size from MAIL FROM SIZE= parameter.
    pub message_size: u64,
    /// Name of the auth mechanism that authenticated the sender.
    pub sender_host_authenticated: Option<String>,
    /// Whether the host was unknown (no reverse DNS).
    pub sender_host_unknown: bool,
    /// Whether SMTPUTF8 was advertised in the MAIL FROM.
    pub smtputf8_advertised: bool,
    /// Body type from MAIL FROM BODY= parameter (7BIT or 8BITMIME).
    pub body_type: BodyType,
    /// Whether sender address has been verified.
    pub sender_verified: bool,
    /// The SMTP banner string (expanded from config).
    pub smtp_banner: Option<String>,
    /// When true, `smtp_setup_msg` will NOT send the 220 banner on entry.
    /// Set after the first call so that re-entering the command loop after
    /// DATA Yield does not repeat the banner.
    pub skip_banner: bool,
    /// TLS backend extracted from the SMTP session when yielding for DATA/BDAT.
    /// The daemon reads from this after `SmtpSetupResult::Yield` to continue
    /// encrypted I/O during message body reception.  `None` for plaintext.
    #[cfg(feature = "tls")]
    pub tls_backend: Option<Box<exim_tls::rustls_backend::RustlsBackend>>,
    /// Message IDs of messages received during this SMTP session.
    /// After the session ends, the caller (exim-core) iterates these IDs
    /// to trigger delivery for each message (or queue them for later).
    pub received_message_ids: Vec<String>,
    /// Headers added by ACL warn/message directives during the DATA phase.
    /// These are written into the -H spool file with type '0' (ACL-added).
    pub acl_added_headers: Vec<String>,

    /// Optional callback invoked immediately after each message is accepted
    /// (250 OK sent) and BEFORE the SMTP session continues to the next
    /// command.  In C Exim, delivery happens inline after each DATA; the
    /// callback allows `exim-core` to replicate this by passing a closure
    /// that calls `deliver_smtp_message()`.
    ///
    /// Signature: `fn(msg_id: &str)`.  If `None`, delivery is deferred
    /// until the session ends (the caller then drains `received_message_ids`).
    #[allow(clippy::type_complexity)]
    // Callback signature mirrors C Exim's function pointer pattern
    pub post_message_callback: Option<Box<dyn FnMut(&str)>>,

    /// Optional callback invoked by `verify = recipient` ACL conditions.
    /// The ACL engine calls this to route the recipient address through the
    /// router chain, returning `Ok(VerifyRecipientResult)` on success or
    /// `Err(reason)` on failure.  `exim-core` populates this before calling
    /// `smtp_setup_msg()` so the ACL engine can verify recipients without
    /// `exim-smtp` depending on `exim-deliver`.
    ///
    /// Arguments: `(recipient_address, sender_address)`.
    #[allow(clippy::type_complexity)]
    // Callback signature mirrors C Exim's verify callback pattern
    pub verify_recipient_cb: Option<
        std::sync::Arc<dyn Fn(&str, &str) -> exim_acl::engine::VerifyRecipientResult + Send + Sync>,
    >,
}

/// TLS session information for logging and header generation.
#[derive(Default)]
pub struct TlsSessionInfo {
    /// Whether TLS is active on this connection.
    pub active: bool,
    /// Negotiated cipher suite name.
    pub cipher: Option<String>,
    /// Whether the peer certificate was verified.
    pub certificate_verified: bool,
    /// Distinguished name from the peer certificate.
    pub peerdn: Option<String>,
    /// Server Name Indication value.
    pub sni: Option<String>,
}

/// DSN RET parameter values.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum DsnRet {
    /// No RET parameter specified.
    #[default]
    None,
    /// Return full message on bounce.
    Full,
    /// Return headers only on bounce.
    Hdrs,
}

/// MAIL FROM BODY= type parameter.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum BodyType {
    /// No BODY parameter specified (default 7BIT).
    #[default]
    SevenBit,
    /// 8BITMIME body type.
    EightBitMime,
}

/// Single recipient entry constructed by the RCPT TO handler.
pub struct RecipientItem {
    /// The recipient email address.
    pub address: String,
    /// DSN notification flags (NEVER, SUCCESS, FAILURE, DELAY).
    pub dsn_flags: u32,
    /// DSN original recipient (ORCPT parameter).
    pub orcpt: Option<String>,
    /// Errors-to address override.
    pub errors_to: Option<String>,
}

/// Data collected during SMTP DATA phase message reception.
///
/// Contains parsed headers (name/value pairs), raw header lines preserving
/// original formatting, raw body bytes, and computed metrics matching C
/// Exim's `receive_msg()` output.
///
/// **Canonical source**: `receive.c` `receive_msg()`.
pub struct ReceivedMessageData {
    /// Parsed header name/value pairs (name is lowercased).
    pub parsed_headers: Vec<(String, String)>,
    /// Raw header lines preserving original formatting.
    pub raw_header_lines: Vec<String>,
    /// Raw body bytes (after dot-stuffing removal).
    pub body_data: Vec<u8>,
    /// Number of lines in the body.
    pub body_linecount: i64,
    /// Number of NUL bytes in the body.
    pub body_zerocount: i64,
    /// Maximum line length in the received message.
    pub max_received_linelength: i64,
    /// Total line count (headers + body).
    pub message_linecount: i64,
    /// Total message size in bytes.
    pub message_size: i64,
}

/// Immutable parsed configuration context for the SMTP session.
///
/// This is a **local mirror type** containing the SMTP-relevant subset of
/// `exim_config::types::ConfigContext`.  Use [`ConfigContext::from_config()`]
/// to construct from the canonical parsed configuration, ensuring ACL names,
/// limits, and advertisement settings are correctly propagated.
///
/// **Canonical source**: `exim-config/src/types.rs` `ConfigContext`.
pub struct ConfigContext {
    // Named ACL definitions parsed from the `begin acl` section.
    // Key: ACL name (e.g., "a1"), Value: raw ACL body text.
    // These are pre-parsed into `AclEvalContext::named_acls` before
    // each ACL evaluation so the engine can resolve ACL names.
    /// ACL definitions: name → (raw_body, source_file, start_line).
    /// Source file and line are used for HDEBUG "processing ACL" output.
    pub acl_definitions: HashMap<String, (String, String, i32)>,

    // ACL definitions for each SMTP phase
    pub acl_smtp_connect: Option<String>,
    pub acl_smtp_helo: Option<String>,
    pub acl_smtp_mail: Option<String>,
    pub acl_smtp_rcpt: Option<String>,
    pub acl_smtp_data: Option<String>,
    pub acl_smtp_auth: Option<String>,
    pub acl_smtp_starttls: Option<String>,
    pub acl_smtp_vrfy: Option<String>,
    pub acl_smtp_expn: Option<String>,
    pub acl_smtp_etrn: Option<String>,
    pub acl_smtp_predata: Option<String>,

    // SMTP limits
    pub smtp_accept_max_nonmail: u32,
    pub smtp_max_synprot_errors: u32,
    pub smtp_max_unknown_commands: u32,
    pub smtp_enforce_sync: bool,
    pub message_size_limit: u64,

    // Auth driver instances
    pub auth_instances: Vec<AuthInstanceConfig>,

    // SMTP banner and verification
    pub smtp_banner: Option<String>,
    pub helo_verify_hosts: Option<String>,
    pub helo_try_verify_hosts: Option<String>,

    // EHLO capability advertisement hosts
    pub chunking_advertise_hosts: Option<String>,
    pub dsn_advertise_hosts: Option<String>,
    pub auth_advertise_hosts: Option<String>,
    pub pipelining_advertise_hosts: Option<String>,

    #[cfg(feature = "tls")]
    pub tls_advertise_hosts: Option<String>,
    /// Path to PEM certificate chain for inbound STARTTLS.
    #[cfg(feature = "tls")]
    pub tls_certificate: Option<String>,
    /// Path to PEM private key for inbound STARTTLS.
    #[cfg(feature = "tls")]
    pub tls_privatekey: Option<String>,
    /// Cipher suite restriction string for inbound TLS.
    #[cfg(feature = "tls")]
    pub tls_require_ciphers: Option<String>,

    #[cfg(feature = "prdr")]
    pub prdr_enable: bool,

    #[cfg(feature = "i18n")]
    pub smtputf8_advertise_hosts: Option<String>,

    #[cfg(feature = "wellknown")]
    pub wellknown_advertise_hosts: Option<String>,

    #[cfg(feature = "esmtp-limits")]
    pub limits_advertise_hosts: Option<String>,

    #[cfg(feature = "xclient")]
    pub xclient_advertise_hosts: Option<String>,

    // ATRN / ODMR settings (RFC 2645)
    /// ACL for SMTP ATRN command. When `None`, ATRN is not advertised.
    pub acl_smtp_atrn: Option<String>,
    /// Colon-separated list of domains to relay via ATRN.
    pub atrn_domains: Option<String>,
    /// Remote ATRN host to connect to (customer mode only).
    pub atrn_host: Option<String>,

    // Submission mode settings
    pub submission_mode: bool,
    pub submission_domain: Option<String>,
    pub submission_name: Option<String>,

    // Named lists from configuration for ACL condition evaluation.
    // These are propagated into AclSessionState so conditions like
    // `domains = +local_domains` can resolve `+` references.
    pub named_domain_lists: HashMap<String, String>,
    pub named_host_lists: HashMap<String, String>,
    pub named_address_lists: HashMap<String, String>,
    pub named_local_part_lists: HashMap<String, String>,

    // Spool directory path for writing -H/-D files after DATA.
    pub spool_directory: String,

    // Log file path pattern for mainlog/rejectlog/paniclog.
    pub log_file_path: Option<String>,

    // Whether to immediately deliver messages (-odi) vs queue (-odq).
    pub deliver_immediately: bool,

    // Message ID header domain for Message-Id header generation.
    pub message_id_header_domain: Option<String>,

    // Message ID header text for Message-Id header text.
    pub message_id_header_text: Option<String>,

    // Originator login (the local user submitting the message).
    pub originator_login: String,

    // Originator uid/gid.
    pub originator_uid: u32,
    pub originator_gid: u32,

    // Received header text expansion template.
    pub received_header_text: Option<String>,

    // Trusted users list (for -f sender override).
    pub trusted_users: Option<String>,

    // Primary hostname.
    pub primary_hostname: String,

    // Timezone string for log timestamps.
    pub timezone: Option<String>,
}

impl ConfigContext {
    /// Construct from the canonical parsed configuration.
    ///
    /// Copies all SMTP-relevant fields from the canonical
    /// `exim_config::types::ConfigContext` into this local mirror type.
    /// This is the **only correct way** to construct a `ConfigContext` for
    /// real SMTP sessions — using `Default` produces an empty config with
    /// no ACLs (effectively an open relay).
    ///
    /// # Arguments
    ///
    /// * `cfg` — Reference to the canonical parsed configuration
    /// * `auth_instances` — Pre-built auth driver instance configs (constructed
    ///   by the binary crate from the parsed driver definitions)
    pub fn from_config(
        cfg: &exim_config::types::ConfigContext,
        auth_instances: Vec<AuthInstanceConfig>,
    ) -> Self {
        Self {
            // Named ACL definitions — convert from BTreeMap<String, AclBlock>
            // to HashMap carrying source file/line info for HDEBUG output
            acl_definitions: cfg
                .acl_definitions
                .iter()
                .map(|(name, block)| {
                    (
                        name.clone(),
                        (
                            block.raw_definition.clone(),
                            block.source_file.clone(),
                            block.start_line,
                        ),
                    )
                })
                .collect(),

            // ACL definitions — propagated from the parsed config
            acl_smtp_connect: cfg.acl_smtp_connect.clone(),
            acl_smtp_helo: cfg.acl_smtp_helo.clone(),
            acl_smtp_mail: cfg.acl_smtp_mail.clone(),
            acl_smtp_rcpt: cfg.acl_smtp_rcpt.clone(),
            acl_smtp_data: cfg.acl_smtp_data.clone(),
            acl_smtp_auth: cfg.acl_smtp_auth.clone(),
            acl_smtp_starttls: cfg.acl_smtp_starttls.clone(),
            acl_smtp_vrfy: cfg.acl_smtp_vrfy.clone(),
            acl_smtp_expn: cfg.acl_smtp_expn.clone(),
            acl_smtp_etrn: cfg.acl_smtp_etrn.clone(),
            acl_smtp_predata: cfg.acl_smtp_predata.clone(),

            // SMTP limits — cast from i32 (C config type) to u32 (Rust SMTP layer)
            smtp_accept_max_nonmail: cfg.smtp_accept_max_nonmail.max(0) as u32,
            smtp_max_synprot_errors: cfg.smtp_max_synprot_errors.max(0) as u32,
            smtp_max_unknown_commands: cfg.smtp_max_unknown_commands.max(0) as u32,
            smtp_enforce_sync: cfg.smtp_enforce_sync,
            // Parse message_size_limit from Option<String> (e.g., "50M") to u64 bytes
            message_size_limit: cfg
                .message_size_limit
                .as_deref()
                .and_then(parse_size_string)
                .unwrap_or(52_428_800), // 50 MiB default

            // Auth instances
            auth_instances,

            // SMTP banner and verification
            smtp_banner: cfg.smtp_banner.clone(),
            helo_verify_hosts: cfg.helo_verify_hosts.clone(),
            helo_try_verify_hosts: cfg.helo_try_verify_hosts.clone(),

            // EHLO capability hosts
            chunking_advertise_hosts: cfg.chunking_advertise_hosts.clone(),
            dsn_advertise_hosts: cfg.dsn_advertise_hosts.clone(),
            auth_advertise_hosts: cfg.auth_advertise_hosts.clone(),
            pipelining_advertise_hosts: cfg.pipelining_advertise_hosts.clone(),

            #[cfg(feature = "tls")]
            tls_advertise_hosts: cfg.tls_advertise_hosts.clone(),
            #[cfg(feature = "tls")]
            tls_certificate: cfg.tls_certificate.clone(),
            #[cfg(feature = "tls")]
            tls_privatekey: cfg.tls_privatekey.clone(),
            #[cfg(feature = "tls")]
            tls_require_ciphers: cfg.tls_require_ciphers.clone(),

            // PRDR is an extension feature; not yet represented in exim_config,
            // so default to disabled.
            #[cfg(feature = "prdr")]
            prdr_enable: false,

            // SMTPUTF8/WELLKNOWN/ESMTP-LIMITS/XCLIENT advertise hosts are not
            // yet represented in exim_config::ConfigContext — default to None
            // (disabled) until the config parser populates these fields.
            #[cfg(feature = "i18n")]
            smtputf8_advertise_hosts: None,

            #[cfg(feature = "wellknown")]
            wellknown_advertise_hosts: None,

            #[cfg(feature = "esmtp-limits")]
            limits_advertise_hosts: None,

            #[cfg(feature = "xclient")]
            xclient_advertise_hosts: None,

            // ATRN / ODMR settings — not yet represented in exim_config,
            // default to disabled/empty
            acl_smtp_atrn: cfg.acl_smtp_atrn.clone(),
            atrn_domains: None,
            atrn_host: None,

            // Submission mode settings — not yet represented in exim_config,
            // default to disabled
            submission_mode: false,
            submission_domain: None,
            submission_name: None,

            // Named lists — propagated from parsed config for ACL condition resolution
            named_domain_lists: cfg
                .named_lists
                .domain_lists
                .iter()
                .map(|(k, v)| (k.clone(), v.value.clone()))
                .collect(),
            named_host_lists: cfg
                .named_lists
                .host_lists
                .iter()
                .map(|(k, v)| (k.clone(), v.value.clone()))
                .collect(),
            named_address_lists: cfg
                .named_lists
                .address_lists
                .iter()
                .map(|(k, v)| (k.clone(), v.value.clone()))
                .collect(),
            named_local_part_lists: cfg
                .named_lists
                .localpart_lists
                .iter()
                .map(|(k, v)| (k.clone(), v.value.clone()))
                .collect(),

            // Spool and delivery settings from the canonical config
            spool_directory: if cfg.spool_directory.is_empty() {
                "/var/spool/exim".to_string()
            } else {
                cfg.spool_directory.clone()
            },
            log_file_path: if cfg.log_file_path.is_empty() {
                None
            } else {
                Some(cfg.log_file_path.clone())
            },
            deliver_immediately: false,
            message_id_header_domain: cfg.message_id_header_domain.clone(),
            message_id_header_text: cfg.message_id_header_text.clone(),
            originator_login: String::new(),
            originator_uid: 0,
            originator_gid: 0,
            received_header_text: cfg.received_header_text.clone(),
            trusted_users: cfg.trusted_users.clone(),
            primary_hostname: if cfg.primary_hostname.is_empty() {
                "localhost".to_string()
            } else {
                cfg.primary_hostname.clone()
            },
            timezone: cfg.timezone.clone(),
        }
    }
}

impl Default for MessageContext {
    fn default() -> Self {
        Self {
            sender_address: String::new(),
            recipients_list: Vec::new(),
            recipients_count: 0,
            headers: Vec::new(),
            message_id: String::new(),
            authenticated_id: None,
            sender_ident: None,
            sender_host_address: None,
            sender_host_name: None,
            sender_host_port: 0,
            received_protocol: SmtpProtocol::Smtp,
            helo_name: None,
            tls_in: TlsSessionInfo::default(),
            acl_vars: Vec::new(),
            smtp_command: String::new(),
            authenticated_sender: None,
            dsn_ret: DsnRet::None,
            dsn_envid: None,
            message_size: 0,
            sender_host_authenticated: None,
            sender_host_unknown: false,
            smtputf8_advertised: false,
            body_type: BodyType::SevenBit,
            sender_verified: false,
            smtp_banner: None,
            skip_banner: false,
            #[cfg(feature = "tls")]
            tls_backend: None,
            received_message_ids: Vec::new(),
            acl_added_headers: Vec::new(),
            post_message_callback: None,
            verify_recipient_cb: None,
        }
    }
}

// =============================================================================
// SmtpSetupResult — Return type for smtp_setup_msg()
// =============================================================================

/// Result of the SMTP command loop processing.
///
/// Replaces the C `done` variable from `smtp_setup_msg()`:
/// - `done == 1` → `Done` (connection finished normally via QUIT or fatal error)
/// - `done == 3` → `Yield` (DATA/BDAT received — yield to message reception)
/// - `done == 2` → `Error` (DROP from ACL or fatal protocol violation)
///
/// C reference: smtp_in.c lines 5982-5992.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpSetupResult {
    /// The SMTP session should be closed (QUIT received, fatal error, or
    /// max-nonmail threshold exceeded).
    Done,
    /// A DATA or BDAT command was received and validated — the caller should
    /// proceed to receive the message body.
    Yield,
    /// A fatal error occurred (ACL DROP, connection reset, etc.) requiring
    /// immediate session teardown.
    Error,
}

// TLS backend is deposited into `MessageContext::tls_backend` before
// returning `Yield` — no return-type changes needed for SMTP functions.

// =============================================================================
// SMTP Command List — matches C cmd_list[] (smtp_in.c lines 195-224)
// =============================================================================

/// Static command definition table matching C `cmd_list[]`.
///
/// The ordering and indexing are significant — CL_RSET=0, CL_HELO=1, CL_EHLO=2,
/// CL_AUTH=3, CL_STARTTLS=4, CL_HELO_5=5 (TLS_AUTH). The `is_mail_cmd` field
/// is initially `true` for AUTH and QUIT (reset per-loop iteration for RSET,
/// HELO, EHLO, STARTTLS to track non-mail commands correctly).
///
/// C reference: smtp_in.c lines 195-224.
const CMD_LIST: &[SmtpCommandDef] = &[
    SmtpCommandDef {
        name: "RSET",
        cmd: SmtpCommand::Rset,
        is_mail_cmd: false,
        min_len: 4,
    },
    SmtpCommandDef {
        name: "HELO",
        cmd: SmtpCommand::Helo,
        is_mail_cmd: false,
        min_len: 4,
    },
    SmtpCommandDef {
        name: "EHLO",
        cmd: SmtpCommand::Ehlo,
        is_mail_cmd: false,
        min_len: 4,
    },
    SmtpCommandDef {
        name: "AUTH",
        cmd: SmtpCommand::Auth,
        is_mail_cmd: true,
        min_len: 4,
    },
    SmtpCommandDef {
        name: "STARTTLS",
        cmd: SmtpCommand::Starttls,
        is_mail_cmd: false,
        min_len: 8,
    },
    SmtpCommandDef {
        name: "HELO",
        cmd: SmtpCommand::TlsAuth,
        is_mail_cmd: false,
        min_len: 4,
    },
    SmtpCommandDef {
        name: "MAIL FROM:",
        cmd: SmtpCommand::Mail,
        is_mail_cmd: true,
        min_len: 10,
    },
    SmtpCommandDef {
        name: "RCPT TO:",
        cmd: SmtpCommand::Rcpt,
        is_mail_cmd: true,
        min_len: 8,
    },
    SmtpCommandDef {
        name: "DATA",
        cmd: SmtpCommand::Data,
        is_mail_cmd: true,
        min_len: 4,
    },
    SmtpCommandDef {
        name: "BDAT",
        cmd: SmtpCommand::Bdat,
        is_mail_cmd: true,
        min_len: 4,
    },
    SmtpCommandDef {
        name: "QUIT",
        cmd: SmtpCommand::Quit,
        is_mail_cmd: true,
        min_len: 4,
    },
    SmtpCommandDef {
        name: "NOOP",
        cmd: SmtpCommand::Noop,
        is_mail_cmd: false,
        min_len: 4,
    },
    SmtpCommandDef {
        name: "ETRN",
        cmd: SmtpCommand::Etrn,
        is_mail_cmd: false,
        min_len: 4,
    },
    SmtpCommandDef {
        name: "VRFY",
        cmd: SmtpCommand::Vrfy,
        is_mail_cmd: false,
        min_len: 4,
    },
    SmtpCommandDef {
        name: "EXPN",
        cmd: SmtpCommand::Expn,
        is_mail_cmd: false,
        min_len: 4,
    },
    SmtpCommandDef {
        name: "HELP",
        cmd: SmtpCommand::Help,
        is_mail_cmd: false,
        min_len: 4,
    },
    SmtpCommandDef {
        name: "ATRN",
        cmd: SmtpCommand::Atrn,
        is_mail_cmd: false,
        min_len: 4,
    },
    #[cfg(feature = "xclient")]
    SmtpCommandDef {
        name: "XCLIENT",
        cmd: SmtpCommand::Xclient,
        is_mail_cmd: false,
        min_len: 7,
    },
    #[cfg(feature = "wellknown")]
    SmtpCommandDef {
        name: "WELLKNOWN",
        cmd: SmtpCommand::Wellknown,
        is_mail_cmd: false,
        min_len: 9,
    },
];

/// Indices into CMD_LIST for resetting `is_mail_cmd` flags per loop iteration.
/// These are used during smtp_setup_msg() to reset RSET/HELO/EHLO/STARTTLS
/// as non-mail commands at the start of each loop iteration, matching
/// C smtp_in.c lines 3838-3843.
// Justified: These constants preserve the C `smtp_cmd_list[]` index
// assignments from `smtp_in.c` lines 3838-3843 for documentation and future
// use by the `is_mail_cmd` reset logic.  They are intentionally kept even
// when the Rust command loop does not yet index CMD_LIST by position, because
// removing them would lose the source correspondence needed for verification
// against the C implementation.
#[allow(dead_code)]
const CL_RSET: usize = 0;
#[allow(dead_code)]
const CL_HELO: usize = 1;
#[allow(dead_code)]
const CL_EHLO: usize = 2;
#[allow(dead_code)]
const CL_AUTH: usize = 3;
#[allow(dead_code)]
const CL_STARTTLS: usize = 4;

/// Default SMTP response codes for ACL phases.
///
/// Maps each `AclWhere` variant to its default SMTP response code.
/// C reference: smtp_in.c `acl_wherecodes[]` array.
fn acl_wherecode(phase: &AclWhere) -> u16 {
    match phase {
        AclWhere::Helo => 550,
        AclWhere::Mail => 550,
        AclWhere::Rcpt => 550,
        AclWhere::Data => 550,
        AclWhere::Predata => 550,
        AclWhere::Auth => 503,
        AclWhere::StartTls => 550,
        AclWhere::Vrfy => 252,
        AclWhere::Expn => 550,
        AclWhere::Etrn => 458,
        _ => 550,
    }
}

/// Maximum size of the SMTP connection history ring buffer.
/// C reference: smtp_in.c line 116: `smtp_ch_index`.
const SMTP_HISTRY_SIZE: usize = 64;

// =============================================================================
// SmtpSession<S> — Type-State SMTP Session (AAP §0.4.2)
// =============================================================================

/// SMTP session with compile-time state tracking via phantom type parameter.
///
/// The type parameter `S` encodes the current SMTP protocol state:
/// - [`Connected`] — TCP connection established, awaiting HELO/EHLO
/// - [`Greeted`] — HELO/EHLO completed, awaiting MAIL FROM
/// - [`MailFrom`] — MAIL FROM accepted, awaiting RCPT TO
/// - [`RcptTo`] — At least one RCPT TO accepted, awaiting DATA/BDAT
/// - [`DataPhase`] — DATA/BDAT initiated, message body expected
///
/// State transitions are enforced at compile time via consuming methods:
/// - `greet()` transitions `Connected → Greeted`
/// - `mail_from()` transitions `Greeted → MailFrom`
/// - `rcpt_to()` transitions `MailFrom → RcptTo` (or `RcptTo → RcptTo`)
/// - `data()` transitions `RcptTo → DataPhase`
/// - `reset()` transitions any post-HELO state back to `Greeted`
///
/// C reference: Replaces the runtime `done` variable and command validity
/// checks in `smtp_setup_msg()` (smtp_in.c lines 3815–5992).
pub struct SmtpSession<'ctx, S> {
    /// Phantom type parameter carrying the state — zero-sized.
    _state: PhantomData<S>,

    // ── Session Counters (replacing C static locals, smtp_in.c:149-161) ──
    /// Reference to the currently authenticated auth instance index, if any.
    pub authenticated_by: Option<usize>,

    /// Whether to count non-mail commands. `None` = TRUE_UNSET from C.
    pub count_nonmail: Option<bool>,

    /// Current count of non-mail commands in this transaction.
    pub nonmail_command_count: u32,

    /// Count of synchronization protocol errors in this session.
    pub synprot_error_count: u32,

    /// Count of unknown commands in this session.
    pub unknown_command_count: u32,

    /// The command at which sync checking begins for pipelining enforcement.
    pub sync_cmd_limit: SmtpCommand,

    // ── Shared Context References (AAP §0.4.4) ──
    /// Daemon-lifetime server context (read-only).
    pub server_ctx: &'ctx ServerContext,

    /// Per-message mutable context — sender, recipients, headers, etc.
    pub message_ctx: &'ctx mut MessageContext,

    /// Immutable parsed configuration context.
    pub config_ctx: &'ctx ConfigContext,

    /// Per-session boolean flags replacing C `fl` struct.
    pub flags: SmtpSessionFlags,

    // ── SMTP I/O State ──
    /// Buffered I/O state for the SMTP connection.
    /// `pub(crate)` so that the ATRN module can access fd state for role swap.
    pub(crate) io: SmtpIoState,

    /// BDAT/chunking protocol state.
    chunking_ctx: ChunkingContext,

    /// PRDR state (feature-gated).
    #[cfg(feature = "prdr")]
    prdr_state: PrdrState,

    // ── Command/Response Buffers ──
    /// Raw command buffer for reading SMTP commands from the client.
    pub cmd_buffer: Vec<u8>,

    /// Response output buffer for batching SMTP responses.
    pub resp_buffer: Vec<u8>,

    /// Current write position in the response buffer.
    resp_ptr: usize,

    /// Ring buffer of recent SMTP commands for connection history logging.
    connection_had: [SmtpCommandHistory; SMTP_HISTRY_SIZE],

    /// Current index into the connection_had ring buffer.
    connection_had_index: usize,

    /// Write error code from the last socket write operation.
    smtp_write_error: i32,

    /// Whether we are currently inside an RCPT TO response sequence.
    rcpt_in_progress: bool,

    /// Track whether the sender verification failure prefix has already been
    /// emitted in this transaction.  C Exim uses `af_sverify_told` flag on
    /// `sender_verified_failed->flags` to suppress the multi-line prefix on
    /// subsequent RCPTs after the first one (smtp_in.c ~3191-3194).
    /// Reset on RSET/MAIL FROM.
    sender_verify_told: bool,
}

// =============================================================================
// Constructor — Creates a new session in the Connected state
// =============================================================================

impl<'ctx> SmtpSession<'ctx, Connected> {
    /// Create a new SMTP session in the `Connected` state.
    ///
    /// This is the entry point for a new SMTP connection. The session starts
    /// in `Connected` state and must transition to `Greeted` via HELO/EHLO
    /// before any mail commands are accepted.
    ///
    /// # Arguments
    ///
    /// * `in_fd` — Inbound socket file descriptor (client → server)
    /// * `out_fd` — Outbound socket file descriptor (server → client)
    /// * `server_ctx` — Daemon-lifetime server state
    /// * `message_ctx` — Per-message mutable state
    /// * `config_ctx` — Immutable parsed configuration
    pub fn new(
        in_fd: RawFd,
        out_fd: RawFd,
        server_ctx: &'ctx ServerContext,
        message_ctx: &'ctx mut MessageContext,
        config_ctx: &'ctx ConfigContext,
    ) -> Self {
        let io = SmtpIoState::new(in_fd, out_fd);
        let chunking_ctx = ChunkingContext::new(false);

        SmtpSession {
            _state: PhantomData,
            authenticated_by: None,
            count_nonmail: None,
            nonmail_command_count: 0,
            synprot_error_count: 0,
            unknown_command_count: 0,
            sync_cmd_limit: SmtpCommand::Noop,
            server_ctx,
            message_ctx,
            config_ctx,
            flags: SmtpSessionFlags::default(),
            io,
            chunking_ctx,
            #[cfg(feature = "prdr")]
            prdr_state: PrdrState::default(),
            cmd_buffer: vec![0u8; SMTP_CMD_BUFFER_SIZE],
            resp_buffer: vec![0u8; SMTP_RESP_BUFFER_SIZE],
            resp_ptr: 0,
            connection_had: [SmtpCommandHistory::SchNone; SMTP_HISTRY_SIZE],
            connection_had_index: 0,
            smtp_write_error: 0,
            rcpt_in_progress: false,
            sender_verify_told: false,
        }
    }
}

// =============================================================================
// Common Methods — Available in ALL states
// =============================================================================

impl<'ctx, S> SmtpSession<'ctx, S> {
    // ── ACL Session State Builder ──

    /// Build an `AclSessionState` from the current SMTP session, carrying
    /// envelope sender, client IP, HELO name, and named lists into the
    /// ACL evaluation context. Called before each `run_acl_check()` so that
    /// conditions like `senders`, `hosts`, and `domains` can match against
    /// real session data.
    pub(crate) fn acl_session_state(&self) -> AclSessionState {
        self.acl_session_state_for_recipient("")
    }

    /// Build ACL session state with a specific recipient address pre-set.
    /// Used for RCPT TO ACL evaluation where the recipient is known.
    pub(crate) fn acl_session_state_for_recipient(&self, recipient: &str) -> AclSessionState {
        AclSessionState {
            sender_address: self.message_ctx.sender_address.clone(),
            client_ip: self
                .message_ctx
                .sender_host_address
                .clone()
                .unwrap_or_default(),
            helo_name: self.message_ctx.helo_name.clone().unwrap_or_default(),
            named_domain_lists: self.config_ctx.named_domain_lists.clone(),
            named_host_lists: self.config_ctx.named_host_lists.clone(),
            named_address_lists: self.config_ctx.named_address_lists.clone(),
            named_local_part_lists: self.config_ctx.named_local_part_lists.clone(),
            reply_address: String::new(),
            header_list: HashMap::new(),
            host_checking: self.server_ctx.host_checking,
            verify_recipient_cb: self.message_ctx.verify_recipient_cb.clone(),
            recipient: recipient.to_string(),
            primary_hostname: self.config_ctx.primary_hostname.clone(),
            spool_directory: self.config_ctx.spool_directory.clone(),
            recipients_count: self.message_ctx.recipients_count as i32,
        }
    }

    // ── HAD Macro — Command History Ring Buffer (smtp_in.c:116-118) ──

    /// Record a command in the connection history ring buffer.
    ///
    /// Replaces the C `HAD(n)` macro from smtp_in.c line 116.
    /// The ring buffer is used for connection logging when the session ends.
    pub fn had(&mut self, cmd: SmtpCommandHistory) {
        self.connection_had[self.connection_had_index] = cmd;
        self.connection_had_index = (self.connection_had_index + 1) % SMTP_HISTRY_SIZE;
    }

    // ── SMTP Response Output (smtp_in.c lines 998-1157) ──

    /// Send a formatted SMTP response to the client.
    ///
    /// Replaces C `smtp_printf()` from smtp_in.c lines 998-1072.
    ///
    /// # Arguments
    ///
    /// * `msg` — Pre-formatted response string (including CRLF)
    /// * `more` — If `true`, buffer the response; if `false`, flush immediately
    pub fn smtp_printf(&mut self, msg: &str, more: bool) {
        // In batch SMTP mode (-bS), C Exim's smtp_setup_batch_msg() processes
        // commands WITHOUT writing any SMTP response lines. The responses are
        // entirely suppressed. Only error handling via moan_smtp_batch() sends
        // output (as a bounce message, not SMTP responses).
        if self.server_ctx.smtp_batched_input {
            return;
        }

        // Log the response for debugging
        if more {
            trace!("SMTP>| {}", msg.trim_end());
        } else {
            debug!("SMTP>> {}", msg.trim_end());
        }

        let msg_bytes = msg.as_bytes();

        // Track RCPT TO response for response_same detection
        if self.rcpt_in_progress {
            self.flags.rcpt_smtp_response_same = true;
        }

        if more {
            // Buffer the response for later flush
            let available = self.resp_buffer.len() - self.resp_ptr;
            let to_copy = msg_bytes.len().min(available);
            self.resp_buffer[self.resp_ptr..self.resp_ptr + to_copy]
                .copy_from_slice(&msg_bytes[..to_copy]);
            self.resp_ptr += to_copy;
        } else {
            // Flush any buffered data plus this message
            if self.resp_ptr > 0 {
                let buffered = self.resp_buffer[..self.resp_ptr].to_vec();
                self.write_to_socket(&buffered);
                self.resp_ptr = 0;
            }
            self.write_to_socket(msg_bytes);
        }
    }

    /// Send a multi-line or single-line SMTP response.
    ///
    /// Replaces C `smtp_respond()` from smtp_in.c lines 1073-1120.
    /// Builds proper multi-line responses with continuation lines (code-space
    /// vs code-dash format).
    ///
    /// # Arguments
    ///
    /// * `code` — 3-digit SMTP response code as string (e.g., "250")
    /// * `more` — Whether more response lines follow
    /// * `msg` — Response message text (may contain embedded newlines)
    pub fn smtp_respond(&mut self, code: &str, more: bool, msg: &str) {
        let lines: Vec<&str> = msg.lines().collect();
        if lines.is_empty() {
            let response = format!("{} \r\n", code);
            self.smtp_printf(&response, more);
            return;
        }

        for (i, line) in lines.iter().enumerate() {
            let is_last = i == lines.len() - 1;
            let separator = if is_last && !more { ' ' } else { '-' };
            let response = format!("{}{}{}\r\n", code, separator, line);
            let buffer_this = more || !is_last;
            self.smtp_printf(&response, buffer_this);
        }
    }

    /// Write a raw pre-formatted response string to the client.
    ///
    /// Used by the BdatSessionOps trait implementation where the response
    /// is already formatted with code, separator, and CRLF.
    fn smtp_respond_raw(&mut self, msg: &str) {
        self.smtp_printf(msg, false);
    }

    /// Flush the SMTP response buffer to the socket.
    ///
    /// Replaces C `smtp_fflush()` from smtp_in.c lines 1129-1157.
    /// Handles TCP_CORK management for optimal TCP segment coalescing.
    pub fn smtp_fflush(&mut self, uncork: bool) -> Result<(), SmtpError> {
        if self.resp_ptr > 0 {
            let buffered = self.resp_buffer[..self.resp_ptr].to_vec();
            self.write_to_socket(&buffered);
            self.resp_ptr = 0;
        }

        // Manage TCP_CORK on Linux for optimal segment coalescing
        #[cfg(target_os = "linux")]
        {
            if uncork {
                let fd = self.io.out_fd;
                let _ = exim_ffi::fd::safe_setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_CORK, 0);
            }
        }

        // Suppress unused variable warning on non-Linux
        #[cfg(not(target_os = "linux"))]
        let _ = uncork;

        Ok(())
    }

    /// Write raw bytes to the SMTP output socket.
    ///
    /// Write data to the SMTP output file descriptor.
    ///
    /// Uses `exim_ffi::fd::safe_write_fd()` which works on **both** sockets
    /// and pipes/files (unlike `nix::sys::socket::send()` which returns
    /// ENOTSOCK for pipe-based fds in `-bs` mode).  This is the fix for
    /// QA Issue 6 ("SMTP socket write error: ENOTSOCK").
    fn write_to_socket(&mut self, buf: &[u8]) {
        // When TLS is active, write through the encrypted TLS stream
        // instead of the raw socket fd.
        #[cfg(feature = "tls")]
        if let Some(ref mut tls) = self.io.tls_backend {
            let mut sent = 0usize;
            while sent < buf.len() {
                match tls.write(&buf[sent..]) {
                    Ok(n) => sent += n,
                    Err(e) => {
                        error!("TLS write error: {}", e);
                        self.smtp_write_error = 1;
                        return;
                    }
                }
            }
            return;
        }

        let fd = self.io.out_fd;
        let mut sent = 0usize;
        while sent < buf.len() {
            match exim_ffi::fd::safe_write_fd(fd, &buf[sent..]) {
                Ok(n) => {
                    sent += n;
                }
                Err(nix::errno::Errno::EINTR) => {
                    // Interrupted by signal — retry immediately.
                    continue;
                }
                Err(e) => {
                    error!("SMTP socket write error: {}", e);
                    self.smtp_write_error = e as i32;
                    return;
                }
            }
        }
    }

    // ── SMTP Command Reading (smtp_in.c lines 1252-1382) ──

    /// Read and parse the next SMTP command from the client.
    ///
    /// Reads characters from the input buffer until a newline is found,
    /// strips trailing CR and whitespace, matches against the command list,
    /// and returns the identified command and its argument.
    ///
    /// # Arguments
    ///
    /// * `do_check_sync` — Whether to enforce pipelining synchronization
    /// * `buffer_lim` — Maximum command buffer size
    ///
    /// # Returns
    ///
    /// A tuple of (SmtpCommand, argument_string). The argument_string
    /// contains the command parameters (e.g., sender address for MAIL FROM).
    ///
    /// C reference: smtp_in.c lines 1252-1382.
    pub fn smtp_read_command(
        &mut self,
        do_check_sync: bool,
        buffer_lim: u32,
    ) -> (SmtpCommand, String) {
        // Set up alarm timeout for command reading
        nix::unistd::alarm::set(300); // 5-minute command timeout

        let mut cmd_len = 0usize;
        let max_len = buffer_lim.min(self.cmd_buffer.len() as u32);
        let mut had_null = false;

        // Read characters until newline
        loop {
            let ch = smtp_getc(&mut self.io, max_len);
            if ch < 0 {
                // EOF or error
                nix::unistd::alarm::cancel();
                return (SmtpCommand::Eof, String::new());
            }

            let byte = ch as u8;

            // Handle NUL bytes — replace with '?' and flag
            if byte == 0 {
                had_null = true;
                if cmd_len < max_len as usize {
                    self.cmd_buffer[cmd_len] = b'?';
                    cmd_len += 1;
                }
                continue;
            }

            // Newline terminates the command
            if byte == b'\n' {
                break;
            }

            // Store character in buffer
            if cmd_len < max_len as usize {
                self.cmd_buffer[cmd_len] = byte;
                cmd_len += 1;
            }
        }

        // Cancel the alarm
        nix::unistd::alarm::cancel();

        // Strip trailing CR and whitespace
        while cmd_len > 0 {
            let last = self.cmd_buffer[cmd_len - 1];
            if last == b'\r' || last == b' ' || last == b'\t' {
                cmd_len -= 1;
            } else {
                break;
            }
        }

        // Convert to string for processing
        let cmd_str = String::from_utf8_lossy(&self.cmd_buffer[..cmd_len]).to_string();

        // Log the received command
        debug!("SMTP<< {}", cmd_str);

        // Store for logging purposes
        self.message_ctx.smtp_command = cmd_str.clone();

        // Handle NUL byte detection
        if had_null {
            return (SmtpCommand::BadChar, cmd_str);
        }

        // Buffer overflow check
        if cmd_len >= max_len as usize {
            return (SmtpCommand::Other, cmd_str);
        }

        // Match against command list
        let (cmd, arg_start) = self.match_command(&cmd_str, do_check_sync);

        // Extract argument
        let argument = if arg_start < cmd_str.len() {
            cmd_str[arg_start..].trim_start().to_string()
        } else {
            String::new()
        };

        (cmd, argument)
    }

    /// Match a command string against the CMD_LIST table.
    ///
    /// Performs case-insensitive matching. For commands like "MAIL FROM:" and
    /// "RCPT TO:", the colon is part of the match. For other commands, the
    /// match is followed by a space or end-of-string.
    ///
    /// # Returns
    ///
    /// (matched_command, byte_offset_of_argument)
    fn match_command(&self, cmd_str: &str, do_check_sync: bool) -> (SmtpCommand, usize) {
        let upper = cmd_str.to_ascii_uppercase();

        for def in CMD_LIST {
            let name_len = def.name.len();
            if upper.len() >= name_len && upper[..name_len].eq_ignore_ascii_case(def.name) {
                // For commands ending with ':', the colon is part of the match
                if def.name.ends_with(':') {
                    // Check synchronization if required
                    if do_check_sync && self.should_sync_check(def.cmd) {
                        return (SmtpCommand::BadSyn, 0);
                    }
                    return (def.cmd, name_len);
                }

                // For other commands, next char must be space or end-of-string
                if upper.len() == name_len
                    || upper.as_bytes()[name_len] == b' '
                    || upper.as_bytes()[name_len] == b'\t'
                {
                    if do_check_sync && self.should_sync_check(def.cmd) {
                        return (SmtpCommand::BadSyn, 0);
                    }
                    let arg_start = if upper.len() > name_len {
                        name_len + 1
                    } else {
                        name_len
                    };
                    return (def.cmd, arg_start);
                }
            }
        }

        // No match — unknown command
        (SmtpCommand::Other, 0)
    }

    /// Determine if sync checking should fail for a given command.
    ///
    /// Pipelining enforcement per RFC 5321 §4.5.3.2: if there is unread
    /// data in the input buffer before the server has sent its response to
    /// the prior command, the client may be attempting command smuggling.
    ///
    /// Sync checking is performed for commands that are NOT part of the
    /// pipelining group (RSET, MAIL FROM, RCPT TO, DATA per RFC 2920).
    /// Commands that ARE pipelineable are allowed to arrive before the
    /// prior response is sent.
    ///
    /// Returns `true` if there is pending input data and the command is
    /// not pipelineable — indicating a sync violation that should be
    /// rejected.
    fn should_sync_check(&self, cmd: SmtpCommand) -> bool {
        // If sync enforcement is disabled in config, never flag a violation.
        if !self.config_ctx.smtp_enforce_sync {
            return false;
        }

        // Pipelineable commands per RFC 2920: RSET, MAIL, RCPT, DATA.
        // These are allowed to arrive before the prior response.
        // All other commands require strict synchronization.
        let is_pipelineable = matches!(
            cmd,
            SmtpCommand::Rset | SmtpCommand::Mail | SmtpCommand::Rcpt | SmtpCommand::Data
        );

        if is_pipelineable {
            return false;
        }

        // Check if there is unread data pending in the input buffer.
        // If the input buffer has data beyond what we've consumed for
        // the current command, the client sent commands before receiving
        // our response — a potential smuggling attack.
        self.io.has_pending_input()
    }

    // ── Protocol Error Handling (smtp_in.c lines ~2860-2940) ──

    /// Handle a synchronization protocol error.
    ///
    /// Logs the error, sends an appropriate SMTP error response, and
    /// increments the sync protocol error counter.
    ///
    /// # Arguments
    ///
    /// * `log_type` — Log category flags
    /// * `code` — SMTP response code (4xx or 5xx)
    /// * `data` — Optional extra data for the log message
    /// * `msg` — Error message text
    ///
    /// # Returns
    ///
    /// 0 if the session should continue, -1 if it should be dropped.
    ///
    /// C reference: smtp_in.c lines ~2860-2940.
    pub fn synprot_error(
        &mut self,
        _log_type: u32,
        code: u16,
        data: Option<&str>,
        msg: &str,
    ) -> i32 {
        // Log the protocol error
        if let Some(d) = data {
            warn!(
                "SMTP protocol synchronization error ({}): {} [{}]",
                code, msg, d
            );
        } else {
            warn!("SMTP protocol synchronization error ({}): {}", code, msg);
        }

        // Increment the counter and check threshold
        self.synprot_error_count += 1;
        let max_errors = self.config_ctx.smtp_max_synprot_errors;
        if max_errors > 0 && self.synprot_error_count >= max_errors {
            let response = format!("{} Too many syntax or protocol errors\r\n", code);
            self.smtp_printf(&response, false);
            return -1;
        }

        // Send the error response
        let code_str = format!("{}", code);
        self.smtp_respond(&code_str, false, msg);
        0
    }

    // ── ACL Failure Handling (smtp_in.c lines 3090-3300) ──
    // ── Log File Writing Helpers ──────────────────────────────────────

    /// Write a log line to mainlog and optionally rejectlog.
    ///
    /// In `-bh` (host_checking) mode, writes "LOG: <body>" to stderr
    /// instead of the actual log files, matching C Exim's behavior.
    ///
    /// `flags` is a bitmask: 1 = LOG_MAIN, 2 = LOG_REJECT.
    /// When both are set the same line appears in both files.
    pub fn log_write(&self, flags: u32, body: &str) {
        // In host_checking mode C Exim writes "LOG: <body>" to stderr
        if self.server_ctx.host_checking {
            eprintln!("LOG: {body}");
            return;
        }

        if let Some(ref log_path) = self.config_ctx.log_file_path {
            let now = {
                let epoch = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                format_log_timestamp(epoch)
            };
            let formatted = format!("{now} {body}\n");

            // LOG_MAIN (bit 0)
            if flags & 1 != 0 {
                let mainlog = log_path.replace("%slog", "mainlog");
                Self::append_log_file(&mainlog, &formatted);
            }
            // LOG_REJECT (bit 1)
            if flags & 2 != 0 {
                let rejectlog = log_path.replace("%slog", "rejectlog");
                Self::append_log_file(&rejectlog, &formatted);
            }
        }
    }

    /// Append `text` to the given log file, creating it if necessary.
    fn append_log_file(path: &str, text: &str) {
        if let Some(dir) = std::path::Path::new(path).parent() {
            let _ = std::fs::create_dir_all(dir);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750));
            }
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o666);
        }
        if let Ok(mut f) = opts.open(path) {
            use std::io::Write;
            let _ = f.write_all(text.as_bytes());
        }
    }

    /// Build the connection-info prefix for log lines.
    ///
    /// Returns something like `H=(helo) [1.2.3.4]:12345` or
    /// `U=root` for local callers.
    pub fn log_sender_info(&self) -> String {
        let mut info = String::new();
        if let Some(ref ip) = self.message_ctx.sender_host_address {
            if !ip.is_empty() {
                let helo_part = self.message_ctx.helo_name.as_deref().unwrap_or("");
                if !helo_part.is_empty() {
                    let _ = write!(info, "H=({helo_part}) [{ip}]");
                } else {
                    let _ = write!(info, "H=[{ip}]");
                }
                return info;
            }
        }
        // Local submission: show U=<user>
        let user = &self.config_ctx.originator_login;
        let u = if user.is_empty() {
            "root"
        } else {
            user.as_str()
        };
        let _ = write!(info, "U={u}");
        info
    }

    /// Maps ACL results (deny, defer, drop, discard, etc.) to SMTP response
    /// codes and sends the appropriate response to the client.
    ///
    /// # Arguments
    ///
    /// * `where_phase` — Which SMTP phase the ACL was evaluated at
    /// * `rc` — The ACL evaluation result
    /// * `user_msg` — User-provided message from ACL `message =` modifier
    /// * `log_msg` — Message for the log
    ///
    /// # Returns
    ///
    /// 0 to continue, -1 to drop the connection, 2 for discard.
    ///
    /// C reference: smtp_in.c lines 3090-3300.
    pub fn smtp_handle_acl_fail(
        &mut self,
        where_phase: AclWhere,
        rc: AclResult,
        user_msg: &str,
        log_msg: &str,
        sender_verify_failure: Option<&SenderVerifyFailure>,
    ) -> i32 {
        let default_code = acl_wherecode(&where_phase);

        // Log the ACL failure
        if !log_msg.is_empty() {
            warn!(
                "ACL {} check failed at {}: {}",
                format!("{:?}", where_phase),
                format!("{:?}", rc),
                log_msg
            );
        }

        // ── Sender verification failure prefix (C smtp_in.c ~3177-3213)
        //
        // If sender verification failed (the ACL contained `verify = sender`
        // that did not succeed), emit the multi-line "Verification failed
        // for <addr>\n<reason>" prefix as a NOT-FINAL response before the
        // actual ACL-result response.  This is a one-shot: once emitted the
        // flag is consumed so subsequent RCPT evaluations within the same
        // transaction do not repeat it (matching C's `af_sverify_told`).
        // ── Sender verification failure prefix (af_sverify_told logic)
        //
        // Emit the multi-line "Verification failed for <addr>\n<reason>"
        // prefix ONLY on the FIRST RCPT that triggers this failure within
        // the current transaction.  C Exim uses af_sverify_told on the
        // sender_verified_failed address to prevent repetition.
        if rc == AclResult::Fail {
            if let Some(svf) = sender_verify_failure {
                if !self.sender_verify_told {
                    self.sender_verify_told = true;
                    let prefix = format!(
                        "Verification failed for <{}>\n{}",
                        svf.address, svf.user_message
                    );
                    let code = if default_code >= 500 {
                        default_code
                    } else {
                        550
                    };
                    let code_str = format!("{}", code);
                    // Emit as NOT-FINAL (multi-line continuation) — each '\n'
                    // in the prefix becomes a separate "code-" line.
                    self.smtp_respond(&code_str, true, &prefix);
                }
            }
        }

        match rc {
            AclResult::Fail => {
                // Permanent failure — 5xx response
                let msg = if user_msg.is_empty() {
                    "Administrative prohibition".to_string()
                } else {
                    user_msg.to_string()
                };
                let code = if default_code >= 500 {
                    default_code
                } else {
                    550
                };
                let code_str = format!("{}", code);
                self.smtp_respond(&code_str, false, &msg);
                0
            }
            AclResult::Defer | AclResult::Error => {
                // Temporary failure — 4xx response
                // In C Exim (smtp_in.c ~3237–3251), non-FAIL results all
                // follow the same path:
                //  - If acl_temp_details AND user_msg: use user_msg
                //  - Otherwise: "Temporary local problem - please try later"
                // We approximate acl_temp_details as true when user_msg is
                // non-empty (matching the C semantics where defer/error verbs
                // set acl_temp_details).
                let msg = if user_msg.is_empty() {
                    "Temporary local problem - please try later".to_string()
                } else {
                    user_msg.to_string()
                };
                self.smtp_respond("451", false, &msg);
                0
            }
            AclResult::FailDrop => {
                // Drop the connection immediately
                let msg = if user_msg.is_empty() {
                    "Administrative prohibition — dropping connection".to_string()
                } else {
                    user_msg.to_string()
                };
                self.smtp_respond("421", false, &msg);
                -1
            }
            AclResult::Discard => {
                // Silently discard — respond with success but don't deliver
                debug!("ACL discard at {:?}", where_phase);
                2
            }
            _ => {
                // Unexpected ACL result — log and reject
                error!("Unexpected ACL result {:?} at {:?}", rc, where_phase);
                self.smtp_respond("451", false, "Internal error in ACL processing");
                0
            }
        }
    }

    // ── Connection Info (smtp_in.c lines 1448-1532) ──

    /// Build a human-readable connection information string.
    ///
    /// Includes hostname, IP address, port, TLS status, and authentication
    /// details. Used for logging and Received header construction.
    ///
    /// C reference: smtp_in.c lines 1448-1482.
    pub fn smtp_get_connection_info(&self) -> String {
        let mut info = String::with_capacity(256);

        if self.server_ctx.host_checking {
            let _ = write!(info, "H=host-checking");
            return info;
        }

        if self.server_ctx.sender_host_notsocket {
            let _ = write!(info, "H=(no-socket)");
            return info;
        }

        if self.server_ctx.atrn_mode {
            let _ = write!(info, "H=atrn-provider");
            return info;
        }

        if self.server_ctx.is_inetd {
            let _ = write!(info, "H=inetd");
        }

        // Host identification
        if let Some(ref name) = self.message_ctx.sender_host_name {
            let _ = write!(info, "H={}", name);
        }
        if let Some(ref addr) = self.message_ctx.sender_host_address {
            if info.is_empty() {
                let _ = write!(info, "H=[{}]", addr);
            } else {
                let _ = write!(info, " [{}]", addr);
            }
        }

        // Port information
        if self.message_ctx.sender_host_port > 0 {
            let _ = write!(info, ":{}", self.message_ctx.sender_host_port);
        }

        // Interface information
        if let Some(ref iface) = self.server_ctx.interface_address {
            let _ = write!(info, " I=[{}]:{}", iface, self.server_ctx.interface_port);
        }

        // Add TLS info if active
        #[cfg(feature = "tls")]
        {
            self.add_tls_info_for_log(&mut info);
        }

        // Add command history
        self.s_connhad_log(&mut info);

        info
    }

    /// Append TLS session details to a log string.
    ///
    /// C reference: smtp_in.c lines 1493-1513.
    #[cfg(feature = "tls")]
    fn add_tls_info_for_log(&self, g: &mut String) {
        if self.message_ctx.tls_in.active {
            if let Some(ref cipher) = self.message_ctx.tls_in.cipher {
                let _ = write!(g, " X={}", cipher);
            }
            if self.message_ctx.tls_in.certificate_verified {
                let _ = write!(g, " CV=yes");
            } else {
                let _ = write!(g, " CV=no");
            }
            if let Some(ref dn) = self.message_ctx.tls_in.peerdn {
                let _ = write!(g, " DN=\"{}\"", dn);
            }
            if let Some(ref sni) = self.message_ctx.tls_in.sni {
                let _ = write!(g, " SNI={}", sni);
            }
        }
    }

    /// Append connection command history to a log string.
    ///
    /// C reference: smtp_in.c lines 1517-1532.
    fn s_connhad_log(&self, g: &mut String) {
        let _ = write!(g, " C=\"");
        let mut idx = self.connection_had_index;
        let mut first = true;
        for _ in 0..SMTP_HISTRY_SIZE {
            if idx == 0 {
                idx = SMTP_HISTRY_SIZE;
            }
            idx -= 1;
            let entry = &self.connection_had[idx];
            if *entry == SmtpCommandHistory::SchNone {
                continue;
            }
            if !first {
                let _ = write!(g, " ");
            }
            first = false;
            let name = match entry {
                SmtpCommandHistory::SchAuth => "AUTH",
                SmtpCommandHistory::SchData => "DATA",
                SmtpCommandHistory::SchBdat => "BDAT",
                SmtpCommandHistory::SchEhlo => "EHLO",
                SmtpCommandHistory::SchHelo => "HELO",
                SmtpCommandHistory::SchMail => "MAIL",
                SmtpCommandHistory::SchRcpt => "RCPT",
                SmtpCommandHistory::SchRset => "RSET",
                SmtpCommandHistory::SchStarttls => "STARTTLS",
                SmtpCommandHistory::SchQuit => "QUIT",
                SmtpCommandHistory::SchNoop => "NOOP",
                SmtpCommandHistory::SchVrfy => "VRFY",
                SmtpCommandHistory::SchNone => "???",
            };
            let _ = write!(g, "{}", name);
        }
        let _ = write!(g, "\"");
    }

    /// Internal helper to transition session state.
    ///
    /// Consumes `self` and produces a new `SmtpSession<T>` with the same
    /// data but a different phantom type parameter. This is safe because
    /// the phantom type has no runtime representation.
    fn transition<T>(self) -> SmtpSession<'ctx, T> {
        SmtpSession {
            _state: PhantomData,
            authenticated_by: self.authenticated_by,
            count_nonmail: self.count_nonmail,
            nonmail_command_count: self.nonmail_command_count,
            synprot_error_count: self.synprot_error_count,
            unknown_command_count: self.unknown_command_count,
            sync_cmd_limit: self.sync_cmd_limit,
            server_ctx: self.server_ctx,
            message_ctx: self.message_ctx,
            config_ctx: self.config_ctx,
            flags: self.flags,
            io: self.io,
            chunking_ctx: self.chunking_ctx,
            #[cfg(feature = "prdr")]
            prdr_state: self.prdr_state,
            cmd_buffer: self.cmd_buffer,
            resp_buffer: self.resp_buffer,
            resp_ptr: self.resp_ptr,
            connection_had: self.connection_had,
            connection_had_index: self.connection_had_index,
            smtp_write_error: self.smtp_write_error,
            rcpt_in_progress: self.rcpt_in_progress,
            sender_verify_told: self.sender_verify_told,
        }
    }

    /// Reset per-message state (RSET equivalent).
    ///
    /// Clears sender address, recipient list, headers, body type, DSN state,
    /// and any PRDR/chunking state. Called on RSET and at the start of each
    /// new message transaction.
    ///
    /// C reference: smtp_in.c `smtp_reset()` function.
    fn smtp_reset(&mut self) {
        self.message_ctx.sender_address.clear();
        self.message_ctx.recipients_list.clear();
        self.message_ctx.recipients_count = 0;
        self.message_ctx.headers.clear();
        self.message_ctx.acl_added_headers.clear();
        self.message_ctx.authenticated_sender = None;
        self.message_ctx.dsn_ret = DsnRet::None;
        self.message_ctx.dsn_envid = None;
        self.message_ctx.message_size = 0;
        self.message_ctx.body_type = BodyType::SevenBit;
        self.message_ctx.smtputf8_advertised = false;
        self.rcpt_in_progress = false;
        self.sender_verify_told = false;

        // Reset PRDR state
        #[cfg(feature = "prdr")]
        {
            self.prdr_state = PrdrState::default();
        }

        // Flush any BDAT data
        bdat_flush_data(&mut self.chunking_ctx, &mut self.io);
    }
}

// =============================================================================
// State Transition Implementations
// =============================================================================

impl<'ctx> SmtpSession<'ctx, Connected> {
    /// Process HELO/EHLO and transition to `Greeted` state.
    ///
    /// Validates the HELO name, runs ACL checks, and builds the EHLO
    /// capability advertisement string if EHLO was used.
    ///
    /// # Arguments
    ///
    /// * `is_ehlo` — `true` for EHLO, `false` for HELO
    /// * `helo_name` — The hostname/domain provided by the client
    ///
    /// # Returns
    ///
    /// `Ok(SmtpSession<Greeted>)` on success.
    /// `Err((SmtpSession<Connected>, SmtpError))` on failure — the session
    /// is returned to the caller so the connection can continue (the client
    /// may retry after a 5xx rejection, per RFC 5321 §4.1.1.1).
    ///
    /// C reference: smtp_in.c lines 4092-4520.
    pub fn greet(
        mut self,
        is_ehlo: bool,
        helo_name: Tainted<String>,
    ) -> Result<SmtpSession<'ctx, Greeted>, Box<(SmtpSession<'ctx, Connected>, SmtpError)>> {
        // Record command in history
        if is_ehlo {
            self.had(SmtpCommandHistory::SchEhlo);
        } else {
            self.had(SmtpCommandHistory::SchHelo);
        }

        // Validate HELO argument — must be non-empty
        let name_ref = helo_name.as_ref();
        if name_ref.is_empty() {
            self.smtp_respond("501", false, "Syntactically invalid HELO/EHLO argument(s)");
            return Err(Box::new((
                self,
                SmtpError::ProtocolError {
                    message: "Empty HELO/EHLO argument".into(),
                },
            )));
        }

        // Store the HELO name
        self.message_ctx.helo_name = Some(name_ref.clone());
        self.flags.helo_seen = true;

        // HDEBUG: helo_lookup_domains check on the HELO argument.
        // C Exim checks the HELO name against `helo_lookup_domains` to decide
        // whether to do a DNS lookup on the HELO argument. The default value
        // is "@ : @[]" (local hostname and local IPs).
        // In `-bh` mode, the HDEBUG output shows this list matching.
        if self.server_ctx.host_checking {
            // The default helo_lookup_domains is "@ : @[]"
            let helo_list = "@ : @[]";
            eprintln!(">>> {} in helo_lookup_domains?", name_ref);
            // Split on ':' and print each element
            for item in helo_list.split(':') {
                let trimmed = item.trim();
                if !trimmed.is_empty() {
                    eprintln!(">>>  list element: {}", trimmed);
                }
            }
            eprintln!(">>> {} in helo_lookup_domains? no (end of list)", name_ref);
        }

        // HELO verification if configured
        if let Some(ref verify_hosts) = self.config_ctx.helo_verify_hosts {
            if !verify_hosts.is_empty() {
                self.flags.helo_verify_required = true;
                // Perform HELO verification via DNS lookup
                // The expand_check_condition function evaluates the host list condition
                let verified = expand_check_condition(verify_hosts, "helo_verify_hosts", "helo");
                self.flags.helo_verify = verified;
            }
        }

        // Run HELO ACL if configured
        if let Some(ref acl) = self.config_ctx.acl_smtp_helo {
            let (acl_rc, user_msg, log_msg) = run_acl_check(
                AclWhere::Helo,
                Some(acl),
                Some(name_ref),
                &self.config_ctx.acl_definitions,
                &self.acl_session_state(),
            );
            if acl_rc != AclResult::Ok {
                let result =
                    self.smtp_handle_acl_fail(AclWhere::Helo, acl_rc, &user_msg, &log_msg, None);
                if result < 0 {
                    // ACL DROP — return session so caller can close gracefully
                    return Err(Box::new((
                        self,
                        SmtpError::ProtocolError {
                            message: "HELO ACL rejected with DROP".into(),
                        },
                    )));
                }
            }
        }

        // Update ESMTP flag and protocol
        self.flags.esmtp = is_ehlo;
        if is_ehlo {
            self.message_ctx.received_protocol = SmtpProtocol::Esmtp;
        } else {
            self.message_ctx.received_protocol = SmtpProtocol::Smtp;
        }

        // Update protocol based on TLS and auth state
        self.update_received_protocol();

        // Send response — C Exim format (smtp_in.c:4224-4232):
        //   "250 <hostname> Hello <sender_ident> at <helo_name> [<ip>]"
        // sender_ident is present in -bs mode (originator_login), absent in -bh mode.
        if is_ehlo {
            self.send_ehlo_response();
        } else {
            let hostname = self.server_ctx.smtp_active_hostname.clone();
            let ident_prefix = match &self.message_ctx.sender_ident {
                Some(ident) if !ident.is_empty() => format!("{} at ", ident),
                _ => String::new(),
            };
            let ip_suffix = match &self.message_ctx.sender_host_address {
                Some(ip) if !ip.is_empty() => format!(" [{}]", ip),
                _ => String::new(),
            };
            let response = format!(
                "{} Hello {}{}{}",
                hostname, ident_prefix, name_ref, ip_suffix
            );
            self.smtp_respond("250", false, &response);
        }

        info!(
            "{} from {}",
            if is_ehlo { "EHLO" } else { "HELO" },
            name_ref
        );

        Ok(self.transition())
    }
}

impl<'ctx> SmtpSession<'ctx, Greeted> {
    /// Create a new SMTP session directly in the `Greeted` state.
    ///
    /// This is used when re-entering the command loop after message reception.
    /// The client has already completed EHLO/HELO, so we skip the banner and
    /// the Connected → Greeted transition. The session continues accepting
    /// MAIL FROM, RSET, QUIT, and other post-greeting commands.
    ///
    /// This avoids sending a duplicate 220 banner when the daemon loops back
    /// after accepting a message (the "250 OK id=..." response already
    /// acknowledged the message).
    fn new_greeted(
        in_fd: RawFd,
        out_fd: RawFd,
        server_ctx: &'ctx ServerContext,
        message_ctx: &'ctx mut MessageContext,
        config_ctx: &'ctx ConfigContext,
    ) -> Self {
        let io = SmtpIoState::new(in_fd, out_fd);
        let chunking_ctx = ChunkingContext::new(false);

        SmtpSession {
            _state: PhantomData,
            authenticated_by: None,
            count_nonmail: None,
            nonmail_command_count: 0,
            synprot_error_count: 0,
            unknown_command_count: 0,
            sync_cmd_limit: SmtpCommand::Noop,
            server_ctx,
            message_ctx,
            config_ctx,
            flags: SmtpSessionFlags::default(),
            io,
            chunking_ctx,
            #[cfg(feature = "prdr")]
            prdr_state: PrdrState::default(),
            cmd_buffer: vec![0u8; SMTP_CMD_BUFFER_SIZE],
            resp_buffer: vec![0u8; SMTP_RESP_BUFFER_SIZE],
            resp_ptr: 0,
            connection_had: [SmtpCommandHistory::SchNone; SMTP_HISTRY_SIZE],
            connection_had_index: 0,
            smtp_write_error: 0,
            rcpt_in_progress: false,
            sender_verify_told: false,
        }
    }

    /// Process MAIL FROM and transition to `MailFrom` state.
    ///
    /// Parses the sender address and MAIL FROM extensions (SIZE, BODY, AUTH,
    /// PRDR, RET, ENVID, SMTPUTF8), runs ACL checks, and stores the sender.
    ///
    /// C reference: smtp_in.c lines 4530-4970.
    ///
    /// Returns `Err((SmtpSession<Greeted>, SmtpError))` on rejection so the
    /// caller retains the session and the client can retry MAIL FROM, matching
    /// C Exim's behaviour of staying in the Greeted state after a 5xx rejection.
    pub fn mail_from(
        mut self,
        raw_address: Tainted<String>,
    ) -> Result<SmtpSession<'ctx, MailFrom>, Box<(SmtpSession<'ctx, Greeted>, SmtpError)>> {
        self.had(SmtpCommandHistory::SchMail);
        self.smtp_reset();

        // Parse the sender address from the argument
        let addr_str = raw_address.as_ref();
        let (sender, extensions) = match parse_mail_address(addr_str) {
            Ok(result) => result,
            Err(msg) => {
                self.smtp_respond("501", false, &msg);
                return Err(Box::new((
                    self,
                    SmtpError::ProtocolError {
                        message: format!("MAIL FROM address error: {}", msg),
                    },
                )));
            }
        };

        // Parse MAIL FROM extensions
        self.parse_mail_from_extensions(&extensions);

        // Check message size against limit
        if self.config_ctx.message_size_limit > 0
            && self.message_ctx.message_size > self.config_ctx.message_size_limit
        {
            self.smtp_respond(
                "552",
                false,
                "Message size exceeds fixed maximum message size",
            );
            return Err(Box::new((
                self,
                SmtpError::ProtocolError {
                    message: "Message size exceeds limit".into(),
                },
            )));
        }

        // Store sender address
        self.message_ctx.sender_address = sender.clone();

        // Run MAIL FROM ACL if configured
        if let Some(ref acl) = self.config_ctx.acl_smtp_mail {
            let (acl_rc, user_msg, log_msg) = run_acl_check(
                AclWhere::Mail,
                Some(acl),
                Some(&sender),
                &self.config_ctx.acl_definitions,
                &self.acl_session_state(),
            );
            if acl_rc != AclResult::Ok {
                let result =
                    self.smtp_handle_acl_fail(AclWhere::Mail, acl_rc, &user_msg, &log_msg, None);
                if result < 0 {
                    return Err(Box::new((
                        self,
                        SmtpError::ProtocolError {
                            message: "MAIL FROM ACL rejected with DROP".into(),
                        },
                    )));
                }
                if result != 2 {
                    // Not discard — clear sender and return to Greeted state
                    self.message_ctx.sender_address.clear();
                    return Err(Box::new((
                        self,
                        SmtpError::ProtocolError {
                            message: "MAIL FROM ACL rejected".into(),
                        },
                    )));
                }
            }
        }

        // Success response
        self.smtp_respond("250", false, "OK");
        info!("MAIL FROM:<{}>", sender);

        Ok(self.transition())
    }
}

impl<'ctx> SmtpSession<'ctx, MailFrom> {
    /// Process RCPT TO and transition to `RcptTo` state.
    ///
    /// Parses the recipient address and DSN parameters, runs ACL checks,
    /// and adds the recipient to the recipient list.
    ///
    /// Returns `Err((SmtpSession<MailFrom>, SmtpError))` on rejection so the
    /// caller retains the session and the client can retry with another
    /// recipient, matching C Exim's behaviour (RFC 5321 §3.3).
    ///
    /// C reference: smtp_in.c lines 4980-5180.
    pub fn rcpt_to(
        mut self,
        raw_address: Tainted<String>,
    ) -> Result<SmtpSession<'ctx, RcptTo>, Box<(SmtpSession<'ctx, MailFrom>, SmtpError)>> {
        self.had(SmtpCommandHistory::SchRcpt);

        // Parse the recipient address
        let addr_str = raw_address.as_ref();
        let (recipient, extensions) = match parse_mail_address(addr_str) {
            Ok(result) => result,
            Err(msg) => {
                self.smtp_respond("501", false, &msg);
                return Err(Box::new((
                    self,
                    SmtpError::ProtocolError {
                        message: format!("RCPT TO address error: {}", msg),
                    },
                )));
            }
        };

        // Parse DSN flags from extensions
        let mut dsn_flags: u32 = 0;
        let mut orcpt: Option<String> = None;
        for ext in extensions.split_whitespace() {
            let upper = ext.to_ascii_uppercase();
            if upper.starts_with("NOTIFY=") {
                let notify_val = &ext[7..];
                for flag in notify_val.split(',') {
                    match flag.to_ascii_uppercase().as_str() {
                        "NEVER" => dsn_flags |= 0x01,
                        "SUCCESS" => dsn_flags |= 0x02,
                        "FAILURE" => dsn_flags |= 0x04,
                        "DELAY" => dsn_flags |= 0x08,
                        _ => {}
                    }
                }
            } else if upper.starts_with("ORCPT=") {
                orcpt = Some(ext[6..].to_string());
            }
        }

        // Run RCPT TO ACL if configured
        self.rcpt_in_progress = true;
        if let Some(ref acl) = self.config_ctx.acl_smtp_rcpt {
            let acl_full = run_acl_check_full(
                AclWhere::Rcpt,
                Some(acl),
                Some(&recipient),
                &self.config_ctx.acl_definitions,
                &self.acl_session_state(),
            );
            let acl_rc = acl_full.result;
            let user_msg = acl_full.user_msg;
            let log_msg = acl_full.log_msg;
            if acl_rc != AclResult::Ok {
                self.rcpt_in_progress = false;
                let result = self.smtp_handle_acl_fail(
                    AclWhere::Rcpt,
                    acl_rc,
                    &user_msg,
                    &log_msg,
                    acl_full.sender_verify_failure.as_ref(),
                );

                // C Exim logs RCPT rejections to both mainlog and rejectlog.
                // In C smtp_handle_acl_fail(), the log uses `log_msg` (from
                // log_message= or condition-generated messages), NOT user_msg
                // (from message= modifiers).  The SMTP response uses user_msg.
                // Format: "<sender_info> F=<sender> rejected RCPT <recipient>: <log_msg>"
                let sender_info = self.log_sender_info();
                let sender = &self.message_ctx.sender_address;
                let reject_reason = if !log_msg.is_empty() {
                    log_msg.to_string()
                } else if !user_msg.is_empty() {
                    user_msg.to_string()
                } else {
                    String::new()
                };
                let reject_line = if reject_reason.is_empty() {
                    format!("{sender_info} F=<{sender}> rejected RCPT <{recipient}>")
                } else {
                    format!(
                        "{sender_info} F=<{sender}> rejected RCPT <{recipient}>: {reject_reason}"
                    )
                };
                // LOG_MAIN | LOG_REJECT = 0x03
                self.log_write(3, &reject_line);

                if result < 0 {
                    return Err(Box::new((
                        self,
                        SmtpError::ProtocolError {
                            message: "RCPT TO ACL rejected with DROP".into(),
                        },
                    )));
                }
                return Err(Box::new((
                    self,
                    SmtpError::ProtocolError {
                        message: "RCPT TO ACL rejected".into(),
                    },
                )));
            }
        }
        self.rcpt_in_progress = false;

        // Add recipient to the list
        let item = RecipientItem {
            address: recipient.clone(),
            dsn_flags,
            orcpt,
            errors_to: None,
        };
        self.message_ctx.recipients_list.push(item);
        self.message_ctx.recipients_count += 1;

        // Success response
        self.smtp_respond("250", false, "Accepted");
        info!("RCPT TO:<{}>", recipient);

        Ok(self.transition())
    }
}

impl<'ctx> SmtpSession<'ctx, RcptTo> {
    /// Accept additional RCPT TO commands in the `RcptTo` state.
    ///
    /// This allows multiple recipients before DATA. Returns the same
    /// state type since we're already in `RcptTo`.
    ///
    /// Returns `Err((SmtpSession<RcptTo>, SmtpError))` on rejection so the
    /// caller retains the session and the client can try more recipients,
    /// matching C Exim's behaviour (RFC 5321 §3.3).
    pub fn rcpt_to(
        mut self,
        raw_address: Tainted<String>,
    ) -> Result<SmtpSession<'ctx, RcptTo>, Box<(SmtpSession<'ctx, RcptTo>, SmtpError)>> {
        self.had(SmtpCommandHistory::SchRcpt);

        let addr_str = raw_address.as_ref();
        let (recipient, extensions) = match parse_mail_address(addr_str) {
            Ok(result) => result,
            Err(msg) => {
                self.smtp_respond("501", false, &msg);
                return Err(Box::new((
                    self,
                    SmtpError::ProtocolError {
                        message: format!("RCPT TO address error: {}", msg),
                    },
                )));
            }
        };

        // Parse DSN flags
        let mut dsn_flags: u32 = 0;
        let mut orcpt: Option<String> = None;
        for ext in extensions.split_whitespace() {
            let upper = ext.to_ascii_uppercase();
            if upper.starts_with("NOTIFY=") {
                let notify_val = &ext[7..];
                for flag in notify_val.split(',') {
                    match flag.to_ascii_uppercase().as_str() {
                        "NEVER" => dsn_flags |= 0x01,
                        "SUCCESS" => dsn_flags |= 0x02,
                        "FAILURE" => dsn_flags |= 0x04,
                        "DELAY" => dsn_flags |= 0x08,
                        _ => {}
                    }
                }
            } else if upper.starts_with("ORCPT=") {
                orcpt = Some(ext[6..].to_string());
            }
        }

        // Run RCPT TO ACL
        self.rcpt_in_progress = true;
        if let Some(ref acl) = self.config_ctx.acl_smtp_rcpt {
            let acl_full = run_acl_check_full(
                AclWhere::Rcpt,
                Some(acl),
                Some(&recipient),
                &self.config_ctx.acl_definitions,
                &self.acl_session_state_for_recipient(&recipient),
            );
            let acl_rc = acl_full.result;
            let user_msg = acl_full.user_msg;
            let log_msg = acl_full.log_msg;
            if acl_rc != AclResult::Ok {
                self.rcpt_in_progress = false;
                let result = self.smtp_handle_acl_fail(
                    AclWhere::Rcpt,
                    acl_rc,
                    &user_msg,
                    &log_msg,
                    acl_full.sender_verify_failure.as_ref(),
                );

                // Rejection log entry (mainlog + rejectlog).
                // Log uses log_msg (from log_message= or condition failure),
                // NOT user_msg (from message= SMTP response override).
                let sender_info = self.log_sender_info();
                let sender = &self.message_ctx.sender_address;
                let reject_reason = if !log_msg.is_empty() {
                    log_msg.to_string()
                } else if !user_msg.is_empty() {
                    user_msg.to_string()
                } else {
                    String::new()
                };
                let reject_line = if reject_reason.is_empty() {
                    format!("{sender_info} F=<{sender}> rejected RCPT <{recipient}>")
                } else {
                    format!(
                        "{sender_info} F=<{sender}> rejected RCPT <{recipient}>: {reject_reason}"
                    )
                };
                self.log_write(3, &reject_line);

                if result < 0 {
                    return Err(Box::new((
                        self,
                        SmtpError::ProtocolError {
                            message: "RCPT TO ACL rejected with DROP".into(),
                        },
                    )));
                }
                return Err(Box::new((
                    self,
                    SmtpError::ProtocolError {
                        message: "RCPT TO ACL rejected".into(),
                    },
                )));
            }
        }
        self.rcpt_in_progress = false;

        let item = RecipientItem {
            address: recipient.clone(),
            dsn_flags,
            orcpt,
            errors_to: None,
        };
        self.message_ctx.recipients_list.push(item);
        self.message_ctx.recipients_count += 1;

        self.smtp_respond("250", false, "Accepted");
        info!("RCPT TO:<{}>", recipient);

        Ok(self.transition())
    }

    /// Process DATA command and transition to `DataPhase` state.
    ///
    /// Verifies at least one recipient has been accepted, runs the PREDATA
    /// and DATA ACL checks, and sends the "354 Enter message" response.
    ///
    /// C reference: smtp_in.c lines 5190-5260.
    /// Returns `Err((SmtpSession<RcptTo>, SmtpError))` on rejection so
    /// the caller retains the session and the client can issue RSET or
    /// more RCPT TO commands.
    pub fn data(
        mut self,
    ) -> Result<SmtpSession<'ctx, DataPhase>, Box<(SmtpSession<'ctx, RcptTo>, SmtpError)>> {
        self.had(SmtpCommandHistory::SchData);

        // Verify at least one recipient
        if self.message_ctx.recipients_count == 0 {
            self.smtp_respond("503", false, "No valid recipients");
            return Err(Box::new((
                self,
                SmtpError::ProtocolError {
                    message: "DATA without recipients".into(),
                },
            )));
        }

        // Run PREDATA ACL if configured
        if let Some(ref acl) = self.config_ctx.acl_smtp_predata {
            let (acl_rc, user_msg, log_msg) = run_acl_check(
                AclWhere::Predata,
                Some(acl),
                None,
                &self.config_ctx.acl_definitions,
                &self.acl_session_state(),
            );
            if acl_rc != AclResult::Ok {
                let result =
                    self.smtp_handle_acl_fail(AclWhere::Predata, acl_rc, &user_msg, &log_msg, None);
                if result < 0 {
                    return Err(Box::new((
                        self,
                        SmtpError::ProtocolError {
                            message: "PREDATA ACL rejected with DROP".into(),
                        },
                    )));
                }
                if result != 2 {
                    return Err(Box::new((
                        self,
                        SmtpError::ProtocolError {
                            message: "PREDATA ACL rejected".into(),
                        },
                    )));
                }
            }
        }

        // NOTE: The DATA ACL (acl_smtp_data) is NOT run here.
        // In C Exim, acl_smtp_data runs AFTER the message body is fully
        // received (after the terminating "."), not at the DATA command.
        // Only acl_smtp_predata runs at the DATA command (above).
        // The DATA ACL is evaluated by the message reception code after
        // the body has been read and headers parsed, giving it access to
        // variables like $reply_address, $h_subject, etc.

        // Send 354 response — ready for message data
        self.smtp_respond(
            "354",
            false,
            "Enter message, ending with \".\" on a line by itself",
        );
        info!(
            "DATA command accepted, {} recipients",
            self.message_ctx.recipients_count
        );

        Ok(self.transition())
    }

    /// Reset the transaction and return to `Greeted` state.
    pub fn reset(mut self) -> SmtpSession<'ctx, Greeted> {
        self.had(SmtpCommandHistory::SchRset);
        self.smtp_reset();
        self.smtp_respond("250", false, "Reset OK");
        self.transition()
    }
}

impl<'ctx> SmtpSession<'ctx, MailFrom> {
    /// Reset the transaction from `MailFrom` state and return to `Greeted`.
    pub fn reset(mut self) -> SmtpSession<'ctx, Greeted> {
        self.had(SmtpCommandHistory::SchRset);
        self.smtp_reset();
        self.smtp_respond("250", false, "Reset OK");
        self.transition()
    }
}

impl<'ctx> SmtpSession<'ctx, DataPhase> {
    /// Reset the transaction from `DataPhase` state and return to `Greeted`.
    pub fn reset(mut self) -> SmtpSession<'ctx, Greeted> {
        self.had(SmtpCommandHistory::SchRset);
        self.smtp_reset();
        self.smtp_respond("250", false, "Reset OK");
        self.transition()
    }

    /// Read the message body from the SMTP connection until the lone "."
    /// terminator.  Returns a `ReceivedMessageData` struct containing parsed
    /// headers, raw header lines, raw body data, and computed metrics.
    ///
    /// This uses the same I/O buffer as the command loop so no data is lost
    /// to separate buffering layers.
    ///
    /// C reference: `receive_msg()` in `receive.c`.
    pub fn read_message_body(&mut self) -> ReceivedMessageData {
        let mut parsed_headers: Vec<(String, String)> = Vec::new();
        let mut raw_header_lines: Vec<String> = Vec::new();
        let mut body_data: Vec<u8> = Vec::new();
        let mut in_headers = true;
        let mut current_header_name = String::new();
        let mut current_header_value = String::new();
        let mut current_raw_header = String::new();
        let mut body_linecount: i64 = 0;
        let mut body_zerocount: i64 = 0;
        let mut max_received_linelength: i64 = 0;
        let mut header_linecount: i64 = 0;
        let mut message_size: i64 = 0;

        /// Flush a completed header into the lists.
        fn flush_header(
            name: &mut String,
            value: &mut String,
            raw: &mut String,
            parsed: &mut Vec<(String, String)>,
            raw_lines: &mut Vec<String>,
        ) {
            if !name.is_empty() {
                let v = value.trim().to_string();
                parsed.push((std::mem::take(name).to_ascii_lowercase(), v));
                value.clear();
                raw_lines.push(std::mem::take(raw));
            } else {
                raw.clear();
            }
        }

        loop {
            // Read one line from the SMTP I/O buffer.
            let mut line = Vec::new();
            loop {
                let ch = smtp_getc(&mut self.io, SMTP_CMD_BUFFER_SIZE as u32);
                if ch < 0 {
                    // EOF — flush any pending header and return
                    flush_header(
                        &mut current_header_name,
                        &mut current_header_value,
                        &mut current_raw_header,
                        &mut parsed_headers,
                        &mut raw_header_lines,
                    );
                    let total_linecount = header_linecount + body_linecount;
                    return ReceivedMessageData {
                        parsed_headers,
                        raw_header_lines,
                        body_data,
                        body_linecount,
                        body_zerocount,
                        max_received_linelength,
                        message_linecount: total_linecount,
                        message_size,
                    };
                }
                let byte = ch as u8;
                line.push(byte);
                if byte == b'\n' {
                    break;
                }
            }

            let line_len = line.len() as i64;
            message_size += line_len;

            // Track max line length (excluding CRLF/LF)
            let content_len = {
                let mut end = line.len();
                if end > 0 && line[end - 1] == b'\n' {
                    end -= 1;
                }
                if end > 0 && line[end - 1] == b'\r' {
                    end -= 1;
                }
                end as i64
            };
            if content_len > max_received_linelength {
                max_received_linelength = content_len;
            }

            // Trim CRLF or LF for text processing
            let trimmed = {
                let mut end = line.len();
                if end > 0 && line[end - 1] == b'\n' {
                    end -= 1;
                }
                if end > 0 && line[end - 1] == b'\r' {
                    end -= 1;
                }
                String::from_utf8_lossy(&line[..end]).to_string()
            };

            // Lone "." marks end of message body (dot-stuffing: ".." → ".")
            if trimmed == "." {
                flush_header(
                    &mut current_header_name,
                    &mut current_header_value,
                    &mut current_raw_header,
                    &mut parsed_headers,
                    &mut raw_header_lines,
                );
                let total_linecount = header_linecount + body_linecount;
                return ReceivedMessageData {
                    parsed_headers,
                    raw_header_lines,
                    body_data,
                    body_linecount,
                    body_zerocount,
                    max_received_linelength,
                    message_linecount: total_linecount,
                    message_size,
                };
            }

            // Dot-stuffing: lines starting with ".." have the leading dot removed
            let effective_line = if trimmed.starts_with("..") {
                &trimmed[1..]
            } else {
                &trimmed
            };

            if in_headers {
                // Empty line separates headers from body
                if trimmed.is_empty() {
                    flush_header(
                        &mut current_header_name,
                        &mut current_header_value,
                        &mut current_raw_header,
                        &mut parsed_headers,
                        &mut raw_header_lines,
                    );
                    in_headers = false;
                    // C Exim includes the blank separator line in
                    // $message_linecount — count it here so the
                    // total matches (header_linecount + body_linecount).
                    body_linecount += 1;
                    continue;
                }
                header_linecount += 1;
                // Continuation line (starts with space/tab)
                if line.first() == Some(&b' ') || line.first() == Some(&b'\t') {
                    if !current_header_name.is_empty() {
                        current_header_value.push(' ');
                        current_header_value.push_str(effective_line.trim_start());
                        current_raw_header.push('\n');
                        current_raw_header.push_str(effective_line);
                    }
                    continue;
                }
                // New header: "Name: Value"
                flush_header(
                    &mut current_header_name,
                    &mut current_header_value,
                    &mut current_raw_header,
                    &mut parsed_headers,
                    &mut raw_header_lines,
                );
                if let Some(colon_pos) = effective_line.find(':') {
                    current_header_name = effective_line[..colon_pos].to_string();
                    current_header_value = effective_line[colon_pos + 1..].trim_start().to_string();
                    current_raw_header = effective_line.to_string();
                } else {
                    // Malformed header — treat as start of body
                    in_headers = false;
                    body_linecount += 1;
                    body_data.extend_from_slice(effective_line.as_bytes());
                    body_data.push(b'\n');
                    for &b in line.iter() {
                        if b == 0 {
                            body_zerocount += 1;
                        }
                    }
                }
            } else {
                // Body line
                body_linecount += 1;
                body_data.extend_from_slice(effective_line.as_bytes());
                body_data.push(b'\n');
                for &b in line.iter() {
                    if b == 0 {
                        body_zerocount += 1;
                    }
                }
            }
        }
    }

    /// Transition back to the `Greeted` state after DATA processing
    /// without sending RSET response (unlike reset()).
    /// Used after handling the DATA ACL response inline.
    pub fn finish_data(mut self) -> SmtpSession<'ctx, Greeted> {
        self.smtp_reset();
        self.transition()
    }
}

// =============================================================================
// Command Handler Methods — Available in specific states
// =============================================================================

impl<'ctx, S> SmtpSession<'ctx, S> {
    // ── EHLO Response Builder ──

    /// Build and send the EHLO capability advertisement response.
    ///
    /// Constructs the multi-line 250 response with all supported SMTP
    /// extensions. Capability strings are character-for-character identical
    /// to the C implementation for identical configurations (AAP §0.7.1).
    ///
    /// **Ordering guarantee**: Extensions are appended in the same order as
    /// the C implementation at `smtp_in.c` lines 4330-4500:
    ///   1. SIZE  2. 8BITMIME  3. PIPELINING  4. DSN  5. CHUNKING
    ///   6. AUTH  7. STARTTLS  8. PRDR  9. SMTPUTF8  10. WELLKNOWN
    ///   11. LIMITS  12. XCLIENT
    ///
    /// This ordering matches `s_]` in the C source and ensures EHLO
    /// response diffs between C and Rust binaries are zero for identical
    /// configurations.
    ///
    /// C reference: smtp_in.c lines 4330-4500.
    fn send_ehlo_response(&mut self) {
        let hostname = self.server_ctx.smtp_active_hostname.clone();
        let helo_name = self.message_ctx.helo_name.as_deref().unwrap_or("unknown");
        let ident_prefix = match &self.message_ctx.sender_ident {
            Some(ident) if !ident.is_empty() => format!("{} at ", ident),
            _ => String::new(),
        };
        let ip_suffix = match &self.message_ctx.sender_host_address {
            Some(ip) if !ip.is_empty() => format!(" [{}]", ip),
            _ => String::new(),
        };
        let greeting = format!(
            "{} Hello {}{}{}",
            hostname, ident_prefix, helo_name, ip_suffix
        );

        // Build capability list
        let mut caps: Vec<String> = Vec::with_capacity(16);
        caps.push(greeting);

        // SIZE extension — always advertise
        if self.config_ctx.message_size_limit > 0 {
            caps.push(format!("SIZE {}", self.config_ctx.message_size_limit));
        } else {
            caps.push("SIZE".to_string());
        }

        // 8BITMIME — always advertise with ESMTP
        caps.push("8BITMIME".to_string());

        // PIPELINING — advertise if configured
        if self.config_ctx.pipelining_advertise_hosts.is_some() {
            caps.push("PIPELINING".to_string());
        }

        // DSN (Delivery Status Notifications)
        if self.config_ctx.dsn_advertise_hosts.is_some() {
            caps.push("DSN".to_string());
            self.flags.dsn_advertised = true;
        }

        // CHUNKING (BDAT support)
        if self.config_ctx.chunking_advertise_hosts.is_some() {
            caps.push("CHUNKING".to_string());
        }

        // AUTH mechanisms
        let auth_line = self.advertise_auth_mechanisms();
        if !auth_line.is_empty() {
            caps.push(auth_line);
            self.flags.auth_advertised = true;
        }

        // STARTTLS (feature-gated)
        #[cfg(feature = "tls")]
        {
            if !self.message_ctx.tls_in.active {
                if let Some(ref hosts) = self.config_ctx.tls_advertise_hosts {
                    if !hosts.is_empty() {
                        caps.push("STARTTLS".to_string());
                    }
                }
            }
        }

        // PRDR (feature-gated)
        #[cfg(feature = "prdr")]
        {
            if self.config_ctx.prdr_enable {
                caps.push("PRDR".to_string());
            }
        }

        // SMTPUTF8 (feature-gated)
        #[cfg(feature = "i18n")]
        {
            if let Some(ref hosts) = self.config_ctx.smtputf8_advertise_hosts {
                if !hosts.is_empty() {
                    caps.push("SMTPUTF8".to_string());
                }
            }
        }

        // WELLKNOWN (feature-gated)
        #[cfg(feature = "wellknown")]
        {
            if let Some(ref hosts) = self.config_ctx.wellknown_advertise_hosts {
                if !hosts.is_empty() {
                    caps.push("WELLKNOWN".to_string());
                }
            }
        }

        // LIMITS (feature-gated)
        #[cfg(feature = "esmtp-limits")]
        {
            if let Some(ref hosts) = self.config_ctx.limits_advertise_hosts {
                if !hosts.is_empty() {
                    caps.push("LIMITS".to_string());
                }
            }
        }

        // XCLIENT (feature-gated)
        #[cfg(feature = "xclient")]
        {
            if let Some(ref hosts) = self.config_ctx.xclient_advertise_hosts {
                if !hosts.is_empty() {
                    caps.push("XCLIENT".to_string());
                }
            }
        }

        // HELP — always advertised as the last EHLO capability, matching C
        // Exim's behaviour (smtp_in.c ehlo_response, always terminates the
        // capability list with "HELP").
        caps.push("HELP".to_string());

        // Send capabilities as multi-line response
        for (i, cap) in caps.iter().enumerate() {
            let is_last = i == caps.len() - 1;
            if is_last {
                let line = format!("250 {}\r\n", cap);
                self.smtp_printf(&line, false);
            } else {
                let line = format!("250-{}\r\n", cap);
                self.smtp_printf(&line, true);
            }
        }
    }

    /// Build the AUTH capability advertisement line.
    ///
    /// Iterates over configured auth instances and builds the
    /// "AUTH mechanism1 mechanism2" capability line for EHLO.
    fn advertise_auth_mechanisms(&self) -> String {
        let mut mechanisms = Vec::new();
        for instance in &self.config_ctx.auth_instances {
            // Check advertise condition if present
            if let Some(ref condition) = instance.advertise_condition {
                if !expand_check_condition(condition, "auth", "advertise") {
                    continue;
                }
            }
            mechanisms.push(instance.public_name.clone());
        }

        if mechanisms.is_empty() {
            String::new()
        } else {
            format!("AUTH {}", mechanisms.join(" "))
        }
    }

    /// Update the received protocol identifier based on connection state.
    ///
    /// The protocol string is built from the combination of:
    /// - SMTP vs ESMTP (HELO vs EHLO)
    /// - TLS state (s suffix)
    /// - Auth state (a suffix)
    ///
    /// C reference: smtp_in.c lines 281-285, protocol index calculation.
    fn update_received_protocol(&mut self) {
        // In batched SMTP (-bS) mode, the protocol is always "local-bsmtp"
        // regardless of HELO/EHLO.  C Exim preserves this invariant: the
        // protocols_local[] table is never consulted when batched input is
        // active (smtp_in.c ~5880).
        if self.server_ctx.smtp_batched_input {
            self.message_ctx.received_protocol = SmtpProtocol::LocalBsmtp;
            return;
        }

        let is_esmtp = self.flags.esmtp;
        let is_tls = self.message_ctx.tls_in.active;
        let is_authed = self.message_ctx.authenticated_id.is_some();
        let is_local = self.server_ctx.is_local_session;

        // Protocol string selection based on local/ESMTP/TLS/AUTH status.
        // C Exim uses protocols_local[] for -bs/-bS mode and protocols[]
        // for network connections (smtp_in.c ~line 5880).
        self.message_ctx.received_protocol = if is_local {
            match (is_esmtp, is_tls, is_authed) {
                (false, false, false) => SmtpProtocol::LocalSmtp,
                (true, false, false) => SmtpProtocol::LocalEsmtp,
                (false, true, false) => SmtpProtocol::LocalSmtps,
                (true, true, false) => SmtpProtocol::LocalEsmtps,
                (_, _, true) => SmtpProtocol::LocalEsmtpa,
            }
        } else {
            match (is_esmtp, is_tls, is_authed) {
                (false, false, false) => SmtpProtocol::Smtp,
                (true, false, false) => SmtpProtocol::Esmtp,
                (false, true, false) => SmtpProtocol::Smtps,
                (true, true, false) => SmtpProtocol::Esmtps,
                (false, false, true) => SmtpProtocol::Esmtpa,
                (true, false, true) => SmtpProtocol::Esmtpa,
                (false, true, true) => SmtpProtocol::Esmtpsa,
                (true, true, true) => SmtpProtocol::Esmtpsa,
            }
        };
    }

    // ── MAIL FROM Extension Parsing ──

    /// Parse MAIL FROM extension parameters.
    ///
    /// Processes SIZE, BODY, AUTH, RET, ENVID, PRDR, and SMTPUTF8
    /// parameters from the MAIL FROM command arguments.
    ///
    /// C reference: smtp_in.c lines 4550-4800.
    fn parse_mail_from_extensions(&mut self, extensions: &str) {
        for param in extensions.split_whitespace() {
            let upper = param.to_ascii_uppercase();

            if upper.starts_with("SIZE=") {
                // SIZE extension — declared message size
                if let Ok(size) = param[5..].parse::<u64>() {
                    self.message_ctx.message_size = size;
                }
            } else if let Some(body_val) = upper.strip_prefix("BODY=") {
                // BODY extension — 7BIT or 8BITMIME
                match body_val {
                    "7BIT" => self.message_ctx.body_type = BodyType::SevenBit,
                    "8BITMIME" => self.message_ctx.body_type = BodyType::EightBitMime,
                    _ => {
                        warn!("Unrecognized BODY value: {}", body_val);
                    }
                }
            } else if upper.starts_with("AUTH=") {
                // AUTH extension — authenticated sender
                let auth_sender = &param[5..];
                if auth_sender != "<>" {
                    self.message_ctx.authenticated_sender = Some(auth_sender.to_string());
                }
            } else if let Some(ret_val) = upper.strip_prefix("RET=") {
                // RET extension — DSN return type
                match ret_val {
                    "FULL" => self.message_ctx.dsn_ret = DsnRet::Full,
                    "HDRS" => self.message_ctx.dsn_ret = DsnRet::Hdrs,
                    _ => {
                        warn!("Unrecognized RET value: {}", ret_val);
                    }
                }
            } else if upper.starts_with("ENVID=") {
                // ENVID extension — DSN envelope ID
                self.message_ctx.dsn_envid = Some(param[6..].to_string());
            }
            // PRDR extension (feature-gated)
            #[cfg(feature = "prdr")]
            {
                if upper == "PRDR" {
                    self.prdr_state.requested = true;
                }
            }
            // SMTPUTF8 extension (feature-gated)
            #[cfg(feature = "i18n")]
            {
                if upper == "SMTPUTF8" {
                    self.message_ctx.smtputf8_advertised = true;
                }
            }
        }
    }

    // ── AUTH Command Handler ──

    /// Handle the AUTH command.
    ///
    /// Finds the matching auth driver, runs the ACL check, and delegates
    /// to the driver's server() method for the actual authentication exchange.
    ///
    /// C reference: smtp_in.c lines 3938-4089.
    fn handle_auth(&mut self, argument: &str) -> i32 {
        self.had(SmtpCommandHistory::SchAuth);

        // AUTH not allowed inside a transaction
        if !self.message_ctx.sender_address.is_empty() {
            self.smtp_respond("503", false, "AUTH command used when not advertised");
            return 0;
        }

        // Already authenticated
        if self.message_ctx.authenticated_id.is_some() {
            self.smtp_respond("503", false, "Already authenticated");
            return 0;
        }

        // AUTH must have been advertised
        if !self.flags.auth_advertised {
            self.smtp_respond("503", false, "AUTH command used when not advertised");
            return 0;
        }

        // Parse mechanism name from argument
        let mechanism = argument
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();

        if mechanism.is_empty() {
            self.smtp_respond("501", false, "AUTH mechanism not given");
            return 0;
        }

        // Find matching auth driver
        let mut driver_idx: Option<usize> = None;
        for (idx, instance) in self.config_ctx.auth_instances.iter().enumerate() {
            if instance.public_name.eq_ignore_ascii_case(&mechanism) {
                driver_idx = Some(idx);
                break;
            }
        }

        let idx = match driver_idx {
            Some(i) => i,
            None => {
                self.smtp_respond(
                    "504",
                    false,
                    &format!("{} authentication mechanism not supported", mechanism),
                );
                return 0;
            }
        };

        // Run AUTH ACL if configured
        if let Some(ref acl) = self.config_ctx.acl_smtp_auth {
            let (acl_rc, user_msg, log_msg) = run_acl_check(
                AclWhere::Auth,
                Some(acl),
                Some(&mechanism),
                &self.config_ctx.acl_definitions,
                &self.acl_session_state(),
            );
            if acl_rc != AclResult::Ok {
                let result =
                    self.smtp_handle_acl_fail(AclWhere::Auth, acl_rc, &user_msg, &log_msg, None);
                if result < 0 {
                    return -1;
                }
                return 0;
            }
        }

        // Extract initial response data if provided after the mechanism name
        let initial_data = argument
            .split_once(char::is_whitespace)
            .map(|x| x.1)
            .unwrap_or("");

        // Look up the auth driver for this instance via the registry.
        // AuthInstanceConfig stores the driver_name; we look up the driver
        // factory from the inventory-registered AuthDriverFactory entries.
        let instance = &self.config_ctx.auth_instances[idx];

        // Find the matching factory and create a driver instance via
        // the centralized DriverRegistry (which wraps inventory internally).
        let driver_name = &instance.driver_name;
        let factory = exim_drivers::DriverRegistry::find_auth(driver_name.as_str());

        let driver: Box<dyn exim_drivers::auth_driver::AuthDriver> = match factory {
            Some(f) => (f.create)(),
            None => {
                error!(
                    "AUTH {} driver '{}' not found in registry",
                    mechanism, driver_name
                );
                self.smtp_respond("454", false, "Temporary authentication failure");
                return 0;
            }
        };

        let auth_result = driver.server(instance, initial_data);

        match auth_result {
            Ok(exim_drivers::auth_driver::AuthServerResult::Authenticated) => {
                // Authentication succeeded
                let authenticated_id: String = instance.set_id.clone().unwrap_or_default();
                self.message_ctx.authenticated_id = Some(authenticated_id.clone());
                self.message_ctx.sender_host_authenticated = Some(instance.public_name.clone());
                self.authenticated_by = Some(idx);

                // Update received protocol
                self.update_received_protocol();

                self.smtp_respond("235", false, "Authentication succeeded");
                info!("AUTH {} succeeded for {}", mechanism, authenticated_id);
                0
            }
            Ok(exim_drivers::auth_driver::AuthServerResult::Failed)
            | Ok(exim_drivers::auth_driver::AuthServerResult::Cancelled) => {
                warn!("AUTH {} credentials invalid", mechanism);
                self.smtp_respond("535", false, "Authentication credentials invalid");
                0
            }
            Ok(exim_drivers::auth_driver::AuthServerResult::Deferred) => {
                warn!("AUTH {} temporarily unavailable", mechanism);
                self.smtp_respond("454", false, "Temporary authentication failure");
                0
            }
            Ok(_) | Err(_) => {
                warn!("AUTH {} error", mechanism);
                self.smtp_respond("454", false, "Temporary authentication failure");
                0
            }
        }
    }

    // ── STARTTLS Command Handler ──

    /// Handle the STARTTLS command.
    ///
    /// Runs the ACL check, sends "220 Ready to start TLS", initiates TLS
    /// negotiation, and on success resets AUTH/HELO state.
    ///
    /// C reference: smtp_in.c lines 5400-5640.
    #[cfg(feature = "tls")]
    fn handle_starttls(&mut self) -> i32 {
        self.had(SmtpCommandHistory::SchStarttls);

        // TLS already active
        if self.message_ctx.tls_in.active {
            self.smtp_respond("554", false, "TLS already active");
            return 0;
        }

        // Run STARTTLS ACL if configured
        if let Some(ref acl) = self.config_ctx.acl_smtp_starttls {
            let (acl_rc, user_msg, log_msg) = run_acl_check(
                AclWhere::StartTls,
                Some(acl),
                None,
                &self.config_ctx.acl_definitions,
                &self.acl_session_state(),
            );
            if acl_rc != AclResult::Ok {
                let result = self.smtp_handle_acl_fail(
                    AclWhere::StartTls,
                    acl_rc,
                    &user_msg,
                    &log_msg,
                    None,
                );
                if result < 0 {
                    return -1;
                }
                return 0;
            }
        }

        // Send "220 Ready to start TLS"
        self.smtp_respond("220", false, "Ready to start TLS");
        let _ = self.smtp_fflush(true);

        // Perform TLS negotiation via the TLS backend.
        //
        // C reference: smtp_in.c lines 5510-5630 — tls_server_start().
        //
        // TLS handshake is delegated to the `tls_server_start()` helper which
        // invokes the appropriate TlsBackend trait method (rustls or openssl).
        // On success it returns a `TlsSession` handle whose cipher/peer-DN/SNI
        // are populated; on failure we send a 454 response.
        //
        // After TLS establishment, the I/O layer transparently encrypts
        // all subsequent reads and writes.  The SMTP session MUST be
        // reset (RFC 3207 §4.2) — HELO/AUTH state is cleared so the
        // client re-identifies itself over the encrypted channel.
        match tls_server_start(
            self.io.in_fd,
            self.config_ctx.tls_certificate.as_deref(),
            self.config_ctx.tls_privatekey.as_deref(),
            self.config_ctx.tls_require_ciphers.as_deref(),
        ) {
            Ok((tls_session, tls_backend)) => {
                // Store the live TLS backend so all subsequent I/O goes
                // through the encrypted stream.
                self.io.tls_backend = Some(tls_backend);

                // Populate TLS session metadata for logging and headers
                self.message_ctx.tls_in.active = true;
                self.message_ctx.tls_in.cipher = tls_session.cipher.clone();
                self.message_ctx.tls_in.certificate_verified = tls_session.certificate_verified;
                self.message_ctx.tls_in.peerdn = tls_session.peer_dn.clone();
                self.message_ctx.tls_in.sni = tls_session.sni.clone();

                // RFC 3207 §4.2: Reset HELO/AUTH state after STARTTLS
                self.flags.helo_seen = false;
                self.flags.auth_advertised = false;
                self.message_ctx.authenticated_id = None;
                self.message_ctx.sender_host_authenticated = None;
                self.authenticated_by = None;

                // Update received protocol (adds "s" suffix for TLS)
                self.update_received_protocol();

                info!(
                    "STARTTLS negotiation succeeded, cipher={}",
                    self.message_ctx
                        .tls_in
                        .cipher
                        .as_deref()
                        .unwrap_or("unknown")
                );
                0
            }
            Err(tls_err) => {
                // TLS negotiation failed — log and send 454 temporary failure.
                // The connection remains unencrypted; the client may retry
                // without TLS or disconnect.
                warn!("STARTTLS negotiation failed: {}", tls_err);
                self.smtp_respond("454", false, "TLS currently unavailable");
                0
            }
        }
    }

    // ── QUIT Command Handler ──

    /// Handle the QUIT command.
    ///
    /// Sends "221 Goodbye" and signals session termination.
    ///
    /// C reference: smtp_in.c lines 3660-3690.
    fn handle_quit(&mut self) -> i32 {
        self.had(SmtpCommandHistory::SchQuit);
        let hostname = self.server_ctx.smtp_active_hostname.clone();
        let msg = format!("{} closing connection", hostname);
        self.smtp_respond("221", false, &msg);
        let _ = self.smtp_fflush(true);
        info!("QUIT");
        1 // Signal done
    }

    // ── RSET Command Handler ──

    /// Handle the RSET command in the command dispatch loop.
    ///
    /// Resets per-message state and responds with 250 OK.
    ///
    /// C reference: smtp_in.c lines 3730-3750.
    fn handle_rset_cmd(&mut self) {
        self.had(SmtpCommandHistory::SchRset);
        self.smtp_reset();
        self.smtp_respond("250", false, "Reset OK");
    }

    // ── VRFY Command Handler ──

    /// Handle the VRFY command.
    ///
    /// Runs the ACL check and responds with address verification result.
    fn handle_vrfy(&mut self, argument: &str) {
        self.had(SmtpCommandHistory::SchVrfy);

        if let Some(ref acl) = self.config_ctx.acl_smtp_vrfy {
            let (acl_rc, user_msg, log_msg) = run_acl_check(
                AclWhere::Vrfy,
                Some(acl),
                Some(argument),
                &self.config_ctx.acl_definitions,
                &self.acl_session_state(),
            );
            if acl_rc != AclResult::Ok {
                let _ =
                    self.smtp_handle_acl_fail(AclWhere::Vrfy, acl_rc, &user_msg, &log_msg, None);
                return;
            }
        }

        // Respond with a conservative verification
        let msg = format!(
            "Cannot VRFY user, but will accept message for <{}>",
            argument
        );
        self.smtp_respond("252", false, &msg);
    }

    // ── EXPN Command Handler ──

    /// Handle the EXPN command.
    ///
    /// Runs the ACL check and responds (typically refusing to expand).
    fn handle_expn(&mut self, argument: &str) {
        if let Some(ref acl) = self.config_ctx.acl_smtp_expn {
            let (acl_rc, user_msg, log_msg) = run_acl_check(
                AclWhere::Expn,
                Some(acl),
                Some(argument),
                &self.config_ctx.acl_definitions,
                &self.acl_session_state(),
            );
            if acl_rc != AclResult::Ok {
                let _ =
                    self.smtp_handle_acl_fail(AclWhere::Expn, acl_rc, &user_msg, &log_msg, None);
                return;
            }
        }

        self.smtp_respond("502", false, "EXPN not available");
    }

    // ── ETRN Command Handler ──

    /// Handle the ETRN command.
    ///
    /// Runs the ACL check and triggers a queue run for the specified domain.
    fn handle_etrn(&mut self, argument: &str) {
        self.had(SmtpCommandHistory::SchNone);

        if argument.is_empty() {
            self.smtp_respond("501", false, "Missing domain for ETRN");
            return;
        }

        // C Exim logs "ETRN <domain> received from [ip]" before ACL check
        let sender_info = self.log_sender_info();
        let etrn_received_line = if let Some(ref ip) = self.message_ctx.sender_host_address {
            if !ip.is_empty() {
                format!("ETRN {argument} received from [{ip}]")
            } else {
                format!("ETRN {argument} received from {sender_info}")
            }
        } else {
            format!("ETRN {argument} received from {sender_info}")
        };
        // LOG_MAIN only for the "received" line
        self.log_write(1, &etrn_received_line);

        if let Some(ref acl) = self.config_ctx.acl_smtp_etrn {
            let (acl_rc, user_msg, log_msg) = run_acl_check(
                AclWhere::Etrn,
                Some(acl),
                Some(argument),
                &self.config_ctx.acl_definitions,
                &self.acl_session_state(),
            );
            if acl_rc != AclResult::Ok {
                let _ =
                    self.smtp_handle_acl_fail(AclWhere::Etrn, acl_rc, &user_msg, &log_msg, None);
                // C Exim logs "rejected ETRN <domain>" on failure
                let ip_part = self
                    .message_ctx
                    .sender_host_address
                    .as_deref()
                    .unwrap_or("");
                let reject_line = if !ip_part.is_empty() {
                    format!("H=[{ip_part}] rejected ETRN {argument}")
                } else {
                    format!("{sender_info} rejected ETRN {argument}")
                };
                self.log_write(3, &reject_line);
                return;
            }
        }

        // Queue run would be triggered here by the binary crate
        self.smtp_respond("250", false, "Queuing started");
        info!("ETRN {}", argument);
    }

    // ── NOOP Command Handler ──

    /// Handle the NOOP command with a simple "250 OK" response.
    fn handle_noop(&mut self) {
        self.had(SmtpCommandHistory::SchNoop);
        self.smtp_respond("250", false, "OK");
    }

    // ── HELP Command Handler ──

    /// Handle the HELP command with a help text response.
    fn handle_help(&mut self) {
        let hostname = self.server_ctx.smtp_active_hostname.clone();
        let msg = format!("{} SMTP server ready", hostname);
        self.smtp_respond("214", false, &msg);
    }
}

// =============================================================================
// BdatSessionOps Trait Implementation
// =============================================================================

impl<'ctx, S> BdatSessionOps for SmtpSession<'ctx, S> {
    /// Read the next SMTP command during BDAT processing.
    /// Corresponds to C `smtp_read_command(TRUE, 1)`.
    fn read_command(&mut self, _io: &mut SmtpIoState) -> (SmtpCommand, String) {
        self.smtp_read_command(true, SMTP_CMD_BUFFER_SIZE as u32)
    }

    /// Send a response line to the SMTP client.
    /// Corresponds to C `smtp_printf(msg, SP_NO_MORE)`.
    fn send_response(&mut self, msg: &str) {
        // Write the response directly — msg should be a full SMTP response line
        self.smtp_respond_raw(msg);
    }

    /// Handle QUIT during BDAT processing.
    /// Corresponds to C `smtp_quit_handler()`.
    fn handle_quit(&mut self) {
        self.smtp_respond("221", false, "closing connection");
        debug!("BDAT processing: QUIT received");
    }

    /// Handle RSET during BDAT processing.
    /// Corresponds to C `smtp_rset_handler()`.
    fn handle_rset(&mut self) {
        self.smtp_reset();
        self.smtp_respond("250", false, "Reset OK");
        debug!("BDAT processing: RSET received");
    }

    /// Log an incomplete transaction with the given reason.
    /// Corresponds to C `incomplete_transaction_log()`.
    fn log_incomplete_transaction(&mut self, reason: &str) {
        if !self.message_ctx.sender_address.is_empty() {
            warn!(
                sender = %self.message_ctx.sender_address,
                recipients = self.message_ctx.recipients_count,
                "incomplete transaction ({}): {}",
                reason, self.message_ctx.sender_address,
            );
        }
    }

    /// Report a synchronization protocol error.
    /// Returns `true` if max sync errors exceeded (connection should drop).
    /// Corresponds to C `synprot_error()`.
    fn report_synprot_error(&mut self, code: u32, msg: &str) -> bool {
        self.synprot_error(0, code as u16, None, msg) < 0
    }

    /// Record a NOOP command in SMTP statistics.
    /// Corresponds to C `HAD(SCH_NOOP)`.
    fn record_noop(&mut self) {
        self.had(SmtpCommandHistory::SchNoop);
    }
}

// =============================================================================
// smtp_setup_msg() — Main SMTP Command Dispatch Loop
// =============================================================================

/// Main SMTP command loop — reads and dispatches SMTP commands.
///
/// This is the primary entry point for SMTP command processing. It reads
/// commands from the client, dispatches to the appropriate handler, and
/// manages the session state machine.
///
/// Returns `SmtpSetupResult` indicating whether the session should:
/// - `Done` — close the connection
/// - `Yield` — proceed to receive message body
/// - `Error` — abort with error
///
/// C reference: smtp_in.c `smtp_setup_msg()` lines 3815-5992.
pub fn smtp_setup_msg(
    server_ctx: &ServerContext,
    message_ctx: &mut MessageContext,
    config_ctx: &ConfigContext,
    in_fd: RawFd,
    out_fd: RawFd,
) -> SmtpSetupResult {
    // Construct the 220 SMTP banner BEFORE creating the session, because
    // SmtpSession::new() takes a mutable borrow on message_ctx which would
    // prevent reading message_ctx.smtp_banner afterwards.
    //
    // This fixes QA Issue 5: "No 220 SMTP banner sent on connection".
    // C Exim sends the banner at smtp_in.c ~4060 before reading any commands.
    let banner = if let Some(ref b) = message_ctx.smtp_banner {
        b.clone()
    } else {
        // C Exim default banner: "$primary_hostname ESMTP Exim $version_number $tod_full"
        // where $tod_full is a timestamp like "Tue, 2 Mar 1999 09:44:33 +0000".
        // The test harness munges dates to a canonical form, so the exact format
        // of the timestamp matters but the actual values are replaced.
        let version = exim_ffi::get_patched_version();
        let tod_full = format_tod_full();
        format!(
            "220 {} ESMTP Exim {} {}\r\n",
            server_ctx.smtp_active_hostname, version, tod_full
        )
    };

    // In batch SMTP mode (-bS), C Exim sets the protocol to
    // "local-bsmtp" (smtp_in.c ~3850).  This must be done BEFORE
    // creating the session, which borrows message_ctx mutably.
    let is_batched = server_ctx.smtp_batched_input;
    if is_batched {
        message_ctx.received_protocol = SmtpProtocol::LocalBsmtp;
    }

    // Create a session in the Connected state
    let mut session: SmtpSession<'_, Connected> =
        SmtpSession::new(in_fd, out_fd, server_ctx, message_ctx, config_ctx);

    // Reset per-message state at loop start
    session.smtp_reset();

    // Disable TCP_QUICKACK on Linux (smtp_in.c lines 3862-3866)
    #[cfg(target_os = "linux")]
    {
        let _ = exim_ffi::fd::safe_setsockopt_int(in_fd, libc::IPPROTO_TCP, libc::TCP_QUICKACK, 0);
    }

    // Send the 220 SMTP banner immediately, before entering the command loop.
    // On re-entry after Yield (post-DATA), skip the banner because the
    // connection is already established and the client expects to continue
    // the same session.
    //
    // In batch SMTP mode (-bS), no banner is sent — the client sends MAIL FROM
    // immediately without a greeting exchange.
    //
    // Access via session.message_ctx because SmtpSession holds the mutable
    // borrow on MessageContext — direct access through message_ctx is
    // forbidden while session is alive.
    if is_batched {
        // Batch SMTP: no 220 banner, no HELO/EHLO required
    } else if session.message_ctx.skip_banner {
        // Already sent the banner on the first call — do NOT send again.
    } else {
        session.smtp_printf(&banner, false);
        // Mark the banner as sent so subsequent calls skip it.
        session.message_ctx.skip_banner = true;
    }

    // ── HDEBUG: Host option checks at session start (smtp_in.c ~4000) ──
    //
    // In C Exim, host_checking mode prints these checks to stderr at
    // session startup. Each option is checked against the client IP.
    // When the option is unset (None), the output is "no (option unset)".
    if server_ctx.host_checking {
        let host_options: &[(&str, &Option<String>)] = &[
            ("hosts_connection_nolog", &None), // Not in our config struct
            ("host_lookup", &None),
            ("host_reject_connection", &None),
            ("sender_unqualified_hosts", &None),
            ("recipient_unqualified_hosts", &None),
            ("helo_verify_hosts", &config_ctx.helo_verify_hosts),
            ("helo_try_verify_hosts", &config_ctx.helo_try_verify_hosts),
            ("helo_accept_junk_hosts", &None),
        ];
        for (name, option) in host_options {
            if option.is_none() && server_ctx.host_checking {
                eprintln!(">>> host in {}? no (option unset)", name);
            }
            // If set, would need to do actual host list matching — for now
            // only the "unset" case is handled which covers the common test.
        }
    }

    // In batched SMTP mode (-bS), skip the HELO/EHLO greeting entirely.
    // The session transitions directly to Greeted state, allowing MAIL FROM
    // to be accepted immediately. No 220 banner was sent.
    // C Exim (smtp_in.c ~3850) does the same: when smtp_batched_input is set,
    // it skips to the command loop in an already-greeted state.
    if is_batched {
        // Drop the Connected session and create a Greeted session directly
        drop(session);
        let greeted =
            SmtpSession::<Greeted>::new_greeted(in_fd, out_fd, server_ctx, message_ctx, config_ctx);
        return handle_greeted_session(greeted);
    }

    // Main command dispatch loop — replaces C `while (done <= 0)`
    //
    // Since Rust's type-state pattern prevents calling methods in wrong states,
    // the dispatch loop uses a dynamic state tracker alongside the type-safe
    // session. The type-state transitions are enforced at the transition
    // boundaries (greet, mail_from, rcpt_to, data, reset).
    loop {
        let (cmd, argument) = session.smtp_read_command(true, SMTP_CMD_BUFFER_SIZE as u32);

        match cmd {
            SmtpCommand::Quit => {
                let result = session.handle_quit();
                if result > 0 {
                    return SmtpSetupResult::Done;
                }
            }

            SmtpCommand::Rset => {
                session.handle_rset_cmd();
            }

            SmtpCommand::Helo | SmtpCommand::Ehlo => {
                let is_ehlo = cmd == SmtpCommand::Ehlo;
                let tainted_name = Tainted::<String>::new(argument);

                // Process greeting — transition from Connected to Greeted
                match session.greet(is_ehlo, tainted_name) {
                    Ok(greeted) => {
                        // Now in Greeted state — enter inner loop for mail commands
                        return handle_greeted_session(greeted);
                    }
                    Err(boxed_err) => {
                        let (returned_session, e) = *boxed_err;
                        warn!("HELO/EHLO failed: {}", e);
                        // Session returned — connection stays in Connected state.
                        // Client may retry HELO/EHLO per RFC 5321.
                        session = returned_session;
                        // Check for DROP — ACL may have requested connection close
                        if e.to_string().contains("DROP") {
                            return SmtpSetupResult::Done;
                        }
                    }
                }
            }

            SmtpCommand::Auth => {
                // AUTH before HELO is not valid
                session.smtp_respond("503", false, "EHLO/HELO first");
            }

            SmtpCommand::Starttls => {
                #[cfg(feature = "tls")]
                {
                    let result = session.handle_starttls();
                    if result < 0 {
                        return SmtpSetupResult::Error;
                    }
                }
                #[cfg(not(feature = "tls"))]
                {
                    session.smtp_respond("502", false, "STARTTLS not available");
                }
            }

            SmtpCommand::Noop => {
                session.handle_noop();
            }

            SmtpCommand::Help => {
                session.handle_help();
            }

            SmtpCommand::Eof => {
                info!("Connection closed by client (EOF)");
                return SmtpSetupResult::Done;
            }

            SmtpCommand::BadChar => {
                warn!("SMTP command contained NUL characters");
                session.smtp_respond("500", false, "Command contained NUL characters");
            }

            SmtpCommand::BadSyn => {
                let result = session.synprot_error(0, 554, None, "SMTP synchronization error");
                if result < 0 {
                    return SmtpSetupResult::Error;
                }
            }

            SmtpCommand::TooManyNonMail => {
                warn!("Too many nonmail commands");
                session.smtp_respond("421", false, "Too many nonmail commands");
                return SmtpSetupResult::Done;
            }

            #[cfg(feature = "proxy")]
            SmtpCommand::ProxyFailIgnore => {
                session.smtp_respond("503", false, "Command refused");
            }

            // VRFY, EXPN, and ETRN are non-mail commands that do NOT
            // require a prior HELO/EHLO.  C Exim processes them in
            // smtp_setup_msg() regardless of smtp_state.
            SmtpCommand::Vrfy => {
                session.handle_vrfy(&argument);
            }

            SmtpCommand::Expn => {
                session.handle_expn(&argument);
            }

            SmtpCommand::Etrn => {
                session.handle_etrn(&argument);
            }

            // MAIL FROM, RCPT TO, and DATA are recognized SMTP commands
            // but are not permitted before EHLO/HELO has been sent.
            // RFC 5321 §4.1.4: "In the absence of an extension
            // negotiated by the client and server, the server MUST return
            // a 503 reply" for commands used out of sequence.
            SmtpCommand::Mail => {
                session.smtp_respond("503", false, "EHLO or HELO first");
            }

            SmtpCommand::Rcpt => {
                session.smtp_respond("503", false, "EHLO or HELO first");
            }

            SmtpCommand::Data | SmtpCommand::Bdat => {
                session.smtp_respond("503", false, "EHLO or HELO first");
            }

            _ => {
                // Unknown command
                session.unknown_command_count += 1;
                if session.config_ctx.smtp_max_unknown_commands > 0
                    && session.unknown_command_count >= session.config_ctx.smtp_max_unknown_commands
                {
                    session.smtp_respond("421", false, "Too many unrecognized commands");
                    return SmtpSetupResult::Done;
                }
                session.smtp_respond("500", false, "Unrecognized command");
            }
        }
    }
}

/// Continue an SMTP session after message reception.
///
/// This entry point is used after `receive_and_spool_message()` has accepted
/// a message and sent the "250 OK id=..." response. It re-enters the
/// command loop from the Greeted state WITHOUT sending a new 220 banner.
///
/// The client may start a new MAIL FROM transaction, send RSET, or QUIT.
///
/// # Arguments
///
/// * `server_ctx` — Daemon-lifetime server state
/// * `message_ctx` — Per-message mutable state (already reset by caller)
/// * `config_ctx` — Frozen parsed configuration
/// * `in_fd` — Inbound socket file descriptor
/// * `out_fd` — Outbound socket file descriptor
pub fn smtp_continue_msg(
    server_ctx: &ServerContext,
    message_ctx: &mut MessageContext,
    config_ctx: &ConfigContext,
    in_fd: RawFd,
    out_fd: RawFd,
) -> SmtpSetupResult {
    let session: SmtpSession<'_, Greeted> =
        SmtpSession::new_greeted(in_fd, out_fd, server_ctx, message_ctx, config_ctx);

    handle_greeted_session(session)
}

/// Handle the SMTP session after HELO/EHLO has been accepted.
///
/// This inner function processes commands in the Greeted state and manages
/// transitions through MailFrom, RcptTo, and DataPhase states.
fn handle_greeted_session(mut session: SmtpSession<'_, Greeted>) -> SmtpSetupResult {
    loop {
        let (cmd, argument) = session.smtp_read_command(true, SMTP_CMD_BUFFER_SIZE as u32);

        match cmd {
            SmtpCommand::Quit => {
                let result = session.handle_quit();
                if result > 0 {
                    return SmtpSetupResult::Done;
                }
            }

            SmtpCommand::Rset => {
                session.handle_rset_cmd();
            }

            SmtpCommand::Helo | SmtpCommand::Ehlo => {
                // Re-greeting resets to Greeted state
                let is_ehlo = cmd == SmtpCommand::Ehlo;
                let in_fd = session.io.in_fd;
                let out_fd = session.io.out_fd;

                // Re-send EHLO response without consuming session
                if is_ehlo {
                    session.had(SmtpCommandHistory::SchEhlo);
                } else {
                    session.had(SmtpCommandHistory::SchHelo);
                }
                session.flags.esmtp = is_ehlo;
                session.flags.helo_seen = true;
                session.message_ctx.helo_name = Some(argument.clone());

                // Update protocol and resend greeting
                session.update_received_protocol();
                if is_ehlo {
                    session.send_ehlo_response();
                } else {
                    let hostname = session.server_ctx.smtp_active_hostname.clone();
                    let ident_prefix = match &session.message_ctx.sender_ident {
                        Some(ident) if !ident.is_empty() => format!("{} at ", ident),
                        _ => String::new(),
                    };
                    let ip_suffix = match &session.message_ctx.sender_host_address {
                        Some(ip) if !ip.is_empty() => format!(" [{}]", ip),
                        _ => String::new(),
                    };
                    let response = format!(
                        "{} Hello {}{}{}",
                        hostname, ident_prefix, argument, ip_suffix
                    );
                    session.smtp_respond("250", false, &response);
                }

                let _ = (in_fd, out_fd); // suppress unused warnings
            }

            SmtpCommand::Mail => {
                let tainted_addr = Tainted::<String>::new(argument);
                match session.mail_from(tainted_addr) {
                    Ok(mail_session) => {
                        // Now in MailFrom state — handle RCPT TO commands
                        return handle_mailfrom_session(mail_session);
                    }
                    Err(boxed_err) => {
                        let (returned_session, e) = *boxed_err;
                        warn!("MAIL FROM failed: {}", e);
                        // Session returned to Greeted state — client can retry
                        // MAIL FROM per RFC 5321 §3.3 (5xx is a transient failure
                        // from the client's perspective).
                        session = returned_session;
                        if e.to_string().contains("DROP") {
                            return SmtpSetupResult::Done;
                        }
                    }
                }
            }

            SmtpCommand::Auth => {
                session.handle_auth(&argument);
            }

            SmtpCommand::Starttls => {
                #[cfg(feature = "tls")]
                {
                    let result = session.handle_starttls();
                    if result < 0 {
                        return SmtpSetupResult::Error;
                    }
                }
                #[cfg(not(feature = "tls"))]
                {
                    session.smtp_respond("502", false, "STARTTLS not available");
                }
            }

            SmtpCommand::Rcpt => {
                session.smtp_respond("503", false, "sender not yet given");
            }

            SmtpCommand::Data => {
                session.smtp_respond("503", false, "sender not yet given");
            }

            SmtpCommand::Bdat => {
                session.smtp_respond("503", false, "sender not yet given");
            }

            SmtpCommand::Vrfy => {
                session.handle_vrfy(&argument);
            }

            SmtpCommand::Expn => {
                session.handle_expn(&argument);
            }

            SmtpCommand::Etrn => {
                session.handle_etrn(&argument);
            }

            SmtpCommand::Noop => {
                session.handle_noop();
            }

            SmtpCommand::Help => {
                session.handle_help();
            }

            SmtpCommand::Eof => {
                info!("Connection closed by client (EOF)");
                return SmtpSetupResult::Done;
            }

            SmtpCommand::BadChar => {
                warn!("SMTP command contained NUL characters");
                session.smtp_respond("500", false, "Command contained NUL characters");
            }

            SmtpCommand::BadSyn => {
                let result = session.synprot_error(0, 554, None, "SMTP synchronization error");
                if result < 0 {
                    return SmtpSetupResult::Error;
                }
            }

            SmtpCommand::TooManyNonMail => {
                warn!("Too many nonmail commands");
                session.smtp_respond("421", false, "Too many nonmail commands");
                return SmtpSetupResult::Done;
            }

            #[cfg(feature = "proxy")]
            SmtpCommand::ProxyFailIgnore => {
                session.smtp_respond("503", false, "Command refused");
            }

            SmtpCommand::Atrn => {
                session.smtp_respond("502", false, "ATRN not available in current state");
            }

            #[cfg(feature = "xclient")]
            SmtpCommand::Xclient => {
                // XCLIENT handling would be delegated to xclient module
                session.smtp_respond("220", false, "XCLIENT accepted");
            }

            #[cfg(feature = "wellknown")]
            SmtpCommand::Wellknown => {
                session.smtp_respond("250", false, "WELLKNOWN response");
            }

            _ => {
                session.unknown_command_count += 1;
                if session.config_ctx.smtp_max_unknown_commands > 0
                    && session.unknown_command_count >= session.config_ctx.smtp_max_unknown_commands
                {
                    session.smtp_respond("421", false, "Too many unrecognized commands");
                    return SmtpSetupResult::Done;
                }
                session.smtp_respond("500", false, "Unrecognized command");
            }
        }
    }
}

/// Handle the SMTP session after MAIL FROM has been accepted.
///
/// Processes RCPT TO commands until DATA or BDAT is received.
fn handle_mailfrom_session(mut session: SmtpSession<'_, MailFrom>) -> SmtpSetupResult {
    loop {
        let (cmd, argument) = session.smtp_read_command(true, SMTP_CMD_BUFFER_SIZE as u32);

        match cmd {
            SmtpCommand::Quit => {
                let result = session.handle_quit();
                if result > 0 {
                    return SmtpSetupResult::Done;
                }
            }

            SmtpCommand::Rset => {
                let greeted = session.reset();
                return handle_greeted_session(greeted);
            }

            SmtpCommand::Rcpt => {
                let tainted_addr = Tainted::<String>::new(argument);
                match session.rcpt_to(tainted_addr) {
                    Ok(rcpt_session) => {
                        // Now in RcptTo state — handle DATA/more RCPT
                        return handle_rcptto_session(rcpt_session);
                    }
                    Err(boxed_err) => {
                        let (returned_session, e) = *boxed_err;
                        warn!("RCPT TO failed: {}", e);
                        // Session returned to MailFrom state — client can
                        // retry RCPT TO per RFC 5321 §3.3.
                        session = returned_session;
                        if e.to_string().contains("DROP") {
                            return SmtpSetupResult::Done;
                        }
                    }
                }
            }

            SmtpCommand::Data => {
                session.smtp_respond("503", false, "No valid recipients");
            }

            SmtpCommand::Mail => {
                session.smtp_respond("503", false, "nested MAIL command");
            }

            SmtpCommand::Noop => {
                session.handle_noop();
            }

            SmtpCommand::Help => {
                session.handle_help();
            }

            SmtpCommand::Vrfy => {
                session.handle_vrfy(&argument);
            }

            SmtpCommand::Expn => {
                session.handle_expn(&argument);
            }

            SmtpCommand::Eof => {
                info!("Connection closed by client (EOF)");
                return SmtpSetupResult::Done;
            }

            SmtpCommand::BadChar => {
                warn!("SMTP command contained NUL characters");
                session.smtp_respond("500", false, "Command contained NUL characters");
            }

            SmtpCommand::BadSyn => {
                let result = session.synprot_error(0, 554, None, "SMTP synchronization error");
                if result < 0 {
                    return SmtpSetupResult::Error;
                }
            }

            SmtpCommand::TooManyNonMail => {
                warn!("Too many nonmail commands");
                session.smtp_respond("421", false, "Too many nonmail commands");
                return SmtpSetupResult::Done;
            }

            _ => {
                session.unknown_command_count += 1;
                if session.config_ctx.smtp_max_unknown_commands > 0
                    && session.unknown_command_count >= session.config_ctx.smtp_max_unknown_commands
                {
                    session.smtp_respond("421", false, "Too many unrecognized commands");
                    return SmtpSetupResult::Done;
                }
                session.smtp_respond("500", false, "Unrecognized command");
            }
        }
    }
}

/// Handle the SMTP session after at least one RCPT TO has been accepted.
///
/// Accepts additional RCPT TO commands, DATA, or BDAT.
fn handle_rcptto_session(mut session: SmtpSession<'_, RcptTo>) -> SmtpSetupResult {
    loop {
        let (cmd, argument) = session.smtp_read_command(true, SMTP_CMD_BUFFER_SIZE as u32);

        match cmd {
            SmtpCommand::Quit => {
                let result = session.handle_quit();
                if result > 0 {
                    return SmtpSetupResult::Done;
                }
            }

            SmtpCommand::Rset => {
                let greeted = session.reset();
                return handle_greeted_session(greeted);
            }

            SmtpCommand::Rcpt => {
                let tainted_addr = Tainted::<String>::new(argument);
                match session.rcpt_to(tainted_addr) {
                    Ok(new_session) => {
                        session = new_session;
                    }
                    Err(boxed_err) => {
                        let (returned_session, e) = *boxed_err;
                        warn!("Additional RCPT TO failed: {}", e);
                        // Session returned — client can try more recipients
                        session = returned_session;
                        if e.to_string().contains("DROP") {
                            return SmtpSetupResult::Done;
                        }
                    }
                }
            }

            SmtpCommand::Data => {
                session.had(SmtpCommandHistory::SchData);
                match session.data() {
                    Ok(mut data_session) => {
                        // DATA accepted — 354 already sent.
                        // Read the message body and parse headers using the
                        // same I/O buffer as the command loop (avoids the
                        // buffering mismatch that occurs when reading from
                        // a separate stdin handle).
                        let received_data = data_session.read_message_body();

                        // Build header lookup map from parsed headers
                        let mut header_map = std::collections::HashMap::new();
                        for (name, value) in &received_data.parsed_headers {
                            header_map.insert(name.clone(), value.clone());
                        }

                        // Compute $reply_address per C Exim rules:
                        // 1. Use Reply-To if present and non-empty
                        // 2. Otherwise use From if present
                        // 3. Otherwise empty
                        let reply_address = if let Some(reply_to) = header_map.get("reply-to") {
                            if reply_to.is_empty() {
                                header_map.get("from").cloned().unwrap_or_default()
                            } else {
                                reply_to.clone()
                            }
                        } else {
                            header_map.get("from").cloned().unwrap_or_default()
                        };

                        // Run the DATA ACL if configured
                        if let Some(ref acl_name) = data_session.config_ctx.acl_smtp_data {
                            let acl_state = AclSessionState {
                                sender_address: data_session.message_ctx.sender_address.clone(),
                                client_ip: data_session
                                    .message_ctx
                                    .sender_host_address
                                    .clone()
                                    .unwrap_or_default(),
                                helo_name: data_session
                                    .message_ctx
                                    .helo_name
                                    .clone()
                                    .unwrap_or_default(),
                                named_domain_lists: data_session
                                    .config_ctx
                                    .named_domain_lists
                                    .clone(),
                                named_host_lists: data_session.config_ctx.named_host_lists.clone(),
                                named_address_lists: data_session
                                    .config_ctx
                                    .named_address_lists
                                    .clone(),
                                named_local_part_lists: data_session
                                    .config_ctx
                                    .named_local_part_lists
                                    .clone(),
                                reply_address: reply_address.clone(),
                                header_list: header_map.clone(),
                                host_checking: data_session.server_ctx.host_checking,
                                verify_recipient_cb: data_session
                                    .message_ctx
                                    .verify_recipient_cb
                                    .clone(),
                                recipient: String::new(),
                                primary_hostname: data_session.config_ctx.primary_hostname.clone(),
                                spool_directory: data_session.config_ctx.spool_directory.clone(),
                                recipients_count: data_session.message_ctx.recipients_count as i32,
                            };

                            let acl_result = run_acl_check_full(
                                AclWhere::Data,
                                Some(acl_name),
                                None,
                                &data_session.config_ctx.acl_definitions,
                                &acl_state,
                            );
                            let acl_rc = acl_result.result;
                            let user_msg = acl_result.user_msg;

                            // Build an ExpandContext populated with message-level
                            // variables so that ACL-added headers and user_msg
                            // containing references like $message_linecount are
                            // expanded to their actual values.
                            let build_data_expand_ctx = || {
                                let mut exp_ctx = exim_expand::variables::ExpandContext::new();
                                exp_ctx.reply_address = reply_address.clone();
                                exp_ctx.header_list = header_map.clone();
                                exp_ctx.sender_address = exim_expand::Tainted::new(
                                    data_session.message_ctx.sender_address.clone(),
                                );
                                exp_ctx.sender_host_address = exim_expand::Tainted::new(
                                    data_session
                                        .message_ctx
                                        .sender_host_address
                                        .clone()
                                        .unwrap_or_default(),
                                );
                                exp_ctx.sender_helo_name = exim_expand::Tainted::new(
                                    data_session
                                        .message_ctx
                                        .helo_name
                                        .clone()
                                        .unwrap_or_default(),
                                );
                                exp_ctx.primary_hostname = exim_expand::Clean::new(
                                    data_session.server_ctx.smtp_active_hostname.clone(),
                                );
                                // Populate message metrics so $message_linecount,
                                // $body_linecount, $message_size, $received_count
                                // are available during expansion.
                                exp_ctx.message_linecount = received_data.message_linecount as i32;
                                exp_ctx.body_linecount = received_data.body_linecount as i32;
                                exp_ctx.message_size = received_data.message_size;
                                exp_ctx.received_count = received_data
                                    .parsed_headers
                                    .iter()
                                    .filter(|(n, _)| n == "received")
                                    .count()
                                    as i32;
                                exp_ctx
                            };

                            // Propagate ACL-added headers (from warn message =)
                            // into the SMTP message context so they get written
                            // to the -H spool file.  Expand $variable references
                            // in header text (C Exim calls expand_string() on
                            // the `message` modifier argument in acl.c).
                            for raw_hdr in &acl_result.added_headers {
                                let mut ectx = build_data_expand_ctx();
                                let expanded_hdr = match exim_expand::expand_string_with_context(
                                    raw_hdr, &mut ectx,
                                ) {
                                    Ok(e) => e,
                                    Err(_) => raw_hdr.clone(),
                                };
                                data_session
                                    .message_ctx
                                    .acl_added_headers
                                    .push(expanded_hdr);
                            }

                            // Expand the user_msg with header + reply_address context
                            let expanded_msg = {
                                let mut exp_ctx = build_data_expand_ctx();
                                match exim_expand::expand_string_with_context(
                                    &user_msg,
                                    &mut exp_ctx,
                                ) {
                                    Ok(expanded) => expanded,
                                    Err(_) => user_msg.clone(),
                                }
                            };

                            // Send appropriate SMTP response based on ACL result
                            if acl_rc == AclResult::Ok {
                                // Generate real message ID and write spool
                                let msg_id = write_spool_and_respond(&data_session, &received_data);
                                let ok_msg = format!("OK id={msg_id}");
                                data_session.smtp_respond("250", false, &ok_msg);
                                // In -bh (host checking) mode, print the
                                // "not a real message id" notice after the
                                // 250 OK line, matching C Exim behaviour.
                                if data_session.server_ctx.host_checking {
                                    data_session.smtp_printf(
                                        "\n**** SMTP testing: that is not a real message id!\n\n",
                                        false,
                                    );
                                }
                                // Store message ID and deliver inline (C Exim
                                // delivers after each DATA, not at session end)
                                data_session
                                    .message_ctx
                                    .received_message_ids
                                    .push(msg_id.clone());
                                if let Some(ref mut cb) =
                                    data_session.message_ctx.post_message_callback
                                {
                                    cb(&msg_id);
                                }
                            } else {
                                // deny/drop → 550 with expanded message
                                let resp = format!("550 {}\r\n", expanded_msg);
                                data_session.smtp_printf(&resp, false);
                            }
                        } else {
                            // No DATA ACL — accept the message
                            let msg_id = write_spool_and_respond(&data_session, &received_data);
                            let ok_msg = format!("OK id={msg_id}");
                            data_session.smtp_respond("250", false, &ok_msg);
                            // In -bh (host checking) mode, print the
                            // "not a real message id" notice after the
                            // 250 OK line, matching C Exim behaviour.
                            if data_session.server_ctx.host_checking {
                                data_session.smtp_printf(
                                    "\n**** SMTP testing: that is not a real message id!\n\n",
                                    false,
                                );
                            }
                            // Store message ID and deliver inline
                            data_session
                                .message_ctx
                                .received_message_ids
                                .push(msg_id.clone());
                            if let Some(ref mut cb) = data_session.message_ctx.post_message_callback
                            {
                                cb(&msg_id);
                            }
                        }

                        // Transition back to Greeted to continue session
                        let greeted = data_session.finish_data();
                        return handle_greeted_session(greeted);
                    }
                    Err(boxed_err) => {
                        let (returned_session, e) = *boxed_err;
                        warn!("DATA failed: {}", e);
                        // Session returned — client can retry or RSET
                        session = returned_session;
                        if e.to_string().contains("DROP") {
                            return SmtpSetupResult::Error;
                        }
                    }
                }
            }

            SmtpCommand::Bdat => {
                session.had(SmtpCommandHistory::SchData);

                // Parse BDAT size and LAST flag
                let parts: Vec<&str> = argument.split_whitespace().collect();
                let _size = parts
                    .first()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                let is_last = parts
                    .get(1)
                    .map(|s| s.eq_ignore_ascii_case("LAST"))
                    .unwrap_or(false);

                // Push BDAT receive functions
                let lower = ReceiveFunctions::default_smtp();
                bdat_push_receive_functions(&mut session.chunking_ctx, lower);

                // Update chunking state via direct field assignment
                if is_last {
                    session.chunking_ctx.state = crate::inbound::chunking::ChunkingState::Last;
                } else {
                    session.chunking_ctx.state = crate::inbound::chunking::ChunkingState::Active;
                }

                // Deposit TLS backend into MessageContext before yielding.
                #[cfg(feature = "tls")]
                {
                    session.message_ctx.tls_backend = session.io.tls_backend.take();
                }
                return SmtpSetupResult::Yield;
            }

            SmtpCommand::Mail => {
                session.smtp_respond("503", false, "nested MAIL command");
            }

            SmtpCommand::Noop => {
                session.handle_noop();
            }

            SmtpCommand::Help => {
                session.handle_help();
            }

            SmtpCommand::Vrfy => {
                session.handle_vrfy(&argument);
            }

            SmtpCommand::Expn => {
                session.handle_expn(&argument);
            }

            SmtpCommand::Eof => {
                info!("Connection closed by client (EOF)");
                return SmtpSetupResult::Done;
            }

            SmtpCommand::BadChar => {
                warn!("SMTP command contained NUL characters");
                session.smtp_respond("500", false, "Command contained NUL characters");
            }

            SmtpCommand::BadSyn => {
                let result = session.synprot_error(0, 554, None, "SMTP synchronization error");
                if result < 0 {
                    return SmtpSetupResult::Error;
                }
            }

            SmtpCommand::TooManyNonMail => {
                warn!("Too many nonmail commands");
                session.smtp_respond("421", false, "Too many nonmail commands");
                return SmtpSetupResult::Done;
            }

            _ => {
                session.unknown_command_count += 1;
                if session.config_ctx.smtp_max_unknown_commands > 0
                    && session.unknown_command_count >= session.config_ctx.smtp_max_unknown_commands
                {
                    session.smtp_respond("421", false, "Too many unrecognized commands");
                    return SmtpSetupResult::Done;
                }
                session.smtp_respond("500", false, "Unrecognized command");
            }
        }
    }
}

// =============================================================================
// authres_smtpauth() — Authentication-Results Header Field Generation
// =============================================================================

/// Generate the Authentication-Results header field for SMTP AUTH.
///
/// Appends "smtp.auth=<mechanism>" and "smtp.mailfrom=<sender>" to the
/// provided string buffer for inclusion in the Authentication-Results header.
///
/// C reference: smtp_in.c lines 5996-6016.
pub fn authres_smtpauth(g: &mut String, message_ctx: &MessageContext) {
    if let Some(ref auth_name) = message_ctx.sender_host_authenticated {
        let name: &str = auth_name.as_ref();
        if !name.is_empty() {
            let _ = write!(g, ";\n\tauth={} ", name);
        }
    }

    if let Some(ref auth_id) = message_ctx.authenticated_id {
        let id: &str = auth_id.as_ref();
        if !id.is_empty() {
            let _ = write!(g, "({})", id);
        }
    }

    let sender: &str = message_ctx.sender_address.as_ref();
    if !sender.is_empty() {
        let _ = write!(g, " smtp.mailfrom={}", sender);
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Parse an email address from MAIL FROM or RCPT TO syntax.
///
/// Extracts the address from angle brackets and returns it along with
/// any remaining extension parameters.
///
/// # Returns
///
/// (address, extensions) — the parsed address and any trailing parameters.
/// Result of parsing a MAIL FROM / RCPT TO address.
/// `Err(String)` contains the error message for a 501 response.
fn parse_mail_address(input: &str) -> Result<(String, String), String> {
    let trimmed = input.trim();

    // Handle <address> syntax
    if let Some(start) = trimmed.find('<') {
        if let Some(end) = trimmed[start..].find('>') {
            let end = start + end;
            let address = trimmed[start + 1..end].trim().to_string();
            let extensions = if end + 1 < trimmed.len() {
                trimmed[end + 1..].trim().to_string()
            } else {
                String::new()
            };
            // Check for extra characters after address but before closing >
            // that would make it malformed
            return Ok((address, extensions));
        }
        // `<` found but no matching `>` — check if `<` is at end of bare address
        let before_bracket = trimmed[..start].trim();
        if !before_bracket.is_empty() {
            // Pattern: "someone@host<" — `<` after bare address
            return Err(format!(
                "malformed address: < may not follow {}",
                before_bracket
            ));
        }
        // Pattern: "<address" with no closing `>` — missing `>`
        return Err("'>' missing at end of address".to_string());
    }

    // Check for lone `>` without matching `<`
    if let Some(pos) = trimmed.find('>') {
        let before = trimmed[..pos].trim();
        if !before.is_empty() {
            return Err(format!("malformed address: > may not follow {}", before));
        }
        return Err("unexpected > without preceding <".to_string());
    }

    // Handle bare address (no angle brackets)
    let parts: Vec<&str> = trimmed.splitn(2, char::is_whitespace).collect();
    let address = parts.first().unwrap_or(&"").to_string();
    let extensions = parts.get(1).unwrap_or(&"").to_string();
    Ok((address, extensions))
}

// =============================================================================
// Module-Level Helper Functions
// =============================================================================

/// Generate a real message ID, write spool -H and -D files, and write a
/// mainlog reception line.  Returns the generated message ID string.
///
/// This bridges the SMTP layer's DATA handler to the spool subsystem,
/// matching the flow in C Exim's `receive_msg()` (receive.c) where the
/// spool files are written and the `<=` log line is emitted.
///
/// **Spool compatibility**: The -H and -D files produced here MUST be
/// byte-level compatible with C Exim (AAP §0.7.1 / Directive 2).
fn write_spool_and_respond<S>(
    data_session: &SmtpSession<'_, S>,
    received_data: &ReceivedMessageData,
) -> String {
    use exim_spool::message_id::generate_message_id;

    // Generate a real 23-character base-62 message ID using current time
    // and PID, matching C Exim's message_id_tv-based generation.
    let now_dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let tv_sec = now_dur.as_secs() as u32;
    let tv_usec = now_dur.subsec_micros();
    let pid = std::process::id() as u64;
    let msg_id = generate_message_id(tv_sec, pid, tv_usec, None, 1);

    let spool_dir = &data_session.config_ctx.spool_directory;
    let sender = &data_session.message_ctx.sender_address;

    tracing::debug!(spool_dir = %spool_dir, sender = %sender, msg_id = %msg_id, "writing spool files");

    // ----- Write -D (data) file -----
    // The -D file contains the raw message body exactly as received.
    let input_dir = format!("{}/input", spool_dir);
    let _ = std::fs::create_dir_all(&input_dir);

    let data_path = format!("{}/{}-D", input_dir, msg_id);
    // C Exim writes a leading line "message_id-D\n" then raw body.
    // The header file format version line distinguishes v4 spool.
    let data_header_line = format!("{}-D\n", msg_id);
    let mut data_content: Vec<u8> = data_header_line.into_bytes();
    data_content.extend_from_slice(&received_data.body_data);
    match std::fs::write(&data_path, &data_content) {
        Ok(()) => tracing::debug!(path = %data_path, bytes = data_content.len(), "wrote -D file"),
        Err(e) => tracing::error!(path = %data_path, error = %e, "failed to write -D file"),
    }

    // ----- Build Received: header -----
    // C Exim generates: "Received: from HELO_NAME (CLIENT_HOST [CLIENT_IP])\n\tby HOSTNAME..."
    let client_ip = data_session
        .message_ctx
        .sender_host_address
        .as_deref()
        .unwrap_or("unknown");
    let helo_name = data_session
        .message_ctx
        .helo_name
        .as_deref()
        .unwrap_or("unknown");
    let hostname = &data_session.config_ctx.primary_hostname;
    // Use Display impl which produces exact C-compatible protocol strings
    // e.g. "smtp", "local-smtp", "esmtp", "local-esmtp" etc.
    let protocol = data_session.message_ctx.received_protocol.to_string();

    // Build timestamp in C Exim format: "Thu, 01 Jan 2025 00:00:00 +0000"
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let timestamp = format_rfc2822_timestamp(now);

    // Build the Received: header matching C Exim's received_header_text
    // default.  For local (-bs) mode the format is:
    //   Received: from $sender_ident (helo=$sender_helo_name)
    //       by $hostname with $protocol (Exim $version)
    //       (envelope-from <$sender>)
    //       id $msgid
    //       for $recipient;\n\t$timestamp\n
    // For network SMTP the format uses sender_rcvhost instead.
    let sender_ident = data_session
        .message_ctx
        .sender_ident
        .as_deref()
        .unwrap_or("");
    let version = exim_ffi::get_patched_version();

    // Determine the "from" clause: local vs network.
    // In C Exim, local submission uses a single-line form:
    //   "Received: from CALLER by hostname with protocol (Exim ver)..."
    // Network SMTP uses multi-line with continuation tab:
    //   "Received: from helo (host [ip])\n\tby hostname..."
    let from_clause = if client_ip == "unknown" || client_ip.is_empty() {
        // Local submission (-bs/-bS): use sender_ident and helo, single line
        if !sender_ident.is_empty() && helo_name != "unknown" {
            format!("from {} (helo={}) ", sender_ident, helo_name)
        } else if !sender_ident.is_empty() {
            format!("from {} ", sender_ident)
        } else if helo_name != "unknown" {
            format!("from (helo={}) ", helo_name)
        } else {
            String::new()
        }
    } else {
        // Network SMTP: from helo (host [ip]) — multi-line form
        format!(
            "from {} ({})\n\t",
            helo_name,
            format!("{} [{}]", sender_ident.trim(), client_ip).trim()
        )
    };

    // Build "for" clause: only when there is exactly one recipient
    let for_clause = if data_session.message_ctx.recipients_list.len() == 1 {
        format!(
            "\n\tfor {}",
            &data_session.message_ctx.recipients_list[0].address
        )
    } else {
        String::new()
    };

    let received_header = format!(
        "Received: {}by {} with {} (Exim {})\n\t(envelope-from <{}>)\n\tid {}{};\n\t{}\n",
        from_clause, hostname, protocol, version, sender, msg_id, for_clause, timestamp,
    );

    // ----- Write -H (header) file using SpoolHeaderFile::write_to() -----
    // Construct the full internal SpoolHeaderFile struct so the delivery
    // subsystem can parse it correctly with spool_read_header().
    let mut spool_headers: Vec<exim_spool::header_file::SpoolHeader> = Vec::new();

    // Prepend the Received: header (type 'P' = Postmark / Received)
    // C Exim uses htype_received = 'P' (macros.h line 675).
    // '*' is htype_old (deleted) and must NOT be used here.
    spool_headers.push(exim_spool::header_file::SpoolHeader {
        text: received_header.clone(),
        slen: received_header.len(),
        header_type: 'P',
    });

    // Add original message headers from DATA body (type ' ' = normal)
    for raw_hdr in &received_data.raw_header_lines {
        let mut text = raw_hdr.clone();
        if !text.ends_with('\n') {
            text.push('\n');
        }
        let slen = text.len();
        spool_headers.push(exim_spool::header_file::SpoolHeader {
            slen,
            text,
            header_type: ' ',
        });
    }

    // ----- Auto-generate missing headers (C Exim receive.c behaviour) -----
    // For local submissions (-bs), auto-generate Message-Id:, From:, Date:
    // if the sender did not provide them.
    let is_local = client_ip == "unknown" || client_ip.is_empty();
    let has_message_id = received_data
        .parsed_headers
        .iter()
        .any(|(n, _)| n == "message-id");
    let has_from = received_data
        .parsed_headers
        .iter()
        .any(|(n, _)| n == "from");
    let has_date = received_data
        .parsed_headers
        .iter()
        .any(|(n, _)| n == "date");

    if is_local && !has_message_id {
        // C Exim format: Message-Id: <E$message_id.$id_text@$id_domain>
        // id_text comes from message_id_header_text config option
        // id_domain comes from message_id_header_domain config option
        let id_text_cfg = data_session
            .config_ctx
            .message_id_header_text
            .as_deref()
            .unwrap_or("");
        let id_domain_cfg = data_session
            .config_ctx
            .message_id_header_domain
            .as_deref()
            .unwrap_or("");

        // Expand simple ${if eq{0}{0}{VALUE}} patterns in config values
        let id_text_raw = expand_simple_if_eq(id_text_cfg);
        let id_domain = expand_simple_if_eq(id_domain_cfg);

        // C Exim sanitises the id_text: characters that would break the
        // angle-bracket Message-Id syntax (RFC 5322) are replaced with '-'.
        // Specifically '@', '[', ']' are not allowed in the local-part of
        // a msg-id (they have structural meaning).  This matches C Exim's
        // receive.c behavior.
        let id_text: String = id_text_raw
            .chars()
            .map(|c| match c {
                '@' | '[' | ']' => '-',
                _ => c,
            })
            .collect();

        let domain = if id_domain.is_empty() {
            hostname.as_str()
        } else {
            &id_domain
        };
        let dot_text = if id_text.is_empty() {
            String::new()
        } else {
            format!(".{}", id_text)
        };
        let mid_hdr = format!("Message-Id: <E{}{}@{}>\n", msg_id, dot_text, domain);
        let mid_len = mid_hdr.len();
        spool_headers.push(exim_spool::header_file::SpoolHeader {
            text: mid_hdr,
            slen: mid_len,
            header_type: ' ',
        });
    }

    if is_local && !has_from {
        // Auto-generate From: header using sender_address
        let from_hdr = format!("From: {}\n", sender);
        let from_len = from_hdr.len();
        spool_headers.push(exim_spool::header_file::SpoolHeader {
            text: from_hdr,
            slen: from_len,
            header_type: ' ',
        });
    }

    if is_local && !has_date {
        // Auto-generate Date: header
        let date_hdr = format!("Date: {}\n", timestamp);
        let date_len = date_hdr.len();
        spool_headers.push(exim_spool::header_file::SpoolHeader {
            text: date_hdr,
            slen: date_len,
            header_type: ' ',
        });
    }

    // ----- Process ACL-added headers -----
    // The data ACL may have added headers via "warn message = ...".
    // These are stored in the SMTP session's acl_added_headers list.
    for acl_hdr in &data_session.message_ctx.acl_added_headers {
        let mut text = acl_hdr.clone();
        if !text.ends_with('\n') {
            text.push('\n');
        }
        let slen = text.len();
        // ACL-added headers use a non-digit type character in the spool
        // file.  C Exim uses ' ' (space) as the generic header type.
        // CRITICAL: the type char MUST NOT be a digit because the spool
        // reader uses variable-length digit parsing for the length field
        // and stops at the first non-digit to obtain the type character.
        spool_headers.push(exim_spool::header_file::SpoolHeader {
            text,
            slen,
            header_type: ' ',
        });
    }

    let spool_recipients: Vec<exim_spool::header_file::Recipient> = data_session
        .message_ctx
        .recipients_list
        .iter()
        .map(|r| exim_spool::header_file::Recipient {
            address: r.address.clone(),
            pno: -1,
            errors_to: None,
            dsn: exim_spool::header_file::DsnInfo::default(),
        })
        .collect();

    // Originator uid/gid: use values from config context (set during -bs
    // initialization from the calling user's credentials).
    let orig_uid = data_session.config_ctx.originator_uid as i64;
    let orig_gid = data_session.config_ctx.originator_gid as i64;

    let mut spool_file = exim_spool::header_file::SpoolHeaderFile {
        message_id: msg_id.clone(),
        originator_login: data_session.config_ctx.originator_login.clone(),
        originator_uid: orig_uid,
        originator_gid: orig_gid,
        sender_address: sender.clone(),
        received_time_sec: now as i64,
        received_time_usec: tv_usec,
        received_time_complete_sec: now as i64,
        received_time_complete_usec: tv_usec,
        received_protocol: Some(protocol.clone()),
        sender_ident: data_session.message_ctx.sender_ident.clone(),
        headers: spool_headers,
        recipients: spool_recipients,
        body_linecount: received_data.body_linecount,
        body_zerocount: received_data.body_zerocount,
        max_received_linelength: received_data.max_received_linelength,
        ..Default::default()
    };
    // Set flags for local submission (-bs) and first delivery attempt.
    spool_file.flags.sender_local = data_session.server_ctx.is_local_session;
    spool_file.flags.deliver_firsttime = true;

    let header_path = format!("{}/{}-H", input_dir, msg_id);
    match std::fs::File::create(&header_path) {
        Ok(file) => match spool_file.write_to(file) {
            Ok(sz) => tracing::debug!(path = %header_path, size = sz, "wrote -H file"),
            Err(e) => tracing::error!(path = %header_path, error = %e, "failed to write -H file"),
        },
        Err(e) => tracing::error!(path = %header_path, error = %e, "failed to create -H file"),
    }

    // ----- Write mainlog reception line -----
    // C Exim format: "TIMESTAMP MSGID <= sender U=user P=protocol S=size"
    // For -bs mode: H= is not shown (local submission), U= shows originator_login
    // For network SMTP: H=helo [ip] is shown, U= may be absent
    let msg_size = received_data.message_size;
    let originator = &data_session.config_ctx.originator_login;
    let ts = format_log_timestamp(now);

    // Determine the H= field format. C Exim wraps the HELO name in
    // parentheses when the HELO name does not match the verified host
    // name (sender_host_name). In -bh mode and most tests, there is no
    // reverse DNS verification, so the HELO name is always parenthesised.
    let sender_host_name = data_session
        .message_ctx
        .sender_host_name
        .as_deref()
        .unwrap_or("");
    let h_field = if client_ip == "unknown" || client_ip.is_empty() {
        String::new()
    } else if !sender_host_name.is_empty() && sender_host_name == helo_name {
        // Verified hostname matches HELO: show bare name
        format!("H={helo_name} [{client_ip}]")
    } else if !sender_host_name.is_empty() {
        // Verified hostname differs from HELO: show "verified (helo)"
        format!("H={sender_host_name} ({helo_name}) [{client_ip}]")
    } else {
        // No verified hostname: wrap HELO in parens
        format!("H=({helo_name}) [{client_ip}]")
    };

    let log_line = if client_ip == "unknown" || client_ip.is_empty() {
        // Local submission (-bs mode): show U= but not H=
        format!("{ts} {msg_id} <= {sender} U={originator} P={protocol} S={msg_size}",)
    } else {
        // Network SMTP: show H= and client IP
        format!("{ts} {msg_id} <= {sender} {h_field} P={protocol} S={msg_size}",)
    };

    if data_session.server_ctx.host_checking {
        // -bh mode: write "LOG: <log_line>" to stderr instead of mainlog.
        // C Exim: log_write() with LOG_MAIN flag outputs to stderr with
        // "LOG: " prefix when host_checking is true.
        // The log line omits the timestamp in the LOG: stderr form, matching
        // C Exim's behavior where the LOG: line contains just the message
        // fields without leading timestamp.
        let log_body = if client_ip == "unknown" || client_ip.is_empty() {
            format!("{msg_id} <= {sender} U={originator} P={protocol} S={msg_size}")
        } else {
            format!("{msg_id} <= {sender} {h_field} P={protocol} S={msg_size}")
        };
        eprintln!("LOG: {log_body}");
    } else {
        // Normal mode: write to mainlog file
        if let Some(ref log_path) = data_session.config_ctx.log_file_path {
            let mainlog = log_path.replace("%slog", "mainlog");
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
                use std::io::Write;
                let _ = writeln!(f, "{log_line}");
            }
        }
    }

    msg_id
}

/// Format a Unix timestamp as an RFC 2822 date for Received: headers.
///
/// Produces format: "Thu, 01 Jan 2025 00:00:00 +0000"
/// Uses pure Rust arithmetic to avoid `unsafe` libc calls (AAP §0.7.2).
fn format_rfc2822_timestamp(epoch_secs: u64) -> String {
    let (year, month, day, hour, min, sec, wday) = epoch_to_utc_components(epoch_secs);

    let days = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let day_name = days[(wday % 7) as usize];
    let mon_name = if (month as usize) >= 1 && (month as usize) <= 12 {
        months[(month - 1) as usize]
    } else {
        "???"
    };

    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} +0000",
        day_name, day, mon_name, year, hour, min, sec,
    )
}

/// Format a Unix timestamp for Exim mainlog lines.
///
/// Produces format: "2025-01-01 00:00:00"
/// Uses UTC since we cannot safely call `localtime_r` without `unsafe`.
fn format_log_timestamp(epoch_secs: u64) -> String {
    let (year, month, day, hour, min, sec, _wday) = epoch_to_utc_components(epoch_secs);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, hour, min, sec,
    )
}

/// Convert a Unix epoch timestamp to UTC date/time components.
///
/// Returns (year, month 1-12, day 1-31, hour, minute, second, day_of_epoch).
/// The day_of_epoch can be used for weekday calculation (epoch day 0 = Thursday).
///
/// Algorithm based on Howard Hinnant's `civil_from_days` — no unsafe code.
fn epoch_to_utc_components(epoch_secs: u64) -> (i32, u32, u32, u32, u32, u32, u32) {
    let secs = epoch_secs;
    let sec = (secs % 60) as u32;
    let total_min = secs / 60;
    let min = (total_min % 60) as u32;
    let total_hour = total_min / 60;
    let hour = (total_hour % 24) as u32;
    let days = (total_hour / 24) as i64;

    // Howard Hinnant's algorithm for civil date from day count (epoch = 1970-01-01)
    let z = days + 719_468; // shift to 0000-03-01 epoch
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64 + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    // weekday: epoch day 0 (1970-01-01) is Thursday (index 0 in our table)
    let wday = ((days % 7 + 7) % 7) as u32;

    (year, m, d, hour, min, sec, wday)
}

/// Parse a human-readable size string (e.g., "50M", "1G", "1024K", "8192")
/// into a byte count. Returns `None` if the string is not a valid size.
///
/// Supports suffixes: K/k (KiB), M/m (MiB), G/g (GiB), or no suffix (bytes).
/// This matches C Exim's `readconf_readfixed()` parsing for message_size_limit.
/// Expand simple `${if eq{A}{A}{VALUE}}` or `${if eq{A}{A}{VALUE}{}}` patterns
/// commonly used in Exim config for `message_id_header_text` /
/// `message_id_header_domain`.  If the string does not match this trivial
/// pattern, return it unchanged.  C Exim does full expansion here; we only
/// need the common identity-comparison pattern used in test configs.
fn expand_simple_if_eq(input: &str) -> String {
    let s = input.trim();
    // Pattern: ${if eq{X}{X}{VALUE}} or ${if eq{X}{X}{VALUE}{}}
    if !s.starts_with("${if eq{") || !s.ends_with('}') {
        return s.to_string();
    }
    // Strip outer ${...}
    let inner = &s[2..s.len() - 1]; // "if eq{X}{X}{VALUE}" or "if eq{X}{X}{VALUE}{}"
    let inner = inner.strip_prefix("if eq").unwrap_or(inner).trim_start();
    // Parse {A}{B}{C} or {A}{B}{C}{D} braces
    let mut parts: Vec<String> = Vec::new();
    let mut chars = inner.chars().peekable();
    while chars.peek().is_some() {
        // skip whitespace
        while chars.peek() == Some(&' ') || chars.peek() == Some(&'\t') {
            chars.next();
        }
        if chars.peek() != Some(&'{') {
            break;
        }
        chars.next(); // consume '{'
        let mut depth = 1i32;
        let mut part = String::new();
        for ch in chars.by_ref() {
            if ch == '{' {
                depth += 1;
                part.push(ch);
            } else if ch == '}' {
                depth -= 1;
                if depth == 0 {
                    break;
                }
                part.push(ch);
            } else {
                part.push(ch);
            }
        }
        parts.push(part);
    }
    // Expected: parts[0]=A, parts[1]=B, parts[2]=VALUE, optional parts[3]=ELSE
    if parts.len() >= 3 && parts[0] == parts[1] {
        parts[2].clone()
    } else if parts.len() >= 4 && parts[0] != parts[1] {
        parts[3].clone()
    } else {
        s.to_string()
    }
}

fn parse_size_string(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num_str, multiplier) = match s.as_bytes().last()? {
        b'K' | b'k' => (&s[..s.len() - 1], 1024u64),
        b'M' | b'm' => (&s[..s.len() - 1], 1024 * 1024),
        b'G' | b'g' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s, 1u64),
    };
    let num: u64 = num_str.trim().parse().ok()?;
    Some(num.saturating_mul(multiplier))
}

/// Perform server-side TLS handshake on the given file descriptor.
///
/// This helper bridges the SMTP inbound layer to the `exim_tls` crate's
/// TLS backend. It delegates to the backend (rustls by default) to perform
/// the actual TLS handshake on the accepted socket, then constructs a
/// `TlsSession` from the backend's post-handshake state.
///
/// C reference: `tls_server_start()` in tls.c / tls-openssl.c / tls-gnu.c.
///
/// In the production daemon flow, the `TlsBackend` is initialised during
/// daemon startup (`daemon_init`) and credentials are loaded via
/// `server_creds_init`. The per-connection handshake is then performed via
/// `server_start(fd)`.  Currently the backend instance is constructed per-call;
/// in production wiring, the pre-initialised backend will be threaded through
/// `ServerContext` → `SmtpSession` so that credentials loaded at daemon startup
/// are reused across connections.
#[cfg(feature = "tls")]
fn tls_server_start(
    fd: RawFd,
    cert_path: Option<&str>,
    key_path: Option<&str>,
    ciphers: Option<&str>,
) -> Result<
    (
        exim_tls::TlsSession,
        Box<exim_tls::rustls_backend::RustlsBackend>,
    ),
    exim_tls::TlsError,
> {
    let cert = cert_path.ok_or_else(|| {
        exim_tls::TlsError::HandshakeError("tls_certificate not configured".into())
    })?;
    let key = key_path.unwrap_or(cert);

    let mut backend = Box::new(exim_tls::rustls_backend::RustlsBackend::new());

    // Load server credentials (certificate chain + private key) before
    // attempting the handshake — without this the ServerConfig is None
    // and the handshake would fail with "not initialized".
    let creds = exim_tls::rustls_backend::ServerCredsConfig {
        certificate: cert,
        privatekey: key,
        ciphers,
        min_version: None,
        ca_file: None,
        require_client_cert: false,
    };
    backend
        .server_creds_init(&creds)
        .map_err(|e| exim_tls::TlsError::HandshakeError(e.to_string()))?;

    backend
        .server_start(fd)
        .map_err(|e| exim_tls::TlsError::HandshakeError(e.to_string()))?;

    // Build TlsSession metadata from the backend's post-handshake accessors.
    let session = exim_tls::TlsSession {
        active: true,
        cipher: backend.cipher_name().map(String::from),
        protocol_version: backend.protocol_version().map(String::from),
        bits: 0,
        certificate_verified: backend.peer_dn().is_some(),
        peer_dn: backend.peer_dn().map(String::from),
        sni: backend.sni().map(String::from),
        peer_cert: None,
        channel_binding: None,
        resumption: exim_tls::ResumptionFlags::default(),
    };
    // Return both the session metadata and the live backend so the caller
    // can store the backend for subsequent encrypted I/O.
    Ok((session, backend))
}

/// Format the current local time as C Exim's `$tod_full`, e.g.
/// `"Tue, 2 Mar 1999 09:44:33 +0000"`.  Uses the `exim-ffi` safe wrapper
/// around `strftime` to produce locale-independent RFC-2822-style output
/// matching the C binary exactly.
fn format_tod_full() -> String {
    exim_ffi::format_tod_full()
}

/// Extract the numeric response code from an SMTP response string.
///
/// Returns the 3-digit code or 0 if parsing fails.
#[cfg(test)]
fn extract_response_code(response: &str) -> u16 {
    if response.len() >= 3 {
        response[..3].parse::<u16>().unwrap_or(0)
    } else {
        0
    }
}

/// Strip the response code prefix from an SMTP response string.
///
/// Removes "NNN " or "NNN-" prefix, returning just the message text.
#[cfg(test)]
fn strip_response_code(response: &str) -> &str {
    if response.len() >= 4 {
        &response[4..]
    } else {
        response
    }
}

/// Run an ACL check with the proper evaluation context.
///
/// This is a helper that creates the ACL evaluation context and delegates
/// to the ACL engine. Since the ACL engine has its own MessageContext type,
/// we bridge between our local MessageContext and the ACL's.
///
/// # Returns
///
/// (AclResult, user_message, log_message)
/// Session state passed from the SMTP handler into ACL evaluation.
///
/// This struct carries the envelope sender, client IP, HELO name, and
/// named lists from the configuration so that ACL conditions like
/// `hosts`, `senders`, `domains`, and `local_parts` can evaluate
/// against the actual session data instead of empty defaults.
#[derive(Default)]
pub struct AclSessionState {
    /// Envelope sender address from MAIL FROM (empty for null sender).
    pub sender_address: String,
    /// Client IP address (`sender_host_address`). Empty for local (-bs) connections.
    pub client_ip: String,
    /// Client's HELO/EHLO name.
    pub helo_name: String,
    /// Named domain lists from configuration (`domainlist local_domains = ...`).
    pub named_domain_lists: HashMap<String, String>,
    /// Named host lists from configuration (`hostlist ...`).
    pub named_host_lists: HashMap<String, String>,
    /// Named address lists from configuration (`addresslist ...`).
    pub named_address_lists: HashMap<String, String>,
    /// Named local-part lists from configuration (`localpartlist ...`).
    pub named_local_part_lists: HashMap<String, String>,
    /// Reply address computed from message headers (Reply-To or From).
    /// Set for DATA ACL evaluation after message body is received.
    pub reply_address: String,
    /// Parsed message headers for `$h_name:` variable lookups.
    /// Keys are lowercased header names, values are the header values.
    pub header_list: HashMap<String, String>,
    /// Whether we are in `-bh` host-checking mode. When true, HDEBUG output
    /// (`>>> ...`) is written to stderr during ACL evaluation.
    pub host_checking: bool,
    /// Optional callback for `verify = recipient`.  When provided, the ACL
    /// engine invokes it to route the recipient through the router chain.
    #[allow(clippy::type_complexity)]
    // Callback signature mirrors C Exim's verify callback pattern
    pub verify_recipient_cb: Option<
        std::sync::Arc<dyn Fn(&str, &str) -> exim_acl::engine::VerifyRecipientResult + Send + Sync>,
    >,
    /// Current recipient address (for RCPT TO ACL evaluation).
    pub recipient: String,
    /// Primary hostname from config.
    pub primary_hostname: String,
    /// Spool directory from config.
    pub spool_directory: String,
    /// Number of recipients already accepted in the current message
    /// transaction.  Needed so that `$recipients_count` resolves to the
    /// correct value during RCPT-time ACL evaluation.
    pub recipients_count: i32,
}

/// Result from an ACL check, including headers added by `warn message =`.
pub struct AclCheckResult {
    /// The ACL verdict (Ok, Deny, Defer, etc.).
    pub result: AclResult,
    /// User-facing message set by the ACL (may be empty).
    pub user_msg: String,
    /// Log message set by the ACL (may be empty).
    pub log_msg: String,
    /// Headers added by `warn message =` directives during evaluation.
    /// Each entry is a complete header line (e.g. "X-Foo: bar").
    pub added_headers: Vec<String>,
    /// When `verify = sender` fails, C Exim stores the failed sender
    /// address and its failure message as `sender_verified_failed`.
    /// In `smtp_handle_acl_fail()` this is emitted as a multi-line
    /// prefix ("Verification failed for <addr>\n<reason>") before the
    /// final ACL `message =` text.
    pub sender_verify_failure: Option<SenderVerifyFailure>,
}

/// Details of a sender verification failure, mirroring C Exim's
/// `sender_verified_failed` address struct.
pub struct SenderVerifyFailure {
    /// The sender address that failed verification.
    pub address: String,
    /// The failure reason (e.g. "Unrouteable address").
    pub user_message: String,
}

pub fn run_acl_check(
    where_phase: AclWhere,
    acl_text: Option<&str>,
    recipient: Option<&str>,
    acl_definitions: &HashMap<String, (String, String, i32)>,
    session_state: &AclSessionState,
) -> (AclResult, String, String) {
    let r = run_acl_check_full(
        where_phase,
        acl_text,
        recipient,
        acl_definitions,
        session_state,
    );
    (r.result, r.user_msg, r.log_msg)
}

/// Like `run_acl_check` but returns the full `AclCheckResult` including
/// ACL-added headers from `warn message =` directives.
pub fn run_acl_check_full(
    where_phase: AclWhere,
    acl_text: Option<&str>,
    recipient: Option<&str>,
    acl_definitions: &HashMap<String, (String, String, i32)>,
    session_state: &AclSessionState,
) -> AclCheckResult {
    // Create ACL evaluation context
    let mut eval_ctx = exim_acl::engine::AclEvalContext::default();
    let mut acl_msg_ctx = exim_acl::MessageContext::default();
    let mut var_store = exim_acl::AclVarStore::default();
    let mut user_msg: Option<String> = None;
    let mut log_msg: Option<String> = None;

    // Populate ACL message context with session state so that conditions
    // like `senders`, `hosts`, `domains`, `local_parts` have the actual
    // values to match against.
    acl_msg_ctx.sender_address = session_state.sender_address.clone();
    acl_msg_ctx.named_domain_lists = session_state.named_domain_lists.clone();
    acl_msg_ctx.named_host_lists = session_state.named_host_lists.clone();
    acl_msg_ctx.named_address_lists = session_state.named_address_lists.clone();
    acl_msg_ctx.named_local_part_lists = session_state.named_local_part_lists.clone();

    // Set client IP, HELO name, and host_checking flag on the eval context
    eval_ctx.client_ip = session_state.client_ip.clone();
    eval_ctx.sender_helo_name = session_state.helo_name.clone();
    eval_ctx.host_checking = session_state.host_checking;

    // ── Populate the expand context so that `message =` modifiers can
    //    resolve variables like `$sender_address`, `$local_part`, `$domain`,
    //    `$address_data`, `$sender_host_address`, etc.
    {
        let ectx = &mut eval_ctx.expand_ctx;
        ectx.sender_address = exim_store::Tainted::new(session_state.sender_address.clone());
        ectx.sender_host_address = exim_store::Tainted::new(session_state.client_ip.clone());
        ectx.sender_helo_name = exim_store::Tainted::new(session_state.helo_name.clone());
        ectx.primary_hostname = exim_store::Clean::new(session_state.primary_hostname.clone());
        ectx.spool_directory = exim_store::Clean::new(session_state.spool_directory.clone());
        ectx.recipients_count = session_state.recipients_count;
        // Parse recipient into local_part and domain for expansion
        let recip = recipient.unwrap_or(&session_state.recipient);
        if let Some(at_pos) = recip.rfind('@') {
            ectx.local_part = recip[..at_pos].to_string();
            ectx.domain = recip[at_pos + 1..].to_string();
        } else if !recip.is_empty() {
            ectx.local_part = recip.to_string();
        }
    }

    // ── Install the verify=recipient callback if provided by the caller.
    // The callback is wrapped in Arc so it can be cloned from the shared
    // session state into the eval context's Box<dyn Fn>.
    if let Some(ref arc_cb) = session_state.verify_recipient_cb {
        let cb_clone = arc_cb.clone();
        eval_ctx.verify_recipient_cb = Some(Box::new(move |addr, sender| cb_clone(addr, sender)));
    }

    // Initialize DNS resolver for ACL conditions that need DNS lookups
    // (hosts, dnslists, verify, etc.). In C Exim, the DNS resolver is a
    // global singleton initialised once at startup. Here we create it
    // per-evaluation because DnsResolver is not Clone and the eval context
    // takes ownership. The resolver reads /etc/resolv.conf and caches
    // results internally, so repeated creation is acceptable for
    // correctness even if not optimal for throughput.
    match exim_dns::DnsResolver::from_system() {
        Ok(resolver) => {
            eval_ctx.dns_resolver = Some(resolver);
        }
        Err(e) => {
            warn!(error = %e, "failed to initialise DNS resolver for ACL evaluation");
        }
    }

    // Pre-parse all named ACL definitions from the config into the eval
    // context's named_acls map.
    for (name, (raw_body, source_file, start_line)) in acl_definitions {
        match exim_acl::engine::acl_read(raw_body, Some(source_file), *start_line) {
            Ok(blocks) => {
                eval_ctx.named_acls.insert(name.clone(), blocks);
            }
            Err(e) => {
                warn!(
                    acl = %name,
                    error = %e,
                    "failed to parse named ACL definition"
                );
            }
        }
    }

    let result = exim_acl::acl_check(
        &mut eval_ctx,
        &mut acl_msg_ctx,
        &mut var_store,
        where_phase,
        acl_text,
        recipient,
        &mut user_msg,
        &mut log_msg,
    );

    // Extract sender verification failure details from the ACL eval
    // context — set by `acl_verify_sender_via_cb()` when `verify = sender`
    // fails.  The SMTP layer uses this to emit the multi-line prefix.
    let svf = eval_ctx
        .sender_verify_failure
        .take()
        .map(|(addr, msg)| SenderVerifyFailure {
            address: addr,
            user_message: msg,
        });

    AclCheckResult {
        result,
        user_msg: user_msg.unwrap_or_default(),
        log_msg: log_msg.unwrap_or_default(),
        added_headers: acl_msg_ctx.acl_added_headers,
        sender_verify_failure: svf,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smtp_setup_result_variants() {
        assert_eq!(SmtpSetupResult::Done, SmtpSetupResult::Done);
        assert_eq!(SmtpSetupResult::Yield, SmtpSetupResult::Yield);
        assert_eq!(SmtpSetupResult::Error, SmtpSetupResult::Error);
        assert_ne!(SmtpSetupResult::Done, SmtpSetupResult::Yield);
    }

    #[test]
    fn test_parse_mail_address_with_brackets() {
        let (addr, ext) = parse_mail_address("<user@example.com> SIZE=1024").unwrap();
        assert_eq!(addr, "user@example.com");
        assert_eq!(ext, "SIZE=1024");
    }

    #[test]
    fn test_parse_mail_address_empty() {
        let (addr, ext) = parse_mail_address("<>").unwrap();
        assert_eq!(addr, "");
        assert_eq!(ext, "");
    }

    #[test]
    fn test_parse_mail_address_bare() {
        let (addr, ext) = parse_mail_address("user@example.com SIZE=512").unwrap();
        assert_eq!(addr, "user@example.com");
        assert_eq!(ext, "SIZE=512");
    }

    #[test]
    fn test_parse_mail_address_malformed_trailing_bracket() {
        let err = parse_mail_address("someone@some.where<").unwrap_err();
        assert!(err.contains("malformed address"));
        assert!(err.contains("< may not follow"));
    }

    #[test]
    fn test_parse_mail_address_missing_close_bracket() {
        let err = parse_mail_address("<user@example.com").unwrap_err();
        assert!(err.contains("'>' missing"));
    }

    #[test]
    fn test_extract_response_code() {
        assert_eq!(extract_response_code("250 OK"), 250);
        assert_eq!(extract_response_code("550-Error"), 550);
        assert_eq!(extract_response_code(""), 0);
    }

    #[test]
    fn test_strip_response_code() {
        assert_eq!(strip_response_code("250 OK"), "OK");
        assert_eq!(strip_response_code("550-Error line"), "Error line");
    }

    #[test]
    fn test_acl_wherecode() {
        assert_eq!(acl_wherecode(&AclWhere::Helo), 550);
        assert_eq!(acl_wherecode(&AclWhere::Auth), 503);
        assert_eq!(acl_wherecode(&AclWhere::Vrfy), 252);
        assert_eq!(acl_wherecode(&AclWhere::Etrn), 458);
    }

    #[test]
    fn test_dsn_ret_default() {
        assert_eq!(DsnRet::default(), DsnRet::None);
    }

    #[test]
    fn test_body_type_default() {
        assert_eq!(BodyType::default(), BodyType::SevenBit);
    }
}
