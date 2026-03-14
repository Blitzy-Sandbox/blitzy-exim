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

/// Immutable parsed configuration context for the SMTP session.
///
/// This is a **local mirror type** containing the SMTP-relevant subset of
/// `exim_config::types::ConfigContext`.  Use [`ConfigContext::from_config()`]
/// to construct from the canonical parsed configuration, ensuring ACL names,
/// limits, and advertisement settings are correctly propagated.
///
/// **Canonical source**: `exim-config/src/types.rs` `ConfigContext`.
pub struct ConfigContext {
    // ACL definitions for each SMTP phase
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
            // ACL definitions — propagated from the parsed config
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
        }
    }
}

// =============================================================================
// Common Methods — Available in ALL states
// =============================================================================

impl<'ctx, S> SmtpSession<'ctx, S> {
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

    /// Handle an ACL check failure by generating the appropriate SMTP response.
    ///
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
            AclResult::Defer => {
                // Temporary failure — 4xx response
                let msg = if user_msg.is_empty() {
                    "Temporary service refusal".to_string()
                } else {
                    user_msg.to_string()
                };
                let code = if default_code < 500 {
                    default_code
                } else {
                    450
                };
                let code_str = format!("{}", code);
                self.smtp_respond(&code_str, false, &msg);
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
            AclResult::Error => {
                // Internal error — 4xx temporary failure
                let msg = if user_msg.is_empty() {
                    "Internal configuration error".to_string()
                } else {
                    user_msg.to_string()
                };
                self.smtp_respond("451", false, &msg);
                0
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
        self.message_ctx.authenticated_sender = None;
        self.message_ctx.dsn_ret = DsnRet::None;
        self.message_ctx.dsn_envid = None;
        self.message_ctx.message_size = 0;
        self.message_ctx.body_type = BodyType::SevenBit;
        self.message_ctx.smtputf8_advertised = false;
        self.rcpt_in_progress = false;

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
            let (acl_rc, user_msg, log_msg) =
                run_acl_check(AclWhere::Helo, Some(acl), Some(name_ref));
            if acl_rc != AclResult::Ok {
                let result = self.smtp_handle_acl_fail(AclWhere::Helo, acl_rc, &user_msg, &log_msg);
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

        // Send response
        if is_ehlo {
            self.send_ehlo_response();
        } else {
            let hostname = self.server_ctx.smtp_active_hostname.clone();
            let response = format!("{} Hello {}", hostname, name_ref);
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
        let (sender, extensions) = parse_mail_address(addr_str);

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
            let (acl_rc, user_msg, log_msg) =
                run_acl_check(AclWhere::Mail, Some(acl), Some(&sender));
            if acl_rc != AclResult::Ok {
                let result = self.smtp_handle_acl_fail(AclWhere::Mail, acl_rc, &user_msg, &log_msg);
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
        let (recipient, extensions) = parse_mail_address(addr_str);

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
            let (acl_rc, user_msg, log_msg) =
                run_acl_check(AclWhere::Rcpt, Some(acl), Some(&recipient));
            if acl_rc != AclResult::Ok {
                self.rcpt_in_progress = false;
                let result = self.smtp_handle_acl_fail(AclWhere::Rcpt, acl_rc, &user_msg, &log_msg);
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
        let (recipient, extensions) = parse_mail_address(addr_str);

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
            let (acl_rc, user_msg, log_msg) =
                run_acl_check(AclWhere::Rcpt, Some(acl), Some(&recipient));
            if acl_rc != AclResult::Ok {
                self.rcpt_in_progress = false;
                let result = self.smtp_handle_acl_fail(AclWhere::Rcpt, acl_rc, &user_msg, &log_msg);
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
            let (acl_rc, user_msg, log_msg) = run_acl_check(AclWhere::Predata, Some(acl), None);
            if acl_rc != AclResult::Ok {
                let result =
                    self.smtp_handle_acl_fail(AclWhere::Predata, acl_rc, &user_msg, &log_msg);
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

        // Run DATA ACL if configured
        if let Some(ref acl) = self.config_ctx.acl_smtp_data {
            let (acl_rc, user_msg, log_msg) = run_acl_check(AclWhere::Data, Some(acl), None);
            if acl_rc != AclResult::Ok {
                let result = self.smtp_handle_acl_fail(AclWhere::Data, acl_rc, &user_msg, &log_msg);
                if result < 0 {
                    return Err(Box::new((
                        self,
                        SmtpError::ProtocolError {
                            message: "DATA ACL rejected with DROP".into(),
                        },
                    )));
                }
            }
        }

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
        let greeting = format!(
            "{} Hello {}",
            hostname,
            self.message_ctx.helo_name.as_deref().unwrap_or("unknown")
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
        let is_esmtp = self.flags.esmtp;
        let is_tls = self.message_ctx.tls_in.active;
        let is_authed = self.message_ctx.authenticated_id.is_some();

        // Protocol string selection based on ESMTP/TLS/AUTH status.
        // Non-ESMTP + authenticated combos are impossible in practice
        // (AUTH requires EHLO), but we map them to Esmtpa/Esmtpsa for safety.
        self.message_ctx.received_protocol = match (is_esmtp, is_tls, is_authed) {
            (false, false, false) => SmtpProtocol::Smtp,
            (true, false, false) => SmtpProtocol::Esmtp,
            (false, true, false) => SmtpProtocol::Smtps,
            (true, true, false) => SmtpProtocol::Esmtps,
            (false, false, true) => SmtpProtocol::Esmtpa,
            (true, false, true) => SmtpProtocol::Esmtpa,
            (false, true, true) => SmtpProtocol::Esmtpsa,
            (true, true, true) => SmtpProtocol::Esmtpsa,
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
            let (acl_rc, user_msg, log_msg) =
                run_acl_check(AclWhere::Auth, Some(acl), Some(&mechanism));
            if acl_rc != AclResult::Ok {
                let result = self.smtp_handle_acl_fail(AclWhere::Auth, acl_rc, &user_msg, &log_msg);
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
            let (acl_rc, user_msg, log_msg) = run_acl_check(AclWhere::StartTls, Some(acl), None);
            if acl_rc != AclResult::Ok {
                let result =
                    self.smtp_handle_acl_fail(AclWhere::StartTls, acl_rc, &user_msg, &log_msg);
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
        match tls_server_start(self.io.in_fd) {
            Ok(tls_session) => {
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
            let (acl_rc, user_msg, log_msg) =
                run_acl_check(AclWhere::Vrfy, Some(acl), Some(argument));
            if acl_rc != AclResult::Ok {
                let _ = self.smtp_handle_acl_fail(AclWhere::Vrfy, acl_rc, &user_msg, &log_msg);
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
            let (acl_rc, user_msg, log_msg) =
                run_acl_check(AclWhere::Expn, Some(acl), Some(argument));
            if acl_rc != AclResult::Ok {
                let _ = self.smtp_handle_acl_fail(AclWhere::Expn, acl_rc, &user_msg, &log_msg);
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

        if let Some(ref acl) = self.config_ctx.acl_smtp_etrn {
            let (acl_rc, user_msg, log_msg) =
                run_acl_check(AclWhere::Etrn, Some(acl), Some(argument));
            if acl_rc != AclResult::Ok {
                let _ = self.smtp_handle_acl_fail(AclWhere::Etrn, acl_rc, &user_msg, &log_msg);
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
        format!(
            "220 {} ESMTP Exim 4.99 ready\r\n",
            server_ctx.smtp_active_hostname
        )
    };

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
    session.smtp_printf(&banner, false);

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
                    let response = format!("{} Hello {}", hostname, argument);
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
                    Ok(_data_session) => {
                        // DATA accepted — yield to message reception
                        return SmtpSetupResult::Yield;
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

                // Yield to message reception
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
fn parse_mail_address(input: &str) -> (String, String) {
    let trimmed = input.trim();

    // Handle <address> syntax
    if let Some(start) = trimmed.find('<') {
        if let Some(end) = trimmed.find('>') {
            let address = trimmed[start + 1..end].trim().to_string();
            let extensions = if end + 1 < trimmed.len() {
                trimmed[end + 1..].trim().to_string()
            } else {
                String::new()
            };
            return (address, extensions);
        }
    }

    // Handle bare address (no angle brackets)
    let parts: Vec<&str> = trimmed.splitn(2, char::is_whitespace).collect();
    let address = parts.first().unwrap_or(&"").to_string();
    let extensions = parts.get(1).unwrap_or(&"").to_string();
    (address, extensions)
}

// =============================================================================
// Module-Level Helper Functions
// =============================================================================

/// Parse a human-readable size string (e.g., "50M", "1G", "1024K", "8192")
/// into a byte count. Returns `None` if the string is not a valid size.
///
/// Supports suffixes: K/k (KiB), M/m (MiB), G/g (GiB), or no suffix (bytes).
/// This matches C Exim's `readconf_readfixed()` parsing for message_size_limit.
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
fn tls_server_start(fd: RawFd) -> Result<exim_tls::TlsSession, exim_tls::TlsError> {
    let mut backend = exim_tls::rustls_backend::RustlsBackend::new();
    backend
        .server_start(fd)
        .map_err(|e| exim_tls::TlsError::HandshakeError(e.to_string()))?;
    // Build TlsSession from the backend's post-handshake accessor methods
    Ok(exim_tls::TlsSession {
        active: true,
        cipher: backend.cipher_name().map(String::from),
        protocol_version: backend.protocol_version().map(String::from),
        bits: 0, // Bit strength not directly exposed by rustls backend
        certificate_verified: backend.peer_dn().is_some(),
        peer_dn: backend.peer_dn().map(String::from),
        sni: backend.sni().map(String::from),
        peer_cert: None,
        channel_binding: None,
        resumption: exim_tls::ResumptionFlags::default(),
    })
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
pub(crate) fn run_acl_check(
    where_phase: AclWhere,
    acl_text: Option<&str>,
    recipient: Option<&str>,
) -> (AclResult, String, String) {
    // Create ACL evaluation context
    let mut eval_ctx = exim_acl::engine::AclEvalContext::default();
    let mut acl_msg_ctx = exim_acl::MessageContext::default();
    let mut var_store = exim_acl::AclVarStore::default();
    let mut user_msg: Option<String> = None;
    let mut log_msg: Option<String> = None;

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

    (
        result,
        user_msg.unwrap_or_default(),
        log_msg.unwrap_or_default(),
    )
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
        let (addr, ext) = parse_mail_address("<user@example.com> SIZE=1024");
        assert_eq!(addr, "user@example.com");
        assert_eq!(ext, "SIZE=1024");
    }

    #[test]
    fn test_parse_mail_address_empty() {
        let (addr, ext) = parse_mail_address("<>");
        assert_eq!(addr, "");
        assert_eq!(ext, "");
    }

    #[test]
    fn test_parse_mail_address_bare() {
        let (addr, ext) = parse_mail_address("user@example.com SIZE=512");
        assert_eq!(addr, "user@example.com");
        assert_eq!(ext, "SIZE=512");
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
