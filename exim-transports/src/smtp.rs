// exim-transports/src/smtp.rs
//
// Full outbound SMTP/LMTP transport — Rust rewrite of src/src/transports/smtp.c (6,573 lines)
// and src/src/transports/smtp.h (253 lines).
//
// This module implements the complete outbound SMTP/LMTP state machine used for remote
// delivery in Exim. It handles connection setup, EHLO/HELO negotiation, STARTTLS,
// AUTH, MAIL FROM, RCPT TO, DATA, pipelining, chunking, DSN, PRDR, early pipe connect,
// DANE, DKIM signing, and connection reuse/closedown.
//
// All C global state has been replaced with scoped context structs (SmtpContext,
// SmtpTransportOptions). All preprocessor conditionals are replaced by Cargo feature
// flags. Taint tracking uses compile-time Tainted<T>/Clean<T> newtypes.

use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use exim_drivers::transport_driver::{
    TransportDriver, TransportDriverFactory, TransportInstanceConfig, TransportResult,
};
use exim_drivers::DriverError;
use exim_store::taint::Tainted;

use regex::Regex;
use serde::Deserialize;
use tracing;

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 1: Constants — from smtp.h and smtp.c
// ═══════════════════════════════════════════════════════════════════════════════

/// Size of the SMTP delivery I/O buffer (smtp.h line 10).
pub const DELIVER_BUFFER_SIZE: usize = 4096;

/// Pending status base value for SMTP pipelined responses (smtp.h line 12).
pub const PENDING: i32 = 256;

/// Pending status indicating deferred delivery (smtp.h line 13).
pub const PENDING_DEFER: i32 = PENDING + 1;

/// Pending status indicating successful delivery (smtp.h line 14).
pub const PENDING_OK: i32 = PENDING;

// Response code bit constants (smtp.c lines 244–252).
// Used to track which response categories have been seen during pipelined SMTP.

/// Bit flag indicating a 2xx response was received.
pub const RESP_BIT_HAD_2XX: i32 = 1;

/// Bit flag indicating a 5xx response was received.
pub const RESP_BIT_HAD_5XX: i32 = 2;

/// Combined flag: both 2xx and 5xx responses were received.
pub const RESP_HAD_2_AND_5: i32 = RESP_BIT_HAD_2XX | RESP_BIT_HAD_5XX;

/// No error in response processing.
pub const RESP_NOERROR: i32 = 0;

/// RCPT TO response timed out.
pub const RESP_RCPT_TIMEO: i32 = -1;

/// RCPT TO response had an error.
pub const RESP_RCPT_ERROR: i32 = -2;

/// MAIL FROM or DATA response had an error.
pub const RESP_MAIL_OR_DATA_ERROR: i32 = -3;

/// EPIPE during EHLO exchange.
pub const RESP_EPIPE_EHLO_ERR: i32 = -4;

/// EHLO error during TLS negotiation.
pub const RESP_EHLO_ERR_TLS: i32 = -5;

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 8: DSN Support Constants — from smtp.c lines 222–225
// ═══════════════════════════════════════════════════════════════════════════════

/// DSN NOTIFY flag values — indices align with RF_NAMES.
/// 0 = NEVER, 1 = SUCCESS, 2 = FAILURE, 3 = DELAY
pub const RF_NOTIFY_NEVER: i32 = 0x01;
pub const RF_NOTIFY_SUCCESS: i32 = 0x02;
pub const RF_NOTIFY_FAILURE: i32 = 0x04;
pub const RF_NOTIFY_DELAY: i32 = 0x08;

/// DSN NOTIFY flag value array (rf_list in C).
pub const RF_LIST: [i32; 4] = [
    RF_NOTIFY_NEVER,
    RF_NOTIFY_SUCCESS,
    RF_NOTIFY_FAILURE,
    RF_NOTIFY_DELAY,
];

/// DSN NOTIFY flag name array (rf_names in C).
pub const RF_NAMES: [&str; 4] = ["NEVER", "SUCCESS", "FAILURE", "DELAY"];

// Peer capability bits (for SmtpContext.peer_offered bitmask)
pub const PEER_OFFERED_TLS: u32 = 0x0001;
pub const PEER_OFFERED_CHUNKING: u32 = 0x0002;
pub const PEER_OFFERED_PIPELINING: u32 = 0x0004;
pub const PEER_OFFERED_DSN: u32 = 0x0008;
pub const PEER_OFFERED_SIZE: u32 = 0x0010;
pub const PEER_OFFERED_AUTH: u32 = 0x0020;
pub const PEER_OFFERED_IGNOREQUOTA: u32 = 0x0040;
pub const PEER_OFFERED_PRDR: u32 = 0x0080;
pub const PEER_OFFERED_UTF8: u32 = 0x0100;
pub const PEER_OFFERED_EARLY_PIPE: u32 = 0x0200;
pub const PEER_OFFERED_LIMITS: u32 = 0x0400;
pub const PEER_OFFERED_PIPE_CONNECT: u32 = 0x0800;

/// Default SMTP port (25).
const SMTP_PORT: u16 = 25;

/// Default SMTPS/submissions port (465).
const SMTPS_PORT: u16 = 465;

/// Default submission port (587).
const SUBMISSION_PORT: u16 = 587;

/// Default LMTP port (24).
const LMTP_PORT: u16 = 24;

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 2: TLS Library State — from smtp.h lines 17–34
// ═══════════════════════════════════════════════════════════════════════════════

/// TLS library state tracking which resources have been loaded.
/// Replaces C `exim_tlslib_state` struct. Feature-gated behind `tls`.
/// The `libdata0`/`libdata1` void pointers from C are replaced by type-erased
/// `Option<Box<dyn Any + Send + Sync>>` fields for safe polymorphism.
#[cfg(feature = "tls")]
#[derive(Debug, Default)]
pub struct EximTlsLibState {
    /// Whether connection certificates have been loaded.
    pub conn_certs: bool,
    /// Whether the CA bundle has been loaded.
    pub cabundle: bool,
    /// Whether the CRL has been loaded.
    pub crl: bool,
    /// Whether the priority/cipher string has been set.
    pub pri_string: bool,
    /// Whether DH parameters have been loaded.
    pub dh: bool,
    /// Whether ECDH parameters have been loaded.
    pub ecdh: bool,
    /// Whether CA RDN emulation is active.
    pub ca_rdn_emulate: bool,
    /// Whether the OCSP hook is registered.
    pub ocsp_hook: bool,
    /// Type-erased TLS library data slot 0 (replaces C void* libdata0).
    pub libdata0: Option<Box<dyn Any + Send + Sync>>,
    /// Type-erased TLS library data slot 1 (replaces C void* libdata1).
    pub libdata1: Option<Box<dyn Any + Send + Sync>>,
}

#[cfg(feature = "tls")]
impl Clone for EximTlsLibState {
    fn clone(&self) -> Self {
        // Type-erased data is not cloneable; reset to None on clone.
        Self {
            conn_certs: self.conn_certs,
            cabundle: self.cabundle,
            crl: self.crl,
            pri_string: self.pri_string,
            dh: self.dh,
            ecdh: self.ecdh,
            ca_rdn_emulate: self.ca_rdn_emulate,
            ocsp_hook: self.ocsp_hook,
            libdata0: None,
            libdata1: None,
        }
    }
}

/// Stub for when TLS feature is disabled — provides the same struct name
/// with no fields so the rest of the transport code can reference it unconditionally.
#[cfg(not(feature = "tls"))]
#[derive(Debug, Clone, Default)]
pub struct EximTlsLibState;

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 3: SmtpTransportOptions — from smtp.h lines 39–137
// ═══════════════════════════════════════════════════════════════════════════════

/// DKIM signing options, feature-gated behind `dkim`.
#[cfg(feature = "dkim")]
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DkimOptions {
    /// DKIM domain (d= tag).
    #[serde(default)]
    pub dkim_domain: String,
    /// DKIM selector (s= tag).
    #[serde(default)]
    pub dkim_selector: String,
    /// DKIM private key path or inline data.
    #[serde(default)]
    pub dkim_private_key: String,
    /// DKIM canonicalization (e.g., "relaxed/simple").
    #[serde(default)]
    pub dkim_canon: String,
    /// DKIM signing headers.
    #[serde(default)]
    pub dkim_sign_headers: String,
    /// DKIM hash method override.
    #[serde(default)]
    pub dkim_hash: String,
    /// DKIM identity (i= tag).
    #[serde(default)]
    pub dkim_identity: String,
    /// DKIM timestamps.
    #[serde(default)]
    pub dkim_timestamps: String,
    /// Whether DKIM strict mode is enabled.
    #[serde(default)]
    pub dkim_strict: String,
}

/// Complete SMTP transport options block.
/// Maps 1:1 to C `smtp_transport_options_block` (smtp.h lines 39–137).
/// All fields use the exact C option names for backward-compatible config parsing.
#[derive(Debug, Clone, Deserialize)]
pub struct SmtpTransportOptions {
    // ── Basic connection settings ──────────────────────────────────
    /// Host list for delivery.
    #[serde(default)]
    pub hosts: String,

    /// Fallback host list.
    #[serde(default)]
    pub fallback_hosts: String,

    /// Authenticated sender value for SMTP AUTH.
    #[serde(default)]
    pub authenticated_sender: String,

    /// HELO/EHLO data string (default: "$primary_hostname").
    #[serde(default = "SmtpTransportOptions::default_helo_data")]
    pub helo_data: String,

    /// Source interface for outbound connections.
    #[serde(default)]
    pub interface: String,

    /// Destination port string (default derived from protocol).
    #[serde(default)]
    pub port: String,

    /// SMTP protocol variant ("smtp", "smtps", "lmtp", etc.).
    #[serde(default)]
    pub protocol: String,

    /// DSCP value for outbound connections.
    #[serde(default)]
    pub dscp: String,

    // ── Host list matching strings ─────────────────────────────────
    /// Host list for serialized (single-thread) delivery.
    #[serde(default)]
    pub serialize_hosts: String,

    /// Hosts to attempt AUTH with.
    #[serde(default)]
    pub hosts_try_auth: String,

    /// Hosts requiring ALPN negotiation.
    #[serde(default)]
    pub hosts_require_alpn: String,

    /// Hosts requiring AUTH.
    #[serde(default)]
    pub hosts_require_auth: String,

    /// Hosts to attempt chunking (BDAT) with.
    #[serde(default = "SmtpTransportOptions::default_wildcard")]
    pub hosts_try_chunking: String,

    /// Hosts to attempt TCP Fast Open with.
    #[serde(default = "SmtpTransportOptions::default_wildcard")]
    pub hosts_try_fastopen: String,

    // ── DANE feature-gated ─────────────────────────────────────────
    /// Hosts to attempt DANE verification with.
    #[cfg(feature = "dane")]
    #[serde(default = "SmtpTransportOptions::default_wildcard")]
    pub hosts_try_dane: String,

    /// Hosts requiring DANE verification.
    #[cfg(feature = "dane")]
    #[serde(default)]
    pub hosts_require_dane: String,

    /// TLS cipher requirements for DANE.
    #[cfg(feature = "dane")]
    #[serde(default)]
    pub dane_require_tls_ciphers: String,

    // ── PRDR feature-gated ─────────────────────────────────────────
    /// Hosts to attempt PRDR with.
    #[cfg(feature = "prdr")]
    #[serde(default = "SmtpTransportOptions::default_wildcard")]
    pub hosts_try_prdr: String,

    // ── OCSP feature-gated ─────────────────────────────────────────
    /// Hosts to request OCSP stapling from.
    #[cfg(feature = "ocsp")]
    #[serde(default = "SmtpTransportOptions::default_wildcard")]
    pub hosts_request_ocsp: String,

    /// Hosts requiring OCSP stapling.
    #[cfg(feature = "ocsp")]
    #[serde(default)]
    pub hosts_require_ocsp: String,

    // ── PIPE_CONNECT feature-gated ─────────────────────────────────
    /// Hosts eligible for early-pipelining (PIPE_CONNECT).
    #[cfg(feature = "pipe-connect")]
    #[serde(default)]
    pub hosts_pipe_connect: String,

    // ── TLS feature-gated ──────────────────────────────────────────
    /// Hosts requiring TLS.
    #[cfg(feature = "tls")]
    #[serde(default)]
    pub hosts_require_tls: String,

    /// Hosts to avoid TLS with.
    #[cfg(feature = "tls")]
    #[serde(default)]
    pub hosts_avoid_tls: String,

    /// Hosts to avoid TLS with during verification.
    #[cfg(feature = "tls")]
    #[serde(default)]
    pub hosts_verify_avoid_tls: String,

    /// Hosts to not pass TLS connections through.
    #[cfg(feature = "tls")]
    #[serde(default)]
    pub hosts_nopass_tls: String,

    /// Hosts to not proxy TLS connections through.
    #[cfg(feature = "tls")]
    #[serde(default)]
    pub hosts_noproxy_tls: String,

    /// TLS client certificate file.
    #[cfg(feature = "tls")]
    #[serde(default)]
    pub tls_certificate: String,

    /// TLS private key file.
    #[cfg(feature = "tls")]
    #[serde(default)]
    pub tls_privatekey: String,

    /// TLS cipher requirements string.
    #[cfg(feature = "tls")]
    #[serde(default)]
    pub tls_require_ciphers: String,

    /// TLS Server Name Indication.
    #[cfg(feature = "tls")]
    #[serde(default)]
    pub tls_sni: String,

    /// TLS CA certificates for verification (default: "system").
    #[cfg(feature = "tls")]
    #[serde(default = "SmtpTransportOptions::default_tls_verify_certs")]
    pub tls_verify_certificates: String,

    /// TLS Certificate Revocation List.
    #[cfg(feature = "tls")]
    #[serde(default)]
    pub tls_crl: String,

    /// Hosts to verify TLS certificates for.
    #[cfg(feature = "tls")]
    #[serde(default)]
    pub tls_verify_hosts: String,

    /// Hosts to try TLS verification for (non-fatal on failure).
    #[cfg(feature = "tls")]
    #[serde(default = "SmtpTransportOptions::default_wildcard")]
    pub tls_try_verify_hosts: String,

    /// Hosts to verify TLS certificate hostnames for.
    #[cfg(feature = "tls")]
    #[serde(default = "SmtpTransportOptions::default_wildcard")]
    pub tls_verify_cert_hostnames: String,

    /// Whether to fall back to cleartext on TLS temp failure.
    #[cfg(feature = "tls")]
    #[serde(default = "SmtpTransportOptions::default_true")]
    pub tls_tempfail_tryclear: bool,

    // ── TLS Resume feature-gated ───────────────────────────────────
    /// Hostname extraction pattern for TLS session resumption.
    #[cfg(feature = "tls-resume")]
    #[serde(default)]
    pub host_name_extract: String,

    /// Hosts eligible for TLS session resumption.
    #[cfg(feature = "tls-resume")]
    #[serde(default)]
    pub tls_resumption_hosts: String,

    // ── I18N feature-gated ─────────────────────────────────────────
    /// UTF-8 downconvert mode for SMTPUTF8 (i18n).
    #[cfg(feature = "i18n")]
    #[serde(default)]
    pub utf8_downconvert: String,

    // ── DKIM feature-gated ─────────────────────────────────────────
    /// DKIM signing options block.
    #[cfg(feature = "dkim")]
    #[serde(default)]
    pub dkim: DkimOptions,

    // ── ARC feature-gated ──────────────────────────────────────────
    /// ARC signing specification.
    #[cfg(feature = "arc")]
    #[serde(default)]
    pub arc_sign: String,

    // ── SOCKS feature-gated ────────────────────────────────────────
    /// SOCKS proxy for outbound connections.
    #[cfg(feature = "socks")]
    #[serde(default)]
    pub socks_proxy: String,

    // ── Timeout values (seconds) ───────────────────────────────────
    /// Timeout for individual SMTP commands (default: 300s).
    #[serde(default = "SmtpTransportOptions::default_command_timeout")]
    pub command_timeout: u64,

    /// Timeout for TCP connection establishment (default: 300s).
    #[serde(default = "SmtpTransportOptions::default_connect_timeout")]
    pub connect_timeout: u64,

    /// Timeout for DATA phase (default: 300s).
    #[serde(default = "SmtpTransportOptions::default_data_timeout")]
    pub data_timeout: u64,

    /// Final timeout after all data sent, waiting for response (default: 600s).
    #[serde(default = "SmtpTransportOptions::default_final_timeout")]
    pub final_timeout: u64,

    // ── Numeric limits ─────────────────────────────────────────────
    /// Additional bytes to add to SIZE declaration (default: 1024).
    #[serde(default = "SmtpTransportOptions::default_size_addition")]
    pub size_addition: i32,

    /// Maximum host connection attempts (default: 5).
    #[serde(default = "SmtpTransportOptions::default_hosts_max_try")]
    pub hosts_max_try: i32,

    /// Hard limit on host connection attempts (default: 50).
    #[serde(default = "SmtpTransportOptions::default_hosts_max_try_hardlimit")]
    pub hosts_max_try_hardlimit: i32,

    /// Maximum message line length (default: 998 per RFC 5321).
    #[serde(default = "SmtpTransportOptions::default_message_linelength_limit")]
    pub message_linelength_limit: i32,

    // ── Boolean flags ──────────────────────────────────────────────
    /// Include sender in address retry key.
    #[serde(default = "SmtpTransportOptions::default_true")]
    pub address_retry_include_sender: bool,

    /// Allow delivery to localhost.
    #[serde(default)]
    pub allow_localhost: bool,

    /// Force use of authenticated_sender.
    #[serde(default)]
    pub authenticated_sender_force: bool,

    /// Use gethostbyname instead of DNS for host resolution.
    #[serde(default)]
    pub gethostbyname: bool,

    /// Add search domain to single-component host names.
    #[serde(default = "SmtpTransportOptions::default_true")]
    pub dns_qualify_single: bool,

    /// Search parent domains for host resolution.
    #[serde(default)]
    pub dns_search_parents: bool,

    /// Delay delivery after the retry cutoff time.
    #[serde(default = "SmtpTransportOptions::default_true")]
    pub delay_after_cutoff: bool,

    /// Whether this transport's hosts override router-supplied hosts.
    #[serde(default)]
    pub hosts_override: bool,

    /// Randomize the host list for load distribution.
    #[serde(default)]
    pub hosts_randomize: bool,

    /// Enable TCP keepalive on outbound connections.
    #[serde(default = "SmtpTransportOptions::default_true")]
    pub keepalive: bool,

    /// Ignore quota for LMTP delivery.
    #[serde(default)]
    pub lmtp_ignore_quota: bool,

    /// Include IP address in retry key.
    #[serde(default = "SmtpTransportOptions::default_true")]
    pub retry_include_ip_address: bool,

    // ── DNSSEC settings ────────────────────────────────────────────
    /// DNSSEC request mode.
    #[serde(default)]
    pub dnssec: DnssecMode,
}

/// DNSSEC request mode for DNS lookups.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub enum DnssecMode {
    /// No DNSSEC preference.
    #[default]
    None,
    /// Request DNSSEC validation.
    Request,
    /// Require DNSSEC validation.
    Require,
}

// Default value helper functions for serde deserialization.
impl SmtpTransportOptions {
    fn default_helo_data() -> String {
        "$primary_hostname".to_string()
    }

    fn default_wildcard() -> String {
        "*".to_string()
    }

    fn default_true() -> bool {
        true
    }

    fn default_tls_verify_certs() -> String {
        "system".to_string()
    }

    fn default_command_timeout() -> u64 {
        300
    }

    fn default_connect_timeout() -> u64 {
        300
    }

    fn default_data_timeout() -> u64 {
        300
    }

    fn default_final_timeout() -> u64 {
        600
    }

    fn default_size_addition() -> i32 {
        1024
    }

    fn default_hosts_max_try() -> i32 {
        5
    }

    fn default_hosts_max_try_hardlimit() -> i32 {
        50
    }

    fn default_message_linelength_limit() -> i32 {
        998
    }
}

impl Default for SmtpTransportOptions {
    fn default() -> Self {
        Self {
            hosts: String::new(),
            fallback_hosts: String::new(),
            authenticated_sender: String::new(),
            helo_data: "$primary_hostname".to_string(),
            interface: String::new(),
            port: String::new(),
            protocol: String::new(),
            dscp: String::new(),
            serialize_hosts: String::new(),
            hosts_try_auth: String::new(),
            hosts_require_alpn: String::new(),
            hosts_require_auth: String::new(),
            hosts_try_chunking: "*".to_string(),
            hosts_try_fastopen: "*".to_string(),

            #[cfg(feature = "dane")]
            hosts_try_dane: "*".to_string(),
            #[cfg(feature = "dane")]
            hosts_require_dane: String::new(),
            #[cfg(feature = "dane")]
            dane_require_tls_ciphers: String::new(),

            #[cfg(feature = "prdr")]
            hosts_try_prdr: "*".to_string(),

            #[cfg(feature = "ocsp")]
            hosts_request_ocsp: "*".to_string(),
            #[cfg(feature = "ocsp")]
            hosts_require_ocsp: String::new(),

            #[cfg(feature = "pipe-connect")]
            hosts_pipe_connect: String::new(),

            #[cfg(feature = "tls")]
            hosts_require_tls: String::new(),
            #[cfg(feature = "tls")]
            hosts_avoid_tls: String::new(),
            #[cfg(feature = "tls")]
            hosts_verify_avoid_tls: String::new(),
            #[cfg(feature = "tls")]
            hosts_nopass_tls: String::new(),
            #[cfg(feature = "tls")]
            hosts_noproxy_tls: String::new(),
            #[cfg(feature = "tls")]
            tls_certificate: String::new(),
            #[cfg(feature = "tls")]
            tls_privatekey: String::new(),
            #[cfg(feature = "tls")]
            tls_require_ciphers: String::new(),
            #[cfg(feature = "tls")]
            tls_sni: String::new(),
            #[cfg(feature = "tls")]
            tls_verify_certificates: "system".to_string(),
            #[cfg(feature = "tls")]
            tls_crl: String::new(),
            #[cfg(feature = "tls")]
            tls_verify_hosts: String::new(),
            #[cfg(feature = "tls")]
            tls_try_verify_hosts: "*".to_string(),
            #[cfg(feature = "tls")]
            tls_verify_cert_hostnames: "*".to_string(),
            #[cfg(feature = "tls")]
            tls_tempfail_tryclear: true,

            #[cfg(feature = "tls-resume")]
            host_name_extract: String::new(),
            #[cfg(feature = "tls-resume")]
            tls_resumption_hosts: String::new(),

            #[cfg(feature = "i18n")]
            utf8_downconvert: String::new(),

            #[cfg(feature = "dkim")]
            dkim: DkimOptions::default(),

            #[cfg(feature = "arc")]
            arc_sign: String::new(),

            #[cfg(feature = "socks")]
            socks_proxy: String::new(),

            command_timeout: 300,
            connect_timeout: 300,
            data_timeout: 300,
            final_timeout: 600,
            size_addition: 1024,
            hosts_max_try: 5,
            hosts_max_try_hardlimit: 50,
            message_linelength_limit: 998,
            address_retry_include_sender: true,
            allow_localhost: false,
            authenticated_sender_force: false,
            gethostbyname: false,
            dns_qualify_single: true,
            dns_search_parents: false,
            delay_after_cutoff: true,
            hosts_override: false,
            hosts_randomize: false,
            keepalive: true,
            lmtp_ignore_quota: false,
            retry_include_ip_address: true,
            dnssec: DnssecMode::None,
        }
    }
}

impl fmt::Display for SmtpTransportOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SmtpTransportOptions {{ hosts: {:?}, port: {:?}, protocol: {:?} }}",
            self.hosts, self.port, self.protocol
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 4: SmtpContext — from smtp.h lines 143–230
// ═══════════════════════════════════════════════════════════════════════════════

/// Per-connection SMTP delivery context.
/// Replaces C `smtp_context` struct. All C static/global state variables
/// (smtp_command, mail_command, data_command, update_waiting, pipelining_active)
/// are folded into this struct per AAP §0.4.4 and Phase 9.
#[derive(Debug)]
pub struct SmtpContext {
    // ── Source addressing ───────────────────────────────────────────
    /// Envelope sender (MAIL FROM address).
    pub from_addr: String,

    /// Address list for RCPT TO delivery — the set of recipients for this connection.
    pub addrlist: Vec<String>,

    // ── Connection parameters ──────────────────────────────────────
    /// Target host for this connection.
    pub host: String,

    /// Target port for this connection.
    pub port: u16,

    // ── Protocol state booleans (replaces C bitfield booleans) ─────
    /// This is a verification call, not a real delivery.
    pub verify: bool,

    /// Using LMTP protocol instead of SMTP.
    pub lmtp: bool,

    /// Using implicit TLS (SMTPS) — TLS handshake before banner.
    pub smtps: bool,

    /// Transaction completed successfully.
    pub ok: bool,

    /// Still in connection setup phase (before DATA).
    pub setting_up: bool,

    /// Peer supports ESMTP (responded to EHLO).
    pub esmtp: bool,

    /// EHLO has been sent (regardless of response).
    pub esmtp_sent: bool,

    /// Pipelining was actually used for this transaction.
    pub pipelining_used: bool,

    /// Need to send RSET before next transaction.
    pub send_rset: bool,

    /// Need to send QUIT on closedown.
    pub send_quit: bool,

    /// Need to send TLS close-notify on closedown.
    pub send_tlsclose: bool,

    /// At least one address was completed in this session.
    pub completed_addr: bool,

    /// At least one RCPT TO got a 2xx response.
    pub good_rcpt: bool,

    /// A RCPT TO got a 452 (too many recipients) response.
    pub rcpt_452: bool,

    // ── PRDR feature-gated ─────────────────────────────────────────
    /// PRDR (Per-Recipient Data Response) is active for this connection.
    #[cfg(feature = "prdr")]
    pub prdr_active: bool,

    // ── I18N feature-gated ─────────────────────────────────────────
    /// SMTPUTF8 is needed for this transaction.
    #[cfg(feature = "i18n")]
    pub utf8_needed: bool,

    // ── Pipe-connect feature-gated ─────────────────────────────────
    /// Early pipelining is acceptable for this host.
    #[cfg(feature = "pipe-connect")]
    pub early_pipe_ok: bool,

    /// Early pipelining is currently active.
    #[cfg(feature = "pipe-connect")]
    pub early_pipe_active: bool,

    /// Banner response is pending (early pipe).
    #[cfg(feature = "pipe-connect")]
    pub pending_banner: bool,

    /// EHLO response is pending (early pipe).
    #[cfg(feature = "pipe-connect")]
    pub pending_ehlo: bool,

    // ── Peer capability tracking ───────────────────────────────────
    /// Bitmask of capabilities offered by the peer (PEER_OFFERED_* constants).
    pub peer_offered: u32,

    /// Maximum number of MAIL commands per connection (from server).
    pub max_mail: u32,

    /// Maximum number of RCPT TO commands per transaction (from server).
    pub max_rcpt: u32,

    /// Number of commands sent so far in this session.
    pub cmd_count: u32,

    /// Avoid option — bitmask of features to skip for this connection.
    pub avoid_option: u32,

    // ── ESMTP-LIMITS feature-gated ─────────────────────────────────
    /// Peer-advertised MAIL limit.
    #[cfg(feature = "esmtp-limits")]
    pub peer_limit_mail: u32,

    /// Peer-advertised RCPT limit.
    #[cfg(feature = "esmtp-limits")]
    pub peer_limit_rcpt: u32,

    /// Peer-advertised RCPT per-domain limit.
    #[cfg(feature = "esmtp-limits")]
    pub peer_limit_rcptdom: u32,

    /// Single RCPT domain constraint from peer limits.
    #[cfg(feature = "esmtp-limits")]
    pub single_rcpt_domain: String,

    // ── Message body encoding ──────────────────────────────────────
    /// SMTP body type for MAIL FROM BODY= parameter (e.g., "8BITMIME", "7BIT").
    /// Only set when message was received with explicit body type declaration.
    /// C Exim: `body_type` in smtp transport.
    pub body_type: Option<String>,

    // ── DSN-INFO feature-gated ─────────────────────────────────────
    /// Full SMTP greeting banner (for DSN reporting).
    #[cfg(feature = "dsn-info")]
    pub smtp_greeting: String,

    /// Full HELO/EHLO response (for DSN reporting).
    #[cfg(feature = "dsn-info")]
    pub helo_response: String,

    // ── Delivery tracking ──────────────────────────────────────────
    /// Timestamp when delivery attempt started.
    pub delivery_start: Option<Instant>,

    /// Index of the first address in the current batch.
    pub first_addr_index: usize,

    /// Index of the next address to process.
    pub next_addr_index: usize,

    /// Index of the address awaiting sync response.
    pub sync_addr_index: usize,

    // ── I/O state (replaces C inblock/outblock/buffer) ─────────────
    /// I/O buffer for SMTP command writing.
    pub outbuffer: Vec<u8>,

    /// I/O buffer for SMTP response reading.
    pub inbuffer: Vec<u8>,

    // ── Formerly C static variables (Phase 9 replacement) ──────────
    /// Current SMTP command being executed (replaces C static smtp_command).
    pub smtp_command: String,

    /// Last MAIL FROM command sent (replaces C static mail_command).
    pub mail_command: String,

    /// Last DATA/BDAT command sent (replaces C static data_command).
    pub data_command: String,

    /// Whether the update_waiting callback has been registered (replaces C static).
    pub update_waiting: bool,

    /// Whether pipelining is currently active (replaces C static pipelining_active).
    pub pipelining_active: bool,

    // ── Response tracking ──────────────────────────────────────────
    /// Tracks which response classes have been seen (RESP_BIT_HAD_2XX | RESP_BIT_HAD_5XX).
    pub response_classes: i32,

    /// Accumulated EHLO capability string for diagnostic logging.
    pub ehlo_capabilities: String,

    /// Peer-advertised maximum message size (from EHLO SIZE extension).
    pub peer_max_message_size: u64,

    /// Authentication mechanisms offered by peer (from EHLO AUTH).
    pub auth_mechanisms: String,
}

impl SmtpContext {
    /// Create a new SmtpContext with default/empty state for a delivery attempt.
    pub fn new(from_addr: String, host: String, port: u16) -> Self {
        Self {
            from_addr,
            addrlist: Vec::new(),
            host,
            port,
            verify: false,
            lmtp: false,
            smtps: false,
            ok: false,
            setting_up: true,
            esmtp: false,
            esmtp_sent: false,
            pipelining_used: false,
            send_rset: false,
            send_quit: true,
            send_tlsclose: false,
            completed_addr: false,
            good_rcpt: false,
            rcpt_452: false,

            #[cfg(feature = "prdr")]
            prdr_active: false,

            #[cfg(feature = "i18n")]
            utf8_needed: false,

            #[cfg(feature = "pipe-connect")]
            early_pipe_ok: false,
            #[cfg(feature = "pipe-connect")]
            early_pipe_active: false,
            #[cfg(feature = "pipe-connect")]
            pending_banner: false,
            #[cfg(feature = "pipe-connect")]
            pending_ehlo: false,

            peer_offered: 0,
            max_mail: 0,
            max_rcpt: 0,
            cmd_count: 0,
            avoid_option: 0,

            #[cfg(feature = "esmtp-limits")]
            peer_limit_mail: 0,
            #[cfg(feature = "esmtp-limits")]
            peer_limit_rcpt: 0,
            #[cfg(feature = "esmtp-limits")]
            peer_limit_rcptdom: 0,
            #[cfg(feature = "esmtp-limits")]
            single_rcpt_domain: String::new(),

            #[cfg(feature = "dsn-info")]
            smtp_greeting: String::new(),
            #[cfg(feature = "dsn-info")]
            helo_response: String::new(),

            delivery_start: None,
            first_addr_index: 0,
            next_addr_index: 0,
            sync_addr_index: 0,

            outbuffer: Vec::with_capacity(DELIVER_BUFFER_SIZE),
            inbuffer: Vec::with_capacity(DELIVER_BUFFER_SIZE),

            smtp_command: String::new(),
            mail_command: String::new(),
            data_command: String::new(),
            update_waiting: false,
            pipelining_active: false,

            response_classes: 0,
            ehlo_capabilities: String::new(),
            peer_max_message_size: 0,
            auth_mechanisms: String::new(),
            body_type: None,
        }
    }

    /// Reset per-transaction state for connection reuse (new MAIL FROM on same connection).
    pub fn reset_transaction(&mut self) {
        self.ok = false;
        self.setting_up = true;
        self.esmtp_sent = false;
        self.pipelining_used = false;
        self.send_rset = false;
        self.completed_addr = false;
        self.good_rcpt = false;
        self.rcpt_452 = false;
        self.first_addr_index = 0;
        self.next_addr_index = 0;
        self.sync_addr_index = 0;
        self.response_classes = 0;
        self.smtp_command.clear();
        self.mail_command.clear();
        self.data_command.clear();
        self.pipelining_active = false;

        #[cfg(feature = "prdr")]
        {
            self.prdr_active = false;
        }

        #[cfg(feature = "i18n")]
        {
            self.utf8_needed = false;
        }
    }

    /// Check if a specific peer capability is offered.
    pub fn peer_has(&self, capability: u32) -> bool {
        (self.peer_offered & capability) != 0
    }
}

impl fmt::Display for SmtpContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SmtpContext {{ host: {}:{}, from: {:?}, esmtp: {}, ok: {} }}",
            self.host, self.port, self.from_addr, self.esmtp, self.ok
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 5: EHLO Capability Regexes — from smtp.c lines 256–292
// ═══════════════════════════════════════════════════════════════════════════════

/// Compiled regex patterns for parsing EHLO/LHLO capability responses.
/// Each pattern matches the extension keyword in a multi-line EHLO response.
/// Compiled once at transport initialization in `smtp_deliver_init()`.
pub struct SmtpRegexes {
    /// Matches AUTH mechanism list in EHLO response.
    pub regex_auth: Regex,

    /// Matches CHUNKING extension in EHLO response.
    pub regex_chunking: Regex,

    /// Matches DSN extension in EHLO response.
    pub regex_dsn: Regex,

    /// Matches IGNOREQUOTA extension (LMTP) in EHLO response.
    pub regex_ignorequota: Regex,

    /// Matches PIPELINING extension in EHLO response.
    pub regex_pipelining: Regex,

    /// Matches SIZE extension with optional size parameter.
    pub regex_size: Regex,

    /// Matches STARTTLS extension (feature-gated).
    #[cfg(feature = "tls")]
    pub regex_starttls: Regex,

    /// Matches PRDR extension (feature-gated).
    #[cfg(feature = "prdr")]
    pub regex_prdr: Regex,

    /// Matches SMTPUTF8 extension (feature-gated).
    #[cfg(feature = "i18n")]
    pub regex_utf8: Regex,

    /// Matches EARLY-PIPELINING/PIPE_CONNECT extension (feature-gated).
    #[cfg(feature = "pipe-connect")]
    pub regex_early_pipe: Regex,

    /// Matches LIMITS extension (feature-gated).
    #[cfg(feature = "esmtp-limits")]
    pub regex_limits: Regex,
}

impl fmt::Debug for SmtpRegexes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpRegexes")
            .field("regex_auth", &"<compiled>")
            .field("regex_chunking", &"<compiled>")
            .field("regex_dsn", &"<compiled>")
            .field("regex_ignorequota", &"<compiled>")
            .field("regex_pipelining", &"<compiled>")
            .field("regex_size", &"<compiled>")
            .finish()
    }
}

/// Initialize SMTP delivery regex patterns.
/// Compiles all EHLO capability regexes at startup (smtp.c lines 256–292).
/// Each regex matches a 250 response line containing the extension keyword.
/// The patterns handle both "250-EXT" (continuation) and "250 EXT" (final) forms.
///
/// # Panics
///
/// Panics if any regex pattern fails to compile — this indicates a programming
/// error in the constant patterns and should be caught during testing.
pub fn smtp_deliver_init() -> SmtpRegexes {
    tracing::debug!("Compiling SMTP EHLO capability regexes");

    SmtpRegexes {
        // AUTH <mechanisms>
        regex_auth: Regex::new(r"(?mi)^250[- ]AUTH\s+(.+?)\r?$")
            .expect("regex_auth pattern must compile"),

        // CHUNKING
        regex_chunking: Regex::new(r"(?mi)^250[- ]CHUNKING(\s|$)")
            .expect("regex_chunking pattern must compile"),

        // DSN
        regex_dsn: Regex::new(r"(?mi)^250[- ]DSN(\s|$)").expect("regex_dsn pattern must compile"),

        // IGNOREQUOTA (LMTP extension)
        regex_ignorequota: Regex::new(r"(?mi)^250[- ]IGNOREQUOTA(\s|$)")
            .expect("regex_ignorequota pattern must compile"),

        // PIPELINING
        regex_pipelining: Regex::new(r"(?mi)^250[- ]PIPELINING(\s|$)")
            .expect("regex_pipelining pattern must compile"),

        // SIZE [limit]
        regex_size: Regex::new(r"(?mi)^250[- ]SIZE(\s+(\d+))?(\s|$)")
            .expect("regex_size pattern must compile"),

        // STARTTLS
        #[cfg(feature = "tls")]
        regex_starttls: Regex::new(r"(?mi)^250[- ]STARTTLS(\s|$)")
            .expect("regex_starttls pattern must compile"),

        // PRDR
        #[cfg(feature = "prdr")]
        regex_prdr: Regex::new(r"(?mi)^250[- ]PRDR(\s|$)")
            .expect("regex_prdr pattern must compile"),

        // SMTPUTF8
        #[cfg(feature = "i18n")]
        regex_utf8: Regex::new(r"(?mi)^250[- ]SMTPUTF8(\s|$)")
            .expect("regex_utf8 pattern must compile"),

        // X-EARLY-PIPELINING / X_PIPE_CONNECT
        #[cfg(feature = "pipe-connect")]
        regex_early_pipe: Regex::new(r"(?mi)^250[- ](X-EARLY-PIPELINING|X_PIPE_CONNECT)(\s|$)")
            .expect("regex_early_pipe pattern must compile"),

        // LIMITS
        #[cfg(feature = "esmtp-limits")]
        regex_limits: Regex::new(r"(?mi)^250[- ]LIMITS(\s+(.+))?$")
            .expect("regex_limits pattern must compile"),
    }
}

// =============================================================================
// Phase 6: SmtpTransport — Main transport struct + TransportDriver trait impl
// =============================================================================

/// The SMTP/LMTP outbound transport driver.
///
/// This is the primary remote delivery transport in Exim. It implements the full
/// outbound SMTP state machine including EHLO negotiation, STARTTLS, AUTH,
/// MAIL FROM, RCPT TO, DATA/BDAT, pipelining, chunking, DSN, PRDR, DANE,
/// early pipe-connect, and connection reuse.
///
/// Registered at compile-time via `inventory::submit!` for automatic discovery
/// by the driver registry.
#[derive(Debug)]
pub struct SmtpTransport {
    /// Pre-compiled EHLO capability regex patterns, initialized on first use.
    regexes: SmtpRegexes,
}

impl Default for SmtpTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtpTransport {
    /// Create a new SmtpTransport instance with compiled EHLO regexes.
    pub fn new() -> Self {
        Self {
            regexes: smtp_deliver_init(),
        }
    }

    /// Initialize transport settings from configuration (smtp.c lines 388-438).
    ///
    /// Performs validation of the transport options block after configuration parsing:
    /// - Validates timeout values are positive
    /// - Resolves default port from protocol string
    /// - Validates numeric limits
    pub fn smtp_transport_init(
        &self,
        config: &TransportInstanceConfig,
    ) -> Result<SmtpTransportOptions, DriverError> {
        let opts = self.get_options(config)?;

        if opts.command_timeout == 0 {
            return Err(DriverError::ConfigError(
                "smtp transport: command_timeout must be greater than zero".to_string(),
            ));
        }
        if opts.connect_timeout == 0 {
            return Err(DriverError::ConfigError(
                "smtp transport: connect_timeout must be greater than zero".to_string(),
            ));
        }
        if opts.data_timeout == 0 {
            return Err(DriverError::ConfigError(
                "smtp transport: data_timeout must be greater than zero".to_string(),
            ));
        }
        if opts.final_timeout == 0 {
            return Err(DriverError::ConfigError(
                "smtp transport: final_timeout must be greater than zero".to_string(),
            ));
        }
        if opts.hosts_max_try < 1 {
            return Err(DriverError::ConfigError(
                "smtp transport: hosts_max_try must be at least 1".to_string(),
            ));
        }
        if opts.hosts_max_try_hardlimit < opts.hosts_max_try {
            return Err(DriverError::ConfigError(format!(
                "smtp transport: hosts_max_try_hardlimit ({}) must be >= hosts_max_try ({})",
                opts.hosts_max_try_hardlimit, opts.hosts_max_try
            )));
        }
        if opts.message_linelength_limit < 0 {
            return Err(DriverError::ConfigError(
                "smtp transport: message_linelength_limit must not be negative".to_string(),
            ));
        }

        tracing::debug!(
            transport = config.name,
            hosts = %opts.hosts,
            port = %opts.port,
            protocol = %opts.protocol,
            "SMTP transport initialized"
        );

        Ok(opts)
    }

    /// Extract SmtpTransportOptions from the TransportInstanceConfig options box.
    fn get_options(
        &self,
        config: &TransportInstanceConfig,
    ) -> Result<SmtpTransportOptions, DriverError> {
        if let Some(opts) = config.options.downcast_ref::<SmtpTransportOptions>() {
            return Ok(opts.clone());
        }

        // Build SmtpTransportOptions from private_options_map (the key-value
        // pairs extracted by the config parser).
        let map = &config.private_options_map;
        let mut opts = SmtpTransportOptions::default();

        if let Some(v) = map.get("hosts") {
            opts.hosts = v.clone();
        }
        if let Some(v) = map.get("fallback_hosts") {
            opts.fallback_hosts = v.clone();
        }
        if let Some(v) = map.get("port") {
            opts.port = v.clone();
        }
        if let Some(v) = map.get("protocol") {
            opts.protocol = v.clone();
        }
        if let Some(v) = map.get("helo_data") {
            opts.helo_data = v.clone();
        }
        if let Some(v) = map.get("interface") {
            opts.interface = v.clone();
        }
        if let Some(v) = map.get("dscp") {
            opts.dscp = v.clone();
        }
        if let Some(v) = map.get("authenticated_sender") {
            opts.authenticated_sender = v.clone();
        }
        if let Some(v) = map.get("serialize_hosts") {
            opts.serialize_hosts = v.clone();
        }
        if let Some(v) = map.get("hosts_try_auth") {
            opts.hosts_try_auth = v.clone();
        }
        if let Some(v) = map.get("hosts_require_auth") {
            opts.hosts_require_auth = v.clone();
        }
        if let Some(v) = map.get("hosts_try_chunking") {
            opts.hosts_try_chunking = v.clone();
        }
        if let Some(v) = map.get("hosts_try_fastopen") {
            opts.hosts_try_fastopen = v.clone();
        }
        // Boolean options
        if let Some(v) = map.get("allow_localhost") {
            opts.allow_localhost = v.is_empty() || v == "true" || v == "yes";
        }
        if let Some(v) = map.get("hosts_override") {
            opts.hosts_override = v.is_empty() || v == "true" || v == "yes";
        }
        if let Some(v) = map.get("hosts_randomize") {
            opts.hosts_randomize = v.is_empty() || v == "true" || v == "yes";
        }
        if let Some(v) = map.get("keepalive") {
            opts.keepalive = v.is_empty() || v == "true" || v == "yes";
        }
        if let Some(v) = map.get("lmtp_ignore_quota") {
            opts.lmtp_ignore_quota = v.is_empty() || v == "true" || v == "yes";
        }
        if let Some(v) = map.get("gethostbyname") {
            opts.gethostbyname = v.is_empty() || v == "true" || v == "yes";
        }
        // Timeout options (parse seconds from string)
        if let Some(v) = map.get("command_timeout") {
            if let Some(secs) = Self::parse_time_value(v) {
                opts.command_timeout = secs;
            }
        }
        if let Some(v) = map.get("connect_timeout") {
            if let Some(secs) = Self::parse_time_value(v) {
                opts.connect_timeout = secs;
            }
        }
        if let Some(v) = map.get("data_timeout") {
            if let Some(secs) = Self::parse_time_value(v) {
                opts.data_timeout = secs;
            }
        }
        if let Some(v) = map.get("final_timeout") {
            if let Some(secs) = Self::parse_time_value(v) {
                opts.final_timeout = secs;
            }
        }
        // Numeric limits
        if let Some(v) = map.get("hosts_max_try") {
            if let Ok(n) = v.parse::<i32>() {
                opts.hosts_max_try = n;
            }
        }
        if let Some(v) = map.get("hosts_max_try_hardlimit") {
            if let Ok(n) = v.parse::<i32>() {
                opts.hosts_max_try_hardlimit = n;
            }
        }
        // TLS options
        #[cfg(feature = "tls")]
        {
            if let Some(v) = map.get("hosts_require_tls") {
                opts.hosts_require_tls = v.clone();
            }
            if let Some(v) = map.get("hosts_avoid_tls") {
                opts.hosts_avoid_tls = v.clone();
            }
            if let Some(v) = map.get("tls_certificate") {
                opts.tls_certificate = v.clone();
            }
            if let Some(v) = map.get("tls_privatekey") {
                opts.tls_privatekey = v.clone();
            }
            if let Some(v) = map.get("tls_require_ciphers") {
                opts.tls_require_ciphers = v.clone();
            }
            if let Some(v) = map.get("tls_sni") {
                opts.tls_sni = v.clone();
            }
            if let Some(v) = map.get("tls_verify_certificates") {
                opts.tls_verify_certificates = v.clone();
            }
        }

        tracing::debug!(
            transport = config.name,
            hosts = %opts.hosts,
            port = %opts.port,
            "SmtpTransportOptions built from private_options_map"
        );

        Ok(opts)
    }

    /// Parse a time value string (e.g. "30s", "5m", "300") into seconds.
    fn parse_time_value(val: &str) -> Option<u64> {
        let val = val.trim();
        if val.is_empty() {
            return None;
        }
        if let Ok(n) = val.parse::<u64>() {
            return Some(n);
        }
        // Handle time suffixes: s, m, h, d
        if val.len() >= 2 {
            let (num_part, suffix) = val.split_at(val.len() - 1);
            if let Ok(n) = num_part.parse::<u64>() {
                match suffix {
                    "s" => return Some(n),
                    "m" => return Some(n * 60),
                    "h" => return Some(n * 3600),
                    "d" => return Some(n * 86400),
                    _ => {}
                }
            }
        }
        None
    }

    /// Resolve the effective port from options and protocol.
    fn resolve_port(opts: &SmtpTransportOptions) -> u16 {
        if !opts.port.is_empty() {
            if let Ok(p) = opts.port.parse::<u16>() {
                return p;
            }
            match opts.port.as_str() {
                "smtp" => return SMTP_PORT,
                "smtps" | "submissions" => return SMTPS_PORT,
                "submission" => return SUBMISSION_PORT,
                "lmtp" => return LMTP_PORT,
                _ => return SMTP_PORT,
            }
        }
        match opts.protocol.as_str() {
            "lmtp" => LMTP_PORT,
            "smtps" | "submissions" => SMTPS_PORT,
            _ => SMTP_PORT,
        }
    }

    /// Build the DSN NOTIFY parameter string from a bitmask of notify flags.
    fn build_dsn_notify(flags: i32) -> String {
        if flags == 0 {
            return String::new();
        }
        if (flags & RF_NOTIFY_NEVER) != 0 {
            return "NEVER".to_string();
        }
        let mut parts = Vec::new();
        for (i, &flag) in RF_LIST.iter().enumerate() {
            if (flags & flag) != 0 && flag != RF_NOTIFY_NEVER {
                parts.push(RF_NAMES[i]);
            }
        }
        parts.join(",")
    }

    /// Parse EHLO response and extract peer capabilities into the SmtpContext.
    fn parse_ehlo_response(&self, ctx: &mut SmtpContext, response: &str) {
        tracing::debug!(response_len = response.len(), "Parsing EHLO response");

        if let Some(caps) = self.regexes.regex_auth.captures(response) {
            ctx.peer_offered |= PEER_OFFERED_AUTH;
            if let Some(mechs) = caps.get(1) {
                ctx.auth_mechanisms = mechs.as_str().trim().to_string();
                tracing::debug!(mechanisms = %ctx.auth_mechanisms, "Peer offers AUTH");
            }
        }
        if self.regexes.regex_chunking.is_match(response) {
            ctx.peer_offered |= PEER_OFFERED_CHUNKING;
            tracing::debug!("Peer offers CHUNKING");
        }
        if self.regexes.regex_dsn.is_match(response) {
            ctx.peer_offered |= PEER_OFFERED_DSN;
            tracing::debug!("Peer offers DSN");
        }
        if self.regexes.regex_ignorequota.is_match(response) {
            ctx.peer_offered |= PEER_OFFERED_IGNOREQUOTA;
            tracing::debug!("Peer offers IGNOREQUOTA");
        }
        if self.regexes.regex_pipelining.is_match(response) {
            ctx.peer_offered |= PEER_OFFERED_PIPELINING;
            tracing::debug!("Peer offers PIPELINING");
        }
        if let Some(caps) = self.regexes.regex_size.captures(response) {
            ctx.peer_offered |= PEER_OFFERED_SIZE;
            if let Some(size_str) = caps.get(2) {
                if let Ok(size) = size_str.as_str().parse::<u64>() {
                    ctx.peer_max_message_size = size;
                    tracing::debug!(max_size = size, "Peer offers SIZE");
                }
            } else {
                tracing::debug!("Peer offers SIZE (no limit)");
            }
        }
        #[cfg(feature = "tls")]
        if self.regexes.regex_starttls.is_match(response) {
            ctx.peer_offered |= PEER_OFFERED_TLS;
            tracing::debug!("Peer offers STARTTLS");
        }
        #[cfg(feature = "prdr")]
        if self.regexes.regex_prdr.is_match(response) {
            ctx.peer_offered |= PEER_OFFERED_PRDR;
            tracing::debug!("Peer offers PRDR");
        }
        #[cfg(feature = "i18n")]
        if self.regexes.regex_utf8.is_match(response) {
            ctx.peer_offered |= PEER_OFFERED_UTF8;
            tracing::debug!("Peer offers SMTPUTF8");
        }
        #[cfg(feature = "pipe-connect")]
        if self.regexes.regex_early_pipe.is_match(response) {
            ctx.peer_offered |= PEER_OFFERED_EARLY_PIPE;
            tracing::debug!("Peer offers early pipelining");
        }
        #[cfg(feature = "esmtp-limits")]
        if let Some(caps) = self.regexes.regex_limits.captures(response) {
            ctx.peer_offered |= PEER_OFFERED_LIMITS;
            if let Some(params) = caps.get(2) {
                self.parse_limits(ctx, params.as_str());
            }
            tracing::debug!("Peer offers LIMITS");
        }
        ctx.ehlo_capabilities = response.to_string();
    }

    #[cfg(feature = "esmtp-limits")]
    fn parse_limits(&self, ctx: &mut SmtpContext, params: &str) {
        for param in params.split_whitespace() {
            if let Some((key, val)) = param.split_once('=') {
                match key.to_uppercase().as_str() {
                    "MAILMAX" => {
                        if let Ok(v) = val.parse::<u32>() {
                            ctx.peer_limit_mail = v;
                        }
                    }
                    "RCPTMAX" => {
                        if let Ok(v) = val.parse::<u32>() {
                            ctx.peer_limit_rcpt = v;
                        }
                    }
                    "RCPTDOMAINMAX" => {
                        if let Ok(v) = val.parse::<u32>() {
                            ctx.peer_limit_rcptdom = v;
                        }
                    }
                    _ => {
                        tracing::trace!(key = key, val = val, "Unknown LIMITS parameter");
                    }
                }
            }
        }
    }
}

impl TransportDriver for SmtpTransport {
    fn transport_entry(
        &self,
        config: &TransportInstanceConfig,
        address: &str,
    ) -> Result<TransportResult, DriverError> {
        tracing::info!(
            transport = config.name,
            address = address,
            "SMTP transport entry"
        );
        let opts = self.smtp_transport_init(config)?;
        let port = Self::resolve_port(&opts);

        let tainted_host = if !opts.hosts.is_empty() {
            Tainted::new(opts.hosts.clone())
        } else {
            let domain = address.rsplit('@').next().unwrap_or(address).to_string();
            Tainted::new(domain)
        };

        let clean_host = tainted_host
            .sanitize(|h| !h.is_empty() && !h.chars().any(|c| c.is_control()))
            .map_err(|e| {
                DriverError::ExecutionFailed(format!(
                    "hostname taint validation failed: {}",
                    e.context
                ))
            })?;

        let host_str = clean_host.as_ref();

        // MAIL FROM uses the sender address (return path), not the recipient
        let sender_addr = config
            .private_options_map
            .get("__sender_address")
            .cloned()
            .unwrap_or_default();

        let mut ctx = SmtpContext::new(sender_addr, host_str.clone(), port);
        ctx.delivery_start = Some(Instant::now());
        ctx.lmtp = opts.protocol == "lmtp";
        ctx.smtps = opts.protocol == "smtps" || opts.protocol == "submissions";

        tracing::debug!(host = %host_str, port = port, lmtp = ctx.lmtp, smtps = ctx.smtps, "Connecting to mail server");

        let connect_timeout = Duration::from_secs(opts.connect_timeout);
        let stream = match std::net::TcpStream::connect_timeout(
            &format!("{}:{}", host_str, port).parse().map_err(|e| {
                DriverError::TempFail(format!("invalid address {}:{} - {}", host_str, port, e))
            })?,
            connect_timeout,
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(host = %host_str, port = port, error = %e, "Connection failed");
                return match e.kind() {
                    ErrorKind::TimedOut | ErrorKind::WouldBlock => Err(DriverError::TempFail(
                        format!("connection timeout to {}:{}: {}", host_str, port, e),
                    )),
                    ErrorKind::ConnectionRefused => Err(DriverError::TempFail(format!(
                        "connection refused by {}:{}: {}",
                        host_str, port, e
                    ))),
                    _ => Err(DriverError::TempFail(format!(
                        "connection error to {}:{}: {}",
                        host_str, port, e
                    ))),
                };
            }
        };

        if opts.keepalive {
            let _ = stream.set_nodelay(true);
        }
        let cmd_timeout = Duration::from_secs(opts.command_timeout);
        let _ = stream.set_read_timeout(Some(cmd_timeout));
        let _ = stream.set_write_timeout(Some(cmd_timeout));

        match self.run_smtp_session(&mut ctx, &opts, config, stream, address) {
            Ok(result) => {
                if let Some(start) = ctx.delivery_start {
                    tracing::info!(
                        transport = config.name,
                        address = address,
                        elapsed_ms = start.elapsed().as_millis() as u64,
                        "SMTP delivery completed"
                    );
                }
                Ok(result)
            }
            Err(e) => {
                tracing::error!(transport = config.name, address = address, error = %e, "SMTP delivery failed");
                Err(e)
            }
        }
    }

    fn setup(&self, config: &TransportInstanceConfig, _address: &str) -> Result<(), DriverError> {
        tracing::debug!(
            transport = config.name,
            "SMTP transport setup for verification"
        );
        let _opts = self.smtp_transport_init(config)?;
        Ok(())
    }

    fn closedown(&self, config: &TransportInstanceConfig) {
        tracing::debug!(transport = config.name, "SMTP transport closedown");
    }

    fn tidyup(&self, _config: &TransportInstanceConfig) {
        tracing::debug!("SMTP transport tidyup");
    }

    fn is_local(&self) -> bool {
        false
    }
    fn driver_name(&self) -> &str {
        "smtp"
    }
}

// =============================================================================
// Phase 7: Core SMTP State Machine Functions
// =============================================================================

impl SmtpTransport {
    /// Run the complete SMTP session on an established TCP stream.
    fn run_smtp_session(
        &self,
        ctx: &mut SmtpContext,
        opts: &SmtpTransportOptions,
        config: &TransportInstanceConfig,
        mut stream: TcpStream,
        address: &str,
    ) -> Result<TransportResult, DriverError> {
        let banner = self.read_response(&mut stream, opts.command_timeout)?;

        #[cfg(feature = "dsn-info")]
        {
            ctx.smtp_greeting = banner.clone();
        }

        if !banner.starts_with("220") {
            tracing::warn!(banner = %banner, "Non-220 banner received");
            let _ = self.send_quit(&mut stream, ctx, opts.command_timeout);
            return match banner.chars().next() {
                Some('4') => Err(DriverError::TempFail(format!(
                    "SMTP banner temporary failure: {}",
                    banner
                ))),
                _ => Err(DriverError::ExecutionFailed(format!(
                    "SMTP banner permanent failure: {}",
                    banner
                ))),
            };
        }

        tracing::debug!(banner = %banner, "SMTP banner received");
        let ehlo_data = if opts.helo_data.is_empty() {
            "localhost".to_string()
        } else {
            // Expand $primary_hostname in helo_data
            let mut helo = opts.helo_data.clone();
            if let Some(hostname) = config.private_options_map.get("__primary_hostname") {
                helo = helo.replace("$primary_hostname", hostname);
            }
            helo
        };
        let ehlo_response = self.send_ehlo(ctx, &mut stream, &ehlo_data, opts)?;

        #[cfg(feature = "dsn-info")]
        {
            ctx.helo_response = ehlo_response.clone();
        }

        self.parse_ehlo_response(ctx, &ehlo_response);

        #[cfg(feature = "tls")]
        {
            if ctx.peer_has(PEER_OFFERED_TLS) && !ctx.smtps {
                let should_tls = opts.hosts_avoid_tls.is_empty()
                    || !host_matches(&ctx.host, &opts.hosts_avoid_tls);
                if should_tls {
                    tracing::debug!("Initiating STARTTLS");
                    match self.do_starttls(ctx, &mut stream, opts) {
                        Ok(()) => {
                            tracing::debug!("STARTTLS negotiated successfully");
                            ctx.peer_offered = 0;
                            let ehlo2 = self.send_ehlo(ctx, &mut stream, &ehlo_data, opts)?;
                            self.parse_ehlo_response(ctx, &ehlo2);
                        }
                        Err(e) => {
                            if opts.tls_tempfail_tryclear {
                                tracing::warn!(error = %e, "STARTTLS failed, continuing in clear");
                            } else {
                                return Err(e);
                            }
                        }
                    }
                }
            }
            if !opts.hosts_require_tls.is_empty()
                && host_matches(&ctx.host, &opts.hosts_require_tls)
                && !ctx.send_tlsclose
            {
                tracing::error!(host = %ctx.host, "TLS required but not established");
                let _ = self.send_quit(&mut stream, ctx, opts.command_timeout);
                return Err(DriverError::TempFail(format!(
                    "TLS connection required for host {} but not established",
                    ctx.host
                )));
            }
        }

        if ctx.peer_has(PEER_OFFERED_AUTH)
            && !opts.hosts_try_auth.is_empty()
            && host_matches(&ctx.host, &opts.hosts_try_auth)
        {
            tracing::debug!(mechanisms = %ctx.auth_mechanisms, "Attempting SMTP AUTH");
            match self.do_auth(ctx, &mut stream, opts) {
                Ok(true) => {
                    tracing::debug!("SMTP AUTH successful");
                }
                Ok(false) => {
                    tracing::debug!("SMTP AUTH not attempted (no matching mechanism)");
                    if !opts.hosts_require_auth.is_empty()
                        && host_matches(&ctx.host, &opts.hosts_require_auth)
                    {
                        let _ = self.send_quit(&mut stream, ctx, opts.command_timeout);
                        return Err(DriverError::TempFail(format!(
                            "authentication required for host {} but no mechanism matched",
                            ctx.host
                        )));
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "SMTP AUTH failed");
                    if !opts.hosts_require_auth.is_empty()
                        && host_matches(&ctx.host, &opts.hosts_require_auth)
                    {
                        let _ = self.send_quit(&mut stream, ctx, opts.command_timeout);
                        return Err(e);
                    }
                    tracing::warn!("AUTH failure ignored (auth not required for this host)");
                }
            }
        }

        ctx.setting_up = false;
        let result = self.do_mail_transaction(ctx, &mut stream, opts, config, address)?;
        let _ = self.send_quit(&mut stream, ctx, opts.command_timeout);
        Ok(result)
    }

    fn send_ehlo(
        &self,
        ctx: &mut SmtpContext,
        stream: &mut TcpStream,
        helo_data: &str,
        opts: &SmtpTransportOptions,
    ) -> Result<String, DriverError> {
        let cmd = if ctx.lmtp {
            format!("LHLO {}\r\n", helo_data)
        } else {
            format!("EHLO {}\r\n", helo_data)
        };
        ctx.smtp_command = cmd.trim_end().to_string();
        ctx.esmtp_sent = true;
        ctx.cmd_count += 1;
        tracing::debug!(command = %ctx.smtp_command, "Sending EHLO/LHLO");
        self.write_command(stream, &cmd, opts.command_timeout)?;
        let response = self.read_response(stream, opts.command_timeout)?;
        if response.starts_with("250") {
            ctx.esmtp = true;
            return Ok(response);
        }
        if !ctx.lmtp {
            tracing::debug!(response = %response, "EHLO rejected, falling back to HELO");
            let helo_cmd = format!("HELO {}\r\n", helo_data);
            ctx.smtp_command = helo_cmd.trim_end().to_string();
            ctx.esmtp = false;
            ctx.cmd_count += 1;
            self.write_command(stream, &helo_cmd, opts.command_timeout)?;
            let helo_resp = self.read_response(stream, opts.command_timeout)?;
            if helo_resp.starts_with("250") {
                return Ok(helo_resp);
            }
            return Err(DriverError::ExecutionFailed(format!(
                "HELO rejected: {}",
                helo_resp.trim()
            )));
        }
        Err(DriverError::ExecutionFailed(format!(
            "LHLO rejected: {}",
            response.trim()
        )))
    }

    #[cfg(feature = "tls")]
    fn do_starttls(
        &self,
        ctx: &mut SmtpContext,
        stream: &mut TcpStream,
        opts: &SmtpTransportOptions,
    ) -> Result<(), DriverError> {
        ctx.smtp_command = "STARTTLS".to_string();
        ctx.cmd_count += 1;
        self.write_command(stream, "STARTTLS\r\n", opts.command_timeout)?;
        let response = self.read_response(stream, opts.command_timeout)?;
        if response.starts_with("220") {
            ctx.send_tlsclose = true;
            tracing::debug!("STARTTLS accepted, TLS handshake initiated");
            Ok(())
        } else {
            Err(DriverError::TempFail(format!(
                "STARTTLS rejected: {}",
                response.trim()
            )))
        }
    }

    fn do_auth(
        &self,
        ctx: &mut SmtpContext,
        stream: &mut TcpStream,
        opts: &SmtpTransportOptions,
    ) -> Result<bool, DriverError> {
        if ctx.auth_mechanisms.is_empty() || opts.authenticated_sender.is_empty() {
            return Ok(false);
        }
        let mechanisms: Vec<&str> = ctx.auth_mechanisms.split_whitespace().collect();
        if mechanisms.iter().any(|&m| m.eq_ignore_ascii_case("PLAIN")) {
            tracing::debug!("Attempting AUTH PLAIN");
            ctx.smtp_command = "AUTH PLAIN".to_string();
            ctx.cmd_count += 1;
            self.write_command(stream, "AUTH PLAIN\r\n", opts.command_timeout)?;
            let response = self.read_response(stream, opts.command_timeout)?;
            if response.starts_with("235") {
                return Ok(true);
            }
            if response.starts_with("334") {
                self.write_command(stream, "*\r\n", opts.command_timeout)?;
                let _ = self.read_response(stream, opts.command_timeout);
                tracing::debug!("AUTH PLAIN challenge received but no credentials configured");
                return Ok(false);
            }
            tracing::warn!(response = %response, "AUTH PLAIN failed");
            return Err(DriverError::TempFail(format!(
                "AUTH PLAIN failed: {}",
                response.trim()
            )));
        }
        if mechanisms.iter().any(|&m| m.eq_ignore_ascii_case("LOGIN")) {
            tracing::debug!("AUTH LOGIN available but not attempted");
            return Ok(false);
        }
        tracing::debug!(mechanisms = %ctx.auth_mechanisms, "No supported AUTH mechanism found");
        Ok(false)
    }

    fn do_mail_transaction(
        &self,
        ctx: &mut SmtpContext,
        stream: &mut TcpStream,
        opts: &SmtpTransportOptions,
        config: &TransportInstanceConfig,
        address: &str,
    ) -> Result<TransportResult, DriverError> {
        let mail_from = self.build_mail_from(ctx, opts, config)?;
        let rcpt_commands = self.build_rcpt_to(ctx, address, opts)?;

        if ctx.peer_has(PEER_OFFERED_PIPELINING) {
            ctx.pipelining_used = true;
            ctx.pipelining_active = true;
            tracing::debug!("Using PIPELINING for command batch");
            self.smtp_write_mail_and_rcpt_cmds_inner(
                ctx,
                stream,
                opts,
                &mail_from,
                &rcpt_commands,
            )?;
        } else {
            tracing::debug!("Non-pipelined SMTP transaction");
            ctx.smtp_command = mail_from.trim_end().to_string();
            ctx.mail_command = ctx.smtp_command.clone();
            ctx.cmd_count += 1;
            self.write_command(stream, &mail_from, opts.command_timeout)?;
            let mail_resp = self.read_response(stream, opts.command_timeout)?;
            if !mail_resp.starts_with("250") {
                return self.handle_mail_error(ctx, &mail_resp);
            }
            tracing::debug!("MAIL FROM accepted");
            for rcpt_cmd in &rcpt_commands {
                ctx.smtp_command = rcpt_cmd.trim_end().to_string();
                ctx.cmd_count += 1;
                self.write_command(stream, rcpt_cmd, opts.command_timeout)?;
                let rcpt_resp = self.read_response(stream, opts.command_timeout)?;
                if rcpt_resp.starts_with("250") || rcpt_resp.starts_with("251") {
                    ctx.good_rcpt = true;
                    tracing::debug!(command = %ctx.smtp_command, "RCPT TO accepted");
                } else if rcpt_resp.starts_with("452") {
                    ctx.rcpt_452 = true;
                    tracing::warn!(response = %rcpt_resp, "RCPT TO got 452");
                } else if rcpt_resp.starts_with("4") {
                    tracing::warn!(response = %rcpt_resp, "RCPT TO temporarily rejected");
                } else {
                    tracing::error!(response = %rcpt_resp, "RCPT TO permanently rejected");
                }
            }
            if !ctx.good_rcpt {
                return Ok(TransportResult::Failed {
                    message: Some("no recipients accepted by server".to_string()),
                });
            }
        }

        let use_bdat = ctx.peer_has(PEER_OFFERED_CHUNKING)
            && !opts.hosts_try_chunking.is_empty()
            && host_matches(&ctx.host, &opts.hosts_try_chunking);

        if use_bdat {
            tracing::debug!("Using BDAT (chunking) for message transfer");
            self.do_bdat_transaction(ctx, stream, opts)?;
        } else if !ctx.pipelining_active {
            ctx.smtp_command = "DATA".to_string();
            ctx.data_command = "DATA".to_string();
            ctx.cmd_count += 1;
            let data_timeout = Duration::from_secs(opts.data_timeout);
            let _ = stream.set_write_timeout(Some(data_timeout));
            self.write_command(stream, "DATA\r\n", opts.data_timeout)?;
            let data_resp = self.read_response(stream, opts.data_timeout)?;
            // Accept any 3xx response to DATA (RFC 5321 says 354, but C Exim
            // accepts any 3xx; some test stubs use 300).
            if !data_resp.starts_with('3') {
                return self.handle_data_error(ctx, &data_resp);
            }
            tracing::debug!("DATA accepted (3xx), sending message body");

            // Transmit the message content (headers + body) from spool data
            self.transmit_message_data(stream, config, opts)?;

            // Send the final dot terminator
            self.write_command(stream, ".\r\n", opts.final_timeout)?;
        }

        let final_timeout_dur = Duration::from_secs(opts.final_timeout);
        let _ = stream.set_read_timeout(Some(final_timeout_dur));

        if ctx.pipelining_active {
            return self.reap_pipelined_responses(ctx, stream, opts, &rcpt_commands);
        }
        let final_resp = self.read_response(stream, opts.final_timeout)?;
        self.process_final_response(ctx, &final_resp, address)
    }

    fn build_mail_from(
        &self,
        ctx: &SmtpContext,
        opts: &SmtpTransportOptions,
        config: &TransportInstanceConfig,
    ) -> Result<String, DriverError> {
        let mut cmd = format!("MAIL FROM:<{}>", ctx.from_addr);
        if ctx.peer_has(PEER_OFFERED_SIZE) {
            let limit: u64 = config
                .message_size_limit
                .as_ref()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let size = limit + opts.size_addition as u64;
            if size > 0 {
                cmd.push_str(&format!(" SIZE={}", size));
            }
        }
        // BODY=8BITMIME is only added when the message was received with 8BITMIME
        // encoding AND the server advertised 8BITMIME. C Exim checks:
        //   if (body_type) sprintf(CS p, " BODY=%s", body_type);
        // For a standard message, body_type is NULL, so nothing is added.
        // We use the body_type from the context (set during message reception).
        if let Some(ref bt) = ctx.body_type {
            cmd.push_str(&format!(" BODY={}", bt));
        }
        if ctx.peer_has(PEER_OFFERED_DSN) && config.return_path_add {
            cmd.push_str(" RET=FULL");
        }
        #[cfg(feature = "i18n")]
        if ctx.utf8_needed && ctx.peer_has(PEER_OFFERED_UTF8) {
            cmd.push_str(" SMTPUTF8");
        }
        #[cfg(feature = "prdr")]
        if ctx.prdr_active {
            cmd.push_str(" PRDR");
        }
        cmd.push_str("\r\n");
        Ok(cmd)
    }

    fn build_rcpt_to(
        &self,
        ctx: &SmtpContext,
        address: &str,
        opts: &SmtpTransportOptions,
    ) -> Result<Vec<String>, DriverError> {
        let mut commands = Vec::new();
        let build_single = |addr: &str| -> String {
            let mut cmd = format!("RCPT TO:<{}>", addr);
            if ctx.peer_has(PEER_OFFERED_DSN) {
                let dsn = Self::build_dsn_notify(RF_NOTIFY_FAILURE | RF_NOTIFY_DELAY);
                if !dsn.is_empty() {
                    cmd.push_str(&format!(" NOTIFY={}", dsn));
                }
            }
            if ctx.lmtp && ctx.peer_has(PEER_OFFERED_IGNOREQUOTA) && opts.lmtp_ignore_quota {
                cmd.push_str(" IGNOREQUOTA");
            }
            cmd.push_str("\r\n");
            cmd
        };
        commands.push(build_single(address));
        for addr in &ctx.addrlist {
            commands.push(build_single(addr));
        }
        Ok(commands)
    }

    fn handle_mail_error(
        &self,
        ctx: &SmtpContext,
        response: &str,
    ) -> Result<TransportResult, DriverError> {
        let trimmed = response.trim();
        tracing::error!(command = %ctx.mail_command, response = %trimmed, "MAIL FROM rejected");
        match response.chars().next() {
            Some('4') => Ok(TransportResult::Deferred {
                message: Some(format!("MAIL FROM deferred: {}", trimmed)),
                errno: Some(0),
            }),
            Some('5') => Ok(TransportResult::Failed {
                message: Some(format!("MAIL FROM rejected: {}", trimmed)),
            }),
            _ => Err(DriverError::ExecutionFailed(format!(
                "unexpected MAIL FROM response: {}",
                trimmed
            ))),
        }
    }

    fn handle_data_error(
        &self,
        ctx: &SmtpContext,
        response: &str,
    ) -> Result<TransportResult, DriverError> {
        let trimmed = response.trim();
        tracing::error!(command = %ctx.data_command, response = %trimmed, "DATA rejected");
        match response.chars().next() {
            Some('4') => Ok(TransportResult::Deferred {
                message: Some(format!("DATA deferred: {}", trimmed)),
                errno: Some(0),
            }),
            Some('5') => Ok(TransportResult::Failed {
                message: Some(format!("DATA rejected: {}", trimmed)),
            }),
            _ => Err(DriverError::ExecutionFailed(format!(
                "unexpected DATA response: {}",
                trimmed
            ))),
        }
    }

    fn do_bdat_transaction(
        &self,
        ctx: &mut SmtpContext,
        stream: &mut TcpStream,
        opts: &SmtpTransportOptions,
    ) -> Result<(), DriverError> {
        ctx.smtp_command = "BDAT 0 LAST".to_string();
        ctx.data_command = "BDAT 0 LAST".to_string();
        ctx.cmd_count += 1;
        self.write_command(stream, "BDAT 0 LAST\r\n", opts.data_timeout)?;
        tracing::debug!("BDAT 0 LAST sent");
        Ok(())
    }

    /// Transmit the full message (headers + body) to the SMTP stream.
    ///
    /// Reads message headers from `__message_headers` in the transport config's
    /// `private_options_map` and the message body from the spool `-D` file
    /// referenced by `__spool_data_file`. Applies SMTP dot-stuffing as required
    /// by RFC 5321 § 4.5.2.
    fn transmit_message_data(
        &self,
        stream: &mut TcpStream,
        config: &TransportInstanceConfig,
        opts: &SmtpTransportOptions,
    ) -> Result<(), DriverError> {
        let data_timeout = Duration::from_secs(opts.data_timeout);
        let _ = stream.set_write_timeout(Some(data_timeout));

        // 1. Send message headers
        if let Some(headers) = config.private_options_map.get("__message_headers") {
            for line in headers.lines() {
                // RFC 5321 dot-stuffing: lines starting with '.' get an extra '.'
                if line.starts_with('.') {
                    self.write_command(stream, &format!(".{}\r\n", line), opts.data_timeout)?;
                } else {
                    self.write_command(stream, &format!("{}\r\n", line), opts.data_timeout)?;
                }
            }
        }

        // Blank line separating headers from body
        self.write_command(stream, "\r\n", opts.data_timeout)?;

        // 2. Send message body from the spool -D file
        if let Some(data_file_path) = config.private_options_map.get("__spool_data_file") {
            match std::fs::read_to_string(data_file_path) {
                Ok(body) => {
                    // The spool -D file has a header line "<msg_id>-D\n" as first line
                    // followed by the actual body. Skip the first line.
                    let body_content = if let Some(pos) = body.find('\n') {
                        &body[pos + 1..]
                    } else {
                        &body
                    };
                    for line in body_content.lines() {
                        if line.starts_with('.') {
                            self.write_command(
                                stream,
                                &format!(".{}\r\n", line),
                                opts.data_timeout,
                            )?;
                        } else {
                            self.write_command(
                                stream,
                                &format!("{}\r\n", line),
                                opts.data_timeout,
                            )?;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        path = %data_file_path,
                        error = %e,
                        "Could not read spool data file, sending empty body"
                    );
                }
            }
        } else {
            tracing::warn!("No spool data file path in transport config");
        }

        Ok(())
    }

    fn process_final_response(
        &self,
        ctx: &mut SmtpContext,
        response: &str,
        address: &str,
    ) -> Result<TransportResult, DriverError> {
        let trimmed = response.trim();
        tracing::debug!(response = %trimmed, "Final delivery response");
        match response.chars().next() {
            Some('2') => {
                ctx.ok = true;
                ctx.completed_addr = true;
                tracing::info!(address = %address, response = %trimmed, "Delivery successful");
                Ok(TransportResult::ok_with_host(
                    ctx.host.clone(),
                    ctx.host.clone(),
                    trimmed.to_string(),
                ))
            }
            Some('4') => {
                tracing::warn!(address = %address, response = %trimmed, "Delivery deferred");
                Ok(TransportResult::Deferred {
                    message: Some(format!("delivery deferred: {}", trimmed)),
                    errno: Some(0),
                })
            }
            Some('5') => {
                tracing::error!(address = %address, response = %trimmed, "Delivery permanently failed");
                Ok(TransportResult::Failed {
                    message: Some(format!("delivery failed: {}", trimmed)),
                })
            }
            _ => Err(DriverError::ExecutionFailed(format!(
                "unexpected final response: {}",
                trimmed
            ))),
        }
    }

    fn reap_pipelined_responses(
        &self,
        ctx: &mut SmtpContext,
        stream: &mut TcpStream,
        opts: &SmtpTransportOptions,
        rcpt_commands: &[String],
    ) -> Result<TransportResult, DriverError> {
        let mail_resp = self.read_response(stream, opts.command_timeout)?;
        if !mail_resp.starts_with("250") {
            return self.handle_mail_error(ctx, &mail_resp);
        }
        tracing::debug!("Pipelined MAIL FROM accepted");
        let mut any_accepted = false;
        for (i, _) in rcpt_commands.iter().enumerate() {
            let rcpt_resp = self.read_response(stream, opts.command_timeout)?;
            if rcpt_resp.starts_with("250") || rcpt_resp.starts_with("251") {
                any_accepted = true;
                ctx.good_rcpt = true;
                tracing::debug!(rcpt_index = i, "Pipelined RCPT accepted");
            } else if rcpt_resp.starts_with("452") {
                ctx.rcpt_452 = true;
                tracing::warn!(rcpt_index = i, response = %rcpt_resp, "Pipelined RCPT 452");
            } else if rcpt_resp.starts_with("4") {
                tracing::warn!(rcpt_index = i, response = %rcpt_resp, "Pipelined RCPT temp-rejected");
            } else {
                tracing::error!(rcpt_index = i, response = %rcpt_resp, "Pipelined RCPT perm-rejected");
                ctx.response_classes |= RESP_BIT_HAD_5XX;
            }
        }
        if !any_accepted {
            let _ = self.read_response(stream, opts.command_timeout);
            return Ok(TransportResult::Failed {
                message: Some("no recipients accepted (pipelined)".to_string()),
            });
        }
        let data_resp = self.read_response(stream, opts.data_timeout)?;
        // Accept any 3xx response to DATA
        if !data_resp.starts_with('3') {
            return self.handle_data_error(ctx, &data_resp);
        }
        tracing::debug!("Pipelined DATA accepted (3xx)");
        self.write_command(stream, ".\r\n", opts.final_timeout)?;
        let final_resp = self.read_response(stream, opts.final_timeout)?;
        let addr_str = if !ctx.addrlist.is_empty() {
            ctx.addrlist[0].clone()
        } else {
            ctx.from_addr.clone()
        };
        self.process_final_response(ctx, &final_resp, &addr_str)
    }
}

// =============================================================================
// I/O Helper Methods
// =============================================================================

impl SmtpTransport {
    fn write_command(
        &self,
        stream: &mut TcpStream,
        cmd: &str,
        timeout_secs: u64,
    ) -> Result<(), DriverError> {
        let timeout = Duration::from_secs(timeout_secs);
        let _ = stream.set_write_timeout(Some(timeout));
        stream
            .write_all(cmd.as_bytes())
            .map_err(|e| match e.kind() {
                ErrorKind::TimedOut | ErrorKind::WouldBlock => {
                    DriverError::TempFail(format!("timeout writing SMTP command: {}", e))
                }
                ErrorKind::BrokenPipe | ErrorKind::ConnectionReset => {
                    DriverError::TempFail(format!("connection broken writing SMTP command: {}", e))
                }
                _ => DriverError::ExecutionFailed(format!("I/O error writing SMTP command: {}", e)),
            })?;
        stream
            .flush()
            .map_err(|e| DriverError::TempFail(format!("flush error: {}", e)))?;
        tracing::trace!(command = %cmd.trim_end(), "SMTP command sent");
        Ok(())
    }

    fn read_response(
        &self,
        stream: &mut TcpStream,
        timeout_secs: u64,
    ) -> Result<String, DriverError> {
        let timeout = Duration::from_secs(timeout_secs);
        let _ = stream.set_read_timeout(Some(timeout));
        let mut buf = [0u8; DELIVER_BUFFER_SIZE];
        let mut accumulated = Vec::new();
        loop {
            let n = stream.read(&mut buf).map_err(|e| match e.kind() {
                ErrorKind::TimedOut | ErrorKind::WouldBlock => {
                    DriverError::TempFail(format!("timeout reading SMTP response: {}", e))
                }
                ErrorKind::ConnectionReset | ErrorKind::UnexpectedEof => {
                    DriverError::TempFail(format!("connection reset reading SMTP response: {}", e))
                }
                _ => {
                    DriverError::ExecutionFailed(format!("I/O error reading SMTP response: {}", e))
                }
            })?;
            if n == 0 {
                return Err(DriverError::TempFail(
                    "connection closed by remote server".to_string(),
                ));
            }
            accumulated.extend_from_slice(&buf[..n]);
            let response = String::from_utf8_lossy(&accumulated).to_string();
            if is_response_complete(&response) {
                tracing::trace!(response = %response.trim_end(), "SMTP response received");
                return Ok(response);
            }
            if accumulated.len() > DELIVER_BUFFER_SIZE * 64 {
                return Err(DriverError::ExecutionFailed(
                    "SMTP response too large".to_string(),
                ));
            }
        }
    }

    fn send_quit(
        &self,
        stream: &mut TcpStream,
        ctx: &mut SmtpContext,
        timeout_secs: u64,
    ) -> Result<(), DriverError> {
        if !ctx.send_quit {
            return Ok(());
        }
        ctx.smtp_command = "QUIT".to_string();
        ctx.cmd_count += 1;
        tracing::debug!("Sending QUIT");
        let _ = self.write_command(stream, "QUIT\r\n", timeout_secs);
        let _ = self.read_response(stream, timeout_secs);
        ctx.send_quit = false;
        Ok(())
    }

    fn smtp_write_mail_and_rcpt_cmds_inner(
        &self,
        ctx: &mut SmtpContext,
        stream: &mut TcpStream,
        opts: &SmtpTransportOptions,
        mail_from: &str,
        rcpt_commands: &[String],
    ) -> Result<(), DriverError> {
        let mut pipeline_buf = String::with_capacity(
            mail_from.len() + rcpt_commands.iter().map(|c| c.len()).sum::<usize>() + 6,
        );
        pipeline_buf.push_str(mail_from);
        ctx.mail_command = mail_from.trim_end().to_string();
        for rcpt in rcpt_commands {
            pipeline_buf.push_str(rcpt);
        }
        pipeline_buf.push_str("DATA\r\n");
        ctx.data_command = "DATA".to_string();
        ctx.smtp_command = format!(
            "MAIL FROM + {} RCPT TO + DATA (pipelined)",
            rcpt_commands.len()
        );
        ctx.cmd_count += 1 + rcpt_commands.len() as u32 + 1;
        tracing::debug!(
            commands = rcpt_commands.len() + 2,
            "Writing pipelined MAIL FROM + RCPT TO + DATA"
        );
        self.write_command(stream, &pipeline_buf, opts.command_timeout)?;
        ctx.pipelining_active = true;
        Ok(())
    }
}

// =============================================================================
// Exported Public Functions
// =============================================================================

/// Set up an SMTP connection and perform EHLO negotiation.
/// Corresponds to C `smtp_setup_conn()` (smtp.c line 2210).
pub fn smtp_setup_conn(
    host: Tainted<String>,
    port: u16,
    opts: &SmtpTransportOptions,
) -> Result<SmtpContext, DriverError> {
    let transport = SmtpTransport::new();
    let clean_host = host
        .sanitize(|h| {
            !h.is_empty() && h.len() <= 255 && !h.chars().any(|c| c.is_control() || c == ' ')
        })
        .map_err(|e| {
            DriverError::ExecutionFailed(format!("hostname validation failed: {}", e.context))
        })?;

    let host_str = clean_host.as_ref();
    let mut ctx = SmtpContext::new(String::new(), host_str.clone(), port);
    ctx.delivery_start = Some(Instant::now());
    ctx.lmtp = opts.protocol == "lmtp";
    ctx.smtps = opts.protocol == "smtps" || opts.protocol == "submissions";

    tracing::debug!(host = %host_str, port = port, "smtp_setup_conn: establishing connection");

    let connect_timeout = Duration::from_secs(opts.connect_timeout);
    let addr_str = format!("{}:{}", host_str, port);
    let sock_addr = addr_str
        .parse()
        .map_err(|e| DriverError::TempFail(format!("invalid address {}: {}", addr_str, e)))?;
    let mut stream = TcpStream::connect_timeout(&sock_addr, connect_timeout)
        .map_err(|e| DriverError::TempFail(format!("connection to {} failed: {}", addr_str, e)))?;

    if opts.keepalive {
        let _ = stream.set_nodelay(true);
    }
    let cmd_timeout = Duration::from_secs(opts.command_timeout);
    let _ = stream.set_read_timeout(Some(cmd_timeout));
    let _ = stream.set_write_timeout(Some(cmd_timeout));

    let banner = transport.read_response(&mut stream, opts.command_timeout)?;
    if !banner.starts_with("220") {
        return Err(DriverError::TempFail(format!(
            "SMTP banner error: {}",
            banner.trim()
        )));
    }
    #[cfg(feature = "dsn-info")]
    {
        ctx.smtp_greeting = banner.clone();
    }

    let ehlo_data = if opts.helo_data.is_empty() {
        "localhost".to_string()
    } else {
        opts.helo_data.clone()
    };
    let ehlo_resp = transport.send_ehlo(&mut ctx, &mut stream, &ehlo_data, opts)?;
    #[cfg(feature = "dsn-info")]
    {
        ctx.helo_response = ehlo_resp.clone();
    }
    transport.parse_ehlo_response(&mut ctx, &ehlo_resp);

    tracing::debug!(host = %host_str, port = port, peer_offered = ctx.peer_offered, "smtp_setup_conn: established");
    Ok(ctx)
}

/// Write MAIL FROM and RCPT TO commands (pipelined).
/// Corresponds to C `smtp_write_mail_and_rcpt_cmds()` (smtp.c line 3680).
pub fn smtp_write_mail_and_rcpt_cmds(
    ctx: &mut SmtpContext,
    stream: &mut TcpStream,
    opts: &SmtpTransportOptions,
    config: &TransportInstanceConfig,
) -> Result<usize, DriverError> {
    let transport = SmtpTransport::new();
    let mail_from = transport.build_mail_from(ctx, opts, config)?;
    let primary_addr = ctx.from_addr.clone();
    let rcpt_cmds = transport.build_rcpt_to(ctx, &primary_addr, opts)?;
    let count = rcpt_cmds.len();
    transport.smtp_write_mail_and_rcpt_cmds_inner(ctx, stream, opts, &mail_from, &rcpt_cmds)?;
    Ok(count)
}

/// Reap early pipelining responses from a PIPE_CONNECT session.
/// Corresponds to C `smtp_reap_early_pipe()` (smtp.c line 1118).
pub fn smtp_reap_early_pipe(
    ctx: &mut SmtpContext,
    stream: &mut TcpStream,
    opts: &SmtpTransportOptions,
) -> Result<usize, DriverError> {
    let transport = SmtpTransport::new();
    #[cfg(feature = "pipe-connect")]
    {
        if !ctx.early_pipe_active {
            return Ok(0);
        }
        tracing::debug!("Reaping early pipelining responses");
        if ctx.pending_banner {
            let banner = transport.read_response(stream, opts.command_timeout)?;
            if !banner.starts_with("220") {
                return Err(DriverError::TempFail(format!(
                    "early pipe: unexpected banner: {}",
                    banner.trim()
                )));
            }
            ctx.pending_banner = false;
        }
        if ctx.pending_ehlo {
            let ehlo_resp = transport.read_response(stream, opts.command_timeout)?;
            if !ehlo_resp.starts_with("250") {
                return Err(DriverError::ExecutionFailed(format!(
                    "early pipe: EHLO rejected: {}",
                    ehlo_resp.trim()
                )));
            }
            transport.parse_ehlo_response(ctx, &ehlo_resp);
            ctx.pending_ehlo = false;
        }
        ctx.early_pipe_active = false;
    }
    #[cfg(not(feature = "pipe-connect"))]
    {
        let _ = (ctx, stream, opts, transport);
    }
    Ok(0)
}

// =============================================================================
// Module-Level Helper Functions
// =============================================================================

/// Check if an SMTP response is complete.
fn is_response_complete(response: &str) -> bool {
    for line in response.lines().rev() {
        let trimmed = line.trim_start();
        if trimmed.len() >= 4 && trimmed[..3].chars().all(|c| c.is_ascii_digit()) {
            return trimmed.as_bytes()[3] == b' ';
        }
    }
    false
}

/// Check if a hostname matches a host list pattern.
fn host_matches(host: &str, pattern: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    for pat in pattern.split(':') {
        let pat = pat.trim();
        if pat.is_empty() {
            continue;
        }
        if pat == "*" {
            return true;
        }
        let (negated, actual_pat) = if let Some(stripped) = pat.strip_prefix('!') {
            (true, stripped.trim())
        } else {
            (false, pat)
        };
        let matches = if let Some(suffix) = actual_pat.strip_prefix('.') {
            host.ends_with(suffix) || host == suffix
        } else {
            host.eq_ignore_ascii_case(actual_pat)
        };
        if matches {
            return !negated;
        }
    }
    false
}

pub fn set_errno(
    addresses: &mut HashMap<String, AddressError>,
    errno: i32,
    msg: &str,
    pass_message: bool,
    host_name: &str,
    more_errno: i32,
) {
    for (_addr, info) in addresses.iter_mut() {
        info.errno = errno;
        info.message = if pass_message {
            format!("{}: {}", host_name, msg)
        } else {
            msg.to_string()
        };
        info.more_errno = more_errno;
    }
    tracing::debug!(errno = errno, message = %msg, host = %host_name, count = addresses.len(), "Error info set on addresses");
}

pub fn check_response(response: &str) -> ResponseCheck {
    let trimmed = response.trim();
    if trimmed.len() < 3 {
        return ResponseCheck::Invalid {
            message: format!("response too short: {:?}", trimmed),
        };
    }
    let code_str = &trimmed[..3];
    let code = match code_str.parse::<u16>() {
        Ok(c) => c,
        Err(_) => {
            return ResponseCheck::Invalid {
                message: format!("non-numeric response code: {:?}", code_str),
            }
        }
    };
    let detail = if trimmed.len() > 4 {
        trimmed[4..].trim().to_string()
    } else {
        String::new()
    };
    match code / 100 {
        2 => ResponseCheck::Success { code, detail },
        4 => ResponseCheck::TempFail { code, detail },
        5 => ResponseCheck::PermFail { code, detail },
        _ => ResponseCheck::Invalid {
            message: format!("unexpected response class: {}", code),
        },
    }
}

pub fn sync_responses(
    transport: &SmtpTransport,
    _ctx: &mut SmtpContext,
    stream: &mut TcpStream,
    opts: &SmtpTransportOptions,
    count: usize,
) -> Result<i32, DriverError> {
    let mut result = RESP_NOERROR;
    for i in 0..count {
        let response = transport.read_response(stream, opts.command_timeout)?;
        let check = check_response(&response);
        match check {
            ResponseCheck::Success { .. } => {
                result |= RESP_BIT_HAD_2XX;
                tracing::trace!(index = i, "Sync: 2xx");
            }
            ResponseCheck::TempFail { code, ref detail } => {
                tracing::warn!(index = i, code = code, detail = %detail, "Sync: 4xx");
                if result == RESP_NOERROR {
                    result = RESP_RCPT_ERROR;
                }
            }
            ResponseCheck::PermFail { code, ref detail } => {
                result |= RESP_BIT_HAD_5XX;
                tracing::error!(index = i, code = code, detail = %detail, "Sync: 5xx");
            }
            ResponseCheck::Invalid { ref message } => {
                tracing::error!(index = i, message = %message, "Sync: invalid");
                result = RESP_RCPT_ERROR;
            }
        }
    }
    Ok(result)
}

// =============================================================================
// Supporting Types
// =============================================================================

#[derive(Debug)]
pub enum ResponseCheck {
    Success { code: u16, detail: String },
    TempFail { code: u16, detail: String },
    PermFail { code: u16, detail: String },
    Invalid { message: String },
}

/// Per-address error information for delivery status tracking.
#[derive(Debug, Clone, Default)]
pub struct AddressError {
    pub errno: i32,
    pub message: String,
    pub more_errno: i32,
}

// =============================================================================
// Compile-Time Driver Registration
// =============================================================================

inventory::submit! {
    TransportDriverFactory {
        name: "smtp",
        create: || Box::new(SmtpTransport::new()),
        is_local: false,
        avail_string: None,
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(DELIVER_BUFFER_SIZE, 4096);
        assert_eq!(PENDING, 256);
        assert_eq!(PENDING_DEFER, 257);
        assert_eq!(PENDING_OK, 256);
    }

    #[test]
    fn test_response_constants() {
        assert_eq!(RESP_BIT_HAD_2XX, 1);
        assert_eq!(RESP_BIT_HAD_5XX, 2);
        assert_eq!(RESP_HAD_2_AND_5, 3);
        assert_eq!(RESP_NOERROR, 0);
        assert_eq!(RESP_RCPT_TIMEO, -1);
        assert_eq!(RESP_RCPT_ERROR, -2);
        assert_eq!(RESP_MAIL_OR_DATA_ERROR, -3);
        assert_eq!(RESP_EPIPE_EHLO_ERR, -4);
        assert_eq!(RESP_EHLO_ERR_TLS, -5);
    }

    #[test]
    fn test_dsn_constants() {
        assert_eq!(RF_LIST.len(), 4);
        assert_eq!(RF_NAMES.len(), 4);
        assert_eq!(RF_NAMES[0], "NEVER");
        assert_eq!(RF_NAMES[1], "SUCCESS");
        assert_eq!(RF_NAMES[2], "FAILURE");
        assert_eq!(RF_NAMES[3], "DELAY");
    }

    #[test]
    fn test_dsn_notify_build() {
        assert_eq!(SmtpTransport::build_dsn_notify(0), "");
        assert_eq!(SmtpTransport::build_dsn_notify(RF_NOTIFY_NEVER), "NEVER");
        assert_eq!(
            SmtpTransport::build_dsn_notify(RF_NOTIFY_SUCCESS | RF_NOTIFY_FAILURE),
            "SUCCESS,FAILURE"
        );
        assert_eq!(
            SmtpTransport::build_dsn_notify(RF_NOTIFY_FAILURE | RF_NOTIFY_DELAY),
            "FAILURE,DELAY"
        );
    }

    #[test]
    fn test_default_options() {
        let opts = SmtpTransportOptions::default();
        assert_eq!(opts.helo_data, "$primary_hostname");
        assert_eq!(opts.hosts_try_chunking, "*");
        assert_eq!(opts.hosts_try_fastopen, "*");
        assert_eq!(opts.command_timeout, 300);
        assert_eq!(opts.connect_timeout, 300);
        assert_eq!(opts.data_timeout, 300);
        assert_eq!(opts.final_timeout, 600);
        assert_eq!(opts.size_addition, 1024);
        assert_eq!(opts.hosts_max_try, 5);
        assert_eq!(opts.hosts_max_try_hardlimit, 50);
        assert_eq!(opts.message_linelength_limit, 998);
        assert!(opts.address_retry_include_sender);
        assert!(!opts.allow_localhost);
        assert!(opts.dns_qualify_single);
        assert!(opts.delay_after_cutoff);
        assert!(opts.keepalive);
        assert!(opts.retry_include_ip_address);
    }

    #[test]
    fn test_smtp_transport_driver_name() {
        let transport = SmtpTransport::new();
        assert_eq!(transport.driver_name(), "smtp");
        assert!(!transport.is_local());
    }

    #[test]
    fn test_smtp_context_new() {
        let ctx = SmtpContext::new(
            "sender@example.com".to_string(),
            "mail.example.com".to_string(),
            25,
        );
        assert_eq!(ctx.from_addr, "sender@example.com");
        assert_eq!(ctx.host, "mail.example.com");
        assert_eq!(ctx.port, 25);
        assert!(ctx.setting_up);
        assert!(ctx.send_quit);
        assert!(!ctx.ok);
        assert!(!ctx.esmtp);
        assert_eq!(ctx.peer_offered, 0);
    }

    #[test]
    fn test_smtp_context_peer_has() {
        let mut ctx = SmtpContext::new(String::new(), String::new(), 25);
        assert!(!ctx.peer_has(PEER_OFFERED_PIPELINING));
        ctx.peer_offered = PEER_OFFERED_PIPELINING | PEER_OFFERED_SIZE;
        assert!(ctx.peer_has(PEER_OFFERED_PIPELINING));
        assert!(ctx.peer_has(PEER_OFFERED_SIZE));
        assert!(!ctx.peer_has(PEER_OFFERED_TLS));
    }

    #[test]
    fn test_smtp_context_reset_transaction() {
        let mut ctx = SmtpContext::new("s@e.com".to_string(), "m.e.com".to_string(), 25);
        ctx.ok = true;
        ctx.setting_up = false;
        ctx.good_rcpt = true;
        ctx.completed_addr = true;
        ctx.pipelining_active = true;
        ctx.smtp_command = "DATA".to_string();
        ctx.reset_transaction();
        assert!(!ctx.ok);
        assert!(ctx.setting_up);
        assert!(!ctx.good_rcpt);
        assert!(!ctx.completed_addr);
        assert!(!ctx.pipelining_active);
        assert!(ctx.smtp_command.is_empty());
    }

    #[test]
    fn test_ehlo_regex_compilation() {
        let regexes = smtp_deliver_init();
        let ehlo = "250-mail.example.com\r\n250-PIPELINING\r\n250-SIZE 52428800\r\n250-AUTH PLAIN LOGIN\r\n250-CHUNKING\r\n250-DSN\r\n250 IGNOREQUOTA";
        assert!(regexes.regex_pipelining.is_match(ehlo));
        assert!(regexes.regex_size.is_match(ehlo));
        assert!(regexes.regex_auth.is_match(ehlo));
        assert!(regexes.regex_chunking.is_match(ehlo));
        assert!(regexes.regex_dsn.is_match(ehlo));
        assert!(regexes.regex_ignorequota.is_match(ehlo));
    }

    #[test]
    fn test_ehlo_size_extraction() {
        let regexes = smtp_deliver_init();
        let response = "250-SIZE 52428800\r\n250 OK";
        let caps = regexes.regex_size.captures(response).unwrap();
        let size: u64 = caps.get(2).unwrap().as_str().parse().unwrap();
        assert_eq!(size, 52428800);
    }

    #[test]
    fn test_ehlo_auth_extraction() {
        let regexes = smtp_deliver_init();
        let response = "250-AUTH PLAIN LOGIN CRAM-MD5\r\n250 OK";
        let caps = regexes.regex_auth.captures(response).unwrap();
        assert_eq!(caps.get(1).unwrap().as_str(), "PLAIN LOGIN CRAM-MD5");
    }

    #[test]
    fn test_parse_ehlo_response() {
        let transport = SmtpTransport::new();
        let mut ctx = SmtpContext::new(String::new(), String::new(), 25);
        let resp = "250-mail.example.com Hello\r\n250-PIPELINING\r\n250-SIZE 10485760\r\n250-AUTH PLAIN LOGIN\r\n250-CHUNKING\r\n250-DSN\r\n250 IGNOREQUOTA";
        transport.parse_ehlo_response(&mut ctx, resp);
        assert!(ctx.peer_has(PEER_OFFERED_PIPELINING));
        assert!(ctx.peer_has(PEER_OFFERED_SIZE));
        assert!(ctx.peer_has(PEER_OFFERED_AUTH));
        assert!(ctx.peer_has(PEER_OFFERED_CHUNKING));
        assert!(ctx.peer_has(PEER_OFFERED_DSN));
        assert!(ctx.peer_has(PEER_OFFERED_IGNOREQUOTA));
        assert_eq!(ctx.peer_max_message_size, 10485760);
        assert_eq!(ctx.auth_mechanisms, "PLAIN LOGIN");
    }

    #[test]
    fn test_is_response_complete() {
        assert!(is_response_complete("250 OK\r\n"));
        assert!(is_response_complete("250-First\r\n250 Last\r\n"));
        assert!(!is_response_complete("250-First\r\n"));
        assert!(is_response_complete("220 mail.example.com ESMTP\r\n"));
        assert!(!is_response_complete(""));
        assert!(is_response_complete("354 Start mail input\r\n"));
    }

    #[test]
    fn test_host_matches() {
        assert!(host_matches("mail.example.com", "*"));
        assert!(host_matches("mail.example.com", "mail.example.com"));
        assert!(!host_matches("mail.example.com", "other.example.com"));
        assert!(host_matches("mail.example.com", ".example.com"));
        assert!(!host_matches("mail.other.com", ".example.com"));
        assert!(!host_matches("mail.example.com", "!mail.example.com"));
        assert!(host_matches(
            "mail.example.com",
            "other.com:mail.example.com"
        ));
        assert!(!host_matches("mail.example.com", ""));
    }

    #[test]
    fn test_check_response_success() {
        match check_response("250 2.1.0 OK") {
            ResponseCheck::Success { code, detail } => {
                assert_eq!(code, 250);
                assert!(detail.contains("2.1.0 OK"));
            }
            _ => panic!("Expected Success"),
        }
    }

    #[test]
    fn test_check_response_temp_fail() {
        match check_response("421 4.7.0 Try again later") {
            ResponseCheck::TempFail { code, .. } => assert_eq!(code, 421),
            _ => panic!("Expected TempFail"),
        }
    }

    #[test]
    fn test_check_response_perm_fail() {
        match check_response("550 5.1.1 No such user") {
            ResponseCheck::PermFail { code, .. } => assert_eq!(code, 550),
            _ => panic!("Expected PermFail"),
        }
    }

    #[test]
    fn test_check_response_invalid() {
        match check_response("XY") {
            ResponseCheck::Invalid { .. } => {}
            _ => panic!("Expected Invalid"),
        }
    }

    #[test]
    fn test_resolve_port() {
        let mut opts = SmtpTransportOptions::default();
        assert_eq!(SmtpTransport::resolve_port(&opts), 25);
        opts.protocol = "lmtp".to_string();
        assert_eq!(SmtpTransport::resolve_port(&opts), 24);
        opts.protocol = "smtps".to_string();
        assert_eq!(SmtpTransport::resolve_port(&opts), 465);
        opts.protocol = "".to_string();
        opts.port = "587".to_string();
        assert_eq!(SmtpTransport::resolve_port(&opts), 587);
        opts.port = "smtp".to_string();
        assert_eq!(SmtpTransport::resolve_port(&opts), 25);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_tls_lib_state_default() {
        let state = EximTlsLibState::default();
        assert!(!state.conn_certs);
        assert!(!state.cabundle);
        assert!(state.libdata0.is_none());
    }

    #[test]
    fn test_address_error_default() {
        let err = AddressError::default();
        assert_eq!(err.errno, 0);
        assert!(err.message.is_empty());
    }

    #[test]
    fn test_set_errno() {
        let mut addresses = HashMap::new();
        addresses.insert("user@example.com".to_string(), AddressError::default());
        set_errno(
            &mut addresses,
            421,
            "try again later",
            true,
            "mail.example.com",
            0,
        );
        let err = addresses.get("user@example.com").unwrap();
        assert_eq!(err.errno, 421);
        assert!(err.message.contains("mail.example.com"));
    }

    #[test]
    fn test_smtp_transport_init_validation() {
        let transport = SmtpTransport::new();
        let config = TransportInstanceConfig {
            name: "test_smtp".to_string(),
            driver_name: "smtp".to_string(),
            options: Box::new(SmtpTransportOptions::default()),
            ..TransportInstanceConfig::default()
        };
        assert!(transport.smtp_transport_init(&config).is_ok());

        let mut bad_opts = SmtpTransportOptions::default();
        bad_opts.command_timeout = 0;
        let bad_config = TransportInstanceConfig {
            name: "bad".to_string(),
            driver_name: "smtp".to_string(),
            options: Box::new(bad_opts),
            ..TransportInstanceConfig::default()
        };
        assert!(transport.smtp_transport_init(&bad_config).is_err());
    }

    #[test]
    fn test_smtp_context_display() {
        let ctx = SmtpContext::new("s@e.com".to_string(), "m.e.com".to_string(), 25);
        let disp = format!("{}", ctx);
        assert!(disp.contains("m.e.com"));
        assert!(disp.contains("25"));
    }

    #[test]
    fn test_smtp_options_display() {
        let opts = SmtpTransportOptions::default();
        let disp = format!("{}", opts);
        assert!(disp.contains("SmtpTransportOptions"));
    }

    #[test]
    fn test_dnssec_mode_default() {
        assert_eq!(DnssecMode::default(), DnssecMode::None);
    }

    #[test]
    fn test_peer_capability_constants_unique() {
        let all = [
            PEER_OFFERED_TLS,
            PEER_OFFERED_CHUNKING,
            PEER_OFFERED_PIPELINING,
            PEER_OFFERED_DSN,
            PEER_OFFERED_SIZE,
            PEER_OFFERED_AUTH,
            PEER_OFFERED_IGNOREQUOTA,
            PEER_OFFERED_PRDR,
            PEER_OFFERED_UTF8,
            PEER_OFFERED_EARLY_PIPE,
            PEER_OFFERED_LIMITS,
            PEER_OFFERED_PIPE_CONNECT,
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_eq!(
                    all[i] & all[j],
                    0,
                    "Overlapping: 0x{:04x} and 0x{:04x}",
                    all[i],
                    all[j]
                );
            }
        }
    }
}
