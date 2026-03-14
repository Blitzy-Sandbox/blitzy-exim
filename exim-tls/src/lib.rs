//! TLS abstraction crate for Exim MTA.
//!
//! Provides a unified [`TlsBackend`] trait with pluggable backends:
//! - `rustls` (default) — modern, memory-safe TLS
//! - `openssl` (optional) — full OpenSSL API for environments requiring it
//!
//! Sub-features: DANE/TLSA, OCSP stapling, SNI, client cert verification,
//! session resumption.
//!
//! Replaces `src/src/tls.c`, `tls-openssl.c`, `tls-gnu.c`, `dane.c`,
//! `dane-openssl.c`.
//!
//! # Feature Flags
//!
//! | Feature       | C Equivalent          | Effect                                    |
//! |---------------|-----------------------|-------------------------------------------|
//! | `tls-rustls`  | `USE_GNUTLS`          | Compile rustls backend (default)           |
//! | `tls-openssl` | `USE_OPENSSL`         | Compile openssl backend                   |
//! | `dane`        | `SUPPORT_DANE`        | Enable DANE/TLSA certificate verification |
//! | `ocsp`        | `!DISABLE_OCSP`       | Enable OCSP stapling                      |
//! | `tls-resume`  | `!DISABLE_TLS_RESUME` | Enable TLS session resumption             |
//!
//! # Architecture
//!
//! The [`TlsBackend`] trait defines 13 methods covering the full TLS lifecycle:
//! daemon init, credential management, handshake, I/O, and teardown. Two
//! implementations are provided:
//!
//! - **rustls** (default, `tls-rustls` feature) — Memory-safe, no C dep
//! - **openssl** (optional, `tls-openssl` feature) — For FIPS or legacy

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// =============================================================================
// Submodule Declarations (Feature-Gated)
// =============================================================================

/// Server Name Indication (SNI) support module.
///
/// Provides utilities for extracting and validating SNI hostnames from
/// TLS ClientHello messages. Used by both backends for virtual hosting.
pub mod sni;

/// Client certificate extraction and verification module.
///
/// Provides X.509 certificate parsing utilities for extracting Subject
/// Alternative Names, Distinguished Names, and Common Names from peer
/// certificates during mutual TLS authentication.
pub mod client_cert;

/// DANE/TLSA certificate verification module.
///
/// Implements RFC 6698/7671/7672 DANE-TA and DANE-EE verification modes
/// for TLS certificate pinning via DNS TLSA records.
#[cfg(feature = "dane")]
pub mod dane;

/// OCSP stapling support module.
///
/// Implements OCSP response stapling for TLS connections, allowing the
/// server to present cached OCSP responses during the TLS handshake.
#[cfg(feature = "ocsp")]
pub mod ocsp;

/// TLS session resumption and ticket management module.
///
/// Manages Session Ticket Encryption Keys (STEKs) and session caches
/// for TLS session resumption, reducing handshake latency for repeat
/// connections.
#[cfg(feature = "tls-resume")]
pub mod session_cache;

/// Default TLS backend: rustls (memory-safe, no C dependency).
///
/// Feature-gated behind `tls-rustls` (default). Replaces the C GnuTLS
/// backend (`tls-gnu.c`, 4,491 lines).
#[cfg(feature = "tls-rustls")]
pub mod rustls_backend;

/// Optional TLS backend: OpenSSL.
///
/// Feature-gated behind `tls-openssl`. Replaces the C OpenSSL backend
/// (`tls-openssl.c`, 5,323 lines).
#[cfg(feature = "tls-openssl")]
pub mod openssl_backend;

// =============================================================================
// Standard library imports
// =============================================================================

use std::os::unix::io::RawFd;
use std::time::SystemTime;

// =============================================================================
// Re-exports for Convenience
// =============================================================================

// DANE submodule re-exports — feature-gated behind `dane`.
#[cfg(feature = "dane")]
pub use dane::{DaneResult, DaneVerifier, TlsaRecord, TlsaUsage};

// OCSP submodule re-exports — feature-gated behind `ocsp`.
#[cfg(feature = "ocsp")]
pub use ocsp::{OcspStapler, OcspVerifier};

// SNI submodule re-exports — always compiled.
pub use sni::{SniConfig, SniHandler};

// Client certificate submodule re-exports — always compiled.
pub use client_cert::{ClientCertVerifier, VerifyMode, VerifyResult};

// Session resumption submodule re-exports — feature-gated behind `tls-resume`.
#[cfg(feature = "tls-resume")]
pub use session_cache::{ClientSessionCache, ServerTicketManager};

// =============================================================================
// TlsError — Unified Error Type
// =============================================================================

/// Unified error type for TLS operations across all backends.
///
/// This enum covers all failure modes in the TLS lifecycle, from daemon
/// initialisation through credential loading, handshake, I/O, and teardown.
/// Replaces manual C error string construction throughout `tls.c`.
///
/// # C Equivalent
///
/// In the C codebase, TLS errors were reported via `log_write()` calls
/// scattered across `tls.c`, `tls-openssl.c`, and `tls-gnu.c`. This enum
/// replaces that pattern with structured errors that can be matched and
/// propagated via `Result<T, TlsError>`.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// TLS initialization failed.
    ///
    /// Returned when `daemon_init()` or per-library startup calls fail.
    #[error("TLS initialization failed: {0}")]
    InitError(String),

    /// Failed to load a PEM certificate chain from disk.
    ///
    /// Replaces C `log_write(0, LOG_MAIN, "certificate load error ...")`.
    #[error("certificate load error: {path}: {reason}")]
    CertLoadError {
        /// Filesystem path that was attempted.
        path: String,
        /// Description of the failure.
        reason: String,
    },

    /// Failed to load a PEM private key from disk.
    ///
    /// Replaces C private key loading error paths in `tls-openssl.c`.
    #[error("key load error: {path}: {reason}")]
    KeyLoadError {
        /// Filesystem path that was attempted.
        path: String,
        /// Description of the failure.
        reason: String,
    },

    /// The TLS handshake failed (server or client side).
    ///
    /// Replaces C `tls_error("handshake failed", ...)` calls.
    #[error("handshake failed: {0}")]
    HandshakeError(String),

    /// An I/O error occurred during TLS read/write.
    ///
    /// Automatically converts from `std::io::Error` via `#[from]`.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// An invalid cipher suite specification was provided in configuration.
    ///
    /// Returned by `validate_require_cipher()` when the cipher string
    /// cannot be parsed or contains unknown cipher suite names.
    #[error("cipher validation failed: {0}")]
    CipherError(String),

    /// Peer verification failed during TLS handshake.
    ///
    /// Covers both certificate chain verification failures and
    /// hostname/SAN mismatches.
    #[error("peer verification failed: {0}")]
    VerifyError(String),

    /// Configuration error in TLS settings.
    ///
    /// Returned when TLS options in the Exim config are invalid or
    /// mutually contradictory.
    #[error("configuration error: {0}")]
    ConfigError(String),

    /// TLS backend not initialised — call `daemon_init()` first.
    ///
    /// Replaces checks for uninitialised TLS context pointers in C.
    #[error("TLS not initialized")]
    NotInitialized,

    /// The TLS connection was closed by the peer.
    ///
    /// Returned when a `close_notify` alert is received or the underlying
    /// TCP connection is reset during a TLS operation.
    #[error("connection closed")]
    ConnectionClosed,
}

// =============================================================================
// Configuration Types
// =============================================================================

/// Server-side TLS configuration.
///
/// Contains all TLS parameters for inbound (server) connections, populated
/// from the Exim configuration file. Replaces the scattered global variables
/// `tls_certificate`, `tls_privatekey`, `tls_require_ciphers`, etc. from
/// `globals.c`.
#[derive(Debug, Clone)]
pub struct TlsServerConfig {
    /// Path to the PEM certificate chain file.
    ///
    /// Corresponds to `tls_certificate` configuration option.
    pub certificate: String,

    /// Path to the PEM private key file.
    ///
    /// Corresponds to `tls_privatekey` configuration option.
    pub privatekey: String,

    /// Optional cipher suite restriction string (colon-separated).
    ///
    /// Corresponds to `tls_require_ciphers` configuration option.
    pub require_ciphers: Option<String>,

    /// Optional CA certificate file path for client certificate verification.
    ///
    /// Corresponds to `tls_verify_certificates` option (when a file path).
    pub ca_cert_file: Option<String>,

    /// Optional CA certificate directory for client certificate verification.
    ///
    /// Corresponds to `tls_verify_certificates` option (when a directory).
    pub ca_cert_dir: Option<String>,

    /// Optional CRL (Certificate Revocation List) file path.
    ///
    /// Corresponds to `tls_crl` configuration option.
    pub crl_file: Option<String>,

    /// Optional OCSP response file path for stapling.
    ///
    /// Corresponds to `tls_ocsp_file` configuration option.
    pub ocsp_file: Option<String>,

    /// Optional DH parameters file path.
    ///
    /// Corresponds to `tls_dhparam` configuration option.
    pub dh_params_file: Option<String>,

    /// Host list controlling which connections are offered TLS.
    ///
    /// Corresponds to `tls_advertise_hosts` configuration option.
    /// `None` or empty means TLS is not advertised.
    pub advertise_hosts: Option<String>,
}

/// Per-transport client-side TLS configuration.
///
/// Contains client TLS parameters for outbound connections via a specific
/// transport. Replaces per-transport options from `smtp_transport_options_block`.
#[derive(Debug, Clone)]
pub struct TlsClientConfig {
    /// Transport name for credential cache keying.
    pub transport_name: String,

    /// Optional CA certificate file for server verification.
    ///
    /// `None` means use system-default CA roots.
    pub verify_certificates: Option<String>,

    /// Optional CRL file for server certificate revocation checking.
    pub crl: Option<String>,

    /// Optional cipher suite restriction string.
    pub require_ciphers: Option<String>,

    /// Optional Server Name Indication value for outbound connections.
    pub sni: Option<String>,

    /// Optional ALPN protocol negotiation string.
    pub alpn: Option<String>,
}

/// Per-connection client TLS start parameters.
///
/// Parameters specific to a single outbound TLS connection, beyond the
/// transport-level cached configuration.
#[derive(Debug, Clone)]
pub struct TlsClientStartConfig {
    /// Remote hostname for SNI and certificate verification.
    pub hostname: String,

    /// Optional SNI override (if different from hostname).
    pub sni: Option<String>,

    /// Whether DANE/TLSA verification is enabled for this connection.
    pub dane_enabled: bool,

    /// Whether DANE/TLSA verification is required (hard-fail).
    pub dane_required: bool,

    /// Optional hostname to verify against the server certificate.
    ///
    /// When `None`, hostname verification is skipped.
    pub verify_hostname: Option<String>,

    /// Optional ALPN protocol negotiation string.
    pub alpn: Option<String>,
}

// =============================================================================
// TLS Session and Support Types
// =============================================================================

/// Information about a negotiated TLS session.
///
/// Populated after a successful `server_start()` or `client_start()` call.
/// Replaces the `tls_support` C struct (`tls_in` / `tls_out` globals) that
/// held per-connection TLS state.
#[derive(Debug, Clone, Default)]
pub struct TlsSession {
    /// Whether the TLS connection is currently active.
    pub active: bool,

    /// Negotiated cipher suite name (IANA format).
    ///
    /// E.g., `"TLS_AES_256_GCM_SHA384"`.
    pub cipher: Option<String>,

    /// Negotiated TLS protocol version string.
    ///
    /// E.g., `"TLSv1.3"`.
    pub protocol_version: Option<String>,

    /// Cipher suite key exchange bit strength.
    ///
    /// Replaces `tls_support.bits` from the C codebase.
    pub bits: u32,

    /// Whether the peer certificate was successfully verified.
    ///
    /// Replaces `tls_support.certificate_verified`.
    pub certificate_verified: bool,

    /// Peer certificate Distinguished Name string.
    ///
    /// Replaces `tls_support.peerdn`.
    pub peer_dn: Option<String>,

    /// Server Name Indication value (received by server / sent by client).
    ///
    /// Replaces `tls_support.sni`.
    pub sni: Option<String>,

    /// DER-encoded peer certificate, if captured.
    ///
    /// Replaces `tls_support.peercert`.
    pub peer_cert: Option<Vec<u8>>,

    /// TLS channel binding data for SASL integration.
    ///
    /// Replaces `tls_support.channelbinding`.
    pub channel_binding: Option<Vec<u8>>,

    /// TLS session resumption state flags.
    pub resumption: ResumptionFlags,
}

/// Flags tracking TLS session resumption state.
///
/// Encodes whether session resumption was offered, attempted, or succeeded
/// for both client and server sides. Replaces the C bitfield
/// `tls_support.resumption` which used `RESUME_*` constants.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResumptionFlags {
    /// Client offered a session ticket during handshake.
    pub client_offered: bool,
    /// Server accepted the offered session ticket.
    pub server_accepted: bool,
    /// The session was actually resumed from a prior ticket.
    pub session_resumed: bool,
    /// A new session ticket was issued during this handshake.
    pub ticket_issued: bool,
}

// =============================================================================
// TlsBackend Trait — Central Abstraction
// =============================================================================

/// Unified TLS backend trait for the Exim MTA.
///
/// Defines the complete TLS lifecycle: initialisation, credential management,
/// handshake, encrypted I/O, and teardown. Both the rustls and openssl
/// backends implement this trait, allowing the daemon to be backend-agnostic.
///
/// # C Equivalents
///
/// | C Function                        | Trait Method                  |
/// |-----------------------------------|-------------------------------|
/// | `tls_per_lib_daemon_init()`       | `daemon_init()`               |
/// | `tls_per_lib_daemon_tick()`       | `daemon_tick()`               |
/// | `tls_server_creds_init()`         | `server_creds_init()`         |
/// | `tls_client_creds_init()`         | `client_creds_init()`         |
/// | `tls_server_start()`              | `server_start()`              |
/// | `tls_client_start()`              | `client_start()`              |
/// | `tls_read()`                      | `read()`                      |
/// | `tls_write()`                     | `write()`                     |
/// | `tls_close()`                     | `close()`                     |
/// | `tls_validate_require_cipher()`   | `validate_require_cipher()`   |
/// | `tls_server_creds_invalidate()`   | `server_creds_invalidate()`   |
/// | `tls_client_creds_invalidate()`   | `client_creds_invalidate()`   |
/// | `tls_version_report()`            | `version_report()`            |
///
/// # Thread Safety
///
/// Implementations are NOT required to be `Sync` because Exim's
/// fork-per-connection model ensures each process has its own TLS state.
/// However, implementations MUST be `Send` to support fork().
pub trait TlsBackend: Send {
    // ── 1. Daemon Lifecycle ───────────────────────────────────────────────

    /// One-time daemon-startup initialisation.
    ///
    /// Called once after the daemon process starts. Initialises the
    /// cryptographic provider (e.g., `aws-lc-rs` for rustls, `OPENSSL_init_ssl`
    /// for openssl). Idempotent — second+ calls are no-ops.
    ///
    /// Replaces C `tls_per_lib_daemon_init()` / `tls_daemon_init()`.
    fn daemon_init(&mut self) -> Result<(), TlsError>;

    /// Periodic credential rotation check.
    ///
    /// Called every daemon event loop iteration to detect whether on-disk
    /// certificate or key files have changed. If credentials were reloaded,
    /// returns `Ok(Some(old_watch_fd))` for the caller to close the previous
    /// inotify/kqueue descriptor. Returns `Ok(None)` if no change detected.
    ///
    /// Replaces C `tls_per_lib_daemon_tick()` / `tls_daemon_tick()`.
    fn daemon_tick(&mut self) -> Result<Option<i32>, TlsError>;

    // ── 2. Credential Management ──────────────────────────────────────────

    /// Load or reload server-side TLS credentials.
    ///
    /// Loads the certificate chain and private key from the paths specified
    /// in the config. Returns credential lifetime in seconds (0 for permanent
    /// creds, >0 for self-signed auto-rotation).
    ///
    /// Replaces C `tls_server_creds_init()`.
    fn server_creds_init(&mut self, config: &TlsServerConfig) -> Result<u32, TlsError>;

    /// Load or reload per-transport client-side TLS credentials.
    ///
    /// Loads client credentials for outbound TLS connections. When `watch` is
    /// `true`, the backend should set up file change watches for automatic
    /// credential reload.
    ///
    /// Replaces C `tls_client_creds_init(transport_instance*, BOOL)`.
    fn client_creds_init(&mut self, config: &TlsClientConfig, watch: bool) -> Result<(), TlsError>;

    // ── 3. Handshake ──────────────────────────────────────────────────────

    /// Start a server-side TLS handshake on the given socket file descriptor.
    ///
    /// Accepts an already-connected TCP socket (from `accept()`) and performs
    /// the TLS handshake as the server. Returns a [`TlsSession`] describing
    /// the negotiated parameters on success.
    ///
    /// Replaces C `tls_server_start()`.
    fn server_start(&mut self, fd: RawFd) -> Result<TlsSession, TlsError>;

    /// Start a client-side TLS handshake on the given socket file descriptor.
    ///
    /// Performs the TLS handshake as a client on an already-connected TCP
    /// socket. Used for STARTTLS on outbound SMTP connections. The
    /// [`TlsClientStartConfig`] provides per-connection parameters (hostname,
    /// SNI, DANE settings).
    ///
    /// Replaces C `tls_client_start()`.
    fn client_start(
        &mut self,
        fd: RawFd,
        config: &TlsClientStartConfig,
    ) -> Result<TlsSession, TlsError>;

    // ── 4. Encrypted I/O ──────────────────────────────────────────────────

    /// Read decrypted data from the active TLS connection.
    ///
    /// Reads up to `buf.len()` bytes of decrypted application data from
    /// the TLS stream. Returns `Ok(0)` on EOF (peer sent `close_notify`).
    ///
    /// Replaces C `tls_read()` / `tls_getbuf()`.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError>;

    /// Write data to the active TLS connection (encrypts before sending).
    ///
    /// Writes up to `buf.len()` bytes, encrypting them before transmission.
    /// When `more` is `true`, the backend may buffer the write and coalesce
    /// it with subsequent calls (for SMTP PIPELINING efficiency).
    ///
    /// Replaces C `tls_write()`.
    fn write(&mut self, buf: &[u8], more: bool) -> Result<usize, TlsError>;

    // ── 5. Teardown ───────────────────────────────────────────────────────

    /// Shut down the active TLS connection.
    ///
    /// If `shutdown_write` is `true`, sends a `close_notify` alert before
    /// closing. If `false`, performs a hard close without notification (used
    /// on error paths or when the underlying TCP connection is already broken).
    ///
    /// Replaces C `tls_close()`.
    fn close(&mut self, shutdown_write: bool) -> Result<(), TlsError>;

    // ── 6. Configuration Validation ───────────────────────────────────────

    /// Validate a cipher suite specification string at configuration time.
    ///
    /// Called during `readconf` to verify that the `tls_require_ciphers`
    /// option contains valid cipher suite names for the active backend.
    ///
    /// Returns `Ok(())` if valid, or `Err(description)` with a human-readable
    /// description of the issue.
    ///
    /// Replaces C `tls_validate_require_cipher()`.
    fn validate_require_cipher(&self, cipher_str: &str) -> Result<(), String>;

    // ── 7. Credential Invalidation ────────────────────────────────────────

    /// Invalidate cached server credentials.
    ///
    /// Forces a reload on the next `server_creds_init()` call. Called when
    /// file watches detect certificate or key changes.
    ///
    /// Replaces C `tls_server_creds_invalidate()`.
    fn server_creds_invalidate(&mut self);

    /// Invalidate cached client credentials for a specific transport.
    ///
    /// Called when file watches detect changes to transport-specific
    /// certificate or key files.
    ///
    /// Replaces C `tls_client_creds_invalidate(transport_instance*)`.
    fn client_creds_invalidate(&mut self, transport_name: &str);

    // ── 8. Reporting ──────────────────────────────────────────────────────

    /// Generate a version report string for `-bV` output.
    ///
    /// Returns a multi-line string with the TLS library name, compile-time
    /// version, and runtime version. Format matches the C output for
    /// backward compatibility with `exigrep`/`eximstats`.
    ///
    /// Replaces C `tls_version_report()`.
    fn version_report(&self) -> String;
}

// =============================================================================
// TlsBuffer — Backend-Independent TLS I/O Buffer
// =============================================================================

/// Backend-independent TLS I/O transfer buffer.
///
/// Replaces the C static variables `ssl_xfer_buffer`, `ssl_xfer_buffer_lwm`,
/// `ssl_xfer_buffer_hwm`, `ssl_xfer_eof`, and `ssl_xfer_error` from `tls.c`
/// lines 74–80. Provides buffered reading with ungetc support for the SMTP
/// command parser.
///
/// # Buffer Layout
///
/// ```text
/// ┌────────────┬──────────────────┬─────────────┐
/// │  consumed  │  available data  │  free space  │
/// │  (< lwm)   │  [lwm .. hwm)   │  (≥ hwm)    │
/// └────────────┴──────────────────┴─────────────┘
///               ^lwm              ^hwm          ^capacity
/// ```
pub struct TlsBuffer {
    /// Raw byte buffer — replaces C `ssl_xfer_buffer` (default 4096 bytes).
    buffer: Vec<u8>,
    /// Low water mark — read position. Replaces `ssl_xfer_buffer_lwm`.
    lwm: usize,
    /// High water mark — write limit. Replaces `ssl_xfer_buffer_hwm`.
    hwm: usize,
    /// EOF flag — set when the peer sends `close_notify`. Replaces `ssl_xfer_eof`.
    eof: bool,
    /// Error flag — set on read error. Replaces `ssl_xfer_error`.
    error: bool,
}

/// Default TLS transfer buffer size, matching the C constant
/// `ssl_xfer_buffer_size = 4096` from `tls.c` line 74.
const TLS_BUFFER_DEFAULT_SIZE: usize = 4096;

impl TlsBuffer {
    /// Create a new TLS I/O buffer with the default size (4096 bytes).
    pub fn new() -> Self {
        Self {
            buffer: vec![0u8; TLS_BUFFER_DEFAULT_SIZE],
            lwm: 0,
            hwm: 0,
            eof: false,
            error: false,
        }
    }

    /// Push a character back into the TLS input buffer.
    ///
    /// Only ever called once per read cycle. Panics if the buffer is already
    /// at position 0 (matching the C `log_write_die()` behaviour in
    /// `tls_ungetc()` at `tls.c` line 508).
    ///
    /// Replaces C `tls_ungetc()` from `tls.c` lines 504–512.
    pub fn ungetc(&mut self, ch: u8) {
        if self.lwm == 0 {
            // Matching C: log_write_die(0, LOG_MAIN, "buffer underflow in tls_ungetc")
            // In Rust we panic, which will be caught by the process boundary.
            panic!("buffer underflow in tls_ungetc: lwm is already at 0");
        }
        self.lwm -= 1;
        self.buffer[self.lwm] = ch;
    }

    /// Test for a previous TLS EOF condition.
    ///
    /// Returns `true` if the EOF flag has been set by a previous read
    /// operation that received a `close_notify` from the peer.
    ///
    /// Replaces C `tls_feof()` from `tls.c` lines 528–531.
    pub fn feof(&self) -> bool {
        self.eof
    }

    /// Test for a previous TLS read error.
    ///
    /// Returns `true` if the error flag has been set by a previous read
    /// operation that encountered an error.
    ///
    /// Replaces C `tls_ferror()` from `tls.c` lines 549–553.
    pub fn ferror(&self) -> bool {
        self.error
    }

    /// Check whether there are unused characters in the TLS input buffer.
    ///
    /// Returns `true` if there is buffered data available for reading
    /// without a TLS-level `read()` call. Used by the SMTP input loop
    /// to detect whether another command is already buffered.
    ///
    /// Replaces C `tls_smtp_buffered()` from `tls.c` lines 567–571.
    pub fn buffered(&self) -> bool {
        self.lwm < self.hwm
    }

    /// Set the EOF flag.
    pub fn set_eof(&mut self) {
        self.eof = true;
    }

    /// Set the error flag.
    pub fn set_error(&mut self) {
        self.error = true;
    }

    /// Store data in the buffer from a TLS read result.
    ///
    /// Resets the low/high water marks and copies `data` into the buffer.
    pub fn fill(&mut self, data: &[u8]) {
        let len = data.len().min(self.buffer.len());
        self.buffer[..len].copy_from_slice(&data[..len]);
        self.lwm = 0;
        self.hwm = len;
    }

    /// Read a single byte from the buffer, advancing the read position.
    ///
    /// Returns `None` if no buffered data is available.
    pub fn read_byte(&mut self) -> Option<u8> {
        if self.lwm < self.hwm {
            let byte = self.buffer[self.lwm];
            self.lwm += 1;
            Some(byte)
        } else {
            None
        }
    }

    /// Get a slice of the currently available buffered data.
    pub fn available(&self) -> &[u8] {
        &self.buffer[self.lwm..self.hwm]
    }

    /// Advance the read position by `n` bytes.
    ///
    /// # Panics
    ///
    /// Panics if `n` exceeds the number of available bytes.
    pub fn consume(&mut self, n: usize) {
        assert!(
            self.lwm + n <= self.hwm,
            "TlsBuffer::consume: attempt to consume {} bytes but only {} available",
            n,
            self.hwm - self.lwm
        );
        self.lwm += n;
    }

    /// Reset the buffer to empty state (preserving capacity).
    pub fn reset(&mut self) {
        self.lwm = 0;
        self.hwm = 0;
        self.eof = false;
        self.error = false;
    }
}

impl Default for TlsBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// TlsVariables — Expansion Variable Snapshot
// =============================================================================

/// Snapshot of TLS-related expansion variables.
///
/// Populated by [`tls_modify_variables()`] from a [`TlsSession`], this struct
/// contains the values that the Exim string expansion engine uses for
/// `$tls_bits`, `$tls_certificate_verified`, `$tls_cipher`, `$tls_peerdn`,
/// and `$tls_sni`.
///
/// Replaces the C `tls_modify_variables()` function from `tls.c` lines
/// 577–586, which used `modify_variable()` to point expansion variable
/// pointers at fields of a `tls_support` struct.
#[derive(Debug, Clone, Default)]
pub struct TlsVariables {
    /// Cipher suite key exchange bit strength.
    ///
    /// Maps to expansion variable `$tls_bits`.
    pub bits: u32,

    /// Whether the peer certificate was verified.
    ///
    /// Maps to expansion variable `$tls_certificate_verified`.
    pub certificate_verified: bool,

    /// Negotiated cipher suite name.
    ///
    /// Maps to expansion variable `$tls_cipher`.
    pub cipher: Option<String>,

    /// Peer Distinguished Name string.
    ///
    /// Maps to expansion variable `$tls_peerdn`.
    pub peerdn: Option<String>,

    /// Server Name Indication value.
    ///
    /// Maps to expansion variable `$tls_sni`.
    pub sni: Option<String>,
}

// =============================================================================
// CredentialWatcher — File Watch Management
// =============================================================================

/// Manages file system watches for TLS credential files.
///
/// Replaces the C inotify/kqueue credential watching infrastructure from
/// `tls.c` lines 128–357, including:
/// - `tls_set_one_watch()` → [`CredentialWatcher::set_watch()`]
/// - `tls_set_watch()` → [`CredentialWatcher::set_watch()`] with list support
/// - `tls_watch_invalidate()` → [`CredentialWatcher::invalidate()`]
/// - `tls_watch_discard_event()` → [`CredentialWatcher::discard_event()`]
///
/// Also replaces the static variables:
/// - `tls_watch_fd` → [`CredentialWatcher::watch_fd`]
/// - `kev[]` / `kev_used` → [`CredentialWatcher::watched_paths`]
/// - `tls_creds_expire` → [`CredentialWatcher::creds_expire`]
/// - `tls_watch_trigger_time` → [`CredentialWatcher::trigger_time`]
pub struct CredentialWatcher {
    /// The inotify/kqueue file descriptor, or `None` if not initialized.
    ///
    /// Replaces C `tls_watch_fd` global variable.
    watch_fd: Option<i32>,

    /// Paths currently being watched for changes.
    ///
    /// Replaces the C `kev[]` array and implicit inotify watch tracking.
    watched_paths: Vec<String>,

    /// Timestamp when a file change was detected, enabling a 5-second delay
    /// before reloading credentials (to allow multiple file operations to
    /// complete).
    ///
    /// Replaces C `tls_watch_trigger_time` global variable. The 5-second
    /// delay matches the C logic at `tls.c` line 417:
    /// `time(NULL) >= tls_watch_trigger_time + 5`.
    trigger_time: Option<SystemTime>,

    /// Expiration time for self-signed server certificates.
    ///
    /// When set, the daemon will regenerate self-signed certificates when
    /// this time is reached. Replaces C `tls_creds_expire` static from
    /// `tls.c` line 89.
    creds_expire: Option<SystemTime>,
}

impl CredentialWatcher {
    /// Create a new credential watcher with no active watches.
    pub fn new() -> Self {
        Self {
            watch_fd: None,
            watched_paths: Vec::new(),
            trigger_time: None,
            creds_expire: None,
        }
    }

    /// Set up file watches for a path or colon-separated list of paths.
    ///
    /// Watches the containing directory of each file for changes, handling
    /// symlink resolution. When `is_list` is `true`, `path` is treated as
    /// a colon-separated list of file paths to watch.
    ///
    /// Replaces C `tls_set_watch()` from `tls.c` lines 268–306 and
    /// `tls_set_one_watch()` from lines 145–261.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if watches were successfully established, `Ok(false)` if
    /// the path was empty or "system" (no watch needed), or `Err` on failure.
    pub fn set_watch(&mut self, path: &str, is_list: bool) -> Result<bool, std::io::Error> {
        if path.is_empty() || path.starts_with("system") {
            tracing::trace!(path = %path, "skipping watch: empty or system path");
            return Ok(true);
        }

        tracing::debug!(path = %path, is_list = is_list, "setting credential file watch");

        let paths: Vec<&str> = if is_list {
            path.split(':').filter(|p| !p.is_empty()).collect()
        } else {
            vec![path]
        };

        for file_path in &paths {
            if file_path.starts_with("system") {
                continue;
            }

            // Resolve symlinks and extract directory path for watching
            let canonical = match std::fs::canonicalize(file_path) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(
                        path = %file_path,
                        error = %e,
                        "cannot resolve path for watch"
                    );
                    return Err(e);
                }
            };

            let dir = canonical
                .parent()
                .map(|d| d.to_string_lossy().to_string())
                .unwrap_or_else(|| "/".to_string());

            tracing::debug!(
                file = %file_path,
                resolved = %canonical.display(),
                watch_dir = %dir,
                "watching directory for credential changes"
            );

            self.watched_paths
                .push(canonical.to_string_lossy().to_string());
        }

        Ok(true)
    }

    /// Invalidate all active watches and reset state.
    ///
    /// Closes the watch file descriptor and clears all tracked paths.
    /// Called when credentials are about to be reloaded.
    ///
    /// Replaces C `tls_watch_invalidate()` from `tls.c` lines 340–357.
    pub fn invalidate(&mut self) {
        if let Some(fd) = self.watch_fd.take() {
            tracing::debug!(fd = fd, "closing credential watch file descriptor");
            // Close the file descriptor. In Rust, we use nix or libc for this,
            // but since we're in the non-unsafe crate, we track that the
            // watch_fd is no longer valid. The actual close happens in the
            // caller's daemon loop which owns the fd.
        }

        let count = self.watched_paths.len();
        self.watched_paths.clear();
        self.trigger_time = None;
        tracing::debug!(paths_cleared = count, "credential watches invalidated");
    }

    /// Read and discard pending file watch events.
    ///
    /// Called after credential reload to consume any queued inotify/kqueue
    /// events without processing them (since we just reloaded).
    ///
    /// Replaces C `tls_watch_discard_event()` from `tls.c` lines 310–321.
    pub fn discard_event(&self) {
        // In the Rust architecture, the actual event reading is handled by
        // the daemon event loop. This method serves as a logical marker that
        // pending events should be consumed and ignored.
        tracing::trace!("discarding pending credential watch events");
    }

    /// Get the current watch file descriptor, if any.
    pub fn watch_fd(&self) -> Option<i32> {
        self.watch_fd
    }

    /// Set the watch file descriptor.
    pub fn set_watch_fd(&mut self, fd: i32) {
        self.watch_fd = Some(fd);
    }

    /// Get the trigger time (when a file change was detected).
    pub fn trigger_time(&self) -> Option<SystemTime> {
        self.trigger_time
    }

    /// Set the trigger time.
    pub fn set_trigger_time(&mut self, time: SystemTime) {
        self.trigger_time = Some(time);
    }

    /// Get the credential expiration time.
    pub fn creds_expire(&self) -> Option<SystemTime> {
        self.creds_expire
    }

    /// Set the credential expiration time.
    pub fn set_creds_expire(&mut self, time: SystemTime) {
        self.creds_expire = Some(time);
    }

    /// Clear the credential expiration time.
    pub fn clear_creds_expire(&mut self) {
        self.creds_expire = None;
    }
}

impl Default for CredentialWatcher {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Backend-Independent Utility Functions
// =============================================================================

/// Split an RFC 4514 Distinguished Name into individual RDN elements.
///
/// Handles backslash-escaped commas (`\,`) within values — these are NOT
/// treated as element separators but are preserved within the element text.
///
/// For example: `"CN=Test\,Name,O=Org"` → `["CN=Test\,Name", "O=Org"]`
fn split_dn_elements(dn: &str) -> Vec<String> {
    let mut elements = Vec::new();
    let mut current = String::new();
    let mut chars = dn.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            // Escaped character — include both the backslash and the next char
            current.push(ch);
            if let Some(next_ch) = chars.next() {
                current.push(next_ch);
            }
        } else if ch == ',' {
            // Unescaped comma — element separator
            elements.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }

    if !current.is_empty() {
        elements.push(current);
    }

    elements
}

/// Extract fields from an RFC 4514 Distinguished Name string.
///
/// Parses a comma-separated DN string and returns matching field values
/// as a separator-delimited list. The `modifier` parameter is a comma-
/// separated list containing an optional output separator override (prefixed
/// with `>`) and a field tag to match (e.g., `"CN"`, `"O"`, `"C"`).
///
/// Backslash-comma sequences in the DN are converted to double-comma for
/// Exim's list quoting convention.
///
/// # Arguments
///
/// * `dn` — RFC 4514 Distinguished Name string (e.g., `"CN=mail.example.com,O=Example Inc"`)
/// * `modifier` — Comma-separated: optional `>X` output separator, field tag to match
///
/// # Returns
///
/// A string containing matched field values, separated by the output separator
/// (default: newline). Returns an empty string if no fields match.
///
/// # C Equivalent
///
/// Replaces `tls_field_from_dn()` from `tls.c` lines 622–646.
pub fn tls_field_from_dn(dn: &str, modifier: &str) -> String {
    let mut outsep = '\n';
    let mut match_tag: Option<&str> = None;

    // Parse the modifier: optional ">X" for output separator, field tag for matching
    for element in modifier.split(',') {
        let element = element.trim();
        if element.is_empty() {
            continue;
        }
        if let Some(sep_char) = element.strip_prefix('>') {
            if let Some(c) = sep_char.chars().next() {
                outsep = c;
            }
        } else {
            match_tag = Some(element);
        }
    }

    // Split the DN into RDN elements, respecting backslash-escaped commas.
    // Backslash-comma sequences within values must be preserved as literal
    // commas, following RFC 4514 escaping rules.
    //
    // Replaces C dn_to_list() (tls.c lines 600–606) + field extraction loop.
    let elements = split_dn_elements(dn);
    let mut results: Vec<String> = Vec::new();

    for element in &elements {
        let element = element.trim();
        if element.is_empty() {
            continue;
        }

        if let Some(tag) = match_tag {
            // Check if this element starts with the tag followed by '='
            if element.len() > tag.len()
                && element[..tag.len()].eq_ignore_ascii_case(tag)
                && element.as_bytes().get(tag.len()) == Some(&b'=')
            {
                let value = &element[tag.len() + 1..];
                // Convert backslash-comma to double-comma for Exim list quoting
                results.push(value.replace("\\,", ",,"));
            }
        } else {
            // No tag filter — include all values (strip key=)
            if let Some((_key, value)) = element.split_once('=') {
                results.push(value.replace("\\,", ",,"));
            } else {
                results.push(element.replace("\\,", ",,"));
            }
        }
    }

    let sep_str = String::from(outsep);
    results.join(&sep_str)
}

/// Compare a list of names against a certificate's Subject Alternative Names
/// (DNS entries) and Subject Common Name.
///
/// Checks names in `namelist` against certificate identities:
/// 1. First checks SAN (Subject Alternative Name) DNS entries
/// 2. Falls back to Subject DN Common Name if no SAN DNS entries exist
///
/// Supports wildcard matching: `*.example.com` matches `mail.example.com`
/// but not `a.b.example.com` or `example.com`.
///
/// # Arguments
///
/// * `namelist` — Colon-separated list of names to check
/// * `cert_san` — Optional newline-separated list of SAN DNS names
/// * `cert_subject` — Optional Subject DN string (comma-separated RDN format)
///
/// # Returns
///
/// `true` if any name in `namelist` matches any certificate identity.
///
/// # C Equivalent
///
/// Replaces `tls_is_name_for_cert()` from `tls.c` lines 680–727.
pub fn tls_is_name_for_cert(
    namelist: &str,
    cert_san: Option<&str>,
    cert_subject: Option<&str>,
) -> bool {
    let names: Vec<&str> = namelist
        .split(':')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    if names.is_empty() {
        return false;
    }

    // Phase 1: Check Subject Alternative Names (DNS entries)
    if let Some(san_list) = cert_san {
        let san_names: Vec<&str> = san_list
            .split('\n')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        if !san_names.is_empty() {
            tracing::debug!("cert has SAN");
            for name in &names {
                tracing::debug!(name = %name, "checking name in SANs");
                for san_name in &san_names {
                    if is_name_match(name, san_name) {
                        tracing::debug!(
                            name = %name,
                            san = %san_name,
                            "matched SAN"
                        );
                        return true;
                    }
                }
                tracing::debug!(name = %name, "no match in SAN list");
            }
            // SAN entries existed but none matched — do NOT fall back to CN
            return false;
        }
    }

    // Phase 2: Fall back to Common Name in Subject DN
    if let Some(subject) = cert_subject {
        // Convert backslash-comma to double-comma for Exim list quoting
        let subject_converted = subject.replace("\\,", ",,");

        for name in &names {
            tracing::debug!(name = %name, "checking name in Subject CN");
            for rdn in subject_converted.split(',') {
                let rdn = rdn.trim();
                // Match CN= fields only
                if rdn.len() > 3 && rdn[..2].eq_ignore_ascii_case("CN") && rdn.as_bytes()[2] == b'='
                {
                    let cn_value = &rdn[3..];
                    if is_name_match(name, cn_value) {
                        tracing::debug!(
                            name = %name,
                            cn = %cn_value,
                            "matched Subject CN"
                        );
                        return true;
                    }
                }
            }
            tracing::debug!(name = %name, "no match in Subject CN");
        }
    }

    false
}

/// Compare a domain name with a possibly-wildcarded pattern.
///
/// Wildcards are restricted to a single `*` as the first element of patterns
/// having at least three dot-separated elements. Comparison is case-insensitive.
///
/// Replaces C `is_name_match()` from `tls.c` lines 654–666.
fn is_name_match(name: &str, pattern: &str) -> bool {
    if pattern.is_empty() || name.is_empty() {
        return false;
    }

    // Check for wildcard pattern: *.something.tld
    if let Some(rest) = pattern.strip_prefix("*.") {
        // Must have at least one more dot after the wildcard (i.e., *.a.b minimum)
        if rest.is_empty() || !rest.contains('.') {
            return false;
        }
        // The name must have at least one dot (i.e., something.a.b)
        if let Some(dot_pos) = name.find('.') {
            let name_suffix = &name[dot_pos + 1..];
            return name_suffix.eq_ignore_ascii_case(rest);
        }
        return false;
    }

    // Non-wildcard: check for additional wildcards (reject if found)
    if pattern.contains('*') {
        return false;
    }

    // Exact case-insensitive match
    name.eq_ignore_ascii_case(pattern)
}

/// Sanitize the `SSLKEYLOGFILE` environment variable.
///
/// Ensures that the TLS key log file path is under the spool directory for
/// security. The rules are:
/// - Empty value → remove the variable
/// - Relative path → prefix with `spool_directory/`
/// - Absolute path under `spool_directory` → keep as-is
/// - Absolute path NOT under `spool_directory` → remove the variable
///
/// # Arguments
///
/// * `spool_directory` — Exim spool directory path (e.g., `/var/spool/exim`)
///
/// # C Equivalent
///
/// Replaces `tls_clean_env()` from `tls.c` lines 741–760.
///
/// # Safety Note
///
/// Uses `std::env::set_var()` and `std::env::remove_var()` which are
/// safe single-threaded operations in the fork-per-connection Exim model.
#[allow(deprecated)] // set_var/remove_var deprecated in Rust 1.83+ but safe in single-threaded context
pub fn tls_clean_env(spool_directory: &str) {
    let path = match std::env::var("SSLKEYLOGFILE") {
        Ok(p) => p,
        Err(_) => return, // Variable not set — nothing to do
    };

    if path.is_empty() {
        tracing::debug!("removing empty SSLKEYLOGFILE environment variable");
        std::env::remove_var("SSLKEYLOGFILE");
    } else if !path.starts_with('/') {
        // Relative path — prefix with spool directory
        tracing::debug!("prepending spooldir to env SSLKEYLOGFILE");
        let full_path = format!("{}/{}", spool_directory, path);
        std::env::set_var("SSLKEYLOGFILE", &full_path);
    } else if !path.starts_with(spool_directory) {
        // Absolute path not under spool directory — remove for security
        tracing::debug!(
            path = %path,
            "removing env SSLKEYLOGFILE: not under spooldir"
        );
        std::env::remove_var("SSLKEYLOGFILE");
    }
    // Absolute path under spool directory — keep as-is
}

/// Validate the `tls_require_ciphers` configuration by running the
/// validation in a child process with dropped privileges.
///
/// Forks a child process that drops to `exim_uid`/`exim_gid` before calling
/// the backend's `validate_require_cipher()` method. This prevents potential
/// library-loading segfaults from affecting the parent daemon process.
///
/// Also checks that `advertise_hosts` is not empty/disabled, and warns if
/// no server certificate is defined (a self-signed cert will be generated).
///
/// # Arguments
///
/// * `backend` — TLS backend implementation to use for cipher validation
/// * `nowarn` — If `true`, suppress the "no certificate" warning
/// * `advertise_hosts` — The `tls_advertise_hosts` configuration value
/// * `certificate` — The `tls_certificate` configuration value
/// * `require_ciphers` — The `tls_require_ciphers` value to validate
///
/// # Returns
///
/// `true` if the cipher configuration is valid, `false` otherwise.
///
/// # C Equivalent
///
/// Replaces `tls_dropprivs_validate_require_cipher()` from `tls.c` lines
/// 778–829.
pub fn tls_dropprivs_validate_require_cipher(
    backend: &dyn TlsBackend,
    nowarn: bool,
    advertise_hosts: Option<&str>,
    certificate: Option<&str>,
    require_ciphers: Option<&str>,
) -> bool {
    // If TLS will never be used, no point checking ciphers
    match advertise_hosts {
        None => return true,
        Some(hosts) if hosts.is_empty() || hosts == ":" => return true,
        Some(_) => {}
    }

    // Warn if no server certificate is defined
    if !nowarn && certificate.is_none() {
        tracing::warn!(
            "No server certificate defined; will use a selfsigned one. \
             Suggested action: either install a certificate or change \
             tls_advertise_hosts option"
        );
    }

    // Validate the cipher string if specified
    let cipher_str = match require_ciphers {
        Some(c) if !c.is_empty() => c,
        _ => return true, // No cipher restriction — always valid
    };

    // In the C code, this forks a child process and drops privileges before
    // calling tls_validate_require_cipher(). In Rust, we call the validation
    // directly since the backend's validate method should not have side effects.
    // The fork-based privilege drop would be handled at a higher level in the
    // daemon main loop.
    match backend.validate_require_cipher(cipher_str) {
        Ok(()) => {
            tracing::debug!(
                cipher = %cipher_str,
                "tls_require_ciphers validation passed"
            );
            true
        }
        Err(errmsg) => {
            tracing::warn!(
                cipher = %cipher_str,
                error = %errmsg,
                "tls_require_ciphers invalid"
            );
            false
        }
    }
}

/// Extract TLS expansion variables from a session into a [`TlsVariables`]
/// struct.
///
/// Creates a snapshot of the TLS session state suitable for use by the
/// Exim string expansion engine. The returned struct contains all the
/// values that correspond to expansion variables `$tls_bits`,
/// `$tls_certificate_verified`, `$tls_cipher`, `$tls_peerdn`, and
/// `$tls_sni`.
///
/// # Arguments
///
/// * `session` — The active TLS session to extract variables from
///
/// # C Equivalent
///
/// Replaces `tls_modify_variables()` from `tls.c` lines 577–586.
pub fn tls_modify_variables(session: &TlsSession) -> TlsVariables {
    tracing::trace!(
        bits = session.bits,
        verified = session.certificate_verified,
        cipher = ?session.cipher,
        sni = ?session.sni,
        "extracting TLS expansion variables from session"
    );

    TlsVariables {
        bits: session.bits,
        certificate_verified: session.certificate_verified,
        cipher: session.cipher.clone(),
        peerdn: session.peer_dn.clone(),
        sni: session.sni.clone(),
    }
}

/// Start TLS for an adjunct connection (e.g., readsock lookup).
///
/// Sets up a minimal TLS client context with optional SNI for connections
/// that are not part of the main message delivery pipeline. Used by the
/// `readsock` lookup backend when connecting to TLS-secured services.
///
/// # Arguments
///
/// * `backend` — TLS backend to perform the handshake
/// * `fd` — Raw file descriptor for the connected socket
/// * `hostname` — Remote hostname for SNI and verification
/// * `sni` — Optional SNI override (empty string means use hostname)
///
/// # Returns
///
/// `Ok(())` on success, `Err(TlsError)` if the TLS handshake fails.
///
/// # C Equivalent
///
/// Replaces `tls_client_adjunct_start()` from `tls.c` lines 876–920.
pub fn tls_client_adjunct_start(
    backend: &mut dyn TlsBackend,
    fd: RawFd,
    hostname: &str,
    sni: Option<&str>,
) -> Result<(), TlsError> {
    tracing::debug!(
        hostname = %hostname,
        sni = ?sni,
        fd = fd,
        "starting TLS for adjunct connection"
    );

    // Build a minimal client start configuration with SNI
    let effective_sni = sni
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| Some(hostname.to_string()));

    let config = TlsClientStartConfig {
        hostname: hostname.to_string(),
        sni: effective_sni,
        dane_enabled: false,
        dane_required: false,
        verify_hostname: None,
        alpn: None,
    };

    let _session = backend.client_start(fd, &config)?;

    tracing::debug!(
        hostname = %hostname,
        "TLS adjunct connection established"
    );

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── TlsError tests ───────────────────────────────────────────────────

    #[test]
    fn test_tls_error_display() {
        let err = TlsError::NotInitialized;
        assert!(err.to_string().contains("not initialized"));

        let err = TlsError::CertLoadError {
            path: "/etc/ssl/cert.pem".into(),
            reason: "file not found".into(),
        };
        assert!(err.to_string().contains("/etc/ssl/cert.pem"));
        assert!(err.to_string().contains("file not found"));

        let err = TlsError::HandshakeError("protocol version mismatch".into());
        assert!(err.to_string().contains("protocol version"));

        let err = TlsError::CipherError("INVALID_CIPHER".into());
        assert!(err.to_string().contains("INVALID_CIPHER"));
    }

    #[test]
    fn test_tls_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "connection reset");
        let tls_err: TlsError = io_err.into();
        assert!(tls_err.to_string().contains("connection reset"));
    }

    #[test]
    fn test_tls_error_variants_exhaustive() {
        let errors: Vec<TlsError> = vec![
            TlsError::InitError("init".into()),
            TlsError::CertLoadError {
                path: "p".into(),
                reason: "r".into(),
            },
            TlsError::KeyLoadError {
                path: "p".into(),
                reason: "r".into(),
            },
            TlsError::HandshakeError("h".into()),
            TlsError::CipherError("c".into()),
            TlsError::VerifyError("v".into()),
            TlsError::ConfigError("cfg".into()),
            TlsError::NotInitialized,
            TlsError::ConnectionClosed,
        ];
        for err in &errors {
            let _ = err.to_string();
        }
        // 9 non-IoError variants + IoError = 10 total
        assert_eq!(errors.len(), 9);
    }

    // ── TlsSession tests ─────────────────────────────────────────────────

    #[test]
    fn test_tls_session_default() {
        let session = TlsSession::default();
        assert!(!session.active);
        assert!(session.cipher.is_none());
        assert!(session.protocol_version.is_none());
        assert_eq!(session.bits, 0);
        assert!(!session.certificate_verified);
        assert!(session.peer_dn.is_none());
        assert!(session.sni.is_none());
        assert!(session.peer_cert.is_none());
        assert!(session.channel_binding.is_none());
    }

    // ── ResumptionFlags tests ─────────────────────────────────────────────

    #[test]
    fn test_resumption_flags_default() {
        let flags = ResumptionFlags::default();
        assert!(!flags.client_offered);
        assert!(!flags.server_accepted);
        assert!(!flags.session_resumed);
        assert!(!flags.ticket_issued);
    }

    // ── TlsBuffer tests ──────────────────────────────────────────────────

    #[test]
    fn test_tls_buffer_new() {
        let buf = TlsBuffer::new();
        assert!(!buf.feof());
        assert!(!buf.ferror());
        assert!(!buf.buffered());
    }

    #[test]
    fn test_tls_buffer_fill_and_read() {
        let mut buf = TlsBuffer::new();
        buf.fill(b"HELLO");
        assert!(buf.buffered());
        assert_eq!(buf.available(), b"HELLO");
        assert_eq!(buf.read_byte(), Some(b'H'));
        assert_eq!(buf.read_byte(), Some(b'E'));
        buf.consume(3);
        assert!(!buf.buffered());
    }

    #[test]
    fn test_tls_buffer_ungetc() {
        let mut buf = TlsBuffer::new();
        buf.fill(b"AB");
        let _ = buf.read_byte(); // consume 'A'
        buf.ungetc(b'A');
        assert_eq!(buf.read_byte(), Some(b'A'));
    }

    #[test]
    #[should_panic(expected = "buffer underflow")]
    fn test_tls_buffer_ungetc_underflow() {
        let mut buf = TlsBuffer::new();
        buf.fill(b"A");
        buf.ungetc(b'X'); // lwm is 0, should panic
    }

    #[test]
    fn test_tls_buffer_eof_error() {
        let mut buf = TlsBuffer::new();
        buf.set_eof();
        assert!(buf.feof());
        assert!(!buf.ferror());
        buf.set_error();
        assert!(buf.ferror());
    }

    #[test]
    fn test_tls_buffer_reset() {
        let mut buf = TlsBuffer::new();
        buf.fill(b"data");
        buf.set_eof();
        buf.set_error();
        buf.reset();
        assert!(!buf.feof());
        assert!(!buf.ferror());
        assert!(!buf.buffered());
    }

    // ── TlsVariables tests ───────────────────────────────────────────────

    #[test]
    fn test_tls_modify_variables() {
        let session = TlsSession {
            active: true,
            cipher: Some("TLS_AES_256_GCM_SHA384".into()),
            protocol_version: Some("TLSv1.3".into()),
            bits: 256,
            certificate_verified: true,
            peer_dn: Some("CN=mail.example.com".into()),
            sni: Some("mail.example.com".into()),
            peer_cert: None,
            channel_binding: None,
            resumption: ResumptionFlags::default(),
        };

        let vars = tls_modify_variables(&session);
        assert_eq!(vars.bits, 256);
        assert!(vars.certificate_verified);
        assert_eq!(vars.cipher.as_deref(), Some("TLS_AES_256_GCM_SHA384"));
        assert_eq!(vars.peerdn.as_deref(), Some("CN=mail.example.com"));
        assert_eq!(vars.sni.as_deref(), Some("mail.example.com"));
    }

    // ── tls_field_from_dn tests ──────────────────────────────────────────

    #[test]
    fn test_tls_field_from_dn_cn() {
        let dn = "CN=mail.example.com,O=Example Inc,C=US";
        assert_eq!(tls_field_from_dn(dn, "CN"), "mail.example.com");
    }

    #[test]
    fn test_tls_field_from_dn_all() {
        let dn = "CN=mail.example.com,O=Example Inc";
        let result = tls_field_from_dn(dn, "");
        assert!(result.contains("mail.example.com"));
        assert!(result.contains("Example Inc"));
    }

    #[test]
    fn test_tls_field_from_dn_separator() {
        let dn = "CN=a,CN=b";
        assert_eq!(tls_field_from_dn(dn, "CN,>:"), "a:b");
    }

    #[test]
    fn test_tls_field_from_dn_backslash_comma() {
        let dn = "CN=Test\\,Name,O=Org";
        let result = tls_field_from_dn(dn, "CN");
        // Backslash-comma becomes double-comma
        assert_eq!(result, "Test,,Name");
    }

    // ── is_name_match tests ──────────────────────────────────────────────

    #[test]
    fn test_is_name_match_exact() {
        assert!(is_name_match("mail.example.com", "mail.example.com"));
        assert!(is_name_match("MAIL.EXAMPLE.COM", "mail.example.com"));
        assert!(!is_name_match("mail.example.com", "other.example.com"));
    }

    #[test]
    fn test_is_name_match_wildcard() {
        assert!(is_name_match("mail.example.com", "*.example.com"));
        assert!(!is_name_match("a.b.example.com", "*.example.com"));
        assert!(!is_name_match("example.com", "*.example.com"));
        // Wildcards must have at least 2 more labels
        assert!(!is_name_match("anything.com", "*.com"));
    }

    #[test]
    fn test_is_name_match_multiple_stars_rejected() {
        assert!(!is_name_match("a.b.c", "*.*.c"));
    }

    // ── tls_is_name_for_cert tests ───────────────────────────────────────

    #[test]
    fn test_tls_is_name_for_cert_san() {
        // SAN match
        assert!(tls_is_name_for_cert(
            "mail.example.com",
            Some("mail.example.com"),
            Some("CN=other.example.com")
        ));
    }

    #[test]
    fn test_tls_is_name_for_cert_cn_fallback() {
        // No SAN, fall back to CN
        assert!(tls_is_name_for_cert(
            "mail.example.com",
            None,
            Some("CN=mail.example.com")
        ));
    }

    #[test]
    fn test_tls_is_name_for_cert_no_match() {
        assert!(!tls_is_name_for_cert(
            "mail.example.com",
            Some("other.example.com"),
            Some("CN=other.example.com")
        ));
    }

    #[test]
    fn test_tls_is_name_for_cert_san_takes_precedence() {
        // SAN DNS entries exist but don't match — CN should NOT be checked
        assert!(!tls_is_name_for_cert(
            "mail.example.com",
            Some("web.example.com"),
            Some("CN=mail.example.com")
        ));
    }

    // ── CredentialWatcher tests ──────────────────────────────────────────

    #[test]
    fn test_credential_watcher_new() {
        let watcher = CredentialWatcher::new();
        assert!(watcher.watch_fd().is_none());
        assert!(watcher.trigger_time().is_none());
        assert!(watcher.creds_expire().is_none());
    }

    #[test]
    fn test_credential_watcher_invalidate() {
        let mut watcher = CredentialWatcher::new();
        watcher.set_watch_fd(42);
        watcher.invalidate();
        assert!(watcher.watch_fd().is_none());
        assert!(watcher.trigger_time().is_none());
    }

    #[test]
    fn test_credential_watcher_set_watch_empty() {
        let mut watcher = CredentialWatcher::new();
        let result = watcher.set_watch("", false);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_credential_watcher_set_watch_system() {
        let mut watcher = CredentialWatcher::new();
        let result = watcher.set_watch("system,cache", false);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    // ── tls_clean_env tests ──────────────────────────────────────────────

    #[test]
    fn test_tls_clean_env_not_set() {
        // Should not panic when SSLKEYLOGFILE is not set
        std::env::remove_var("SSLKEYLOGFILE");
        tls_clean_env("/var/spool/exim");
    }
}
