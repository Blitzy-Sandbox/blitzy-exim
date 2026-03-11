#![deny(unsafe_code)]
//! # exim-tls — TLS Abstraction Layer for Exim MTA
//!
//! This crate provides a unified TLS abstraction layer replacing Exim's dual
//! TLS backend implementation across six C source files (~12,579 lines total):
//!
//! - `src/src/tls.c`          — Backend-independent TLS glue
//! - `src/src/tls-openssl.c`  — OpenSSL backend
//! - `src/src/tls-gnu.c`      — GnuTLS backend
//! - `src/src/dane.c`         — DANE/TLSA dispatcher
//! - `src/src/dane-openssl.c` — DANE OpenSSL verification
//! - `src/src/danessl.h`      — DANE SSL API header
//!
//! # Architecture
//!
//! The [`TlsBackend`] trait defines 13 methods covering the full TLS lifecycle:
//! daemon init, credential management, handshake, I/O, and teardown. Two
//! implementations are provided:
//!
//! - **rustls** (default, `tls-rustls` feature) — Memory-safe, no C dep
//! - **openssl** (optional, `tls-openssl` feature) — For FIPS or legacy
//!
//! # Feature Flags
//!
//! | Feature       | Effect                                     |
//! |---------------|--------------------------------------------|
//! | `tls-rustls`  | Compile rustls backend (default)            |
//! | `tls-openssl` | Compile openssl backend                    |
//! | `dane`        | Enable DANE/TLSA certificate verification  |
//! | `ocsp`        | Enable OCSP stapling                       |
//! | `tls-resume`  | Enable TLS session resumption              |

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
// Re-exports for Convenience
// =============================================================================

#[cfg(feature = "tls-rustls")]
pub use rustls_backend::RustlsBackend;

#[cfg(feature = "tls-openssl")]
pub use openssl_backend::OpensslBackend;

// =============================================================================
// TlsError — Unified Error Type
// =============================================================================

/// Unified error type for TLS operations across all backends.
///
/// This enum covers all failure modes in the TLS lifecycle, from daemon
/// initialisation through credential loading, handshake, I/O, and teardown.
/// Backend-specific errors are wrapped in the `BackendSpecific` variant to
/// allow uniform error handling by callers.
///
/// # C Equivalent
///
/// In the C codebase, TLS errors were reported via `log_write()` calls
/// scattered across `tls.c`, `tls-openssl.c`, and `tls-gnu.c`. This enum
/// replaces that pattern with structured errors that can be matched and
/// propagated via `Result<T, TlsError>`.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// The TLS backend has not been initialised via `daemon_init()`.
    #[error("TLS backend not initialised — call daemon_init() first")]
    NotInitialised,

    /// Failed to load a PEM certificate chain from disk.
    #[error("failed to load TLS certificate from '{path}': {detail}")]
    CertificateLoadFailed {
        /// Filesystem path that was attempted.
        path: String,
        /// Description of the failure.
        detail: String,
    },

    /// Failed to load a PEM private key from disk.
    #[error("failed to load TLS private key from '{path}': {detail}")]
    PrivateKeyLoadFailed {
        /// Filesystem path that was attempted.
        path: String,
        /// Description of the failure.
        detail: String,
    },

    /// The TLS handshake failed (server or client side).
    #[error("TLS handshake failed: {detail}")]
    HandshakeFailed {
        /// Description of the handshake failure.
        detail: String,
    },

    /// An I/O error occurred during TLS read/write.
    #[error("TLS I/O error: {source}")]
    IoError {
        /// Underlying I/O error.
        #[from]
        source: std::io::Error,
    },

    /// An invalid cipher suite specification was provided in configuration.
    #[error("invalid cipher suite specification: '{cipher}'")]
    InvalidCipher {
        /// The cipher string that could not be parsed.
        cipher: String,
    },

    /// DANE/TLSA verification failed.
    #[error("DANE verification failed: {detail}")]
    DaneVerificationFailed {
        /// Description of the DANE failure.
        detail: String,
    },

    /// OCSP stapling failed or produced an invalid response.
    #[error("OCSP stapling error: {detail}")]
    OcspError {
        /// Description of the OCSP failure.
        detail: String,
    },

    /// Client certificate verification failed during mutual TLS.
    #[error("client certificate verification failed: {detail}")]
    ClientCertFailed {
        /// Description of the failure.
        detail: String,
    },

    /// TLS session resumption failed.
    #[error("TLS session resumption failed: {detail}")]
    ResumptionFailed {
        /// Description of the failure.
        detail: String,
    },

    /// Backend-specific error not covered by the other variants.
    #[error("TLS backend error: {detail}")]
    BackendSpecific {
        /// Description of the backend-specific error.
        detail: String,
    },

    /// The requested operation is not supported by the current backend.
    #[error("TLS operation not supported: {detail}")]
    NotSupported {
        /// Description of the unsupported operation.
        detail: String,
    },
}

// =============================================================================
// TlsSession — Active TLS Connection Info
// =============================================================================

/// Information about a negotiated TLS session.
///
/// Populated after a successful `server_start()` or `client_start()` call
/// and accessible via the `TlsBackend::session_info()` method. Replaces
/// the global TLS state variables from the C codebase (e.g.,
/// `tls_in.cipher`, `tls_in.peerdn`, `tls_out.ver`).
#[derive(Debug, Clone, Default)]
pub struct TlsSessionInfo {
    /// Negotiated cipher suite name (IANA format, e.g., "TLS_AES_256_GCM_SHA384").
    pub cipher_name: Option<String>,
    /// Negotiated TLS protocol version (e.g., "TLSv1.3").
    pub protocol_version: Option<String>,
    /// Peer certificate Distinguished Name string.
    pub peer_dn: Option<String>,
    /// Server Name Indication value (received by server / sent by client).
    pub sni: Option<String>,
    /// Whether the session was resumed from a cached ticket.
    pub resumed: bool,
    /// DANE verification status (if DANE was attempted).
    pub dane_verified: bool,
    /// OCSP stapling status (if OCSP was performed).
    pub ocsp_status: Option<String>,
}

// =============================================================================
// TlsBackend Trait — Central Abstraction (13 Methods)
// =============================================================================

/// Unified TLS backend trait for the Exim MTA.
///
/// Defines the complete TLS lifecycle: initialisation, credential management,
/// handshake, encrypted I/O, and teardown. Both the rustls and openssl
/// backends implement this trait, allowing the daemon to be backend-agnostic.
///
/// # 13 Required Methods
///
/// 1. `daemon_init`          — One-time startup initialisation
/// 2. `daemon_tick`          — Periodic credential rotation check
/// 3. `server_creds_init`    — Load server certificate + key
/// 4. `client_creds_init`    — Load per-transport client credentials
/// 5. `server_start`         — Begin server-side TLS handshake
/// 6. `client_start`         — Begin client-side TLS handshake
/// 7. `read`                 — Read decrypted data from TLS stream
/// 8. `write`                — Write data to TLS stream (encrypts)
/// 9. `close`                — Shut down TLS connection
/// 10. `validate_require_cipher` — Check cipher string validity at config time
/// 11. `session_info`        — Retrieve negotiated session parameters
/// 12. `version_report`      — Generate version string for `-bV` output
/// 13. `is_initialised`      — Query whether daemon_init() has been called
///
/// # C Equivalents
///
/// | C Function                      | Trait Method              |
/// |-------------------------------|---------------------------|
/// | `tls_per_lib_daemon_init()`   | `daemon_init()`           |
/// | `tls_per_lib_daemon_tick()`   | `daemon_tick()`           |
/// | `tls_server_creds_init()`     | `server_creds_init()`     |
/// | `tls_client_creds_init()`     | `client_creds_init()`     |
/// | `tls_server_start()`          | `server_start()`          |
/// | `tls_client_start()`          | `client_start()`          |
/// | `tls_read()`                  | `read()`                  |
/// | `tls_write()`                 | `write()`                 |
/// | `tls_close()`                 | `close()`                 |
/// | `tls_validate_require_cipher()` | `validate_require_cipher()` |
/// | (various global accesses)     | `session_info()`          |
/// | `tls_version_report()`        | `version_report()`        |
/// | (implicit)                    | `is_initialised()`        |
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
    /// Replaces C `tls_per_lib_daemon_init()`.
    fn daemon_init(&mut self) -> Result<(), TlsError>;

    /// Periodic credential rotation check.
    ///
    /// Called periodically by the daemon main loop to detect whether on-disk
    /// certificate or key files have changed. If credentials were reloaded,
    /// returns `Some(watch_fd)` for the caller to close the old inotify/kqueue
    /// descriptor. Returns `None` if no change was detected.
    ///
    /// Replaces C `tls_per_lib_daemon_tick()`.
    fn daemon_tick(&mut self) -> Option<i32>;

    // ── 2. Credential Management ──────────────────────────────────────────

    /// Load or reload server-side TLS credentials.
    ///
    /// Loads the certificate chain and private key from the paths specified
    /// in the Exim configuration. The resulting TLS configuration is cached
    /// internally and shared across all inbound connections.
    ///
    /// # Arguments
    ///
    /// * `certificate_path` — Path to the PEM certificate chain file.
    /// * `privatekey_path`  — Path to the PEM private key file.
    /// * `ciphers`          — Optional cipher suite restriction (colon-separated).
    /// * `min_version`      — Optional minimum TLS version ("1.2" or "1.3").
    /// * `ca_file`          — Optional CA file for client certificate verification.
    /// * `require_client_cert` — Whether to require client certificates.
    ///
    /// # Returns
    ///
    /// `Ok(lifetime_secs)` — `0` for permanent credentials, or the credential
    /// lifetime in seconds for auto-rotation. `Err(TlsError)` on failure.
    ///
    /// Replaces C `tls_server_creds_init()`.
    fn server_creds_init(
        &mut self,
        certificate_path: &str,
        privatekey_path: &str,
        ciphers: Option<&str>,
        min_version: Option<&str>,
        ca_file: Option<&str>,
        require_client_cert: bool,
    ) -> Result<u32, TlsError>;

    /// Load or reload per-transport client-side TLS credentials.
    ///
    /// Loads client credentials for outbound TLS connections. The
    /// configuration is cached per `transport_name` for reuse across
    /// connections using the same transport.
    ///
    /// # Arguments
    ///
    /// * `transport_name` — Cache key identifying the transport.
    /// * `ca_file`        — Optional CA certificate file (`None` = system roots).
    /// * `certificate`    — Optional client certificate for mutual TLS.
    /// * `privatekey`     — Optional client private key for mutual TLS.
    /// * `ciphers`        — Optional cipher suite restriction.
    /// * `min_version`    — Optional minimum TLS version.
    ///
    /// Replaces C `tls_client_creds_init()`.
    fn client_creds_init(
        &mut self,
        transport_name: &str,
        ca_file: Option<&str>,
        certificate: Option<&str>,
        privatekey: Option<&str>,
        ciphers: Option<&str>,
        min_version: Option<&str>,
    ) -> Result<(), TlsError>;

    // ── 3. Handshake ──────────────────────────────────────────────────────

    /// Start a server-side TLS handshake on the given socket file descriptor.
    ///
    /// Accepts an already-connected TCP socket (from `accept()`) and performs
    /// the TLS handshake as the server. After success, all subsequent `read()`
    /// and `write()` calls operate on the encrypted channel.
    ///
    /// # Arguments
    ///
    /// * `fd` — Raw POSIX file descriptor for the connected TCP socket.
    ///
    /// Replaces C `tls_server_start()`.
    fn server_start(&mut self, fd: std::os::unix::io::RawFd) -> Result<(), TlsError>;

    /// Start a client-side TLS handshake on the given socket file descriptor.
    ///
    /// Performs the TLS handshake as a client on an already-connected TCP
    /// socket. Used for STARTTLS on outbound SMTP connections.
    ///
    /// # Arguments
    ///
    /// * `fd`             — Raw POSIX file descriptor for the connected socket.
    /// * `host`           — The hostname for SNI and certificate verification.
    /// * `transport_name` — Transport name for credential cache lookup.
    /// * `dane_tlsa`      — Optional TLSA records for DANE verification.
    ///
    /// Replaces C `tls_client_start()`.
    fn client_start(
        &mut self,
        fd: std::os::unix::io::RawFd,
        host: &str,
        transport_name: &str,
        dane_tlsa: Option<&[u8]>,
    ) -> Result<(), TlsError>;

    // ── 4. Encrypted I/O ──────────────────────────────────────────────────

    /// Read decrypted data from the active TLS connection.
    ///
    /// Reads up to `buf.len()` bytes of decrypted application data from
    /// the TLS stream. Returns 0 on EOF (peer sent close_notify).
    ///
    /// Replaces C `tls_read()`.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError>;

    /// Write data to the active TLS connection (encrypts before sending).
    ///
    /// Writes up to `buf.len()` bytes, encrypting them before transmission.
    /// Returns the number of bytes consumed from `buf`.
    ///
    /// Replaces C `tls_write()`.
    fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError>;

    // ── 5. Teardown ───────────────────────────────────────────────────────

    /// Shut down the active TLS connection.
    ///
    /// If `shutdown` is true, sends a close_notify alert before closing.
    /// If false, performs a hard close without notification (used on error
    /// paths or when the underlying TCP connection is already broken).
    ///
    /// Replaces C `tls_close()`.
    fn close(&mut self, shutdown: bool) -> Result<(), TlsError>;

    // ── 6. Configuration Validation ───────────────────────────────────────

    /// Validate a cipher suite specification string at configuration time.
    ///
    /// Called during `readconf` to verify that the `tls_require_ciphers`
    /// option contains valid cipher suite names for the active backend.
    /// This is a config-time check only — it does not affect the active
    /// TLS connection.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the cipher string is valid, or `Err(description)` with
    /// a human-readable description of the issue.
    ///
    /// Replaces C `tls_validate_require_cipher()`.
    fn validate_require_cipher(&self, cipher_str: &str) -> Result<(), String>;

    // ── 7. Session Information ────────────────────────────────────────────

    /// Retrieve information about the negotiated TLS session.
    ///
    /// Returns cipher name, protocol version, peer DN, SNI, and DANE/OCSP
    /// status for the active connection. Returns `None` if no TLS session
    /// is active.
    ///
    /// Replaces direct access to C global variables `tls_in.*` / `tls_out.*`.
    fn session_info(&self) -> Option<TlsSessionInfo>;

    // ── 8. Reporting ──────────────────────────────────────────────────────

    /// Generate a version report string for `-bV` output.
    ///
    /// Returns a multi-line string with the TLS library name, compile-time
    /// version, and runtime version. Format matches the C output for
    /// backward compatibility with `exigrep`/`eximstats`.
    ///
    /// Replaces C `tls_version_report()`.
    fn version_report(&self) -> String;

    // ── 9. State Query ────────────────────────────────────────────────────

    /// Query whether `daemon_init()` has been called successfully.
    ///
    /// Returns `true` if the TLS backend has been initialised and is
    /// ready to accept credential loading and handshake requests.
    fn is_initialised(&self) -> bool;
}

// =============================================================================
// Credential Watch Utilities
// =============================================================================

/// Check whether a file's modification time has changed since last check.
///
/// Utility function for `daemon_tick()` implementations to detect credential
/// rotation. Compares the file's current `st_mtime` against the provided
/// `last_mtime`. Returns `Some(new_mtime)` if the file was modified, or
/// `None` if unchanged or on error.
///
/// Replaces the C `tls_daemon_creds_reload_check()` function.
pub fn check_file_changed(
    path: &str,
    last_mtime: std::time::SystemTime,
) -> Option<std::time::SystemTime> {
    match std::fs::metadata(path) {
        Ok(meta) => {
            if let Ok(mtime) = meta.modified() {
                if mtime != last_mtime {
                    return Some(mtime);
                }
            }
            None
        }
        Err(e) => {
            tracing::warn!(
                path = %path,
                error = %e,
                "check_file_changed: cannot stat file"
            );
            None
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_error_display() {
        let err = TlsError::NotInitialised;
        assert!(err.to_string().contains("not initialised"));

        let err = TlsError::CertificateLoadFailed {
            path: "/etc/ssl/cert.pem".into(),
            detail: "file not found".into(),
        };
        assert!(err.to_string().contains("/etc/ssl/cert.pem"));

        let err = TlsError::HandshakeFailed {
            detail: "protocol version mismatch".into(),
        };
        assert!(err.to_string().contains("protocol version"));

        let err = TlsError::InvalidCipher {
            cipher: "INVALID_CIPHER".into(),
        };
        assert!(err.to_string().contains("INVALID_CIPHER"));
    }

    #[test]
    fn test_tls_session_info_default() {
        let info = TlsSessionInfo::default();
        assert!(info.cipher_name.is_none());
        assert!(info.protocol_version.is_none());
        assert!(info.peer_dn.is_none());
        assert!(info.sni.is_none());
        assert!(!info.resumed);
        assert!(!info.dane_verified);
        assert!(info.ocsp_status.is_none());
    }

    #[test]
    fn test_tls_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "connection reset");
        let tls_err: TlsError = io_err.into();
        assert!(tls_err.to_string().contains("connection reset"));
    }

    #[test]
    fn test_check_file_changed_nonexistent() {
        let result = check_file_changed(
            "/nonexistent/path/cert.pem",
            std::time::SystemTime::UNIX_EPOCH,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_tls_error_variants_exhaustive() {
        // Verify all error variants can be constructed
        let errors: Vec<TlsError> = vec![
            TlsError::NotInitialised,
            TlsError::CertificateLoadFailed {
                path: "p".into(),
                detail: "d".into(),
            },
            TlsError::PrivateKeyLoadFailed {
                path: "p".into(),
                detail: "d".into(),
            },
            TlsError::HandshakeFailed { detail: "d".into() },
            TlsError::InvalidCipher { cipher: "c".into() },
            TlsError::DaneVerificationFailed { detail: "d".into() },
            TlsError::OcspError { detail: "d".into() },
            TlsError::ClientCertFailed { detail: "d".into() },
            TlsError::ResumptionFailed { detail: "d".into() },
            TlsError::BackendSpecific { detail: "d".into() },
            TlsError::NotSupported { detail: "d".into() },
        ];
        for err in &errors {
            // Ensure Display is implemented
            let _ = err.to_string();
        }
        assert_eq!(errors.len(), 11);
    }
}
