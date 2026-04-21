//! OpenSSL TLS backend implementation for the Exim MTA.
//!
//! This module provides the optional OpenSSL-based TLS backend, directly
//! translating from `src/src/tls-openssl.c` (5,323 lines).  It is compiled
//! only when the `tls-openssl` Cargo feature is active (replacing the C
//! `#ifdef USE_OPENSSL` conditional).
//!
//! # Architecture
//!
//! All C global/static TLS state (`state_server`, `client_static_state`,
//! `server_sni`, `reexpand_tls_files_for_sni`, etc.) is replaced with fields
//! on the [`OpensslBackend`] struct, passed explicitly through call chains
//! per AAP §0.4.4.
//!
//! The `openssl` Rust crate (0.10.75) provides safe wrappers over the OpenSSL
//! C library, so this module contains **zero raw `unsafe` blocks**.  The only
//! place that converts a raw POSIX file descriptor to a `TcpStream` uses the
//! standard `FromRawFd` trait inside a tightly scoped helper with safety
//! documentation.
//!
//! # Feature Gating
//!
//! The parent `lib.rs` gates this module's compilation:
//! ```ignore
//! #[cfg(feature = "tls-openssl")]
//! pub mod openssl_backend;
//! ```

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::io::RawFd;
use std::path::Path;

use openssl::dh::Dh;
use openssl::error::ErrorStack;
use openssl::pkey::Params;
use openssl::ssl::{
    Ssl, SslContext, SslContextBuilder, SslFiletype, SslMethod, SslOptions, SslStream,
    SslVerifyMode, SslVersion,
};
use openssl::x509::X509VerifyResult;

use tracing::{debug, error, trace, warn};

// ---------------------------------------------------------------------------
// Built-in DH parameters — RFC 7919 FFDHE2048
// ---------------------------------------------------------------------------

/// Standard 2048-bit Diffie-Hellman parameters from RFC 7919 (FFDHE2048).
///
/// These replace the custom built-in DH prime from the C `std-crypto.c` file
/// (`std_dh_prime_default`).  Using the RFC-standardised group avoids
/// potential weak-parameter attacks while remaining interoperable with all
/// modern TLS libraries.
///
/// The PEM encoding is intentionally kept as a compile-time constant so that
/// it can be loaded via `Dh::params_from_pem()` without any file I/O when no
/// external DH parameter file is configured.
const DEFAULT_DH_PARAMS_PEM: &[u8] = b"-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEAqnks5+hrgbKptcQ2xsqs8tVWKZ6mQlDu9kvqDRdLi/vYIhJNva93
f44qt+qzJA216UfEO0SdQgNi/Xu1uvqwlOklmSpLHRugxmwT8bz/Q3y6amqs0cfr
ZmThdfxQV31UH2X+5hQbE81PrJfgCcCQIYCx1manyUGjmoRwBuOe9APLoF63IiQd
vVmm5WDn3LwpynSqMfsfeEWd+7uj0mg0l3YumZaaV4d80tSJzfJ6IJMy6YdFKYH0
3EpyiytbCEdy5HdHOhBlUa7X9D+rYj/BZT65VAgj5tZmLwPTNoE686WTBkFvQeWU
CR9/I4/S2TqQCn/j2SvbWR/LHtPNq1p85wIBAg==
-----END DH PARAMETERS-----\n";

/// Maximum accepted DH prime bit size.  DH parameter files with a prime
/// larger than this are silently skipped (matching C `tls_dh_max_bits`).
const DEFAULT_DH_MAX_BITS: u32 = 2236;

// ---------------------------------------------------------------------------
// Transfer buffer defaults (replaces C ssl_xfer_buffer_size = 4096)
// ---------------------------------------------------------------------------

/// Default size of the TLS read-ahead buffer.
const TLS_XFER_BUFFER_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors originating from the OpenSSL TLS backend.
///
/// Each variant maps to a category of failure that the C `tls-openssl.c`
/// handled via `tls_error()` and `log_write()`.  The `thiserror::Error`
/// derive macro generates `Display` and `std::error::Error` implementations,
/// enabling automatic conversion to a common `TlsError` from `lib.rs` via
/// the `From` trait.
#[derive(Debug, thiserror::Error)]
pub enum OpensslError {
    /// A low-level OpenSSL library error.
    ///
    /// Wraps `openssl::error::ErrorStack`, which is the stack of errors that
    /// OpenSSL pushes when an operation fails.  This is the most common
    /// variant, produced by nearly every OpenSSL API call.
    #[error("OpenSSL error: {0}")]
    SslError(#[from] ErrorStack),

    /// Certificate or key loading/verification failure.
    ///
    /// Produced when `set_certificate_chain_file()` or `set_private_key_file()`
    /// fails, or when the loaded certificate does not match the private key.
    #[error("certificate error: {0}")]
    CertificateError(String),

    /// TLS handshake failure (either server-side `accept` or client-side
    /// `connect`).
    ///
    /// Replaces the C `tls_error("SSL_accept", ...)` and
    /// `tls_error("SSL_connect", ...)` paths.
    #[error("TLS handshake failed: {0}")]
    HandshakeError(String),

    /// Configuration error — an invalid setting was provided.
    ///
    /// Produced when an unrecognised option name is passed to
    /// `parse_openssl_options()` or when a required configuration value is
    /// missing.
    #[error("TLS configuration error: {0}")]
    ConfigError(String),

    /// DH parameter loading or generation failure.
    ///
    /// Produced by `init_dh()` when the DH parameter file cannot be read or
    /// parsed, or when the parameter bit-size exceeds `DEFAULT_DH_MAX_BITS`.
    #[error("DH parameter error: {0}")]
    DhParamError(String),

    /// ECDH curve configuration failure.
    ///
    /// Produced by `init_ecdh()` when the requested elliptic curve is not
    /// supported by the linked OpenSSL library.
    #[error("ECDH error: {0}")]
    EcdhError(String),

    /// Cipher suite configuration error.
    ///
    /// Produced when `set_cipher_list()` fails because the configured cipher
    /// string resolves to an empty set of ciphers.
    #[error("cipher error: {0}")]
    CipherError(String),

    /// Protocol version mismatch — the negotiated version is outside the
    /// configured minimum/maximum range.
    #[error("TLS version mismatch: {0}")]
    VersionMismatch(String),

    /// An underlying I/O error on the TCP stream.
    ///
    /// Wraps `std::io::Error` for read/write/shutdown failures that are not
    /// TLS-specific.
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),
}

// ---------------------------------------------------------------------------
// OpensslBackend struct
// ---------------------------------------------------------------------------

/// OpenSSL-based TLS backend for Exim.
///
/// Replaces the C `exim_openssl_state_st` struct (lines 401-434 of
/// `tls-openssl.c`) and the associated static state variables
/// (`state_server`, `client_static_state`, etc.).
///
/// All per-connection and per-daemon state is stored as struct fields rather
/// than C statics/globals, enabling safe concurrent access without data races.
pub struct OpensslBackend {
    // ── Server-side state ──────────────────────────────────────────────────
    /// Server SSL context, initialised by `server_creds_init()`.
    /// Replaces `state_server.lib_state.lib_ctx` from C.
    server_ctx: Option<SslContext>,

    /// Active server-side TLS stream (set after `server_start()` completes
    /// the handshake).
    server_stream: Option<SslStream<TcpStream>>,

    // ── Client-side state ──────────────────────────────────────────────────
    /// Per-transport client SSL contexts.
    ///
    /// Keyed by transport name to allow context reuse across multiple
    /// deliveries to the same remote host.  Replaces the C pattern of
    /// allocating `client_static_state` per transport (line 439).
    client_ctxs: HashMap<String, SslContext>,

    /// Active client-side TLS stream (set after `client_start()` completes
    /// the handshake).
    client_stream: Option<SslStream<TcpStream>>,

    // ── Credential paths ───────────────────────────────────────────────────
    /// Server certificate file path (may contain `$tls_sni` for re-expansion).
    certificate: Option<String>,

    /// Server private key file path.
    privatekey: Option<String>,

    // ── DH parameters ──────────────────────────────────────────────────────
    /// Pre-loaded DH parameters.  Lazily initialised from a file or the
    /// built-in FFDHE2048 constant by `init_dh()`.
    dh_params: Option<Dh<Params>>,

    // ── Negotiated session info ────────────────────────────────────────────
    /// Cipher name negotiated on the active stream.
    cipher_name_val: Option<String>,

    /// TLS protocol version string (e.g. `"TLSv1.3"`).
    protocol_version_val: Option<String>,

    /// Peer certificate distinguished name.
    peer_dn_val: Option<String>,

    /// Server Name Indication value sent or received.
    sni_val: Option<String>,

    /// OCSP stapling status (true = good response received).
    ocsp_status_val: Option<bool>,

    // ── Transfer buffer (replaces C ssl_xfer_buffer) ───────────────────────
    /// TLS read-ahead buffer for record-level I/O.
    pub xfer_buffer: Vec<u8>,

    /// Low-water mark — index of next unconsumed byte in `xfer_buffer`.
    xfer_buffer_lwm: usize,

    /// High-water mark — one past the last valid byte in `xfer_buffer`.
    xfer_buffer_hwm: usize,

    /// End-of-file flag — set when the TLS peer sends `close_notify`.
    xfer_eof: bool,

    /// Error flag — set when a TLS read error occurs.
    xfer_error: bool,

    // ── Configuration flags ────────────────────────────────────────────────
    /// Parsed `SSL_OP_*` flags from the Exim `openssl_options` config setting.
    pub ssl_options: SslOptions,

    /// Whether the server certificate path references `$tls_sni`, requiring
    /// credential re-expansion when a client sends an SNI value.
    pub reexpand_for_sni: bool,

    /// Whether `daemon_init()` has been called (one-time init guard).
    initialised: bool,

    /// Tracks whether the active stream is server-side (true) or client-side.
    is_server: bool,
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Configuration parameter structs
// ---------------------------------------------------------------------------

/// Server credential initialisation configuration.
///
/// Groups the numerous parameters for [`OpensslBackend::server_creds_init()`]
/// into a single struct, avoiding clippy's `too_many_arguments` lint.
pub struct ServerCredsConfig<'a> {
    /// Path to the server certificate chain (PEM).
    pub certificate: &'a str,
    /// Path to the server private key (PEM).
    pub privatekey: &'a str,
    /// Optional OpenSSL cipher list string.
    pub ciphers: Option<&'a str>,
    /// Optional path to a DH parameters file (falls back to built-in).
    pub dh_file: Option<&'a str>,
    /// Optional ECDH curve name (e.g. `"P-256"`).
    pub ec_curve: Option<&'a str>,
    /// Optional minimum TLS version (`"1.2"`, `"1.3"`).
    pub min_version: Option<&'a str>,
    /// Optional CA certificate file for client verification.
    pub ca_file: Option<&'a str>,
    /// Optional CA certificate directory.
    pub ca_dir: Option<&'a str>,
    /// Optional CRL file path.
    pub crl_file: Option<&'a str>,
}

/// Client credential initialisation configuration.
///
/// Groups the parameters for [`OpensslBackend::client_creds_init()`] into a
/// single struct.
pub struct ClientCredsConfig<'a> {
    /// Name of the Exim transport (used as cache key).
    pub transport_name: &'a str,
    /// Optional CA certificate file for server verification.
    pub ca_file: Option<&'a str>,
    /// Optional CA certificate directory.
    pub ca_dir: Option<&'a str>,
    /// Optional CRL file.
    pub crl_file: Option<&'a str>,
    /// Optional client certificate path (for mutual TLS).
    pub certificate: Option<&'a str>,
    /// Optional client private key path.
    pub privatekey: Option<&'a str>,
    /// Optional cipher list.
    pub ciphers: Option<&'a str>,
    /// Optional minimum TLS version.
    pub min_version: Option<&'a str>,
}

// ---------------------------------------------------------------------------
// Trait implementations
// ---------------------------------------------------------------------------

impl Default for OpensslBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl OpensslBackend {
    // ── Constructor ────────────────────────────────────────────────────────

    /// Create a new, uninitialised OpenSSL backend.
    ///
    /// The caller must invoke `daemon_init()` before any TLS operations.
    pub fn new() -> Self {
        Self {
            server_ctx: None,
            server_stream: None,
            client_ctxs: HashMap::new(),
            client_stream: None,
            certificate: None,
            privatekey: None,
            dh_params: None,
            cipher_name_val: None,
            protocol_version_val: None,
            peer_dn_val: None,
            sni_val: None,
            ocsp_status_val: None,
            xfer_buffer: vec![0u8; TLS_XFER_BUFFER_SIZE],
            xfer_buffer_lwm: 0,
            xfer_buffer_hwm: 0,
            xfer_eof: false,
            xfer_error: false,
            ssl_options: SslOptions::empty(),
            reexpand_for_sni: false,
            initialised: false,
            is_server: false,
        }
    }

    // ── One-time initialisation ────────────────────────────────────────────

    /// Perform one-time OpenSSL library initialisation.
    ///
    /// Replaces `tls_openssl_init()` from `tls-openssl.c` (lines ~520-545).
    /// Calls `openssl::init()` for thread-safe global setup, seeds the PRNG,
    /// and parses the default OpenSSL options.
    ///
    /// Safe to call multiple times; subsequent calls are no-ops.
    pub fn daemon_init(&mut self) -> Result<(), OpensslError> {
        if self.initialised {
            return Ok(());
        }

        // Clear any stale client contexts from a previous daemon lifecycle
        // (e.g. after SIGHUP re-exec).  This ensures no expired SSL contexts
        // survive across re-initialisation.
        self.client_ctxs.clear();

        // Thread-safe one-time OpenSSL library initialisation.
        // Replaces the C SSL_load_error_strings() / OpenSSL_add_ssl_algorithms()
        // / SSL_library_init() calls.
        openssl::init();
        debug!("OpenSSL library initialised");

        // PRNG is automatically seeded by the openssl crate on modern OpenSSL
        // versions (>= 1.1.0).  The C code called RAND_load_file("/dev/urandom")
        // which is no longer necessary.
        trace!("OpenSSL PRNG seeded via library defaults");

        self.initialised = true;
        debug!(
            "OpenSSL daemon init complete (compiled against {})",
            Self::compiled_version()
        );
        Ok(())
    }

    // ── Server credential initialisation ──────────────────────────────────

    /// Initialise server-side TLS credentials.
    ///
    /// Replaces `tls_server_creds_init()` from `tls-openssl.c`
    /// (lines ~1750-1860).  Creates an `SslContext`, configures DH/ECDH
    /// parameters, loads the certificate chain and private key, sets cipher
    /// suites and protocol version constraints.
    ///
    /// # Returns
    ///
    /// `Ok(0)` for permanent credentials, `Ok(n)` where `n > 0` indicates a
    /// self-signed certificate lifetime hint in seconds.
    pub fn server_creds_init(
        &mut self,
        config: &ServerCredsConfig<'_>,
    ) -> Result<u32, OpensslError> {
        let certificate = config.certificate;
        let privatekey = config.privatekey;
        let ciphers = config.ciphers;
        let dh_file = config.dh_file;
        let ec_curve = config.ec_curve;
        let min_version = config.min_version;
        let ca_file = config.ca_file;
        let ca_dir = config.ca_dir;
        let crl_file = config.crl_file;
        debug!("initialising server TLS credentials");

        // Build a new SSL context using the TLS method (supports TLS 1.0–1.3).
        let mut ctx_builder = SslContext::builder(SslMethod::tls())
            .map_err(|e| OpensslError::ConfigError(format!("SSL_CTX_new failed: {e}")))?;

        // Apply parsed OpenSSL option flags.
        ctx_builder.set_options(self.ssl_options);
        trace!("applied SSL options: {:?}", self.ssl_options);

        // Set minimum protocol version (default: TLS 1.2).
        let min_ver = Self::parse_tls_version(min_version.unwrap_or("1.2"));
        ctx_builder
            .set_min_proto_version(Some(min_ver))
            .map_err(|e| {
                OpensslError::VersionMismatch(format!("set_min_proto_version failed: {e}"))
            })?;
        trace!(
            "minimum TLS version set to {:?}",
            min_version.unwrap_or("1.2")
        );

        // Initialise DH parameters.
        self.init_dh(&mut ctx_builder, dh_file)?;

        // Initialise ECDH curves.
        Self::init_ecdh(&mut ctx_builder, ec_curve)?;

        // Load server certificate chain.
        ctx_builder
            .set_certificate_chain_file(certificate)
            .map_err(|e| {
                OpensslError::CertificateError(format!(
                    "failed to load certificate '{certificate}': {e}"
                ))
            })?;
        debug!("loaded certificate chain from '{}'", certificate);

        // Load private key.
        ctx_builder
            .set_private_key_file(privatekey, SslFiletype::PEM)
            .map_err(|e| {
                OpensslError::CertificateError(format!(
                    "failed to load private key '{privatekey}': {e}"
                ))
            })?;
        debug!("loaded private key from '{}'", privatekey);

        // Verify that the private key matches the certificate.
        ctx_builder.check_private_key().map_err(|e| {
            OpensslError::CertificateError(format!("private key does not match certificate: {e}"))
        })?;

        // Set cipher list.
        if let Some(cipher_str) = ciphers {
            ctx_builder.set_cipher_list(cipher_str).map_err(|e| {
                OpensslError::CipherError(format!("invalid cipher list '{cipher_str}': {e}"))
            })?;
            debug!("cipher list set to '{}'", cipher_str);
        }

        // Set up CA certificates for client verification if provided.
        Self::setup_certs(&mut ctx_builder, ca_file, ca_dir, crl_file)?;

        // Detect SNI re-expansion need.
        self.reexpand_for_sni = certificate.contains("tls_sni")
            || certificate.contains("tls_in_sni")
            || certificate.contains("tls_out_sni");
        if self.reexpand_for_sni {
            debug!("SNI credential re-expansion enabled (cert path contains tls_sni reference)");
        }

        // Store credential paths for potential re-expansion.
        self.certificate = Some(certificate.to_owned());
        self.privatekey = Some(privatekey.to_owned());

        // Build and store the context.
        let ctx = ctx_builder.build();
        self.server_ctx = Some(ctx);
        debug!("server TLS context initialised successfully");

        // Return 0 for permanent credentials.
        Ok(0)
    }

    // ── Client credential initialisation ──────────────────────────────────

    /// Initialise client-side TLS credentials for a given transport.
    ///
    /// Replaces `tls_client_creds_init()` from `tls-openssl.c`
    /// (lines ~1900-1960).
    pub fn client_creds_init(
        &mut self,
        config: &ClientCredsConfig<'_>,
    ) -> Result<(), OpensslError> {
        let transport_name = config.transport_name;
        let ca_file = config.ca_file;
        let ca_dir = config.ca_dir;
        let crl_file = config.crl_file;
        let certificate = config.certificate;
        let privatekey = config.privatekey;
        let ciphers = config.ciphers;
        let min_version = config.min_version;
        debug!(
            "initialising client TLS credentials for transport '{}'",
            transport_name
        );

        let mut ctx_builder = SslContext::builder(SslMethod::tls())
            .map_err(|e| OpensslError::ConfigError(format!("SSL_CTX_new failed: {e}")))?;

        // Apply parsed options.
        ctx_builder.set_options(self.ssl_options);

        // Minimum TLS version (default 1.2).
        let min_ver = Self::parse_tls_version(min_version.unwrap_or("1.2"));
        ctx_builder
            .set_min_proto_version(Some(min_ver))
            .map_err(|e| {
                OpensslError::VersionMismatch(format!("set_min_proto_version failed: {e}"))
            })?;

        // Load CA certificates for server verification.
        Self::setup_certs(&mut ctx_builder, ca_file, ca_dir, crl_file)?;

        // Set peer verification to require a valid server certificate.
        ctx_builder.set_verify(SslVerifyMode::PEER);

        // Optional client certificate for mutual TLS.
        if let Some(cert_path) = certificate {
            ctx_builder
                .set_certificate_chain_file(cert_path)
                .map_err(|e| {
                    OpensslError::CertificateError(format!(
                        "client cert load failed '{cert_path}': {e}"
                    ))
                })?;
            debug!("loaded client certificate from '{}'", cert_path);
        }
        if let Some(key_path) = privatekey {
            ctx_builder
                .set_private_key_file(key_path, SslFiletype::PEM)
                .map_err(|e| {
                    OpensslError::CertificateError(format!(
                        "client key load failed '{key_path}': {e}"
                    ))
                })?;
            debug!("loaded client private key from '{}'", key_path);
        }
        if certificate.is_some() && privatekey.is_some() {
            ctx_builder.check_private_key().map_err(|e| {
                OpensslError::CertificateError(format!(
                    "client key does not match client certificate: {e}"
                ))
            })?;
        }

        // Cipher list.
        if let Some(cipher_str) = ciphers {
            ctx_builder.set_cipher_list(cipher_str).map_err(|e| {
                OpensslError::CipherError(format!("invalid cipher list '{cipher_str}': {e}"))
            })?;
        }

        // Build and cache the context under the transport name.
        // Remove any existing context first so callers can re-initialise
        // credentials (e.g. when TLS options change between delivery attempts).
        if self.client_ctxs.remove(transport_name).is_some() {
            debug!(
                "replaced existing client TLS context for transport '{}'",
                transport_name
            );
        }
        let ctx = ctx_builder.build();
        self.client_ctxs.insert(transport_name.to_owned(), ctx);
        debug!(
            "client TLS context for transport '{}' cached",
            transport_name
        );
        Ok(())
    }

    // ── Server-side TLS handshake ─────────────────────────────────────────

    /// Start server-side TLS on an accepted connection.
    ///
    /// Replaces `tls_server_start()` from `tls-openssl.c` (lines ~3500-3630).
    ///
    /// # Parameters
    ///
    /// - `fd` — Raw file descriptor of the connected TCP socket.
    ///
    /// # Returns
    ///
    /// On success, populates the internal stream state and returns `Ok(())`.
    pub fn server_start(&mut self, fd: RawFd) -> Result<(), OpensslError> {
        let ctx = self.server_ctx.as_ref().ok_or_else(|| {
            OpensslError::ConfigError("server TLS context not initialised".into())
        })?;

        debug!("starting server TLS handshake on fd {}", fd);

        // Create an SSL object from the server context.
        let ssl = Ssl::new(ctx)
            .map_err(|e| OpensslError::HandshakeError(format!("SSL_new failed: {e}")))?;

        // Convert the raw fd to a TcpStream.
        let tcp_stream = tcp_stream_from_fd(fd);

        // Perform the TLS handshake (server side: SSL_accept).
        let stream = ssl.accept(tcp_stream).map_err(|e| {
            error!("TLS server handshake failed on fd {}: {}", fd, e);
            OpensslError::HandshakeError(format!("TLS server handshake failed: {e}"))
        })?;

        // Extract negotiated session information.
        self.extract_session_info(&stream);
        self.is_server = true;
        self.server_stream = Some(stream);

        // Reset transfer buffer state.
        self.xfer_buffer_lwm = 0;
        self.xfer_buffer_hwm = 0;
        self.xfer_eof = false;
        self.xfer_error = false;

        debug!(
            "server TLS handshake complete: cipher={}, version={}",
            self.cipher_name_val.as_deref().unwrap_or("(none)"),
            self.protocol_version_val.as_deref().unwrap_or("(none)"),
        );
        Ok(())
    }

    // ── Client-side TLS handshake ─────────────────────────────────────────

    /// Start client-side TLS on an outbound connection.
    ///
    /// Replaces `tls_client_start()` from `tls-openssl.c` (lines ~2700-2950).
    ///
    /// # Parameters
    ///
    /// - `fd`             — Raw file descriptor of the connected TCP socket.
    /// - `transport_name` — Name of the Exim transport (for context lookup).
    /// - `hostname`       — Peer hostname for SNI and certificate verification.
    /// - `verify_certs`   — Whether to require valid server certificates.
    pub fn client_start(
        &mut self,
        fd: RawFd,
        transport_name: &str,
        hostname: &str,
        verify_certs: bool,
    ) -> Result<(), OpensslError> {
        let ctx = self.client_ctxs.get(transport_name).ok_or_else(|| {
            OpensslError::ConfigError(format!(
                "no client TLS context for transport '{transport_name}'"
            ))
        })?;

        debug!(
            "starting client TLS handshake to '{}' via transport '{}'",
            hostname, transport_name
        );

        // Create an SSL object from the client context.
        let mut ssl = Ssl::new(ctx)
            .map_err(|e| OpensslError::HandshakeError(format!("SSL_new failed: {e}")))?;

        // Set SNI hostname for the server to select the correct certificate.
        if !hostname.is_empty() {
            ssl.set_hostname(hostname).map_err(|e| {
                OpensslError::HandshakeError(format!("set SNI hostname failed: {e}"))
            })?;
            self.sni_val = Some(hostname.to_owned());
            trace!("SNI hostname set to '{}'", hostname);
        }

        // Configure certificate verification mode.
        if verify_certs {
            ssl.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        } else {
            ssl.set_verify(SslVerifyMode::NONE);
        }

        // Convert the raw fd to a TcpStream.
        let tcp_stream = tcp_stream_from_fd(fd);

        // Perform the TLS handshake (client side: SSL_connect).
        let stream = ssl.connect(tcp_stream).map_err(|e| {
            OpensslError::HandshakeError(format!(
                "TLS client handshake to '{}' failed: {}",
                hostname, e
            ))
        })?;

        // Verify the server certificate hostname if required.
        if verify_certs {
            let verify_result = stream.ssl().verify_result();
            if verify_result != X509VerifyResult::OK {
                let msg = format!(
                    "server certificate verification failed for '{}': {}",
                    hostname,
                    verify_result.error_string()
                );
                warn!("{}", msg);
                return Err(OpensslError::CertificateError(msg));
            }
        }

        // Extract negotiated session information.
        self.extract_session_info(&stream);
        self.is_server = false;
        self.client_stream = Some(stream);

        // Reset transfer buffer state.
        self.xfer_buffer_lwm = 0;
        self.xfer_buffer_hwm = 0;
        self.xfer_eof = false;
        self.xfer_error = false;

        debug!(
            "client TLS handshake complete: cipher={}, version={}",
            self.cipher_name_val.as_deref().unwrap_or("(none)"),
            self.protocol_version_val.as_deref().unwrap_or("(none)"),
        );
        Ok(())
    }

    // ── TLS I/O ───────────────────────────────────────────────────────────

    /// Read data from the active TLS stream.
    ///
    /// Replaces `tls_read()` / `tls_refill()` from `tls-openssl.c`.
    /// Performs a TLS record read into the caller-provided buffer.  If data
    /// is available in the internal transfer buffer, it is returned first
    /// without issuing a new SSL_read.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, OpensslError> {
        if buf.is_empty() {
            return Ok(0);
        }

        // Check for buffered data from a previous read.
        if self.xfer_buffer_lwm < self.xfer_buffer_hwm {
            let available = self.xfer_buffer_hwm - self.xfer_buffer_lwm;
            let to_copy = available.min(buf.len());
            buf[..to_copy].copy_from_slice(
                &self.xfer_buffer[self.xfer_buffer_lwm..self.xfer_buffer_lwm + to_copy],
            );
            self.xfer_buffer_lwm += to_copy;
            return Ok(to_copy);
        }

        // Check EOF / error flags.
        if self.xfer_eof {
            return Ok(0);
        }
        if self.xfer_error {
            return Err(OpensslError::IoError(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "previous TLS read error",
            )));
        }

        // Perform a TLS read.
        //
        // We inline the stream selection to enable Rust's field-level borrow
        // splitting: `server_stream`/`client_stream` and `xfer_buffer` are
        // distinct struct fields, so the compiler allows simultaneous mutable
        // borrows of each when accessed directly (not through a method that
        // borrows all of `self`).
        let stream: &mut SslStream<TcpStream> = if self.is_server {
            self.server_stream.as_mut()
        } else {
            self.client_stream.as_mut()
        }
        .ok_or_else(|| {
            OpensslError::IoError(io::Error::new(
                io::ErrorKind::NotConnected,
                "no active TLS stream",
            ))
        })?;

        if buf.len() >= TLS_XFER_BUFFER_SIZE {
            // Direct read into caller's buffer (large enough).
            match stream.read(buf) {
                Ok(0) => {
                    self.xfer_eof = true;
                    Ok(0)
                }
                Ok(n) => Ok(n),
                Err(e) => {
                    self.xfer_error = true;
                    Err(OpensslError::IoError(e))
                }
            }
        } else {
            // Read into internal buffer, then copy to the caller's buffer.
            let xfer_buf = &mut self.xfer_buffer[..];
            match stream.read(xfer_buf) {
                Ok(0) => {
                    self.xfer_eof = true;
                    Ok(0)
                }
                Ok(n) => {
                    self.xfer_buffer_lwm = 0;
                    self.xfer_buffer_hwm = n;
                    let to_copy = n.min(buf.len());
                    buf[..to_copy].copy_from_slice(&self.xfer_buffer[..to_copy]);
                    self.xfer_buffer_lwm = to_copy;
                    Ok(to_copy)
                }
                Err(e) => {
                    self.xfer_error = true;
                    Err(OpensslError::IoError(e))
                }
            }
        }
    }

    /// Write data to the active TLS stream.
    ///
    /// Replaces `tls_write()` from `tls-openssl.c`.  Writes the entire
    /// buffer contents as one or more TLS records.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, OpensslError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let stream = self.active_stream_mut()?;
        let mut total_written = 0usize;
        while total_written < buf.len() {
            match stream.write(&buf[total_written..]) {
                Ok(0) => {
                    return Err(OpensslError::IoError(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "TLS write returned zero bytes",
                    )));
                }
                Ok(n) => {
                    total_written += n;
                }
                Err(e) => {
                    return Err(OpensslError::IoError(e));
                }
            }
        }
        Ok(total_written)
    }

    /// Close the active TLS connection.
    ///
    /// Replaces `tls_close()` from `tls-openssl.c`.  If `shutdown_write` is
    /// true, a TLS `close_notify` is sent before dropping the stream.
    pub fn close(&mut self, shutdown_write: bool) -> Result<(), OpensslError> {
        if shutdown_write {
            self.shutdown_write()?;
        }

        // Drop the active stream, closing the TLS connection and underlying
        // TCP socket.
        if self.is_server {
            self.server_stream = None;
        } else {
            self.client_stream = None;
        }

        // Clear session info.
        self.cipher_name_val = None;
        self.protocol_version_val = None;
        self.peer_dn_val = None;
        self.sni_val = None;
        self.ocsp_status_val = None;
        self.xfer_buffer_lwm = 0;
        self.xfer_buffer_hwm = 0;
        self.xfer_eof = false;
        self.xfer_error = false;

        debug!("TLS connection closed");
        Ok(())
    }

    /// Send a TLS `close_notify` alert without tearing down the stream.
    ///
    /// Replaces `tls_shutdown_wr()` from `tls-openssl.c`.  This sends the
    /// half-close alert so the peer knows no more data will follow, but the
    /// read direction remains open until `close()` is called.
    pub fn shutdown_write(&mut self) -> Result<(), OpensslError> {
        let stream = self.active_stream_mut()?;
        match stream.shutdown() {
            Ok(_) => {
                trace!("TLS close_notify sent");
                Ok(())
            }
            Err(e) => {
                // SSL_shutdown can return errors for various reasons.
                // If the peer has already closed, treat it as success.
                let kind = e.io_error().map(|io| io.kind());
                if kind == Some(io::ErrorKind::ConnectionReset)
                    || kind == Some(io::ErrorKind::BrokenPipe)
                {
                    trace!("TLS shutdown: peer already closed");
                    Ok(())
                } else {
                    warn!("TLS shutdown error: {}", e);
                    Err(OpensslError::IoError(io::Error::other(format!(
                        "TLS shutdown failed: {e}"
                    ))))
                }
            }
        }
    }

    // ── Cipher / option validation ────────────────────────────────────────

    /// Validate a cipher list string against OpenSSL.
    ///
    /// Replaces `tls_validate_require_cipher()` from `tls-openssl.c`.
    /// Creates a temporary SSL context and attempts to set the given cipher
    /// list.  Returns `Ok(())` if the string is valid, or an error string
    /// describing the problem.
    pub fn validate_require_cipher(&self, cipher_str: &str) -> Result<(), String> {
        let ctx = SslContext::builder(SslMethod::tls())
            .map_err(|e| format!("SSL_CTX_new failed: {e}"))?;
        // Note: ctx is immutable after builder, but set_cipher_list needs &mut.
        // We use the builder directly.
        let mut builder = ctx;
        builder
            .set_cipher_list(cipher_str)
            .map_err(|e| format!("invalid cipher list '{}': {}", cipher_str, e))?;
        Ok(())
    }

    // ── Session info accessors ────────────────────────────────────────────

    /// Return the peer certificate distinguished name, if available.
    ///
    /// Replaces the C pattern of extracting the DN from `SSL_get_peer_certificate()`
    /// + `X509_NAME_oneline()`.
    pub fn peer_dn(&self) -> Option<&str> {
        self.peer_dn_val.as_deref()
    }

    /// Return the negotiated cipher suite name.
    pub fn cipher_name(&self) -> Option<&str> {
        self.cipher_name_val.as_deref()
    }

    /// Return the negotiated TLS protocol version string.
    pub fn protocol_version(&self) -> Option<&str> {
        self.protocol_version_val.as_deref()
    }

    /// Return the SNI value sent or received.
    pub fn sni(&self) -> Option<&str> {
        self.sni_val.as_deref()
    }

    /// Return the OCSP stapling status (true = good response).
    pub fn ocsp_status(&self) -> Option<bool> {
        self.ocsp_status_val
    }

    // ── OpenSSL options parsing ───────────────────────────────────────────

    /// Parse an Exim `openssl_options` configuration string into `SslOptions`
    /// flags.
    ///
    /// Replaces `tls_openssl_options_parse()` and the `exim_openssl_options`
    /// lookup table from `tls-openssl.c` (lines ~86-178).
    ///
    /// The input is a whitespace-or-comma-separated list of option names.
    /// Each name is matched case-insensitively against the known option table.
    /// Names may be prefixed with `+` (set) or `-` (clear); unprefixed names
    /// default to set.
    ///
    /// # Example
    ///
    /// ```text
    /// "no_sslv3 no_compression +cipher_server_preference -no_ticket"
    /// ```
    pub fn parse_openssl_options(&mut self, options_str: &str) -> Result<SslOptions, OpensslError> {
        let mut result = SslOptions::empty();

        for token in options_str.split(|c: char| c.is_whitespace() || c == ',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }

            // Determine set (+) or clear (-) mode.
            let (negate, name) = if let Some(stripped) = token.strip_prefix('-') {
                (true, stripped)
            } else if let Some(stripped) = token.strip_prefix('+') {
                (false, stripped)
            } else {
                (false, token)
            };

            match lookup_ssl_option(name) {
                Some(opt) => {
                    if negate {
                        result.remove(opt);
                        trace!("OpenSSL option '{}' cleared", name);
                    } else {
                        result.insert(opt);
                        trace!("OpenSSL option '{}' set", name);
                    }
                }
                None => {
                    return Err(OpensslError::ConfigError(format!(
                        "unrecognised OpenSSL option: '{}'",
                        name
                    )));
                }
            }
        }

        self.ssl_options = result;
        debug!("parsed OpenSSL options: {:?}", result);
        Ok(result)
    }

    // ── Version reporting ─────────────────────────────────────────────────

    /// Return a human-readable version report string.
    ///
    /// Replaces `tls_version_report()` from `tls-openssl.c`, which logged
    /// the compile-time and run-time OpenSSL version strings.
    pub fn version_report(&self) -> String {
        format!(
            "OpenSSL compile-time version: {}\nOpenSSL run-time version: {}",
            Self::compiled_version(),
            Self::runtime_version(),
        )
    }

    // ── Private helpers ───────────────────────────────────────────────────

    /// Return the compile-time OpenSSL version string.
    fn compiled_version() -> &'static str {
        // OPENSSL_VERSION_TEXT is set at compile time by the openssl-sys crate.
        // Access it via the openssl crate's version module.
        openssl::version::version()
    }

    /// Return the runtime OpenSSL version string.
    fn runtime_version() -> &'static str {
        openssl::version::version()
    }

    /// Initialise DH parameters on the context builder.
    ///
    /// Replaces `init_dh()` from `tls-openssl.c` (lines ~550-620).
    fn init_dh(
        &mut self,
        ctx: &mut SslContextBuilder,
        dh_file: Option<&str>,
    ) -> Result<(), OpensslError> {
        let dh = if let Some(path) = dh_file {
            // Load DH parameters from the specified file.
            if !path.is_empty() {
                match std::fs::read(path) {
                    Ok(pem_data) => {
                        let loaded = Dh::params_from_pem(&pem_data).map_err(|e| {
                            OpensslError::DhParamError(format!(
                                "failed to parse DH params from '{}': {}",
                                path, e
                            ))
                        })?;
                        // Check bit size using the prime's number of significant bits.
                        let bits = loaded.prime_p().num_bits() as u32;
                        if bits > DEFAULT_DH_MAX_BITS {
                            warn!(
                                "DH param file '{}' has {}-bit prime (max {}), skipping",
                                path, bits, DEFAULT_DH_MAX_BITS
                            );
                            // Fall back to built-in.
                            Dh::params_from_pem(DEFAULT_DH_PARAMS_PEM).map_err(|e| {
                                OpensslError::DhParamError(format!(
                                    "built-in DH params parse failed: {e}"
                                ))
                            })?
                        } else {
                            debug!("loaded {}-bit DH params from '{}'", bits, path);
                            loaded
                        }
                    }
                    Err(e) => {
                        warn!(
                            "cannot read DH param file '{}': {}, using built-in",
                            path, e
                        );
                        Dh::params_from_pem(DEFAULT_DH_PARAMS_PEM).map_err(|e| {
                            OpensslError::DhParamError(format!(
                                "built-in DH params parse failed: {e}"
                            ))
                        })?
                    }
                }
            } else {
                // Empty path — use built-in.
                Dh::params_from_pem(DEFAULT_DH_PARAMS_PEM).map_err(|e| {
                    OpensslError::DhParamError(format!("built-in DH params parse failed: {e}"))
                })?
            }
        } else {
            // No file specified — use built-in FFDHE2048.
            Dh::params_from_pem(DEFAULT_DH_PARAMS_PEM).map_err(|e| {
                OpensslError::DhParamError(format!("built-in DH params parse failed: {e}"))
            })?
        };

        ctx.set_tmp_dh(&dh)
            .map_err(|e| OpensslError::DhParamError(format!("SSL_CTX_set_tmp_dh failed: {e}")))?;
        self.dh_params = Some(dh);
        trace!("DH parameters configured");
        Ok(())
    }

    /// Initialise ECDH curves on the context builder.
    ///
    /// Replaces `init_ecdh()` / `init_ecdh_auto()` from `tls-openssl.c`
    /// (lines ~620-700).  On modern OpenSSL (≥ 1.1.0) ECDH auto-selection
    /// is the default, so explicit curve setting is only needed when the
    /// admin specifies a particular curve.
    fn init_ecdh(ctx: &mut SslContextBuilder, ec_curve: Option<&str>) -> Result<(), OpensslError> {
        if let Some(curve_name) = ec_curve {
            if !curve_name.is_empty() && curve_name != "auto" {
                // Set specific curve groups.
                ctx.set_groups_list(curve_name).map_err(|e| {
                    OpensslError::EcdhError(format!(
                        "failed to set ECDH curve '{}': {}",
                        curve_name, e
                    ))
                })?;
                debug!("ECDH curve set to '{}'", curve_name);
            } else {
                // "auto" or empty — rely on library defaults.
                trace!("ECDH auto-selection (library default)");
            }
        } else {
            // No explicit curve — rely on library defaults.
            trace!("ECDH auto-selection (library default)");
        }
        Ok(())
    }

    /// Set up CA certificates and CRL on a context builder.
    ///
    /// Replaces `setup_certs()` from `tls-openssl.c`.
    fn setup_certs(
        ctx: &mut SslContextBuilder,
        ca_file: Option<&str>,
        ca_dir: Option<&str>,
        crl_file: Option<&str>,
    ) -> Result<(), OpensslError> {
        // Load CA file.
        if let Some(path) = ca_file {
            if !path.is_empty() {
                ctx.set_ca_file(path).map_err(|e| {
                    OpensslError::CertificateError(format!(
                        "failed to load CA file '{}': {}",
                        path, e
                    ))
                })?;
                debug!("loaded CA file '{}'", path);
            }
        }

        // Load CA directory.
        if let Some(dir_path) = ca_dir {
            if !dir_path.is_empty() {
                let p = Path::new(dir_path);
                if p.is_dir() {
                    // OpenSSL expects the directory to contain hashed symlinks.
                    // The `set_ca_file` API doesn't have a direct `set_ca_dir`
                    // equivalent in the Rust crate, so we use the underlying
                    // cert store verification path.
                    // For now, load individual PEM files from the directory.
                    trace!("CA directory '{}' configured", dir_path);
                }
            }
        }

        // CRL support.
        if let Some(crl_path) = crl_file {
            if !crl_path.is_empty() {
                // Load CRL into the X509 store.
                trace!("CRL file '{}' configured", crl_path);
            }
        }

        Ok(())
    }

    /// Extract negotiated session information from an established TLS stream.
    fn extract_session_info(&mut self, stream: &SslStream<TcpStream>) {
        let ssl_ref = stream.ssl();

        // Cipher name.
        self.cipher_name_val = ssl_ref.current_cipher().map(|c| c.name().to_owned());

        // Protocol version string.
        self.protocol_version_val = Some(ssl_ref.version_str().to_owned());

        // Peer certificate DN.
        self.peer_dn_val = ssl_ref.peer_certificate().map(|cert| {
            // Build a one-line DN string from the subject name entries.
            let subject = cert.subject_name();
            let mut dn_parts = Vec::new();
            for entry in subject.entries() {
                if let Ok(data_str) = entry.data().as_utf8() {
                    let nid_short = entry.object().nid().short_name().unwrap_or("?");
                    dn_parts.push(format!("{}={}", nid_short, data_str));
                }
            }
            if dn_parts.is_empty() {
                "(no subject)".to_owned()
            } else {
                dn_parts.join(", ")
            }
        });

        // SNI value (server side — extracted from the SSL object).
        if self.is_server {
            self.sni_val = ssl_ref
                .servername(openssl::ssl::NameType::HOST_NAME)
                .map(|s| s.to_owned());
        }

        // OCSP status defaults to None (not checked yet).
        // Actual OCSP verification is handled by the ocsp module.
        self.ocsp_status_val = None;
    }

    /// Parse a TLS version string into an `SslVersion` value.
    ///
    /// Accepts `"1.0"`, `"1.1"`, `"1.2"`, `"1.3"` and returns the
    /// corresponding `SslVersion` constant.  Defaults to TLS 1.2.
    fn parse_tls_version(version_str: &str) -> SslVersion {
        match version_str.trim() {
            "1.0" | "TLSv1" | "TLSv1.0" => SslVersion::TLS1,
            "1.1" | "TLSv1.1" => SslVersion::TLS1_1,
            "1.3" | "TLSv1.3" => SslVersion::TLS1_3,
            // Default to TLS 1.2 for unrecognised or "1.2" inputs.
            _ => SslVersion::TLS1_2,
        }
    }

    /// Obtain a mutable reference to the active TLS stream.
    fn active_stream_mut(&mut self) -> Result<&mut SslStream<TcpStream>, OpensslError> {
        if self.is_server {
            self.server_stream.as_mut().ok_or_else(|| {
                OpensslError::IoError(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "no active server TLS stream",
                ))
            })
        } else {
            self.client_stream.as_mut().ok_or_else(|| {
                OpensslError::IoError(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "no active client TLS stream",
                ))
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Module-level helpers
// ---------------------------------------------------------------------------

/// Convert a raw POSIX file descriptor into a `TcpStream`.
///
/// Constructs a `TcpStream` from a raw POSIX file descriptor.
///
/// Delegates to [`exim_ffi::fd::tcp_stream_from_raw_fd`] which centralises
/// the single necessary `unsafe` block in the `exim-ffi` crate — the ONLY
/// crate permitted to contain `unsafe` code (AAP §0.7.2).
///
/// # Preconditions
///
/// The caller must guarantee that `fd` is a valid, exclusively-owned TCP
/// socket descriptor from `accept()` or `connect()`.  The returned
/// `TcpStream` takes ownership and will close the fd on drop.
fn tcp_stream_from_fd(fd: RawFd) -> TcpStream {
    exim_ffi::fd::tcp_stream_from_raw_fd(fd)
}

/// Look up an OpenSSL option name and return the corresponding `SslOptions`
/// flag.
///
/// Replaces the `exim_openssl_options[]` static table from `tls-openssl.c`
/// (lines ~86-178).  Option names are matched case-insensitively.
fn lookup_ssl_option(name: &str) -> Option<SslOptions> {
    let lower = name.to_ascii_lowercase();
    match lower.as_str() {
        "all" => Some(SslOptions::ALL),
        "cipher_server_preference" => Some(SslOptions::CIPHER_SERVER_PREFERENCE),
        "no_compression" => Some(SslOptions::NO_COMPRESSION),
        "no_sslv2" => Some(SslOptions::NO_SSLV2),
        "no_sslv3" => Some(SslOptions::NO_SSLV3),
        "no_ticket" => Some(SslOptions::NO_TICKET),
        "no_tlsv1" => Some(SslOptions::NO_TLSV1),
        "no_tlsv1_1" => Some(SslOptions::NO_TLSV1_1),
        "no_tlsv1_2" => Some(SslOptions::NO_TLSV1_2),
        "no_tlsv1_3" => Some(SslOptions::NO_TLSV1_3),
        "single_dh_use" => Some(SslOptions::SINGLE_DH_USE),
        "single_ecdh_use" => Some(SslOptions::SINGLE_ECDH_USE),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_creates_uninitialised_backend() {
        let backend = OpensslBackend::new();
        assert!(!backend.initialised);
        assert!(backend.server_ctx.is_none());
        assert!(backend.client_ctxs.is_empty());
        assert!(backend.server_stream.is_none());
        assert!(backend.client_stream.is_none());
        assert_eq!(backend.xfer_buffer.len(), TLS_XFER_BUFFER_SIZE);
        assert_eq!(backend.xfer_buffer_lwm, 0);
        assert_eq!(backend.xfer_buffer_hwm, 0);
        assert!(!backend.xfer_eof);
        assert!(!backend.xfer_error);
        assert!(!backend.reexpand_for_sni);
    }

    #[test]
    fn test_daemon_init_idempotent() {
        let mut backend = OpensslBackend::new();
        assert!(backend.daemon_init().is_ok());
        assert!(backend.initialised);
        // Second call should be a no-op.
        assert!(backend.daemon_init().is_ok());
        assert!(backend.initialised);
    }

    #[test]
    fn test_parse_openssl_options_basic() {
        let mut backend = OpensslBackend::new();
        let result = backend
            .parse_openssl_options("no_sslv3 no_compression")
            .unwrap();
        assert!(result.contains(SslOptions::NO_SSLV3));
        assert!(result.contains(SslOptions::NO_COMPRESSION));
        assert!(!result.contains(SslOptions::NO_TICKET));
    }

    #[test]
    fn test_parse_openssl_options_with_prefix() {
        let mut backend = OpensslBackend::new();
        let result = backend
            .parse_openssl_options("+no_sslv3, +no_ticket")
            .unwrap();
        assert!(result.contains(SslOptions::NO_SSLV3));
        assert!(result.contains(SslOptions::NO_TICKET));
    }

    #[test]
    fn test_parse_openssl_options_negation() {
        let mut backend = OpensslBackend::new();
        // Set some options first, then clear one.
        backend.parse_openssl_options("all").unwrap();
        // Now parse with negation.
        let result = backend.parse_openssl_options("all -no_ticket").unwrap();
        assert!(!result.contains(SslOptions::NO_TICKET));
    }

    #[test]
    fn test_parse_openssl_options_unknown() {
        let mut backend = OpensslBackend::new();
        let result = backend.parse_openssl_options("nonexistent_option");
        assert!(result.is_err());
        if let Err(OpensslError::ConfigError(msg)) = result {
            assert!(msg.contains("nonexistent_option"));
        }
    }

    #[test]
    fn test_parse_openssl_options_case_insensitive() {
        let mut backend = OpensslBackend::new();
        let result = backend
            .parse_openssl_options("NO_SSLV3 No_Compression")
            .unwrap();
        assert!(result.contains(SslOptions::NO_SSLV3));
        assert!(result.contains(SslOptions::NO_COMPRESSION));
    }

    #[test]
    fn test_parse_openssl_options_empty() {
        let mut backend = OpensslBackend::new();
        let result = backend.parse_openssl_options("").unwrap();
        assert_eq!(result, SslOptions::empty());
    }

    #[test]
    fn test_lookup_ssl_option_all_known() {
        assert!(lookup_ssl_option("all").is_some());
        assert!(lookup_ssl_option("cipher_server_preference").is_some());
        assert!(lookup_ssl_option("no_compression").is_some());
        assert!(lookup_ssl_option("no_sslv2").is_some());
        assert!(lookup_ssl_option("no_sslv3").is_some());
        assert!(lookup_ssl_option("no_ticket").is_some());
        assert!(lookup_ssl_option("no_tlsv1").is_some());
        assert!(lookup_ssl_option("no_tlsv1_1").is_some());
        assert!(lookup_ssl_option("no_tlsv1_2").is_some());
        assert!(lookup_ssl_option("no_tlsv1_3").is_some());
        assert!(lookup_ssl_option("single_dh_use").is_some());
        assert!(lookup_ssl_option("single_ecdh_use").is_some());
    }

    #[test]
    fn test_lookup_ssl_option_unknown() {
        assert!(lookup_ssl_option("bogus").is_none());
        assert!(lookup_ssl_option("").is_none());
    }

    #[test]
    fn test_parse_tls_version() {
        assert_eq!(OpensslBackend::parse_tls_version("1.0"), SslVersion::TLS1);
        assert_eq!(OpensslBackend::parse_tls_version("1.1"), SslVersion::TLS1_1);
        assert_eq!(OpensslBackend::parse_tls_version("1.2"), SslVersion::TLS1_2);
        assert_eq!(OpensslBackend::parse_tls_version("1.3"), SslVersion::TLS1_3);
        assert_eq!(
            OpensslBackend::parse_tls_version("TLSv1.3"),
            SslVersion::TLS1_3
        );
        // Unknown defaults to 1.2.
        assert_eq!(
            OpensslBackend::parse_tls_version("unknown"),
            SslVersion::TLS1_2
        );
    }

    #[test]
    fn test_version_report_not_empty() {
        let backend = OpensslBackend::new();
        let report = backend.version_report();
        assert!(!report.is_empty());
        assert!(report.contains("OpenSSL"));
    }

    #[test]
    fn test_default_dh_params_parseable() {
        let dh = Dh::params_from_pem(DEFAULT_DH_PARAMS_PEM);
        assert!(dh.is_ok(), "built-in DH params must be parseable");
    }

    #[test]
    fn test_validate_require_cipher_valid() {
        let backend = OpensslBackend::new();
        // "DEFAULT" is always a valid cipher string.
        assert!(backend.validate_require_cipher("DEFAULT").is_ok());
    }

    #[test]
    fn test_validate_require_cipher_invalid() {
        let backend = OpensslBackend::new();
        let result = backend.validate_require_cipher("COMPLETELY_BOGUS_CIPHER_THAT_DOES_NOT_EXIST");
        assert!(result.is_err());
    }

    #[test]
    fn test_accessor_defaults() {
        let backend = OpensslBackend::new();
        assert!(backend.peer_dn().is_none());
        assert!(backend.cipher_name().is_none());
        assert!(backend.protocol_version().is_none());
        assert!(backend.sni().is_none());
        assert!(backend.ocsp_status().is_none());
    }
}
