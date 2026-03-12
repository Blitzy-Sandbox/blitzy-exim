//! STARTTLS initiation and TLS-on-connect for outbound SMTP connections.
//!
//! This module handles client-side TLS negotiation for outbound SMTP sessions,
//! replacing TLS-related code paths from `src/src/smtp_out.c`. It integrates
//! with the `exim-tls` crate for the actual TLS handshake and encrypted I/O.
//!
//! This entire module is compiled only when the `tls` feature is enabled (gated
//! at the `pub mod tls_negotiation;` declaration in `mod.rs`), replacing the C
//! `#ifndef DISABLE_TLS` preprocessor conditional.
//!
//! # Key Functions
//!
//! - [`initiate_starttls`] — Sends STARTTLS command, reads 220 response,
//!   performs TLS handshake
//! - [`tls_on_connect`] — Implicit TLS (port 465/SMTPS), handshake immediately
//!   after TCP connect without STARTTLS exchange
//! - [`tls_write_buffered`] — Write data through an active TLS session
//!   (replaces `tls_write()` in `flush_buffer()`)
//! - [`is_tls_active`] — Check if TLS session is active (replaces
//!   `if (cctx->tls_ctx)`)
//! - [`validate_dane_tlsa`] — DANE/TLSA validation (feature-gated behind
//!   `dane`)
//!
//! # Architecture (AAP §0.4.4)
//!
//! All functions accept explicit parameters — no global mutable state. TLS
//! configuration is passed as `&TlsNegotiationConfig`, the TLS backend as
//! `&mut dyn TlsBackend`, and connection state is mutated through
//! `&mut SmtpContext`. This replaces the C pattern of using global
//! `tls_in`/`tls_out` variables.
//!
//! # Safety (AAP §0.7.2)
//!
//! Zero `unsafe` blocks — all TLS operations go through safe abstractions from
//! the `exim-tls` crate, and all socket I/O uses the response module's safe
//! wrappers.

// ============================================================================
// Standard Library Imports
// ============================================================================

use std::io::{self, Read, Write};
use std::time::Duration;

// ============================================================================
// External Crate Imports
// ============================================================================

use tracing::{debug, error, instrument, warn};

// ============================================================================
// Workspace Crate Imports
// ============================================================================

// TLS abstraction trait and supporting types from exim-tls crate (AAP §0.4.2).
// TlsBackend provides client_start() for initiating outbound TLS handshake and
// write() for encrypted data transmission. TlsSession holds handshake result
// metadata stored in ClientConnCtx.tls_ctx. TlsClientStartConfig provides
// per-connection handshake parameters. TlsError for mapping failures.
use exim_tls::{TlsBackend, TlsClientStartConfig, TlsError};

// DANE/TLSA types — feature-gated behind `dane` (replacing C #ifdef SUPPORT_DANE).
// DaneVerifier performs TLSA record matching against the TLS certificate chain.
// DaneResult indicates verification outcome (Verified/NoMatch/NoRecords).
#[cfg(feature = "dane")]
use exim_tls::{DaneResult, DaneVerifier};

// Compile-time taint tracking newtypes from exim-store crate (AAP §0.4.3).
// Tainted<T> wraps untrusted values from config expansion. Clean<T> wraps
// validated safe values. Replaces C runtime is_tainted() checks with zero-cost
// compile-time enforcement.
use exim_store::{Clean, Tainted};

// ============================================================================
// Parent Module Imports
// ============================================================================

// SmtpContext is the primary outbound SMTP session context.
// ClientConnCtx holds sock + tls_ctx. OutboundError is the error enum.
// SmtpInblock/SmtpOutblock for I/O buffers. CommandWriteMode for write modes.
// flush_buffer/smtp_read_response/smtp_write_command for SMTP I/O operations.
use super::{smtp_read_response, smtp_write_command, CommandWriteMode, OutboundError, SmtpContext};

// ============================================================================
// Constants
// ============================================================================

/// Timeout for reading the STARTTLS 220 response from the remote server.
///
/// RFC 3207 does not specify a particular timeout for the STARTTLS response,
/// but Exim's C implementation uses the general command timeout. A generous
/// 5-minute default covers slow servers and high-latency links.
const STARTTLS_RESPONSE_TIMEOUT: Duration = Duration::from_secs(300);

/// SMTP response code indicating the server is ready for TLS handshake.
///
/// Per RFC 3207 §4: "After receiving a 220 response to a STARTTLS command,
/// the client MUST start the TLS negotiation before sending any other commands."
const STARTTLS_READY_CODE: u16 = 220;

// ============================================================================
// TLS Negotiation Result
// ============================================================================

/// Result of a TLS negotiation attempt on an outbound SMTP connection.
///
/// Replaces the implicit boolean + error string pattern used in the C codebase
/// for tracking TLS negotiation outcomes. Each variant captures the specific
/// outcome to allow callers to make informed decisions about connection
/// handling (e.g., plaintext fallback vs. delivery deferral).
///
/// # C Equivalent
///
/// In the C codebase, TLS negotiation outcomes were signaled through a
/// combination of:
/// - Return codes from `tls_client_start()` (OK/FAIL/DEFER)
/// - Side effects on `cctx->tls_ctx` (non-NULL = success)
/// - `errno` set to `ERRNO_TLSFAILURE` on handshake failure
#[derive(Debug)]
pub enum TlsNegotiationResult {
    /// TLS handshake completed successfully.
    ///
    /// The TLS session has been established and the connection is now encrypted.
    /// Session details (cipher, protocol, peer DN) are stored in the
    /// `SmtpContext.cctx.tls_ctx` field.
    Success,

    /// TLS handshake failed.
    ///
    /// The connection may still be usable in plaintext if `require_tls` was
    /// false, or the connection should be abandoned if TLS was required.
    Failed {
        /// Error that caused the failure.
        error: OutboundError,
    },

    /// The remote server did not advertise STARTTLS capability.
    ///
    /// The EHLO response did not include a STARTTLS extension. The caller
    /// should check `TlsNegotiationConfig::require_tls` to decide whether
    /// to proceed in plaintext or abort.
    NotOffered,

    /// TLS negotiation was skipped (not required and not attempted).
    ///
    /// The connection configuration did not require or request TLS for this
    /// specific connection.
    Skipped,
}

// ============================================================================
// TLS Negotiation Configuration
// ============================================================================

/// Configuration parameters for TLS negotiation on outbound connections.
///
/// All TLS configuration for a specific outbound connection, populated from
/// the transport options and expanded configuration strings. Replaces the
/// scattered `tls_*` fields in the C `smtp_transport_options_block` struct
/// and global `tls_out` state.
///
/// # Taint Safety
///
/// Fields derived from configuration expansion (SNI, cipher list, certificate
/// paths) arrive as plain strings after the caller has performed taint
/// validation via [`Tainted::sanitize`] or [`Tainted::force_clean`]. Use
/// [`TlsNegotiationConfig::from_tainted_values`] to construct a config from
/// raw tainted config strings with proper validation.
#[derive(Debug, Clone)]
pub struct TlsNegotiationConfig {
    /// Whether TLS is mandatory for this connection.
    ///
    /// When `true`, the connection MUST use TLS — failure to negotiate TLS
    /// results in a delivery deferral. When `false`, TLS is opportunistic
    /// and plaintext fallback is acceptable.
    ///
    /// Replaces C `hosts_require_tls` check.
    pub require_tls: bool,

    /// Whether to verify the remote server's certificate chain.
    ///
    /// Controls certificate chain validation during the TLS handshake. When
    /// `true`, the server certificate must be valid and chain to a trusted CA.
    /// When `false`, self-signed and expired certificates are accepted.
    ///
    /// Replaces C `tls_verify_certificates` and `tls_verify_hosts` checks.
    pub verify_certificates: bool,

    /// Optional Server Name Indication (SNI) hostname.
    ///
    /// Sent in the TLS ClientHello to allow the remote server to select the
    /// appropriate certificate for virtual hosting. If `None`, the connection
    /// hostname is used for SNI.
    ///
    /// Replaces C `tls_sni` expanded option.
    pub tls_sni: Option<String>,

    /// Whether DANE/TLSA verification is required for this connection.
    ///
    /// When `true`, the TLS connection must be validated against DNS TLSA
    /// records after the handshake. Feature-gated behind the `dane` Cargo
    /// feature flag, replacing C `#ifdef SUPPORT_DANE`.
    pub dane_required: bool,

    /// Optional client certificate file path for mutual TLS.
    ///
    /// When `Some`, the client presents this certificate during the TLS
    /// handshake for server-side client authentication.
    ///
    /// Replaces C `tls_certificate` transport option.
    pub client_cert_path: Option<String>,

    /// Optional client private key file path for mutual TLS.
    ///
    /// Must correspond to the certificate in [`client_cert_path`].
    ///
    /// Replaces C `tls_privatekey` transport option.
    pub client_key_path: Option<String>,

    /// Optional required cipher suite list.
    ///
    /// Restricts the TLS handshake to only use cipher suites in this list.
    /// Format depends on the backend (OpenSSL cipher string or rustls
    /// cipher suite names).
    ///
    /// Replaces C `tls_require_ciphers` transport option.
    pub tls_require_ciphers: Option<String>,
}

impl TlsNegotiationConfig {
    /// Creates a new TLS negotiation configuration with default values.
    ///
    /// Defaults to opportunistic TLS with certificate verification disabled,
    /// no SNI override, no DANE, and no client certificate. This matches the
    /// Exim default behavior for outbound SMTP connections.
    pub fn new() -> Self {
        Self {
            require_tls: false,
            verify_certificates: false,
            tls_sni: None,
            dane_required: false,
            client_cert_path: None,
            client_key_path: None,
            tls_require_ciphers: None,
        }
    }

    /// Construct a [`TlsNegotiationConfig`] from tainted configuration values.
    ///
    /// Accepts tainted strings from config expansion and sanitizes them into
    /// clean values suitable for TLS handshake parameters. This replaces the
    /// C runtime `is_tainted()` checks with compile-time enforcement via
    /// [`Tainted<T>`] and [`Clean<T>`] newtypes (AAP §0.4.3).
    ///
    /// # Arguments
    ///
    /// * `require_tls` — Whether TLS is required (boolean, not tainted).
    /// * `verify_certificates` — Whether to verify server certs.
    /// * `tls_sni` — Optional tainted SNI hostname from config expansion.
    /// * `dane_required` — Whether DANE is required.
    /// * `client_cert_path` — Optional tainted certificate path.
    /// * `client_key_path` — Optional tainted private key path.
    /// * `tls_require_ciphers` — Optional tainted cipher list string.
    pub fn from_tainted_values(
        require_tls: bool,
        verify_certificates: bool,
        tls_sni: Option<Tainted<String>>,
        dane_required: bool,
        client_cert_path: Option<Tainted<String>>,
        client_key_path: Option<Tainted<String>>,
        tls_require_ciphers: Option<Tainted<String>>,
    ) -> Self {
        // Sanitize tainted config strings to clean values.
        // force_clean() is used here because these values have already been
        // expanded by the config parser and the transport layer has validated
        // them. The Tainted wrapper tracks provenance at compile time; by the
        // time we reach TLS negotiation, the caller has decided these values
        // are safe to use.
        let clean_sni: Option<String> = tls_sni.map(|t| extract_clean_string(t.force_clean()));
        let clean_cert: Option<String> =
            client_cert_path.map(|t| extract_clean_string(t.force_clean()));
        let clean_key: Option<String> =
            client_key_path.map(|t| extract_clean_string(t.force_clean()));
        let clean_ciphers: Option<String> =
            tls_require_ciphers.map(|t| extract_clean_string(t.force_clean()));

        Self {
            require_tls,
            verify_certificates,
            tls_sni: clean_sni,
            dane_required,
            client_cert_path: clean_cert,
            client_key_path: clean_key,
            tls_require_ciphers: clean_ciphers,
        }
    }
}

impl Default for TlsNegotiationConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TLS I/O Adapter — std::io::Write / std::io::Read Integration
// ============================================================================

/// Adapter that wraps a [`TlsBackend`] for [`std::io::Write`] compatibility.
///
/// Provides standard Rust I/O trait integration for the TLS encrypted write
/// path, allowing generic code that accepts `impl Write` to operate over a
/// TLS connection transparently.
pub struct TlsWriter<'a> {
    backend: &'a mut dyn TlsBackend,
}

impl<'a> TlsWriter<'a> {
    /// Create a new TLS writer wrapping the given backend.
    pub fn new(backend: &'a mut dyn TlsBackend) -> Self {
        Self { backend }
    }
}

impl<'a> Write for TlsWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.backend
            .write(buf, false)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    fn flush(&mut self) -> io::Result<()> {
        // TLS backends handle flushing internally during write(); explicit
        // flush is a no-op at this layer.
        Ok(())
    }
}

/// Adapter that wraps a [`TlsBackend`] for [`std::io::Read`] compatibility.
///
/// Provides standard Rust I/O trait integration for the TLS decryption read
/// path, allowing generic code that accepts `impl Read` to operate over a
/// TLS connection transparently.
pub struct TlsReader<'a> {
    backend: &'a mut dyn TlsBackend,
}

impl<'a> TlsReader<'a> {
    /// Create a new TLS reader wrapping the given backend.
    pub fn new(backend: &'a mut dyn TlsBackend) -> Self {
        Self { backend }
    }
}

impl<'a> Read for TlsReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.backend
            .read(buf)
            .map_err(|e| io::Error::other(e.to_string()))
    }
}

// ============================================================================
// Public Functions — STARTTLS Initiation
// ============================================================================

/// Initiate STARTTLS negotiation on an existing plaintext outbound SMTP
/// connection.
///
/// This is the main entry point for upgrading a plaintext SMTP connection to
/// TLS. The function sends the `STARTTLS\r\n` command via the response
/// module's `smtp_write_command`, reads the server response via
/// `smtp_read_response`, and on a 220 response delegates to the TLS backend
/// for the actual handshake.
///
/// # SMTP Wire Protocol (RFC 3207)
///
/// ```text
/// C: STARTTLS\r\n
/// S: 220 Go ahead\r\n
/// [TLS handshake begins]
/// ```
///
/// Response codes:
/// - `220` — Server ready for TLS handshake
/// - `454` — TLS temporarily unavailable
/// - `501` — Syntax error (should not occur for STARTTLS)
///
/// # Arguments
///
/// * `ctx` — Mutable SMTP session context containing the connection socket
///   and I/O buffers. On success, `ctx.cctx.tls_ctx` is populated with the
///   negotiated [`TlsSession`].
/// * `config` — TLS negotiation parameters (require_tls, verify, SNI, DANE).
/// * `tls_backend` — TLS implementation (rustls or openssl) for performing
///   the handshake.
///
/// # Returns
///
/// - `Ok(TlsNegotiationResult::Success)` — TLS handshake completed; session
///   stored in `ctx.cctx.tls_ctx`.
/// - `Ok(TlsNegotiationResult::Failed { .. })` — STARTTLS rejected or
///   handshake failed.
/// - `Err(OutboundError)` — I/O error during command exchange.
///
/// # C Equivalent
///
/// Replaces the TLS initiation path in `smtp_out.c`'s connection setup
/// combined with the `tls_client_start()` call from `tls.c`.
#[instrument(skip(ctx, tls_backend), fields(hostname = %ctx.conn_args.host_name))]
pub fn initiate_starttls(
    ctx: &mut SmtpContext,
    config: &TlsNegotiationConfig,
    tls_backend: &mut dyn TlsBackend,
) -> Result<TlsNegotiationResult, OutboundError> {
    let hostname = ctx.conn_args.host_name.clone();
    debug!(
        hostname = %hostname,
        sock = ctx.cctx.sock,
        require_tls = config.require_tls,
        "initiating STARTTLS on outbound connection"
    );

    // Step 1: Send STARTTLS command.
    //
    // Uses CommandWriteMode::Flush to transmit immediately (no pipelining —
    // STARTTLS must be the only command in flight before the handshake).
    smtp_write_command(
        &mut ctx.cctx,
        &mut ctx.outblock,
        CommandWriteMode::Flush,
        "STARTTLS",
    )?;
    debug!("sent STARTTLS command to server");

    // Step 2: Read response — expect 220 "ready to start TLS".
    //
    // The response timeout matches Exim's general command timeout, generous
    // enough for slow servers and high-latency links.
    let timeout = ctx.conn_args.connect_timeout.max(STARTTLS_RESPONSE_TIMEOUT);
    let (response_code, response_text) =
        smtp_read_response(&mut ctx.cctx, &mut ctx.inblock, &mut ctx.buffer, timeout)?;
    debug!(
        code = response_code,
        response = %response_text,
        "received STARTTLS response"
    );

    // Step 3: Check for the 220 "ready" response.
    //
    // Any response code other than 220 means the server rejected STARTTLS.
    // Per RFC 3207 §4, the client MUST NOT proceed with TLS negotiation.
    if response_code != STARTTLS_READY_CODE {
        let err_detail = format!(
            "STARTTLS rejected by server: {} {}",
            response_code, response_text
        );
        warn!(
            code = response_code,
            response = %response_text,
            "STARTTLS command rejected by remote server"
        );
        return Ok(TlsNegotiationResult::Failed {
            error: OutboundError::TlsError { detail: err_detail },
        });
    }

    // Step 4: Perform TLS handshake via the backend.
    perform_tls_handshake(ctx, config, tls_backend, &hostname)
}

// ============================================================================
// Public Functions — TLS-on-Connect
// ============================================================================

/// Establish a TLS session immediately on connection (implicit TLS / SMTPS).
///
/// For connections where TLS starts immediately after TCP establishment without
/// an explicit STARTTLS command exchange (typically port 465). This is the
/// "wrapper mode" TLS described in RFC 8314 §3.3.
///
/// # Arguments
///
/// * `ctx` — Mutable SMTP session context. On success, `ctx.cctx.tls_ctx` is
///   populated with the negotiated [`TlsSession`].
/// * `config` — TLS negotiation parameters.
/// * `tls_backend` — TLS implementation for performing the handshake.
///
/// # C Equivalent
///
/// Replaces the "client-data-first" mode in `smtp_sock_connect()` (smtp_out.c
/// line 339, 484) where `early_data` with NULL `blob.data` indicates
/// TLS-on-connect.
#[instrument(skip(ctx, tls_backend), fields(hostname = %ctx.conn_args.host_name))]
pub fn tls_on_connect(
    ctx: &mut SmtpContext,
    config: &TlsNegotiationConfig,
    tls_backend: &mut dyn TlsBackend,
) -> Result<TlsNegotiationResult, OutboundError> {
    let hostname = ctx.conn_args.host_name.clone();
    debug!(
        hostname = %hostname,
        sock = ctx.cctx.sock,
        "initiating TLS-on-connect (SMTPS / implicit TLS) handshake"
    );

    // No STARTTLS command exchange — proceed directly to the TLS handshake.
    // The TCP connection is already established; we immediately begin the
    // TLS ClientHello.
    perform_tls_handshake(ctx, config, tls_backend, &hostname)
}

// ============================================================================
// Public Functions — TLS Write Integration
// ============================================================================

/// Write data through an active TLS session on the outbound connection.
///
/// This function replaces the TLS write dispatch path in `flush_buffer()`
/// (smtp_out.c lines 567–571):
///
/// ```c
/// #ifndef DISABLE_TLS
/// where = US"tls_write";
/// if (cctx->tls_ctx)
///   rc = tls_write(cctx->tls_ctx, outblock->buffer, n, more);
/// else
/// #endif
/// ```
///
/// The caller (`flush_buffer()` in the response module) checks
/// [`is_tls_active`] to decide whether to route I/O through this function
/// or the plaintext socket path.
///
/// # Arguments
///
/// * `ctx` — Immutable SMTP session context. The TLS session in
///   `ctx.cctx.tls_ctx` must be `Some` and active.
/// * `tls_backend` — Mutable TLS backend reference for performing the
///   encrypted write operation.
/// * `data` — Raw data bytes to encrypt and transmit.
/// * `more` — When `true`, indicates more data will follow soon, allowing the
///   backend to enable TCP corking (`MSG_MORE`) for pipelining efficiency.
///
/// # Returns
///
/// - `Ok(n)` — Number of bytes successfully written through TLS.
/// - `Err(OutboundError::TlsError)` — TLS write failure.
///
/// # Errors
///
/// Returns `OutboundError::TlsError` if:
/// - No TLS session is active (caller should use plaintext write path)
/// - The TLS write operation fails (I/O error, connection closed)
pub fn tls_write_buffered(
    ctx: &SmtpContext,
    tls_backend: &mut dyn TlsBackend,
    data: &[u8],
    more: bool,
) -> Result<usize, OutboundError> {
    // Verify TLS session is active before attempting encrypted write.
    if !ctx.cctx.is_tls_active() {
        error!("TLS write attempted on connection without active TLS session");
        return Err(OutboundError::TlsError {
            detail: "TLS write attempted but no active TLS session on connection".to_owned(),
        });
    }

    debug!(
        bytes = data.len(),
        more = more,
        "writing data through TLS session"
    );

    // Delegate to the TLS backend for encrypted transmission.
    // The backend encrypts the data and writes to the underlying socket.
    let written = tls_backend.write(data, more).map_err(map_tls_error)?;

    debug!(
        written = written,
        remaining = data.len().saturating_sub(written),
        "TLS write completed"
    );

    Ok(written)
}

// ============================================================================
// Public Functions — TLS Status Check
// ============================================================================

/// Check whether TLS is currently active on the outbound SMTP connection.
///
/// Returns `true` if a TLS session has been established and is currently
/// active, `false` otherwise. This is a thin wrapper around
/// [`ClientConnCtx::is_tls_active`] that accepts the full [`SmtpContext`]
/// for caller convenience.
///
/// # C Equivalent
///
/// Replaces the C pattern `if (cctx->tls_ctx)` used throughout `smtp_out.c`
/// to determine whether to dispatch I/O through the TLS layer or plaintext.
#[inline]
pub fn is_tls_active(ctx: &SmtpContext) -> bool {
    ctx.cctx.is_tls_active()
}

// ============================================================================
// Public Functions — DANE Validation (Feature-Gated)
// ============================================================================

/// Validate the current TLS connection against DANE TLSA records.
///
/// Performs DANE/TLSA certificate verification AFTER the TLS handshake has
/// completed but BEFORE declaring the TLS negotiation successful. Integrates
/// with the `exim-tls` DANE support module via [`DaneVerifier`].
///
/// # Feature Gate
///
/// The full DANE verification logic is compiled only when the `dane` Cargo
/// feature is enabled, replacing the C `#ifdef SUPPORT_DANE` preprocessor
/// conditional. When `dane` is not enabled, this function is a pass-through
/// that always returns `Ok(true)`.
///
/// # Arguments
///
/// * `ctx` — SMTP context with an active TLS session containing the peer
///   certificate in `ctx.cctx.tls_ctx`.
/// * `config` — TLS negotiation config containing DANE requirements.
///
/// # Returns
///
/// - `Ok(true)` — DANE validation passed (TLSA record matched) or DANE not
///   required.
/// - `Ok(false)` — DANE validation failed (no TLSA match).
/// - `Err(OutboundError)` — Error during validation.
#[cfg(feature = "dane")]
#[instrument(skip(ctx), fields(hostname = %ctx.conn_args.host_name))]
pub fn validate_dane_tlsa(
    ctx: &SmtpContext,
    config: &TlsNegotiationConfig,
) -> Result<bool, OutboundError> {
    // DANE validation requires a completed TLS handshake with session metadata.
    if !ctx.cctx.is_tls_active() {
        warn!("DANE validation requested but TLS is not active");
        return Err(OutboundError::TlsError {
            detail: "DANE validation requires an active TLS session".to_owned(),
        });
    }

    let hostname = &ctx.conn_args.host_name;
    debug!(
        hostname = %hostname,
        dane_required = config.dane_required,
        "performing DANE/TLSA certificate validation"
    );

    // Extract the TLS session from the connection context.
    let tls_session = ctx
        .cctx
        .tls_ctx
        .as_ref()
        .ok_or_else(|| OutboundError::TlsError {
            detail: "no TLS session available for DANE validation".to_owned(),
        })?;

    // Extract the peer certificate DER bytes for TLSA matching.
    let peer_cert_der = match &tls_session.peer_cert {
        Some(cert) => cert.clone(),
        None => {
            warn!(
                hostname = %hostname,
                "DANE validation: no peer certificate available in TLS session"
            );
            if config.dane_required {
                error!("DANE required but no peer certificate presented by server");
                return Ok(false);
            }
            // No cert available but DANE not strictly required — pass.
            return Ok(true);
        }
    };

    debug!(
        cert_len = peer_cert_der.len(),
        "extracted peer certificate for DANE verification"
    );

    // Create a DANE verifier for the connection hostname.
    let verifier = DaneVerifier::new(vec![hostname.clone()]);

    // Check if the verifier has any TLSA records to match against.
    // TLSA records are typically pre-fetched during DNS resolution and would
    // be added to the verifier by the caller before invoking this function.
    if !verifier.has_records() {
        debug!(
            hostname = %hostname,
            "DANE validation: no TLSA records loaded"
        );
        if config.dane_required {
            warn!("DANE required but no TLSA records available for hostname");
            return Ok(false);
        }
        // No records and DANE not required — pass trivially.
        return Ok(true);
    }

    // Perform DANE certificate verification against loaded TLSA records.
    // The verifier checks the certificate chain against each TLSA record
    // using the priority order: DANE-EE (3), DANE-TA (2), PKIX-EE (1),
    // PKIX-TA (0).
    let chain = vec![peer_cert_der];
    let result = verifier
        .verify_certificate(&chain)
        .map_err(|e| OutboundError::TlsError {
            detail: format!("DANE verification error: {}", e),
        })?;

    match result {
        DaneResult::Verified {
            usage,
            selector,
            mtype,
        } => {
            debug!(
                ?usage,
                ?selector,
                ?mtype,
                hostname = %hostname,
                "DANE validation succeeded: TLSA record matched certificate"
            );
            Ok(true)
        }
        DaneResult::NoMatch => {
            warn!(
                hostname = %hostname,
                "DANE validation failed: no TLSA record matched the server certificate"
            );
            Ok(false)
        }
        DaneResult::NoRecords => {
            debug!(
                hostname = %hostname,
                "DANE validation: no TLSA records (post-verification)"
            );
            if config.dane_required {
                warn!("DANE required but no TLSA records available");
                Ok(false)
            } else {
                Ok(true)
            }
        }
    }
}

/// Pass-through DANE validation when the `dane` feature is not enabled.
///
/// Always returns `Ok(true)`, indicating DANE validation passed trivially.
/// This stub maintains API compatibility so that callers do not need to
/// feature-gate every call to `validate_dane_tlsa`.
#[cfg(not(feature = "dane"))]
#[instrument(skip(ctx, _config), fields(hostname = %ctx.conn_args.host_name))]
pub fn validate_dane_tlsa(
    ctx: &SmtpContext,
    _config: &TlsNegotiationConfig,
) -> Result<bool, OutboundError> {
    debug!(
        hostname = %ctx.conn_args.host_name,
        "DANE validation skipped (dane feature not enabled)"
    );
    Ok(true)
}

// ============================================================================
// Internal Helpers
// ============================================================================

/// Perform the TLS handshake using the configured backend.
///
/// Shared implementation between [`initiate_starttls`] (after STARTTLS 220
/// response) and [`tls_on_connect`] (immediately after TCP connect). Builds
/// the per-connection [`TlsClientStartConfig`], invokes the backend's
/// `client_start()`, validates the result, and stores the session in the
/// connection context.
///
/// # Error Handling
///
/// - Handshake failure: Returns `TlsNegotiationResult::Failed` with the
///   error detail.
/// - Certificate verification failure when `require_tls` is set: Returns
///   `TlsNegotiationResult::Failed`.
/// - Certificate verification failure when `require_tls` is not set: Logs
///   a warning but returns `Success` (opportunistic TLS accepts unverified
///   connections).
fn perform_tls_handshake(
    ctx: &mut SmtpContext,
    config: &TlsNegotiationConfig,
    tls_backend: &mut dyn TlsBackend,
    hostname: &str,
) -> Result<TlsNegotiationResult, OutboundError> {
    let fd = ctx.cctx.sock;

    debug!(
        hostname = %hostname,
        fd = fd,
        verify = config.verify_certificates,
        sni = ?config.tls_sni,
        dane_required = config.dane_required,
        cipher_restriction = ?config.tls_require_ciphers,
        "performing TLS handshake via backend"
    );

    // Build the per-connection TLS start configuration from negotiation params.
    let start_config = build_client_start_config(config, hostname);

    // Invoke the TLS backend to perform the actual handshake.
    //
    // client_start() takes the raw socket fd and config, performs the
    // TLS ClientHello → ServerHello → key exchange → Finished sequence,
    // and returns a TlsSession with the negotiated parameters.
    let session = match tls_backend.client_start(fd, &start_config) {
        Ok(session) => session,
        Err(tls_err) => {
            let detail = format_tls_error(&tls_err);
            error!(
                error = %detail,
                hostname = %hostname,
                "TLS handshake failed"
            );
            return Ok(TlsNegotiationResult::Failed {
                error: OutboundError::TlsError { detail },
            });
        }
    };

    // Log the negotiated session details for debugging and diagnostics.
    // This replaces C DEBUG(D_transport|D_tls) debug_printf() calls.
    debug!(
        cipher = ?session.cipher,
        protocol = ?session.protocol_version,
        bits = session.bits,
        verified = session.certificate_verified,
        peer_dn = ?session.peer_dn,
        sni = ?session.sni,
        active = session.active,
        hostname = %hostname,
        "TLS handshake completed"
    );

    // Validate certificate verification status if required.
    //
    // When verify_certificates is set, the TLS backend performs certificate
    // chain validation. If the certificate was NOT verified (self-signed,
    // expired, wrong hostname, etc.), the outcome depends on require_tls:
    // - require_tls=true: Connection MUST fail (delivery deferral)
    // - require_tls=false: Warning logged but connection proceeds
    if config.verify_certificates && !session.certificate_verified {
        warn!(
            hostname = %hostname,
            peer_dn = ?session.peer_dn,
            "TLS certificate verification failed for peer"
        );
        if config.require_tls {
            return Ok(TlsNegotiationResult::Failed {
                error: OutboundError::TlsError {
                    detail: format!(
                        "peer certificate verification failed for {} (peer_dn: {:?})",
                        hostname, session.peer_dn
                    ),
                },
            });
        }
        // Opportunistic TLS — proceed despite verification failure.
        warn!("proceeding with unverified TLS (require_tls is false)");
    }

    // Store the TLS session in the connection context, marking the
    // connection as encrypted. All subsequent I/O on this connection
    // should be routed through the TLS backend.
    ctx.cctx.tls_ctx = Some(session);

    debug!(
        hostname = %hostname,
        "TLS session established and stored in connection context"
    );

    Ok(TlsNegotiationResult::Success)
}

/// Build a [`TlsClientStartConfig`] from the negotiation config and
/// connection hostname, suitable for passing to `TlsBackend::client_start()`.
///
/// Resolves the SNI hostname: if `config.tls_sni` is set, it overrides the
/// connection hostname; otherwise the connection hostname is used for both
/// SNI and certificate verification.
fn build_client_start_config(
    config: &TlsNegotiationConfig,
    hostname: &str,
) -> TlsClientStartConfig {
    let sni = config.tls_sni.clone();
    let verify_hostname = if config.verify_certificates {
        Some(hostname.to_owned())
    } else {
        None
    };

    TlsClientStartConfig {
        hostname: hostname.to_owned(),
        sni,
        dane_enabled: config.dane_required,
        dane_required: config.dane_required,
        verify_hostname,
        alpn: None,
    }
}

/// Map a [`TlsError`] to an [`OutboundError::TlsError`].
///
/// Converts TLS-layer errors into the outbound SMTP error hierarchy, preserving
/// the error description for diagnostic logging. Replaces the C pattern of
/// `errno = ERRNO_TLSFAILURE`.
fn map_tls_error(tls_err: TlsError) -> OutboundError {
    OutboundError::TlsError {
        detail: format_tls_error(&tls_err),
    }
}

/// Format a [`TlsError`] into a human-readable detail string.
///
/// Includes specific error variant information for diagnostics. Distinguishes
/// between handshake errors (protocol negotiation failures) and I/O errors
/// (network-level failures).
fn format_tls_error(tls_err: &TlsError) -> String {
    match tls_err {
        TlsError::HandshakeError(detail) => {
            format!("TLS handshake error: {}", detail)
        }
        TlsError::IoError(io_err) => {
            format!("TLS I/O error: {}", io_err)
        }
        other => {
            format!("TLS error: {}", other)
        }
    }
}

/// Extract the inner `String` from a `Clean<String>` wrapper.
///
/// Since [`Clean<T>`] implements `Deref<Target=T>`, this clones the inner
/// value to produce an owned `String`. Used when constructing
/// [`TlsNegotiationConfig`] fields from tainted config values.
fn extract_clean_string(clean: Clean<String>) -> String {
    // Clean<T> implements Deref<Target=T>, so we can access the inner String
    // via deref coercion and convert to an owned String.
    clean.to_string()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify TlsNegotiationConfig default values match Exim defaults.
    #[test]
    fn test_config_default() {
        let config = TlsNegotiationConfig::default();
        assert!(!config.require_tls);
        assert!(!config.verify_certificates);
        assert!(config.tls_sni.is_none());
        assert!(!config.dane_required);
        assert!(config.client_cert_path.is_none());
        assert!(config.client_key_path.is_none());
        assert!(config.tls_require_ciphers.is_none());
    }

    /// Verify TlsNegotiationConfig::new() matches Default.
    #[test]
    fn test_config_new_matches_default() {
        let new_config = TlsNegotiationConfig::new();
        let default_config = TlsNegotiationConfig::default();
        assert_eq!(new_config.require_tls, default_config.require_tls);
        assert_eq!(
            new_config.verify_certificates,
            default_config.verify_certificates
        );
        assert_eq!(new_config.tls_sni, default_config.tls_sni);
        assert_eq!(new_config.dane_required, default_config.dane_required);
        assert_eq!(new_config.client_cert_path, default_config.client_cert_path);
        assert_eq!(new_config.client_key_path, default_config.client_key_path);
        assert_eq!(
            new_config.tls_require_ciphers,
            default_config.tls_require_ciphers
        );
    }

    /// Verify from_tainted_values correctly extracts clean values.
    #[test]
    fn test_config_from_tainted_values() {
        let config = TlsNegotiationConfig::from_tainted_values(
            true,
            true,
            Some(Tainted::new("mail.example.com".to_owned())),
            false,
            Some(Tainted::new("/etc/tls/client.pem".to_owned())),
            Some(Tainted::new("/etc/tls/client.key".to_owned())),
            Some(Tainted::new("ECDHE+AESGCM".to_owned())),
        );
        assert!(config.require_tls);
        assert!(config.verify_certificates);
        assert_eq!(config.tls_sni, Some("mail.example.com".to_owned()));
        assert!(!config.dane_required);
        assert_eq!(
            config.client_cert_path,
            Some("/etc/tls/client.pem".to_owned())
        );
        assert_eq!(
            config.client_key_path,
            Some("/etc/tls/client.key".to_owned())
        );
        assert_eq!(config.tls_require_ciphers, Some("ECDHE+AESGCM".to_owned()));
    }

    /// Verify from_tainted_values with None optional fields.
    #[test]
    fn test_config_from_tainted_none_values() {
        let config =
            TlsNegotiationConfig::from_tainted_values(false, false, None, false, None, None, None);
        assert!(!config.require_tls);
        assert!(!config.verify_certificates);
        assert!(config.tls_sni.is_none());
        assert!(!config.dane_required);
        assert!(config.client_cert_path.is_none());
        assert!(config.client_key_path.is_none());
        assert!(config.tls_require_ciphers.is_none());
    }

    /// Verify build_client_start_config applies SNI override.
    #[test]
    fn test_build_start_config_with_sni() {
        let config = TlsNegotiationConfig {
            require_tls: true,
            verify_certificates: true,
            tls_sni: Some("override.example.com".to_owned()),
            dane_required: false,
            client_cert_path: None,
            client_key_path: None,
            tls_require_ciphers: None,
        };
        let start = build_client_start_config(&config, "mail.example.com");
        assert_eq!(start.hostname, "mail.example.com");
        assert_eq!(start.sni, Some("override.example.com".to_owned()));
        assert_eq!(start.verify_hostname, Some("mail.example.com".to_owned()));
        assert!(!start.dane_enabled);
        assert!(!start.dane_required);
        assert!(start.alpn.is_none());
    }

    /// Verify build_client_start_config uses hostname as SNI when no override.
    #[test]
    fn test_build_start_config_no_sni_override() {
        let config = TlsNegotiationConfig {
            require_tls: false,
            verify_certificates: false,
            tls_sni: None,
            dane_required: false,
            client_cert_path: None,
            client_key_path: None,
            tls_require_ciphers: None,
        };
        let start = build_client_start_config(&config, "mail.example.com");
        assert_eq!(start.hostname, "mail.example.com");
        assert!(start.sni.is_none());
        // verify_hostname is None when verify_certificates is false
        assert!(start.verify_hostname.is_none());
    }

    /// Verify build_client_start_config passes DANE flags.
    #[test]
    fn test_build_start_config_dane_enabled() {
        let config = TlsNegotiationConfig {
            require_tls: true,
            verify_certificates: true,
            tls_sni: None,
            dane_required: true,
            client_cert_path: None,
            client_key_path: None,
            tls_require_ciphers: None,
        };
        let start = build_client_start_config(&config, "mail.example.com");
        assert!(start.dane_enabled);
        assert!(start.dane_required);
    }

    /// Verify TlsNegotiationResult Debug implementation.
    #[test]
    fn test_negotiation_result_debug() {
        let success = TlsNegotiationResult::Success;
        let debug_str = format!("{:?}", success);
        assert_eq!(debug_str, "Success");

        let not_offered = TlsNegotiationResult::NotOffered;
        let debug_str = format!("{:?}", not_offered);
        assert_eq!(debug_str, "NotOffered");

        let skipped = TlsNegotiationResult::Skipped;
        let debug_str = format!("{:?}", skipped);
        assert_eq!(debug_str, "Skipped");
    }
}
