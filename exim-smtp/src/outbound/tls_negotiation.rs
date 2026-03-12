//! STARTTLS initiation and TLS-on-connect for outbound connections.
//!
//! Stub module — provides type signatures for mod.rs re-exports.
//! Will be replaced by the implementation agent.

use super::{ClientConnCtx, OutboundError, SmtpInblock, SmtpOutblock};

/// Result of a TLS negotiation attempt.
#[derive(Debug)]
pub enum TlsNegotiationResult {
    /// TLS handshake succeeded; session details are in the ClientConnCtx.
    Success,
    /// TLS handshake failed; connection may still be usable in plaintext.
    Failed {
        /// Reason for failure.
        reason: String,
    },
    /// STARTTLS command was rejected by the server (response code 4xx/5xx).
    Rejected {
        /// SMTP response code.
        code: u16,
        /// SMTP response message.
        message: String,
    },
}

/// Configuration for TLS negotiation.
#[derive(Debug)]
pub struct TlsNegotiationConfig {
    /// Whether to require TLS (fail if STARTTLS is rejected).
    pub require_tls: bool,
    /// Server name for SNI.
    pub sni_name: Option<String>,
    /// Whether DANE/TLSA verification is required.
    pub dane_required: bool,
    /// Minimum TLS protocol version to accept.
    pub min_tls_version: Option<String>,
}

/// Initiate STARTTLS on an existing plaintext SMTP connection.
///
/// Sends the STARTTLS command, waits for a 220 response, then performs
/// the TLS handshake using the configured TLS backend.
pub fn initiate_starttls(
    _cctx: &mut ClientConnCtx,
    _inblock: &mut SmtpInblock,
    _outblock: &mut SmtpOutblock,
    _config: &TlsNegotiationConfig,
) -> Result<TlsNegotiationResult, OutboundError> {
    Err(OutboundError::ConnectionFailed {
        reason: "not yet implemented".into(),
    })
}

/// Write data through the TLS layer on an active TLS connection.
pub fn tls_write_buffered(_cctx: &mut ClientConnCtx, _data: &[u8]) -> Result<usize, OutboundError> {
    Err(OutboundError::ConnectionFailed {
        reason: "not yet implemented".into(),
    })
}

/// Check whether TLS is currently active on the connection.
pub fn is_tls_active(cctx: &ClientConnCtx) -> bool {
    cctx.is_tls_active()
}

/// Establish a TLS-on-connect (SMTPS) session.
///
/// For port 465 connections where TLS begins immediately without STARTTLS.
pub fn tls_on_connect(
    _cctx: &mut ClientConnCtx,
    _config: &TlsNegotiationConfig,
) -> Result<TlsNegotiationResult, OutboundError> {
    Err(OutboundError::ConnectionFailed {
        reason: "not yet implemented".into(),
    })
}

/// Validate DANE/TLSA records for the current TLS session.
pub fn validate_dane_tlsa(cctx: &ClientConnCtx, _host: &str) -> Result<bool, OutboundError> {
    if cctx.is_tls_active() {
        Ok(true)
    } else {
        Err(OutboundError::ConnectionFailed {
            reason: "TLS not active for DANE validation".into(),
        })
    }
}
