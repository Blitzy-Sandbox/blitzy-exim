// exim-tls/src/client_cert.rs — Client Certificate Verification
//
// Implements X.509 client certificate verification for TLS connections,
// supporting both optional and required verification modes. This module
// replaces the verify callback chain from src/src/tls-openssl.c
// (verify_callback at lines 1112-1234, verify_callback_client/server,
// peer_cert at lines 3141-3174).
//
// All static state (client_verify_callback_called, server_verify_callback_called,
// client_verify_optional, server_verify_optional) from the C implementation is
// replaced by fields on the ClientCertVerifier struct, passed explicitly through
// call chains per AAP §0.4.4.
//
// Zero unsafe code per AAP §0.7.2.

use std::net::IpAddr;

use thiserror::Error;
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during client certificate verification.
///
/// Replaces the integer error codes and `X509_verify_cert_error_string()`
/// calls in tls-openssl.c `verify_callback()` (lines 1112-1234).
#[derive(Debug, Error)]
pub enum VerifyError {
    /// Certificate chain exceeds the configured maximum depth.
    ///
    /// Corresponds to the depth check at tls-openssl.c line 1116 where
    /// `depth > configured_verify_depth` causes rejection.
    #[error("certificate chain exceeds max depth {max_depth} at depth {actual_depth}")]
    ExceedsMaxDepth {
        /// The configured maximum depth (tls_verify_depth).
        max_depth: u32,
        /// The depth at which the certificate was presented.
        actual_depth: u32,
    },

    /// OpenSSL (or equivalent) pre-verification failed and mode is required.
    ///
    /// Corresponds to `preverify_ok == 0` with `!*optionalp` at line 1139.
    #[error("certificate pre-verification failed")]
    PreVerifyFailed,

    /// Hostname in the expected name does not match any SAN DNS entry or CN
    /// in the certificate's Subject DN.
    ///
    /// Replaces the `X509_check_host()` failure at line 1181 and the
    /// `tls_is_name_for_cert()` fallback at line 1199.
    #[error("hostname {expected} does not match certificate")]
    HostnameMismatch {
        /// The hostname we tried to match.
        expected: String,
    },

    /// Certificate has been revoked according to a CRL.
    #[error("certificate has been revoked")]
    CertRevoked,

    /// Failed to parse the DER-encoded certificate data.
    ///
    /// Corresponds to `X509_NAME_oneline()` error at line 1121.
    #[error("certificate parse error: {0}")]
    ParseError(String),
}

// ---------------------------------------------------------------------------
// Verification mode
// ---------------------------------------------------------------------------

/// Controls whether a client certificate is requested and whether
/// verification failure is fatal.
///
/// Maps to the Exim configuration directives:
/// - `VerifyMode::None`     — `tls_verify_certificates` not set
/// - `VerifyMode::Optional` — host matched `tls_try_verify_hosts`
/// - `VerifyMode::Required` — host matched `tls_verify_hosts`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    /// No client certificate requested.
    None,
    /// Certificate requested but not required — verification failures are
    /// logged and overridden (host in `tls_try_verify_hosts`).
    Optional,
    /// Certificate required — verification failures cause connection rejection.
    Required,
}

// ---------------------------------------------------------------------------
// Verification result
// ---------------------------------------------------------------------------

/// Outcome of a single certificate verification step.
///
/// Replaces the integer return value (0 = reject, 1 = accept) from the C
/// `verify_callback()` function, with the addition of an explicit
/// "accepted but unverified" state for optional mode.
#[derive(Debug)]
pub enum VerifyResult {
    /// Certificate verified successfully.
    Accept,
    /// Verification failed but mode is optional — continue the handshake.
    AcceptUnverified,
    /// Verification failed — reject the connection.
    Reject(VerifyError),
}

// ---------------------------------------------------------------------------
// Verification configuration
// ---------------------------------------------------------------------------

/// Configuration controlling client certificate verification behaviour.
///
/// Populated from the Exim configuration directives `tls_verify_certificates`,
/// `tls_verify_hosts`, `tls_try_verify_hosts`, and related options.
/// Replaces the scattered static state in tls-openssl.c (`setup_certs`,
/// `verify_callback`) with an explicit, immutable configuration record.
#[derive(Debug, Clone)]
pub struct VerifyConfig {
    /// Verification mode (none / optional / required).
    pub mode: VerifyMode,

    /// Maximum certificate chain depth. Defaults to 9 (matching the OpenSSL
    /// default `SSL_CTX_set_verify_depth` behaviour).
    pub max_depth: u32,

    /// Path to a PEM file containing trusted CA certificates.
    pub ca_cert_file: Option<String>,

    /// Path to a directory containing hashed CA certificate files.
    pub ca_cert_dir: Option<String>,

    /// Path to a CRL (Certificate Revocation List) PEM file.
    pub crl_file: Option<String>,

    /// Hostname to verify against the certificate's SAN DNS / CN fields.
    /// Set for outbound connections where the server identity must be confirmed.
    pub verify_hostname: Option<String>,

    /// When `true`, partial wildcard labels (e.g. `f*.example.com`) are
    /// rejected. Corresponds to `X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS`.
    pub no_partial_wildcards: bool,
}

// ---------------------------------------------------------------------------
// ClientCertVerifier — stateful verifier replacing C verify callback chain
// ---------------------------------------------------------------------------

/// Stateful client certificate verifier.
///
/// Replaces the pair of static booleans (`client_verify_callback_called`,
/// `server_verify_callback_called`) and the `tls_support` struct fields
/// (`peercert`, `peerdn`, `certificate_verified`, `verify_override`) from
/// tls-openssl.c. An instance is created per TLS session and mutated across
/// the series of `verify_certificate()` calls that the TLS library makes
/// for each certificate in the presented chain.
pub struct ClientCertVerifier {
    /// Verification configuration (immutable after construction).
    config: VerifyConfig,

    /// Whether the verify callback has been invoked at least once.
    /// Replaces `client_verify_callback_called` / `server_verify_callback_called`.
    callback_called: bool,

    /// Captured end-entity peer certificate in DER encoding.
    /// Replaces `tlsp->peercert` (`X509_dup(cert)` at line 1142).
    peer_cert: Option<Vec<u8>>,

    /// Peer certificate Subject DN as a human-readable string.
    /// Replaces `tlsp->peerdn` populated by `peer_cert()` at line 3161.
    peer_dn: Option<String>,

    /// Whether the full verification chain succeeded.
    /// Replaces `tlsp->certificate_verified` at line 3173.
    verified: bool,

    /// Accumulated chain logging entries (depth + subject DN + issuer DN).
    /// Replaces the `DEBUG(D_tls) debug_printf` calls inside the callback.
    chain_log: Vec<String>,
}

impl ClientCertVerifier {
    // -------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------

    /// Create a new verifier with the given configuration.
    ///
    /// All mutable state is initialised to "not yet called".
    pub fn new(config: VerifyConfig) -> Self {
        Self {
            config,
            callback_called: false,
            peer_cert: None,
            peer_dn: None,
            verified: false,
            chain_log: Vec::new(),
        }
    }

    // -------------------------------------------------------------------
    // Core verification — replaces verify_callback() lines 1112-1234
    // -------------------------------------------------------------------

    /// Verify a single certificate in the presented chain.
    ///
    /// This method is called once per certificate starting from the root
    /// (highest depth) down to the end-entity certificate (depth 0).
    ///
    /// # Parameters
    /// - `cert_der` — DER-encoded X.509 certificate at this chain position.
    /// - `chain`    — Full chain of DER-encoded certificates (for logging).
    /// - `depth`    — Position in the chain (0 = end-entity).
    /// - `preverify_ok` — Whether the underlying TLS library's built-in
    ///   verification passed for this certificate. Corresponds to the
    ///   `preverify_ok` parameter of the C `verify_callback()`.
    ///
    /// # Returns
    /// A `VerifyResult` indicating whether the handshake should continue.
    pub fn verify_certificate(
        &mut self,
        cert_der: &[u8],
        chain: &[Vec<u8>],
        depth: u32,
        preverify_ok: bool,
    ) -> VerifyResult {
        // Step 1: Depth check — mirrors tls-openssl.c line 1116.
        if depth > self.config.max_depth {
            tracing::warn!(
                depth = depth,
                max_depth = self.config.max_depth,
                "certificate chain exceeds max depth"
            );
            return VerifyResult::Reject(VerifyError::ExceedsMaxDepth {
                max_depth: self.config.max_depth,
                actual_depth: depth,
            });
        }

        // Attempt to extract the Subject DN for logging.
        let dn_display = extract_dn(cert_der).unwrap_or_else(|| "<unable to parse DN>".into());

        // Step 2: Peer certificate capture (first call only) — mirrors
        // the `!*calledp` branch at line 1138.
        if !self.callback_called {
            self.callback_called = true;
            self.peer_cert = Some(cert_der.to_vec());
            self.peer_dn = Some(dn_display.clone());
        }

        // Log the current depth + DN at debug level.
        tracing::debug!(
            depth = depth,
            dn = %dn_display,
            preverify_ok = preverify_ok,
            "TLS verify callback invoked"
        );

        // Step 3: Pre-verification status — mirrors lines 1129-1148.
        if !preverify_ok {
            return self.handle_preverify_failure(cert_der, &dn_display, chain);
        }

        // Step 4: Hostname verification at depth 0 — mirrors lines 1158-1221.
        if depth == 0 {
            if let Some(hostname) = self.config.verify_hostname.clone() {
                return self.check_hostname(cert_der, &hostname, chain);
            }
        } else {
            // Intermediate certificate accepted — log and continue.
            tracing::debug!(
                depth = depth,
                dn = %dn_display,
                "TLS verify ok: intermediate certificate"
            );
        }

        // Step 5: Accept.
        if depth == 0 {
            self.verified = true;
            tracing::debug!(
                dn = %dn_display,
                "TLS verify ok: depth=0 end-entity certificate"
            );
        }
        VerifyResult::Accept
    }

    // -------------------------------------------------------------------
    // Chain logging — replaces DEBUG(D_tls) debug_printf in verify_callback
    // -------------------------------------------------------------------

    /// Log the entire certificate chain at debug level.
    ///
    /// Iterates through each certificate in `chain`, extracts the subject
    /// and issuer DNs, and emits structured log events. The log entries are
    /// also accumulated in `self.chain_log` for later retrieval.
    pub fn log_chain(&mut self, chain: &[Vec<u8>]) {
        self.chain_log.clear();

        for (i, cert_der) in chain.iter().enumerate() {
            let depth = chain.len().saturating_sub(1).saturating_sub(i) as u32;
            let (subject, issuer) = match X509Certificate::from_der(cert_der) {
                Ok((_, cert)) => (cert.subject().to_string(), cert.issuer().to_string()),
                Err(e) => {
                    let msg = format!("depth={depth} <parse error: {e}>");
                    tracing::debug!(entry = %msg, "TLS chain entry (parse error)");
                    self.chain_log.push(msg);
                    continue;
                }
            };

            let entry = format!("depth={depth} subject=\"{subject}\" issuer=\"{issuer}\"");
            tracing::debug!(chain_entry = %entry, "TLS chain entry");
            self.chain_log.push(entry);
        }
    }

    // -------------------------------------------------------------------
    // ACL integration accessors — for $tls_peerdn, $tls_certificate_verified
    // -------------------------------------------------------------------

    /// Return the captured peer (end-entity) certificate in DER encoding.
    ///
    /// Available after the first `verify_certificate()` call. Used by ACL
    /// conditions that inspect the peer certificate.
    pub fn get_peer_cert(&self) -> Option<&[u8]> {
        self.peer_cert.as_deref()
    }

    /// Return the peer certificate Subject DN as a string.
    ///
    /// Provides the value for the `$tls_peerdn` expansion variable.
    /// Replaces `tlsp->peerdn` populated by `peer_cert()` at line 3161.
    pub fn get_peer_dn(&self) -> Option<&str> {
        self.peer_dn.as_deref()
    }

    /// Whether the full verification succeeded.
    ///
    /// Provides the value for the `$tls_certificate_verified` expansion
    /// variable. Returns `true` only when all callbacks returned `Accept`
    /// (not `AcceptUnverified` or `Reject`).
    pub fn is_verified(&self) -> bool {
        self.verified
    }

    // -------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------

    /// Handle a pre-verification failure (`preverify_ok == false`).
    ///
    /// In optional mode, logs a warning and returns `AcceptUnverified`.
    /// In required mode, captures the failing cert and returns `Reject`.
    /// Mirrors tls-openssl.c lines 1129-1148.
    fn handle_preverify_failure(
        &mut self,
        cert_der: &[u8],
        dn_display: &str,
        _chain: &[Vec<u8>],
    ) -> VerifyResult {
        match self.config.mode {
            VerifyMode::Optional => {
                tracing::warn!(
                    dn = %dn_display,
                    "TLS peer cert verification failed (optional), continuing \
                     — host in tls_try_verify_hosts"
                );
                // Ensure the failing cert is captured for ACL inspection.
                if self.peer_cert.is_none() {
                    self.peer_cert = Some(cert_der.to_vec());
                    self.peer_dn = Some(dn_display.to_owned());
                }
                VerifyResult::AcceptUnverified
            }
            VerifyMode::Required => {
                tracing::warn!(
                    dn = %dn_display,
                    "TLS peer cert pre-verification failed (required)"
                );
                // Capture the failing cert if not already captured.
                if self.peer_cert.is_none() {
                    self.peer_cert = Some(cert_der.to_vec());
                    self.peer_dn = Some(dn_display.to_owned());
                }
                VerifyResult::Reject(VerifyError::PreVerifyFailed)
            }
            VerifyMode::None => {
                // No verification requested — this should not normally
                // be reached, but handle gracefully.
                VerifyResult::Accept
            }
        }
    }

    /// Perform hostname verification on the end-entity certificate.
    ///
    /// Tries SAN DNS matching first (via `verify_hostname()`), then falls
    /// back to IP address matching (via `verify_ip()`).
    /// Mirrors tls-openssl.c lines 1162-1221.
    fn check_hostname(
        &mut self,
        cert_der: &[u8],
        hostname: &str,
        _chain: &[Vec<u8>],
    ) -> VerifyResult {
        // First, try hostname matching against SAN DNS entries + CN fallback.
        if verify_hostname(cert_der, hostname, self.config.no_partial_wildcards) {
            tracing::trace!(
                hostname = %hostname,
                "hostname matches certificate (SAN/CN)"
            );
            self.verified = true;
            return VerifyResult::Accept;
        }

        // If hostname looks like an IP address, try IP SAN matching.
        if hostname.parse::<IpAddr>().is_ok() && verify_ip(cert_der, hostname) {
            tracing::trace!(
                ip = %hostname,
                "IP address matches certificate SAN"
            );
            self.verified = true;
            return VerifyResult::Accept;
        }

        // Hostname mismatch.
        tracing::warn!(
            hostname = %hostname,
            "TLS verify error: certificate name mismatch"
        );

        match self.config.mode {
            VerifyMode::Optional => {
                tracing::debug!(
                    "TLS verify name failure overridden — host in tls_try_verify_hosts"
                );
                VerifyResult::AcceptUnverified
            }
            VerifyMode::Required | VerifyMode::None => {
                VerifyResult::Reject(VerifyError::HostnameMismatch {
                    expected: hostname.to_owned(),
                })
            }
        }
    }
}

// ===========================================================================
// Public free functions
// ===========================================================================

/// Check whether `hostname` matches the certificate identified by `cert_der`.
///
/// Implements RFC 6125 hostname matching:
/// 1. Extract Subject Alternative Name (SAN) DNS entries.
/// 2. If any SAN DNS names exist, match `hostname` against each one.
///    - Supports wildcard matching (`*.example.com`).
///    - If `no_partial_wildcards` is `true`, reject partial wildcards
///      (`f*.example.com`).
/// 3. If no SAN DNS names exist, fall back to the Common Name (CN) in the
///    certificate's Subject DN.
///
/// Returns `true` if the hostname matches at least one name in the certificate.
///
/// Replaces the `X509_check_host()` call at tls-openssl.c line 1181 and the
/// `tls_is_name_for_cert()` fallback at line 1199.
pub fn verify_hostname(cert_der: &[u8], hostname: &str, no_partial_wildcards: bool) -> bool {
    let cert = match X509Certificate::from_der(cert_der) {
        Ok((_, cert)) => cert,
        Err(e) => {
            tracing::trace!(error = %e, "failed to parse certificate for hostname verification");
            return false;
        }
    };

    // Collect SAN DNS names.
    let san_dns_names = extract_san_dns_names(&cert);

    if !san_dns_names.is_empty() {
        // RFC 6125 §6.4.4: if SANs are present, the CN MUST NOT be used.
        for san_name in &san_dns_names {
            if hostname_matches(san_name, hostname, no_partial_wildcards) {
                tracing::trace!(
                    san = %san_name,
                    hostname = %hostname,
                    "SAN DNS name matches hostname"
                );
                return true;
            }
        }
        tracing::trace!(
            hostname = %hostname,
            san_count = san_dns_names.len(),
            "no SAN DNS name matched hostname"
        );
        return false;
    }

    // Fallback: check CN in Subject DN.
    if let Some(cn) = extract_common_name(&cert) {
        if hostname_matches(&cn, hostname, no_partial_wildcards) {
            tracing::trace!(
                cn = %cn,
                hostname = %hostname,
                "CN matches hostname (SAN fallback)"
            );
            return true;
        }
    }

    false
}

/// Check whether `ip_str` matches an IP address SAN entry in the certificate.
///
/// Parses the provided string as an `IpAddr` and compares it against each
/// `GeneralName::IPAddress` entry in the certificate's Subject Alternative Name
/// extension.
///
/// Returns `true` if the IP address matches at least one SAN IP entry.
pub fn verify_ip(cert_der: &[u8], ip_str: &str) -> bool {
    let target_ip: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => {
            tracing::trace!(ip = %ip_str, "invalid IP address string");
            return false;
        }
    };

    let cert = match X509Certificate::from_der(cert_der) {
        Ok((_, cert)) => cert,
        Err(e) => {
            tracing::trace!(error = %e, "failed to parse certificate for IP verification");
            return false;
        }
    };

    let san_ips = extract_san_ip_addresses(&cert);
    for san_ip in &san_ips {
        if *san_ip == target_ip {
            tracing::trace!(
                san_ip = %san_ip,
                target_ip = %target_ip,
                "SAN IP address matches"
            );
            return true;
        }
    }

    false
}

/// Extract the Subject Distinguished Name from a DER-encoded certificate
/// and format it as an RFC 4514 string.
///
/// Returns `None` if the certificate cannot be parsed.
///
/// Replaces `X509_NAME_oneline()` calls in tls-openssl.c `verify_callback()`
/// (line 1119) and `peer_cert()` (line 3156).
///
/// # Example output
/// ```text
/// CN=mail.example.com, O=Example Inc., C=US
/// ```
pub fn extract_dn(cert_der: &[u8]) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    let subject = cert.subject();
    Some(subject.to_string())
}

// ===========================================================================
// Internal helpers
// ===========================================================================

/// Extract all DNS names from the certificate's Subject Alternative Name
/// extension.
fn extract_san_dns_names<'a>(cert: &'a X509Certificate<'a>) -> Vec<&'a str> {
    let mut names = Vec::new();

    let san_ext = match cert.subject_alternative_name() {
        Ok(Some(ext)) => ext,
        _ => return names,
    };

    for gn in &san_ext.value.general_names {
        if let GeneralName::DNSName(dns) = gn {
            names.push(*dns);
        }
    }

    names
}

/// Extract all IP addresses from the certificate's Subject Alternative Name
/// extension.
///
/// SAN IP addresses are encoded as raw octets: 4 bytes for IPv4, 16 bytes
/// for IPv6.
fn extract_san_ip_addresses(cert: &X509Certificate<'_>) -> Vec<IpAddr> {
    let mut addrs = Vec::new();

    let san_ext = match cert.subject_alternative_name() {
        Ok(Some(ext)) => ext,
        _ => return addrs,
    };

    for gn in &san_ext.value.general_names {
        if let GeneralName::IPAddress(bytes) = gn {
            if let Some(ip) = ip_from_bytes(bytes) {
                addrs.push(ip);
            }
        }
    }

    addrs
}

/// Convert raw SAN IP address bytes to a `std::net::IpAddr`.
///
/// - 4 bytes  → IPv4
/// - 16 bytes → IPv6
/// - Other lengths are ignored (may be CIDR ranges in name constraints).
fn ip_from_bytes(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => {
            let octets: [u8; 4] = bytes.try_into().ok()?;
            Some(IpAddr::V4(octets.into()))
        }
        16 => {
            let octets: [u8; 16] = bytes.try_into().ok()?;
            Some(IpAddr::V6(octets.into()))
        }
        _ => None,
    }
}

/// Extract the first Common Name (CN) attribute from the certificate's
/// Subject DN, as a UTF-8 string.
fn extract_common_name(cert: &X509Certificate<'_>) -> Option<String> {
    for attr in cert.subject().iter_common_name() {
        if let Ok(cn) = attr.as_str() {
            return Some(cn.to_owned());
        }
    }
    None
}

/// Perform RFC 6125 hostname matching, including wildcard support.
///
/// Matching rules:
/// 1. Case-insensitive comparison.
/// 2. A wildcard `*` is only permitted as the complete leftmost label
///    (e.g. `*.example.com`).
/// 3. The wildcard matches exactly one label (i.e. `*.example.com` matches
///    `foo.example.com` but NOT `bar.foo.example.com`).
/// 4. If `no_partial_wildcards` is true, the wildcard label must be exactly
///    `*` with no surrounding characters (rejects `f*.example.com`).
/// 5. Wildcards MUST NOT match top-level domains or single-label names.
fn hostname_matches(pattern: &str, hostname: &str, no_partial_wildcards: bool) -> bool {
    let pattern_lower = pattern.to_ascii_lowercase();
    let hostname_lower = hostname.to_ascii_lowercase();

    // Direct exact match (most common case).
    if pattern_lower == hostname_lower {
        return true;
    }

    // Check for wildcard in the leftmost label.
    if !pattern_lower.contains('*') {
        return false;
    }

    // Split pattern into leftmost label and the rest.
    let (pattern_left, pattern_rest) = match pattern_lower.split_once('.') {
        Some((left, rest)) => (left, rest),
        // Wildcard in a single-label pattern is not valid.
        None => return false,
    };

    // The remaining part of the pattern must have at least one dot
    // (i.e. at least two labels), preventing wildcard matches against TLDs.
    if !pattern_rest.contains('.') {
        return false;
    }

    // If no_partial_wildcards, the left label must be exactly "*".
    if no_partial_wildcards && pattern_left != "*" {
        return false;
    }

    // The wildcard must be in the leftmost label only.
    if pattern_rest.contains('*') {
        return false;
    }

    // Split hostname into its leftmost label and the rest.
    let (hostname_left, hostname_rest) = match hostname_lower.split_once('.') {
        Some((left, rest)) => (left, rest),
        // Single-label hostname cannot match a wildcard pattern.
        None => return false,
    };

    // The non-wildcard suffix of the pattern must match exactly.
    if hostname_rest != pattern_rest {
        return false;
    }

    // Match the leftmost label against the wildcard pattern.
    if pattern_left == "*" {
        // Wildcard matches any single label (but must be non-empty).
        return !hostname_left.is_empty();
    }

    // Partial wildcard matching (e.g. "f*o" in "f*o.example.com").
    // Only reached when no_partial_wildcards is false.
    wildcard_label_match(pattern_left, hostname_left)
}

/// Match a label pattern containing `*` against a hostname label.
///
/// The `*` can appear at any position within the label and matches zero or
/// more characters. Only a single `*` is supported.
fn wildcard_label_match(pattern: &str, label: &str) -> bool {
    let star_pos = match pattern.find('*') {
        Some(pos) => pos,
        None => return pattern == label,
    };

    let prefix = &pattern[..star_pos];
    let suffix = &pattern[star_pos + 1..];

    // The label must be at least as long as prefix + suffix.
    if label.len() < prefix.len() + suffix.len() {
        return false;
    }

    label.starts_with(prefix) && label.ends_with(suffix)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // hostname_matches tests
    // ------------------------------------------------------------------

    #[test]
    fn test_exact_match() {
        assert!(hostname_matches(
            "mail.example.com",
            "mail.example.com",
            false
        ));
        assert!(hostname_matches(
            "MAIL.Example.COM",
            "mail.example.com",
            false
        ));
    }

    #[test]
    fn test_wildcard_match() {
        assert!(hostname_matches("*.example.com", "mail.example.com", false));
        assert!(hostname_matches("*.example.com", "foo.example.com", false));
    }

    #[test]
    fn test_wildcard_no_subdomain() {
        // *.example.com must NOT match bar.foo.example.com.
        assert!(!hostname_matches(
            "*.example.com",
            "bar.foo.example.com",
            false
        ));
    }

    #[test]
    fn test_wildcard_no_tld() {
        // *.com must not match (only one label in suffix).
        assert!(!hostname_matches("*.com", "example.com", false));
    }

    #[test]
    fn test_partial_wildcard_allowed() {
        assert!(hostname_matches("f*.example.com", "foo.example.com", false));
        assert!(!hostname_matches(
            "f*.example.com",
            "bar.example.com",
            false
        ));
    }

    #[test]
    fn test_partial_wildcard_rejected() {
        // With no_partial_wildcards = true, "f*.example.com" must NOT match.
        assert!(!hostname_matches("f*.example.com", "foo.example.com", true));
    }

    #[test]
    fn test_wildcard_empty_label() {
        // *.example.com should not match ".example.com" (empty hostname label).
        assert!(!hostname_matches("*.example.com", ".example.com", false));
    }

    #[test]
    fn test_no_wildcard_mismatch() {
        assert!(!hostname_matches(
            "mail.example.com",
            "smtp.example.com",
            false
        ));
    }

    // ------------------------------------------------------------------
    // wildcard_label_match tests
    // ------------------------------------------------------------------

    #[test]
    fn test_label_match_star_prefix() {
        assert!(wildcard_label_match("*bar", "foobar"));
        assert!(!wildcard_label_match("*bar", "foobaz"));
    }

    #[test]
    fn test_label_match_star_suffix() {
        assert!(wildcard_label_match("foo*", "foobar"));
        assert!(!wildcard_label_match("foo*", "bazbar"));
    }

    #[test]
    fn test_label_match_star_middle() {
        assert!(wildcard_label_match("f*r", "foobar"));
        assert!(!wildcard_label_match("f*r", "foobaz"));
    }

    // ------------------------------------------------------------------
    // ip_from_bytes tests
    // ------------------------------------------------------------------

    #[test]
    fn test_ipv4_from_bytes() {
        let ip = ip_from_bytes(&[192, 168, 1, 1]).unwrap();
        assert_eq!(ip, "192.168.1.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_ipv6_from_bytes() {
        let bytes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1u8];
        let ip = ip_from_bytes(&bytes).unwrap();
        assert_eq!(ip, "::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_invalid_length() {
        assert!(ip_from_bytes(&[1, 2, 3]).is_none());
        assert!(ip_from_bytes(&[]).is_none());
    }

    // ------------------------------------------------------------------
    // VerifyMode / VerifyConfig defaults
    // ------------------------------------------------------------------

    #[test]
    fn test_verify_mode_equality() {
        assert_eq!(VerifyMode::None, VerifyMode::None);
        assert_eq!(VerifyMode::Optional, VerifyMode::Optional);
        assert_eq!(VerifyMode::Required, VerifyMode::Required);
        assert_ne!(VerifyMode::None, VerifyMode::Required);
    }

    #[test]
    fn test_verifier_initial_state() {
        let config = VerifyConfig {
            mode: VerifyMode::Required,
            max_depth: 9,
            ca_cert_file: None,
            ca_cert_dir: None,
            crl_file: None,
            verify_hostname: None,
            no_partial_wildcards: true,
        };
        let v = ClientCertVerifier::new(config);
        assert!(!v.is_verified());
        assert!(v.get_peer_cert().is_none());
        assert!(v.get_peer_dn().is_none());
    }

    // ------------------------------------------------------------------
    // VerifyError display
    // ------------------------------------------------------------------

    #[test]
    fn test_error_display() {
        let e = VerifyError::ExceedsMaxDepth {
            max_depth: 9,
            actual_depth: 12,
        };
        let s = e.to_string();
        assert!(s.contains("max depth 9"));
        assert!(s.contains("depth 12"));

        let e = VerifyError::HostnameMismatch {
            expected: "mail.example.com".into(),
        };
        assert!(e.to_string().contains("mail.example.com"));
    }

    #[test]
    fn test_parse_error_display() {
        let e = VerifyError::ParseError("bad DER".into());
        assert!(e.to_string().contains("bad DER"));
    }

    #[test]
    fn test_revoked_display() {
        let e = VerifyError::CertRevoked;
        assert!(e.to_string().contains("revoked"));
    }

    #[test]
    fn test_preverify_display() {
        let e = VerifyError::PreVerifyFailed;
        assert!(e.to_string().contains("pre-verification failed"));
    }
}
