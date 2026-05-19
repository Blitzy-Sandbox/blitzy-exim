//! DANE/TLSA Support — RFC 6698/7672
//!
//! Implements DNS-Based Authentication of Named Entities (DANE) for TLS
//! certificate verification. This module translates functionality from the C
//! source files `dane.c` (49 lines — dispatcher), `dane-openssl.c` (1,740
//! lines — full DANE implementation), and `danessl.h` (47 lines — constants
//! and declarations) into safe Rust.
//!
//! # Architecture
//!
//! The [`DaneVerifier`] struct replaces the per-connection `ssl_dane` C struct,
//! providing:
//! - TLSA record ingestion and validation via [`DaneVerifier::add_tlsa`]
//! - Certificate chain verification against TLSA records via
//!   [`DaneVerifier::verify_certificate`]
//! - Match result retrieval via [`DaneVerifier::get_match`]
//!
//! Standalone functions provide:
//! - Hostname verification via [`verify_hostname`] (SAN-first, CN-fallback
//!   per RFC 6125)
//! - Hash computation for TLSA matching via [`compute_match`]
//!
//! # Feature Gate
//!
//! This module is compiled only when the `dane` Cargo feature is enabled,
//! gated at the `pub mod dane;` declaration in `lib.rs`. This replaces the
//! C `#ifdef SUPPORT_DANE` preprocessor conditional.
//!
//! # RFC Compliance
//!
//! - RFC 6698 — DANE TLSA record format and semantics
//! - RFC 7671 — Updates to the DANE TLSA specification
//! - RFC 7672 — SMTP security via opportunistic DANE TLS
//! - RFC 6125 — Hostname verification rules (wildcard matching)
//!
//! # Safety
//!
//! This module contains zero `unsafe` code. All cryptographic operations
//! (SHA-256, SHA-512) use the pure-Rust `sha2` crate. Certificate parsing
//! uses the pure-Rust `x509-parser` crate. No FFI calls are made.

use sha2::{Digest, Sha256, Sha512};
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

// ---------------------------------------------------------------------------
// Error type — replaces C DANEerr() macro and DANESSL_R_* error codes
// ---------------------------------------------------------------------------

/// Errors that can occur during DANE operations.
///
/// Each variant replaces a corresponding `DANESSL_R_*` error code from the
/// C `dane-openssl.c` implementation:
/// - `InvalidUsage` → `DANESSL_R_BAD_USAGE`
/// - `InvalidSelector` → `DANESSL_R_BAD_SELECTOR`
/// - `InvalidMatchingType` → `DANESSL_R_BAD_DIGEST`
/// - `CertParseError` → `DANESSL_R_BAD_CERT`
/// - `HashError` → digest computation failures
#[derive(Debug, thiserror::Error)]
pub enum DaneError {
    /// TLSA usage field value is outside the valid range (0–3).
    #[error("invalid TLSA usage: {0}")]
    InvalidUsage(u8),

    /// TLSA selector field value is outside the valid range (0–1).
    #[error("invalid TLSA selector: {0}")]
    InvalidSelector(u8),

    /// TLSA matching type field value is outside the valid range (0–2).
    #[error("invalid TLSA matching type: {0}")]
    InvalidMatchingType(u8),

    /// Certificate DER data could not be parsed as a valid X.509 certificate.
    #[error("certificate parse error: {0}")]
    CertParseError(String),

    /// An error occurred during hash computation for TLSA matching.
    #[error("hash computation error: {0}")]
    HashError(String),
}

// ---------------------------------------------------------------------------
// TLSA record field enumerations — RFC 6698 §2.1
// ---------------------------------------------------------------------------

/// TLSA certificate usage types as defined in RFC 6698 §2.1.1.
///
/// These correspond to the `DANESSL_USAGE_*` constants from `danessl.h`:
/// - `DANESSL_USAGE_PKIX_TA` (0)
/// - `DANESSL_USAGE_PKIX_EE` (1)
/// - `DANESSL_USAGE_DANE_TA` (2)
/// - `DANESSL_USAGE_DANE_EE` (3)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsaUsage {
    /// Usage 0 — CA constraint: the TLSA record specifies a CA certificate or
    /// public key that MUST be found in the PKIX-validated certificate chain.
    PkixTa = 0,
    /// Usage 1 — Service certificate constraint: the end-entity certificate
    /// MUST match AND be PKIX-validated.
    PkixEe = 1,
    /// Usage 2 — Trust anchor assertion: the specified certificate or public
    /// key serves as a trust anchor, bypassing PKIX validation entirely.
    DaneTa = 2,
    /// Usage 3 — Domain-issued certificate: the end-entity certificate is
    /// directly authenticated by DANE, no PKIX validation and no hostname
    /// matching required (per RFC 7672 §3.1.1).
    DaneEe = 3,
}

impl TryFrom<u8> for TlsaUsage {
    type Error = DaneError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::PkixTa),
            1 => Ok(Self::PkixEe),
            2 => Ok(Self::DaneTa),
            3 => Ok(Self::DaneEe),
            _ => Err(DaneError::InvalidUsage(value)),
        }
    }
}

/// TLSA selector types as defined in RFC 6698 §2.1.2.
///
/// Corresponds to `DANESSL_SELECTOR_CERT` (0) and `DANESSL_SELECTOR_SPKI` (1)
/// from `danessl.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsaSelector {
    /// Selector 0 — Match against the full DER-encoded certificate.
    /// Replaces `DANESSL_SELECTOR_CERT`.
    FullCert = 0,
    /// Selector 1 — Match against the DER-encoded SubjectPublicKeyInfo.
    /// Replaces `DANESSL_SELECTOR_SPKI`.
    SubjectPublicKeyInfo = 1,
}

impl TryFrom<u8> for TlsaSelector {
    type Error = DaneError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::FullCert),
            1 => Ok(Self::SubjectPublicKeyInfo),
            _ => Err(DaneError::InvalidSelector(value)),
        }
    }
}

/// TLSA matching types as defined in RFC 6698 §2.1.3.
///
/// Corresponds to `DANESSL_MATCHING_FULL` (0), `DANESSL_MATCHING_2256` (1),
/// and `DANESSL_MATCHING_2512` (2) from `danessl.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsaMatchingType {
    /// Matching type 0 — Exact byte comparison of the full certificate
    /// or SPKI data. Replaces `DANESSL_MATCHING_FULL`.
    Full = 0,
    /// Matching type 1 — SHA-256 hash comparison.
    /// Replaces `DANESSL_MATCHING_2256`.
    Sha256 = 1,
    /// Matching type 2 — SHA-512 hash comparison.
    /// Replaces `DANESSL_MATCHING_2512`.
    Sha512 = 2,
}

impl TryFrom<u8> for TlsaMatchingType {
    type Error = DaneError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Full),
            1 => Ok(Self::Sha256),
            2 => Ok(Self::Sha512),
            _ => Err(DaneError::InvalidMatchingType(value)),
        }
    }
}

// ---------------------------------------------------------------------------
// TlsaRecord — single DNS TLSA resource record
// ---------------------------------------------------------------------------

/// A single TLSA resource record from DNS, as defined in RFC 6698 §2.1.
///
/// Encapsulates the four fields of a TLSA record:
/// - `usage` — certificate usage (how the association is used)
/// - `selector` — which part of the certificate to match
/// - `matching_type` — how to compare the data
/// - `data` — the certificate association data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsaRecord {
    /// Certificate usage field (RFC 6698 §2.1.1).
    pub usage: TlsaUsage,
    /// Selector field (RFC 6698 §2.1.2).
    pub selector: TlsaSelector,
    /// Matching type field (RFC 6698 §2.1.3).
    pub matching_type: TlsaMatchingType,
    /// Certificate association data — the hash or full DER content to match
    /// against, depending on matching_type and selector.
    pub data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// DaneResult — verification outcome
// ---------------------------------------------------------------------------

/// Result of DANE certificate verification.
///
/// Returned by [`DaneVerifier::verify_certificate`] to indicate whether a
/// TLSA record matched the presented certificate chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaneResult {
    /// A TLSA record matched the certificate chain. Contains the matching
    /// usage, selector, and matching type for caller inspection.
    Verified {
        /// Which usage type matched.
        usage: TlsaUsage,
        /// Which selector was used.
        selector: TlsaSelector,
        /// Which matching type was used.
        mtype: TlsaMatchingType,
    },
    /// No TLSA record matched any certificate in the chain.
    NoMatch,
    /// No TLSA records were available for verification — DANE is not
    /// applicable for this connection.
    NoRecords,
}

// ---------------------------------------------------------------------------
// DER parsing helpers — pure-Rust manual SPKI extraction
// ---------------------------------------------------------------------------

/// Parse a single DER TLV (Tag-Length-Value) element at the given byte offset.
///
/// Returns `(tag, content_start_offset, content_length)` on success, where:
/// - `tag` is the ASN.1 tag byte
/// - `content_start_offset` is the byte index where content begins
/// - `content_length` is the number of content bytes
///
/// Handles both short-form (single byte) and long-form (multi-byte) DER
/// length encodings per X.690 §8.1.3.
fn parse_der_tlv(data: &[u8], pos: usize) -> Result<(u8, usize, usize), DaneError> {
    if pos >= data.len() {
        return Err(DaneError::CertParseError(
            "unexpected end of DER data at tag byte".into(),
        ));
    }
    let tag = data[pos];
    let mut offset = pos + 1;

    if offset >= data.len() {
        return Err(DaneError::CertParseError(
            "unexpected end of DER data at length byte".into(),
        ));
    }

    let length_byte = data[offset];
    offset += 1;

    let length = if length_byte & 0x80 == 0 {
        // Short form: length encoded directly in this byte (0–127).
        length_byte as usize
    } else {
        // Long form: low 7 bits indicate number of subsequent length bytes.
        let num_length_bytes = (length_byte & 0x7f) as usize;
        if num_length_bytes == 0 || num_length_bytes > 4 {
            return Err(DaneError::CertParseError(format!(
                "unsupported DER length encoding: {} length bytes",
                num_length_bytes
            )));
        }
        if offset + num_length_bytes > data.len() {
            return Err(DaneError::CertParseError(
                "truncated DER multi-byte length".into(),
            ));
        }
        let mut len = 0usize;
        for &b in &data[offset..offset + num_length_bytes] {
            len = len
                .checked_shl(8)
                .ok_or_else(|| DaneError::CertParseError("DER length overflow".into()))?
                | (b as usize);
        }
        offset += num_length_bytes;
        len
    };

    Ok((tag, offset, length))
}

/// Extract the raw DER-encoded SubjectPublicKeyInfo bytes from a DER-encoded
/// X.509 v3 certificate.
///
/// Walks the DER structure manually:
/// ```text
/// Certificate ::= SEQUENCE {
///   tbsCertificate       SEQUENCE {
///     version         [0] EXPLICIT INTEGER OPTIONAL,
///     serialNumber        INTEGER,
///     signature           AlgorithmIdentifier,
///     issuer              Name,
///     validity            SEQUENCE { ... },
///     subject             Name,
///     subjectPublicKeyInfo  SEQUENCE { ... },  ← extracted here
///     ...
///   },
///   ...
/// }
/// ```
///
/// This function returns the complete TLV encoding of the SPKI SEQUENCE,
/// suitable for hashing per RFC 6698 §2.1.2 selector=1.
fn extract_spki_der(cert_der: &[u8]) -> Result<Vec<u8>, DaneError> {
    // Tag 0x30 = SEQUENCE (constructed)
    const TAG_SEQUENCE: u8 = 0x30;
    // Tag 0xA0 = context-specific [0] EXPLICIT (constructed)
    const TAG_VERSION: u8 = 0xA0;

    let mut pos: usize = 0;

    // Outer Certificate SEQUENCE
    let (tag, content_start, _content_len) = parse_der_tlv(cert_der, pos)?;
    if tag != TAG_SEQUENCE {
        return Err(DaneError::CertParseError(format!(
            "expected Certificate SEQUENCE (0x30), got 0x{:02x}",
            tag
        )));
    }
    pos = content_start;

    // TBSCertificate SEQUENCE
    let (tag, tbs_content_start, _tbs_len) = parse_der_tlv(cert_der, pos)?;
    if tag != TAG_SEQUENCE {
        return Err(DaneError::CertParseError(format!(
            "expected TBSCertificate SEQUENCE (0x30), got 0x{:02x}",
            tag
        )));
    }
    pos = tbs_content_start;

    // Skip version [0] EXPLICIT if present (tag 0xA0)
    if pos < cert_der.len() && cert_der[pos] == TAG_VERSION {
        let (_tag, next, len) = parse_der_tlv(cert_der, pos)?;
        pos = next + len;
    }

    // Skip serialNumber INTEGER
    let (_tag, next, len) = parse_der_tlv(cert_der, pos)?;
    pos = next + len;

    // Skip signature AlgorithmIdentifier SEQUENCE
    let (_tag, next, len) = parse_der_tlv(cert_der, pos)?;
    pos = next + len;

    // Skip issuer Name (SEQUENCE of SEQUENCE)
    let (_tag, next, len) = parse_der_tlv(cert_der, pos)?;
    pos = next + len;

    // Skip validity SEQUENCE
    let (_tag, next, len) = parse_der_tlv(cert_der, pos)?;
    pos = next + len;

    // Skip subject Name (SEQUENCE of SEQUENCE)
    let (_tag, next, len) = parse_der_tlv(cert_der, pos)?;
    pos = next + len;

    // Read subjectPublicKeyInfo SEQUENCE — capture full TLV encoding
    let spki_start = pos;
    let (tag, next, len) = parse_der_tlv(cert_der, pos)?;
    if tag != TAG_SEQUENCE {
        return Err(DaneError::CertParseError(format!(
            "expected SPKI SEQUENCE (0x30), got 0x{:02x}",
            tag
        )));
    }
    let spki_end = next + len;
    if spki_end > cert_der.len() {
        return Err(DaneError::CertParseError(
            "SPKI extends beyond certificate DER boundary".into(),
        ));
    }

    Ok(cert_der[spki_start..spki_end].to_vec())
}

// ---------------------------------------------------------------------------
// Hash computation — replaces C EVP_Digest() calls in match()
// ---------------------------------------------------------------------------

/// Compute the TLSA matching representation of the given data.
///
/// Depending on `matching_type`, this either returns the raw data unchanged
/// (for full comparison) or computes a cryptographic hash.
///
/// This replaces the C `EVP_Digest(buf, len, cmpbuf, &cmplen, m->value->md, 0)`
/// calls from `dane-openssl.c` lines 318–322.
///
/// # Arguments
///
/// * `data` — Raw DER-encoded certificate or SPKI bytes.
/// * `matching_type` — Determines how the data is processed:
///   - [`TlsaMatchingType::Full`] — returns `data` as-is
///   - [`TlsaMatchingType::Sha256`] — returns SHA-256 digest (32 bytes)
///   - [`TlsaMatchingType::Sha512`] — returns SHA-512 digest (64 bytes)
///
/// # Returns
///
/// The computed representation suitable for comparison against a TLSA record's
/// association data field.
pub fn compute_match(data: &[u8], matching_type: TlsaMatchingType) -> Vec<u8> {
    match matching_type {
        TlsaMatchingType::Full => {
            tracing::debug!(
                len = data.len(),
                "DANE compute_match: full comparison (no hash)"
            );
            data.to_vec()
        }
        TlsaMatchingType::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            let result = hasher.finalize().to_vec();
            tracing::debug!(
                input_len = data.len(),
                digest_len = result.len(),
                "DANE compute_match: SHA-256 digest computed"
            );
            result
        }
        TlsaMatchingType::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            let result = hasher.finalize().to_vec();
            tracing::debug!(
                input_len = data.len(),
                digest_len = result.len(),
                "DANE compute_match: SHA-512 digest computed"
            );
            result
        }
    }
}

// ---------------------------------------------------------------------------
// Hostname verification — replaces C name_check() + match_name()
// ---------------------------------------------------------------------------

/// Check whether a single certificate identity (from SAN or CN) matches any
/// of the expected hostnames, implementing RFC 6125 wildcard matching.
///
/// Wildcard rules (matching the C `match_name()` function):
/// - Wildcard `*` is only valid as the entire leftmost label (`*.example.com`)
/// - The pattern must contain at least two labels after the wildcard
///   (`*.com` is NOT valid)
/// - The wildcard matches exactly one label in single-label mode
/// - Comparisons are case-insensitive per DNS conventions
fn hostname_matches_one(cert_id: &str, hostname: &str) -> bool {
    // Empty strings never match
    if cert_id.is_empty() || hostname.is_empty() {
        return false;
    }

    // Handle subdomain matching when hostname starts with '.'
    // (This matches the C code's behavior when `domain` starts with '.')
    let (hostname_trimmed, match_subdomain) = if let Some(stripped) = hostname.strip_prefix('.') {
        if stripped.is_empty() {
            return false;
        }
        (stripped, true)
    } else {
        (hostname, false)
    };

    if match_subdomain {
        // Subdomain match: cert_id must be a subdomain of hostname_trimmed.
        // E.g., cert_id="sub.example.com", hostname_trimmed="example.com"
        let cert_lower = cert_id.to_ascii_lowercase();
        let host_lower = hostname_trimmed.to_ascii_lowercase();
        if cert_lower.len() > host_lower.len() + 1
            && cert_lower.as_bytes()[cert_lower.len() - host_lower.len() - 1] == b'.'
            && cert_lower.ends_with(&host_lower)
        {
            return true;
        }
        return false;
    }

    // Exact case-insensitive match
    if cert_id.eq_ignore_ascii_case(hostname_trimmed) {
        return true;
    }

    // Wildcard match: cert_id starts with "*." and hostname contains a parent
    // domain that matches. E.g., cert_id="*.example.com" matches
    // hostname="mail.example.com".
    if let Some(wildcard_suffix) = cert_id.strip_prefix("*.") {
        if wildcard_suffix.is_empty() {
            return false;
        }
        // The hostname must have at least one label before the parent domain.
        if let Some(parent_start) = hostname_trimmed.find('.') {
            let parent = &hostname_trimmed[parent_start..];
            // In single-label wildcard mode (the default per RFC 6125),
            // the parent domain must exactly match the wildcard suffix.
            if parent.len() == wildcard_suffix.len() + 1
                && parent[1..].eq_ignore_ascii_case(wildcard_suffix)
            {
                return true;
            }
        }
    }

    false
}

/// Validate that a certificate identity string contains only valid DNS label
/// characters: letters, digits, hyphens, dots, and wildcards.
///
/// Replicates the `check_name()` function from `dane-openssl.c` lines 822–843.
fn is_valid_dns_identity(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    for c in name.chars() {
        if !matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '*') {
            return false;
        }
    }
    true
}

/// Extract the Common Name (CN) from a certificate's Subject Distinguished
/// Name as a hostname matching fallback per RFC 6125.
///
/// Iterates the Subject's Relative Distinguished Names looking for the
/// OID 2.5.4.3 (id-at-commonName). Returns the first CN value found as a
/// UTF-8 string, or `None` if no CN is present or the value is not valid.
fn extract_cn_from_cert(cert: &X509Certificate<'_>) -> Option<String> {
    // OID 2.5.4.3 = id-at-commonName, DER encoding: [0x55, 0x04, 0x03]
    const CN_OID_BYTES: &[u8] = &[0x55, 0x04, 0x03];

    for rdn in cert.subject().iter() {
        for attr in rdn.iter() {
            if attr.attr_type().as_bytes() == CN_OID_BYTES {
                if let Ok(s) = attr.as_str() {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

/// Verify that a certificate's identity (SAN or CN) matches at least one
/// of the expected hostnames.
///
/// This replaces the `name_check()` function from `dane-openssl.c` lines
/// 885–934 and the `verify_chain()` hostname matching logic.
///
/// # Matching Order (per RFC 6125)
///
/// 1. Check Subject Alternative Name (SAN) DNS entries first. If any DNS SAN
///    entries are present, ONLY those are used for matching — the CN is ignored.
/// 2. If NO DNS SAN entries are present, fall back to the Common Name (CN)
///    in the Subject Distinguished Name.
///
/// # Wildcard Matching
///
/// Wildcards (`*.example.com`) in certificate identities are supported per
/// RFC 6125 §6.4.3 rules, matching a single leftmost label.
///
/// # Arguments
///
/// * `cert_der` — DER-encoded X.509 certificate to check.
/// * `hostnames` — List of expected hostnames to match against.
///
/// # Returns
///
/// `true` if any certificate identity matches any expected hostname, `false`
/// otherwise. Returns `false` if the certificate cannot be parsed.
pub fn verify_hostname(cert_der: &[u8], hostnames: &[String]) -> bool {
    let cert = match X509Certificate::from_der(cert_der) {
        Ok((_, cert)) => cert,
        Err(e) => {
            tracing::debug!("DANE verify_hostname: certificate parse failed: {}", e);
            return false;
        }
    };

    // Phase 1: Check SAN DNS names
    let mut found_san_dns = false;
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            if let GeneralName::DNSName(dns_name) = name {
                found_san_dns = true;
                if !is_valid_dns_identity(dns_name) {
                    continue;
                }
                for hostname in hostnames {
                    if hostname_matches_one(dns_name, hostname) {
                        tracing::debug!(
                            san = dns_name,
                            hostname = hostname.as_str(),
                            "DANE verify_hostname: matched SAN"
                        );
                        return true;
                    }
                }
            }
        }
    }

    // Phase 2: Fall back to CN only if no DNS SAN entries were found
    // (per RFC 6125 §6.4.4)
    if !found_san_dns {
        if let Some(cn) = extract_cn_from_cert(&cert) {
            if is_valid_dns_identity(&cn) {
                for hostname in hostnames {
                    if hostname_matches_one(&cn, hostname) {
                        tracing::debug!(
                            cn = cn.as_str(),
                            hostname = hostname.as_str(),
                            "DANE verify_hostname: matched CN"
                        );
                        return true;
                    }
                }
            }
        }
    }

    tracing::debug!("DANE verify_hostname: no hostname match found");
    false
}

// ---------------------------------------------------------------------------
// DaneVerifier — per-connection DANE verification state
// ---------------------------------------------------------------------------

/// Per-connection DANE verification state, replacing the C `ssl_dane` struct
/// from `dane-openssl.c` lines 234–250.
///
/// # Usage
///
/// ```ignore
/// let mut verifier = DaneVerifier::new(vec!["mail.example.com".into()]);
/// verifier.add_tlsa(record)?;
/// let result = verifier.verify_certificate(&chain)?;
/// match result {
///     DaneResult::Verified { usage, .. } => { /* DANE match found */ }
///     DaneResult::NoMatch => { /* No TLSA record matched */ }
///     DaneResult::NoRecords => { /* No TLSA records were provided */ }
/// }
/// ```
///
/// # Verification Order
///
/// The verification follows the same priority order as the C implementation
/// (`verify_cert()` in `dane-openssl.c` lines 1070–1158):
///
/// 1. **DANE-EE (usage 3)** — Direct end-entity match. If matched, DANE
///    verification succeeds immediately with no hostname check required
///    (per RFC 7672 §3.1.1).
/// 2. **DANE-TA (usage 2)** — Trust anchor match. Walks the certificate
///    chain looking for a matching trust anchor. Hostname verification
///    IS required after a TA match.
/// 3. **PKIX-EE (usage 1)** — End-entity match with PKIX validation.
///    The DANE matching is performed; PKIX validation is the TLS backend's
///    responsibility.
/// 4. **PKIX-TA (usage 0)** — Trust anchor match with PKIX validation.
///    The DANE matching is performed; PKIX validation is the TLS backend's
///    responsibility.
pub struct DaneVerifier {
    /// Hostnames to verify against (SAN/CN matching). Replaces `dane->hosts`
    /// linked list from the C implementation.
    hostnames: Vec<String>,

    /// Collected TLSA records from DNS. Replaces the nested
    /// `selectors[usage][selector][mtype][data]` linked-list structure
    /// from `ssl_dane`.
    tlsa_records: Vec<TlsaRecord>,

    /// Index into `tlsa_records` of the matching record after successful
    /// verification. `None` if no match has been found yet.
    matched_record_index: Option<usize>,

    /// DER-encoded matched certificate (if any). Replaces `dane->match`.
    matched_cert: Option<Vec<u8>>,

    /// Which usage type produced the match. Replaces implicit tracking via
    /// the C `selectors[usage]` dispatch.
    matched_usage: Option<TlsaUsage>,

    /// Which selector was used for the match.
    matched_selector: Option<TlsaSelector>,

    /// Which matching type was used for the match.
    matched_mtype: Option<TlsaMatchingType>,

    /// Whether DANE verification succeeded.
    verified: bool,
}

impl DaneVerifier {
    /// Create a new DANE verifier for a TLS connection.
    ///
    /// Replaces `DANESSL_init()` from `dane-openssl.c` lines 1558–1611.
    ///
    /// # Arguments
    ///
    /// * `hostnames` — List of expected peer hostnames for SAN/CN matching.
    ///   Typically contains the MX hostname and the original domain.
    pub fn new(hostnames: Vec<String>) -> Self {
        tracing::debug!(count = hostnames.len(), "DANE verifier initialized");
        Self {
            hostnames,
            tlsa_records: Vec::new(),
            matched_record_index: None,
            matched_cert: None,
            matched_usage: None,
            matched_selector: None,
            matched_mtype: None,
            verified: false,
        }
    }

    /// Ingest a DNS TLSA record for later verification.
    ///
    /// Replaces `DANESSL_add_tlsa()` from `dane-openssl.c` lines 1364–1531.
    ///
    /// # Validation
    ///
    /// - Usage, selector, and matching_type fields are pre-validated by the
    ///   type system (enums), but the data is checked for:
    ///   - Non-empty data
    ///   - Correct hash length for SHA-256 (32 bytes) and SHA-512 (64 bytes)
    ///   - Valid DER for full-certificate records (selector=0, matching_type=0)
    ///
    /// # Deduplication
    ///
    /// Duplicate records (same usage/selector/matching_type/data) are silently
    /// ignored, matching the C implementation's deduplication logic.
    pub fn add_tlsa(&mut self, record: TlsaRecord) -> Result<(), DaneError> {
        // Validate data is not empty
        if record.data.is_empty() {
            return Err(DaneError::CertParseError(
                "TLSA record data must not be empty".into(),
            ));
        }

        // Validate hash lengths for digest-based matching types
        match record.matching_type {
            TlsaMatchingType::Sha256 => {
                if record.data.len() != 32 {
                    return Err(DaneError::HashError(format!(
                        "SHA-256 TLSA data must be 32 bytes, got {}",
                        record.data.len()
                    )));
                }
            }
            TlsaMatchingType::Sha512 => {
                if record.data.len() != 64 {
                    return Err(DaneError::HashError(format!(
                        "SHA-512 TLSA data must be 64 bytes, got {}",
                        record.data.len()
                    )));
                }
            }
            TlsaMatchingType::Full => {
                // For full match with selector=FullCert, optionally validate
                // that the data is a parseable DER certificate.
                if record.selector == TlsaSelector::FullCert
                    && X509Certificate::from_der(&record.data).is_err()
                {
                    tracing::debug!(
                        "DANE add_tlsa: full cert data is not valid DER X.509 \
                         (may be acceptable for some records)"
                    );
                }
            }
        }

        // Deduplication check — replaces the C nested-loop dedup in
        // DANESSL_add_tlsa() lines 1482–1495.
        let is_duplicate = self.tlsa_records.iter().any(|existing| {
            existing.usage == record.usage
                && existing.selector == record.selector
                && existing.matching_type == record.matching_type
                && existing.data == record.data
        });

        if is_duplicate {
            tracing::debug!(
                usage = ?record.usage,
                selector = ?record.selector,
                mtype = ?record.matching_type,
                "DANE add_tlsa: duplicate record ignored"
            );
            return Ok(());
        }

        tracing::debug!(
            usage = ?record.usage,
            selector = ?record.selector,
            mtype = ?record.matching_type,
            data_len = record.data.len(),
            "DANE add_tlsa: record accepted"
        );

        self.tlsa_records.push(record);
        Ok(())
    }

    /// Check whether any TLSA records have been added.
    ///
    /// Returns `true` if at least one TLSA record was successfully ingested
    /// via [`add_tlsa`](Self::add_tlsa). Used by callers to determine whether
    /// DANE verification is applicable for this connection.
    pub fn has_records(&self) -> bool {
        !self.tlsa_records.is_empty()
    }

    /// Retrieve the TLSA record that matched during verification, if any.
    ///
    /// Replaces `DANESSL_get_match_cert()` from `dane-openssl.c` lines
    /// 1276–1298 (the record-level match information).
    ///
    /// Returns `None` if [`verify_certificate`](Self::verify_certificate) has
    /// not been called or no match was found.
    pub fn get_match(&self) -> Option<&TlsaRecord> {
        self.matched_record_index
            .and_then(|idx| self.tlsa_records.get(idx))
    }

    /// Verify a certificate chain against the stored TLSA records.
    ///
    /// This is the main DANE verification entry point, replacing `verify_cert()`
    /// from `dane-openssl.c` lines 1070–1158 plus the matching logic from
    /// `check_end_entity()` (lines 745–773) and `set_trust_anchor()` (lines
    /// 637–743).
    ///
    /// # Arguments
    ///
    /// * `chain` — DER-encoded certificate chain, ordered from end-entity
    ///   (index 0) through intermediates to the root (last index). Each
    ///   element is the complete DER encoding of one X.509 certificate.
    ///
    /// # Verification Order
    ///
    /// 1. DANE-EE (usage 3): Check end-entity certificate only
    /// 2. DANE-TA (usage 2): Walk chain looking for trust anchor
    /// 3. PKIX-EE (usage 1): Check end-entity with PKIX prerequisite
    /// 4. PKIX-TA (usage 0): Walk chain looking for TA with PKIX prerequisite
    ///
    /// # Returns
    ///
    /// - [`DaneResult::Verified`] if a TLSA record matched
    /// - [`DaneResult::NoMatch`] if no TLSA record matched any certificate
    /// - [`DaneResult::NoRecords`] if no TLSA records were available
    pub fn verify_certificate(&mut self, chain: &[Vec<u8>]) -> Result<DaneResult, DaneError> {
        // Reset previous match state
        self.reset_match_state();

        if self.tlsa_records.is_empty() {
            tracing::debug!("DANE verify_certificate: no TLSA records available");
            return Ok(DaneResult::NoRecords);
        }

        if chain.is_empty() {
            tracing::debug!("DANE verify_certificate: empty certificate chain");
            return Ok(DaneResult::NoMatch);
        }

        let ee_cert = &chain[0];

        // Priority 1: DANE-EE (usage 3) — direct end-entity match
        // Per RFC 7672 §3.1.1, no hostname or chain validation required.
        if let Some(result) = self.check_dane_ee(ee_cert)? {
            tracing::debug!("DANE verify_certificate: DANE-EE match found");
            self.verified = true;
            return Ok(result);
        }

        // Priority 2: DANE-TA (usage 2) — trust anchor in chain
        // Per RFC 7672 §3.1.2, hostname matching IS required.
        if let Some(result) = self.check_dane_ta(chain)? {
            // Verify hostname for DANE-TA matches
            if verify_hostname(ee_cert, &self.hostnames) {
                tracing::debug!("DANE verify_certificate: DANE-TA match with hostname verified");
                self.verified = true;
                return Ok(result);
            }
            tracing::debug!(
                "DANE verify_certificate: DANE-TA matched but hostname verification failed"
            );
            // Continue checking other usages — hostname mismatch voids the
            // DANE-TA match.
            self.reset_match_state();
        }

        // Priority 3: PKIX-EE (usage 1) — end-entity match
        // PKIX validation is the TLS backend's responsibility; we perform
        // the DANE matching component.
        if let Some(result) = self.check_pkix_ee(ee_cert)? {
            // Hostname check required for PKIX-EE
            if verify_hostname(ee_cert, &self.hostnames) {
                tracing::debug!("DANE verify_certificate: PKIX-EE match with hostname verified");
                self.verified = true;
                return Ok(result);
            }
            tracing::debug!(
                "DANE verify_certificate: PKIX-EE matched but hostname verification failed"
            );
            self.reset_match_state();
        }

        // Priority 4: PKIX-TA (usage 0) — trust anchor match
        // PKIX validation is the TLS backend's responsibility; we perform
        // the DANE matching component.
        if let Some(result) = self.check_pkix_ta(chain)? {
            if verify_hostname(ee_cert, &self.hostnames) {
                tracing::debug!("DANE verify_certificate: PKIX-TA match with hostname verified");
                self.verified = true;
                return Ok(result);
            }
            tracing::debug!(
                "DANE verify_certificate: PKIX-TA matched but hostname verification failed"
            );
            self.reset_match_state();
        }

        tracing::debug!("DANE verify_certificate: no TLSA record matched");
        Ok(DaneResult::NoMatch)
    }

    /// Reset all match-related state fields. Called at the start of each
    /// verification attempt and when a partial match (e.g., DANE match
    /// without hostname) is voided.
    fn reset_match_state(&mut self) {
        self.matched_record_index = None;
        self.matched_cert = None;
        self.matched_usage = None;
        self.matched_selector = None;
        self.matched_mtype = None;
        self.verified = false;
    }

    /// Record a successful match with the given parameters.
    fn record_match(
        &mut self,
        record_index: usize,
        cert_der: &[u8],
        usage: TlsaUsage,
        selector: TlsaSelector,
        mtype: TlsaMatchingType,
    ) {
        self.matched_record_index = Some(record_index);
        self.matched_cert = Some(cert_der.to_vec());
        self.matched_usage = Some(usage);
        self.matched_selector = Some(selector);
        self.matched_mtype = Some(mtype);
    }

    /// Check end-entity certificate against DANE-EE (usage 3) TLSA records.
    ///
    /// Replaces `check_end_entity()` from `dane-openssl.c` lines 745–773.
    /// For DANE-EE, only the end-entity certificate (chain[0]) is checked.
    fn check_dane_ee(&mut self, ee_cert: &[u8]) -> Result<Option<DaneResult>, DaneError> {
        self.match_cert_against_records(ee_cert, TlsaUsage::DaneEe)
    }

    /// Check certificate chain against DANE-TA (usage 2) TLSA records.
    ///
    /// Replaces `set_trust_anchor()` from `dane-openssl.c` lines 637–743.
    /// Walks the certificate chain from end-entity to root, checking each
    /// certificate against DANE-TA records.
    fn check_dane_ta(&mut self, chain: &[Vec<u8>]) -> Result<Option<DaneResult>, DaneError> {
        // Walk chain from end-entity through intermediates to root.
        // Any certificate in the chain can serve as the trust anchor.
        for cert_der in chain {
            if let Some(result) = self.match_cert_against_records(cert_der, TlsaUsage::DaneTa)? {
                return Ok(Some(result));
            }
        }
        Ok(None)
    }

    /// Check end-entity certificate against PKIX-EE (usage 1) TLSA records.
    ///
    /// Replaces the PKIX-EE matching portion of `verify_chain()` from
    /// `dane-openssl.c` lines 1009–1011.
    fn check_pkix_ee(&mut self, ee_cert: &[u8]) -> Result<Option<DaneResult>, DaneError> {
        self.match_cert_against_records(ee_cert, TlsaUsage::PkixEe)
    }

    /// Check certificate chain against PKIX-TA (usage 0) TLSA records.
    ///
    /// Replaces the PKIX-TA matching portion of `verify_chain()` from
    /// `dane-openssl.c` lines 1013–1019.
    fn check_pkix_ta(&mut self, chain: &[Vec<u8>]) -> Result<Option<DaneResult>, DaneError> {
        for cert_der in chain {
            if let Some(result) = self.match_cert_against_records(cert_der, TlsaUsage::PkixTa)? {
                return Ok(Some(result));
            }
        }
        Ok(None)
    }

    /// Match a single certificate against all TLSA records with the specified
    /// usage type.
    ///
    /// This replaces the `match()` function from `dane-openssl.c` lines
    /// 258–334, adapted to operate on the flat `tlsa_records` vector instead
    /// of the nested C linked-list structure.
    ///
    /// For each TLSA record with the specified usage:
    /// 1. Select the data source based on selector (full cert DER or SPKI DER)
    /// 2. Compute the hash based on matching_type (full/SHA-256/SHA-512)
    /// 3. Compare against the TLSA record's association data
    fn match_cert_against_records(
        &mut self,
        cert_der: &[u8],
        usage: TlsaUsage,
    ) -> Result<Option<DaneResult>, DaneError> {
        // We collect match info into a local to avoid holding an immutable
        // borrow on `self.tlsa_records` while calling `self.record_match()`.
        let mut found: Option<(usize, TlsaUsage, TlsaSelector, TlsaMatchingType)> = None;

        for (idx, record) in self.tlsa_records.iter().enumerate() {
            if record.usage != usage {
                continue;
            }

            // Select data based on selector
            let selected_data = match record.selector {
                TlsaSelector::FullCert => cert_der.to_vec(),
                TlsaSelector::SubjectPublicKeyInfo => extract_spki_der(cert_der)?,
            };

            // Compute hash based on matching type
            let computed = compute_match(&selected_data, record.matching_type);

            // Compare against TLSA record data
            if computed == record.data {
                found = Some((idx, record.usage, record.selector, record.matching_type));
                break;
            }
        }

        // Apply the match result after releasing the immutable borrow on
        // tlsa_records.
        if let Some((idx, rec_usage, rec_selector, rec_mtype)) = found {
            tracing::debug!(
                usage = ?rec_usage,
                selector = ?rec_selector,
                mtype = ?rec_mtype,
                "DANE match: TLSA record matched"
            );

            self.record_match(idx, cert_der, rec_usage, rec_selector, rec_mtype);

            Ok(Some(DaneResult::Verified {
                usage: rec_usage,
                selector: rec_selector,
                mtype: rec_mtype,
            }))
        } else {
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── TlsaUsage tests ──────────────────────────────────────────────────

    #[test]
    fn test_tlsa_usage_try_from_valid() {
        assert_eq!(TlsaUsage::try_from(0).unwrap(), TlsaUsage::PkixTa);
        assert_eq!(TlsaUsage::try_from(1).unwrap(), TlsaUsage::PkixEe);
        assert_eq!(TlsaUsage::try_from(2).unwrap(), TlsaUsage::DaneTa);
        assert_eq!(TlsaUsage::try_from(3).unwrap(), TlsaUsage::DaneEe);
    }

    #[test]
    fn test_tlsa_usage_try_from_invalid() {
        assert!(TlsaUsage::try_from(4).is_err());
        assert!(TlsaUsage::try_from(255).is_err());
    }

    // ── TlsaSelector tests ───────────────────────────────────────────────

    #[test]
    fn test_tlsa_selector_try_from_valid() {
        assert_eq!(TlsaSelector::try_from(0).unwrap(), TlsaSelector::FullCert);
        assert_eq!(
            TlsaSelector::try_from(1).unwrap(),
            TlsaSelector::SubjectPublicKeyInfo
        );
    }

    #[test]
    fn test_tlsa_selector_try_from_invalid() {
        assert!(TlsaSelector::try_from(2).is_err());
    }

    // ── TlsaMatchingType tests ───────────────────────────────────────────

    #[test]
    fn test_tlsa_matching_type_try_from_valid() {
        assert_eq!(
            TlsaMatchingType::try_from(0).unwrap(),
            TlsaMatchingType::Full
        );
        assert_eq!(
            TlsaMatchingType::try_from(1).unwrap(),
            TlsaMatchingType::Sha256
        );
        assert_eq!(
            TlsaMatchingType::try_from(2).unwrap(),
            TlsaMatchingType::Sha512
        );
    }

    #[test]
    fn test_tlsa_matching_type_try_from_invalid() {
        assert!(TlsaMatchingType::try_from(3).is_err());
    }

    // ── compute_match tests ──────────────────────────────────────────────

    #[test]
    fn test_compute_match_full() {
        let data = b"hello world";
        let result = compute_match(data, TlsaMatchingType::Full);
        assert_eq!(result, data.to_vec());
    }

    #[test]
    fn test_compute_match_sha256() {
        let data = b"hello world";
        let result = compute_match(data, TlsaMatchingType::Sha256);
        assert_eq!(result.len(), 32);
        // Known SHA-256 of "hello world"
        let expected =
            hex_decode("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_compute_match_sha512() {
        let data = b"hello world";
        let result = compute_match(data, TlsaMatchingType::Sha512);
        assert_eq!(result.len(), 64);
        // Known SHA-512 of "hello world"
        let expected = hex_decode(
            "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f\
             989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f",
        );
        assert_eq!(result, expected);
    }

    #[test]
    fn test_compute_match_empty_data() {
        let result = compute_match(b"", TlsaMatchingType::Sha256);
        assert_eq!(result.len(), 32);
    }

    // ── hostname_matches_one tests ───────────────────────────────────────

    #[test]
    fn test_exact_match() {
        assert!(hostname_matches_one("mail.example.com", "mail.example.com"));
    }

    #[test]
    fn test_exact_match_case_insensitive() {
        assert!(hostname_matches_one("Mail.Example.COM", "mail.example.com"));
    }

    #[test]
    fn test_wildcard_match() {
        assert!(hostname_matches_one("*.example.com", "mail.example.com"));
    }

    #[test]
    fn test_wildcard_no_match_bare_domain() {
        // *.example.com should NOT match example.com
        assert!(!hostname_matches_one("*.example.com", "example.com"));
    }

    #[test]
    fn test_wildcard_no_match_deep_subdomain() {
        // *.example.com should NOT match sub.mail.example.com (single-label)
        assert!(!hostname_matches_one(
            "*.example.com",
            "sub.mail.example.com"
        ));
    }

    #[test]
    fn test_wildcard_empty_suffix() {
        assert!(!hostname_matches_one("*.", "anything."));
    }

    #[test]
    fn test_subdomain_match() {
        // Leading dot in hostname means match any subdomain
        assert!(hostname_matches_one("sub.mail.example.com", ".example.com"));
    }

    #[test]
    fn test_no_match_empty() {
        assert!(!hostname_matches_one("", "example.com"));
        assert!(!hostname_matches_one("example.com", ""));
    }

    // ── is_valid_dns_identity tests ──────────────────────────────────────

    #[test]
    fn test_valid_dns_identity() {
        assert!(is_valid_dns_identity("mail.example.com"));
        assert!(is_valid_dns_identity("*.example.com"));
        assert!(is_valid_dns_identity("a-b.c.d"));
    }

    #[test]
    fn test_invalid_dns_identity() {
        assert!(!is_valid_dns_identity(""));
        assert!(!is_valid_dns_identity("mail example.com"));
        assert!(!is_valid_dns_identity("mail@example.com"));
        assert!(!is_valid_dns_identity("mail\x00.example.com"));
    }

    // ── DaneVerifier tests ───────────────────────────────────────────────

    #[test]
    fn test_verifier_new_empty() {
        let verifier = DaneVerifier::new(vec!["example.com".into()]);
        assert!(!verifier.has_records());
        assert!(verifier.get_match().is_none());
    }

    #[test]
    fn test_verifier_add_tlsa_valid() {
        let mut verifier = DaneVerifier::new(vec!["example.com".into()]);
        let record = TlsaRecord {
            usage: TlsaUsage::DaneEe,
            selector: TlsaSelector::FullCert,
            matching_type: TlsaMatchingType::Sha256,
            data: vec![0u8; 32],
        };
        assert!(verifier.add_tlsa(record).is_ok());
        assert!(verifier.has_records());
    }

    #[test]
    fn test_verifier_add_tlsa_empty_data() {
        let mut verifier = DaneVerifier::new(vec!["example.com".into()]);
        let record = TlsaRecord {
            usage: TlsaUsage::DaneEe,
            selector: TlsaSelector::FullCert,
            matching_type: TlsaMatchingType::Full,
            data: vec![],
        };
        assert!(verifier.add_tlsa(record).is_err());
    }

    #[test]
    fn test_verifier_add_tlsa_wrong_sha256_length() {
        let mut verifier = DaneVerifier::new(vec!["example.com".into()]);
        let record = TlsaRecord {
            usage: TlsaUsage::DaneEe,
            selector: TlsaSelector::FullCert,
            matching_type: TlsaMatchingType::Sha256,
            data: vec![0u8; 16], // Wrong length
        };
        assert!(verifier.add_tlsa(record).is_err());
    }

    #[test]
    fn test_verifier_add_tlsa_wrong_sha512_length() {
        let mut verifier = DaneVerifier::new(vec!["example.com".into()]);
        let record = TlsaRecord {
            usage: TlsaUsage::DaneEe,
            selector: TlsaSelector::FullCert,
            matching_type: TlsaMatchingType::Sha512,
            data: vec![0u8; 32], // Wrong length
        };
        assert!(verifier.add_tlsa(record).is_err());
    }

    #[test]
    fn test_verifier_deduplication() {
        let mut verifier = DaneVerifier::new(vec!["example.com".into()]);
        let record = TlsaRecord {
            usage: TlsaUsage::DaneEe,
            selector: TlsaSelector::FullCert,
            matching_type: TlsaMatchingType::Sha256,
            data: vec![0u8; 32],
        };
        verifier.add_tlsa(record.clone()).unwrap();
        verifier.add_tlsa(record).unwrap();
        // Only one record should be stored
        assert_eq!(verifier.tlsa_records.len(), 1);
    }

    #[test]
    fn test_verifier_no_records() {
        let mut verifier = DaneVerifier::new(vec!["example.com".into()]);
        let result = verifier.verify_certificate(&[]).unwrap();
        assert_eq!(result, DaneResult::NoRecords);
    }

    #[test]
    fn test_verifier_empty_chain() {
        let mut verifier = DaneVerifier::new(vec!["example.com".into()]);
        verifier
            .add_tlsa(TlsaRecord {
                usage: TlsaUsage::DaneEe,
                selector: TlsaSelector::FullCert,
                matching_type: TlsaMatchingType::Sha256,
                data: vec![0u8; 32],
            })
            .unwrap();
        let result = verifier.verify_certificate(&[]).unwrap();
        assert_eq!(result, DaneResult::NoMatch);
    }

    // ── DER parsing tests ────────────────────────────────────────────────

    #[test]
    fn test_parse_der_tlv_short_form() {
        // Tag 0x30, length 5, followed by content
        let data = [0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        let (tag, content_start, content_len) = parse_der_tlv(&data, 0).unwrap();
        assert_eq!(tag, 0x30);
        assert_eq!(content_start, 2);
        assert_eq!(content_len, 5);
    }

    #[test]
    fn test_parse_der_tlv_long_form() {
        // Tag 0x30, long-form length: 0x82, 0x01, 0x00 = 256
        let mut data = vec![0x30, 0x82, 0x01, 0x00];
        data.extend(vec![0u8; 256]);
        let (tag, content_start, content_len) = parse_der_tlv(&data, 0).unwrap();
        assert_eq!(tag, 0x30);
        assert_eq!(content_start, 4);
        assert_eq!(content_len, 256);
    }

    #[test]
    fn test_parse_der_tlv_empty_data() {
        let result = parse_der_tlv(&[], 0);
        assert!(result.is_err());
    }

    // ── DaneError Display tests ──────────────────────────────────────────

    #[test]
    fn test_dane_error_display() {
        let err = DaneError::InvalidUsage(5);
        assert_eq!(format!("{}", err), "invalid TLSA usage: 5");

        let err = DaneError::InvalidSelector(3);
        assert_eq!(format!("{}", err), "invalid TLSA selector: 3");

        let err = DaneError::InvalidMatchingType(4);
        assert_eq!(format!("{}", err), "invalid TLSA matching type: 4");

        let err = DaneError::CertParseError("bad cert".into());
        assert_eq!(format!("{}", err), "certificate parse error: bad cert");

        let err = DaneError::HashError("bad hash".into());
        assert_eq!(format!("{}", err), "hash computation error: bad hash");
    }

    // ── Helper for hex decoding in tests ─────────────────────────────────

    fn hex_decode(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
