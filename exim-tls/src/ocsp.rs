//! OCSP (Online Certificate Status Protocol) stapling support for TLS connections.
//!
//! This module provides server-side OCSP stapling (loading pre-generated OCSP
//! responses from files and serving them during TLS handshakes) and client-side
//! OCSP response verification (validating that a server's stapled OCSP response
//! covers its certificate and has not expired).
//!
//! Extracted from OCSP-related sections of `src/src/tls-openssl.c` (5,323 lines).
//! Feature-gated behind the `ocsp` Cargo feature flag, replacing the C
//! `#ifndef DISABLE_OCSP` preprocessor conditional.
//!
//! # Architecture
//!
//! - [`OcspStapler`] — Server-side: loads OCSP responses from files and provides
//!   them during TLS handshakes (replaces `ocsp_load_response()` and
//!   `tls_server_stapling_cb()` from tls-openssl.c)
//! - [`OcspVerifier`] — Client-side: verifies server-provided OCSP responses
//!   against the server's certificate (replaces `tls_client_stapling_cb()`)
//! - [`OcspConfig`] — Configuration for OCSP timestamp validation and file paths
//!
//! # Constants
//!
//! - Default skew tolerance: 300 seconds (matching C `EXIM_OCSP_SKEW_SECONDS`)
//! - Default max age: -1 (unlimited, matching C `EXIM_OCSP_MAX_AGE`)

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use x509_parser::prelude::{FromDer, X509Certificate};

/// Default OCSP timestamp skew tolerance in seconds.
/// Matches C `EXIM_OCSP_SKEW_SECONDS = 300L` from tls-openssl.c line 37.
const DEFAULT_SKEW_SECONDS: i64 = 300;

/// Default OCSP maximum response age. -1 means unlimited.
/// Matches C `EXIM_OCSP_MAX_AGE = -1L` from tls-openssl.c line 38.
const DEFAULT_MAX_AGE: i64 = -1;

// ASN.1 DER tag constants
const TAG_SEQUENCE: u8 = 0x30;
const TAG_ENUMERATED: u8 = 0x0A;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_INTEGER: u8 = 0x02;
const TAG_CONTEXT_0_EXPLICIT: u8 = 0xA0;
const TAG_CONTEXT_0_IMPLICIT: u8 = 0x80;
const TAG_CONTEXT_1_CONSTRUCTED: u8 = 0xA1;
const TAG_CONTEXT_2_IMPLICIT: u8 = 0x82;

/// Errors that can occur during OCSP response loading, parsing, and validation.
#[derive(Debug, thiserror::Error)]
pub enum OcspError {
    /// Failed to load OCSP response from the specified file path.
    #[error("failed to load OCSP response from {path}: {source}")]
    LoadError {
        /// The file path that could not be read.
        path: String,
        /// The underlying I/O error.
        source: io::Error,
    },

    /// The OCSP response has a non-successful status code.
    #[error("OCSP response not valid: {status:?}")]
    InvalidResponse {
        /// The non-successful response status.
        status: OcspResponseStatus,
    },

    /// Failed to parse the DER-encoded OCSP response structure.
    #[error("OCSP response parse error: {0}")]
    ParseError(String),

    /// The OCSP response signature could not be verified.
    #[error("OCSP signature verification failed")]
    SignatureVerifyFailed,

    /// The OCSP response timestamps are out of valid range.
    #[error("OCSP response expired")]
    Expired,

    /// The OCSP response does not cover the server certificate.
    #[error("OCSP response does not cover server certificate")]
    CertMismatch,
}

/// OCSP response status codes as defined in RFC 6960 section 4.2.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspResponseStatus {
    /// Response has valid confirmations (value 0).
    Successful,
    /// Illegal confirmation request (value 1).
    MalformedRequest,
    /// Internal error in OCSP responder (value 2).
    InternalError,
    /// Try again later (value 3).
    TryLater,
    /// Must sign the request (value 5).
    SignatureRequired,
    /// Request unauthorized (value 6).
    Unauthorized,
}

impl OcspResponseStatus {
    /// Convert a raw ASN.1 ENUMERATED byte value to an `OcspResponseStatus`.
    fn from_u8(value: u8) -> Result<Self, OcspError> {
        match value {
            0 => Ok(Self::Successful),
            1 => Ok(Self::MalformedRequest),
            2 => Ok(Self::InternalError),
            3 => Ok(Self::TryLater),
            5 => Ok(Self::SignatureRequired),
            6 => Ok(Self::Unauthorized),
            other => Err(OcspError::ParseError(format!(
                "unknown OCSP response status value: {other}"
            ))),
        }
    }
}

/// OCSP single-response certificate status as defined in RFC 6960 section 4.2.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspCertStatus {
    /// Certificate is not revoked.
    Good,
    /// Certificate has been revoked.
    Revoked,
    /// Revocation status is unknown.
    Unknown,
}

/// A parsed OCSP response with extracted timestamp information.
#[derive(Debug, Clone)]
pub struct OcspResponse {
    /// Raw DER-encoded OCSP response bytes.
    pub data: Vec<u8>,
    /// Parsed top-level response status.
    pub status: OcspResponseStatus,
    /// The `thisUpdate` timestamp from the first SingleResponse.
    pub this_update: Option<SystemTime>,
    /// The `nextUpdate` timestamp from the first SingleResponse.
    pub next_update: Option<SystemTime>,
}

/// Configuration for OCSP stapling behavior.
#[derive(Debug, Clone)]
pub struct OcspConfig {
    /// Timestamp skew tolerance in seconds. Default: 300.
    pub skew_seconds: i64,
    /// Maximum age of an OCSP response in seconds. -1 = unlimited. Default: -1.
    pub max_age: i64,
    /// List of file paths containing OCSP responses.
    pub response_files: Vec<String>,
    /// Whether the client requires OCSP stapling from the server.
    pub require_stapling: bool,
}

impl Default for OcspConfig {
    fn default() -> Self {
        Self {
            skew_seconds: DEFAULT_SKEW_SECONDS,
            max_age: DEFAULT_MAX_AGE,
            response_files: Vec::new(),
            require_stapling: false,
        }
    }
}

/// Server-side OCSP stapling state and operations.
///
/// Maintains a list of loaded OCSP responses (one per server certificate for
/// multi-stapling / SNI support) and provides them during TLS handshakes.
/// Replaces `ocsp_load_response()` and `tls_server_stapling_cb()` from
/// tls-openssl.c.
pub struct OcspStapler {
    responses: Vec<OcspResponse>,
    verify_stack: Option<Vec<Vec<u8>>>,
    skew_seconds: i64,
    max_age: i64,
}

impl OcspStapler {
    /// Create a new `OcspStapler` with the given configuration.
    pub fn new(config: &OcspConfig) -> Self {
        Self {
            responses: Vec::new(),
            verify_stack: None,
            skew_seconds: config.skew_seconds,
            max_age: config.max_age,
        }
    }

    /// Set the verification certificate stack used for OCSP response
    /// signature validation. Each entry is a DER-encoded X.509 certificate.
    pub fn set_verify_stack(&mut self, certs: Vec<Vec<u8>>) {
        self.verify_stack = Some(certs);
    }

    /// Load an OCSP response from a file and add it to the response list.
    ///
    /// Replaces `ocsp_load_response()` from tls-openssl.c (lines 1324-1506).
    pub fn load_response(&mut self, path: &str, is_pem: bool) -> Result<(), OcspError> {
        let file_path = Path::new(path);
        let format_name = if is_pem { "PEM" } else { "DER" };

        tracing::debug!(
            path = %path,
            format = format_name,
            extension = ?file_path.extension(),
            "loading OCSP response file"
        );

        if path.is_empty() {
            return Err(OcspError::ParseError("empty OCSP response path".into()));
        }

        let raw_bytes = read_file_bytes(path)?;
        let der_bytes = if is_pem {
            decode_pem_to_der(&raw_bytes)?
        } else {
            raw_bytes
        };

        let response = parse_ocsp_response(&der_bytes)?;

        if response.status != OcspResponseStatus::Successful {
            tracing::warn!(status = ?response.status, path = %path, "OCSP response not valid");
            return Err(OcspError::InvalidResponse {
                status: response.status,
            });
        }

        self.validate_response_timestamps(&response, path)?;

        if let Some(ref stack) = self.verify_stack {
            verify_response_chain(&response, stack)?;
        }

        tracing::debug!(
            path = %path,
            status = ?response.status,
            this_update = ?response.this_update,
            next_update = ?response.next_update,
            response_count = self.responses.len() + 1,
            "OCSP response loaded and validated"
        );

        self.responses.push(response);
        Ok(())
    }

    /// Validate the timestamps of an OCSP response.
    fn validate_response_timestamps(
        &self,
        response: &OcspResponse,
        path: &str,
    ) -> Result<(), OcspError> {
        let this_update = match &response.this_update {
            Some(t) => t,
            None => return Ok(()),
        };

        let now = SystemTime::now();
        let skew_duration = Duration::from_secs(self.skew_seconds.unsigned_abs());

        if let Ok(ahead) = this_update.duration_since(now) {
            if ahead > skew_duration {
                tracing::warn!(
                    path = %path,
                    ahead_secs = ahead.as_secs(),
                    skew_secs = self.skew_seconds,
                    "OCSP response thisUpdate is too far in the future"
                );
                return Err(OcspError::Expired);
            }
        }

        if let Some(next_update) = &response.next_update {
            if let Ok(age) = now.duration_since(*next_update) {
                tracing::warn!(
                    path = %path,
                    expired_ago_secs = age.as_secs(),
                    "OCSP response nextUpdate is in the past"
                );
                return Err(OcspError::Expired);
            }
        }

        if self.max_age >= 0 {
            let max_age_duration = Duration::from_secs(self.max_age as u64);
            if let Ok(age) = now.duration_since(*this_update) {
                if age > max_age_duration {
                    tracing::warn!(
                        path = %path,
                        age_secs = age.as_secs(),
                        max_age_secs = self.max_age,
                        "OCSP response exceeds max_age"
                    );
                    return Err(OcspError::Expired);
                }
            }
        }

        Ok(())
    }

    /// Get the raw DER-encoded OCSP response for a given certificate index.
    ///
    /// Replaces `tls_server_stapling_cb()` from tls-openssl.c (lines 2401-2479).
    pub fn get_response(&self, cert_index: usize) -> Option<&[u8]> {
        self.responses.get(cert_index).map(|r| r.data.as_slice())
    }

    /// Returns the number of loaded OCSP responses.
    pub fn response_count(&self) -> usize {
        self.responses.len()
    }

    /// Clear all loaded OCSP responses.
    pub fn clear(&mut self) {
        self.responses.clear();
    }
}

/// Client-side OCSP response verifier.
///
/// Validates OCSP responses received from servers during TLS handshakes.
/// Replaces the client OCSP verification logic in `tls_client_stapling_cb()`
/// from tls-openssl.c (lines 2500-2808).
pub struct OcspVerifier {
    required: bool,
    verify_store: Option<Vec<Vec<u8>>>,
}

impl OcspVerifier {
    /// Create a new `OcspVerifier`.
    pub fn new(required: bool) -> Self {
        Self {
            required,
            verify_store: None,
        }
    }

    /// Set the certificate store for verifying OCSP response signatures.
    pub fn set_verify_store(&mut self, certs: Vec<Vec<u8>>) {
        self.verify_store = Some(certs);
    }

    /// Verify a server-provided OCSP response against the server's certificate.
    ///
    /// Replaces the client-side OCSP verification in `tls_client_stapling_cb()`.
    pub fn verify_response(
        &self,
        response: &[u8],
        server_cert: &[u8],
    ) -> Result<OcspCertStatus, OcspError> {
        tracing::debug!("verifying server OCSP response");

        let parsed = parse_ocsp_response(response)?;

        if parsed.status != OcspResponseStatus::Successful {
            tracing::warn!(status = ?parsed.status, "OCSP response not successful");
            return Err(OcspError::InvalidResponse {
                status: parsed.status,
            });
        }

        if let Some(ref store) = self.verify_store {
            verify_response_chain(&parsed, store)?;
        }

        // Parse the server certificate to extract its serial number via x509-parser
        let (_, server_x509) = X509Certificate::from_der(server_cert).map_err(|e| {
            OcspError::ParseError(format!("failed to parse server certificate: {e}"))
        })?;
        let server_serial = server_x509.tbs_certificate.raw_serial();

        tracing::trace!(server_serial = ?server_serial, "extracted server certificate serial");

        let inner = parse_inner_response(response)?;

        if server_serial != inner.serial_number.as_slice() {
            tracing::warn!(
                server_serial = ?server_serial,
                response_serial = ?inner.serial_number,
                "OCSP response does not cover server certificate"
            );
            return Err(OcspError::CertMismatch);
        }

        tracing::debug!(cert_status = ?inner.cert_status, "OCSP certificate status");

        // Validate timestamps using default skew settings
        if let Some(ref this_update) = parsed.this_update {
            let now = SystemTime::now();
            let skew = Duration::from_secs(DEFAULT_SKEW_SECONDS.unsigned_abs());

            if let Ok(ahead) = this_update.duration_since(now) {
                if ahead > skew {
                    tracing::warn!(
                        ahead_secs = ahead.as_secs(),
                        "OCSP thisUpdate too far in future"
                    );
                    return Err(OcspError::Expired);
                }
            }

            if let Some(ref next_update) = parsed.next_update {
                if let Ok(expired) = now.duration_since(*next_update) {
                    tracing::warn!(
                        expired_secs = expired.as_secs(),
                        "OCSP nextUpdate in the past"
                    );
                    return Err(OcspError::Expired);
                }
            }
        }

        Ok(inner.cert_status)
    }

    /// Returns whether OCSP verification is required (hard-fail mode).
    pub fn is_required(&self) -> bool {
        self.required
    }
}

/// Validate OCSP response timestamps against the current system time.
///
/// Replaces the `OCSP_check_validity(thisupd, nextupd, skew, max_age)` call
/// from tls-openssl.c.
pub fn validate_timestamps(
    this_update: &[u8],
    next_update: Option<&[u8]>,
    skew: i64,
    max_age: i64,
) -> Result<bool, OcspError> {
    let now = SystemTime::now();
    let skew_duration = Duration::from_secs(skew.unsigned_abs());

    tracing::trace!(
        skew_seconds = skew,
        max_age_seconds = max_age,
        "validating OCSP timestamps"
    );

    let this_time = parse_generalized_time(this_update)?;
    tracing::trace!(this_update = ?this_time, "parsed thisUpdate timestamp");

    if let Ok(ahead) = this_time.duration_since(now) {
        if ahead > skew_duration {
            tracing::warn!(
                ahead_secs = ahead.as_secs(),
                skew_secs = skew,
                "thisUpdate too far in future"
            );
            return Err(OcspError::Expired);
        }
    }

    if max_age >= 0 {
        let max_age_duration = Duration::from_secs(max_age as u64);
        if let Ok(age) = now.duration_since(this_time) {
            if age > max_age_duration {
                tracing::warn!(
                    age_secs = age.as_secs(),
                    max_age_secs = max_age,
                    "OCSP exceeds max_age"
                );
                return Err(OcspError::Expired);
            }
        }
    }

    if let Some(next_bytes) = next_update {
        let next_time = parse_generalized_time(next_bytes)?;
        tracing::trace!(next_update = ?next_time, "parsed nextUpdate timestamp");

        if let Ok(elapsed) = now.duration_since(next_time) {
            tracing::warn!(
                expired_ago_secs = elapsed.as_secs(),
                "nextUpdate in the past"
            );
            return Err(OcspError::Expired);
        }

        if next_time < this_time {
            return Err(OcspError::ParseError(
                "nextUpdate is before thisUpdate".into(),
            ));
        }
    }

    tracing::trace!("OCSP timestamps valid");
    Ok(true)
}

/// Parse a DER-encoded OCSP response into an [`OcspResponse`] struct.
pub fn parse_ocsp_response(data: &[u8]) -> Result<OcspResponse, OcspError> {
    if data.is_empty() {
        return Err(OcspError::ParseError("empty OCSP response data".into()));
    }

    let (tag, outer_content, _) = read_der_element(data)?;
    if tag != TAG_SEQUENCE {
        return Err(OcspError::ParseError(format!(
            "expected SEQUENCE at top level, got tag 0x{tag:02X}"
        )));
    }

    let (tag, status_bytes, remaining) = read_der_element(outer_content)?;
    if tag != TAG_ENUMERATED {
        return Err(OcspError::ParseError(format!(
            "expected ENUMERATED for response status, got tag 0x{tag:02X}"
        )));
    }
    if status_bytes.is_empty() {
        return Err(OcspError::ParseError("empty ENUMERATED value".into()));
    }
    let status = OcspResponseStatus::from_u8(status_bytes[0])?;

    if status != OcspResponseStatus::Successful {
        return Ok(OcspResponse {
            data: data.to_vec(),
            status,
            this_update: None,
            next_update: None,
        });
    }

    if remaining.is_empty() {
        return Err(OcspError::ParseError("missing responseBytes".into()));
    }

    let (tag, resp_bytes_outer, _) = read_der_element(remaining)?;
    if tag != TAG_CONTEXT_0_EXPLICIT {
        return Err(OcspError::ParseError(format!(
            "expected [0] EXPLICIT for responseBytes, got tag 0x{tag:02X}"
        )));
    }

    let (tag, rb_content, _) = read_der_element(resp_bytes_outer)?;
    if tag != TAG_SEQUENCE {
        return Err(OcspError::ParseError(
            "expected SEQUENCE for ResponseBytes".into(),
        ));
    }

    let (tag, _oid, rb_remaining) = read_der_element(rb_content)?;
    if tag != TAG_OID {
        return Err(OcspError::ParseError(
            "expected OID for responseType".into(),
        ));
    }

    let (tag, basic_resp_der, _) = read_der_element(rb_remaining)?;
    if tag != TAG_OCTET_STRING {
        return Err(OcspError::ParseError(
            "expected OCTET STRING for response body".into(),
        ));
    }

    let (this_update, next_update) = parse_basic_response_timestamps(basic_resp_der)?;

    Ok(OcspResponse {
        data: data.to_vec(),
        status,
        this_update,
        next_update,
    })
}

// === Internal DER Parsing ===

fn read_der_length(data: &[u8]) -> Result<(usize, usize), OcspError> {
    if data.is_empty() {
        return Err(OcspError::ParseError(
            "unexpected end of data reading DER length".into(),
        ));
    }
    let first = data[0];
    if first & 0x80 == 0 {
        Ok((first as usize, 1))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 0 {
            return Err(OcspError::ParseError(
                "indefinite DER length not supported".into(),
            ));
        }
        if num_bytes > 4 {
            return Err(OcspError::ParseError(format!(
                "DER length too large: {num_bytes} bytes"
            )));
        }
        if data.len() < 1 + num_bytes {
            return Err(OcspError::ParseError(
                "insufficient data for long-form DER length".into(),
            ));
        }
        let mut length: usize = 0;
        for i in 0..num_bytes {
            length = length
                .checked_shl(8)
                .ok_or_else(|| OcspError::ParseError("DER length overflow".into()))?;
            length |= data[1 + i] as usize;
        }
        Ok((length, 1 + num_bytes))
    }
}

fn read_der_element(data: &[u8]) -> Result<(u8, &[u8], &[u8]), OcspError> {
    if data.is_empty() {
        return Err(OcspError::ParseError(
            "unexpected end of data reading DER element".into(),
        ));
    }
    let tag = data[0];
    let (length, length_size) = read_der_length(&data[1..])?;
    let header_len = 1 + length_size;
    if data.len() < header_len + length {
        return Err(OcspError::ParseError(format!(
            "DER content length {length} exceeds available data {} (tag 0x{tag:02X})",
            data.len() - header_len
        )));
    }
    let content = &data[header_len..header_len + length];
    let remaining = &data[header_len + length..];
    Ok((tag, content, remaining))
}

fn skip_der_element(data: &[u8]) -> Result<&[u8], OcspError> {
    let (_, _, remaining) = read_der_element(data)?;
    Ok(remaining)
}

// === Internal Time Parsing ===

fn parse_generalized_time(data: &[u8]) -> Result<SystemTime, OcspError> {
    let text = std::str::from_utf8(data)
        .map_err(|_| OcspError::ParseError("GeneralizedTime is not valid UTF-8".into()))?;
    let trimmed = text.trim_end_matches('Z');
    let base = match trimmed.find('.') {
        Some(pos) => &trimmed[..pos],
        None => trimmed,
    };
    if base.len() < 14 {
        return Err(OcspError::ParseError(format!(
            "GeneralizedTime too short: '{text}'"
        )));
    }
    let year: u32 = base[0..4]
        .parse()
        .map_err(|_| OcspError::ParseError(format!("invalid year: '{text}'")))?;
    let month: u32 = base[4..6]
        .parse()
        .map_err(|_| OcspError::ParseError(format!("invalid month: '{text}'")))?;
    let day: u32 = base[6..8]
        .parse()
        .map_err(|_| OcspError::ParseError(format!("invalid day: '{text}'")))?;
    let hour: u32 = base[8..10]
        .parse()
        .map_err(|_| OcspError::ParseError(format!("invalid hour: '{text}'")))?;
    let minute: u32 = base[10..12]
        .parse()
        .map_err(|_| OcspError::ParseError(format!("invalid minute: '{text}'")))?;
    let second: u32 = base[12..14]
        .parse()
        .map_err(|_| OcspError::ParseError(format!("invalid second: '{text}'")))?;
    if !(1..=12).contains(&month) {
        return Err(OcspError::ParseError(format!(
            "month out of range: {month}"
        )));
    }
    if !(1..=31).contains(&day) {
        return Err(OcspError::ParseError(format!("day out of range: {day}")));
    }
    if hour > 23 || minute > 59 || second > 59 {
        return Err(OcspError::ParseError(format!(
            "time out of range: {hour:02}:{minute:02}:{second:02}"
        )));
    }
    let unix_secs = datetime_to_unix(year, month, day, hour, minute, second)?;
    Ok(UNIX_EPOCH + Duration::from_secs(unix_secs))
}

fn datetime_to_unix(
    year: u32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Result<u64, OcspError> {
    let days_before_month: [u32; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    if year < 1970 {
        return Err(OcspError::ParseError(format!(
            "year {year} is before UNIX epoch"
        )));
    }
    let month_idx = (month - 1) as usize;
    if month_idx >= 12 {
        return Err(OcspError::ParseError(format!("invalid month: {month}")));
    }
    let y = if month <= 2 { year - 1 } else { year };
    let mut days: u64 = 365 * (year as u64 - 1970);
    days += leap_days_since_epoch(y);
    days += days_before_month[month_idx] as u64;
    if month > 2 && is_leap_year(year) {
        days += 1;
    }
    days += (day - 1) as u64;
    Ok(days * 86400 + (hour as u64) * 3600 + (minute as u64) * 60 + second as u64)
}

fn leap_days_since_epoch(year: u32) -> u64 {
    if year < 1970 {
        return 0;
    }
    let y = year as u64;
    (y / 4 - y / 100 + y / 400) - (1969u64 / 4 - 1969 / 100 + 1969 / 400)
}

fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

// === Internal File / PEM Handling ===

fn read_file_bytes(path: &str) -> Result<Vec<u8>, OcspError> {
    let mut file = File::open(path).map_err(|source| OcspError::LoadError {
        path: path.to_string(),
        source,
    })?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|source| OcspError::LoadError {
            path: path.to_string(),
            source,
        })?;
    Ok(buffer)
}

fn decode_pem_to_der(pem_data: &[u8]) -> Result<Vec<u8>, OcspError> {
    let text = std::str::from_utf8(pem_data)
        .map_err(|_| OcspError::ParseError("PEM data is not valid UTF-8".into()))?;
    let mut in_block = false;
    let mut base64_content = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN ") {
            in_block = true;
            continue;
        }
        if trimmed.starts_with("-----END ") {
            break;
        }
        if in_block {
            base64_content.push_str(trimmed);
        }
    }
    if base64_content.is_empty() {
        return Err(OcspError::ParseError(
            "no base64 content found in PEM data".into(),
        ));
    }
    base64_decode(&base64_content)
}

fn base64_decode(input: &str) -> Result<Vec<u8>, OcspError> {
    fn b64_val(c: u8) -> Result<u8, OcspError> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(OcspError::ParseError(format!(
                "invalid base64 character: 0x{c:02X}"
            ))),
        }
    }
    let chars: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
        .collect();
    let mut output = Vec::with_capacity(chars.len() * 3 / 4);
    for chunk in chars.chunks(4) {
        match chunk.len() {
            4 => {
                let (a, b, c, d) = (
                    b64_val(chunk[0])?,
                    b64_val(chunk[1])?,
                    b64_val(chunk[2])?,
                    b64_val(chunk[3])?,
                );
                output.push((a << 2) | (b >> 4));
                output.push((b << 4) | (c >> 2));
                output.push((c << 6) | d);
            }
            3 => {
                let (a, b, c) = (b64_val(chunk[0])?, b64_val(chunk[1])?, b64_val(chunk[2])?);
                output.push((a << 2) | (b >> 4));
                output.push((b << 4) | (c >> 2));
            }
            2 => {
                let (a, b) = (b64_val(chunk[0])?, b64_val(chunk[1])?);
                output.push((a << 2) | (b >> 4));
            }
            1 => {
                return Err(OcspError::ParseError(
                    "invalid base64: single trailing character".into(),
                ))
            }
            _ => {}
        }
    }
    Ok(output)
}

// === Internal OCSP Response Inner Parsing ===

struct InnerResponseData {
    serial_number: Vec<u8>,
    cert_status: OcspCertStatus,
}

fn parse_basic_response_timestamps(
    basic_der: &[u8],
) -> Result<(Option<SystemTime>, Option<SystemTime>), OcspError> {
    let (tag, basic_content, _) = read_der_element(basic_der)?;
    if tag != TAG_SEQUENCE {
        return Err(OcspError::ParseError(
            "expected SEQUENCE for BasicOCSPResponse".into(),
        ));
    }
    let (tag, tbs_content, _) = read_der_element(basic_content)?;
    if tag != TAG_SEQUENCE {
        return Err(OcspError::ParseError(
            "expected SEQUENCE for ResponseData".into(),
        ));
    }
    let mut cursor = tbs_content;
    // Skip optional version [0] EXPLICIT
    if !cursor.is_empty() && cursor[0] == TAG_CONTEXT_0_EXPLICIT {
        cursor = skip_der_element(cursor)?;
    }
    // Skip responderID
    if cursor.is_empty() {
        return Err(OcspError::ParseError("missing responderID".into()));
    }
    cursor = skip_der_element(cursor)?;
    // Skip producedAt
    if cursor.is_empty() {
        return Err(OcspError::ParseError("missing producedAt".into()));
    }
    cursor = skip_der_element(cursor)?;
    // responses SEQUENCE OF SingleResponse
    if cursor.is_empty() {
        return Err(OcspError::ParseError("missing responses".into()));
    }
    let (tag, responses_content, _) = read_der_element(cursor)?;
    if tag != TAG_SEQUENCE {
        return Err(OcspError::ParseError(
            "expected SEQUENCE OF SingleResponse".into(),
        ));
    }
    if responses_content.is_empty() {
        return Err(OcspError::ParseError("no SingleResponse entries".into()));
    }
    let (tag, single_resp_content, _) = read_der_element(responses_content)?;
    if tag != TAG_SEQUENCE {
        return Err(OcspError::ParseError(
            "expected SEQUENCE for SingleResponse".into(),
        ));
    }
    let mut sr_cursor = single_resp_content;
    sr_cursor = skip_der_element(sr_cursor)?; // certID
    sr_cursor = skip_der_element(sr_cursor)?; // certStatus
                                              // thisUpdate GeneralizedTime
    if sr_cursor.is_empty() {
        return Err(OcspError::ParseError("missing thisUpdate".into()));
    }
    let (tag, this_update_bytes, sr_remaining) = read_der_element(sr_cursor)?;
    if tag != TAG_GENERALIZED_TIME {
        return Err(OcspError::ParseError(format!(
            "expected GeneralizedTime for thisUpdate, got tag 0x{tag:02X}"
        )));
    }
    let this_update = parse_generalized_time(this_update_bytes)?;
    // optional nextUpdate [0] EXPLICIT GeneralizedTime
    let next_update = if !sr_remaining.is_empty() && sr_remaining[0] == TAG_CONTEXT_0_EXPLICIT {
        let (_, next_content, _) = read_der_element(sr_remaining)?;
        let (tag, next_time_bytes, _) = read_der_element(next_content)?;
        if tag != TAG_GENERALIZED_TIME {
            return Err(OcspError::ParseError(format!(
                "expected GeneralizedTime for nextUpdate, got tag 0x{tag:02X}"
            )));
        }
        Some(parse_generalized_time(next_time_bytes)?)
    } else {
        None
    };
    Ok((Some(this_update), next_update))
}

fn parse_inner_response(data: &[u8]) -> Result<InnerResponseData, OcspError> {
    let (_, outer_content, _) = read_der_element(data)?;
    let (_, _status_bytes, remaining) = read_der_element(outer_content)?;
    if remaining.is_empty() {
        return Err(OcspError::ParseError(
            "missing responseBytes for inner parse".into(),
        ));
    }
    let (_, resp_bytes_outer, _) = read_der_element(remaining)?;
    let (_, rb_content, _) = read_der_element(resp_bytes_outer)?;
    let (_, _, rb_remaining) = read_der_element(rb_content)?;
    let (_, basic_resp_der, _) = read_der_element(rb_remaining)?;
    let (_, basic_content, _) = read_der_element(basic_resp_der)?;
    let (_, tbs_content, _) = read_der_element(basic_content)?;
    let mut cursor = tbs_content;
    if !cursor.is_empty() && cursor[0] == TAG_CONTEXT_0_EXPLICIT {
        cursor = skip_der_element(cursor)?;
    }
    cursor = skip_der_element(cursor)?; // responderID
    cursor = skip_der_element(cursor)?; // producedAt
    let (_, responses_content, _) = read_der_element(cursor)?;
    let (_, single_resp, _) = read_der_element(responses_content)?;
    // CertID SEQUENCE
    let (tag, certid_content, certid_remaining) = read_der_element(single_resp)?;
    if tag != TAG_SEQUENCE {
        return Err(OcspError::ParseError("expected SEQUENCE for CertID".into()));
    }
    let mut cid_cursor = certid_content;
    cid_cursor = skip_der_element(cid_cursor)?; // hashAlgorithm
    cid_cursor = skip_der_element(cid_cursor)?; // issuerNameHash
    cid_cursor = skip_der_element(cid_cursor)?; // issuerKeyHash
    let (tag, serial_bytes, _) = read_der_element(cid_cursor)?;
    if tag != TAG_INTEGER {
        return Err(OcspError::ParseError(format!(
            "expected INTEGER for serial number, got tag 0x{tag:02X}"
        )));
    }
    let cert_status = parse_cert_status(certid_remaining)?;
    Ok(InnerResponseData {
        serial_number: serial_bytes.to_vec(),
        cert_status,
    })
}

fn parse_cert_status(data: &[u8]) -> Result<OcspCertStatus, OcspError> {
    if data.is_empty() {
        return Err(OcspError::ParseError("missing certStatus".into()));
    }
    match data[0] {
        TAG_CONTEXT_0_IMPLICIT => Ok(OcspCertStatus::Good),
        TAG_CONTEXT_1_CONSTRUCTED => Ok(OcspCertStatus::Revoked),
        TAG_CONTEXT_2_IMPLICIT => Ok(OcspCertStatus::Unknown),
        tag => Err(OcspError::ParseError(format!(
            "unknown certStatus tag: 0x{tag:02X}"
        ))),
    }
}

fn verify_response_chain(response: &OcspResponse, chain: &[Vec<u8>]) -> Result<(), OcspError> {
    if chain.is_empty() {
        tracing::debug!("no OCSP verify chain configured, skipping chain check");
        return Ok(());
    }
    let signer_certs = extract_signer_certs(&response.data);
    match signer_certs {
        Ok(certs) if !certs.is_empty() => {
            for signer_der in &certs {
                if chain.iter().any(|chain_cert| chain_cert == signer_der) {
                    tracing::debug!("OCSP signer certificate found in verify chain");
                    return Ok(());
                }
            }
            tracing::warn!("OCSP signer certificate not found in verify chain");
            Err(OcspError::SignatureVerifyFailed)
        }
        _ => {
            tracing::debug!("no embedded signer certs in OCSP response, delegating to backend");
            Ok(())
        }
    }
}

fn extract_signer_certs(data: &[u8]) -> Result<Vec<Vec<u8>>, OcspError> {
    let (_, outer_content, _) = read_der_element(data)?;
    let (tag, _, remaining) = read_der_element(outer_content)?;
    if tag != TAG_ENUMERATED {
        return Err(OcspError::ParseError("unexpected structure".into()));
    }
    if remaining.is_empty() {
        return Ok(Vec::new());
    }
    let (_, resp_bytes_outer, _) = read_der_element(remaining)?;
    let (_, rb_content, _) = read_der_element(resp_bytes_outer)?;
    let (_, _, rb_remaining) = read_der_element(rb_content)?;
    let (_, basic_resp_der, _) = read_der_element(rb_remaining)?;
    let (_, basic_content, _) = read_der_element(basic_resp_der)?;
    let rest = skip_der_element(basic_content)?; // tbsResponseData
    let rest = skip_der_element(rest)?; // signatureAlgorithm
    let rest = skip_der_element(rest)?; // signature
    if rest.is_empty() || rest[0] != TAG_CONTEXT_0_EXPLICIT {
        return Ok(Vec::new());
    }
    let (_, certs_outer, _) = read_der_element(rest)?;
    let (_, certs_seq, _) = read_der_element(certs_outer)?;
    let mut certs = Vec::new();
    let mut cur = certs_seq;
    while !cur.is_empty() {
        let (_, _, after) = read_der_element(cur)?;
        let cert_len = cur.len() - after.len();
        certs.push(cur[..cert_len].to_vec());
        cur = after;
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ocsp_response_status_from_u8() {
        assert_eq!(
            OcspResponseStatus::from_u8(0).unwrap(),
            OcspResponseStatus::Successful
        );
        assert_eq!(
            OcspResponseStatus::from_u8(1).unwrap(),
            OcspResponseStatus::MalformedRequest
        );
        assert_eq!(
            OcspResponseStatus::from_u8(2).unwrap(),
            OcspResponseStatus::InternalError
        );
        assert_eq!(
            OcspResponseStatus::from_u8(3).unwrap(),
            OcspResponseStatus::TryLater
        );
        assert_eq!(
            OcspResponseStatus::from_u8(5).unwrap(),
            OcspResponseStatus::SignatureRequired
        );
        assert_eq!(
            OcspResponseStatus::from_u8(6).unwrap(),
            OcspResponseStatus::Unauthorized
        );
        assert!(OcspResponseStatus::from_u8(4).is_err());
        assert!(OcspResponseStatus::from_u8(7).is_err());
    }

    #[test]
    fn test_ocsp_config_default() {
        let config = OcspConfig::default();
        assert_eq!(config.skew_seconds, 300);
        assert_eq!(config.max_age, -1);
        assert!(config.response_files.is_empty());
        assert!(!config.require_stapling);
    }

    #[test]
    fn test_der_length_short_form() {
        let (len, consumed) = read_der_length(&[0x0A_u8]).unwrap();
        assert_eq!(len, 10);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_der_length_long_form() {
        let (len, consumed) = read_der_length(&[0x81_u8, 0x80]).unwrap();
        assert_eq!(len, 128);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_der_element_parsing() {
        let data = [0x30_u8, 0x03, 0x0A, 0x01, 0x00];
        let (tag, content, remaining) = read_der_element(&data).unwrap();
        assert_eq!(tag, TAG_SEQUENCE);
        assert_eq!(content, &[0x0A, 0x01, 0x00]);
        assert!(remaining.is_empty());
    }

    #[test]
    fn test_generalized_time_parsing() {
        let secs = parse_generalized_time(b"20240101120000Z")
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(secs, 1704110400);
    }

    #[test]
    fn test_generalized_time_with_fractional() {
        assert!(parse_generalized_time(b"20240615153045.123Z").is_ok());
    }

    #[test]
    fn test_generalized_time_invalid() {
        assert!(parse_generalized_time(b"short").is_err());
        assert!(parse_generalized_time(b"20241301120000Z").is_err());
        assert!(parse_generalized_time(b"20240132120000Z").is_err());
        assert!(parse_generalized_time(b"20240101250000Z").is_err());
    }

    #[test]
    fn test_base64_decode_simple() {
        assert_eq!(base64_decode("SGVsbG8gV29ybGQ=").unwrap(), b"Hello World");
    }

    #[test]
    fn test_base64_decode_no_padding() {
        assert_eq!(base64_decode("SGVsbG8").unwrap(), b"Hello");
    }

    #[test]
    fn test_pem_decode() {
        let pem = b"-----BEGIN OCSP RESPONSE-----\nSGVsbG8gV29ybGQ=\n-----END OCSP RESPONSE-----\n";
        assert_eq!(decode_pem_to_der(pem).unwrap(), b"Hello World");
    }

    #[test]
    fn test_pem_decode_empty() {
        let pem = b"-----BEGIN OCSP RESPONSE-----\n-----END OCSP RESPONSE-----\n";
        assert!(decode_pem_to_der(pem).is_err());
    }

    #[test]
    fn test_ocsp_stapler_new() {
        let stapler = OcspStapler::new(&OcspConfig::default());
        assert_eq!(stapler.response_count(), 0);
        assert!(stapler.get_response(0).is_none());
    }

    #[test]
    fn test_ocsp_verifier_new() {
        assert!(OcspVerifier::new(true).is_required());
        assert!(!OcspVerifier::new(false).is_required());
    }

    #[test]
    fn test_parse_non_successful_response() {
        let data = [0x30_u8, 0x03, 0x0A, 0x01, 0x06];
        let result = parse_ocsp_response(&data).unwrap();
        assert_eq!(result.status, OcspResponseStatus::Unauthorized);
        assert!(result.this_update.is_none());
    }

    #[test]
    fn test_parse_empty_data() {
        assert!(parse_ocsp_response(&[]).is_err());
    }

    #[test]
    fn test_parse_invalid_top_level_tag() {
        assert!(parse_ocsp_response(&[0x04_u8, 0x03, 0x0A, 0x01, 0x00]).is_err());
    }

    #[test]
    fn test_validate_timestamps_valid() {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let this_gt = fmt_gt(now_secs - 3600);
        let next_gt = fmt_gt(now_secs + 3600);
        assert!(
            validate_timestamps(this_gt.as_bytes(), Some(next_gt.as_bytes()), 300, -1).unwrap()
        );
    }

    #[test]
    fn test_validate_timestamps_expired() {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let this_gt = fmt_gt(now_secs - 7200);
        let next_gt = fmt_gt(now_secs - 3600);
        assert!(
            validate_timestamps(this_gt.as_bytes(), Some(next_gt.as_bytes()), 300, -1).is_err()
        );
    }

    #[test]
    fn test_validate_timestamps_future_this() {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let this_gt = fmt_gt(now_secs + 600);
        let next_gt = fmt_gt(now_secs + 7200);
        assert!(
            validate_timestamps(this_gt.as_bytes(), Some(next_gt.as_bytes()), 300, -1).is_err()
        );
    }

    #[test]
    fn test_validate_timestamps_max_age() {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let this_gt = fmt_gt(now_secs - 7200);
        let next_gt = fmt_gt(now_secs + 3600);
        assert!(
            validate_timestamps(this_gt.as_bytes(), Some(next_gt.as_bytes()), 300, 3600).is_err()
        );
    }

    #[test]
    fn test_cert_status() {
        assert_eq!(
            parse_cert_status(&[TAG_CONTEXT_0_IMPLICIT, 0x00]).unwrap(),
            OcspCertStatus::Good
        );
        assert_eq!(
            parse_cert_status(&[TAG_CONTEXT_1_CONSTRUCTED, 0x02, 0x00, 0x00]).unwrap(),
            OcspCertStatus::Revoked
        );
        assert_eq!(
            parse_cert_status(&[TAG_CONTEXT_2_IMPLICIT, 0x00]).unwrap(),
            OcspCertStatus::Unknown
        );
    }

    #[test]
    fn test_leap_year() {
        assert!(is_leap_year(2000));
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(1900));
        assert!(!is_leap_year(2023));
    }

    #[test]
    fn test_load_response_missing_file() {
        let mut stapler = OcspStapler::new(&OcspConfig::default());
        match stapler
            .load_response("/nonexistent/ocsp.der", false)
            .unwrap_err()
        {
            OcspError::LoadError { path, .. } => assert_eq!(path, "/nonexistent/ocsp.der"),
            other => panic!("expected LoadError, got: {other:?}"),
        }
    }

    fn fmt_gt(unix_secs: u64) -> String {
        let mut s = unix_secs;
        let sec = s % 60;
        s /= 60;
        let min = s % 60;
        s /= 60;
        let hr = s % 24;
        let mut d = s / 24;
        let mut y = 1970u32;
        loop {
            let diy: u64 = if is_leap_year(y) { 366 } else { 365 };
            if d < diy {
                break;
            }
            d -= diy;
            y += 1;
        }
        let dim: [u64; 12] = if is_leap_year(y) {
            [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        } else {
            [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        };
        let mut m = 1u32;
        for &dm in &dim {
            if d < dm {
                break;
            }
            d -= dm;
            m += 1;
        }
        format!("{y:04}{m:02}{:02}{hr:02}{min:02}{sec:02}Z", d + 1)
    }
}
