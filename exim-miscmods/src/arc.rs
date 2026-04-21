//! ARC (Authenticated Received Chain) — RFC 8617 implementation.
//!
//! Rewrites `src/src/miscmods/arc.c` (2,179 lines) into idiomatic Rust,
//! providing ARC verify/sign functionality built on top of DKIM primitives
//! from the sibling `dkim` module.
//!
//! ARC provides a chain of authentication results across message-forwarding
//! hops, allowing intermediaries to record the authentication status of a
//! message at each hop.  This enables downstream receivers to validate the
//! chain of custody even when SPF/DKIM may break due to forwarding.
//!
//! # Feature Gate
//!
//! This module is gated behind `#[cfg(feature = "arc")]`, which implies
//! `dkim` (see `Cargo.toml`: `arc = ["dkim"]`).  ARC cannot function
//! without the DKIM primitives.
//!
//! # Architecture
//!
//! - **Verification**: Collect ARC-* headers → parse into [`ArcLine`] →
//!   group into [`ArcSet`] by instance → validate chain ordering → verify
//!   ARC-Message-Signature via DKIM → verify ARC-Seal → report state.
//!
//! - **Signing**: Determine next instance number → construct AAR, AMS, AS
//!   headers → sign AMS with DKIM → sign AS over chain → return headers.
//!
//! # Global State Elimination
//!
//! All C global variables (`arc_received`, `arc_received_instance`,
//! `arc_oldest_pass`, `arc_state`, `arc_state_reason`) are encapsulated in
//! [`ArcVerifyState`] and passed explicitly through all call chains per
//! AAP §0.4.4.
//!
//! # Safety
//!
//! This module contains zero `unsafe` code per AAP §0.7.2.

// ---------------------------------------------------------------------------
// External imports
// ---------------------------------------------------------------------------

use std::rc::Rc;
use thiserror::Error;
use tracing::{debug, info};

use exim_dns::DnsResolver;

// ---------------------------------------------------------------------------
// Internal imports — DKIM module (same crate)
// ---------------------------------------------------------------------------

use super::dkim::pdkim::signing::{self, HashAlgorithm, KeyFormat, KeyType, SigningError};
use super::dkim::pdkim::{
    self, decode_base64, encode_base64, relax_header_n, Canon, PdkimError,
    PDKIM_DEFAULT_SIGN_HEADERS,
};
use super::dkim::DkimError;

// ===========================================================================
// Constants
// ===========================================================================

/// Default expiry delta for ARC signing: 30 days in seconds.
///
/// Matches C `ARC_SIGN_DEFAULT_EXPIRE_DELTA` (60 * 60 * 24 * 30 = 2,592,000).
pub const ARC_DEFAULT_EXPIRE_DELTA: u64 = 60 * 60 * 24 * 30;

/// ARC header prefix for ARC-Authentication-Results.
const ARC_HDR_AAR: &str = "ARC-Authentication-Results:";
/// Length of the AAR header name.
const ARC_HDRLEN_AAR: usize = 27;

/// ARC header prefix for ARC-Message-Signature.
const ARC_HDR_AMS: &str = "ARC-Message-Signature:";
/// Length of the AMS header name.
const ARC_HDRLEN_AMS: usize = 22;

/// ARC header prefix for ARC-Seal.
const ARC_HDR_AS: &str = "ARC-Seal:";
/// Length of the AS header name.
const ARC_HDRLEN_AS: usize = 9;

/// Maximum allowed ARC instance number (prevents DoS).
const ARC_MAX_INSTANCE: u32 = 50;

// ===========================================================================
// ArcError — Structured error types
// ===========================================================================

/// Errors arising from ARC verification and signing operations.
///
/// Replaces ad-hoc error string handling from C `arc.c`.  Each variant
/// corresponds to a distinct failure category.
#[derive(Debug, Error)]
pub enum ArcError {
    /// ARC verification failed with the given reason.
    #[error("ARC verification error: {0}")]
    VerificationError(String),

    /// ARC signing operation failed.
    #[error("ARC signing error: {0}")]
    SigningError(String),

    /// ARC chain validation failed (instance ordering, missing headers).
    #[error("ARC chain validation error: {0}")]
    ChainValidation(String),

    /// ARC header parsing failed.
    #[error("ARC header parsing error: {0}")]
    HeaderParsing(String),

    /// A required ARC tag is missing.
    #[error("ARC missing required tag: {0}")]
    MissingTag(String),

    /// Error propagated from underlying DKIM primitives.
    #[error("DKIM primitive error: {0}")]
    DkimPrimitive(#[from] DkimError),

    /// Bad signing specification (identity, selector, or private key).
    #[error("ARC bad signing specification: {0}")]
    BadSignSpec(String),

    /// Body hash mismatch during AMS verification.
    #[error("ARC body hash mismatch: {0}")]
    BadBodyhash(String),
}

impl From<PdkimError> for ArcError {
    fn from(e: PdkimError) -> Self {
        ArcError::DkimPrimitive(DkimError::PdkimError(format!("{e}")))
    }
}

impl From<SigningError> for ArcError {
    fn from(e: SigningError) -> Self {
        ArcError::DkimPrimitive(DkimError::SigningError(format!("{e}")))
    }
}

// ===========================================================================
// ArcState — Overall ARC chain state
// ===========================================================================

/// Overall ARC chain verification state (RFC 8617 §5.2).
///
/// Replaces the C global `arc_state` string pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArcState {
    /// No ARC headers present in the message.
    None,
    /// ARC chain verified successfully.
    Pass,
    /// ARC chain verification failed.
    Fail,
}

impl std::fmt::Display for ArcState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArcState::None => write!(f, "none"),
            ArcState::Pass => write!(f, "pass"),
            ArcState::Fail => write!(f, "fail"),
        }
    }
}

// ===========================================================================
// ArcCV — Chain Validation status per ARC-Seal
// ===========================================================================

/// Chain validation status from the `cv=` tag of an ARC-Seal header.
///
/// Per RFC 8617 §4.1.1, the cv tag indicates the result of chain validation
/// at the time the seal was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArcCV {
    /// No previous chain (`cv=none`); valid only for instance 1.
    None,
    /// Previous chain validation failed (`cv=fail`).
    Fail,
    /// Previous chain validation passed (`cv=pass`).
    Pass,
}

impl ArcCV {
    /// Parse a cv= tag value string into an `ArcCV` variant.
    fn from_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" => Some(ArcCV::None),
            "fail" => Some(ArcCV::Fail),
            "pass" => Some(ArcCV::Pass),
            _ => Option::None,
        }
    }
}

impl std::fmt::Display for ArcCV {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArcCV::None => write!(f, "none"),
            ArcCV::Fail => write!(f, "fail"),
            ArcCV::Pass => write!(f, "pass"),
        }
    }
}

// ===========================================================================
// ArcLine — Parsed ARC header line
// ===========================================================================

/// A parsed ARC header line with extracted tag fields.
///
/// Replaces C `arc_line` struct (arc.c lines 44–71).  Each field corresponds
/// to a tag from the ARC header as defined in RFC 8617 / RFC 6376.
#[derive(Debug, Clone)]
pub struct ArcLine {
    /// Instance number from `i=` tag.
    pub instance: u32,

    /// Chain validation status from `cv=` tag (ARC-Seal only).
    pub chain_validation: ArcCV,

    /// Full algorithm string from `a=` tag (e.g., "rsa-sha256").
    pub algorithm: String,

    /// Algorithm hash portion (e.g., "sha256" from "rsa-sha256").
    pub algorithm_hash: String,

    /// Algorithm key type portion (e.g., "rsa" from "rsa-sha256").
    pub algorithm_key: String,

    /// Decoded signature bytes from `b=` tag (base64-decoded).
    pub signature: Vec<u8>,

    /// Decoded body hash bytes from `bh=` tag (base64-decoded).
    pub body_hash: Vec<u8>,

    /// Signing domain from `d=` tag.
    pub domain: String,

    /// List of signed header names from `h=` tag.
    pub signed_headers: Vec<String>,

    /// Key selector from `s=` tag.
    pub selector: String,

    /// Canonicalization method pair from `c=` tag (header, body).
    pub canonicalization: (Canon, Canon),

    /// Body length limit from `l=` tag (None if not specified).
    pub body_length: Option<u64>,

    /// IP address from `smtp.remote-ip=` in AAR.
    pub ip_address: Option<String>,

    /// Raw signature header with b= value stripped (for verification hash).
    pub raw_sig_no_b_val: String,

    /// Relaxed-canonicalized form of the complete header (cached).
    pub relaxed: Option<String>,

    /// Complete original header text.
    pub complete: String,
}

impl Default for ArcLine {
    fn default() -> Self {
        Self {
            instance: 0,
            chain_validation: ArcCV::None,
            algorithm: String::new(),
            algorithm_hash: String::new(),
            algorithm_key: String::new(),
            signature: Vec::new(),
            body_hash: Vec::new(),
            domain: String::new(),
            signed_headers: Vec::new(),
            selector: String::new(),
            canonicalization: (Canon::Simple, Canon::Simple),
            body_length: Option::None,
            ip_address: Option::None,
            raw_sig_no_b_val: String::new(),
            relaxed: Option::None,
            complete: String::new(),
        }
    }
}

// ===========================================================================
// ArcSet — One complete ARC instance (AAR + AMS + AS)
// ===========================================================================

/// A complete ARC set consisting of one instance's three headers.
///
/// Per RFC 8617 §4.1, each ARC set contains exactly one of each:
/// ARC-Authentication-Results, ARC-Message-Signature, and ARC-Seal,
/// all sharing the same instance number (`i=` tag).
///
/// Replaces C `arc_set` struct (arc.c lines 73–84).
#[derive(Debug, Clone)]
pub struct ArcSet {
    /// Instance number (1..n).
    pub instance: u32,

    /// Parsed ARC-Authentication-Results header.
    pub hdr_aar: Option<ArcLine>,

    /// Parsed ARC-Message-Signature header.
    pub hdr_ams: Option<ArcLine>,

    /// Parsed ARC-Seal header.
    pub hdr_as: Option<ArcLine>,

    /// Whether AMS verification has been attempted for this set.
    pub ams_verify_done: Option<String>,

    /// Whether AMS verification passed for this set.
    pub ams_verify_passed: bool,
}

impl ArcSet {
    /// Create a new empty ARC set for the given instance number.
    fn new(instance: u32) -> Self {
        Self {
            instance,
            hdr_aar: Option::None,
            hdr_ams: Option::None,
            hdr_as: Option::None,
            ams_verify_done: Option::None,
            ams_verify_passed: false,
        }
    }
}

// ===========================================================================
// ArcSignOptions — Configuration for ARC signing
// ===========================================================================

/// Options controlling ARC signature generation.
///
/// Replaces the C signing specification parsing from `arc_sign()` (arc.c
/// lines 1779–1838) and the `ARC_SIGN_OPT_*` bitmask flags.
#[derive(Debug, Clone)]
pub struct ArcSignOptions {
    /// Whether to include a `t=` timestamp tag.
    pub include_timestamp: bool,

    /// Whether to include an `x=` expiry tag.
    pub include_expiry: bool,

    /// Expiry delta from current time in seconds (default: 30 days).
    pub expire_delta: u64,

    /// Signing domain (identity), e.g. `"example.com"`.
    pub domain: String,

    /// Key selector, e.g. `"arc-20240101"`.
    pub selector: String,

    /// PEM-encoded private key or file path.
    pub private_key: String,
}

impl Default for ArcSignOptions {
    fn default() -> Self {
        Self {
            include_timestamp: false,
            include_expiry: false,
            expire_delta: ARC_DEFAULT_EXPIRE_DELTA,
            domain: String::new(),
            selector: String::new(),
            private_key: String::new(),
        }
    }
}

// ===========================================================================
// ArcSigningContext — State for an in-progress signing operation
// ===========================================================================

/// Context for an in-progress ARC signing operation.
///
/// Created by [`arc_sign_init`] and consumed by [`arc_sign`].
#[derive(Debug, Clone)]
pub struct ArcSigningContext {
    /// Instance number for the new ARC set being created.
    pub instance: u32,

    /// Signing options (domain, selector, key, timestamps).
    pub options: ArcSignOptions,

    /// Body hash bytes computed by DKIM for the message body.
    pub bodyhash: Vec<u8>,

    /// Reverse-order list of message header texts for signing.
    pub headers_rlist: Vec<HeaderEntry>,

    /// Pre-existing ARC chain parsed from the inbound message headers.
    ///
    /// Populated by [`arc_sign_init`] by parsing any existing AAR/AMS/AS
    /// headers in the message.  Consumed by [`arc_sign`] when constructing
    /// the ARC-Seal `hdata` accumulator for signing: the chain must be
    /// hashed in instance-ascending order — AAR(i=1), AMS(i=1), AS(i=1),
    /// AAR(i=2), AMS(i=2), AS(i=2), ..., followed by the *new* set's
    /// AAR+AMS+AS-with-empty-b — per RFC 8617 §5.1.2.
    ///
    /// Mirrors the C code's reliance on `ctx->arcset_chain` from
    /// `arc_sign_prepend_as()` (arc.c lines 1643–1670) which walks the
    /// entire chain when signing a non-fail AS.
    pub existing_sets: Vec<ArcSet>,
}

// ===========================================================================
// Internal helper types
// ===========================================================================

/// A header entry in the reverse-order list used during signing/verification.
///
/// Replaces C `hdr_rlist` struct (arc.c lines 38–42).
#[derive(Debug, Clone)]
pub struct HeaderEntry {
    /// Whether this header has been consumed by signature computation.
    pub used: bool,
    /// The complete header text (including name and value).
    pub text: String,
    /// Length of the header text.
    pub len: usize,
}

/// Internal verification context tracking the chain of ARC sets.
///
/// Replaces C `arc_ctx` struct (arc.c lines 86–89).
#[derive(Debug, Clone, Default)]
struct ArcContext {
    /// Ordered chain of ARC sets (by instance number, ascending).
    arcset_chain: Vec<ArcSet>,
}

impl ArcContext {
    /// Find or create an ARC set for the given instance number.
    ///
    /// Sets are maintained in ascending instance-number order.
    fn find_or_create_set(&mut self, instance: u32) -> &mut ArcSet {
        // Find existing
        if let Some(pos) = self
            .arcset_chain
            .iter()
            .position(|s| s.instance == instance)
        {
            debug!("ARC: existing instance {}", instance);
            return &mut self.arcset_chain[pos];
        }

        debug!("ARC: new instance {}", instance);
        let new_set = ArcSet::new(instance);

        // Insert in sorted order
        let insert_pos = self
            .arcset_chain
            .iter()
            .position(|s| s.instance > instance)
            .unwrap_or(self.arcset_chain.len());
        self.arcset_chain.insert(insert_pos, new_set);

        &mut self.arcset_chain[insert_pos]
    }

    /// Get the last (highest instance) arc set, if any.
    fn last_set(&self) -> Option<&ArcSet> {
        self.arcset_chain.last()
    }
}

/// What level of tag extraction to perform during line parsing.
///
/// Replaces C `line_extract_t` enum (arc.c lines 100–104).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineExtract {
    /// Only extract the `i=` tag (instance number).
    InstanceOnly,
    /// Extract `i=` and `smtp.remote-ip=`.
    InstancePlusIp,
    /// Extract all tags.
    All,
}

// ===========================================================================
// Verification state (replaces C globals)
// ===========================================================================

/// Mutable state for an ARC verification session.
///
/// Replaces all C global variables (`arc_received`, `arc_received_instance`,
/// `arc_oldest_pass`, `arc_state`, `arc_state_reason`).
#[derive(Debug, Clone, Default)]
struct ArcVerifyState {
    /// Verification context holding the parsed ARC chain.
    ctx: ArcContext,
    /// Reverse-order list of all message headers.
    headers_rlist: Vec<HeaderEntry>,
    /// Highest ARC instance number found in headers.
    received_instance: u32,
    /// Lowest ARC instance number that passed AMS verification.
    oldest_pass: u32,
    /// Reason string for failure (if any).
    state_reason: Option<String>,
}

// ===========================================================================
// ARC tag parsing
// ===========================================================================

/// Skip folding whitespace (FWS) in a tag-list string.
///
/// Replaces C `skip_fws()` (arc.c lines 178–183).
fn skip_fws(s: &str) -> &str {
    s.trim_start_matches([' ', '\t', '\n', '\r'])
}

/// Parse an ARC header line and extract tag values.
///
/// Replaces C `arc_parse_line()` (arc.c lines 262–465).
///
/// Parses the tag-value list after the header name, extracting fields
/// according to the `extract_level` parameter.
fn arc_parse_line(
    header_text: &str,
    header_name_len: usize,
    extract_level: LineExtract,
) -> Result<ArcLine, ArcError> {
    let mut al = ArcLine {
        complete: header_text.to_string(),
        ..Default::default()
    };

    let body = &header_text[header_name_len..];

    // Parse tag-value list: tag=value; tag=value; ...
    let mut tags: Vec<(String, String)> = Vec::new();
    let mut remaining = body;

    while !remaining.is_empty() {
        remaining = skip_fws(remaining);
        if remaining.is_empty() {
            break;
        }

        // Find tag name (single char for ARC tags, or multi-char for AAR)
        let mut chars = remaining.chars();
        let tag_char = match chars.next() {
            Some(c) => c,
            Option::None => break,
        };

        remaining = chars.as_str();
        remaining = skip_fws(remaining);

        // Check for special multi-character tags like "cv", "bh", or
        // "smtp.remote-ip"
        let tag_name: String;

        if tag_char == 'c' && remaining.starts_with('v') {
            // cv= tag
            remaining = &remaining[1..]; // skip 'v'
            remaining = skip_fws(remaining);
            tag_name = "cv".to_string();
        } else if tag_char == 'b' && remaining.starts_with('h') {
            // bh= tag
            remaining = &remaining[1..]; // skip 'h'
            remaining = skip_fws(remaining);
            tag_name = "bh".to_string();
        } else if tag_char == 's' && remaining.starts_with("mtp.remote-ip") {
            // smtp.remote-ip= tag (in AAR)
            remaining = &remaining["mtp.remote-ip".len()..];
            remaining = skip_fws(remaining);
            tag_name = "smtp.remote-ip".to_string();
        } else {
            tag_name = tag_char.to_string();
        }

        // Expect '='
        if !remaining.starts_with('=') {
            // Not a tag=value pair; skip to next semicolon
            if let Some(semi_pos) = remaining.find(';') {
                remaining = &remaining[semi_pos + 1..];
            } else {
                break;
            }
            continue;
        }
        remaining = &remaining[1..]; // skip '='
        remaining = skip_fws(remaining);

        // Extract value up to semicolon or end
        let semi_pos = remaining.find(';').unwrap_or(remaining.len());
        let raw_value = &remaining[..semi_pos];

        // Trim trailing FWS from value
        let value = raw_value
            .trim_end_matches([' ', '\t', '\n', '\r'])
            .to_string();

        remaining = if semi_pos < remaining.len() {
            &remaining[semi_pos + 1..]
        } else {
            ""
        };

        tags.push((tag_name, value));
    }

    // Process extracted tags
    for (tag_name, value) in &tags {
        match tag_name.as_str() {
            "i" => {
                al.instance = value.parse::<u32>().unwrap_or(0);
                if extract_level == LineExtract::InstanceOnly {
                    return Ok(al);
                }
            }
            "a" if extract_level == LineExtract::All => {
                al.algorithm = value.clone();
                // Parse sub-portions: algo-hash (e.g., rsa-sha256)
                if let Some(dash_pos) = value.find('-') {
                    al.algorithm_key = value[..dash_pos].to_string();
                    al.algorithm_hash = value[dash_pos + 1..].to_string();
                }
            }
            "b" if extract_level == LineExtract::All => {
                // Strip embedded FWS from b= value
                let stripped: String = value
                    .chars()
                    .filter(|c| !matches!(c, ' ' | '\t' | '\n' | '\r'))
                    .collect();
                al.signature = decode_base64(&stripped);
            }
            "bh" if extract_level == LineExtract::All => {
                let stripped: String = value
                    .chars()
                    .filter(|c| !matches!(c, ' ' | '\t' | '\n' | '\r'))
                    .collect();
                al.body_hash = decode_base64(&stripped);
            }
            "cv" if extract_level == LineExtract::All => {
                al.chain_validation = ArcCV::from_str(value).unwrap_or(ArcCV::None);
            }
            "c" if extract_level == LineExtract::All => {
                // Parse canonicalization: head/body
                let parts: Vec<&str> = value.splitn(2, '/').collect();
                let header_canon = match parts.first().map(|s| s.trim()) {
                    Some("relaxed") => Canon::Relaxed,
                    _ => Canon::Simple,
                };
                let body_canon = match parts.get(1).map(|s| s.trim()) {
                    Some("relaxed") => Canon::Relaxed,
                    _ => Canon::Simple,
                };
                al.canonicalization = (header_canon, body_canon);
            }
            "d" if extract_level == LineExtract::All => {
                al.domain = value.clone();
            }
            "h" => {
                // h= tag contains colon-separated header names
                al.signed_headers = value
                    .split(':')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            "l" if extract_level == LineExtract::All => {
                al.body_length = value.parse::<u64>().ok();
            }
            "s" if extract_level == LineExtract::All => {
                al.selector = value.clone();
            }
            "smtp.remote-ip" if extract_level == LineExtract::InstancePlusIp => {
                al.ip_address = Some(value.clone());
            }
            _ => {
                // Unknown or non-extracted tag — skip
            }
        }
    }

    // Build raw_sig_no_b_val: header text with b= value replaced by empty
    if extract_level == LineExtract::All {
        al.raw_sig_no_b_val = build_raw_sig_no_b_val(header_text, header_name_len);
    }

    // Apply defaults for canonicalization if c= was absent
    if al.algorithm.is_empty() && extract_level == LineExtract::All {
        // No a= tag found — this will be caught later as a missing tag
    }

    Ok(al)
}

/// Build a copy of the header with the b= tag value stripped.
///
/// This is used for signature verification: the b= tag value is excluded
/// from the data that is hashed.
fn build_raw_sig_no_b_val(header_text: &str, _header_name_len: usize) -> String {
    // Find "b=" in the header (not "bh=")
    let mut result = String::with_capacity(header_text.len());
    let mut remaining = header_text;

    loop {
        // Find next 'b' that could start a b= tag
        if let Some(pos) = remaining.find("b=") {
            // Make sure it's not "bh="
            if pos > 0 && remaining.as_bytes().get(pos.wrapping_sub(1)) == Some(&b'b') {
                // This is part of a longer string, skip
                result.push_str(&remaining[..pos + 2]);
                remaining = &remaining[pos + 2..];
                continue;
            }
            // Check it's not "bh="
            if remaining.as_bytes().get(pos + 1) == Some(&b'h') {
                result.push_str(&remaining[..pos + 2]);
                remaining = &remaining[pos + 2..];
                continue;
            }

            // Check the char before 'b' is FWS or ';' or start
            let prev_ok = if pos == 0 {
                true
            } else {
                let prev = remaining.as_bytes()[pos - 1];
                matches!(prev, b' ' | b'\t' | b'\n' | b'\r' | b';')
            };

            if prev_ok {
                // Found b= tag — copy up to and including "b="
                result.push_str(&remaining[..pos + 2]);
                remaining = &remaining[pos + 2..];

                // Skip the b= value (up to next ';' or end)
                if let Some(semi_pos) = remaining.find(';') {
                    remaining = &remaining[semi_pos..];
                } else {
                    remaining = "";
                }
            } else {
                result.push_str(&remaining[..pos + 2]);
                remaining = &remaining[pos + 2..];
            }
        } else {
            result.push_str(remaining);
            break;
        }
    }

    result
}

// ===========================================================================
// ARC header identification and insertion
// ===========================================================================

/// Try to identify and parse an ARC header, inserting it into the context.
///
/// Replaces C `arc_try_header()` (arc.c lines 502–569).
fn arc_try_header(
    ctx: &mut ArcContext,
    header_text: &str,
    is_signing: bool,
) -> Result<Option<ArcLine>, ArcError> {
    let text_lower = header_text.to_ascii_lowercase();

    if text_lower.starts_with("arc-authentication-results:") {
        debug!("ARC: found AAR: {}", header_text.trim_end());
        let extract = if is_signing {
            LineExtract::InstanceOnly
        } else {
            LineExtract::InstancePlusIp
        };
        let al = arc_parse_line(header_text, ARC_HDRLEN_AAR, extract)?;
        let instance = al.instance;
        if instance == 0 {
            return Err(ArcError::HeaderParsing("AAR: instance find".to_string()));
        }
        if instance > ARC_MAX_INSTANCE {
            return Err(ArcError::HeaderParsing(
                "AAR: overlarge instance number".to_string(),
            ));
        }
        let arc_set = ctx.find_or_create_set(instance);
        if arc_set.hdr_aar.is_some() {
            return Err(ArcError::HeaderParsing("AAR: dup hdr".to_string()));
        }
        arc_set.hdr_aar = Some(al);
        Ok(Option::None)
    } else if text_lower.starts_with("arc-message-signature:") {
        debug!("ARC: found AMS: {}", header_text.trim_end());
        let extract = if is_signing {
            LineExtract::InstanceOnly
        } else {
            LineExtract::All
        };
        let al = arc_parse_line(header_text, ARC_HDRLEN_AMS, extract)?;
        let instance = al.instance;
        if instance == 0 {
            return Err(ArcError::HeaderParsing("AMS: instance find".to_string()));
        }
        if instance > ARC_MAX_INSTANCE {
            return Err(ArcError::HeaderParsing(
                "AMS: overlarge instance number".to_string(),
            ));
        }
        let arc_set = ctx.find_or_create_set(instance);
        if arc_set.hdr_ams.is_some() {
            return Err(ArcError::HeaderParsing("AMS: dup hdr".to_string()));
        }
        let ams_ref = al.clone();
        arc_set.hdr_ams = Some(al);
        Ok(Some(ams_ref))
    } else if text_lower.starts_with("arc-seal:") {
        debug!("ARC: found AS: {}", header_text.trim_end());
        let extract = if is_signing {
            LineExtract::InstanceOnly
        } else {
            LineExtract::All
        };
        let al = arc_parse_line(header_text, ARC_HDRLEN_AS, extract)?;
        let instance = al.instance;
        if instance == 0 {
            return Err(ArcError::HeaderParsing("AS: instance find".to_string()));
        }
        if instance > ARC_MAX_INSTANCE {
            return Err(ArcError::HeaderParsing(
                "AS: overlarge instance number".to_string(),
            ));
        }
        let arc_set = ctx.find_or_create_set(instance);
        if arc_set.hdr_as.is_some() {
            return Err(ArcError::HeaderParsing("AS: dup hdr".to_string()));
        }
        arc_set.hdr_as = Some(al);
        Ok(Option::None)
    } else {
        Ok(Option::None)
    }
}

// ===========================================================================
// Verification functions
// ===========================================================================

/// Collect all ARC headers from the message and build the chain.
///
/// Replaces C `arc_vfy_collect_hdrs()` (arc.c lines 581–607).
fn arc_vfy_collect_hdrs(
    state: &mut ArcVerifyState,
    headers: &[String],
) -> Result<ArcState, ArcError> {
    debug!("ARC: collecting arc sets");

    // Build reverse-order header list and parse ARC headers
    for header_text in headers {
        state.headers_rlist.push(HeaderEntry {
            used: false,
            text: header_text.clone(),
            len: header_text.len(),
        });

        if let Err(e) = arc_try_header(&mut state.ctx, header_text, false) {
            state.state_reason = Some(format!("collecting headers: {e}"));
            return Ok(ArcState::Fail);
        }
    }

    // Reverse the header list for proper ordering
    state.headers_rlist.reverse();

    if state.ctx.arcset_chain.is_empty() {
        return Ok(ArcState::None);
    }

    Ok(ArcState::Pass) // Placeholder — further checks follow
}

/// Compute the raw canonicalized data bytes used as input for AMS
/// signature verification.
///
/// Walks the reverse-order header list and, for each header name listed in
/// `ams.signed_headers` (the `h=` tag), finds the first unused matching
/// header, canonicalizes it per the AMS `c=` setting, and appends it to the
/// accumulation buffer. Finally appends the AMS header itself (with the
/// `b=` value stripped, no trailing CRLF) which is the self-signed
/// pseudo-header per RFC 6376 §3.5.
///
/// The returned bytes are passed directly to [`signing::verify`] as the
/// message to verify against; the Rust signing backend (`RustCrypto`) then
/// hashes the data internally (using SHA-256 for `rsa-sha256` or raw mode
/// for Ed25519) before performing the public-key verification.
///
/// This differs from the C implementation which pre-computes a hash and
/// passes it to GnuTLS `gnutls_pubkey_verify_hash2` (which expects a hash
/// rather than raw data). The semantic result is identical — the same
/// digest is computed — but the API boundary is different.
///
/// Replaces C `arc_get_verify_hhash()` (arc.c lines 655–710), adapted to
/// the RustCrypto API shape.
fn arc_get_verify_data(headers_rlist: &mut [HeaderEntry], ams: &ArcLine) -> Vec<u8> {
    let is_relaxed = ams.canonicalization.0 == Canon::Relaxed;

    let mut data = Vec::new();

    debug!("ARC: AMS header data for verification:");

    // Reset used marks
    for entry in headers_rlist.iter_mut() {
        entry.used = false;
    }

    // For each header name in h= list, find first unused matching header
    for header_name in &ams.signed_headers {
        for entry in headers_rlist.iter_mut() {
            if !entry.used {
                let hdr_lower = entry.text.to_ascii_lowercase();
                let name_lower = header_name.to_ascii_lowercase();
                if hdr_lower.starts_with(&name_lower)
                    && entry
                        .text
                        .as_bytes()
                        .get(name_lower.len())
                        .is_some_and(|&b| b == b':')
                {
                    let s = if is_relaxed {
                        relax_header_n(&entry.text, entry.len, true)
                    } else {
                        entry.text.clone()
                    };
                    debug!("  {}", s.trim_end());
                    data.extend_from_slice(s.as_bytes());
                    entry.used = true;
                    break;
                }
            }
        }
    }

    // Add the signature header with b= stripped (no trailing CRLF)
    let sig_header = &ams.raw_sig_no_b_val;
    let s = if is_relaxed {
        relax_header_n(sig_header, sig_header.len(), false)
    } else {
        sig_header.clone()
    };
    debug!("  {}", s.trim_end());
    data.extend_from_slice(s.as_bytes());

    debug!("ARC: AMS raw verify-data len={}", data.len());
    data
}

/// Map an ARC algorithm string (e.g. `"rsa-sha256"`, `"ed25519-sha256"`)
/// into the pair ([`KeyType`], [`HashAlgorithm`]) required by
/// [`signing::verify_init`] / [`signing::signing_init`].
///
/// Returns `None` if the key-type or hash-algo portion is unrecognized.
/// RFC 8617 mandates `rsa-sha256` but Ed25519 is also widely implemented.
fn arc_algo_components(
    algorithm_key: &str,
    algorithm_hash: &str,
) -> Option<(KeyType, HashAlgorithm)> {
    let key_type = match algorithm_key.to_ascii_lowercase().as_str() {
        "rsa" => KeyType::Rsa,
        "ed25519" => KeyType::Ed25519,
        _ => return None,
    };
    let hash_algo = HashAlgorithm::from_name(algorithm_hash)?;
    Some((key_type, hash_algo))
}

/// Verify an ARC-Message-Signature.
///
/// Performs real cryptographic verification: fetches the DKIM public key
/// from DNS using the AMS `d=`/`s=` tags, canonicalizes the signed
/// headers plus the AMS pseudo-header (with `b=` stripped), then invokes
/// [`signing::verify`] which hashes the data internally and checks the
/// public-key signature.
///
/// Replaces C `arc_ams_verify()` (arc.c lines 855–938).
///
/// When `dns` is `None`, verification is limited to structural checks
/// (required-tag presence and format). This mode is used only by tests
/// that exercise non-verification code paths; in production the DNS
/// resolver is always passed in from the DATA ACL.
fn arc_ams_verify(
    state: &mut ArcVerifyState,
    set_index: usize,
    dns: Option<&DnsResolver>,
) -> Result<(), ArcError> {
    let arc_set = &state.ctx.arcset_chain[set_index];
    let ams = match &arc_set.hdr_ams {
        Some(ams) => ams.clone(),
        Option::None => {
            return Err(ArcError::MissingTag("AMS header missing".to_string()));
        }
    };

    // Check required tags: a, b, bh, d, h, s
    if ams.algorithm.is_empty() {
        let reason = "required tag missing: a";
        state.ctx.arcset_chain[set_index].ams_verify_done = Some(reason.to_string());
        state.state_reason = Some(reason.to_string());
        return Err(ArcError::MissingTag(reason.to_string()));
    }
    if ams.signature.is_empty() {
        let reason = "required tag missing: b";
        state.ctx.arcset_chain[set_index].ams_verify_done = Some(reason.to_string());
        state.state_reason = Some(reason.to_string());
        return Err(ArcError::MissingTag(reason.to_string()));
    }
    if ams.body_hash.is_empty() {
        let reason = "required tag missing: bh";
        state.ctx.arcset_chain[set_index].ams_verify_done = Some(reason.to_string());
        state.state_reason = Some(reason.to_string());
        return Err(ArcError::MissingTag(reason.to_string()));
    }
    if ams.domain.is_empty() {
        let reason = "required tag missing: d";
        state.ctx.arcset_chain[set_index].ams_verify_done = Some(reason.to_string());
        state.state_reason = Some(reason.to_string());
        return Err(ArcError::MissingTag(reason.to_string()));
    }
    if ams.signed_headers.is_empty() {
        let reason = "required tag missing: h";
        state.ctx.arcset_chain[set_index].ams_verify_done = Some(reason.to_string());
        state.state_reason = Some(reason.to_string());
        return Err(ArcError::MissingTag(reason.to_string()));
    }
    if ams.selector.is_empty() {
        let reason = "required tag missing: s";
        state.ctx.arcset_chain[set_index].ams_verify_done = Some(reason.to_string());
        state.state_reason = Some(reason.to_string());
        return Err(ArcError::MissingTag(reason.to_string()));
    }

    state.ctx.arcset_chain[set_index].ams_verify_done = Some("in-progress".to_string());

    debug!(
        "ARC i={} AMS verify — domain={}, selector={}",
        ams.instance, ams.domain, ams.selector
    );

    // Compute the raw canonicalized data bytes for verification.
    let verify_data = arc_get_verify_data(&mut state.headers_rlist, &ams);
    if verify_data.is_empty() {
        let reason = "AMS header data computation failed";
        state.ctx.arcset_chain[set_index].ams_verify_done = Some(reason.to_string());
        state.state_reason = Some(reason.to_string());
        return Err(ArcError::VerificationError(reason.to_string()));
    }

    // When no DNS resolver is supplied (test-only path), skip the
    // cryptographic step and leave the entry marked as unverified.
    // This keeps legacy no-DNS tests compilable without asserting a
    // false "pass" state.
    let resolver = match dns {
        Some(r) => r,
        Option::None => {
            debug!(
                "ARC i={} AMS verify: no DNS resolver — skipping signature check",
                ams.instance
            );
            state.ctx.arcset_chain[set_index].ams_verify_done = Some("no dns".to_string());
            state.state_reason = Some("no dns resolver available".to_string());
            return Err(ArcError::VerificationError("no dns resolver".to_string()));
        }
    };

    // Decode the base64-encoded signature into raw bytes for verify().
    let signature = match decode_base64(&String::from_utf8_lossy(&ams.signature)) {
        Some(bytes) => bytes,
        Option::None => {
            // Signature is already stored as raw bytes by the parser, so
            // this fallback path is just defensive; try raw directly.
            ams.signature.clone()
        }
    };
    let sig_bytes = if signature.is_empty() {
        ams.signature.clone()
    } else {
        signature
    };

    // Fetch the DKIM public key from DNS. The DKIM _domainkey namespace
    // is shared between DKIM and ARC per RFC 8617 §4.1.3.
    let dnsname = format!("{}._domainkey.{}", ams.selector, ams.domain);
    let (pubkey_bytes, _dns_hashes) = match super::dkim::parse_dns_pubkey(&dnsname, resolver) {
        Ok(tup) => tup,
        Err(e) => {
            let reason = format!("DNS pubkey fetch failed for {}: {}", dnsname, e);
            state.ctx.arcset_chain[set_index].ams_verify_done = Some(reason.clone());
            state.state_reason = Some(reason.clone());
            return Err(ArcError::VerificationError(reason));
        }
    };

    // Map algorithm strings to the signing-module enums.
    let (key_type, hash_algo) = match arc_algo_components(&ams.algorithm_key, &ams.algorithm_hash) {
        Some(tup) => tup,
        Option::None => {
            let reason = format!(
                "unsupported algorithm: {}-{}",
                ams.algorithm_key, ams.algorithm_hash
            );
            state.ctx.arcset_chain[set_index].ams_verify_done = Some(reason.clone());
            state.state_reason = Some(reason.clone());
            return Err(ArcError::VerificationError(reason));
        }
    };

    // Ed25519 public keys in DNS are raw 32-byte values; RSA keys are
    // DER-encoded `SubjectPublicKeyInfo` per RFC 6376.
    let key_format = match key_type {
        KeyType::Ed25519 => KeyFormat::Ed25519Bare,
        KeyType::Rsa => KeyFormat::Der,
    };

    // Initialize verification context, feed raw data, and verify. The
    // RustCrypto backend hashes the data internally; we pass the raw
    // canonicalized bytes (NOT a pre-computed digest).
    let (mut vctx, _key_bits) = match signing::verify_init(&pubkey_bytes, key_type, key_format) {
        Ok(tup) => tup,
        Err(e) => {
            let reason = format!("verify_init failed: {}", e);
            state.ctx.arcset_chain[set_index].ams_verify_done = Some(reason.clone());
            state.state_reason = Some(reason.clone());
            return Err(ArcError::VerificationError(reason));
        }
    };
    vctx.data_append(&verify_data);

    let verified = match signing::verify(&mut vctx, &sig_bytes, hash_algo) {
        Ok(b) => b,
        Err(e) => {
            let reason = format!("verify failed: {}", e);
            state.ctx.arcset_chain[set_index].ams_verify_done = Some(reason.clone());
            state.state_reason = Some(reason.clone());
            return Err(ArcError::VerificationError(reason));
        }
    };

    if verified {
        debug!("ARC i={} AMS verify pass (crypto)", ams.instance);
        state.ctx.arcset_chain[set_index].ams_verify_passed = true;
        state.ctx.arcset_chain[set_index].ams_verify_done = Some("pass".to_string());
        Ok(())
    } else {
        let reason = "AMS signature mismatch";
        debug!(
            "ARC i={} AMS verify fail (signature mismatch)",
            ams.instance
        );
        state.ctx.arcset_chain[set_index].ams_verify_done = Some(reason.to_string());
        state.state_reason = Some(reason.to_string());
        Err(ArcError::VerificationError(reason.to_string()))
    }
}

/// Check chain integrity: sequential instances, all members present, no
/// cv=fail seals. Also verify the latest AMS.
///
/// Replaces C `arc_headers_check()` (arc.c lines 947–1008).
fn arc_headers_check(
    state: &mut ArcVerifyState,
    dns: Option<&DnsResolver>,
) -> Result<(), ArcError> {
    let chain_len = state.ctx.arcset_chain.len();
    if chain_len == 0 {
        return Err(ArcError::ChainValidation("no ARC sets".to_string()));
    }

    let highest_instance = state.ctx.arcset_chain.last().unwrap().instance;
    let mut ams_fail_found = false;

    // Walk from highest to lowest instance
    let mut expected_inst = highest_instance;
    for idx in (0..chain_len).rev() {
        let arc_set = &state.ctx.arcset_chain[idx];

        if arc_set.instance != expected_inst {
            let reason = format!(
                "i={} (sequence; expected {})",
                arc_set.instance, expected_inst
            );
            state.state_reason = Some(reason.clone());
            debug!("ARC chain fail at {}", reason);
            return Err(ArcError::ChainValidation(reason));
        }

        if arc_set.hdr_aar.is_none() || arc_set.hdr_ams.is_none() || arc_set.hdr_as.is_none() {
            let reason = format!("i={} (missing header)", arc_set.instance);
            state.state_reason = Some(reason.clone());
            debug!("ARC chain fail at {}", reason);
            return Err(ArcError::ChainValidation(reason));
        }

        // Check if AS cv=fail
        if let Some(ref hdr_as) = arc_set.hdr_as {
            if hdr_as.chain_validation == ArcCV::Fail {
                let reason = format!("i={} (cv)", arc_set.instance);
                state.state_reason = Some(reason.clone());
                debug!("ARC chain fail at {}", reason);
                return Err(ArcError::ChainValidation(reason));
            }
        }

        // Evaluate AMS verification for oldest-pass tracking
        if !ams_fail_found {
            match arc_ams_verify(state, idx, dns) {
                Ok(()) => {
                    state.oldest_pass = expected_inst;
                }
                Err(_) => {
                    ams_fail_found = true;
                }
            }
        }

        state.state_reason = Option::None;
        expected_inst -= 1;
    }

    // After walking all sets, expected_inst should be 0
    if expected_inst != 0 {
        let reason = format!("(sequence; expected i={})", expected_inst);
        state.state_reason = Some(reason.clone());
        debug!("ARC chain fail {}", reason);
        return Err(ArcError::ChainValidation(reason));
    }

    state.received_instance = highest_instance;

    // Verify the latest AMS if not already done
    let last_idx = chain_len - 1;
    if !state.ctx.arcset_chain[last_idx].ams_verify_passed {
        if let Some(ref done) = state.ctx.arcset_chain[last_idx].ams_verify_done {
            if done != "in-progress" {
                state.state_reason = Some(done.clone());
                return Err(ArcError::VerificationError(done.clone()));
            }
        }
        arc_ams_verify(state, last_idx, dns)?;
    }

    Ok(())
}

/// Verify all ARC-Seal signatures in the chain.
///
/// Replaces C `arc_verify_seals()` (arc.c lines 1150–1162).
fn arc_verify_seals(state: &mut ArcVerifyState, dns: Option<&DnsResolver>) -> Result<(), ArcError> {
    let chain_len = state.ctx.arcset_chain.len();
    if chain_len == 0 {
        return Err(ArcError::ChainValidation("no ARC sets".to_string()));
    }

    // Verify seals from highest to lowest instance
    for idx in (0..chain_len).rev() {
        arc_seal_verify(state, idx, dns)?;
    }

    debug!("ARC: AS vfy overall pass");
    Ok(())
}

/// Build the raw canonicalized byte sequence used as input for ARC-Seal
/// signature verification.
///
/// RFC 8617 §5.1.2 specifies the AS hash input as the concatenation of
/// canonicalized AAR+AMS+AS triples from the earliest instance up to and
/// including the seal being verified. For the seal being verified itself,
/// the `b=` value is stripped and no trailing CRLF is appended; all
/// other headers use their complete form with a trailing CRLF.
///
/// The returned bytes are passed directly to [`signing::verify`], which
/// hashes them internally per the configured hash algorithm.
fn arc_get_seal_verify_data(arcset_chain: &[ArcSet], set_index: usize) -> Vec<u8> {
    let mut data = Vec::new();
    debug!("ARC: AS header data for verification:");

    for chain_idx in 0..=set_index {
        let chain_set = &arcset_chain[chain_idx];

        if let Some(ref aar) = chain_set.hdr_aar {
            let s = relax_header_n(&aar.complete, aar.complete.len(), true);
            debug!("  {}", s.trim_end());
            data.extend_from_slice(s.as_bytes());
        }

        if let Some(ref ams) = chain_set.hdr_ams {
            let s = relax_header_n(&ams.complete, ams.complete.len(), true);
            debug!("  {}", s.trim_end());
            data.extend_from_slice(s.as_bytes());
        }

        if let Some(ref as_hdr) = chain_set.hdr_as {
            let s = if chain_idx == set_index {
                relax_header_n(
                    &as_hdr.raw_sig_no_b_val,
                    as_hdr.raw_sig_no_b_val.len(),
                    false,
                )
            } else {
                relax_header_n(&as_hdr.complete, as_hdr.complete.len(), true)
            };
            debug!("  {}", s.trim_end());
            data.extend_from_slice(s.as_bytes());
        }
    }

    data
}

/// Verify a single ARC-Seal.
///
/// Performs real cryptographic verification: walks the chain to build the
/// seal-hash input, fetches the seal's DKIM public key from DNS using the
/// AS `d=`/`s=` tags, then invokes [`signing::verify`] which hashes the
/// data and checks the public-key signature.
///
/// Replaces C `arc_seal_verify()` (arc.c lines 1012–1147).
///
/// When `dns` is `None`, structural verification (cv= state checks) is
/// performed but the signature check is skipped. This is used only by
/// tests and returns `Err` so the chain is flagged as unverified.
fn arc_seal_verify(
    state: &mut ArcVerifyState,
    set_index: usize,
    dns: Option<&DnsResolver>,
) -> Result<(), ArcError> {
    let arc_set = &state.ctx.arcset_chain[set_index];
    let instance = arc_set.instance;

    let hdr_as = match &arc_set.hdr_as {
        Some(a) => a.clone(),
        Option::None => {
            return Err(ArcError::MissingTag("AS header missing".to_string()));
        }
    };

    debug!("ARC: AS vfy i={}", instance);

    // Step 2: Check cv= validity per RFC 8617 §5.2
    if instance == 1 && hdr_as.chain_validation != ArcCV::None {
        state.state_reason = Some("seal cv state".to_string());
        return Err(ArcError::ChainValidation("seal cv state".to_string()));
    }
    if hdr_as.chain_validation == ArcCV::None && instance != 1 {
        state.state_reason = Some("seal cv state".to_string());
        return Err(ArcError::ChainValidation("seal cv state".to_string()));
    }

    // Step 3: Build canonicalized data bytes for this seal.
    let seal_data = arc_get_seal_verify_data(&state.ctx.arcset_chain, set_index);
    debug!(
        "ARC i={} AS raw seal-data len={}",
        instance,
        seal_data.len()
    );

    // Step 4: Fetch public key if DNS resolver is available.
    let resolver = match dns {
        Some(r) => r,
        Option::None => {
            state.state_reason = Some("no dns resolver available".to_string());
            debug!(
                "ARC i={} AS verify: no DNS resolver — skipping signature check",
                instance
            );
            return Err(ArcError::VerificationError("no dns resolver".to_string()));
        }
    };

    let dnsname = format!("{}._domainkey.{}", hdr_as.selector, hdr_as.domain);
    let (pubkey_bytes, _dns_hashes) = match super::dkim::parse_dns_pubkey(&dnsname, resolver) {
        Ok(tup) => tup,
        Err(e) => {
            let reason = format!("DNS pubkey fetch failed for {}: {}", dnsname, e);
            state.state_reason = Some(reason.clone());
            return Err(ArcError::VerificationError(reason));
        }
    };

    // Step 5: Map algorithm strings to the signing-module enums.
    let (key_type, hash_algo) =
        match arc_algo_components(&hdr_as.algorithm_key, &hdr_as.algorithm_hash) {
            Some(tup) => tup,
            Option::None => {
                let reason = format!(
                    "unsupported seal algorithm: {}-{}",
                    hdr_as.algorithm_key, hdr_as.algorithm_hash
                );
                state.state_reason = Some(reason.clone());
                return Err(ArcError::VerificationError(reason));
            }
        };

    let key_format = match key_type {
        KeyType::Ed25519 => KeyFormat::Ed25519Bare,
        KeyType::Rsa => KeyFormat::Der,
    };

    // Step 6: Decode the base64 signature bytes.
    let signature = match decode_base64(&String::from_utf8_lossy(&hdr_as.signature)) {
        Some(bytes) if !bytes.is_empty() => bytes,
        _ => hdr_as.signature.clone(),
    };
    if signature.is_empty() {
        let reason = format!("AS i={} signature empty", instance);
        state.state_reason = Some(reason.clone());
        return Err(ArcError::VerificationError(reason));
    }

    // Step 7: Run the RustCrypto verify — it hashes seal_data internally.
    let (mut vctx, _key_bits) = match signing::verify_init(&pubkey_bytes, key_type, key_format) {
        Ok(tup) => tup,
        Err(e) => {
            let reason = format!("seal verify_init failed: {}", e);
            state.state_reason = Some(reason.clone());
            return Err(ArcError::VerificationError(reason));
        }
    };
    vctx.data_append(&seal_data);

    let verified = match signing::verify(&mut vctx, &signature, hash_algo) {
        Ok(b) => b,
        Err(e) => {
            let reason = format!("seal verify failed: {}", e);
            state.state_reason = Some(reason.clone());
            return Err(ArcError::VerificationError(reason));
        }
    };

    if verified {
        debug!("ARC: AS vfy i={} pass (crypto)", instance);
        Ok(())
    } else {
        let reason = format!("AS i={} signature mismatch", instance);
        state.state_reason = Some(reason.clone());
        debug!("ARC: AS vfy i={} fail (signature mismatch)", instance);
        Err(ArcError::VerificationError(reason))
    }
}

// ===========================================================================
// Public API — Verification
// ===========================================================================

/// Perform ARC verification on the given message headers.
///
/// This is the main ARC verification entry point, called from the DATA ACL
/// on a `verify = arc` condition.
///
/// Replaces C `acl_verify_arc()` (arc.c lines 1175–1270).
///
/// # Arguments
///
/// * `headers` — All message headers in original order.
/// * `dns` — DNS resolver for public-key lookups, shared via `Rc` so the
///   same resolver can be reused across the entire chain walk without
///   cloning the underlying hickory resolver. Mirrors the D1 pattern from
///   [`crate::dkim::verify_init`].
///
/// # Returns
///
/// * `Ok(ArcState::Pass)` — ARC chain verified successfully (AMS and all
///   seals verified cryptographically).
/// * `Ok(ArcState::None)` — No ARC headers present.
/// * `Ok(ArcState::Fail)` — ARC chain verification failed (structural,
///   crypto, or DNS error).
/// * `Err(ArcError)` — Internal error during parsing before verification.
pub fn arc_verify(headers: &[String], dns: Rc<DnsResolver>) -> Result<ArcState, ArcError> {
    let mut state = ArcVerifyState::default();

    // Step 1: Collect all ARC sets from headers
    let collect_result = arc_vfy_collect_hdrs(&mut state, headers)?;
    if collect_result == ArcState::None {
        debug!("ARC verify result: none");
        return Ok(ArcState::None);
    }
    if collect_result == ArcState::Fail {
        debug!(
            "ARC verify result: fail ({})",
            state.state_reason.as_deref().unwrap_or("")
        );
        return Ok(ArcState::Fail);
    }

    let dns_ref = Some(dns.as_ref());

    // Steps 2-3: Check chain integrity and verify latest AMS
    if let Err(e) = arc_headers_check(&mut state, dns_ref) {
        debug!("ARC verify result: fail ({})", e);
        return Ok(ArcState::Fail);
    }

    // Steps 4-5: Verify all seals
    if let Err(e) = arc_verify_seals(&mut state, dns_ref) {
        debug!("ARC verify result: fail ({})", e);
        return Ok(ArcState::Fail);
    }

    debug!(
        "ARC verify result: pass (oldest_pass={}, received_instance={})",
        state.oldest_pass, state.received_instance
    );
    Ok(ArcState::Pass)
}

/// Internal structural-verification entry point for code paths that parse
/// the ARC chain only for tag inspection (`fn_arc_domains`, `arc_set_info`,
/// `arc_arcset_string`) without needing a DNS resolver.
///
/// Performs only Step 1 of [`arc_verify`] — header parsing — and returns
/// the collected chain along with the parse-level state. No DNS lookups,
/// no cryptographic verification. This is NOT a substitute for
/// [`arc_verify`] in ACL code paths.
fn arc_collect_only(headers: &[String]) -> Result<(ArcState, ArcVerifyState), ArcError> {
    let mut state = ArcVerifyState::default();
    let collect_result = arc_vfy_collect_hdrs(&mut state, headers)?;
    Ok((collect_result, state))
}

/// Feed a header line into ARC processing during message reception.
///
/// Called from the DKIM input processing path to identify ARC-Message-Signature
/// headers and set up body hash computation.
///
/// Replaces C `arc_header_feed()` (arc.c lines 2017–2021).
///
/// # Arguments
///
/// * `header_text` — Complete header line text.
/// * `is_verify` — `true` for verification mode, `false` for signing mode.
pub fn arc_header_feed(header_text: &str, is_verify: bool) -> Result<(), ArcError> {
    if is_verify {
        // In verification mode, check for AMS to request body hash
        let text_lower = header_text.to_ascii_lowercase();
        if text_lower.starts_with("arc-message-signature:") {
            debug!("ARC: spotted AMS header during input");
            // Parse the AMS to discover what body hash we need
            let al = arc_parse_line(header_text, ARC_HDRLEN_AMS, LineExtract::All)?;
            if al.algorithm_hash.is_empty() {
                debug!("ARC: no a_hash from AMS header");
                return Err(ArcError::HeaderParsing(
                    "no algorithm hash in AMS".to_string(),
                ));
            }
            // The body hash will be requested from the DKIM layer
            // in the integrated system
            debug!("ARC: AMS parsed — hash={}", al.algorithm_hash);
        }
    }
    // In signing mode, headers are accumulated through arc_sign's feed path
    Ok(())
}

// ===========================================================================
// Public API — Signing
// ===========================================================================

/// Initialize ARC signing context.
///
/// Creates a signing context with the next instance number based on the
/// existing ARC chain (if any) in the message.
///
/// Replaces C `arc_sign_init()` (arc.c lines 1711–1718).
///
/// # Arguments
///
/// * `options` — Signing configuration (domain, selector, key, timestamps).
/// * `existing_headers` — Existing message headers (to determine instance).
///
/// # Returns
///
/// An [`ArcSigningContext`] ready for use with [`arc_sign`].
pub fn arc_sign_init(
    options: &ArcSignOptions,
    existing_headers: &[String],
) -> Result<ArcSigningContext, ArcError> {
    // Parse existing ARC headers to determine next instance number AND
    // capture the full chain for later AS signing (the seal-signing hdata
    // must include every prior set's AAR+AMS+AS per RFC 8617 §5.1.2).
    let mut ctx = ArcContext::default();
    for header in existing_headers {
        let _ = arc_try_header(&mut ctx, header, true);
    }

    let instance = ctx.last_set().map(|s| s.instance + 1).unwrap_or(1);
    // Snapshot the chain: arc_sign() needs to walk it when accumulating
    // the AS signing data, so we move ownership here once and avoid
    // re-parsing on every sign call.
    let existing_sets = ctx.arcset_chain;

    debug!("ARC: sign_init — new instance {}", instance);

    // Build reverse-order header list
    let headers_rlist: Vec<HeaderEntry> = existing_headers
        .iter()
        .rev()
        .map(|h| HeaderEntry {
            used: false,
            text: h.clone(),
            len: h.len(),
        })
        .collect();

    Ok(ArcSigningContext {
        instance,
        options: options.clone(),
        bodyhash: Vec::new(), // Will be populated by DKIM body hash
        headers_rlist,
        existing_sets,
    })
}

/// Fold a base64-encoded signature over 74-character lines with
/// `"\r\n\t  "` (CRLF + TAB + two spaces) as the inter-line separator.
///
/// This mirrors the C folding loop in `arc_sign_append_sig()` (arc.c
/// lines 1453–1471) exactly: take up to 74 characters, advance the
/// pointer, emit a continuation whitespace run, repeat until the
/// signature is exhausted.  The first line starts flush (no leading
/// whitespace); subsequent continuation lines are indented with
/// `TAB + two spaces`, matching the column-4 wrap preferred by Exim's
/// historical DKIM/ARC output.
fn arc_fold_signature(sig_b64: &str) -> String {
    let bytes = sig_b64.as_bytes();
    // Pre-size: sig length plus one 5-byte continuation per full line.
    let continuations = bytes.len().saturating_sub(1) / 74;
    let mut out = String::with_capacity(bytes.len() + continuations * 5);
    let mut pos = 0usize;
    while pos < bytes.len() {
        let take = (bytes.len() - pos).min(74);
        // Each chunk is guaranteed ASCII (base64 alphabet), so UTF-8 slicing is safe.
        // Nonetheless, validate conservatively to avoid panics on unexpected input.
        match std::str::from_utf8(&bytes[pos..pos + take]) {
            Ok(chunk) => out.push_str(chunk),
            Err(_) => {
                // Fallback: lossily push as bytes via char casts (all base64 = ASCII).
                for &b in &bytes[pos..pos + take] {
                    out.push(b as char);
                }
            }
        }
        pos += take;
        if pos < bytes.len() {
            out.push_str("\r\n\t  ");
        }
    }
    out
}

/// Sign a raw byte slice using the configured private key, returning the
/// raw signature bytes (not base64-encoded).
///
/// The helper wraps the three-step RustCrypto pipeline used everywhere
/// else in this crate:
///
/// 1. `signing::signing_init(private_key, key_type, hash)` — imports the
///    PEM, detects the actual key type, and prepares a `SigningContext`.
/// 2. `sctx.data_append(hdata)` — streams the canonicalized header bytes
///    into the context's buffer.  Unlike the C GnuTLS path, the Rust
///    backend hashes *internally* from raw data (not from a
///    pre-computed digest), so we must pass the RAW bytes here.
/// 3. `signing::sign(&mut sctx)` — produces the raw signature, e.g.
///    PKCS#1 v1.5 DigestInfo-wrapped for RSA-SHA256 or a fixed 64-byte
///    Ed25519 signature.
///
/// The key type is requested as `Rsa` by default; `signing_init()`
/// detects the actual type from the PEM headers/length (see
/// `detect_key_type_from_pem` in `signing.rs`) and overrides as needed,
/// so Ed25519 ARC keys work without any caller-side handling.
fn arc_sign_bytes(private_key: &str, hdata: &[u8]) -> Result<Vec<u8>, ArcError> {
    let mut sctx = signing::signing_init(private_key, KeyType::Rsa, HashAlgorithm::Sha256)?;
    sctx.data_append(hdata);
    let sig = signing::sign(&mut sctx)?;
    Ok(sig)
}

/// Perform ARC signing, producing the three ARC headers for a new ARC set.
///
/// Creates ARC-Authentication-Results, ARC-Message-Signature, and ARC-Seal
/// headers with incremented instance number.  The AMS and AS headers are
/// cryptographically signed via RSA-SHA256 (or Ed25519 if the supplied
/// PEM is an Ed25519 key — detected automatically by `signing_init()`).
///
/// Replaces C `arc_sign()` / `arc_sign_append_ams()` /
/// `arc_sign_prepend_as()` / `arc_sign_append_sig()`
/// (arc.c lines 1453–1780).
///
/// # Algorithm (matching C, RFC 8617)
///
/// ## ARC-Message-Signature (AMS)
///
/// The AMS hashes (1) the relaxed-canonicalized signed headers, in the
/// reverse order they appear in the `h=` tag, *followed by* (2) the
/// relaxed-canonicalized AMS header itself with `b=` value empty.
///
/// ## ARC-Seal (AS)
///
/// The AS hashes the relaxed-canonicalized concatenation of every ARC
/// set's `AAR`, `AMS`, and `AS` headers, walking the chain in
/// instance-ascending order.  The final AS (the one being signed) has an
/// empty `b=;` value and is appended *without* a trailing CRLF, while
/// all other headers in the accumulator are appended *with* CRLF.
///
/// Per RFC 8617 §5.1.2, when the chain validity status is `fail`, the AS
/// signing accumulator only contains the new (failing) set — prior sets
/// are excluded.  For `pass` and `none` states, the entire chain is
/// hashed.
///
/// # Arguments
///
/// * `signing_ctx` — Context from [`arc_sign_init`], populated with
///   body hash, header list, and existing chain.
/// * `auth_results` — Authentication-Results content for the AAR header;
///   also supplies the `arc=…` fragment used to derive the `cv=` status.
/// * `sender_ip` — Sender's IP address for the AAR `smtp.remote-ip` field.
///
/// # Returns
///
/// A vector of new header strings `[AAR, AMS, AS]` to prepend to the
/// message.  Each element ends with `\r\n`.
pub fn arc_sign(
    signing_ctx: &ArcSigningContext,
    auth_results: &str,
    sender_ip: &str,
) -> Result<Vec<String>, ArcError> {
    let instance = signing_ctx.instance;
    let options = &signing_ctx.options;

    // -----------------------------------------------------------------
    // Input validation — reject malformed specs before doing crypto work
    // -----------------------------------------------------------------
    if options.domain.is_empty() {
        return Err(ArcError::BadSignSpec("identity empty".to_string()));
    }
    if options.selector.is_empty() {
        return Err(ArcError::BadSignSpec("selector empty".to_string()));
    }
    if options.private_key.is_empty() {
        return Err(ArcError::BadSignSpec("privkey empty".to_string()));
    }
    if !arc_valid_id(&options.domain) {
        return Err(ArcError::BadSignSpec("identity chars".to_string()));
    }
    if !arc_valid_id(&options.selector) {
        return Err(ArcError::BadSignSpec("selector chars".to_string()));
    }

    debug!("ARC: sign for {} (instance {})", options.domain, instance);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // -----------------------------------------------------------------
    // 1. Build the AAR (ARC-Authentication-Results) header — unsigned.
    //
    //    The AAR carries the prior verifier's results and is not
    //    cryptographically protected by itself (the AS signs all the
    //    AARs in the chain collectively).  We build it first because
    //    the AS signing accumulator will need its canonicalized form.
    // -----------------------------------------------------------------
    let mut aar_complete = format!(
        "{} i={}; {}; smtp.remote-ip={};\r\n\t{}",
        ARC_HDR_AAR, instance, options.domain, sender_ip, auth_results
    );
    if !aar_complete.ends_with("\r\n") {
        aar_complete.push_str("\r\n");
    }
    debug!("ARC: AAR '{}'", aar_complete.trim_end());

    // -----------------------------------------------------------------
    // 2. Build the AMS (ARC-Message-Signature) and sign it.
    //
    //    Algorithm (see RFC 8617 §5.1.1 and C `arc_sign_append_ams`):
    //      a. Format AMS header prefix up through "h=".
    //      b. Walk `headers_rlist` (already reversed — most recent first).
    //         For each header whose name matches one in the signing set,
    //         (i) append the case-preserved name + ':' to the `h=` tag,
    //         (ii) append the relaxed-canonicalized header *with* CRLF
    //              to the `hdata` signing accumulator.
    //      c. Trim trailing ':' from `h=`, append `; b=;\r\n`.
    //      d. Relax-canonicalize the AMS pseudo-header itself *without*
    //         CRLF and append to `hdata` — this is what makes the AMS
    //         self-covering (its own `b=` empty value is in the hash).
    //      e. Hand `hdata` to RustCrypto `signing::sign()`, base64 the
    //         result, fold over 74-char lines, splice into the `b=`.
    // -----------------------------------------------------------------
    let mut ams_pre = format!(
        "{} i={}; a=rsa-sha256; c=relaxed; d={}; s={}",
        ARC_HDR_AMS, instance, options.domain, options.selector
    );
    if options.include_timestamp {
        ams_pre.push_str(&format!("; t={}", now));
    }
    if options.include_expiry {
        let expire = if options.expire_delta > 0 {
            now + options.expire_delta
        } else {
            now + ARC_DEFAULT_EXPIRE_DELTA
        };
        ams_pre.push_str(&format!("; x={}", expire));
    }

    let bh_b64 = encode_base64(&signing_ctx.bodyhash);
    ams_pre.push_str(&format!(";\r\n\tbh={};\r\n\th=", bh_b64));

    // Standard DKIM-like signing header set, plus DKIM-Signature itself
    // (so a DKIM signature added in the same message is also ARC-protected).
    let sign_headers_list = format!("DKIM-Signature:{}", PDKIM_DEFAULT_SIGN_HEADERS);
    let header_names: Vec<&str> = sign_headers_list.split(':').collect();

    // Accumulator for cryptographic signing.  Holds raw canonicalized
    // bytes; RustCrypto will hash this internally inside `sign()`.
    let mut ams_hdata: Vec<u8> = Vec::new();
    let mut matched_any = false;

    for entry in &signing_ctx.headers_rlist {
        for name in &header_names {
            let nlen = name.len();
            if entry.text.len() > nlen
                && entry
                    .text
                    .get(..nlen)
                    .is_some_and(|p| p.eq_ignore_ascii_case(name))
                && entry.text.as_bytes().get(nlen) == Some(&b':')
            {
                // (i) Append header name + ':' to `h=` tag.
                //     Note: matches the C behaviour of emitting each
                //     matching occurrence (duplicates included), so a
                //     verifier can replay exactly the same header stream.
                ams_pre.push_str(name);
                ams_pre.push(':');
                // (ii) Canonicalize the *actual* header text and
                //      accumulate into the signing buffer with CRLF.
                let relaxed = relax_header_n(&entry.text, entry.len, true);
                ams_hdata.extend_from_slice(relaxed.as_bytes());
                matched_any = true;
                break;
            }
        }
    }

    // Trim trailing ':' left over from the last appended name, then close.
    if matched_any && ams_pre.ends_with(':') {
        ams_pre.pop();
    }
    ams_pre.push_str(";\r\n\tb=;\r\n");

    debug!("ARC: AMS (pre-sign) '{}'", ams_pre.trim_end());

    // Canonicalize the AMS pseudo-header itself *without* a trailing
    // CRLF (parameter `false`) — this is the RFC 6376 §3.5 "b= stripped"
    // inclusion rule applied to ARC per RFC 8617 §5.1.1.
    let ams_pseudo_relaxed = relax_header_n(&ams_pre, ams_pre.len(), false);
    ams_hdata.extend_from_slice(ams_pseudo_relaxed.as_bytes());

    // Sign → base64 → fold → splice into `b=` placeholder.
    let ams_sig_bytes = arc_sign_bytes(&options.private_key, &ams_hdata)?;
    let ams_sig_b64 = encode_base64(&ams_sig_bytes);
    let ams_sig_folded = arc_fold_signature(&ams_sig_b64);

    let ams_complete = splice_signature(&ams_pre, ";\r\n\tb=;\r\n", &ams_sig_folded, ";\r\n\tb=")?;

    debug!("ARC: AMS (signed) '{}'", ams_complete.trim_end());

    // -----------------------------------------------------------------
    // 3. Build the AS (ARC-Seal) and sign it.
    //
    //    Algorithm (RFC 8617 §5.1.2, mirroring C `arc_sign_prepend_as`):
    //      a. Derive `cv=` status from the auth_results fragment.
    //         "fail" → seal only the new (failing) set;
    //         "pass"/"none" → seal the entire chain plus new set.
    //      b. Format the AS header with `b=;` empty.
    //      c. Walk the sets in ascending instance order.  For each set,
    //         append canonicalized `AAR`, `AMS`, `AS` to `as_hdata` —
    //         always with CRLF, EXCEPT the very last AS (the one being
    //         signed right now), which has no trailing CRLF.
    //      d. Sign the accumulator, base64-fold, splice into `b=`.
    // -----------------------------------------------------------------
    let cv_status = arc_ar_cv_status(auth_results);
    let mut as_pre = format!(
        "{} i={}; cv={}; a=rsa-sha256; d={}; s={}",
        ARC_HDR_AS, instance, cv_status, options.domain, options.selector
    );
    if options.include_timestamp {
        as_pre.push_str(&format!("; t={}", now));
    }
    as_pre.push_str(";\r\n\t b=;\r\n");

    debug!("ARC: AS (pre-sign) '{}'", as_pre.trim_end());

    // Build the AS signing accumulator.  For every set, we need the
    // relaxed-canonicalized AAR, AMS, and AS.  For existing sets
    // (parsed out of the inbound headers), all three have real values.
    // For the new set we inject here, the AS is the pseudo-header with
    // empty `b=` and is appended without a trailing CRLF.
    let seal_all_sets = cv_status != "fail";
    let mut as_hdata: Vec<u8> = Vec::new();

    if seal_all_sets {
        for set in &signing_ctx.existing_sets {
            if let Some(aar) = &set.hdr_aar {
                let relaxed = relax_header_n(&aar.complete, aar.complete.len(), true);
                as_hdata.extend_from_slice(relaxed.as_bytes());
            }
            if let Some(ams) = &set.hdr_ams {
                let relaxed = relax_header_n(&ams.complete, ams.complete.len(), true);
                as_hdata.extend_from_slice(relaxed.as_bytes());
            }
            if let Some(as_line) = &set.hdr_as {
                // Prior sets' AS headers are *complete* (have real
                // signatures), and since they are never the final item
                // in the accumulator they are appended with CRLF.
                let relaxed = relax_header_n(&as_line.complete, as_line.complete.len(), true);
                as_hdata.extend_from_slice(relaxed.as_bytes());
            }
        }
    }
    // Now append the new (current) set — always, regardless of
    // seal_all_sets: even the "fail" path still includes the new set
    // (it is the *only* thing sealed in that path).
    let aar_relaxed = relax_header_n(&aar_complete, aar_complete.len(), true);
    as_hdata.extend_from_slice(aar_relaxed.as_bytes());
    let ams_relaxed_for_as = relax_header_n(&ams_complete, ams_complete.len(), true);
    as_hdata.extend_from_slice(ams_relaxed_for_as.as_bytes());
    // The new AS pseudo-header is the LAST item, so no CRLF.
    let as_pre_relaxed = relax_header_n(&as_pre, as_pre.len(), false);
    as_hdata.extend_from_slice(as_pre_relaxed.as_bytes());

    // Sign → base64 → fold → splice.  Note the `b=` placeholder is
    // `";\r\n\t b=;\r\n"` (space after tab) matching the C code's
    // historical AS layout — distinct from AMS's `";\r\n\tb=;\r\n"`.
    let as_sig_bytes = arc_sign_bytes(&options.private_key, &as_hdata)?;
    let as_sig_b64 = encode_base64(&as_sig_bytes);
    let as_sig_folded = arc_fold_signature(&as_sig_b64);

    let as_complete = splice_signature(&as_pre, ";\r\n\t b=;\r\n", &as_sig_folded, ";\r\n\t b=")?;

    debug!("ARC: AS (signed) '{}'", as_complete.trim_end());

    Ok(vec![aar_complete, ams_complete, as_complete])
}

/// Splice a folded base64 signature into a pre-sign header that contains
/// an empty `b=;` placeholder.
///
/// The caller supplies (1) the pre-sign header text with the `b=;`
/// still empty, (2) the exact placeholder sequence to locate (this
/// differs between AMS `";\r\n\tb=;\r\n"` and AS `";\r\n\t b=;\r\n"`),
/// (3) the folded base64 signature payload, and (4) the `b=` prefix
/// with whitespace context matching the placeholder, used to build the
/// replacement.
///
/// Returns an error if the placeholder cannot be located — this should
/// never occur because we construct the pre-sign header immediately
/// before calling this function, but a defensive check prevents silent
/// corruption if a future refactor changes the layout.
fn splice_signature(
    pre_sign: &str,
    placeholder: &str,
    folded_sig: &str,
    b_prefix: &str,
) -> Result<String, ArcError> {
    let pos = pre_sign.rfind(placeholder).ok_or_else(|| {
        ArcError::BadSignSpec(
            "internal error: b=; placeholder not found in pre-sign header".to_string(),
        )
    })?;
    let mut out = String::with_capacity(pre_sign.len() + folded_sig.len() + 8);
    out.push_str(&pre_sign[..pos]);
    out.push_str(b_prefix);
    out.push_str(folded_sig);
    out.push_str(";\r\n");
    Ok(out)
}

/// Validate an ADMD identity or selector string.
///
/// Per RFCs 6376, 7489 the only allowed chars are ALPHA/DIGIT/'-'/'.'.
///
/// Replaces C `arc_valid_id()` (arc.c lines 1751–1757).
fn arc_valid_id(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}

/// Extract the arc= result from an Authentication-Results blob.
///
/// Replaces C `arc_ar_cv_status()` (arc.c lines 1577–1593).
fn arc_ar_cv_status(ar: &str) -> &str {
    for part in ar.split(';') {
        let trimmed = part.trim();
        if let Some(rest) = trimmed.strip_prefix("arc=") {
            let end = rest.find([';', ' ', '\r', '\n']).unwrap_or(rest.len());
            let status = rest[..end].trim();
            if !status.is_empty() {
                // Return a static str for known values
                return match status {
                    "pass" => "pass",
                    "fail" => "fail",
                    _ => "none",
                };
            }
        }
    }
    "none"
}

// ===========================================================================
// Public API — Query and state functions
// ===========================================================================

/// Query ARC set information for expansion variables.
///
/// Parses ARC headers in the given message without performing any DNS
/// lookups or cryptographic verification — used by expansion variables
/// and the DMARC history writer which need only structural information.
///
/// Replaces C `arc_arcset_string()` (arc.c lines 2102–2134).
///
/// Returns the ARC state string and set info for DMARC history.
pub fn arc_set_info(headers: &[String]) -> Result<(ArcState, Vec<ArcSet>), ArcError> {
    let (collect_result, state) = arc_collect_only(headers)?;
    if collect_result == ArcState::None {
        return Ok((ArcState::None, Vec::new()));
    }

    Ok((collect_result, state.ctx.arcset_chain))
}

/// Generate Authentication-Results header portion for ARC.
///
/// Performs a full ARC verification (including DNS-backed signature
/// checks) and returns the `arc=pass|fail|none|temperror` fragment to
/// be included in the Authentication-Results header.
///
/// Replaces C `authres_arc()` (arc.c lines 2060–2090).
///
/// # Arguments
///
/// * `headers` — Message headers for ARC verification.
/// * `dns` — DNS resolver for public-key lookups, shared via `Rc`.
///
/// # Returns
///
/// Authentication-Results fragment string for ARC, or empty if no ARC state.
pub fn authres_arc(headers: &[String], dns: Rc<DnsResolver>) -> String {
    match arc_verify(headers, dns) {
        Ok(ArcState::Pass) => {
            let result = ";\n\tarc=pass".to_string();
            debug!("ARC:\tauthres '{}'", result.trim());
            result
        }
        Ok(ArcState::Fail) => {
            let result = ";\n\tarc=fail".to_string();
            debug!("ARC:\tauthres '{}'", result.trim());
            result
        }
        Ok(ArcState::None) => {
            let result = ";\n\tarc=none".to_string();
            debug!("ARC:\tauthres '{}'", result.trim());
            result
        }
        Err(e) => {
            debug!("ARC:\tauthres error: {}", e);
            format!(";\n\tarc=temperror ({})", e)
        }
    }
}

/// Construct the list of domains from the ARC chain.
///
/// Parses ARC headers for structural information only — no DNS or crypto.
///
/// Replaces C `fn_arc_domains()` (arc.c lines 2029–2055).
///
/// Returns a colon-separated list of domains from ARC-Seal headers.
pub fn fn_arc_domains(headers: &[String]) -> String {
    let (_state, sets) = match arc_set_info(headers) {
        Ok(r) => r,
        Err(_) => return String::new(),
    };

    if sets.is_empty() {
        return String::new();
    }

    let mut result = String::new();
    let mut expected_inst: u32 = 1;

    for arc_set in &sets {
        // Fill gaps with empty colons
        while expected_inst < arc_set.instance {
            if !result.is_empty() {
                result.push(':');
            }
            expected_inst += 1;
        }

        if !result.is_empty() {
            result.push(':');
        }

        if let Some(ref hdr_as) = arc_set.hdr_as {
            if !hdr_as.domain.is_empty() {
                result.push_str(&hdr_as.domain);
            }
        }

        expected_inst = arc_set.instance + 1;
    }

    result
}

/// Check whether the ARC state is "pass".
///
/// Performs a full ARC verification (including DNS-backed signature
/// checks) and returns `true` only if the chain verifies successfully.
///
/// Replaces C `arc_is_pass()` (arc.c lines 1272–1276).
pub fn arc_is_pass(headers: &[String], dns: Rc<DnsResolver>) -> bool {
    matches!(arc_verify(headers, dns), Ok(ArcState::Pass))
}

/// Construct ARC set information string for DMARC history.
///
/// Replaces C `arc_arcset_string()` (arc.c lines 2102–2134).
///
/// Returns a JSON-like structured string with ARC set details. This is
/// a structural-only traversal — it does not perform cryptographic
/// verification and never queries DNS.
pub fn arc_arcset_string(headers: &[String]) -> Option<String> {
    let (state, sets) = arc_set_info(headers).ok()?;

    if state == ArcState::None {
        return Option::None;
    }

    let mut parts: Vec<String> = Vec::new();

    for arc_set in &sets {
        if let Some(ref hdr_as) = arc_set.hdr_as {
            let mut entry = format!(
                " (\"i\":{}, \"d\":\"{}\" , \"s\":\"{}\"",
                arc_set.instance, hdr_as.domain, hdr_as.selector
            );

            if let Some(ref hdr_aar) = arc_set.hdr_aar {
                if let Some(ref ip) = hdr_aar.ip_address {
                    entry.push_str(&format!(", \"ip\":\"{}\"", ip));
                }
            }

            entry.push(')');
            parts.push(entry);
        }
    }

    if parts.is_empty() {
        return Option::None;
    }

    Some(parts.join(","))
}

// ===========================================================================
// Module lifecycle
// ===========================================================================

/// Initialize the ARC module.
///
/// Verifies that the DKIM module is available (required dependency).
///
/// Replaces C `arc_init()` (arc.c lines 146–154).
pub fn arc_init() -> bool {
    info!("ARC: module initializing");
    // In the integrated system, this verifies the DKIM module is loaded.
    // Since Rust enforces this at compile time through the `arc = ["dkim"]`
    // feature dependency, initialization always succeeds.
    true
}

/// Reset ARC state between SMTP transactions.
///
/// Replaces C `arc_smtp_reset()` (arc.c lines 156–161).
pub fn arc_smtp_reset() {
    debug!("ARC: smtp_reset");
    // In the Rust architecture, state is scoped per-message and dropped
    // automatically. This function exists for API compatibility with the
    // C module registration pattern.
}

// ===========================================================================
// Module Registration
// ===========================================================================

/// ARC module registration information.
///
/// Replaces C `arc_module_info` struct (arc.c lines 2159–2174).
///
/// Registered via `inventory::submit!` for compile-time collection by the
/// driver registry. The module provides:
/// - 6 API function slots (verify, header_feed, is_pass, sign_init, sign,
///   arcset_info)
/// - 4 expansion variables (arc_domains, arc_oldest_pass, arc_state,
///   arc_state_reason)
pub struct ArcModuleInfo {
    /// Module name identifier.
    pub name: &'static str,
}

inventory::collect!(ArcModuleInfo);

inventory::submit! {
    ArcModuleInfo {
        name: "arc",
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arc_cv_from_str() {
        assert_eq!(ArcCV::from_str("none"), Some(ArcCV::None));
        assert_eq!(ArcCV::from_str("pass"), Some(ArcCV::Pass));
        assert_eq!(ArcCV::from_str("fail"), Some(ArcCV::Fail));
        assert_eq!(ArcCV::from_str("PASS"), Some(ArcCV::Pass));
        assert_eq!(ArcCV::from_str("invalid"), Option::None);
    }

    #[test]
    fn test_arc_state_display() {
        assert_eq!(ArcState::None.to_string(), "none");
        assert_eq!(ArcState::Pass.to_string(), "pass");
        assert_eq!(ArcState::Fail.to_string(), "fail");
    }

    #[test]
    fn test_arc_cv_display() {
        assert_eq!(ArcCV::None.to_string(), "none");
        assert_eq!(ArcCV::Pass.to_string(), "pass");
        assert_eq!(ArcCV::Fail.to_string(), "fail");
    }

    #[test]
    fn test_arc_valid_id() {
        assert!(arc_valid_id("example.com"));
        assert!(arc_valid_id("arc-20240101"));
        assert!(arc_valid_id("test123"));
        assert!(!arc_valid_id("bad id"));
        assert!(!arc_valid_id("bad@id"));
        assert!(!arc_valid_id("bad/id"));
    }

    #[test]
    fn test_arc_ar_cv_status() {
        assert_eq!(arc_ar_cv_status("arc=pass"), "pass");
        assert_eq!(arc_ar_cv_status("arc=fail"), "fail");
        assert_eq!(arc_ar_cv_status("dkim=pass; arc=pass"), "pass");
        assert_eq!(arc_ar_cv_status("dkim=pass"), "none");
    }

    #[test]
    fn test_skip_fws() {
        assert_eq!(skip_fws("  hello"), "hello");
        assert_eq!(skip_fws("\t\nhello"), "hello");
        assert_eq!(skip_fws("hello"), "hello");
        assert_eq!(skip_fws(""), "");
    }

    #[test]
    fn test_arc_verify_no_headers() {
        // When no ARC headers are present, the verify path returns
        // `ArcState::None` before touching DNS or crypto — but the
        // public API still requires a `Rc<DnsResolver>` for type safety.
        // `from_system()` is cheap (no network I/O until queried) and
        // succeeds in every environment where `/etc/resolv.conf` exists.
        let headers: Vec<String> = vec![
            "From: sender@example.com\r\n".to_string(),
            "To: recipient@example.com\r\n".to_string(),
        ];
        let dns = match DnsResolver::from_system() {
            Ok(r) => Rc::new(r),
            Err(_) => {
                // Environments without `/etc/resolv.conf` (e.g. some
                // containerized CI runners) cannot construct a system
                // resolver; skip silently — the early-return path does
                // not actually use DNS, but we cannot even build one.
                eprintln!("test_arc_verify_no_headers: /etc/resolv.conf unavailable; skipping");
                return;
            }
        };
        let result = arc_verify(&headers, dns);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ArcState::None);
    }

    #[test]
    fn test_arc_sign_options_default() {
        let opts = ArcSignOptions::default();
        assert!(!opts.include_timestamp);
        assert!(!opts.include_expiry);
        assert_eq!(opts.expire_delta, ARC_DEFAULT_EXPIRE_DELTA);
    }

    #[test]
    fn test_arc_sign_init_no_existing() {
        let opts = ArcSignOptions {
            domain: "example.com".to_string(),
            selector: "arc1".to_string(),
            private_key: "test-key".to_string(),
            ..Default::default()
        };
        let headers: Vec<String> = vec!["From: sender@example.com\r\n".to_string()];
        let ctx = arc_sign_init(&opts, &headers).unwrap();
        assert_eq!(ctx.instance, 1);
    }

    #[test]
    fn test_arc_sign_bad_spec() {
        // Build a signing context with an empty domain — the spec
        // validation at the top of `arc_sign()` must reject this
        // before any crypto work is attempted.  The `existing_sets`
        // field is required by the struct layout introduced for real
        // AS chain accumulation; it is safely empty here because the
        // test exits before the chain is consulted.
        let signing_ctx = ArcSigningContext {
            instance: 1,
            options: ArcSignOptions::default(), // empty domain
            bodyhash: Vec::new(),
            headers_rlist: Vec::new(),
            existing_sets: Vec::new(),
        };
        let result = arc_sign(&signing_ctx, "dkim=pass", "127.0.0.1");
        assert!(result.is_err());
    }

    #[test]
    fn test_arc_default_expire_delta() {
        // 30 days in seconds
        assert_eq!(ARC_DEFAULT_EXPIRE_DELTA, 2_592_000);
    }

    #[test]
    fn test_arc_header_feed_non_ams() {
        let result = arc_header_feed("From: test@example.com\r\n", true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_arc_is_pass_no_headers() {
        // Same rationale as `test_arc_verify_no_headers`: we can't
        // actually reach the crypto path because there are no ARC
        // headers to verify, but the API still takes a DnsResolver.
        let headers: Vec<String> = vec!["From: test@example.com\r\n".to_string()];
        let dns = match DnsResolver::from_system() {
            Ok(r) => Rc::new(r),
            Err(_) => {
                eprintln!("test_arc_is_pass_no_headers: /etc/resolv.conf unavailable; skipping");
                return;
            }
        };
        assert!(!arc_is_pass(&headers, dns));
    }

    #[test]
    fn test_arc_init_returns_true() {
        assert!(arc_init());
    }

    #[test]
    fn test_fn_arc_domains_empty() {
        let headers: Vec<String> = vec!["From: test@example.com\r\n".to_string()];
        assert_eq!(fn_arc_domains(&headers), "");
    }

    #[test]
    fn test_arc_error_display() {
        let err = ArcError::VerificationError("test error".to_string());
        assert!(err.to_string().contains("test error"));

        let err = ArcError::MissingTag("b".to_string());
        assert!(err.to_string().contains("b"));
    }

    #[test]
    fn test_build_raw_sig_no_b_val() {
        let header = "ARC-Message-Signature: i=1; a=rsa-sha256; b=abc123; d=example.com";
        let result = build_raw_sig_no_b_val(header, ARC_HDRLEN_AMS);
        // b= value should be stripped
        assert!(result.contains("b="));
        assert!(!result.contains("abc123"));
    }

    #[test]
    fn test_arc_parse_line_ams() {
        let header = "ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=sel1; h=from:to; b=dGVzdA==; bh=dGVzdA==\r\n";
        let al = arc_parse_line(header, ARC_HDRLEN_AMS, LineExtract::All).unwrap();
        assert_eq!(al.instance, 1);
        assert_eq!(al.algorithm, "rsa-sha256");
        assert_eq!(al.algorithm_key, "rsa");
        assert_eq!(al.algorithm_hash, "sha256");
        assert_eq!(al.domain, "example.com");
        assert_eq!(al.selector, "sel1");
    }

    #[test]
    fn test_arc_parse_line_instance_only() {
        let header = "ARC-Seal: i=3; cv=pass; a=rsa-sha256; d=example.com; s=sel1; b=sig\r\n";
        let al = arc_parse_line(header, ARC_HDRLEN_AS, LineExtract::InstanceOnly).unwrap();
        assert_eq!(al.instance, 3);
        // Other fields should be default since we only extracted instance
        assert!(al.domain.is_empty());
    }

    #[test]
    fn test_arc_context_find_or_create() {
        let mut ctx = ArcContext::default();
        ctx.find_or_create_set(2);
        ctx.find_or_create_set(1);
        ctx.find_or_create_set(3);

        assert_eq!(ctx.arcset_chain.len(), 3);
        assert_eq!(ctx.arcset_chain[0].instance, 1);
        assert_eq!(ctx.arcset_chain[1].instance, 2);
        assert_eq!(ctx.arcset_chain[2].instance, 3);
    }
}
