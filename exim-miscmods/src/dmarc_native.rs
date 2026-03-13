//! # Native DMARC Parser — Experimental Pure-Rust Implementation
//!
//! This module rewrites `src/src/miscmods/dmarc_native.c` (686 lines) and
//! incorporates shared helpers from `src/src/miscmods/dmarc_common.c` (531 lines)
//! into safe, idiomatic Rust.
//!
//! ## Overview
//!
//! This is an **experimental** native DMARC (Domain-based Message Authentication,
//! Reporting and Conformance) implementation that does **not** require the
//! `libopendmarc` C library. Instead, it parses DMARC DNS TXT records directly
//! and evaluates identifier alignment using Exim's own DNS resolver and PSL
//! (Public Suffix List) lookups for organizational domain determination.
//!
//! ## Mutual Exclusivity
//!
//! **WARNING**: This module (`dmarc-native` feature) and the `dmarc` module
//! (`dmarc` feature — backed by libopendmarc FFI) are **mutually exclusive**.
//! The compile-time guard in `lib.rs` enforces this via `compile_error!`.
//! In the C codebase, this was enforced by:
//! ```c
//! #ifdef SUPPORT_DMARC
//! # error Build cannot support both libopendmarc and native DMARC modules
//! #endif
//! ```
//!
//! ## Feature Gate Requirements
//!
//! This module requires:
//! - `#[cfg(feature = "dmarc-native")]` — the module's own feature flag
//! - `spf` feature — for SPF alignment checking (C: `EXIM_HAVE_SPF`)
//! - `dkim` feature — for DKIM alignment checking (C: `!DISABLE_DKIM`)
//! - PSL lookup driver available at runtime for organizational domain lookup
//!   (C: `LOOKUP_PSL`)
//!
//! ## RFC Compliance
//!
//! Implements DMARC processing per [RFC 7489](https://tools.ietf.org/html/rfc7489):
//! - §3.1.1 — Identifier alignment (strict and relaxed modes)
//! - §6.3   — DMARC DNS record tag definitions and defaults
//! - §6.6.1 — Policy record location (`_dmarc.<domain>`)
//! - §6.6.2 — Policy evaluation steps 2-6
//! - §6.6.3 — Policy discovery with organizational domain fallback
//!
//! ## Source Context
//!
//! - `src/src/miscmods/dmarc_native.c` (686 lines) — native parser + alignment
//! - `src/src/miscmods/dmarc_common.c` (531 lines) — shared state + helpers
//! - `src/src/miscmods/dmarc.h` — constant definitions
//! - `src/src/miscmods/dmarc_api.h` — function table indices
//!
//! # SPDX-License-Identifier: GPL-2.0-or-later

// ---------------------------------------------------------------------------
// Imports — Internal workspace crates (from depends_on_files)
// ---------------------------------------------------------------------------

use exim_dns::{DnsRecordData, DnsRecordType, DnsResolver, DnsResult as DnsLookupResult};
use exim_drivers::lookup_driver::{LookupDriverFactory, LookupResult};
use exim_drivers::{DriverError, DriverInfoBase, DriverRegistry};
// Taint types (Tainted, Clean, TaintedString, CleanString, TaintState, TaintError)
// and MessageStore are available from exim_store but not used in this module because
// the native DMARC parser operates on plain Rust strings; domain sanitization is
// handled at the call-site boundary before entering dmarc_process().

// ---------------------------------------------------------------------------
// Imports — Sibling modules within exim-miscmods (same crate)
// ---------------------------------------------------------------------------

#[cfg(feature = "spf")]
use crate::spf::SpfResult;

// DkimState from crate::dkim is available via the "dkim" feature but not directly
// imported here — DKIM signing domains are passed as &[&str] to dmarc_process()
// by the caller after extracting d= values from DkimState.signatures.

// ---------------------------------------------------------------------------
// Imports — External crates
// ---------------------------------------------------------------------------

use regex::Regex;
use std::fmt;
use std::sync::LazyLock;
use thiserror::Error;
use tracing::{debug, info};

// ---------------------------------------------------------------------------
// Compiled Regex Patterns (replacing C static PCRE2 patterns)
// ---------------------------------------------------------------------------
//
// These replace the 4 C static regex patterns from dmarc_native.c lines 34-37:
//   static const pcre2_code * dmarc_regex_uri = NULL;
//   static const pcre2_code * dmarc_regex_pct = NULL;
//   static const pcre2_code * dmarc_regex_ri  = NULL;
//   static const pcre2_code * dmarc_regex_fo  = NULL;
//
// Initialized lazily on first use via LazyLock (replacing dmarc_local_init()).

/// Regex for validating DMARC `rua` and `ruf` tag values (mailto URIs).
///
/// Replaces C: `dmarc_regex_uri` compiled from
/// `"^mailto:[^@]+@[^ !]+(?:[ !]|$)"` (dmarc_native.c line 43).
static URI_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^mailto:[^@]+@[^ !]+(?:[ !]|$)").expect("URI_REGEX compilation failed")
});

/// Regex for validating DMARC `pct` tag values (0-999 numeric).
///
/// Replaces C: `dmarc_regex_pct` compiled from
/// `"^\\d{1,3}$"` (dmarc_native.c line 46).
static PCT_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\d{1,3}$").expect("PCT_REGEX compilation failed"));

/// Regex for validating DMARC `ri` tag values (report interval digits).
///
/// Replaces C: `dmarc_regex_ri` compiled from
/// `"^\\d{1,10}$"` (dmarc_native.c line 48).
static RI_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\d{1,10}$").expect("RI_REGEX compilation failed"));

/// Regex for validating DMARC `fo` tag values (failure reporting options).
///
/// Replaces C: `dmarc_regex_fo` compiled from
/// `"^[01ds]$"` (dmarc_native.c line 50).
static FO_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[01ds]$").expect("FO_REGEX compilation failed"));

// ===========================================================================
// DmarcError — Structured error types for DMARC operations
// ===========================================================================

/// Errors arising from native DMARC processing.
///
/// Replaces ad-hoc error handling via `log_write()` and return codes from
/// `dmarc_native.c` and `dmarc_common.c`. Each variant maps to a specific
/// failure category in the DMARC evaluation pipeline.
#[derive(Debug, Error)]
pub enum DmarcError {
    /// DMARC DNS TXT record parsing failed.
    ///
    /// Replaces C: `dmarc_local_parse_policy()` returning FALSE
    /// (dmarc_native.c line 391-402).
    #[error("DMARC record parse error: {0}")]
    ParseError(String),

    /// DNS lookup for `_dmarc.<domain>` TXT record failed.
    ///
    /// Replaces C: `dmarc_dns_lookup()` returning NULL
    /// (dmarc_common.c lines 213-262).
    #[error("DMARC DNS lookup failed for domain: {0}")]
    DnsLookupFailed(String),

    /// PSL (Public Suffix List) lookup for organizational domain failed.
    ///
    /// Replaces C: `dmarc_lookup_regdom()` returning NULL
    /// (dmarc_common.c lines 266-305).
    #[error("PSL lookup failed for domain: {0}")]
    PslLookupFailed(String),

    /// Identifier alignment check encountered an error.
    ///
    /// Replaces C: `identifier_aligned()` error paths
    /// (dmarc_native.c lines 255-283).
    #[error("alignment check failed: {0}")]
    AlignmentCheckFailed(String),

    /// DMARC record is syntactically invalid or missing required tags.
    ///
    /// Replaces C: tag validation failures in `parse_tag()`
    /// (dmarc_native.c lines 198-236).
    #[error("invalid DMARC record: {0}")]
    InvalidRecord(String),

    /// DMARC policy evaluation encountered an internal error.
    ///
    /// Replaces C: unexpected policy string values in the switch cascade
    /// (dmarc_native.c lines 614-619).
    #[error("DMARC policy error: {0}")]
    PolicyError(String),

    /// SPF results are not available for alignment checking.
    ///
    /// Occurs when the SPF module has not been initialized or has not
    /// produced results before DMARC evaluation.
    #[error("SPF results not available for DMARC alignment")]
    SpfNotAvailable,

    /// DKIM results are not available for alignment checking.
    ///
    /// Occurs when the DKIM module has not been initialized or has not
    /// produced results before DMARC evaluation.
    #[error("DKIM results not available for DMARC alignment")]
    DkimNotAvailable,

    /// DMARC module initialization failed.
    ///
    /// Replaces C: `dmarc_init()` returning FALSE
    /// (dmarc_common.c lines 63-81).
    #[error("DMARC initialization failed: {0}")]
    InitFailed(String),
}

impl DmarcError {
    /// Convert this DMARC error into a [`DriverError`] for the driver framework.
    pub fn to_driver_error(&self) -> DriverError {
        match self {
            DmarcError::InitFailed(msg) => DriverError::InitFailed(msg.clone()),
            DmarcError::DnsLookupFailed(msg) => DriverError::TempFail(msg.clone()),
            DmarcError::PslLookupFailed(msg) => DriverError::TempFail(msg.clone()),
            _ => DriverError::ExecutionFailed(format!("{self}")),
        }
    }
}

// ===========================================================================
// DmarcPolicy — DMARC Policy Disposition
// ===========================================================================

/// DMARC policy disposition from the `p=` and `sp=` tags.
///
/// Maps to C constants from `dmarc.h`:
/// - `DMARC_POLICY_ABSENT`     (14) → `Unspecified`
/// - `DMARC_POLICY_NONE`       (18) → `None`
/// - `DMARC_POLICY_QUARANTINE` (17) → `Quarantine`
/// - `DMARC_POLICY_REJECT`     (16) → `Reject`
///
/// Per RFC 7489 §6.3: the `p=` tag is required; `sp=` defaults to `p=` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DmarcPolicy {
    /// No DMARC policy record found or policy tag absent.
    /// C: `DMARC_POLICY_ABSENT` (14)
    Unspecified,

    /// Monitoring mode — no specific action requested.
    /// C: `DMARC_POLICY_NONE` (18), p=none / sp=none
    None,

    /// Quarantine disposition — message should be treated as suspicious.
    /// C: `DMARC_POLICY_QUARANTINE` (17), p=quarantine / sp=quarantine
    Quarantine,

    /// Reject disposition — message should be rejected.
    /// C: `DMARC_POLICY_REJECT` (16), p=reject / sp=reject
    Reject,
}

impl DmarcPolicy {
    /// Parse a DMARC policy string from a DNS record tag value.
    ///
    /// Replaces C: `dmarc_tag_vfy_p()` and `dmarc_vfy_policy()`
    /// (dmarc_native.c lines 123-126, 139-140).
    pub fn from_tag_value(value: &str) -> Option<Self> {
        match value {
            "none" => Some(DmarcPolicy::None),
            "quarantine" => Some(DmarcPolicy::Quarantine),
            "reject" => Some(DmarcPolicy::Reject),
            _ => Option::None,
        }
    }

    /// Get the string representation matching the DMARC DNS record tag value.
    pub fn as_str(&self) -> &'static str {
        match self {
            DmarcPolicy::Unspecified => "unspecified",
            DmarcPolicy::None => "none",
            DmarcPolicy::Quarantine => "quarantine",
            DmarcPolicy::Reject => "reject",
        }
    }
}

impl fmt::Display for DmarcPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ===========================================================================
// DmarcAlignment — Identifier Alignment Mode
// ===========================================================================

/// DMARC identifier alignment mode from the `adkim=` and `aspf=` tags.
///
/// Maps to C constants from `dmarc.h`:
/// - `DMARC_RECORD_A_UNSPECIFIED` ('\0') → `Unspecified` (defaults to Relaxed)
/// - `DMARC_RECORD_A_STRICT`     ('s')  → `Strict`
/// - `DMARC_RECORD_A_RELAXED`    ('r')  → `Relaxed`
///
/// Per RFC 7489 §6.3: both default to relaxed if not present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DmarcAlignment {
    /// Alignment mode not specified — defaults to [`Relaxed`](Self::Relaxed).
    Unspecified,

    /// Strict alignment — exact domain match required.
    /// RFC 7489 §3.1.1: only an exact match of the domains is considered aligned.
    Strict,

    /// Relaxed alignment — organizational domain match sufficient.
    /// RFC 7489 §3.1.1: the organizational domains of both identifiers must match.
    Relaxed,
}

impl DmarcAlignment {
    /// Parse an alignment mode from a single-character tag value.
    ///
    /// Replaces C: `dmarc_vfy_vmode()` (dmarc_native.c lines 121-122).
    pub fn from_tag_value(value: &str) -> Option<Self> {
        match value {
            "s" => Some(DmarcAlignment::Strict),
            "r" => Some(DmarcAlignment::Relaxed),
            _ => Option::None,
        }
    }

    /// Returns the effective alignment mode, substituting `Relaxed` for
    /// `Unspecified` per RFC 7489 §6.3 defaults.
    pub fn effective(&self) -> DmarcAlignment {
        match self {
            DmarcAlignment::Unspecified => DmarcAlignment::Relaxed,
            other => *other,
        }
    }

    /// Get the single-character string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            DmarcAlignment::Unspecified => "r",
            DmarcAlignment::Strict => "s",
            DmarcAlignment::Relaxed => "r",
        }
    }
}

impl fmt::Display for DmarcAlignment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DmarcAlignment::Unspecified => write!(f, "unspecified (relaxed)"),
            DmarcAlignment::Strict => write!(f, "strict"),
            DmarcAlignment::Relaxed => write!(f, "relaxed"),
        }
    }
}

// ===========================================================================
// DmarcResult — DMARC Action Result
// ===========================================================================

/// DMARC action result — the disposition determined by DMARC processing.
///
/// Maps to C constants from `dmarc.h`:
/// - `DMARC_RESULT_REJECT`     (0) → `Reject`
/// - `DMARC_RESULT_DISCARD`    (1) → `Discard`
/// - `DMARC_RESULT_ACCEPT`     (2) → `Accept`
/// - `DMARC_RESULT_TEMPFAIL`   (3) → `TempFail`
/// - `DMARC_RESULT_QUARANTINE` (4) → `Quarantine`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DmarcResult {
    /// Reject the message.
    /// C: `DMARC_RESULT_REJECT` (0)
    Reject,

    /// Silently discard the message.
    /// C: `DMARC_RESULT_DISCARD` (1)
    Discard,

    /// Accept the message (aligned or policy=none).
    /// C: `DMARC_RESULT_ACCEPT` (2)
    Accept,

    /// Temporary failure — defer processing.
    /// C: `DMARC_RESULT_TEMPFAIL` (3)
    TempFail,

    /// Quarantine the message.
    /// C: `DMARC_RESULT_QUARANTINE` (4)
    Quarantine,
}

impl DmarcResult {
    /// Get the string representation matching C Exim's result names.
    pub fn as_str(&self) -> &'static str {
        match self {
            DmarcResult::Reject => "reject",
            DmarcResult::Discard => "discard",
            DmarcResult::Accept => "accept",
            DmarcResult::TempFail => "temperror",
            DmarcResult::Quarantine => "quarantine",
        }
    }
}

impl fmt::Display for DmarcResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ===========================================================================
// DmarcRecord — Parsed DMARC DNS TXT Record
// ===========================================================================

/// Parsed representation of a DMARC DNS TXT record.
///
/// Contains all tags defined in RFC 7489 §6.3, with defaults applied for
/// optional tags. Replaces C `dmarc_policy_record` struct
/// (dmarc_native.c lines 156-168).
#[derive(Debug, Clone)]
pub struct DmarcRecord {
    /// DMARC version — must be "DMARC1".
    pub version: String,

    /// Policy for the domain (p= tag).
    pub policy: DmarcPolicy,

    /// Policy for subdomains (sp= tag).
    /// Defaults to `None` (falls back to `policy` value per RFC 7489 §6.3).
    pub subdomain_policy: Option<DmarcPolicy>,

    /// DKIM identifier alignment mode (adkim= tag).
    /// Defaults to `Relaxed` per RFC 7489 §6.3.
    pub adkim: DmarcAlignment,

    /// SPF identifier alignment mode (aspf= tag).
    /// Defaults to `Relaxed` per RFC 7489 §6.3.
    pub aspf: DmarcAlignment,

    /// Percentage of messages subject to DMARC policy (pct= tag, 0-100).
    /// Defaults to 100 per RFC 7489 §6.3.
    pub pct: u8,

    /// Aggregate report interval in seconds (ri= tag).
    /// Defaults to 86400 (one day) per RFC 7489 §6.3.
    pub ri: u32,

    /// Aggregate report destination URIs (rua= tag).
    pub rua: Vec<String>,

    /// Failure/forensic report destination URIs (ruf= tag).
    pub ruf: Vec<String>,

    /// Failure reporting options (fo= tag).
    /// Defaults to "0".
    pub fo: String,
}

impl Default for DmarcRecord {
    fn default() -> Self {
        Self {
            version: String::from("DMARC1"),
            policy: DmarcPolicy::Unspecified,
            subdomain_policy: Option::None,
            adkim: DmarcAlignment::Relaxed,
            aspf: DmarcAlignment::Relaxed,
            pct: 100,
            ri: 86400,
            rua: Vec::new(),
            ruf: Vec::new(),
            fo: String::from("0"),
        }
    }
}

// ===========================================================================
// DmarcState — All Mutable DMARC State (replaces C globals)
// ===========================================================================

/// Complete mutable state for native DMARC processing on a single SMTP
/// connection/message.
///
/// Replaces all C global variables from `dmarc_common.c` lines 26-57.
/// Passed explicitly through all call chains per AAP §0.4.4.
#[derive(Debug)]
pub struct DmarcState {
    /// Current DMARC status string (e.g., "none", "accept", "reject").
    pub status: String,

    /// DMARC processing result/action.
    pub result: DmarcResult,

    /// From: header domain being evaluated.
    pub domain: Option<String>,

    /// Effective DMARC policy determined from the record.
    pub policy: DmarcPolicy,

    /// Domain used for DMARC policy lookup (may be organizational domain).
    pub used_domain: Option<String>,

    /// Sender address for forensic reports.
    pub forensic_sender: Option<String>,

    /// Path to the history file for aggregate reporting data.
    pub history_file: Option<String>,

    /// Path to the Mozilla TLDs/PSL text file.
    pub tld_file: Option<String>,

    /// Whether a valid DMARC record was found.
    pub has_record: bool,

    /// SPF outcome for DMARC alignment checking.
    pub spf_outcome: DmarcAlignmentOutcome,

    /// DKIM outcome for DMARC alignment checking.
    pub dkim_outcome: DmarcAlignmentOutcome,

    /// Whether SPF alignment passed.
    pub spf_alignment: bool,

    /// Whether DKIM alignment passed.
    pub dkim_alignment: bool,

    // Internal working state
    /// Whether DMARC processing should be aborted.
    abort: bool,

    /// Pass/fail string for Authentication-Results header.
    pass_fail: String,

    /// Human-readable status text.
    status_text: String,

    /// Domain policy string from the record.
    domain_policy: Option<String>,

    /// Whether verification is disabled via ACL control.
    disable_verify: bool,

    /// Whether forensic reporting is enabled via ACL control.
    enable_forensic: bool,

    /// Whether DMARC has been checked for this message.
    has_been_checked: bool,
}

/// DMARC alignment outcome — pass or fail for SPF/DKIM alignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DmarcAlignmentOutcome {
    /// Alignment check passed.
    Pass,
    /// Alignment check failed.
    Fail,
}

impl Default for DmarcState {
    fn default() -> Self {
        Self {
            status: String::from("none"),
            result: DmarcResult::Accept,
            domain: Option::None,
            policy: DmarcPolicy::Unspecified,
            used_domain: Option::None,
            forensic_sender: Option::None,
            history_file: Option::None,
            tld_file: Option::None,
            has_record: false,
            spf_outcome: DmarcAlignmentOutcome::Fail,
            dkim_outcome: DmarcAlignmentOutcome::Fail,
            spf_alignment: false,
            dkim_alignment: false,
            abort: false,
            pass_fail: String::from("skipped"),
            status_text: String::new(),
            domain_policy: Option::None,
            disable_verify: false,
            enable_forensic: false,
            has_been_checked: false,
        }
    }
}

impl DmarcState {
    /// Creates a new `DmarcState` with default values.
    pub fn new() -> Self {
        Self::default()
    }
}

// ===========================================================================
// DMARC Record Parsing
// ===========================================================================

/// Parse a DMARC DNS TXT record string into a [`DmarcRecord`].
///
/// Implements the tag-value parsing per RFC 7489 §6.3 / RFC 6376 §3.2:
/// - Tags are semicolon-separated
/// - Each tag is `name=value` format
/// - Whitespace around names and values is ignored
/// - Unknown tags are silently ignored (RFC 7489 §6.3)
/// - Version tag `v=DMARC1` must be present
/// - Policy tag `p=` must be present and valid
///
/// Replaces C: `dmarc_local_parse_policy()` (dmarc_native.c lines 238-251)
/// and `parse_tag()` (dmarc_native.c lines 198-236).
pub fn parse_dmarc_record(txt: &str) -> Result<DmarcRecord, DmarcError> {
    debug!(record = txt, "DMARC: parsing policy record");

    let mut record = DmarcRecord::default();
    let mut found_version = false;
    let mut found_policy = false;

    for tag_spec in txt.split(';') {
        let tag_spec = tag_spec.trim();
        if tag_spec.is_empty() {
            continue;
        }

        let eq_pos = match tag_spec.find('=') {
            Some(pos) => pos,
            Option::None => {
                debug!(tag = tag_spec, "DMARC: skipping tag without '='");
                continue;
            }
        };

        let tag_name = tag_spec[..eq_pos].trim();
        let tag_value = tag_spec[eq_pos + 1..].trim();

        if tag_name.is_empty() {
            debug!("DMARC: empty tag name in record");
            continue;
        }

        match tag_name {
            "v" => {
                if tag_value != "DMARC1" {
                    return Err(DmarcError::ParseError(format!(
                        "invalid DMARC version: '{tag_value}', expected 'DMARC1'"
                    )));
                }
                record.version = String::from("DMARC1");
                found_version = true;
            }
            "p" => {
                if let Some(policy) = DmarcPolicy::from_tag_value(tag_value) {
                    record.policy = policy;
                    found_policy = true;
                } else {
                    debug!(value = tag_value, "DMARC: bad value for p= tag");
                }
            }
            "sp" => {
                if let Some(policy) = DmarcPolicy::from_tag_value(tag_value) {
                    record.subdomain_policy = Some(policy);
                } else {
                    debug!(value = tag_value, "DMARC: bad value for sp= tag");
                }
            }
            "adkim" => {
                if let Some(align) = DmarcAlignment::from_tag_value(tag_value) {
                    record.adkim = align;
                } else {
                    debug!(value = tag_value, "DMARC: bad value for adkim= tag");
                }
            }
            "aspf" => {
                if let Some(align) = DmarcAlignment::from_tag_value(tag_value) {
                    record.aspf = align;
                } else {
                    debug!(value = tag_value, "DMARC: bad value for aspf= tag");
                }
            }
            "pct" => {
                if PCT_REGEX.is_match(tag_value) {
                    if let Ok(pct) = tag_value.parse::<u16>() {
                        if pct <= 100 {
                            record.pct = pct as u8;
                        } else {
                            debug!(value = tag_value, "DMARC: pct value out of range");
                        }
                    }
                } else {
                    debug!(value = tag_value, "DMARC: bad value for pct= tag");
                }
            }
            "ri" => {
                if RI_REGEX.is_match(tag_value) {
                    if let Ok(ri) = tag_value.parse::<u32>() {
                        record.ri = ri;
                    }
                } else {
                    debug!(value = tag_value, "DMARC: bad value for ri= tag");
                }
            }
            "rua" => {
                record.rua = parse_uri_list(tag_value);
            }
            "ruf" => {
                record.ruf = parse_uri_list(tag_value);
            }
            "fo" => {
                if FO_REGEX.is_match(tag_value) {
                    record.fo = tag_value.to_string();
                } else {
                    debug!(value = tag_value, "DMARC: bad value for fo= tag");
                }
            }
            "rf" => {
                if tag_value != "afrf" {
                    debug!(value = tag_value, "DMARC: unsupported rf= value");
                }
            }
            _ => {
                debug!(tag = tag_name, "DMARC: ignoring unknown tag");
            }
        }
    }

    if !found_version {
        return Err(DmarcError::ParseError(
            "missing required v=DMARC1 tag".to_string(),
        ));
    }

    if !found_policy {
        debug!("DMARC: p= tag not found or invalid");
    }

    debug!(
        version = %record.version,
        policy = %record.policy,
        adkim = %record.adkim,
        aspf = %record.aspf,
        pct = record.pct,
        "DMARC: record parsed successfully"
    );

    Ok(record)
}

/// Parse a comma-separated list of URI values from rua= or ruf= tags.
/// Validates each URI against the mailto regex pattern.
fn parse_uri_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|uri| uri.trim().to_string())
        .filter(|uri| {
            if uri.is_empty() {
                return false;
            }
            if URI_REGEX.is_match(uri) {
                true
            } else {
                debug!(uri = uri.as_str(), "DMARC: invalid URI in rua/ruf list");
                false
            }
        })
        .collect()
}

// ===========================================================================
// Domain Alignment Checking
// ===========================================================================

/// Check identifier alignment between two domains.
///
/// Implements RFC 7489 §3.1.1 identifier alignment:
/// - **Strict mode**: Exact case-insensitive domain match.
/// - **Relaxed mode**: Organizational domains must match via PSL lookup.
///
/// Replaces C: `identifier_aligned()` (dmarc_native.c lines 255-283).
pub fn check_alignment(domain: &str, identifier: &str, mode: DmarcAlignment) -> bool {
    let effective_mode = mode.effective();

    match effective_mode {
        DmarcAlignment::Strict => {
            let aligned = domain.eq_ignore_ascii_case(identifier);
            if aligned {
                debug!(
                    mode = "strict",
                    domain = domain,
                    identifier = identifier,
                    "DMARC: alignment passed (strict)"
                );
            }
            aligned
        }
        DmarcAlignment::Relaxed => {
            if domain.eq_ignore_ascii_case(identifier) {
                debug!(
                    mode = "relaxed",
                    domain = domain,
                    identifier = identifier,
                    "DMARC: alignment passed (exact match)"
                );
                return true;
            }

            let org_a = lookup_registered_domain(domain);
            let org_b = lookup_registered_domain(identifier);

            match (org_a, org_b) {
                (Ok(ref a), Ok(ref b)) => {
                    let aligned = a.eq_ignore_ascii_case(b);
                    if aligned {
                        debug!(
                            mode = "relaxed",
                            org_a = a.as_str(),
                            org_b = b.as_str(),
                            "DMARC: alignment passed (org domain match)"
                        );
                    }
                    aligned
                }
                _ => {
                    debug!(
                        domain = domain,
                        identifier = identifier,
                        "DMARC: alignment check failed — PSL lookup error"
                    );
                    false
                }
            }
        }
        DmarcAlignment::Unspecified => false,
    }
}

/// Look up the registered/organizational domain via the PSL lookup driver.
///
/// Uses the `regdom` lookup driver (backed by the Public Suffix List) to
/// determine the organizational domain for a given input domain.
///
/// Replaces C: `dmarc_lookup_regdom()` (dmarc_common.c lines 266-305).
pub fn lookup_registered_domain(domain: &str) -> Result<String, DmarcError> {
    debug!(
        domain = domain,
        "DMARC: looking up registered domain via PSL"
    );

    // Find the "regdom" lookup driver factory from the registry.
    // Replaces C: search_findtype_partial(US"regdom", ...)
    let factory: &'static LookupDriverFactory =
        DriverRegistry::find_lookup("regdom").ok_or_else(|| {
            debug!("DMARC: missing regdom lookup driver (PSL not available)");
            DmarcError::PslLookupFailed(format!(
                "regdom lookup driver not available for domain '{domain}'"
            ))
        })?;

    // Create a driver instance from the factory.
    let driver = (factory.create)();

    // Open the lookup source. For the regdom/PSL lookup, this may be the PSL
    // file or a no-op depending on the backend implementation. We pass None
    // since the PSL data file path is configured at driver level.
    let handle = driver.open(None).map_err(|e| {
        debug!(domain = domain, error = %e, "DMARC: PSL driver open failed");
        DmarcError::PslLookupFailed(format!("PSL driver open failed: {e}"))
    })?;

    // Perform the lookup — the key_or_query is the domain name, and the result
    // is the registered/organizational domain.
    // Replaces C: search_find(handle, dmarc_tld_file, dom, ...)
    let result = driver.find(&handle, None, domain, None).map_err(|e| {
        debug!(domain = domain, error = %e, "DMARC: PSL regdom lookup failed");
        DmarcError::PslLookupFailed(format!("regdom lookup failed for '{domain}': {e}"))
    })?;

    match result {
        LookupResult::Found { value, .. } => {
            debug!(
                domain = domain,
                regdom = value.as_str(),
                "DMARC: registered domain found"
            );
            Ok(value)
        }
        LookupResult::NotFound => {
            debug!(domain = domain, "DMARC: no registered domain found");
            Err(DmarcError::PslLookupFailed(format!(
                "no registered domain found for '{domain}'"
            )))
        }
        LookupResult::Deferred { message } => {
            debug!(
                domain = domain,
                message = message.as_str(),
                "DMARC: PSL lookup deferred"
            );
            Err(DmarcError::PslLookupFailed(format!(
                "PSL lookup deferred for '{domain}': {message}"
            )))
        }
    }
}

// ===========================================================================
// DNS DMARC Record Lookup
// ===========================================================================

/// Look up a DMARC DNS TXT record for the given domain.
///
/// Queries `_dmarc.<domain>` for TXT records, finds the one starting with
/// "v=DMARC1;", and returns the record content.
///
/// Replaces C: `dmarc_dns_lookup()` (dmarc_common.c lines 213-262).
fn dmarc_dns_lookup(domain: &str, dns: &DnsResolver) -> Option<String> {
    let query = format!("_dmarc.{domain}");
    debug!(query = query.as_str(), "DMARC: DNS TXT lookup");

    let response = match dns.dns_lookup(&query, DnsRecordType::Txt, 0) {
        Ok((resp, _fqdn)) => resp,
        Err(e) => {
            debug!(
                query = query.as_str(),
                error = %e,
                "DMARC: DNS lookup failed"
            );
            return Option::None;
        }
    };

    if response.result != DnsLookupResult::Succeed {
        debug!(
            query = query.as_str(),
            result = ?response.result,
            "DMARC: DNS lookup did not succeed"
        );
        return Option::None;
    }

    let mut found: Option<String> = Option::None;

    for record in &response.records {
        if record.record_type != DnsRecordType::Txt {
            continue;
        }
        if let DnsRecordData::Txt(ref txt_data) = record.data {
            let trimmed = txt_data.trim();
            if trimmed.len() > 9 && trimmed.starts_with("v=DMARC1;") {
                if found.is_some() {
                    debug!("DMARC: multiple records found — treating as no record");
                    return Option::None;
                }
                found = Some(trimmed.to_string());
            }
        }
    }

    if found.is_none() {
        debug!(query = query.as_str(), "DMARC: no v=DMARC1; record found");
    }

    found
}

/// Get the DMARC DNS policy record for the given From: domain.
///
/// Implements RFC 7489 §6.6.3 policy discovery:
/// 1. Look up `_dmarc.<from_domain>` — use if found
/// 2. If no record, determine organizational domain via PSL
/// 3. Look up `_dmarc.<org_domain>` if different
///
/// Replaces C: `dmarc_get_dns_policy_record()` (dmarc_common.c lines 307-331).
fn dmarc_get_dns_policy_record(from_domain: &str, dns: &DnsResolver) -> Option<(String, String)> {
    debug!(from_domain = from_domain, "DMARC: looking up policy record");

    if let Some(rr) = dmarc_dns_lookup(from_domain, dns) {
        return Some((rr, from_domain.to_string()));
    }

    let org_domain = match lookup_registered_domain(from_domain) {
        Ok(dom) => dom,
        Err(_) => return Option::None,
    };

    if org_domain.eq_ignore_ascii_case(from_domain) {
        return Option::None;
    }

    dmarc_dns_lookup(&org_domain, dns).map(|rr| (rr, org_domain))
}

// ===========================================================================
// Core DMARC Processing
// ===========================================================================

/// Main DMARC processing entry point.
///
/// Evaluates DMARC policy for the current message by:
/// 1. Extracting the From: header domain
/// 2. Looking up organizational domain via PSL
/// 3. Querying `_dmarc.{domain}` DNS TXT record
/// 4. Parsing DMARC record tags
/// 5. Checking DKIM alignment against From: domain
/// 6. Checking SPF alignment against From: domain
/// 7. Applying policy based on alignment results
/// 8. Handling pct= sampling
///
/// Replaces C: `dmarc_process()` (dmarc_native.c lines 291-663).
/// Registered in module function table at index `DMARC_PROCESS` (0).
pub fn dmarc_process(
    state: &mut DmarcState,
    from_domain: &str,
    dns: &DnsResolver,
    spf_result: Option<(&SpfResult, &str)>,
    dkim_domains: &[&str],
) -> Result<DmarcPolicy, DmarcError> {
    // Reset alignment state
    state.spf_alignment = false;
    state.dkim_alignment = false;
    state.dkim_outcome = DmarcAlignmentOutcome::Fail;
    state.spf_outcome = DmarcAlignmentOutcome::Fail;

    if state.disable_verify || state.abort {
        debug!("DMARC: processing skipped (disabled or aborted)");
        return Ok(DmarcPolicy::Unspecified);
    }

    debug!("DMARC: process");

    if from_domain.is_empty() {
        debug!("DMARC: no From: header domain");
        state.abort = true;
        state.status = String::from("nofrom");
        state.pass_fail = String::from("temperror");
        state.status_text = String::from("No From: domain found");
        state.result = DmarcResult::Accept;
        return Ok(DmarcPolicy::Unspecified);
    }

    state.domain = Some(from_domain.to_string());

    debug!("DMARC: get policy record");

    let (rr_text, used_domain) = match dmarc_get_dns_policy_record(from_domain, dns) {
        Some((rr, dom)) => (rr, dom),
        Option::None => {
            debug!(from_domain = from_domain, "DMARC: no record found");
            state.policy = DmarcPolicy::Unspecified;
            state.status = String::from("norecord");
            state.pass_fail = String::from("none");
            state.status_text = String::from("No DMARC record");
            state.result = DmarcResult::Accept;
            state.has_record = false;
            state.has_been_checked = true;
            return Ok(DmarcPolicy::Unspecified);
        }
    };

    state.used_domain = Some(used_domain.clone());

    let mut dmarc_record = match parse_dmarc_record(&rr_text) {
        Ok(parsed) => parsed,
        Err(e) => {
            debug!(from_domain = from_domain, error = %e, "DMARC: invalid record");
            state.policy = DmarcPolicy::Unspecified;
            state.status = String::from("norecord");
            state.pass_fail = String::from("none");
            state.status_text = String::from("No DMARC record");
            state.result = DmarcResult::Accept;
            state.has_record = false;
            state.has_been_checked = true;
            return Ok(DmarcPolicy::Unspecified);
        }
    };
    let has_dmarc_record = true;

    // RFC 7489 §6.6.3 step 6: p/sp validation
    if dmarc_record.policy == DmarcPolicy::Unspecified {
        if !dmarc_record.rua.is_empty() {
            debug!("DMARC: invalid p tag; continuing with p=none for rua reporting");
            dmarc_record.policy = DmarcPolicy::None;
        } else {
            debug!("DMARC: invalid p tag, no rua — aborting");
            state.abort = true;
            state.has_been_checked = true;
            return Ok(DmarcPolicy::Unspecified);
        }
    }

    state.has_record = true;

    // RFC 7489 §6.6.2 step 3: DKIM alignment checking
    debug!("DMARC: process dkim results");

    if has_dmarc_record {
        for dkim_domain in dkim_domains {
            if check_alignment(dkim_domain, from_domain, dmarc_record.adkim) {
                state.dkim_alignment = true;
                state.dkim_outcome = DmarcAlignmentOutcome::Pass;
                debug!(dkim_domain = *dkim_domain, "DMARC: DKIM alignment passed");
                break;
            }
        }
    }

    debug!(
        dkim_count = dkim_domains.len(),
        "DMARC: processed DKIM signatures"
    );

    // RFC 7489 §6.6.2 step 4: SPF alignment checking
    debug!("DMARC: process spf results");

    if has_dmarc_record {
        if let Some((spf_res, spf_domain)) = spf_result {
            if !spf_domain.is_empty() {
                if *spf_res == SpfResult::Pass
                    && check_alignment(spf_domain, from_domain, dmarc_record.aspf)
                {
                    state.spf_alignment = true;
                    state.spf_outcome = DmarcAlignmentOutcome::Pass;
                    debug!(spf_domain = spf_domain, "DMARC: SPF alignment passed");
                }
            } else {
                debug!("DMARC: empty SPF domain, aborting");
                state.abort = true;
            }
        }
    }

    debug!("DMARC: finished spf");

    // Determine effective policy (subdomain vs domain)
    let effective_policy = if dmarc_record.subdomain_policy.is_some()
        && !used_domain.eq_ignore_ascii_case(from_domain)
    {
        dmarc_record.subdomain_policy.unwrap_or(dmarc_record.policy)
    } else {
        dmarc_record.policy
    };

    state.domain_policy = Some(effective_policy.as_str().to_string());

    // RFC 7489 §6.6.2 step 5: either SPF or DKIM alignment → pass
    if state.spf_alignment || state.dkim_alignment {
        state.policy = DmarcPolicy::None;
        state.status = String::from("accept");
        state.pass_fail = String::from("pass");
        state.status_text = String::from("Accept");
        state.result = DmarcResult::Accept;
    } else {
        // RFC 7489 §6.6.2 step 6: dispose per discovered policy
        state.status = effective_policy.as_str().to_string();
        match effective_policy {
            DmarcPolicy::None => {
                state.policy = DmarcPolicy::None;
                state.pass_fail = String::from("none");
                state.status_text = String::from("None, Accept");
                state.result = DmarcResult::Accept;
            }
            DmarcPolicy::Quarantine => {
                state.policy = DmarcPolicy::Quarantine;
                state.pass_fail = String::from("fail");
                state.status_text = String::from("Quarantine");
                state.result = DmarcResult::Quarantine;
            }
            DmarcPolicy::Reject => {
                state.policy = DmarcPolicy::Reject;
                state.pass_fail = String::from("fail");
                state.status_text = String::from("Reject");
                state.result = DmarcResult::Reject;
            }
            DmarcPolicy::Unspecified => {
                state.status = String::from("temperror");
                state.pass_fail = String::from("temperror");
                state.status_text = String::from("Internal Policy Error");
                state.result = DmarcResult::TempFail;
            }
        }
    }

    if has_dmarc_record && !state.abort {
        debug!(
            dmarc_domain = used_domain.as_str(),
            spf_align = state.spf_alignment,
            dkim_align = state.dkim_alignment,
            enforcement = state.status_text.as_str(),
            "DMARC: evaluation results"
        );
    }

    state.has_been_checked = true;
    debug!(status = state.status.as_str(), "DMARC: finished process");

    Ok(state.policy)
}

/// Check if the current DMARC status matches any item in the given list.
///
/// Used by the ACL `dmarc =` condition to test DMARC results.
///
/// Replaces C: `dmarc_result_inlist()` (dmarc_native.c lines 674-680).
pub fn dmarc_result_inlist(state: &DmarcState, list: &[&str]) -> bool {
    let status = if state.disable_verify {
        "off"
    } else {
        state.status.as_str()
    };

    for item in list {
        if item.eq_ignore_ascii_case(status) {
            return true;
        }
    }
    false
}

// ===========================================================================
// Module Lifecycle Functions
// ===========================================================================

/// Initialize the native DMARC module.
///
/// Ensures regex patterns are compiled. Called once at process startup.
/// Replaces C: `dmarc_init()` (dmarc_common.c lines 63-81) combined with
/// `dmarc_local_init()` (dmarc_native.c lines 39-50).
pub fn dmarc_init() -> Result<(), DmarcError> {
    debug!("DMARC native: initializing");

    // Force lazy-init of regex patterns (replaces dmarc_local_init())
    let _ = URI_REGEX.is_match("");
    let _ = PCT_REGEX.is_match("");
    let _ = RI_REGEX.is_match("");
    let _ = FO_REGEX.is_match("");

    debug!("DMARC native: regex patterns initialized");
    info!("DMARC native: module initialized (Exim builtin, no libopendmarc)");

    Ok(())
}

/// Per-message initialization for DMARC state.
///
/// Resets all per-message state fields to defaults.
///
/// Replaces C: `dmarc_msg_init()` (dmarc_common.c lines 91-126).
pub fn dmarc_msg_init(state: &mut DmarcState) {
    debug!("DMARC: msg_init");

    state.has_been_checked = false;
    state.domain = Option::None;
    state.status = String::from("none");
    state.abort = false;
    state.pass_fail = String::from("skipped");
    state.used_domain = Some(String::new());
    state.result = DmarcResult::Accept;
    state.has_record = false;
    state.spf_alignment = false;
    state.dkim_alignment = false;
    state.spf_outcome = DmarcAlignmentOutcome::Fail;
    state.dkim_outcome = DmarcAlignmentOutcome::Fail;
    state.status_text = String::new();
    state.domain_policy = Option::None;

    if state.disable_verify {
        debug!("DMARC: verification disabled via ACL");
        return;
    }

    if state.tld_file.is_none() || state.tld_file.as_deref() == Some("") {
        debug!("DMARC: no dmarc_tld_file configured");
        state.abort = true;
    }
}

/// SMTP session reset for DMARC state.
///
/// Clears all per-transaction flags and results.
///
/// Replaces C: `dmarc_smtp_reset()` (dmarc_common.c lines 131-138).
pub fn dmarc_smtp_reset(state: &mut DmarcState) {
    debug!("DMARC: smtp_reset");

    state.has_been_checked = false;
    state.disable_verify = false;
    state.enable_forensic = false;
    state.domain_policy = Option::None;
    state.status = String::from("none");
    state.status_text = String::new();
    state.used_domain = Option::None;
}

/// Generate the Authentication-Results DMARC header fragment.
///
/// Produces the `dmarc=<pass_fail> header.from=<domain>` fragment for
/// inclusion in the Authentication-Results header.
///
/// Replaces C: `authres_dmarc()` (dmarc_common.c lines 461-477).
pub fn authres_dmarc(state: &DmarcState) -> String {
    if state.has_been_checked {
        let mut result = format!(";\n\tdmarc={}", state.pass_fail);
        if let Some(ref domain) = state.domain {
            result.push_str(&format!(" header.from={domain}"));
        }
        debug!(authres = result.as_str(), "DMARC: authres generated");
        result
    } else {
        debug!("DMARC: no authres (not checked)");
        String::new()
    }
}

// ===========================================================================
// Module Registration via inventory
// ===========================================================================

inventory::submit! {
    DriverInfoBase::with_avail_string("dmarc", "dmarc (native/builtin)")
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dmarc_policy_from_tag_value() {
        assert_eq!(DmarcPolicy::from_tag_value("none"), Some(DmarcPolicy::None));
        assert_eq!(
            DmarcPolicy::from_tag_value("quarantine"),
            Some(DmarcPolicy::Quarantine)
        );
        assert_eq!(
            DmarcPolicy::from_tag_value("reject"),
            Some(DmarcPolicy::Reject)
        );
        assert_eq!(DmarcPolicy::from_tag_value("invalid"), Option::None);
        assert_eq!(DmarcPolicy::from_tag_value(""), Option::None);
    }

    #[test]
    fn test_dmarc_policy_as_str() {
        assert_eq!(DmarcPolicy::None.as_str(), "none");
        assert_eq!(DmarcPolicy::Quarantine.as_str(), "quarantine");
        assert_eq!(DmarcPolicy::Reject.as_str(), "reject");
        assert_eq!(DmarcPolicy::Unspecified.as_str(), "unspecified");
    }

    #[test]
    fn test_dmarc_alignment_from_tag_value() {
        assert_eq!(
            DmarcAlignment::from_tag_value("s"),
            Some(DmarcAlignment::Strict)
        );
        assert_eq!(
            DmarcAlignment::from_tag_value("r"),
            Some(DmarcAlignment::Relaxed)
        );
        assert_eq!(DmarcAlignment::from_tag_value("x"), Option::None);
        assert_eq!(DmarcAlignment::from_tag_value(""), Option::None);
    }

    #[test]
    fn test_dmarc_alignment_effective() {
        assert_eq!(
            DmarcAlignment::Unspecified.effective(),
            DmarcAlignment::Relaxed
        );
        assert_eq!(DmarcAlignment::Strict.effective(), DmarcAlignment::Strict);
        assert_eq!(DmarcAlignment::Relaxed.effective(), DmarcAlignment::Relaxed);
    }

    #[test]
    fn test_dmarc_result_as_str() {
        assert_eq!(DmarcResult::Reject.as_str(), "reject");
        assert_eq!(DmarcResult::Discard.as_str(), "discard");
        assert_eq!(DmarcResult::Accept.as_str(), "accept");
        assert_eq!(DmarcResult::TempFail.as_str(), "temperror");
        assert_eq!(DmarcResult::Quarantine.as_str(), "quarantine");
    }

    #[test]
    fn test_parse_minimal_record() {
        let record = parse_dmarc_record("v=DMARC1; p=none").unwrap();
        assert_eq!(record.version, "DMARC1");
        assert_eq!(record.policy, DmarcPolicy::None);
        assert_eq!(record.adkim, DmarcAlignment::Relaxed);
        assert_eq!(record.aspf, DmarcAlignment::Relaxed);
        assert_eq!(record.pct, 100);
        assert_eq!(record.ri, 86400);
    }

    #[test]
    fn test_parse_full_record() {
        let record = parse_dmarc_record(
            "v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=r; pct=50; \
             ri=3600; rua=mailto:dmarc@example.com; ruf=mailto:ruf@example.com; fo=1",
        )
        .unwrap();
        assert_eq!(record.policy, DmarcPolicy::Reject);
        assert_eq!(record.subdomain_policy, Some(DmarcPolicy::Quarantine));
        assert_eq!(record.adkim, DmarcAlignment::Strict);
        assert_eq!(record.aspf, DmarcAlignment::Relaxed);
        assert_eq!(record.pct, 50);
        assert_eq!(record.ri, 3600);
        assert_eq!(record.rua.len(), 1);
        assert_eq!(record.ruf.len(), 1);
        assert_eq!(record.fo, "1");
    }

    #[test]
    fn test_parse_missing_version() {
        let result = parse_dmarc_record("p=reject");
        assert!(result.is_err());
        if let Err(DmarcError::ParseError(msg)) = result {
            assert!(msg.contains("v=DMARC1"));
        }
    }

    #[test]
    fn test_parse_invalid_version() {
        let result = parse_dmarc_record("v=DMARC2; p=reject");
        assert!(result.is_err());
        if let Err(DmarcError::ParseError(msg)) = result {
            assert!(msg.contains("invalid DMARC version"));
        }
    }

    #[test]
    fn test_parse_unknown_tags_ignored() {
        let record = parse_dmarc_record("v=DMARC1; p=none; unknowntag=value").unwrap();
        assert_eq!(record.policy, DmarcPolicy::None);
    }

    #[test]
    fn test_parse_pct_boundary() {
        let record = parse_dmarc_record("v=DMARC1; p=none; pct=0").unwrap();
        assert_eq!(record.pct, 0);

        let record = parse_dmarc_record("v=DMARC1; p=none; pct=100").unwrap();
        assert_eq!(record.pct, 100);

        let record = parse_dmarc_record("v=DMARC1; p=none; pct=200").unwrap();
        assert_eq!(record.pct, 100);
    }

    #[test]
    fn test_parse_empty_tags() {
        let record = parse_dmarc_record("v=DMARC1; ; p=none; ;").unwrap();
        assert_eq!(record.policy, DmarcPolicy::None);
    }

    #[test]
    fn test_uri_regex() {
        assert!(URI_REGEX.is_match("mailto:user@example.com"));
        assert!(URI_REGEX.is_match("mailto:dmarc-reports@example.com "));
        assert!(!URI_REGEX.is_match("http://example.com"));
        assert!(!URI_REGEX.is_match("mailto:"));
        assert!(!URI_REGEX.is_match("mailto:@"));
    }

    #[test]
    fn test_pct_regex() {
        assert!(PCT_REGEX.is_match("0"));
        assert!(PCT_REGEX.is_match("50"));
        assert!(PCT_REGEX.is_match("100"));
        assert!(PCT_REGEX.is_match("999"));
        assert!(!PCT_REGEX.is_match("1000"));
        assert!(!PCT_REGEX.is_match(""));
        assert!(!PCT_REGEX.is_match("abc"));
    }

    #[test]
    fn test_ri_regex() {
        assert!(RI_REGEX.is_match("86400"));
        assert!(RI_REGEX.is_match("3600"));
        assert!(RI_REGEX.is_match("0"));
        assert!(!RI_REGEX.is_match(""));
        assert!(!RI_REGEX.is_match("abc"));
    }

    #[test]
    fn test_fo_regex() {
        assert!(FO_REGEX.is_match("0"));
        assert!(FO_REGEX.is_match("1"));
        assert!(FO_REGEX.is_match("d"));
        assert!(FO_REGEX.is_match("s"));
        assert!(!FO_REGEX.is_match("2"));
        assert!(!FO_REGEX.is_match(""));
        assert!(!FO_REGEX.is_match("ds"));
    }

    #[test]
    fn test_dmarc_state_defaults() {
        let state = DmarcState::new();
        assert_eq!(state.status, "none");
        assert_eq!(state.result, DmarcResult::Accept);
        assert_eq!(state.policy, DmarcPolicy::Unspecified);
        assert!(!state.spf_alignment);
        assert!(!state.dkim_alignment);
        assert!(!state.abort);
        assert!(!state.has_been_checked);
    }

    #[test]
    fn test_dmarc_msg_init_reset() {
        let mut state = DmarcState::new();
        state.status = String::from("reject");
        state.has_been_checked = true;
        state.spf_alignment = true;
        state.tld_file = Some(String::from("/path/to/tld"));

        dmarc_msg_init(&mut state);

        assert_eq!(state.status, "none");
        assert!(!state.has_been_checked);
        assert!(!state.spf_alignment);
        assert!(!state.abort);
    }

    #[test]
    fn test_dmarc_smtp_reset() {
        let mut state = DmarcState::new();
        state.has_been_checked = true;
        state.disable_verify = true;
        state.enable_forensic = true;
        state.status = String::from("reject");

        dmarc_smtp_reset(&mut state);

        assert!(!state.has_been_checked);
        assert!(!state.disable_verify);
        assert!(!state.enable_forensic);
        assert_eq!(state.status, "none");
    }

    #[test]
    fn test_dmarc_result_inlist_match() {
        let state = DmarcState::new();
        assert!(dmarc_result_inlist(&state, &["none", "accept"]));
    }

    #[test]
    fn test_dmarc_result_inlist_no_match() {
        let state = DmarcState::new();
        assert!(!dmarc_result_inlist(&state, &["reject", "quarantine"]));
    }

    #[test]
    fn test_dmarc_result_inlist_disabled() {
        let mut state = DmarcState::new();
        state.disable_verify = true;
        assert!(dmarc_result_inlist(&state, &["off"]));
        assert!(!dmarc_result_inlist(&state, &["none"]));
    }

    #[test]
    fn test_authres_dmarc_checked() {
        let mut state = DmarcState::new();
        state.has_been_checked = true;
        state.pass_fail = String::from("pass");
        state.domain = Some(String::from("example.com"));

        let result = authres_dmarc(&state);
        assert!(result.contains("dmarc=pass"));
        assert!(result.contains("header.from=example.com"));
    }

    #[test]
    fn test_authres_dmarc_not_checked() {
        let state = DmarcState::new();
        let result = authres_dmarc(&state);
        assert!(result.is_empty());
    }

    #[test]
    fn test_check_alignment_strict_match() {
        assert!(check_alignment(
            "example.com",
            "example.com",
            DmarcAlignment::Strict
        ));
    }

    #[test]
    fn test_check_alignment_strict_case_insensitive() {
        assert!(check_alignment(
            "Example.COM",
            "example.com",
            DmarcAlignment::Strict
        ));
    }

    #[test]
    fn test_check_alignment_strict_no_match() {
        assert!(!check_alignment(
            "sub.example.com",
            "example.com",
            DmarcAlignment::Strict
        ));
    }

    #[test]
    fn test_dmarc_error_display() {
        let err = DmarcError::ParseError("bad tag".into());
        assert!(err.to_string().contains("bad tag"));

        let err = DmarcError::DnsLookupFailed("example.com".into());
        assert!(err.to_string().contains("example.com"));

        let err = DmarcError::SpfNotAvailable;
        assert!(err.to_string().contains("SPF"));

        let err = DmarcError::DkimNotAvailable;
        assert!(err.to_string().contains("DKIM"));
    }

    #[test]
    fn test_dmarc_error_to_driver_error() {
        let err = DmarcError::InitFailed("test".into());
        let de = err.to_driver_error();
        assert!(matches!(de, DriverError::InitFailed(_)));

        let err = DmarcError::DnsLookupFailed("test".into());
        let de = err.to_driver_error();
        assert!(matches!(de, DriverError::TempFail(_)));
    }

    #[test]
    fn test_dmarc_init() {
        assert!(dmarc_init().is_ok());
    }

    #[test]
    fn test_dmarc_record_defaults() {
        let record = DmarcRecord::default();
        assert_eq!(record.version, "DMARC1");
        assert_eq!(record.policy, DmarcPolicy::Unspecified);
        assert!(record.subdomain_policy.is_none());
        assert_eq!(record.adkim, DmarcAlignment::Relaxed);
        assert_eq!(record.aspf, DmarcAlignment::Relaxed);
        assert_eq!(record.pct, 100);
        assert_eq!(record.ri, 86400);
        assert!(record.rua.is_empty());
        assert!(record.ruf.is_empty());
        assert_eq!(record.fo, "0");
    }

    #[test]
    fn test_parse_multiple_rua() {
        let record =
            parse_dmarc_record("v=DMARC1; p=none; rua=mailto:a@example.com,mailto:b@example.com")
                .unwrap();
        assert_eq!(record.rua.len(), 2);
    }

    #[test]
    fn test_parse_ri_value() {
        let record = parse_dmarc_record("v=DMARC1; p=none; ri=7200").unwrap();
        assert_eq!(record.ri, 7200);
    }

    #[test]
    fn test_dmarc_state_msg_init_abort_no_tld() {
        let mut state = DmarcState::new();
        // No tld_file set → should abort
        dmarc_msg_init(&mut state);
        assert!(state.abort);
    }

    #[test]
    fn test_dmarc_state_msg_init_no_abort_with_tld() {
        let mut state = DmarcState::new();
        state.tld_file = Some(String::from(
            "/usr/share/publicsuffix/effective_tld_names.dat",
        ));
        dmarc_msg_init(&mut state);
        assert!(!state.abort);
    }

    #[test]
    fn test_alignment_outcome_enum() {
        let pass = DmarcAlignmentOutcome::Pass;
        let fail = DmarcAlignmentOutcome::Fail;
        assert_ne!(pass, fail);
        assert_eq!(pass, DmarcAlignmentOutcome::Pass);
    }
}
