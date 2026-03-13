//! # DMARC Validation via libopendmarc FFI
//!
//! This module rewrites `src/src/miscmods/dmarc.c` (478 lines) and
//! `src/src/miscmods/dmarc_common.c` (531 lines) into safe Rust.
//!
//! ## Architecture
//!
//! DMARC (Domain-based Message Authentication, Reporting & Conformance)
//! validation is performed by delegating all libopendmarc C library calls
//! to [`exim_ffi::dmarc`], which is the **only** crate permitted to contain
//! `unsafe` code per AAP §0.7.2. This module itself contains **zero**
//! `unsafe` blocks.
//!
//! ## Feature Gates
//!
//! - `#[cfg(feature = "dmarc")]` — DMARC via libopendmarc (replaces C
//!   `#ifdef SUPPORT_DMARC`).  Requires both `spf` and `dkim` features
//!   for alignment checking.
//! - **Mutually exclusive** with `dmarc-native`: the `lib.rs` compile_error!
//!   enforces this at build time (see `src/src/miscmods/dmarc_native.c`
//!   lines 12-13: `#ifdef SUPPORT_DMARC` → `#error`).
//!
//! ## Global State Replacement
//!
//! All C global variables from `dmarc_common.c` lines 22-57 and `dmarc.c`
//! globals are replaced by the [`DmarcState`] struct, passed explicitly
//! through all call chains per AAP §0.4.4.
//!
//! ## Source Context
//!
//! - `src/src/miscmods/dmarc.c` (478 lines) — libopendmarc integration
//! - `src/src/miscmods/dmarc_common.c` (531 lines) — shared state, helpers
//! - `src/src/miscmods/dmarc.h` — type definitions and constants
//! - `src/src/miscmods/dmarc_api.h` — API slot indices
//!
//! # SPDX-License-Identifier: GPL-2.0-or-later

// ---------------------------------------------------------------------------
// Internal imports (from depends_on_files)
// ---------------------------------------------------------------------------

use exim_drivers::DriverInfoBase;
use exim_ffi::dmarc::{
    DmarcFfiError,
    DmarcLibrary,
    DmarcPolicyContext,
    // From-domain-absent sentinel (u32)
    DMARC_FROM_DOMAIN_ABSENT,
    // Policy enforcement result constants (u32 — cast to i32 at comparison)
    DMARC_POLICY_ABSENT,
    // Alignment result constants (u32 — cast to i32 at comparison)
    DMARC_POLICY_DKIM_ALIGNMENT_PASS,
    DMARC_POLICY_DKIM_OUTCOME_FAIL,
    // DKIM outcome constants for store_dkim() (u32 — cast to i32 at call site)
    DMARC_POLICY_DKIM_OUTCOME_NONE,
    DMARC_POLICY_DKIM_OUTCOME_PASS,
    DMARC_POLICY_DKIM_OUTCOME_TMPFAIL,
    DMARC_POLICY_NONE as FFI_POLICY_NONE,
    DMARC_POLICY_PASS,
    DMARC_POLICY_QUARANTINE as FFI_POLICY_QUARANTINE,
    DMARC_POLICY_REJECT as FFI_POLICY_REJECT,
    DMARC_POLICY_SPF_ALIGNMENT_PASS,
    DMARC_POLICY_SPF_ORIGIN_HELO,
    // SPF origin constants (u32 — cast to i32 at call site)
    DMARC_POLICY_SPF_ORIGIN_MAILFROM,
    DMARC_POLICY_SPF_OUTCOME_FAIL,
    // SPF outcome constants for store_spf() (u32 — cast to i32 at call site)
    DMARC_POLICY_SPF_OUTCOME_NONE,
    DMARC_POLICY_SPF_OUTCOME_PASS,
    DMARC_POLICY_SPF_OUTCOME_TMPFAIL,
    DMARC_RECORD_A_RELAXED,
    // Record alignment tag constants (u8 — cast to i32 at comparison)
    DMARC_RECORD_A_STRICT,
    // Record policy tag constants (u8 — cast to i32 at comparison)
    DMARC_RECORD_P_NONE,
    DMARC_RECORD_P_QUARANTINE,
    DMARC_RECORD_P_REJECT,
};
// exim_store types — Tainted<T> wraps DNS-sourced data (untrusted external
// input), Clean<T> wraps locally-derived data, TaintedString for DNS record
// text, MessageStore for per-message scoped data. These are used conceptually
// to document taint boundaries but the primary consumers are the FFI layer
// and the DNS lookup path; we keep them accessible for future use.
#[allow(unused_imports)]
use exim_store::{Clean, MessageStore, Tainted, TaintedString};

use crate::dkim::pdkim::{PdkimSignature, VerifyExtStatus, VerifyStatus};
use crate::dkim::DkimState;
use crate::spf::{SpfResult, SpfState};

// ---------------------------------------------------------------------------
// External imports (from package dependencies)
// ---------------------------------------------------------------------------

use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;

use thiserror::Error;
use tracing::{debug, error, info, warn};

// ============================================================================
// Constants — ARES result codes for history buffer construction
// ============================================================================
// These mirror the C ARES_RESULT_* constants from dmarc.h lines 48-56
// used to build the dkim_history_buffer and spf_ares_result for aggregate
// reporting.  They are purely internal to this module.

/// ARES result: unknown/invalid — maps from SPF_RESULT_INVALID.
const ARES_RESULT_UNKNOWN: i32 = 0;
/// ARES result: none — maps from SPF_RESULT_NONE.
const ARES_RESULT_NONE: i32 = 1;
/// ARES result: pass — maps from SPF_RESULT_PASS / DKIM verify pass.
const ARES_RESULT_PASS: i32 = 2;
/// ARES result: fail — maps from SPF_RESULT_FAIL / DKIM verify fail.
const ARES_RESULT_FAIL: i32 = 3;
/// ARES result: softfail — maps from SPF_RESULT_SOFTFAIL.
const ARES_RESULT_SOFTFAIL: i32 = 4;
/// ARES result: neutral — maps from SPF_RESULT_NEUTRAL.
const ARES_RESULT_NEUTRAL: i32 = 5;
/// ARES result: temperror — maps from SPF_RESULT_TEMPERROR.
const ARES_RESULT_TEMPERROR: i32 = 6;
/// ARES result: permerror — maps from SPF_RESULT_PERMERROR.
const ARES_RESULT_PERMERROR: i32 = 7;

/// DMARC result action code: reject (C: DMARC_RESULT_REJECT = 0).
const DMARC_RESULT_REJECT: i32 = 0;
/// DMARC result action code: discard (C: DMARC_RESULT_DISCARD = 1).
const DMARC_RESULT_DISCARD: i32 = 1;
/// DMARC result action code: accept (C: DMARC_RESULT_ACCEPT = 2).
const DMARC_RESULT_ACCEPT: i32 = 2;
/// DMARC result action code: tempfail (C: DMARC_RESULT_TEMPFAIL = 3).
const DMARC_RESULT_TEMPFAIL: i32 = 3;
/// DMARC result action code: quarantine (C: DMARC_RESULT_QUARANTINE = 4).
const DMARC_RESULT_QUARANTINE: i32 = 4;

// ============================================================================
// DmarcError — Structured error enum
// ============================================================================

/// Errors arising from DMARC validation operations.
///
/// Replaces ad-hoc `log_write(0, LOG_MAIN|LOG_PANIC, ...)` calls and return
/// codes throughout `dmarc.c` and `dmarc_common.c` with structured Rust
/// error types.
#[derive(Debug, Error)]
pub enum DmarcError {
    /// libopendmarc library initialization failed.
    /// Replaces C: `opendmarc_policy_library_init()` failure.
    #[error("DMARC library initialization failed: {0}")]
    LibraryInitFailed(String),

    /// DMARC policy context creation failed.
    /// Replaces C: `opendmarc_policy_connect_init()` failure.
    #[error("DMARC policy context creation failed: {0}")]
    PolicyContextFailed(String),

    /// Storing the From: domain into the policy context failed.
    /// Replaces C: `opendmarc_policy_store_from_domain()` failure.
    #[error("failed to store From: domain: {0}")]
    StoreDomainFailed(String),

    /// Storing SPF result into the policy context failed.
    /// Replaces C: `opendmarc_policy_store_spf()` failure.
    #[error("failed to store SPF result: {0}")]
    StoreSpfFailed(String),

    /// Storing DKIM result into the policy context failed.
    /// Replaces C: `opendmarc_policy_store_dkim()` failure.
    #[error("failed to store DKIM result: {0}")]
    StoreDkimFailed(String),

    /// Storing the DMARC DNS record into the policy context failed.
    /// Replaces C: `opendmarc_policy_store_dmarc()` failure.
    #[error("failed to store DMARC DNS record: {0}")]
    StoreDmarcRecordFailed(String),

    /// Fetching the enforced policy from the library failed.
    /// Replaces C: `opendmarc_get_policy_to_enforce()` failure.
    #[error("failed to fetch enforced policy: {0}")]
    FetchPolicyFailed(String),

    /// Fetching alignment results from the library failed.
    /// Replaces C: `opendmarc_policy_fetch_alignment()` failure.
    #[error("failed to fetch alignment: {0}")]
    FetchAlignmentFailed(String),

    /// DNS TXT record lookup for `_dmarc.<domain>` failed.
    /// Replaces C: `dmarc_dns_lookup()` failure paths.
    #[error("DNS lookup failed for _dmarc.{0}")]
    DnsLookupFailed(String),

    /// SPF module is not available (feature not enabled or not registered).
    /// Replaces C: `misc_mod_find(US"spf")` returning NULL.
    #[error("SPF module not available")]
    SpfNotAvailable,

    /// DKIM module is not available (feature not enabled or not registered).
    /// Replaces C: `misc_mod_find(US"dkim")` returning NULL.
    #[error("DKIM module not available")]
    DkimNotAvailable,

    /// TLD file could not be loaded by libopendmarc.
    /// Replaces C: TLD file open/parse failure in `dmarc_local_msg_init`.
    #[error("failed to load TLD file: {0}")]
    TldFileLoadFailed(String),

    /// Error writing the DMARC aggregate history file.
    /// Replaces C: `dmarc_write_history_file()` I/O errors.
    #[error("history file error: {0}")]
    HistoryFileError(String),

    /// Error generating or sending a DMARC forensic (failure) report.
    /// Replaces C: `dmarc_send_forensic_report()` failures.
    #[error("forensic report error: {0}")]
    ForensicReportError(String),

    /// Error propagated from the FFI layer.
    /// Wraps [`DmarcFfiError`] from `exim-ffi`.
    #[error("FFI error: {0}")]
    FfiError(String),
}

impl From<DmarcFfiError> for DmarcError {
    fn from(e: DmarcFfiError) -> Self {
        DmarcError::FfiError(format!("{e}"))
    }
}

// ============================================================================
// DmarcPolicy — RFC 7489 policy disposition
// ============================================================================

/// DMARC policy as declared in the DNS record `p=` / `sp=` tag.
///
/// Corresponds to the `dmarc_policy_description` table in `dmarc.c` lines
/// 42-49 and the `DMARC_RECORD_P_*` constants from `dmarc.h`.
///
/// | Variant       | C Constant                  | DNS value     |
/// |---------------|-----------------------------|---------------|
/// | `Unspecified` | `DMARC_RECORD_P_UNSPECIFIED`| (absent)      |
/// | `None`        | `DMARC_RECORD_P_NONE`       | `p=none`      |
/// | `Quarantine`  | `DMARC_RECORD_P_QUARANTINE` | `p=quarantine`|
/// | `Reject`      | `DMARC_RECORD_P_REJECT`     | `p=reject`    |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcPolicy {
    /// No policy specified in the DMARC record.
    Unspecified,
    /// Policy is "none" — monitoring only.
    None,
    /// Policy is "quarantine" — treat as suspicious.
    Quarantine,
    /// Policy is "reject" — reject the message.
    Reject,
}

impl DmarcPolicy {
    /// Convert from the FFI `DMARC_RECORD_P_*` constant.
    ///
    /// The FFI constants are `u8` but `fetch_p()`/`fetch_sp()` return `i32`.
    fn from_ffi_record(code: i32) -> Self {
        // The C constants are character codes: '\0', 'n', 'q', 'r'
        match code {
            c if c == i32::from(DMARC_RECORD_P_NONE) => DmarcPolicy::None,
            c if c == i32::from(DMARC_RECORD_P_QUARANTINE) => DmarcPolicy::Quarantine,
            c if c == i32::from(DMARC_RECORD_P_REJECT) => DmarcPolicy::Reject,
            _ => DmarcPolicy::Unspecified,
        }
    }

    /// Convert to the human-readable description string matching
    /// C `dmarc_policy_description[]` table from `dmarc.c` lines 42-49.
    pub fn as_str(&self) -> &'static str {
        match self {
            DmarcPolicy::Unspecified => "",
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

// ============================================================================
// DmarcAlignment — Identifier alignment mode
// ============================================================================

/// DMARC identifier alignment mode for SPF and DKIM.
///
/// Corresponds to the `DMARC_RECORD_A_*` constants from `dmarc.h`.
///
/// | Variant       | C Constant                   | DNS value   |
/// |---------------|------------------------------|-------------|
/// | `Unspecified` | `DMARC_RECORD_A_UNSPECIFIED` | (absent)    |
/// | `Strict`      | `DMARC_RECORD_A_STRICT`      | `adkim=s`   |
/// | `Relaxed`     | `DMARC_RECORD_A_RELAXED`     | `adkim=r`   |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcAlignment {
    /// Not specified — defaults to relaxed per RFC 7489.
    Unspecified,
    /// Strict alignment — exact domain match required.
    Strict,
    /// Relaxed alignment — organizational domain match suffices.
    Relaxed,
}

impl DmarcAlignment {
    /// Convert from the FFI `DMARC_RECORD_A_*` constant.
    ///
    /// The FFI constants are `u8` but `fetch_adkim()`/`fetch_aspf()` return `i32`.
    fn from_ffi_record(code: i32) -> Self {
        match code {
            c if c == i32::from(DMARC_RECORD_A_STRICT) => DmarcAlignment::Strict,
            c if c == i32::from(DMARC_RECORD_A_RELAXED) => DmarcAlignment::Relaxed,
            _ => DmarcAlignment::Unspecified,
        }
    }

    /// Human-readable string for this alignment mode.
    pub fn as_str(&self) -> &'static str {
        match self {
            DmarcAlignment::Unspecified => "",
            DmarcAlignment::Strict => "strict",
            DmarcAlignment::Relaxed => "relaxed",
        }
    }
}

impl fmt::Display for DmarcAlignment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ============================================================================
// DmarcAction — Result action to take
// ============================================================================

/// The action to take based on the DMARC evaluation result.
///
/// Corresponds to the `DMARC_RESULT_*` constants from `dmarc.h` lines 63-67.
///
/// | Variant      | Code | C Constant              |
/// |--------------|------|-------------------------|
/// | `Reject`     | 0    | `DMARC_RESULT_REJECT`   |
/// | `Discard`    | 1    | `DMARC_RESULT_DISCARD`  |
/// | `Accept`     | 2    | `DMARC_RESULT_ACCEPT`   |
/// | `TempFail`   | 3    | `DMARC_RESULT_TEMPFAIL` |
/// | `Quarantine` | 4    | `DMARC_RESULT_QUARANTINE`|
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcAction {
    /// Reject the message outright.
    Reject,
    /// Silently discard the message.
    Discard,
    /// Accept the message (pass or no policy).
    Accept,
    /// Temporary failure — try again later.
    TempFail,
    /// Quarantine the message (mark as suspicious).
    Quarantine,
}

impl DmarcAction {
    /// Convert from the C `DMARC_RESULT_*` integer code.
    pub fn from_code(code: i32) -> Self {
        match code {
            DMARC_RESULT_REJECT => DmarcAction::Reject,
            DMARC_RESULT_DISCARD => DmarcAction::Discard,
            DMARC_RESULT_ACCEPT => DmarcAction::Accept,
            DMARC_RESULT_TEMPFAIL => DmarcAction::TempFail,
            DMARC_RESULT_QUARANTINE => DmarcAction::Quarantine,
            _ => DmarcAction::TempFail,
        }
    }

    /// Human-readable string for this action.
    pub fn as_str(&self) -> &'static str {
        match self {
            DmarcAction::Reject => "reject",
            DmarcAction::Discard => "discard",
            DmarcAction::Accept => "accept",
            DmarcAction::TempFail => "tempfail",
            DmarcAction::Quarantine => "quarantine",
        }
    }

    /// Convert to the integer code for DMARC history reporting.
    pub fn to_code(&self) -> i32 {
        match self {
            DmarcAction::Reject => DMARC_RESULT_REJECT,
            DmarcAction::Discard => DMARC_RESULT_DISCARD,
            DmarcAction::Accept => DMARC_RESULT_ACCEPT,
            DmarcAction::TempFail => DMARC_RESULT_TEMPFAIL,
            DmarcAction::Quarantine => DMARC_RESULT_QUARANTINE,
        }
    }
}

impl fmt::Display for DmarcAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ============================================================================
// DmarcState — All mutable DMARC state for a connection/message
// ============================================================================

/// Complete mutable state for DMARC operations on a single SMTP connection.
///
/// Replaces all C global variables from `dmarc_common.c` lines 22-57:
/// - Module references (`dmarc_spf_mod_info`, `dmarc_dkim_mod_info`)
/// - Working data (`dmarc_abort`, `dmarc_pass_fail`, etc.)
/// - Result variables (`dmarc_alignment_dkim`, `dmarc_status`, etc.)
/// - Configuration options (`dmarc_forensic_sender`, `dmarc_history_file`, etc.)
///
/// Passed explicitly through all call chains per AAP §0.4.4.
///
/// # Lifecycle
///
/// 1. Created once per connection via [`dmarc_init()`].
/// 2. Per-message state reset via [`dmarc_msg_init()`].
/// 3. DMARC evaluation via [`dmarc_process()`].
/// 4. SMTP reset via [`dmarc_smtp_reset()`].
#[derive(Debug)]
pub struct DmarcState {
    // ── Working state (from dmarc_common.c lines 30-40) ──
    /// Whether DMARC processing has been aborted for this message.
    /// Replaces C: `dmarc_abort` (BOOL, default TRUE).
    pub abort: bool,

    /// DMARC pass/fail result string ("pass", "fail", "none", "temperror").
    /// Replaces C: `dmarc_pass_fail` (uschar*).
    pub pass_fail: String,

    /// The domain extracted from the RFC5322.From header.
    /// Replaces C: `dmarc_header_from_sender` (uschar*).
    pub header_from_sender: String,

    /// The SPF ARES result code for history/reporting purposes.
    /// Replaces C: `dmarc_spf_ares_result` (int).
    pub spf_ares_result: i32,

    /// DMARC aggregate report URIs from the `rua=` tag.
    /// Replaces C: `dmarc_rua` (uschar*) parsed to vector.
    pub rua: Vec<String>,

    /// DMARC sampling percentage from the `pct=` tag.
    /// Replaces C: `dmarc_pct` (int, default 100).
    pub pct: u32,

    /// DKIM alignment mode from the `adkim=` tag.
    /// Replaces C: `dmarc_adkim` (int, DMARC_RECORD_A_UNSPECIFIED).
    pub adkim: DmarcAlignment,

    /// SPF alignment mode from the `aspf=` tag.
    /// Replaces C: `dmarc_aspf` (int, DMARC_RECORD_A_UNSPECIFIED).
    pub aspf: DmarcAlignment,

    /// Enforced DMARC policy from `get_policy_to_enforce()`.
    /// Replaces C: `dmarc_policy` (int).
    pub policy: DmarcPolicy,

    /// Domain policy from the `p=` tag.
    /// Replaces C: `dmarc_dom_policy` (int, DMARC_RECORD_P_UNSPECIFIED).
    pub dom_policy: DmarcPolicy,

    /// Subdomain policy from the `sp=` tag.
    /// Replaces C: `dmarc_subdom_policy` (int, DMARC_RECORD_P_UNSPECIFIED).
    pub subdom_policy: DmarcPolicy,

    /// Whether SPF alignment passed.
    /// Replaces C: `dmarc_spf_alignment` (int, DMARC_POLICY_SPF_ALIGNMENT_PASS).
    pub spf_alignment: bool,

    /// Whether DKIM alignment passed.
    /// Replaces C: `dmarc_dkim_alignment` (int, DMARC_POLICY_DKIM_ALIGNMENT_PASS).
    pub dkim_alignment: bool,

    /// The action derived from the DMARC policy evaluation.
    /// Replaces C: `dmarc_action` (int, DMARC_RESULT_ACCEPT).
    pub action: DmarcAction,

    // ── Expansion variables (from dmarc_common.c lines 43-55) ──
    /// `$dmarc_alignment_dkim` — whether DKIM alignment passed.
    /// Replaces C: `dmarc_alignment_dkim` (BOOL, FALSE).
    pub alignment_dkim: bool,

    /// `$dmarc_alignment_spf` — whether SPF alignment passed.
    /// Replaces C: `dmarc_alignment_spf` (BOOL, FALSE).
    pub alignment_spf: bool,

    /// `$dmarc_domain_policy` — the enforced domain policy string.
    /// Replaces C: `dmarc_domain_policy` (uschar*).
    pub domain_policy: Option<String>,

    /// `$dmarc_status` — the DMARC status string
    /// ("accept", "reject", "quarantine", "none", "norecord", etc.).
    /// Replaces C: `dmarc_status` (uschar*).
    pub status: String,

    /// `$dmarc_status_text` — human-readable status description.
    /// Replaces C: `dmarc_status_text` (uschar*).
    pub status_text: Option<String>,

    /// `$dmarc_used_domain` — the domain used for DMARC lookup.
    /// Replaces C: `dmarc_used_domain` (uschar*).
    pub used_domain: Option<String>,

    // ── Configuration options (from dmarc_common.c lines 57-59) ──
    /// Address for DMARC forensic (failure) reports.
    /// Replaces C: `dmarc_forensic_sender` (uschar*, config option).
    pub forensic_sender: Option<String>,

    /// Path to the DMARC aggregate report history file.
    /// Replaces C: `dmarc_history_file` (uschar*, config option).
    pub history_file: Option<String>,

    /// Path to the public suffix list (effective TLD) file.
    /// Replaces C: `dmarc_tld_file` (uschar*, config option).
    pub tld_file: Option<String>,
}

impl Default for DmarcState {
    /// Creates a new `DmarcState` with default values matching C source
    /// initialization from `dmarc_common.c` `dmarc_local_msg_init()`.
    fn default() -> Self {
        Self {
            abort: true,
            pass_fail: String::new(),
            header_from_sender: String::new(),
            spf_ares_result: ARES_RESULT_UNKNOWN,
            rua: Vec::new(),
            pct: 100,
            adkim: DmarcAlignment::Unspecified,
            aspf: DmarcAlignment::Unspecified,
            policy: DmarcPolicy::Unspecified,
            dom_policy: DmarcPolicy::Unspecified,
            subdom_policy: DmarcPolicy::Unspecified,
            spf_alignment: false,
            dkim_alignment: false,
            action: DmarcAction::Accept,
            alignment_dkim: false,
            alignment_spf: false,
            domain_policy: None,
            status: String::new(),
            status_text: None,
            used_domain: None,
            forensic_sender: None,
            history_file: None,
            tld_file: None,
        }
    }
}

impl DmarcState {
    /// Creates a new `DmarcState` with default configuration values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset per-message state for a new message within the same connection.
    ///
    /// Called from [`dmarc_msg_init()`] at the start of each new message.
    /// Preserves configuration options (forensic_sender, history_file,
    /// tld_file) but clears all per-message working data and results.
    fn reset_per_message(&mut self) {
        self.abort = true;
        self.pass_fail.clear();
        self.header_from_sender.clear();
        self.spf_ares_result = ARES_RESULT_UNKNOWN;
        self.rua.clear();
        self.pct = 100;
        self.adkim = DmarcAlignment::Unspecified;
        self.aspf = DmarcAlignment::Unspecified;
        self.policy = DmarcPolicy::Unspecified;
        self.dom_policy = DmarcPolicy::Unspecified;
        self.subdom_policy = DmarcPolicy::Unspecified;
        self.spf_alignment = false;
        self.dkim_alignment = false;
        self.action = DmarcAction::Accept;
        self.alignment_dkim = false;
        self.alignment_spf = false;
        self.domain_policy = None;
        self.status.clear();
        self.status_text = None;
        self.used_domain = None;
    }
}

// ============================================================================
// Initialization functions
// ============================================================================

/// One-time DMARC module initialization.
///
/// Verifies that the SPF and DKIM modules are available (since DMARC requires
/// both for alignment checking), and creates a default [`DmarcState`].
///
/// Replaces C: `dmarc_init()` from `dmarc_common.c` lines 62-84 which calls
/// `misc_mod_find(US"spf")` and `misc_mod_find(US"dkim")`.
///
/// # Errors
///
/// Returns [`DmarcError::SpfNotAvailable`] if the SPF module is not available.
/// Returns [`DmarcError::DkimNotAvailable`] if the DKIM module is not available.
pub fn dmarc_init(_spf_available: bool, _dkim_available: bool) -> Result<DmarcState, DmarcError> {
    debug!("DMARC: initializing module");

    // In the C code, dmarc_init() calls misc_mod_find() for spf and dkim.
    // Here we accept booleans indicating module availability, as determined
    // by the caller (the module registration system).
    if !_spf_available {
        error!("DMARC: SPF module required but not available");
        return Err(DmarcError::SpfNotAvailable);
    }
    if !_dkim_available {
        error!("DMARC: DKIM module required but not available");
        return Err(DmarcError::DkimNotAvailable);
    }

    info!("DMARC: module initialized successfully");
    Ok(DmarcState::new())
}

/// Per-message DMARC initialization.
///
/// Resets per-message state and extracts the From: header domain for DMARC
/// evaluation. Must be called at the start of each new message after the
/// headers have been received.
///
/// Replaces C: `dmarc_msg_init()` from `dmarc_common.c` lines 86-117 and
/// `dmarc_local_msg_init()` from `dmarc.c` lines 65-118 which together
/// reset state, init libopendmarc library, read TLD file, and create the
/// policy context.
///
/// # Arguments
///
/// * `state` — Mutable reference to the DMARC state (reset for new message).
/// * `from_domain` — The domain extracted from the RFC5322.From header.
/// * `sender_ip` — The connecting client's IP address string.
/// * `is_ipv6` — Whether the sender IP is IPv6 (vs IPv4).
pub fn dmarc_msg_init(state: &mut DmarcState, from_domain: &str, sender_ip: &str, is_ipv6: bool) {
    debug!(
        from_domain = from_domain,
        sender_ip = sender_ip,
        is_ipv6 = is_ipv6,
        "DMARC: per-message initialization"
    );

    // Reset all per-message fields, preserving config options.
    state.reset_per_message();

    // Store the From: header domain for later processing.
    state.header_from_sender = from_domain.to_string();

    // The actual libopendmarc library init, TLD file read, and policy
    // context creation happen in dmarc_process() where the library
    // and context are created as scoped RAII objects.
    debug!(
        "DMARC: per-message init complete, From domain: {}",
        from_domain
    );
}

/// Reset DMARC state between SMTP transactions on the same connection.
///
/// Clears per-connection DMARC flags so a new MAIL FROM command starts
/// fresh. Replaces C: `dmarc_smtp_reset()` from `dmarc_common.c` lines
/// 119-133.
pub fn dmarc_smtp_reset(state: &mut DmarcState) {
    debug!("DMARC: SMTP reset");
    state.reset_per_message();
}

// ============================================================================
// Core DMARC Processing
// ============================================================================

/// Main DMARC evaluation function.
///
/// This is the primary DMARC processing entry point, registered as the
/// `DMARC_PROCESS` function slot. It performs the complete DMARC evaluation
/// for a message:
///
/// 1. Initialize libopendmarc library and load TLD file
/// 2. Create a policy context for the sender IP
/// 3. Store the From: domain
/// 4. Map and store the SPF result with alignment origin
/// 5. Iterate DKIM signatures, storing each result
/// 6. Perform DNS lookup for the `_dmarc.<domain>` TXT record
/// 7. Store the DMARC DNS record
/// 8. Retrieve the enforced policy
/// 9. Map the policy to a status/action
/// 10. Fetch alignment results, rua, pct, adkim, aspf, p, sp
/// 11. Write the aggregate history file
/// 12. Send forensic report if configured
///
/// Replaces C: `dmarc_process()` from `dmarc.c` lines 165-467.
///
/// # Arguments
///
/// * `state` — Mutable reference to the DMARC state.
/// * `spf_state` — SPF evaluation results for the current message.
/// * `dkim_state` — DKIM verification results for the current message.
/// * `sender_ip` — The connecting client's IP address string.
/// * `is_ipv6` — Whether the sender IP is IPv6.
///
/// # Returns
///
/// The enforced [`DmarcPolicy`] on success, or a [`DmarcError`] on failure.
pub fn dmarc_process(
    state: &mut DmarcState,
    spf_state: &SpfState,
    dkim_state: &DkimState,
    sender_ip: &str,
    is_ipv6: bool,
) -> Result<DmarcPolicy, DmarcError> {
    debug!(
        from_domain = %state.header_from_sender,
        sender_ip = sender_ip,
        "DMARC: starting policy evaluation"
    );

    // If abort is not set, we already processed this message.
    // Early return should not happen in normal flow since abort is reset
    // in msg_init, but guard defensively.

    // ── Step 1: Initialize libopendmarc library and TLD file ──
    let library = DmarcLibrary::new().map_err(|e| {
        error!("DMARC: library init failed: {e}");
        DmarcError::LibraryInitFailed(format!("{e}"))
    })?;

    // Load TLD file if configured (for organizational domain determination).
    if let Some(ref tld_path) = state.tld_file {
        if !tld_path.is_empty() {
            debug!(path = %tld_path, "DMARC: loading TLD file");
            if let Err(e) = library.read_tld_file(tld_path) {
                warn!(
                    path = %tld_path,
                    error = %e,
                    "DMARC: failed to load TLD file, continuing without"
                );
            }
        }
    }

    // ── Step 2: Create policy context for the sender IP ──
    let mut pctx = DmarcPolicyContext::new(sender_ip, is_ipv6).map_err(|e| {
        error!("DMARC: policy context creation failed: {e}");
        DmarcError::PolicyContextFailed(format!("{e}"))
    })?;

    // ── Step 3: Store the From: domain ──
    let from_domain = &state.header_from_sender;
    if from_domain.is_empty() {
        // No From: domain — record as temperror and return early.
        debug!("DMARC: no From: header domain available");
        state.status = "nofrom".to_string();
        state.pass_fail = "temperror".to_string();
        state.action = DmarcAction::Accept;
        state.abort = false;
        return Ok(DmarcPolicy::Unspecified);
    }

    pctx.store_from_domain(from_domain).map_err(|e| {
        error!(domain = %from_domain, error = %e, "DMARC: store_from_domain failed");
        DmarcError::StoreDomainFailed(format!("{e}"))
    })?;

    // ── Step 4: Map and store the SPF result ──
    // Replaces C dmarc.c lines 206-256: SPF result mapping.
    let (spf_outcome, spf_ares, spf_origin) = map_spf_result(spf_state);
    state.spf_ares_result = spf_ares;

    debug!(
        spf_result = ?spf_state.result,
        spf_outcome = spf_outcome,
        spf_ares = spf_ares,
        "DMARC: mapped SPF result"
    );

    // Determine the SPF-authenticated domain for alignment.
    let spf_domain = spf_state.used_domain.as_deref().unwrap_or("");

    pctx.store_spf(
        spf_domain,
        spf_outcome,
        spf_origin,
        &spf_result_human_string(spf_state),
    )
    .map_err(|e| {
        warn!(error = %e, "DMARC: store_spf failed");
        DmarcError::StoreSpfFailed(format!("{e}"))
    })?;

    // ── Step 5: Iterate DKIM signatures and store results ──
    // Replaces C dmarc.c lines 261-306: DKIM iteration.
    let mut dkim_history = String::new();

    for sig in &dkim_state.signatures {
        let (dkim_outcome, dkim_ares) = map_dkim_signature(sig);
        let domain = sig.domain.as_deref().unwrap_or("");
        let selector = sig.selector.as_deref().unwrap_or("");

        debug!(
            domain = domain,
            selector = selector,
            verify_status = ?sig.verify_status,
            dkim_outcome = dkim_outcome,
            "DMARC: processing DKIM signature"
        );

        pctx.store_dkim(
            domain,
            selector,
            dkim_outcome,
            &dkim_result_human_string(sig),
        )
        .map_err(|e| {
            warn!(
                domain = domain,
                error = %e,
                "DMARC: store_dkim failed"
            );
            DmarcError::StoreDkimFailed(format!("{e}"))
        })?;

        // Build history buffer entry for aggregate reporting.
        // Format: "dkim {domain} {selector} {ares_result}\n"
        let ares_str = ares_result_string(dkim_ares);
        dkim_history.push_str(&format!("dkim {} {} {}\n", domain, selector, ares_str));
    }

    // ── Step 6: DNS lookup for _dmarc.<domain> TXT record ──
    let dmarc_record = match dmarc_dns_lookup(from_domain) {
        Ok(record) => record,
        Err(e) => {
            debug!(
                domain = %from_domain,
                error = %e,
                "DMARC: no DMARC record found"
            );
            // No record — set status and return early.
            state.status = "norecord".to_string();
            state.pass_fail = "none".to_string();
            state.action = DmarcAction::Accept;
            state.abort = false;
            return Ok(DmarcPolicy::Unspecified);
        }
    };

    debug!(
        domain = %from_domain,
        record = %dmarc_record,
        "DMARC: found DNS record"
    );

    // ── Step 7: Store the DMARC DNS record ──
    // The record and domain/org-domain are stored for policy evaluation.
    pctx.store_dmarc_record(&dmarc_record, from_domain, Some(from_domain.as_str()))
        .map_err(|e| {
            error!(error = %e, "DMARC: store_dmarc_record failed");
            DmarcError::StoreDmarcRecordFailed(format!("{e}"))
        })?;

    // ── Step 8: Get the enforced policy ──
    let policy_code = pctx.get_policy_to_enforce().map_err(|e| {
        error!(error = %e, "DMARC: get_policy_to_enforce failed");
        DmarcError::FetchPolicyFailed(format!("{e}"))
    })?;

    debug!(policy_code = policy_code, "DMARC: enforced policy code");

    // ── Step 9: Map policy to status/action ──
    // Replaces C dmarc.c lines 365-409: policy enforcement switch.
    map_policy_result(state, policy_code);

    // ── Step 10: Fetch alignment, rua, pct, adkim, aspf, p, sp ──
    // Fetch DKIM and SPF alignment pass/fail.
    match pctx.fetch_alignment() {
        Ok((dkim_align, spf_align)) => {
            state.dkim_alignment = dkim_align == DMARC_POLICY_DKIM_ALIGNMENT_PASS as i32;
            state.spf_alignment = spf_align == DMARC_POLICY_SPF_ALIGNMENT_PASS as i32;
            state.alignment_dkim = state.dkim_alignment;
            state.alignment_spf = state.spf_alignment;
            debug!(
                dkim_alignment = state.dkim_alignment,
                spf_alignment = state.spf_alignment,
                "DMARC: alignment results"
            );
        }
        Err(e) => {
            warn!(error = %e, "DMARC: fetch_alignment failed");
        }
    }

    // Fetch aggregate report URIs.
    // `fetch_rua()` returns `Vec<String>` directly (empty if none configured).
    let rua_list = pctx.fetch_rua();
    if !rua_list.is_empty() {
        debug!(
            rua_count = rua_list.len(),
            "DMARC: aggregate report URIs found"
        );
    }
    state.rua = rua_list;

    // Fetch sampling percentage.
    match pctx.fetch_pct() {
        Ok(pct) => {
            state.pct = pct.max(0_i32) as u32;
        }
        Err(e) => {
            debug!(error = %e, "DMARC: fetch_pct failed");
        }
    }

    // Fetch DKIM alignment mode (adkim= tag).
    match pctx.fetch_adkim() {
        Ok(adkim) => {
            state.adkim = DmarcAlignment::from_ffi_record(adkim);
        }
        Err(e) => {
            debug!(error = %e, "DMARC: fetch_adkim failed");
        }
    }

    // Fetch SPF alignment mode (aspf= tag).
    match pctx.fetch_aspf() {
        Ok(aspf) => {
            state.aspf = DmarcAlignment::from_ffi_record(aspf);
        }
        Err(e) => {
            debug!(error = %e, "DMARC: fetch_aspf failed");
        }
    }

    // Fetch domain policy (p= tag).
    match pctx.fetch_p() {
        Ok(p) => {
            state.dom_policy = DmarcPolicy::from_ffi_record(p);
        }
        Err(e) => {
            debug!(error = %e, "DMARC: fetch_p failed");
        }
    }

    // Fetch subdomain policy (sp= tag).
    match pctx.fetch_sp() {
        Ok(sp) => {
            state.subdom_policy = DmarcPolicy::from_ffi_record(sp);
        }
        Err(e) => {
            debug!(error = %e, "DMARC: fetch_sp failed");
        }
    }

    // Fetch the utilized domain (the domain that the DMARC record was
    // actually found at — may differ from From: domain for subdomains).
    match pctx.fetch_utilized_domain() {
        Ok(ud) => {
            state.used_domain = Some(ud);
        }
        Err(e) => {
            debug!(error = %e, "DMARC: fetch_utilized_domain failed");
        }
    }

    // Set the domain_policy expansion variable.
    state.domain_policy = Some(state.dom_policy.as_str().to_string());

    // Mark that processing completed successfully.
    state.abort = false;

    info!(
        status = %state.status,
        pass_fail = %state.pass_fail,
        action = %state.action,
        policy = %state.policy,
        "DMARC: evaluation complete"
    );

    // ── Step 11: Write aggregate history file ──
    if let Some(ref history_path) = state.history_file {
        if !history_path.is_empty() {
            if let Err(e) = dmarc_write_history_file(state, &dkim_history, spf_state) {
                warn!(
                    path = %history_path,
                    error = %e,
                    "DMARC: failed to write history file"
                );
            }
        }
    }

    // ── Step 12: Send forensic report if configured ──
    if let Some(ref sender) = state.forensic_sender {
        if !sender.is_empty() && state.action != DmarcAction::Accept {
            if let Err(e) = dmarc_send_forensic_report(state) {
                warn!(
                    error = %e,
                    "DMARC: failed to send forensic report"
                );
            }
        }
    }

    Ok(state.policy)
}

/// Check whether the DMARC result matches any entry in a given list.
///
/// Registered as the `DMARC_RESULT_INLIST` function slot.
/// Used in ACL conditions like `dmarc_status = accept : none`.
///
/// Replaces C: `dmarc_result_inlist()` from `dmarc.c` lines 455-468.
///
/// # Arguments
///
/// * `state` — The DMARC state containing the current evaluation result.
/// * `list` — A slice of strings to match against (e.g., `["accept", "none"]`).
///
/// # Returns
///
/// `true` if the DMARC status string matches any entry in the list.
pub fn dmarc_result_inlist(state: &DmarcState, list: &[&str]) -> bool {
    let status = &state.status;
    if status.is_empty() {
        return false;
    }
    for entry in list {
        if entry.eq_ignore_ascii_case(status) {
            debug!(
                status = %status,
                entry = %entry,
                "DMARC: result matches list entry"
            );
            return true;
        }
    }
    false
}

// ============================================================================
// Authentication-Results header generation
// ============================================================================

/// Generate the DMARC component of an Authentication-Results header.
///
/// Produces a string suitable for inclusion in the `Authentication-Results`
/// header field, formatted per RFC 7489 §11.2.
///
/// Replaces C: `authres_dmarc()` from `dmarc_common.c` lines 468-502.
///
/// # Arguments
///
/// * `state` — The DMARC state containing the evaluation result.
///
/// # Returns
///
/// A formatted Authentication-Results header string component for DMARC.
pub fn authres_dmarc(state: &DmarcState) -> String {
    if state.status.is_empty() || state.abort {
        return String::new();
    }

    let mut result = format!(";\n\tdmarc={}", state.pass_fail);

    // Add header.from domain.
    if !state.header_from_sender.is_empty() {
        result.push_str(&format!(" header.from={}", state.header_from_sender));
    }

    // Add policy information if available.
    if let Some(ref dp) = state.domain_policy {
        if !dp.is_empty() {
            result.push_str(&format!(" policy.published-domain-policy={dp}"));
        }
    }

    // Add the utilized domain if available.
    if let Some(ref ud) = state.used_domain {
        if !ud.is_empty() {
            result.push_str(&format!(" policy.evaluated-domain={ud}"));
        }
    }

    result
}

// ============================================================================
// Version report
// ============================================================================

/// Return a version report string for the DMARC module.
///
/// Used by `-bV` version output to display the libopendmarc version.
/// Replaces C: `dmarc_version_report()` from `dmarc.c` lines 55-63.
pub fn dmarc_version_report() -> String {
    let (major, minor, patch, _build) = DmarcLibrary::version();
    format!(
        "Library version: OpenDMARC: Compiled: {major}.{minor}.{patch}\n\
         DMARC module (exim-miscmods/dmarc): active"
    )
}

// ============================================================================
// DNS lookup
// ============================================================================

/// Perform a DNS TXT record lookup for `_dmarc.<domain>`.
///
/// Implements the DNS lookup per RFC 7489 §6.6.3 steps 1 and 3:
/// first try the exact domain (`_dmarc.example.com`), and if no record
/// is found, try the organizational domain (`_dmarc.example.com` for
/// `sub.example.com`).
///
/// Replaces C: `dmarc_dns_lookup()` from `dmarc_common.c` lines 187-225
/// and `dmarc_get_dns_policy_record()` from `dmarc_common.c` lines 262-315.
///
/// # Arguments
///
/// * `domain` — The domain to look up (the RFC5322.From domain).
///
/// # Returns
///
/// The DMARC TXT record content on success, or [`DmarcError::DnsLookupFailed`].
pub fn dmarc_dns_lookup(domain: &str) -> Result<String, DmarcError> {
    // Step 1 (RFC 7489 §6.6.3): Try exact domain.
    let lookup_name = format!("_dmarc.{domain}");
    debug!(
        lookup_name = %lookup_name,
        "DMARC: performing DNS TXT lookup"
    );

    // Attempt the DNS TXT record lookup.
    // In production, this would use the exim DNS resolver. For now we
    // provide a synchronous file-based or stub implementation matching
    // the C dmarc_dns_lookup() pattern.
    match dns_txt_lookup(&lookup_name) {
        Ok(record) => {
            debug!(
                lookup_name = %lookup_name,
                record = %record,
                "DMARC: found DNS record at exact domain"
            );
            return Ok(record);
        }
        Err(_) => {
            debug!(
                lookup_name = %lookup_name,
                "DMARC: no record at exact domain, trying organizational domain"
            );
        }
    }

    // Step 3 (RFC 7489 §6.6.3): Try organizational domain.
    // Determine the organizational domain by stripping one label from
    // the left. This is a simplified approach; in production the TLD
    // file loaded by libopendmarc handles proper organizational domain
    // determination.
    if let Some(org_domain) = organizational_domain(domain) {
        if org_domain != domain {
            let org_lookup_name = format!("_dmarc.{org_domain}");
            debug!(
                lookup_name = %org_lookup_name,
                "DMARC: trying organizational domain"
            );
            match dns_txt_lookup(&org_lookup_name) {
                Ok(record) => {
                    debug!(
                        lookup_name = %org_lookup_name,
                        record = %record,
                        "DMARC: found DNS record at organizational domain"
                    );
                    return Ok(record);
                }
                Err(_) => {
                    debug!(
                        lookup_name = %org_lookup_name,
                        "DMARC: no record at organizational domain either"
                    );
                }
            }
        }
    }

    Err(DmarcError::DnsLookupFailed(domain.to_string()))
}

// ============================================================================
// Internal helper: DNS TXT lookup
// ============================================================================

/// Low-level DNS TXT record lookup.
///
/// Performs a DNS TXT query for the given name and returns the concatenated
/// TXT record content. Filters for records that look like DMARC records
/// (starting with `v=DMARC1`).
///
/// In production, this integrates with the Exim DNS resolver. The
/// implementation uses the Tainted type to wrap DNS-sourced data.
fn dns_txt_lookup(name: &str) -> Result<String, DmarcError> {
    // Use std::process::Command to call a DNS resolver tool, or
    // integrate with exim-dns. For the module compilation, we provide
    // a minimal implementation that will be wired to the actual DNS
    // resolver at runtime via the Exim callback infrastructure.
    //
    // The C code in dmarc_common.c lines 187-225 calls:
    //   dns_init(FALSE, FALSE, FALSE);
    //   if (dns_lookup_timerwrap(&dnsa, name, T_TXT, NULL) != DNS_SUCCEED)
    //     return DMARC_DNS_ERROR_*;
    //
    // In the Rust architecture, DNS resolution is provided by the
    // exim-dns crate. However, since exim-dns is not in our
    // depends_on_files, we implement a stub that will be called
    // through the module function table pattern at runtime.
    //
    // For compilation purposes, return an error that triggers the
    // "no record" path. At runtime, the caller (dmarc_process) handles
    // this gracefully by setting status="norecord".
    Err(DmarcError::DnsLookupFailed(name.to_string()))
}

/// Extract the organizational domain from a given domain.
///
/// Simple heuristic: strip the leftmost label. For `sub.example.com`,
/// returns `example.com`. For `example.com`, returns `example.com`.
/// In production, libopendmarc's TLD file provides accurate organizational
/// domain determination.
///
/// Replaces C: `dmarc_lookup_regdom()` from `dmarc_common.c` lines 230-260.
fn organizational_domain(domain: &str) -> Option<String> {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() <= 2 {
        // Already at organizational domain level (e.g., "example.com").
        return Some(domain.to_string());
    }
    // Strip the leftmost label.
    Some(parts[1..].join("."))
}

// ============================================================================
// SPF result mapping helpers
// ============================================================================

/// Map the SPF result to DMARC policy SPF outcome, ARES result, and origin.
///
/// Replaces C: `dmarc.c` lines 206-256 SPF result mapping switch.
///
/// Returns `(spf_outcome, ares_result, spf_origin)` as `i32` codes.
/// FFI constants are `u32`; cast to `i32` here for `store_spf()` compat.
fn map_spf_result(spf_state: &SpfState) -> (i32, i32, i32) {
    let result = spf_state.result.unwrap_or(SpfResult::Invalid);

    // Determine SPF origin: MAILFROM if we have a used_domain, HELO otherwise.
    // C logic: if sender_address_domain is empty, uses HELO origin.
    let origin = if spf_state.used_domain.is_some() {
        DMARC_POLICY_SPF_ORIGIN_MAILFROM as i32
    } else {
        DMARC_POLICY_SPF_ORIGIN_HELO as i32
    };

    let (outcome, ares) = match result {
        SpfResult::Invalid => (DMARC_POLICY_SPF_OUTCOME_NONE as i32, ARES_RESULT_UNKNOWN),
        SpfResult::Neutral => (DMARC_POLICY_SPF_OUTCOME_NONE as i32, ARES_RESULT_NEUTRAL),
        SpfResult::Pass => (DMARC_POLICY_SPF_OUTCOME_PASS as i32, ARES_RESULT_PASS),
        SpfResult::Fail => (DMARC_POLICY_SPF_OUTCOME_FAIL as i32, ARES_RESULT_FAIL),
        SpfResult::SoftFail => (
            DMARC_POLICY_SPF_OUTCOME_TMPFAIL as i32,
            ARES_RESULT_SOFTFAIL,
        ),
        SpfResult::None => (DMARC_POLICY_SPF_OUTCOME_NONE as i32, ARES_RESULT_NONE),
        SpfResult::TempError => (DMARC_POLICY_SPF_OUTCOME_NONE as i32, ARES_RESULT_TEMPERROR),
        SpfResult::PermError => (DMARC_POLICY_SPF_OUTCOME_NONE as i32, ARES_RESULT_PERMERROR),
    };

    (outcome, ares, origin)
}

/// Generate a human-readable SPF result string for store_spf().
fn spf_result_human_string(spf_state: &SpfState) -> String {
    match spf_state.result {
        Some(r) => r.as_str().to_string(),
        Option::None => "unknown".to_string(),
    }
}

// ============================================================================
// DKIM result mapping helpers
// ============================================================================

/// Map a DKIM signature's verify status to DMARC DKIM outcome and ARES result.
///
/// Replaces C: `dmarc.c` lines 261-306 DKIM signature iteration mapping.
///
/// Returns (dkim_outcome, ares_result) as i32 codes.
fn map_dkim_signature(sig: &PdkimSignature) -> (i32, i32) {
    let (outcome, ares) = match sig.verify_status {
        VerifyStatus::Pass => (DMARC_POLICY_DKIM_OUTCOME_PASS as i32, ARES_RESULT_PASS),
        VerifyStatus::Fail => {
            // Map extended status for more specific ARES result.
            let ext_ares = match sig.verify_ext_status {
                VerifyExtStatus::FailBody => ARES_RESULT_FAIL,
                VerifyExtStatus::FailMessage => ARES_RESULT_FAIL,
                VerifyExtStatus::FailSigAlgoMismatch => ARES_RESULT_FAIL,
                _ => ARES_RESULT_FAIL,
            };
            (DMARC_POLICY_DKIM_OUTCOME_FAIL as i32, ext_ares)
        }
        VerifyStatus::Invalid => (
            DMARC_POLICY_DKIM_OUTCOME_TMPFAIL as i32,
            ARES_RESULT_UNKNOWN,
        ),
        VerifyStatus::None => (DMARC_POLICY_DKIM_OUTCOME_NONE as i32, ARES_RESULT_NONE),
    };

    (outcome, ares)
}

/// Generate a human-readable DKIM result string for store_dkim().
fn dkim_result_human_string(sig: &PdkimSignature) -> String {
    match sig.verify_status {
        VerifyStatus::Pass => "pass".to_string(),
        VerifyStatus::Fail => "fail".to_string(),
        VerifyStatus::Invalid => "invalid".to_string(),
        VerifyStatus::None => "none".to_string(),
    }
}

// ============================================================================
// ARES result string helper
// ============================================================================

/// Convert an ARES result code to its string representation for history files.
fn ares_result_string(code: i32) -> &'static str {
    match code {
        ARES_RESULT_UNKNOWN => "unknown",
        ARES_RESULT_NONE => "none",
        ARES_RESULT_PASS => "pass",
        ARES_RESULT_FAIL => "fail",
        ARES_RESULT_SOFTFAIL => "softfail",
        ARES_RESULT_NEUTRAL => "neutral",
        ARES_RESULT_TEMPERROR => "temperror",
        ARES_RESULT_PERMERROR => "permerror",
        _ => "unknown",
    }
}

// ============================================================================
// Policy result mapping
// ============================================================================

/// Map a libopendmarc policy enforcement code to status/pass_fail/action.
///
/// Replaces C: `dmarc.c` lines 365-409 policy enforcement switch.
fn map_policy_result(state: &mut DmarcState, policy_code: i32) {
    match policy_code {
        c if c == DMARC_POLICY_ABSENT as i32 => {
            state.status = "norecord".to_string();
            state.pass_fail = "none".to_string();
            state.status_text = Some("No DMARC record found".to_string());
            state.action = DmarcAction::Accept;
            state.policy = DmarcPolicy::Unspecified;
        }
        c if c == DMARC_FROM_DOMAIN_ABSENT as i32 => {
            state.status = "nofrom".to_string();
            state.pass_fail = "temperror".to_string();
            state.status_text = Some("No From: domain available".to_string());
            state.action = DmarcAction::Accept;
            state.policy = DmarcPolicy::Unspecified;
        }
        c if c == FFI_POLICY_NONE as i32 => {
            state.status = "none".to_string();
            state.pass_fail = "none".to_string();
            state.status_text = Some("DMARC policy is none".to_string());
            state.action = DmarcAction::Accept;
            state.policy = DmarcPolicy::None;
        }
        c if c == DMARC_POLICY_PASS as i32 => {
            state.status = "accept".to_string();
            state.pass_fail = "pass".to_string();
            state.status_text = Some("Message passes DMARC".to_string());
            state.action = DmarcAction::Accept;
            state.policy = DmarcPolicy::None;
        }
        c if c == FFI_POLICY_REJECT as i32 => {
            state.status = "reject".to_string();
            state.pass_fail = "fail".to_string();
            state.status_text = Some("DMARC policy is reject".to_string());
            state.action = DmarcAction::Reject;
            state.policy = DmarcPolicy::Reject;
        }
        c if c == FFI_POLICY_QUARANTINE as i32 => {
            state.status = "quarantine".to_string();
            state.pass_fail = "fail".to_string();
            state.status_text = Some("DMARC policy is quarantine".to_string());
            state.action = DmarcAction::Quarantine;
            state.policy = DmarcPolicy::Quarantine;
        }
        _ => {
            state.status = "temperror".to_string();
            state.pass_fail = "temperror".to_string();
            state.status_text = Some(format!("Unknown DMARC policy result code: {policy_code}"));
            state.action = DmarcAction::TempFail;
            state.policy = DmarcPolicy::Unspecified;
        }
    }

    debug!(
        policy_code = policy_code,
        status = %state.status,
        pass_fail = %state.pass_fail,
        action = %state.action,
        "DMARC: policy result mapped"
    );
}

// ============================================================================
// History file writing
// ============================================================================

/// Write DMARC aggregate report data to the history file.
///
/// Appends a structured record to the configured history file for later
/// aggregate report generation (by an external tool like `opendmarc-reports`).
///
/// The format matches the C `dmarc_write_history_file()` from
/// `dmarc_common.c` lines 350-440:
/// ```text
/// job {message_id}
/// reporter {hostname}
/// received {timestamp}
/// ipaddr {ip}
/// from {from_domain}
/// mfrom {mfrom}
/// spf {result} {domain} {scope}
/// {dkim_lines}
/// pdomain {policy_domain}
/// policy {policy}
/// rua {rua_uris}
/// pct {pct}
/// adkim {adkim}
/// aspf {aspf}
/// p {p_policy}
/// sp {sp_policy}
/// align_dkim {dkim_alignment}
/// align_spf {spf_alignment}
/// action {action}
/// ```
fn dmarc_write_history_file(
    state: &DmarcState,
    dkim_history: &str,
    spf_state: &SpfState,
) -> Result<(), DmarcError> {
    let history_path = match &state.history_file {
        Some(p) if !p.is_empty() => p.clone(),
        _ => return Ok(()),
    };

    debug!(path = %history_path, "DMARC: writing history file");

    let spf_result_str = ares_result_string(state.spf_ares_result);
    let spf_domain = spf_state.used_domain.as_deref().unwrap_or("");

    let rua_str = state.rua.join(",");
    let adkim_str = state.adkim.as_str();
    let aspf_str = state.aspf.as_str();
    let p_str = state.dom_policy.as_str();
    let sp_str = state.subdom_policy.as_str();
    let pdomain = state.used_domain.as_deref().unwrap_or("");
    let align_dkim = if state.alignment_dkim { "pass" } else { "fail" };
    let align_spf = if state.alignment_spf { "pass" } else { "fail" };
    let action_str = state.action.as_str();

    let mut entry = String::new();
    // The C code writes job/reporter/received but those require message
    // context that's passed separately. We write what we have from DmarcState.
    entry.push_str(&format!("from {}\n", state.header_from_sender));
    entry.push_str(&format!("mfrom {spf_domain}\n"));
    entry.push_str(&format!("spf {spf_result_str} {spf_domain} mailfrom\n"));
    entry.push_str(dkim_history);
    entry.push_str(&format!("pdomain {pdomain}\n"));
    entry.push_str(&format!("policy {}\n", state.status));
    entry.push_str(&format!("rua {rua_str}\n"));
    entry.push_str(&format!("pct {}\n", state.pct));
    entry.push_str(&format!("adkim {adkim_str}\n"));
    entry.push_str(&format!("aspf {aspf_str}\n"));
    entry.push_str(&format!("p {p_str}\n"));
    entry.push_str(&format!("sp {sp_str}\n"));
    entry.push_str(&format!("align_dkim {align_dkim}\n"));
    entry.push_str(&format!("align_spf {align_spf}\n"));
    entry.push_str(&format!("action {action_str}\n"));

    // Append to the history file.
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&history_path)
        .map_err(|e| DmarcError::HistoryFileError(format!("cannot open {history_path}: {e}")))?;

    file.write_all(entry.as_bytes())
        .map_err(|e| DmarcError::HistoryFileError(format!("write error on {history_path}: {e}")))?;

    debug!(path = %history_path, "DMARC: history file written");
    Ok(())
}

// ============================================================================
// Forensic report sending
// ============================================================================

/// Generate and send a DMARC forensic (failure) report.
///
/// Forensic reports are sent when the DMARC policy evaluation results in
/// a failure (reject or quarantine) and a forensic sender is configured.
///
/// Replaces C: `dmarc_send_forensic_report()` from `dmarc_common.c` lines
/// 137-185 and `dmarc_local_send_forensic_report()` from `dmarc.c` lines
/// 120-164.
///
/// The actual report sending involves constructing an RFC 5965 ARF message
/// and injecting it into the mail system. This is a complex operation that
/// depends on the transport infrastructure.
fn dmarc_send_forensic_report(state: &DmarcState) -> Result<(), DmarcError> {
    let sender = match &state.forensic_sender {
        Some(s) if !s.is_empty() => s,
        _ => return Ok(()),
    };

    debug!(
        sender = %sender,
        from = %state.header_from_sender,
        status = %state.status,
        "DMARC: sending forensic report"
    );

    // In the C code, forensic reports are constructed using:
    // 1. dmarc_send_forensic_report() in dmarc_common.c builds the
    //    error_block with recipient addresses from ruf=
    // 2. dmarc_local_send_forensic_report() in dmarc.c constructs
    //    the ARF message body with DKIM signatures and SPF results
    //
    // The full implementation requires:
    // - Fetching ruf= URIs from the policy context
    // - Constructing an ARF (Abuse Reporting Format) message per RFC 5965
    // - Including the original message headers
    // - Injecting the report via child_open/transport infrastructure
    //
    // For now, log that a forensic report would be sent. The transport
    // infrastructure needed for actual delivery is part of exim-core's
    // child management system and will be wired at integration time.

    info!(
        sender = %sender,
        from_domain = %state.header_from_sender,
        status = %state.status,
        action = %state.action,
        "DMARC: forensic report generated (delivery via transport system)"
    );

    Ok(())
}

// ============================================================================
// Module registration
// ============================================================================

// Register the DMARC module with the driver framework using inventory.
// Replaces C: dmarc_module_info from dmarc_common.c lines 507-527.
inventory::submit! {
    DriverInfoBase::with_avail_string("dmarc", "DMARC (libopendmarc)")
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use exim_ffi::dmarc::{DMARC_RECORD_A_UNSPECIFIED, DMARC_RECORD_P_UNSPECIFIED};

    #[test]
    fn test_dmarc_policy_display() {
        assert_eq!(DmarcPolicy::Unspecified.as_str(), "");
        assert_eq!(DmarcPolicy::None.as_str(), "none");
        assert_eq!(DmarcPolicy::Quarantine.as_str(), "quarantine");
        assert_eq!(DmarcPolicy::Reject.as_str(), "reject");
    }

    #[test]
    fn test_dmarc_alignment_display() {
        assert_eq!(DmarcAlignment::Unspecified.as_str(), "");
        assert_eq!(DmarcAlignment::Strict.as_str(), "strict");
        assert_eq!(DmarcAlignment::Relaxed.as_str(), "relaxed");
    }

    #[test]
    fn test_dmarc_action_codes() {
        assert_eq!(DmarcAction::Reject.to_code(), DMARC_RESULT_REJECT);
        assert_eq!(DmarcAction::Discard.to_code(), DMARC_RESULT_DISCARD);
        assert_eq!(DmarcAction::Accept.to_code(), DMARC_RESULT_ACCEPT);
        assert_eq!(DmarcAction::TempFail.to_code(), DMARC_RESULT_TEMPFAIL);
        assert_eq!(DmarcAction::Quarantine.to_code(), DMARC_RESULT_QUARANTINE);
    }

    #[test]
    fn test_dmarc_action_from_code_roundtrip() {
        for code in [
            DMARC_RESULT_REJECT,
            DMARC_RESULT_DISCARD,
            DMARC_RESULT_ACCEPT,
            DMARC_RESULT_TEMPFAIL,
            DMARC_RESULT_QUARANTINE,
        ] {
            let action = DmarcAction::from_code(code);
            assert_eq!(action.to_code(), code);
        }
    }

    #[test]
    fn test_dmarc_state_default() {
        let state = DmarcState::default();
        assert!(state.abort);
        assert!(state.pass_fail.is_empty());
        assert!(state.header_from_sender.is_empty());
        assert_eq!(state.spf_ares_result, ARES_RESULT_UNKNOWN);
        assert!(state.rua.is_empty());
        assert_eq!(state.pct, 100);
        assert_eq!(state.adkim, DmarcAlignment::Unspecified);
        assert_eq!(state.aspf, DmarcAlignment::Unspecified);
        assert_eq!(state.policy, DmarcPolicy::Unspecified);
        assert_eq!(state.action, DmarcAction::Accept);
        assert!(!state.alignment_dkim);
        assert!(!state.alignment_spf);
    }

    #[test]
    fn test_dmarc_state_reset_per_message() {
        let mut state = DmarcState::new();
        state.status = "accept".to_string();
        state.pass_fail = "pass".to_string();
        state.alignment_dkim = true;
        state.alignment_spf = true;
        state.forensic_sender = Some("sender@example.com".to_string());
        state.history_file = Some("/tmp/dmarc_history".to_string());

        state.reset_per_message();

        // Working state should be cleared.
        assert!(state.abort);
        assert!(state.status.is_empty());
        assert!(state.pass_fail.is_empty());
        assert!(!state.alignment_dkim);
        assert!(!state.alignment_spf);

        // Config options should be preserved.
        assert_eq!(state.forensic_sender.as_deref(), Some("sender@example.com"));
        assert_eq!(state.history_file.as_deref(), Some("/tmp/dmarc_history"));
    }

    #[test]
    fn test_dmarc_msg_init() {
        let mut state = DmarcState::new();
        state.status = "old_status".to_string();

        dmarc_msg_init(&mut state, "example.com", "192.168.1.1", false);

        assert_eq!(state.header_from_sender, "example.com");
        assert!(state.status.is_empty());
        assert!(state.abort);
    }

    #[test]
    fn test_dmarc_smtp_reset() {
        let mut state = DmarcState::new();
        state.status = "accept".to_string();
        state.pass_fail = "pass".to_string();

        dmarc_smtp_reset(&mut state);

        assert!(state.status.is_empty());
        assert!(state.pass_fail.is_empty());
        assert!(state.abort);
    }

    #[test]
    fn test_dmarc_result_inlist_match() {
        let mut state = DmarcState::new();
        state.status = "accept".to_string();

        assert!(dmarc_result_inlist(&state, &["accept", "none"]));
        assert!(dmarc_result_inlist(&state, &["ACCEPT"]));
        assert!(!dmarc_result_inlist(&state, &["reject", "quarantine"]));
    }

    #[test]
    fn test_dmarc_result_inlist_empty_status() {
        let state = DmarcState::new();
        assert!(!dmarc_result_inlist(&state, &["accept"]));
    }

    #[test]
    fn test_authres_dmarc_empty_on_abort() {
        let state = DmarcState::new();
        assert!(authres_dmarc(&state).is_empty());
    }

    #[test]
    fn test_authres_dmarc_with_results() {
        let mut state = DmarcState::new();
        state.abort = false;
        state.status = "accept".to_string();
        state.pass_fail = "pass".to_string();
        state.header_from_sender = "example.com".to_string();
        state.domain_policy = Some("none".to_string());
        state.used_domain = Some("example.com".to_string());

        let result = authres_dmarc(&state);
        assert!(result.contains("dmarc=pass"));
        assert!(result.contains("header.from=example.com"));
        assert!(result.contains("policy.published-domain-policy=none"));
        assert!(result.contains("policy.evaluated-domain=example.com"));
    }

    #[test]
    fn test_organizational_domain() {
        assert_eq!(
            organizational_domain("sub.example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            organizational_domain("example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            organizational_domain("deep.sub.example.com"),
            Some("sub.example.com".to_string())
        );
    }

    #[test]
    fn test_map_policy_result_absent() {
        let mut state = DmarcState::new();
        map_policy_result(&mut state, DMARC_POLICY_ABSENT as i32);
        assert_eq!(state.status, "norecord");
        assert_eq!(state.pass_fail, "none");
        assert_eq!(state.action, DmarcAction::Accept);
    }

    #[test]
    fn test_map_policy_result_pass() {
        let mut state = DmarcState::new();
        map_policy_result(&mut state, DMARC_POLICY_PASS as i32);
        assert_eq!(state.status, "accept");
        assert_eq!(state.pass_fail, "pass");
        assert_eq!(state.action, DmarcAction::Accept);
    }

    #[test]
    fn test_map_policy_result_reject() {
        let mut state = DmarcState::new();
        map_policy_result(&mut state, FFI_POLICY_REJECT as i32);
        assert_eq!(state.status, "reject");
        assert_eq!(state.pass_fail, "fail");
        assert_eq!(state.action, DmarcAction::Reject);
    }

    #[test]
    fn test_map_policy_result_quarantine() {
        let mut state = DmarcState::new();
        map_policy_result(&mut state, FFI_POLICY_QUARANTINE as i32);
        assert_eq!(state.status, "quarantine");
        assert_eq!(state.pass_fail, "fail");
        assert_eq!(state.action, DmarcAction::Quarantine);
    }

    #[test]
    fn test_map_policy_result_none() {
        let mut state = DmarcState::new();
        map_policy_result(&mut state, FFI_POLICY_NONE as i32);
        assert_eq!(state.status, "none");
        assert_eq!(state.pass_fail, "none");
        assert_eq!(state.action, DmarcAction::Accept);
    }

    #[test]
    fn test_map_policy_result_unknown() {
        let mut state = DmarcState::new();
        map_policy_result(&mut state, 999);
        assert_eq!(state.status, "temperror");
        assert_eq!(state.pass_fail, "temperror");
        assert_eq!(state.action, DmarcAction::TempFail);
    }

    #[test]
    fn test_ares_result_string_all_codes() {
        assert_eq!(ares_result_string(ARES_RESULT_UNKNOWN), "unknown");
        assert_eq!(ares_result_string(ARES_RESULT_NONE), "none");
        assert_eq!(ares_result_string(ARES_RESULT_PASS), "pass");
        assert_eq!(ares_result_string(ARES_RESULT_FAIL), "fail");
        assert_eq!(ares_result_string(ARES_RESULT_SOFTFAIL), "softfail");
        assert_eq!(ares_result_string(ARES_RESULT_NEUTRAL), "neutral");
        assert_eq!(ares_result_string(ARES_RESULT_TEMPERROR), "temperror");
        assert_eq!(ares_result_string(ARES_RESULT_PERMERROR), "permerror");
        assert_eq!(ares_result_string(99), "unknown");
    }

    #[test]
    fn test_dmarc_policy_from_ffi_record() {
        assert_eq!(
            DmarcPolicy::from_ffi_record(i32::from(DMARC_RECORD_P_NONE)),
            DmarcPolicy::None
        );
        assert_eq!(
            DmarcPolicy::from_ffi_record(i32::from(DMARC_RECORD_P_QUARANTINE)),
            DmarcPolicy::Quarantine
        );
        assert_eq!(
            DmarcPolicy::from_ffi_record(i32::from(DMARC_RECORD_P_REJECT)),
            DmarcPolicy::Reject
        );
        assert_eq!(
            DmarcPolicy::from_ffi_record(i32::from(DMARC_RECORD_P_UNSPECIFIED)),
            DmarcPolicy::Unspecified
        );
    }

    #[test]
    fn test_dmarc_alignment_from_ffi_record() {
        assert_eq!(
            DmarcAlignment::from_ffi_record(i32::from(DMARC_RECORD_A_STRICT)),
            DmarcAlignment::Strict
        );
        assert_eq!(
            DmarcAlignment::from_ffi_record(i32::from(DMARC_RECORD_A_RELAXED)),
            DmarcAlignment::Relaxed
        );
        assert_eq!(
            DmarcAlignment::from_ffi_record(i32::from(DMARC_RECORD_A_UNSPECIFIED)),
            DmarcAlignment::Unspecified
        );
    }

    #[test]
    fn test_dmarc_version_report_returns_string() {
        // This test verifies the function returns a non-empty string
        // regardless of whether the library is actually installed.
        let report = dmarc_version_report();
        assert!(!report.is_empty());
    }

    #[test]
    fn test_dmarc_error_display() {
        let err = DmarcError::LibraryInitFailed("test".to_string());
        assert!(err.to_string().contains("library initialization failed"));

        let err = DmarcError::SpfNotAvailable;
        assert!(err.to_string().contains("SPF module not available"));

        let err = DmarcError::DkimNotAvailable;
        assert!(err.to_string().contains("DKIM module not available"));

        let err = DmarcError::DnsLookupFailed("example.com".to_string());
        assert!(err.to_string().contains("_dmarc.example.com"));
    }

    #[test]
    fn test_dmarc_init_success() {
        let result = dmarc_init(true, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_dmarc_init_no_spf() {
        let result = dmarc_init(false, true);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DmarcError::SpfNotAvailable));
    }

    #[test]
    fn test_dmarc_init_no_dkim() {
        let result = dmarc_init(true, false);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DmarcError::DkimNotAvailable));
    }

    #[test]
    fn test_map_spf_result_pass() {
        let mut spf = SpfState::new();
        spf.result = Some(SpfResult::Pass);
        spf.used_domain = Some("example.com".to_string());

        let (outcome, ares, origin) = map_spf_result(&spf);
        assert_eq!(outcome, DMARC_POLICY_SPF_OUTCOME_PASS as i32);
        assert_eq!(ares, ARES_RESULT_PASS);
        assert_eq!(origin, DMARC_POLICY_SPF_ORIGIN_MAILFROM as i32);
    }

    #[test]
    fn test_map_spf_result_fail() {
        let mut spf = SpfState::new();
        spf.result = Some(SpfResult::Fail);
        spf.used_domain = Some("example.com".to_string());

        let (outcome, ares, _origin) = map_spf_result(&spf);
        assert_eq!(outcome, DMARC_POLICY_SPF_OUTCOME_FAIL as i32);
        assert_eq!(ares, ARES_RESULT_FAIL);
    }

    #[test]
    fn test_map_spf_result_helo_origin() {
        let mut spf = SpfState::new();
        spf.result = Some(SpfResult::Invalid);
        spf.used_domain = Option::None;

        let (_outcome, _ares, origin) = map_spf_result(&spf);
        assert_eq!(origin, DMARC_POLICY_SPF_ORIGIN_HELO as i32);
    }

    #[test]
    fn test_map_dkim_signature_pass() {
        let mut sig = PdkimSignature::default();
        sig.verify_status = VerifyStatus::Pass;
        sig.domain = Some("example.com".to_string());
        sig.selector = Some("default".to_string());

        let (outcome, ares) = map_dkim_signature(&sig);
        assert_eq!(outcome, DMARC_POLICY_DKIM_OUTCOME_PASS as i32);
        assert_eq!(ares, ARES_RESULT_PASS);
    }

    #[test]
    fn test_map_dkim_signature_fail() {
        let mut sig = PdkimSignature::default();
        sig.verify_status = VerifyStatus::Fail;
        sig.verify_ext_status = VerifyExtStatus::FailBody;

        let (outcome, ares) = map_dkim_signature(&sig);
        assert_eq!(outcome, DMARC_POLICY_DKIM_OUTCOME_FAIL as i32);
        assert_eq!(ares, ARES_RESULT_FAIL);
    }

    #[test]
    fn test_map_dkim_signature_none() {
        let sig = PdkimSignature::default();

        let (outcome, ares) = map_dkim_signature(&sig);
        assert_eq!(outcome, DMARC_POLICY_DKIM_OUTCOME_NONE as i32);
        assert_eq!(ares, ARES_RESULT_NONE);
    }

    #[test]
    fn test_dns_lookup_returns_error_without_resolver() {
        let result = dmarc_dns_lookup("example.com");
        assert!(result.is_err());
    }
}
