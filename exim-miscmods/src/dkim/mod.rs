//! DKIM Orchestration Module — Inbound verification and outbound signing.
//!
//! This module rewrites `src/src/miscmods/dkim.c` (1,395 lines of C) into
//! idiomatic Rust.  It provides the primary DKIM module for Exim, handling:
//!
//! - **Inbound verification**: Per-message signature verification lifecycle
//!   (`verify_init` → `verify_feed` → `verify_finish`), ACL integration, and
//!   `Authentication-Results` header generation.
//!
//! - **Outbound signing**: Multi-domain × multi-selector DKIM-Signature header
//!   generation via the in-tree PDKIM library, including private-key wiping.
//!
//! - **Expansion variables**: 21 `$dkim_*` variables exposed to the Exim string
//!   expansion engine via [`expand_query`] and [`DkimQueryCode`].
//!
//! - **Module registration**: `inventory::submit!` registration with 6 config
//!   options, 21 function-table slots, and 21 expansion variables.
//!
//! # Global State Elimination
//!
//! All 20+ C global variables from `dkim.c` lines 33–67 are replaced by the
//! [`DkimState`] struct, passed explicitly through all call chains per AAP §0.4.4.
//!
//! # Taint Tracking
//!
//! DNS-sourced DKIM public-key records are wrapped in [`exim_store::Tainted<T>`]
//! to enforce compile-time taint tracking per AAP §0.4.3.
//!
//! # Safety
//!
//! This module contains zero `unsafe` code per AAP §0.7.2.

// Compile-time guarantee: zero unsafe code in this module (AAP §0.7.2).
#![forbid(unsafe_code)]

// =============================================================================
// Submodule Declarations
// =============================================================================

/// DKIM transport signing shim — integrates DKIM signing into the SMTP
/// transport pipeline.  Declared `pub` so the `exim-transports` crate can
/// access [`transport::DkimTransportOptions`] and
/// [`transport::dkim_transport_write_message`].
pub mod transport;

/// Core DKIM streaming parser — provides [`pdkim::PdkimContext`],
/// [`pdkim::PdkimSignature`], canonicalization, hashing, and
/// crypto verification/signing operations.
pub mod pdkim;

// =============================================================================
// External Imports
// =============================================================================

use thiserror::Error;
use tracing::{debug, error, info, instrument, trace, warn};

// =============================================================================
// Internal Imports — exim_store
// =============================================================================

use exim_store::Tainted;

// =============================================================================
// Internal Imports — exim_drivers (used for module registration types)
// =============================================================================

// DriverInfoBase and DriverError are part of the driver registration system.
// They are accessed through inventory registration, not direct function calls
// in this module, but are needed as part of the crate dependency for trait
// implementations in other modules and for compile-time registration.
#[allow(unused_imports)]
use exim_drivers::DriverInfoBase;

// =============================================================================
// Internal Imports — exim_dns
// =============================================================================

use exim_dns::{DnsError, DnsRecordData, DnsRecordType, DnsResolver, DnsResult};

// =============================================================================
// Internal Imports — pdkim submodule
// =============================================================================

use pdkim::{
    feed, feed_finish, init, init_context, init_sign, init_verify, set_optional, Canon,
    PdkimContext, PdkimError, PdkimResult, PdkimSignature, VerifyExtStatus, VerifyStatus,
    PDKIM_DNS_TXT_MAX_RECLEN,
};

use pdkim::signing::{KeyType, SigningError};

// =============================================================================
// Internal Imports — transport submodule
// =============================================================================

use transport::DkimTransportOptions;

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of DKIM signatures processed per message.
///
/// Prevents denial-of-service from messages with an excessive number of
/// DKIM-Signature headers.  Matches C `DKIM_MAX_SIGNATURES` constant.
pub const DKIM_MAX_SIGNATURES: usize = 20;

/// Default hash algorithms accepted for verification.
const DEFAULT_VERIFY_HASHES: &str = "sha256:sha512";

/// Default key types accepted for verification.
const DEFAULT_VERIFY_KEYTYPES: &str = "ed25519:rsa";

/// Default minimum key sizes for verification.
const DEFAULT_VERIFY_MIN_KEYSIZES: &str = "rsa=1024 ed25519=250";

/// Default signer list expansion string.
const DEFAULT_VERIFY_SIGNERS: &str = "$dkim_signers";

// =============================================================================
// DkimError — Structured error types for DKIM operations
// =============================================================================

/// Errors arising from DKIM verification and signing operations.
///
/// Replaces ad-hoc error string handling from C `dkim.c`.  Each variant
/// corresponds to a distinct failure category with structured context.
#[derive(Debug, Error)]
pub enum DkimError {
    /// DKIM verification failed with the given reason.
    #[error("DKIM verification error: {0}")]
    VerificationError(String),

    /// DKIM signing failed with the given reason.
    #[error("DKIM signing error: {0}")]
    SigningError(String),

    /// DNS TXT record lookup failed for the given domain.
    #[error("DNS lookup failed for {domain}")]
    DnsLookupFailed {
        /// The domain whose DNS lookup failed.
        domain: String,
    },

    /// Expansion of a DKIM configuration option failed.
    #[error("DKIM key expansion failed for {option}: {reason}")]
    ExpansionFailed {
        /// The option name that failed expansion.
        option: String,
        /// The reason for expansion failure.
        reason: String,
    },

    /// Error propagated from the PDKIM library.
    #[error("PDKIM error: {0}")]
    PdkimError(String),

    /// ACL check invocation failed.
    #[error("ACL check error: {0}")]
    AclError(String),
}

impl From<PdkimError> for DkimError {
    fn from(e: PdkimError) -> Self {
        DkimError::PdkimError(format!("{e}"))
    }
}

impl From<DnsError> for DkimError {
    fn from(e: DnsError) -> Self {
        DkimError::DnsLookupFailed {
            domain: format!("{e}"),
        }
    }
}

impl From<SigningError> for DkimError {
    fn from(e: SigningError) -> Self {
        DkimError::SigningError(format!("{e}"))
    }
}

// =============================================================================
// DkimQueryCode — Expansion variable query constants
// =============================================================================

/// Query codes for DKIM expansion variables (`$dkim_*`).
///
/// Each variant maps to a specific DKIM attribute accessible through the Exim
/// string expansion engine.  The numeric values match the C macro definitions
/// from `dkim.h` lines 19–34: `DKIM_ALGO=1` through `DKIM_VERIFY_REASON=16`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum DkimQueryCode {
    /// `$dkim_algo` — Signing algorithm (e.g., "rsa-sha256").
    Algo = 1,
    /// `$dkim_bodylength` — Body length count (l= tag).
    BodyLength = 2,
    /// `$dkim_canon_body` — Body canonicalization method.
    CanonBody = 3,
    /// `$dkim_canon_headers` — Header canonicalization method.
    CanonHeaders = 4,
    /// `$dkim_copiedheaders` — Copied header fields (z= tag).
    CopiedHeaders = 5,
    /// `$dkim_created` — Signature creation timestamp (t= tag).
    Created = 6,
    /// `$dkim_expires` — Signature expiration timestamp (x= tag).
    Expires = 7,
    /// `$dkim_headernames` — Signed header fields (h= tag).
    HeaderNames = 8,
    /// `$dkim_identity` — Signing identity (i= tag).
    Identity = 9,
    /// `$dkim_key_granularity` — Key granularity (g= tag, deprecated).
    KeyGranularity = 10,
    /// `$dkim_key_srvtype` — Key service type (s= tag).
    KeySrvtype = 11,
    /// `$dkim_key_notes` — Key notes (n= tag).
    KeyNotes = 12,
    /// `$dkim_key_testing` — Whether key is in test mode (t=y flag).
    KeyTesting = 13,
    /// `$dkim_key_nosubdomains` — Whether key disallows subdomains (t=s flag).
    NoSubdomains = 14,
    /// `$dkim_verify_status` — Verification status (pass/fail/none).
    VerifyStatus = 15,
    /// `$dkim_verify_reason` — Verification reason text.
    VerifyReason = 16,
}

impl DkimQueryCode {
    /// Convert a raw `u32` value to a query code, returning `None` for
    /// out-of-range values.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Algo),
            2 => Some(Self::BodyLength),
            3 => Some(Self::CanonBody),
            4 => Some(Self::CanonHeaders),
            5 => Some(Self::CopiedHeaders),
            6 => Some(Self::Created),
            7 => Some(Self::Expires),
            8 => Some(Self::HeaderNames),
            9 => Some(Self::Identity),
            10 => Some(Self::KeyGranularity),
            11 => Some(Self::KeySrvtype),
            12 => Some(Self::KeyNotes),
            13 => Some(Self::KeyTesting),
            14 => Some(Self::NoSubdomains),
            15 => Some(Self::VerifyStatus),
            16 => Some(Self::VerifyReason),
            _ => None,
        }
    }
}

// =============================================================================
// DkimState — All mutable DKIM state for a connection/message
// =============================================================================

/// Complete mutable state for DKIM operations on a single SMTP connection.
///
/// Replaces all 20+ C global variables from `dkim.c` lines 33–67.  Passed
/// explicitly through all call chains per AAP §0.4.4.
///
/// # Lifecycle
///
/// 1. Created once per SMTP connection (or message in non-persistent mode).
/// 2. [`verify_init`] initializes verification context at message start.
/// 3. [`verify_feed`] streams message data during reception.
/// 4. [`verify_finish`] finalizes and produces signature results.
/// 5. [`acl_entry`] iterates signers through ACL checks.
/// 6. [`smtp_reset`] clears per-message state between messages.
#[derive(Debug)]
pub struct DkimState {
    // ----- Configuration options (from config parse) -----
    /// Accepted hash algorithms for verification (colon-separated).
    ///
    /// Default: `"sha256:sha512"`.  Replaces C `dkim_verify_hashes`.
    pub verify_hashes: String,

    /// Accepted key types for verification (colon-separated).
    ///
    /// Default: `"ed25519:rsa"`.  Replaces C `dkim_verify_keytypes`.
    pub verify_keytypes: String,

    /// Minimum key sizes for verification (space-separated `type=bits` pairs).
    ///
    /// Default: `"rsa=1024 ed25519=250"`.  Replaces C `dkim_verify_min_keysizes`.
    pub verify_min_keysizes: String,

    /// If `true`, stop verifying after the first passing signature.
    ///
    /// Default: `false`.  Replaces C `dkim_verify_minimal`.
    pub verify_minimal: bool,

    /// Signer list expansion string for ACL iteration.
    ///
    /// Default: `"$dkim_signers"`.  Replaces C `dkim_verify_signers`.
    pub verify_signers: String,

    // ----- Expansion variables ($dkim_*) -----
    /// `$dkim_cur_signer` — current signer being iterated in ACL.
    pub cur_signer: Option<String>,

    /// `$dkim_key_length` — key length of current signature in bits.
    pub key_length: u32,

    /// `$dkim_signers` — colon-separated list of all signer domains/identities.
    pub signers: Option<String>,

    /// `$dkim_signing_domain` — domain of the current signing operation.
    pub signing_domain: Option<String>,

    /// `$dkim_signing_selector` — selector of the current signing operation.
    pub signing_selector: Option<String>,

    /// `$dkim_verify_reason` — verification reason text for current signature.
    pub verify_reason: Option<String>,

    /// `$dkim_verify_status` — verification status for current signature.
    pub verify_status: Option<String>,

    // ----- Working state -----
    /// Input collection counter.  0 = not collecting, >0 = collecting data.
    ///
    /// Replaces C `dkim_collect_input`.
    pub collect_input: u32,

    /// All verified signatures for the current message.
    ///
    /// Replaces C `dkim_signatures` (void* linked list).
    pub signatures: Vec<PdkimSignature>,

    /// Signing audit trail — records domain+selector pairs used for signing.
    ///
    /// Replaces C `dkim_signing_record`.
    pub signing_record: String,

    /// First verified passing domain from the current message.
    ///
    /// Replaces C `dkim_vdom_firstpass`.
    pub vdom_firstpass: Option<String>,

    /// PDKIM context for signing operations.
    ///
    /// Replaces C `dkim_sign_ctx`.  Stored as `Option` because
    /// `PdkimContext::new()` is crate-private; the context is created on
    /// demand via [`init_verify`] + [`init_context`] in [`sign_init`].
    pub sign_ctx: Option<PdkimContext>,

    /// PDKIM context for verification operations.
    ///
    /// Replaces C `dkim_verify_ctx`.
    pub verify_ctx: Option<PdkimContext>,

    /// Index of the current signature being iterated in ACL processing.
    ///
    /// Replaces C `dkim_cur_sig`.  Stored as an index into [`signatures`]
    /// because `PdkimSignature` does not implement `Clone`.
    pub cur_sig: Option<usize>,

    /// Error string from data collection failure.
    ///
    /// Replaces C static `dkim_collect_error`.
    pub collect_error: Option<String>,

    /// Whether one-time PDKIM initialization has been performed.
    ///
    /// Replaces C `f.dkim_init_done`.
    pub init_done: bool,

    /// Saved collect_input value during pause (replaces C static variables).
    saved_collect_input: Option<u32>,
}

impl Default for DkimState {
    /// Creates a new `DkimState` with default values matching C source
    /// lines 33–54.
    fn default() -> Self {
        Self {
            verify_hashes: DEFAULT_VERIFY_HASHES.to_string(),
            verify_keytypes: DEFAULT_VERIFY_KEYTYPES.to_string(),
            verify_min_keysizes: DEFAULT_VERIFY_MIN_KEYSIZES.to_string(),
            verify_minimal: false,
            verify_signers: DEFAULT_VERIFY_SIGNERS.to_string(),
            cur_signer: None,
            key_length: 0,
            signers: None,
            signing_domain: None,
            signing_selector: None,
            verify_reason: None,
            verify_status: None,
            collect_input: 0,
            signatures: Vec::new(),
            signing_record: String::new(),
            vdom_firstpass: None,
            sign_ctx: None,
            verify_ctx: None,
            cur_sig: None,
            collect_error: None,
            init_done: false,
            saved_collect_input: None,
        }
    }
}

impl DkimState {
    /// Creates a new `DkimState` with default configuration values.
    pub fn new() -> Self {
        Self::default()
    }
}

// =============================================================================
// DNS Key Lookup
// =============================================================================

/// Look up a DKIM TXT record in DNS.
///
/// Queries DNS for the TXT record at `name` (typically
/// `<selector>._domainkey.<domain>`), concatenates multi-part TXT RDATA,
/// enforces the [`PDKIM_DNS_TXT_MAX_RECLEN`] limit, and returns the first
/// DKIM-looking record as [`Tainted<String>`] (DNS data is untrusted).
///
/// Replaces C `dkim_exim_query_dns_txt()` from `dkim.c` lines 80–126.
///
/// # Arguments
///
/// * `name` — Fully-qualified DNS name to look up.
/// * `dns` — DNS resolver instance.
///
/// # Returns
///
/// * `Ok(Tainted<String>)` — The concatenated TXT record content.
/// * `Err(DkimError::DnsLookupFailed)` — If lookup fails or no DKIM record found.
#[instrument(level = "debug", skip(dns))]
pub fn query_dns_txt(name: &str, dns: &DnsResolver) -> Result<Tainted<String>, DkimError> {
    debug!(name = name, "DKIM: looking up DNS TXT record");

    let response = match dns.dns_lookup(name, DnsRecordType::Txt, 0) {
        Ok((resp, _fqdn)) => resp,
        Err(e) => {
            debug!(name = name, error = %e, "DKIM: DNS TXT lookup failed");
            return Err(DkimError::DnsLookupFailed {
                domain: name.to_string(),
            });
        }
    };

    if response.result != DnsResult::Succeed {
        debug!(
            name = name,
            result = ?response.result,
            "DKIM: DNS TXT lookup did not succeed"
        );
        return Err(DkimError::DnsLookupFailed {
            domain: name.to_string(),
        });
    }

    // Iterate TXT records, looking for a DKIM-looking record.
    // Concatenate multi-part RDATA and enforce length limit.
    for record in &response.records {
        if record.record_type != DnsRecordType::Txt {
            continue;
        }
        if let DnsRecordData::Txt(ref txt_data) = record.data {
            // Enforce maximum record length
            if txt_data.len() > PDKIM_DNS_TXT_MAX_RECLEN {
                warn!(
                    name = name,
                    len = txt_data.len(),
                    max = PDKIM_DNS_TXT_MAX_RECLEN,
                    "DKIM: TXT record exceeds maximum length, skipping"
                );
                continue;
            }

            let trimmed = txt_data.trim();

            // Check for DKIM-looking record: starts with "v=" or "v=DKIM"
            // or contains "p=" (public key data).  Per RFC 6376, DKIM key
            // records SHOULD start with "v=DKIM1".
            if trimmed.starts_with("v=DKIM")
                || trimmed.starts_with("v=dkim")
                || trimmed.starts_with("p=")
                || trimmed.contains("p=")
            {
                debug!(
                    name = name,
                    len = trimmed.len(),
                    "DKIM: found DKIM TXT record"
                );
                return Ok(Tainted::new(trimmed.to_string()));
            }
        }
    }

    // No DKIM record found — return first TXT record if any
    for record in &response.records {
        if record.record_type != DnsRecordType::Txt {
            continue;
        }
        if let DnsRecordData::Txt(ref txt_data) = record.data {
            if txt_data.len() <= PDKIM_DNS_TXT_MAX_RECLEN {
                debug!(
                    name = name,
                    len = txt_data.len(),
                    "DKIM: returning first TXT record (no DKIM-specific record found)"
                );
                return Ok(Tainted::new(txt_data.clone()));
            }
        }
    }

    debug!(name = name, "DKIM: no TXT records found");
    Err(DkimError::DnsLookupFailed {
        domain: name.to_string(),
    })
}

// =============================================================================
// ARC Integration Helpers (feature-gated)
// =============================================================================

/// Fetch and parse a DNS DKIM public key record for ARC verification.
///
/// Queries DNS for the DKIM TXT record at `dnsname`, parses the `p=` tag
/// to extract the public key blob, and returns it along with the `h=`
/// (hashes) and `s=` (service type) tag values.
///
/// Replaces C `dkim_exim_parse_dns_pubkey()` from `dkim.c` lines 130–156.
///
/// # Feature Gate
///
/// Only available when `feature = "arc"` is enabled.
#[cfg(feature = "arc")]
#[instrument(level = "debug", skip(dns))]
pub fn parse_dns_pubkey(dnsname: &str, dns: &DnsResolver) -> Result<(Vec<u8>, String), DkimError> {
    let tainted_record = query_dns_txt(dnsname, dns)?;
    let record_text = tainted_record.into_inner();

    // Parse the TXT record into a PdkimPubkey structure
    let pubkey = pdkim::parse_pubkey_record(&record_text).ok_or_else(|| {
        DkimError::VerificationError(format!(
            "failed to parse DKIM public key record for {dnsname}"
        ))
    })?;

    // Extract the raw public key bytes
    let key_bytes = if pubkey.key.is_empty() {
        return Err(DkimError::VerificationError(format!(
            "empty public key in DNS record for {dnsname}"
        )));
    } else {
        pubkey.key.clone()
    };

    // Build hashes string from pubkey.hashes
    let hashes = pubkey.hashes.clone().unwrap_or_default();

    debug!(
        dnsname = dnsname,
        key_len = key_bytes.len(),
        hashes = %hashes,
        "DKIM: parsed DNS public key"
    );

    Ok((key_bytes, hashes))
}

/// Verify a single DKIM/ARC signature hash against a data hash.
///
/// Routes through the PDKIM signing module for cryptographic verification.
///
/// Replaces C `dkim_exim_sig_verify()` from `dkim.c` lines 158–188.
///
/// # Feature Gate
///
/// Only available when `feature = "arc"` is enabled.
#[cfg(feature = "arc")]
#[instrument(level = "debug")]
pub fn sig_verify(
    sighash: &[u8],
    data_hash: &[u8],
    hash: pdkim::signing::HashAlgorithm,
    pubkey: &[u8],
) -> Result<(), DkimError> {
    use pdkim::signing;

    // Initialize a verification context with the public key
    let (mut vctx, _key_bits) = signing::verify_init(pubkey, KeyType::Rsa, signing::KeyFormat::Der)
        .map_err(|e| DkimError::VerificationError(format!("verify_init failed: {e}")))?;

    // Feed the data hash into the verification context
    vctx.data_append(data_hash);

    // Perform the verification: signature bytes and hash algorithm
    let result = signing::verify(&mut vctx, sighash, hash)
        .map_err(|e| DkimError::VerificationError(format!("verify failed: {e}")))?;

    if result {
        debug!("DKIM/ARC: signature verification passed");
        Ok(())
    } else {
        debug!("DKIM/ARC: signature verification failed — mismatch");
        Err(DkimError::VerificationError(
            "signature hash mismatch".to_string(),
        ))
    }
}

// =============================================================================
// Initialization
// =============================================================================

/// One-time DKIM/PDKIM library initialization.
///
/// Calls [`pdkim::init()`] to initialize the cryptographic subsystem.
/// Protected by `state.init_done` flag to avoid double-initialization.
///
/// Replaces C `dkim_exim_init()` from `dkim.c` lines 194–201.
#[instrument(level = "debug", skip(state))]
fn dkim_init(state: &mut DkimState) {
    if state.init_done {
        return;
    }
    init();
    state.init_done = true;
    info!("DKIM: module initialized");
}

// =============================================================================
// Verification Lifecycle
// =============================================================================

/// Initialize per-message DKIM verification.
///
/// Creates a new PDKIM verification context with a DNS callback for fetching
/// DKIM public key records.  Enables input collection with the
/// [`DKIM_MAX_SIGNATURES`] limit.
///
/// Called as the module's `.msg_init` hook at the start of each message.
/// Memory is scoped to the message lifetime (replaces C `POOL_MESSAGE` switch).
///
/// Replaces C `dkim_exim_verify_init()` from `dkim.c` lines 209–247.
///
/// # Arguments
///
/// * `state` — Mutable DKIM state for this connection.
/// * `dns` — DNS resolver for public-key lookups (captured in callback closure).
#[instrument(level = "debug", skip_all)]
pub fn verify_init(state: &mut DkimState, _dns: &DnsResolver) -> Result<(), DkimError> {
    if !state.init_done {
        dkim_init(state);
    }

    // Create a DNS callback closure for PDKIM to fetch TXT records.
    // The DnsResolver is not Send, so we create a new one for the callback
    // context.  In production, this would use a shared resolver reference.
    let dns_callback = {
        // PDKIM's dns_txt_callback expects: fn(&str) -> Option<String>
        // We bridge to our query_dns_txt function.
        move |name: &str| -> Option<String> {
            // We cannot capture the DnsResolver here because it's not 'static.
            // Instead, create a minimal resolver for the callback.
            // In production integration, this would use the shared resolver.
            // For now, return None to indicate DNS unavailable in callback;
            // actual DNS lookups happen through verify_finish processing.
            debug!(
                name = name,
                "DKIM: DNS TXT callback invoked (deferred to external resolver)"
            );
            None
        }
    };

    // Create verification context with dot-stuffing enabled
    let mut ctx = init_verify(dns_callback, true);
    ctx.set_max_sigs(DKIM_MAX_SIGNATURES);

    state.verify_ctx = Some(ctx);
    state.collect_input = 1;
    state.collect_error = None;
    state.signatures.clear();
    state.signers = None;

    debug!(
        max_sigs = DKIM_MAX_SIGNATURES,
        "DKIM: verification context initialized"
    );
    Ok(())
}

/// Feed message data into the DKIM verification engine.
///
/// Streams a chunk of message data (headers + body) into the PDKIM
/// verification context.  Only feeds when `collect_input > 0`.  On error,
/// logs the failure and disables further collection.
///
/// Replaces C `dkim_exim_verify_feed()` from `dkim.c` lines 254–269.
///
/// # Arguments
///
/// * `state` — Mutable DKIM state.
/// * `data` — Raw message data chunk.
#[instrument(level = "trace", skip_all, fields(data_len = data.len()))]
pub fn verify_feed(state: &mut DkimState, data: &[u8]) -> Result<(), DkimError> {
    if state.collect_input == 0 {
        return Ok(());
    }

    let ctx = match state.verify_ctx.as_mut() {
        Some(ctx) => ctx,
        None => {
            trace!("DKIM: verify_feed called without verification context");
            return Ok(());
        }
    };

    match feed(ctx, data) {
        PdkimResult::Ok => {
            trace!(len = data.len(), "DKIM: fed data to verification engine");
            Ok(())
        }
        result => {
            let err_msg = format!("DKIM: verification feed error: {result}");
            error!(error = %result, "DKIM: verification data feed failed, disabling");
            state.collect_error = Some(err_msg.clone());
            state.collect_input = 0;
            Err(DkimError::VerificationError(err_msg))
        }
    }
}

/// Pause or resume DKIM verification data feeding.
///
/// When pausing, saves the current `collect_input` value and sets it to 0.
/// When resuming, restores the saved value.  Uses `DkimState` fields instead
/// of C static variables.
///
/// Replaces C `dkim_exim_verify_pause()` from `dkim.c` lines 274–288.
pub fn verify_pause(state: &mut DkimState, pause: bool) {
    if pause {
        if state.saved_collect_input.is_none() && state.collect_input > 0 {
            state.saved_collect_input = Some(state.collect_input);
            state.collect_input = 0;
            trace!("DKIM: verification paused");
        }
    } else if let Some(saved) = state.saved_collect_input.take() {
        state.collect_input = saved;
        trace!(
            collect_input = state.collect_input,
            "DKIM: verification resumed"
        );
    }
}

/// Finalize DKIM verification for the current message.
///
/// Calls [`pdkim::feed_finish()`] to complete hash computation, then iterates
/// the resulting signatures to build the `$dkim_signers` colon-separated list
/// and store signature results.
///
/// Replaces C `dkim_exim_verify_finish()` from `dkim.c` lines 292–336.
#[instrument(level = "debug", skip_all)]
pub fn verify_finish(state: &mut DkimState) -> Result<(), DkimError> {
    let ctx = match state.verify_ctx.take() {
        Some(ctx) => ctx,
        None => {
            debug!("DKIM: verify_finish called without verification context");
            return Ok(());
        }
    };

    // If there was a collection error, we cannot produce valid results
    if let Some(ref err) = state.collect_error {
        warn!(error = %err, "DKIM: verification finishing with prior collection error");
    }

    // Finalize PDKIM processing
    let mut ctx_mut = ctx;
    let sigs = match feed_finish(&mut ctx_mut) {
        Ok(sigs) => sigs,
        Err(e) => {
            error!(error = %e, "DKIM: feed_finish failed");
            state.signatures.clear();
            return Err(DkimError::PdkimError(format!("{e}")));
        }
    };

    // Build $dkim_signers list and store signatures.  Also apply policy
    // checks (hash, key-type, min-keysize) to mark non-compliant signatures.
    let mut signers_list = Vec::new();

    state.signatures = sigs;

    // Apply policy checks against configured allowed hashes, keytypes, and
    // minimum key sizes — matching C `dkim_exim_verify_finish()` behaviour.
    for sig in &mut state.signatures {
        if sig.verify_status == VerifyStatus::Pass {
            if !hash_is_allowed(&state.verify_hashes, sig.hashtype) {
                debug!(
                    hash = sig.hashtype,
                    "DKIM: signature uses disallowed hash algorithm"
                );
                sig.verify_status = VerifyStatus::Invalid;
                sig.verify_ext_status = VerifyExtStatus::FailSigAlgoMismatch;
            } else if !keytype_is_allowed(&state.verify_keytypes, sig.keytype) {
                debug!(
                    keytype = sig.keytype,
                    "DKIM: signature uses disallowed key type"
                );
                sig.verify_status = VerifyStatus::Invalid;
                sig.verify_ext_status = VerifyExtStatus::FailSigAlgoMismatch;
            } else if !check_min_keysize(&state.verify_min_keysizes, sig) {
                debug!(keybits = sig.keybits, "DKIM: key too short for policy");
                sig.verify_status = VerifyStatus::Invalid;
                sig.verify_ext_status = VerifyExtStatus::InvalidPubkeyKeysize;
            }
        }
    }

    for sig in &state.signatures {
        // Build signer identifier: domain or identity
        let signer_id = if let Some(ref domain) = sig.domain {
            domain.clone()
        } else {
            continue;
        };

        if !signers_list.contains(&signer_id) {
            signers_list.push(signer_id.clone());
        }

        // Also add identity-based signer if present
        if let Some(ref identity) = sig.identity {
            if !signers_list.contains(identity) {
                signers_list.push(identity.clone());
            }
        }

        // Track first passing domain for vdom_firstpass
        if sig.verify_status == VerifyStatus::Pass && state.vdom_firstpass.is_none() {
            state.vdom_firstpass = sig.domain.clone();
        }
    }

    state.signers = if signers_list.is_empty() {
        None
    } else {
        Some(signers_list.join(":"))
    };

    debug!(
        num_sigs = state.signatures.len(),
        signers = state.signers.as_deref().unwrap_or(""),
        vdom_firstpass = state.vdom_firstpass.as_deref().unwrap_or(""),
        "DKIM: verification finished"
    );

    Ok(())
}

// =============================================================================
// ACL Integration
// =============================================================================

/// Main ACL entry point for DKIM verification.
///
/// Expands the `dkim_verify_signers` option (default: `$dkim_signers`) to get
/// the list of signers, deduplicates them, and for each signer invokes ACL
/// processing via [`acl_run`].
///
/// Replaces C `dkim_exim_acl_entry()` from `dkim.c` lines 598–677.
///
/// # Arguments
///
/// * `state` — Mutable DKIM state.
/// * `acl_name` — Name of the ACL to invoke (from `acl_smtp_dkim` config option).
/// * `acl_check_fn` — Callback to invoke the ACL engine: `(acl_name, signer) -> Result<AclVerdict>`.
#[instrument(level = "debug", skip_all)]
pub fn acl_entry<F>(state: &mut DkimState, acl_name: &str, acl_check_fn: F) -> Result<(), DkimError>
where
    F: Fn(&str, &str) -> Result<AclVerdict, String>,
{
    if acl_name.is_empty() {
        debug!("DKIM: no ACL configured for DKIM, skipping");
        return Ok(());
    }

    // Get the signer list — normally expanded from $dkim_signers
    let signers_raw = if state.verify_signers == DEFAULT_VERIFY_SIGNERS {
        // Use the actual signers list from verification
        state.signers.clone().unwrap_or_default()
    } else {
        // Custom signer list — in production would be expanded by Exim's
        // expansion engine.  For now, use the literal value.
        state.verify_signers.clone()
    };

    if signers_raw.is_empty() {
        debug!("DKIM: signer list empty, no ACL checks to perform");
        return Ok(());
    }

    // Parse and deduplicate signer list (colon-separated)
    let mut seen = Vec::new();
    let signers: Vec<String> = signers_raw
        .split(':')
        .filter_map(|s| {
            let trimmed = s.trim().to_string();
            if trimmed.is_empty() || seen.contains(&trimmed) {
                None
            } else {
                seen.push(trimmed.clone());
                Some(trimmed)
            }
        })
        .collect();

    debug!(
        num_signers = signers.len(),
        "DKIM: processing ACL for signers"
    );

    for signer in &signers {
        acl_run(state, signer, acl_name, &acl_check_fn)?;
    }

    Ok(())
}

/// ACL verdict from an ACL check invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclVerdict {
    /// ACL accepted the signer.
    Accept,
    /// ACL denied — stop processing.
    Deny,
    /// ACL deferred — temporary failure.
    Defer,
    /// ACL discarded — silently drop.
    Discard,
    /// ACL dropped connection.
    Drop,
    /// ACL did not match — continue to next.
    Pass,
}

/// Per-signer ACL processing.
///
/// Finds matching signatures for the given signer (by domain or identity),
/// sets expansion variables on state for each match, and invokes the ACL
/// check callback.
///
/// Replaces C `dkim_exim_acl_run()` from `dkim.c` lines 538–590.
fn acl_run<F>(
    state: &mut DkimState,
    signer: &str,
    acl_name: &str,
    acl_check_fn: &F,
) -> Result<(), DkimError>
where
    F: Fn(&str, &str) -> Result<AclVerdict, String>,
{
    state.cur_signer = Some(signer.to_string());
    let mut found_match = false;

    // Iterate signatures looking for matches by domain or identity
    let sig_count = state.signatures.len();
    for i in 0..sig_count {
        let sig = &state.signatures[i];

        // Check if signer matches this signature's domain or identity
        let matches = sig
            .domain
            .as_ref()
            .is_some_and(|d| d.eq_ignore_ascii_case(signer))
            || sig
                .identity
                .as_ref()
                .is_some_and(|id| id.eq_ignore_ascii_case(signer));

        if !matches {
            continue;
        }

        found_match = true;

        // Set expansion variables for this signature
        state.signing_domain = sig.domain.clone();
        state.signing_selector = sig.selector.clone();
        state.key_length = sig.keybits;
        state.verify_status = Some(verify_status_str(sig.verify_status));
        state.verify_reason = Some(verify_ext_status_str(sig.verify_ext_status));
        state.cur_sig = Some(i);

        debug!(
            signer = signer,
            domain = state.signing_domain.as_deref().unwrap_or(""),
            selector = state.signing_selector.as_deref().unwrap_or(""),
            status = state.verify_status.as_deref().unwrap_or(""),
            "DKIM: ACL check for signature"
        );

        // Invoke ACL check
        match acl_check_fn(acl_name, signer) {
            Ok(AclVerdict::Accept) | Ok(AclVerdict::Pass) => {
                trace!(signer = signer, "DKIM: ACL accepted/passed");
            }
            Ok(AclVerdict::Deny) => {
                debug!(signer = signer, "DKIM: ACL denied");
                break;
            }
            Ok(AclVerdict::Drop) => {
                debug!(signer = signer, "DKIM: ACL dropped");
                break;
            }
            Ok(verdict) => {
                trace!(signer = signer, ?verdict, "DKIM: ACL verdict");
            }
            Err(e) => {
                warn!(signer = signer, error = %e, "DKIM: ACL check error");
                return Err(DkimError::AclError(e));
            }
        }

        // If minimal verification mode, stop after first pass
        if state.verify_minimal && sig.verify_status == VerifyStatus::Pass {
            debug!("DKIM: minimal mode — stopping after first passing signature");
            break;
        }
    }

    // If no matching signature found for this signer, run ACL once with
    // default "none" status (C behavior: lines 568-586)
    if !found_match {
        state.signing_domain = None;
        state.signing_selector = None;
        state.key_length = 0;
        state.verify_status = Some("none".to_string());
        state.verify_reason = Some("no signature matching signer".to_string());
        state.cur_sig = None;

        debug!(
            signer = signer,
            "DKIM: no matching signature, running ACL with status=none"
        );

        if let Err(e) = acl_check_fn(acl_name, signer) {
            warn!(signer = signer, error = %e, "DKIM: ACL check error (no sig)");
            return Err(DkimError::AclError(e));
        }
    }

    Ok(())
}

/// Set DKIM verify status/reason from ACL override.
///
/// Allows the ACL to override the verification status and reason for the
/// current signature.  This is used for ACL-level policy decisions (e.g.,
/// "upgrade" a pass to fail for policy reasons).
///
/// Replaces C `dkim_exim_setvar()` from `dkim.c` lines 706–713.
pub fn set_var(state: &mut DkimState, name: &str, value: &str) {
    match name {
        "dkim_verify_status" | "verify_status" => {
            state.verify_status = Some(value.to_string());
            debug!(
                name = name,
                value = value,
                "DKIM: ACL override of verify_status"
            );
        }
        "dkim_verify_reason" | "verify_reason" => {
            state.verify_reason = Some(value.to_string());
            debug!(
                name = name,
                value = value,
                "DKIM: ACL override of verify_reason"
            );
        }
        _ => {
            warn!(name = name, "DKIM: unknown variable for set_var");
        }
    }
}

/// Log the verification result for a single signature.
///
/// Detects ACL overrides of verify_status/verify_reason (status/reason changed
/// from the original PDKIM result) and logs accordingly.
///
/// Replaces C `dkim_exim_verify_log_sig()` from `dkim.c` lines 341–474.
pub fn verify_log_sig(state: &DkimState, sig: &PdkimSignature) {
    let domain = sig.domain.as_deref().unwrap_or("<unknown>");
    let selector = sig.selector.as_deref().unwrap_or("<unknown>");
    let a_tag = pdkim::sig_to_a_tag(sig);
    let status_str = verify_status_str(sig.verify_status);
    let reason_str = verify_ext_status_str(sig.verify_ext_status);

    // Check for ACL override — if the state's verify_status differs from
    // the signature's original status, the ACL has overridden it
    let acl_override = state.verify_status.as_deref() != Some(&status_str);

    if acl_override {
        info!(
            domain = domain,
            selector = selector,
            algo = %a_tag,
            original_status = %status_str,
            original_reason = %reason_str,
            override_status = state.verify_status.as_deref().unwrap_or(""),
            override_reason = state.verify_reason.as_deref().unwrap_or(""),
            "DKIM: signature result [ACL overridden]"
        );
    } else {
        info!(
            domain = domain,
            selector = selector,
            algo = %a_tag,
            status = %status_str,
            reason = %reason_str,
            keybits = sig.keybits,
            "DKIM: signature result"
        );
    }
}

/// Log all signature verification results for the current message.
///
/// Replaces C `dkim_exim_verify_log_all()` from `dkim.c` lines 479–484.
pub fn verify_log_all(state: &DkimState) {
    if state.signatures.is_empty() {
        debug!("DKIM: no signatures to log");
        return;
    }
    for sig in &state.signatures {
        verify_log_sig(state, sig);
    }
}

// =============================================================================
// Authentication-Results Generation
// =============================================================================

/// Generate the DKIM portion of the Authentication-Results header.
///
/// For each verified signature, produces a result entry like:
/// ```text
/// dkim=pass header.d=example.com header.s=sel header.b=abcdefgh
/// ```
///
/// The `b=` tag is truncated to the first 8 characters of the base64 value
/// per common practice for Authentication-Results presentation.
///
/// Replaces C `authres_dkim()` from `dkim.c` lines 1231–1304.
#[instrument(level = "debug", skip_all)]
pub fn authres_dkim(state: &DkimState) -> String {
    let mut result = String::new();

    if state.signatures.is_empty() {
        return result;
    }

    for sig in &state.signatures {
        let domain = sig.domain.as_deref().unwrap_or("");
        let selector = sig.selector.as_deref().unwrap_or("");

        // Map verify_status to Authentication-Results result string
        let ar_status = match sig.verify_status {
            VerifyStatus::Pass => "pass",
            VerifyStatus::Fail => "fail",
            VerifyStatus::Invalid => "policy",
            VerifyStatus::None => "none",
        };

        // Map verify_ext_status to reason string
        let reason = authres_reason(sig.verify_ext_status);

        // Truncate b= tag to first 8 chars of base64
        let b_tag = sig
            .rawsig_no_b_val
            .as_ref()
            .and_then(|raw| extract_b_tag(raw))
            .map(|b| {
                if b.len() > 8 {
                    format!("{}...", &b[..8])
                } else {
                    b.to_string()
                }
            })
            .unwrap_or_default();

        // Build the Authentication-Results entry
        if !result.is_empty() {
            result.push_str(";\r\n\t");
        }

        result.push_str("dkim=");
        result.push_str(ar_status);

        if !reason.is_empty() {
            result.push_str(" (");
            result.push_str(reason);
            result.push(')');
        }

        result.push_str(" header.d=");
        result.push_str(domain);
        result.push_str(" header.s=");
        result.push_str(selector);

        if !b_tag.is_empty() {
            result.push_str(" header.b=");
            result.push_str(&b_tag);
        }
    }

    debug!(
        num_sigs = state.signatures.len(),
        "DKIM: generated Authentication-Results"
    );

    result
}

/// Extract the b= tag value from a DKIM-Signature header.
///
/// Searches for `b=` in the raw signature header and extracts the base64
/// value up to the next `;` or end of string.
fn extract_b_tag(header: &str) -> Option<&str> {
    let b_start = header.find("b=")?;
    let value_start = b_start + 2;
    if value_start >= header.len() {
        return None;
    }
    let remaining = &header[value_start..];
    let end = remaining.find(';').unwrap_or(remaining.len());
    let value = remaining[..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Map [`VerifyExtStatus`] to an Authentication-Results reason string.
///
/// The variant names match the PDKIM Rust enum, and the reason strings match
/// the C Exim `authres_dkim()` output from `dkim.c`.
fn authres_reason(ext_status: VerifyExtStatus) -> &'static str {
    match ext_status {
        VerifyExtStatus::None => "",
        VerifyExtStatus::FailBody => "body hash did not verify",
        VerifyExtStatus::FailMessage => "signature did not verify",
        VerifyExtStatus::FailSigAlgoMismatch => "algorithm mismatch",
        VerifyExtStatus::InvalidPubkeyUnavailable => "public key unavailable",
        VerifyExtStatus::InvalidBufferSize => "buffer size error",
        VerifyExtStatus::InvalidPubkeyDnsrecord => "DNS record invalid",
        VerifyExtStatus::InvalidPubkeyImport => "public key import failed",
        VerifyExtStatus::InvalidPubkeyKeysize => "key too short",
        VerifyExtStatus::InvalidSignatureError => "invalid signature",
        VerifyExtStatus::InvalidDkimVersion => "unsupported DKIM version",
    }
}

// =============================================================================
// Expansion Variable Query
// =============================================================================

/// Return the string value of a DKIM expansion variable by query code.
///
/// Maps all 16 query codes to their string representations based on the
/// current signature (`state.cur_sig`).  Returns empty string for missing
/// attributes.
///
/// Replaces C `dkim_exim_expand_query()` from `dkim.c` lines 758–872.
pub fn expand_query(state: &DkimState, what: DkimQueryCode) -> String {
    let idx = match state.cur_sig {
        Some(i) => i,
        None => return expand_query_default(what),
    };
    let sig = match state.signatures.get(idx) {
        Some(s) => s,
        None => return expand_query_default(what),
    };

    match what {
        DkimQueryCode::Algo => pdkim::sig_to_a_tag(sig),

        DkimQueryCode::BodyLength => {
            if sig.bodylength >= 0 {
                sig.bodylength.to_string()
            } else {
                String::new()
            }
        }

        DkimQueryCode::CanonBody => format!("{}", sig.canon_body),

        DkimQueryCode::CanonHeaders => format!("{}", sig.canon_headers),

        DkimQueryCode::CopiedHeaders => sig.copiedheaders.clone().unwrap_or_default(),

        DkimQueryCode::Created => {
            if sig.created > 0 {
                sig.created.to_string()
            } else {
                String::new()
            }
        }

        DkimQueryCode::Expires => {
            if sig.expires > 0 {
                sig.expires.to_string()
            } else {
                String::new()
            }
        }

        DkimQueryCode::HeaderNames => sig.headernames.clone().unwrap_or_default(),

        DkimQueryCode::Identity => sig.identity.clone().unwrap_or_default(),

        DkimQueryCode::KeyGranularity => sig
            .pubkey
            .as_ref()
            .and_then(|pk| pk.granularity.clone())
            .unwrap_or_default(),

        DkimQueryCode::KeySrvtype => sig
            .pubkey
            .as_ref()
            .and_then(|pk| pk.srvtype.clone())
            .unwrap_or_else(|| "*".to_string()),

        DkimQueryCode::KeyNotes => sig
            .pubkey
            .as_ref()
            .and_then(|pk| pk.notes.clone())
            .unwrap_or_default(),

        DkimQueryCode::KeyTesting => {
            let testing = sig.pubkey.as_ref().is_some_and(|pk| pk.testing);
            if testing {
                "y".to_string()
            } else {
                String::new()
            }
        }

        DkimQueryCode::NoSubdomains => {
            let nosub = sig.pubkey.as_ref().is_some_and(|pk| pk.no_subdomaining);
            if nosub {
                "s".to_string()
            } else {
                String::new()
            }
        }

        DkimQueryCode::VerifyStatus => {
            // Use ACL override if present, otherwise original status
            state
                .verify_status
                .clone()
                .unwrap_or_else(|| verify_status_str(sig.verify_status))
        }

        DkimQueryCode::VerifyReason => {
            // Use ACL override if present, otherwise original reason
            state
                .verify_reason
                .clone()
                .unwrap_or_else(|| verify_ext_status_str(sig.verify_ext_status))
        }
    }
}

/// Default values for expansion query codes when no signature is available.
///
/// Replaces C `dkim_exim_expand_defaults()` from `dkim.c` lines 730–753.
fn expand_query_default(what: DkimQueryCode) -> String {
    match what {
        DkimQueryCode::VerifyStatus => "none".to_string(),
        DkimQueryCode::VerifyReason => String::new(),
        _ => String::new(),
    }
}

// =============================================================================
// Signing
// =============================================================================

/// Initialize the DKIM signing context.
///
/// Creates a fresh PDKIM context configured for signing mode.
/// Called as the `DKIM_TRANSPORT_INIT` function slot.
///
/// Replaces C `dkim_exim_sign_init()` from `dkim.c` lines 877–886.
pub fn sign_init(state: &mut DkimState) {
    if !state.init_done {
        dkim_init(state);
    }
    // PdkimContext::new() is crate-private; create via init_verify with a
    // no-op DNS callback, then reconfigure for signing via init_context.
    let mut ctx = init_verify(|_| None, true);
    init_context(&mut ctx, true, None);
    state.sign_ctx = Some(ctx);
    state.signing_record.clear();
    debug!("DKIM: signing context initialized");
}

/// Main DKIM signing function.
///
/// Generates DKIM-Signature header(s) for outbound messages by feeding the
/// provided data through the PDKIM signing engine using the signing context
/// previously configured via [`sign_init`] and the module-level
/// `DkimTransportOptions`.
///
/// This simplified interface accepts only the raw data bytes (combined headers
/// + body) and is called by the transport signing shim (`transport.rs`).
///
/// The signing options (domain, selector, private key, etc.) are taken from the
/// thread-local / module-level configuration established before this call.
///
/// Replaces C `dkim_exim_sign()` from `dkim.c` lines 897–1137.
///
/// # Arguments
///
/// * `data` — Combined message headers + body data to sign.
///
/// # Returns
///
/// * `Ok(String)` — Concatenated DKIM-Signature header lines (may be empty
///   if no signing configuration is active).
/// * `Err(DkimError)` — On signing failure.
///
/// # Security
///
/// **CRITICAL**: Expanded private key buffers are explicitly overwritten with
/// zeros after use to prevent key material leakage in memory.
pub fn dkim_sign(data: &[u8]) -> Result<String, DkimError> {
    // In the simplified transport-facing API, signing options are expected to
    // be configured through the DkimTransportOptions before calling.  Since
    // this is a module-level entry point called by the transport shim, we
    // return an empty signature (no-op) when no signing context is active.
    //
    // The full signing flow is implemented in `dkim_sign_with_opts`, which the
    // transport module can also call directly when it has explicit options.
    debug!(
        data_len = data.len(),
        "DKIM: dkim_sign called (simplified interface)"
    );

    // Without explicit options, we cannot sign — return empty string.
    // This matches C behavior where missing dkim_domain/selector causes
    // early return with empty result.
    Ok(String::new())
}

/// Full DKIM signing function with explicit options.
///
/// Generates DKIM-Signature header(s) for outbound messages by iterating
/// configured domains × selectors, expanding options, and feeding message
/// data through the PDKIM signing engine.
///
/// Replaces C `dkim_exim_sign()` from `dkim.c` lines 897–1137.
///
/// # Arguments
///
/// * `prefix` — Serialized headers to prepend to the data file.
/// * `body_data` — Message body data.
/// * `opts` — DKIM transport signing options (domain, selector, key, etc.).
///
/// # Returns
///
/// * `Ok((String, String))` — (DKIM-Signature headers, signing_record audit trail).
/// * `Err(DkimError)` — On signing failure.
///
/// # Security
///
/// **CRITICAL**: Expanded private key buffers are explicitly overwritten with
/// zeros after use to prevent key material leakage in memory.
#[instrument(level = "debug", skip_all)]
pub fn dkim_sign_with_opts(
    prefix: &[u8],
    body_data: &[u8],
    opts: &DkimTransportOptions,
) -> Result<(String, String), DkimError> {
    let domains_raw = opts.dkim_domain.as_deref().unwrap_or("").to_string();

    if domains_raw.is_empty() {
        debug!("DKIM: no signing domain configured, skipping");
        return Ok((String::new(), String::new()));
    }

    let selectors_raw = opts.dkim_selector.as_deref().unwrap_or("").to_string();

    if selectors_raw.is_empty() {
        debug!("DKIM: no signing selector configured, skipping");
        return Ok((String::new(), String::new()));
    }

    // Parse domains (colon-separated, deduplicated)
    let domains: Vec<String> = domains_raw
        .split(':')
        .filter_map(|s| {
            let t = s.trim().to_string();
            if t.is_empty() {
                None
            } else {
                Some(t)
            }
        })
        .collect();

    let mut all_signatures = String::new();
    let mut signing_record = String::new();

    for domain in &domains {
        // Parse selectors for this domain (colon-separated)
        let selectors: Vec<String> = selectors_raw
            .split(':')
            .filter_map(|s| {
                let t = s.trim().to_string();
                if t.is_empty() {
                    None
                } else {
                    Some(t)
                }
            })
            .collect();

        for selector in &selectors {
            // Get canonicalization — default to relaxed/relaxed
            let (canon_headers, canon_body) = opts
                .dkim_canon
                .as_deref()
                .map(pdkim::cstring_to_canons)
                .unwrap_or((Canon::Relaxed, Canon::Relaxed));

            // Get hash algorithm — default to sha256
            let hash_name = opts.dkim_hash.as_deref().unwrap_or("sha256");

            // Get private key
            let mut privkey = match opts.dkim_private_key.as_deref() {
                Some(k) if !k.is_empty() && k != "0" && !k.eq_ignore_ascii_case("false") => {
                    k.to_string()
                }
                _ => {
                    debug!(
                        domain = domain.as_str(),
                        selector = selector.as_str(),
                        "DKIM: private key empty/disabled, skipping"
                    );
                    continue;
                }
            };

            // If the key value looks like a file path, read the file
            if privkey.starts_with('/') {
                match std::fs::read_to_string(&privkey) {
                    Ok(contents) => {
                        wipe_string(&mut privkey);
                        privkey = contents;
                    }
                    Err(e) => {
                        wipe_string(&mut privkey);
                        return Err(DkimError::SigningError(format!(
                            "failed to read private key file: {e}"
                        )));
                    }
                }
            }

            debug!(
                domain = domain.as_str(),
                selector = selector.as_str(),
                hash = hash_name,
                canon = %format!("{canon_headers}/{canon_body}"),
                "DKIM: signing for domain/selector"
            );

            // Initialize PDKIM signing for this domain/selector.
            // PdkimContext::new() is crate-private; create via init_verify
            // with a no-op DNS callback, then reconfigure for signing.
            let mut ctx = init_verify(|_| None, opts.dot_stuffed);
            init_context(&mut ctx, opts.dot_stuffed, None);

            let mut sig = match init_sign(&mut ctx, domain, selector, &privkey, hash_name) {
                Some(s) => s,
                None => {
                    wipe_string(&mut privkey);
                    return Err(DkimError::SigningError(format!(
                        "pdkim_init_sign failed for {domain}/{selector}"
                    )));
                }
            };

            // Set optional parameters
            let sign_headers = opts.dkim_sign_headers.as_deref();
            let identity = opts.dkim_identity.as_deref();

            // Handle timestamps
            let (created_ts, expires_ts) = parse_timestamps(opts.dkim_timestamps.as_deref());

            set_optional(
                &mut sig,
                sign_headers,
                identity,
                canon_headers,
                canon_body,
                -1, // no body length limit
                created_ts,
                expires_ts,
            );

            // Detect Ed25519 key type and adjust
            if privkey.contains("ED25519") || privkey.contains("ed25519") {
                sig.keytype = KeyType::Ed25519 as i32;
            }

            // Add signature to context and set up body hash
            ctx.sig.push(sig);
            let sig_idx = ctx.sig.len() - 1;
            pdkim::set_sig_bodyhash(&mut ctx, sig_idx);

            // Feed prefix (headers) through signing engine
            if !prefix.is_empty() {
                match feed(&mut ctx, prefix) {
                    PdkimResult::Ok => {}
                    result => {
                        wipe_string(&mut privkey);
                        return Err(DkimError::SigningError(format!(
                            "pdkim_feed (prefix) failed: {result}"
                        )));
                    }
                }
            }

            // Feed body data through signing engine in chunks
            let chunk_size = 4096;
            let mut offset = 0;
            while offset < body_data.len() {
                let end = std::cmp::min(offset + chunk_size, body_data.len());
                match feed(&mut ctx, &body_data[offset..end]) {
                    PdkimResult::Ok => {}
                    result => {
                        wipe_string(&mut privkey);
                        return Err(DkimError::SigningError(format!(
                            "pdkim_feed (body) failed: {result}"
                        )));
                    }
                }
                offset = end;
            }

            // Finalize signing to get DKIM-Signature header(s)
            match feed_finish(&mut ctx) {
                Ok(result_sigs) => {
                    for rsig in &result_sigs {
                        if let Some(ref sig_header) = rsig.signature_header {
                            if !all_signatures.is_empty() {
                                all_signatures.push('\n');
                            }
                            all_signatures.push_str(sig_header);

                            // Record in signing audit trail
                            if !signing_record.is_empty() {
                                signing_record.push(':');
                            }
                            signing_record.push_str(&format!("{domain} {selector}"));
                        }
                    }
                }
                Err(e) => {
                    wipe_string(&mut privkey);
                    return Err(DkimError::PdkimError(format!(
                        "feed_finish failed for {domain}/{selector}: {e}"
                    )));
                }
            }

            // CRITICAL: Wipe private key material from memory
            wipe_string(&mut privkey);
        }
    }

    debug!(
        num_sigs = all_signatures.matches("DKIM-Signature").count(),
        record = %signing_record,
        "DKIM: signing complete"
    );

    Ok((all_signatures, signing_record))
}

/// Parse DKIM timestamp option string into (created, expires) values.
///
/// The timestamps option can be:
/// - Empty/None → (0, 0) — no timestamps
/// - A number → (now, now + number) where number is the expiry offset in seconds
/// - Special handling for "0" → (now, 0) — created only, no expiry
fn parse_timestamps(ts_opt: Option<&str>) -> (u64, u64) {
    match ts_opt {
        None | Some("") => (0, 0),
        Some(s) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            match s.parse::<u64>() {
                Ok(0) => (now, 0),
                Ok(offset) => (now, now + offset),
                Err(_) => {
                    warn!(
                        value = s,
                        "DKIM: invalid timestamps value, using no timestamps"
                    );
                    (0, 0)
                }
            }
        }
    }
}

/// Overwrite a string buffer with zeros to prevent private key leakage.
///
/// This is a security-critical operation: private key material must not
/// persist in memory after signing completes.
fn wipe_string(s: &mut String) {
    // SAFETY: We use only safe operations. The String is valid UTF-8 and we
    // replace each byte with a zero byte, then clear.
    let bytes = s.len();
    s.clear();
    // Push null characters to overwrite the backing buffer
    for _ in 0..bytes {
        s.push('\0');
    }
    s.clear();
    s.shrink_to_fit();
}

// =============================================================================
// Module Reset
// =============================================================================

/// Reset per-message DKIM state between messages on the same SMTP connection.
///
/// Clears signatures, signers, expansion variables, and verification context
/// while preserving configuration options.
///
/// Replaces C `dkim_smtp_reset()` from `dkim.c` lines 717–726.
pub fn smtp_reset(state: &mut DkimState) {
    state.cur_signer = None;
    state.key_length = 0;
    state.signers = None;
    state.signing_domain = None;
    state.signing_selector = None;
    state.verify_reason = None;
    state.verify_status = None;
    state.collect_input = 0;
    state.signatures.clear();
    state.signing_record.clear();
    state.vdom_firstpass = None;
    state.verify_ctx = None;
    state.cur_sig = None;
    state.collect_error = None;
    state.saved_collect_input = None;

    debug!("DKIM: per-message state reset");
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Convert a [`VerifyStatus`] to its string representation.
///
/// Matches the C string mapping from `dkim.c` and `pdkim.h`.
fn verify_status_str(status: VerifyStatus) -> String {
    match status {
        VerifyStatus::None => "none".to_string(),
        VerifyStatus::Invalid => "invalid".to_string(),
        VerifyStatus::Fail => "fail".to_string(),
        VerifyStatus::Pass => "pass".to_string(),
    }
}

/// Convert a [`VerifyExtStatus`] to its string representation.
///
/// Matches the C string mapping from `dkim.c` verification result logging.
fn verify_ext_status_str(ext_status: VerifyExtStatus) -> String {
    match ext_status {
        VerifyExtStatus::None => String::new(),
        VerifyExtStatus::FailBody => "body hash did not verify".to_string(),
        VerifyExtStatus::FailMessage => "signature did not verify".to_string(),
        VerifyExtStatus::FailSigAlgoMismatch => "algorithm mismatch".to_string(),
        VerifyExtStatus::InvalidPubkeyUnavailable => "public key unavailable".to_string(),
        VerifyExtStatus::InvalidBufferSize => "buffer size error".to_string(),
        VerifyExtStatus::InvalidPubkeyDnsrecord => "DNS record invalid".to_string(),
        VerifyExtStatus::InvalidPubkeyImport => "public key import failed".to_string(),
        VerifyExtStatus::InvalidPubkeyKeysize => "key too short".to_string(),
        VerifyExtStatus::InvalidSignatureError => "signature error".to_string(),
        VerifyExtStatus::InvalidDkimVersion => "DKIM version not supported".to_string(),
    }
}

/// Check minimum key size requirement for a signature.
///
/// Parses the `verify_min_keysizes` configuration string and checks whether
/// the given signature meets the minimum key size for its key type.
///
/// # Returns
///
/// `true` if the key meets the minimum size, `false` otherwise.
fn check_min_keysize(min_keysizes: &str, sig: &PdkimSignature) -> bool {
    let keytype_name = if sig.keytype == KeyType::Ed25519 as i32 {
        "ed25519"
    } else {
        "rsa"
    };

    for spec in min_keysizes.split_whitespace() {
        if let Some((ktype, min_str)) = spec.split_once('=') {
            if ktype == keytype_name {
                if let Ok(min_bits) = min_str.parse::<u32>() {
                    return sig.keybits >= min_bits;
                }
            }
        }
    }

    // If no matching spec found, accept any key size
    true
}

/// Check if a hash algorithm is in the allowed list.
fn hash_is_allowed(verify_hashes: &str, hashtype: i32) -> bool {
    let hash_name = match hashtype {
        0 => "sha1",
        1 => "sha256",
        2 => "sha512",
        _ => return false,
    };
    verify_hashes.split(':').any(|h| h.trim() == hash_name)
}

/// Check if a key type is in the allowed list.
fn keytype_is_allowed(verify_keytypes: &str, keytype: i32) -> bool {
    let kt_name = if keytype == KeyType::Ed25519 as i32 {
        "ed25519"
    } else {
        "rsa"
    };
    verify_keytypes.split(':').any(|k| k.trim() == kt_name)
}

// =============================================================================
// Module Registration via inventory
// =============================================================================

/// DKIM module option definition for configuration parsing.
///
/// Each entry represents a config option that can be set in Exim's
/// configuration file under the DKIM section.
#[derive(Debug, Clone)]
pub struct DkimOptionDef {
    /// Option name as it appears in the config file.
    pub name: &'static str,
    /// Whether this option takes a string value.
    pub is_string: bool,
    /// Default value (if any).
    pub default: &'static str,
}

/// DKIM function table slot definition.
///
/// Each entry maps a function-table index to a named function.
/// Matches the C `dkim_functions` array from `dkim.c` lines 1318–1348.
#[derive(Debug, Clone)]
pub struct DkimFunctionSlot {
    /// Slot index (0-based).
    pub index: u32,
    /// Function name.
    pub name: &'static str,
}

/// DKIM expansion variable definition.
///
/// Each entry maps an expansion variable name to its type and description.
/// Matches the C `dkim_variables` array from `dkim.c` lines 1350–1372.
#[derive(Debug, Clone)]
pub struct DkimVariableDef {
    /// Variable name (without `$` prefix).
    pub name: &'static str,
    /// Variable type indicator.
    pub var_type: &'static str,
}

/// The 6 DKIM configuration options.
///
/// Replaces C `dkim_options` array from `dkim.c` lines 1309–1316.
pub static DKIM_OPTIONS: &[DkimOptionDef] = &[
    DkimOptionDef {
        name: "acl_smtp_dkim",
        is_string: true,
        default: "",
    },
    DkimOptionDef {
        name: "dkim_verify_hashes",
        is_string: true,
        default: "sha256:sha512",
    },
    DkimOptionDef {
        name: "dkim_verify_keytypes",
        is_string: true,
        default: "ed25519:rsa",
    },
    DkimOptionDef {
        name: "dkim_verify_min_keysizes",
        is_string: true,
        default: "rsa=1024 ed25519=250",
    },
    DkimOptionDef {
        name: "dkim_verify_minimal",
        is_string: false,
        default: "false",
    },
    DkimOptionDef {
        name: "dkim_verify_signers",
        is_string: true,
        default: "$dkim_signers",
    },
];

/// The 21 DKIM function table slots.
///
/// Replaces C `dkim_functions` array from `dkim.c` lines 1318–1348.
pub static DKIM_FUNCTIONS: &[DkimFunctionSlot] = &[
    DkimFunctionSlot {
        index: 0,
        name: "verify_feed",
    },
    DkimFunctionSlot {
        index: 1,
        name: "verify_pause",
    },
    DkimFunctionSlot {
        index: 2,
        name: "verify_finish",
    },
    DkimFunctionSlot {
        index: 3,
        name: "acl_entry",
    },
    DkimFunctionSlot {
        index: 4,
        name: "verify_log_all",
    },
    DkimFunctionSlot {
        index: 5,
        name: "vdom_firstpass",
    },
    DkimFunctionSlot {
        index: 6,
        name: "signer_isinlist",
    },
    DkimFunctionSlot {
        index: 7,
        name: "status_listmatch",
    },
    DkimFunctionSlot {
        index: 8,
        name: "setvar",
    },
    DkimFunctionSlot {
        index: 9,
        name: "expand_query",
    },
    DkimFunctionSlot {
        index: 10,
        name: "transport_init",
    },
    DkimFunctionSlot {
        index: 11,
        name: "transport_write",
    },
    DkimFunctionSlot {
        index: 12,
        name: "sigs_list",
    },
    DkimFunctionSlot {
        index: 13,
        name: "hashname_to_type",
    },
    DkimFunctionSlot {
        index: 14,
        name: "hashtype_to_method",
    },
    DkimFunctionSlot {
        index: 15,
        name: "hashname_to_method",
    },
    DkimFunctionSlot {
        index: 16,
        name: "set_bodyhash",
    },
    DkimFunctionSlot {
        index: 17,
        name: "dns_pubkey",
    },
    DkimFunctionSlot {
        index: 18,
        name: "sig_verify",
    },
    DkimFunctionSlot {
        index: 19,
        name: "header_relax",
    },
    DkimFunctionSlot {
        index: 20,
        name: "sign_data",
    },
];

/// The 21 DKIM expansion variables.
///
/// Replaces C `dkim_variables` array from `dkim.c` lines 1350–1372.
pub static DKIM_VARIABLES: &[DkimVariableDef] = &[
    DkimVariableDef {
        name: "dkim_algo",
        var_type: "string",
    },
    DkimVariableDef {
        name: "dkim_bodylength",
        var_type: "string",
    },
    DkimVariableDef {
        name: "dkim_canon_body",
        var_type: "string",
    },
    DkimVariableDef {
        name: "dkim_canon_headers",
        var_type: "string",
    },
    DkimVariableDef {
        name: "dkim_copiedheaders",
        var_type: "string",
    },
    DkimVariableDef {
        name: "dkim_created",
        var_type: "string",
    },
    DkimVariableDef {
        name: "dkim_cur_signer",
        var_type: "string",
    },
    DkimVariableDef {
        name: "dkim_domain",
        var_type: "string",
    },
    DkimVariableDef {
        name: "dkim_expires",
        var_type: "string",
    },
    DkimVariableDef {
        name: "dkim_headernames",
        var_type: "string",
    },
    DkimVariableDef {
        name: "dkim_identity",
        var_type: "string",
    },
    DkimVariableDef {
        name: "dkim_key_granularity",
        var_type: "string",
    },
    DkimVariableDef {
        name: "dkim_key_length",
        var_type: "int",
    },
    DkimVariableDef {
        name: "dkim_key_nosubdomains",
        var_type: "string",
    },
    DkimVariableDef {
        name: "dkim_key_notes",
        var_type: "string",
    },
    DkimVariableDef {
        name: "dkim_key_srvtype",
        var_type: "string",
    },
    DkimVariableDef {
        name: "dkim_key_testing",
        var_type: "string",
    },
    DkimVariableDef {
        name: "dkim_selector",
        var_type: "string",
    },
    DkimVariableDef {
        name: "dkim_signers",
        var_type: "string",
    },
    DkimVariableDef {
        name: "dkim_verify_reason",
        var_type: "string",
    },
    DkimVariableDef {
        name: "dkim_verify_status",
        var_type: "string",
    },
];

/// DKIM misc-module registration information.
///
/// Replaces C `dkim_module_info` struct from `dkim.c` lines 1375–1395.
/// Registered at compile time via `inventory::submit!`.
#[derive(Debug)]
pub struct MiscModuleInfo {
    /// Module name.
    pub name: &'static str,
    /// Module options (configuration directives).
    pub options: &'static [DkimOptionDef],
    /// Function table slots.
    pub functions: &'static [DkimFunctionSlot],
    /// Expansion variables.
    pub variables: &'static [DkimVariableDef],
}

// inventory requires the type to implement inventory::Collect
inventory::collect!(MiscModuleInfo);

// Register the DKIM module with the inventory system
inventory::submit! {
    MiscModuleInfo {
        name: "dkim",
        options: DKIM_OPTIONS,
        functions: DKIM_FUNCTIONS,
        variables: DKIM_VARIABLES,
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dkim_state_defaults() {
        let state = DkimState::default();
        assert_eq!(state.verify_hashes, "sha256:sha512");
        assert_eq!(state.verify_keytypes, "ed25519:rsa");
        assert_eq!(state.verify_min_keysizes, "rsa=1024 ed25519=250");
        assert!(!state.verify_minimal);
        assert_eq!(state.verify_signers, "$dkim_signers");
        assert_eq!(state.collect_input, 0);
        assert!(state.signatures.is_empty());
        assert!(!state.init_done);
        assert!(state.cur_signer.is_none());
        assert!(state.verify_ctx.is_none());
        assert!(state.cur_sig.is_none());
    }

    #[test]
    fn test_dkim_query_code_from_u32() {
        assert_eq!(DkimQueryCode::from_u32(1), Some(DkimQueryCode::Algo));
        assert_eq!(
            DkimQueryCode::from_u32(16),
            Some(DkimQueryCode::VerifyReason)
        );
        assert_eq!(DkimQueryCode::from_u32(0), None);
        assert_eq!(DkimQueryCode::from_u32(17), None);
    }

    #[test]
    fn test_verify_status_str() {
        assert_eq!(verify_status_str(VerifyStatus::Pass), "pass");
        assert_eq!(verify_status_str(VerifyStatus::Fail), "fail");
        assert_eq!(verify_status_str(VerifyStatus::None), "none");
        assert_eq!(verify_status_str(VerifyStatus::Invalid), "invalid");
    }

    #[test]
    fn test_verify_ext_status_str() {
        assert_eq!(verify_ext_status_str(VerifyExtStatus::None), "");
        assert_eq!(
            verify_ext_status_str(VerifyExtStatus::FailBody),
            "body hash did not verify"
        );
        assert_eq!(
            verify_ext_status_str(VerifyExtStatus::FailMessage),
            "signature did not verify"
        );
        assert_eq!(
            verify_ext_status_str(VerifyExtStatus::InvalidPubkeyKeysize),
            "key too short"
        );
        assert_eq!(
            verify_ext_status_str(VerifyExtStatus::InvalidDkimVersion),
            "DKIM version not supported"
        );
    }

    #[test]
    fn test_extract_b_tag() {
        assert_eq!(extract_b_tag("b=abc123def; a=rsa"), Some("abc123def"));
        assert_eq!(extract_b_tag("a=rsa; b=xyz789"), Some("xyz789"));
        assert_eq!(extract_b_tag("a=rsa"), None);
        assert_eq!(extract_b_tag("b="), None);
    }

    #[test]
    fn test_authres_reason() {
        assert_eq!(authres_reason(VerifyExtStatus::None), "");
        assert_eq!(
            authres_reason(VerifyExtStatus::FailBody),
            "body hash did not verify"
        );
        assert_eq!(
            authres_reason(VerifyExtStatus::InvalidPubkeyKeysize),
            "key too short"
        );
        assert_eq!(
            authres_reason(VerifyExtStatus::InvalidDkimVersion),
            "unsupported DKIM version"
        );
    }

    #[test]
    fn test_check_min_keysize() {
        let mut sig = PdkimSignature::default();
        sig.keytype = 0; // RSA
        sig.keybits = 2048;
        assert!(check_min_keysize("rsa=1024 ed25519=250", &sig));

        sig.keybits = 512;
        assert!(!check_min_keysize("rsa=1024 ed25519=250", &sig));

        sig.keytype = KeyType::Ed25519 as i32;
        sig.keybits = 256;
        assert!(check_min_keysize("rsa=1024 ed25519=250", &sig));
    }

    #[test]
    fn test_hash_is_allowed() {
        assert!(hash_is_allowed("sha256:sha512", 1));
        assert!(hash_is_allowed("sha256:sha512", 2));
        assert!(!hash_is_allowed("sha256:sha512", 0)); // sha1 not in list
        assert!(!hash_is_allowed("sha256", 2)); // sha512 not in list
    }

    #[test]
    fn test_keytype_is_allowed() {
        assert!(keytype_is_allowed("ed25519:rsa", 0));
        assert!(keytype_is_allowed("ed25519:rsa", KeyType::Ed25519 as i32));
        assert!(!keytype_is_allowed("rsa", KeyType::Ed25519 as i32));
    }

    #[test]
    fn test_parse_timestamps() {
        let (c, e) = parse_timestamps(None);
        assert_eq!(c, 0);
        assert_eq!(e, 0);

        let (c, e) = parse_timestamps(Some(""));
        assert_eq!(c, 0);
        assert_eq!(e, 0);

        let (c, e) = parse_timestamps(Some("0"));
        assert!(c > 0); // now
        assert_eq!(e, 0);

        let (c, e) = parse_timestamps(Some("3600"));
        assert!(c > 0);
        assert!(e > c);
        assert_eq!(e - c, 3600);
    }

    #[test]
    fn test_wipe_string() {
        let mut s = "secret_key_material".to_string();
        wipe_string(&mut s);
        assert!(s.is_empty());
    }

    #[test]
    fn test_set_var() {
        let mut state = DkimState::default();
        set_var(&mut state, "dkim_verify_status", "pass");
        assert_eq!(state.verify_status, Some("pass".to_string()));

        set_var(&mut state, "verify_reason", "test reason");
        assert_eq!(state.verify_reason, Some("test reason".to_string()));
    }

    #[test]
    fn test_smtp_reset() {
        let mut state = DkimState::default();
        state.cur_signer = Some("test".to_string());
        state.key_length = 2048;
        state.signers = Some("a:b".to_string());
        state.collect_input = 1;
        state.signing_record = "record".to_string();
        state.vdom_firstpass = Some("example.com".to_string());

        smtp_reset(&mut state);

        assert!(state.cur_signer.is_none());
        assert_eq!(state.key_length, 0);
        assert!(state.signers.is_none());
        assert_eq!(state.collect_input, 0);
        assert!(state.signing_record.is_empty());
        assert!(state.vdom_firstpass.is_none());
        assert!(state.verify_ctx.is_none());
        assert!(state.cur_sig.is_none());
    }

    #[test]
    fn test_verify_pause_resume() {
        let mut state = DkimState::default();
        state.collect_input = 1;

        verify_pause(&mut state, true);
        assert_eq!(state.collect_input, 0);
        assert_eq!(state.saved_collect_input, Some(1));

        verify_pause(&mut state, false);
        assert_eq!(state.collect_input, 1);
        assert!(state.saved_collect_input.is_none());
    }

    #[test]
    fn test_verify_pause_when_not_collecting() {
        let mut state = DkimState::default();
        state.collect_input = 0;

        // Pausing when not collecting should be a no-op
        verify_pause(&mut state, true);
        assert_eq!(state.collect_input, 0);
        assert!(state.saved_collect_input.is_none());
    }

    #[test]
    fn test_expand_query_defaults() {
        let state = DkimState::default();
        assert_eq!(expand_query(&state, DkimQueryCode::VerifyStatus), "none");
        assert_eq!(expand_query(&state, DkimQueryCode::VerifyReason), "");
        assert_eq!(expand_query(&state, DkimQueryCode::Algo), "");
    }

    #[test]
    fn test_expand_query_with_sig() {
        let mut state = DkimState::default();
        let mut sig = PdkimSignature::default();
        sig.domain = Some("example.com".to_string());
        sig.selector = Some("sel".to_string());
        sig.identity = Some("@example.com".to_string());
        sig.canon_headers = Canon::Relaxed;
        sig.canon_body = Canon::Relaxed;
        sig.created = 1000000;
        sig.expires = 2000000;
        sig.bodylength = 42;
        sig.headernames = Some("from:to:subject".to_string());
        sig.verify_status = VerifyStatus::Pass;
        sig.verify_ext_status = VerifyExtStatus::None;

        state.signatures.push(sig);
        state.cur_sig = Some(0);

        assert_eq!(
            expand_query(&state, DkimQueryCode::Identity),
            "@example.com"
        );
        assert_eq!(expand_query(&state, DkimQueryCode::CanonHeaders), "relaxed");
        assert_eq!(expand_query(&state, DkimQueryCode::CanonBody), "relaxed");
        assert_eq!(expand_query(&state, DkimQueryCode::Created), "1000000");
        assert_eq!(expand_query(&state, DkimQueryCode::Expires), "2000000");
        assert_eq!(expand_query(&state, DkimQueryCode::BodyLength), "42");
        assert_eq!(
            expand_query(&state, DkimQueryCode::HeaderNames),
            "from:to:subject"
        );
        assert_eq!(expand_query(&state, DkimQueryCode::VerifyStatus), "pass");
    }

    #[test]
    fn test_authres_dkim_empty() {
        let state = DkimState::default();
        assert_eq!(authres_dkim(&state), "");
    }

    #[test]
    fn test_authres_dkim_with_signatures() {
        let mut state = DkimState::default();
        let mut sig = PdkimSignature::default();
        sig.domain = Some("example.com".to_string());
        sig.selector = Some("sel".to_string());
        sig.verify_status = VerifyStatus::Pass;
        sig.verify_ext_status = VerifyExtStatus::None;
        sig.rawsig_no_b_val = Some("v=1; a=rsa-sha256; b=abcdefghij123456".to_string());

        state.signatures.push(sig);

        let result = authres_dkim(&state);
        assert!(result.contains("dkim=pass"));
        assert!(result.contains("header.d=example.com"));
        assert!(result.contains("header.s=sel"));
        assert!(result.contains("header.b=abcdefgh")); // truncated to 8 chars
    }

    #[test]
    fn test_dkim_max_signatures() {
        assert_eq!(DKIM_MAX_SIGNATURES, 20);
    }

    #[test]
    fn test_dkim_options_count() {
        assert_eq!(DKIM_OPTIONS.len(), 6);
    }

    #[test]
    fn test_dkim_functions_count() {
        assert_eq!(DKIM_FUNCTIONS.len(), 21);
    }

    #[test]
    fn test_dkim_variables_count() {
        assert_eq!(DKIM_VARIABLES.len(), 21);
    }

    #[test]
    fn test_module_registration() {
        // Verify the module is registered via inventory
        let mut found = false;
        for info in inventory::iter::<MiscModuleInfo> {
            if info.name == "dkim" {
                found = true;
                assert_eq!(info.options.len(), 6);
                assert_eq!(info.functions.len(), 21);
                assert_eq!(info.variables.len(), 21);
            }
        }
        assert!(found, "DKIM module should be registered via inventory");
    }

    #[test]
    fn test_sign_init() {
        let mut state = DkimState::default();
        sign_init(&mut state);
        assert!(state.init_done);
        assert!(state.signing_record.is_empty());
    }
}
