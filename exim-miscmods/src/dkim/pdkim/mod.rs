//! PDKIM — Streaming DKIM library implementing RFC 4871 / RFC 6376.
//!
//! This module provides a complete DKIM (DomainKeys Identified Mail)
//! implementation supporting both signing and verification of email messages.
//! It processes message data incrementally (streaming), performing
//! canonicalization, body hashing, DKIM-Signature header parsing, DNS public
//! key retrieval, and cryptographic sign/verify operations.
//!
//! # Architecture
//!
//! The streaming design processes message data byte-by-byte through [`feed`],
//! accumulating headers and body lines. After all data is fed, [`feed_finish`]
//! completes signing or verification by computing header hashes and invoking
//! the cryptographic backend via the [`signing`] submodule.
//!
//! # Usage
//!
//! **Signing:**
//! 1. Call [`init`] once at startup.
//! 2. Create a context via [`init_context`] or construct [`PdkimContext`] directly.
//! 3. Add signing signatures via [`init_sign`] and [`set_optional`].
//! 4. Feed message data via [`feed`].
//! 5. Complete signing via [`feed_finish`], which returns signatures with
//!    generated `DKIM-Signature` headers.
//!
//! **Verification:**
//! 1. Call [`init`] once at startup.
//! 2. Create a context via [`init_verify`] with a DNS TXT callback.
//! 3. Feed message data via [`feed`] — DKIM-Signature headers are detected
//!    and parsed automatically.
//! 4. Complete verification via [`feed_finish`], which fetches DNS keys and
//!    returns signatures with verification status.
//!
//! # Behavioral Compatibility
//!
//! This is a faithful rewrite of the C `pdkim.c` (2,110 lines) and `pdkim.h`
//! (374 lines) from the Exim MTA. Every function, constant, and data structure
//! preserves the original behavioral semantics to ensure identical DKIM
//! signing/verification results.

// SAFETY: This module contains zero unsafe code per AAP §0.7.2.
// All cryptographic operations are delegated to the `signing` submodule
// which in turn uses the exim-ffi crate for C library bindings.
#![forbid(unsafe_code)]

/// Cryptographic backend abstraction for DKIM signing and verification.
pub mod signing;

// =============================================================================
// External imports
// =============================================================================

use tracing::{debug, error, info, trace, warn};

// =============================================================================
// Internal imports
// =============================================================================

use crate::dkim::pdkim::signing::{
    HashAlgorithm, KeyFormat, KeyType, SigningError, VerificationContext,
};
use exim_store::{Clean, MessageArena, Tainted, TaintedString};

/// Type alias for the DNS TXT record lookup callback function.
///
/// Accepts a DNS name (e.g., `"selector._domainkey.example.com."`) and
/// returns the concatenated TXT record content, or `None` on lookup failure.
pub type DnsTxtCallback = Box<dyn Fn(&str) -> Option<String>>;

/// Type alias for the ARC header feed callback.
type ArcHeaderCallback = Box<dyn Fn(&str, bool)>;

// =============================================================================
// Constants (from pdkim.h lines 35-56 and pdkim.c lines 53-59)
// =============================================================================

/// Default set of headers to include in DKIM signatures.
///
/// Matches C `PDKIM_DEFAULT_SIGN_HEADERS` from pdkim.h lines 35-42 exactly.
/// These are the headers recommended by RFC 6376 §5.4 for inclusion in the
/// signature, listed as colon-separated names.
pub const PDKIM_DEFAULT_SIGN_HEADERS: &str = "\
From:Sender:Reply-To:Subject:Date:Message-ID:\
To:Cc:MIME-Version:Content-Type:Content-Transfer-Encoding:\
Content-ID:Content-Description:\
Resent-Date:Resent-From:Resent-Sender:Resent-To:Resent-Cc:\
Resent-Message-ID:\
In-Reply-To:References:\
List-Id:List-Help:List-Unsubscribe:List-Subscribe:List-Post:\
List-Owner:List-Archive";

/// Headers to oversign (with `+` prefix indicating multi-sign mode).
///
/// Matches C `PDKIM_OVERSIGN_HEADERS` from pdkim.h lines 44-51.
/// The `+` prefix tells the signing code to sign these headers even if
/// they appear multiple times, preventing header injection attacks.
pub const PDKIM_OVERSIGN_HEADERS: &str = "\
+From:+Sender:+Reply-To:+Subject:+Date:+Message-ID:\
+To:+Cc:+MIME-Version:+Content-Type:+Content-Transfer-Encoding:\
+Content-ID:+Content-Description:\
+Resent-Date:+Resent-From:+Resent-Sender:+Resent-To:+Resent-Cc:\
+Resent-Message-ID:\
+In-Reply-To:+References:\
+List-Id:+List-Help:+List-Unsubscribe:+List-Subscribe:+List-Post:\
+List-Owner:+List-Archive";

/// Maximum length of a DNS TXT record for DKIM public keys.
/// Matches C `PDKIM_DNS_TXT_MAX_RECLEN` from pdkim.h line 56: `(1 << 16)`.
pub const PDKIM_DNS_TXT_MAX_RECLEN: usize = 1 << 16;

/// DKIM signature version string. Only version "1" is supported per RFC 6376.
/// Matches C `PDKIM_SIGNATURE_VERSION` from pdkim.c line 53.
pub const PDKIM_SIGNATURE_VERSION: &str = "1";

/// DKIM public key record version string.
/// Matches C `PDKIM_PUB_RECORD_VERSION` from pdkim.c line 54.
pub const PDKIM_PUB_RECORD_VERSION: &str = "DKIM1";

/// Maximum length of a single header line (including folded continuations).
/// Matches C `PDKIM_MAX_HEADER_LEN` from pdkim.c line 56.
pub const PDKIM_MAX_HEADER_LEN: usize = 65536;

/// Maximum number of headers to process before rejecting the message.
/// Matches C `PDKIM_MAX_HEADERS` from pdkim.c line 57.
pub const PDKIM_MAX_HEADERS: usize = 512;

/// Maximum length of a single body line.
/// Matches C `PDKIM_MAX_BODY_LINE_LEN` from pdkim.c line 58.
pub const PDKIM_MAX_BODY_LINE_LEN: usize = 16384;

/// Maximum length of a DNS TXT record name for DKIM key lookup.
/// Matches C `PDKIM_DNS_TXT_MAX_NAMELEN` from pdkim.c line 59.
pub const PDKIM_DNS_TXT_MAX_NAMELEN: usize = 1024;

/// Bitmask flag for verify-policy override status.
/// Matches C `PDKIM_VERIFY_POLICY` from pdkim.h line 76: `BIT(31)`.
pub const PDKIM_VERIFY_POLICY: u32 = 1 << 31;

// =============================================================================
// Lookup tables (from pdkim.c lines 70-113)
// =============================================================================

/// Supported DKIM query methods. Only `dns/txt` is defined by RFC 6376.
/// Matches C `pdkim_querymethods` from pdkim.c lines 70-73.
pub const PDKIM_QUERYMETHODS: &[&str] = &["dns/txt"];

/// Hash type descriptor mapping DKIM hash names to internal algorithm types.
///
/// Matches C `pdkim_hashtype` struct from pdkim.h lines 310-314 and
/// `pdkim_hashes` array from pdkim.c lines 80-84.
#[derive(Debug, Clone, Copy)]
pub struct PdkimHashType {
    /// DKIM algorithm name as it appears in the `a=` tag (e.g., "sha256").
    pub dkim_hashname: &'static str,
    /// Corresponding internal hash algorithm enum value.
    pub exim_hashmethod: HashAlgorithm,
}

/// Table of supported DKIM hash algorithms.
///
/// Index 0 = SHA-1 (legacy), 1 = SHA-256, 2 = SHA-512.
/// Matches C `pdkim_hashes` from pdkim.c lines 80-84.
pub const PDKIM_HASHES: &[PdkimHashType] = &[
    PdkimHashType {
        dkim_hashname: "sha1",
        exim_hashmethod: HashAlgorithm::Sha1,
    },
    PdkimHashType {
        dkim_hashname: "sha256",
        exim_hashmethod: HashAlgorithm::Sha256,
    },
    PdkimHashType {
        dkim_hashname: "sha512",
        exim_hashmethod: HashAlgorithm::Sha512,
    },
];

/// Table of supported DKIM key types.
///
/// Index 0 = RSA, 1 = Ed25519.
/// Matches C `pdkim_keytypes` from pdkim.c lines 86-97.
pub const PDKIM_KEYTYPES: &[&str] = &["rsa", "ed25519"];

/// Combined canonicalization method descriptor.
///
/// Maps a string representation (e.g., "relaxed/simple") to header and body
/// canonicalization methods. Matches C `pdkim_combined_canon` struct and
/// `pdkim_combined_canons` array from pdkim.c lines 99-113.
#[derive(Debug, Clone, Copy)]
pub struct CombinedCanon {
    /// String representation as it appears in the `c=` tag.
    pub str_repr: &'static str,
    /// Canonicalization method for headers.
    pub canon_headers: Canon,
    /// Canonicalization method for the message body.
    pub canon_body: Canon,
}

/// Table of all valid canonicalization method combinations.
///
/// Includes both explicit (`simple/relaxed`) and shorthand (`simple`) forms.
/// Per RFC 6376 §3.5, when only one method is specified, it applies to
/// headers and `simple` is implied for the body.
pub const PDKIM_COMBINED_CANONS: &[CombinedCanon] = &[
    CombinedCanon {
        str_repr: "simple/simple",
        canon_headers: Canon::Simple,
        canon_body: Canon::Simple,
    },
    CombinedCanon {
        str_repr: "simple/relaxed",
        canon_headers: Canon::Simple,
        canon_body: Canon::Relaxed,
    },
    CombinedCanon {
        str_repr: "relaxed/simple",
        canon_headers: Canon::Relaxed,
        canon_body: Canon::Simple,
    },
    CombinedCanon {
        str_repr: "relaxed/relaxed",
        canon_headers: Canon::Relaxed,
        canon_body: Canon::Relaxed,
    },
    CombinedCanon {
        str_repr: "simple",
        canon_headers: Canon::Simple,
        canon_body: Canon::Simple,
    },
    CombinedCanon {
        str_repr: "relaxed",
        canon_headers: Canon::Relaxed,
        canon_body: Canon::Simple,
    },
];

// =============================================================================
// Enums (from pdkim.h lines 60-94)
// =============================================================================

/// Canonicalization method for headers or body per RFC 6376 §3.4.
///
/// Matches C `PDKIM_CANON_SIMPLE` (0) and `PDKIM_CANON_RELAXED` (1)
/// from pdkim.h lines 93-94.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Canon {
    /// Simple canonicalization: no modification except trailing CRLF.
    Simple = 0,
    /// Relaxed canonicalization: whitespace folding and header lowercasing.
    Relaxed = 1,
}

/// PDKIM function result codes.
///
/// Matches C error codes from pdkim.h lines 60-68.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdkimResult {
    /// Success (PDKIM_OK = 0).
    Ok = 0,
    /// General failure (PDKIM_FAIL = -1).
    Fail = -1,
    /// RSA private key error (PDKIM_ERR_RSA_PRIVKEY = -101).
    ErrRsaPrivkey = -101,
    /// RSA signing error (PDKIM_ERR_RSA_SIGNING = -102).
    ErrRsaSigning = -102,
    /// Line too long (PDKIM_ERR_LONG_LINE = -103).
    ErrLongLine = -103,
    /// Buffer too small (PDKIM_ERR_BUFFER_TOO_SMALL = -104).
    ErrBufferTooSmall = -104,
    /// Too many signatures (PDKIM_ERR_EXCESS_SIGS = -105).
    ErrExcessSigs = -105,
    /// Private key wrapping error (PDKIM_SIGN_PRIVKEY_WRAP = -106).
    SignPrivkeyWrap = -106,
    /// Private key base64 decode error (PDKIM_SIGN_PRIVKEY_B64D = -107).
    SignPrivkeyB64d = -107,
}

/// DKIM verification status.
///
/// Matches C `PDKIM_VERIFY_*` constants from pdkim.h lines 72-75.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyStatus {
    /// Not yet verified.
    None = 0,
    /// Signature is structurally invalid.
    Invalid = 1,
    /// Signature verification failed.
    Fail = 2,
    /// Signature verification passed.
    Pass = 3,
}

/// Extended verification status providing failure/invalidity reason.
///
/// Matches C `PDKIM_VERIFY_FAIL_*` and `PDKIM_VERIFY_INVALID_*` constants
/// from pdkim.h lines 78-87.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyExtStatus {
    /// No extended status.
    None = 0,
    /// Body hash mismatch.
    FailBody = 1,
    /// Message signature (header hash) mismatch.
    FailMessage = 2,
    /// Signature algorithm mismatch with pubkey.
    FailSigAlgoMismatch = 3,
    /// Public key unavailable from DNS.
    InvalidPubkeyUnavailable = 4,
    /// Buffer size error.
    InvalidBufferSize = 5,
    /// Invalid DNS public key record format.
    InvalidPubkeyDnsrecord = 6,
    /// Public key import failed.
    InvalidPubkeyImport = 7,
    /// Public key size below minimum.
    InvalidPubkeyKeysize = 8,
    /// Signature parse error.
    InvalidSignatureError = 9,
    /// Invalid DKIM version in signature.
    InvalidDkimVersion = 10,
}

// =============================================================================
// Error type (from pdkim.c lines 197-213)
// =============================================================================

/// Errors that can occur during PDKIM operations.
///
/// Replaces the C `pdkim_errstr()` error string mapping and provides
/// structured error variants for Rust-idiomatic error handling.
#[derive(Debug, thiserror::Error)]
pub enum PdkimError {
    /// General PDKIM error wrapping a result code.
    #[error("PDKIM error: {0}")]
    General(PdkimResult),
    /// Hash context initialization failed.
    #[error("Hash initialization failed")]
    HashInitFailed,
    /// Signing operation failed during initialization.
    #[error("Signing initialization failed: {0}")]
    SigningInitFailed(String),
    /// Signature verification failed.
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    /// DNS lookup for public key failed.
    #[error("DNS lookup failed for {0}")]
    DnsLookupFailed(String),
    /// Cryptographic signing error from the signing backend.
    #[error("Crypto signing error: {0}")]
    CryptoError(#[from] SigningError),
}

// =============================================================================
// Bitflags (from pdkim.h lines 280-305)
// =============================================================================

bitflags::bitflags! {
    /// Flags controlling the state and mode of a PDKIM context.
    ///
    /// Matches C `#define PDKIM_MODE_SIGN` through `PDKIM_SEEN_EOD`
    /// from pdkim.h lines 280-305 (BIT(0) through BIT(5)).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PdkimFlags: u32 {
        /// Context is in signing mode (vs verification).
        /// C: `PDKIM_MODE_SIGN  BIT(0)` = 0x01.
        const MODE_SIGN = 0x01;
        /// Input is dot-terminated (SMTP DATA).
        /// C: `PDKIM_DOT_TERM   BIT(1)` = 0x02.
        const DOT_TERM  = 0x02;
        /// Last byte was CR.
        /// C: `PDKIM_SEEN_CR    BIT(2)` = 0x04.
        const SEEN_CR   = 0x04;
        /// Last byte was LF.
        /// C: `PDKIM_SEEN_LF    BIT(3)` = 0x08.
        const SEEN_LF   = 0x08;
        /// Past the end of headers, now in body.
        /// C: `PDKIM_PAST_HDRS  BIT(4)` = 0x10.
        const PAST_HDRS = 0x10;
        /// End-of-data marker seen (body complete).
        /// C: `PDKIM_SEEN_EOD   BIT(5)` = 0x20.
        const SEEN_EOD  = 0x20;
    }
}

// =============================================================================
// HashContext — Streaming hash wrapper (for body + header hashing)
// =============================================================================

/// Streaming hash context wrapping SHA-1, SHA-256, or SHA-512.
///
/// Provides a unified interface for incremental hash computation used in
/// both body hash (PdkimBodyhash) and header hash (feed_finish) contexts.
/// Replaces the C `exim_sha_init`/`exim_sha_update`/`exim_sha_finish` calls.
pub enum HashContext {
    /// SHA-1 hash context (legacy, for backward compatibility).
    Sha1(sha1::Sha1),
    /// SHA-256 hash context (most common DKIM hash).
    Sha256(sha2::Sha256),
    /// SHA-512 hash context.
    Sha512(sha2::Sha512),
}

impl HashContext {
    /// Create a new hash context for the given hash algorithm index.
    ///
    /// The index corresponds to `PDKIM_HASHES` table positions:
    /// 0 = SHA-1, 1 = SHA-256, 2 = SHA-512.
    pub fn new_from_index(hash_index: i32) -> Option<Self> {
        match hash_index {
            0 => Some(HashContext::Sha1(sha1::Digest::new())),
            1 => Some(HashContext::Sha256(sha2::Digest::new())),
            2 => Some(HashContext::Sha512(sha2::Digest::new())),
            _ => None,
        }
    }

    /// Create a new hash context for the given algorithm.
    pub fn new_from_algo(algo: HashAlgorithm) -> Self {
        match algo {
            HashAlgorithm::Sha1 => HashContext::Sha1(sha1::Digest::new()),
            HashAlgorithm::Sha256 => HashContext::Sha256(sha2::Digest::new()),
            HashAlgorithm::Sha512 => HashContext::Sha512(sha2::Digest::new()),
        }
    }

    /// Feed data into the hash context incrementally.
    pub fn update(&mut self, data: &[u8]) {
        match self {
            HashContext::Sha1(h) => sha1::Digest::update(h, data),
            HashContext::Sha256(h) => sha2::Digest::update(h, data),
            HashContext::Sha512(h) => sha2::Digest::update(h, data),
        }
    }

    /// Consume the hash context and return the final digest bytes.
    pub fn finalize(self) -> Vec<u8> {
        match self {
            HashContext::Sha1(h) => sha1::Digest::finalize(h).to_vec(),
            HashContext::Sha256(h) => sha2::Digest::finalize(h).to_vec(),
            HashContext::Sha512(h) => sha2::Digest::finalize(h).to_vec(),
        }
    }

    /// Finalize the current context and reset it to a fresh state.
    ///
    /// Returns the final digest while leaving the context ready for reuse
    /// with the same algorithm. This is used when the context is owned by
    /// a parent struct (e.g., `PdkimBodyhash`) and cannot be consumed.
    fn finalize_reset(&mut self) -> Vec<u8> {
        let replacement = self.new_like();
        let old = std::mem::replace(self, replacement);
        old.finalize()
    }

    /// Create a new empty hash context of the same algorithm variant.
    fn new_like(&self) -> Self {
        match self {
            HashContext::Sha1(_) => HashContext::Sha1(sha1::Digest::new()),
            HashContext::Sha256(_) => HashContext::Sha256(sha2::Digest::new()),
            HashContext::Sha512(_) => HashContext::Sha512(sha2::Digest::new()),
        }
    }

    /// Returns the hash algorithm index corresponding to `PDKIM_HASHES`.
    pub fn hash_index(&self) -> i32 {
        match self {
            HashContext::Sha1(_) => 0,
            HashContext::Sha256(_) => 1,
            HashContext::Sha512(_) => 2,
        }
    }
}

impl std::fmt::Debug for HashContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashContext::Sha1(_) => write!(f, "HashContext::Sha1"),
            HashContext::Sha256(_) => write!(f, "HashContext::Sha256"),
            HashContext::Sha512(_) => write!(f, "HashContext::Sha512"),
        }
    }
}

// =============================================================================
// Core data structures (from pdkim.h lines 119-305)
// =============================================================================

/// Parsed DKIM public key record from DNS TXT.
///
/// Represents the parsed content of a DNS TXT record at
/// `{selector}._domainkey.{domain}`. Matches C `pdkim_pubkey` struct
/// from pdkim.h lines 119-131.
#[derive(Debug, Clone)]
pub struct PdkimPubkey {
    /// `v=` tag: key record version (default "DKIM1").
    pub version: Option<String>,
    /// `g=` tag: granularity (default "*").
    pub granularity: Option<String>,
    /// `h=` tag: acceptable hash algorithms (colon-separated).
    pub hashes: Option<String>,
    /// `k=` tag: key type name (default "rsa").
    pub keytype: Option<String>,
    /// `s=` tag: service type (default "*").
    pub srvtype: Option<String>,
    /// `n=` tag: notes (human-readable, QP-decoded).
    pub notes: Option<String>,
    /// `p=` tag: base64-decoded public key data.
    pub key: Vec<u8>,
    /// `t=y` flag: domain is testing DKIM.
    pub testing: bool,
    /// `t=s` flag: no subdomaining allowed.
    pub no_subdomaining: bool,
}

// =============================================================================
// Display implementations (from pdkim.c lines 165-213)
// =============================================================================

impl std::fmt::Display for PdkimResult {
    /// Matches C `pdkim_errstr()` from pdkim.c lines 197-213.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            PdkimResult::Ok => "OK",
            PdkimResult::Fail => "FAIL",
            PdkimResult::ErrRsaPrivkey => "ERR_RSA_PRIVKEY",
            PdkimResult::ErrRsaSigning => "ERR_RSA_SIGNING",
            PdkimResult::ErrLongLine => "ERR_LONG_LINE",
            PdkimResult::ErrBufferTooSmall => "ERR_BUFFER_TOO_SMALL",
            PdkimResult::ErrExcessSigs => "ERR_EXCESS_SIGS",
            PdkimResult::SignPrivkeyWrap => "SIGN_PRIVKEY_WRAP",
            PdkimResult::SignPrivkeyB64d => "SIGN_PRIVKEY_B64D",
        };
        write!(f, "{s}")
    }
}

impl std::fmt::Display for VerifyStatus {
    /// Matches C `pdkim_verify_status_str()` from pdkim.c lines 165-176.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            VerifyStatus::None => "none",
            VerifyStatus::Invalid => "invalid",
            VerifyStatus::Fail => "fail",
            VerifyStatus::Pass => "pass",
        };
        write!(f, "{s}")
    }
}

impl std::fmt::Display for VerifyExtStatus {
    /// Matches C `pdkim_verify_ext_status_str()` from pdkim.c lines 178-195.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            VerifyExtStatus::None => "",
            VerifyExtStatus::FailBody => "body hash did not verify",
            VerifyExtStatus::FailMessage => "message signature did not verify",
            VerifyExtStatus::FailSigAlgoMismatch => "public key algorithm mismatch",
            VerifyExtStatus::InvalidPubkeyUnavailable => "public key unavailable",
            VerifyExtStatus::InvalidBufferSize => "buffer too small",
            VerifyExtStatus::InvalidPubkeyDnsrecord => "public key DNS record invalid",
            VerifyExtStatus::InvalidPubkeyImport => "public key import failed",
            VerifyExtStatus::InvalidPubkeyKeysize => "public key too short",
            VerifyExtStatus::InvalidSignatureError => "signature error",
            VerifyExtStatus::InvalidDkimVersion => "unsupported DKIM version",
        };
        write!(f, "{s}")
    }
}

impl std::fmt::Display for Canon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Canon::Simple => write!(f, "simple"),
            Canon::Relaxed => write!(f, "relaxed"),
        }
    }
}

// =============================================================================
// PdkimBodyhash (from pdkim.h lines 135-146)
// =============================================================================

/// Body hash computation state for a specific hash/canon/length combination.
///
/// Multiple signatures can share a body hash context if they use the same
/// hash algorithm, canonicalization method, and body length limit.
/// Matches C `pdkim_bodyhash` struct from pdkim.h lines 135-146.
#[derive(Debug)]
pub struct PdkimBodyhash {
    /// Hash algorithm index into `PDKIM_HASHES`.
    pub hashtype: i32,
    /// Body canonicalization method.
    pub canon_method: Canon,
    /// Maximum body length to hash (-1 = unlimited).
    pub bodylength: i64,
    /// Streaming hash context for incremental body hash computation.
    pub body_hash_ctx: HashContext,
    /// Number of body bytes actually signed (may differ from bodylength).
    pub signed_body_bytes: u64,
    /// Number of buffered trailing blank lines (not yet fed to hash).
    pub num_buffered_blanklines: i32,
    /// Completed body hash bytes (populated after finalization).
    pub bh: Vec<u8>,
}

// =============================================================================
// PdkimSignature (from pdkim.h lines 150-275)
// =============================================================================

/// A parsed or constructed DKIM signature.
///
/// In verification mode, this is populated by parsing a `DKIM-Signature:`
/// header. In signing mode, this is constructed by the caller and populated
/// with computed values during `feed_finish()`.
///
/// Matches C `pdkim_signature` struct from pdkim.h lines 150-275.
#[derive(Debug)]
pub struct PdkimSignature {
    /// DKIM signature version (from `v=` tag, must be 1).
    pub version: i32,
    /// Key type index into `PDKIM_KEYTYPES` (0=rsa, 1=ed25519).
    pub keytype: i32,
    /// Key size in bits (populated after DNS key retrieval).
    pub keybits: u32,
    /// Hash algorithm index into `PDKIM_HASHES` (0=sha1, 1=sha256, 2=sha512).
    pub hashtype: i32,
    /// Header canonicalization method.
    pub canon_headers: Canon,
    /// Body canonicalization method.
    pub canon_body: Canon,
    /// Query method index into `PDKIM_QUERYMETHODS` (0=dns/txt).
    pub querymethod: i32,
    /// `s=` tag: selector name.
    pub selector: Option<String>,
    /// `d=` tag: signing domain.
    pub domain: Option<String>,
    /// `i=` tag: signing identity (agent or user identifier).
    pub identity: Option<String>,
    /// `t=` tag: signature creation timestamp (seconds since epoch).
    pub created: u64,
    /// `x=` tag: signature expiration timestamp (0 = no expiry).
    pub expires: u64,
    /// `l=` tag: body length limit (-1 = unlimited, default).
    pub bodylength: i64,
    /// `h=` tag: colon-separated list of signed header names.
    pub headernames: Option<String>,
    /// `z=` tag: copied headers for diagnostic use (QP-encoded in wire format).
    pub copiedheaders: Option<String>,
    /// `b=` tag: base64-decoded signature hash bytes.
    pub sighash: Vec<u8>,
    /// `bh=` tag: base64-decoded body hash bytes.
    pub bodyhash: Vec<u8>,
    /// Generated DKIM-Signature header (signing mode only).
    pub signature_header: Option<String>,
    /// Verification result status.
    pub verify_status: VerifyStatus,
    /// Extended verification status (reason for failure/invalidity).
    pub verify_ext_status: VerifyExtStatus,
    /// Parsed public key from DNS (verification mode).
    pub pubkey: Option<PdkimPubkey>,
    /// Index into `PdkimContext.bodyhash` for the matching body hash.
    pub calc_body_hash: Option<usize>,
    /// Raw headers collected for this signature's hash computation.
    pub headers: Vec<String>,
    /// PEM-encoded private key (signing mode only).
    pub privkey: Option<String>,
    /// Colon-separated list of headers to sign (signing mode).
    pub sign_headers: Option<String>,
    /// Original DKIM-Signature header with `b=` value stripped.
    /// Critical for verification: this is what gets hashed as the
    /// final header in the header hash computation.
    pub rawsig_no_b_val: Option<String>,
}

impl Default for PdkimSignature {
    /// Create a signature with default values matching C initialization.
    fn default() -> Self {
        Self {
            version: 0,
            keytype: -1,
            keybits: 0,
            hashtype: -1,
            canon_headers: Canon::Simple,
            canon_body: Canon::Simple,
            querymethod: 0,
            selector: None,
            domain: None,
            identity: None,
            created: 0,
            expires: 0,
            bodylength: -1,
            headernames: None,
            copiedheaders: None,
            sighash: Vec::new(),
            bodyhash: Vec::new(),
            signature_header: None,
            verify_status: VerifyStatus::None,
            verify_ext_status: VerifyExtStatus::None,
            pubkey: None,
            calc_body_hash: None,
            headers: Vec::new(),
            privkey: None,
            sign_headers: None,
            rawsig_no_b_val: None,
        }
    }
}

// =============================================================================
// PdkimContext (from pdkim.h lines 280-305)
// =============================================================================

/// Main PDKIM processing context holding all state for a signing or
/// verification session.
///
/// Replaces C `pdkim_ctx` struct from pdkim.h lines 280-305. All C global
/// state and linked list pointers are replaced with owned Vec collections
/// and explicit fields.
pub struct PdkimContext {
    /// Mode and state flags.
    pub flags: PdkimFlags,
    /// Signatures being processed (linked list in C → Vec in Rust).
    pub sig: Vec<PdkimSignature>,
    /// Body hash contexts (linked list in C → Vec in Rust).
    pub bodyhash: Vec<PdkimBodyhash>,
    /// DNS TXT record lookup callback for public key retrieval.
    /// Returns the DNS TXT record content as a string, or None on failure.
    pub dns_txt_callback: Option<DnsTxtCallback>,
    /// Current header being accumulated (working buffer).
    pub cur_header: String,
    /// Body line buffer for accumulating bytes until a complete line.
    pub linebuf: Vec<u8>,
    /// Current write offset into `linebuf`.
    pub linebuf_offset: usize,
    /// Number of headers processed so far.
    pub num_headers: usize,
    /// All raw headers collected (for verification mode header matching).
    pub headers: Vec<String>,

    // ── Internal state not in C struct but needed for Rust impl ──
    /// Counter for number of DKIM signatures seen (for excess check).
    /// Replaces C static `n_dkim_sigs` from pdkim.c.
    n_sigs: usize,
    /// Maximum number of signatures to accept (0 = unlimited).
    /// Corresponds to C extern `dkim_collect_input`.
    max_sigs: usize,
    /// Optional ARC header feed callback (behind arc feature).
    /// Called with (header_text, is_verify_mode) for each complete header.
    arc_header_callback: Option<ArcHeaderCallback>,
    /// Optional per-message arena for scoped allocations (replaces C
    /// `store_get(sizeof(...), GET_UNTAINTED)` pattern from pdkim.c).
    /// Allocated strings and structs are released when the arena is dropped
    /// at the end of the message transaction.
    pub arena: Option<MessageArena>,
}

impl std::fmt::Debug for PdkimContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PdkimContext")
            .field("flags", &self.flags)
            .field("sig_count", &self.sig.len())
            .field("bodyhash_count", &self.bodyhash.len())
            .field("cur_header_len", &self.cur_header.len())
            .field("linebuf_offset", &self.linebuf_offset)
            .field("num_headers", &self.num_headers)
            .field("headers_count", &self.headers.len())
            .field("n_sigs", &self.n_sigs)
            .field("max_sigs", &self.max_sigs)
            .finish()
    }
}

impl PdkimContext {
    /// Create a new empty context with default values.
    fn new() -> Self {
        Self {
            flags: PdkimFlags::empty(),
            sig: Vec::new(),
            bodyhash: Vec::new(),
            dns_txt_callback: None,
            cur_header: String::new(),
            linebuf: vec![0u8; PDKIM_MAX_BODY_LINE_LEN],
            linebuf_offset: 0,
            num_headers: 0,
            headers: Vec::new(),
            n_sigs: 0,
            max_sigs: 0,
            arc_header_callback: None,
            arena: None,
        }
    }

    /// Set the ARC header callback for header feed integration.
    pub fn set_arc_callback(&mut self, cb: ArcHeaderCallback) {
        self.arc_header_callback = Some(cb);
    }

    /// Set the maximum number of DKIM signatures to accept.
    pub fn set_max_sigs(&mut self, max: usize) {
        self.max_sigs = max;
    }
}

// =============================================================================
// Conversion / Lookup helper functions (from pdkim.c lines 119-161)
// =============================================================================

/// Format the `a=` tag value from a signature's keytype and hashtype indices.
///
/// Produces strings like "rsa-sha256", "ed25519-sha512", etc.
/// Returns "err" if either index is out of range.
///
/// Matches C `pdkim_sig_to_a_tag()` from pdkim.c lines 119-127.
pub fn sig_to_a_tag(sig: &PdkimSignature) -> String {
    let kt = sig.keytype;
    let ht = sig.hashtype;
    if kt < 0
        || ht < 0
        || (kt as usize) >= PDKIM_KEYTYPES.len()
        || (ht as usize) >= PDKIM_HASHES.len()
    {
        return "err".to_string();
    }
    format!(
        "{}-{}",
        PDKIM_KEYTYPES[kt as usize], PDKIM_HASHES[ht as usize].dkim_hashname
    )
}

/// Look up a key type name in the PDKIM_KEYTYPES table.
///
/// Returns the index if found, None otherwise.
/// Matches C `pdkim_keyname_to_keytype()` from pdkim.c lines 130-136.
fn keyname_to_keytype(s: &str) -> Option<usize> {
    PDKIM_KEYTYPES.iter().position(|&k| k == s)
}

/// Look up a hash algorithm name in the PDKIM_HASHES table.
///
/// Returns the index if found, None otherwise.
/// Matches C `pdkim_hashname_to_hashtype()` from pdkim.c lines 138-146.
pub fn hashname_to_hashtype(s: &str) -> Option<usize> {
    PDKIM_HASHES.iter().position(|h| h.dkim_hashname == s)
}

/// Parse a canonicalization specification string into header and body Canon values.
///
/// Accepts formats like "relaxed/relaxed", "simple/relaxed", "relaxed", "simple".
/// Falls back to (Simple, Simple) if the string is not recognized.
///
/// Matches C `pdkim_cstring_to_canons()` from pdkim.c lines 148-161.
pub fn cstring_to_canons(s: &str) -> (Canon, Canon) {
    for cc in PDKIM_COMBINED_CANONS {
        if cc.str_repr == s {
            return (cc.canon_headers, cc.canon_body);
        }
    }
    (Canon::Simple, Canon::Simple)
}

// =============================================================================
// String manipulation helpers (from pdkim.c lines 219-431)
// =============================================================================

/// Trim leading and trailing whitespace (space and tab only) from a string.
///
/// Matches C `pdkim_strtrim()` from pdkim.c lines 234-249.
fn strtrim(s: &mut String) {
    let trimmed = s
        .trim_start_matches([' ', '\t'])
        .trim_end_matches([' ', '\t'])
        .to_string();
    *s = trimmed;
}

/// Check if a header name matches an entry in a colon-separated header name list.
///
/// If `tick` is true and a match is found, the matched entry in the list is
/// invalidated (replaced with underscores) so it cannot match again —
/// this implements the "each header signs only once" rule from RFC 6376 §5.4.2.
///
/// The comparison is case-insensitive on the header name (before the colon).
///
/// Matches C `header_name_match()` from pdkim.c lines 254-303.
fn header_name_match(header: &str, tick_list: &mut String, tick: bool) -> bool {
    // Extract the header name (everything before the first colon)
    let hdr_name = match header.find(':') {
        Some(pos) => &header[..pos],
        None => header,
    };
    let hdr_name_lower = hdr_name.to_ascii_lowercase();

    // Parse tick_list as a colon-separated list and search for matches
    let entries: Vec<&str> = tick_list.split(':').collect();
    let mut found_index: Option<usize> = None;

    for (i, entry) in entries.iter().enumerate() {
        // Skip entries that have been ticked (start with underscore sequences)
        let entry_trimmed = entry.trim();
        if entry_trimmed.is_empty() {
            continue;
        }

        // Check if entry has been invalidated (all underscores or starts with _)
        let first_char = entry_trimmed.chars().next().unwrap_or('_');
        if first_char == '_' {
            continue;
        }

        if entry_trimmed.eq_ignore_ascii_case(&hdr_name_lower) {
            found_index = Some(i);
            break;
        }
    }

    if let Some(idx) = found_index {
        if tick {
            // Replace the matched entry with underscores to invalidate it.
            // Rebuild the tick_list safely without unsafe code.
            let parts: Vec<&str> = tick_list.split(':').collect();
            let mut new_list = String::with_capacity(tick_list.len());
            for (i, part) in parts.iter().enumerate() {
                if i > 0 {
                    new_list.push(':');
                }
                if i == idx {
                    // Replace with underscores of the same length
                    for _ in 0..part.len() {
                        new_list.push('_');
                    }
                } else {
                    new_list.push_str(part);
                }
            }
            *tick_list = new_list;
        }
        true
    } else {
        false
    }
}

/// Perform "relaxed" header canonicalization per RFC 6376 §3.4.2.
///
/// Applies the following transformations:
/// - Ignores CR and LF characters
/// - Collapses sequences of WSP (space/tab) into a single space
/// - Removes WSP immediately before the colon separating name from value
/// - Removes WSP immediately after the colon
/// - Lowercases the header name (everything before the colon)
/// - Removes trailing whitespace
/// - Optionally appends CRLF
///
/// Matches C `pdkim_relax_header_n()` from pdkim.c lines 308-349.
pub fn relax_header_n(header: &str, len: usize, append_crlf: bool) -> String {
    let input = if len < header.len() {
        &header[..len]
    } else {
        header
    };

    let mut result = String::with_capacity(input.len());
    let mut past_colon = false;
    let mut in_wsp = false;
    let mut after_colon = false;

    for ch in input.chars() {
        // Skip CR and LF
        if ch == '\r' || ch == '\n' {
            continue;
        }

        if !past_colon {
            // In header name: lowercase, strip trailing WSP before colon
            if ch == ':' {
                // Remove any trailing WSP we accumulated before the colon
                while result.ends_with(' ') || result.ends_with('\t') {
                    result.pop();
                }
                result.push(':');
                past_colon = true;
                after_colon = true;
                in_wsp = false;
                continue;
            }
            // Accumulate header name character, lowercased
            if ch == ' ' || ch == '\t' {
                // Track WSP in header name but don't emit yet - might be before colon
                in_wsp = true;
            } else {
                if in_wsp {
                    result.push(' ');
                    in_wsp = false;
                }
                result.push(ch.to_ascii_lowercase());
            }
        } else {
            // In header value
            if ch == ' ' || ch == '\t' {
                if after_colon {
                    // Skip WSP immediately after colon
                    continue;
                }
                in_wsp = true;
            } else {
                after_colon = false;
                if in_wsp {
                    result.push(' ');
                    in_wsp = false;
                }
                result.push(ch);
            }
        }
    }

    // Remove trailing whitespace from the result
    while result.ends_with(' ') || result.ends_with('\t') {
        result.pop();
    }

    if append_crlf {
        result.push_str("\r\n");
    }

    result
}

/// Convenience wrapper for `relax_header_n()` using the full string length.
///
/// Matches C `pdkim_relax_header()` from pdkim.c lines 352-356.
pub fn relax_header(header: &str, append_crlf: bool) -> String {
    relax_header_n(header, header.len(), append_crlf)
}

/// Decode a single quoted-printable encoded character.
///
/// Returns (decoded_byte_value, bytes_consumed). Returns (-1, 0) on failure.
/// Matches C `pdkim_decode_qp_char()` from pdkim.c lines 362-382.
fn decode_qp_char(data: &[u8], pos: usize) -> (i32, usize) {
    if pos + 2 > data.len() {
        return (-1, 0);
    }
    let hi = data[pos];
    let lo = data[pos + 1];

    let hi_val = match hi {
        b'0'..=b'9' => (hi - b'0') as i32,
        b'A'..=b'F' => (hi - b'A' + 10) as i32,
        b'a'..=b'f' => (hi - b'a' + 10) as i32,
        _ => return (-1, 0),
    };
    let lo_val = match lo {
        b'0'..=b'9' => (lo - b'0') as i32,
        b'A'..=b'F' => (lo - b'A' + 10) as i32,
        b'a'..=b'f' => (lo - b'a' + 10) as i32,
        _ => return (-1, 0),
    };

    ((hi_val << 4) | lo_val, 2)
}

/// Decode a full quoted-printable encoded string.
///
/// Matches C `pdkim_decode_qp()` from pdkim.c lines 387-414.
fn decode_qp(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'=' && i + 2 < bytes.len() {
            let (val, consumed) = decode_qp_char(bytes, i + 1);
            if val >= 0 {
                result.push(val as u8);
                i += 1 + consumed;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }

    String::from_utf8_lossy(&result).into_owned()
}

/// Base64 decode wrapper.
///
/// Returns empty Vec on decode failure.
/// Matches C `pdkim_decode_base64()` from pdkim.c lines 420-425.
pub fn decode_base64(s: &str) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.decode(s).unwrap_or_default()
}

/// Base64 encode wrapper.
///
/// Matches C `pdkim_encode_base64()` from pdkim.c lines 427-431.
pub fn encode_base64(data: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.encode(data)
}

// =============================================================================
// DKIM-Signature header parser (from pdkim.c lines 435-624)
// =============================================================================

/// Parse state for DKIM-Signature header tag-value processing.
/// Matches C defines at pdkim.c lines 435-437.
const PDKIM_HDR_LIMBO: u8 = 0;
const PDKIM_HDR_TAG: u8 = 1;
const PDKIM_HDR_VALUE: u8 = 2;

/// Parse a DKIM-Signature header into a PdkimSignature struct.
///
/// This is the critical parsing function that extracts all tag-value pairs
/// from a DKIM-Signature header. It uses a state machine with three states:
/// LIMBO (between tags), TAG (reading tag name), VALUE (reading tag value).
///
/// The `rawsig_no_b_val` field is populated with the original header text
/// but with the `b=` tag's value stripped — this is essential for
/// verification (it's the header that gets hashed as the final entry in
/// the header hash computation).
///
/// Matches C `pdkim_parse_sig_header()` from pdkim.c lines 435-624.
fn parse_sig_header(ctx: &mut PdkimContext, raw_hdr: &str) -> Option<PdkimSignature> {
    let mut sig = PdkimSignature::default();
    let mut cur_tag = String::new();
    let mut cur_val = String::new();
    let mut state = PDKIM_HDR_LIMBO;

    // Build rawsig_no_b_val: copy everything except the b= tag value.
    // We track whether we are inside the b= value to skip it.
    let mut rawsig = String::with_capacity(raw_hdr.len());
    let mut in_b_val = false;
    // Skip past "DKIM-Signature:" prefix if present (case-insensitive)
    let hdr = if let Some(pos) = raw_hdr.find(':') {
        let name = &raw_hdr[..pos];
        if name.eq_ignore_ascii_case("dkim-signature")
            || name.eq_ignore_ascii_case("DKIM-Signature")
        {
            &raw_hdr[pos + 1..]
        } else {
            raw_hdr
        }
    } else {
        raw_hdr
    };

    // Reconstruct rawsig_no_b_val from the full header
    // Start with "DKIM-Signature:" prefix for the raw sig
    if let Some(pos) = raw_hdr.find(':') {
        rawsig.push_str(&raw_hdr[..=pos]);
    }

    for ch in hdr.chars() {
        // Track state transitions for rawsig_no_b_val construction
        match state {
            PDKIM_HDR_LIMBO => {
                // Between tags — skip whitespace and semicolons
                if ch == ';' || ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' {
                    if !in_b_val {
                        rawsig.push(ch);
                    }
                    continue;
                }
                state = PDKIM_HDR_TAG;
                cur_tag.clear();
                cur_tag.push(ch);
                if !in_b_val {
                    rawsig.push(ch);
                }
            }
            PDKIM_HDR_TAG => {
                if ch == '=' {
                    strtrim(&mut cur_tag);
                    cur_val.clear();
                    // Check if this is the b= tag (not bh=)
                    in_b_val = cur_tag == "b";
                    state = PDKIM_HDR_VALUE;
                    rawsig.push('=');
                } else {
                    cur_tag.push(ch);
                    if !in_b_val {
                        rawsig.push(ch);
                    }
                }
            }
            PDKIM_HDR_VALUE => {
                if ch == ';' || ch == '\0' {
                    // End of tag value — process it
                    strtrim(&mut cur_val);

                    process_sig_tag(&mut sig, &cur_tag, &cur_val);

                    if in_b_val {
                        // For b= tag, write the semicolon but not the value
                        in_b_val = false;
                    }
                    rawsig.push(';');

                    state = PDKIM_HDR_LIMBO;
                    cur_tag.clear();
                    cur_val.clear();
                } else {
                    cur_val.push(ch);
                    if !in_b_val {
                        rawsig.push(ch);
                    }
                }
            }
            _ => {}
        }
    }

    // Process last tag if we ended in VALUE state
    if state == PDKIM_HDR_VALUE {
        strtrim(&mut cur_val);
        let was_b = in_b_val;
        process_sig_tag(&mut sig, &cur_tag, &cur_val);
        if !was_b {
            // Append remaining value to rawsig
        }
    }

    sig.rawsig_no_b_val = Some(rawsig);

    // Validation: key type and hash type must be resolved
    if sig.keytype < 0 || sig.hashtype < 0 {
        debug!(
            keytype = sig.keytype,
            hashtype = sig.hashtype,
            "PDKIM: signature header missing required algorithm fields"
        );
        return None;
    }

    // Link signature to a body hash context
    let sig_idx = ctx.sig.len();
    ctx.sig.push(sig);
    set_sig_bodyhash(ctx, sig_idx);
    let sig = ctx.sig.pop().unwrap();

    debug!(
        domain = ?sig.domain,
        selector = ?sig.selector,
        algo = %sig_to_a_tag(&sig),
        "PDKIM: parsed DKIM-Signature header"
    );

    Some(sig)
}

/// Process a single DKIM-Signature tag-value pair.
///
/// Handles all tag types defined by RFC 6376 §3.5:
/// b, bh, v, a, c, q, s, d, i, t, x, l, h, z.
fn process_sig_tag(sig: &mut PdkimSignature, tag: &str, val: &str) {
    match tag {
        "b" => {
            sig.sighash = decode_base64(val);
            trace!(len = sig.sighash.len(), "PDKIM: parsed b= tag");
        }
        "bh" => {
            sig.bodyhash = decode_base64(val);
            trace!(len = sig.bodyhash.len(), "PDKIM: parsed bh= tag");
        }
        "v" => {
            // Version must be "1" per RFC 6376
            if val == PDKIM_SIGNATURE_VERSION {
                sig.version = 1;
            } else {
                debug!(version = val, "PDKIM: unexpected signature version");
                sig.version = 0;
            }
        }
        "a" => {
            // Algorithm: "rsa-sha256", "ed25519-sha256", etc.
            // Split on '-' to get keytype and hashtype
            if let Some(dash_pos) = val.find('-') {
                let keyname = &val[..dash_pos];
                let hashname = &val[dash_pos + 1..];
                if let Some(kt) = keyname_to_keytype(keyname) {
                    sig.keytype = kt as i32;
                }
                if let Some(ht) = hashname_to_hashtype(hashname) {
                    sig.hashtype = ht as i32;
                }
            }
        }
        "c" => {
            let (ch, cb) = cstring_to_canons(val);
            sig.canon_headers = ch;
            sig.canon_body = cb;
        }
        "q" => {
            // Query method (only "dns/txt" is defined)
            for (i, &qm) in PDKIM_QUERYMETHODS.iter().enumerate() {
                if qm == val {
                    sig.querymethod = i as i32;
                    break;
                }
            }
        }
        "s" => {
            sig.selector = Some(val.to_string());
        }
        "d" => {
            sig.domain = Some(val.to_string());
        }
        "i" => {
            sig.identity = Some(decode_qp(val));
        }
        "t" => {
            sig.created = val.parse::<u64>().unwrap_or(0);
        }
        "x" => {
            sig.expires = val.parse::<u64>().unwrap_or(0);
        }
        "l" => {
            sig.bodylength = val.parse::<i64>().unwrap_or(-1);
        }
        "h" => {
            sig.headernames = Some(val.to_string());
        }
        "z" => {
            sig.copiedheaders = Some(decode_qp(val));
        }
        _ => {
            trace!(tag = tag, "PDKIM: ignoring unknown signature tag");
        }
    }
}

// =============================================================================
// Public key record parser (from pdkim.c lines 629-703)
// =============================================================================

/// Parse a DNS TXT record containing a DKIM public key.
///
/// Extracts tag-value pairs from the record and populates a `PdkimPubkey`
/// struct. The record format is defined by RFC 6376 §3.6.1.
///
/// Returns `None` if:
/// - The record has no `p=` (public key) tag, or
/// - The version tag doesn't match "DKIM1".
///
/// Matches C `pdkim_parse_pubkey_record()` from pdkim.c lines 629-703.
pub fn parse_pubkey_record(raw_record: &str) -> Option<PdkimPubkey> {
    let mut pubkey = PdkimPubkey {
        version: None,
        granularity: None,
        hashes: None,
        keytype: None,
        srvtype: None,
        notes: None,
        key: Vec::new(),
        testing: false,
        no_subdomaining: false,
    };

    let mut has_key = false;

    // Parse semicolon-delimited tag=value pairs
    for pair in raw_record.split(';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }

        let eq_pos = match pair.find('=') {
            Some(p) => p,
            None => continue,
        };

        let tag = pair[..eq_pos].trim();
        let val = pair[eq_pos + 1..].trim();

        match tag {
            "v" => {
                pubkey.version = Some(val.to_string());
            }
            "h" => {
                pubkey.hashes = Some(val.to_string());
            }
            "k" => {
                pubkey.keytype = Some(val.to_string());
            }
            "g" => {
                pubkey.granularity = Some(val.to_string());
            }
            "n" => {
                pubkey.notes = Some(decode_qp(val));
            }
            "p" => {
                pubkey.key = decode_base64(val);
                has_key = true;
            }
            "s" => {
                pubkey.srvtype = Some(val.to_string());
            }
            "t" => {
                // Flags: "y" = testing, "s" = no subdomaining
                for flag in val.split(':') {
                    let flag = flag.trim();
                    match flag {
                        "y" => pubkey.testing = true,
                        "s" => pubkey.no_subdomaining = true,
                        _ => {}
                    }
                }
            }
            _ => {
                trace!(tag = tag, "PDKIM: ignoring unknown pubkey tag");
            }
        }
    }

    // Must have a public key
    if !has_key {
        debug!("PDKIM: DNS pubkey record missing p= tag");
        return None;
    }

    // Apply defaults for missing tags
    if pubkey.version.is_none() {
        pubkey.version = Some(PDKIM_PUB_RECORD_VERSION.to_string());
    }
    if pubkey.granularity.is_none() {
        pubkey.granularity = Some("*".to_string());
    }
    if pubkey.keytype.is_none() {
        pubkey.keytype = Some("rsa".to_string());
    }
    if pubkey.srvtype.is_none() {
        pubkey.srvtype = Some("*".to_string());
    }

    // Version must match "DKIM1"
    if let Some(ref v) = pubkey.version {
        if v != PDKIM_PUB_RECORD_VERSION {
            debug!(version = %v, "PDKIM: DNS pubkey record version mismatch");
            return None;
        }
    }

    debug!(
        keytype = ?pubkey.keytype,
        key_len = pubkey.key.len(),
        testing = pubkey.testing,
        "PDKIM: parsed DNS pubkey record"
    );

    Some(pubkey)
}

// =============================================================================
// Body hash management (from pdkim.c lines 706-937)
// =============================================================================

/// Update a body hash context with data, applying canonicalization.
///
/// For relaxed canonicalization:
/// - Collapse contiguous WSP into single SP
/// - Remove trailing WSP before CRLF
///
/// For both methods, enforce bodylength limit.
///
/// Matches C `pdkim_update_ctx_bodyhash()` from pdkim.c lines 711-775.
fn update_ctx_bodyhash(b: &mut PdkimBodyhash, data: &[u8], is_relaxed: bool) {
    if data.is_empty() {
        return;
    }

    let canon_data: Vec<u8>;
    let feed_data = if is_relaxed {
        // Relaxed body canonicalization: collapse WSP, remove trailing WSP
        let mut relaxed = Vec::with_capacity(data.len());
        let mut seen_wsp = false;
        for &byte in data {
            if byte == b' ' || byte == b'\t' {
                seen_wsp = true;
                continue;
            }
            if byte == b'\r' || byte == b'\n' {
                // Discard trailing WSP before line ending
                seen_wsp = false;
                relaxed.push(byte);
                continue;
            }
            if seen_wsp {
                relaxed.push(b' ');
                seen_wsp = false;
            }
            relaxed.push(byte);
        }
        canon_data = relaxed;
        &canon_data
    } else {
        data
    };

    // Enforce bodylength limit
    let bytes_to_feed = if b.bodylength >= 0 {
        let remaining = (b.bodylength as u64).saturating_sub(b.signed_body_bytes);
        if remaining == 0 {
            return;
        }
        let limit = remaining as usize;
        if feed_data.len() > limit {
            &feed_data[..limit]
        } else {
            feed_data
        }
    } else {
        feed_data
    };

    if !bytes_to_feed.is_empty() {
        b.body_hash_ctx.update(bytes_to_feed);
        b.signed_body_bytes += bytes_to_feed.len() as u64;
        trace!(
            bytes = bytes_to_feed.len(),
            total = b.signed_body_bytes,
            "PDKIM: body hash update"
        );
    }
}

/// Finalize all body hashes and compare with signature bodyhash values.
///
/// For signing mode: adjusts bodylength if less data was received.
/// For verification mode: compares computed body hash with the sig's `bh=` tag.
///
/// Matches C `pdkim_finish_bodyhash()` from pdkim.c lines 780-835.
fn finish_bodyhash(ctx: &mut PdkimContext) {
    for bh in &mut ctx.bodyhash {
        // Finalize the hash context
        let computed_hash = bh.body_hash_ctx.finalize_reset();
        bh.bh = computed_hash;

        debug!(
            hashtype = bh.hashtype,
            canon = %bh.canon_method,
            hash_hex = hex_encode(&bh.bh),
            signed_bytes = bh.signed_body_bytes,
            "PDKIM: body hash finalized"
        );
    }

    let is_signing = ctx.flags.contains(PdkimFlags::MODE_SIGN);

    for sig in &mut ctx.sig {
        if let Some(bh_idx) = sig.calc_body_hash {
            if bh_idx < ctx.bodyhash.len() {
                let bh = &ctx.bodyhash[bh_idx];

                if is_signing {
                    // Signing: update bodylength if we received less data
                    if sig.bodylength >= 0 && (bh.signed_body_bytes as i64) < sig.bodylength {
                        sig.bodylength = bh.signed_body_bytes as i64;
                    }
                    // Copy computed hash to signature's bodyhash field
                    sig.bodyhash = bh.bh.clone();
                } else {
                    // Verification: compare computed hash with sig's bh= tag
                    if sig.bodyhash != bh.bh {
                        debug!(
                            expected = hex_encode(&sig.bodyhash),
                            computed = hex_encode(&bh.bh),
                            "PDKIM: body hash mismatch"
                        );
                        sig.verify_status = VerifyStatus::Fail;
                        sig.verify_ext_status = VerifyExtStatus::FailBody;
                    }
                }
            }
        }
    }
}

/// Handle end-of-body: emit trailing CRLF for simple canonicalization.
///
/// Per RFC 6376 §3.4.3: if there is no body or the body is empty,
/// a CRLF is added for simple canonicalization. For relaxed canon,
/// an empty body is hashed as empty (no trailing CRLF).
///
/// Matches C `pdkim_body_complete()` from pdkim.c lines 839-857.
fn body_complete(ctx: &mut PdkimContext) {
    for bh in &mut ctx.bodyhash {
        // Per RFC 6376 §3.4.3/§3.4.4: for simple canonicalization, if no
        // body content was received, we still hash one CRLF.
        if bh.canon_method == Canon::Simple && bh.signed_body_bytes == 0 {
            bh.body_hash_ctx.update(b"\r\n");
            bh.signed_body_bytes = 2;
            trace!("PDKIM: added trailing CRLF for empty body (simple canon)");
        }

        // Flush any remaining buffered blank lines for simple canon
        if bh.canon_method == Canon::Simple {
            for _ in 0..bh.num_buffered_blanklines {
                bh.body_hash_ctx.update(b"\r\n");
                bh.signed_body_bytes += 2;
            }
            bh.num_buffered_blanklines = 0;
        }
    }

    ctx.flags.insert(PdkimFlags::SEEN_EOD);
    ctx.linebuf_offset = 0;
}

/// Process a complete body line.
///
/// Handles:
/// - Dot-termination detection (`.CRLF` in SMTP DATA mode)
/// - Dot-unstuffing (leading `.` removed)
/// - Blank line buffering (deferred to avoid trailing blank lines in hash)
/// - Whitespace-only line buffering (for relaxed canonicalization)
///
/// Matches C `pdkim_bodyline_complete()` from pdkim.c lines 865-937.
fn bodyline_complete(ctx: &mut PdkimContext) {
    let line_len = ctx.linebuf_offset;

    // Check for end-of-data marker (dot-termination)
    if ctx.flags.contains(PdkimFlags::DOT_TERM) {
        let linebuf = &ctx.linebuf[..line_len];
        if (line_len == 3 && linebuf[0] == b'.' && linebuf[1] == b'\r' && linebuf[2] == b'\n')
            || (line_len == 2 && linebuf[0] == b'.' && linebuf[1] == b'\n')
        {
            body_complete(ctx);
            return;
        }
    }

    // Get the line data, handling dot-unstuffing
    let (line_start, effective_len) = {
        let linebuf = &ctx.linebuf[..line_len];
        if ctx.flags.contains(PdkimFlags::DOT_TERM) && line_len > 0 && linebuf[0] == b'.' {
            (1, line_len - 1) // Skip leading dot
        } else {
            (0, line_len)
        }
    };

    // Check if the line is "blank" (CRLF only)
    let is_blank = {
        let line = &ctx.linebuf[line_start..line_start + effective_len];
        effective_len == 2 && line[0] == b'\r' && line[1] == b'\n'
    };

    // For relaxed canon, also check if line is whitespace-only
    let is_wsp_only = if !is_blank {
        let line = &ctx.linebuf[line_start..line_start + effective_len];
        line.iter()
            .all(|&b| b == b' ' || b == b'\t' || b == b'\r' || b == b'\n')
    } else {
        true
    };

    for bh in &mut ctx.bodyhash {
        if is_blank || (bh.canon_method == Canon::Relaxed && is_wsp_only) {
            // Buffer blank/whitespace-only lines — RFC 6376 §3.4.3/§3.4.4
            // says trailing blank lines are not signed.
            bh.num_buffered_blanklines += 1;
            continue;
        }

        // Non-blank line: flush buffered blank lines first
        let is_relaxed = bh.canon_method == Canon::Relaxed;
        for _ in 0..bh.num_buffered_blanklines {
            update_ctx_bodyhash(bh, b"\r\n", is_relaxed);
        }
        bh.num_buffered_blanklines = 0;

        // Feed the actual line
        let line = &ctx.linebuf[line_start..line_start + effective_len];
        update_ctx_bodyhash(bh, line, is_relaxed);
    }

    ctx.linebuf_offset = 0;
}

/// Hex-encode bytes for debug logging.
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

// =============================================================================
// Header processing (from pdkim.c lines 942-1020)
// =============================================================================

/// Process a complete header line.
///
/// In signing mode: prepends the header to each signature's header list.
/// In verification mode: detects DKIM-Signature headers, parses them, and
/// adds them to the signature chain. Also stores all headers for later
/// matching during feed_finish().
///
/// Matches C `pdkim_header_complete()` from pdkim.c lines 944-1020.
fn header_complete(ctx: &mut PdkimContext) -> PdkimResult {
    // Trim trailing CR from header
    while ctx.cur_header.ends_with('\r') {
        ctx.cur_header.pop();
    }

    if ctx.cur_header.is_empty() {
        return PdkimResult::Ok;
    }

    // ARC integration: feed header to ARC processing if callback is set
    if let Some(ref arc_cb) = ctx.arc_header_callback {
        let is_verify = !ctx.flags.contains(PdkimFlags::MODE_SIGN);
        arc_cb(&ctx.cur_header, is_verify);
    }

    // Check header count limit
    if ctx.num_headers > PDKIM_MAX_HEADERS {
        warn!(
            count = ctx.num_headers,
            max = PDKIM_MAX_HEADERS,
            "PDKIM: too many headers"
        );
        return PdkimResult::Ok;
    }

    if ctx.flags.contains(PdkimFlags::MODE_SIGN) {
        // SIGNING MODE: prepend header to each signature's header list
        let hdr = ctx.cur_header.clone();
        for sig in &mut ctx.sig {
            sig.headers.insert(0, hdr.clone());
        }
    } else {
        // VERIFICATION MODE: detect DKIM-Signature headers
        let hdr = ctx.cur_header.clone();

        if let Some(colon_pos) = hdr.find(':') {
            let name = &hdr[..colon_pos];
            if name.eq_ignore_ascii_case("DKIM-Signature") {
                // Parse the DKIM-Signature header
                if let Some(sig) = parse_sig_header(ctx, &hdr) {
                    ctx.n_sigs += 1;

                    // Check excess signatures limit
                    if ctx.max_sigs > 0 && ctx.n_sigs > ctx.max_sigs {
                        warn!(
                            count = ctx.n_sigs,
                            max = ctx.max_sigs,
                            "PDKIM: excess DKIM signatures"
                        );
                        ctx.cur_header.clear();
                        return PdkimResult::ErrExcessSigs;
                    }

                    ctx.sig.push(sig);
                }
            }
        }

        // Store header for later matching during feed_finish verification
        ctx.headers.push(hdr);
    }

    ctx.num_headers += 1;
    ctx.cur_header.clear();
    PdkimResult::Ok
}

// =============================================================================
// Main feed function (from pdkim.c lines 1027-1097)
// =============================================================================

/// Feed message data into the PDKIM context for processing.
///
/// This is THE main streaming ingestion function. It processes data
/// byte-by-byte, handling the transition from headers to body, tracking
/// CR/LF sequences for line detection, and delegating to header_complete()
/// and bodyline_complete() as appropriate.
///
/// An empty slice signals end-of-body, completing body hash computation.
///
/// Matches C `pdkim_feed()` from pdkim.c lines 1027-1097.
pub fn feed(ctx: &mut PdkimContext, data: &[u8]) -> PdkimResult {
    // Empty data signals end of body
    if data.is_empty() {
        if !ctx.flags.contains(PdkimFlags::SEEN_EOD) {
            body_complete(ctx);
        }
        return PdkimResult::Ok;
    }

    for &byte in data {
        if ctx.flags.contains(PdkimFlags::PAST_HDRS) {
            // ═══════════════════════════════════════════════════════════════
            // BODY MODE
            // ═══════════════════════════════════════════════════════════════

            // Emulate CR before bare LF (some MTAs send bare LFs)
            if byte == b'\n'
                && !ctx.flags.contains(PdkimFlags::SEEN_CR)
                && ctx.linebuf_offset < PDKIM_MAX_BODY_LINE_LEN
            {
                ctx.linebuf[ctx.linebuf_offset] = b'\r';
                ctx.linebuf_offset += 1;
            }

            // Track CR/LF state
            if byte == b'\r' {
                ctx.flags.insert(PdkimFlags::SEEN_CR);
            } else {
                ctx.flags.remove(PdkimFlags::SEEN_CR);
            }

            // Accumulate byte in line buffer
            if ctx.linebuf_offset < PDKIM_MAX_BODY_LINE_LEN {
                ctx.linebuf[ctx.linebuf_offset] = byte;
                ctx.linebuf_offset += 1;
            }

            // On LF: line is complete
            if byte == b'\n' {
                bodyline_complete(ctx);
                if ctx.flags.contains(PdkimFlags::SEEN_EOD) {
                    return PdkimResult::Ok;
                }
            }

            // Check body line length limit
            if ctx.linebuf_offset >= PDKIM_MAX_BODY_LINE_LEN {
                return PdkimResult::ErrLongLine;
            }
        } else {
            // ═══════════════════════════════════════════════════════════════
            // HEADER MODE
            // ═══════════════════════════════════════════════════════════════

            if byte == b'\r' {
                ctx.flags.insert(PdkimFlags::SEEN_CR);
                continue;
            }

            if byte == b'\n' {
                let had_lf = ctx.flags.contains(PdkimFlags::SEEN_LF);
                ctx.flags.insert(PdkimFlags::SEEN_LF);
                ctx.flags.remove(PdkimFlags::SEEN_CR);

                if had_lf {
                    // Double LF (blank line) = end of headers, enter body mode
                    let rc = header_complete(ctx);
                    if rc != PdkimResult::Ok {
                        return rc;
                    }
                    ctx.flags.insert(PdkimFlags::PAST_HDRS);
                    ctx.linebuf_offset = 0;
                    continue;
                }
                continue;
            }

            if ctx.flags.contains(PdkimFlags::SEEN_LF) {
                // We had an LF and now see a non-LF character
                ctx.flags.remove(PdkimFlags::SEEN_LF);

                if byte == b' ' || byte == b'\t' {
                    // WSP after LF = continuation (folded header)
                    // Append LF and WSP to current header
                    ctx.cur_header.push('\n');
                    ctx.cur_header.push(byte as char);
                } else {
                    // Non-WSP after LF = end of current header
                    let rc = header_complete(ctx);
                    if rc != PdkimResult::Ok {
                        return rc;
                    }
                    // Start new header with this byte
                    ctx.cur_header.clear();
                    ctx.cur_header.push(byte as char);
                }
                continue;
            }

            // Regular header byte
            if ctx.cur_header.len() < PDKIM_MAX_HEADER_LEN {
                ctx.cur_header.push(byte as char);
            }
        }
    }

    PdkimResult::Ok
}

// =============================================================================
// Signature header creation (from pdkim.c lines 1101-1305)
// =============================================================================

/// Append CRLF+TAB continuation to a header string, resetting the column.
///
/// Matches C `pdkim_hdr_cont()` from pdkim.c lines 1102-1107.
fn hdr_cont(s: &mut String, col: &mut usize) {
    s.push_str("\r\n\t");
    *col = 1; // Tab counts as 1 column
}

/// Smart header value appender respecting 78-char line length per RFC 5322.
///
/// The `pad` is typically a semicolon separator, `intro` is the tag name
/// (e.g., `"d="`), and `payload` is the tag value. The function handles
/// line folding by splitting values at column 78 boundaries.
///
/// Faithfully replicates C `pdkim_headcat()` from pdkim.c lines 1133-1197.
fn headcat(
    col: &mut usize,
    s: &mut String,
    pad: Option<&str>,
    intro: Option<&str>,
    payload: Option<&str>,
) {
    let mut padded = false;
    let mut pad_consumed = false;

    // If we can fit at least the pad (single char ";") at end of current line,
    // do it now. Otherwise, wrap if there is a pad.
    if let Some(p) = pad {
        if *col < 78 {
            // Append just the first character of pad (";")
            s.push_str(&p[..1]);
            *col += 1;
            pad_consumed = true;
            padded = true;
        } else {
            hdr_cont(s, col);
        }
    }

    // Special case: if the whole addition does not fit at end of current line,
    // but could fit on a new line, wrap to give it its full, dedicated line.
    let total_len = (if pad.is_some() && !pad_consumed {
        2 // pad char + space
    } else if padded {
        1 // just space
    } else {
        0
    }) + intro.map_or(0, |i| i.len())
        + payload.map_or(0, |p| p.len());

    if total_len <= 77 && *col + total_len > 78 {
        hdr_cont(s, col);
        padded = false;
    }

    // Either we already dealt with the pad or we know there is room
    if pad.is_some() && !pad_consumed {
        // Pad wasn't consumed above (line was wrapped), output pad + space
        s.push_str("; ");
        *col += 2;
    } else if padded && *col < 78 {
        s.push(' ');
        *col += 1;
    }

    // Call recursively with intro as payload: it gets the same special
    // treatment (split at column 78)
    if intro.is_some() {
        headcat(col, s, None, None, intro);
    }

    // Handle payload: split at 78-char line boundaries
    if let Some(payload) = payload {
        let bytes = payload.as_bytes();
        let mut remaining = bytes.len();
        let mut offset = 0;
        while remaining > 0 {
            if *col >= 78 {
                hdr_cont(s, col);
            }
            let chomp = if *col + remaining > 78 {
                78 - *col
            } else {
                remaining
            };
            s.push_str(&payload[offset..offset + chomp]);
            *col += chomp;
            offset += chomp;
            remaining -= chomp;
        }
    }
}

/// Build a complete DKIM-Signature header from a signature struct.
///
/// When `is_final` is true, includes the actual `b=` signature value.
/// When false, includes an empty `b=` tag for preliminary header hash
/// computation (the hash of everything except the b= value itself).
///
/// The header is formatted per RFC 5322 with 78-char line folding.
///
/// Matches C `pdkim_create_header()` from pdkim.c lines 1204-1305.
fn create_header(sig: &PdkimSignature, is_final: bool) -> String {
    let mut hdr = String::with_capacity(512);
    let mut col: usize = 0;

    // Encode body hash upfront (from sig's bodyhash or calc_body_hash)
    let base64_bh = encode_base64(&sig.bodyhash);

    // "DKIM-Signature: v=1" — intro only, no pad, no payload
    // Matches C: pdkim_headcat(&col, hdr, NULL, US"DKIM-Signature: v="PDKIM_SIGNATURE_VERSION, NULL)
    headcat(
        &mut col,
        &mut hdr,
        None,
        Some(&format!("DKIM-Signature: v={}", PDKIM_SIGNATURE_VERSION)),
        None,
    );

    // a= (algorithm)
    let algo = sig_to_a_tag(sig);
    headcat(&mut col, &mut hdr, Some(";"), Some("a="), Some(&algo));

    // q= (query method)
    let qm_idx = sig.querymethod as usize;
    if qm_idx < PDKIM_QUERYMETHODS.len() {
        headcat(
            &mut col,
            &mut hdr,
            Some(";"),
            Some("q="),
            Some(PDKIM_QUERYMETHODS[qm_idx]),
        );
    }

    // c= (canonicalization) — look up combined canon string
    let canon_idx = sig.canon_headers as usize + 2 * sig.canon_body as usize;
    let canon_str = if canon_idx < PDKIM_COMBINED_CANONS.len() {
        PDKIM_COMBINED_CANONS[canon_idx].str_repr.to_string()
    } else {
        format!("{}/{}", sig.canon_headers, sig.canon_body)
    };
    headcat(&mut col, &mut hdr, Some(";"), Some("c="), Some(&canon_str));

    // d= (domain)
    if let Some(ref domain) = sig.domain {
        headcat(&mut col, &mut hdr, Some(";"), Some("d="), Some(domain));
    }

    // s= (selector)
    if let Some(ref selector) = sig.selector {
        headcat(&mut col, &mut hdr, Some(";"), Some("s="), Some(selector));
    }

    // h= (header list)
    if let Some(ref headernames) = sig.headernames {
        headcat(&mut col, &mut hdr, Some(";"), Some("h="), Some(headernames));
    }

    // bh= (body hash) — only for preliminary (non-final) header per C code
    // In C: if (!is_final) pdkim_headcat(&col, hdr, US";", US"bh=", base64_bh);
    if !is_final {
        headcat(&mut col, &mut hdr, Some(";"), Some("bh="), Some(&base64_bh));
    }

    // i= (identity) — optional
    if let Some(ref identity) = sig.identity {
        headcat(&mut col, &mut hdr, Some(";"), Some("i="), Some(identity));
    }

    // t= (created timestamp) — optional, only if > 0
    if sig.created > 0 {
        let ts = sig.created.to_string();
        headcat(&mut col, &mut hdr, Some(";"), Some("t="), Some(&ts));
    }

    // x= (expiry timestamp) — optional, only if > 0
    if sig.expires > 0 {
        let ts = sig.expires.to_string();
        headcat(&mut col, &mut hdr, Some(";"), Some("x="), Some(&ts));
    }

    // l= (body length) — optional, only if >= 0
    if sig.bodylength >= 0 {
        let bl = sig.bodylength.to_string();
        headcat(&mut col, &mut hdr, Some(";"), Some("l="), Some(&bl));
    }

    if is_final {
        // Final header: b= with actual base64-encoded signature value,
        // followed by ";\r\n" terminator.
        // C: pdkim_headcat(&col, hdr, US";", US"b=", base64_b);
        //    string_catn(hdr, US";\r\n", 3);
        let sig_b64 = encode_base64(&sig.sighash);
        headcat(&mut col, &mut hdr, Some(";"), Some("b="), Some(&sig_b64));
        hdr.push_str(";\r\n");
    } else {
        // Preliminary header: empty b= for header hash calculation.
        // C: pdkim_headcat(&col, hdr, US";", US"b=;", NULL);
        //    string_catn(hdr, US"\r\n", 2);
        headcat(&mut col, &mut hdr, Some(";"), Some("b=;"), None);
        hdr.push_str("\r\n");
    }

    hdr
}

// =============================================================================
// Ed25519 key handling (from pdkim.c lines 1320-1330)
// =============================================================================

/// Strip SubjectPublicKeyInfo wrapper from Ed25519 public keys.
///
/// Per draft-ietf-dcrup-dkim-crypto-07, Ed25519 keys are 256 bits (32 bytes).
/// If the key is longer than 32 bytes, it likely has an ASN.1 wrapper, so
/// we take only the last 32 bytes (the raw key data).
///
/// Matches C `check_bare_ed25519_pubkey()` from pdkim.c lines 1320-1330.
fn check_bare_ed25519_pubkey(key: &mut Vec<u8>) {
    if key.len() > 32 {
        let bare = key[key.len() - 32..].to_vec();
        *key = bare;
    }
}

// =============================================================================
// DNS key retrieval (from pdkim.c lines 1333-1416)
// =============================================================================

/// Fetch and parse the DKIM public key from DNS for a signature.
///
/// Constructs the DNS name `{selector}._domainkey.{domain}`, calls the
/// DNS TXT callback, parses the result, validates it, and initializes
/// a verification context with the public key.
///
/// On failure, sets the signature's verify_status and verify_ext_status.
///
/// Matches C `pdkim_key_from_dns()` from pdkim.c lines 1333-1416.
fn key_from_dns(
    ctx: &PdkimContext,
    sig: &mut PdkimSignature,
) -> Result<(PdkimPubkey, VerificationContext), PdkimError> {
    let selector = sig.selector.as_deref().unwrap_or("");
    let domain = sig.domain.as_deref().unwrap_or("");

    // Construct DNS name
    let dns_name = format!("{selector}._domainkey.{domain}.");
    if dns_name.len() > PDKIM_DNS_TXT_MAX_NAMELEN {
        warn!(
            name_len = dns_name.len(),
            max = PDKIM_DNS_TXT_MAX_NAMELEN,
            "PDKIM: DNS name too long"
        );
        sig.verify_status = VerifyStatus::Invalid;
        sig.verify_ext_status = VerifyExtStatus::InvalidPubkeyUnavailable;
        return Err(PdkimError::DnsLookupFailed(dns_name));
    }

    debug!(dns_name = %dns_name, "PDKIM: querying DNS for public key");

    // Call DNS callback
    let dns_callback = ctx.dns_txt_callback.as_ref().ok_or_else(|| {
        sig.verify_status = VerifyStatus::Invalid;
        sig.verify_ext_status = VerifyExtStatus::InvalidPubkeyUnavailable;
        PdkimError::DnsLookupFailed("no DNS callback configured".to_string())
    })?;

    // DNS data is untrusted external input — wrap as TaintedString per AAP §0.4.3
    let raw_record: TaintedString = match dns_callback(&dns_name) {
        Some(record) => Tainted::new(record),
        None => {
            debug!(dns_name = %dns_name, "PDKIM: DNS lookup returned no record");
            sig.verify_status = VerifyStatus::Invalid;
            sig.verify_ext_status = VerifyExtStatus::InvalidPubkeyUnavailable;
            return Err(PdkimError::DnsLookupFailed(dns_name));
        }
    };

    // Parse the public key record (consuming the tainted wrapper)
    let mut pubkey = match parse_pubkey_record(&raw_record.into_inner()) {
        Some(pk) => pk,
        None => {
            debug!("PDKIM: failed to parse DNS pubkey record");
            sig.verify_status = VerifyStatus::Invalid;
            sig.verify_ext_status = VerifyExtStatus::InvalidPubkeyDnsrecord;
            return Err(PdkimError::DnsLookupFailed(dns_name));
        }
    };

    // Validate service type
    if let Some(ref srvtype) = pubkey.srvtype {
        if srvtype != "*" && !srvtype.contains("email") {
            debug!(srvtype = %srvtype, "PDKIM: pubkey srvtype mismatch");
            sig.verify_status = VerifyStatus::Invalid;
            sig.verify_ext_status = VerifyExtStatus::InvalidPubkeyDnsrecord;
            return Err(PdkimError::DnsLookupFailed(dns_name));
        }
    }

    // Determine key type and format
    let key_type = if sig.keytype < PDKIM_KEYTYPES.len() as i32 {
        match sig.keytype {
            0 => KeyType::Rsa,
            1 => KeyType::Ed25519,
            _ => KeyType::Rsa,
        }
    } else {
        KeyType::Rsa
    };

    let key_format = if key_type == KeyType::Ed25519 {
        // Ed25519: check for bare key format
        check_bare_ed25519_pubkey(&mut pubkey.key);
        if pubkey.key.len() == 32 {
            KeyFormat::Ed25519Bare
        } else {
            KeyFormat::Der
        }
    } else {
        KeyFormat::Der
    };

    // Initialize verification context
    let (verify_ctx, key_bits) =
        signing::verify_init(&pubkey.key, key_type, key_format).map_err(|e| {
            debug!(error = %e, "PDKIM: public key import failed");
            sig.verify_status = VerifyStatus::Invalid;
            sig.verify_ext_status = VerifyExtStatus::InvalidPubkeyImport;
            PdkimError::VerificationFailed(e.to_string())
        })?;

    sig.keybits = key_bits;

    debug!(
        key_type = %key_type,
        key_bits = key_bits,
        "PDKIM: public key imported successfully"
    );

    // Validated pubkey is now clean (has passed parsing, srvtype, and key import
    // validation) — wrap in Clean<> to mark as verified trusted data
    let clean_pubkey: Clean<PdkimPubkey> = Clean::new(pubkey);

    Ok((clean_pubkey.into_inner(), verify_ctx))
}

// =============================================================================
// Signature sorting (from pdkim.c lines 1422-1471)
// =============================================================================

/// Sort signatures by hash type preference, then key type preference.
///
/// This ensures that the preferred verification method is tried first.
/// The preference order comes from the `dkim_verify_hashes` and
/// `dkim_verify_keytypes` configuration strings.
///
/// Matches C `sort_sig_methods()` from pdkim.c lines 1422-1471.
fn sort_sig_methods(sigs: &mut [PdkimSignature], verify_hashes: &str, verify_keytypes: &str) {
    if sigs.is_empty() {
        return;
    }

    // Build hash preference order
    let hash_prefs: Vec<&str> = verify_hashes.split(':').collect();
    // Build keytype preference order
    let key_prefs: Vec<&str> = verify_keytypes.split(':').collect();

    sigs.sort_by(|a, b| {
        // First: sort by hash preference (lower index = higher preference)
        let a_hash_pref = if a.hashtype >= 0 && (a.hashtype as usize) < PDKIM_HASHES.len() {
            let name = PDKIM_HASHES[a.hashtype as usize].dkim_hashname;
            hash_prefs
                .iter()
                .position(|&h| h == name)
                .unwrap_or(usize::MAX)
        } else {
            usize::MAX
        };
        let b_hash_pref = if b.hashtype >= 0 && (b.hashtype as usize) < PDKIM_HASHES.len() {
            let name = PDKIM_HASHES[b.hashtype as usize].dkim_hashname;
            hash_prefs
                .iter()
                .position(|&h| h == name)
                .unwrap_or(usize::MAX)
        } else {
            usize::MAX
        };

        let hash_cmp = a_hash_pref.cmp(&b_hash_pref);
        if hash_cmp != std::cmp::Ordering::Equal {
            return hash_cmp;
        }

        // Then: sort by keytype preference
        let a_key_pref = if a.keytype >= 0 && (a.keytype as usize) < PDKIM_KEYTYPES.len() {
            let name = PDKIM_KEYTYPES[a.keytype as usize];
            key_prefs
                .iter()
                .position(|&k| k == name)
                .unwrap_or(usize::MAX)
        } else {
            usize::MAX
        };
        let b_key_pref = if b.keytype >= 0 && (b.keytype as usize) < PDKIM_KEYTYPES.len() {
            let name = PDKIM_KEYTYPES[b.keytype as usize];
            key_prefs
                .iter()
                .position(|&k| k == name)
                .unwrap_or(usize::MAX)
        } else {
            usize::MAX
        };

        a_key_pref.cmp(&b_key_pref)
    });
}

// =============================================================================
// Feed finish — signing and verification completion
// (from pdkim.c lines 1476-1918)
// =============================================================================

/// Complete DKIM signing or verification after all data has been fed.
///
/// This is THE critical completion function that performs the final
/// cryptographic operations.
///
/// **SIGNING mode:**
/// 1. Computes header hash over the signed headers + preliminary sig header.
/// 2. Signs the hash with the private key.
/// 3. Builds the final DKIM-Signature header with the `b=` value.
///
/// **VERIFICATION mode:**
/// 1. Computes header hash over the headers listed in `h=` tag.
/// 2. Fetches the public key from DNS.
/// 3. Verifies the signature against the computed hash.
/// 4. Checks minimum key size requirements.
///
/// Returns the list of processed signatures with their results.
///
/// Matches C `pdkim_feed_finish()` from pdkim.c lines 1476-1918.
pub fn feed_finish(ctx: &mut PdkimContext) -> Result<Vec<PdkimSignature>, PdkimError> {
    // Flush any pending header
    if !ctx.cur_header.is_empty() {
        let rc = header_complete(ctx);
        if rc != PdkimResult::Ok && rc != PdkimResult::ErrExcessSigs {
            return Err(PdkimError::General(rc));
        }
    }

    // If body was never entered (message with headers only), feed an empty
    // CRLF to finalize body hashes properly.
    if !ctx.flags.contains(PdkimFlags::PAST_HDRS) {
        ctx.flags.insert(PdkimFlags::PAST_HDRS);
    }

    if !ctx.flags.contains(PdkimFlags::SEEN_EOD) {
        body_complete(ctx);
    }

    // Finalize all body hashes and compare with signature bh= values
    finish_bodyhash(ctx);

    // For verification mode: sort signatures by preference
    if !ctx.flags.contains(PdkimFlags::MODE_SIGN) {
        sort_sig_methods(&mut ctx.sig, "sha256:sha512:sha1", "rsa:ed25519");
    }

    let is_signing = ctx.flags.contains(PdkimFlags::MODE_SIGN);
    let num_sigs = ctx.sig.len();

    // Process each signature
    for sig_idx in 0..num_sigs {
        if is_signing {
            // ═════════════════════════════════════════════════════════════
            // SIGNING MODE
            // ═════════════════════════════════════════════════════════════

            let hashtype = ctx.sig[sig_idx].hashtype;
            if hashtype < 0 || hashtype as usize >= PDKIM_HASHES.len() {
                continue;
            }

            // Initialize header hash context
            let mut hdr_hash = match HashContext::new_from_index(hashtype) {
                Some(h) => h,
                None => {
                    error!(hashtype = hashtype, "PDKIM: failed to init header hash");
                    continue;
                }
            };

            // Import private key
            let privkey = match ctx.sig[sig_idx].privkey.as_deref() {
                Some(pk) => pk,
                None => {
                    error!("PDKIM: no private key for signing");
                    continue;
                }
            };

            let hash_algo = PDKIM_HASHES[hashtype as usize].exim_hashmethod;
            let key_type_idx = ctx.sig[sig_idx].keytype;
            let key_type = if key_type_idx == 1 {
                KeyType::Ed25519
            } else {
                KeyType::Rsa
            };

            let mut sign_ctx = match signing::signing_init(privkey, key_type, hash_algo) {
                Ok(sc) => sc,
                Err(e) => {
                    error!(error = %e, "PDKIM: signing init failed");
                    continue;
                }
            };

            // Walk headers, match against sign_headers, add to hash
            let sign_headers_list = ctx.sig[sig_idx]
                .sign_headers
                .clone()
                .unwrap_or_else(|| PDKIM_DEFAULT_SIGN_HEADERS.to_string());

            let mut signed_header_names = String::new();
            let mut tick_list = sign_headers_list.clone();

            // Process headers in order (first to last as stored)
            let headers_snapshot: Vec<String> = ctx.sig[sig_idx].headers.clone();
            for hdr in &headers_snapshot {
                if header_name_match(hdr, &mut tick_list, true) {
                    // Extract header name (everything before the colon)
                    let hdr_name_len = hdr.find(':').unwrap_or(hdr.len());

                    // Add to header hash
                    let canon_hdr = if ctx.sig[sig_idx].canon_headers == Canon::Relaxed {
                        relax_header(hdr, true)
                    } else {
                        format!("{hdr}\r\n")
                    };
                    hdr_hash.update(canon_hdr.as_bytes());
                    sign_ctx.data_append(canon_hdr.as_bytes());

                    // Collect header name for h= tag
                    if !signed_header_names.is_empty() {
                        signed_header_names.push(':');
                    }
                    signed_header_names.push_str(&hdr[..hdr_name_len]);

                    trace!(header = &hdr[..hdr_name_len], "PDKIM: signing header");
                }
            }

            // Update signature with collected header names
            ctx.sig[sig_idx].headernames = Some(signed_header_names);

            // Build preliminary signature header (with empty b=)
            let prelim_header = create_header(&ctx.sig[sig_idx], false);

            // Apply canonicalization to preliminary header and add to hash
            // NOTE: The final header in the hash does NOT get a trailing CRLF
            let canon_sig_hdr = if ctx.sig[sig_idx].canon_headers == Canon::Relaxed {
                relax_header(&prelim_header, false)
            } else {
                prelim_header.clone()
            };
            hdr_hash.update(canon_sig_hdr.as_bytes());
            sign_ctx.data_append(canon_sig_hdr.as_bytes());

            // For Ed25519: signing uses the raw accumulated data.
            // For RSA: signing uses the raw accumulated data too
            // (the signing module handles the hash internally).
            let sig_bytes = match signing::sign(&mut sign_ctx) {
                Ok(bytes) => bytes,
                Err(e) => {
                    error!(error = %e, "PDKIM: signing failed");
                    continue;
                }
            };

            ctx.sig[sig_idx].sighash = sig_bytes;

            // Build final DKIM-Signature header with actual b= value
            let final_header = create_header(&ctx.sig[sig_idx], true);
            ctx.sig[sig_idx].signature_header = Some(final_header);

            debug!(
                domain = ?ctx.sig[sig_idx].domain,
                selector = ?ctx.sig[sig_idx].selector,
                "PDKIM: signing complete"
            );
        } else {
            // ═════════════════════════════════════════════════════════════
            // VERIFICATION MODE
            // ═════════════════════════════════════════════════════════════

            // Skip signatures that already failed body hash check
            if ctx.sig[sig_idx].verify_status == VerifyStatus::Fail {
                continue;
            }

            let hashtype = ctx.sig[sig_idx].hashtype;
            if hashtype < 0 || hashtype as usize >= PDKIM_HASHES.len() {
                ctx.sig[sig_idx].verify_status = VerifyStatus::Invalid;
                ctx.sig[sig_idx].verify_ext_status = VerifyExtStatus::InvalidSignatureError;
                continue;
            }

            // Initialize header hash context
            let mut hdr_hash = match HashContext::new_from_index(hashtype) {
                Some(h) => h,
                None => {
                    ctx.sig[sig_idx].verify_status = VerifyStatus::Invalid;
                    ctx.sig[sig_idx].verify_ext_status = VerifyExtStatus::InvalidSignatureError;
                    continue;
                }
            };

            // Initialize verification data accumulator
            let mut verify_data = Vec::new();

            // Walk h= header names, find matching headers, hash them
            let header_names = ctx.sig[sig_idx].headernames.clone().unwrap_or_default();

            // Build a copy of headers for matching
            let all_headers: Vec<String> = ctx.headers.clone();
            let mut used_headers: Vec<bool> = vec![false; all_headers.len()];

            for hname in header_names.split(':') {
                let hname = hname.trim();
                if hname.is_empty() {
                    continue;
                }

                // Find the last unused header matching this name
                // (search from end to beginning per RFC 6376 §5.4.2)
                let mut found_idx: Option<usize> = None;
                for (i, hdr) in all_headers.iter().enumerate().rev() {
                    if used_headers[i] {
                        continue;
                    }
                    if let Some(colon) = hdr.find(':') {
                        let name = &hdr[..colon];
                        if name.eq_ignore_ascii_case(hname) {
                            found_idx = Some(i);
                            break;
                        }
                    }
                }

                if let Some(idx) = found_idx {
                    used_headers[idx] = true;
                    let hdr = &all_headers[idx];

                    // Apply canonicalization
                    let canon_hdr = if ctx.sig[sig_idx].canon_headers == Canon::Relaxed {
                        relax_header(hdr, true)
                    } else {
                        format!("{hdr}\r\n")
                    };

                    hdr_hash.update(canon_hdr.as_bytes());
                    verify_data.extend_from_slice(canon_hdr.as_bytes());

                    trace!(header = hname, "PDKIM: verification hashing header");
                }
            }

            // Add the DKIM-Signature header itself (with b= stripped) as the
            // final entry in the header hash. Per RFC 6376 §3.7, this header
            // does NOT get a trailing CRLF.
            if let Some(ref rawsig) = ctx.sig[sig_idx].rawsig_no_b_val {
                let canon_sig = if ctx.sig[sig_idx].canon_headers == Canon::Relaxed {
                    relax_header(rawsig, false)
                } else {
                    rawsig.clone()
                };
                hdr_hash.update(canon_sig.as_bytes());
                verify_data.extend_from_slice(canon_sig.as_bytes());
            }

            // Validate required tags are present
            let sig_ref = &ctx.sig[sig_idx];
            if sig_ref.domain.is_none()
                || sig_ref.selector.is_none()
                || sig_ref.headernames.is_none()
                || sig_ref.bodyhash.is_empty()
                || sig_ref.sighash.is_empty()
            {
                debug!("PDKIM: signature missing required tags");
                ctx.sig[sig_idx].verify_status = VerifyStatus::Invalid;
                ctx.sig[sig_idx].verify_ext_status = VerifyExtStatus::InvalidSignatureError;
                continue;
            }

            // Validate DKIM version
            if ctx.sig[sig_idx].version != 1 {
                debug!(
                    version = ctx.sig[sig_idx].version,
                    "PDKIM: invalid DKIM version"
                );
                ctx.sig[sig_idx].verify_status = VerifyStatus::Invalid;
                ctx.sig[sig_idx].verify_ext_status = VerifyExtStatus::InvalidDkimVersion;
                continue;
            }

            // Fetch public key from DNS.
            // We must temporarily remove the signature from ctx to satisfy
            // the borrow checker — key_from_dns needs &PdkimContext (for dns_txt_callback)
            // and &mut PdkimSignature simultaneously.
            let mut sig_tmp = std::mem::take(&mut ctx.sig[sig_idx]);
            let dns_result = key_from_dns(ctx, &mut sig_tmp);
            ctx.sig[sig_idx] = sig_tmp;
            let (pubkey, mut verify_ctx) = match dns_result {
                Ok(result) => result,
                Err(_) => continue, // verify_status already set by key_from_dns
            };

            // Check pubkey h= tag restricts hash types
            if let Some(ref pubkey_hashes) = pubkey.hashes {
                let sig_hash_idx = ctx.sig[sig_idx].hashtype as usize;
                if sig_hash_idx < PDKIM_HASHES.len() {
                    let sig_hash_name = PDKIM_HASHES[sig_hash_idx].dkim_hashname;
                    let allowed: Vec<&str> = pubkey_hashes.split(':').collect();
                    if !allowed.contains(&sig_hash_name) {
                        debug!(
                            sig_hash = sig_hash_name,
                            allowed = %pubkey_hashes,
                            "PDKIM: hash algorithm not allowed by pubkey"
                        );
                        ctx.sig[sig_idx].verify_status = VerifyStatus::Fail;
                        ctx.sig[sig_idx].verify_ext_status = VerifyExtStatus::FailSigAlgoMismatch;
                        continue;
                    }
                }
            }

            // Perform signature verification
            let hash_algo = PDKIM_HASHES[hashtype as usize].exim_hashmethod;
            verify_ctx.data_append(&verify_data);

            let sig_bytes = &ctx.sig[sig_idx].sighash;
            match signing::verify(&mut verify_ctx, sig_bytes, hash_algo) {
                Ok(true) => {
                    // Check minimum key size (1024 bits for RSA)
                    let min_keybits: u32 = if ctx.sig[sig_idx].keytype == 0 {
                        1024 // RSA minimum
                    } else {
                        0 // Ed25519 has fixed 256-bit keys
                    };

                    if ctx.sig[sig_idx].keybits > 0 && ctx.sig[sig_idx].keybits < min_keybits {
                        debug!(
                            keybits = ctx.sig[sig_idx].keybits,
                            min = min_keybits,
                            "PDKIM: key too short"
                        );
                        ctx.sig[sig_idx].verify_status = VerifyStatus::Invalid;
                        ctx.sig[sig_idx].verify_ext_status = VerifyExtStatus::InvalidPubkeyKeysize;
                    } else {
                        info!(
                            domain = ?ctx.sig[sig_idx].domain,
                            selector = ?ctx.sig[sig_idx].selector,
                            algo = %sig_to_a_tag(&ctx.sig[sig_idx]),
                            keybits = ctx.sig[sig_idx].keybits,
                            "PDKIM: signature verification PASSED"
                        );
                        ctx.sig[sig_idx].verify_status = VerifyStatus::Pass;
                    }

                    // Store pubkey on signature
                    ctx.sig[sig_idx].pubkey = Some(pubkey);
                }
                Ok(false) => {
                    debug!(
                        domain = ?ctx.sig[sig_idx].domain,
                        "PDKIM: signature verification FAILED (mismatch)"
                    );
                    ctx.sig[sig_idx].verify_status = VerifyStatus::Fail;
                    ctx.sig[sig_idx].verify_ext_status = VerifyExtStatus::FailMessage;
                    ctx.sig[sig_idx].pubkey = Some(pubkey);
                }
                Err(e) => {
                    error!(error = %e, "PDKIM: verification error");
                    ctx.sig[sig_idx].verify_status = VerifyStatus::Fail;
                    ctx.sig[sig_idx].verify_ext_status = VerifyExtStatus::FailMessage;
                    ctx.sig[sig_idx].pubkey = Some(pubkey);
                }
            }
        }
    }

    // Return all signatures with their results
    Ok(ctx.sig.drain(..).collect())
}

// =============================================================================
// Initialization functions (from pdkim.c lines 1923-2106)
// =============================================================================

/// Create a new verification context.
///
/// Matches C `pdkim_init_verify()` from pdkim.c lines 1923-1938.
pub fn init_verify(
    dns_callback: impl Fn(&str) -> Option<String> + 'static,
    dot_stuffing: bool,
) -> PdkimContext {
    let mut ctx = PdkimContext::new();
    ctx.dns_txt_callback = Some(Box::new(dns_callback));
    if dot_stuffing {
        ctx.flags.insert(PdkimFlags::DOT_TERM);
    }
    debug!(
        dot_stuffing = dot_stuffing,
        "PDKIM: initialized verification context"
    );
    ctx
}

/// Create a new signing signature.
///
/// Matches C `pdkim_init_sign()` from pdkim.c lines 1943-1987.
pub fn init_sign(
    ctx: &mut PdkimContext,
    domain: &str,
    selector: &str,
    privkey: &str,
    hashname: &str,
) -> Option<PdkimSignature> {
    if domain.is_empty() || selector.is_empty() || privkey.is_empty() {
        error!("PDKIM: init_sign requires domain, selector, and privkey");
        return None;
    }
    let hashtype = match hashname_to_hashtype(hashname) {
        Some(ht) => ht as i32,
        None => {
            error!(hashname = hashname, "PDKIM: unknown hash algorithm");
            return None;
        }
    };
    let sig = PdkimSignature {
        domain: Some(domain.to_string()),
        selector: Some(selector.to_string()),
        privkey: Some(privkey.to_string()),
        hashtype,
        keytype: 0,
        ..PdkimSignature::default()
    };
    ctx.flags.insert(PdkimFlags::MODE_SIGN);
    debug!(
        domain = domain,
        selector = selector,
        hashname = hashname,
        "PDKIM: initialized signing signature"
    );
    Some(sig)
}

/// Set optional parameters on a signing signature.
///
/// Matches C `pdkim_set_optional()` from pdkim.c lines 1992-2015.
// Clippy `too_many_arguments`: this function mirrors the C API `pdkim_set_optional()`
// which accepts exactly these 8 parameters. Changing the signature would break the
// public API contract matching the C version (pdkim.c lines 1992-2015).
#[allow(clippy::too_many_arguments)]
pub fn set_optional(
    sig: &mut PdkimSignature,
    sign_headers: Option<&str>,
    identity: Option<&str>,
    canon_headers: Canon,
    canon_body: Canon,
    bodylength: i64,
    created: u64,
    expires: u64,
) {
    sig.sign_headers = Some(
        sign_headers
            .unwrap_or(PDKIM_DEFAULT_SIGN_HEADERS)
            .to_string(),
    );
    sig.identity = identity.map(String::from);
    sig.canon_headers = canon_headers;
    sig.canon_body = canon_body;
    sig.bodylength = bodylength;
    sig.created = created;
    sig.expires = expires;
    trace!(
        canon = %format!("{canon_headers}/{canon_body}"),
        bodylength = bodylength,
        "PDKIM: set optional signature parameters"
    );
}

/// Find or create a body hash context matching the given parameters.
///
/// Matches C `pdkim_set_bodyhash()` from pdkim.c lines 2024-2068.
pub fn set_bodyhash(
    ctx: &mut PdkimContext,
    hashtype: i32,
    canon_method: Canon,
    bodylength: i64,
) -> Option<usize> {
    for (i, bh) in ctx.bodyhash.iter().enumerate() {
        if bh.hashtype == hashtype && bh.canon_method == canon_method && bh.bodylength == bodylength
        {
            return Some(i);
        }
    }
    let hash_ctx = HashContext::new_from_index(hashtype)?;
    let bh = PdkimBodyhash {
        hashtype,
        canon_method,
        bodylength,
        body_hash_ctx: hash_ctx,
        signed_body_bytes: 0,
        num_buffered_blanklines: 0,
        bh: Vec::new(),
    };
    ctx.bodyhash.push(bh);
    let idx = ctx.bodyhash.len() - 1;
    trace!(hashtype = hashtype, canon = %canon_method, bodylength = bodylength, index = idx, "PDKIM: created new body hash context");
    Some(idx)
}

/// Link a signature to its matching body hash context.
///
/// Matches C `pdkim_set_sig_bodyhash()` from pdkim.c lines 2077-2084.
pub fn set_sig_bodyhash(ctx: &mut PdkimContext, sig_index: usize) -> Option<usize> {
    if sig_index >= ctx.sig.len() {
        return None;
    }
    let hashtype = ctx.sig[sig_index].hashtype;
    let canon = ctx.sig[sig_index].canon_body;
    let bodylength = ctx.sig[sig_index].bodylength;
    let bh_idx = set_bodyhash(ctx, hashtype, canon, bodylength)?;
    ctx.sig[sig_index].calc_body_hash = Some(bh_idx);
    Some(bh_idx)
}

/// Initialize a PDKIM context for signing.
///
/// Matches C `pdkim_init_context()` from pdkim.c lines 2090-2099.
pub fn init_context(
    ctx: &mut PdkimContext,
    dot_stuffed: bool,
    dns_callback: Option<DnsTxtCallback>,
) {
    if dot_stuffed {
        ctx.flags.insert(PdkimFlags::DOT_TERM);
    }
    ctx.dns_txt_callback = dns_callback;
    ctx.flags.insert(PdkimFlags::MODE_SIGN);
    trace!(
        dot_stuffed = dot_stuffed,
        "PDKIM: initialized signing context"
    );
}

/// One-time PDKIM library initialization.
///
/// Matches C `pdkim_init()` from pdkim.c lines 2103-2106.
pub fn init() {
    if let Err(e) = signing::signers_init() {
        error!(error = %e, "PDKIM: crypto subsystem initialization failed");
    } else {
        // Log crypto backend capabilities for diagnostics
        let caps: signing::CryptoCapabilities = signing::crypto_capabilities();
        info!(
            backend = caps.backend_name,
            ed25519 = caps.ed25519_supported,
            "PDKIM: library initialized with crypto backend"
        );
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canon_display() {
        assert_eq!(format!("{}", Canon::Simple), "simple");
        assert_eq!(format!("{}", Canon::Relaxed), "relaxed");
    }

    #[test]
    fn test_verify_status_display() {
        assert_eq!(format!("{}", VerifyStatus::None), "none");
        assert_eq!(format!("{}", VerifyStatus::Pass), "pass");
        assert_eq!(format!("{}", VerifyStatus::Fail), "fail");
        assert_eq!(format!("{}", VerifyStatus::Invalid), "invalid");
    }

    #[test]
    fn test_verify_ext_status_display() {
        assert_eq!(
            format!("{}", VerifyExtStatus::FailBody),
            "body hash did not verify"
        );
        assert_eq!(
            format!("{}", VerifyExtStatus::FailMessage),
            "message signature did not verify"
        );
    }

    #[test]
    fn test_pdkim_result_display() {
        assert_eq!(format!("{}", PdkimResult::Ok), "OK");
        assert_eq!(format!("{}", PdkimResult::Fail), "FAIL");
        assert_eq!(format!("{}", PdkimResult::ErrLongLine), "ERR_LONG_LINE");
    }

    #[test]
    fn test_sig_to_a_tag() {
        let mut sig = PdkimSignature::default();
        sig.keytype = 0;
        sig.hashtype = 1;
        assert_eq!(sig_to_a_tag(&sig), "rsa-sha256");
        sig.keytype = 1;
        sig.hashtype = 2;
        assert_eq!(sig_to_a_tag(&sig), "ed25519-sha512");
    }

    #[test]
    fn test_sig_to_a_tag_invalid() {
        let sig = PdkimSignature::default();
        assert_eq!(sig_to_a_tag(&sig), "err");
    }

    #[test]
    fn test_hashname_to_hashtype_values() {
        assert_eq!(hashname_to_hashtype("sha1"), Some(0));
        assert_eq!(hashname_to_hashtype("sha256"), Some(1));
        assert_eq!(hashname_to_hashtype("sha512"), Some(2));
        assert_eq!(hashname_to_hashtype("md5"), None);
    }

    #[test]
    fn test_cstring_to_canons_values() {
        assert_eq!(
            cstring_to_canons("relaxed/relaxed"),
            (Canon::Relaxed, Canon::Relaxed)
        );
        assert_eq!(
            cstring_to_canons("simple/relaxed"),
            (Canon::Simple, Canon::Relaxed)
        );
        assert_eq!(
            cstring_to_canons("relaxed"),
            (Canon::Relaxed, Canon::Simple)
        );
        assert_eq!(cstring_to_canons("unknown"), (Canon::Simple, Canon::Simple));
    }

    #[test]
    fn test_relax_header_basic() {
        let result = relax_header("From:  John  Doe", false);
        assert_eq!(result, "from:John Doe");
    }

    #[test]
    fn test_relax_header_with_crlf() {
        let result = relax_header("Subject: Hello  World", true);
        assert_eq!(result, "subject:Hello World\r\n");
    }

    #[test]
    fn test_relax_header_wsp_around_colon() {
        let result = relax_header("From \t : \t value", false);
        assert_eq!(result, "from:value");
    }

    #[test]
    fn test_relax_header_ignore_crlf() {
        let result = relax_header("Subject: line1\r\n\tline2", false);
        assert_eq!(result, "subject:line1 line2");
    }

    #[test]
    fn test_decode_base64_valid() {
        let result = decode_base64("SGVsbG8=");
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_encode_base64_valid() {
        let result = encode_base64(b"Hello");
        assert_eq!(result, "SGVsbG8=");
    }

    #[test]
    fn test_decode_base64_invalid() {
        let result = decode_base64("not-valid!!!");
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_pubkey_record_basic() {
        let record = "v=DKIM1; k=rsa; p=SGVsbG8=";
        let pk = parse_pubkey_record(record).unwrap();
        assert_eq!(pk.version.as_deref(), Some("DKIM1"));
        assert_eq!(pk.keytype.as_deref(), Some("rsa"));
        assert_eq!(pk.key, b"Hello");
        assert!(!pk.testing);
        assert!(!pk.no_subdomaining);
    }

    #[test]
    fn test_parse_pubkey_record_no_key() {
        let record = "v=DKIM1; k=rsa";
        assert!(parse_pubkey_record(record).is_none());
    }

    #[test]
    fn test_parse_pubkey_record_wrong_version() {
        let record = "v=DKIM2; p=SGVsbG8=";
        assert!(parse_pubkey_record(record).is_none());
    }

    #[test]
    fn test_parse_pubkey_record_defaults() {
        let record = "p=SGVsbG8=";
        let pk = parse_pubkey_record(record).unwrap();
        assert_eq!(pk.version.as_deref(), Some("DKIM1"));
        assert_eq!(pk.granularity.as_deref(), Some("*"));
        assert_eq!(pk.keytype.as_deref(), Some("rsa"));
        assert_eq!(pk.srvtype.as_deref(), Some("*"));
    }

    #[test]
    fn test_parse_pubkey_record_flags() {
        let record = "p=SGVsbG8=; t=y:s";
        let pk = parse_pubkey_record(record).unwrap();
        assert!(pk.testing);
        assert!(pk.no_subdomaining);
    }

    #[test]
    fn test_pdkim_flags() {
        let mut flags = PdkimFlags::empty();
        assert!(flags.is_empty());
        flags.insert(PdkimFlags::MODE_SIGN);
        assert!(flags.contains(PdkimFlags::MODE_SIGN));
        flags.insert(PdkimFlags::DOT_TERM);
        assert!(flags.contains(PdkimFlags::DOT_TERM));
        flags.remove(PdkimFlags::MODE_SIGN);
        assert!(!flags.contains(PdkimFlags::MODE_SIGN));
        assert!(flags.contains(PdkimFlags::DOT_TERM));
        flags.toggle(PdkimFlags::SEEN_CR);
        assert!(flags.contains(PdkimFlags::SEEN_CR));
        flags.set(PdkimFlags::SEEN_LF, true);
        assert!(flags.contains(PdkimFlags::SEEN_LF));
    }

    #[test]
    fn test_hash_context_sha256() {
        let mut ctx = HashContext::new_from_algo(HashAlgorithm::Sha256);
        ctx.update(b"hello");
        let hash = ctx.finalize();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_hash_context_sha1() {
        let mut ctx = HashContext::new_from_index(0).unwrap();
        ctx.update(b"test");
        let hash = ctx.finalize();
        assert_eq!(hash.len(), 20);
    }

    #[test]
    fn test_hash_context_sha512() {
        let mut ctx = HashContext::new_from_index(2).unwrap();
        ctx.update(b"data");
        let hash = ctx.finalize();
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_hash_context_invalid_index() {
        assert!(HashContext::new_from_index(99).is_none());
    }

    #[test]
    fn test_set_bodyhash_dedup() {
        let mut ctx = PdkimContext::new();
        let idx1 = set_bodyhash(&mut ctx, 1, Canon::Relaxed, -1).unwrap();
        let idx2 = set_bodyhash(&mut ctx, 1, Canon::Relaxed, -1).unwrap();
        assert_eq!(idx1, idx2);
        let idx3 = set_bodyhash(&mut ctx, 0, Canon::Simple, -1).unwrap();
        assert_ne!(idx1, idx3);
    }

    #[test]
    fn test_check_bare_ed25519_pubkey() {
        let mut key: Vec<u8> = (0u8..44).collect();
        check_bare_ed25519_pubkey(&mut key);
        assert_eq!(key.len(), 32);
        assert_eq!(key[0], 12);
    }

    #[test]
    fn test_check_bare_ed25519_pubkey_already_bare() {
        let mut key = vec![42u8; 32];
        check_bare_ed25519_pubkey(&mut key);
        assert_eq!(key.len(), 32);
        assert_eq!(key[0], 42);
    }

    #[test]
    fn test_pdkim_signature_default() {
        let sig = PdkimSignature::default();
        assert_eq!(sig.version, 0);
        assert_eq!(sig.keytype, -1);
        assert_eq!(sig.hashtype, -1);
        assert_eq!(sig.bodylength, -1);
        assert_eq!(sig.verify_status, VerifyStatus::None);
    }

    #[test]
    fn test_feed_empty_signals_eod() {
        let mut ctx = PdkimContext::new();
        ctx.flags.insert(PdkimFlags::PAST_HDRS);
        let result = feed(&mut ctx, &[]);
        assert_eq!(result, PdkimResult::Ok);
        assert!(ctx.flags.contains(PdkimFlags::SEEN_EOD));
    }

    #[test]
    fn test_create_header_basic() {
        let mut sig = PdkimSignature::default();
        sig.keytype = 0;
        sig.hashtype = 1;
        sig.domain = Some("example.com".to_string());
        sig.selector = Some("sel".to_string());
        sig.canon_headers = Canon::Relaxed;
        sig.canon_body = Canon::Relaxed;
        sig.headernames = Some("from:to:subject".to_string());
        sig.bodyhash = vec![1, 2, 3, 4];
        // Non-final: includes bh= but b= is empty (b=;)
        let hdr = create_header(&sig, false);
        assert!(hdr.starts_with("DKIM-Signature: v=1"));
        assert!(hdr.contains("a=rsa-sha256"));
        assert!(hdr.contains("d=example.com"));
        assert!(hdr.contains("s=sel"));
        assert!(hdr.contains("h=from:to:subject"));
        assert!(hdr.contains("bh="), "Non-final must include bh=");
        assert!(hdr.contains("b=;"), "Non-final must include empty b=;");
        assert!(hdr.ends_with("\r\n"));

        // Final header: includes b= with sighash, no bh=, trailing ;\r\n
        sig.sighash = vec![5, 6, 7, 8];
        let hdr_final = create_header(&sig, true);
        assert!(hdr_final.starts_with("DKIM-Signature: v=1"));
        assert!(hdr_final.contains("a=rsa-sha256"));
        assert!(hdr_final.contains("d=example.com"));
        assert!(hdr_final.contains("b="), "Final must include b=");
        assert!(hdr_final.ends_with(";\r\n"));
    }

    #[test]
    fn test_header_complete_signing() {
        let mut ctx = PdkimContext::new();
        ctx.flags.insert(PdkimFlags::MODE_SIGN);
        let mut sig = PdkimSignature::default();
        sig.keytype = 0;
        sig.hashtype = 1;
        ctx.sig.push(sig);
        ctx.cur_header = "From: test@example.com".to_string();
        let result = header_complete(&mut ctx);
        assert_eq!(result, PdkimResult::Ok);
        assert_eq!(ctx.sig[0].headers.len(), 1);
        assert_eq!(ctx.sig[0].headers[0], "From: test@example.com");
    }

    #[test]
    fn test_decode_qp_values() {
        assert_eq!(decode_qp("hello=20world"), "hello world");
        assert_eq!(decode_qp("=41=42=43"), "ABC");
        assert_eq!(decode_qp("no encoding"), "no encoding");
    }

    #[test]
    fn test_strtrim_values() {
        let mut s = "  hello  ".to_string();
        strtrim(&mut s);
        assert_eq!(s, "hello");
        let mut s2 = "\thello\t".to_string();
        strtrim(&mut s2);
        assert_eq!(s2, "hello");
    }

    #[test]
    fn test_hex_encode_values() {
        assert_eq!(hex_encode(&[0x0a, 0xff, 0x42]), "0aff42");
    }

    #[test]
    fn test_combined_canons_table() {
        assert_eq!(PDKIM_COMBINED_CANONS.len(), 6);
        assert_eq!(PDKIM_COMBINED_CANONS[0].str_repr, "simple/simple");
        assert_eq!(PDKIM_COMBINED_CANONS[3].str_repr, "relaxed/relaxed");
    }

    #[test]
    fn test_constants_values() {
        assert_eq!(PDKIM_DNS_TXT_MAX_RECLEN, 65536);
        assert_eq!(PDKIM_MAX_HEADER_LEN, 65536);
        assert_eq!(PDKIM_MAX_HEADERS, 512);
        assert_eq!(PDKIM_MAX_BODY_LINE_LEN, 16384);
        assert_eq!(PDKIM_DNS_TXT_MAX_NAMELEN, 1024);
        assert_eq!(PDKIM_SIGNATURE_VERSION, "1");
        assert_eq!(PDKIM_PUB_RECORD_VERSION, "DKIM1");
        assert_eq!(PDKIM_VERIFY_POLICY, 1 << 31);
    }

    #[test]
    fn test_hashes_table() {
        assert_eq!(PDKIM_HASHES.len(), 3);
        assert_eq!(PDKIM_HASHES[0].dkim_hashname, "sha1");
        assert_eq!(PDKIM_HASHES[1].dkim_hashname, "sha256");
        assert_eq!(PDKIM_HASHES[2].dkim_hashname, "sha512");
    }

    #[test]
    fn test_keytypes_table() {
        assert_eq!(PDKIM_KEYTYPES.len(), 2);
        assert_eq!(PDKIM_KEYTYPES[0], "rsa");
        assert_eq!(PDKIM_KEYTYPES[1], "ed25519");
    }

    #[test]
    fn test_init_verify_creates_context() {
        let ctx = init_verify(|_| None, true);
        assert!(!ctx.flags.contains(PdkimFlags::MODE_SIGN));
        assert!(ctx.flags.contains(PdkimFlags::DOT_TERM));
        assert!(ctx.dns_txt_callback.is_some());
    }

    #[test]
    fn test_init_sign_creates_signature() {
        let mut ctx = PdkimContext::new();
        let sig = init_sign(
            &mut ctx,
            "example.com",
            "selector",
            "test-privkey",
            "sha256",
        );
        assert!(sig.is_some());
        let sig = sig.unwrap();
        assert_eq!(sig.domain.as_deref(), Some("example.com"));
        assert_eq!(sig.selector.as_deref(), Some("selector"));
        assert_eq!(sig.hashtype, 1);
        assert_eq!(sig.keytype, 0);
    }

    #[test]
    fn test_init_sign_rejects_empty() {
        let mut ctx = PdkimContext::new();
        assert!(init_sign(&mut ctx, "", "sel", "key", "sha256").is_none());
        assert!(init_sign(&mut ctx, "d", "", "key", "sha256").is_none());
        assert!(init_sign(&mut ctx, "d", "sel", "", "sha256").is_none());
    }

    #[test]
    fn test_init_sign_rejects_bad_hash() {
        let mut ctx = PdkimContext::new();
        assert!(init_sign(&mut ctx, "d", "sel", "key", "md5").is_none());
    }

    #[test]
    fn test_set_optional_defaults() {
        let mut sig = PdkimSignature::default();
        set_optional(
            &mut sig,
            None,
            Some("user@example.com"),
            Canon::Relaxed,
            Canon::Relaxed,
            -1,
            1234567890,
            0,
        );
        assert_eq!(
            sig.sign_headers.as_deref(),
            Some(PDKIM_DEFAULT_SIGN_HEADERS)
        );
        assert_eq!(sig.identity.as_deref(), Some("user@example.com"));
        assert_eq!(sig.canon_headers, Canon::Relaxed);
        assert_eq!(sig.canon_body, Canon::Relaxed);
        assert_eq!(sig.created, 1234567890);
    }

    #[test]
    fn test_set_sig_bodyhash_links() {
        let mut ctx = PdkimContext::new();
        let mut sig = PdkimSignature::default();
        sig.hashtype = 1;
        sig.canon_body = Canon::Relaxed;
        sig.bodylength = -1;
        ctx.sig.push(sig);
        let bh_idx = set_sig_bodyhash(&mut ctx, 0).unwrap();
        assert_eq!(ctx.sig[0].calc_body_hash, Some(bh_idx));
        assert_eq!(ctx.bodyhash.len(), 1);
    }

    #[test]
    fn test_init_context_sets_flags() {
        let mut ctx = PdkimContext::new();
        init_context(&mut ctx, true, None);
        assert!(ctx.flags.contains(PdkimFlags::DOT_TERM));
        assert!(ctx.flags.contains(PdkimFlags::MODE_SIGN));
    }

    #[test]
    fn test_header_name_match_basic() {
        let mut list = "from:to:subject".to_string();
        assert!(header_name_match("From: test", &mut list, false));
        assert!(header_name_match("To: test", &mut list, false));
        assert!(!header_name_match("CC: test", &mut list, false));
    }

    #[test]
    fn test_header_name_match_tick() {
        let mut list = "from:to:subject".to_string();
        assert!(header_name_match("From: test", &mut list, true));
        assert!(!header_name_match("From: test2", &mut list, true));
        assert!(header_name_match("To: test", &mut list, true));
    }

    #[test]
    fn test_hash_context_hash_index() {
        let ctx_sha1 = HashContext::new_from_index(0).unwrap();
        assert_eq!(ctx_sha1.hash_index(), 0);
        let ctx_sha256 = HashContext::new_from_index(1).unwrap();
        assert_eq!(ctx_sha256.hash_index(), 1);
        let ctx_sha512 = HashContext::new_from_index(2).unwrap();
        assert_eq!(ctx_sha512.hash_index(), 2);
    }

    #[test]
    fn test_relax_header_n_with_limit() {
        let result = relax_header_n("Subject: Hello World Extra", 15, false);
        // Only first 15 chars: "Subject: Hello "
        assert_eq!(result, "subject:Hello");
    }

    #[test]
    fn test_keyname_to_keytype_values() {
        assert_eq!(keyname_to_keytype("rsa"), Some(0));
        assert_eq!(keyname_to_keytype("ed25519"), Some(1));
        assert_eq!(keyname_to_keytype("dsa"), None);
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = b"The quick brown fox jumps over the lazy dog";
        let encoded = encode_base64(original);
        let decoded = decode_base64(&encoded);
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_feed_header_mode_to_body() {
        let mut ctx = PdkimContext::new();
        ctx.flags.insert(PdkimFlags::MODE_SIGN);
        let mut sig = PdkimSignature::default();
        sig.keytype = 0;
        sig.hashtype = 1;
        ctx.sig.push(sig);

        // Feed a header followed by blank line (end of headers)
        let msg = b"From: test@example.com\r\n\r\n";
        let result = feed(&mut ctx, msg);
        assert_eq!(result, PdkimResult::Ok);
        assert!(ctx.flags.contains(PdkimFlags::PAST_HDRS));
    }

    #[test]
    fn test_bodyhash_simple_empty_body() {
        // With no body data and simple canon, the body hash should
        // be computed over a single CRLF per RFC 6376 §3.4.3
        let mut ctx = PdkimContext::new();
        ctx.flags.insert(PdkimFlags::PAST_HDRS);
        let bh_idx = set_bodyhash(&mut ctx, 1, Canon::Simple, -1).unwrap();
        assert_eq!(bh_idx, 0);
        body_complete(&mut ctx);
        assert!(ctx.flags.contains(PdkimFlags::SEEN_EOD));
    }

    #[test]
    fn test_set_sig_bodyhash_out_of_range() {
        let mut ctx = PdkimContext::new();
        assert!(set_sig_bodyhash(&mut ctx, 0).is_none());
        assert!(set_sig_bodyhash(&mut ctx, 100).is_none());
    }
}
