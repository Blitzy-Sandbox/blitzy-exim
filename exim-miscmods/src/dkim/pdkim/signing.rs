//! Crypto Backend for PDKIM DKIM signing and verification.
//!
//! Rewrites `src/src/miscmods/pdkim/signing.c` (919 lines) plus types from
//! `signing.h` (101 lines) and conditional compilation from `crypt_ver.h`
//! (35 lines) into safe Rust using pure-Rust cryptographic primitives from
//! the RustCrypto project (`rsa`, `ed25519-dalek`, `sha1`, `sha2`).
//!
//! All cryptographic operations execute in pure Rust — no unsafe code is
//! required (per AAP §0.7.2), and no FFI into GnuTLS / GCrypt / OpenSSL is
//! necessary for the DKIM hot path. C-library crypto remains available via
//! `exim-ffi` for other subsystems (TLS, Kerberos GSSAPI), but DKIM signing
//! and verification live entirely within memory-safe Rust.
//!
//! # Backend Selection (C → Rust mapping)
//!
//! The C implementation selected between three backends via preprocessor
//! conditionals in `crypt_ver.h`:
//! - **GnuTLS** (`SIGN_GNUTLS`): GnuTLS ≥3.0.0, Ed25519 with ≥3.6.0
//! - **GCrypt** (`SIGN_GCRYPT`): Legacy backend for pre-3.0.0 GnuTLS (RSA only)
//! - **OpenSSL** (`SIGN_OPENSSL`): OpenSSL ≥1.1.1 (non-LibreSSL) for Ed25519
//!
//! In the Rust rewrite, a single pure-Rust backend replaces all three:
//! - RSA-PKCS#1 v1.5 signing/verification: `rsa::pkcs1v15::SigningKey` /
//!   `rsa::pkcs1v15::VerifyingKey` parameterised over SHA-1, SHA-256, SHA-512.
//! - Ed25519 signing/verification: `ed25519_dalek::SigningKey` /
//!   `ed25519_dalek::VerifyingKey` (RFC 8032 / RFC 8463).
//! - PEM/DER key parsing: `rsa::pkcs1`, `rsa::pkcs8`, `spki` (transitive via
//!   `rsa`'s `encoding` feature) for RSA; `ed25519_dalek::pkcs8` for Ed25519.
//!
//! # Critical Behavioral Notes
//!
//! - **Ed25519** signs/verifies **raw data** (not pre-hashed) — the algorithm
//!   performs the internal SHA-512 hash as part of the Ed25519 computation.
//!   `hash_algo` is ignored for Ed25519.
//! - **RSA** signs/verifies **pre-hashed data** — the signer hashes the
//!   accumulated data internally, wraps in DigestInfo ASN.1, then applies
//!   PKCS#1 v1.5. The `hash_algo` parameter selects SHA-1 / SHA-256 / SHA-512.
//! - Signature mismatch (forgery or corruption) returns `Ok(false)` — distinct
//!   from backend failure which returns `Err(...)`. This matches C Exim's
//!   distinction between "" (mismatch) and non-empty error string.
//! - All debug/error logging uses `tracing` (replaces C `debug_printf`).
//! - Zero `unsafe` code in this file (enforced via `#![forbid(unsafe_code)]`).

// Per AAP §0.7.2: zero unsafe code in any crate except exim-ffi.
#![forbid(unsafe_code)]

use std::fmt;

use thiserror::Error;

// ── RustCrypto primitives for DKIM / ARC signing + verification ──────────
// All three crates below are pure-Rust and compatible with `#![forbid(unsafe_code)]`.
// Feature flags are declared in exim-miscmods/Cargo.toml and at the workspace root.
//
// The `Signer` / `Verifier` traits (from the `signature` crate) are brought
// into scope via the aliased imports below so that `.sign(data)` and
// `.verify(data, &sig)` method calls resolve correctly. We rename to
// `_Ed25519Signer` / `_Ed25519Verifier` because `rsa` also re-exports the
// same traits and the compiler would otherwise complain about the
// duplicate glob imports.

use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as _Ed25519Signer, SigningKey as Ed25519SigningKey,
    Verifier as _Ed25519Verifier, VerifyingKey as Ed25519VerifyingKey,
};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs1v15::{
    Signature as Pkcs1v15Signature, SigningKey as Pkcs1v15SigningKey,
    VerifyingKey as Pkcs1v15VerifyingKey,
};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
// `SignatureEncoding` exposes `to_bytes()` on signature values so we can
// serialize RSA signatures back to the wire format.
// The `Signer` / `Verifier` traits themselves come from the `signature`
// crate and are already in scope via the Ed25519 aliased imports above
// (both `rsa` and `ed25519_dalek` re-export the same `signature` traits).
use rsa::signature::SignatureEncoding;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

// =============================================================================
// HashAlgorithm — Digest algorithm selection
// =============================================================================

/// Hash algorithm used for DKIM signing and verification.
///
/// Maps the C `pdkim_hashtype` values and the hash algorithms supported
/// across the three crypto backends (GnuTLS `gnutls_digest_algorithm_t`,
/// GCrypt `gcry_md_algos`, OpenSSL `EVP_MD`).
///
/// The C source (`signing.c`) maps these to backend-specific constants:
/// - `HASH_SHA1`   → `GNUTLS_DIG_SHA1`   / `GCRY_MD_SHA1`   / `EVP_sha1()`
/// - `HASH_SHA256` → `GNUTLS_DIG_SHA256` / `GCRY_MD_SHA256` / `EVP_sha256()`
/// - `HASH_SHA512` → `GNUTLS_DIG_SHA512` / (not in GCrypt)  / `EVP_sha512()`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// SHA-1 (deprecated per RFC 8301, kept for verification compatibility).
    Sha1,
    /// SHA-256 (required by RFC 6376, the default and recommended hash).
    Sha256,
    /// SHA-512 (supported by GnuTLS and OpenSSL backends; not GCrypt).
    Sha512,
}

impl HashAlgorithm {
    /// Returns the DKIM algorithm name as used in `a=` tag (e.g., `"sha256"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }

    /// Returns the digest output size in bytes for this algorithm.
    pub fn digest_size(&self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    /// Parses a DKIM hash algorithm name (case-insensitive).
    ///
    /// Accepts both DKIM-style (`"sha256"`) and canonical forms (`"sha-256"`).
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "sha1" | "sha-1" => Some(Self::Sha1),
            "sha256" | "sha-256" => Some(Self::Sha256),
            "sha512" | "sha-512" => Some(Self::Sha512),
            _ => None,
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// =============================================================================
// KeyType — Cryptographic key type
// =============================================================================

/// Cryptographic key type for DKIM signing and verification.
///
/// Replaces the C `keytype` enum from `signing.h` lines 16–19:
/// ```c
/// enum keytype { KEYTYPE_RSA, KEYTYPE_ED25519 };
/// ```
///
/// Ed25519 support is conditionally available depending on the crypto
/// backend version:
/// - GnuTLS ≥3.6.0 (`SIGN_HAVE_ED25519` in `crypt_ver.h` lines 13–16)
/// - OpenSSL ≥1.1.1, non-LibreSSL (`crypt_ver.h` lines 26–32)
/// - GCrypt: Ed25519 NOT supported (RSA only)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum KeyType {
    /// RSA key — PKCS#1 v1.5 signing with configurable SHA hash.
    Rsa = 0,
    /// Ed25519 key — RFC 8463 Edwards-curve Digital Signature Algorithm.
    Ed25519 = 1,
}

impl KeyType {
    /// Returns the DKIM key type name as used in the DNS `k=` tag.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rsa => "rsa",
            Self::Ed25519 => "ed25519",
        }
    }

    /// Parses a DKIM key type name from a DNS `k=` tag value.
    ///
    /// Per RFC 6376 §3.6.1, the default key type is RSA when `k=` is absent.
    pub fn from_dns_tag(tag: &str) -> Option<Self> {
        match tag.to_ascii_lowercase().as_str() {
            "rsa" | "" => Some(Self::Rsa),
            "ed25519" => Some(Self::Ed25519),
            _ => None,
        }
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// =============================================================================
// KeyFormat — Public key encoding format
// =============================================================================

/// Public key format for DKIM verification.
///
/// Replaces the C `keyformat` enum from `signing.h` lines 21–24:
/// ```c
/// enum keyformat { KEYFMT_DER, KEYFMT_ED25519_BARE };
/// ```
///
/// RSA public keys are DER-encoded `SubjectPublicKeyInfo` structures.
/// Ed25519 public keys may be either DER-encoded or raw 32-byte values
/// depending on the DNS record format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum KeyFormat {
    /// DER-encoded `SubjectPublicKeyInfo` (RSA) or PKCS#8 wrapper.
    Der = 0,
    /// Raw 32-byte Ed25519 public key without ASN.1 wrapping.
    Ed25519Bare = 1,
}

// =============================================================================
// SigningError — Cryptographic operation errors
// =============================================================================

/// Errors from DKIM cryptographic operations.
///
/// Replaces ad-hoc error handling via return codes and string messages from
/// `signing.c` functions:
/// - `exim_dkim_signing_init` returning `NULL` on failure
/// - `exim_dkim_sign`/`exim_dkim_verify` returning error strings
/// - Empty string `""` from verify indicating signature mismatch (not error)
///
/// Each variant corresponds to a distinct failure mode across the three C
/// backend implementations (GnuTLS, GCrypt, OpenSSL).
#[derive(Debug, Error)]
pub enum SigningError {
    /// Private key import failed during [`signing_init`].
    ///
    /// Replaces:
    /// - GnuTLS: `gnutls_x509_privkey_import_pkcs8_raw` failure
    /// - GCrypt: PEM parse / ASN.1 DER walk failure
    /// - OpenSSL: `PEM_read_bio_PrivateKey` failure
    #[error("Private key import failed: {0}")]
    PrivateKeyImportFailed(String),

    /// Public key import failed during [`verify_init`].
    ///
    /// Replaces:
    /// - GnuTLS: `gnutls_pubkey_import` / `gnutls_pubkey_import_ecc_raw` failure
    /// - GCrypt: ASN.1 SubjectPublicKeyInfo parse failure
    /// - OpenSSL: `d2i_PUBKEY` / `EVP_PKEY_new_raw_public_key` failure
    #[error("Public key import failed: {0}")]
    PublicKeyImportFailed(String),

    /// Signing operation failed.
    ///
    /// Replaces:
    /// - GnuTLS: `gnutls_privkey_sign_data` / `gnutls_privkey_sign_hash` failure
    /// - GCrypt: `gcry_pk_sign` failure
    /// - OpenSSL: `EVP_DigestSign` / `EVP_DigestSignFinal` failure
    #[error("Signing operation failed: {0}")]
    SigningFailed(String),

    /// Verification operation failed.
    ///
    /// Replaces:
    /// - GnuTLS: `gnutls_pubkey_verify_data2` / `gnutls_pubkey_verify_hash2` failure
    /// - GCrypt: `gcry_pk_verify` failure
    /// - OpenSSL: `EVP_DigestVerify` / `EVP_PKEY_verify` failure
    #[error("Verification operation failed: {0}")]
    VerificationFailed(String),

    /// The requested key type is not supported by the active crypto backend.
    ///
    /// Typically: Ed25519 requested but backend lacks support
    /// (GCrypt has no Ed25519, GnuTLS <3.6.0, LibreSSL).
    #[error("Unsupported key type")]
    UnsupportedKeyType,

    /// Error from the FFI crypto backend layer.
    ///
    /// Wraps errors returned by `exim-ffi` crypto functions when the
    /// backend reports an internal failure.
    #[error("FFI error: {0}")]
    FfiError(String),

    /// Data append to signing/verification context failed.
    ///
    /// This is a memory allocation failure during data accumulation,
    /// replacing the C `string_cat` allocation failure path.
    #[error("Data append failed")]
    DataAppendFailed,
}

// =============================================================================
// Internal Crypto Handle Types
// =============================================================================
//
// These types abstract the cryptographic state. In the C implementation, three
// backends (GnuTLS, GCrypt, OpenSSL) maintained their own opaque objects:
// - GnuTLS: `gnutls_privkey_t` / `gnutls_pubkey_t`
// - GCrypt: raw MPI values (n, e, d, p, q, dp, dq, qp for signing; n, e for verify)
// - OpenSSL: `EVP_PKEY*`
//
// In the Rust rewrite, the handles hold already-parsed RustCrypto key objects.
// This means key parsing happens once (at `signing_init` / `verify_init`),
// and subsequent `sign()` / `verify()` calls reuse the parsed key — matching
// the C Exim behavior where `exim_dkim_signing_init` imports the key once.
//
// The handles are RAII resources: they own the parsed key objects and release
// them on drop. Rust's ownership system provides automatic cleanup (no
// explicit `gnutls_privkey_deinit` / `EVP_PKEY_free` needed).

/// Parsed private key used for signing.
///
/// Mirrors the C `es_ctx` union-like state, which held either RSA MPIs
/// (GCrypt) or an opaque `gnutls_privkey_t` / `EVP_PKEY*` handle.
/// Here the enum explicitly encodes the two supported algorithms, satisfying
/// compile-time exhaustiveness checks in `crypto_sign`.
enum ParsedSigningKey {
    /// PKCS#1 v1.5 RSA private key (modulus + private exponent + optional
    /// CRT parameters). Parsed from PEM / DER via `rsa::RsaPrivateKey`.
    Rsa(RsaPrivateKey),
    /// Ed25519 private seed (32 bytes) expanded into a full signing key.
    /// Parsed from PKCS#8 PEM via `ed25519_dalek::SigningKey`.
    Ed25519(Ed25519SigningKey),
}

/// Parsed public key used for verification.
///
/// Same design rationale as [`ParsedSigningKey`]: encode the algorithm
/// choice in the enum discriminator so `crypto_verify` is exhaustive and
/// can dispatch without runtime type checks.
enum ParsedVerifyKey {
    /// RSA public key (modulus + public exponent). Parsed from PKCS#1 DER
    /// or from a DER-encoded `SubjectPublicKeyInfo` (SPKI) container.
    Rsa(RsaPublicKey),
    /// Ed25519 public key (compressed Edwards point, 32 bytes). Parsed
    /// either from raw bare bytes (DKIM DNS `p=` tag format per RFC 8463)
    /// or from a DER-encoded `SubjectPublicKeyInfo`.
    Ed25519(Ed25519VerifyingKey),
}

/// Handle wrapping a parsed private key for signing operations.
///
/// In the C implementation, this corresponds to the `es_ctx` struct which
/// had three conditional variants (`signing.h` lines 29–54). In Rust, all
/// three are unified under the [`ParsedSigningKey`] enum which explicitly
/// encodes the algorithm choice.
struct CryptoSigningHandle {
    /// The parsed private key material, ready for immediate signing use.
    parsed_key: ParsedSigningKey,
    /// The detected key type after importing the private key.
    /// Derived from which `ParsedSigningKey` variant was constructed.
    detected_key_type: KeyType,
    /// Whether the handle has been successfully initialized with key material.
    initialized: bool,
}

/// Handle wrapping a parsed public key for verification operations.
///
/// In the C implementation, this corresponds to the `ev_ctx` struct which
/// had three conditional variants (`signing.h` lines 57–93). In Rust, all
/// three are unified under the [`ParsedVerifyKey`] enum.
struct CryptoVerifyHandle {
    /// The parsed public key material, ready for immediate verification use.
    parsed_key: ParsedVerifyKey,
    /// The format of the imported public key (DER SPKI or bare Ed25519).
    /// Retained for diagnostic / debug output.
    key_format: KeyFormat,
    /// The detected key type (RSA or Ed25519).
    detected_key_type: KeyType,
    /// Precise number of bits in the public key.
    ///
    /// For RSA, this is the bit-length of the modulus (computed via
    /// `RsaPublicKey::n().bits()`). For Ed25519, this is always 256.
    /// Used for enforcing `dkim_verify_min_keysizes` config policy per
    /// `src/src/miscmods/dkim.c`'s minimum-keysize check.
    key_bits: u32,
    /// Whether the handle has been successfully initialized.
    initialized: bool,
}

// =============================================================================
// Internal crypto backend functions
// =============================================================================
//
// These functions implement the crypto backend abstraction layer. In the full
// system, they delegate to `exim_ffi::crypto_*` functions which wrap the
// chosen C crypto library (GnuTLS/GCrypt/OpenSSL) behind safe Rust interfaces.
//
// Current implementation provides the complete initialization, validation, and
// data-flow logic. The actual cryptographic primitive operations (modular
// exponentiation for RSA, curve arithmetic for Ed25519) require the exim-ffi
// crypto module to be populated with backend bindings.

/// One-time crypto backend initialization.
///
/// Replaces:
/// - GnuTLS (`signing.c` lines 71–82): `gnutls_global_init()` +
///   `gnutls_global_set_log_function(exim_gnutls_logger_cb)` +
///   `gnutls_global_set_log_level(EXIM_GNUTLS_LIBRARY_LOG_LEVEL)`
/// - GCrypt (`signing.c` lines 312–346): `gcry_check_version(NULL)` +
///   `gcry_set_log_handler()` + `gcry_control(GCRYCTL_INIT_SECMEM, 16384)` +
///   `gcry_control(GCRYCTL_INITIALIZATION_FINISHED)`
/// - OpenSSL (`signing.c` lines 714–718): `ERR_load_crypto_strings()` +
///   `OpenSSL_add_all_algorithms()`
fn crypto_init() -> Result<(), String> {
    // In C, the GnuTLS logger callback (`exim_gnutls_logger_cb`,
    // signing.c lines 55–66) routes GnuTLS debug messages to Exim's
    // debug_printf. In Rust, tracing handles this automatically —
    // the exim-ffi backend configures the C library's logging to route
    // through tracing during initialization.
    tracing::debug!("PDKIM: crypto backend initialization");
    Ok(())
}

/// Import a PEM-encoded private key and create a signing handle.
///
/// Parses the PEM into a typed [`ParsedSigningKey`] (RSA or Ed25519) via the
/// RustCrypto `rsa` / `ed25519-dalek` PEM decoders. Once parsed, subsequent
/// calls to [`crypto_sign`] reuse the in-memory key without re-parsing.
///
/// Replaces the key import logic in:
/// - GnuTLS (`signing.c` lines 97–126): `gnutls_x509_privkey_init()` +
///   `gnutls_x509_privkey_import_pkcs8_raw()` + key type detection via
///   `gnutls_privkey_get_pk_algorithm()`
/// - GCrypt (`signing.c` lines 366–486): Manual PEM header stripping,
///   base64 decode, ASN.1 DER sequence walking to extract 8 RSA MPIs
/// - OpenSSL (`signing.c` lines 733–750): `BIO_new_mem_buf()` +
///   `PEM_read_bio_PrivateKey()` + `EVP_PKEY_get_id()` for type detection
///
/// # Key-format support
///
/// **RSA**: PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`) is attempted first
/// (via [`RsaPrivateKey::from_pkcs1_pem`]). If that fails, PKCS#8
/// (`-----BEGIN PRIVATE KEY-----`) is attempted (via
/// [`RsaPrivateKey::from_pkcs8_pem`]). Encrypted PEM is NOT supported —
/// the DKIM key must be plaintext (matching C Exim behavior where
/// `exim_dkim_signing_init` does not prompt for a password).
///
/// **Ed25519**: PKCS#8 (`-----BEGIN PRIVATE KEY-----`) via
/// [`Ed25519SigningKey::from_pkcs8_pem`]. Raw 32-byte seed material
/// in pure base64 form without PEM markers is also accepted.
fn crypto_signing_init(
    privkey_pem: &str,
    _key_type_hint: u32,
    _hash_hint: u32,
) -> Result<CryptoSigningHandle, String> {
    if privkey_pem.is_empty() {
        return Err("empty private key data".to_string());
    }

    // Validate PEM structure: must contain BEGIN/END markers or be raw base64.
    let trimmed = privkey_pem.trim();
    let has_pem_markers = trimmed.contains("-----BEGIN") && trimmed.contains("-----END");
    let has_content = if has_pem_markers {
        // Check that there's base64 content between markers
        let mut found_content = false;
        let mut in_body = false;
        for line in trimmed.lines() {
            let l = line.trim();
            if l.starts_with("-----BEGIN") {
                in_body = true;
                continue;
            }
            if l.starts_with("-----END") {
                break;
            }
            if in_body && !l.is_empty() {
                found_content = true;
                break;
            }
        }
        found_content
    } else {
        // Raw base64 without PEM markers — check non-empty after whitespace removal
        trimmed
            .chars()
            .any(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    };

    if !has_content {
        return Err("private key PEM contains no key material".to_string());
    }

    // Preliminary key-type detection from PEM markers. This is a HINT used
    // to pick the initial parse strategy; if it misidentifies, we fall
    // through all parsers before giving up.
    let hinted_key_type = detect_key_type_from_pem(trimmed);

    // Attempt to parse the PEM as each supported private-key format.
    // The order depends on the hint to minimise false-negatives in logs:
    // - If the PEM headers say "ED25519" or "PRIVATE KEY" with short body,
    //   try Ed25519 first.
    // - Otherwise try RSA PKCS#1, then RSA PKCS#8, then Ed25519 PKCS#8 as
    //   a last-resort fallback.
    let (parsed_key, detected_key_type) = match hinted_key_type {
        KeyType::Ed25519 => {
            // Try Ed25519 PKCS#8 first.
            match parse_ed25519_signing_key(trimmed) {
                Ok(sk) => (ParsedSigningKey::Ed25519(sk), KeyType::Ed25519),
                Err(e_ed) => {
                    // Fall back to RSA in case the heuristic was wrong.
                    match parse_rsa_private_key(trimmed) {
                        Ok(rk) => (ParsedSigningKey::Rsa(rk), KeyType::Rsa),
                        Err(e_rsa) => {
                            return Err(format!(
                                "private key PEM could not be parsed as \
                                 Ed25519 ({e_ed}) or RSA ({e_rsa})"
                            ));
                        }
                    }
                }
            }
        }
        KeyType::Rsa => {
            // Try RSA (PKCS#1 then PKCS#8) first.
            match parse_rsa_private_key(trimmed) {
                Ok(rk) => (ParsedSigningKey::Rsa(rk), KeyType::Rsa),
                Err(e_rsa) => {
                    // Fall back to Ed25519 in case heuristic was wrong.
                    match parse_ed25519_signing_key(trimmed) {
                        Ok(sk) => (ParsedSigningKey::Ed25519(sk), KeyType::Ed25519),
                        Err(e_ed) => {
                            return Err(format!(
                                "private key PEM could not be parsed as \
                                 RSA ({e_rsa}) or Ed25519 ({e_ed})"
                            ));
                        }
                    }
                }
            }
        }
    };

    tracing::debug!(
        key_type = %detected_key_type,
        pem_len = trimmed.len(),
        "PDKIM: imported private key for signing"
    );

    Ok(CryptoSigningHandle {
        parsed_key,
        detected_key_type,
        initialized: true,
    })
}

/// Parse an RSA private key from PEM, trying PKCS#1 then PKCS#8.
///
/// PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`) is the traditional Exim
/// format generated by older `openssl genrsa` invocations. PKCS#8
/// (`-----BEGIN PRIVATE KEY-----`) is the modern default for
/// `openssl genpkey -algorithm RSA`. Both are fully supported.
fn parse_rsa_private_key(pem: &str) -> Result<RsaPrivateKey, String> {
    match RsaPrivateKey::from_pkcs1_pem(pem) {
        Ok(k) => Ok(k),
        Err(e_pkcs1) => match RsaPrivateKey::from_pkcs8_pem(pem) {
            Ok(k) => Ok(k),
            Err(e_pkcs8) => Err(format!(
                "PKCS#1 parse failed ({e_pkcs1}), PKCS#8 parse failed ({e_pkcs8})"
            )),
        },
    }
}

/// Parse an Ed25519 signing key from PEM (PKCS#8).
///
/// RFC 8410 / RFC 8032 Ed25519 keys are always stored in PKCS#8 format
/// with the OID `1.3.101.112`. The `ed25519-dalek` crate's PKCS#8
/// decoder handles both unencrypted and the variant with explicit
/// Ed25519 algorithm identifier.
fn parse_ed25519_signing_key(pem: &str) -> Result<Ed25519SigningKey, String> {
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    Ed25519SigningKey::from_pkcs8_pem(pem).map_err(|e| format!("Ed25519 PKCS#8 parse failed: {e}"))
}

/// Detect the key type from an initialized signing handle.
///
/// After key import, the backend knows whether the key is RSA or Ed25519.
/// This function queries that detected type.
fn crypto_detect_key_type(handle: &CryptoSigningHandle) -> Result<KeyType, String> {
    if !handle.initialized {
        return Err("signing handle not initialized".to_string());
    }
    Ok(handle.detected_key_type)
}

/// Perform the signing operation on accumulated data using the handle's key.
///
/// The behavior differs critically by key type:
/// - **Ed25519**: Signs raw data directly — the Ed25519 algorithm internally
///   performs SHA-512 hashing as part of the signature computation
///   (RFC 8032 §5.1.6). The resulting signature is always exactly 64 bytes.
///   (GnuTLS: `gnutls_privkey_sign_data`, OpenSSL: `EVP_DigestSign` with
///   NULL md.)
/// - **RSA**: The `rsa::pkcs1v15::SigningKey<H>` type (where `H` is the
///   hash algorithm generic parameter) internally hashes the data with the
///   specified algorithm, wraps the hash in the DigestInfo ASN.1 structure,
///   applies PKCS#1 v1.5 padding, and produces the signature via RSA
///   modular exponentiation. The resulting signature length equals
///   `key_bits / 8` bytes (e.g. 256 bytes for 2048-bit RSA).
///   (GnuTLS: `gnutls_privkey_sign_hash`, GCrypt: `gcry_md_hash_buffer` +
///   `gcry_pk_sign`, OpenSSL: `EVP_DigestSignInit/Update/Final`.)
///
/// # Arguments
///
/// * `handle` — Previously initialized signing handle holding the parsed key.
/// * `data` — Canonicalized data to sign (DKIM header canonicalization output
///   or ARC-AMS canonicalization output, depending on caller).
/// * `_key_type` — Redundant key-type hint (already known from the handle).
///   Retained in signature for C-API parity.
/// * `hash_algo` — Hash algorithm selector. For RSA this controls the
///   `DigestInfo` OID written into the signature. For Ed25519 it is ignored
///   (Ed25519 always uses SHA-512 internally).
///
/// # Returns
///
/// Raw signature bytes. For RSA this is `key_bits / 8` bytes. For Ed25519
/// this is exactly 64 bytes.
fn crypto_sign(
    handle: &CryptoSigningHandle,
    data: &[u8],
    _key_type: u32,
    hash_algo: u32,
) -> Result<Vec<u8>, String> {
    if !handle.initialized {
        return Err("signing handle not initialized".to_string());
    }
    if data.is_empty() {
        return Err("no data to sign".to_string());
    }

    // Map the numeric u32 hash-algo tag back to the typed enum. Unknown
    // values default to SHA-256 (the most common DKIM hash).
    let hash = match hash_algo {
        h if h == HashAlgorithm::Sha1 as u32 => HashAlgorithm::Sha1,
        h if h == HashAlgorithm::Sha512 as u32 => HashAlgorithm::Sha512,
        _ => HashAlgorithm::Sha256,
    };

    tracing::debug!(
        key_type = %handle.detected_key_type,
        hash_algo = %hash,
        data_len = data.len(),
        "PDKIM: performing signing operation"
    );

    match &handle.parsed_key {
        ParsedSigningKey::Rsa(priv_key) => {
            // RSA-PKCS#1-v1.5 dispatch by hash algorithm. Each branch uses
            // a typed `SigningKey<H>` where `H` is the hash type, so the
            // compiler monomorphizes away the dispatch.
            match hash {
                HashAlgorithm::Sha1 => {
                    let signing_key = Pkcs1v15SigningKey::<Sha1>::new(priv_key.clone());
                    let sig: Pkcs1v15Signature = signing_key.sign(data);
                    Ok(sig.to_bytes().into_vec())
                }
                HashAlgorithm::Sha256 => {
                    let signing_key = Pkcs1v15SigningKey::<Sha256>::new(priv_key.clone());
                    let sig: Pkcs1v15Signature = signing_key.sign(data);
                    Ok(sig.to_bytes().into_vec())
                }
                HashAlgorithm::Sha512 => {
                    let signing_key = Pkcs1v15SigningKey::<Sha512>::new(priv_key.clone());
                    let sig: Pkcs1v15Signature = signing_key.sign(data);
                    Ok(sig.to_bytes().into_vec())
                }
            }
        }
        ParsedSigningKey::Ed25519(sk) => {
            // Ed25519 signs the raw data. The 64-byte signature (R || S) is
            // deterministic per RFC 8032 — no RNG consumed.
            let sig: Ed25519Signature = sk.sign(data);
            Ok(sig.to_bytes().to_vec())
        }
    }
}

/// Import a public key and create a verification handle.
///
/// Parses the wire-format public key bytes into a typed [`ParsedVerifyKey`]
/// (RSA or Ed25519). For RSA, the input is a DER-encoded
/// `SubjectPublicKeyInfo` (SPKI) — the standard DKIM `p=` tag format per
/// RFC 6376 §3.6.1. For Ed25519, the input is either a 32-byte bare point
/// per RFC 8463 §3.1 or a DER-encoded SPKI.
///
/// Returns the handle and the **actual** number of key bits (measured from
/// the parsed modulus for RSA, fixed at 256 for Ed25519). The returned
/// bit-count is used to enforce the `dkim_verify_min_keysizes` config
/// policy, so it MUST be accurate — not an estimate.
///
/// Replaces:
/// - GnuTLS (`signing.c` lines 172–203):
///   - DER: `gnutls_pubkey_import(pubkey, DER)`
///   - Ed25519 bare: `gnutls_pubkey_import_ecc_raw(GNUTLS_ECC_CURVE_ED25519, x, NULL)`
/// - GCrypt (`signing.c` lines 570–651):
///   - ASN.1 DER parsing of SubjectPublicKeyInfo to extract RSA n, e MPIs
///   - key_bits = `gcry_mpi_get_nbits(n)`
/// - OpenSSL (`signing.c` lines 816–844):
///   - DER: `d2i_PUBKEY(der_data)`
///   - Ed25519 bare: `EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, raw, 32)`
///   - key_bits = `EVP_PKEY_get_bits()`
fn crypto_verify_init(
    pubkey_data: &[u8],
    key_type: u32,
    key_format: u32,
) -> Result<(CryptoVerifyHandle, u32), String> {
    if pubkey_data.is_empty() {
        return Err("empty public key data".to_string());
    }

    let detected_key_type = if key_type == KeyType::Ed25519 as u32 {
        KeyType::Ed25519
    } else {
        KeyType::Rsa
    };

    let fmt = if key_format == KeyFormat::Ed25519Bare as u32 {
        KeyFormat::Ed25519Bare
    } else {
        KeyFormat::Der
    };

    // Validate Ed25519 bare key size up-front.
    if fmt == KeyFormat::Ed25519Bare && pubkey_data.len() != 32 {
        return Err(format!(
            "Ed25519 bare public key must be exactly 32 bytes, got {}",
            pubkey_data.len()
        ));
    }

    // Parse the wire-format bytes into a typed key object. The resulting
    // `key_bits` is computed from the parsed key (accurate), NOT estimated
    // from the DER length.
    let (parsed_key, key_bits) = match (detected_key_type, fmt) {
        (KeyType::Ed25519, KeyFormat::Ed25519Bare) => {
            // 32 raw bytes = compressed Edwards point.
            let bytes: [u8; 32] = pubkey_data.try_into().map_err(|_| {
                format!(
                    "Ed25519 bare public key must be 32 bytes (got {})",
                    pubkey_data.len()
                )
            })?;
            let vk = Ed25519VerifyingKey::from_bytes(&bytes)
                .map_err(|e| format!("invalid Ed25519 public key point: {e}"))?;
            (ParsedVerifyKey::Ed25519(vk), 256u32)
        }
        (KeyType::Ed25519, KeyFormat::Der) => {
            // DER-encoded SubjectPublicKeyInfo for Ed25519.
            use ed25519_dalek::pkcs8::DecodePublicKey;
            let vk = Ed25519VerifyingKey::from_public_key_der(pubkey_data)
                .map_err(|e| format!("Ed25519 SPKI DER parse failed: {e}"))?;
            (ParsedVerifyKey::Ed25519(vk), 256u32)
        }
        (KeyType::Rsa, _) => {
            // DKIM RSA public keys are stored in DNS as base64-encoded
            // SubjectPublicKeyInfo. RFC 6376 §3.6.1 permits either raw
            // RSAPublicKey (PKCS#1) or SPKI — try SPKI first (the common
            // case), fall back to PKCS#1.
            let pk = match RsaPublicKey::from_public_key_der(pubkey_data) {
                Ok(k) => k,
                Err(e_spki) => RsaPublicKey::from_pkcs1_der(pubkey_data).map_err(|e_pkcs1| {
                    format!("RSA SPKI parse failed ({e_spki}), PKCS#1 parse failed ({e_pkcs1})")
                })?,
            };
            // Real modulus bit-length — not an estimate.
            let bits = pk.n().bits() as u32;
            (ParsedVerifyKey::Rsa(pk), bits)
        }
    };

    tracing::debug!(
        key_type = %detected_key_type,
        key_format = ?fmt,
        key_bits = key_bits,
        data_len = pubkey_data.len(),
        "PDKIM: imported public key for verification"
    );

    let handle = CryptoVerifyHandle {
        parsed_key,
        key_format: fmt,
        detected_key_type,
        key_bits,
        initialized: true,
    };

    Ok((handle, key_bits))
}

/// Verify a signature against accumulated data using the handle's public key.
///
/// The behavior differs by key type (critical distinction):
/// - **Ed25519**: Verifies against raw data. The Ed25519 algorithm internally
///   hashes with SHA-512.
///   (GnuTLS: `gnutls_pubkey_verify_data2`, signing.c line 230;
///   OpenSSL: `EVP_DigestVerify` with NULL md, signing.c line 893)
/// - **RSA**: The `rsa::pkcs1v15::VerifyingKey<H>` type hashes the data
///   with the specified algorithm, extracts the hash from the signature's
///   DigestInfo (after RSA decryption), and performs constant-time
///   comparison.
///   (GnuTLS: `gnutls_pubkey_verify_hash2`, signing.c line 233;
///   GCrypt: `gcry_pk_verify`, signing.c line 698;
///   OpenSSL: `EVP_PKEY_verify` with PKCS1 padding, signing.c line 907)
///
/// # Return semantics
///
/// - `Ok(true)` — Signature is cryptographically valid for the provided data.
/// - `Ok(false)` — Signature does not verify. This is the expected outcome
///   for forged, truncated, or wrong-key signatures. The C code returns
///   the empty string `""` in this case, which callers distinguish from
///   a genuine error. In Rust we distinguish via `Ok(false)` vs `Err`.
/// - `Err(...)` — Processing error (malformed signature bytes that cannot be
///   parsed at all, uninitialized handle, etc.). Callers should treat this
///   as a "temperror" per DKIM's `Status: Temperror` semantics.
fn crypto_verify(
    handle: &CryptoVerifyHandle,
    data: &[u8],
    signature: &[u8],
    _key_type: u32,
    hash_algo: u32,
) -> Result<bool, String> {
    if !handle.initialized {
        return Err("verification handle not initialized".to_string());
    }
    if data.is_empty() {
        return Err("no data to verify".to_string());
    }
    if signature.is_empty() {
        return Err("no signature bytes to verify".to_string());
    }

    let hash = match hash_algo {
        h if h == HashAlgorithm::Sha1 as u32 => HashAlgorithm::Sha1,
        h if h == HashAlgorithm::Sha512 as u32 => HashAlgorithm::Sha512,
        _ => HashAlgorithm::Sha256,
    };

    tracing::debug!(
        key_type = %handle.detected_key_type,
        key_format = ?handle.key_format,
        hash_algo = %hash,
        data_len = data.len(),
        sig_len = signature.len(),
        key_bits = handle.key_bits,
        "PDKIM: performing verification operation"
    );

    match &handle.parsed_key {
        ParsedVerifyKey::Rsa(pub_key) => {
            // PKCS#1 v1.5 RSA signatures are exactly key_bits/8 bytes long.
            // Length mismatch indicates the signature bytes came from a
            // different key or were corrupted — treat as a mismatch
            // (Ok(false)), not an error.
            let expected_len = (handle.key_bits as usize).div_ceil(8);
            if signature.len() != expected_len {
                tracing::debug!(
                    sig_len = signature.len(),
                    expected_len = expected_len,
                    "RSA signature length does not match key modulus size"
                );
                return Ok(false);
            }

            // Parse the signature bytes into the typed Signature struct.
            // A parse failure here is a malformed signature, NOT a
            // cryptographic mismatch — return Ok(false) so DKIM marks
            // the signature as "fail" rather than "temperror".
            let sig = match Pkcs1v15Signature::try_from(signature) {
                Ok(s) => s,
                Err(_) => return Ok(false),
            };

            let verified = match hash {
                HashAlgorithm::Sha1 => {
                    let vk = Pkcs1v15VerifyingKey::<Sha1>::new(pub_key.clone());
                    vk.verify(data, &sig).is_ok()
                }
                HashAlgorithm::Sha256 => {
                    let vk = Pkcs1v15VerifyingKey::<Sha256>::new(pub_key.clone());
                    vk.verify(data, &sig).is_ok()
                }
                HashAlgorithm::Sha512 => {
                    let vk = Pkcs1v15VerifyingKey::<Sha512>::new(pub_key.clone());
                    vk.verify(data, &sig).is_ok()
                }
            };
            Ok(verified)
        }
        ParsedVerifyKey::Ed25519(vk) => {
            // Ed25519 signatures are exactly 64 bytes.
            if signature.len() != 64 {
                tracing::debug!(
                    sig_len = signature.len(),
                    "Ed25519 signature length must be exactly 64 bytes"
                );
                return Ok(false);
            }
            let bytes: [u8; 64] = match signature.try_into() {
                Ok(b) => b,
                Err(_) => return Ok(false),
            };
            let sig = Ed25519Signature::from_bytes(&bytes);
            Ok(vk.verify(data, &sig).is_ok())
        }
    }
}

/// Release backend resources owned by a signing handle.
///
/// Replaces:
/// - GnuTLS: `gnutls_privkey_deinit()` + `gnutls_x509_privkey_deinit()`
/// - GCrypt: `gcry_sexp_release()` on key + `gcry_mpi_release()` on all MPIs
/// - OpenSSL: `EVP_PKEY_free()`
///
/// In the Rust implementation the parsed key object
/// ([`ParsedSigningKey`]) is automatically dropped when the handle itself
/// is dropped — the underlying `RsaPrivateKey` (which uses `num-bigint-dig`
/// with `zeroize`-on-drop for its secret components) and
/// `Ed25519SigningKey` (which uses `zeroize`-on-drop for its secret scalar)
/// both implement `Zeroize` / `ZeroizeOnDrop`. This function simply marks
/// the handle as released and emits a trace event for parity with the C API.
fn crypto_signing_cleanup(handle: &mut CryptoSigningHandle) -> Result<(), String> {
    handle.initialized = false;
    tracing::debug!("PDKIM: signing handle resources released");
    Ok(())
}

/// Release backend resources owned by a verification handle.
///
/// Replaces:
/// - GnuTLS: `gnutls_pubkey_deinit()`
/// - GCrypt: `gcry_mpi_release()` on n, e
/// - OpenSSL: `EVP_PKEY_free()`
///
/// Public keys contain no secret material, so no zeroization is required;
/// the parsed `RsaPublicKey` / `Ed25519VerifyingKey` is dropped with the
/// handle. This function simply marks the handle as released.
fn crypto_verify_cleanup(handle: &mut CryptoVerifyHandle) -> Result<(), String> {
    handle.initialized = false;
    tracing::debug!("PDKIM: verification handle resources released");
    Ok(())
}

/// Returns a human-readable name for the active crypto backend.
///
/// Used in diagnostic output (replaces backend-specific version strings
/// from the C code).
fn crypto_backend_name() -> &'static str {
    // In the full system, this returns the actual backend name:
    // - "GnuTLS" (with version from gnutls_check_version)
    // - "GCrypt" (with version from gcry_check_version)
    // - "OpenSSL" (with version from OpenSSL_version)
    "rust-crypto"
}

// =============================================================================
// SigningContext — Signing operation state
// =============================================================================

/// DKIM signing context wrapping backend-specific cryptographic state.
///
/// Replaces the C `es_ctx` struct from `signing.h` which has three
/// conditional definitions for GnuTLS, GCrypt, and OpenSSL backends.
///
/// The context accumulates message data via [`data_append`](Self::data_append)
/// (matching the C `exim_dkim_data_append` function which uses `string_cat`),
/// then produces a signature via the [`sign`] function.
///
/// Resources are released automatically via [`Drop`].
pub struct SigningContext {
    /// Opaque handle to the backend-specific signing state.
    inner: CryptoSigningHandle,
    /// The key type detected during initialization.
    pub key_type: KeyType,
    /// The hash algorithm selected for this signing operation.
    pub hash_algo: HashAlgorithm,
    /// Accumulated data buffer for signing.
    ///
    /// Replaces the `gstring` accumulator used in all three C backends.
    /// Data is appended via `data_append()` (the C `string_cat` pattern)
    /// and consumed by `sign()`.
    data_buffer: Vec<u8>,
}

impl SigningContext {
    /// Append data to the signing accumulation buffer.
    ///
    /// Replaces `exim_dkim_data_append()` from all three C backends:
    /// - GnuTLS (`signing.c` lines 86–90): `string_cat(hdata, dkim_data)`
    /// - GCrypt (`signing.c` lines 354–358): `string_cat(hdata, dkim_data)`
    /// - OpenSSL (`signing.c` lines 723–727): `string_cat(hdata, dkim_data)`
    ///
    /// All three backends perform identical buffer concatenation.
    pub fn data_append(&mut self, data: &[u8]) {
        self.data_buffer.extend_from_slice(data);
    }

    /// Returns the number of bytes currently accumulated.
    pub fn accumulated_len(&self) -> usize {
        self.data_buffer.len()
    }

    /// Clears the accumulated data buffer without releasing the context.
    pub fn clear_buffer(&mut self) {
        self.data_buffer.clear();
    }
}

impl Drop for SigningContext {
    /// Release all backend resources owned by this signing context.
    ///
    /// Delegates to the internal cleanup function which handles:
    /// - GnuTLS: `gnutls_privkey_deinit` + `gnutls_x509_privkey_deinit`
    /// - GCrypt: `gcry_sexp_release` on key, `gcry_mpi_release` on all MPIs
    /// - OpenSSL: `EVP_PKEY_free`
    fn drop(&mut self) {
        let _ = crypto_signing_cleanup(&mut self.inner);
        // Clear accumulated data
        self.data_buffer.clear();
    }
}

impl fmt::Debug for SigningContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningContext")
            .field("key_type", &self.key_type)
            .field("hash_algo", &self.hash_algo)
            .field("buffer_len", &self.data_buffer.len())
            .field("initialized", &self.inner.initialized)
            .finish()
    }
}

// =============================================================================
// VerificationContext — Verification operation state
// =============================================================================

/// DKIM verification context wrapping backend-specific cryptographic state.
///
/// Replaces the C `ev_ctx` struct from `signing.h` which has three
/// conditional definitions for GnuTLS, GCrypt, and OpenSSL backends.
///
/// The context accumulates message data via [`data_append`](Self::data_append),
/// then verifies a signature via the [`verify`] function.
///
/// Resources are released automatically via [`Drop`].
pub struct VerificationContext {
    /// Opaque handle to the backend-specific verification state.
    inner: CryptoVerifyHandle,
    /// The key type detected during initialization.
    pub key_type: KeyType,
    /// The hash algorithm to use for verification.
    pub hash_algo: HashAlgorithm,
    /// Accumulated data buffer for verification.
    ///
    /// Replaces the `gstring` accumulator used in all three C backends.
    data_buffer: Vec<u8>,
}

impl VerificationContext {
    /// Append data to the verification accumulation buffer.
    ///
    /// Identical to [`SigningContext::data_append`] — all three C backends
    /// use the same `string_cat` accumulation pattern for both signing
    /// and verification contexts.
    pub fn data_append(&mut self, data: &[u8]) {
        self.data_buffer.extend_from_slice(data);
    }

    /// Returns the number of bytes currently accumulated.
    pub fn accumulated_len(&self) -> usize {
        self.data_buffer.len()
    }

    /// Clears the accumulated data buffer without releasing the context.
    pub fn clear_buffer(&mut self) {
        self.data_buffer.clear();
    }

    /// Returns the number of key bits detected during initialization.
    pub fn key_bits(&self) -> u32 {
        self.inner.key_bits
    }
}

impl Drop for VerificationContext {
    /// Release all backend resources owned by this verification context.
    ///
    /// Delegates to the internal cleanup function which handles:
    /// - GnuTLS: `gnutls_pubkey_deinit`
    /// - GCrypt: `gcry_mpi_release` on n, e
    /// - OpenSSL: `EVP_PKEY_free`
    fn drop(&mut self) {
        let _ = crypto_verify_cleanup(&mut self.inner);
        self.data_buffer.clear();
    }
}

impl fmt::Debug for VerificationContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerificationContext")
            .field("key_type", &self.key_type)
            .field("hash_algo", &self.hash_algo)
            .field("buffer_len", &self.data_buffer.len())
            .field("key_bits", &self.inner.key_bits)
            .field("initialized", &self.inner.initialized)
            .finish()
    }
}

// =============================================================================
// CryptoCapabilities — Backend feature detection
// =============================================================================

/// Reports the capabilities of the active crypto backend.
///
/// Replaces the C `features_crypto()` function (`signing.c` lines 16–28)
/// which uses `MACRO_PREDEF` mode to register build macros:
/// - `_CRYPTO_SIGN_ED25519` → `ed25519_supported`
/// - `_CRYPTO_HASH_SHA3` → `sha3_supported`
///
/// In C, `SIGN_HAVE_ED25519` is set by `crypt_ver.h` based on backend version:
/// - GnuTLS ≥3.6.0
/// - OpenSSL ≥1.1.1 (non-LibreSSL)
/// - GCrypt: never (RSA only)
///
/// In Rust, these are Cargo feature flags checked at compile time.
#[derive(Debug)]
pub struct CryptoCapabilities {
    /// Whether Ed25519 signing/verification is available.
    ///
    /// Corresponds to C `SIGN_HAVE_ED25519` from `crypt_ver.h`.
    pub ed25519_supported: bool,

    /// Whether SHA-3 hash algorithms are available.
    ///
    /// Corresponds to C `SHA3_AVAILABLE` from `crypt_ver.h`.
    pub sha3_supported: bool,

    /// Human-readable name of the active crypto backend.
    ///
    /// In C, this would be "GnuTLS", "GCrypt", or "OpenSSL" with version.
    pub backend_name: &'static str,
}

// =============================================================================
// Public API Functions
// =============================================================================

/// Initialize the crypto signing/verification subsystem.
///
/// Must be called once before any signing or verification operations.
/// Replaces `exim_dkim_signers_init()` from all three C backends:
///
/// - **GnuTLS** (`signing.c` lines 71–82): Calls `gnutls_global_init()`,
///   sets up the GnuTLS logger callback (`exim_gnutls_logger_cb`) which
///   routes GnuTLS debug output to Exim's `debug_printf`.
///
/// - **GCrypt** (`signing.c` lines 312–346): Calls `gcry_check_version(NULL)`,
///   sets the logging handler, initializes 16384 bytes of secure memory via
///   `gcry_control(GCRYCTL_INIT_SECMEM, 16384)`, and marks initialization
///   complete with `gcry_control(GCRYCTL_INITIALIZATION_FINISHED)`.
///
/// - **OpenSSL** (`signing.c` lines 714–718): Calls
///   `ERR_load_crypto_strings()` and `OpenSSL_add_all_algorithms()`.
///
/// In Rust, the GnuTLS logger callback is replaced by `tracing` configuration —
/// no explicit callback registration is needed since `tracing` captures all
/// debug output through its subscriber system.
pub fn signers_init() -> Result<(), SigningError> {
    crypto_init().map_err(SigningError::FfiError)
}

/// Initialize a signing context with a PEM-encoded private key.
///
/// Parses the private key, detects the key type (RSA or Ed25519), and
/// creates a signing context ready to accumulate data for signing.
///
/// # Arguments
///
/// * `privkey_pem` — PEM-encoded private key string. The function handles
///   both PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`) and PKCS#8
///   (`-----BEGIN PRIVATE KEY-----`) formats.
/// * `key_type` — Expected key type. The function detects the actual type
///   from the key material and returns it in the context.
/// * `hash` — Hash algorithm to use for RSA signing. Ignored for Ed25519
///   (which always uses SHA-512 internally per the algorithm specification).
///
/// # Returns
///
/// A [`SigningContext`] ready for data accumulation via `data_append()`.
///
/// # Errors
///
/// - [`SigningError::PrivateKeyImportFailed`] — PEM data is malformed or
///   the backend cannot import the key.
/// - [`SigningError::UnsupportedKeyType`] — Ed25519 key detected but the
///   backend does not support Ed25519.
pub fn signing_init(
    privkey_pem: &str,
    key_type: KeyType,
    hash: HashAlgorithm,
) -> Result<SigningContext, SigningError> {
    tracing::debug!(
        requested_key_type = %key_type,
        hash_algo = %hash,
        pem_len = privkey_pem.len(),
        "PDKIM: initializing signing context"
    );

    // Import the private key via the crypto backend.
    let handle = crypto_signing_init(privkey_pem, key_type as u32, hash as u32)
        .map_err(SigningError::PrivateKeyImportFailed)?;

    // Detect the actual key type from the imported key material.
    // This may differ from the requested type if the PEM contains
    // a different key type than expected.
    let detected_key_type =
        crypto_detect_key_type(&handle).map_err(SigningError::PrivateKeyImportFailed)?;

    tracing::debug!(
        detected_key_type = %detected_key_type,
        "PDKIM: signing context initialized successfully"
    );

    Ok(SigningContext {
        inner: handle,
        key_type: detected_key_type,
        hash_algo: hash,
        data_buffer: Vec::new(),
    })
}

/// Produce a cryptographic signature over the accumulated data.
///
/// Consumes the data accumulated via [`SigningContext::data_append`] and
/// returns the raw signature bytes suitable for base64 encoding into the
/// DKIM `b=` tag.
///
/// # Critical Ed25519 vs RSA distinction
///
/// - **Ed25519**: The accumulated data is signed directly (raw data mode).
///   The Ed25519 algorithm internally applies SHA-512 hashing.
///   (GnuTLS: `gnutls_privkey_sign_data`, `signing.c` line 161)
///   (OpenSSL: `EVP_DigestSign` with NULL md, `signing.c` line 776)
///
/// - **RSA**: The backend first hashes the accumulated data with the
///   configured hash algorithm, then signs the hash.
///   (GnuTLS: `gnutls_privkey_sign_hash`, `signing.c` line 163)
///   (GCrypt: `gcry_md_hash_buffer` + `gcry_pk_sign`, `signing.c` lines 509–541)
///   (OpenSSL: `EVP_DigestSignInit/Update/Final`, `signing.c` lines 792–806)
///
/// # Arguments
///
/// * `ctx` — Mutable reference to the signing context. The data buffer is
///   cleared after signing (the context can be reused for another signature).
///
/// # Returns
///
/// Raw signature bytes. For RSA, the length equals `key_bits / 8`.
/// For Ed25519, the length is always 64 bytes.
pub fn sign(ctx: &mut SigningContext) -> Result<Vec<u8>, SigningError> {
    if ctx.data_buffer.is_empty() {
        tracing::warn!("PDKIM: sign called with empty data buffer");
    }

    tracing::debug!(
        key_type = %ctx.key_type,
        hash_algo = %ctx.hash_algo,
        data_len = ctx.data_buffer.len(),
        "PDKIM: producing signature"
    );

    let signature = crypto_sign(
        &ctx.inner,
        &ctx.data_buffer,
        ctx.key_type as u32,
        ctx.hash_algo as u32,
    )
    .map_err(SigningError::SigningFailed)?;

    // Clear the data buffer after signing (matches C behavior where
    // the accumulator is consumed by the signing operation).
    ctx.data_buffer.clear();

    tracing::debug!(
        sig_len = signature.len(),
        "PDKIM: signature produced successfully"
    );

    Ok(signature)
}

/// Initialize a verification context with a public key.
///
/// Imports the public key data (DER-encoded or raw Ed25519 bytes) and
/// creates a verification context ready to accumulate data for verification.
///
/// # Arguments
///
/// * `pubkey_data` — Raw bytes of the public key. For RSA, this is the
///   DER-encoded `SubjectPublicKeyInfo`. For Ed25519 with bare format,
///   this is the raw 32-byte public key.
/// * `key_type` — The key type (RSA or Ed25519) as indicated by the DNS
///   `k=` tag value.
/// * `key_format` — How the public key is encoded ([`KeyFormat::Der`] or
///   [`KeyFormat::Ed25519Bare`]).
///
/// # Returns
///
/// A tuple of ([`VerificationContext`], key_bits) where `key_bits` is the
/// number of bits in the public key (used for minimum key size enforcement).
///
/// # Errors
///
/// - [`SigningError::PublicKeyImportFailed`] — Key data is malformed or
///   the backend cannot import it.
/// - [`SigningError::UnsupportedKeyType`] — Key type not supported by backend.
pub fn verify_init(
    pubkey_data: &[u8],
    key_type: KeyType,
    key_format: KeyFormat,
) -> Result<(VerificationContext, u32), SigningError> {
    tracing::debug!(
        key_type = %key_type,
        key_format = ?key_format,
        data_len = pubkey_data.len(),
        "PDKIM: initializing verification context"
    );

    let (handle, key_bits) = crypto_verify_init(pubkey_data, key_type as u32, key_format as u32)
        .map_err(SigningError::PublicKeyImportFailed)?;

    tracing::debug!(
        key_bits = key_bits,
        "PDKIM: verification context initialized successfully"
    );

    Ok((
        VerificationContext {
            inner: handle,
            key_type,
            hash_algo: HashAlgorithm::Sha256, // Default, overridden by caller as needed
            data_buffer: Vec::new(),
        },
        key_bits,
    ))
}

/// Verify a signature against the accumulated data.
///
/// Checks whether `signature` is a valid cryptographic signature over
/// the data accumulated via [`VerificationContext::data_append`] using
/// the public key imported during [`verify_init`].
///
/// # Critical Ed25519 vs RSA distinction
///
/// - **Ed25519**: Verifies against raw accumulated data.
///   (GnuTLS: `gnutls_pubkey_verify_data2`, `signing.c` line 230)
///   (OpenSSL: `EVP_DigestVerify`, `signing.c` line 893)
///
/// - **RSA**: The backend hashes the accumulated data first, then verifies
///   the signature against the hash.
///   (GnuTLS: `gnutls_pubkey_verify_hash2`, `signing.c` line 233)
///   (GCrypt: `gcry_md_hash_buffer` + `gcry_pk_verify`, `signing.c` line 698)
///   (OpenSSL: `EVP_PKEY_verify` with PKCS1 padding, `signing.c` line 907)
///
/// # Arguments
///
/// * `ctx` — Mutable reference to the verification context. The data buffer
///   is cleared after verification.
/// * `signature` — Raw signature bytes to verify (decoded from the DKIM `b=`
///   tag's base64 value).
/// * `hash` — Hash algorithm used during signing (determines which hash the
///   backend applies for RSA verification).
///
/// # Returns
///
/// - `Ok(true)` — Signature is valid.
/// - `Ok(false)` — Signature does not match (the C code returns empty string
///   `""` for this case, which is distinct from an error).
/// - `Err(...)` — Processing error (backend failure, not a signature mismatch).
pub fn verify(
    ctx: &mut VerificationContext,
    signature: &[u8],
    hash: HashAlgorithm,
) -> Result<bool, SigningError> {
    if signature.is_empty() {
        tracing::error!("PDKIM: verify called with empty signature");
        return Err(SigningError::VerificationFailed(
            "empty signature data".to_string(),
        ));
    }

    tracing::debug!(
        key_type = %ctx.key_type,
        hash_algo = %hash,
        data_len = ctx.data_buffer.len(),
        sig_len = signature.len(),
        "PDKIM: verifying signature"
    );

    let result = crypto_verify(
        &ctx.inner,
        &ctx.data_buffer,
        signature,
        ctx.key_type as u32,
        hash as u32,
    )
    .map_err(SigningError::VerificationFailed)?;

    // Clear the data buffer after verification (matches C behavior).
    ctx.data_buffer.clear();

    if result {
        tracing::debug!("PDKIM: signature verification passed");
    } else {
        tracing::debug!("PDKIM: signature verification failed — mismatch");
    }

    Ok(result)
}

/// Returns the crypto capabilities of the active backend.
///
/// Replaces the C `features_crypto()` function (`signing.c` lines 16–28)
/// which registers `_CRYPTO_SIGN_ED25519` and `_CRYPTO_HASH_SHA3` build
/// macros in `MACRO_PREDEF` mode.
///
/// In Rust, Ed25519 and SHA-3 support are determined at build time based
/// on the compiled crypto backend capabilities. The Rust implementation
/// supports Ed25519 unconditionally (via the safe abstraction layer), and
/// SHA-3 support depends on the underlying backend availability.
///
/// The C code gated Ed25519 on GnuTLS ≥3.6.0 or OpenSSL ≥1.1.1; in the
/// Rust rewrite, Ed25519 is always available through the abstraction.
pub fn crypto_capabilities() -> CryptoCapabilities {
    // Ed25519 is supported in the Rust abstraction layer — the exim-ffi
    // backend provides the actual curve arithmetic when connected. Both
    // GnuTLS ≥3.6.0 and OpenSSL ≥1.1.1 support Ed25519 in modern
    // deployments, so we report it as available.
    let ed25519_supported = true;

    // SHA-3 support depends on the backend. Currently not available
    // through the standard DKIM hash set (SHA-1, SHA-256, SHA-512),
    // but the infrastructure is ready for future extension.
    let sha3_supported = false;

    CryptoCapabilities {
        ed25519_supported,
        sha3_supported,
        backend_name: crypto_backend_name(),
    }
}

// =============================================================================
// Internal helper functions
// =============================================================================

/// Detect the key type from PEM content by examining headers and content.
///
/// In C:
/// - GnuTLS: `gnutls_privkey_get_pk_algorithm() == GNUTLS_PK_EDDSA_ED25519`
/// - OpenSSL: `EVP_PKEY_get_id() == EVP_PKEY_ED25519`
/// - GCrypt: always RSA (no Ed25519 support)
fn detect_key_type_from_pem(pem: &str) -> KeyType {
    // Check for explicit Ed25519 markers in PEM headers
    if pem.contains("ED25519") || pem.contains("ed25519") {
        return KeyType::Ed25519;
    }

    // Check for RSA-specific markers
    if pem.contains("RSA PRIVATE KEY") {
        return KeyType::Rsa;
    }

    // For generic "PRIVATE KEY" (PKCS#8), attempt to detect from DER content.
    // Ed25519 PKCS#8 keys are very short (~48 bytes of base64), while RSA
    // keys are typically much longer (>100 bytes of base64).
    if pem.contains("BEGIN PRIVATE KEY") {
        // Extract and measure base64 content length
        let b64_len = pem
            .lines()
            .filter(|l| {
                let t = l.trim();
                !t.starts_with("-----") && !t.is_empty()
            })
            .map(|l| l.trim().len())
            .sum::<usize>();

        // Ed25519 PKCS#8 private keys are ~48 bytes encoded (~64 base64 chars).
        // RSA-1024 keys are ~640+ bytes encoded.
        if b64_len < 100 {
            return KeyType::Ed25519;
        }
    }

    // Default to RSA (matches C behavior where GCrypt always assumes RSA,
    // and GnuTLS/OpenSSL default to RSA when detection fails).
    KeyType::Rsa
}

/// Estimate RSA key size in bits from DER-encoded public key length.
///
/// **Deprecated for production use.** The real [`crypto_verify_init`] now
/// computes exact bit counts via [`RsaPublicKey::n`]`()`[`.bits()`] — an
/// accurate measurement is critical for `dkim_verify_min_keysizes`
/// enforcement. This function remains in the codebase purely as a test
/// helper / reference implementation documenting the historical length
/// heuristic used by the earlier scaffolding, and is exercised by the
/// `rsa_key_bits_estimation` unit test.
#[cfg(test)]
fn estimate_rsa_key_bits(der_len: usize) -> u32 {
    // RSA SubjectPublicKeyInfo DER sizes (approximate):
    // - 1024-bit: ~162 bytes
    // - 2048-bit: ~294 bytes
    // - 3072-bit: ~422 bytes
    // - 4096-bit: ~550 bytes
    // - 8192-bit: ~1062 bytes
    if der_len >= 1000 {
        8192
    } else if der_len >= 500 {
        4096
    } else if der_len >= 380 {
        3072
    } else if der_len >= 250 {
        2048
    } else if der_len >= 130 {
        1024
    } else if der_len >= 64 {
        512
    } else {
        256
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::EncodePrivateKey as _Ed25519EncodePriv;
    use rand::rngs::OsRng;
    use rsa::pkcs1::EncodeRsaPrivateKey as _;
    use rsa::pkcs8::{EncodePublicKey as _, LineEnding};
    use std::sync::OnceLock;

    // ── Real-crypto test fixtures ────────────────────────────────────────
    //
    // The helpers below generate genuine RSA and Ed25519 keypairs on first
    // access and cache them in a process-wide `OnceLock`. Generation is
    // expensive (~300–1500 ms for RSA-1024 depending on the machine), so
    // all tests that need a key reuse the same cached instance.
    //
    // We deliberately use RSA-1024 (not RSA-2048) because:
    // - `dkim_verify_min_keysizes` defaults to 1024 in the C implementation.
    // - 1024-bit keys generate ~5–10x faster than 2048-bit keys, keeping
    //   the unit-test suite fast enough for developer iteration.
    // - The keys are never used outside the test process.

    struct RsaFixture {
        pkcs1_pem: String,
        pkcs8_pem: String,
        pub_spki_der: Vec<u8>,
    }

    struct Ed25519Fixture {
        pkcs8_pem: String,
        pub_bare: [u8; 32],
    }

    fn rsa_test_key() -> &'static RsaFixture {
        static CELL: OnceLock<RsaFixture> = OnceLock::new();
        CELL.get_or_init(|| {
            let mut rng = OsRng;
            let priv_key =
                RsaPrivateKey::new(&mut rng, 1024).expect("failed to generate RSA-1024 test key");
            let pub_key = RsaPublicKey::from(&priv_key);
            RsaFixture {
                pkcs1_pem: priv_key
                    .to_pkcs1_pem(LineEnding::LF)
                    .expect("RSA PKCS#1 PEM encoding failed")
                    .to_string(),
                pkcs8_pem: priv_key
                    .to_pkcs8_pem(LineEnding::LF)
                    .expect("RSA PKCS#8 PEM encoding failed")
                    .to_string(),
                pub_spki_der: pub_key
                    .to_public_key_der()
                    .expect("RSA SPKI DER encoding failed")
                    .as_bytes()
                    .to_vec(),
            }
        })
    }

    fn ed25519_test_key() -> &'static Ed25519Fixture {
        static CELL: OnceLock<Ed25519Fixture> = OnceLock::new();
        CELL.get_or_init(|| {
            let mut rng = OsRng;
            let sk = Ed25519SigningKey::generate(&mut rng);
            let pem = sk
                .to_pkcs8_pem(LineEnding::LF)
                .expect("Ed25519 PKCS#8 PEM encoding failed")
                .to_string();
            Ed25519Fixture {
                pkcs8_pem: pem,
                pub_bare: sk.verifying_key().to_bytes(),
            }
        })
    }

    // ── HashAlgorithm tests ──────────────────────────────────────────────

    #[test]
    fn hash_algorithm_names() {
        assert_eq!(HashAlgorithm::Sha1.as_str(), "sha1");
        assert_eq!(HashAlgorithm::Sha256.as_str(), "sha256");
        assert_eq!(HashAlgorithm::Sha512.as_str(), "sha512");
    }

    #[test]
    fn hash_algorithm_display() {
        assert_eq!(format!("{}", HashAlgorithm::Sha256), "sha256");
        assert_eq!(format!("{}", HashAlgorithm::Sha512), "sha512");
    }

    #[test]
    fn hash_algorithm_digest_sizes() {
        assert_eq!(HashAlgorithm::Sha1.digest_size(), 20);
        assert_eq!(HashAlgorithm::Sha256.digest_size(), 32);
        assert_eq!(HashAlgorithm::Sha512.digest_size(), 64);
    }

    #[test]
    fn hash_algorithm_from_name() {
        assert_eq!(
            HashAlgorithm::from_name("sha256"),
            Some(HashAlgorithm::Sha256)
        );
        assert_eq!(
            HashAlgorithm::from_name("SHA-256"),
            Some(HashAlgorithm::Sha256)
        );
        assert_eq!(HashAlgorithm::from_name("sha1"), Some(HashAlgorithm::Sha1));
        assert_eq!(
            HashAlgorithm::from_name("sha512"),
            Some(HashAlgorithm::Sha512)
        );
        assert_eq!(HashAlgorithm::from_name("md5"), None);
        assert_eq!(HashAlgorithm::from_name(""), None);
    }

    // ── KeyType tests ────────────────────────────────────────────────────

    #[test]
    fn key_type_values() {
        assert_eq!(KeyType::Rsa as u32, 0);
        assert_eq!(KeyType::Ed25519 as u32, 1);
    }

    #[test]
    fn key_type_names() {
        assert_eq!(KeyType::Rsa.as_str(), "rsa");
        assert_eq!(KeyType::Ed25519.as_str(), "ed25519");
    }

    #[test]
    fn key_type_from_dns() {
        assert_eq!(KeyType::from_dns_tag("rsa"), Some(KeyType::Rsa));
        assert_eq!(KeyType::from_dns_tag(""), Some(KeyType::Rsa));
        assert_eq!(KeyType::from_dns_tag("ed25519"), Some(KeyType::Ed25519));
        assert_eq!(KeyType::from_dns_tag("dsa"), None);
    }

    // ── KeyFormat tests ──────────────────────────────────────────────────

    #[test]
    fn key_format_values() {
        assert_eq!(KeyFormat::Der as u32, 0);
        assert_eq!(KeyFormat::Ed25519Bare as u32, 1);
    }

    // ── SigningError tests ───────────────────────────────────────────────

    #[test]
    fn signing_error_display() {
        let e = SigningError::PrivateKeyImportFailed("bad PEM".into());
        assert_eq!(format!("{e}"), "Private key import failed: bad PEM");

        let e = SigningError::UnsupportedKeyType;
        assert_eq!(format!("{e}"), "Unsupported key type");

        let e = SigningError::DataAppendFailed;
        assert_eq!(format!("{e}"), "Data append failed");

        let e = SigningError::FfiError("backend crash".into());
        assert_eq!(format!("{e}"), "FFI error: backend crash");
    }

    #[test]
    fn signing_error_is_std_error() {
        let e: Box<dyn std::error::Error> = Box::new(SigningError::SigningFailed("test".into()));
        assert!(e.to_string().contains("Signing operation failed"));
    }

    // ── Crypto initialization tests ──────────────────────────────────────

    #[test]
    fn signers_init_succeeds() {
        let result = signers_init();
        assert!(result.is_ok());
    }

    // ── signing_init tests ───────────────────────────────────────────────

    #[test]
    fn signing_init_empty_key_fails() {
        let result = signing_init("", KeyType::Rsa, HashAlgorithm::Sha256);
        assert!(result.is_err());
        match result.unwrap_err() {
            SigningError::PrivateKeyImportFailed(msg) => {
                assert!(msg.contains("empty"), "msg was: {msg}");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn signing_init_rsa_pem() {
        // Use a real RSA-1024 PKCS#1 PEM — previous scaffolding used a fake
        // PEM string which the real `rsa` parser correctly rejects.
        let pem = &rsa_test_key().pkcs1_pem;
        let result = signing_init(pem, KeyType::Rsa, HashAlgorithm::Sha256);
        assert!(result.is_ok(), "signing_init failed: {:?}", result.err());
        let ctx = result.unwrap();
        assert_eq!(ctx.key_type, KeyType::Rsa);
        assert_eq!(ctx.hash_algo, HashAlgorithm::Sha256);
    }

    #[test]
    fn signing_init_rsa_pkcs8_pem() {
        // RSA key expressed in PKCS#8 PEM (modern openssl default).
        let pem = &rsa_test_key().pkcs8_pem;
        let result = signing_init(pem, KeyType::Rsa, HashAlgorithm::Sha256);
        assert!(result.is_ok(), "signing_init failed: {:?}", result.err());
        assert_eq!(result.unwrap().key_type, KeyType::Rsa);
    }

    #[test]
    fn signing_init_ed25519_pkcs8() {
        // RFC 8410 PKCS#8 encoding of a real Ed25519 seed.
        let pem = &ed25519_test_key().pkcs8_pem;
        let result = signing_init(pem, KeyType::Ed25519, HashAlgorithm::Sha256);
        assert!(result.is_ok(), "signing_init failed: {:?}", result.err());
        let ctx = result.unwrap();
        assert_eq!(ctx.key_type, KeyType::Ed25519);
    }

    #[test]
    fn signing_init_malformed_pem_fails() {
        // Any sort of PEM-shaped but cryptographically invalid input MUST
        // now be rejected — the previous scaffolding accepted these blindly,
        // which would have masked configuration errors in production.
        let pem = "-----BEGIN RSA PRIVATE KEY-----\n\
                    MIIBogIBAAJBAL8eJ5AKoIsgURqeBZw=\n\
                    -----END RSA PRIVATE KEY-----";
        let result = signing_init(pem, KeyType::Rsa, HashAlgorithm::Sha256);
        assert!(
            result.is_err(),
            "malformed RSA PEM must be rejected by crypto parser"
        );
        match result.unwrap_err() {
            SigningError::PrivateKeyImportFailed(msg) => {
                assert!(
                    msg.contains("parse") || msg.contains("DER") || msg.contains("ASN"),
                    "error message should describe parse failure: {msg}"
                );
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    // ── SigningContext data accumulation tests ────────────────────────────

    #[test]
    fn signing_context_data_append() {
        let pem = &rsa_test_key().pkcs1_pem;
        let mut ctx = signing_init(pem, KeyType::Rsa, HashAlgorithm::Sha256).unwrap();

        assert_eq!(ctx.accumulated_len(), 0);
        ctx.data_append(b"hello ");
        assert_eq!(ctx.accumulated_len(), 6);
        ctx.data_append(b"world");
        assert_eq!(ctx.accumulated_len(), 11);

        ctx.clear_buffer();
        assert_eq!(ctx.accumulated_len(), 0);
    }

    // ── verify_init tests ────────────────────────────────────────────────

    #[test]
    fn verify_init_empty_key_fails() {
        let result = verify_init(&[], KeyType::Rsa, KeyFormat::Der);
        assert!(result.is_err());
        match result.unwrap_err() {
            SigningError::PublicKeyImportFailed(msg) => {
                assert!(msg.contains("empty"), "msg was: {msg}");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn verify_init_rsa_der() {
        // Real DER-encoded SubjectPublicKeyInfo from our RSA-1024 fixture.
        let der = &rsa_test_key().pub_spki_der;
        let result = verify_init(der, KeyType::Rsa, KeyFormat::Der);
        assert!(result.is_ok(), "verify_init failed: {:?}", result.err());
        let (ctx, key_bits) = result.unwrap();
        assert_eq!(ctx.key_type, KeyType::Rsa);
        // Exact modulus bit-count, not an estimate.
        assert_eq!(key_bits, 1024);
    }

    #[test]
    fn verify_init_rsa_malformed_der_fails() {
        // All-zeros is not a valid SPKI — the real parser must reject it.
        let fake_der = vec![0u8; 294];
        let result = verify_init(&fake_der, KeyType::Rsa, KeyFormat::Der);
        assert!(
            result.is_err(),
            "all-zero bytes are not a valid DER SPKI and must be rejected"
        );
    }

    #[test]
    fn verify_init_ed25519_bare() {
        // Real Ed25519 public key bytes (a valid compressed Edwards point).
        let key = ed25519_test_key().pub_bare;
        let result = verify_init(&key, KeyType::Ed25519, KeyFormat::Ed25519Bare);
        assert!(result.is_ok(), "verify_init failed: {:?}", result.err());
        let (ctx, key_bits) = result.unwrap();
        assert_eq!(ctx.key_type, KeyType::Ed25519);
        assert_eq!(key_bits, 256);
    }

    #[test]
    fn verify_init_ed25519_bare_wrong_size() {
        let key = vec![0u8; 33]; // Wrong size for bare Ed25519
        let result = verify_init(&key, KeyType::Ed25519, KeyFormat::Ed25519Bare);
        assert!(result.is_err());
    }

    // ── VerificationContext data accumulation tests ───────────────────────

    #[test]
    fn verification_context_data_append() {
        let key = ed25519_test_key().pub_bare;
        let (mut ctx, _) = verify_init(&key, KeyType::Ed25519, KeyFormat::Ed25519Bare).unwrap();

        assert_eq!(ctx.accumulated_len(), 0);
        ctx.data_append(b"test data");
        assert_eq!(ctx.accumulated_len(), 9);
        ctx.data_append(b" more");
        assert_eq!(ctx.accumulated_len(), 14);

        ctx.clear_buffer();
        assert_eq!(ctx.accumulated_len(), 0);
    }

    // ── verify with empty signature ──────────────────────────────────────

    #[test]
    fn verify_empty_signature_fails() {
        let key = ed25519_test_key().pub_bare;
        let (mut ctx, _) = verify_init(&key, KeyType::Ed25519, KeyFormat::Ed25519Bare).unwrap();
        ctx.data_append(b"test");
        let result = verify(&mut ctx, &[], HashAlgorithm::Sha256);
        assert!(result.is_err());
    }

    // ── End-to-end crypto round-trip tests ────────────────────────────────
    //
    // These tests exercise the full sign → verify path with real RustCrypto
    // primitives. They prove that the crypto backend is actually wired up
    // (as opposed to the previous stub that returned
    // "crypto signing backend not yet connected").

    #[test]
    fn rsa_sign_verify_roundtrip_sha256() {
        let rsa = rsa_test_key();
        let mut sctx = signing_init(&rsa.pkcs1_pem, KeyType::Rsa, HashAlgorithm::Sha256).unwrap();
        sctx.data_append(b"The quick brown fox jumps over the lazy dog");

        let sig = sign(&mut sctx).expect("RSA-SHA256 signing must succeed");

        // RSA-1024 signature is exactly 128 bytes.
        assert_eq!(sig.len(), 128);

        let (mut vctx, key_bits) =
            verify_init(&rsa.pub_spki_der, KeyType::Rsa, KeyFormat::Der).unwrap();
        assert_eq!(key_bits, 1024);
        vctx.data_append(b"The quick brown fox jumps over the lazy dog");

        let ok = verify(&mut vctx, &sig, HashAlgorithm::Sha256).unwrap();
        assert!(ok, "RSA-SHA256 round-trip verification failed");
    }

    #[test]
    fn rsa_sign_verify_roundtrip_sha1() {
        let rsa = rsa_test_key();
        let mut sctx = signing_init(&rsa.pkcs1_pem, KeyType::Rsa, HashAlgorithm::Sha1).unwrap();
        sctx.data_append(b"DKIM legacy rsa-sha1 signature");

        let sig = sign(&mut sctx).expect("RSA-SHA1 signing must succeed");
        assert_eq!(sig.len(), 128);

        let (mut vctx, _) = verify_init(&rsa.pub_spki_der, KeyType::Rsa, KeyFormat::Der).unwrap();
        vctx.data_append(b"DKIM legacy rsa-sha1 signature");

        let ok = verify(&mut vctx, &sig, HashAlgorithm::Sha1).unwrap();
        assert!(ok, "RSA-SHA1 round-trip verification failed");
    }

    #[test]
    fn rsa_verify_rejects_modified_data() {
        let rsa = rsa_test_key();
        let mut sctx = signing_init(&rsa.pkcs1_pem, KeyType::Rsa, HashAlgorithm::Sha256).unwrap();
        sctx.data_append(b"original data");
        let sig = sign(&mut sctx).unwrap();

        let (mut vctx, _) = verify_init(&rsa.pub_spki_der, KeyType::Rsa, KeyFormat::Der).unwrap();
        vctx.data_append(b"tampered data");
        let ok = verify(&mut vctx, &sig, HashAlgorithm::Sha256).unwrap();
        assert!(!ok, "RSA verify must reject signatures over tampered data");
    }

    #[test]
    fn rsa_verify_rejects_corrupted_signature() {
        let rsa = rsa_test_key();
        let mut sctx = signing_init(&rsa.pkcs1_pem, KeyType::Rsa, HashAlgorithm::Sha256).unwrap();
        sctx.data_append(b"data");
        let mut sig = sign(&mut sctx).unwrap();
        // Flip a bit in the middle of the signature.
        sig[64] ^= 0xFF;

        let (mut vctx, _) = verify_init(&rsa.pub_spki_der, KeyType::Rsa, KeyFormat::Der).unwrap();
        vctx.data_append(b"data");
        let ok = verify(&mut vctx, &sig, HashAlgorithm::Sha256).unwrap();
        assert!(!ok, "RSA verify must reject corrupted signatures");
    }

    #[test]
    fn rsa_verify_rejects_wrong_length_signature() {
        let rsa = rsa_test_key();
        let (mut vctx, _) = verify_init(&rsa.pub_spki_der, KeyType::Rsa, KeyFormat::Der).unwrap();
        vctx.data_append(b"data");
        // Obviously-wrong-size signature (RSA-1024 needs 128 bytes).
        let short_sig = vec![0u8; 16];
        let result = verify(&mut vctx, &short_sig, HashAlgorithm::Sha256).unwrap();
        assert!(
            !result,
            "wrong-length signature must be treated as a mismatch, not a parse error"
        );
    }

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let ed = ed25519_test_key();
        let mut sctx =
            signing_init(&ed.pkcs8_pem, KeyType::Ed25519, HashAlgorithm::Sha256).unwrap();
        sctx.data_append(b"Ed25519 test message per RFC 8032");

        let sig = sign(&mut sctx).expect("Ed25519 signing must succeed");
        assert_eq!(sig.len(), 64, "Ed25519 signatures are always 64 bytes");

        let (mut vctx, key_bits) =
            verify_init(&ed.pub_bare, KeyType::Ed25519, KeyFormat::Ed25519Bare).unwrap();
        assert_eq!(key_bits, 256);
        vctx.data_append(b"Ed25519 test message per RFC 8032");

        let ok = verify(&mut vctx, &sig, HashAlgorithm::Sha256).unwrap();
        assert!(ok, "Ed25519 round-trip verification failed");
    }

    #[test]
    fn ed25519_verify_rejects_modified_data() {
        let ed = ed25519_test_key();
        let mut sctx =
            signing_init(&ed.pkcs8_pem, KeyType::Ed25519, HashAlgorithm::Sha256).unwrap();
        sctx.data_append(b"genuine message");
        let sig = sign(&mut sctx).unwrap();

        let (mut vctx, _) =
            verify_init(&ed.pub_bare, KeyType::Ed25519, KeyFormat::Ed25519Bare).unwrap();
        vctx.data_append(b"forged message");
        let ok = verify(&mut vctx, &sig, HashAlgorithm::Sha256).unwrap();
        assert!(
            !ok,
            "Ed25519 verify must reject signatures over tampered data"
        );
    }

    #[test]
    fn ed25519_verify_rejects_wrong_length_signature() {
        let ed = ed25519_test_key();
        let (mut vctx, _) =
            verify_init(&ed.pub_bare, KeyType::Ed25519, KeyFormat::Ed25519Bare).unwrap();
        vctx.data_append(b"data");
        let short_sig = vec![0u8; 32];
        let result = verify(&mut vctx, &short_sig, HashAlgorithm::Sha256).unwrap();
        assert!(!result, "wrong-length Ed25519 signature must be rejected");
    }

    #[test]
    fn rsa_reproducible_signatures_are_deterministic() {
        // PKCS#1 v1.5 signing is deterministic: the same (key, message)
        // input must produce the same signature every time.
        let rsa = rsa_test_key();
        let mut sctx1 = signing_init(&rsa.pkcs1_pem, KeyType::Rsa, HashAlgorithm::Sha256).unwrap();
        sctx1.data_append(b"determinism check");
        let sig1 = sign(&mut sctx1).unwrap();

        let mut sctx2 = signing_init(&rsa.pkcs1_pem, KeyType::Rsa, HashAlgorithm::Sha256).unwrap();
        sctx2.data_append(b"determinism check");
        let sig2 = sign(&mut sctx2).unwrap();

        assert_eq!(sig1, sig2, "PKCS#1 v1.5 signatures must be deterministic");
    }

    #[test]
    fn ed25519_signatures_are_deterministic() {
        // RFC 8032 Ed25519 is deterministic by design.
        let ed = ed25519_test_key();
        let mut sctx1 =
            signing_init(&ed.pkcs8_pem, KeyType::Ed25519, HashAlgorithm::Sha256).unwrap();
        sctx1.data_append(b"determinism check");
        let sig1 = sign(&mut sctx1).unwrap();

        let mut sctx2 =
            signing_init(&ed.pkcs8_pem, KeyType::Ed25519, HashAlgorithm::Sha256).unwrap();
        sctx2.data_append(b"determinism check");
        let sig2 = sign(&mut sctx2).unwrap();

        assert_eq!(sig1, sig2, "Ed25519 signatures must be deterministic");
    }

    // ── CryptoCapabilities tests ─────────────────────────────────────────

    #[test]
    fn crypto_capabilities_returns_valid() {
        let caps = crypto_capabilities();
        // Without ed25519/sha3 features enabled, these should be false
        assert!(!caps.backend_name.is_empty());
    }

    // ── Drop safety tests ────────────────────────────────────────────────

    #[test]
    fn signing_context_drop_does_not_panic() {
        // Use a real RSA key fixture — the parser now rejects malformed PEM.
        let pem = &rsa_test_key().pkcs1_pem;
        let mut ctx = signing_init(pem, KeyType::Rsa, HashAlgorithm::Sha256).unwrap();
        ctx.data_append(b"some data");
        drop(ctx); // Should not panic; secrets are zeroized on drop by RustCrypto.
    }

    #[test]
    fn verification_context_drop_does_not_panic() {
        let key = ed25519_test_key().pub_bare;
        let (mut ctx, _) = verify_init(&key, KeyType::Ed25519, KeyFormat::Ed25519Bare).unwrap();
        ctx.data_append(b"some data");
        drop(ctx); // Should not panic
    }

    // ── estimate_rsa_key_bits tests ──────────────────────────────────────

    #[test]
    fn rsa_key_bits_estimation() {
        // Legacy DER-length-heuristic function retained for historical callers.
        assert_eq!(estimate_rsa_key_bits(162), 1024);
        assert_eq!(estimate_rsa_key_bits(294), 2048);
        assert_eq!(estimate_rsa_key_bits(422), 3072);
        assert_eq!(estimate_rsa_key_bits(550), 4096);
        assert_eq!(estimate_rsa_key_bits(1062), 8192);
        assert_eq!(estimate_rsa_key_bits(50), 256);
    }

    // ── Debug formatting tests ───────────────────────────────────────────

    #[test]
    fn signing_context_debug_format() {
        let pem = &rsa_test_key().pkcs1_pem;
        let ctx = signing_init(pem, KeyType::Rsa, HashAlgorithm::Sha256).unwrap();
        let debug = format!("{ctx:?}");
        assert!(debug.contains("SigningContext"));
        assert!(debug.contains("Rsa"));
    }

    #[test]
    fn verification_context_debug_format() {
        let key = ed25519_test_key().pub_bare;
        let (ctx, _) = verify_init(&key, KeyType::Ed25519, KeyFormat::Ed25519Bare).unwrap();
        let debug = format!("{ctx:?}");
        assert!(debug.contains("VerificationContext"));
        assert!(debug.contains("Ed25519"));
    }
}
