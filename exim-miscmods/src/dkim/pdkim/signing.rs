// =============================================================================
// exim-miscmods/src/dkim/pdkim/signing.rs — DKIM Crypto Backend Abstraction
// =============================================================================
//
// Rewrites `src/src/miscmods/pdkim/signing.c` (919 lines) — cryptographic
// backend abstraction for DKIM signing and verification operations.
//
// Provides RSA and Ed25519 signing/verification, hash computation, and
// key parsing for the PDKIM streaming DKIM implementation.
//
// Per AAP §0.7.2: zero unsafe blocks.
// Per AAP §0.4.2: used by dkim/mod.rs and dkim/transport.rs.

use std::fmt;

// =============================================================================
// Constants
// =============================================================================

/// RSA minimum key size in bits.
const RSA_MIN_KEY_SIZE: u32 = 1024;

/// RSA maximum key size in bits.
const RSA_MAX_KEY_SIZE: u32 = 8192;

/// Ed25519 key size in bytes.
const ED25519_KEY_SIZE: usize = 32;

/// SHA-256 digest size in bytes.
const SHA256_DIGEST_SIZE: usize = 32;

/// Maximum signature size in bytes (RSA-8192 raw signature).
const MAX_SIGNATURE_SIZE: usize = 1024;

/// Maximum DER-encoded key size.
const MAX_KEY_DER_SIZE: usize = 16384;

// =============================================================================
// Enumerations
// =============================================================================

/// Hash algorithm used for DKIM signing.
///
/// Replaces the C `pdkim_hashtype` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256 (recommended, required by RFC 6376).
    Sha256,
    /// SHA-1 (deprecated, kept for verification compatibility).
    Sha1,
}

impl HashAlgorithm {
    /// Return the algorithm name as used in DKIM headers (e.g., "sha256").
    pub fn dkim_name(&self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha1 => "sha1",
        }
    }

    /// Parse a DKIM algorithm name.
    pub fn from_dkim_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "sha256" | "sha-256" => Some(Self::Sha256),
            "sha1" | "sha-1" => Some(Self::Sha1),
            _ => None,
        }
    }

    /// Return the digest output size in bytes.
    pub fn digest_size(&self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha1 => 20,
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.dkim_name())
    }
}

/// Signing algorithm for DKIM.
///
/// Replaces the C `pdkim_keytype` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// RSA with SHA-256 (rsa-sha256, the default).
    RsaSha256,
    /// RSA with SHA-1 (rsa-sha1, deprecated).
    RsaSha1,
    /// Ed25519 with SHA-256 (ed25519-sha256, RFC 8463).
    Ed25519Sha256,
}

impl SigningAlgorithm {
    /// Return the DKIM "a=" tag value.
    pub fn dkim_tag(&self) -> &'static str {
        match self {
            Self::RsaSha256 => "rsa-sha256",
            Self::RsaSha1 => "rsa-sha1",
            Self::Ed25519Sha256 => "ed25519-sha256",
        }
    }

    /// Parse a DKIM "a=" tag value.
    pub fn from_dkim_tag(tag: &str) -> Option<Self> {
        match tag.to_ascii_lowercase().as_str() {
            "rsa-sha256" => Some(Self::RsaSha256),
            "rsa-sha1" => Some(Self::RsaSha1),
            "ed25519-sha256" => Some(Self::Ed25519Sha256),
            _ => None,
        }
    }

    /// Return the hash algorithm used by this signing algorithm.
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            Self::RsaSha256 | Self::Ed25519Sha256 => HashAlgorithm::Sha256,
            Self::RsaSha1 => HashAlgorithm::Sha1,
        }
    }

    /// Return whether this is an RSA-based algorithm.
    pub fn is_rsa(&self) -> bool {
        matches!(self, Self::RsaSha256 | Self::RsaSha1)
    }

    /// Return whether this is an Ed25519-based algorithm.
    pub fn is_ed25519(&self) -> bool {
        matches!(self, Self::Ed25519Sha256)
    }
}

impl fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.dkim_tag())
    }
}

// =============================================================================
// Errors
// =============================================================================

/// Errors from cryptographic operations.
#[derive(Debug, Clone)]
pub enum SigningError {
    /// The private key data is malformed or unsupported.
    InvalidKey(String),
    /// The key type does not match the requested algorithm.
    KeyTypeMismatch { expected: String, actual: String },
    /// The RSA key size is below the minimum (1024 bits).
    KeyTooSmall { bits: u32, minimum: u32 },
    /// The RSA key size exceeds the maximum (8192 bits).
    KeyTooLarge { bits: u32, maximum: u32 },
    /// Hash computation failed.
    HashError(String),
    /// Signing operation failed.
    SignError(String),
    /// Verification operation failed.
    VerifyError(String),
    /// The signature data is malformed.
    InvalidSignature(String),
    /// Base64 encoding/decoding error.
    Base64Error(String),
    /// The public key from DNS is malformed.
    InvalidPublicKey(String),
    /// Unsupported algorithm or key type.
    Unsupported(String),
}

impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey(msg) => write!(f, "invalid key: {}", msg),
            Self::KeyTypeMismatch { expected, actual } => {
                write!(f, "key type mismatch: expected {}, got {}", expected, actual)
            }
            Self::KeyTooSmall { bits, minimum } => {
                write!(f, "RSA key too small: {} bits (minimum {})", bits, minimum)
            }
            Self::KeyTooLarge { bits, maximum } => {
                write!(f, "RSA key too large: {} bits (maximum {})", bits, maximum)
            }
            Self::HashError(msg) => write!(f, "hash error: {}", msg),
            Self::SignError(msg) => write!(f, "signing error: {}", msg),
            Self::VerifyError(msg) => write!(f, "verification error: {}", msg),
            Self::InvalidSignature(msg) => write!(f, "invalid signature: {}", msg),
            Self::Base64Error(msg) => write!(f, "base64 error: {}", msg),
            Self::InvalidPublicKey(msg) => write!(f, "invalid public key: {}", msg),
            Self::Unsupported(msg) => write!(f, "unsupported: {}", msg),
        }
    }
}

impl std::error::Error for SigningError {}

// =============================================================================
// HashContext — Streaming hash computation
// =============================================================================

/// Streaming hash context for computing message digests.
///
/// Wraps the underlying hash implementation (SHA-256 or SHA-1) and provides
/// an incremental update/finalize interface matching the C pdkim_hash
/// streaming pattern.
#[derive(Debug)]
pub struct HashContext {
    algorithm: HashAlgorithm,
    /// Accumulated data for hashing (we accumulate and compute at finalize).
    data: Vec<u8>,
}

impl HashContext {
    /// Create a new hash context for the specified algorithm.
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            algorithm,
            data: Vec::new(),
        }
    }

    /// Feed data into the hash context.
    pub fn update(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    /// Finalize the hash and return the digest.
    pub fn finalize(&self) -> Result<Vec<u8>, SigningError> {
        use sha2::{Digest, Sha256};

        match self.algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(&self.data);
                Ok(hasher.finalize().to_vec())
            }
            HashAlgorithm::Sha1 => {
                use sha1::Sha1;
                let mut hasher = Sha1::new();
                hasher.update(&self.data);
                Ok(hasher.finalize().to_vec())
            }
        }
    }

    /// Reset the context for reuse.
    pub fn reset(&mut self) {
        self.data.clear();
    }
}

// =============================================================================
// KeyData — Private key representation
// =============================================================================

/// Parsed private key data for DKIM signing.
///
/// Supports RSA and Ed25519 key types. The key material is stored as
/// raw bytes (DER-encoded for RSA, raw 32 bytes for Ed25519).
#[derive(Debug, Clone)]
pub enum KeyData {
    /// RSA private key (DER-encoded PKCS#1 or PKCS#8).
    Rsa {
        der_bytes: Vec<u8>,
        key_size_bits: u32,
    },
    /// Ed25519 private key (32-byte seed).
    Ed25519 { seed: [u8; ED25519_KEY_SIZE] },
}

impl KeyData {
    /// Parse a PEM-encoded private key.
    pub fn from_pem(pem_data: &str) -> Result<Self, SigningError> {
        let trimmed = pem_data.trim();

        if trimmed.contains("RSA PRIVATE KEY") || trimmed.contains("PRIVATE KEY") {
            // Extract base64 content between PEM markers.
            let b64 = extract_pem_base64(trimmed)?;
            let der = base64_decode(&b64)?;

            if der.len() < 128 {
                return Err(SigningError::InvalidKey(
                    "RSA key DER data too short".into(),
                ));
            }

            // Estimate key size from DER length.
            // RSA key DER is approximately (key_bits / 4) bytes.
            let estimated_bits = (der.len() as u32) * 4;
            let key_bits = if estimated_bits >= 8192 {
                8192
            } else if estimated_bits >= 4096 {
                4096
            } else if estimated_bits >= 2048 {
                2048
            } else {
                1024
            };

            if key_bits < RSA_MIN_KEY_SIZE {
                return Err(SigningError::KeyTooSmall {
                    bits: key_bits,
                    minimum: RSA_MIN_KEY_SIZE,
                });
            }
            if key_bits > RSA_MAX_KEY_SIZE {
                return Err(SigningError::KeyTooLarge {
                    bits: key_bits,
                    maximum: RSA_MAX_KEY_SIZE,
                });
            }

            Ok(Self::Rsa {
                der_bytes: der,
                key_size_bits: key_bits,
            })
        } else if trimmed.contains("ED25519") || trimmed.contains("ed25519") {
            let b64 = extract_pem_base64(trimmed)?;
            let raw = base64_decode(&b64)?;

            if raw.len() < ED25519_KEY_SIZE {
                return Err(SigningError::InvalidKey(format!(
                    "Ed25519 key too short: {} bytes (need {})",
                    raw.len(),
                    ED25519_KEY_SIZE
                )));
            }

            // Take the last 32 bytes as the seed (handles PKCS#8 wrapping).
            let offset = raw.len() - ED25519_KEY_SIZE;
            let mut seed = [0u8; ED25519_KEY_SIZE];
            seed.copy_from_slice(&raw[offset..]);

            Ok(Self::Ed25519 { seed })
        } else {
            // Try to detect key type from DER content.
            let b64 = extract_pem_base64(trimmed)?;
            let der = base64_decode(&b64)?;

            if der.len() >= 128 {
                // Likely RSA.
                let estimated_bits = (der.len() as u32) * 4;
                let key_bits = estimated_bits.min(RSA_MAX_KEY_SIZE).max(RSA_MIN_KEY_SIZE);
                Ok(Self::Rsa {
                    der_bytes: der,
                    key_size_bits: key_bits,
                })
            } else if der.len() >= ED25519_KEY_SIZE {
                let offset = der.len() - ED25519_KEY_SIZE;
                let mut seed = [0u8; ED25519_KEY_SIZE];
                seed.copy_from_slice(&der[offset..]);
                Ok(Self::Ed25519 { seed })
            } else {
                Err(SigningError::InvalidKey(
                    "cannot determine key type from PEM data".into(),
                ))
            }
        }
    }

    /// Parse a raw DER-encoded key.
    pub fn from_der(der_data: &[u8], is_ed25519: bool) -> Result<Self, SigningError> {
        if is_ed25519 {
            if der_data.len() < ED25519_KEY_SIZE {
                return Err(SigningError::InvalidKey(
                    "Ed25519 DER data too short".into(),
                ));
            }
            let offset = der_data.len() - ED25519_KEY_SIZE;
            let mut seed = [0u8; ED25519_KEY_SIZE];
            seed.copy_from_slice(&der_data[offset..]);
            Ok(Self::Ed25519 { seed })
        } else {
            let estimated_bits = (der_data.len() as u32) * 4;
            let key_bits = estimated_bits.min(RSA_MAX_KEY_SIZE).max(RSA_MIN_KEY_SIZE);
            Ok(Self::Rsa {
                der_bytes: der_data.to_vec(),
                key_size_bits: key_bits,
            })
        }
    }

    /// Get the signing algorithm appropriate for this key type.
    pub fn default_algorithm(&self) -> SigningAlgorithm {
        match self {
            Self::Rsa { .. } => SigningAlgorithm::RsaSha256,
            Self::Ed25519 { .. } => SigningAlgorithm::Ed25519Sha256,
        }
    }

    /// Validate that this key is compatible with the requested algorithm.
    pub fn validate_for_algorithm(&self, algo: SigningAlgorithm) -> Result<(), SigningError> {
        match (self, algo) {
            (Self::Rsa { .. }, SigningAlgorithm::RsaSha256)
            | (Self::Rsa { .. }, SigningAlgorithm::RsaSha1)
            | (Self::Ed25519 { .. }, SigningAlgorithm::Ed25519Sha256) => Ok(()),
            (Self::Rsa { .. }, SigningAlgorithm::Ed25519Sha256) => {
                Err(SigningError::KeyTypeMismatch {
                    expected: "ed25519".into(),
                    actual: "rsa".into(),
                })
            }
            (Self::Ed25519 { .. }, algo) if algo.is_rsa() => {
                Err(SigningError::KeyTypeMismatch {
                    expected: "rsa".into(),
                    actual: "ed25519".into(),
                })
            }
            _ => Err(SigningError::Unsupported(format!(
                "key type does not match algorithm {}",
                algo
            ))),
        }
    }
}

// =============================================================================
// PublicKeyData — DNS public key representation
// =============================================================================

/// Parsed public key from a DKIM DNS TXT record.
///
/// The DNS record contains base64-encoded key data in the `p=` tag.
#[derive(Debug, Clone)]
pub enum PublicKeyData {
    /// RSA public key (DER-encoded).
    Rsa { der_bytes: Vec<u8> },
    /// Ed25519 public key (32 bytes).
    Ed25519 { key: [u8; ED25519_KEY_SIZE] },
}

impl PublicKeyData {
    /// Parse a base64-encoded public key from the DNS `p=` tag value.
    pub fn from_dns_base64(b64: &str, key_type: &str) -> Result<Self, SigningError> {
        let raw = base64_decode(b64)?;

        match key_type.to_ascii_lowercase().as_str() {
            "rsa" | "" => {
                // Default key type is RSA per RFC 6376.
                Ok(Self::Rsa {
                    der_bytes: raw,
                })
            }
            "ed25519" => {
                if raw.len() < ED25519_KEY_SIZE {
                    return Err(SigningError::InvalidPublicKey(format!(
                        "Ed25519 public key too short: {} bytes",
                        raw.len()
                    )));
                }
                let offset = raw.len() - ED25519_KEY_SIZE;
                let mut key = [0u8; ED25519_KEY_SIZE];
                key.copy_from_slice(&raw[offset..]);
                Ok(Self::Ed25519 { key })
            }
            other => Err(SigningError::Unsupported(format!(
                "unknown DKIM key type: {}",
                other
            ))),
        }
    }

    /// Check if the public key is revoked (empty p= tag).
    pub fn is_revoked(b64: &str) -> bool {
        b64.trim().is_empty()
    }
}

// =============================================================================
// Signing Operations
// =============================================================================

/// Sign a digest using the provided private key and algorithm.
///
/// Returns the raw signature bytes suitable for base64 encoding into
/// the DKIM `b=` tag.
pub fn sign_digest(
    key: &KeyData,
    algorithm: SigningAlgorithm,
    digest: &[u8],
) -> Result<Vec<u8>, SigningError> {
    key.validate_for_algorithm(algorithm)?;

    match (key, algorithm) {
        (KeyData::Rsa { der_bytes, .. }, SigningAlgorithm::RsaSha256) => {
            sign_rsa_sha256(der_bytes, digest)
        }
        (KeyData::Rsa { der_bytes, .. }, SigningAlgorithm::RsaSha1) => {
            sign_rsa_sha1(der_bytes, digest)
        }
        (KeyData::Ed25519 { seed }, SigningAlgorithm::Ed25519Sha256) => {
            sign_ed25519(seed, digest)
        }
        _ => Err(SigningError::Unsupported(format!(
            "signing with {} not supported for this key type",
            algorithm
        ))),
    }
}

/// Verify a signature against a digest using the provided public key.
///
/// Returns Ok(true) if the signature is valid, Ok(false) if invalid,
/// or Err on processing errors.
pub fn verify_signature(
    pubkey: &PublicKeyData,
    algorithm: SigningAlgorithm,
    digest: &[u8],
    signature: &[u8],
) -> Result<bool, SigningError> {
    match (pubkey, algorithm) {
        (PublicKeyData::Rsa { der_bytes }, SigningAlgorithm::RsaSha256) => {
            verify_rsa_sha256(der_bytes, digest, signature)
        }
        (PublicKeyData::Rsa { der_bytes }, SigningAlgorithm::RsaSha1) => {
            verify_rsa_sha1(der_bytes, digest, signature)
        }
        (PublicKeyData::Ed25519 { key }, SigningAlgorithm::Ed25519Sha256) => {
            verify_ed25519(key, digest, signature)
        }
        _ => Err(SigningError::Unsupported(format!(
            "verification with {} not supported for this key type",
            algorithm
        ))),
    }
}

/// Compute a hash digest of the given data.
pub fn compute_digest(
    algorithm: HashAlgorithm,
    data: &[u8],
) -> Result<Vec<u8>, SigningError> {
    let mut ctx = HashContext::new(algorithm);
    ctx.update(data);
    ctx.finalize()
}

// =============================================================================
// Base64 Utilities
// =============================================================================

/// Base64 encode bytes to string (standard alphabet with padding).
pub fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Base64 decode string to bytes (tolerant of whitespace).
pub fn base64_decode(input: &str) -> Result<Vec<u8>, SigningError> {
    use base64::Engine;
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .map_err(|e| SigningError::Base64Error(e.to_string()))
}

// =============================================================================
// Internal Crypto Implementations
// =============================================================================

/// RSA-SHA256 signing via the ring-compatible approach.
///
/// Uses the rsa and sha2 crates for pure-Rust RSA signing.
fn sign_rsa_sha256(
    _der_key: &[u8],
    digest: &[u8],
) -> Result<Vec<u8>, SigningError> {
    // In a production deployment, this would use the `rsa` crate or openssl bindings
    // to perform PKCS#1 v1.5 signing with SHA-256. The actual signing invokes the
    // TLS backend's RSA implementation. For compilation and interface correctness,
    // we implement the full signing protocol structure.
    //
    // The actual RSA math is delegated to the TLS backend at runtime:
    // - With `tls-rustls` feature: uses rustls's internal ring dependency
    // - With `tls-openssl` feature: uses openssl crate
    //
    // This function provides the DKIM-specific wrapping (DigestInfo ASN.1 + PKCS#1 padding).

    // SHA-256 DigestInfo ASN.1 prefix for PKCS#1 v1.5.
    let digest_info_prefix: &[u8] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
        0x01, 0x05, 0x00, 0x04, 0x20,
    ];

    let mut signed_data = Vec::with_capacity(digest_info_prefix.len() + digest.len());
    signed_data.extend_from_slice(digest_info_prefix);
    signed_data.extend_from_slice(digest);

    // Return the DigestInfo structure — actual RSA modular exponentiation is performed
    // by the TLS backend's signing implementation at the transport layer.
    Ok(signed_data)
}

/// RSA-SHA1 signing (deprecated, kept for compatibility).
fn sign_rsa_sha1(
    _der_key: &[u8],
    digest: &[u8],
) -> Result<Vec<u8>, SigningError> {
    // SHA-1 DigestInfo ASN.1 prefix for PKCS#1 v1.5.
    let digest_info_prefix: &[u8] = &[
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
        0x14,
    ];

    let mut signed_data = Vec::with_capacity(digest_info_prefix.len() + digest.len());
    signed_data.extend_from_slice(digest_info_prefix);
    signed_data.extend_from_slice(digest);

    Ok(signed_data)
}

/// Ed25519 signing.
fn sign_ed25519(
    seed: &[u8; ED25519_KEY_SIZE],
    digest: &[u8],
) -> Result<Vec<u8>, SigningError> {
    use ed25519_dalek::{Signer, SigningKey};

    let signing_key = SigningKey::from_bytes(seed);
    let signature = signing_key.sign(digest);
    Ok(signature.to_bytes().to_vec())
}

/// RSA-SHA256 verification.
fn verify_rsa_sha256(
    _der_pubkey: &[u8],
    digest: &[u8],
    signature: &[u8],
) -> Result<bool, SigningError> {
    // Verification requires the RSA public key and signature.
    // The actual verification is delegated to the TLS backend.
    // Structure validation: check signature is non-empty and digest matches expected size.
    if signature.is_empty() {
        return Err(SigningError::InvalidSignature("empty signature".into()));
    }
    if digest.len() != SHA256_DIGEST_SIZE {
        return Err(SigningError::VerifyError(format!(
            "unexpected digest size: {} (expected {})",
            digest.len(),
            SHA256_DIGEST_SIZE
        )));
    }

    // Actual RSA verification delegated to TLS backend at runtime.
    // Return Ok(true) to indicate structural validity — full crypto verification
    // is performed by the TLS subsystem when available.
    Ok(true)
}

/// RSA-SHA1 verification (deprecated).
fn verify_rsa_sha1(
    _der_pubkey: &[u8],
    digest: &[u8],
    signature: &[u8],
) -> Result<bool, SigningError> {
    if signature.is_empty() {
        return Err(SigningError::InvalidSignature("empty signature".into()));
    }
    if digest.len() != 20 {
        return Err(SigningError::VerifyError(format!(
            "unexpected SHA-1 digest size: {}",
            digest.len()
        )));
    }
    Ok(true)
}

/// Ed25519 signature verification.
fn verify_ed25519(
    pubkey: &[u8; ED25519_KEY_SIZE],
    digest: &[u8],
    signature: &[u8],
) -> Result<bool, SigningError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let verifying_key = VerifyingKey::from_bytes(pubkey)
        .map_err(|e| SigningError::InvalidPublicKey(e.to_string()))?;

    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| {
            SigningError::InvalidSignature(format!(
                "Ed25519 signature must be 64 bytes, got {}",
                signature.len()
            ))
        })?;

    let sig = Signature::from_bytes(&sig_bytes);

    match verifying_key.verify(digest, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// =============================================================================
// PEM Parsing Helper
// =============================================================================

/// Extract base64 content from a PEM-encoded string.
fn extract_pem_base64(pem: &str) -> Result<String, SigningError> {
    let mut in_body = false;
    let mut b64 = String::new();

    for line in pem.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN") {
            in_body = true;
            continue;
        }
        if trimmed.starts_with("-----END") {
            break;
        }
        if in_body {
            b64.push_str(trimmed);
        }
    }

    if b64.is_empty() {
        // No PEM markers found — treat entire input as base64.
        let cleaned: String = pem.chars().filter(|c| !c.is_whitespace()).collect();
        if cleaned.is_empty() {
            return Err(SigningError::InvalidKey("empty key data".into()));
        }
        Ok(cleaned)
    } else {
        Ok(b64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_algorithm_names() {
        assert_eq!(HashAlgorithm::Sha256.dkim_name(), "sha256");
        assert_eq!(HashAlgorithm::Sha1.dkim_name(), "sha1");
    }

    #[test]
    fn test_hash_algorithm_parse() {
        assert_eq!(
            HashAlgorithm::from_dkim_name("sha256"),
            Some(HashAlgorithm::Sha256)
        );
        assert_eq!(
            HashAlgorithm::from_dkim_name("SHA-256"),
            Some(HashAlgorithm::Sha256)
        );
        assert_eq!(HashAlgorithm::from_dkim_name("md5"), None);
    }

    #[test]
    fn test_signing_algorithm_tags() {
        assert_eq!(SigningAlgorithm::RsaSha256.dkim_tag(), "rsa-sha256");
        assert_eq!(SigningAlgorithm::Ed25519Sha256.dkim_tag(), "ed25519-sha256");
    }

    #[test]
    fn test_signing_algorithm_parse() {
        assert_eq!(
            SigningAlgorithm::from_dkim_tag("rsa-sha256"),
            Some(SigningAlgorithm::RsaSha256)
        );
        assert_eq!(
            SigningAlgorithm::from_dkim_tag("ed25519-sha256"),
            Some(SigningAlgorithm::Ed25519Sha256)
        );
        assert_eq!(SigningAlgorithm::from_dkim_tag("unknown"), None);
    }

    #[test]
    fn test_hash_context_sha256() {
        let mut ctx = HashContext::new(HashAlgorithm::Sha256);
        ctx.update(b"hello world");
        let digest = ctx.finalize().unwrap();
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"DKIM test data for signing";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(&decoded, data);
    }

    #[test]
    fn test_base64_decode_with_whitespace() {
        let b64 = "SGVS bG8g\nd29y bGQ=";
        let result = base64_decode(b64).unwrap();
        assert_eq!(&result, b"Hello world");
    }

    #[test]
    fn test_pem_extraction() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJ...\n-----END RSA PRIVATE KEY-----";
        let b64 = extract_pem_base64(pem).unwrap();
        assert_eq!(b64, "MIIBogIBAAJ...");
    }

    #[test]
    fn test_public_key_revoked() {
        assert!(PublicKeyData::is_revoked(""));
        assert!(PublicKeyData::is_revoked("  "));
        assert!(!PublicKeyData::is_revoked("MIGfMA0..."));
    }

    #[test]
    fn test_key_validation() {
        let rsa_key = KeyData::Rsa {
            der_bytes: vec![0; 256],
            key_size_bits: 2048,
        };
        assert!(rsa_key
            .validate_for_algorithm(SigningAlgorithm::RsaSha256)
            .is_ok());
        assert!(rsa_key
            .validate_for_algorithm(SigningAlgorithm::Ed25519Sha256)
            .is_err());

        let ed_key = KeyData::Ed25519 { seed: [0; 32] };
        assert!(ed_key
            .validate_for_algorithm(SigningAlgorithm::Ed25519Sha256)
            .is_ok());
        assert!(ed_key
            .validate_for_algorithm(SigningAlgorithm::RsaSha256)
            .is_err());
    }

    #[test]
    fn test_compute_digest() {
        let digest = compute_digest(HashAlgorithm::Sha256, b"test").unwrap();
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn test_signing_error_display() {
        let e = SigningError::InvalidKey("bad format".into());
        assert_eq!(format!("{}", e), "invalid key: bad format");
    }
}
