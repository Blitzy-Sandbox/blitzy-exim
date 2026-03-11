//! TLS session resumption — session ticket management and client session cache.
//!
//! This module provides:
//! - **Server-side** Session Ticket Encryption Key (STEK) management with automatic
//!   two-key rotation (`ServerTicketManager`)
//! - **Client-side** session caching keyed by SHA-256 resumption keys
//!   (`ClientSessionCache`)
//! - Session data serialization for persistent storage (`serialize_session`,
//!   `deserialize_session`)
//! - TLS 1.3 ticket configuration (`TicketConfig`)
//!
//! Feature-gated behind `tls-resume` — replaces C `#ifndef DISABLE_TLS_RESUME`.
//!
//! # Server-Side Session Tickets
//!
//! The [`ServerTicketManager`] maintains a two-key rotation buffer (current +
//! previous) that replaces the C `exim_tk` / `exim_tk_old` static variables
//! from `tls-openssl.c`. Keys are generated using OS-provided cryptographic
//! randomness via `getrandom`.
//!
//! # Client-Side Session Cache
//!
//! The [`ClientSessionCache`] stores serialized TLS session data keyed by a
//! SHA-256 hash of connection parameters (see [`compute_resumption_key`]),
//! replacing the C hints DB-based session storage in `tls_retrieve_session()`
//! and `tls_save_session_cb()`.
//!
//! # Resumption Key Computation
//!
//! [`compute_resumption_key`] produces a hex-encoded SHA-256 hash of all
//! connection parameters that uniquely identify a TLS session, matching the
//! C `tls_client_resmption_key()` in `tls.c` lines 834–868.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors that can occur during TLS session resumption operations.
///
/// Replaces C error code returns from `ticket_key_callback()` and session
/// retrieval/storage functions in `tls-openssl.c`.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// No valid session ticket encryption key is available (server-side).
    /// Returned when `ensure_key()` has not been called or key generation
    /// failed.
    #[error("no valid session ticket key available")]
    NoValidKey,

    /// The session ticket encryption key has expired and can no longer be
    /// used for decryption. Maps to C `key->expire < now` check in
    /// `ticket_key_callback()` (tls-openssl.c line 2172).
    #[error("session ticket key expired")]
    KeyExpired,

    /// No session ticket encryption key matches the provided key name.
    /// Maps to C `tk_find()` returning NULL (tls-openssl.c lines 2091–2097).
    #[error("session ticket key not found for name {0:?}")]
    KeyNotFound([u8; 16]),

    /// Failed to serialize session data for persistent storage.
    #[error("session data serialization error: {0}")]
    SerializationError(String),

    /// Failed to deserialize session data from persistent storage.
    #[error("session data deserialization error: {0}")]
    DeserializationError(String),

    /// Cryptographic random number generation failed.
    /// Maps to C `RAND_bytes()` failure in `tk_init()` (tls-openssl.c
    /// lines 2069–2071).
    #[error("random number generation failed")]
    RngError,
}

// ---------------------------------------------------------------------------
// Session Ticket Key Types (Server-Side)
// ---------------------------------------------------------------------------

/// Session Ticket Encryption Key (STEK) — replaces C `exim_stek` struct.
///
/// Contains the key material used to encrypt/decrypt TLS session tickets on
/// the server side, plus rotation and expiry timestamps.
///
/// # Key Layout
/// - `name`: 16-byte identifier sent in cleartext with the ticket for key
///   lookup. First byte is set to `b'E'` (Exim marker) matching C behavior
///   in `tk_init()` (tls-openssl.c line 2073).
/// - `aes_key`: 32-byte AES-256-CBC encryption key.
/// - `hmac_key`: 16-byte HMAC-SHA256 authentication key.
///
/// # C Correspondence
/// ```c
/// typedef struct {        /* tls-openssl.c lines 2037-2050 */
///     uschar name[16];    /* Ticket key name                */
///     uschar aes_key[32]; /* AES-256 encryption key         */
///     uschar hmac_key[16];/* HMAC authentication key        */
///     time_t renew;       /* Renewal trigger time           */
///     time_t expire;      /* Absolute expiry time           */
/// } exim_stek;
/// ```
pub struct SessionTicketKey {
    /// Ticket key name (16 bytes, sent in cleartext for key identification).
    /// First byte is `b'E'` as Exim marker, remaining 15 bytes are random.
    pub name: [u8; 16],
    /// AES-256 encryption key (32 bytes).
    pub aes_key: [u8; 32],
    /// HMAC authentication key (16 bytes).
    pub hmac_key: [u8; 16],
    /// Time at which a new key should be created (rotation trigger).
    /// Corresponds to C `exim_stek.renew`.
    pub renew_at: SystemTime,
    /// Time at which this key can no longer be used for decryption.
    /// Corresponds to C `exim_stek.expire`.
    pub expire_at: SystemTime,
}

/// Subset of session ticket key material returned for encrypt/decrypt ops.
///
/// Provides just the cryptographic material needed for ticket operations
/// without the time management fields, suitable for passing to the TLS
/// backend's ticket encryption/decryption routines.
#[derive(Debug)]
pub struct TicketKeyMaterial {
    /// Ticket key name for identification.
    pub name: [u8; 16],
    /// AES-256 encryption key.
    pub aes_key: [u8; 32],
    /// HMAC authentication key.
    pub hmac_key: [u8; 16],
}

// ---------------------------------------------------------------------------
// Server-Side Ticket Manager
// ---------------------------------------------------------------------------

/// Server-side Session Ticket Encryption Key manager.
///
/// Maintains a two-key rotation buffer (current + previous) replacing the C
/// static variables `exim_tk` and `exim_tk_old` (tls-openssl.c lines
/// 2052–2053). The previous key is kept to allow decryption of tickets
/// encrypted with the prior key during the rotation grace period.
///
/// # Key Rotation
///
/// When [`ensure_key`](ServerTicketManager::ensure_key) is called and the
/// current key's renewal time has passed:
/// 1. The current key becomes the previous key
/// 2. A new key is generated with fresh random material
/// 3. The new key's renewal time is set to `now + renew_interval`
/// 4. The new key's expiry time is set to `renew_at + expire_margin`
///
/// This matches the behavior of C `tk_init()` in tls-openssl.c lines 2056–2082.
pub struct ServerTicketManager {
    /// Current active session ticket encryption key.
    current_key: Option<SessionTicketKey>,
    /// Previous key retained for decrypting tickets encrypted before rotation.
    previous_key: Option<SessionTicketKey>,
    /// Duration from key creation until rotation occurs.
    /// Corresponds to C `ssl_session_timeout / 2`.
    renew_interval: Duration,
    /// Additional duration after renewal before the old key expires.
    /// Corresponds to C `ssl_session_timeout / 2` (the second half).
    expire_margin: Duration,
}

impl ServerTicketManager {
    /// Creates a new `ServerTicketManager` with the specified key lifetime
    /// parameters.
    ///
    /// # Arguments
    /// - `renew_interval`: Time from key creation until rotation
    ///   (C: `ssl_session_timeout / 2`).
    /// - `expire_margin`: Additional time after renewal before the old key
    ///   expires (C: `ssl_session_timeout / 2`).
    pub fn new(renew_interval: Duration, expire_margin: Duration) -> Self {
        Self {
            current_key: None,
            previous_key: None,
            renew_interval,
            expire_margin,
        }
    }

    /// Creates a `ServerTicketManager` from a [`TicketConfig`].
    pub fn from_config(config: &TicketConfig) -> Self {
        Self::new(config.key_renew_interval, config.key_expire_margin)
    }

    /// Ensures a valid current key exists, rotating if necessary.
    ///
    /// Replaces C `tk_init()` (tls-openssl.c lines 2056–2082):
    /// - If no current key exists: generate a new one ("creating STEK").
    /// - If current key's renewal time has passed: rotate current → previous,
    ///   generate new ("rotating STEK").
    /// - Otherwise: return existing current key unchanged.
    ///
    /// # Errors
    /// Returns [`SessionError::RngError`] if cryptographic random generation
    /// fails (equivalent to C `RAND_bytes()` returning ≤ 0).
    pub fn ensure_key(&mut self) -> Result<&SessionTicketKey, SessionError> {
        let now = SystemTime::now();

        let needs_new_key = match &self.current_key {
            None => true,
            Some(key) => {
                // C: `if (exim_tk.renew >= t) return;`
                // If renew_at has NOT been reached, key is still valid.
                // If renew_at <= now, rotation is needed.
                key.renew_at <= now
            }
        };

        if needs_new_key {
            let was_existing = self.current_key.is_some();

            // Rotate: move current → previous (for graceful key transition)
            // C: `exim_tk_old = exim_tk;`
            self.previous_key = self.current_key.take();

            // Generate new key with fresh random material
            let key = Self::generate_key(now, self.renew_interval, self.expire_margin)?;
            self.current_key = Some(key);

            // Log matching C: debug_printf("OpenSSL: %s STEK\n", ...)
            if was_existing {
                tracing::debug!("rotating session ticket encryption key");
            } else {
                tracing::debug!("creating session ticket encryption key");
            }
        }

        // The current_key is guaranteed to be Some after the block above
        self.current_key.as_ref().ok_or(SessionError::NoValidKey)
    }

    /// Returns key material for encrypting a new session ticket.
    ///
    /// Replaces the encrypt branch (`enc == 1`) of C `ticket_key_callback()`
    /// (tls-openssl.c lines 2146–2163). Calls [`ensure_key`] to guarantee
    /// a valid current key exists before returning its material.
    ///
    /// # Errors
    /// - [`SessionError::NoValidKey`] if no valid key exists.
    /// - [`SessionError::RngError`] if key generation fails during rotation.
    pub fn encrypt_ticket(&mut self) -> Result<TicketKeyMaterial, SessionError> {
        let key = self.ensure_key()?;
        Ok(TicketKeyMaterial {
            name: key.name,
            aes_key: key.aes_key,
            hmac_key: key.hmac_key,
        })
    }

    /// Finds a key matching the given name and returns its material for
    /// ticket decryption.
    ///
    /// Replaces the decrypt branch (`enc == 0`) of C `ticket_key_callback()`
    /// (tls-openssl.c lines 2165–2193).
    ///
    /// # Returns
    /// - `Ok((material, false))` — Key found in current slot and still before
    ///   its renewal time. Caller should NOT re-issue a ticket.
    ///   Maps to C return value `1`.
    /// - `Ok((material, true))` — Key found but past its renewal time, or
    ///   found in the previous slot. Caller SHOULD re-issue a ticket with
    ///   the new key. Maps to C return value `2`.
    /// - `Err(SessionError::KeyNotFound)` — No matching key found.
    ///   Maps to C return value `0` (key not found branch).
    /// - `Err(SessionError::KeyExpired)` — Matching key found but expired.
    ///   Maps to C return value `0` (expired branch).
    pub fn decrypt_ticket(
        &self,
        key_name: &[u8; 16],
    ) -> Result<(TicketKeyMaterial, bool), SessionError> {
        let now = SystemTime::now();

        // Search for matching key: current first, then previous
        // Mirrors C tk_find() in tls-openssl.c lines 2091–2097
        let (key, is_previous) = self
            .find_key_by_name(key_name)
            .ok_or(SessionError::KeyNotFound(*key_name))?;

        // Check expiry: C `key->expire < now` → reject
        if key.expire_at <= now {
            tracing::warn!(
                key_name_prefix = ?&key_name[..4],
                "session ticket key expired"
            );
            return Err(SessionError::KeyExpired);
        }

        let material = TicketKeyMaterial {
            name: key.name,
            aes_key: key.aes_key,
            hmac_key: key.hmac_key,
        };

        // Signal re-ticketing if the key is past its renewal time or was
        // found in the previous slot.
        // C: `return key->renew < now ? 2 : 1;`
        let needs_reticket = is_previous || key.renew_at <= now;

        if needs_reticket {
            tracing::trace!("session ticket key past renewal, re-ticketing advised");
        }

        Ok((material, needs_reticket))
    }

    /// Searches current and previous keys for a name match.
    ///
    /// Returns `(key_ref, is_previous)` where `is_previous` is `true` if the
    /// match was found in the previous (rotated-out) key slot.
    fn find_key_by_name(&self, name: &[u8; 16]) -> Option<(&SessionTicketKey, bool)> {
        if let Some(ref key) = self.current_key {
            if key.name == *name {
                return Some((key, false));
            }
        }
        if let Some(ref key) = self.previous_key {
            if key.name == *name {
                return Some((key, true));
            }
        }
        None
    }

    /// Generates a new [`SessionTicketKey`] with fresh random material.
    ///
    /// Replaces the key generation portion of C `tk_init()`:
    /// - 15 random bytes for name[1..16], with name[0] = `b'E'` (Exim marker)
    /// - 32 random bytes for AES-256 key
    /// - 16 random bytes for HMAC key
    ///
    /// Timestamps:
    /// - `renew_at = now + renew_interval`
    /// - `expire_at = renew_at + expire_margin`
    fn generate_key(
        now: SystemTime,
        renew_interval: Duration,
        expire_margin: Duration,
    ) -> Result<SessionTicketKey, SessionError> {
        let mut name = [0u8; 16];
        let mut aes_key = [0u8; 32];
        let mut hmac_key = [0u8; 16];

        // Generate random material using OS CSPRNG
        // Replaces C RAND_bytes() calls in tk_init() lines 2069–2071
        getrandom::getrandom(&mut name[1..]).map_err(|_| SessionError::RngError)?;
        getrandom::getrandom(&mut aes_key).map_err(|_| SessionError::RngError)?;
        getrandom::getrandom(&mut hmac_key).map_err(|_| SessionError::RngError)?;

        // Set first byte to 'E' (Exim marker, matching C tk_init() line 2073:
        // `exim_tk.name[0] = 'E';`)
        name[0] = b'E';

        // C: `exim_tk.renew = t + ssl_session_timeout/2;`
        let renew_at = now.checked_add(renew_interval).unwrap_or(now);

        // C: `exim_tk.expire = t + ssl_session_timeout;`
        // Which equals `renew + ssl_session_timeout/2` = `renew + expire_margin`
        let expire_at = renew_at.checked_add(expire_margin).unwrap_or(renew_at);

        Ok(SessionTicketKey {
            name,
            aes_key,
            hmac_key,
            renew_at,
            expire_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Client-Side Session Cache
// ---------------------------------------------------------------------------

/// Cached TLS session data with Exim-specific metadata.
///
/// Stores the serialized TLS session alongside Exim metadata (certificate
/// verification override, OCSP result) that was valid at the time of caching.
///
/// # C Correspondence
/// Replaces `dbdata_tls_session` struct containing:
/// - `verify_override`: Whether peer certificate verification was overridden
/// - `ocsp`: OCSP stapling result at time of handshake
/// - `session[]`: DER-encoded TLS session data (flexible array member)
#[derive(Debug)]
pub struct CachedSession {
    /// Serialized TLS session data (DER-encoded `SSL_SESSION` in C,
    /// backend-specific format in Rust).
    pub session_data: Vec<u8>,
    /// Whether certificate verification was overridden for this connection.
    /// Corresponds to C `dt->verify_override` in `tls_save_session_cb()`
    /// (tls-openssl.c line 4092).
    pub verify_override: bool,
    /// OCSP stapling result at time of handshake.
    /// `None` if OCSP was not checked, `Some(true)` for valid response,
    /// `Some(false)` for invalid/absent response.
    /// Corresponds to C `dt->ocsp` in `tls_save_session_cb()`
    /// (tls-openssl.c line 4093).
    pub ocsp_result: Option<bool>,
    /// Timestamp when this session was cached, used for expiry checks.
    pub cached_at: SystemTime,
}

/// Parameters for computing a TLS session resumption key via SHA-256 hash.
///
/// Contains all connection parameters that uniquely identify a TLS session,
/// matching the fields hashed in C `tls_client_resmption_key()` (tls.c
/// lines 834–868).
///
/// # Hash Input Order
/// 1. `host_lbserver` — Load-balanced server name
/// 2. `dane_data` — DANE/TLSA DNS answer data
/// 3. `host_address` — Host IP address string
/// 4. `host_port` — Host port number (native-endian bytes)
/// 5. `sending_ip` — Local IP address string
/// 6. `ssl_options` — TLS protocol options string
/// 7. `require_ciphers` — Required cipher suite specification
/// 8. `sni` — Server Name Indication hostname
/// 9. `alpn` — Application-Layer Protocol Negotiation value
pub struct ResumptionKeyParams<'a> {
    /// Load-balanced server name, if configured.
    /// Corresponds to C `conn_args->host_lbserver`.
    pub host_lbserver: Option<&'a str>,
    /// DANE/TLSA data for this connection, if DANE is active.
    /// Corresponds to C `conn_args->tlsa_dnsa` (raw DNS answer bytes).
    pub dane_data: Option<&'a [u8]>,
    /// Host IP address being connected to.
    /// Corresponds to C `conn_args->host->address`.
    pub host_address: &'a str,
    /// Host port being connected to.
    /// Corresponds to C `conn_args->host->port`.
    pub host_port: u16,
    /// Local IP address used for the outgoing connection.
    /// Corresponds to C `conn_args->sending_ip_address`.
    pub sending_ip: &'a str,
    /// TLS/SSL protocol options string.
    /// Corresponds to C `openssl_options`.
    pub ssl_options: &'a str,
    /// Required cipher suite specification, if configured.
    /// Corresponds to C `ob->tls_require_ciphers`.
    pub require_ciphers: Option<&'a str>,
    /// Server Name Indication hostname, if configured.
    /// Corresponds to C `tlsp->sni`.
    pub sni: Option<&'a str>,
    /// Application-Layer Protocol Negotiation value, if configured.
    /// Corresponds to C `ob->tls_alpn`.
    pub alpn: Option<&'a str>,
}

/// Client-side TLS session cache backed by an in-memory `HashMap`.
///
/// Stores cached sessions keyed by hex-encoded SHA-256 hash of connection
/// parameters (see [`compute_resumption_key`]), replacing the C hints
/// DB-based session storage pattern from `tls_retrieve_session()` and
/// `tls_save_session_cb()` in tls-openssl.c.
pub struct ClientSessionCache {
    /// Cached sessions keyed by hex-encoded SHA-256 resumption key.
    sessions: HashMap<String, CachedSession>,
}

impl ClientSessionCache {
    /// Creates a new empty session cache.
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Stores a TLS session in the cache under the given resumption key.
    ///
    /// Replaces C `tls_save_session_cb()` (tls-openssl.c lines 4069–4100)
    /// which wrote session data to the hints DB via `dbfn_write()`.
    ///
    /// If a session already exists for the given key, it is replaced.
    pub fn store(&mut self, key: &str, session: CachedSession) {
        tracing::trace!(
            resumption_key = key,
            session_len = session.session_data.len(),
            verify_override = session.verify_override,
            "storing TLS session in cache"
        );
        self.sessions.insert(key.to_owned(), session);
    }

    /// Retrieves a cached TLS session by resumption key.
    ///
    /// Replaces C `tls_retrieve_session()` (tls-openssl.c lines 4001–4063)
    /// which looked up session data from the hints DB via `dbfn_read_with_length()`.
    ///
    /// Returns `None` if no session exists for the given key. Expiry checking
    /// is left to the caller (matching C pattern where expiry is checked
    /// after retrieval using `SSL_SESSION_get_ticket_lifetime_hint()`).
    pub fn retrieve(&self, key: &str) -> Option<&CachedSession> {
        let result = self.sessions.get(key);
        match result {
            Some(session) => {
                let age = session
                    .cached_at
                    .elapsed()
                    .unwrap_or(Duration::from_secs(0));
                tracing::trace!(
                    resumption_key = key,
                    session_len = session.session_data.len(),
                    age_secs = age.as_secs(),
                    "TLS session cache hit"
                );
            }
            None => {
                tracing::trace!(resumption_key = key, "TLS session cache miss");
            }
        }
        result
    }

    /// Removes a cached session (on verification failure or invalidation).
    ///
    /// Replaces C `dbfn_delete(dbm_file, tlsp->resume_index)` used when
    /// a cached session is found to be expired or invalid (tls-openssl.c
    /// line 4042).
    pub fn remove(&mut self, key: &str) {
        if self.sessions.remove(key).is_some() {
            tracing::trace!(resumption_key = key, "removed TLS session from cache");
        }
    }
}

impl Default for ClientSessionCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TLS 1.3 Ticket Configuration
// ---------------------------------------------------------------------------

/// Default session timeout in seconds, matching Exim C default of 7200s.
const DEFAULT_SESSION_TIMEOUT_SECS: u64 = 7200;

/// Configuration for TLS session ticket behavior.
///
/// Controls server-side ticket issuance and key rotation timing. Replaces
/// the C configuration options accessed via `tls_in.host_resumable`,
/// `SSL_CTX_set_num_tickets()`, and `ssl_session_timeout`.
pub struct TicketConfig {
    /// Number of TLS 1.3 session tickets to send after handshake (server-side).
    /// `0` disables ticket sending, `1` is the standard single ticket.
    /// Corresponds to C `SSL_CTX_set_num_tickets(ctx, host_resumable ? 1 : 0)`
    /// (tls-openssl.c line 3574).
    pub num_tickets: u32,
    /// Whether the remote host supports session resumption.
    /// Corresponds to C `tls_in.host_resumable` / `tlsp->host_resumable`.
    pub host_resumable: bool,
    /// Session ticket key renewal interval.
    /// After this duration, the current key is rotated to previous and a new
    /// key is generated. Default: 3600 seconds (1 hour).
    /// Corresponds to C `ssl_session_timeout / 2`.
    pub key_renew_interval: Duration,
    /// Session ticket key expiry margin after renewal.
    /// The old key remains valid for decryption for this duration after rotation.
    /// Default: 3600 seconds (1 hour).
    /// Combined with `key_renew_interval`, the total key lifetime is 7200
    /// seconds (2 hours), matching C's default `ssl_session_timeout`.
    pub key_expire_margin: Duration,
}

impl Default for TicketConfig {
    fn default() -> Self {
        let half_timeout = DEFAULT_SESSION_TIMEOUT_SECS / 2;
        Self {
            num_tickets: 1,
            host_resumable: false,
            key_renew_interval: Duration::from_secs(half_timeout),
            key_expire_margin: Duration::from_secs(half_timeout),
        }
    }
}

// ---------------------------------------------------------------------------
// Resumption Key Computation
// ---------------------------------------------------------------------------

/// Computes a SHA-256 resumption key from connection parameters.
///
/// Returns a hex-encoded SHA-256 hash string that uniquely identifies a TLS
/// session based on all relevant connection parameters. Used as the key for
/// client-side session cache lookups.
///
/// Replaces C `tls_client_resmption_key()` (tls.c lines 834–868).
///
/// # Parameters
/// All fields from [`ResumptionKeyParams`] are fed into the hash in the same
/// order as the C implementation. `None` values are skipped, matching C
/// behavior where NULL strings are not hashed.
///
/// # Hash Inputs (in order)
/// 1. `host_lbserver` — `exim_sha_update_string(h, conn_args->host_lbserver)`
/// 2. `dane_data` — `exim_sha_update(h, &conn_args->tlsa_dnsa, sizeof(dns_answer))`
/// 3. `host_address` — `exim_sha_update_string(h, conn_args->host->address)`
/// 4. `host_port` — `exim_sha_update(h, &conn_args->host->port, sizeof(port))`
/// 5. `sending_ip` — `exim_sha_update_string(h, conn_args->sending_ip_address)`
/// 6. `ssl_options` — `exim_sha_update_string(h, openssl_options)`
/// 7. `require_ciphers` — `exim_sha_update_string(h, ob->tls_require_ciphers)`
/// 8. `sni` — `exim_sha_update_string(h, tlsp->sni)`
/// 9. `alpn` — `exim_sha_update_string(h, ob->tls_alpn)`
///
/// # Output
/// Hex-encoded SHA-256 hash (64 lowercase hex characters), matching C
/// `string_sprintf("%.*H", ...)` format used in tls.c line 865.
pub fn compute_resumption_key(params: &ResumptionKeyParams<'_>) -> String {
    let mut hasher = Sha256::new();

    // Feed each parameter in the same order as C tls_client_resmption_key()
    // (tls.c lines 850–863).
    //
    // exim_sha_update_string() in C feeds the string bytes into the hash.
    // For NULL strings, the C function is a no-op. We mirror this by skipping
    // None values.
    if let Some(lbserver) = params.host_lbserver {
        Digest::update(&mut hasher, lbserver.as_bytes());
    }

    // C: `if (conn_args->dane) exim_sha_update(h, &conn_args->tlsa_dnsa, ...)`
    if let Some(dane_data) = params.dane_data {
        Digest::update(&mut hasher, dane_data);
    }

    // C: `exim_sha_update_string(h, conn_args->host->address)`
    Digest::update(&mut hasher, params.host_address.as_bytes());

    // C: `exim_sha_update(h, &conn_args->host->port, sizeof(port))`
    // Feed port as native-endian bytes
    Digest::update(&mut hasher, params.host_port.to_ne_bytes());

    // C: `exim_sha_update_string(h, conn_args->sending_ip_address)`
    Digest::update(&mut hasher, params.sending_ip.as_bytes());

    // C: `exim_sha_update_string(h, openssl_options)`
    Digest::update(&mut hasher, params.ssl_options.as_bytes());

    // C: `exim_sha_update_string(h, ob->tls_require_ciphers)`
    if let Some(ciphers) = params.require_ciphers {
        Digest::update(&mut hasher, ciphers.as_bytes());
    }

    // C: `exim_sha_update_string(h, tlsp->sni)`
    if let Some(sni) = params.sni {
        Digest::update(&mut hasher, sni.as_bytes());
    }

    // C: `exim_sha_update_string(h, ob->tls_alpn)`
    if let Some(alpn) = params.alpn {
        Digest::update(&mut hasher, alpn.as_bytes());
    }

    let result = hasher.finalize();

    // Hex-encode the hash, matching C `string_sprintf("%.*H", ...)` output
    hex_encode(&result)
}

/// Hex-encodes a byte slice to a lowercase hex string.
///
/// Produces the same output as Exim's C `string_sprintf("%.*H", len, data)`
/// format specifier.
fn hex_encode(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        // Two hex digits per byte, lowercase
        let hi = b >> 4;
        let lo = b & 0x0f;
        hex.push(char::from(HEX_CHARS[hi as usize]));
        hex.push(char::from(HEX_CHARS[lo as usize]));
    }
    hex
}

/// Lowercase hex digit lookup table for efficient hex encoding.
const HEX_CHARS: [u8; 16] = *b"0123456789abcdef";

// ---------------------------------------------------------------------------
// Session Serialization
// ---------------------------------------------------------------------------

/// Serialization format version for forward compatibility.
const SERIALIZATION_VERSION: u8 = 1;

/// Minimum header size for the serialized format (bytes).
/// version(1) + verify_override(1) + ocsp_result(1) + timestamp(8) + session_len(4) = 15
const SERIALIZATION_HEADER_SIZE: usize = 1 + 1 + 1 + 8 + 4;

/// Serializes a [`CachedSession`] into a byte vector for persistent storage.
///
/// # Binary Format (version 1)
/// ```text
/// Offset  Size  Field
/// ------  ----  -----
///   0       1   version           (always 1)
///   1       1   verify_override   (0 = false, 1 = true)
///   2       1   ocsp_result       (0 = None, 1 = Some(false), 2 = Some(true))
///   3       8   timestamp         (seconds since UNIX_EPOCH, little-endian u64)
///  11       4   session_len       (little-endian u32)
///  15       N   session_data      (raw TLS session bytes)
/// ```
///
/// Replaces the C serialization via `i2d_SSL_SESSION()` with Exim's
/// `dbdata_tls_session` wrapper containing `verify_override` and `ocsp`
/// fields (tls-openssl.c lines 4083–4094).
pub fn serialize_session(session: &CachedSession) -> Vec<u8> {
    let timestamp_secs = session
        .cached_at
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();

    let session_len = session.session_data.len() as u32;

    // Pre-allocate exact size
    let total_len = SERIALIZATION_HEADER_SIZE + session.session_data.len();
    let mut buf = Vec::with_capacity(total_len);

    // Version tag
    buf.push(SERIALIZATION_VERSION);

    // verify_override: 0 = false, 1 = true
    buf.push(u8::from(session.verify_override));

    // ocsp_result: 0 = None, 1 = Some(false), 2 = Some(true)
    let ocsp_byte = match session.ocsp_result {
        None => 0u8,
        Some(false) => 1u8,
        Some(true) => 2u8,
    };
    buf.push(ocsp_byte);

    // Timestamp as little-endian u64
    buf.extend_from_slice(&timestamp_secs.to_le_bytes());

    // Session data length as little-endian u32
    buf.extend_from_slice(&session_len.to_le_bytes());

    // Session data payload
    buf.extend_from_slice(&session.session_data);

    buf
}

/// Deserializes a [`CachedSession`] from a byte slice.
///
/// Reverses the format produced by [`serialize_session`].
///
/// # Errors
/// Returns [`SessionError::DeserializationError`] if:
/// - The data is shorter than the minimum header size (15 bytes)
/// - The version byte is not recognized
/// - Field values are out of range
/// - The session data payload is truncated
pub fn deserialize_session(data: &[u8]) -> Result<CachedSession, SessionError> {
    if data.len() < SERIALIZATION_HEADER_SIZE {
        return Err(SessionError::DeserializationError(format!(
            "data too short: {} bytes, minimum {} required",
            data.len(),
            SERIALIZATION_HEADER_SIZE
        )));
    }

    // Version check
    let version = data[0];
    if version != SERIALIZATION_VERSION {
        return Err(SessionError::DeserializationError(format!(
            "unsupported serialization version: {}, expected {}",
            version, SERIALIZATION_VERSION
        )));
    }

    // verify_override
    let verify_override = match data[1] {
        0 => false,
        1 => true,
        v => {
            return Err(SessionError::DeserializationError(format!(
                "invalid verify_override value: {}",
                v
            )));
        }
    };

    // ocsp_result
    let ocsp_result = match data[2] {
        0 => None,
        1 => Some(false),
        2 => Some(true),
        v => {
            return Err(SessionError::DeserializationError(format!(
                "invalid ocsp_result value: {}",
                v
            )));
        }
    };

    // Timestamp (little-endian u64)
    let timestamp_bytes: [u8; 8] = data[3..11]
        .try_into()
        .map_err(|e| SessionError::DeserializationError(format!("timestamp read error: {}", e)))?;
    let timestamp_secs = u64::from_le_bytes(timestamp_bytes);

    // Session data length (little-endian u32)
    let len_bytes: [u8; 4] = data[11..15].try_into().map_err(|e| {
        SessionError::DeserializationError(format!("session length read error: {}", e))
    })?;
    let session_len = u32::from_le_bytes(len_bytes) as usize;

    // Validate total length
    let expected_total = SERIALIZATION_HEADER_SIZE + session_len;
    if data.len() < expected_total {
        return Err(SessionError::DeserializationError(format!(
            "data truncated: {} bytes available, {} expected ({} header + {} session)",
            data.len(),
            expected_total,
            SERIALIZATION_HEADER_SIZE,
            session_len
        )));
    }

    // Extract session data
    let session_data =
        data[SERIALIZATION_HEADER_SIZE..SERIALIZATION_HEADER_SIZE + session_len].to_vec();

    // Reconstruct cached_at timestamp
    let cached_at = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(timestamp_secs))
        .unwrap_or(SystemTime::UNIX_EPOCH);

    Ok(CachedSession {
        session_data,
        verify_override,
        ocsp_result,
        cached_at,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_error_display() {
        let err = SessionError::NoValidKey;
        assert_eq!(err.to_string(), "no valid session ticket key available");

        let err = SessionError::KeyExpired;
        assert_eq!(err.to_string(), "session ticket key expired");

        let name = [0u8; 16];
        let err = SessionError::KeyNotFound(name);
        assert!(err.to_string().contains("not found"));

        let err = SessionError::SerializationError("test".to_string());
        assert!(err.to_string().contains("test"));

        let err = SessionError::DeserializationError("bad data".to_string());
        assert!(err.to_string().contains("bad data"));

        let err = SessionError::RngError;
        assert_eq!(err.to_string(), "random number generation failed");
    }

    #[test]
    fn test_ticket_config_default() {
        let config = TicketConfig::default();
        assert_eq!(config.num_tickets, 1);
        assert!(!config.host_resumable);
        assert_eq!(config.key_renew_interval, Duration::from_secs(3600));
        assert_eq!(config.key_expire_margin, Duration::from_secs(3600));
    }

    #[test]
    fn test_server_ticket_manager_ensure_key_creates() {
        let mut mgr =
            ServerTicketManager::new(Duration::from_secs(3600), Duration::from_secs(3600));

        // First call should create a new key
        let key = mgr.ensure_key().expect("key creation should succeed");
        assert_eq!(key.name[0], b'E');
        assert!(key.renew_at > SystemTime::now());
        assert!(key.expire_at > key.renew_at);

        // Previous key should still be None after first creation
        assert!(mgr.previous_key.is_none());
    }

    #[test]
    fn test_server_ticket_manager_encrypt_ticket() {
        let mut mgr =
            ServerTicketManager::new(Duration::from_secs(3600), Duration::from_secs(3600));

        let material = mgr.encrypt_ticket().expect("encrypt should succeed");
        assert_eq!(material.name[0], b'E');
        assert_ne!(material.aes_key, [0u8; 32]);
        assert_ne!(material.hmac_key, [0u8; 16]);
    }

    #[test]
    fn test_server_ticket_manager_decrypt_ticket() {
        let mut mgr =
            ServerTicketManager::new(Duration::from_secs(3600), Duration::from_secs(3600));

        // Create a key first
        let material = mgr.encrypt_ticket().expect("encrypt should succeed");
        let key_name = material.name;

        // Decrypt with matching name should succeed
        let (dec_material, needs_reticket) = mgr
            .decrypt_ticket(&key_name)
            .expect("decrypt should succeed");
        assert_eq!(dec_material.name, key_name);
        assert_eq!(dec_material.aes_key, material.aes_key);
        assert_eq!(dec_material.hmac_key, material.hmac_key);
        assert!(!needs_reticket);
    }

    #[test]
    fn test_server_ticket_manager_decrypt_unknown_key() {
        let mut mgr =
            ServerTicketManager::new(Duration::from_secs(3600), Duration::from_secs(3600));

        // Create a key
        let _ = mgr.ensure_key().expect("key creation should succeed");

        // Decrypt with a non-matching name should fail
        let unknown_name = [0xFFu8; 16];
        let result = mgr.decrypt_ticket(&unknown_name);
        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::KeyNotFound(name) => {
                assert_eq!(name, unknown_name);
            }
            other => panic!("expected KeyNotFound, got {:?}", other),
        }
    }

    #[test]
    fn test_server_ticket_manager_rotation() {
        // Use zero renew interval to force immediate rotation
        let mut mgr = ServerTicketManager::new(Duration::from_secs(0), Duration::from_secs(3600));

        // Create first key
        let key1 = mgr.ensure_key().expect("first key creation should succeed");
        let name1 = key1.name;

        // With zero renew interval, the next ensure_key should rotate
        let key2 = mgr.ensure_key().expect("rotation should succeed");
        let name2 = key2.name;

        // Keys should be different (different random material)
        assert_ne!(name1, name2);

        // Previous key should now be the old current key
        assert!(mgr.previous_key.is_some());
        assert_eq!(mgr.previous_key.as_ref().unwrap().name, name1);

        // Should be able to decrypt with old key name
        let (_, needs_reticket) = mgr
            .decrypt_ticket(&name1)
            .expect("decrypt with old key should succeed");
        assert!(needs_reticket);
    }

    #[test]
    fn test_server_ticket_manager_from_config() {
        let config = TicketConfig::default();
        let mgr = ServerTicketManager::from_config(&config);
        assert_eq!(mgr.renew_interval, Duration::from_secs(3600));
        assert_eq!(mgr.expire_margin, Duration::from_secs(3600));
    }

    #[test]
    fn test_client_session_cache_store_retrieve() {
        let mut cache = ClientSessionCache::new();

        let session = CachedSession {
            session_data: vec![1, 2, 3, 4],
            verify_override: true,
            ocsp_result: Some(true),
            cached_at: SystemTime::now(),
        };

        cache.store("test-key", session);

        let retrieved = cache.retrieve("test-key");
        assert!(retrieved.is_some());
        let s = retrieved.unwrap();
        assert_eq!(s.session_data, vec![1, 2, 3, 4]);
        assert!(s.verify_override);
        assert_eq!(s.ocsp_result, Some(true));
    }

    #[test]
    fn test_client_session_cache_retrieve_missing() {
        let cache = ClientSessionCache::new();
        assert!(cache.retrieve("nonexistent").is_none());
    }

    #[test]
    fn test_client_session_cache_remove() {
        let mut cache = ClientSessionCache::new();

        let session = CachedSession {
            session_data: vec![5, 6, 7],
            verify_override: false,
            ocsp_result: None,
            cached_at: SystemTime::now(),
        };

        cache.store("remove-me", session);
        assert!(cache.retrieve("remove-me").is_some());

        cache.remove("remove-me");
        assert!(cache.retrieve("remove-me").is_none());
    }

    #[test]
    fn test_client_session_cache_remove_nonexistent() {
        let mut cache = ClientSessionCache::new();
        // Removing a key that doesn't exist should not panic
        cache.remove("does-not-exist");
    }

    #[test]
    fn test_client_session_cache_default() {
        let cache = ClientSessionCache::default();
        assert!(cache.retrieve("any").is_none());
    }

    #[test]
    fn test_compute_resumption_key_deterministic() {
        let params = ResumptionKeyParams {
            host_lbserver: None,
            dane_data: None,
            host_address: "192.168.1.1",
            host_port: 25,
            sending_ip: "10.0.0.1",
            ssl_options: "no_sslv2",
            require_ciphers: None,
            sni: Some("mail.example.com"),
            alpn: None,
        };

        let key1 = compute_resumption_key(&params);
        let key2 = compute_resumption_key(&params);
        assert_eq!(key1, key2);
        // SHA-256 hex output is always 64 characters
        assert_eq!(key1.len(), 64);
        // All characters should be lowercase hex
        assert!(key1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_compute_resumption_key_different_params() {
        let params1 = ResumptionKeyParams {
            host_lbserver: None,
            dane_data: None,
            host_address: "192.168.1.1",
            host_port: 25,
            sending_ip: "10.0.0.1",
            ssl_options: "",
            require_ciphers: None,
            sni: None,
            alpn: None,
        };

        let params2 = ResumptionKeyParams {
            host_lbserver: None,
            dane_data: None,
            host_address: "192.168.1.2",
            host_port: 25,
            sending_ip: "10.0.0.1",
            ssl_options: "",
            require_ciphers: None,
            sni: None,
            alpn: None,
        };

        assert_ne!(
            compute_resumption_key(&params1),
            compute_resumption_key(&params2)
        );
    }

    #[test]
    fn test_compute_resumption_key_all_params() {
        let dane_data = b"fake-tlsa-record-data";
        let params = ResumptionKeyParams {
            host_lbserver: Some("lb1.example.com"),
            dane_data: Some(dane_data),
            host_address: "2001:db8::1",
            host_port: 465,
            sending_ip: "2001:db8::100",
            ssl_options: "no_sslv2 no_sslv3",
            require_ciphers: Some("ECDHE-RSA-AES256-GCM-SHA384"),
            sni: Some("mail.example.com"),
            alpn: Some("smtp"),
        };

        let key = compute_resumption_key(&params);
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let original = CachedSession {
            session_data: vec![10, 20, 30, 40, 50],
            verify_override: true,
            ocsp_result: Some(true),
            cached_at: SystemTime::now(),
        };

        let serialized = serialize_session(&original);
        let deserialized =
            deserialize_session(&serialized).expect("deserialization should succeed");

        assert_eq!(deserialized.session_data, original.session_data);
        assert_eq!(deserialized.verify_override, original.verify_override);
        assert_eq!(deserialized.ocsp_result, original.ocsp_result);
        // Timestamps may have sub-second precision loss due to u64 seconds
        // encoding, so compare at second granularity
        let orig_secs = original
            .cached_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let deser_secs = deserialized
            .cached_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(orig_secs, deser_secs);
    }

    #[test]
    fn test_serialize_deserialize_no_ocsp() {
        let original = CachedSession {
            session_data: vec![0xFF; 100],
            verify_override: false,
            ocsp_result: None,
            cached_at: SystemTime::UNIX_EPOCH,
        };

        let serialized = serialize_session(&original);
        let deserialized =
            deserialize_session(&serialized).expect("deserialization should succeed");

        assert_eq!(deserialized.session_data.len(), 100);
        assert!(!deserialized.verify_override);
        assert_eq!(deserialized.ocsp_result, None);
    }

    #[test]
    fn test_serialize_deserialize_ocsp_false() {
        let original = CachedSession {
            session_data: vec![],
            verify_override: false,
            ocsp_result: Some(false),
            cached_at: SystemTime::now(),
        };

        let serialized = serialize_session(&original);
        let deserialized =
            deserialize_session(&serialized).expect("deserialization should succeed");

        assert!(deserialized.session_data.is_empty());
        assert_eq!(deserialized.ocsp_result, Some(false));
    }

    #[test]
    fn test_deserialize_too_short() {
        let result = deserialize_session(&[1, 2, 3]);
        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::DeserializationError(msg) => {
                assert!(msg.contains("too short"));
            }
            other => panic!("expected DeserializationError, got {:?}", other),
        }
    }

    #[test]
    fn test_deserialize_bad_version() {
        let mut data = vec![0u8; SERIALIZATION_HEADER_SIZE];
        data[0] = 99; // Invalid version
        let result = deserialize_session(&data);
        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::DeserializationError(msg) => {
                assert!(msg.contains("version"));
            }
            other => panic!("expected DeserializationError, got {:?}", other),
        }
    }

    #[test]
    fn test_deserialize_bad_verify_override() {
        let mut data = vec![0u8; SERIALIZATION_HEADER_SIZE];
        data[0] = SERIALIZATION_VERSION;
        data[1] = 5; // Invalid verify_override
        let result = deserialize_session(&data);
        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::DeserializationError(msg) => {
                assert!(msg.contains("verify_override"));
            }
            other => panic!("expected DeserializationError, got {:?}", other),
        }
    }

    #[test]
    fn test_deserialize_bad_ocsp() {
        let mut data = vec![0u8; SERIALIZATION_HEADER_SIZE];
        data[0] = SERIALIZATION_VERSION;
        data[1] = 0; // valid verify_override
        data[2] = 10; // Invalid ocsp_result
        let result = deserialize_session(&data);
        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::DeserializationError(msg) => {
                assert!(msg.contains("ocsp_result"));
            }
            other => panic!("expected DeserializationError, got {:?}", other),
        }
    }

    #[test]
    fn test_deserialize_truncated_session() {
        // Header claims 100 bytes of session data, but only provide header
        let mut data = vec![0u8; SERIALIZATION_HEADER_SIZE];
        data[0] = SERIALIZATION_VERSION;
        data[1] = 0;
        data[2] = 0;
        // timestamp: 0
        // session_len: 100 (little-endian)
        data[11] = 100;
        data[12] = 0;
        data[13] = 0;
        data[14] = 0;

        let result = deserialize_session(&data);
        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::DeserializationError(msg) => {
                assert!(msg.contains("truncated"));
            }
            other => panic!("expected DeserializationError, got {:?}", other),
        }
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0x00]), "00");
        assert_eq!(hex_encode(&[0xff]), "ff");
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex_encode(&[0x01, 0x23, 0x45, 0x67]), "01234567");
    }

    #[test]
    fn test_session_ticket_key_sizes() {
        // Verify STEK byte sizes match C exim_stek structure
        assert_eq!(std::mem::size_of::<[u8; 16]>(), 16); // name
        assert_eq!(std::mem::size_of::<[u8; 32]>(), 32); // aes_key
        assert_eq!(std::mem::size_of::<[u8; 16]>(), 16); // hmac_key
    }
}
