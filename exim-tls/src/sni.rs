//! Server Name Indication (SNI) support for TLS connections.
//!
//! Enables virtual hosting with different TLS certificates, private keys, and
//! OCSP responses per server name. This module is the Rust equivalent of the
//! SNI callback and session re-expansion logic from `tls-openssl.c`:
//!
//! - `server_sni` static (C line 381) → [`SniHandler::credential_cache`]
//! - `reexpand_tls_files_for_sni` static (C line 393) → [`SniConfig::requires_reexpansion`]
//! - `tls_servername_cb()` (C lines 2232–2314) → [`SniHandler::on_sni_received()`]
//! - SNI detection in `tls_expand_session_files()` (C lines 1579–1584) →
//!   [`SniConfig::detect_sni_references()`]
//!
//! # Design
//!
//! Given TLS SNI, Exim can use different keys, certs, and various other
//! configuration settings, because they are re-expanded with `$tls_sni` set.
//! This allows virtual hosting with TLS. A client might not send SNI, so a
//! fallback (the default credentials) is always needed.
//!
//! When SNI is sent by the client, the server mid-negotiation determines
//! whether credential re-expansion is needed (based on whether the certificate
//! path references `$tls_sni`). If re-expansion is needed, previously cached
//! credentials for that hostname are returned, or the caller is signaled to
//! perform expansion and provide new credentials.
//!
//! All static/global state from the C implementation (`server_sni`,
//! `reexpand_tls_files_for_sni`) is replaced with struct fields per AAP §0.4.4.

use std::collections::HashMap;

use tracing::debug;

// ---------------------------------------------------------------------------
// SNI variable name patterns for re-expansion detection
// ---------------------------------------------------------------------------

/// Substring patterns checked in certificate/key/OCSP paths to detect
/// whether credential re-expansion is required when an SNI value is received.
///
/// These match the C code in `tls_expand_session_files()` (lines 1579–1584):
///
/// ```c
/// Ustrstr(state->certificate, US"tls_sni")
/// Ustrstr(state->certificate, US"tls_in_sni")
/// Ustrstr(state->certificate, US"tls_out_sni")
/// ```
///
/// The substrings intentionally omit the `$` prefix so they match all Exim
/// variable reference forms: `$tls_sni`, `${tls_sni}`, `$tls_in_sni`, etc.
const SNI_VARIABLE_PATTERNS: &[&str] = &["tls_sni", "tls_in_sni", "tls_out_sni"];

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during SNI credential handling.
///
/// Replaces the error paths in `tls_servername_cb()` from `tls-openssl.c`
/// (lines 2255–2313), where failures were logged via `log_write()` and the
/// callback returned `SSL_TLSEXT_ERR_ALERT_FATAL`.
#[derive(Debug, thiserror::Error)]
pub enum SniError {
    /// Credential expansion failed for the given hostname.
    ///
    /// Occurs when the Exim string expansion engine cannot resolve the
    /// certificate or key path template with `$tls_sni` set to the received
    /// server name.
    #[error("SNI credential expansion failed for {hostname}: {reason}")]
    ExpansionFailed {
        /// The SNI hostname that triggered the expansion.
        hostname: String,
        /// Description of the expansion failure.
        reason: String,
    },

    /// Credential loading failed after successful expansion.
    ///
    /// The expanded file path was resolved, but the certificate or key
    /// could not be read or parsed from disk.
    #[error("SNI credential loading failed: {0}")]
    CredentialLoadFailed(String),

    /// SNI-specific TLS context creation failed.
    ///
    /// Replaces the `lib_ctx_new(&server_sni, ...)` failure path in the C
    /// callback (line 2255), which logged the error and returned
    /// `SSL_TLSEXT_ERR_ALERT_FATAL`.
    #[error("SNI context creation failed: {0}")]
    ContextCreationFailed(String),
}

// ---------------------------------------------------------------------------
// SniConfig — re-expansion detection and path pattern storage
// ---------------------------------------------------------------------------

/// Configuration for SNI-based credential selection.
///
/// Stores the certificate, key, and OCSP response path patterns (which may
/// contain Exim variable references like `$tls_sni`) and tracks whether
/// credential re-expansion is needed when an SNI value is received.
///
/// Replaces the `reexpand_tls_files_for_sni` static boolean (C line 393)
/// and the detection logic in `tls_expand_session_files()` (C lines 1579–1584).
#[derive(Debug, Clone)]
pub struct SniConfig {
    /// Whether credential re-expansion is needed for SNI.
    ///
    /// Set to `true` when any of the certificate, key, or OCSP response
    /// path patterns contain a reference to `$tls_sni`, `$tls_in_sni`, or
    /// `$tls_out_sni`. When `false`, receiving an SNI value from the client
    /// is recorded but does not trigger credential re-loading.
    pub requires_reexpansion: bool,

    /// Certificate file path pattern (may contain `$tls_sni`).
    ///
    /// Corresponds to the `tls_certificate` configuration option. When this
    /// pattern contains an SNI variable reference, the path is re-expanded
    /// with `$tls_sni` set to the received server name to load a hostname-
    /// specific certificate chain.
    pub certificate_pattern: Option<String>,

    /// Private key file path pattern (may contain `$tls_sni`).
    ///
    /// Corresponds to the `tls_privatekey` configuration option.
    pub privatekey_pattern: Option<String>,

    /// OCSP response file path pattern (may contain `$tls_sni`).
    ///
    /// Corresponds to the `tls_ocsp_file` configuration option.
    pub ocsp_file_pattern: Option<String>,
}

impl SniConfig {
    /// Detect SNI variable references in credential file paths and construct
    /// an [`SniConfig`] with the appropriate `requires_reexpansion` flag.
    ///
    /// Replaces the detection logic in `tls_expand_session_files()` from
    /// `tls-openssl.c` (lines 1579–1584):
    ///
    /// ```c
    /// if ( !reexpand_tls_files_for_sni
    ///    && (  Ustrstr(state->certificate, US"tls_sni")
    ///          || Ustrstr(state->certificate, US"tls_in_sni")
    ///          || Ustrstr(state->certificate, US"tls_out_sni")
    ///    )  )
    ///     reexpand_tls_files_for_sni = TRUE;
    /// ```
    ///
    /// Unlike the C code which only checked the certificate path, this
    /// implementation checks all three path patterns (certificate, key, OCSP)
    /// for completeness and forward compatibility.
    ///
    /// # Arguments
    ///
    /// * `cert_path` — The `tls_certificate` configuration value.
    /// * `key_path`  — The `tls_privatekey` configuration value, if set.
    /// * `ocsp_path` — The `tls_ocsp_file` configuration value, if set.
    ///
    /// # Returns
    ///
    /// An [`SniConfig`] with `requires_reexpansion` set to `true` if any
    /// of the provided paths contain an SNI variable reference.
    pub fn detect_sni_references(
        cert_path: &str,
        key_path: Option<&str>,
        ocsp_path: Option<&str>,
    ) -> Self {
        let requires_reexpansion = path_contains_sni_reference(cert_path)
            || key_path.is_some_and(path_contains_sni_reference)
            || ocsp_path.is_some_and(path_contains_sni_reference);

        SniConfig {
            requires_reexpansion,
            certificate_pattern: Some(cert_path.to_string()),
            privatekey_pattern: key_path.map(String::from),
            ocsp_file_pattern: ocsp_path.map(String::from),
        }
    }
}

/// Check whether a path string contains any SNI variable reference.
///
/// Searches for the substrings `"tls_sni"`, `"tls_in_sni"`, and
/// `"tls_out_sni"` to match all Exim variable reference forms
/// (`$tls_sni`, `${tls_sni}`, etc.).
fn path_contains_sni_reference(path: &str) -> bool {
    SNI_VARIABLE_PATTERNS.iter().any(|pat| path.contains(pat))
}

// ---------------------------------------------------------------------------
// SniCredentials — per-hostname credential set
// ---------------------------------------------------------------------------

/// A set of TLS credentials associated with a specific SNI hostname.
///
/// Contains the DER-encoded certificate chain, private key, and optional
/// OCSP response that were produced by re-expanding the credential path
/// patterns with `$tls_sni` set to the hostname value.
///
/// Replaces the per-SNI `SSL_CTX` clone (`server_sni`) from `tls-openssl.c`
/// (line 381). Instead of cloning an entire OpenSSL context, we cache the
/// raw credential material and let the TLS backend build a context from it.
#[derive(Debug, Clone)]
pub struct SniCredentials {
    /// DER-encoded certificate chain.
    ///
    /// Each inner `Vec<u8>` is one DER-encoded X.509 certificate.
    /// The first entry is the end-entity certificate; subsequent entries
    /// are intermediate CA certificates in chain order.
    pub cert_chain: Vec<Vec<u8>>,

    /// DER-encoded private key.
    ///
    /// May be PKCS#8, PKCS#1 (RSA), or SEC1 (EC) encoded.
    pub private_key: Vec<u8>,

    /// DER-encoded OCSP response, if available.
    ///
    /// Provided when the `tls_ocsp_file` pattern was also expanded for
    /// this hostname and the resulting file was successfully loaded.
    pub ocsp_response: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// SniAction — result of SNI callback processing
// ---------------------------------------------------------------------------

/// The action that the TLS backend should take after processing an SNI
/// callback.
///
/// Returned by [`SniHandler::on_sni_received()`] to communicate whether the
/// caller needs to perform credential re-expansion, use cached credentials,
/// or simply continue with the existing (default) credentials.
///
/// This enum replaces the control flow branches in `tls_servername_cb()`
/// from `tls-openssl.c` (lines 2232–2314).
#[derive(Debug)]
pub enum SniAction {
    /// No SNI was sent by the client.
    ///
    /// The default credentials should be used. Corresponds to the early
    /// return at C line 2239–2240:
    /// ```c
    /// if (!servername) return SSL_TLSEXT_ERR_OK;
    /// ```
    NoSni,

    /// SNI was received but no credential re-expansion is needed.
    ///
    /// The default credentials already apply (the certificate path does
    /// not reference `$tls_sni`). Corresponds to the early return at C
    /// lines 2248–2249:
    /// ```c
    /// if (!reexpand_tls_files_for_sni) return SSL_TLSEXT_ERR_OK;
    /// ```
    UseExisting,

    /// Cached credentials were found for this SNI hostname.
    ///
    /// The TLS backend should switch to these credentials for the current
    /// connection. This optimizes repeated connections to the same hostname
    /// by avoiding redundant string expansion and file I/O.
    UseCredentials(SniCredentials),

    /// The caller must expand credential path patterns with `$tls_sni`
    /// set to the contained hostname, load the resulting files, and call
    /// [`SniHandler::cache_credentials()`] before completing the handshake.
    ///
    /// Corresponds to the context-cloning and `tls_expand_session_files()`
    /// call at C lines 2255–2304.
    NeedExpansion(String),
}

// ---------------------------------------------------------------------------
// SniHandler — stateful SNI callback processor
// ---------------------------------------------------------------------------

/// Manages Server Name Indication (SNI) state for a TLS server.
///
/// Encapsulates the SNI callback logic, credential caching, and re-expansion
/// detection that was previously scattered across C static variables
/// (`server_sni`, `reexpand_tls_files_for_sni`) and the `tls_servername_cb()`
/// function in `tls-openssl.c`.
///
/// # Usage
///
/// ```rust,ignore
/// let config = SniConfig::detect_sni_references(
///     "/etc/exim4/certs/$tls_sni.pem",
///     Some("/etc/exim4/keys/$tls_sni.key"),
///     None,
/// );
/// let mut handler = SniHandler::new(config);
///
/// // During TLS handshake, when the client sends SNI:
/// match handler.on_sni_received("mail.example.com")? {
///     SniAction::NeedExpansion(hostname) => {
///         // Expand paths, load creds, then cache them:
///         let creds = load_credentials_for(&hostname);
///         handler.cache_credentials(&hostname, creds);
///     }
///     SniAction::UseCredentials(creds) => { /* apply creds to TLS context */ }
///     SniAction::UseExisting | SniAction::NoSni => { /* keep defaults */ }
/// }
/// ```
pub struct SniHandler {
    /// SNI configuration (path patterns and re-expansion flag).
    config: SniConfig,

    /// Cached per-SNI credentials, keyed by normalized hostname.
    ///
    /// Replaces the C pattern of re-creating the `server_sni` `SSL_CTX`
    /// on every SNI callback. By caching expanded credentials per hostname,
    /// subsequent connections to the same server name skip string expansion
    /// and file I/O entirely.
    credential_cache: HashMap<String, SniCredentials>,

    /// The SNI value received for the current connection, if any.
    ///
    /// Replaces `tls_in.sni = string_copy_perm(servername, TRUE)` from the
    /// C callback (line 2246). Used by ACL variables and logging via the
    /// `$tls_sni` expansion variable.
    current_sni: Option<String>,
}

impl SniHandler {
    /// Create a new [`SniHandler`] from the given SNI configuration.
    ///
    /// Initializes an empty credential cache and no current SNI value.
    ///
    /// # Arguments
    ///
    /// * `config` — An [`SniConfig`] produced by
    ///   [`SniConfig::detect_sni_references()`] or constructed directly.
    pub fn new(config: SniConfig) -> Self {
        SniHandler {
            config,
            credential_cache: HashMap::new(),
            current_sni: None,
        }
    }

    /// Process an incoming SNI value from the TLS handshake.
    ///
    /// This is the Rust equivalent of `tls_servername_cb()` from
    /// `tls-openssl.c` (lines 2232–2314). The method:
    ///
    /// 1. Records the received server name (for `$tls_sni` expansion).
    /// 2. Logs the SNI value at `DEBUG` level (replacing C
    ///    `DEBUG(D_tls) debug_printf("Received TLS SNI %q%s\n", ...)`
    ///    at line 2242).
    /// 3. If re-expansion is not needed, returns [`SniAction::UseExisting`].
    /// 4. If re-expansion is needed:
    ///    - Checks the credential cache for this hostname.
    ///    - Returns [`SniAction::UseCredentials`] if cached.
    ///    - Returns [`SniAction::NeedExpansion`] otherwise.
    ///
    /// # Arguments
    ///
    /// * `server_name` — The SNI hostname extracted from the TLS ClientHello
    ///   message, equivalent to
    ///   `SSL_get_servername(s, TLSEXT_NAMETYPE_host_name)` in the C callback.
    ///
    /// # Errors
    ///
    /// Currently infallible from the handler's perspective. The `Result`
    /// return type is provided for forward compatibility with future
    /// validation logic (e.g., hostname format checks).
    pub fn on_sni_received(&mut self, server_name: &str) -> Result<SniAction, SniError> {
        // Store the received SNI value for ACL variables and logging.
        // Replaces: tls_in.sni = string_copy_perm(US servername, TRUE);
        self.current_sni = Some(server_name.to_string());

        // Log at debug level, matching C behavior:
        //   DEBUG(D_tls) debug_printf("Received TLS SNI %q%s\n", servername,
        //       reexpand_tls_files_for_sni ? "" : " (unused for certificate selection)");
        if self.config.requires_reexpansion {
            debug!("Received TLS SNI: {server_name}");
        } else {
            debug!("Received TLS SNI: {server_name} (unused for certificate selection)");
        }

        // If re-expansion is not needed, the default credentials apply.
        // Replaces: if (!reexpand_tls_files_for_sni) return SSL_TLSEXT_ERR_OK;
        if !self.config.requires_reexpansion {
            return Ok(SniAction::UseExisting);
        }

        // Re-expansion is needed — check the credential cache first.
        if let Some(cached) = self.credential_cache.get(server_name) {
            debug!("Using cached SNI credentials for hostname: {server_name}");
            return Ok(SniAction::UseCredentials(cached.clone()));
        }

        // No cached credentials — signal the caller to expand and load.
        debug!("SNI credential expansion required for hostname: {server_name}");
        Ok(SniAction::NeedExpansion(server_name.to_string()))
    }

    /// Cache expanded credentials for a hostname.
    ///
    /// After the caller expands credential path patterns with `$tls_sni` set
    /// to `hostname` and loads the resulting files, this method stores the
    /// credential set so that future connections with the same SNI value can
    /// skip expansion entirely.
    ///
    /// # Arguments
    ///
    /// * `hostname` — The SNI hostname (must match the value passed to
    ///   [`on_sni_received()`](Self::on_sni_received)).
    /// * `creds` — The expanded and loaded credential set.
    pub fn cache_credentials(&mut self, hostname: &str, creds: SniCredentials) {
        debug!(
            hostname = hostname,
            cert_chain_len = creds.cert_chain.len(),
            has_ocsp = creds.ocsp_response.is_some(),
            "Caching SNI credentials for hostname",
        );
        self.credential_cache.insert(hostname.to_string(), creds);
    }

    /// Invalidate all cached SNI credentials.
    ///
    /// Called when the underlying certificate or key files change (detected
    /// by the credential file watcher). Replaces the SNI cleanup portion of
    /// `tls_server_creds_invalidate()` from `tls.c`, which freed the
    /// `server_sni` `SSL_CTX`.
    ///
    /// After invalidation, the next SNI callback for any hostname will
    /// trigger fresh credential expansion via [`SniAction::NeedExpansion`].
    pub fn invalidate_cache(&mut self) {
        let count = self.credential_cache.len();
        self.credential_cache.clear();
        debug!(entries_cleared = count, "Invalidated SNI credential cache",);
    }

    /// Return the SNI value received for the current connection, if any.
    ///
    /// Used by ACL variable expansion (`$tls_sni`) and logging. Replaces
    /// the `tls_in.sni` field from the C code.
    ///
    /// Returns `None` if no SNI was received (i.e., the client did not
    /// include an SNI extension in the ClientHello message).
    pub fn get_sni(&self) -> Option<&str> {
        self.current_sni.as_deref()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- SniConfig::detect_sni_references tests --

    #[test]
    fn detect_sni_references_with_tls_sni_in_cert() {
        let config = SniConfig::detect_sni_references("/etc/exim4/certs/$tls_sni.pem", None, None);
        assert!(config.requires_reexpansion);
        assert_eq!(
            config.certificate_pattern.as_deref(),
            Some("/etc/exim4/certs/$tls_sni.pem")
        );
    }

    #[test]
    fn detect_sni_references_with_tls_in_sni() {
        let config =
            SniConfig::detect_sni_references("/etc/exim4/certs/${tls_in_sni}.pem", None, None);
        assert!(config.requires_reexpansion);
    }

    #[test]
    fn detect_sni_references_with_tls_out_sni() {
        let config = SniConfig::detect_sni_references(
            "/etc/exim4/certs/server.pem",
            Some("/etc/exim4/keys/${tls_out_sni}.key"),
            None,
        );
        assert!(config.requires_reexpansion);
        assert_eq!(
            config.privatekey_pattern.as_deref(),
            Some("/etc/exim4/keys/${tls_out_sni}.key")
        );
    }

    #[test]
    fn detect_sni_references_in_ocsp_path() {
        let config = SniConfig::detect_sni_references(
            "/etc/exim4/certs/server.pem",
            None,
            Some("/etc/exim4/ocsp/$tls_sni.der"),
        );
        assert!(config.requires_reexpansion);
    }

    #[test]
    fn detect_sni_references_no_references() {
        let config = SniConfig::detect_sni_references(
            "/etc/exim4/certs/server.pem",
            Some("/etc/exim4/keys/server.key"),
            Some("/etc/exim4/ocsp/server.der"),
        );
        assert!(!config.requires_reexpansion);
    }

    #[test]
    fn detect_sni_references_brace_form() {
        let config =
            SniConfig::detect_sni_references("/etc/exim4/certs/${tls_sni}/cert.pem", None, None);
        assert!(config.requires_reexpansion);
    }

    // -- SniHandler tests --

    fn make_test_creds() -> SniCredentials {
        SniCredentials {
            cert_chain: vec![vec![0x30, 0x82, 0x01, 0x00]],
            private_key: vec![0x30, 0x82, 0x02, 0x00],
            ocsp_response: None,
        }
    }

    #[test]
    fn handler_no_reexpansion_returns_use_existing() {
        let config = SniConfig {
            requires_reexpansion: false,
            certificate_pattern: Some("/etc/exim4/certs/server.pem".to_string()),
            privatekey_pattern: None,
            ocsp_file_pattern: None,
        };
        let mut handler = SniHandler::new(config);

        let action = handler.on_sni_received("mail.example.com").unwrap();
        assert!(matches!(action, SniAction::UseExisting));
        assert_eq!(handler.get_sni(), Some("mail.example.com"));
    }

    #[test]
    fn handler_reexpansion_no_cache_returns_need_expansion() {
        let config = SniConfig {
            requires_reexpansion: true,
            certificate_pattern: Some("/etc/exim4/certs/$tls_sni.pem".to_string()),
            privatekey_pattern: None,
            ocsp_file_pattern: None,
        };
        let mut handler = SniHandler::new(config);

        let action = handler.on_sni_received("mail.example.com").unwrap();
        match action {
            SniAction::NeedExpansion(ref hostname) => {
                assert_eq!(hostname, "mail.example.com");
            }
            _ => panic!("Expected NeedExpansion, got {action:?}"),
        }
    }

    #[test]
    fn handler_returns_cached_credentials() {
        let config = SniConfig {
            requires_reexpansion: true,
            certificate_pattern: Some("/etc/exim4/certs/$tls_sni.pem".to_string()),
            privatekey_pattern: None,
            ocsp_file_pattern: None,
        };
        let mut handler = SniHandler::new(config);

        // Pre-cache credentials for a hostname.
        let creds = make_test_creds();
        handler.cache_credentials("mail.example.com", creds);

        // Now the handler should return UseCredentials.
        let action = handler.on_sni_received("mail.example.com").unwrap();
        match action {
            SniAction::UseCredentials(ref cached) => {
                assert_eq!(cached.cert_chain.len(), 1);
                assert!(cached.ocsp_response.is_none());
            }
            _ => panic!("Expected UseCredentials, got {action:?}"),
        }
    }

    #[test]
    fn handler_invalidate_clears_cache() {
        let config = SniConfig {
            requires_reexpansion: true,
            certificate_pattern: Some("/etc/exim4/certs/$tls_sni.pem".to_string()),
            privatekey_pattern: None,
            ocsp_file_pattern: None,
        };
        let mut handler = SniHandler::new(config);

        handler.cache_credentials("mail.example.com", make_test_creds());
        handler.cache_credentials("smtp.example.org", make_test_creds());

        handler.invalidate_cache();

        // After invalidation, should return NeedExpansion again.
        let action = handler.on_sni_received("mail.example.com").unwrap();
        assert!(matches!(action, SniAction::NeedExpansion(_)));
    }

    #[test]
    fn handler_get_sni_none_before_callback() {
        let config = SniConfig {
            requires_reexpansion: false,
            certificate_pattern: None,
            privatekey_pattern: None,
            ocsp_file_pattern: None,
        };
        let handler = SniHandler::new(config);
        assert_eq!(handler.get_sni(), None);
    }

    #[test]
    fn handler_get_sni_updated_on_each_call() {
        let config = SniConfig {
            requires_reexpansion: false,
            certificate_pattern: None,
            privatekey_pattern: None,
            ocsp_file_pattern: None,
        };
        let mut handler = SniHandler::new(config);

        handler.on_sni_received("first.example.com").unwrap();
        assert_eq!(handler.get_sni(), Some("first.example.com"));

        handler.on_sni_received("second.example.org").unwrap();
        assert_eq!(handler.get_sni(), Some("second.example.org"));
    }

    // -- SniError display tests --

    #[test]
    fn sni_error_expansion_failed_display() {
        let err = SniError::ExpansionFailed {
            hostname: "mail.example.com".to_string(),
            reason: "unknown variable".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("mail.example.com"));
        assert!(msg.contains("unknown variable"));
    }

    #[test]
    fn sni_error_credential_load_failed_display() {
        let err = SniError::CredentialLoadFailed("file not found".to_string());
        let msg = format!("{err}");
        assert!(msg.contains("file not found"));
    }

    #[test]
    fn sni_error_context_creation_failed_display() {
        let err = SniError::ContextCreationFailed("out of memory".to_string());
        let msg = format!("{err}");
        assert!(msg.contains("out of memory"));
    }

    // -- path_contains_sni_reference tests --

    #[test]
    fn path_contains_sni_reference_positive_cases() {
        assert!(path_contains_sni_reference("$tls_sni"));
        assert!(path_contains_sni_reference("/path/$tls_sni/cert.pem"));
        assert!(path_contains_sni_reference("/path/${tls_sni}.pem"));
        assert!(path_contains_sni_reference("$tls_in_sni"));
        assert!(path_contains_sni_reference("prefix_tls_out_sni_suffix"));
    }

    #[test]
    fn path_contains_sni_reference_negative_cases() {
        assert!(!path_contains_sni_reference("/etc/certs/server.pem"));
        assert!(!path_contains_sni_reference(""));
        assert!(!path_contains_sni_reference("$tls_certificate"));
        assert!(!path_contains_sni_reference("no_sni_here"));
    }

    // -- SniCredentials clone test --

    #[test]
    fn sni_credentials_clone() {
        let creds = SniCredentials {
            cert_chain: vec![vec![1, 2, 3], vec![4, 5, 6]],
            private_key: vec![7, 8, 9],
            ocsp_response: Some(vec![10, 11, 12]),
        };
        let cloned = creds.clone();
        assert_eq!(cloned.cert_chain, creds.cert_chain);
        assert_eq!(cloned.private_key, creds.private_key);
        assert_eq!(cloned.ocsp_response, creds.ocsp_response);
    }
}
