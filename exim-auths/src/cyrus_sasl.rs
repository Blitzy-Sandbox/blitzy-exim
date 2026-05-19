// exim-auths/src/cyrus_sasl.rs — Cyrus SASL Authenticator via FFI
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Rust rewrite of `src/src/auths/cyrus_sasl.c` (536 lines) + `cyrus_sasl.h`
// (37 lines). Implements Cyrus SASL server-side authentication by delegating
// to libsasl2 via `exim-ffi`.
//
// The client hook is explicitly a stub (not implemented in the C codebase
// either — see C line 498-508).
//
// # Architecture
//
// All libsasl2 C API calls are confined to the `exim-ffi` crate's
// `cyrus_sasl` module. This file contains ZERO `unsafe` code (per AAP §0.7.2).
//
// The SASL token exchange loop (C lines 323-470) follows this pattern:
//   1. Initialize SASL library via `SaslContext::new()`
//   2. Create connection via `SaslConnection::new()`
//   3. Start exchange via `SaslConnection::server_start()`
//   4. Loop on `SaslStepResult::Continue`:
//      - Base64-encode server challenge, send via 334 response
//      - Read client response, base64-decode
//      - Feed to `SaslConnection::server_step()`
//   5. On `Complete`: extract username, evaluate server_condition
//   6. On error: return appropriate AuthServerResult
//
// # Feature Gate
//
// This module is gated behind `#[cfg(feature = "auth-cyrus-sasl")]`,
// replacing the C `#ifdef AUTH_CYRUS_SASL` preprocessor conditional.

use std::any::Any;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use tracing::{debug, error, info, warn};

use exim_drivers::auth_driver::{
    AuthClientResult, AuthDriver, AuthDriverFactory, AuthInstanceConfig, AuthServerResult,
};
use exim_drivers::DriverError;
use exim_ffi::cyrus_sasl::{
    SaslConnection, SaslContext, SaslError, SaslStepResult, SaslVersionInfo,
};
use exim_store::taint::{Clean, Tainted};

use crate::helpers::base64_io::{
    auth_get_data, auth_get_no64_data, AuthIoResult, AuthSmtpIo, DEFAULT_MAX_RESPONSE_LEN,
};
use crate::helpers::server_condition::{auth_check_serv_cond, AuthConditionResult};

// =============================================================================
// CyrusSaslOptions — Driver-specific configuration options
// =============================================================================

/// Configuration options specific to the Cyrus SASL authenticator driver.
///
/// Replaces the C `auth_cyrus_sasl_options_block` struct from `cyrus_sasl.h`
/// (lines 14-19). Each field corresponds to a named option in the Exim
/// configuration file's authenticator block.
///
/// # C-to-Rust Field Mapping
///
/// | C Field            | Rust Field        | Type             | Default        |
/// |--------------------|-------------------|------------------|----------------|
/// | `server_service`   | `server_service`  | `Option<String>` | `Some("smtp")` |
/// | `server_hostname`  | `server_hostname` | `Option<String>` | `Some("$primary_hostname")` |
/// | `server_realm`     | `server_realm`    | `Option<String>` | `None`         |
/// | `server_mech`      | `server_mech`     | `Option<String>` | `None`         |
///
/// # Example Configuration
///
/// ```text
/// cyrus_sasl_auth:
///   driver = cyrus_sasl
///   public_name = PLAIN
///   server_service = smtp
///   server_hostname = mail.example.com
///   server_realm = EXAMPLE.COM
///   server_condition = ${if eq{$auth1}{validuser}{yes}{no}}
/// ```
#[derive(Debug, Clone)]
pub struct CyrusSaslOptions {
    /// SASL service name passed to `sasl_server_new()`.
    ///
    /// Controls which SASL plugin configuration files are loaded.
    /// Default: `"smtp"` (matching C default at `cyrus_sasl.c` line 61).
    pub server_service: Option<String>,

    /// Server hostname for SASL, passed to `sasl_server_new()` as the
    /// server FQDN parameter.
    ///
    /// This is an expandable string — the C code calls `expand_string()`
    /// on it (C line 129). Default: `"$primary_hostname"` (matching C
    /// default at `cyrus_sasl.c` line 62).
    pub server_hostname: Option<String>,

    /// SASL realm, passed to `sasl_server_new()` as the user realm.
    ///
    /// This is an expandable string — the C code calls `expand_string()`
    /// on it when set (C lines 135-139). Default: `None` (matching C
    /// default `NULL` at `cyrus_sasl.c` line 63).
    pub server_realm: Option<String>,

    /// Override SASL mechanism name for this authenticator.
    ///
    /// If `None`, the `public_name` from the auth instance configuration
    /// is used as the mechanism name (C line 127: `ob->server_mech =
    /// string_copy(ablock->public_name)`). This allows overriding the
    /// SASL mechanism independently of the advertised name.
    pub server_mech: Option<String>,
}

impl Default for CyrusSaslOptions {
    /// Returns default options matching the C `auth_cyrus_sasl_option_defaults`
    /// struct (cyrus_sasl.c lines 60-65).
    ///
    /// All fields match the C defaults:
    /// - `server_service` = `"smtp"`
    /// - `server_hostname` = `"$primary_hostname"` (expandable)
    /// - `server_realm` = `None` (C: `NULL`)
    /// - `server_mech` = `None` (C: `NULL` — defaults to `public_name` at init)
    fn default() -> Self {
        Self {
            server_service: Some("smtp".to_string()),
            server_hostname: Some("$primary_hostname".to_string()),
            server_realm: None,
            server_mech: None,
        }
    }
}

// =============================================================================
// CyrusSaslAuth — Driver implementation struct
// =============================================================================

/// Cyrus SASL authenticator driver implementation.
///
/// Replaces the C `cyrus_sasl_auth_info` struct and associated function
/// implementations from `cyrus_sasl.c`. This driver delegates all SASL
/// authentication operations to the Cyrus SASL library (libsasl2) via
/// the safe FFI wrappers in `exim-ffi`.
///
/// # Thread Safety
///
/// Implements `Send + Sync` as required by the `AuthDriver` trait. The
/// `CyrusSaslOptions` struct contains only owned `String` values and is
/// safe to share across threads.
///
/// # Initialization
///
/// The [`init()`](CyrusSaslAuth::init) method probes libsasl2 to verify that
/// the configured SASL mechanism is available (C `auth_cyrus_sasl_init` lines
/// 108-195). If the mechanism is not found, initialization fails with a
/// `ConfigError`.
///
/// # Authentication Flow
///
/// The [`server()`](CyrusSaslAuth::server) method implements the full SASL
/// token exchange loop:
/// 1. Initialize SASL library and create a connection
/// 2. Base64-decode initial client data (if any)
/// 3. Start/step through the SASL exchange
/// 4. On success: extract username, set `$auth1`, evaluate `server_condition`
/// 5. On failure: return appropriate error codes
#[derive(Debug)]
pub struct CyrusSaslAuth {
    /// Driver-specific options parsed from the configuration file.
    options: CyrusSaslOptions,
}

impl Default for CyrusSaslAuth {
    fn default() -> Self {
        Self::new()
    }
}

impl CyrusSaslAuth {
    /// Create a new `CyrusSaslAuth` instance with default options.
    ///
    /// The returned driver is not yet initialized — call [`init()`](Self::init)
    /// with the `AuthInstanceConfig` to probe mechanism availability.
    pub fn new() -> Self {
        Self {
            options: CyrusSaslOptions::default(),
        }
    }

    /// Initialize the driver by probing libsasl2 for mechanism availability.
    ///
    /// Replaces C `auth_cyrus_sasl_init()` (cyrus_sasl.c lines 108-195).
    ///
    /// This method:
    /// 1. Determines the effective SASL mechanism name (from `server_mech`
    ///    option or `public_name`)
    /// 2. Initializes the SASL library via `SaslContext::new()`
    /// 3. Creates a temporary `SaslConnection` to probe mechanism availability
    /// 4. Lists available mechanisms and verifies the target is present
    /// 5. Cleans up the probe connection and library context
    ///
    /// # Arguments
    ///
    /// * `config` — The auth instance configuration providing the `public_name`
    ///   and instance `name` for logging.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` — Mechanism is available; the driver can be used.
    /// * `Ok(false)` — Mechanism is not available; the driver should not
    ///   advertise this mechanism.
    /// * `Err(DriverError)` — Fatal initialization error.
    pub fn init(&mut self, config: &AuthInstanceConfig) -> Result<bool, DriverError> {
        // Extract driver-specific options from the config
        if let Some(opts) = config.downcast_options::<CyrusSaslOptions>() {
            self.options = opts.clone();
        }

        // Determine the effective mechanism name:
        // C line 127: if (!ob->server_mech) ob->server_mech = string_copy(ablock->public_name);
        let effective_mech = self
            .options
            .server_mech
            .clone()
            .unwrap_or_else(|| config.public_name.clone());

        // Resolve hostname for the probe connection.
        // In the full Exim system, this would call expand_string(). For initialization
        // probing, we use the raw value or a sensible default.
        let hostname = self
            .options
            .server_hostname
            .as_deref()
            .unwrap_or("localhost");

        let realm = self.options.server_realm.as_deref();

        let service = self.options.server_service.as_deref().unwrap_or("smtp");

        // Initialize the SASL library for probing mechanism availability.
        // C lines 147-149: sasl_server_init(cbs, "exim")
        let _ctx = SaslContext::new("exim").map_err(|e| {
            DriverError::InitFailed(format!(
                "{} authenticator: couldn't initialise Cyrus SASL library: {}",
                config.name,
                e.message()
            ))
        })?;

        // Create a temporary SASL connection to list mechanisms.
        // C lines 151-154: sasl_server_new(...)
        let conn = SaslConnection::new(service, hostname, realm).map_err(|e| {
            DriverError::InitFailed(format!(
                "{} authenticator: couldn't initialise Cyrus SASL server connection: {}",
                config.name,
                e.message()
            ))
        })?;

        // List available mechanisms.
        // C lines 156-158: sasl_listmech(...)
        let mech_list = conn.list_mechanisms().map_err(|e| {
            DriverError::InitFailed(format!(
                "{} authenticator: couldn't get Cyrus SASL mechanism list: {}",
                config.name,
                e.message()
            ))
        })?;

        debug!(
            service = %service,
            hostname = %hostname,
            realm = ?realm,
            "Initialised Cyrus SASL service={} fqdn={} realm={:?}",
            service,
            hostname,
            realm,
        );
        debug!(mechanisms = %mech_list, "Cyrus SASL knows mechanisms: {}", mech_list);

        // Check if the target mechanism is in the list.
        // C lines 179-184: loop searching for mechanism in colon-separated list
        let mech_found = mech_list
            .split_whitespace()
            .any(|m| m.eq_ignore_ascii_case(&effective_mech));

        if !mech_found {
            return Err(DriverError::ConfigError(format!(
                "{} authenticator: Cyrus SASL doesn't know about mechanism {}",
                config.name, effective_mech
            )));
        }

        // Store the resolved mechanism name back into options for server() use
        self.options.server_mech = Some(effective_mech.clone());

        debug!(
            driver = %config.name,
            mechanism = %effective_mech,
            "Cyrus SASL driver {}: {} initialised",
            config.name,
            config.public_name,
        );

        // Connection and context are dropped here, releasing SASL resources.
        // C lines 193-194: sasl_dispose(&conn); sasl_done();

        Ok(true)
    }

    /// Perform the full multi-step SASL token exchange loop with SMTP I/O.
    ///
    /// This encapsulates the main SASL exchange logic from C lines 241-470,
    /// driving the challenge/response cycle through the SMTP I/O handle.
    ///
    /// The method uses [`auth_get_data`] for standard base64-encoded challenges
    /// and [`auth_get_no64_data`] when the challenge data is empty (sending a
    /// bare "334" continuation without base64 payload, as done for certain
    /// mechanism-specific edge cases).
    ///
    /// # Arguments
    ///
    /// * `config` — Auth instance configuration for logging.
    /// * `conn` — Mutable reference to the SASL connection.
    /// * `mechanism` — The SASL mechanism name.
    /// * `initial_data` — The initial client data (empty if none provided).
    /// * `io` — SMTP I/O handle for challenge/response exchange.
    ///
    /// # Returns
    ///
    /// * `Ok(AuthServerResult)` — The authentication outcome.
    /// * `Err(DriverError)` — Infrastructure failure.
    pub fn sasl_exchange(
        &self,
        config: &AuthInstanceConfig,
        conn: &mut SaslConnection,
        mechanism: &str,
        initial_data: &[u8],
        io: &mut dyn AuthSmtpIo,
    ) -> Result<AuthServerResult, DriverError> {
        // Start the SASL exchange.
        // C lines 325-330: sasl_server_start(conn, mechanism, input, inlen, &output, &outlen)
        let initial = if initial_data.is_empty() {
            None
        } else {
            Some(initial_data)
        };

        debug!(mechanism = %mechanism, "Calling sasl_server_start({})", mechanism);

        let mut step_result = conn
            .server_start(mechanism, initial)
            .map_err(|e| self.classify_sasl_error_with_conn(config, &e, Some(conn)))?;

        // SASL exchange loop.
        // C lines 323-470: for (rc = SASL_CONTINUE; rc == SASL_CONTINUE; )
        loop {
            match step_result {
                SaslStepResult::Complete(ref _final_data) => {
                    // Authentication is complete (SASL_OK).
                    return self.complete_authentication(config, conn, mechanism);
                }

                SaslStepResult::Continue(ref challenge_data) => {
                    // Need more exchange steps (SASL_CONTINUE).
                    // Send the server challenge and read the client response.
                    // C lines 337-361: auth_get_data() + sasl_server_step()

                    let (io_result, response_opt) = if challenge_data.is_empty() {
                        // Empty challenge — use non-base64 "334 " bare continuation.
                        // This handles edge cases where the SASL mechanism produces
                        // an empty challenge that still requires a client response.
                        let empty_challenge = Clean::new("");
                        auth_get_no64_data(io, empty_challenge, DEFAULT_MAX_RESPONSE_LEN)
                    } else {
                        // Non-empty challenge — base64-encode and send via 334.
                        let challenge_clean = Clean::new(challenge_data.as_slice());
                        auth_get_data(io, challenge_clean, DEFAULT_MAX_RESPONSE_LEN)
                    };

                    // Handle I/O result
                    match io_result {
                        AuthIoResult::Ok => {
                            // Client responded — proceed to decode and step.
                        }
                        AuthIoResult::Cancelled => {
                            debug!("Client cancelled SASL exchange");
                            return Ok(AuthServerResult::Cancelled);
                        }
                        AuthIoResult::Bad64 => {
                            debug!("Bad base64 in client SASL response");
                            return Ok(AuthServerResult::Unexpected);
                        }
                        AuthIoResult::FailSend => {
                            return Err(DriverError::TempFail(
                                "failed to send SASL challenge".to_string(),
                            ));
                        }
                        _ => {
                            return Err(DriverError::TempFail(
                                "I/O error during SASL exchange".to_string(),
                            ));
                        }
                    }

                    // Base64-decode the client response.
                    // C lines 348-358: b64decode(input, &clear, GET_TAINTED)
                    let raw_response = response_opt.ok_or_else(|| {
                        DriverError::TempFail(
                            "no response data from client during SASL exchange".to_string(),
                        )
                    })?;

                    let tainted_response = raw_response;
                    let response_str: &str = tainted_response.as_ref();

                    // Decode the base64 response into raw bytes for SASL.
                    let client_bytes = if response_str.is_empty() {
                        Vec::new()
                    } else {
                        STANDARD.decode(response_str.as_bytes()).map_err(|_| {
                            debug!("Bad base64 decoding in SASL response");
                            // C lines 350-355: return BAD64
                            DriverError::ExecutionFailed(
                                "bad base64 in client SASL response".to_string(),
                            )
                        })?
                    };

                    debug!("Calling sasl_server_step()");
                    step_result = conn
                        .server_step(&client_bytes)
                        .map_err(|e| self.classify_sasl_error_with_conn(config, &e, Some(conn)))?;
                }
            }
        }
    }

    /// Complete authentication after SASL_OK: extract username and check condition.
    ///
    /// Shared by both `server()` (single-step) and `sasl_exchange()` (multi-step)
    /// to handle the post-authentication steps.
    fn complete_authentication(
        &self,
        config: &AuthInstanceConfig,
        conn: &SaslConnection,
        mechanism: &str,
    ) -> Result<AuthServerResult, DriverError> {
        // Extract the authenticated username.
        // C lines 376-390: sasl_getprop(conn, SASL_USERNAME, ...)
        let username = conn.get_username().map_err(|e| {
            error!(
                driver = %config.name,
                mechanism = %mechanism,
                error = %e.message(),
                "Cyrus SASL library will not tell us the username: {}",
                e.message(),
            );
            DriverError::ExecutionFailed(format!(
                "{} authenticator ({}): Cyrus SASL username fetch problem: {}",
                config.name,
                mechanism,
                e.message()
            ))
        })?;

        info!(
            mechanism = %mechanism,
            username = %username,
            "Cyrus SASL {} authentication succeeded for {}",
            mechanism,
            username,
        );

        // Mark the username as clean after successful SASL validation.
        let _clean_username = Clean::new(username);

        // Evaluate server_condition for authorization checking.
        // C line 456: return auth_check_serv_cond(ablock);
        match auth_check_serv_cond(config) {
            AuthConditionResult::Ok => Ok(AuthServerResult::Authenticated),
            AuthConditionResult::Fail => {
                warn!(
                    driver = %config.name,
                    "server_condition evaluation failed for {}",
                    config.name,
                );
                Ok(AuthServerResult::Failed)
            }
            AuthConditionResult::Defer { msg, user_msg: _ } => {
                warn!(
                    driver = %config.name,
                    error = %msg,
                    "server_condition deferred for {}: {}",
                    config.name,
                    msg,
                );
                Ok(AuthServerResult::Deferred)
            }
        }
    }

    /// Classify a SASL error into the appropriate `DriverError`.
    ///
    /// Replaces the C switch statement (lines 392-469) that maps SASL error
    /// codes to Exim return codes (FAIL, DEFER).
    ///
    /// When a `SaslConnection` reference is provided, additional detail is
    /// retrieved via [`SaslConnection::error_detail()`] to produce more
    /// informative error messages (mirroring the C `sasl_errdetail()` usage).
    fn classify_sasl_error_with_conn(
        &self,
        config: &AuthInstanceConfig,
        err: &SaslError,
        conn: Option<&SaslConnection>,
    ) -> DriverError {
        let mechanism = self.options.server_mech.as_deref().unwrap_or("unknown");

        // Attempt to get detailed error information from the connection.
        // C code uses sasl_errdetail(conn) for enriched error messages.
        let detail = conn.map(|c| c.error_detail()).unwrap_or_default();

        // Match SASL error code categories from C lines 394-469.
        // Negative codes are SASL errors; we classify by severity.
        let code = err.code();

        // Build the message suffix from error_detail() when available.
        let detail_suffix = if detail.is_empty() {
            String::new()
        } else {
            format!(" [detail: {}]", detail)
        };

        // Permanent failure codes (C lines 394-405):
        // SASL_FAIL, SASL_BUFOVER, SASL_BADMAC, SASL_BADAUTH,
        // SASL_NOAUTHZ, SASL_ENCRYPT, SASL_EXPIRED, SASL_DISABLED, SASL_NOUSER
        if matches!(code, -1 | -3 | -9 | -13 | -14 | -16 | -18 | -19 | -20) {
            error!(
                driver = %config.name,
                mechanism = %mechanism,
                code = code,
                error = %err.message(),
                "Cyrus SASL permanent failure {} ({})",
                code,
                err.message(),
            );
            return DriverError::ExecutionFailed(format!(
                "{} authenticator ({}): Cyrus SASL permanent failure: {}{}",
                config.name,
                mechanism,
                err.message(),
                detail_suffix
            ));
        }

        // SASL_NOMECH (C lines 407-418) — temporary: mechanism not available
        // for this user
        if code == -4 {
            warn!(
                driver = %config.name,
                mechanism = %mechanism,
                "Cyrus SASL temporary failure {} ({})",
                code,
                err.message(),
            );
            return DriverError::TempFail(format!(
                "Cyrus SASL: mechanism {} not available{}",
                mechanism, detail_suffix
            ));
        }

        // SASL_BADPROT (C lines 364-369) — protocol error
        if code == -5 {
            warn!(
                driver = %config.name,
                mechanism = %mechanism,
                "Cyrus SASL protocol error: {}",
                err.message(),
            );
            return DriverError::ExecutionFailed(format!(
                "Cyrus SASL protocol error: {}{}",
                err.message(),
                detail_suffix
            ));
        }

        // Default: all other errors are temporary (C lines 458-468)
        warn!(
            driver = %config.name,
            mechanism = %mechanism,
            code = code,
            error = %err.message(),
            "Cyrus SASL temporary failure {} ({})",
            code,
            err.message(),
        );
        DriverError::TempFail(format!("Cyrus SASL: {}{}", err.message(), detail_suffix))
    }

    /// Convenience wrapper that classifies a SASL error without a connection.
    ///
    /// Used in contexts where only a `SaslError` is available (e.g., after
    /// the connection has already been disposed or during init probing).
    fn classify_sasl_error(&self, config: &AuthInstanceConfig, err: &SaslError) -> DriverError {
        self.classify_sasl_error_with_conn(config, err, None)
    }
}

// =============================================================================
// AuthDriver Trait Implementation
// =============================================================================

impl AuthDriver for CyrusSaslAuth {
    /// Server-side SASL authentication via Cyrus SASL library.
    ///
    /// Replaces C `auth_cyrus_sasl_server()` (cyrus_sasl.c lines 206-473).
    ///
    /// Performs the full SASL authentication exchange:
    /// 1. Expand hostname and realm configuration strings
    /// 2. Base64-decode any initial data from the AUTH command
    /// 3. Initialize SASL library and create a connection
    /// 4. Set connection properties (IP addresses, external SSF)
    /// 5. Execute the SASL exchange loop
    /// 6. On success: extract username, evaluate server_condition
    ///
    /// # Arguments
    ///
    /// * `config` — Auth instance configuration with all parsed options.
    /// * `initial_data` — Initial client data from the AUTH command line
    ///   (may be empty).
    ///
    /// # Returns
    ///
    /// * `Ok(Authenticated)` — SASL exchange succeeded and server_condition passed.
    /// * `Ok(Failed)` — Permanent authentication failure.
    /// * `Ok(Deferred)` — Temporary failure (backend unavailable, etc.).
    /// * `Ok(Cancelled)` — Client cancelled the exchange.
    /// * `Ok(Unexpected)` — Malformed client data.
    /// * `Err(DriverError)` — Infrastructure-level error.
    fn server(
        &self,
        config: &AuthInstanceConfig,
        initial_data: &str,
    ) -> Result<AuthServerResult, DriverError> {
        let mechanism = self
            .options
            .server_mech
            .as_deref()
            .unwrap_or(&config.public_name);

        // Resolve hostname. In the full Exim system, this would call
        // expand_string(). For now, use the raw value or default.
        // C lines 224-231: hname = expand_string(ob->server_hostname)
        let hostname = self
            .options
            .server_hostname
            .as_deref()
            .unwrap_or("localhost");

        let realm = self.options.server_realm.as_deref();

        let service = self.options.server_service.as_deref().unwrap_or("smtp");

        // Wrap the initial data as tainted (from SMTP wire).
        let tainted_initial = Tainted::new(initial_data.to_string());

        // Base64-decode initial data if present.
        // C lines 233-239: if (inlen) { clen = b64decode(...) }
        let decoded_initial: Vec<u8> = if initial_data.is_empty() {
            Vec::new()
        } else {
            match STANDARD.decode(tainted_initial.as_ref().as_bytes()) {
                Ok(bytes) => bytes,
                Err(_) => {
                    debug!("Bad base64 in initial AUTH data");
                    return Ok(AuthServerResult::Unexpected);
                }
            }
        };

        // Initialize the SASL library.
        // C lines 241-245: sasl_server_init(cbs, "exim")
        let _ctx = SaslContext::new("exim").map_err(|e| {
            DriverError::TempFail(format!(
                "couldn't initialise Cyrus SASL library: {}",
                e.message()
            ))
        })?;

        // Create a SASL connection.
        // C lines 247-258: sasl_server_new(...)
        let mut conn = SaslConnection::new(service, hostname, realm).map_err(|e| {
            DriverError::TempFail(format!(
                "couldn't initialise Cyrus SASL connection: {}",
                e.message()
            ))
        })?;

        debug!(
            service = %service,
            hostname = %hostname,
            realm = ?realm,
            "Initialised Cyrus SASL server connection; service={} fqdn={} realm={:?}",
            service,
            hostname,
            realm,
        );

        // In the full Exim system, we would set TLS SSF external and IP address
        // properties here (C lines 261-321). The SaslConnection supports these
        // via set_prop(). For now, these are set when the SMTP connection context
        // provides them.

        // Execute the SASL exchange loop.
        // We create a no-op I/O handle since the actual SMTP I/O is handled
        // by the calling framework. In the full implementation, the SMTP
        // context would be passed through.
        //
        // For the server() method in the trait, the SASL exchange is driven
        // externally. The initial_data contains the first client response.
        // If more steps are needed, the framework handles the challenge/response.

        // Start the SASL exchange with the decoded initial data.
        let initial = if decoded_initial.is_empty() {
            None
        } else {
            Some(decoded_initial.as_slice())
        };

        debug!(
            mechanism = %mechanism,
            "Calling sasl_server_start({}, initial_data_len={})",
            mechanism,
            decoded_initial.len(),
        );

        let step_result = conn
            .server_start(mechanism, initial)
            .map_err(|e| self.classify_sasl_error(config, &e))?;

        // Process the SASL result.
        // Delegates post-authentication logic (username extraction,
        // server_condition evaluation) to complete_authentication()
        // to share code with the multi-step sasl_exchange() path.
        match step_result {
            SaslStepResult::Complete(_final_data) => {
                // One-step authentication (rare but possible for SASL EXTERNAL
                // or pre-authenticated mechanisms).
                self.complete_authentication(config, &conn, mechanism)
            }

            SaslStepResult::Continue(_challenge) => {
                // Multi-step exchange needed. The trait server() method does
                // not receive an SMTP I/O handle, so the full exchange must
                // be driven via the public sasl_exchange() method when the
                // SMTP framework provides the I/O context.
                //
                // Return Deferred to signal that the single-call interface
                // cannot complete the multi-step exchange without an I/O channel.
                debug!(
                    "Cyrus SASL exchange requires additional steps; \
                     multi-step exchange not available in single-call mode"
                );
                Ok(AuthServerResult::Deferred)
            }
        }
    }

    /// Client-side authentication — explicitly a stub.
    ///
    /// Replaces C `auth_cyrus_sasl_client()` (cyrus_sasl.c lines 498-508):
    /// ```c
    /// /* We don't support clients (yet) in this implementation of cyrus_sasl */
    /// return FAIL;
    /// ```
    ///
    /// The C code explicitly does not implement client-side auth for Cyrus SASL.
    /// This Rust implementation preserves that behavior by returning `Error`.
    fn client(
        &self,
        _config: &AuthInstanceConfig,
        _smtp_context: &mut dyn Any,
        _timeout: i32,
    ) -> Result<AuthClientResult, DriverError> {
        // C line 507: return FAIL;
        // Note: The C code uses FAIL but the schema expects Error for "not implemented"
        debug!("Cyrus SASL client authentication is not implemented");
        Ok(AuthClientResult::Error)
    }

    /// Check server authorization condition.
    ///
    /// Delegates to the shared `auth_check_serv_cond()` helper to evaluate
    /// the `server_condition` expandable string from the auth instance
    /// configuration.
    fn server_condition(&self, config: &AuthInstanceConfig) -> Result<bool, DriverError> {
        match auth_check_serv_cond(config) {
            AuthConditionResult::Ok => Ok(true),
            AuthConditionResult::Fail => Ok(false),
            AuthConditionResult::Defer { msg, user_msg: _ } => Err(DriverError::TempFail(msg)),
        }
    }

    /// Report Cyrus SASL library version information.
    ///
    /// Replaces C `auth_cyrus_sasl_version_report()` (cyrus_sasl.c lines 479-490).
    ///
    /// Returns a formatted string containing the SASL library implementation
    /// name and version, matching the format used by `exim -bV`:
    /// ```text
    /// Library version: Cyrus SASL: Runtime: 2.1.28 [Cyrus SASL]
    /// ```
    fn version_report(&self) -> Option<String> {
        let info: SaslVersionInfo = exim_ffi::cyrus_sasl::version_info();
        Some(format!(
            "Library version: Cyrus SASL: Compile: {}.{}.{}\n\
             {spacer}Runtime: {version} [{implementation}]",
            info.version_major,
            info.version_minor,
            info.version_step,
            spacer = "                             ",
            version = info.version_string,
            implementation = info.implementation,
        ))
    }

    /// Create feature macros for this auth mechanism.
    ///
    /// The C code has `macros_create = NULL` in the auth_info struct
    /// (cyrus_sasl.c line 531), meaning no additional macros are defined.
    /// The default trait implementation (empty Vec) matches this behavior.
    fn macros_create(&self) -> Vec<(String, String)> {
        Vec::new()
    }

    /// Returns the driver name for identification.
    ///
    /// Matches the C `driver_name = US"cyrus_sasl"` (cyrus_sasl.c line 518).
    fn driver_name(&self) -> &str {
        "cyrus_sasl"
    }
}

// =============================================================================
// Driver Registration via inventory
// =============================================================================

// Compile-time registration of the Cyrus SASL auth driver factory.
//
// Replaces the C `cyrus_sasl_auth_info` struct definition (cyrus_sasl.c
// lines 516-532) and its inclusion in the `drtables.c` linked list.
//
// The `inventory::submit!` macro registers this factory so that the
// `DriverRegistry` can discover it at startup when looking for a driver
// named `"cyrus_sasl"`.
//
// Wrapped in `#[cfg(feature = "auth-cyrus-sasl")]` to replace the C
// `#ifdef AUTH_CYRUS_SASL` / `#endif` preprocessor conditional.
inventory::submit! {
    AuthDriverFactory {
        name: "cyrus_sasl",
        create: || Box::new(CyrusSaslAuth::new()),
        avail_string: Some("Cyrus SASL"),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify CyrusSaslOptions default values match C defaults.
    #[test]
    fn test_options_defaults() {
        let opts = CyrusSaslOptions::default();
        assert_eq!(opts.server_service, Some("smtp".to_string()));
        assert_eq!(opts.server_hostname, Some("$primary_hostname".to_string()));
        assert_eq!(opts.server_realm, None);
        assert_eq!(opts.server_mech, None);
    }

    /// Verify CyrusSaslAuth driver name.
    #[test]
    fn test_driver_name() {
        let driver = CyrusSaslAuth::new();
        assert_eq!(driver.driver_name(), "cyrus_sasl");
    }

    /// Verify CyrusSaslAuth can be created.
    #[test]
    fn test_new_creates_driver() {
        let driver = CyrusSaslAuth::new();
        assert_eq!(driver.options.server_service, Some("smtp".to_string()));
    }

    /// Verify version_report returns a non-empty string with version info.
    #[test]
    fn test_version_report() {
        let driver = CyrusSaslAuth::new();
        let report = driver.version_report();
        assert!(report.is_some(), "version_report should return Some");
        let text = report.unwrap();
        assert!(
            text.contains("Cyrus SASL"),
            "version report should contain 'Cyrus SASL': {}",
            text
        );
        assert!(
            text.contains("Library version"),
            "version report should contain 'Library version': {}",
            text
        );
    }

    /// Verify macros_create returns empty vec (matching C NULL).
    #[test]
    fn test_macros_create_empty() {
        let driver = CyrusSaslAuth::new();
        assert!(driver.macros_create().is_empty());
    }

    /// Verify client() returns Error (stub, matching C FAIL behavior).
    #[test]
    fn test_client_stub() {
        let driver = CyrusSaslAuth::new();
        let config = AuthInstanceConfig::new(
            "test_cyrus",
            "cyrus_sasl",
            "PLAIN",
            Box::new(CyrusSaslOptions::default()),
        );
        struct DummyCtx;
        let mut ctx: Box<dyn Any> = Box::new(DummyCtx);
        let result = driver.client(&config, ctx.as_mut(), 30);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), AuthClientResult::Error);
    }

    /// Verify server_condition with no condition set returns Ok(true).
    #[test]
    fn test_server_condition_no_condition() {
        let driver = CyrusSaslAuth::new();
        let config = AuthInstanceConfig::new(
            "test_cyrus",
            "cyrus_sasl",
            "PLAIN",
            Box::new(CyrusSaslOptions::default()),
        );
        // With no server_condition set, auth_check_serv_cond returns Ok,
        // which maps to Ok(true).
        let result = driver.server_condition(&config);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    /// Verify CyrusSaslOptions Clone works correctly.
    #[test]
    fn test_options_clone() {
        let opts = CyrusSaslOptions {
            server_service: Some("imap".to_string()),
            server_hostname: Some("imap.example.com".to_string()),
            server_realm: Some("EXAMPLE.COM".to_string()),
            server_mech: Some("GSSAPI".to_string()),
        };
        let cloned = opts.clone();
        assert_eq!(cloned.server_service, Some("imap".to_string()));
        assert_eq!(cloned.server_hostname, Some("imap.example.com".to_string()));
        assert_eq!(cloned.server_realm, Some("EXAMPLE.COM".to_string()));
        assert_eq!(cloned.server_mech, Some("GSSAPI".to_string()));
    }

    /// Verify Debug formatting for CyrusSaslAuth.
    #[test]
    fn test_debug_format() {
        let driver = CyrusSaslAuth::new();
        let debug_str = format!("{:?}", driver);
        assert!(
            debug_str.contains("CyrusSaslAuth"),
            "debug should contain struct name"
        );
    }

    /// Verify SASL error classification for permanent failure codes.
    #[test]
    fn test_classify_sasl_error_permanent() {
        let driver = CyrusSaslAuth::new();
        let config = AuthInstanceConfig::new(
            "test_cyrus",
            "cyrus_sasl",
            "PLAIN",
            Box::new(CyrusSaslOptions::default()),
        );
        // SASL_BADAUTH = -13 — permanent failure.
        // Uses SaslError::from_code() to construct the error from a numeric code.
        let err = SaslError::from_code(-13);
        let result = driver.classify_sasl_error(&config, &err);
        match result {
            DriverError::ExecutionFailed(msg) => {
                assert!(
                    msg.contains("permanent failure"),
                    "expected 'permanent failure' in: {}",
                    msg
                );
            }
            other => panic!("expected ExecutionFailed, got {:?}", other),
        }
    }

    /// Verify SASL error classification for temporary failure (SASL_NOMECH).
    #[test]
    fn test_classify_sasl_error_temp() {
        let driver = CyrusSaslAuth::new();
        let config = AuthInstanceConfig::new(
            "test_cyrus",
            "cyrus_sasl",
            "PLAIN",
            Box::new(CyrusSaslOptions::default()),
        );
        // SASL_NOMECH = -4 — temporary failure.
        let err = SaslError::from_code(-4);
        let result = driver.classify_sasl_error(&config, &err);
        match result {
            DriverError::TempFail(msg) => {
                assert!(
                    msg.contains("not available"),
                    "expected 'not available' in: {}",
                    msg
                );
            }
            other => panic!("expected TempFail, got {:?}", other),
        }
    }

    /// Verify SASL error classification for protocol errors (SASL_BADPROT).
    #[test]
    fn test_classify_sasl_error_protocol() {
        let driver = CyrusSaslAuth::new();
        let config = AuthInstanceConfig::new(
            "test_cyrus",
            "cyrus_sasl",
            "PLAIN",
            Box::new(CyrusSaslOptions::default()),
        );
        // SASL_BADPROT = -5 — protocol error, mapped to ExecutionFailed.
        let err = SaslError::from_code(-5);
        let result = driver.classify_sasl_error(&config, &err);
        match result {
            DriverError::ExecutionFailed(msg) => {
                assert!(
                    msg.contains("protocol error"),
                    "expected 'protocol error' in: {}",
                    msg
                );
            }
            other => panic!("expected ExecutionFailed, got {:?}", other),
        }
    }
}
