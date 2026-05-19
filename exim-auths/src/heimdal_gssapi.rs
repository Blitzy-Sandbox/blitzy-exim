// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! Kerberos GSSAPI Authenticator via Heimdal/MIT FFI.
//!
//! Rust rewrite of `src/src/auths/heimdal_gssapi.c` (640 lines) +
//! `src/src/auths/heimdal_gssapi.h` (40 lines). Implements server-side
//! Kerberos GSSAPI authentication via the `exim-ffi` krb5 module.
//!
//! # Protocol Overview
//!
//! The GSSAPI SASL mechanism (RFC 4752) uses a multi-step token exchange:
//!
//! 1. **Service name import** — Construct `service@hostname` and import via
//!    `gss_import_name` with `GSS_C_NT_HOSTBASED_SERVICE`.
//! 2. **Keytab registration** — Optionally set a specific keytab via
//!    `gsskrb5_register_acceptor_identity`.
//! 3. **Credential acquisition** — Acquire server credentials via
//!    `gss_acquire_cred` with `GSS_C_ACCEPT`.
//! 4. **Token exchange loop** — Repeatedly call `gss_accept_sec_context`
//!    with client tokens until `GSS_S_COMPLETE` is returned.
//! 5. **Security-layer negotiation** — Exchange 4-byte SASL security-layer
//!    capabilities. Exim only supports "no security layer" (0x01).
//! 6. **Identity extraction** — Use `gss_display_name` to get the
//!    authenticated Kerberos principal name.
//! 7. **Authorization check** — Evaluate `server_condition` for final
//!    authorization decision.
//!
//! # GSSAPI Resource Management
//!
//! All GSSAPI handles (`GssName`, `GssContext`, `GssCredential`) are RAII
//! wrappers in `exim_ffi::krb5` that call the corresponding release/free
//! function on `Drop`. No manual cleanup is needed in this module.
//!
//! # Safety
//!
//! This module contains **zero `unsafe` code** (per AAP §0.7.2). All GSSAPI
//! calls are encapsulated in the `exim-ffi` crate's safe wrappers.

use std::any::Any;
use std::cell::RefCell;
use std::fmt;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use tracing::{debug, error, info};

use exim_drivers::auth_driver::{
    AuthClientResult, AuthDriver, AuthDriverFactory, AuthInstanceConfig, AuthServerResult,
};
use exim_drivers::DriverError;
use exim_ffi::krb5::{
    register_acceptor_identity, GssContext, GssContextStepResult, GssCredential, GssName,
    GssapiError, Krb5Context,
};

use crate::helpers::base64_io::{
    auth_get_data, AuthIoResult, AuthSmtpIo, DEFAULT_MAX_RESPONSE_LEN,
};
use crate::helpers::server_condition::{auth_check_serv_cond, AuthConditionResult};

use exim_store::taint::Clean;

// =============================================================================
// Thread-Local SMTP I/O for Multi-Step Authentication
// =============================================================================

thread_local! {
    /// Thread-local SMTP I/O handle for multi-step authentication exchanges.
    ///
    /// The SMTP inbound code sets this before calling `AuthDriver::server()`
    /// and clears it afterward. This mirrors the C pattern where SMTP I/O
    /// was accessible through global state (fork-per-connection model ensures
    /// thread-local is effectively per-connection).
    static SMTP_IO: RefCell<Option<Box<dyn AuthSmtpIo>>> = const { RefCell::new(None) };
}

/// Install the SMTP I/O handle for the current connection's auth exchange.
///
/// Must be called by the SMTP inbound code before invoking
/// `AuthDriver::server()` for any multi-step authentication mechanism
/// (GSSAPI, GSASL, etc.). The handle is consumed and stored in thread-local
/// storage until [`clear_smtp_io`] is called.
///
/// # Arguments
///
/// * `io` — The SMTP connection I/O handle implementing [`AuthSmtpIo`].
pub fn set_smtp_io(io: Box<dyn AuthSmtpIo>) {
    SMTP_IO.with(|cell| {
        *cell.borrow_mut() = Some(io);
    });
}

/// Clear the SMTP I/O handle after the authentication exchange completes.
///
/// Called by the SMTP inbound code after `AuthDriver::server()` returns to
/// release the I/O handle back to the connection manager.
pub fn clear_smtp_io() -> Option<Box<dyn AuthSmtpIo>> {
    SMTP_IO.with(|cell| cell.borrow_mut().take())
}

// =============================================================================
// HeimdalGssapiOptions — Driver-Specific Configuration
// =============================================================================

/// Driver-specific options for the Heimdal GSSAPI authenticator.
///
/// Replaces C `auth_heimdal_gssapi_options_block` from `heimdal_gssapi.h`
/// lines 18–22. All fields are `Option<String>`:
///
/// | C Field           | Rust Field         | C Default              |
/// |-------------------|--------------------|------------------------|
/// | `server_hostname` | `server_hostname`  | `$primary_hostname`    |
/// | `server_keytab`   | `server_keytab`    | `NULL` (system default)|
/// | `server_service`  | `server_service`   | `"smtp"`               |
///
/// When `server_hostname` is `None`, the calling code should substitute the
/// system's primary hostname. When `server_service` is `None`, `"smtp"` is
/// used as the default.
#[derive(Default)]
pub struct HeimdalGssapiOptions {
    /// Kerberos service hostname for the principal `{service}@{hostname}`.
    ///
    /// Defaults to the system's primary hostname in the C code
    /// (`$primary_hostname`). Callers should expand this string and set
    /// the result before storing in `AuthInstanceConfig.options`.
    pub server_hostname: Option<String>,

    /// Path to the Kerberos keytab file.
    ///
    /// When set, the keytab is registered via
    /// `gsskrb5_register_acceptor_identity()` before credential acquisition.
    /// When `None`, the system default keytab is used.
    pub server_keytab: Option<String>,

    /// Kerberos service name (e.g., `"smtp"`, `"imap"`).
    ///
    /// Combined with `server_hostname` to form the service principal
    /// `{service}@{hostname}`. Defaults to `"smtp"`.
    pub server_service: Option<String>,
}

impl fmt::Debug for HeimdalGssapiOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeimdalGssapiOptions")
            .field("server_hostname", &self.server_hostname)
            .field(
                "server_keytab",
                &self.server_keytab.as_deref().unwrap_or("<system default>"),
            )
            .field("server_service", &self.server_service)
            .finish()
    }
}

// =============================================================================
// HeimdalGssapiAuth — Driver Implementation
// =============================================================================

/// Heimdal GSSAPI authenticator driver.
///
/// Implements server-side Kerberos GSSAPI authentication via the `exim-ffi`
/// krb5 module. Client-side authentication is not implemented (matching the
/// C code at `heimdal_gssapi.c` line 594: "Client side NOT IMPLEMENTED").
///
/// Registered via `inventory::submit!` as `"heimdal_gssapi"`.
#[derive(Debug)]
pub struct HeimdalGssapiAuth;

impl HeimdalGssapiAuth {
    /// Create a new Heimdal GSSAPI authenticator driver instance.
    pub fn new() -> Self {
        Self
    }

    /// Extract the `HeimdalGssapiOptions` from the auth instance config.
    ///
    /// Downcasts `config.options` to `HeimdalGssapiOptions`, returning an
    /// error if the options are not the expected type.
    fn get_options(config: &AuthInstanceConfig) -> Result<&HeimdalGssapiOptions, DriverError> {
        config
            .downcast_options::<HeimdalGssapiOptions>()
            .ok_or_else(|| {
                DriverError::ConfigError(
                    "heimdal_gssapi: invalid options type in AuthInstanceConfig".to_string(),
                )
            })
    }

    /// Resolve the effective service name, defaulting to `"smtp"` if unset.
    fn effective_service(opts: &HeimdalGssapiOptions) -> &str {
        opts.server_service.as_deref().unwrap_or("smtp")
    }

    /// Resolve the effective hostname, returning an error if unset.
    fn effective_hostname(opts: &HeimdalGssapiOptions) -> Result<&str, DriverError> {
        opts.server_hostname.as_deref().ok_or_else(|| {
            DriverError::ConfigError(
                "heimdal_gssapi: server_hostname is required but not configured".to_string(),
            )
        })
    }

    /// Perform the complete GSSAPI server-side authentication exchange.
    ///
    /// This is the core implementation of C `auth_heimdal_gssapi_server()`
    /// (lines 227–538). It handles all six steps of the GSSAPI SASL exchange:
    ///
    /// 1. Service name import via `gss_import_name`
    /// 2. Optional keytab registration via `gsskrb5_register_acceptor_identity`
    /// 3. Credential acquisition via `gss_acquire_cred`
    /// 4. Multi-step token exchange via `gss_accept_sec_context`
    /// 5. Security-layer negotiation (no-security-layer handshake)
    /// 6. Identity extraction via `gss_display_name`
    ///
    /// # Arguments
    ///
    /// * `config` — The auth instance configuration.
    /// * `opts`   — The Heimdal GSSAPI-specific options.
    /// * `initial_data` — The initial AUTH command data (possibly empty).
    /// * `io` — The SMTP I/O handle for multi-step challenge/response.
    ///
    /// # Returns
    ///
    /// - `Ok(AuthServerResult::Authenticated)` on success.
    /// - `Ok(AuthServerResult::Failed)` on authentication failure.
    /// - `Ok(AuthServerResult::Deferred)` on temporary failure.
    /// - `Ok(AuthServerResult::Cancelled)` if client cancelled.
    /// - `Err(DriverError)` on infrastructure failure.
    fn perform_server_exchange(
        &self,
        config: &AuthInstanceConfig,
        opts: &HeimdalGssapiOptions,
        initial_data: &str,
        io: &mut dyn AuthSmtpIo,
    ) -> Result<AuthServerResult, DriverError> {
        let service = Self::effective_service(opts);
        let hostname = Self::effective_hostname(opts)?;

        debug!(
            driver = "heimdal_gssapi",
            instance = %config.name,
            "initialising auth context for {}",
            config.name,
        );

        // ── Step 1: Import service name ─────────────────────────────────
        //
        // Construct "service@hostname" and import via gss_import_name with
        // GSS_C_NT_HOSTBASED_SERVICE. Replaces C lines 256–265.
        let gss_name = GssName::import_service(service, hostname).map_err(|e| {
            error!(
                driver = "heimdal_gssapi",
                "gss_import_name({service}@{hostname}) failed: {e}",
            );
            DriverError::TempFail(format!("gss_import_name({service}@{hostname}): {e}"))
        })?;
        debug!("heimdal: imported service name {}@{}", service, hostname,);

        // ── Step 2: Register keytab (optional) ─────────────────────────
        //
        // If server_keytab is configured, register it via
        // gsskrb5_register_acceptor_identity. Replaces C lines 268–276.
        if let Some(ref keytab_path) = opts.server_keytab {
            register_acceptor_identity(keytab_path).map_err(|e| {
                error!(
                    driver = "heimdal_gssapi",
                    "keytab registration failed for {keytab_path}: {e}",
                );
                DriverError::TempFail(format!("registering keytab {keytab_path}: {e}"))
            })?;
            debug!("heimdal: using keytab {}", keytab_path);
        }

        // ── Step 3: Acquire server credentials ─────────────────────────
        //
        // gss_acquire_cred with GSS_C_ACCEPT usage for the service principal.
        // Replaces C lines 278–293.
        let cred = GssCredential::acquire_accept(&gss_name).map_err(|e| {
            error!(
                driver = "heimdal_gssapi",
                "gss_acquire_cred({service}@{hostname}) failed: {e}",
            );
            DriverError::TempFail(format!("gss_acquire_cred({service}@{hostname}): {e}"))
        })?;
        debug!("heimdal: have server credentials");

        // ── Step 4: Token exchange loop ─────────────────────────────────
        //
        // Multi-step GSSAPI context establishment. The loop mirrors C lines
        // 296–379 (step values 0–1 in the C state machine).
        let mut ctx: GssContext = GssContext::new();
        let mut from_client: String = initial_data.to_string();
        let mut handled_empty_ir: bool = false;
        let mut client_name: Option<GssName> = None;

        // Step 0: Handle empty initial response (C lines 315–334)
        if from_client.is_empty() {
            debug!("gssapi: missing initial response, nudging");
            let (io_result, response) =
                auth_get_data(io, Clean::new(&[] as &[u8]), DEFAULT_MAX_RESPONSE_LEN);
            match io_result {
                AuthIoResult::Ok => {
                    if let Some(resp) = response {
                        from_client = resp.into_inner();
                        handled_empty_ir = true;
                    } else {
                        return Ok(AuthServerResult::Unexpected);
                    }
                }
                AuthIoResult::Cancelled => return Ok(AuthServerResult::Cancelled),
                AuthIoResult::Bad64 => return Ok(AuthServerResult::Unexpected),
                AuthIoResult::FailSend => {
                    return Err(DriverError::ExecutionFailed(
                        "failed to send initial 334 challenge".to_string(),
                    ));
                }
                _ => {
                    return Err(DriverError::ExecutionFailed(
                        "unexpected I/O error during initial nudge".to_string(),
                    ));
                }
            }
        }

        // Repeated empty check — C lines 318–323
        if from_client.is_empty() {
            if handled_empty_ir {
                debug!("gssapi: repeated empty input, grr");
                return Ok(AuthServerResult::Unexpected);
            }
            return Ok(AuthServerResult::Unexpected);
        }

        debug!("heimdal: have initial client data");

        // Token exchange loop — C step 1 (lines 336–379)
        loop {
            // Base64-decode the client token
            let input_token = STANDARD.decode(from_client.as_bytes()).map_err(|_| {
                debug!("heimdal: invalid base64 in client token");
                DriverError::ExecutionFailed("invalid base64 in GSSAPI client token".to_string())
            })?;

            // Call gss_accept_sec_context
            let (step_result, step_client_name) = ctx.accept(&cred, &input_token).map_err(|e| {
                error!(
                    driver = "heimdal_gssapi",
                    "gss_accept_sec_context failed: {e}",
                );
                DriverError::ExecutionFailed(format!("gss_accept_sec_context: {e}"))
            })?;

            // Update the client name if returned
            if step_client_name.is_some() {
                client_name = step_client_name;
            }

            match step_result {
                GssContextStepResult::Continue(output_token) => {
                    // Send the output token to the client and get next response
                    debug!("heimdal: need more data");
                    let (io_result, response) = auth_get_data(
                        io,
                        Clean::new(output_token.as_slice()),
                        DEFAULT_MAX_RESPONSE_LEN,
                    );
                    match io_result {
                        AuthIoResult::Ok => {
                            if let Some(resp) = response {
                                from_client = resp.into_inner();
                            } else {
                                return Ok(AuthServerResult::Unexpected);
                            }
                        }
                        AuthIoResult::Cancelled => return Ok(AuthServerResult::Cancelled),
                        AuthIoResult::Bad64 => return Ok(AuthServerResult::Unexpected),
                        AuthIoResult::FailSend => {
                            return Err(DriverError::ExecutionFailed(
                                "failed to send GSSAPI continuation token".to_string(),
                            ));
                        }
                        _ => {
                            return Err(DriverError::ExecutionFailed(
                                "unexpected I/O error during token exchange".to_string(),
                            ));
                        }
                    }
                    // Continue the loop with the new client data
                }
                GssContextStepResult::Done(output_token) => {
                    // If there's a final output token, send it as a challenge.
                    // The client's response is consumed but not stored, since
                    // the next step (security-layer negotiation) sends a new
                    // challenge and reads a fresh response. This matches C
                    // heimdal_gssapi.c lines 366–378 where from_client is
                    // overwritten by step 2.
                    debug!("heimdal: GSS complete");

                    if !output_token.is_empty() {
                        let (io_result, _response) = auth_get_data(
                            io,
                            Clean::new(output_token.as_slice()),
                            DEFAULT_MAX_RESPONSE_LEN,
                        );
                        match io_result {
                            AuthIoResult::Ok => {
                                // Response consumed; security-layer negotiation
                                // will send a new challenge and read fresh data.
                            }
                            AuthIoResult::Cancelled => return Ok(AuthServerResult::Cancelled),
                            _ => {
                                return Err(DriverError::ExecutionFailed(
                                    "failed to complete GSSAPI final token".to_string(),
                                ));
                            }
                        }
                    }
                    break;
                }
            }
        }

        // ── Step 5: Security-layer negotiation ──────────────────────────
        //
        // SASL GSSAPI (draft-ietf-sasl-gssapi-06) requires a security-layer
        // capabilities exchange after the GSSAPI context is established.
        //
        // Server sends 4 bytes (wrapped with gss_wrap):
        //   Byte 0: bitmask of supported security layers
        //     0x01 = No security layer
        //     0x02 = Integrity protection
        //     0x04 = Confidentiality protection
        //   Bytes 1-3: maximum buffer size for wrapped content (network order)
        //
        // Exim only supports "no security layer" (0x01), with maximum buffer
        // size 0xFFFFFF. Replaces C lines 381–418.
        let sasl_capabilities: [u8; 4] = [0x01, 0xFF, 0xFF, 0xFF];

        // Wrap the capabilities with GSSAPI integrity protection and send
        // as a 334 challenge. The client unwraps, selects a security layer,
        // wraps its response, and sends it back.
        let wrapped_caps = ctx.wrap(&sasl_capabilities, false).map_err(|e| {
            error!(
                driver = "heimdal_gssapi",
                "gss_wrap(SASL state after auth) failed: {e}",
            );
            DriverError::ExecutionFailed(format!("gss_wrap(SASL state): {e}"))
        })?;

        debug!("heimdal SASL: requesting QOP with no security layers");

        let (io_result, sasl_response) = auth_get_data(
            io,
            Clean::new(wrapped_caps.as_slice()),
            DEFAULT_MAX_RESPONSE_LEN,
        );
        match io_result {
            AuthIoResult::Ok => {}
            AuthIoResult::Cancelled => return Ok(AuthServerResult::Cancelled),
            _ => {
                return Err(DriverError::ExecutionFailed(
                    "failed during SASL security-layer exchange".to_string(),
                ));
            }
        }

        let sasl_response_b64 = sasl_response
            .ok_or_else(|| {
                DriverError::ExecutionFailed(
                    "empty response to SASL security-layer challenge".to_string(),
                )
            })?
            .into_inner();

        // ── Step 5b: Unwrap and verify client's security-layer choice ───
        //
        // Decode the base64 response, then unwrap with gss_unwrap.
        // Replaces C lines 421–454.
        let sasl_wrapped = STANDARD.decode(sasl_response_b64.as_bytes()).map_err(|_| {
            debug!("heimdal: invalid base64 in SASL security-layer response");
            DriverError::ExecutionFailed(
                "invalid base64 in SASL security-layer response".to_string(),
            )
        })?;

        let sasl_unwrapped = ctx.unwrap(&sasl_wrapped).map_err(|e| {
            error!(
                driver = "heimdal_gssapi",
                "gss_unwrap(final SASL message from client) failed: {e}",
            );
            DriverError::ExecutionFailed(format!("gss_unwrap(final SASL message from client): {e}"))
        })?;

        // The unwrapped message must be at least 4 bytes:
        //   Byte 0: client's chosen security layer bitmask
        //   Bytes 1-3: client's maximum buffer size
        //   Bytes 4+: optional authorization identity (authzid)
        if sasl_unwrapped.len() < 4 {
            debug!(
                "gssapi: final message too short ({}); need flags, buf sizes and optional authzid",
                sasl_unwrapped.len(),
            );
            return Ok(AuthServerResult::Failed);
        }

        let requested_qop = sasl_unwrapped[0];
        if requested_qop & 0x01 == 0 {
            debug!(
                "gssapi: client requested security layers ({:#04x}) — Exim only supports no-security-layer",
                requested_qop,
            );
            return Ok(AuthServerResult::Failed);
        }

        // ── Step 6: Extract authenticated identity ──────────────────────
        //
        // Use gss_display_name to get the authenticated Kerberos principal.
        // Store in $auth1. The optional SASL authzid (bytes 4+ of the
        // unwrapped message) goes in $auth2.
        // Replaces C lines 456–510.

        // $auth2: SASL authzid (unverified, from client)
        let authzid = if sasl_unwrapped.len() > 4 {
            let authz_bytes = &sasl_unwrapped[4..];
            Some(String::from_utf8_lossy(authz_bytes).into_owned())
        } else {
            None
        };

        // $auth1: GSSAPI display name (verified by Kerberos)
        let gss_display: String = match &client_name {
            Some(name) => name.display().map_err(|e: GssapiError| {
                error!(
                    driver = "heimdal_gssapi",
                    "gss_display_name(client identifier) failed: {e}",
                );
                DriverError::ExecutionFailed(format!("gss_display_name(client identifier): {e}"))
            })?,
            None => {
                error!(
                    driver = "heimdal_gssapi",
                    "no client name available after GSSAPI exchange",
                );
                return Ok(AuthServerResult::Failed);
            }
        };

        // If no authzid was provided, duplicate the GSSAPI display name
        // (matching C behavior at lines 494–501).
        let effective_authzid = authzid.unwrap_or_else(|| {
            debug!("heimdal SASL: empty authzid, set to dup of GSSAPI display name");
            gss_display.clone()
        });

        debug!(
            "heimdal SASL: happy with client request\n  \
             auth1 (verified GSSAPI display-name): {}\n  \
             auth2 (unverified SASL requested authzid): {}",
            gss_display, effective_authzid,
        );

        info!(
            driver = "heimdal_gssapi",
            auth1 = %gss_display,
            auth2 = %effective_authzid,
            "GSSAPI authentication succeeded for {}",
            gss_display,
        );

        // ── Step 7: Check server_condition ──────────────────────────────
        //
        // Delegate to auth_check_serv_cond for final authorization.
        // Replaces C line 537: `return auth_check_serv_cond(ablock);`
        match auth_check_serv_cond(config) {
            AuthConditionResult::Ok => Ok(AuthServerResult::Authenticated),
            AuthConditionResult::Fail => {
                debug!(
                    driver = "heimdal_gssapi",
                    "server_condition evaluation failed for {}", gss_display,
                );
                Ok(AuthServerResult::Failed)
            }
            AuthConditionResult::Defer { msg, user_msg } => {
                error!(
                    driver = "heimdal_gssapi",
                    defer_msg = %msg,
                    defer_user_msg = ?user_msg,
                    "server_condition deferred for {}",
                    gss_display,
                );
                Err(DriverError::TempFail(msg))
            }
        }
    }
}

impl Default for HeimdalGssapiAuth {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// AuthDriver Trait Implementation
// =============================================================================

impl AuthDriver for HeimdalGssapiAuth {
    /// Returns the driver name `"heimdal_gssapi"`.
    ///
    /// Matches the C `driver_name` at `heimdal_gssapi.c` line 622:
    /// `.driver_name = US"heimdal_gssapi"`.
    fn driver_name(&self) -> &str {
        "heimdal_gssapi"
    }

    /// Server-side GSSAPI authentication exchange.
    ///
    /// Implements the complete multi-step GSSAPI SASL exchange per RFC 4752.
    /// Replaces C `auth_heimdal_gssapi_server()` (lines 227–538).
    ///
    /// The SMTP I/O handle is obtained from thread-local storage, which must
    /// be set by the calling SMTP inbound code via [`set_smtp_io`] before
    /// invoking this method.
    ///
    /// # Arguments
    ///
    /// - `config` — Auth instance configuration with `HeimdalGssapiOptions`
    ///   stored in `config.options`.
    /// - `initial_data` — The AUTH command initial response data (base64-encoded).
    ///   May be empty if the client did not provide initial data.
    ///
    /// # Returns
    ///
    /// See [`HeimdalGssapiAuth::perform_server_exchange`] for return values.
    fn server(
        &self,
        config: &AuthInstanceConfig,
        initial_data: &str,
    ) -> Result<AuthServerResult, DriverError> {
        let opts = Self::get_options(config)?;

        // Validate that the service is configured
        let service = Self::effective_service(opts);
        if service.is_empty() {
            return Err(DriverError::ConfigError(
                "heimdal_gssapi: server_service is empty".to_string(),
            ));
        }

        // Access the thread-local SMTP I/O handle for multi-step exchange.
        // In the C code, SMTP I/O was accessible through global state; in
        // Rust, we use thread-local storage set by the SMTP inbound code.
        SMTP_IO.with(|io_cell| {
            let mut io_opt = io_cell.borrow_mut();
            match io_opt.as_mut() {
                Some(io) => self.perform_server_exchange(config, opts, initial_data, io.as_mut()),
                None => {
                    // No SMTP I/O handle available — this means the calling
                    // code did not set up the thread-local I/O context. For
                    // GSSAPI, which requires multi-step exchange, this is a
                    // configuration error.
                    error!(
                        driver = "heimdal_gssapi",
                        "SMTP I/O handle not available — call set_smtp_io() before server()",
                    );
                    Err(DriverError::ExecutionFailed(
                        "heimdal_gssapi requires SMTP I/O for multi-step exchange; \
                         call set_smtp_io() before server()"
                            .to_string(),
                    ))
                }
            }
        })
    }

    /// Client-side GSSAPI authentication — **not implemented**.
    ///
    /// The C code at `heimdal_gssapi.c` lines 586–598 explicitly states
    /// "Client side NOT IMPLEMENTED" and returns `FAIL`. This Rust port
    /// preserves that behavior.
    fn client(
        &self,
        _config: &AuthInstanceConfig,
        _smtp_context: &mut dyn Any,
        _timeout: i32,
    ) -> Result<AuthClientResult, DriverError> {
        debug!(
            driver = "heimdal_gssapi",
            "Client side NOT IMPLEMENTED: you should not see this!",
        );
        Ok(AuthClientResult::Failed)
    }

    /// Evaluate the `server_condition` for authorization.
    ///
    /// Delegates to [`auth_check_serv_cond`] from the shared helpers module.
    /// This is the common pattern used by all 9 authenticator drivers.
    ///
    /// Replaces C `auth_check_serv_cond(ablock)` at `heimdal_gssapi.c`
    /// line 537.
    fn server_condition(&self, config: &AuthInstanceConfig) -> Result<bool, DriverError> {
        match auth_check_serv_cond(config) {
            AuthConditionResult::Ok => Ok(true),
            AuthConditionResult::Fail => Ok(false),
            AuthConditionResult::Defer { msg, .. } => Err(DriverError::TempFail(msg)),
        }
    }

    /// Report the Heimdal/MIT Kerberos library version.
    ///
    /// Replaces C `auth_heimdal_gssapi_version_report()` at
    /// `heimdal_gssapi.c` lines 604–613. The C code accessed the global
    /// variables `heimdal_version` and `heimdal_long_version`; in Rust we
    /// verify Kerberos library availability by initializing a context.
    fn version_report(&self) -> Option<String> {
        match Krb5Context::new() {
            Ok(_ctx) => Some(
                "Library version: Heimdal: Runtime: available\n \
                 Build Info: linked via exim-ffi"
                    .to_string(),
            ),
            Err(e) => Some(format!(
                "Library version: Heimdal: initialization failed: {e}"
            )),
        }
    }
}

// =============================================================================
// Compile-Time Driver Registration
// =============================================================================

// Register the Heimdal GSSAPI authenticator with the driver registry.
//
// Uses `inventory::submit!` for compile-time registration (per AAP §0.7.3),
// replacing the C `auth_info heimdal_gssapi_auth_info` struct at
// `heimdal_gssapi.c` lines 620–636.
//
// The factory creates a new `HeimdalGssapiAuth` instance when the driver
// registry resolves the name `"heimdal_gssapi"` from configuration.
inventory::submit! {
    AuthDriverFactory {
        name: "heimdal_gssapi",
        create: || Box::new(HeimdalGssapiAuth::new()),
        avail_string: Some("Heimdal GSSAPI"),
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the driver name matches the C registration name.
    #[test]
    fn test_driver_name() {
        let driver = HeimdalGssapiAuth::new();
        assert_eq!(driver.driver_name(), "heimdal_gssapi");
    }

    /// Verify default options are all None.
    #[test]
    fn test_default_options() {
        let opts = HeimdalGssapiOptions::default();
        assert!(opts.server_hostname.is_none());
        assert!(opts.server_keytab.is_none());
        assert!(opts.server_service.is_none());
    }

    /// Verify effective_service defaults to "smtp".
    #[test]
    fn test_effective_service_default() {
        let opts = HeimdalGssapiOptions::default();
        assert_eq!(HeimdalGssapiAuth::effective_service(&opts), "smtp");
    }

    /// Verify effective_service uses configured value.
    #[test]
    fn test_effective_service_configured() {
        let opts = HeimdalGssapiOptions {
            server_service: Some("imap".to_string()),
            ..Default::default()
        };
        assert_eq!(HeimdalGssapiAuth::effective_service(&opts), "imap");
    }

    /// Verify effective_hostname returns error when not configured.
    #[test]
    fn test_effective_hostname_missing() {
        let opts = HeimdalGssapiOptions::default();
        assert!(HeimdalGssapiAuth::effective_hostname(&opts).is_err());
    }

    /// Verify effective_hostname returns configured value.
    #[test]
    fn test_effective_hostname_configured() {
        let opts = HeimdalGssapiOptions {
            server_hostname: Some("mail.example.com".to_string()),
            ..Default::default()
        };
        assert_eq!(
            HeimdalGssapiAuth::effective_hostname(&opts).unwrap(),
            "mail.example.com",
        );
    }

    /// Verify client() returns Failed (NOT IMPLEMENTED).
    #[test]
    fn test_client_not_implemented() {
        let driver = HeimdalGssapiAuth::new();
        let config = AuthInstanceConfig::new(
            "test_gssapi",
            "heimdal_gssapi",
            "GSSAPI",
            Box::new(HeimdalGssapiOptions::default()),
        );
        struct DummyCtx;
        let mut ctx: Box<dyn Any> = Box::new(DummyCtx);
        let result = driver.client(&config, ctx.as_mut(), 30);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), AuthClientResult::Failed);
    }

    /// Verify server_condition with no condition returns true (Ok).
    #[test]
    fn test_server_condition_unset() {
        let driver = HeimdalGssapiAuth::new();
        let config = AuthInstanceConfig::new(
            "test_gssapi",
            "heimdal_gssapi",
            "GSSAPI",
            Box::new(HeimdalGssapiOptions::default()),
        );
        // When server_condition is None, auth_check_serv_cond returns Ok
        let result = driver.server_condition(&config);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    /// Verify server() returns error when options type is wrong.
    #[test]
    fn test_server_wrong_options_type() {
        let driver = HeimdalGssapiAuth::new();
        let config = AuthInstanceConfig::new(
            "test_gssapi",
            "heimdal_gssapi",
            "GSSAPI",
            Box::new(42_u32), // Wrong type
        );
        let result = driver.server(&config, "");
        assert!(result.is_err());
    }

    /// Verify version_report returns some string.
    #[test]
    fn test_version_report() {
        let driver = HeimdalGssapiAuth::new();
        let report = driver.version_report();
        assert!(report.is_some());
        // The report should mention Heimdal
        let text = report.unwrap();
        assert!(text.contains("Heimdal"));
    }

    /// Verify HeimdalGssapiOptions Debug output.
    #[test]
    fn test_options_debug() {
        let opts = HeimdalGssapiOptions {
            server_hostname: Some("mail.example.com".to_string()),
            server_keytab: None,
            server_service: Some("smtp".to_string()),
        };
        let dbg = format!("{:?}", opts);
        assert!(dbg.contains("mail.example.com"));
        assert!(dbg.contains("smtp"));
        assert!(dbg.contains("system default"));
    }

    /// Verify thread-local SMTP I/O set/clear lifecycle.
    #[test]
    fn test_smtp_io_lifecycle() {
        // Initially should be None
        SMTP_IO.with(|cell| {
            assert!(cell.borrow().is_none());
        });

        // clear_smtp_io on empty should return None
        let cleared = clear_smtp_io();
        assert!(cleared.is_none());
    }

    /// Verify the HeimdalGssapiAuth Default trait.
    #[test]
    fn test_default_trait() {
        let driver = HeimdalGssapiAuth::default();
        assert_eq!(driver.driver_name(), "heimdal_gssapi");
    }
}
