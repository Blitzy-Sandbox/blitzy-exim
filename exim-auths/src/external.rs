// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! SASL EXTERNAL Mechanism Authenticator (RFC 4422 Appendix A)
//!
//! Rust rewrite of `src/src/auths/external.c` (186 lines) plus
//! `src/src/auths/external.h` (34 lines).  Implements both server-side
//! and client-side SASL EXTERNAL authentication.
//!
//! # Server Side
//!
//! 1. Parses the initial AUTH response by base64-decoding and splitting
//!    at NUL (0x00) byte boundaries into `$auth1`, `$auth2`, etc.
//! 2. Optionally expands `server_param2` and `server_param3`, storing
//!    the results as `$auth2` and `$auth3` (overriding decoded values).
//! 3. Evaluates `server_condition` for final authorization via
//!    [`auth_check_serv_cond`].
//!
//! # Client Side
//!
//! Sends a single `AUTH EXTERNAL` command with the expanded
//! `client_send` string (base64-encoded).  Uses [`auth_client_item`]
//! with `AUTH_ITEM_FIRST | AUTH_ITEM_LAST` flags for a one-step exchange.
//!
//! # Registration
//!
//! The driver is registered at compile time via `inventory::submit!`
//! with the name `"external"`, replacing the C `external_auth_info`
//! struct from `external.c` lines 167–183 and its entry in `drtables.c`.
//!
//! # Safety
//!
//! This module contains **zero `unsafe` blocks** (per AAP §0.7.2).
//! It is a pure Rust implementation with no FFI dependencies.

use std::any::Any;
use std::fmt;

// ── Internal workspace crate imports ────────────────────────────────────
use exim_drivers::auth_driver::{
    AuthClientResult, AuthDriver, AuthDriverFactory, AuthInstanceConfig, AuthServerResult,
};
use exim_drivers::DriverError;

use crate::helpers::base64_io::{
    auth_client_item, auth_read_input, AuthInstanceInfo, AuthIoResult, AuthSmtpIo, AuthVarsContext,
    StringExpander, AUTH_ITEM_FIRST, AUTH_ITEM_LAST,
};
use crate::helpers::server_condition::{auth_check_serv_cond, AuthConditionResult};

use exim_expand::{expand_string, ExpandError};
use exim_store::taint::Tainted;

// =============================================================================
// ExternalOptions — Driver-specific configuration options
// =============================================================================

/// Configuration options specific to the SASL EXTERNAL authenticator.
///
/// Replaces the C `auth_external_options_block` typedef from `external.h`
/// lines 12–17:
///
/// ```c
/// typedef struct {
///   uschar * server_param2;
///   uschar * server_param3;
///   uschar * client_send;
/// } auth_external_options_block;
/// ```
///
/// All fields are optional expansion strings, defaulting to `None`
/// (replacing the C `NULL` defaults from `external.c` lines 36–41).
///
/// # C Option Table Mapping
///
/// | C `optionlist` entry | Rust field       | Type           |
/// |----------------------|------------------|----------------|
/// | `"client_send"`      | `client_send`    | `Option<String>` |
/// | `"server_param2"`    | `server_param2`  | `Option<String>` |
/// | `"server_param3"`    | `server_param3`  | `Option<String>` |
#[derive(Debug, Clone)]
pub struct ExternalOptions {
    /// Second expansion parameter for server-side authentication.
    ///
    /// When set, this string is expanded after the initial AUTH data
    /// is decoded and the result overrides `$auth2`.  This allows the
    /// server configuration to inject computed values into the
    /// authorization context — for example, extracting the CN from
    /// the TLS client certificate.
    ///
    /// Replaces C `auth_external_options_block.server_param2`.
    pub server_param2: Option<String>,

    /// Third expansion parameter for server-side authentication.
    ///
    /// Like [`server_param2`](Self::server_param2), but overrides
    /// `$auth3`.  Only expanded when `server_param2` is also set
    /// (the C code nests the param3 expansion inside the param2
    /// block at `external.c` lines 118–124).
    ///
    /// Replaces C `auth_external_options_block.server_param3`.
    pub server_param3: Option<String>,

    /// Client initial response string for client-side authentication.
    ///
    /// Expanded and base64-encoded when Exim acts as an SMTP client
    /// authenticating with a remote server via SASL EXTERNAL.  The
    /// expanded value is sent as the initial response of the
    /// `AUTH EXTERNAL` command.
    ///
    /// Supports `^` escape sequences for NUL bytes (handled by the
    /// [`auth_client_item`] helper).
    ///
    /// Replaces C `auth_external_options_block.client_send`.
    pub client_send: Option<String>,
}

impl Default for ExternalOptions {
    /// Creates `ExternalOptions` with all fields set to `None`.
    ///
    /// Replaces the C default initializer at `external.c` lines 36–41:
    /// ```c
    /// auth_external_options_block auth_external_option_defaults = {
    ///     .server_param2 = NULL,
    ///     .server_param3 = NULL,
    ///     .client_send = NULL,
    /// };
    /// ```
    fn default() -> Self {
        Self {
            server_param2: None,
            server_param3: None,
            client_send: None,
        }
    }
}

// =============================================================================
// SmtpAuthClientCtx — Client-side SMTP context wrapper
// =============================================================================

/// Context for client-side AUTH EXTERNAL exchange.
///
/// The SMTP outbound layer constructs this struct and passes it as the
/// `smtp_context` parameter (type-erased as `&mut dyn Any`) when calling
/// [`ExternalAuth::client()`].
///
/// This struct wraps the SMTP I/O interface and string expansion engine
/// needed by [`auth_client_item`] to expand the `client_send` option,
/// encode and send the AUTH command, and process the server's response.
///
/// # Example Construction (in SMTP outbound layer)
///
/// ```ignore
/// let ctx = SmtpAuthClientCtx {
///     io: Box::new(my_smtp_connection),
///     expander: Box::new(my_string_expander),
/// };
/// driver.client(config, &mut ctx, timeout)?;
/// ```
pub struct SmtpAuthClientCtx {
    /// SMTP connection I/O handle for reading/writing protocol data.
    ///
    /// Provides `write_command_flush()` for sending AUTH commands and
    /// `read_response()` for reading server responses.
    pub io: Box<dyn AuthSmtpIo>,

    /// String expansion engine for resolving Exim configuration variables
    /// (e.g., `$tls_out_peerdn`, `$host`) in the `client_send` option.
    pub expander: Box<dyn StringExpander>,
}

// =============================================================================
// ExternalAuth — SASL EXTERNAL driver implementation
// =============================================================================

/// SASL EXTERNAL mechanism authenticator driver.
///
/// Implements the [`AuthDriver`] trait, providing both server-side and
/// client-side SASL EXTERNAL authentication.  The EXTERNAL mechanism
/// (RFC 4422 Appendix A) allows a server to authenticate a client based
/// on credentials established by external means — typically a TLS client
/// certificate.
///
/// # Server-Side Flow (replaces `auth_external_server`, C lines 87–128)
///
/// 1. Decode the initial AUTH response via [`auth_read_input()`]
/// 2. If `server_param2` is configured, expand and store as `$auth2`
/// 3. If `server_param3` is configured, expand and store as `$auth3`
/// 4. Evaluate `server_condition` via [`auth_check_serv_cond()`]
///
/// # Client-Side Flow (replaces `auth_external_client`, C lines 138–158)
///
/// 1. Expand `client_send` option string
/// 2. Base64-encode and send as `AUTH EXTERNAL <data>`
/// 3. Process server's 2xx/3xx/4xx/5xx response
///
/// # Configuration Example
///
/// ```text
/// # Server: trust TLS client certificate identity
/// external_server:
///   driver = external
///   server_condition = ${if eq{$tls_in_peerdn}{CN=relay}{yes}{no}}
///
/// # Client: present our identity to remote server
/// external_client:
///   driver = external
///   client_send = myserver.example.com
/// ```
pub struct ExternalAuth;

impl ExternalAuth {
    /// Create a new SASL EXTERNAL authenticator driver instance.
    ///
    /// The driver is stateless — all per-instance configuration is stored
    /// in the [`ExternalOptions`] block within [`AuthInstanceConfig`].
    pub fn new() -> Self {
        Self
    }
}

impl Default for ExternalAuth {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ExternalAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalAuth")
            .field("driver_name", &"external")
            .finish()
    }
}

// =============================================================================
// AuthDriver trait implementation
// =============================================================================

impl AuthDriver for ExternalAuth {
    /// Returns the driver identification name.
    ///
    /// This matches the `driver = external` configuration option and the
    /// C `external_auth_info.drinfo.driver_name` field (external.c line 169).
    fn driver_name(&self) -> &str {
        "external"
    }

    /// Server-side SASL EXTERNAL authentication processing.
    ///
    /// Replaces C `auth_external_server()` from `external.c` lines 87–128.
    ///
    /// # Processing Flow
    ///
    /// 1. **Decode initial response** — If the client provided initial data
    ///    with the AUTH command, base64-decode it and split at NUL boundaries
    ///    into `$auth1`, `$auth2`, etc. via [`auth_read_input()`].
    ///
    /// 2. **Expand `server_param2`** — If configured, expand the string and
    ///    store the result as `$auth2`, overriding any value from step 1.
    ///    Replaces C lines 112–117.
    ///
    /// 3. **Expand `server_param3`** — If configured (and `server_param2`
    ///    is also set), expand and store as `$auth3`.
    ///    Replaces C lines 118–124.
    ///
    /// 4. **Evaluate `server_condition`** — Delegate to
    ///    [`auth_check_serv_cond()`] for the final authorization decision.
    ///    Replaces C line 127.
    ///
    /// # Error Handling
    ///
    /// - Base64 decode failure → `AuthServerResult::Failed`
    /// - Forced expansion failure → `AuthServerResult::Failed`
    /// - Other expansion errors → `DriverError::ExecutionFailed`
    /// - Server condition defer → `AuthServerResult::Deferred`
    fn server(
        &self,
        config: &AuthInstanceConfig,
        initial_data: &str,
    ) -> Result<AuthServerResult, DriverError> {
        let opts = config
            .downcast_options::<ExternalOptions>()
            .ok_or_else(|| {
                DriverError::ConfigError(
                    "external auth: failed to downcast options to ExternalOptions".to_string(),
                )
            })?;

        tracing::debug!(
            authenticator = %config.name,
            driver = "external",
            initial_data_present = !initial_data.is_empty(),
            "server entry",
        );

        // ── Step 1: Decode initial AUTH response data ───────────────────
        //
        // Replaces C `external.c` lines 99–101:
        //   if (*data)
        //     if ((rc = auth_read_input(data)) != OK)
        //       return rc;
        //
        // The initial data is base64-encoded; auth_read_input() decodes it
        // and splits at NUL (0x00) byte boundaries, storing segments in
        // $auth1, $auth2, etc. (auth_vars) and $1, $2, etc. (expand_nstring).
        let mut ctx = AuthVarsContext::new();

        if !initial_data.is_empty() {
            let tainted_data = Tainted::new(initial_data);
            match auth_read_input(tainted_data, &mut ctx) {
                AuthIoResult::Ok => {
                    tracing::debug!(expand_nmax = ctx.expand_nmax, "decoded initial AUTH data",);
                }
                AuthIoResult::Bad64 => {
                    tracing::debug!("auth_read_input: invalid base64 in initial data");
                    return Ok(AuthServerResult::Failed);
                }
                AuthIoResult::Cancelled => {
                    tracing::debug!("auth_read_input: client cancelled");
                    return Ok(AuthServerResult::Cancelled);
                }
                AuthIoResult::FailSend => {
                    tracing::debug!("auth_read_input: transport send failure");
                    return Ok(AuthServerResult::Error);
                }
                AuthIoResult::Fail => {
                    tracing::debug!("auth_read_input: authentication failed");
                    return Ok(AuthServerResult::Failed);
                }
                AuthIoResult::Error(msg) => {
                    tracing::debug!(error = %msg, "auth_read_input: processing error");
                    return Err(DriverError::ExecutionFailed(msg));
                }
                AuthIoResult::Defer => {
                    // Defer from auth_read_input on initial data processing is
                    // unexpected; continue with whatever partial data was decoded.
                    tracing::debug!("auth_read_input: defer (continuing)");
                }
            }
        }

        // ── Step 2: Handle empty-data scenario ──────────────────────────
        //
        // Replaces C `external.c` lines 108–110:
        //   if (expand_nmax == 0)
        //     if ((rc = auth_prompt(CUS"")) != OK)
        //       return rc;
        //
        // In the C code, if no initial data was provided, an empty 334
        // challenge is sent to solicit the client's authorization identity.
        // In the Rust trait architecture, the SMTP inbound layer handles
        // the 334 challenge/response exchange before calling server().
        // If we still have no data, we proceed — the authorization
        // decision will rely on server_param2/3 and server_condition
        // (e.g., checking TLS certificate variables).
        if ctx.expand_nmax == 0 && initial_data.is_empty() {
            tracing::debug!(
                "no initial data received; proceeding with server_param expansion \
                 and server_condition evaluation",
            );
        }

        // ── Step 3: Expand server_param2 → override $auth2 ─────────────
        //
        // Replaces C `external.c` lines 112–117:
        //   if (ob->server_param2) {
        //     uschar * s = expand_string(ob->server_param2);
        //     auth_vars[expand_nmax = 1] = s;
        //     expand_nstring[++expand_nmax] = s;
        //     expand_nlength[expand_nmax] = Ustrlen(s);
        //
        // The C code sets expand_nmax to 1 (indexing auth_vars for $auth2),
        // then increments to 2 for the expand_nstring slot.
        if let Some(ref param2_str) = opts.server_param2 {
            let expanded2 = match expand_string(param2_str) {
                Ok(s) => s,
                Err(ExpandError::ForcedFail) => {
                    tracing::debug!("server_param2: forced expansion failure");
                    return Ok(AuthServerResult::Failed);
                }
                Err(e) => {
                    let msg = format!("external auth: expansion of server_param2 failed: {e}");
                    tracing::debug!(error = %e, "server_param2 expansion error");
                    return Err(DriverError::ExecutionFailed(msg));
                }
            };

            tracing::debug!(
                param = "server_param2",
                result = %expanded2,
                "expanded server_param2",
            );

            let len2 = expanded2.len();

            // C: auth_vars[expand_nmax = 1] = s;
            // → Set expand_nmax to 1, store in auth_vars[1] ($auth2)
            ctx.expand_nmax = 1;
            if ctx.auth_vars.len() > 1 {
                ctx.auth_vars[1] = Some(Tainted::new(expanded2.clone()));
            }

            // C: expand_nstring[++expand_nmax] = s;
            // → Increment expand_nmax to 2, store in expand_nstring[2]
            ctx.expand_nmax += 1;
            while ctx.expand_nstring.len() <= ctx.expand_nmax {
                ctx.expand_nstring.push(Tainted::new(String::new()));
            }
            while ctx.expand_nlength.len() <= ctx.expand_nmax {
                ctx.expand_nlength.push(0);
            }
            ctx.expand_nstring[ctx.expand_nmax] = Tainted::new(expanded2);
            ctx.expand_nlength[ctx.expand_nmax] = len2;

            // ── Step 4: Expand server_param3 → override $auth3 ──────────
            //
            // Replaces C `external.c` lines 118–124 (nested inside param2):
            //   if (ob->server_param3) {
            //     s = expand_string(ob->server_param3);
            //     auth_vars[expand_nmax] = s;
            //     expand_nstring[++expand_nmax] = s;
            //     expand_nlength[expand_nmax] = Ustrlen(s);
            //   }
            if let Some(ref param3_str) = opts.server_param3 {
                let expanded3 = match expand_string(param3_str) {
                    Ok(s) => s,
                    Err(ExpandError::ForcedFail) => {
                        tracing::debug!("server_param3: forced expansion failure");
                        return Ok(AuthServerResult::Failed);
                    }
                    Err(e) => {
                        let msg = format!("external auth: expansion of server_param3 failed: {e}");
                        tracing::debug!(error = %e, "server_param3 expansion error");
                        return Err(DriverError::ExecutionFailed(msg));
                    }
                };

                tracing::debug!(
                    param = "server_param3",
                    result = %expanded3,
                    "expanded server_param3",
                );

                let len3 = expanded3.len();

                // C: auth_vars[expand_nmax] = s;
                // → Store in auth_vars[2] ($auth3)
                if ctx.auth_vars.len() > ctx.expand_nmax {
                    ctx.auth_vars[ctx.expand_nmax] = Some(Tainted::new(expanded3.clone()));
                }

                // C: expand_nstring[++expand_nmax] = s;
                // → Increment expand_nmax to 3, store in expand_nstring[3]
                ctx.expand_nmax += 1;
                while ctx.expand_nstring.len() <= ctx.expand_nmax {
                    ctx.expand_nstring.push(Tainted::new(String::new()));
                }
                while ctx.expand_nlength.len() <= ctx.expand_nmax {
                    ctx.expand_nlength.push(0);
                }
                ctx.expand_nstring[ctx.expand_nmax] = Tainted::new(expanded3);
                ctx.expand_nlength[ctx.expand_nmax] = len3;
            }
        }

        // ── Step 5: Evaluate server_condition ───────────────────────────
        //
        // Replaces C `external.c` line 127:
        //   return auth_check_serv_cond(ablock);
        //
        // This evaluates the `server_condition` expandable string from the
        // auth instance config.  The expansion engine has access to $auth1,
        // $auth2, $auth3 (and TLS variables like $tls_in_peerdn) to make
        // the authorization decision.
        match auth_check_serv_cond(config) {
            AuthConditionResult::Ok => {
                tracing::debug!(
                    authenticator = %config.name,
                    "server_condition passed: authenticated",
                );
                Ok(AuthServerResult::Authenticated)
            }
            AuthConditionResult::Fail => {
                tracing::debug!(
                    authenticator = %config.name,
                    "server_condition failed: authentication rejected",
                );
                Ok(AuthServerResult::Failed)
            }
            AuthConditionResult::Defer { ref msg, .. } => {
                tracing::debug!(
                    authenticator = %config.name,
                    reason = %msg,
                    "server_condition deferred",
                );
                Ok(AuthServerResult::Deferred)
            }
        }
    }

    /// Client-side SASL EXTERNAL authentication processing.
    ///
    /// Replaces C `auth_external_client()` from `external.c` lines 138–158.
    ///
    /// Sends a single `AUTH EXTERNAL` command with the expanded `client_send`
    /// value as the initial response.  Uses `AUTH_ITEM_FIRST | AUTH_ITEM_LAST`
    /// flags for a one-step exchange (the EXTERNAL mechanism does not support
    /// multi-step challenge-response).
    ///
    /// # SMTP Context
    ///
    /// The `smtp_context` parameter must be a `&mut SmtpAuthClientCtx`
    /// (type-erased via `&mut dyn Any`).  The SMTP outbound layer constructs
    /// this before calling `client()`.
    ///
    /// # Return Value Mapping (from C)
    ///
    /// The C code maps `DEFER → FAIL` explicitly (line 154):
    /// ```c
    /// return rc == DEFER ? FAIL : rc;
    /// ```
    fn client(
        &self,
        config: &AuthInstanceConfig,
        smtp_context: &mut dyn Any,
        timeout: i32,
    ) -> Result<AuthClientResult, DriverError> {
        let opts = config
            .downcast_options::<ExternalOptions>()
            .ok_or_else(|| {
                DriverError::ConfigError(
                    "external auth: failed to downcast options to ExternalOptions".to_string(),
                )
            })?;

        // Get client_send text — empty string if not configured.
        // C `external.c` line 147: `const uschar * text = ob->client_send;`
        let text = opts.client_send.as_deref().unwrap_or("");

        tracing::debug!(
            authenticator = %config.name,
            driver = "external",
            client_send_configured = opts.client_send.is_some(),
            "client entry",
        );

        // Downcast the SMTP context to our expected wrapper type.
        let smtp_ctx = smtp_context
            .downcast_mut::<SmtpAuthClientCtx>()
            .ok_or_else(|| {
                DriverError::ConfigError(
                    "external auth client: smtp_context must be SmtpAuthClientCtx".to_string(),
                )
            })?;

        // Build auth instance metadata for the auth_client_item helper.
        // Replaces C access to `ablock->public_name` and `ablock->drinst.name`.
        let auth_info = AuthInstanceInfo {
            public_name: &config.public_name,
            driver_name: &config.name,
        };

        // Send AUTH EXTERNAL with the client_send value.
        //
        // Replaces C `external.c` lines 152–154:
        //   if ((rc = auth_client_item(sx, ablock, &text,
        //         AUTH_ITEM_FIRST | AUTH_ITEM_LAST,
        //         timeout, buffer, buffsize)) != OK)
        //     return rc == DEFER ? FAIL : rc;
        let timeout_u32 = if timeout > 0 { timeout as u32 } else { 0 };
        let mut buffer = String::new();
        let (result, _returned_text) = auth_client_item(
            &mut *smtp_ctx.io,
            &*smtp_ctx.expander,
            &auth_info,
            text,
            AUTH_ITEM_FIRST | AUTH_ITEM_LAST,
            timeout_u32,
            &mut buffer,
        );

        // Map the I/O result to an AuthClientResult.
        //
        // Key mapping from C: `rc == DEFER ? FAIL : rc`
        // AuthIoResult::Defer is mapped to AuthClientResult::Failed.
        match result {
            AuthIoResult::Ok => {
                // Authentication accepted — 2xx response received.
                //
                // C `external.c` lines 156–157:
                //   if (text) auth_vars[0] = string_copy(text);
                //   return OK;
                //
                // In the C code, `text` may be updated to point at decoded
                // continuation data.  For a successful 2xx exchange, there
                // is no continuation data, but the C code stores the
                // original text defensively.  In the Rust version, the
                // auth variable storage is handled at a higher level.
                tracing::debug!(
                    authenticator = %config.name,
                    "client: authentication succeeded",
                );
                Ok(AuthClientResult::Authenticated)
            }
            AuthIoResult::Defer => {
                // C: DEFER → FAIL (explicit mapping at line 154)
                tracing::debug!(
                    authenticator = %config.name,
                    "client: defer mapped to fail",
                );
                Ok(AuthClientResult::Failed)
            }
            AuthIoResult::Fail => {
                tracing::debug!(
                    authenticator = %config.name,
                    response = %buffer,
                    "client: server rejected authentication",
                );
                Ok(AuthClientResult::Failed)
            }
            AuthIoResult::Cancelled => {
                tracing::debug!(
                    authenticator = %config.name,
                    "client: exchange cancelled",
                );
                Ok(AuthClientResult::Cancelled)
            }
            AuthIoResult::FailSend => {
                tracing::debug!(
                    authenticator = %config.name,
                    "client: transport send failure",
                );
                Ok(AuthClientResult::Failed)
            }
            AuthIoResult::Bad64 => {
                tracing::debug!(
                    authenticator = %config.name,
                    "client: invalid base64 in response",
                );
                Ok(AuthClientResult::Failed)
            }
            AuthIoResult::Error(msg) => {
                tracing::debug!(
                    authenticator = %config.name,
                    error = %msg,
                    "client: processing error",
                );
                Err(DriverError::ExecutionFailed(msg))
            }
        }
    }

    /// Check the server authorization condition.
    ///
    /// Evaluates the `server_condition` from the auth instance configuration.
    /// This is the standalone condition-check entry point used by the SMTP
    /// framework independently of the full SASL exchange.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — Condition passed or was unset (no condition configured).
    /// - `Ok(false)` — Condition evaluated to a falsy value.
    /// - `Err(DriverError)` — Condition evaluation encountered a deferral
    ///   or expansion error.
    fn server_condition(&self, config: &AuthInstanceConfig) -> Result<bool, DriverError> {
        match auth_check_serv_cond(config) {
            AuthConditionResult::Ok => Ok(true),
            AuthConditionResult::Fail => Ok(false),
            AuthConditionResult::Defer { msg, .. } => Err(DriverError::ExecutionFailed(format!(
                "external auth: server_condition deferred: {msg}"
            ))),
        }
    }
}

// =============================================================================
// Driver Registration via inventory
// =============================================================================

// Register the EXTERNAL authenticator with the compile-time driver registry.
//
// This replaces the C `external_auth_info` struct from `external.c`
// lines 167–183 and its entry in `drtables.c`.  The factory is
// submitted via `inventory::submit!` so the registry module can
// discover and instantiate it at startup.
//
// The `auth-external` feature gate is handled at the module level in
// `lib.rs` (`#[cfg(feature = "auth-external")] pub mod external;`),
// so this submit! macro is only compiled when the feature is enabled.
inventory::submit! {
    AuthDriverFactory {
        name: "external",
        create: || Box::new(ExternalAuth::new()),
        avail_string: Some("EXTERNAL"),
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── ExternalOptions tests ───────────────────────────────────────────

    #[test]
    fn test_external_options_default_all_none() {
        let opts = ExternalOptions::default();
        assert!(
            opts.server_param2.is_none(),
            "server_param2 should default to None"
        );
        assert!(
            opts.server_param3.is_none(),
            "server_param3 should default to None"
        );
        assert!(
            opts.client_send.is_none(),
            "client_send should default to None"
        );
    }

    #[test]
    fn test_external_options_with_values() {
        let opts = ExternalOptions {
            server_param2: Some("$tls_in_peerdn".to_string()),
            server_param3: Some("${lookup{...}}".to_string()),
            client_send: Some("myhost.example.com".to_string()),
        };
        assert_eq!(opts.server_param2.as_deref(), Some("$tls_in_peerdn"));
        assert_eq!(opts.server_param3.as_deref(), Some("${lookup{...}}"));
        assert_eq!(opts.client_send.as_deref(), Some("myhost.example.com"));
    }

    #[test]
    fn test_external_options_clone() {
        let opts = ExternalOptions {
            server_param2: Some("param2".to_string()),
            server_param3: None,
            client_send: Some("send".to_string()),
        };
        let cloned = opts.clone();
        assert_eq!(opts.server_param2, cloned.server_param2);
        assert_eq!(opts.server_param3, cloned.server_param3);
        assert_eq!(opts.client_send, cloned.client_send);
    }

    #[test]
    fn test_external_options_debug_format() {
        let opts = ExternalOptions::default();
        let debug_str = format!("{opts:?}");
        assert!(debug_str.contains("ExternalOptions"));
        assert!(debug_str.contains("server_param2"));
        assert!(debug_str.contains("None"));
    }

    // ── ExternalAuth construction tests ─────────────────────────────────

    #[test]
    fn test_external_auth_new() {
        let auth = ExternalAuth::new();
        assert_eq!(auth.driver_name(), "external");
    }

    #[test]
    fn test_external_auth_driver_name() {
        let auth = ExternalAuth::new();
        assert_eq!(auth.driver_name(), "external");
    }

    #[test]
    fn test_external_auth_debug_format() {
        let auth = ExternalAuth::new();
        let debug_str = format!("{auth:?}");
        assert!(debug_str.contains("ExternalAuth"));
        assert!(debug_str.contains("external"));
    }

    // ── server_condition standalone test ─────────────────────────────────

    #[test]
    fn test_server_condition_no_condition_returns_true() {
        let auth = ExternalAuth::new();
        let config = AuthInstanceConfig::new(
            "test_external",
            "external",
            "EXTERNAL",
            Box::new(ExternalOptions::default()),
        );
        // When server_condition is None, auth_check_serv_cond returns Ok
        // (the default unset behavior), so server_condition() returns true.
        let result = auth.server_condition(&config);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    // ── server() with empty initial data and no params ──────────────────

    #[test]
    fn test_server_empty_data_no_params_no_condition() {
        let auth = ExternalAuth::new();
        let config = AuthInstanceConfig::new(
            "test_external",
            "external",
            "EXTERNAL",
            Box::new(ExternalOptions::default()),
        );
        // Empty initial data, no server_param2/3, no server_condition.
        // Should succeed because auth_check_serv_cond returns Ok when
        // no condition is configured.
        let result = auth.server(&config, "");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), AuthServerResult::Authenticated);
    }

    // ── server() with base64-encoded initial data ───────────────────────

    #[test]
    fn test_server_with_valid_base64_data() {
        let auth = ExternalAuth::new();
        let config = AuthInstanceConfig::new(
            "test_external",
            "external",
            "EXTERNAL",
            Box::new(ExternalOptions::default()),
        );
        // "dXNlcg==" is base64 for "user"
        let result = auth.server(&config, "dXNlcg==");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), AuthServerResult::Authenticated);
    }

    #[test]
    fn test_server_with_invalid_base64_data() {
        let auth = ExternalAuth::new();
        let config = AuthInstanceConfig::new(
            "test_external",
            "external",
            "EXTERNAL",
            Box::new(ExternalOptions::default()),
        );
        // Invalid base64 string
        let result = auth.server(&config, "!!!invalid!!!");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), AuthServerResult::Failed);
    }

    #[test]
    fn test_server_with_equals_sign_data() {
        let auth = ExternalAuth::new();
        let config = AuthInstanceConfig::new(
            "test_external",
            "external",
            "EXTERNAL",
            Box::new(ExternalOptions::default()),
        );
        // "=" means a single empty string (RFC 4954 §4)
        let result = auth.server(&config, "=");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), AuthServerResult::Authenticated);
    }

    // ── server() with server_param2 expansion ───────────────────────────

    #[test]
    fn test_server_with_server_param2_literal() {
        let auth = ExternalAuth::new();
        // server_param2 is a literal (no $ or \ chars → fast path returns as-is)
        let opts = ExternalOptions {
            server_param2: Some("computed_identity".to_string()),
            server_param3: None,
            client_send: None,
        };
        let config =
            AuthInstanceConfig::new("test_external", "external", "EXTERNAL", Box::new(opts));
        // The literal "computed_identity" should expand to itself.
        let result = auth.server(&config, "");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), AuthServerResult::Authenticated);
    }

    #[test]
    fn test_server_with_both_params_literal() {
        let auth = ExternalAuth::new();
        let opts = ExternalOptions {
            server_param2: Some("identity2".to_string()),
            server_param3: Some("identity3".to_string()),
            client_send: None,
        };
        let config =
            AuthInstanceConfig::new("test_external", "external", "EXTERNAL", Box::new(opts));
        let result = auth.server(&config, "");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), AuthServerResult::Authenticated);
    }

    // ── client() config downcast test ───────────────────────────────────

    #[test]
    fn test_client_bad_options_downcast() {
        let auth = ExternalAuth::new();
        // Pass the wrong options type to trigger downcast failure
        let config = AuthInstanceConfig::new(
            "test_external",
            "external",
            "EXTERNAL",
            Box::new(42_u32), // Wrong type — not ExternalOptions
        );
        let mut dummy: u32 = 0;
        let result = auth.client(&config, &mut dummy, 30);
        assert!(result.is_err());
        match result.unwrap_err() {
            DriverError::ConfigError(msg) => {
                assert!(msg.contains("ExternalOptions"));
            }
            other => panic!("expected ConfigError, got: {other:?}"),
        }
    }

    #[test]
    fn test_client_bad_smtp_context_downcast() {
        let auth = ExternalAuth::new();
        let config = AuthInstanceConfig::new(
            "test_external",
            "external",
            "EXTERNAL",
            Box::new(ExternalOptions::default()),
        );
        // Pass wrong smtp_context type
        let mut dummy: u32 = 0;
        let result = auth.client(&config, &mut dummy, 30);
        assert!(result.is_err());
        match result.unwrap_err() {
            DriverError::ConfigError(msg) => {
                assert!(msg.contains("SmtpAuthClientCtx"));
            }
            other => panic!("expected ConfigError, got: {other:?}"),
        }
    }

    // ── server() config downcast test ───────────────────────────────────

    #[test]
    fn test_server_bad_options_downcast() {
        let auth = ExternalAuth::new();
        let config = AuthInstanceConfig::new(
            "test_external",
            "external",
            "EXTERNAL",
            Box::new("wrong_type".to_string()),
        );
        let result = auth.server(&config, "");
        assert!(result.is_err());
        match result.unwrap_err() {
            DriverError::ConfigError(msg) => {
                assert!(msg.contains("ExternalOptions"));
            }
            other => panic!("expected ConfigError, got: {other:?}"),
        }
    }
}
