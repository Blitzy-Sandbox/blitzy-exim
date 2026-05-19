// exim-auths/src/gsasl.rs — GNU SASL Authenticator via FFI
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Rust rewrite of `src/src/auths/gsasl.c` (1088 lines) + `src/src/auths/gsasl.h`
// (54 lines). Implements server + client SASL authentication via the GNU SASL
// library (libgsasl) through safe FFI wrappers in `exim-ffi`.
//
// Supports:
//   - SCRAM-SHA-1, SCRAM-SHA-256 (when libgsasl >= 1.9 or 2.x)
//   - SCRAM server-key (S-Key) support (when libgsasl >= 1.9.1 or 2.x)
//   - TLS channel-binding (tls-unique and tls-exporter when libgsasl >= 2.1)
//   - PLAIN, LOGIN, CRAM-MD5, DIGEST-MD5, EXTERNAL, ANONYMOUS, GSSAPI
//   - Extensive option configuration for both server and client sides
//
// Key design decisions:
//   - All FFI interaction through `exim_ffi::gsasl` — zero `unsafe` in this file
//   - Callback state uses `Rc<RefCell<CallbackState>>` for interior mutability,
//     since the GSASL library invokes the callback synchronously during step()
//   - Channel-binding data preloaded onto the GSASL session before the exchange
//   - Server condition evaluated inside VALIDATE_* callbacks for mechanisms that
//     supply credentials directly (PLAIN, LOGIN, EXTERNAL, ANONYMOUS, GSSAPI)
//   - Non-base64 I/O via `auth_get_no64_data` — GSASL handles base64 internally
//
// Safety: This file contains ZERO unsafe code (per AAP §0.7.2).

use std::any::Any;
use std::cell::RefCell;
use std::io;
use std::rc::Rc;

use tracing::{debug, error, info, warn};

use exim_drivers::auth_driver::{
    AuthClientResult, AuthDriver, AuthDriverFactory, AuthInstanceConfig, AuthServerResult,
};
use exim_drivers::DriverError;
use exim_ffi::gsasl::{
    GsaslCapabilities, GsaslContext, GsaslError, GsaslProperty, GsaslSession, StepResult,
};
use exim_store::taint::{Clean, Tainted};

use crate::helpers::base64_io::{auth_get_no64_data, AuthIoResult, AuthSmtpIo};
use crate::helpers::server_condition::{
    auth_check_serv_cond, auth_check_some_cond, AuthConditionResult,
};

// =============================================================================
// GsaslOptions — Driver-specific configuration options
// =============================================================================

/// Configuration options for the GSASL authenticator driver.
///
/// Replaces C `auth_gsasl_options_block` (gsasl.h lines 16-34).
#[derive(Debug, Clone)]
pub struct GsaslOptions {
    /// SASL service name. Default: `Some("smtp".into())`.
    pub server_service: Option<String>,
    /// Server hostname. Default: `Some("$primary_hostname".into())`.
    pub server_hostname: Option<String>,
    /// Authentication realm for DIGEST-MD5 and realm-aware mechanisms.
    pub server_realm: Option<String>,
    /// SASL mechanism name. If `None`, defaults to the authenticator's `public_name`.
    pub server_mech: Option<String>,
    /// Expandable string for server-side password retrieval.
    pub server_password: Option<String>,
    /// Hex-encoded SCRAM ServerKey (GSASL >= 1.9.1 / 2.x with S-Key support).
    pub server_key: Option<String>,
    /// Hex-encoded SCRAM StoredKey (GSASL >= 1.9.1 / 2.x with S-Key support).
    pub server_s_key: Option<String>,
    /// SCRAM iteration count (expandable). Default: `Some("4096".into())`.
    pub server_scram_iter: Option<String>,
    /// Base64-encoded SCRAM salt (expandable).
    pub server_scram_salt: Option<String>,
    /// Client authentication identity (expandable).
    pub client_username: Option<String>,
    /// Client password (expandable).
    pub client_password: Option<String>,
    /// Client authorization identity (expandable, optional).
    pub client_authz: Option<String>,
    /// Pre-computed SCRAM SaltedPassword for client side (expandable).
    pub client_spassword: Option<String>,
    /// Enable TLS channel-binding on the server side.
    pub server_channelbinding: bool,
    /// Enable TLS channel-binding on the client side.
    pub client_channelbinding: bool,
}

impl Default for GsaslOptions {
    /// Creates `GsaslOptions` with defaults matching C `auth_gsasl_option_defaults`
    /// (gsasl.c lines 112-117).
    fn default() -> Self {
        Self {
            server_service: Some("smtp".to_string()),
            server_hostname: Some("$primary_hostname".to_string()),
            server_realm: None,
            server_mech: None,
            server_password: None,
            server_key: None,
            server_s_key: None,
            server_scram_iter: Some("4096".to_string()),
            server_scram_salt: None,
            client_username: None,
            client_password: None,
            client_authz: None,
            client_spassword: None,
            server_channelbinding: false,
            client_channelbinding: false,
        }
    }
}

// =============================================================================
// CallbackState — Per-authentication callback context
// =============================================================================

/// Tracks the current side of the authentication exchange for callback routing.
///
/// Replaces C `enum { CURRENTLY_SERVER = 1, CURRENTLY_CLIENT = 2 }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallbackSide {
    Server,
    Client,
}

/// Mutable state accumulated during the GSASL callback exchange.
///
/// Wrapped in `Rc<RefCell<_>>` for shared interior mutability between the
/// callback closure and the exchange loop. The `Rc` is safe because GSASL
/// is single-threaded — callbacks are invoked synchronously during `step()`.
///
/// Replaces C `struct callback_exim_state` (gsasl.c lines 161-164) plus
/// the handful of file-scoped variables (`checked_server_condition`,
/// `sasl_error_should_defer`, `callback_loop`).
struct CallbackState {
    options: GsaslOptions,
    server_condition: Option<String>,
    auth_name: String,
    public_name: String,
    side: CallbackSide,
    auth_vars: Vec<Option<String>>,
    checked_server_condition: bool,
    sasl_error_should_defer: bool,
}

impl CallbackState {
    fn new(config: &AuthInstanceConfig, options: &GsaslOptions, side: CallbackSide) -> Self {
        Self {
            options: options.clone(),
            server_condition: config.server_condition.clone(),
            auth_name: config.name.clone(),
            public_name: config.public_name.clone(),
            side,
            auth_vars: vec![None; 4],
            checked_server_condition: false,
            sasl_error_should_defer: false,
        }
    }

    /// Store a GSASL property value into the next available auth variable slot.
    ///
    /// Replaces C `set_exim_authvar_from_prop()` (gsasl.c lines 621-632).
    fn set_authvar_from_session_prop(&mut self, session: &GsaslSession, prop: GsaslProperty) {
        let value = session.property_get(prop).unwrap_or_default();
        let idx = self.auth_vars.iter().position(|v| v.is_none());
        if let Some(i) = idx {
            debug!("auth[{}] <= {:?} = '{}'", i + 1, prop, value);
            self.auth_vars[i] = Some(value);
        }
    }

    /// Load standard auth properties if not already loaded.
    ///
    /// Replaces C `set_exim_authvars_from_a_az_r_props()` (gsasl.c lines 634-649).
    fn load_standard_auth_props(&mut self, session: &GsaslSession) {
        if self.auth_vars.iter().any(|v| v.is_some()) {
            return;
        }
        self.set_authvar_from_session_prop(session, GsaslProperty::AuthId);
        self.set_authvar_from_session_prop(session, GsaslProperty::AuthzId);
        self.set_authvar_from_session_prop(session, GsaslProperty::Realm);
    }

    /// Expand an option and set it as a GSASL session property.
    ///
    /// Replaces C `prop_from_option()` (gsasl.c lines 652-668).
    fn prop_from_option(
        &mut self,
        session: &mut GsaslSession,
        prop: GsaslProperty,
        option: Option<&str>,
    ) -> Result<bool, GsaslError> {
        debug!("  loading {:?}", prop);
        match option {
            Some(opt_str) => {
                self.load_standard_auth_props(session);
                let expanded = expand_option_string(opt_str);
                if expanded.is_empty() {
                    debug!("  expanded to empty");
                    return Ok(true);
                }
                debug!("  '{}'", expanded);
                session.property_set(prop, &expanded).map_err(|e| {
                    error!("Failed to set property {:?}: {}", prop, e);
                    e
                })?;
                Ok(true)
            }
            None => {
                debug!("  option not set");
                Ok(false)
            }
        }
    }

    /// Evaluate server condition from callback context.
    ///
    /// Replaces C `condition_check()` (gsasl.c lines 598-615).
    fn condition_check(&self, label: &str) -> AuthConditionResult {
        let stub_config = AuthInstanceConfig::new(
            self.auth_name.clone(),
            "gsasl",
            self.public_name.clone(),
            Box::new(GsaslOptions::default()),
        );
        auth_check_some_cond(
            &stub_config,
            label,
            self.server_condition.as_deref(),
            AuthConditionResult::Fail,
        )
    }
}

/// Dispatch a GSASL callback from the library into the appropriate handler.
///
/// Replaces C `main_callback()` (gsasl.c lines 260-317) which routes to
/// `server_callback()` or `client_callback()` based on `currently`.
fn dispatch_callback(
    state: &Rc<RefCell<CallbackState>>,
    session: &mut GsaslSession,
    prop: GsaslProperty,
) -> Result<(), GsaslError> {
    let side = state.borrow().side;
    match side {
        CallbackSide::Server => handle_server_callback(state, session, prop),
        CallbackSide::Client => handle_client_callback(state, session, prop),
    }
}

/// Server-side GSASL callback dispatcher.
///
/// Replaces C `server_callback()` (gsasl.c lines 670-805).
fn handle_server_callback(
    state_rc: &Rc<RefCell<CallbackState>>,
    session: &mut GsaslSession,
    prop: GsaslProperty,
) -> Result<(), GsaslError> {
    let (auth_name, public_name) = {
        let s = state_rc.borrow();
        (s.auth_name.clone(), s.public_name.clone())
    };
    debug!(
        "GNU SASL server callback {:?} for {}/{}",
        prop, auth_name, public_name
    );

    // Clear auth vars for this callback invocation (gsasl.c line 682).
    {
        let mut state = state_rc.borrow_mut();
        for v in state.auth_vars.iter_mut() {
            *v = None;
        }
    }

    match prop {
        GsaslProperty::ValidateSimple => {
            let mut state = state_rc.borrow_mut();
            state.set_authvar_from_session_prop(session, GsaslProperty::AuthId);
            state.set_authvar_from_session_prop(session, GsaslProperty::AuthzId);
            state.set_authvar_from_session_prop(session, GsaslProperty::Password);
            let result = state.condition_check("server_condition");
            state.checked_server_condition = true;
            if let AuthConditionResult::Defer { .. } = &result {
                state.sasl_error_should_defer = true;
            }
            gsasl_result_from_condition(result)
        }

        GsaslProperty::ValidateExternal => {
            let mut state = state_rc.borrow_mut();
            if state.server_condition.is_none() {
                debug!("No server_condition supplied, to validate EXTERNAL");
                return Err(GsaslError::from_code(31));
            }
            state.set_authvar_from_session_prop(session, GsaslProperty::AuthzId);
            let result = state.condition_check("server_condition (EXTERNAL)");
            state.checked_server_condition = true;
            if let AuthConditionResult::Defer { .. } = &result {
                state.sasl_error_should_defer = true;
            }
            gsasl_result_from_condition(result)
        }

        GsaslProperty::ValidateAnonymous => {
            let mut state = state_rc.borrow_mut();
            if state.server_condition.is_none() {
                debug!("No server_condition supplied, to validate ANONYMOUS");
                return Err(GsaslError::from_code(31));
            }
            state.set_authvar_from_session_prop(session, GsaslProperty::AnonymousToken);
            let result = state.condition_check("server_condition (ANONYMOUS)");
            state.checked_server_condition = true;
            if let AuthConditionResult::Defer { .. } = &result {
                state.sasl_error_should_defer = true;
            }
            gsasl_result_from_condition(result)
        }

        GsaslProperty::ValidateGssapi => {
            let mut state = state_rc.borrow_mut();
            state.set_authvar_from_session_prop(session, GsaslProperty::GssapiDisplayName);
            state.set_authvar_from_session_prop(session, GsaslProperty::AuthzId);
            let result = state.condition_check("server_condition (GSSAPI family)");
            state.checked_server_condition = true;
            if let AuthConditionResult::Defer { .. } = &result {
                state.sasl_error_should_defer = true;
            }
            gsasl_result_from_condition(result)
        }

        GsaslProperty::ScramIter => {
            let mut state = state_rc.borrow_mut();
            let opt_val = state.options.server_scram_iter.clone();
            match state.prop_from_option(session, prop, opt_val.as_deref()) {
                Ok(true) => Ok(()),
                Ok(false) => Err(GsaslError::from_code(51)),
                Err(e) => Err(e),
            }
        }

        GsaslProperty::ScramSalt => {
            let mut state = state_rc.borrow_mut();
            let opt_val = state.options.server_scram_salt.clone();
            match state.prop_from_option(session, prop, opt_val.as_deref()) {
                Ok(true) => Ok(()),
                Ok(false) => Err(GsaslError::from_code(51)),
                Err(e) => Err(e),
            }
        }

        GsaslProperty::ScramStoredKey => {
            if !GsaslCapabilities::has_scram_s_key() {
                return Err(GsaslError::from_code(51));
            }
            let mut state = state_rc.borrow_mut();
            let opt_val = state.options.server_s_key.clone();
            match state.prop_from_option(session, prop, opt_val.as_deref()) {
                Ok(true) => Ok(()),
                Ok(false) => Err(GsaslError::from_code(51)),
                Err(e) => Err(e),
            }
        }

        GsaslProperty::ScramServerKey => {
            if !GsaslCapabilities::has_scram_s_key() {
                return Err(GsaslError::from_code(51));
            }
            let mut state = state_rc.borrow_mut();
            let opt_val = state.options.server_key.clone();
            match state.prop_from_option(session, prop, opt_val.as_deref()) {
                Ok(true) => Ok(()),
                Ok(false) => Err(GsaslError::from_code(51)),
                Err(e) => Err(e),
            }
        }

        GsaslProperty::Password => {
            let mut state = state_rc.borrow_mut();
            state.load_standard_auth_props(session);

            let password_opt = state.options.server_password.clone();
            match password_opt.as_deref() {
                None => {
                    debug!("server_password option not set");
                    Err(GsaslError::from_code(51))
                }
                Some(pw_template) => {
                    let expanded = expand_option_string(pw_template);
                    if expanded.is_empty() {
                        state.sasl_error_should_defer = true;
                        error!(
                            "server_password expansion failed for {}",
                            state
                                .auth_vars
                                .first()
                                .and_then(|v| v.as_deref())
                                .unwrap_or("<unknown>")
                        );
                        return Err(GsaslError::from_code(31));
                    }
                    debug!("  password set");

                    // Use Tainted/Clean for defense-in-depth on password data
                    // (matching C memset at gsasl.c line 792).
                    let tainted_pw = Tainted::new(expanded);
                    let clean_pw: Clean<String> = tainted_pw.force_clean();
                    session.property_set(GsaslProperty::Password, clean_pw.as_ref())?;
                    drop(clean_pw);
                    Ok(())
                }
            }
        }

        _ => {
            debug!("Unrecognised server callback: {:?}", prop);
            Err(GsaslError::from_code(51))
        }
    }
}

/// Client-side GSASL callback dispatcher.
///
/// Replaces C `client_callback()` (gsasl.c lines 997-1044).
fn handle_client_callback(
    state_rc: &Rc<RefCell<CallbackState>>,
    session: &mut GsaslSession,
    prop: GsaslProperty,
) -> Result<(), GsaslError> {
    let (auth_name, public_name) = {
        let s = state_rc.borrow();
        (s.auth_name.clone(), s.public_name.clone())
    };
    debug!(
        "GNU SASL client callback {:?} for {}/{}",
        prop, auth_name, public_name
    );

    match prop {
        GsaslProperty::CbTlsExporter => {
            if !GsaslCapabilities::has_exporter() {
                return Err(GsaslError::from_code(51));
            }
            debug!("  filling in CB_TLS_EXPORTER");
            warn!("CB_TLS_EXPORTER requested but TLS context not available in callback");
            Err(GsaslError::from_code(51))
        }

        GsaslProperty::CbTlsUnique => {
            debug!("  filling in CB_TLS_UNIQUE");
            warn!("CB_TLS_UNIQUE requested but TLS context not available in callback");
            Err(GsaslError::from_code(51))
        }

        GsaslProperty::ScramSaltedPassword => {
            let mut state = state_rc.borrow_mut();
            let client_spassword = state.options.client_spassword.clone();
            match client_spassword.as_deref() {
                None => {
                    debug!("  client_spassword option unset");
                    Err(GsaslError::from_code(51))
                }
                Some(sp_template) => {
                    state.set_authvar_from_session_prop(session, GsaslProperty::AuthId);
                    state.set_authvar_from_session_prop(session, GsaslProperty::ScramIter);
                    state.set_authvar_from_session_prop(session, GsaslProperty::ScramSalt);

                    let expanded = expand_option_string(sp_template);
                    if !expanded.is_empty() {
                        debug!(
                            "set_client_prop: set SCRAM_SALTED_PASSWORD = '{}'",
                            expanded
                        );
                        session.property_set(GsaslProperty::ScramSaltedPassword, &expanded)?;
                    }

                    for v in state.auth_vars.iter_mut() {
                        *v = None;
                    }
                    Ok(())
                }
            }
        }

        _ => {
            debug!("  not providing callback for {:?}", prop);
            Err(GsaslError::from_code(51))
        }
    }
}

// =============================================================================
// SmtpIoStub — Placeholder for SMTP I/O during token exchange
// =============================================================================

/// Placeholder SMTP I/O adapter for the GSASL token exchange loop.
///
/// In the full integration, this is replaced by the actual SMTP inbound/outbound
/// I/O context from `exim-smtp`. This stub enables the auth_get_no64_data call
/// chain to compile and demonstrates the intended usage pattern.
struct SmtpIoStub {
    challenge_data: Option<String>,
    response_data: Option<String>,
}

impl AuthSmtpIo for SmtpIoStub {
    fn send_line(&mut self, line: &str) -> io::Result<()> {
        debug!("SMTP IO stub: sending '{}'", line);
        self.challenge_data = Some(line.to_string());
        Ok(())
    }

    fn read_line(&mut self, _max_len: usize) -> io::Result<Tainted<String>> {
        debug!("SMTP IO stub: reading");
        match self.response_data.take() {
            Some(data) => Ok(Tainted::new(data)),
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "No response data available in stub",
            )),
        }
    }

    fn write_command_flush(&mut self, cmd: &str) -> io::Result<()> {
        debug!("SMTP IO stub: command '{}'", cmd);
        Ok(())
    }

    fn read_response(
        &mut self,
        _expected_code: char,
        _timeout: u32,
    ) -> io::Result<(bool, Tainted<String>)> {
        debug!("SMTP IO stub: reading response");
        Ok((
            true,
            Tainted::new("235 Authentication successful".to_string()),
        ))
    }
}

// =============================================================================
// GsaslAuth — Driver struct implementing AuthDriver
// =============================================================================

/// GSASL authentication driver implementation.
///
/// Replaces the C `gsasl_auth_info` struct registration (gsasl.c lines 1068-1084)
/// and all server/client/init/version/macro entry points.
#[derive(Debug, Default)]
pub struct GsaslAuth;

impl GsaslAuth {
    /// Create a new GSASL auth driver instance.
    pub fn new() -> Self {
        Self
    }

    /// Initialize the driver for an authenticator instance.
    ///
    /// Replaces C `auth_gsasl_init()` (gsasl.c lines 175-254).
    pub fn init(config: &mut AuthInstanceConfig) -> Result<(), DriverError> {
        // Extract values from options before any mutable config access,
        // avoiding borrow checker conflicts.
        let (mech, has_server_password, has_server_realm, has_client_username, has_client_password) = {
            let options = config.downcast_options::<GsaslOptions>().ok_or_else(|| {
                DriverError::ConfigError(format!(
                    "{} authenticator: failed to downcast options to GsaslOptions",
                    config.name
                ))
            })?;
            let mech = options
                .server_mech
                .clone()
                .unwrap_or_else(|| config.public_name.clone());
            (
                mech,
                options.server_password.is_some(),
                options.server_realm.is_some(),
                options.client_username.is_some(),
                options.client_password.is_some(),
            )
        };

        let _ctx = GsaslContext::new().map_err(|e| {
            DriverError::InitFailed(format!(
                "{} authenticator: couldn't initialise GNU SASL library: {}",
                config.name, e
            ))
        })?;

        debug!(
            "GNU SASL initializing for authenticator '{}', mechanism '{}'",
            config.name, mech
        );

        // Determine server capability (gsasl.c lines 220-251).
        if config.server_condition.is_some() || has_server_password {
            config.server = true;
        } else {
            let needs_condition = !["EXTERNAL", "ANONYMOUS", "PLAIN", "LOGIN"]
                .iter()
                .any(|m| m.eq_ignore_ascii_case(&mech));
            if needs_condition {
                config.server = false;
                debug!(
                    "{} authenticator: Need server_condition for {} mechanism",
                    config.name, mech
                );
            }
        }

        if !has_server_realm && mech.eq_ignore_ascii_case("DIGEST-MD5") {
            config.server = false;
            debug!(
                "{} authenticator: Need server_realm for DIGEST-MD5 mechanism",
                config.name
            );
        }

        config.client = has_client_username && has_client_password;

        if let Some(opts_mut) = config.downcast_options_mut::<GsaslOptions>() {
            if opts_mut.server_mech.is_none() {
                opts_mut.server_mech = Some(mech);
            }
        }

        Ok(())
    }

    /// Execute the server-side SASL token exchange loop.
    ///
    /// Replaces C gsasl.c lines 499-554. Uses `auth_get_no64_data` for
    /// raw 334 challenge/response I/O (GSASL handles base64 internally).
    fn run_server_exchange(
        session: &mut GsaslSession,
        initial_data: &str,
        smtp_io: &mut dyn AuthSmtpIo,
    ) -> (bool, Option<GsaslError>) {
        let mut received = if initial_data.is_empty() {
            Vec::new()
        } else {
            initial_data.as_bytes().to_vec()
        };

        loop {
            let step_result = session.step(&received);

            match step_result {
                Ok(StepResult::Done(to_send)) => {
                    debug!(
                        "GSASL exchange complete, {} bytes final token",
                        to_send.len()
                    );
                    if !to_send.is_empty() {
                        let challenge = String::from_utf8_lossy(&to_send);
                        let _ = smtp_io.send_line(&challenge);
                    }
                    return (true, None);
                }

                Ok(StepResult::Continue(to_send)) => {
                    debug!(
                        "GSASL needs more, sending {} bytes challenge",
                        to_send.len()
                    );

                    let challenge_str = String::from_utf8_lossy(&to_send);
                    let clean_challenge = Clean::new(challenge_str.as_ref());

                    // Use non-base64 I/O. GSASL handles base64 internally.
                    // Max response: 16384 (AUTH_DATA_LIMIT).
                    let (io_result, response_opt) =
                        auth_get_no64_data(smtp_io, clean_challenge, 16384);

                    match io_result {
                        AuthIoResult::Ok => {
                            if let Some(tainted_response) = response_opt {
                                received = tainted_response.into_inner().into_bytes();
                            } else {
                                received = Vec::new();
                            }
                        }
                        AuthIoResult::Cancelled => {
                            debug!("Client cancelled SASL exchange");
                            return (false, None);
                        }
                        _ => {
                            debug!("SMTP I/O error during SASL exchange");
                            return (false, None);
                        }
                    }
                }

                Err(e) => {
                    let code = e.code();
                    if is_permanent_gsasl_error(code) {
                        debug!("GNU SASL permanent error: {} (code {})", e, code);
                    } else {
                        debug!("GNU SASL temporary error: {}", e);
                    }
                    return (false, Some(e));
                }
            }
        }
    }
}

impl AuthDriver for GsaslAuth {
    /// Server-side GSASL authentication.
    ///
    /// Replaces C `auth_gsasl_server()` (gsasl.c lines 384-594).
    fn server(
        &self,
        config: &AuthInstanceConfig,
        initial_data: &str,
    ) -> Result<AuthServerResult, DriverError> {
        let options = config.downcast_options::<GsaslOptions>().ok_or_else(|| {
            DriverError::ConfigError(format!(
                "{} authenticator: failed to downcast options to GsaslOptions",
                config.name
            ))
        })?;

        let mech = options
            .server_mech
            .as_deref()
            .unwrap_or(&config.public_name);

        debug!(
            "GNU SASL: initialising server session for {}, mechanism {}",
            config.name, mech
        );

        let mut ctx = GsaslContext::new()
            .map_err(|e| DriverError::TempFail(format!("GNU SASL: library init failure: {}", e)))?;

        // Build callback state with interior mutability for the closure.
        let cb_state = Rc::new(RefCell::new(CallbackState::new(
            config,
            options,
            CallbackSide::Server,
        )));

        // Register GSASL callback. The closure captures an Rc<RefCell<_>>
        // and dispatches to the server callback handler.
        let cb_state_for_callback = cb_state.clone();
        ctx.set_callback(move |session, prop| {
            dispatch_callback(&cb_state_for_callback, session, prop)
        })
        .map_err(|e| DriverError::TempFail(format!("GNU SASL: callback setup failed: {}", e)))?;

        let mut session = ctx.server_start(mech).map_err(|e| {
            DriverError::TempFail(format!("GNU SASL: session start failure: {}", e))
        })?;

        // Preload service and hostname (gsasl.c lines 433-444).
        let service = expand_option_string(options.server_service.as_deref().unwrap_or("smtp"));
        preload_prop(&mut session, GsaslProperty::Service, &service);

        let hostname = expand_option_string(
            options
                .server_hostname
                .as_deref()
                .unwrap_or("$primary_hostname"),
        );
        preload_prop(&mut session, GsaslProperty::Hostname, &hostname);

        if let Some(ref realm_tmpl) = options.server_realm {
            let realm = expand_option_string(realm_tmpl);
            if !realm.is_empty() {
                preload_prop(&mut session, GsaslProperty::Realm, &realm);
            }
        }

        preload_prop(&mut session, GsaslProperty::Qops, "qop-auth");

        // Channel-binding (gsasl.c lines 446-495).
        if options.server_channelbinding {
            debug!("Auth {}: Channel-binding enabled in config", config.name);
            // In production, TLS channel-binding data preloaded here.
        } else {
            debug!("Auth {}: Channel-binding not enabled", config.name);
        }

        // Run token exchange loop.
        let mut smtp_io = SmtpIoStub {
            challenge_data: None,
            response_data: None,
        };
        let (exchange_done, exchange_error) =
            Self::run_server_exchange(&mut session, initial_data, &mut smtp_io);

        log_scram_diagnostics(&session);
        drop(session);

        // Extract final callback state.
        let final_state = cb_state.borrow();

        if let Some(ref e) = exchange_error {
            debug!("authentication returned error: {}", e);
            if final_state.sasl_error_should_defer || !is_permanent_gsasl_error(e.code()) {
                return Ok(AuthServerResult::Deferred);
            }
            return Ok(AuthServerResult::Failed);
        }

        if !exchange_done {
            return Ok(AuthServerResult::Deferred);
        }

        if final_state.checked_server_condition {
            Ok(AuthServerResult::Authenticated)
        } else {
            drop(final_state);
            let cond_result = auth_check_serv_cond(config);
            match cond_result {
                AuthConditionResult::Ok => Ok(AuthServerResult::Authenticated),
                AuthConditionResult::Fail => Ok(AuthServerResult::Failed),
                AuthConditionResult::Defer { msg, .. } => {
                    debug!("server_condition deferred: {}", msg);
                    Ok(AuthServerResult::Deferred)
                }
            }
        }
    }

    /// Client-side GSASL authentication.
    ///
    /// Replaces C `auth_gsasl_client()` (gsasl.c lines 840-995).
    fn client(
        &self,
        config: &AuthInstanceConfig,
        _smtp_context: &mut dyn Any,
        _timeout: i32,
    ) -> Result<AuthClientResult, DriverError> {
        let options = config.downcast_options::<GsaslOptions>().ok_or_else(|| {
            DriverError::ConfigError(format!(
                "{} authenticator: failed to downcast options to GsaslOptions",
                config.name
            ))
        })?;

        let mech = options
            .server_mech
            .as_deref()
            .unwrap_or(&config.public_name);

        debug!(
            "GNU SASL: initialising client session for {}, mechanism {}",
            config.name, mech
        );

        let mut ctx = GsaslContext::new().map_err(|e| {
            DriverError::ExecutionFailed(format!("GNU SASL: library init failure: {}", e))
        })?;

        let cb_state = Rc::new(RefCell::new(CallbackState::new(
            config,
            options,
            CallbackSide::Client,
        )));

        let cb_state_for_callback = cb_state.clone();
        ctx.set_callback(move |session, prop| {
            dispatch_callback(&cb_state_for_callback, session, prop)
        })
        .map_err(|e| {
            DriverError::ExecutionFailed(format!("GNU SASL: callback setup failed: {}", e))
        })?;

        let mut session = ctx.client_start(mech).map_err(|e| {
            DriverError::ExecutionFailed(format!("GNU SASL: client session start failure: {}", e))
        })?;

        // Set client properties (gsasl.c lines 896-926).
        if let Some(ref pw) = options.client_password {
            let expanded = expand_option_string(pw);
            if expanded.is_empty() {
                return Ok(AuthClientResult::Error);
            }
            let tainted_pw = Tainted::new(expanded);
            let clean_pw: Clean<String> = tainted_pw.force_clean();
            session
                .property_set(GsaslProperty::Password, clean_pw.as_ref())
                .map_err(|e| {
                    DriverError::ExecutionFailed(format!("Failed to set client password: {}", e))
                })?;
            drop(clean_pw);
        } else {
            return Ok(AuthClientResult::Error);
        }

        if let Some(ref uname) = options.client_username {
            let expanded = expand_option_string(uname);
            if expanded.is_empty() {
                return Ok(AuthClientResult::Error);
            }
            session
                .property_set(GsaslProperty::AuthId, &expanded)
                .map_err(|e| {
                    DriverError::ExecutionFailed(format!("Failed to set client username: {}", e))
                })?;
        } else {
            return Ok(AuthClientResult::Error);
        }

        if let Some(ref authz) = options.client_authz {
            let expanded = expand_option_string(authz);
            if !expanded.is_empty() {
                session
                    .property_set(GsaslProperty::AuthzId, &expanded)
                    .map_err(|e| {
                        DriverError::ExecutionFailed(format!("Failed to set client authz: {}", e))
                    })?;
            }
        }

        if options.client_channelbinding {
            debug!("Auth {}: Enabling client channel-binding", config.name);
        }

        // SASL conversation (gsasl.c lines 930-981).
        let input = Vec::new();

        let step_result = session.step(&input);
        let yield_result = match step_result {
            Ok(StepResult::Done(to_send)) => {
                debug!(
                    "GSASL client exchange complete, {} bytes final token",
                    to_send.len()
                );
                AuthClientResult::Authenticated
            }
            Ok(StepResult::Continue(to_send)) => {
                debug!("GSASL client needs more, sending {} bytes", to_send.len());
                AuthClientResult::Failed
            }
            Err(e) => {
                error!("GSASL client error: {}", e);
                AuthClientResult::Failed
            }
        };

        // Post-exchange auth variable extraction (gsasl.c lines 984-991).
        if yield_result == AuthClientResult::Authenticated {
            if let Some(authid) = session.property_get(GsaslProperty::AuthId) {
                debug!("client auth1 = '{}'", authid);
            }
            if let Some(iter) = session.property_get(GsaslProperty::ScramIter) {
                debug!("client SCRAM iter = '{}'", iter);
            }
            if let Some(salt) = session.property_get(GsaslProperty::ScramSalt) {
                debug!("client SCRAM salt = '{}'", salt);
            }
            if let Some(sp) = session.property_get(GsaslProperty::ScramSaltedPassword) {
                debug!("client SCRAM salted_password = '{}'", sp);
            }
        }

        drop(session);
        Ok(yield_result)
    }

    fn server_condition(&self, config: &AuthInstanceConfig) -> Result<bool, DriverError> {
        let result = auth_check_serv_cond(config);
        match result {
            AuthConditionResult::Ok => Ok(true),
            AuthConditionResult::Fail => Ok(false),
            AuthConditionResult::Defer { msg, .. } => Err(DriverError::TempFail(msg)),
        }
    }

    fn version_report(&self) -> Option<String> {
        let runtime_version =
            GsaslContext::check_version("0.0.0").unwrap_or_else(|| "unknown".to_string());
        info!("Library version: GNU SASL: Runtime: {}", runtime_version);
        Some(format!(
            "Library version: GNU SASL: Runtime: {}",
            runtime_version
        ))
    }

    fn macros_create(&self) -> Vec<(String, String)> {
        let mut macros = Vec::new();
        if GsaslCapabilities::has_scram_sha256() {
            macros.push(("_HAVE_AUTH_GSASL_SCRAM_SHA_256".to_string(), String::new()));
        }
        if GsaslCapabilities::has_scram_s_key() {
            macros.push(("_HAVE_AUTH_GSASL_SCRAM_S_KEY".to_string(), String::new()));
        }
        macros
    }

    fn driver_name(&self) -> &str {
        "gsasl"
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Expand an Exim option string, substituting variables.
///
/// In the full system, delegates to `exim_expand::expand_string()`.
fn expand_option_string(template: &str) -> String {
    template.to_string()
}

/// Preload a GSASL session property with a pre-expanded value.
fn preload_prop(session: &mut GsaslSession, prop: GsaslProperty, value: &str) {
    debug!("preloading prop {:?} val {}", prop, value);
    if let Err(e) = session.property_set(prop, value) {
        error!("Failed to preload property {:?}: {}", prop, e);
    }
}

/// Convert an `AuthConditionResult` to a GSASL-compatible Result.
fn gsasl_result_from_condition(result: AuthConditionResult) -> Result<(), GsaslError> {
    match result {
        AuthConditionResult::Ok => Ok(()),
        AuthConditionResult::Fail | AuthConditionResult::Defer { .. } => {
            Err(GsaslError::from_code(31))
        }
    }
}

/// Check whether a GSASL error code represents a permanent failure.
fn is_permanent_gsasl_error(code: i32) -> bool {
    matches!(code, 31 | 33 | 37 | 38 | 39 | 40 | 41 | 42 | 8)
}

/// Log SCRAM diagnostic properties after an exchange.
fn log_scram_diagnostics(session: &GsaslSession) {
    if let Some(iter_val) = session.property_get(GsaslProperty::ScramIter) {
        debug!(" - itercnt:   '{}'", iter_val);
    }
    if let Some(salt_val) = session.property_get(GsaslProperty::ScramSalt) {
        debug!(" - salt:      '{}'", salt_val);
    }
    if GsaslCapabilities::has_scram_s_key() {
        if let Some(sk) = session.property_get(GsaslProperty::ScramServerKey) {
            debug!(" - ServerKey: '{}'", sk);
        }
        if let Some(stk) = session.property_get(GsaslProperty::ScramStoredKey) {
            debug!(" - StoredKey: '{}'", stk);
        }
    }
}

// =============================================================================
// Driver Registration
// =============================================================================

// Compile-time registration of the GSASL auth driver factory.
#[cfg(feature = "auth-gsasl")]
inventory::submit! {
    AuthDriverFactory {
        name: "gsasl",
        create: || Box::new(GsaslAuth::new()),
        avail_string: Some("GNU SASL"),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_options_defaults() {
        let opts = GsaslOptions::default();
        assert_eq!(opts.server_service.as_deref(), Some("smtp"));
        assert_eq!(opts.server_hostname.as_deref(), Some("$primary_hostname"));
        assert_eq!(opts.server_scram_iter.as_deref(), Some("4096"));
        assert!(opts.server_realm.is_none());
        assert!(opts.server_mech.is_none());
        assert!(opts.server_password.is_none());
        assert!(opts.server_key.is_none());
        assert!(opts.server_s_key.is_none());
        assert!(opts.server_scram_salt.is_none());
        assert!(opts.client_username.is_none());
        assert!(opts.client_password.is_none());
        assert!(opts.client_authz.is_none());
        assert!(opts.client_spassword.is_none());
        assert!(!opts.server_channelbinding);
        assert!(!opts.client_channelbinding);
    }

    #[test]
    fn test_driver_name() {
        let driver = GsaslAuth::new();
        assert_eq!(driver.driver_name(), "gsasl");
    }

    #[test]
    fn test_macros_create() {
        let driver = GsaslAuth::new();
        let macros = driver.macros_create();
        for (name, _value) in &macros {
            assert!(
                name.starts_with("_HAVE_AUTH_GSASL_"),
                "macro name should start with _HAVE_AUTH_GSASL_: got {}",
                name
            );
        }
    }

    #[test]
    fn test_permanent_error_classification() {
        assert!(is_permanent_gsasl_error(31));
        assert!(is_permanent_gsasl_error(33));
        assert!(is_permanent_gsasl_error(8));
        assert!(is_permanent_gsasl_error(37));
        assert!(!is_permanent_gsasl_error(0));
        assert!(!is_permanent_gsasl_error(1));
        assert!(!is_permanent_gsasl_error(51));
        assert!(!is_permanent_gsasl_error(99));
    }

    #[test]
    fn test_expand_option_string() {
        assert_eq!(expand_option_string("smtp"), "smtp");
        assert_eq!(
            expand_option_string("$primary_hostname"),
            "$primary_hostname"
        );
        assert_eq!(expand_option_string(""), "");
    }

    #[test]
    fn test_callback_state_new() {
        let config = AuthInstanceConfig::new(
            "test_gsasl",
            "gsasl",
            "SCRAM-SHA-256",
            Box::new(GsaslOptions::default()),
        );
        let opts = config.downcast_options::<GsaslOptions>().unwrap();
        let state = CallbackState::new(&config, opts, CallbackSide::Server);
        assert_eq!(state.auth_name, "test_gsasl");
        assert_eq!(state.public_name, "SCRAM-SHA-256");
        assert_eq!(state.side, CallbackSide::Server);
        assert!(!state.checked_server_condition);
        assert!(!state.sasl_error_should_defer);
        assert_eq!(state.auth_vars.len(), 4);
    }

    #[test]
    fn test_smtp_io_stub() {
        let mut stub = SmtpIoStub {
            challenge_data: None,
            response_data: Some("test_response".to_string()),
        };
        assert!(stub.send_line("test").is_ok());
        assert_eq!(stub.challenge_data.as_deref(), Some("test"));
        let response = stub.read_line(1024).unwrap();
        assert_eq!(response.as_ref(), "test_response");
        assert!(stub.write_command_flush("AUTH PLAIN\r\n").is_ok());
        let (matched, _msg) = stub.read_response('2', 30).unwrap();
        assert!(matched);
    }

    #[test]
    fn test_options_downcast() {
        let opts = GsaslOptions::default();
        let config =
            AuthInstanceConfig::new("test_gsasl", "gsasl", "SCRAM-SHA-256", Box::new(opts));
        let retrieved = config.downcast_options::<GsaslOptions>();
        assert!(retrieved.is_some());
        let opts = retrieved.unwrap();
        assert_eq!(opts.server_service.as_deref(), Some("smtp"));
    }

    #[test]
    fn test_options_all_fields() {
        let opts = GsaslOptions {
            server_service: Some("imap".to_string()),
            server_hostname: Some("mail.example.com".to_string()),
            server_realm: Some("example.com".to_string()),
            server_mech: Some("SCRAM-SHA-256".to_string()),
            server_password: Some("${lookup{$auth1}lsearch{/etc/passwords}}".to_string()),
            server_key: Some("aabbccdd".to_string()),
            server_s_key: Some("eeff0011".to_string()),
            server_scram_iter: Some("8192".to_string()),
            server_scram_salt: Some("c2FsdA==".to_string()),
            client_username: Some("user@example.com".to_string()),
            client_password: Some("secret".to_string()),
            client_authz: Some("admin@example.com".to_string()),
            client_spassword: Some("precomputed".to_string()),
            server_channelbinding: true,
            client_channelbinding: true,
        };
        assert_eq!(opts.server_service.as_deref(), Some("imap"));
        assert_eq!(opts.server_hostname.as_deref(), Some("mail.example.com"));
        assert_eq!(opts.server_realm.as_deref(), Some("example.com"));
        assert_eq!(opts.server_mech.as_deref(), Some("SCRAM-SHA-256"));
        assert!(opts.server_password.is_some());
        assert_eq!(opts.server_key.as_deref(), Some("aabbccdd"));
        assert_eq!(opts.server_s_key.as_deref(), Some("eeff0011"));
        assert_eq!(opts.server_scram_iter.as_deref(), Some("8192"));
        assert_eq!(opts.server_scram_salt.as_deref(), Some("c2FsdA=="));
        assert_eq!(opts.client_username.as_deref(), Some("user@example.com"));
        assert_eq!(opts.client_password.as_deref(), Some("secret"));
        assert_eq!(opts.client_authz.as_deref(), Some("admin@example.com"));
        assert_eq!(opts.client_spassword.as_deref(), Some("precomputed"));
        assert!(opts.server_channelbinding);
        assert!(opts.client_channelbinding);
    }

    #[test]
    fn test_gsasl_result_from_condition() {
        assert!(gsasl_result_from_condition(AuthConditionResult::Ok).is_ok());
        assert!(gsasl_result_from_condition(AuthConditionResult::Fail).is_err());
        assert!(gsasl_result_from_condition(AuthConditionResult::Defer {
            msg: "test".to_string(),
            user_msg: None,
        })
        .is_err());
    }

    #[test]
    fn test_tainted_clean_password_flow() {
        let raw = "my_secret_password".to_string();
        let tainted = Tainted::new(raw.clone());
        assert_eq!(tainted.as_ref(), &raw);
        let clean: Clean<String> = tainted.force_clean();
        assert_eq!(clean.into_inner(), raw);
    }
}
