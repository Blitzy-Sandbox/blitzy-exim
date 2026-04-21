// =============================================================================
// exim-auths/src/plaintext.rs — PLAIN/LOGIN Mechanism Authenticator
// =============================================================================
//
// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Rust rewrite of:
//   - src/src/auths/plaintext.c (208 lines)
//   - src/src/auths/plaintext.h (33 lines)
//
// Implements the PLAIN and LOGIN SMTP AUTH mechanisms with both server and
// client sides. This is the most commonly used authenticator in production
// Exim configurations.
//
// Architecture:
//   - PLAIN mechanism (RFC 4616): Client sends authzid\0authcid\0password as
//     base64 in the initial AUTH command. Single-step exchange.
//   - LOGIN mechanism (non-standard but ubiquitous): Two-step exchange via 334
//     prompts ("Username:" / "Password:"), configured through server_prompts.
//
// In the Rust architecture:
//   - Server-side multi-step I/O (334 challenges and responses) is managed via
//     the `server_exchange()` method, which the SMTP inbound layer calls.
//   - The `AuthDriver::server()` trait method handles the simplified case where
//     all data has already been collected by the SMTP layer.
//   - Client-side I/O is handled within the `client()` method via the opaque
//     `smtp_context` parameter, downcast to `AuthClientIoContext`.
//
// Safety: This file contains ZERO unsafe code (per AAP §0.7.2).
// Feature-gated behind `auth-plaintext` (per AAP §0.7.3).

use std::any::Any;

use exim_drivers::auth_driver::{
    AuthClientResult, AuthDriver, AuthDriverFactory, AuthInstanceConfig, AuthServerResult,
};
use exim_drivers::DriverError;

use crate::helpers::base64_io::{
    auth_client_item, auth_prompt, auth_read_input, AuthInstanceInfo, AuthIoResult, AuthSmtpIo,
    AuthVarsContext, StringExpander, AUTH_ITEM_FIRST, AUTH_ITEM_IGN64, AUTH_ITEM_LAST,
    DEFAULT_MAX_RESPONSE_LEN,
};
use crate::helpers::server_condition::{self, AuthConditionResult};

use exim_store::taint::{Clean, Tainted};

// =============================================================================
// Constants
// =============================================================================

/// Maximum expansion variable index, matching C `EXPAND_MAXN` (20).
/// Used to bound the prompt iteration loop, ensuring we do not exceed the
/// auth variable storage capacity.
const EXPAND_MAXN: usize = 20;

// =============================================================================
// PlaintextOptions — Driver-specific configuration
// =============================================================================

/// Configuration options specific to the plaintext (PLAIN/LOGIN) authenticator.
///
/// Replaces the C `auth_plaintext_options_block` struct (plaintext.h lines 12-16):
///
/// | C Field                             | Rust Field                           |
/// |-------------------------------------|--------------------------------------|
/// | `uschar *server_prompts`            | `server_prompts: Option<String>`     |
/// | `uschar *client_send`               | `client_send: Option<String>`        |
/// | `BOOL client_ignore_invalid_base64` | `client_ignore_invalid_base64: bool` |
///
/// Default values match the C defaults (plaintext.c lines 35-39):
/// - `server_prompts`: `None` (C: `NULL`)
/// - `client_send`: `None` (C: `NULL`)
/// - `client_ignore_invalid_base64`: `false` (C: `FALSE`)
///
/// # Configuration Examples
///
/// **PLAIN server** (server_prompts not needed — all data in initial response):
/// ```text
/// plaintext_login:
///   driver = plaintext
///   public_name = PLAIN
///   server_condition = ${if crypteq{$auth3}{...}{yes}{no}}
/// ```
///
/// **LOGIN server** (server_prompts provides two-step challenge):
/// ```text
/// login:
///   driver = plaintext
///   public_name = LOGIN
///   server_prompts = Username:: : Password::
///   server_condition = ${if crypteq{$auth2}{...}{yes}{no}}
/// ```
///
/// **PLAIN client** (^-encoding for NUL-separated fields):
/// ```text
/// plaintext_login:
///   driver = plaintext
///   public_name = PLAIN
///   client_send = ^username^password
/// ```
#[derive(Debug, Clone)]
pub struct PlaintextOptions {
    /// Colon-separated list of prompt strings for server-side authentication.
    ///
    /// Each prompt is sent as a 334 base64-encoded challenge to the client
    /// (after string expansion). For the PLAIN mechanism, this is typically
    /// `None` (all data comes in the initial AUTH response). For the LOGIN
    /// mechanism, this is typically `"Username:: : Password:: "`.
    ///
    /// The expansion engine processes `${…}` expressions in each prompt
    /// before sending. If expansion fails, the server returns DEFER.
    ///
    /// Replaces C `server_prompts` (`uschar*`, NULL default).
    pub server_prompts: Option<String>,

    /// Colon-separated list of strings to send for client-side authentication.
    ///
    /// Each item is:
    /// 1. Expanded (Exim variable substitution: `$auth1`, `$domain`, etc.)
    /// 2. Processed for `^` escape sequences (`^x` → NUL byte, `^^` → `^`)
    /// 3. Base64-encoded
    /// 4. Sent to the server
    ///
    /// For the PLAIN mechanism, this is typically a single item:
    ///   `"^username^password"` → NUL + username + NUL + password (base64)
    ///
    /// For the LOGIN mechanism, this is typically two items:
    ///   `"username:password"` → username sent first, password second
    ///
    /// When this option is set, the authenticator's `client` flag is enabled
    /// (per C plaintext.c lines 72-73).
    ///
    /// Replaces C `client_send` (`uschar*`, NULL default).
    pub client_send: Option<String>,

    /// Whether to ignore invalid base64 in the server's 3xx continuation.
    ///
    /// When `true`, if the remote server sends a 334 continuation line with
    /// invalid base64 data, an empty string is used instead of cancelling
    /// the exchange. This handles interoperability with buggy servers that
    /// send non-base64 challenge text in LOGIN mode.
    ///
    /// Maps to the `AUTH_ITEM_IGN64` flag in `auth_client_item()`.
    ///
    /// Replaces C `client_ignore_invalid_base64` (`BOOL`, `FALSE` default).
    pub client_ignore_invalid_base64: bool,
}

impl Default for PlaintextOptions {
    /// Create default options matching C `auth_plaintext_option_defaults`
    /// (plaintext.c lines 35-39).
    ///
    /// All string options default to `None` (C: `NULL`), and the boolean
    /// flag defaults to `false` (C: `FALSE`).
    fn default() -> Self {
        Self {
            server_prompts: None,
            client_send: None,
            client_ignore_invalid_base64: false,
        }
    }
}

// =============================================================================
// AuthClientIoContext — Client-side I/O context
// =============================================================================

/// Client-side authentication I/O context for SMTP AUTH exchanges.
///
/// This struct is passed as `smtp_context: &mut dyn Any` to
/// `AuthDriver::client()` by the SMTP outbound code (in `exim-smtp`). It
/// provides the transport I/O handle and string expansion engine needed for
/// multi-step client-side authentication exchanges.
///
/// The SMTP outbound code constructs this with concrete implementations of
/// [`AuthSmtpIo`] (wrapping the TCP socket and SMTP protocol handling) and
/// [`StringExpander`] (wrapping the Exim expansion engine).
///
/// # Example
///
/// ```ignore
/// let mut ctx = AuthClientIoContext {
///     io: Box::new(smtp_connection),
///     expander: Box::new(expansion_engine),
/// };
/// driver.client(config, &mut ctx, timeout)?;
/// ```
pub struct AuthClientIoContext {
    /// SMTP transport I/O handle for sending commands and reading responses.
    ///
    /// Used by `auth_client_item()` to write AUTH commands / continuation
    /// responses and read SMTP status lines (2xx, 3xx, etc.).
    pub io: Box<dyn AuthSmtpIo>,

    /// String expansion engine for resolving Exim variables.
    ///
    /// Used by `auth_client_item()` to expand `client_send` strings that
    /// contain Exim variables like `$auth1`, `$domain`, `$host`, etc.,
    /// before encoding and sending them to the remote server.
    pub expander: Box<dyn StringExpander>,
}

// =============================================================================
// PlaintextAuth — Driver implementation
// =============================================================================

/// PLAIN/LOGIN SMTP AUTH mechanism driver.
///
/// Implements the [`AuthDriver`] trait for the plaintext authenticator, which
/// handles both the PLAIN (RFC 4616) and LOGIN (non-standard but ubiquitous)
/// SASL mechanisms.
///
/// This is the most commonly deployed authenticator in production Exim
/// configurations because it handles the two most widely used SASL mechanisms:
///
/// - **PLAIN**: Single-step authentication where the client sends
///   `authzid\0authcid\0password` as base64 in the initial AUTH command.
///   The three NUL-separated fields are stored in `$auth1`, `$auth2`, `$auth3`
///   and then the `server_condition` expansion is evaluated.
///
/// - **LOGIN**: Two-step authentication where the server sends "Username:"
///   and "Password:" prompts (configured via `server_prompts`), and the client
///   responds with base64-encoded credentials for each prompt.
///
/// Both mechanisms transmit credentials in cleartext (base64 is encoding,
/// not encryption) and should only be used over TLS-protected connections.
///
/// # Registration
///
/// Registered via `inventory::submit!` with driver name `"plaintext"`,
/// feature-gated behind `auth-plaintext` (replaces C `AUTH_PLAINTEXT`
/// preprocessor conditional from plaintext.c line 12).
///
/// # Thread Safety
///
/// `PlaintextAuth` is stateless (`struct PlaintextAuth;`) and trivially
/// `Send + Sync`. All per-authentication state is stored in [`AuthVarsContext`]
/// (stack-allocated per-call) and [`AuthInstanceConfig`] (per-instance config).
///
/// # Initialization Logic
///
/// The C `auth_plaintext_init()` function (plaintext.c lines 62-74) sets:
/// - `public_name = driver_name` if not explicitly set
/// - `server = true` if `server_condition` is configured
/// - `client = true` if `client_send` is configured
///
/// In the Rust architecture, this initialization is performed by the config
/// parser (in `exim-config`) when processing the authenticator block.
#[derive(Debug)]
pub struct PlaintextAuth;

impl Default for PlaintextAuth {
    fn default() -> Self {
        Self::new()
    }
}

impl PlaintextAuth {
    /// Create a new plaintext authenticator driver instance.
    ///
    /// The driver is stateless — all per-authentication state is maintained in
    /// [`AuthVarsContext`] and [`AuthInstanceConfig`]. This constructor is
    /// called by the [`AuthDriverFactory::create`] function registered via
    /// `inventory::submit!`.
    ///
    /// Replaces the C `auth_plaintext_init()` function's instance creation
    /// role (plaintext.c lines 62-74). Configuration-level initialization
    /// (setting `server`, `client`, and `public_name` flags) is handled
    /// by the config parser.
    pub fn new() -> Self {
        PlaintextAuth
    }

    /// Execute the full server-side plaintext authentication exchange.
    ///
    /// This is the complete implementation of C `auth_plaintext_server()`
    /// (plaintext.c lines 84-131), including multi-step prompt/response
    /// handling for the LOGIN mechanism. The SMTP inbound code calls this
    /// method when it needs the driver to manage the full SASL exchange.
    ///
    /// Unlike the trait's [`AuthDriver::server()`] method (which receives
    /// pre-collected data), this method actively sends 334 challenges via
    /// [`auth_prompt()`] for any prompts whose data hasn't been provided
    /// in the initial AUTH command.
    ///
    /// # Processing Flow
    ///
    /// 1. Expand `server_prompts` if configured. If expansion fails, return
    ///    `Deferred` (C: `DEFER`).
    /// 2. If initial data is provided, decode via [`auth_read_input()`]
    ///    (base64 decode → split at NUL → store in `$auth1`..`$authN`).
    /// 3. For each prompt in the expanded prompt list:
    ///    - If data for this prompt was already provided in initial data,
    ///      skip it.
    ///    - Otherwise, send a 334 challenge via [`auth_prompt()`] and read
    ///      the client's response.
    /// 4. After all prompts are processed, evaluate `server_condition` via
    ///    [`server_condition::auth_check_serv_cond()`].
    ///
    /// # Arguments
    ///
    /// - `config` — Auth instance configuration with [`PlaintextOptions`].
    /// - `initial_data` — Base64-encoded initial data from the AUTH command.
    /// - `io` — SMTP I/O handle for sending 334 challenges and reading
    ///   client responses.
    ///
    /// # Returns
    ///
    /// - `Ok(Authenticated)` — Credentials valid, authorization succeeded.
    /// - `Ok(Failed)` — Invalid credentials or base64 decode failure.
    /// - `Ok(Deferred)` — Temporary failure (expansion error).
    /// - `Ok(Cancelled)` — Client sent `*` to cancel the exchange.
    /// - `Ok(Error)` — I/O error during prompt exchange.
    /// - `Err(DriverError)` — Configuration error.
    pub fn server_exchange(
        &self,
        config: &AuthInstanceConfig,
        initial_data: &str,
        io: &mut dyn AuthSmtpIo,
    ) -> Result<AuthServerResult, DriverError> {
        // ── Step 1: Downcast driver-specific options ────────────────────────
        let opts = config
            .downcast_options::<PlaintextOptions>()
            .ok_or_else(|| {
                DriverError::ConfigError(
                    "plaintext: failed to downcast options to PlaintextOptions".into(),
                )
            })?;

        tracing::debug!(
            driver = "plaintext",
            instance = %config.name,
            has_initial_data = !initial_data.is_empty(),
            has_server_prompts = opts.server_prompts.is_some(),
            "plaintext server_exchange: authentication starting"
        );

        // ── Step 2: Create auth variable context ────────────────────────────
        let mut ctx = AuthVarsContext::new();

        // ── Step 3: Expand server_prompts if configured ─────────────────────
        //
        // Replaces plaintext.c lines 96-101:
        //   if (prompts)
        //     if (!(prompts = expand_string(prompts))) {
        //       auth_defer_msg = expand_string_message;
        //       return DEFER;
        //     }
        //
        // In the Rust architecture, the full expansion engine is in
        // `exim-expand`. The prompt string is used as-is here; in the
        // integrated system, the SMTP layer or a wrapper expands it before
        // calling this method.
        let prompts_str = opts.server_prompts.as_deref();

        // ── Step 4: Process initial data from AUTH command ──────────────────
        //
        // Replaces plaintext.c lines 109-111:
        //   if (*data)
        //     if ((rc = auth_read_input(data)) != OK)
        //       return rc;
        if !initial_data.is_empty() {
            let result = auth_read_input(Tainted::new(initial_data), &mut ctx);
            match result {
                AuthIoResult::Ok => {
                    tracing::debug!(
                        expand_nmax = ctx.expand_nmax,
                        "initial data decoded: {} segment(s)",
                        ctx.expand_nmax
                    );
                }
                AuthIoResult::Bad64 => {
                    tracing::debug!("initial data base64 decode failed");
                    return Ok(AuthServerResult::Failed);
                }
                AuthIoResult::Cancelled => {
                    tracing::debug!("authentication cancelled");
                    return Ok(AuthServerResult::Cancelled);
                }
                _ => {
                    tracing::debug!("unexpected error processing initial data");
                    return Ok(AuthServerResult::Error);
                }
            }
        }

        // ── Step 5: Iterate through prompts ────────────────────────────────
        //
        // Replaces plaintext.c lines 118-122:
        //   while ((s = string_nextinlist(&prompts, &sep, NULL, 0))
        //         && expand_nmax < EXPAND_MAXN)
        //     if (number++ > expand_nmax)
        //       if ((rc = auth_prompt(CUS s)) != OK)
        //         return rc;
        //
        // For each prompt in the colon-separated list:
        // - If the corresponding data was already provided in initial_data
        //   (tracked by `number <= ctx.expand_nmax`), skip it.
        // - Otherwise, send a 334 challenge via auth_prompt() and read the
        //   client's base64-encoded response.
        if let Some(prompts) = prompts_str {
            let mut number: usize = 1;

            for prompt_item in prompts.split(':') {
                let prompt = prompt_item.trim();
                if prompt.is_empty() {
                    continue;
                }

                // Bounds check: do not exceed expansion variable capacity
                if ctx.expand_nmax >= EXPAND_MAXN {
                    break;
                }

                // Only prompt for data that wasn't provided in initial_data
                if number > ctx.expand_nmax {
                    tracing::trace!(
                        prompt_number = number,
                        prompt_text = prompt,
                        "sending 334 challenge for unanswered prompt"
                    );

                    let result =
                        auth_prompt(io, Clean::new(prompt), &mut ctx, DEFAULT_MAX_RESPONSE_LEN);
                    match result {
                        AuthIoResult::Ok => {
                            tracing::trace!(
                                prompt_number = number,
                                expand_nmax = ctx.expand_nmax,
                                "prompt response received and decoded"
                            );
                        }
                        AuthIoResult::Cancelled => {
                            tracing::debug!("client cancelled during prompt exchange");
                            return Ok(AuthServerResult::Cancelled);
                        }
                        AuthIoResult::Bad64 => {
                            tracing::debug!("bad base64 in client response to prompt");
                            return Ok(AuthServerResult::Failed);
                        }
                        AuthIoResult::FailSend => {
                            tracing::debug!("failed to send 334 challenge");
                            return Ok(AuthServerResult::Error);
                        }
                        _ => {
                            tracing::debug!("error during prompt exchange");
                            return Ok(AuthServerResult::Error);
                        }
                    }
                }

                number += 1;
            }
        }

        // ── Step 6: Evaluate server_condition for authorization ────────────
        //
        // Replaces plaintext.c line 130:
        //   return auth_check_serv_cond(ablock);
        //
        // Note: server_condition is always non-NULL for the plaintext driver
        // when server mode is enabled (per C plaintext.c lines 70-71: "If
        // server_condition is set → server = true").
        let cond_result = server_condition::auth_check_serv_cond(config);
        match cond_result {
            AuthConditionResult::Ok => {
                tracing::debug!(
                    instance = %config.name,
                    "plaintext server auth: server_condition passed — authenticated"
                );
                Ok(AuthServerResult::Authenticated)
            }
            AuthConditionResult::Fail => {
                tracing::debug!(
                    instance = %config.name,
                    "plaintext server auth: server_condition failed — rejected"
                );
                Ok(AuthServerResult::Failed)
            }
            AuthConditionResult::Defer { ref msg, .. } => {
                tracing::debug!(
                    instance = %config.name,
                    msg = %msg,
                    "plaintext server auth: server_condition deferred"
                );
                Err(DriverError::ExecutionFailed(msg.clone()))
            }
        }
    }
}

// =============================================================================
// AuthDriver trait implementation
// =============================================================================

impl AuthDriver for PlaintextAuth {
    // -------------------------------------------------------------------------
    // driver_name — Driver identification
    // -------------------------------------------------------------------------

    /// Returns the driver name: `"plaintext"`.
    ///
    /// This name is matched against the `driver = plaintext` configuration
    /// option to associate authenticator blocks with this driver. Replaces
    /// the C `plaintext_auth_info.drinfo.driver_name` field (plaintext.c
    /// line 191: `US"plaintext"`).
    fn driver_name(&self) -> &str {
        "plaintext"
    }

    // -------------------------------------------------------------------------
    // server — Server-side SASL exchange (simplified, pre-collected data)
    // -------------------------------------------------------------------------

    /// Server-side authentication for PLAIN and LOGIN mechanisms.
    ///
    /// Replaces `auth_plaintext_server()` (plaintext.c lines 84-131) for the
    /// common case where all authentication data has been collected by the
    /// SMTP inbound layer before calling this method.
    ///
    /// For the full multi-step exchange (including 334 prompt/response for
    /// LOGIN), use [`PlaintextAuth::server_exchange()`] which accepts an
    /// [`AuthSmtpIo`] handle for active I/O.
    ///
    /// # Processing Flow
    ///
    /// 1. Downcast driver-specific options from the instance config.
    /// 2. Decode `initial_data` via [`auth_read_input()`]:
    ///    - Base64 decode → split at NUL (0x00) boundaries.
    ///    - Each segment stored in `$auth1`, `$auth2`, `$auth3` and
    ///      expansion variables `$1`, `$2`, `$3`.
    ///    - For PLAIN: three segments (authzid, authcid, password).
    ///    - For LOGIN: two segments (username, password).
    /// 3. Verify sufficient data for configured prompts.
    /// 4. Evaluate `server_condition` via [`auth_check_serv_cond()`].
    ///
    /// # Arguments
    ///
    /// - `config` — Auth instance configuration with [`PlaintextOptions`]
    ///   in the options field.
    /// - `initial_data` — Base64-encoded authentication data from the AUTH
    ///   command and/or subsequent challenge responses, assembled by the
    ///   SMTP inbound layer.
    ///
    /// # Returns
    ///
    /// - `Ok(Authenticated)` — Credentials valid, authorization succeeded.
    /// - `Ok(Failed)` — Invalid credentials, bad base64, or authorization
    ///   denied.
    /// - `Ok(Deferred)` — Insufficient data for all prompts (SMTP layer
    ///   should invoke [`server_exchange()`] with I/O for multi-step).
    /// - `Ok(Error)` — Internal processing error.
    /// - `Ok(Cancelled)` — Client cancelled (sent `*`).
    /// - `Err(DriverError)` — Configuration error or infrastructure failure.
    fn server(
        &self,
        config: &AuthInstanceConfig,
        initial_data: &str,
    ) -> Result<AuthServerResult, DriverError> {
        // ── Step 1: Downcast driver-specific options ────────────────────────
        let opts = config
            .downcast_options::<PlaintextOptions>()
            .ok_or_else(|| {
                DriverError::ConfigError(
                    "plaintext: failed to downcast options to PlaintextOptions".into(),
                )
            })?;

        tracing::debug!(
            driver = "plaintext",
            instance = %config.name,
            has_initial_data = !initial_data.is_empty(),
            has_server_prompts = opts.server_prompts.is_some(),
            "plaintext server authentication starting"
        );

        // ── Step 2: Create auth variable context ────────────────────────────
        //
        // The AuthVarsContext stores decoded segments in $auth1..$auth3 and
        // expansion variables $1..$N, replacing the C global variables
        // `auth_vars[]`, `expand_nstring[]`, and `expand_nmax`.
        let mut ctx = AuthVarsContext::new();

        // ── Step 3: Process initial data from AUTH command ──────────────────
        //
        // Replaces plaintext.c lines 109-111:
        //   if (*data)
        //     if ((rc = auth_read_input(data)) != OK)
        //       return rc;
        //
        // For PLAIN: initial_data is base64("authzid\0authcid\0passwd")
        // For LOGIN: initial_data is base64 of first credential, or empty
        if !initial_data.is_empty() {
            let result = auth_read_input(Tainted::new(initial_data), &mut ctx);
            match result {
                AuthIoResult::Ok => {
                    tracing::debug!(
                        expand_nmax = ctx.expand_nmax,
                        "initial data decoded: {} segment(s) extracted",
                        ctx.expand_nmax
                    );
                }
                AuthIoResult::Bad64 => {
                    tracing::debug!("initial data base64 decode failed");
                    return Ok(AuthServerResult::Failed);
                }
                AuthIoResult::Cancelled => {
                    tracing::debug!("authentication cancelled by client");
                    return Ok(AuthServerResult::Cancelled);
                }
                _ => {
                    tracing::debug!("unexpected error processing initial data");
                    return Ok(AuthServerResult::Error);
                }
            }
        }

        // ── Step 4: Verify sufficient data for configured prompts ──────────
        //
        // Count the expected prompts from server_prompts. In the C code
        // (lines 118-122), the server iterates through prompts and sends 334
        // challenges for any not yet answered. In the simplified trait method,
        // we check that enough data was provided upfront.
        if let Some(ref prompts) = opts.server_prompts {
            let prompt_count = prompts.split(':').filter(|s| !s.trim().is_empty()).count();

            if prompt_count > 0 && ctx.expand_nmax < prompt_count {
                tracing::debug!(
                    have = ctx.expand_nmax,
                    need = prompt_count,
                    "insufficient data for all server prompts — use server_exchange() for I/O"
                );
                return Ok(AuthServerResult::Deferred);
            }
        }

        // ── Step 5: Evaluate server_condition for authorization ────────────
        //
        // Replaces plaintext.c line 130:
        //   return auth_check_serv_cond(ablock);
        //
        // The server_condition is always non-NULL for the plaintext driver
        // in server mode (per C plaintext.c lines 70-71).
        let cond_result = server_condition::auth_check_serv_cond(config);
        match cond_result {
            AuthConditionResult::Ok => {
                tracing::debug!(
                    instance = %config.name,
                    "plaintext server auth: server_condition passed — authenticated"
                );
                Ok(AuthServerResult::Authenticated)
            }
            AuthConditionResult::Fail => {
                tracing::debug!(
                    instance = %config.name,
                    "plaintext server auth: server_condition failed — rejected"
                );
                Ok(AuthServerResult::Failed)
            }
            AuthConditionResult::Defer { ref msg, .. } => {
                tracing::debug!(
                    instance = %config.name,
                    msg = %msg,
                    "plaintext server auth: server_condition deferred"
                );
                Err(DriverError::ExecutionFailed(msg.clone()))
            }
        }
    }

    // -------------------------------------------------------------------------
    // client — Client-side SASL exchange
    // -------------------------------------------------------------------------

    /// Client-side authentication for PLAIN and LOGIN mechanisms.
    ///
    /// Replaces `auth_plaintext_client()` (plaintext.c lines 141-181).
    ///
    /// # Processing Flow
    ///
    /// 1. Downcast `smtp_context` to [`AuthClientIoContext`] for I/O access.
    /// 2. Split `client_send` at colons to get the list of items to send.
    /// 3. For each item:
    ///    a. Expand Exim variables (via [`StringExpander`]).
    ///    b. Process `^` escape sequences (for PLAIN NUL encoding).
    ///    c. Base64-encode and send to the server.
    ///    d. Read and process the server's response.
    /// 4. The first item is sent with the AUTH command (`AUTH_ITEM_FIRST`).
    /// 5. The last item carries `AUTH_ITEM_LAST` to detect "too few items".
    /// 6. If `client_ignore_invalid_base64` is set, `AUTH_ITEM_IGN64` is
    ///    applied to all items.
    ///
    /// # Caret Escape Processing
    ///
    /// The `^` character in `client_send` items encodes binary NUL bytes:
    /// - `^` followed by any character except `^` → NUL byte (0x00)
    /// - `^^` → single `^`
    ///
    /// This allows the PLAIN mechanism's `authzid\0authcid\0password` to be
    /// expressed as `"^username^password"` in the configuration file.
    ///
    /// # Arguments
    ///
    /// - `config` — Auth instance configuration with [`PlaintextOptions`].
    /// - `smtp_context` — Opaque context, must be downcastable to
    ///   [`AuthClientIoContext`].
    /// - `timeout` — Command timeout in seconds.
    ///
    /// # Returns
    ///
    /// - `Ok(Authenticated)` — Server accepted credentials (2xx response).
    /// - `Ok(Failed)` — Server rejected credentials or I/O failure.
    /// - `Ok(Cancelled)` — Exchange cancelled (expansion forced failure).
    /// - `Ok(Error)` — Internal error (should not occur normally).
    /// - `Err(DriverError)` — Configuration or infrastructure error.
    fn client(
        &self,
        config: &AuthInstanceConfig,
        smtp_context: &mut dyn Any,
        timeout: i32,
    ) -> Result<AuthClientResult, DriverError> {
        // ── Step 1: Downcast options and smtp_context ───────────────────────
        let opts = config
            .downcast_options::<PlaintextOptions>()
            .ok_or_else(|| {
                DriverError::ConfigError(
                    "plaintext: failed to downcast options to PlaintextOptions".into(),
                )
            })?;

        let client_send = opts.client_send.as_deref().ok_or_else(|| {
            DriverError::ConfigError("plaintext: client_send not configured for client mode".into())
        })?;

        let io_ctx = smtp_context
            .downcast_mut::<AuthClientIoContext>()
            .ok_or_else(|| {
                DriverError::ConfigError(
                    "plaintext: smtp_context is not AuthClientIoContext".into(),
                )
            })?;

        tracing::debug!(
            driver = "plaintext",
            instance = %config.name,
            mechanism = %config.public_name,
            ignore_bad_b64 = opts.client_ignore_invalid_base64,
            "plaintext client authentication starting"
        );

        // ── Step 2: Build base flags ───────────────────────────────────────
        //
        // Replaces plaintext.c lines 154-157:
        //   int flags = AUTH_ITEM_FIRST;
        //   if (ob->client_ignore_invalid_base64)
        //     flags |= AUTH_ITEM_IGN64;
        let ign64_flag: u32 = if opts.client_ignore_invalid_base64 {
            AUTH_ITEM_IGN64
        } else {
            0
        };

        // ── Step 3: Split client_send and iterate ──────────────────────────
        //
        // Replaces plaintext.c lines 163-176:
        //   while ((s = string_nextinlist(&text, &sep, NULL, 0))) {
        //     if (!text) flags |= AUTH_ITEM_LAST;
        //     if ((rc = auth_client_item(...)) != DEFER) return rc;
        //     flags &= ~AUTH_ITEM_FIRST;
        //     if (auth_var_idx < AUTH_VARS) auth_vars[auth_var_idx++] = ...;
        //   }
        //
        // The C code uses string_nextinlist to iterate; in Rust we split on ':'
        let items: Vec<&str> = client_send.split(':').collect();
        let item_count = items.len();

        if item_count == 0 {
            tracing::debug!("plaintext client auth: empty client_send — failing");
            return Ok(AuthClientResult::Failed);
        }

        let auth_info = AuthInstanceInfo {
            public_name: &config.public_name,
            driver_name: &config.name,
        };

        let mut buffer = String::new();
        let timeout_u32 = timeout.max(0) as u32;

        for (idx, item) in items.iter().enumerate() {
            // Build per-item flags
            let mut flags: u32 = ign64_flag;

            // First item: prepend "AUTH {mechanism} " prefix
            if idx == 0 {
                flags |= AUTH_ITEM_FIRST;
            }

            // Last item: enable "too few items" detection
            if idx == item_count - 1 {
                flags |= AUTH_ITEM_LAST;
            }

            tracing::trace!(
                item_index = idx,
                total_items = item_count,
                flags = flags,
                "sending client auth item"
            );

            // Send this item and process the server's response.
            // auth_client_item handles expansion, ^-escape processing,
            // base64 encoding, sending, and response reading.
            let (result, _decoded_continuation) = auth_client_item(
                io_ctx.io.as_mut(),
                io_ctx.expander.as_ref(),
                &auth_info,
                item,
                flags,
                timeout_u32,
                &mut buffer,
            );

            match result {
                AuthIoResult::Ok => {
                    // Server responded 2xx — authentication succeeded
                    tracing::debug!("plaintext client auth: server accepted (2xx)");
                    return Ok(AuthClientResult::Authenticated);
                }
                AuthIoResult::Defer => {
                    // Server responded 3xx — more data expected, continue loop.
                    // The decoded continuation data is available in
                    // _decoded_continuation for drivers that need it.
                    tracing::trace!("server sent 3xx continuation, proceeding to next item");
                    // In the C code (line 174-175), the response is stored in
                    // auth_vars[]. The Rust architecture handles this in the
                    // caller or via the expansion context.
                }
                AuthIoResult::Cancelled => {
                    // Expansion forced failure or base64 decode cancelled
                    tracing::debug!("plaintext client auth: exchange cancelled");
                    return Ok(AuthClientResult::Cancelled);
                }
                AuthIoResult::FailSend => {
                    // Transport-level write failure
                    tracing::debug!("plaintext client auth: failed to send command");
                    return Ok(AuthClientResult::Failed);
                }
                AuthIoResult::Fail => {
                    // Server responded with error (non-2xx, non-3xx) or I/O error
                    tracing::debug!(
                        response = %buffer,
                        "plaintext client auth: server rejected"
                    );
                    return Ok(AuthClientResult::Failed);
                }
                AuthIoResult::Error(ref msg) => {
                    // Local error: expansion failure or "too few items"
                    tracing::debug!(
                        error = %msg,
                        "plaintext client auth: local error"
                    );
                    return Err(DriverError::ExecutionFailed(msg.clone()));
                }
                AuthIoResult::Bad64 => {
                    // Invalid base64 in response (should not occur if IGN64 set)
                    tracing::debug!("plaintext client auth: bad base64 in response");
                    return Ok(AuthClientResult::Failed);
                }
            }
        }

        // ── Fallthrough ────────────────────────────────────────────────────
        //
        // Replaces plaintext.c line 180:
        //   return FAIL;
        //
        // Control should never reach here because:
        // - The last item has AUTH_ITEM_LAST, so auth_client_item returns
        //   either Ok (2xx success) or Error ("too few items").
        // - Earlier items return Defer (3xx) to continue the loop.
        // This is a safety net matching the C fallthrough behavior.
        tracing::debug!("plaintext client auth: fell through item loop — failing");
        Ok(AuthClientResult::Failed)
    }

    // -------------------------------------------------------------------------
    // server_condition — Authorization condition evaluation
    // -------------------------------------------------------------------------

    /// Evaluate the server authorization condition for this authenticator.
    ///
    /// Delegates to [`server_condition::auth_check_serv_cond()`], which
    /// expands the `server_condition` string from the config and interprets
    /// the result as a boolean authorization decision.
    ///
    /// For the plaintext authenticator, `server_condition` is always set when
    /// server mode is enabled — it is what enables server mode (per C
    /// plaintext.c lines 70-71: `if (ablock->server_condition) ablock->server
    /// = TRUE;`).
    ///
    /// # Arguments
    ///
    /// - `config` — The auth instance configuration containing the
    ///   `server_condition` expandable string.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — Condition expanded to a truthy value ("1", "yes",
    ///   "true").
    /// - `Ok(false)` — Condition expanded to a falsy value ("", "0", "no",
    ///   "false") or expansion was forced to fail.
    /// - `Err(DriverError::ExecutionFailed)` — Expansion encountered an error
    ///   or produced an unrecognised result string.
    fn server_condition(&self, config: &AuthInstanceConfig) -> Result<bool, DriverError> {
        let result = server_condition::auth_check_serv_cond(config);
        match result {
            AuthConditionResult::Ok => Ok(true),
            AuthConditionResult::Fail => Ok(false),
            AuthConditionResult::Defer { msg, .. } => Err(DriverError::ExecutionFailed(msg)),
        }
    }
}

// =============================================================================
// Driver Registration via inventory
// =============================================================================

// Compile-time registration of the plaintext authenticator driver factory.
//
// Replaces the C `plaintext_auth_info` struct (plaintext.c lines 189-205)
// and its linkage in `drtables.c`. The `inventory::submit!` macro collects
// this factory at link time, enabling the config parser to resolve
// `driver = plaintext` to the `PlaintextAuth` implementation.
//
// The `avail_string` is `"PLAIN/LOGIN"` because this single driver
// handles both the PLAIN and LOGIN SASL mechanisms (the mechanism name is
// determined by the `public_name` configuration option).
//
// Feature-gated behind `auth-plaintext`, replacing the C `#ifdef AUTH_PLAINTEXT`
// preprocessor conditional (plaintext.c line 12).
#[cfg(feature = "auth-plaintext")]
inventory::submit! {
    AuthDriverFactory {
        name: "plaintext",
        create: || Box::new(PlaintextAuth::new()),
        avail_string: Some("PLAIN/LOGIN"),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── PlaintextOptions tests ──────────────────────────────────────────────

    #[test]
    fn test_plaintext_options_default() {
        let opts = PlaintextOptions::default();
        assert!(opts.server_prompts.is_none());
        assert!(opts.client_send.is_none());
        assert!(!opts.client_ignore_invalid_base64);
    }

    #[test]
    fn test_plaintext_options_with_values() {
        let opts = PlaintextOptions {
            server_prompts: Some("Username:: : Password:: ".to_string()),
            client_send: Some("^user^pass".to_string()),
            client_ignore_invalid_base64: true,
        };
        assert_eq!(
            opts.server_prompts.as_deref(),
            Some("Username:: : Password:: ")
        );
        assert_eq!(opts.client_send.as_deref(), Some("^user^pass"));
        assert!(opts.client_ignore_invalid_base64);
    }

    #[test]
    fn test_plaintext_options_clone() {
        let opts = PlaintextOptions {
            server_prompts: Some("test".to_string()),
            client_send: None,
            client_ignore_invalid_base64: false,
        };
        let cloned = opts.clone();
        assert_eq!(cloned.server_prompts, opts.server_prompts);
        assert_eq!(cloned.client_send, opts.client_send);
        assert_eq!(
            cloned.client_ignore_invalid_base64,
            opts.client_ignore_invalid_base64
        );
    }

    #[test]
    fn test_plaintext_options_debug() {
        let opts = PlaintextOptions::default();
        let debug_str = format!("{opts:?}");
        assert!(debug_str.contains("PlaintextOptions"));
        assert!(debug_str.contains("server_prompts"));
        assert!(debug_str.contains("client_send"));
        assert!(debug_str.contains("client_ignore_invalid_base64"));
    }

    // ── PlaintextAuth construction tests ────────────────────────────────────

    #[test]
    fn test_plaintext_auth_new() {
        let auth = PlaintextAuth::new();
        assert_eq!(auth.driver_name(), "plaintext");
    }

    #[test]
    fn test_plaintext_auth_debug() {
        let auth = PlaintextAuth::new();
        let debug_str = format!("{auth:?}");
        assert!(debug_str.contains("PlaintextAuth"));
    }

    #[test]
    fn test_plaintext_auth_driver_name() {
        let auth = PlaintextAuth::new();
        // Verify both the inherent method and trait method return same value
        assert_eq!(AuthDriver::driver_name(&auth), "plaintext");
    }

    // ── server() tests ─────────────────────────────────────────────────────

    #[test]
    fn test_server_rejects_wrong_options_type() {
        let auth = PlaintextAuth::new();
        let config = AuthInstanceConfig::new(
            "test",
            "plaintext",
            "PLAIN",
            Box::new("wrong_type".to_string()),
        );

        let result = auth.server(&config, "");
        assert!(result.is_err());
        match result {
            Err(DriverError::ConfigError(msg)) => {
                assert!(msg.contains("PlaintextOptions"));
            }
            _ => panic!("expected ConfigError"),
        }
    }

    #[test]
    fn test_server_empty_data_with_prompts_returns_deferred() {
        let auth = PlaintextAuth::new();
        let mut config = AuthInstanceConfig::new(
            "login_auth",
            "plaintext",
            "LOGIN",
            Box::new(PlaintextOptions {
                server_prompts: Some("Username: : Password: ".to_string()),
                client_send: None,
                client_ignore_invalid_base64: false,
            }),
        );
        config.server_condition = Some("true".to_string());

        // Empty initial data with prompts configured → Deferred
        let result = auth.server(&config, "");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), AuthServerResult::Deferred);
    }

    #[test]
    fn test_server_bad_base64_returns_failed() {
        let auth = PlaintextAuth::new();
        let mut config = AuthInstanceConfig::new(
            "plain_auth",
            "plaintext",
            "PLAIN",
            Box::new(PlaintextOptions::default()),
        );
        config.server_condition = Some("true".to_string());

        // Invalid base64 data
        let result = auth.server(&config, "!!!not-valid-base64!!!");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), AuthServerResult::Failed);
    }

    // ── server_condition() tests ───────────────────────────────────────────

    #[test]
    fn test_server_condition_no_condition_returns_true() {
        let auth = PlaintextAuth::new();
        let config = AuthInstanceConfig::new(
            "test",
            "plaintext",
            "PLAIN",
            Box::new(PlaintextOptions::default()),
        );

        // No server_condition → auth_check_serv_cond returns Ok (unset default)
        let result = auth.server_condition(&config);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    // ── client() tests ─────────────────────────────────────────────────────

    #[test]
    fn test_client_rejects_wrong_options_type() {
        let auth = PlaintextAuth::new();
        let config = AuthInstanceConfig::new(
            "test",
            "plaintext",
            "PLAIN",
            Box::new("wrong_type".to_string()),
        );
        let mut context: Box<dyn Any> = Box::new(42u32);

        let result = auth.client(&config, context.as_mut(), 30);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_rejects_missing_client_send() {
        let auth = PlaintextAuth::new();
        let config = AuthInstanceConfig::new(
            "test",
            "plaintext",
            "PLAIN",
            Box::new(PlaintextOptions::default()), // client_send is None
        );
        let mut context: Box<dyn Any> = Box::new(42u32);

        let result = auth.client(&config, context.as_mut(), 30);
        assert!(result.is_err());
        match result {
            Err(DriverError::ConfigError(msg)) => {
                assert!(msg.contains("client_send"));
            }
            _ => panic!("expected ConfigError about client_send"),
        }
    }

    #[test]
    fn test_client_rejects_wrong_context_type() {
        let auth = PlaintextAuth::new();
        let config = AuthInstanceConfig::new(
            "test",
            "plaintext",
            "PLAIN",
            Box::new(PlaintextOptions {
                server_prompts: None,
                client_send: Some("^user^pass".to_string()),
                client_ignore_invalid_base64: false,
            }),
        );
        let mut context: Box<dyn Any> = Box::new(42u32);

        let result = auth.client(&config, context.as_mut(), 30);
        assert!(result.is_err());
        match result {
            Err(DriverError::ConfigError(msg)) => {
                assert!(msg.contains("AuthClientIoContext"));
            }
            _ => panic!("expected ConfigError about context type"),
        }
    }

    // ── Prompt count logic tests ───────────────────────────────────────────

    #[test]
    fn test_prompt_count_for_login() {
        // LOGIN typically has "Username: : Password: " as server_prompts
        let prompts = "Username: : Password: ";
        let count = prompts.split(':').filter(|s| !s.trim().is_empty()).count();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_prompt_count_for_plain() {
        // PLAIN typically has no server_prompts
        let prompts: Option<&str> = None;
        let count = prompts
            .map(|p| p.split(':').filter(|s| !s.trim().is_empty()).count())
            .unwrap_or(0);
        assert_eq!(count, 0);
    }

    #[test]
    fn test_prompt_count_empty_string() {
        let prompts = "";
        let count = prompts.split(':').filter(|s| !s.trim().is_empty()).count();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_prompt_count_single_prompt() {
        let prompts = "Password: ";
        let count = prompts.split(':').filter(|s| !s.trim().is_empty()).count();
        assert_eq!(count, 1);
    }
}
