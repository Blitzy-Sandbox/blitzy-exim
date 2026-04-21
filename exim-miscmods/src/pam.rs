//! PAM (Pluggable Authentication Modules) authentication module for Exim MTA.
//!
//! This module provides PAM authentication support, calling `libpam` via the
//! `exim-ffi` crate's safe wrappers.  It replaces the C `src/src/miscmods/pam.c`
//! (224 lines) with safe Rust code containing **zero `unsafe` blocks**.
//!
//! # Architecture
//!
//! The original C implementation used static global variables for PAM
//! conversation state (`pam_conv_had_error`, `pam_args`, `pam_arg_ended` —
//! `pam.c` lines 40–42).  The Rust implementation eliminates all global mutable
//! state by:
//!
//! - Passing conversation data through [`exim_ffi::pam::PamConversationData`]
//!   structs owned by the FFI layer's [`exim_ffi::pam::PamHandle`] RAII wrapper
//! - Using [`PamAuthenticator`] instances with scoped lifetime instead of statics
//! - Wrapping user-supplied credentials in [`exim_store::Tainted<T>`] newtypes
//!   for compile-time taint tracking (AAP §0.4.3)
//!
//! # Feature Gate
//!
//! This module is compiled only when the `pam` Cargo feature is enabled
//! (gated at the `lib.rs` module declaration level via
//! `#[cfg(feature = "pam")] pub mod pam;`).  This replaces the C preprocessor
//! `#ifdef SUPPORT_PAM` conditional from `pam.c` line 24.
//!
//! # Safety
//!
//! All PAM library calls are confined to the `exim-ffi` crate per AAP §0.7.2.
//! This module contains zero `unsafe` blocks.
//!
//! # Module Registration
//!
//! The module registers itself with the `exim-drivers` registry via
//! [`inventory::submit!`] for compile-time discovery, replacing the C
//! `misc_module_info pam_module_info` struct from `pam.c` lines 211–220.

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

// Internal workspace crate: exim-drivers — driver trait definitions and
// module registration infrastructure.  DriverInfoBase provides module
// metadata for registry; DriverError provides error propagation through
// the generic driver infrastructure.
use exim_drivers::{DriverError, DriverInfoBase};

// Internal workspace crate: exim-ffi::pam — safe Rust wrappers around
// libpam.  ALL unsafe libpam calls are confined to this FFI module (per
// AAP §0.7.2).  We import the module alias and use its public types:
// PamHandle (RAII session), PamError (FFI error), PamAuthResult (3-state
// result), PamConversationData (conversation callback data),
// PAM_SILENT (flag constant), and authenticate() (convenience function).
use exim_ffi::pam as ffi_pam;

// Internal workspace crate: exim-store — memory management and taint
// tracking newtypes.  Tainted<T> wraps untrusted user-supplied credentials
// (from SMTP AUTH), Clean<T> wraps validated/trusted data (admin-configured
// PAM service name).  TaintedString and CleanString are convenience aliases.
use exim_store::{Clean, CleanString, Tainted, TaintedString};

// Internal workspace crate: exim-store::taint — additional taint types.
// TaintState for dynamic taint status representation in logging,
// TaintError for sanitization validation failures.
use exim_store::taint::{TaintError, TaintState};

// External crate: thiserror — derive macro for std::error::Error.
use thiserror::Error;

// External crate: tracing — structured logging macros replacing C
// debug_printf(D_auth, ...) and log_write() calls.
use tracing::{debug, error, warn};

// ---------------------------------------------------------------------------
// PamError — High-level PAM error type
// ---------------------------------------------------------------------------

/// Error type for PAM authentication operations.
///
/// Maps PAM failure modes into semantic Rust error variants, replacing the C
/// return-code pattern (`OK`/`FAIL`/`ERROR` integers from `pam.c` lines
/// 187–199).  Each variant carries enough context for structured logging and
/// caller error handling.
///
/// Implements [`std::error::Error`] via the [`thiserror::Error`] derive macro,
/// enabling automatic conversion into `MiscModError::Pam` via the `#[from]`
/// attribute in `lib.rs`.
#[derive(Debug, Error)]
pub enum PamError {
    /// Authentication failed due to bad credentials or unknown user.
    ///
    /// Maps to C PAM codes: `PAM_AUTH_ERR` (7), `PAM_USER_UNKNOWN` (10).
    /// Replaces C `return FAIL` at `pam.c` line 197.
    #[error("PAM authentication failed: bad credentials or unknown user")]
    AuthenticationFailed,

    /// The user account has expired or been disabled.
    ///
    /// Maps to C PAM code: `PAM_ACCT_EXPIRED` (13).
    /// Replaces C `return FAIL` at `pam.c` line 196.
    #[error("PAM account expired or disabled")]
    AccountExpired,

    /// The PAM conversation callback encountered an error.
    ///
    /// This occurs when the conversation function cannot provide valid
    /// responses to PAM prompts — for example, when credential data
    /// contains interior null bytes that would truncate C strings, or when
    /// all credentials have been exhausted and PAM requests more.
    ///
    /// Replaces the C `pam_conv_had_error` static variable check at
    /// `pam.c` line 174 and the `PAM_CONV_ERR` return at line 105.
    #[error("PAM conversation error: callback failed during authentication")]
    ConversationError,

    /// PAM service is unavailable — `pam_start` failed.
    ///
    /// This indicates a system-level configuration issue: missing PAM
    /// service file (`/etc/pam.d/exim`), `libpam` not installed, or
    /// incorrect PAM stack configuration.
    ///
    /// Replaces C `return ERROR` at `pam.c` line 199 when `pam_start`
    /// returns a non-`PAM_SUCCESS` code.
    #[error("PAM service unavailable: session could not be started")]
    ServiceUnavailable,

    /// An error from the underlying PAM FFI layer.
    ///
    /// Wraps [`exim_ffi::pam::PamError`] for unexpected PAM return codes
    /// not covered by the specific variants above.  The raw PAM error code
    /// is preserved for diagnostic purposes via [`exim_ffi::pam::PamError::code()`].
    #[error("PAM FFI error: {0}")]
    FfiError(#[from] ffi_pam::PamError),
}

impl PamError {
    /// Convert this PAM error into a [`DriverError`] for compatibility with
    /// the driver registry error propagation system.
    ///
    /// Used when PAM errors need to bubble up through the generic driver
    /// infrastructure defined in `exim-drivers`.  Maps PAM-specific error
    /// semantics to driver-level categories:
    ///
    /// - Authentication/account/conversation failures → `ExecutionFailed`
    /// - Service unavailable → `TempFail` (may succeed on retry after
    ///   PAM reconfiguration)
    /// - FFI errors → `ExecutionFailed` with raw code detail
    pub fn into_driver_error(self) -> DriverError {
        match self {
            PamError::AuthenticationFailed | PamError::AccountExpired => {
                DriverError::ExecutionFailed(self.to_string())
            }
            PamError::ConversationError => DriverError::ExecutionFailed(self.to_string()),
            PamError::ServiceUnavailable => DriverError::TempFail(self.to_string()),
            PamError::FfiError(ref ffi_err) => DriverError::ExecutionFailed(format!(
                "PAM FFI error code {}: {}",
                ffi_err.code(),
                self
            )),
        }
    }
}

/// Conversion from taint validation errors into PAM errors.
///
/// When [`Tainted::sanitize()`] rejects user-supplied credential data
/// (e.g., containing null bytes), the resulting [`TaintError`] is mapped
/// to [`PamError::ConversationError`] because the issue lies with the
/// conversation data quality.
impl From<TaintError> for PamError {
    fn from(_err: TaintError) -> Self {
        PamError::ConversationError
    }
}

// ---------------------------------------------------------------------------
// PamAuthenticator — Stateful PAM authentication context
// ---------------------------------------------------------------------------

/// PAM authenticator providing structured authentication with conversation
/// state management.
///
/// Replaces the C static global variables (`pam_conv_had_error`, `pam_args`,
/// `pam_arg_ended` from `pam.c` lines 40–42) with a scoped struct that
/// manages PAM service configuration and delegates authentication to the
/// `exim-ffi` safe wrapper layer.
///
/// The service name is wrapped in [`Clean<String>`] (via [`CleanString`])
/// because it originates from the administrator's configuration — a trusted
/// source per the taint model (AAP §0.4.3).
///
/// # Examples
///
/// ```rust,ignore
/// use exim_miscmods::pam::{PamAuthenticator, PamError};
///
/// let auth = PamAuthenticator::new();
/// match auth.authenticate("testuser", "password123") {
///     Ok(()) => println!("Authentication succeeded"),
///     Err(PamError::AuthenticationFailed) => println!("Bad credentials"),
///     Err(e) => eprintln!("PAM error: {e}"),
/// }
/// ```
#[derive(Debug)]
pub struct PamAuthenticator {
    /// PAM service name — defaults to `"exim"` matching the C implementation.
    ///
    /// Wrapped in [`CleanString`] (`Clean<String>`) because it originates
    /// from admin configuration (trusted source), not from external SMTP
    /// input.  This corresponds to the hardcoded `"exim"` string literal
    /// at C `pam.c` line 165: `pam_start("exim", ...)`.
    service_name: CleanString,
}

impl Default for PamAuthenticator {
    /// Create a `PamAuthenticator` with the default PAM service name
    /// `"exim"`.  Equivalent to [`PamAuthenticator::new()`].
    fn default() -> Self {
        Self::new()
    }
}

impl PamAuthenticator {
    /// Create a new `PamAuthenticator` with the default PAM service name
    /// `"exim"`.
    ///
    /// The service name is wrapped in [`Clean<String>`] because it comes
    /// from the administrator's configuration, which is a trusted source
    /// per the taint model (AAP §0.4.3).
    ///
    /// This replaces the hardcoded `"exim"` string literal at C `pam.c`
    /// line 165: `pam_start("exim", CS user, &pamc, &pamh)`.
    pub fn new() -> Self {
        debug!("Creating PAM authenticator with service name 'exim'");
        Self {
            service_name: Clean::new("exim".to_string()),
        }
    }

    /// Authenticate a user via PAM with the given credentials.
    ///
    /// This method:
    /// 1. Wraps input parameters in [`Tainted<T>`] newtypes for compile-time
    ///    taint safety — user credentials arrive from SMTP AUTH and are
    ///    untrusted external input
    /// 2. Sanitizes user credentials (rejects empty usernames, null bytes)
    ///    via [`Tainted::sanitize()`]
    /// 3. Parses the colon-delimited credential string into individual fields
    ///    matching the C `string_nextinlist()` parsing at `pam.c` line 71
    /// 4. Calls the `exim-ffi` PAM convenience function for authentication
    ///    and account management checks
    /// 5. Maps [`PamAuthResult`](ffi_pam::PamAuthResult) codes to
    ///    [`PamError`] variants
    ///
    /// # Arguments
    ///
    /// * `user` — The username to authenticate.  Must not be empty — PAM does
    ///   not support empty usernames (`pam.c` line 159:
    ///   `if (user == NULL || user[0] == 0) return FAIL`).
    /// * `credentials` — Colon-separated credential string.  The first field
    ///   is typically the password.  Additional fields are passed sequentially
    ///   to PAM conversation prompts when PAM issues multiple challenges.
    ///
    /// # Errors
    ///
    /// Returns [`PamError`] on authentication failure, account issues, or
    /// system errors.
    pub fn authenticate(&self, user: &str, credentials: &str) -> Result<(), PamError> {
        // ------------------------------------------------------------------
        // Step 1: Taint-wrap user-supplied input (from SMTP AUTH — untrusted)
        // ------------------------------------------------------------------
        let tainted_user: TaintedString = Tainted::new(user.to_string());
        let tainted_creds: TaintedString = Tainted::new(credentials.to_string());

        debug!(
            taint_state = %TaintState::Tainted,
            "Received PAM authentication request with tainted credentials"
        );

        // ------------------------------------------------------------------
        // Step 2: Sanitize username — reject empty or null-byte-containing
        // strings.  Empty usernames cause PAM to prompt interactively,
        // leading to potential misinterpretation (pam.c lines 155–159).
        // ------------------------------------------------------------------
        let clean_user = tainted_user
            .sanitize(|u| !u.is_empty() && !u.contains('\0'))
            .map_err(|te: TaintError| {
                error!(
                    context = %te,
                    "PAM user sanitization failed — empty or null-byte username"
                );
                PamError::AuthenticationFailed
            })?;

        // ------------------------------------------------------------------
        // Step 3: Sanitize credentials — reject null bytes that would
        // truncate C strings when passed through the FFI boundary.
        // ------------------------------------------------------------------
        let clean_creds =
            tainted_creds
                .sanitize(|c| !c.contains('\0'))
                .map_err(|te: TaintError| {
                    error!(
                        context = %te,
                        "PAM credential sanitization failed — null bytes in credentials"
                    );
                    PamError::ConversationError
                })?;

        // ------------------------------------------------------------------
        // Step 4: Parse colon-delimited credentials into individual fields.
        // Matches C behaviour at pam.c line 71: `int sep = ':';` and the
        // conversation callback at line 87: `string_nextinlist(&pam_args, &sep, ...)`.
        // ------------------------------------------------------------------
        let cred_parts: Vec<&str> = clean_creds.split(':').collect();

        debug!(
            user = user,
            credential_count = cred_parts.len(),
            "Running PAM authentication for user"
        );

        // ------------------------------------------------------------------
        // Step 5: Call exim-ffi convenience function for credential-based
        // authentication.  This internally creates a PamHandle with
        // PamConversationData containing the credential list, calls
        // pam_authenticate(PAM_SILENT), then pam_acct_mgmt(PAM_SILENT),
        // and drops the handle (calling pam_end) via RAII.
        // ------------------------------------------------------------------
        let result = ffi_pam::authenticate(&self.service_name, &clean_user, &cred_parts);

        // ------------------------------------------------------------------
        // Step 6: Map PamAuthResult to high-level PamError type.
        // ------------------------------------------------------------------
        match result {
            ffi_pam::PamAuthResult::Ok => {
                debug!(user = user, "PAM authentication succeeded");
                Ok(())
            }
            ffi_pam::PamAuthResult::Fail => {
                debug!(
                    user = user,
                    "PAM authentication failed — credentials rejected"
                );
                Err(PamError::AuthenticationFailed)
            }
            ffi_pam::PamAuthResult::Error(ffi_err) => {
                // Obtain the PAM library's native error description for
                // structured logging.
                let err_detail =
                    get_pam_error_description(&self.service_name, &clean_user, &ffi_err);
                error!(
                    user = user,
                    pam_code = ffi_err.code(),
                    pam_error = %err_detail,
                    "PAM authentication error"
                );
                Err(classify_ffi_error(ffi_err))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// pam_auth_call — Public entry point function
// ---------------------------------------------------------------------------

/// Perform PAM authentication for the given user with credentials.
///
/// This is the main entry point for PAM authentication, equivalent to the C
/// `auth_call_pam()` function exported via the `PAM_AUTH_CALL` slot in
/// `pam.c` lines 207–209.  It is registered with the driver registry via
/// `inventory::submit!` for compile-time discovery.
///
/// # Arguments
///
/// * `user` — The username to authenticate.  Originates from the first
///   colon-delimited field of the `server_condition` expansion in the
///   calling ACL context.  Empty usernames are rejected immediately
///   (matching C `pam.c` line 159).
/// * `args` — Colon-separated credential string passed to the PAM
///   conversation callback.  Typically contains the password as the first
///   (and often only) field.  Additional fields supply responses to PAM
///   prompts beyond the initial password challenge.
///
/// # Returns
///
/// * `Ok(())` — Authentication and account validation both succeeded.
/// * `Err(PamError)` — Authentication failed or a PAM error occurred.
///
/// # Behavior Preservation
///
/// Matches the C implementation's behavior exactly:
/// - Empty username → `AuthenticationFailed` (C: `FAIL`)
/// - `pam_start` failure → `ServiceUnavailable` (C: `ERROR`)
/// - `pam_authenticate` failure → classified by PAM error code
/// - `pam_acct_mgmt` failure → classified by PAM error code
/// - Success → `Ok(())` (C: `OK`)
pub fn pam_auth_call(user: &str, args: &str) -> Result<(), PamError> {
    let authenticator = PamAuthenticator::new();
    authenticator.authenticate(user, args)
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

/// Classify a raw PAM FFI error into a high-level [`PamError`] variant.
///
/// Maps specific PAM error codes to semantic error variants:
/// - `PAM_AUTH_ERR` (7) / `PAM_USER_UNKNOWN` (10) → [`PamError::AuthenticationFailed`]
/// - `PAM_ACCT_EXPIRED` (13) → [`PamError::AccountExpired`]
/// - `PAM_CONV_ERR` (19) → [`PamError::ConversationError`]
/// - `PAM_SERVICE_ERR` (3) / `PAM_SYSTEM_ERR` (4) → [`PamError::ServiceUnavailable`]
/// - All others → [`PamError::FfiError`] (preserving the original error code)
///
/// This replaces the C error classification at `pam.c` lines 194–199:
/// ```c
/// if (pam_error == PAM_USER_UNKNOWN ||
///     pam_error == PAM_AUTH_ERR ||
///     pam_error == PAM_ACCT_EXPIRED)
///   return FAIL;
/// return ERROR;
/// ```
///
/// The Rust version adds finer-grained classification (account expired,
/// conversation error, service error) while preserving the same caller-visible
/// OK / FAIL / ERROR trichotomy.
fn classify_ffi_error(err: ffi_pam::PamError) -> PamError {
    // Use PamError::code() to inspect the raw PAM error code for
    // classification.
    let code = err.code();

    // PAM_AUTH_ERR (7): incorrect credentials
    // PAM_USER_UNKNOWN (10): user does not exist in PAM backend
    // These map to C's `return FAIL` path at pam.c line 197.
    if code == 7 || code == 10 {
        return PamError::AuthenticationFailed;
    }

    // PAM_ACCT_EXPIRED (13): account has expired.
    // In C, this was grouped with FAIL at pam.c line 196.  We give it a
    // distinct variant for more precise error reporting.
    if code == 13 {
        return PamError::AccountExpired;
    }

    // PAM_CONV_ERR (19): conversation callback failed.
    // Indicates the conversation function returned an error or could not
    // provide credentials.
    if code == 19 {
        return PamError::ConversationError;
    }

    // PAM_SERVICE_ERR (3): service module error
    // PAM_SYSTEM_ERR (4): system error in PAM framework
    // These indicate infrastructure issues, not authentication failures.
    if code == 3 || code == 4 {
        return PamError::ServiceUnavailable;
    }

    // All other error codes — wrap as FfiError to preserve the raw code
    // for diagnostic purposes.  This maps to C's `return ERROR` at
    // pam.c line 199.
    PamError::FfiError(err)
}

/// Obtain a human-readable error description from the PAM library.
///
/// Opens a temporary PAM session using [`PamHandle::start()`] solely to call
/// [`PamHandle::strerror()`] for the given error code.  This provides the
/// system-specific PAM error string for diagnostic logging.
///
/// Falls back to a numeric description if the temporary session cannot be
/// created.  Replaces C `pam_strerror(pamh, pam_error)` at `pam.c` line 191.
///
/// The temporary [`PamHandle`](ffi_pam::PamHandle) is dropped immediately
/// after the strerror call (RAII guarantee from `PamHandle::drop` calling
/// `pam_end`).
fn get_pam_error_description(service: &str, user: &str, err: &ffi_pam::PamError) -> String {
    // Attempt to open a temporary PAM session for error string retrieval.
    // PamHandle::start() creates a session with no credentials — we only
    // need it for the strerror() call, not for authentication.
    match ffi_pam::PamHandle::start(service, user) {
        Ok(handle) => {
            // PamHandle::strerror() returns the PAM library's native error
            // description.  The handle is dropped after this call via RAII.
            let description = handle.strerror(err.code());
            debug!(
                pam_code = err.code(),
                pam_description = %description,
                "Retrieved PAM error description"
            );
            description
        }
        Err(start_err) => {
            // Cannot open temporary session — fall back to numeric
            // description.  This is a non-fatal condition: the original
            // error is still fully classified by classify_ffi_error().
            warn!(
                start_error_code = start_err.code(),
                target_error_code = err.code(),
                "Could not start temporary PAM session for error string retrieval"
            );
            format!("PAM error code {}", err.code())
        }
    }
}

/// Parse a colon-delimited credential string into a
/// [`PamConversationData`](ffi_pam::PamConversationData) structure.
///
/// Splits the input string on `:` (colon) boundaries, matching the C
/// implementation's `string_nextinlist()` with `sep = ':'` at `pam.c`
/// line 71 and line 158.  Empty fields are preserved to maintain
/// positional correspondence with PAM conversation prompts.
///
/// This function is primarily useful for diagnostic inspection of the
/// conversation data that would be passed to PAM's conversation callback.
/// In normal authentication flow, the `exim-ffi` layer constructs
/// `PamConversationData` internally.
pub fn parse_conversation_data(credentials: &str) -> ffi_pam::PamConversationData {
    let responses: Vec<String> = credentials.split(':').map(String::from).collect();
    debug!(
        field_count = responses.len(),
        "Parsed credential fields for PAM conversation data"
    );
    ffi_pam::PamConversationData {
        responses,
        current_index: 0,
    }
}

// ---------------------------------------------------------------------------
// Module Registration
// ---------------------------------------------------------------------------

// Register the PAM module with the exim-drivers registry at compile time.
//
// This replaces the C `misc_module_info pam_module_info` struct from
// `pam.c` lines 211–220:
//
//   misc_module_info pam_module_info = {
//     .name = US"pam",
//     .functions = pam_functions,
//     .functions_count = nelem(pam_functions),
//   };
//
// The `inventory::submit!` macro collects `DriverInfoBase` entries at link
// time, enabling the config parser to discover the PAM module when the
// `pam` feature is enabled (AAP §0.4.2, §0.7.3).
inventory::submit! {
    DriverInfoBase::new("pam")
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // PamError display and trait tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_pam_error_authentication_failed_display() {
        let err = PamError::AuthenticationFailed;
        assert_eq!(
            err.to_string(),
            "PAM authentication failed: bad credentials or unknown user"
        );
    }

    #[test]
    fn test_pam_error_account_expired_display() {
        let err = PamError::AccountExpired;
        assert_eq!(err.to_string(), "PAM account expired or disabled");
    }

    #[test]
    fn test_pam_error_conversation_error_display() {
        let err = PamError::ConversationError;
        assert_eq!(
            err.to_string(),
            "PAM conversation error: callback failed during authentication"
        );
    }

    #[test]
    fn test_pam_error_service_unavailable_display() {
        let err = PamError::ServiceUnavailable;
        assert_eq!(
            err.to_string(),
            "PAM service unavailable: session could not be started"
        );
    }

    #[test]
    fn test_pam_error_ffi_variant_display() {
        let ffi_err = ffi_pam::PamError::new(42);
        let err = PamError::FfiError(ffi_err);
        let display = err.to_string();
        assert!(
            display.contains("42"),
            "display should contain error code: {display}"
        );
    }

    #[test]
    fn test_pam_error_implements_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(PamError::AuthenticationFailed);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn test_pam_error_from_ffi_error() {
        let ffi_err = ffi_pam::PamError::new(99);
        let pam_err: PamError = ffi_err.into();
        assert!(matches!(pam_err, PamError::FfiError(_)));
    }

    // -----------------------------------------------------------------------
    // PamError::into_driver_error tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_auth_failed_into_driver_error() {
        let err = PamError::AuthenticationFailed;
        let driver_err = err.into_driver_error();
        assert!(matches!(driver_err, DriverError::ExecutionFailed(_)));
    }

    #[test]
    fn test_account_expired_into_driver_error() {
        let err = PamError::AccountExpired;
        let driver_err = err.into_driver_error();
        assert!(matches!(driver_err, DriverError::ExecutionFailed(_)));
    }

    #[test]
    fn test_service_unavailable_into_driver_error() {
        let err = PamError::ServiceUnavailable;
        let driver_err = err.into_driver_error();
        assert!(matches!(driver_err, DriverError::TempFail(_)));
    }

    #[test]
    fn test_ffi_error_into_driver_error() {
        let ffi_err = ffi_pam::PamError::new(77);
        let err = PamError::FfiError(ffi_err);
        let driver_err = err.into_driver_error();
        match driver_err {
            DriverError::ExecutionFailed(msg) => {
                assert!(msg.contains("77"), "should contain error code: {msg}");
            }
            other => panic!("expected ExecutionFailed, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // TaintError → PamError conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_taint_error_converts_to_conversation_error() {
        let taint_err = TaintError::new("credential contains null byte");
        let pam_err: PamError = taint_err.into();
        assert!(matches!(pam_err, PamError::ConversationError));
    }

    // -----------------------------------------------------------------------
    // classify_ffi_error tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_classify_pam_auth_err_code_7() {
        // PAM_AUTH_ERR = 7
        let err = ffi_pam::PamError::new(7);
        assert!(matches!(
            classify_ffi_error(err),
            PamError::AuthenticationFailed
        ));
    }

    #[test]
    fn test_classify_pam_user_unknown_code_10() {
        // PAM_USER_UNKNOWN = 10
        let err = ffi_pam::PamError::new(10);
        assert!(matches!(
            classify_ffi_error(err),
            PamError::AuthenticationFailed
        ));
    }

    #[test]
    fn test_classify_pam_acct_expired_code_13() {
        // PAM_ACCT_EXPIRED = 13
        let err = ffi_pam::PamError::new(13);
        assert!(matches!(classify_ffi_error(err), PamError::AccountExpired));
    }

    #[test]
    fn test_classify_pam_conv_err_code_19() {
        // PAM_CONV_ERR = 19
        let err = ffi_pam::PamError::new(19);
        assert!(matches!(
            classify_ffi_error(err),
            PamError::ConversationError
        ));
    }

    #[test]
    fn test_classify_pam_service_err_code_3() {
        // PAM_SERVICE_ERR = 3
        let err = ffi_pam::PamError::new(3);
        assert!(matches!(
            classify_ffi_error(err),
            PamError::ServiceUnavailable
        ));
    }

    #[test]
    fn test_classify_pam_system_err_code_4() {
        // PAM_SYSTEM_ERR = 4
        let err = ffi_pam::PamError::new(4);
        assert!(matches!(
            classify_ffi_error(err),
            PamError::ServiceUnavailable
        ));
    }

    #[test]
    fn test_classify_unknown_code_as_ffi_error() {
        let err = ffi_pam::PamError::new(999);
        match classify_ffi_error(err) {
            PamError::FfiError(e) => assert_eq!(e.code(), 999),
            other => panic!("expected FfiError, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // PamAuthenticator tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_authenticator_creation_default_service() {
        let auth = PamAuthenticator::new();
        // Clean<String> derefs to String which derefs to str
        assert_eq!(&*auth.service_name, "exim");
    }

    // -----------------------------------------------------------------------
    // parse_conversation_data tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_conversation_data_multiple_fields() {
        let data = parse_conversation_data("user:password:extra");
        assert_eq!(data.responses, vec!["user", "password", "extra"]);
        assert_eq!(data.current_index, 0);
    }

    #[test]
    fn test_parse_conversation_data_single_field() {
        let data = parse_conversation_data("password");
        assert_eq!(data.responses, vec!["password"]);
        assert_eq!(data.current_index, 0);
    }

    #[test]
    fn test_parse_conversation_data_empty_string() {
        let data = parse_conversation_data("");
        assert_eq!(data.responses, vec![""]);
        assert_eq!(data.current_index, 0);
    }

    #[test]
    fn test_parse_conversation_data_preserves_empty_fields() {
        let data = parse_conversation_data("a::c");
        assert_eq!(data.responses, vec!["a", "", "c"]);
    }

    // -----------------------------------------------------------------------
    // Taint-related integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_tainted_string_creation() {
        let tainted: TaintedString = Tainted::new("secret".to_string());
        // Verify the tainted wrapper exists — cannot directly access inner
        // value without sanitize() or force_clean().
        let clean = tainted.sanitize(|s| !s.is_empty()).unwrap();
        assert_eq!(clean.into_inner(), "secret");
    }

    #[test]
    fn test_tainted_sanitize_rejects_empty_user() {
        let tainted: TaintedString = Tainted::new(String::new());
        let result = tainted.sanitize(|u| !u.is_empty());
        assert!(result.is_err());
    }

    #[test]
    fn test_tainted_sanitize_rejects_null_bytes() {
        let tainted: TaintedString = Tainted::new("pass\0word".to_string());
        let result = tainted.sanitize(|c| !c.contains('\0'));
        assert!(result.is_err());
    }

    #[test]
    fn test_clean_string_deref() {
        let clean: CleanString = Clean::new("exim".to_string());
        // Clean<String> implements Deref<Target=String>
        let as_str: &str = &clean;
        assert_eq!(as_str, "exim");
    }

    #[test]
    fn test_taint_state_display() {
        assert_eq!(TaintState::Tainted.to_string(), "tainted");
        assert_eq!(TaintState::Untainted.to_string(), "untainted");
    }
}
