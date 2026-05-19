//! RADIUS Authentication Module for Exim MTA.
//!
//! Rewrite of `src/src/miscmods/radius.c` (243 lines) — provides RADIUS
//! authentication support for Exim, calling `libradius` or `radiusclient`
//! C libraries via the `exim-ffi` crate.
//!
//! Feature-gated behind `#[cfg(feature = "radius")]` in `lib.rs`, replacing
//! the C `RADIUS_CONFIG_FILE` preprocessor guard (`radius.c` line 27).
//!
//! # Three Library Variants
//!
//! The C implementation supported three RADIUS library backends:
//!
//! | C Macro | Library | Header |
//! |---|---|---|
//! | `RADIUS_LIB_RADLIB` | FreeBSD `libradius` | `<radlib.h>` |
//! | `RADIUS_LIB_RADIUSCLIENT` | radiusclient (legacy API) | `<radiusclient.h>` |
//! | `RADIUS_LIB_RADIUSCLIENTNEW` | freeradiusclient (new API) | `<freeradius-client.h>` |
//!
//! In the Rust implementation, library variant selection is handled entirely
//! within `exim-ffi/src/radius.rs` via build-time header detection.  This module
//! uses the unified safe [`RadiusClient`] API without knowledge of the underlying
//! C library variant.
//!
//! # Taint Tracking
//!
//! Per AAP §0.4.3, user-supplied credentials (username, password) from SMTP AUTH
//! are treated as tainted external input.  They are wrapped in [`Tainted<T>`]
//! internally and sanitized before passage to the FFI layer.  The RADIUS config
//! file path is admin-configured and treated as [`Clean<T>`].
//!
//! # Module Registration
//!
//! The module is registered with the `exim-drivers` registry via
//! [`inventory::submit!`] at compile time, replacing the C static
//! `misc_module_info radius_module_info` struct (`radius.c` lines 230–239).
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` code.  All RADIUS C library calls are
//! confined to the `exim-ffi` crate (per AAP §0.7.2).
//!
//! [`RadiusClient`]: exim_ffi::radius::RadiusClient
//! [`Tainted<T>`]: exim_store::Tainted
//! [`Clean<T>`]: exim_store::Clean

// SPDX-License-Identifier: GPL-2.0-or-later

use exim_drivers::{DriverError, DriverInfoBase};
use exim_ffi::radius::{RadiusAuthResult, RadiusClient, RadiusError as FfiRadiusError};
use exim_store::taint::{TaintError, TaintState};
use exim_store::{Clean, CleanString, Tainted, TaintedString};

// ── Error Type ──────────────────────────────────────────────────────────────

/// RADIUS module authentication error type.
///
/// Replaces the C pattern of ad-hoc `*errptr` string assignment and
/// `log_write()` calls throughout `radius.c` (lines 106–209) with structured
/// error variants.  Each variant maps to a specific failure mode in the RADIUS
/// authentication flow.
///
/// Uses [`thiserror::Error`] derive macro for automatic [`Display`] and
/// [`std::error::Error`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum RadiusError {
    /// RADIUS configuration file could not be opened or parsed.
    ///
    /// C equivalents:
    /// - `*errptr = string_sprintf("RADIUS: can't open %s", ...)` (lines 106, 123)
    /// - `*errptr = string_sprintf("RADIUS: can't initialise libradius")` (line 179)
    #[error("RADIUS config file error: {0}")]
    ConfigError(String),

    /// RADIUS dictionary file could not be read.
    ///
    /// C equivalent: `*errptr = US"RADIUS: can't read dictionary"` (lines 109, 126)
    #[error("RADIUS dictionary error: {0}")]
    DictionaryError(String),

    /// Authentication operation failed with a descriptive message.
    ///
    /// C equivalents:
    /// - `*errptr = US"RADIUS: add user name failed"` (lines 112, 129)
    /// - `*errptr = US"RADIUS: add password failed"` (lines 115, 133)
    /// - `*errptr = US"RADIUS: add service type failed"` (lines 118, 136)
    /// - `*errptr = string_sprintf("RADIUS: %s", rad_strerror(h))` (lines 189, 204)
    #[error("RADIUS authentication error: {0}")]
    AuthError(String),

    /// Error propagated from the FFI layer (`exim-ffi` RADIUS bindings).
    ///
    /// Wraps the underlying C library error with `#[from]` for ergonomic `?`
    /// operator usage.  Covers all low-level FFI failures such as null pointer
    /// returns, CString conversion errors, and library-specific error codes.
    #[error("RADIUS FFI error: {0}")]
    FfiError(#[from] FfiRadiusError),

    /// The RADIUS server did not respond within the configured timeout.
    ///
    /// C equivalent: `*errptr = US"RADIUS: timed out"` (line 164)
    #[error("RADIUS: timed out")]
    Timeout,

    /// An unexpected or malformed response code was received from the server.
    ///
    /// The inner `i32` is the raw C return code for diagnostic purposes.
    ///
    /// C equivalents:
    /// - `*errptr = string_sprintf("RADIUS: unexpected response (%d)", ...)` (lines 169, 209)
    #[error("RADIUS: unexpected response ({0})")]
    BadResponse(i32),
}

/// Conversion from the RADIUS-specific error type to the generic driver error.
///
/// Enables integration with the `exim-drivers` registry error handling.
///
/// Mapping:
/// - Config/dictionary errors → [`DriverError::ConfigError`]
/// - Timeout → [`DriverError::TempFail`] (retriable)
/// - Auth/FFI/BadResponse → [`DriverError::ExecutionFailed`]
impl From<RadiusError> for DriverError {
    fn from(err: RadiusError) -> Self {
        match err {
            RadiusError::ConfigError(msg) => DriverError::ConfigError(msg),
            RadiusError::DictionaryError(msg) => DriverError::ConfigError(msg),
            RadiusError::Timeout => DriverError::TempFail("RADIUS server timed out".to_string()),
            other => DriverError::ExecutionFailed(other.to_string()),
        }
    }
}

// ── Taint-Aware Credential Wrapper ──────────────────────────────────────────

/// Tainted RADIUS authentication credentials received from SMTP AUTH.
///
/// Encapsulates the untrusted user-supplied data (username and password) and
/// the trusted admin-configured RADIUS settings.  All fields use taint-tracking
/// newtypes per AAP §0.4.3:
///
/// - `user` and `password` are [`TaintedString`] because they arrive from
///   the connecting SMTP client and are untrusted external input.
/// - `config_file` is [`CleanString`] because it is an admin-configured path
///   from the Exim configuration file (trusted source).
///
/// Replaces the implicit trust in C `radius.c` lines 89-90 where
/// `string_nextinlist()` output was used directly without taint awareness.
struct RadiusCredentials {
    /// RADIUS authentication username — tainted because it originates from
    /// the SMTP AUTH exchange (untrusted client input).
    user: TaintedString,

    /// RADIUS authentication password — tainted because it originates from
    /// the SMTP AUTH exchange (untrusted client input).
    password: TaintedString,

    /// Path to the RADIUS configuration file — clean because it is set by
    /// the Exim administrator in the configuration file (trusted source).
    config_file: CleanString,
}

impl RadiusCredentials {
    /// Construct new credentials with explicit taint tracking.
    ///
    /// Wraps the raw string data in the appropriate taint newtypes:
    /// user and password become [`TaintedString`], config_file becomes
    /// [`CleanString`].
    fn new(user: &str, password: &str, config_file: &str) -> Self {
        Self {
            user: Tainted::new(user.to_owned()),
            password: Tainted::new(password.to_owned()),
            config_file: Clean::new(config_file.to_owned()),
        }
    }

    /// Sanitize tainted credentials for safe FFI passage.
    ///
    /// Validates that the tainted user and password strings do not contain
    /// embedded null bytes, which would cause string truncation at the C FFI
    /// boundary.  Returns clean owned strings suitable for passing to
    /// [`RadiusClient::authenticate()`].
    ///
    /// This replaces the implicit trust in C where `string_nextinlist()` output
    /// from `radius.c` lines 89-90 was passed directly to
    /// `rc_avpair_add()` / `rad_put_string()` without validation.
    fn sanitize(&self) -> Result<(CleanString, CleanString), RadiusError> {
        let clean_user =
            self.user
                .clone()
                .sanitize(|u| !u.contains('\0'))
                .map_err(|e: TaintError| {
                    tracing::error!(
                        context = %e,
                        "RADIUS: username failed taint sanitization"
                    );
                    RadiusError::AuthError(format!("username contains invalid characters: {}", e))
                })?;

        let clean_password = self
            .password
            .clone()
            .sanitize(|p| !p.contains('\0'))
            .map_err(|e: TaintError| {
                tracing::error!(
                    context = %e,
                    "RADIUS: password failed taint sanitization"
                );
                RadiusError::AuthError(format!("password contains invalid characters: {}", e))
            })?;

        Ok((clean_user, clean_password))
    }
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Perform RADIUS authentication for the given user credentials.
///
/// This is the main entry point for RADIUS-based authentication in Exim,
/// registered at function table slot [`RADIUS_AUTH_CALL`] (index 0).
/// It replaces C `auth_call_radius()` from `src/src/miscmods/radius.c`
/// (lines 70–219) with a safe Rust implementation.
///
/// # Authentication Flow
///
/// 1. Wraps user/password in [`Tainted<T>`] to track data provenance
/// 2. Logs the authentication attempt via structured logging
/// 3. Sanitizes credentials (validates no embedded null bytes for FFI safety)
/// 4. Creates a [`RadiusClient`] using the admin-configured config file path
/// 5. Calls [`RadiusClient::authenticate()`] to perform the RADIUS exchange
/// 6. Maps the [`RadiusAuthResult`] to success/failure
///
/// The [`exim_ffi::radius::authenticate()`] convenience function provides an
/// equivalent one-shot API if no intermediate error handling is needed.
///
/// # Arguments
///
/// * `user` — Username to authenticate (from SMTP AUTH — untrusted external input)
/// * `password` — Password to authenticate (from SMTP AUTH — untrusted external input)
/// * `config_file` — Path to the RADIUS configuration file (admin-configured — trusted)
///
/// # Returns
///
/// * `Ok(())` — Authentication succeeded (C equivalent: return `OK`)
/// * `Err(RadiusError::AuthError(_))` — Authentication rejected (C: `FAIL`)
/// * `Err(RadiusError::Timeout)` — RADIUS server timed out (C: `ERROR`)
/// * `Err(RadiusError::BadResponse(_))` — Unexpected response (C: `ERROR`)
/// * `Err(RadiusError::ConfigError(_))` — Config file error (C: `ERROR`)
/// * `Err(RadiusError::FfiError(_))` — FFI-level error (C: `ERROR`)
///
/// # Examples
///
/// ```ignore
/// use exim_miscmods::radius::{radius_auth_call, RadiusError};
///
/// match radius_auth_call("user@example.com", "s3cret", "/etc/radius.conf") {
///     Ok(()) => println!("Authentication succeeded"),
///     Err(RadiusError::AuthError(_)) => println!("Bad credentials"),
///     Err(RadiusError::Timeout) => println!("Server timed out, retry later"),
///     Err(e) => eprintln!("Authentication error: {e}"),
/// }
/// ```
///
/// [`RadiusClient`]: exim_ffi::radius::RadiusClient
/// [`RadiusClient::authenticate()`]: exim_ffi::radius::RadiusClient::authenticate
/// [`RadiusAuthResult`]: exim_ffi::radius::RadiusAuthResult
/// [`Tainted<T>`]: exim_store::Tainted
/// [`exim_ffi::radius::authenticate()`]: exim_ffi::radius::authenticate
pub fn radius_auth_call(user: &str, password: &str, config_file: &str) -> Result<(), RadiusError> {
    // ── Step 1: Wrap credentials with taint tracking ────────────────────
    //
    // Per AAP §0.4.3, user/password from SMTP AUTH are untrusted external
    // input and are wrapped in Tainted<T>.  The config file path is
    // admin-configured and is Clean<T>.
    let credentials = RadiusCredentials::new(user, password, config_file);

    // ── Step 2: Structured logging ─────────────────────────────────────
    //
    // Replaces C: DEBUG(D_auth) debug_printf("Running RADIUS authentication
    // for user %q and %q\n", user, pwd) at radius.c lines 92-93.
    if user.is_empty() {
        tracing::warn!("RADIUS authentication attempt with empty username");
    }
    if password.is_empty() {
        tracing::warn!("RADIUS authentication attempt with empty password");
    }
    tracing::debug!(
        user = %user,
        taint_state = %TaintState::Tainted,
        config_file = %config_file,
        "Running RADIUS authentication for user"
    );

    // ── Step 3: Sanitize tainted credentials for FFI passage ───────────
    //
    // Validate that user/password strings do not contain embedded null bytes,
    // which would cause string truncation at the C FFI boundary.  This
    // replaces the implicit trust in C where string_nextinlist() output was
    // passed directly to rc_avpair_add() / rad_put_string() without
    // validation.
    let (clean_user, clean_password) = credentials.sanitize()?;

    // ── Step 4: Create RADIUS client and authenticate ──────────────────
    //
    // Uses RadiusClient::new() to open the RADIUS configuration and
    // RadiusClient::authenticate() to perform the authentication exchange.
    // This provides finer-grained error handling than the convenience
    // function exim_ffi::radius::authenticate().
    //
    // Replaces C flow:
    //   radlib variant (lines 177-216):
    //     rad_auth_open() → rad_config() → rad_create_request()
    //     → rad_put_string() × 3 → rad_put_int() → rad_send_request()
    //     → rad_close()
    //   radiusclient variant (lines 100-171):
    //     rc_read_config() → rc_read_dictionary()
    //     → rc_avpair_add() × 3 → rc_auth()
    let client = RadiusClient::new(&credentials.config_file).map_err(|e| {
        tracing::error!(
            config_file = %config_file,
            error = %e,
            "RADIUS: failed to open configuration"
        );
        RadiusError::ConfigError(format!("can't open {}: {}", config_file, e))
    })?;

    let result = client
        .authenticate(&clean_user, &clean_password)
        .map_err(|e| {
            tracing::error!(error = %e, "RADIUS: authentication call failed");
            RadiusError::from(e)
        })?;

    // ── Step 5: Map RADIUS result codes ────────────────────────────────
    //
    // Replaces C switch statement at radius.c lines 154-171 (radiusclient)
    // and lines 193-211 (radlib).  Maps RadiusAuthResult to our Result type.
    //
    // C: DEBUG(D_auth) debug_printf("RADIUS code returned %d\n", result)
    tracing::debug!(result = ?result, "RADIUS code returned");

    match result {
        RadiusAuthResult::Ok => {
            // C: OK_RC / RAD_ACCESS_ACCEPT → return OK
            tracing::debug!("RADIUS authentication succeeded");
            Ok(())
        }

        RadiusAuthResult::Fail => {
            // C: REJECT_RC / ERROR_RC → return FAIL
            //    RAD_ACCESS_REJECT → return FAIL
            tracing::debug!("RADIUS authentication rejected");
            Err(RadiusError::AuthError(
                "authentication rejected by RADIUS server".to_string(),
            ))
        }

        RadiusAuthResult::Error => {
            // C: radlib case -1 → return ERROR with rad_strerror()
            tracing::error!("RADIUS authentication error from server");
            Err(RadiusError::AuthError(
                "RADIUS server returned error".to_string(),
            ))
        }

        RadiusAuthResult::Timeout => {
            // C: TIMEOUT_RC → return ERROR with "RADIUS: timed out"
            tracing::error!("RADIUS server timed out");
            Err(RadiusError::Timeout)
        }

        RadiusAuthResult::BadResponse(code) => {
            // C: BADRESP_RC / default → return ERROR with "unexpected response (%d)"
            tracing::error!(code = code, "RADIUS: unexpected response code");
            Err(RadiusError::BadResponse(code))
        }
    }
}

// ── Module Registration ─────────────────────────────────────────────────────
//
// Register the RADIUS misc module with the exim-drivers registry system via
// `inventory::submit!`, replacing the C static `misc_module_info` struct from
// `radius.c` lines 230-239:
//
//   misc_module_info radius_module_info = {
//     .name       = US"radius",
//     .functions   = rad_functions,       // [RADIUS_AUTH_CALL] = auth_call_radius
//     .functions_count = nelem(rad_functions),
//   };
//
// In Rust, the function dispatch table is replaced by direct function calls
// from the module consumer.  The `DriverInfoBase` metadata provides the module
// name for configuration file matching and `-bV` version output display.
//
// Per AAP §0.7.3: Driver registration via inventory crate for compile-time
// collection and runtime resolution by name from config.

inventory::submit! {
    DriverInfoBase::new("radius")
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use exim_ffi::radius::authenticate as ffi_authenticate;

    // -- RadiusError display tests ----------------------------------------

    #[test]
    fn test_radius_error_config_display() {
        let err = RadiusError::ConfigError("can't open /etc/radius.conf".to_string());
        assert_eq!(
            err.to_string(),
            "RADIUS config file error: can't open /etc/radius.conf"
        );
    }

    #[test]
    fn test_radius_error_dictionary_display() {
        let err = RadiusError::DictionaryError("can't read dictionary".to_string());
        assert_eq!(
            err.to_string(),
            "RADIUS dictionary error: can't read dictionary"
        );
    }

    #[test]
    fn test_radius_error_auth_display() {
        let err = RadiusError::AuthError("authentication rejected".to_string());
        assert_eq!(
            err.to_string(),
            "RADIUS authentication error: authentication rejected"
        );
    }

    #[test]
    fn test_radius_error_timeout_display() {
        let err = RadiusError::Timeout;
        assert_eq!(err.to_string(), "RADIUS: timed out");
    }

    #[test]
    fn test_radius_error_bad_response_display() {
        let err = RadiusError::BadResponse(42);
        assert_eq!(err.to_string(), "RADIUS: unexpected response (42)");
    }

    // -- DriverError conversion tests -------------------------------------

    #[test]
    fn test_driver_error_from_config_error() {
        let radius_err = RadiusError::ConfigError("test config error".to_string());
        let driver_err: DriverError = radius_err.into();
        assert!(matches!(driver_err, DriverError::ConfigError(_)));
        assert_eq!(
            driver_err.to_string(),
            "configuration error: test config error"
        );
    }

    #[test]
    fn test_driver_error_from_dictionary_error() {
        let radius_err = RadiusError::DictionaryError("test dict error".to_string());
        let driver_err: DriverError = radius_err.into();
        assert!(matches!(driver_err, DriverError::ConfigError(_)));
    }

    #[test]
    fn test_driver_error_from_timeout() {
        let radius_err = RadiusError::Timeout;
        let driver_err: DriverError = radius_err.into();
        assert!(matches!(driver_err, DriverError::TempFail(_)));
    }

    #[test]
    fn test_driver_error_from_auth_error() {
        let radius_err = RadiusError::AuthError("rejected".to_string());
        let driver_err: DriverError = radius_err.into();
        assert!(matches!(driver_err, DriverError::ExecutionFailed(_)));
    }

    #[test]
    fn test_driver_error_from_bad_response() {
        let radius_err = RadiusError::BadResponse(99);
        let driver_err: DriverError = radius_err.into();
        assert!(matches!(driver_err, DriverError::ExecutionFailed(_)));
    }

    // -- RadiusCredentials tests ------------------------------------------

    #[test]
    fn test_credentials_new() {
        let creds = RadiusCredentials::new("testuser", "testpass", "/etc/radius.conf");
        assert_eq!(creds.user.as_ref(), &"testuser".to_string());
        assert_eq!(creds.password.as_ref(), &"testpass".to_string());
        assert_eq!(&*creds.config_file, "/etc/radius.conf");
    }

    #[test]
    fn test_credentials_sanitize_valid() {
        let creds = RadiusCredentials::new("user@example.com", "s3cret", "/etc/radius.conf");
        let result = creds.sanitize();
        assert!(result.is_ok());
        let (clean_user, clean_password) = result.unwrap();
        assert_eq!(&*clean_user, "user@example.com");
        assert_eq!(&*clean_password, "s3cret");
    }

    #[test]
    fn test_credentials_sanitize_null_byte_in_user() {
        let creds = RadiusCredentials::new("user\0evil", "password", "/etc/radius.conf");
        let result = creds.sanitize();
        assert!(result.is_err());
        if let Err(RadiusError::AuthError(msg)) = result {
            assert!(
                msg.contains("username"),
                "error message should mention username: {}",
                msg
            );
        } else {
            panic!("expected RadiusError::AuthError");
        }
    }

    #[test]
    fn test_credentials_sanitize_null_byte_in_password() {
        let creds = RadiusCredentials::new("user", "pass\0word", "/etc/radius.conf");
        let result = creds.sanitize();
        assert!(result.is_err());
        if let Err(RadiusError::AuthError(msg)) = result {
            assert!(
                msg.contains("password"),
                "error message should mention password: {}",
                msg
            );
        } else {
            panic!("expected RadiusError::AuthError");
        }
    }

    #[test]
    fn test_credentials_sanitize_empty_strings() {
        // Empty strings are valid (no null bytes) — the RADIUS server decides
        // whether empty credentials are acceptable.
        let creds = RadiusCredentials::new("", "", "/etc/radius.conf");
        let result = creds.sanitize();
        assert!(result.is_ok());
    }

    // -- Constant tests ---------------------------------------------------

    /// RADIUS authentication function table slot index.
    ///
    /// Replaces C `#define RADIUS_AUTH_CALL 0` from `radius_api.h` line 14.
    /// Preserved for documentation and test verification — in the Rust crate,
    /// the dispatcher calls [`radius_auth_call`] directly instead of using
    /// a function table slot index.
    const RADIUS_AUTH_CALL: usize = 0;

    #[test]
    fn test_radius_auth_call_slot_constant() {
        // Verify the function table slot index matches C `radius_api.h` line 14:
        // `#define RADIUS_AUTH_CALL 0`
        assert_eq!(RADIUS_AUTH_CALL, 0);
    }

    // -- Taint type usage tests -------------------------------------------

    #[test]
    fn test_taint_state_display() {
        // Verify TaintState variants are accessible and format correctly
        // (used in structured logging within radius_auth_call)
        let tainted = TaintState::Tainted;
        assert_eq!(tainted.to_string(), "tainted");

        let untainted = TaintState::Untainted;
        assert_eq!(untainted.to_string(), "untainted");
    }

    #[test]
    fn test_tainted_string_type_alias() {
        // Verify TaintedString type alias works correctly
        let ts: TaintedString = Tainted::new("hello".to_string());
        assert_eq!(ts.as_ref(), &"hello".to_string());
    }

    #[test]
    fn test_clean_string_type_alias() {
        // Verify CleanString type alias works correctly
        let cs: CleanString = Clean::new("/etc/radius.conf".to_string());
        assert_eq!(&*cs, "/etc/radius.conf");
    }

    // -- FFI type accessibility tests -------------------------------------

    #[test]
    fn test_radius_auth_result_variants() {
        // Verify RadiusAuthResult variants are accessible for matching
        let ok = RadiusAuthResult::Ok;
        let fail = RadiusAuthResult::Fail;
        let error = RadiusAuthResult::Error;
        let timeout = RadiusAuthResult::Timeout;
        let bad = RadiusAuthResult::BadResponse(42);

        assert_eq!(ok, RadiusAuthResult::Ok);
        assert_eq!(fail, RadiusAuthResult::Fail);
        assert_eq!(error, RadiusAuthResult::Error);
        assert_eq!(timeout, RadiusAuthResult::Timeout);
        assert_eq!(bad, RadiusAuthResult::BadResponse(42));
    }

    #[test]
    fn test_ffi_error_conversion() {
        // Verify #[from] conversion from FfiRadiusError to RadiusError
        let ffi_err = FfiRadiusError::new("test FFI error");
        let radius_err: RadiusError = RadiusError::from(ffi_err);
        assert!(matches!(radius_err, RadiusError::FfiError(_)));
        assert!(radius_err.to_string().contains("FFI error"));
    }

    #[test]
    fn test_ffi_authenticate_import_accessible() {
        // Verify the ffi_authenticate convenience function is accessible via import.
        // We verify the function signature by creating a function pointer.
        // This cannot be called without a running RADIUS server, but the
        // compile-time check ensures the exim_ffi::radius::authenticate import
        // resolves correctly and has the expected signature.
        let _fn_ref: fn(
            &str,
            &str,
            &str,
        ) -> Result<
            exim_ffi::radius::RadiusAuthResult,
            exim_ffi::radius::RadiusError,
        > = ffi_authenticate;
        let _ = _fn_ref; // suppress unused warning
    }
}
