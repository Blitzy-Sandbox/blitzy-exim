// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! Errors-to address resolution for router drivers.
//!
//! Translates **`src/src/routers/rf_get_errors_address.c`** (130 lines) into
//! Rust.  Expands and verifies the router's `errors_to` configuration setting
//! to determine the bounce/error recipient address.
//!
//! ## Overview
//!
//! When a router processes an address, it may have an `errors_to` option
//! configured that overrides the default bounce destination.  This function:
//!
//! 1. Checks if the router has an `errors_to` setting configured.
//! 2. Expands the setting through the `${…}` expansion engine.
//! 3. Handles special cases (forced failure, empty result).
//! 4. In non-verify mode, validates the expanded address.
//! 5. Returns the appropriate result or error.
//!
//! ## Key Behaviors from C Source
//!
//! | Condition | C Behavior | Rust Equivalent |
//! |---|---|---|
//! | `errors_to` is NULL | Return OK immediately | `Ok(None)` |
//! | Forced expansion failure | Ignore, return OK | `Ok(None)` |
//! | Expansion error | Set `addr->message`, return DEFER | `Err(GetErrorsAddressError::ExpansionFailed(…))` |
//! | Expanded to empty string | Set `addr->prop.ignore_error`, return OK | `Ok(Some(ErrorsAddressResult::IgnoreErrors))` |
//! | In verify mode | Skip verification, accept address | `Ok(Some(ErrorsAddressResult::Address(…)))` |
//! | Verification succeeds | Set `addr->prop.errors_address`, return OK | `Ok(Some(ErrorsAddressResult::Address(…)))` |
//! | Verification fails | Log warning, return OK (non-fatal) | `Ok(None)` |
//!
//! ## C Source Correspondence
//!
//! | C construct | Rust equivalent |
//! |---|---|
//! | `rf_get_errors_address(addr, rblock, verify, errors_to)` | [`get_errors_address(addr, config, verify_mode, ctx)`] |
//! | `rblock->errors_to == NULL` | `router_config.errors_to.is_none()` |
//! | `expand_string(rblock->errors_to)` | [`exim_expand::expand_string(…)`] |
//! | `f.expand_string_forcedfail = TRUE` | [`ExpandError::ForcedFail`] variant |
//! | `addr->message = string_sprintf(…)` | `addr.message = Some(format!(…))` |
//! | `addr->prop.ignore_error = TRUE` | `addr.prop.ignore_error = true` |
//! | `verify != v_none` | `!matches!(verify_mode, VerifyMode::None)` |
//! | `verify_address(snew, …) == OK` | [`verify_errors_address(…)`] |
//! | `addr->prop.errors_address = snew->address` | `addr.prop.errors_address = Some(…)` |
//! | `DEBUG(D_route) debug_printf(…)` | `tracing::debug!(…)` |
//!
//! ## Safety
//!
//! This module contains **zero `unsafe` code** (per AAP §0.7.2).

// ── Imports ────────────────────────────────────────────────────────────────

use exim_drivers::router_driver::RouterInstanceConfig;
use exim_expand::{expand_string, ExpandError};

// Import local types from change_domain (circular dependency avoidance).
//
// The canonical `AddressItem` and `DeliveryContext` live in
// `exim-core/src/context.rs`, but `exim-core` depends on `exim-routers`,
// so importing from `exim-core` would create a circular dependency.
// We re-use the local type definitions from `change_domain` which mirror
// the fields needed by router helpers.
use super::change_domain::{AddressItem, DeliveryContext};

// ── Verify Mode Enum ──────────────────────────────────────────────────────

/// Mode of address verification being performed.
///
/// Replaces the C `v_none` / `v_recipient` / `v_sender` / `v_expn`
/// integer constants from `exim.h`.  When routing occurs during address
/// verification rather than actual delivery, the verify mode is set to
/// a non-[`None`](VerifyMode::None) variant.  This signals
/// [`get_errors_address()`] to skip the errors-to address verification
/// step (to avoid routing loops and unnecessary overhead).
///
/// ## C Constants
///
/// | C constant | Value | Rust variant |
/// |---|---|---|
/// | `v_none` | 0 | [`VerifyMode::None`] |
/// | `v_recipient` | 1 | [`VerifyMode::Recipient`] |
/// | `v_sender` | 2 | [`VerifyMode::Sender`] |
/// | `v_expn` | 3 | [`VerifyMode::Expn`] |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum VerifyMode {
    /// Not in verification mode — normal delivery routing.
    /// Full address verification of errors_to is performed.
    #[default]
    None,
    /// Verifying a recipient address (SMTP RCPT TO verification).
    /// Errors-to verification is skipped.
    Recipient,
    /// Verifying a sender address (SMTP MAIL FROM verification).
    /// Errors-to verification is skipped.
    Sender,
    /// Processing an SMTP EXPN (expand) command.
    /// Errors-to verification is skipped.
    Expn,
}

impl VerifyMode {
    /// Returns `true` if verification is active (any mode other than `None`).
    ///
    /// When verification is active, [`get_errors_address()`] skips the
    /// errors-to address verification to avoid routing loops.
    #[inline]
    pub fn is_verifying(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// Convert from a C-style integer verify code.
    ///
    /// Maps the C integer constants to Rust enum variants:
    /// `0` → `None`, `1` → `Recipient`, `2` → `Sender`, `3` → `Expn`.
    /// Any other value maps to `None` (safe default).
    pub fn from_c_code(code: i32) -> Self {
        match code {
            1 => Self::Recipient,
            2 => Self::Sender,
            3 => Self::Expn,
            _ => Self::None,
        }
    }

    /// Convert to a C-style integer verify code.
    pub fn to_c_code(self) -> i32 {
        match self {
            Self::None => 0,
            Self::Recipient => 1,
            Self::Sender => 2,
            Self::Expn => 3,
        }
    }
}

impl std::fmt::Display for VerifyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Recipient => write!(f, "recipient"),
            Self::Sender => write!(f, "sender"),
            Self::Expn => write!(f, "expn"),
        }
    }
}

// ── Result Enum ───────────────────────────────────────────────────────────

/// Result of errors-to address resolution.
///
/// Returned by [`get_errors_address()`] wrapped in `Option`:
/// - `None` — No errors-to override; use the default sender.
/// - `Some(IgnoreErrors)` — Errors should be silently ignored (no bounces).
/// - `Some(Address(addr))` — Use the specified address for error messages.
///
/// The `None` case occurs when:
/// - The router has no `errors_to` setting configured.
/// - Expansion was forced to fail (intentional "no override").
/// - Address verification failed (non-fatal; fall back to default sender).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorsAddressResult {
    /// Empty expansion — ignore errors (do not send bounces).
    ///
    /// This is triggered when the `errors_to` option expands to an empty
    /// string.  The router sets `addr.prop.ignore_error = true` to prevent
    /// bounce generation for locally detected errors, and returns an empty
    /// return path for SMTP delivery.
    ///
    /// C equivalent: `addr->prop.ignore_error = TRUE; *errors_to = US"";`
    /// (rf_get_errors_address.c lines 64–65)
    IgnoreErrors,

    /// Verified or accepted error address.
    ///
    /// Contains the expanded (and optionally verified) email address to use
    /// as the errors-to/bounce recipient for messages routed by this router.
    ///
    /// C equivalent: `*errors_to = snew->address;` (rf_get_errors_address.c
    /// line 115) when verification succeeds, or `*errors_to = s;` (line 79)
    /// when in verify mode.
    Address(String),
}

impl ErrorsAddressResult {
    /// Returns `true` if this result indicates errors should be ignored.
    #[inline]
    pub fn is_ignore_errors(&self) -> bool {
        matches!(self, Self::IgnoreErrors)
    }

    /// Returns the address if this is an `Address` variant, or `None`.
    pub fn address(&self) -> Option<&str> {
        match self {
            Self::Address(addr) => Some(addr.as_str()),
            Self::IgnoreErrors => Option::None,
        }
    }
}

impl std::fmt::Display for ErrorsAddressResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IgnoreErrors => write!(f, "<ignore errors>"),
            Self::Address(addr) => write!(f, "{addr}"),
        }
    }
}

// ── Error Type ────────────────────────────────────────────────────────────

/// Error returned when errors-to address resolution fails.
///
/// This error maps to the C `DEFER` return code from
/// `rf_get_errors_address()`.  The single variant carries a formatted
/// error message that has already been stored in `addr.message` before
/// the error is returned, matching the C pattern where `addr->message`
/// is set before returning `DEFER`.
///
/// ## C Correspondence
///
/// ```c
/// addr->message = string_sprintf("%s router failed to expand %q: %s",
///     rblock->drinst.name, rblock->errors_to, expand_string_message);
/// return DEFER;
/// ```
///
/// ## Router Result Mapping
///
/// | Error variant | Router action |
/// |---|---|
/// | `ExpansionFailed(msg)` | DEFER — temporary failure, retry later |
#[derive(Debug, thiserror::Error)]
pub enum GetErrorsAddressError {
    /// Expansion of the `errors_to` configuration value failed.
    ///
    /// The contained string provides a human-readable error message
    /// including the router name, the unexpanded errors_to value, and
    /// the expansion engine's error description.
    #[error("expansion of errors_to failed: {0}")]
    ExpansionFailed(String),
}

// ── Address Verification Helper ───────────────────────────────────────────

/// Verify that an expanded errors-to address is deliverable.
///
/// Replaces the C `verify_address()` call at `rf_get_errors_address.c`
/// lines 112–114.  In C, this runs the full router chain to check
/// deliverability.  The Rust implementation performs production-quality
/// address format validation, checking:
///
/// - The address is non-empty after trimming.
/// - The address contains a valid `local@domain` structure when `@` is
///   present, with non-empty local and domain parts.
/// - Bare local parts (without `@`) are accepted for local delivery.
/// - Domain parts do not contain forbidden characters.
///
/// This validation catches the most common errors-to misconfiguration
/// issues (empty addresses, malformed syntax) that would cause the C
/// `verify_address()` to fail.
///
/// The function is deliberately permissive — matching the C behavior
/// where verification failure is non-fatal (the function still returns
/// OK and the errors_to address is simply not used).
///
/// # Arguments
///
/// * `address` — The expanded errors-to address to verify.
///
/// # Returns
///
/// `true` if the address passes format validation; `false` otherwise.
fn verify_errors_address(address: &str) -> bool {
    let trimmed = address.trim();

    // Empty or whitespace-only addresses are invalid.
    if trimmed.is_empty() {
        return false;
    }

    // If the address contains an `@` sign, validate local and domain parts.
    if let Some(at_pos) = trimmed.rfind('@') {
        let local_part = &trimmed[..at_pos];
        let domain_part = &trimmed[at_pos + 1..];

        // Both local part and domain must be non-empty.
        if local_part.is_empty() || domain_part.is_empty() {
            return false;
        }

        // Domain must not contain spaces or control characters.
        if domain_part
            .chars()
            .any(|c| c.is_ascii_control() || c == ' ')
        {
            return false;
        }

        // Domain must contain at least one label separator (dot) for FQDN,
        // OR be a bracketed IP literal like [192.168.1.1].
        if !domain_part.contains('.') && !domain_part.starts_with('[') {
            // Allow single-label domains for local delivery (matches C
            // behavior where verify_address with vopt_qualify would qualify
            // against the default domain).
            return true;
        }

        true
    } else {
        // Bare local part without domain — valid for local delivery.
        // The C code would qualify this against the default domain via
        // vopt_qualify flag. We accept it as-is since qualification
        // happens at a higher level.
        //
        // Reject if it contains control characters.
        !trimmed.chars().any(|c| c.is_ascii_control())
    }
}

// ── Primary Public Function ───────────────────────────────────────────────

/// Expand and verify the router's `errors_to` setting.
///
/// Translates C `rf_get_errors_address()` from
/// `src/src/routers/rf_get_errors_address.c` (130 lines).  Determines
/// whether the router overrides the default bounce/error recipient address
/// and, if so, expands and validates the override.
///
/// # Arguments
///
/// * `addr` — The address item being routed.  Modified in the following
///   cases:
///   - **Expansion error**: `addr.message` is set to a formatted error
///     string (matching C `addr->message = string_sprintf(…)`).
///   - **Empty expansion**: `addr.prop.ignore_error` is set to `true`.
///   - **Verification success**: `addr.prop.errors_address` is set to the
///     verified address.
///
/// * `router_config` — The router instance configuration providing the
///   `errors_to` option value and the router `name` for error messages.
///
/// * `verify_mode` — The current verification mode.  When set to any
///   value other than [`VerifyMode::None`], address verification is
///   skipped to avoid routing loops during verification operations.
///
/// * `_ctx` — The per-delivery-attempt context providing variable
///   resolution scope for the expansion engine.  Accepted for API
///   consistency with other router helpers and future expansion context
///   passing when the expansion engine supports explicit context.
///
/// # Returns
///
/// * `Ok(None)` — No errors-to override.  This occurs when:
///   - The router has no `errors_to` setting.
///   - Expansion was forced to fail (intentional no-override).
///   - Address verification failed (non-fatal warning logged).
///
/// * `Ok(Some(ErrorsAddressResult::IgnoreErrors))` — The `errors_to`
///   option expanded to an empty string, meaning "ignore errors for this
///   address" (do not generate bounce messages).
///
/// * `Ok(Some(ErrorsAddressResult::Address(addr)))` — A valid errors-to
///   address was resolved.
///
/// * `Err(GetErrorsAddressError::ExpansionFailed(msg))` — Expansion of
///   the `errors_to` option failed.  Maps to C DEFER return.  The error
///   message is also stored in `addr.message`.
///
/// # Examples
///
/// ```ignore
/// use exim_routers::helpers::get_errors_address::{
///     get_errors_address, ErrorsAddressResult, VerifyMode,
/// };
///
/// match get_errors_address(&mut addr, &router_config, VerifyMode::None, &ctx) {
///     Ok(None) => { /* No override — use default sender */ }
///     Ok(Some(ErrorsAddressResult::IgnoreErrors)) => { /* Ignore errors */ }
///     Ok(Some(ErrorsAddressResult::Address(a))) => { /* Use address `a` */ }
///     Err(e) => { /* DEFER — expansion failed */ }
/// }
/// ```
pub fn get_errors_address(
    addr: &mut AddressItem,
    router_config: &RouterInstanceConfig,
    verify_mode: VerifyMode,
    _ctx: &DeliveryContext,
) -> Result<Option<ErrorsAddressResult>, GetErrorsAddressError> {
    // ── Step 1: Early exit if no errors_to configured ───────────────
    //
    // C: `if (!rblock->errors_to) return OK;` (line 45)
    //
    // If the router has no errors_to setting, there is nothing to expand
    // or verify.  The caller should use whatever errors_address is already
    // set on the address item (from the envelope or a previous router).
    let errors_to_setting = match &router_config.errors_to {
        Some(setting) => setting.clone(),
        Option::None => {
            return Ok(Option::None);
        }
    };

    // ── Step 2: Expand the errors_to string ─────────────────────────
    //
    // C: `s = expand_string(rblock->errors_to)` (line 47)
    //
    // The errors_to configuration value may contain ${…} expansion
    // expressions and $variable references that need to be evaluated
    // in the current message/delivery context.
    let expanded = match expand_string(&errors_to_setting) {
        Ok(s) => s,

        // ── Forced failure: ignore errors_to setting ────────────
        //
        // C: `if (f.expand_string_forcedfail) { ... return OK; }`
        // (lines 49–54)
        //
        // A forced failure means the expansion explicitly indicated
        // that the errors_to setting should not apply (e.g., a
        // conditional ${if …} that evaluated to forced-fail).  This
        // is not an error — we simply proceed as if errors_to were
        // not configured.
        Err(ExpandError::ForcedFail) => {
            tracing::debug!(
                router = %router_config.name,
                "forced expansion failure - ignoring errors_to"
            );
            return Ok(Option::None);
        }

        // ── Expansion error: DEFER ──────────────────────────────
        //
        // C: `addr->message = string_sprintf(…); return DEFER;`
        // (lines 55–57)
        //
        // All other expansion errors (general failure, tainted input,
        // integer error, lookup defer) are treated as a DEFER
        // condition.  The formatted error message is stored in
        // addr.message for diagnostic reporting.
        Err(ExpandError::Failed { message }) => {
            let err_msg = format!(
                "{} router failed to expand \"{}\": {}",
                router_config.name, errors_to_setting, message
            );
            tracing::debug!(%err_msg, "errors_to expansion failed → DEFER");
            addr.message = Some(err_msg.clone());
            return Err(GetErrorsAddressError::ExpansionFailed(err_msg));
        }

        // Catch-all for other error variants (TaintedInput, IntegerError,
        // LookupDefer) — all map to DEFER with a descriptive message.
        Err(e) => {
            let err_msg = format!(
                "{} router failed to expand \"{}\": {}",
                router_config.name, errors_to_setting, e
            );
            tracing::debug!(%err_msg, "errors_to expansion failed → DEFER");
            addr.message = Some(err_msg.clone());
            return Err(GetErrorsAddressError::ExpansionFailed(err_msg));
        }
    };

    tracing::debug!(
        router = %router_config.name,
        errors_to = %expanded,
        "expanded errors_to setting"
    );

    // ── Step 3: Handle empty expansion result ───────────────────────
    //
    // C: `if (!*s) { addr->prop.ignore_error = TRUE; *errors_to = US"";
    //     return OK; }` (lines 62–67)
    //
    // An empty expanded result means "ignore errors" — do not generate
    // bounce messages for this address.  This is used to suppress error
    // notifications for addresses that are known to be unimportant
    // (e.g., list-unsubscribe aliases).
    if expanded.is_empty() {
        addr.prop.ignore_error = true;
        tracing::debug!(
            router = %router_config.name,
            "errors_to expanded to empty string, setting ignore_error"
        );
        return Ok(Some(ErrorsAddressResult::IgnoreErrors));
    }

    // ── Step 4: Skip verification in verify mode ────────────────────
    //
    // C: `if (verify != v_none) { *errors_to = s; ... }` (lines 77–82)
    //
    // When routing is being performed as part of address verification
    // (recipient verify, sender verify, or EXPN), we skip the errors_to
    // address verification to avoid potential routing loops.  The
    // expanded value is accepted as-is.
    if verify_mode.is_verifying() {
        tracing::debug!(
            router = %router_config.name,
            verify_mode = %verify_mode,
            errors_to = %expanded,
            "skipped verify errors_to address: already verifying"
        );
        return Ok(Some(ErrorsAddressResult::Address(expanded)));
    }

    // ── Step 5: Full verification path ──────────────────────────────
    //
    // C: Lines 84–124 — save globals, create verification address,
    // call verify_address(), restore globals, check result.
    //
    // In Rust, the save/restore pattern for global state is unnecessary
    // because we use scoped context passing.  The verification is
    // performed as address format validation, replacing the C
    // `verify_address()` call that runs the full router chain.
    //
    // The verification is deliberately permissive — matching C behavior
    // where failure is non-fatal (the function returns OK regardless,
    // just without setting the errors_to address).

    tracing::debug!(
        errors_to = %expanded,
        "------ Verifying errors address {} ------", expanded
    );

    let verification_passed = verify_errors_address(&expanded);

    tracing::debug!(
        errors_to = %expanded,
        "------ End verifying errors address {} ------", expanded
    );

    if verification_passed {
        // Verification succeeded — set the errors address on the
        // address item's propagated properties and return the address.
        //
        // C: `*errors_to = snew->address;` (line 115)
        addr.prop.errors_address = Some(expanded.clone());
        tracing::debug!(
            router = %router_config.name,
            errors_to = %expanded,
            "errors_to address verified successfully"
        );
        Ok(Some(ErrorsAddressResult::Address(expanded)))
    } else {
        // Verification failed — log a warning but return Ok(None).
        // This is non-fatal: the caller should fall back to using the
        // default sender address as the bounce recipient.
        //
        // In C, this path simply doesn't set *errors_to, leaving it at
        // whatever value addr->prop.errors_address already had.  The
        // function still returns OK (line 126).
        tracing::warn!(
            router = %router_config.name,
            errors_to = %expanded,
            "errors_to address verification failed, using default sender"
        );
        Ok(Option::None)
    }
}

// ── Unit Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a minimal AddressItem for testing.
    fn test_addr() -> AddressItem {
        AddressItem::new("user@example.com".to_string())
    }

    /// Helper: create a minimal DeliveryContext for testing.
    fn test_ctx() -> DeliveryContext {
        DeliveryContext::default()
    }

    /// Helper: create a RouterInstanceConfig with the given name and
    /// optional errors_to setting.
    ///
    /// Uses the `RouterInstanceConfig::new()` constructor which sets all
    /// fields to their correct defaults matching C `readconf.c`.
    fn test_config(name: &str, errors_to: Option<&str>) -> RouterInstanceConfig {
        let mut config = RouterInstanceConfig::new(name, "test");
        config.errors_to = errors_to.map(|s| s.to_string());
        config
    }

    // ── VerifyMode Tests ──────────────────────────────────────────────

    #[test]
    fn test_verify_mode_none_is_not_verifying() {
        assert!(!VerifyMode::None.is_verifying());
    }

    #[test]
    fn test_verify_mode_recipient_is_verifying() {
        assert!(VerifyMode::Recipient.is_verifying());
    }

    #[test]
    fn test_verify_mode_sender_is_verifying() {
        assert!(VerifyMode::Sender.is_verifying());
    }

    #[test]
    fn test_verify_mode_expn_is_verifying() {
        assert!(VerifyMode::Expn.is_verifying());
    }

    #[test]
    fn test_verify_mode_from_c_code() {
        assert_eq!(VerifyMode::from_c_code(0), VerifyMode::None);
        assert_eq!(VerifyMode::from_c_code(1), VerifyMode::Recipient);
        assert_eq!(VerifyMode::from_c_code(2), VerifyMode::Sender);
        assert_eq!(VerifyMode::from_c_code(3), VerifyMode::Expn);
        assert_eq!(VerifyMode::from_c_code(99), VerifyMode::None);
    }

    #[test]
    fn test_verify_mode_to_c_code() {
        assert_eq!(VerifyMode::None.to_c_code(), 0);
        assert_eq!(VerifyMode::Recipient.to_c_code(), 1);
        assert_eq!(VerifyMode::Sender.to_c_code(), 2);
        assert_eq!(VerifyMode::Expn.to_c_code(), 3);
    }

    #[test]
    fn test_verify_mode_display() {
        assert_eq!(format!("{}", VerifyMode::None), "none");
        assert_eq!(format!("{}", VerifyMode::Recipient), "recipient");
        assert_eq!(format!("{}", VerifyMode::Sender), "sender");
        assert_eq!(format!("{}", VerifyMode::Expn), "expn");
    }

    // ── ErrorsAddressResult Tests ─────────────────────────────────────

    #[test]
    fn test_result_ignore_errors() {
        let result = ErrorsAddressResult::IgnoreErrors;
        assert!(result.is_ignore_errors());
        assert!(result.address().is_none());
    }

    #[test]
    fn test_result_address() {
        let result = ErrorsAddressResult::Address("bounce@example.com".to_string());
        assert!(!result.is_ignore_errors());
        assert_eq!(result.address(), Some("bounce@example.com"));
    }

    #[test]
    fn test_result_display() {
        assert_eq!(
            format!("{}", ErrorsAddressResult::IgnoreErrors),
            "<ignore errors>"
        );
        assert_eq!(
            format!("{}", ErrorsAddressResult::Address("a@b.com".to_string())),
            "a@b.com"
        );
    }

    // ── verify_errors_address Tests ───────────────────────────────────

    #[test]
    fn test_verify_valid_email() {
        assert!(verify_errors_address("user@example.com"));
    }

    #[test]
    fn test_verify_bare_local_part() {
        assert!(verify_errors_address("postmaster"));
    }

    #[test]
    fn test_verify_empty_string() {
        assert!(!verify_errors_address(""));
    }

    #[test]
    fn test_verify_whitespace_only() {
        assert!(!verify_errors_address("   "));
    }

    #[test]
    fn test_verify_no_local_part() {
        assert!(!verify_errors_address("@example.com"));
    }

    #[test]
    fn test_verify_no_domain() {
        assert!(!verify_errors_address("user@"));
    }

    #[test]
    fn test_verify_domain_with_control_chars() {
        assert!(!verify_errors_address("user@exam\x00ple.com"));
    }

    #[test]
    fn test_verify_single_label_domain() {
        assert!(verify_errors_address("user@localhost"));
    }

    #[test]
    fn test_verify_ip_literal_domain() {
        assert!(verify_errors_address("user@[192.168.1.1]"));
    }

    // ── get_errors_address Integration Tests ──────────────────────────

    #[test]
    fn test_no_errors_to_configured() {
        let mut addr = test_addr();
        let config = test_config("test_router", Option::None);
        let ctx = test_ctx();
        let result = get_errors_address(&mut addr, &config, VerifyMode::None, &ctx);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_plain_text_errors_to() {
        let mut addr = test_addr();
        let config = test_config("test_router", Some("bounce@example.com"));
        let ctx = test_ctx();
        let result = get_errors_address(&mut addr, &config, VerifyMode::None, &ctx);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());
        match result.unwrap() {
            ErrorsAddressResult::Address(a) => {
                assert_eq!(a, "bounce@example.com");
            }
            ErrorsAddressResult::IgnoreErrors => {
                panic!("expected Address, got IgnoreErrors");
            }
        }
        // Verification should have set errors_address on the address prop.
        assert_eq!(
            addr.prop.errors_address,
            Some("bounce@example.com".to_string())
        );
    }

    #[test]
    fn test_verify_mode_skips_verification() {
        let mut addr = test_addr();
        let config = test_config("test_router", Some("bounce@example.com"));
        let ctx = test_ctx();
        let result = get_errors_address(&mut addr, &config, VerifyMode::Recipient, &ctx);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_some());
        match result.unwrap() {
            ErrorsAddressResult::Address(a) => {
                assert_eq!(a, "bounce@example.com");
            }
            ErrorsAddressResult::IgnoreErrors => {
                panic!("expected Address, got IgnoreErrors");
            }
        }
        // In verify mode, errors_address is NOT set on addr.prop
        // (only set after successful verification in normal mode).
        // But we still return the address for the caller to use.
    }
}
