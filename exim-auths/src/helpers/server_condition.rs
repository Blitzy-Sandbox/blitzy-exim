// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! Server condition evaluation for authenticator authorization.
//!
//! This module is the Rust rewrite of `src/src/auths/check_serv_cond.c`
//! (126 lines). It provides [`auth_check_serv_cond`] and
//! [`auth_check_some_cond`], which are called by **all** authenticator
//! drivers to evaluate authorization conditions after the SASL exchange
//! completes.
//!
//! # Condition Evaluation Flow
//!
//! 1. If no condition is configured (`None`), the caller-supplied
//!    `unset` default is returned.
//! 2. The condition string is passed through the Exim string expansion
//!    engine ([`exim_expand::expand_string`]).
//! 3. A forced expansion failure (`ExpandError::ForcedFail`) causes an
//!    immediate authentication **failure** (`Fail`).
//! 4. Any other expansion error causes a **deferral** (`Defer`), signalling
//!    a temporary server-side problem.
//! 5. The expanded result is interpreted:
//!    - Empty `""`, `"0"`, `"no"` (any case), `"false"` (any case) →
//!      **`Fail`**
//!    - `"1"`, `"yes"` (any case), `"true"` (any case) → **`Ok`**
//!    - Any other non-empty string → **`Defer`** with the string as
//!      the error message.
//!
//! # Safety
//!
//! This module contains **zero `unsafe` blocks** (per AAP §0.7.2).

use exim_drivers::auth_driver::AuthInstanceConfig;
use exim_expand::{expand_string, ExpandError};

// =============================================================================
// AuthConditionResult enum
// =============================================================================

/// Result of evaluating an authentication authorization condition.
///
/// This enum replaces the C return codes (`OK`, `FAIL`, `DEFER`) from
/// `auth_check_some_cond()` in `check_serv_cond.c`. The `Defer` variant
/// carries the two message fields that the C code stored in the global
/// variables `auth_defer_msg` and `auth_defer_user_msg`.
///
/// # C-to-Rust Mapping
///
/// | C Return | Rust Variant | Meaning |
/// |----------|-------------|---------|
/// | `OK` | [`Ok`](Self::Ok) | Authorization succeeded |
/// | `FAIL` | [`Fail`](Self::Fail) | Authorization failed |
/// | `DEFER` | [`Defer`](Self::Defer) | Temporary failure; try again later |
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthConditionResult {
    /// Authentication/authorization succeeded.
    ///
    /// Corresponds to the C `OK` return value. The SMTP server proceeds
    /// with the authenticated session.
    Ok,

    /// Authentication/authorization failed.
    ///
    /// Corresponds to the C `FAIL` return value. The SMTP server rejects
    /// the authentication attempt. This is returned when:
    /// - The expanded condition is empty, `"0"`, `"no"`, or `"false"`
    /// - The expansion engine signalled a forced failure
    Fail,

    /// Temporary failure — the check could not be completed.
    ///
    /// Corresponds to the C `DEFER` return value. The SMTP server returns
    /// a temporary error code (`454`) to the client, indicating that the
    /// authentication should be retried later.
    ///
    /// In the C code, the two message fields were stored in the global
    /// variables `auth_defer_msg` and `auth_defer_user_msg`. In Rust,
    /// they are returned as part of this variant.
    Defer {
        /// Internal error text for logging.
        ///
        /// Replaces the C global `auth_defer_msg`. Set to the expansion
        /// error message (on expansion failure) or the unexpected expanded
        /// string value (on unrecognised condition result).
        msg: String,

        /// User-visible text appended to the SMTP error response.
        ///
        /// Replaces the C global `auth_defer_user_msg`. Format: `": {value}"`.
        /// `None` when the deferral is due to an expansion error (only set
        /// when the expanded result is an unrecognised string).
        user_msg: Option<String>,
    },
}

// =============================================================================
// auth_check_serv_cond — Thin wrapper for server_condition evaluation
// =============================================================================

/// Check the `server_condition` for an authenticator instance.
///
/// This is the primary entry point called by **all 9 authenticator drivers**
/// after their protocol-specific authentication exchange completes. It
/// delegates to [`auth_check_some_cond`] with:
///
/// - `label = "server_condition"` (for debug logging)
/// - `condition = ablock.server_condition` (the configured condition)
/// - `unset = AuthConditionResult::Ok` (if no condition is set,
///   authentication succeeds by default)
///
/// # Replaces
///
/// C function `auth_check_serv_cond(auth_instance *ablock)` at
/// `check_serv_cond.c` lines 34–39.
///
/// # Arguments
///
/// * `ablock` — The authenticator instance configuration containing
///   `server_condition`, `name`, and `server_debug_string`.
///
/// # Returns
///
/// - [`AuthConditionResult::Ok`] — Condition passed or was unset.
/// - [`AuthConditionResult::Fail`] — Condition evaluated to a falsy value
///   or expansion was forced to fail.
/// - [`AuthConditionResult::Defer`] — Expansion error or unrecognised
///   result string.
pub fn auth_check_serv_cond(ablock: &AuthInstanceConfig) -> AuthConditionResult {
    auth_check_some_cond(
        ablock,
        "server_condition",
        ablock.server_condition.as_deref(),
        AuthConditionResult::Ok,
    )
}

// =============================================================================
// auth_check_some_cond — Core condition evaluation logic
// =============================================================================

/// Evaluate a generic condition string for authentication authorization.
///
/// This is the core evaluation engine underlying [`auth_check_serv_cond`].
/// It is also used directly by some authenticator drivers for additional
/// generic condition checks beyond `server_condition`.
///
/// # Replaces
///
/// C function `auth_check_some_cond(auth_instance *ablock, uschar *label,
/// uschar *condition, int unset)` at `check_serv_cond.c` lines 61–124.
///
/// # Arguments
///
/// * `ablock`    — The authenticator instance configuration (provides the
///   driver name and optional debug string).
/// * `label`     — A descriptive label for debug logging (e.g.,
///   `"server_condition"`).
/// * `condition` — The condition string to expand and evaluate.
///   `None` means the condition was not configured.
/// * `unset`     — The value to return when `condition` is `None`. For
///   `server_condition`, this is typically `AuthConditionResult::Ok`
///   (unset condition lets everything through). For other uses, callers
///   may pass `AuthConditionResult::Fail`.
///
/// # Evaluation Flow
///
/// 1. Debug-log the authenticator name and label.
/// 2. If `condition` is `None` → return `unset`.
/// 3. Expand the condition string via [`expand_string`].
/// 4. On expansion failure:
///    - Forced failure (`ExpandError::ForcedFail`) → `Fail`
///    - Other errors → `Defer { msg: error_message, user_msg: None }`
/// 5. Interpret the expanded result:
///    - `""` | `"0"` | `"no"` (ci) | `"false"` (ci) → `Fail`
///    - `"1"` | `"yes"` (ci) | `"true"` (ci) → `Ok`
///    - Anything else → `Defer { msg: value, user_msg: Some(": value") }`
///
/// # Returns
///
/// An [`AuthConditionResult`] indicating the authorization outcome.
pub fn auth_check_some_cond(
    ablock: &AuthInstanceConfig,
    label: &str,
    condition: Option<&str>,
    unset: AuthConditionResult,
) -> AuthConditionResult {
    // ── Debug output ────────────────────────────────────────────────
    //
    // Replaces the C `HDEBUG(D_auth)` block at check_serv_cond.c lines 67–75.
    //
    // In the C code, this block also printed `auth_vars[0..AUTH_VARS-1]`
    // and `expand_nstring[1..expand_nmax]`, which are global variables set
    // by the authenticator driver's regex/match operations. In the Rust
    // rewrite, those variables are part of the expansion context and are
    // logged by the calling authenticator driver or the expansion engine
    // itself. Here we log the fields directly available through the
    // `AuthInstanceConfig` parameter.
    tracing::debug!(
        authenticator = %ablock.name,
        label = %label,
        "{} authenticator {}:",
        ablock.name,
        label,
    );

    // Log the custom server debug string if configured.
    // Replaces C `debug_print_string(ablock->server_debug_string)` at
    // check_serv_cond.c line 74. In the C code, `debug_print_string()`
    // expands the string before printing; here we expand it and log
    // the result.
    if let Some(ref debug_str) = ablock.server_debug_string {
        match expand_string(debug_str) {
            Result::Ok(expanded_debug) => {
                tracing::debug!(
                    server_debug_string = %expanded_debug,
                    "custom debug: {}",
                    expanded_debug,
                );
            }
            Err(err) => {
                tracing::debug!(
                    error = %err,
                    "server_debug_string expansion failed: {}",
                    err,
                );
            }
        }
    }

    // ── NULL condition handling ──────────────────────────────────────
    //
    // Replaces check_serv_cond.c line 85: `if (!condition) return unset;`
    //
    // For the `auth_check_serv_cond()` wrapper, `unset` is `Ok`, meaning
    // an unset `server_condition` lets authentication succeed (the
    // protocol-specific exchange was already successful). Plaintext and
    // GSASL authenticators always have `server_condition` set because it
    // is required to enable server-side operation for those drivers.
    let condition_str = match condition {
        Some(c) => c,
        None => return unset,
    };

    // ── Condition expansion ─────────────────────────────────────────
    //
    // Replaces check_serv_cond.c line 86: `cond = expand_string(condition);`
    //
    // The expansion engine processes `${…}` expressions, variable
    // substitutions, and all Exim string expansion DSL constructs.
    let cond = match expand_string(condition_str) {
        Result::Ok(expanded) => {
            // Replaces the success branch of the debug output at
            // check_serv_cond.c line 92: `debug_printf("expanded string: %s\n", cond);`
            tracing::debug!(
                expanded = %expanded,
                "expanded string: {}",
                expanded,
            );
            expanded
        }
        Err(ExpandError::ForcedFail) => {
            // Replaces check_serv_cond.c line 101:
            //   `if (f.expand_string_forcedfail) return FAIL;`
            //
            // A forced expansion failure (`${if …{fail}}` or similar) is
            // a deliberate signal that authentication should fail. This is
            // NOT a temporary error — it's an explicit rejection.
            tracing::debug!("expansion failed: forced failure");
            return AuthConditionResult::Fail;
        }
        Err(ExpandError::Failed { ref message }) => {
            // Replaces check_serv_cond.c lines 89–90, 102–103:
            //   `debug_printf("expansion failed: %s\n", expand_string_message);`
            //   `auth_defer_msg = expand_string_message; return DEFER;`
            //
            // Non-forced expansion failures indicate a server-side problem
            // (configuration error, lookup failure, etc.). The client should
            // retry later, so we return `Defer`.
            tracing::debug!(
                error = %message,
                "expansion failed: {}",
                message,
            );
            return AuthConditionResult::Defer {
                msg: message.clone(),
                user_msg: None,
            };
        }
        Err(other_err) => {
            // Handle all other ExpandError variants (TaintedInput,
            // IntegerError, LookupDefer) as generic expansion failures.
            // These all result in a deferral.
            let msg: String = other_err.to_string();
            tracing::debug!(
                error = %msg,
                "expansion failed: {}",
                msg,
            );
            return AuthConditionResult::Defer {
                msg,
                user_msg: None,
            };
        }
    };

    // ── Result interpretation ───────────────────────────────────────
    //
    // Replaces check_serv_cond.c lines 110–123.
    //
    // The expanded string is evaluated as a boolean-like value with the
    // following semantics:
    //
    // - Empty `""`, `"0"`, `"no"` (case-insensitive), `"false"`
    //   (case-insensitive) → FAIL (authentication denied)
    // - `"1"`, `"yes"` (case-insensitive), `"true"` (case-insensitive)
    //   → OK (authentication approved)
    // - Any other non-empty string → DEFER (treated as an error message)
    //
    // IMPORTANT: Empty string returns FAIL, not OK. This is a critical
    // edge case from C line 110: `if (*cond == 0 || …) return FAIL;`
    interpret_condition_result(&cond)
}

// =============================================================================
// Private helper — condition result interpretation
// =============================================================================

/// Interpret an expanded condition string as an [`AuthConditionResult`].
///
/// This pure function contains the boolean-like interpretation logic that
/// maps expanded strings to authorization outcomes, extracted from
/// [`auth_check_some_cond`] for clarity and testability.
///
/// # Rules (from check_serv_cond.c lines 110–123)
///
/// | Expanded Value | Result | C Line |
/// |---------------|--------|--------|
/// | `""` (empty)  | `Fail` | 110 |
/// | `"0"`         | `Fail` | 111 |
/// | `"no"` (ci)   | `Fail` | 112 |
/// | `"false"` (ci) | `Fail` | 113 |
/// | `"1"`         | `Ok`   | 116 |
/// | `"yes"` (ci)  | `Ok`   | 117 |
/// | `"true"` (ci) | `Ok`   | 118 |
/// | anything else | `Defer` | 121–123 |
///
/// Case-insensitive comparisons use [`str::eq_ignore_ascii_case`],
/// matching the C `strcmpic()` behaviour.
fn interpret_condition_result(cond: &str) -> AuthConditionResult {
    // Falsy values → FAIL
    //
    // C lines 110–114:
    //   if (*cond == 0 ||
    //       Ustrcmp(cond, "0") == 0 ||
    //       strcmpic(cond, US"no") == 0 ||
    //       strcmpic(cond, US"false") == 0)
    //     return FAIL;
    if cond.is_empty()
        || cond == "0"
        || cond.eq_ignore_ascii_case("no")
        || cond.eq_ignore_ascii_case("false")
    {
        return AuthConditionResult::Fail;
    }

    // Truthy values → OK
    //
    // C lines 116–119:
    //   if (Ustrcmp(cond, "1") == 0 ||
    //       strcmpic(cond, US"yes") == 0 ||
    //       strcmpic(cond, US"true") == 0)
    //     return OK;
    if cond == "1" || cond.eq_ignore_ascii_case("yes") || cond.eq_ignore_ascii_case("true") {
        return AuthConditionResult::Ok;
    }

    // Unrecognised value → DEFER with the value as an error message
    //
    // C lines 121–123:
    //   auth_defer_msg = cond;
    //   auth_defer_user_msg = string_sprintf(": %s", cond);
    //   return DEFER;
    //
    // The condition expanded to a string that is neither a recognised
    // truthy value nor a recognised falsy value. This typically indicates
    // a misconfiguration where the condition evaluates to an error message
    // or diagnostic text rather than a boolean decision.
    AuthConditionResult::Defer {
        msg: cond.to_owned(),
        user_msg: Some(format!(": {}", cond)),
    }
}

// =============================================================================
// Unit tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── interpret_condition_result tests ─────────────────────────────

    #[test]
    fn empty_string_returns_fail() {
        assert_eq!(interpret_condition_result(""), AuthConditionResult::Fail);
    }

    #[test]
    fn zero_returns_fail() {
        assert_eq!(interpret_condition_result("0"), AuthConditionResult::Fail);
    }

    #[test]
    fn no_lowercase_returns_fail() {
        assert_eq!(interpret_condition_result("no"), AuthConditionResult::Fail);
    }

    #[test]
    fn no_uppercase_returns_fail() {
        assert_eq!(interpret_condition_result("NO"), AuthConditionResult::Fail);
    }

    #[test]
    fn no_mixed_case_returns_fail() {
        assert_eq!(interpret_condition_result("No"), AuthConditionResult::Fail);
        assert_eq!(interpret_condition_result("nO"), AuthConditionResult::Fail);
    }

    #[test]
    fn false_lowercase_returns_fail() {
        assert_eq!(
            interpret_condition_result("false"),
            AuthConditionResult::Fail
        );
    }

    #[test]
    fn false_uppercase_returns_fail() {
        assert_eq!(
            interpret_condition_result("FALSE"),
            AuthConditionResult::Fail
        );
    }

    #[test]
    fn false_mixed_case_returns_fail() {
        assert_eq!(
            interpret_condition_result("False"),
            AuthConditionResult::Fail
        );
        assert_eq!(
            interpret_condition_result("fAlSe"),
            AuthConditionResult::Fail
        );
    }

    #[test]
    fn one_returns_ok() {
        assert_eq!(interpret_condition_result("1"), AuthConditionResult::Ok);
    }

    #[test]
    fn yes_lowercase_returns_ok() {
        assert_eq!(interpret_condition_result("yes"), AuthConditionResult::Ok);
    }

    #[test]
    fn yes_uppercase_returns_ok() {
        assert_eq!(interpret_condition_result("YES"), AuthConditionResult::Ok);
    }

    #[test]
    fn yes_mixed_case_returns_ok() {
        assert_eq!(interpret_condition_result("Yes"), AuthConditionResult::Ok);
        assert_eq!(interpret_condition_result("yEs"), AuthConditionResult::Ok);
    }

    #[test]
    fn true_lowercase_returns_ok() {
        assert_eq!(interpret_condition_result("true"), AuthConditionResult::Ok);
    }

    #[test]
    fn true_uppercase_returns_ok() {
        assert_eq!(interpret_condition_result("TRUE"), AuthConditionResult::Ok);
    }

    #[test]
    fn true_mixed_case_returns_ok() {
        assert_eq!(interpret_condition_result("True"), AuthConditionResult::Ok);
        assert_eq!(interpret_condition_result("tRuE"), AuthConditionResult::Ok);
    }

    #[test]
    fn unrecognised_string_returns_defer() {
        let result = interpret_condition_result("some error message");
        match result {
            AuthConditionResult::Defer {
                ref msg,
                ref user_msg,
            } => {
                assert_eq!(msg, "some error message");
                assert_eq!(user_msg.as_deref(), Some(": some error message"));
            }
            other => panic!("expected Defer, got {:?}", other),
        }
    }

    #[test]
    fn numeric_non_zero_non_one_returns_defer() {
        let result = interpret_condition_result("2");
        match result {
            AuthConditionResult::Defer {
                ref msg,
                ref user_msg,
            } => {
                assert_eq!(msg, "2");
                assert_eq!(user_msg.as_deref(), Some(": 2"));
            }
            other => panic!("expected Defer, got {:?}", other),
        }
    }

    #[test]
    fn negative_one_returns_defer() {
        let result = interpret_condition_result("-1");
        assert!(matches!(result, AuthConditionResult::Defer { .. }));
    }

    // ── auth_check_some_cond with None condition ────────────────────

    #[test]
    fn none_condition_returns_unset_ok() {
        let ablock = make_test_config("test_auth");
        let result =
            auth_check_some_cond(&ablock, "server_condition", None, AuthConditionResult::Ok);
        assert_eq!(result, AuthConditionResult::Ok);
    }

    #[test]
    fn none_condition_returns_unset_fail() {
        let ablock = make_test_config("test_auth");
        let result =
            auth_check_some_cond(&ablock, "other_condition", None, AuthConditionResult::Fail);
        assert_eq!(result, AuthConditionResult::Fail);
    }

    // ── Helper to build test AuthInstanceConfig ─────────────────────

    fn make_test_config(name: &str) -> AuthInstanceConfig {
        AuthInstanceConfig::new(name, "test_driver", "TEST", Box::new(()))
    }
}
