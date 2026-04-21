// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! String expansion wrapper for router drivers.
//!
//! Translates **`src/src/routers/rf_expand_data.c`** (51 lines) into Rust.
//!
//! ## Overview
//!
//! This is a thin wrapper around [`exim_expand::expand_string()`] that maps
//! the expansion result into a three-way return value suitable for router
//! driver use:
//!
//! | Expansion outcome | C return | Rust return |
//! |---|---|---|
//! | Success (expanded string) | `*result = expanded; return OK` | `Ok(Some(expanded))` |
//! | Forced failure (`${if false:…{fail}}`) | `*prc = DECLINE; return NULL` | `Ok(None)` |
//! | Expansion error | `addr->message = …; *prc = DEFER; return NULL` | `Err(ExpandDataError::ExpansionFailed(…))` |
//!
//! ## C Source Correspondence
//!
//! | C construct | Rust equivalent |
//! |---|---|
//! | `expand_string(s)` | [`exim_expand::expand_string(s)`] |
//! | `f.expand_string_forcedfail` | [`ExpandError::ForcedFail`] variant |
//! | `expand_string_message` | [`ExpandError::Failed { message }`] inner field |
//! | `addr->message = string_sprintf(…)` | `addr.message = Some(format!(…))` |
//! | `*prc = DECLINE` | `Ok(None)` |
//! | `*prc = DEFER` | `Err(ExpandDataError::ExpansionFailed(…))` |
//! | `return yield` / `return NULL` | `Ok(Some(…))` / `Ok(None)` or `Err(…)` |
//! | `DEBUG(D_route) debug_printf(…)` | `tracing::debug!(…)` |
//!
//! ## Safety
//!
//! This module contains **zero `unsafe` code** (per AAP §0.7.2).

// ── Imports ────────────────────────────────────────────────────────────────

use exim_expand::{expand_string, ExpandError};

// Import local types from change_domain (circular dependency avoidance).
//
// The canonical `AddressItem` and `DeliveryContext` live in
// `exim-core/src/context.rs`, but `exim-core` depends on `exim-routers`,
// so importing from `exim-core` would create a circular dependency.
// We re-use the local type definitions from `change_domain` which mirror
// the fields needed by router helpers.
use super::change_domain::{AddressItem, DeliveryContext};

// ── Error Type ─────────────────────────────────────────────────────────────

/// Error returned when string expansion fails during router option processing.
///
/// This maps to the C `DEFER` return code from `rf_expand_data()`.
/// The single variant carries the formatted error message that has already
/// been stored in `addr.message` before the error is returned, matching the
/// C pattern where `addr->message` is set before returning `DEFER`.
///
/// # Router Result Mapping
///
/// Callers should map this error to a router DEFER result, indicating a
/// temporary failure that should be retried later.
#[derive(Debug, thiserror::Error)]
pub enum ExpandDataError {
    /// String expansion failed with a descriptive error message.
    ///
    /// The contained string has the format:
    /// `failed to expand "<input>": <reason>`
    ///
    /// This matches the C `string_sprintf("failed to expand %q: %s", …)`
    /// from `rf_expand_data.c` line 43–44.
    #[error("{0}")]
    ExpansionFailed(String),
}

// ── Public API ─────────────────────────────────────────────────────────────

/// Expand a configuration string value and map errors to router result codes.
///
/// This is a thin wrapper around [`exim_expand::expand_string()`] that
/// translates the expansion result into a three-way return suitable for
/// router driver use.  It replaces the C `rf_expand_data()` function from
/// `src/src/routers/rf_expand_data.c`.
///
/// # Arguments
///
/// * `addr` — The address item being routed.  On expansion error, its
///   `message` field is set to a formatted error string (matching the C
///   behavior of `addr->message = string_sprintf(…)`).
/// * `s` — The string to expand.  May contain `${…}` expressions,
///   `$variable` references, and backslash escapes.
/// * `_ctx` — The per-delivery-attempt context providing variable resolution
///   scope.  Currently unused because [`expand_string()`] resolves variables
///   through a separate mechanism, but accepted in the signature for API
///   consistency with other router helpers and future expansion.
///
/// # Returns
///
/// * `Ok(Some(expanded))` — Expansion succeeded; the expanded string is
///   returned.  Callers should use the value and proceed (maps to C `OK`).
/// * `Ok(None)` — Expansion encountered a forced failure (e.g., `${if …}`
///   that resolved to `{fail}`).  Callers should treat this as a **DECLINE**
///   and pass the address to the next router.
/// * `Err(ExpandDataError::ExpansionFailed(msg))` — Expansion failed with
///   an error.  The error message has been stored in `addr.message`.  Callers
///   should treat this as a **DEFER** (temporary failure, retry later).
///
/// # Examples
///
/// ```ignore
/// use exim_routers::helpers::expand_data::{expand_data, ExpandDataError};
///
/// let result = expand_data(&mut addr, "${lookup{key}lsearch{file}}", &ctx);
/// match result {
///     Ok(Some(value)) => { /* use expanded value */ }
///     Ok(None)        => { /* DECLINE — pass to next router */ }
///     Err(_)          => { /* DEFER — temporary failure */ }
/// }
/// ```
pub fn expand_data(
    addr: &mut AddressItem,
    s: &str,
    _ctx: &DeliveryContext,
) -> Result<Option<String>, ExpandDataError> {
    match expand_string(s) {
        // ── Success: expansion produced a result string ──────────────
        Ok(expanded) => {
            tracing::debug!(input = %s, result = %expanded, "expansion succeeded");
            Ok(Some(expanded))
        }

        // ── Forced failure: expansion explicitly declined ───────────
        //
        // This occurs when the expansion encounters a construct like
        // `${if false:{fail}}` that signals intentional non-expansion.
        // In C, this sets `f.expand_string_forcedfail = TRUE` and the
        // caller receives DECLINE.
        Err(ExpandError::ForcedFail) => {
            tracing::debug!(input = %s, "expansion forced failure → DECLINE");
            Ok(None)
        }

        // ── Expansion error: set addr.message and return DEFER ──────
        //
        // All other error variants (Failed, TaintedInput, IntegerError,
        // LookupDefer) are treated as expansion errors.  The formatted
        // error message is stored in addr.message before returning,
        // matching the C pattern at rf_expand_data.c lines 43–45:
        //
        //   addr->message = string_sprintf(
        //       "failed to expand %q: %s", s, expand_string_message);
        //   *prc = DEFER;
        Err(e) => {
            // Extract the raw error detail, avoiding double-wrapping
            // the "expansion failed:" prefix from ExpandError::Failed's
            // Display implementation.
            let err_detail = match e {
                ExpandError::Failed { message } => message,
                other => other.to_string(),
            };
            let message = format!("failed to expand \"{}\": {}", s, err_detail);
            tracing::debug!(%message, "expansion error → DEFER");
            addr.message = Some(message.clone());
            Err(ExpandDataError::ExpansionFailed(message))
        }
    }
}

// ── Unit Tests ─────────────────────────────────────────────────────────────

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

    #[test]
    fn test_expand_data_success_plain_text() {
        // Plain text without any expansion operators should pass through.
        let mut addr = test_addr();
        let ctx = test_ctx();
        let result = expand_data(&mut addr, "plain text", &ctx);
        assert!(result.is_ok());
        let value = result.unwrap();
        assert!(value.is_some());
        assert_eq!(value.unwrap(), "plain text");
        // addr.message should remain None on success.
        assert!(addr.message.is_none());
    }

    #[test]
    fn test_expand_data_success_empty_string() {
        let mut addr = test_addr();
        let ctx = test_ctx();
        let result = expand_data(&mut addr, "", &ctx);
        assert!(result.is_ok());
        let value = result.unwrap();
        assert!(value.is_some());
        assert_eq!(value.unwrap(), "");
        assert!(addr.message.is_none());
    }

    #[test]
    fn test_expand_data_error_type_display() {
        let err = ExpandDataError::ExpansionFailed("test error".to_string());
        assert_eq!(err.to_string(), "test error");
    }

    #[test]
    fn test_expand_data_error_is_std_error() {
        let err = ExpandDataError::ExpansionFailed("test".to_string());
        // Verify it implements std::error::Error (via thiserror).
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn test_expand_data_error_debug_format() {
        let err = ExpandDataError::ExpansionFailed("debug test".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("ExpansionFailed"));
        assert!(debug_str.contains("debug test"));
    }
}
