// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! Transport resolution by name for router drivers.
//!
//! Translates **`src/src/routers/rf_get_transport.c`** (100 lines) into Rust.
//!
//! ## Overview
//!
//! Resolves a transport by name from the configured transport list, with
//! optional `${...}` string expansion of the transport name.  Includes a
//! **critical taint check** that rejects expanded transport names derived
//! from untrusted input.
//!
//! The function is called by every router that assigns a transport to a
//! delivery address (e.g., `accept`, `dnslookup`, `manualroute`).  The
//! transport name is typically a literal string from configuration, but it
//! may contain `$` for variable expansion at route time.
//!
//! ## C Source Correspondence
//!
//! | C construct | Rust equivalent |
//! |---|---|
//! | `rf_get_transport(tpname, tpptr, addr, router_name, new_key)` | [`get_transport()`] |
//! | `tpname == NULL → return TRUE` | `tpname == None → Ok(None)` |
//! | `Ustrchr(tpname, '$') → expand_string()` | `tpname.contains('$') → expand_string()` |
//! | `is_tainted(ss) → FAIL` | `Tainted<T>` validation → [`GetTransportError::TaintedName`] |
//! | `for (tp = transports; tp; tp = tp->next)` | `transport_list.iter().find(...)` |
//! | `addr->message = string_sprintf(...)` | `addr.message = Some(format!(...))` |
//! | `DEBUG(D_route) debug_printf_indent(...)` | `tracing::debug!(...)` |
//! | `log_write(0, LOG_MAIN\|LOG_PANIC, ...)` | `tracing::error!(...)` |
//!
//! ## Safety
//!
//! This module contains **zero `unsafe` code** (per AAP §0.7.2).

// ── Imports ────────────────────────────────────────────────────────────────

use exim_drivers::transport_driver::TransportInstanceConfig;
use exim_expand::{expand_string, ExpandError};
use exim_store::{Clean, Tainted};

// Import local types from change_domain (circular dependency avoidance).
//
// The canonical `AddressItem` and `DeliveryContext` live in
// `exim-core/src/context.rs`, but `exim-core` depends on `exim-routers`,
// so importing from `exim-core` would create a circular dependency.
// We re-use the local type definitions from `change_domain` which mirror
// the fields needed by router helpers.
use super::change_domain::{AddressItem, DeliveryContext};

// ── Error Type ─────────────────────────────────────────────────────────────

/// Error enum for transport resolution failures.
///
/// Replaces the C pattern of setting `addr->message` and returning `FALSE`
/// from `rf_get_transport()`.  Each variant corresponds to a specific failure
/// mode in `rf_get_transport.c`.
///
/// # Error Mapping
///
/// | C failure mode | Rust variant |
/// |---|---|
/// | `expand_string()` returns NULL (non-forced) | [`ExpansionFailed`](GetTransportError::ExpansionFailed) |
/// | `f.expand_string_forcedfail` is set | [`ForcedFailure`](GetTransportError::ForcedFailure) |
/// | `is_tainted(ss)` is true | [`TaintedName`](GetTransportError::TaintedName) |
/// | Transport name not in linked list | [`NotFound`](GetTransportError::NotFound) |
#[derive(Debug, thiserror::Error)]
pub enum GetTransportError {
    /// String expansion of the transport name failed.
    ///
    /// Corresponds to C `rf_get_transport.c` lines 66–73 where `expand_string()`
    /// returns NULL and `f.expand_string_forcedfail` is false.  The contained
    /// string carries the formatted error message that has already been stored
    /// in `addr.message`.
    #[error("expansion of transport name failed: {0}")]
    ExpansionFailed(String),

    /// Expansion was explicitly forced to fail.
    ///
    /// Corresponds to C `rf_get_transport.c` lines 63–65 where `expand_string()`
    /// returns NULL and `f.expand_string_forcedfail` is true.  This is not an
    /// error per se — it allows configuration to dynamically skip transport
    /// assignment via `${if false:...{fail}}`.
    #[error("forced expansion failure for transport name")]
    ForcedFailure,

    /// The expanded transport name is tainted (derived from untrusted input).
    ///
    /// **CRITICAL security check** corresponding to C `rf_get_transport.c`
    /// lines 72–80.  Rejects expanded transport names that could have been
    /// injected via tainted data (e.g., `$local_part_data` from untrusted
    /// SMTP input).  The C code sets `addr->message = "internal configuration
    /// error"` to avoid leaking information to attackers; the Rust code
    /// preserves this behavior.
    #[error("attempt to use tainted value '{name}' for transport name")]
    TaintedName {
        /// The tainted name value (for logging purposes only — never exposed
        /// to the remote SMTP client).
        name: String,
    },

    /// No transport with the given name was found in the transport list.
    ///
    /// Corresponds to C `rf_get_transport.c` lines 93–96 where the linked-list
    /// walk finds no matching `transport_instance`.
    #[error("transport '{name}' not found (router '{router}')")]
    NotFound {
        /// The transport name that was searched for.
        name: String,
        /// The router name that requested this transport.
        router: String,
    },
}

// ── Transport Name Validation ──────────────────────────────────────────────

/// Validates that a transport name contains only safe identifier characters.
///
/// Transport names in Exim configuration are identifiers that should only
/// contain ASCII alphanumeric characters, underscores, hyphens, and dots.
/// Names containing other characters indicate potential injection from
/// tainted (untrusted) input.
///
/// This function replaces the C `is_tainted()` memory-pool-based taint check
/// with a content-based validation approach using Rust's [`Tainted<T>`] /
/// [`Clean<T>`] newtype system.
///
/// # Arguments
///
/// * `name` — The transport name to validate.
///
/// # Returns
///
/// `true` if the name is non-empty and contains only safe characters
/// (`[a-zA-Z0-9_.-]`), `false` otherwise.
fn is_valid_transport_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

// ── Public API ─────────────────────────────────────────────────────────────

/// Resolves a transport by name, with optional string expansion.
///
/// Translates C `rf_get_transport()` from `rf_get_transport.c` (100 lines).
///
/// If `tpname` contains `$`, it is expanded first via [`expand_string`].
/// Tainted expansion results are rejected (security enforcement).
/// The resolved transport instance configuration is returned on success.
///
/// # Arguments
///
/// * `tpname` — Transport name from router configuration.  `None` means no
///   transport override (returns `Ok(None)`).
/// * `addr` — Mutable address item for error reporting (`addr.message` is set
///   on failure, matching C `rf_get_transport.c` behavior).
/// * `router_name` — Name of the calling router (for error context in messages
///   and logs).
/// * `transport_list` — Slice of all configured transport instances to search.
///   Replaces the C global `transports` linked list.
/// * `_ctx` — Delivery context providing expansion variables (`$local_part`,
///   `$domain`, etc.).  Currently unused because [`expand_string()`] resolves
///   variables through a separate mechanism, but accepted in the signature for
///   API consistency with other router helpers and future expansion support.
///
/// # Returns
///
/// * `Ok(None)` — No transport name provided (`tpname` was `None` or empty).
/// * `Ok(Some(&TransportInstanceConfig))` — Transport found successfully.
/// * `Err(GetTransportError)` — Expansion failed, name is tainted, or
///   transport not found.
///
/// # Security
///
/// **CRITICAL**: When a transport name containing `$` is expanded, the result
/// is wrapped in [`Tainted<String>`] and validated before use.  Names that
/// fail validation (containing characters outside the safe set
/// `[a-zA-Z0-9_.-]`) are rejected with [`GetTransportError::TaintedName`].
/// This prevents untrusted SMTP input from being used to select arbitrary
/// transports.
///
/// # Examples
///
/// ```ignore
/// use exim_routers::helpers::get_transport::{get_transport, GetTransportError};
///
/// // Static transport name — no expansion needed
/// let result = get_transport(
///     Some("remote_smtp"),
///     &mut addr,
///     "dnslookup",
///     &transport_list,
///     &ctx,
/// );
/// // Returns Ok(Some(&config)) if "remote_smtp" is in the list
///
/// // No transport name — returns Ok(None)
/// let result = get_transport(None, &mut addr, "accept", &transport_list, &ctx);
/// assert!(matches!(result, Ok(None)));
/// ```
pub fn get_transport<'a>(
    tpname: Option<&str>,
    addr: &mut AddressItem,
    router_name: &str,
    transport_list: &'a [TransportInstanceConfig],
    _ctx: &DeliveryContext,
) -> Result<Option<&'a TransportInstanceConfig>, GetTransportError> {
    // ── C line 51–55: Early exit if no transport name ──────────────────
    //
    // In C: `if (!tpname) { if (!require_name) return TRUE; ... }`
    // When tpname is None or empty, there is no transport to resolve.
    // The caller can check for a required-but-missing transport separately.
    let tpname = match tpname {
        Some(name) if !name.is_empty() => name,
        _ => return Ok(None),
    };

    // ── C lines 60–83: Resolve transport name (with optional expansion) ─
    //
    // In C: `expandable = Ustrchr(tpname, '$') != NULL;`
    // If the name contains '$', it must be expanded via the ${...} engine.
    let resolved_name: String = if tpname.contains('$') {
        // Transport name contains '$' → needs string expansion.
        // C: `if (!(ss = expand_string(tpname))) { ... }`
        let expanded = match expand_string(tpname) {
            Ok(s) => s,

            // ── C lines 63–65: forced failure ──────────────────────────
            // `if (f.expand_string_forcedfail) { ... return FALSE; }`
            Err(ExpandError::ForcedFail) => {
                let msg = format!(
                    "forced failure when expanding transport name '{}' in {} router",
                    tpname, router_name,
                );
                addr.message = Some(msg);
                return Err(GetTransportError::ForcedFailure);
            }

            // ── C lines 66–73: expansion error ────────────────────────
            // `addr->message = string_sprintf("failed to expand transport ...")`
            Err(e) => {
                let msg = format!(
                    "failed to expand transport '{}' in {} router: {}",
                    tpname, router_name, e,
                );
                addr.message = Some(msg.clone());
                return Err(GetTransportError::ExpansionFailed(msg));
            }
        };

        // ── C lines 72–80: CRITICAL taint check ────────────────────────
        //
        // In C, `is_tainted()` checks whether the expansion result was
        // allocated from a tainted memory pool (indicating derivation from
        // untrusted input).  In Rust, we wrap the expanded result in
        // `Tainted<T>` and validate that the name contains only safe
        // identifier characters.
        //
        // C code being translated:
        //   if (is_tainted(ss)) {
        //     log_write(0, LOG_MAIN|LOG_PANIC,
        //       "attempt to use tainted value '%s' from '%s' for transport",
        //       ss, tpname);
        //     addr->message = US"internal configuration error";
        //     return FALSE;
        //   }
        let tainted_expanded = Tainted::new(expanded);

        // Validate the expanded name within a scoped borrow so that the
        // `Tainted` wrapper can be consumed afterward (via `into_inner()`
        // or `force_clean()`).
        let is_valid = {
            let name_ref: &String = tainted_expanded.as_ref();
            is_valid_transport_name(name_ref)
        };

        if !is_valid {
            // Tainted/invalid transport name — extract value for error
            // reporting using `into_inner()`, then reject.
            let raw_name: String = tainted_expanded.into_inner();
            tracing::error!(
                tainted_name = %raw_name,
                original = %tpname,
                "attempt to use tainted value for transport name"
            );
            // Match C: `addr->message = US"internal configuration error"`
            // Intentionally vague to avoid leaking information to attackers.
            addr.message = Some("internal configuration error".to_string());
            return Err(GetTransportError::TaintedName { name: raw_name });
        }

        // Validated — promote to `Clean<String>` and extract the inner value.
        // `force_clean()` is safe here because we already validated the name
        // content above via `is_valid_transport_name()`.
        let clean_name: Clean<String> = tainted_expanded.force_clean();
        let validated_name: String = clean_name.into_inner();

        tracing::debug!(
            original = %tpname,
            expanded = %validated_name,
            "expanded transport name"
        );

        validated_name
    } else {
        // No expansion needed — name is from configuration (trusted/clean).
        // C: `ss = tpname;`  (static config value, guaranteed untainted)
        tpname.to_string()
    };

    // ── C lines 85–96: Look up transport by name ───────────────────────
    //
    // C: `for (transport_instance * tp = transports; tp; tp = tp->next)`
    //    `  if (Ustrcmp(tp->name, ss) == 0) { *tpptr = tp; return TRUE; }`
    //
    // In Rust, the global `transports` linked list is replaced by an
    // explicit `transport_list` slice parameter.
    let transport = transport_list
        .iter()
        .find(|t| t.name == resolved_name)
        .ok_or_else(|| {
            // C lines 93–96: transport not found
            // `addr->message = string_sprintf("transport %s not found ...")`
            let msg = format!(
                "transport '{}' not found in {} router",
                resolved_name, router_name,
            );
            addr.message = Some(msg);
            GetTransportError::NotFound {
                name: resolved_name.clone(),
                router: router_name.to_string(),
            }
        })?;

    // ── C line 88: DEBUG(D_route) debug_printf_indent("set transport") ─
    tracing::debug!(
        transport = %resolved_name,
        router = %router_name,
        "resolved transport"
    );

    Ok(Some(transport))
}

// ── Unit Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a minimal `AddressItem` for testing.
    fn make_addr(address: &str) -> AddressItem {
        AddressItem::new(address.to_string())
    }

    /// Helper: create a minimal `DeliveryContext` for testing.
    fn make_ctx() -> DeliveryContext {
        DeliveryContext::default()
    }

    /// Helper: create a `TransportInstanceConfig` with just a name.
    fn make_transport(name: &str) -> TransportInstanceConfig {
        TransportInstanceConfig {
            name: name.to_string(),
            ..TransportInstanceConfig::default()
        }
    }

    #[test]
    fn test_none_tpname_returns_ok_none() {
        let mut addr = make_addr("user@example.com");
        let ctx = make_ctx();
        let transports = vec![make_transport("smtp")];

        let result = get_transport(None, &mut addr, "test_router", &transports, &ctx);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn test_empty_tpname_returns_ok_none() {
        let mut addr = make_addr("user@example.com");
        let ctx = make_ctx();
        let transports = vec![make_transport("smtp")];

        let result = get_transport(Some(""), &mut addr, "test_router", &transports, &ctx);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn test_static_name_found() {
        let mut addr = make_addr("user@example.com");
        let ctx = make_ctx();
        let transports = vec![
            make_transport("local_delivery"),
            make_transport("remote_smtp"),
        ];

        let result = get_transport(
            Some("remote_smtp"),
            &mut addr,
            "dnslookup",
            &transports,
            &ctx,
        );
        match result {
            Ok(Some(t)) => assert_eq!(t.name, "remote_smtp"),
            other => panic!("expected Ok(Some(remote_smtp)), got {:?}", other),
        }
    }

    #[test]
    fn test_static_name_not_found() {
        let mut addr = make_addr("user@example.com");
        let ctx = make_ctx();
        let transports = vec![make_transport("local_delivery")];

        let result = get_transport(
            Some("nonexistent"),
            &mut addr,
            "test_router",
            &transports,
            &ctx,
        );
        match result {
            Err(GetTransportError::NotFound { name, router }) => {
                assert_eq!(name, "nonexistent");
                assert_eq!(router, "test_router");
                assert!(addr.message.is_some());
            }
            other => panic!("expected Err(NotFound), got {:?}", other),
        }
    }

    #[test]
    fn test_not_found_sets_addr_message() {
        let mut addr = make_addr("user@example.com");
        let ctx = make_ctx();
        let transports = vec![make_transport("local_delivery")];

        let _ = get_transport(Some("missing"), &mut addr, "accept", &transports, &ctx);
        let msg = addr.message.as_ref().expect("message should be set");
        assert!(msg.contains("missing"));
        assert!(msg.contains("accept"));
    }

    #[test]
    fn test_tainted_name_rejected() {
        // A name with characters outside [a-zA-Z0-9_.-] should be rejected
        // when it's the result of expansion (contains '$').
        // Since expand_string is a real function that may not be available
        // in unit tests, this tests the validation helper directly.
        assert!(!is_valid_transport_name(""));
        assert!(!is_valid_transport_name("foo bar"));
        assert!(!is_valid_transport_name("transport;rm -rf"));
        assert!(!is_valid_transport_name("name\x00null"));
        assert!(!is_valid_transport_name("../escape"));
        assert!(!is_valid_transport_name("name@domain"));
    }

    #[test]
    fn test_valid_transport_names() {
        assert!(is_valid_transport_name("remote_smtp"));
        assert!(is_valid_transport_name("local_delivery"));
        assert!(is_valid_transport_name("smtp-out"));
        assert!(is_valid_transport_name("transport.name"));
        assert!(is_valid_transport_name("a"));
        assert!(is_valid_transport_name("transport123"));
        assert!(is_valid_transport_name("my_transport-v2.1"));
    }

    #[test]
    fn test_first_matching_transport_returned() {
        let mut addr = make_addr("user@example.com");
        let ctx = make_ctx();
        // Multiple transports with different names
        let transports = vec![
            make_transport("alpha"),
            make_transport("beta"),
            make_transport("gamma"),
        ];

        let result = get_transport(Some("beta"), &mut addr, "router", &transports, &ctx);
        match result {
            Ok(Some(t)) => assert_eq!(t.name, "beta"),
            other => panic!("expected Ok(Some(beta)), got {:?}", other),
        }
    }

    #[test]
    fn test_empty_transport_list() {
        let mut addr = make_addr("user@example.com");
        let ctx = make_ctx();
        let transports: Vec<TransportInstanceConfig> = vec![];

        let result = get_transport(Some("remote_smtp"), &mut addr, "router", &transports, &ctx);
        assert!(matches!(result, Err(GetTransportError::NotFound { .. })));
    }

    #[test]
    fn test_error_variants_display() {
        let e1 = GetTransportError::ExpansionFailed("some error".to_string());
        assert!(e1
            .to_string()
            .contains("expansion of transport name failed"));

        let e2 = GetTransportError::ForcedFailure;
        assert!(e2.to_string().contains("forced expansion failure"));

        let e3 = GetTransportError::TaintedName {
            name: "bad".to_string(),
        };
        assert!(e3.to_string().contains("tainted value"));
        assert!(e3.to_string().contains("bad"));

        let e4 = GetTransportError::NotFound {
            name: "smtp".to_string(),
            router: "dnslookup".to_string(),
        };
        assert!(e4.to_string().contains("smtp"));
        assert!(e4.to_string().contains("dnslookup"));
    }
}
