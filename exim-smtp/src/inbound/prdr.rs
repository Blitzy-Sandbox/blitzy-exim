//! Per-Recipient Data Response (PRDR) support for the inbound SMTP server.
//!
//! Gated behind the `prdr` Cargo feature flag, replacing
//! `#ifndef DISABLE_PRDR` from `smtp_in.c`. The module declaration in
//! `inbound/mod.rs` uses `#[cfg(feature = "prdr")]` so no code in this
//! file is compiled when the `prdr` feature is disabled.
//!
//! PRDR allows each RCPT TO recipient to receive its own accept/reject
//! decision after the DATA phase, rather than a single collective response.
//! This is specified in an Internet Draft by Eric A. Hall extending RFC 5321.
//!
//! # Architecture
//!
//! The PRDR functionality in the original C source (`smtp_in.c`) is scattered
//! across seven `#ifndef DISABLE_PRDR` blocks at lines 291, 309, 1784, 3137,
//! 4457, 4790, and 4955. This module consolidates all PRDR logic into a
//! single cohesive unit with explicit state passing (per AAP §0.4.4).
//!
//! # State Management
//!
//! PRDR session state is tracked in [`PrdrState`] rather than global variables.
//! The `requested` flag is set when a client includes the PRDR keyword in
//! MAIL FROM and is cleared on every message reset ([`prdr_reset`]).
//! The `enabled` flag reflects the server configuration (`prdr_enable` option).
//!
//! # SMTP Protocol Integration Points
//!
//! 1. **EHLO advertisement** — [`advertise_prdr`] appends "250-PRDR\r\n"
//! 2. **MAIL FROM parsing** — [`handle_mail_from_prdr`] activates PRDR for the session
//! 3. **DATA phase** — [`generate_prdr_responses`] produces per-recipient responses
//! 4. **Logging** — [`prdr_log_suffix`] appends ", PRDR Requested" to log lines
//! 5. **Reset** — [`prdr_reset`] clears state between messages

// Internal workspace dependency: ACL evaluation result type.
// AclResult variants (Ok, Fail, Defer, Discard, Error, FailDrop) map directly
// to SMTP response codes in generate_prdr_responses(). This import is the
// only cross-crate dependency for this module.
use exim_acl::AclResult;

// =============================================================================
// PrdrState — Per-message PRDR session state
// =============================================================================

/// PRDR session state tracked per-message transaction.
///
/// Replaces the C global `prdr_requested` (bool) and config `prdr_enable`
/// (bool) from `globals.c`/`globals.h`. Per AAP §0.4.4, this state is passed
/// as an explicit parameter rather than through global variables.
///
/// # Lifecycle
///
/// - `enabled` is set once during configuration parsing and does not change.
/// - `requested` is set to `true` when a client sends `MAIL FROM:... PRDR`
///   and the server has PRDR enabled. It is reset to `false` on each
///   `smtp_reset()` call via [`prdr_reset`].
///
/// # C Reference
///
/// The C codebase uses two separate variables:
/// - `prdr_enable` (config option, `globals.c`) — whether the server offers PRDR
/// - `prdr_requested` (session state, `globals.c`) — whether the client requested it
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrdrState {
    /// Whether PRDR was requested by the client in the MAIL FROM command.
    ///
    /// Set to `true` by [`handle_mail_from_prdr`] when the client includes
    /// the PRDR keyword and the server has PRDR enabled. Reset to `false`
    /// by [`prdr_reset`] at each message boundary.
    ///
    /// C equivalent: `prdr_requested` global variable in `globals.c`.
    pub requested: bool,

    /// Whether PRDR is enabled in the server configuration.
    ///
    /// Reflects the `prdr_enable` configuration option. When `false`, PRDR
    /// is not advertised in EHLO and PRDR requests in MAIL FROM are ignored.
    ///
    /// C equivalent: `prdr_enable` configuration variable in `globals.c`.
    pub enabled: bool,
}

impl Default for PrdrState {
    /// Create a new `PrdrState` with PRDR disabled and not requested.
    ///
    /// Matches the C initialization where both `prdr_enable` and
    /// `prdr_requested` default to `FALSE`.
    fn default() -> Self {
        Self {
            requested: false,
            enabled: false,
        }
    }
}

impl PrdrState {
    /// Create a new `PrdrState` with the given configuration enable status.
    ///
    /// The `requested` flag always starts as `false` and is set during
    /// MAIL FROM processing.
    pub fn new(enabled: bool) -> Self {
        Self {
            requested: false,
            enabled,
        }
    }

    /// Check if PRDR is both enabled and was requested for the current message.
    ///
    /// This is the condition under which per-recipient ACL evaluation should
    /// be performed after the DATA phase.
    pub fn is_active(&self) -> bool {
        self.enabled && self.requested
    }
}

// =============================================================================
// PrdrResponse — Per-recipient SMTP response
// =============================================================================

/// Per-recipient SMTP response generated during PRDR processing.
///
/// After the DATA phase with PRDR, each recipient receives an individual
/// SMTP response with its own status code, allowing selective acceptance
/// or rejection on a per-recipient basis.
///
/// # Response Code Mapping
///
/// | ACL Result     | SMTP Code | Meaning                    |
/// |----------------|-----------|----------------------------|
/// | `AclResult::Ok`      | 250 | Accepted for this recipient |
/// | `AclResult::Discard` | 250 | Accepted (silently discarded) |
/// | `AclResult::Fail`    | 550 | Permanently rejected       |
/// | `AclResult::FailDrop`| 550 | Rejected, connection dropped |
/// | `AclResult::Defer`   | 450 | Temporarily deferred       |
/// | `AclResult::Error`   | 451 | Internal server error      |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrdrResponse {
    /// The recipient email address this response applies to.
    pub recipient: String,

    /// SMTP response code (2xx for accept, 4xx for defer, 5xx for reject).
    ///
    /// Standard SMTP enhanced status codes:
    /// - 250: Message accepted for this recipient
    /// - 450: Temporary failure, try again later
    /// - 451: Internal server error during processing
    /// - 550: Permanent rejection for this recipient
    pub code: u16,

    /// Human-readable response message accompanying the status code.
    ///
    /// Includes the recipient address for correlation in multi-recipient
    /// responses. Format matches Exim C output for log compatibility.
    pub message: String,
}

impl PrdrResponse {
    /// Returns `true` if this response indicates successful acceptance.
    ///
    /// A 2xx response code means the message was accepted for this recipient
    /// (either for delivery or silent discard in the case of `AclResult::Discard`).
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.code)
    }

    /// Returns `true` if this response indicates a temporary failure.
    ///
    /// A 4xx response code means the client should retry delivery later.
    pub fn is_temporary_failure(&self) -> bool {
        (400..500).contains(&self.code)
    }

    /// Returns `true` if this response indicates a permanent rejection.
    ///
    /// A 5xx response code means the message was permanently rejected
    /// for this recipient and should not be retried.
    pub fn is_permanent_failure(&self) -> bool {
        (500..600).contains(&self.code)
    }
}

// =============================================================================
// EHLO PRDR Advertisement
// =============================================================================

/// Append PRDR extension advertisement to an EHLO response.
///
/// If `prdr_enable` is `true`, appends `"250-PRDR\r\n"` to the EHLO response
/// string. The advertisement string is exactly `"PRDR"` with no parameters,
/// matching the C output byte-for-byte.
///
/// This function should be called during EHLO response construction, after
/// the base capabilities and before the final 250 line.
///
/// # Parameters
///
/// - `ehlo_response` — Mutable reference to the EHLO response being built.
///   Lines are in SMTP multi-line format with `250-` prefix.
/// - `prdr_enable` — Whether PRDR is enabled in the server configuration.
///
/// # C Reference
///
/// `smtp_in.c` lines 4457–4464:
/// ```c
/// #ifndef DISABLE_PRDR
/// if (prdr_enable)
///   {
///   g = string_catn(g, smtp_code, 3);
///   g = string_catn(g, US"-PRDR\r\n", 7);
///   }
/// #endif
/// ```
///
/// Note: In the C code, `smtp_code` contains "250" and is prepended separately.
/// Here we include the full "250-PRDR\r\n" for self-contained output.
pub fn advertise_prdr(ehlo_response: &mut String, prdr_enable: bool) {
    if prdr_enable {
        ehlo_response.push_str("250-PRDR\r\n");
    }
}

// =============================================================================
// MAIL FROM PRDR Parameter Handling
// =============================================================================

/// Handle the PRDR parameter in a MAIL FROM command.
///
/// When the client includes the PRDR keyword in the MAIL FROM command
/// (e.g., `MAIL FROM:<user@example.com> PRDR`), this function processes
/// the request. PRDR is only activated if the server configuration has
/// PRDR enabled (`prdr_enable = true`).
///
/// Returns `true` if PRDR was successfully requested and enabled, `false`
/// if the server does not support PRDR (the parameter is silently ignored
/// per the C behavior — no error is returned to the client).
///
/// # Parameters
///
/// - `prdr_state` — Mutable reference to the per-message PRDR state.
/// - `prdr_enable` — Whether PRDR is enabled in the server configuration.
///
/// # C Reference
///
/// `smtp_in.c` lines 4790–4794:
/// ```c
/// #ifndef DISABLE_PRDR
/// case ENV_MAIL_OPT_PRDR:
///   if (prdr_enable)
///     prdr_requested = TRUE;
///   break;
/// #endif
/// ```
///
/// The C code silently ignores the PRDR keyword when `prdr_enable` is false
/// (it falls through the `break` without setting the flag or returning an
/// error). This Rust implementation preserves that behavior.
pub fn handle_mail_from_prdr(prdr_state: &mut PrdrState, prdr_enable: bool) -> bool {
    if prdr_enable {
        prdr_state.requested = true;
        true
    } else {
        false
    }
}

// =============================================================================
// PRDR Response Generation
// =============================================================================

/// Generate per-recipient PRDR responses based on ACL evaluation results.
///
/// After the DATA phase, when PRDR was requested, each recipient receives
/// its own ACL evaluation at the `ACL_WHERE_PRDR` phase (described in
/// `smtp_in.c` line 3137–3138 as "after DATA PRDR"). This function maps
/// the pre-computed ACL results to individual SMTP response codes and
/// messages for each recipient.
///
/// The caller is responsible for performing ACL evaluation for each recipient
/// and providing the results. This function only maps results to responses.
///
/// # Parameters
///
/// - `recipients` — Slice of recipient email addresses. These are extracted
///   from the per-message recipient list (replaces C `recipients_list[]`).
/// - `acl_results` — Corresponding ACL evaluation results, one per recipient.
///   Must have the same length as `recipients`.
///
/// # Returns
///
/// A `Vec<PrdrResponse>` with one entry per recipient, containing the
/// appropriate SMTP response code and message based on the ACL result.
///
/// # Panics
///
/// Debug-asserts that `recipients.len() == acl_results.len()`. In release
/// builds, if lengths differ, processing stops at the shorter slice length.
///
/// # Response Code Mapping
///
/// | `AclResult`    | SMTP Code | Enhanced Code | Meaning |
/// |----------------|-----------|---------------|---------|
/// | `Ok`           | 250       | 2.1.5         | Accepted |
/// | `Discard`      | 250       | 2.1.5         | Accepted (silently discarded) |
/// | `Fail`         | 550       | 5.1.1         | Permanently rejected |
/// | `FailDrop`     | 550       | 5.1.1         | Rejected, connection will drop |
/// | `Defer`        | 450       | 4.2.0         | Temporarily deferred |
/// | `Error`        | 451       | 4.3.0         | Internal server error |
///
/// # C Reference
///
/// `smtp_in.c` line 3137–3138:
/// ```c
/// case ACL_WHERE_PRDR: what = US"after DATA PRDR"; break;
/// ```
pub fn generate_prdr_responses(
    recipients: &[String],
    acl_results: &[AclResult],
) -> Vec<PrdrResponse> {
    debug_assert_eq!(
        recipients.len(),
        acl_results.len(),
        "PRDR: recipient count ({}) must match ACL result count ({})",
        recipients.len(),
        acl_results.len(),
    );

    recipients
        .iter()
        .zip(acl_results.iter())
        .map(|(recipient_address, acl_result)| {
            let (code, message) = match acl_result {
                AclResult::Ok => (250_u16, format!("2.1.5 OK for <{}>", recipient_address)),
                AclResult::Discard => (250_u16, format!("2.1.5 OK for <{}>", recipient_address)),
                AclResult::Fail => (
                    550_u16,
                    format!("5.1.1 Rejected for <{}>", recipient_address),
                ),
                AclResult::FailDrop => (
                    550_u16,
                    format!("5.1.1 Rejected for <{}>", recipient_address),
                ),
                AclResult::Defer => (
                    450_u16,
                    format!("4.2.0 Deferred for <{}>", recipient_address),
                ),
                AclResult::Error => (
                    451_u16,
                    format!("4.3.0 Internal error for <{}>", recipient_address),
                ),
            };

            PrdrResponse {
                recipient: recipient_address.clone(),
                code,
                message,
            }
        })
        .collect()
}

// =============================================================================
// PRDR Logging Integration
// =============================================================================

/// Return the PRDR log suffix string for SMTP response messages.
///
/// When PRDR was requested by the client, the string `", PRDR Requested"`
/// is appended to SMTP 250 OK responses and log messages. Returns an
/// empty string when PRDR was not requested.
///
/// The returned suffix is a static string matching the C output byte-for-byte
/// for log format compatibility with existing `exigrep`/`eximstats` tools.
///
/// # Parameters
///
/// - `prdr_requested` — Whether PRDR was requested for the current message.
///
/// # C Reference
///
/// `smtp_in.c` lines 4955–4965:
/// ```c
/// /* In the normal 250 OK response: */
/// prdr_requested ? US", PRDR Requested" : US"",
///
/// /* When appending to a user message: */
/// if (prdr_requested)
///   user_msg = string_sprintf("%s%s", user_msg, US", PRDR Requested");
/// ```
pub fn prdr_log_suffix(prdr_requested: bool) -> &'static str {
    if prdr_requested {
        ", PRDR Requested"
    } else {
        ""
    }
}

// =============================================================================
// PRDR State Reset
// =============================================================================

/// Reset PRDR state at the start of a new message transaction.
///
/// Called during `smtp_reset()` to clear PRDR state from the previous
/// message. Only clears the `requested` flag — `enabled` reflects the
/// server configuration and persists across messages within the same
/// SMTP session.
///
/// # Parameters
///
/// - `prdr_state` — Mutable reference to the per-message PRDR state.
///
/// # C Reference
///
/// `smtp_in.c` lines 1784–1785:
/// ```c
/// #ifndef DISABLE_PRDR
///   prdr_requested = FALSE;
/// #endif
/// ```
pub fn prdr_reset(prdr_state: &mut PrdrState) {
    prdr_state.requested = false;
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prdr_state_default() {
        let state = PrdrState::default();
        assert!(!state.requested);
        assert!(!state.enabled);
    }

    #[test]
    fn test_prdr_state_new() {
        let state = PrdrState::new(true);
        assert!(!state.requested);
        assert!(state.enabled);
    }

    #[test]
    fn test_prdr_state_is_active() {
        let mut state = PrdrState::new(true);
        assert!(!state.is_active());
        state.requested = true;
        assert!(state.is_active());

        let mut state_disabled = PrdrState::new(false);
        state_disabled.requested = true;
        assert!(!state_disabled.is_active());
    }

    #[test]
    fn test_advertise_prdr_enabled() {
        let mut ehlo = String::new();
        advertise_prdr(&mut ehlo, true);
        assert_eq!(ehlo, "250-PRDR\r\n");
    }

    #[test]
    fn test_advertise_prdr_disabled() {
        let mut ehlo = String::new();
        advertise_prdr(&mut ehlo, false);
        assert!(ehlo.is_empty());
    }

    #[test]
    fn test_advertise_prdr_appends() {
        let mut ehlo = String::from("250-SIZE 52428800\r\n");
        advertise_prdr(&mut ehlo, true);
        assert_eq!(ehlo, "250-SIZE 52428800\r\n250-PRDR\r\n");
    }

    #[test]
    fn test_handle_mail_from_prdr_enabled() {
        let mut state = PrdrState::default();
        let result = handle_mail_from_prdr(&mut state, true);
        assert!(result);
        assert!(state.requested);
    }

    #[test]
    fn test_handle_mail_from_prdr_disabled() {
        let mut state = PrdrState::default();
        let result = handle_mail_from_prdr(&mut state, false);
        assert!(!result);
        assert!(!state.requested);
    }

    #[test]
    fn test_prdr_reset() {
        let mut state = PrdrState {
            requested: true,
            enabled: true,
        };
        prdr_reset(&mut state);
        assert!(!state.requested);
        assert!(state.enabled); // enabled is NOT cleared by reset
    }

    #[test]
    fn test_prdr_log_suffix_requested() {
        assert_eq!(prdr_log_suffix(true), ", PRDR Requested");
    }

    #[test]
    fn test_prdr_log_suffix_not_requested() {
        assert_eq!(prdr_log_suffix(false), "");
    }

    #[test]
    fn test_generate_prdr_responses_ok() {
        let recipients = vec!["user@example.com".to_string()];
        let results = vec![AclResult::Ok];
        let responses = generate_prdr_responses(&recipients, &results);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].code, 250);
        assert_eq!(responses[0].recipient, "user@example.com");
        assert!(responses[0].is_success());
    }

    #[test]
    fn test_generate_prdr_responses_fail() {
        let recipients = vec!["bad@example.com".to_string()];
        let results = vec![AclResult::Fail];
        let responses = generate_prdr_responses(&recipients, &results);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].code, 550);
        assert!(responses[0].is_permanent_failure());
    }

    #[test]
    fn test_generate_prdr_responses_defer() {
        let recipients = vec!["slow@example.com".to_string()];
        let results = vec![AclResult::Defer];
        let responses = generate_prdr_responses(&recipients, &results);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].code, 450);
        assert!(responses[0].is_temporary_failure());
    }

    #[test]
    fn test_generate_prdr_responses_mixed() {
        let recipients = vec![
            "good@example.com".to_string(),
            "bad@example.com".to_string(),
            "slow@example.com".to_string(),
        ];
        let results = vec![AclResult::Ok, AclResult::Fail, AclResult::Defer];
        let responses = generate_prdr_responses(&recipients, &results);

        assert_eq!(responses.len(), 3);
        assert_eq!(responses[0].code, 250);
        assert!(responses[0].is_success());
        assert_eq!(responses[1].code, 550);
        assert!(responses[1].is_permanent_failure());
        assert_eq!(responses[2].code, 450);
        assert!(responses[2].is_temporary_failure());
    }

    #[test]
    fn test_generate_prdr_responses_discard() {
        let recipients = vec!["discard@example.com".to_string()];
        let results = vec![AclResult::Discard];
        let responses = generate_prdr_responses(&recipients, &results);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].code, 250);
        assert!(responses[0].is_success());
    }

    #[test]
    fn test_generate_prdr_responses_error() {
        let recipients = vec!["error@example.com".to_string()];
        let results = vec![AclResult::Error];
        let responses = generate_prdr_responses(&recipients, &results);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].code, 451);
        assert!(responses[0].is_temporary_failure());
    }

    #[test]
    fn test_generate_prdr_responses_fail_drop() {
        let recipients = vec!["drop@example.com".to_string()];
        let results = vec![AclResult::FailDrop];
        let responses = generate_prdr_responses(&recipients, &results);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].code, 550);
        assert!(responses[0].is_permanent_failure());
    }

    #[test]
    fn test_generate_prdr_responses_empty() {
        let recipients: Vec<String> = vec![];
        let results: Vec<AclResult> = vec![];
        let responses = generate_prdr_responses(&recipients, &results);
        assert!(responses.is_empty());
    }

    #[test]
    fn test_prdr_response_helper_methods() {
        let success = PrdrResponse {
            recipient: "a@b.c".to_string(),
            code: 250,
            message: "OK".to_string(),
        };
        assert!(success.is_success());
        assert!(!success.is_temporary_failure());
        assert!(!success.is_permanent_failure());

        let temp_fail = PrdrResponse {
            recipient: "a@b.c".to_string(),
            code: 450,
            message: "Deferred".to_string(),
        };
        assert!(!temp_fail.is_success());
        assert!(temp_fail.is_temporary_failure());
        assert!(!temp_fail.is_permanent_failure());

        let perm_fail = PrdrResponse {
            recipient: "a@b.c".to_string(),
            code: 550,
            message: "Rejected".to_string(),
        };
        assert!(!perm_fail.is_success());
        assert!(!perm_fail.is_temporary_failure());
        assert!(perm_fail.is_permanent_failure());
    }

    #[test]
    fn test_full_prdr_lifecycle() {
        // 1. Create PRDR state with PRDR enabled
        let mut state = PrdrState::new(true);
        assert!(!state.requested);

        // 2. Client sends MAIL FROM with PRDR
        let enabled = state.enabled;
        let requested = handle_mail_from_prdr(&mut state, enabled);
        assert!(requested);
        assert!(state.is_active());

        // 3. Check log suffix
        assert_eq!(prdr_log_suffix(state.requested), ", PRDR Requested");

        // 4. Generate per-recipient responses
        let recipients = vec![
            "alice@example.com".to_string(),
            "bob@example.com".to_string(),
        ];
        let acl_results = vec![AclResult::Ok, AclResult::Fail];
        let responses = generate_prdr_responses(&recipients, &acl_results);
        assert_eq!(responses.len(), 2);
        assert!(responses[0].is_success());
        assert!(responses[1].is_permanent_failure());

        // 5. Reset for next message
        prdr_reset(&mut state);
        assert!(!state.requested);
        assert!(state.enabled); // Enabled persists across messages
        assert_eq!(prdr_log_suffix(state.requested), "");
    }
}
