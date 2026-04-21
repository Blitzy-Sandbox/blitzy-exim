// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! Header add/remove processing for router drivers.
//!
//! Translates **`src/src/routers/rf_get_munge_headers.c`** (127 lines) into
//! Rust.
//!
//! ## Overview
//!
//! Routers may add or remove headers from messages they process.  The
//! `headers_add` option provides a newline-separated list of header lines to
//! add, while `headers_remove` provides a colon-separated list of header
//! names to remove.  Both options may contain `${…}` expansion expressions
//! that are evaluated at routing time.
//!
//! [`get_munge_headers()`] expands these options and returns the combined
//! result in a [`MungeHeadersResult`], aggregating any pre-existing header
//! modifications already carried on the address item.
//!
//! ## Key Behaviors
//!
//! | Expansion outcome | headers\_add action | headers\_remove action |
//! |---|---|---|
//! | Success (non-empty) | Create `HeaderLine`, prepend to list | Append to colon-separated string |
//! | Success (empty) | Skip silently | Skip silently |
//! | Forced failure | Skip silently (ignore) | Skip silently (ignore) |
//! | Expansion error | Set `addr.message`, return `Err` | Set `addr.message`, return `Err` |
//!
//! ## C Source Correspondence
//!
//! | C construct | Rust equivalent |
//! |---|---|
//! | `rf_get_munge_headers(addr, rblock, &ehdr, &rhdr)` | [`get_munge_headers(addr, config, ctx)`] |
//! | `*extra_headers = addr->prop.extra_headers` | Start from `addr.prop.extra_headers` |
//! | `string_nextinlist(&list, &sep, NULL, 0)` with `sep = '\n'` | `.split('\n')` iterator |
//! | `expand_string(t = s)` | [`exim_expand::expand_string(item)`] |
//! | `f.expand_string_forcedfail` | [`ExpandError::ForcedFail`] variant |
//! | `addr->message = string_sprintf(…)` | `addr.message = Some(format!(…))` |
//! | `return DEFER` | `Err(GetMungeHeadersError::*)` |
//! | `h->next = *extra_headers; *extra_headers = h;` | `extra_headers.insert(0, h)` (prepend) |
//! | `string_append_listele(g, ':', s)` | `format!("{}:{}", existing, expanded)` |
//! | `return OK` | `Ok(MungeHeadersResult { … })` |
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

// ═══════════════════════════════════════════════════════════════════════════
//  HeaderType — Simplified header classification for router-added headers
// ═══════════════════════════════════════════════════════════════════════════

/// Header type classification for headers added by router configuration.
///
/// A simplified enum for router-added headers.  All headers added through
/// the `headers_add` router option are classified as [`Other`](Self::Other),
/// matching the C assignment `h->type = htype_other` in
/// `rf_get_munge_headers.c` line 82.
///
/// This is intentionally simpler than the full `HeaderType` enum in
/// `exim-core::context` or `change_domain` — router-added headers are
/// always generic "other" type, so no additional classification is needed
/// at this layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderType {
    /// Generic other header type (maps to C `htype_other`).
    ///
    /// All router-added headers use this classification because the
    /// router `headers_add` option does not provide per-header type
    /// metadata.
    Other,
}

// ═══════════════════════════════════════════════════════════════════════════
//  HeaderLine — A single header line to be added during routing
// ═══════════════════════════════════════════════════════════════════════════

/// Represents a header line to be added to the message during routing.
///
/// This is a simplified header representation carrying only the fields needed
/// for router-added headers: the header text and its type classification.
/// All header text **MUST** end with a newline character (`\n`) per Exim
/// convention (matching C `rf_get_munge_headers.c` lines 71–79 where the
/// code ensures every header line has a trailing `\n`).
///
/// ## Relation to other `HeaderLine` types
///
/// The `change_domain` module defines a full `HeaderLine` with `text`,
/// `slen`, and `htype` fields (mirroring `exim-core::context::HeaderLine`).
/// This struct is intentionally simpler because the router header-add path
/// only needs text and type — the length is implicit in the `String`.
#[derive(Debug, Clone)]
pub struct HeaderLine {
    /// The complete header text including name, colon, value, and trailing
    /// newline.
    ///
    /// Example: `"X-Custom-Header: value\n"`.
    ///
    /// Corresponds to C `header_line.text` from `rf_get_munge_headers.c`
    /// lines 72–79.
    pub text: String,

    /// Header type classification.
    ///
    /// Always [`HeaderType::Other`] for router-added headers, matching
    /// C `h->type = htype_other` at `rf_get_munge_headers.c` line 82.
    pub header_type: HeaderType,
}

// ═══════════════════════════════════════════════════════════════════════════
//  MungeHeadersResult — Combined header add/remove result
// ═══════════════════════════════════════════════════════════════════════════

/// Result of header munging: combined extra headers to add and header names
/// to remove.
///
/// Returned by [`get_munge_headers()`] on success.  Contains the aggregated
/// list of headers to add (including pre-existing headers from the address
/// item) and the colon-separated string of header names to remove (including
/// pre-existing remove list).
///
/// ## Ordering
///
/// New headers from `headers_add` are **prepended** to the existing header
/// list, matching the C behavior at `rf_get_munge_headers.c` lines 81–84:
///
/// ```c
/// h->next = *extra_headers;
/// *extra_headers = h;
/// ```
///
/// The output function emits headers in reverse order, so prepending at the
/// front of the vector produces the correct final order.
#[derive(Debug, Clone)]
pub struct MungeHeadersResult {
    /// Headers to add to the message during delivery.
    ///
    /// Contains:
    /// 1. Newly expanded headers from `router_config.extra_headers`,
    ///    prepended to the front of the vector.
    /// 2. Pre-existing headers from `addr.prop.extra_headers`, carried
    ///    from earlier routing stages.
    pub extra_headers: Vec<HeaderLine>,

    /// Colon-separated header names to remove from the message.
    ///
    /// Contains the aggregation of:
    /// 1. Pre-existing remove list from `addr.prop.remove_headers`.
    /// 2. Newly expanded items from `router_config.remove_headers`,
    ///    appended with colon separators.
    ///
    /// `None` if no headers are configured for removal and no pre-existing
    /// remove list exists.
    pub remove_headers: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
//  GetMungeHeadersError — Expansion failure error type
// ═══════════════════════════════════════════════════════════════════════════

/// Error type for header munging expansion failures.
///
/// Maps to the C `DEFER` return code from `rf_get_munge_headers()`.  Before
/// returning either variant, [`get_munge_headers()`] sets `addr.message` with
/// a formatted error string matching the C `string_sprintf()` pattern.
///
/// ## Error Mapping
///
/// | C failure mode | Rust variant |
/// |---|---|
/// | headers\_add expansion error (line 52) | [`HeadersAddExpansionFailed`](Self::HeadersAddExpansionFailed) |
/// | headers\_remove expansion error (line 108) | [`HeadersRemoveExpansionFailed`](Self::HeadersRemoveExpansionFailed) |
///
/// Forced failure (`ExpandError::ForcedFail`) is NOT an error — it is silently
/// ignored, matching C behavior where `f.expand_string_forcedfail = TRUE`
/// causes the item to be skipped without returning `DEFER`.
#[derive(Debug, thiserror::Error)]
pub enum GetMungeHeadersError {
    /// Expansion of a `headers_add` item failed.
    ///
    /// Corresponds to C `rf_get_munge_headers.c` lines 52–55:
    /// ```c
    /// addr->message = string_sprintf(
    ///   "%s router failed to expand add_headers item %q: %s",
    ///   rblock->drinst.name, t, expand_string_message);
    /// return DEFER;
    /// ```
    #[error("expansion of headers_add failed: {0}")]
    HeadersAddExpansionFailed(String),

    /// Expansion of a `headers_remove` item failed.
    ///
    /// Corresponds to C `rf_get_munge_headers.c` lines 108–111:
    /// ```c
    /// addr->message = string_sprintf(
    ///   "%s router failed to expand remove_headers item %q: %s",
    ///   rblock->drinst.name, t, expand_string_message);
    /// return DEFER;
    /// ```
    #[error("expansion of headers_remove failed: {0}")]
    HeadersRemoveExpansionFailed(String),
}

// ═══════════════════════════════════════════════════════════════════════════
//  get_munge_headers — Main public function
// ═══════════════════════════════════════════════════════════════════════════

/// Expand `headers_add` and `headers_remove` from router configuration.
///
/// Translates C `rf_get_munge_headers()` from
/// `src/src/routers/rf_get_munge_headers.c` (127 lines).
///
/// # Processing
///
/// 1. **headers\_add** (C lines 34–86):
///    - Starts with existing `addr.prop.extra_headers` as the base list.
///    - Splits `router_config.extra_headers` on newline (`\n`) boundaries.
///    - Expands each item individually via [`expand_string()`].
///    - On forced failure: silently ignores the item (C line 50–51).
///    - On expansion error: sets `addr.message` and returns
///      [`GetMungeHeadersError::HeadersAddExpansionFailed`] (C lines 52–55).
///    - On success with non-empty result: creates a [`HeaderLine`] with
///      `\n`-terminated text and [`HeaderType::Other`], prepended to the
///      result vector (C lines 65–85).
///
/// 2. **headers\_remove** (C lines 88–119):
///    - Starts with existing `addr.prop.remove_headers` as the base string.
///    - Splits `router_config.remove_headers` on colon (`:`) boundaries.
///    - Expands each item individually via [`expand_string()`].
///    - On forced failure: silently ignores the item (C lines 106–107).
///    - On expansion error: sets `addr.message` and returns
///      [`GetMungeHeadersError::HeadersRemoveExpansionFailed`] (C lines
///      108–111).
///    - On success with non-empty result: aggregates into a colon-separated
///      string (C line 115).
///
/// # Arguments
///
/// * `addr` — The address item being routed.  Its `prop.extra_headers` and
///   `prop.remove_headers` provide the pre-existing header modifications
///   from prior routing stages.  On expansion failure, `addr.message` is
///   set with a diagnostic string (matching C behavior).
/// * `router_config` — The router instance configuration providing the
///   `extra_headers` and `remove_headers` option values to expand.  Uses
///   `router_config.name` in error messages.
/// * `_ctx` — The per-delivery-attempt context.  Accepted for API
///   consistency with other router helpers; the expansion engine resolves
///   variables through its own mechanism.
///
/// # Returns
///
/// * `Ok(MungeHeadersResult)` — Successfully expanded headers.
/// * `Err(GetMungeHeadersError)` — Expansion of a header item failed.
///   The `addr.message` field has been set before the error is returned.
///
/// # C Equivalence
///
/// | C return | Rust return |
/// |----------|-------------|
/// | `OK`     | `Ok(MungeHeadersResult)` |
/// | `DEFER`  | `Err(GetMungeHeadersError::*)` |
pub fn get_munge_headers(
    addr: &mut AddressItem,
    router_config: &RouterInstanceConfig,
    _ctx: &DeliveryContext,
) -> Result<MungeHeadersResult, GetMungeHeadersError> {
    // ── Phase 1: headers_add processing (C lines 34–86) ────────────────

    // Start with existing extra headers from the address properties.
    // C line 37: *extra_headers = addr->prop.extra_headers;
    //
    // Convert from the change_domain::HeaderLine type (with slen/htype)
    // to our simplified HeaderLine type (text/header_type only).
    let mut extra_headers: Vec<HeaderLine> = addr
        .prop
        .extra_headers
        .iter()
        .map(|h| HeaderLine {
            text: h.text.clone(),
            header_type: HeaderType::Other,
        })
        .collect();

    // Expand each item in the headers_add configuration option.
    // C lines 40–86: if (rblock->extra_headers) { ... }
    if let Some(ref headers_add_config) = router_config.extra_headers {
        // C lines 42–43: const uschar * list = rblock->extra_headers;
        //                 int sep = '\n';
        // Iterate over newline-separated items, expanding each individually.
        for item in headers_add_config.split('\n') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }

            // C line 48: if (!(s = expand_string(t = s)))
            match expand_string(item) {
                Ok(expanded) => {
                    // C line 58: else if ((slen = Ustrlen(s)) > 0)
                    if !expanded.is_empty() {
                        // Ensure the header text ends with '\n' (Exim convention).
                        // C lines 71–79:
                        //   if (s[slen-1] == '\n')
                        //     h->text = s;
                        //   else { ... append '\n' ... }
                        let text = if expanded.ends_with('\n') {
                            expanded
                        } else {
                            format!("{}\n", expanded)
                        };

                        // Prepend to the header chain. C lines 81–84:
                        //   h->next = *extra_headers;
                        //   *extra_headers = h;
                        // Insert at position 0 for prepend semantics.
                        extra_headers.insert(
                            0,
                            HeaderLine {
                                text,
                                header_type: HeaderType::Other,
                            },
                        );
                    }
                }
                Err(ExpandError::ForcedFail) => {
                    // Forced failure → silently ignore this item (do not error).
                    // C lines 50–51: if (!f.expand_string_forcedfail) { ... }
                    // When forced fail IS set, the outer `if` falls through
                    // without entering the DEFER block.
                    tracing::debug!(
                        item = %item,
                        router = %router_config.name,
                        "headers_add expansion forced fail, ignoring item"
                    );
                }
                Err(ExpandError::Failed { message }) => {
                    // Expansion error → set addr->message and return DEFER.
                    // C lines 52–55:
                    //   addr->message = string_sprintf(
                    //     "%s router failed to expand add_headers item %q: %s",
                    //     rblock->drinst.name, t, expand_string_message);
                    //   return DEFER;
                    let error_msg = format!(
                        "{} router failed to expand add_headers item \"{}\": {}",
                        router_config.name, item, message
                    );
                    addr.message = Some(error_msg.clone());
                    return Err(GetMungeHeadersError::HeadersAddExpansionFailed(error_msg));
                }
                Err(other_error) => {
                    // Any other expansion error variant (TaintedInput,
                    // IntegerError, LookupDefer) → treat as expansion failure.
                    // The C code has a single error path for all non-forced
                    // failures; we mirror that by catching all remaining
                    // ExpandError variants.
                    let error_msg = format!(
                        "{} router failed to expand add_headers item \"{}\": {}",
                        router_config.name, item, other_error
                    );
                    addr.message = Some(error_msg.clone());
                    return Err(GetMungeHeadersError::HeadersAddExpansionFailed(error_msg));
                }
            }
        }
    }

    tracing::debug!(count = extra_headers.len(), "expanded headers_add");

    // ── Phase 2: headers_remove processing (C lines 88–119) ────────────

    // Start with existing remove headers from the address properties.
    // C line 89: *remove_headers = addr->prop.remove_headers;
    let mut remove_headers: Option<String> = addr.prop.remove_headers.clone();

    // Expand each item in the headers_remove configuration option.
    // C lines 93–119: if (rblock->remove_headers) { ... }
    if let Some(ref headers_remove_config) = router_config.remove_headers {
        // C lines 95–96: const uschar * list = rblock->remove_headers;
        //                 int sep = ':';
        // Iterate over colon-separated items, expanding each individually.
        for item in headers_remove_config.split(':') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }

            // C line 104: if (!(s = expand_string(t = s)))
            match expand_string(item) {
                Ok(expanded) => {
                    // C line 114: else if (*s)
                    if !expanded.is_empty() {
                        // Aggregate with colon separator.
                        // C line 115: g = string_append_listele(g, ':', s);
                        remove_headers = Some(match remove_headers {
                            Some(existing) => format!("{}:{}", existing, expanded),
                            None => expanded,
                        });
                    }
                }
                Err(ExpandError::ForcedFail) => {
                    // Forced failure → silently ignore this item.
                    // C lines 106–107: if (!f.expand_string_forcedfail) { ... }
                    tracing::debug!(
                        item = %item,
                        router = %router_config.name,
                        "headers_remove expansion forced fail, ignoring item"
                    );
                }
                Err(ExpandError::Failed { message }) => {
                    // Expansion error → set addr->message and return DEFER.
                    // C lines 108–111:
                    //   addr->message = string_sprintf(
                    //     "%s router failed to expand remove_headers item %q: %s",
                    //     rblock->drinst.name, t, expand_string_message);
                    //   return DEFER;
                    let error_msg = format!(
                        "{} router failed to expand remove_headers item \"{}\": {}",
                        router_config.name, item, message
                    );
                    addr.message = Some(error_msg.clone());
                    return Err(GetMungeHeadersError::HeadersRemoveExpansionFailed(
                        error_msg,
                    ));
                }
                Err(other_error) => {
                    // Any other expansion error variant → treat as expansion
                    // failure, matching the single C error path.
                    let error_msg = format!(
                        "{} router failed to expand remove_headers item \"{}\": {}",
                        router_config.name, item, other_error
                    );
                    addr.message = Some(error_msg.clone());
                    return Err(GetMungeHeadersError::HeadersRemoveExpansionFailed(
                        error_msg,
                    ));
                }
            }
        }
    }

    tracing::debug!(remove = ?remove_headers, "expanded headers_remove");

    Ok(MungeHeadersResult {
        extra_headers,
        remove_headers,
    })
}
