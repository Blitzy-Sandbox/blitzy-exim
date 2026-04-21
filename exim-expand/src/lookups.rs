// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later
//
// =============================================================================
// exim-expand/src/lookups.rs — `${lookup …}` Integration Bridge
// =============================================================================
//
// This module implements the `${lookup{key} type {file} {yes}{no}}` expansion
// item, providing the integration bridge between the string expansion engine
// and the lookup subsystem (exim-lookups crate).
//
// **Source context**: Replaces `EITEM_LOOKUP` handler from `expand.c` lines
// 5199–5370 (~171 lines of C code) plus lookup-related logic in `search.c`
// (`search_findtype_partial`, `search_args`, `search_open`, `search_find`).
//
// **Architecture**:
//   - `LookupArgs`          — parsed components of a `${lookup …}` expansion
//   - `PartialLookupSpec`   — partial-matching configuration (always available)
//   - `LookupTypeInfo`      — resolved lookup type metadata
//   - `resolve_lookup_type` — type name → metadata resolver
//   - `eval_lookup`         — main evaluation entry point
//
// When the `lookup-integration` Cargo feature is enabled, this module
// delegates to `exim_lookups::search_findtype_partial()` for type resolution
// and calls `LookupDriver` trait methods directly for open/find operations.
// When the feature is disabled, all functions return descriptive errors
// indicating that lookup support is not compiled in.
//
// **Memory safety**: Zero `unsafe` blocks — all lookup execution is delegated
// to the safe `LookupDriver` trait interface from `exim-drivers`.

use crate::evaluator::Evaluator;
use crate::{ExpandError, RDO_LOOKUP};
use exim_drivers::lookup_driver::LookupType;

// =============================================================================
// Public Data Structures
// =============================================================================

/// Arguments for a `${lookup …}` expansion item.
///
/// Captures the three parsed components of the lookup expansion *before*
/// evaluation.  The evaluator's AST handler extracts these from the parsed
/// expression tree and passes them to [`eval_lookup`].
///
/// # Single-key example
///
/// ```text
/// ${lookup{user} lsearch {/etc/aliases} {$value}{FAIL}}
/// ```
/// → `key = Some("user"), lookup_type = "lsearch", query_or_filename = "/etc/aliases"`
///
/// # Query-style example
///
/// ```text
/// ${lookup mysql {SELECT name FROM users WHERE id=1} {$value}}
/// ```
/// → `key = None, lookup_type = "mysql", query_or_filename = "SELECT …"`
#[derive(Debug, Clone)]
pub struct LookupArgs {
    /// The lookup key for single-key lookups (lsearch, dbm, cdb, etc.).
    ///
    /// `Some(key)` when the expansion has a `{key}` argument, `None` for
    /// query-style lookups (mysql, pgsql, ldap, redis, etc.).
    pub key: Option<String>,

    /// The lookup type name, potentially including partial-match modifiers.
    ///
    /// This is the raw type string as written in the expansion, *before*
    /// parsing.  Examples: `"lsearch"`, `"partial-dbm"`, `"partial2-lsearch"`,
    /// `"mysql"`, `"partial-dbm*@"`, `"cdb,ret=key"`.
    pub lookup_type: String,

    /// The filename (for single-key lookups) or query string (for query-style).
    ///
    /// For single-key lookups this is the file path to search (e.g.,
    /// `/etc/aliases`).  For query-style lookups this is the SQL query,
    /// LDAP filter, Redis command, or socket request.
    pub query_or_filename: String,
}

// -----------------------------------------------------------------------------
// Partial Matching Specification
// -----------------------------------------------------------------------------

/// Partial matching specification for progressive domain shortening.
///
/// Mirrors the C `partial`/`starflags`/`affix`/`affixlen` variables from
/// `search_findtype_partial()` (search.c lines 130–221).
///
/// Partial matching progressively shortens a lookup key by removing leading
/// domain components, prepending an affix, and looking up each candidate.
///
/// # Example
///
/// For key `"a.b.c.d"` with prefix `"*."` and depth 2:
///   1. `"*.a.b.c.d"` — affix-prefixed full key
///   2. `"*.b.c.d"`   — one component removed
///   3. `"*.c.d"`     — two components removed (stops at depth 2)
///
/// Star/starat fallbacks are tried *after* partial candidates:
///   4. `"*@domain"` (if `star_at` is set and key contains `@`)
///   5. `"*"`        (if `wildcard_key` or `star_at` is set)
#[derive(Debug, Clone)]
pub struct PartialLookupSpec {
    /// Minimum number of non-wild domain components to retain during
    /// progressive shortening.
    ///
    /// - `-1` means no partial matching (the default).
    /// -  `0+` means progressive shortening will not remove more components
    ///    than leave fewer than this count.
    /// -  Default value when `partial` prefix is used without an explicit
    ///    digit: `2`.
    pub partial_depth: i32,

    /// Affix string prepended to shortened keys during partial matching.
    ///
    /// Default: `"*."` when the `partial-` prefix form is used.
    /// Empty when `partial0`/`partial1`/`partial2` is used without dash.
    pub prefix: String,

    /// Suffix string (reserved for future extensions; currently unused).
    pub suffix: String,

    /// Whether to try `"*"` as a final fallback key.
    ///
    /// Corresponds to the C `SEARCH_STAR` flag in `starflags`.
    pub wildcard_key: bool,

    /// Whether to try `"*@domain"` as a fallback before plain `"*"`.
    ///
    /// Corresponds to the C `SEARCH_STARAT` flag in `starflags`.
    pub star_at: bool,
}

impl Default for PartialLookupSpec {
    fn default() -> Self {
        Self {
            partial_depth: -1,
            prefix: String::new(),
            suffix: String::new(),
            wildcard_key: false,
            star_at: false,
        }
    }
}

impl PartialLookupSpec {
    /// Check whether partial matching is enabled.
    ///
    /// Returns `true` when `partial_depth >= 0`, indicating that the lookup
    /// type name included a `partial` prefix.
    #[inline]
    pub fn is_partial(&self) -> bool {
        self.partial_depth >= 0
    }

    /// Check whether any star/starat fallback flags are set.
    #[inline]
    pub fn has_star_flags(&self) -> bool {
        self.wildcard_key || self.star_at
    }
}

// -----------------------------------------------------------------------------
// Resolved Lookup Type Information
// -----------------------------------------------------------------------------

/// Resolved lookup type information returned by [`resolve_lookup_type`].
///
/// Contains the driver's type flags, any partial-matching specification
/// parsed from the type name prefix, driver-specific options extracted
/// from the type name suffix, and the canonical driver name.
#[derive(Debug, Clone)]
pub struct LookupTypeInfo {
    /// The lookup type flags from the resolved driver factory.
    ///
    /// Determines whether this is a `QUERY_STYLE`, `ABS_FILE`, or single-key
    /// lookup, controlling key/filename validation in [`eval_lookup`].
    pub lookup_type: LookupType,

    /// Partial matching specification extracted from the type name prefix.
    ///
    /// Populated when the type name starts with `partial`, `partial-`,
    /// `partial0`, `partial1`, etc.  See [`PartialLookupSpec`].
    pub partial_spec: PartialLookupSpec,

    /// Driver-specific options extracted from the type name suffix.
    ///
    /// For example, `Some("ret=key")` from the type spec `"lsearch,ret=key"`.
    /// `None` when no options were specified.
    pub options: Option<String>,

    /// Canonical driver name after stripping partial/star modifiers.
    ///
    /// For example, `"lsearch"` from the full type spec
    /// `"partial-lsearch*@"`.
    pub driver_name: String,
}

// =============================================================================
// Public API Functions
// =============================================================================

/// Resolve a lookup type name including partial-match option prefixes.
///
/// Parses the extended lookup type specification (e.g., `"partial-lsearch*@"`)
/// and resolves it to a [`LookupTypeInfo`] containing the driver type flags,
/// partial matching configuration, and canonical driver name.
///
/// Delegates to `exim_lookups::search_findtype_partial()` when the
/// `lookup-integration` feature is enabled.
///
/// # Errors
///
/// Returns `ExpandError::Failed` if the lookup type name is unknown, not
/// compiled in, or if the `lookup-integration` feature is not enabled.
///
/// # Examples
///
/// ```rust,ignore
/// let info = resolve_lookup_type("partial-lsearch*@")?;
/// assert_eq!(info.driver_name, "lsearch");
/// assert!(info.partial_spec.is_partial());
/// assert!(info.partial_spec.star_at);
/// ```
pub fn resolve_lookup_type(name: &str) -> Result<LookupTypeInfo, ExpandError> {
    // Dispatch to the feature-gated implementation.
    resolve_lookup_type_dispatch(name)
}

/// Main entry point for `${lookup …}` expansion evaluation.
///
/// Performs the complete lookup operation corresponding to the C
/// `EITEM_LOOKUP` handler from `expand.c` lines 5199–5370:
///
/// 1. Checks expansion forbid flags (`RDO_LOOKUP`).
/// 2. Saves current evaluator state (`lookup_value`, `expand_nstring[]`).
/// 3. Resolves the lookup type (including partial-match options).
/// 4. Validates key/query style consistency.
/// 5. Opens the lookup source and executes the find operation.
/// 6. Processes the result, setting `$value` and `$1`/`$2` as needed.
/// 7. Restores saved state after processing.
///
/// # Returns
///
/// - `Ok(Some(value))` — Lookup succeeded; `value` is the found data.
/// - `Ok(None)` — Lookup did not find a match (not-found).
/// - `Err(ExpandError::Failed{..})` — Lookup failed with an error message.
/// - `Err(ExpandError::LookupDefer)` — Lookup deferred (temporary failure).
/// - `Err(ExpandError::ForcedFail)` — Forced failure triggered.
///
/// # State Effects
///
/// On success, `evaluator.lookup_value` is temporarily set to the found
/// value for use in `{yes}` branch evaluation.  After processing, the
/// previous `lookup_value` and `expand_nstring[]` are restored.
///
/// When partial matching produces a shortened key different from the
/// original, `evaluator.expand_nstring[1]` is set to the matched
/// shortened key and `evaluator.expand_nstring[2]` is set to the
/// original full key.  These correspond to `$1` and `$2` in the
/// expansion language.
pub fn eval_lookup(
    args: LookupArgs,
    evaluator: &mut Evaluator<'_>,
) -> Result<Option<String>, ExpandError> {
    // ── Step 1: Check expansion forbid flags ────────────────────────────
    // Replaces expand.c line 5211: if (expand_forbid & RDO_LOOKUP)
    if evaluator.expand_forbid & RDO_LOOKUP != 0 {
        return Err(ExpandError::Failed {
            message: "lookup expansions are not permitted".into(),
        });
    }

    // ── Step 2: Save evaluator state for restoration ────────────────────
    // Replaces expand.c lines 5205–5207:
    //   save_lookup_value  = lookup_value;
    //   save_expand_nmax   = expand_nmax;
    //   save_expand_nstring[i] = expand_nstring[i];
    let save_lookup_value = evaluator.lookup_value.clone();
    let save_expand_nstring = evaluator.expand_nstring.clone();
    let save_search_find_defer = evaluator.search_find_defer;

    // Reset the defer flag for this fresh lookup attempt.
    evaluator.search_find_defer = false;

    // ── Step 3: Delegate to inner implementation ────────────────────────
    let result = eval_lookup_dispatch(&args, evaluator);

    // ── Step 4: Restore state ───────────────────────────────────────────
    // Replaces expand.c lines 5352–5360:
    //   restore_expand_strings(save_expand_nmax, save_expand_nstring, ...);
    //   lookup_value = save_lookup_value;
    //
    // The expand_nstring array (partial match $1/$2 captures) is restored
    // because captures are only valid during the yes/no branch evaluation,
    // which the caller (evaluator.process_yesno) performs before we return.
    evaluator.expand_nstring = save_expand_nstring;

    // Restore the previous lookup_value ($value) so that nested lookups
    // do not interfere with outer scopes.
    evaluator.lookup_value = save_lookup_value;

    // The search_find_defer flag is intentionally NOT restored on success:
    // it must propagate upward so the caller knows that a lookup in this
    // expansion deferred.  On error, restore it to prevent stale flags.
    if result.is_err() {
        evaluator.search_find_defer = save_search_find_defer;
    }

    result
}

// =============================================================================
// Feature-gated dispatch — lookup-integration ENABLED
// =============================================================================

/// Resolve a lookup type name when lookup support is compiled in.
///
/// Calls `exim_lookups::search_findtype_partial()` to parse partial-match
/// modifiers, star flags, and the canonical driver name.  Converts the
/// exim-lookups `PartialLookupSpec` to the local [`PartialLookupSpec`] type
/// for the public API.
#[cfg(feature = "lookup-integration")]
fn resolve_lookup_type_dispatch(name: &str) -> Result<LookupTypeInfo, ExpandError> {
    use exim_lookups::search_findtype_partial;

    tracing::debug!(name = %name, "resolving lookup type");

    let spec = search_findtype_partial(name).map_err(|e| ExpandError::Failed {
        message: format!("unknown lookup type \"{}\" ({})", name, e),
    })?;

    tracing::debug!(
        driver = %spec.driver_name,
        partial_depth = spec.partial_depth,
        prefix = %spec.prefix,
        wildcard_key = spec.wildcard_key,
        star_at = spec.star_at,
        query_style = spec.lookup_type.is_query_style(),
        "lookup type resolved"
    );

    // The `ret=key` option is the only global option currently parsed by
    // search_findtype_partial into the spec.  Represent it in the options
    // field so the caller can see what global directives were active.
    let options = if spec.ret_key {
        Some("ret=key".to_string())
    } else {
        None
    };

    Ok(LookupTypeInfo {
        lookup_type: spec.lookup_type,
        partial_spec: PartialLookupSpec {
            partial_depth: spec.partial_depth,
            prefix: spec.prefix.clone(),
            suffix: spec.suffix.clone(),
            wildcard_key: spec.wildcard_key,
            star_at: spec.star_at,
        },
        options,
        driver_name: spec.driver_name.clone(),
    })
}

/// Perform the complete `${lookup …}` evaluation when lookup support is
/// compiled in.
///
/// Resolves the type, validates key/query style, opens the driver, executes
/// the find (with optional partial matching), and updates the evaluator
/// state with the result.
#[cfg(feature = "lookup-integration")]
fn eval_lookup_dispatch(
    args: &LookupArgs,
    evaluator: &mut Evaluator<'_>,
) -> Result<Option<String>, ExpandError> {
    use exim_lookups::{search_findtype, search_findtype_partial};

    tracing::debug!(
        lookup_type = %args.lookup_type,
        key = ?args.key,
        "evaluating ${{lookup}}"
    );

    // ── Step 1: Resolve lookup type with partial match options ───────────
    // Replaces expand.c lines 5232–5260: search_findtype_partial(name, …)
    let spec = search_findtype_partial(&args.lookup_type).map_err(|e| ExpandError::Failed {
        message: format!("unknown lookup type \"{}\" ({})", args.lookup_type, e),
    })?;

    let lookup_type = spec.lookup_type;

    // ── Step 2: Validate key/query style consistency ────────────────────
    // Replaces expand.c lines 5262–5279.
    validate_key_query_style(lookup_type, args)?;

    // ── Step 3: Determine effective key and filename ────────────────────
    // Replaces expand.c lines 5282–5310 and search_args() from search.c
    // lines 234–270.
    //
    // For single-key lookups:
    //   key      = the user-provided {key}
    //   filename = the {query_or_filename} (file path to search)
    //
    // For query-style lookups:
    //   key      = the {query_or_filename} (SQL query, LDAP filter, etc.)
    //   filename = None (no file; connection is established by the driver)
    let (key, filename): (String, Option<String>) = if lookup_type.is_single_key() {
        (
            args.key.clone().unwrap_or_default(),
            Some(args.query_or_filename.clone()),
        )
    } else {
        (args.query_or_filename.clone(), None)
    };

    // ── Step 4: Get driver factory and create driver instance ───────────
    // Replaces expand.c lines 5312–5315: search_open(filename, type, …)
    // uses the driver registry to locate the factory by canonical name.
    let factory = search_findtype(&spec.driver_name).ok_or_else(|| ExpandError::Failed {
        message: format!(
            "unknown lookup type \"{}\" — driver not available",
            spec.driver_name
        ),
    })?;
    let driver = (factory.create)();

    // ── Step 5: Open the lookup source ──────────────────────────────────
    // Replaces expand.c lines 5312–5320: search_open(filename, type, …)
    tracing::trace!(
        driver = %spec.driver_name,
        filename = ?filename,
        "opening lookup source"
    );

    let handle = driver
        .open(filename.as_deref())
        .map_err(|e| ExpandError::Failed {
            message: format!(
                "lookup open failed for type \"{}\": {}",
                spec.driver_name, e
            ),
        })?;

    // ── Step 6: Execute the lookup ──────────────────────────────────────
    // Replaces expand.c lines 5320–5350.
    // Partial matching is handled by perform_lookup_with_partial().
    tracing::trace!(
        driver = %spec.driver_name,
        key = %key,
        partial = spec.is_partial(),
        "executing lookup find"
    );

    let (result, matched_key) =
        perform_lookup_with_partial(&*driver, &handle, filename.as_deref(), &key, &spec)?;

    // ── Step 7: Process result and update evaluator state ────────────────
    let return_value = process_lookup_result(
        &result,
        &spec.driver_name,
        &key,
        matched_key.as_deref(),
        spec.ret_key,
        evaluator,
    );

    // Close the driver handle (releases file descriptors, connections, etc.).
    driver.close(handle);

    return_value
}

/// Validate that the key/query style is consistent with the lookup type.
///
/// Single-key lookups (lsearch, dbm, cdb, etc.) *require* a `{key}` argument.
/// Query-style lookups (mysql, pgsql, ldap, etc.) *must not* have a `{key}`.
///
/// Replaces expand.c lines 5262–5279.
#[cfg(feature = "lookup-integration")]
fn validate_key_query_style(lookup_type: LookupType, args: &LookupArgs) -> Result<(), ExpandError> {
    if lookup_type.is_single_key() && args.key.is_none() {
        return Err(ExpandError::Failed {
            message: format!(
                "missing {{key}} for single-key \"{}\" lookup",
                args.lookup_type
            ),
        });
    }

    if lookup_type.is_query_style() && args.key.is_some() {
        return Err(ExpandError::Failed {
            message: format!(
                "a single key was given for lookup type \"{}\", \
                 which is not a single-key lookup type",
                args.lookup_type
            ),
        });
    }

    Ok(())
}

/// Execute the lookup operation with optional partial matching.
///
/// Mirrors the combined logic of `search_find()` + `search_find_partial()`
/// from `search.c`.  Calls `LookupDriver::find()` directly (bypassing
/// the `SearchState` caching layer) for clean ownership semantics.
///
/// Returns `(LookupResult, Option<matched_key>)` where `matched_key` is
/// the key that actually produced the hit (may differ from the original
/// key when partial matching shortened it, or when `*@`/`*` fallback
/// was used).
#[cfg(feature = "lookup-integration")]
fn perform_lookup_with_partial(
    driver: &dyn exim_drivers::lookup_driver::LookupDriver,
    handle: &exim_drivers::lookup_driver::LookupHandle,
    filename: Option<&str>,
    key: &str,
    spec: &exim_lookups::PartialLookupSpec,
) -> Result<(exim_lookups::LookupResult, Option<String>), ExpandError> {
    use exim_lookups::LookupResult;

    // Guard: empty keys always fail — matches search_find() "insurance"
    // at search.c line 755.
    if key.is_empty() {
        tracing::debug!("empty lookup key — returning NotFound");
        return Ok((LookupResult::NotFound, None));
    }

    // ── Step 1: Exact match on the original key ─────────────────────────
    let exact_result = driver_find(driver, handle, filename, key)?;

    if exact_result.is_found() || exact_result.is_deferred() {
        return Ok((exact_result, Some(key.to_string())));
    }

    // ── Step 2: Partial matching (progressive domain shortening) ────────
    if spec.is_partial() {
        let candidates = spec.partial_key_sequence(key);

        tracing::trace!(
            num_candidates = candidates.len(),
            "trying partial match candidates"
        );

        for candidate in &candidates {
            tracing::trace!(candidate = %candidate, "trying partial candidate");

            let partial_result = driver_find(driver, handle, filename, candidate)?;

            if partial_result.is_found() || partial_result.is_deferred() {
                return Ok((partial_result, Some(candidate.clone())));
            }
        }
    }

    // ── Step 3: Try *@domain match (SEARCH_STARAT flag) ─────────────────
    if spec.star_at {
        if let Some(at_pos) = key.rfind('@') {
            if at_pos > 0 {
                let starat_key = format!("*{}", &key[at_pos..]);
                tracing::trace!(starat_key = %starat_key, "trying *@ match");

                let starat_result = driver_find(driver, handle, filename, &starat_key)?;

                if starat_result.is_found() || starat_result.is_deferred() {
                    return Ok((starat_result, Some(starat_key)));
                }
            }
        }
    }

    // ── Step 4: Try plain * match (SEARCH_STAR or SEARCH_STARAT) ────────
    if spec.has_star_flags() {
        tracing::trace!("trying * wildcard match");

        let star_result = driver_find(driver, handle, filename, "*")?;

        if star_result.is_found() || star_result.is_deferred() {
            return Ok((star_result, Some("*".to_string())));
        }
    }

    // No match found at any level.
    Ok((LookupResult::NotFound, None))
}

/// Thin wrapper around `LookupDriver::find()` that converts `DriverError`
/// into `ExpandError::Failed` for uniform error propagation.
#[cfg(feature = "lookup-integration")]
#[inline]
fn driver_find(
    driver: &dyn exim_drivers::lookup_driver::LookupDriver,
    handle: &exim_drivers::lookup_driver::LookupHandle,
    filename: Option<&str>,
    key: &str,
) -> Result<exim_lookups::LookupResult, ExpandError> {
    driver
        .find(handle, filename, key, None)
        .map_err(|e| ExpandError::Failed {
            message: format!("lookup find failed: {}", e),
        })
}

/// Process the result of a lookup operation and update the evaluator state.
///
/// Handles the three possible outcomes:
///   - **Found**: Sets `lookup_value` ($value) and optional `$1`/`$2`
///     partial-match captures.
///   - **NotFound**: Clears `lookup_value`; checks `forced_fail` flag.
///   - **Deferred**: Sets `search_find_defer` flag and returns
///     `ExpandError::LookupDefer`.
///
/// When `ret_key` is `true`, the returned value is the matched key rather
/// than the looked-up data value (C `ret=key` option in `search_find()`).
#[cfg(feature = "lookup-integration")]
fn process_lookup_result(
    result: &exim_lookups::LookupResult,
    driver_name: &str,
    original_key: &str,
    matched_key: Option<&str>,
    ret_key: bool,
    evaluator: &mut Evaluator<'_>,
) -> Result<Option<String>, ExpandError> {
    use exim_lookups::LookupResult;

    match result {
        LookupResult::Found { value, .. } => {
            // Determine the return value: either the looked-up data or the
            // matched key (when ret=key is active).
            let return_value = if ret_key {
                matched_key.unwrap_or(original_key).to_string()
            } else {
                value.clone()
            };

            tracing::debug!(
                driver = %driver_name,
                key = %original_key,
                value_len = return_value.len(),
                ret_key = ret_key,
                "lookup found"
            );

            // Set $value (lookup_value) for use in the {yes} branch.
            evaluator.lookup_value = Some(return_value.clone());

            // Set $1/$2 partial match captures if the matched key differs
            // from the original.  This replaces the expand_setup / expand_nmax
            // logic from expand.c lines 5352–5360.
            //
            //   $1 = the key that actually matched (shortened/wildcarded)
            //   $2 = the original full lookup key
            if let Some(mk) = matched_key {
                if mk != original_key {
                    evaluator.expand_nstring[1] = Some(mk.to_string());
                    evaluator.expand_nstring[2] = Some(original_key.to_string());
                }
            }

            Ok(Some(return_value))
        }

        LookupResult::NotFound => {
            tracing::debug!(
                driver = %driver_name,
                key = %original_key,
                "lookup not found"
            );

            evaluator.lookup_value = None;

            // Check if the evaluator's forced_fail flag was set during
            // lookup processing (e.g., by a nested expansion that triggered
            // a forced failure).
            if evaluator.forced_fail {
                return Err(ExpandError::ForcedFail);
            }

            Ok(None)
        }

        LookupResult::Deferred { message } => {
            tracing::warn!(
                driver = %driver_name,
                key = %original_key,
                message = %message,
                "lookup deferred"
            );

            evaluator.search_find_defer = true;

            Err(ExpandError::LookupDefer)
        }
    }
}

// =============================================================================
// Feature-gated dispatch — lookup-integration DISABLED
// =============================================================================

#[cfg(not(feature = "lookup-integration"))]
fn resolve_lookup_type_dispatch(name: &str) -> Result<LookupTypeInfo, ExpandError> {
    // Suppress "unused variable" warning when feature is disabled.
    let _ = name;
    Err(ExpandError::Failed {
        message: "\"${lookup\" encountered, but lookup support is not \
                  included in this binary"
            .into(),
    })
}

#[cfg(not(feature = "lookup-integration"))]
fn eval_lookup_dispatch(
    _args: &LookupArgs,
    _evaluator: &mut Evaluator<'_>,
) -> Result<Option<String>, ExpandError> {
    Err(ExpandError::Failed {
        message: "\"${lookup\" encountered, but lookup support is not \
                  included in this binary"
            .into(),
    })
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── PartialLookupSpec tests ─────────────────────────────────────────

    #[test]
    fn test_default_partial_spec_is_disabled() {
        let spec = PartialLookupSpec::default();
        assert!(!spec.is_partial(), "default spec should NOT be partial");
        assert!(
            !spec.has_star_flags(),
            "default spec should have no star flags"
        );
        assert_eq!(spec.partial_depth, -1);
        assert!(spec.prefix.is_empty());
        assert!(spec.suffix.is_empty());
    }

    #[test]
    fn test_partial_spec_enabled() {
        let spec = PartialLookupSpec {
            partial_depth: 2,
            prefix: "*.".to_string(),
            ..Default::default()
        };
        assert!(spec.is_partial(), "depth >= 0 should be partial");
        assert!(!spec.has_star_flags(), "no star flags set");
    }

    #[test]
    fn test_partial_spec_star_at() {
        let spec = PartialLookupSpec {
            star_at: true,
            ..Default::default()
        };
        assert!(spec.has_star_flags(), "star_at should set has_star_flags");
    }

    #[test]
    fn test_partial_spec_wildcard_key() {
        let spec = PartialLookupSpec {
            wildcard_key: true,
            ..Default::default()
        };
        assert!(
            spec.has_star_flags(),
            "wildcard_key should set has_star_flags"
        );
    }

    // ── LookupArgs tests ────────────────────────────────────────────────

    #[test]
    fn test_lookup_args_single_key() {
        let args = LookupArgs {
            key: Some("user".into()),
            lookup_type: "lsearch".into(),
            query_or_filename: "/etc/aliases".into(),
        };
        assert!(args.key.is_some());
        assert_eq!(args.lookup_type, "lsearch");
    }

    #[test]
    fn test_lookup_args_query_style() {
        let args = LookupArgs {
            key: None,
            lookup_type: "mysql".into(),
            query_or_filename: "SELECT 1".into(),
        };
        assert!(args.key.is_none());
        assert_eq!(args.lookup_type, "mysql");
    }

    // ── LookupTypeInfo tests ────────────────────────────────────────────

    #[test]
    fn test_lookup_type_info_construction() {
        let info = LookupTypeInfo {
            lookup_type: LookupType::NONE,
            partial_spec: PartialLookupSpec::default(),
            options: None,
            driver_name: "lsearch".to_string(),
        };
        assert_eq!(info.driver_name, "lsearch");
        assert!(info.options.is_none());
        assert!(!info.partial_spec.is_partial());
    }

    #[test]
    fn test_lookup_type_info_with_options() {
        let info = LookupTypeInfo {
            lookup_type: LookupType::NONE,
            partial_spec: PartialLookupSpec {
                partial_depth: 2,
                prefix: "*.".to_string(),
                suffix: String::new(),
                wildcard_key: false,
                star_at: true,
            },
            options: Some("ret=key".to_string()),
            driver_name: "dbm".to_string(),
        };
        assert_eq!(info.driver_name, "dbm");
        assert_eq!(info.options.as_deref(), Some("ret=key"));
        assert!(info.partial_spec.is_partial());
        assert!(info.partial_spec.star_at);
    }

    // ── eval_lookup forbid-flag test ────────────────────────────────────

    #[test]
    fn test_eval_lookup_forbidden() {
        let mut evaluator = Evaluator::new_default();
        evaluator.expand_forbid = RDO_LOOKUP;

        let args = LookupArgs {
            key: Some("test".into()),
            lookup_type: "lsearch".into(),
            query_or_filename: "/dev/null".into(),
        };

        let result = eval_lookup(args, &mut evaluator);
        assert!(result.is_err());
        match result {
            Err(ExpandError::Failed { message }) => {
                assert!(
                    message.contains("not permitted"),
                    "expected 'not permitted', got: {}",
                    message
                );
            }
            other => panic!("expected Failed, got: {:?}", other),
        }
    }

    #[test]
    fn test_eval_lookup_state_restored_after_forbid() {
        let mut evaluator = Evaluator::new_default();
        evaluator.expand_forbid = RDO_LOOKUP;
        evaluator.lookup_value = Some("original_value".into());
        evaluator.expand_nstring[1] = Some("original_n1".into());

        let args = LookupArgs {
            key: None,
            lookup_type: "mysql".into(),
            query_or_filename: "SELECT 1".into(),
        };

        // The forbid check happens BEFORE state save, so state should
        // remain unchanged.
        let _ = eval_lookup(args, &mut evaluator);

        assert_eq!(
            evaluator.lookup_value.as_deref(),
            Some("original_value"),
            "lookup_value should be unchanged after forbid error"
        );
        assert_eq!(
            evaluator.expand_nstring[1].as_deref(),
            Some("original_n1"),
            "expand_nstring[1] should be unchanged after forbid error"
        );
    }

    // ── resolve_lookup_type disabled test ────────────────────────────────

    #[cfg(not(feature = "lookup-integration"))]
    #[test]
    fn test_resolve_type_disabled() {
        let result = resolve_lookup_type("lsearch");
        assert!(result.is_err());
        match result {
            Err(ExpandError::Failed { message }) => {
                assert!(message.contains("not included"));
            }
            other => panic!("expected Failed, got: {:?}", other),
        }
    }

    // ── eval_lookup disabled test ───────────────────────────────────────

    #[cfg(not(feature = "lookup-integration"))]
    #[test]
    fn test_eval_lookup_disabled() {
        let mut evaluator = Evaluator::new_default();

        let args = LookupArgs {
            key: Some("test".into()),
            lookup_type: "lsearch".into(),
            query_or_filename: "/etc/passwd".into(),
        };

        let result = eval_lookup(args, &mut evaluator);
        assert!(result.is_err());
        match result {
            Err(ExpandError::Failed { message }) => {
                assert!(message.contains("not included"));
            }
            other => panic!("expected Failed, got: {:?}", other),
        }
    }
}
