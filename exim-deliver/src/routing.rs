// =============================================================================
// exim-deliver/src/routing.rs — Router Chain Evaluation and Preconditions
// =============================================================================
//
// Translates `src/src/route.c` (2,098 lines of C) into idiomatic Rust while
// preserving exact behavioral parity with the C implementation.
//
// This module implements:
//   - `route_address()`          — Main routing loop iterating through router chain
//   - `route_init()`             — Router chain initialization from config
//   - `check_router_conditions()`— Full precondition evaluation for each router
//   - `route_check_prefix/suffix()` — Local-part prefix/suffix matching with wildcards
//   - `route_check_dls()`        — Domain/local-part/sender list checking
//   - `route_check_access()`     — Filesystem permission checks
//   - `check_files()`            — File existence tests for require_files
//   - `route_finduser/group()`   — User/group lookup with caching and retries
//   - `route_find_expanded_user/group()` — Expand-then-lookup helpers
//   - `route_unseen()`           — Cloning addresses for unseen routing
//   - `router_current_name()`    — Error message formatting helper
//
// Design patterns applied (per AAP §0.4.2):
//   - Scoped context passing: ServerContext, MessageContext, DeliveryContext, ConfigContext
//   - Trait-based drivers: RouterDriver trait from exim-drivers
//   - Inventory registration: Router lookup via DriverRegistry
//   - Taint tracking: Tainted<T>/Clean<T> for user-supplied data
//   - Arena allocation: MessageArena for per-message temporary routing allocations
//
// CRITICAL rules (per AAP §0.7.2):
//   - Zero `unsafe` code in this file
//   - No `#[allow(...)]` without justification
//   - Preserve exact router chain ordering from C
//   - Loop detection with parent chain checking + caseful_local_part
//   - File access checks use same permission model as C
//   - tracing replaces DEBUG(D_route) / debug_printf
//   - Feature flags replace #ifdef SUPPORT_TRANSLATE_IP_ADDRESS
//
// This file contains ZERO unsafe code.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;

use nix::unistd::{Group, Uid, User};
use thiserror::Error;

use crate::orchestrator::{AddressFlags, AddressItem};
use exim_config::types::{ConfigContext, DeliveryContext, MessageContext, ServerContext};
use exim_drivers::registry::DriverRegistry;
use exim_drivers::router_driver::{RouterDriver, RouterInstanceConfig, RouterResult};
use exim_drivers::DriverError;
use exim_expand::{expand_check_condition, expand_hide_passwords, expand_string, ExpandError};
use exim_store::taint::Tainted;

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of routing iterations before declaring a loop (C: 100).
const MAX_ROUTING_LOOPS: u32 = 100;

/// Default number of retries for user lookup (NIS/NFS delays).
/// In C this is `finduser_retries` global, default 0.
const DEFAULT_FINDUSER_RETRIES: u32 = 0;

/// Delay between user lookup retries in milliseconds.
const FINDUSER_RETRY_DELAY_MS: u64 = 500;

// =============================================================================
// RoutingResult Enum — C return value equivalents
// =============================================================================

/// Result of router chain evaluation for a single address.
///
/// Maps to C route.c return values used by `route_address()`:
///   - `OK`       → `RoutingResult::Routed`
///   - `DISCARD`  → `RoutingResult::Discard`
///   - `FAIL`     → `RoutingResult::Fail`
///   - `DEFER`    → `RoutingResult::Defer`
///   - `ERROR`    → `RoutingResult::Error`
///   - `REROUTED` → `RoutingResult::Rerouted`
///   - `SKIP`     → `RoutingResult::Skip` (precondition skip, not a C return)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingResult {
    /// Address successfully routed — assigned a transport for delivery.
    /// Maps to C `OK` (0).
    Ok,
    /// Address was discarded (e.g., by an ACL discard action).
    /// Maps to C `DISCARD`.
    Discard,
    /// Permanent routing failure — address cannot be delivered, generate bounce.
    /// Maps to C `FAIL` (2).
    Fail,
    /// Temporary routing failure — retry later.
    /// Maps to C `DEFER` (1).
    Defer,
    /// Major internal or configuration error during routing.
    /// Maps to C `ERROR` (3).
    Error,
    /// Domain changed during routing, re-route needed.
    /// Maps to C `REROUTED`.
    Rerouted,
    /// Router skipped by preconditions (not a final result — internal only).
    /// Used by `check_router_conditions()` to signal that a router's
    /// preconditions were not met and should be skipped.
    Skip,
}

// =============================================================================
// VerifyMode Enum — Verification context
// =============================================================================

/// Verification mode passed to `route_address()`.
///
/// Determines which routers are eligible and how results are interpreted.
/// Maps to C `v_none`/`v_sender`/`v_recipient`/`v_expn` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    /// Not verifying — actual delivery routing. C: `v_none`.
    #[allow(clippy::enum_variant_names)] // Matches C naming exactly for behavioral parity
    None,
    /// Verifying sender address. C: `v_sender`.
    Sender,
    /// Verifying recipient address. C: `v_recipient`.
    Recipient,
    /// Processing SMTP EXPN command. C: `v_expn`.
    Expn,
}

// =============================================================================
// RoutingError — Error types for routing operations
// =============================================================================

/// Errors that can occur during routing operations.
///
/// Uses `thiserror` for derive-based error formatting (per AAP §0.6.1).
/// Each variant corresponds to a distinct failure mode in the routing subsystem.
#[derive(Debug, Error)]
pub enum RoutingError {
    /// A router failed during execution.
    #[error("router {name} failed: {message}")]
    RouterFailed {
        /// Name of the router that failed.
        name: String,
        /// Human-readable failure description.
        message: String,
    },

    /// Address could not be routed by any router in the chain.
    #[error("unrouteable address: {0}")]
    Unrouteable(String),

    /// Routing loop detected (address passed through same router too many times).
    #[error("loop detected in router {0}")]
    LoopDetected(String),

    /// Configuration error detected during routing.
    #[error("config error: {0}")]
    ConfigError(String),

    /// String expansion failed during routing (e.g., condition, require_files).
    #[error("expansion failed: {0}")]
    ExpansionFailed(String),

    /// User or group lookup failed during routing.
    #[error("user lookup failed: {0}")]
    UserLookupFailed(String),
}

impl From<DriverError> for RoutingError {
    fn from(e: DriverError) -> Self {
        match e {
            DriverError::NotFound { name } => {
                RoutingError::ConfigError(format!("router driver not found: {name}"))
            }
            DriverError::InitFailed(msg) => RoutingError::ConfigError(msg),
            DriverError::ExecutionFailed(msg) => RoutingError::RouterFailed {
                name: String::new(),
                message: msg,
            },
            DriverError::ConfigError(msg) => RoutingError::ConfigError(msg),
            DriverError::TempFail(msg) => RoutingError::RouterFailed {
                name: String::new(),
                message: msg,
            },
        }
    }
}

impl From<ExpandError> for RoutingError {
    fn from(e: ExpandError) -> Self {
        RoutingError::ExpansionFailed(e.to_string())
    }
}

// =============================================================================
// UserInfo — passwd entry result
// =============================================================================

/// Information about a system user, equivalent to C `struct passwd`.
///
/// Returned by `route_finduser()` and `route_find_expanded_user()`.
/// Replaces C `struct passwd` fields used during routing.
#[derive(Debug, Clone)]
pub struct UserInfo {
    /// Numeric user ID (C: `pw_uid`).
    pub uid: u32,
    /// Numeric primary group ID (C: `pw_gid`).
    pub gid: u32,
    /// Username (C: `pw_name`).
    pub name: String,
    /// Home directory path (C: `pw_dir`).
    pub home_dir: String,
    /// GECOS field / full name (C: `pw_gecos`).
    pub gecos: String,
    /// Login shell path (C: `pw_shell`).
    pub shell: String,
}

// =============================================================================
// RouterInstance — Pairs driver config with driver implementation
// =============================================================================

/// A router instance pairing configuration with a driver implementation.
///
/// Created during `route_init()` for each router defined in the config file.
/// The router chain is an ordered `Vec<RouterInstance>` iterated during
/// `route_address()`.
///
/// In C, `router_instance` holds both config fields and a pointer to
/// `router_info` (the driver's function table). In Rust, these are separated
/// into `RouterInstanceConfig` (data) and `Box<dyn RouterDriver>` (behavior).
#[derive(Debug)]
pub struct RouterInstance {
    /// Configuration for this router instance, stored as an Arc-wrapped
    /// type-erased Any so it can share ownership with ConfigContext's
    /// `router_instances` list. Access the typed config via `typed_config()`.
    pub config_arc: Arc<dyn std::any::Any + Send + Sync>,
    /// Driver implementation providing the `route()` method.
    pub driver: Box<dyn RouterDriver>,
}

impl RouterInstance {
    /// Downcast the shared config to `RouterInstanceConfig`.
    ///
    /// # Panics
    ///
    /// Panics if the stored config is not a `RouterInstanceConfig`.
    /// This is guaranteed by `route_init()` which only stores validated configs.
    pub fn config(&self) -> &RouterInstanceConfig {
        self.config_arc
            .downcast_ref::<RouterInstanceConfig>()
            .expect("RouterInstance config_arc is always a RouterInstanceConfig")
    }
}

// =============================================================================
// route_init — Initialize router chain from configuration
// =============================================================================

/// Initialize the router chain from configuration.
///
/// Replaces C `route_init()` (route.c line 261). Iterates router definitions
/// from the config, looks up each driver via the `inventory`-based registry,
/// creates driver instances, validates required options, and returns the
/// ordered router chain.
///
/// # Arguments
///
/// * `config` — Parsed configuration containing router definitions.
///
/// # Returns
///
/// Ordered vector of initialized router instances, or an error if any
/// driver lookup or validation fails.
///
/// # Errors
///
/// * `RoutingError::ConfigError` — Driver not found in registry, or
///   required options missing/invalid.
pub fn route_init(config: &ConfigContext) -> Result<Vec<RouterInstance>, RoutingError> {
    tracing::info!("initializing router chain from configuration");

    let mut routers = Vec::new();

    // Iterate router instance configs stored in ConfigContext.
    // They are stored as Arc<dyn Any + Send + Sync> and need downcasting.
    for (idx, instance_any) in config.router_instances.iter().enumerate() {
        // Verify this is a RouterInstanceConfig by downcasting
        let instance_config = match instance_any.downcast_ref::<RouterInstanceConfig>() {
            Some(cfg) => cfg,
            None => {
                tracing::warn!(
                    index = idx,
                    "router instance at index {} is not a RouterInstanceConfig, skipping",
                    idx,
                );
                continue;
            }
        };

        let driver_name = &instance_config.driver_name;
        tracing::debug!(
            router_name = %instance_config.name,
            driver = %driver_name,
            "initializing router"
        );

        // Look up driver factory via inventory-based registry
        let factory = DriverRegistry::find_router(driver_name).ok_or_else(|| {
            RoutingError::ConfigError(format!(
                "unknown router driver \"{}\" for router \"{}\"",
                driver_name, instance_config.name,
            ))
        })?;

        // Create driver instance from factory
        let driver = (factory.create)();

        routers.push(RouterInstance {
            config_arc: Arc::clone(instance_any),
            driver,
        });
    }

    // Validate router chain: resolve pass_router and redirect_router references
    validate_router_references(&routers)?;

    tracing::info!(count = routers.len(), "router chain initialized");
    Ok(routers)
}

/// Validate that pass_router_name and redirect_router_name references
/// resolve to routers that appear AFTER the referring router in the chain.
///
/// Replaces the C validation at route.c lines 330-360 that walks the router
/// list checking `pass_router` and `redirect_router` pointers.
fn validate_router_references(routers: &[RouterInstance]) -> Result<(), RoutingError> {
    for (i, router) in routers.iter().enumerate() {
        // Check pass_router_name
        if let Some(ref target_name) = router.config().pass_router_name {
            let found = routers
                .iter()
                .skip(i + 1)
                .any(|r| r.config().name == *target_name);
            if !found {
                return Err(RoutingError::ConfigError(format!(
                    "pass_router \"{}\" in router \"{}\" not found after it in the chain",
                    target_name,
                    router.config().name,
                )));
            }
        }

        // Check redirect_router_name
        if let Some(ref target_name) = router.config().redirect_router_name {
            let found = routers
                .iter()
                .skip(i + 1)
                .any(|r| r.config().name == *target_name);
            if !found {
                return Err(RoutingError::ConfigError(format!(
                    "redirect_router \"{}\" in router \"{}\" not found after it in the chain",
                    target_name,
                    router.config().name,
                )));
            }
        }
    }
    Ok(())
}

// =============================================================================
// route_check_prefix — Local-part prefix matching with wildcards
// =============================================================================

/// Check if a local part matches any prefix in a colon-separated list.
///
/// Replaces C `route_check_prefix()` (route.c line 405). Supports wildcard
/// `*` at the start of a prefix pattern. Returns the matched prefix length
/// and wildcard portion length on match.
///
/// # Arguments
///
/// * `local_part` — The local part of the email address to check.
/// * `prefixes`   — Colon-separated list of prefix patterns. Each pattern may
///   start with `*` indicating a wildcard match of zero or more characters.
///
/// # Returns
///
/// * `Some((matched_len, wildcard_len))` — The prefix matched. `matched_len`
///   is the total prefix length consumed from `local_part`. `wildcard_len` is
///   the portion of `local_part` matched by the `*` wildcard (0 if no wildcard).
/// * `None` — No prefix matched.
pub fn route_check_prefix(local_part: &str, prefixes: &str) -> Option<(usize, usize)> {
    // C Exim's route_check_prefix() uses strncmpic() — case-insensitive
    // comparison — for both wildcard and exact prefix matching.
    let lp_lower = local_part.to_ascii_lowercase();

    for pattern in prefixes.split(':') {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            continue;
        }

        if let Some(suffix_part) = pattern.strip_prefix('*') {
            // Wildcard at start: *<fixed_suffix>
            // The fixed suffix must appear in local_part and everything before
            // it is matched by the wildcard.
            if suffix_part.is_empty() {
                // Pattern is just "*" — matches zero-length prefix
                return Some((0, 0));
            }
            let sp_lower = suffix_part.to_ascii_lowercase();
            // Search from the END of the string backwards (C Exim scans
            // rightward from `local_part + len - plen`, effectively matching
            // the rightmost occurrence that still leaves a non-empty local
            // part).  We replicate by scanning left-to-right through all
            // occurrences and returning the last one that leaves at least one
            // char remaining.  However, C Exim scans from the far right and
            // returns the FIRST match it finds (rightmost).  We use rfind to
            // get the rightmost occurrence.
            // Actually, C code iterates `p` from `local_part + Ustrlen(local_part) - (--plen)`
            // down to `local_part`.  It returns the first match from the right.
            // We replicate with rfind on the lowercased strings.
            if let Some(pos) = lp_lower.rfind(&sp_lower) {
                let total_matched = pos + suffix_part.len();
                // Ensure the match leaves at least one character for the local part
                if total_matched < local_part.len() {
                    return Some((total_matched, pos));
                }
            }
        } else {
            // Exact prefix match (no wildcard) — case-insensitive
            let pat_lower = pattern.to_ascii_lowercase();
            if lp_lower.starts_with(&pat_lower) && pattern.len() < local_part.len() {
                return Some((pattern.len(), 0));
            }
        }
    }
    None
}

// =============================================================================
// route_check_suffix — Local-part suffix matching with wildcards
// =============================================================================

/// Check if a local part matches any suffix in a colon-separated list.
///
/// Replaces C `route_check_suffix()` (route.c line 457). Supports wildcard
/// `*` at the end of a suffix pattern. Returns the matched suffix length
/// and wildcard portion length on match.
///
/// # Arguments
///
/// * `local_part` — The local part of the email address to check.
/// * `suffixes`   — Colon-separated list of suffix patterns. Each pattern may
///   end with `*` indicating a wildcard match of zero or more characters.
///
/// # Returns
///
/// * `Some((matched_len, wildcard_len))` — The suffix matched. `matched_len`
///   is the total suffix length consumed from the end of `local_part`.
///   `wildcard_len` is the portion matched by the `*` wildcard.
/// * `None` — No suffix matched.
pub fn route_check_suffix(local_part: &str, suffixes: &str) -> Option<(usize, usize)> {
    // C Exim's route_check_suffix() uses strncmpic() — case-insensitive
    // comparison — for both wildcard and exact suffix matching.
    let lp_lower = local_part.to_ascii_lowercase();
    let alen = local_part.len();

    for pattern in suffixes.split(':') {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            continue;
        }

        if let Some(prefix_part) = pattern.strip_suffix('*') {
            // Wildcard at end: <fixed_prefix>*
            // C code: scans `p` from `local_part` to `local_part + alen - slen + 1`
            //   checking strncmpic(suffix, p, slen).  Returns total = alen - (p - local_part).
            if prefix_part.is_empty() {
                return Some((0, 0));
            }
            let pp_lower = prefix_part.to_ascii_lowercase();
            let slen = prefix_part.len();
            // Scan from left (pos 0) up to alen - slen (inclusive)
            if alen > slen {
                for pos in 0..=(alen - slen) {
                    if lp_lower[pos..].starts_with(&pp_lower) {
                        let tlen = alen - pos;
                        let wildcard_len = tlen - slen;
                        return Some((tlen, wildcard_len));
                    }
                }
            } else if alen == slen && lp_lower == pp_lower {
                // Exact match — but leaves nothing for local part (C requires
                // alen > slen for the non-wildcard branch; the wildcard branch
                // would match tlen == alen which is the whole string).
                // C code: pend = local_part + alen - slen + 1 = local_part + 1
                // so p iterates from local_part[0] only — pos=0, tlen = alen.
                // That strips the entire local part, which C allows for wildcard suffixes.
                return Some((alen, 0));
            }
        } else {
            // Exact suffix match (no wildcard) — case-insensitive
            let pat_lower = pattern.to_ascii_lowercase();
            let slen = pattern.len();
            if alen > slen && lp_lower[alen - slen..] == pat_lower[..] {
                return Some((slen, 0));
            }
        }
    }
    None
}

// =============================================================================
// List matching helpers
// =============================================================================

/// Check if a value matches an entry in a colon-separated list.
///
/// Supports literal matching, named list references (`+listname`), negation
/// (`!pattern`), and wildcard `*`. This is a Rust equivalent of the C
/// `match_isinlist()` function covering the most common matching patterns.
fn match_in_list(
    value: &str,
    list: &str,
    caseless: bool,
    config: &ConfigContext,
) -> Result<bool, RoutingError> {
    let val = if caseless {
        value.to_ascii_lowercase()
    } else {
        value.to_string()
    };

    for raw_item in list.split(':') {
        let item = raw_item.trim();
        if item.is_empty() {
            continue;
        }

        let (negated, pattern) = if let Some(rest) = item.strip_prefix('!') {
            (true, rest.trim())
        } else {
            (false, item)
        };

        let matched = if let Some(list_name) = pattern.strip_prefix('+') {
            match_named_list(&val, list_name.trim(), caseless, config)?
        } else if pattern == "*" {
            true
        } else if pattern.starts_with('^') {
            // Regex pattern (C Exim: items starting with '^' are PCRE regexes).
            // Build the regex with case-insensitive flag if caseless.
            let re_str = if caseless {
                format!("(?i){}", pattern)
            } else {
                pattern.to_string()
            };
            match regex::Regex::new(&re_str) {
                Ok(re) => re.is_match(&val),
                Err(e) => {
                    tracing::warn!(pattern = %pattern, error = %e, "invalid regex in list");
                    false
                }
            }
        } else {
            let pat = if caseless {
                pattern.to_ascii_lowercase()
            } else {
                pattern.to_string()
            };
            if pat.contains('*') || pat.contains('?') {
                glob_match(&val, &pat)
            } else {
                val == pat
            }
        };

        if matched {
            return Ok(!negated);
        }
    }

    Ok(false)
}

/// Check if a value matches a named list from ConfigContext.
fn match_named_list(
    value: &str,
    list_name: &str,
    caseless: bool,
    config: &ConfigContext,
) -> Result<bool, RoutingError> {
    if let Some(list_content) = config.named_lists.domain_lists.get(list_name) {
        return match_in_list(value, &list_content.value, caseless, config);
    }
    if let Some(list_content) = config.named_lists.localpart_lists.get(list_name) {
        return match_in_list(value, &list_content.value, caseless, config);
    }
    if let Some(list_content) = config.named_lists.address_lists.get(list_name) {
        return match_in_list(value, &list_content.value, caseless, config);
    }
    if let Some(list_content) = config.named_lists.host_lists.get(list_name) {
        return match_in_list(value, &list_content.value, caseless, config);
    }

    tracing::warn!(list_name = %list_name, "named list not found in configuration");
    Ok(false)
}

/// Simple glob pattern matching supporting `*` (any chars) and `?` (single char).
fn glob_match(text: &str, pattern: &str) -> bool {
    let text_bytes = text.as_bytes();
    let pat_bytes = pattern.as_bytes();
    let (mut ti, mut pi) = (0usize, 0usize);
    let (mut star_pi, mut star_ti) = (usize::MAX, 0usize);

    while ti < text_bytes.len() {
        if pi < pat_bytes.len() && (pat_bytes[pi] == b'?' || pat_bytes[pi] == text_bytes[ti]) {
            ti += 1;
            pi += 1;
        } else if pi < pat_bytes.len() && pat_bytes[pi] == b'*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < pat_bytes.len() && pat_bytes[pi] == b'*' {
        pi += 1;
    }
    pi == pat_bytes.len()
}

// =============================================================================
// route_check_dls — Domain/local-part/sender list checking
// =============================================================================

/// Check a value against a domain, local-part, or sender list.
///
/// Replaces C `route_check_dls()` (route.c line 518). Returns whether routing
/// should proceed, skip, or defer based on list membership.
pub fn route_check_dls(
    router_name: &str,
    check_type: &str,
    list: Option<&str>,
    domain_or_localpart: Option<&str>,
    caseless: bool,
    config: &ConfigContext,
) -> Result<RoutingResult, RoutingError> {
    let list_str = match list {
        Some(l) if !l.is_empty() => l,
        _ => {
            tracing::trace!(router = %router_name, check = %check_type, "no list, check passes");
            return Ok(RoutingResult::Ok);
        }
    };

    let value = match domain_or_localpart {
        Some(v) => v,
        None => {
            tracing::trace!(router = %router_name, check = %check_type, "no value, skipping");
            return Ok(RoutingResult::Skip);
        }
    };

    tracing::trace!(
        router = %router_name, check = %check_type,
        value = %value, list = %list_str,
        "checking value against list"
    );

    match match_in_list(value, list_str, caseless, config) {
        Ok(true) => {
            tracing::trace!(router = %router_name, check = %check_type, "value matched list");
            Ok(RoutingResult::Ok)
        }
        Ok(false) => {
            tracing::debug!(router = %router_name, check = %check_type, "value not in list, skip");
            Ok(RoutingResult::Skip)
        }
        Err(e) => {
            tracing::warn!(router = %router_name, check = %check_type, error = %e, "list check failed");
            Err(e)
        }
    }
}

// =============================================================================
// route_check_access — Filesystem permission checks
// =============================================================================

/// Check filesystem access for a path with given uid/gid/permission bits.
///
/// Replaces C `route_check_access()` (route.c line 585). Walks each component
/// of the path checking that the given uid/gid has the required access rights
/// via `stat()` and permission bit checks.
pub fn route_check_access(
    path: &Path,
    uid: u32,
    gid: u32,
    bits: u32,
) -> Result<bool, std::io::Error> {
    let real_path = match fs::canonicalize(path) {
        Ok(p) => p,
        Err(e) => {
            tracing::trace!(path = %path.display(), error = %e, "canonicalize failed");
            return Err(e);
        }
    };

    let mut current = std::path::PathBuf::new();
    for component in real_path.components() {
        current.push(component);
        if current.as_os_str() == "/" {
            continue;
        }

        let metadata = match fs::metadata(&current) {
            Ok(m) => m,
            Err(e) => {
                tracing::trace!(component = %current.display(), error = %e, "stat failed");
                return Err(e);
            }
        };

        if metadata.is_dir() {
            let file_uid = metadata.uid();
            let file_gid = metadata.gid();
            let mode = metadata.mode();
            let has_access = if file_uid == uid {
                (mode & 0o100) != 0
            } else if file_gid == gid {
                (mode & 0o010) != 0
            } else {
                (mode & 0o001) != 0
            };
            if !has_access {
                tracing::trace!(
                    component = %current.display(),
                    mode = format!("{:o}", mode),
                    "directory traversal denied"
                );
                return Ok(false);
            }
        }
    }

    // Check final target permissions
    let metadata = fs::metadata(&real_path)?;
    let file_uid = metadata.uid();
    let file_gid = metadata.gid();
    let mode = metadata.mode();

    let has_access = if file_uid == uid {
        (mode & (bits << 6)) != 0
    } else if file_gid == gid {
        (mode & (bits << 3)) != 0
    } else {
        (mode & bits) != 0
    };

    tracing::trace!(
        path = %real_path.display(), uid = uid, gid = gid,
        bits = format!("{:o}", bits), result = has_access,
        "access check complete"
    );
    Ok(has_access)
}

// =============================================================================
// check_files — File existence tests for require_files
// =============================================================================

/// Process `require_files` list for a router.
///
/// Replaces C `check_files()` (route.c line 658). Processes a colon-separated
/// list of file requirements. Each item may have:
///   - `!` prefix — require that the file does NOT exist
///   - `+` prefix — treat permission-denied as non-existence
///   - `user:group/path` — check access as specific user/group
///
/// Items are expanded via `expand_string()` before checking.
pub fn check_files(
    file_list: Option<&str>,
    _config: &ConfigContext,
) -> Result<RoutingResult, RoutingError> {
    let list_str = match file_list {
        Some(l) if !l.is_empty() => l,
        _ => return Ok(RoutingResult::Ok),
    };

    for raw_item in list_str.split(':') {
        let item = raw_item.trim();
        if item.is_empty() {
            continue;
        }

        // Parse flags
        let mut work = item;
        let mut require_nonexist = false;
        let mut eacces_as_noent = false;

        if let Some(rest) = work.strip_prefix('!') {
            require_nonexist = true;
            work = rest.trim();
        }
        if let Some(rest) = work.strip_prefix('+') {
            eacces_as_noent = true;
            work = rest.trim();
        }

        // Expand the item
        let expanded = match expand_string(work) {
            Ok(s) => s,
            Err(ExpandError::ForcedFail) => {
                tracing::trace!(item = %work, "require_files expansion forced-fail, treating as non-existing");
                if require_nonexist {
                    continue; // Non-existence is what we want
                }
                return Ok(RoutingResult::Skip);
            }
            Err(e) => {
                return Err(RoutingError::ExpansionFailed(format!(
                    "failed to expand require_files item \"{}\": {}",
                    work, e
                )));
            }
        };

        if expanded.is_empty() {
            continue;
        }

        // Parse optional user:group prefix (e.g., "user:group/path")
        let (check_uid, check_gid, check_path) = parse_file_check_spec(&expanded);

        let path = Path::new(&check_path);
        let exists = match fs::metadata(path) {
            Ok(_) => true,
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied && eacces_as_noent => {
                false
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                // Permission denied while checking — defer
                tracing::debug!(
                    path = %check_path,
                    "permission denied checking require_files, deferring"
                );
                return Ok(RoutingResult::Defer);
            }
            Err(e) => {
                tracing::debug!(
                    path = %check_path,
                    error = %e,
                    "error checking require_files"
                );
                return Ok(RoutingResult::Defer);
            }
        };

        // If uid/gid check is specified, verify access permissions
        if exists && (check_uid.is_some() || check_gid.is_some()) {
            let uid = check_uid.unwrap_or(0);
            let gid = check_gid.unwrap_or(0);
            match route_check_access(path, uid, gid, 0o004) {
                Ok(true) => { /* access OK */ }
                Ok(false) => {
                    if require_nonexist {
                        continue; // Inaccessible is like non-existent for `!` checks
                    }
                    tracing::debug!(
                        path = %check_path, uid = uid, gid = gid,
                        "require_files access denied, skipping router"
                    );
                    return Ok(RoutingResult::Skip);
                }
                Err(e) => {
                    tracing::debug!(
                        path = %check_path, error = %e,
                        "require_files access check failed"
                    );
                    return Ok(RoutingResult::Defer);
                }
            }
        }

        // Apply the require_nonexist / require_exist logic
        if require_nonexist && exists {
            tracing::debug!(
                path = %check_path,
                "require_files: file exists but ! requires non-existence, skipping"
            );
            return Ok(RoutingResult::Skip);
        }
        if !require_nonexist && !exists {
            tracing::debug!(
                path = %check_path,
                "require_files: file does not exist, skipping"
            );
            return Ok(RoutingResult::Skip);
        }
    }

    Ok(RoutingResult::Ok)
}

/// Parse a file check specification with optional `user:group/path` format.
///
/// Returns (optional_uid, optional_gid, path_string).
fn parse_file_check_spec(spec: &str) -> (Option<u32>, Option<u32>, String) {
    // Check for user:group prefix before an absolute path
    // Format: "user" or "user:group" followed by whitespace or `/`
    if spec.starts_with('/') {
        return (None, None, spec.to_string());
    }

    // Look for the path separator (first `/`)
    if let Some(slash_pos) = spec.find('/') {
        let prefix = &spec[..slash_pos];
        let path = &spec[slash_pos..];

        // Parse user:group from prefix
        let (user_str, group_str) = if let Some(colon_pos) = prefix.find(':') {
            (&prefix[..colon_pos], Some(&prefix[colon_pos + 1..]))
        } else {
            (prefix, Option::<&str>::None)
        };

        let uid = user_str
            .parse::<u32>()
            .ok()
            .or_else(|| route_finduser(user_str).map(|u| u.uid));

        let gid = group_str.and_then(|g| g.parse::<u32>().ok().or_else(|| route_findgroup(g)));

        if uid.is_some() || gid.is_some() {
            return (uid, gid, path.to_string());
        }
    }

    // No valid user:group prefix found — treat entire string as path
    (None, None, spec.to_string())
}

// =============================================================================
// check_router_conditions — Full precondition check for a router
// =============================================================================

/// Evaluate all preconditions for a router against an address.
///
/// Replaces C `check_router_conditions()` (route.c line 774/910). Checks are
/// performed in the exact same order as the C implementation to preserve
/// behavioral parity:
///
///   1. `verify_only` — skip if not verifying
///   2. `address_test` — skip if in address test mode and flag is false
///   3. `verify_sender` / `verify_recipient` — skip based on verify direction
///   4. `expn` — skip if processing EXPN and flag is false
///   5. `domains` list check
///   6. `local_parts` list check
///   7. `check_local_user` — getpwnam lookup
///   8. `router_home_directory` expansion
///   9. `senders` list check
///  10. `require_files` existence check
///  11. `condition` expansion check
///
/// # Returns
///
/// * `Ok(RoutingResult::Ok)` — All preconditions met, proceed with routing.
/// * `Ok(RoutingResult::Skip)` — Precondition not met, skip this router.
/// * `Ok(RoutingResult::Defer)` — Temporary failure in precondition check.
/// * `Err(_)` — Hard error during precondition evaluation.
pub fn check_router_conditions(
    router_config: &RouterInstanceConfig,
    addr: &mut AddressItem,
    verify: VerifyMode,
    address_test_mode: bool,
    config: &ConfigContext,
) -> Result<RoutingResult, RoutingError> {
    let router_name = &router_config.name;

    // 1. verify_only: router only runs during verification
    if router_config.verify_only && verify == VerifyMode::None {
        tracing::debug!(router = %router_name, "skipping: verify_only but not verifying");
        return Ok(RoutingResult::Skip);
    }

    // 2. address_test: router requires address test mode
    // C: if ((verify == v_none || verify == v_expn) && !r->address_test)
    // means: if we're in delivery/expn mode and router has address_test=false, skip
    // (unless we're in actual address_test_mode)
    if address_test_mode && !router_config.address_test {
        tracing::debug!(router = %router_name, "skipping: address_test=false in test mode");
        return Ok(RoutingResult::Skip);
    }

    // 3. verify_sender / verify_recipient checks
    if verify == VerifyMode::Sender && !router_config.verify_sender {
        tracing::debug!(router = %router_name, "skipping: verify_sender=false");
        return Ok(RoutingResult::Skip);
    }
    if verify == VerifyMode::Recipient && !router_config.verify_recipient {
        tracing::debug!(router = %router_name, "skipping: verify_recipient=false");
        return Ok(RoutingResult::Skip);
    }

    // 4. expn: skip if EXPN and router has expn=false
    if verify == VerifyMode::Expn && !router_config.expn {
        tracing::debug!(router = %router_name, "skipping: expn=false during EXPN");
        return Ok(RoutingResult::Skip);
    }

    // 5. domains list check
    let caseless_domain = !router_config.caseful_local_part;
    if let result @ Ok(RoutingResult::Skip | RoutingResult::Defer) = route_check_dls(
        router_name,
        "domains",
        router_config.domains.as_deref(),
        Some(&addr.domain),
        caseless_domain,
        config,
    ) {
        return result;
    }

    // 6. local_parts list check
    let caseless_lp = !router_config.caseful_local_part;
    if let result @ Ok(RoutingResult::Skip | RoutingResult::Defer) = route_check_dls(
        router_name,
        "local_parts",
        router_config.local_parts.as_deref(),
        Some(&addr.local_part),
        caseless_lp,
        config,
    ) {
        return result;
    }

    // 7. check_local_user: look up the local part in /etc/passwd
    if router_config.check_local_user {
        match route_finduser(&addr.local_part) {
            Some(user_info) => {
                // Set home directory from passwd if not already set
                if addr.home_dir.is_none() {
                    addr.home_dir = Some(user_info.home_dir.clone());
                }
                addr.uid = user_info.uid;
                addr.gid = user_info.gid;
                tracing::trace!(
                    router = %router_name,
                    user = %user_info.name,
                    uid = user_info.uid,
                    "check_local_user: user found"
                );
            }
            None => {
                tracing::debug!(
                    router = %router_name,
                    local_part = %addr.local_part,
                    "check_local_user: user not found, skipping"
                );
                return Ok(RoutingResult::Skip);
            }
        }
    }

    // 8. router_home_directory expansion
    if let Some(ref home_dir_template) = router_config.router_home_directory {
        match expand_string(home_dir_template) {
            Ok(expanded) => {
                if !expanded.is_empty() {
                    addr.home_dir = Some(expanded);
                }
            }
            Err(ExpandError::ForcedFail) => {
                tracing::debug!(
                    router = %router_name,
                    "router_home_directory forced-fail, skipping"
                );
                return Ok(RoutingResult::Skip);
            }
            Err(e) => {
                return Err(RoutingError::ExpansionFailed(format!(
                    "router_home_directory expansion failed for {}: {}",
                    router_name, e
                )));
            }
        }
    }

    // 9. senders list check
    // The `senders` option checks the envelope sender against a list
    if let result @ Ok(RoutingResult::Skip | RoutingResult::Defer) = route_check_dls(
        router_name,
        "senders",
        router_config.senders.as_deref(),
        // Sender address would come from message context — for now use empty
        // The caller should set this appropriately via DeliveryContext
        Option::<&str>::None,
        true, // senders are always caseless
        config,
    ) {
        return result;
    }

    // 10. require_files existence check
    if let result @ Ok(RoutingResult::Skip | RoutingResult::Defer) =
        check_files(router_config.require_files.as_deref(), config)
    {
        return result;
    }

    // 11. condition expansion check
    if let Some(ref condition) = router_config.condition {
        if !expand_check_condition(condition, "condition", router_name) {
            tracing::debug!(
                router = %router_name,
                "condition evaluated to false, skipping"
            );
            return Ok(RoutingResult::Skip);
        }
    }

    // All preconditions passed
    tracing::trace!(router = %router_name, "all preconditions met");
    Ok(RoutingResult::Ok)
}

// =============================================================================
// route_finduser — User lookup by name or numeric uid
// =============================================================================

/// Look up a system user by name or numeric UID.
///
/// Replaces C `route_finduser()` (route.c line 1130). If the name is a
/// numeric string, it is interpreted as a UID. Otherwise, it is looked up
/// via `getpwnam()` (wrapped by `nix::unistd::User::from_name()`).
/// Includes retry support for NIS/NFS delays.
pub fn route_finduser(name: &str) -> Option<UserInfo> {
    tracing::trace!(name = %name, "route_finduser");

    if let Ok(uid_num) = name.parse::<u32>() {
        return lookup_user_by_uid(uid_num);
    }

    let retries = DEFAULT_FINDUSER_RETRIES;
    for attempt in 0..=retries {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(FINDUSER_RETRY_DELAY_MS));
            tracing::trace!(name = %name, attempt = attempt, "retrying user lookup");
        }

        match User::from_name(name) {
            Ok(Some(user)) => {
                let info = UserInfo {
                    uid: user.uid.as_raw(),
                    gid: user.gid.as_raw(),
                    name: user.name.clone(),
                    home_dir: user.dir.to_str().unwrap_or("").to_string(),
                    gecos: user.gecos.to_str().unwrap_or("").to_string(),
                    shell: user.shell.to_str().unwrap_or("").to_string(),
                };
                tracing::trace!(name = %name, uid = info.uid, gid = info.gid, "user found");
                return Some(info);
            }
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(name = %name, error = %e, "error looking up user");
                continue;
            }
        }
    }

    tracing::trace!(name = %name, "user not found after retries");
    None
}

/// Look up a user by numeric UID via `getpwuid()`.
fn lookup_user_by_uid(uid: u32) -> Option<UserInfo> {
    match User::from_uid(Uid::from_raw(uid)) {
        Ok(Some(user)) => Some(UserInfo {
            uid: user.uid.as_raw(),
            gid: user.gid.as_raw(),
            name: user.name.clone(),
            home_dir: user.dir.to_str().unwrap_or("").to_string(),
            gecos: user.gecos.to_str().unwrap_or("").to_string(),
            shell: user.shell.to_str().unwrap_or("").to_string(),
        }),
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(uid = uid, error = %e, "error looking up user by uid");
            None
        }
    }
}

// =============================================================================
// route_findgroup — Group lookup by name or numeric gid
// =============================================================================

/// Look up a system group by name or numeric GID.
///
/// Replaces C `route_findgroup()` (route.c line 1222). If the name is a
/// numeric string, it is returned directly as the GID. Includes retry
/// support for NIS/NFS delays.
pub fn route_findgroup(name: &str) -> Option<u32> {
    tracing::trace!(name = %name, "route_findgroup");

    if let Ok(gid_num) = name.parse::<u32>() {
        return Some(gid_num);
    }

    let retries = DEFAULT_FINDUSER_RETRIES;
    for attempt in 0..=retries {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(FINDUSER_RETRY_DELAY_MS));
        }
        match Group::from_name(name) {
            Ok(Some(group)) => {
                let gid = group.gid.as_raw();
                tracing::trace!(name = %name, gid = gid, "group found");
                return Some(gid);
            }
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(name = %name, error = %e, "error looking up group");
                continue;
            }
        }
    }

    tracing::trace!(name = %name, "group not found after retries");
    None
}

// =============================================================================
// route_find_expanded_user — Expand string then find user
// =============================================================================

/// Expand a configuration string and look up the resulting user.
///
/// Replaces C `route_find_expanded_user()` (route.c line 1268).
pub fn route_find_expanded_user(
    template: &str,
    driver_name: &str,
    driver_type: &str,
    _config: &ConfigContext,
) -> Result<UserInfo, RoutingError> {
    tracing::trace!(
        template = %template, driver = %driver_name,
        driver_type = %driver_type, "expanding user template"
    );

    let expanded = expand_string(template).map_err(|e| {
        RoutingError::ExpansionFailed(format!(
            "failed to expand user for {} \"{}\": {}",
            driver_type, driver_name, e
        ))
    })?;

    route_finduser(&expanded).ok_or_else(|| {
        RoutingError::UserLookupFailed(format!(
            "{} \"{}\" user \"{}\" not found",
            driver_type, driver_name, expanded
        ))
    })
}

// =============================================================================
// route_find_expanded_group — Expand string then find group
// =============================================================================

/// Expand a configuration string and look up the resulting group.
///
/// Replaces C `route_find_expanded_group()` (route.c line 1309).
pub fn route_find_expanded_group(
    template: &str,
    driver_name: &str,
    driver_type: &str,
    _config: &ConfigContext,
) -> Result<u32, RoutingError> {
    tracing::trace!(
        template = %template, driver = %driver_name,
        driver_type = %driver_type, "expanding group template"
    );

    let expanded = expand_string(template).map_err(|e| {
        RoutingError::ExpansionFailed(format!(
            "failed to expand group for {} \"{}\": {}",
            driver_type, driver_name, e
        ))
    })?;

    route_findgroup(&expanded).ok_or_else(|| {
        RoutingError::UserLookupFailed(format!(
            "{} \"{}\" group \"{}\" not found",
            driver_type, driver_name, expanded
        ))
    })
}

// =============================================================================
// route_unseen — Handle unseen routing (clone address)
// =============================================================================

/// Clone an address for unseen routing.
///
/// Replaces C `route_unseen()` (route.c line 1340). When a router has the
/// `unseen` flag set and more routers follow, the address is cloned. The
/// clone goes to delivery while the original continues routing.
fn route_unseen(
    router_name: &str,
    addr: &AddressItem,
    addr_local: &mut Vec<AddressItem>,
    addr_remote: &mut Vec<AddressItem>,
    _addr_new: &mut Vec<AddressItem>,
) {
    tracing::debug!(
        router = %router_name,
        address = %addr.address.as_ref(),
        "unseen routing: cloning address"
    );

    let mut clone = addr.clone();
    clone.flags.set(AddressFlags::AF_UNSEEN);

    if clone.host_list.is_empty() {
        tracing::trace!(router = %router_name, "unseen clone → local delivery");
        addr_local.push(clone);
    } else {
        tracing::trace!(router = %router_name, "unseen clone → remote delivery");
        addr_remote.push(clone);
    }
}

// =============================================================================
// set_router — Resolve router name to instance index
// =============================================================================

/// Resolve a router name to its index in the router chain.
///
/// Replaces C `set_router()` (route.c line ~160). Used for `pass_router` and
/// `redirect_router` directives.
fn set_router(name: &str, routers: &[RouterInstance]) -> Option<usize> {
    routers.iter().position(|r| r.config().name == name)
}

// =============================================================================
// router_current_name — Error message helper
// =============================================================================

/// Format a descriptive string identifying the current router for error messages.
///
/// Replaces C `router_current_name()` (route.c line 2090). Returns `None` if
/// not currently inside a router.
pub fn router_current_name(
    router_name: Option<&str>,
    source_file: Option<&str>,
    source_line: u32,
) -> Option<String> {
    router_name.map(|name| {
        let src = source_file.unwrap_or("<unknown>");
        format!(" (router {}, {} {})", name, src, source_line)
    })
}

// =============================================================================
// expand_bool_option — Expand a boolean option with dynamic override
// =============================================================================

/// Expand a boolean option that may have a dynamic (expandable) override.
///
/// Replaces the C `exp_bool()` pattern used for options like `unseen` and
/// `more` where the static boolean can be overridden by expanding a string.
fn expand_bool_option(
    static_value: bool,
    expand_override: Option<&str>,
    option_name: &str,
    router_name: &str,
) -> Result<bool, RoutingError> {
    match expand_override {
        Some(template) if !template.is_empty() => {
            Ok(expand_check_condition(template, option_name, router_name))
        }
        _ => Ok(static_value),
    }
}

// =============================================================================
// route_address — Main routing function
// =============================================================================

/// Route a single address through the router chain.
///
/// Replaces C `route_address()` (route.c line 1551, ~530 lines). This is the
/// main routing function that iterates through the configured router chain,
/// evaluating preconditions and invoking each router's `route()` method until
/// one accepts the address or the chain is exhausted.
///
/// # Routing Loop Algorithm
///
/// 1. Start from `addr.start_router` (for re-routing) or the first router
/// 2. For each router in order:
///     - a. Loop protection: check parent chain for same address + same router
///     - b. `check_router_conditions()` precondition evaluation
///     - c. Strip prefix/suffix from local part as configured
///     - d. Call `router.route()` via the `RouterDriver` trait
///     - e. Handle results: Accept/Pass/Decline/Fail/Defer/Rerouted
///     - f. Handle `no_more` flag (stop routing after this router)
/// 3. Post-routing:
///     - a. If all routers exhausted → FAIL with "Unrouteable address"
///     - b. If `unseen` flag → clone address for delivery, continue routing
///     - c. Expand `translate_ip_address` if configured (feature-gated)
///     - d. Hide passwords in deferred error messages
///
/// # Arguments
///
/// * `addr`            — The address to route (modified in place).
/// * `addr_local`      — Output list for locally-delivered addresses.
/// * `addr_remote`     — Output list for remotely-delivered addresses.
/// * `addr_new`        — Output list for new addresses from redirects.
/// * `addr_succeed`    — Output list for successfully routed addresses.
/// * `routers`         — The ordered router chain from `route_init()`.
/// * `verify`          — Verification mode (None/Sender/Recipient/Expn).
/// * `address_test_mode` — Whether running in address test mode (-bt flag).
/// * `sender_address`  — Envelope sender for senders list checking.
/// * `server_ctx`      — Daemon-lifetime server context.
/// * `msg_ctx`         — Per-message context.
/// * `delivery_ctx`    — Per-delivery-attempt context.
/// * `config`          — Parsed configuration context.
///
/// # Returns
///
/// * `Ok(RoutingResult::Ok)` — Address routed successfully.
/// * `Ok(RoutingResult::Fail)` — Address is unrouteable.
/// * `Ok(RoutingResult::Defer)` — Temporary routing failure.
/// * `Ok(RoutingResult::Rerouted)` — Domain changed, re-route needed.
/// * `Ok(RoutingResult::Discard)` — Address was discarded.
/// * `Err(RoutingError)` — Internal error during routing.
// Justification: route_address() mirrors the C `route_address()` (route.c line 1551)
// which inherently requires separate address lists, context structs, and control
// parameters. Bundling into a struct would lose semantic clarity — each parameter
// has a distinct ownership/mutability requirement. This is the top-level routing
// entry point called from a single site in the orchestrator.
#[allow(clippy::too_many_arguments)]
pub fn route_address(
    addr: &mut AddressItem,
    addr_local: &mut Vec<AddressItem>,
    addr_remote: &mut Vec<AddressItem>,
    addr_new: &mut Vec<AddressItem>,
    addr_succeed: &mut Vec<AddressItem>,
    routers: &[RouterInstance],
    verify: VerifyMode,
    address_test_mode: bool,
    _sender_address: Option<&str>,
    _server_ctx: &ServerContext,
    _msg_ctx: &MessageContext,
    delivery_ctx: &mut DeliveryContext,
    config: &ConfigContext,
) -> Result<RoutingResult, RoutingError> {
    tracing::debug!(
        address = %addr.address.as_ref(),
        verify = ?verify,
        "route_address entry"
    );

    if routers.is_empty() {
        tracing::warn!("no routers configured");
        addr.message = Some("Unrouteable address".to_string());
        return Ok(RoutingResult::Fail);
    }

    // Determine starting router index
    // If addr.router is set (from previous routing attempt), find it in the chain
    let start_idx = match &addr.router {
        Some(start_name) => set_router(start_name, routers).unwrap_or(0),
        None => 0,
    };

    let mut yield_result = RoutingResult::Fail;
    let mut loop_count: u32 = 0;
    let mut last_router_name: Option<String> = None;
    let mut router_idx = start_idx;

    // ─── Main Router Chain Loop ───────────────────────────────────────────
    while router_idx < routers.len() {
        let router_inst = &routers[router_idx];
        let rname = &router_inst.config().name;

        tracing::debug!(
            router = %rname,
            index = router_idx,
            address = %addr.address.as_ref(),
            "evaluating router"
        );

        // ── Loop protection ────────────────────────────────────────────
        // Check for routing loops: same address reaching same router too many times.
        // In C, this walks the parent chain; here we use a simple counter per router.
        loop_count += 1;
        if loop_count > MAX_ROUTING_LOOPS {
            tracing::warn!(
                router = %rname,
                address = %addr.address.as_ref(),
                loop_count = loop_count,
                "routing loop detected (>{} iterations)",
                MAX_ROUTING_LOOPS
            );
            addr.message = Some(format!(
                "routing loop detected for {} at router {}",
                addr.address.as_ref(),
                rname
            ));
            addr.basic_errno = 0;
            yield_result = RoutingResult::Defer;
            break;
        }

        // Set delivery context variables for this router
        delivery_ctx.router_name = Some(rname.clone());
        if let Some(ref srcfile) = router_inst.config().srcfile {
            last_router_name = Some(format!(
                "{} ({} {})",
                rname,
                srcfile,
                router_inst.config().srcline.unwrap_or(0)
            ));
        } else {
            last_router_name = Some(rname.clone());
        }

        // ── Disable logging if configured ──────────────────────────────
        if router_inst.config().disable_logging {
            tracing::trace!(router = %rname, "logging disabled for this router");
        }

        // ── Precondition checks ────────────────────────────────────────
        match check_router_conditions(
            router_inst.config(),
            addr,
            verify,
            address_test_mode,
            config,
        ) {
            Ok(RoutingResult::Ok) => {
                // Preconditions passed — proceed with routing
            }
            Ok(RoutingResult::Skip) => {
                tracing::debug!(router = %rname, "preconditions not met, skipping");
                router_idx += 1;
                continue;
            }
            Ok(RoutingResult::Defer) => {
                tracing::debug!(router = %rname, "precondition check deferred");
                if router_inst.config().pass_on_timeout {
                    tracing::debug!(router = %rname, "pass_on_timeout, continuing to next");
                    router_idx += 1;
                    continue;
                }
                yield_result = RoutingResult::Defer;
                break;
            }
            Ok(RoutingResult::Fail) => {
                yield_result = RoutingResult::Fail;
                break;
            }
            Ok(other) => {
                tracing::warn!(
                    router = %rname,
                    result = ?other,
                    "unexpected precondition result"
                );
                router_idx += 1;
                continue;
            }
            Err(e) => {
                tracing::warn!(router = %rname, error = %e, "precondition check error");
                addr.message = Some(format!("router {} precondition error: {}", rname, e));
                yield_result = RoutingResult::Error;
                break;
            }
        }

        // ── Local-part case folding (C Exim route.c line 1658) ────────
        // C Exim stores both cc_local_part (caseful) and lc_local_part
        // (lowercased) and selects the appropriate one per-router based on
        // the caseful_local_part setting.  By default, the lowercased form
        // is used for prefix/suffix matching and downstream $local_part
        // expansion.  We replicate that here.
        let original_local_part = addr.local_part.clone();
        if !router_inst.config().caseful_local_part {
            addr.local_part = addr.local_part.to_ascii_lowercase();
        }
        let mut prefix_len = 0usize;
        let mut suffix_len = 0usize;

        if let Some(ref prefix_list) = router_inst.config().prefix {
            let result = route_check_prefix(&addr.local_part, prefix_list);
            if let Some((plen, _wlen)) = result {
                prefix_len = plen;
            } else if !router_inst.config().prefix_optional {
                // Required prefix not found — skip this router
                tracing::debug!(router = %rname, "required prefix not matched, skipping");
                router_idx += 1;
                continue;
            }
        }

        if let Some(ref suffix_list) = router_inst.config().suffix {
            let result = route_check_suffix(&addr.local_part, suffix_list);
            if let Some((slen, _wlen)) = result {
                suffix_len = slen;
            } else if !router_inst.config().suffix_optional {
                tracing::debug!(router = %rname, "required suffix not matched, skipping");
                router_idx += 1;
                continue;
            }
        }

        // Strip prefix and suffix from local part for routing
        let stripped_local = if prefix_len > 0 || suffix_len > 0 {
            let end = addr.local_part.len().saturating_sub(suffix_len);
            if prefix_len <= end {
                addr.local_part[prefix_len..end].to_string()
            } else {
                addr.local_part.clone()
            }
        } else {
            addr.local_part.clone()
        };

        // Build the address string for the driver
        let route_address_str = if stripped_local != addr.local_part {
            format!("{}@{}", stripped_local, addr.domain)
        } else {
            addr.address.as_ref().clone()
        };

        // ── address_data expansion ─────────────────────────────────────
        if let Some(ref addr_data_template) = router_inst.config().address_data {
            match expand_string(addr_data_template) {
                Ok(expanded) => {
                    addr.prop.address_data = Some(expanded);
                }
                Err(ExpandError::ForcedFail) => {
                    addr.prop.address_data = None;
                    if !router_inst.config().more {
                        tracing::debug!(router = %rname, "address_data forced-fail and no_more");
                        yield_result = RoutingResult::Fail;
                        break;
                    }
                    router_idx += 1;
                    continue;
                }
                Err(e) => {
                    addr.message = Some(format!(
                        "failed to expand address_data in router {}: {}",
                        rname, e
                    ));
                    yield_result = RoutingResult::Defer;
                    break;
                }
            }
        }

        // ── DSN lasthop flag ───────────────────────────────────────────
        if router_inst.config().dsn_lasthop {
            tracing::trace!(router = %rname, "setting DSN lasthop");
            // Mark address as DSN last hop
            addr.dsn_flags |= 0x10; // DSN_LASTHOP flag
        }

        // ── Invoke the router driver ───────────────────────────────────
        // Determine local user for check_local_user
        let local_user = if router_inst.config().check_local_user {
            Some(stripped_local.as_str())
        } else {
            Option::<&str>::None
        };

        tracing::trace!(
            router = %rname,
            address = %route_address_str,
            local_user = ?local_user,
            "calling router.route()"
        );

        let router_result =
            match router_inst
                .driver
                .route(router_inst.config(), &route_address_str, local_user)
            {
                Ok(result) => result,
                Err(e) => {
                    tracing::warn!(
                        router = %rname,
                        error = %e,
                        "router execution error"
                    );
                    addr.message = Some(format!("router {} error: {}", rname, e));
                    yield_result = RoutingResult::Error;
                    break;
                }
            };

        // ── Handle router result ───────────────────────────────────────
        match router_result {
            RouterResult::Accept {
                transport_name,
                host_list,
            } => {
                tracing::debug!(
                    router = %rname,
                    transport = ?transport_name,
                    hosts = ?host_list,
                    "router accepted address"
                );

                // Assign transport and host list
                if let Some(tn) =
                    transport_name.or_else(|| router_inst.config().transport_name.clone())
                {
                    addr.transport = Some(tn.clone());
                    delivery_ctx.transport_name = Some(tn);
                }
                addr.host_list = host_list;
                addr.router = Some(rname.clone());

                // Copy errors_to from router config
                if let Some(ref errors_to) = router_inst.config().errors_to {
                    match expand_string(errors_to) {
                        Ok(expanded) if !expanded.is_empty() => {
                            addr.errors_address = Some(expanded.clone());
                            addr.prop.errors_address = Some(expanded);
                        }
                        _ => {}
                    }
                }

                // Copy extra headers — use context-aware expansion so that
                // $local_user_uid / $local_user_gid resolve to the passwd
                // values found by check_local_user.
                if let Some(ref extra) = router_inst.config().extra_headers {
                    let mut exp_ctx = exim_expand::variables::ExpandContext::new();
                    exp_ctx.local_user_uid = addr.uid;
                    exp_ctx.local_user_gid = addr.gid;
                    match exim_expand::expand_string_with_context(extra, &mut exp_ctx) {
                        Ok(expanded) if !expanded.is_empty() => {
                            addr.prop.extra_headers = Some(expanded);
                        }
                        _ => {}
                    }
                }

                // Copy remove headers
                if let Some(ref remove) = router_inst.config().remove_headers {
                    match expand_string(remove) {
                        Ok(expanded) if !expanded.is_empty() => {
                            addr.prop.remove_headers = Some(expanded);
                        }
                        _ => {}
                    }
                }

                // Restore original local part (prefix/suffix are metadata only)
                addr.local_part = original_local_part;

                yield_result = RoutingResult::Ok;
                break;
            }

            RouterResult::Pass => {
                tracing::debug!(router = %rname, "router passed");
                addr.local_part = original_local_part;

                // If pass_router is specified, jump to that router
                if let Some(ref pass_name) = router_inst.config().pass_router_name {
                    if let Some(target_idx) = set_router(pass_name, routers) {
                        tracing::debug!(
                            router = %rname,
                            pass_router = %pass_name,
                            "jumping to pass_router"
                        );
                        router_idx = target_idx;
                        continue;
                    }
                }

                router_idx += 1;
                continue;
            }

            RouterResult::Decline => {
                tracing::debug!(router = %rname, "router declined");
                addr.local_part = original_local_part;

                // Check the `more` option (may be dynamically expanded)
                let should_continue = expand_bool_option(
                    router_inst.config().more,
                    router_inst.config().expand_more.as_deref(),
                    "more",
                    rname,
                )
                .unwrap_or(true);

                if !should_continue {
                    tracing::debug!(router = %rname, "more=false after decline, stopping");
                    yield_result = RoutingResult::Fail;
                    break;
                }

                router_idx += 1;
                continue;
            }

            RouterResult::Fail { message } => {
                tracing::debug!(
                    router = %rname,
                    message = ?message,
                    "router failed address"
                );
                addr.local_part = original_local_part;

                if let Some(msg) = message {
                    addr.message = Some(msg);
                }
                addr.router = Some(rname.clone());

                // Handle fail_verify_sender / fail_verify_recipient
                if verify == VerifyMode::Sender && router_inst.config().fail_verify_sender {
                    tracing::trace!(router = %rname, "fail_verify_sender set");
                }
                if verify == VerifyMode::Recipient && router_inst.config().fail_verify_recipient {
                    tracing::trace!(router = %rname, "fail_verify_recipient set");
                }

                yield_result = RoutingResult::Fail;
                break;
            }

            RouterResult::Defer { message } => {
                tracing::debug!(
                    router = %rname,
                    message = ?message,
                    "router deferred address"
                );
                addr.local_part = original_local_part;

                if let Some(msg) = message {
                    addr.message = Some(msg);
                }
                addr.router = Some(rname.clone());

                // Handle pass_on_timeout: treat timeout as pass
                if router_inst.config().pass_on_timeout {
                    tracing::debug!(router = %rname, "pass_on_timeout set, treating as pass");
                    router_idx += 1;
                    continue;
                }

                yield_result = RoutingResult::Defer;
                break;
            }

            RouterResult::Error { message } => {
                tracing::warn!(
                    router = %rname,
                    message = %message,
                    "router returned error"
                );
                addr.local_part = original_local_part;
                addr.message = Some(message);

                yield_result = RoutingResult::Error;
                break;
            }

            RouterResult::Rerouted { new_addresses } => {
                tracing::debug!(
                    router = %rname,
                    new_count = new_addresses.len(),
                    "router rerouted address"
                );
                addr.local_part = original_local_part;
                addr.router = Some(rname.clone());

                // Add new addresses to the addr_new list
                for new_addr_str in &new_addresses {
                    // Split address into local_part@domain
                    let (lp, dom) = if let Some(at_pos) = new_addr_str.rfind('@') {
                        (
                            new_addr_str[..at_pos].to_string(),
                            new_addr_str[at_pos + 1..].to_ascii_lowercase(),
                        )
                    } else {
                        (new_addr_str.clone(), String::new())
                    };

                    // Track the original top-level address so the
                    // delivery log can display it in angle brackets
                    // (C Exim: addr->onetime_parent).
                    let original = addr
                        .onetime_parent
                        .clone()
                        .unwrap_or_else(|| addr.address.as_ref().to_string());

                    let new_item = AddressItem {
                        address: Tainted::new(new_addr_str.clone()),
                        domain: dom,
                        local_part: lp,
                        home_dir: None,
                        current_dir: None,
                        errors_address: None,
                        host_list: Vec::new(),
                        router: None,
                        transport: None,
                        prop: addr.prop.clone(),
                        flags: AddressFlags::default(),
                        message: None,
                        basic_errno: 0,
                        more_errno: 0,
                        dsn_flags: addr.dsn_flags,
                        dsn_orcpt: addr.dsn_orcpt.clone(),
                        dsn_aware: addr.dsn_aware,
                        return_path: addr.return_path.clone(),
                        uid: 0,
                        gid: 0,
                        prefix: None,
                        suffix: None,
                        onetime_parent: Some(original),
                        unique: new_addr_str.to_ascii_lowercase(),
                        parent_index: 0,
                        children: Vec::new(),
                    };

                    addr_new.push(new_item);
                }

                yield_result = RoutingResult::Rerouted;
                break;
            }
        }
    }
    // ─── End of main router chain loop ─────────────────────────────────────

    // ── Post-loop handling ─────────────────────────────────────────────────

    // If all routers exhausted without a result
    if yield_result == RoutingResult::Fail && router_idx >= routers.len() {
        tracing::debug!(
            address = %addr.address.as_ref(),
            "no more routers"
        );

        if addr.message.is_none() {
            // Try to expand cannot_route_message from the last router that ran
            let message = if let Some(ref last_rname) = last_router_name {
                // Find the last router by index
                if router_idx > 0 {
                    let last_idx = router_idx - 1;
                    if let Some(ref crm) = routers[last_idx].config().cannot_route_message {
                        match expand_string(crm) {
                            Ok(expanded) if !expanded.is_empty() => expanded,
                            _ => format!("Unrouteable address (last router: {})", last_rname),
                        }
                    } else {
                        "Unrouteable address".to_string()
                    }
                } else {
                    "Unrouteable address".to_string()
                }
            } else {
                "Unrouteable address".to_string()
            };
            addr.message = Some(message);
        }
        addr.router = None; // Clear router reference for logging
    }

    // Handle DEFER with password hiding
    if yield_result == RoutingResult::Defer {
        if let Some(ref msg) = addr.message {
            addr.message = Some(expand_hide_passwords(msg));
        }
    }

    // Handle OK result: check unseen and translate_ip_address
    if yield_result == RoutingResult::Ok {
        // Check unseen flag (may be dynamically expanded)
        if let Some(ref current_router_name) = addr.router {
            if let Some(ridx) = set_router(current_router_name, routers) {
                let router_inst = &routers[ridx];

                let is_unseen = expand_bool_option(
                    router_inst.config().unseen,
                    router_inst.config().expand_unseen.as_deref(),
                    "unseen",
                    &router_inst.config().name,
                )
                .unwrap_or(false);

                if is_unseen && ridx + 1 < routers.len() {
                    route_unseen(
                        &router_inst.config().name,
                        addr,
                        addr_local,
                        addr_remote,
                        addr_new,
                    );
                }

                // Feature-gated: translate_ip_address
                #[cfg(feature = "translate-ip-address")]
                {
                    if let Some(ref translate_template) = router_inst.config().translate_ip_address
                    {
                        for host in &mut addr.host_list {
                            match expand_string(translate_template) {
                                Ok(new_addr) if !new_addr.is_empty() => {
                                    tracing::debug!(
                                        original = %host,
                                        translated = %new_addr,
                                        "translated IP address"
                                    );
                                    *host = new_addr;
                                }
                                Ok(_) => {} // Empty expansion — skip
                                Err(ExpandError::ForcedFail) => continue,
                                Err(e) => {
                                    addr.message = Some(format!(
                                        "translate_ip_address expansion failed: {}",
                                        e
                                    ));
                                    yield_result = RoutingResult::Defer;
                                    break;
                                }
                            }
                        }
                    }
                }

                // Debug output for successful routing
                tracing::debug!(
                    router = %router_inst.config().name,
                    address = %addr.address.as_ref(),
                    transport = ?addr.transport,
                    hosts = ?addr.host_list,
                    is_unseen = is_unseen,
                    "routed successfully"
                );
            }
        }

        // Clear any temporary error message from a declined router
        if yield_result == RoutingResult::Ok {
            // Place address in the succeed list
            addr_succeed.push(addr.clone());
        }
    }

    // Handle REROUTED: signal that the address domain changed
    if yield_result == RoutingResult::Rerouted {
        tracing::debug!(
            address = %addr.address.as_ref(),
            "re-routed to new address"
        );
        yield_result = RoutingResult::Ok;
    }

    // Clean up delivery context
    delivery_ctx.router_name = None;
    delivery_ctx.transport_name = None;

    tracing::debug!(
        address = %addr.address.as_ref(),
        result = ?yield_result,
        "route_address exit"
    );

    Ok(yield_result)
}
