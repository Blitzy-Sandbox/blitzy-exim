// =============================================================================
// exim-routers/src/helpers/ugid.rs — UID/GID Resolution and Assignment
// =============================================================================
//
// Translates the C helper functions `rf_get_ugid()` from
// `src/src/routers/rf_get_ugid.c` (82 lines) and `rf_set_ugid()` from
// `src/src/routers/rf_set_ugid.c` (48 lines).
//
// These helpers handle resolving uid/gid values for router instances and
// copying them onto address items for use by local transports (appendfile,
// pipe, etc.).
//
// ## C Behavior Preserved
//
// `rf_get_ugid()` resolves uid/gid for a router from three sources (in priority):
//   1. Fixed numeric uid/gid from router config (`rblock->uid`, `rblock->gid`)
//   2. Expandable uid/gid strings (`rblock->expand_uid`, `rblock->expand_gid`)
//      that are expanded at route time and optionally looked up via getpwnam(3)
//   3. If uid is set but gid is not, the gid is taken from the passwd entry
//      of the user lookup (if one occurred), or an error is returned
//
// `rf_set_ugid()` copies resolved uid/gid/initgroups from a `UgidBlock` into
// an address item, setting the corresponding flags.
//
// ## Memory Safety
//
// This file contains ZERO unsafe code (per AAP §0.7.2). User lookups use the
// `nix` crate's safe POSIX wrappers.

use nix::unistd::{Group, User};
use std::fmt;
use thiserror::Error;
use tracing::debug;

// =============================================================================
// UgidBlock — UID/GID Configuration Block
// =============================================================================

/// UID/GID configuration block for a router instance.
///
/// Translates the C `ugid_block` struct from `structs.h`:
/// ```c
/// typedef struct ugid_block {
///   uid_t   uid;
///   gid_t   gid;
///   BOOL    uid_set;
///   BOOL    gid_set;
///   BOOL    initgroups;
/// } ugid_block;
/// ```
///
/// This struct is filled in by [`get_ugid()`] from router instance configuration
/// and then applied to an address item by [`set_ugid()`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UgidBlock {
    /// Numeric user ID for the delivery process.
    pub uid: u32,

    /// Numeric group ID for the delivery process.
    pub gid: u32,

    /// Whether `uid` has been explicitly set (from fixed config or expansion).
    pub uid_set: bool,

    /// Whether `gid` has been explicitly set (from fixed config or expansion).
    pub gid_set: bool,

    /// Whether to call `initgroups(3)` to initialize the supplementary group
    /// list for the delivery process. Maps to C `ugid->initgroups` and the
    /// `af_initgroups` address flag.
    pub initgroups: bool,
}

// Default derived automatically — all fields are zero/false.

impl fmt::Display for UgidBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UgidBlock(uid={}{}, gid={}{}, initgroups={})",
            self.uid,
            if self.uid_set { " [set]" } else { "" },
            self.gid,
            if self.gid_set { " [set]" } else { "" },
            self.initgroups,
        )
    }
}

// =============================================================================
// Router UID/GID Configuration
// =============================================================================

/// Router instance UID/GID configuration fields.
///
/// Extracts the uid/gid-related fields from C `router_instance` that
/// `rf_get_ugid()` reads. Routers populate this from their parsed
/// configuration options.
#[derive(Debug, Clone, Default)]
pub struct RouterUgidConfig {
    /// Fixed numeric UID from router config (`rblock->uid` in C).
    pub uid: u32,

    /// Fixed numeric GID from router config (`rblock->gid` in C).
    pub gid: u32,

    /// Whether a fixed UID was set in the configuration (`rblock->uid_set`).
    pub uid_set: bool,

    /// Whether a fixed GID was set in the configuration (`rblock->gid_set`).
    pub gid_set: bool,

    /// Whether to initialize supplementary groups (`rblock->initgroups`).
    pub initgroups: bool,

    /// Expandable UID string from router config (`rblock->expand_uid`).
    /// When present and `uid_set` is false, this string is expanded at route
    /// time and optionally looked up as a username via getpwnam(3).
    pub expand_uid: Option<String>,

    /// Expandable GID string from router config (`rblock->expand_gid`).
    /// When present and `gid_set` is false, this string is expanded at route
    /// time and optionally looked up as a group name via getgrnam(3).
    pub expand_gid: Option<String>,

    /// Router driver name, used in error messages.
    pub router_name: String,
}

// =============================================================================
// Address UID/GID Fields
// =============================================================================

/// Address item UID/GID fields that [`set_ugid()`] populates.
///
/// Translates the uid/gid-related fields from C `address_item`:
/// ```c
/// addr->uid        = ugid->uid;
/// addr->gid        = ugid->gid;
/// setflag(addr, af_uid_set);
/// setflag(addr, af_gid_set);
/// setflag(addr, af_initgroups);
/// ```
#[derive(Debug, Clone, Default)]
pub struct AddressUgid {
    /// Numeric user ID for the delivery process.
    pub uid: u32,

    /// Numeric group ID for the delivery process.
    pub gid: u32,

    /// Whether `uid` has been explicitly set on this address.
    pub uid_set: bool,

    /// Whether `gid` has been explicitly set on this address.
    pub gid_set: bool,

    /// Whether to initialize supplementary groups for this address.
    pub initgroups: bool,
}

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during UID/GID resolution.
///
/// Translates the C error paths in `rf_get_ugid()` where `addr->message` is
/// set and FALSE is returned.
#[derive(Debug, Error)]
pub enum UgidError {
    /// The expanded UID string could not be resolved to a user.
    /// C equivalent: `route_find_expanded_user()` returning FALSE.
    #[error("failed to resolve expanded uid '{expanded}' for {router} router: {reason}")]
    UidResolutionFailed {
        /// The expanded UID string that failed to resolve.
        expanded: String,
        /// The router name for error context.
        router: String,
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// The expanded GID string could not be resolved to a group.
    /// C equivalent: `route_find_expanded_group()` returning FALSE.
    #[error("failed to resolve expanded gid '{expanded}' for {router} router: {reason}")]
    GidResolutionFailed {
        /// The expanded GID string that failed to resolve.
        expanded: String,
        /// The router name for error context.
        router: String,
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// A UID was set but no GID was available (neither fixed, expanded, nor
    /// from a passwd entry). C equivalent: `"user set without group for %s router"`.
    #[error("user set without group for {router} router")]
    UidWithoutGid {
        /// The router name for error context.
        router: String,
    },
}

// =============================================================================
// get_ugid — Resolve UID/GID for a Router
// =============================================================================

/// Resolve UID/GID values for a router instance, filling in a [`UgidBlock`].
///
/// This function translates `rf_get_ugid()` from `src/src/routers/rf_get_ugid.c`.
///
/// The resolution process follows this priority chain:
/// 1. Copy fixed uid/gid/initgroups from the router configuration
/// 2. If no fixed uid is set but `expand_uid` is configured, expand and
///    resolve it (either as a numeric UID or a username via getpwnam)
/// 3. If no fixed gid is set but `expand_gid` is configured, expand and
///    resolve it (either as a numeric GID or a group name via getgrnam)
/// 4. If uid is set but gid is not, attempt to use the gid from the passwd
///    entry looked up during uid expansion; error if no passwd entry exists
///
/// # Arguments
///
/// * `config` — Router instance UID/GID configuration fields
/// * `expand_fn` — A callback to expand configuration strings at route time.
///   Takes a string template and returns the expanded result, or an error
///   message. This replaces the C `expand_string()` call.
///
/// # Returns
///
/// * `Ok(UgidBlock)` — Successfully resolved uid/gid configuration
/// * `Err(UgidError)` — Resolution failed (e.g., unknown user, uid without gid)
///
/// # Examples
///
/// ```rust,ignore
/// let config = RouterUgidConfig {
///     uid: 1000,
///     uid_set: true,
///     gid: 1000,
///     gid_set: true,
///     initgroups: false,
///     expand_uid: None,
///     expand_gid: None,
///     router_name: "local_delivery".to_string(),
/// };
///
/// let ugid = get_ugid(&config, |s| Ok(s.to_string()))?;
/// assert_eq!(ugid.uid, 1000);
/// assert!(ugid.uid_set);
/// ```
pub fn get_ugid<F>(config: &RouterUgidConfig, expand_fn: F) -> Result<UgidBlock, UgidError>
where
    F: Fn(&str) -> Result<String, String>,
{
    // Step 1: Initialize from fixed values (C: ugid->uid = rblock->uid, etc.)
    let mut ugid = UgidBlock {
        uid: config.uid,
        gid: config.gid,
        uid_set: config.uid_set,
        gid_set: config.gid_set,
        initgroups: config.initgroups,
    };

    // Track whether a passwd entry was found during uid expansion, so we can
    // fall back to its gid if needed (C: `struct passwd *upw = NULL`)
    let mut passwd_gid: Option<u32> = None;

    // Step 2: If no fixed uid, try expanding expand_uid
    // C: if (!ugid->uid_set && rblock->expand_uid) { ... }
    if !ugid.uid_set {
        if let Some(ref expand_uid_template) = config.expand_uid {
            let expanded = expand_fn(expand_uid_template).map_err(|reason| {
                UgidError::UidResolutionFailed {
                    expanded: expand_uid_template.clone(),
                    router: config.router_name.clone(),
                    reason,
                }
            })?;

            debug!(
                router = %config.router_name,
                expanded_uid = %expanded,
                "resolving expanded uid"
            );

            // Try to parse as numeric UID first, then fall back to username lookup.
            // This mirrors C `route_find_expanded_user()` which tries string_to_uid()
            // first, then getpwnam().
            match resolve_uid(&expanded) {
                Ok((uid, opt_gid)) => {
                    ugid.uid = uid;
                    ugid.uid_set = true;
                    passwd_gid = opt_gid;
                    debug!(
                        router = %config.router_name,
                        uid = uid,
                        passwd_gid = ?opt_gid,
                        "uid resolved successfully"
                    );
                }
                Err(reason) => {
                    return Err(UgidError::UidResolutionFailed {
                        expanded: expanded.clone(),
                        router: config.router_name.clone(),
                        reason,
                    });
                }
            }
        }
    }

    // Step 3: If no fixed gid, try expanding expand_gid
    // C: if (!ugid->gid_set && rblock->expand_gid) { ... }
    if !ugid.gid_set {
        if let Some(ref expand_gid_template) = config.expand_gid {
            let expanded = expand_fn(expand_gid_template).map_err(|reason| {
                UgidError::GidResolutionFailed {
                    expanded: expand_gid_template.clone(),
                    router: config.router_name.clone(),
                    reason,
                }
            })?;

            debug!(
                router = %config.router_name,
                expanded_gid = %expanded,
                "resolving expanded gid"
            );

            // Try numeric GID first, then group name lookup.
            // Mirrors C `route_find_expanded_group()`.
            match resolve_gid(&expanded) {
                Ok(gid) => {
                    ugid.gid = gid;
                    ugid.gid_set = true;
                    debug!(
                        router = %config.router_name,
                        gid = gid,
                        "gid resolved successfully"
                    );
                }
                Err(reason) => {
                    return Err(UgidError::GidResolutionFailed {
                        expanded: expanded.clone(),
                        router: config.router_name.clone(),
                        reason,
                    });
                }
            }
        }
    }

    // Step 4: If uid is set but gid is not, use passwd entry gid or error.
    // C: if (ugid->uid_set && !ugid->gid_set) { if (upw) ugid->gid = upw->pw_gid; else error }
    if ugid.uid_set && !ugid.gid_set {
        if let Some(gid_from_passwd) = passwd_gid {
            ugid.gid = gid_from_passwd;
            ugid.gid_set = true;
            debug!(
                router = %config.router_name,
                gid = gid_from_passwd,
                "gid taken from passwd entry of resolved uid"
            );
        } else {
            return Err(UgidError::UidWithoutGid {
                router: config.router_name.clone(),
            });
        }
    }

    Ok(ugid)
}

// =============================================================================
// set_ugid — Copy UID/GID from UgidBlock to Address Fields
// =============================================================================

/// Copy resolved UID/GID values from a [`UgidBlock`] into address UID/GID fields.
///
/// This function translates `rf_set_ugid()` from `src/src/routers/rf_set_ugid.c`.
///
/// Only copies values that are explicitly set in the ugid block. The
/// corresponding `*_set` flags are also set on the address, along with
/// the `initgroups` flag.
///
/// # Arguments
///
/// * `addr_ugid` — Mutable reference to the address item's UID/GID fields
/// * `ugid` — The resolved UID/GID block to copy from
///
/// # Examples
///
/// ```rust,ignore
/// let ugid = UgidBlock {
///     uid: 1000, gid: 1000, uid_set: true, gid_set: true, initgroups: true,
/// };
/// let mut addr = AddressUgid::default();
/// set_ugid(&mut addr, &ugid);
/// assert_eq!(addr.uid, 1000);
/// assert!(addr.uid_set);
/// assert!(addr.initgroups);
/// ```
pub fn set_ugid(addr_ugid: &mut AddressUgid, ugid: &UgidBlock) {
    // C: if (ugid->uid_set) { addr->uid = ugid->uid; setflag(addr, af_uid_set); }
    if ugid.uid_set {
        addr_ugid.uid = ugid.uid;
        addr_ugid.uid_set = true;
    }

    // C: if (ugid->gid_set) { addr->gid = ugid->gid; setflag(addr, af_gid_set); }
    if ugid.gid_set {
        addr_ugid.gid = ugid.gid;
        addr_ugid.gid_set = true;
    }

    // C: if (ugid->initgroups) setflag(addr, af_initgroups);
    if ugid.initgroups {
        addr_ugid.initgroups = true;
    }
}

// =============================================================================
// Internal Resolution Helpers
// =============================================================================

/// Resolve a UID from a string that may be numeric or a username.
///
/// Mirrors C `route_find_expanded_user()`:
///   1. Try parsing as numeric UID
///   2. Fall back to username lookup via `getpwnam(3)`
///
/// Returns `(uid, Option<gid>)` — the gid is only populated when the resolution
/// came from a passwd entry (username lookup), providing a fallback gid.
fn resolve_uid(expanded: &str) -> Result<(u32, Option<u32>), String> {
    let trimmed = expanded.trim();

    // Try numeric UID first (C: string_to_uid)
    if let Ok(numeric_uid) = trimmed.parse::<u32>() {
        return Ok((numeric_uid, None));
    }

    // Fall back to username lookup via getpwnam (C: getpwnam)
    match User::from_name(trimmed) {
        Ok(Some(user)) => {
            let uid = user.uid.as_raw();
            let gid = user.gid.as_raw();
            Ok((uid, Some(gid)))
        }
        Ok(None) => Err(format!("unknown user '{trimmed}'")),
        Err(e) => Err(format!("user lookup failed for '{trimmed}': {e}")),
    }
}

/// Resolve a GID from a string that may be numeric or a group name.
///
/// Mirrors C `route_find_expanded_group()`:
///   1. Try parsing as numeric GID
///   2. Fall back to group name lookup via `getgrnam(3)`
fn resolve_gid(expanded: &str) -> Result<u32, String> {
    let trimmed = expanded.trim();

    // Try numeric GID first (C: string_to_gid)
    if let Ok(numeric_gid) = trimmed.parse::<u32>() {
        return Ok(numeric_gid);
    }

    // Fall back to group name lookup via getgrnam (C: getgrnam)
    match Group::from_name(trimmed) {
        Ok(Some(group)) => Ok(group.gid.as_raw()),
        Ok(None) => Err(format!("unknown group '{trimmed}'")),
        Err(e) => Err(format!("group lookup failed for '{trimmed}': {e}")),
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Identity expansion function for testing — returns the input unchanged.
    fn identity_expand(s: &str) -> Result<String, String> {
        Ok(s.to_string())
    }

    /// Failing expansion function for testing — always returns an error.
    fn failing_expand(_s: &str) -> Result<String, String> {
        Err("expansion forced failure".to_string())
    }

    // ── UgidBlock tests ─────────────────────────────────────────────────────

    #[test]
    fn test_ugid_block_default() {
        let ugid = UgidBlock::default();
        assert_eq!(ugid.uid, 0);
        assert_eq!(ugid.gid, 0);
        assert!(!ugid.uid_set);
        assert!(!ugid.gid_set);
        assert!(!ugid.initgroups);
    }

    #[test]
    fn test_ugid_block_display() {
        let ugid = UgidBlock {
            uid: 1000,
            gid: 1000,
            uid_set: true,
            gid_set: true,
            initgroups: true,
        };
        let display = format!("{ugid}");
        assert!(display.contains("uid=1000"));
        assert!(display.contains("[set]"));
        assert!(display.contains("initgroups=true"));
    }

    // ── get_ugid tests with fixed values ────────────────────────────────────

    #[test]
    fn test_get_ugid_fixed_values() {
        let config = RouterUgidConfig {
            uid: 1000,
            gid: 1000,
            uid_set: true,
            gid_set: true,
            initgroups: true,
            expand_uid: None,
            expand_gid: None,
            router_name: "test_router".to_string(),
        };

        let ugid = get_ugid(&config, identity_expand).unwrap();
        assert_eq!(ugid.uid, 1000);
        assert_eq!(ugid.gid, 1000);
        assert!(ugid.uid_set);
        assert!(ugid.gid_set);
        assert!(ugid.initgroups);
    }

    #[test]
    fn test_get_ugid_no_values_set() {
        let config = RouterUgidConfig {
            uid: 0,
            gid: 0,
            uid_set: false,
            gid_set: false,
            initgroups: false,
            expand_uid: None,
            expand_gid: None,
            router_name: "test_router".to_string(),
        };

        let ugid = get_ugid(&config, identity_expand).unwrap();
        assert!(!ugid.uid_set);
        assert!(!ugid.gid_set);
    }

    #[test]
    fn test_get_ugid_expand_numeric_uid_and_gid() {
        let config = RouterUgidConfig {
            uid: 0,
            gid: 0,
            uid_set: false,
            gid_set: false,
            initgroups: false,
            expand_uid: Some("65534".to_string()),
            expand_gid: Some("65534".to_string()),
            router_name: "test_router".to_string(),
        };

        let ugid = get_ugid(&config, identity_expand).unwrap();
        assert_eq!(ugid.uid, 65534);
        assert!(ugid.uid_set);
        assert_eq!(ugid.gid, 65534);
        assert!(ugid.gid_set);
    }

    #[test]
    fn test_get_ugid_uid_set_without_gid_fails() {
        // uid is set via fixed value, but gid is not set and no expand_gid.
        // No passwd entry either (since uid was fixed, not expanded from username).
        let config = RouterUgidConfig {
            uid: 1000,
            gid: 0,
            uid_set: true,
            gid_set: false,
            initgroups: false,
            expand_uid: None,
            expand_gid: None,
            router_name: "test_router".to_string(),
        };

        let result = get_ugid(&config, identity_expand);
        assert!(result.is_err());
        match result.unwrap_err() {
            UgidError::UidWithoutGid { router } => {
                assert_eq!(router, "test_router");
            }
            other => panic!("expected UidWithoutGid, got: {other}"),
        }
    }

    #[test]
    fn test_get_ugid_expand_uid_numeric_without_gid_fails() {
        // Numeric expand_uid resolves but provides no passwd entry gid fallback.
        let config = RouterUgidConfig {
            uid: 0,
            gid: 0,
            uid_set: false,
            gid_set: false,
            initgroups: false,
            expand_uid: Some("99999".to_string()),
            expand_gid: None,
            router_name: "test_router".to_string(),
        };

        let result = get_ugid(&config, identity_expand);
        assert!(result.is_err());
        match result.unwrap_err() {
            UgidError::UidWithoutGid { router } => {
                assert_eq!(router, "test_router");
            }
            other => panic!("expected UidWithoutGid, got: {other}"),
        }
    }

    #[test]
    fn test_get_ugid_expand_uid_resolution_failure() {
        let config = RouterUgidConfig {
            uid: 0,
            gid: 0,
            uid_set: false,
            gid_set: false,
            initgroups: false,
            expand_uid: Some("nonexistent_user_xyz_12345".to_string()),
            expand_gid: None,
            router_name: "test_router".to_string(),
        };

        let result = get_ugid(&config, identity_expand);
        assert!(result.is_err());
        match result.unwrap_err() {
            UgidError::UidResolutionFailed { expanded, .. } => {
                assert_eq!(expanded, "nonexistent_user_xyz_12345");
            }
            other => panic!("expected UidResolutionFailed, got: {other}"),
        }
    }

    #[test]
    fn test_get_ugid_expand_gid_resolution_failure() {
        let config = RouterUgidConfig {
            uid: 1000,
            gid: 0,
            uid_set: true,
            gid_set: false,
            initgroups: false,
            expand_uid: None,
            expand_gid: Some("nonexistent_group_xyz_12345".to_string()),
            router_name: "test_router".to_string(),
        };

        let result = get_ugid(&config, identity_expand);
        assert!(result.is_err());
        match result.unwrap_err() {
            UgidError::GidResolutionFailed { expanded, .. } => {
                assert_eq!(expanded, "nonexistent_group_xyz_12345");
            }
            other => panic!("expected GidResolutionFailed, got: {other}"),
        }
    }

    #[test]
    fn test_get_ugid_expand_fn_failure() {
        let config = RouterUgidConfig {
            uid: 0,
            gid: 0,
            uid_set: false,
            gid_set: false,
            initgroups: false,
            expand_uid: Some("$local_part".to_string()),
            expand_gid: None,
            router_name: "test_router".to_string(),
        };

        let result = get_ugid(&config, failing_expand);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_ugid_fixed_uid_overrides_expand() {
        // When uid_set is true, expand_uid should be ignored.
        let config = RouterUgidConfig {
            uid: 500,
            gid: 500,
            uid_set: true,
            gid_set: true,
            initgroups: false,
            expand_uid: Some("99999".to_string()),
            expand_gid: Some("99999".to_string()),
            router_name: "test_router".to_string(),
        };

        let ugid = get_ugid(&config, identity_expand).unwrap();
        assert_eq!(ugid.uid, 500);
        assert_eq!(ugid.gid, 500);
    }

    #[test]
    fn test_get_ugid_expand_root_user() {
        // The root user (uid 0) should always exist on Unix systems.
        let config = RouterUgidConfig {
            uid: 0,
            gid: 0,
            uid_set: false,
            gid_set: false,
            initgroups: false,
            expand_uid: Some("root".to_string()),
            expand_gid: None,
            router_name: "test_router".to_string(),
        };

        let ugid = get_ugid(&config, identity_expand).unwrap();
        assert_eq!(ugid.uid, 0);
        assert!(ugid.uid_set);
        // gid should come from root's passwd entry
        assert!(ugid.gid_set);
    }

    // ── set_ugid tests ──────────────────────────────────────────────────────

    #[test]
    fn test_set_ugid_both_set() {
        let ugid = UgidBlock {
            uid: 1000,
            gid: 1000,
            uid_set: true,
            gid_set: true,
            initgroups: true,
        };
        let mut addr = AddressUgid::default();
        set_ugid(&mut addr, &ugid);
        assert_eq!(addr.uid, 1000);
        assert_eq!(addr.gid, 1000);
        assert!(addr.uid_set);
        assert!(addr.gid_set);
        assert!(addr.initgroups);
    }

    #[test]
    fn test_set_ugid_none_set() {
        let ugid = UgidBlock::default();
        let mut addr = AddressUgid::default();
        set_ugid(&mut addr, &ugid);
        assert!(!addr.uid_set);
        assert!(!addr.gid_set);
        assert!(!addr.initgroups);
    }

    #[test]
    fn test_set_ugid_only_uid() {
        let ugid = UgidBlock {
            uid: 500,
            gid: 0,
            uid_set: true,
            gid_set: false,
            initgroups: false,
        };
        let mut addr = AddressUgid::default();
        set_ugid(&mut addr, &ugid);
        assert_eq!(addr.uid, 500);
        assert!(addr.uid_set);
        assert!(!addr.gid_set);
    }

    #[test]
    fn test_set_ugid_only_gid() {
        let ugid = UgidBlock {
            uid: 0,
            gid: 500,
            uid_set: false,
            gid_set: true,
            initgroups: false,
        };
        let mut addr = AddressUgid::default();
        set_ugid(&mut addr, &ugid);
        assert!(!addr.uid_set);
        assert_eq!(addr.gid, 500);
        assert!(addr.gid_set);
    }

    #[test]
    fn test_set_ugid_initgroups_only() {
        let ugid = UgidBlock {
            uid: 0,
            gid: 0,
            uid_set: false,
            gid_set: false,
            initgroups: true,
        };
        let mut addr = AddressUgid::default();
        set_ugid(&mut addr, &ugid);
        assert!(!addr.uid_set);
        assert!(!addr.gid_set);
        assert!(addr.initgroups);
    }

    #[test]
    fn test_set_ugid_preserves_existing_values() {
        let ugid = UgidBlock {
            uid: 0,
            gid: 999,
            uid_set: false,
            gid_set: true,
            initgroups: false,
        };
        let mut addr = AddressUgid {
            uid: 123,
            gid: 456,
            uid_set: true,
            gid_set: false,
            initgroups: false,
        };
        set_ugid(&mut addr, &ugid);
        // uid should be preserved since ugid.uid_set is false
        assert_eq!(addr.uid, 123);
        assert!(addr.uid_set);
        // gid should be overwritten since ugid.gid_set is true
        assert_eq!(addr.gid, 999);
        assert!(addr.gid_set);
    }

    // ── resolve_uid / resolve_gid tests ─────────────────────────────────────

    #[test]
    fn test_resolve_uid_numeric() {
        let (uid, gid) = resolve_uid("65534").unwrap();
        assert_eq!(uid, 65534);
        assert!(gid.is_none()); // Numeric UID provides no passwd entry
    }

    #[test]
    fn test_resolve_uid_root() {
        let (uid, gid) = resolve_uid("root").unwrap();
        assert_eq!(uid, 0);
        assert!(gid.is_some()); // Root has a passwd entry with gid
    }

    #[test]
    fn test_resolve_uid_trimmed() {
        let (uid, _) = resolve_uid("  65534  ").unwrap();
        assert_eq!(uid, 65534);
    }

    #[test]
    fn test_resolve_uid_unknown_user() {
        let result = resolve_uid("nonexistent_user_xyz_12345_67890");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown user"));
    }

    #[test]
    fn test_resolve_gid_numeric() {
        let gid = resolve_gid("65534").unwrap();
        assert_eq!(gid, 65534);
    }

    #[test]
    fn test_resolve_gid_root_group() {
        let gid = resolve_gid("root").unwrap();
        assert_eq!(gid, 0);
    }

    #[test]
    fn test_resolve_gid_trimmed() {
        let gid = resolve_gid("  65534  ").unwrap();
        assert_eq!(gid, 65534);
    }

    #[test]
    fn test_resolve_gid_unknown_group() {
        let result = resolve_gid("nonexistent_group_xyz_12345_67890");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown group"));
    }
}
