// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! UID/GID resolution and assignment helpers for router drivers.
//!
//! Translates **both** `src/src/routers/rf_get_ugid.c` (85 lines) and
//! `src/src/routers/rf_set_ugid.c` (47 lines) into a single Rust module.
//!
//! ## Overview
//!
//! [`get_ugid()`] resolves uid/gid values for a router instance from three
//! sources (in priority order):
//!
//! 1. Fixed numeric uid/gid from the router configuration
//!    (`RouterInstanceConfig::uid`, `RouterInstanceConfig::gid` when the
//!    corresponding `uid_set` / `gid_set` flags are `true`).
//!
//! 2. Expandable uid/gid strings (`expand_uid`, `expand_gid`) evaluated at
//!    route time via [`exim_expand::expand_string()`]. The expanded result is
//!    interpreted first as a numeric id, then as a username/group name via
//!    `getpwnam(3)` / `getgrnam(3)`.
//!
//! 3. When a uid was resolved from a username expansion and no explicit gid
//!    is configured, the gid from the corresponding `passwd` entry is used
//!    as fallback. If no passwd entry is available, an error is returned.
//!
//! [`set_ugid()`] copies resolved uid/gid/initgroups from a [`UgidBlock`]
//! into an [`AddressUgid`] structure, setting the corresponding flags.
//!
//! ## Safety
//!
//! This module contains **zero `unsafe` code** (per AAP §0.7.2). User and
//! group lookups use the `nix` crate's safe POSIX wrappers.

// ── Imports ─────────────────────────────────────────────────────────────

use exim_drivers::router_driver::RouterInstanceConfig;
use exim_expand::{expand_string, ExpandError};
use nix::unistd::{Gid, Group, Uid, User};
use std::fmt;
use thiserror::Error;

// ═══════════════════════════════════════════════════════════════════════
//  UgidBlock — UID/GID Configuration Block
// ═══════════════════════════════════════════════════════════════════════

/// UID/GID configuration block for router delivery.
///
/// Replaces the C `ugid_block` struct from `structs.h`:
///
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
/// The Rust version uses `Option<u32>` to combine the value and set-flag
/// into a single field, which is the idiomatic Rust pattern for optional
/// values. `None` means the value was not configured; `Some(id)` means
/// the value was resolved.
///
/// This struct is filled by [`get_ugid()`] from router configuration and
/// then applied to an address by [`set_ugid()`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UgidBlock {
    /// Numeric user ID for the delivery process.
    ///
    /// `None` when no uid was configured (neither fixed nor expanded).
    /// `Some(id)` when resolved from fixed config, string expansion, or
    /// username lookup.
    pub uid: Option<u32>,

    /// Numeric group ID for the delivery process.
    ///
    /// `None` when no gid was configured (neither fixed, expanded, nor
    /// derived from a passwd entry). `Some(id)` when resolved.
    pub gid: Option<u32>,

    /// Whether to call `initgroups(3)` to initialize the supplementary
    /// group list for the delivery process.
    ///
    /// Maps to C `ugid->initgroups` and the `af_initgroups` address flag.
    pub initgroups: bool,
}

impl fmt::Display for UgidBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UgidBlock(uid={}, gid={}, initgroups={})",
            match self.uid {
                Some(id) => format!("{id}"),
                None => "unset".to_string(),
            },
            match self.gid {
                Some(id) => format!("{id}"),
                None => "unset".to_string(),
            },
            self.initgroups,
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  AddressUgid — Address Item UID/GID Fields
// ═══════════════════════════════════════════════════════════════════════

/// Address item UID/GID fields that [`set_ugid()`] populates.
///
/// Translates the uid/gid-related fields from C `address_item`:
///
/// ```c
/// addr->uid = ugid->uid;     setflag(addr, af_uid_set);
/// addr->gid = ugid->gid;     setflag(addr, af_gid_set);
/// if (ugid->initgroups)      setflag(addr, af_initgroups);
/// ```
///
/// Callers construct this from their own address representation, call
/// [`set_ugid()`], then copy the results back.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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

// ═══════════════════════════════════════════════════════════════════════
//  GetUgidError — Error Types for UID/GID Resolution
// ═══════════════════════════════════════════════════════════════════════

/// Errors that can occur during UID/GID resolution in [`get_ugid()`].
///
/// Translates the C error paths in `rf_get_ugid.c` where `addr->message`
/// is set and `FALSE` is returned. In C, the error information is written
/// to `addr->message` as a side-effect; in Rust, each variant carries its
/// own descriptive context.
#[derive(Debug, Error)]
pub enum GetUgidError {
    /// The `expand_uid` string could not be expanded.
    ///
    /// C equivalent: `expand_string()` returning NULL for the uid template,
    /// causing `route_find_expanded_user()` to return FALSE.
    #[error("failed to expand uid: {0}")]
    UidExpansionFailed(String),

    /// The `expand_gid` string could not be expanded.
    ///
    /// C equivalent: `expand_string()` returning NULL for the gid template,
    /// causing `route_find_expanded_group()` to return FALSE.
    #[error("failed to expand gid: {0}")]
    GidExpansionFailed(String),

    /// The expanded uid string did not match any system user.
    ///
    /// C equivalent: `getpwnam()` returning NULL in `route_find_expanded_user()`.
    #[error("user not found: {0}")]
    UserNotFound(String),

    /// The expanded gid string did not match any system group.
    ///
    /// C equivalent: `getgrnam()` returning NULL in `route_find_expanded_group()`.
    #[error("group not found: {0}")]
    GroupNotFound(String),
}

// ═══════════════════════════════════════════════════════════════════════
//  get_ugid — Resolve UID/GID for a Router
// ═══════════════════════════════════════════════════════════════════════

/// Resolve UID/GID values for a router instance, returning a [`UgidBlock`].
///
/// This function translates `rf_get_ugid()` from
/// `src/src/routers/rf_get_ugid.c` (85 lines).
///
/// The resolution process follows this priority chain:
///
/// 1. Copy fixed uid/gid from the router configuration (when `uid_set` /
///    `gid_set` is `true`).
/// 2. If no fixed uid is set but `expand_uid` is configured, expand it via
///    [`exim_expand::expand_string()`] and resolve either as a numeric UID
///    or a username via `getpwnam(3)`. A username lookup also produces a
///    passwd entry that may supply a fallback GID.
/// 3. If no fixed gid is set but `expand_gid` is configured, expand and
///    resolve it similarly via `getgrnam(3)`.
/// 4. If uid is set but gid is not: use the gid from the passwd entry
///    obtained during uid expansion (if any), or return an error.
///
/// The `initgroups` flag is always copied from the router configuration.
///
/// # Expansion Failure Handling
///
/// - [`ExpandError::ForcedFail`]: the uid/gid is simply not set — this is
///   not an error (the expansion explicitly declined).
/// - [`ExpandError::Failed`]: maps to [`GetUgidError::UidExpansionFailed`]
///   or [`GetUgidError::GidExpansionFailed`].
///
/// # Arguments
///
/// * `router_config` — Router instance configuration containing the fixed
///   and expandable uid/gid fields.
///
/// # Returns
///
/// * `Ok(UgidBlock)` — Successfully resolved uid/gid configuration.
/// * `Err(GetUgidError)` — Resolution failed.
pub fn get_ugid(router_config: &RouterInstanceConfig) -> Result<UgidBlock, GetUgidError> {
    let mut ugid = UgidBlock::default();

    // Track whether a passwd entry was found during uid expansion so we
    // can fall back to its gid if needed. In C this is `struct passwd *upw`.
    let mut passwd_gid: Option<u32> = None;

    // ── Step 1: Resolve UID ────────────────────────────────────────────
    // C: ugid->uid = rblock->uid; ugid->uid_set = rblock->uid_set;
    // C: if (!ugid->uid_set && rblock->expand_uid) { ... }

    if router_config.uid_set {
        ugid.uid = Some(router_config.uid);
        tracing::debug!(
            router = %router_config.name,
            uid = router_config.uid,
            "using fixed uid from router config"
        );
    } else if let Some(ref expand_uid_template) = router_config.expand_uid {
        match expand_string(expand_uid_template) {
            Ok(expanded) => {
                tracing::debug!(
                    router = %router_config.name,
                    expanded_uid = %expanded,
                    "resolving expanded uid"
                );
                let (uid, opt_gid) = resolve_uid(&expanded, &router_config.name)?;
                ugid.uid = Some(uid);
                passwd_gid = opt_gid;
                tracing::debug!(
                    router = %router_config.name,
                    uid = uid,
                    passwd_gid = ?opt_gid,
                    "uid resolved successfully"
                );
            }
            Err(ExpandError::ForcedFail) => {
                // Forced failure means uid is intentionally not set — not an error.
                tracing::debug!(
                    router = %router_config.name,
                    template = %expand_uid_template,
                    "expand_uid forced fail, uid not set"
                );
            }
            Err(ExpandError::Failed { message }) => {
                return Err(GetUgidError::UidExpansionFailed(message));
            }
            Err(other) => {
                return Err(GetUgidError::UidExpansionFailed(other.to_string()));
            }
        }
    }

    // ── Step 2: Resolve GID ────────────────────────────────────────────
    // C: ugid->gid = rblock->gid; ugid->gid_set = rblock->gid_set;
    // C: if (!ugid->gid_set && rblock->expand_gid) { ... }

    if router_config.gid_set {
        ugid.gid = Some(router_config.gid);
        tracing::debug!(
            router = %router_config.name,
            gid = router_config.gid,
            "using fixed gid from router config"
        );
    } else if let Some(ref expand_gid_template) = router_config.expand_gid {
        match expand_string(expand_gid_template) {
            Ok(expanded) => {
                tracing::debug!(
                    router = %router_config.name,
                    expanded_gid = %expanded,
                    "resolving expanded gid"
                );
                let gid = resolve_gid(&expanded, &router_config.name)?;
                ugid.gid = Some(gid);
                tracing::debug!(
                    router = %router_config.name,
                    gid = gid,
                    "gid resolved successfully"
                );
            }
            Err(ExpandError::ForcedFail) => {
                // Forced failure means gid is intentionally not set — not an error.
                tracing::debug!(
                    router = %router_config.name,
                    template = %expand_gid_template,
                    "expand_gid forced fail, gid not set"
                );
            }
            Err(ExpandError::Failed { message }) => {
                return Err(GetUgidError::GidExpansionFailed(message));
            }
            Err(other) => {
                return Err(GetUgidError::GidExpansionFailed(other.to_string()));
            }
        }
    } else if let Some(gid_from_passwd) = passwd_gid {
        // Fallback: use gid from the passwd entry obtained during uid
        // expansion. This mirrors C line 70: `ugid->gid = upw->pw_gid`.
        ugid.gid = Some(gid_from_passwd);
        tracing::debug!(
            router = %router_config.name,
            gid = gid_from_passwd,
            "gid taken from passwd entry of resolved uid"
        );
    }

    // ── Step 3: Validate uid-requires-gid invariant ────────────────────
    // C: if (ugid->uid_set && !ugid->gid_set)
    //      { if (upw) ... else { addr->message = "user set without group"; return FALSE; } }
    //
    // If a uid was resolved but no gid is available from any source,
    // that is a configuration error.
    if ugid.uid.is_some() && ugid.gid.is_none() {
        return Err(GetUgidError::GidExpansionFailed(format!(
            "user set without group for {} router",
            router_config.name
        )));
    }

    // ── Step 4: Copy initgroups flag ───────────────────────────────────
    // C: ugid->initgroups = rblock->initgroups;
    ugid.initgroups = router_config.initgroups;

    tracing::debug!(
        uid = ?ugid.uid,
        gid = ?ugid.gid,
        initgroups = ugid.initgroups,
        "resolved ugid"
    );

    Ok(ugid)
}

// ═══════════════════════════════════════════════════════════════════════
//  set_ugid — Copy UID/GID from UgidBlock to Address Fields
// ═══════════════════════════════════════════════════════════════════════

/// Copy resolved UID/GID values from a [`UgidBlock`] into address fields.
///
/// Translates `rf_set_ugid()` from `src/src/routers/rf_set_ugid.c` (47 lines).
///
/// Only copies values that are present (`Some`) in the ugid block. The
/// corresponding `*_set` flags are also set on the address, along with the
/// `initgroups` flag.
///
/// # Arguments
///
/// * `addr_ugid` — Mutable reference to the address item's UID/GID fields.
/// * `ugid` — The resolved UID/GID block to copy from.
///
/// # C Equivalent
///
/// ```c
/// void rf_set_ugid(address_item *addr, const ugid_block *ugid) {
///     if (ugid->uid_set) { addr->uid = ugid->uid; setflag(addr, af_uid_set); }
///     if (ugid->gid_set) { addr->gid = ugid->gid; setflag(addr, af_gid_set); }
///     if (ugid->initgroups) setflag(addr, af_initgroups);
/// }
/// ```
pub fn set_ugid(addr_ugid: &mut AddressUgid, ugid: &UgidBlock) {
    // C: if (ugid->uid_set) { addr->uid = ugid->uid; setflag(addr, af_uid_set); }
    if let Some(uid) = ugid.uid {
        addr_ugid.uid = uid;
        addr_ugid.uid_set = true;
    }

    // C: if (ugid->gid_set) { addr->gid = ugid->gid; setflag(addr, af_gid_set); }
    if let Some(gid) = ugid.gid {
        addr_ugid.gid = gid;
        addr_ugid.gid_set = true;
    }

    // C: if (ugid->initgroups) setflag(addr, af_initgroups);
    if ugid.initgroups {
        addr_ugid.initgroups = true;
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Internal Resolution Helpers
// ═══════════════════════════════════════════════════════════════════════

/// Resolve a UID from a string that may be numeric or a username.
///
/// Mirrors C `route_find_expanded_user()`:
///   1. Try parsing as a numeric UID via `str::parse::<u32>()`
///   2. Fall back to username lookup via `getpwnam(3)` through
///      [`nix::unistd::User::from_name()`]
///
/// Returns `(uid, Option<gid>)` — the gid is only populated when the
/// resolution came from a passwd entry (username lookup), providing a
/// fallback gid for cases where no explicit gid is configured.
///
/// When a numeric UID is provided, [`nix::unistd::User::from_uid()`] is
/// called to verify the UID exists on the system and to retrieve the
/// associated username for diagnostic logging.
fn resolve_uid(expanded: &str, router_name: &str) -> Result<(u32, Option<u32>), GetUgidError> {
    let trimmed = expanded.trim();

    // Try numeric UID first (C: string_to_uid).
    if let Ok(numeric_uid) = trimmed.parse::<u32>() {
        // Validate the numeric UID exists on the system and log the
        // associated username if available. This uses User::from_uid()
        // for diagnostic purposes only — numeric UIDs are accepted even
        // if they don't correspond to a named user (matching C behaviour).
        match User::from_uid(Uid::from_raw(numeric_uid)) {
            Ok(Some(user)) => {
                tracing::debug!(
                    uid = numeric_uid,
                    username = %user.name,
                    router = %router_name,
                    "numeric uid resolved to known user"
                );
            }
            Ok(None) | Err(_) => {
                tracing::debug!(
                    uid = numeric_uid,
                    router = %router_name,
                    "numeric uid has no corresponding passwd entry"
                );
            }
        }
        // Numeric UIDs do NOT provide a passwd gid fallback (matching C
        // behaviour where `string_to_uid()` returns without setting `upw`).
        return Ok((numeric_uid, None));
    }

    // Fall back to username lookup via getpwnam (C: getpwnam).
    match User::from_name(trimmed) {
        Ok(Some(user)) => {
            let uid = user.uid.as_raw();
            let gid = user.gid.as_raw();
            Ok((uid, Some(gid)))
        }
        Ok(None) => Err(GetUgidError::UserNotFound(trimmed.to_string())),
        Err(e) => Err(GetUgidError::UserNotFound(format!(
            "user lookup failed for '{trimmed}': {e}"
        ))),
    }
}

/// Resolve a GID from a string that may be numeric or a group name.
///
/// Mirrors C `route_find_expanded_group()`:
///   1. Try parsing as a numeric GID via `str::parse::<u32>()`
///   2. Fall back to group name lookup via `getgrnam(3)` through
///      [`nix::unistd::Group::from_name()`]
///
/// When a numeric GID is provided, [`nix::unistd::Group::from_gid()`] is
/// called to verify the GID exists on the system and to retrieve the
/// associated group name for diagnostic logging.
fn resolve_gid(expanded: &str, router_name: &str) -> Result<u32, GetUgidError> {
    let trimmed = expanded.trim();

    // Try numeric GID first (C: string_to_gid).
    if let Ok(numeric_gid) = trimmed.parse::<u32>() {
        // Validate the numeric GID exists on the system and log the
        // associated group name if available.
        match Group::from_gid(Gid::from_raw(numeric_gid)) {
            Ok(Some(group)) => {
                tracing::debug!(
                    gid = numeric_gid,
                    group_name = %group.name,
                    router = %router_name,
                    "numeric gid resolved to known group"
                );
            }
            Ok(None) | Err(_) => {
                tracing::debug!(
                    gid = numeric_gid,
                    router = %router_name,
                    "numeric gid has no corresponding group entry"
                );
            }
        }
        return Ok(numeric_gid);
    }

    // Fall back to group name lookup via getgrnam (C: getgrnam).
    match Group::from_name(trimmed) {
        Ok(Some(group)) => Ok(group.gid.as_raw()),
        Ok(None) => Err(GetUgidError::GroupNotFound(trimmed.to_string())),
        Err(e) => Err(GetUgidError::GroupNotFound(format!(
            "group lookup failed for '{trimmed}': {e}"
        ))),
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Unit Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── UgidBlock tests ─────────────────────────────────────────────────

    #[test]
    fn test_ugid_block_default() {
        let ugid = UgidBlock::default();
        assert_eq!(ugid.uid, None);
        assert_eq!(ugid.gid, None);
        assert!(!ugid.initgroups);
    }

    #[test]
    fn test_ugid_block_display_unset() {
        let ugid = UgidBlock::default();
        let display = format!("{ugid}");
        assert!(display.contains("uid=unset"));
        assert!(display.contains("gid=unset"));
        assert!(display.contains("initgroups=false"));
    }

    #[test]
    fn test_ugid_block_display_set() {
        let ugid = UgidBlock {
            uid: Some(1000),
            gid: Some(1000),
            initgroups: true,
        };
        let display = format!("{ugid}");
        assert!(display.contains("uid=1000"));
        assert!(display.contains("gid=1000"));
        assert!(display.contains("initgroups=true"));
    }

    #[test]
    fn test_ugid_block_clone() {
        let ugid = UgidBlock {
            uid: Some(500),
            gid: Some(500),
            initgroups: true,
        };
        let cloned = ugid.clone();
        assert_eq!(ugid, cloned);
    }

    // ── AddressUgid tests ───────────────────────────────────────────────

    #[test]
    fn test_address_ugid_default() {
        let addr = AddressUgid::default();
        assert_eq!(addr.uid, 0);
        assert_eq!(addr.gid, 0);
        assert!(!addr.uid_set);
        assert!(!addr.gid_set);
        assert!(!addr.initgroups);
    }

    // ── set_ugid tests ──────────────────────────────────────────────────

    #[test]
    fn test_set_ugid_both_set() {
        let ugid = UgidBlock {
            uid: Some(1000),
            gid: Some(1000),
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
            uid: Some(500),
            gid: None,
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
            uid: None,
            gid: Some(500),
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
            uid: None,
            gid: None,
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
            uid: None,
            gid: Some(999),
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
        // uid should be preserved since ugid.uid is None.
        assert_eq!(addr.uid, 123);
        assert!(addr.uid_set);
        // gid should be overwritten since ugid.gid is Some.
        assert_eq!(addr.gid, 999);
        assert!(addr.gid_set);
    }

    // ── resolve_uid tests ───────────────────────────────────────────────

    #[test]
    fn test_resolve_uid_numeric() {
        let (uid, gid) = resolve_uid("65534", "test").unwrap();
        assert_eq!(uid, 65534);
        // Numeric UID provides no passwd entry gid fallback.
        assert!(gid.is_none());
    }

    #[test]
    fn test_resolve_uid_root() {
        let (uid, gid) = resolve_uid("root", "test").unwrap();
        assert_eq!(uid, 0);
        // Root has a passwd entry with a gid.
        assert!(gid.is_some());
    }

    #[test]
    fn test_resolve_uid_trimmed() {
        let (uid, _) = resolve_uid("  65534  ", "test").unwrap();
        assert_eq!(uid, 65534);
    }

    #[test]
    fn test_resolve_uid_unknown_user() {
        let result = resolve_uid("nonexistent_user_xyz_12345_67890", "test");
        assert!(result.is_err());
        match result.unwrap_err() {
            GetUgidError::UserNotFound(name) => {
                assert!(name.contains("nonexistent_user_xyz_12345_67890"));
            }
            other => panic!("expected UserNotFound, got: {other}"),
        }
    }

    // ── resolve_gid tests ───────────────────────────────────────────────

    #[test]
    fn test_resolve_gid_numeric() {
        let gid = resolve_gid("65534", "test").unwrap();
        assert_eq!(gid, 65534);
    }

    #[test]
    fn test_resolve_gid_root_group() {
        let gid = resolve_gid("root", "test").unwrap();
        assert_eq!(gid, 0);
    }

    #[test]
    fn test_resolve_gid_trimmed() {
        let gid = resolve_gid("  65534  ", "test").unwrap();
        assert_eq!(gid, 65534);
    }

    #[test]
    fn test_resolve_gid_unknown_group() {
        let result = resolve_gid("nonexistent_group_xyz_12345_67890", "test");
        assert!(result.is_err());
        match result.unwrap_err() {
            GetUgidError::GroupNotFound(name) => {
                assert!(name.contains("nonexistent_group_xyz_12345_67890"));
            }
            other => panic!("expected GroupNotFound, got: {other}"),
        }
    }

    // ── get_ugid tests with fixed values ────────────────────────────────

    #[test]
    fn test_get_ugid_fixed_values() {
        let config = RouterInstanceConfig::new("test_router", "accept");
        let mut config = config;
        config.uid = 1000;
        config.gid = 1000;
        config.uid_set = true;
        config.gid_set = true;
        config.initgroups = true;

        let ugid = get_ugid(&config).unwrap();
        assert_eq!(ugid.uid, Some(1000));
        assert_eq!(ugid.gid, Some(1000));
        assert!(ugid.initgroups);
    }

    #[test]
    fn test_get_ugid_no_values_set() {
        let config = RouterInstanceConfig::new("test_router", "accept");

        let ugid = get_ugid(&config).unwrap();
        assert_eq!(ugid.uid, None);
        assert_eq!(ugid.gid, None);
        assert!(!ugid.initgroups);
    }

    #[test]
    fn test_get_ugid_fixed_uid_without_gid_fails() {
        let mut config = RouterInstanceConfig::new("test_router", "accept");
        config.uid = 1000;
        config.uid_set = true;
        // gid_set remains false, no expand_gid, no passwd fallback.

        let result = get_ugid(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            GetUgidError::GidExpansionFailed(msg) => {
                assert!(msg.contains("user set without group"));
                assert!(msg.contains("test_router"));
            }
            other => panic!("expected GidExpansionFailed, got: {other}"),
        }
    }

    #[test]
    fn test_get_ugid_fixed_uid_overrides_expand() {
        let mut config = RouterInstanceConfig::new("test_router", "accept");
        config.uid = 500;
        config.gid = 500;
        config.uid_set = true;
        config.gid_set = true;
        config.expand_uid = Some("99999".to_string());
        config.expand_gid = Some("99999".to_string());

        let ugid = get_ugid(&config).unwrap();
        assert_eq!(ugid.uid, Some(500));
        assert_eq!(ugid.gid, Some(500));
    }

    // ── GetUgidError tests ──────────────────────────────────────────────

    #[test]
    fn test_error_display_uid_expansion_failed() {
        let err = GetUgidError::UidExpansionFailed("test error".to_string());
        assert_eq!(err.to_string(), "failed to expand uid: test error");
    }

    #[test]
    fn test_error_display_gid_expansion_failed() {
        let err = GetUgidError::GidExpansionFailed("test error".to_string());
        assert_eq!(err.to_string(), "failed to expand gid: test error");
    }

    #[test]
    fn test_error_display_user_not_found() {
        let err = GetUgidError::UserNotFound("nobody".to_string());
        assert_eq!(err.to_string(), "user not found: nobody");
    }

    #[test]
    fn test_error_display_group_not_found() {
        let err = GetUgidError::GroupNotFound("nogroup".to_string());
        assert_eq!(err.to_string(), "group not found: nogroup");
    }
}
