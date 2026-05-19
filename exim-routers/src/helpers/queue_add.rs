// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! Queue an address for local or remote transport delivery.
//!
//! Translates **`src/src/routers/rf_queue_add.c`** (132 lines) into Rust.
//!
//! ## Overview
//!
//! After a router has made its routing decision and selected a transport,
//! [`queue_add()`] copies propagating data (domain/localpart expansion
//! results) from the delivery context into the address, resolves uid/gid
//! for local transports, sets up fallback hosts for remote transports,
//! and appends the address to the appropriate delivery queue.
//!
//! ## C → Rust Translation
//!
//! | C Concept | Rust Equivalent |
//! |-----------|-----------------|
//! | `address_item **paddr_local` linked list | `&mut Vec<AddressItem>` local queue |
//! | `address_item **paddr_remote` linked list | `&mut Vec<AddressItem>` remote queue |
//! | `struct passwd *pw` | `Option<&PasswdEntry>` |
//! | `router_instance *rblock` | `&RouterInstanceConfig` |
//! | Global `deliver_domain_data` | `DeliveryContext.deliver_domain_data` |
//! | Global `deliver_localpart_data` | `DeliveryContext.deliver_localpart_data` |
//! | Global `deliver_home` | `DeliveryContext.deliver_home` |
//! | Global `remote_delivery_count` | `DeliveryContext.remote_delivery_count` |
//! | `setflag(addr, af_*)` | Bitwise OR on `addr.flags` |
//! | `expand_string()` + `expand_string_message` | `exim_expand::expand_string()` → `Result` |
//! | `rf_get_ugid()` / `rf_set_ugid()` | `super::ugid::get_ugid()` / `super::ugid::set_ugid()` |
//! | `DEBUG(D_route)` | `tracing::debug!()` |
//! | Returns `BOOL` (TRUE/FALSE) | Returns `Result<(), QueueAddError>` |
//!
//! ## Safety
//!
//! This module contains **zero `unsafe` code** (per AAP §0.7.2).

// ── Imports ─────────────────────────────────────────────────────────────

// Address and delivery context types defined locally in change_domain.rs
// to avoid a circular dependency between exim-routers and exim-core.
// See change_domain.rs module doc for rationale.
use super::change_domain::{AddressItem, DeliveryContext};

use exim_drivers::router_driver::RouterInstanceConfig;
use exim_drivers::transport_driver::TransportDriver;
use exim_expand::expand_string;
use exim_store::taint::Tainted;
use thiserror::Error;

use super::ugid::{get_ugid, set_ugid, AddressUgid, GetUgidError, UgidBlock};

// ═══════════════════════════════════════════════════════════════════════
//  Address Flag Constants
// ═══════════════════════════════════════════════════════════════════════
//
// These constants mirror the C `af_*` bitflags from `structs.h` that are
// combined into `address_item.flags`.  The `queue_add()` function sets
// several of these when populating uid/gid and home directory information.

/// Flag: UID has been explicitly set on the address.
///
/// C equivalent: `af_uid_set` — set by `setflag(addr, af_uid_set)` in
/// `rf_queue_add.c` line 63 and `rf_set_ugid.c`.
const AF_UID_SET: u32 = 0x0001;

/// Flag: GID has been explicitly set on the address.
///
/// C equivalent: `af_gid_set` — set by `setflag(addr, af_gid_set)` in
/// `rf_queue_add.c` line 64 and `rf_set_ugid.c`.
const AF_GID_SET: u32 = 0x0002;

/// Flag: Home directory was obtained from a `passwd` entry (already
/// expanded, not requiring further expansion at transport time).
///
/// C equivalent: `af_home_expanded` — set by `setflag(addr, af_home_expanded)`
/// in `rf_queue_add.c` line 65 when the home dir comes from the passwd entry.
const AF_HOME_EXPANDED: u32 = 0x0004;

/// Flag: `initgroups(3)` should be called when setting supplementary groups
/// for the delivery process.
///
/// C equivalent: `af_initgroups` — set by `rf_set_ugid()` when the router
/// has `initgroups = true`.
const AF_INITGROUPS: u32 = 0x0008;

// ═══════════════════════════════════════════════════════════════════════
//  PasswdEntry — POSIX passwd information
// ═══════════════════════════════════════════════════════════════════════

/// POSIX passwd entry information for local delivery.
///
/// Wraps the essential fields from `struct passwd` used by [`queue_add()`]
/// to set the delivery user identity. When a router provides a passwd entry
/// (e.g., from `getpwnam(3)` during user lookup), the uid, gid, and home
/// directory are copied directly onto the address.
///
/// In C, this is `struct passwd *pw` from `<pwd.h>`.
///
/// # Fields
///
/// - `pw_name`  — Login name (e.g., `"exim"`)
/// - `pw_uid`   — Numeric user ID
/// - `pw_gid`   — Numeric group ID (primary group)
/// - `pw_dir`   — Home directory path
/// - `pw_shell` — Login shell (not used by delivery, retained for completeness)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    /// Login name from the password database.
    pub pw_name: String,

    /// Numeric user ID.
    pub pw_uid: u32,

    /// Numeric primary group ID.
    pub pw_gid: u32,

    /// Home directory path.
    pub pw_dir: String,

    /// Login shell path.
    pub pw_shell: String,
}

impl PasswdEntry {
    /// Create a new `PasswdEntry` with the given fields.
    ///
    /// This is a convenience constructor for test code and programmatic
    /// construction. For production use, passwd entries are typically
    /// obtained from `nix::unistd::User::from_name()`.
    pub fn new(
        pw_name: impl Into<String>,
        pw_uid: u32,
        pw_gid: u32,
        pw_dir: impl Into<String>,
        pw_shell: impl Into<String>,
    ) -> Self {
        Self {
            pw_name: pw_name.into(),
            pw_uid,
            pw_gid,
            pw_dir: pw_dir.into(),
            pw_shell: pw_shell.into(),
        }
    }
}

impl std::fmt::Display for PasswdEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PasswdEntry(name={}, uid={}, gid={}, dir={}, shell={})",
            self.pw_name, self.pw_uid, self.pw_gid, self.pw_dir, self.pw_shell
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  QueueAddError — Errors from queue_add
// ═══════════════════════════════════════════════════════════════════════

/// Errors that can occur during [`queue_add()`].
///
/// Translates the two error return paths in C `rf_queue_add.c`:
///
/// 1. **UgidFailed** — `rf_get_ugid()` returned FALSE (C lines 72–73).
///    The router could not resolve the uid/gid from its configuration.
///
/// 2. **FallbackHostsExpansionFailed** — `expand_string()` returned NULL
///    for the `fallback_hosts` option (C lines 106–110). The fallback
///    hosts string contained an expansion that failed.
#[derive(Debug, Error)]
pub enum QueueAddError {
    /// UID/GID resolution from the router configuration failed.
    ///
    /// This error wraps [`GetUgidError`] from the ugid helper module.
    /// Common causes: unknown username/group in `expand_uid`/`expand_gid`,
    /// uid set without a corresponding gid, or expansion failure in the
    /// uid/gid template strings.
    #[error("failed to get uid/gid: {0}")]
    UgidFailed(String),

    /// String expansion of the router's `fallback_hosts` option failed.
    ///
    /// This error occurs when the `fallback_hosts` configuration string
    /// contains a `${...}` expansion that cannot be evaluated. Common
    /// causes: undefined variable, lookup failure, or syntax error in
    /// the expansion template.
    #[error("failed to expand fallback_hosts: {0}")]
    FallbackHostsExpansionFailed(String),
}

/// Convert a [`GetUgidError`] into a [`QueueAddError::UgidFailed`].
///
/// This allows the `?` operator to propagate ugid errors automatically
/// through `queue_add()`, translating the error type at the boundary.
impl From<GetUgidError> for QueueAddError {
    fn from(err: GetUgidError) -> Self {
        QueueAddError::UgidFailed(err.to_string())
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  parse_host_list — Build HostItem vec from colon-separated string
// ═══════════════════════════════════════════════════════════════════════

/// Parse a colon-separated list of host names into a vector of host name
/// strings.
///
/// This helper mirrors the C behavior in `rf_queue_add.c` lines 101–110
/// where the expanded `fallback_hosts` string (a colon-separated list of
/// host names or IP addresses) is converted into a linked list of
/// `host_item` structures. In the Rust codebase, the local
/// [`AddressItem::fallback_hosts`] field stores a simple `Vec<String>`
/// (host names are resolved to IP addresses at delivery time).
///
/// # Format
///
/// The input is expected to be a colon-separated list of host identifiers:
///
/// ```text
/// "mail1.example.com : mail2.example.com : 10.0.0.1"
/// ```
///
/// Each entry is trimmed of whitespace and empty entries are skipped.
///
/// # Arguments
///
/// * `hosts_str` — The colon-separated host list string.
///
/// # Returns
///
/// A `Vec<String>` of individual host name entries.
fn parse_host_list(hosts_str: &str) -> Vec<String> {
    hosts_str
        .split(':')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|host_name| host_name.to_string())
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════
//  queue_add — Queue Address for Transport Delivery
// ═══════════════════════════════════════════════════════════════════════

/// Queue an address for local or remote transport delivery.
///
/// This function translates `rf_queue_add()` from
/// `src/src/routers/rf_queue_add.c` (132 lines). It is called after a
/// router has made its routing decision and selected a transport for the
/// address.
///
/// The function performs these steps:
///
/// 1. **Save propagating data** — Copies `deliver_domain_data` and
///    `deliver_localpart_data` from the delivery context into the
///    address's propagated properties.
///
/// 2. **Local transport path** (when `transport.is_local()` is `true`):
///    - If a `passwd_entry` is provided: set uid, gid, home directory,
///      and `af_uid_set | af_gid_set | af_home_expanded` flags.
///    - Otherwise: call [`get_ugid()`] to resolve uid/gid from the
///      router configuration, then [`set_ugid()`] to apply the result.
///    - Apply home directory priority: router `home_directory` >
///      `deliver_home` from context.
///    - Apply current directory from router configuration.
///    - Append the address to the local delivery queue.
///
/// 3. **Remote transport path** (when transport is remote or absent):
///    - Use the pre-built `fallback_hostlist` from the router, or expand
///      the `fallback_hosts` string and parse it into a host list.
///    - Append the address to the remote delivery queue.
///    - Increment the remote delivery count in the context.
///
/// 4. **Debug logging** — Log the transport name, local part, domain,
///    errors-to address, and propagated data.
///
/// # Arguments
///
/// * `addr` — The address to queue (modified in place with uid/gid/home/etc.).
/// * `local_queue` — The local delivery queue (C: `paddr_local` chain).
/// * `remote_queue` — The remote delivery queue (C: `paddr_remote` chain).
/// * `router_config` — The router instance configuration that made the
///   routing decision.
/// * `passwd_entry` — Optional passwd entry for the delivery user (from
///   `getpwnam(3)` during router evaluation). When `Some`, uid/gid/home
///   are taken directly from the passwd entry.
/// * `transport` — Optional resolved transport driver trait object, used
///   to call [`TransportDriver::is_local()`] and
///   [`TransportDriver::driver_name()`].
/// * `ctx` — Mutable delivery context providing propagating data and
///   the remote delivery counter.
///
/// # Returns
///
/// * `Ok(())` — Address successfully queued.
/// * `Err(QueueAddError::UgidFailed)` — uid/gid resolution failed
///   (local transport path only).
/// * `Err(QueueAddError::FallbackHostsExpansionFailed)` — `fallback_hosts`
///   string expansion failed (remote transport path only).
///
/// # Examples
///
/// ```ignore
/// use exim_routers::helpers::queue_add::{queue_add, PasswdEntry};
/// use exim_core::context::{AddressItem, DeliveryContext};
/// use exim_drivers::router_driver::RouterInstanceConfig;
///
/// let mut addr = AddressItem::new("user@example.com".to_string());
/// let mut local_q = Vec::new();
/// let mut remote_q = Vec::new();
/// let config = RouterInstanceConfig::new("my_router", "accept");
/// let pw = PasswdEntry::new("user", 1000, 1000, "/home/user", "/bin/bash");
/// let mut ctx = DeliveryContext::new();
///
/// // Queue for local delivery with passwd entry
/// queue_add(
///     &mut addr, &mut local_q, &mut remote_q,
///     &config, Some(&pw), None, &mut ctx,
/// ).unwrap();
/// ```
pub fn queue_add(
    addr: &mut AddressItem,
    local_queue: &mut Vec<AddressItem>,
    remote_queue: &mut Vec<AddressItem>,
    router_config: &RouterInstanceConfig,
    passwd_entry: Option<&PasswdEntry>,
    transport: Option<&dyn TransportDriver>,
    ctx: &mut DeliveryContext,
) -> Result<(), QueueAddError> {
    // ── Step 1: Save propagating data (C lines 45–46) ──────────────────
    //
    // C: addr->prop.domain_data = deliver_domain_data;
    // C: addr->prop.localpart_data = deliver_localpart_data;
    //
    // In C, these globals are set by the router that processed the address.
    // In Rust, they are fields on the DeliveryContext passed explicitly.
    addr.prop.domain_data = ctx.deliver_domain_data.clone();
    addr.prop.localpart_data = ctx.deliver_localpart_data.clone();

    // ── Step 2: Determine transport locality (C line 53) ───────────────
    //
    // C: if (addr->transport && addr->transport->info->local)
    //
    // In Rust, we receive the resolved transport as a trait object and call
    // is_local() to determine the queue target. If no transport is provided,
    // the address is queued for remote delivery (matching C behaviour when
    // ti->local is false).
    let is_local = transport.is_some_and(|t| t.is_local());
    let transport_name = transport.map(|t| t.driver_name().to_string());

    if is_local {
        // ── LOCAL TRANSPORT PATH (C lines 55–93) ───────────────────────

        if let Some(pw) = passwd_entry {
            // ── passwd entry available (C lines 57–69) ─────────────────
            //
            // C: addr->uid = pw->pw_uid;
            //    addr->gid = pw->pw_gid;
            //    setflag(addr, af_uid_set);
            //    setflag(addr, af_gid_set);
            //    setflag(addr, af_home_expanded);
            //    addr->home_dir = CS pw->pw_dir;
            //
            // The passwd entry provides uid, gid, and home directory directly.
            // The af_home_expanded flag tells the transport that the home
            // directory is already resolved and should not be re-expanded.
            addr.uid = pw.pw_uid as i32;
            addr.gid = pw.pw_gid as i32;
            addr.flags |= AF_UID_SET | AF_GID_SET | AF_HOME_EXPANDED;
            addr.home_dir = Some(pw.pw_dir.clone());

            tracing::debug!(
                pw_name = %pw.pw_name,
                uid = pw.pw_uid,
                gid = pw.pw_gid,
                home = %pw.pw_dir,
                "queue_add: uid/gid/home set from passwd entry"
            );
        } else {
            // ── No passwd entry — resolve from router config (C lines 71–77) ──
            //
            // C: if (!rf_get_ugid(rblock, addr)) return FALSE;
            //    rf_set_ugid(addr, &(rblock->ugid));
            //
            // Call get_ugid() to resolve uid/gid from the router's fixed values
            // or expandable strings, then apply the result to the address fields
            // via set_ugid().
            let ugid: UgidBlock = get_ugid(router_config)?;

            // Adapter: extract AddressUgid from AddressItem fields, apply
            // set_ugid, then copy back. This bridges the ugid module's
            // AddressUgid type and AddressItem's flat uid/gid/flags fields.
            let mut addr_ugid = AddressUgid {
                uid: u32::try_from(addr.uid).unwrap_or(0),
                gid: u32::try_from(addr.gid).unwrap_or(0),
                uid_set: (addr.flags & AF_UID_SET) != 0,
                gid_set: (addr.flags & AF_GID_SET) != 0,
                initgroups: (addr.flags & AF_INITGROUPS) != 0,
            };

            set_ugid(&mut addr_ugid, &ugid);

            // Copy resolved values back to AddressItem.
            addr.uid = addr_ugid.uid as i32;
            addr.gid = addr_ugid.gid as i32;
            if addr_ugid.uid_set {
                addr.flags |= AF_UID_SET;
            }
            if addr_ugid.gid_set {
                addr.flags |= AF_GID_SET;
            }
            if addr_ugid.initgroups {
                addr.flags |= AF_INITGROUPS;
            }

            tracing::debug!(
                ugid = %ugid,
                "queue_add: uid/gid set from router config"
            );
        }

        // ── Home directory priority (C lines 79–87) ───────────────────
        //
        // If the address doesn't already have a home directory (e.g., not
        // set from the passwd entry), try the router's home_directory
        // option first, then fall back to the deliver_home global
        // (now on DeliveryContext).
        //
        // C: if (!addr->home_dir && rblock->home_directory)
        //        addr->home_dir = rblock->home_directory;
        //    else if (!addr->home_dir)
        //        addr->home_dir = deliver_home;
        if addr.home_dir.is_none() {
            if let Some(ref home) = router_config.home_directory {
                addr.home_dir = Some(home.clone());
                tracing::debug!(
                    home_dir = %home,
                    source = "router_config.home_directory",
                    "queue_add: home directory set"
                );
            } else if let Some(ref deliver_home) = ctx.deliver_home {
                addr.home_dir = Some(deliver_home.clone());
                tracing::debug!(
                    home_dir = %deliver_home,
                    source = "deliver_home",
                    "queue_add: home directory set from deliver_home fallback"
                );
            }
        }

        // ── Current directory (C lines 88–89) ─────────────────────────
        //
        // C: if (addr->current_dir == NULL && rblock->current_directory)
        //        addr->current_dir = rblock->current_directory;
        if addr.current_dir.is_none() {
            if let Some(ref current) = router_config.current_directory {
                addr.current_dir = Some(current.clone());
                tracing::debug!(
                    current_dir = %current,
                    "queue_add: current directory set from router config"
                );
            }
        }

        // ── Queue for local delivery (C lines 91–92) ──────────────────
        //
        // C: addr->next = *paddr_local; *paddr_local = addr;
        //
        // In C, this prepends the address to the local chain. In Rust,
        // we push to the Vec (callers process all queued addresses).
        local_queue.push(addr.clone());
    } else {
        // ── REMOTE TRANSPORT PATH (C lines 95–116) ─────────────────────

        // ── Set up fallback hosts (C lines 101–113) ───────────────────
        //
        // Priority:
        // 1. Pre-built fallback_hostlist from router config (static list)
        // 2. Expand fallback_hosts string and parse into host items
        //
        // C: if (rblock->fallback_hostlist)
        //        addr->fallback_hosts = rblock->fallback_hostlist;
        //    else if ((s = rblock->fallback_hosts) != NULL)
        //        { ... expand and parse ... }
        if !router_config.fallback_hostlist.is_empty() {
            // Use pre-built host list from router configuration.
            // The fallback_hostlist is already a Vec<String> of host names,
            // matching the local AddressItem's Vec<String> fallback_hosts field.
            addr.fallback_hosts = router_config.fallback_hostlist.clone();

            tracing::debug!(
                count = addr.fallback_hosts.len(),
                "queue_add: fallback hosts set from pre-built hostlist"
            );
        } else if let Some(ref fallback_str) = router_config.fallback_hosts {
            // Expand the fallback_hosts string (may contain ${...} expressions).
            //
            // The fallback_hosts value comes from router configuration and may
            // incorporate tainted data through expansion. We wrap the raw string
            // in Tainted<> to document its provenance, then expand and parse.
            //
            // C: if (!(s = expand_string(s))) {
            //        addr->message = string_sprintf("failed to expand ...");
            //        return FALSE;
            //    }
            let _tainted_input = Tainted::new(fallback_str.clone());

            let expanded = expand_string(fallback_str).map_err(|e| {
                QueueAddError::FallbackHostsExpansionFailed(format!(
                    "failed to expand \"{}\" for {} router: {}",
                    fallback_str, router_config.name, e
                ))
            })?;

            // The expanded result is potentially tainted — wrap it to track
            // provenance per AAP §0.7 taint tracking rules.
            let tainted_expanded = Tainted::new(expanded);

            // Parse the tainted expanded string into HostItems. We extract the
            // inner value at the boundary because AddressItem.fallback_hosts
            // stores Vec<HostItem> (not Vec<Tainted<HostItem>>).
            let hosts_str = tainted_expanded.into_inner();
            addr.fallback_hosts = parse_host_list(&hosts_str);

            tracing::debug!(
                expanded = %hosts_str,
                count = addr.fallback_hosts.len(),
                "queue_add: fallback hosts set from expanded string"
            );
        }

        // ── Queue for remote delivery (C lines 114–116) ───────────────
        //
        // C: addr->next = *paddr_remote; *paddr_remote = addr;
        //    remote_delivery_count++;
        remote_queue.push(addr.clone());
        ctx.remote_delivery_count += 1;

        tracing::debug!(
            remote_delivery_count = ctx.remote_delivery_count,
            "queue_add: remote delivery count incremented"
        );
    }

    // ── Step 3: Debug logging (C lines 119–127) ────────────────────────
    //
    // C: DEBUG(D_route) {
    //      debug_printf("queued for %s transport ", addr->transport->name);
    //      debug_printf("  local_part = %s\n  domain = %s\n", ...);
    //      if (addr->prop.errors_address) debug_printf("  errors_to = %s\n", ...);
    //      if (addr->prop.domain_data) debug_printf("  domain_data = %s\n", ...);
    //      if (addr->prop.localpart_data) debug_printf("  localpart_data = %s\n", ...);
    //    }
    tracing::debug!(
        transport = ?transport_name.as_deref().unwrap_or("<none>"),
        local_part = %addr.local_part,
        domain = %addr.domain,
        errors_to = ?addr.prop.errors_address,
        domain_data = ?addr.prop.domain_data,
        localpart_data = ?addr.prop.localpart_data,
        is_local = is_local,
        "queued for transport"
    );

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
//  Unit Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── PasswdEntry tests ───────────────────────────────────────────────

    #[test]
    fn test_passwd_entry_new() {
        let pw = PasswdEntry::new("testuser", 1000, 1000, "/home/testuser", "/bin/bash");
        assert_eq!(pw.pw_name, "testuser");
        assert_eq!(pw.pw_uid, 1000);
        assert_eq!(pw.pw_gid, 1000);
        assert_eq!(pw.pw_dir, "/home/testuser");
        assert_eq!(pw.pw_shell, "/bin/bash");
    }

    #[test]
    fn test_passwd_entry_display() {
        let pw = PasswdEntry::new("exim", 100, 101, "/var/spool/exim", "/usr/sbin/nologin");
        let display = format!("{pw}");
        assert!(display.contains("exim"));
        assert!(display.contains("100"));
        assert!(display.contains("101"));
        assert!(display.contains("/var/spool/exim"));
        assert!(display.contains("/usr/sbin/nologin"));
    }

    #[test]
    fn test_passwd_entry_clone() {
        let pw = PasswdEntry::new("user", 500, 500, "/home/user", "/bin/sh");
        let cloned = pw.clone();
        assert_eq!(pw, cloned);
    }

    // ── QueueAddError tests ─────────────────────────────────────────────

    #[test]
    fn test_error_display_ugid_failed() {
        let err = QueueAddError::UgidFailed("user not found: nobody".to_string());
        let display = err.to_string();
        assert!(display.contains("failed to get uid/gid"));
        assert!(display.contains("user not found: nobody"));
    }

    #[test]
    fn test_error_display_fallback_hosts_failed() {
        let err = QueueAddError::FallbackHostsExpansionFailed(
            "expansion failed: unknown variable".to_string(),
        );
        let display = err.to_string();
        assert!(display.contains("failed to expand fallback_hosts"));
        assert!(display.contains("unknown variable"));
    }

    #[test]
    fn test_error_from_get_ugid_error() {
        let ugid_err = GetUgidError::UserNotFound("nobody".to_string());
        let queue_err: QueueAddError = ugid_err.into();
        match queue_err {
            QueueAddError::UgidFailed(msg) => {
                assert!(msg.contains("nobody"));
            }
            other => panic!("expected UgidFailed, got: {other}"),
        }
    }

    // ── parse_host_list tests ───────────────────────────────────────────

    #[test]
    fn test_parse_host_list_single() {
        let hosts = parse_host_list("mail.example.com");
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0], "mail.example.com");
    }

    #[test]
    fn test_parse_host_list_multiple() {
        let hosts = parse_host_list("mx1.example.com : mx2.example.com : mx3.example.com");
        assert_eq!(hosts.len(), 3);
        assert_eq!(hosts[0], "mx1.example.com");
        assert_eq!(hosts[1], "mx2.example.com");
        assert_eq!(hosts[2], "mx3.example.com");
    }

    #[test]
    fn test_parse_host_list_with_ip() {
        let hosts = parse_host_list("10.0.0.1 : 10.0.0.2");
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0], "10.0.0.1");
        assert_eq!(hosts[1], "10.0.0.2");
    }

    #[test]
    fn test_parse_host_list_empty() {
        let hosts = parse_host_list("");
        assert!(hosts.is_empty());
    }

    #[test]
    fn test_parse_host_list_whitespace_only() {
        let hosts = parse_host_list("  :  :  ");
        assert!(hosts.is_empty());
    }

    #[test]
    fn test_parse_host_list_trims_whitespace() {
        let hosts = parse_host_list("  host1  :  host2  ");
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0], "host1");
        assert_eq!(hosts[1], "host2");
    }

    #[test]
    fn test_parse_host_list_single_entry_returned() {
        let hosts = parse_host_list("host1");
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0], "host1");
    }

    // ── Address flag constant tests ─────────────────────────────────────

    #[test]
    fn test_flag_bits_are_distinct() {
        assert_ne!(AF_UID_SET, AF_GID_SET);
        assert_ne!(AF_UID_SET, AF_HOME_EXPANDED);
        assert_ne!(AF_UID_SET, AF_INITGROUPS);
        assert_ne!(AF_GID_SET, AF_HOME_EXPANDED);
        assert_ne!(AF_GID_SET, AF_INITGROUPS);
        assert_ne!(AF_HOME_EXPANDED, AF_INITGROUPS);
    }

    #[test]
    fn test_flag_bits_are_powers_of_two() {
        assert!(AF_UID_SET.is_power_of_two());
        assert!(AF_GID_SET.is_power_of_two());
        assert!(AF_HOME_EXPANDED.is_power_of_two());
        assert!(AF_INITGROUPS.is_power_of_two());
    }

    #[test]
    fn test_flag_bitwise_combine() {
        let combined = AF_UID_SET | AF_GID_SET | AF_HOME_EXPANDED;
        assert!(combined & AF_UID_SET != 0);
        assert!(combined & AF_GID_SET != 0);
        assert!(combined & AF_HOME_EXPANDED != 0);
        assert!(combined & AF_INITGROUPS == 0);
    }
}
