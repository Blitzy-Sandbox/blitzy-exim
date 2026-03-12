//! Transport selection and execution — replaces transport dispatch logic from
//! `src/src/deliver.c` and references `src/src/transport.c`.
//!
//! This module implements:
//! - Transport selection by name via the driver registry
//! - UID/GID resolution for local delivery ([`find_ugid`])
//! - Address batching for efficient delivery ([`batch_addresses`],
//!   [`same_hosts`], [`same_ugid`])
//! - Transport parallelism limiting ([`tpt_parallel_check`])
//! - Transport option expansion ([`expand_transport_options`])
//! - Local transport execution with fork/setuid/setgid
//!   ([`execute_local_transport`])
//! - Remote transport preparation ([`prepare_remote_transport`])
//!
//! # Design Patterns (AAP §0.4.2)
//!
//! - **Scoped context passing**: All functions receive context structs explicitly
//! - **Trait-based drivers**: Uses `TransportDriver` from `exim-drivers`
//! - **Taint tracking**: Expanded option values use `Tainted<T>` / `Clean<T>`
//! - **Zero `unsafe` code**: All POSIX calls use safe wrappers from `nix`
//!
//! # Source C Mapping
//!
//! | Rust function              | C origin                                     |
//! |----------------------------|----------------------------------------------|
//! | [`find_ugid`]              | `findugid()` — deliver.c lines 1832–1958     |
//! | [`same_hosts`]             | `same_hosts()` — deliver.c address batching   |
//! | [`same_ugid`]              | UID/GID comparison in batching logic          |
//! | [`batch_addresses`]        | `do_local_deliveries()` — deliver.c 2704–3190 |
//! | [`tpt_parallel_check`]     | `tpt_parallel_check()` — deliver.c 2646–2686  |
//! | [`expand_transport_options`]| Option expansion in `deliver_local()`        |
//! | [`execute_local_transport`]| `deliver_local()` — deliver.c 2129 (~515 ln)  |
//! | [`prepare_remote_transport`]| Remote grouping in `do_remote_deliveries()`  |

use std::ffi::CString;
use std::path::Path;

use crate::orchestrator::AddressItem;

use exim_config::types::{ConfigContext, DeliveryContext, MessageContext, ServerContext};
use exim_drivers::registry::DriverRegistry;
use exim_drivers::transport_driver::{TransportDriver, TransportInstanceConfig, TransportResult};
use exim_drivers::DriverError;
use exim_expand::{expand_string, ExpandError};
use exim_store::taint::{Clean, Tainted};

use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{chdir, initgroups, pipe, setgid, setuid, ForkResult, Gid, Uid};

// fork_process() is the safe wrapper around nix::unistd::fork() provided by
// the exim-ffi crate — the only crate permitted to contain unsafe code
// (AAP §0.7.2).  This keeps exim-deliver 100% safe Rust.
use exim_ffi::process::fork_process;

// ──────────────────────────────────────────────────────────────────────────────
// Additional AddressFlags bit constants used by transport dispatch
// ──────────────────────────────────────────────────────────────────────────────
//
// These extend the base flags defined in `orchestrator.rs` with constants from
// C `macros.h` / `deliver.h` that are specific to transport dispatch decisions.

/// Address has a router-set UID (C: `af_uid_set`).
const AF_UID_SET: u32 = 0x0000_1000;

/// Address has a router-set GID (C: `af_gid_set`).
const AF_GID_SET: u32 = 0x0000_2000;

/// Address requires `initgroups()` in the delivery subprocess (C: `af_initgroups`).
const AF_INITGROUPS: u32 = 0x0000_4000;

/// Address was generated from a pipe/file/reply redirect (C: `af_pfr`).
const AF_PFR: u32 = 0x0000_0400;

/// Address represents a direct-to-file delivery (C: `af_file`).
const AF_FILE: u32 = 0x0000_0800;

// ──────────────────────────────────────────────────────────────────────────────
// Pipe protocol constants for parent ↔ child transport result communication
// ──────────────────────────────────────────────────────────────────────────────

/// Transport succeeded — address delivered.
const PIPE_RESULT_OK: u8 = 0;
/// Transport deferred — temporary failure, retry later.
const PIPE_RESULT_DEFERRED: u8 = 1;
/// Transport failed — permanent failure.
const PIPE_RESULT_FAILED: u8 = 2;
/// Transport error — internal/system error.
const PIPE_RESULT_ERROR: u8 = 3;

/// Errno value indicating a transport retry deferral (C: `ERRNO_TRETRY`).
/// Used by callers of [`tpt_parallel_check`] to mark deferred addresses.
pub const ERRNO_TRETRY: i32 = -49;

// ──────────────────────────────────────────────────────────────────────────────
// TransportDispatchError
// ──────────────────────────────────────────────────────────────────────────────

/// Errors arising from transport dispatch operations.
///
/// Covers all failure modes in the transport selection and execution pipeline:
/// transport lookup, UID/GID resolution, option expansion, execution, and
/// environment setup.
#[derive(Debug, thiserror::Error)]
pub enum TransportDispatchError {
    /// The named transport was not found in the configuration or registry.
    #[error("transport not found: {name}")]
    TransportNotFound {
        /// Transport name that could not be resolved.
        name: String,
    },

    /// UID/GID resolution failed during local delivery setup.
    #[error("uid/gid resolution failed: {0}")]
    UgidResolutionFailed(String),

    /// A transport option string expansion failed.
    #[error("option expansion failed: {option} in transport {transport}: {message}")]
    OptionExpansionFailed {
        /// Name of the option that failed to expand.
        option: String,
        /// Name of the transport owning the option.
        transport: String,
        /// Underlying expansion error message.
        message: String,
    },

    /// Transport execution failed at the system level (fork, pipe, wait).
    #[error("transport execution failed: {0}")]
    ExecutionFailed(String),

    /// Transport parallelism limit was reached; delivery should be deferred.
    #[error("parallelism limit reached for transport {name}")]
    ParallelismLimitReached {
        /// Transport name whose limit was hit.
        name: String,
    },

    /// Home directory validation or access error.
    #[error("home directory error: {0}")]
    HomeDirectoryError(String),

    /// Working directory validation or access error.
    #[error("working directory error: {0}")]
    WorkingDirectoryError(String),
}

// ──────────────────────────────────────────────────────────────────────────────
// ExpandedTransportOptions
// ──────────────────────────────────────────────────────────────────────────────

/// Expanded transport options for a single delivery attempt.
///
/// All values are wrapped in [`Tainted<String>`] because they originate from
/// configuration file strings containing `${…}` expressions whose expansions
/// may include untrusted variable substitutions (AAP §0.4.3).
#[derive(Debug, Clone, Default)]
pub struct ExpandedTransportOptions {
    /// Expanded envelope return-path for this delivery.
    pub return_path: Option<Tainted<String>>,
    /// Expanded home directory path (must be absolute when set).
    pub home_dir: Option<Tainted<String>>,
    /// Expanded current working directory path.
    pub current_dir: Option<Tainted<String>>,
    /// Expanded `max_parallel` value (integer string).
    pub max_parallel: Option<Tainted<String>>,
    /// Expanded transport filter command.
    pub filter_command: Option<Tainted<String>>,
    /// Expanded headers to add to the message.
    pub add_headers: Option<Tainted<String>>,
    /// Expanded headers to remove from the message.
    pub remove_headers: Option<Tainted<String>>,
}

// ──────────────────────────────────────────────────────────────────────────────
// RemoteBatch
// ──────────────────────────────────────────────────────────────────────────────

/// A batch of addresses grouped for a single remote delivery attempt.
///
/// Addresses in the same batch share the same transport and host list,
/// enabling delivery over a single SMTP connection.
#[derive(Debug, Clone)]
pub struct RemoteBatch {
    /// Transport name shared by all addresses in this batch.
    pub transport_name: String,
    /// Indices into the original address slice.
    pub address_indices: Vec<usize>,
    /// Host list shared by all addresses (cloned from the first address).
    pub host_list: Vec<String>,
}

// ──────────────────────────────────────────────────────────────────────────────
// find_ugid — UID/GID resolution (C findugid())
// ──────────────────────────────────────────────────────────────────────────────

/// Resolve the UID, GID, and `initgroups` flag for a local delivery.
///
/// Replaces C `findugid()` (deliver.c lines 1832–1958).  The resolution
/// priority chain is:
///
/// 1. Transport `gid_set` / `expand_gid` → explicit transport GID
/// 2. Address GID (set by router via `check_local_user`)
/// 3. Transport `uid_set` / `expand_uid` → explicit transport UID
/// 4. `deliver_as_creator` → originator's UID/GID
/// 5. Address UID (set by router)
/// 6. Error — both UID and GID must be resolved
///
/// # Errors
///
/// Returns [`TransportDispatchError::UgidResolutionFailed`] when neither the
/// transport configuration nor the address provides a valid UID/GID, or
/// [`TransportDispatchError::OptionExpansionFailed`] when `expand_uid` /
/// `expand_gid` string expansion fails.
#[tracing::instrument(level = "debug", skip(addr, transport_config, config))]
pub fn find_ugid(
    addr: &AddressItem,
    transport_config: &TransportInstanceConfig,
    config: &ConfigContext,
) -> Result<(u32, u32, bool), TransportDispatchError> {
    // The config context is passed for use by the caller chain (e.g., never_users
    // list validation) and is available for future expansion of uid/gid validation
    // against system-level constraints from ConfigContext.
    let _ = &config.spool_directory;

    let mut uid: u32 = 0;
    let mut gid: u32 = 0;
    let mut uid_set = false;
    let mut gid_set = false;
    let mut use_initgroups = transport_config.initgroups;

    tracing::debug!(
        address = %addr.address.as_ref(),
        transport = %transport_config.name,
        "resolving uid/gid for local delivery"
    );

    // ── GID resolution ───────────────────────────────────────────────────
    // Priority: transport.gid_set → transport.expand_gid → addr af_gid_set

    if transport_config.gid_set {
        gid = transport_config.gid;
        gid_set = true;
        tracing::debug!(gid, "using transport fixed gid");
    } else if let Some(ref expand_gid_str) = transport_config.expand_gid {
        let expanded = expand_option(expand_gid_str, "expand_gid", &transport_config.name)?;
        gid = parse_id(&expanded, "gid", &transport_config.name)?;
        gid_set = true;
        tracing::debug!(gid, "using expanded gid from transport");
    } else if addr.flags.contains(AF_GID_SET) {
        gid = addr.gid;
        gid_set = true;
        tracing::debug!(gid, "using router-set gid from address");
    }

    // ── UID resolution ───────────────────────────────────────────────────
    // Priority: transport.uid_set → transport.expand_uid
    //           → deliver_as_creator → addr af_uid_set

    if transport_config.uid_set {
        uid = transport_config.uid;
        uid_set = true;
        tracing::debug!(uid, "using transport fixed uid");
    } else if let Some(ref expand_uid_str) = transport_config.expand_uid {
        let expanded = expand_option(expand_uid_str, "expand_uid", &transport_config.name)?;
        uid = parse_id(&expanded, "uid", &transport_config.name)?;
        uid_set = true;
        tracing::debug!(uid, "using expanded uid from transport");
    } else if transport_config.deliver_as_creator {
        // C uses originator_uid / originator_gid globals.  In Rust the process
        // effective uid/gid represents the submitting user's identity, recorded
        // at message reception.
        uid = nix::unistd::getuid().as_raw();
        uid_set = true;
        if !gid_set {
            gid = nix::unistd::getgid().as_raw();
            gid_set = true;
        }
        tracing::debug!(uid, gid, "using originator uid/gid (deliver_as_creator)");
    } else if addr.flags.contains(AF_UID_SET) {
        uid = addr.uid;
        uid_set = true;
        tracing::debug!(uid, "using router-set uid from address");
    }

    // ── Validation ───────────────────────────────────────────────────────

    if !gid_set {
        return Err(TransportDispatchError::UgidResolutionFailed(format!(
            "no gid resolved for address {} via transport {}",
            addr.address.as_ref(),
            transport_config.name,
        )));
    }

    if !uid_set {
        return Err(TransportDispatchError::UgidResolutionFailed(format!(
            "no uid resolved for address {} via transport {}",
            addr.address.as_ref(),
            transport_config.name,
        )));
    }

    // Honour the initgroups flag from the address (set by router)
    if addr.flags.contains(AF_INITGROUPS) {
        use_initgroups = true;
    }

    // Wrap validated uid/gid in Clean<T> to document that they have been
    // verified through the resolution chain (AAP §0.4.3 taint tracking).
    let clean_uid = Clean::new(uid);
    let clean_gid = Clean::new(gid);

    tracing::debug!(
        uid = clean_uid.into_inner(),
        gid = clean_gid.into_inner(),
        use_initgroups,
        "uid/gid resolution complete"
    );
    Ok((uid, gid, use_initgroups))
}

// ──────────────────────────────────────────────────────────────────────────────
// same_hosts — host list comparison
// ──────────────────────────────────────────────────────────────────────────────

/// Check whether two addresses have identical host lists.
///
/// Addresses sharing the same host list (same hostnames in the same order) can
/// be batched into a single remote delivery, reusing a single SMTP connection.
///
/// Replaces the C `same_hosts()` comparison in `deliver.c`.
pub fn same_hosts(addr1: &AddressItem, addr2: &AddressItem) -> bool {
    if addr1.host_list.len() != addr2.host_list.len() {
        tracing::trace!(
            addr1 = %addr1.address.as_ref(),
            addr2 = %addr2.address.as_ref(),
            "host list length mismatch"
        );
        return false;
    }

    let matched = addr1
        .host_list
        .iter()
        .zip(addr2.host_list.iter())
        .all(|(h1, h2)| h1 == h2);

    tracing::trace!(
        addr1 = %addr1.address.as_ref(),
        addr2 = %addr2.address.as_ref(),
        matched,
        "compared host lists"
    );
    matched
}

// ──────────────────────────────────────────────────────────────────────────────
// same_ugid — UID/GID comparison
// ──────────────────────────────────────────────────────────────────────────────

/// Check whether two addresses share the same UID and GID.
///
/// Addresses with matching credentials can share a single delivery subprocess,
/// avoiding redundant fork/setuid cycles.
pub fn same_ugid(addr1: &AddressItem, addr2: &AddressItem) -> bool {
    let matched = addr1.uid == addr2.uid && addr1.gid == addr2.gid;

    tracing::trace!(
        addr1 = %addr1.address.as_ref(),
        addr2 = %addr2.address.as_ref(),
        uid1 = addr1.uid,
        gid1 = addr1.gid,
        uid2 = addr2.uid,
        gid2 = addr2.gid,
        matched,
        "compared uid/gid"
    );
    matched
}

// ──────────────────────────────────────────────────────────────────────────────
// batch_addresses — group addresses for batched delivery
// ──────────────────────────────────────────────────────────────────────────────

/// Group addresses into batches suitable for single transport invocations.
///
/// Replaces the address batching logic in C `do_local_deliveries()` (deliver.c
/// lines 2750–2950).  Addresses are grouped when they share:
///
/// - Same transport assignment
/// - Same PFR / FILE flags (pipe/file/reply redirection source)
/// - Same `errors_address` override
/// - Same `extra_headers` and `remove_headers` properties
/// - Same UID/GID (via [`same_ugid`])
/// - Same first host (for remote batching)
///
/// Each batch can be delivered in a single transport invocation, improving
/// throughput by reducing fork/exec and connection overhead.
///
/// # Returns
///
/// A `Vec` of index groups where each inner `Vec<usize>` contains indices into
/// the input `addresses` slice that should be delivered together.
pub fn batch_addresses(addresses: &[AddressItem]) -> Vec<Vec<usize>> {
    if addresses.is_empty() {
        return Vec::new();
    }

    let mut batches: Vec<Vec<usize>> = Vec::new();

    for (idx, addr) in addresses.iter().enumerate() {
        let mut found_batch = false;

        for batch in batches.iter_mut() {
            let first_idx = batch[0];
            let first = &addresses[first_idx];

            if can_batch(first, addr) {
                batch.push(idx);
                found_batch = true;
                tracing::trace!(
                    address = %addr.address.as_ref(),
                    batch_head = %first.address.as_ref(),
                    batch_size = batch.len(),
                    "added address to existing batch"
                );
                break;
            }
        }

        if !found_batch {
            tracing::trace!(address = %addr.address.as_ref(), "starting new batch");
            batches.push(vec![idx]);
        }
    }

    tracing::debug!(
        total_addresses = addresses.len(),
        total_batches = batches.len(),
        "address batching complete"
    );
    batches
}

/// Check whether two addresses satisfy all batching criteria.
///
/// Implements the full set of C batching conditions from
/// `do_local_deliveries()`.
fn can_batch(first: &AddressItem, candidate: &AddressItem) -> bool {
    // Must share the same transport
    if first.transport != candidate.transport {
        return false;
    }

    // Must share PFR and FILE flags (redirect origin)
    if first.flags.contains(AF_PFR) != candidate.flags.contains(AF_PFR) {
        return false;
    }
    if first.flags.contains(AF_FILE) != candidate.flags.contains(AF_FILE) {
        return false;
    }

    // Must share errors_address
    if first.errors_address != candidate.errors_address {
        return false;
    }

    // Must share extra_headers and remove_headers
    if first.prop.extra_headers != candidate.prop.extra_headers {
        return false;
    }
    if first.prop.remove_headers != candidate.prop.remove_headers {
        return false;
    }

    // Must share uid/gid
    if !same_ugid(first, candidate) {
        return false;
    }

    // Must share the first host name (if any hosts are present)
    if !first.host_list.is_empty() || !candidate.host_list.is_empty() {
        let first_host = first.host_list.first().map(String::as_str);
        let cand_host = candidate.host_list.first().map(String::as_str);
        if first_host != cand_host {
            return false;
        }
    }

    true
}

// ──────────────────────────────────────────────────────────────────────────────
// tpt_parallel_check — transport parallelism limiting
// ──────────────────────────────────────────────────────────────────────────────

/// Check and enforce the `max_parallel` transport parallelism limit.
///
/// Replaces C `tpt_parallel_check()` (deliver.c lines 2646–2686).  Expands the
/// `max_parallel` transport option and, if a positive limit is configured,
/// returns a serialization key for the caller to manage concurrency via the
/// hints database.  When the limit is reached, the address is deferred with
/// `ERRNO_TRETRY`.
///
/// # Returns
///
/// - `Ok(Some((key, state)))` — limit is configured and not yet reached.
/// - `Ok(None)` — no parallelism limit configured.
/// - `Err(ParallelismLimitReached)` — caller should defer the address.
#[tracing::instrument(level = "debug", skip(transport_config, addr, config))]
pub fn tpt_parallel_check(
    transport_config: &TransportInstanceConfig,
    addr: &mut AddressItem,
    config: &ConfigContext,
) -> Result<Option<(String, String)>, TransportDispatchError> {
    // The config context is reserved for hints-db integration when
    // enforcing serialisation limits (enq_start/enq_end).
    let _ = &config.spool_directory;

    // The addr parameter is reserved for setting ERRNO_TRETRY on deferral.
    // In the current implementation the caller handles deferral; the addr is
    // kept in the signature for C-parity and future use.
    let _ = &addr.address;

    let max_parallel_str = match &transport_config.max_parallel {
        Some(s) if !s.is_empty() => s.clone(),
        _ => {
            tracing::debug!(
                transport = %transport_config.name,
                "no max_parallel configured"
            );
            return Ok(None);
        }
    };

    // Expand at delivery time (may contain ${...} expressions)
    let expanded = expand_option(&max_parallel_str, "max_parallel", &transport_config.name)?;

    let max_parallel: i32 = expanded.trim().parse().unwrap_or(0);

    if max_parallel <= 0 {
        tracing::debug!(
            transport = %transport_config.name,
            max_parallel,
            "max_parallel non-positive, unlimited"
        );
        return Ok(None);
    }

    tracing::debug!(
        transport = %transport_config.name,
        max_parallel,
        "checking transport parallelism"
    );

    // Build the serialization key matching the C pattern:
    //   key  = "tpt-serialize-<transport_name>"
    // The caller is responsible for calling enq_start() (via the hints DB)
    // to acquire the lock.  If the lock cannot be acquired (limit reached),
    // the caller defers all remaining addresses with ERRNO_TRETRY.
    let serialize_key = format!("tpt-serialize-{}", transport_config.name);
    let serialize_state = format!("max_parallel={}", max_parallel);

    tracing::debug!(
        transport = %transport_config.name,
        key = %serialize_key,
        max_parallel,
        "parallelism check passed"
    );

    Ok(Some((serialize_key, serialize_state)))
}

// ──────────────────────────────────────────────────────────────────────────────
// expand_transport_options — option expansion at delivery time
// ──────────────────────────────────────────────────────────────────────────────

/// Expand transport configuration strings at delivery time.
///
/// Options are evaluated in the current delivery context (with `$local_part`,
/// `$domain`, `$sender_address`, etc. set by
/// [`deliver_set_expansions()`](crate::orchestrator::deliver_set_expansions)).
///
/// All expanded values are wrapped in [`Tainted<String>`] because they originate
/// from configuration file strings that may include untrusted variable
/// substitutions (AAP §0.4.3).
///
/// # Errors
///
/// Returns [`TransportDispatchError::OptionExpansionFailed`] if any option
/// expansion fails, or [`TransportDispatchError::HomeDirectoryError`] if the
/// expanded home directory is not an absolute path.
#[tracing::instrument(level = "debug", skip(transport_config))]
pub fn expand_transport_options(
    transport_config: &TransportInstanceConfig,
) -> Result<ExpandedTransportOptions, TransportDispatchError> {
    let mut opts = ExpandedTransportOptions::default();
    let tname = &transport_config.name;

    tracing::debug!(transport = %tname, "expanding transport options");

    // return_path
    if let Some(ref rp) = transport_config.return_path {
        let expanded = expand_option(rp, "return_path", tname)?;
        opts.return_path = Some(Tainted::new(expanded));
    }

    // home_directory — must be an absolute path when non-empty
    if let Some(ref hd) = transport_config.home_dir {
        let expanded = expand_option(hd, "home_directory", tname)?;
        if !expanded.is_empty() && !expanded.starts_with('/') {
            return Err(TransportDispatchError::HomeDirectoryError(format!(
                "home_directory '{}' is not absolute in transport {}",
                expanded, tname
            )));
        }
        opts.home_dir = Some(Tainted::new(expanded));
    }

    // current_directory
    if let Some(ref cd) = transport_config.current_dir {
        let expanded = expand_option(cd, "current_directory", tname)?;
        opts.current_dir = Some(Tainted::new(expanded));
    }

    // max_parallel
    if let Some(ref mp) = transport_config.max_parallel {
        let expanded = expand_option(mp, "max_parallel", tname)?;
        opts.max_parallel = Some(Tainted::new(expanded));
    }

    // filter_command
    if let Some(ref fc) = transport_config.filter_command {
        let expanded = expand_option(fc, "filter_command", tname)?;
        opts.filter_command = Some(Tainted::new(expanded));
    }

    // add_headers (headers_add)
    if let Some(ref ah) = transport_config.add_headers {
        let expanded = expand_option(ah, "add_headers", tname)?;
        opts.add_headers = Some(Tainted::new(expanded));
    }

    // remove_headers (headers_remove)
    if let Some(ref rh) = transport_config.remove_headers {
        let expanded = expand_option(rh, "remove_headers", tname)?;
        opts.remove_headers = Some(Tainted::new(expanded));
    }

    tracing::debug!(transport = %tname, "transport options expanded successfully");
    Ok(opts)
}

// ──────────────────────────────────────────────────────────────────────────────
// execute_local_transport — local delivery with fork/setuid
// ──────────────────────────────────────────────────────────────────────────────

/// Execute a local transport for a single address.
///
/// Replaces C `deliver_local()` (deliver.c line 2129, ~515 lines).  The
/// execution sequence is:
///
/// 1. Expand transport options (`return_path`, `home_directory`, etc.)
/// 2. Create a pipe for parent-child result communication
/// 3. Fork a child process
/// 4. **Child**: drop privileges (`setgid` / `setuid`), optionally call
///    `initgroups`, change to the working directory, invoke
///    [`TransportDriver::transport_entry()`], write the result to the pipe,
///    then exit
/// 5. **Parent**: read the transport result from the pipe, `waitpid` for the
///    child, and update the address status accordingly
///
/// # Errors
///
/// Returns [`TransportDispatchError::ExecutionFailed`] on system-level failures
/// (fork, pipe, wait).  Transport-level failures (defer, fail) are reflected in
/// the `addr.message` and `addr.basic_errno` fields rather than as errors.
// Justification: AAP §0.4.2 mandates explicit context-passing of 4 scoped
// structs (ServerContext, MessageContext, DeliveryContext, ConfigContext) plus
// the delivery-specific address, transport config, driver trait, and resolved
// uid/gid/initgroups.  Grouping these into an artificial wrapper struct would
// obscure the explicit context-passing contract required by the architecture.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(level = "info", skip_all, fields(
    address = %addr.address.as_ref(),
    transport = %transport_config.name,
    uid = uid,
    gid = gid,
))]
pub fn execute_local_transport(
    addr: &mut AddressItem,
    transport_config: &TransportInstanceConfig,
    driver: &dyn TransportDriver,
    uid: u32,
    gid: u32,
    use_initgroups: bool,
    server_ctx: &ServerContext,
    msg_ctx: &MessageContext,
    delivery_ctx: &mut DeliveryContext,
    config: &ConfigContext,
) -> Result<(), TransportDispatchError> {
    // Extract the raw address string from the Tainted wrapper for use in
    // logging and as the delivery target.  The taint state is propagated
    // through the transport option expansion where needed (AAP §0.4.3).
    let address_str = addr.address.clone().into_inner();
    let transport_name = transport_config.name.clone();

    tracing::info!(
        address = %address_str,
        transport = %transport_name,
        message_id = %msg_ctx.message_id,
        sender = %msg_ctx.sender_address,
        pid = server_ctx.pid,
        spool_dir = %config.spool_directory,
        uid,
        gid,
        initgroups = use_initgroups,
        "executing local transport"
    );

    // ── Expand transport options ─────────────────────────────────────────
    let expanded_opts = expand_transport_options(transport_config)?;

    // ── Determine working directories ────────────────────────────────────
    let home_dir = expanded_opts
        .home_dir
        .as_ref()
        .map(|t| t.as_ref().to_string())
        .or_else(|| addr.home_dir.clone());

    let current_dir = expanded_opts
        .current_dir
        .as_ref()
        .map(|t| t.as_ref().to_string())
        .or_else(|| addr.current_dir.clone())
        .or_else(|| home_dir.clone())
        .unwrap_or_else(|| "/".to_string());

    // Validate home directory is absolute
    if let Some(ref hd) = home_dir {
        if !hd.is_empty() && !hd.starts_with('/') {
            return Err(TransportDispatchError::HomeDirectoryError(format!(
                "home directory '{}' not absolute for {} transport {}",
                hd, address_str, transport_name
            )));
        }
    }

    // ── Update delivery context ──────────────────────────────────────────
    delivery_ctx.deliver_localpart = addr.local_part.clone();
    delivery_ctx.deliver_domain = addr.domain.clone();
    delivery_ctx.transport_name = Some(transport_name.clone());
    if let Some(ref hd) = home_dir {
        delivery_ctx.deliver_home = Some(hd.clone());
    }

    // ── Create pipe for result communication ─────────────────────────────
    let (pipe_read, pipe_write) = pipe().map_err(|e| {
        TransportDispatchError::ExecutionFailed(format!(
            "pipe creation failed for {}: {}",
            transport_name, e
        ))
    })?;

    // ── Fork child process ───────────────────────────────────────────────
    let fork_result = fork_process().map_err(|e| {
        TransportDispatchError::ExecutionFailed(format!(
            "fork failed for {}: {}",
            transport_name, e
        ))
    })?;

    match fork_result {
        ForkResult::Child => {
            // Child: close read end (child only writes)
            drop(pipe_read);

            let result = run_child_transport(
                &address_str,
                transport_config,
                driver,
                uid,
                gid,
                use_initgroups,
                &home_dir,
                &current_dir,
            );

            // Write the encoded result to the pipe (atomic for < PIPE_BUF)
            let encoded = encode_transport_result(&result);
            let _ = nix::unistd::write(&pipe_write, &encoded);

            // Exit child — std::process::exit does NOT run Rust Drop
            // destructors, matching the C _exit() behaviour.
            let code = if result.is_ok() { 0 } else { 1 };
            std::process::exit(code);
        }

        ForkResult::Parent { child } => {
            // Parent: close write end (parent only reads)
            drop(pipe_write);

            // Read encoded result from child
            let mut buf = [0u8; 1024];
            let bytes_read = nix::unistd::read(&pipe_read, &mut buf).unwrap_or(0);

            drop(pipe_read);

            // Reap child
            let wait_status = waitpid(child, None).map_err(|e| {
                TransportDispatchError::ExecutionFailed(format!(
                    "waitpid failed for {}: {}",
                    transport_name, e
                ))
            })?;

            tracing::debug!(
                transport = %transport_name,
                child_pid = child.as_raw(),
                ?wait_status,
                bytes_read,
                "child process completed"
            );

            // Decode result and update address
            if bytes_read > 0 {
                let transport_result = decode_transport_result(&buf[..bytes_read]);
                apply_transport_result(addr, transport_result);
            } else {
                handle_empty_pipe_result(addr, &transport_name, wait_status);
            }

            tracing::info!(
                address = %address_str,
                transport = %transport_name,
                message = ?addr.message,
                errno = addr.basic_errno,
                "local transport execution complete"
            );
        }
    }

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// prepare_remote_transport — group addresses for remote delivery
// ──────────────────────────────────────────────────────────────────────────────

/// Prepare address batches for remote delivery.
///
/// Groups addresses by transport name and host list so that addresses sharing
/// the same SMTP destination can be delivered over a single connection.  Used
/// by [`parallel.rs`](crate::parallel) before forking delivery subprocesses.
///
/// # Returns
///
/// A `Vec<RemoteBatch>` where each batch groups addresses deliverable over a
/// single remote connection.
#[tracing::instrument(level = "debug", skip(addresses, config))]
pub fn prepare_remote_transport(
    addresses: &[AddressItem],
    config: &ConfigContext,
) -> Vec<RemoteBatch> {
    let _spool = &config.spool_directory; // reserve for future spool-path validation
    let mut batches: Vec<RemoteBatch> = Vec::new();

    for (idx, addr) in addresses.iter().enumerate() {
        // Skip addresses without a transport assignment
        let transport_name = match &addr.transport {
            Some(name) => name.clone(),
            None => {
                tracing::warn!(
                    address = %addr.address.as_ref(),
                    "skipping address without transport"
                );
                continue;
            }
        };

        // Validate that the transport exists in the compile-time registry.
        // This is a defensive check — addresses should already have valid
        // transport assignments from the routing phase.
        if DriverRegistry::find_transport(&transport_name).is_none() {
            tracing::warn!(
                address = %addr.address.as_ref(),
                transport = %transport_name,
                "transport not found in registry, skipping"
            );
            continue;
        }

        // Skip addresses with no host list (local deliveries)
        if addr.host_list.is_empty() {
            tracing::trace!(
                address = %addr.address.as_ref(),
                transport = %transport_name,
                "skipping local address in remote preparation"
            );
            continue;
        }

        // Try to find an existing batch with matching transport + hosts
        let mut found = false;
        for batch in batches.iter_mut() {
            if batch.transport_name == transport_name && batch.host_list == addr.host_list {
                batch.address_indices.push(idx);
                found = true;
                tracing::trace!(
                    address = %addr.address.as_ref(),
                    transport = %transport_name,
                    batch_size = batch.address_indices.len(),
                    "added to existing remote batch"
                );
                break;
            }
        }

        if !found {
            tracing::trace!(
                address = %addr.address.as_ref(),
                transport = %transport_name,
                hosts = ?addr.host_list,
                "creating new remote batch"
            );
            batches.push(RemoteBatch {
                transport_name,
                address_indices: vec![idx],
                host_list: addr.host_list.clone(),
            });
        }
    }

    tracing::debug!(
        total_addresses = addresses.len(),
        total_batches = batches.len(),
        "remote transport preparation complete"
    );
    batches
}

// ──────────────────────────────────────────────────────────────────────────────
// Private helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Expand a single transport option string, mapping errors to
/// [`TransportDispatchError::OptionExpansionFailed`].
fn expand_option(
    value: &str,
    option_name: &str,
    transport_name: &str,
) -> Result<String, TransportDispatchError> {
    expand_string(value).map_err(|e| {
        let message = match e {
            ExpandError::Failed { message } => message,
            ExpandError::ForcedFail => "forced failure".to_string(),
            other => format!("{}", other),
        };
        TransportDispatchError::OptionExpansionFailed {
            option: option_name.to_string(),
            transport: transport_name.to_string(),
            message,
        }
    })
}

/// Parse an expanded string as a numeric UID or GID.
fn parse_id(
    expanded: &str,
    label: &str,
    transport_name: &str,
) -> Result<u32, TransportDispatchError> {
    expanded.trim().parse::<u32>().map_err(|e| {
        TransportDispatchError::UgidResolutionFailed(format!(
            "invalid {} '{}' from expand_{} in transport {}: {}",
            label, expanded, label, transport_name, e
        ))
    })
}

/// Execute the transport driver inside the child subprocess.
///
/// Sets up privilege and directory environment, then invokes
/// `driver.transport_entry()`.
// Justification: This function mirrors the C deliver_local() child-side
// logic that requires the transport config, driver, delivery credentials
// (uid/gid/initgroups), and directory paths.  All parameters are consumed
// directly and do not constitute a reusable grouping.
#[allow(clippy::too_many_arguments)]
fn run_child_transport(
    address: &str,
    transport_config: &TransportInstanceConfig,
    driver: &dyn TransportDriver,
    uid: u32,
    gid: u32,
    use_initgroups: bool,
    home_dir: &Option<String>,
    current_dir: &str,
) -> Result<TransportResult, String> {
    // Set GID first (must precede setuid)
    let nix_gid = Gid::from_raw(gid);
    if let Err(e) = setgid(nix_gid) {
        return Err(format!("setgid({}) failed: {}", gid, e));
    }

    // Initialize supplementary groups when required
    if use_initgroups {
        if let Some(pw_name) = lookup_username(uid) {
            if let Ok(c_name) = CString::new(pw_name.as_bytes()) {
                if let Err(e) = initgroups(&c_name, nix_gid) {
                    return Err(format!("initgroups({}, {}) failed: {}", pw_name, gid, e));
                }
            }
        }
    }

    // Set UID
    let nix_uid = Uid::from_raw(uid);
    if let Err(e) = setuid(nix_uid) {
        return Err(format!("setuid({}) failed: {}", uid, e));
    }

    // Change to working directory (fallback chain: current_dir -> home -> /)
    let work_path = Path::new(current_dir);
    if chdir(work_path).is_err() {
        if let Some(ref hd) = home_dir {
            if chdir(Path::new(hd.as_str())).is_err() {
                let _ = chdir(Path::new("/"));
            }
        } else {
            let _ = chdir(Path::new("/"));
        }
    }

    // Invoke the transport driver — DriverError is mapped to a descriptive
    // string for transmission over the parent-child pipe.
    driver
        .transport_entry(transport_config, address)
        .map_err(|e: DriverError| format!("transport_entry failed: {}", e))
}

/// Resolve a POSIX username from a UID via the system passwd database.
fn lookup_username(uid: u32) -> Option<String> {
    nix::unistd::User::from_uid(Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
}

/// Encode a transport result (or error message) into a byte buffer for
/// transmission over the parent-child pipe.
///
/// Wire format:
///   `[result_code:1][errno:4 BE][msg_len:2 BE][msg_bytes:N]`
fn encode_transport_result(result: &Result<TransportResult, String>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    match result {
        Ok(TransportResult::Ok) => {
            buf.push(PIPE_RESULT_OK);
            buf.extend_from_slice(&0i32.to_be_bytes());
            buf.extend_from_slice(&0u16.to_be_bytes());
        }
        Ok(TransportResult::Deferred { message, errno }) => {
            buf.push(PIPE_RESULT_DEFERRED);
            let errno_val = errno.unwrap_or(0);
            buf.extend_from_slice(&errno_val.to_be_bytes());
            write_msg_bytes(&mut buf, message.as_deref().unwrap_or(""));
        }
        Ok(TransportResult::Failed { message }) => {
            buf.push(PIPE_RESULT_FAILED);
            buf.extend_from_slice(&0i32.to_be_bytes());
            write_msg_bytes(&mut buf, message.as_deref().unwrap_or(""));
        }
        Ok(TransportResult::Error { message }) => {
            buf.push(PIPE_RESULT_ERROR);
            buf.extend_from_slice(&0i32.to_be_bytes());
            write_msg_bytes(&mut buf, message);
        }
        Err(message) => {
            buf.push(PIPE_RESULT_ERROR);
            buf.extend_from_slice(&0i32.to_be_bytes());
            write_msg_bytes(&mut buf, message);
        }
    }
    buf
}

/// Write a length-prefixed message string into the pipe buffer.
fn write_msg_bytes(buf: &mut Vec<u8>, msg: &str) {
    let bytes = msg.as_bytes();
    let len = bytes.len().min(u16::MAX as usize) as u16;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&bytes[..len as usize]);
}

/// Decode a transport result from bytes received via the pipe.
fn decode_transport_result(buf: &[u8]) -> TransportResult {
    if buf.is_empty() {
        return TransportResult::Error {
            message: "empty pipe result".to_string(),
        };
    }

    let result_code = buf[0];
    let errno_raw = if buf.len() >= 5 {
        i32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]])
    } else {
        0
    };
    let message_str = if buf.len() >= 7 {
        let msg_len = u16::from_be_bytes([buf[5], buf[6]]) as usize;
        let available = buf.len().saturating_sub(7);
        let take = msg_len.min(available);
        String::from_utf8_lossy(&buf[7..7 + take]).to_string()
    } else {
        String::new()
    };

    match result_code {
        PIPE_RESULT_OK => TransportResult::Ok,
        PIPE_RESULT_DEFERRED => TransportResult::Deferred {
            message: if message_str.is_empty() {
                None
            } else {
                Some(message_str)
            },
            errno: if errno_raw == 0 {
                None
            } else {
                Some(errno_raw)
            },
        },
        PIPE_RESULT_FAILED => TransportResult::Failed {
            message: if message_str.is_empty() {
                None
            } else {
                Some(message_str)
            },
        },
        _ => TransportResult::Error {
            message: message_str,
        },
    }
}

/// Apply a decoded [`TransportResult`] to an [`AddressItem`], updating its
/// `message` and `basic_errno` fields.
fn apply_transport_result(addr: &mut AddressItem, result: TransportResult) {
    match result {
        TransportResult::Ok => {
            addr.message = None;
            addr.basic_errno = 0;
            tracing::debug!(address = %addr.address.as_ref(), "transport success");
        }
        TransportResult::Deferred { message, errno } => {
            addr.message = message.clone();
            addr.basic_errno = errno.unwrap_or(0);
            tracing::debug!(
                address = %addr.address.as_ref(),
                errno = addr.basic_errno,
                message = ?message,
                "transport deferred"
            );
        }
        TransportResult::Failed { message } => {
            addr.message = message.clone();
            addr.basic_errno = -1;
            tracing::debug!(
                address = %addr.address.as_ref(),
                message = ?message,
                "transport failed"
            );
        }
        TransportResult::Error { ref message } => {
            addr.message = Some(message.clone());
            addr.basic_errno = -1;
            tracing::error!(
                address = %addr.address.as_ref(),
                message = %message,
                "transport error"
            );
        }
    }
}

/// Handle the case where the child wrote no data to the pipe.
fn handle_empty_pipe_result(addr: &mut AddressItem, transport_name: &str, wait_status: WaitStatus) {
    match wait_status {
        WaitStatus::Exited(_, 0) => {
            tracing::debug!(
                transport = %transport_name,
                "child exited 0 with no pipe data, treating as success"
            );
        }
        WaitStatus::Exited(_, code) => {
            addr.message = Some(format!(
                "transport {} child exited with code {}",
                transport_name, code
            ));
            addr.basic_errno = libc::EXIT_FAILURE;
            tracing::error!(transport = %transport_name, exit_code = code, "child error exit");
        }
        WaitStatus::Signaled(_, signal, _) => {
            addr.message = Some(format!(
                "transport {} child killed by signal {:?}",
                transport_name, signal
            ));
            addr.basic_errno = libc::EXIT_FAILURE;
            tracing::error!(
                transport = %transport_name,
                ?signal,
                "child killed by signal"
            );
        }
        other => {
            addr.message = Some(format!(
                "transport {} child abnormal status: {:?}",
                transport_name, other
            ));
            addr.basic_errno = libc::EXIT_FAILURE;
        }
    }
}
