//! # exim-deliver
//!
//! Delivery orchestration crate for the Exim mail transfer agent.
//!
//! This crate implements the complete delivery pipeline, replacing four core C
//! source files totalling 13,119 lines:
//!
//! | C source file | Lines | Rust module                |
//! |---------------|-------|----------------------------|
//! | `deliver.c`   | 9,104 | [`orchestrator`], [`parallel`], [`journal`] |
//! | `route.c`     | 2,098 | [`routing`]                |
//! | `retry.c`     | 1,032 | [`retry`]                  |
//! | `moan.c`      |   885 | [`bounce`]                 |
//!
//! ## Pipeline Stages
//!
//! The delivery pipeline processes each message through these stages:
//!
//! 1. **Message ingestion** — [`deliver_message()`] reads the spool header file,
//!    recovers any partially-completed deliveries from the [`JournalState`]
//!    journal, and classifies recipients via [`ProcessRecipients`].
//!
//! 2. **Routing** — Each recipient address is routed through the router chain
//!    via [`route_address()`], which evaluates preconditions, prefix/suffix
//!    stripping, user/group lookup, and driver-specific logic.  Routed
//!    addresses are placed into the appropriate chain within [`AddressLists`].
//!
//! 3. **Local delivery** — Addresses in `addr_local` are delivered in-process
//!    (or via fork/exec with uid/gid privilege management) by the transport
//!    dispatch layer ([`transport_dispatch`]).
//!
//! 4. **Remote delivery** — Addresses in `addr_remote` are handed to the
//!    [`ParallelDeliveryManager`], which maintains a subprocess pool using
//!    fork-per-connection semantics, communicating results over pipes using
//!    the [`PipeMessageType`] protocol.
//!
//! 5. **Post-processing** — Delivery results are collected, the retry database
//!    is updated via [`retry_update()`], bounces and DSN notifications are
//!    generated via [`send_bounce_message()`] and [`maybe_send_dsn()`], and
//!    the spool header is rewritten.
//!
//! 6. **Journal cleanup** — On successful completion the journal file is
//!    removed via [`JournalState::close_and_remove()`].
//!
//! ## Architecture
//!
//! ### Modules
//!
//! - [`orchestrator`] — Main `deliver_message()` entry point, address data
//!   structures ([`AddressItem`], [`AddressLists`], [`AddressFlags`],
//!   [`AddressProperties`]), helper utilities (`deliver_split_address`,
//!   `deliver_make_addr`, `deliver_set_expansions`, etc.).
//!
//! - [`routing`] — Router chain evaluation via [`route_address()`], router
//!   initialization, prefix/suffix checking, user/group lookup, and router
//!   precondition checks.
//!
//! - [`transport_dispatch`] — Transport selection, uid/gid resolution, address
//!   batching, option expansion, and local/remote transport execution.
//!
//! - [`parallel`] — Fork-per-connection subprocess pool for remote delivery
//!   with pipe-based IPC, delivery result serialization, and domain-sorted
//!   address grouping.
//!
//! - [`retry`] — Per-host and per-message retry scheduling with hints database
//!   integration, retry rule evaluation, and host status tracking.
//!
//! - [`bounce`] — RFC 3464 DSN generation, bounce messages, delay warning
//!   messages, error copy notifications, and SMTP batch error reporting.
//!
//! - [`journal`] — Crash recovery via `-J` spool journal files.  Records
//!   completed deliveries as they happen so that a crash mid-delivery does
//!   not lose information about already-delivered addresses.
//!
//! ### Context Structs
//!
//! All functions receive explicit context structs instead of global variables
//! (AAP §0.4.4):
//!
//! - `ServerContext` — daemon-lifetime state (listening sockets, process table,
//!   signal state, TLS credentials)
//! - `MessageContext` — per-message state (sender, recipients, headers, body
//!   reference, message ID, ACL variables)
//! - `DeliveryContext` — per-delivery-attempt state (current address,
//!   router/transport results, retry data)
//! - `ConfigContext` — parsed configuration (all options, driver instances, ACL
//!   definitions, rewrite rules)
//!
//! ### Design Patterns (AAP §0.4.2)
//!
//! - **Scoped context passing** — no global mutable state
//! - **Compile-time taint tracking** — `Tainted<T>` / `Clean<T>` newtypes
//!   from `exim-store` for untrusted address data
//! - **Arena allocation** — per-message temporaries use `MessageArena`,
//!   dropped at message completion
//! - **Trait-based drivers** — routers and transports implement traits from
//!   `exim-drivers`, resolved at runtime from configuration
//! - **Feature flags** — optional functionality gated via Cargo features
//!   (see `Cargo.toml`): `dsn`, `tls`, `content-scan`, `i18n`, `dkim`,
//!   `measure-timing`, `dane`, `prdr`, `translate-ip-address`
//!
//! ## Safety (AAP §0.7.2)
//!
//! This crate contains **zero** `unsafe` code.  All POSIX system calls are
//! performed through the `nix` crate's safe wrappers.

// SPDX-License-Identifier: GPL-2.0-or-later

// Enforce the zero-unsafe-code policy at the crate level (AAP §0.7.2).
#![forbid(unsafe_code)]

// ---------------------------------------------------------------------------
// Module declarations
// ---------------------------------------------------------------------------

/// Bounce/DSN message generation, delay warnings, and error notifications.
///
/// Translates the notification and error-reporting functions from `moan.c`
/// (885 lines) and the bounce/DSN sections of `deliver.c`.
pub mod bounce;

/// Journal file management for crash recovery during delivery.
///
/// Implements the `-J` spool journal that records completed deliveries as
/// they happen, enabling safe recovery after an unexpected process exit.
pub mod journal;

/// Main delivery orchestration engine.
///
/// Contains the `deliver_message()` entry point and the core address data
/// structures (`AddressItem`, `AddressLists`, `AddressFlags`, etc.) that
/// flow through every stage of the delivery pipeline.  Translates the bulk
/// of `deliver.c` (9,104 lines).
pub mod orchestrator;

/// Subprocess pool for parallel remote delivery.
///
/// Manages fork-per-connection child processes, pipe-based IPC using the
/// `PipeMessageType` protocol, and domain-sorted address grouping for
/// efficient remote transport execution.
pub mod parallel;

/// Retry scheduling and hints database integration.
///
/// Implements per-host and per-message retry rules, the hints database
/// read/write cycle, and host status determination.  Translates `retry.c`
/// (1,032 lines).
pub mod retry;

/// Router chain evaluation and address routing.
///
/// Iterates the configured router chain for each recipient address,
/// evaluating preconditions, prefix/suffix stripping, and driver-specific
/// routing logic.  Translates `route.c` (2,098 lines).
pub mod routing;

/// Transport selection, uid/gid resolution, and execution.
///
/// Handles the dispatch of routed addresses to the appropriate transport
/// driver, including address batching, parallelism checks, transport option
/// expansion, and local/remote transport execution paths.
pub mod transport_dispatch;

// ---------------------------------------------------------------------------
// Re-exports — Orchestrator (primary public API)
// ---------------------------------------------------------------------------

pub use orchestrator::{
    // Helper functions
    common_error,
    deliver_make_addr,
    // Entry point
    deliver_message,
    deliver_msglog,
    deliver_set_expansions,
    deliver_split_address,
    post_process_one,
    // Core data structures
    AddressFlags,
    AddressItem,
    AddressLists,
    AddressProperties,
    // Enums
    DeliveryError,
    DeliveryResult,
    ProcessRecipients,
};

// ---------------------------------------------------------------------------
// Re-exports — Routing
// ---------------------------------------------------------------------------

pub use routing::{
    // Precondition helpers
    check_files,
    check_router_conditions,
    // Primary routing functions
    route_address,
    route_check_access,
    route_check_dls,
    // Prefix/suffix checks
    route_check_prefix,
    route_check_suffix,
    route_find_expanded_group,
    route_find_expanded_user,
    // User/group lookup
    route_findgroup,
    route_finduser,
    route_init,
    // Diagnostic utility
    router_current_name,
    // Types and enums
    RouterInstance,
    RoutingError,
    RoutingResult,
    UserInfo,
    VerifyMode,
};

// ---------------------------------------------------------------------------
// Re-exports — Transport Dispatch
// ---------------------------------------------------------------------------

pub use transport_dispatch::{
    // Uid/gid and address helpers
    batch_addresses,
    // Execution paths
    execute_local_transport,
    // Transport option expansion
    expand_transport_options,
    find_ugid,
    prepare_remote_transport,
    same_hosts,
    same_ugid,
    tpt_parallel_check,
    // Types
    ExpandedTransportOptions,
    RemoteBatch,
    TransportDispatchError,
};

// ---------------------------------------------------------------------------
// Re-exports — Parallel Delivery
// ---------------------------------------------------------------------------

pub use parallel::{
    // Utility functions
    sort_remote_deliveries,
    write_delivery_result,
    ParData,
    // Manager and data structures
    ParallelDeliveryManager,
    // IPC protocol
    PipeMessageType,
    PIPE_HEADER_SIZE,
};

// ---------------------------------------------------------------------------
// Re-exports — Retry
// ---------------------------------------------------------------------------

pub use retry::{
    // Primary retry functions
    retry_add_item,
    retry_check_address,
    retry_find_config,
    // Key-building and timeout helpers
    retry_host_key_build,
    retry_ultimate_address_timeout,
    retry_update,
    // Host status
    HostStatus,
    HostWhyUnusable,
    // Configuration and rule types
    RetryConfig,
    RetryError,
    RetryItem,
    RetryItemFlags,
    RetryRecord,
    RetryRule,
    RetryRuleType,
};

// ---------------------------------------------------------------------------
// Re-exports — Bounce / DSN
// ---------------------------------------------------------------------------

// The `maybe_send_dsn` function is always available: when the `dsn` Cargo
// feature is enabled, the real DSN implementation runs; when disabled, the
// bounce module provides a no-op stub.  No feature-gating is required here.
pub use bounce::{
    // Bounce/DSN generation
    maybe_send_dsn,
    // Notification entry points
    moan_check_errorcopy,
    moan_send_message,
    moan_skipped_syntax_errors,
    moan_smtp_batch,
    moan_tell_someone,
    moan_to_sender,
    send_bounce_message,
    send_warning_message,
    // Formatting helpers
    write_bounce_from,
    write_bounce_references,
    // Types and enums
    BounceError,
    ErrorBlock,
    ErrorMessageIdent,
};

// ---------------------------------------------------------------------------
// Re-exports — Journal
// ---------------------------------------------------------------------------

pub use journal::{JournalError, JournalState};
