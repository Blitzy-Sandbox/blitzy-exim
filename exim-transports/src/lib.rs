// =============================================================================
// exim-transports/src/lib.rs — Transport Driver Crate Root
// =============================================================================
//
// Crate root for the `exim-transports` crate. This file declares all transport
// modules (conditionally gated behind Cargo feature flags) and re-exports key
// types for downstream crates (`exim-deliver`, `exim-core`).
//
// This is the Rust equivalent of the transport section of `src/src/drtables.c`
// (compile-time transport registration) combined with the `Makefile` build
// logic in `src/src/transports/Makefile` (conditional compilation control).
//
// ## Architecture
//
// The crate provides 6 Exim transport driver implementations plus a Maildir
// helper module. Each transport implements the [`TransportDriver`] trait from
// `exim-drivers` and registers itself via `inventory::submit!` for compile-time
// driver collection — replacing the C `transport_info` struct inheritance
// pattern and `drtables.c` static registration tables.
//
// ## Transport Classification
//
// Transports are classified as either **local** or **remote**:
//
// - **Local transports** deliver to the local filesystem or run local commands:
//   - [`appendfile`] — mbox/MBX/Maildir/Mailstore with file locking
//   - [`autoreply`] — Vacation auto-response generation
//   - [`lmtp`] — LMTP client transport (via command pipe or UNIX socket)
//   - [`pipe`] — Pipe message to external command
//   - [`queuefile`] — Experimental spool file copy (behind feature flag)
//
// - **Remote transports** connect to other hosts over the network:
//   - [`smtp`] — Full outbound SMTP/LMTP state machine (6,573 lines in C)
//
// ## Maildir Helper
//
// The [`maildir`] module provides Maildir-specific helper functions (quota
// computation via `maildirsize` files, directory creation, size file
// management) used by the `appendfile` transport when Maildir format is
// enabled.
//
// ## Feature Flags
//
// Each transport module is conditionally compiled behind its corresponding
// Cargo feature flag, replacing C preprocessor conditionals (`TRANSPORT_*`,
// `EXPERIMENTAL_*`, `SUPPORT_*`). See `Cargo.toml` for the full feature
// mapping. Disabling all transport features produces a valid but empty crate
// containing only the re-exported types.
//
// ## Driver Registration
//
// Unlike the C `drtables.c` approach with explicit transport tables, Rust uses
// the `inventory` crate for automatic compile-time registration. Each transport
// module's `inventory::submit!(TransportDriverFactory { ... })` call runs at
// link time. No explicit initialization function is needed — the
// `inventory::iter::<TransportDriverFactory>()` call in
// `exim-drivers/src/registry.rs` collects all submitted factories.
//
// ## Zero Unsafe Code
//
// This crate root file contains zero `unsafe` code per AAP §0.7.2. All
// `unsafe` code is confined to the `exim-ffi` crate.
// =============================================================================

// Forbid unsafe code in this crate — `forbid` cannot be overridden by
// module-level `#[allow]` (AAP §0.7.2).
#![forbid(unsafe_code)]

// =============================================================================
// Feature-Gated Module Declarations
// =============================================================================
//
// Each transport module is conditionally compiled behind its Cargo feature
// flag. The feature flag names map directly to C preprocessor defines:
//
//   C Preprocessor Define          →  Cargo Feature
//   ─────────────────────────────────────────────────
//   TRANSPORT_APPENDFILE           →  transport-appendfile
//   TRANSPORT_AUTOREPLY            →  transport-autoreply
//   TRANSPORT_LMTP                 →  transport-lmtp
//   TRANSPORT_PIPE                 →  transport-pipe
//   (smtp.c always compiled)       →  transport-smtp
//   EXPERIMENTAL_QUEUEFILE         →  transport-queuefile
//   SUPPORT_MAILDIR                →  maildir

/// Appendfile transport — mbox/MBX/Maildir/Mailstore delivery with POSIX
/// file locking (fcntl/flock). Replaces `src/src/transports/appendfile.c`
/// (3,373 lines).
///
/// This is the primary local delivery transport, supporting four mailbox
/// formats with configurable locking strategies and quota enforcement.
///
/// **Feature flag**: `transport-appendfile` (replaces C `TRANSPORT_APPENDFILE`)
#[cfg(feature = "transport-appendfile")]
pub mod appendfile;

/// Autoreply transport — vacation auto-response message generation.
/// Replaces `src/src/transports/autoreply.c` (833 lines).
///
/// Generates automatic responses with template expansion, "never_mail"
/// filtering, and "once" suppression via DBM or circular cache file.
///
/// **Feature flag**: `transport-autoreply` (replaces C `TRANSPORT_AUTOREPLY`)
#[cfg(feature = "transport-autoreply")]
pub mod autoreply;

/// LMTP transport — LMTP client for local delivery via command pipe or
/// UNIX domain socket. Replaces `src/src/transports/lmtp.c` (839 lines).
///
/// Implements LHLO negotiation, optional IGNOREQUOTA, per-recipient
/// response mapping, and multi-line reply handling with timeouts.
///
/// **Feature flag**: `transport-lmtp` (replaces C `TRANSPORT_LMTP`)
#[cfg(feature = "transport-lmtp")]
pub mod lmtp;

/// Pipe transport — delivers messages to external commands via direct argv
/// or `/bin/sh -c`. Replaces `src/src/transports/pipe.c` (1,156 lines).
///
/// Provides controlled environment, taint restrictions, optional BSMTP
/// framing, output capture with reader process, and exit-status
/// interpretation.
///
/// **Feature flag**: `transport-pipe` (replaces C `TRANSPORT_PIPE`)
#[cfg(feature = "transport-pipe")]
pub mod pipe;

/// Queuefile transport — experimental spool file copy transport.
/// Replaces `src/src/transports/queuefile.c` (313 lines).
///
/// Copies spool `-H` (header) and `-D` (data) files into a target
/// directory using `openat`/`linkat` for safe spool file operations.
/// This is the simplest transport driver and is NOT included in default
/// features.
///
/// **Feature flag**: `transport-queuefile` (replaces C `EXPERIMENTAL_QUEUEFILE`)
#[cfg(feature = "transport-queuefile")]
pub mod queuefile;

/// SMTP transport — full outbound SMTP/LMTP state machine.
/// Replaces `src/src/transports/smtp.c` (6,573 lines — largest transport).
///
/// Implements the complete outbound SMTP protocol with TLS/DANE,
/// PIPELINING, CHUNKING, DKIM signing, PRDR, PIPE CONNECT early
/// pipelining, and ESMTP extensions. This is the only **remote**
/// transport.
///
/// **Feature flag**: `transport-smtp` (replaces C `TRANSPORT_SMTP`)
#[cfg(feature = "transport-smtp")]
pub mod smtp;

/// Maildir helper — quota computation, directory creation, and size file
/// management for Maildir format delivery.
/// Replaces `src/src/transports/tf_maildir.c` (570 lines).
///
/// Used by the [`appendfile`] transport when Maildir format is enabled.
/// Provides `maildirsize` file parsing, directory scanning for quota
/// enforcement, and Maildir directory hierarchy creation.
///
/// **Feature flag**: `maildir` (replaces C `SUPPORT_MAILDIR`)
#[cfg(feature = "maildir")]
pub mod maildir;

// =============================================================================
// Re-Exports from exim-drivers
// =============================================================================
//
// Re-export the transport driver trait and associated types from `exim-drivers`
// for convenience. This enables downstream crates (`exim-deliver`, `exim-core`)
// to import transport types via `exim_transports::TransportDriver` without
// needing a direct dependency on `exim-drivers`.
//
// These re-exports replace the C pattern where `structs.h` was included
// everywhere to access `transport_info` and `transport_instance` definitions.

/// The core transport driver trait — all 6 transport implementations implement
/// this trait.
///
/// Provides the following methods:
/// - [`transport_entry()`](TransportDriver::transport_entry) — Main delivery
///   entry point (replaces C `code()` function pointer)
/// - [`setup()`](TransportDriver::setup) — Pre-delivery setup for address
///   verification (default no-op)
/// - [`tidyup()`](TransportDriver::tidyup) — Post-delivery cleanup (default
///   no-op)
/// - [`closedown()`](TransportDriver::closedown) — Channel shutdown, primarily
///   used by SMTP transport (default no-op)
/// - [`is_local()`](TransportDriver::is_local) — Local vs remote
///   classification
/// - [`driver_name()`](TransportDriver::driver_name) — Driver identification
///   string
pub use exim_drivers::transport_driver::TransportDriver;

/// Result of transport execution — indicates the outcome of a delivery attempt.
///
/// Variants:
/// - [`Ok`](TransportResult::Ok) — Delivery succeeded
/// - [`Deferred`](TransportResult::Deferred) — Temporary failure, retry later
/// - [`Failed`](TransportResult::Failed) — Permanent failure
/// - [`Error`](TransportResult::Error) — Internal error during transport
pub use exim_drivers::transport_driver::TransportResult;

/// Per-instance transport configuration parsed from the Exim configuration
/// file.
///
/// Contains both generic transport fields (applicable to all transports)
/// and a type-erased `options` field holding driver-specific configuration.
///
/// Key fields include:
/// - `name` — Instance name from config (e.g., `"local_delivery"`)
/// - `driver_name` — Driver type (e.g., `"appendfile"`, `"smtp"`)
/// - `options` — Type-erased driver-specific options (`Box<dyn Any>`)
pub use exim_drivers::transport_driver::TransportInstanceConfig;

/// Factory for creating [`TransportDriver`] instances via compile-time
/// registration.
///
/// Each transport module registers a `TransportDriverFactory` via
/// `inventory::submit!` during compilation. At runtime, the
/// `DriverRegistry` collects all registered factories and uses them to
/// instantiate driver trait objects when processing the configuration file.
///
/// Key fields:
/// - `name` — Driver name matching config `driver = <name>` directives
/// - `create` — Factory function producing a boxed trait object
/// - `is_local` — Whether this transport is local (cached for registry queries)
pub use exim_drivers::transport_driver::TransportDriverFactory;

// =============================================================================
// Note on Driver Registration
// =============================================================================
//
// Unlike the C `drtables.c` approach with explicit transport tables, Rust uses
// the `inventory` crate for automatic compile-time registration:
//
//   1. Each transport module (e.g., `smtp.rs`, `appendfile.rs`) contains an
//      `inventory::submit!(TransportDriverFactory { ... })` call.
//
//   2. These registrations execute at link time — no explicit initialization
//      function is needed in this lib.rs.
//
//   3. The `inventory::iter::<TransportDriverFactory>()` call in
//      `exim-drivers/src/registry.rs` collects all submitted factories,
//      building the driver registry used during config parsing.
//
// This replaces the C pattern of:
//   - `transport_info * transports_available = NULL;` (drtables.c)
//   - Compile-time linked list construction via TRANSPORT_* macros
//   - Runtime `transport_info` chain traversal for driver lookup
