//! # Context Struct Definitions — Scoped Replacements for 714 Global Variables
//!
//! Per AAP §0.4.4, the 714 global variables in `globals.c`/`globals.h` are
//! replaced with 4 scoped context structs:
//!
//! | Context           | Scope               | Description                               |
//! |-------------------|----------------------|-------------------------------------------|
//! | [`ConfigContext`] | Process lifetime     | Parsed configuration, frozen into `Arc`   |
//! | [`ServerContext`] | Daemon lifetime      | Listening sockets, process table, TLS     |
//! | [`MessageContext`]| Per-message          | Sender, recipients, headers, ACL vars     |
//! | [`DeliveryContext`]| Per-delivery-attempt | Current address, router/transport results |
//!
//! # Architectural Note
//!
//! The canonical definitions of these structs reside in
//! [`exim_config::types`](exim_config::types) rather than in this file.
//! This is an intentional architectural decision to avoid a circular
//! dependency: many workspace crates (exim-acl, exim-expand, exim-deliver,
//! exim-smtp, etc.) depend on the context structs but must NOT depend on
//! `exim-core` (which depends on all of them). Placing the definitions in
//! `exim-config` — a low-level crate with minimal dependencies — allows
//! every crate in the workspace to import the context types without
//! introducing cycles.
//!
//! This module re-exports all four context structs plus supporting types
//! so that `exim-core` internal modules (daemon.rs, modes.rs, process.rs,
//! queue_runner.rs) can use `crate::context::ServerContext` as specified
//! in the AAP §0.4.1 file table.
//!
//! # Usage
//!
//! ```rust,ignore
//! use exim_core::context::{ServerContext, MessageContext, DeliveryContext, ConfigContext};
//! use exim_core::context::{Config, TlsInfo};
//!
//! // Create contexts at the appropriate scope boundary
//! let server_ctx = ServerContext::default();
//! let msg_ctx = MessageContext::default();
//! let delivery_ctx = DeliveryContext::default();
//! ```

// ============================================================================
// Re-exports from exim-config::types
// ============================================================================
//
// These re-exports provide the expected API surface described in AAP §0.4.4
// and the exim-core/src/context.rs file specification.

/// The frozen immutable configuration wrapper (AAP §0.4.3).
///
/// Created via [`Config::freeze()`] after configuration parsing is complete.
/// Shared across forked children via `Arc<Config>`.
pub use exim_config::types::Config;

/// The comprehensive parsed configuration context (AAP §0.4.4).
///
/// Holds all parsed options, driver instances, ACL definitions, rewrite
/// rules, retry rules, and named lists. Frozen into [`Arc<Config>`] after
/// parsing.
pub use exim_config::types::ConfigContext;

/// Per-delivery-attempt state (AAP §0.4.4).
///
/// Created fresh for each address delivery attempt. Holds the current
/// delivery address, router/transport results, retry data, and
/// delivery-attempt-specific settings. Dropped when the attempt completes.
pub use exim_config::types::DeliveryContext;

/// Per-message state (AAP §0.4.4).
///
/// Created for each message received. Holds sender, recipients, headers,
/// message body reference, message ID, ACL variables, and per-message
/// TLS state. Dropped when message processing completes.
pub use exim_config::types::MessageContext;

/// Daemon-lifetime server state (AAP §0.4.4).
///
/// Created once at startup. Holds listening sockets, process table (SMTP
/// slots), TLS credentials, and daemon-wide settings. Mutated during
/// daemon operation (connection acceptance, child reaping).
pub use exim_config::types::ServerContext;

/// TLS session information for inbound/outbound connections.
///
/// Embedded within [`MessageContext`] (as `tls_in`) and used during
/// delivery (as `tls_out`). Replaces the C `tls_support` struct.
pub use exim_config::types::TlsInfo;
