//! # exim-deliver — Delivery Orchestration Crate
//!
//! This crate implements the delivery orchestration engine for the Exim MTA,
//! replacing the core of `src/src/deliver.c` (9,104 lines of C) with safe Rust.
//!
//! ## Architecture
//!
//! The crate is organized around the main `deliver_message()` entry point in
//! the `orchestrator` module, which coordinates:
//!
//! - Spool header reading and journal crash recovery
//! - Recipient classification and routing through the router chain
//! - Local delivery via fork/exec with uid/gid privilege management
//! - Remote delivery dispatch (delegated to the parallel delivery subsystem)
//! - Bounce generation for permanent failures
//! - DSN (Delivery Status Notification) processing
//! - Retry database updates and spool header persistence
//!
//! ## Design Principles
//!
//! - **Zero `unsafe` code** — all system calls use safe wrappers from `nix`
//! - **Scoped context passing** — no global mutable state; all state flows
//!   through `ServerContext`, `MessageContext`, `DeliveryContext`, `ConfigContext`
//! - **Compile-time taint tracking** — address data from external sources uses
//!   `Tainted<T>` / `Clean<T>` newtypes from `exim-store`
//! - **Arena allocation** — per-message temporaries use `MessageArena` from
//!   `exim-store`, dropped at message completion

#![deny(unsafe_code)]

pub mod bounce;
pub mod journal;
pub mod orchestrator;

// Re-export primary public types for ergonomic access
pub use bounce::{
    maybe_send_dsn, moan_check_errorcopy, moan_send_message, moan_skipped_syntax_errors,
    moan_smtp_batch, moan_tell_someone, moan_to_sender, send_bounce_message, send_warning_message,
    write_bounce_from, write_bounce_references, BounceError, ErrorBlock, ErrorMessageIdent,
};
pub use journal::{JournalError, JournalState};
pub use orchestrator::{
    common_error, deliver_make_addr, deliver_message, deliver_msglog, deliver_set_expansions,
    deliver_split_address, post_process_one, AddressFlags, AddressItem, AddressLists,
    AddressProperties, DeliveryError, DeliveryResult, ProcessRecipients,
};
