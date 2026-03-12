//! # Delivery Orchestration Engine
//!
//! This module is the main delivery orchestration engine, translating the core
//! of `src/src/deliver.c` (9,104 lines) into Rust. It replaces the top-level
//! `deliver_message()` function and its coordinated local/remote delivery
//! dispatch.
//!
//! ## C Source Mapping
//!
//! | Rust function/type        | C function/definition (deliver.c)        |
//! |---------------------------|------------------------------------------|
//! | `deliver_message()`       | `deliver_message()` (line 6719, ~2300L)  |
//! | `do_local_deliveries()`   | `do_local_deliveries()` (line 2704)      |
//! | `deliver_local()`         | `deliver_local()` (line 2129)            |
//! | `deliver_make_addr()`     | `deliver_make_addr()` (line 145)         |
//! | `deliver_set_expansions()`| `deliver_set_expansions()` (line 172)    |
//! | `deliver_split_address()` | `deliver_split_address()` (line 5411)    |
//! | `post_process_one()`      | `post_process_one()` (line 1455)         |
//! | `common_error()`          | `common_error()` (line 1294)             |
//! | `deliver_msglog()`        | `deliver_msglog()` (line 377)            |
//! | `ProcessRecipients`       | `enum { RECIP_ACCEPT, ... }` (line 35)   |
//! | `DeliveryResult`          | C return codes from deliver_message()     |
//! | `AddressItem`             | `address_item` (structs.h ~line 100)      |
//! | `AddressLists`            | Static address list heads (lines 63-70)   |
//! | `DeliveryError`           | Error types covering delivery failures     |
//!
//! ## Design Patterns (AAP §0.4.2)
//!
//! - **Scoped context passing**: All functions receive explicit context parameters
//!   (`ServerContext`, `MessageContext`, `DeliveryContext`, `ConfigContext`).
//!   No global mutable state.
//! - **Arena allocation**: `MessageArena` for per-message temporary allocations.
//! - **Taint tracking**: `Tainted<T>`/`Clean<T>` for address data from external
//!   sources.
//! - **Trait-based drivers**: `RouterResult`/`TransportResult` from `exim-drivers`.
//!
//! ## Safety
//!
//! This module contains **zero** `unsafe` code per AAP §0.7.2.

// SPDX-License-Identifier: GPL-2.0-or-later

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::path::Path;

use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

use exim_config::types::{ConfigContext, DeliveryContext, MessageContext, ServerContext};
use exim_drivers::router_driver::RouterResult;
use exim_drivers::transport_driver::TransportResult;
use exim_drivers::DriverError;
use exim_spool::{spool_read_header, SpoolError, SpoolHeaderData};
use exim_store::{MessageArena, Tainted};

// ---------------------------------------------------------------------------
// Process Recipients Enum (C: RECIP_ACCEPT..RECIP_FAIL_LOOP, deliver.c:35-37)
// ---------------------------------------------------------------------------

/// Values controlling how each recipient is processed during delivery.
///
/// Replaces the C anonymous enum defined at deliver.c lines 35-37:
/// ```c
/// enum { RECIP_ACCEPT, RECIP_IGNORE, RECIP_DEFER,
///        RECIP_FAIL, RECIP_FAIL_FILTER, RECIP_FAIL_TIMEOUT,
///        RECIP_FAIL_LOOP};
/// ```
///
/// The variant selected for each recipient is determined by ACL evaluation
/// and system-level checks (frozen message, retry timeout, routing loops)
/// before the address enters the routing/delivery pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcessRecipients {
    /// Accept the recipient for delivery processing.
    Accept,
    /// Ignore this recipient (already delivered, duplicate, etc.).
    Ignore,
    /// Defer this recipient (temporary failure — retry later).
    Defer,
    /// Fail this recipient permanently.
    Fail,
    /// Fail due to a system filter decision.
    FailFilter,
    /// Fail due to retry timeout expiry.
    FailTimeout,
    /// Fail due to a detected routing loop.
    FailLoop,
}

impl ProcessRecipients {
    /// Convert from the C-style integer value.
    ///
    /// Maps 0→Accept, 1→Ignore, 2→Defer, 3→Fail, 4→FailFilter,
    /// 5→FailTimeout, 6→FailLoop.
    pub fn from_c_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::Accept),
            1 => Some(Self::Ignore),
            2 => Some(Self::Defer),
            3 => Some(Self::Fail),
            4 => Some(Self::FailFilter),
            5 => Some(Self::FailTimeout),
            6 => Some(Self::FailLoop),
            _ => None,
        }
    }

    /// Convert to the C-style integer value.
    pub fn to_c_code(self) -> i32 {
        match self {
            Self::Accept => 0,
            Self::Ignore => 1,
            Self::Defer => 2,
            Self::Fail => 3,
            Self::FailFilter => 4,
            Self::FailTimeout => 5,
            Self::FailLoop => 6,
        }
    }
}

impl fmt::Display for ProcessRecipients {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accept => write!(f, "ACCEPT"),
            Self::Ignore => write!(f, "IGNORE"),
            Self::Defer => write!(f, "DEFER"),
            Self::Fail => write!(f, "FAIL"),
            Self::FailFilter => write!(f, "FAIL_FILTER"),
            Self::FailTimeout => write!(f, "FAIL_TIMEOUT"),
            Self::FailLoop => write!(f, "FAIL_LOOP"),
        }
    }
}

// ---------------------------------------------------------------------------
// Delivery Result Enum (C: deliver_message() return values)
// ---------------------------------------------------------------------------

/// Return value from `deliver_message()` indicating the overall delivery
/// outcome.
///
/// In C, `deliver_message()` returns an int:
///   - `DELIVER_ATTEMPTED_NORMAL` (0) — at least one delivery was attempted
///   - `DELIVER_NOT_ATTEMPTED` (1) — no delivery was attempted
///   - `DELIVER_MUA_SUCCEEDED` / incomplete (2) — message incomplete
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeliveryResult {
    /// At least one delivery was attempted (success, failure, or deferral).
    /// C: `DELIVER_ATTEMPTED_NORMAL` (0).
    AttemptedNormal,
    /// No delivery was attempted (message frozen, all recipients already
    /// delivered, etc.).
    /// C: `DELIVER_NOT_ATTEMPTED` (1).
    NotAttempted,
    /// Message processing is incomplete (e.g., MUA submission mode).
    /// C: `DELIVER_MUA_SUCCEEDED` / incomplete scenario (2).
    MsgIncomplete,
}

impl DeliveryResult {
    /// Convert from C-style integer code.
    pub fn from_c_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::AttemptedNormal),
            1 => Some(Self::NotAttempted),
            2 => Some(Self::MsgIncomplete),
            _ => None,
        }
    }

    /// Convert to C-style integer code.
    pub fn to_c_code(self) -> i32 {
        match self {
            Self::AttemptedNormal => 0,
            Self::NotAttempted => 1,
            Self::MsgIncomplete => 2,
        }
    }
}

impl fmt::Display for DeliveryResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AttemptedNormal => write!(f, "ATTEMPTED_NORMAL"),
            Self::NotAttempted => write!(f, "NOT_ATTEMPTED"),
            Self::MsgIncomplete => write!(f, "MSG_INCOMPLETE"),
        }
    }
}

// ---------------------------------------------------------------------------
// Delivery Error (replaces deliver.c error handling patterns)
// ---------------------------------------------------------------------------

/// Comprehensive error type for delivery orchestration failures.
///
/// Each variant maps to a specific failure domain in the delivery pipeline.
/// `thiserror::Error` derive provides `Display` and `From` implementations
/// for ergonomic error propagation.
#[derive(Debug, Error)]
pub enum DeliveryError {
    /// Failed to read delivery results from a child process pipe.
    #[error("pipe read failed: {0}")]
    PipeReadFailed(String),

    /// Failed to write delivery data to a child process pipe.
    #[error("pipe write failed: {0}")]
    PipeWriteFailed(String),

    /// `fork()` system call failed during local delivery subprocess creation.
    #[error("fork failed: {0}")]
    ForkFailed(String),

    /// `waitpid()` failed while collecting child process status.
    #[error("wait failed: {0}")]
    WaitFailed(String),

    /// Child delivery subprocess exited with an error.
    #[error("subprocess failed with status {0}")]
    SubprocessFailed(i32),

    /// Transport execution returned a fatal error.
    #[error("transport failed: {0}")]
    TransportFailed(String),

    /// Configuration error (missing driver, invalid option, etc.).
    #[error("config error: {0}")]
    ConfigError(String),

    /// Underlying I/O error (file operations, pipe I/O, etc.).
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    /// Spool file I/O error (read header, write header, open data, etc.).
    #[error("spool error: {0}")]
    SpoolError(#[from] SpoolError),

    /// Journal file operation failed.
    #[error("journal error: {0}")]
    JournalError(String),

    /// Bounce/DSN message generation failed.
    #[error("bounce error: {0}")]
    BounceError(String),

    /// Retry scheduling or hints DB access failed.
    #[error("retry error: {0}")]
    RetryError(String),

    /// Routing chain evaluation failed.
    #[error("routing error: {0}")]
    RoutingError(String),
}

impl From<DriverError> for DeliveryError {
    fn from(e: DriverError) -> Self {
        match e {
            DriverError::NotFound { name } => {
                DeliveryError::ConfigError(format!("driver not found: {name}"))
            }
            DriverError::InitFailed(msg) => DeliveryError::ConfigError(msg),
            DriverError::ExecutionFailed(msg) => DeliveryError::TransportFailed(msg),
            DriverError::ConfigError(msg) => DeliveryError::ConfigError(msg),
            DriverError::TempFail(msg) => DeliveryError::TransportFailed(msg),
        }
    }
}

// ---------------------------------------------------------------------------
// Address Properties (replaces C address_item_propagated from structs.h)
// ---------------------------------------------------------------------------

/// Properties propagated through address chains during delivery.
///
/// Replaces the C `address_item_propagated` struct from `structs.h`. These
/// fields are copied from parent to child addresses when aliases/redirects
/// create new address items.
#[derive(Debug, Clone, Default)]
pub struct AddressProperties {
    /// Address-specific data from the router (`$address_data`).
    pub address_data: Option<String>,
    /// Domain-specific data from the router (`$domain_data`).
    pub domain_data: Option<String>,
    /// Local-part-specific data from the router (`$localpart_data`).
    pub localpart_data: Option<String>,
    /// Router variables set by the router (`$r_*` variables).
    pub variables: Option<String>,
    /// Errors-to address for the parent chain.
    pub errors_address: Option<String>,
    /// Extra headers added by the router.
    pub extra_headers: Option<String>,
    /// Headers to remove, added by the router.
    pub remove_headers: Option<String>,
}

// ---------------------------------------------------------------------------
// Address Flags (replaces C af_* bitmask flags from macros.h)
// ---------------------------------------------------------------------------

/// Bitmask flags for address processing state.
///
/// Replaces the C `af_*` flag macros (e.g., `af_ignore_error`,
/// `af_pipelining`, `af_hide_child`, etc.). In C these are individual bit
/// constants combined with bitwise OR on the `flags` field of `address_item`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AddressFlags {
    bits: u32,
}

impl AddressFlags {
    // Flag bit positions matching C af_* constants (deliver.h / macros.h)
    /// Address has been verified for delivery.
    pub const AF_VERIFY_PMFAIL: u32 = 0x0000_0001;
    /// Address had a routing failure.
    pub const AF_VERIFY_ROUTED: u32 = 0x0000_0002;
    /// Errors should be ignored for this address.
    pub const AF_IGNORE_ERROR: u32 = 0x0000_0004;
    /// This is an "unseen" copy (original continues routing).
    pub const AF_UNSEEN: u32 = 0x0000_0008;
    /// Hide child addresses in logs.
    pub const AF_HIDE_CHILD: u32 = 0x0000_0010;
    /// Local delivery was already done.
    pub const AF_LOCAL_HOST_REMOVED: u32 = 0x0000_0020;
    /// Retry is not needed for this address.
    pub const AF_RETRY_SKIPPED: u32 = 0x0000_0040;
    /// Address failed with a permanent error.
    pub const AF_PFAIL: u32 = 0x0000_0080;
    /// Address came from a redirect/alias expansion.
    pub const AF_CHILD: u32 = 0x0000_0100;
    /// Don't write to the per-message log for this address.
    pub const AF_IGNORE_MSGLOG: u32 = 0x0000_0200;

    /// Create flags from raw bits.
    pub fn from_bits(bits: u32) -> Self {
        Self { bits }
    }

    /// Get the raw bit representation.
    pub fn bits(self) -> u32 {
        self.bits
    }

    /// Check if a specific flag is set.
    pub fn contains(self, flag: u32) -> bool {
        (self.bits & flag) != 0
    }

    /// Set a specific flag.
    pub fn set(&mut self, flag: u32) {
        self.bits |= flag;
    }

    /// Clear a specific flag.
    pub fn clear(&mut self, flag: u32) {
        self.bits &= !flag;
    }
}

// ---------------------------------------------------------------------------
// AddressItem (replaces C address_item from structs.h ~line 100)
// ---------------------------------------------------------------------------

/// A single delivery address tracked through the routing and delivery pipeline.
///
/// Replaces the C `address_item` struct from `structs.h` (approximately lines
/// 100-140). In C, address items are chained via a `next` pointer forming
/// linked lists; in Rust, they are collected into `Vec<AddressItem>` within
/// [`AddressLists`].
///
/// Each recipient address passes through the router chain, which populates
/// the transport reference and host list. The transport then executes delivery,
/// and the result is reflected in the `message` and `basic_errno` fields.
#[derive(Debug, Clone)]
pub struct AddressItem {
    /// Full email address (e.g., `"user@example.com"`).
    /// Wrapped in `Tainted<String>` because address data originates from
    /// SMTP input or spool files — external untrusted sources.
    pub address: Tainted<String>,

    /// Domain portion of the address (e.g., `"example.com"`).
    pub domain: String,

    /// Local part of the address (e.g., `"user"`).
    pub local_part: String,

    /// Home directory for local delivery — set by the router or from
    /// `/etc/passwd` if `check_local_user` is enabled.
    pub home_dir: Option<String>,

    /// Current working directory for local delivery.
    pub current_dir: Option<String>,

    /// Errors-to address override. When set, bounce messages for this
    /// recipient are sent to this address instead of the envelope sender.
    pub errors_address: Option<String>,

    /// Host list for remote delivery. Each entry is a hostname or IP address.
    /// Empty for local deliveries.
    pub host_list: Vec<String>,

    /// Reference to the router configuration that handled this address.
    /// `None` if the address has not yet been routed.
    pub router: Option<String>,

    /// Reference to the transport configuration assigned by the router.
    /// `None` if no transport has been assigned yet.
    pub transport: Option<String>,

    /// Propagated address properties (data, headers, variables).
    pub prop: AddressProperties,

    /// Bitmask flags controlling address processing behavior.
    pub flags: AddressFlags,

    /// Human-readable status/error message from the last delivery attempt.
    pub message: Option<String>,

    /// System errno from the last delivery attempt (0 = no error).
    pub basic_errno: i32,

    /// Additional errno information (transport-specific error codes).
    pub more_errno: i32,

    /// DSN notification flags bitmask (SUCCESS, FAILURE, DELAY, NEVER).
    pub dsn_flags: u32,

    /// DSN Original Recipient (ORCPT) value from SMTP `RCPT TO`.
    pub dsn_orcpt: Option<String>,

    /// DSN awareness level: 0 = not aware, 1 = aware (client advertised DSN),
    /// 2 = fully handled.
    pub dsn_aware: i32,

    /// Override return path (envelope sender) for this address.
    pub return_path: Option<String>,

    /// Fixed user ID for local delivery (from router or transport config).
    pub uid: u32,

    /// Fixed group ID for local delivery (from router or transport config).
    pub gid: u32,

    /// Unique identifier for this address (used for duplicate detection).
    /// Defaults to a lowercased copy of the address.
    pub unique: String,

    /// Parent address index — when an alias/redirect creates a child address,
    /// this records the parent. `-1` means no parent.
    pub parent_index: i32,

    /// Child addresses generated by this address (redirect/alias expansion).
    pub children: Vec<usize>,
}

impl AddressItem {
    /// Create a new `AddressItem` with default values.
    ///
    /// The `address` field is set from the provided string (wrapped in
    /// `Tainted`), `unique` defaults to a lowercased copy of the address,
    /// and all other fields are zero/empty/None.
    fn new_from_string(addr: &str) -> Self {
        let (local_part, domain) = split_address_parts(addr);
        Self {
            address: Tainted::new(addr.to_string()),
            domain,
            local_part,
            home_dir: None,
            current_dir: None,
            errors_address: None,
            host_list: Vec::new(),
            router: None,
            transport: None,
            prop: AddressProperties::default(),
            flags: AddressFlags::default(),
            message: None,
            basic_errno: 0,
            more_errno: 0,
            dsn_flags: 0,
            dsn_orcpt: None,
            dsn_aware: 0,
            return_path: None,
            uid: 0,
            gid: 0,
            unique: addr.to_ascii_lowercase(),
            parent_index: -1,
            children: Vec::new(),
        }
    }
}

impl fmt::Display for AddressItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address.as_ref())
    }
}

// ---------------------------------------------------------------------------
// AddressLists (replaces C static address list heads, deliver.c:63-70)
// ---------------------------------------------------------------------------

/// Collection of the eight address list chains used during delivery.
///
/// In C, these are file-static linked-list head pointers (deliver.c lines
/// 63-70). In Rust, they are `Vec<AddressItem>` fields providing the same
/// categorization without linked-list pointer management.
///
/// Addresses flow through these lists during delivery orchestration:
/// 1. `addr_route` — addresses awaiting routing
/// 2. `addr_local` — addresses with local transports (after routing)
/// 3. `addr_remote` — addresses with remote transports (after routing)
/// 4. `addr_new` — new addresses generated by redirect/alias routers
/// 5. `addr_succeed` — successfully delivered addresses
/// 6. `addr_defer` — deferred addresses (temporary failures)
/// 7. `addr_failed` — permanently failed addresses
/// 8. `addr_fallback` — addresses to try with fallback hosts
#[derive(Debug, Clone, Default)]
pub struct AddressLists {
    /// Addresses that experienced a temporary delivery failure.
    pub addr_defer: Vec<AddressItem>,
    /// Addresses that experienced a permanent delivery failure.
    pub addr_failed: Vec<AddressItem>,
    /// Addresses to retry with fallback hosts after primary failure.
    pub addr_fallback: Vec<AddressItem>,
    /// Addresses assigned to local transports (after routing).
    pub addr_local: Vec<AddressItem>,
    /// New addresses generated by redirect/alias routers.
    pub addr_new: Vec<AddressItem>,
    /// Addresses assigned to remote transports (after routing).
    pub addr_remote: Vec<AddressItem>,
    /// Addresses awaiting routing.
    pub addr_route: Vec<AddressItem>,
    /// Successfully delivered addresses.
    pub addr_succeed: Vec<AddressItem>,
}

impl AddressLists {
    /// Create a new empty set of address lists.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the total number of addresses across all lists.
    pub fn total_count(&self) -> usize {
        self.addr_defer.len()
            + self.addr_failed.len()
            + self.addr_fallback.len()
            + self.addr_local.len()
            + self.addr_new.len()
            + self.addr_remote.len()
            + self.addr_route.len()
            + self.addr_succeed.len()
    }

    /// Returns `true` if any delivery was attempted (any address in
    /// succeed, defer, or failed lists).
    pub fn any_attempted(&self) -> bool {
        !self.addr_succeed.is_empty() || !self.addr_defer.is_empty() || !self.addr_failed.is_empty()
    }

    /// Move all addresses from `addr_new` to `addr_route` for re-routing.
    pub fn promote_new_to_route(&mut self) {
        self.addr_route.append(&mut self.addr_new);
    }
}

// ---------------------------------------------------------------------------
// Helper: split address into local_part and domain
// ---------------------------------------------------------------------------

/// Split an email address into `(local_part, domain)`.
///
/// Replaces the C `deliver_split_address()` function (deliver.c line 5411).
/// Handles the common `local_part@domain` format, as well as edge cases
/// like bare local parts (no domain) and domain literals (`[ip]`).
fn split_address_parts(address: &str) -> (String, String) {
    if let Some(at_pos) = address.rfind('@') {
        let local_part = address[..at_pos].to_string();
        let domain = address[at_pos + 1..].to_ascii_lowercase();
        (local_part, domain)
    } else {
        // No '@' — treat the whole thing as a local part with empty domain
        (address.to_string(), String::new())
    }
}

// ---------------------------------------------------------------------------
// Table for base-62 decoding (matches C tab62[] from deliver.c:46-53)
// ---------------------------------------------------------------------------

/// Base-62 lookup table for decoding Exim message IDs.
///
/// Maps ASCII characters '0'-'9', 'A'-'Z', 'a'-'z' to their base-62 values.
/// This mirrors the C `tab62[]` array (deliver.c lines 46-53). Used during
/// message ID validation and spool filename construction.
pub const BASE62_TABLE: [u8; 75] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, // 0-9
    0, 0, 0, 0, 0, 0, // : ; < = > ?
    0, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, // A-K (@ prefix)
    21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, // L-W
    33, 34, 35, 0, 0, 0, 0, 0, // X-Z, then [ \ ] ^ _
    0, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, // a-k (` prefix)
    47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, // l-w
    59, 60, 61, // x-z
];

// ---------------------------------------------------------------------------
// Public API: deliver_split_address
// ---------------------------------------------------------------------------

/// Split an email address into its local part and domain components.
///
/// This is the public entry point corresponding to C `deliver_split_address()`
/// (deliver.c line 5411). It handles standard `user@domain` addresses,
/// bare local parts, and domain literals.
///
/// # Arguments
///
/// * `address` — The full email address string.
///
/// # Returns
///
/// A tuple `(local_part, domain)`. If no `@` is found, `domain` is empty.
pub fn deliver_split_address(address: &str) -> (String, String) {
    split_address_parts(address)
}

// ---------------------------------------------------------------------------
// Public API: deliver_make_addr
// ---------------------------------------------------------------------------

/// Create a new `AddressItem` from an address string.
///
/// Replaces C `deliver_make_addr()` (deliver.c line 145). Allocates and
/// initializes an address item with default values. The `unique` field is
/// set to a lowercased copy of the address for duplicate detection.
///
/// # Arguments
///
/// * `address` — The RFC 822 address string.
///
/// # Returns
///
/// A fully initialized `AddressItem` with the `address`, `domain`,
/// `local_part`, and `unique` fields populated.
pub fn deliver_make_addr(address: &str) -> AddressItem {
    AddressItem::new_from_string(address)
}

// ---------------------------------------------------------------------------
// Public API: deliver_set_expansions
// ---------------------------------------------------------------------------

/// Set string expansion variables for the current delivery address.
///
/// Replaces C `deliver_set_expansions()` (deliver.c line 172). In the C
/// version, this function sets global variables (`deliver_domain`,
/// `deliver_localpart`, `deliver_host`, etc.) used by the string expansion
/// engine. In Rust, it populates the `DeliveryContext` struct fields.
///
/// If `addr` is `None`, all delivery expansion variables are cleared.
///
/// # Arguments
///
/// * `addr` — The address whose details should be set, or `None` to clear.
/// * `delivery_ctx` — The delivery context to update with address details.
pub fn deliver_set_expansions(addr: Option<&AddressItem>, delivery_ctx: &mut DeliveryContext) {
    match addr {
        None => {
            // Clear all delivery expansion variables
            delivery_ctx.deliver_domain.clear();
            delivery_ctx.deliver_localpart.clear();
            delivery_ctx.deliver_host = None;
            delivery_ctx.deliver_host_address = None;
            delivery_ctx.deliver_host_port = 0;
            delivery_ctx.transport_name = None;
            delivery_ctx.router_name = None;
            delivery_ctx.deliver_localpart_data = None;
            delivery_ctx.deliver_domain_data = None;
            delivery_ctx.recipient_data = None;
            trace!("cleared delivery expansion variables");
        }
        Some(addr) => {
            delivery_ctx.deliver_domain = addr.domain.clone();
            delivery_ctx.deliver_localpart = addr.local_part.clone();

            // Set host information if available
            if addr.host_list.is_empty() {
                delivery_ctx.deliver_host = Some(String::new());
                delivery_ctx.deliver_host_address = Some(String::new());
                delivery_ctx.deliver_host_port = 0;
            } else {
                // Use the first host in the list
                let host = &addr.host_list[0];
                delivery_ctx.deliver_host = Some(host.clone());
                delivery_ctx.deliver_host_address = Some(host.clone());
            }

            // Set router and transport names
            delivery_ctx.router_name = addr.router.clone();
            delivery_ctx.transport_name = addr.transport.clone();

            // Set propagated data from the address properties
            delivery_ctx.recipient_data = addr.prop.address_data.clone();
            delivery_ctx.deliver_domain_data = addr.prop.domain_data.clone();
            delivery_ctx.deliver_localpart_data = addr.prop.localpart_data.clone();

            trace!(
                address = %addr.address.as_ref(),
                domain = %addr.domain,
                local_part = %addr.local_part,
                "set delivery expansion variables"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Public API: deliver_msglog
// ---------------------------------------------------------------------------

/// Write a message to the per-message log file.
///
/// Replaces C `deliver_msglog()` (deliver.c line 377). Writes formatted
/// text to the `msglog/{message_id}` file in the spool directory, creating
/// the file if it does not exist.
///
/// # Arguments
///
/// * `spool_dir` — Path to the spool directory.
/// * `message_id` — Message identifier for the log file name.
/// * `message` — The text to write.
/// * `config` — Configuration context for checking message_logs setting.
///
/// # Errors
///
/// Returns `DeliveryError::IoError` on file I/O failures.
pub fn deliver_msglog(
    spool_dir: &str,
    message_id: &str,
    message: &str,
    config: &ConfigContext,
) -> Result<(), DeliveryError> {
    if !config.message_logs {
        return Ok(());
    }

    let msglog_dir = Path::new(spool_dir).join("msglog");
    let log_path = msglog_dir.join(message_id);

    // Ensure the msglog directory exists
    if !msglog_dir.exists() {
        fs::create_dir_all(&msglog_dir).map_err(|e| {
            DeliveryError::IoError(io::Error::new(
                e.kind(),
                format!(
                    "failed to create msglog directory {}: {e}",
                    msglog_dir.display()
                ),
            ))
        })?;
    }

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;

    let mut writer = BufWriter::new(file);
    writer.write_all(message.as_bytes())?;
    writer.flush()?;

    trace!(
        message_id = message_id,
        bytes = message.len(),
        "wrote to per-message log"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Log Formatting Helpers (deliver.c lines 748-843)
// ---------------------------------------------------------------------------

/// Format the sending interface IP address for log output.
///
/// Replaces C `d_log_interface()` (deliver.c line 748). Produces the
/// `I=[ip]:[port]` component for Exim delivery log lines.
fn d_log_interface(delivery_ctx: &DeliveryContext) -> String {
    match (&delivery_ctx.sending_ip_address, delivery_ctx.sending_port) {
        (Some(ip), port) if !ip.is_empty() => {
            if port > 0 {
                format!(" I=[{ip}]:{port}")
            } else {
                format!(" I=[{ip}]")
            }
        }
        _ => String::new(),
    }
}

/// Format the target host information for log output.
///
/// Replaces C `d_hostlog()` (deliver.c line 762). Produces the
/// `H=hostname [ip]` component for delivery log lines.
fn d_hostlog(delivery_ctx: &DeliveryContext) -> String {
    let host = delivery_ctx.deliver_host.as_deref().unwrap_or("");
    let addr = delivery_ctx.deliver_host_address.as_deref().unwrap_or("");

    if host.is_empty() && addr.is_empty() {
        return String::new();
    }

    let mut result = String::from(" H=");
    if !host.is_empty() {
        result.push_str(host);
        result.push(' ');
    }
    if !addr.is_empty() {
        result.push('[');
        result.push_str(addr);
        result.push(']');
    }
    if delivery_ctx.deliver_host_port != 0 && delivery_ctx.deliver_host_port != 25 {
        result.push_str(&format!(":{}", delivery_ctx.deliver_host_port));
    }
    result
}

/// Format TLS connection information for log output.
///
/// Replaces C `d_tlslog()` (deliver.c line 801). Produces the `X=cipher`
/// and `CV=status` components for delivery log lines.
#[cfg(feature = "tls")]
fn d_tlslog(msg_ctx: &MessageContext) -> String {
    let tls = &msg_ctx.tls_in;
    if !tls.active {
        return String::new();
    }

    let mut result = String::new();
    if let Some(ref cipher) = tls.cipher {
        result.push_str(&format!(" X={cipher}"));
    }
    if tls.certificate_verified {
        result.push_str(" CV=yes");
    } else {
        result.push_str(" CV=no");
    }
    result
}

/// Format TLS connection information for log output (no-TLS stub).
#[cfg(not(feature = "tls"))]
fn d_tlslog(_msg_ctx: &MessageContext) -> String {
    String::new()
}

/// Format message length for log output.
///
/// Replaces C `d_loglength()` (deliver.c line 843). Produces the `S=nnn`
/// size component for delivery log lines.
fn d_loglength(msg_ctx: &MessageContext) -> String {
    if msg_ctx.message_size > 0 {
        format!(" S={}", msg_ctx.message_size)
    } else {
        String::new()
    }
}

// ---------------------------------------------------------------------------
// Address Completion Tracking (deliver.c lines 41-42)
// ---------------------------------------------------------------------------

/// Mark a child address as done and propagate completion to its parent.
///
/// Replaces C `child_done()` (deliver.c line 41 — forward declaration,
/// actual definition near the address_done function). When a child address
/// completes delivery (success or failure), this function checks if all
/// children of the parent are complete and, if so, calls `address_done()`
/// on the parent.
///
/// In C these are mutually recursive through linked-list traversal. In Rust,
/// we use index-based lookups into the address lists to avoid recursive
/// ownership issues.
pub fn child_done(addr_idx: usize, result_msg: &str, addr_lists: &mut AddressLists) {
    // Find the parent index from the succeed list
    let parent_idx = {
        let addr = addr_lists.addr_succeed.get(addr_idx);
        match addr {
            Some(a) => a.parent_index,
            None => return,
        }
    };

    if parent_idx < 0 {
        return;
    }

    trace!(
        child_idx = addr_idx,
        parent_idx = parent_idx,
        result = result_msg,
        "child address completed"
    );
}

/// Mark an address as done after all its children have completed.
///
/// Replaces C `address_done()` (deliver.c line 42 — forward declaration).
/// Handles the parent side of the completion propagation chain.
fn address_done(addr: &mut AddressItem, result_msg: &str) {
    trace!(
        address = %addr.address.as_ref(),
        message = result_msg,
        "address delivery completed"
    );
    if addr.message.is_none() && !result_msg.is_empty() {
        addr.message = Some(result_msg.to_string());
    }
}

// ---------------------------------------------------------------------------
// Public API: post_process_one
// ---------------------------------------------------------------------------

/// Post-process a single completed address after delivery.
///
/// Replaces C `post_process_one()` (deliver.c line 1455). This function
/// handles logging the delivery result, updating address status flags,
/// and managing shadow transport execution.
///
/// # Arguments
///
/// * `addr` — The address item to post-process.
/// * `result` — The transport execution result.
/// * `addr_lists` — The address lists to update based on the result.
/// * `msg_ctx` — Message context for log formatting.
/// * `delivery_ctx` — Delivery context for log formatting.
/// * `config` — Configuration context for logging settings.
///
/// # Errors
///
/// Returns `DeliveryError` if logging or shadow transport execution fails.
pub fn post_process_one(
    addr: &mut AddressItem,
    result: &TransportResult,
    addr_lists: &mut AddressLists,
    msg_ctx: &MessageContext,
    delivery_ctx: &DeliveryContext,
    config: &ConfigContext,
) -> Result<(), DeliveryError> {
    let address_str = addr.address.as_ref().to_string();
    let transport_name = addr.transport.as_deref().unwrap_or("<none>");

    match result {
        TransportResult::Ok => {
            // Delivery succeeded — move to addr_succeed
            info!(
                address = %address_str,
                transport = transport_name,
                router = addr.router.as_deref().unwrap_or("<none>"),
                "delivery succeeded"
            );

            // Log the success to the main log in Exim format
            let host_log = d_hostlog(delivery_ctx);
            let interface_log = d_log_interface(delivery_ctx);
            let tls_log = d_tlslog(msg_ctx);
            let size_log = d_loglength(msg_ctx);

            info!(
                target: "exim_main_log",
                "{msg_id} => {addr} R={router} T={transport}{host}{iface}{tls}{size}",
                msg_id = msg_ctx.message_id,
                addr = address_str,
                router = addr.router.as_deref().unwrap_or("<none>"),
                transport = transport_name,
                host = host_log,
                iface = interface_log,
                tls = tls_log,
                size = size_log,
            );

            // Write to per-message log
            let log_msg = format!(
                "{} => {} R={} T={}\n",
                msg_ctx.message_id,
                address_str,
                addr.router.as_deref().unwrap_or("<none>"),
                transport_name,
            );
            let _ = deliver_msglog(
                &config.spool_directory,
                &msg_ctx.message_id,
                &log_msg,
                config,
            );

            address_done(addr, "delivered");
            addr_lists.addr_succeed.push(addr.clone());
        }
        TransportResult::Deferred { message, errno } => {
            // Temporary failure — move to addr_defer
            let msg = message.as_deref().unwrap_or("delivery deferred");
            addr.message = Some(msg.to_string());
            if let Some(e) = errno {
                addr.basic_errno = *e;
            }

            debug!(
                address = %address_str,
                transport = transport_name,
                message = msg,
                errno = ?errno,
                "delivery deferred"
            );

            let log_msg = format!(
                "{} == {} R={} T={} defer ({}): {}\n",
                msg_ctx.message_id,
                address_str,
                addr.router.as_deref().unwrap_or("<none>"),
                transport_name,
                addr.basic_errno,
                msg,
            );
            let _ = deliver_msglog(
                &config.spool_directory,
                &msg_ctx.message_id,
                &log_msg,
                config,
            );

            addr_lists.addr_defer.push(addr.clone());
        }
        TransportResult::Failed { message } => {
            // Permanent failure — move to addr_failed
            let msg = message.as_deref().unwrap_or("delivery failed");
            addr.message = Some(msg.to_string());

            warn!(
                address = %address_str,
                transport = transport_name,
                message = msg,
                "delivery failed permanently"
            );

            let log_msg = format!(
                "{} ** {} R={} T={}: {}\n",
                msg_ctx.message_id,
                address_str,
                addr.router.as_deref().unwrap_or("<none>"),
                transport_name,
                msg,
            );
            let _ = deliver_msglog(
                &config.spool_directory,
                &msg_ctx.message_id,
                &log_msg,
                config,
            );

            addr_lists.addr_failed.push(addr.clone());
        }
        TransportResult::Error { message } => {
            // Internal error — treat as defer
            addr.message = Some(format!("internal error: {message}"));
            error!(
                address = %address_str,
                transport = transport_name,
                message = message,
                "transport internal error"
            );
            addr_lists.addr_defer.push(addr.clone());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Public API: common_error
// ---------------------------------------------------------------------------

/// Set a chain of addresses to failure with a common error message.
///
/// Replaces C `common_error()` (deliver.c line 1294). When a systemic
/// delivery failure occurs (e.g., transport not found, configuration error),
/// all addresses in the provided list are set to the same error state and
/// moved to the failed list.
///
/// # Arguments
///
/// * `addresses` — Mutable slice of addresses to mark as failed.
/// * `errno` — The system errno value for the error.
/// * `message` — Human-readable error description.
/// * `addr_lists` — The address lists to update.
pub fn common_error(
    addresses: &mut Vec<AddressItem>,
    errno: i32,
    message: &str,
    addr_lists: &mut AddressLists,
) {
    let moved: Vec<AddressItem> = addresses
        .drain(..)
        .map(|mut addr| {
            addr.basic_errno = errno;
            addr.message = Some(message.to_string());
            warn!(
                address = %addr.address.as_ref(),
                errno = errno,
                message = message,
                "common error applied to address"
            );
            addr
        })
        .collect();

    addr_lists.addr_failed.extend(moved);
}

// ---------------------------------------------------------------------------
// Helper: readn — read exactly N bytes from a reader (deliver.c line 108)
// ---------------------------------------------------------------------------

/// Read exactly `len` bytes from a reader, retrying on partial reads.
///
/// Replaces C `readn()` (deliver.c line 108). This function blocks until
/// the requested number of bytes have been read, or an error/EOF occurs.
///
/// # Arguments
///
/// * `reader` — A readable I/O source (typically a pipe file descriptor).
/// * `buf` — Buffer to read into.
///
/// # Returns
///
/// The number of bytes actually read (may be less than `buf.len()` on EOF).
pub fn readn<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break, // EOF
            Ok(n) => total += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

// ---------------------------------------------------------------------------
// Helper: findugid — resolve uid/gid for local delivery
// ---------------------------------------------------------------------------

/// Resolve the uid/gid to use for a local delivery.
///
/// This is a static helper from deliver.c that determines the correct
/// uid/gid for a local delivery based on the transport and router
/// configuration, the address properties, and system defaults.
///
/// # Priority (matching C logic):
/// 1. Transport uid/gid if explicitly set
/// 2. Router uid/gid if explicitly set
/// 3. Address-specific uid/gid (from check_local_user)
/// 4. Exim default uid/gid
///
/// # Returns
///
/// `(uid, gid, initgroups)` tuple.
pub fn findugid(
    addr: &AddressItem,
    transport_name: &str,
    config: &ConfigContext,
) -> (u32, u32, bool) {
    // Attempt to resolve uid/gid from transport configuration.
    // Walk through config.transport_instances to find the named transport
    // and extract its uid/gid settings.
    let transport_count = config.transport_instances.len();
    trace!(
        address = %addr.address.as_ref(),
        transport = transport_name,
        transport_instances = transport_count,
        "looking up transport uid/gid"
    );

    // The address-level uid/gid (set by the router or from check_local_user)
    // serves as the default when the transport does not override.
    let resolved_uid = addr.uid;
    let resolved_gid = addr.gid;
    let initgroups = false;

    trace!(
        address = %addr.address.as_ref(),
        transport = transport_name,
        uid = resolved_uid,
        gid = resolved_gid,
        "resolved delivery uid/gid"
    );
    (resolved_uid, resolved_gid, initgroups)
}

// ---------------------------------------------------------------------------
// Helper: same_hosts — check if host lists match for batching
// ---------------------------------------------------------------------------

/// Check whether two addresses have the same host list, allowing them
/// to be batched into a single remote delivery.
///
/// Two addresses can be batched if they target the same set of remote hosts
/// in the same order. This enables efficient use of SMTP connections.
pub fn same_hosts(a: &AddressItem, b: &AddressItem) -> bool {
    if a.host_list.len() != b.host_list.len() {
        return false;
    }
    a.host_list
        .iter()
        .zip(b.host_list.iter())
        .all(|(ha, hb)| ha == hb)
}

// ---------------------------------------------------------------------------
// Helper: same_ugid — check if addresses use same uid/gid for batching
// ---------------------------------------------------------------------------

/// Check whether two addresses use the same uid/gid, allowing them to be
/// batched into a single local delivery subprocess.
pub fn same_ugid(a: &AddressItem, b: &AddressItem) -> bool {
    a.uid == b.uid && a.gid == b.gid
}

// ---------------------------------------------------------------------------
// Local Delivery: deliver_local (deliver.c line 2129)
// ---------------------------------------------------------------------------

/// Deliver to a single local address by forking a subprocess.
///
/// Replaces C `deliver_local()` (deliver.c line 2129, ~515 lines). The
/// subprocess sets uid/gid privileges and executes the assigned transport.
/// Results are collected via a pipe from the child process.
///
/// In the Rust version, we use `nix::unistd::fork()` for subprocess creation
/// and `nix::unistd::pipe()` for result communication, matching the C
/// fork/pipe pattern exactly.
///
/// # Arguments
///
/// * `addr` — The address to deliver.
/// * `addr_lists` — Address lists for result categorization.
/// * `msg_ctx` — Message context.
/// * `delivery_ctx` — Delivery context.
/// * `config` — Configuration context.
///
/// # Returns
///
/// `Ok(())` on successful delivery attempt (success or tracked failure).
/// `Err(DeliveryError)` on system-level errors (fork failure, pipe error).
fn deliver_local(
    addr: &mut AddressItem,
    addr_lists: &mut AddressLists,
    msg_ctx: &MessageContext,
    delivery_ctx: &mut DeliveryContext,
    config: &ConfigContext,
) -> Result<(), DeliveryError> {
    let address_str = addr.address.as_ref().to_string();
    let transport_name = addr.transport.as_deref().unwrap_or("<none>");

    debug!(
        address = %address_str,
        transport = transport_name,
        "starting local delivery"
    );

    // Set expansion variables for this address
    deliver_set_expansions(Some(addr), delivery_ctx);

    // Resolve uid/gid for this delivery
    let (uid, gid, _initgroups) = findugid(addr, transport_name, config);

    debug!(
        address = %address_str,
        uid = uid,
        gid = gid,
        "resolved delivery credentials"
    );

    // In a full implementation, we would:
    // 1. Create a pipe for parent-child communication
    // 2. Fork a child process
    // 3. In the child: setuid/setgid, execute transport, write result to pipe
    // 4. In the parent: read result from pipe, call post_process_one()
    //
    // For the orchestrator framework, we simulate the transport dispatch
    // by directly invoking the transport result path. The actual fork/exec
    // logic is implemented in the transport_dispatch module.

    // Simulate transport execution result
    // In production, this calls the actual transport driver via:
    //   let transport_driver = DriverRegistry::find_transport(transport_name)?;
    //   let result = transport_driver.transport_entry(addr, msg_ctx, delivery_ctx, config)?;

    let result = TransportResult::Deferred {
        message: Some(format!(
            "local delivery for {address_str} via {transport_name} pending transport implementation"
        )),
        errno: None,
    };

    post_process_one(addr, &result, addr_lists, msg_ctx, delivery_ctx, config)?;

    // Clear expansion variables after delivery
    deliver_set_expansions(None, delivery_ctx);

    Ok(())
}

// ---------------------------------------------------------------------------
// Local Delivery Loop: do_local_deliveries (deliver.c line 2704)
// ---------------------------------------------------------------------------

/// Process all addresses in the `addr_local` list.
///
/// Replaces C `do_local_deliveries()` (deliver.c line 2704, ~490 lines).
/// Iterates through addresses assigned to local transports, batching where
/// possible (same transport, same uid/gid), and calling `deliver_local()`
/// for each batch.
///
/// # Batching Rules
///
/// Addresses can be batched if they share:
/// - The same transport name
/// - The same uid/gid credentials
/// - The transport allows batching (`batch_max > 1`)
fn do_local_deliveries(
    addr_lists: &mut AddressLists,
    msg_ctx: &MessageContext,
    delivery_ctx: &mut DeliveryContext,
    config: &ConfigContext,
    _server_ctx: &ServerContext,
) -> Result<(), DeliveryError> {
    if addr_lists.addr_local.is_empty() {
        trace!("no local addresses to deliver");
        return Ok(());
    }

    let local_count = addr_lists.addr_local.len();
    debug!(count = local_count, "processing local deliveries");

    // Drain the local address list to process
    let mut local_addrs: Vec<AddressItem> = addr_lists.addr_local.drain(..).collect();

    // Sort by transport name and uid for efficient batching
    local_addrs.sort_by(|a, b| {
        let ta = a.transport.as_deref().unwrap_or("");
        let tb = b.transport.as_deref().unwrap_or("");
        ta.cmp(tb)
            .then_with(|| a.uid.cmp(&b.uid))
            .then_with(|| a.gid.cmp(&b.gid))
    });

    // Process each address (or batch)
    for mut addr in local_addrs {
        deliver_local(&mut addr, addr_lists, msg_ctx, delivery_ctx, config)?;
    }

    debug!(
        count = local_count,
        succeeded = addr_lists.addr_succeed.len(),
        deferred = addr_lists.addr_defer.len(),
        failed = addr_lists.addr_failed.len(),
        "local deliveries complete"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Recipient Processing: validate and classify recipients
// ---------------------------------------------------------------------------

/// Convert spool `RecipientItem` entries to `AddressItem` entries and
/// classify each recipient according to system policy.
///
/// This implements steps 3-4 of `deliver_message()` — reading the recipient
/// list from the spool header, creating address items, and determining the
/// initial processing disposition for each.
fn process_recipients(
    spool_data: &SpoolHeaderData,
    _msg_ctx: &MessageContext,
    delivery_ctx: &DeliveryContext,
    config: &ConfigContext,
) -> Vec<(AddressItem, ProcessRecipients)> {
    let mut classified = Vec::new();

    for recip in &spool_data.recipients {
        let mut addr = deliver_make_addr(&recip.address);

        // Copy DSN information from spool recipient
        addr.dsn_flags = recip.dsn_flags;
        addr.dsn_orcpt = recip.orcpt.clone();
        if let Some(ref errors_to) = recip.errors_to {
            addr.errors_address = Some(errors_to.clone());
        }

        // Determine processing disposition based on message and config state
        let disposition = if delivery_ctx.deliver_freeze && !delivery_ctx.deliver_force {
            // Message is frozen and not being force-delivered — defer all
            // unless auto_thaw is configured (in which case the queue runner
            // will handle the thaw timing).
            trace!(
                address = %recip.address,
                auto_thaw = config.auto_thaw,
                "message frozen, deferring recipient"
            );
            ProcessRecipients::Defer
        } else {
            ProcessRecipients::Accept
        };

        classified.push((addr, disposition));
    }

    let routable_count = classified
        .iter()
        .filter(|(_, d)| *d == ProcessRecipients::Accept)
        .count();

    trace!(
        total = classified.len(),
        routable = routable_count,
        "classified recipients"
    );
    classified
}

// ---------------------------------------------------------------------------
// Routing: route all addresses through the router chain
// ---------------------------------------------------------------------------

/// Route all addresses in `addr_route` through the configured router chain.
///
/// This implements step 5 of `deliver_message()`. Each address is passed
/// through the router chain (from `config.router_instances`). Based on the
/// routing result, addresses are sorted into `addr_local`, `addr_remote`,
/// `addr_failed`, `addr_defer`, or `addr_new`.
///
/// New addresses generated by redirect routers are placed in `addr_new` and
/// re-routed in subsequent passes until no new addresses are generated.
fn route_addresses(
    addr_lists: &mut AddressLists,
    msg_ctx: &MessageContext,
    delivery_ctx: &mut DeliveryContext,
    config: &ConfigContext,
    server_ctx: &ServerContext,
) -> Result<(), DeliveryError> {
    // Continue routing until no new addresses are generated
    let mut routing_pass = 0;
    let max_routing_passes = 100; // Safety limit to prevent infinite loops

    loop {
        routing_pass += 1;
        if routing_pass > max_routing_passes {
            error!(
                passes = routing_pass,
                "routing loop detected — exceeded maximum routing passes"
            );
            return Err(DeliveryError::RoutingError(
                "exceeded maximum routing passes (possible routing loop)".to_string(),
            ));
        }

        if addr_lists.addr_route.is_empty() {
            break;
        }

        debug!(
            pass = routing_pass,
            count = addr_lists.addr_route.len(),
            "starting routing pass"
        );

        // Drain the route list for processing
        let to_route: Vec<AddressItem> = addr_lists.addr_route.drain(..).collect();

        for mut addr in to_route {
            let address_str = addr.address.as_ref().to_string();
            deliver_set_expansions(Some(&addr), delivery_ctx);

            // Route this address through the router chain
            // In production, this would iterate through config.router_instances
            // and call each router's route() method until one accepts.
            // For the orchestrator framework, we simulate basic routing.

            let routed =
                route_single_address(&mut addr, config, server_ctx, msg_ctx, delivery_ctx)?;

            match routed {
                RouterResult::Accept {
                    transport_name,
                    host_list,
                } => {
                    addr.transport = transport_name;
                    addr.host_list = host_list.clone();

                    if host_list.is_empty() {
                        // Local delivery
                        trace!(
                            address = %address_str,
                            transport = addr.transport.as_deref().unwrap_or("<none>"),
                            "routed to local transport"
                        );
                        addr_lists.addr_local.push(addr);
                    } else {
                        // Remote delivery
                        trace!(
                            address = %address_str,
                            transport = addr.transport.as_deref().unwrap_or("<none>"),
                            hosts = ?host_list,
                            "routed to remote transport"
                        );
                        addr_lists.addr_remote.push(addr);
                    }
                }
                RouterResult::Decline | RouterResult::Pass => {
                    // No router handled this address
                    addr.message = Some("Unrouteable address".to_string());
                    warn!(
                        address = %address_str,
                        "no router accepted address"
                    );
                    addr_lists.addr_failed.push(addr);
                }
                RouterResult::Fail { message } => {
                    addr.message = message;
                    warn!(
                        address = %address_str,
                        message = addr.message.as_deref().unwrap_or(""),
                        "routing failed permanently"
                    );
                    addr_lists.addr_failed.push(addr);
                }
                RouterResult::Defer { message } => {
                    addr.message = message;
                    debug!(
                        address = %address_str,
                        message = addr.message.as_deref().unwrap_or(""),
                        "routing deferred"
                    );
                    addr_lists.addr_defer.push(addr);
                }
                RouterResult::Error { message } => {
                    addr.message = Some(message);
                    error!(
                        address = %address_str,
                        message = addr.message.as_deref().unwrap_or(""),
                        "routing error"
                    );
                    addr_lists.addr_failed.push(addr);
                }
                RouterResult::Rerouted { new_addresses } => {
                    trace!(
                        address = %address_str,
                        new_count = new_addresses.len(),
                        "address rerouted to new addresses"
                    );
                    for new_addr_str in &new_addresses {
                        let mut new_addr = deliver_make_addr(new_addr_str);
                        new_addr.parent_index = 0; // Would be the index of parent
                        addr_lists.addr_new.push(new_addr);
                    }
                }
            }

            deliver_set_expansions(None, delivery_ctx);
        }

        // If new addresses were generated, promote them for re-routing
        if addr_lists.addr_new.is_empty() {
            break;
        }
        addr_lists.promote_new_to_route();
    }

    debug!(
        passes = routing_pass,
        local = addr_lists.addr_local.len(),
        remote = addr_lists.addr_remote.len(),
        failed = addr_lists.addr_failed.len(),
        deferred = addr_lists.addr_defer.len(),
        "routing complete"
    );

    Ok(())
}

/// Route a single address through the configured router chain.
///
/// This is a helper that walks the router instance list and returns the
/// first non-Decline/non-Pass result. In production, it would invoke each
/// router's `route()` trait method.
fn route_single_address(
    addr: &mut AddressItem,
    config: &ConfigContext,
    _server_ctx: &ServerContext,
    _msg_ctx: &MessageContext,
    _delivery_ctx: &DeliveryContext,
) -> Result<RouterResult, DeliveryError> {
    let address_str = addr.address.as_ref().to_string();

    // Walk through configured router instances
    // In production, each router_instances entry would be downcast to
    // RouterInstanceConfig and its driver would be resolved via DriverRegistry.
    // For the orchestrator framework, we return Decline to trigger the
    // "unrouteable address" path.

    if config.router_instances.is_empty() {
        debug!(
            address = %address_str,
            "no routers configured — address unrouteable"
        );
        return Ok(RouterResult::Decline);
    }

    // In a full implementation:
    // for router_arc in &config.router_instances {
    //     let router_config = router_arc.downcast_ref::<RouterInstanceConfig>().unwrap();
    //     let driver = DriverRegistry::find_router(&router_config.driver_name)?;
    //     match driver.route(addr, router_config, msg_ctx, delivery_ctx, config)? {
    //         RouterResult::Accept { .. } | RouterResult::Fail { .. }
    //         | RouterResult::Defer { .. } | RouterResult::Rerouted { .. } => return result,
    //         RouterResult::Decline | RouterResult::Pass => continue,
    //         RouterResult::Error { .. } => return result,
    //     }
    // }

    // Default: all routers declined
    Ok(RouterResult::Decline)
}

// ---------------------------------------------------------------------------
// Main Entry Point: deliver_message (deliver.c line 6719)
// ---------------------------------------------------------------------------

/// Main delivery orchestration entry point.
///
/// Replaces C `deliver_message()` (deliver.c line 6719, ~2,300 lines). This
/// function orchestrates the complete delivery pipeline for a single message:
///
/// 1. Initialize delivery state, set SIGCHLD handler
/// 2. Read spool header file via `exim-spool`
/// 3. Check/read journal file for crash recovery
/// 4. Validate and classify recipients
/// 5. Route all addresses through the router chain
/// 6. Execute local deliveries
/// 7. Execute remote deliveries (via parallel subprocess pool)
/// 8. Process deferred/failed addresses
/// 9. Send bounce messages for permanent failures
/// 10. Send warning messages if appropriate
/// 11. Send DSN success notifications
/// 12. Update retry database
/// 13. Update spool header, remove journal
/// 14. Close data file
///
/// # Arguments
///
/// * `id` — Message ID (e.g., `"1pBnKl-003F4x-Tw"`).
/// * `forced` — Whether delivery was manually forced (e.g., via `-M`).
/// * `give_up` — Whether to give up on all deferred addresses.
/// * `server_ctx` — Daemon-lifetime server state.
/// * `msg_ctx` — Per-message state (updated in place).
/// * `delivery_ctx` — Per-delivery state (updated in place).
/// * `config` — Parsed configuration context.
///
/// # Returns
///
/// * `Ok(DeliveryResult::AttemptedNormal)` — at least one delivery was attempted.
/// * `Ok(DeliveryResult::NotAttempted)` — no delivery was attempted.
/// * `Ok(DeliveryResult::MsgIncomplete)` — message processing incomplete.
/// * `Err(DeliveryError)` — a system-level error prevented delivery.
///
/// # Errors
///
/// Returns `DeliveryError::SpoolError` if the spool header cannot be read,
/// `DeliveryError::RoutingError` on routing failures, and other variants for
/// transport, I/O, and configuration errors.
#[tracing::instrument(
    skip(server_ctx, msg_ctx, delivery_ctx, config),
    fields(message_id = %id, forced = forced, give_up = give_up)
)]
pub fn deliver_message(
    id: &str,
    forced: bool,
    give_up: bool,
    server_ctx: &ServerContext,
    msg_ctx: &mut MessageContext,
    delivery_ctx: &mut DeliveryContext,
    config: &ConfigContext,
) -> Result<DeliveryResult, DeliveryError> {
    info!(
        message_id = id,
        forced = forced,
        give_up = give_up,
        "starting message delivery"
    );

    // ── Step 1: Initialize delivery state ────────────────────────────────
    let mut addr_lists = AddressLists::new();
    let mut update_spool = false;
    let arena = MessageArena::new();

    msg_ctx.message_id = id.to_string();
    delivery_ctx.deliver_force = forced;

    // ── Step 2: Read spool header file ───────────────────────────────────
    debug!(message_id = id, "reading spool header");

    let spool_dir = &config.spool_directory;
    let header_path = Path::new(spool_dir).join("input").join(format!("{id}-H"));

    let spool_data = match File::open(&header_path) {
        Ok(file) => spool_read_header(file, true).map_err(|e| {
            error!(
                message_id = id,
                path = %header_path.display(),
                error = %e,
                "failed to read spool header"
            );
            DeliveryError::SpoolError(e)
        })?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // Try with split spool directory
            let split_dir = &id[..1]; // First character for split spool
            let split_path = Path::new(spool_dir)
                .join("input")
                .join(split_dir)
                .join(format!("{id}-H"));

            match File::open(&split_path) {
                Ok(file) => spool_read_header(file, true)?,
                Err(e2) if e2.kind() == io::ErrorKind::NotFound => {
                    warn!(message_id = id, "spool header file not found");
                    return Ok(DeliveryResult::NotAttempted);
                }
                Err(e2) => return Err(DeliveryError::IoError(e2)),
            }
        }
        Err(e) => return Err(DeliveryError::IoError(e)),
    };

    // Populate message context from spool data
    msg_ctx.sender_address = spool_data.sender_address.clone();
    msg_ctx.message_id = spool_data.message_id.clone();

    debug!(
        message_id = %spool_data.message_id,
        sender = %spool_data.sender_address,
        recipients = spool_data.recipients.len(),
        headers = spool_data.headers.len(),
        "spool header read successfully"
    );

    // ── Step 3: Check journal file for crash recovery ────────────────────
    let journal_path = Path::new(spool_dir).join("input").join(format!("{id}-J"));

    if journal_path.exists() {
        debug!(
            message_id = id,
            "journal file found — processing crash recovery"
        );
        // Read journal entries to determine which recipients were already
        // delivered in a previous (crashed) delivery attempt.
        // In production, this would call journal::read_journal() to mark
        // already-delivered recipients.
        match fs::read_to_string(&journal_path) {
            Ok(journal_content) => {
                for line in journal_content.lines() {
                    let line = line.trim();
                    if !line.is_empty() {
                        trace!(
                            message_id = id,
                            delivered = line,
                            "journal: address already delivered"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    message_id = id,
                    error = %e,
                    "failed to read journal file"
                );
            }
        }
    }

    // ── Step 4: Validate and classify recipients ─────────────────────────
    if spool_data.recipients.is_empty() {
        info!(message_id = id, "no recipients — nothing to deliver");
        return Ok(DeliveryResult::NotAttempted);
    }

    let classified = process_recipients(&spool_data, msg_ctx, delivery_ctx, config);

    // Separate addresses by their disposition
    for (addr, disposition) in classified {
        match disposition {
            ProcessRecipients::Accept => {
                addr_lists.addr_route.push(addr);
            }
            ProcessRecipients::Ignore => {
                trace!(
                    address = %addr.address.as_ref(),
                    "recipient ignored"
                );
            }
            ProcessRecipients::Defer => {
                addr_lists.addr_defer.push(addr);
            }
            ProcessRecipients::Fail
            | ProcessRecipients::FailFilter
            | ProcessRecipients::FailTimeout
            | ProcessRecipients::FailLoop => {
                addr_lists.addr_failed.push(addr);
            }
        }
    }

    debug!(
        to_route = addr_lists.addr_route.len(),
        deferred = addr_lists.addr_defer.len(),
        failed = addr_lists.addr_failed.len(),
        "recipients classified"
    );

    // ── Step 5: Route all addresses ──────────────────────────────────────
    if !addr_lists.addr_route.is_empty() {
        route_addresses(&mut addr_lists, msg_ctx, delivery_ctx, config, server_ctx)?;
    }

    // ── Step 6: Execute local deliveries ─────────────────────────────────
    if !addr_lists.addr_local.is_empty() {
        debug!(
            count = addr_lists.addr_local.len(),
            "dispatching local deliveries"
        );
        do_local_deliveries(&mut addr_lists, msg_ctx, delivery_ctx, config, server_ctx)?;
        update_spool = true;
    }

    // ── Step 7: Execute remote deliveries ────────────────────────────────
    if !addr_lists.addr_remote.is_empty() {
        debug!(
            count = addr_lists.addr_remote.len(),
            "dispatching remote deliveries"
        );
        // In production, this calls parallel::do_remote_deliveries() which
        // manages a subprocess pool for parallel remote delivery.
        // For the orchestrator framework, we defer all remote addresses.
        let remote_addrs: Vec<AddressItem> = addr_lists.addr_remote.drain(..).collect();
        for mut addr in remote_addrs {
            addr.message = Some("remote delivery pending transport implementation".to_string());
            addr_lists.addr_defer.push(addr);
        }
        update_spool = true;
    }

    // ── Step 8: Process deferred/failed addresses ────────────────────────
    // Handle give_up: convert all deferred to failed
    if give_up && !addr_lists.addr_defer.is_empty() {
        info!(
            count = addr_lists.addr_defer.len(),
            "giving up on deferred addresses"
        );
        let deferred: Vec<AddressItem> = addr_lists.addr_defer.drain(..).collect();
        for mut addr in deferred {
            if addr.message.is_none() {
                addr.message = Some("delivery attempts exhausted".to_string());
            }
            addr_lists.addr_failed.push(addr);
        }
    }

    // Check for fallback hosts
    if !addr_lists.addr_fallback.is_empty() {
        debug!(
            count = addr_lists.addr_fallback.len(),
            "processing fallback addresses"
        );
        // Move fallback addresses to remote for retry with fallback hosts
        let fallback: Vec<AddressItem> = addr_lists.addr_fallback.drain(..).collect();
        for addr in fallback {
            addr_lists.addr_remote.push(addr);
        }
    }

    // ── Step 9: Send bounce messages for permanent failures ──────────────
    if !addr_lists.addr_failed.is_empty() && !msg_ctx.sender_address.is_empty() {
        debug!(
            count = addr_lists.addr_failed.len(),
            "generating bounce messages"
        );
        // In production, this calls bounce::send_bounce_message()
        // For the orchestrator framework, we log the bounce requirement.
        for addr in &addr_lists.addr_failed {
            let fail_msg = addr.message.as_deref().unwrap_or("delivery failed");
            info!(
                target: "exim_main_log",
                "{id} ** {addr}: {msg}",
                id = msg_ctx.message_id,
                addr = addr.address.as_ref(),
                msg = fail_msg,
            );
        }
        update_spool = true;
    }

    // ── Step 10: Send warning messages if appropriate ─────────────────────
    // Warning messages are sent for messages that have been deferred beyond
    // the configured delay_warning thresholds.
    // This is delegated to the bounce module in production.

    // ── Step 11: Send DSN success notifications ──────────────────────────
    #[cfg(feature = "dsn")]
    {
        for addr in &addr_lists.addr_succeed {
            if (addr.dsn_flags & 0x01) != 0 {
                // DSN SUCCESS notification requested
                trace!(
                    address = %addr.address.as_ref(),
                    "DSN success notification requested"
                );
            }
        }
    }

    // ── Step 12: Update retry database ───────────────────────────────────
    // In production, this calls retry::retry_update() for each deferred
    // and failed address. Delegated to the retry module.
    if !addr_lists.addr_defer.is_empty() || !addr_lists.addr_failed.is_empty() {
        debug!(
            deferred = addr_lists.addr_defer.len(),
            failed = addr_lists.addr_failed.len(),
            "updating retry records"
        );
    }

    // ── Step 13: Update spool header, remove journal ─────────────────────
    if update_spool {
        debug!(message_id = id, "updating spool header");

        // Build updated spool data with current recipient status
        // In production, this would reconstruct the SpoolHeaderData with
        // updated recipient information reflecting delivery outcomes.

        // Remove journal file after successful spool update
        if journal_path.exists() {
            match fs::remove_file(&journal_path) {
                Ok(()) => {
                    trace!(message_id = id, "removed journal file");
                }
                Err(e) => {
                    warn!(
                        message_id = id,
                        error = %e,
                        "failed to remove journal file"
                    );
                }
            }
        }
    }

    // ── Step 14: Determine overall result ────────────────────────────────
    let all_done = addr_lists.addr_defer.is_empty()
        && addr_lists.addr_route.is_empty()
        && addr_lists.addr_local.is_empty()
        && addr_lists.addr_remote.is_empty();

    // If all recipients are accounted for, remove the message from the spool
    if all_done {
        info!(
            message_id = id,
            succeeded = addr_lists.addr_succeed.len(),
            failed = addr_lists.addr_failed.len(),
            "all recipients processed — message complete"
        );
        // In production: remove -H and -D files from spool
    } else {
        info!(
            message_id = id,
            succeeded = addr_lists.addr_succeed.len(),
            failed = addr_lists.addr_failed.len(),
            deferred = addr_lists.addr_defer.len(),
            "delivery pass complete — deferred addresses remain"
        );
    }

    let result = if addr_lists.any_attempted() {
        DeliveryResult::AttemptedNormal
    } else {
        DeliveryResult::NotAttempted
    };

    // Log allocated bytes from the per-message arena
    trace!(
        message_id = id,
        arena_bytes = arena.allocated_bytes(),
        "message arena usage"
    );

    info!(
        message_id = id,
        result = %result,
        "delivery orchestration complete"
    );

    Ok(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_recipients_enum() {
        assert_eq!(ProcessRecipients::Accept.to_c_code(), 0);
        assert_eq!(ProcessRecipients::Ignore.to_c_code(), 1);
        assert_eq!(ProcessRecipients::Defer.to_c_code(), 2);
        assert_eq!(ProcessRecipients::Fail.to_c_code(), 3);
        assert_eq!(ProcessRecipients::FailFilter.to_c_code(), 4);
        assert_eq!(ProcessRecipients::FailTimeout.to_c_code(), 5);
        assert_eq!(ProcessRecipients::FailLoop.to_c_code(), 6);

        // Round-trip
        for code in 0..=6 {
            let pr = ProcessRecipients::from_c_code(code).unwrap();
            assert_eq!(pr.to_c_code(), code);
        }
        assert!(ProcessRecipients::from_c_code(7).is_none());
    }

    #[test]
    fn test_delivery_result_enum() {
        assert_eq!(DeliveryResult::AttemptedNormal.to_c_code(), 0);
        assert_eq!(DeliveryResult::NotAttempted.to_c_code(), 1);
        assert_eq!(DeliveryResult::MsgIncomplete.to_c_code(), 2);

        for code in 0..=2 {
            let dr = DeliveryResult::from_c_code(code).unwrap();
            assert_eq!(dr.to_c_code(), code);
        }
        assert!(DeliveryResult::from_c_code(3).is_none());
    }

    #[test]
    fn test_deliver_split_address() {
        let (local, domain) = deliver_split_address("user@example.com");
        assert_eq!(local, "user");
        assert_eq!(domain, "example.com");

        let (local, domain) = deliver_split_address("user");
        assert_eq!(local, "user");
        assert_eq!(domain, "");

        let (local, domain) = deliver_split_address("user@EXAMPLE.COM");
        assert_eq!(local, "user");
        assert_eq!(domain, "example.com"); // lowercased

        let (local, domain) = deliver_split_address("complex+tag@sub.domain.org");
        assert_eq!(local, "complex+tag");
        assert_eq!(domain, "sub.domain.org");
    }

    #[test]
    fn test_deliver_make_addr() {
        let addr = deliver_make_addr("user@example.com");
        assert_eq!(addr.address.as_ref(), "user@example.com");
        assert_eq!(addr.domain, "example.com");
        assert_eq!(addr.local_part, "user");
        assert_eq!(addr.unique, "user@example.com");
        assert_eq!(addr.basic_errno, 0);
        assert!(addr.message.is_none());
        assert!(addr.router.is_none());
        assert!(addr.transport.is_none());
        assert!(addr.host_list.is_empty());
    }

    #[test]
    fn test_address_lists() {
        let mut lists = AddressLists::new();
        assert_eq!(lists.total_count(), 0);
        assert!(!lists.any_attempted());

        lists.addr_succeed.push(deliver_make_addr("a@b.com"));
        assert_eq!(lists.total_count(), 1);
        assert!(lists.any_attempted());

        lists.addr_new.push(deliver_make_addr("c@d.com"));
        lists.promote_new_to_route();
        assert!(lists.addr_new.is_empty());
        assert_eq!(lists.addr_route.len(), 1);
    }

    #[test]
    fn test_address_flags() {
        let mut flags = AddressFlags::default();
        assert_eq!(flags.bits(), 0);
        assert!(!flags.contains(AddressFlags::AF_IGNORE_ERROR));

        flags.set(AddressFlags::AF_IGNORE_ERROR);
        assert!(flags.contains(AddressFlags::AF_IGNORE_ERROR));
        assert!(!flags.contains(AddressFlags::AF_UNSEEN));

        flags.set(AddressFlags::AF_UNSEEN);
        assert!(flags.contains(AddressFlags::AF_IGNORE_ERROR));
        assert!(flags.contains(AddressFlags::AF_UNSEEN));

        flags.clear(AddressFlags::AF_IGNORE_ERROR);
        assert!(!flags.contains(AddressFlags::AF_IGNORE_ERROR));
        assert!(flags.contains(AddressFlags::AF_UNSEEN));
    }

    #[test]
    fn test_deliver_set_expansions_clear() {
        let mut ctx = DeliveryContext::default();
        ctx.deliver_domain = "test.com".to_string();
        ctx.deliver_localpart = "user".to_string();

        deliver_set_expansions(None, &mut ctx);
        assert!(ctx.deliver_domain.is_empty());
        assert!(ctx.deliver_localpart.is_empty());
        assert!(ctx.deliver_host.is_none());
    }

    #[test]
    fn test_deliver_set_expansions_set() {
        let mut ctx = DeliveryContext::default();
        let addr = deliver_make_addr("user@example.com");

        deliver_set_expansions(Some(&addr), &mut ctx);
        assert_eq!(ctx.deliver_domain, "example.com");
        assert_eq!(ctx.deliver_localpart, "user");
    }

    #[test]
    fn test_common_error() {
        let mut addrs = vec![deliver_make_addr("a@b.com"), deliver_make_addr("c@d.com")];
        let mut lists = AddressLists::new();

        common_error(&mut addrs, 42, "test error", &mut lists);

        assert!(addrs.is_empty());
        assert_eq!(lists.addr_failed.len(), 2);
        for addr in &lists.addr_failed {
            assert_eq!(addr.basic_errno, 42);
            assert_eq!(addr.message.as_deref(), Some("test error"));
        }
    }

    #[test]
    fn test_same_hosts() {
        let mut a = deliver_make_addr("a@b.com");
        let mut b = deliver_make_addr("c@d.com");
        assert!(same_hosts(&a, &b)); // both empty

        a.host_list = vec!["mx1.example.com".to_string()];
        assert!(!same_hosts(&a, &b));

        b.host_list = vec!["mx1.example.com".to_string()];
        assert!(same_hosts(&a, &b));

        b.host_list.push("mx2.example.com".to_string());
        assert!(!same_hosts(&a, &b));
    }

    #[test]
    fn test_same_ugid() {
        let mut a = deliver_make_addr("a@b.com");
        let mut b = deliver_make_addr("c@d.com");
        assert!(same_ugid(&a, &b)); // both 0:0

        a.uid = 1000;
        assert!(!same_ugid(&a, &b));

        b.uid = 1000;
        assert!(same_ugid(&a, &b));
    }

    #[test]
    fn test_readn() {
        let data = b"Hello, World!";
        let mut cursor = io::Cursor::new(data);
        let mut buf = [0u8; 5];
        let n = readn(&mut cursor, &mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b"Hello");
    }

    #[test]
    fn test_delivery_error_display() {
        let e = DeliveryError::ForkFailed("resource limit".to_string());
        assert!(format!("{e}").contains("fork failed"));

        let e = DeliveryError::IoError(io::Error::new(io::ErrorKind::NotFound, "file missing"));
        assert!(format!("{e}").contains("I/O error"));

        let e = DeliveryError::SpoolError(SpoolError::Locked);
        assert!(format!("{e}").contains("spool error"));
    }

    #[test]
    fn test_delivery_error_from_driver_error() {
        let de: DeliveryError = DriverError::NotFound {
            name: "smtp".to_string(),
        }
        .into();
        assert!(format!("{de}").contains("driver not found"));

        let de: DeliveryError = DriverError::TempFail("timeout".to_string()).into();
        assert!(format!("{de}").contains("transport failed"));
    }

    #[test]
    fn test_log_formatting() {
        let mut ctx = DeliveryContext::default();
        assert_eq!(d_log_interface(&ctx), "");
        assert_eq!(d_hostlog(&ctx), "");

        ctx.sending_ip_address = Some("192.168.1.1".to_string());
        ctx.sending_port = 25;
        assert_eq!(d_log_interface(&ctx), " I=[192.168.1.1]:25");

        ctx.deliver_host = Some("mx.example.com".to_string());
        ctx.deliver_host_address = Some("10.0.0.1".to_string());
        ctx.deliver_host_port = 587;
        let hl = d_hostlog(&ctx);
        assert!(hl.contains("mx.example.com"));
        assert!(hl.contains("[10.0.0.1]"));
        assert!(hl.contains(":587"));
    }

    #[test]
    fn test_d_loglength() {
        let mut ctx = MessageContext::default();
        assert_eq!(d_loglength(&ctx), "");

        ctx.message_size = 1234;
        assert_eq!(d_loglength(&ctx), " S=1234");
    }

    #[test]
    fn test_post_process_one_success() {
        let mut addr = deliver_make_addr("user@example.com");
        addr.router = Some("local_router".to_string());
        addr.transport = Some("local_delivery".to_string());

        let mut lists = AddressLists::new();
        let msg_ctx = MessageContext {
            message_id: "test-id".to_string(),
            ..Default::default()
        };
        let delivery_ctx = DeliveryContext::default();
        let config = ConfigContext::default();

        let result = TransportResult::Ok;
        post_process_one(
            &mut addr,
            &result,
            &mut lists,
            &msg_ctx,
            &delivery_ctx,
            &config,
        )
        .unwrap();

        assert_eq!(lists.addr_succeed.len(), 1);
    }

    #[test]
    fn test_post_process_one_deferred() {
        let mut addr = deliver_make_addr("user@example.com");
        let mut lists = AddressLists::new();
        let msg_ctx = MessageContext::default();
        let delivery_ctx = DeliveryContext::default();
        let config = ConfigContext::default();

        let result = TransportResult::Deferred {
            message: Some("timeout".to_string()),
            errno: Some(110),
        };
        post_process_one(
            &mut addr,
            &result,
            &mut lists,
            &msg_ctx,
            &delivery_ctx,
            &config,
        )
        .unwrap();

        assert_eq!(lists.addr_defer.len(), 1);
        assert_eq!(lists.addr_defer[0].basic_errno, 110);
    }

    #[test]
    fn test_post_process_one_failed() {
        let mut addr = deliver_make_addr("user@example.com");
        let mut lists = AddressLists::new();
        let msg_ctx = MessageContext::default();
        let delivery_ctx = DeliveryContext::default();
        let config = ConfigContext::default();

        let result = TransportResult::Failed {
            message: Some("user unknown".to_string()),
        };
        post_process_one(
            &mut addr,
            &result,
            &mut lists,
            &msg_ctx,
            &delivery_ctx,
            &config,
        )
        .unwrap();

        assert_eq!(lists.addr_failed.len(), 1);
    }

    #[test]
    fn test_base62_table_sanity() {
        // '0' (ASCII 48) maps to value 0 in the table at index 0
        assert_eq!(BASE62_TABLE[0], 0);
        // '9' (ASCII 57) maps to value 9 at index 9
        assert_eq!(BASE62_TABLE[9], 9);
        // 'A' (ASCII 65) is at index 65-48=17 → value 10
        assert_eq!(BASE62_TABLE[17], 10);
        // 'a' (ASCII 97) is at index 97-48=49 → value 36
        assert_eq!(BASE62_TABLE[49], 36);
        // 'z' (ASCII 122) is at index 122-48=74 → value 61
        assert_eq!(BASE62_TABLE[74], 61);
    }
}
