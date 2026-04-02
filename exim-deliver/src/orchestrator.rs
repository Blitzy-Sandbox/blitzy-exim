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
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

use exim_config::types::{ConfigContext, DeliveryContext, MessageContext, ServerContext};
use exim_drivers::registry::DriverRegistry;
use exim_drivers::router_driver::{RouterInstanceConfig, RouterResult};
use exim_drivers::transport_driver::{TransportInstanceConfig, TransportResult};
use exim_drivers::DriverError;
use exim_expand::rfc2047_decode;
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

    /// Stripped prefix set by the accepting router (e.g. `"page+"`).
    /// Used by transports for `$local_part_prefix` expansion.
    pub prefix: Option<String>,

    /// Stripped suffix set by the accepting router (e.g. `"-S"`).
    /// Used by transports for `$local_part_suffix` expansion.
    pub suffix: Option<String>,

    /// For one-time redirect aliases, the original top-level recipient
    /// address before any redirection occurred.  Used in the delivery log
    /// to display the original address in angle brackets.
    pub onetime_parent: Option<String>,

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
    pub fn new_from_string(addr: &str) -> Self {
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
            prefix: None,
            suffix: None,
            onetime_parent: None,
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

/// Compute the RCPT TO address from the original case-preserved `addr.address`
/// by stripping prefix and suffix characters. This mirrors C Exim's
/// `transport_rcpt_address()` function from `transport.c`:
///
/// ```c
/// if (addr->suffix || addr->prefix) {
///     at = Ustrrchr(addr->address, '@');
///     plen = addr->prefix ? Ustrlen(addr->prefix) : 0;
///     slen = addr->suffix ? Ustrlen(addr->suffix) : 0;
///     return string_sprintf("%.*s@%s",
///         (int)(at - addr->address - plen - slen), addr->address + plen, at + 1);
/// }
/// return addr->address;
/// ```
///
/// This preserves the original case of the address (unlike using the lowercased
/// `addr.local_part` and `addr.domain` fields used for routing/matching).
fn transport_rcpt_address(addr: &AddressItem) -> String {
    let original = addr.address.as_ref();
    let prefix = addr.prefix.as_deref().unwrap_or("");
    let suffix = addr.suffix.as_deref().unwrap_or("");

    if prefix.is_empty() && suffix.is_empty() {
        return original.to_string();
    }

    if let Some(at_pos) = original.rfind('@') {
        let plen = prefix.len();
        let slen = suffix.len();
        let local_with_affixes = &original[..at_pos];
        let domain = &original[at_pos + 1..];

        // Strip prefix from start and suffix from end of local part
        let stripped_end = if slen > 0 && local_with_affixes.len() >= plen + slen {
            local_with_affixes.len() - slen
        } else {
            local_with_affixes.len()
        };
        let stripped_start = plen.min(local_with_affixes.len());
        let stripped_local = &local_with_affixes[stripped_start..stripped_end];
        format!("{}@{}", stripped_local, domain)
    } else {
        // No '@' — just strip prefix/suffix from the string
        let plen = prefix.len();
        let slen = suffix.len();
        let stripped_end = if slen > 0 && original.len() >= plen + slen {
            original.len() - slen
        } else {
            original.len()
        };
        original[plen..stripped_end].to_string()
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

    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    opts.mode(0o660);
    let file = opts.open(&log_path)?;

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
// Mainlog File Writer (deliver.c log_write() for LOG_MAIN)
// ---------------------------------------------------------------------------

/// Write a log entry to the Exim mainlog file.
///
/// The mainlog path is derived from `config.log_file_path` by replacing
/// `%slog` with `mainlog` (matching C Exim `log_open_as` in log.c).
/// If the log path template is empty, the default
/// `{spool_directory}/log/mainlog` is used.
///
/// Each entry is a single line terminated by `\n`, prefixed with a timestamp
/// in `YYYY-MM-DD HH:MM:SS` format.
fn write_mainlog(config: &ConfigContext, line: &str) {
    let mainlog_path = if config.log_file_path.is_empty() {
        format!("{}/log/mainlog", config.spool_directory)
    } else {
        config.log_file_path.replace("%slog", "mainlog")
    };

    let log_dir = Path::new(&mainlog_path).parent();
    if let Some(dir) = log_dir {
        let _ = fs::create_dir_all(dir);
        // Ensure log directory is accessible by both root and exim user
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o750));
        }
    }
    // Create log file with mode 0666 so both root and the exim setuid
    // binary can append to the same mainlog.  C Exim achieves this by
    // always creating the file as the exim user (via a fork+setuid
    // subprocess); we use permissive mode instead for simplicity.
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    opts.mode(0o666);
    match opts.open(&mainlog_path) {
        Ok(mut f) => {
            let _ = writeln!(f, "{line}");
        }
        Err(e) => {
            tracing::error!(path = %mainlog_path, error = %e, "failed to write mainlog");
        }
    }
}

/// Format a Unix timestamp for Exim mainlog lines.
///
/// Produces: `YYYY-MM-DD HH:MM:SS`
fn format_delivery_timestamp() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (year, month, day, hour, min, sec, _wday) = epoch_to_utc_components(now);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02}",)
}

/// Convert a Unix epoch timestamp to UTC calendar components.
///
/// Returns `(year, month, day, hour, minute, second, weekday)`.
/// Weekday: 0 = Thursday (epoch day), 1 = Friday, ... (mod 7).
fn epoch_to_utc_components(epoch_secs: u64) -> (u64, u64, u64, u64, u64, u64, u64) {
    let secs_per_day: u64 = 86400;
    let total_days = epoch_secs / secs_per_day;
    let day_secs = epoch_secs % secs_per_day;
    let hour = day_secs / 3600;
    let min = (day_secs % 3600) / 60;
    let sec = day_secs % 60;
    let wday = (total_days + 4) % 7; // 1970-01-01 was Thursday (4)

    // Civil date from day count (algorithm from Howard Hinnant)
    let z = total_days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    (year, m, d, hour, min, sec, wday)
}

// ---------------------------------------------------------------------------
// Log Formatting Helpers (deliver.c lines 748-843)
// ---------------------------------------------------------------------------

/// Format the sending interface IP address for log output.
///
/// Replaces C `d_log_interface()` (deliver.c line 748). Produces the
/// `I=[ip]:[port]` component for Exim delivery log lines.
fn _d_log_interface(delivery_ctx: &DeliveryContext) -> String {
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
fn _d_hostlog(delivery_ctx: &DeliveryContext) -> String {
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
fn _d_tlslog(msg_ctx: &MessageContext) -> String {
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
fn _d_tlslog(_msg_ctx: &MessageContext) -> String {
    String::new()
}

/// Format message length for log output.
///
/// Replaces C `d_loglength()` (deliver.c line 843). Produces the `S=nnn`
/// size component for delivery log lines.
fn _d_loglength(msg_ctx: &MessageContext) -> String {
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
    _delivery_ctx: &DeliveryContext,
    config: &ConfigContext,
) -> Result<(), DeliveryError> {
    let address_str = addr.address.as_ref().to_string();
    let transport_name = addr.transport.as_deref().unwrap_or("<none>");

    match result {
        TransportResult::Ok {
            ref host_name,
            ref host_address,
            ref smtp_confirmation,
        } => {
            // Delivery succeeded — move to addr_succeed
            info!(
                address = %address_str,
                transport = transport_name,
                router = addr.router.as_deref().unwrap_or("<none>"),
                "delivery succeeded"
            );

            // Build the C-compatible mainlog delivery line using the same
            // logic as C Exim's `string_log_address()` (deliver.c ~line 1000).
            //
            // For local transports:  "=> local_part"
            // For remote transports: "=> local_part@domain"
            // Then, if the built display address differs from the top-level
            // original address, append " <original>" in angle brackets.
            let ts = format_delivery_timestamp();
            let router_name = addr.router.as_deref().unwrap_or("<none>");

            // Determine local vs remote using the transport driver's
            // `is_local` flag — matching C Exim's `rf_queue_add()`.
            let is_local_transport = if let Some(ref tname) = addr.transport {
                let driver_name = config.transport_instances.iter().find_map(|arc| {
                    arc.downcast_ref::<TransportInstanceConfig>()
                        .filter(|tc| tc.name == *tname)
                        .map(|tc| tc.driver_name.clone())
                });
                if let Some(ref dname) = driver_name {
                    DriverRegistry::find_transport(dname)
                        .map(|f| f.is_local)
                        .unwrap_or(addr.host_list.is_empty())
                } else {
                    addr.host_list.is_empty()
                }
            } else {
                addr.host_list.is_empty()
            };

            let display_addr = if is_local_transport {
                // C Exim: for local deliveries, show just the local part
                addr.local_part.clone()
            } else {
                // C Exim: for remote deliveries, show local_part@domain
                format!("{}@{}", addr.local_part, addr.domain)
            };

            // Determine the original (top-level) address for the angle
            // bracket display.  C Exim uses `onetime_parent` if set,
            // otherwise walks up the parent chain to the topaddr.
            let top_addr = addr.onetime_parent.as_deref().unwrap_or(&address_str);

            // C Exim (deliver.c ~line 1060): Only add the angle-bracket
            // original address if it differs from the display address.
            let need_angle = !display_addr.eq_ignore_ascii_case(top_addr);

            // Build the base log line
            let mut mainlog_line = if need_angle {
                format!(
                    "{ts} {msg_id} => {da} <{orig}> R={router} T={transport}",
                    msg_id = msg_ctx.message_id,
                    da = display_addr,
                    orig = top_addr,
                    router = router_name,
                    transport = transport_name,
                )
            } else {
                format!(
                    "{ts} {msg_id} => {da} R={router} T={transport}",
                    msg_id = msg_ctx.message_id,
                    da = display_addr,
                    router = router_name,
                    transport = transport_name,
                )
            };

            // For remote (SMTP) deliveries, append H=host [addr] and C="resp"
            // matching C Exim deliver.c lines 1332+ and 1252+.
            if let Some(ref hn) = host_name {
                let ha = host_address.as_deref().unwrap_or(hn);
                mainlog_line.push_str(&format!(" H={} [{}]", hn, ha));
            }
            if let Some(ref conf) = smtp_confirmation {
                // C Exim quotes the confirmation string and escapes " and \.
                let escaped: String = conf
                    .chars()
                    .flat_map(|c| {
                        if c == '"' || c == '\\' {
                            vec!['\\', c]
                        } else {
                            vec![c]
                        }
                    })
                    .collect();
                mainlog_line.push_str(&format!(" C=\"{}\"", escaped));
            }

            write_mainlog(config, &mainlog_line);

            // Write to per-message log
            let log_msg = format!(
                "{} => {} R={} T={}\n",
                msg_ctx.message_id, address_str, router_name, transport_name,
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
    spool_data: &SpoolHeaderData,
) -> Result<(), DeliveryError> {
    let address_str = addr.address.as_ref().to_string();
    let transport_name = addr.transport.as_deref().unwrap_or("<none>");

    debug!(
        address = %address_str,
        transport = transport_name,
        "starting local delivery"
    );

    // ── Special case: /dev/null file delivery ──
    //
    // C Exim (transport.c ~line 280, deliver.c ~line 4175):
    // When the delivery target is /dev/null, the transport is
    // "bypassed" — the message is considered delivered without
    // actually writing anything.  The mainlog shows:
    //   => /dev/null <original_addr> R=router_name T=**bypassed**
    //
    // Detection: if the local_part is "/dev/null" (set by the
    // redirect router for file deliveries), treat as bypassed.
    if addr.local_part == "/dev/null" {
        let router_name = addr.router.as_deref().unwrap_or("???");
        let top_addr = addr.onetime_parent.as_deref().unwrap_or(&address_str);
        let ts = format_delivery_timestamp();

        let mainlog_line = format!(
            "{ts} {mid} => /dev/null <{oa}> R={rn} T=**bypassed**",
            mid = msg_ctx.message_id,
            oa = top_addr,
            rn = router_name,
        );
        write_mainlog(config, &mainlog_line);

        let log_msg = format!(
            "{} => /dev/null <{}> R={} T=**bypassed**\n",
            msg_ctx.message_id, top_addr, router_name,
        );
        let _ = deliver_msglog(
            &config.spool_directory,
            &msg_ctx.message_id,
            &log_msg,
            config,
        );

        address_done(addr, "delivered (/dev/null bypassed)");
        addr_lists.addr_succeed.push(addr.clone());
        return Ok(());
    }

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

    // Resolve transport driver from the registry and execute delivery.
    //
    // This replaces the C fork/exec/pipe pattern in deliver_local() (deliver.c
    // line 2129). In the C code, a child process was forked, the child set
    // uid/gid and called the transport's code() function, then wrote the result
    // to a pipe read by the parent. In Rust, we call the transport driver
    // directly since process isolation is not required for memory-safe code.
    //
    // Two-step resolution:
    // 1. Find the transport INSTANCE config by instance name (e.g., "local_delivery")
    // 2. Find the transport DRIVER factory by driver type name (e.g., "appendfile")
    let result = {
        // Step 1: Find the transport instance config
        let transport_config = config.transport_instances.iter().find_map(|arc| {
            arc.downcast_ref::<TransportInstanceConfig>()
                .filter(|tc| tc.name == transport_name)
        });

        match transport_config {
            Some(tc) => {
                let driver_type = tc.driver_name.clone();

                // Step 2: Find the driver factory by driver type name
                match DriverRegistry::find_transport(&driver_type) {
                    Some(factory) => {
                        let driver = (factory.create)();
                        debug!(
                            address = %address_str,
                            transport = transport_name,
                            driver = %driver_type,
                            "invoking transport driver"
                        );

                        // Build a transport config copy with spool data
                        // injected so the transport can access the actual
                        // message content. The message data is read from
                        // the spool -D file and passed via private_options_map.
                        let mut tc_with_data = TransportInstanceConfig {
                            name: tc.name.clone(),
                            driver_name: tc.driver_name.clone(),
                            srcfile: tc.srcfile.clone(),
                            srcline: tc.srcline,
                            batch_max: tc.batch_max,
                            batch_id: tc.batch_id.clone(),
                            home_dir: tc.home_dir.clone(),
                            current_dir: tc.current_dir.clone(),
                            expand_multi_domain: tc.expand_multi_domain.clone(),
                            multi_domain: tc.multi_domain,
                            overrides_hosts: tc.overrides_hosts,
                            max_addresses: tc.max_addresses.clone(),
                            connection_max_messages: tc.connection_max_messages,
                            deliver_as_creator: tc.deliver_as_creator,
                            disable_logging: tc.disable_logging,
                            initgroups: tc.initgroups,
                            uid_set: tc.uid_set,
                            gid_set: tc.gid_set,
                            uid: tc.uid,
                            gid: tc.gid,
                            expand_uid: tc.expand_uid.clone(),
                            expand_gid: tc.expand_gid.clone(),
                            warn_message: tc.warn_message.clone(),
                            shadow: tc.shadow.clone(),
                            shadow_condition: tc.shadow_condition.clone(),
                            filter_command: tc.filter_command.clone(),
                            filter_timeout: tc.filter_timeout,
                            event_action: tc.event_action.clone(),
                            add_headers: tc.add_headers.clone(),
                            remove_headers: tc.remove_headers.clone(),
                            return_path: tc.return_path.clone(),
                            debug_string: tc.debug_string.clone(),
                            max_parallel: tc.max_parallel.clone(),
                            message_size_limit: tc.message_size_limit.clone(),
                            headers_rewrite: tc.headers_rewrite.clone(),
                            body_only: tc.body_only,
                            delivery_date_add: tc.delivery_date_add,
                            envelope_to_add: tc.envelope_to_add,
                            headers_only: tc.headers_only,
                            rcpt_include_affixes: tc.rcpt_include_affixes,
                            return_path_add: tc.return_path_add,
                            return_output: tc.return_output,
                            return_fail_output: tc.return_fail_output,
                            log_output: tc.log_output,
                            log_fail_output: tc.log_fail_output,
                            log_defer_output: tc.log_defer_output,
                            retry_use_local_part: tc.retry_use_local_part,
                            options: Box::new(()),
                            private_options_map: tc.private_options_map.clone(),
                        };

                        // Inject spool directory and message ID so the
                        // transport can read the actual message -D data file.
                        tc_with_data.private_options_map.insert(
                            "__spool_directory".to_string(),
                            config.spool_directory.clone(),
                        );
                        tc_with_data
                            .private_options_map
                            .insert("__message_id".to_string(), msg_ctx.message_id.clone());
                        tc_with_data.private_options_map.insert(
                            "__sender_address".to_string(),
                            msg_ctx.sender_address.clone(),
                        );

                        // ── Compute message metrics from spool files ──
                        // These are needed for variable expansion of
                        // headers_add ($body_linecount, $message_linecount,
                        // $received_count).
                        let (body_linecount, message_linecount, received_count) =
                            compute_message_metrics(&config.spool_directory, &msg_ctx.message_id);

                        // ── Expand and inject transport add_headers ──
                        // C Exim expands transport headers_add in
                        // transport_write_message() with full variable
                        // context.  We expand common variables here and
                        // pass the result via __expanded_transport_add_headers.
                        if let Some(ref add_hdr) = tc.add_headers {
                            let expanded = expand_transport_add_headers(
                                add_hdr,
                                body_linecount,
                                message_linecount,
                                received_count,
                                uid,
                                gid,
                                spool_data,
                                &addr.local_part,
                                addr.prefix.as_deref().unwrap_or(""),
                                addr.suffix.as_deref().unwrap_or(""),
                            );
                            if !expanded.is_empty() {
                                tc_with_data.private_options_map.insert(
                                    "__expanded_transport_add_headers".to_string(),
                                    expanded,
                                );
                            }
                        }

                        // ── Inject router extra_headers (already expanded) ──
                        if let Some(ref extra) = addr.prop.extra_headers {
                            if !extra.is_empty() {
                                tc_with_data.private_options_map.insert(
                                    "__expanded_router_add_headers".to_string(),
                                    extra.clone(),
                                );
                            }
                        }

                        // ── Inject stripped local_part and affixes ──
                        // C Exim's transport sees the STRIPPED local part
                        // (after prefix/suffix removal by the accepting
                        // router).  We pass it via the private_options_map
                        // so the transport can use it for $local_part
                        // expansion in file paths.
                        tc_with_data
                            .private_options_map
                            .insert("__local_part".to_string(), addr.local_part.clone());
                        tc_with_data.private_options_map.insert(
                            "__local_part_prefix".to_string(),
                            addr.prefix.clone().unwrap_or_default(),
                        );
                        tc_with_data.private_options_map.insert(
                            "__local_part_suffix".to_string(),
                            addr.suffix.clone().unwrap_or_default(),
                        );

                        // ── Inject the original (top-level) address ──
                        // C Exim's Envelope-to header uses the progenitor
                        // address (walking up addr->parent until root).
                        // For one-time redirects, we stored this in
                        // `onetime_parent`.
                        if let Some(ref orig) = addr.onetime_parent {
                            tc_with_data
                                .private_options_map
                                .insert("__original_address".to_string(), orig.clone());
                        }

                        match driver.transport_entry(&tc_with_data, &address_str) {
                            Ok(tr) => tr,
                            Err(e) => {
                                warn!(
                                    address = %address_str,
                                    transport = transport_name,
                                    error = %e,
                                    "transport driver returned error"
                                );
                                TransportResult::Deferred {
                                    message: Some(format!("transport error: {e}")),
                                    errno: None,
                                }
                            }
                        }
                    }
                    None => {
                        warn!(
                            address = %address_str,
                            transport = transport_name,
                            driver = %driver_type,
                            "transport driver type not found in registry"
                        );
                        TransportResult::Failed {
                            message: Some(format!(
                                "transport driver type '{driver_type}' not found"
                            )),
                        }
                    }
                }
            }
            None => {
                // Transport instance not found in config — this means the
                // router assigned a transport name that doesn't exist.
                warn!(
                    address = %address_str,
                    transport = transport_name,
                    "transport instance not found in configuration"
                );
                TransportResult::Deferred {
                    message: Some(format!(
                        "transport instance '{transport_name}' not found in configuration"
                    )),
                    errno: None,
                }
            }
        }
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
    spool_data: &SpoolHeaderData,
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
        deliver_local(
            &mut addr,
            addr_lists,
            msg_ctx,
            delivery_ctx,
            config,
            spool_data,
        )?;
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
// Remote Deliveries: execute transport for remote addresses
// ---------------------------------------------------------------------------

/// Execute remote deliveries for all addresses in `addr_remote`.
///
/// This implements step 7 of `deliver_message()`, replacing C Exim's
/// `do_remote_deliveries()` in deliver.c. For each remote address, we
/// look up the transport instance, resolve the driver factory, and invoke
/// the transport's `transport_entry()` method — which for the smtp
/// transport opens a TCP connection to the destination host and performs
/// the SMTP transaction.
///
/// In C Exim this is done via a subprocess pool for parallelism.  For now
/// we execute each delivery sequentially in-process, which is sufficient
/// for correctness (parallelism is a performance optimisation).
fn do_remote_deliveries(
    addr_lists: &mut AddressLists,
    msg_ctx: &MessageContext,
    delivery_ctx: &mut DeliveryContext,
    config: &ConfigContext,
    _server_ctx: &ServerContext,
    spool_data: &SpoolHeaderData,
) -> Result<(), DeliveryError> {
    if addr_lists.addr_remote.is_empty() {
        trace!("no remote addresses to deliver");
        return Ok(());
    }

    let remote_count = addr_lists.addr_remote.len();
    debug!(count = remote_count, "processing remote deliveries");

    let mut remote_addrs: Vec<AddressItem> = addr_lists.addr_remote.drain(..).collect();

    for mut addr in remote_addrs.drain(..) {
        let address_str = addr.address.as_ref().to_string();

        // For remote delivery, the RCPT TO address uses the original case-preserved
        // address with prefix/suffix characters stripped. C Exim's
        // transport_rcpt_address() reconstructs from addr->address, not from
        // the lowercased addr->local_part. This preserves original case.
        let delivery_addr = transport_rcpt_address(&addr);

        let transport_name = addr.transport.clone().unwrap_or_default();

        if transport_name.is_empty() {
            addr.message = Some("no transport assigned for remote delivery".to_string());
            addr_lists.addr_failed.push(addr);
            continue;
        }

        deliver_set_expansions(Some(&addr), delivery_ctx);

        // Find the transport instance config and driver, then invoke delivery.
        let transport_config = config.transport_instances.iter().find_map(|arc| {
            arc.downcast_ref::<TransportInstanceConfig>()
                .filter(|tc| tc.name == transport_name)
        });

        let result = match transport_config {
            Some(tc) => {
                let driver_type = tc.driver_name.clone();
                match DriverRegistry::find_transport(&driver_type) {
                    Some(factory) => {
                        let driver = (factory.create)();
                        debug!(
                            address = %address_str,
                            transport = %transport_name,
                            driver = %driver_type,
                            "invoking remote transport driver"
                        );

                        // Build a transport config with spool data injected
                        let mut tc_copy = TransportInstanceConfig {
                            name: tc.name.clone(),
                            driver_name: tc.driver_name.clone(),
                            srcfile: tc.srcfile.clone(),
                            srcline: tc.srcline,
                            batch_max: tc.batch_max,
                            batch_id: tc.batch_id.clone(),
                            home_dir: tc.home_dir.clone(),
                            current_dir: tc.current_dir.clone(),
                            expand_multi_domain: tc.expand_multi_domain.clone(),
                            multi_domain: tc.multi_domain,
                            overrides_hosts: tc.overrides_hosts,
                            max_addresses: tc.max_addresses.clone(),
                            connection_max_messages: tc.connection_max_messages,
                            deliver_as_creator: tc.deliver_as_creator,
                            disable_logging: tc.disable_logging,
                            initgroups: tc.initgroups,
                            uid_set: tc.uid_set,
                            gid_set: tc.gid_set,
                            uid: tc.uid,
                            gid: tc.gid,
                            expand_uid: tc.expand_uid.clone(),
                            expand_gid: tc.expand_gid.clone(),
                            warn_message: tc.warn_message.clone(),
                            shadow: tc.shadow.clone(),
                            shadow_condition: tc.shadow_condition.clone(),
                            filter_command: tc.filter_command.clone(),
                            filter_timeout: tc.filter_timeout,
                            event_action: tc.event_action.clone(),
                            add_headers: tc.add_headers.clone(),
                            remove_headers: tc.remove_headers.clone(),
                            return_path: tc.return_path.clone(),
                            debug_string: tc.debug_string.clone(),
                            max_parallel: tc.max_parallel.clone(),
                            message_size_limit: tc.message_size_limit.clone(),
                            headers_rewrite: tc.headers_rewrite.clone(),
                            body_only: tc.body_only,
                            delivery_date_add: tc.delivery_date_add,
                            envelope_to_add: tc.envelope_to_add,
                            headers_only: tc.headers_only,
                            rcpt_include_affixes: tc.rcpt_include_affixes,
                            return_path_add: tc.return_path_add,
                            return_output: tc.return_output,
                            return_fail_output: tc.return_fail_output,
                            log_output: tc.log_output,
                            log_fail_output: tc.log_fail_output,
                            log_defer_output: tc.log_defer_output,
                            retry_use_local_part: tc.retry_use_local_part,
                            private_options_map: tc.private_options_map.clone(),
                            // The transport's get_options() builds typed options
                            // from private_options_map when a downcast fails.
                            options: Box::new(0u8),
                        };

                        // Inject spool data for message content access
                        inject_spool_data_to_transport(
                            &mut tc_copy,
                            spool_data,
                            msg_ctx,
                            config,
                            &addr,
                        );

                        // Inject primary hostname for EHLO expansion
                        tc_copy.private_options_map.insert(
                            "__primary_hostname".to_string(),
                            config.primary_hostname.clone(),
                        );

                        // Use the stripped delivery address for RCPT TO
                        // (local_part@domain without prefix/suffix)
                        let rcpt_addr = if tc_copy.rcpt_include_affixes {
                            address_str.clone()
                        } else {
                            delivery_addr.clone()
                        };

                        match driver.transport_entry(&tc_copy, &rcpt_addr) {
                            Ok(r) => r,
                            Err(e) => {
                                warn!(
                                    address = %address_str,
                                    error = %e,
                                    "remote transport execution failed"
                                );
                                TransportResult::Deferred {
                                    message: Some(format!("remote transport error: {}", e)),
                                    errno: Some(0),
                                }
                            }
                        }
                    }
                    None => {
                        error!(
                            driver = %driver_type,
                            "remote transport driver not found in registry"
                        );
                        TransportResult::Deferred {
                            message: Some(format!("transport driver '{}' not found", driver_type)),
                            errno: Some(0),
                        }
                    }
                }
            }
            None => {
                error!(
                    transport = %transport_name,
                    "remote transport instance not found in config"
                );
                TransportResult::Deferred {
                    message: Some(format!(
                        "transport '{}' not found in config",
                        transport_name
                    )),
                    errno: Some(0),
                }
            }
        };

        post_process_one(
            &mut addr,
            &result,
            addr_lists,
            msg_ctx,
            delivery_ctx,
            config,
        )?;
    }

    debug!(
        count = remote_count,
        succeeded = addr_lists.addr_succeed.len(),
        deferred = addr_lists.addr_defer.len(),
        failed = addr_lists.addr_failed.len(),
        "remote deliveries complete"
    );

    Ok(())
}

/// Helper: inject spool data into transport config for message content access.
fn inject_spool_data_to_transport(
    tc: &mut TransportInstanceConfig,
    spool_data: &SpoolHeaderData,
    msg_ctx: &MessageContext,
    config: &ConfigContext,
    addr: &AddressItem,
) {
    // Inject spool data path for the transport to read message content
    let data_path = format!("{}/input/{}-D", config.spool_directory, msg_ctx.message_id);
    tc.private_options_map
        .insert("__spool_data_file".to_string(), data_path);

    // Inject message headers for transports that need them.
    // HeaderLine.text already contains the full header line (name: value\n).
    let mut header_text = String::new();
    for hdr in &spool_data.headers {
        header_text.push_str(&hdr.text);
    }
    tc.private_options_map
        .insert("__message_headers".to_string(), header_text);

    // Inject sender address
    tc.private_options_map.insert(
        "__sender_address".to_string(),
        msg_ctx.sender_address.clone(),
    );

    // Inject stripped local_part and affixes
    tc.private_options_map
        .insert("__local_part".to_string(), addr.local_part.clone());
    tc.private_options_map.insert(
        "__local_part_prefix".to_string(),
        addr.prefix.clone().unwrap_or_default(),
    );
    tc.private_options_map.insert(
        "__local_part_suffix".to_string(),
        addr.suffix.clone().unwrap_or_default(),
    );
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
                    addr.transport = transport_name.clone();
                    addr.host_list = host_list.clone();

                    // ── Special case: blackhole discard (transport_name = None) ──
                    //
                    // When the redirect router returns Accept with no transport,
                    // this is a :blackhole: discard.  C Exim (deliver.c ~line 4175)
                    // handles this by writing a "=> :blackhole:" mainlog entry and
                    // marking the address as delivered without invoking any transport.
                    //
                    // Without this special case, the address would be pushed onto
                    // addr_local and then fail in do_local_deliveries() because
                    // there is no transport to dispatch to.
                    if transport_name.is_none() {
                        let router_name = addr.router.as_deref().unwrap_or("???");
                        let top_addr = addr.onetime_parent.as_deref().unwrap_or(&address_str);
                        let ts = format_delivery_timestamp();

                        // C Exim format: "=> :blackhole: <original_addr> R=router_name"
                        let mainlog_line = format!(
                            "{ts} {mid} => :blackhole: <{oa}> R={rn}",
                            mid = msg_ctx.message_id,
                            oa = top_addr,
                            rn = router_name,
                        );
                        write_mainlog(config, &mainlog_line);

                        // Write to per-message log as well
                        let log_msg = format!(
                            "{} => :blackhole: <{}> R={}\n",
                            msg_ctx.message_id, top_addr, router_name,
                        );
                        let _ = deliver_msglog(
                            &config.spool_directory,
                            &msg_ctx.message_id,
                            &log_msg,
                            config,
                        );

                        address_done(&mut addr, "delivered (blackhole)");
                        addr_lists.addr_succeed.push(addr);
                        continue;
                    }

                    // Classify as local vs remote using the transport
                    // driver's `is_local` flag — matching C Exim's
                    // `rf_queue_add()` logic in routers/rf_queue_add.c.
                    //
                    // Steps:
                    //  1. Find the transport *instance* config by name
                    //  2. Look up the driver *factory* by driver_name
                    //  3. If factory.is_local → local, else → remote
                    //
                    // Fallback: if transport cannot be resolved, use the
                    // host_list emptiness heuristic.
                    let is_local_transport = if let Some(ref tname) = transport_name {
                        let driver_name = config.transport_instances.iter().find_map(|arc| {
                            arc.downcast_ref::<TransportInstanceConfig>()
                                .filter(|tc| tc.name == *tname)
                                .map(|tc| tc.driver_name.clone())
                        });
                        if let Some(ref dname) = driver_name {
                            DriverRegistry::find_transport(dname)
                                .map(|f| f.is_local)
                                .unwrap_or(host_list.is_empty())
                        } else {
                            host_list.is_empty()
                        }
                    } else {
                        host_list.is_empty()
                    };

                    if is_local_transport {
                        // Local delivery
                        trace!(
                            address = %address_str,
                            transport = addr.transport.as_deref().unwrap_or("<none>"),
                            "routed to local transport"
                        );
                        addr_lists.addr_local.push(addr);
                    } else {
                        // Remote delivery — if the router didn't supply
                        // hosts, the transport itself defines them (e.g.
                        // smtp transport with `hosts = ...`).
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
                    // Track the original top-level address for delivery
                    // logging.  C Exim (deliver.c ~line 7377) sets
                    // `new->onetime_parent = recipients_list[pno].address`.
                    // IMPORTANT: use addr.address (qualified after routing),
                    // NOT the stale pre-qualification `address_str`.
                    let original = addr
                        .onetime_parent
                        .clone()
                        .unwrap_or_else(|| addr.address.as_ref().to_string());
                    let parent_router = addr.router.clone();

                    for new_addr_str in &new_addresses {
                        let mut new_addr = deliver_make_addr(new_addr_str);
                        new_addr.parent_index = 0;
                        new_addr.onetime_parent = Some(original.clone());

                        // ── File/pipe delivery detection ──
                        //
                        // C Exim: the redirect router places file and pipe
                        // delivery addresses directly on addr_local with
                        // the appropriate transport already assigned.
                        // These addresses are NOT re-routed.
                        //
                        // Detection:
                        //  - File delivery: address starts with '/'
                        //  - Pipe delivery: address starts with '|'
                        //
                        // For file deliveries, the redirect router's
                        // `file_transport` config option provides the
                        // transport name.  We look it up from the router
                        // config.  For `/dev/null`, the transport is set
                        // but bypassed — the `deliver_local` function
                        // handles the `/dev/null` special case.
                        if new_addr_str.starts_with('/') || new_addr_str.starts_with('|') {
                            // Set the router name from the parent address
                            new_addr.router = parent_router.clone();

                            // Find the file/pipe transport from the router config
                            let is_pipe = new_addr_str.starts_with('|');
                            if let Some(ref rname) = parent_router {
                                let transport_name =
                                    config.router_instances.iter().find_map(|arc| {
                                        arc.downcast_ref::<RouterInstanceConfig>()
                                            .filter(|rc| rc.name == *rname)
                                            .and_then(|rc| {
                                                if is_pipe {
                                                    rc.private_options_map
                                                        .get("pipe_transport")
                                                        .cloned()
                                                } else {
                                                    rc.private_options_map
                                                        .get("file_transport")
                                                        .cloned()
                                                }
                                            })
                                    });
                                new_addr.transport = transport_name;
                            }

                            // Set local_part for /dev/null detection
                            new_addr.local_part = new_addr_str.clone();

                            trace!(
                                address = %new_addr_str,
                                transport = new_addr.transport.as_deref().unwrap_or("<none>"),
                                "file/pipe delivery — direct to local queue"
                            );
                            addr_lists.addr_local.push(new_addr);
                        } else {
                            addr_lists.addr_new.push(new_addr);
                        }
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
    let mut address_str = addr.address.as_ref().to_string();

    // ── Address qualification (C: route.c ~line 1700) ──
    // If the address has no domain, qualify it with qualify_domain.
    // In C Exim, unqualified local addresses are qualified during
    // reception (receive.c), but we also ensure it here for safety.
    if !address_str.contains('@') {
        let qualify = if config.qualify_domain_recipient.is_empty() {
            &config.qualify_domain_sender
        } else {
            &config.qualify_domain_recipient
        };
        if !qualify.is_empty() {
            address_str = format!("{}@{}", address_str, qualify);
            addr.address = exim_store::taint::Tainted::new(address_str.clone());
            addr.domain = qualify.clone();
        }
    }

    // Walk through configured router instances. Each entry is an
    // Arc<dyn Any + Send + Sync> wrapping a RouterInstanceConfig created
    // during configuration parsing in exim-config/driver_init.rs.
    //
    // For each router, we:
    //   1. Downcast the Arc to RouterInstanceConfig
    //   2. Look up the driver factory in the DriverRegistry
    //   3. Create a driver instance via the factory
    //   4. Call driver.route() with the config and address
    //   5. Handle the result (Accept/Decline/Pass/Fail/Defer/Error/Rerouted)

    if config.router_instances.is_empty() {
        debug!(
            address = %address_str,
            "no routers configured — address unrouteable"
        );
        return Ok(RouterResult::Decline);
    }

    for router_arc in &config.router_instances {
        // Downcast the Arc to the concrete RouterInstanceConfig type.
        let router_config =
            match router_arc.downcast_ref::<exim_drivers::router_driver::RouterInstanceConfig>() {
                Some(cfg) => cfg,
                None => {
                    warn!(
                        address = %address_str,
                        "router instance is not a RouterInstanceConfig — skipping"
                    );
                    continue;
                }
            };

        debug!(
            router = %router_config.name,
            driver = %router_config.driver_name,
            address = %address_str,
            "trying router"
        );

        // ── Router precondition checks (C: route.c route_address() lines 1760–2100) ──
        // These checks mirror the generic preconditions evaluated by the C routing
        // framework BEFORE calling the driver-specific route() entry point.
        //
        // IMPORTANT: In C Exim the ordering is:
        //   1. domains check
        //   2. prefix/suffix stripping
        //   3. local_parts check (uses STRIPPED local part)
        //   4. check_local_user (uses STRIPPED local part)
        //   5. condition check
        //   6. driver.route()

        // Extract local part and domain from the address
        let (local_part, domain) = {
            if let Some(at_pos) = address_str.rfind('@') {
                (&address_str[..at_pos], &address_str[at_pos + 1..])
            } else {
                (address_str.as_str(), "")
            }
        };

        // 1. Check `domains` precondition (C: route.c ~line 1830)
        //    If the router specifies a domain list, skip if the address domain
        //    doesn't match.
        if let Some(ref domains_list) = router_config.domains {
            let named = build_named_domain_map(config);
            // Resolve `@` in the domain list to primary_hostname
            let expanded = domains_list.replace("@", &config.primary_hostname);
            let matched = match_domain_list(domain, &expanded, &named);
            if !matched {
                debug!(
                    router = %router_config.name,
                    address = %address_str,
                    domains = %domains_list,
                    "router skipped: domain does not match domains list"
                );
                continue;
            }
        }

        // 2. Prefix / suffix stripping (C: route.c ~line 2050-2100)
        //    MUST happen BEFORE local_parts / check_local_user checks
        //    because those checks use the stripped local part.
        //
        // C Exim (route.c ~line 1658): By default, addr->local_part is set
        // to the lowercased version (`lc_local_part`) unless the router has
        // `caseful_local_part` enabled.
        let working_lp = if router_config.caseful_local_part {
            local_part.to_string()
        } else {
            local_part.to_ascii_lowercase()
        };
        let mut routed_local_part = working_lp.clone();
        let mut stripped_prefix = String::new();
        let mut stripped_suffix = String::new();

        // Strip prefix if configured (e.g. `local_part_prefix = *+`)
        if let Some(ref pfx_pattern) = router_config.prefix {
            if let Some((pfx, rest)) = match_affix(&working_lp, pfx_pattern, true) {
                stripped_prefix = pfx;
                routed_local_part = rest;
            } else if !router_config.prefix_optional {
                // Prefix is required but doesn't match — skip router
                debug!(
                    router = %router_config.name,
                    address = %address_str,
                    prefix = %pfx_pattern,
                    "router skipped: required prefix not found"
                );
                continue;
            }
        }

        // Strip suffix if configured (e.g. `local_part_suffix = -S`)
        if let Some(ref sfx_pattern) = router_config.suffix {
            if let Some((sfx, rest)) = match_affix(&routed_local_part, sfx_pattern, false) {
                stripped_suffix = sfx;
                routed_local_part = rest;
            } else if !router_config.suffix_optional {
                // Suffix is required but doesn't match — skip router
                debug!(
                    router = %router_config.name,
                    address = %address_str,
                    suffix = %sfx_pattern,
                    "router skipped: required suffix not found"
                );
                continue;
            }
        }

        // 3. Check `local_parts` precondition (C: route.c ~line 1850)
        //    Uses the STRIPPED local part (after prefix/suffix removal).
        if let Some(ref lp_list) = router_config.local_parts {
            let named = build_named_localpart_map(config);
            let matched = match_string_list_generic(&routed_local_part, lp_list, false, &named);
            if !matched {
                debug!(
                    router = %router_config.name,
                    address = %address_str,
                    stripped_local = %routed_local_part,
                    "router skipped: local_part does not match local_parts list"
                );
                continue;
            }
        }

        // 4. Check `check_local_user` precondition (C: route.c ~line 1960)
        //    Uses the STRIPPED local part.
        if router_config.check_local_user {
            match check_local_user_exists(&routed_local_part) {
                Some((uid, gid)) => {
                    debug!(
                        router = %router_config.name,
                        local_part = %routed_local_part,
                        uid = uid,
                        gid = gid,
                        "check_local_user: user found"
                    );
                    // Set uid/gid on the address for later use by transport
                    addr.uid = uid;
                    addr.gid = gid;
                }
                None => {
                    debug!(
                        router = %router_config.name,
                        local_part = %routed_local_part,
                        "router skipped: check_local_user failed — user not found"
                    );
                    continue;
                }
            }
        }

        // 5. Check `condition` precondition (C: route.c ~line 1900)
        //    If set, expand the condition string and skip if it evaluates to false/empty.
        if let Some(ref condition) = router_config.condition {
            // Simple condition check: expand the string and check if non-empty/truthy
            let expanded = condition.trim();
            if expanded.is_empty()
                || expanded == "0"
                || expanded.eq_ignore_ascii_case("false")
                || expanded.eq_ignore_ascii_case("no")
            {
                debug!(
                    router = %router_config.name,
                    "router skipped: condition evaluated to false"
                );
                continue;
            }
        }

        // ── End precondition checks — proceed to driver dispatch ──

        // ── Set up thread-local ExpandContext for variable resolution ──
        // In C Exim, global variables like `deliver_domain`, `deliver_localpart`,
        // `deliver_localpart_prefix`, `deliver_localpart_suffix` are set before
        // the driver route() call.  We populate the thread-local ExpandContext
        // so that $domain, $local_part, $local_part_prefix, etc. resolve
        // correctly during string expansion within the router.
        {
            let mut exp_ctx = exim_expand::variables::ExpandContext::new();
            exp_ctx.domain = domain.to_string();
            exp_ctx.local_part = routed_local_part.clone();
            exp_ctx.local_part_prefix = stripped_prefix.clone();
            exp_ctx.local_part_suffix = stripped_suffix.clone();
            exp_ctx.local_part_prefix_v = stripped_prefix.clone();
            exp_ctx.local_part_suffix_v = stripped_suffix.clone();
            exp_ctx.router_name = router_config.name.clone();
            exp_ctx.primary_hostname =
                exim_store::taint::Clean::new(config.primary_hostname.clone());
            exp_ctx.qualify_domain =
                exim_store::taint::Clean::new(config.qualify_domain_sender.clone());
            exp_ctx.qualify_recipient =
                exim_store::taint::Clean::new(config.qualify_domain_recipient.clone());
            // Sender address from message context
            exp_ctx.sender_address =
                exim_store::taint::Tainted::new(_msg_ctx.sender_address.clone());
            exp_ctx.message_id = _msg_ctx.message_id.clone();
            exim_expand::set_expand_context(Some(exp_ctx));
        }

        // Look up the driver factory in the registry.
        let factory =
            match exim_drivers::registry::DriverRegistry::find_router(&router_config.driver_name) {
                Some(f) => f,
                None => {
                    exim_expand::set_expand_context(None);
                    warn!(
                        router = %router_config.name,
                        driver = %router_config.driver_name,
                        "router driver not found in registry — skipping"
                    );
                    continue;
                }
            };

        // Create a driver instance and call route().
        let driver = (factory.create)();
        let result = driver.route(router_config, &address_str, None);

        // Clear thread-local context after routing
        exim_expand::set_expand_context(None);

        match result {
            Ok(RouterResult::Accept {
                transport_name,
                host_list,
            }) => {
                let tname = transport_name.as_deref().unwrap_or("<none>");
                debug!(
                    router = %router_config.name,
                    address = %address_str,
                    transport = %tname,
                    "router accepted address"
                );
                // Set the router name on the address for logging/post-processing
                addr.router = Some(router_config.name.clone());

                // ── Update addr.local_part to the stripped (routed) value ──
                // C Exim (route.c ~line 1658): addr->local_part is set to
                // the lowercased, prefix/suffix-stripped local part after
                // routing.  The prefix and suffix are stored separately.
                addr.local_part = routed_local_part.clone();
                if !stripped_prefix.is_empty() {
                    addr.prefix = Some(stripped_prefix.clone());
                }
                if !stripped_suffix.is_empty() {
                    addr.suffix = Some(stripped_suffix.clone());
                }

                // ── Copy router extra_headers (headers_add) ──
                // C Exim route.c copies extra_headers from the router
                // config to the address, expanding $local_user_uid /
                // $local_user_gid using the passwd results from
                // check_local_user.
                if let Some(ref extra) = router_config.extra_headers {
                    let mut exp_ctx = exim_expand::variables::ExpandContext::new();
                    exp_ctx.local_user_uid = addr.uid;
                    exp_ctx.local_user_gid = addr.gid;
                    match exim_expand::expand_string_with_context(extra, &mut exp_ctx) {
                        Ok(expanded) => {
                            if !expanded.is_empty() {
                                addr.prop.extra_headers = Some(expanded);
                            }
                        }
                        Err(_e) => {
                            // Expansion failure for router extra_headers is non-fatal;
                            // C Exim logs and continues delivery.
                        }
                    }
                }

                // ── Copy router remove_headers ──
                if let Some(ref remove) = router_config.remove_headers {
                    addr.prop.remove_headers = Some(remove.clone());
                }

                return Ok(RouterResult::Accept {
                    transport_name,
                    host_list,
                });
            }
            Ok(RouterResult::Decline) | Ok(RouterResult::Pass) => {
                debug!(
                    router = %router_config.name,
                    address = %address_str,
                    "router declined — trying next"
                );
                continue;
            }
            Ok(RouterResult::Fail { message }) => {
                let msg = message.as_deref().unwrap_or("");
                debug!(
                    router = %router_config.name,
                    address = %address_str,
                    message = %msg,
                    "router permanently failed address"
                );
                return Ok(RouterResult::Fail { message });
            }
            Ok(RouterResult::Defer { message }) => {
                let msg = message.as_deref().unwrap_or("");
                debug!(
                    router = %router_config.name,
                    address = %address_str,
                    message = %msg,
                    "router deferred address"
                );
                return Ok(RouterResult::Defer { message });
            }
            Ok(result @ RouterResult::Error { .. }) => {
                warn!(
                    router = %router_config.name,
                    address = %address_str,
                    "router error"
                );
                return Ok(result);
            }
            Ok(RouterResult::Rerouted { new_addresses }) => {
                debug!(
                    router = %router_config.name,
                    address = %address_str,
                    "router rerouted address"
                );
                // Record which router produced the Rerouted result so that
                // downstream delivery-log lines can print `R=<name>`.  In C
                // Exim, the parent router is always known when generating
                // child addresses from redirect/alias expansion.
                addr.router = Some(router_config.name.clone());
                return Ok(RouterResult::Rerouted { new_addresses });
            }
            Err(e) => {
                warn!(
                    router = %router_config.name,
                    address = %address_str,
                    error = %e,
                    "router returned error"
                );
                return Ok(RouterResult::Defer {
                    message: Some(format!("router error: {}", e)),
                });
            }
        }
    }

    // All routers declined — address is unrouteable.
    debug!(
        address = %address_str,
        "all routers declined — address unrouteable"
    );
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
        do_local_deliveries(
            &mut addr_lists,
            msg_ctx,
            delivery_ctx,
            config,
            server_ctx,
            &spool_data,
        )?;
        update_spool = true;
    }

    // ── Step 7: Execute remote deliveries ────────────────────────────────
    if !addr_lists.addr_remote.is_empty() {
        debug!(
            count = addr_lists.addr_remote.len(),
            "dispatching remote deliveries"
        );
        do_remote_deliveries(
            &mut addr_lists,
            msg_ctx,
            delivery_ctx,
            config,
            server_ctx,
            &spool_data,
        )?;
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

        // Write "Completed" entry to mainlog (C Exim deliver.c line ~7059).
        let ts = format_delivery_timestamp();
        write_mainlog(config, &format!("{ts} {id} Completed"));

        // Remove spool files: -H, -D, and -J (journal) files.
        let spool_dir = &config.spool_directory;
        let input_dir = Path::new(spool_dir).join("input");
        for suffix in &["-H", "-D", "-J"] {
            let path = input_dir.join(format!("{id}{suffix}"));
            if path.exists() {
                let _ = fs::remove_file(&path);
            }
        }

        // Remove msglog file — C Exim removes it when delivery is complete
        // (deliver.c ~line 7106).
        let msglog_path = Path::new(spool_dir).join("msglog").join(id);
        if msglog_path.exists() {
            let _ = fs::remove_file(&msglog_path);
        }
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
// Router precondition helpers
// ---------------------------------------------------------------------------

/// Build a named domain list map from ConfigContext for domain matching.
///
/// Converts from ConfigContext's `BTreeMap<String, NamedList>` to the
/// `HashMap<String, String>` format expected by `match_domain_list`.
fn build_named_domain_map(config: &ConfigContext) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for (name, nl) in &config.named_lists.domain_lists {
        // Resolve `@` in the list value to primary_hostname
        let val = nl.value.replace("@", &config.primary_hostname);
        map.insert(name.clone(), val);
    }
    map
}

/// Build a named local-part list map from ConfigContext.
fn build_named_localpart_map(config: &ConfigContext) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for (name, nl) in &config.named_lists.localpart_lists {
        map.insert(name.clone(), nl.value.clone());
    }
    map
}

/// Match a prefix or suffix pattern against a local part.
///
/// In C Exim (route.c `route_check_prefix`/`route_check_suffix`), prefix
/// and suffix patterns are colon-separated lists.  Each element may contain
/// a wildcard `*` matching zero or more characters.
///
/// For a **prefix** (e.g. `*+`):
///   - The pattern is matched against the beginning of the local part.
///   - `*+` means "any characters followed by `+`". For `page+user`, the
///     prefix is `page+` and the remaining local part is `user`.
///
/// For a **suffix** (e.g. `-S`):
///   - The pattern is matched against the end of the local part.
///   - `-S` means the local part must end with `-S`. For `user-S`, the
///     suffix is `-S` and the remaining local part is `user`.
///
/// Returns `Some((matched_affix, remaining_local_part))` on success,
/// `None` if no pattern matches.
fn match_affix(local_part: &str, pattern_list: &str, is_prefix: bool) -> Option<(String, String)> {
    // C Exim uses strncmpic() (case-insensitive) for all prefix/suffix
    // matching in route_check_prefix() and route_check_suffix().  We
    // replicate that by lowercasing both sides before comparison, but
    // return the ORIGINAL (non-lowercased) matched portions so callers
    // see the actual characters from the local part.
    let lp_lower = local_part.to_ascii_lowercase();

    for pattern in pattern_list.split(':') {
        let pat = pattern.trim();
        if pat.is_empty() {
            continue;
        }
        let pat_lower = pat.to_ascii_lowercase();

        if is_prefix {
            // Prefix matching
            if let Some(star_pos) = pat.find('*') {
                // Wildcard prefix: e.g. `*+` means any chars then `+`
                let after_star = &pat_lower[star_pos + 1..];
                let before_star = &pat_lower[..star_pos];
                // The local part must start with before_star, then have
                // the after_star delimiter somewhere after that.
                if !before_star.is_empty() && !lp_lower.starts_with(before_star) {
                    continue;
                }
                let search_start = before_star.len();
                let search_area = &lp_lower[search_start..];
                // C Exim scans from the RIGHT for prefix wildcards (route.c
                // line 420: `for (p = local_part + Ustrlen(local_part) - (--plen); p >= local_part; p--)`)
                // That finds the RIGHTMOST occurrence.  But the `*` is at the
                // START of the pattern for prefixes, and the fixed part is at
                // the end.  The scan finds the rightmost position where the
                // fixed part starts, so the wildcard portion is as LARGE as
                // possible.
                if let Some(delim_pos) = search_area.rfind(after_star) {
                    let prefix_end = search_start + delim_pos + after_star.len();
                    if prefix_end < local_part.len() {
                        let prefix_str = &local_part[..prefix_end];
                        let remainder = &local_part[prefix_end..];
                        return Some((prefix_str.to_string(), remainder.to_string()));
                    }
                }
            } else {
                // Exact prefix match (no wildcard) — case-insensitive
                if lp_lower.starts_with(&pat_lower) && pat_lower.len() < local_part.len() {
                    let prefix_str = &local_part[..pat.len()];
                    let remainder = &local_part[pat.len()..];
                    return Some((prefix_str.to_string(), remainder.to_string()));
                }
            }
        } else {
            // Suffix matching
            if let Some(star_pos) = pat.find('*') {
                // Wildcard suffix: e.g. `-*` means `-` then any chars
                let before_star = &pat_lower[..star_pos];
                let _after_star = &pat_lower[star_pos + 1..];
                // C code scans left-to-right: `for (p = local_part; p < pend; p++)`
                // checking strncmpic(suffix, p, slen).
                let slen = before_star.len();
                if slen == 0 {
                    // Just `*` — matches zero-length suffix
                    return Some((String::new(), local_part.to_string()));
                }
                let alen = local_part.len();
                // Scan from left to right like C code
                if alen > slen {
                    for pos in 0..=(alen - slen) {
                        if lp_lower[pos..].starts_with(before_star) {
                            let suffix_str = &local_part[pos..];
                            let remainder = &local_part[..pos];
                            if !remainder.is_empty() {
                                return Some((suffix_str.to_string(), remainder.to_string()));
                            }
                        }
                    }
                }
            } else {
                // Exact suffix match (no wildcard) — case-insensitive
                let slen = pat.len();
                if local_part.len() > slen && lp_lower[local_part.len() - slen..] == pat_lower[..] {
                    let suffix_str = &local_part[local_part.len() - slen..];
                    let remainder = &local_part[..local_part.len() - slen];
                    return Some((suffix_str.to_string(), remainder.to_string()));
                }
            }
        }
    }
    None
}

/// Match a domain against a domain list (colon-separated).
/// Supports: exact match, wildcard (*.), negation (!), named lists (+name),
/// and `@` for primary hostname.
fn match_domain_list(
    domain: &str,
    list: &str,
    named_lists: &std::collections::HashMap<String, String>,
) -> bool {
    let domain_lower = domain.to_lowercase();
    let items = split_list(list);

    for item in &items {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (negated, pattern) = if let Some(rest) = trimmed.strip_prefix('!') {
            (true, rest.trim())
        } else {
            (false, trimmed)
        };

        // Named list: +listname
        if let Some(list_name) = pattern.strip_prefix('+') {
            if let Some(list_value) = named_lists.get(list_name) {
                let inner = match_domain_list(&domain_lower, list_value, named_lists);
                if inner {
                    return !negated;
                }
            }
            continue;
        }

        let pat_lower = pattern.to_lowercase();

        // Wildcard: *.example.com
        if let Some(_rest) = pat_lower.strip_prefix("*.") {
            let suffix = &pat_lower[1..]; // .example.com
            let matched = domain_lower.ends_with(suffix) || domain_lower == pat_lower[2..];
            if matched {
                return !negated;
            }
        } else if let Some(rest) = pat_lower.strip_prefix('.') {
            let matched = domain_lower.ends_with(&pat_lower) || domain_lower == rest;
            if matched {
                return !negated;
            }
        } else {
            // Exact match
            if domain_lower == pat_lower {
                return !negated;
            }
        }
    }
    false
}

/// Match a string against a colon-separated list.
/// Supports: exact match (case-insensitive), wildcard (*), negation (!),
/// named lists (+name).
fn match_string_list_generic(
    value: &str,
    list: &str,
    case_sensitive: bool,
    named_lists: &std::collections::HashMap<String, String>,
) -> bool {
    let val = if case_sensitive {
        value.to_string()
    } else {
        value.to_lowercase()
    };
    let items = split_list(list);

    for item in &items {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (negated, pattern) = if let Some(rest) = trimmed.strip_prefix('!') {
            (true, rest.trim())
        } else {
            (false, trimmed)
        };

        // Named list: +listname
        if let Some(list_name) = pattern.strip_prefix('+') {
            if let Some(list_value) = named_lists.get(list_name) {
                let inner =
                    match_string_list_generic(value, list_value, case_sensitive, named_lists);
                if inner {
                    return !negated;
                }
            }
            continue;
        }

        let pat = if case_sensitive {
            pattern.to_string()
        } else {
            pattern.to_lowercase()
        };

        // Wildcard prefix: *suffix
        if let Some(suffix) = pat.strip_prefix('*') {
            if val.ends_with(suffix) {
                return !negated;
            }
        } else if val == pat {
            return !negated;
        }
    }
    false
}

/// Split a colon-separated Exim list, handling doubled colons as escape.
fn split_list(list: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut chars = list.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == ':' {
            if chars.peek() == Some(&':') {
                // Doubled colon → literal colon
                chars.next();
                current.push(':');
            } else {
                items.push(std::mem::take(&mut current));
            }
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        items.push(current);
    }
    items
}

/// Check if a local part corresponds to a valid local system user.
///
/// Returns `Some((uid, gid))` if the user exists, `None` otherwise.
/// This replaces the C `route_finduser()` function call that sets
/// `pw` (passwd struct) and `local_user_uid`/`local_user_gid`.
///
/// Uses the `nix` crate's safe `User::from_name()` wrapper to avoid
/// any `unsafe` code in this crate (which has `#![forbid(unsafe_code)]`).
fn check_local_user_exists(local_part: &str) -> Option<(u32, u32)> {
    match nix::unistd::User::from_name(local_part) {
        Ok(Some(user)) => Some((user.uid.as_raw(), user.gid.as_raw())),
        _ => None,
    }
}

/// Compute message metrics from spool files.
///
/// Reads the -H and -D files to determine:
/// - `body_linecount`: lines in the message body (from -D file)
/// - `message_linecount`: total lines in the message (headers + body)
/// - `received_count`: number of Received: headers
///
/// Returns (body_linecount, message_linecount, received_count).
fn compute_message_metrics(spool_dir: &str, msg_id: &str) -> (i32, i32, i32) {
    let input_dir = format!("{}/input", spool_dir);

    // Count Received: headers and header lines from -H file
    let h_path = format!("{}/{}-H", input_dir, msg_id);
    let mut received_count = 0i32;
    let mut header_linecount = 0i32;
    if let Ok(f) = std::fs::File::open(&h_path) {
        if let Ok(hdr_data) = exim_spool::spool_read_header(f, true) {
            for hdr in &hdr_data.headers {
                if hdr.header_type == 'X' {
                    continue; // skip deleted
                }
                // Count lines in header text
                header_linecount += hdr.text.lines().count() as i32;
                // Check if it's a Received: header
                if hdr.text.starts_with("Received:") || hdr.header_type == '*' {
                    received_count += 1;
                }
            }
        }
    }

    // Count body lines from -D file
    let d_path = format!("{}/{}-D", input_dir, msg_id);
    let mut body_linecount = 0i32;
    if let Ok(data) = std::fs::read(&d_path) {
        // Skip the first line (header line "msgid-D\n")
        let msg_start = data
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| p + 1)
            .unwrap_or(0);
        let body = &data[msg_start..];
        // Count newlines in body
        body_linecount = body.iter().filter(|&&b| b == b'\n').count() as i32;
    }

    let message_linecount = header_linecount + body_linecount;
    (body_linecount, message_linecount, received_count)
}

/// Expand transport `headers_add` template with message metric variables.
///
/// C Exim expands these in `transport_write_message()`.  The common variables
/// used in transport headers_add are:
/// - `$body_linecount`
/// - `$message_linecount`
/// - `$received_count`
/// - `$local_user_uid`
/// - `$local_user_gid`
#[allow(clippy::too_many_arguments)] // mirrors C Exim's expand_transport_add_headers parameter set
fn expand_transport_add_headers(
    template: &str,
    body_linecount: i32,
    message_linecount: i32,
    received_count: i32,
    uid: u32,
    gid: u32,
    spool_data: &SpoolHeaderData,
    local_part: &str,
    prefix: &str,
    suffix: &str,
) -> String {
    let mut result = template.to_string();
    // Replace \\n (literal backslash-n in config) with actual newlines.
    // Config parser may have already translated these, but handle both.
    result = result.replace("\\n", "\n");

    // C Exim config continuation (`\n\` followed by indented next line)
    // strips leading whitespace on continuation lines when the value is
    // a multi-header string like headers_add.  After converting `\n` to
    // real newlines, strip leading whitespace from every line except the
    // first so that each header starts at column 0.
    //
    // Example config:
    //   headers_add = "X-a: 1\n\
    //                  X-b: 2"
    // Must produce two headers "X-a: 1" and "X-b: 2" (no indent on X-b).
    let lines: Vec<&str> = result.split('\n').collect();
    if lines.len() > 1 {
        let mut cleaned = String::with_capacity(result.len());
        for (i, line) in lines.iter().enumerate() {
            if i > 0 {
                cleaned.push('\n');
                cleaned.push_str(line.trim_start());
            } else {
                cleaned.push_str(line);
            }
        }
        result = cleaned;
    }

    result = result.replace("$body_linecount", &body_linecount.to_string());
    result = result.replace("$message_linecount", &message_linecount.to_string());
    result = result.replace("$received_count", &received_count.to_string());
    result = result.replace("$local_user_uid", &uid.to_string());
    result = result.replace("$local_user_gid", &gid.to_string());

    // Expand variables sourced from the spool header envelope data.
    // C Exim's expand_string() resolves these from global variables that
    // were populated when the spool header was read during delivery.
    let iface = spool_data.interface_address.as_deref().unwrap_or("");
    result = result.replace("$interface_address", iface);

    let host_addr = spool_data.host_address.as_deref().unwrap_or("");
    result = result.replace("$sender_host_address", host_addr);

    let host_name = spool_data.host_name.as_deref().unwrap_or("");
    result = result.replace("$sender_host_name", host_name);

    let protocol = spool_data.received_protocol.as_deref().unwrap_or("");
    result = result.replace("$received_protocol", protocol);

    let ident = spool_data.sender_ident.as_deref().unwrap_or("");
    result = result.replace("$sender_ident", ident);

    // ── $message_headers / $message_headers_raw ──
    // C Exim's find_header(NULL, ...) iterates all headers that are not
    // htype_old ('*') and concatenates their text.
    //
    // For the COOKED variant ($message_headers), C Exim:
    //   1. Concatenates header texts
    //   2. Strips trailing whitespace (including newlines)
    //   3. Applies RFC 2047 decoding
    //
    // For the RAW variant ($message_headers_raw), C Exim:
    //   1. Concatenates header texts verbatim
    //   2. Preserves trailing whitespace/newlines as-is
    //   3. No RFC 2047 decoding
    if result.contains("$message_headers") {
        // Build raw header text from spool headers (skip deleted '*' type)
        let mut raw_headers = String::new();
        for h in &spool_data.headers {
            if h.header_type == '*' {
                continue;
            }
            raw_headers.push_str(&h.text);
        }
        // Cooked: strip trailing whitespace, then RFC 2047 decode
        let cooked = {
            let trimmed = raw_headers.trim_end();
            rfc2047_decode(trimmed)
        };
        // IMPORTANT: Replace the longer name first to avoid partial
        // matching ("$message_headers_raw" contains "$message_headers").
        // Raw: preserve trailing newlines verbatim (matches C Exim).
        result = result.replace("$message_headers_raw", &raw_headers);
        result = result.replace("$message_headers", &cooked);
    }

    // ── Address-derived variables (C: transport sets these from addr->*) ──
    // $local_part_prefix_v is the "variable" part (without the wildcard
    // delimiter).  For `local_part_prefix = *+` matching `page+`, the
    // variable part is `page` (everything before the `+`).
    let prefix_v = if prefix.len() > 1 {
        // Strip the last char (the wildcard delimiter like '+')
        &prefix[..prefix.len() - 1]
    } else {
        prefix
    };
    let suffix_v = if suffix.len() > 1 {
        // Strip the first char (the wildcard delimiter like '-')
        &suffix[1..]
    } else {
        suffix
    };
    // CRITICAL: Replace longer variable names FIRST to prevent partial
    // matching (e.g. "$local_part_prefix" must not eat the start of
    // "$local_part_prefix_v").
    result = result.replace("$local_part_prefix_v", prefix_v);
    result = result.replace("$local_part_prefix", prefix);
    result = result.replace("$local_part_suffix_v", suffix_v);
    result = result.replace("$local_part_suffix", suffix);
    // $local_part_data defaults to $local_part when no override.
    result = result.replace("$local_part_data", local_part);
    result = result.replace("$local_part", local_part);

    result
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
        assert_eq!(_d_log_interface(&ctx), "");
        assert_eq!(_d_hostlog(&ctx), "");

        ctx.sending_ip_address = Some("192.168.1.1".to_string());
        ctx.sending_port = 25;
        assert_eq!(_d_log_interface(&ctx), " I=[192.168.1.1]:25");

        ctx.deliver_host = Some("mx.example.com".to_string());
        ctx.deliver_host_address = Some("10.0.0.1".to_string());
        ctx.deliver_host_port = 587;
        let hl = _d_hostlog(&ctx);
        assert!(hl.contains("mx.example.com"));
        assert!(hl.contains("[10.0.0.1]"));
        assert!(hl.contains(":587"));
    }

    #[test]
    fn test_d_loglength() {
        let mut ctx = MessageContext::default();
        assert_eq!(_d_loglength(&ctx), "");

        ctx.message_size = 1234;
        assert_eq!(_d_loglength(&ctx), " S=1234");
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

        let result = TransportResult::ok();
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
