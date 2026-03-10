// =============================================================================
// exim-drivers/src/transport_driver.rs — TransportDriver Trait Definition
// =============================================================================
//
// Defines the `TransportDriver` trait that replaces the C `transport_info`
// struct inheritance pattern (structs.h lines 250-261). Each transport
// (appendfile, pipe, smtp, lmtp, autoreply, queuefile) implements this trait.
//
// This file contains ZERO unsafe code (per AAP §0.7.2).

use crate::DriverError;

// =============================================================================
// Transport Result Enum
// =============================================================================

/// Result of transport execution.
///
/// Maps to C transport return values (`BOOL` from `code()` + `deferred_errno` patterns).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportResult {
    /// Delivery succeeded.
    /// C: returns TRUE from `code()`.
    Ok,
    /// Delivery deferred — retry later.
    Deferred {
        /// Optional deferral message.
        message: Option<String>,
        /// Optional errno from the deferral.
        errno: Option<i32>,
    },
    /// Delivery failed permanently.
    Failed {
        /// Optional failure message.
        message: Option<String>,
    },
    /// Internal error during transport.
    Error {
        /// Error description.
        message: String,
    },
}

// =============================================================================
// Transport Instance Config
// =============================================================================

/// Configuration for a transport instance, from Exim config file.
///
/// Replaces C `transport_instance` struct (structs.h lines 184-244).
#[derive(Debug)]
pub struct TransportInstanceConfig {
    // Base fields (from driver_instance)
    /// Instance name from config.
    pub name: String,
    /// Driver name (e.g., "appendfile", "smtp", "pipe").
    pub driver_name: String,
    /// Config source file for error reporting.
    pub srcfile: Option<String>,
    /// Config source line for error reporting.
    pub srcline: Option<i32>,

    // Transport-specific fields
    /// Max messages per batch.
    pub batch_max: i32,
    /// Batch identification.
    pub batch_id: Option<String>,
    /// Home directory (local transports only).
    pub home_dir: Option<String>,
    /// Current directory (local transports only).
    pub current_dir: Option<String>,
    /// Expand for multi-domain (remote transports only).
    pub expand_multi_domain: Option<String>,
    /// Used only for remote transports.
    pub multi_domain: bool,
    /// Used only for remote transports.
    pub overrides_hosts: bool,
    /// Used only for remote transports.
    pub max_addresses: Option<String>,
    /// Used only for remote transports.
    pub connection_max_messages: i32,
    /// Used only by pipe at present.
    pub deliver_as_creator: bool,
    /// Disable logging for this transport.
    pub disable_logging: bool,
    /// Initialize groups when setting uid.
    pub initgroups: bool,
    /// uid is set.
    pub uid_set: bool,
    /// gid is set.
    pub gid_set: bool,
    /// Fixed uid value.
    pub uid: u32,
    /// Fixed gid value.
    pub gid: u32,
    /// Expanded uid string.
    pub expand_uid: Option<String>,
    /// Expanded gid string.
    pub expand_gid: Option<String>,
    /// Warning message (used by appendfile mainly).
    pub warn_message: Option<String>,
    /// Name of shadow transport.
    pub shadow: Option<String>,
    /// Condition for running shadow transport.
    pub shadow_condition: Option<String>,
    /// For on-the-fly filtering.
    pub filter_command: Option<String>,
    /// Additional headers.
    pub add_headers: Option<String>,
    /// Headers to remove.
    pub remove_headers: Option<String>,
    /// Overriding return path.
    pub return_path: Option<String>,
    /// Debugging output string.
    pub debug_string: Option<String>,
    /// Number of concurrent instances.
    pub max_parallel: Option<String>,
    /// Biggest message this transport handles.
    pub message_size_limit: Option<String>,
    /// Rules for rewriting headers.
    pub headers_rewrite: Option<String>,
    /// Deliver only the body.
    pub body_only: bool,
    /// Add Delivery-Date header.
    pub delivery_date_add: bool,
    /// Add Envelope-To header.
    pub envelope_to_add: bool,
    /// Deliver only the headers.
    pub headers_only: bool,
    /// TRUE to retain affixes in RCPT commands.
    pub rcpt_include_affixes: bool,
    /// Add Return-Path header.
    pub return_path_add: bool,
    /// TRUE if output should always be returned.
    pub return_output: bool,
    /// Return output only on failure.
    pub return_fail_output: bool,
    /// Log transport output.
    pub log_output: bool,
    /// Log output on failure.
    pub log_fail_output: bool,
    /// Log output on deferral.
    pub log_defer_output: bool,
    /// Use local part in retry key (defaults true for local, false for remote).
    pub retry_use_local_part: bool,
    /// Event hook action string.
    pub event_action: Option<String>,
    /// Filter timeout in seconds.
    pub filter_timeout: i32,

    /// Driver-specific options (opaque to framework).
    pub options: Box<dyn std::any::Any + Send + Sync>,
}

// =============================================================================
// TransportDriver Trait
// =============================================================================

/// Trait for transport driver implementations.
///
/// Replaces C `transport_info` struct function pointers (structs.h lines 250-261):
/// ```c
/// typedef struct transport_info {
///   driver_info drinfo;
///   BOOL (*code)(transport_instance *, address_item *);
///   void (*tidyup)(transport_instance *);
///   void (*closedown)(transport_instance *);
///   BOOL local;
/// } transport_info;
/// ```
///
/// Each transport (appendfile, pipe, smtp, lmtp, autoreply, queuefile)
/// implements this trait.
pub trait TransportDriver: Send + Sync + std::fmt::Debug {
    /// Main transport entry point — delivers a message to the given address.
    ///
    /// Replaces C: `BOOL (*code)(transport_instance *, address_item *)`.
    fn transport_entry(
        &self,
        config: &TransportInstanceConfig,
        address: &str,
    ) -> Result<TransportResult, DriverError>;

    /// Setup entry point, used for address verification without actual delivery.
    ///
    /// Replaces C: `transport_instance.setup()` function pointer.
    fn setup(&self, _config: &TransportInstanceConfig, _address: &str) -> Result<(), DriverError> {
        // Default no-op — not all transports need setup.
        Ok(())
    }

    /// Tidyup function called during cleanup.
    ///
    /// Replaces C: `void (*tidyup)(transport_instance *)`.
    fn tidyup(&self, _config: &TransportInstanceConfig) {
        // Default no-op.
    }

    /// Close down a passed channel (for SMTP transport mainly).
    ///
    /// Replaces C: `void (*closedown)(transport_instance *)`.
    fn closedown(&self, _config: &TransportInstanceConfig) {
        // Default no-op.
    }

    /// Whether this is a local transport (as opposed to remote).
    ///
    /// Replaces C: `BOOL local` field in `transport_info`.
    fn is_local(&self) -> bool;

    /// Driver name for identification (e.g., "appendfile", "smtp", "pipe").
    fn driver_name(&self) -> &str;
}

// =============================================================================
// TransportDriverFactory
// =============================================================================

/// Factory for creating `TransportDriver` instances. Registered via `inventory::submit!`.
pub struct TransportDriverFactory {
    /// Name of the transport driver (e.g., "appendfile", "smtp", "pipe").
    pub name: &'static str,
    /// Factory function that creates a new transport driver instance.
    pub create: fn() -> Box<dyn TransportDriver>,
    /// Whether this is a local transport.
    pub is_local: bool,
    /// Optional display string.
    pub avail_string: Option<&'static str>,
}
