// =============================================================================
// exim-drivers/src/transport_driver.rs — TransportDriver Trait Definition
// =============================================================================
//
// Defines the `TransportDriver` trait, `TransportResult` enum,
// `TransportInstanceConfig` struct, and `TransportDriverFactory` factory type
// that together replace the C `transport_info` struct inheritance pattern
// (structs.h lines 250-261) and the `transport_instance` configuration struct
// (structs.h lines 184-244).
//
// In C, each transport driver (appendfile, pipe, smtp, lmtp, autoreply,
// queuefile) provides a `transport_info` struct with function pointers for
// `code()` (main delivery), `tidyup()` (cleanup), and `closedown()` (channel
// shutdown). The `transport_instance` struct carries per-instance
// configuration fields parsed from the Exim configuration file.
//
// In Rust, the function pointers become trait methods on `TransportDriver`,
// the per-instance configuration becomes the `TransportInstanceConfig` struct,
// and compile-time registration is handled via `inventory::submit!` using
// `TransportDriverFactory`.
//
// This file contains ZERO unsafe code (per AAP §0.7.2).
// =============================================================================

use crate::DriverError;
use std::any::Any;
use std::collections::HashMap;
use std::fmt;

// =============================================================================
// Transport Result Enum
// =============================================================================

/// Result of transport execution — indicates the outcome of a delivery attempt.
///
/// Maps to C transport return values: the `BOOL` return from the `code()`
/// function pointer in `transport_info` (structs.h line 253), combined with
/// the `deferred_errno` and error message patterns used throughout Exim's
/// delivery subsystem (`deliver.c`).
///
/// # Variants
///
/// - `Ok` — Delivery succeeded (C: returns `TRUE` from `code()`)
/// - `Deferred` — Temporary failure, retry later (C: `DEFER` + errno)
/// - `Failed` — Permanent failure (C: `FAIL` return)
/// - `Error` — Internal error during transport (C: `PANIC_DIE` / log_write patterns)
///
/// # Examples
///
/// ```
/// use exim_drivers::transport_driver::TransportResult;
///
/// let result = TransportResult::Ok;
/// assert!(result.is_ok());
///
/// let deferred = TransportResult::Deferred {
///     message: Some("connection timed out".to_string()),
///     errno: Some(110), // ETIMEDOUT
/// };
/// assert!(deferred.is_deferred());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportResult {
    /// Delivery succeeded.
    ///
    /// C equivalent: `code()` returns `TRUE` in `transport_info` (structs.h
    /// line 253). The message has been accepted by the downstream system.
    Ok,

    /// Delivery deferred — the message should be retried later.
    ///
    /// C equivalent: `code()` returns `FALSE` with `addr->basic_errno` set to
    /// a temporary error code and `addr->message` describing the failure.
    /// The retry subsystem (`retry.c`) will schedule a future attempt.
    Deferred {
        /// Human-readable description of why delivery was deferred.
        /// Corresponds to C `addr->message` in the `address_item` struct.
        message: Option<String>,

        /// System errno value associated with the deferral, if applicable.
        /// Corresponds to C `addr->basic_errno` in the `address_item` struct.
        /// Common values: 110 (ETIMEDOUT), 111 (ECONNREFUSED), 113 (EHOSTUNREACH).
        errno: Option<i32>,
    },

    /// Delivery failed permanently — the message will not be retried.
    ///
    /// C equivalent: `code()` returns `FALSE` with the address marked as
    /// failed (not deferred). A bounce message will be generated for the
    /// sender unless the message is a bounce itself.
    Failed {
        /// Human-readable description of the permanent failure.
        /// Corresponds to C `addr->message` in the `address_item` struct.
        message: Option<String>,
    },

    /// Internal error during transport execution.
    ///
    /// C equivalent: situations that trigger `log_write()` with `LOG_PANIC`
    /// flag or result in process-level error handling. These are not normal
    /// delivery failures but rather programming or system errors.
    Error {
        /// Description of the internal error.
        message: String,
    },
}

impl TransportResult {
    /// Returns `true` if delivery succeeded.
    ///
    /// # Examples
    ///
    /// ```
    /// use exim_drivers::transport_driver::TransportResult;
    /// assert!(TransportResult::Ok.is_ok());
    /// ```
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }

    /// Returns `true` if delivery was deferred (temporary failure).
    ///
    /// # Examples
    ///
    /// ```
    /// use exim_drivers::transport_driver::TransportResult;
    /// let r = TransportResult::Deferred { message: None, errno: None };
    /// assert!(r.is_deferred());
    /// ```
    pub fn is_deferred(&self) -> bool {
        matches!(self, Self::Deferred { .. })
    }

    /// Returns `true` if delivery failed permanently.
    ///
    /// # Examples
    ///
    /// ```
    /// use exim_drivers::transport_driver::TransportResult;
    /// let r = TransportResult::Failed { message: Some("user unknown".into()) };
    /// assert!(r.is_failed());
    /// ```
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }

    /// Returns `true` if an internal error occurred.
    ///
    /// # Examples
    ///
    /// ```
    /// use exim_drivers::transport_driver::TransportResult;
    /// let r = TransportResult::Error { message: "out of memory".into() };
    /// assert!(r.is_error());
    /// ```
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error { .. })
    }

    /// Returns the human-readable message associated with the result, if any.
    ///
    /// - `Ok` returns `None`.
    /// - `Deferred`, `Failed`, and `Error` return their respective messages.
    pub fn message(&self) -> Option<&str> {
        match self {
            Self::Ok => None,
            Self::Deferred { message, .. } => message.as_deref(),
            Self::Failed { message } => message.as_deref(),
            Self::Error { message } => Some(message.as_str()),
        }
    }

    /// Returns `true` if the result represents a successful delivery.
    /// This is equivalent to `is_ok()` but named for clarity in boolean
    /// contexts.
    pub fn is_success(&self) -> bool {
        self.is_ok()
    }

    /// Returns `true` if the result represents any kind of failure
    /// (deferred, failed, or error).
    pub fn is_failure(&self) -> bool {
        !self.is_ok()
    }
}

impl fmt::Display for TransportResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => write!(f, "OK"),
            Self::Deferred { message, errno } => {
                write!(f, "DEFERRED")?;
                if let Some(msg) = message {
                    write!(f, ": {msg}")?;
                }
                if let Some(e) = errno {
                    write!(f, " (errno={e})")?;
                }
                Result::Ok(())
            }
            Self::Failed { message } => {
                write!(f, "FAILED")?;
                if let Some(msg) = message {
                    write!(f, ": {msg}")?;
                }
                Result::Ok(())
            }
            Self::Error { message } => write!(f, "ERROR: {message}"),
        }
    }
}

// =============================================================================
// Transport Instance Config
// =============================================================================

/// Configuration for a transport instance, parsed from the Exim configuration
/// file.
///
/// Replaces the C `transport_instance` struct (structs.h lines 184-244). Each
/// named transport section in the Exim config file produces one instance of
/// this struct. The fields map 1:1 to the C struct members.
///
/// The `options` field is a type-erased container (`Box<dyn Any + Send + Sync>`)
/// holding driver-specific options. In C, this was the `void *options_block`
/// pointer in `driver_instance` (structs.h line 146), which pointed to a
/// driver-specific struct (e.g., `smtp_transport_options_block`,
/// `appendfile_transport_options_block`, `pipe_transport_options_block`).
///
/// # Field Categories
///
/// Fields are grouped by their usage scope:
///
/// - **Base fields**: Inherited from `driver_instance` — name, driver type,
///   source location for error reporting
/// - **Local transport fields**: `home_dir`, `current_dir` — only meaningful
///   for local transports (appendfile, pipe)
/// - **Remote transport fields**: `multi_domain`, `overrides_hosts`,
///   `max_addresses`, `connection_max_messages` — only meaningful for remote
///   transports (smtp, lmtp)
/// - **General fields**: Applicable to all transport types
/// - **Driver-specific options**: Opaque `options` box holding per-driver config
#[derive(Debug)]
pub struct TransportInstanceConfig {
    // =========================================================================
    // Base fields (from C driver_instance — structs.h lines 142-151)
    // =========================================================================
    /// Instance name from the configuration file.
    ///
    /// This is the user-assigned name in the `begin transports` section,
    /// e.g., `local_delivery`, `remote_smtp`.
    /// C: `driver_instance.name` (structs.h line 144).
    pub name: String,

    /// Driver type name (e.g., `"appendfile"`, `"smtp"`, `"pipe"`, `"lmtp"`,
    /// `"autoreply"`, `"queuefile"`).
    ///
    /// Used to look up the driver implementation in the registry.
    /// C: `driver_instance.driver_name` (structs.h line 148).
    pub driver_name: String,

    /// Configuration source file path for error reporting.
    ///
    /// `None` if the instance was created programmatically.
    /// C: `driver_instance.srcfile` (structs.h line 149).
    pub srcfile: Option<String>,

    /// Configuration source line number for error reporting.
    ///
    /// `None` if the instance was created programmatically.
    /// C: `driver_instance.srcline` (structs.h line 150).
    pub srcline: Option<i32>,

    // =========================================================================
    // Transport-specific fields (structs.h lines 195-243)
    // =========================================================================
    /// Maximum number of messages per batch delivery.
    ///
    /// Used by transports that support batching multiple messages in a single
    /// connection (primarily smtp). Default: 1.
    /// C: `transport_instance.batch_max` (structs.h line 195).
    pub batch_max: i32,

    /// Batch identification string for grouping messages.
    ///
    /// C: `transport_instance.batch_id` (structs.h line 196).
    pub batch_id: Option<String>,

    /// Home directory override — used only by local transports.
    ///
    /// When set, overrides the recipient's home directory for transports like
    /// appendfile and pipe. C: `transport_instance.home_dir` (structs.h line 197).
    pub home_dir: Option<String>,

    /// Current working directory — used only by local transports.
    ///
    /// C: `transport_instance.current_dir` (structs.h line 198).
    pub current_dir: Option<String>,

    /// Expand string for multi-domain determination — remote transports only.
    ///
    /// C: `transport_instance.expand_multi_domain` (structs.h line 200).
    pub expand_multi_domain: Option<String>,

    /// Whether this remote transport handles multiple domains per connection.
    ///
    /// Primarily relevant for the smtp transport. Default: `false`.
    /// C: `transport_instance.multi_domain` (structs.h line 201).
    pub multi_domain: bool,

    /// Whether this transport overrides hosts from the router — remote only.
    ///
    /// C: `transport_instance.overrides_hosts` (structs.h line 202).
    pub overrides_hosts: bool,

    /// Maximum number of addresses per delivery attempt — remote only.
    ///
    /// Stored as an expandable string for runtime evaluation.
    /// C: `transport_instance.max_addresses` (structs.h line 203).
    pub max_addresses: Option<String>,

    /// Maximum messages per connection — remote transports only.
    ///
    /// Limits how many messages are sent over a single SMTP connection
    /// before disconnecting. Default: 0 (unlimited).
    /// C: `transport_instance.connection_max_messages` (structs.h line 204).
    pub connection_max_messages: i32,

    /// Deliver as the creating user — used by the pipe transport.
    ///
    /// C: `transport_instance.deliver_as_creator` (structs.h line 206).
    pub deliver_as_creator: bool,

    /// Disable logging for this transport.
    ///
    /// For very unusual requirements where transport output should not
    /// appear in logs. C: `transport_instance.disable_logging` (structs.h line 207).
    pub disable_logging: bool,

    /// Initialize supplementary groups when setting uid.
    ///
    /// When `true`, calls `initgroups()` to set up the full group list
    /// for the delivery uid. C: `transport_instance.initgroups` (structs.h line 208).
    pub initgroups: bool,

    /// Whether `uid` has been explicitly set in config.
    ///
    /// C: `transport_instance.uid_set` (structs.h line 209).
    pub uid_set: bool,

    /// Whether `gid` has been explicitly set in config.
    ///
    /// C: `transport_instance.gid_set` (structs.h line 210).
    pub gid_set: bool,

    /// Fixed uid for delivery.
    ///
    /// C: `transport_instance.uid` (structs.h line 211). Stored as `u32`
    /// matching POSIX `uid_t` on Linux.
    pub uid: u32,

    /// Fixed gid for delivery.
    ///
    /// C: `transport_instance.gid` (structs.h line 212). Stored as `u32`
    /// matching POSIX `gid_t` on Linux.
    pub gid: u32,

    /// Expandable string for dynamic uid resolution.
    ///
    /// C: `transport_instance.expand_uid` (structs.h line 213).
    pub expand_uid: Option<String>,

    /// Expandable string for dynamic gid resolution.
    ///
    /// C: `transport_instance.expand_gid` (structs.h line 214).
    pub expand_gid: Option<String>,

    /// Warning message template — used primarily by the appendfile transport.
    ///
    /// C: `transport_instance.warn_message` (structs.h line 215).
    pub warn_message: Option<String>,

    /// Name of a shadow transport to run after successful delivery.
    ///
    /// Shadow transports receive a copy of the message after successful
    /// primary delivery. C: `transport_instance.shadow` (structs.h line 216).
    pub shadow: Option<String>,

    /// Condition string for running the shadow transport.
    ///
    /// Evaluated as an Exim expansion; if it yields a false value, the
    /// shadow transport is skipped.
    /// C: `transport_instance.shadow_condition` (structs.h line 217).
    pub shadow_condition: Option<String>,

    /// Command for on-the-fly message filtering before delivery.
    ///
    /// When set, message content is piped through this command before
    /// being passed to the transport.
    /// C: `transport_instance.filter_command` (structs.h line 218).
    pub filter_command: Option<String>,

    /// Additional headers to add to the message during delivery.
    ///
    /// C: `transport_instance.add_headers` (structs.h line 219).
    pub add_headers: Option<String>,

    /// Headers to remove from the message during delivery.
    ///
    /// C: `transport_instance.remove_headers` (structs.h line 220).
    pub remove_headers: Option<String>,

    /// Overriding return path (envelope sender) for this transport.
    ///
    /// C: `transport_instance.return_path` (structs.h line 221).
    pub return_path: Option<String>,

    /// Debug string for diagnostic output.
    ///
    /// C: `transport_instance.debug_string` (structs.h line 222).
    pub debug_string: Option<String>,

    /// Maximum number of concurrent delivery processes for this transport.
    ///
    /// Stored as an expandable string for runtime evaluation.
    /// C: `transport_instance.max_parallel` (structs.h line 223).
    pub max_parallel: Option<String>,

    /// Maximum message size this transport will handle.
    ///
    /// Messages exceeding this size are deferred with a temporary error.
    /// Stored as an expandable string for runtime evaluation.
    /// C: `transport_instance.message_size_limit` (structs.h line 224).
    pub message_size_limit: Option<String>,

    /// Rules for rewriting headers during transport.
    ///
    /// A string containing header rewriting rules that are parsed into
    /// `rewrite_rule` structures at config time.
    /// C: `transport_instance.headers_rewrite` (structs.h line 225).
    pub headers_rewrite: Option<String>,

    /// Deliver only the message body (no headers).
    ///
    /// C: `transport_instance.body_only` (structs.h line 229).
    pub body_only: bool,

    /// Add a `Delivery-Date` header to the message.
    ///
    /// C: `transport_instance.delivery_date_add` (structs.h line 230).
    pub delivery_date_add: bool,

    /// Add an `Envelope-To` header to the message.
    ///
    /// C: `transport_instance.envelope_to_add` (structs.h line 231).
    pub envelope_to_add: bool,

    /// Deliver only the message headers (no body).
    ///
    /// C: `transport_instance.headers_only` (structs.h line 232).
    pub headers_only: bool,

    /// Retain address affixes in RCPT TO commands.
    ///
    /// When `true`, prefix and suffix from router processing are kept
    /// in the recipient address passed to the transport.
    /// C: `transport_instance.rcpt_include_affixes` (structs.h line 233).
    pub rcpt_include_affixes: bool,

    /// Add a `Return-Path` header to the message.
    ///
    /// C: `transport_instance.return_path_add` (structs.h line 234).
    pub return_path_add: bool,

    /// Return transport output to the sender in all cases.
    ///
    /// C: `transport_instance.return_output` (structs.h line 235).
    pub return_output: bool,

    /// Return transport output to the sender only on failure.
    ///
    /// C: `transport_instance.return_fail_output` (structs.h line 236).
    pub return_fail_output: bool,

    /// Log transport output.
    ///
    /// C: `transport_instance.log_output` (structs.h line 237).
    pub log_output: bool,

    /// Log transport output on delivery failure.
    ///
    /// C: `transport_instance.log_fail_output` (structs.h line 238).
    pub log_fail_output: bool,

    /// Log transport output on delivery deferral.
    ///
    /// C: `transport_instance.log_defer_output` (structs.h line 239).
    pub log_defer_output: bool,

    /// Use local part in the retry key.
    ///
    /// Defaults to `true` for local transports (retry per local-part) and
    /// `false` for remote transports (retry per domain/host).
    /// C: `transport_instance.retry_use_local_part` (structs.h line 240).
    pub retry_use_local_part: bool,

    /// Event hook action string — expanded on notable delivery events.
    ///
    /// Only active when the `event` feature is enabled (replaces C's
    /// `#ifndef DISABLE_EVENT` guard at structs.h line 241-243).
    /// C: `transport_instance.event_action` (structs.h line 242).
    pub event_action: Option<String>,

    /// Timeout in seconds for the transport filter command.
    ///
    /// Applies when `filter_command` is set. Default: 300 seconds.
    /// C: `transport_instance.filter_timeout` (structs.h line 228).
    pub filter_timeout: i32,

    // =========================================================================
    // Driver-specific options (opaque to framework)
    // =========================================================================
    /// Driver-specific options block — opaque to the transport framework.
    ///
    /// Replaces C's `void *options_block` pointer in `driver_instance`
    /// (structs.h line 146). Each transport driver defines its own options
    /// struct (e.g., `SmtpTransportOptions`, `AppendfileTransportOptions`,
    /// `PipeTransportOptions`) and stores it here as a type-erased box.
    ///
    /// Transport driver implementations downcast this to their concrete type
    /// using `options.downcast_ref::<ConcreteType>()`.
    pub options: Box<dyn Any + Send + Sync>,

    /// Driver-specific private options parsed from the configuration file.
    ///
    /// Stores the raw key-value pairs for options that are not part of the
    /// generic transport option table. Each driver retrieves its specific
    /// options by name (e.g., "file" for appendfile, "command" for pipe).
    /// The values are the raw option values after the `=` sign, trimmed.
    ///
    /// This field supplements the `options` field by providing a simple
    /// string-based access path that does not require type-specific
    /// downcasting.
    pub private_options_map: HashMap<String, String>,
}

/// Unit struct used as the default value for `TransportInstanceConfig.options`.
///
/// When no driver-specific options have been set, the `options` field holds a
/// boxed `EmptyOptions` value. Drivers should check for this case when
/// downcasting and use their own default configuration if found.
#[derive(Debug, Clone, Copy)]
struct EmptyOptions;

impl Default for TransportInstanceConfig {
    /// Creates a `TransportInstanceConfig` with sensible defaults matching
    /// the C `transport_instance` initialization in `readconf.c`.
    ///
    /// All string options default to `None`, boolean flags default to `false`,
    /// `batch_max` defaults to `1`, `connection_max_messages` defaults to `0`
    /// (unlimited), `filter_timeout` defaults to `300` seconds, and `options`
    /// holds an `EmptyOptions` marker.
    fn default() -> Self {
        Self {
            name: String::new(),
            driver_name: String::new(),
            srcfile: None,
            srcline: None,
            batch_max: 1,
            batch_id: None,
            home_dir: None,
            current_dir: None,
            expand_multi_domain: None,
            multi_domain: false,
            overrides_hosts: false,
            max_addresses: None,
            connection_max_messages: 0,
            deliver_as_creator: false,
            disable_logging: false,
            initgroups: false,
            uid_set: false,
            gid_set: false,
            uid: 0,
            gid: 0,
            expand_uid: None,
            expand_gid: None,
            warn_message: None,
            shadow: None,
            shadow_condition: None,
            filter_command: None,
            add_headers: None,
            remove_headers: None,
            return_path: None,
            debug_string: None,
            max_parallel: None,
            message_size_limit: None,
            headers_rewrite: None,
            body_only: false,
            delivery_date_add: false,
            envelope_to_add: false,
            headers_only: false,
            rcpt_include_affixes: false,
            return_path_add: false,
            return_output: false,
            return_fail_output: false,
            log_output: false,
            log_fail_output: false,
            log_defer_output: false,
            retry_use_local_part: false,
            event_action: None,
            filter_timeout: 300,
            options: Box::new(EmptyOptions),
            private_options_map: HashMap::new(),
        }
    }
}

impl TransportInstanceConfig {
    /// Creates a new `TransportInstanceConfig` with the given instance name
    /// and driver name, using defaults for all other fields.
    ///
    /// # Arguments
    ///
    /// - `name` — The instance name from the config file (e.g., `"local_delivery"`)
    /// - `driver_name` — The driver type name (e.g., `"appendfile"`, `"smtp"`)
    ///
    /// # Examples
    ///
    /// ```
    /// use exim_drivers::transport_driver::TransportInstanceConfig;
    ///
    /// let config = TransportInstanceConfig::new("local_delivery", "appendfile");
    /// assert_eq!(config.name, "local_delivery");
    /// assert_eq!(config.driver_name, "appendfile");
    /// assert_eq!(config.batch_max, 1);
    /// ```
    pub fn new(name: impl Into<String>, driver_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            driver_name: driver_name.into(),
            ..Self::default()
        }
    }

    /// Creates a new `TransportInstanceConfig` with config source location
    /// information for error reporting.
    ///
    /// # Arguments
    ///
    /// - `name` — The instance name from the config file
    /// - `driver_name` — The driver type name
    /// - `srcfile` — The configuration file path where this transport was defined
    /// - `srcline` — The line number in the configuration file
    pub fn with_source(
        name: impl Into<String>,
        driver_name: impl Into<String>,
        srcfile: impl Into<String>,
        srcline: i32,
    ) -> Self {
        Self {
            name: name.into(),
            driver_name: driver_name.into(),
            srcfile: Some(srcfile.into()),
            srcline: Some(srcline),
            ..Self::default()
        }
    }

    /// Format the source location for error messages.
    ///
    /// Returns a string like `"filename:42"` or `"<unknown>"` if no source
    /// information is available. Used by config validation and error
    /// reporting throughout the delivery subsystem.
    pub fn source_location(&self) -> String {
        match (&self.srcfile, self.srcline) {
            (Some(file), Some(line)) => format!("{file}:{line}"),
            (Some(file), None) => file.clone(),
            _ => "<unknown>".to_string(),
        }
    }

    /// Sets the driver-specific options block.
    ///
    /// The provided value must implement `Any + Send + Sync` so it can be
    /// stored type-erased and later recovered via `downcast_ref()`.
    ///
    /// # Type Parameters
    ///
    /// - `T` — The concrete driver options type (e.g., `SmtpTransportOptions`)
    pub fn set_options<T: Any + Send + Sync + 'static>(&mut self, opts: T) {
        self.options = Box::new(opts);
    }

    /// Attempts to downcast the driver-specific options to a concrete type.
    ///
    /// Returns `None` if the options are not of type `T` or if no
    /// driver-specific options have been set (i.e., the options hold the
    /// default `EmptyOptions` marker).
    ///
    /// # Type Parameters
    ///
    /// - `T` — The expected concrete driver options type
    pub fn options_as<T: Any + Send + Sync + 'static>(&self) -> Option<&T> {
        self.options.downcast_ref::<T>()
    }
}

impl fmt::Display for TransportInstanceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "transport \"{}\" (driver={})",
            self.name, self.driver_name
        )
    }
}

// =============================================================================
// TransportDriver Trait
// =============================================================================

/// Trait for transport driver implementations.
///
/// Replaces the C `transport_info` struct function pointers (structs.h lines
/// 250-261):
///
/// ```c
/// typedef struct transport_info {
///   driver_info drinfo;
///   BOOL (*code)(transport_instance *, address_item *);  // Main entry point
///   void (*tidyup)(transport_instance *);                // Tidyup function
///   void (*closedown)(transport_instance *);             // Close passed channel
///   BOOL local;                                          // TRUE for local
/// } transport_info;
/// ```
///
/// Each transport (appendfile, pipe, smtp, lmtp, autoreply, queuefile)
/// implements this trait and registers itself via `inventory::submit!` using
/// a `TransportDriverFactory`.
///
/// # Required Methods
///
/// - [`transport_entry`](TransportDriver::transport_entry) — Main delivery
///   entry point
/// - [`is_local`](TransportDriver::is_local) — Local vs remote classification
/// - [`driver_name`](TransportDriver::driver_name) — Driver identification
///
/// # Default-Implemented Methods
///
/// - [`setup`](TransportDriver::setup) — Pre-delivery setup (no-op by default)
/// - [`tidyup`](TransportDriver::tidyup) — Post-delivery cleanup (no-op)
/// - [`closedown`](TransportDriver::closedown) — Channel shutdown (no-op)
///
/// # Thread Safety
///
/// All transport drivers must be `Send + Sync` because the driver registry is
/// accessed from multiple forked processes and the driver instances may be
/// shared. The `Debug` supertrait is required for diagnostic output.
pub trait TransportDriver: Send + Sync + fmt::Debug {
    /// Main transport entry point — delivers a message to the given address.
    ///
    /// This is the primary function of a transport driver. It performs the
    /// actual delivery of a message to a single recipient address.
    ///
    /// Replaces C: `BOOL (*code)(transport_instance *, address_item *)`
    /// (structs.h line 253).
    ///
    /// # Arguments
    ///
    /// - `config` — The transport instance configuration, including both
    ///   generic transport options and driver-specific options in the
    ///   `options` field (downcast to the appropriate driver options type).
    /// - `address` — The recipient address to deliver to. In the C code,
    ///   this was a pointer to `address_item`; here it is the address string.
    ///
    /// # Returns
    ///
    /// - `Ok(TransportResult::Ok)` — Delivery succeeded
    /// - `Ok(TransportResult::Deferred { .. })` — Temporary failure, retry
    /// - `Ok(TransportResult::Failed { .. })` — Permanent failure
    /// - `Ok(TransportResult::Error { .. })` — Internal error
    /// - `Err(DriverError)` — Driver-level error (distinct from delivery failure)
    fn transport_entry(
        &self,
        config: &TransportInstanceConfig,
        address: &str,
    ) -> Result<TransportResult, DriverError>;

    /// Setup entry point — used for address verification without actual
    /// delivery.
    ///
    /// Called during address verification (`-bv` mode) to check that the
    /// transport can handle the address without performing actual delivery.
    /// Not all transports need setup; the default implementation is a no-op.
    ///
    /// Replaces C: `transport_instance.setup()` function pointer
    /// (structs.h line 187-193).
    ///
    /// # Arguments
    ///
    /// - `config` — The transport instance configuration
    /// - `address` — The address being verified
    ///
    /// # Returns
    ///
    /// - `Ok(())` — Setup succeeded, transport can handle this address
    /// - `Err(DriverError)` — Setup failed, transport cannot verify this address
    fn setup(&self, _config: &TransportInstanceConfig, _address: &str) -> Result<(), DriverError> {
        // Default no-op — not all transports need setup for verification.
        Result::Ok(())
    }

    /// Tidyup function called during cleanup after delivery attempts.
    ///
    /// Called after delivery processing is complete for a set of addresses.
    /// Used to release resources such as database connections or file handles.
    /// The default implementation is a no-op.
    ///
    /// Replaces C: `void (*tidyup)(transport_instance *)`
    /// (structs.h line 256-257).
    ///
    /// # Arguments
    ///
    /// - `config` — The transport instance configuration
    fn tidyup(&self, _config: &TransportInstanceConfig) {
        // Default no-op — most transports don't need tidyup.
    }

    /// Close down a passed SMTP channel.
    ///
    /// Primarily used by the SMTP transport to properly shut down an SMTP
    /// connection that was passed to it for delivery. The smtp transport
    /// sends QUIT and closes the socket. Other transports typically don't
    /// need this. The default implementation is a no-op.
    ///
    /// Replaces C: `void (*closedown)(transport_instance *)`
    /// (structs.h line 258-259).
    ///
    /// # Arguments
    ///
    /// - `config` — The transport instance configuration
    fn closedown(&self, _config: &TransportInstanceConfig) {
        // Default no-op — only the SMTP transport uses this.
    }

    /// Whether this is a local transport (as opposed to remote).
    ///
    /// Local transports (appendfile, pipe, autoreply) deliver to the local
    /// filesystem or run local commands. Remote transports (smtp, lmtp)
    /// connect to other hosts over the network.
    ///
    /// This distinction affects:
    /// - Default `retry_use_local_part` behavior (`true` for local, `false`
    ///   for remote)
    /// - Which config options are meaningful (e.g., `home_dir` for local,
    ///   `multi_domain` for remote)
    /// - Delivery parallelism strategies
    ///
    /// Replaces C: `BOOL local` field in `transport_info`
    /// (structs.h line 260).
    fn is_local(&self) -> bool;

    /// Driver name for identification and logging.
    ///
    /// Returns the canonical name of this transport driver (e.g.,
    /// `"appendfile"`, `"smtp"`, `"pipe"`, `"lmtp"`, `"autoreply"`,
    /// `"queuefile"`). Used for:
    /// - Configuration file `driver = <name>` matching
    /// - Log output identification
    /// - `-bP` config printing
    fn driver_name(&self) -> &str;
}

// =============================================================================
// TransportDriverFactory
// =============================================================================

/// Factory for creating `TransportDriver` instances.
///
/// Each transport driver implementation registers a `TransportDriverFactory`
/// via `inventory::submit!` during compilation. At runtime, the
/// `DriverRegistry` collects all registered factories and uses them to
/// instantiate driver trait objects when processing the configuration file.
///
/// This replaces the C pattern of statically linking `transport_info` structs
/// into a global linked list in `drtables.c` (lines 26-28:
/// `transport_info * transports_available = NULL;`).
///
/// # Examples
///
/// ```ignore
/// use exim_drivers::transport_driver::{
///     TransportDriverFactory, TransportDriver, TransportInstanceConfig,
///     TransportResult,
/// };
/// use exim_drivers::DriverError;
///
/// #[derive(Debug)]
/// struct MyTransport;
///
/// impl TransportDriver for MyTransport {
///     fn transport_entry(
///         &self,
///         _config: &TransportInstanceConfig,
///         _address: &str,
///     ) -> Result<TransportResult, DriverError> {
///         Ok(TransportResult::Ok)
///     }
///     fn is_local(&self) -> bool { true }
///     fn driver_name(&self) -> &str { "my_transport" }
/// }
///
/// inventory::submit! {
///     TransportDriverFactory {
///         name: "my_transport",
///         create: || Box::new(MyTransport),
///         is_local: true,
///         avail_string: None,
///     }
/// }
/// ```
pub struct TransportDriverFactory {
    /// Name of the transport driver (e.g., `"appendfile"`, `"smtp"`, `"pipe"`,
    /// `"lmtp"`, `"autoreply"`, `"queuefile"`).
    ///
    /// Must match the `driver = <name>` directive in the Exim configuration
    /// file. This name is used for registry lookup during config parsing.
    /// C: `driver_info.driver_name` (structs.h line 155).
    pub name: &'static str,

    /// Factory function that creates a new transport driver trait object.
    ///
    /// Called when the configuration parser encounters a transport section
    /// with `driver = <name>` matching this factory's name.
    /// C: replaced the combined `init()` + struct creation in `drtables.c`.
    pub create: fn() -> Box<dyn TransportDriver>,

    /// Whether this transport is local (as opposed to remote).
    ///
    /// Cached here for registry queries before a driver instance is created.
    /// C: `transport_info.local` (structs.h line 260).
    pub is_local: bool,

    /// Optional display string shown in `-bV` version output.
    ///
    /// When set, this string is displayed instead of the driver name in
    /// version information output. Used for dynamically loaded transports.
    /// C: `driver_info.avail_string` (structs.h line 156).
    pub avail_string: Option<&'static str>,
}

// Implement Debug manually since function pointers don't implement Debug.
impl fmt::Debug for TransportDriverFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransportDriverFactory")
            .field("name", &self.name)
            .field("is_local", &self.is_local)
            .field("avail_string", &self.avail_string)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for TransportDriverFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.avail_string {
            Some(s) => write!(f, "{s}"),
            None => write!(f, "{}", self.name),
        }
    }
}

// NOTE: The `inventory::collect!(TransportDriverFactory)` macro is called in
// `registry.rs` to avoid duplicate collection declarations. Transport driver
// implementations register via `inventory::submit!` and the registry module
// handles collection.

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // TransportResult tests
    // =========================================================================

    #[test]
    fn transport_result_ok_properties() {
        let result = TransportResult::Ok;
        assert!(result.is_ok());
        assert!(result.is_success());
        assert!(!result.is_failure());
        assert!(!result.is_deferred());
        assert!(!result.is_failed());
        assert!(!result.is_error());
        assert!(result.message().is_none());
    }

    #[test]
    fn transport_result_deferred_properties() {
        let result = TransportResult::Deferred {
            message: Some("connection timed out".to_string()),
            errno: Some(110),
        };
        assert!(!result.is_ok());
        assert!(!result.is_success());
        assert!(result.is_failure());
        assert!(result.is_deferred());
        assert!(!result.is_failed());
        assert!(!result.is_error());
        assert_eq!(result.message(), Some("connection timed out"));
    }

    #[test]
    fn transport_result_deferred_no_message() {
        let result = TransportResult::Deferred {
            message: None,
            errno: None,
        };
        assert!(result.is_deferred());
        assert!(result.message().is_none());
    }

    #[test]
    fn transport_result_failed_properties() {
        let result = TransportResult::Failed {
            message: Some("user unknown".to_string()),
        };
        assert!(!result.is_ok());
        assert!(result.is_failure());
        assert!(result.is_failed());
        assert!(!result.is_deferred());
        assert!(!result.is_error());
        assert_eq!(result.message(), Some("user unknown"));
    }

    #[test]
    fn transport_result_failed_no_message() {
        let result = TransportResult::Failed { message: None };
        assert!(result.is_failed());
        assert!(result.message().is_none());
    }

    #[test]
    fn transport_result_error_properties() {
        let result = TransportResult::Error {
            message: "internal error".to_string(),
        };
        assert!(!result.is_ok());
        assert!(result.is_failure());
        assert!(result.is_error());
        assert!(!result.is_deferred());
        assert!(!result.is_failed());
        assert_eq!(result.message(), Some("internal error"));
    }

    #[test]
    fn transport_result_display() {
        assert_eq!(format!("{}", TransportResult::Ok), "OK");

        let deferred = TransportResult::Deferred {
            message: Some("timeout".to_string()),
            errno: Some(110),
        };
        assert_eq!(format!("{deferred}"), "DEFERRED: timeout (errno=110)");

        let deferred_no_info = TransportResult::Deferred {
            message: None,
            errno: None,
        };
        assert_eq!(format!("{deferred_no_info}"), "DEFERRED");

        let failed = TransportResult::Failed {
            message: Some("rejected".to_string()),
        };
        assert_eq!(format!("{failed}"), "FAILED: rejected");

        let error = TransportResult::Error {
            message: "panic".to_string(),
        };
        assert_eq!(format!("{error}"), "ERROR: panic");
    }

    #[test]
    fn transport_result_equality() {
        assert_eq!(TransportResult::Ok, TransportResult::Ok);
        assert_ne!(
            TransportResult::Ok,
            TransportResult::Failed { message: None }
        );

        let d1 = TransportResult::Deferred {
            message: Some("a".to_string()),
            errno: Some(1),
        };
        let d2 = TransportResult::Deferred {
            message: Some("a".to_string()),
            errno: Some(1),
        };
        assert_eq!(d1, d2);
    }

    #[test]
    fn transport_result_clone() {
        let original = TransportResult::Deferred {
            message: Some("test".to_string()),
            errno: Some(42),
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    // =========================================================================
    // TransportInstanceConfig tests
    // =========================================================================

    #[test]
    fn config_default_values() {
        let config = TransportInstanceConfig::default();
        assert!(config.name.is_empty());
        assert!(config.driver_name.is_empty());
        assert!(config.srcfile.is_none());
        assert!(config.srcline.is_none());
        assert_eq!(config.batch_max, 1);
        assert!(config.batch_id.is_none());
        assert!(config.home_dir.is_none());
        assert!(config.current_dir.is_none());
        assert!(!config.multi_domain);
        assert!(!config.overrides_hosts);
        assert_eq!(config.connection_max_messages, 0);
        assert!(!config.deliver_as_creator);
        assert!(!config.disable_logging);
        assert!(!config.initgroups);
        assert!(!config.uid_set);
        assert!(!config.gid_set);
        assert_eq!(config.uid, 0);
        assert_eq!(config.gid, 0);
        assert!(!config.body_only);
        assert!(!config.delivery_date_add);
        assert!(!config.envelope_to_add);
        assert!(!config.headers_only);
        assert!(!config.rcpt_include_affixes);
        assert!(!config.return_path_add);
        assert!(!config.return_output);
        assert!(!config.return_fail_output);
        assert!(!config.log_output);
        assert!(!config.log_fail_output);
        assert!(!config.log_defer_output);
        assert!(!config.retry_use_local_part);
        assert!(config.event_action.is_none());
        assert_eq!(config.filter_timeout, 300);
    }

    #[test]
    fn config_new_constructor() {
        let config = TransportInstanceConfig::new("local_delivery", "appendfile");
        assert_eq!(config.name, "local_delivery");
        assert_eq!(config.driver_name, "appendfile");
        assert_eq!(config.batch_max, 1);
        assert_eq!(config.filter_timeout, 300);
    }

    #[test]
    fn config_with_source() {
        let config =
            TransportInstanceConfig::with_source("remote_smtp", "smtp", "/etc/exim/configure", 42);
        assert_eq!(config.name, "remote_smtp");
        assert_eq!(config.driver_name, "smtp");
        assert_eq!(config.srcfile, Some("/etc/exim/configure".to_string()));
        assert_eq!(config.srcline, Some(42));
    }

    #[test]
    fn config_source_location_full() {
        let config =
            TransportInstanceConfig::with_source("test", "pipe", "/etc/exim/configure", 100);
        assert_eq!(config.source_location(), "/etc/exim/configure:100");
    }

    #[test]
    fn config_source_location_unknown() {
        let config = TransportInstanceConfig::new("test", "pipe");
        assert_eq!(config.source_location(), "<unknown>");
    }

    #[test]
    fn config_set_and_get_options() {
        #[derive(Debug)]
        struct TestOptions {
            value: i32,
        }

        let mut config = TransportInstanceConfig::new("test", "test_driver");
        config.set_options(TestOptions { value: 42 });

        let opts = config.options_as::<TestOptions>();
        assert!(opts.is_some());
        assert_eq!(opts.unwrap().value, 42);
    }

    #[test]
    fn config_options_wrong_type_returns_none() {
        let config = TransportInstanceConfig::new("test", "test_driver");
        let opts = config.options_as::<String>();
        assert!(opts.is_none());
    }

    #[test]
    fn config_display() {
        let config = TransportInstanceConfig::new("remote_smtp", "smtp");
        let display = format!("{config}");
        assert_eq!(display, "transport \"remote_smtp\" (driver=smtp)");
    }

    #[test]
    fn config_debug() {
        let config = TransportInstanceConfig::new("test", "pipe");
        let debug = format!("{config:?}");
        assert!(debug.contains("TransportInstanceConfig"));
        assert!(debug.contains("test"));
        assert!(debug.contains("pipe"));
    }

    // =========================================================================
    // TransportDriver trait object tests
    // =========================================================================

    /// Minimal test transport implementation for trait validation.
    #[derive(Debug)]
    struct TestTransport {
        local: bool,
    }

    impl TransportDriver for TestTransport {
        fn transport_entry(
            &self,
            _config: &TransportInstanceConfig,
            _address: &str,
        ) -> Result<TransportResult, DriverError> {
            Result::Ok(TransportResult::Ok)
        }

        fn is_local(&self) -> bool {
            self.local
        }

        fn driver_name(&self) -> &str {
            "test_transport"
        }
    }

    #[test]
    fn trait_object_creation() {
        let transport: Box<dyn TransportDriver> = Box::new(TestTransport { local: true });
        assert!(transport.is_local());
        assert_eq!(transport.driver_name(), "test_transport");
    }

    #[test]
    fn trait_transport_entry_call() {
        let transport = TestTransport { local: false };
        let config = TransportInstanceConfig::new("test", "test_transport");
        let result = transport.transport_entry(&config, "user@example.com");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TransportResult::Ok);
    }

    #[test]
    fn trait_default_setup() {
        let transport = TestTransport { local: true };
        let config = TransportInstanceConfig::new("test", "test_transport");
        let result = transport.setup(&config, "user@example.com");
        assert!(result.is_ok());
    }

    #[test]
    fn trait_default_tidyup() {
        let transport = TestTransport { local: true };
        let config = TransportInstanceConfig::new("test", "test_transport");
        // Should not panic — tidyup is a no-op by default.
        transport.tidyup(&config);
    }

    #[test]
    fn trait_default_closedown() {
        let transport = TestTransport { local: false };
        let config = TransportInstanceConfig::new("test", "test_transport");
        // Should not panic — closedown is a no-op by default.
        transport.closedown(&config);
    }

    #[test]
    fn trait_is_local_classification() {
        let local = TestTransport { local: true };
        let remote = TestTransport { local: false };
        assert!(local.is_local());
        assert!(!remote.is_local());
    }

    // =========================================================================
    // TransportDriverFactory tests
    // =========================================================================

    #[test]
    fn factory_creation() {
        let factory = TransportDriverFactory {
            name: "test",
            create: || Box::new(TestTransport { local: true }),
            is_local: true,
            avail_string: None,
        };
        assert_eq!(factory.name, "test");
        assert!(factory.is_local);
        assert!(factory.avail_string.is_none());
    }

    #[test]
    fn factory_creates_driver() {
        let factory = TransportDriverFactory {
            name: "test",
            create: || Box::new(TestTransport { local: false }),
            is_local: false,
            avail_string: Some("test (custom)"),
        };
        let driver = (factory.create)();
        assert!(!driver.is_local());
        assert_eq!(driver.driver_name(), "test_transport");
    }

    #[test]
    fn factory_debug() {
        let factory = TransportDriverFactory {
            name: "smtp",
            create: || Box::new(TestTransport { local: false }),
            is_local: false,
            avail_string: None,
        };
        let debug = format!("{factory:?}");
        assert!(debug.contains("TransportDriverFactory"));
        assert!(debug.contains("smtp"));
    }

    #[test]
    fn factory_display_with_avail_string() {
        let factory = TransportDriverFactory {
            name: "smtp",
            create: || Box::new(TestTransport { local: false }),
            is_local: false,
            avail_string: Some("smtp (built-in)"),
        };
        assert_eq!(format!("{factory}"), "smtp (built-in)");
    }

    #[test]
    fn factory_display_without_avail_string() {
        let factory = TransportDriverFactory {
            name: "pipe",
            create: || Box::new(TestTransport { local: true }),
            is_local: true,
            avail_string: None,
        };
        assert_eq!(format!("{factory}"), "pipe");
    }

    #[test]
    fn inventory_iter_compiles() {
        // Verify that inventory::iter works for TransportDriverFactory.
        // In a test context with no submitted factories, the iterator is empty.
        let count = inventory::iter::<TransportDriverFactory>
            .into_iter()
            .count();
        // We don't submit any factories in this test module, so count is 0.
        assert_eq!(count, 0);
    }
}
