#![forbid(unsafe_code)]
// =============================================================================
// exim-drivers — Trait-Based Driver System for Exim MTA
// =============================================================================
//
// This crate is the foundational driver abstraction layer for the Exim MTA Rust
// rewrite. It replaces the C `drtables.c` registration machinery and the
// `driver_info` struct inheritance pattern from `structs.h` (lines 153-165) with
// Rust trait-based polymorphism and `inventory`-based compile-time registration.
//
// ALL driver implementation crates (exim-auths, exim-routers, exim-transports,
// exim-lookups, exim-miscmods) depend on this crate for trait definitions and
// compile-time registration via `inventory::submit!`.
//
// Architecture:
//   - `AuthDriver` trait      → replaces C `auth_info` function pointers
//   - `RouterDriver` trait    → replaces C `router_info` function pointers
//   - `TransportDriver` trait → replaces C `transport_info` function pointers
//   - `LookupDriver` trait    → replaces C `lookup_info` function pointers (lookupapi.h)
//   - `DriverRegistry`        → replaces C global linked lists and tree from drtables.c
//
// Memory safety: This crate contains ZERO unsafe code (per AAP §0.7.2).

// =============================================================================
// Module Declarations
// =============================================================================
// Five submodules provide the four driver traits and the registry.

/// Authentication driver trait definitions.
/// Replaces C `auth_info` struct and function pointers from `structs.h` lines 418-433.
pub mod auth_driver;

/// Router driver trait definitions.
/// Replaces C `router_info` struct and function pointers from `structs.h` lines 372-387.
pub mod router_driver;

/// Transport driver trait definitions.
/// Replaces C `transport_info` struct and function pointers from `structs.h` lines 250-261.
pub mod transport_driver;

/// Lookup driver trait definitions.
/// Replaces C `lookup_info` struct and function pointers from `lookupapi.h` lines 20-58.
pub mod lookup_driver;

/// Compile-time driver registration via `inventory` crate.
/// Replaces C `drtables.c` linked-list and tree-based registration.
pub mod registry;

// =============================================================================
// Public Re-exports
// =============================================================================
// Re-export all 4 driver traits and the registry at the crate root for ergonomic use.
// Users can write `use exim_drivers::AuthDriver;` instead of
// `use exim_drivers::auth_driver::AuthDriver;`.

pub use auth_driver::AuthDriver;
pub use lookup_driver::LookupDriver;
pub use registry::DriverRegistry;
pub use router_driver::RouterDriver;
pub use transport_driver::TransportDriver;

// =============================================================================
// Common Driver Error Types
// =============================================================================

use thiserror::Error;

/// Common error type for all driver operations across the Exim MTA.
///
/// Replaces ad-hoc error string handling in C `drtables.c` and various driver
/// source files. Each variant maps to a category of failure that can occur
/// during driver resolution, initialization, or execution.
///
/// # Variants
///
/// - `NotFound` — The named driver does not exist in the registry.
/// - `InitFailed` — Driver initialization (the C `init()` entry point) failed.
/// - `ExecutionFailed` — A driver operation (route, transport, auth, lookup) failed.
/// - `ConfigError` — The driver's configuration is invalid.
/// - `TempFail` — A temporary failure occurred; the operation may succeed on retry.
#[derive(Debug, Error)]
pub enum DriverError {
    /// A driver with the specified name was not found in the registry.
    /// Replaces C pattern: log_write(0, LOG_MAIN|LOG_PANIC, "unknown driver ...")
    #[error("driver not found: {name}")]
    NotFound {
        /// The name that was looked up in the driver registry.
        name: String,
    },

    /// Driver initialization failed during setup.
    /// Replaces C pattern: failure in the `init()` function pointer of `driver_info`.
    #[error("driver initialization failed: {0}")]
    InitFailed(String),

    /// Driver execution failed during an operation (route, transport, auth, lookup).
    /// Replaces C pattern: return codes indicating failure from driver entry points.
    #[error("driver execution failed: {0}")]
    ExecutionFailed(String),

    /// Driver configuration is invalid or missing required options.
    /// Replaces C pattern: errors during `readconf.c` option processing.
    #[error("configuration error: {0}")]
    ConfigError(String),

    /// A temporary failure occurred; the operation should be retried.
    /// Replaces C pattern: DEFER return code from driver entry points.
    #[error("temporary failure: {0}")]
    TempFail(String),
}

// =============================================================================
// Common Driver Result Enum
// =============================================================================

/// Common result codes mirroring C Exim's delivery result values.
///
/// These correspond to the C macros defined in `exim.h`:
///   - `OK`      = 0 — Operation succeeded
///   - `DEFER`   = 1 — Temporary failure, retry later
///   - `FAIL`    = 2 — Permanent failure
///   - `ERROR`   = 3 — Internal error
///   - `DECLINE` = 4 — Driver does not handle this item, try next
///   - `PASS`    = 5 — Pass to next driver in chain (router-specific)
///
/// This enum is used as a general-purpose result code across different driver
/// types. Individual driver traits may define more specific result enums
/// (e.g., `RouterResult`, `TransportResult`, `AuthServerResult`) that map
/// to and from these codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DriverResult {
    /// Operation completed successfully.
    /// C: `OK` (0)
    Ok,

    /// Temporary failure — the operation should be retried later.
    /// C: `DEFER` (1)
    Defer,

    /// Permanent failure — the operation will not succeed on retry.
    /// C: `FAIL` (2)
    Fail,

    /// Internal error occurred during the operation.
    /// C: `ERROR` (3)
    Error,

    /// Driver declined to handle this item — pass to next driver.
    /// C: `DECLINE` (4)
    Decline,

    /// Pass to next driver in chain (primarily used by routers).
    /// C: `PASS` (5)
    Pass,
}

impl DriverResult {
    /// Convert a C-style integer result code to a `DriverResult`.
    ///
    /// Maps the traditional C Exim integer return codes:
    ///   0 → Ok, 1 → Defer, 2 → Fail, 3 → Error, 4 → Decline, 5 → Pass
    ///
    /// Returns `None` for unrecognized codes.
    pub fn from_c_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::Ok),
            1 => Some(Self::Defer),
            2 => Some(Self::Fail),
            3 => Some(Self::Error),
            4 => Some(Self::Decline),
            5 => Some(Self::Pass),
            _ => None,
        }
    }

    /// Convert this `DriverResult` to the corresponding C-style integer code.
    ///
    /// Returns the traditional C Exim integer return code:
    ///   Ok → 0, Defer → 1, Fail → 2, Error → 3, Decline → 4, Pass → 5
    pub fn to_c_code(self) -> i32 {
        match self {
            Self::Ok => 0,
            Self::Defer => 1,
            Self::Fail => 2,
            Self::Error => 3,
            Self::Decline => 4,
            Self::Pass => 5,
        }
    }

    /// Returns `true` if the result indicates success.
    pub fn is_success(self) -> bool {
        self == Self::Ok
    }

    /// Returns `true` if the result indicates a temporary failure.
    pub fn is_temporary(self) -> bool {
        self == Self::Defer
    }

    /// Returns `true` if the result indicates a permanent failure.
    pub fn is_permanent_failure(self) -> bool {
        matches!(self, Self::Fail | Self::Error)
    }
}

impl std::fmt::Display for DriverResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => write!(f, "OK"),
            Self::Defer => write!(f, "DEFER"),
            Self::Fail => write!(f, "FAIL"),
            Self::Error => write!(f, "ERROR"),
            Self::Decline => write!(f, "DECLINE"),
            Self::Pass => write!(f, "PASS"),
        }
    }
}

// =============================================================================
// Common Driver Instance Base
// =============================================================================

/// Base fields for all driver instances — replaces C `driver_instance` struct.
///
/// In C (structs.h lines 142-151), this was:
/// ```c
/// typedef struct driver_instance {
///   void   *next;
///   uschar *name;
///   void   *info;
///   void   *options_block;
///   uschar *driver_name;
///   const uschar *srcfile;
///   int     srcline;
/// } driver_instance;
/// ```
///
/// In Rust, the linked-list `next` pointer is replaced by collection ownership,
/// the `info` pointer is replaced by the trait object itself, and the
/// `options_block` is replaced by typed driver-specific configuration structs.
///
/// The `name`, `driver_name`, `srcfile`, and `srcline` fields are preserved
/// for configuration file error reporting and driver identification.
#[derive(Debug, Clone)]
pub struct DriverInstanceBase {
    /// Instance name from the configuration file.
    /// This is the user-assigned name (e.g., "local_delivery" for a transport,
    /// "dnslookup" for a router instance).
    pub name: String,

    /// Name of the driver type (e.g., "appendfile", "smtp", "accept").
    /// Used to look up the driver implementation in the registry.
    pub driver_name: String,

    /// Configuration source file path for error reporting.
    /// `None` if the instance was created programmatically rather than from config.
    pub srcfile: Option<String>,

    /// Configuration source line number for error reporting.
    /// `None` if the instance was created programmatically rather than from config.
    pub srcline: Option<i32>,
}

impl DriverInstanceBase {
    /// Create a new `DriverInstanceBase` with the given instance name and driver name.
    ///
    /// Config source information (`srcfile`/`srcline`) defaults to `None` and
    /// can be set after construction during configuration file parsing.
    pub fn new(name: impl Into<String>, driver_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            driver_name: driver_name.into(),
            srcfile: None,
            srcline: None,
        }
    }

    /// Create a new `DriverInstanceBase` with full config source information.
    ///
    /// Used during configuration file parsing when the source file and line
    /// number are known.
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
        }
    }

    /// Format the source location for error messages.
    ///
    /// Returns a string like `"filename:42"` or `"<unknown>"` if no source
    /// information is available.
    pub fn source_location(&self) -> String {
        match (&self.srcfile, self.srcline) {
            (Some(file), Some(line)) => format!("{file}:{line}"),
            (Some(file), None) => file.clone(),
            _ => "<unknown>".to_string(),
        }
    }
}

impl std::fmt::Display for DriverInstanceBase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}({})", self.name, self.driver_name)
    }
}

// =============================================================================
// Common Driver Info Base
// =============================================================================

/// Base metadata for a driver type — replaces C `driver_info` struct.
///
/// In C (structs.h lines 153-165), this was:
/// ```c
/// typedef struct driver_info {
///   struct driver_info *next;
///   uschar *driver_name;
///   uschar *avail_string;
///   optionlist *options;
///   int *options_count;
///   void *options_block;
///   int options_len;
///   void (*init)(struct driver_instance *);
///   uint dyn_magic;
/// } driver_info;
/// ```
///
/// In Rust, the linked-list traversal (`next` pointer) is replaced by
/// `inventory`-based compile-time registration. The function pointers
/// (`init`, and per-type entry points) are replaced by trait methods.
/// The `options`/`options_block` are replaced by typed Rust structs
/// with `serde` deserialization. The `dyn_magic` field is not needed
/// since Rust's type system prevents ABI mismatches at compile time.
///
/// Only `driver_name` and `avail_string` are retained as static metadata.
#[derive(Debug, Clone, Copy)]
pub struct DriverInfoBase {
    /// Name of the driver type (e.g., "appendfile", "smtp", "cram_md5", "lsearch").
    /// Used for matching against configuration file `driver = <name>` directives.
    pub driver_name: &'static str,

    /// Optional display string shown in `-bV` version output.
    /// If `None`, the `driver_name` is used instead.
    /// Replaces C `avail_string` field — when set, this is displayed in
    /// `auth_show_supported()` / `route_show_supported()` etc. instead of
    /// the raw driver name.
    pub avail_string: Option<&'static str>,
}

impl DriverInfoBase {
    /// Create a new `DriverInfoBase` with the given driver name and no
    /// custom display string.
    pub const fn new(driver_name: &'static str) -> Self {
        Self {
            driver_name,
            avail_string: None,
        }
    }

    /// Create a new `DriverInfoBase` with a custom display string.
    pub const fn with_avail_string(driver_name: &'static str, avail_string: &'static str) -> Self {
        Self {
            driver_name,
            avail_string: Some(avail_string),
        }
    }

    /// Returns the display name for this driver — `avail_string` if set,
    /// otherwise `driver_name`.
    pub const fn display_name(&self) -> &'static str {
        match self.avail_string {
            Some(s) => s,
            None => self.driver_name,
        }
    }
}

impl std::fmt::Display for DriverInfoBase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_driver_result_c_code_roundtrip() {
        for code in 0..=5 {
            let result = DriverResult::from_c_code(code).unwrap();
            assert_eq!(result.to_c_code(), code);
        }
    }

    #[test]
    fn test_driver_result_from_invalid_code() {
        assert!(DriverResult::from_c_code(-1).is_none());
        assert!(DriverResult::from_c_code(6).is_none());
        assert!(DriverResult::from_c_code(100).is_none());
    }

    #[test]
    fn test_driver_result_properties() {
        assert!(DriverResult::Ok.is_success());
        assert!(!DriverResult::Fail.is_success());

        assert!(DriverResult::Defer.is_temporary());
        assert!(!DriverResult::Ok.is_temporary());

        assert!(DriverResult::Fail.is_permanent_failure());
        assert!(DriverResult::Error.is_permanent_failure());
        assert!(!DriverResult::Defer.is_permanent_failure());
        assert!(!DriverResult::Ok.is_permanent_failure());
    }

    #[test]
    fn test_driver_result_display() {
        assert_eq!(DriverResult::Ok.to_string(), "OK");
        assert_eq!(DriverResult::Defer.to_string(), "DEFER");
        assert_eq!(DriverResult::Fail.to_string(), "FAIL");
        assert_eq!(DriverResult::Error.to_string(), "ERROR");
        assert_eq!(DriverResult::Decline.to_string(), "DECLINE");
        assert_eq!(DriverResult::Pass.to_string(), "PASS");
    }

    #[test]
    fn test_driver_error_display() {
        let err = DriverError::NotFound {
            name: "nonexistent".to_string(),
        };
        assert_eq!(err.to_string(), "driver not found: nonexistent");

        let err = DriverError::InitFailed("bad config".to_string());
        assert_eq!(err.to_string(), "driver initialization failed: bad config");

        let err = DriverError::ExecutionFailed("timeout".to_string());
        assert_eq!(err.to_string(), "driver execution failed: timeout");

        let err = DriverError::ConfigError("missing option".to_string());
        assert_eq!(err.to_string(), "configuration error: missing option");

        let err = DriverError::TempFail("network error".to_string());
        assert_eq!(err.to_string(), "temporary failure: network error");
    }

    #[test]
    fn test_driver_instance_base_new() {
        let base = DriverInstanceBase::new("my_router", "dnslookup");
        assert_eq!(base.name, "my_router");
        assert_eq!(base.driver_name, "dnslookup");
        assert!(base.srcfile.is_none());
        assert!(base.srcline.is_none());
    }

    #[test]
    fn test_driver_instance_base_with_source() {
        let base =
            DriverInstanceBase::with_source("my_router", "dnslookup", "/etc/exim/configure", 42);
        assert_eq!(base.name, "my_router");
        assert_eq!(base.driver_name, "dnslookup");
        assert_eq!(base.srcfile.as_deref(), Some("/etc/exim/configure"));
        assert_eq!(base.srcline, Some(42));
        assert_eq!(base.source_location(), "/etc/exim/configure:42");
    }

    #[test]
    fn test_driver_instance_base_source_location_unknown() {
        let base = DriverInstanceBase::new("test", "test_driver");
        assert_eq!(base.source_location(), "<unknown>");
    }

    #[test]
    fn test_driver_instance_base_display() {
        let base = DriverInstanceBase::new("my_transport", "smtp");
        assert_eq!(base.to_string(), "my_transport(smtp)");
    }

    #[test]
    fn test_driver_info_base_new() {
        let info = DriverInfoBase::new("cram_md5");
        assert_eq!(info.driver_name, "cram_md5");
        assert!(info.avail_string.is_none());
        assert_eq!(info.display_name(), "cram_md5");
    }

    #[test]
    fn test_driver_info_base_with_avail_string() {
        let info = DriverInfoBase::with_avail_string("cram_md5", "CRAM-MD5");
        assert_eq!(info.driver_name, "cram_md5");
        assert_eq!(info.avail_string, Some("CRAM-MD5"));
        assert_eq!(info.display_name(), "CRAM-MD5");
    }

    #[test]
    fn test_driver_info_base_display() {
        let info = DriverInfoBase::new("smtp");
        assert_eq!(info.to_string(), "smtp");

        let info = DriverInfoBase::with_avail_string("smtp", "SMTP Transport");
        assert_eq!(info.to_string(), "SMTP Transport");
    }

    #[test]
    fn test_driver_result_equality() {
        assert_eq!(DriverResult::Ok, DriverResult::Ok);
        assert_ne!(DriverResult::Ok, DriverResult::Fail);
        assert_ne!(DriverResult::Defer, DriverResult::Error);
    }

    #[test]
    fn test_driver_result_clone_copy() {
        let result = DriverResult::Defer;
        let cloned = result;
        assert_eq!(result, cloned);
    }

    #[test]
    fn test_driver_instance_base_clone() {
        let base = DriverInstanceBase::with_source("router1", "accept", "/etc/exim/configure", 100);
        let cloned = base.clone();
        assert_eq!(base.name, cloned.name);
        assert_eq!(base.driver_name, cloned.driver_name);
        assert_eq!(base.srcfile, cloned.srcfile);
        assert_eq!(base.srcline, cloned.srcline);
    }

    #[test]
    fn test_driver_info_base_copy() {
        let info = DriverInfoBase::new("lsearch");
        let copied = info;
        assert_eq!(info.driver_name, copied.driver_name);
    }
}
