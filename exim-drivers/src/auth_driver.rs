// =============================================================================
// exim-drivers/src/auth_driver.rs — AuthDriver Trait Definition
// =============================================================================
//
// Defines the `AuthDriver` trait that replaces the C `auth_info` struct
// inheritance pattern for authenticator drivers (structs.h lines 418-433).
//
// Each auth mechanism (CRAM-MD5, PLAIN, Dovecot, etc.) implements this trait.
// Drivers are registered at compile time via `inventory::submit!`.
//
// This file contains ZERO unsafe code (per AAP §0.7.2).

use crate::DriverError;

// =============================================================================
// Auth Instance Config
// =============================================================================

/// Configuration for an auth driver instance, from Exim config file.
///
/// Replaces C `auth_instance` struct fields (structs.h lines 398-412):
/// ```c
/// typedef struct auth_instance {
///   driver_instance drinst;
///   uschar *advertise_condition;
///   uschar *client_condition;
///   uschar *public_name;
///   uschar *set_id;
///   uschar *set_client_id;
///   uschar *mail_auth_condition;
///   uschar *server_debug_string;
///   uschar *server_condition;
///   BOOL    client;
///   BOOL    server;
///   BOOL    advertised;
/// } auth_instance;
/// ```
#[derive(Debug)]
pub struct AuthInstanceConfig {
    /// Instance name from config.
    pub name: String,
    /// Driver name (e.g., "cram_md5", "plaintext", "dovecot").
    pub driver_name: String,
    /// Advertised SASL mechanism name (e.g., "PLAIN", "CRAM-MD5", "LOGIN").
    pub public_name: String,
    /// Condition for advertising this mechanism (expandable string).
    pub advertise_condition: Option<String>,
    /// Should the client try this mechanism? (expandable condition).
    pub client_condition: Option<String>,
    /// String to set as authenticated identity on server side.
    pub set_id: Option<String>,
    /// String to set as client authenticated identity.
    pub set_client_id: Option<String>,
    /// Condition for AUTH parameter on MAIL FROM command.
    pub mail_auth_condition: Option<String>,
    /// Debug string for this driver.
    pub server_debug_string: Option<String>,
    /// Server authorization condition (expandable).
    pub server_condition: Option<String>,
    /// Whether client-side options are configured.
    pub client: bool,
    /// Whether server-side options are configured.
    pub server: bool,
    /// Whether this mechanism has been advertised in this session.
    pub advertised: bool,
    /// Config source file for error reporting.
    pub srcfile: Option<String>,
    /// Config source line for error reporting.
    pub srcline: Option<i32>,
    /// Driver-specific options (opaque to the framework).
    pub options: Box<dyn std::any::Any + Send + Sync>,
}

// =============================================================================
// Auth Result Enums
// =============================================================================

/// Result of server-side authentication attempt.
///
/// Maps to C return codes from `auth_*_server()` functions:
///   - OK (0) = authenticated
///   - FAIL (2) = authentication failed
///   - DEFER (1) = temporary problem
///   - ERROR (3) = internal error
///   - CANCELLED = client cancelled
///   - UNEXPECTED = unexpected data received
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthServerResult {
    /// Authentication succeeded.
    Authenticated,
    /// Authentication failed (wrong credentials).
    Failed,
    /// Temporary problem — try again later.
    Deferred,
    /// Internal error during authentication.
    Error,
    /// Client cancelled the authentication exchange.
    Cancelled,
    /// Unexpected data received from client.
    Unexpected,
}

/// Result of client-side authentication attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthClientResult {
    /// Authentication succeeded.
    Authenticated,
    /// Authentication failed.
    Failed,
    /// Temporary problem — try again later.
    Deferred,
    /// Internal error during authentication.
    Error,
    /// Authentication exchange was cancelled.
    Cancelled,
}

// =============================================================================
// AuthDriver Trait
// =============================================================================

/// Trait for authentication driver implementations.
///
/// Replaces C `auth_info` struct function pointers (structs.h lines 418-433):
/// ```c
/// typedef struct auth_info {
///   driver_info drinfo;
///   int (*servercode)(auth_instance *, uschar *);
///   int (*clientcode)(auth_instance *, void *, int, uschar *, int);
///   gstring * (*version_report)(gstring *);
///   void (*macros_create)(void);
/// } auth_info;
/// ```
///
/// Each authenticator (CRAM-MD5, PLAIN, Dovecot, etc.) implements this trait.
/// Drivers are registered at compile time via `inventory::submit!`.
pub trait AuthDriver: Send + Sync + std::fmt::Debug {
    /// Server-side authentication processing.
    ///
    /// Replaces C: `int (*servercode)(auth_instance *, uschar *)`.
    ///
    /// # Arguments
    /// - `config` — The auth instance configuration.
    /// - `initial_data` — The initial AUTH command data (after the mechanism name).
    ///
    /// # Returns
    /// `AuthServerResult` indicating the outcome of the authentication attempt.
    fn server(
        &self,
        config: &AuthInstanceConfig,
        initial_data: &str,
    ) -> Result<AuthServerResult, DriverError>;

    /// Client-side authentication processing.
    ///
    /// Replaces C: `int (*clientcode)(auth_instance *, void *, int, uschar *, int)`.
    ///
    /// # Arguments
    /// - `config` — The auth instance configuration.
    /// - `smtp_context` — Opaque SMTP connection context (replaces C `void*`).
    /// - `timeout` — Command timeout in seconds.
    ///
    /// # Returns
    /// `AuthClientResult` indicating the outcome of the authentication attempt.
    fn client(
        &self,
        config: &AuthInstanceConfig,
        smtp_context: &mut dyn std::any::Any,
        timeout: i32,
    ) -> Result<AuthClientResult, DriverError>;

    /// Check server condition.
    ///
    /// Replaces C `auth_check_serv_cond()` from `auths/check_serv_cond.c`.
    fn server_condition(&self, config: &AuthInstanceConfig) -> Result<bool, DriverError>;

    /// Diagnostic version reporting.
    ///
    /// Replaces C: `gstring * (*version_report)(gstring *)`.
    fn version_report(&self) -> Option<String> {
        None
    }

    /// Create feature macros for this auth mechanism.
    ///
    /// Replaces C: `void (*macros_create)(void)`.
    /// Returns a list of (name, value) macro pairs.
    fn macros_create(&self) -> Vec<(String, String)> {
        Vec::new()
    }

    /// Driver name for identification (e.g., "cram_md5", "plaintext", "dovecot").
    fn driver_name(&self) -> &str;
}

// =============================================================================
// AuthDriverFactory
// =============================================================================

/// Factory for creating `AuthDriver` instances. Registered via `inventory::submit!`.
///
/// Each auth driver module (cram_md5, plaintext, etc.) submits one of these.
pub struct AuthDriverFactory {
    /// Name of the auth mechanism (e.g., "cram_md5", "plaintext", "dovecot").
    pub name: &'static str,
    /// Factory function that creates a new auth driver instance.
    pub create: fn() -> Box<dyn AuthDriver>,
    /// Optional display string (replaces C `driver_info.avail_string`).
    pub avail_string: Option<&'static str>,
}
