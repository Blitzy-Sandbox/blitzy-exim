// =============================================================================
// exim-drivers/src/auth_driver.rs — AuthDriver Trait Definition
// =============================================================================
//
// Defines the `AuthDriver` trait that replaces the C `auth_info` struct
// inheritance pattern for authenticator drivers (structs.h lines 418-433).
//
// In the C codebase, each auth mechanism (CRAM-MD5, PLAIN, Dovecot, SPA, etc.)
// provides an `auth_info` struct with function pointers for server-side auth,
// client-side auth, version reporting, and macro creation. In Rust, this becomes
// a trait (`AuthDriver`) with corresponding methods.
//
// The `auth_instance` configuration struct (structs.h lines 398-412) is replaced
// by `AuthInstanceConfig`, which captures all fields from the C struct plus the
// base `driver_instance` fields (name, driver_name, srcfile, srcline) and a
// type-erased `options` field for driver-specific configuration blocks.
//
// Drivers are registered at compile time via `inventory::submit!` and collected
// via `inventory::iter::<AuthDriverFactory>()` in the registry module.
//
// This file contains ZERO unsafe code (per AAP §0.7.2).

use std::any::Any;
use std::fmt;

use crate::DriverError;

// =============================================================================
// Auth Instance Config
// =============================================================================

/// Configuration for an auth driver instance, parsed from the Exim config file.
///
/// Replaces the C `auth_instance` struct (structs.h lines 398-412) and the
/// relevant fields from `driver_instance` (structs.h lines 142-151).
///
/// Each configured authenticator block in the Exim configuration produces one
/// `AuthInstanceConfig` instance. The `options` field holds driver-specific
/// configuration (e.g., `server_secret` for CRAM-MD5, `server_socket` for
/// Dovecot) as a type-erased `Box<dyn Any + Send + Sync>`, replacing the C
/// pattern of `void *options_block`.
///
/// # C-to-Rust Field Mapping
///
/// | C `auth_instance` field  | Rust `AuthInstanceConfig` field |
/// |--------------------------|----------------------------------|
/// | `drinst.name`            | `name`                          |
/// | `drinst.driver_name`     | `driver_name`                   |
/// | `drinst.srcfile`         | `srcfile`                       |
/// | `drinst.srcline`         | `srcline`                       |
/// | `drinst.options_block`   | `options`                       |
/// | `public_name`            | `public_name`                   |
/// | `advertise_condition`    | `advertise_condition`           |
/// | `client_condition`       | `client_condition`              |
/// | `set_id`                 | `set_id`                        |
/// | `set_client_id`          | `set_client_id`                 |
/// | `mail_auth_condition`    | `mail_auth_condition`           |
/// | `server_debug_string`    | `server_debug_string`           |
/// | `server_condition`       | `server_condition`              |
/// | `client` (BOOL)          | `client`                        |
/// | `server` (BOOL)          | `server`                        |
/// | `advertised` (BOOL)      | `advertised`                    |
#[derive(Debug)]
pub struct AuthInstanceConfig {
    /// Instance name from the configuration file.
    ///
    /// This is the user-assigned name for the authenticator block, used for
    /// identification in logging and error messages.
    /// Replaces C `driver_instance.name`.
    pub name: String,

    /// Driver name identifying the auth implementation (e.g., "cram_md5",
    /// "plaintext", "dovecot", "gsasl", "spa", "external", "tls").
    ///
    /// Used to look up the `AuthDriverFactory` in the compile-time registry.
    /// Replaces C `driver_instance.driver_name`.
    pub driver_name: String,

    /// Advertised SASL mechanism name (e.g., "PLAIN", "CRAM-MD5", "LOGIN",
    /// "EXTERNAL", "GSSAPI").
    ///
    /// This is the mechanism name advertised in SMTP EHLO AUTH= and used to
    /// match incoming AUTH commands. Replaces C `auth_instance.public_name`.
    pub public_name: String,

    /// Condition for advertising this mechanism (expandable string).
    ///
    /// When set, the string is expanded at EHLO time; the mechanism is only
    /// advertised if the expansion yields a truthy value. `None` means the
    /// mechanism is always advertised when server-side options are configured.
    /// Replaces C `auth_instance.advertise_condition`.
    pub advertise_condition: Option<String>,

    /// Condition controlling whether the client should attempt this mechanism.
    ///
    /// Expanded before client-side authentication; if it yields false, this
    /// mechanism is skipped. `None` means always attempt when client-side
    /// options are configured.
    /// Replaces C `auth_instance.client_condition`.
    pub client_condition: Option<String>,

    /// String to set as the authenticated identity on the server side.
    ///
    /// This expandable string is evaluated after successful server-side
    /// authentication. The result becomes `$authenticated_id`.
    /// Replaces C `auth_instance.set_id`.
    pub set_id: Option<String>,

    /// String to set as the client authenticated identity.
    ///
    /// Evaluated after successful client-side authentication. The result
    /// becomes the `client_authenticated_id` used in subsequent MAIL FROM.
    /// Replaces C `auth_instance.set_client_id`.
    pub set_client_id: Option<String>,

    /// Condition for accepting the AUTH parameter on MAIL FROM command.
    ///
    /// Controls whether a MAIL FROM with `AUTH=` is accepted from a client
    /// authenticating with this mechanism.
    /// Replaces C `auth_instance.mail_auth_condition`.
    pub mail_auth_condition: Option<String>,

    /// Debug string for diagnostic output when this driver processes.
    ///
    /// When set, this string is expanded and logged during server-side
    /// authentication to aid debugging.
    /// Replaces C `auth_instance.server_debug_string`.
    pub server_debug_string: Option<String>,

    /// Server authorization condition (expandable).
    ///
    /// Evaluated after the SASL exchange completes to perform authorization
    /// checks. Authentication succeeds only if this condition evaluates true.
    /// `None` means no additional authorization check.
    /// Replaces C `auth_instance.server_condition`.
    pub server_condition: Option<String>,

    /// Whether client-side options are configured for this authenticator.
    ///
    /// Set `true` when the configuration file specifies client-side options
    /// (e.g., `client_send` for plaintext, `client_secret` for CRAM-MD5).
    /// Replaces C `auth_instance.client` (BOOL).
    pub client: bool,

    /// Whether server-side options are configured for this authenticator.
    ///
    /// Set `true` when the configuration file specifies server-side options
    /// (e.g., `server_condition`, `server_prompts`).
    /// Replaces C `auth_instance.server` (BOOL).
    pub server: bool,

    /// Whether this mechanism has been advertised in the current SMTP session.
    ///
    /// Set `true` by the SMTP inbound code after including this mechanism
    /// in an AUTH= EHLO response line. Reset per-session.
    /// Replaces C `auth_instance.advertised` (BOOL).
    pub advertised: bool,

    /// Configuration source file path for error reporting.
    ///
    /// `None` if the instance was created programmatically.
    /// Replaces C `driver_instance.srcfile`.
    pub srcfile: Option<String>,

    /// Configuration source line number for error reporting.
    ///
    /// `None` if the instance was created programmatically.
    /// Replaces C `driver_instance.srcline`.
    pub srcline: Option<i32>,

    /// Driver-specific options block (opaque to the framework).
    ///
    /// Each auth driver defines its own options struct (e.g.,
    /// `auth_cram_md5_options_block`, `auth_plaintext_options_block`). The
    /// concrete type is stored here via type erasure and downcast by the
    /// driver implementation.
    /// Replaces C `driver_instance.options_block` (`void*`).
    pub options: Box<dyn Any + Send + Sync>,
}

impl AuthInstanceConfig {
    /// Create a new `AuthInstanceConfig` with required fields and sensible defaults.
    ///
    /// All optional string fields default to `None`, boolean flags default to
    /// `false`, and `options` is initialized with the provided driver-specific
    /// options block.
    ///
    /// # Arguments
    /// - `name` — Instance name from configuration.
    /// - `driver_name` — Driver implementation name (e.g., "cram_md5").
    /// - `public_name` — SASL mechanism name (e.g., "CRAM-MD5").
    /// - `options` — Driver-specific options block.
    pub fn new(
        name: impl Into<String>,
        driver_name: impl Into<String>,
        public_name: impl Into<String>,
        options: Box<dyn Any + Send + Sync>,
    ) -> Self {
        Self {
            name: name.into(),
            driver_name: driver_name.into(),
            public_name: public_name.into(),
            advertise_condition: None,
            client_condition: None,
            set_id: None,
            set_client_id: None,
            mail_auth_condition: None,
            server_debug_string: None,
            server_condition: None,
            client: false,
            server: false,
            advertised: false,
            srcfile: None,
            srcline: None,
            options,
        }
    }

    /// Set the configuration source location for error reporting.
    ///
    /// Used during configuration file parsing to record where the authenticator
    /// block was defined.
    pub fn with_source(mut self, srcfile: impl Into<String>, srcline: i32) -> Self {
        self.srcfile = Some(srcfile.into());
        self.srcline = Some(srcline);
        self
    }

    /// Format the source location for error messages.
    ///
    /// Returns a string like `"filename:42"` if both file and line are known,
    /// just the filename if only the file is known, or `"<unknown>"` if neither.
    pub fn source_location(&self) -> String {
        match (&self.srcfile, self.srcline) {
            (Some(file), Some(line)) => format!("{file}:{line}"),
            (Some(file), None) => file.clone(),
            _ => "<unknown>".to_string(),
        }
    }

    /// Downcast the driver-specific options to a concrete type.
    ///
    /// Returns `Some(&T)` if the stored options are of type `T`, `None` otherwise.
    /// This replaces the C pattern of casting `void *options_block` to the
    /// driver-specific struct pointer.
    ///
    /// # Example
    /// ```ignore
    /// if let Some(opts) = config.downcast_options::<CramMd5Options>() {
    ///     let secret = &opts.server_secret;
    /// }
    /// ```
    pub fn downcast_options<T: Any + Send + Sync>(&self) -> Option<&T> {
        self.options.downcast_ref::<T>()
    }

    /// Downcast the driver-specific options to a mutable concrete type.
    ///
    /// Returns `Some(&mut T)` if the stored options are of type `T`, `None`
    /// otherwise.
    pub fn downcast_options_mut<T: Any + Send + Sync>(&mut self) -> Option<&mut T> {
        self.options.downcast_mut::<T>()
    }

    /// Check whether this authenticator has server-side capability.
    ///
    /// Returns `true` if the `server` flag is set, indicating that server-side
    /// options were configured for this authenticator.
    pub fn is_server_enabled(&self) -> bool {
        self.server
    }

    /// Check whether this authenticator has client-side capability.
    ///
    /// Returns `true` if the `client` flag is set, indicating that client-side
    /// options were configured for this authenticator.
    pub fn is_client_enabled(&self) -> bool {
        self.client
    }
}

impl fmt::Display for AuthInstanceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "auth:{name} (driver={driver}, mechanism={public})",
            name = self.name,
            driver = self.driver_name,
            public = self.public_name,
        )
    }
}

// =============================================================================
// Auth Server Result Enum
// =============================================================================

/// Result of a server-side authentication attempt.
///
/// Maps to the C integer return codes from `auth_*_server()` functions defined
/// in each authenticator header (e.g., `cram_md5.h`, `plaintext.h`):
///
/// | C Return Code | Numeric | Rust Variant         |
/// |---------------|---------|----------------------|
/// | `OK`          | 0       | `Authenticated`      |
/// | `DEFER`       | 1       | `Deferred`           |
/// | `FAIL`        | 2       | `Failed`             |
/// | `ERROR`       | 3       | `Error`              |
/// | (custom)      | —       | `Cancelled`          |
/// | (custom)      | —       | `Unexpected`         |
///
/// `Cancelled` and `Unexpected` are Rust-side refinements that in C were
/// communicated via side effects or specific `FAIL` sub-codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthServerResult {
    /// Authentication succeeded — the client provided valid credentials.
    /// C equivalent: `OK` (0).
    Authenticated,

    /// Authentication failed — wrong credentials or policy rejection.
    /// C equivalent: `FAIL` (2).
    Failed,

    /// Temporary problem — the authentication backend is unavailable.
    /// C equivalent: `DEFER` (1).
    Deferred,

    /// Internal error during authentication processing.
    /// C equivalent: `ERROR` (3).
    Error,

    /// Client cancelled the authentication exchange (sent `*` response).
    /// In C this was a specific FAIL sub-case signaled via global state.
    Cancelled,

    /// Unexpected data received from the client during the SASL exchange.
    /// In C this was handled by returning FAIL with a log message.
    Unexpected,
}

impl AuthServerResult {
    /// Convert a C-style integer result code to an `AuthServerResult`.
    ///
    /// Maps the traditional C Exim integer return codes:
    ///   0 (OK) → Authenticated, 1 (DEFER) → Deferred,
    ///   2 (FAIL) → Failed, 3 (ERROR) → Error.
    ///
    /// Returns `None` for unrecognized codes. `Cancelled` and `Unexpected`
    /// have no direct C integer mapping.
    pub fn from_c_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::Authenticated),
            1 => Some(Self::Deferred),
            2 => Some(Self::Failed),
            3 => Some(Self::Error),
            _ => None,
        }
    }

    /// Convert this result to the corresponding C-style integer code.
    ///
    ///   Authenticated → 0 (OK), Deferred → 1 (DEFER),
    ///   Failed → 2 (FAIL), Error → 3 (ERROR),
    ///   Cancelled → 2 (FAIL), Unexpected → 2 (FAIL).
    ///
    /// Both `Cancelled` and `Unexpected` map to `FAIL` (2) in C since they
    /// are subtypes of failure.
    pub fn to_c_code(self) -> i32 {
        match self {
            Self::Authenticated => 0,
            Self::Deferred => 1,
            Self::Failed | Self::Cancelled | Self::Unexpected => 2,
            Self::Error => 3,
        }
    }

    /// Returns `true` if the authentication attempt succeeded.
    pub fn is_success(self) -> bool {
        self == Self::Authenticated
    }

    /// Returns `true` if the result indicates a temporary failure.
    pub fn is_temporary(self) -> bool {
        self == Self::Deferred
    }

    /// Returns `true` if the result indicates any kind of failure.
    pub fn is_failure(self) -> bool {
        matches!(
            self,
            Self::Failed | Self::Error | Self::Cancelled | Self::Unexpected
        )
    }
}

impl fmt::Display for AuthServerResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authenticated => write!(f, "OK"),
            Self::Failed => write!(f, "FAIL"),
            Self::Deferred => write!(f, "DEFER"),
            Self::Error => write!(f, "ERROR"),
            Self::Cancelled => write!(f, "CANCELLED"),
            Self::Unexpected => write!(f, "UNEXPECTED"),
        }
    }
}

// =============================================================================
// Auth Client Result Enum
// =============================================================================

/// Result of a client-side authentication attempt.
///
/// Maps to the C integer return codes from `auth_*_client()` functions:
///
/// | C Return Code | Numeric | Rust Variant    |
/// |---------------|---------|-----------------|
/// | `OK`          | 0       | `Authenticated` |
/// | `DEFER`       | 1       | `Deferred`      |
/// | `FAIL`        | 2       | `Failed`        |
/// | `ERROR`       | 3       | `Error`         |
/// | (custom)      | —       | `Cancelled`     |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthClientResult {
    /// Client-side authentication succeeded.
    /// C equivalent: `OK` (0).
    Authenticated,

    /// Client-side authentication failed.
    /// C equivalent: `FAIL` (2).
    Failed,

    /// Temporary problem — try again later.
    /// C equivalent: `DEFER` (1).
    Deferred,

    /// Internal error during client-side authentication.
    /// C equivalent: `ERROR` (3).
    Error,

    /// Authentication exchange was cancelled.
    /// In C this was a specific FAIL sub-case.
    Cancelled,
}

impl AuthClientResult {
    /// Convert a C-style integer result code to an `AuthClientResult`.
    ///
    /// Maps the traditional C Exim integer return codes:
    ///   0 (OK) → Authenticated, 1 (DEFER) → Deferred,
    ///   2 (FAIL) → Failed, 3 (ERROR) → Error.
    ///
    /// Returns `None` for unrecognized codes.
    pub fn from_c_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::Authenticated),
            1 => Some(Self::Deferred),
            2 => Some(Self::Failed),
            3 => Some(Self::Error),
            _ => None,
        }
    }

    /// Convert this result to the corresponding C-style integer code.
    ///
    ///   Authenticated → 0 (OK), Deferred → 1 (DEFER),
    ///   Failed → 2 (FAIL), Error → 3 (ERROR),
    ///   Cancelled → 2 (FAIL).
    pub fn to_c_code(self) -> i32 {
        match self {
            Self::Authenticated => 0,
            Self::Deferred => 1,
            Self::Failed | Self::Cancelled => 2,
            Self::Error => 3,
        }
    }

    /// Returns `true` if the client authentication succeeded.
    pub fn is_success(self) -> bool {
        self == Self::Authenticated
    }

    /// Returns `true` if the result indicates a temporary failure.
    pub fn is_temporary(self) -> bool {
        self == Self::Deferred
    }

    /// Returns `true` if the result indicates any kind of failure.
    pub fn is_failure(self) -> bool {
        matches!(self, Self::Failed | Self::Error | Self::Cancelled)
    }
}

impl fmt::Display for AuthClientResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authenticated => write!(f, "OK"),
            Self::Failed => write!(f, "FAIL"),
            Self::Deferred => write!(f, "DEFER"),
            Self::Error => write!(f, "ERROR"),
            Self::Cancelled => write!(f, "CANCELLED"),
        }
    }
}

// =============================================================================
// AuthDriver Trait
// =============================================================================

/// Trait for authentication driver implementations.
///
/// Replaces the C `auth_info` struct function pointers (structs.h lines 418-433):
///
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
/// Each authenticator (CRAM-MD5, PLAIN, Dovecot, SPA, GSASL, Heimdal GSSAPI,
/// Cyrus SASL, EXTERNAL, TLS cert) implements this trait. Drivers are registered
/// at compile time via `inventory::submit!` using `AuthDriverFactory`.
///
/// # Required Bounds
///
/// - `Send + Sync` — The driver must be safely shareable across the
///   fork-per-connection model.
/// - `Debug` — Required for diagnostic output and logging.
///
/// # Required Methods
///
/// - [`server()`](AuthDriver::server) — Server-side SASL exchange.
/// - [`client()`](AuthDriver::client) — Client-side SASL exchange.
/// - [`server_condition()`](AuthDriver::server_condition) — Server authorization check.
/// - [`driver_name()`](AuthDriver::driver_name) — Driver identification.
///
/// # Provided Methods (with defaults)
///
/// - [`version_report()`](AuthDriver::version_report) — Returns `None` by default.
/// - [`macros_create()`](AuthDriver::macros_create) — Returns empty `Vec` by default.
pub trait AuthDriver: Send + Sync + fmt::Debug {
    /// Server-side authentication processing.
    ///
    /// Replaces C function pointer: `int (*servercode)(auth_instance *, uschar *)`.
    ///
    /// Called when a client issues an SMTP `AUTH <mechanism>` command and this
    /// driver handles the named mechanism. The implementation conducts the
    /// full SASL exchange (possibly multi-step for challenge-response) and
    /// returns the outcome.
    ///
    /// # Arguments
    ///
    /// - `config` — The auth instance configuration including all options.
    /// - `initial_data` — The initial AUTH command data (after the mechanism
    ///   name). May be empty if no initial response was provided.
    ///
    /// # Returns
    ///
    /// - `Ok(AuthServerResult::Authenticated)` — SASL exchange succeeded.
    /// - `Ok(AuthServerResult::Failed)` — Client provided invalid credentials.
    /// - `Ok(AuthServerResult::Deferred)` — Temporary backend unavailability.
    /// - `Ok(AuthServerResult::Error)` — Internal processing error.
    /// - `Ok(AuthServerResult::Cancelled)` — Client sent `*` to cancel.
    /// - `Ok(AuthServerResult::Unexpected)` — Unexpected data from client.
    /// - `Err(DriverError)` — Infrastructure-level failure.
    fn server(
        &self,
        config: &AuthInstanceConfig,
        initial_data: &str,
    ) -> Result<AuthServerResult, DriverError>;

    /// Client-side authentication processing.
    ///
    /// Replaces C function pointer:
    /// `int (*clientcode)(auth_instance *, void *, int, uschar *, int)`.
    ///
    /// Called when Exim acts as an SMTP client and needs to authenticate with
    /// a remote server using this mechanism. The `smtp_context` parameter
    /// replaces the C `void*` for the SMTP connection handle containing the
    /// socket, output buffer, and input buffer.
    ///
    /// # Arguments
    ///
    /// - `config` — The auth instance configuration.
    /// - `smtp_context` — Opaque SMTP connection context (type-erased).
    ///   Implementations downcast this to their expected concrete type.
    /// - `timeout` — Command timeout in seconds.
    ///
    /// # Returns
    ///
    /// - `Ok(AuthClientResult::Authenticated)` — Successfully authenticated.
    /// - `Ok(AuthClientResult::Failed)` — Authentication was rejected.
    /// - `Ok(AuthClientResult::Deferred)` — Temporary failure.
    /// - `Ok(AuthClientResult::Error)` — Internal error.
    /// - `Ok(AuthClientResult::Cancelled)` — Exchange was cancelled.
    /// - `Err(DriverError)` — Infrastructure-level failure.
    fn client(
        &self,
        config: &AuthInstanceConfig,
        smtp_context: &mut dyn Any,
        timeout: i32,
    ) -> Result<AuthClientResult, DriverError>;

    /// Check server authorization condition.
    ///
    /// Replaces C `auth_check_serv_cond()` from `auths/check_serv_cond.c`.
    ///
    /// Evaluates the `server_condition` expandable string from the auth
    /// instance configuration. Called after the SASL exchange completes
    /// successfully to perform authorization checks (e.g., verifying the
    /// authenticated identity is permitted to relay).
    ///
    /// # Arguments
    ///
    /// - `config` — The auth instance configuration containing the
    ///   `server_condition` to evaluate.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — Authorization succeeded.
    /// - `Ok(false)` — Authorization denied.
    /// - `Err(DriverError)` — Condition evaluation failed.
    fn server_condition(&self, config: &AuthInstanceConfig) -> Result<bool, DriverError>;

    /// Diagnostic version reporting.
    ///
    /// Replaces C function pointer: `gstring * (*version_report)(gstring *)`.
    ///
    /// Returns an optional string containing version information about the
    /// underlying authentication library (e.g., Cyrus SASL version, Heimdal
    /// GSSAPI version). Used in `exim -bV` output.
    ///
    /// The default implementation returns `None`, appropriate for drivers
    /// that do not link external libraries (e.g., plaintext, cram_md5).
    fn version_report(&self) -> Option<String> {
        None
    }

    /// Create feature macros for this auth mechanism.
    ///
    /// Replaces C function pointer: `void (*macros_create)(void)`.
    ///
    /// Returns a list of `(name, value)` macro pairs that should be defined
    /// when this authenticator is compiled in. These are used in `readconf.c`
    /// macro expansion for `${if def:...}` conditions.
    ///
    /// The default implementation returns an empty list, appropriate for
    /// drivers that do not define additional macros.
    fn macros_create(&self) -> Vec<(String, String)> {
        Vec::new()
    }

    /// Returns the driver name for identification.
    ///
    /// This should return a static string matching the configured `driver`
    /// option value (e.g., "cram_md5", "plaintext", "dovecot", "gsasl",
    /// "spa", "external", "heimdal_gssapi", "cyrus_sasl", "tls").
    fn driver_name(&self) -> &str;
}

// =============================================================================
// AuthDriverFactory
// =============================================================================

/// Factory for creating `AuthDriver` instances, registered via `inventory::submit!`.
///
/// Each auth driver module (e.g., `exim-auths/src/cram_md5.rs`) submits one
/// `AuthDriverFactory` to the inventory at compile time. The registry module
/// iterates over all collected factories to resolve driver names from config.
///
/// # Example Registration (in a driver crate)
///
/// ```ignore
/// inventory::submit! {
///     AuthDriverFactory {
///         name: "cram_md5",
///         create: || Box::new(CramMd5Driver::new()),
///         avail_string: Some("CRAM-MD5"),
///     }
/// }
/// ```
///
/// # Fields
///
/// - `name` — The driver name used in configuration files (e.g., "cram_md5").
/// - `create` — Factory function producing a new boxed `AuthDriver` instance.
/// - `avail_string` — Optional display string shown in `exim -bV` output
///   (replaces C `driver_info.avail_string`).
pub struct AuthDriverFactory {
    /// Name of the auth mechanism as used in the configuration file.
    ///
    /// Must match the `driver = <name>` option in the Exim config. Examples:
    /// "cram_md5", "plaintext", "dovecot", "gsasl", "spa", "external",
    /// "heimdal_gssapi", "cyrus_sasl", "tls".
    pub name: &'static str,

    /// Factory function that creates a new, default-configured auth driver.
    ///
    /// The returned `Box<dyn AuthDriver>` is then used to process
    /// authentication requests for instances configured with this driver name.
    pub create: fn() -> Box<dyn AuthDriver>,

    /// Optional display string for `exim -bV` version output.
    ///
    /// When set, this string is displayed instead of the `name` field in the
    /// "Authenticators:" section of version output. Used for drivers where
    /// the display name differs from the internal name (e.g., "Cyrus SASL"
    /// vs "cyrus_sasl"). `None` means `name` is used directly.
    /// Replaces C `driver_info.avail_string`.
    pub avail_string: Option<&'static str>,
}

// NOTE: `inventory::collect!(AuthDriverFactory)` is declared in `registry.rs`
// to centralize all collection declarations. Driver crates register factories
// via `inventory::submit!(AuthDriverFactory { ... })` and the registry
// iterates with `inventory::iter::<AuthDriverFactory>()`.

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify AuthServerResult C code round-trip conversion.
    #[test]
    fn test_auth_server_result_c_code_round_trip() {
        assert_eq!(
            AuthServerResult::from_c_code(0),
            Some(AuthServerResult::Authenticated)
        );
        assert_eq!(
            AuthServerResult::from_c_code(1),
            Some(AuthServerResult::Deferred)
        );
        assert_eq!(
            AuthServerResult::from_c_code(2),
            Some(AuthServerResult::Failed)
        );
        assert_eq!(
            AuthServerResult::from_c_code(3),
            Some(AuthServerResult::Error)
        );
        assert_eq!(AuthServerResult::from_c_code(4), None);
        assert_eq!(AuthServerResult::from_c_code(-1), None);

        assert_eq!(AuthServerResult::Authenticated.to_c_code(), 0);
        assert_eq!(AuthServerResult::Deferred.to_c_code(), 1);
        assert_eq!(AuthServerResult::Failed.to_c_code(), 2);
        assert_eq!(AuthServerResult::Error.to_c_code(), 3);
        assert_eq!(AuthServerResult::Cancelled.to_c_code(), 2);
        assert_eq!(AuthServerResult::Unexpected.to_c_code(), 2);
    }

    /// Verify AuthClientResult C code round-trip conversion.
    #[test]
    fn test_auth_client_result_c_code_round_trip() {
        assert_eq!(
            AuthClientResult::from_c_code(0),
            Some(AuthClientResult::Authenticated)
        );
        assert_eq!(
            AuthClientResult::from_c_code(1),
            Some(AuthClientResult::Deferred)
        );
        assert_eq!(
            AuthClientResult::from_c_code(2),
            Some(AuthClientResult::Failed)
        );
        assert_eq!(
            AuthClientResult::from_c_code(3),
            Some(AuthClientResult::Error)
        );
        assert_eq!(AuthClientResult::from_c_code(4), None);
        assert_eq!(AuthClientResult::from_c_code(-1), None);

        assert_eq!(AuthClientResult::Authenticated.to_c_code(), 0);
        assert_eq!(AuthClientResult::Deferred.to_c_code(), 1);
        assert_eq!(AuthClientResult::Failed.to_c_code(), 2);
        assert_eq!(AuthClientResult::Error.to_c_code(), 3);
        assert_eq!(AuthClientResult::Cancelled.to_c_code(), 2);
    }

    /// Verify Display impls produce expected output for logging.
    #[test]
    fn test_result_display() {
        assert_eq!(format!("{}", AuthServerResult::Authenticated), "OK");
        assert_eq!(format!("{}", AuthServerResult::Failed), "FAIL");
        assert_eq!(format!("{}", AuthServerResult::Deferred), "DEFER");
        assert_eq!(format!("{}", AuthServerResult::Error), "ERROR");
        assert_eq!(format!("{}", AuthServerResult::Cancelled), "CANCELLED");
        assert_eq!(format!("{}", AuthServerResult::Unexpected), "UNEXPECTED");

        assert_eq!(format!("{}", AuthClientResult::Authenticated), "OK");
        assert_eq!(format!("{}", AuthClientResult::Failed), "FAIL");
        assert_eq!(format!("{}", AuthClientResult::Deferred), "DEFER");
        assert_eq!(format!("{}", AuthClientResult::Error), "ERROR");
        assert_eq!(format!("{}", AuthClientResult::Cancelled), "CANCELLED");
    }

    /// Verify success/failure/temporary classification methods.
    #[test]
    fn test_result_classification() {
        assert!(AuthServerResult::Authenticated.is_success());
        assert!(!AuthServerResult::Failed.is_success());
        assert!(!AuthServerResult::Deferred.is_success());

        assert!(AuthServerResult::Deferred.is_temporary());
        assert!(!AuthServerResult::Authenticated.is_temporary());

        assert!(AuthServerResult::Failed.is_failure());
        assert!(AuthServerResult::Error.is_failure());
        assert!(AuthServerResult::Cancelled.is_failure());
        assert!(AuthServerResult::Unexpected.is_failure());
        assert!(!AuthServerResult::Authenticated.is_failure());
        assert!(!AuthServerResult::Deferred.is_failure());

        assert!(AuthClientResult::Authenticated.is_success());
        assert!(!AuthClientResult::Failed.is_success());

        assert!(AuthClientResult::Deferred.is_temporary());

        assert!(AuthClientResult::Failed.is_failure());
        assert!(AuthClientResult::Error.is_failure());
        assert!(AuthClientResult::Cancelled.is_failure());
        assert!(!AuthClientResult::Authenticated.is_failure());
        assert!(!AuthClientResult::Deferred.is_failure());
    }

    /// Verify AuthInstanceConfig construction and field access.
    #[test]
    fn test_auth_instance_config_new() {
        let config = AuthInstanceConfig::new("my_auth", "plaintext", "PLAIN", Box::new(()));

        assert_eq!(config.name, "my_auth");
        assert_eq!(config.driver_name, "plaintext");
        assert_eq!(config.public_name, "PLAIN");
        assert!(config.advertise_condition.is_none());
        assert!(config.client_condition.is_none());
        assert!(config.set_id.is_none());
        assert!(config.set_client_id.is_none());
        assert!(config.mail_auth_condition.is_none());
        assert!(config.server_debug_string.is_none());
        assert!(config.server_condition.is_none());
        assert!(!config.client);
        assert!(!config.server);
        assert!(!config.advertised);
        assert!(config.srcfile.is_none());
        assert!(config.srcline.is_none());
    }

    /// Verify builder-style source location setter.
    #[test]
    fn test_auth_instance_config_with_source() {
        let config = AuthInstanceConfig::new("test", "cram_md5", "CRAM-MD5", Box::new(()))
            .with_source("/etc/exim/exim.conf", 42);

        assert_eq!(config.srcfile.as_deref(), Some("/etc/exim/exim.conf"));
        assert_eq!(config.srcline, Some(42));
        assert_eq!(config.source_location(), "/etc/exim/exim.conf:42");
    }

    /// Verify source_location formatting edge cases.
    #[test]
    fn test_source_location_formatting() {
        let config = AuthInstanceConfig::new("a", "b", "C", Box::new(()));
        assert_eq!(config.source_location(), "<unknown>");

        let mut config2 = AuthInstanceConfig::new("a", "b", "C", Box::new(()));
        config2.srcfile = Some("test.conf".to_string());
        assert_eq!(config2.source_location(), "test.conf");
    }

    /// Verify options downcasting works correctly.
    #[test]
    fn test_options_downcast() {
        #[derive(Debug)]
        struct TestOptions {
            value: String,
        }

        let config = AuthInstanceConfig::new(
            "test",
            "test_driver",
            "TEST",
            Box::new(TestOptions {
                value: "hello".to_string(),
            }),
        );

        let opts = config.downcast_options::<TestOptions>();
        assert!(opts.is_some());
        assert_eq!(opts.map(|o| o.value.as_str()), Some("hello"));

        let wrong_type = config.downcast_options::<String>();
        assert!(wrong_type.is_none());
    }

    /// Verify mutable options downcasting.
    #[test]
    fn test_options_downcast_mut() {
        #[derive(Debug)]
        struct TestOptions {
            counter: i32,
        }

        let mut config = AuthInstanceConfig::new(
            "test",
            "test_driver",
            "TEST",
            Box::new(TestOptions { counter: 0 }),
        );

        if let Some(opts) = config.downcast_options_mut::<TestOptions>() {
            opts.counter += 1;
        }

        let opts = config.downcast_options::<TestOptions>().unwrap();
        assert_eq!(opts.counter, 1);
    }

    /// Verify Display implementation for AuthInstanceConfig.
    #[test]
    fn test_auth_instance_config_display() {
        let config = AuthInstanceConfig::new("my_auth", "plaintext", "PLAIN", Box::new(()));
        let display = format!("{config}");
        assert!(display.contains("my_auth"));
        assert!(display.contains("plaintext"));
        assert!(display.contains("PLAIN"));
    }

    /// Verify server/client enable checks.
    #[test]
    fn test_server_client_enabled() {
        let mut config = AuthInstanceConfig::new("a", "b", "C", Box::new(()));
        assert!(!config.is_server_enabled());
        assert!(!config.is_client_enabled());

        config.server = true;
        config.client = true;
        assert!(config.is_server_enabled());
        assert!(config.is_client_enabled());
    }

    /// Verify Debug output is well-formed (does not panic).
    #[test]
    fn test_auth_instance_config_debug() {
        let config = AuthInstanceConfig::new("test", "dovecot", "PLAIN", Box::new(()));
        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("AuthInstanceConfig"));
        assert!(debug_str.contains("dovecot"));
    }

    /// Verify that AuthDriverFactory has expected fields.
    #[test]
    fn test_auth_driver_factory_fields() {
        fn dummy_create() -> Box<dyn AuthDriver> {
            panic!("factory called in test");
        }

        let factory = AuthDriverFactory {
            name: "test_auth",
            create: dummy_create,
            avail_string: Some("Test Auth Driver"),
        };

        assert_eq!(factory.name, "test_auth");
        assert_eq!(factory.avail_string, Some("Test Auth Driver"));
    }

    /// Verify that AuthDriverFactory with no avail_string works.
    #[test]
    fn test_auth_driver_factory_no_avail_string() {
        fn dummy_create() -> Box<dyn AuthDriver> {
            panic!("factory called in test");
        }

        let factory = AuthDriverFactory {
            name: "simple",
            create: dummy_create,
            avail_string: None,
        };

        assert_eq!(factory.name, "simple");
        assert!(factory.avail_string.is_none());
    }
}
