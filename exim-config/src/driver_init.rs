//! Driver instance creation from configuration blocks.
//!
//! This module translates the C driver initialization machinery into Rust:
//!
//! - `readconf_driver_init()` (readconf.c lines 3943–4063)
//!   → [`init_drivers()`]
//! - `init_driver()` (inline in readconf_driver_init)
//!   → [`resolve_driver()`]
//! - `driver_init_fini()` (readconf.c)
//!   → [`finalize_driver()`]
//! - `readconf_depends()` (readconf.c lines 4067–4100)
//!   → [`check_driver_depends()`]
//! - `auths_init()`, `route_init()`, `transport_init()`
//!   → [`init_auth_drivers()`], [`init_router_drivers()`],
//!   [`init_transport_drivers()`]
//! - `auth_show_supported()`, `route_show_supported()`,
//!   `transport_show_supported()` (drtables.c lines 58–77)
//!   → [`show_supported_drivers()`]
//!
//! # Architecture
//!
//! The C code uses a generic `readconf_driver_init()` function that works for
//! all driver classes (authenticators, routers, transports) via void pointers,
//! linked-list anchors, and memcpy-based default initialization. In Rust, we
//! use:
//!
//! - **`DriverClass` enum** to distinguish driver types at the type level
//! - **`inventory`-based registry** (via `exim-drivers`) for compile-time
//!   driver registration, replacing C's `auths_available` / `routers_available`
//!   / `transports_available` linked lists
//! - **Typed factory functions** returning `Box<dyn Trait>` instead of memcpy
//!   from default templates
//! - **`OptionEntry` tables** from [`super::options`] for binary-chop option
//!   lookup, preserving the C behavior exactly
//!
//! # Initialization Flow
//!
//! ```text
//! init_auth_drivers()  ──┐
//! init_router_drivers() ─┤──► init_drivers(class, lines, options)
//! init_transport_drivers()┘      │
//!                                ├─ detect "name:" stanza header
//!                                ├─ check duplicate names
//!                                ├─ handle macro definitions
//!                                ├─ process generic options via handle_option()
//!                                ├─ on "driver = <name>": resolve_driver()
//!                                ├─ process private options
//!                                └─ finalize_driver() for each instance
//! ```
//!
//! Per AAP §0.7.2: This module contains ZERO `unsafe` code.
//! Per AAP §0.7.3: Driver registration uses the `inventory` crate.
//! Per AAP §0.7.3: Config data is frozen into `Arc<Config>` after parsing.

use std::collections::HashMap;
use std::sync::Arc;

use crate::macros::MacroStore;
use crate::options::{
    find_option, handle_option, read_name, HandleOptionResult, OptionEntry, OptionFlags,
    OptionType, OptionValue,
};
use crate::types::{Config, ConfigContext, ConfigError};

use exim_drivers::auth_driver::{AuthDriverFactory, AuthInstanceConfig};
use exim_drivers::lookup_driver::LookupDriverFactory;
use exim_drivers::registry::DriverRegistry;
use exim_drivers::router_driver::{RouterDriverFactory, RouterInstanceConfig};
use exim_drivers::transport_driver::{TransportDriverFactory, TransportInstanceConfig};
use exim_drivers::{
    AuthDriver, DriverError, DriverInstanceBase, DriverResult, LookupDriver, RouterDriver,
    TransportDriver,
};

// =============================================================================
// DriverClass Enum
// =============================================================================

/// Classification of driver types, used to select the correct registry
/// and option table during initialization.
///
/// Replaces the C `class` string parameter ("authenticator", "router",
/// "transport") passed to `readconf_driver_init()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DriverClass {
    /// Authenticator drivers (SMTP AUTH mechanisms).
    /// C: `readconf_driver_init()` called with class = "authenticator".
    Authenticator,
    /// Router drivers (address routing chain).
    /// C: `readconf_driver_init()` called with class = "router".
    Router,
    /// Transport drivers (message delivery mechanisms).
    /// C: `readconf_driver_init()` called with class = "transport".
    Transport,
}

impl DriverClass {
    /// Return the human-readable class name for logging and error messages.
    ///
    /// Matches the exact C strings used in `readconf_driver_init()` for
    /// error messages like "there are two authenticators called foo".
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authenticator => "authenticator",
            Self::Router => "router",
            Self::Transport => "transport",
        }
    }

    /// Return the plural form for summary logging.
    pub fn plural(self) -> &'static str {
        match self {
            Self::Authenticator => "authenticators",
            Self::Router => "routers",
            Self::Transport => "transports",
        }
    }
}

impl std::fmt::Display for DriverClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// =============================================================================
// DriverInstance — intermediate representation during parsing
// =============================================================================

/// Intermediate representation of a driver instance being parsed from config.
///
/// This struct holds the parsing state for a single driver block between the
/// `name:` header and the end of the block. It accumulates both generic
/// options and driver-specific options before the driver's init hook is called.
///
/// After parsing completes, the instance is finalized via [`finalize_driver()`]
/// and converted into the appropriate typed instance config
/// (`AuthInstanceConfig`, `RouterInstanceConfig`, `TransportInstanceConfig`).
#[derive(Debug)]
struct DriverParseState {
    /// The base driver instance metadata.
    base: DriverInstanceBase,
    /// The driver class (auth/router/transport).
    class: DriverClass,
    /// Whether the `driver = <name>` option has been resolved.
    driver_resolved: bool,
    /// Accumulated generic option results (name → value).
    generic_options: Vec<HandleOptionResult>,
    /// Accumulated private (driver-specific) option results.
    private_options: Vec<HandleOptionResult>,
}

impl DriverParseState {
    /// Create a new parse state for a driver instance.
    fn new(name: &str, class: DriverClass, srcfile: &str, srcline: u32) -> Self {
        Self {
            base: DriverInstanceBase::with_source(name, "", srcfile, srcline as i32),
            class,
            driver_resolved: false,
            generic_options: Vec::new(),
            private_options: Vec::new(),
        }
    }
}

// =============================================================================
// ConfigLineReader — abstraction for reading config lines
// =============================================================================

/// Iterator-like abstraction over configuration lines being parsed.
///
/// This replaces the C `get_config_line()` function pointer usage in
/// `readconf_driver_init()`. In the C code, `get_config_line()` reads from a
/// global file handle and handles continuation lines. In Rust, we accept a
/// slice of pre-read, macro-expanded lines with their line numbers.
#[derive(Debug)]
pub struct ConfigLines<'a> {
    /// The lines to iterate over, each paired with its source line number.
    lines: &'a [(String, u32)],
    /// Current position in the lines slice.
    pos: usize,
    /// Source file path for error reporting.
    pub srcfile: String,
}

impl<'a> ConfigLines<'a> {
    /// Create a new `ConfigLines` from a slice of (line_text, line_number) pairs.
    pub fn new(lines: &'a [(String, u32)], srcfile: &str) -> Self {
        Self {
            lines,
            pos: 0,
            srcfile: srcfile.to_string(),
        }
    }

    /// Read the next non-empty, non-comment config line.
    ///
    /// Returns `None` when all lines are consumed.
    pub fn next_line(&mut self) -> Option<(String, u32)> {
        while self.pos < self.lines.len() {
            let (ref line, lineno) = self.lines[self.pos];
            self.pos += 1;
            let trimmed = line.trim().to_string();
            // Skip empty lines and full-line comments.
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            return Some((trimmed, lineno));
        }
        None
    }

    /// Peek at the current position without consuming.
    pub fn peek(&self) -> Option<(&str, u32)> {
        let mut temp_pos = self.pos;
        while temp_pos < self.lines.len() {
            let (ref line, lineno) = self.lines[temp_pos];
            temp_pos += 1;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            return Some((trimmed, lineno));
        }
        None
    }
}

// =============================================================================
// Driver Error Conversion Helpers
// =============================================================================

/// Convert a [`DriverError`] into a [`ConfigError`].
///
/// This bridges the `exim-drivers` error type into the config error type,
/// used when driver resolution or initialization fails.
pub fn driver_error_to_config_error(err: DriverError, driver_name: &str) -> ConfigError {
    match err {
        DriverError::NotFound { name } => ConfigError::UnknownDriver(format!(
            "driver \"{}\" not found (looking for \"{}\")",
            name, driver_name
        )),
        DriverError::InitFailed(msg) => ConfigError::ValidationError(format!(
            "driver \"{}\" initialization failed: {}",
            driver_name, msg
        )),
        DriverError::ConfigError(msg) => ConfigError::ParseError {
            file: String::new(),
            line: 0,
            message: format!("driver \"{}\" config error: {}", driver_name, msg),
        },
        DriverError::ExecutionFailed(msg) => ConfigError::ValidationError(format!(
            "driver \"{}\" execution failed during init: {}",
            driver_name, msg
        )),
        DriverError::TempFail(msg) => ConfigError::ValidationError(format!(
            "driver \"{}\" temporary failure during init: {}",
            driver_name, msg
        )),
    }
}

/// Map a [`DriverResult`] to a [`ConfigError`] for failed initialization
/// outcomes.
///
/// During driver initialization, only `DriverResult::Ok` and
/// `DriverResult::Decline` (meaning "not my responsibility") are acceptable.
/// Any other result is an initialization failure.
pub fn check_driver_result(result: DriverResult, driver_name: &str) -> Result<(), ConfigError> {
    match result {
        DriverResult::Ok | DriverResult::Decline | DriverResult::Pass => Ok(()),
        DriverResult::Defer => Err(ConfigError::ValidationError(format!(
            "driver \"{}\" deferred during initialization",
            driver_name
        ))),
        DriverResult::Fail => Err(ConfigError::ValidationError(format!(
            "driver \"{}\" failed during initialization",
            driver_name
        ))),
        DriverResult::Error => Err(ConfigError::ValidationError(format!(
            "driver \"{}\" returned error during initialization",
            driver_name
        ))),
    }
}

// =============================================================================
// Driver Factory Helpers
// =============================================================================

/// Create an authenticator driver instance from a factory.
///
/// Wraps the factory's `create` function, providing logging and
/// error handling around driver instantiation.
fn create_auth_from_factory(factory: &AuthDriverFactory) -> Box<dyn AuthDriver> {
    tracing::debug!(
        factory_name = %factory.name,
        "creating auth driver from factory"
    );
    (factory.create)()
}

/// Create a router driver instance from a factory.
///
/// Wraps the factory's `create` function, providing logging and
/// error handling around driver instantiation.
fn create_router_from_factory(factory: &RouterDriverFactory) -> Box<dyn RouterDriver> {
    tracing::debug!(
        factory_name = %factory.name,
        "creating router driver from factory"
    );
    (factory.create)()
}

/// Create a transport driver instance from a factory.
///
/// Wraps the factory's `create` function, providing logging and
/// error handling around driver instantiation.
fn create_transport_from_factory(factory: &TransportDriverFactory) -> Box<dyn TransportDriver> {
    tracing::debug!(
        factory_name = %factory.name,
        is_local = factory.is_local,
        "creating transport driver from factory"
    );
    (factory.create)()
}

/// Find a lookup driver factory by name.
///
/// Queries the `inventory`-based registry for a lookup driver factory
/// matching the given name. Used when lookup modules are referenced
/// in configuration (e.g., `${lookup ... }` expansion).
pub fn find_lookup_factory(name: &str) -> Option<&'static LookupDriverFactory> {
    let result = DriverRegistry::find_lookup(name);
    if let Some(factory) = result {
        tracing::debug!(
            lookup_name = %name,
            lookup_type = ?factory.lookup_type,
            "found lookup driver factory"
        );
    }
    result
}

/// Instantiate a lookup driver from its factory.
///
/// Creates a new [`LookupDriver`] trait object from a lookup factory.
pub fn create_lookup_from_factory(factory: &LookupDriverFactory) -> Box<dyn LookupDriver> {
    tracing::debug!(
        factory_name = %factory.name,
        "creating lookup driver from factory"
    );
    (factory.create)()
}

// =============================================================================
// Config Freeze Helper
// =============================================================================

/// Freeze a completed [`ConfigContext`] into an immutable [`Config`].
///
/// This wraps [`Config::freeze()`] to provide logging and a clear
/// integration point. Per AAP §0.7.3, configuration data is frozen into
/// `Arc<Config>` after parsing completes.
pub fn freeze_config(ctx: ConfigContext) -> Arc<Config> {
    tracing::info!("freezing configuration into Arc<Config>");
    Config::freeze(ctx)
}

// =============================================================================
// init_drivers — Generic driver initialization (readconf_driver_init)
// =============================================================================

/// Initialize driver instances from configuration blocks.
///
/// This is the Rust equivalent of `readconf_driver_init()` (readconf.c lines
/// 3943–4063). It reads driver configuration blocks from the provided lines,
/// creates instances, processes options, resolves driver implementations via
/// the `inventory`-based registry, and stores the typed instance configs
/// into the [`ConfigContext`].
///
/// # Arguments
///
/// * `class` — The driver class being initialized.
/// * `lines` — Configuration lines for this section.
/// * `ctx` — The mutable configuration context being populated.
/// * `macro_store` — The macro store for handling inline macro definitions.
///
/// # Returns
///
/// The number of driver instances that were initialized.
///
/// # Errors
///
/// Returns `ConfigError` if:
/// - A duplicate driver name is detected.
/// - An unknown option is encountered before the `driver` option.
/// - The `driver` option is missing or references an unknown driver.
/// - Any option parsing error occurs.
pub fn init_drivers(
    class: DriverClass,
    lines: &mut ConfigLines<'_>,
    ctx: &mut ConfigContext,
    macro_store: &mut MacroStore,
) -> Result<usize, ConfigError> {
    let mut generic_options = match class {
        DriverClass::Authenticator => build_auth_generic_options(),
        DriverClass::Router => build_router_generic_options(),
        DriverClass::Transport => build_transport_generic_options(),
    };

    let instances = parse_driver_blocks(class, lines, &mut generic_options, ctx, macro_store)?;
    let count = instances.len();

    // Build typed configs and store in context.
    for state in &instances {
        match class {
            DriverClass::Authenticator => {
                let config = build_auth_instance_config(state)?;
                if let Some(factory) = DriverRegistry::find_auth(&state.base.driver_name) {
                    let _driver = create_auth_from_factory(factory);
                    tracing::debug!(
                        name = %state.base.name,
                        driver = %factory.name,
                        "auth driver factory verified"
                    );
                }
                ctx.auth_instances.push(Arc::new(config));
            }
            DriverClass::Router => {
                let config = build_router_instance_config(state)?;
                if let Some(factory) = DriverRegistry::find_router(&state.base.driver_name) {
                    let _driver = create_router_from_factory(factory);
                    tracing::debug!(
                        name = %state.base.name,
                        driver = %factory.name,
                        "router driver factory verified"
                    );
                }
                ctx.router_instances.push(Arc::new(config));
            }
            DriverClass::Transport => {
                let config = build_transport_instance_config(state)?;
                if let Some(factory) = DriverRegistry::find_transport(&state.base.driver_name) {
                    let _driver = create_transport_from_factory(factory);
                    tracing::debug!(
                        name = %state.base.name,
                        driver = %factory.name,
                        "transport driver factory verified"
                    );
                }
                ctx.transport_instances.push(Arc::new(config));
            }
        }
    }

    tracing::info!(
        class = %class,
        count,
        "driver initialization and config building complete"
    );

    Ok(count)
}

/// Parse driver blocks from configuration lines into intermediate state.
///
/// This is the core parsing loop that reads config lines, detects stanza
/// headers, processes options, and resolves driver types. It is the internal
/// implementation behind [`init_drivers()`].
fn parse_driver_blocks(
    class: DriverClass,
    lines: &mut ConfigLines<'_>,
    generic_options: &mut [OptionEntry],
    ctx: &mut ConfigContext,
    macro_store: &mut MacroStore,
) -> Result<Vec<DriverParseState>, ConfigError> {
    let mut instances: Vec<DriverParseState> = Vec::new();
    let mut current: Option<DriverParseState> = None;
    let mut seen_names: HashMap<String, u32> = HashMap::new();

    // Clone the source filename to avoid borrow-checker conflict with the
    // mutable borrow through `lines.next_line()`.
    let srcfile = lines.srcfile.clone();

    tracing::debug!(class = %class, "beginning driver initialization");

    while let Some((line, lineno)) = lines.next_line() {
        let (name, rest) = read_name(&line);

        // Handle macro definition: uppercase name followed by '='.
        // C readconf.c line 3980: if macro definition detected, call
        // macro_read_assignment() before continuing with driver parsing.
        if !name.is_empty() && name.as_bytes()[0].is_ascii_uppercase() && rest.starts_with('=') {
            if let Some(ref mut d) = current {
                tracing::debug!(
                    driver = %d.base.name,
                    class = %class,
                    "processing macro within driver block"
                );
            }
            // Process macro assignment within driver block.
            macro_store.read_macro_assignment(&line)?;
            continue;
        }

        // Check if this is a new driver stanza: "name:" at start of line.
        if !name.is_empty() && rest.starts_with(':') {
            // Finalize previous driver instance if any.
            if let Some(ref mut d) = current {
                tracing::debug!(
                    driver = %d.base.name,
                    class = %class,
                    "finalizing previous driver"
                );
                finalize_driver_state(d)?;
            }
            if let Some(d) = current.take() {
                instances.push(d);
            }

            // Check for duplicate driver names.
            if let Some(prev_line) = seen_names.get(name) {
                tracing::error!(
                    name = %name,
                    class = %class,
                    previous_line = prev_line,
                    current_line = lineno,
                    "duplicate driver name"
                );
                return Err(ConfigError::DuplicateDriver(format!(
                    "there are two {}s called \"{}\"",
                    class.plural(),
                    name
                )));
            }
            seen_names.insert(name.to_string(), lineno);

            // Create a new driver parse state.
            let state = DriverParseState::new(name, class, &srcfile, lineno);
            tracing::debug!(
                name = %name,
                class = %class,
                line = lineno,
                "new driver stanza"
            );

            // Clear "set" bits in generic options for the new instance.
            // This matches C readconf.c line 3996: clearing opt_set bits.
            for opt in generic_options.iter_mut() {
                opt.flags.remove(OptionFlags::SET);
            }

            current = Some(state);

            // Check nothing more on this line after "name:".
            let after_colon = rest[1..].trim();
            if !after_colon.is_empty() && !after_colon.starts_with('#') {
                return Err(ConfigError::ParseError {
                    file: srcfile.clone(),
                    line: lineno,
                    message: format!(
                        "extra characters after {} name \"{}\"",
                        class.as_str(),
                        name
                    ),
                });
            }
            continue;
        }

        // Not the start of a new driver. Error if no current driver set.
        let d = match current.as_mut() {
            Some(d) => d,
            None => {
                tracing::error!(
                    class = %class,
                    line = lineno,
                    "option line outside driver block"
                );
                return Err(ConfigError::ParseError {
                    file: srcfile.clone(),
                    line: lineno,
                    message: format!("{} name missing", class.as_str()),
                });
            }
        };

        // Try to process as a generic option first.
        let generic_result = handle_option(&line, generic_options, ctx, None)?;

        if let Some(result) = generic_result {
            tracing::debug!(
                driver = %d.base.name,
                option = %result.name,
                class = %class,
                "processed generic option"
            );

            // If the option is "driver", resolve the driver implementation.
            if result.name == "driver" {
                if let OptionValue::Str(ref driver_name) = result.value {
                    // Verify the driver exists in the registry before accepting.
                    resolve_driver(driver_name, class)?;
                    d.base.driver_name = driver_name.clone();
                    d.driver_resolved = true;
                    tracing::debug!(
                        driver_instance = %d.base.name,
                        driver_type = %driver_name,
                        class = %class,
                        "resolved driver type"
                    );
                }
            }
            d.generic_options.push(result);
        } else if d.driver_resolved {
            // Generic option not found — try as a private option.
            // Private options are only valid after `driver = <name>` is set.
            // Store the raw line as a private option for the driver's own
            // option table processing during finalization.
            d.private_options.push(HandleOptionResult {
                name: name.to_string(),
                value: OptionValue::Str(line.to_string()),
                is_secure: false,
                is_negated: false,
            });
        } else {
            // No driver resolved yet and this is not a generic option.
            // C readconf.c checks: "unknown option" error before driver specified.
            tracing::error!(
                driver = %d.base.name,
                option = %name,
                class = %class,
                line = lineno,
                "private option before driver specification"
            );
            return Err(ConfigError::ParseError {
                file: srcfile.clone(),
                line: lineno,
                message: format!(
                    "option \"{}\" unknown (\"driver\" must be specified \
                     before any private options)",
                    name
                ),
            });
        }
    }

    // Finalize the last driver instance.
    if let Some(ref mut d) = current {
        tracing::debug!(
            driver = %d.base.name,
            class = %class,
            "finalizing final driver"
        );
        finalize_driver_state(d)?;
    }
    if let Some(d) = current.take() {
        instances.push(d);
    }

    tracing::info!(
        class = %class,
        count = instances.len(),
        "driver initialization complete"
    );

    Ok(instances)
}

// =============================================================================
// resolve_driver — Driver resolution by name (init_driver)
// =============================================================================

/// Resolve a driver implementation by name from the `inventory`-based registry.
///
/// This is the Rust equivalent of `init_driver()` in readconf.c, which linearly
/// searches the `info_anchor` chain for a matching driver name. In Rust, we use
/// the compile-time `inventory` registry via [`DriverRegistry`].
///
/// # Arguments
///
/// * `driver_name` — The driver type name from the `driver = <name>` option.
/// * `class` — The driver class to search.
///
/// # Returns
///
/// `Ok(())` if the driver is found in the registry.
///
/// # Errors
///
/// Returns `ConfigError::UnknownDriver` if no driver with the given name is
/// registered for the specified class.
pub fn resolve_driver(driver_name: &str, class: DriverClass) -> Result<(), ConfigError> {
    tracing::debug!(
        driver = %driver_name,
        class = %class,
        "resolving driver from registry"
    );

    let found = match class {
        DriverClass::Authenticator => DriverRegistry::find_auth(driver_name).is_some(),
        DriverClass::Router => DriverRegistry::find_router(driver_name).is_some(),
        DriverClass::Transport => DriverRegistry::find_transport(driver_name).is_some(),
    };

    if found {
        tracing::debug!(
            driver = %driver_name,
            class = %class,
            "driver found in registry"
        );
        Ok(())
    } else {
        tracing::warn!(
            driver = %driver_name,
            class = %class,
            "driver not found in registry"
        );
        Err(ConfigError::UnknownDriver(format!(
            "{} driver \"{}\" not found",
            class.as_str(),
            driver_name
        )))
    }
}

// =============================================================================
// init_auth_drivers — Authenticator initialization (auths_init)
// =============================================================================

/// Initialize authenticator driver instances from configuration.
///
/// This is the Rust equivalent of `auths_init()` (readconf.c lines 4403–4490).
/// It seeds available authenticators from the `inventory` registry, then calls
/// [`init_drivers()`] with the auth-specific option list and defaults.
///
/// # Arguments
///
/// * `lines` — Configuration lines for the `begin authenticators` section.
/// * `ctx` — The mutable configuration context being populated.
/// * `macro_store` — The macro store for handling inline macro definitions.
///
/// # Returns
///
/// The number of authenticator instances initialized.
///
/// # Errors
///
/// Returns `ConfigError` if any driver initialization error occurs.
pub fn init_auth_drivers(
    lines: &mut ConfigLines<'_>,
    ctx: &mut ConfigContext,
    macro_store: &mut MacroStore,
) -> Result<usize, ConfigError> {
    tracing::info!("initializing authenticator drivers");

    // Log available authenticators from the inventory registry.
    for factory in DriverRegistry::list_auths() {
        tracing::debug!(auth_driver = %factory.name, "available auth driver");
    }

    let count = init_drivers(DriverClass::Authenticator, lines, ctx, macro_store)?;

    tracing::info!(count, "authenticator driver initialization complete");
    Ok(count)
}

// =============================================================================
// init_router_drivers — Router initialization (route_init)
// =============================================================================

/// Initialize router driver instances from configuration.
///
/// This is the Rust equivalent of `route_init()` called from
/// `readconf_rest()`. It calls [`init_drivers()`] with the router-specific
/// option list and defaults.
///
/// # Arguments
///
/// * `lines` — Configuration lines for the `begin routers` section.
/// * `ctx` — The mutable configuration context being populated.
/// * `macro_store` — The macro store for handling inline macro definitions.
///
/// # Returns
///
/// The number of router instances initialized.
///
/// # Errors
///
/// Returns `ConfigError` if any driver initialization error occurs.
pub fn init_router_drivers(
    lines: &mut ConfigLines<'_>,
    ctx: &mut ConfigContext,
    macro_store: &mut MacroStore,
) -> Result<usize, ConfigError> {
    tracing::info!("initializing router drivers");

    // Log available routers from the inventory registry.
    for factory in DriverRegistry::list_routers() {
        tracing::debug!(router_driver = %factory.name, "available router driver");
    }

    let count = init_drivers(DriverClass::Router, lines, ctx, macro_store)?;

    tracing::info!(count, "router driver initialization complete");
    Ok(count)
}

// =============================================================================
// init_transport_drivers — Transport initialization (transport_init)
// =============================================================================

/// Initialize transport driver instances from configuration.
///
/// This is the Rust equivalent of `transport_init()` called from
/// `readconf_rest()`. It calls [`init_drivers()`] with the transport-specific
/// option list and defaults.
///
/// # Arguments
///
/// * `lines` — Configuration lines for the `begin transports` section.
/// * `ctx` — The mutable configuration context being populated.
/// * `macro_store` — The macro store for handling inline macro definitions.
///
/// # Returns
///
/// The number of transport instances initialized.
///
/// # Errors
///
/// Returns `ConfigError` if any driver initialization error occurs.
pub fn init_transport_drivers(
    lines: &mut ConfigLines<'_>,
    ctx: &mut ConfigContext,
    macro_store: &mut MacroStore,
) -> Result<usize, ConfigError> {
    tracing::info!("initializing transport drivers");

    // Log available transports from the inventory registry.
    for factory in DriverRegistry::list_transports() {
        tracing::debug!(
            transport_driver = %factory.name,
            is_local = factory.is_local,
            "available transport driver"
        );
    }

    let count = init_drivers(DriverClass::Transport, lines, ctx, macro_store)?;

    tracing::info!(count, "transport driver initialization complete");
    Ok(count)
}

// =============================================================================
// check_driver_depends — Dependency checking (readconf_depends)
// =============================================================================

/// Check whether a driver instance depends on a given expansion variable.
///
/// This is the Rust equivalent of `readconf_depends()` (readconf.c lines
/// 4067–4107). It scans all string-typed options of the driver to see if any
/// contain the given string as an expansion variable reference.
///
/// The check looks for the pattern `$name` or `${name` where `name` is the
/// dependency string, ensuring it is referenced as an expansion variable
/// and not just as a substring of a longer identifier.
///
/// # Arguments
///
/// * `base` — The driver instance base metadata.
/// * `options` — The driver's option values (both generic and private).
/// * `dependency` — The expansion variable name to search for.
///
/// # Returns
///
/// `true` if any string option contains a reference to the dependency.
pub fn check_driver_depends(
    base: &DriverInstanceBase,
    options: &[HandleOptionResult],
    dependency: &str,
) -> bool {
    for opt in options {
        if let OptionValue::Str(ref value) = opt.value {
            if string_contains_expansion_var(value, dependency) {
                tracing::debug!(
                    driver = %base.name,
                    option = %opt.name,
                    dependency = %dependency,
                    "driver depends on expansion variable"
                );
                return true;
            }
        }
    }
    tracing::debug!(
        driver = %base.name,
        dependency = %dependency,
        "driver does not depend on expansion variable"
    );
    false
}

/// Check if a string contains a reference to an expansion variable name.
///
/// Implements the same boundary checking as C readconf.c lines 4095-4098:
/// the dependency must be preceded by `$` or `{` and not followed by an
/// alphanumeric character (to avoid substring matches).
fn string_contains_expansion_var(haystack: &str, var_name: &str) -> bool {
    let hay_bytes = haystack.as_bytes();
    let var_bytes = var_name.as_bytes();
    let var_len = var_bytes.len();

    if var_len == 0 || hay_bytes.len() < var_len {
        return false;
    }

    // Scan all occurrences of var_name in haystack.
    let mut search_from = 0;
    while let Some(rel_pos) = haystack[search_from..].find(var_name) {
        let pos = search_from + rel_pos;

        // Check that the match is preceded by '$' or '{'.
        let before_ok = if pos == 0 {
            false
        } else {
            let prev_byte = hay_bytes[pos - 1];
            prev_byte == b'$' || prev_byte == b'{'
        };

        // Check that the match is not followed by an alphanumeric character
        // (prevents matching "sender_domain" inside "sender_domainname").
        let after_pos = pos + var_len;
        let after_ok = if after_pos >= hay_bytes.len() {
            true
        } else {
            !hay_bytes[after_pos].is_ascii_alphanumeric()
        };

        if before_ok && after_ok {
            return true;
        }

        // Move past this occurrence to look for another.
        search_from = pos + 1;
    }

    false
}

// =============================================================================
// finalize_driver — Driver finalization (driver_init_fini)
// =============================================================================

/// Finalize a driver instance after all options have been processed.
///
/// This is the Rust equivalent of `driver_init_fini()` from readconf.c.
/// In C, this calls the driver's `init` hook and handles dlopen()-based
/// module loading. In Rust, `inventory` handles registration at compile time,
/// so this function validates that required options are set and verifies the
/// driver factory can be resolved.
///
/// # Arguments
///
/// * `base` — The driver instance base metadata.
/// * `class` — The driver class.
/// * `generic_options` — The generic options that were processed.
///
/// # Returns
///
/// `Ok(())` if finalization succeeds.
///
/// # Errors
///
/// Returns `ConfigError` if required options are missing or the driver
/// cannot be resolved.
pub fn finalize_driver(
    base: &DriverInstanceBase,
    class: DriverClass,
    generic_options: &[HandleOptionResult],
) -> Result<(), ConfigError> {
    tracing::debug!(
        driver = %base.name,
        driver_type = %base.driver_name,
        class = %class,
        "finalizing driver instance"
    );

    // Validate that the 'driver' option was specified.
    if base.driver_name.is_empty() {
        return Err(ConfigError::ParseError {
            file: base
                .srcfile
                .clone()
                .unwrap_or_else(|| "<unknown>".to_string()),
            line: base.srcline.unwrap_or(0) as u32,
            message: format!("no driver defined for {} \"{}\"", class.as_str(), base.name),
        });
    }

    // Verify the driver exists in the registry.
    resolve_driver(&base.driver_name, class)?;

    // Log a summary of the finalized driver.
    let option_count = generic_options.len();
    tracing::debug!(
        driver = %base.name,
        driver_type = %base.driver_name,
        class = %class,
        generic_option_count = option_count,
        "driver instance finalized successfully"
    );

    Ok(())
}

// =============================================================================
// show_supported_drivers — Display registered drivers
// =============================================================================

/// Display all supported (registered) drivers for all classes.
///
/// This is the Rust equivalent of `auth_show_supported()`,
/// `route_show_supported()`, and `transport_show_supported()` from
/// drtables.c (lines 58–77). It queries the `inventory`-based registry
/// and formats the output for `-bV` version display.
///
/// Calls [`DriverRegistry::init()`] to ensure the registry is initialized
/// and logged before listing.
///
/// # Returns
///
/// A formatted string listing all registered drivers by class, suitable for
/// inclusion in the Exim version output.
pub fn show_supported_drivers() -> String {
    // Ensure registry is initialized and counts logged.
    DriverRegistry::init();

    let mut output = String::new();

    // Authenticators
    let auth_line = DriverRegistry::auth_show_supported();
    if !auth_line.is_empty() {
        output.push_str(&auth_line);
        output.push('\n');
    }

    // Routers
    let router_line = DriverRegistry::route_show_supported();
    if !router_line.is_empty() {
        output.push_str(&router_line);
        output.push('\n');
    }

    // Transports
    let transport_line = DriverRegistry::transport_show_supported();
    if !transport_line.is_empty() {
        output.push_str(&transport_line);
        output.push('\n');
    }

    // Lookups
    let lookup_line = DriverRegistry::lookup_show_supported();
    if !lookup_line.is_empty() {
        output.push_str(&lookup_line);
        output.push('\n');
    }

    tracing::info!("supported drivers listing generated");
    output
}

// =============================================================================
// Internal helper: finalize_driver_state
// =============================================================================

/// Internal helper to finalize a driver parse state.
///
/// Validates that the driver has been resolved and all required options are
/// present before the state is converted into a typed config.
fn finalize_driver_state(state: &mut DriverParseState) -> Result<(), ConfigError> {
    if !state.driver_resolved || state.base.driver_name.is_empty() {
        return Err(ConfigError::ParseError {
            file: state
                .base
                .srcfile
                .clone()
                .unwrap_or_else(|| "<unknown>".to_string()),
            line: state.base.srcline.unwrap_or(0) as u32,
            message: format!(
                "no driver defined for {} \"{}\"",
                state.class.as_str(),
                state.base.name
            ),
        });
    }

    // Verify the driver exists in the registry.
    resolve_driver(&state.base.driver_name, state.class)?;

    tracing::debug!(
        name = %state.base.name,
        driver = %state.base.driver_name,
        class = %state.class,
        generic_count = state.generic_options.len(),
        private_count = state.private_options.len(),
        "driver parse state finalized"
    );

    Ok(())
}

// =============================================================================
// Generic option table builders
// =============================================================================

/// Validate that a critical option exists in an option table.
///
/// Uses [`find_option()`] to perform binary search on the sorted option table,
/// ensuring the required option is present. This is used during option table
/// construction to verify table integrity.
fn validate_option_table(options: &[OptionEntry], required: &[&str]) -> Result<(), ConfigError> {
    for &name in required {
        if find_option(name, options).is_none() {
            return Err(ConfigError::ValidationError(format!(
                "internal error: required option \"{}\" missing from option table",
                name
            )));
        }
    }
    Ok(())
}

/// Build the generic option table for authenticator drivers.
///
/// These are the options common to all authenticator instances, equivalent to
/// `optionlist_auths[]` in C globals.c. They correspond to fields in
/// `AuthInstanceConfig`.
fn build_auth_generic_options() -> Vec<OptionEntry> {
    let mut opts = vec![
        OptionEntry::simple("advertise_condition", OptionType::StringPtr),
        OptionEntry::simple("client", OptionType::Bool),
        OptionEntry::simple("client_condition", OptionType::StringPtr),
        OptionEntry::simple("driver", OptionType::StringPtr),
        OptionEntry::simple("mail_auth_condition", OptionType::StringPtr),
        OptionEntry::simple("public_name", OptionType::StringPtr),
        OptionEntry::simple("server", OptionType::Bool),
        OptionEntry::simple("server_condition", OptionType::StringPtr),
        OptionEntry::simple("server_debug_string", OptionType::StringPtr),
        OptionEntry::simple("set_client_id", OptionType::StringPtr),
        OptionEntry::simple("set_id", OptionType::StringPtr),
    ];
    // Sort alphabetically for binary search (matching C binary-chop).
    opts.sort_by(|a, b| a.name.cmp(b.name));

    // Verify critical options are present. This is a compile-time
    // sanity check — if it fails, the option table is misconfigured.
    if let Err(e) = validate_option_table(&opts, &["driver", "public_name"]) {
        tracing::error!(error = %e, "auth option table validation failed");
    }

    opts
}

/// Build the generic option table for router drivers.
///
/// These are the options common to all router instances, equivalent to
/// `optionlist_routers[]` in C globals.c. They correspond to fields in
/// `RouterInstanceConfig`.
fn build_router_generic_options() -> Vec<OptionEntry> {
    let mut opts = vec![
        OptionEntry::simple("address_data", OptionType::StringPtr),
        OptionEntry::simple("address_test", OptionType::Bool),
        OptionEntry::simple("cannot_route_message", OptionType::StringPtr),
        OptionEntry::simple("caseful_local_part", OptionType::Bool),
        OptionEntry::simple("check_local_user", OptionType::Bool),
        OptionEntry::simple("condition", OptionType::StringPtr),
        OptionEntry::simple("current_directory", OptionType::StringPtr),
        OptionEntry::simple("debug_string", OptionType::StringPtr),
        OptionEntry::simple("disable_logging", OptionType::Bool),
        OptionEntry::simple("domains", OptionType::StringPtr),
        OptionEntry::simple("driver", OptionType::StringPtr),
        OptionEntry::simple("dsn_lasthop", OptionType::Bool),
        OptionEntry::simple("errors_to", OptionType::StringPtr),
        OptionEntry::simple("expn", OptionType::Bool),
        OptionEntry::simple("extra_headers", OptionType::StringPtr),
        // "headers_add" is the user-facing config option name that maps to
        // the internal extra_headers field (C Exim readconf.c optionlist_routers).
        OptionEntry::simple("headers_add", OptionType::StringPtr),
        OptionEntry::simple("fallback_hosts", OptionType::StringPtr),
        OptionEntry::simple("group", OptionType::Gid),
        OptionEntry::simple("home_directory", OptionType::StringPtr),
        OptionEntry::simple("ignore_target_hosts", OptionType::StringPtr),
        OptionEntry::simple("initgroups", OptionType::Bool),
        OptionEntry::simple("local_parts", OptionType::StringPtr),
        OptionEntry::simple("log_as_local", OptionType::Bool),
        OptionEntry::simple("more", OptionType::Bool),
        OptionEntry::simple("pass_on_timeout", OptionType::Bool),
        OptionEntry::simple("pass_router", OptionType::StringPtr),
        OptionEntry::simple("local_part_prefix", OptionType::StringPtr),
        OptionEntry::simple("local_part_prefix_optional", OptionType::Bool),
        OptionEntry::simple("redirect_router", OptionType::StringPtr),
        OptionEntry::simple("remove_headers", OptionType::StringPtr),
        OptionEntry::simple("repeat_use", OptionType::Bool),
        OptionEntry::simple("require_files", OptionType::StringPtr),
        OptionEntry::simple("retry_use_local_part", OptionType::Bool),
        OptionEntry::simple("router_home_directory", OptionType::StringPtr),
        OptionEntry::simple("same_domain_copy_routing", OptionType::Bool),
        OptionEntry::simple("self", OptionType::StringPtr),
        OptionEntry::simple("self_rewrite", OptionType::Bool),
        OptionEntry::simple("senders", OptionType::StringPtr),
        OptionEntry::simple("local_part_suffix", OptionType::StringPtr),
        OptionEntry::simple("local_part_suffix_optional", OptionType::Bool),
        OptionEntry::simple("translate_ip_address", OptionType::StringPtr),
        OptionEntry::simple("transport", OptionType::StringPtr),
        OptionEntry::simple("unseen", OptionType::Bool),
        OptionEntry::simple("user", OptionType::Uid),
        OptionEntry::simple("verify_only", OptionType::Bool),
        OptionEntry::simple("verify_recipient", OptionType::Bool),
        OptionEntry::simple("verify_sender", OptionType::Bool),
    ];
    opts.sort_by(|a, b| a.name.cmp(b.name));

    if let Err(e) = validate_option_table(&opts, &["driver", "domains", "transport"]) {
        tracing::error!(error = %e, "router option table validation failed");
    }

    opts
}

/// Build the generic option table for transport drivers.
///
/// These are the options common to all transport instances, equivalent to
/// `optionlist_transports[]` in C globals.c. They correspond to fields in
/// `TransportInstanceConfig`.
fn build_transport_generic_options() -> Vec<OptionEntry> {
    let mut opts = vec![
        OptionEntry::simple("batch_id", OptionType::StringPtr),
        OptionEntry::simple("batch_max", OptionType::Int),
        OptionEntry::simple("body_only", OptionType::Bool),
        OptionEntry::simple("connection_max_messages", OptionType::Int),
        OptionEntry::simple("current_directory", OptionType::StringPtr),
        OptionEntry::simple("debug_string", OptionType::StringPtr),
        OptionEntry::simple("deliver_as_creator", OptionType::Bool),
        OptionEntry::simple("delivery_date_add", OptionType::Bool),
        OptionEntry::simple("disable_logging", OptionType::Bool),
        OptionEntry::simple("driver", OptionType::StringPtr),
        OptionEntry::simple("envelope_to_add", OptionType::Bool),
        OptionEntry::simple("event_action", OptionType::StringPtr),
        OptionEntry::simple("filter_command", OptionType::StringPtr),
        OptionEntry::simple("filter_timeout", OptionType::Time),
        OptionEntry::simple("group", OptionType::Gid),
        OptionEntry::simple("headers_add", OptionType::StringPtr),
        OptionEntry::simple("headers_only", OptionType::Bool),
        OptionEntry::simple("headers_remove", OptionType::StringPtr),
        OptionEntry::simple("headers_rewrite", OptionType::StringPtr),
        OptionEntry::simple("home_directory", OptionType::StringPtr),
        OptionEntry::simple("initgroups", OptionType::Bool),
        OptionEntry::simple("log_defer_output", OptionType::Bool),
        OptionEntry::simple("log_fail_output", OptionType::Bool),
        OptionEntry::simple("log_output", OptionType::Bool),
        OptionEntry::simple("max_addresses", OptionType::StringPtr),
        OptionEntry::simple("max_parallel", OptionType::StringPtr),
        OptionEntry::simple("message_size_limit", OptionType::StringPtr),
        OptionEntry::simple("multi_domain", OptionType::Bool),
        OptionEntry::simple("rcpt_include_affixes", OptionType::Bool),
        OptionEntry::simple("retry_use_local_part", OptionType::Bool),
        OptionEntry::simple("return_fail_output", OptionType::Bool),
        OptionEntry::simple("return_output", OptionType::Bool),
        OptionEntry::simple("return_path", OptionType::StringPtr),
        OptionEntry::simple("return_path_add", OptionType::Bool),
        OptionEntry::simple("shadow", OptionType::StringPtr),
        OptionEntry::simple("shadow_condition", OptionType::StringPtr),
        OptionEntry::simple("user", OptionType::Uid),
        OptionEntry::simple("warn_message", OptionType::StringPtr),
    ];
    opts.sort_by(|a, b| a.name.cmp(b.name));

    if let Err(e) = validate_option_table(&opts, &["driver", "batch_max"]) {
        tracing::error!(error = %e, "transport option table validation failed");
    }

    opts
}

// =============================================================================
// Instance config builders
// =============================================================================

/// Extract a string option value from a list of option results by name.
fn extract_string_option(options: &[HandleOptionResult], name: &str) -> Option<String> {
    for opt in options {
        if opt.name == name {
            if let OptionValue::Str(ref v) = opt.value {
                return Some(v.clone());
            }
        }
    }
    None
}

/// Extract a boolean option value from a list of option results by name.
/// Extract the expansion string from an `ExpandBool` option, if present.
///
/// In C Exim, expandable boolean options (e.g. `unseen = ${if ...}`)
/// store the expansion string in the `expand_<name>` slot. This helper
/// retrieves that string when an `ExpandBool` variant was parsed.
fn extract_expand_bool_string(options: &[HandleOptionResult], name: &str) -> Option<String> {
    for opt in options {
        if opt.name == name {
            if let OptionValue::ExpandBool(ref s) = opt.value {
                return Some(s.clone());
            }
        }
    }
    None
}

fn extract_bool_option(options: &[HandleOptionResult], name: &str, default: bool) -> bool {
    for opt in options {
        if opt.name == name {
            match &opt.value {
                OptionValue::Bool(v) => return *v,
                // ExpandBool: the expansion decides the runtime value;
                // the static bool defaults to true so that the option is
                // "set" and the expansion string will be consulted via
                // `expand_<name>` at runtime.
                OptionValue::ExpandBool(_) => return true,
                _ => {}
            }
        }
    }
    default
}

/// Extract an integer option value from a list of option results by name.
fn extract_int_option(options: &[HandleOptionResult], name: &str, default: i64) -> i64 {
    for opt in options {
        if opt.name == name {
            if let OptionValue::Int(v) = opt.value {
                return v;
            }
        }
    }
    default
}

/// Extract a time option value from a list of option results by name.
fn extract_time_option(options: &[HandleOptionResult], name: &str, default: i64) -> i64 {
    for opt in options {
        if opt.name == name {
            if let OptionValue::Time(v) = opt.value {
                return i64::from(v);
            }
        }
    }
    default
}

/// Extract a UID option value from a list of option results by name.
fn extract_uid_option(options: &[HandleOptionResult], name: &str, default: u32) -> u32 {
    for opt in options {
        if opt.name == name {
            if let OptionValue::Uid(v) = opt.value {
                return v;
            }
        }
    }
    default
}

/// Extract a GID option value from a list of option results by name.
fn extract_gid_option(options: &[HandleOptionResult], name: &str, default: u32) -> u32 {
    for opt in options {
        if opt.name == name {
            if let OptionValue::Gid(v) = opt.value {
                return v;
            }
        }
    }
    default
}

/// Build an `AuthInstanceConfig` from a `DriverParseState`.
fn build_auth_instance_config(state: &DriverParseState) -> Result<AuthInstanceConfig, ConfigError> {
    let public_name = extract_string_option(&state.generic_options, "public_name")
        .unwrap_or_else(|| state.base.driver_name.to_uppercase());

    let mut config = AuthInstanceConfig::new(
        state.base.name.clone(),
        state.base.driver_name.clone(),
        public_name,
        Box::new(state.private_options.clone()),
    );

    config.advertise_condition =
        extract_string_option(&state.generic_options, "advertise_condition");
    config.client_condition = extract_string_option(&state.generic_options, "client_condition");
    config.set_id = extract_string_option(&state.generic_options, "set_id");
    config.set_client_id = extract_string_option(&state.generic_options, "set_client_id");
    config.mail_auth_condition =
        extract_string_option(&state.generic_options, "mail_auth_condition");
    config.server_debug_string =
        extract_string_option(&state.generic_options, "server_debug_string");
    config.server_condition = extract_string_option(&state.generic_options, "server_condition");
    config.client = extract_bool_option(&state.generic_options, "client", false);
    config.server = extract_bool_option(&state.generic_options, "server", false);

    if let (Some(ref file), Some(line)) = (&state.base.srcfile, state.base.srcline) {
        config.srcfile = Some(file.clone());
        config.srcline = Some(line);
    }

    Ok(config)
}

/// Build a `RouterInstanceConfig` from a `DriverParseState`.
fn build_router_instance_config(
    state: &DriverParseState,
) -> Result<RouterInstanceConfig, ConfigError> {
    let config = RouterInstanceConfig {
        name: state.base.name.clone(),
        driver_name: state.base.driver_name.clone(),
        srcfile: state.base.srcfile.clone(),
        srcline: state.base.srcline,
        address_data: extract_string_option(&state.generic_options, "address_data"),
        cannot_route_message: extract_string_option(&state.generic_options, "cannot_route_message"),
        condition: extract_string_option(&state.generic_options, "condition"),
        current_directory: extract_string_option(&state.generic_options, "current_directory"),
        debug_string: extract_string_option(&state.generic_options, "debug_string"),
        domains: extract_string_option(&state.generic_options, "domains"),
        errors_to: extract_string_option(&state.generic_options, "errors_to"),
        expand_gid: extract_string_option(&state.generic_options, "expand_gid"),
        expand_uid: extract_string_option(&state.generic_options, "expand_uid"),
        expand_more: extract_string_option(&state.generic_options, "expand_more"),
        expand_unseen: extract_expand_bool_string(&state.generic_options, "unseen")
            .or_else(|| extract_string_option(&state.generic_options, "expand_unseen")),
        // C Exim: "headers_add" is the user-facing config option name that
        // populates the router's extra_headers field.  Check both keys so that
        // `headers_add = ...` in a router block is correctly handled.
        extra_headers: extract_string_option(&state.generic_options, "extra_headers")
            .or_else(|| extract_string_option(&state.generic_options, "headers_add")),
        fallback_hosts: extract_string_option(&state.generic_options, "fallback_hosts"),
        fallback_hostlist: Vec::new(),
        home_directory: extract_string_option(&state.generic_options, "home_directory"),
        ignore_target_hosts: extract_string_option(&state.generic_options, "ignore_target_hosts"),
        local_parts: extract_string_option(&state.generic_options, "local_parts"),
        pass_router_name: extract_string_option(&state.generic_options, "pass_router"),
        prefix: extract_string_option(&state.generic_options, "local_part_prefix"),
        redirect_router_name: extract_string_option(&state.generic_options, "redirect_router"),
        remove_headers: extract_string_option(&state.generic_options, "remove_headers"),
        require_files: extract_string_option(&state.generic_options, "require_files"),
        router_home_directory: extract_string_option(
            &state.generic_options,
            "router_home_directory",
        ),
        self_config: extract_string_option(&state.generic_options, "self"),
        senders: extract_string_option(&state.generic_options, "senders"),
        set: extract_string_option(&state.generic_options, "set"),
        suffix: extract_string_option(&state.generic_options, "local_part_suffix"),
        translate_ip_address: extract_string_option(&state.generic_options, "translate_ip_address"),
        transport_name: extract_string_option(&state.generic_options, "transport"),
        address_test: extract_bool_option(&state.generic_options, "address_test", true),
        expn: extract_bool_option(&state.generic_options, "expn", true),
        caseful_local_part: extract_bool_option(
            &state.generic_options,
            "caseful_local_part",
            false,
        ),
        check_local_user: extract_bool_option(&state.generic_options, "check_local_user", false),
        disable_logging: extract_bool_option(&state.generic_options, "disable_logging", false),
        fail_verify_recipient: false,
        fail_verify_sender: false,
        gid_set: false,
        initgroups: extract_bool_option(&state.generic_options, "initgroups", false),
        log_as_local: extract_bool_option(&state.generic_options, "log_as_local", false),
        more: extract_bool_option(&state.generic_options, "more", true),
        pass_on_timeout: extract_bool_option(&state.generic_options, "pass_on_timeout", false),
        prefix_optional: extract_bool_option(
            &state.generic_options,
            "local_part_prefix_optional",
            false,
        ),
        repeat_use: extract_bool_option(&state.generic_options, "repeat_use", true),
        retry_use_local_part: extract_bool_option(
            &state.generic_options,
            "retry_use_local_part",
            true,
        ),
        same_domain_copy_routing: extract_bool_option(
            &state.generic_options,
            "same_domain_copy_routing",
            false,
        ),
        self_rewrite: extract_bool_option(&state.generic_options, "self_rewrite", false),
        suffix_optional: extract_bool_option(
            &state.generic_options,
            "local_part_suffix_optional",
            false,
        ),
        verify_only: extract_bool_option(&state.generic_options, "verify_only", false),
        verify_recipient: extract_bool_option(&state.generic_options, "verify_recipient", true),
        verify_sender: extract_bool_option(&state.generic_options, "verify_sender", true),
        uid_set: false,
        unseen: extract_bool_option(&state.generic_options, "unseen", false),
        dsn_lasthop: extract_bool_option(&state.generic_options, "dsn_lasthop", false),
        self_code: 1, // Default self_code = "freeze"
        uid: extract_uid_option(&state.generic_options, "user", 0),
        gid: extract_gid_option(&state.generic_options, "group", 0),
        options: Box::new(state.private_options.clone()),
        private_options_map: {
            let mut map = std::collections::HashMap::new();
            for opt in &state.private_options {
                // Extract the value part from the raw line stored in the
                // OptionValue::Str. The raw line is "name = value", so we
                // split on '=' and take everything after.
                if let OptionValue::Str(ref raw_line) = opt.value {
                    if let Some(eq_pos) = raw_line.find('=') {
                        let val = raw_line[eq_pos + 1..].trim();
                        // Strip surrounding double-quotes from Exim config
                        // syntax (e.g. `data = "..."` → value without quotes).
                        let val = strip_config_quotes(val);
                        map.insert(opt.name.clone(), val);
                    } else {
                        // Boolean-style option without '=' — store empty value
                        map.insert(opt.name.clone(), String::new());
                    }
                }
            }
            map
        },
    };

    Ok(config)
}

/// Strip surrounding Exim config double-quotes from a value string.
///
/// In Exim configuration files, string values may be quoted with `"..."`.
/// This function removes those outer quotes and processes basic escape
/// sequences (`\\` → `\`, `\"` → `"`, `\n` → newline).
/// Backslash-newline continuation is collapsed (the `\` + newline are
/// removed, and leading whitespace on the next line is preserved as-is
/// since the config parser already joined continuation lines).
fn strip_config_quotes(s: &str) -> String {
    let trimmed = s.trim();

    // Check for outer double-quotes
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        let inner = &trimmed[1..trimmed.len() - 1];
        let mut result = String::with_capacity(inner.len());
        let mut chars = inner.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                match chars.peek() {
                    Some(&'n') => {
                        chars.next();
                        result.push('\n');
                    }
                    Some(&'\\') => {
                        chars.next();
                        result.push('\\');
                    }
                    Some(&'"') => {
                        chars.next();
                        result.push('"');
                    }
                    Some(&'t') => {
                        chars.next();
                        result.push('\t');
                    }
                    _ => {
                        // Unknown escape — keep the backslash
                        result.push('\\');
                    }
                }
            } else {
                result.push(ch);
            }
        }
        result
    } else {
        trimmed.to_string()
    }
}

/// Build a `TransportInstanceConfig` from a `DriverParseState`.
fn build_transport_instance_config(
    state: &DriverParseState,
) -> Result<TransportInstanceConfig, ConfigError> {
    let config = TransportInstanceConfig {
        name: state.base.name.clone(),
        driver_name: state.base.driver_name.clone(),
        srcfile: state.base.srcfile.clone(),
        srcline: state.base.srcline,
        batch_max: extract_int_option(&state.generic_options, "batch_max", 1) as i32,
        batch_id: extract_string_option(&state.generic_options, "batch_id"),
        home_dir: extract_string_option(&state.generic_options, "home_directory"),
        current_dir: extract_string_option(&state.generic_options, "current_directory"),
        expand_multi_domain: None,
        multi_domain: extract_bool_option(&state.generic_options, "multi_domain", false),
        overrides_hosts: false,
        max_addresses: extract_string_option(&state.generic_options, "max_addresses"),
        connection_max_messages: extract_int_option(
            &state.generic_options,
            "connection_max_messages",
            0,
        ) as i32,
        deliver_as_creator: extract_bool_option(
            &state.generic_options,
            "deliver_as_creator",
            false,
        ),
        disable_logging: extract_bool_option(&state.generic_options, "disable_logging", false),
        initgroups: extract_bool_option(&state.generic_options, "initgroups", false),
        uid_set: false,
        gid_set: false,
        uid: extract_uid_option(&state.generic_options, "user", 0),
        gid: extract_gid_option(&state.generic_options, "group", 0),
        expand_uid: None,
        expand_gid: None,
        warn_message: extract_string_option(&state.generic_options, "warn_message"),
        shadow: extract_string_option(&state.generic_options, "shadow"),
        shadow_condition: extract_string_option(&state.generic_options, "shadow_condition"),
        filter_command: extract_string_option(&state.generic_options, "filter_command"),
        filter_timeout: extract_time_option(&state.generic_options, "filter_timeout", 300) as i32,
        event_action: extract_string_option(&state.generic_options, "event_action"),
        add_headers: extract_string_option(&state.generic_options, "headers_add"),
        remove_headers: extract_string_option(&state.generic_options, "headers_remove"),
        return_path: extract_string_option(&state.generic_options, "return_path"),
        debug_string: extract_string_option(&state.generic_options, "debug_string"),
        max_parallel: extract_string_option(&state.generic_options, "max_parallel"),
        message_size_limit: extract_string_option(&state.generic_options, "message_size_limit"),
        headers_rewrite: extract_string_option(&state.generic_options, "headers_rewrite"),
        body_only: extract_bool_option(&state.generic_options, "body_only", false),
        delivery_date_add: extract_bool_option(&state.generic_options, "delivery_date_add", false),
        envelope_to_add: extract_bool_option(&state.generic_options, "envelope_to_add", false),
        headers_only: extract_bool_option(&state.generic_options, "headers_only", false),
        rcpt_include_affixes: extract_bool_option(
            &state.generic_options,
            "rcpt_include_affixes",
            false,
        ),
        return_path_add: extract_bool_option(&state.generic_options, "return_path_add", false),
        return_output: extract_bool_option(&state.generic_options, "return_output", false),
        return_fail_output: extract_bool_option(
            &state.generic_options,
            "return_fail_output",
            false,
        ),
        log_output: extract_bool_option(&state.generic_options, "log_output", false),
        log_fail_output: extract_bool_option(&state.generic_options, "log_fail_output", false),
        log_defer_output: extract_bool_option(&state.generic_options, "log_defer_output", false),
        retry_use_local_part: extract_bool_option(
            &state.generic_options,
            "retry_use_local_part",
            true,
        ),
        options: Box::new(state.private_options.clone()),
        private_options_map: {
            let mut map = std::collections::HashMap::new();
            for opt in &state.private_options {
                // Extract the value part from the raw line stored in the
                // OptionValue::Str. The raw line is "name = value", so we
                // split on '=' and take everything after.
                if let OptionValue::Str(ref raw_line) = opt.value {
                    if let Some(eq_pos) = raw_line.find('=') {
                        let val = raw_line[eq_pos + 1..].trim();
                        let val = strip_config_quotes(val);
                        map.insert(opt.name.clone(), val);
                    } else {
                        // Boolean-style option without '=' — store empty value
                        map.insert(opt.name.clone(), String::new());
                    }
                }
            }
            map
        },
    };

    Ok(config)
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_driver_class_display() {
        assert_eq!(DriverClass::Authenticator.as_str(), "authenticator");
        assert_eq!(DriverClass::Router.as_str(), "router");
        assert_eq!(DriverClass::Transport.as_str(), "transport");
        assert_eq!(DriverClass::Authenticator.plural(), "authenticators");
        assert_eq!(DriverClass::Router.plural(), "routers");
        assert_eq!(DriverClass::Transport.plural(), "transports");
        assert_eq!(format!("{}", DriverClass::Authenticator), "authenticator");
    }

    #[test]
    fn test_driver_class_equality() {
        assert_eq!(DriverClass::Authenticator, DriverClass::Authenticator);
        assert_ne!(DriverClass::Authenticator, DriverClass::Router);
        assert_ne!(DriverClass::Router, DriverClass::Transport);
    }

    #[test]
    fn test_driver_class_hash() {
        let mut map: HashMap<DriverClass, &str> = HashMap::new();
        map.insert(DriverClass::Authenticator, "auth");
        map.insert(DriverClass::Router, "route");
        map.insert(DriverClass::Transport, "transport");
        assert_eq!(map.get(&DriverClass::Authenticator), Some(&"auth"));
        assert_eq!(map.get(&DriverClass::Router), Some(&"route"));
        assert_eq!(map.get(&DriverClass::Transport), Some(&"transport"));
    }

    #[test]
    fn test_check_driver_depends_finds_dollar_prefix() {
        let base = DriverInstanceBase::new("test_driver", "test_type");
        let opts = vec![HandleOptionResult {
            name: "some_option".to_string(),
            value: OptionValue::Str("prefix $sender_domain suffix".to_string()),
            is_secure: false,
            is_negated: false,
        }];
        assert!(check_driver_depends(&base, &opts, "sender_domain"));
    }

    #[test]
    fn test_check_driver_depends_finds_brace_prefix() {
        let base = DriverInstanceBase::new("test_driver", "test_type");
        let opts = vec![HandleOptionResult {
            name: "condition".to_string(),
            value: OptionValue::Str("some ${sender_domain} text".to_string()),
            is_secure: false,
            is_negated: false,
        }];
        assert!(check_driver_depends(&base, &opts, "sender_domain"));
    }

    #[test]
    fn test_check_driver_depends_no_match() {
        let base = DriverInstanceBase::new("test_driver", "test_type");
        let opts = vec![HandleOptionResult {
            name: "some_option".to_string(),
            value: OptionValue::Str("no expansion here".to_string()),
            is_secure: false,
            is_negated: false,
        }];
        assert!(!check_driver_depends(&base, &opts, "sender_domain"));
    }

    #[test]
    fn test_check_driver_depends_substring_not_variable() {
        let base = DriverInstanceBase::new("test_driver", "test_type");
        let opts = vec![HandleOptionResult {
            name: "some_option".to_string(),
            value: OptionValue::Str("my_sender_domain_value".to_string()),
            is_secure: false,
            is_negated: false,
        }];
        // "sender_domain" appears but not preceded by $ or {
        assert!(!check_driver_depends(&base, &opts, "sender_domain"));
    }

    #[test]
    fn test_check_driver_depends_followed_by_alpha() {
        let base = DriverInstanceBase::new("test_driver", "test_type");
        let opts = vec![HandleOptionResult {
            name: "some_option".to_string(),
            value: OptionValue::Str("$sender_domainname".to_string()),
            is_secure: false,
            is_negated: false,
        }];
        // "sender_domain" is followed by "name" (alphanumeric), so not a match.
        assert!(!check_driver_depends(&base, &opts, "sender_domain"));
    }

    #[test]
    fn test_check_driver_depends_at_end_of_string() {
        let base = DriverInstanceBase::new("test_driver", "test_type");
        let opts = vec![HandleOptionResult {
            name: "option".to_string(),
            value: OptionValue::Str("value $sender_domain".to_string()),
            is_secure: false,
            is_negated: false,
        }];
        assert!(check_driver_depends(&base, &opts, "sender_domain"));
    }

    #[test]
    fn test_check_driver_depends_empty_options() {
        let base = DriverInstanceBase::new("test_driver", "test_type");
        let opts: Vec<HandleOptionResult> = Vec::new();
        assert!(!check_driver_depends(&base, &opts, "anything"));
    }

    #[test]
    fn test_check_driver_depends_non_string_option() {
        let base = DriverInstanceBase::new("test_driver", "test_type");
        let opts = vec![HandleOptionResult {
            name: "batch_max".to_string(),
            value: OptionValue::Int(10),
            is_secure: false,
            is_negated: false,
        }];
        assert!(!check_driver_depends(&base, &opts, "batch_max"));
    }

    #[test]
    fn test_check_driver_depends_multiple_options() {
        let base = DriverInstanceBase::new("test_driver", "test_type");
        let opts = vec![
            HandleOptionResult {
                name: "option1".to_string(),
                value: OptionValue::Str("no match here".to_string()),
                is_secure: false,
                is_negated: false,
            },
            HandleOptionResult {
                name: "option2".to_string(),
                value: OptionValue::Str("but $local_part matches".to_string()),
                is_secure: false,
                is_negated: false,
            },
        ];
        assert!(check_driver_depends(&base, &opts, "local_part"));
        assert!(!check_driver_depends(&base, &opts, "domain"));
    }

    #[test]
    fn test_build_auth_generic_options_sorted() {
        let opts = build_auth_generic_options();
        for window in opts.windows(2) {
            assert!(
                window[0].name <= window[1].name,
                "options not sorted: {} > {}",
                window[0].name,
                window[1].name
            );
        }
        // Verify critical options exist via find_option binary search.
        assert!(find_option("driver", &opts).is_some());
        assert!(find_option("public_name", &opts).is_some());
        assert!(find_option("server", &opts).is_some());
        assert!(find_option("client", &opts).is_some());
    }

    #[test]
    fn test_build_router_generic_options_sorted() {
        let opts = build_router_generic_options();
        for window in opts.windows(2) {
            assert!(
                window[0].name <= window[1].name,
                "options not sorted: {} > {}",
                window[0].name,
                window[1].name
            );
        }
        assert!(find_option("driver", &opts).is_some());
        assert!(find_option("domains", &opts).is_some());
        assert!(find_option("transport", &opts).is_some());
        assert!(find_option("condition", &opts).is_some());
    }

    #[test]
    fn test_build_transport_generic_options_sorted() {
        let opts = build_transport_generic_options();
        for window in opts.windows(2) {
            assert!(
                window[0].name <= window[1].name,
                "options not sorted: {} > {}",
                window[0].name,
                window[1].name
            );
        }
        assert!(find_option("driver", &opts).is_some());
        assert!(find_option("batch_max", &opts).is_some());
        assert!(find_option("filter_timeout", &opts).is_some());
        assert!(find_option("event_action", &opts).is_some());
    }

    #[test]
    fn test_config_lines_basic() {
        let lines = vec![
            ("my_auth:".to_string(), 1),
            ("  driver = plaintext".to_string(), 2),
            ("  public_name = PLAIN".to_string(), 3),
        ];
        let mut reader = ConfigLines::new(&lines, "test.conf");
        let (l, n) = reader.next_line().unwrap();
        assert_eq!(l, "my_auth:");
        assert_eq!(n, 1);
        let (l, n) = reader.next_line().unwrap();
        assert_eq!(l, "driver = plaintext");
        assert_eq!(n, 2);
    }

    #[test]
    fn test_config_lines_skip_comments() {
        let lines = vec![
            ("# comment".to_string(), 1),
            ("".to_string(), 2),
            ("real_line".to_string(), 3),
        ];
        let mut reader = ConfigLines::new(&lines, "test.conf");
        let (l, n) = reader.next_line().unwrap();
        assert_eq!(l, "real_line");
        assert_eq!(n, 3);
    }

    #[test]
    fn test_config_lines_peek() {
        let lines = vec![("line1".to_string(), 1), ("line2".to_string(), 2)];
        let reader = ConfigLines::new(&lines, "test.conf");
        let (l, n) = reader.peek().unwrap();
        assert_eq!(l, "line1");
        assert_eq!(n, 1);
        // Peek again — should return the same.
        let (l2, n2) = reader.peek().unwrap();
        assert_eq!(l2, "line1");
        assert_eq!(n2, 1);
    }

    #[test]
    fn test_config_lines_exhausted() {
        let lines: Vec<(String, u32)> = Vec::new();
        let mut reader = ConfigLines::new(&lines, "test.conf");
        assert!(reader.next_line().is_none());
    }

    #[test]
    fn test_show_supported_drivers() {
        // This exercises the formatted output path; with no drivers
        // registered in test mode, it produces an empty or minimal output.
        let output = show_supported_drivers();
        // Output is a string, verify it can be generated without panics.
        let _ = output.len();
    }

    #[test]
    fn test_resolve_driver_not_found() {
        // No drivers are registered in test mode, so this should fail.
        let result = resolve_driver("nonexistent_driver", DriverClass::Authenticator);
        assert!(result.is_err());
        if let Err(ConfigError::UnknownDriver(msg)) = result {
            assert!(msg.contains("nonexistent_driver"));
            assert!(msg.contains("authenticator"));
        } else {
            panic!("expected UnknownDriver error");
        }
    }

    #[test]
    fn test_resolve_driver_not_found_router() {
        let result = resolve_driver("nonexistent", DriverClass::Router);
        assert!(result.is_err());
        if let Err(ConfigError::UnknownDriver(msg)) = result {
            assert!(msg.contains("router"));
        } else {
            panic!("expected UnknownDriver error");
        }
    }

    #[test]
    fn test_resolve_driver_not_found_transport() {
        let result = resolve_driver("nonexistent", DriverClass::Transport);
        assert!(result.is_err());
        if let Err(ConfigError::UnknownDriver(msg)) = result {
            assert!(msg.contains("transport"));
        } else {
            panic!("expected UnknownDriver error");
        }
    }

    #[test]
    fn test_extract_string_option() {
        let opts = vec![
            HandleOptionResult {
                name: "driver".to_string(),
                value: OptionValue::Str("plaintext".to_string()),
                is_secure: false,
                is_negated: false,
            },
            HandleOptionResult {
                name: "public_name".to_string(),
                value: OptionValue::Str("PLAIN".to_string()),
                is_secure: false,
                is_negated: false,
            },
        ];
        assert_eq!(
            extract_string_option(&opts, "driver"),
            Some("plaintext".to_string())
        );
        assert_eq!(
            extract_string_option(&opts, "public_name"),
            Some("PLAIN".to_string())
        );
        assert_eq!(extract_string_option(&opts, "nonexistent"), None);
    }

    #[test]
    fn test_extract_bool_option() {
        let opts = vec![HandleOptionResult {
            name: "server".to_string(),
            value: OptionValue::Bool(true),
            is_secure: false,
            is_negated: false,
        }];
        assert!(extract_bool_option(&opts, "server", false));
        assert!(!extract_bool_option(&opts, "client", false));
        assert!(extract_bool_option(&opts, "missing", true));
    }

    #[test]
    fn test_extract_int_option() {
        let opts = vec![HandleOptionResult {
            name: "batch_max".to_string(),
            value: OptionValue::Int(100),
            is_secure: false,
            is_negated: false,
        }];
        assert_eq!(extract_int_option(&opts, "batch_max", 1), 100);
        assert_eq!(extract_int_option(&opts, "missing", 42), 42);
    }

    #[test]
    fn test_extract_uid_gid_options() {
        let opts = vec![
            HandleOptionResult {
                name: "user".to_string(),
                value: OptionValue::Uid(1000),
                is_secure: false,
                is_negated: false,
            },
            HandleOptionResult {
                name: "group".to_string(),
                value: OptionValue::Gid(1001),
                is_secure: false,
                is_negated: false,
            },
        ];
        assert_eq!(extract_uid_option(&opts, "user", 0), 1000);
        assert_eq!(extract_gid_option(&opts, "group", 0), 1001);
        assert_eq!(extract_uid_option(&opts, "missing", 65534), 65534);
        assert_eq!(extract_gid_option(&opts, "missing", 65534), 65534);
    }

    #[test]
    fn test_string_contains_expansion_var() {
        // Dollar prefix
        assert!(string_contains_expansion_var("$domain", "domain"));
        // Brace prefix
        assert!(string_contains_expansion_var("${domain}", "domain"));
        // In context
        assert!(string_contains_expansion_var(
            "prefix $sender_domain suffix",
            "sender_domain"
        ));
        // Not a variable — no prefix
        assert!(!string_contains_expansion_var(
            "sender_domain",
            "sender_domain"
        ));
        // Not a variable — followed by alpha
        assert!(!string_contains_expansion_var(
            "$sender_domainname",
            "sender_domain"
        ));
        // Empty cases
        assert!(!string_contains_expansion_var("", "domain"));
        assert!(!string_contains_expansion_var("some text", ""));
        // Multiple occurrences, first not matching, second matching
        assert!(string_contains_expansion_var(
            "xsender_domain $sender_domain",
            "sender_domain"
        ));
    }

    #[test]
    fn test_validate_option_table() {
        let opts = build_auth_generic_options();
        assert!(validate_option_table(&opts, &["driver", "public_name"]).is_ok());
        assert!(validate_option_table(&opts, &["nonexistent"]).is_err());
    }

    #[test]
    fn test_driver_error_conversion() {
        let err = DriverError::NotFound {
            name: "test".to_string(),
        };
        let config_err = driver_error_to_config_error(err, "test");
        match config_err {
            ConfigError::UnknownDriver(msg) => assert!(msg.contains("test")),
            _ => panic!("expected UnknownDriver"),
        }

        let err2 = DriverError::InitFailed("init problem".to_string());
        let config_err2 = driver_error_to_config_error(err2, "driver2");
        match config_err2 {
            ConfigError::ValidationError(msg) => assert!(msg.contains("driver2")),
            _ => panic!("expected ValidationError"),
        }
    }

    #[test]
    fn test_check_driver_result() {
        assert!(check_driver_result(DriverResult::Ok, "test").is_ok());
        assert!(check_driver_result(DriverResult::Decline, "test").is_ok());
        assert!(check_driver_result(DriverResult::Pass, "test").is_ok());
        assert!(check_driver_result(DriverResult::Defer, "test").is_err());
        assert!(check_driver_result(DriverResult::Fail, "test").is_err());
        assert!(check_driver_result(DriverResult::Error, "test").is_err());
    }

    #[test]
    fn test_finalize_driver_no_driver_name() {
        let base = DriverInstanceBase::new("test_instance", "");
        let result = finalize_driver(&base, DriverClass::Authenticator, &[]);
        assert!(result.is_err());
        if let Err(ConfigError::ParseError { message, .. }) = result {
            assert!(message.contains("no driver defined"));
        } else {
            panic!("expected ParseError");
        }
    }

    #[test]
    fn test_freeze_config_returns_arc() {
        let ctx = ConfigContext::default();
        let frozen = freeze_config(ctx);
        // Verify it is shareable (can be cloned).
        let _clone = Arc::clone(&frozen);
    }

    #[test]
    fn test_find_lookup_factory_not_found() {
        // No lookup drivers registered in test mode.
        assert!(find_lookup_factory("nonexistent").is_none());
    }
}
