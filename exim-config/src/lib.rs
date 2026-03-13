#![forbid(unsafe_code)]
//! # exim-config — Exim MTA Configuration File Parser
//!
//! This crate provides the complete Exim configuration file parser, replacing
//! the C `readconf.c` (4,765 lines) with safe Rust.  It is the authoritative
//! bridge between raw configuration text and the typed [`ConfigContext`] that
//! all other crates in the workspace consume.
//!
//! ## Capabilities
//!
//! - **Full backward-compatible configuration syntax** — every valid Exim
//!   configuration file accepted by the C parser is accepted identically here.
//! - **Macro expansion** — `.define` directives and `$MACRO` references are
//!   expanded inline, matching C left-to-right scan semantics.
//! - **File inclusion** — `.include` and `.include_if_exists` directives with
//!   configurable nesting depth (up to 20 levels, matching C).
//! - **Conditional compilation** — `.ifdef` / `.ifndef` / `.elifdef` /
//!   `.elifndef` / `.else` / `.endif` blocks with a 10-level nesting stack.
//! - **Option processing** — typed option parsing for ~400 main configuration
//!   options plus driver-specific option tables (boolean, integer, time, string,
//!   UID/GID, rewrite rules, fixed-point, and more).
//! - **Driver initialization** — authenticator, router, and transport driver
//!   instances are created from configuration blocks and resolved via the
//!   `inventory`-based registry in [`exim-drivers`](exim_drivers).
//! - **Configuration validation** — post-parse validation of the complete
//!   configuration, checking for missing required options, conflicting settings,
//!   and unreachable drivers.
//! - **`-bP` printing** — full support for Exim's `-bP` query interface,
//!   including individual option queries, driver listing, named list display,
//!   and pre-parsed config display.
//!
//! ## Architecture
//!
//! After parsing, the [`ConfigContext`] is frozen into an [`Arc`]-wrapped
//! [`Config`] and shared immutably across all subsystems (per AAP §0.7.3).
//! No mutable shared configuration state exists after the parse phase.
//!
//! Driver instances are resolved through the compile-time `inventory`-based
//! registry from the `exim-drivers` crate (per AAP §0.7.3), replacing the C
//! `auths_available` / `routers_available` / `transports_available` linked
//! lists.
//!
//! ## Module Organization
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`types`] | Core type definitions: [`ConfigContext`], [`Config`], [`ConfigError`] |
//! | [`parser`] | Configuration file parser: [`parse_main_config()`], [`parse_rest()`] |
//! | [`options`] | Option table definitions and typed option handling |
//! | [`macros`] | Macro expansion, `.include`, `.ifdef`/`.endif` conditionals |
//! | [`driver_init`] | Driver instance creation: [`init_drivers()`] |
//! | [`validate`] | Validation and `-bP` printing: [`validate_config()`], [`print_config_option()`] |
//!
//! ## Safety
//!
//! This crate contains **zero** `unsafe` code (enforced by `#![forbid(unsafe_code)]`).
//! All unsafe operations are confined to the `exim-ffi` crate per AAP §0.7.2.

// ---------------------------------------------------------------------------
// Module declarations
// ---------------------------------------------------------------------------

/// Core type definitions: [`ConfigContext`], [`Config`], [`ConfigError`],
/// and supporting types for rewrite rules, retry configuration, named lists,
/// syslog facilities, and macro snapshots.
pub mod types;

/// Configuration file parser providing [`parse_main_config()`] and
/// [`parse_rest()`] for full configuration ingestion.
pub mod parser;

/// Option table definitions and typed option handling for all driver types.
/// Contains [`OptionType`](options::OptionType), [`OptionFlags`](options::OptionFlags),
/// [`OptionEntry`](options::OptionEntry), and the ~400-entry
/// [`MAIN_CONFIG_OPTIONS`](options::MAIN_CONFIG_OPTIONS) table.
pub mod options;

/// Macro expansion, conditional processing (`.ifdef`/`.endif`), and
/// `.include` directive handling.
pub mod macros;

/// Driver instance creation from configuration blocks using the
/// `inventory`-based registry from `exim-drivers`.
pub mod driver_init;

/// Configuration validation and `-bP` option printing.
pub mod validate;

// ---------------------------------------------------------------------------
// Public API re-exports
// ---------------------------------------------------------------------------

// Core types — the fundamental configuration data structures that all
// downstream crates consume.
pub use types::Config;
pub use types::ConfigContext;
pub use types::ConfigError;

// Configuration parsing entry points — equivalent of the C readconf_main()
// and readconf_rest() functions from readconf.c.
pub use parser::parse_main_config;
pub use parser::parse_rest;

// Driver initialization — equivalent of the C readconf_driver_init() function
// from readconf.c, creating typed driver instances from configuration blocks.
pub use driver_init::init_drivers;

// Validation and printing — equivalent of the C readconf_print() and
// print_config() functions, plus a new post-parse validation API.
pub use validate::print_config_option;
pub use validate::print_formatted_config;
pub use validate::validate_config;
