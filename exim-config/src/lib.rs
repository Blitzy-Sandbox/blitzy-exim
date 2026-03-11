//! Exim configuration parser crate.
//!
//! This crate provides the configuration file parser, option processing,
//! macro expansion, driver initialization, and validation for the Exim MTA.
//!
//! The primary public API is the [`types`] module, which defines all
//! configuration-related type definitions including [`types::ConfigContext`],
//! [`types::Config`], and the scoped context structs.
//!
//! The [`options`] module provides the option table definitions and typed
//! option handling that forms the backbone of the configuration system —
//! translating `readconf_handle_option()`, `find_option()`, and the
//! `optionlist_config[]` table from C `readconf.c`.

pub mod options;
pub mod types;
