//! Exim configuration parser crate.
//!
//! This crate provides the configuration file parser, option processing,
//! macro expansion, driver initialization, and validation for the Exim MTA.
//!
//! The primary public API is the [`types`] module, which defines all
//! configuration-related type definitions including [`types::ConfigContext`],
//! [`types::Config`], and the scoped context structs.

pub mod types;
