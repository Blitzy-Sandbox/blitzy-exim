#![deny(unsafe_code)]
//! Lookup module implementations for the Exim MTA.
//!
//! This crate replaces the entire `src/src/lookups/` directory from the C
//! codebase. It provides 22+ lookup backends plus shared helper functions,
//! each backend implementing the `LookupDriver` trait from `exim-drivers`.

pub mod helpers;

#[cfg(feature = "lookup-mysql")]
pub mod mysql;

#[cfg(feature = "lookup-lmdb")]
pub mod lmdb;

#[cfg(feature = "lookup-pgsql")]
pub mod pgsql;

#[cfg(feature = "lookup-ldap")]
pub mod ldap;

#[cfg(feature = "lookup-redis")]
pub mod redis;
