//! # exim-ffi — Foreign Function Interface Bindings for Exim
//!
//! This crate is the **ONLY** crate in the Exim Rust workspace that is
//! permitted to contain `unsafe` code (per AAP §0.7.2). It provides safe
//! Rust wrappers around C libraries that have no viable pure-Rust replacement.
//!
//! Every `unsafe` block within this crate MUST have an inline justification
//! comment explaining why the unsafe operation is necessary and why it is
//! sound. The total number of `unsafe` blocks across all modules MUST remain
//! below 50 (AAP §0.7.2).
//!
//! # Feature-Gated Modules
//!
//! Each FFI module is gated behind a Cargo feature flag. Only modules whose
//! corresponding system library is present on the build host should be enabled.
//! This replaces the C preprocessor `#ifdef` pattern used in the original Exim
//! source tree.
//!
//! | Feature          | C Library          | Module          | Purpose                         |
//! |------------------|--------------------|-----------------|----------------------------------|
//! | `ffi-pam`        | libpam             | `pam`           | PAM authentication               |
//! | `ffi-radius`     | libradius          | `radius`        | RADIUS authentication            |
//! | `ffi-perl`       | libperl            | `perl`          | Embedded Perl interpreter        |
//! | `ffi-gsasl`      | libgsasl           | `gsasl`         | GNU SASL (SCRAM, channel-bind)   |
//! | `ffi-krb5`       | libkrb5/Heimdal    | `krb5`          | Kerberos GSSAPI authentication   |
//! | `ffi-spf`        | libspf2            | [`spf`]         | SPF validation                   |
//!
//! # Hints Database Backends
//!
//! | Feature          | C Library          | Purpose                          |
//! |------------------|--------------------|----------------------------------|
//! | `hintsdb-bdb`    | libdb              | Berkeley DB hints backend        |
//! | `hintsdb-gdbm`   | libgdbm            | GDBM hints backend               |
//! | `hintsdb-ndbm`   | libndbm            | NDBM hints backend               |
//! | `hintsdb-tdb`    | libtdb             | TDB hints backend                |
//!
//! # Safety Policy
//!
//! - **Zero `unsafe` outside this crate** — all other workspace crates must be
//!   100% safe Rust.
//! - **All `unsafe` blocks documented** — every block has an inline comment
//!   explaining soundness.
//! - **No `#[allow(...)]`** without inline justification referencing a specific
//!   technical reason.
//! - **RAII for all C resources** — every raw pointer is wrapped in a struct
//!   with a `Drop` implementation that calls the appropriate C free function.

// Feature-gated module declarations.
// Each module is only compiled when its corresponding feature is enabled,
// ensuring that the system library headers and link libraries are only
// required when explicitly requested.
//
// NOTE: Module declarations for pam, radius, perl, gsasl, krb5, and hintsdb
// will be added by their respective implementation agents when those files
// are created. Only modules with source files present on disk are declared
// below to avoid rustfmt resolution errors.

/// RADIUS authentication bindings (wraps libradius/radiusclient/freeradiusclient).
/// Source: src/src/miscmods/radius.c — replaces RADIUS_CONFIG_FILE preprocessor conditional
#[cfg(feature = "ffi-radius")]
pub mod radius;

#[cfg(feature = "ffi-gsasl")]
pub mod gsasl;

#[cfg(feature = "ffi-krb5")]
pub mod krb5;

#[cfg(feature = "ffi-perl")]
pub mod perl;

#[cfg(feature = "ffi-pam")]
pub mod pam;

#[cfg(feature = "ffi-spf")]
pub mod spf;

/// DMARC policy evaluation bindings (wraps libopendmarc).
/// Source: src/src/miscmods/dmarc.c — replaces SUPPORT_DMARC preprocessor conditional
#[cfg(feature = "ffi-dmarc")]
pub mod dmarc;
