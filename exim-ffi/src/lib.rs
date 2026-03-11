//! # exim-ffi — Minimal C FFI Shim Layer for Exim
//!
//! This crate is the **ONLY** crate in the Exim Rust workspace that contains
//! `unsafe` code. It wraps C libraries that have no viable Rust-native
//! replacement, providing safe Rust APIs over the raw C interfaces.
//!
//! ## Wrapped Libraries
//!
//! Each library is gated behind a Cargo feature flag, replacing the C
//! preprocessor `#ifdef` pattern from the original Exim source tree:
//!
//! | Feature | Library | Module | Purpose |
//! |---------|---------|--------|---------|
//! | `ffi-pam` | libpam | [`pam`] | PAM authentication with conversation callback |
//! | `ffi-radius` | libradius/radiusclient | [`radius`] | RADIUS authentication |
//! | `ffi-perl` | libperl | [`perl`] | Embedded Perl interpreter for `${perl}` |
//! | `ffi-gsasl` | libgsasl | [`gsasl`] | GNU SASL (SCRAM, channel-binding) |
//! | `ffi-krb5` | libkrb5/Heimdal | [`krb5`] | Kerberos GSSAPI authentication |
//! | `ffi-spf` | libspf2 | [`spf`] | SPF validation with DNS callback support |
//! | `ffi-dmarc` | libopendmarc | [`dmarc`] | DMARC policy evaluation |
//! | `ffi-oracle` | libclntsh | [`oracle`] | Oracle OCI v2 SQL lookups |
//! | `ffi-whoson` | libwhoson | [`whoson`] | WHOSON dynamic IP tracking |
//! | `ffi-nisplus` | libnsl (NIS+) | [`nisplus`] | NIS+ directory service lookups |
//! | `ffi-nis` | libnsl (NIS/YP) | [`nis`] | NIS (Yellow Pages) directory lookups |
//! | `ffi-cyrus-sasl` | libsasl2 | [`cyrus_sasl`] | Cyrus SASL server authentication |
//! | `ffi-lmdb` | heed (LMDB) | [`lmdb`] | LMDB environment safe open wrapper |
//!
//! ## Hints Database Backends
//!
//! The [`hintsdb`] module is always compiled (no top-level feature gate); each
//! backend is feature-gated internally:
//!
//! | Feature | Library | Purpose |
//! |---------|---------|---------|
//! | `hintsdb-bdb` | Berkeley DB | BDB hints database backend |
//! | `hintsdb-gdbm` | GDBM | GDBM hints database backend |
//! | `hintsdb-ndbm` | NDBM | NDBM hints database backend |
//! | `hintsdb-tdb` | TDB | TDB hints database backend |
//!
//! SQLite hints are **not** in this crate — they use the pure-Rust `rusqlite`
//! crate in `exim-lookups` instead.
//!
//! ## Always-Compiled Utility Modules
//!
//! Two utility modules have no external C library dependency beyond the Rust
//! standard library and the `nix` crate:
//!
//! - [`fd`] — Safe raw file-descriptor conversions (`FromRawFd` wrapper)
//! - [`signal`] — Safe POSIX signal handling (`sigaction` wrapper)
//!
//! ## Safety Policy
//!
//! - **Zero `unsafe` outside this crate** — all other 17 workspace crates
//!   enforce `#![deny(unsafe_code)]` and consume only safe public APIs from
//!   this crate. Any `unsafe` code found outside `exim-ffi` is a **blocking
//!   defect** per AAP §0.7.2.
//! - **All `unsafe` blocks documented** — every `unsafe` block has an inline
//!   `// SAFETY:` comment explaining why the operation is necessary and why
//!   it is sound.
//! - **RAII for all C resources** — every raw C pointer is wrapped in a
//!   struct with a `Drop` implementation that calls the appropriate C free
//!   function, preventing resource leaks even on early returns or panics.
//! - **No `#[allow(...)]`** without inline justification referencing a
//!   specific technical reason.
//! - **`RUSTFLAGS="-D warnings"`** and **`cargo clippy -- -D warnings`**
//!   must produce zero diagnostics.
//!
//! ## C Preprocessor → Cargo Feature Mapping
//!
//! For code review traceability, the following table documents which C
//! preprocessor conditional each Cargo feature replaces:
//!
//! ```text
//! C Preprocessor          → Cargo Feature
//! ─────────────────────────────────────────────
//! SUPPORT_PAM             → ffi-pam
//! RADIUS_CONFIG_FILE      → ffi-radius
//! EXIM_PERL               → ffi-perl
//! AUTH_GSASL              → ffi-gsasl
//! AUTH_HEIMDAL_GSSAPI     → ffi-krb5
//! SUPPORT_SPF             → ffi-spf
//! SUPPORT_DMARC           → ffi-dmarc
//! LOOKUP_ORACLE           → ffi-oracle
//! LOOKUP_WHOSON           → ffi-whoson
//! LOOKUP_NISPLUS          → ffi-nisplus
//! LOOKUP_NIS              → ffi-nis
//! AUTH_CYRUS_SASL         → ffi-cyrus-sasl
//! USE_DB                  → hintsdb-bdb
//! USE_GDBM                → hintsdb-gdbm
//! USE_NDBM                → hintsdb-ndbm
//! USE_TDB                 → hintsdb-tdb
//! ```

// =============================================================================
// Always-compiled utility modules
// =============================================================================
//
// These modules provide safe wrappers around inherently-unsafe POSIX
// operations that are needed by multiple workspace crates. They are NOT
// feature-gated because they have no external C library dependency beyond
// the Rust standard library and the `nix` crate.

/// Safe raw-file-descriptor conversion utilities.
///
/// Provides a safe wrapper around the `FromRawFd` trait for converting
/// POSIX file descriptors into `std::net::TcpStream`. Consumed by
/// `exim-tls` backends.
pub mod fd;

/// Safe POSIX signal handling wrappers.
///
/// Provides a safe wrapper around `nix::sys::signal::sigaction()`.
/// Consumed by `exim-core/src/signal.rs`.
pub mod signal;

// =============================================================================
// Feature-gated C library FFI module declarations
// =============================================================================
//
// Each module below wraps a C library that has no viable Rust-native
// replacement (see AAP §0.6.2). Modules are only compiled when their
// corresponding Cargo feature is enabled, ensuring that system library
// headers and link libraries are only required when explicitly requested.

/// PAM authentication bindings (wraps libpam).
///
/// Source: `src/src/miscmods/pam.c` — replaces `SUPPORT_PAM` preprocessor
/// conditional.
#[cfg(feature = "ffi-pam")]
pub mod pam;

/// RADIUS authentication bindings (wraps libradius/radiusclient/freeradiusclient).
///
/// Source: `src/src/miscmods/radius.c` — replaces `RADIUS_CONFIG_FILE`
/// preprocessor conditional.
#[cfg(feature = "ffi-radius")]
pub mod radius;

/// Embedded Perl interpreter bindings (wraps libperl).
///
/// Source: `src/src/miscmods/perl.c` — replaces `EXIM_PERL` preprocessor
/// conditional.
#[cfg(feature = "ffi-perl")]
pub mod perl;

/// GNU SASL bindings (wraps libgsasl).
///
/// Source: `src/src/auths/gsasl.c` — replaces `AUTH_GSASL` preprocessor
/// conditional.
#[cfg(feature = "ffi-gsasl")]
pub mod gsasl;

/// Kerberos/GSSAPI bindings (wraps libkrb5/Heimdal).
///
/// Source: `src/src/auths/heimdal_gssapi.c` — replaces
/// `AUTH_HEIMDAL_GSSAPI` preprocessor conditional.
#[cfg(feature = "ffi-krb5")]
pub mod krb5;

/// SPF validation bindings (wraps libspf2).
///
/// Source: `src/src/miscmods/spf.c` — replaces `SUPPORT_SPF` preprocessor
/// conditional.
#[cfg(feature = "ffi-spf")]
pub mod spf;

/// DMARC policy evaluation bindings (wraps libopendmarc).
///
/// Source: `src/src/miscmods/dmarc.c` — replaces `SUPPORT_DMARC`
/// preprocessor conditional.
#[cfg(feature = "ffi-dmarc")]
pub mod dmarc;

/// Oracle OCI (Oracle Call Interface) FFI bindings (wraps libclntsh).
///
/// Source: `src/src/lookups/oracle.c` — replaces `LOOKUP_ORACLE`
/// preprocessor conditional.
#[cfg(feature = "ffi-oracle")]
pub mod oracle;

/// WHOSON dynamic IP user tracking bindings (wraps libwhoson).
///
/// Source: `src/src/lookups/whoson.c` — replaces `LOOKUP_WHOSON`
/// preprocessor conditional.
#[cfg(feature = "ffi-whoson")]
pub mod whoson;

/// NIS+ directory service bindings (wraps libnsl NIS+ API from
/// `<rpcsvc/nis.h>`).
///
/// Source: `src/src/lookups/nisplus.c` — replaces `LOOKUP_NISPLUS`
/// preprocessor conditional.
#[cfg(feature = "ffi-nisplus")]
pub mod nisplus;

/// NIS (Yellow Pages) directory service bindings (wraps libnsl NIS/YP API
/// from `<rpcsvc/ypclnt.h>`).
///
/// Source: `src/src/lookups/nis.c` — replaces `LOOKUP_NIS` preprocessor
/// conditional.
#[cfg(feature = "ffi-nis")]
pub mod nis;

/// Cyrus SASL (libsasl2) server-side authentication bindings.
///
/// Source: `src/src/auths/cyrus_sasl.c` — replaces `AUTH_CYRUS_SASL`
/// preprocessor conditional. NOT to be confused with libgsasl (GNU SASL)
/// which is wrapped in [`gsasl`].
#[cfg(feature = "ffi-cyrus-sasl")]
pub mod cyrus_sasl;

/// LMDB environment safe wrapper — centralises the `unsafe`
/// `heed::EnvOpenOptions::open()` call so that `exim-lookups/src/lmdb.rs`
/// remains 100% safe Rust (per AAP §0.7.2).
#[cfg(feature = "ffi-lmdb")]
pub mod lmdb;

// =============================================================================
// Hints database abstraction layer
// =============================================================================
//
// The `hintsdb` module is always available (no top-level feature gate)
// because it defines the common `HintsDb` trait used by all backends.
// Individual backend implementations are feature-gated internally:
//   - `hintsdb/bdb.rs`  → `#[cfg(feature = "hintsdb-bdb")]`
//   - `hintsdb/gdbm.rs` → `#[cfg(feature = "hintsdb-gdbm")]`
//   - `hintsdb/ndbm.rs` → `#[cfg(feature = "hintsdb-ndbm")]`
//   - `hintsdb/tdb.rs`  → `#[cfg(feature = "hintsdb-tdb")]`
//
// This design allows the common HintsDb trait to always be available even
// when no specific backend is selected, matching the C architecture where
// USE_DB/USE_GDBM/USE_NDBM/USE_TDB conditionals gate backend code but
// the hints API contract is always present.

/// Hints database abstraction layer — common trait and backend
/// implementations.
///
/// Source: `src/src/hintsdb/hints_*.h` — replaces `USE_DB`/`USE_GDBM`/
/// `USE_NDBM`/`USE_TDB` preprocessor conditionals.
pub mod hintsdb;
