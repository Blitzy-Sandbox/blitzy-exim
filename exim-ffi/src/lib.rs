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

/// Safe POSIX process management wrappers.
///
/// Provides a safe wrapper around `nix::unistd::fork()` (which is `unsafe`
/// in the `nix` crate).  Exim's single-threaded fork-per-connection model
/// guarantees the safety preconditions of `fork()`.  Consumed by
/// `exim-deliver/src/transport_dispatch.rs` and `exim-core/src/process.rs`.
pub mod process;

/// Safe wrappers around `libloading` for `${dlfunc}` dynamic function loading.
///
/// Centralises all `unsafe` code for `dlopen(3)` / `dlsym(3)` operations so
/// that `exim-expand/src/dlfunc.rs` contains **zero** `unsafe` blocks.
/// Per AAP §0.7.2, all `unsafe` code in the workspace MUST reside in this
/// crate.
///
/// Source: `src/src/expand.c` (EITEM_DLFUNC handler, lines 7133-7222).
pub mod dlfunc;

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

// =============================================================================
// Patchable version string for test harness compatibility
// =============================================================================

/// Binary-embedded version marker that the `test/patchexim` script finds
/// and replaces with `x.yz\0***...` so that test output is stable across
/// Exim releases. The marker `<<eximversion>>` is the sentinel searched by
/// the Perl regex in `patchexim`.
///
/// C equivalent: `version_string = US EXIM_VERSION_STR "\0<<eximversion>>";`
/// in `src/src/version.c`.
///
/// # Safety of `static mut`
///
/// `patchexim` modifies the binary **file** before execution — it does NOT
/// modify process memory at runtime. Once the binary is loaded, this data
/// is effectively read-only. The `static mut` is required so the linker
/// emits the data in a writable section (`.data`) rather than `.rodata`,
/// which is necessary for `patchexim`'s binary-level byte replacement to
/// succeed on platforms that map `.rodata` as read-only in the filesystem
/// image.
#[used]
#[no_mangle]
pub static mut EXIM_VERSION_DATA: [u8; 20] = *b"4.99\0<<eximversion>>";

/// Returns the (possibly patched) Exim version string.
///
/// After `patchexim` rewrites the binary, the data becomes `x.yz\0***...`.
/// This function reads up to the first NUL byte and returns the result as
/// a `&'static str`.
///
/// # Safety
///
/// Reads from `EXIM_VERSION_DATA` which is only modified at binary-file
/// level by `patchexim` before execution — never at runtime. The read is
/// therefore data-race-free.
pub fn get_patched_version() -> &'static str {
    // SAFETY: EXIM_VERSION_DATA is modified only at binary-file level by
    // patchexim before the process starts. During execution it is never
    // written, so this read is safe and data-race-free.
    let data: &[u8] = unsafe { &*core::ptr::addr_of!(EXIM_VERSION_DATA) };
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    match core::str::from_utf8(&data[..end]) {
        Ok(s) => s,
        Err(_) => "4.99",
    }
}

/// Format the current local time as C Exim's `$tod_full`, e.g.
/// `"Tue, 02 Mar 1999 09:44:33 +0000"`.
///
/// Uses `libc::strftime` for locale-independent RFC-2822-style output
/// that exactly matches the C binary's timestamp format.
/// Returns the login name of the calling process's effective user.
///
/// Equivalent to C Exim's `originator_login` which is set from
/// `getpwuid(getuid())->pw_name`. Used as `sender_ident` in `-bs` mode
/// for the HELO greeting: "250 host Hello CALLER at helo_name".
pub fn get_login_name() -> Option<String> {
    // SAFETY: getuid() is a simple syscall returning the process UID.
    // getpwuid() returns a pointer to a static struct passwd which is
    // valid until the next call to getpwuid/getpwnam in this thread.
    // We copy the name immediately and do not retain the pointer.
    unsafe {
        let uid = libc::getuid();
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return None;
        }
        let name = std::ffi::CStr::from_ptr((*pw).pw_name);
        name.to_str().ok().map(|s| s.to_string())
    }
}

/// Retrieve the real name (GECOS field) of the current process user.
///
/// This reads the `pw_gecos` field from the system passwd database
/// for the calling process's UID.  If the GECOS field contains
/// comma-separated sub-fields, only the first (full name) is returned.
///
/// Returns `None` if the user cannot be looked up.
pub fn get_real_name() -> Option<String> {
    // SAFETY: getuid() is a simple syscall returning the process UID.
    // getpwuid() returns a pointer to a static struct passwd which is
    // valid until the next call to getpwuid/getpwnam in this thread.
    // We copy the gecos string immediately and do not retain the pointer.
    unsafe {
        let uid = libc::getuid();
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return None;
        }
        let gecos = std::ffi::CStr::from_ptr((*pw).pw_gecos);
        let full = gecos.to_str().ok()?.to_string();
        // GECOS may have comma-separated fields; use only the first.
        Some(full.split(',').next().unwrap_or("").to_string())
    }
}

/// Performs a reverse DNS lookup of the given IP address string using
/// libc's `getnameinfo`.  Returns `Some(hostname)` on success or `None`
/// if the lookup fails or only returns a numeric address.
///
/// # Safety justification
/// The `unsafe` block calls `getnameinfo`, a standard POSIX function, with
/// stack-allocated `sockaddr_in`/`sockaddr_in6` structs whose lifetimes
/// exceed the call.
pub fn reverse_lookup(address: &str) -> Option<String> {
    use std::ffi::CStr;

    let addr: std::net::IpAddr = address.parse().ok()?;

    let mut host_buf = [0u8; 256];

    let rc = match addr {
        std::net::IpAddr::V4(v4) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: We pass a valid stack-allocated sockaddr_in with correct
            // length to getnameinfo. The buffer is stack-allocated and large
            // enough. getnameinfo only reads from the sockaddr and writes to
            // the host buffer.
            unsafe {
                libc::getnameinfo(
                    &sin as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host_buf.as_mut_ptr() as *mut libc::c_char,
                    host_buf.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    0,
                )
            }
        }
        std::net::IpAddr::V6(v6) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.octets(),
                },
                sin6_scope_id: 0,
            };
            // SAFETY: Same justification as IPv4 case above.
            unsafe {
                libc::getnameinfo(
                    &sin6 as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host_buf.as_mut_ptr() as *mut libc::c_char,
                    host_buf.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    0,
                )
            }
        }
    };

    if rc == 0 {
        // SAFETY: getnameinfo guarantees NUL-termination on success.
        let cstr = unsafe { CStr::from_ptr(host_buf.as_ptr() as *const libc::c_char) };
        let name = cstr.to_string_lossy().to_string();
        // If it returned a numeric address, that's not a real hostname
        if name == addr.to_string() {
            return None;
        }
        Some(name)
    } else {
        None
    }
}

pub fn format_tod_full() -> String {
    // SAFETY: libc time/localtime/strftime are standard C library functions.
    // localtime returns a pointer to a static `struct tm` which is valid
    // until the next call to localtime/gmtime in this thread. We read it
    // immediately in strftime and do not retain the pointer.
    unsafe {
        let mut t: libc::time_t = 0;
        libc::time(&mut t);
        let tm = libc::localtime(&t);
        if tm.is_null() {
            return String::from("Thu, 01 Jan 1970 00:00:00 +0000");
        }
        let mut buf = [0u8; 128];
        let fmt = b"%a, %d %b %Y %H:%M:%S %z\0";
        let len = libc::strftime(
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            fmt.as_ptr() as *const libc::c_char,
            tm,
        );
        if len == 0 {
            return String::from("Thu, 01 Jan 1970 00:00:00 +0000");
        }
        std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char)
            .to_string_lossy()
            .into_owned()
    }
}
