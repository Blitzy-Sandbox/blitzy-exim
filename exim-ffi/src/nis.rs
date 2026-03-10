//! Safe wrappers around NIS/YP (Network Information Service / Yellow Pages)
//! client functions from `<rpcsvc/ypclnt.h>`.
//!
//! This module is the **ONLY** location for `unsafe` NIS/YP calls in the
//! entire Exim Rust workspace (per AAP §0.7.2). Higher-level crates such as
//! `exim-lookups` consume exclusively the safe public API exported here:
//!
//! - [`get_default_domain()`] — Retrieve the system's default NIS domain name
//! - [`yp_match_query()`]    — Look up a key in a NIS map, returning raw bytes
//! - [`NisError`]            — Typed error enum covering all NIS failure modes
//!
//! ## Source Reference
//!
//! Translated from `src/src/lookups/nis.c` (lines 23–89), which implements:
//! - `nis_open`  — calls `yp_get_default_domain()`
//! - `nis_find`  — calls `yp_match()` with key length excluding null terminator
//! - `nis0_find` — calls `yp_match()` with key length *including* null terminator
//!
//! The safe wrapper [`yp_match_query()`] accepts the key as `&[u8]`, so both
//! the `nis` and `nis0` lookup variants are supported by the caller controlling
//! whether the trailing null byte is included in the slice.
//!
//! ## Safety Policy
//!
//! - Every `unsafe` block has an inline justification comment explaining why
//!   the operation is necessary and why it is sound.
//! - All C-allocated memory (`yp_match` result buffer) is freed via
//!   `libc::free` before the function returns.
//! - Null pointer checks guard every C pointer dereference.
//! - No panics — all errors are returned via [`Result`].
//!
//! ## Feature Gate
//!
//! This module is only compiled when the `ffi-nis` Cargo feature is enabled,
//! replacing the C preprocessor `LOOKUP_NIS` conditional from the original
//! Exim build system.

use std::ffi::{CStr, CString};
use std::ptr;

// ── NIS/YP Error Codes ────────────────────────────────────────────────────
//
// Constants from <rpcsvc/ypclnt.h>. These mirror the system header definitions
// exactly so that return codes from the C library can be matched without
// depending on bindgen-generated constants.

/// Successful operation — no error.
const YPERR_SUCCESS: libc::c_int = 0;

/// Arguments to the function are bad.
const YPERR_BADARGS: libc::c_int = 1;

/// RPC failure communicating with the NIS server.
const YPERR_RPC: libc::c_int = 2;

/// Cannot bind to a server with this domain.
const YPERR_DOMAIN: libc::c_int = 3;

/// No such map in server's domain.
const YPERR_MAP: libc::c_int = 4;

/// No such key in map.
const YPERR_KEY: libc::c_int = 5;

/// Internal yp server or client error.
const YPERR_YPERR: libc::c_int = 6;

/// Local resource allocation failure.
const YPERR_RESRC: libc::c_int = 7;

/// No more records in map database.
const YPERR_NOMORE: libc::c_int = 8;

/// Cannot communicate with portmapper.
const YPERR_PMAP: libc::c_int = 9;

/// Cannot communicate with ypbind.
const YPERR_YPBIND: libc::c_int = 10;

/// Cannot communicate with ypserv.
const YPERR_YPSERV: libc::c_int = 11;

/// Local domain name not set.
const YPERR_NODOM: libc::c_int = 12;

/// YP data base is bad.
const YPERR_BADDB: libc::c_int = 13;

/// YP version mismatch.
const YPERR_VERS: libc::c_int = 14;

/// Access violation.
const YPERR_ACCESS: libc::c_int = 15;

/// Database is busy.
const YPERR_BUSY: libc::c_int = 16;

// ── Raw FFI Declarations ──────────────────────────────────────────────────
//
// NIS/YP exposes a small public API. Hand-written extern "C" declarations
// are used instead of bindgen because the surface area is minimal (only 2
// functions needed), keeping the build simpler and avoiding an unnecessary
// bindgen invocation.
//
// C header: <rpcsvc/ypclnt.h>
// C API (from src/src/lookups/nis.c):
//   int yp_get_default_domain(char **outdomain)   → 0 on success
//   int yp_match(const char *domain, const char *map, const char *key,
//                int keylen, char **result, int *resultlen)  → 0 on success
//
// Linking is handled by build.rs which either compiles a mock static
// library (for testing) or links against the system libnsl.

mod ffi {
    use libc::{c_char, c_int};

    extern "C" {
        /// Retrieve the default NIS domain name.
        ///
        /// On success (return 0), `*outdomain` is set to point to a
        /// statically-allocated null-terminated string containing the
        /// NIS domain name. The caller MUST NOT free this pointer.
        ///
        /// C signature: `int yp_get_default_domain(char **outdomain)`
        pub fn yp_get_default_domain(outdomain: *mut *mut c_char) -> c_int;

        /// Look up a key in a NIS map.
        ///
        /// On success (return 0), `*outval` is set to a `malloc`-allocated
        /// buffer of `*outvallen` bytes containing the lookup result. The
        /// caller is responsible for freeing `*outval` via `free()`.
        ///
        /// The `inkeylen` parameter controls whether the null terminator
        /// is included in the key length:
        /// - `nis`  lookup: `inkeylen` = byte length of key (no null)
        /// - `nis0` lookup: `inkeylen` = byte length of key + 1 (with null)
        ///
        /// C signature:
        /// ```c
        /// int yp_match(const char *indomain, const char *inmap,
        ///              const char *inkey, int inkeylen,
        ///              char **outval, int *outvallen)
        /// ```
        pub fn yp_match(
            indomain: *const c_char,
            inmap: *const c_char,
            inkey: *const c_char,
            inkeylen: c_int,
            outval: *mut *mut c_char,
            outvallen: *mut c_int,
        ) -> c_int;
    }
}

// ── Error Type ────────────────────────────────────────────────────────────

/// Errors from NIS/YP operations.
///
/// Maps the `YPERR_*` return codes from the C NIS client library into a
/// typed Rust enum. The variants correspond to the error categories used
/// in the original C implementation (`src/src/lookups/nis.c` lines 61, 88):
///
/// - `YPERR_KEY` → [`NisError::KeyNotFound`] (lookup returns `FAIL`)
/// - `YPERR_MAP` → [`NisError::MapNotFound`] (lookup returns `FAIL`)
/// - Non-zero from `yp_get_default_domain` → [`NisError::DomainNotBound`]
/// - All other `YPERR_*` codes → [`NisError::SystemError`] (lookup returns `DEFER`)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NisError {
    /// The NIS domain could not be determined.
    ///
    /// Corresponds to a non-zero return from `yp_get_default_domain()`.
    /// The contained string describes the failure reason.
    DomainNotBound(String),

    /// The requested NIS map does not exist on the server.
    ///
    /// Corresponds to `YPERR_MAP` (code 4) from `yp_match()`.
    /// The contained string identifies the map name that was not found.
    MapNotFound(String),

    /// The requested key does not exist in the NIS map.
    ///
    /// Corresponds to `YPERR_KEY` (code 5) from `yp_match()`.
    KeyNotFound,

    /// A system-level NIS error occurred.
    ///
    /// Wraps all `YPERR_*` codes other than `YPERR_KEY` and `YPERR_MAP`.
    /// The `code` field contains the raw C error code and `message` contains
    /// a human-readable description.
    SystemError {
        /// The raw `YPERR_*` code from the C library.
        code: i32,
        /// Human-readable description of the error.
        message: String,
    },
}

impl std::fmt::Display for NisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NisError::DomainNotBound(msg) => {
                write!(f, "NIS domain not bound: {msg}")
            }
            NisError::MapNotFound(map) => {
                write!(f, "NIS map not found: {map}")
            }
            NisError::KeyNotFound => {
                write!(f, "NIS key not found")
            }
            NisError::SystemError { code, message } => {
                write!(f, "NIS system error (code {code}): {message}")
            }
        }
    }
}

impl std::error::Error for NisError {}

// ── Error Description Helper ──────────────────────────────────────────────

/// Returns a human-readable description for a `YPERR_*` error code.
///
/// This is a pure-Rust replacement for the C `yperr_string()` function,
/// avoiding an additional FFI call. The descriptions match the comments
/// in `<rpcsvc/ypclnt.h>`.
fn nis_error_description(code: libc::c_int) -> String {
    match code {
        YPERR_SUCCESS => "success".to_string(),
        YPERR_BADARGS => "bad arguments to NIS function".to_string(),
        YPERR_RPC => "RPC failure communicating with NIS server".to_string(),
        YPERR_DOMAIN => "cannot bind to NIS server for this domain".to_string(),
        YPERR_MAP => "no such map in NIS server domain".to_string(),
        YPERR_KEY => "no such key in NIS map".to_string(),
        YPERR_YPERR => "internal NIS server or client error".to_string(),
        YPERR_RESRC => "local resource allocation failure".to_string(),
        YPERR_NOMORE => "no more records in NIS map database".to_string(),
        YPERR_PMAP => "cannot communicate with portmapper".to_string(),
        YPERR_YPBIND => "cannot communicate with ypbind".to_string(),
        YPERR_YPSERV => "cannot communicate with ypserv".to_string(),
        YPERR_NODOM => "local NIS domain name not set".to_string(),
        YPERR_BADDB => "NIS database is corrupt".to_string(),
        YPERR_VERS => "NIS version mismatch".to_string(),
        YPERR_ACCESS => "NIS access violation".to_string(),
        YPERR_BUSY => "NIS database is busy".to_string(),
        other => format!("unknown NIS error code {other}"),
    }
}

// ── Safe Public API ───────────────────────────────────────────────────────

/// Retrieve the system's default NIS domain name.
///
/// Wraps the C `yp_get_default_domain()` function, converting the result
/// into an owned Rust [`String`].
///
/// This corresponds to the `nis_open()` function in the original C source
/// (`src/src/lookups/nis.c` lines 23–33), which is called once when the
/// NIS lookup module is opened and caches the domain as the lookup handle.
///
/// # Returns
///
/// - `Ok(String)` — the default NIS domain name
/// - `Err(NisError::DomainNotBound(_))` — if `yp_get_default_domain` fails
///
/// # Errors
///
/// Returns [`NisError::DomainNotBound`] if:
/// - The C function returns a non-zero error code (NIS is not configured
///   or the domain cannot be determined).
/// - The C function returns a null pointer (defensive guard).
pub fn get_default_domain() -> Result<String, NisError> {
    let mut domain_ptr: *mut libc::c_char = ptr::null_mut();

    // Safety justification: `yp_get_default_domain` is a standard NIS/YP
    // client function from libnsl. It takes a single `char **` out-parameter
    // and writes a pointer to a statically-allocated, null-terminated C string
    // (the NIS domain name from the system configuration). The pointer
    // `&mut domain_ptr` is a valid, aligned, writable location on our stack.
    // The function does not retain any reference to `domain_ptr` after return.
    // The written pointer (if non-null) points to static data with process
    // lifetime, so it is safe to read after the call returns.
    let rc = unsafe { ffi::yp_get_default_domain(&mut domain_ptr) };

    if rc != YPERR_SUCCESS {
        return Err(NisError::DomainNotBound(format!(
            "yp_get_default_domain failed: {}",
            nis_error_description(rc)
        )));
    }

    // Defensive null-pointer guard — yp_get_default_domain should always
    // set the pointer on success, but we check to prevent UB.
    if domain_ptr.is_null() {
        return Err(NisError::DomainNotBound(
            "yp_get_default_domain returned null domain pointer".to_string(),
        ));
    }

    // Safety justification: `domain_ptr` is non-null (checked above) and
    // points to a statically-allocated, null-terminated C string managed by
    // the NIS client library. This string has process lifetime and will not
    // be freed or mutated. `CStr::from_ptr` reads up to the null terminator,
    // which is guaranteed to exist within the static buffer.
    let domain_cstr = unsafe { CStr::from_ptr(domain_ptr) };

    Ok(domain_cstr.to_string_lossy().into_owned())
}

/// Look up a key in a NIS map, returning the result as raw bytes.
///
/// Wraps the C `yp_match()` function. The key is passed as a byte slice
/// (`&[u8]`) whose length is forwarded directly as the `inkeylen` parameter,
/// supporting both the `nis` and `nis0` lookup variants:
///
/// - **`nis` lookup**: caller passes the key bytes *without* a trailing null
///   (e.g., `b"somekey"`), so `inkeylen` = byte length of the key.
/// - **`nis0` lookup**: caller passes the key bytes *with* a trailing null
///   (e.g., `b"somekey\0"`), so `inkeylen` = byte length of key + 1.
///
/// This corresponds to `nis_find()` and `nis0_find()` in the original C
/// source (`src/src/lookups/nis.c` lines 45–89). The C code strips the
/// trailing newline from the result; this wrapper returns the raw bytes
/// including any trailing newline, leaving stripping to the caller.
///
/// # Arguments
///
/// - `domain` — NIS domain name (typically from [`get_default_domain()`])
/// - `map`    — NIS map name (e.g., `"passwd.byname"`, `"hosts.byaddr"`)
/// - `key`    — Lookup key as raw bytes (length determines nis vs nis0 mode)
///
/// # Returns
///
/// - `Ok(Vec<u8>)` — the lookup result as raw bytes
/// - `Err(NisError::KeyNotFound)` — key does not exist in the map
/// - `Err(NisError::MapNotFound(_))` — map does not exist on the server
/// - `Err(NisError::SystemError { .. })` — other NIS error
///
/// # Errors
///
/// Returns [`NisError`] if:
/// - `domain` or `map` contain interior null bytes (maps to `SystemError`).
/// - `key` length exceeds `c_int::MAX` (maps to `SystemError`).
/// - `yp_match` returns `YPERR_KEY` (5) → [`NisError::KeyNotFound`].
/// - `yp_match` returns `YPERR_MAP` (4) → [`NisError::MapNotFound`].
/// - `yp_match` returns any other non-zero code → [`NisError::SystemError`].
/// - `yp_match` returns a null result pointer or negative length.
pub fn yp_match_query(domain: &str, map: &str, key: &[u8]) -> Result<Vec<u8>, NisError> {
    // Convert domain and map to C strings, rejecting interior null bytes.
    let c_domain = CString::new(domain).map_err(|_| NisError::SystemError {
        code: YPERR_BADARGS,
        message: "domain string contains interior null byte".to_string(),
    })?;

    let c_map = CString::new(map).map_err(|_| NisError::SystemError {
        code: YPERR_BADARGS,
        message: "map name string contains interior null byte".to_string(),
    })?;

    // Validate key length fits in c_int. NIS keys are typically short
    // (hostnames, usernames), so this should never fail in practice.
    let key_len: libc::c_int =
        libc::c_int::try_from(key.len()).map_err(|_| NisError::SystemError {
            code: YPERR_BADARGS,
            message: format!(
                "key length {} exceeds maximum c_int value {}",
                key.len(),
                libc::c_int::MAX
            ),
        })?;

    let mut result_ptr: *mut libc::c_char = ptr::null_mut();
    let mut result_len: libc::c_int = 0;

    // Safety justification: calling C `yp_match` from libnsl with:
    //   1. `c_domain.as_ptr()` — valid, non-null, null-terminated C string
    //      produced by `CString::new()`. Lifetime extends to end of this scope.
    //   2. `c_map.as_ptr()` — valid, non-null, null-terminated C string.
    //      Lifetime extends to end of this scope.
    //   3. `key.as_ptr().cast::<libc::c_char>()` — valid pointer to the start
    //      of the key byte slice. The buffer has at least `key_len` bytes.
    //   4. `key_len` — the exact length of the key buffer, verified above to
    //      fit in `c_int`.
    //   5. `&mut result_ptr` — valid, aligned, writable stack location where
    //      `yp_match` will write a `malloc`-allocated result pointer.
    //   6. `&mut result_len` — valid, aligned, writable stack location where
    //      `yp_match` will write the result byte count.
    //
    // On success (return 0), `result_ptr` points to a `malloc`-allocated
    // buffer of `result_len` bytes. The caller must free it via `free()`.
    // On error, `result_ptr` is not guaranteed to be valid.
    // The C function does not retain references to any input pointers.
    let rc = unsafe {
        ffi::yp_match(
            c_domain.as_ptr(),
            c_map.as_ptr(),
            key.as_ptr().cast::<libc::c_char>(),
            key_len,
            &mut result_ptr,
            &mut result_len,
        )
    };

    // Map non-zero return codes to typed errors, matching the C source:
    //   YPERR_KEY → FAIL (KeyNotFound)
    //   YPERR_MAP → FAIL (MapNotFound)
    //   other     → DEFER (SystemError)
    if rc != YPERR_SUCCESS {
        return match rc {
            YPERR_KEY => Err(NisError::KeyNotFound),
            YPERR_MAP => Err(NisError::MapNotFound(format!("{map} (domain: {domain})"))),
            code => Err(NisError::SystemError {
                code,
                message: nis_error_description(code),
            }),
        };
    }

    // Defensive guards: ensure the result pointer and length are valid
    // before attempting to read the data.
    if result_ptr.is_null() {
        return Err(NisError::SystemError {
            code: 0,
            message: "yp_match returned success but result pointer is null".to_string(),
        });
    }

    if result_len < 0 {
        // Safety justification: `result_ptr` was set by `yp_match` on a
        // success return and is non-null (checked above). It was allocated
        // via `malloc` by the NIS library, so it must be freed with `free()`.
        // Even though `result_len` is invalid, the pointer itself is still a
        // valid malloc allocation that must be released.
        unsafe {
            libc::free(result_ptr.cast::<libc::c_void>());
        }
        return Err(NisError::SystemError {
            code: 0,
            message: format!(
                "yp_match returned success but result length is negative: {result_len}"
            ),
        });
    }

    let len = result_len as usize;

    // Safety justification: `result_ptr` is non-null (checked above) and
    // points to a `malloc`-allocated buffer of at least `result_len` bytes,
    // as guaranteed by a successful `yp_match` return. We create a byte
    // slice view over exactly `len` bytes, copy it into an owned `Vec<u8>`,
    // then immediately free the C-allocated buffer via `libc::free`.
    //
    // The `result_ptr` was allocated by `yp_match` using `malloc`, so
    // freeing it with `free()` is the correct deallocation. After `free`,
    // the pointer is no longer accessed.
    let data = unsafe {
        let byte_slice = std::slice::from_raw_parts(result_ptr.cast::<u8>(), len);
        let owned = byte_slice.to_vec();
        libc::free(result_ptr.cast::<libc::c_void>());
        owned
    };

    Ok(data)
}

// ── Unit Tests ────────────────────────────────────────────────────────────
//
// These tests exercise the safe wrapper logic, error type construction,
// and helper functions. Tests that call FFI functions require the mock
// library compiled by build.rs (or a real libnsl with NIS configured).

#[cfg(test)]
mod tests {
    use super::*;

    // ── NisError construction and Display ────────────────────────────

    #[test]
    fn nis_error_domain_not_bound_display() {
        let err = NisError::DomainNotBound("no NIS domain configured".to_string());
        assert_eq!(
            format!("{err}"),
            "NIS domain not bound: no NIS domain configured"
        );
    }

    #[test]
    fn nis_error_map_not_found_display() {
        let err = NisError::MapNotFound("passwd.byname".to_string());
        assert_eq!(format!("{err}"), "NIS map not found: passwd.byname");
    }

    #[test]
    fn nis_error_key_not_found_display() {
        let err = NisError::KeyNotFound;
        assert_eq!(format!("{err}"), "NIS key not found");
    }

    #[test]
    fn nis_error_system_error_display() {
        let err = NisError::SystemError {
            code: 2,
            message: "RPC failure communicating with NIS server".to_string(),
        };
        assert_eq!(
            format!("{err}"),
            "NIS system error (code 2): RPC failure communicating with NIS server"
        );
    }

    #[test]
    fn nis_error_implements_std_error() {
        let err = NisError::DomainNotBound("test".to_string());
        // Verify NisError implements std::error::Error via trait object coercion.
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn nis_error_clone_eq() {
        let err1 = NisError::KeyNotFound;
        let err2 = err1.clone();
        assert_eq!(err1, err2);

        let err3 = NisError::SystemError {
            code: 7,
            message: "resource failure".to_string(),
        };
        let err4 = err3.clone();
        assert_eq!(err3, err4);
    }

    #[test]
    fn nis_error_ne() {
        let err1 = NisError::KeyNotFound;
        let err2 = NisError::MapNotFound("hosts".to_string());
        assert_ne!(err1, err2);
    }

    // ── Error description helper ─────────────────────────────────────

    #[test]
    fn error_description_known_codes() {
        assert_eq!(nis_error_description(YPERR_SUCCESS), "success");
        assert_eq!(
            nis_error_description(YPERR_BADARGS),
            "bad arguments to NIS function"
        );
        assert_eq!(
            nis_error_description(YPERR_RPC),
            "RPC failure communicating with NIS server"
        );
        assert_eq!(
            nis_error_description(YPERR_DOMAIN),
            "cannot bind to NIS server for this domain"
        );
        assert_eq!(
            nis_error_description(YPERR_MAP),
            "no such map in NIS server domain"
        );
        assert_eq!(nis_error_description(YPERR_KEY), "no such key in NIS map");
        assert_eq!(
            nis_error_description(YPERR_YPERR),
            "internal NIS server or client error"
        );
        assert_eq!(
            nis_error_description(YPERR_RESRC),
            "local resource allocation failure"
        );
        assert_eq!(
            nis_error_description(YPERR_NOMORE),
            "no more records in NIS map database"
        );
        assert_eq!(
            nis_error_description(YPERR_PMAP),
            "cannot communicate with portmapper"
        );
        assert_eq!(
            nis_error_description(YPERR_YPBIND),
            "cannot communicate with ypbind"
        );
        assert_eq!(
            nis_error_description(YPERR_YPSERV),
            "cannot communicate with ypserv"
        );
        assert_eq!(
            nis_error_description(YPERR_NODOM),
            "local NIS domain name not set"
        );
        assert_eq!(
            nis_error_description(YPERR_BADDB),
            "NIS database is corrupt"
        );
        assert_eq!(nis_error_description(YPERR_VERS), "NIS version mismatch");
        assert_eq!(nis_error_description(YPERR_ACCESS), "NIS access violation");
        assert_eq!(nis_error_description(YPERR_BUSY), "NIS database is busy");
    }

    #[test]
    fn error_description_unknown_code() {
        let desc = nis_error_description(99);
        assert_eq!(desc, "unknown NIS error code 99");
    }

    // ── YPERR constant value validation ──────────────────────────────
    //
    // Verify that our constants match the values from <rpcsvc/ypclnt.h>.

    #[test]
    fn yperr_constants_match_system_header() {
        assert_eq!(YPERR_SUCCESS, 0);
        assert_eq!(YPERR_BADARGS, 1);
        assert_eq!(YPERR_RPC, 2);
        assert_eq!(YPERR_DOMAIN, 3);
        assert_eq!(YPERR_MAP, 4);
        assert_eq!(YPERR_KEY, 5);
        assert_eq!(YPERR_YPERR, 6);
        assert_eq!(YPERR_RESRC, 7);
        assert_eq!(YPERR_NOMORE, 8);
        assert_eq!(YPERR_PMAP, 9);
        assert_eq!(YPERR_YPBIND, 10);
        assert_eq!(YPERR_YPSERV, 11);
        assert_eq!(YPERR_NODOM, 12);
        assert_eq!(YPERR_BADDB, 13);
        assert_eq!(YPERR_VERS, 14);
        assert_eq!(YPERR_ACCESS, 15);
        assert_eq!(YPERR_BUSY, 16);
    }

    // ── FFI-backed integration tests ─────────────────────────────────
    //
    // These tests call the safe wrappers, exercising the FFI boundary.
    // They use the mock library compiled by build.rs so they work
    // without a running NIS server.

    #[test]
    fn get_default_domain_returns_result() {
        // With the mock library, yp_get_default_domain returns 0 and
        // sets the domain to "mock.localdomain".
        let result = get_default_domain();
        // The mock returns success with a static domain string.
        assert!(result.is_ok(), "get_default_domain failed: {result:?}");
        let domain = result.unwrap();
        assert!(!domain.is_empty(), "domain string should not be empty");
    }

    #[test]
    fn yp_match_query_returns_key_not_found_for_mock() {
        // The mock yp_match always returns YPERR_KEY (5) to simulate
        // "key not found" — the most common non-error failure mode.
        let result = yp_match_query("mock.localdomain", "passwd.byname", b"nobody");
        match result {
            Err(NisError::KeyNotFound) => { /* expected */ }
            other => panic!("expected KeyNotFound, got {other:?}"),
        }
    }

    #[test]
    fn yp_match_query_rejects_domain_with_null() {
        let result = yp_match_query("bad\0domain", "passwd.byname", b"root");
        match result {
            Err(NisError::SystemError { code, message }) => {
                assert_eq!(code, YPERR_BADARGS);
                assert!(
                    message.contains("null byte"),
                    "expected null byte error, got: {message}"
                );
            }
            other => panic!("expected SystemError for null byte, got {other:?}"),
        }
    }

    #[test]
    fn yp_match_query_rejects_map_with_null() {
        let result = yp_match_query("localdomain", "bad\0map", b"root");
        match result {
            Err(NisError::SystemError { code, message }) => {
                assert_eq!(code, YPERR_BADARGS);
                assert!(
                    message.contains("null byte"),
                    "expected null byte error, got: {message}"
                );
            }
            other => panic!("expected SystemError for null byte, got {other:?}"),
        }
    }

    #[test]
    fn yp_match_query_empty_key() {
        // An empty key is valid — the C function receives inkeylen=0.
        // The mock returns YPERR_KEY, which maps to KeyNotFound.
        let result = yp_match_query("mock.localdomain", "passwd.byname", b"");
        match result {
            Err(NisError::KeyNotFound) => { /* expected from mock */ }
            other => panic!("expected KeyNotFound for empty key, got {other:?}"),
        }
    }
}
