//! Safe wrappers around the libwhoson C library.
//!
//! WHOSON (WHO iS ONline) is a protocol for tracking dynamic IP address
//! assignments. This module wraps the libwhoson C API to provide:
//!
//! - [`wso_query()`] — Query the WHOSON database for a given IP address
//! - [`wso_version()`] — Return the libwhoson library version string
//!
//! ## Safety
//!
//! All `unsafe` blocks are confined to this module per AAP §0.7.2.
//! The safe public API prevents null pointer dereference and buffer overflow
//! by using [`CString`] for outbound strings and bounded stack buffers for
//! inbound data from the C library.
//!
//! ## Feature Gate
//!
//! This module is only compiled when the `ffi-whoson` Cargo feature is enabled
//! (replacing the C preprocessor `LOOKUP_WHOSON` conditional).
//!
//! [`CString`]: std::ffi::CString

use std::error::Error;
use std::ffi::{CStr, CString};
use std::fmt;

// ── Raw FFI Bindings ───────────────────────────────────────────────────────
//
// libwhoson exposes only 2 public functions. Hand-written extern "C"
// declarations are preferred over bindgen for this minimal surface area,
// keeping the build simpler and avoiding an extra bindgen invocation.
//
// C header: <whoson.h>
// C API (from src/src/lookups/whoson.c lines 15, 43, 70):
//   int wso_query(const char *query, char *buffer, size_t bufsize);
//   const char *wso_version(void);

mod ffi {
    use libc::{c_char, c_int, size_t};

    extern "C" {
        /// Query the WHOSON database.
        ///
        /// Looks up `query` (typically an IP address) in the WHOSON daemon.
        /// On success (return code 0), fills `buffer` with the associated user
        /// name (null-terminated, at most `bufsize - 1` bytes).
        ///
        /// # Return codes
        /// - `0`  — IP found; `buffer` contains the user name
        /// - `1`  — IP not found in the WHOSON database
        /// - other — error; `buffer` may contain a diagnostic message
        pub fn wso_query(query: *const c_char, buffer: *mut c_char, bufsize: size_t) -> c_int;

        /// Return the libwhoson library version string.
        ///
        /// Returns a pointer to a static null-terminated C string that is
        /// valid for the lifetime of the process.
        pub fn wso_version() -> *const c_char;
    }
}

// ── Error Type ─────────────────────────────────────────────────────────────

/// Error from the WHOSON library.
///
/// Wraps error conditions arising from:
/// - Invalid query strings containing interior null bytes
/// - Non-zero, non-one return codes from the C `wso_query()` function
#[derive(Debug, Clone)]
pub struct WhosonError {
    /// Human-readable description of the error.
    message: String,
}

impl WhosonError {
    /// Create a new `WhosonError` with the given message.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let err = WhosonError::new("wso_query failed with code 3");
    /// ```
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }
}

impl fmt::Display for WhosonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WHOSON error: {}", self.message)
    }
}

impl Error for WhosonError {}

// ── Query Result Type ──────────────────────────────────────────────────────

/// Result of a WHOSON database query.
///
/// Maps the C return codes from `wso_query()`:
/// - `0` → [`Found`](WhosonQueryResult::Found) with the associated user name
/// - `1` → [`NotFound`](WhosonQueryResult::NotFound)
///
/// Other return codes are mapped to [`WhosonError`] by the safe wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhosonQueryResult {
    /// The IP address was found in the WHOSON database.
    /// Contains the associated user name string.
    Found(String),
    /// The IP address was not found in the WHOSON database.
    NotFound,
}

// ── Safe Public API ────────────────────────────────────────────────────────

/// Buffer size for `wso_query` results, matching the C implementation
/// in `src/src/lookups/whoson.c` line 41: `uschar buffer[80]`.
const WSO_BUFFER_SIZE: usize = 80;

/// Query the WHOSON database for the given key (typically an IP address).
///
/// Wraps the C `wso_query()` function with full safety guarantees:
/// - The query string is converted to a null-terminated [`CString`], rejecting
///   any input containing interior null bytes.
/// - The response buffer is stack-allocated with a fixed 80-byte size matching
///   the original C implementation.
/// - Return codes are mapped to typed Rust values.
///
/// # Returns
///
/// - `Ok(WhosonQueryResult::Found(username))` — IP is registered; `username`
///   is the associated user name from the WHOSON database.
/// - `Ok(WhosonQueryResult::NotFound)` — IP is not in the WHOSON database.
/// - `Err(WhosonError)` — the C library reported an error (return code other
///   than 0 or 1).
///
/// # Errors
///
/// Returns [`WhosonError`] if:
/// - The `query` string contains an interior null byte (invalid for C strings).
/// - The C `wso_query()` returns a code other than 0 or 1.
///
/// [`CString`]: std::ffi::CString
pub fn wso_query(query: &str) -> Result<WhosonQueryResult, WhosonError> {
    let c_query = CString::new(query)
        .map_err(|_| WhosonError::new("query string contains interior null byte"))?;

    let mut buffer = [0u8; WSO_BUFFER_SIZE];

    // SAFETY: `ffi::wso_query` is called with (1) a valid null-terminated
    // C string from `CString::new`, (2) a valid mutable pointer to a
    // stack-allocated `WSO_BUFFER_SIZE`-byte array, (3) the exact buffer
    // size.  On success (rc=0) the C function writes a null-terminated
    // result into `buffer`, making `CStr::from_ptr` sound because the
    // zero-initialized buffer guarantees a terminator within bounds.
    // The C function does not retain any pointers beyond this call.
    unsafe {
        let rc = ffi::wso_query(
            c_query.as_ptr(),
            buffer.as_mut_ptr().cast::<libc::c_char>(),
            WSO_BUFFER_SIZE as libc::size_t,
        );

        match rc {
            0 => {
                let c_result = CStr::from_ptr(buffer.as_ptr().cast::<libc::c_char>());
                Ok(WhosonQueryResult::Found(
                    c_result.to_string_lossy().into_owned(),
                ))
            }
            1 => Ok(WhosonQueryResult::NotFound),
            code => Err(WhosonError::new(format!(
                "wso_query failed with return code {}",
                code
            ))),
        }
    }
}

/// Return the libwhoson library version string.
///
/// Wraps the C `wso_version()` function. The C function returns a pointer
/// to a static null-terminated string that is valid for the process lifetime.
///
/// Returns `"unknown"` if the C function returns a null pointer (defensive
/// guard — should not occur with a correctly linked libwhoson).
pub fn wso_version() -> String {
    // SAFETY: `ffi::wso_version()` returns a pointer to a statically
    // allocated, null-terminated C string valid for the process lifetime.
    // The data is immutable and the pointer is never freed.  When non-null,
    // `CStr::from_ptr` safely reads the static string.  No mutable state
    // is modified by this call.
    unsafe {
        let ptr = ffi::wso_version();
        if ptr.is_null() {
            return String::from("unknown");
        }
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

// ── Unit Tests ─────────────────────────────────────────────────────────────
//
// These tests exercise the safe wrapper logic WITHOUT requiring libwhoson to
// be installed. They validate error handling paths and type construction.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whoson_error_display() {
        let err = WhosonError::new("test failure");
        assert_eq!(format!("{}", err), "WHOSON error: test failure");
    }

    #[test]
    fn whoson_error_debug() {
        let err = WhosonError::new("debug test");
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("debug test"));
    }

    #[test]
    fn whoson_error_implements_std_error() {
        let err = WhosonError::new("std error test");
        // Verify that WhosonError implements std::error::Error
        let _: &dyn Error = &err;
    }

    #[test]
    fn whoson_error_clone() {
        let err = WhosonError::new("clone test");
        let cloned = err.clone();
        assert_eq!(format!("{}", err), format!("{}", cloned));
    }

    #[test]
    fn whoson_query_result_found_eq() {
        let a = WhosonQueryResult::Found("user1".to_string());
        let b = WhosonQueryResult::Found("user1".to_string());
        assert_eq!(a, b);
    }

    #[test]
    fn whoson_query_result_not_found_eq() {
        assert_eq!(WhosonQueryResult::NotFound, WhosonQueryResult::NotFound);
    }

    #[test]
    fn whoson_query_result_found_ne_not_found() {
        let found = WhosonQueryResult::Found("user1".to_string());
        assert_ne!(found, WhosonQueryResult::NotFound);
    }

    #[test]
    fn whoson_query_result_clone() {
        let original = WhosonQueryResult::Found("user2".to_string());
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn whoson_error_new_accepts_string() {
        let err = WhosonError::new(String::from("owned string"));
        assert_eq!(format!("{}", err), "WHOSON error: owned string");
    }

    #[test]
    fn whoson_error_new_accepts_str() {
        let err = WhosonError::new("borrowed str");
        assert_eq!(format!("{}", err), "WHOSON error: borrowed str");
    }

    #[test]
    fn whoson_query_null_byte_in_query() {
        // Queries with interior null bytes should produce an error, not panic
        let result = wso_query("test\0query");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            format!("{}", err).contains("null byte"),
            "Error message should mention null byte: {}",
            err
        );
    }
}
