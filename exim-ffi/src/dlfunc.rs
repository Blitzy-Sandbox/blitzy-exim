// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! Safe wrappers around `libloading` for `${dlfunc}` dynamic function loading.
//!
//! This module centralises the `unsafe` code required for dynamic shared-object
//! loading and symbol resolution, providing safe public APIs consumed by
//! `exim-expand/src/dlfunc.rs`.  Per AAP §0.7.2, all `unsafe` blocks in the
//! workspace MUST reside in the `exim-ffi` crate — this module satisfies that
//! requirement for `${dlfunc}` operations.
//!
//! The three unsafe operations wrapped are:
//!
//! 1. [`load_library()`] — `Library::new(path)` wrapping POSIX `dlopen(3)`
//! 2. [`call_dlfunc()`] — `Library::get::<T>(symbol)` wrapping `dlsym(3)`,
//!    plus calling the loaded function pointer
//!
//! # Process-Level Library Cache
//!
//! A process-level `HashMap<String, Library>` cache is maintained via
//! `LazyLock<Mutex<…>>`, matching the C `dlobj_anchor` tree.  Once loaded,
//! a shared object handle persists until process exit.
//!
//! # C Plugin Calling Convention
//!
//! The loaded function must conform to the `exim_dlfunc_t` ABI:
//!
//! ```c
//! int exim_dlfunc_fn(uschar **result, int argc, uschar *argv[]);
//! ```
//!
//! This is the documented Exim plugin contract.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::sync::{LazyLock, Mutex};

use libloading::Library;

/// Error type for dlfunc FFI operations.
#[derive(Debug, thiserror::Error)]
pub enum DlfuncError {
    /// Library loading failed (dlopen error).
    #[error("dlopen \"{path}\" failed: {detail}")]
    LoadFailed {
        /// Path to the shared object that could not be loaded.
        path: String,
        /// OS-level error detail from dlerror().
        detail: String,
    },

    /// Symbol lookup failed (dlsym error).
    #[error("dlsym \"{symbol}\" in \"{path}\" failed: {detail}")]
    SymbolNotFound {
        /// The function name that was not found.
        symbol: String,
        /// The shared object path.
        path: String,
        /// OS-level error detail.
        detail: String,
    },

    /// Function name contains an interior null byte.
    #[error("function name contains null byte: \"{0}\"")]
    NullInFunctionName(String),

    /// A function argument contains an interior null byte.
    #[error("dlfunc argument contains interior null byte: \"{0}\"")]
    NullInArgument(String),

    /// The library cache mutex was poisoned by a panic in another thread.
    #[error("internal error: library cache lock poisoned: {0}")]
    CachePoisoned(String),
}

/// Result of calling a dynamically loaded function.
///
/// Wraps the C integer status code and the optional result string pointer
/// returned by the plugin function.
#[derive(Debug)]
pub struct DlfuncCallResult {
    /// The C integer status code returned by the plugin function.
    /// Matches the Exim status constants: OK=0, DEFER=1, FAIL=2, FAIL_FORCED=258.
    pub status_code: i32,

    /// The result string set by the plugin function, if non-null.
    /// Copied into Rust-owned memory immediately after the call.
    pub result_string: String,
}

/// Process-level shared library cache.
///
/// Matches the C `dlobj_anchor` tree in expand.c.  Once a shared object is
/// loaded, its handle persists for the lifetime of the process.  The `Library`
/// handles are NOT `Send` in all libloading versions, but Exim's
/// single-threaded fork-per-connection model means the cache is only ever
/// accessed from the main thread of a given process.
static LIBRARY_CACHE: LazyLock<Mutex<HashMap<String, Library>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Load a shared library by path, inserting it into the process-level cache.
///
/// If the library has already been loaded, this is a no-op.  Otherwise the
/// library is opened via `dlopen(path, RTLD_LAZY)` and cached for subsequent
/// calls.
///
/// # Errors
///
/// Returns [`DlfuncError::LoadFailed`] if `dlopen` fails.
pub fn load_library(path: &str) -> Result<(), DlfuncError> {
    let mut cache = LIBRARY_CACHE
        .lock()
        .map_err(|e| DlfuncError::CachePoisoned(e.to_string()))?;

    if cache.contains_key(path) {
        return Ok(());
    }

    // SAFETY: `Library::new` loads a shared object via `dlopen(path, RTLD_LAZY)`.
    // The filename originates from Exim configuration file expansion, which runs
    // in a trusted administrative context.  The loaded library persists in the
    // process-level cache until process exit, matching C behaviour.  Library
    // initialisation routines are executed by the operating system loader;
    // the administrator is responsible for specifying safe libraries in the
    // configuration.
    let lib = unsafe { Library::new(path) }.map_err(|e| DlfuncError::LoadFailed {
        path: path.to_owned(),
        detail: e.to_string(),
    })?;

    cache.insert(path.to_owned(), lib);
    Ok(())
}

/// Look up a function symbol in a previously loaded library and call it.
///
/// The function must conform to the `exim_dlfunc_t` ABI:
///
/// ```c
/// int exim_dlfunc_fn(uschar **result, int argc, uschar *argv[]);
/// ```
///
/// # Arguments
///
/// * `library_path` — Path to the shared object (must have been loaded via
///   [`load_library()`] first).
/// * `function_name` — Symbol name to look up.
/// * `args` — Function arguments (will be converted to C strings).
///
/// # Errors
///
/// Returns [`DlfuncError`] on symbol lookup failure, null byte in arguments,
/// or cache access failure.
pub fn call_dlfunc(
    library_path: &str,
    function_name: &str,
    args: &[String],
) -> Result<DlfuncCallResult, DlfuncError> {
    // Validate the function name does not contain interior null bytes.
    if function_name.as_bytes().contains(&0u8) {
        return Err(DlfuncError::NullInFunctionName(function_name.to_owned()));
    }

    // Convert Rust String arguments to null-terminated C strings.
    let c_args: Result<Vec<CString>, DlfuncError> = args
        .iter()
        .map(|a| CString::new(a.as_bytes()).map_err(|_| DlfuncError::NullInArgument(a.clone())))
        .collect();
    let c_args = c_args?;

    // Build the argv pointer array for the C function.
    let mut c_arg_ptrs: Vec<*mut c_char> =
        c_args.iter().map(|cs| cs.as_ptr() as *mut c_char).collect();
    let argc = c_arg_ptrs.len() as c_int;

    // Result pointer — initialised to null.
    let mut result_ptr: *mut c_char = std::ptr::null_mut();

    // Acquire the cache lock for symbol lookup and function call.
    let cache = LIBRARY_CACHE
        .lock()
        .map_err(|e| DlfuncError::CachePoisoned(e.to_string()))?;

    let lib = cache
        .get(library_path)
        .ok_or_else(|| DlfuncError::LoadFailed {
            path: library_path.to_owned(),
            detail: "library not found in cache — call load_library() first".to_owned(),
        })?;

    /// C function pointer type for Exim dlfunc plugins.
    ///
    /// Matches the `exim_dlfunc_t` typedef:
    ///   `int (*)(uschar **result, int argc, uschar *argv[])`
    type EximDlfuncFn = unsafe extern "C" fn(*mut *mut c_char, c_int, *mut *mut c_char) -> c_int;

    // SAFETY: `Library::get` wraps `dlsym(handle, symbol_name)`, then we call
    // the loaded C function and copy its result. Both operations are consolidated
    // into one unsafe block as they form a single FFI call-chain.
    //
    // Symbol lookup contracts:
    // 1. Library handle is valid — managed by LIBRARY_CACHE, guaranteed to exist.
    // 2. Function name is a valid C symbol (verified above: no interior null bytes).
    // 3. Function conforms to the `exim_dlfunc_t` ABI (documented plugin contract).
    //
    // Function call contracts:
    // - `result_ptr`: valid mutable pointer to a local `*mut c_char`.
    // - `argc`: accurately reflects the number of pointers in `c_arg_ptrs`.
    // - `c_arg_ptrs.as_mut_ptr()`: contiguous array of valid, null-terminated
    //   C string pointers owned by `c_args` (alive for the call duration).
    // - After the call, `result_ptr` (if non-null) is a valid C string copied
    //   into a Rust `String` immediately, creating no C allocator dependency.
    let (status_code, result_string) = unsafe {
        let func: libloading::Symbol<'_, EximDlfuncFn> = lib
            .get(function_name.as_bytes())
            .map_err(|e| DlfuncError::SymbolNotFound {
                symbol: function_name.to_owned(),
                path: library_path.to_owned(),
                detail: e.to_string(),
            })?;

        let code = func(
            &mut result_ptr as *mut *mut c_char,
            argc,
            c_arg_ptrs.as_mut_ptr(),
        );
        let rstr = if result_ptr.is_null() {
            String::new()
        } else {
            CStr::from_ptr(result_ptr).to_string_lossy().into_owned()
        };
        (code, rstr)
    };

    Ok(DlfuncCallResult {
        status_code,
        result_string,
    })
}

// POSIX crypt(3) is not available in the `libc` crate on all platforms.
// We declare the extern function directly, linking against libcrypt (-lcrypt)
// which is standard on Linux and most POSIX systems.
extern "C" {
    /// POSIX `crypt(3)` — hash a password with a salt.
    ///
    /// Returns a pointer to a static buffer containing the hashed password,
    /// or null on error.  The buffer may be overwritten by subsequent calls.
    fn crypt(key: *const c_char, salt: *const c_char) -> *mut c_char;
}

/// Safe wrapper around POSIX `crypt(3)` for password hash comparison.
///
/// Delegates to `crypt()` with proper salt extraction and result
/// comparison.  Used by `exim-expand/src/conditions.rs` for `crypteq`
/// condition evaluation.
///
/// # Arguments
///
/// * `plaintext` — The plaintext password to hash.
/// * `salt` — The salt or full hash string (the first N characters are used
///   as salt by `crypt(3)`, where N depends on the hash algorithm).
///
/// # Returns
///
/// `true` if `crypt(plaintext, salt)` produces a string equal to `salt`.
/// `false` if the hashes do not match or if `crypt()` returns null.
pub fn crypt_compare(plaintext: &str, salt: &str) -> bool {
    let c_plaintext = match CString::new(plaintext) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let c_salt = match CString::new(salt) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // SAFETY: `crypt(3)` is a standard POSIX function that takes two
    // null-terminated C strings and returns a pointer to a static buffer
    // containing the hashed result.  The pointers are valid for the
    // duration of the call (owned by CString locals).  The returned
    // pointer is immediately copied into a Rust string.  `crypt(3)`
    // returns a pointer to a static buffer that may be overwritten by
    // subsequent calls — we copy immediately via `CStr::from_ptr` before
    // any other code can call `crypt()`.
    unsafe {
        let result_ptr = crypt(c_plaintext.as_ptr(), c_salt.as_ptr());
        if result_ptr.is_null() {
            return false;
        }
        let result = CStr::from_ptr(result_ptr);
        match result.to_str() {
            Ok(s) => s == salt,
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypt_compare_null_in_plaintext() {
        // Null bytes in plaintext should return false, not panic.
        assert!(!crypt_compare("pass\0word", "$1$salt$hash"));
    }

    #[test]
    fn test_crypt_compare_empty_salt() {
        // Empty salt should return false (salt < 2 chars handled by caller,
        // but crypt() itself should handle gracefully).
        assert!(!crypt_compare("password", ""));
    }

    #[test]
    fn test_load_library_nonexistent() {
        let result = load_library("/nonexistent/path/to/lib.so");
        assert!(result.is_err());
        match result.unwrap_err() {
            DlfuncError::LoadFailed { path, .. } => {
                assert_eq!(path, "/nonexistent/path/to/lib.so");
            }
            other => panic!("unexpected error variant: {:?}", other),
        }
    }

    #[test]
    fn test_call_dlfunc_null_in_function_name() {
        let result = call_dlfunc("/some/lib.so", "func\0name", &[]);
        assert!(result.is_err());
        match result.unwrap_err() {
            DlfuncError::NullInFunctionName(name) => {
                assert_eq!(name, "func\0name");
            }
            other => panic!("unexpected error variant: {:?}", other),
        }
    }
}
