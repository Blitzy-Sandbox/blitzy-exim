//! # LMDB Environment Safe Wrapper
//!
//! Provides a safe Rust interface around `heed::EnvOpenOptions::open()`, which
//! is marked `unsafe` in the heed crate because LMDB uses memory-mapped I/O
//! (`mmap`) internally.
//!
//! This module exists so that `exim-lookups/src/lmdb.rs` can remain 100% safe
//! Rust (per AAP §0.7.2: zero `unsafe` blocks outside `exim-ffi`).
//!
//! # Safety Invariants
//!
//! The `open_env_readonly()` function wraps the unsafe `heed::EnvOpenOptions::open()`
//! call, which is unsafe because:
//!
//! 1. LMDB's `mdb_env_open()` creates a memory-mapped region over the database
//!    file.  If another process corrupts the file while it is mapped, the
//!    mapping can contain invalid data.
//! 2. Opening the same LMDB environment from multiple threads or processes
//!    without proper lock-file coordination can cause data corruption.
//!
//! These invariants are satisfied in Exim's usage because:
//! - We always open in **read-only** mode (`EnvFlags::READ_ONLY`).
//! - Exim's fork-per-connection model ensures each process has its own env.
//! - File paths originate from validated Exim configuration, not user input.
//! - `NO_SUB_DIR` is set because Exim LMDB lookups use single-file databases.

use std::path::Path;

/// Error type for LMDB environment operations.
#[derive(Debug, thiserror::Error)]
pub enum LmdbEnvError {
    /// The LMDB environment could not be opened.
    #[error("LMDB: unable to open environment at {path}: {source}")]
    OpenFailed {
        /// The path that was attempted.
        path: String,
        /// The underlying heed error.
        source: heed::Error,
    },
}

/// Open an LMDB environment in read-only mode with `NO_SUB_DIR`.
///
/// This function centralises the single `unsafe` call required by heed's API
/// so that all consumer crates (`exim-lookups`) remain 100% safe Rust.
///
/// # Arguments
///
/// * `path` — Absolute path to the LMDB database file (not a directory,
///   because `NO_SUB_DIR` is set).
///
/// # Returns
///
/// A `heed::Env` handle opened in read-only mode, or an `LmdbEnvError` if
/// the environment cannot be opened.
///
/// # Panics
///
/// Does not panic.
pub fn open_env_readonly(path: &Path) -> Result<heed::Env, LmdbEnvError> {
    // SAFETY: heed::EnvOpenOptions::open() is unsafe because LMDB uses
    // memory-mapped I/O (mdb_env_open → mmap).  We satisfy the safety
    // requirements because:
    //   1. We open in read-only mode (EnvFlags::READ_ONLY) — no writes
    //      can corrupt the mapped region.
    //   2. Exim's fork-per-connection model gives each process its own
    //      environment handle — no cross-process sharing occurs.
    //   3. File paths come from Exim configuration validated at startup,
    //      not from untrusted user input.
    //   4. NO_SUB_DIR is set because Exim LMDB lookups reference a single
    //      database file, not a directory of data files plus a lock file.
    let env = unsafe {
        let mut opts = heed::EnvOpenOptions::new();
        opts.flags(heed::EnvFlags::NO_SUB_DIR | heed::EnvFlags::READ_ONLY);
        opts.open(path)
    }
    .map_err(|e| LmdbEnvError::OpenFailed {
        path: path.display().to_string(),
        source: e,
    })?;

    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_open_nonexistent_returns_error() {
        let path = PathBuf::from("/nonexistent/path/test.lmdb");
        let result = open_env_readonly(&path);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("/nonexistent/path/test.lmdb"),
            "error should contain the path: {}",
            err
        );
    }
}
