//! NDBM (New Database Manager) hints database backend.
//!
//! Wraps the NDBM C API (`<ndbm.h>`) for Exim's persistent hints key-value storage.
//!
//! # Behavioral characteristics (from `hints_ndbm.h`)
//!
//! - Handle type is `DBM*` directly — the simplest of all backends
//! - Lockfiles required (`lockfile_needed() → true`)
//! - No cursor object — `dbm_firstkey`/`dbm_nextkey` track internally
//! - No transaction support (stubbed — returns `false` / no-op)
//! - No multi-open support (stubbed)
//! - `lstat()` safety preflight on `O_CREAT` to prevent creating `.pag`/`.dir`
//!   files under a directory name
//! - Datum init/free are no-ops — NDBM manages datum lifetime internally
//! - `EXIM_DB_RLIMIT = 150`
//! - `EXIM_DBTYPE = "ndbm"`
//!
//! # Memory management
//!
//! NDBM has simpler memory rules than GDBM or TDB:
//! - `dbm_fetch()` returns a datum pointing to NDBM-internal storage — NO free needed
//! - `dbm_firstkey()`/`dbm_nextkey()` similarly return internal pointers — NO free needed
//! - Only the `DBM*` handle itself needs to be closed via `dbm_close()`
//!
//! All data returned by NDBM is immediately copied into owned `Vec<u8>` via
//! [`HintsDbDatum::new`] to avoid dangling references into NDBM internals.

use std::ffi::CString;
use std::ptr;

use super::{HintsDb, HintsDbDatum, HintsDbError, OpenFlags, PutResult};

// Justification for #[allow(...)]: bindgen-generated FFI bindings preserve the original
// C naming conventions from <ndbm.h> for types (DBM, datum), functions (dbm_open,
// dbm_close, dbm_fetch, dbm_store, dbm_delete, dbm_firstkey, dbm_nextkey), and
// constants (DBM_INSERT, DBM_REPLACE). Renaming these would make cross-referencing
// with C documentation and the NDBM library source impossible. dead_code is allowed
// because bindgen emits all matched symbols regardless of which ones this module
// actually calls. upper_case_acronyms is suppressed because the type name `DBM` is
// the canonical C type from <ndbm.h> and must be preserved verbatim.
#[allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    dead_code,
    clippy::upper_case_acronyms
)]
mod ffi {
    include!(concat!(env!("OUT_DIR"), "/ndbm_bindings.rs"));
}

/// Database type identifier for NDBM, matching `EXIM_DBTYPE` in `hints_ndbm.h` line 28.
pub const EXIM_DBTYPE: &str = "ndbm";

/// Maximum file descriptor budget for NDBM hints databases.
/// Matches `EXIM_DB_RLIMIT` (value 150) in `hints_ndbm.h` line 152.
pub const EXIM_DB_RLIMIT: usize = 150;

/// Return code for successful `put_no_overwrite` — key was stored.
/// Matches `EXIM_DBPUTB_OK` (value 0) in `hints_ndbm.h` line 91.
const EXIM_DBPUTB_OK: libc::c_int = 0;

/// Safe wrapper around an NDBM hints database handle.
///
/// NDBM is the simplest backend — the handle is just a `DBM*` pointer
/// with no additional state needed for iteration or transactions.
///
/// # Memory ownership
///
/// The `dbm` pointer is owned by this struct and is freed via `dbm_close` in the
/// [`Drop`] implementation (or in the explicit [`close`](HintsDb::close) method).
///
/// # Scan state
///
/// The `scan_started` flag tracks whether [`scan_first`](HintsDb::scan_first) has
/// been called, so that [`scan_next`](HintsDb::scan_next) can distinguish between
/// "not yet started" (error) and "in progress" states. NDBM tracks iteration
/// state internally in the `DBM` handle, so no cursor struct is needed.
pub struct NdbmHintsDb {
    /// Pointer to the underlying `DBM`. Set to null after close.
    dbm: *mut ffi::DBM,
    /// Whether a scan has been initiated via `scan_first`.
    scan_started: bool,
}

impl std::fmt::Debug for NdbmHintsDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NdbmHintsDb")
            .field("dbm", &self.dbm)
            .field("scan_started", &self.scan_started)
            .finish()
    }
}

// SAFETY: DBM is a handle to a file-backed database. The NdbmHintsDb wrapper
// is not Clone and is designed for Exim's fork-per-connection model where each child
// process has exclusive access to its database handle. Send is required by the HintsDb
// trait bound and is safe under this single-owner, single-process usage model.
unsafe impl Send for NdbmHintsDb {}

// ---------------------------------------------------------------------------
// Consolidated FFI Dispatch
// ---------------------------------------------------------------------------

/// Internal FFI operation descriptors for the consolidated NDBM unsafe dispatch.
enum NdbmFfi {
    /// dbm_open(path, flags, mode) → *mut DBM
    Open(*mut libc::c_char, libc::c_int, libc::c_uint),
    /// dbm_close(dbm)
    Close(*mut ffi::DBM),
    /// dbm_fetch(dbm, key) → datum
    Fetch(*mut ffi::DBM, ffi::datum),
    /// dbm_store(dbm, key, data, flag) → c_int
    Store(*mut ffi::DBM, ffi::datum, ffi::datum, libc::c_int),
    /// dbm_delete(dbm, key) → c_int
    Delete(*mut ffi::DBM, ffi::datum),
    /// dbm_firstkey(dbm) → datum
    FirstKey(*mut ffi::DBM),
    /// dbm_nextkey(dbm) → datum
    NextKey(*mut ffi::DBM),
    /// std::slice::from_raw_parts(ptr, len).to_vec() for NDBM datum bytes
    SliceCopy(*const u8, usize),
}

/// Internal FFI result variants returned by the consolidated NDBM dispatch.
enum NdbmFfiResult {
    Handle(*mut ffi::DBM),
    Datum(ffi::datum),
    Code(libc::c_int),
    Bytes(Vec<u8>),
    Done,
}

/// Single consolidated unsafe dispatch point for all NDBM FFI operations.
///
/// Every unsafe interaction with libndbm is routed through this function,
/// maintaining a single auditable unsafe block for the entire module per
/// AAP §0.7.2.
///
/// # Per-variant safety justification
///
/// - `Open`: dbm_open with caller-validated CString path and standard flags/mode
/// - `Close`: dbm_close on a caller-validated non-null handle
/// - `Fetch/Store/Delete`: operations on valid handle with valid datum structs
/// - `FirstKey/NextKey`: scan using NDBM-internal state on valid handle
/// - `SliceCopy`: from_raw_parts on NDBM-internal buffer, immediately copied to Vec
///
/// Note: unlike GDBM/TDB, NDBM datum dptr does NOT need freeing — NDBM manages
/// datum memory internally. No `Free` variant is needed.
fn ndbm_ffi(op: NdbmFfi) -> NdbmFfiResult {
    // SAFETY: All NDBM FFI operations consolidated into a single auditable unsafe
    // region. Callers construct the appropriate NdbmFfi variant with validated
    // pointers and handles. NDBM functions follow POSIX ndbm(3) contracts.
    unsafe {
        match op {
            NdbmFfi::Open(path, flags, mode) => {
                NdbmFfiResult::Handle(ffi::dbm_open(path, flags, mode as libc::c_int))
            }
            NdbmFfi::Close(h) => {
                ffi::dbm_close(h);
                NdbmFfiResult::Done
            }
            NdbmFfi::Fetch(h, k) => NdbmFfiResult::Datum(ffi::dbm_fetch(h, k)),
            NdbmFfi::Store(h, k, d, f) => NdbmFfiResult::Code(ffi::dbm_store(h, k, d, f)),
            NdbmFfi::Delete(h, k) => NdbmFfiResult::Code(ffi::dbm_delete(h, k)),
            NdbmFfi::FirstKey(h) => NdbmFfiResult::Datum(ffi::dbm_firstkey(h)),
            NdbmFfi::NextKey(h) => NdbmFfiResult::Datum(ffi::dbm_nextkey(h)),
            NdbmFfi::SliceCopy(p, len) => {
                NdbmFfiResult::Bytes(std::slice::from_raw_parts(p, len).to_vec())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

/// Convert [`OpenFlags`] to POSIX `open()` flags suitable for `dbm_open`.
fn open_flags_to_posix(flags: &OpenFlags) -> libc::c_int {
    if flags.read_only {
        libc::O_RDONLY
    } else if flags.create {
        libc::O_RDWR | libc::O_CREAT
    } else {
        libc::O_RDWR
    }
}

/// Convert an [`HintsDbDatum`] reference to an `ffi::datum` for passing to NDBM.
fn hints_datum_to_ndbm(datum: &HintsDbDatum) -> ffi::datum {
    let bytes = datum.as_bytes();
    ffi::datum {
        dptr: bytes.as_ptr() as *mut libc::c_char,
        dsize: bytes.len() as libc::c_int,
    }
}

/// Convert an `ffi::datum` returned by NDBM into an owned [`HintsDbDatum`].
///
/// Returns `None` if `dptr` is null. Unlike TDB/GDBM, NDBM datum data does
/// NOT need to be freed — dptr points into NDBM-internal storage.
fn ndbm_datum_to_hints(d: ffi::datum) -> Option<HintsDbDatum> {
    if d.dptr.is_null() || d.dsize < 0 {
        return None;
    }
    let bytes = match ndbm_ffi(NdbmFfi::SliceCopy(d.dptr as *const u8, d.dsize as usize)) {
        NdbmFfiResult::Bytes(b) => b,
        _ => unreachable!(),
    };
    Some(HintsDbDatum::new(&bytes))
}

// ---------------------------------------------------------------------------
// NdbmHintsDb — Inherent Methods (open)
// ---------------------------------------------------------------------------

impl NdbmHintsDb {
    /// Open an NDBM database with the `lstat()` safety preflight.
    ///
    /// Corresponds to `exim_dbopen__` in `hints_ndbm.h` (lines 50-69).
    ///
    /// When `O_CREAT` is in the flags, a `lstat()` check is performed first to
    /// prevent creating `.pag`/`.dir` files under a directory name. This is the
    /// unique safety feature of the NDBM backend from `hints_ndbm.h` lines 57-59:
    ///
    /// ```c
    /// if ((flags & O_CREAT) && (lstat(name, &st) == 0 || errno != ENOENT))
    ///   errno = (st.st_mode & S_IFMT) == S_IFDIR ? EISDIR : EEXIST;
    /// ```
    ///
    /// # Arguments
    ///
    /// * `path` — File path for the NDBM database (null terminator added internally)
    /// * `flags` — Open mode flags (read-only, read-write, create)
    /// * `mode` — POSIX file permission bits (e.g., `0o660`)
    ///
    /// # Errors
    ///
    /// Returns [`HintsDbError`] if:
    /// - The path contains a null byte
    /// - The `lstat()` preflight detects an existing path when `O_CREAT` is set
    /// - `dbm_open` fails for any other reason
    pub fn open(path: &str, flags: &OpenFlags, mode: u32) -> Result<Self, HintsDbError> {
        let posix_flags = open_flags_to_posix(flags);

        // ----------------------------------------------------------------
        // lstat() safety preflight (hints_ndbm.h lines 57-59)
        //
        // When O_CREAT is set, check via lstat (not stat — must detect
        // symlinks) whether the name already exists. If the path exists
        // or lstat fails with something other than ENOENT, we must NOT
        // proceed:
        //   - If existing item is a directory → report "Is a directory"
        //   - If existing item is anything else → report "File exists"
        //   - If lstat fails with ENOENT → safe to create, proceed
        //   - If lstat fails with another error → propagate
        // ----------------------------------------------------------------
        if posix_flags & libc::O_CREAT != 0 {
            match std::fs::symlink_metadata(path) {
                Ok(metadata) => {
                    // Path exists — check if it's a directory
                    if metadata.file_type().is_dir() {
                        return Err(HintsDbError::new(format!(
                            "ndbm_open: is a directory: '{}'",
                            path
                        )));
                    }
                    // Exists but is not a directory (regular file, symlink, etc.)
                    return Err(HintsDbError::new(format!(
                        "ndbm_open: file exists: '{}'",
                        path
                    )));
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        // File doesn't exist — safe to create, proceed to dbm_open
                    } else {
                        // Some other lstat error (permissions, I/O, etc.)
                        return Err(HintsDbError::new(format!(
                            "ndbm_open: lstat preflight failed for '{}': {}",
                            path, e
                        )));
                    }
                }
            }
        }

        let c_path = CString::new(path)
            .map_err(|e| HintsDbError::new(format!("invalid database path: {e}")))?;

        // Dispatch dbm_open: valid CString path, POSIX flags, mode.
        let dbm = match ndbm_ffi(NdbmFfi::Open(
            c_path.as_ptr() as *mut _,
            posix_flags,
            mode as _,
        )) {
            NdbmFfiResult::Handle(h) => h,
            _ => unreachable!(),
        };

        if dbm.is_null() {
            return Err(HintsDbError::new(format!(
                "ndbm_open failed for '{}': {}",
                path,
                std::io::Error::last_os_error()
            )));
        }

        Ok(Self {
            dbm,
            scan_started: false,
        })
    }
}

// ---------------------------------------------------------------------------
// HintsDb Trait Implementation
// ---------------------------------------------------------------------------

impl HintsDb for NdbmHintsDb {
    /// NDBM requires external lockfiles for concurrency control.
    ///
    /// Returns `true`, matching `exim_lockfile_needed()` in `hints_ndbm.h` (lines 32-36).
    fn lockfile_needed(&self) -> bool {
        true
    }

    /// Returns the database type identifier: `"ndbm"`.
    fn db_type(&self) -> &'static str {
        EXIM_DBTYPE
    }

    /// Fetch a value by key from the NDBM database.
    ///
    /// Calls `dbm_fetch(dbp, key)` which returns a `datum` struct by value.
    /// The returned datum's `dptr` points into NDBM-internal storage and does
    /// NOT need to be freed (unlike GDBM/TDB). Data is immediately copied
    /// into an owned [`HintsDbDatum`].
    ///
    /// Returns `Ok(None)` if the key is not found.
    ///
    /// Corresponds to `exim_dbget` in `hints_ndbm.h` (lines 72-77).
    fn get(&self, key: &HintsDbDatum) -> Result<Option<HintsDbDatum>, HintsDbError> {
        let ndbm_key = hints_datum_to_ndbm(key);

        // Dispatch dbm_fetch: self.dbm is valid, key by-value struct copy.
        let result = match ndbm_ffi(NdbmFfi::Fetch(self.dbm, ndbm_key)) {
            NdbmFfiResult::Datum(d) => d,
            _ => unreachable!(),
        };

        Ok(ndbm_datum_to_hints(result))
    }

    /// Store a key-value pair, replacing any existing value.
    ///
    /// Uses `DBM_REPLACE` mode. Corresponds to `exim_dbput` in
    /// `hints_ndbm.h` (lines 80-82).
    fn put(&mut self, key: &HintsDbDatum, data: &HintsDbDatum) -> Result<(), HintsDbError> {
        let ndbm_key = hints_datum_to_ndbm(key);
        let ndbm_data = hints_datum_to_ndbm(data);

        // Dispatch dbm_store with DBM_REPLACE: self.dbm valid, key/data by-value.
        let rc = match ndbm_ffi(NdbmFfi::Store(
            self.dbm,
            ndbm_key,
            ndbm_data,
            ffi::DBM_REPLACE as libc::c_int,
        )) {
            NdbmFfiResult::Code(c) => c,
            _ => unreachable!(),
        };

        if rc != 0 {
            return Err(HintsDbError::new("ndbm dbm_store (replace) failed"));
        }
        Ok(())
    }

    /// Store a key-value pair only if the key does not already exist.
    ///
    /// Uses `DBM_INSERT` mode. Returns [`PutResult::Ok`] on success,
    /// [`PutResult::Duplicate`] if the key already exists.
    ///
    /// Corresponds to `exim_dbputb` in `hints_ndbm.h` (lines 85-87).
    /// Return codes: `EXIM_DBPUTB_OK = 0`, `EXIM_DBPUTB_DUP = 1`.
    fn put_no_overwrite(
        &mut self,
        key: &HintsDbDatum,
        data: &HintsDbDatum,
    ) -> Result<PutResult, HintsDbError> {
        let ndbm_key = hints_datum_to_ndbm(key);
        let ndbm_data = hints_datum_to_ndbm(data);

        // Dispatch dbm_store with DBM_INSERT: returns non-zero if key exists.
        let rc = match ndbm_ffi(NdbmFfi::Store(
            self.dbm,
            ndbm_key,
            ndbm_data,
            ffi::DBM_INSERT as libc::c_int,
        )) {
            NdbmFfiResult::Code(c) => c,
            _ => unreachable!(),
        };

        // Match C behavior: 0 = success (EXIM_DBPUTB_OK), any non-zero = duplicate
        if rc == EXIM_DBPUTB_OK {
            Ok(PutResult::Ok)
        } else {
            Ok(PutResult::Duplicate)
        }
    }

    /// Delete a key-value pair from the NDBM database.
    ///
    /// Corresponds to `exim_dbdel` in `hints_ndbm.h` (lines 95-97).
    fn delete(&mut self, key: &HintsDbDatum) -> Result<(), HintsDbError> {
        let ndbm_key = hints_datum_to_ndbm(key);

        // Dispatch dbm_delete: self.dbm valid, key by-value.
        let rc = match ndbm_ffi(NdbmFfi::Delete(self.dbm, ndbm_key)) {
            NdbmFfiResult::Code(c) => c,
            _ => unreachable!(),
        };

        if rc != 0 {
            return Err(HintsDbError::new("ndbm dbm_delete failed"));
        }
        Ok(())
    }

    /// Begin scanning from the first key in the NDBM database.
    ///
    /// Calls `dbm_firstkey(dbp)` to get the first key, then fetches its value
    /// via `dbm_fetch`. Returns `Ok(None)` if the database is empty.
    ///
    /// NDBM tracks iteration state internally — no cursor struct is needed.
    /// Unlike GDBM, no `lkey` tracking is required; unlike TDB, no cursor
    /// `dptr` freeing is needed.
    ///
    /// Corresponds to the `first == TRUE` branch of `exim_dbscan` in
    /// `hints_ndbm.h` (lines 105-111).
    fn scan_first(&mut self) -> Result<Option<(HintsDbDatum, HintsDbDatum)>, HintsDbError> {
        self.scan_started = true;

        // Dispatch dbm_firstkey: returns datum with internal dptr (no free needed).
        let key_datum = match ndbm_ffi(NdbmFfi::FirstKey(self.dbm)) {
            NdbmFfiResult::Datum(d) => d,
            _ => unreachable!(),
        };

        let key = match ndbm_datum_to_hints(key_datum) {
            Some(k) => k,
            None => return Ok(None),
        };

        // Dispatch dbm_fetch for the value.
        let val_datum = match ndbm_ffi(NdbmFfi::Fetch(self.dbm, key_datum)) {
            NdbmFfiResult::Datum(d) => d,
            _ => unreachable!(),
        };
        let value = ndbm_datum_to_hints(val_datum).unwrap_or_else(HintsDbDatum::empty);

        Ok(Some((key, value)))
    }

    /// Continue scanning to the next key in the NDBM database.
    ///
    /// Calls `dbm_nextkey(dbp)` to advance the internal cursor and get the
    /// next key, then fetches the value via `dbm_fetch`. Returns `Ok(None)`
    /// when iteration is exhausted.
    ///
    /// Must be called after [`scan_first`]. NDBM tracks the previous key
    /// internally, so no explicit cursor or `lkey` tracking is needed
    /// (unlike GDBM's `gdbm_nextkey(key)` which requires the previous key).
    ///
    /// Corresponds to the `first == FALSE` branch of `exim_dbscan` in
    /// `hints_ndbm.h` (lines 105-111).
    fn scan_next(&mut self) -> Result<Option<(HintsDbDatum, HintsDbDatum)>, HintsDbError> {
        if !self.scan_started {
            return Err(HintsDbError::new(
                "scan_next called without prior scan_first",
            ));
        }

        // Dispatch dbm_nextkey: uses NDBM-internal state for iteration.
        let key_datum = match ndbm_ffi(NdbmFfi::NextKey(self.dbm)) {
            NdbmFfiResult::Datum(d) => d,
            _ => unreachable!(),
        };

        let key = match ndbm_datum_to_hints(key_datum) {
            Some(k) => k,
            None => return Ok(None),
        };

        // Dispatch dbm_fetch for the value.
        let val_datum = match ndbm_ffi(NdbmFfi::Fetch(self.dbm, key_datum)) {
            NdbmFfiResult::Datum(d) => d,
            _ => unreachable!(),
        };
        let value = ndbm_datum_to_hints(val_datum).unwrap_or_else(HintsDbDatum::empty);

        Ok(Some((key, value)))
    }

    /// Close the NDBM database handle.
    ///
    /// Corresponds to `exim_dbclose__` in `hints_ndbm.h` (lines 120-121).
    /// Simply calls `dbm_close(dbp)` — no transaction commit or additional
    /// cleanup is needed (NDBM has no transaction support).
    ///
    /// This method consumes `self` to prevent use-after-close. The [`Drop`]
    /// implementation serves as a safety net if this method is not called.
    fn close(mut self) -> Result<(), HintsDbError> {
        if self.dbm.is_null() {
            return Ok(());
        }

        // Dispatch dbm_close: releases file descriptors and resources.
        ndbm_ffi(NdbmFfi::Close(self.dbm));
        self.dbm = ptr::null_mut();

        Ok(())
    }

    // transaction_start() and transaction_commit() use the default trait
    // implementations (returns false / no-op) because NDBM does not support
    // transactions. This matches:
    //   exim_dbtransaction_start → return FALSE  (hints_ndbm.h line 42)
    //   exim_dbtransaction_commit → {}           (hints_ndbm.h line 43)
}

// ---------------------------------------------------------------------------
// Drop Implementation — Safety Net
// ---------------------------------------------------------------------------

impl Drop for NdbmHintsDb {
    /// Closes the NDBM database handle if it was not explicitly closed.
    ///
    /// This is a safety net for cases where [`close()`](HintsDb::close) was
    /// not called explicitly (e.g., due to an early return or panic). After
    /// `close()` runs, `dbm` is set to null so this becomes a no-op.
    fn drop(&mut self) {
        if self.dbm.is_null() {
            return;
        }

        // Dispatch dbm_close via consolidated FFI.
        ndbm_ffi(NdbmFfi::Close(self.dbm));
        self.dbm = ptr::null_mut();
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify constants match the C header definitions.
    #[test]
    fn test_constants() {
        assert_eq!(EXIM_DBTYPE, "ndbm");
        assert_eq!(EXIM_DB_RLIMIT, 150);
        assert_eq!(EXIM_DBPUTB_OK, 0);
    }

    /// Verify NdbmHintsDb starts with correct state after construction.
    #[test]
    fn test_open_flags_to_posix() {
        let rw_create = OpenFlags::read_write_create();
        assert_eq!(
            open_flags_to_posix(&rw_create),
            libc::O_RDWR | libc::O_CREAT
        );

        let ro = OpenFlags::read_only();
        assert_eq!(open_flags_to_posix(&ro), libc::O_RDONLY);

        let rw = OpenFlags::read_write();
        assert_eq!(open_flags_to_posix(&rw), libc::O_RDWR);
    }

    /// Verify datum conversion for empty datum.
    #[test]
    fn test_hints_datum_to_ndbm_empty() {
        let empty = HintsDbDatum::empty();
        let d = hints_datum_to_ndbm(&empty);
        assert_eq!(d.dsize, 0);
    }

    /// Verify datum conversion for non-empty datum.
    #[test]
    fn test_hints_datum_to_ndbm_data() {
        let datum = HintsDbDatum::new(b"hello");
        let d = hints_datum_to_ndbm(&datum);
        assert_eq!(d.dsize, 5);
        assert!(!d.dptr.is_null());
    }

    /// Verify null datum produces None.
    #[test]
    fn test_ndbm_datum_to_hints_null() {
        let d = ffi::datum {
            dptr: ptr::null_mut(),
            dsize: 0,
        };
        assert!(ndbm_datum_to_hints(d).is_none());
    }

    /// Verify negative dsize produces None.
    #[test]
    fn test_ndbm_datum_to_hints_negative_size() {
        let d = ffi::datum {
            dptr: 1 as *mut libc::c_char, // Non-null but arbitrary
            dsize: -1,
        };
        assert!(ndbm_datum_to_hints(d).is_none());
    }

    /// Verify lstat preflight rejects directories on O_CREAT.
    #[test]
    fn test_open_rejects_directory() {
        let flags = OpenFlags::read_write_create();
        // /tmp is a directory — should be rejected by lstat preflight
        let result = NdbmHintsDb::open("/tmp", &flags, 0o660);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("directory"),
            "Expected 'directory' in error: {}",
            err_msg
        );
    }

    /// Verify lstat preflight rejects existing regular files on O_CREAT.
    #[test]
    fn test_open_rejects_existing_file() {
        let flags = OpenFlags::read_write_create();
        // /etc/hostname is a regular file — should be rejected
        let result = NdbmHintsDb::open("/etc/hostname", &flags, 0o660);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("exists"),
            "Expected 'exists' in error: {}",
            err_msg
        );
    }

    /// Verify that open without O_CREAT skips lstat preflight.
    #[test]
    fn test_open_read_only_nonexistent() {
        let flags = OpenFlags::read_only();
        // Non-existent path, no O_CREAT — should fail at dbm_open, not lstat
        let result = NdbmHintsDb::open("/tmp/nonexistent_ndbm_test_db_zzzz", &flags, 0o660);
        assert!(result.is_err());
        // Error should be from dbm_open, not from lstat
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("ndbm_open failed"),
            "Expected 'ndbm_open failed' in error: {}",
            err_msg
        );
    }

    /// Test full lifecycle: open → put → get → delete → close.
    #[test]
    fn test_full_lifecycle() {
        let dir = std::env::temp_dir().join("ndbm_test_lifecycle");
        let path = dir.to_str().unwrap().to_string();

        // Clean up from any previous test run
        let _ = std::fs::remove_file(format!("{}.pag", path));
        let _ = std::fs::remove_file(format!("{}.dir", path));

        let flags = OpenFlags::read_write_create();
        let mut db = NdbmHintsDb::open(&path, &flags, 0o660).expect("open should succeed");

        // Verify trait methods
        assert!(db.lockfile_needed());
        assert_eq!(db.db_type(), "ndbm");
        assert!(!db.transaction_start()); // No transaction support
        db.transaction_commit(); // No-op

        // Put a key-value pair
        let key = HintsDbDatum::new(b"test_key");
        let value = HintsDbDatum::new(b"test_value");
        db.put(&key, &value).expect("put should succeed");

        // Get the value back
        let result = db.get(&key).expect("get should succeed");
        assert!(result.is_some(), "key should exist");
        assert_eq!(result.unwrap().as_bytes(), b"test_value");

        // Get a non-existent key
        let missing = HintsDbDatum::new(b"no_such_key");
        let result = db.get(&missing).expect("get should succeed");
        assert!(result.is_none(), "missing key should return None");

        // Put with no_overwrite on existing key → Duplicate
        let result = db
            .put_no_overwrite(&key, &value)
            .expect("put_no_overwrite should succeed");
        assert_eq!(result, PutResult::Duplicate);

        // Put with no_overwrite on new key → Ok
        let key2 = HintsDbDatum::new(b"key2");
        let val2 = HintsDbDatum::new(b"val2");
        let result = db
            .put_no_overwrite(&key2, &val2)
            .expect("put_no_overwrite should succeed");
        assert_eq!(result, PutResult::Ok);

        // Delete the first key
        db.delete(&key).expect("delete should succeed");

        // Verify it's gone
        let result = db.get(&key).expect("get should succeed");
        assert!(result.is_none(), "deleted key should be gone");

        // Close
        db.close().expect("close should succeed");

        // Clean up
        let _ = std::fs::remove_file(format!("{}.pag", path));
        let _ = std::fs::remove_file(format!("{}.dir", path));
    }

    /// Test scan functionality.
    #[test]
    fn test_scan() {
        let dir = std::env::temp_dir().join("ndbm_test_scan");
        let path = dir.to_str().unwrap().to_string();

        // Clean up from any previous test run
        let _ = std::fs::remove_file(format!("{}.pag", path));
        let _ = std::fs::remove_file(format!("{}.dir", path));

        let flags = OpenFlags::read_write_create();
        let mut db = NdbmHintsDb::open(&path, &flags, 0o660).expect("open should succeed");

        // Insert some entries
        for i in 0..3 {
            let key = HintsDbDatum::new(format!("key_{}", i).as_bytes());
            let val = HintsDbDatum::new(format!("val_{}", i).as_bytes());
            db.put(&key, &val).expect("put should succeed");
        }

        // Scan all entries
        let mut count = 0;
        let first = db.scan_first().expect("scan_first should succeed");
        if first.is_some() {
            count += 1;
            while let Some(_) = db.scan_next().expect("scan_next should succeed") {
                count += 1;
            }
        }
        assert_eq!(count, 3, "should have scanned 3 entries");

        // Close and clean up
        db.close().expect("close should succeed");
        let _ = std::fs::remove_file(format!("{}.pag", path));
        let _ = std::fs::remove_file(format!("{}.dir", path));
    }

    /// Test scan_next without scan_first returns error.
    #[test]
    fn test_scan_next_without_first() {
        let dir = std::env::temp_dir().join("ndbm_test_scan_order");
        let path = dir.to_str().unwrap().to_string();

        let _ = std::fs::remove_file(format!("{}.pag", path));
        let _ = std::fs::remove_file(format!("{}.dir", path));

        let flags = OpenFlags::read_write_create();
        let mut db = NdbmHintsDb::open(&path, &flags, 0o660).expect("open should succeed");

        let result = db.scan_next();
        assert!(result.is_err(), "scan_next without scan_first should error");

        db.close().expect("close should succeed");
        let _ = std::fs::remove_file(format!("{}.pag", path));
        let _ = std::fs::remove_file(format!("{}.dir", path));
    }

    /// Test Drop safety net (implicit close).
    #[test]
    fn test_drop_closes_handle() {
        let dir = std::env::temp_dir().join("ndbm_test_drop");
        let path = dir.to_str().unwrap().to_string();

        let _ = std::fs::remove_file(format!("{}.pag", path));
        let _ = std::fs::remove_file(format!("{}.dir", path));

        let flags = OpenFlags::read_write_create();
        {
            let mut db = NdbmHintsDb::open(&path, &flags, 0o660).expect("open should succeed");
            let key = HintsDbDatum::new(b"drop_key");
            let val = HintsDbDatum::new(b"drop_val");
            db.put(&key, &val).expect("put should succeed");
            // db dropped here without explicit close()
        }

        // Re-open and verify data persisted
        let flags2 = OpenFlags::read_only();
        let db = NdbmHintsDb::open(&path, &flags2, 0o660).expect("reopen should succeed");
        let key = HintsDbDatum::new(b"drop_key");
        let result = db.get(&key).expect("get should succeed");
        assert!(result.is_some(), "data should persist after implicit close");
        assert_eq!(result.unwrap().as_bytes(), b"drop_val");
        db.close().expect("close should succeed");

        let _ = std::fs::remove_file(format!("{}.pag", path));
        let _ = std::fs::remove_file(format!("{}.dir", path));
    }

    /// Test scan on empty database returns None immediately.
    #[test]
    fn test_scan_empty_db() {
        let dir = std::env::temp_dir().join("ndbm_test_empty_scan");
        let path = dir.to_str().unwrap().to_string();

        let _ = std::fs::remove_file(format!("{}.pag", path));
        let _ = std::fs::remove_file(format!("{}.dir", path));

        let flags = OpenFlags::read_write_create();
        let mut db = NdbmHintsDb::open(&path, &flags, 0o660).expect("open should succeed");

        let result = db.scan_first().expect("scan_first should succeed");
        assert!(result.is_none(), "empty db should return None");

        db.close().expect("close should succeed");
        let _ = std::fs::remove_file(format!("{}.pag", path));
        let _ = std::fs::remove_file(format!("{}.dir", path));
    }
}
