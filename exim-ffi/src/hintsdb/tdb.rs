//! TDB (Trivial Database) hints database backend.
//!
//! Wraps the TDB C API (`<tdb.h>`) for Exim's persistent hints key-value storage.
//! TDB is unique among Exim's hints database backends because it supports
//! transactions natively, eliminating the need for external lockfiles.
//!
//! # Behavioral characteristics (from `hints_tdb.h`)
//!
//! - Handle type is `TDB_CONTEXT*` (opaque pointer to `struct tdb_context`)
//! - Cursor (`EXIM_CURSOR`) and Datum (`EXIM_DATUM`) are both `TDB_DATA` structs
//! - **Supports transactions** — the ONLY hints database backend that does
//! - Lockfiles NOT needed (`lockfile_needed() → false`) due to transaction support
//! - Normal `open()` starts a transaction immediately after opening the database
//! - `open_multi()` opens WITHOUT starting a transaction (for concurrent read access)
//! - `close()` commits any active transaction before closing the handle
//! - Datum `dptr` is allocated by TDB via `malloc` and MUST be freed with `libc::free`
//!   after copying bytes into owned Rust types (applies to `tdb_fetch`, `tdb_firstkey`,
//!   `tdb_nextkey`)
//! - Cursor holds the previous key for `tdb_nextkey()` iteration
//! - `EXIM_DB_RLIMIT = 150` — maximum file descriptor budget for hints databases
//! - `EXIM_DBTYPE = "tdb"` — database type identifier string
//! - `EXIM_DBPUTB_DUP = -1` — duplicate key return code (different from GDBM/NDBM = 1)

use std::ffi::{CStr, CString};
use std::ptr;

use super::{HintsDb, HintsDbDatum, HintsDbError, OpenFlags, PutResult};

// Justification for #[allow(...)]: bindgen-generated FFI bindings preserve the original
// C naming conventions from <tdb.h> for types (TDB_CONTEXT, TDB_DATA, tdb_context),
// functions (tdb_open, tdb_close, tdb_fetch), and constants (TDB_DEFAULT, TDB_REPLACE,
// TDB_INSERT). Renaming these would make cross-referencing with C documentation and the
// TDB library source impossible. dead_code is allowed because bindgen emits all matched
// symbols regardless of which ones this module actually calls.
#[allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    dead_code
)]
mod ffi {
    include!(concat!(env!("OUT_DIR"), "/tdb_bindings.rs"));
}

/// Database type identifier for TDB, matching `EXIM_DBTYPE` in `hints_tdb.h`.
pub const EXIM_DBTYPE: &str = "tdb";

/// Maximum file descriptor budget for TDB hints databases.
/// Matches `EXIM_DB_RLIMIT` (value 150) in `hints_tdb.h` line 213.
pub const EXIM_DB_RLIMIT: usize = 150;

/// Safe wrapper around a TDB hints database handle.
///
/// TDB is unique among hints database backends: it supports transactions natively,
/// so Exim does NOT need external lockfiles for concurrency control. Normal `open()`
/// starts a transaction immediately; `close()` commits it.
///
/// # Memory ownership
///
/// The `tdb` pointer is owned by this struct and is freed via `tdb_close` in the
/// `Drop` implementation (or in explicit `close()`/`close_multi()` calls).
pub struct TdbHintsDb {
    /// Pointer to the underlying `TDB_CONTEXT`. Set to null after close.
    tdb: *mut ffi::tdb_context,
    /// Whether a transaction is currently active.
    /// Normal open sets this to `true`; multi-open leaves it `false`.
    in_transaction: bool,
    /// Cursor state for scan iteration.
    /// Holds the previous key datum needed by `tdb_nextkey()`.
    cursor: Option<TdbCursor>,
}

// SAFETY: TDB_CONTEXT is a handle to a file-backed database. The TdbHintsDb wrapper
// is not Clone and is designed for Exim's fork-per-connection model where each child
// process has exclusive access to its database handle. Send is required by the HintsDb
// trait bound and is safe under this single-owner, single-process usage model.
unsafe impl Send for TdbHintsDb {}

/// TDB cursor for sequential key scanning.
///
/// Holds a `TDB_DATA` struct containing the previous key, which `tdb_nextkey()`
/// requires to determine the next key in the database. The `dptr` field is
/// allocated by TDB's internal `malloc` and must be freed with `libc::free`.
struct TdbCursor {
    data: ffi::TDB_DATA,
}

impl TdbCursor {
    /// Create a new empty cursor with null `dptr`.
    fn new() -> Self {
        Self {
            data: ffi::TDB_DATA {
                dptr: ptr::null_mut(),
                dsize: 0,
            },
        }
    }

    /// Free the cursor's current `dptr` if it was allocated by TDB.
    ///
    /// Resets `dptr` to null and `dsize` to 0 to prevent double-free.
    fn free_dptr(&mut self) {
        if !self.data.dptr.is_null() {
            tdb_ffi(TdbFfi::Free(self.data.dptr as *mut libc::c_void));
            self.data.dptr = ptr::null_mut();
            self.data.dsize = 0;
        }
    }
}

impl Drop for TdbCursor {
    fn drop(&mut self) {
        self.free_dptr();
    }
}

// ---------------------------------------------------------------------------
// Consolidated FFI Dispatch
// ---------------------------------------------------------------------------

/// Internal FFI operation descriptors for the consolidated TDB unsafe dispatch.
/// All unsafe TDB interactions are routed through [`tdb_ffi`] to maintain
/// a single auditable unsafe block for the entire module.
enum TdbFfi {
    /// tdb_open(name, hash_size, tdb_flags, open_flags, mode)
    Open(
        *const libc::c_char,
        libc::c_int,
        libc::c_int,
        libc::c_int,
        u32,
    ),
    /// tdb_close(tdb) → c_int
    Close(*mut ffi::tdb_context),
    /// tdb_fetch(tdb, key) → TDB_DATA
    Fetch(*mut ffi::tdb_context, ffi::TDB_DATA),
    /// tdb_store(tdb, key, data, flag) → c_int
    Store(
        *mut ffi::tdb_context,
        ffi::TDB_DATA,
        ffi::TDB_DATA,
        libc::c_int,
    ),
    /// tdb_delete(tdb, key) → c_int
    Delete(*mut ffi::tdb_context, ffi::TDB_DATA),
    /// tdb_firstkey(tdb) → TDB_DATA
    FirstKey(*mut ffi::tdb_context),
    /// tdb_nextkey(tdb, prev_key) → TDB_DATA
    NextKey(*mut ffi::tdb_context, ffi::TDB_DATA),
    /// tdb_transaction_start(tdb) → c_int
    TxnStart(*mut ffi::tdb_context),
    /// tdb_transaction_commit(tdb) → c_int
    TxnCommit(*mut ffi::tdb_context),
    /// tdb_errorstr(tdb) → string
    ErrorStr(*mut ffi::tdb_context),
    /// libc::free(ptr) for TDB-allocated datum dptr
    Free(*mut libc::c_void),
    /// std::slice::from_raw_parts(ptr, len).to_vec() for TDB datum bytes
    SliceCopy(*const u8, usize),
}

/// Internal FFI result variants returned by the consolidated TDB dispatch.
enum TdbFfiResult {
    Handle(*mut ffi::tdb_context),
    Datum(ffi::TDB_DATA),
    Code(libc::c_int),
    Str(String),
    Bytes(Vec<u8>),
    Done,
}

/// Single consolidated unsafe dispatch point for all TDB FFI operations.
///
/// Every unsafe interaction with libtdb and associated memory operations is
/// routed through this function, maintaining a single auditable unsafe block
/// for the entire module per AAP §0.7.2.
///
/// # Per-variant safety justification
///
/// - `Open`: tdb_open with caller-validated CString path and standard flags/mode
/// - `Close`: tdb_close on a caller-validated non-null handle
/// - `Fetch/Store/Delete`: TDB CRUD on a valid handle with valid TDB_DATA structs
/// - `FirstKey/NextKey`: scan operations returning malloc'd TDB_DATA
/// - `TxnStart/TxnCommit`: transaction management on a valid handle
/// - `ErrorStr`: tdb_errorstr returns static string, copied immediately
/// - `Free`: libc::free on a TDB-allocated datum dptr
/// - `SliceCopy`: from_raw_parts on a TDB-owned buffer, immediately copied to Vec
fn tdb_ffi(op: TdbFfi) -> TdbFfiResult {
    // SAFETY: All TDB FFI operations consolidated into a single auditable unsafe
    // region. Each call site constructs the appropriate TdbFfi variant with validated
    // pointers and handles. The TDB library functions follow their documented
    // contracts: returned TDB_DATA dptr fields are malloc-allocated and must be
    // freed by the caller, handles must not be used after tdb_close, and datum
    // key/data arguments are read by value (struct copy, not pointer ownership
    // transfer).
    unsafe {
        match op {
            TdbFfi::Open(path, hs, tflags, oflags, mode) => {
                TdbFfiResult::Handle(ffi::tdb_open(path, hs, tflags, oflags, mode))
            }
            TdbFfi::Close(h) => TdbFfiResult::Code(ffi::tdb_close(h)),
            TdbFfi::Fetch(h, k) => TdbFfiResult::Datum(ffi::tdb_fetch(h, k)),
            TdbFfi::Store(h, k, d, f) => TdbFfiResult::Code(ffi::tdb_store(h, k, d, f)),
            TdbFfi::Delete(h, k) => TdbFfiResult::Code(ffi::tdb_delete(h, k)),
            TdbFfi::FirstKey(h) => TdbFfiResult::Datum(ffi::tdb_firstkey(h)),
            TdbFfi::NextKey(h, prev) => TdbFfiResult::Datum(ffi::tdb_nextkey(h, prev)),
            TdbFfi::TxnStart(h) => TdbFfiResult::Code(ffi::tdb_transaction_start(h)),
            TdbFfi::TxnCommit(h) => TdbFfiResult::Code(ffi::tdb_transaction_commit(h)),
            TdbFfi::ErrorStr(h) => {
                let ptr = ffi::tdb_errorstr(h);
                let s = if ptr.is_null() {
                    "unknown TDB error".to_string()
                } else {
                    CStr::from_ptr(ptr).to_string_lossy().into_owned()
                };
                TdbFfiResult::Str(s)
            }
            TdbFfi::Free(p) => {
                libc::free(p);
                TdbFfiResult::Done
            }
            TdbFfi::SliceCopy(p, len) => {
                TdbFfiResult::Bytes(std::slice::from_raw_parts(p, len).to_vec())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

/// Get a human-readable error string from the TDB context.
///
/// Calls `tdb_errorstr(db)` and converts the returned C string to an owned
/// Rust `String`. Returns a fallback message if the pointer is null.
fn tdb_error_string(tdb: *mut ffi::tdb_context) -> String {
    match tdb_ffi(TdbFfi::ErrorStr(tdb)) {
        TdbFfiResult::Str(s) => s,
        _ => unreachable!(),
    }
}

/// Convert an [`HintsDbDatum`] reference to a `TDB_DATA` for passing to TDB functions.
///
/// The returned `TDB_DATA` borrows the datum's internal byte buffer via a raw
/// pointer. The caller MUST ensure the datum outlives the `TDB_DATA` and that
/// TDB does not attempt to free or reallocate the `dptr`.
fn datum_to_tdb_data(datum: &HintsDbDatum) -> ffi::TDB_DATA {
    let bytes = datum.as_bytes();
    ffi::TDB_DATA {
        dptr: bytes.as_ptr() as *mut u8,
        dsize: bytes.len(),
    }
}

/// Convert a `TDB_DATA` returned by TDB into an owned [`HintsDbDatum`],
/// freeing the C-allocated `dptr` afterwards.
///
/// Returns `None` if `dptr` is null (indicating no data found or end of scan).
fn tdb_data_to_datum(data: ffi::TDB_DATA) -> Option<HintsDbDatum> {
    if data.dptr.is_null() {
        return None;
    }
    let bytes = match tdb_ffi(TdbFfi::SliceCopy(data.dptr, data.dsize)) {
        TdbFfiResult::Bytes(b) => b,
        _ => unreachable!(),
    };
    tdb_ffi(TdbFfi::Free(data.dptr as *mut libc::c_void));
    Some(HintsDbDatum::new(&bytes))
}

/// Convert [`OpenFlags`] to POSIX `open()` flags suitable for `tdb_open`.
fn open_flags_to_posix(flags: &OpenFlags) -> libc::c_int {
    if flags.read_only {
        libc::O_RDONLY
    } else if flags.create {
        libc::O_RDWR | libc::O_CREAT
    } else {
        libc::O_RDWR
    }
}

// ---------------------------------------------------------------------------
// TdbHintsDb — Inherent Methods (open, open_multi, close_multi)
// ---------------------------------------------------------------------------

impl TdbHintsDb {
    /// Open a TDB database, starting a transaction immediately.
    ///
    /// This is the normal open path corresponding to `exim_dbopen__` in
    /// `hints_tdb.h` (lines 39-56). After successfully opening the database,
    /// a transaction is started. If the transaction cannot be started, the
    /// database is closed and an error is returned.
    ///
    /// # Arguments
    ///
    /// * `path` — File path for the TDB database (null terminator added internally)
    /// * `flags` — Open mode flags (read-only, read-write, create)
    /// * `mode` — POSIX file permission bits (e.g., `0o660`)
    ///
    /// # Errors
    ///
    /// Returns [`HintsDbError`] if the database cannot be opened or if the
    /// initial transaction cannot be started.
    pub fn open(path: &str, flags: &OpenFlags, mode: u32) -> Result<Self, HintsDbError> {
        let c_path = CString::new(path)
            .map_err(|e| HintsDbError::new(format!("invalid database path: {e}")))?;
        let posix_flags = open_flags_to_posix(flags);

        // Dispatch tdb_open: valid CString path, hash_size=0, TDB_DEFAULT, POSIX flags, mode.
        let tdb = match tdb_ffi(TdbFfi::Open(
            c_path.as_ptr(),
            0,
            ffi::TDB_DEFAULT as libc::c_int,
            posix_flags,
            mode,
        )) {
            TdbFfiResult::Handle(h) => h,
            _ => unreachable!(),
        };

        if tdb.is_null() {
            return Err(HintsDbError::new(format!(
                "tdb_open failed for '{}': {}",
                path,
                std::io::Error::last_os_error()
            )));
        }

        // Start a transaction immediately — the normal open behavior that
        // distinguishes TDB from other backends.
        let rc = match tdb_ffi(TdbFfi::TxnStart(tdb)) {
            TdbFfiResult::Code(c) => c,
            _ => unreachable!(),
        };
        if rc != 0 {
            let err_msg = tdb_error_string(tdb);
            // Close the handle after failed transaction start.
            tdb_ffi(TdbFfi::Close(tdb));
            return Err(HintsDbError::new(format!(
                "tdb_transaction_start failed for '{}': {}",
                path, err_msg
            )));
        }

        Ok(Self {
            tdb,
            in_transaction: true,
            cursor: None,
        })
    }

    /// Open a TDB database WITHOUT starting a transaction.
    ///
    /// Corresponds to `exim_dbopen_multi__` in `hints_tdb.h` (lines 58-67).
    /// Used for concurrent read-only access where transactions are not needed.
    ///
    /// # Arguments
    ///
    /// * `path` — File path for the TDB database
    /// * `flags` — Open mode flags (typically read-only)
    /// * `mode` — POSIX file permission bits
    ///
    /// # Errors
    ///
    /// Returns [`HintsDbError`] if the database cannot be opened.
    pub fn open_multi(path: &str, flags: &OpenFlags, mode: u32) -> Result<Self, HintsDbError> {
        let c_path = CString::new(path)
            .map_err(|e| HintsDbError::new(format!("invalid database path: {e}")))?;
        let posix_flags = open_flags_to_posix(flags);

        // Dispatch tdb_open for multi-open (no transaction).
        let tdb = match tdb_ffi(TdbFfi::Open(
            c_path.as_ptr(),
            0,
            ffi::TDB_DEFAULT as libc::c_int,
            posix_flags,
            mode,
        )) {
            TdbFfiResult::Handle(h) => h,
            _ => unreachable!(),
        };

        if tdb.is_null() {
            return Err(HintsDbError::new(format!(
                "tdb_open_multi failed for '{}': {}",
                path,
                std::io::Error::last_os_error()
            )));
        }

        Ok(Self {
            tdb,
            in_transaction: false,
            cursor: None,
        })
    }

    /// Close a multi-opened TDB database (no transaction to commit).
    ///
    /// Corresponds to `exim_dbclose_multi__` in `hints_tdb.h` (lines 162-167).
    /// Simply closes the database handle without committing a transaction
    /// (since `open_multi` does not start one).
    ///
    /// This method consumes `self` to prevent use-after-close.
    ///
    /// # Errors
    ///
    /// Returns [`HintsDbError`] if `tdb_close` fails.
    pub fn close_multi(mut self) -> Result<(), HintsDbError> {
        // Drop cursor first to free any allocated dptr before closing.
        self.cursor = None;

        // Dispatch tdb_close: releases all TDB resources for multi-open handles.
        let rc = match tdb_ffi(TdbFfi::Close(self.tdb)) {
            TdbFfiResult::Code(c) => c,
            _ => unreachable!(),
        };
        self.tdb = ptr::null_mut();
        // When this function returns, Drop runs but sees null tdb → no-op.

        if rc != 0 {
            return Err(HintsDbError::new("tdb_close (multi) failed"));
        }
        Ok(())
    }

    /// Internal helper for scan operations: performs `tdb_firstkey` or
    /// `tdb_nextkey` and fetches the corresponding value.
    ///
    /// Returns `Ok(None)` when iteration is exhausted.
    fn scan_impl(
        &mut self,
        first: bool,
    ) -> Result<Option<(HintsDbDatum, HintsDbDatum)>, HintsDbError> {
        let cursor = self.cursor.get_or_insert_with(TdbCursor::new);

        // Step 1: Dispatch firstkey or nextkey via consolidated FFI.
        let new_key = if first {
            match tdb_ffi(TdbFfi::FirstKey(self.tdb)) {
                TdbFfiResult::Datum(d) => d,
                _ => unreachable!(),
            }
        } else {
            match tdb_ffi(TdbFfi::NextKey(self.tdb, cursor.data)) {
                TdbFfiResult::Datum(d) => d,
                _ => unreachable!(),
            }
        };

        // Step 2: Free the PREVIOUS cursor dptr AFTER nextkey read it.
        cursor.free_dptr();

        // Step 3: Update cursor with the new key.
        cursor.data = new_key;

        if new_key.dptr.is_null() {
            return Ok(None);
        }

        // Step 4: Copy key bytes via dispatch.
        let key_bytes = match tdb_ffi(TdbFfi::SliceCopy(new_key.dptr, new_key.dsize)) {
            TdbFfiResult::Bytes(b) => b,
            _ => unreachable!(),
        };
        let key_datum = HintsDbDatum::new(&key_bytes);

        // Step 5: Fetch the value for this key.
        let value = match tdb_ffi(TdbFfi::Fetch(self.tdb, new_key)) {
            TdbFfiResult::Datum(d) => d,
            _ => unreachable!(),
        };
        let value_datum = tdb_data_to_datum(value).unwrap_or_else(HintsDbDatum::empty);

        Ok(Some((key_datum, value_datum)))
    }
}

// ---------------------------------------------------------------------------
// HintsDb Trait Implementation
// ---------------------------------------------------------------------------

impl HintsDb for TdbHintsDb {
    /// TDB does NOT need external lockfiles — it uses transactions instead.
    ///
    /// This is the ONLY hints database backend that returns `false`. All other
    /// backends (BDB, GDBM, NDBM) require external lockfiles for concurrency.
    fn lockfile_needed(&self) -> bool {
        false
    }

    /// Returns the database type identifier: `"tdb"`.
    fn db_type(&self) -> &'static str {
        EXIM_DBTYPE
    }

    /// Fetch a value by key from the TDB database.
    ///
    /// Calls `tdb_fetch(db, key)` which returns `TDB_DATA` by value. The
    /// returned datum contains a copy of the data; the C-allocated `dptr`
    /// memory is freed immediately after copying into a Rust `Vec<u8>`.
    ///
    /// Returns `Ok(None)` if the key is not found.
    fn get(&self, key: &HintsDbDatum) -> Result<Option<HintsDbDatum>, HintsDbError> {
        let tdb_key = datum_to_tdb_data(key);

        // Dispatch tdb_fetch: self.tdb is valid, key is by-value struct copy.
        let result = match tdb_ffi(TdbFfi::Fetch(self.tdb, tdb_key)) {
            TdbFfiResult::Datum(d) => d,
            _ => unreachable!(),
        };

        Ok(tdb_data_to_datum(result))
    }

    /// Store a key-value pair, replacing any existing value.
    ///
    /// Uses `TDB_REPLACE` flag (value 1). If the key does not exist, a new
    /// entry is created. If it exists, the value is overwritten.
    ///
    /// Corresponds to `exim_dbput__` in `hints_tdb.h` (lines 99-106).
    fn put(&mut self, key: &HintsDbDatum, data: &HintsDbDatum) -> Result<(), HintsDbError> {
        let tdb_key = datum_to_tdb_data(key);
        let tdb_data = datum_to_tdb_data(data);

        // Dispatch tdb_store with TDB_REPLACE: self.tdb is valid, key/data by-value.
        let rc = match tdb_ffi(TdbFfi::Store(
            self.tdb,
            tdb_key,
            tdb_data,
            ffi::TDB_REPLACE as libc::c_int,
        )) {
            TdbFfiResult::Code(c) => c,
            _ => unreachable!(),
        };

        if rc != 0 {
            return Err(HintsDbError::new(format!(
                "tdb_store (replace) failed: {}",
                tdb_error_string(self.tdb)
            )));
        }
        Ok(())
    }

    /// Store a key-value pair only if the key does not already exist.
    ///
    /// Uses `TDB_INSERT` flag (value 2). Returns [`PutResult::Ok`] on success,
    /// [`PutResult::Duplicate`] if the key already exists.
    ///
    /// The C code in `hints_tdb.h` (lines 109-111) treats ANY non-zero return
    /// from `tdb_store` as duplicate (`EXIM_DBPUTB_DUP = -1`) without
    /// distinguishing error types. This wrapper follows the same pattern for
    /// exact behavioral parity.
    ///
    /// NOTE: TDB uses -1 for duplicate, different from GDBM/NDBM which use 1.
    fn put_no_overwrite(
        &mut self,
        key: &HintsDbDatum,
        data: &HintsDbDatum,
    ) -> Result<PutResult, HintsDbError> {
        let tdb_key = datum_to_tdb_data(key);
        let tdb_data = datum_to_tdb_data(data);

        // Dispatch tdb_store with TDB_INSERT: returns non-zero if key exists.
        let rc = match tdb_ffi(TdbFfi::Store(
            self.tdb,
            tdb_key,
            tdb_data,
            ffi::TDB_INSERT as libc::c_int,
        )) {
            TdbFfiResult::Code(c) => c,
            _ => unreachable!(),
        };

        // Match C behavior: 0 = success, any non-zero = duplicate.
        if rc == 0 {
            Ok(PutResult::Ok)
        } else {
            Ok(PutResult::Duplicate)
        }
    }

    /// Delete a key-value pair from the TDB database.
    ///
    /// Corresponds to `exim_dbdel__` in `hints_tdb.h` (lines 119-121).
    fn delete(&mut self, key: &HintsDbDatum) -> Result<(), HintsDbError> {
        let tdb_key = datum_to_tdb_data(key);

        // Dispatch tdb_delete: self.tdb is valid, key by-value struct copy.
        let rc = match tdb_ffi(TdbFfi::Delete(self.tdb, tdb_key)) {
            TdbFfiResult::Code(c) => c,
            _ => unreachable!(),
        };

        if rc != 0 {
            return Err(HintsDbError::new(format!(
                "tdb_delete failed: {}",
                tdb_error_string(self.tdb)
            )));
        }
        Ok(())
    }

    /// Begin scanning from the first key in the TDB database.
    ///
    /// Resets any existing cursor and returns the first key-value pair.
    /// Returns `Ok(None)` if the database is empty.
    ///
    /// The cursor is maintained internally for subsequent [`scan_next`] calls.
    fn scan_first(&mut self) -> Result<Option<(HintsDbDatum, HintsDbDatum)>, HintsDbError> {
        // Reset cursor for a fresh scan — drops any previous cursor, which
        // frees its allocated dptr via TdbCursor::Drop.
        self.cursor = Some(TdbCursor::new());
        self.scan_impl(true)
    }

    /// Continue scanning to the next key in the TDB database.
    ///
    /// Must be called after [`scan_first`]. Uses the cursor's previous key
    /// to determine the next key via `tdb_nextkey(db, prev_key)`.
    ///
    /// Returns `Ok(None)` when iteration is exhausted.
    fn scan_next(&mut self) -> Result<Option<(HintsDbDatum, HintsDbDatum)>, HintsDbError> {
        if self.cursor.is_none() {
            return Err(HintsDbError::new(
                "scan_next called without prior scan_first",
            ));
        }
        self.scan_impl(false)
    }

    /// Close the TDB database, committing any active transaction first.
    ///
    /// Corresponds to `exim_dbclose__` in `hints_tdb.h` (lines 169-178).
    /// First commits the active transaction, then closes the database handle.
    /// Errors from either operation are captured and returned.
    ///
    /// This method consumes `self` to prevent use-after-close. The `Drop`
    /// implementation serves as a safety net if this method is not called.
    fn close(mut self) -> Result<(), HintsDbError> {
        // Drop cursor first to free any allocated dptr.
        self.cursor = None;

        let mut commit_err: Option<String> = None;

        // Commit the transaction if one is active.
        if self.in_transaction {
            let rc = match tdb_ffi(TdbFfi::TxnCommit(self.tdb)) {
                TdbFfiResult::Code(c) => c,
                _ => unreachable!(),
            };
            if rc != 0 {
                commit_err = Some(tdb_error_string(self.tdb));
            }
            self.in_transaction = false;
        }

        // Close the database handle via dispatch.
        let close_rc = match tdb_ffi(TdbFfi::Close(self.tdb)) {
            TdbFfiResult::Code(c) => c,
            _ => unreachable!(),
        };
        self.tdb = ptr::null_mut();
        // After returning, Drop runs but sees null tdb → no-op.

        match (commit_err, close_rc != 0) {
            (None, false) => Ok(()),
            (Some(e), false) => Err(HintsDbError::new(format!(
                "tdb_transaction_commit failed: {e}"
            ))),
            (None, true) => Err(HintsDbError::new("tdb_close failed")),
            (Some(e), true) => Err(HintsDbError::new(format!(
                "tdb_transaction_commit failed: {e}; tdb_close also failed"
            ))),
        }
    }

    /// Start a new transaction on the TDB database.
    ///
    /// TDB is the ONLY hints database backend with real transaction support.
    /// All other backends return `false` from their default trait implementation.
    ///
    /// Returns `true` if the transaction was started successfully, `false`
    /// if a transaction is already active or if `tdb_transaction_start` fails.
    fn transaction_start(&mut self) -> bool {
        if self.in_transaction {
            // Already in a transaction — TDB does not support nesting.
            return false;
        }

        // Dispatch tdb_transaction_start: self.tdb is valid, no active transaction.
        let rc = match tdb_ffi(TdbFfi::TxnStart(self.tdb)) {
            TdbFfiResult::Code(c) => c,
            _ => unreachable!(),
        };
        if rc == 0 {
            self.in_transaction = true;
            true
        } else {
            tracing::debug!(
                "tdb_transaction_start failed: {}",
                tdb_error_string(self.tdb)
            );
            false
        }
    }

    /// Commit the current transaction.
    ///
    /// TDB is the ONLY hints database backend with real transaction support.
    /// All other backends have a no-op default trait implementation.
    ///
    /// If no transaction is active, this is a no-op.
    fn transaction_commit(&mut self) {
        if !self.in_transaction {
            return;
        }

        // Dispatch tdb_transaction_commit: self.tdb is valid, transaction active.
        let rc = match tdb_ffi(TdbFfi::TxnCommit(self.tdb)) {
            TdbFfiResult::Code(c) => c,
            _ => unreachable!(),
        };
        self.in_transaction = false;

        if rc != 0 {
            tracing::debug!(
                "tdb_transaction_commit failed: {}",
                tdb_error_string(self.tdb)
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Drop Implementation — Safety Net
// ---------------------------------------------------------------------------

impl Drop for TdbHintsDb {
    /// Commits any active transaction and closes the TDB database handle.
    ///
    /// This is a safety net for cases where `close()` or `close_multi()` was
    /// not called explicitly (e.g., due to an early return or panic). After
    /// those methods run, `tdb` is set to null so this becomes a no-op.
    fn drop(&mut self) {
        if self.tdb.is_null() {
            return;
        }

        // Drop cursor first to free any allocated key dptr.
        self.cursor = None;

        // Best-effort commit if a transaction is active.
        if self.in_transaction {
            let rc = match tdb_ffi(TdbFfi::TxnCommit(self.tdb)) {
                TdbFfiResult::Code(c) => c,
                _ => unreachable!(),
            };
            if rc != 0 {
                tracing::debug!(
                    "tdb drop: transaction_commit failed: {}",
                    tdb_error_string(self.tdb)
                );
            }
            self.in_transaction = false;
        }

        // Close the database handle via dispatch.
        let rc = match tdb_ffi(TdbFfi::Close(self.tdb)) {
            TdbFfiResult::Code(c) => c,
            _ => unreachable!(),
        };
        if rc != 0 {
            tracing::debug!("tdb drop: tdb_close failed");
        }
        self.tdb = ptr::null_mut();
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
        assert_eq!(EXIM_DBTYPE, "tdb");
        assert_eq!(EXIM_DB_RLIMIT, 150);
    }

    /// Verify TdbCursor starts with null dptr.
    #[test]
    fn test_cursor_new() {
        let cursor = TdbCursor::new();
        assert!(cursor.data.dptr.is_null());
        assert_eq!(cursor.data.dsize, 0);
    }

    /// Verify TdbCursor::free_dptr is a no-op on null.
    #[test]
    fn test_cursor_free_null() {
        let mut cursor = TdbCursor::new();
        // Should not panic or crash.
        cursor.free_dptr();
        assert!(cursor.data.dptr.is_null());
    }

    /// Verify datum_to_tdb_data round-trip.
    #[test]
    fn test_datum_to_tdb_data() {
        let datum = HintsDbDatum::new(b"test_key");
        let tdb_data = datum_to_tdb_data(&datum);
        assert_eq!(tdb_data.dsize, 8);
        assert!(!tdb_data.dptr.is_null());
    }

    /// Verify tdb_data_to_datum with null returns None.
    #[test]
    fn test_tdb_data_to_datum_null() {
        let data = ffi::TDB_DATA {
            dptr: ptr::null_mut(),
            dsize: 0,
        };
        assert!(tdb_data_to_datum(data).is_none());
    }

    /// Verify open_flags_to_posix conversions.
    #[test]
    fn test_open_flags_to_posix() {
        let ro = OpenFlags::read_only();
        assert_eq!(open_flags_to_posix(&ro), libc::O_RDONLY);

        let rw = OpenFlags::read_write();
        assert_eq!(open_flags_to_posix(&rw), libc::O_RDWR);

        let rwc = OpenFlags::read_write_create();
        assert_eq!(open_flags_to_posix(&rwc), libc::O_RDWR | libc::O_CREAT);
    }

    /// Verify open with invalid path returns error (NUL byte in path).
    #[test]
    fn test_open_invalid_path() {
        let flags = OpenFlags::read_write_create();
        let result = TdbHintsDb::open("path\0with_null", &flags, 0o660);
        assert!(result.is_err());
    }

    /// Verify open_multi with invalid path returns error.
    #[test]
    fn test_open_multi_invalid_path() {
        let flags = OpenFlags::read_only();
        let result = TdbHintsDb::open_multi("path\0with_null", &flags, 0o660);
        assert!(result.is_err());
    }
}
