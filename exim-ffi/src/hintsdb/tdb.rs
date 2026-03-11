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
            // SAFETY: dptr was allocated by TDB's internal malloc (via tdb_firstkey
            // or tdb_nextkey). The TDB documentation explicitly states: "the caller
            // frees any returned TDB_DATA structures. Just call free(p.dptr)."
            // After freeing, we null the pointer to prevent double-free.
            unsafe {
                libc::free(self.data.dptr as *mut libc::c_void);
            }
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
// Helper Functions
// ---------------------------------------------------------------------------

/// Get a human-readable error string from the TDB context.
///
/// Calls `tdb_errorstr(db)` and converts the returned C string to an owned
/// Rust `String`. Returns a fallback message if the pointer is null.
///
/// # Precondition
///
/// `tdb` must be a valid, non-null `TDB_CONTEXT` pointer. Do NOT call this
/// after `tdb_close()` — the TDB documentation warns that the context is
/// freed by `tdb_close`.
fn tdb_error_string(tdb: *mut ffi::tdb_context) -> String {
    // SAFETY: tdb_errorstr returns a pointer to a static string literal
    // describing the most recent TDB error code. The returned pointer is valid
    // for the lifetime of the TDB library (not tied to the context lifetime).
    // We copy the bytes into an owned String immediately via to_string_lossy,
    // so no dangling reference is possible even if the context is later freed.
    unsafe {
        let ptr = ffi::tdb_errorstr(tdb);
        if ptr.is_null() {
            "unknown TDB error".to_string()
        } else {
            CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
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
        // Cast from *const u8 to *mut u8 is needed because TDB_DATA.dptr is
        // declared as `unsigned char *` (mutable). TDB's read operations
        // (tdb_fetch, tdb_delete) do not actually mutate the key data, so
        // this cast is safe for those call sites.
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
    // SAFETY: data.dptr is non-null and points to data.dsize contiguous bytes
    // allocated by TDB's internal malloc. We create a temporary slice view,
    // copy the bytes into a Vec<u8> via HintsDbDatum::new, then free the
    // original C-allocated memory with libc::free to prevent a memory leak.
    // The slice is only valid until the free call, which happens after the copy.
    unsafe {
        let bytes = std::slice::from_raw_parts(data.dptr, data.dsize);
        let datum = HintsDbDatum::new(bytes);
        libc::free(data.dptr as *mut libc::c_void);
        Some(datum)
    }
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

        // SAFETY: tdb_open is called with a valid null-terminated C string from CString,
        // hash_size=0 (TDB default), TDB_DEFAULT flags, valid POSIX open flags, and
        // valid file mode bits. Returns a valid tdb_context pointer on success or null
        // on failure (with errno set).
        let tdb = unsafe {
            ffi::tdb_open(
                c_path.as_ptr(),
                0,
                ffi::TDB_DEFAULT as libc::c_int,
                posix_flags,
                mode,
            )
        };

        if tdb.is_null() {
            return Err(HintsDbError::new(format!(
                "tdb_open failed for '{}': {}",
                path,
                std::io::Error::last_os_error()
            )));
        }

        // Start a transaction immediately — this is the normal open behavior
        // that distinguishes TDB from other backends. The transaction ensures
        // atomicity for all subsequent operations until close() commits it.
        //
        // SAFETY: tdb is a valid, non-null pointer just returned by tdb_open.
        // tdb_transaction_start returns 0 on success, non-zero on failure.
        let rc = unsafe { ffi::tdb_transaction_start(tdb) };
        if rc != 0 {
            let err_msg = tdb_error_string(tdb);
            // SAFETY: tdb is valid; we must close it to release file descriptors
            // and internal resources after the failed transaction start.
            unsafe {
                ffi::tdb_close(tdb);
            }
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

        // SAFETY: tdb_open with valid arguments as documented in open(). No
        // transaction is started for the multi-open path.
        let tdb = unsafe {
            ffi::tdb_open(
                c_path.as_ptr(),
                0,
                ffi::TDB_DEFAULT as libc::c_int,
                posix_flags,
                mode,
            )
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

        // SAFETY: self.tdb is a valid tdb_context pointer from tdb_open.
        // tdb_close returns 0 on success, -1 on error. After this call the
        // tdb_context is freed by TDB — we null our pointer to prevent
        // Drop from double-closing.
        let rc = unsafe { ffi::tdb_close(self.tdb) };
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

        // Step 1: Obtain the next key. For the first call, use tdb_firstkey.
        // For subsequent calls, tdb_nextkey needs the previous key from the
        // cursor to determine the next entry in the hash chain.
        //
        // SAFETY: self.tdb is a valid tdb_context pointer.
        // - tdb_firstkey: takes only the context, returns TDB_DATA by value
        //   with a malloc'd dptr (or null dptr if database is empty).
        // - tdb_nextkey: takes the context and previous key (by value),
        //   returns TDB_DATA with a malloc'd dptr (or null dptr at end).
        let new_key = unsafe {
            if first {
                ffi::tdb_firstkey(self.tdb)
            } else {
                ffi::tdb_nextkey(self.tdb, cursor.data)
            }
        };

        // Step 2: Free the PREVIOUS cursor dptr. This MUST happen AFTER
        // tdb_nextkey uses it. Follows the C pattern in hints_tdb.h:
        //   free(cursor->dptr);
        //   *cursor = *key;
        cursor.free_dptr();

        // Step 3: Update cursor with the new key (struct copy — the cursor
        // now owns the malloc'd dptr for freeing on next iteration or drop).
        cursor.data = new_key;

        // Check if iteration is exhausted (null dptr = no more keys).
        if new_key.dptr.is_null() {
            return Ok(None);
        }

        // Step 4: Copy key bytes into an owned Rust datum. The original dptr
        // stays in cursor.data for the next tdb_nextkey call.
        //
        // SAFETY: new_key.dptr is non-null and points to new_key.dsize bytes
        // allocated by TDB. We only read from it; ownership stays with the
        // cursor until the next iteration or cursor drop.
        let key_bytes = unsafe { std::slice::from_raw_parts(new_key.dptr, new_key.dsize) };
        let key_datum = HintsDbDatum::new(key_bytes);

        // Step 5: Fetch the value for this key. Pass the key TDB_DATA by value.
        //
        // SAFETY: self.tdb is valid, new_key has a non-null dptr. tdb_fetch
        // returns TDB_DATA by value with its own malloc'd dptr that we free
        // inside tdb_data_to_datum.
        let value = unsafe { ffi::tdb_fetch(self.tdb, new_key) };

        // Convert value to owned datum (frees value dptr) or empty if missing.
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

        // SAFETY: self.tdb is a valid tdb_context pointer. tdb_fetch takes a
        // TDB_DATA key by value and returns a TDB_DATA result by value. The
        // result's dptr is malloc'd by TDB — freed in tdb_data_to_datum.
        let result = unsafe { ffi::tdb_fetch(self.tdb, tdb_key) };

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

        // SAFETY: self.tdb is a valid tdb_context pointer. tdb_store takes
        // key and data TDB_DATA by value (struct copy — TDB reads from the
        // dptr buffers but does not take ownership). TDB_REPLACE permits
        // overwriting. Returns 0 on success, non-zero on error.
        let rc =
            unsafe { ffi::tdb_store(self.tdb, tdb_key, tdb_data, ffi::TDB_REPLACE as libc::c_int) };

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

        // SAFETY: self.tdb is a valid tdb_context pointer. tdb_store with
        // TDB_INSERT will fail (return non-zero) if the key already exists.
        let rc =
            unsafe { ffi::tdb_store(self.tdb, tdb_key, tdb_data, ffi::TDB_INSERT as libc::c_int) };

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

        // SAFETY: self.tdb is a valid tdb_context pointer. tdb_delete takes
        // the key TDB_DATA by value. Returns 0 on success, -1 on error.
        let rc = unsafe { ffi::tdb_delete(self.tdb, tdb_key) };

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
            // SAFETY: self.tdb is a valid tdb_context pointer with an active
            // transaction. tdb_transaction_commit returns 0 on success.
            let rc = unsafe { ffi::tdb_transaction_commit(self.tdb) };
            if rc != 0 {
                commit_err = Some(tdb_error_string(self.tdb));
            }
            self.in_transaction = false;
        }

        // Close the database handle. After tdb_close, the tdb_context is freed
        // by TDB — we MUST NOT call tdb_errorstr after this point.
        //
        // SAFETY: self.tdb is a valid tdb_context pointer (whether or not the
        // commit succeeded). tdb_close releases all internal TDB resources.
        let close_rc = unsafe { ffi::tdb_close(self.tdb) };
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

        // SAFETY: self.tdb is a valid tdb_context pointer with no active
        // transaction. tdb_transaction_start returns 0 on success.
        let rc = unsafe { ffi::tdb_transaction_start(self.tdb) };
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

        // SAFETY: self.tdb is a valid tdb_context pointer with an active
        // transaction (verified by in_transaction flag above).
        let rc = unsafe { ffi::tdb_transaction_commit(self.tdb) };
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
            // SAFETY: self.tdb is valid (non-null check above) with an active
            // transaction. Best-effort commit — errors are logged but cannot
            // be propagated from Drop.
            let rc = unsafe { ffi::tdb_transaction_commit(self.tdb) };
            if rc != 0 {
                tracing::debug!(
                    "tdb drop: transaction_commit failed: {}",
                    tdb_error_string(self.tdb)
                );
            }
            self.in_transaction = false;
        }

        // Close the database handle to release file descriptors and resources.
        //
        // SAFETY: self.tdb is valid (non-null check above). tdb_close frees
        // the internal tdb_context. After this call we null the pointer even
        // though the struct is being dropped, for defense-in-depth.
        let rc = unsafe { ffi::tdb_close(self.tdb) };
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
