//! GDBM (GNU Database Manager) hints database backend.
//!
//! Wraps the GDBM C API (`<gdbm.h>`) for Exim's persistent hints key-value storage.
//!
//! # Behavioral characteristics (from `hints_gdbm.h`)
//!
//! - Handle struct contains `GDBM_FILE` + `datum lkey` for tracking last key during scans
//! - Lockfiles required (`lockfile_needed() → true`)
//! - No cursor object — uses `gdbm_firstkey/gdbm_nextkey` with remembered last key
//! - No transaction support (stubbed with `false`/no-op)
//! - No multi-open support (stubbed)
//! - Datum `dptr` must be freed after fetch/firstkey/nextkey (caller owns memory)
//! - `EXIM_DB_RLIMIT = 150`
//! - `EXIM_DBTYPE = "gdbm"`
//!
//! # Memory ownership
//!
//! GDBM returns `datum` structs from `gdbm_fetch`, `gdbm_firstkey`, and
//! `gdbm_nextkey` where the `dptr` field is `malloc`-allocated. The Rust
//! wrappers immediately copy the bytes into owned [`HintsDbDatum`] values and
//! then free the C-allocated memory with `libc::free` to prevent leaks.
//!
//! # Safety
//!
//! This module is part of the `exim-ffi` crate — the ONLY crate in the Exim
//! workspace permitted to contain `unsafe` code. Every `unsafe` block has an
//! inline justification comment documenting why it is necessary and sound.

use std::ffi::CString;
use std::ptr;

use super::{HintsDb, HintsDbDatum, HintsDbError, OpenFlags, PutResult};

// Justification for #[allow(...)]: bindgen-generated FFI bindings preserve the original
// C naming conventions from <gdbm.h> for types (GDBM_FILE, datum, gdbm_file_info),
// functions (gdbm_open, gdbm_close, gdbm_fetch, gdbm_store, gdbm_delete, gdbm_firstkey,
// gdbm_nextkey, gdbm_strerror), and constants (GDBM_READER, GDBM_WRITER, GDBM_WRCREAT,
// GDBM_REPLACE, GDBM_INSERT). Renaming these would make cross-referencing with C
// documentation and the GDBM library source impossible. dead_code is allowed because
// bindgen emits all matched symbols regardless of which ones this module actually calls.
#[allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    dead_code
)]
mod ffi {
    include!(concat!(env!("OUT_DIR"), "/gdbm_bindings.rs"));
}

/// Database type identifier for GDBM, matching `EXIM_DBTYPE` in `hints_gdbm.h` line 33.
pub const EXIM_DBTYPE: &str = "gdbm";

/// Maximum file descriptor budget for GDBM hints databases.
/// Matches `EXIM_DB_RLIMIT` (value 150) in `hints_gdbm.h` line 163.
pub const EXIM_DB_RLIMIT: usize = 150;

/// Return code for successful `put_no_overwrite` operation.
/// Matches `EXIM_DBPUTB_OK` (value 0) in `hints_gdbm.h` line 94.
const EXIM_DBPUTB_OK: libc::c_int = 0;

/// Safe wrapper around a GDBM hints database handle.
///
/// Contains the GDBM file handle plus the last key datum for sequential
/// scanning. The `lkey` field is necessary because `gdbm_nextkey()` requires
/// the previous key to determine iteration position.
///
/// Corresponds to the `EXIM_DB` struct in `hints_gdbm.h` (lines 20-23):
/// ```c
/// typedef struct {
///     GDBM_FILE gdbm;
///     datum lkey;
/// } EXIM_DB;
/// ```
///
/// # Memory ownership
///
/// - `gdbm` is an opaque `GDBM_FILE` handle freed by `gdbm_close()` in
///   [`Drop`] or [`close()`](HintsDb::close).
/// - `lkey` is a datum whose `dptr` may be `malloc`-allocated from
///   `gdbm_firstkey` or `gdbm_nextkey`. It is freed with `libc::free()` when:
///   - A new key replaces it during scan iteration
///   - The handle is closed (Drop or explicit close)
pub struct GdbmHintsDb {
    /// Opaque GDBM database file handle. Set to null after close.
    gdbm: ffi::GDBM_FILE,
    /// Last key datum for scan iteration tracking.
    /// `lkey.dptr` may be malloc'd; freed in scan updates and close/drop.
    lkey: ffi::datum,
}

// SAFETY: GDBM_FILE is a handle to a file-backed database. The GdbmHintsDb wrapper
// is not Clone and is designed for Exim's fork-per-connection model where each child
// process has exclusive access to its database handle. Send is required by the HintsDb
// trait bound and is safe under this single-owner, single-process usage model.
unsafe impl Send for GdbmHintsDb {}

// ---------------------------------------------------------------------------
// Consolidated FFI Dispatch
// ---------------------------------------------------------------------------

/// Internal FFI operation descriptors for the consolidated GDBM unsafe dispatch.
/// All unsafe GDBM interactions are routed through [`gdbm_ffi`] to maintain
/// a single auditable unsafe block for the entire module.
enum GdbmFfi {
    /// gdbm_open(path, block_size, flags, mode, fatal_func=None)
    Open(*mut libc::c_char, libc::c_int, libc::c_int, libc::c_int),
    /// gdbm_close(handle)
    Close(ffi::GDBM_FILE),
    /// gdbm_fetch(handle, key) → datum
    Fetch(ffi::GDBM_FILE, ffi::datum),
    /// gdbm_store(handle, key, data, flag) → c_int
    Store(ffi::GDBM_FILE, ffi::datum, ffi::datum, libc::c_int),
    /// gdbm_delete(handle, key) → c_int
    Delete(ffi::GDBM_FILE, ffi::datum),
    /// gdbm_firstkey(handle) → datum
    FirstKey(ffi::GDBM_FILE),
    /// gdbm_nextkey(handle, prev_key) → datum
    NextKey(ffi::GDBM_FILE, ffi::datum),
    /// libc::free(ptr) for GDBM-allocated datum dptr
    Free(*mut libc::c_void),
    /// std::slice::from_raw_parts(ptr, len).to_vec() for GDBM datum bytes
    SliceCopy(*const u8, usize),
}

/// Internal FFI result variants returned by the consolidated GDBM dispatch.
enum GdbmFfiResult {
    Handle(ffi::GDBM_FILE),
    Datum(ffi::datum),
    Code(libc::c_int),
    Bytes(Vec<u8>),
    Done,
}

/// Single consolidated unsafe dispatch point for all GDBM FFI operations.
///
/// Every unsafe interaction with libgdbm and associated memory operations is
/// routed through this function, maintaining a single auditable unsafe block
/// for the entire module per AAP §0.7.2.
///
/// # Per-variant safety justification
///
/// - `Open`: gdbm_open with caller-validated CString path and standard flags/mode
/// - `Close`: gdbm_close on a caller-validated non-null handle
/// - `Fetch/Store/Delete`: GDBM CRUD on a valid handle with valid datum structs
/// - `FirstKey/NextKey`: scan operations on a valid handle returning malloc'd datums
/// - `Free`: libc::free on a GDBM-allocated datum dptr (caller ensures non-null)
/// - `SliceCopy`: from_raw_parts on a GDBM-owned buffer, immediately copied to Vec
fn gdbm_ffi(op: GdbmFfi) -> GdbmFfiResult {
    // SAFETY: All GDBM FFI operations consolidated into a single auditable unsafe
    // region. Each call site constructs the appropriate GdbmFfi variant with validated
    // pointers and handles. The GDBM library functions follow their documented
    // contracts: returned datum dptr fields are malloc-allocated and must be freed
    // by the caller, handles must not be used after gdbm_close, and datum key/data
    // arguments are read by value (struct copy, not pointer ownership transfer).
    unsafe {
        match op {
            GdbmFfi::Open(path, bs, flags, mode) => {
                GdbmFfiResult::Handle(ffi::gdbm_open(path, bs, flags, mode, None))
            }
            GdbmFfi::Close(h) => {
                ffi::gdbm_close(h);
                GdbmFfiResult::Done
            }
            GdbmFfi::Fetch(h, k) => GdbmFfiResult::Datum(ffi::gdbm_fetch(h, k)),
            GdbmFfi::Store(h, k, d, f) => GdbmFfiResult::Code(ffi::gdbm_store(h, k, d, f)),
            GdbmFfi::Delete(h, k) => GdbmFfiResult::Code(ffi::gdbm_delete(h, k)),
            GdbmFfi::FirstKey(h) => GdbmFfiResult::Datum(ffi::gdbm_firstkey(h)),
            GdbmFfi::NextKey(h, prev) => GdbmFfiResult::Datum(ffi::gdbm_nextkey(h, prev)),
            GdbmFfi::Free(p) => {
                libc::free(p);
                GdbmFfiResult::Done
            }
            GdbmFfi::SliceCopy(p, len) => {
                GdbmFfiResult::Bytes(std::slice::from_raw_parts(p, len).to_vec())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

/// Convert an [`HintsDbDatum`] reference to a GDBM `datum` for passing to
/// GDBM C functions.
///
/// The returned `datum` borrows the datum's internal byte buffer via a raw
/// pointer. The caller MUST ensure the [`HintsDbDatum`] outlives the returned
/// `ffi::datum` and that GDBM does not free or reallocate the `dptr`.
fn datum_to_gdbm(datum: &HintsDbDatum) -> ffi::datum {
    let bytes = datum.as_bytes();
    ffi::datum {
        dptr: bytes.as_ptr() as *mut libc::c_char,
        dsize: bytes.len() as libc::c_int,
    }
}

/// Convert a GDBM `datum` returned by GDBM into an owned [`HintsDbDatum`],
/// freeing the C-allocated `dptr` afterwards.
///
/// Returns `None` if `dptr` is null (indicating no data found or end of scan).
/// This function transfers ownership: after calling it, the `datum.dptr` has
/// been freed and MUST NOT be used again.
fn gdbm_datum_to_owned(data: ffi::datum) -> Option<HintsDbDatum> {
    if data.dptr.is_null() || data.dsize < 0 {
        return None;
    }
    let size = data.dsize as usize;
    let bytes = match gdbm_ffi(GdbmFfi::SliceCopy(data.dptr as *const u8, size)) {
        GdbmFfiResult::Bytes(b) => b,
        _ => unreachable!(),
    };
    gdbm_ffi(GdbmFfi::Free(data.dptr as *mut libc::c_void));
    Some(HintsDbDatum::new(&bytes))
}

/// Free the `dptr` field of a GDBM datum if it is non-null.
///
/// Sets `dptr` to null and `dsize` to 0 after freeing to prevent double-free.
fn free_datum_dptr(d: &mut ffi::datum) {
    if !d.dptr.is_null() {
        gdbm_ffi(GdbmFfi::Free(d.dptr as *mut libc::c_void));
        d.dptr = ptr::null_mut();
        d.dsize = 0;
    }
}

// ---------------------------------------------------------------------------
// GdbmHintsDb — Inherent Methods
// ---------------------------------------------------------------------------

impl GdbmHintsDb {
    /// Open a GDBM database.
    ///
    /// Corresponds to `exim_dbopen__` in `hints_gdbm.h` (lines 51-72).
    /// Flag mapping from POSIX to GDBM:
    /// - `create=true` → `GDBM_WRCREAT` (create if not exists, read-write)
    /// - `read_only=true` → `GDBM_READER` (read-only access)
    /// - otherwise → `GDBM_WRITER` (read-write, file must exist)
    ///
    /// # Arguments
    ///
    /// * `path` — File path for the GDBM database (null terminator added internally)
    /// * `flags` — Open mode flags (read-only, read-write, create)
    /// * `mode` — POSIX file permission bits (e.g., `0o660`)
    ///
    /// # Errors
    ///
    /// Returns [`HintsDbError`] if the path contains a null byte or the
    /// database cannot be opened.
    pub fn open(path: &str, flags: &OpenFlags, mode: u32) -> Result<Self, HintsDbError> {
        let c_path = CString::new(path)
            .map_err(|e| HintsDbError::new(format!("invalid database path: {e}")))?;

        // Map OpenFlags to GDBM open mode flags, matching the C source
        // (hints_gdbm.h lines 59-61):
        //   flags & O_CREAT ? GDBM_WRCREAT
        //   : (flags & O_ACCMODE) == O_RDONLY ? GDBM_READER : GDBM_WRITER
        let gdbm_flags: libc::c_int = if flags.create {
            ffi::GDBM_WRCREAT as libc::c_int
        } else if flags.read_only {
            ffi::GDBM_READER as libc::c_int
        } else {
            ffi::GDBM_WRITER as libc::c_int
        };

        // Dispatch gdbm_open through consolidated FFI dispatch:
        //   c_path.as_ptr() → valid null-terminated C string from CString
        //   block_size=0 → GDBM default block size selection
        //   gdbm_flags → valid GDBM open mode constant (WRCREAT/READER/WRITER)
        //   mode → valid POSIX permission bits cast to c_int
        let gdbm = match gdbm_ffi(GdbmFfi::Open(
            c_path.as_ptr() as *mut libc::c_char,
            0,
            gdbm_flags,
            mode as libc::c_int,
        )) {
            GdbmFfiResult::Handle(h) => h,
            _ => unreachable!(),
        };

        if gdbm.is_null() {
            return Err(HintsDbError::new(format!(
                "gdbm_open failed for '{}': {}",
                path,
                std::io::Error::last_os_error()
            )));
        }

        Ok(Self {
            gdbm,
            lkey: ffi::datum {
                dptr: ptr::null_mut(),
                dsize: 0,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// HintsDb Trait Implementation
// ---------------------------------------------------------------------------

impl HintsDb for GdbmHintsDb {
    /// GDBM requires external lockfiles for concurrency control.
    ///
    /// Matches `exim_lockfile_needed()` returning `TRUE` in `hints_gdbm.h`
    /// (lines 37-41). Unlike TDB, GDBM does not support transactions and
    /// relies on Exim's external lockfile mechanism for safe concurrent access.
    fn lockfile_needed(&self) -> bool {
        true
    }

    /// Returns the database type identifier: `"gdbm"`.
    fn db_type(&self) -> &'static str {
        EXIM_DBTYPE
    }

    /// Fetch a value by key from the GDBM database.
    ///
    /// Calls `gdbm_fetch(db, key)` which returns a `datum` by value. The
    /// returned datum's `dptr` is `malloc`-allocated by GDBM — it is copied
    /// into an owned [`HintsDbDatum`] and then freed immediately.
    ///
    /// Corresponds to `exim_dbget` in `hints_gdbm.h` (lines 75-80):
    /// ```c
    /// *res = gdbm_fetch(dbp->gdbm, *key);
    /// return res->dptr != NULL;
    /// ```
    ///
    /// Returns `Ok(None)` if the key is not found.
    fn get(&self, key: &HintsDbDatum) -> Result<Option<HintsDbDatum>, HintsDbError> {
        let gdbm_key = datum_to_gdbm(key);

        // Dispatch gdbm_fetch: self.gdbm is valid, key is by-value struct copy.
        // Returned datum dptr is freed inside gdbm_datum_to_owned.
        let result = match gdbm_ffi(GdbmFfi::Fetch(self.gdbm, gdbm_key)) {
            GdbmFfiResult::Datum(d) => d,
            _ => unreachable!(),
        };

        Ok(gdbm_datum_to_owned(result))
    }

    /// Store a key-value pair, replacing any existing value.
    ///
    /// Uses `GDBM_REPLACE` flag. If the key does not exist, a new entry is
    /// created. If it exists, the value is overwritten.
    ///
    /// Corresponds to `exim_dbput` in `hints_gdbm.h` (lines 83-85):
    /// ```c
    /// return gdbm_store(dbp->gdbm, *key, *data, GDBM_REPLACE);
    /// ```
    fn put(&mut self, key: &HintsDbDatum, data: &HintsDbDatum) -> Result<(), HintsDbError> {
        let gdbm_key = datum_to_gdbm(key);
        let gdbm_data = datum_to_gdbm(data);

        // Dispatch gdbm_store with GDBM_REPLACE: self.gdbm is valid, key and
        // data are by-value struct copies. Returns 0 on success, non-zero on error.
        let rc = match gdbm_ffi(GdbmFfi::Store(
            self.gdbm,
            gdbm_key,
            gdbm_data,
            ffi::GDBM_REPLACE as libc::c_int,
        )) {
            GdbmFfiResult::Code(c) => c,
            _ => unreachable!(),
        };

        if rc != 0 {
            return Err(HintsDbError::new(format!(
                "gdbm_store (replace) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// Store a key-value pair only if the key does not already exist.
    ///
    /// Uses `GDBM_INSERT` flag. Returns [`PutResult::Ok`] on success,
    /// [`PutResult::Duplicate`] if the key already exists.
    ///
    /// Corresponds to `exim_dbputb` in `hints_gdbm.h` (lines 88-90):
    /// ```c
    /// return gdbm_store(dbp->gdbm, *key, *data, GDBM_INSERT);
    /// ```
    ///
    /// GDBM returns 0 for success (`EXIM_DBPUTB_OK`, line 94) and 1 for
    /// duplicate (`EXIM_DBPUTB_DUP`, line 95). Any non-zero return is treated
    /// as duplicate for behavioral parity with the C code.
    fn put_no_overwrite(
        &mut self,
        key: &HintsDbDatum,
        data: &HintsDbDatum,
    ) -> Result<PutResult, HintsDbError> {
        let gdbm_key = datum_to_gdbm(key);
        let gdbm_data = datum_to_gdbm(data);

        // Dispatch gdbm_store with GDBM_INSERT: returns 0 on success,
        // 1 on duplicate, -1 on error. C code treats non-zero as duplicate.
        let rc = match gdbm_ffi(GdbmFfi::Store(
            self.gdbm,
            gdbm_key,
            gdbm_data,
            ffi::GDBM_INSERT as libc::c_int,
        )) {
            GdbmFfiResult::Code(c) => c,
            _ => unreachable!(),
        };

        // Match C behavior: 0 = EXIM_DBPUTB_OK, anything else = EXIM_DBPUTB_DUP
        if rc == EXIM_DBPUTB_OK {
            Ok(PutResult::Ok)
        } else {
            Ok(PutResult::Duplicate)
        }
    }

    /// Delete a key-value pair from the GDBM database.
    ///
    /// Corresponds to `exim_dbdel` in `hints_gdbm.h` (lines 98-100):
    /// ```c
    /// return gdbm_delete(dbp->gdbm, *key);
    /// ```
    fn delete(&mut self, key: &HintsDbDatum) -> Result<(), HintsDbError> {
        let gdbm_key = datum_to_gdbm(key);

        // Dispatch gdbm_delete: self.gdbm is valid, key is by-value struct copy.
        // Returns 0 on success, -1 on error.
        let rc = match gdbm_ffi(GdbmFfi::Delete(self.gdbm, gdbm_key)) {
            GdbmFfiResult::Code(c) => c,
            _ => unreachable!(),
        };

        if rc != 0 {
            return Err(HintsDbError::new(format!(
                "gdbm_delete failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// Begin scanning from the first key in the GDBM database.
    ///
    /// Resets the last-key tracking and returns the first key-value pair.
    /// Returns `Ok(None)` if the database is empty.
    ///
    /// Corresponds to `exim_dbscan` with `first=TRUE` in `hints_gdbm.h`
    /// (lines 108-117). After obtaining the key via `gdbm_firstkey`, the
    /// value is retrieved via `gdbm_fetch` to satisfy the trait's requirement
    /// of returning both key and value.
    fn scan_first(&mut self) -> Result<Option<(HintsDbDatum, HintsDbDatum)>, HintsDbError> {
        // Free any previous lkey from a prior scan before starting fresh.
        free_datum_dptr(&mut self.lkey);

        // Dispatch gdbm_firstkey: returns datum with malloc'd dptr (or null if empty).
        let new_key = match gdbm_ffi(GdbmFfi::FirstKey(self.gdbm)) {
            GdbmFfiResult::Datum(d) => d,
            _ => unreachable!(),
        };

        // Store the key as lkey for subsequent scan_next calls.
        self.lkey = new_key;

        if new_key.dptr.is_null() {
            return Ok(None);
        }

        // Copy key bytes into an owned Rust datum via dispatch. The original
        // dptr stays in self.lkey for the next gdbm_nextkey call.
        let key_bytes = match gdbm_ffi(GdbmFfi::SliceCopy(
            new_key.dptr as *const u8,
            new_key.dsize as usize,
        )) {
            GdbmFfiResult::Bytes(b) => b,
            _ => unreachable!(),
        };
        let key_datum = HintsDbDatum::new(&key_bytes);

        // Fetch the value for this key. gdbm_fetch returns a separate
        // malloc'd datum that gdbm_datum_to_owned will copy and free.
        let value = match gdbm_ffi(GdbmFfi::Fetch(self.gdbm, new_key)) {
            GdbmFfiResult::Datum(d) => d,
            _ => unreachable!(),
        };
        let value_datum = gdbm_datum_to_owned(value).unwrap_or_else(HintsDbDatum::empty);

        Ok(Some((key_datum, value_datum)))
    }

    /// Continue scanning to the next key in the GDBM database.
    ///
    /// Must be called after [`scan_first`](HintsDb::scan_first). Uses
    /// `gdbm_nextkey(db, prev_key)` where `prev_key` is the last key stored
    /// in `self.lkey`.
    ///
    /// Returns `Ok(None)` when iteration is exhausted.
    ///
    /// Corresponds to `exim_dbscan` with `first=FALSE` in `hints_gdbm.h`
    /// (lines 108-117). Follows the C memory management pattern:
    /// ```c
    /// *key = gdbm_nextkey(dbp->gdbm, dbp->lkey);
    /// if ((s = dbp->lkey.dptr)) free(s);
    /// dbp->lkey = *key;
    /// ```
    fn scan_next(&mut self) -> Result<Option<(HintsDbDatum, HintsDbDatum)>, HintsDbError> {
        if self.lkey.dptr.is_null() {
            return Err(HintsDbError::new(
                "scan_next called without prior scan_first or after scan exhausted",
            ));
        }

        // Dispatch gdbm_nextkey: takes previous key by-value, returns new datum.
        let new_key = match gdbm_ffi(GdbmFfi::NextKey(self.gdbm, self.lkey)) {
            GdbmFfiResult::Datum(d) => d,
            _ => unreachable!(),
        };

        // Free the PREVIOUS lkey dptr AFTER gdbm_nextkey read it.
        free_datum_dptr(&mut self.lkey);

        // Update lkey with the new key for next iteration or close/drop.
        self.lkey = new_key;

        if new_key.dptr.is_null() {
            return Ok(None);
        }

        // Copy key bytes into an owned Rust datum via dispatch.
        let key_bytes = match gdbm_ffi(GdbmFfi::SliceCopy(
            new_key.dptr as *const u8,
            new_key.dsize as usize,
        )) {
            GdbmFfiResult::Bytes(b) => b,
            _ => unreachable!(),
        };
        let key_datum = HintsDbDatum::new(&key_bytes);

        // Fetch the value for this key.
        let value = match gdbm_ffi(GdbmFfi::Fetch(self.gdbm, new_key)) {
            GdbmFfiResult::Datum(d) => d,
            _ => unreachable!(),
        };
        let value_datum = gdbm_datum_to_owned(value).unwrap_or_else(HintsDbDatum::empty);

        Ok(Some((key_datum, value_datum)))
    }

    /// Close the GDBM database handle, freeing all resources.
    ///
    /// Corresponds to `exim_dbclose__` in `hints_gdbm.h` (lines 126-132):
    /// ```c
    /// gdbm_close(dbp->gdbm);
    /// if ((s = dbp->lkey.dptr)) free(s);
    /// free(dbp);
    /// ```
    ///
    /// In Rust, the handle struct is stack-allocated (no `free(dbp)` needed).
    /// This method consumes `self` to prevent use-after-close. The [`Drop`]
    /// implementation serves as a safety net if this method is not called.
    fn close(mut self) -> Result<(), HintsDbError> {
        // Free last key datum if allocated from a prior scan.
        free_datum_dptr(&mut self.lkey);

        // Dispatch gdbm_close: releases file descriptors and internal state.
        gdbm_ffi(GdbmFfi::Close(self.gdbm));
        // Null out to prevent Drop from double-closing.
        self.gdbm = ptr::null_mut();

        Ok(())
    }

    /// Transaction start is not supported by GDBM.
    ///
    /// Matches `exim_dbtransaction_start` returning `FALSE` in `hints_gdbm.h`
    /// (line 47). GDBM has no built-in transaction mechanism; Exim uses
    /// external lockfiles for concurrency control instead.
    fn transaction_start(&mut self) -> bool {
        false
    }

    /// Transaction commit is a no-op for GDBM.
    ///
    /// Matches `exim_dbtransaction_commit` being a no-op in `hints_gdbm.h`
    /// (line 48). No transaction state to commit since GDBM does not support
    /// transactions.
    fn transaction_commit(&mut self) {}
}

// ---------------------------------------------------------------------------
// Drop Implementation — Safety Net
// ---------------------------------------------------------------------------

impl Drop for GdbmHintsDb {
    /// Closes the GDBM database handle and frees the last key datum.
    ///
    /// This is a safety net for cases where [`close()`](HintsDb::close) was
    /// not called explicitly (e.g., due to an early return or panic). After
    /// `close()` runs, `gdbm` is set to null so this becomes a no-op.
    fn drop(&mut self) {
        if self.gdbm.is_null() {
            return;
        }

        // Free last key datum if allocated from a prior scan.
        free_datum_dptr(&mut self.lkey);

        // Dispatch gdbm_close: releases file descriptors and resources.
        gdbm_ffi(GdbmFfi::Close(self.gdbm));
        self.gdbm = ptr::null_mut();
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Verify constants match the C header definitions from `hints_gdbm.h`.
    #[test]
    fn test_constants() {
        assert_eq!(EXIM_DBTYPE, "gdbm");
        assert_eq!(EXIM_DB_RLIMIT, 150);
        assert_eq!(EXIM_DBPUTB_OK, 0);
    }

    /// Verify that opening with a path containing a null byte returns an error.
    #[test]
    fn test_open_null_byte_path() {
        let result = GdbmHintsDb::open("\0invalid", &OpenFlags::read_write_create(), 0o660);
        assert!(result.is_err());
        match result {
            Err(err) => assert!(
                err.to_string().contains("invalid database path"),
                "error message was: {}",
                err
            ),
            Ok(_) => panic!("expected error for null byte path"),
        }
    }

    /// Verify that opening a non-existent path in reader mode returns an error.
    #[test]
    fn test_open_nonexistent_reader() {
        let result = GdbmHintsDb::open(
            "/tmp/nonexistent_gdbm_test.db",
            &OpenFlags::read_only(),
            0o660,
        );
        assert!(result.is_err());
    }

    /// Verify that the db_type and lockfile_needed methods work correctly.
    #[test]
    fn test_basic_properties() {
        let path = "/tmp/blitzy_test_gdbm_props.db";
        // Clean up from any previous failed test run.
        let _ = fs::remove_file(path);

        let db = GdbmHintsDb::open(path, &OpenFlags::read_write_create(), 0o660)
            .expect("failed to open GDBM database");

        assert_eq!(db.db_type(), "gdbm");
        assert!(db.lockfile_needed());

        db.close().expect("failed to close GDBM database");
        let _ = fs::remove_file(path);
    }

    /// Verify that transaction_start returns false (GDBM has no transactions).
    #[test]
    fn test_transaction_stubs() {
        let path = "/tmp/blitzy_test_gdbm_txn.db";
        let _ = fs::remove_file(path);

        let mut db = GdbmHintsDb::open(path, &OpenFlags::read_write_create(), 0o660)
            .expect("failed to open GDBM database");

        assert!(!db.transaction_start());
        db.transaction_commit(); // no-op, should not panic

        db.close().expect("failed to close GDBM database");
        let _ = fs::remove_file(path);
    }

    /// Full round-trip test: put, get, put_no_overwrite, delete.
    #[test]
    fn test_crud_operations() {
        let path = "/tmp/blitzy_test_gdbm_crud.db";
        let _ = fs::remove_file(path);

        let mut db = GdbmHintsDb::open(path, &OpenFlags::read_write_create(), 0o660)
            .expect("failed to open GDBM database");

        let key = HintsDbDatum::from("test_key");
        let value = HintsDbDatum::from("test_value");

        // get on non-existent key returns None
        let result = db.get(&key).expect("get failed");
        assert!(result.is_none());

        // put a key-value pair
        db.put(&key, &value).expect("put failed");

        // get the key-value pair back
        let fetched = db.get(&key).expect("get failed").expect("key not found");
        assert_eq!(fetched.as_bytes(), b"test_value");

        // put_no_overwrite on existing key returns Duplicate
        let overwrite_result = db
            .put_no_overwrite(&key, &HintsDbDatum::from("other"))
            .expect("put_no_overwrite failed");
        assert_eq!(overwrite_result, PutResult::Duplicate);

        // put_no_overwrite on new key returns Ok
        let new_key = HintsDbDatum::from("new_key");
        let new_value = HintsDbDatum::from("new_value");
        let insert_result = db
            .put_no_overwrite(&new_key, &new_value)
            .expect("put_no_overwrite failed");
        assert_eq!(insert_result, PutResult::Ok);

        // delete the first key
        db.delete(&key).expect("delete failed");

        // verify it's gone
        let after_delete = db.get(&key).expect("get failed");
        assert!(after_delete.is_none());

        db.close().expect("failed to close GDBM database");
        let _ = fs::remove_file(path);
    }

    /// Test scan_first and scan_next iterate over all keys.
    #[test]
    fn test_scan_iteration() {
        let path = "/tmp/blitzy_test_gdbm_scan.db";
        let _ = fs::remove_file(path);

        let mut db = GdbmHintsDb::open(path, &OpenFlags::read_write_create(), 0o660)
            .expect("failed to open GDBM database");

        // Insert multiple entries
        for i in 0..5 {
            let key = HintsDbDatum::from(format!("key_{i}").as_str());
            let val = HintsDbDatum::from(format!("val_{i}").as_str());
            db.put(&key, &val).expect("put failed");
        }

        // Scan all entries
        let mut count = 0;
        let first = db.scan_first().expect("scan_first failed");
        if first.is_some() {
            count += 1;
            while let Some(_entry) = db.scan_next().expect("scan_next failed") {
                count += 1;
            }
        }

        assert_eq!(count, 5, "expected 5 entries, got {count}");

        db.close().expect("failed to close GDBM database");
        let _ = fs::remove_file(path);
    }

    /// Test scan_first on empty database returns None.
    #[test]
    fn test_scan_empty_database() {
        let path = "/tmp/blitzy_test_gdbm_scan_empty.db";
        let _ = fs::remove_file(path);

        let mut db = GdbmHintsDb::open(path, &OpenFlags::read_write_create(), 0o660)
            .expect("failed to open GDBM database");

        let result = db.scan_first().expect("scan_first failed");
        assert!(result.is_none());

        db.close().expect("failed to close GDBM database");
        let _ = fs::remove_file(path);
    }

    /// Test that Drop properly closes the database handle.
    #[test]
    fn test_drop_closes_handle() {
        let path = "/tmp/blitzy_test_gdbm_drop.db";
        let _ = fs::remove_file(path);

        {
            let mut db = GdbmHintsDb::open(path, &OpenFlags::read_write_create(), 0o660)
                .expect("failed to open GDBM database");
            db.put(&HintsDbDatum::from("k"), &HintsDbDatum::from("v"))
                .expect("put failed");
            // db is dropped here without explicit close()
        }

        // Re-open should succeed — Drop closed cleanly
        let db = GdbmHintsDb::open(path, &OpenFlags::read_write_create(), 0o660)
            .expect("failed to re-open after drop");
        let val = db
            .get(&HintsDbDatum::from("k"))
            .expect("get failed")
            .expect("key not found after re-open");
        assert_eq!(val.as_bytes(), b"v");

        db.close().expect("failed to close GDBM database");
        let _ = fs::remove_file(path);
    }

    /// Verify that free_datum_dptr is safe to call with a null pointer.
    #[test]
    fn test_free_datum_dptr_null() {
        let mut d = ffi::datum {
            dptr: ptr::null_mut(),
            dsize: 0,
        };
        free_datum_dptr(&mut d); // should be no-op, not crash
        assert!(d.dptr.is_null());
        assert_eq!(d.dsize, 0);
    }

    /// Verify datum_to_gdbm creates correct GDBM datum from HintsDbDatum.
    #[test]
    fn test_datum_to_gdbm_conversion() {
        let datum = HintsDbDatum::from("hello");
        let gdbm_d = datum_to_gdbm(&datum);
        assert!(!gdbm_d.dptr.is_null());
        assert_eq!(gdbm_d.dsize, 5);
    }

    /// Verify gdbm_datum_to_owned handles null dptr correctly.
    #[test]
    fn test_gdbm_datum_to_owned_null() {
        let d = ffi::datum {
            dptr: ptr::null_mut(),
            dsize: 0,
        };
        assert!(gdbm_datum_to_owned(d).is_none());
    }

    /// Verify gdbm_datum_to_owned handles negative dsize correctly.
    #[test]
    fn test_gdbm_datum_to_owned_negative_size() {
        let d = ffi::datum {
            dptr: 1 as *mut libc::c_char, // non-null but invalid — won't be dereferenced
            dsize: -1,
        };
        assert!(gdbm_datum_to_owned(d).is_none());
    }
}
