//! Berkeley DB (BDB) hints database backend.
//!
//! Wraps the BDB C API (`<db.h>`) for Exim's persistent hints key-value storage.
//! Supports BDB versions 3.x–5.x (version 6+ and <3 are rejected at build time
//! by the build script in `build.rs`).
//!
//! # BDB Version Branching
//!
//! The build script emits Cargo cfg flags based on the detected BDB version:
//!
//! - **`bdb_41_plus`** — BDB 4.1+: uses `DB_ENV` as the primary handle with `DB*`
//!   stored in `DB_ENV.app_private`. This is the modern API path.
//! - **`bdb_3_plus`** (without `bdb_41_plus`) — BDB 3.x/4.0: uses `DB*` directly
//!   as the primary handle without `DB_ENV`.
//! - **`bdb_43_plus`** — BDB 4.3+: error callback has 3-argument signature
//!   `(DB_ENV*, char*, char*)`. Pre-4.3 uses 2-argument `(char*, char*)`.
//!
//! # Key Characteristics (from `hints_bdb.h`)
//!
//! - Lockfiles always required (`lockfile_needed() → true`)
//! - No transaction support (stubbed as no-op)
//! - No multi-open support (stubbed as returning `None`)
//! - Error callback logging via `tracing::error!` (replaces C `log_write`)
//! - `EXIM_DB_RLIMIT = 150` — maximum file descriptor budget
//! - Uses `DB_HASH` on create, `DB_UNKNOWN` on open existing
//! - BDB 4.1+: `DB_PRIVATE | DB_INIT_MPOOL | DB_CREATE` flags for `DB_ENV` creation
//! - All `DBT` datum structures zeroed via `std::mem::zeroed()` before use
//! - No datum free needed after reading (BDB manages internal buffers)

use std::ffi::{CStr, CString};
use std::ptr;

use super::{HintsDb, HintsDbDatum, HintsDbError, OpenFlags, PutResult};

// Justification for #[allow(...)]: bindgen-generated FFI bindings preserve the original
// C naming conventions from <db.h> for types (DB, DB_ENV, DBC, DBT), functions
// (db_create, db_env_create), and constants (DB_CREATE, DB_HASH, DB_RDONLY, DB_KEYEXIST,
// DB_FORCESYNC, DB_PRIVATE, DB_INIT_MPOOL, DB_UNKNOWN, DB_NOOVERWRITE, DB_FIRST, DB_NEXT,
// DB_NOTFOUND). Renaming these would make cross-referencing with C documentation and the
// Berkeley DB library source impossible. dead_code is allowed because bindgen emits all
// matched symbols regardless of which ones this module actually calls.
// clippy::upper_case_acronyms and clippy::type_complexity are suppressed because bindgen
// generates type aliases (FILE, DBT, DBC, DBTYPE, ENV) and complex function pointer types
// that mirror the C API verbatim.
#[allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    dead_code,
    clippy::upper_case_acronyms,
    clippy::type_complexity
)]
mod ffi {
    include!(concat!(env!("OUT_DIR"), "/bdb_bindings.rs"));
}

/// Database type identifier for BDB 4.1+, matching `EXIM_DBTYPE` in `hints_bdb.h` line 44.
#[cfg(bdb_41_plus)]
pub const EXIM_DBTYPE: &str = "db (v4.1+)";

/// Database type identifier for BDB 3.x/4.0, matching `EXIM_DBTYPE` in `hints_bdb.h` line 241.
#[cfg(not(bdb_41_plus))]
pub const EXIM_DBTYPE: &str = "db (v3/4)";

/// Maximum file descriptor budget for BDB hints databases.
/// Matches `EXIM_DB_RLIMIT` (value 150) in `hints_bdb.h` line 369.
pub const EXIM_DB_RLIMIT: usize = 150;

/// Return value indicating a successful non-overwrite put.
/// Matches `EXIM_DBPUTB_OK = 0` in `hints_bdb.h` line 158/292.
const DBPUTB_OK: libc::c_int = 0;

// ---------------------------------------------------------------------------
// BDB Error Callback
// ---------------------------------------------------------------------------

/// BDB error callback compatible with the `DB_ENV->set_errcall` API (BDB 4.3+).
///
/// Registered during `open()` via `dbp->set_errcall(dbp, bdb_error_callback)`.
/// Invoked by BDB on database errors. Logs messages using `tracing::error!`,
/// replacing the C `log_write(0, LOG_MAIN, "Berkeley DB error: %s", msg)` pattern
/// from `hints_bdb.h` line 75.
///
/// # Safety
///
/// This is an `extern "C"` callback invoked by the BDB library. The `msg` parameter
/// is a valid null-terminated C string per the BDB callback contract. The `_env` and
/// `_pfx` parameters are not used but are part of the required callback signature.
#[cfg(bdb_43_plus)]
extern "C" fn bdb_error_callback(
    _env: *const ffi::DB_ENV,
    _pfx: *const libc::c_char,
    msg: *const libc::c_char,
) {
    if msg.is_null() {
        tracing::error!("Berkeley DB error: (null message)");
        return;
    }
    // SAFETY: msg is a valid null-terminated C string from the BDB error callback.
    // We convert it to a Rust string slice for logging. The string is only borrowed
    // for the duration of the error! macro invocation.
    let msg_str = unsafe { CStr::from_ptr(msg) };
    let msg_lossy = msg_str.to_string_lossy();
    tracing::error!("Berkeley DB error: {}", msg_lossy);
}

/// BDB error callback for pre-4.3 (2-argument signature).
///
/// Pre-4.3 BDB uses `(const char *pfx, char *msg)` instead of the 3-argument form.
#[cfg(not(bdb_43_plus))]
extern "C" fn bdb_error_callback(_pfx: *const libc::c_char, msg: *mut libc::c_char) {
    if msg.is_null() {
        tracing::error!("Berkeley DB error: (null message)");
        return;
    }
    // SAFETY: msg is a valid null-terminated C string from the BDB error callback.
    let msg_str = unsafe { CStr::from_ptr(msg) };
    let msg_lossy = msg_str.to_string_lossy();
    tracing::error!("Berkeley DB error: {}", msg_lossy);
}

// ---------------------------------------------------------------------------
// BDB Cursor
// ---------------------------------------------------------------------------

/// BDB cursor for sequential key scanning via `DBC*`.
///
/// Wraps a raw `DBC*` cursor pointer obtained from `DB->cursor()`. The cursor
/// must be closed via `DBC->c_close()` before the database is closed.
struct BdbCursor {
    /// Raw cursor pointer. Set to null after close.
    cursor: *mut ffi::DBC,
}

impl BdbCursor {
    /// Close the cursor, releasing BDB internal resources.
    ///
    /// Sets the internal pointer to null to prevent double-close.
    fn close(&mut self) {
        if self.cursor.is_null() {
            return;
        }
        // SAFETY: self.cursor is a valid DBC pointer from DB->cursor().
        // c_close releases internal BDB cursor resources. After this call
        // the DBC is freed — we null the pointer to prevent double-close.
        unsafe {
            let c_close_fn = (*self.cursor)
                .c_close
                .expect("DBC->c_close function pointer is null");
            c_close_fn(self.cursor);
        }
        self.cursor = ptr::null_mut();
    }
}

impl Drop for BdbCursor {
    fn drop(&mut self) {
        self.close();
    }
}

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

/// Convert [`OpenFlags`] to POSIX `open()` flags used by BDB to determine
/// database access mode and creation behavior.
fn open_flags_to_posix(flags: &OpenFlags) -> libc::c_int {
    if flags.read_only {
        libc::O_RDONLY
    } else if flags.create {
        libc::O_RDWR | libc::O_CREAT
    } else {
        libc::O_RDWR
    }
}

/// Create a zeroed `DBT` structure suitable for BDB API calls.
///
/// BDB requires `DBT` structures to be zeroed before use (`memset(d, 0, sizeof(*d))`),
/// matching `exim_datum_init` in `hints_bdb.h` lines 222-224 / 347-349.
fn zeroed_dbt() -> ffi::DBT {
    // SAFETY: DBT is a plain-old-data C struct consisting of pointers, integers,
    // and flags. Zeroing all fields produces a valid initial state where data=NULL,
    // size=0, and all flag bits are clear, which is the documented BDB requirement
    // for DBT initialization before use.
    unsafe { std::mem::zeroed() }
}

/// Populate a `DBT` from an [`HintsDbDatum`] reference for passing to BDB functions.
///
/// The returned `DBT` borrows the datum's internal byte buffer via a raw pointer.
/// The caller MUST ensure the datum outlives the `DBT`.
fn datum_to_dbt(datum: &HintsDbDatum) -> ffi::DBT {
    let bytes = datum.as_bytes();
    let mut dbt = zeroed_dbt();
    dbt.data = bytes.as_ptr() as *mut libc::c_void;
    dbt.size = bytes.len() as u32;
    dbt
}

/// Convert a `DBT` returned by BDB into an owned [`HintsDbDatum`].
///
/// Copies the bytes from the BDB-managed buffer into an owned `Vec<u8>`.
/// Returns `None` if the data pointer is null (key not found).
///
/// BDB manages the memory for returned `DBT` data internally — no explicit
/// free is needed (documented in `exim_datum_free` at lines 226-228 / 351-353).
fn dbt_to_datum(dbt: &ffi::DBT) -> Option<HintsDbDatum> {
    if dbt.data.is_null() || dbt.size == 0 {
        return None;
    }
    // SAFETY: dbt.data is non-null and points to dbt.size contiguous bytes
    // managed by BDB's internal buffer. We create a temporary slice view and
    // immediately copy the bytes into an owned Vec<u8> via HintsDbDatum::new.
    // The original BDB buffer remains valid until the next BDB operation on
    // the same handle — our copy ensures we don't hold a dangling reference.
    let bytes = unsafe { std::slice::from_raw_parts(dbt.data as *const u8, dbt.size as usize) };
    Some(HintsDbDatum::new(bytes))
}

// ---------------------------------------------------------------------------
// BdbHintsDb — Main Handle Struct
// ---------------------------------------------------------------------------

/// Safe wrapper around a Berkeley DB hints database handle.
///
/// For BDB 4.1+ (`bdb_41_plus`): Encapsulates `DB_ENV*` (environment handle) with
/// `DB*` stored in `DB_ENV.app_private`, following `hints_bdb.h` lines 35-36 and
/// the `ENV_TO_DB` macro at line 99.
///
/// For BDB 3.x/4.0 (no `bdb_41_plus`): Encapsulates `DB*` directly, with `env`
/// set to null, following `hints_bdb.h` lines 232-233.
///
/// # Memory Ownership
///
/// Both `env` and `db` pointers are owned by this struct. They are freed in
/// `close()` or in the `Drop` implementation (safety net).
pub struct BdbHintsDb {
    /// DB_ENV pointer (BDB 4.1+). Null for pre-4.1 builds.
    env: *mut ffi::DB_ENV,
    /// DB pointer — the actual database handle.
    db: *mut ffi::DB,
    /// Active cursor for scan operations, if any.
    cursor: Option<BdbCursor>,
}

// SAFETY: BdbHintsDb wraps raw C pointers to BDB database handles. The struct is not
// Clone and is designed for Exim's fork-per-connection model where each child process
// has exclusive access to its database handle. Send is required by the HintsDb trait
// bound and is safe under this single-owner, single-process usage model.
unsafe impl Send for BdbHintsDb {}

// ---------------------------------------------------------------------------
// BdbHintsDb — Inherent Methods
// ---------------------------------------------------------------------------

impl BdbHintsDb {
    /// Open a BDB database.
    ///
    /// For BDB 4.1+ (`bdb_41_plus`): Creates `DB_ENV` + `DB`, sets the error
    /// callback, opens the environment with `DB_CREATE|DB_INIT_MPOOL|DB_PRIVATE`,
    /// then opens the database within the environment.
    ///
    /// For BDB 3.x/4.0: Creates `DB*` directly, sets error callback, opens with
    /// appropriate flags.
    ///
    /// Corresponds to `exim_dbopen__` in `hints_bdb.h` (lines 101-130 for 4.1+,
    /// lines 259-273 for pre-4.1).
    ///
    /// # Arguments
    ///
    /// * `name` — Database file path (null terminator added internally)
    /// * `dirname` — Directory path for the DB_ENV working directory (BDB 4.1+ only)
    /// * `flags` — Open mode flags (read-only, read-write, create)
    /// * `mode` — POSIX file permission bits (e.g., `0o660`)
    ///
    /// # Errors
    ///
    /// Returns [`HintsDbError`] if the database cannot be opened.
    #[cfg(bdb_41_plus)]
    pub fn open(
        name: &str,
        dirname: &str,
        flags: &OpenFlags,
        mode: u32,
    ) -> Result<Self, HintsDbError> {
        let c_name = CString::new(name)
            .map_err(|e| HintsDbError::new(format!("invalid database path: {e}")))?;
        let c_dirname = CString::new(dirname)
            .map_err(|e| HintsDbError::new(format!("invalid directory path: {e}")))?;
        let posix_flags = open_flags_to_posix(flags);

        // Step 1: Create DB_ENV
        let mut env_ptr: *mut ffi::DB_ENV = ptr::null_mut();
        // SAFETY: db_env_create initializes a new DB_ENV handle. The function takes
        // a pointer to a DB_ENV pointer and a flags argument (0 = default). On success
        // it sets *env_ptr to a valid DB_ENV handle. Returns 0 on success, non-zero error.
        let rc = unsafe { ffi::db_env_create(&mut env_ptr, 0) };
        if rc != 0 || env_ptr.is_null() {
            return Err(HintsDbError::new(format!(
                "db_env_create failed for '{}': rc={}",
                name, rc
            )));
        }

        // Step 2: Set error callback on the DB_ENV
        // SAFETY: env_ptr is a valid DB_ENV handle from db_env_create. set_errcall
        // is a function pointer in the DB_ENV struct that registers a callback for
        // BDB error reporting. The callback function signature matches the BDB 4.3+
        // (or pre-4.3) error callback requirement.
        unsafe {
            let set_errcall_fn = (*env_ptr)
                .set_errcall
                .expect("DB_ENV->set_errcall function pointer is null");
            set_errcall_fn(env_ptr, Some(bdb_error_callback));
        }

        // Step 3: Open DB_ENV with DB_CREATE|DB_INIT_MPOOL|DB_PRIVATE
        // These flags match hints_bdb.h line 109:
        //   dbp->open(dbp, CS dirname, DB_CREATE|DB_INIT_MPOOL|DB_PRIVATE, 0)
        // SAFETY: env_ptr is valid. DB_ENV->open takes the env handle, a directory
        // path (C string), flags, and mode. DB_PRIVATE prevents shared region files.
        // DB_INIT_MPOOL enables the memory pool subsystem. Returns 0 on success.
        let env_open_rc = unsafe {
            let open_fn = (*env_ptr)
                .open
                .expect("DB_ENV->open function pointer is null");
            open_fn(
                env_ptr,
                c_dirname.as_ptr(),
                ffi::DB_CREATE | ffi::DB_INIT_MPOOL | ffi::DB_PRIVATE,
                0,
            )
        };
        if env_open_rc != 0 {
            // Clean up the env handle on failure
            // SAFETY: env_ptr is valid but the open failed. close releases resources.
            unsafe {
                let close_fn = (*env_ptr)
                    .close
                    .expect("DB_ENV->close function pointer is null");
                close_fn(env_ptr, 0);
            }
            return Err(HintsDbError::new(format!(
                "DB_ENV->open failed for '{}': rc={}",
                dirname, env_open_rc
            )));
        }

        // Step 4: Create DB handle within the environment
        let mut db_ptr: *mut ffi::DB = ptr::null_mut();
        // SAFETY: db_create initializes a new DB handle associated with the given
        // DB_ENV. Takes a pointer to a DB pointer, the environment, and flags (0).
        // Returns 0 on success.
        let db_create_rc = unsafe { ffi::db_create(&mut db_ptr, env_ptr, 0) };
        if db_create_rc != 0 || db_ptr.is_null() {
            // Clean up env on failure
            // SAFETY: env_ptr is valid and open. close releases all resources.
            unsafe {
                let close_fn = (*env_ptr)
                    .close
                    .expect("DB_ENV->close function pointer is null");
                close_fn(env_ptr, 0);
            }
            return Err(HintsDbError::new(format!(
                "db_create failed for '{}': rc={}",
                name, db_create_rc
            )));
        }

        // Step 5: Store DB* in env->app_private (ENV_TO_DB pattern, line 99/114)
        // SAFETY: env_ptr and db_ptr are both valid handles. app_private is a void*
        // field in DB_ENV intended for application-specific data storage. We store the
        // DB* pointer here to match the C pattern ENV_TO_DB(env) = (DB*)(env->app_private).
        unsafe {
            (*env_ptr).app_private = db_ptr as *mut libc::c_void;
        }

        // Step 6: Open the database
        // Map POSIX flags to BDB flags (lines 116-118):
        //   flags & O_CREAT ? DB_HASH : DB_UNKNOWN   (database type)
        //   flags & O_CREAT ? DB_CREATE : (flags & O_ACCMODE)==O_RDONLY ? DB_RDONLY : 0
        let db_type = if posix_flags & libc::O_CREAT != 0 {
            ffi::DBTYPE_DB_HASH
        } else {
            ffi::DBTYPE_DB_UNKNOWN
        };
        let db_flags: u32 = if posix_flags & libc::O_CREAT != 0 {
            ffi::DB_CREATE
        } else if (posix_flags & libc::O_ACCMODE) == libc::O_RDONLY {
            ffi::DB_RDONLY
        } else {
            0
        };

        // SAFETY: db_ptr is a valid DB handle from db_create. DB->open takes:
        //   db handle, txn (NULL), file name (C string), sub-database name (NULL),
        //   database type (DB_HASH or DB_UNKNOWN), flags, mode.
        // Returns 0 on success.
        let db_open_rc = unsafe {
            let open_fn = (*db_ptr).open.expect("DB->open function pointer is null");
            open_fn(
                db_ptr,
                ptr::null_mut(), // txnid = NULL
                c_name.as_ptr(),
                ptr::null(), // database (sub-db name) = NULL
                db_type,
                db_flags,
                mode as libc::c_int,
            )
        };

        if db_open_rc != 0 {
            // Clean up DB + ENV on failure (lines 126-129)
            // SAFETY: db_ptr is a valid DB handle and env_ptr is a valid DB_ENV handle.
            // DB->close releases the DB handle, DB_ENV->close releases environment resources.
            unsafe {
                let db_close_fn = (*db_ptr).close.expect("DB->close function pointer is null");
                db_close_fn(db_ptr, 0);
                let env_close_fn = (*env_ptr)
                    .close
                    .expect("DB_ENV->close function pointer is null");
                env_close_fn(env_ptr, 0);
            }
            return Err(HintsDbError::new(format!(
                "DB->open failed for '{}': rc={}, flags=0x{:x}, mode={:04o}",
                name, db_open_rc, posix_flags, mode
            )));
        }

        Ok(Self {
            env: env_ptr,
            db: db_ptr,
            cursor: None,
        })
    }

    /// Open a BDB database (pre-4.1 path — DB* directly, no DB_ENV).
    ///
    /// Corresponds to `exim_dbopen__` in `hints_bdb.h` lines 259-273.
    #[cfg(not(bdb_41_plus))]
    pub fn open(
        name: &str,
        _dirname: &str,
        flags: &OpenFlags,
        mode: u32,
    ) -> Result<Self, HintsDbError> {
        let c_name = CString::new(name)
            .map_err(|e| HintsDbError::new(format!("invalid database path: {e}")))?;
        let posix_flags = open_flags_to_posix(flags);

        // Create DB handle without an environment
        let mut db_ptr: *mut ffi::DB = ptr::null_mut();
        // SAFETY: db_create with NULL env creates a standalone DB handle.
        // Returns 0 on success.
        let rc = unsafe { ffi::db_create(&mut db_ptr, ptr::null_mut(), 0) };
        if rc != 0 || db_ptr.is_null() {
            return Err(HintsDbError::new(format!(
                "db_create failed for '{}': rc={}",
                name, rc
            )));
        }

        // Set error callback on the DB handle directly
        // SAFETY: db_ptr is a valid DB handle. set_errcall registers the error
        // callback for this database handle.
        unsafe {
            let set_errcall_fn = (*db_ptr)
                .set_errcall
                .expect("DB->set_errcall function pointer is null");
            set_errcall_fn(db_ptr as *mut ffi::DB_ENV, Some(bdb_error_callback));
        }

        // Map POSIX flags to BDB flags (lines 267-270)
        let db_type = if posix_flags & libc::O_CREAT != 0 {
            ffi::DBTYPE_DB_HASH
        } else {
            ffi::DBTYPE_DB_UNKNOWN
        };
        let db_flags: u32 = if posix_flags & libc::O_CREAT != 0 {
            ffi::DB_CREATE
        } else if (posix_flags & libc::O_ACCMODE) == libc::O_RDONLY {
            ffi::DB_RDONLY
        } else {
            0
        };

        // SAFETY: db_ptr is valid. DB->open called with NULL txn, file path,
        // NULL sub-db, type, flags, mode. Returns 0 on success.
        let open_rc = unsafe {
            let open_fn = (*db_ptr).open.expect("DB->open function pointer is null");
            open_fn(
                db_ptr,
                c_name.as_ptr(),
                ptr::null(),
                db_type,
                db_flags,
                mode as libc::c_int,
            )
        };

        if open_rc != 0 {
            // SAFETY: db_ptr is valid. close releases DB resources.
            unsafe {
                let close_fn = (*db_ptr).close.expect("DB->close function pointer is null");
                close_fn(db_ptr, 0);
            }
            return Err(HintsDbError::new(format!(
                "DB->open failed for '{}': rc={}",
                name, open_rc
            )));
        }

        Ok(Self {
            env: ptr::null_mut(),
            db: db_ptr,
            cursor: None,
        })
    }

    /// Multi-open stub — BDB does not support multi-open.
    ///
    /// Returns `None` to match the C stub `exim_dbopen_multi__` which returns `NULL`
    /// (hints_bdb.h lines 88-90 / 251-253).
    pub fn open_multi(_name: &str, _dirname: &str, _flags: &OpenFlags, _mode: u32) -> Option<Self> {
        None
    }

    /// Internal helper: retrieve the `DB*` handle for data operations.
    ///
    /// For BDB 4.1+, extracts DB* from `env->app_private` (the ENV_TO_DB macro).
    /// For pre-4.1, returns `self.db` directly.
    fn db_handle(&self) -> *mut ffi::DB {
        #[cfg(bdb_41_plus)]
        {
            // For 4.1+, the DB* is in env->app_private (ENV_TO_DB macro, line 99)
            // but we also store it in self.db directly during open() for convenience.
            self.db
        }
        #[cfg(not(bdb_41_plus))]
        {
            self.db
        }
    }

    /// Internal helper for scan operations using the BDB cursor.
    ///
    /// Creates a cursor on first call, then uses `DBC->c_get` with either
    /// `DB_FIRST` or `DB_NEXT` to iterate through all key-value pairs.
    fn scan_impl(
        &mut self,
        first: bool,
    ) -> Result<Option<(HintsDbDatum, HintsDbDatum)>, HintsDbError> {
        let db = self.db_handle();

        // Create cursor if we don't have one yet
        if self.cursor.is_none() {
            let mut cursor_ptr: *mut ffi::DBC = ptr::null_mut();
            // SAFETY: db is a valid DB handle. DB->cursor creates a new DBC cursor
            // associated with the database. Parameters: DB*, txn (NULL), cursor out ptr,
            // flags (0). Returns 0 on success.
            let rc = unsafe {
                let cursor_fn = (*db).cursor.expect("DB->cursor function pointer is null");
                cursor_fn(db, ptr::null_mut(), &mut cursor_ptr, 0)
            };
            if rc != 0 || cursor_ptr.is_null() {
                return Err(HintsDbError::new(format!("DB->cursor failed: rc={}", rc)));
            }
            self.cursor = Some(BdbCursor { cursor: cursor_ptr });
        }

        let bdb_cursor = self.cursor.as_ref().expect("cursor must exist");
        let cursor_ptr = bdb_cursor.cursor;

        // Prepare zeroed DBT structures for key and data output
        let mut key_dbt = zeroed_dbt();
        let mut data_dbt = zeroed_dbt();

        // Determine scan direction flag. DB_FIRST (7) starts from the
        // beginning; DB_NEXT (16) advances to the next entry.
        let scan_flag: u32 = if first { ffi::DB_FIRST } else { ffi::DB_NEXT };

        // SAFETY: cursor_ptr is a valid DBC cursor from DB->cursor. c_get retrieves
        // the next key-value pair. The key_dbt and data_dbt are zeroed and BDB fills
        // them with pointers to its internal buffers. Returns 0 on success,
        // DB_NOTFOUND when iteration is exhausted.
        let rc = unsafe {
            let c_get_fn = (*cursor_ptr)
                .c_get
                .expect("DBC->c_get function pointer is null");
            c_get_fn(cursor_ptr, &mut key_dbt, &mut data_dbt, scan_flag)
        };

        if rc != 0 {
            // DB_NOTFOUND means end of iteration — not an error
            return Ok(None);
        }

        // Convert BDB internal buffers to owned Rust datums.
        // BDB manages the buffer memory — no explicit free needed.
        let key_datum = dbt_to_datum(&key_dbt).unwrap_or_else(HintsDbDatum::empty);
        let data_datum = dbt_to_datum(&data_dbt).unwrap_or_else(HintsDbDatum::empty);

        Ok(Some((key_datum, data_datum)))
    }

    /// Internal helper: close DB and ENV handles.
    ///
    /// For BDB 4.1+: closes DB first, then ENV with DB_FORCESYNC.
    /// For pre-4.1: closes DB only.
    fn close_handles(&mut self) -> Result<(), HintsDbError> {
        // Close cursor first
        self.cursor = None;

        let mut errors: Vec<String> = Vec::new();

        // Close DB handle
        if !self.db.is_null() {
            // SAFETY: self.db is a valid DB handle from db_create/open.
            // DB->close releases all internal DB resources. The second parameter
            // is flags (0 = default). After this call the DB handle is freed.
            let rc = unsafe {
                let close_fn = (*self.db)
                    .close
                    .expect("DB->close function pointer is null");
                close_fn(self.db, 0)
            };
            self.db = ptr::null_mut();
            if rc != 0 {
                errors.push(format!("DB->close failed: rc={}", rc));
            }
        }

        // Close DB_ENV handle (BDB 4.1+ only)
        #[cfg(bdb_41_plus)]
        if !self.env.is_null() {
            // SAFETY: self.env is a valid DB_ENV handle from db_env_create/open.
            // DB_ENV->close with DB_FORCESYNC forces a sync of the memory pool
            // to disk before closing. After this call the DB_ENV handle is freed.
            // This matches hints_bdb.h line 200: dbp->close(dbp, DB_FORCESYNC).
            let rc = unsafe {
                let close_fn = (*self.env)
                    .close
                    .expect("DB_ENV->close function pointer is null");
                close_fn(self.env, ffi::DB_FORCESYNC)
            };
            self.env = ptr::null_mut();
            if rc != 0 {
                errors.push(format!("DB_ENV->close failed: rc={}", rc));
            }
        }

        #[cfg(not(bdb_41_plus))]
        {
            self.env = ptr::null_mut();
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(HintsDbError::new(errors.join("; ")))
        }
    }
}

// ---------------------------------------------------------------------------
// HintsDb Trait Implementation
// ---------------------------------------------------------------------------

impl HintsDb for BdbHintsDb {
    /// BDB always requires external lockfiles for concurrency control.
    ///
    /// Returns `true`, matching `exim_lockfile_needed() → TRUE` in
    /// `hints_bdb.h` lines 82-86 / 245-249.
    fn lockfile_needed(&self) -> bool {
        true
    }

    /// Returns the database type identifier string.
    ///
    /// Returns `"db (v4.1+)"` for BDB 4.1+ or `"db (v3/4)"` for pre-4.1,
    /// matching `EXIM_DBTYPE` in `hints_bdb.h` lines 44 / 241.
    fn db_type(&self) -> &'static str {
        EXIM_DBTYPE
    }

    /// Fetch a value by key from the BDB database.
    ///
    /// Calls `DB->get(db, NULL, key, res, 0)` per `exim_dbget` in
    /// `hints_bdb.h` lines 133-138 / 275-278.
    ///
    /// Returns `Ok(None)` if the key is not found (`DB_NOTFOUND`).
    fn get(&self, key: &HintsDbDatum) -> Result<Option<HintsDbDatum>, HintsDbError> {
        let db = self.db_handle();
        let key_dbt = datum_to_dbt(key);
        let mut result_dbt = zeroed_dbt();

        // SAFETY: db is a valid DB handle. DB->get takes: db, txn (NULL), key DBT
        // (read-only), result DBT (filled by BDB), flags (0). Returns 0 on success,
        // DB_NOTFOUND if key doesn't exist.
        let rc = unsafe {
            let get_fn = (*db).get.expect("DB->get function pointer is null");
            get_fn(
                db,
                ptr::null_mut(),
                &key_dbt as *const ffi::DBT as *mut ffi::DBT,
                &mut result_dbt,
                0,
            )
        };

        if rc != 0 {
            // DB_NOTFOUND is not an error — just means key doesn't exist
            return Ok(None);
        }

        Ok(dbt_to_datum(&result_dbt))
    }

    /// Store a key-value pair, replacing any existing value.
    ///
    /// Calls `DB->put(db, NULL, key, data, 0)` per `exim_dbput` in
    /// `hints_bdb.h` lines 141-146 / 280-283. Flag 0 means replace mode.
    fn put(&mut self, key: &HintsDbDatum, data: &HintsDbDatum) -> Result<(), HintsDbError> {
        let db = self.db_handle();
        let key_dbt = datum_to_dbt(key);
        let data_dbt = datum_to_dbt(data);

        // SAFETY: db is a valid DB handle. DB->put takes: db, txn (NULL), key DBT,
        // data DBT, flags (0 = replace). The key and data DBTs borrow from the
        // HintsDbDatum buffers which remain valid for this call. Returns 0 on success.
        let rc = unsafe {
            let put_fn = (*db).put.expect("DB->put function pointer is null");
            put_fn(
                db,
                ptr::null_mut(),
                &key_dbt as *const ffi::DBT as *mut ffi::DBT,
                &data_dbt as *const ffi::DBT as *mut ffi::DBT,
                0,
            )
        };

        if rc != 0 {
            return Err(HintsDbError::new(format!("DB->put failed: rc={}", rc)));
        }
        Ok(())
    }

    /// Store a key-value pair only if the key does not already exist.
    ///
    /// Calls `DB->put(db, NULL, key, data, DB_NOOVERWRITE)` per `exim_dbputb` in
    /// `hints_bdb.h` lines 149-154 / 285-288.
    ///
    /// Returns [`PutResult::Ok`] on success (rc == 0),
    /// [`PutResult::Duplicate`] if the key exists (`DB_KEYEXIST`).
    fn put_no_overwrite(
        &mut self,
        key: &HintsDbDatum,
        data: &HintsDbDatum,
    ) -> Result<PutResult, HintsDbError> {
        let db = self.db_handle();
        let key_dbt = datum_to_dbt(key);
        let data_dbt = datum_to_dbt(data);

        // SAFETY: db is a valid DB handle. DB->put with DB_NOOVERWRITE flag
        // returns DB_KEYEXIST if the key already exists, 0 on success.
        let rc = unsafe {
            let put_fn = (*db).put.expect("DB->put function pointer is null");
            put_fn(
                db,
                ptr::null_mut(),
                &key_dbt as *const ffi::DBT as *mut ffi::DBT,
                &data_dbt as *const ffi::DBT as *mut ffi::DBT,
                ffi::DB_NOOVERWRITE,
            )
        };

        if rc == DBPUTB_OK {
            Ok(PutResult::Ok)
        } else {
            // DB_KEYEXIST or any other non-zero return treated as duplicate,
            // matching C behavior where EXIM_DBPUTB_DUP = DB_KEYEXIST
            Ok(PutResult::Duplicate)
        }
    }

    /// Delete a key-value pair from the BDB database.
    ///
    /// Calls `DB->del(db, NULL, key, 0)` per `exim_dbdel` in
    /// `hints_bdb.h` lines 162-167 / 295-298.
    fn delete(&mut self, key: &HintsDbDatum) -> Result<(), HintsDbError> {
        let db = self.db_handle();
        let key_dbt = datum_to_dbt(key);

        // SAFETY: db is a valid DB handle. DB->del takes: db, txn (NULL), key DBT,
        // flags (0). Returns 0 on success, DB_NOTFOUND if key doesn't exist.
        let rc = unsafe {
            let del_fn = (*db).del.expect("DB->del function pointer is null");
            del_fn(
                db,
                ptr::null_mut(),
                &key_dbt as *const ffi::DBT as *mut ffi::DBT,
                0,
            )
        };

        if rc != 0 {
            return Err(HintsDbError::new(format!("DB->del failed: rc={}", rc)));
        }
        Ok(())
    }

    /// Begin scanning from the first key in the BDB database.
    ///
    /// Creates a new cursor via `DB->cursor()` and retrieves the first key-value
    /// pair via `DBC->c_get(cursor, key, data, DB_FIRST)`.
    ///
    /// Corresponds to `exim_dbcreate_cursor` + `exim_dbscan(..., TRUE, ...)` in
    /// `hints_bdb.h` lines 171-186 / 302-316.
    fn scan_first(&mut self) -> Result<Option<(HintsDbDatum, HintsDbDatum)>, HintsDbError> {
        // Close any existing cursor from a previous scan
        self.cursor = None;
        self.scan_impl(true)
    }

    /// Continue scanning to the next key in the BDB database.
    ///
    /// Uses the existing cursor with `DBC->c_get(cursor, key, data, DB_NEXT)`.
    ///
    /// Must be called after [`scan_first`]. Returns `Ok(None)` when iteration
    /// is exhausted.
    fn scan_next(&mut self) -> Result<Option<(HintsDbDatum, HintsDbDatum)>, HintsDbError> {
        if self.cursor.is_none() {
            return Err(HintsDbError::new(
                "scan_next called without prior scan_first",
            ));
        }
        self.scan_impl(false)
    }

    /// Close the BDB database, releasing all handles.
    ///
    /// For BDB 4.1+: closes DB via `DB->close(db, 0)`, then ENV via
    /// `DB_ENV->close(env, DB_FORCESYNC)`, matching `exim_dbclose__` in
    /// `hints_bdb.h` lines 195-201.
    ///
    /// For pre-4.1: closes DB via `DB->close(db, 0)`, matching line 325-326.
    ///
    /// Consumes `self` to prevent use-after-close.
    fn close(mut self) -> Result<(), HintsDbError> {
        self.close_handles()
    }

    /// Transaction start stub — BDB hints backend does not support transactions.
    ///
    /// Returns `false` to match the C stub `exim_dbtransaction_start` which
    /// returns `FALSE` (hints_bdb.h lines 92 / 255).
    fn transaction_start(&mut self) -> bool {
        false
    }

    /// Transaction commit stub — BDB hints backend does not support transactions.
    ///
    /// No-op to match the C stub `exim_dbtransaction_commit` which does nothing
    /// (hints_bdb.h lines 93 / 256).
    fn transaction_commit(&mut self) {}
}

// ---------------------------------------------------------------------------
// Drop Implementation — Safety Net
// ---------------------------------------------------------------------------

impl Drop for BdbHintsDb {
    /// Closes DB and ENV handles if they weren't already closed via `close()`.
    ///
    /// This is a safety net for cases where `close()` was not called explicitly
    /// (e.g., due to an early return or panic). After `close()` runs, both
    /// pointers are set to null so this becomes a no-op.
    fn drop(&mut self) {
        // Close cursor first
        self.cursor = None;

        // Close DB handle if still open
        if !self.db.is_null() {
            // SAFETY: self.db is a valid DB handle (non-null check above).
            // DB->close releases all internal DB resources. Best-effort — errors
            // from Drop cannot be propagated, so we log them via tracing.
            unsafe {
                if let Some(close_fn) = (*self.db).close {
                    let rc = close_fn(self.db, 0);
                    if rc != 0 {
                        tracing::error!("bdb drop: DB->close failed: rc={}", rc);
                    }
                }
            }
            self.db = ptr::null_mut();
        }

        // Close DB_ENV handle if still open (BDB 4.1+ only)
        #[cfg(bdb_41_plus)]
        if !self.env.is_null() {
            // SAFETY: self.env is a valid DB_ENV handle (non-null check above).
            // DB_ENV->close with DB_FORCESYNC syncs the memory pool. Best-effort.
            unsafe {
                if let Some(close_fn) = (*self.env).close {
                    let rc = close_fn(self.env, ffi::DB_FORCESYNC);
                    if rc != 0 {
                        tracing::error!("bdb drop: DB_ENV->close failed: rc={}", rc);
                    }
                }
            }
            self.env = ptr::null_mut();
        }

        #[cfg(not(bdb_41_plus))]
        {
            self.env = ptr::null_mut();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the BDB type string constant is set correctly.
    #[test]
    fn test_db_type_string() {
        #[cfg(bdb_41_plus)]
        assert_eq!(EXIM_DBTYPE, "db (v4.1+)");
        #[cfg(not(bdb_41_plus))]
        assert_eq!(EXIM_DBTYPE, "db (v3/4)");
    }

    /// Verify that EXIM_DB_RLIMIT matches the C constant.
    #[test]
    fn test_rlimit() {
        assert_eq!(EXIM_DB_RLIMIT, 150);
    }

    /// Verify that multi-open returns None (BDB does not support multi-open).
    #[test]
    fn test_open_multi_returns_none() {
        let flags = OpenFlags::read_write_create();
        let result = BdbHintsDb::open_multi("/nonexistent", "/tmp", &flags, 0o660);
        assert!(result.is_none());
    }

    /// Verify datum-to-DBT conversion round-trips correctly.
    #[test]
    fn test_datum_dbt_roundtrip() {
        let datum = HintsDbDatum::new(b"hello world");
        let dbt = datum_to_dbt(&datum);
        assert_eq!(dbt.size, 11);
        assert!(!dbt.data.is_null());

        // Convert back
        let recovered = dbt_to_datum(&dbt);
        assert!(recovered.is_some());
        assert_eq!(recovered.unwrap().as_bytes(), b"hello world");
    }

    /// Verify that a zeroed DBT has null data and zero size.
    #[test]
    fn test_zeroed_dbt() {
        let dbt = zeroed_dbt();
        assert!(dbt.data.is_null());
        assert_eq!(dbt.size, 0);
    }

    /// Verify that dbt_to_datum returns None for a null-data DBT.
    #[test]
    fn test_dbt_to_datum_null() {
        let dbt = zeroed_dbt();
        assert!(dbt_to_datum(&dbt).is_none());
    }

    /// Verify POSIX flag conversion.
    #[test]
    fn test_open_flags_conversion() {
        let flags_ro = OpenFlags::read_only();
        assert_eq!(open_flags_to_posix(&flags_ro), libc::O_RDONLY);

        let flags_rwc = OpenFlags::read_write_create();
        assert_eq!(
            open_flags_to_posix(&flags_rwc),
            libc::O_RDWR | libc::O_CREAT
        );

        let flags_rw = OpenFlags::read_write();
        assert_eq!(open_flags_to_posix(&flags_rw), libc::O_RDWR);
    }
}
