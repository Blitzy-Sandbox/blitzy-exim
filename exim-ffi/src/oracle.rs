//! Safe wrappers around Oracle OCI (Oracle Call Interface) C library.
//!
//! Provides managed Oracle sessions and cursor operations wrapping the
//! legacy OCI v2 API (`olog`, `oopen`, `oparse`, `oexec`, `ofetch`, etc.).
//! These wrappers are consumed by the `exim-lookups` Oracle lookup backend.
//!
//! # Safety
//!
//! All `unsafe` blocks are confined to this module per AAP §0.7.2.
//! The safe public API prevents null pointer dereference and buffer overflow
//! through RAII wrappers with `Drop` implementations for both sessions
//! and cursors.
//!
//! # Feature Gate
//!
//! This module is compiled only when `feature = "ffi-oracle"` is enabled.
//! The Oracle OCI client library (`libclntsh`) must be installed on the
//! build host for linking to succeed.
//!
//! # Pointer Stability Contract
//!
//! [`OracleDefine`] instances returned by [`OracleCursor::define`] contain
//! heap-allocated buffers and metadata that Oracle writes to during
//! [`OracleCursor::fetch`] operations. Callers **must not** drop an
//! `OracleDefine` while its associated cursor is still being fetched.
//! Normal LIFO variable scoping in Rust naturally satisfies this requirement.

use std::ffi::CString;

/// Oracle data type code for NUMBER columns.
/// Source: `oracle.c` line 41 — `#define NUMBER_TYPE 2`.
pub const NUMBER_TYPE: i16 = 2;

/// Oracle data type code for INTEGER columns.
/// Source: `oracle.c` line 42 — `#define INT_TYPE 3`.
pub const INT_TYPE: i16 = 3;

/// Oracle data type code for FLOAT columns.
/// Source: `oracle.c` line 43 — `#define FLOAT_TYPE 4`.
pub const FLOAT_TYPE: i16 = 4;

/// Oracle data type code for STRING (VARCHAR) columns.
/// Source: `oracle.c` line 44 — `#define STRING_TYPE 5`.
pub const STRING_TYPE: i16 = 5;

/// Oracle data type code for ROWID columns.
/// Source: `oracle.c` line 45 — `#define ROWID_TYPE 11`.
pub const ROWID_TYPE: i16 = 11;

/// Oracle data type code for DATE columns.
/// Source: `oracle.c` line 46 — `#define DATE_TYPE 12`.
pub const DATE_TYPE: i16 = 12;

/// Oracle error code indicating a described column does not exist in the
/// select list. Used as a sentinel to detect the end of the column list
/// during `odescr` iteration.
/// Source: `oracle.c` line 50 — `#define VAR_NOT_IN_LIST 1007`.
pub const VAR_NOT_IN_LIST: i16 = 1007;

/// Oracle error code indicating no more rows are available from a fetch.
/// Source: `oracle.c` line 51 — `#define NO_DATA_FOUND 1403`.
pub const NO_DATA_FOUND: i16 = 1403;

/// Maximum size in bytes for a single column output buffer.
/// Source: `oracle.c` line 26 — `#define MAX_ITEM_BUFFER_SIZE 1024`.
pub const MAX_ITEM_BUFFER_SIZE: usize = 1024;

/// Maximum number of columns in a SELECT list.
/// Source: `oracle.c` line 27 — `#define MAX_SELECT_LIST_SIZE 32`.
pub const MAX_SELECT_LIST_SIZE: usize = 32;

// ---------------------------------------------------------------------------
// Raw FFI bindings — private module wrapping Oracle OCI v2 C functions
// ---------------------------------------------------------------------------

mod ffi {
    use libc::{c_char, c_int, c_short, c_uchar};

    /// Signed 2-byte integer (Oracle `sb2`).
    pub type Sb2 = c_short;
    /// Unsigned 2-byte integer (Oracle `ub2`).
    pub type Ub2 = u16;
    /// Unsigned 4-byte integer (Oracle `ub4`).
    pub type Ub4 = u32;
    /// Signed 4-byte integer (Oracle `sb4`).
    pub type Sb4 = i32;
    /// Signed word-width integer (Oracle `sword`).
    pub type Sword = c_int;

    /// Size of the Host Data Area required by `olog`.
    /// Source: `oracle.c` line 37 — changed from 256 to 512 for 64-bit
    /// compatibility per Oracle documentation and Jin Choi's 2007 suggestion.
    pub const HDA_SIZE: usize = 512;

    /// Parse mode: parse the SQL statement immediately (no deferral).
    /// Source: `oracle.c` line 24 — `#define PARSE_NO_DEFER 0`.
    pub const PARSE_NO_DEFER: c_int = 0;

    /// Parse language version: V7 language mode.
    /// Source: `oracle.c` line 25 — `#define PARSE_V7_LNG 2`.
    pub const PARSE_V7_LNG: Ub4 = 2;

    /// Default (blocking) login mode for `olog`.
    /// Source: OCI header `ocidfn.h` — `OCI_LM_DEF` is 0.
    pub const OCI_LM_DEF: Ub4 = 0;

    /// Cursor Data Area — the primary OCI v2 handle structure.
    ///
    /// In Oracle OCI v2 headers, `Lda_Def` and `Cda_Def` are both typedefs
    /// for `struct cda_def`. The same 64-byte structure is used as both a
    /// Login Data Area (LDA) and a Cursor Data Area (CDA).
    ///
    /// Layout reconstructed from `<ocidfn.h>`:
    /// - `v2_rc` (sb2): V2 return code
    /// - `ft` (ub2): SQL function type
    /// - `rpc` (ub4): rows processed count
    /// - `peo` (ub2): parse error offset
    /// - `fc` (ub1): OCI function code
    /// - `rcs1` (ub1): filler
    /// - `rc` (ub2): V7 return code — primary error indicator
    /// - `wrn` (ub1): warning flags
    /// - `rcs2` (ub1): filler
    /// - `rcs3` (sword): filler
    /// - `_rest` ([u8; 44]): remaining fields (RID, fillers)
    ///
    /// Total: 64 bytes.
    #[repr(C)]
    pub struct CdaDef {
        pub v2_rc: Sb2,
        pub ft: Ub2,
        pub rpc: Ub4,
        pub peo: Ub2,
        pub fc: c_uchar,
        pub rcs1: c_uchar,
        pub rc: Ub2,
        pub wrn: c_uchar,
        pub rcs2: c_uchar,
        pub rcs3: Sword,
        pub rest: [u8; 44],
    }

    /// Login Data Area — identical to [`CdaDef`] per OCI v2 headers.
    pub type LdaDef = CdaDef;

    // Link against Oracle's client shared library. During unit tests, the
    // link attribute is omitted because libclntsh is a proprietary library
    // that is typically not available in CI environments. The extern symbols
    // are dead-code-eliminated by the linker since tests never invoke OCI
    // functions. In production builds, libclntsh must be present.
    #[cfg_attr(not(test), link(name = "clntsh"))]
    extern "C" {
        /// Retrieve a human-readable error message for a given Oracle error code.
        ///
        /// Writes a null-terminated string into `buf` (up to `buf_size` bytes)
        /// describing the error identified by `err_code` on the session `lda`.
        pub fn oerhms(lda: *mut LdaDef, err_code: Sb2, buf: *mut c_char, buf_size: c_int);

        /// Describe a column in the current SELECT list.
        ///
        /// Populates output parameters with metadata for column `col` (1-based).
        /// Returns 0 on success; non-zero sets `cursor.rc` to the OCI error code.
        pub fn odescr(
            cursor: *mut CdaDef,
            col: c_int,
            dbsize: *mut Sb4,
            dbtype: *mut Sb2,
            name: *mut c_char,
            name_len: *mut Sb4,
            dsize: *mut Sb4,
            precision: *mut Sb2,
            scale: *mut Sb2,
            nullok: *mut Sb2,
        ) -> c_int;

        /// Define (bind) an output variable for a column in the SELECT list.
        ///
        /// Associates column `col` (1-based) with the caller-provided buffer at
        /// `buf` of length `buf_len`. Oracle writes to `buf`, `indp`,
        /// `col_retlen`, and `col_retcode` during subsequent `ofetch` calls.
        pub fn odefin(
            cursor: *mut CdaDef,
            col: c_int,
            buf: *mut c_char,
            buf_len: c_int,
            ftype: c_int,
            scale: c_int,
            indp: *mut Sb2,
            fmt: *const c_char,
            fmt_len: c_int,
            fmt_type: c_int,
            col_retlen: *mut Ub2,
            col_retcode: *mut Ub2,
        ) -> c_int;

        /// Login to an Oracle database.
        ///
        /// Establishes a session using the given credentials. `hda` must point
        /// to a zero-initialized buffer of at least [`HDA_SIZE`] bytes. String
        /// length of `-1` means the string is null-terminated.
        pub fn olog(
            lda: *mut LdaDef,
            hda: *mut u8,
            uid: *const c_char,
            uid_len: c_int,
            pswd: *const c_char,
            pswd_len: c_int,
            conn: *const c_char,
            conn_len: c_int,
            mode: Ub4,
        ) -> c_int;

        /// Open a cursor on the given session.
        ///
        /// Allocates cursor resources. `name`, `name_len`, `area_size`, and
        /// `uid`/`uid_len` are typically set to null/`-1` for default behavior.
        pub fn oopen(
            cursor: *mut CdaDef,
            lda: *mut LdaDef,
            name: *const c_char,
            name_len: c_int,
            area_size: c_int,
            uid: *const c_char,
            uid_len: c_int,
        ) -> c_int;

        /// Close a cursor, releasing its resources.
        pub fn oclose(cursor: *mut CdaDef) -> c_int;

        /// Parse a SQL statement on the given cursor.
        ///
        /// `query_len` of `-1` means the query string is null-terminated.
        /// `defer_parse` controls deferred parsing (0 = immediate).
        /// `version` selects the language version (2 = V7).
        pub fn oparse(
            cursor: *mut CdaDef,
            query: *const c_char,
            query_len: Sb4,
            defer_parse: c_int,
            version: Ub4,
        ) -> c_int;

        /// Execute the previously parsed statement on the given cursor.
        pub fn oexec(cursor: *mut CdaDef) -> c_int;

        /// Fetch the next row from the cursor's result set.
        ///
        /// After a successful fetch, output buffers bound via `odefin` contain
        /// the column data. When no more rows remain, `cursor.rc` is set to
        /// [`super::NO_DATA_FOUND`] (1403).
        pub fn ofetch(cursor: *mut CdaDef) -> c_int;

        /// Log off from an Oracle session, releasing the LDA and HDA resources.
        pub fn ologof(lda: *mut LdaDef) -> c_int;
    }
}

// ---------------------------------------------------------------------------
// OracleError
// ---------------------------------------------------------------------------

/// Error originating from an Oracle OCI operation.
///
/// Contains the Oracle error code and a human-readable error message
/// obtained via the OCI `oerhms` function.
#[derive(Debug, Clone)]
pub struct OracleError {
    /// Oracle error code (from `Cda_Def.rc`).
    pub code: i16,
    /// Human-readable error description.
    pub message: String,
}

impl OracleError {
    /// Create a new `OracleError` with the given code and message.
    pub fn new(code: i16, message: String) -> Self {
        Self { code, message }
    }
}

impl std::fmt::Display for OracleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Oracle error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for OracleError {}

/// Allow conversion from `CString::new` interior-nul errors into
/// `OracleError`, providing a clear diagnostic when user-supplied
/// strings contain embedded null bytes.
impl From<std::ffi::NulError> for OracleError {
    fn from(e: std::ffi::NulError) -> Self {
        OracleError::new(
            -1,
            format!(
                "string contains interior null byte at position {}",
                e.nul_position()
            ),
        )
    }
}

// ---------------------------------------------------------------------------
// OracleColumnDesc
// ---------------------------------------------------------------------------

/// Column metadata returned by [`OracleCursor::describe`].
///
/// Mirrors the fields of the C `Ora_Describe` struct from `oracle.c`
/// lines 53–62.
#[derive(Debug, Clone)]
pub struct OracleColumnDesc {
    /// Column name as reported by Oracle.
    pub name: String,
    /// Database-internal storage size in bytes.
    pub db_size: i32,
    /// Database type code (see `NUMBER_TYPE`, `STRING_TYPE`, etc.).
    pub db_type: i16,
    /// Display size in bytes (may differ from `db_size` for DATE/ROWID).
    pub display_size: i32,
    /// Numeric precision (meaningful for NUMBER columns).
    pub precision: i16,
    /// Numeric scale (meaningful for NUMBER columns; non-zero → float).
    pub scale: i16,
    /// Whether the column permits NULL values.
    pub nullable: bool,
}

// ---------------------------------------------------------------------------
// OracleDefine — internal metadata storage
// ---------------------------------------------------------------------------

/// Internal heap-allocated storage for Oracle output bindings.
///
/// Heap allocation via `Box` guarantees pointer stability: even when the
/// owning `OracleDefine` is moved, the raw pointers Oracle holds (from
/// `odefin`) continue to point at valid memory.
struct DefineMetadata {
    /// Null indicator: set to -1 by Oracle if the column value is NULL.
    indicator: i16,
    /// Actual byte length of column data written by the last `ofetch`.
    return_length: u16,
    /// Column-level return code from the last `ofetch`.
    return_code: u16,
}

/// Output column definition with buffer and fetch metadata.
///
/// Returned by [`OracleCursor::define`] after binding an output buffer for
/// a specific column. Oracle writes directly into the heap-allocated storage
/// during [`OracleCursor::fetch`] operations.
///
/// # Pointer Stability
///
/// Both the `buffer` data (heap-allocated by `Vec`) and the metadata fields
/// (heap-allocated via `Box<DefineMetadata>`) have stable addresses that
/// survive moves of the `OracleDefine` value itself. Callers must not drop
/// an `OracleDefine` while its associated cursor is still being fetched.
pub struct OracleDefine {
    /// Output data buffer. Oracle writes column data here during fetch.
    /// Read up to [`OracleDefine::return_length`] bytes after a successful
    /// fetch to obtain the column value.
    pub buffer: Vec<u8>,
    /// Heap-pinned metadata written by Oracle during fetch.
    meta: Box<DefineMetadata>,
}

impl std::fmt::Debug for OracleDefine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OracleDefine")
            .field("buffer_len", &self.buffer.len())
            .field("indicator", &self.meta.indicator)
            .field("return_length", &self.meta.return_length)
            .field("return_code", &self.meta.return_code)
            .finish()
    }
}

impl OracleDefine {
    /// Null indicator value.
    ///
    /// Returns `-1` if the column value is `NULL`, `0` otherwise.
    /// Updated by Oracle during each [`OracleCursor::fetch`] call.
    pub fn indicator(&self) -> i16 {
        self.meta.indicator
    }

    /// Actual byte length of data returned for this column.
    ///
    /// After a successful fetch, read `buffer[..return_length() as usize]`
    /// to obtain the column value.
    pub fn return_length(&self) -> u16 {
        self.meta.return_length
    }

    /// Column-level return code from Oracle.
    ///
    /// A value of `0` indicates success; non-zero values indicate
    /// column-specific warnings or errors.
    pub fn return_code(&self) -> u16 {
        self.meta.return_code
    }
}

// ---------------------------------------------------------------------------
// OracleFetchResult
// ---------------------------------------------------------------------------

/// Result of an [`OracleCursor::fetch`] operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OracleFetchResult {
    /// A row was successfully fetched. Column data is available in the
    /// `OracleDefine` buffers bound via [`OracleCursor::define`].
    Row,
    /// No more rows are available (`NO_DATA_FOUND`).
    NoMoreData,
}

// ---------------------------------------------------------------------------
// OracleSession
// ---------------------------------------------------------------------------

/// Safe wrapper around an Oracle database session.
///
/// Manages the Login Data Area (LDA) and Host Data Area (HDA) for a single
/// Oracle connection. Mirrors the `oracle_connection` struct from `oracle.c`
/// lines 79–84.
///
/// The session is disconnected (via `ologof`) when dropped.
pub struct OracleSession {
    /// Login Data Area — heap-allocated for pointer stability.
    lda: Box<ffi::LdaDef>,
    /// Host Data Area — 512-byte heap-allocated buffer.
    /// Prefixed with `_` because it is never read directly; it must remain
    /// allocated for the lifetime of the session because Oracle internally
    /// references this buffer through the LDA pointer established by `olog`.
    _hda: Box<[u8; ffi::HDA_SIZE]>,
    /// Server connection string, retained for diagnostics.
    server: String,
}

impl OracleSession {
    /// Connect to an Oracle database.
    ///
    /// Performs a default (blocking) login using the OCI `olog` function.
    ///
    /// # Arguments
    ///
    /// * `host` — TNS service name or host (passed as the `conn` parameter
    ///   to `olog`).
    /// * `user` — Database user name.
    /// * `password` — Database password.
    ///
    /// # Errors
    ///
    /// Returns [`OracleError`] if the login fails or if any argument
    /// contains an interior null byte.
    pub fn connect(host: &str, user: &str, password: &str) -> Result<Self, OracleError> {
        let c_user = CString::new(user)?;
        let c_password = CString::new(password)?;
        let c_host = CString::new(host)?;

        // SAFETY: std::mem::zeroed is valid for CdaDef because it is a
        // #[repr(C)] struct composed entirely of integer and byte-array
        // fields, all of which have a valid zero representation.
        let mut lda: Box<ffi::CdaDef> = Box::new(unsafe { std::mem::zeroed() });
        let mut hda: Box<[u8; ffi::HDA_SIZE]> = Box::new([0u8; ffi::HDA_SIZE]);

        // SAFETY: calling olog to establish an Oracle connection.
        let rc = unsafe {
            // Safety: calling olog to establish an Oracle connection.
            // - `lda` is a valid heap-allocated, zero-initialized CdaDef.
            // - `hda` is a valid heap-allocated, zero-initialized 512-byte buffer.
            // - All C string pointers come from CString and are null-terminated.
            // - String length -1 tells Oracle the strings are null-terminated.
            ffi::olog(
                &mut *lda,
                hda.as_mut_ptr(),
                c_user.as_ptr(),
                -1,
                c_password.as_ptr(),
                -1,
                c_host.as_ptr(),
                -1,
                ffi::OCI_LM_DEF,
            )
        };

        if rc != 0 {
            let code = lda.rc as i16;
            let mut msg_buf = [0u8; MAX_ITEM_BUFFER_SIZE];
            // SAFETY: calling oerhms to format the Oracle error message.
            unsafe {
                // Safety: calling oerhms to format the Oracle error message.
                // - `lda` is a valid CdaDef whose `rc` field contains the error.
                // - `msg_buf` is a stack-allocated buffer of known size.
                // - oerhms writes a null-terminated string into the buffer.
                ffi::oerhms(
                    &mut *lda,
                    code as ffi::Sb2,
                    msg_buf.as_mut_ptr() as *mut libc::c_char,
                    msg_buf.len() as libc::c_int,
                );
            }
            let message = extract_c_string(&msg_buf);
            return Err(OracleError::new(code, message));
        }

        Ok(Self {
            lda,
            _hda: hda,
            server: host.to_string(),
        })
    }

    /// Retrieve a human-readable error message for the given Oracle error code.
    ///
    /// Calls the OCI `oerhms` function to format the message from this
    /// session's LDA.
    pub fn error_message(&self, error_code: i16) -> String {
        let mut buf = [0u8; MAX_ITEM_BUFFER_SIZE];
        // SAFETY: calling oerhms to retrieve an error description.
        unsafe {
            // Safety: calling oerhms to retrieve an error description.
            // - The const-to-mut cast is sound because oerhms does not modify
            //   the LDA; the `*mut` in its C signature is a legacy API artifact
            //   predating `const` in C89/C99.
            // - `buf` is a valid stack buffer of known size.
            ffi::oerhms(
                &*self.lda as *const ffi::CdaDef as *mut ffi::CdaDef,
                error_code as ffi::Sb2,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len() as libc::c_int,
            );
        }
        extract_c_string(&buf)
    }

    /// Returns the server connection string used to create this session.
    pub fn server(&self) -> &str {
        &self.server
    }
}

impl Drop for OracleSession {
    fn drop(&mut self) {
        // SAFETY: calling ologof to cleanly disconnect from Oracle.
        unsafe {
            // Safety: calling ologof to cleanly disconnect from Oracle.
            // - `self.lda` is a valid LDA from a successful olog call.
            // - After ologof returns, the LDA and HDA are no longer referenced
            //   by Oracle and will be freed when their Boxes drop.
            let _ = ffi::ologof(&mut *self.lda);
        }
    }
}

// ---------------------------------------------------------------------------
// OracleCursor
// ---------------------------------------------------------------------------

/// Safe wrapper around an Oracle cursor.
///
/// Provides methods for parsing SQL statements, describing and defining
/// output columns, executing statements, and fetching rows. The cursor
/// is closed (via `oclose`) when dropped.
pub struct OracleCursor {
    /// Cursor Data Area — heap-allocated for pointer stability.
    cda: Box<ffi::CdaDef>,
}

impl OracleCursor {
    /// Open a cursor on the given Oracle session.
    ///
    /// # Errors
    ///
    /// Returns [`OracleError`] if the OCI `oopen` call fails.
    pub fn open(session: &mut OracleSession) -> Result<Self, OracleError> {
        // SAFETY: std::mem::zeroed is valid for CdaDef (see OracleSession::connect).
        let mut cda: Box<ffi::CdaDef> = Box::new(unsafe { std::mem::zeroed() });

        // SAFETY: calling oopen to allocate cursor resources.
        let rc = unsafe {
            // Safety: calling oopen to allocate cursor resources.
            // - `cda` is a valid, zero-initialized CdaDef.
            // - `session.lda` is a valid LDA from a successful olog call.
            // - Null name/uid with -1 lengths selects default behavior.
            ffi::oopen(
                &mut *cda,
                &mut *session.lda,
                std::ptr::null(),
                -1,
                -1,
                std::ptr::null(),
                -1,
            )
        };

        if rc != 0 {
            let code = cda.rc as i16;
            let message = session.error_message(code);
            return Err(OracleError::new(code, message));
        }

        Ok(Self { cda })
    }

    /// Parse a SQL query on this cursor.
    ///
    /// The statement is parsed immediately (no deferral) using V7 language
    /// mode, matching the behavior in `oracle.c` line 364.
    ///
    /// # Errors
    ///
    /// Returns [`OracleError`] if the OCI `oparse` call fails (e.g., syntax
    /// error in the query).
    pub fn parse(&mut self, query: &str) -> Result<(), OracleError> {
        let c_query = CString::new(query)?;

        // SAFETY: calling oparse to parse the SQL statement.
        let rc = unsafe {
            // Safety: calling oparse to parse the SQL statement.
            // - `self.cda` is a valid CdaDef from a successful oopen call.
            // - `c_query` is a valid null-terminated C string.
            // - query_len of -1 tells Oracle the string is null-terminated.
            // - PARSE_NO_DEFER (0) = immediate parse.
            // - PARSE_V7_LNG (2) = V7 language version.
            ffi::oparse(
                &mut *self.cda,
                c_query.as_ptr(),
                -1,
                ffi::PARSE_NO_DEFER,
                ffi::PARSE_V7_LNG,
            )
        };

        if rc != 0 {
            let code = self.cda.rc as i16;
            return Err(OracleError::new(
                code,
                format!("parse failed (error {})", code),
            ));
        }

        Ok(())
    }

    /// Describe a column in the result set.
    ///
    /// `col` is a **0-based** column index. Internally, Oracle uses 1-based
    /// indexing; this method adjusts accordingly.
    ///
    /// # Errors
    ///
    /// Returns [`OracleError`] if the column does not exist or another OCI
    /// error occurs. When the error code is [`VAR_NOT_IN_LIST`] (1007), it
    /// indicates the end of the select list has been reached.
    pub fn describe(&mut self, col: i32) -> Result<OracleColumnDesc, OracleError> {
        let mut dbsize: ffi::Sb4 = 0;
        let mut dbtype: ffi::Sb2 = 0;
        let mut name_buf = [0u8; MAX_ITEM_BUFFER_SIZE];
        let mut name_len: ffi::Sb4 = MAX_ITEM_BUFFER_SIZE as ffi::Sb4;
        let mut dsize: ffi::Sb4 = 0;
        let mut precision: ffi::Sb2 = 0;
        let mut scale: ffi::Sb2 = 0;
        let mut nullok: ffi::Sb2 = 0;

        // SAFETY: calling odescr to retrieve column metadata.
        let rc = unsafe {
            // Safety: calling odescr to retrieve column metadata.
            // - `self.cda` is a valid cursor with a parsed SELECT statement.
            // - All output parameters are valid stack-allocated variables.
            // - `name_buf` is large enough (MAX_ITEM_BUFFER_SIZE bytes).
            // - Column index is 1-based per Oracle convention.
            ffi::odescr(
                &mut *self.cda,
                col + 1,
                &mut dbsize,
                &mut dbtype,
                name_buf.as_mut_ptr() as *mut libc::c_char,
                &mut name_len,
                &mut dsize,
                &mut precision,
                &mut scale,
                &mut nullok,
            )
        };

        if rc != 0 {
            let code = self.cda.rc as i16;
            return Err(OracleError::new(
                code,
                format!("describe column {} failed (error {})", col, code),
            ));
        }

        // Clamp name_len to a safe range before slicing.
        let safe_name_len = (name_len as usize).min(name_buf.len());
        let name = String::from_utf8_lossy(&name_buf[..safe_name_len])
            .trim_end_matches('\0')
            .to_string();

        Ok(OracleColumnDesc {
            name,
            db_size: dbsize,
            db_type: dbtype,
            display_size: dsize,
            precision,
            scale,
            nullable: nullok != 0,
        })
    }

    /// Bind an output buffer for a column in the SELECT list.
    ///
    /// `col` is a **0-based** column index. The `buf` slice is used only to
    /// determine the desired buffer size; the returned [`OracleDefine`] owns
    /// its own heap-allocated storage.
    ///
    /// Oracle writes to the returned `OracleDefine` during subsequent
    /// [`fetch`](OracleCursor::fetch) calls. The caller **must** keep the
    /// returned `OracleDefine` alive until all fetches are complete.
    ///
    /// # Errors
    ///
    /// Returns [`OracleError`] if the OCI `odefin` call fails.
    pub fn define(&mut self, col: i32, buf: &mut [u8]) -> Result<OracleDefine, OracleError> {
        let buf_len = buf.len().min(MAX_ITEM_BUFFER_SIZE);

        let mut def = OracleDefine {
            buffer: vec![0u8; buf_len],
            meta: Box::new(DefineMetadata {
                indicator: 0,
                return_length: 0,
                return_code: 0,
            }),
        };

        // Obtain stable pointers into the heap-allocated storage.
        // Vec's heap buffer and Box's heap allocation do not move when the
        // OracleDefine value is moved.
        let buf_ptr = def.buffer.as_mut_ptr() as *mut libc::c_char;
        let ind_ptr: *mut ffi::Sb2 = &mut def.meta.indicator;
        let retlen_ptr: *mut ffi::Ub2 = &mut def.meta.return_length;
        let retcode_ptr: *mut ffi::Ub2 = &mut def.meta.return_code;

        // SAFETY: calling odefin to bind an output buffer for a column.
        let rc = unsafe {
            // Safety: calling odefin to bind an output buffer for a column.
            // - `self.cda` is a valid cursor with a parsed statement.
            // - `buf_ptr` points into the Vec's heap allocation (stable).
            // - `ind_ptr`, `retlen_ptr`, `retcode_ptr` point into the
            //   Box<DefineMetadata> heap allocation (stable).
            // - Column index is 1-based per Oracle convention.
            // - ftype = STRING_TYPE (5) to retrieve data as text.
            // - scale = -1, fmt = null, fmt_len = -1, fmt_type = -1 for
            //   default formatting (matches oracle.c line 186–190).
            ffi::odefin(
                &mut *self.cda,
                col + 1,
                buf_ptr,
                buf_len as libc::c_int,
                STRING_TYPE as libc::c_int,
                -1,
                ind_ptr,
                std::ptr::null(),
                -1,
                -1,
                retlen_ptr,
                retcode_ptr,
            )
        };

        if rc != 0 {
            let code = self.cda.rc as i16;
            return Err(OracleError::new(
                code,
                format!("define column {} failed (error {})", col, code),
            ));
        }

        Ok(def)
    }

    /// Execute the previously parsed SQL statement.
    ///
    /// # Errors
    ///
    /// Returns [`OracleError`] if the OCI `oexec` call fails.
    pub fn execute(&mut self) -> Result<(), OracleError> {
        // SAFETY: calling oexec to execute the parsed statement.
        let rc = unsafe {
            // Safety: calling oexec to execute the parsed statement.
            // - `self.cda` is a valid cursor with a successfully parsed statement.
            ffi::oexec(&mut *self.cda)
        };

        if rc != 0 {
            let code = self.cda.rc as i16;
            return Err(OracleError::new(
                code,
                format!("execute failed (error {})", code),
            ));
        }

        Ok(())
    }

    /// Fetch the next row from the result set.
    ///
    /// On success, returns [`OracleFetchResult::Row`] and the bound
    /// [`OracleDefine`] buffers contain the column data. When no more rows
    /// are available, returns [`OracleFetchResult::NoMoreData`].
    ///
    /// # Errors
    ///
    /// Returns [`OracleError`] for fetch failures other than end-of-data.
    pub fn fetch(&mut self) -> Result<OracleFetchResult, OracleError> {
        // SAFETY: calling ofetch to retrieve the next result row.
        let _ = unsafe {
            // Safety: calling ofetch to retrieve the next result row.
            // - `self.cda` is a valid cursor after a successful oexec.
            // - Oracle writes to buffers previously bound via odefin.
            ffi::ofetch(&mut *self.cda)
        };

        let rc = self.cda.rc;
        if rc == NO_DATA_FOUND as ffi::Ub2 {
            return Ok(OracleFetchResult::NoMoreData);
        }
        if rc != 0 {
            let code = rc as i16;
            return Err(OracleError::new(
                code,
                format!("fetch failed (error {})", code),
            ));
        }

        Ok(OracleFetchResult::Row)
    }

    /// Return the current Oracle return code on this cursor.
    ///
    /// Useful for callers that need to inspect the raw OCI error code after
    /// an operation without constructing a full error message.
    pub fn return_code(&self) -> i16 {
        self.cda.rc as i16
    }
}

impl Drop for OracleCursor {
    fn drop(&mut self) {
        // SAFETY: calling oclose to release cursor resources.
        unsafe {
            // Safety: calling oclose to release cursor resources.
            // - `self.cda` is a valid CdaDef from a successful oopen call.
            // - After oclose returns, Oracle no longer references the CDA or
            //   any buffers bound via odefin.
            let _ = ffi::oclose(&mut *self.cda);
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Extract a Rust `String` from a byte buffer containing a null-terminated
/// C string. Returns an empty string if no null terminator is found.
fn extract_c_string(buf: &[u8]) -> String {
    // Find the first null byte; if absent, use the entire buffer.
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..len]).into_owned()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oracle_error_display() {
        let err = OracleError::new(1403, "no data found".to_string());
        assert_eq!(format!("{err}"), "Oracle error 1403: no data found");
    }

    #[test]
    fn test_oracle_error_new() {
        let err = OracleError::new(-1, "test".to_string());
        assert_eq!(err.code, -1);
        assert_eq!(err.message, "test");
    }

    #[test]
    fn test_oracle_error_from_nul() {
        let bad = CString::new("hello\0world");
        assert!(bad.is_err());
        let err: OracleError = bad.unwrap_err().into();
        assert_eq!(err.code, -1);
        assert!(err.message.contains("interior null byte"));
    }

    #[test]
    fn test_constants() {
        assert_eq!(NUMBER_TYPE, 2);
        assert_eq!(INT_TYPE, 3);
        assert_eq!(FLOAT_TYPE, 4);
        assert_eq!(STRING_TYPE, 5);
        assert_eq!(ROWID_TYPE, 11);
        assert_eq!(DATE_TYPE, 12);
        assert_eq!(VAR_NOT_IN_LIST, 1007);
        assert_eq!(NO_DATA_FOUND, 1403);
        assert_eq!(MAX_ITEM_BUFFER_SIZE, 1024);
        assert_eq!(MAX_SELECT_LIST_SIZE, 32);
    }

    #[test]
    fn test_fetch_result_equality() {
        assert_eq!(OracleFetchResult::Row, OracleFetchResult::Row);
        assert_eq!(OracleFetchResult::NoMoreData, OracleFetchResult::NoMoreData);
        assert_ne!(OracleFetchResult::Row, OracleFetchResult::NoMoreData);
    }

    #[test]
    fn test_oracle_define_initial_state() {
        let def = OracleDefine {
            buffer: vec![0u8; 128],
            meta: Box::new(DefineMetadata {
                indicator: 0,
                return_length: 0,
                return_code: 0,
            }),
        };
        assert_eq!(def.indicator(), 0);
        assert_eq!(def.return_length(), 0);
        assert_eq!(def.return_code(), 0);
        assert_eq!(def.buffer.len(), 128);
    }

    #[test]
    fn test_oracle_define_debug() {
        let def = OracleDefine {
            buffer: vec![0u8; 64],
            meta: Box::new(DefineMetadata {
                indicator: -1,
                return_length: 42,
                return_code: 0,
            }),
        };
        let debug = format!("{def:?}");
        assert!(debug.contains("OracleDefine"));
        assert!(debug.contains("indicator"));
        assert!(debug.contains("-1"));
        assert!(debug.contains("42"));
    }

    #[test]
    fn test_oracle_column_desc_clone() {
        let desc = OracleColumnDesc {
            name: "TEST_COL".to_string(),
            db_size: 100,
            db_type: STRING_TYPE,
            display_size: 100,
            precision: 0,
            scale: 0,
            nullable: true,
        };
        let desc2 = desc.clone();
        assert_eq!(desc.name, desc2.name);
        assert_eq!(desc.db_type, desc2.db_type);
        assert!(desc2.nullable);
    }

    #[test]
    fn test_extract_c_string_normal() {
        let buf = b"hello\0world";
        assert_eq!(extract_c_string(buf), "hello");
    }

    #[test]
    fn test_extract_c_string_no_null() {
        let buf = b"hello";
        assert_eq!(extract_c_string(buf), "hello");
    }

    #[test]
    fn test_extract_c_string_empty() {
        let buf = b"\0rest";
        assert_eq!(extract_c_string(buf), "");
    }

    #[test]
    fn test_extract_c_string_all_zero() {
        let buf = [0u8; 8];
        assert_eq!(extract_c_string(&buf), "");
    }
}
