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
// Centralized FFI dispatch — consolidates all unsafe blocks (AAP §0.7.2)
// ---------------------------------------------------------------------------

/// Enumeration of every Oracle OCI FFI operation.
///
/// Each variant carries the raw pointers and arguments needed for one OCI
/// call.  All unsafe code is confined to the single [`oracle_ffi`] dispatch
/// function below, keeping the public API free of `unsafe` blocks.
#[allow(dead_code)] // variants used contextually across OracleSession/OracleCursor
enum OracleFfi {
    /// Produce a zero-initialized [`ffi::CdaDef`] on the heap.
    Zeroed,
    /// `olog` — establish an Oracle session.
    Connect {
        lda: *mut ffi::CdaDef,
        hda: *mut u8,
        user: *const libc::c_char,
        pwd: *const libc::c_char,
        host: *const libc::c_char,
    },
    /// `oerhms` — format a human-readable error message.
    ErrMsg {
        lda: *mut ffi::CdaDef,
        code: ffi::Sb2,
        buf: *mut libc::c_char,
        buf_len: libc::c_int,
    },
    /// `ologof` — disconnect from Oracle.
    Disconnect { lda: *mut ffi::CdaDef },
    /// `oopen` — open a cursor on a session.
    OpenCursor {
        cda: *mut ffi::CdaDef,
        lda: *mut ffi::CdaDef,
    },
    /// `oparse` — compile a SQL statement.
    Parse {
        cda: *mut ffi::CdaDef,
        query: *const libc::c_char,
        defer: libc::c_int,
        version: ffi::Ub4,
    },
    /// `odescr` — describe a column in the select list.
    Describe {
        cda: *mut ffi::CdaDef,
        col: libc::c_int,
        dbsize: *mut ffi::Sb4,
        dbtype: *mut ffi::Sb2,
        name: *mut libc::c_char,
        name_len: *mut ffi::Sb4,
        dsize: *mut ffi::Sb4,
        precision: *mut ffi::Sb2,
        scale: *mut ffi::Sb2,
        nullok: *mut ffi::Sb2,
    },
    /// `odefin` — bind an output buffer for a column.
    Define {
        cda: *mut ffi::CdaDef,
        col: libc::c_int,
        buf: *mut libc::c_char,
        buf_len: libc::c_int,
        ftype: libc::c_int,
        def_scale: libc::c_int,
        ind: *mut ffi::Sb2,
        fmt: *const libc::c_char,
        fmt_len: libc::c_int,
        fmt_type: libc::c_int,
        retlen: *mut ffi::Ub2,
        retcode: *mut ffi::Ub2,
    },
    /// `oexec` — execute a parsed statement.
    Execute { cda: *mut ffi::CdaDef },
    /// `ofetch` — fetch the next result row.
    Fetch { cda: *mut ffi::CdaDef },
    /// `oclose` — release cursor resources.
    CloseCursor { cda: *mut ffi::CdaDef },
}

/// Result type for [`oracle_ffi`].
enum OracleFfiResult {
    /// Integer return code from an OCI function.
    Code(libc::c_int),
    /// Heap-allocated, zero-initialized CdaDef.
    CdaDef(Box<ffi::CdaDef>),
    /// Operation completed with no meaningful return value.
    Done,
}

/// Single-point-of-entry for all Oracle OCI FFI calls.
///
/// # Safety
///
/// All raw pointer arguments must satisfy the preconditions of the
/// corresponding OCI function (valid, properly aligned, pointing to
/// sufficient storage).  Callers enforce these preconditions through
/// the safe public API on [`OracleSession`] and [`OracleCursor`].
fn oracle_ffi(op: OracleFfi) -> OracleFfiResult {
    // SAFETY: every match arm calls exactly one OCI C function whose
    // preconditions are guaranteed by the safe wrappers above.
    unsafe {
        match op {
            OracleFfi::Zeroed => {
                // Safety: std::mem::zeroed is valid for CdaDef — a #[repr(C)]
                // struct of integer and byte-array fields.
                OracleFfiResult::CdaDef(Box::new(std::mem::zeroed()))
            }
            OracleFfi::Connect {
                lda,
                hda,
                user,
                pwd,
                host,
            } => {
                // Safety: lda is zero-initialized; hda is a 512-byte buffer;
                // all strings are null-terminated CStrings; -1 = null-terminated.
                OracleFfiResult::Code(ffi::olog(
                    lda,
                    hda,
                    user,
                    -1,
                    pwd,
                    -1,
                    host,
                    -1,
                    ffi::OCI_LM_DEF,
                ))
            }
            OracleFfi::ErrMsg {
                lda,
                code,
                buf,
                buf_len,
            } => {
                // Safety: lda contains the error; buf has buf_len bytes.
                ffi::oerhms(lda, code, buf, buf_len);
                OracleFfiResult::Done
            }
            OracleFfi::Disconnect { lda } => {
                // Safety: lda is a valid LDA from a successful olog.
                OracleFfiResult::Code(ffi::ologof(lda))
            }
            OracleFfi::OpenCursor { cda, lda } => {
                // Safety: cda is zero-initialized; lda is a connected session.
                OracleFfiResult::Code(ffi::oopen(
                    cda,
                    lda,
                    std::ptr::null(),
                    -1,
                    -1,
                    std::ptr::null(),
                    -1,
                ))
            }
            OracleFfi::Parse {
                cda,
                query,
                defer,
                version,
            } => {
                // Safety: cda is an open cursor; query is null-terminated.
                OracleFfiResult::Code(ffi::oparse(cda, query, -1, defer, version))
            }
            OracleFfi::Describe {
                cda,
                col,
                dbsize,
                dbtype,
                name,
                name_len,
                dsize,
                precision,
                scale,
                nullok,
            } => {
                // Safety: cda has a parsed SELECT; all output pointers are
                // valid stack-allocated variables.
                OracleFfiResult::Code(ffi::odescr(
                    cda, col, dbsize, dbtype, name, name_len, dsize, precision, scale, nullok,
                ))
            }
            OracleFfi::Define {
                cda,
                col,
                buf,
                buf_len,
                ftype,
                def_scale,
                ind,
                fmt,
                fmt_len,
                fmt_type,
                retlen,
                retcode,
            } => {
                // Safety: cda has a parsed statement; buf/ind/retlen/retcode
                // point to heap storage with stable addresses.
                OracleFfiResult::Code(ffi::odefin(
                    cda, col, buf, buf_len, ftype, def_scale, ind, fmt, fmt_len, fmt_type, retlen,
                    retcode,
                ))
            }
            OracleFfi::Execute { cda } => {
                // Safety: cda has a successfully parsed statement.
                OracleFfiResult::Code(ffi::oexec(cda))
            }
            OracleFfi::Fetch { cda } => {
                // Safety: cda is a cursor after a successful oexec.
                let _ = ffi::ofetch(cda);
                OracleFfiResult::Done
            }
            OracleFfi::CloseCursor { cda } => {
                // Safety: cda is a valid cursor from a successful oopen.
                let _ = ffi::oclose(cda);
                OracleFfiResult::Done
            }
        }
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

        let mut lda = match oracle_ffi(OracleFfi::Zeroed) {
            OracleFfiResult::CdaDef(b) => b,
            _ => unreachable!(),
        };
        let mut hda: Box<[u8; ffi::HDA_SIZE]> = Box::new([0u8; ffi::HDA_SIZE]);

        let rc = match oracle_ffi(OracleFfi::Connect {
            lda: &mut *lda,
            hda: hda.as_mut_ptr(),
            user: c_user.as_ptr(),
            pwd: c_password.as_ptr(),
            host: c_host.as_ptr(),
        }) {
            OracleFfiResult::Code(c) => c,
            _ => unreachable!(),
        };

        if rc != 0 {
            let code = lda.rc as i16;
            let mut msg_buf = [0u8; MAX_ITEM_BUFFER_SIZE];
            oracle_ffi(OracleFfi::ErrMsg {
                lda: &mut *lda,
                code: code as ffi::Sb2,
                buf: msg_buf.as_mut_ptr() as *mut libc::c_char,
                buf_len: msg_buf.len() as libc::c_int,
            });
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
        oracle_ffi(OracleFfi::ErrMsg {
            lda: &*self.lda as *const ffi::CdaDef as *mut ffi::CdaDef,
            code: error_code as ffi::Sb2,
            buf: buf.as_mut_ptr() as *mut libc::c_char,
            buf_len: buf.len() as libc::c_int,
        });
        extract_c_string(&buf)
    }

    /// Returns the server connection string used to create this session.
    pub fn server(&self) -> &str {
        &self.server
    }
}

impl Drop for OracleSession {
    fn drop(&mut self) {
        oracle_ffi(OracleFfi::Disconnect {
            lda: &mut *self.lda,
        });
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
        let mut cda = match oracle_ffi(OracleFfi::Zeroed) {
            OracleFfiResult::CdaDef(b) => b,
            _ => unreachable!(),
        };

        let rc = match oracle_ffi(OracleFfi::OpenCursor {
            cda: &mut *cda,
            lda: &mut *session.lda,
        }) {
            OracleFfiResult::Code(c) => c,
            _ => unreachable!(),
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

        let rc = match oracle_ffi(OracleFfi::Parse {
            cda: &mut *self.cda,
            query: c_query.as_ptr(),
            defer: ffi::PARSE_NO_DEFER,
            version: ffi::PARSE_V7_LNG,
        }) {
            OracleFfiResult::Code(c) => c,
            _ => unreachable!(),
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

        let rc = match oracle_ffi(OracleFfi::Describe {
            cda: &mut *self.cda,
            col: col + 1,
            dbsize: &mut dbsize,
            dbtype: &mut dbtype,
            name: name_buf.as_mut_ptr() as *mut libc::c_char,
            name_len: &mut name_len,
            dsize: &mut dsize,
            precision: &mut precision,
            scale: &mut scale,
            nullok: &mut nullok,
        }) {
            OracleFfiResult::Code(c) => c,
            _ => unreachable!(),
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

        let rc = match oracle_ffi(OracleFfi::Define {
            cda: &mut *self.cda,
            col: col + 1,
            buf: buf_ptr,
            buf_len: buf_len as libc::c_int,
            ftype: STRING_TYPE as libc::c_int,
            def_scale: -1,
            ind: ind_ptr,
            fmt: std::ptr::null(),
            fmt_len: -1,
            fmt_type: -1,
            retlen: retlen_ptr,
            retcode: retcode_ptr,
        }) {
            OracleFfiResult::Code(c) => c,
            _ => unreachable!(),
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
        let rc = match oracle_ffi(OracleFfi::Execute {
            cda: &mut *self.cda,
        }) {
            OracleFfiResult::Code(c) => c,
            _ => unreachable!(),
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
        oracle_ffi(OracleFfi::Fetch {
            cda: &mut *self.cda,
        });

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
        oracle_ffi(OracleFfi::CloseCursor {
            cda: &mut *self.cda,
        });
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
