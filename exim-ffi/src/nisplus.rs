//! Safe wrappers around the NIS+ C library (`rpcsvc/nis.h`).
//!
//! NIS+ (Network Information Service Plus) is a directory service for
//! network administration data. This module wraps the NIS+ C API to provide:
//!
//! - [`nis_lookup_table()`] — Look up a NIS+ table to get column metadata
//! - [`nis_query_entries()`] — Query NIS+ table entries matching criteria
//! - [`nis_error_string()`] — Convert NIS+ error status to string
//!
//! ## Safety
//!
//! All `unsafe` blocks are confined to this module per AAP §0.7.2.
//! The safe public API prevents null pointer dereference, properly frees
//! NIS+ results via `nis_freeresult`, and converts C strings/types to
//! Rust-owned types before returning.
//!
//! ## NIS+ Query Format
//!
//! NIS+ queries use "indexed name" syntax:
//! ```text
//! [column=value,...],table_name.org_dir.example.com.
//! ```
//! An optional result-field suffix `...:field_name` restricts output to a
//! single column, but this parsing is handled by the lookup layer, not here.

use std::ffi::{CStr, CString};
use std::fmt;
use std::ptr;

use libc::{c_int, c_void};

// ---------------------------------------------------------------------------
// Raw FFI bindings — private module with hand-written declarations matching
// the system headers <rpcsvc/nis.h>, <rpcsvc/nislib.h>, <rpcsvc/nis_tags.h>.
//
// We use hand-written declarations rather than bindgen because:
//   1. The NIS+ struct hierarchy is deeply nested (XDR-generated unions)
//   2. We only need a small subset of the total API
//   3. Hand-written declarations keep the unsafe surface minimal
// ---------------------------------------------------------------------------
mod ffi {
    use libc::{c_char, c_int, c_uint, c_void};

    // -----------------------------------------------------------------------
    // NIS+ status codes (from rpcsvc/nis.h enum nis_error)
    // -----------------------------------------------------------------------
    pub const NIS_SUCCESS: c_int = 0;
    pub const NIS_S_SUCCESS: c_int = 1;
    pub const NIS_NOTFOUND: c_int = 2;
    pub const NIS_S_NOTFOUND: c_int = 3;
    pub const NIS_NOSUCHTABLE: c_int = 23;

    // -----------------------------------------------------------------------
    // NIS+ object type constants (from rpcsvc/nis.h enum zotypes)
    // -----------------------------------------------------------------------
    pub const TABLE_OBJ: c_int = 4;
    pub const ENTRY_OBJ: c_int = 5;

    // -----------------------------------------------------------------------
    // NIS+ request flags (from rpcsvc/nis_tags.h)
    // -----------------------------------------------------------------------
    /// Expand partially qualified names.
    pub const EXPAND_NAME: c_uint = 1 << 6; // 0x40
    /// Do not return cached results.
    pub const NO_CACHE: c_uint = 1 << 4; // 0x10

    // -----------------------------------------------------------------------
    // Opaque / repr(C) types matching the NIS+ C structures.
    //
    // We define the full struct layouts needed to traverse:
    //   nis_result → nis_object → objdata → table_obj / entry_obj
    //
    // All pointer fields use *mut / *const raw pointers because these
    // structs are allocated and owned by the NIS+ library.
    // -----------------------------------------------------------------------

    /// Column descriptor within a NIS+ table definition.
    /// Matches `struct table_col` in rpcsvc/nis.h.
    #[repr(C)]
    pub struct table_col {
        pub tc_name: *mut c_char,
        pub tc_flags: u32,
        pub tc_rights: u32,
    }

    /// Column value within a NIS+ entry.
    /// Matches `struct entry_col` in rpcsvc/nis.h.
    #[repr(C)]
    pub struct entry_col {
        pub ec_flags: u32,
        pub ec_value_len: c_uint,
        pub ec_value_val: *mut c_char,
    }

    /// NIS+ table object data.
    /// Matches `struct table_obj` in rpcsvc/nis.h.
    #[repr(C)]
    pub struct table_obj {
        pub ta_type: *mut c_char,
        pub ta_maxcol: c_int,
        pub ta_sep: u8,
        pub ta_cols_len: c_uint,
        pub ta_cols_val: *mut table_col,
        pub ta_path: *mut c_char,
    }

    /// NIS+ entry object data.
    /// Matches `struct entry_obj` in rpcsvc/nis.h.
    #[repr(C)]
    pub struct entry_obj {
        pub en_type: *mut c_char,
        pub en_cols_len: c_uint,
        pub en_cols_val: *mut entry_col,
    }

    /// Object data union — we use a byte array sized to hold the largest
    /// variant. The first field is always `zo_type` (a c_int), which
    /// tells us how to interpret the rest.
    ///
    /// On 64-bit Linux the largest variant (`directory_obj`) is well under
    /// 256 bytes. We over-allocate to be safe — the exact offset of the
    /// union payload is always `size_of::<c_int>()` bytes past `zo_type`.
    #[repr(C)]
    pub struct objdata {
        pub zo_type: c_int,
        // Union payload — we cast into this based on zo_type.
        // Padding is generous to cover all union arms.
        pub _payload: [u8; 256],
    }

    /// Minimal NIS+ OID (object identifier with creation/modification time).
    #[repr(C)]
    pub struct nis_oid {
        pub ctime: u32,
        pub mtime: u32,
    }

    /// NIS+ object.  Matches `struct nis_object` in rpcsvc/nis.h.
    #[repr(C)]
    pub struct nis_object {
        pub zo_oid: nis_oid,
        pub zo_name: *mut c_char,
        pub zo_owner: *mut c_char,
        pub zo_group: *mut c_char,
        pub zo_domain: *mut c_char,
        pub zo_access: u32,
        pub zo_ttl: u32,
        pub zo_data: objdata,
    }

    /// NIS+ netobj (opaque byte array used for cookies, keys, etc.).
    #[repr(C)]
    pub struct netobj {
        pub n_len: c_uint,
        pub n_bytes: *mut c_char,
    }

    /// NIS+ result structure returned by `nis_lookup` and `nis_list`.
    /// Matches `struct nis_result` in rpcsvc/nis.h.
    #[repr(C)]
    pub struct nis_result {
        pub status: c_int, // nis_error enum value
        pub objects_len: c_uint,
        pub objects_val: *mut nis_object,
        pub cookie: netobj,
        pub zticks: u32,
        pub dticks: u32,
        pub aticks: u32,
        pub cticks: u32,
    }

    // -----------------------------------------------------------------------
    // Helper to extract the union payload pointer from an objdata struct.
    // -----------------------------------------------------------------------

    impl objdata {
        /// Interpret the union payload as a `table_obj` pointer.
        ///
        /// # Safety
        /// Caller MUST have verified `zo_type == TABLE_OBJ` before calling.
        pub unsafe fn as_table_obj(&self) -> *const table_obj {
            self._payload.as_ptr().cast::<table_obj>()
        }

        /// Interpret the union payload as an `entry_obj` pointer.
        ///
        /// # Safety
        /// Caller MUST have verified `zo_type == ENTRY_OBJ` before calling.
        pub unsafe fn as_entry_obj(&self) -> *const entry_obj {
            self._payload.as_ptr().cast::<entry_obj>()
        }
    }

    // -----------------------------------------------------------------------
    // Extern "C" function declarations from <rpcsvc/nislib.h>.
    // We link against libnsl which provides these symbols.
    // -----------------------------------------------------------------------
    #[link(name = "nsl")]
    extern "C" {
        /// Look up a NIS+ object by fully-qualified name.
        pub fn nis_lookup(name: *const c_char, flags: c_uint) -> *mut nis_result;

        /// List NIS+ table entries matching an indexed name query.
        /// The callback and userdata pointers are both NULL when no callback
        /// is needed (as in Exim's usage).
        pub fn nis_list(
            name: *const c_char,
            flags: c_uint,
            callback: *const c_void,
            userdata: *const c_void,
        ) -> *mut nis_result;

        /// Convert a NIS+ error code to a human-readable string.
        /// Returns a pointer to a static C string.
        pub fn nis_sperrno(status: c_int) -> *const c_char;

        /// Free a `nis_result` structure allocated by `nis_lookup` or `nis_list`.
        pub fn nis_freeresult(result: *mut nis_result);
    }
}

// ===========================================================================
// Public types
// ===========================================================================

/// Error from NIS+ operations.
///
/// Wraps a NIS+ status code and a human-readable message string obtained
/// via [`nis_sperrno`](ffi::nis_sperrno).
#[derive(Debug, Clone)]
pub struct NisplusError {
    /// The raw NIS+ error code (from `enum nis_error` in `rpcsvc/nis.h`).
    pub status: i32,
    /// Human-readable error message.
    pub message: String,
}

impl NisplusError {
    /// Create a new `NisplusError` with the given status code and message.
    pub fn new(status: i32, msg: impl Into<String>) -> Self {
        Self {
            status,
            message: msg.into(),
        }
    }

    /// Create an error by looking up the status code's message via
    /// `nis_sperrno`.
    fn from_status(status: c_int) -> Self {
        let message = nis_error_string(status);
        Self { status, message }
    }
}

impl fmt::Display for NisplusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NIS+ error {}: {}", self.status, self.message)
    }
}

impl std::error::Error for NisplusError {}

/// Metadata about a NIS+ table (column names).
///
/// Extracted from a `nis_object` whose `zo_type == TABLE_OBJ`.
/// Used by the lookup layer to match column names when formatting results.
#[derive(Debug, Clone)]
pub struct NisplusTableInfo {
    /// Column names from the table definition, in column order.
    pub column_names: Vec<String>,
}

/// A single column value in a NIS+ entry.
///
/// NIS+ column values may contain arbitrary bytes (binary data),
/// so the value is stored as `Vec<u8>` rather than `String`.
#[derive(Debug, Clone)]
pub struct NisplusColumn {
    /// Raw column value bytes. May contain arbitrary binary data.
    pub value: Vec<u8>,
    /// Column value length as reported by NIS+ (`ec_value_len`).
    pub len: usize,
}

/// A single NIS+ entry (row) from a table query.
///
/// Each entry contains one [`NisplusColumn`] per column in the table.
#[derive(Debug, Clone)]
pub struct NisplusEntry {
    /// Column values for this entry, in column order.
    pub columns: Vec<NisplusColumn>,
}

/// Result of a NIS+ table query via [`nis_query_entries`].
#[derive(Debug, Clone)]
pub enum NisplusQueryResult {
    /// Query found matching entries.
    Found(Vec<NisplusEntry>),
    /// Key not found in table (`NIS_NOTFOUND`).
    NotFound,
    /// Table does not exist (`NIS_NOSUCHTABLE`).
    NoSuchTable,
}

// ===========================================================================
// RAII guard for nis_result pointers — ensures nis_freeresult is always called
// ===========================================================================

/// RAII guard that calls `nis_freeresult` on drop.
struct NisResultGuard {
    ptr: *mut ffi::nis_result,
}

impl NisResultGuard {
    /// Wrap a non-null `nis_result` pointer.
    fn new(ptr: *mut ffi::nis_result) -> Option<Self> {
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr })
        }
    }

    /// Access the underlying result (immutable).
    fn as_ref(&self) -> &ffi::nis_result {
        // SAFETY: the pointer was validated as non-null in `new()` and is
        // valid until `nis_freeresult` is called in `drop()`.
        unsafe { &*self.ptr }
    }
}

impl Drop for NisResultGuard {
    fn drop(&mut self) {
        // SAFETY: calling nis_freeresult to release the NIS+
        // result structure that was allocated by nis_lookup or nis_list.
        // The pointer was verified non-null in NisResultGuard::new().
        unsafe {
            ffi::nis_freeresult(self.ptr);
        }
    }
}

// ===========================================================================
// Public safe API
// ===========================================================================

/// Look up a NIS+ table to get column metadata.
///
/// Calls `nis_lookup()` with `EXPAND_NAME | NO_CACHE` flags to retrieve the
/// table object and extract column names. This mirrors the table-info lookup
/// in `src/src/lookups/nisplus.c` line 93.
///
/// # Arguments
///
/// * `table_name` — Fully-qualified or partially-qualified NIS+ table name.
///   The `EXPAND_NAME` flag allows partial names to be expanded by the NIS+
///   server.
///
/// # Returns
///
/// * `Ok(NisplusTableInfo)` — Table found; column names extracted.
/// * `Err(NisplusError)` — Lookup failed (table not found, permission error, etc.).
///
/// # Examples
///
/// ```no_run
/// # use exim_ffi::nisplus::{nis_lookup_table, NisplusError};
/// let info = nis_lookup_table("hosts.org_dir.example.com.")?;
/// for name in &info.column_names {
///     println!("column: {}", name);
/// }
/// # Ok::<(), NisplusError>(())
/// ```
pub fn nis_lookup_table(table_name: &str) -> Result<NisplusTableInfo, NisplusError> {
    let c_name = CString::new(table_name)
        .map_err(|_| NisplusError::new(-1, "table name contains interior NUL byte"))?;

    // SAFETY: Consolidated NIS+ table lookup sequence. nis_lookup() is called with
    // a valid CString and standard flags (EXPAND_NAME | NO_CACHE), returning a
    // nis_result pointer freed by NisResultGuard. The result's objects_val pointer
    // is checked for null/count before dereferencing, zo_type is verified as
    // TABLE_OBJ before accessing the union payload, and column name C strings are
    // read via CStr::from_ptr with null checks. All pointers are owned by the
    // nis_result and valid until the guard drops.
    unsafe {
        let result_ptr = ffi::nis_lookup(c_name.as_ptr(), ffi::EXPAND_NAME | ffi::NO_CACHE);

        let guard = NisResultGuard::new(result_ptr)
            .ok_or_else(|| NisplusError::new(-1, "nis_lookup returned null pointer"))?;

        let result = guard.as_ref();

        if result.status != ffi::NIS_SUCCESS {
            return Err(NisplusError::from_status(result.status));
        }

        if result.objects_len == 0 || result.objects_val.is_null() {
            return Err(NisplusError::new(
                result.status,
                "nis_lookup returned success but no objects",
            ));
        }

        let obj = &*result.objects_val;

        if obj.zo_data.zo_type != ffi::TABLE_OBJ {
            return Err(NisplusError::new(
                -1,
                format!("NIS+ object is not a table (type={})", obj.zo_data.zo_type),
            ));
        }

        let ta = &*obj.zo_data.as_table_obj();
        let num_cols = ta.ta_cols_len as usize;
        let mut column_names = Vec::with_capacity(num_cols);

        for i in 0..num_cols {
            let col = &*ta.ta_cols_val.add(i);
            let name = if col.tc_name.is_null() {
                String::new()
            } else {
                CStr::from_ptr(col.tc_name).to_string_lossy().into_owned()
            };
            column_names.push(name);
        }

        Ok(NisplusTableInfo { column_names })
    }
}

/// Query NIS+ table entries matching the given query string.
///
/// Calls `nis_list()` with the `EXPAND_NAME` flag to retrieve matching
/// entries. This mirrors the entry query in `src/src/lookups/nisplus.c`
/// line 113.
///
/// # Arguments
///
/// * `query` — NIS+ search query in indexed name format:
///   `[column=value,...],table_name.org_dir.domain.`
///
/// # Returns
///
/// * `Ok(NisplusQueryResult::Found(entries))` — Matching entries found.
/// * `Ok(NisplusQueryResult::NotFound)` — No matching entries.
/// * `Ok(NisplusQueryResult::NoSuchTable)` — Table does not exist.
/// * `Err(NisplusError)` — Query failed due to network, permission, or
///   other NIS+ error.
///
/// # Examples
///
/// ```no_run
/// # use exim_ffi::nisplus::{nis_query_entries, NisplusQueryResult, NisplusError};
/// match nis_query_entries("[name=testuser],passwd.org_dir.example.com.")? {
///     NisplusQueryResult::Found(entries) => {
///         for entry in &entries {
///             println!("entry has {} columns", entry.columns.len());
///         }
///     }
///     NisplusQueryResult::NotFound => println!("not found"),
///     NisplusQueryResult::NoSuchTable => println!("no such table"),
/// }
/// # Ok::<(), NisplusError>(())
/// ```
pub fn nis_query_entries(query: &str) -> Result<NisplusQueryResult, NisplusError> {
    let c_query = CString::new(query)
        .map_err(|_| NisplusError::new(-1, "query contains interior NUL byte"))?;

    // SAFETY: Consolidated NIS+ entry query. nis_list() is called with a valid
    // CString query and EXPAND_NAME flag (NULL callback/userdata matching the C
    // source). The returned nis_result is freed by NisResultGuard. objects_val is
    // null/count checked before dereferencing, zo_type is verified as ENTRY_OBJ
    // before accessing the union payload, and column value pointers are checked
    // for null before creating byte slices. All pointers are owned by nis_result.
    unsafe {
        let result_ptr = ffi::nis_list(
            c_query.as_ptr(),
            ffi::EXPAND_NAME,
            ptr::null::<c_void>(),
            ptr::null::<c_void>(),
        );

        let guard = NisResultGuard::new(result_ptr)
            .ok_or_else(|| NisplusError::new(-1, "nis_list returned null pointer"))?;

        let result = guard.as_ref();

        match result.status {
            ffi::NIS_SUCCESS | ffi::NIS_S_SUCCESS => {}
            ffi::NIS_NOTFOUND | ffi::NIS_S_NOTFOUND => {
                return Ok(NisplusQueryResult::NotFound);
            }
            ffi::NIS_NOSUCHTABLE => {
                return Ok(NisplusQueryResult::NoSuchTable);
            }
            _ => {
                return Err(NisplusError::from_status(result.status));
            }
        }

        let num_objects = result.objects_len as usize;
        if num_objects == 0 || result.objects_val.is_null() {
            return Ok(NisplusQueryResult::NotFound);
        }

        let mut entries = Vec::with_capacity(num_objects);

        for obj_idx in 0..num_objects {
            let obj = &*result.objects_val.add(obj_idx);

            if obj.zo_data.zo_type != ffi::ENTRY_OBJ {
                continue;
            }

            let eo = &*obj.zo_data.as_entry_obj();
            let num_cols = eo.en_cols_len as usize;
            let mut columns = Vec::with_capacity(num_cols);

            for col_idx in 0..num_cols {
                let ec = &*eo.en_cols_val.add(col_idx);
                let raw_len = ec.ec_value_len as usize;

                let value = if ec.ec_value_val.is_null() || raw_len == 0 {
                    Vec::new()
                } else {
                    std::slice::from_raw_parts(ec.ec_value_val as *const u8, raw_len).to_vec()
                };

                columns.push(NisplusColumn {
                    len: raw_len,
                    value,
                });
            }

            entries.push(NisplusEntry { columns });
        }

        if entries.is_empty() {
            Ok(NisplusQueryResult::NotFound)
        } else {
            Ok(NisplusQueryResult::Found(entries))
        }
    }
}

/// Convert a NIS+ error status code to a human-readable string.
///
/// Wraps `nis_sperrno()` safely. If the status code is not recognized
/// (returns a null pointer), a generic fallback message is returned.
///
/// # Arguments
///
/// * `status` — NIS+ error code from `enum nis_error`.
///
/// # Returns
///
/// A human-readable error description string.
pub fn nis_error_string(status: i32) -> String {
    // SAFETY: nis_sperrno() returns a pointer to a static null-terminated C string
    // for the given NIS+ error code (pure lookup, no side effects). The pointer is
    // null-checked, then CStr::from_ptr reads the static string that remains valid
    // for the process lifetime.
    unsafe {
        let ptr = ffi::nis_sperrno(status as c_int);
        if ptr.is_null() {
            return format!("NIS+ error {}", status);
        }
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

// ===========================================================================
// Unit tests — can run even without a NIS+ server (test error conversion)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nisplus_error_display() {
        let err = NisplusError::new(2, "test error");
        assert_eq!(err.status, 2);
        assert_eq!(err.message, "test error");
        let display = format!("{}", err);
        assert!(display.contains("NIS+ error 2"));
        assert!(display.contains("test error"));
    }

    #[test]
    fn test_nisplus_error_new() {
        let err = NisplusError::new(23, String::from("no such table"));
        assert_eq!(err.status, 23);
        assert_eq!(err.message, "no such table");
    }

    #[test]
    fn test_nis_error_string_known_code() {
        // NIS_SUCCESS (0) should return a non-empty string.
        let msg = nis_error_string(0);
        assert!(
            !msg.is_empty(),
            "nis_sperrno(0) should return a non-empty string"
        );
    }

    #[test]
    fn test_nisplus_column_clone() {
        let col = NisplusColumn {
            value: vec![1, 2, 3],
            len: 3,
        };
        let cloned = col.clone();
        assert_eq!(cloned.value, vec![1, 2, 3]);
        assert_eq!(cloned.len, 3);
    }

    #[test]
    fn test_nisplus_entry_clone() {
        let entry = NisplusEntry {
            columns: vec![
                NisplusColumn {
                    value: vec![b'a'],
                    len: 1,
                },
                NisplusColumn {
                    value: vec![b'b', b'c'],
                    len: 2,
                },
            ],
        };
        let cloned = entry.clone();
        assert_eq!(cloned.columns.len(), 2);
        assert_eq!(cloned.columns[0].value, vec![b'a']);
        assert_eq!(cloned.columns[1].len, 2);
    }

    #[test]
    fn test_nisplus_table_info_clone() {
        let info = NisplusTableInfo {
            column_names: vec!["name".into(), "value".into()],
        };
        let cloned = info.clone();
        assert_eq!(cloned.column_names.len(), 2);
        assert_eq!(cloned.column_names[0], "name");
    }

    #[test]
    fn test_nisplus_query_result_variants() {
        let found = NisplusQueryResult::Found(vec![NisplusEntry { columns: vec![] }]);
        let not_found = NisplusQueryResult::NotFound;
        let no_table = NisplusQueryResult::NoSuchTable;

        // Verify Debug formatting works
        let _ = format!("{:?}", found);
        let _ = format!("{:?}", not_found);
        let _ = format!("{:?}", no_table);
    }

    #[test]
    fn test_nis_lookup_table_nul_byte_error() {
        let result = nis_lookup_table("table\0name");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("NUL"));
    }

    #[test]
    fn test_nis_query_entries_nul_byte_error() {
        let result = nis_query_entries("query\0string");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("NUL"));
    }
}
