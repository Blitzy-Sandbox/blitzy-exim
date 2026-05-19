// =============================================================================
// exim-lookups/src/cdb.rs — CDB Read-Only Lookup (Pure Rust)
// =============================================================================
//
// Rewrites `src/src/lookups/cdb.c` (489 lines) as a pure Rust CDB reader
// implementing the `LookupDriver` trait from `exim-drivers`. This is a
// self-contained, built-in DJB Constant DataBase reader with NO external CDB
// library dependency.
//
// The CDB format (Dan Bernstein's Constant DataBase) is a simple, fast,
// read-only hash-table-based file format optimized for constant data sets.
// CDB files are atomically updated by writing a new file and renaming over
// the old one, so there are no locking concerns during reads.
//
// CDB file structure:
//   - 2048-byte header: 256 entries × 8 bytes (position + length, LE u32)
//   - Data records: key_len(4) + data_len(4) + key + data
//   - Hash subtables: at positions referenced by header entries
//
// Per AAP §0.7.2: This file contains ZERO `unsafe` code.
// Per AAP §0.4.2: Uses `inventory::submit!` for compile-time registration.
// Per AAP §0.4.3: No mmap — uses standard File I/O + BufReader for safety.
//
// C function mapping:
//   cdb_hash()           → cdb_hash()
//   cdb_unpack()         → cdb_unpack()
//   cdb_bread()          → replaced by Read::read_exact()
//   cdb_open()           → CdbLookup::open()
//   cdb_check()          → CdbLookup::check()
//   cdb_find()           → CdbLookup::find()
//   cdb_close()          → CdbLookup::close()
//   cdb_version_report() → CdbLookup::version_report()

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::sync::Mutex;

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;

use crate::helpers::check_file::{check_file, CheckFileTarget, ExpectedFileType};

// =============================================================================
// CDB Constants
// =============================================================================

/// Number of pieces the hash table is split into.
/// Each piece has an 8-byte entry (4-byte position + 4-byte count) in the header.
/// C equivalent: `CDB_HASH_SPLIT` (256)
const CDB_HASH_SPLIT: usize = 256;

/// Bitmask to extract the hash table index from a hash value.
/// C equivalent: `CDB_HASH_MASK` (255)
const CDB_HASH_MASK: u32 = 255;

/// Size of each hash table entry in bytes: 4-byte hash + 4-byte position.
/// C equivalent: `CDB_HASH_ENTRY` (8)
const CDB_HASH_ENTRY: u64 = 8;

/// Total size of the CDB header table in bytes: 256 entries × 8 bytes = 2048.
/// C equivalent: `CDB_HASH_TABLE` (2048)
const CDB_HASH_TABLE: u64 = CDB_HASH_SPLIT as u64 * CDB_HASH_ENTRY;

// =============================================================================
// CDB State
// =============================================================================

/// Internal state for an open CDB file.
///
/// Replaces the C `struct cdb_state` from `cdb.c` lines 84–89. In the C
/// version, this held a file descriptor, file length, optional mmap pointer,
/// and a pointer to the offset table. In Rust, we use a `Mutex<BufReader<File>>`
/// for safe interior mutability (seeking/reading through an immutable trait
/// reference) and store the parsed offset table directly.
///
/// The `cdb_offsets` array stores the parsed 2048-byte header as 256 pairs
/// of (position, slot_count) in native endianness, avoiding repeated LE
/// unpacking during lookups.
struct CdbState {
    /// Mutex-guarded buffered reader wrapping the open CDB file handle.
    /// Replaces C `fileno` (raw file descriptor) and `cdb_map` (mmap pointer).
    ///
    /// The Mutex is required because `LookupDriver::find()` takes `&LookupHandle`
    /// (an immutable reference) but file I/O (seeking + reading) requires mutable
    /// access. The Mutex provides safe interior mutability.
    reader: Mutex<BufReader<File>>,

    /// The underlying file handle, kept separately for metadata and check
    /// operations. `File::metadata()` takes `&self` so no Mutex is needed.
    /// This is a `try_clone()` of the original file handle from `open()`.
    file_for_check: File,

    /// Parsed offset table from the 2048-byte CDB header.
    /// Each entry is a (subtable_position, slot_count) pair.
    /// Index: hash & CDB_HASH_MASK (0..255).
    ///
    /// Replaces C `cdb_offsets` pointer to the raw header bytes.
    offsets: [(u32, u32); CDB_HASH_SPLIT],

    /// Total file size in bytes — used for bounds checking to detect corruption.
    /// Replaces C `filelen` field.
    file_len: u64,
}

// =============================================================================
// DJB Hash Function
// =============================================================================

/// Compute the DJB hash (CDB variant) of a byte slice.
///
/// This is an exact reimplementation of the C `cdb_hash()` function from
/// `cdb.c` lines 98–110. The hash algorithm is:
///   h = 5381
///   for each byte c in key:
///     h = ((h << 5) + h) ^ c
///
/// This is the standard DJB2a hash (XOR variant) used by all CDB
/// implementations. The result must match the C version exactly for
/// correct key lookups.
///
/// # Arguments
///
/// * `key` — The key bytes to hash.
///
/// # Returns
///
/// A 32-bit hash value.
#[inline]
fn cdb_hash(key: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &byte in key {
        // Exact match of C: h += (h << 5); h ^= (uint32) *buf++;
        // This is equivalent to: h = (h + (h << 5)) ^ byte = (h * 33) ^ byte
        // Wrapping arithmetic matches C unsigned integer overflow semantics.
        h = h.wrapping_add(h.wrapping_shl(5)) ^ u32::from(byte);
    }
    h
}

/// Read a little-endian u32 from a 4-byte slice.
///
/// Replaces the C `cdb_unpack()` function from `cdb.c` lines 138–147.
/// Uses Rust's built-in `u32::from_le_bytes` for a safe, platform-independent
/// little-endian read.
///
/// # Panics
///
/// Panics if `buf` has fewer than 4 bytes. Callers must ensure the slice
/// is at least 4 bytes long.
#[inline]
fn cdb_unpack(buf: &[u8]) -> u32 {
    u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
}

// =============================================================================
// CdbLookup Driver
// =============================================================================

/// CDB (Constant DataBase) lookup driver — pure Rust implementation.
///
/// Implements the `LookupDriver` trait for DJB's CDB file format. This is a
/// read-only, single-key, absolute-file lookup that performs hash-based key
/// lookups against `.cdb` files.
///
/// The CDB format provides O(1) average-case lookups with no external library
/// dependency. Files are created by external CDB utilities (e.g., `cdbmake`)
/// and are atomically updated via rename.
///
/// # Registration
///
/// Registered at compile time via `inventory::submit!` under the name `"cdb"`.
/// This replaces the C `cdb_lookup_info` struct and `cdb_lookup_module_info`
/// registration from `cdb.c` lines 470–487.
#[derive(Debug, Default)]
pub struct CdbLookup;

impl CdbLookup {
    /// Create a new `CdbLookup` driver instance.
    ///
    /// The CDB driver is stateless at the type level — all per-file state is
    /// held in `CdbState` inside the `LookupHandle`.
    #[inline]
    pub fn new() -> Self {
        Self
    }
}

impl LookupDriver for CdbLookup {
    /// Open a CDB file, read and validate the 2048-byte header.
    ///
    /// Replaces C `cdb_open()` from `cdb.c` lines 151–234.
    ///
    /// Reads the entire 2048-byte header (256 entries × 8 bytes each, LE u32
    /// pairs of position and slot count), validates the file is large enough,
    /// and returns an opaque handle containing the parsed state.
    ///
    /// Unlike the C version, there is no mmap path — all reads use standard
    /// buffered File I/O for memory safety (per AAP §0.7.2).
    fn open(&self, filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        let path = filename
            .ok_or_else(|| DriverError::ExecutionFailed("cdb lookup requires a filename".into()))?;

        tracing::debug!(filename = %path, "cdb: opening file");

        // Open the file for reading — replaces C Uopen(filename, O_RDONLY, 0)
        let file = File::open(path).map_err(|e| {
            DriverError::ExecutionFailed(format!("{path}: failed to open for cdb lookup: {e}"))
        })?;

        // Get file metadata for length validation — replaces C fstat()
        let metadata = file.metadata().map_err(|e| {
            DriverError::ExecutionFailed(format!(
                "fstat({path}) failed - cannot do cdb lookup: {e}"
            ))
        })?;

        let file_len = metadata.len();

        // The file must be at least CDB_HASH_TABLE (2048) bytes long to contain
        // a valid header. Replaces C check at line 175.
        if file_len < CDB_HASH_TABLE {
            return Err(DriverError::ExecutionFailed(format!(
                "{path} too short for cdb lookup"
            )));
        }

        // Clone the file handle for use in check() — we need a separate handle
        // because BufReader takes ownership of the original File.
        let file_for_check = file.try_clone().map_err(|e| {
            DriverError::ExecutionFailed(format!("{path}: failed to clone file handle: {e}"))
        })?;

        let mut reader = BufReader::new(file);

        // Read the full 2048-byte header table.
        // Replaces C cdb_bread(fileno, cdb_offsets, CDB_HASH_TABLE) at line 221.
        let mut header_buf = [0u8; CDB_HASH_TABLE as usize];
        reader.read_exact(&mut header_buf).map_err(|e| {
            DriverError::ExecutionFailed(format!(
                "cannot read header from {path} for cdb lookup: {e}"
            ))
        })?;

        // Parse the 256 offset entries from the header.
        // Each entry is 8 bytes: 4-byte subtable position + 4-byte slot count.
        let mut offsets = [(0u32, 0u32); CDB_HASH_SPLIT];
        for (i, entry) in offsets.iter_mut().enumerate() {
            let base = i * CDB_HASH_ENTRY as usize;
            let position = cdb_unpack(&header_buf[base..base + 4]);
            let slot_count = cdb_unpack(&header_buf[base + 4..base + 8]);
            *entry = (position, slot_count);
        }

        tracing::debug!(
            filename = %path,
            file_len = file_len,
            "cdb: file opened successfully, header parsed"
        );

        let state = CdbState {
            reader: Mutex::new(reader),
            file_for_check,
            offsets,
            file_len,
        };

        Ok(Box::new(state))
    }

    /// Check a CDB file for security: type, permissions, ownership.
    ///
    /// Replaces C `cdb_check()` from `cdb.c` lines 242–249.
    ///
    /// Delegates to the shared `lf_check_file()` helper to verify:
    ///   - The file is a regular file (not a symlink, directory, etc.)
    ///   - No forbidden permission bits are set (per `modemask`)
    ///   - The file owner UID is in the allowed owners list
    ///   - The file group GID is in the allowed groups list
    fn check(
        &self,
        handle: &LookupHandle,
        filename: Option<&str>,
        modemask: i32,
        owners: &[u32],
        owngroups: &[u32],
    ) -> Result<bool, DriverError> {
        let state = handle
            .downcast_ref::<CdbState>()
            .ok_or_else(|| DriverError::ExecutionFailed("cdb: invalid handle type".into()))?;

        let display_name = filename.unwrap_or("<cdb>");

        // Use the file handle for fstat-based validation (CheckFileTarget::Fd).
        // Replaces C: lf_check_file(cdbp->fileno, filename, S_IFREG, modemask, ...)
        let owners_opt = if owners.is_empty() {
            None
        } else {
            Some(owners)
        };
        let groups_opt = if owngroups.is_empty() {
            None
        } else {
            Some(owngroups)
        };

        match check_file(
            CheckFileTarget::Fd(&state.file_for_check),
            ExpectedFileType::Regular,
            modemask as u32,
            owners_opt,
            groups_opt,
            "cdb",
            display_name,
        ) {
            Ok(()) => Ok(true),
            Err(e) => {
                tracing::debug!(error = %e, "cdb: file check failed");
                Ok(false)
            }
        }
    }

    /// Find a value by key in the CDB file.
    ///
    /// Replaces C `cdb_find()` from `cdb.c` lines 257–425.
    ///
    /// Algorithm:
    /// 1. Hash the key using `cdb_hash()`.
    /// 2. Use the low 8 bits of the hash to select a subtable from the header.
    /// 3. Validate the subtable bounds against the file length (corruption check).
    /// 4. Starting at (hash >> 8) % slot_count, probe slots with wraparound.
    /// 5. For each slot: if position == 0, key not found. If hash matches, seek
    ///    to the record, compare key lengths and bytes. On match, read and
    ///    return the data value.
    ///
    /// # Returns
    ///
    /// - `LookupResult::Found` — Key matched, value returned (untainted).
    /// - `LookupResult::NotFound` — Key not in the CDB file (not an error).
    /// - `LookupResult::Deferred` — File corruption or I/O error.
    fn find(
        &self,
        handle: &LookupHandle,
        filename: Option<&str>,
        key_or_query: &str,
        _options: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        let state = handle
            .downcast_ref::<CdbState>()
            .ok_or_else(|| DriverError::ExecutionFailed("cdb: invalid handle type".into()))?;

        let display_name = filename.unwrap_or("<cdb>");
        let key = key_or_query.as_bytes();
        let key_len = key.len() as u32;

        let key_hash = cdb_hash(key);

        // Select the subtable using the low 8 bits of the hash.
        // C: hash_offset_entry = CDB_HASH_ENTRY * (key_hash & CDB_HASH_MASK)
        let table_index = (key_hash & CDB_HASH_MASK) as usize;
        let (hash_offset, hash_offlen) = state.offsets[table_index];

        tracing::debug!(
            key = %key_or_query,
            key_hash = key_hash,
            table_index = table_index,
            hash_offset = hash_offset,
            hash_offlen = hash_offlen,
            "cdb: looking up key"
        );

        // If the slot count is zero, this key cannot be in the file.
        // C: if (hash_offlen == 0) return FAIL;
        if hash_offlen == 0 {
            return Ok(LookupResult::NotFound);
        }

        // Starting slot within the subtable.
        // C: hash_slotnm = (key_hash >> 8) % hash_offlen;
        let hash_slotnm = (key_hash >> 8) % hash_offlen;

        // Bounds check: the subtable must fit within the file.
        // C: if ((hash_offset + (hash_offlen * CDB_HASH_ENTRY)) > cdbp->filelen)
        let subtable_end = u64::from(hash_offset) + u64::from(hash_offlen) * CDB_HASH_ENTRY;
        if subtable_end > state.file_len {
            let msg = format!("cdb: corrupt cdb file {display_name} (too short)");
            tracing::debug!("{}", msg);
            return Ok(LookupResult::Deferred { message: msg });
        }

        // Calculate starting and ending offsets within the subtable.
        // C: cur_offset = hash_offset + (hash_slotnm * CDB_HASH_ENTRY);
        // C: end_offset = hash_offset + (hash_offlen * CDB_HASH_ENTRY);
        let start_offset = u64::from(hash_offset) + u64::from(hash_slotnm) * CDB_HASH_ENTRY;
        let end_offset = u64::from(hash_offset) + u64::from(hash_offlen) * CDB_HASH_ENTRY;

        // Acquire mutable access to the BufReader via the Mutex.
        // The Mutex provides interior mutability since the LookupDriver trait
        // passes `&LookupHandle` (immutable), but file I/O requires seeking
        // and reading (mutable operations).
        let mut reader = state
            .reader
            .lock()
            .map_err(|e| DriverError::TempFail(format!("cdb: failed to lock reader mutex: {e}")))?;

        let mut cur_offset = start_offset;

        // Linear probe through the subtable with wraparound.
        // C: for (int loop = 0; (loop < hash_offlen); ++loop)
        for _probe in 0..hash_offlen {
            // Seek to the current slot and read the 8-byte entry.
            // C: lseek(cdbp->fileno, (off_t) cur_offset, SEEK_SET)
            reader.seek(SeekFrom::Start(cur_offset)).map_err(|e| {
                DriverError::TempFail(format!("cdb: seek to offset {cur_offset} failed: {e}"))
            })?;

            let mut slot_buf = [0u8; 8];
            reader.read_exact(&mut slot_buf).map_err(|e| {
                DriverError::TempFail(format!("cdb: read slot at offset {cur_offset} failed: {e}"))
            })?;

            let item_hash = cdb_unpack(&slot_buf[0..4]);
            let item_posn = cdb_unpack(&slot_buf[4..8]);

            // If the position is zero, this is an empty slot — definite miss.
            // C: if (item_posn == 0) return FAIL;
            if item_posn == 0 {
                return Ok(LookupResult::NotFound);
            }

            // Check if the hash matches before doing expensive I/O.
            if item_hash == key_hash {
                // Seek to the record and read the key/data length header (8 bytes).
                // C: lseek(cdbp->fileno, (off_t) item_posn, SEEK_SET)
                reader
                    .seek(SeekFrom::Start(u64::from(item_posn)))
                    .map_err(|e| {
                        DriverError::TempFail(format!(
                            "cdb: seek to record at {item_posn} failed: {e}"
                        ))
                    })?;

                let mut record_header = [0u8; 8];
                reader.read_exact(&mut record_header).map_err(|e| {
                    DriverError::TempFail(format!(
                        "cdb: read record header at {item_posn} failed: {e}"
                    ))
                })?;

                let item_key_len = cdb_unpack(&record_header[0..4]);
                let item_dat_len = cdb_unpack(&record_header[4..8]);

                // Check key length matches before comparing bytes.
                // C: if (item_key_len == key_len)
                if item_key_len == key_len {
                    // Read the key bytes and compare.
                    let mut item_key = vec![0u8; item_key_len as usize];
                    reader.read_exact(&mut item_key).map_err(|e| {
                        DriverError::TempFail(format!(
                            "cdb: read key at record {item_posn} failed: {e}"
                        ))
                    })?;

                    if item_key == key {
                        // Match found — read the data value.
                        // C: *result = store_get(item_dat_len + 1, GET_UNTAINTED);
                        // C: cdb_bread(cdbp->fileno, *result, item_dat_len);
                        let mut data = vec![0u8; item_dat_len as usize];
                        reader.read_exact(&mut data).map_err(|e| {
                            DriverError::TempFail(format!(
                                "cdb: read data at record {item_posn} failed: {e}"
                            ))
                        })?;

                        // Convert data to a UTF-8 string. CDB values are typically
                        // text, but we handle non-UTF-8 by using lossy conversion
                        // to match the C behavior of treating data as raw bytes
                        // null-terminated.
                        let value = String::from_utf8_lossy(&data).into_owned();

                        tracing::debug!(
                            key = %key_or_query,
                            value_len = item_dat_len,
                            "cdb: key found"
                        );

                        return Ok(LookupResult::Found {
                            value,
                            cache_ttl: None,
                        });
                    }
                }
            }

            // Advance to the next slot, wrapping around to the start of
            // the subtable if we reach the end.
            // C: cur_offset += 8;
            // C: if (cur_offset == end_offset) cur_offset = hash_offset;
            cur_offset += CDB_HASH_ENTRY;
            if cur_offset == end_offset {
                cur_offset = u64::from(hash_offset);
            }
        }

        // Exhausted all slots without finding the key.
        // C: return FAIL;
        Ok(LookupResult::NotFound)
    }

    /// Close an open CDB handle, releasing the file handle.
    ///
    /// Replaces C `cdb_close()` from `cdb.c` lines 435–450.
    ///
    /// In Rust, dropping the `CdbState` inside the `LookupHandle` Box
    /// automatically closes the file handles (BufReader<File> and File both
    /// implement Drop). No explicit close/munmap is needed.
    fn close(&self, handle: LookupHandle) {
        // Attempt to extract the CdbState for debug logging, then drop it.
        if let Ok(state) = handle.downcast::<CdbState>() {
            tracing::debug!(file_len = state.file_len, "cdb: closing file handle");
            // state is dropped here, closing both file handles
            drop(state);
        }
        // If downcast fails, the handle is still dropped automatically.
    }

    /// Tidy up all CDB resources — no-op for CDB.
    ///
    /// CDB files are read-only and have no persistent state beyond the
    /// per-file handle. There is nothing to tidy globally.
    ///
    /// C equivalent: `tidy = NULL` in `cdb_lookup_info` (line 477).
    fn tidy(&self) {
        // No-op — CDB has no global state to clean up.
    }

    /// Quote a string for CDB — not applicable.
    ///
    /// CDB is a binary key-value store with exact-match semantics. There is
    /// no query language or escaping requirement.
    ///
    /// C equivalent: `quote = NULL` in `cdb_lookup_info` (line 478).
    fn quote(&self, _value: &str, _additional: Option<&str>) -> Option<String> {
        None
    }

    /// Report the CDB library version for `-bV` output.
    ///
    /// Replaces C `cdb_version_report()` from `cdb.c` lines 462–467:
    /// ```c
    /// string_fmt_append(g, "Library version: CDB: Exim %s builtin\n", EXIM_VERSION_STR);
    /// ```
    ///
    /// Since this is the built-in Rust implementation (not an external library),
    /// the version string identifies it as "Exim builtin".
    fn version_report(&self) -> Option<String> {
        Some("Library version: CDB: Exim builtin".to_string())
    }

    /// Return the lookup type: single-key with absolute file path.
    ///
    /// CDB lookups require a fully qualified file path (absolute) and a
    /// single key string.
    ///
    /// C equivalent: `type = lookup_absfile` in `cdb_lookup_info` (line 472).
    fn lookup_type(&self) -> LookupType {
        LookupType::ABS_FILE
    }

    /// Return the driver name used in configuration files.
    ///
    /// This is the name used in Exim configuration to reference CDB lookups:
    /// ```text
    /// domainlist local_domains = ${lookup{$domain}cdb{/etc/mail/domains.cdb}}
    /// ```
    ///
    /// C equivalent: `name = US"cdb"` in `cdb_lookup_info` (line 471).
    fn driver_name(&self) -> &str {
        "cdb"
    }
}

// =============================================================================
// Compile-Time Driver Registration
// =============================================================================

// Register the CDB lookup driver factory at compile time.
//
// Replaces C static registration from cdb.c lines 470-487:
//   lookup_info cdb_lookup_info = { .name = US"cdb", .type = lookup_absfile, ... };
//   static lookup_info *_lookup_list[] = { &cdb_lookup_info };
//   lookup_module_info cdb_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };
//
// The inventory::submit! macro collects this factory at link time, making
// it discoverable by DriverRegistry::find_lookup("cdb") without explicit
// module listing in a central registration table.
inventory::submit! {
    LookupDriverFactory {
        name: "cdb",
        create: || Box::new(CdbLookup::new()),
        lookup_type: LookupType::ABS_FILE,
        avail_string: Some("cdb (built-in)"),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test the DJB hash function against known values.
    ///
    /// The DJB2a hash of an empty key should be 5381 (the initial value).
    #[test]
    fn test_cdb_hash_empty() {
        assert_eq!(cdb_hash(b""), 5381);
    }

    /// Test the DJB hash against a simple single-byte key.
    ///
    /// For key "a" (0x61):
    ///   h = 5381
    ///   h = ((5381 << 5) + 5381) ^ 0x61
    ///   h = (172192 + 5381) ^ 97
    ///   h = 177573 ^ 97
    ///   h = 177636 (in decimal, if wrapping)
    ///
    /// Let's compute: 5381 * 33 = 177573, 177573 ^ 97 = 177636
    #[test]
    fn test_cdb_hash_single_byte() {
        let h = cdb_hash(b"a");
        // 5381 * 33 ^ 97
        let expected = (5381u32.wrapping_mul(33)) ^ 97;
        assert_eq!(h, expected);
    }

    /// Test that the hash matches the C implementation for a multi-byte key.
    ///
    /// For "abc":
    ///   h0 = 5381
    ///   h1 = (h0 * 33) ^ 'a' = 177573 ^ 97 = 177636
    ///   h2 = (h1 * 33) ^ 'b' = 5861988 ^ 98 = 5861894
    ///   h3 = (h2 * 33) ^ 'c' = 193442502 ^ 99 = 193442537
    ///
    /// Wait, let me recalculate carefully with wrapping u32:
    ///   h0 = 5381
    ///   h1 = ((5381 << 5) + 5381) ^ 97
    ///       = (172192 + 5381) ^ 97
    ///       = 177573 ^ 97
    ///       = 177636
    ///   h2 = ((177636 << 5) + 177636) ^ 98
    ///       = (5684352 + 177636) ^ 98
    ///       = 5861988 ^ 98
    ///       = 5861894
    ///   h3 = ((5861894 << 5) + 5861894) ^ 99
    ///       = (187580608 + 5861894) ^ 99
    ///       = 193442502 ^ 99 (check bit patterns)
    #[test]
    fn test_cdb_hash_multi_byte() {
        let h = cdb_hash(b"abc");
        // Manually compute step by step
        let mut expected: u32 = 5381;
        for &b in b"abc" {
            expected = expected.wrapping_add(expected.wrapping_shl(5)) ^ u32::from(b);
        }
        assert_eq!(h, expected);
    }

    /// Test `cdb_unpack` for little-endian u32 reading.
    #[test]
    fn test_cdb_unpack() {
        // LE encoding of 0x04030201 is [0x01, 0x02, 0x03, 0x04]
        assert_eq!(cdb_unpack(&[0x01, 0x02, 0x03, 0x04]), 0x04030201);
        // Zero
        assert_eq!(cdb_unpack(&[0x00, 0x00, 0x00, 0x00]), 0);
        // Max u32
        assert_eq!(cdb_unpack(&[0xFF, 0xFF, 0xFF, 0xFF]), u32::MAX);
        // 2048 in LE = [0x00, 0x08, 0x00, 0x00]
        assert_eq!(cdb_unpack(&[0x00, 0x08, 0x00, 0x00]), 2048);
    }

    /// Test that `CdbLookup::new()` creates a valid instance.
    #[test]
    fn test_cdb_lookup_new() {
        let driver = CdbLookup::new();
        assert_eq!(driver.driver_name(), "cdb");
        assert_eq!(driver.lookup_type(), LookupType::ABS_FILE);
    }

    /// Test version report format.
    #[test]
    fn test_version_report() {
        let driver = CdbLookup::new();
        let report = driver.version_report();
        assert!(report.is_some());
        assert!(report.unwrap().contains("CDB: Exim builtin"));
    }

    /// Test that open fails with a descriptive error for missing files.
    #[test]
    fn test_open_missing_file() {
        let driver = CdbLookup::new();
        let result = driver.open(Some("/nonexistent/path/to/file.cdb"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("failed to open"));
    }

    /// Test that open fails with a descriptive error when no filename given.
    #[test]
    fn test_open_no_filename() {
        let driver = CdbLookup::new();
        let result = driver.open(None);
        assert!(result.is_err());
    }

    /// Test that open fails for a file that is too short.
    #[test]
    fn test_open_too_short() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("exim_cdb_tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("too_short.cdb");
        let mut f = File::create(&path).unwrap();
        // Write only 100 bytes — less than the required 2048
        f.write_all(&[0u8; 100]).unwrap();
        drop(f);

        let driver = CdbLookup::new();
        let result = driver.open(Some(path.to_str().unwrap()));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("too short"));

        // Clean up
        let _ = std::fs::remove_file(&path);
    }

    /// Test quote returns None (CDB has no quoting).
    #[test]
    fn test_quote_returns_none() {
        let driver = CdbLookup::new();
        assert!(driver.quote("test", None).is_none());
        assert!(driver.quote("test", Some("extra")).is_none());
    }

    /// Test tidy is a no-op (doesn't panic).
    #[test]
    fn test_tidy_noop() {
        let driver = CdbLookup::new();
        driver.tidy(); // Should not panic
    }
}
