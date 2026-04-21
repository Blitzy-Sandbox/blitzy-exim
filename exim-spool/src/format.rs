//! Spool format constants, helper functions, and shared types.
//!
//! This is the foundational module for the `exim-spool` crate. It defines all
//! spool format constants (message ID lengths, data start offsets, file
//! permissions), shared enumerations (`SpoolReadResult`, `SpoolWriteContext`),
//! and helper functions for path construction, newline sanitization, and spool
//! variable serialization.
//!
//! **Compatibility Rule (AAP §0.7.1):** Every constant in this module MUST
//! exactly match the corresponding C definition so that spool files written by
//! C Exim are byte-level readable by Rust Exim and vice-versa.
//!
//! # Source origins
//!
//! - `src/src/local_scan.h` lines 114–129 — Message ID length constants, spool
//!   data start offset constants.
//! - `src/src/macros.h` lines 879–884 — `SpoolReadResult` (spool_read_OK …).
//! - `src/src/macros.h` line 1032 — `SpoolWriteContext` (SW_RECEIVING …).
//! - `src/src/config.h.defaults` lines 90, 150 — `INPUT_DIRECTORY_MODE`,
//!   `SPOOL_MODE`.
//! - `src/src/macros.h` lines 188–189 — `SPOOL_NAME_LENGTH`.
//! - `src/src/functions.h` lines 1194–1262 — inline helpers: `spool_q_sname`,
//!   `spool_q_fname`, `spool_fname`, `set_subdir_str`, `is_new_message_id`,
//!   `is_old_message_id`, `spool_data_start_offset`.
//! - `src/src/spool_out.c` lines 109–134 — `zap_newlines`, `spool_var_write`.

use std::borrow::Cow;
use std::io::{self, Write};
use std::path::PathBuf;

// =============================================================================
// Message ID Format Constants
// =============================================================================
//
// Exim message IDs encode a timestamp, process ID, and sub-second counter in
// base-62. Two formats exist: the current (64-bit PID) format and the legacy
// (32-bit PID) format. Both formats use the same 6-character time component.
//
// Current format: TTTTTT-PPPPPPPPPPP-SSSS   (23 characters)
// Legacy format:  TTTTTT-PPPPPP-SS           (16 characters)

/// Time component length — always 6 characters, base-62 encoded seconds since
/// the Unix epoch.
///
/// Source: `src/src/local_scan.h` line 118 — `#define MESSAGE_ID_TIME_LEN 6`
pub const MESSAGE_ID_TIME_LEN: usize = 6;

/// PID component length — current format (11 characters, base-62 encoded
/// 64-bit process ID).
///
/// Source: `src/src/local_scan.h` line 119 — `#define MESSAGE_ID_PID_LEN 11`
pub const MESSAGE_ID_PID_LEN: usize = 11;

/// PID component length — old/legacy format (6 characters, base-62 encoded
/// 32-bit process ID).
///
/// Source: `src/src/local_scan.h` line 114 — `#define MESSAGE_ID_PID_LEN_OLD 6`
pub const MESSAGE_ID_PID_LEN_OLD: usize = 6;

/// Sub-second component length — current format (4 characters).
///
/// Source: `src/src/local_scan.h` line 120 — `#define MESSAGE_ID_SUBTIME_LEN 4`
pub const MESSAGE_ID_SUBTIME_LEN: usize = 4;

/// Sub-second component length — old/legacy format (2 characters).
///
/// Source: `src/src/local_scan.h` line 115 —
///   `#define MESSAGE_ID_SUBTIME_LEN_OLD 2`
pub const MESSAGE_ID_SUBTIME_LEN_OLD: usize = 2;

/// Total message ID length — current format.
///
/// Layout: `TTTTTT-PPPPPPPPPPP-SSSS` → 6 + 1 + 11 + 1 + 4 = **23**.
///
/// Source: `src/src/local_scan.h` line 123 —
///   `#define MESSAGE_ID_LENGTH (MESSAGE_ID_TIME_LEN+1+MESSAGE_ID_PID_LEN+1+MESSAGE_ID_SUBTIME_LEN)`
pub const MESSAGE_ID_LENGTH: usize =
    MESSAGE_ID_TIME_LEN + 1 + MESSAGE_ID_PID_LEN + 1 + MESSAGE_ID_SUBTIME_LEN;

/// Total message ID length — old/legacy format.
///
/// Layout: `TTTTTT-PPPPPP-SS` → 6 + 1 + 6 + 1 + 2 = **16**.
///
/// Source: `src/src/local_scan.h` line 122 —
///   `#define MESSAGE_ID_LENGTH_OLD (MESSAGE_ID_TIME_LEN+1+MESSAGE_ID_PID_LEN_OLD+1+MESSAGE_ID_SUBTIME_LEN_OLD)`
pub const MESSAGE_ID_LENGTH_OLD: usize =
    MESSAGE_ID_TIME_LEN + 1 + MESSAGE_ID_PID_LEN_OLD + 1 + MESSAGE_ID_SUBTIME_LEN_OLD;

// =============================================================================
// Spool Data Start Offset Constants
// =============================================================================
//
// The -D (data) file begins with a line containing the message ID followed by
// "-D\n". The actual message data starts immediately after that line. The
// offset from the beginning of the file to the start of message data is
// therefore MESSAGE_ID_LENGTH + 3 (for the "-D\n" suffix).

/// Data start offset for the current message ID format.
///
/// Value: 23 + 3 = **26**.
///
/// Source: `src/src/local_scan.h` line 129 —
///   `#define SPOOL_DATA_START_OFFSET (MESSAGE_ID_LENGTH+3)`
pub const SPOOL_DATA_START_OFFSET: usize = MESSAGE_ID_LENGTH + 3;

/// Data start offset for the old/legacy message ID format.
///
/// Value: 16 + 3 = **19**.
///
/// Source: `src/src/local_scan.h` line 128 —
///   `#define SPOOL_DATA_START_OFFSET_OLD (MESSAGE_ID_LENGTH_OLD+3)`
pub const SPOOL_DATA_START_OFFSET_OLD: usize = MESSAGE_ID_LENGTH_OLD + 3;

/// Spool filename length — message ID length plus 2 for the "-H" or "-D"
/// suffix.
///
/// Value: 23 + 2 = **25**.
///
/// Source: `src/src/macros.h` line 189 —
///   `#define SPOOL_NAME_LENGTH (MESSAGE_ID_LENGTH + 2)`
pub const SPOOL_NAME_LENGTH: usize = MESSAGE_ID_LENGTH + 2;

// =============================================================================
// File Permission Constants
// =============================================================================

/// Default spool file permissions: owner read/write, group read (0640).
///
/// Source: `src/src/config.h.defaults` line 150 —
///   `#define SPOOL_MODE 0640`
pub const SPOOL_MODE: u32 = 0o640;

/// Input directory permissions: owner rwx, group rx (0750).
///
/// Source: `src/src/config.h.defaults` line 90 —
///   `#define INPUT_DIRECTORY_MODE 0750`
pub const INPUT_DIRECTORY_MODE: u32 = 0o750;

// =============================================================================
// Enumerations
// =============================================================================

/// Result codes returned from spool header read operations.
///
/// These values match the C enum defined in `src/src/macros.h` lines 879–884
/// exactly, including discriminant values, to ensure binary-level
/// compatibility when interpreting return codes.
///
/// ```text
/// enum {
///   spool_read_OK,        /* 0 — success */
///   spool_read_notopen,   /* 1 — open failed */
///   spool_read_enverror,  /* 2 — error in the envelope */
///   spool_read_hdrerror   /* 3 — error in the headers */
/// };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum SpoolReadResult {
    /// `spool_read_OK` — spool header read completed successfully.
    OK = 0,
    /// `spool_read_notopen` — spool file could not be opened.
    NotOpen = 1,
    /// `spool_read_enverror` — error encountered while reading the envelope
    /// portion of the spool header file.
    EnvError = 2,
    /// `spool_read_hdrerror` — error encountered while reading the RFC 2822
    /// header portion of the spool header file.
    HdrError = 3,
}

/// Context indicator for spool write operations.
///
/// Determines the error message wording when a spool write fails. Matches the
/// C enum defined in `src/src/macros.h` line 1032:
///
/// ```text
/// enum { SW_RECEIVING, SW_DELIVERING, SW_MODIFYING };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum SpoolWriteContext {
    /// `SW_RECEIVING` — writing the spool file while receiving a message from
    /// the sender (initial spool creation).
    Receiving = 0,
    /// `SW_DELIVERING` — writing the spool file while delivering a message
    /// (updating delivery status, adding journal entries).
    Delivering = 1,
    /// `SW_MODIFYING` — writing the spool file while modifying a message
    /// in-place (e.g., header rewrite, address rewrite).
    Modifying = 2,
}

// =============================================================================
// Spool Path Helper Functions
// =============================================================================

/// Construct a spool file path using the default queue name.
///
/// Produces a path of the form:
/// ```text
/// {spool_directory}/{queue_name}/{purpose}/{subdir}/{fname}{suffix}
/// ```
///
/// This is the Rust equivalent of the C inline function at
/// `src/src/functions.h` lines 1217–1231:
/// ```c
/// string_sprintf("%s/%s/%s/%s/%s%s",
///     spool_directory, queue_name, purpose, subdir, fname, suffix);
/// ```
///
/// When `queue_name` is empty the path collapses to
/// `{spool_directory}//{purpose}/…`, which the filesystem treats identically
/// to a single slash.
///
/// # Arguments
///
/// * `spool_directory` — Base spool directory path (e.g., `/var/spool/exim`).
/// * `queue_name` — Queue name; empty string for the default queue.
/// * `purpose` — Directory purpose identifier (`"input"`, `"msglog"`, etc.).
/// * `subdir` — Subdirectory; empty string or a single-character split
///   directory derived from the message ID.
/// * `fname` — Filename stem (typically the message ID).
/// * `suffix` — Filename suffix (`"-H"`, `"-D"`, `""`, etc.).
///
/// # Returns
///
/// A [`PathBuf`] representing the fully qualified spool file path.
pub fn spool_fname(
    spool_directory: &str,
    queue_name: &str,
    purpose: &str,
    subdir: &str,
    fname: &str,
    suffix: &str,
) -> PathBuf {
    // Replicate the exact C format string: "%s/%s/%s/%s/%s%s"
    // This preserves double-slash behavior when queue_name or subdir is empty,
    // which the filesystem normalizes transparently.
    PathBuf::from(format!(
        "{}/{}/{}/{}/{}{}",
        spool_directory, queue_name, purpose, subdir, fname, suffix
    ))
}

/// Construct a queue-specific spool file path.
///
/// Like [`spool_fname`] but with an explicit `queue` parameter instead of
/// using a stored queue name.
///
/// Produces:
/// ```text
/// {spool_directory}/{queue}/{purpose}/{subdir}/{fname}{suffix}
/// ```
///
/// Source: `src/src/functions.h` lines 1209–1215.
///
/// # Arguments
///
/// * `spool_directory` — Base spool directory path.
/// * `purpose` — Directory purpose identifier.
/// * `queue` — Queue name; empty string for the default queue.
/// * `subdir` — Single-character subdirectory or empty string.
/// * `fname` — Filename stem.
/// * `suffix` — Filename suffix.
///
/// # Returns
///
/// A [`PathBuf`] representing the fully qualified spool file path.
pub fn spool_q_fname(
    spool_directory: &str,
    purpose: &str,
    queue: &str,
    subdir: &str,
    fname: &str,
    suffix: &str,
) -> PathBuf {
    PathBuf::from(format!(
        "{}/{}/{}/{}/{}{}",
        spool_directory, queue, purpose, subdir, fname, suffix
    ))
}

/// Construct a queue-specific spool subdirectory name **without** the
/// `spool_directory` prefix.
///
/// The result is a relative path fragment suitable for logging or for
/// appending to a spool directory base path. When `queue` is empty the
/// leading `queue/` component is omitted; when `subdir` is empty the
/// trailing `/subdir` component is omitted.
///
/// Equivalent C function at `src/src/functions.h` lines 1194–1201:
/// ```c
/// string_sprintf("%s%s%s%s%s",
///     q, *q ? "/" : "",
///     purpose,
///     *subdir ? "/" : "", subdir);
/// ```
///
/// # Examples
///
/// ```
/// use exim_spool::format::spool_q_sname;
///
/// assert_eq!(spool_q_sname("input", "q1", "a"), "q1/input/a");
/// assert_eq!(spool_q_sname("input", "", "a"), "input/a");
/// assert_eq!(spool_q_sname("input", "q1", ""), "q1/input");
/// assert_eq!(spool_q_sname("input", "", ""), "input");
/// ```
pub fn spool_q_sname(purpose: &str, queue: &str, subdir: &str) -> String {
    let mut result = String::with_capacity(queue.len() + 1 + purpose.len() + 1 + subdir.len());

    if !queue.is_empty() {
        result.push_str(queue);
        result.push('/');
    }

    result.push_str(purpose);

    if !subdir.is_empty() {
        result.push('/');
        result.push_str(subdir);
    }

    result
}

/// Compute the spool subdirectory character for a given message ID.
///
/// When Exim is configured with `split_spool_directory`, the input directory
/// is split into 62 single-character subdirectories (one per base-62 digit).
/// The subdirectory is derived from the last character of the time component
/// of the message ID (position `MESSAGE_ID_TIME_LEN - 1`, i.e., index 5).
///
/// The `search_sequence` parameter controls the search order:
/// - On the **first** search attempt (`search_sequence == 0`), if
///   `split_spool_directory` is `true`, the subdirectory character is used;
///   otherwise the root directory (empty string) is tried.
/// - On the **second** attempt (`search_sequence == 1`), the opposite
///   strategy is tried: if `split_spool_directory` is `true`, the root
///   directory is tried; if `false`, the subdirectory character is used.
///
/// This dual-pass strategy allows Exim to find messages even when the
/// `split_spool_directory` setting has been toggled since the message was
/// enqueued.
///
/// Equivalent C implementation at `src/src/functions.h` lines 1233–1240:
/// ```c
/// subdir_str[0] = split_spool_directory == (search_sequence == 0)
///        ? name[MESSAGE_ID_TIME_LEN-1] : '\0';
/// subdir_str[1] = '\0';
/// ```
///
/// # Arguments
///
/// * `name` — The message ID string (must be at least `MESSAGE_ID_TIME_LEN`
///   bytes long).
/// * `search_sequence` — Search attempt number (0 for first, 1 for second).
/// * `split_spool_directory` — Whether the spool directory is currently
///   configured as split.
///
/// # Returns
///
/// A [`String`] containing a single character (the subdirectory name) or an
/// empty string (indicating the root input directory).
pub fn set_subdir_str(name: &str, search_sequence: usize, split_spool_directory: bool) -> String {
    // Replicate the C logic exactly:
    //   split_spool_directory == (search_sequence == 0)
    // In C, (search_sequence == 0) yields 1 (true) or 0 (false), and the
    // comparison with split_spool_directory (also 0 or 1) determines whether
    // to use the subdirectory character.
    let use_subdir = split_spool_directory == (search_sequence == 0);

    if use_subdir {
        // Extract the character at position MESSAGE_ID_TIME_LEN - 1 (index 5).
        // If the name is too short, fall back to empty string.
        match name.as_bytes().get(MESSAGE_ID_TIME_LEN - 1) {
            Some(&ch) if ch != 0 => {
                let mut s = String::with_capacity(1);
                s.push(ch as char);
                s
            }
            _ => String::new(),
        }
    } else {
        String::new()
    }
}

/// Compute the data start offset for a spool -D file based on message ID
/// format.
///
/// New-format message IDs (23 characters) have a 26-byte data start offset;
/// old-format message IDs (16 characters) have a 19-byte data start offset.
/// The offset accounts for the message ID, a `-D` suffix, and a newline at
/// the beginning of the -D file.
///
/// Source: `src/src/functions.h` lines 1257–1262.
///
/// # Arguments
///
/// * `id` — The message ID string.
///
/// # Returns
///
/// The byte offset from the start of the -D file to the beginning of the
/// actual message data.
pub fn spool_data_start_offset(id: &str) -> usize {
    if is_old_message_id(id) {
        SPOOL_DATA_START_OFFSET_OLD
    } else {
        SPOOL_DATA_START_OFFSET
    }
}

// =============================================================================
// String Helper Functions
// =============================================================================

/// Replace all newline characters (`\n`) with spaces in a string.
///
/// This function is used when writing spool header values that must be
/// single-line. If the input contains no newlines, the original string
/// reference is returned without allocation (via [`Cow::Borrowed`]).
///
/// Equivalent C function at `src/src/spool_out.c` lines 109–119:
/// ```c
/// static const uschar *
/// zap_newlines(const uschar *s) {
///     if (Ustrchr(s, '\n') == NULL) return s;
///     p = z = string_copy(s);
///     while ((p = Ustrchr(p, '\n')) != NULL) *p++ = ' ';
///     return z;
/// }
/// ```
///
/// # Arguments
///
/// * `s` — The input string that may contain newlines.
///
/// # Returns
///
/// A [`Cow<str>`] that borrows the original string when no newlines are
/// present, or owns a new string with newlines replaced by spaces.
pub fn zap_newlines(s: &str) -> Cow<'_, str> {
    if !s.contains('\n') {
        Cow::Borrowed(s)
    } else {
        Cow::Owned(s.replace('\n', " "))
    }
}

/// Write a spool variable in the taint-aware format used by Exim spool
/// header files.
///
/// The output format depends on the taint status of the value:
///
/// | Taint status        | Output format                    |
/// |---------------------|----------------------------------|
/// | Untainted           | `-{name} {value}\n`              |
/// | Tainted, no quoter  | `--{name} {value}\n`             |
/// | Tainted, with quoter| `--({quoter_name}){name} {value}\n` |
///
/// This matches the C function `spool_var_write()` at `src/src/spool_out.c`
/// lines 121–134:
/// ```c
/// putc('-', fp);
/// if (is_tainted(val)) {
///     putc('-', fp);
///     (void) quoter_for_address(val, &quoter_name);
///     if (quoter_name) fprintf(fp, "(%s)", quoter_name);
/// }
/// fprintf(fp, "%s %s\n", name, val);
/// ```
///
/// # Arguments
///
/// * `writer` — Destination implementing [`std::io::Write`].
/// * `name` — Spool variable name (e.g., `"host_name"`, `"sender_address"`).
/// * `value` — Variable value to serialize.
/// * `is_tainted` — Whether the value is tainted (originated from external
///   input).
/// * `quoter_name` — Optional quoter/lookup type name for tainted values
///   (e.g., `"sql"`, `"ldap"`). Only written when the value is tainted.
///
/// # Errors
///
/// Returns [`io::Error`] if any write to the underlying writer fails.
pub fn spool_var_write<W: Write>(
    writer: &mut W,
    name: &str,
    value: &str,
    is_tainted: bool,
    quoter_name: Option<&str>,
) -> io::Result<()> {
    // Leading dash — always present.
    writer.write_all(b"-")?;

    // If tainted, write a second dash and optional quoter name.
    if is_tainted {
        writer.write_all(b"-")?;
        if let Some(qname) = quoter_name {
            write!(writer, "({})", qname)?;
        }
    }

    // Variable name, space, value, newline.
    writeln!(writer, "{} {}", name, value)
}

// =============================================================================
// Message ID Format Detection
// =============================================================================

/// Check whether a message ID is in the **new** (current) format.
///
/// New-format IDs have a dash (`-`) at position
/// `MESSAGE_ID_TIME_LEN + 1 + MESSAGE_ID_PID_LEN` (= 18), which separates
/// the 11-character PID component from the 4-character sub-second component.
///
/// Source: `src/src/functions.h` lines 1245–1249:
/// ```c
/// static inline BOOL
/// is_new_message_id(const uschar * id) {
///     return id[MESSAGE_ID_TIME_LEN + 1 + MESSAGE_ID_PID_LEN] == '-';
/// }
/// ```
///
/// # Arguments
///
/// * `id` — The message ID string to inspect.
///
/// # Returns
///
/// `true` if the byte at position 18 is `b'-'`, indicating a new-format ID.
/// Returns `false` if the string is too short or the byte is not `b'-'`.
pub fn is_new_message_id(id: &str) -> bool {
    id.as_bytes()
        .get(MESSAGE_ID_TIME_LEN + 1 + MESSAGE_ID_PID_LEN)
        == Some(&b'-')
}

/// Check whether a message ID is in the **old** (legacy) format.
///
/// Old-format IDs have a dash (`-`) at position
/// `MESSAGE_ID_TIME_LEN + 1 + MESSAGE_ID_PID_LEN_OLD` (= 13), which
/// separates the 6-character PID component from the 2-character sub-second
/// component.
///
/// Source: `src/src/functions.h` lines 1251–1255:
/// ```c
/// static inline BOOL
/// is_old_message_id(const uschar * id) {
///     return id[MESSAGE_ID_TIME_LEN + 1 + MESSAGE_ID_PID_LEN_OLD] == '-';
/// }
/// ```
///
/// # Arguments
///
/// * `id` — The message ID string to inspect.
///
/// # Returns
///
/// `true` if the byte at position 13 is `b'-'`, indicating an old-format ID.
/// Returns `false` if the string is too short or the byte is not `b'-'`.
pub fn is_old_message_id(id: &str) -> bool {
    id.as_bytes()
        .get(MESSAGE_ID_TIME_LEN + 1 + MESSAGE_ID_PID_LEN_OLD)
        == Some(&b'-')
}

// =============================================================================
// Compile-time assertions
// =============================================================================
//
// These const assertions verify that the computed constants match the expected
// values from the C source. If any assertion fails, compilation will fail with
// a clear error.

const _: () = assert!(MESSAGE_ID_LENGTH == 23, "MESSAGE_ID_LENGTH must be 23");
const _: () = assert!(
    MESSAGE_ID_LENGTH_OLD == 16,
    "MESSAGE_ID_LENGTH_OLD must be 16"
);
const _: () = assert!(
    SPOOL_DATA_START_OFFSET == 26,
    "SPOOL_DATA_START_OFFSET must be 26"
);
const _: () = assert!(
    SPOOL_DATA_START_OFFSET_OLD == 19,
    "SPOOL_DATA_START_OFFSET_OLD must be 19"
);
const _: () = assert!(SPOOL_NAME_LENGTH == 25, "SPOOL_NAME_LENGTH must be 25");
const _: () = assert!(SPOOL_MODE == 0o640, "SPOOL_MODE must be 0o640");
const _: () = assert!(
    INPUT_DIRECTORY_MODE == 0o750,
    "INPUT_DIRECTORY_MODE must be 0o750"
);

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Constant value tests
    // =========================================================================

    #[test]
    fn test_message_id_time_len() {
        assert_eq!(MESSAGE_ID_TIME_LEN, 6);
    }

    #[test]
    fn test_message_id_pid_len() {
        assert_eq!(MESSAGE_ID_PID_LEN, 11);
    }

    #[test]
    fn test_message_id_pid_len_old() {
        assert_eq!(MESSAGE_ID_PID_LEN_OLD, 6);
    }

    #[test]
    fn test_message_id_subtime_len() {
        assert_eq!(MESSAGE_ID_SUBTIME_LEN, 4);
    }

    #[test]
    fn test_message_id_subtime_len_old() {
        assert_eq!(MESSAGE_ID_SUBTIME_LEN_OLD, 2);
    }

    #[test]
    fn test_message_id_length() {
        // TTTTTT-PPPPPPPPPPP-SSSS = 6+1+11+1+4 = 23
        assert_eq!(MESSAGE_ID_LENGTH, 23);
    }

    #[test]
    fn test_message_id_length_old() {
        // TTTTTT-PPPPPP-SS = 6+1+6+1+2 = 16
        assert_eq!(MESSAGE_ID_LENGTH_OLD, 16);
    }

    #[test]
    fn test_spool_data_start_offset() {
        assert_eq!(SPOOL_DATA_START_OFFSET, 26);
    }

    #[test]
    fn test_spool_data_start_offset_old() {
        assert_eq!(SPOOL_DATA_START_OFFSET_OLD, 19);
    }

    #[test]
    fn test_spool_name_length() {
        assert_eq!(SPOOL_NAME_LENGTH, 25);
    }

    #[test]
    fn test_spool_mode() {
        assert_eq!(SPOOL_MODE, 0o640);
    }

    #[test]
    fn test_input_directory_mode() {
        assert_eq!(INPUT_DIRECTORY_MODE, 0o750);
    }

    // =========================================================================
    // Enum discriminant tests
    // =========================================================================

    #[test]
    fn test_spool_read_result_discriminants() {
        assert_eq!(SpoolReadResult::OK as u32, 0);
        assert_eq!(SpoolReadResult::NotOpen as u32, 1);
        assert_eq!(SpoolReadResult::EnvError as u32, 2);
        assert_eq!(SpoolReadResult::HdrError as u32, 3);
    }

    #[test]
    fn test_spool_write_context_discriminants() {
        assert_eq!(SpoolWriteContext::Receiving as u32, 0);
        assert_eq!(SpoolWriteContext::Delivering as u32, 1);
        assert_eq!(SpoolWriteContext::Modifying as u32, 2);
    }

    #[test]
    fn test_spool_read_result_equality() {
        assert_eq!(SpoolReadResult::OK, SpoolReadResult::OK);
        assert_ne!(SpoolReadResult::OK, SpoolReadResult::NotOpen);
    }

    #[test]
    fn test_spool_write_context_equality() {
        assert_eq!(SpoolWriteContext::Receiving, SpoolWriteContext::Receiving);
        assert_ne!(SpoolWriteContext::Receiving, SpoolWriteContext::Delivering);
    }

    #[test]
    fn test_spool_read_result_debug() {
        assert_eq!(format!("{:?}", SpoolReadResult::OK), "OK");
        assert_eq!(format!("{:?}", SpoolReadResult::NotOpen), "NotOpen");
        assert_eq!(format!("{:?}", SpoolReadResult::EnvError), "EnvError");
        assert_eq!(format!("{:?}", SpoolReadResult::HdrError), "HdrError");
    }

    #[test]
    fn test_spool_write_context_debug() {
        assert_eq!(format!("{:?}", SpoolWriteContext::Receiving), "Receiving");
        assert_eq!(format!("{:?}", SpoolWriteContext::Delivering), "Delivering");
        assert_eq!(format!("{:?}", SpoolWriteContext::Modifying), "Modifying");
    }

    #[test]
    // This test intentionally invokes `.clone()` on a Copy type to verify the
    // `Clone` trait is implemented (in addition to `Copy`). The clippy
    // `clone_on_copy` lint is suppressed because the redundancy is the point
    // of the test.
    #[allow(clippy::clone_on_copy)]
    fn test_spool_read_result_clone_copy() {
        let a = SpoolReadResult::EnvError;
        let b = a; // Copy
        let c = a.clone(); // Clone
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    // Same rationale as test_spool_read_result_clone_copy: verify that both
    // Copy and Clone are implemented. The explicit `.clone()` call exercises
    // the Clone impl independently of the implicit Copy semantics.
    #[allow(clippy::clone_on_copy)]
    fn test_spool_write_context_clone_copy() {
        let a = SpoolWriteContext::Modifying;
        let b = a; // Copy
        let c = a.clone(); // Clone
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    // =========================================================================
    // spool_fname tests
    // =========================================================================

    #[test]
    fn test_spool_fname_full_path() {
        let path = spool_fname(
            "/var/spool/exim",
            "queue1",
            "input",
            "a",
            "1pBCDE-00000000Ab-1234",
            "-H",
        );
        assert_eq!(
            path,
            PathBuf::from("/var/spool/exim/queue1/input/a/1pBCDE-00000000Ab-1234-H")
        );
    }

    #[test]
    fn test_spool_fname_empty_queue() {
        let path = spool_fname(
            "/var/spool/exim",
            "",
            "input",
            "a",
            "1pBCDE-00000000Ab-1234",
            "-D",
        );
        // Empty queue produces double-slash, matching C behavior
        assert_eq!(
            path,
            PathBuf::from("/var/spool/exim//input/a/1pBCDE-00000000Ab-1234-D")
        );
    }

    #[test]
    fn test_spool_fname_empty_subdir() {
        let path = spool_fname(
            "/var/spool/exim",
            "q1",
            "input",
            "",
            "1pBCDE-00000000Ab-1234",
            "-H",
        );
        assert_eq!(
            path,
            PathBuf::from("/var/spool/exim/q1/input//1pBCDE-00000000Ab-1234-H")
        );
    }

    #[test]
    fn test_spool_fname_empty_suffix() {
        let path = spool_fname(
            "/var/spool/exim",
            "",
            "msglog",
            "",
            "1pBCDE-00000000Ab-1234",
            "",
        );
        assert_eq!(
            path,
            PathBuf::from("/var/spool/exim//msglog//1pBCDE-00000000Ab-1234")
        );
    }

    #[test]
    fn test_spool_fname_all_empty() {
        let path = spool_fname("", "", "", "", "", "");
        assert_eq!(path, PathBuf::from("////"));
    }

    // =========================================================================
    // spool_q_fname tests
    // =========================================================================

    #[test]
    fn test_spool_q_fname_full_path() {
        let path = spool_q_fname(
            "/var/spool/exim",
            "input",
            "myqueue",
            "b",
            "1pBCDE-00000000Ab-5678",
            "-H",
        );
        assert_eq!(
            path,
            PathBuf::from("/var/spool/exim/myqueue/input/b/1pBCDE-00000000Ab-5678-H")
        );
    }

    #[test]
    fn test_spool_q_fname_empty_queue() {
        let path = spool_q_fname(
            "/var/spool/exim",
            "input",
            "",
            "a",
            "1pBCDE-00000000Ab-5678",
            "-D",
        );
        assert_eq!(
            path,
            PathBuf::from("/var/spool/exim//input/a/1pBCDE-00000000Ab-5678-D")
        );
    }

    // =========================================================================
    // spool_q_sname tests
    // =========================================================================

    #[test]
    fn test_spool_q_sname_with_queue_and_subdir() {
        assert_eq!(spool_q_sname("input", "q1", "a"), "q1/input/a");
    }

    #[test]
    fn test_spool_q_sname_empty_queue() {
        assert_eq!(spool_q_sname("input", "", "a"), "input/a");
    }

    #[test]
    fn test_spool_q_sname_empty_subdir() {
        assert_eq!(spool_q_sname("input", "q1", ""), "q1/input");
    }

    #[test]
    fn test_spool_q_sname_both_empty() {
        assert_eq!(spool_q_sname("input", "", ""), "input");
    }

    #[test]
    fn test_spool_q_sname_msglog() {
        assert_eq!(spool_q_sname("msglog", "backup", "z"), "backup/msglog/z");
    }

    // =========================================================================
    // set_subdir_str tests
    // =========================================================================

    #[test]
    fn test_set_subdir_str_split_true_seq_0() {
        // split_spool_directory=true, search_sequence=0 => true == true => use char
        // Message ID "AbCdEf-...", index 5 = 'f'
        let result = set_subdir_str("AbCdEf-00000000Ab-1234", 0, true);
        assert_eq!(result, "f");
    }

    #[test]
    fn test_set_subdir_str_split_true_seq_1() {
        // split_spool_directory=true, search_sequence=1 => true == false => empty
        let result = set_subdir_str("AbCdEf-00000000Ab-1234", 1, true);
        assert_eq!(result, "");
    }

    #[test]
    fn test_set_subdir_str_split_false_seq_0() {
        // split_spool_directory=false, search_sequence=0 => false == true => empty
        let result = set_subdir_str("AbCdEf-00000000Ab-1234", 0, false);
        assert_eq!(result, "");
    }

    #[test]
    fn test_set_subdir_str_split_false_seq_1() {
        // split_spool_directory=false, search_sequence=1 => false == false => use char
        let result = set_subdir_str("AbCdEf-00000000Ab-1234", 1, false);
        assert_eq!(result, "f");
    }

    #[test]
    fn test_set_subdir_str_short_name() {
        // Name shorter than MESSAGE_ID_TIME_LEN — should return empty
        let result = set_subdir_str("Ab", 0, true);
        assert_eq!(result, "");
    }

    #[test]
    fn test_set_subdir_str_empty_name() {
        let result = set_subdir_str("", 0, true);
        assert_eq!(result, "");
    }

    #[test]
    fn test_set_subdir_str_extracts_correct_position() {
        // Position MESSAGE_ID_TIME_LEN - 1 = 5
        // "012345..." => character at index 5 is '5'
        let result = set_subdir_str("012345-rest", 0, true);
        assert_eq!(result, "5");
    }

    // =========================================================================
    // spool_data_start_offset (function) tests
    // =========================================================================

    #[test]
    fn test_spool_data_start_offset_new_format() {
        // New format: TTTTTT-PPPPPPPPPPP-SSSS (23 chars, dash at position 18)
        let id = "1pBCDE-00000000Ab-1234";
        assert_eq!(spool_data_start_offset(id), 26);
    }

    #[test]
    fn test_spool_data_start_offset_old_format() {
        // Old format: TTTTTT-PPPPPP-SS (16 chars, dash at position 13)
        let id = "1pBCDE-AbCdEf-12";
        assert_eq!(spool_data_start_offset(id), 19);
    }

    #[test]
    fn test_spool_data_start_offset_empty_string() {
        // Empty string — not old format, defaults to new format offset
        assert_eq!(spool_data_start_offset(""), 26);
    }

    #[test]
    fn test_spool_data_start_offset_short_string() {
        // Too short for either format — defaults to new format offset
        assert_eq!(spool_data_start_offset("abc"), 26);
    }

    // =========================================================================
    // zap_newlines tests
    // =========================================================================

    #[test]
    fn test_zap_newlines_no_newlines() {
        let result = zap_newlines("hello world");
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(result.as_ref(), "hello world");
    }

    #[test]
    fn test_zap_newlines_with_newlines() {
        let result = zap_newlines("hello\nworld\nfoo");
        assert!(matches!(result, Cow::Owned(_)));
        assert_eq!(result.as_ref(), "hello world foo");
    }

    #[test]
    fn test_zap_newlines_only_newlines() {
        let result = zap_newlines("\n\n\n");
        assert_eq!(result.as_ref(), "   ");
    }

    #[test]
    fn test_zap_newlines_empty_string() {
        let result = zap_newlines("");
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(result.as_ref(), "");
    }

    #[test]
    fn test_zap_newlines_trailing_newline() {
        let result = zap_newlines("hello\n");
        assert_eq!(result.as_ref(), "hello ");
    }

    #[test]
    fn test_zap_newlines_leading_newline() {
        let result = zap_newlines("\nhello");
        assert_eq!(result.as_ref(), " hello");
    }

    // =========================================================================
    // spool_var_write tests
    // =========================================================================

    #[test]
    fn test_spool_var_write_untainted() {
        let mut buf = Vec::new();
        spool_var_write(&mut buf, "host_name", "mail.example.com", false, None)
            .expect("write should succeed");
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "-host_name mail.example.com\n"
        );
    }

    #[test]
    fn test_spool_var_write_tainted_no_quoter() {
        let mut buf = Vec::new();
        spool_var_write(&mut buf, "sender_address", "user@evil.com", true, None)
            .expect("write should succeed");
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "--sender_address user@evil.com\n"
        );
    }

    #[test]
    fn test_spool_var_write_tainted_with_quoter() {
        let mut buf = Vec::new();
        spool_var_write(&mut buf, "local_part", "injected", true, Some("sql"))
            .expect("write should succeed");
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "--(sql)local_part injected\n"
        );
    }

    #[test]
    fn test_spool_var_write_untainted_ignores_quoter() {
        // When not tainted, quoter_name should be ignored
        let mut buf = Vec::new();
        spool_var_write(&mut buf, "domain", "example.com", false, Some("ldap"))
            .expect("write should succeed");
        assert_eq!(String::from_utf8(buf).unwrap(), "-domain example.com\n");
    }

    #[test]
    fn test_spool_var_write_empty_value() {
        let mut buf = Vec::new();
        spool_var_write(&mut buf, "local_part", "", false, None).expect("write should succeed");
        assert_eq!(String::from_utf8(buf).unwrap(), "-local_part \n");
    }

    #[test]
    fn test_spool_var_write_tainted_empty_quoter_string() {
        // quoter_name is Some("") — still writes the parentheses
        let mut buf = Vec::new();
        spool_var_write(&mut buf, "name", "val", true, Some("")).expect("write should succeed");
        assert_eq!(String::from_utf8(buf).unwrap(), "--()name val\n");
    }

    // =========================================================================
    // is_new_message_id tests
    // =========================================================================

    #[test]
    fn test_is_new_message_id_valid() {
        // Position 18 should be '-': TTTTTT-PPPPPPPPPPP-SSSS
        // 012345678901234567890123
        // AbCdEf-0123456789A-BcDe
        assert!(is_new_message_id("AbCdEf-0123456789A-BcDe"));
    }

    #[test]
    fn test_is_new_message_id_old_format() {
        // Old format: TTTTTT-PPPPPP-SS (16 chars)
        // Position 18 does not exist
        assert!(!is_new_message_id("AbCdEf-012345-AB"));
    }

    #[test]
    fn test_is_new_message_id_too_short() {
        assert!(!is_new_message_id("short"));
    }

    #[test]
    fn test_is_new_message_id_empty() {
        assert!(!is_new_message_id(""));
    }

    #[test]
    fn test_is_new_message_id_no_dash_at_18() {
        // 19 chars but no dash at position 18
        assert!(!is_new_message_id("AbCdEf-0123456789AxBcDe"));
    }

    // =========================================================================
    // is_old_message_id tests
    // =========================================================================

    #[test]
    fn test_is_old_message_id_valid() {
        // Position 13 should be '-': TTTTTT-PPPPPP-SS
        // 0123456789012345
        // AbCdEf-012345-AB
        assert!(is_old_message_id("AbCdEf-012345-AB"));
    }

    #[test]
    fn test_is_old_message_id_new_format() {
        // New format: TTTTTT-PPPPPPPPPPP-SSSS
        // Position 13 is a PID character (not '-')
        assert!(!is_old_message_id("AbCdEf-0123456789A-BcDe"));
    }

    #[test]
    fn test_is_old_message_id_too_short() {
        assert!(!is_old_message_id("short"));
    }

    #[test]
    fn test_is_old_message_id_empty() {
        assert!(!is_old_message_id(""));
    }

    #[test]
    fn test_is_old_message_id_no_dash_at_13() {
        // 14+ chars but no dash at position 13
        assert!(!is_old_message_id("AbCdEf-012345xAB"));
    }
}
