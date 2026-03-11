// =============================================================================
// exim-miscmods/src/dscp.rs — DSCP Traffic Marking Module
// =============================================================================
//
// Replaces `src/src/miscmods/dscp.c` (278 lines).
//
// Provides DSCP (Differentiated Services Code Point) traffic marking support
// for the Exim MTA. This module allows inbound ACL and outbound transport
// DSCP tagging via `setsockopt()` with `IP_TOS` (IPv4) and `IPV6_TCLASS`
// (IPv6).
//
// Feature-gated behind `#[cfg(feature = "dscp")]` at the module declaration
// in `lib.rs`. The C preprocessor guard `#ifdef SUPPORT_DSCP` is replaced
// by the Cargo feature `dscp` per AAP §0.7.3.
//
// ## Safety
//
// This module contains ZERO `unsafe` code per AAP §0.7.2. All socket
// operations use the `nix` crate's safe wrappers (`getsockname`,
// `setsockopt`) instead of raw `libc` calls.
//
// ## C Source Correspondence
//
// | C Function / Entity        | Rust Replacement                         |
// |-----------------------------|------------------------------------------|
// | `ip_get_address_family(fd)` | `get_address_family(fd)`                 |
// | `dscp_lookup(name,af,...)`  | `dscp_lookup(name)` → `Result<i32,...>`  |
// | `dscp_acl(control, opt)`    | `dscp_set(fd, name)` (caller handles ACL)|
// | `dscp_transport(sock,...)`  | `dscp_set(fd, name)` (caller handles tx) |
// | `dscp_keywords(stream)`     | `dscp_keywords()` → `Vec<&'static str>`  |
// | `dscp_module_info`          | `inventory::submit!(DriverInfoBase{...})` |
// | `dscp_table[]`              | `DSCP_TABLE` static slice                |

//! DSCP (Differentiated Services Code Point) traffic marking module.
//!
//! Provides DSCP tagging for inbound ACL and outbound transport sockets via
//! `setsockopt()` with `IP_TOS` (IPv4) and `IPV6_TCLASS` (IPv6). Replaces
//! the C `dscp.c` module (278 lines) with zero `unsafe` code.
//!
//! # Usage
//!
//! ```ignore
//! use std::os::fd::BorrowedFd;
//! use exim_miscmods::dscp::{dscp_set, dscp_lookup, dscp_keywords};
//!
//! // Look up a DSCP keyword to get the TOS byte value
//! let tos_value = dscp_lookup("ef").unwrap(); // returns 0xB8 (184)
//!
//! // Set DSCP on a socket
//! let fd: BorrowedFd<'_> = /* ... */;
//! dscp_set(fd, "ef").unwrap();
//!
//! // Get all valid DSCP keywords
//! let keywords = dscp_keywords();
//! ```
//!
//! # DSCP Keywords
//!
//! The keyword table matches the C source exactly. Supported keywords
//! (case-insensitive):
//!
//! - **Assured Forwarding**: `af11` through `af43` (12 keywords)
//! - **Expedited Forwarding**: `ef`
//! - **Legacy TOS**: `lowcost`, `lowdelay`, `mincost`, `reliability`, `throughput`
//!
//! Numeric values 0–63 are also accepted and are shifted left by 2 to produce
//! the TOS byte value (matching the C behavior from `dscp.c` lines 142–154).

use std::os::fd::{AsRawFd, BorrowedFd};

use exim_drivers::DriverInfoBase;
use nix::sys::socket::{
    getsockname, setsockopt,
    sockopt::{Ipv4Tos, Ipv6TClass},
    AddressFamily, SockaddrLike, SockaddrStorage,
};
use thiserror::Error;
use tracing::{debug, warn};

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during DSCP operations.
///
/// Replaces the C pattern of returning `FALSE` from `dscp_lookup()` or an
/// error string from `dscp_acl()`. Each variant corresponds to a specific
/// failure mode from the original C code:
///
/// - `InvalidKeyword` — C: binary search falls off the end of `dscp_table[]`
/// - `SocketError`    — C: `getsockname()` or `setsockopt()` returns -1
/// - `NotASocket`     — C: `ip_get_address_family()` returns -1 with `ENOTSOCK`
/// - `UnsupportedAddressFamily` — C: unhandled AF in `dscp_lookup()`
/// - `EmptyValue`     — C: null/empty `dscp_name` check
/// - `ValueOutOfRange` — C: numeric value outside 0..=0x3F range
#[derive(Debug, Error)]
pub enum DscpError {
    /// The provided string is not a recognized DSCP keyword.
    /// C equivalent: binary search of `dscp_table[]` finds no match.
    #[error("invalid DSCP keyword: {0}")]
    InvalidKeyword(String),

    /// A socket system call (`getsockname` or `setsockopt`) failed.
    /// C equivalent: `getsockname()` or `setsockopt()` returns -1 with errno.
    #[error("socket error: {0}")]
    SocketError(nix::Error),

    /// The file descriptor is not a socket.
    /// C equivalent: `ip_get_address_family()` returns -1.
    #[error("file descriptor is not a socket")]
    NotASocket,

    /// The socket uses an address family that is not IPv4 or IPv6.
    /// C equivalent: unhandled AF branch in `dscp_lookup()` (dscp.c line 120–125).
    #[error("unsupported address family: {0}")]
    UnsupportedAddressFamily(i32),

    /// The DSCP value string was empty or blank after trimming.
    /// C equivalent: null or empty `dscp_name` check (dscp.c lines 126–140).
    #[error("empty DSCP value")]
    EmptyValue,

    /// A numeric DSCP value was outside the valid 0–63 range.
    /// C equivalent: `rawlong < 0 || rawlong > 0x3F` check (dscp.c line 147).
    #[error("DSCP value {0} out of range (must be 0-63)")]
    ValueOutOfRange(i64),
}

// =============================================================================
// DscpConfig
// =============================================================================

/// Resolved DSCP configuration for a socket, combining the TOS byte value
/// with the address family determination.
///
/// This struct is returned internally when a DSCP keyword or numeric value has
/// been resolved in the context of a specific socket's address family. The
/// `is_ipv6` field determines which socket option to use:
///
/// - `is_ipv6 == false` → `setsockopt(IPPROTO_IP, IP_TOS, value)`
/// - `is_ipv6 == true`  → `setsockopt(IPPROTO_IPV6, IPV6_TCLASS, value)`
///
/// For dual-stack IPv6 sockets, both options are set (matching the C behavior
/// from `dscp_transport()` at dscp.c lines 241–244).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DscpConfig {
    /// The TOS/TCLASS byte value to set on the socket.
    ///
    /// For keyword lookups, this is the pre-shifted value from the keyword table
    /// (e.g., `0xB8` for "ef"). For numeric inputs, the 6-bit DSCP value is
    /// shifted left by 2 to produce the TOS byte (e.g., input `46` → `0xB8`).
    pub value: i32,

    /// Whether this configuration targets an IPv6 socket.
    ///
    /// When `true`, `IPV6_TCLASS` is used as the primary socket option, and
    /// `IP_TOS` is also set for dual-stack compatibility.
    pub is_ipv6: bool,
}

// =============================================================================
// DSCP Keyword Table
// =============================================================================
//
// This table is an exact replica of the C `dscp_table[]` array from dscp.c
// lines 58–83. The entries MUST remain sorted alphabetically by name to match
// the C binary search behavior, though the Rust implementation uses linear
// search with case-insensitive comparison.
//
// Each value is the TOS byte value (already shifted for DSCP classes).
// For DSCP Assured Forwarding classes, the formula is:
//   TOS = (class * 8 + drop_precedence * 2) << 2
//
// For legacy IP TOS values, the constants are defined in <netinet/ip.h>:
//   IPTOS_LOWDELAY    = 0x10
//   IPTOS_THROUGHPUT  = 0x08
//   IPTOS_RELIABILITY = 0x04
//   IPTOS_MINCOST     = 0x02 (alias: IPTOS_LOWCOST)
//
// C preprocessor conditionals (#ifdef IPTOS_DSCP_AF11, etc.) are removed
// because these constants are universally defined on Linux. The Rust module
// uses literal values to avoid dependence on C header macros.

/// A single entry in the DSCP keyword-to-value mapping table.
struct DscpKeywordEntry {
    /// Lowercase keyword name (e.g., "ef", "af11", "lowdelay").
    name: &'static str,
    /// TOS byte value (pre-shifted for DSCP classes, raw for legacy TOS).
    value: i32,
}

/// Static DSCP keyword table, sorted alphabetically by name.
///
/// Reproduces the C `dscp_table[]` from dscp.c lines 58–83. All entries from
/// the C source are included unconditionally (the C `#ifdef IPTOS_DSCP_AF11`,
/// `#ifdef IPTOS_LOWCOST`, and `#ifdef IPTOS_MINCOST` guards are always true
/// on modern Linux).
static DSCP_TABLE: &[DscpKeywordEntry] = &[
    // Assured Forwarding — RFC 2597
    // Class 1: low drop (AF11), medium drop (AF12), high drop (AF13)
    DscpKeywordEntry {
        name: "af11",
        value: 0x28,
    }, // DSCP 10 → TOS 0x28 (40)
    DscpKeywordEntry {
        name: "af12",
        value: 0x30,
    }, // DSCP 12 → TOS 0x30 (48)
    DscpKeywordEntry {
        name: "af13",
        value: 0x38,
    }, // DSCP 14 → TOS 0x38 (56)
    // Class 2
    DscpKeywordEntry {
        name: "af21",
        value: 0x48,
    }, // DSCP 18 → TOS 0x48 (72)
    DscpKeywordEntry {
        name: "af22",
        value: 0x50,
    }, // DSCP 20 → TOS 0x50 (80)
    DscpKeywordEntry {
        name: "af23",
        value: 0x58,
    }, // DSCP 22 → TOS 0x58 (88)
    // Class 3
    DscpKeywordEntry {
        name: "af31",
        value: 0x68,
    }, // DSCP 26 → TOS 0x68 (104)
    DscpKeywordEntry {
        name: "af32",
        value: 0x70,
    }, // DSCP 28 → TOS 0x70 (112)
    DscpKeywordEntry {
        name: "af33",
        value: 0x78,
    }, // DSCP 30 → TOS 0x78 (120)
    // Class 4
    DscpKeywordEntry {
        name: "af41",
        value: 0x88,
    }, // DSCP 34 → TOS 0x88 (136)
    DscpKeywordEntry {
        name: "af42",
        value: 0x90,
    }, // DSCP 36 → TOS 0x90 (144)
    DscpKeywordEntry {
        name: "af43",
        value: 0x98,
    }, // DSCP 38 → TOS 0x98 (152)
    // Expedited Forwarding — RFC 3246
    DscpKeywordEntry {
        name: "ef",
        value: 0xB8,
    }, // DSCP 46 → TOS 0xB8 (184)
    // Legacy IP TOS values — RFC 1349 / <netinet/ip.h>
    DscpKeywordEntry {
        name: "lowcost",
        value: 0x02,
    }, // IPTOS_LOWCOST (= IPTOS_MINCOST)
    DscpKeywordEntry {
        name: "lowdelay",
        value: 0x10,
    }, // IPTOS_LOWDELAY
    DscpKeywordEntry {
        name: "mincost",
        value: 0x02,
    }, // IPTOS_MINCOST
    DscpKeywordEntry {
        name: "reliability",
        value: 0x04,
    }, // IPTOS_RELIABILITY
    DscpKeywordEntry {
        name: "throughput",
        value: 0x08,
    }, // IPTOS_THROUGHPUT
];

// =============================================================================
// Internal Helper: Address Family Detection
// =============================================================================

/// Determines the address family (IPv4 or IPv6) of a socket.
///
/// Replaces C `ip_get_address_family(fd)` from dscp.c lines 35–45.
/// Uses `nix::sys::socket::getsockname()` to query the socket address
/// without any `unsafe` code.
///
/// # Arguments
///
/// * `fd` — A borrowed file descriptor referencing an open socket.
///
/// # Returns
///
/// * `Ok(AddressFamily)` — The socket's address family (`Inet` or `Inet6`).
/// * `Err(DscpError::SocketError)` — `getsockname()` failed (e.g., bad fd).
/// * `Err(DscpError::NotASocket)` — The fd has no identifiable address family.
fn get_address_family(fd: BorrowedFd<'_>) -> Result<AddressFamily, DscpError> {
    let addr: SockaddrStorage = getsockname(fd.as_raw_fd()).map_err(DscpError::SocketError)?;

    // SockaddrStorage::family() returns Option<AddressFamily>.
    // A connected socket should always have a valid family; None indicates
    // either AF_UNSPEC (0) or an unrecognizable family, both of which mean
    // the fd is not a usable socket for DSCP purposes.
    addr.family().ok_or(DscpError::NotASocket)
}

// =============================================================================
// Internal Helper: Keyword Table Lookup
// =============================================================================

/// Performs a case-insensitive lookup of a DSCP keyword in the static table.
///
/// Returns `Some(value)` if the keyword matches an entry, `None` otherwise.
/// The C version uses `Ustrcmp()` (case-sensitive binary search on a sorted
/// table). The Rust version uses case-insensitive linear search, which is
/// equally fast for 18 entries and more forgiving of user input.
fn keyword_lookup(keyword: &str) -> Option<i32> {
    let lower = keyword.to_ascii_lowercase();
    DSCP_TABLE
        .iter()
        .find(|entry| entry.name == lower)
        .map(|entry| entry.value)
}

// =============================================================================
// Public API: dscp_lookup
// =============================================================================

/// Resolves a DSCP keyword or numeric string to its TOS byte value.
///
/// Replaces the core logic of C `dscp_lookup()` from dscp.c lines 106–174.
/// The function accepts either:
///
/// 1. **A keyword** (case-insensitive): looked up in [`DSCP_TABLE`].
///    Returns the pre-shifted TOS byte value directly from the table.
///
/// 2. **A numeric value** (decimal, hex with `0x`, or octal with `0o`):
///    interpreted as a 6-bit DSCP field value (0–63). The value is shifted
///    left by 2 to produce the TOS byte, matching the C behavior:
///    ```c
///    *dscp_value = rawlong << 2;  // dscp.c line 153
///    ```
///
/// # Arguments
///
/// * `dscp_name` — A string containing a DSCP keyword (e.g., `"ef"`, `"af11"`,
///   `"lowdelay"`) or a numeric DSCP value (e.g., `"46"`, `"0x2E"`).
///   Leading and trailing whitespace is trimmed.
///
/// # Returns
///
/// * `Ok(i32)` — The TOS byte value ready for `setsockopt()`.
/// * `Err(DscpError::EmptyValue)` — The input was empty or all whitespace.
/// * `Err(DscpError::ValueOutOfRange)` — A numeric value was outside 0–63.
/// * `Err(DscpError::InvalidKeyword)` — Not a number and not a recognized keyword.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(dscp_lookup("ef").unwrap(), 0xB8);
/// assert_eq!(dscp_lookup("AF11").unwrap(), 0x28);
/// assert_eq!(dscp_lookup("46").unwrap(), 0xB8);  // 46 << 2 = 184 = 0xB8
/// assert_eq!(dscp_lookup("0").unwrap(), 0x00);
/// assert!(dscp_lookup("bogus").is_err());
/// assert!(dscp_lookup("64").is_err());            // out of range
/// ```
pub fn dscp_lookup(dscp_name: &str) -> Result<i32, DscpError> {
    let trimmed = dscp_name.trim();

    if trimmed.is_empty() {
        return Err(DscpError::EmptyValue);
    }

    // Attempt numeric parse first (C: Ustrtol with base 0 — supports decimal,
    // hex (0x), and octal (0) prefixes). We replicate this with Rust's integer
    // parsing, handling the 0x and 0o prefixes manually.
    if let Some(numeric_value) = parse_numeric(trimmed) {
        // C behavior: six bits available, values 0–0x3F, shifted left by 2.
        // dscp.c lines 147–154.
        if !(0..=0x3F).contains(&numeric_value) {
            debug!(
                value = numeric_value,
                "DSCP value out of range, must be 0-63"
            );
            return Err(DscpError::ValueOutOfRange(numeric_value));
        }
        // Shift left by 2 to convert from DSCP field value to TOS byte value.
        // RFC 2474: the DSCP occupies bits 7–2 of the TOS/Traffic Class byte.
        let tos_value = (numeric_value as i32) << 2;
        return Ok(tos_value);
    }

    // Not a number — try keyword lookup (case-insensitive).
    match keyword_lookup(trimmed) {
        Some(value) => Ok(value),
        None => Err(DscpError::InvalidKeyword(trimmed.to_string())),
    }
}

/// Attempts to parse a string as a numeric value supporting decimal, hexadecimal
/// (`0x`/`0X` prefix), and octal (`0` prefix) formats.
///
/// Mirrors the C `Ustrtol(dscp_lookup, &p, 0)` call at dscp.c line 142, where
/// base 0 enables automatic base detection (hex with 0x, octal with 0, else
/// decimal).
///
/// Returns `Some(value)` if the entire string is a valid number, `None` otherwise.
fn parse_numeric(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // Handle negative values.
    let (is_negative, digits) = if let Some(rest) = s.strip_prefix('-') {
        (true, rest)
    } else if let Some(rest) = s.strip_prefix('+') {
        (false, rest)
    } else {
        (false, s)
    };

    if digits.is_empty() {
        return None;
    }

    // Determine base from prefix (C strtol base-0 semantics).
    let (base, digits) = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        (16, hex)
    } else if let Some(oct) = digits
        .strip_prefix("0o")
        .or_else(|| digits.strip_prefix("0O"))
    {
        (8, oct)
    } else if digits.starts_with('0')
        && digits.len() > 1
        && digits[1..].chars().all(|c| c.is_ascii_digit())
    {
        // C strtol: leading 0 means octal (but "0" alone is decimal 0).
        (8, digits)
    } else {
        (10, digits)
    };

    if digits.is_empty() {
        return None;
    }

    let value = i64::from_str_radix(digits, base).ok()?;
    Some(if is_negative { -value } else { value })
}

// =============================================================================
// Public API: dscp_set
// =============================================================================

/// Sets DSCP marking on a socket file descriptor.
///
/// This is the primary API for applying DSCP traffic marking. It combines the
/// functionality of C `dscp_acl()` (dscp.c lines 183–214) and
/// `dscp_transport()` (dscp.c lines 222–246) into a single safe function.
///
/// The function:
/// 1. Determines the socket's address family via `getsockname()`.
/// 2. Resolves the DSCP keyword/numeric value via [`dscp_lookup()`].
/// 3. Applies the value using `setsockopt()` with the appropriate option:
///    - IPv4: `IP_TOS` at `IPPROTO_IP` level
///    - IPv6: `IPV6_TCLASS` at `IPPROTO_IPV6` level
/// 4. For IPv6 sockets, also sets `IP_TOS` for dual-stack compatibility
///    (matching C behavior from dscp.c lines 241–244).
///
/// # Arguments
///
/// * `fd` — A borrowed file descriptor referencing an open, connected socket.
///   The caller must ensure the fd is valid for the duration of this call.
/// * `dscp_name` — A DSCP keyword or numeric value string.
///
/// # Returns
///
/// * `Ok(())` — DSCP was successfully applied to the socket.
/// * `Err(DscpError)` — An error occurred; see [`DscpError`] variants.
///
/// # Socket Option Details
///
/// | Address Family | Level       | Option       | Rust Type  |
/// |---------------|-------------|-------------|------------|
/// | `AF_INET`     | `IPPROTO_IP`   | `IP_TOS`       | `Ipv4Tos`    |
/// | `AF_INET6`    | `IPPROTO_IPV6` | `IPV6_TCLASS`  | `Ipv6TClass` |
pub fn dscp_set(fd: BorrowedFd<'_>, dscp_name: &str) -> Result<(), DscpError> {
    // Step 1: Determine socket address family.
    let af = get_address_family(fd)?;

    // Step 2: Resolve DSCP value.
    let tos_value = dscp_lookup(dscp_name)?;

    // Step 3: Apply via setsockopt based on address family.
    match af {
        AddressFamily::Inet => {
            setsockopt(&fd, Ipv4Tos, &tos_value).map_err(|e| {
                warn!(
                    dscp_name,
                    error = %e,
                    "failed to set DSCP (IP_TOS) on IPv4 socket"
                );
                DscpError::SocketError(e)
            })?;
            debug!(
                dscp_name,
                value = tos_value,
                "set DSCP (IP_TOS) on IPv4 socket"
            );
        }
        AddressFamily::Inet6 => {
            // Set IPV6_TCLASS for IPv6.
            setsockopt(&fd, Ipv6TClass, &tos_value).map_err(|e| {
                warn!(
                    dscp_name,
                    error = %e,
                    "failed to set DSCP (IPV6_TCLASS) on IPv6 socket"
                );
                DscpError::SocketError(e)
            })?;
            debug!(
                dscp_name,
                value = tos_value,
                "set DSCP (IPV6_TCLASS) on IPv6 socket"
            );

            // Step 4: For dual-stack IPv6 sockets, also set IP_TOS.
            // This matches the C behavior from dscp_transport() at dscp.c
            // lines 241–244: if host_af == AF_INET6, also set for AF_INET.
            // Failures here are silently ignored (matching C's `(void)` cast).
            if let Err(e) = setsockopt(&fd, Ipv4Tos, &tos_value) {
                debug!(
                    dscp_name,
                    error = %e,
                    "failed to set dual-stack IP_TOS on IPv6 socket (non-fatal)"
                );
            }
        }
        _ => {
            // Unhandled address family — matches C dscp_lookup() lines 120–125.
            let af_raw = af as i32;
            warn!(
                address_family = af_raw,
                "unhandled address family in DSCP set"
            );
            return Err(DscpError::UnsupportedAddressFamily(af_raw));
        }
    }

    Ok(())
}

// =============================================================================
// Public API: dscp_keywords
// =============================================================================

/// Returns a list of all valid DSCP keyword names.
///
/// Replaces C `dscp_keywords(FILE *stream)` from dscp.c lines 250–255, which
/// printed each keyword on a separate line. The Rust version returns a `Vec`
/// instead, allowing callers to format the output as needed.
///
/// The keywords are returned in the same alphabetical order as the static
/// keyword table, matching the C output.
///
/// # Returns
///
/// A vector of static string slices containing all recognized DSCP keywords.
///
/// # Example
///
/// ```ignore
/// let keywords = dscp_keywords();
/// assert!(keywords.contains(&"ef"));
/// assert!(keywords.contains(&"af11"));
/// assert!(keywords.contains(&"lowdelay"));
/// ```
pub fn dscp_keywords() -> Vec<&'static str> {
    DSCP_TABLE.iter().map(|entry| entry.name).collect()
}

// =============================================================================
// Module Registration
// =============================================================================
//
// Register the DSCP module with the driver registry via `inventory::submit!`.
// This replaces the C `dscp_module_info` struct from dscp.c lines 266–274:
//
//   misc_module_info dscp_module_info = {
//     .name = US"dscp",
//     .functions = dscp_functions,
//     .functions_count = nelem(dscp_functions),
//   };
//
// In Rust, the function dispatch is handled by direct function calls rather
// than a function pointer array, so only the metadata (name, avail_string)
// is registered.

inventory::submit! {
    DriverInfoBase::new("dscp")
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Keyword Lookup Tests ─────────────────────────────────────────────

    #[test]
    fn test_dscp_lookup_ef() {
        // EF (Expedited Forwarding) — DSCP 46 → TOS 0xB8
        assert_eq!(dscp_lookup("ef").unwrap(), 0xB8);
    }

    #[test]
    fn test_dscp_lookup_af_classes() {
        // Assured Forwarding class 1
        assert_eq!(dscp_lookup("af11").unwrap(), 0x28);
        assert_eq!(dscp_lookup("af12").unwrap(), 0x30);
        assert_eq!(dscp_lookup("af13").unwrap(), 0x38);
        // Assured Forwarding class 2
        assert_eq!(dscp_lookup("af21").unwrap(), 0x48);
        assert_eq!(dscp_lookup("af22").unwrap(), 0x50);
        assert_eq!(dscp_lookup("af23").unwrap(), 0x58);
        // Assured Forwarding class 3
        assert_eq!(dscp_lookup("af31").unwrap(), 0x68);
        assert_eq!(dscp_lookup("af32").unwrap(), 0x70);
        assert_eq!(dscp_lookup("af33").unwrap(), 0x78);
        // Assured Forwarding class 4
        assert_eq!(dscp_lookup("af41").unwrap(), 0x88);
        assert_eq!(dscp_lookup("af42").unwrap(), 0x90);
        assert_eq!(dscp_lookup("af43").unwrap(), 0x98);
    }

    #[test]
    fn test_dscp_lookup_legacy_tos() {
        assert_eq!(dscp_lookup("lowcost").unwrap(), 0x02);
        assert_eq!(dscp_lookup("lowdelay").unwrap(), 0x10);
        assert_eq!(dscp_lookup("mincost").unwrap(), 0x02);
        assert_eq!(dscp_lookup("reliability").unwrap(), 0x04);
        assert_eq!(dscp_lookup("throughput").unwrap(), 0x08);
    }

    #[test]
    fn test_dscp_lookup_case_insensitive() {
        assert_eq!(dscp_lookup("EF").unwrap(), 0xB8);
        assert_eq!(dscp_lookup("Ef").unwrap(), 0xB8);
        assert_eq!(dscp_lookup("AF11").unwrap(), 0x28);
        assert_eq!(dscp_lookup("LowDelay").unwrap(), 0x10);
        assert_eq!(dscp_lookup("THROUGHPUT").unwrap(), 0x08);
    }

    // ── Numeric Value Tests ──────────────────────────────────────────────

    #[test]
    fn test_dscp_lookup_numeric_decimal() {
        // Numeric DSCP values are shifted left by 2 to get TOS byte.
        assert_eq!(dscp_lookup("0").unwrap(), 0); // 0 << 2 = 0
        assert_eq!(dscp_lookup("46").unwrap(), 0xB8); // 46 << 2 = 184 = 0xB8
        assert_eq!(dscp_lookup("63").unwrap(), 252); // 63 << 2 = 252 = 0xFC
        assert_eq!(dscp_lookup("10").unwrap(), 40); // 10 << 2 = 40 = AF11
    }

    #[test]
    fn test_dscp_lookup_numeric_hex() {
        assert_eq!(dscp_lookup("0x2E").unwrap(), 0xB8); // 0x2E = 46 → 46 << 2 = 0xB8
        assert_eq!(dscp_lookup("0x0").unwrap(), 0);
        assert_eq!(dscp_lookup("0x3F").unwrap(), 252);
    }

    #[test]
    fn test_dscp_lookup_numeric_octal() {
        // C strtol base 0: leading 0 means octal.
        assert_eq!(dscp_lookup("056").unwrap(), 0xB8); // 056 octal = 46 decimal → 0xB8
        assert_eq!(dscp_lookup("00").unwrap(), 0);
    }

    #[test]
    fn test_dscp_lookup_numeric_out_of_range() {
        assert!(matches!(
            dscp_lookup("64"),
            Err(DscpError::ValueOutOfRange(64))
        ));
        assert!(matches!(
            dscp_lookup("100"),
            Err(DscpError::ValueOutOfRange(100))
        ));
        assert!(matches!(
            dscp_lookup("-1"),
            Err(DscpError::ValueOutOfRange(-1))
        ));
        assert!(matches!(
            dscp_lookup("0xFF"),
            Err(DscpError::ValueOutOfRange(255))
        ));
    }

    // ── Error Condition Tests ────────────────────────────────────────────

    #[test]
    fn test_dscp_lookup_empty() {
        assert!(matches!(dscp_lookup(""), Err(DscpError::EmptyValue)));
        assert!(matches!(dscp_lookup("   "), Err(DscpError::EmptyValue)));
    }

    #[test]
    fn test_dscp_lookup_invalid_keyword() {
        assert!(matches!(
            dscp_lookup("bogus"),
            Err(DscpError::InvalidKeyword(_))
        ));
        assert!(matches!(
            dscp_lookup("cs0"),
            Err(DscpError::InvalidKeyword(_))
        ));
    }

    #[test]
    fn test_dscp_lookup_whitespace_trimming() {
        assert_eq!(dscp_lookup("  ef  ").unwrap(), 0xB8);
        assert_eq!(dscp_lookup("\taf11\n").unwrap(), 0x28);
        assert_eq!(dscp_lookup("  46  ").unwrap(), 0xB8);
    }

    // ── Keywords List Test ───────────────────────────────────────────────

    #[test]
    fn test_dscp_keywords_returns_all_entries() {
        let keywords = dscp_keywords();
        assert_eq!(keywords.len(), DSCP_TABLE.len());
        assert_eq!(keywords.len(), 18);
        assert!(keywords.contains(&"ef"));
        assert!(keywords.contains(&"af11"));
        assert!(keywords.contains(&"af43"));
        assert!(keywords.contains(&"lowdelay"));
        assert!(keywords.contains(&"throughput"));
        assert!(keywords.contains(&"reliability"));
        assert!(keywords.contains(&"mincost"));
        assert!(keywords.contains(&"lowcost"));
    }

    #[test]
    fn test_dscp_keywords_sorted_alphabetically() {
        let keywords = dscp_keywords();
        let mut sorted = keywords.clone();
        sorted.sort();
        assert_eq!(keywords, sorted);
    }

    // ── DscpConfig Tests ─────────────────────────────────────────────────

    #[test]
    fn test_dscp_config_struct() {
        let config = DscpConfig {
            value: 0xB8,
            is_ipv6: false,
        };
        assert_eq!(config.value, 0xB8);
        assert!(!config.is_ipv6);

        let config_v6 = DscpConfig {
            value: 0x28,
            is_ipv6: true,
        };
        assert_eq!(config_v6.value, 0x28);
        assert!(config_v6.is_ipv6);
    }

    // ── Numeric Parser Tests ─────────────────────────────────────────────

    #[test]
    fn test_parse_numeric_decimal() {
        assert_eq!(parse_numeric("0"), Some(0));
        assert_eq!(parse_numeric("46"), Some(46));
        assert_eq!(parse_numeric("63"), Some(63));
        assert_eq!(parse_numeric("100"), Some(100));
    }

    #[test]
    fn test_parse_numeric_hex() {
        assert_eq!(parse_numeric("0x0"), Some(0));
        assert_eq!(parse_numeric("0x2E"), Some(46));
        assert_eq!(parse_numeric("0xFF"), Some(255));
        assert_eq!(parse_numeric("0X2e"), Some(46));
    }

    #[test]
    fn test_parse_numeric_octal() {
        assert_eq!(parse_numeric("00"), Some(0));
        assert_eq!(parse_numeric("056"), Some(46));
        assert_eq!(parse_numeric("077"), Some(63));
    }

    #[test]
    fn test_parse_numeric_negative() {
        assert_eq!(parse_numeric("-1"), Some(-1));
        assert_eq!(parse_numeric("-10"), Some(-10));
    }

    #[test]
    fn test_parse_numeric_not_a_number() {
        assert_eq!(parse_numeric("ef"), None);
        assert_eq!(parse_numeric("abc"), None);
        assert_eq!(parse_numeric(""), None);
        assert_eq!(parse_numeric("  "), None);
    }

    // ── Error Display Tests ──────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        let e = DscpError::InvalidKeyword("bogus".to_string());
        assert_eq!(e.to_string(), "invalid DSCP keyword: bogus");

        let e = DscpError::NotASocket;
        assert_eq!(e.to_string(), "file descriptor is not a socket");

        let e = DscpError::UnsupportedAddressFamily(99);
        assert_eq!(e.to_string(), "unsupported address family: 99");

        let e = DscpError::EmptyValue;
        assert_eq!(e.to_string(), "empty DSCP value");

        let e = DscpError::ValueOutOfRange(100);
        assert_eq!(e.to_string(), "DSCP value 100 out of range (must be 0-63)");
    }
}
