// =============================================================================
// exim-lookups/src/psl.rs — Public Suffix List Lookup (Pure Rust)
// =============================================================================
//
// Rewrites `src/src/lookups/psl.c` (250 lines) as a pure Rust PSL lookup
// using the `publicsuffix` crate (2.3.0) for PSL parsing/matching and the
// `idna` crate (1.0.3) for internationalized domain name conversion.
//
// This module provides two lookup types:
//   - `psl`    — returns the public suffix for a given domain
//   - `regdom` — returns the registrable domain for a given domain
//
// Both lookup types use absolute file paths (`LookupType::ABS_FILE`) pointing
// to a Public Suffix List data file (e.g., `public_suffix_list.dat` from
// https://publicsuffix.org/list/public_suffix_list.dat).
//
// C → Rust mapping:
//   C `psl_open()`       → `PslLookup::open()`   — reads + parses PSL file
//   C `psl_gen_find()`   → `PslLookup::find()`   — PSL matching with IDNA
//   C `psl_close()`      → `PslLookup::close()`  — drops parsed data
//   C `psl_find()`       → `PslLookup` with `PslVariant::Psl`
//   C `regdom_find()`    → `PslLookup` with `PslVariant::Regdom`
//   C `psl_version_report()` → `PslLookup::version_report()`
//
// The 170-line custom PSL matching algorithm in C (lines 44–175 of psl.c) —
// including manual right-to-left label comparison, wildcard handling, exception
// rules, and longest-match tracking — is entirely replaced by the `publicsuffix`
// crate's `Psl::suffix()` and `Psl::domain()` methods.
//
// IDNA handling (replacing C `string_domain_utf8_to_alabel()` and
// `string_domain_alabel_to_utf8()`):
//   1. Detect non-ASCII input (UTF-8 internationalized domain)
//   2. Convert to ASCII (punycode) via `idna::domain_to_ascii()`
//   3. Perform PSL lookup on the ASCII form
//   4. Convert result back to UTF-8 via `idna::domain_to_unicode()`
//
// Per AAP §0.7.2: This file contains ZERO `unsafe` code.
// Per AAP §0.3.2: Feature-gated behind `lookup-psl` Cargo feature.

use std::fmt;
use std::fs;

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;
use publicsuffix::{List, Psl};
use tracing::{debug, trace};

// =============================================================================
// PSL Variant Enum
// =============================================================================

/// Indicates which PSL lookup mode this driver instance performs.
///
/// Replaces the C pattern of two separate `lookup_info` structs
/// (`psl_lookup_info` and `regdom_lookup_info`) that share the same
/// `psl_open()` / `psl_close()` functions but differ in their `find()`
/// entry points (`psl_find` vs `regdom_find`).
///
/// In Rust, a single `PslLookup` struct handles both variants, with the
/// variant determining the behavior of `find()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PslVariant {
    /// Public Suffix lookup — checks whether a domain is a public suffix
    /// and returns the matching suffix portion.
    ///
    /// For example, looking up "www.example.co.uk" returns "co.uk".
    /// Looking up "co.uk" returns "co.uk" (it IS a public suffix).
    ///
    /// C equivalent: `psl_find()` calls `psl_gen_find(..., is_regdom=FALSE)`.
    Psl,

    /// Registrable Domain lookup — returns the registrable domain
    /// (public suffix + one label to the left).
    ///
    /// For example, looking up "www.example.co.uk" returns "example.co.uk".
    /// Looking up "co.uk" returns nothing (it is a public suffix with no
    /// registrable domain above it).
    ///
    /// C equivalent: `regdom_find()` calls `psl_gen_find(..., is_regdom=TRUE)`.
    Regdom,
}

impl fmt::Display for PslVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Psl => write!(f, "psl"),
            Self::Regdom => write!(f, "regdom"),
        }
    }
}

// =============================================================================
// Internal Handle — Stores Parsed PSL Data
// =============================================================================

/// Internal handle storing the parsed Public Suffix List data.
///
/// Created by `PslLookup::open()` from a PSL data file. The parsed `List`
/// is stored in a `LookupHandle` (`Box<dyn Any + Send + Sync>`) and
/// downcast back in `find()` and `close()`.
///
/// Unlike the C implementation (which opens a `FILE *` and re-reads the
/// file on every `find()` call via `fgets()` + `rewind()`), this Rust
/// implementation parses the entire PSL file once in `open()` and performs
/// efficient in-memory lookups in `find()`.
struct PslHandle {
    /// Parsed Public Suffix List data structure.
    /// Provides `suffix()` and `domain()` methods via the `Psl` trait.
    list: List,
}

// PslHandle needs Debug for diagnostic purposes, but List doesn't derive Debug.
// We implement it manually with a summary.
impl fmt::Debug for PslHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PslHandle")
            .field("list", &"<parsed PSL data>")
            .finish()
    }
}

// =============================================================================
// PslLookup — Main Driver Implementation
// =============================================================================

/// Public Suffix List lookup driver.
///
/// Implements the `LookupDriver` trait to provide PSL-based domain lookups.
/// Each instance is configured with a `PslVariant` that determines whether
/// it returns the public suffix or the registrable domain.
///
/// Two instances are registered via `inventory::submit!`:
///   - `"psl"` — returns the public suffix (e.g., "co.uk" for "www.example.co.uk")
///   - `"regdom"` — returns the registrable domain (e.g., "example.co.uk")
///
/// # Thread Safety
///
/// `PslLookup` is `Send + Sync` (required by `LookupDriver`). The internal
/// `PslHandle` containing the parsed `List` is also `Send + Sync` since it
/// is an immutable data structure after parsing.
///
/// # I18N Support
///
/// Internationalized domain names (IDN) are handled via the `idna` crate:
///   - UTF-8 input is detected and converted to ASCII (punycode) before lookup
///   - Results are converted back to UTF-8 if the input was internationalized
///   - This mirrors the C implementation's use of `string_domain_utf8_to_alabel()`
///     and `string_domain_alabel_to_utf8()`
#[derive(Debug)]
pub struct PslLookup {
    /// Which PSL lookup mode this instance performs.
    variant: PslVariant,
}

impl PslLookup {
    /// Create a new PSL lookup driver with the specified variant.
    ///
    /// # Arguments
    ///
    /// * `variant` — `PslVariant::Psl` for public suffix lookup,
    ///   `PslVariant::Regdom` for registrable domain lookup.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let psl_driver = PslLookup::new(PslVariant::Psl);
    /// let regdom_driver = PslLookup::new(PslVariant::Regdom);
    /// ```
    pub fn new(variant: PslVariant) -> Self {
        Self { variant }
    }
}

// =============================================================================
// IDNA Helper Functions
// =============================================================================

/// Check whether a string contains any non-ASCII bytes (indicating UTF-8
/// internationalized domain content).
///
/// Replaces C `string_is_utf8()` check in `psl_gen_find()` (line 55).
#[inline]
fn is_non_ascii(s: &str) -> bool {
    s.bytes().any(|b| b > 0x7F)
}

/// Convert a UTF-8 domain to its ASCII (punycode / A-label) representation.
///
/// Replaces C `string_domain_utf8_to_alabel()` from the Exim core.
/// Uses `idna::domain_to_ascii()` which implements UTS #46 processing.
///
/// # Arguments
///
/// * `domain` — UTF-8 domain string (e.g., "www.食狮.中国")
///
/// # Returns
///
/// ASCII punycode representation (e.g., "www.xn--85x722f.xn--fiqs8s")
/// or a `DriverError::TempFail` if conversion fails.
fn utf8_to_ascii(domain: &str) -> Result<String, DriverError> {
    idna::domain_to_ascii(domain).map_err(|e| {
        DriverError::TempFail(format!(
            "failed to convert UTF-8 domain '{}' to ASCII (punycode): {}",
            domain, e
        ))
    })
}

/// Convert an ASCII (punycode / A-label) domain back to its UTF-8 (Unicode)
/// representation.
///
/// Replaces C `string_domain_alabel_to_utf8()` from the Exim core.
/// Uses `idna::domain_to_unicode()` which performs UTS #46 Unicode processing.
///
/// # Arguments
///
/// * `ascii_domain` — ASCII punycode domain (e.g., "xn--fiqs8s")
///
/// # Returns
///
/// UTF-8 Unicode representation (e.g., "中国"). The conversion is best-effort;
/// if individual labels fail to decode, they are returned as-is.
fn ascii_to_utf8(ascii_domain: &str) -> String {
    let (unicode, _result) = idna::domain_to_unicode(ascii_domain);
    // domain_to_unicode always returns a string, even if some labels
    // failed to convert. The _result indicates whether all labels
    // converted successfully, but we use the best-effort output
    // regardless (matching C behavior where partial results are accepted).
    unicode
}

// =============================================================================
// LookupDriver Trait Implementation
// =============================================================================

impl LookupDriver for PslLookup {
    /// Open a PSL data file and parse it into an in-memory data structure.
    ///
    /// Replaces C `psl_open()` (psl.c lines 22–29):
    /// ```c
    /// static void * psl_open(const uschar * filename, uschar ** errmsg) {
    ///     FILE * f = fopen(CCS filename, "r");
    ///     if (f) return (void *) f;
    ///     *errmsg = US strerror(errno);
    ///     return NULL;
    /// }
    /// ```
    ///
    /// Unlike C (which opens a FILE* and re-reads on every find), Rust reads
    /// the entire file and parses it into a `publicsuffix::List` once. This
    /// is more efficient for repeated lookups.
    ///
    /// # Arguments
    ///
    /// * `filename` — Path to the PSL data file (e.g.,
    ///   `/usr/share/publicsuffix/public_suffix_list.dat`).
    ///   Must be `Some` since this is an `ABS_FILE` type lookup.
    ///
    /// # Returns
    ///
    /// A `LookupHandle` containing the parsed PSL data, or `DriverError` if
    /// the file cannot be read or parsed.
    fn open(&self, filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        let path = filename.ok_or_else(|| {
            DriverError::ExecutionFailed(
                "PSL lookup requires an absolute file path to a PSL data file".into(),
            )
        })?;

        debug!(
            driver = %self.variant,
            path = %path,
            "psl: opening PSL data file"
        );

        // Read the entire file contents — replaces C fopen()/fgets()/rewind()
        // pattern where the file was read line-by-line on every find() call.
        let contents = fs::read_to_string(path).map_err(|e| {
            DriverError::ExecutionFailed(format!(
                "psl: failed to read PSL data file '{}': {}",
                path, e
            ))
        })?;

        // Parse the PSL file into a List data structure.
        // The publicsuffix crate handles the standard PSL format:
        //   - Comment lines starting with "//"
        //   - Empty lines
        //   - Exception rules starting with "!"
        //   - Wildcard rules starting with "*."
        //   - Internationalized rules in UTF-8
        let list: List = contents.parse().map_err(|e| {
            DriverError::ExecutionFailed(format!(
                "psl: failed to parse PSL data file '{}': {}",
                path, e
            ))
        })?;

        debug!(
            driver = %self.variant,
            "psl: PSL data file parsed successfully"
        );

        Ok(Box::new(PslHandle { list }))
    }

    /// Check file validity — no-op for PSL lookups.
    ///
    /// The C implementation has `.check = NULL` for both `psl_lookup_info`
    /// and `regdom_lookup_info`, meaning no check function was registered.
    /// We return `Ok(true)` to indicate the file is always considered valid
    /// (actual file access errors are caught in `open()`).
    fn check(
        &self,
        _handle: &LookupHandle,
        _filename: Option<&str>,
        _modemask: i32,
        _owners: &[u32],
        _owngroups: &[u32],
    ) -> Result<bool, DriverError> {
        Ok(true)
    }

    /// Perform a PSL or registrable domain lookup.
    ///
    /// Replaces C `psl_gen_find()` (psl.c lines 44–175) — the 130-line core
    /// matching algorithm with manual right-to-left label comparison, wildcard
    /// handling, exception rules, and longest-match tracking. All of this is
    /// replaced by a single call to `publicsuffix::Psl::suffix()` or
    /// `publicsuffix::Psl::domain()`.
    ///
    /// IDNA handling (replacing C lines 53–65):
    ///   1. If input contains non-ASCII bytes → convert to punycode
    ///   2. If input is ASCII → lowercase for case-insensitive matching
    ///   3. Perform PSL lookup
    ///   4. If input was UTF-8 → convert result back to Unicode
    ///
    /// # Variant Behavior
    ///
    /// - `PslVariant::Psl`: Returns the public suffix portion of the domain.
    ///   For "www.example.co.uk", returns "co.uk".
    ///   C equivalent: `psl_find()` → `psl_gen_find(..., is_regdom=FALSE)`.
    ///
    /// - `PslVariant::Regdom`: Returns the registrable domain.
    ///   For "www.example.co.uk", returns "example.co.uk".
    ///   C equivalent: `regdom_find()` → `psl_gen_find(..., is_regdom=TRUE)`.
    fn find(
        &self,
        handle: &LookupHandle,
        _filename: Option<&str>,
        key_or_query: &str,
        _options: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        // Downcast the opaque handle to our PslHandle type.
        let psl_handle = handle.downcast_ref::<PslHandle>().ok_or_else(|| {
            DriverError::ExecutionFailed("psl: invalid handle type — expected PslHandle".into())
        })?;

        // Detect whether the input domain contains non-ASCII characters,
        // indicating an internationalized domain name (IDN).
        // Replaces C: `key_utf8 = string_is_utf8(keystring)` (psl.c line 55).
        let input_is_utf8 = is_non_ascii(key_or_query);

        // Convert domain to ASCII form for lookup:
        //   - UTF-8 input → punycode via idna::domain_to_ascii()
        //   - ASCII input → lowercase for case-insensitive matching
        //
        // Replaces C lines 55–65 in psl_gen_find():
        //   if ((key_utf8 = string_is_utf8(keystring)))
        //     keystring = string_domain_utf8_to_alabel(keystring, errmsg);
        //   else
        //     for (k = keystring; *k; k++)
        //       if (isupper(*k)) { keystring = string_copylc(keystring); break; }
        let ascii_domain = if input_is_utf8 {
            debug!(
                driver = %self.variant,
                domain = %key_or_query,
                "psl: converting UTF-8 key to ASCII (punycode)"
            );
            let ascii = utf8_to_ascii(key_or_query)?;
            debug!(
                driver = %self.variant,
                result = %ascii,
                "psl: UTF-8 → ASCII conversion result"
            );
            ascii
        } else {
            // Case-normalize ASCII domains for matching.
            // Domain names are case-insensitive per RFC 4343.
            key_or_query.to_lowercase()
        };

        // Perform the PSL lookup based on variant.
        //
        // PslVariant::Psl → list.suffix() returns the public suffix
        //   Replaces C: psl_gen_find() with is_regdom=FALSE
        //   The 130-line C matching algorithm (lines 67–175) is entirely
        //   replaced by the publicsuffix crate's efficient trie lookup.
        //
        // PslVariant::Regdom → list.domain() returns the registrable domain
        //   Replaces C: psl_gen_find() with is_regdom=TRUE
        //   The C code's "prepend one label" logic (lines 147–155) is handled
        //   internally by the publicsuffix crate's domain() method.
        let result_str = match self.variant {
            PslVariant::Psl => {
                trace!(
                    domain = %ascii_domain,
                    "psl: looking up public suffix"
                );
                psl_handle
                    .list
                    .suffix(ascii_domain.as_bytes())
                    .map(|suffix| {
                        // Suffix borrows from input bytes. Convert to owned String
                        // via Display impl (safe for ASCII punycode bytes).
                        let s = std::str::from_utf8(suffix.as_bytes())
                            .unwrap_or_default()
                            .to_string();
                        trace!(suffix = %s, "psl: suffix match found");
                        s
                    })
            }
            PslVariant::Regdom => {
                trace!(
                    domain = %ascii_domain,
                    "psl: looking up registrable domain"
                );
                psl_handle
                    .list
                    .domain(ascii_domain.as_bytes())
                    .map(|domain| {
                        // Domain borrows from input bytes. Convert to owned String
                        // via Display impl.
                        let d = std::str::from_utf8(domain.as_bytes())
                            .unwrap_or_default()
                            .to_string();
                        trace!(domain = %d, "psl: registrable domain found");
                        d
                    })
            }
        };

        // Process the lookup result.
        match result_str {
            Some(result) if !result.is_empty() => {
                // If input was UTF-8 (internationalized), convert the punycode
                // result back to Unicode.
                // Replaces C lines 159–167 in psl_gen_find():
                //   if (key_utf8 && res) {
                //     *result = string_domain_alabel_to_utf8(res, errmsg);
                //   }
                let output = if input_is_utf8 {
                    let unicode = ascii_to_utf8(&result);
                    debug!(
                        driver = %self.variant,
                        ascii = %result,
                        unicode = %unicode,
                        "psl: converting result from ASCII to UTF-8"
                    );
                    unicode
                } else {
                    result
                };

                debug!(
                    driver = %self.variant,
                    value = %output,
                    "psl: lookup found"
                );

                Ok(LookupResult::Found {
                    value: output,
                    cache_ttl: None,
                })
            }
            _ => {
                // No match found — domain is not in the PSL, or no registrable
                // domain exists (e.g., the domain IS a public suffix for regdom).
                debug!(
                    driver = %self.variant,
                    domain = %ascii_domain,
                    "psl: no match found"
                );
                Ok(LookupResult::NotFound)
            }
        }
    }

    /// Close an open PSL handle, releasing the parsed data.
    ///
    /// Replaces C `psl_close()` (psl.c lines 31–35):
    /// ```c
    /// static void psl_close(void * handle) { (void) fclose(handle); }
    /// ```
    ///
    /// In Rust, the handle is dropped when the Box is consumed, which
    /// deallocates the parsed `List` data structure.
    fn close(&self, handle: LookupHandle) {
        debug!(
            driver = %self.variant,
            "psl: closing PSL handle"
        );
        // Explicitly drop the handle. The Box<dyn Any + Send + Sync>
        // destructor will deallocate the PslHandle and its List.
        drop(handle);
    }

    /// Tidy up resources — no-op for PSL lookups.
    ///
    /// The C implementation has `.tidy = NULL` for both lookup info structs,
    /// meaning no tidy function was registered. PSL handles are cleaned up
    /// individually via `close()`.
    fn tidy(&self) {
        // No persistent resources to clean up.
        // Each PSL handle is independent and released via close().
    }

    /// Quote a string for PSL lookup — not applicable.
    ///
    /// The C implementation has `.quote = NULL` for both lookup info structs.
    /// PSL lookups do not require any string quoting/escaping.
    /// Uses the default trait implementation which returns `None`.
    fn quote(&self, _value: &str, _additional: Option<&str>) -> Option<String> {
        None
    }

    /// Version reporting for `-bV` output.
    ///
    /// Replaces C `psl_version_report()` (psl.c lines 212–217):
    /// ```c
    /// gstring * psl_version_report(gstring * g) {
    ///     return string_fmt_append(g, "Library version: psl: Exim %s builtin\n",
    ///                              EXIM_VERSION_STR);
    /// }
    /// ```
    ///
    /// Only the `Psl` variant reports version information. The `Regdom`
    /// variant returns `None` (matching C where `regdom_lookup_info` has
    /// `.version_report = NULL`).
    fn version_report(&self) -> Option<String> {
        match self.variant {
            PslVariant::Psl => {
                Some("Library version: psl: Exim (Rust, publicsuffix crate) built-in".to_string())
            }
            // C: regdom_lookup_info has .version_report = NULL
            PslVariant::Regdom => None,
        }
    }

    /// Return the lookup type flags.
    ///
    /// Both `psl` and `regdom` lookups require an absolute file path to the
    /// PSL data file, matching C `.type = lookup_absfile` for both
    /// `psl_lookup_info` and `regdom_lookup_info`.
    fn lookup_type(&self) -> LookupType {
        LookupType::ABS_FILE
    }

    /// Return the driver name for configuration file matching.
    ///
    /// Returns `"psl"` for the public suffix variant or `"regdom"` for the
    /// registrable domain variant. These names are used in Exim configuration
    /// files as `${lookup psl { ... } }` and `${lookup regdom { ... } }`.
    fn driver_name(&self) -> &str {
        match self.variant {
            PslVariant::Psl => "psl",
            PslVariant::Regdom => "regdom",
        }
    }
}

// =============================================================================
// Driver Registration
// =============================================================================
//
// Register two LookupDriverFactory instances via inventory::submit!() for
// compile-time driver registration, replacing the C registration:
//
//   static lookup_info *_lookup_list[] = { &psl_lookup_info, &regdom_lookup_info };
//   lookup_module_info psl_lookup_module_info = {
//       LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 2
//   };

inventory::submit! {
    LookupDriverFactory {
        name: "psl",
        create: || Box::new(PslLookup::new(PslVariant::Psl)),
        lookup_type: LookupType::ABS_FILE,
        avail_string: Some("psl (publicsuffix crate, built-in)"),
    }
}

inventory::submit! {
    LookupDriverFactory {
        name: "regdom",
        create: || Box::new(PslLookup::new(PslVariant::Regdom)),
        lookup_type: LookupType::ABS_FILE,
        avail_string: Some("regdom (publicsuffix crate, built-in)"),
    }
}

// =============================================================================
// Module-Level Documentation for PSL Module Info
// =============================================================================

/// Module info for the PSL lookup module, documenting the two lookup types.
///
/// Replaces C `psl_lookup_module_info`:
/// ```c
/// static lookup_info *_lookup_list[] = { &psl_lookup_info, &regdom_lookup_info };
/// lookup_module_info psl_lookup_module_info = {
///     LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 2
/// };
/// ```
pub static PSL_MODULE_INFO: exim_drivers::lookup_driver::LookupModuleInfo =
    exim_drivers::lookup_driver::LookupModuleInfo {
        module_name: "psl",
        lookup_names: &["psl", "regdom"],
    };

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psl_variant_display() {
        assert_eq!(PslVariant::Psl.to_string(), "psl");
        assert_eq!(PslVariant::Regdom.to_string(), "regdom");
    }

    #[test]
    fn test_psl_variant_equality() {
        assert_eq!(PslVariant::Psl, PslVariant::Psl);
        assert_eq!(PslVariant::Regdom, PslVariant::Regdom);
        assert_ne!(PslVariant::Psl, PslVariant::Regdom);
    }

    #[test]
    fn test_psl_lookup_new() {
        let psl = PslLookup::new(PslVariant::Psl);
        assert_eq!(psl.variant, PslVariant::Psl);
        assert_eq!(psl.driver_name(), "psl");
        assert_eq!(psl.lookup_type(), LookupType::ABS_FILE);

        let regdom = PslLookup::new(PslVariant::Regdom);
        assert_eq!(regdom.variant, PslVariant::Regdom);
        assert_eq!(regdom.driver_name(), "regdom");
        assert_eq!(regdom.lookup_type(), LookupType::ABS_FILE);
    }

    #[test]
    fn test_psl_version_report() {
        let psl = PslLookup::new(PslVariant::Psl);
        assert!(psl.version_report().is_some());

        let regdom = PslLookup::new(PslVariant::Regdom);
        assert!(regdom.version_report().is_none());
    }

    #[test]
    fn test_psl_check_always_ok() {
        let psl = PslLookup::new(PslVariant::Psl);
        let handle: LookupHandle = Box::new(42_u32); // dummy handle
        let result = psl.check(&handle, None, 0, &[], &[]);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_psl_open_missing_filename() {
        let psl = PslLookup::new(PslVariant::Psl);
        let result = psl.open(None);
        assert!(result.is_err());
    }

    #[test]
    fn test_psl_open_nonexistent_file() {
        let psl = PslLookup::new(PslVariant::Psl);
        let result = psl.open(Some("/nonexistent/path/to/psl.dat"));
        assert!(result.is_err());
    }

    #[test]
    fn test_is_non_ascii() {
        assert!(!is_non_ascii("example.com"));
        assert!(!is_non_ascii("www.example.co.uk"));
        assert!(is_non_ascii("www.食狮.中国"));
        assert!(is_non_ascii("münchen.de"));
        assert!(!is_non_ascii(""));
    }

    #[test]
    fn test_psl_tidy_no_panic() {
        let psl = PslLookup::new(PslVariant::Psl);
        psl.tidy(); // Should not panic
    }

    #[test]
    fn test_psl_quote_returns_none() {
        let psl = PslLookup::new(PslVariant::Psl);
        assert!(psl.quote("test.com", None).is_none());
        assert!(psl.quote("test.com", Some("extra")).is_none());
    }

    #[test]
    fn test_psl_find_invalid_handle() {
        let psl = PslLookup::new(PslVariant::Psl);
        let handle: LookupHandle = Box::new(42_u32); // wrong handle type
        let result = psl.find(&handle, None, "example.com", None);
        assert!(result.is_err());
    }

    /// Integration test that creates a minimal PSL file and performs lookups.
    #[test]
    fn test_psl_open_parse_find() {
        // Create a minimal PSL data file
        let psl_content = "\
// ===BEGIN ICANN DOMAINS===
com
co.uk
uk
org
// ===END ICANN DOMAINS===
";
        let tmpfile = tempfile_path();
        std::fs::write(&tmpfile, psl_content).expect("failed to write temp PSL file");

        // Test PSL variant
        let psl_driver = PslLookup::new(PslVariant::Psl);
        let handle = psl_driver
            .open(Some(&tmpfile))
            .expect("failed to open PSL file");

        // Look up "www.example.com" — suffix should be "com"
        let result = psl_driver
            .find(&handle, None, "www.example.com", None)
            .expect("find failed");
        match &result {
            LookupResult::Found { value, .. } => {
                assert_eq!(value, "com", "expected suffix 'com' for 'www.example.com'");
            }
            other => panic!("expected Found, got {:?}", other),
        }

        // Look up "www.example.co.uk" — suffix should be "co.uk"
        let result = psl_driver
            .find(&handle, None, "www.example.co.uk", None)
            .expect("find failed");
        match &result {
            LookupResult::Found { value, .. } => {
                assert_eq!(
                    value, "co.uk",
                    "expected suffix 'co.uk' for 'www.example.co.uk'"
                );
            }
            other => panic!("expected Found, got {:?}", other),
        }

        psl_driver.close(handle);

        // Test Regdom variant
        let regdom_driver = PslLookup::new(PslVariant::Regdom);
        let handle = regdom_driver
            .open(Some(&tmpfile))
            .expect("failed to open PSL file");

        // Look up "www.example.com" — registrable domain should be "example.com"
        let result = regdom_driver
            .find(&handle, None, "www.example.com", None)
            .expect("find failed");
        match &result {
            LookupResult::Found { value, .. } => {
                assert_eq!(
                    value, "example.com",
                    "expected domain 'example.com' for 'www.example.com'"
                );
            }
            other => panic!("expected Found, got {:?}", other),
        }

        // Look up "www.example.co.uk" — registrable domain should be "example.co.uk"
        let result = regdom_driver
            .find(&handle, None, "www.example.co.uk", None)
            .expect("find failed");
        match &result {
            LookupResult::Found { value, .. } => {
                assert_eq!(
                    value, "example.co.uk",
                    "expected domain 'example.co.uk' for 'www.example.co.uk'"
                );
            }
            other => panic!("expected Found, got {:?}", other),
        }

        regdom_driver.close(handle);

        // Clean up
        let _ = std::fs::remove_file(&tmpfile);
    }

    /// Helper: generate a unique temporary file path.
    fn tempfile_path() -> String {
        use std::time::SystemTime;
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("/tmp/blitzy_psl_test_{}.dat", ts)
    }
}
