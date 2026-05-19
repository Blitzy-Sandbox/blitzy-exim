//! Line-scan file lookup module (pure Rust).
//!
//! Rewrites `src/src/lookups/lsearch.c` (484 lines of C) as a pure Rust
//! implementation providing 4 lookup variants:
//!
//! - **`lsearch`** — Caseless exact key matching (PLAIN)
//! - **`wildlsearch`** — Wildcard/regex pattern matching with expansion (WILD)
//! - **`nwildlsearch`** — Wildcard/regex pattern matching without expansion (NWILD)
//! - **`iplsearch`** — IP address / CIDR network membership matching (IP)
//!
//! File format:
//! - Lines beginning with `#` are comments
//! - Blank lines are ignored
//! - Lines starting with whitespace are continuation lines belonging to the
//!   preceding key's value
//! - Keys can be unquoted (terminated by `:` or whitespace) or double-quoted
//!   with backslash escape interpretation
//! - Values follow the key after an optional `:` separator
//! - The `ret=full` option returns the entire matched line instead of just the value
//!
//! Each variant is registered as a separate `LookupDriverFactory` via
//! `inventory::submit!` for compile-time driver registration.

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::sync::Mutex;

use regex::Regex;

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;

use crate::helpers::check_file::{check_file, CheckFileTarget, ExpectedFileType};

use exim_store::taint::{Clean, Tainted};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Discriminant for the four lsearch lookup variants.
///
/// Each variant uses a different key-matching algorithm while sharing the
/// same file-scanning and value-assembly logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsearchType {
    /// Plain lsearch: caseless exact-length string comparison.
    Plain,
    /// wildlsearch: wildcard / regex pattern matching (with expansion).
    Wild,
    /// nwildlsearch: wildcard / regex pattern matching (without expansion).
    NWild,
    /// iplsearch: IP address / CIDR network membership matching.
    Ip,
}

impl std::fmt::Display for LsearchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plain => write!(f, "lsearch"),
            Self::Wild => write!(f, "wildlsearch"),
            Self::NWild => write!(f, "nwildlsearch"),
            Self::Ip => write!(f, "iplsearch"),
        }
    }
}

/// Line-scan file lookup driver implementing the four lsearch variants.
///
/// Each `LsearchLookup` instance is bound to a single variant type at
/// construction time.  The `LookupDriver` trait implementation delegates
/// to the shared `internal_lsearch_find` method with the stored variant.
#[derive(Debug)]
pub struct LsearchLookup {
    /// Which matching algorithm this instance uses.
    search_type: LsearchType,
}

// ---------------------------------------------------------------------------
// Internal handle — stored inside the type-erased `LookupHandle`
// ---------------------------------------------------------------------------

/// File state kept between `open()` and `close()`.
///
/// A `Mutex` provides the interior mutability required by
/// `LookupDriver::find(&self, handle: &LookupHandle, …)` — the trait
/// takes `&self` and `&LookupHandle` (immutable references) yet we must
/// seek and read from the underlying file.
struct LsearchHandle {
    reader: Mutex<BufReader<File>>,
}

// Safety reasoning (no unsafe needed):
// • `File` is `Send + Sync`.
// • `BufReader<File>` is `Send + Sync`.
// • `Mutex<T>` is `Send + Sync` when `T: Send`.
// Therefore `LsearchHandle` satisfies the `Any + Send + Sync` bound of
// `LookupHandle`.

// ---------------------------------------------------------------------------
// Core implementation
// ---------------------------------------------------------------------------

impl LsearchLookup {
    /// Create a new lookup driver instance for the given variant.
    pub fn new(search_type: LsearchType) -> Self {
        Self { search_type }
    }

    // -- Key parsing --------------------------------------------------------

    /// Parse a key from the beginning of a line.
    ///
    /// Returns `(extracted_key, remainder_of_line_after_key)`.
    /// The remainder includes any separator characters (`:`, whitespace)
    /// that precede the value — the caller must skip them.
    fn parse_key(line: &str) -> (String, &str) {
        if line.starts_with('"') {
            Self::parse_quoted_key(line)
        } else {
            Self::parse_unquoted_key(line)
        }
    }

    /// Parse a double-quoted key with backslash escape interpretation.
    ///
    /// The input `line` starts with `"`.  Returns the key content (without
    /// quotes) and the remainder of the line after the closing quote.
    fn parse_quoted_key(line: &str) -> (String, &str) {
        debug_assert!(line.starts_with('"'));
        let inner = &line[1..]; // skip opening quote
        let mut key = String::new();
        let mut iter = inner.char_indices();

        // Scan until closing quote, EOF, or error.  `end_pos` is set to
        // the byte offset *past* the delimiter that ended the key.
        let end_pos = loop {
            match iter.next() {
                None => {
                    // Unterminated quote — treat everything as the key
                    break inner.len();
                }
                Some((pos, '"')) => {
                    // Closing quote found (ASCII `"` is 1 byte)
                    break pos + 1;
                }
                Some((_, '\\')) => {
                    // Backslash escape — interpret the next character
                    if let Some((_, esc)) = iter.next() {
                        key.push(Self::interpret_escape(esc));
                    }
                    // If backslash is the last char, silently ignore it
                }
                Some((_, c)) => {
                    key.push(c);
                }
            }
        };

        (key, &inner[end_pos..])
    }

    /// Parse an unquoted key terminated by `:` or whitespace.
    ///
    /// Returns `(key, remainder_of_line)` where the remainder starts at
    /// the first `:` or whitespace character after the key.
    fn parse_unquoted_key(line: &str) -> (String, &str) {
        let end = line
            .find(|c: char| c == ':' || c.is_ascii_whitespace())
            .unwrap_or(line.len());
        (line[..end].to_string(), &line[end..])
    }

    /// Interpret a single character after a backslash in a quoted key.
    ///
    /// Supports the common C-style escape sequences.  Unknown sequences
    /// pass through literally (matching the C `string_interpret_escape`
    /// behaviour for unrecognised characters).
    fn interpret_escape(c: char) -> char {
        match c {
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            '0' => '\0',
            '\\' => '\\',
            '"' => '"',
            'a' => '\x07',  // BEL
            'b' => '\x08',  // Backspace
            'f' => '\x0C',  // Form feed
            'v' => '\x0B',  // Vertical tab
            other => other, // pass through
        }
    }

    /// Advance past optional whitespace and a single optional `:` separator
    /// to reach the beginning of the value portion.
    fn skip_separator(s: &str) -> &str {
        let s = s.trim_start();
        if let Some(rest) = s.strip_prefix(':') {
            rest.trim_start()
        } else {
            s
        }
    }

    // -- Key matching -------------------------------------------------------

    /// PLAIN variant: caseless exact-length string comparison.
    ///
    /// Both the search key and the file key must be the same length and
    /// match case-insensitively (ASCII folding, matching C `strncmpic`).
    fn match_plain(search_key: &str, file_key: &str) -> bool {
        search_key.eq_ignore_ascii_case(file_key)
    }

    /// WILD variant: wildcard / regex pattern matching with expansion.
    ///
    /// Delegates to `pattern_match` — expansion of `$variables` is handled
    /// at a higher layer (the expansion engine), not within the lookup.
    fn match_wild(search_key: &str, pattern: &str) -> bool {
        Self::pattern_match(search_key, pattern)
    }

    /// NWILD variant: wildcard / regex pattern matching *without* expansion.
    ///
    /// Identical matching logic to WILD at this layer; the distinction
    /// (MCL_NOEXPAND) is enforced by the caller/expansion engine.
    fn match_nwild(search_key: &str, pattern: &str) -> bool {
        Self::pattern_match(search_key, pattern)
    }

    /// Common pattern matching for WILD / NWILD variants.
    ///
    /// Matching rules (mirroring Exim `match_isinlist`):
    /// 1. Pattern starting with `^` is treated as a regex.
    /// 2. Pattern containing `*` or `?` is treated as a glob and converted
    ///    to a regex.
    /// 3. Otherwise a caseless exact comparison is performed.
    ///
    /// All regex matching is case-insensitive.
    fn pattern_match(search_key: &str, pattern: &str) -> bool {
        if pattern.starts_with('^') {
            // Regex pattern — prepend case-insensitive flag
            let re_src = format!("(?i){}", pattern);
            match Regex::new(&re_src) {
                Ok(re) => re.is_match(search_key),
                Err(e) => {
                    tracing::warn!(
                        pattern = %pattern,
                        error = %e,
                        "lsearch: invalid regex pattern in file"
                    );
                    false
                }
            }
        } else if pattern.contains('*') || pattern.contains('?') {
            // Glob-style wildcard — convert to anchored regex
            let re_src = Self::glob_to_regex(pattern);
            match Regex::new(&re_src) {
                Ok(re) => re.is_match(search_key),
                Err(e) => {
                    tracing::warn!(
                        pattern = %pattern,
                        error = %e,
                        "lsearch: invalid glob pattern in file"
                    );
                    false
                }
            }
        } else {
            // Plain caseless comparison
            search_key.eq_ignore_ascii_case(pattern)
        }
    }

    /// Convert a glob-style pattern to an anchored, case-insensitive regex.
    ///
    /// `*` → `.*`, `?` → `.`, all other regex metacharacters are escaped.
    fn glob_to_regex(pattern: &str) -> String {
        let mut re = String::with_capacity(pattern.len() * 2 + 8);
        re.push_str("(?i)^");

        for c in pattern.chars() {
            match c {
                '*' => re.push_str(".*"),
                '?' => re.push('.'),
                // Escape regex metacharacters
                '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$' | '\\' => {
                    re.push('\\');
                    re.push(c);
                }
                _ => re.push(c),
            }
        }

        re.push('$');
        re
    }

    /// IP variant: check whether `search_key` (an IP address) is matched
    /// by `file_key` (an IP address, CIDR network, or `*`).
    fn match_ip(search_key: &str, file_key: &str) -> bool {
        // Special wildcard: `*` matches every address
        if file_key.trim() == "*" {
            return true;
        }

        // Parse the search key as an IP address
        let search_ip: IpAddr = match search_key.parse() {
            Ok(ip) => ip,
            Err(_) => return false, // already validated in find()
        };

        Self::ip_in_network(search_ip, file_key.trim())
    }

    /// Check whether `ip` falls within the CIDR network described by
    /// `network` (e.g. `"192.168.1.0/24"` or `"2001:db8::/32"`).
    ///
    /// If no prefix length is given the comparison is an exact-address match
    /// (i.e. `/32` for IPv4, `/128` for IPv6).
    fn ip_in_network(ip: IpAddr, network: &str) -> bool {
        let (addr_str, mask_bits) = match network.find('/') {
            Some(pos) => {
                let bits = match network[pos + 1..].parse::<u32>() {
                    Ok(b) => b,
                    Err(_) => return false,
                };
                (&network[..pos], Some(bits))
            }
            None => (network, None),
        };

        let net_addr: IpAddr = match addr_str.parse() {
            Ok(a) => a,
            Err(_) => return false,
        };

        match (ip, net_addr) {
            (IpAddr::V4(search), IpAddr::V4(net)) => {
                let mask = mask_bits.unwrap_or(32);
                if mask > 32 {
                    return false;
                }
                if mask == 0 {
                    return true;
                }
                let shift = 32u32.saturating_sub(mask);
                let mask_val = u32::MAX.checked_shl(shift).unwrap_or(0);
                (u32::from(search) & mask_val) == (u32::from(net) & mask_val)
            }
            (IpAddr::V6(search), IpAddr::V6(net)) => {
                let mask = mask_bits.unwrap_or(128);
                if mask > 128 {
                    return false;
                }
                if mask == 0 {
                    return true;
                }
                let shift = 128u32.saturating_sub(mask);
                let mask_val = u128::MAX.checked_shl(shift).unwrap_or(0);
                (u128::from(search) & mask_val) == (u128::from(net) & mask_val)
            }
            _ => false, // mixed address families never match
        }
    }

    /// Validate that `s` is either `"*"` or a syntactically valid IP address
    /// (with or without CIDR prefix length).  Used by the IP variant to
    /// reject non-IP search keys before scanning the file.
    fn is_valid_ip_input(s: &str) -> bool {
        if s == "*" {
            return true;
        }
        if s.parse::<IpAddr>().is_ok() {
            return true;
        }
        // Accept CIDR notation (e.g. "192.168.1.0/24")
        if let Some(slash) = s.find('/') {
            if s[..slash].parse::<IpAddr>().is_ok() {
                if let Ok(bits) = s[slash + 1..].parse::<u32>() {
                    return match s[..slash].parse::<IpAddr>() {
                        Ok(IpAddr::V4(_)) => bits <= 32,
                        Ok(IpAddr::V6(_)) => bits <= 128,
                        Err(_) => false,
                    };
                }
            }
        }
        false
    }

    // -- Core file-scan engine ----------------------------------------------

    /// Rewind the file, scan line-by-line, and return the first matching
    /// entry.
    ///
    /// This is the Rust equivalent of C `internal_lsearch_find()`.
    ///
    /// ## Algorithm
    ///
    /// 1. Optionally parse `ret=full` from the options string.
    /// 2. Seek to the beginning of the file.
    /// 3. For each line:
    ///    - Skip blank lines, `#` comments, and continuation lines
    ///      (lines starting with whitespace).
    ///    - Parse the key (quoted or unquoted).
    ///    - Match the key against `search_key` using the variant's algorithm.
    ///    - On match: assemble the value from the remainder of the line and
    ///      any following continuation lines.
    /// 4. Return `Found` with the assembled value, or `NotFound` if no key
    ///    matched.
    fn internal_lsearch_find(
        &self,
        handle: &LookupHandle,
        _filename: Option<&str>,
        search_key: &str,
        search_type: LsearchType,
        opts: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        // ---- option parsing ------------------------------------------------
        let ret_full = opts.is_some_and(|o| {
            o.split(|c: char| c == ',' || c.is_ascii_whitespace())
                .any(|token| token == "ret=full")
        });

        // ---- acquire handle ------------------------------------------------
        let lsearch_handle = handle.downcast_ref::<LsearchHandle>().ok_or_else(|| {
            DriverError::ExecutionFailed("lsearch: invalid handle (not an LsearchHandle)".into())
        })?;

        let mut reader = lsearch_handle
            .reader
            .lock()
            .map_err(|e| DriverError::ExecutionFailed(format!("lsearch: mutex poisoned: {e}")))?;

        // ---- rewind --------------------------------------------------------
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|e| DriverError::ExecutionFailed(format!("lsearch: seek failed: {e}")))?;

        // ---- line-by-line scan ---------------------------------------------
        let mut line_buf = String::new();

        loop {
            line_buf.clear();
            let bytes_read = reader
                .read_line(&mut line_buf)
                .map_err(|e| DriverError::ExecutionFailed(format!("lsearch: read error: {e}")))?;

            if bytes_read == 0 {
                break; // EOF — key not found
            }

            // Trim trailing newline / carriage-return
            let line = line_buf.trim_end_matches(['\n', '\r']);

            // Skip empty lines
            if line.is_empty() {
                continue;
            }

            // Skip comment lines
            if line.starts_with('#') {
                continue;
            }

            // Skip continuation lines (leading whitespace) — they belong to
            // a preceding key's value and are only consumed after a match.
            if line.starts_with(|c: char| c.is_ascii_whitespace()) {
                continue;
            }

            // ---- parse key -------------------------------------------------
            let (file_key, after_key) = Self::parse_key(line);

            if file_key.is_empty() {
                continue;
            }

            // ---- match key -------------------------------------------------
            let matched = match search_type {
                LsearchType::Plain => Self::match_plain(search_key, &file_key),
                LsearchType::Wild => Self::match_wild(search_key, &file_key),
                LsearchType::NWild => Self::match_nwild(search_key, &file_key),
                LsearchType::Ip => Self::match_ip(search_key, &file_key),
            };

            if !matched {
                continue;
            }

            tracing::debug!(
                file_key = %file_key,
                search_key = %search_key,
                variant = %search_type,
                "lsearch: key matched"
            );

            // ---- extract value ---------------------------------------------

            if ret_full {
                // Return the entire original line (key + separator + value)
                let clean = Clean::new(line.to_string());
                return Ok(LookupResult::Found {
                    value: clean.into_inner(),
                    cache_ttl: None,
                });
            }

            // Normal mode: return only the value portion
            let value_start = Self::skip_separator(after_key);
            let mut result = String::from(value_start);

            // ---- read continuation lines -----------------------------------
            loop {
                line_buf.clear();
                let cont_bytes = reader.read_line(&mut line_buf).map_err(|e| {
                    DriverError::ExecutionFailed(format!("lsearch: read error: {e}"))
                })?;

                if cont_bytes == 0 {
                    break; // EOF
                }

                let cont_line = line_buf.trim_end_matches(['\n', '\r']);

                // Continuation lines must start with whitespace
                if cont_line.is_empty() || !cont_line.starts_with(|c: char| c.is_ascii_whitespace())
                {
                    break; // not a continuation — stop
                }

                // Trim leading whitespace
                let trimmed = cont_line.trim_start();

                // Skip comment continuation lines (whitespace then `#`)
                if trimmed.starts_with('#') {
                    continue;
                }

                // Append with a single space separator (collapsing the
                // original indentation to one blank, matching C behaviour)
                if !result.is_empty() || !trimmed.is_empty() {
                    result.push(' ');
                }
                result.push_str(trimmed);
            }

            // Wrap the assembled value in Clean to denote it has been
            // validated through the lookup pipeline.
            let clean_result = Clean::new(result);
            return Ok(LookupResult::Found {
                value: clean_result.into_inner(),
                cache_ttl: None,
            });
        }

        // No matching key found
        Ok(LookupResult::NotFound)
    }
}

// ---------------------------------------------------------------------------
// LookupDriver trait implementation
// ---------------------------------------------------------------------------

impl LookupDriver for LsearchLookup {
    /// Open a file for line-scan lookup.
    ///
    /// The returned `LookupHandle` wraps a `BufReader<File>` behind a
    /// `Mutex` so that `find()` can seek and read through an immutable
    /// reference.
    fn open(&self, filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        let path = filename
            .ok_or_else(|| DriverError::ConfigError("lsearch: a filename is required".into()))?;

        tracing::debug!(
            filename = %path,
            variant = %self.search_type,
            "lsearch: opening file"
        );

        let file = File::open(path).map_err(|e| {
            DriverError::ExecutionFailed(format!("lsearch: cannot open \"{path}\": {e}"))
        })?;

        let reader = BufReader::new(file);
        let handle = LsearchHandle {
            reader: Mutex::new(reader),
        };

        Ok(Box::new(handle))
    }

    /// Verify that the opened file has acceptable type, mode, owner, and
    /// group.
    ///
    /// Delegates to `helpers::check_file` with `ExpectedFileType::Regular`.
    fn check(
        &self,
        handle: &LookupHandle,
        filename: Option<&str>,
        modemask: i32,
        owners: &[u32],
        owngroups: &[u32],
    ) -> Result<bool, DriverError> {
        let lsearch_handle = handle.downcast_ref::<LsearchHandle>().ok_or_else(|| {
            DriverError::ExecutionFailed("lsearch: invalid handle (not an LsearchHandle)".into())
        })?;

        let reader_guard = lsearch_handle
            .reader
            .lock()
            .map_err(|e| DriverError::ExecutionFailed(format!("lsearch: mutex poisoned: {e}")))?;

        let file_ref = reader_guard.get_ref();
        let fname = filename.unwrap_or("<unknown>");

        // The trait passes modemask as i32; check_file expects u32.
        #[allow(clippy::cast_sign_loss)]
        let mode_u32 = modemask as u32;

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
            CheckFileTarget::Fd(file_ref),
            ExpectedFileType::Regular,
            mode_u32,
            owners_opt,
            groups_opt,
            self.driver_name(),
            fname,
        ) {
            Ok(()) => Ok(true),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    filename = %fname,
                    variant = %self.search_type,
                    "lsearch: file security check failed"
                );
                Ok(false)
            }
        }
    }

    /// Look up a key in the file.
    ///
    /// For the IP variant the search key is first validated as a
    /// syntactically correct IP address (or `*`); if invalid the lookup
    /// returns `Deferred` with a diagnostic message, matching the C
    /// `iplsearch_find` behaviour.
    fn find(
        &self,
        handle: &LookupHandle,
        filename: Option<&str>,
        key_or_query: &str,
        options: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        // Mark the incoming key as tainted (it originates from SMTP client
        // input or other untrusted sources).
        let tainted_key = Tainted::new(key_or_query.to_string());

        tracing::debug!(
            key = tainted_key.as_ref().as_str(),
            variant = %self.search_type,
            "lsearch: find request"
        );

        // IP variant: validate that the search key is a valid IP address
        // (or "*") before scanning the file.  Invalid keys are deferred,
        // not silently ignored.
        if self.search_type == LsearchType::Ip && !Self::is_valid_ip_input(tainted_key.as_ref()) {
            return Ok(LookupResult::Deferred {
                message: format!(
                    "\"{}\" is not a valid IP address or network",
                    tainted_key.as_ref()
                ),
            });
        }

        self.internal_lsearch_find(
            handle,
            filename,
            tainted_key.as_ref(),
            self.search_type,
            options,
        )
    }

    /// Release the file handle.  The `LookupHandle` is consumed and its
    /// resources (file descriptor, buffer) are dropped.
    fn close(&self, _handle: LookupHandle) {
        tracing::debug!(
            variant = %self.search_type,
            "lsearch: file handle closed"
        );
        // `LsearchHandle` (and its `BufReader<File>`) is dropped here.
    }

    /// No-op: lsearch holds no cross-lookup state that needs tidying.
    fn tidy(&self) {
        // Equivalent to C tidy=NULL for all four variants.
    }

    /// No quoting transformation needed for lsearch keys.
    fn quote(&self, _value: &str, _additional: Option<&str>) -> Option<String> {
        // Equivalent to C quote=NULL for all four variants.
        None
    }

    /// Return a human-readable version string (Plain variant only).
    fn version_report(&self) -> Option<String> {
        match self.search_type {
            LsearchType::Plain => {
                Some("lsearch: Exim Rust rewrite (built-in line-scan lookup)".to_string())
            }
            _ => None,
        }
    }

    /// All four variants are absolute-file lookups (not query-style).
    fn lookup_type(&self) -> LookupType {
        LookupType::ABS_FILE
    }

    /// Return the canonical driver name for this variant.
    fn driver_name(&self) -> &str {
        match self.search_type {
            LsearchType::Plain => "lsearch",
            LsearchType::Wild => "wildlsearch",
            LsearchType::NWild => "nwildlsearch",
            LsearchType::Ip => "iplsearch",
        }
    }
}

// ---------------------------------------------------------------------------
// Factory functions for inventory registration
// ---------------------------------------------------------------------------

/// Create an `lsearch` (PLAIN) driver instance.
fn create_lsearch_plain() -> Box<dyn LookupDriver> {
    Box::new(LsearchLookup::new(LsearchType::Plain))
}

/// Create a `wildlsearch` (WILD) driver instance.
fn create_wildlsearch() -> Box<dyn LookupDriver> {
    Box::new(LsearchLookup::new(LsearchType::Wild))
}

/// Create a `nwildlsearch` (NWILD) driver instance.
fn create_nwildlsearch() -> Box<dyn LookupDriver> {
    Box::new(LsearchLookup::new(LsearchType::NWild))
}

/// Create an `iplsearch` (IP) driver instance.
fn create_iplsearch() -> Box<dyn LookupDriver> {
    Box::new(LsearchLookup::new(LsearchType::Ip))
}

// ---------------------------------------------------------------------------
// Compile-time driver registration via `inventory`
// ---------------------------------------------------------------------------
// Each variant is registered as a separate factory so that the config parser
// can resolve "lsearch", "wildlsearch", "nwildlsearch", and "iplsearch"
// independently.  This replaces the C `lsearch_lookup_module_info` array
// containing four `lookup_info` structs.

inventory::submit! {
    LookupDriverFactory {
        name: "lsearch",
        create: create_lsearch_plain,
        lookup_type: LookupType::ABS_FILE,
        avail_string: None,
    }
}

inventory::submit! {
    LookupDriverFactory {
        name: "wildlsearch",
        create: create_wildlsearch,
        lookup_type: LookupType::ABS_FILE,
        avail_string: None,
    }
}

inventory::submit! {
    LookupDriverFactory {
        name: "nwildlsearch",
        create: create_nwildlsearch,
        lookup_type: LookupType::ABS_FILE,
        avail_string: None,
    }
}

inventory::submit! {
    LookupDriverFactory {
        name: "iplsearch",
        create: create_iplsearch,
        lookup_type: LookupType::ABS_FILE,
        avail_string: None,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Key parsing tests --------------------------------------------------

    #[test]
    fn parse_unquoted_key_colon_separator() {
        let (key, rest) = LsearchLookup::parse_key("myhost: some-value");
        assert_eq!(key, "myhost");
        assert_eq!(rest, ": some-value");
    }

    #[test]
    fn parse_unquoted_key_whitespace_separator() {
        let (key, rest) = LsearchLookup::parse_key("myhost  some-value");
        assert_eq!(key, "myhost");
        assert_eq!(rest, "  some-value");
    }

    #[test]
    fn parse_quoted_key_simple() {
        let (key, rest) = LsearchLookup::parse_key("\"my host\": value");
        assert_eq!(key, "my host");
        assert_eq!(rest, ": value");
    }

    #[test]
    fn parse_quoted_key_with_escapes() {
        let (key, _) = LsearchLookup::parse_key("\"line\\none\": v");
        assert_eq!(key, "line\none");
    }

    #[test]
    fn parse_quoted_key_escaped_quote() {
        let (key, rest) = LsearchLookup::parse_key("\"say \\\"hi\\\"\": val");
        assert_eq!(key, "say \"hi\"");
        assert_eq!(rest, ": val");
    }

    #[test]
    fn parse_quoted_key_unterminated() {
        let (key, rest) = LsearchLookup::parse_key("\"unterminated");
        assert_eq!(key, "unterminated");
        assert_eq!(rest, "");
    }

    // -- Separator skipping -------------------------------------------------

    #[test]
    fn skip_separator_colon() {
        assert_eq!(LsearchLookup::skip_separator(": value"), "value");
    }

    #[test]
    fn skip_separator_spaces_colon() {
        assert_eq!(LsearchLookup::skip_separator("  :  value"), "value");
    }

    #[test]
    fn skip_separator_no_colon() {
        assert_eq!(LsearchLookup::skip_separator("  value"), "value");
    }

    // -- Plain matching -----------------------------------------------------

    #[test]
    fn match_plain_caseless() {
        assert!(LsearchLookup::match_plain("MyHost", "myhost"));
        assert!(LsearchLookup::match_plain("MYHOST", "myhost"));
        assert!(!LsearchLookup::match_plain("myhos", "myhost"));
        assert!(!LsearchLookup::match_plain("myhost2", "myhost"));
    }

    // -- Glob / regex matching ----------------------------------------------

    #[test]
    fn match_wild_glob_star() {
        assert!(LsearchLookup::match_wild(
            "anything.example.com",
            "*.example.com"
        ));
        assert!(!LsearchLookup::match_wild("example.com", "*.example.com"));
    }

    #[test]
    fn match_wild_glob_question() {
        assert!(LsearchLookup::match_wild("ab", "a?"));
        assert!(!LsearchLookup::match_wild("abc", "a?"));
    }

    #[test]
    fn match_wild_regex() {
        assert!(LsearchLookup::match_wild(
            "host123.example.com",
            "^host[0-9]+\\.example\\.com$"
        ));
        assert!(!LsearchLookup::match_wild(
            "hostABC.example.com",
            "^host[0-9]+\\.example\\.com$"
        ));
    }

    #[test]
    fn match_nwild_exact_caseless() {
        assert!(LsearchLookup::match_nwild("Hello", "hello"));
    }

    // -- IP matching --------------------------------------------------------

    #[test]
    fn match_ip_wildcard() {
        assert!(LsearchLookup::match_ip("10.0.0.1", "*"));
    }

    #[test]
    fn match_ip_exact_v4() {
        assert!(LsearchLookup::match_ip("192.168.1.1", "192.168.1.1"));
        assert!(!LsearchLookup::match_ip("192.168.1.2", "192.168.1.1"));
    }

    #[test]
    fn match_ip_cidr_v4() {
        assert!(LsearchLookup::match_ip("192.168.1.50", "192.168.1.0/24"));
        assert!(!LsearchLookup::match_ip("192.168.2.1", "192.168.1.0/24"));
    }

    #[test]
    fn match_ip_cidr_v6() {
        assert!(LsearchLookup::match_ip("2001:db8::1", "2001:db8::/32"));
        assert!(!LsearchLookup::match_ip("2001:db9::1", "2001:db8::/32"));
    }

    #[test]
    fn match_ip_mixed_families() {
        assert!(!LsearchLookup::match_ip("::1", "127.0.0.1"));
    }

    #[test]
    fn ip_cidr_mask_zero() {
        // /0 matches everything in the same address family
        assert!(LsearchLookup::match_ip("10.99.99.99", "0.0.0.0/0"));
    }

    // -- IP input validation ------------------------------------------------

    #[test]
    fn is_valid_ip_input_tests() {
        assert!(LsearchLookup::is_valid_ip_input("*"));
        assert!(LsearchLookup::is_valid_ip_input("10.0.0.1"));
        assert!(LsearchLookup::is_valid_ip_input("192.168.1.0/24"));
        assert!(LsearchLookup::is_valid_ip_input("::1"));
        assert!(LsearchLookup::is_valid_ip_input("2001:db8::/32"));
        assert!(!LsearchLookup::is_valid_ip_input("hostname"));
        assert!(!LsearchLookup::is_valid_ip_input(""));
    }

    // -- Glob-to-regex conversion -------------------------------------------

    #[test]
    fn glob_to_regex_conversion() {
        let re = LsearchLookup::glob_to_regex("*.example.com");
        assert_eq!(re, "(?i)^.*\\.example\\.com$");

        let re2 = LsearchLookup::glob_to_regex("host?");
        assert_eq!(re2, "(?i)^host.$");
    }

    // -- ip_in_network edge cases -------------------------------------------

    #[test]
    fn ip_in_network_invalid_mask() {
        assert!(!LsearchLookup::ip_in_network(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.0/33"
        ));
    }

    #[test]
    fn ip_in_network_no_mask() {
        assert!(LsearchLookup::ip_in_network(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.1"
        ));
        assert!(!LsearchLookup::ip_in_network(
            "10.0.0.2".parse().unwrap(),
            "10.0.0.1"
        ));
    }

    // -- LsearchType display ------------------------------------------------

    #[test]
    fn lsearch_type_display() {
        assert_eq!(format!("{}", LsearchType::Plain), "lsearch");
        assert_eq!(format!("{}", LsearchType::Wild), "wildlsearch");
        assert_eq!(format!("{}", LsearchType::NWild), "nwildlsearch");
        assert_eq!(format!("{}", LsearchType::Ip), "iplsearch");
    }

    // -- Driver metadata ----------------------------------------------------

    #[test]
    fn driver_name_matches_variant() {
        let plain = LsearchLookup::new(LsearchType::Plain);
        assert_eq!(plain.driver_name(), "lsearch");

        let wild = LsearchLookup::new(LsearchType::Wild);
        assert_eq!(wild.driver_name(), "wildlsearch");

        let nwild = LsearchLookup::new(LsearchType::NWild);
        assert_eq!(nwild.driver_name(), "nwildlsearch");

        let ip = LsearchLookup::new(LsearchType::Ip);
        assert_eq!(ip.driver_name(), "iplsearch");
    }

    #[test]
    fn lookup_type_is_abs_file() {
        for variant in &[
            LsearchType::Plain,
            LsearchType::Wild,
            LsearchType::NWild,
            LsearchType::Ip,
        ] {
            let lookup = LsearchLookup::new(*variant);
            assert_eq!(lookup.lookup_type(), LookupType::ABS_FILE);
        }
    }

    #[test]
    fn version_report_only_plain() {
        let plain = LsearchLookup::new(LsearchType::Plain);
        assert!(plain.version_report().is_some());

        for variant in &[LsearchType::Wild, LsearchType::NWild, LsearchType::Ip] {
            let lookup = LsearchLookup::new(*variant);
            assert!(lookup.version_report().is_none());
        }
    }

    #[test]
    fn quote_returns_none() {
        let lookup = LsearchLookup::new(LsearchType::Plain);
        assert!(lookup.quote("key", None).is_none());
    }
}
