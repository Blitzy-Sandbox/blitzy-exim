//! Name=value quoting helper for multi-column lookup results.
//!
//! This module replaces `src/src/lookups/lf_quote.c` (64 lines) and provides
//! consistent formatting of `name=value` pairs used by lookup backends that
//! return multi-column result sets (SQL queries, LDAP attribute lists, etc.).
//!
//! # Format
//!
//! Each call appends one `name=value ` pair (with trailing space) to the result
//! buffer. The value is quoted with double-quote delimiters and backslash
//! escaping when any of the following conditions is true:
//!
//! - The value is empty (zero length).
//! - The value is `None` (treated as empty string).
//! - The value contains whitespace: ASCII space (0x20), tab (0x09),
//!   newline (0x0A), or carriage return (0x0D).
//! - The value starts with a double-quote character (`"`).
//!
//! Inside quoted values, the only escape sequences produced are `\"` (escaped
//! double-quote) and `\\` (escaped backslash). All other characters are passed
//! through verbatim.
//!
//! Unquoted values are appended raw without any transformation.
//!
//! A trailing space character is **always** appended after the value (whether
//! quoted or unquoted), which allows the consumer to split the result on
//! whitespace and parse individual `name=value` tokens.
//!
//! # Consumers
//!
//! The following lookup backends use this function:
//! - `sqlite.rs` — SQLite multi-column results
//! - `mysql.rs` — MySQL multi-column results
//! - `pgsql.rs` — PostgreSQL multi-column results
//! - `oracle.rs` — Oracle multi-column results
//! - `ldap.rs` — LDAP attribute pair formatting
//!
//! # Examples
//!
//! ```
//! use exim_lookups::helpers::quote::lf_quote;
//!
//! let mut buf = String::new();
//!
//! // Simple unquoted value:
//! lf_quote("host", Some("example.com"), &mut buf);
//! assert_eq!(buf, "host=example.com ");
//!
//! // Value containing a space → quoted:
//! buf.clear();
//! lf_quote("name", Some("John Doe"), &mut buf);
//! assert_eq!(buf, r#"name="John Doe" "#);
//!
//! // Empty value → quoted:
//! buf.clear();
//! lf_quote("field", Some(""), &mut buf);
//! assert_eq!(buf, r#"field="" "#);
//!
//! // None value → treated as empty → quoted:
//! buf.clear();
//! lf_quote("field", None, &mut buf);
//! assert_eq!(buf, r#"field="" "#);
//!
//! // Value with backslash only (no whitespace) → unquoted:
//! buf.clear();
//! lf_quote("path", Some(r"C:\dir"), &mut buf);
//! assert_eq!(buf, r"path=C:\dir ");
//! ```

/// Determine whether a string value requires quoting.
///
/// A value needs quoting when any of the following is true:
/// - It is empty (zero length).
/// - It contains ASCII whitespace: space (0x20), horizontal tab (0x09),
///   newline (0x0A), or carriage return (0x0D).
/// - It starts with a double-quote character (`"`, 0x22).
///
/// This exactly mirrors the C conditional at `lf_quote.c` line 47:
/// ```c
/// if (value[0] == 0 || Ustrpbrk(value, " \t\n\r") != NULL || value[0] == '"')
/// ```
fn needs_quoting(value: &str) -> bool {
    value.is_empty() || value.contains([' ', '\t', '\n', '\r']) || value.starts_with('"')
}

/// Determine whether a byte-slice value requires quoting.
///
/// Byte-level equivalent of [`needs_quoting`] for use with
/// [`lf_quote_bytes`]. The same conditions apply but operate on raw `u8`
/// values rather than Rust `char`.
fn needs_quoting_bytes(value: &[u8]) -> bool {
    value.is_empty()
        || value
            .iter()
            .any(|&b| b == b' ' || b == b'\t' || b == b'\n' || b == b'\r')
        || value.first() == Some(&b'"')
}

/// Append a `name=value` pair to the result string, quoting the value if
/// necessary.
///
/// This is the primary Rust replacement for the C function
/// `lf_quote(uschar *name, uschar *value, int vlength, gstring *result)`
/// defined in `src/src/lookups/lf_quote.c`.
///
/// # Parameters
///
/// - `name` — The field name (e.g., a SQL column name or LDAP attribute).
/// - `value` — The data value. `None` is treated as an empty string (matching
///   the C code's NULL → `""` fallback at lines 38–42).
/// - `result` — The mutable string buffer to append to. This replaces the
///   C `gstring *` expanding-string pattern with standard Rust
///   `String::push` / `String::push_str`.
///
/// # Quoting Rules
///
/// The value is wrapped in double quotes (`"..."`) with backslash escaping
/// when:
/// - The value is empty, OR
/// - The value contains whitespace (space, tab, newline, carriage return), OR
/// - The value starts with `"`.
///
/// Inside quoted values, `"` becomes `\"` and `\` becomes `\\`. All other
/// characters are passed through unmodified.
///
/// A single trailing space is **always** appended after the (possibly quoted)
/// value.
///
/// # Examples
///
/// ```
/// use exim_lookups::helpers::quote::lf_quote;
///
/// let mut buf = String::new();
///
/// // Unquoted:
/// lf_quote("host", Some("example.com"), &mut buf);
/// assert_eq!(buf, "host=example.com ");
///
/// // Quoted (contains space):
/// buf.clear();
/// lf_quote("name", Some("John Doe"), &mut buf);
/// assert_eq!(buf, r#"name="John Doe" "#);
///
/// // Quoted (empty):
/// buf.clear();
/// lf_quote("field", Some(""), &mut buf);
/// assert_eq!(buf, r#"field="" "#);
///
/// // Quoted (escape double-quote):
/// buf.clear();
/// lf_quote("val", Some(r#"say "hello""#), &mut buf);
/// assert_eq!(buf, r#"val="say \"hello\"" "#);
///
/// // Backslash only (no whitespace) → unquoted:
/// buf.clear();
/// lf_quote("path", Some(r"C:\dir"), &mut buf);
/// assert_eq!(buf, r"path=C:\dir ");
///
/// // None value → treated as empty → quoted:
/// buf.clear();
/// lf_quote("field", None, &mut buf);
/// assert_eq!(buf, r#"field="" "#);
/// ```
pub fn lf_quote(name: &str, value: Option<&str>, result: &mut String) {
    // Append "name=" prefix (C line 34: string_append(result, 2, name, US"="))
    result.push_str(name);
    result.push('=');

    // Handle None → empty string (C lines 38–42)
    let val = value.unwrap_or("");

    if needs_quoting(val) {
        // Quoted output (C lines 49–56)
        result.push('"');
        for ch in val.chars() {
            if ch == '"' || ch == '\\' {
                result.push('\\');
            }
            result.push(ch);
        }
        result.push('"');
    } else {
        // Unquoted output (C lines 58–59)
        result.push_str(val);
    }

    // Always append trailing space (C line 61)
    result.push(' ');
}

/// Convenience wrapper that creates a new `String` and returns the formatted
/// `name=value ` pair.
///
/// This is a shorthand for creating a `String`, calling [`lf_quote`], and
/// returning the result. Useful when constructing a single-pair output or
/// when the caller does not already have a mutable buffer.
///
/// # Parameters
///
/// - `name` — The field name.
/// - `value` — The data value (`None` → empty string, quoted).
///
/// # Returns
///
/// A `String` containing exactly one `name=value ` pair with trailing space.
///
/// # Examples
///
/// ```
/// use exim_lookups::helpers::quote::lf_quote_to_string;
///
/// assert_eq!(lf_quote_to_string("host", Some("mx.example.com")),
///            "host=mx.example.com ");
///
/// assert_eq!(lf_quote_to_string("field", None),
///            r#"field="" "#);
/// ```
pub fn lf_quote_to_string(name: &str, value: Option<&str>) -> String {
    let mut result = String::new();
    lf_quote(name, value, &mut result);
    result
}

/// Append a `name=value` pair to a byte buffer, quoting the value if
/// necessary.
///
/// This is the byte-level counterpart to [`lf_quote`], provided for full
/// behavioral parity with the C implementation which operates on raw byte
/// arrays (`uschar *` with explicit `vlength`). Unlike [`lf_quote`], this
/// function:
///
/// - Accepts `value` as `&[u8]` instead of `&str`, allowing non-UTF-8 data.
/// - Writes to a `Vec<u8>` instead of `String`.
///
/// The quoting and escaping logic is identical:
/// - Quote when empty, contains whitespace bytes, or starts with `"` (0x22).
/// - Escape `"` (0x22) and `\` (0x5C) inside quoted values.
/// - Always append a trailing space byte (0x20).
///
/// # Parameters
///
/// - `name` — The field name (UTF-8). This is always valid text in practice
///   since SQL column names and LDAP attributes are ASCII identifiers.
/// - `value` — The raw data bytes. An empty slice behaves like C `NULL`
///   (produces `name="" `).
/// - `result` — The mutable byte buffer to append to.
///
/// # Examples
///
/// ```
/// use exim_lookups::helpers::quote::lf_quote_bytes;
///
/// let mut buf: Vec<u8> = Vec::new();
/// lf_quote_bytes("col", b"simple", &mut buf);
/// assert_eq!(buf, b"col=simple ");
///
/// buf.clear();
/// lf_quote_bytes("col", b"has space", &mut buf);
/// assert_eq!(buf, br#"col="has space" "#);
///
/// buf.clear();
/// lf_quote_bytes("col", b"", &mut buf);
/// assert_eq!(buf, br#"col="" "#);
/// ```
pub fn lf_quote_bytes(name: &str, value: &[u8], result: &mut Vec<u8>) {
    // Append "name=" prefix
    result.extend_from_slice(name.as_bytes());
    result.push(b'=');

    if needs_quoting_bytes(value) {
        // Quoted output
        result.push(b'"');
        for &byte in value {
            if byte == b'"' || byte == b'\\' {
                result.push(b'\\');
            }
            result.push(byte);
        }
        result.push(b'"');
    } else {
        // Unquoted output
        result.extend_from_slice(value);
    }

    // Always append trailing space
    result.push(b' ');
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── needs_quoting tests ───────────────────────────────────────────────

    #[test]
    fn test_needs_quoting_empty() {
        assert!(needs_quoting(""));
    }

    #[test]
    fn test_needs_quoting_space() {
        assert!(needs_quoting("hello world"));
    }

    #[test]
    fn test_needs_quoting_tab() {
        assert!(needs_quoting("hello\tworld"));
    }

    #[test]
    fn test_needs_quoting_newline() {
        assert!(needs_quoting("line1\nline2"));
    }

    #[test]
    fn test_needs_quoting_carriage_return() {
        assert!(needs_quoting("line1\rline2"));
    }

    #[test]
    fn test_needs_quoting_starts_with_quote() {
        assert!(needs_quoting("\"already quoted"));
    }

    #[test]
    fn test_needs_quoting_simple_value() {
        assert!(!needs_quoting("simple"));
    }

    #[test]
    fn test_needs_quoting_alphanumeric() {
        assert!(!needs_quoting("abc123"));
    }

    #[test]
    fn test_needs_quoting_dot_separated() {
        assert!(!needs_quoting("mail.example.com"));
    }

    #[test]
    fn test_needs_quoting_with_equals() {
        assert!(!needs_quoting("foo=bar"));
    }

    // ── lf_quote tests (str-based) ───────────────────────────────────────

    #[test]
    fn test_lf_quote_simple_unquoted() {
        let mut buf = String::new();
        lf_quote("host", Some("example.com"), &mut buf);
        assert_eq!(buf, "host=example.com ");
    }

    #[test]
    fn test_lf_quote_value_with_space() {
        let mut buf = String::new();
        lf_quote("name", Some("John Doe"), &mut buf);
        assert_eq!(buf, r#"name="John Doe" "#);
    }

    #[test]
    fn test_lf_quote_empty_value() {
        let mut buf = String::new();
        lf_quote("field", Some(""), &mut buf);
        assert_eq!(buf, r#"field="" "#);
    }

    #[test]
    fn test_lf_quote_none_value() {
        let mut buf = String::new();
        lf_quote("field", None, &mut buf);
        assert_eq!(buf, r#"field="" "#);
    }

    #[test]
    fn test_lf_quote_backslash_unquoted() {
        // A value with backslash but no whitespace, not empty, and not starting
        // with `"` is NOT quoted — the C code only checks for whitespace, empty,
        // or leading `"`.
        let mut buf = String::new();
        lf_quote("path", Some(r"C:\dir"), &mut buf);
        assert_eq!(buf, r"path=C:\dir ");
    }

    #[test]
    fn test_lf_quote_double_quote_escape() {
        let mut buf = String::new();
        lf_quote("val", Some(r#"say "hi""#), &mut buf);
        assert_eq!(buf, r#"val="say \"hi\"" "#);
    }

    #[test]
    fn test_lf_quote_value_starting_with_quote() {
        let mut buf = String::new();
        lf_quote("val", Some(r#""already""#), &mut buf);
        assert_eq!(buf, r#"val="\"already\"" "#);
    }

    #[test]
    fn test_lf_quote_tab_in_value() {
        let mut buf = String::new();
        lf_quote("data", Some("col1\tcol2"), &mut buf);
        assert_eq!(buf, "data=\"col1\tcol2\" ");
    }

    #[test]
    fn test_lf_quote_newline_in_value() {
        let mut buf = String::new();
        lf_quote("data", Some("line1\nline2"), &mut buf);
        assert_eq!(buf, "data=\"line1\nline2\" ");
    }

    #[test]
    fn test_lf_quote_carriage_return_in_value() {
        let mut buf = String::new();
        lf_quote("data", Some("line1\rline2"), &mut buf);
        assert_eq!(buf, "data=\"line1\rline2\" ");
    }

    #[test]
    fn test_lf_quote_mixed_no_whitespace_unquoted() {
        // Value contains `"` and `\` but NO whitespace and does NOT start with
        // `"`, so the C code leaves it unquoted.
        let mut buf = String::new();
        lf_quote("val", Some(r#"a"b\c"#), &mut buf);
        assert_eq!(buf, "val=a\"b\\c ");
    }

    #[test]
    fn test_lf_quote_trailing_space_always_present() {
        let mut buf = String::new();
        lf_quote("a", Some("b"), &mut buf);
        assert!(buf.ends_with(' '), "trailing space must always be present");
    }

    #[test]
    fn test_lf_quote_appends_to_existing_buffer() {
        let mut buf = String::from("prev ");
        lf_quote("host", Some("mx1.example.com"), &mut buf);
        assert_eq!(buf, "prev host=mx1.example.com ");
    }

    #[test]
    fn test_lf_quote_multiple_appends() {
        let mut buf = String::new();
        lf_quote("host", Some("mx.example.com"), &mut buf);
        lf_quote("port", Some("25"), &mut buf);
        lf_quote("name", Some("John Doe"), &mut buf);
        assert_eq!(buf, r#"host=mx.example.com port=25 name="John Doe" "#);
    }

    #[test]
    fn test_lf_quote_only_backslash() {
        // Backslash alone doesn't trigger quoting — no whitespace, not empty,
        // doesn't start with `"`.
        let mut buf = String::new();
        lf_quote("v", Some(r"\"), &mut buf);
        assert_eq!(buf, r"v=\ ");
    }

    #[test]
    fn test_lf_quote_backslash_with_space_quoted() {
        // When quoting IS triggered (by whitespace), backslash gets escaped.
        let mut buf = String::new();
        lf_quote("path", Some(r"C:\my dir"), &mut buf);
        assert_eq!(buf, r#"path="C:\\my dir" "#);
    }

    #[test]
    fn test_lf_quote_only_quote_char() {
        let mut buf = String::new();
        lf_quote("v", Some("\""), &mut buf);
        // Starts with `"` → must be quoted, the `"` itself is escaped
        assert_eq!(buf, r#"v="\"" "#);
    }

    #[test]
    fn test_lf_quote_unicode_unquoted() {
        let mut buf = String::new();
        lf_quote("text", Some("café"), &mut buf);
        assert_eq!(buf, "text=café ");
    }

    #[test]
    fn test_lf_quote_unicode_with_space() {
        let mut buf = String::new();
        lf_quote("text", Some("café latte"), &mut buf);
        assert_eq!(buf, "text=\"café latte\" ");
    }

    // ── lf_quote_to_string tests ─────────────────────────────────────────

    #[test]
    fn test_lf_quote_to_string_simple() {
        assert_eq!(
            lf_quote_to_string("host", Some("mx.example.com")),
            "host=mx.example.com "
        );
    }

    #[test]
    fn test_lf_quote_to_string_none() {
        assert_eq!(lf_quote_to_string("field", None), r#"field="" "#);
    }

    #[test]
    fn test_lf_quote_to_string_quoted() {
        assert_eq!(
            lf_quote_to_string("name", Some("John Doe")),
            r#"name="John Doe" "#
        );
    }

    // ── lf_quote_bytes tests ─────────────────────────────────────────────

    #[test]
    fn test_lf_quote_bytes_simple() {
        let mut buf: Vec<u8> = Vec::new();
        lf_quote_bytes("col", b"simple", &mut buf);
        assert_eq!(buf, b"col=simple ");
    }

    #[test]
    fn test_lf_quote_bytes_empty() {
        let mut buf: Vec<u8> = Vec::new();
        lf_quote_bytes("col", b"", &mut buf);
        assert_eq!(buf, b"col=\"\" ");
    }

    #[test]
    fn test_lf_quote_bytes_with_space() {
        let mut buf: Vec<u8> = Vec::new();
        lf_quote_bytes("col", b"has space", &mut buf);
        assert_eq!(buf, br#"col="has space" "#);
    }

    #[test]
    fn test_lf_quote_bytes_backslash_unquoted() {
        // Backslash alone does not trigger quoting — no whitespace, not empty,
        // doesn't start with `"`.
        let mut buf: Vec<u8> = Vec::new();
        lf_quote_bytes("p", b"C:\\dir", &mut buf);
        assert_eq!(buf, b"p=C:\\dir ");
    }

    #[test]
    fn test_lf_quote_bytes_double_quote() {
        let mut buf: Vec<u8> = Vec::new();
        lf_quote_bytes("v", b"say \"hi\"", &mut buf);
        assert_eq!(buf, br#"v="say \"hi\"" "#);
    }

    #[test]
    fn test_lf_quote_bytes_non_utf8() {
        // Value contains bytes 0x80 0xFF which are not valid UTF-8.
        // The byte-level function must handle them without panicking.
        let mut buf: Vec<u8> = Vec::new();
        lf_quote_bytes("bin", &[0x80, 0xFF], &mut buf);
        // No whitespace, not empty, doesn't start with `"` → unquoted
        assert_eq!(&buf[..4], b"bin=");
        assert_eq!(buf[4], 0x80);
        assert_eq!(buf[5], 0xFF);
        assert_eq!(buf[6], b' ');
    }

    #[test]
    fn test_lf_quote_bytes_trailing_space_always() {
        let mut buf: Vec<u8> = Vec::new();
        lf_quote_bytes("k", b"v", &mut buf);
        assert_eq!(*buf.last().expect("non-empty"), b' ');
    }

    #[test]
    fn test_lf_quote_bytes_appends() {
        let mut buf: Vec<u8> = Vec::new();
        lf_quote_bytes("a", b"1", &mut buf);
        lf_quote_bytes("b", b"2", &mut buf);
        assert_eq!(buf, b"a=1 b=2 ");
    }

    // ── needs_quoting_bytes tests ────────────────────────────────────────

    #[test]
    fn test_needs_quoting_bytes_empty() {
        assert!(needs_quoting_bytes(b""));
    }

    #[test]
    fn test_needs_quoting_bytes_space() {
        assert!(needs_quoting_bytes(b"a b"));
    }

    #[test]
    fn test_needs_quoting_bytes_tab() {
        assert!(needs_quoting_bytes(b"a\tb"));
    }

    #[test]
    fn test_needs_quoting_bytes_starts_with_quote() {
        assert!(needs_quoting_bytes(b"\"test"));
    }

    #[test]
    fn test_needs_quoting_bytes_simple() {
        assert!(!needs_quoting_bytes(b"simple"));
    }

    #[test]
    fn test_needs_quoting_bytes_non_utf8() {
        // 0x80 0xFF — no whitespace, not empty, doesn't start with `"`
        assert!(!needs_quoting_bytes(&[0x80, 0xFF]));
    }
}
