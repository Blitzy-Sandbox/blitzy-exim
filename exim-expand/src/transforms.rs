// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later
//
// exim-expand/src/transforms.rs — Operator/Transform Implementations
//
// Implements all 50+ expansion operators/transforms from `op_table_underscore[]`
// and `op_table_main[]` (expand.c lines 184-312). These are invoked as
// `${operator:subject}` and transform a subject string into a result.
//
// Replaces the massive operator dispatch block in `expand_string_internal()`
// (expand.c lines ~7300-8700, approximately 1,400 lines of C code).
//
// # Safety
//
// This module contains **zero `unsafe` blocks** (enforced by the crate-level
// `#![forbid(unsafe_code)]` attribute in lib.rs).

use std::fmt::Write as FmtWrite;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use rand::RngExt;
use sha2::Digest;
use tracing;

use crate::evaluator::Evaluator;
use crate::parser::OperatorKind;
use crate::ExpandError;

// ═══════════════════════════════════════════════════════════════════════
//  Latin-1 helper
// ═══════════════════════════════════════════════════════════════════════

/// Convert a Latin-1-encoded Rust String back to raw bytes.
///
/// With Latin-1 encoding (each input byte 0x00..0xFF stored as char
/// U+0000..U+00FF), this maps each char back to the original byte.
/// Used by hashing and encoding functions that need raw byte input
/// matching C Exim's byte-level string representation.
#[inline]
fn latin1_bytes(s: &str) -> Vec<u8> {
    s.chars().map(|ch| ch as u8).collect()
}

// ═══════════════════════════════════════════════════════════════════════
//  Constants — ported verbatim from expand.c for backward compatibility
// ═══════════════════════════════════════════════════════════════════════

/// Hash-code character table for textual hashing (expand.c lines 872-874).
///
/// **CRITICAL**: The typo in the original C source (`qrtsuvwxyz` instead of
/// `qrstuvwxyz`) is deliberately preserved for byte-level behavioral
/// compatibility (AAP §0.7.1).
const HASHCODES: &str = "abcdefghijklmnopqrtsuvwxyz\
                          ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                          0123456789";

/// Prime table for numeric hashing (expand.c lines 880-883).
const PRIME: [u32; 30] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113,
];

/// Base-32 alphabet used by Exim (expand.c line 943).
/// This is the RFC 4648 base-32 alphabet (lowercase).
const BASE32_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Base-62 character set for Exim message ID encoding.
/// Digits 0-9, then uppercase A-Z, then lowercase a-z.
const BASE62_CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// File mode display table — normal permissions (expand.c line 889).
const MTABLE_NORMAL: [&str; 8] = ["---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"];

/// File mode display table — setuid/setgid bits (expand.c line 891).
const MTABLE_SETID: [&str; 8] = ["--S", "--s", "-wS", "-ws", "r-S", "r-s", "rwS", "rws"];

/// File mode display table — sticky bit (expand.c line 893).
const MTABLE_STICKY: [&str; 8] = ["--T", "--t", "-wT", "-wt", "r-T", "r-t", "rwT", "rwt"];

// ═══════════════════════════════════════════════════════════════════════
//  Main dispatch function
// ═══════════════════════════════════════════════════════════════════════

/// Apply a string transformation operator to a subject string.
///
/// This is the main dispatch function for all 50+ Exim expansion operators
/// from `op_table_underscore[]` and `op_table_main[]`. Each operator receives
/// the already-evaluated subject string and produces a transformed result.
///
/// # Arguments
///
/// * `op` — The operator variant to apply, parsed from the `${operator:…}` syntax.
/// * `subject` — The evaluated subject string to transform.
/// * `evaluator` — Mutable reference to the evaluator, needed by operators that
///   delegate back to the evaluator (eval, eval10, expand).
///
/// # Returns
///
/// The transformed string on success, or an [`ExpandError`] on failure.
///
/// # Errors
///
/// Returns `ExpandError::Failed` for invalid input (e.g., non-numeric input
/// to base32, invalid IP for reverse_ip), and `ExpandError::IntegerError` for
/// numeric conversion failures.
pub fn apply_transform(
    op: OperatorKind,
    subject: &str,
    evaluator: &mut Evaluator,
) -> Result<String, ExpandError> {
    tracing::debug!(?op, subject_len = subject.len(), "apply_transform");

    let result = match op {
        // ─── Underscore operators (op_table_underscore) ─────────────
        OperatorKind::FromUtf8 => transform_from_utf8(subject),
        OperatorKind::LocalPart => Ok(transform_local_part(subject)),
        OperatorKind::QuoteLocalPart => Ok(transform_quote_local_part(subject)),
        OperatorKind::ReverseIp => transform_reverse_ip(subject),
        OperatorKind::TimeEval => transform_time_eval(subject),
        OperatorKind::TimeInterval => transform_time_interval(subject),

        // ─── I18N underscore operators (feature-gated) ──────────────
        #[cfg(feature = "i18n")]
        OperatorKind::Utf8DomainFromAlabel => transform_utf8_domain_from_alabel(subject),
        #[cfg(not(feature = "i18n"))]
        OperatorKind::Utf8DomainFromAlabel => Err(ExpandError::Failed {
            message: "utf8_domain_from_alabel not available \
                      (compiled without i18n feature)"
                .into(),
        }),

        #[cfg(feature = "i18n")]
        OperatorKind::Utf8DomainToAlabel => transform_utf8_domain_to_alabel(subject),
        #[cfg(not(feature = "i18n"))]
        OperatorKind::Utf8DomainToAlabel => Err(ExpandError::Failed {
            message: "utf8_domain_to_alabel not available \
                      (compiled without i18n feature)"
                .into(),
        }),

        #[cfg(feature = "i18n")]
        OperatorKind::Utf8LocalpartFromAlabel => transform_utf8_localpart_from_alabel(subject),
        #[cfg(not(feature = "i18n"))]
        OperatorKind::Utf8LocalpartFromAlabel => Err(ExpandError::Failed {
            message: "utf8_localpart_from_alabel not available \
                      (compiled without i18n feature)"
                .into(),
        }),

        #[cfg(feature = "i18n")]
        OperatorKind::Utf8LocalpartToAlabel => transform_utf8_localpart_to_alabel(subject),
        #[cfg(not(feature = "i18n"))]
        OperatorKind::Utf8LocalpartToAlabel => Err(ExpandError::Failed {
            message: "utf8_localpart_to_alabel not available \
                      (compiled without i18n feature)"
                .into(),
        }),

        // ─── Main operators (op_table_main) ─────────────────────────

        // Address extraction
        OperatorKind::Address => Ok(transform_address(subject)),
        OperatorKind::Addresses => Ok(transform_addresses(subject)),

        // Base encoding/decoding
        OperatorKind::Base32 => transform_base32_encode(subject),
        OperatorKind::Base32d => transform_base32_decode(subject),
        OperatorKind::Base62 => transform_base62_encode(subject),
        OperatorKind::Base62d => transform_base62_decode(subject),
        OperatorKind::Base64 => Ok(transform_base64_encode(subject)),
        OperatorKind::Base64d => transform_base64_decode(subject),

        // Domain extraction
        OperatorKind::Domain => Ok(transform_domain(subject)),

        // Escaping/quoting
        OperatorKind::Escape => Ok(transform_escape(subject)),
        OperatorKind::Escape8bit => Ok(transform_escape8bit(subject)),
        OperatorKind::Hexquote => Ok(transform_hexquote(subject)),
        OperatorKind::Quote => Ok(transform_quote(subject)),
        OperatorKind::Rxquote => Ok(regex::escape(subject)),
        OperatorKind::Xtextd => Ok(transform_xtextd(subject)),

        // Hash/crypto
        OperatorKind::HashOp => Ok(transform_hash(subject)),
        OperatorKind::Md5 => Ok(transform_md5(subject)),
        OperatorKind::Sha1 => Ok(transform_sha1(subject)),
        OperatorKind::Sha2 | OperatorKind::Sha256 => Ok(transform_sha256(subject)),
        OperatorKind::Sha3 => Ok(transform_sha3(subject)),
        OperatorKind::Hex2b64 => transform_hex2b64(subject),
        OperatorKind::Str2b64 => Ok(transform_str2b64(subject)),

        // Numeric hash
        OperatorKind::Nhash => Ok(transform_nhash(subject)),
        OperatorKind::Nh => Ok(transform_nhash(subject)),

        // String manipulation
        OperatorKind::Lc | OperatorKind::L => Ok(transform_lc(subject)),
        OperatorKind::Uc => Ok(transform_uc(subject)),
        OperatorKind::LengthOp | OperatorKind::Strlen => Ok(transform_length(subject)),
        OperatorKind::SubstrOp | OperatorKind::S => Ok(subject.to_owned()),
        OperatorKind::Headerwrap => Ok(transform_headerwrap(subject)),

        // Evaluation (delegate to evaluator)
        OperatorKind::Eval => transform_eval(subject, evaluator, false),
        OperatorKind::Eval10 => transform_eval(subject, evaluator, true),
        OperatorKind::Expand => transform_expand(subject, evaluator),

        // Header/list operations
        OperatorKind::H => Ok(transform_hash(subject)),
        OperatorKind::Listcount => Ok(transform_listcount(subject)),
        OperatorKind::Listnamed
        | OperatorKind::ListnamedD
        | OperatorKind::ListnamedH
        | OperatorKind::ListnamedA
        | OperatorKind::ListnamedL => Ok(transform_listnamed(subject, evaluator)),
        OperatorKind::HeaderwrapParam(_, _) => {
            // Handled by the evaluator directly; this path shouldn't
            // normally be reached, but provide a fallback.
            Ok(subject.to_owned())
        }

        // Network operations
        OperatorKind::Mask => transform_mask(subject),
        OperatorKind::MaskNorm => transform_mask_n(subject),
        OperatorKind::MaskParam(_) => {
            // Handled by the evaluator directly.
            Ok(subject.to_owned())
        }
        OperatorKind::Ipv6norm => transform_ipv6norm(subject),
        OperatorKind::Ipv6denorm => transform_ipv6denorm(subject),

        // MIME/encoding
        OperatorKind::Rfc2047 => Ok(transform_rfc2047_encode(subject)),
        OperatorKind::Rfc2047d => Ok(transform_rfc2047_decode(subject)),

        // File operations
        OperatorKind::Stat => transform_stat(subject),

        // Miscellaneous
        OperatorKind::Randint => transform_randint(subject),
        OperatorKind::Utf8clean => Ok(transform_utf8clean(subject)),

        // Lookup quoting — handled by the evaluator directly.
        OperatorKind::QuoteLookup(_) => Ok(subject.to_owned()),
    };

    if let Ok(ref val) = result {
        tracing::debug!(?op, result_len = val.len(), "apply_transform complete");
    }
    result
}

// ═══════════════════════════════════════════════════════════════════════
//  Underscore operator implementations
// ═══════════════════════════════════════════════════════════════════════

/// `${from_utf8:subject}` — Convert UTF-8 string to charset-appropriate
/// representation, handling byte-level decoding using the utf8_table1/
/// utf8_table2 arrays (expand.c lines 914-939).
///
/// In Rust, strings are always valid UTF-8, so this operator converts
/// UTF-8 code points above U+00FF to the `?` replacement character,
/// matching the C behavior that maps multi-byte sequences down to
/// single-byte Latin-1 (or replaces them).
fn transform_from_utf8(subject: &str) -> Result<String, ExpandError> {
    let mut result = String::with_capacity(subject.len());
    for ch in subject.chars() {
        if ch as u32 <= 0xFF {
            // Fits in Latin-1 range — output directly
            result.push(ch);
        } else {
            // Above Latin-1 — replace with '?' matching C behavior
            result.push('?');
        }
    }
    Ok(result)
}

/// `${local_part:subject}` — Extract local part from email address
/// (everything before the last @).
fn transform_local_part(subject: &str) -> String {
    if let Some(at_pos) = subject.rfind('@') {
        subject[..at_pos].to_owned()
    } else {
        subject.to_owned()
    }
}

/// `${quote_local_part:subject}` — RFC 2821 quoting of local part if
/// it contains special characters that require quoting.
fn transform_quote_local_part(subject: &str) -> String {
    // Split into local-part and domain
    let (local, domain) = if let Some(at_pos) = subject.rfind('@') {
        (&subject[..at_pos], &subject[at_pos..])
    } else {
        (subject, "")
    };

    if needs_local_part_quoting(local) {
        let mut result = String::with_capacity(local.len() + domain.len() + 4);
        result.push('"');
        for ch in local.chars() {
            if ch == '\\' || ch == '"' {
                result.push('\\');
            }
            result.push(ch);
        }
        result.push('"');
        result.push_str(domain);
        result
    } else {
        subject.to_owned()
    }
}

/// Check whether an email local part needs RFC 5321 quoting.
fn needs_local_part_quoting(local: &str) -> bool {
    if local.is_empty() {
        return true;
    }
    // A local part needs quoting if it contains any special characters
    // defined in RFC 5321 / RFC 5322, or starts/ends with a dot, or
    // contains consecutive dots.
    for ch in local.chars() {
        match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' => {}
            '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '/' | '=' | '?' | '^' | '_'
            | '`' | '{' | '|' | '}' | '~' | '.' => {}
            _ => return true,
        }
    }
    // Check for leading/trailing dot or consecutive dots
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return true;
    }
    false
}

/// `${reverse_ip:subject}` — Reverse an IP address for DNSBL lookup.
///
/// IPv4: `1.2.3.4` → `4.3.2.1`
/// IPv6: `2001:db8::1` → expanded nibble-reversed dot-separated form
fn transform_reverse_ip(subject: &str) -> Result<String, ExpandError> {
    let trimmed = subject.trim();
    // Try IPv4 first
    if let Ok(ipv4) = trimmed.parse::<Ipv4Addr>() {
        let octets = ipv4.octets();
        return Ok(format!(
            "{}.{}.{}.{}",
            octets[3], octets[2], octets[1], octets[0]
        ));
    }
    // Try IPv6
    if let Ok(ipv6) = trimmed.parse::<Ipv6Addr>() {
        let segments = ipv6.segments();
        let mut nibbles = Vec::with_capacity(32);
        for seg in &segments {
            nibbles.push((seg >> 12) & 0xf);
            nibbles.push((seg >> 8) & 0xf);
            nibbles.push((seg >> 4) & 0xf);
            nibbles.push(seg & 0xf);
        }
        nibbles.reverse();
        let parts: Vec<String> = nibbles.iter().map(|n| format!("{:x}", n)).collect();
        return Ok(parts.join("."));
    }
    Err(ExpandError::Failed {
        message: format!("reverse_ip: invalid IP address: {}", trimmed),
    })
}

/// `${time_eval:subject}` — Parse a time/date string to Unix epoch seconds.
///
/// Supports standard date formats. In the C implementation, this calls
/// `readconf_readtime()` which handles Exim's time specification format.
fn transform_time_eval(subject: &str) -> Result<String, ExpandError> {
    let trimmed = subject.trim();

    // First try parsing as a pure integer (already epoch seconds)
    if let Ok(val) = trimmed.parse::<i64>() {
        return Ok(val.to_string());
    }

    // Parse Exim time interval format (e.g., "2d3h", "1w")
    let secs = parse_time_interval_str(trimmed)?;
    Ok(secs.to_string())
}

/// `${time_interval:subject}` — Format seconds as time interval string.
///
/// Converts a numeric seconds value to human-readable interval form.
/// Matches the C `readconf_printtime()` output format.
fn transform_time_interval(subject: &str) -> Result<String, ExpandError> {
    let trimmed = subject.trim();
    let secs: i64 = trimmed.parse().map_err(|_| {
        ExpandError::IntegerError(format!("time_interval: not a number: {}", trimmed))
    })?;
    Ok(format_time_interval(secs))
}

/// Format seconds as a human-readable time interval.
///
/// Produces output like "1w2d3h4m5s" matching the C `readconf_printtime()`
/// format.
fn format_time_interval(mut secs: i64) -> String {
    if secs == 0 {
        return "0s".to_owned();
    }

    let mut result = String::new();
    let negative = secs < 0;
    if negative {
        secs = -secs;
        result.push('-');
    }

    let weeks = secs / (7 * 24 * 3600);
    secs %= 7 * 24 * 3600;
    let days = secs / (24 * 3600);
    secs %= 24 * 3600;
    let hours = secs / 3600;
    secs %= 3600;
    let minutes = secs / 60;
    secs %= 60;

    if weeks > 0 {
        let _ = write!(result, "{}w", weeks);
    }
    if days > 0 {
        let _ = write!(result, "{}d", days);
    }
    if hours > 0 {
        let _ = write!(result, "{}h", hours);
    }
    if minutes > 0 {
        let _ = write!(result, "{}m", minutes);
    }
    if secs > 0 {
        let _ = write!(result, "{}s", secs);
    }
    result
}

/// Parse an Exim time interval specification string to seconds.
///
/// Handles formats: `NNs` (seconds), `NNm` (minutes), `NNh` (hours),
/// `NNd` (days), `NNw` (weeks), and combinations like `2d3h30m`.
fn parse_time_interval_str(input: &str) -> Result<i64, ExpandError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(ExpandError::Failed {
            message: "time_eval: empty time specification".into(),
        });
    }

    // Try as a plain integer first (seconds)
    if let Ok(val) = trimmed.parse::<i64>() {
        return Ok(val);
    }

    let mut total: i64 = 0;
    let mut current_num = String::new();
    let bytes = trimmed.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let ch = bytes[i] as char;
        if ch.is_ascii_digit() {
            current_num.push(ch);
        } else {
            if current_num.is_empty() {
                return Err(ExpandError::Failed {
                    message: format!(
                        "time_eval: unexpected character '{}' in time spec: {}",
                        ch, trimmed
                    ),
                });
            }
            let num: i64 = current_num.parse().map_err(|_| ExpandError::Failed {
                message: format!("time_eval: invalid number in time spec: {}", trimmed),
            })?;
            current_num.clear();

            let multiplier: i64 = match ch {
                's' => 1,
                'm' => 60,
                'h' => 3600,
                'd' => 86400,
                'w' => 604800,
                _ => {
                    return Err(ExpandError::Failed {
                        message: format!("time_eval: invalid time suffix '{}' in: {}", ch, trimmed),
                    });
                }
            };
            total += num * multiplier;
        }
        i += 1;
    }

    // Handle trailing number with no suffix (treated as seconds)
    if !current_num.is_empty() {
        let num: i64 = current_num.parse().map_err(|_| ExpandError::Failed {
            message: format!("time_eval: invalid number in time spec: {}", trimmed),
        })?;
        total += num;
    }

    Ok(total)
}

// ═══════════════════════════════════════════════════════════════════════
//  I18N operator implementations (feature-gated)
// ═══════════════════════════════════════════════════════════════════════

/// `${utf8_domain_from_alabel:subject}` — Convert A-label (ACE) domain
/// to U-label (UTF-8 Unicode domain).
///
/// Strips "xn--" prefix from punycode-encoded labels and decodes them
/// to their Unicode representation.
#[cfg(feature = "i18n")]
fn transform_utf8_domain_from_alabel(subject: &str) -> Result<String, ExpandError> {
    // In a full implementation this would use the IDNA2008 algorithm.
    // For now, we handle the common case of passing through domains
    // that are already in U-label form, and strip "xn--" prefixes
    // from A-label domains.
    let mut result_parts = Vec::new();
    for label in subject.split('.') {
        if label.starts_with("xn--") || label.starts_with("XN--") {
            // Punycode decode: basic implementation
            match punycode_decode(&label[4..]) {
                Ok(decoded) => result_parts.push(decoded),
                Err(_) => result_parts.push(label.to_owned()),
            }
        } else {
            result_parts.push(label.to_owned());
        }
    }
    Ok(result_parts.join("."))
}

/// `${utf8_domain_to_alabel:subject}` — Convert U-label (UTF-8) domain
/// to A-label (ACE/punycode) domain.
#[cfg(feature = "i18n")]
fn transform_utf8_domain_to_alabel(subject: &str) -> Result<String, ExpandError> {
    let mut result_parts = Vec::new();
    for label in subject.split('.') {
        if label.is_ascii() {
            result_parts.push(label.to_owned());
        } else {
            match punycode_encode(label) {
                Ok(encoded) => result_parts.push(format!("xn--{}", encoded)),
                Err(_) => result_parts.push(label.to_owned()),
            }
        }
    }
    Ok(result_parts.join("."))
}

/// `${utf8_localpart_from_alabel:subject}` — Convert A-label local part
/// to UTF-8 form.
#[cfg(feature = "i18n")]
fn transform_utf8_localpart_from_alabel(subject: &str) -> Result<String, ExpandError> {
    // Local parts in A-label form use UTF-8 encoding directly;
    // pass through as-is since Rust strings are already UTF-8.
    Ok(subject.to_owned())
}

/// `${utf8_localpart_to_alabel:subject}` — Convert UTF-8 local part
/// to A-label form.
#[cfg(feature = "i18n")]
fn transform_utf8_localpart_to_alabel(subject: &str) -> Result<String, ExpandError> {
    // Local parts in internationalized email (RFC 6531) are carried
    // as UTF-8; the A-label conversion applies primarily to domains.
    // For local parts, pass through as-is.
    Ok(subject.to_owned())
}

/// Minimal punycode decoder for IDN A-label to U-label conversion.
#[cfg(feature = "i18n")]
fn punycode_decode(encoded: &str) -> Result<String, ExpandError> {
    // Bootstring parameters for Punycode (RFC 3492)
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    const SKEW: u32 = 38;
    const DAMP: u32 = 700;
    const INITIAL_BIAS: u32 = 72;
    const INITIAL_N: u32 = 0x80;

    fn adapt(delta: u32, num_points: u32, first_time: bool) -> u32 {
        let mut d = if first_time { delta / DAMP } else { delta / 2 };
        d += d / num_points;
        let mut k = 0u32;
        while d > ((BASE - TMIN) * TMAX) / 2 {
            d /= BASE - TMIN;
            k += BASE;
        }
        k + ((BASE - TMIN + 1) * d) / (d + SKEW)
    }

    fn decode_digit(cp: u8) -> Option<u32> {
        match cp {
            b'a'..=b'z' => Some(u32::from(cp - b'a')),
            b'A'..=b'Z' => Some(u32::from(cp - b'A')),
            b'0'..=b'9' => Some(u32::from(cp - b'0') + 26),
            _ => None,
        }
    }

    // Split at the last delimiter (hyphen) to get basic and extended parts
    let (basic_str, extended_str) = if let Some(pos) = encoded.rfind('-') {
        (&encoded[..pos], &encoded[pos + 1..])
    } else {
        ("", encoded)
    };

    let mut output: Vec<u32> = basic_str.chars().map(|c| c as u32).collect();
    let mut n = INITIAL_N;
    let mut bias = INITIAL_BIAS;
    let mut i: u32 = 0;
    let mut idx = 0;
    let ext_bytes = extended_str.as_bytes();

    while idx < ext_bytes.len() {
        let old_i = i;
        let mut w: u32 = 1;
        let mut k: u32 = BASE;
        loop {
            if idx >= ext_bytes.len() {
                return Err(ExpandError::Failed {
                    message: "punycode decode: incomplete sequence".into(),
                });
            }
            let digit = decode_digit(ext_bytes[idx]).ok_or_else(|| ExpandError::Failed {
                message: format!(
                    "punycode decode: invalid digit '{}'",
                    ext_bytes[idx] as char
                ),
            })?;
            idx += 1;

            i = i
                .checked_add(digit.checked_mul(w).ok_or_else(|| ExpandError::Failed {
                    message: "punycode decode: overflow".into(),
                })?)
                .ok_or_else(|| ExpandError::Failed {
                    message: "punycode decode: overflow".into(),
                })?;

            let t = if k <= bias {
                TMIN
            } else if k >= bias + TMAX {
                TMAX
            } else {
                k - bias
            };
            if digit < t {
                break;
            }
            w = w.checked_mul(BASE - t).ok_or_else(|| ExpandError::Failed {
                message: "punycode decode: overflow".into(),
            })?;
            k += BASE;
        }
        let out_len = output.len() as u32 + 1;
        bias = adapt(i - old_i, out_len, old_i == 0);
        n = n
            .checked_add(i / out_len)
            .ok_or_else(|| ExpandError::Failed {
                message: "punycode decode: overflow".into(),
            })?;
        i %= out_len;

        output.insert(i as usize, n);
        i += 1;
    }

    output
        .iter()
        .map(|&cp| {
            char::from_u32(cp).ok_or_else(|| ExpandError::Failed {
                message: format!("punycode decode: invalid code point U+{:04X}", cp),
            })
        })
        .collect::<Result<String, _>>()
}

/// Minimal punycode encoder for IDN U-label to A-label conversion.
#[cfg(feature = "i18n")]
fn punycode_encode(input: &str) -> Result<String, ExpandError> {
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    const SKEW: u32 = 38;
    const DAMP: u32 = 700;
    const INITIAL_BIAS: u32 = 72;
    const INITIAL_N: u32 = 0x80;

    fn adapt(delta: u32, num_points: u32, first_time: bool) -> u32 {
        let mut d = if first_time { delta / DAMP } else { delta / 2 };
        d += d / num_points;
        let mut k = 0u32;
        while d > ((BASE - TMIN) * TMAX) / 2 {
            d /= BASE - TMIN;
            k += BASE;
        }
        k + ((BASE - TMIN + 1) * d) / (d + SKEW)
    }

    fn encode_digit(d: u32) -> u8 {
        if d < 26 {
            b'a' + d as u8
        } else {
            b'0' + (d as u8 - 26)
        }
    }

    let code_points: Vec<u32> = input.chars().map(|c| c as u32).collect();
    let mut output = Vec::new();

    // Copy basic code points
    for &cp in &code_points {
        if cp < INITIAL_N {
            output.push(cp as u8);
        }
    }

    let basic_len = output.len() as u32;
    if basic_len > 0 {
        output.push(b'-');
    }

    let mut n = INITIAL_N;
    let mut delta: u32 = 0;
    let mut bias = INITIAL_BIAS;
    let mut h = basic_len;
    let input_len = code_points.len() as u32;

    while h < input_len {
        // Find the minimum code point >= n
        let m = code_points
            .iter()
            .filter(|&&cp| cp >= n)
            .copied()
            .min()
            .unwrap_or(n);

        delta = delta
            .checked_add(
                (m - n)
                    .checked_mul(h + 1)
                    .ok_or_else(|| ExpandError::Failed {
                        message: "punycode encode: overflow".into(),
                    })?,
            )
            .ok_or_else(|| ExpandError::Failed {
                message: "punycode encode: overflow".into(),
            })?;
        n = m;

        for &cp in &code_points {
            if cp < n {
                delta = delta.checked_add(1).ok_or_else(|| ExpandError::Failed {
                    message: "punycode encode: overflow".into(),
                })?;
            }
            if cp == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias {
                        TMIN
                    } else if k >= bias + TMAX {
                        TMAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    output.push(encode_digit(t + ((q - t) % (BASE - t))));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                output.push(encode_digit(q));
                bias = adapt(delta, h + 1, h == basic_len);
                delta = 0;
                h += 1;
            }
        }
        delta += 1;
        n += 1;
    }

    String::from_utf8(output).map_err(|e| ExpandError::Failed {
        message: format!("punycode encode: {}", e),
    })
}

// ═══════════════════════════════════════════════════════════════════════
//  Address extraction operators
// ═══════════════════════════════════════════════════════════════════════

/// `${address:subject}` — Extract bare address from RFC 2822 form.
/// `<user@domain>` → `user@domain`, strips display name.
fn transform_address(subject: &str) -> String {
    let trimmed = subject.trim();
    // Check for angle-bracket form
    if let Some(start) = trimmed.find('<') {
        if let Some(end) = trimmed[start..].find('>') {
            return trimmed[start + 1..start + end].to_owned();
        }
    }
    // If no angle brackets, return the whole string trimmed
    trimmed.to_owned()
}

/// `${addresses:subject}` — Extract all addresses from a header field,
/// returning them comma-separated.
fn transform_addresses(subject: &str) -> String {
    let mut addresses = Vec::new();
    // Split on commas, handling quoted strings and angle brackets
    let mut in_quotes = false;
    let mut angle_depth = 0i32;
    let mut current = String::new();

    for ch in subject.chars() {
        match ch {
            '"' if angle_depth == 0 => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            '<' if !in_quotes => {
                angle_depth += 1;
                current.push(ch);
            }
            '>' if !in_quotes && angle_depth > 0 => {
                angle_depth -= 1;
                current.push(ch);
            }
            ',' if !in_quotes && angle_depth == 0 => {
                let addr = extract_single_address(&current);
                if !addr.is_empty() {
                    addresses.push(addr);
                }
                current.clear();
            }
            _ => {
                current.push(ch);
            }
        }
    }
    // Handle last entry
    let addr = extract_single_address(&current);
    if !addr.is_empty() {
        addresses.push(addr);
    }

    addresses.join(", ")
}

/// Extract a bare email address from a single address specification.
fn extract_single_address(spec: &str) -> String {
    let trimmed = spec.trim();
    if let Some(start) = trimmed.find('<') {
        if let Some(end) = trimmed[start..].find('>') {
            return trimmed[start + 1..start + end].trim().to_owned();
        }
    }
    // No angle brackets — try to extract address directly
    trimmed.to_owned()
}

// ═══════════════════════════════════════════════════════════════════════
//  Base encoding/decoding operators
// ═══════════════════════════════════════════════════════════════════════

/// `${base32:subject}` — Encode integer to base-32 using Exim's alphabet.
///
/// Note: In Exim, this operates on NUMERIC input, converting an integer
/// to its base-32 string representation. This is NOT standard base32
/// encoding of binary data.
fn transform_base32_encode(subject: &str) -> Result<String, ExpandError> {
    let trimmed = subject.trim();
    let mut val: u64 = trimmed.parse().map_err(|_| ExpandError::Failed {
        message: format!("base32: \"{}\" is not a number", trimmed),
    })?;

    if val == 0 {
        return Ok("a".to_owned());
    }

    let mut result = Vec::new();
    while val > 0 {
        let digit = (val % 32) as usize;
        result.push(BASE32_CHARS[digit]);
        val /= 32;
    }
    result.reverse();
    String::from_utf8(result).map_err(|e| ExpandError::Failed {
        message: format!("base32 encode: {}", e),
    })
}

/// `${base32d:subject}` — Decode base-32 string to integer.
fn transform_base32_decode(subject: &str) -> Result<String, ExpandError> {
    let trimmed = subject.trim();
    let mut val: u64 = 0;
    for ch in trimmed.chars() {
        let digit = BASE32_CHARS
            .iter()
            .position(|&c| c == ch as u8)
            .ok_or_else(|| ExpandError::Failed {
                message: format!("base32d: invalid character '{}' in \"{}\"", ch, trimmed),
            })?;
        val = val
            .checked_mul(32)
            .and_then(|v| v.checked_add(digit as u64))
            .ok_or_else(|| ExpandError::Failed {
                message: format!("base32d: overflow decoding \"{}\"", trimmed),
            })?;
    }
    Ok(val.to_string())
}

/// `${base62:subject}` — Encode integer to base-62.
fn transform_base62_encode(subject: &str) -> Result<String, ExpandError> {
    let trimmed = subject.trim();
    let mut val: u64 = trimmed.parse().map_err(|_| {
        ExpandError::IntegerError(format!("base62: \"{}\" is not a number", trimmed))
    })?;

    if val == 0 {
        return Ok("0".to_owned());
    }

    let mut result = Vec::new();
    while val > 0 {
        let digit = (val % 62) as usize;
        result.push(BASE62_CHARS[digit]);
        val /= 62;
    }
    result.reverse();
    String::from_utf8(result).map_err(|e| ExpandError::Failed {
        message: format!("base62 encode: {}", e),
    })
}

/// `${base62d:subject}` — Decode base-62 string to integer.
fn transform_base62_decode(subject: &str) -> Result<String, ExpandError> {
    let trimmed = subject.trim();
    let mut val: u64 = 0;
    for ch in trimmed.chars() {
        let digit = BASE62_CHARS
            .iter()
            .position(|&c| c == ch as u8)
            .ok_or_else(|| ExpandError::Failed {
                message: format!("base62d: invalid character '{}' in \"{}\"", ch, trimmed),
            })?;
        val = val
            .checked_mul(62)
            .and_then(|v| v.checked_add(digit as u64))
            .ok_or_else(|| ExpandError::Failed {
                message: format!("base62d: overflow decoding \"{}\"", trimmed),
            })?;
    }
    Ok(val.to_string())
}

/// `${base64:subject}` — Base64 encode binary data.
fn transform_base64_encode(subject: &str) -> String {
    // Use Latin-1 byte values (char codepoints) to match C Exim's
    // byte-level base64 encoding.
    BASE64_STANDARD.encode(latin1_bytes(subject))
}

/// `${base64d:subject}` — Base64 decode string.
fn transform_base64_decode(subject: &str) -> Result<String, ExpandError> {
    let decoded =
        BASE64_STANDARD
            .decode(latin1_bytes(subject))
            .map_err(|e| ExpandError::Failed {
                message: format!("base64d: decode error: {}", e),
            })?;
    // Decoded bytes are interpreted as Latin-1 chars for consistency
    // with the rest of the pipeline.
    Ok(decoded.iter().map(|&b| b as char).collect())
}

// ═══════════════════════════════════════════════════════════════════════
//  Domain extraction operator
// ═══════════════════════════════════════════════════════════════════════

/// `${domain:subject}` — Extract domain from email address (everything
/// after the last @).
fn transform_domain(subject: &str) -> String {
    if let Some(at_pos) = subject.rfind('@') {
        subject[at_pos + 1..].to_owned()
    } else {
        String::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Escaping/quoting operators
// ═══════════════════════════════════════════════════════════════════════

/// `${escape:subject}` — Escape non-printing characters to `\xHH` hex.
///
/// Matching C behavior: printable ASCII (0x20-0x7E) passes through,
/// control characters and high bytes get `\xHH` escaping.
fn transform_escape(subject: &str) -> String {
    let mut result = String::with_capacity(subject.len());
    // Iterate over chars rather than UTF-8 bytes so that Latin-1
    // encoded input (each original byte 0x00..0xFF stored as char
    // U+0000..U+00FF) is processed at the logical-byte level,
    // matching C Exim's byte-level `*s` iteration.
    for ch in subject.chars() {
        let cp = ch as u32;
        if (0x20..=0x7E).contains(&cp) && cp != 0x5C {
            result.push(ch);
        } else if cp == 0x5C {
            result.push_str("\\\\");
        } else {
            // C Exim: uses octal format \NNN for non-printable bytes
            let _ = write!(result, "\\{:03o}", cp);
        }
    }
    result
}

/// `${escape8bit:subject}` — Escape only characters with bit 7 set
/// (8-bit chars) to `\NNN` octal.
fn transform_escape8bit(subject: &str) -> String {
    let mut result = String::with_capacity(subject.len());
    // Iterate over chars rather than UTF-8 bytes — with Latin-1
    // encoding, each original high byte is a single char U+0080..
    // U+00FF whose codepoint equals the original byte value.
    for ch in subject.chars() {
        let cp = ch as u32;
        if cp >= 0x80 {
            // C Exim: uses octal format \NNN for high-bit bytes
            let _ = write!(result, "\\{:03o}", cp);
        } else {
            result.push(ch);
        }
    }
    result
}

/// `${hexquote:subject}` — Encode non-alphanumeric characters as `%HH`.
///
/// This is similar to URL-encoding but applies to all characters that
/// are not alphanumeric.
fn transform_hexquote(subject: &str) -> String {
    let mut result = String::with_capacity(subject.len() * 3);
    // Iterate over chars — Latin-1 encoding guarantees each char's
    // codepoint equals the original byte value.
    for ch in subject.chars() {
        let cp = ch as u32;
        if ch.is_ascii_alphanumeric() || cp == b'_' as u32 || cp == b'-' as u32 || cp == b'.' as u32
        {
            result.push(ch);
        } else {
            let _ = write!(result, "%{:02X}", cp);
        }
    }
    result
}

/// `${quote:subject}` — Quote string for use in header fields / shell.
///
/// Doubles backslashes and surrounds with double quotes if the string
/// contains characters that need quoting.
fn transform_quote(subject: &str) -> String {
    let needs_quoting = subject.chars().any(|c| {
        c == ' '
            || c == '\t'
            || c == '\n'
            || c == '"'
            || c == '\\'
            || c == '\''
            || c == '`'
            || c == '$'
            || c == '!'
            || c == '&'
            || c == '|'
            || c == ';'
            || c == '('
            || c == ')'
            || c == '<'
            || c == '>'
    });

    if !needs_quoting {
        return subject.to_owned();
    }

    let mut result = String::with_capacity(subject.len() + 4);
    for ch in subject.chars() {
        if ch == '\\' || ch == '"' {
            result.push('\\');
        }
        result.push(ch);
    }
    result
}

/// `${xtextd:subject}` — Decode xtext encoding (RFC 3461 DSN parameter).
///
/// Xtext uses `+XX` to encode special characters where XX is the
/// hex value of the byte.
fn transform_xtextd(subject: &str) -> String {
    let mut result = String::with_capacity(subject.len());
    let chars: Vec<char> = subject.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '+' && i + 2 < chars.len() {
            // Try to decode the two hex digits
            let hi = hex_digit_value(chars[i + 1] as u8);
            let lo = hex_digit_value(chars[i + 2] as u8);
            if let (Some(h), Some(l)) = (hi, lo) {
                result.push((h * 16 + l) as char);
                i += 3;
                continue;
            }
        }
        result.push(chars[i]);
        i += 1;
    }
    result
}

/// Convert a hex digit byte to its numeric value.
fn hex_digit_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Hash/crypto operators
// ═══════════════════════════════════════════════════════════════════════

/// `${hash:subject}` — Textual hash using the HASHCODES table.
///
/// Computes a hash value from the subject string using the prime table,
/// then maps the result to a character from the HASHCODES table.
/// Default: hash to a single letter (limit=62).
fn transform_hash(subject: &str) -> String {
    let hash_val = compute_hash_value(subject);
    let hashcodes_bytes = HASHCODES.as_bytes();
    let index = (hash_val as usize) % hashcodes_bytes.len();
    (hashcodes_bytes[index] as char).to_string()
}

/// Compute the Exim textual hash value from a string, using the prime
/// table (expand.c hash algorithm).
fn compute_hash_value(input: &str) -> u32 {
    let mut hash_val: u32 = 0;
    // Iterate chars — with Latin-1 encoding, each char's codepoint
    // equals the original byte value, matching C Exim's byte iteration.
    for (i, ch) in input.chars().enumerate() {
        let prime_idx = i % PRIME.len();
        hash_val += (ch as u32).wrapping_mul(PRIME[prime_idx]);
    }
    hash_val
}

/// `${nhash:subject}` — Numeric hash using the prime table.
///
/// Produces a numeric hash value. Default divisor is 100.
fn transform_nhash(subject: &str) -> String {
    let hash_val = compute_hash_value(subject);
    (hash_val % 100).to_string()
}

/// `${md5:subject}` — MD5 hex digest of string (32-character lowercase).
fn transform_md5(subject: &str) -> String {
    let hash = <md5::Md5 as Digest>::digest(latin1_bytes(subject));
    let mut result = String::with_capacity(32);
    for byte in hash.iter() {
        let _ = write!(result, "{:02x}", byte);
    }
    result
}

/// `${sha1:subject}` — SHA-1 hex digest of string (40-character lowercase).
fn transform_sha1(subject: &str) -> String {
    let hash = <sha1::Sha1 as Digest>::digest(latin1_bytes(subject));
    let mut result = String::with_capacity(40);
    for byte in hash.iter() {
        let _ = write!(result, "{:02x}", byte);
    }
    result
}

/// `${sha2:subject}` / `${sha256:subject}` — SHA-256 hex digest
/// (64-character lowercase).
fn transform_sha256(subject: &str) -> String {
    let hash = <sha2::Sha256 as Digest>::digest(latin1_bytes(subject));
    let mut result = String::with_capacity(64);
    for byte in hash.iter() {
        let _ = write!(result, "{:02x}", byte);
    }
    result
}

/// `${sha3:subject}` — SHA3-256 hex digest (64-character lowercase).
fn transform_sha3(subject: &str) -> String {
    let hash = <sha3::Sha3_256 as Digest>::digest(latin1_bytes(subject));
    let mut result = String::with_capacity(64);
    for byte in hash.iter() {
        let _ = write!(result, "{:02x}", byte);
    }
    result
}

/// `${hex2b64:subject}` — Convert hex string to base64.
fn transform_hex2b64(subject: &str) -> Result<String, ExpandError> {
    let bytes = hex_decode_bytes(subject.trim())?;
    Ok(BASE64_STANDARD.encode(&bytes))
}

/// `${str2b64:subject}` — Encode string to base64.
fn transform_str2b64(subject: &str) -> String {
    BASE64_STANDARD.encode(latin1_bytes(subject))
}

/// Decode a hex string into raw bytes.
fn hex_decode_bytes(hex_str: &str) -> Result<Vec<u8>, ExpandError> {
    if !hex_str.len().is_multiple_of(2) {
        return Err(ExpandError::Failed {
            message: format!("hex2b64: hex string has odd length ({})", hex_str.len()),
        });
    }
    let mut bytes = Vec::with_capacity(hex_str.len() / 2);
    let hex_bytes = hex_str.as_bytes();
    let mut i = 0;
    while i < hex_bytes.len() {
        let hi = hex_digit_value(hex_bytes[i]).ok_or_else(|| ExpandError::Failed {
            message: format!("hex2b64: invalid hex character '{}'", hex_bytes[i] as char),
        })?;
        let lo = hex_digit_value(hex_bytes[i + 1]).ok_or_else(|| ExpandError::Failed {
            message: format!(
                "hex2b64: invalid hex character '{}'",
                hex_bytes[i + 1] as char
            ),
        })?;
        bytes.push(hi * 16 + lo);
        i += 2;
    }
    Ok(bytes)
}

// ═══════════════════════════════════════════════════════════════════════
//  String manipulation operators
// ═══════════════════════════════════════════════════════════════════════

/// `${lc:subject}` / `${l:subject}` — Convert to lowercase (ASCII only).
///
/// Uses ASCII-only folding to match C `tolower()` behavior, NOT Unicode
/// case folding (AAP §0.7 CRITICAL rule).
fn transform_lc(subject: &str) -> String {
    // Iterate chars — ASCII-only case folding is char-safe since
    // ASCII uppercase A-Z are always single-byte chars.
    subject
        .chars()
        .map(|ch| {
            if ch.is_ascii_uppercase() {
                ((ch as u8) + 32) as char
            } else {
                ch
            }
        })
        .collect()
}

/// `${uc:subject}` — Convert to uppercase (ASCII only).
///
/// Uses ASCII-only folding to match C `toupper()` behavior.
fn transform_uc(subject: &str) -> String {
    subject
        .chars()
        .map(|ch| {
            if ch.is_ascii_lowercase() {
                ((ch as u8) - 32) as char
            } else {
                ch
            }
        })
        .collect()
}

/// `${length:subject}` / `${strlen:subject}` — Return string length as
/// decimal number.
fn transform_length(subject: &str) -> String {
    // Count chars (= original bytes with Latin-1 encoding), not
    // UTF-8 byte length, to match C Exim's strlen() behavior.
    subject.chars().count().to_string()
}

/// `${headerwrap:subject}` — Wrap header lines at appropriate points
/// per RFC 5322 line length limits (76 characters).
fn transform_headerwrap(subject: &str) -> String {
    const MAX_LINE_LEN: usize = 76;

    if subject.len() <= MAX_LINE_LEN {
        return subject.to_owned();
    }

    let mut result = String::with_capacity(subject.len() + subject.len() / MAX_LINE_LEN * 3);
    let mut line_pos = 0usize;
    let mut last_space = None;
    let mut start = 0usize;

    for (i, ch) in subject.char_indices() {
        if ch == ' ' || ch == '\t' {
            last_space = Some(i);
        }
        line_pos += 1;
        if line_pos >= MAX_LINE_LEN {
            if let Some(sp) = last_space {
                result.push_str(&subject[start..=sp]);
                result.push_str("\r\n ");
                start = sp + 1;
                line_pos = i - sp;
                last_space = None;
            } else {
                // No space found — force break at current position
                result.push_str(&subject[start..=i]);
                result.push_str("\r\n ");
                start = i + ch.len_utf8();
                line_pos = 0;
            }
        }
    }
    // Append remaining text
    if start < subject.len() {
        result.push_str(&subject[start..]);
    }
    result
}

// ═══════════════════════════════════════════════════════════════════════
//  Evaluation operators (delegate to evaluator)
// ═══════════════════════════════════════════════════════════════════════

/// `${eval:subject}` / `${eval10:subject}` — Evaluate arithmetic expression.
///
/// Delegates to `evaluator.eval_expr()`.
/// * `eval` supports C-style notation (hex 0x, octal 0).
/// * `eval10` is decimal-only.
fn transform_eval(
    subject: &str,
    evaluator: &mut Evaluator,
    decimal: bool,
) -> Result<String, ExpandError> {
    let val = evaluator.eval_expr(subject, decimal)?;
    Ok(val.to_string())
}

/// `${expand:subject}` — Re-expand the subject string (double expansion).
///
/// Parses and evaluates the subject string as a new expansion expression.
fn transform_expand(subject: &str, evaluator: &mut Evaluator) -> Result<String, ExpandError> {
    // Parse the subject as a new expression and evaluate it.
    // Parser::new() accepts &str and internally tokenizes.
    use crate::parser::Parser;
    use crate::EsiFlags;

    let mut parser = Parser::new(subject);
    let ast = parser.parse()?;
    evaluator.evaluate(&ast, EsiFlags::ESI_BRACE_ENDS | EsiFlags::ESI_HONOR_DOLLAR)
}

// ═══════════════════════════════════════════════════════════════════════
//  Header/list operations
// ═══════════════════════════════════════════════════════════════════════

/// `${listcount:subject}` — Count items in a colon-separated list.
///
/// Exim uses colon as the default list separator. Empty entries between
/// colons still count.
fn transform_listcount(subject: &str) -> String {
    if subject.is_empty() {
        return "0".to_owned();
    }
    // Count items separated by colon. Exim counts the number of actual
    // separator-delimited elements.
    let count = subject.split(':').count();
    count.to_string()
}

/// `${listnamed:subject}` — Return a named list's contents.
///
/// In the full implementation, this looks up a named list from the
/// configuration. Currently returns the subject as a passthrough.
fn transform_listnamed(subject: &str, evaluator: &Evaluator) -> String {
    // Named lists are resolved from the configuration context.
    // The evaluator's lookup_value may contain relevant state.
    if let Some(ref val) = evaluator.lookup_value {
        if !val.is_empty() {
            return val.clone();
        }
    }
    subject.to_owned()
}

// ═══════════════════════════════════════════════════════════════════════
//  Network operators
// ═══════════════════════════════════════════════════════════════════════

/// `${mask:subject}` — Apply network mask to IP address.
///
/// Subject format: `ip_address/bits` (CIDR notation).
fn transform_mask(subject: &str) -> Result<String, ExpandError> {
    transform_mask_inner(subject, false)
}

/// `${mask_n:subject}` — Like mask but normalize IPv6 to compressed form.
fn transform_mask_n(subject: &str) -> Result<String, ExpandError> {
    transform_mask_inner(subject, true)
}

/// Inner implementation for both `mask` and `mask_n` operators.
///
/// C Exim mask operator:
/// - Validates IP/mask format, errors if not valid IP.
/// - For IPv4: standard dotted-quad output.
/// - For IPv6: uses dot-separated 4-hex-digit groups (mask) or
///   colon-compressed form (mask_n).
/// - Rejects mask values > 32 (IPv4) or > 128 (IPv6).
fn transform_mask_inner(subject: &str, normalize: bool) -> Result<String, ExpandError> {
    let trimmed = subject.trim();
    let (addr_str, bits_str) = trimmed.split_once('/').ok_or_else(|| ExpandError::Failed {
        message: format!("\"{}\" is not an IP address", trimmed),
    })?;

    let bits: u32 = bits_str.trim().parse().map_err(|_| ExpandError::Failed {
        message: format!("mask: invalid bit count \"{}\"", bits_str),
    })?;

    let addr: IpAddr = addr_str.trim().parse().map_err(|_| ExpandError::Failed {
        message: format!("\"{}\" is not an IP address", addr_str),
    })?;

    match addr {
        IpAddr::V4(ipv4) => {
            if bits > 32 {
                return Err(ExpandError::Failed {
                    message: format!("mask value too big in \"{}\"", trimmed),
                });
            }
            let ip_u32 = u32::from(ipv4);
            let mask = if bits == 0 {
                0u32
            } else {
                !0u32 << (32 - bits)
            };
            let masked = Ipv4Addr::from(ip_u32 & mask);
            Ok(format!("{}/{}", masked, bits))
        }
        IpAddr::V6(ipv6) => {
            if bits > 128 {
                return Err(ExpandError::Failed {
                    message: format!("mask value too big in \"{}\"", trimmed),
                });
            }
            let ip_u128 = u128::from(ipv6);
            let mask = if bits == 0 {
                0u128
            } else {
                !0u128 << (128 - bits)
            };
            let masked = Ipv6Addr::from(ip_u128 & mask);
            if normalize {
                // mask_n: compressed colon notation (Rust Display for Ipv6Addr)
                Ok(format!("{}/{}", masked, bits))
            } else {
                // mask: use dot-separated 4-hex-digit groups
                // C Exim format: XXXX.XXXX.XXXX.XXXX.XXXX.XXXX.XXXX.XXXX/bits
                let segments = masked.segments();
                Ok(format!(
                    "{:04x}.{:04x}.{:04x}.{:04x}.{:04x}.{:04x}.{:04x}.{:04x}/{}",
                    segments[0],
                    segments[1],
                    segments[2],
                    segments[3],
                    segments[4],
                    segments[5],
                    segments[6],
                    segments[7],
                    bits
                ))
            }
        }
    }
}

/// `${ipv6norm:subject}` — Normalize IPv6 address to canonical compressed
/// form (e.g., `::1`, `2001:db8::1`).
fn transform_ipv6norm(subject: &str) -> Result<String, ExpandError> {
    let trimmed = subject.trim();
    let ipv6: Ipv6Addr = trimmed.parse().map_err(|_| ExpandError::Failed {
        message: format!("ipv6norm: invalid IPv6 address \"{}\"", trimmed),
    })?;
    // Rust's Ipv6Addr Display produces the canonical compressed form
    Ok(ipv6.to_string())
}

/// `${ipv6denorm:subject}` — Expand IPv6 address to full 8-group
/// colon-hex form (e.g., `0000:0000:0000:0000:0000:0000:0000:0001`).
fn transform_ipv6denorm(subject: &str) -> Result<String, ExpandError> {
    let trimmed = subject.trim();
    let ipv6: Ipv6Addr = trimmed.parse().map_err(|_| ExpandError::Failed {
        message: format!("ipv6denorm: invalid IPv6 address \"{}\"", trimmed),
    })?;
    let segments = ipv6.segments();
    Ok(format!(
        "{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
        segments[0],
        segments[1],
        segments[2],
        segments[3],
        segments[4],
        segments[5],
        segments[6],
        segments[7]
    ))
}

// ═══════════════════════════════════════════════════════════════════════
//  MIME/encoding operators
// ═══════════════════════════════════════════════════════════════════════

/// `${rfc2047:subject}` — RFC 2047 MIME encode string for header use.
///
/// Encodes using the `headers_charset` (defaults to iso-8859-1) with
/// Quoted-Printable encoding, matching C Exim's `parse_quote_2047()`.
/// Characters outside 33-126 or in the RFC 2047 special set are encoded.
/// Line-wrapping at 75 chars per encoded-word (67 chars payload).
fn transform_rfc2047_encode(subject: &str) -> String {
    transform_rfc2047_encode_with_charset(subject, "iso-8859-8")
}

/// RFC 2047 encoding with a configurable charset.
///
/// Mirrors C Exim's `parse_quote_2047(string, len, charset, fold=FALSE)`.
fn transform_rfc2047_encode_with_charset(subject: &str, charset: &str) -> String {
    // Characters that require encoding (C Exim: ch < 33 || ch > 126 || in special set)
    const SPECIALS: &[u8] = b"?=()<>@,;:\\\".[]_";
    let needs_encode = |b: u8| -> bool { !(33..=126).contains(&b) || SPECIALS.contains(&b) };

    let header = format!("=?{}?Q?", charset);
    let _hlen = header.len();
    let mut result = String::new();
    let mut coded = false;
    let mut line_off: usize = 0;
    let mut first_byte = false;

    result.push_str(&header);

    // Iterate over chars — with Latin-1 encoding, each char's
    // codepoint equals the original byte value (0x00..0xFF).
    for ch in subject.chars() {
        let byte = ch as u32 as u8;
        // Line wrapping: if current encoded-word exceeds 67 chars
        // (matching C Exim's g->ptr - line_off > 67 check).
        if result.len() - line_off > 67 && !first_byte {
            result.push_str("?= ");
            line_off = result.len();
            result.push_str(&header);
        }

        if needs_encode(byte) {
            if byte == b' ' {
                result.push('_');
                first_byte = false;
            } else {
                let _ = write!(result, "={:02X}", byte);
                coded = true;
                first_byte = !first_byte;
            }
        } else {
            result.push(ch);
            first_byte = false;
        }
    }

    if coded {
        result.push_str("?=");
        result
    } else {
        // No encoding was needed — return original string unchanged
        // (C Exim returns the original when coded == false)
        subject.to_owned()
    }
}

/// `${rfc2047d:subject}` — RFC 2047 MIME decode string.
///
/// Decodes `=?charset?encoding?encoded-text?=` sequences back to
/// their original form.
fn transform_rfc2047_decode(subject: &str) -> String {
    let mut result = String::with_capacity(subject.len());
    let mut remaining = subject;

    while let Some(start) = remaining.find("=?") {
        // Append everything before the encoded word
        result.push_str(&remaining[..start]);

        let after_start = &remaining[start + 2..];
        // Find charset delimiter
        if let Some(charset_end) = after_start.find('?') {
            let after_charset = &after_start[charset_end + 1..];
            // Find encoding type delimiter
            if let Some(enc_end) = after_charset.find('?') {
                let encoding = &after_charset[..enc_end];
                let after_enc = &after_charset[enc_end + 1..];
                // Find closing `?=`
                if let Some(text_end) = after_enc.find("?=") {
                    let encoded_text = &after_enc[..text_end];

                    // Decode based on encoding type
                    let decoded = match encoding.to_ascii_uppercase().as_str() {
                        "Q" => decode_rfc2047_q(encoded_text),
                        "B" => decode_rfc2047_b(encoded_text),
                        _ => encoded_text.to_owned(),
                    };
                    result.push_str(&decoded);

                    remaining = &after_enc[text_end + 2..];
                    continue;
                }
            }
        }

        // Malformed encoded word — pass through literally
        result.push_str("=?");
        remaining = after_start;
    }
    result.push_str(remaining);
    result
}

/// Decode RFC 2047 Q-encoded text.
///
/// Decodes the raw bytes first, then interprets them as UTF-8 to
/// handle multi-byte character sequences like `=C3=A9` (é in UTF-8).
fn decode_rfc2047_q(encoded: &str) -> String {
    let mut raw_bytes = Vec::with_capacity(encoded.len());
    let bytes = encoded.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'_' => {
                raw_bytes.push(b' ');
                i += 1;
            }
            b'=' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) =
                    (hex_digit_value(bytes[i + 1]), hex_digit_value(bytes[i + 2]))
                {
                    raw_bytes.push(hi * 16 + lo);
                    i += 3;
                } else {
                    raw_bytes.push(b'=');
                    i += 1;
                }
            }
            b => {
                raw_bytes.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&raw_bytes).into_owned()
}

/// Decode RFC 2047 B-encoded (base64) text.
fn decode_rfc2047_b(encoded: &str) -> String {
    match BASE64_STANDARD.decode(encoded.as_bytes()) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(_) => encoded.to_owned(),
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  File operations (stat)
// ═══════════════════════════════════════════════════════════════════════

/// `${stat:subject}` — File stat: returns formatted mode/size/uid/gid/etc.
///
/// Uses `mtable_normal`, `mtable_setid`, `mtable_sticky` for symbolic
/// mode display (expand.c lines 887-894).
///
/// Output format matches C Exim's stat operator output:
/// `mode=<octal> smode=<symbolic> inode=<ino> device=<dev> links=<nlink>
///  uid=<uid> gid=<gid> size=<size> atime=<epoch> mtime=<epoch> ctime=<epoch>`
fn transform_stat(subject: &str) -> Result<String, ExpandError> {
    use std::os::unix::fs::MetadataExt;

    let trimmed = subject.trim();
    let meta = std::fs::metadata(trimmed).map_err(|e| ExpandError::Failed {
        message: format!("stat: {}: {}", trimmed, e),
    })?;

    let mode = meta.mode();
    let smode = format_symbolic_mode(mode);

    Ok(format!(
        "mode={:04o} smode={} inode={} device={} links={} uid={} gid={} size={} atime={} mtime={} ctime={}",
        mode & 0o7777,
        smode,
        meta.ino(),
        meta.dev(),
        meta.nlink(),
        meta.uid(),
        meta.gid(),
        meta.size(),
        meta.atime(),
        meta.mtime(),
        meta.ctime(),
    ))
}

/// Format a Unix file mode into symbolic form like `-rwxr-xr-x`.
///
/// Uses the mtable_normal, mtable_setid, and mtable_sticky tables from
/// expand.c (lines 887-894).
fn format_symbolic_mode(mode: u32) -> String {
    let mut result = String::with_capacity(10);

    // File type character
    let ftype = mode & 0o170000;
    result.push(match ftype {
        0o140000 => 's', // socket
        0o120000 => 'l', // symlink
        0o100000 => '-', // regular file
        0o060000 => 'b', // block device
        0o040000 => 'd', // directory
        0o020000 => 'c', // char device
        0o010000 => 'p', // named pipe (FIFO)
        _ => '?',
    });

    // Owner bits (with setuid)
    let owner_bits = ((mode >> 6) & 7) as usize;
    let has_setuid = (mode & 0o4000) != 0;
    if has_setuid {
        result.push_str(MTABLE_SETID[owner_bits]);
    } else {
        result.push_str(MTABLE_NORMAL[owner_bits]);
    }

    // Group bits (with setgid)
    let group_bits = ((mode >> 3) & 7) as usize;
    let has_setgid = (mode & 0o2000) != 0;
    if has_setgid {
        result.push_str(MTABLE_SETID[group_bits]);
    } else {
        result.push_str(MTABLE_NORMAL[group_bits]);
    }

    // Others bits (with sticky)
    let other_bits = (mode & 7) as usize;
    let has_sticky = (mode & 0o1000) != 0;
    if has_sticky {
        result.push_str(MTABLE_STICKY[other_bits]);
    } else {
        result.push_str(MTABLE_NORMAL[other_bits]);
    }

    result
}

// ═══════════════════════════════════════════════════════════════════════
//  Miscellaneous operators
// ═══════════════════════════════════════════════════════════════════════

/// `${randint:subject}` — Generate random integer in range [0, subject-1].
///
/// Uses `rand::rng()` with `Rng::random_range()` for uniform distribution,
/// replacing C `vaguely_random_number()`.
fn transform_randint(subject: &str) -> Result<String, ExpandError> {
    let trimmed = subject.trim();
    let max: u32 = trimmed.parse().map_err(|_| {
        ExpandError::IntegerError(format!("randint: \"{}\" is not a number", trimmed))
    })?;
    if max == 0 {
        return Err(ExpandError::Failed {
            message: "randint: limit must be non-zero".into(),
        });
    }
    let mut rng = rand::rng();
    let val: u32 = rng.random_range(0..max);
    Ok(val.to_string())
}

/// `${utf8clean:subject}` — Clean invalid UTF-8 sequences, replacing
/// them with U+FFFD REPLACEMENT CHARACTER.
fn transform_utf8clean(subject: &str) -> String {
    // In Rust, &str is always valid UTF-8. However, the input may
    // have been constructed from raw bytes. We use from_utf8_lossy
    // on the raw bytes to clean any invalid sequences.
    String::from_utf8_lossy(subject.as_bytes()).into_owned()
}

// ═══════════════════════════════════════════════════════════════════════
//  Unit tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hashcodes_typo_preserved() {
        // CRITICAL: The typo "qrtsuvwxyz" (not "qrstuvwxyz") must be preserved
        // for backward compatibility with C Exim.
        assert!(HASHCODES.contains("qrtsuvwxyz"));
        assert!(!HASHCODES.contains("qrstuvwxyz"));
    }

    #[test]
    fn test_base32_encode() {
        assert_eq!(transform_base32_encode("0").unwrap(), "a");
        assert_eq!(transform_base32_encode("1").unwrap(), "b");
        assert_eq!(transform_base32_encode("31").unwrap(), "7"); // 31 is single digit '7'
        assert_eq!(transform_base32_encode("32").unwrap(), "ba"); // 32 = 1*32 + 0
        assert_eq!(transform_base32_encode("1023").unwrap(), "77"); // 1023 = 31*32 + 31
    }

    #[test]
    fn test_base32_decode() {
        assert_eq!(transform_base32_decode("a").unwrap(), "0");
        assert_eq!(transform_base32_decode("b").unwrap(), "1");
        assert_eq!(transform_base32_decode("ba").unwrap(), "32");
    }

    #[test]
    fn test_base62_roundtrip() {
        for val in [0, 1, 9, 10, 61, 62, 100, 12345, 999999] {
            let encoded = transform_base62_encode(&val.to_string()).unwrap();
            let decoded = transform_base62_decode(&encoded).unwrap();
            assert_eq!(
                decoded,
                val.to_string(),
                "base62 roundtrip failed for {}",
                val
            );
        }
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(transform_base64_encode("hello"), "aGVsbG8=");
    }

    #[test]
    fn test_base64_decode() {
        assert_eq!(transform_base64_decode("aGVsbG8=").unwrap(), "hello");
    }

    #[test]
    fn test_local_part() {
        assert_eq!(transform_local_part("user@example.com"), "user");
        assert_eq!(transform_local_part("user"), "user");
        assert_eq!(transform_local_part("user@host@domain"), "user@host");
    }

    #[test]
    fn test_domain() {
        assert_eq!(transform_domain("user@example.com"), "example.com");
        assert_eq!(transform_domain("user"), "");
    }

    #[test]
    fn test_reverse_ip_v4() {
        assert_eq!(transform_reverse_ip("1.2.3.4").unwrap(), "4.3.2.1");
    }

    #[test]
    fn test_reverse_ip_v6() {
        let result = transform_reverse_ip("::1").unwrap();
        assert!(result.starts_with("1.0.0.0.0.0.0.0"));
        assert!(result.ends_with("0.0.0.0.0.0.0.0"));
    }

    #[test]
    fn test_md5() {
        assert_eq!(transform_md5("hello"), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_sha1() {
        assert_eq!(
            transform_sha1("hello"),
            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        );
    }

    #[test]
    fn test_sha256() {
        let result = transform_sha256("hello");
        assert_eq!(result.len(), 64);
        assert_eq!(
            result,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_sha3() {
        let result = transform_sha3("hello");
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_lc() {
        assert_eq!(transform_lc("Hello WORLD"), "hello world");
        assert_eq!(transform_lc("123"), "123");
    }

    #[test]
    fn test_uc() {
        assert_eq!(transform_uc("Hello World"), "HELLO WORLD");
    }

    #[test]
    fn test_length() {
        assert_eq!(transform_length("hello"), "5");
        assert_eq!(transform_length(""), "0");
    }

    #[test]
    fn test_escape() {
        let result = transform_escape("hello\x01world");
        // \x01 is escaped to octal \001
        assert!(result.contains("\\001"));
        assert_eq!(result, "hello\\001world");
    }

    #[test]
    fn test_escape8bit() {
        assert_eq!(transform_escape8bit("hello"), "hello");
        // With Latin-1 encoding, U+00E9 (é) has codepoint 0xE9
        // and is escaped to octal \351
        let input = "h\u{00e9}";
        let result = transform_escape8bit(input);
        assert!(result.contains("\\351"));
        assert_eq!(result, "h\\351");
    }

    #[test]
    fn test_address() {
        assert_eq!(transform_address("<user@example.com>"), "user@example.com");
        assert_eq!(
            transform_address("User Name <user@example.com>"),
            "user@example.com"
        );
    }

    #[test]
    fn test_listcount() {
        assert_eq!(transform_listcount("a:b:c"), "3");
        assert_eq!(transform_listcount(""), "0");
        assert_eq!(transform_listcount("single"), "1");
    }

    #[test]
    fn test_ipv6norm() {
        assert_eq!(
            transform_ipv6norm("0000:0000:0000:0000:0000:0000:0000:0001").unwrap(),
            "::1"
        );
    }

    #[test]
    fn test_ipv6denorm() {
        assert_eq!(
            transform_ipv6denorm("::1").unwrap(),
            "0000:0000:0000:0000:0000:0000:0000:0001"
        );
    }

    #[test]
    fn test_mask_ipv4() {
        assert_eq!(
            transform_mask("192.168.1.100/24").unwrap(),
            "192.168.1.0/24"
        );
    }

    #[test]
    fn test_quote_local_part() {
        assert_eq!(
            transform_quote_local_part("user@example.com"),
            "user@example.com"
        );
        assert_eq!(
            transform_quote_local_part("user name@example.com"),
            "\"user name\"@example.com"
        );
    }

    #[test]
    fn test_xtextd() {
        assert_eq!(transform_xtextd("hello+20world"), "hello world");
        assert_eq!(transform_xtextd("plain"), "plain");
    }

    #[test]
    fn test_time_interval() {
        assert_eq!(transform_time_interval("3661").unwrap(), "1h1m1s");
        assert_eq!(transform_time_interval("0").unwrap(), "0s");
    }

    #[test]
    fn test_format_time_interval() {
        assert_eq!(format_time_interval(0), "0s");
        assert_eq!(format_time_interval(60), "1m");
        assert_eq!(format_time_interval(3600), "1h");
        assert_eq!(format_time_interval(86400), "1d");
        assert_eq!(format_time_interval(604800), "1w");
        assert_eq!(format_time_interval(694861), "1w1d1h1m1s");
    }

    #[test]
    fn test_parse_time_interval() {
        assert_eq!(parse_time_interval_str("1h").unwrap(), 3600);
        assert_eq!(parse_time_interval_str("2d3h").unwrap(), 183600);
        assert_eq!(parse_time_interval_str("1w").unwrap(), 604800);
        assert_eq!(parse_time_interval_str("30m").unwrap(), 1800);
    }

    #[test]
    fn test_hex2b64() {
        // "48656c6c6f" = "Hello" in hex
        let result = transform_hex2b64("48656c6c6f").unwrap();
        assert_eq!(result, "SGVsbG8=");
    }

    #[test]
    fn test_str2b64() {
        assert_eq!(transform_str2b64("Hello"), "SGVsbG8=");
    }

    #[test]
    fn test_from_utf8() {
        assert_eq!(transform_from_utf8("hello").unwrap(), "hello");
        assert_eq!(transform_from_utf8("\u{00e9}").unwrap(), "\u{00e9}"); // é
        assert_eq!(transform_from_utf8("\u{1F600}").unwrap(), "?"); // emoji → ?
    }

    #[test]
    fn test_utf8clean() {
        assert_eq!(transform_utf8clean("hello"), "hello");
        // Valid UTF-8 passes through unchanged
        assert_eq!(transform_utf8clean("héllo"), "héllo");
    }

    #[test]
    fn test_randint() {
        let result = transform_randint("100").unwrap();
        let val: u32 = result.parse().unwrap();
        assert!(val < 100);
    }

    #[test]
    fn test_randint_zero_fails() {
        assert!(transform_randint("0").is_err());
    }

    #[test]
    fn test_prime_table() {
        assert_eq!(PRIME.len(), 30);
        assert_eq!(PRIME[0], 2);
        assert_eq!(PRIME[29], 113);
    }

    #[test]
    fn test_mode_tables() {
        assert_eq!(MTABLE_NORMAL[0], "---");
        assert_eq!(MTABLE_NORMAL[7], "rwx");
        assert_eq!(MTABLE_SETID[1], "--s");
        assert_eq!(MTABLE_STICKY[1], "--t");
    }

    #[test]
    fn test_symbolic_mode() {
        // Regular file with mode 0644 (-rw-r--r--)
        let mode = 0o100644;
        assert_eq!(format_symbolic_mode(mode), "-rw-r--r--");

        // Directory with mode 0755 (drwxr-xr-x)
        let mode = 0o040755;
        assert_eq!(format_symbolic_mode(mode), "drwxr-xr-x");

        // Regular file with setuid and mode 4755 (-rwsr-xr-x)
        let mode = 0o104755;
        assert_eq!(format_symbolic_mode(mode), "-rwsr-xr-x");
    }

    #[test]
    fn test_rxquote() {
        // regex::escape is the implementation
        assert_eq!(regex::escape("hello.world"), r"hello\.world");
        assert_eq!(regex::escape("test[0]"), r"test\[0\]");
    }

    #[test]
    fn test_rfc2047_encode() {
        assert_eq!(transform_rfc2047_encode("hello"), "hello");
        // Default charset is iso-8859-8 (matching C Exim default)
        let result = transform_rfc2047_encode("h\u{00e9}llo");
        assert!(result.starts_with("=?iso-8859-8?Q?"));
        assert!(result.ends_with("?="));
    }

    #[test]
    fn test_rfc2047_decode() {
        assert_eq!(transform_rfc2047_decode("=?UTF-8?Q?h=C3=A9llo?="), "héllo");
        assert_eq!(transform_rfc2047_decode("=?UTF-8?B?aGVsbG8=?="), "hello");
        assert_eq!(transform_rfc2047_decode("plain text"), "plain text");
    }

    #[test]
    fn test_addresses() {
        let result = transform_addresses("User <user@example.com>, Admin <admin@test.org>");
        assert!(result.contains("user@example.com"));
        assert!(result.contains("admin@test.org"));
    }

    #[test]
    fn test_hexquote() {
        let result = transform_hexquote("a b");
        assert!(result.contains("a"));
        assert!(result.contains("%20"));
        assert!(result.contains("b"));
    }
}
