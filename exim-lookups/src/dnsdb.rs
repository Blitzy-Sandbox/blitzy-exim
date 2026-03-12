//! DNS query lookup backend for the Exim MTA.
//!
//! This module implements the `dnsdb` lookup type, which performs DNS queries
//! and returns results formatted for Exim's string expansion engine. It replaces
//! `src/src/lookups/dnsdb.c` (623 lines) with a pure-Rust implementation using
//! the `exim-dns` crate for DNS resolution via hickory-resolver.
//!
//! # Supported Record Types
//!
//! Standard: A, AAAA, MX, SRV, TXT, PTR, CNAME, NS, SOA, TLSA
//! Virtual:  A+ (combined AAAA+A), MXH (MX hostnames only), ZNS (zone NS),
//!           CSA (Client SMTP Authorization), SPF (type 99, mapped to TXT)
//!
//! # Key Grammar
//!
//! ```text
//! [>outsep[,fieldsep | ;]]
//! [defer_strict|defer_lax|defer_never,]
//! [dnssec_strict|dnssec_lax|dnssec_never,]
//! [retrans_SECS,] [retry_COUNT,]
//! [TYPE=]
//! domain[:domain:...]
//! ```
//!
//! Default record type is TXT.  Default output separator is newline (`\n`).
//! Default field separator depends on the record type.
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` code (AAP §0.7.2).

use std::fmt::Write as FmtWrite;
use std::net::IpAddr;
use std::sync::Mutex;

use exim_dns::{
    DnsError, DnsRecordData, DnsRecordType, DnsResolver, DnsResponse, DnsResult, DnsSection,
    SpecialDnsType,
};
use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;
use tracing::{debug, warn};

// =============================================================================
// Constants
// =============================================================================

/// Maximum CNAME chain depth to follow during DNS resolution.
const CNAME_CHAIN_LIMIT: u32 = 10;

/// Exim version string for version reporting.
const EXIM_VERSION: &str = "4.99";

// =============================================================================
// Key Grammar Types
// =============================================================================

/// How to handle temporary DNS failures (SERVFAIL, timeouts).
///
/// Maps to C `defer_mode` variable in `dnsdb_find()`:
/// - `Strict` → C `DEFER`: any temporary failure causes immediate deferral
/// - `Lax`    → C `PASS` : defer only if ALL domains fail (default)
/// - `Never`  → C `FAIL` : treat temporary failures as not-found
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeferMode {
    Strict,
    Lax,
    Never,
}

/// DNSSEC validation policy for DNS responses.
///
/// Maps to C `dnssec_mode` variable in `dnsdb_find()`:
/// - `Strict` → require AD bit; non-secure responses treated as failures
/// - `Lax`    → request DNSSEC but accept non-secure (default)
/// - `Never`  → don't request or check DNSSEC
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnssecMode {
    Strict,
    Lax,
    Never,
}

/// DNS record type for dnsdb queries, including virtual/special types.
///
/// Maps to the C `type_names[]` / `type_values[]` arrays (dnsdb.c lines 25–54).
/// Virtual types (A+, MXH, ZNS, CSA, SPF) have no direct DNS wire-format type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsdbType {
    /// Standard A record (IPv4 address).
    A,
    /// Standard AAAA record (IPv6 address).
    Aaaa,
    /// Virtual: query AAAA then A, combine results.
    Addresses,
    /// Standard CNAME record.
    Cname,
    /// Virtual: Client SMTP Authorization (SRV at `_client._smtp.<domain>`).
    Csa,
    /// Standard MX record (preference + exchange).
    Mx,
    /// Virtual: MX hostnames only (skip preference value).
    MxHosts,
    /// Standard NS record.
    Ns,
    /// Standard PTR record (reverse DNS).
    Ptr,
    /// Standard SOA record.
    Soa,
    /// Virtual: SPF (type 99, deprecated) — queries TXT with concat default.
    Spf,
    /// Standard SRV record (priority/weight/port/target).
    Srv,
    /// Standard TLSA record (DANE certificate association).
    Tlsa,
    /// Standard TXT record.
    Txt,
    /// Virtual: zone nameservers with parent-domain walking.
    ZoneNs,
}

impl DnsdbType {
    /// Return the DNS record type used to filter answer-section records.
    ///
    /// For virtual types, returns the underlying wire-format record type
    /// that appears in the DNS response.
    fn search_record_type(self) -> DnsRecordType {
        match self {
            Self::A => DnsRecordType::A,
            Self::Aaaa | Self::Addresses => DnsRecordType::Aaaa,
            Self::Cname => DnsRecordType::Cname,
            Self::Csa | Self::Srv => DnsRecordType::Srv,
            Self::Mx | Self::MxHosts => DnsRecordType::Mx,
            Self::Ns | Self::ZoneNs => DnsRecordType::Ns,
            Self::Ptr => DnsRecordType::Ptr,
            Self::Soa => DnsRecordType::Soa,
            Self::Spf | Self::Txt => DnsRecordType::Txt,
            Self::Tlsa => DnsRecordType::Tlsa,
        }
    }

    /// Return the `DnsRecordType` for a standard `dns_lookup()`, or `None` if
    /// the type requires special dispatch (A+, MXH, ZNS, CSA).
    fn to_record_type(self) -> Option<DnsRecordType> {
        match self {
            Self::A => Some(DnsRecordType::A),
            Self::Aaaa => Some(DnsRecordType::Aaaa),
            Self::Cname => Some(DnsRecordType::Cname),
            Self::Mx => Some(DnsRecordType::Mx),
            Self::Ns => Some(DnsRecordType::Ns),
            Self::Ptr => Some(DnsRecordType::Ptr),
            Self::Soa => Some(DnsRecordType::Soa),
            Self::Srv => Some(DnsRecordType::Srv),
            Self::Tlsa => Some(DnsRecordType::Tlsa),
            Self::Txt | Self::Spf => Some(DnsRecordType::Txt),
            Self::Addresses | Self::Csa | Self::MxHosts | Self::ZoneNs => None,
        }
    }

    /// Return the `SpecialDnsType` for virtual types dispatched via
    /// `DnsResolver::dns_special_lookup()`.
    fn to_special_type(self) -> Option<SpecialDnsType> {
        match self {
            Self::MxHosts => Some(SpecialDnsType::MxHosts),
            Self::ZoneNs => Some(SpecialDnsType::ZoneNs),
            Self::Csa => Some(SpecialDnsType::Csa),
            _ => None,
        }
    }

    /// Default field separator for this record type.
    ///
    /// Matches C defaults in `dnsdb_find()` (dnsdb.c lines 197–201):
    /// - SPF: `Concat` (empty string — concatenate TXT chunks)
    /// - MX/MXH/SRV/TLSA/CSA: `Char(' ')` (space between fields)
    /// - Everything else: `None` (TXT: first chunk; SOA: MNAME only)
    fn default_field_sep(self) -> FieldSep {
        match self {
            Self::Spf => FieldSep::Concat,
            Self::Mx | Self::MxHosts | Self::Srv | Self::Tlsa | Self::Csa => FieldSep::Char(' '),
            _ => FieldSep::None,
        }
    }
}

/// Field separator for multi-field record types and TXT chunk joining.
///
/// Controls how fields within a single DNS record are separated in output.
/// For TXT/SPF records, controls how multiple character-string chunks within
/// a single TXT RR are joined.
#[derive(Debug, Clone)]
enum FieldSep {
    /// No field separator (C: `outsep2 = NULL`).
    /// TXT → output only first chunk.  SOA → output only MNAME.
    None,
    /// Concatenate fields with no separator (C: `outsep2 = ""`).
    Concat,
    /// Separate fields with this character (C: `outsep2 = "X"`).
    Char(char),
}

/// Parsed dnsdb key/query specification after grammar analysis.
#[derive(Debug)]
struct DnsdbQuery {
    /// DNS record type to query.
    record_type: DnsdbType,
    /// List of domain names to query (colon-separated in key grammar).
    domains: Vec<String>,
    /// Output separator between records (default `\n`).
    output_sep: char,
    /// Field separator within records.
    field_sep: FieldSep,
    /// Temporary failure handling policy.
    defer_mode: DeferMode,
    /// DNSSEC validation policy.
    dnssec_mode: DnssecMode,
}

/// Opaque handle stored in the `LookupHandle` for DNS lookups.
///
/// Wraps `DnsResolver` in a `Mutex` because `DnsResolver` is `Send` but not
/// `Sync` (contains `RefCell` for the internal negative cache).  The `Mutex`
/// makes the wrapper `Send + Sync` as required by `LookupHandle`.
struct DnsdbHandle {
    resolver: Mutex<DnsResolver>,
}

// =============================================================================
// Key Grammar Parser
// =============================================================================

/// Parse a dnsdb key string into a structured `DnsdbQuery`.
///
/// Implements the key grammar from `dnsdb_find()` (dnsdb.c lines 140–285).
///
/// Grammar overview:
/// ```text
/// [>OUTSEP [,FIELDSEP | ;]]
/// [modifier,]...
/// [TYPE=]
/// domain_list
/// ```
///
/// Modifiers: `defer_strict`, `defer_lax`, `defer_never`,
///            `dnssec_strict`, `dnssec_lax`, `dnssec_never`,
///            `retrans_VAL`, `retry_VAL`
fn parse_dnsdb_key(key: &str) -> Result<DnsdbQuery, String> {
    let bytes = key.as_bytes();
    let mut pos = skip_ws(bytes, 0);

    // ── Phase 1: Output separator prefix ( >X[,Y | ;] ) ────────────────
    let mut output_sep = '\n';
    let mut field_sep_override: Option<FieldSep> = None;

    if pos < bytes.len() && bytes[pos] == b'>' {
        pos += 1;
        if pos >= bytes.len() {
            return Err("dnsdb: missing separator character after '>'".into());
        }
        output_sep = bytes[pos] as char;
        pos += 1;

        if pos < bytes.len() && bytes[pos] == b',' {
            pos += 1;
            if pos >= bytes.len() {
                return Err("dnsdb: missing field separator character after ','".into());
            }
            field_sep_override = Some(FieldSep::Char(bytes[pos] as char));
            pos += 1;
        } else if pos < bytes.len() && bytes[pos] == b';' {
            field_sep_override = Some(FieldSep::Concat);
            pos += 1;
        }
        pos = skip_ws(bytes, pos);
    }

    // ── Phase 2: Modifier keywords (comma-terminated) ───────────────────
    let mut defer_mode = DeferMode::Lax;
    let mut dnssec_mode = DnssecMode::Lax;

    loop {
        let remaining = &key[pos..];
        let matched = if starts_with_ci(remaining, "defer_strict") {
            defer_mode = DeferMode::Strict;
            12
        } else if starts_with_ci(remaining, "defer_never") {
            defer_mode = DeferMode::Never;
            11
        } else if starts_with_ci(remaining, "defer_lax") {
            defer_mode = DeferMode::Lax;
            9
        } else if starts_with_ci(remaining, "dnssec_strict") {
            dnssec_mode = DnssecMode::Strict;
            13
        } else if starts_with_ci(remaining, "dnssec_never") {
            dnssec_mode = DnssecMode::Never;
            12
        } else if starts_with_ci(remaining, "dnssec_lax") {
            dnssec_mode = DnssecMode::Lax;
            10
        } else if starts_with_ci(remaining, "retrans_") {
            // Skip the retrans value — resolver configuration is external.
            let after = &remaining[8..];
            8 + after.find(',').unwrap_or(after.len())
        } else if starts_with_ci(remaining, "retry_") {
            // Skip the retry value — resolver configuration is external.
            let after = &remaining[6..];
            6 + after.find(',').unwrap_or(after.len())
        } else {
            break;
        };

        pos += matched;
        // Modifiers must be followed by a comma separator.
        if pos < bytes.len() && bytes[pos] == b',' {
            pos += 1;
            pos = skip_ws(bytes, pos);
        } else {
            pos = skip_ws(bytes, pos);
            break;
        }
    }

    // ── Phase 3: Record type ( TYPE= prefix ) ──────────────────────────
    let remaining = &key[pos..];
    let record_type;
    if let Some(eq_idx) = remaining.find('=') {
        let type_str = remaining[..eq_idx].trim();
        record_type = parse_record_type(type_str)?;
        pos += eq_idx + 1;
    } else {
        record_type = DnsdbType::Txt;
    }

    // ── Phase 4: Field separator defaults ───────────────────────────────
    let field_sep = field_sep_override.unwrap_or_else(|| record_type.default_field_sep());

    // ── Phase 5: Domain list ────────────────────────────────────────────
    let domain_str = key[pos..].trim();
    if domain_str.is_empty() {
        return Err("dnsdb: no domain specified".into());
    }
    let domains = parse_domain_list(domain_str, record_type);
    if domains.is_empty() {
        return Err("dnsdb: empty domain list".into());
    }

    debug!(
        record_type = ?record_type,
        domain_count = domains.len(),
        output_sep = ?output_sep,
        defer_mode = ?defer_mode,
        dnssec_mode = ?dnssec_mode,
        "dnsdb: parsed key grammar"
    );

    Ok(DnsdbQuery {
        record_type,
        domains,
        output_sep,
        field_sep,
        defer_mode,
        dnssec_mode,
    })
}

/// Parse a record type name string (case-insensitive).
fn parse_record_type(s: &str) -> Result<DnsdbType, String> {
    match s.to_ascii_lowercase().as_str() {
        "a" => Ok(DnsdbType::A),
        "a+" => Ok(DnsdbType::Addresses),
        "aaaa" => Ok(DnsdbType::Aaaa),
        "cname" => Ok(DnsdbType::Cname),
        "csa" => Ok(DnsdbType::Csa),
        "mx" => Ok(DnsdbType::Mx),
        "mxh" => Ok(DnsdbType::MxHosts),
        "ns" => Ok(DnsdbType::Ns),
        "ptr" => Ok(DnsdbType::Ptr),
        "soa" => Ok(DnsdbType::Soa),
        "spf" => Ok(DnsdbType::Spf),
        "srv" => Ok(DnsdbType::Srv),
        "tlsa" => Ok(DnsdbType::Tlsa),
        "txt" => Ok(DnsdbType::Txt),
        "zns" => Ok(DnsdbType::ZoneNs),
        _ => Err(format!("dnsdb: unsupported DNS record type '{s}'")),
    }
}

/// Parse a colon-separated domain list with optional custom separator.
///
/// For PTR type with a single IP address, the entire string is treated as
/// one domain (matching C behavior where `sep = -1` prevents splitting).
fn parse_domain_list(s: &str, record_type: DnsdbType) -> Vec<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    // PTR with a bare IP address: don't split on colons (C: sep = -1).
    if record_type == DnsdbType::Ptr
        && !trimmed.starts_with('<')
        && trimmed.parse::<IpAddr>().is_ok()
    {
        return vec![trimmed.to_string()];
    }

    // Check for custom separator prefix ( <X... ).
    let (sep, list_str) = if let Some(rest) = trimmed.strip_prefix('<') {
        if rest.is_empty() {
            return Vec::new();
        }
        let sep_char = rest.as_bytes()[0] as char;
        (sep_char, rest[1..].trim_start())
    } else {
        (':', trimmed)
    };

    list_str
        .split(sep)
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
        .collect()
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Skip ASCII whitespace starting from `pos`.
fn skip_ws(bytes: &[u8], mut pos: usize) -> usize {
    while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
        pos += 1;
    }
    pos
}

/// Case-insensitive prefix check.
fn starts_with_ci(s: &str, prefix: &str) -> bool {
    s.len() >= prefix.len() && s.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

/// Encode a byte slice as lowercase hexadecimal pairs.
fn hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Append a value to the output string, inserting the output separator between
/// items (not before the first).
fn append_to_output(output: &mut String, sep: char, value: &str) {
    if !output.is_empty() {
        output.push(sep);
    }
    output.push_str(value);
}

// =============================================================================
// Record Formatting
// =============================================================================

/// Format answer-section records from a DNS response into the output string.
///
/// Iterates over answer records matching `filter_type`, formats each per the
/// query record type and field separator settings, and tracks the minimum TTL.
fn format_response_records(
    response: &DnsResponse,
    query: &DnsdbQuery,
    filter_type: DnsRecordType,
    queried_domain: &str,
    output: &mut String,
    min_ttl: &mut Option<u32>,
) {
    for record in response
        .records
        .iter()
        .filter(|r| r.section == DnsSection::Answer && r.record_type == filter_type)
    {
        // Track minimum TTL across all matched records for cache control.
        *min_ttl = Some(min_ttl.map_or(record.ttl, |m| m.min(record.ttl)));

        match (&record.data, &query.record_type) {
            // ── A record: IPv4 address string ───────────────────────
            (DnsRecordData::A(addr), _) => {
                append_to_output(output, query.output_sep, &addr.to_string());
            }

            // ── AAAA record: IPv6 address string ────────────────────
            (DnsRecordData::Aaaa(addr), _) => {
                append_to_output(output, query.output_sep, &addr.to_string());
            }

            // ── MX record: "preference exchange" ────────────────────
            (
                DnsRecordData::Mx {
                    preference,
                    exchange,
                },
                DnsdbType::Mx,
            ) => {
                let formatted = match &query.field_sep {
                    FieldSep::None => format!("{preference} {exchange}"),
                    FieldSep::Concat => format!("{preference}{exchange}"),
                    FieldSep::Char(c) => format!("{preference}{c}{exchange}"),
                };
                append_to_output(output, query.output_sep, &formatted);
            }

            // ── MXH (hostnames only): skip preference ───────────────
            (DnsRecordData::Mx { exchange, .. }, DnsdbType::MxHosts) => {
                append_to_output(output, query.output_sep, exchange);
            }

            // ── SRV record: "priority weight port target" ───────────
            (
                DnsRecordData::Srv {
                    priority,
                    weight,
                    port,
                    target,
                },
                DnsdbType::Srv,
            ) => {
                let formatted = match &query.field_sep {
                    FieldSep::None => {
                        format!("{priority} {weight} {port} {target}")
                    }
                    FieldSep::Concat => {
                        format!("{priority}{weight}{port}{target}")
                    }
                    FieldSep::Char(c) => {
                        format!("{priority}{c}{weight}{c}{port}{c}{target}")
                    }
                };
                append_to_output(output, query.output_sep, &formatted);
            }

            // ── CSA (Client SMTP Authorization) from SRV ────────────
            // Checks: priority must be 1.  Compares the domain where the
            // record was found with the originally queried domain to
            // determine the authorization status character.
            (
                DnsRecordData::Srv {
                    priority,
                    weight,
                    port,
                    target,
                    ..
                },
                DnsdbType::Csa,
            ) => {
                // C: if (priority != 1) continue;
                if *priority != 1 {
                    continue;
                }
                let found_domain = response
                    .fully_qualified_name
                    .as_deref()
                    .unwrap_or(queried_domain);
                let status = if found_domain != queried_domain {
                    // Record found at a parent domain.
                    if port & 1 != 0 {
                        "X"
                    } else {
                        "?"
                    }
                } else if *weight > 3 {
                    // Invalid CSA weight — skip this record.
                    continue;
                } else if *weight < 2 {
                    "N" // No authorization
                } else if *weight == 2 {
                    "Y" // Authorized
                } else {
                    "?" // Unknown
                };
                append_to_output(output, query.output_sep, &format!("{status} {target}"));
            }

            // ── TXT / SPF records: text content ─────────────────────
            // exim-dns provides each TXT RR as a single joined `String`.
            (DnsRecordData::Txt(text), DnsdbType::Txt | DnsdbType::Spf) => {
                append_to_output(output, query.output_sep, text);
            }

            // ── PTR record: hostname ────────────────────────────────
            (DnsRecordData::Ptr(name), _) => {
                append_to_output(output, query.output_sep, name);
            }

            // ── CNAME record: canonical name ────────────────────────
            (DnsRecordData::Cname(name), _) => {
                append_to_output(output, query.output_sep, name);
            }

            // ── NS record: nameserver hostname ──────────────────────
            (DnsRecordData::Ns(name), _) => {
                append_to_output(output, query.output_sep, name);
            }

            // ── SOA record: mname [sep rname sep serial ...] ────────
            // With FieldSep::None, only the primary NS (MNAME) is output.
            // With a separator, all 7 SOA fields are included.
            (
                DnsRecordData::Soa {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                },
                _,
            ) => {
                let formatted = match &query.field_sep {
                    FieldSep::None => mname.clone(),
                    FieldSep::Concat => {
                        format!("{mname}{rname}{serial}{refresh}{retry}{expire}{minimum}")
                    }
                    FieldSep::Char(c) => format!(
                        "{mname}{c}{rname}{c}{serial}{c}{refresh}{c}\
                         {retry}{c}{expire}{c}{minimum}"
                    ),
                };
                append_to_output(output, query.output_sep, &formatted);
            }

            // ── TLSA record: "usage selector matching hex_data" ─────
            (
                DnsRecordData::Tlsa {
                    cert_usage,
                    selector,
                    matching_type,
                    cert_data,
                },
                _,
            ) => {
                let hex = hex_encode(cert_data);
                let formatted = match &query.field_sep {
                    FieldSep::None => {
                        format!("{cert_usage} {selector} {matching_type} {hex}")
                    }
                    FieldSep::Concat => {
                        format!("{cert_usage}{selector}{matching_type}{hex}")
                    }
                    FieldSep::Char(c) => {
                        format!("{cert_usage}{c}{selector}{c}{matching_type}{c}{hex}")
                    }
                };
                append_to_output(output, query.output_sep, &formatted);
            }

            // ── Unmatched record data: skip silently ────────────────
            _ => {}
        }
    }
}

// =============================================================================
// Query Execution
// =============================================================================

/// Internal error type for per-domain DNS query results.
#[derive(Debug)]
enum QueryError {
    /// Domain not found (NXDOMAIN).
    NoMatch,
    /// Domain exists but no records of the requested type (NODATA).
    NoData,
    /// Temporary failure (SERVFAIL, timeout, DNSSEC policy violation).
    Temporary(String),
}

/// Execute a DNS query for a single domain within the dnsdb lookup.
///
/// Handles reverse IP construction for PTR/CSA, special type dispatch
/// (MXH/ZNS/CSA), the A+ dual-query pattern, DNSSEC policy enforcement,
/// and per-record formatting with TTL tracking.
fn execute_domain_query(
    resolver: &DnsResolver,
    domain: &str,
    query: &DnsdbQuery,
    output: &mut String,
    min_ttl: &mut Option<u32>,
) -> Result<(), QueryError> {
    // Build reverse name for PTR and CSA when the domain is an IP address.
    let lookup_domain = if matches!(query.record_type, DnsdbType::Ptr | DnsdbType::Csa)
        && domain.parse::<IpAddr>().is_ok()
    {
        DnsResolver::dns_build_reverse(domain)
            .map_err(|e| QueryError::Temporary(format!("reverse: {e}")))?
    } else {
        domain.to_string()
    };

    debug!(
        domain = %lookup_domain,
        record_type = ?query.record_type,
        "dnsdb: performing DNS query"
    );

    // ── A+ (Addresses): dual AAAA + A query ─────────────────────────────
    // The C code uses a do-while loop that first queries AAAA, then A.
    // Both queries are attempted regardless of individual failures
    // (matching defer_lax/defer_never behavior in C).
    if query.record_type == DnsdbType::Addresses {
        let mut last_temp_err: Option<String> = None;

        // AAAA query
        match do_standard_lookup(
            resolver,
            &lookup_domain,
            DnsRecordType::Aaaa,
            query,
            domain,
            output,
            min_ttl,
        ) {
            Ok(()) => {}
            Err(QueryError::NoMatch | QueryError::NoData) => {}
            Err(QueryError::Temporary(msg)) => {
                last_temp_err = Some(msg);
            }
        }

        // A query
        match do_standard_lookup(
            resolver,
            &lookup_domain,
            DnsRecordType::A,
            query,
            domain,
            output,
            min_ttl,
        ) {
            Ok(()) => {}
            Err(QueryError::NoMatch | QueryError::NoData) => {}
            Err(QueryError::Temporary(msg)) => {
                last_temp_err = Some(msg);
            }
        }

        return if let Some(msg) = last_temp_err {
            Err(QueryError::Temporary(msg))
        } else {
            Ok(())
        };
    }

    // ── Special types: MXH / ZNS / CSA ─────────────────────────────────
    if let Some(special) = query.record_type.to_special_type() {
        return do_special_lookup(
            resolver,
            &lookup_domain,
            special,
            query,
            domain,
            output,
            min_ttl,
        );
    }

    // ── Standard DNS query ──────────────────────────────────────────────
    let record_type = query
        .record_type
        .to_record_type()
        .ok_or_else(|| QueryError::Temporary("dnsdb: no record type mapping".into()))?;

    do_standard_lookup(
        resolver,
        &lookup_domain,
        record_type,
        query,
        domain,
        output,
        min_ttl,
    )
}

/// Perform a standard DNS lookup via `DnsResolver::dns_lookup()` and format
/// the matching answer records.
fn do_standard_lookup(
    resolver: &DnsResolver,
    lookup_domain: &str,
    record_type: DnsRecordType,
    query: &DnsdbQuery,
    original_domain: &str,
    output: &mut String,
    min_ttl: &mut Option<u32>,
) -> Result<(), QueryError> {
    let (response, _cname_target) = resolver
        .dns_lookup(lookup_domain, record_type, CNAME_CHAIN_LIMIT)
        .map_err(|e| map_dns_error(&e))?;

    check_response(&response, query, lookup_domain)?;

    // For A+ queries, the filter type matches the actual query type,
    // not the virtual Addresses type.
    let filter_type = if query.record_type == DnsdbType::Addresses {
        record_type
    } else {
        query.record_type.search_record_type()
    };

    format_response_records(
        &response,
        query,
        filter_type,
        original_domain,
        output,
        min_ttl,
    );
    Ok(())
}

/// Perform a special DNS lookup via `DnsResolver::dns_special_lookup()` and
/// format the matching answer records.
fn do_special_lookup(
    resolver: &DnsResolver,
    lookup_domain: &str,
    special_type: SpecialDnsType,
    query: &DnsdbQuery,
    original_domain: &str,
    output: &mut String,
    min_ttl: &mut Option<u32>,
) -> Result<(), QueryError> {
    let response = resolver
        .dns_special_lookup(lookup_domain, special_type)
        .map_err(|e| map_dns_error(&e))?;

    check_response(&response, query, lookup_domain)?;

    let search_type = query.record_type.search_record_type();
    format_response_records(
        &response,
        query,
        search_type,
        original_domain,
        output,
        min_ttl,
    );
    Ok(())
}

/// Validate a DNS response: check result code and DNSSEC policy.
fn check_response(
    response: &DnsResponse,
    query: &DnsdbQuery,
    lookup_domain: &str,
) -> Result<(), QueryError> {
    match response.result {
        DnsResult::Succeed => {}
        DnsResult::NoMatch => return Err(QueryError::NoMatch),
        DnsResult::NoData => return Err(QueryError::NoData),
        DnsResult::Again => {
            return Err(QueryError::Temporary(format!(
                "DNS temporary failure for {lookup_domain}"
            )));
        }
        DnsResult::Fail => {
            return Err(QueryError::Temporary(format!(
                "DNS query failed for {lookup_domain}"
            )));
        }
    }

    // DNSSEC strict mode: require the Authenticated Data (AD) flag.
    if query.dnssec_mode == DnssecMode::Strict && !response.authenticated_data {
        return Err(QueryError::Temporary(format!(
            "DNSSEC: response for {lookup_domain} is not authenticated"
        )));
    }

    Ok(())
}

/// Map a `DnsError` to a `QueryError`.
fn map_dns_error(err: &DnsError) -> QueryError {
    match err {
        DnsError::QueryResult(result) => match result {
            DnsResult::NoMatch => QueryError::NoMatch,
            DnsResult::NoData => QueryError::NoData,
            DnsResult::Again | DnsResult::Fail => QueryError::Temporary(format!("{err}")),
            DnsResult::Succeed => QueryError::Temporary(format!("unexpected DNS state: {err}")),
        },
        DnsError::ResolveError(_) | DnsError::RuntimeError(_) => {
            QueryError::Temporary(format!("{err}"))
        }
        DnsError::InvalidDomain(_) | DnsError::InvalidAddress(_) => {
            QueryError::Temporary(format!("{err}"))
        }
        DnsError::ConfigError(_) => QueryError::Temporary(format!("{err}")),
    }
}

// =============================================================================
// DnsdbLookup — LookupDriver Implementation
// =============================================================================

/// DNS query lookup driver for the Exim MTA.
///
/// Provides the `dnsdb` lookup type, performing DNS queries via `DnsResolver`
/// from the `exim-dns` crate and returning formatted results for Exim's
/// expansion engine.
///
/// Registered at compile time via `inventory::submit!` as `"dnsdb"`.
#[derive(Debug)]
pub struct DnsdbLookup;

impl LookupDriver for DnsdbLookup {
    /// Create a DNS resolver handle.
    ///
    /// Replaces C `dnsdb_open()` (dnsdb.c line 84) which returned a dummy
    /// non-null handle `(void*)(1)`.  Our implementation creates a real
    /// `DnsResolver` backed by the system's DNS configuration, wrapped in a
    /// `Mutex` for the `LookupHandle` trait requirement of `Send + Sync`.
    fn open(&self, _filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        debug!("dnsdb: creating resolver handle");
        let resolver = DnsResolver::from_system().map_err(|e| {
            DriverError::InitFailed(format!("dnsdb: failed to create DNS resolver: {e}"))
        })?;
        Ok(Box::new(DnsdbHandle {
            resolver: Mutex::new(resolver),
        }))
    }

    /// File-based check — always succeeds for query-style lookups.
    ///
    /// DNS lookups are query-style and have no underlying file to validate.
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

    /// Execute a DNS lookup based on the dnsdb key grammar.
    ///
    /// Replaces C `dnsdb_find()` (dnsdb.c lines 132–582).  Parses the extended
    /// key grammar, performs DNS queries via `DnsResolver`, formats results per
    /// record type, enforces DNSSEC policy, and tracks TTL for cache control.
    ///
    /// Returns `LookupResult::Found` with formatted results and minimum TTL,
    /// `LookupResult::NotFound` if no records match, or
    /// `LookupResult::Deferred` for temporary failures per the defer policy.
    fn find(
        &self,
        handle: &LookupHandle,
        _filename: Option<&str>,
        key: &str,
        _opts: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        // Parse the key grammar into a structured query.
        let query = parse_dnsdb_key(key).map_err(DriverError::ExecutionFailed)?;

        // Downcast the handle to get the resolver.
        let dns_handle = handle.downcast_ref::<DnsdbHandle>().ok_or_else(|| {
            DriverError::ExecutionFailed("dnsdb: invalid handle type (expected DnsdbHandle)".into())
        })?;
        let resolver = dns_handle
            .resolver
            .lock()
            .map_err(|e| DriverError::TempFail(format!("dnsdb: resolver mutex poisoned: {e}")))?;

        // Execute queries for each domain in the list.
        let mut output = String::new();
        let mut min_ttl: Option<u32> = None;
        let mut fail_rc_is_defer = false;

        for domain in &query.domains {
            match execute_domain_query(&resolver, domain, &query, &mut output, &mut min_ttl) {
                Ok(()) => {
                    // Records may or may not have been added to output.
                }
                Err(QueryError::NoMatch) | Err(QueryError::NoData) => {
                    debug!(domain = %domain, "dnsdb: no matching records");
                    continue;
                }
                Err(QueryError::Temporary(msg)) => {
                    warn!(
                        domain = %domain,
                        error = %msg,
                        "dnsdb: temporary DNS failure"
                    );
                    match query.defer_mode {
                        DeferMode::Strict => {
                            return Ok(LookupResult::Deferred { message: msg });
                        }
                        DeferMode::Lax => {
                            fail_rc_is_defer = true;
                        }
                        DeferMode::Never => {
                            // Treat as not-found; continue to next domain.
                        }
                    }
                }
            }
        }

        // Determine the final lookup result.
        if output.is_empty() {
            if fail_rc_is_defer {
                debug!("dnsdb: all queries deferred, returning Deferred");
                Ok(LookupResult::Deferred {
                    message: "dnsdb: DNS lookup deferred".into(),
                })
            } else {
                debug!("dnsdb: no results found across all domains");
                Ok(LookupResult::NotFound)
            }
        } else {
            debug!(
                result_len = output.len(),
                cache_ttl = ?min_ttl,
                "dnsdb: returning results"
            );
            Ok(LookupResult::Found {
                value: output,
                cache_ttl: min_ttl,
            })
        }
    }

    /// Close the DNS resolver handle.
    ///
    /// The resolver is dropped automatically when the `Box<DnsdbHandle>` is
    /// consumed, releasing the internal tokio runtime and resolver resources.
    fn close(&self, _handle: LookupHandle) {
        debug!("dnsdb: handle closed");
    }

    /// Tidy up — no persistent resources to release.
    fn tidy(&self) {
        debug!("dnsdb: tidy (no-op)");
    }

    /// No quoting is needed for query-style DNS lookups.
    fn quote(&self, _value: &str, _additional: Option<&str>) -> Option<String> {
        None
    }

    /// Return version information for the dnsdb lookup module.
    ///
    /// Replaces C `dnsdb_version_report()` (dnsdb.c lines 584–592).
    fn version_report(&self) -> Option<String> {
        Some(format!(
            "Library version: DNSDB: Exim {EXIM_VERSION} builtin"
        ))
    }

    /// This is a query-style lookup — no filename is required.
    fn lookup_type(&self) -> LookupType {
        LookupType::QUERY_STYLE
    }

    /// Driver name for configuration matching.
    fn driver_name(&self) -> &str {
        "dnsdb"
    }
}

// =============================================================================
// Compile-Time Registration
// =============================================================================

// Register the `dnsdb` lookup driver at compile time via the `inventory`
// crate, replacing the C `dnsdb_lookup_module_info` static registration
// struct (dnsdb.c lines 602–619).
inventory::submit! {
    LookupDriverFactory {
        name: "dnsdb",
        create: || Box::new(DnsdbLookup),
        lookup_type: LookupType::QUERY_STYLE,
        avail_string: Some("dnsdb (exim-dns resolver)"),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Driver metadata tests ───────────────────────────────────────────

    #[test]
    fn test_driver_name() {
        let driver = DnsdbLookup;
        assert_eq!(driver.driver_name(), "dnsdb");
    }

    #[test]
    fn test_lookup_type_is_query_style() {
        let driver = DnsdbLookup;
        assert!(driver.lookup_type().is_query_style());
    }

    #[test]
    fn test_version_report_contains_version() {
        let driver = DnsdbLookup;
        let report = driver.version_report().expect("report must exist");
        assert!(report.contains("DNSDB"));
        assert!(report.contains(EXIM_VERSION));
        assert!(report.contains("builtin"));
    }

    #[test]
    fn test_check_always_passes() {
        let driver = DnsdbLookup;
        let handle: LookupHandle = Box::new(0_u32);
        assert!(driver.check(&handle, None, 0, &[], &[]).unwrap());
    }

    #[test]
    fn test_quote_returns_none() {
        let driver = DnsdbLookup;
        assert!(driver.quote("anything", None).is_none());
    }

    // ── Key grammar parser tests ────────────────────────────────────────

    #[test]
    fn test_parse_bare_domain_defaults_to_txt() {
        let q = parse_dnsdb_key("example.com").unwrap();
        assert_eq!(q.record_type, DnsdbType::Txt);
        assert_eq!(q.domains, vec!["example.com"]);
        assert_eq!(q.output_sep, '\n');
        assert!(matches!(q.field_sep, FieldSep::None));
        assert_eq!(q.defer_mode, DeferMode::Lax);
        assert_eq!(q.dnssec_mode, DnssecMode::Lax);
    }

    #[test]
    fn test_parse_typed_a_query() {
        let q = parse_dnsdb_key("A=example.com").unwrap();
        assert_eq!(q.record_type, DnsdbType::A);
        assert_eq!(q.domains, vec!["example.com"]);
    }

    #[test]
    fn test_parse_typed_mx_defaults() {
        let q = parse_dnsdb_key("mx=example.com").unwrap();
        assert_eq!(q.record_type, DnsdbType::Mx);
        assert!(matches!(q.field_sep, FieldSep::Char(' ')));
    }

    #[test]
    fn test_parse_spf_default_concat() {
        let q = parse_dnsdb_key("spf=example.com").unwrap();
        assert_eq!(q.record_type, DnsdbType::Spf);
        assert!(matches!(q.field_sep, FieldSep::Concat));
    }

    #[test]
    fn test_parse_output_separator() {
        let q = parse_dnsdb_key(">, txt=example.com").unwrap();
        assert_eq!(q.output_sep, ',');
    }

    #[test]
    fn test_parse_field_separator_char() {
        // >\n is a single output separator (newline), then ,| sets field sep
        let q = parse_dnsdb_key(">\n,| txt=example.com").unwrap();
        assert_eq!(q.output_sep, '\n');
        assert!(matches!(q.field_sep, FieldSep::Char('|')));
    }

    #[test]
    fn test_parse_field_separator_semicolon() {
        // >\n is a single output separator (newline), then ; sets concat mode
        let q = parse_dnsdb_key(">\n; txt=example.com").unwrap();
        assert_eq!(q.output_sep, '\n');
        assert!(matches!(q.field_sep, FieldSep::Concat));
    }

    #[test]
    fn test_parse_defer_strict_modifier() {
        let q = parse_dnsdb_key("defer_strict, txt=example.com").unwrap();
        assert_eq!(q.defer_mode, DeferMode::Strict);
    }

    #[test]
    fn test_parse_defer_never_modifier() {
        let q = parse_dnsdb_key("defer_never, txt=example.com").unwrap();
        assert_eq!(q.defer_mode, DeferMode::Never);
    }

    #[test]
    fn test_parse_dnssec_strict_modifier() {
        let q = parse_dnsdb_key("dnssec_strict, txt=example.com").unwrap();
        assert_eq!(q.dnssec_mode, DnssecMode::Strict);
    }

    #[test]
    fn test_parse_dnssec_never_modifier() {
        let q = parse_dnsdb_key("dnssec_never, txt=example.com").unwrap();
        assert_eq!(q.dnssec_mode, DnssecMode::Never);
    }

    #[test]
    fn test_parse_combined_modifiers() {
        let q = parse_dnsdb_key("defer_strict,dnssec_lax, mx=example.com").unwrap();
        assert_eq!(q.defer_mode, DeferMode::Strict);
        assert_eq!(q.dnssec_mode, DnssecMode::Lax);
        assert_eq!(q.record_type, DnsdbType::Mx);
    }

    #[test]
    fn test_parse_retrans_retry_skipped() {
        let q = parse_dnsdb_key("retrans_5s,retry_3, txt=example.com").unwrap();
        assert_eq!(q.record_type, DnsdbType::Txt);
        assert_eq!(q.domains, vec!["example.com"]);
    }

    #[test]
    fn test_parse_multiple_colon_separated_domains() {
        let q = parse_dnsdb_key("txt=a.com:b.com:c.com").unwrap();
        assert_eq!(q.domains, vec!["a.com", "b.com", "c.com"]);
    }

    #[test]
    fn test_parse_custom_domain_separator() {
        let q = parse_dnsdb_key("txt=<;a.com;b.com;c.com").unwrap();
        assert_eq!(q.domains, vec!["a.com", "b.com", "c.com"]);
    }

    #[test]
    fn test_parse_ptr_single_ip_no_split() {
        let q = parse_dnsdb_key("ptr=192.168.1.1").unwrap();
        assert_eq!(q.domains, vec!["192.168.1.1"]);
    }

    #[test]
    fn test_parse_ptr_ipv6_no_split() {
        let q = parse_dnsdb_key("ptr=::1").unwrap();
        assert_eq!(q.domains, vec!["::1"]);
    }

    #[test]
    fn test_parse_addresses_type() {
        let q = parse_dnsdb_key("a+=example.com").unwrap();
        assert_eq!(q.record_type, DnsdbType::Addresses);
    }

    #[test]
    fn test_parse_virtual_types() {
        assert_eq!(
            parse_dnsdb_key("mxh=x.com").unwrap().record_type,
            DnsdbType::MxHosts
        );
        assert_eq!(
            parse_dnsdb_key("zns=x.com").unwrap().record_type,
            DnsdbType::ZoneNs
        );
        assert_eq!(
            parse_dnsdb_key("csa=x.com").unwrap().record_type,
            DnsdbType::Csa
        );
    }

    #[test]
    fn test_parse_empty_key_fails() {
        assert!(parse_dnsdb_key("").is_err());
    }

    #[test]
    fn test_parse_type_only_no_domain_fails() {
        assert!(parse_dnsdb_key("txt=").is_err());
    }

    #[test]
    fn test_parse_unknown_type_fails() {
        assert!(parse_dnsdb_key("bogus=example.com").is_err());
    }

    // ── Record type conversion tests ────────────────────────────────────

    #[test]
    fn test_search_record_type_standard() {
        assert_eq!(DnsdbType::A.search_record_type(), DnsRecordType::A);
        assert_eq!(DnsdbType::Aaaa.search_record_type(), DnsRecordType::Aaaa);
        assert_eq!(DnsdbType::Mx.search_record_type(), DnsRecordType::Mx);
        assert_eq!(DnsdbType::Srv.search_record_type(), DnsRecordType::Srv);
        assert_eq!(DnsdbType::Txt.search_record_type(), DnsRecordType::Txt);
        assert_eq!(DnsdbType::Ptr.search_record_type(), DnsRecordType::Ptr);
        assert_eq!(DnsdbType::Soa.search_record_type(), DnsRecordType::Soa);
        assert_eq!(DnsdbType::Tlsa.search_record_type(), DnsRecordType::Tlsa);
    }

    #[test]
    fn test_search_record_type_virtual() {
        assert_eq!(
            DnsdbType::Addresses.search_record_type(),
            DnsRecordType::Aaaa
        );
        assert_eq!(DnsdbType::MxHosts.search_record_type(), DnsRecordType::Mx);
        assert_eq!(DnsdbType::ZoneNs.search_record_type(), DnsRecordType::Ns);
        assert_eq!(DnsdbType::Csa.search_record_type(), DnsRecordType::Srv);
        assert_eq!(DnsdbType::Spf.search_record_type(), DnsRecordType::Txt);
    }

    #[test]
    fn test_special_type_conversions() {
        assert_eq!(
            DnsdbType::MxHosts.to_special_type(),
            Some(SpecialDnsType::MxHosts)
        );
        assert_eq!(
            DnsdbType::ZoneNs.to_special_type(),
            Some(SpecialDnsType::ZoneNs)
        );
        assert_eq!(DnsdbType::Csa.to_special_type(), Some(SpecialDnsType::Csa));
        assert_eq!(DnsdbType::A.to_special_type(), None);
        assert_eq!(DnsdbType::Txt.to_special_type(), None);
    }

    #[test]
    fn test_to_record_type_standard() {
        assert_eq!(DnsdbType::A.to_record_type(), Some(DnsRecordType::A));
        assert_eq!(DnsdbType::Aaaa.to_record_type(), Some(DnsRecordType::Aaaa));
        assert_eq!(DnsdbType::Txt.to_record_type(), Some(DnsRecordType::Txt));
        assert_eq!(DnsdbType::Spf.to_record_type(), Some(DnsRecordType::Txt));
    }

    #[test]
    fn test_to_record_type_virtual_returns_none() {
        assert_eq!(DnsdbType::Addresses.to_record_type(), None);
        assert_eq!(DnsdbType::MxHosts.to_record_type(), None);
        assert_eq!(DnsdbType::ZoneNs.to_record_type(), None);
        assert_eq!(DnsdbType::Csa.to_record_type(), None);
    }

    // ── Default field separator tests ───────────────────────────────────

    #[test]
    fn test_default_field_sep_txt_is_none() {
        assert!(matches!(DnsdbType::Txt.default_field_sep(), FieldSep::None));
    }

    #[test]
    fn test_default_field_sep_spf_is_concat() {
        assert!(matches!(
            DnsdbType::Spf.default_field_sep(),
            FieldSep::Concat
        ));
    }

    #[test]
    fn test_default_field_sep_mx_is_space() {
        assert!(matches!(
            DnsdbType::Mx.default_field_sep(),
            FieldSep::Char(' ')
        ));
    }

    #[test]
    fn test_default_field_sep_srv_is_space() {
        assert!(matches!(
            DnsdbType::Srv.default_field_sep(),
            FieldSep::Char(' ')
        ));
    }

    #[test]
    fn test_default_field_sep_tlsa_is_space() {
        assert!(matches!(
            DnsdbType::Tlsa.default_field_sep(),
            FieldSep::Char(' ')
        ));
    }

    // ── Utility function tests ──────────────────────────────────────────

    #[test]
    fn test_hex_encode_empty() {
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn test_hex_encode_various_bytes() {
        assert_eq!(hex_encode(&[0x01, 0xab, 0xff]), "01abff");
        assert_eq!(hex_encode(&[0x00, 0x10, 0x20]), "001020");
    }

    #[test]
    fn test_append_to_output_first_item() {
        let mut out = String::new();
        append_to_output(&mut out, '\n', "first");
        assert_eq!(out, "first");
    }

    #[test]
    fn test_append_to_output_separator_between() {
        let mut out = String::new();
        append_to_output(&mut out, '\n', "first");
        append_to_output(&mut out, '\n', "second");
        assert_eq!(out, "first\nsecond");
    }

    #[test]
    fn test_append_to_output_custom_separator() {
        let mut out = String::new();
        append_to_output(&mut out, ',', "a");
        append_to_output(&mut out, ',', "b");
        append_to_output(&mut out, ',', "c");
        assert_eq!(out, "a,b,c");
    }

    #[test]
    fn test_starts_with_ci_positive() {
        assert!(starts_with_ci("defer_strict", "defer_strict"));
        assert!(starts_with_ci("DEFER_STRICT", "defer_strict"));
        assert!(starts_with_ci("Defer_Strict,rest", "defer_strict"));
    }

    #[test]
    fn test_starts_with_ci_negative() {
        assert!(!starts_with_ci("defer", "defer_strict"));
        assert!(!starts_with_ci("", "defer_strict"));
    }

    #[test]
    fn test_skip_ws() {
        assert_eq!(skip_ws(b"  hello", 0), 2);
        assert_eq!(skip_ws(b"hello", 0), 0);
        assert_eq!(skip_ws(b"", 0), 0);
        assert_eq!(skip_ws(b" \t\n x", 0), 4);
    }

    // ── Domain list parsing tests ───────────────────────────────────────

    #[test]
    fn test_parse_domain_list_single() {
        let domains = parse_domain_list("example.com", DnsdbType::Txt);
        assert_eq!(domains, vec!["example.com"]);
    }

    #[test]
    fn test_parse_domain_list_colon_separated() {
        let domains = parse_domain_list("a.com:b.com:c.com", DnsdbType::Txt);
        assert_eq!(domains, vec!["a.com", "b.com", "c.com"]);
    }

    #[test]
    fn test_parse_domain_list_custom_separator() {
        let domains = parse_domain_list("<;a.com;b.com", DnsdbType::Txt);
        assert_eq!(domains, vec!["a.com", "b.com"]);
    }

    #[test]
    fn test_parse_domain_list_ptr_ip_no_split() {
        let domains = parse_domain_list("192.168.1.1", DnsdbType::Ptr);
        assert_eq!(domains, vec!["192.168.1.1"]);
    }

    #[test]
    fn test_parse_domain_list_ptr_hostname_splits() {
        let domains = parse_domain_list("a.com:b.com", DnsdbType::Ptr);
        assert_eq!(domains, vec!["a.com", "b.com"]);
    }

    #[test]
    fn test_parse_domain_list_empty() {
        assert!(parse_domain_list("", DnsdbType::Txt).is_empty());
        assert!(parse_domain_list("   ", DnsdbType::Txt).is_empty());
    }
}
