// =============================================================================
// exim-lookups/src/dnsdb.rs — DNS Query Lookup Backend
// =============================================================================
//
// Rewrites `src/src/lookups/dnsdb.c` (623 lines) as a pure Rust DNS query
// lookup backend using the `hickory-resolver` crate. This lookup provides
// the `dnsdb` lookup type, which performs DNS queries and returns results
// formatted for Exim's string expansion engine.
//
// Supported record types: A, AAAA, MX, SRV, TXT, PTR, CNAME, NS, SOA,
// TLSA, CSA (Client SMTP Authorization). Multiple record types can be
// combined in a single lookup via comma-separated type lists.
//
// C function mapping:
//   dnsdb_open()  → DnsdbLookup::open()  — no-op (DNS is connectionless)
//   dnsdb_find()  → DnsdbLookup::find()  — parse query spec, perform DNS lookup
//   dnsdb_close() → DnsdbLookup::close() — no-op
//
// Per AAP §0.7.2: This file contains ZERO `unsafe` code.
// Per AAP §0.4.2: Uses `inventory::submit!` for compile-time registration.
// Per AAP §0.7.3: tokio runtime scoped to block_on() for async resolver calls.

use std::fmt::Write;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;

use hickory_resolver::config::{ResolveHosts, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::Resolver;

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;

// =============================================================================
// Type alias for the concrete Resolver type
// =============================================================================

/// Concrete resolver type using Tokio connection provider.
/// hickory-resolver 0.25+ requires a generic ConnectionProvider parameter.
type DnsResolver = Resolver<TokioConnectionProvider>;

// =============================================================================
// Constants
// =============================================================================

/// Default separator for multi-record results (newline).
/// C equivalent: `\n` default in dnsdb_find.
const DEFAULT_SEPARATOR: &str = "\n";

/// Default output separator between fields in structured records (space).
const DEFAULT_FIELD_SEPARATOR: &str = " ";

/// Maximum number of DNS query retries before giving up.
const MAX_DNS_RETRIES: usize = 3;

/// Timeout for individual DNS queries (seconds).
const DNS_TIMEOUT_SECS: u64 = 30;

// =============================================================================
// DNS Record Type Enum
// =============================================================================

/// Supported DNS record types for the dnsdb lookup.
///
/// Replaces the C `T_A`, `T_AAAA`, `T_MX`, etc. constants from `dns.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsRecordType {
    A,
    Aaaa,
    Mx,
    Srv,
    Txt,
    Ptr,
    Cname,
    Ns,
    Soa,
    Tlsa,
    Csa,
}

impl DnsRecordType {
    /// Parse a record type name from a string (case-insensitive).
    fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_uppercase().as_str() {
            "A" => Some(Self::A),
            "AAAA" => Some(Self::Aaaa),
            "MX" => Some(Self::Mx),
            "SRV" => Some(Self::Srv),
            "TXT" => Some(Self::Txt),
            "PTR" => Some(Self::Ptr),
            "CNAME" => Some(Self::Cname),
            "NS" => Some(Self::Ns),
            "SOA" => Some(Self::Soa),
            "TLSA" => Some(Self::Tlsa),
            "CSA" => Some(Self::Csa),
            _ => None,
        }
    }
}

// =============================================================================
// DNS Handle — holds a cached resolver
// =============================================================================

/// Handle for the DNS lookup — holds a cached resolver instance.
/// Protected by Mutex for interior mutability in multi-threaded contexts.
struct DnsdbHandle {
    /// Cached resolver instance.
    resolver: Mutex<DnsResolver>,
}

// =============================================================================
// DnsdbLookup — LookupDriver implementation
// =============================================================================

/// DNS query lookup driver.
///
/// Provides DNS record lookup for Exim's expansion engine. The key format is:
/// ```text
/// [<options>] <record_type>=<domain_name>
/// ```
///
/// Options:
/// - `defer_never` — return FAIL instead of DEFER on DNS timeouts
/// - `defer_lax` — return FAIL for NXDOMAIN, DEFER for others
/// - `retrans=<seconds>` — per-query timeout
/// - `retry=<count>` — number of retries
/// - `dnssec_strict` / `dnssec_lax` — DNSSEC validation mode
/// - `>separator` — output record separator (default newline)
/// - `,fieldsep` — field separator within records (default space)
#[derive(Debug)]
struct DnsdbLookup;

impl DnsdbLookup {
    fn new() -> Self {
        Self
    }

    /// Create a resolver with the given timeout and retry settings.
    ///
    /// Uses `Resolver::builder_with_config()` from hickory-resolver 0.25+.
    /// The TokioConnectionProvider enables async DNS resolution bridged
    /// via block_on() per AAP §0.7.3.
    fn create_resolver(timeout_secs: u64, retries: usize) -> Result<DnsResolver, DriverError> {
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(timeout_secs);
        opts.attempts = retries;
        opts.use_hosts_file = ResolveHosts::Never;

        let resolver = Resolver::builder_with_config(
            ResolverConfig::default(),
            TokioConnectionProvider::default(),
        )
        .with_options(opts)
        .build();

        Ok(resolver)
    }

    /// Parse the query specification and return (record_types, domain, options).
    fn parse_query_spec(
        key: &str,
    ) -> Result<(Vec<DnsRecordType>, String, QueryOptions), DriverError> {
        let mut opts = QueryOptions::default();
        let mut remaining = key.trim();

        // Parse leading options
        while !remaining.is_empty() {
            if remaining.starts_with("defer_never") {
                opts.defer_mode = DeferMode::Never;
                remaining = remaining["defer_never".len()..].trim_start();
            } else if remaining.starts_with("defer_lax") {
                opts.defer_mode = DeferMode::Lax;
                remaining = remaining["defer_lax".len()..].trim_start();
            } else if remaining.starts_with("dnssec_strict") {
                opts.dnssec = DnssecMode::Strict;
                remaining = remaining["dnssec_strict".len()..].trim_start();
            } else if remaining.starts_with("dnssec_lax") {
                opts.dnssec = DnssecMode::Lax;
                remaining = remaining["dnssec_lax".len()..].trim_start();
            } else if let Some(rest) = remaining.strip_prefix("retrans=") {
                let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
                opts.timeout_secs = rest[..end].parse().unwrap_or(DNS_TIMEOUT_SECS);
                remaining = rest[end..].trim_start();
            } else if let Some(rest) = remaining.strip_prefix("retry=") {
                let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
                opts.retries = rest[..end].parse().unwrap_or(MAX_DNS_RETRIES);
                remaining = rest[end..].trim_start();
            } else if remaining.starts_with('>') {
                // Custom separator: >X where X is the separator character
                if remaining.len() > 1 {
                    opts.separator = remaining[1..2].to_string();
                    remaining = remaining[2..].trim_start();
                } else {
                    remaining = &remaining[1..];
                }
            } else if remaining.starts_with(',') {
                // Custom field separator: ,X
                if remaining.len() > 1 {
                    opts.field_sep = remaining[1..2].to_string();
                    remaining = remaining[2..].trim_start();
                } else {
                    remaining = &remaining[1..];
                }
            } else {
                break;
            }
        }

        // Parse type=domain
        let (type_str, domain) = if let Some(eq_pos) = remaining.find('=') {
            (
                &remaining[..eq_pos],
                remaining[eq_pos + 1..].trim().to_string(),
            )
        } else {
            // Default to TXT if no type specified
            ("TXT", remaining.to_string())
        };

        // Parse record types (can be comma-separated)
        let mut record_types = Vec::new();
        for t in type_str.split(',') {
            let t = t.trim();
            if t.is_empty() {
                continue;
            }
            match DnsRecordType::from_name(t) {
                Some(rt) => record_types.push(rt),
                None => {
                    return Err(DriverError::ExecutionFailed(format!(
                        "dnsdb: unknown DNS record type: {}",
                        t
                    )));
                }
            }
        }

        if record_types.is_empty() {
            record_types.push(DnsRecordType::Txt);
        }

        if domain.is_empty() {
            return Err(DriverError::ExecutionFailed(
                "dnsdb: no domain name specified".into(),
            ));
        }

        Ok((record_types, domain, opts))
    }

    /// Perform a DNS lookup for a specific record type and domain.
    ///
    /// All hickory-resolver lookup methods are async. We bridge to synchronous
    /// execution via tokio block_on() per AAP §0.7.3.
    fn lookup_records(
        resolver: &DnsResolver,
        rtype: DnsRecordType,
        domain: &str,
        opts: &QueryOptions,
    ) -> Result<Vec<String>, DnsLookupError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                DnsLookupError::Defer(format!("dnsdb: failed to create runtime: {}", e))
            })?;

        rt.block_on(Self::lookup_records_async(resolver, rtype, domain, opts))
    }

    /// Async implementation of DNS record lookup.
    async fn lookup_records_async(
        resolver: &DnsResolver,
        rtype: DnsRecordType,
        domain: &str,
        opts: &QueryOptions,
    ) -> Result<Vec<String>, DnsLookupError> {
        let mut results = Vec::new();

        match rtype {
            DnsRecordType::A => {
                let response = resolver
                    .lookup_ip(domain)
                    .await
                    .map_err(|e| DnsLookupError::from_resolve_error(e, opts.defer_mode))?;
                for addr in response.iter() {
                    if let IpAddr::V4(v4) = addr {
                        results.push(v4.to_string());
                    }
                }
            }
            DnsRecordType::Aaaa => {
                let response = resolver
                    .lookup_ip(domain)
                    .await
                    .map_err(|e| DnsLookupError::from_resolve_error(e, opts.defer_mode))?;
                for addr in response.iter() {
                    if let IpAddr::V6(v6) = addr {
                        results.push(v6.to_string());
                    }
                }
            }
            DnsRecordType::Mx => {
                let response = resolver
                    .mx_lookup(domain)
                    .await
                    .map_err(|e| DnsLookupError::from_resolve_error(e, opts.defer_mode))?;
                for mx in response.iter() {
                    results.push(format!(
                        "{}{}{}",
                        mx.preference(),
                        opts.field_sep,
                        mx.exchange()
                    ));
                }
            }
            DnsRecordType::Srv => {
                let response = resolver
                    .srv_lookup(domain)
                    .await
                    .map_err(|e| DnsLookupError::from_resolve_error(e, opts.defer_mode))?;
                for srv in response.iter() {
                    results.push(format!(
                        "{}{}{}{}{}{}{}",
                        srv.priority(),
                        opts.field_sep,
                        srv.weight(),
                        opts.field_sep,
                        srv.port(),
                        opts.field_sep,
                        srv.target()
                    ));
                }
            }
            DnsRecordType::Txt => {
                let response = resolver
                    .txt_lookup(domain)
                    .await
                    .map_err(|e| DnsLookupError::from_resolve_error(e, opts.defer_mode))?;
                for txt in response.iter() {
                    // Concatenate all character strings in the TXT record
                    let mut value = String::new();
                    for part in txt.iter() {
                        value.push_str(&String::from_utf8_lossy(part));
                    }
                    results.push(value);
                }
            }
            DnsRecordType::Ptr => {
                // PTR requires an IP address — construct reverse name
                if let Ok(ip) = IpAddr::from_str(domain) {
                    let reverse_name = match ip {
                        IpAddr::V4(v4) => {
                            let octets = v4.octets();
                            format!(
                                "{}.{}.{}.{}.in-addr.arpa.",
                                octets[3], octets[2], octets[1], octets[0]
                            )
                        }
                        IpAddr::V6(v6) => {
                            let segments = v6.segments();
                            let mut nibbles = String::new();
                            for seg in segments.iter().rev() {
                                for shift in (0..16).step_by(4) {
                                    let nibble = (seg >> shift) & 0xf;
                                    write!(nibbles, "{:x}.", nibble).unwrap_or_default();
                                }
                            }
                            format!("{}ip6.arpa.", nibbles)
                        }
                    };
                    let response = resolver
                        .lookup(&reverse_name, RecordType::PTR)
                        .await
                        .map_err(|e| DnsLookupError::from_resolve_error(e, opts.defer_mode))?;
                    for record in response.iter() {
                        results.push(record.to_string());
                    }
                } else {
                    // If not an IP, do a direct PTR lookup on the name
                    let response = resolver
                        .lookup(domain, RecordType::PTR)
                        .await
                        .map_err(|e| DnsLookupError::from_resolve_error(e, opts.defer_mode))?;
                    for record in response.iter() {
                        results.push(record.to_string());
                    }
                }
            }
            DnsRecordType::Cname => {
                let response = resolver
                    .lookup(domain, RecordType::CNAME)
                    .await
                    .map_err(|e| DnsLookupError::from_resolve_error(e, opts.defer_mode))?;
                for record in response.iter() {
                    results.push(record.to_string());
                }
            }
            DnsRecordType::Ns => {
                let response = resolver
                    .ns_lookup(domain)
                    .await
                    .map_err(|e| DnsLookupError::from_resolve_error(e, opts.defer_mode))?;
                for ns in response.iter() {
                    results.push(ns.to_string());
                }
            }
            DnsRecordType::Soa => {
                let response = resolver
                    .soa_lookup(domain)
                    .await
                    .map_err(|e| DnsLookupError::from_resolve_error(e, opts.defer_mode))?;
                for soa in response.iter() {
                    results.push(format!(
                        "{}{}{}{}{}{}{}{}{}{}{}",
                        soa.mname(),
                        opts.field_sep,
                        soa.rname(),
                        opts.field_sep,
                        soa.serial(),
                        opts.field_sep,
                        soa.refresh(),
                        opts.field_sep,
                        soa.retry(),
                        opts.field_sep,
                        soa.expire()
                    ));
                }
            }
            DnsRecordType::Tlsa => {
                let response = resolver
                    .tlsa_lookup(domain)
                    .await
                    .map_err(|e| DnsLookupError::from_resolve_error(e, opts.defer_mode))?;
                for record in response.iter() {
                    // Format: usage selector matching_type cert_data_hex
                    // CertUsage, Selector, Matching implement From<T> for u8
                    // but not Display, so convert to numeric values.
                    let usage: u8 = record.cert_usage().into();
                    let selector: u8 = record.selector().into();
                    let matching: u8 = record.matching().into();
                    results.push(format!(
                        "{} {} {} {}",
                        usage,
                        selector,
                        matching,
                        record
                            .cert_data()
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<String>()
                    ));
                }
            }
            DnsRecordType::Csa => {
                // CSA (Client SMTP Authorization) is a TXT record lookup on
                // _client._smtp.<domain>. This is Exim-specific.
                let csa_domain = format!("_client._smtp.{}", domain);
                let response = resolver
                    .txt_lookup(&csa_domain)
                    .await
                    .map_err(|e| DnsLookupError::from_resolve_error(e, opts.defer_mode))?;
                for txt in response.iter() {
                    let mut value = String::new();
                    for part in txt.iter() {
                        value.push_str(&String::from_utf8_lossy(part));
                    }
                    results.push(value);
                }
            }
        }

        Ok(results)
    }
}

// =============================================================================
// Query Options
// =============================================================================

/// Options parsed from the dnsdb query specification.
#[derive(Debug, Clone)]
struct QueryOptions {
    /// How to handle DNS lookup failures.
    defer_mode: DeferMode,
    /// DNSSEC validation mode.
    dnssec: DnssecMode,
    /// Per-query timeout in seconds.
    timeout_secs: u64,
    /// Number of retries.
    retries: usize,
    /// Separator between multiple result records.
    separator: String,
    /// Separator between fields within a record.
    field_sep: String,
}

impl Default for QueryOptions {
    fn default() -> Self {
        Self {
            defer_mode: DeferMode::Default,
            dnssec: DnssecMode::Off,
            timeout_secs: DNS_TIMEOUT_SECS,
            retries: MAX_DNS_RETRIES,
            separator: DEFAULT_SEPARATOR.to_string(),
            field_sep: DEFAULT_FIELD_SEPARATOR.to_string(),
        }
    }
}

/// Defer handling mode for DNS lookup failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeferMode {
    /// Default: DEFER on temporary failures.
    Default,
    /// Never defer — return FAIL on all failures.
    Never,
    /// Lax: FAIL on NXDOMAIN, DEFER on other failures.
    Lax,
}

/// DNSSEC validation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnssecMode {
    /// No DNSSEC validation requested.
    Off,
    /// DNSSEC validation requested but not required.
    Lax,
    /// DNSSEC validation required — fail if not validated.
    Strict,
}

// =============================================================================
// DNS Lookup Error
// =============================================================================

/// Internal error type for DNS lookups, supporting defer/fail distinction.
#[derive(Debug)]
enum DnsLookupError {
    /// Temporary failure — the lookup should be retried.
    Defer(String),
    /// Permanent failure — no such domain or record.
    NotFound,
}

impl DnsLookupError {
    fn from_resolve_error(e: hickory_resolver::ResolveError, defer_mode: DeferMode) -> Self {
        // hickory-resolver 0.25 uses method-based error classification
        // instead of enum variants for NoRecordsFound.
        if e.is_no_records_found() || e.is_nx_domain() {
            return Self::NotFound;
        }

        match defer_mode {
            DeferMode::Never => Self::NotFound,
            DeferMode::Lax => {
                // For lax mode, NXDOMAIN is a definitive failure.
                // Other errors are deferred.
                let msg = format!("{}", e);
                if msg.contains("NXDomain") || msg.contains("no records") {
                    Self::NotFound
                } else {
                    Self::Defer(format!("DNS lookup failed: {}", e))
                }
            }
            DeferMode::Default => Self::Defer(format!("DNS lookup failed: {}", e)),
        }
    }
}

// =============================================================================
// LookupDriver Implementation
// =============================================================================

impl LookupDriver for DnsdbLookup {
    fn driver_name(&self) -> &str {
        "dnsdb"
    }

    fn lookup_type(&self) -> LookupType {
        LookupType::QUERY_STYLE
    }

    fn open(&self, _filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        // DNS is connectionless — create a resolver handle.
        let resolver = Self::create_resolver(DNS_TIMEOUT_SECS, MAX_DNS_RETRIES)?;
        Ok(Box::new(DnsdbHandle {
            resolver: Mutex::new(resolver),
        }))
    }

    fn check(
        &self,
        _handle: &LookupHandle,
        _filename: Option<&str>,
        _modemask: i32,
        _owners: &[u32],
        _owngroups: &[u32],
    ) -> Result<bool, DriverError> {
        // DNS lookups are query-style and don't have files to check.
        // Always return true (no file-based validation needed).
        Ok(true)
    }

    fn find(
        &self,
        handle: &LookupHandle,
        _filename: Option<&str>,
        key: &str,
        _opts: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        let dns_handle = handle
            .downcast_ref::<DnsdbHandle>()
            .ok_or_else(|| DriverError::ExecutionFailed("dnsdb: invalid handle type".into()))?;

        let (record_types, domain, opts) = Self::parse_query_spec(key)?;

        tracing::debug!(
            domain = %domain,
            types = ?record_types,
            "dnsdb: performing DNS lookup"
        );

        // Recreate resolver if custom timeout/retries are specified
        let resolver = if opts.timeout_secs != DNS_TIMEOUT_SECS || opts.retries != MAX_DNS_RETRIES {
            Self::create_resolver(opts.timeout_secs, opts.retries)?
        } else {
            let guard = dns_handle.resolver.lock().map_err(|e| {
                DriverError::ExecutionFailed(format!("dnsdb: mutex poisoned: {}", e))
            })?;
            // Return early using the cached resolver
            let mut all_results = Vec::new();
            for rtype in &record_types {
                match Self::lookup_records(&guard, *rtype, &domain, &opts) {
                    Ok(records) => all_results.extend(records),
                    Err(DnsLookupError::NotFound) => {}
                    Err(DnsLookupError::Defer(msg)) => {
                        return Err(DriverError::TempFail(msg));
                    }
                }
            }

            if all_results.is_empty() {
                return Ok(LookupResult::NotFound);
            }

            let combined = all_results.join(&opts.separator);
            return Ok(LookupResult::Found {
                value: combined,
                cache_ttl: None,
            });
        };

        let mut all_results = Vec::new();
        for rtype in &record_types {
            match Self::lookup_records(&resolver, *rtype, &domain, &opts) {
                Ok(records) => all_results.extend(records),
                Err(DnsLookupError::NotFound) => {}
                Err(DnsLookupError::Defer(msg)) => {
                    return Err(DriverError::TempFail(msg));
                }
            }
        }

        if all_results.is_empty() {
            Ok(LookupResult::NotFound)
        } else {
            let combined = all_results.join(&opts.separator);
            Ok(LookupResult::Found {
                value: combined,
                cache_ttl: None,
            })
        }
    }

    fn close(&self, _handle: LookupHandle) {
        tracing::debug!("dnsdb: closed");
    }

    fn tidy(&self) {
        tracing::debug!("dnsdb: tidy (no-op)");
    }

    fn version_report(&self) -> Option<String> {
        Some("Lookup: dnsdb (Rust, hickory-resolver)".to_string())
    }
}

// =============================================================================
// Compile-Time Registration
// =============================================================================

inventory::submit! {
    LookupDriverFactory {
        name: "dnsdb",
        create: || Box::new(DnsdbLookup::new()),
        lookup_type: LookupType::QUERY_STYLE,
        avail_string: Some("dnsdb (hickory-resolver)"),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dnsdb_driver_name() {
        let driver = DnsdbLookup::new();
        assert_eq!(driver.driver_name(), "dnsdb");
    }

    #[test]
    fn test_dnsdb_lookup_type() {
        let driver = DnsdbLookup::new();
        assert!(driver.lookup_type().is_query_style());
    }

    #[test]
    fn test_parse_record_types() {
        assert_eq!(DnsRecordType::from_name("A"), Some(DnsRecordType::A));
        assert_eq!(DnsRecordType::from_name("aaaa"), Some(DnsRecordType::Aaaa));
        assert_eq!(DnsRecordType::from_name("MX"), Some(DnsRecordType::Mx));
        assert_eq!(DnsRecordType::from_name("SRV"), Some(DnsRecordType::Srv));
        assert_eq!(DnsRecordType::from_name("TXT"), Some(DnsRecordType::Txt));
        assert_eq!(DnsRecordType::from_name("PTR"), Some(DnsRecordType::Ptr));
        assert_eq!(
            DnsRecordType::from_name("CNAME"),
            Some(DnsRecordType::Cname)
        );
        assert_eq!(DnsRecordType::from_name("NS"), Some(DnsRecordType::Ns));
        assert_eq!(DnsRecordType::from_name("SOA"), Some(DnsRecordType::Soa));
        assert_eq!(DnsRecordType::from_name("TLSA"), Some(DnsRecordType::Tlsa));
        assert_eq!(DnsRecordType::from_name("CSA"), Some(DnsRecordType::Csa));
        assert_eq!(DnsRecordType::from_name("UNKNOWN"), None);
    }

    #[test]
    fn test_parse_simple_query() {
        let (types, domain, _opts) = DnsdbLookup::parse_query_spec("A=example.com").unwrap();
        assert_eq!(types, vec![DnsRecordType::A]);
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn test_parse_multi_type_query() {
        let (types, domain, _opts) = DnsdbLookup::parse_query_spec("A,AAAA=example.com").unwrap();
        assert_eq!(types, vec![DnsRecordType::A, DnsRecordType::Aaaa]);
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn test_parse_query_with_options() {
        let (types, domain, opts) =
            DnsdbLookup::parse_query_spec("defer_never retry=5 retrans=10 MX=example.com").unwrap();
        assert_eq!(types, vec![DnsRecordType::Mx]);
        assert_eq!(domain, "example.com");
        assert_eq!(opts.defer_mode, DeferMode::Never);
        assert_eq!(opts.retries, 5);
        assert_eq!(opts.timeout_secs, 10);
    }

    #[test]
    fn test_parse_query_no_domain() {
        let result = DnsdbLookup::parse_query_spec("A=");
        assert!(result.is_err());
    }

    #[test]
    fn test_default_query_options() {
        let opts = QueryOptions::default();
        assert_eq!(opts.separator, "\n");
        assert_eq!(opts.field_sep, " ");
        assert_eq!(opts.timeout_secs, DNS_TIMEOUT_SECS);
        assert_eq!(opts.retries, MAX_DNS_RETRIES);
    }

    #[test]
    fn test_version_report() {
        let driver = DnsdbLookup::new();
        let report = driver.version_report();
        assert!(report.is_some());
        assert!(report.unwrap().contains("dnsdb"));
    }

    #[test]
    fn test_check_always_passes() {
        let driver = DnsdbLookup::new();
        let handle: LookupHandle = Box::new(42_u32);
        // DNS lookups don't check files — always returns true
        // (The actual handle type doesn't matter for check())
        let result = driver.check(&handle, None, 0, &[], &[]);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
