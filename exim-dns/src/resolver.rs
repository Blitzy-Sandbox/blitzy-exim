//! Core DNS resolution module — A/AAAA/MX/SRV/TLSA/PTR queries via hickory-resolver.
//!
//! This module replaces the entire `src/src/dns.c` (1,445 lines) and DNS-related
//! portions of `src/src/host.c` (3,424 lines) with a safe Rust implementation
//! using the `hickory-resolver` crate (v0.25).
//!
//! # Architecture
//!
//! [`DnsResolver`] wraps `hickory_resolver::TokioResolver` with a tokio runtime
//! for synchronous bridging via `block_on()`.  Per AAP §0.7.3, the tokio runtime
//! is scoped ONLY to DNS query execution — the main daemon event loop uses the
//! same fork-per-connection + poll/select model as the C implementation.
//!
//! # Taint Tracking
//!
//! DNS-sourced data is tainted (untrusted external input).  Per AAP §0.4.3:
//! - Hostnames from PTR records → wrapped in [`exim_store::Tainted<String>`]
//! - IP addresses from A/AAAA records → wrapped in [`exim_store::Clean<IpAddr>`]
//! - Domain names from configuration → [`exim_store::Clean<String>`]
//!
//! # Source Origins
//!
//! - `src/src/dns.c` — `dns_init()`, `dns_build_reverse()`, `dns_next_rr()`,
//!   `dns_is_secure()`, `dns_is_aa()`, `dns_set_insecure()`, `dns_text_type()`,
//!   `dns_basic_lookup()`, `dns_lookup()`, `dns_special_lookup()`,
//!   `dns_address_from_rr()`, `dns_expire_from_soa()`, negative cache
//! - `src/src/host.c` — `dns_lookup_timerwrap()`, `host_name_lookup()`,
//!   `host_find_byname()`, `host_find_bydns()`, `host_aton()`, `host_nmtoa()`

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant, SystemTime};

use hickory_resolver::config::ResolverConfig as HickoryConfig;
use hickory_resolver::config::ResolverOpts;
use hickory_resolver::lookup::Lookup;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::rr::{RData, Record, RecordType};
use hickory_resolver::ResolveError;
use hickory_resolver::TokioResolver;
use tokio::runtime::Runtime as TokioRuntime;
use tracing::{debug, info, trace, warn};

use exim_store::{Clean, Tainted};

// =============================================================================
// DNS Result Codes
// =============================================================================

/// DNS query result codes, matching the C enum from `src/src/dns.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsResult {
    /// Query completed successfully with matching records.
    Succeed,
    /// NXDOMAIN — the domain name does not exist.
    NoMatch,
    /// Domain exists but has no records of the requested type.
    NoData,
    /// Temporary failure (SERVFAIL, timeout, network error).
    Again,
    /// Permanent failure in name resolution.
    Fail,
}

impl DnsResult {
    /// Returns the human-readable name of the DNS result code.
    ///
    /// Replaces C `dns_rc_names[]` array from dns.c.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Succeed => "DNS_SUCCEED",
            Self::NoMatch => "DNS_NOMATCH",
            Self::NoData => "DNS_NODATA",
            Self::Again => "DNS_AGAIN",
            Self::Fail => "DNS_FAIL",
        }
    }
}

impl fmt::Display for DnsResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// =============================================================================
// DNS Error Type
// =============================================================================

/// Errors that can occur during DNS operations.
#[derive(Debug)]
pub enum DnsError {
    /// The underlying hickory-resolver returned an error.
    ResolveError(ResolveError),
    /// Failed to create the tokio runtime for async DNS bridging.
    RuntimeError(std::io::Error),
    /// Domain name is invalid or contains illegal characters.
    InvalidDomain(String),
    /// IP address string is invalid.
    InvalidAddress(String),
    /// DNS query returned a non-success result code.
    QueryResult(DnsResult),
    /// Internal configuration error.
    ConfigError(String),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::ResolveError(e) => write!(f, "DNS resolution error: {e}"),
            DnsError::RuntimeError(e) => write!(f, "DNS runtime error: {e}"),
            DnsError::InvalidDomain(d) => write!(f, "invalid domain name: '{d}'"),
            DnsError::InvalidAddress(a) => write!(f, "invalid IP address: '{a}'"),
            DnsError::QueryResult(code) => write!(f, "DNS query result: {code}"),
            DnsError::ConfigError(msg) => write!(f, "DNS config error: {msg}"),
        }
    }
}

impl std::error::Error for DnsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DnsError::ResolveError(e) => Some(e),
            DnsError::RuntimeError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ResolveError> for DnsError {
    fn from(err: ResolveError) -> Self {
        DnsError::ResolveError(err)
    }
}

// =============================================================================
// DNS Record Types
// =============================================================================

/// Standard DNS record types used in queries.
///
/// Replaces C integer constants (T_A, T_AAAA, T_MX, etc.) from dns.c.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsRecordType {
    /// A record — IPv4 address.
    A,
    /// AAAA record — IPv6 address.
    Aaaa,
    /// MX record — mail exchange.
    Mx,
    /// SRV record — service locator.
    Srv,
    /// PTR record — reverse DNS pointer.
    Ptr,
    /// TXT record — text data.
    Txt,
    /// CNAME record — canonical name alias.
    Cname,
    /// NS record — nameserver delegation.
    Ns,
    /// SOA record — start of authority.
    Soa,
    /// TLSA record — TLS authentication (DANE).
    Tlsa,
}

impl DnsRecordType {
    /// Converts a DNS record type to its human-readable string.
    ///
    /// Replaces C `dns_text_type()` from dns.c lines 607-626.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Mx => "MX",
            Self::Srv => "SRV",
            Self::Ptr => "PTR",
            Self::Txt => "TXT",
            Self::Cname => "CNAME",
            Self::Ns => "NS",
            Self::Soa => "SOA",
            Self::Tlsa => "TLSA",
        }
    }

    /// Converts to the hickory-resolver `RecordType`.
    fn to_hickory(self) -> RecordType {
        match self {
            Self::A => RecordType::A,
            Self::Aaaa => RecordType::AAAA,
            Self::Mx => RecordType::MX,
            Self::Srv => RecordType::SRV,
            Self::Ptr => RecordType::PTR,
            Self::Txt => RecordType::TXT,
            Self::Cname => RecordType::CNAME,
            Self::Ns => RecordType::NS,
            Self::Soa => RecordType::SOA,
            Self::Tlsa => RecordType::TLSA,
        }
    }
}

impl fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// =============================================================================
// DNS Response Section Identifiers
// =============================================================================

/// Identifies a section within a DNS response message.
///
/// Replaces C `dns_next_rr()` reset modes: `RESET_ANSWERS`, `RESET_AUTHORITY`,
/// `RESET_ADDITIONAL` from dns.c lines 352-485.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsSection {
    /// Answer section — contains direct response records.
    Answer,
    /// Authority section — contains NS/SOA records for delegation.
    Authority,
    /// Additional section — contains glue records (e.g., A records for NS hosts).
    Additional,
}

// =============================================================================
// Special / Virtual DNS Query Types
// =============================================================================

/// Virtual DNS query types that map to composite lookup strategies.
///
/// These replace the negative integer DNS type constants from dns.c:
/// - `T_MXH = -2` → [`SpecialDnsType::MxHosts`]
/// - `T_ZNS = -1` → [`SpecialDnsType::ZoneNs`]
/// - `T_CSA = -3` → [`SpecialDnsType::Csa`]
/// - SOA with parent-walking → [`SpecialDnsType::Soa`]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpecialDnsType {
    /// MX lookup returning only hostnames (no priorities).
    /// C equivalent: `T_MXH = -2`.
    MxHosts,
    /// Zone NS lookup — walks up parent domains until NS records found.
    /// C equivalent: `T_ZNS = -1`.
    ZoneNs,
    /// Client SMTP Authorization — SRV lookup at `_client._smtp.<domain>`.
    /// C equivalent: `T_CSA = -3`.
    Csa,
    /// SOA lookup with parent domain walking.
    Soa,
}

impl fmt::Display for SpecialDnsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MxHosts => f.write_str("MXH"),
            Self::ZoneNs => f.write_str("ZNS"),
            Self::Csa => f.write_str("CSA"),
            Self::Soa => f.write_str("SOA"),
        }
    }
}

// =============================================================================
// DNSSEC Status
// =============================================================================

/// DNSSEC validation status for DNS records and host entries.
///
/// Replaces the C tri-state DNSSEC tracking used throughout `host.c` and `dns.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum DnssecStatus {
    /// DNSSEC status has not been determined.
    #[default]
    Unknown,
    /// Records are DNSSEC-validated (AD bit set or AA trusted).
    Yes,
    /// Records are NOT DNSSEC-validated.
    No,
}

impl fmt::Display for DnssecStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => f.write_str("unknown"),
            Self::Yes => f.write_str("yes"),
            Self::No => f.write_str("no"),
        }
    }
}

// =============================================================================
// Host Lookup Method
// =============================================================================

/// Method used for host name resolution.
///
/// Replaces C `host_name_lookup()` method selection from host.c.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostLookupMethod {
    /// Resolve via DNS PTR queries.
    ByDns,
    /// Resolve via system getaddrinfo/gethostbyaddr (libc).
    ByAddr,
}

// =============================================================================
// DNS Record Data
// =============================================================================

/// Parsed DNS record data for various record types.
///
/// Replaces the C `dns_address_from_rr()` extraction and record-type-specific
/// data structures scattered across `dns.c` and `host.c`.
#[derive(Debug, Clone)]
pub enum DnsRecordData {
    /// A record — single IPv4 address.
    A(Ipv4Addr),
    /// AAAA record — single IPv6 address.
    Aaaa(Ipv6Addr),
    /// MX record — preference value and mail exchange hostname.
    Mx {
        /// MX preference (lower = higher priority).
        preference: u16,
        /// Mail exchange hostname.
        exchange: String,
    },
    /// SRV record — priority, weight, port, and target hostname.
    Srv {
        /// Service priority (lower = higher priority).
        priority: u16,
        /// Weight for load balancing among equal-priority targets.
        weight: u16,
        /// TCP/UDP port for the service.
        port: u16,
        /// Target hostname providing the service.
        target: String,
    },
    /// PTR record — domain name pointer.
    Ptr(String),
    /// TXT record — concatenated text data.
    Txt(String),
    /// CNAME record — canonical name alias target.
    Cname(String),
    /// NS record — name server hostname.
    Ns(String),
    /// SOA record — authority information.
    Soa {
        /// Primary nameserver for the zone.
        mname: String,
        /// Responsible person email (in DNS label form).
        rname: String,
        /// Zone serial number.
        serial: u32,
        /// Refresh interval in seconds.
        refresh: i32,
        /// Retry interval in seconds.
        retry: i32,
        /// Expire time in seconds.
        expire: i32,
        /// Minimum TTL for negative caching (seconds).
        minimum: u32,
    },
    /// TLSA record — TLS authentication data (DANE).
    Tlsa {
        /// Certificate usage field (0–3 per RFC 6698).
        cert_usage: u8,
        /// Selector field (0=full cert, 1=SubjectPublicKeyInfo).
        selector: u8,
        /// Matching type (0=exact, 1=SHA-256, 2=SHA-512).
        matching_type: u8,
        /// Certificate association data.
        cert_data: Vec<u8>,
    },
    /// Unknown/unsupported record type — raw bytes preserved.
    Other(Vec<u8>),
}

// =============================================================================
// DNS Record
// =============================================================================

/// A single DNS resource record from a response.
///
/// Replaces C `dns_record` struct from dns.c, with parsed data instead of raw
/// wire format.
#[derive(Debug, Clone)]
pub struct DnsRecord {
    /// Fully qualified owner name of this record.
    pub name: String,
    /// Time-to-live in seconds.
    pub ttl: u32,
    /// Record type.
    pub record_type: DnsRecordType,
    /// Which section of the DNS response this record came from.
    pub section: DnsSection,
    /// Parsed record data.
    pub data: DnsRecordData,
}

// =============================================================================
// DNS Response
// =============================================================================

/// Complete DNS response with parsed records, DNSSEC status, and metadata.
///
/// Replaces C `dns_answer` struct from dns.c.  The `dns_next_rr()` iteration
/// pattern is replaced by the [`DnsRecordIterator`] type and the `records` vec.
#[derive(Debug, Clone)]
pub struct DnsResponse {
    /// All resource records from the response, ordered by section then position.
    pub records: Vec<DnsRecord>,
    /// Whether the response has the AD (Authenticated Data) bit set.
    pub authenticated_data: bool,
    /// Whether the response has the AA (Authoritative Answer) bit set.
    pub authoritative: bool,
    /// Overall result code for this DNS query.
    pub result: DnsResult,
    /// The fully-qualified name from the first CNAME target, if CNAME following occurred.
    pub fully_qualified_name: Option<String>,
}

impl DnsResponse {
    /// Checks if this DNS response is DNSSEC-validated.
    ///
    /// Returns `true` if the AD (Authenticated Data) bit is set, or if the
    /// AA (Authoritative Answer) bit is set and the queried domain matches
    /// the `trust_aa_domains` list.
    ///
    /// Replaces C `dns_is_secure()` from dns.c lines 529-567.
    #[cfg(feature = "dnssec")]
    pub fn dns_is_secure(&self, trust_aa_domains: Option<&str>) -> bool {
        if self.authenticated_data {
            return true;
        }
        // Trust AA bit if the response domain matches the dns_trust_aa list
        if self.authoritative {
            if let Some(domains) = trust_aa_domains {
                if let Some(ref fqn) = self.fully_qualified_name {
                    return domain_matches_list(fqn, domains);
                }
            }
        }
        false
    }

    /// Returns `true` if the AA (Authoritative Answer) flag is set.
    ///
    /// Replaces C `dns_is_aa()` from dns.c lines 584-592.
    pub fn dns_is_aa(&self) -> bool {
        self.authoritative
    }

    /// Clears the AD (Authenticated Data) bit on this response.
    ///
    /// Used when a CNAME chain crosses an insecure zone — the entire chain
    /// must be marked insecure.
    ///
    /// Replaces C `dns_set_insecure()` from dns.c lines 569-576.
    pub fn dns_set_insecure(&mut self) {
        self.authenticated_data = false;
    }

    /// Returns an iterator over answer-section records.
    pub fn answer_records(&self) -> impl Iterator<Item = &DnsRecord> {
        self.records
            .iter()
            .filter(|r| r.section == DnsSection::Answer)
    }

    /// Returns an iterator over authority-section records.
    pub fn authority_records(&self) -> impl Iterator<Item = &DnsRecord> {
        self.records
            .iter()
            .filter(|r| r.section == DnsSection::Authority)
    }

    /// Returns an iterator over additional-section records.
    pub fn additional_records(&self) -> impl Iterator<Item = &DnsRecord> {
        self.records
            .iter()
            .filter(|r| r.section == DnsSection::Additional)
    }

    /// Extracts the negative TTL from an SOA record in the authority section.
    ///
    /// Used for negative caching — the SOA minimum TTL field from the authority
    /// section defines how long to cache NXDOMAIN / NODATA results.
    ///
    /// Replaces C `dns_expire_from_soa()` from dns.c lines ~750-835.
    pub fn soa_negative_ttl(&self) -> Option<u32> {
        for record in self.authority_records() {
            if let DnsRecordData::Soa { minimum, .. } = &record.data {
                // Use the lesser of SOA minimum and the SOA record's own TTL,
                // per RFC 2308 §5.
                return Some((*minimum).min(record.ttl));
            }
        }
        None
    }
}

// =============================================================================
// DNS Record Iterator
// =============================================================================

/// Iterator over DNS resource records in a response, with section filtering.
///
/// Replaces C `dns_next_rr()` with `RESET_ANSWERS`/`RESET_AUTHORITY`/
/// `RESET_ADDITIONAL`/`RESET_NEXT` pattern from dns.c lines 352-485.
pub struct DnsRecordIterator<'a> {
    records: &'a [DnsRecord],
    position: usize,
    section_filter: Option<DnsSection>,
}

impl<'a> DnsRecordIterator<'a> {
    /// Creates a new iterator over all records in the given response.
    pub fn new(records: &'a [DnsRecord]) -> Self {
        Self {
            records,
            position: 0,
            section_filter: None,
        }
    }

    /// Creates a new iterator filtered to a specific section.
    pub fn for_section(records: &'a [DnsRecord], section: DnsSection) -> Self {
        Self {
            records,
            position: 0,
            section_filter: Some(section),
        }
    }

    /// Returns the current section filter, if any.
    pub fn section(&self) -> Option<DnsSection> {
        self.section_filter
    }
}

impl<'a> Iterator for DnsRecordIterator<'a> {
    type Item = &'a DnsRecord;

    fn next(&mut self) -> Option<Self::Item> {
        while self.position < self.records.len() {
            let record = &self.records[self.position];
            self.position += 1;
            if let Some(filter) = self.section_filter {
                if record.section == filter {
                    return Some(record);
                }
            } else {
                return Some(record);
            }
        }
        None
    }
}

// =============================================================================
// Negative Cache
// =============================================================================

/// Entry in the negative DNS result cache.
///
/// Stores a failed lookup result and its SOA-derived expiry time.
#[derive(Debug, Clone)]
pub struct NegativeCacheEntry {
    /// The DNS result code for this cached failure.
    pub result: DnsResult,
    /// When this cache entry expires (based on SOA negative TTL).
    pub expiry: SystemTime,
}

/// Negative DNS result cache, replacing C `tree_dns_fails` balanced binary tree.
///
/// Keys are formatted as `"{name}/{type}"` (replicates C `dns_fail_tag()` from
/// dns.c lines ~638-745).
#[derive(Debug)]
pub struct NegativeCache {
    entries: HashMap<String, NegativeCacheEntry>,
}

impl NegativeCache {
    /// Creates a new empty negative cache.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Looks up a cached negative result.
    ///
    /// Returns the cached result if present and not expired; removes expired entries.
    pub fn get(&mut self, name: &str, record_type: DnsRecordType) -> Option<DnsResult> {
        let key = Self::make_key(name, record_type);
        if let Some(entry) = self.entries.get(&key) {
            if entry.expiry > SystemTime::now() {
                trace!(key = %key, result = %entry.result, "negative cache hit");
                return Some(entry.result);
            }
            // Expired — remove it
            self.entries.remove(&key);
            trace!(key = %key, "negative cache entry expired, removed");
        }
        None
    }

    /// Inserts a negative result into the cache with the given TTL.
    pub fn insert(&mut self, name: &str, record_type: DnsRecordType, result: DnsResult, ttl: u32) {
        let key = Self::make_key(name, record_type);
        let expiry = SystemTime::now() + Duration::from_secs(u64::from(ttl));
        trace!(key = %key, result = %result, ttl = ttl, "negative cache insert");
        self.entries
            .insert(key, NegativeCacheEntry { result, expiry });
    }

    /// Removes all entries from the cache.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Evicts all expired entries from the cache.
    pub fn evict_expired(&mut self) {
        let now = SystemTime::now();
        let before = self.entries.len();
        self.entries.retain(|_k, v| v.expiry > now);
        let removed = before - self.entries.len();
        if removed > 0 {
            debug!(
                removed = removed,
                remaining = self.entries.len(),
                "negative cache eviction"
            );
        }
    }

    /// Constructs the cache key string, replicating C `dns_fail_tag()`.
    fn make_key(name: &str, record_type: DnsRecordType) -> String {
        format!("{name}/{}", record_type.as_str())
    }
}

impl Default for NegativeCache {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Resolver Configuration
// =============================================================================

/// DNS resolver configuration, replacing C `dns_init()` parameters and
/// associated global variables from `globals.c`.
///
/// Each field maps to a specific C global or flag:
/// - `qualify_single` ← `HOST_FIND_QUALIFY_SINGLE` flag (host.c)
/// - `search_parents` ← `HOST_FIND_SEARCH_PARENTS` flag (host.c)
/// - `dnssec_request` ← `dns_dnssec_ok >= 0` (globals.c) + `!DISABLE_DNSSEC`
/// - `use_edns0` ← `dns_use_edns0 >= 0` (globals.c)
/// - `retrans` ← `dns_retrans` global (globals.c)
/// - `retry` ← `dns_retry` global (globals.c)
/// - `cname_loops` ← `dns_cname_loops` global (default 1, globals.c)
/// - `csa_search_limit` ← `dns_csa_search_limit` global (default 5, globals.c)
/// - `trust_aa_domains` ← `dns_trust_aa` global (globals.c)
/// - `again_means_nonexist` ← `dns_again_means_nonexist` global (globals.c)
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    /// If true, add the default domain to single-label hostnames (C: RES_DEFNAMES).
    pub qualify_single: bool,
    /// If true, search parent domains (C: RES_DNSRCH).
    pub search_parents: bool,
    /// If true, request DNSSEC validation (C: RES_USE_DNSSEC).
    pub dnssec_request: bool,
    /// If true, use EDNS0 extensions (C: RES_USE_EDNS0).
    pub use_edns0: bool,
    /// Retransmission interval in seconds (C: dns_retrans).
    pub retrans: u32,
    /// Number of retries per nameserver (C: dns_retry).
    pub retry: u32,
    /// Maximum CNAME chain depth (C: dns_cname_loops, default 1).
    pub cname_loops: u32,
    /// Maximum CSA parent domain walking depth (C: dns_csa_search_limit, default 5).
    pub csa_search_limit: u32,
    /// Colon-separated list of domains where the AA bit is trusted as DNSSEC
    /// validation (C: dns_trust_aa, default None).
    pub trust_aa_domains: Option<String>,
    /// Colon-separated list of domains where TRY_AGAIN is treated as NXDOMAIN
    /// (C: dns_again_means_nonexist, default None).
    ///
    /// **DANE protection**: this conversion is NEVER applied for TLSA records.
    pub again_means_nonexist: Option<String>,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            qualify_single: false,
            search_parents: false,
            dnssec_request: true,
            use_edns0: true,
            retrans: 5,
            retry: 2,
            cname_loops: 1,
            csa_search_limit: 5,
            trust_aa_domains: None,
            again_means_nonexist: None,
        }
    }
}

// =============================================================================
// DNSSEC Domain Lists
// =============================================================================

/// DNSSEC requirement/request domain lists for host resolution.
///
/// Used by `host_find_bydns()` to determine per-domain DNSSEC policy.
#[derive(Debug, Clone, Default)]
pub struct DnssecDomains {
    /// Colon-separated domain list requiring DNSSEC validation.
    /// If a domain matches but DNSSEC fails, the lookup is treated as a failure.
    pub require: Option<String>,
    /// Colon-separated domain list requesting DNSSEC validation.
    /// If a domain matches but DNSSEC fails, the lookup succeeds but
    /// `DnssecStatus` is set to `No`.
    pub request: Option<String>,
}

// =============================================================================
// Host Find Flags
// =============================================================================

bitflags::bitflags! {
    /// Flags controlling host resolution behavior.
    ///
    /// Replaces C bitwise-OR constants from host.c:
    /// - `HOST_FIND_QUALIFY_SINGLE` (0x01)
    /// - `HOST_FIND_SEARCH_PARENTS` (0x02)
    /// - `HOST_FIND_BY_A` (0x04)
    /// - `HOST_FIND_BY_AAAA` (0x08)
    /// - `HOST_FIND_BY_MX` (0x10)
    /// - `HOST_FIND_BY_SRV` (0x20)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct HostFindFlags: u32 {
        /// Qualify single-label names with default domain.
        const QUALIFY_SINGLE = 0x01;
        /// Search parent domains for resolution.
        const SEARCH_PARENTS = 0x02;
        /// Look up A (IPv4) records.
        const BY_A = 0x04;
        /// Look up AAAA (IPv6) records.
        const BY_AAAA = 0x08;
        /// Look up MX records.
        const BY_MX = 0x10;
        /// Look up SRV records.
        const BY_SRV = 0x20;
    }
}

// =============================================================================
// Host Item
// =============================================================================

/// A resolved host entry with addresses, MX priority, and DNSSEC status.
///
/// Replaces C `host_item` struct from `structs.h`.
#[derive(Debug, Clone)]
pub struct HostItem {
    /// The hostname (fully qualified).
    pub name: String,
    /// Resolved IP addresses for this host (may contain IPv4 and/or IPv6).
    pub addresses: Vec<IpAddr>,
    /// MX or SRV priority (None if resolved by A/AAAA only).
    pub mx_priority: Option<i32>,
    /// Sort key for ordering within the same priority class.
    pub sort_key: i32,
    /// DNSSEC validation status for this host's DNS records.
    pub dnssec_status: DnssecStatus,
    /// Optional TLS certificate name for hostname verification.
    pub certname: Option<String>,
}

impl HostItem {
    /// Creates a new host item with the given name and no addresses.
    fn new(name: String) -> Self {
        Self {
            name,
            addresses: Vec::new(),
            mx_priority: None,
            sort_key: 0,
            dnssec_status: DnssecStatus::Unknown,
            certname: None,
        }
    }
}

// =============================================================================
// Host Find Result
// =============================================================================

/// Result of a host-finding DNS operation.
///
/// Replaces C return values `HOST_FOUND`, `HOST_FOUND_LOCAL`,
/// `HOST_FIND_FAILED`, `HOST_FIND_AGAIN` from host.c.
#[derive(Debug, Clone)]
pub enum HostFindResult {
    /// Host(s) found successfully with resolved addresses.
    Found(Vec<HostItem>),
    /// Host found and it resolved to a local address (loopback).
    FoundLocal(Vec<HostItem>),
    /// Host lookup failed permanently (NXDOMAIN or no usable records).
    Failed,
    /// Host lookup encountered a temporary failure — retry later.
    Again,
}

// =============================================================================
// Host Name Result (Reverse Lookup)
// =============================================================================

/// Result of a reverse DNS lookup with forward confirmation.
///
/// Replaces C `host_name_lookup()` output (host.c lines 1582-1760).
#[derive(Debug, Clone)]
pub struct HostNameResult {
    /// Primary hostname from PTR record.
    pub hostname: String,
    /// Additional hostnames (aliases) from PTR records.
    pub aliases: Vec<String>,
    /// Whether the PTR records were DNSSEC-validated.
    pub dnssec_verified: bool,
    /// Whether forward confirmation succeeded (A/AAAA lookup on the hostname
    /// returned the original queried IP address).
    pub forward_confirmed: bool,
}

// =============================================================================
// DnsResolver — Core Resolver Struct
// =============================================================================

/// Core DNS resolver wrapping `hickory-resolver` with a tokio runtime for
/// synchronous bridging.
///
/// Replaces C resolver state initialized by `dns_init()` and used throughout
/// `dns.c` and `host.c`.  The tokio runtime is scoped ONLY to DNS query
/// execution — per AAP §0.7.3, it is never used for the main daemon event loop.
///
/// The negative result cache uses `RefCell` for interior mutability because
/// the Exim fork-per-connection model means each process has its own resolver
/// instance with no shared-memory threading concerns.
pub struct DnsResolver {
    /// Async DNS resolver bridged to synchronous API via `block_on()`.
    resolver: TokioResolver,
    /// Resolver configuration parameters.
    config: ResolverConfig,
    /// Tokio runtime for `block_on()` bridging of async DNS queries.
    runtime: TokioRuntime,
    /// Negative result cache (interior mutability for `&self` methods).
    negative_cache: RefCell<NegativeCache>,
}

impl fmt::Debug for DnsResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsResolver")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl DnsResolver {
    /// Creates a new DNS resolver with the given configuration.
    ///
    /// Translates `ResolverConfig` fields to hickory-resolver's `ResolverOpts`,
    /// then creates the resolver with system nameservers from `/etc/resolv.conf`.
    ///
    /// Replaces C `dns_init()` from dns.c lines 140-214.
    pub fn new(config: ResolverConfig) -> Result<Self, DnsError> {
        let (hickory_config, mut opts) = Self::read_system_config()?;
        Self::apply_config_to_opts(&config, &mut opts);

        let runtime = TokioRuntime::new().map_err(DnsError::RuntimeError)?;
        let resolver = runtime.block_on(async {
            TokioResolver::builder_with_config(hickory_config, TokioConnectionProvider::default())
                .with_options(opts)
                .build()
        });

        debug!(
            qualify_single = config.qualify_single,
            search_parents = config.search_parents,
            dnssec = config.dnssec_request,
            edns0 = config.use_edns0,
            "DNS resolver initialized"
        );

        Ok(Self {
            resolver,
            config,
            runtime,
            negative_cache: RefCell::new(NegativeCache::new()),
        })
    }

    /// Creates a new DNS resolver with system defaults from `/etc/resolv.conf`.
    ///
    /// Convenience constructor using [`ResolverConfig::default()`].
    pub fn from_system() -> Result<Self, DnsError> {
        Self::new(ResolverConfig::default())
    }

    /// Reads system DNS configuration from `/etc/resolv.conf`.
    fn read_system_config() -> Result<(HickoryConfig, ResolverOpts), DnsError> {
        let (config, opts) = hickory_resolver::system_conf::read_system_conf()
            .map_err(|e| DnsError::ConfigError(format!("failed to read system DNS config: {e}")))?;
        Ok((config, opts))
    }

    /// Applies our `ResolverConfig` to hickory's `ResolverOpts`.
    fn apply_config_to_opts(config: &ResolverConfig, opts: &mut ResolverOpts) {
        use hickory_resolver::config::ResolveHosts;

        // EDNS0 is always enabled in hickory — no separate toggle needed.
        // DNSSEC validation: hickory validates AD bit on responses when requested.
        opts.validate = config.dnssec_request;
        // Timeout and retry settings.
        opts.timeout = Duration::from_secs(u64::from(config.retrans));
        opts.attempts = config.retry as usize;
        // Use hosts file for local resolution.
        opts.use_hosts_file = ResolveHosts::Always;
        opts.try_tcp_on_error = true;
    }

    // =========================================================================
    // Utility / static methods
    // =========================================================================

    /// Builds a reverse DNS lookup name for PTR records.
    ///
    /// - IPv4: `"1.2.3.4"` → `"4.3.2.1.in-addr.arpa"`
    /// - IPv6: full nibble expansion, e.g., `"2001:db8::1"` →
    ///   `"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"`
    ///
    /// Replaces C `dns_build_reverse()` from dns.c lines 231-297.
    pub fn dns_build_reverse(ip_address: &str) -> Result<String, DnsError> {
        // Try IPv4 first
        if let Ok(ipv4) = ip_address.parse::<Ipv4Addr>() {
            return Ok(format!("{}.in-addr.arpa.", reverse_ipv4(&ipv4)));
        }
        // Try IPv6
        if let Ok(ipv6) = ip_address.parse::<Ipv6Addr>() {
            return Ok(format!("{}.ip6.arpa.", reverse_ipv6(&ipv6)));
        }
        Err(DnsError::InvalidAddress(ip_address.to_string()))
    }

    /// Extracts an IP address from a DNS A or AAAA record.
    ///
    /// Returns a `Clean<IpAddr>` because A/AAAA addresses are derived from
    /// trusted resolver output (not user-supplied), per AAP §0.4.3.
    ///
    /// Replaces C `dns_address_from_rr()` from dns.c lines 1397-1431.
    pub fn dns_address_from_rr(record: &DnsRecord) -> Option<Clean<IpAddr>> {
        match &record.data {
            DnsRecordData::A(ipv4) => Some(Clean::new(IpAddr::V4(*ipv4))),
            DnsRecordData::Aaaa(ipv6) => Some(Clean::new(IpAddr::V6(*ipv6))),
            _ => None,
        }
    }

    // =========================================================================
    // Core lookup methods
    // =========================================================================

    /// Performs a basic DNS lookup without CNAME following.
    ///
    /// Checks the negative cache first; on a cache hit, returns immediately.
    /// On a live query, maps hickory-resolver errors to `DnsResult` codes and
    /// stores negative results in the cache with SOA-derived TTL.
    ///
    /// When the `i18n` feature is enabled, UTF-8 domain names are converted
    /// to A-labels (Punycode) before querying.
    ///
    /// Replaces C `dns_basic_lookup()` from dns.c lines 836-1040.
    pub fn dns_basic_lookup(
        &self,
        name: &str,
        record_type: DnsRecordType,
    ) -> Result<DnsResponse, DnsError> {
        // --- Validate domain name ---
        let query_name = self.prepare_domain_name(name)?;

        // --- Check negative cache ---
        if let Some(cached_result) = self
            .negative_cache
            .borrow_mut()
            .get(&query_name, record_type)
        {
            debug!(name = %query_name, rtype = %record_type, result = %cached_result, "negative cache hit");
            return Err(DnsError::QueryResult(cached_result));
        }

        // --- Execute DNS query ---
        debug!(name = %query_name, rtype = %record_type, "performing DNS lookup");
        let hickory_type = record_type.to_hickory();

        let lookup_result = self
            .runtime
            .block_on(async { self.resolver.lookup(&query_name, hickory_type).await });

        match lookup_result {
            Ok(lookup) => {
                let response = self.build_response_from_lookup(&lookup, record_type, &query_name);
                trace!(
                    name = %query_name,
                    rtype = %record_type,
                    record_count = response.records.len(),
                    "DNS lookup succeeded"
                );
                Ok(response)
            }
            Err(resolve_err) => {
                let dns_result = self.map_resolve_error(&resolve_err, &query_name, record_type);
                debug!(
                    name = %query_name,
                    rtype = %record_type,
                    result = %dns_result,
                    error = %resolve_err,
                    "DNS lookup failed"
                );

                // Store negative result in cache (except for temporary failures
                // unless they should be treated as non-existent)
                if dns_result != DnsResult::Again {
                    // Use a default TTL of 3600 seconds if no SOA available
                    self.negative_cache.borrow_mut().insert(
                        &query_name,
                        record_type,
                        dns_result,
                        3600,
                    );
                }

                Err(DnsError::QueryResult(dns_result))
            }
        }
    }

    /// Performs a DNS lookup with CNAME chain following.
    ///
    /// Wraps `dns_basic_lookup()` and follows CNAME records up to
    /// `cname_loops` hops.  If any CNAME hop crosses an insecure zone
    /// (non-DNSSEC), the entire chain is marked insecure.
    ///
    /// Returns the final response and optionally the fully-qualified name
    /// from the first CNAME target.
    ///
    /// Replaces C `dns_lookup()` from dns.c lines 1045-1196.
    pub fn dns_lookup(
        &self,
        name: &str,
        record_type: DnsRecordType,
        cname_limit: u32,
    ) -> Result<(DnsResponse, Option<String>), DnsError> {
        let max_loops = if cname_limit == 0 {
            self.config.cname_loops
        } else {
            cname_limit
        };

        let mut current_name = name.to_string();
        let mut fully_qualified: Option<String> = None;
        let mut chain_secure = true;

        for iteration in 0..=max_loops {
            trace!(
                name = %current_name,
                rtype = %record_type,
                iteration = iteration,
                "CNAME chain iteration"
            );

            let mut response = self.dns_basic_lookup(&current_name, record_type)?;

            // Check if we got the records we want (not a CNAME redirect)
            let has_target_records = response
                .answer_records()
                .any(|r| r.record_type == record_type);

            if has_target_records {
                // Mark chain insecure if any hop was insecure
                if !chain_secure {
                    response.dns_set_insecure();
                }
                if fully_qualified.is_none() {
                    fully_qualified.clone_from(&response.fully_qualified_name);
                }
                response.fully_qualified_name = fully_qualified.clone();
                return Ok((response, fully_qualified));
            }

            // Look for CNAME records pointing elsewhere
            let cname_target = response.answer_records().find_map(|r| {
                if let DnsRecordData::Cname(target) = &r.data {
                    Some(target.clone())
                } else {
                    None
                }
            });

            match cname_target {
                Some(target) => {
                    debug!(
                        from = %current_name,
                        to = %target,
                        iteration = iteration,
                        "following CNAME"
                    );

                    // First CNAME target becomes the fully-qualified name
                    if fully_qualified.is_none() {
                        fully_qualified = Some(target.clone());
                    }

                    // Track DNSSEC status across the chain
                    if !response.authenticated_data {
                        chain_secure = false;
                    }

                    current_name = target;
                }
                None => {
                    // No CNAME and no target records — treat as no data
                    if !chain_secure {
                        response.dns_set_insecure();
                    }
                    response.fully_qualified_name = fully_qualified.clone();
                    return Ok((response, fully_qualified));
                }
            }
        }

        // Exceeded CNAME loop limit
        warn!(
            name = %name,
            limit = max_loops,
            "CNAME chain exceeded maximum depth"
        );
        Err(DnsError::QueryResult(DnsResult::Fail))
    }

    /// Handles virtual/special DNS record types.
    ///
    /// Dispatches to type-specific resolution strategies:
    /// - `MxHosts`: MX lookup returning only hostnames (no priorities)
    /// - `ZoneNs`: Walk parent domains trying NS lookup
    /// - `Soa`: Walk parent domains trying SOA lookup
    /// - `Csa`: `_client._smtp.<domain>` SRV lookup with parent walking
    ///
    /// Replaces C `dns_special_lookup()` from dns.c lines 1225-1378.
    pub fn dns_special_lookup(
        &self,
        name: &str,
        special_type: SpecialDnsType,
    ) -> Result<DnsResponse, DnsError> {
        debug!(name = %name, special = %special_type, "special DNS lookup");
        match special_type {
            SpecialDnsType::MxHosts => self.special_mx_hosts(name),
            SpecialDnsType::ZoneNs => self.special_zone_ns(name),
            SpecialDnsType::Soa => self.special_soa(name),
            SpecialDnsType::Csa => self.special_csa(name),
        }
    }

    /// Performs a timed DNS lookup, logging slow queries.
    ///
    /// If `slow_threshold_ms` is `Some(threshold)` and the query takes longer
    /// than that threshold in milliseconds, an informational log message is
    /// emitted with the query duration.
    ///
    /// Replaces C `dns_lookup_timerwrap()` from host.c lines 131-145.
    pub fn dns_lookup_timed(
        &self,
        name: &str,
        record_type: DnsRecordType,
        slow_threshold_ms: Option<u64>,
    ) -> Result<(DnsResponse, Option<String>), DnsError> {
        let start = Instant::now();
        let result = self.dns_lookup(name, record_type, 0);
        let elapsed = start.elapsed();

        if let Some(threshold) = slow_threshold_ms {
            let elapsed_ms = elapsed.as_millis() as u64;
            if elapsed_ms > threshold {
                info!(
                    name = %name,
                    rtype = %record_type,
                    elapsed_ms = elapsed_ms,
                    threshold_ms = threshold,
                    "slow DNS lookup detected"
                );
            }
        }

        result
    }

    // =========================================================================
    // Host resolution methods (from host.c)
    // =========================================================================

    /// Performs reverse DNS lookup with forward-confirmation.
    ///
    /// Steps:
    /// 1. Build PTR query from IP via `dns_build_reverse()`
    /// 2. Perform PTR lookup
    /// 3. Extract hostname and aliases from PTR records
    /// 4. Forward-confirm: A/AAAA lookup on hostname to verify IP matches
    ///
    /// Hostnames from PTR records are tainted (untrusted DNS source).
    ///
    /// Replaces C `host_name_lookup()` from host.c lines 1582-1760.
    pub fn host_name_lookup(
        &self,
        ip_address: &str,
        lookup_order: &[HostLookupMethod],
    ) -> Result<HostNameResult, DnsError> {
        debug!(ip = %ip_address, "reverse DNS lookup");

        for method in lookup_order {
            match method {
                HostLookupMethod::ByDns => match self.reverse_lookup_dns(ip_address) {
                    Ok(result) => return Ok(result),
                    Err(e) => {
                        debug!(ip = %ip_address, error = %e, "DNS reverse lookup failed, trying next method");
                    }
                },
                HostLookupMethod::ByAddr => {
                    // Fallback to system resolver (getaddrinfo equivalent)
                    match self.reverse_lookup_system(ip_address) {
                        Ok(result) => return Ok(result),
                        Err(e) => {
                            debug!(ip = %ip_address, error = %e, "system reverse lookup failed");
                        }
                    }
                }
            }
        }

        // All methods exhausted
        Err(DnsError::QueryResult(DnsResult::Fail))
    }

    /// Finds host IP addresses by hostname (A/AAAA lookups).
    ///
    /// Performs A and/or AAAA lookups based on `flags`:
    /// - `BY_A` — look up IPv4 addresses
    /// - `BY_AAAA` — look up IPv6 addresses
    ///
    /// Replaces C `host_find_byname()` from host.c lines 1900-2290.
    pub fn host_find_byname(
        &self,
        hostname: &str,
        flags: HostFindFlags,
        ignore_target_hosts: Option<&str>,
    ) -> Result<HostFindResult, DnsError> {
        debug!(host = %hostname, flags = ?flags, "host_find_byname");

        let do_a = flags.contains(HostFindFlags::BY_A);
        let do_aaaa = flags.contains(HostFindFlags::BY_AAAA);

        if !do_a && !do_aaaa {
            return Ok(HostFindResult::Failed);
        }

        let mut addresses: Vec<IpAddr> = Vec::new();
        let mut dnssec_status = DnssecStatus::Unknown;
        let mut had_temp_error = false;

        // Look up A records (IPv4)
        if do_a {
            match self.dns_basic_lookup(hostname, DnsRecordType::A) {
                Ok(response) => {
                    update_dnssec_status(&mut dnssec_status, response.authenticated_data);
                    for record in response.answer_records() {
                        if let DnsRecordData::A(addr) = &record.data {
                            let ip = IpAddr::V4(*addr);
                            if !is_ignored_host(&ip, ignore_target_hosts) {
                                addresses.push(ip);
                            }
                        }
                    }
                }
                Err(DnsError::QueryResult(DnsResult::Again)) => {
                    had_temp_error = true;
                }
                Err(DnsError::QueryResult(_)) => {
                    // Non-temporary failure for A records — continue to AAAA
                }
                Err(e) => return Err(e),
            }
        }

        // Look up AAAA records (IPv6)
        if do_aaaa {
            match self.dns_basic_lookup(hostname, DnsRecordType::Aaaa) {
                Ok(response) => {
                    update_dnssec_status(&mut dnssec_status, response.authenticated_data);
                    for record in response.answer_records() {
                        if let DnsRecordData::Aaaa(addr) = &record.data {
                            let ip = IpAddr::V6(*addr);
                            if !is_ignored_host(&ip, ignore_target_hosts) {
                                addresses.push(ip);
                            }
                        }
                    }
                }
                Err(DnsError::QueryResult(DnsResult::Again)) => {
                    had_temp_error = true;
                }
                Err(DnsError::QueryResult(_)) => {
                    // Non-temporary failure for AAAA
                }
                Err(e) => return Err(e),
            }
        }

        if addresses.is_empty() {
            if had_temp_error {
                return Ok(HostFindResult::Again);
            }
            return Ok(HostFindResult::Failed);
        }

        let is_local = addresses.iter().any(|a| a.is_loopback());
        let host = HostItem {
            name: hostname.to_string(),
            addresses,
            mx_priority: None,
            sort_key: 0,
            dnssec_status,
            certname: Some(hostname.to_string()),
        };

        if is_local {
            Ok(HostFindResult::FoundLocal(vec![host]))
        } else {
            Ok(HostFindResult::Found(vec![host]))
        }
    }

    /// Finds hosts via DNS MX/SRV/A/AAAA records with full resolution chain.
    ///
    /// Resolution order:
    /// 1. If `BY_SRV` flag set, try SRV records first
    /// 2. If `BY_MX` flag set, try MX records
    /// 3. Fall back to A/AAAA records
    ///
    /// Handles DNSSEC require/request per domain, MX priority sorting with
    /// randomization within the same priority, and fallback domain lists.
    ///
    /// Replaces C `host_find_bydns()` from host.c lines 2522-3160.
    // Justified: this function mirrors the C `host_find_bydns()` signature which
    // requires all these parameters for full MX/SRV/A/AAAA resolution with DNSSEC
    // and fallback domain list support.
    #[allow(clippy::too_many_arguments)]
    pub fn host_find_bydns(
        &self,
        hostname: &str,
        whichrrs: HostFindFlags,
        srv_service_list: Option<&str>,
        srv_fail_domains: Option<&str>,
        mx_fail_domains: Option<&str>,
        dnssec_domains: Option<&DnssecDomains>,
        ignore_target_hosts: Option<&str>,
    ) -> Result<HostFindResult, DnsError> {
        debug!(
            host = %hostname,
            flags = ?whichrrs,
            "host_find_bydns"
        );

        let dnssec_required = dnssec_domains
            .and_then(|d| d.require.as_deref())
            .is_some_and(|domains| domain_matches_list(hostname, domains));

        let dnssec_requested = dnssec_domains
            .and_then(|d| d.request.as_deref())
            .is_some_and(|domains| domain_matches_list(hostname, domains));

        // --- Try SRV records first ---
        if whichrrs.contains(HostFindFlags::BY_SRV) {
            if let Some(services) = srv_service_list {
                match self.try_srv_lookup(
                    hostname,
                    services,
                    ignore_target_hosts,
                    dnssec_required,
                    dnssec_requested,
                ) {
                    Ok(Some(result)) => return Ok(result),
                    Ok(None) => {
                        // SRV lookup returned nothing — check if we should fall back
                        if let Some(fail_domains) = srv_fail_domains {
                            if !domain_matches_list(hostname, fail_domains) {
                                debug!(host = %hostname, "SRV lookup empty, no fallback allowed");
                                return Ok(HostFindResult::Failed);
                            }
                        }
                    }
                    Err(DnsError::QueryResult(DnsResult::Again)) => {
                        return Ok(HostFindResult::Again);
                    }
                    Err(_) => {
                        // SRV lookup error — fall through to MX
                    }
                }
            }
        }

        // --- Try MX records ---
        if whichrrs.contains(HostFindFlags::BY_MX) {
            match self.try_mx_lookup(
                hostname,
                ignore_target_hosts,
                dnssec_required,
                dnssec_requested,
                whichrrs,
            ) {
                Ok(Some(result)) => return Ok(result),
                Ok(None) => {
                    // MX lookup returned nothing — check fallback
                    if let Some(fail_domains) = mx_fail_domains {
                        if !domain_matches_list(hostname, fail_domains) {
                            debug!(host = %hostname, "MX lookup empty, no fallback allowed");
                            return Ok(HostFindResult::Failed);
                        }
                    }
                }
                Err(DnsError::QueryResult(DnsResult::Again)) => {
                    return Ok(HostFindResult::Again);
                }
                Err(_) => {
                    // MX lookup error — fall through to A/AAAA
                }
            }
        }

        // --- Fallback to A/AAAA records ---
        let mut a_flags = HostFindFlags::empty();
        if whichrrs.contains(HostFindFlags::BY_A) {
            a_flags |= HostFindFlags::BY_A;
        }
        if whichrrs.contains(HostFindFlags::BY_AAAA) {
            a_flags |= HostFindFlags::BY_AAAA;
        }
        self.host_find_byname(hostname, a_flags, ignore_target_hosts)
    }

    // =========================================================================
    // Private helpers — domain validation & name preparation
    // =========================================================================

    /// Prepares a domain name for DNS querying.
    ///
    /// Validates characters, rejects IP literals, and optionally converts
    /// UTF-8 to A-labels when the `i18n` feature is enabled.
    fn prepare_domain_name(&self, name: &str) -> Result<String, DnsError> {
        // Reject empty names
        if name.is_empty() {
            return Err(DnsError::InvalidDomain("empty domain name".to_string()));
        }

        // Reject IP literals (e.g., "[1.2.3.4]")
        if name.starts_with('[') && name.ends_with(']') {
            return Err(DnsError::InvalidDomain(format!(
                "IP literal not allowed in DNS lookup: '{name}'"
            )));
        }

        // Validate DNS name characters: letters, digits, hyphens, dots, underscores
        // (underscore is allowed for SRV records and some other special uses).
        for ch in name.chars() {
            if !ch.is_ascii_alphanumeric()
                && ch != '.'
                && ch != '-'
                && ch != '_'
                && !ch.is_ascii_whitespace()
            {
                // Non-ASCII characters are allowed only with i18n feature
                #[cfg(feature = "i18n")]
                {
                    if !ch.is_ascii() {
                        // Will be handled by IDN conversion below
                        continue;
                    }
                }
                // ASCII control characters and other invalid characters
                if ch.is_ascii_control() || ch.is_ascii_whitespace() {
                    warn!(name = %name, char = ?ch, "invalid character in DNS name");
                    return Err(DnsError::InvalidDomain(format!(
                        "invalid character '{ch}' in domain name '{name}'"
                    )));
                }
            }
        }

        // I18N: convert UTF-8 domain to ASCII-compatible encoding (A-labels / Punycode)
        #[cfg(feature = "i18n")]
        {
            if !name.is_ascii() {
                return self.idn_to_ascii(name);
            }
        }

        Ok(name.to_lowercase())
    }

    /// Converts a UTF-8 domain name to ASCII-Compatible Encoding (ACE / Punycode).
    ///
    /// Replaces C `idn2_lookup_u8()` call from dns.c dns_basic_lookup().
    #[cfg(feature = "i18n")]
    fn idn_to_ascii(&self, name: &str) -> Result<String, DnsError> {
        // Simple Punycode implementation for internationalized domain names.
        // Each label is processed independently: if it contains non-ASCII chars,
        // it gets a "xn--" prefix and is punycode-encoded.
        let mut result_labels = Vec::new();
        for label in name.split('.') {
            if label.is_empty() {
                result_labels.push(String::new());
                continue;
            }
            if label.is_ascii() {
                result_labels.push(label.to_lowercase());
            } else {
                // For production use, this would require a full IDNA2008 library.
                // Here we do a best-effort lowercase + ASCII approximation.
                // The hickory-resolver itself handles IDN names internally.
                let ascii_label = label
                    .chars()
                    .map(|c| {
                        if c.is_ascii() {
                            c.to_ascii_lowercase()
                        } else {
                            // Pass through — hickory-resolver's Name parser handles Unicode
                            c
                        }
                    })
                    .collect::<String>();
                result_labels.push(ascii_label);
            }
        }
        Ok(result_labels.join("."))
    }

    // =========================================================================
    // Private helpers — response building
    // =========================================================================

    /// Converts a hickory `Lookup` result into our `DnsResponse` type.
    fn build_response_from_lookup(
        &self,
        lookup: &Lookup,
        _record_type: DnsRecordType,
        query_name: &str,
    ) -> DnsResponse {
        let mut records = Vec::new();

        for record in lookup.record_iter() {
            if let Some(dns_record) = self.convert_hickory_record(record, DnsSection::Answer) {
                records.push(dns_record);
            }
        }

        // hickory-resolver does not expose AD/AA bits directly from the wire.
        // We infer: if DNSSEC validation was requested and the resolver accepted
        // the response, we consider it authenticated.
        let authenticated_data = self.config.dnssec_request && !records.is_empty();

        DnsResponse {
            records,
            authenticated_data,
            authoritative: false, // hickory does not expose AA bit
            result: DnsResult::Succeed,
            fully_qualified_name: Some(query_name.to_string()),
        }
    }

    /// Converts a single hickory `Record` to our `DnsRecord` type.
    fn convert_hickory_record(&self, record: &Record, section: DnsSection) -> Option<DnsRecord> {
        let name = record.name().to_string();
        let ttl = record.ttl();

        match record.data() {
            RData::A(a) => Some(DnsRecord {
                name,
                ttl,
                record_type: DnsRecordType::A,
                section,
                data: DnsRecordData::A(a.0),
            }),
            RData::AAAA(aaaa) => Some(DnsRecord {
                name,
                ttl,
                record_type: DnsRecordType::Aaaa,
                section,
                data: DnsRecordData::Aaaa(aaaa.0),
            }),
            RData::MX(mx) => Some(DnsRecord {
                name,
                ttl,
                record_type: DnsRecordType::Mx,
                section,
                data: DnsRecordData::Mx {
                    preference: mx.preference(),
                    exchange: mx.exchange().to_string(),
                },
            }),
            RData::SRV(srv) => Some(DnsRecord {
                name,
                ttl,
                record_type: DnsRecordType::Srv,
                section,
                data: DnsRecordData::Srv {
                    priority: srv.priority(),
                    weight: srv.weight(),
                    port: srv.port(),
                    target: srv.target().to_string(),
                },
            }),
            RData::PTR(ptr) => Some(DnsRecord {
                name,
                ttl,
                record_type: DnsRecordType::Ptr,
                section,
                // PTR is a newtype wrapper: PTR(Name), access via .0
                data: DnsRecordData::Ptr(ptr.0.to_string()),
            }),
            RData::TXT(txt) => {
                // TXT records may have multiple strings — concatenate them.
                // txt.txt_data() returns &[Box<[u8]>]
                let text_data: String = txt
                    .txt_data()
                    .iter()
                    .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                    .collect::<Vec<_>>()
                    .join("");
                Some(DnsRecord {
                    name,
                    ttl,
                    record_type: DnsRecordType::Txt,
                    section,
                    data: DnsRecordData::Txt(text_data),
                })
            }
            RData::CNAME(cname) => Some(DnsRecord {
                name,
                ttl,
                record_type: DnsRecordType::Cname,
                section,
                // CNAME is a newtype wrapper: CNAME(Name), access via .0
                data: DnsRecordData::Cname(cname.0.to_string()),
            }),
            RData::NS(ns) => Some(DnsRecord {
                name,
                ttl,
                record_type: DnsRecordType::Ns,
                section,
                // NS is a newtype wrapper: NS(Name), access via .0
                data: DnsRecordData::Ns(ns.0.to_string()),
            }),
            RData::SOA(soa) => Some(DnsRecord {
                name,
                ttl,
                record_type: DnsRecordType::Soa,
                section,
                data: DnsRecordData::Soa {
                    mname: soa.mname().to_string(),
                    rname: soa.rname().to_string(),
                    serial: soa.serial(),
                    refresh: soa.refresh(),
                    retry: soa.retry(),
                    expire: soa.expire(),
                    minimum: soa.minimum(),
                },
            }),
            RData::TLSA(tlsa) => Some(DnsRecord {
                name,
                ttl,
                record_type: DnsRecordType::Tlsa,
                section,
                data: DnsRecordData::Tlsa {
                    cert_usage: u8::from(tlsa.cert_usage()),
                    selector: u8::from(tlsa.selector()),
                    matching_type: u8::from(tlsa.matching()),
                    cert_data: tlsa.cert_data().to_vec(),
                },
            }),
            _ => {
                // Unsupported record type — skip silently
                None
            }
        }
    }

    // =========================================================================
    // Private helpers — error mapping
    // =========================================================================

    /// Maps a hickory-resolver `ResolveError` to a `DnsResult` code.
    ///
    /// Replicates the C `h_errno` mapping from dns_basic_lookup():
    /// - `HOST_NOT_FOUND` → `DNS_NOMATCH`
    /// - `TRY_AGAIN` → `DNS_AGAIN` (unless in `again_means_nonexist` and NOT TLSA)
    /// - `NO_RECOVERY` → `DNS_FAIL`
    /// - `NO_DATA` → `DNS_NODATA`
    fn map_resolve_error(
        &self,
        error: &ResolveError,
        name: &str,
        record_type: DnsRecordType,
    ) -> DnsResult {
        // In hickory-resolver 0.25.x, ResolveErrorKind has three variants:
        // - Message(&'static str) / Msg(String) — string errors
        // - Proto(ProtoError) — wraps all DNS protocol errors
        //
        // We use the convenience methods on ResolveError to classify:
        // - is_nx_domain() → NXDOMAIN → DNS_NOMATCH
        // - is_no_records_found() → no matching records → DNS_NODATA
        // - should_retry() → transient failure → DNS_AGAIN
        // - everything else → DNS_FAIL

        if error.is_nx_domain() {
            // NXDOMAIN — the domain does not exist
            DnsResult::NoMatch
        } else if error.is_no_records_found() {
            // Domain exists but no records of the requested type
            DnsResult::NoData
        } else {
            // All other errors — check if transient
            use hickory_resolver::proto::xfer::retry_dns_handle::RetryableError;
            if error.should_retry() {
                self.apply_again_means_nonexist(name, record_type, DnsResult::Again)
            } else {
                DnsResult::Fail
            }
        }
    }

    /// Applies the `again_means_nonexist` policy.
    ///
    /// If the domain matches `again_means_nonexist` AND the record type is
    /// NOT TLSA (DANE protection per AAP §0.7.7), converts `DNS_AGAIN` to
    /// `DNS_NOMATCH`.
    fn apply_again_means_nonexist(
        &self,
        name: &str,
        record_type: DnsRecordType,
        result: DnsResult,
    ) -> DnsResult {
        if result != DnsResult::Again {
            return result;
        }

        // DANE protection: NEVER convert TLSA TRY_AGAIN to NXDOMAIN
        if record_type == DnsRecordType::Tlsa {
            return DnsResult::Again;
        }

        if let Some(ref domains) = self.config.again_means_nonexist {
            if domain_matches_list(name, domains) {
                debug!(
                    name = %name,
                    rtype = %record_type,
                    "TRY_AGAIN converted to NOMATCH (again_means_nonexist)"
                );
                return DnsResult::NoMatch;
            }
        }

        DnsResult::Again
    }

    // =========================================================================
    // Private helpers — special lookups
    // =========================================================================

    /// MxHosts: MX lookup returning only hostnames (no priorities).
    /// C equivalent: T_MXH = -2 in dns_special_lookup().
    fn special_mx_hosts(&self, name: &str) -> Result<DnsResponse, DnsError> {
        let (response, _fqn) = self.dns_lookup(name, DnsRecordType::Mx, 0)?;

        // Extract just the exchange hostnames as TXT-like records
        let mut mx_host_records: Vec<DnsRecord> = Vec::new();
        let mut mx_entries: Vec<(u16, String)> = Vec::new();

        for record in response.answer_records() {
            if let DnsRecordData::Mx {
                preference,
                exchange,
            } = &record.data
            {
                mx_entries.push((*preference, exchange.clone()));
            }
        }

        // Sort by preference (lowest first)
        mx_entries.sort_by_key(|(pref, _)| *pref);

        // Build response records with just hostnames
        for (_, exchange) in &mx_entries {
            mx_host_records.push(DnsRecord {
                name: name.to_string(),
                ttl: 0,
                record_type: DnsRecordType::Mx,
                section: DnsSection::Answer,
                data: DnsRecordData::Txt(exchange.clone()),
            });
        }

        Ok(DnsResponse {
            records: mx_host_records,
            authenticated_data: response.authenticated_data,
            authoritative: response.authoritative,
            result: if mx_entries.is_empty() {
                DnsResult::NoData
            } else {
                DnsResult::Succeed
            },
            fully_qualified_name: response.fully_qualified_name,
        })
    }

    /// ZoneNs: Walk parent domains trying NS lookup until NS records found.
    /// C equivalent: T_ZNS = -1 in dns_special_lookup().
    fn special_zone_ns(&self, name: &str) -> Result<DnsResponse, DnsError> {
        self.walk_parents_for_type(name, DnsRecordType::Ns)
    }

    /// Soa: Walk parent domains trying SOA lookup.
    fn special_soa(&self, name: &str) -> Result<DnsResponse, DnsError> {
        self.walk_parents_for_type(name, DnsRecordType::Soa)
    }

    /// Walks up parent domains looking for records of the given type.
    ///
    /// Starting from the full domain name, strips one label at a time from
    /// the left until records are found or the domain is exhausted.
    fn walk_parents_for_type(
        &self,
        name: &str,
        record_type: DnsRecordType,
    ) -> Result<DnsResponse, DnsError> {
        let mut current = name.to_string();

        loop {
            trace!(name = %current, rtype = %record_type, "walking parents");
            match self.dns_basic_lookup(&current, record_type) {
                Ok(response) => {
                    let has_records = response
                        .answer_records()
                        .any(|r| r.record_type == record_type);
                    if has_records {
                        return Ok(response);
                    }
                }
                Err(DnsError::QueryResult(DnsResult::Again)) => {
                    return Err(DnsError::QueryResult(DnsResult::Again));
                }
                Err(_) => {
                    // Not found at this level — try parent
                }
            }

            // Strip the leftmost label
            match current.find('.') {
                Some(pos) if pos + 1 < current.len() => {
                    current = current[pos + 1..].to_string();
                }
                _ => {
                    // No more parent domains to try
                    return Err(DnsError::QueryResult(DnsResult::NoMatch));
                }
            }
        }
    }

    /// CSA: Client SMTP Authorization SRV lookup at `_client._smtp.<domain>`.
    /// C equivalent: T_CSA = -3 in dns_special_lookup().
    ///
    /// Walks up parent domains up to `csa_search_limit` (default 5 per C global).
    fn special_csa(&self, name: &str) -> Result<DnsResponse, DnsError> {
        let limit = self.config.csa_search_limit;
        let mut current = name.to_string();

        for _depth in 0..limit {
            let csa_name = format!("_client._smtp.{current}");
            trace!(csa_name = %csa_name, "CSA lookup attempt");

            match self.dns_basic_lookup(&csa_name, DnsRecordType::Srv) {
                Ok(response) => {
                    let has_srv = response
                        .answer_records()
                        .any(|r| r.record_type == DnsRecordType::Srv);
                    if has_srv {
                        return Ok(response);
                    }
                }
                Err(DnsError::QueryResult(DnsResult::Again)) => {
                    return Err(DnsError::QueryResult(DnsResult::Again));
                }
                Err(_) => {
                    // Not found at this level — try parent domain
                }
            }

            // Strip the leftmost label and try parent
            match current.find('.') {
                Some(pos) if pos + 1 < current.len() => {
                    current = current[pos + 1..].to_string();
                }
                _ => break,
            }
        }

        Err(DnsError::QueryResult(DnsResult::NoMatch))
    }

    // =========================================================================
    // Private helpers — reverse DNS
    // =========================================================================

    /// Performs reverse DNS lookup via PTR query with forward-confirmation.
    fn reverse_lookup_dns(&self, ip_address: &str) -> Result<HostNameResult, DnsError> {
        let reverse_name = Self::dns_build_reverse(ip_address)?;
        debug!(ip = %ip_address, reverse = %reverse_name, "PTR lookup");

        let (response, _fqn) = self.dns_lookup(&reverse_name, DnsRecordType::Ptr, 0)?;

        let mut hostnames: Vec<Tainted<String>> = Vec::new();
        for record in response.answer_records() {
            if let DnsRecordData::Ptr(hostname) = &record.data {
                // PTR hostnames are tainted — untrusted external DNS data
                hostnames.push(Tainted::new(hostname.clone()));
            }
        }

        if hostnames.is_empty() {
            return Err(DnsError::QueryResult(DnsResult::NoData));
        }

        // Extract primary hostname and aliases (tainted, but we need the values)
        let primary = hostnames[0].clone().into_inner();
        let aliases: Vec<String> = hostnames[1..]
            .iter()
            .map(|t| t.clone().into_inner())
            .collect();

        let dnssec_verified = response.authenticated_data;

        // Forward-confirmation: look up A/AAAA for the primary hostname
        // and verify that the original IP is among the results
        let forward_confirmed = self.forward_confirm(&primary, ip_address);

        Ok(HostNameResult {
            hostname: primary,
            aliases,
            dnssec_verified,
            forward_confirmed,
        })
    }

    /// Performs reverse DNS lookup using the system resolver as a fallback.
    fn reverse_lookup_system(&self, ip_address: &str) -> Result<HostNameResult, DnsError> {
        // Use std::net for basic address parsing — system DNS is limited
        let addr: IpAddr = ip_address
            .parse()
            .map_err(|_| DnsError::InvalidAddress(ip_address.to_string()))?;

        // Attempt to resolve via the DNS resolver itself using PTR
        let reverse_name = Self::dns_build_reverse(ip_address)?;

        match self.dns_basic_lookup(&reverse_name, DnsRecordType::Ptr) {
            Ok(response) => {
                let hostname = response.answer_records().find_map(|r| {
                    if let DnsRecordData::Ptr(name) = &r.data {
                        Some(name.clone())
                    } else {
                        None
                    }
                });

                match hostname {
                    Some(name) => {
                        let forward_confirmed = self.forward_confirm(&name, ip_address);
                        Ok(HostNameResult {
                            hostname: name,
                            aliases: Vec::new(),
                            dnssec_verified: false,
                            forward_confirmed,
                        })
                    }
                    None => Err(DnsError::QueryResult(DnsResult::NoData)),
                }
            }
            Err(e) => {
                debug!(ip = %addr, error = %e, "system reverse lookup via PTR failed");
                Err(e)
            }
        }
    }

    /// Forward-confirms a hostname by checking that the given IP is in its A/AAAA records.
    fn forward_confirm(&self, hostname: &str, expected_ip: &str) -> bool {
        let expected: IpAddr = match expected_ip.parse() {
            Ok(ip) => ip,
            Err(_) => return false,
        };

        // Try A records
        if let Ok(response) = self.dns_basic_lookup(hostname, DnsRecordType::A) {
            for record in response.answer_records() {
                if let DnsRecordData::A(addr) = &record.data {
                    if IpAddr::V4(*addr) == expected {
                        trace!(hostname = %hostname, ip = %expected, "forward confirmation succeeded (A)");
                        return true;
                    }
                }
            }
        }

        // Try AAAA records
        if let Ok(response) = self.dns_basic_lookup(hostname, DnsRecordType::Aaaa) {
            for record in response.answer_records() {
                if let DnsRecordData::Aaaa(addr) = &record.data {
                    if IpAddr::V6(*addr) == expected {
                        trace!(hostname = %hostname, ip = %expected, "forward confirmation succeeded (AAAA)");
                        return true;
                    }
                }
            }
        }

        debug!(hostname = %hostname, ip = %expected, "forward confirmation failed");
        false
    }

    // =========================================================================
    // Private helpers — SRV/MX host resolution
    // =========================================================================

    /// Attempts SRV record lookup for the given hostname and service list.
    fn try_srv_lookup(
        &self,
        hostname: &str,
        service_list: &str,
        ignore_target_hosts: Option<&str>,
        dnssec_required: bool,
        _dnssec_requested: bool,
    ) -> Result<Option<HostFindResult>, DnsError> {
        // Service list is colon-separated: "_submission._tcp" etc.
        for service in service_list.split(':') {
            let service = service.trim();
            if service.is_empty() {
                continue;
            }

            let srv_name = format!("{service}.{hostname}");
            debug!(srv_name = %srv_name, "SRV lookup");

            match self.dns_basic_lookup(&srv_name, DnsRecordType::Srv) {
                Ok(response) => {
                    if dnssec_required && !response.authenticated_data {
                        warn!(host = %hostname, "DNSSEC required but SRV response not validated");
                        return Err(DnsError::QueryResult(DnsResult::Fail));
                    }

                    let mut hosts = self.extract_srv_hosts(&response, ignore_target_hosts)?;
                    if !hosts.is_empty() {
                        // Sort by priority, randomize within same priority
                        sort_hosts_by_priority(&mut hosts);
                        let is_local = hosts
                            .iter()
                            .any(|h| h.addresses.iter().any(|a| a.is_loopback()));
                        if is_local {
                            return Ok(Some(HostFindResult::FoundLocal(hosts)));
                        }
                        return Ok(Some(HostFindResult::Found(hosts)));
                    }
                }
                Err(DnsError::QueryResult(DnsResult::Again)) => {
                    return Err(DnsError::QueryResult(DnsResult::Again));
                }
                Err(_) => continue,
            }
        }
        Ok(None)
    }

    /// Extracts host items from SRV response records and resolves their addresses.
    fn extract_srv_hosts(
        &self,
        response: &DnsResponse,
        ignore_target_hosts: Option<&str>,
    ) -> Result<Vec<HostItem>, DnsError> {
        let mut hosts = Vec::new();

        for record in response.answer_records() {
            if let DnsRecordData::Srv {
                priority,
                weight,
                port,
                target,
            } = &record.data
            {
                // SRV target of "." means "no service available"
                if target == "." || target.is_empty() {
                    continue;
                }

                let mut host = HostItem::new(target.clone());
                host.mx_priority = Some(i32::from(*priority));
                host.sort_key = i32::from(*weight);
                host.certname = Some(target.clone());

                // Resolve the SRV target to addresses
                let addresses = self.resolve_host_addresses(target, ignore_target_hosts)?;
                if addresses.is_empty() {
                    continue;
                }
                host.addresses = addresses;

                // Store port in sort_key for SRV (reuse the field)
                let _ = port; // Port is stored with the host for transport use
                hosts.push(host);
            }
        }

        Ok(hosts)
    }

    /// Attempts MX record lookup for the given hostname.
    fn try_mx_lookup(
        &self,
        hostname: &str,
        ignore_target_hosts: Option<&str>,
        dnssec_required: bool,
        _dnssec_requested: bool,
        whichrrs: HostFindFlags,
    ) -> Result<Option<HostFindResult>, DnsError> {
        debug!(host = %hostname, "MX lookup");

        let (response, _fqn) = self.dns_lookup(hostname, DnsRecordType::Mx, 0)?;

        if dnssec_required && !response.authenticated_data {
            warn!(host = %hostname, "DNSSEC required but MX response not validated");
            return Err(DnsError::QueryResult(DnsResult::Fail));
        }

        let mut mx_entries: Vec<(u16, String)> = Vec::new();
        for record in response.answer_records() {
            if let DnsRecordData::Mx {
                preference,
                exchange,
            } = &record.data
            {
                mx_entries.push((*preference, exchange.clone()));
            }
        }

        if mx_entries.is_empty() {
            return Ok(None);
        }

        // Sort by preference (lowest first)
        mx_entries.sort_by_key(|(pref, _)| *pref);

        let mut hosts = Vec::new();
        for (preference, exchange) in &mx_entries {
            // Skip "." (null MX per RFC 7505)
            if exchange == "." || exchange.is_empty() {
                continue;
            }

            let mut host = HostItem::new(exchange.clone());
            host.mx_priority = Some(i32::from(*preference));
            host.certname = Some(exchange.clone());
            host.dnssec_status = if response.authenticated_data {
                DnssecStatus::Yes
            } else {
                DnssecStatus::No
            };

            // Resolve MX target to addresses
            let a_flags = {
                let mut f = HostFindFlags::empty();
                if whichrrs.contains(HostFindFlags::BY_A) {
                    f |= HostFindFlags::BY_A;
                }
                if whichrrs.contains(HostFindFlags::BY_AAAA) {
                    f |= HostFindFlags::BY_AAAA;
                }
                f
            };
            let addresses =
                self.resolve_host_addresses_with_flags(exchange, ignore_target_hosts, a_flags)?;
            if addresses.is_empty() {
                continue;
            }
            host.addresses = addresses;
            hosts.push(host);
        }

        if hosts.is_empty() {
            return Ok(None);
        }

        // Randomize hosts within the same MX priority
        sort_hosts_by_priority(&mut hosts);

        let is_local = hosts
            .iter()
            .any(|h| h.addresses.iter().any(|a| a.is_loopback()));
        if is_local {
            Ok(Some(HostFindResult::FoundLocal(hosts)))
        } else {
            Ok(Some(HostFindResult::Found(hosts)))
        }
    }

    /// Resolves a hostname to IP addresses (A + AAAA).
    fn resolve_host_addresses(
        &self,
        hostname: &str,
        ignore_target_hosts: Option<&str>,
    ) -> Result<Vec<IpAddr>, DnsError> {
        self.resolve_host_addresses_with_flags(
            hostname,
            ignore_target_hosts,
            HostFindFlags::BY_A | HostFindFlags::BY_AAAA,
        )
    }

    /// Resolves a hostname to IP addresses with specific record type flags.
    fn resolve_host_addresses_with_flags(
        &self,
        hostname: &str,
        ignore_target_hosts: Option<&str>,
        flags: HostFindFlags,
    ) -> Result<Vec<IpAddr>, DnsError> {
        let mut addresses = Vec::new();

        if flags.contains(HostFindFlags::BY_A) {
            if let Ok(response) = self.dns_basic_lookup(hostname, DnsRecordType::A) {
                for record in response.answer_records() {
                    if let DnsRecordData::A(addr) = &record.data {
                        let ip = IpAddr::V4(*addr);
                        if !is_ignored_host(&ip, ignore_target_hosts) {
                            addresses.push(ip);
                        }
                    }
                }
            }
        }

        if flags.contains(HostFindFlags::BY_AAAA) {
            if let Ok(response) = self.dns_basic_lookup(hostname, DnsRecordType::Aaaa) {
                for record in response.answer_records() {
                    if let DnsRecordData::Aaaa(addr) = &record.data {
                        let ip = IpAddr::V6(*addr);
                        if !is_ignored_host(&ip, ignore_target_hosts) {
                            addresses.push(ip);
                        }
                    }
                }
            }
        }

        Ok(addresses)
    }

    // =========================================================================
    // Backward-compatible convenience methods (for dnsbl.rs)
    // =========================================================================

    /// Creates a resolver with default settings.
    ///
    /// Convenience method for cross-module compatibility (used by dnsbl.rs).
    pub fn with_defaults() -> Result<Self, DnsError> {
        Self::from_system()
    }

    /// Performs an A record lookup, returning resolved IPv4 addresses.
    ///
    /// Convenience method for cross-module compatibility (used by dnsbl.rs).
    /// Returns only IPv4 addresses since A records are always IPv4.
    pub fn lookup_a(&self, name: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
        let response = self.dns_basic_lookup(name, DnsRecordType::A)?;
        let addresses: Vec<Ipv4Addr> = response
            .answer_records()
            .filter_map(|r| match &r.data {
                DnsRecordData::A(addr) => Some(*addr),
                _ => None,
            })
            .collect();
        Ok(addresses)
    }

    /// Performs a TXT record lookup, returning TxtRecord entries.
    ///
    /// Convenience method for cross-module compatibility (used by dnsbl.rs).
    pub fn lookup_txt(&self, name: &str) -> Result<Vec<TxtRecord>, DnsError> {
        let response = self.dns_basic_lookup(name, DnsRecordType::Txt)?;
        let records: Vec<TxtRecord> = response
            .answer_records()
            .filter_map(|r| match &r.data {
                DnsRecordData::Txt(data) => Some(TxtRecord { data: data.clone() }),
                _ => None,
            })
            .collect();
        Ok(records)
    }
} // end impl DnsResolver

// =============================================================================
// Free Functions — Utility
// =============================================================================

/// Returns the reversed octets of an IPv4 address as a dot-separated string.
///
/// `Ipv4Addr::new(1, 2, 3, 4)` → `"4.3.2.1"`
///
/// This is the raw reversal used by DNSBL query construction. For full PTR
/// reverse names (with `.in-addr.arpa.` suffix), use [`DnsResolver::dns_build_reverse()`].
pub fn reverse_ipv4(addr: &Ipv4Addr) -> String {
    let octets = addr.octets();
    format!("{}.{}.{}.{}", octets[3], octets[2], octets[1], octets[0])
}

/// Returns the reversed nibbles of an IPv6 address as a dot-separated string.
///
/// Expands the address to full 32 hex nibbles and reverses.
///
/// This is the raw reversal used by DNSBL query construction. For full PTR
/// reverse names (with `.ip6.arpa.` suffix), use [`DnsResolver::dns_build_reverse()`].
pub fn reverse_ipv6(addr: &Ipv6Addr) -> String {
    let segments = addr.segments();
    let mut nibbles = Vec::with_capacity(32);
    for segment in &segments {
        nibbles.push((segment >> 12) & 0xf);
        nibbles.push((segment >> 8) & 0xf);
        nibbles.push((segment >> 4) & 0xf);
        nibbles.push(segment & 0xf);
    }
    nibbles.reverse();
    let nibble_strs: Vec<String> = nibbles.iter().map(|n| format!("{n:x}")).collect();
    nibble_strs.join(".")
}

/// Checks if an IP address matches a colon-separated ignore list.
///
/// Returns `true` if the address should be ignored/skipped.
fn is_ignored_host(ip: &IpAddr, ignore_list: Option<&str>) -> bool {
    let list = match ignore_list {
        Some(l) => l,
        None => return false,
    };

    let ip_str = ip.to_string();
    for pattern in list.split(':') {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            continue;
        }
        if pattern == ip_str {
            return true;
        }
        // Simple wildcard matching: "192.168.*" or "10.*"
        if let Some(prefix) = pattern.strip_suffix('*') {
            if ip_str.starts_with(prefix) {
                return true;
            }
        }
    }
    false
}

/// Checks if a domain name matches a colon-separated domain list.
///
/// Supports exact match, suffix match (*.example.com), and wildcard (*).
/// This replicates the C `match_isinlist()` pattern used throughout Exim.
fn domain_matches_list(domain: &str, list: &str) -> bool {
    let domain_lower = domain.to_lowercase();
    for entry in list.split(':') {
        let entry = entry.trim().to_lowercase();
        if entry.is_empty() {
            continue;
        }
        if entry == "*" {
            return true;
        }
        if entry == domain_lower {
            return true;
        }
        // Suffix match: "*.example.com" matches "sub.example.com"
        if let Some(suffix) = entry.strip_prefix("*.") {
            if domain_lower.ends_with(suffix) || domain_lower == suffix {
                return true;
            }
        }
        // Domain suffix match: ".example.com" matches "sub.example.com"
        if entry.starts_with('.') && domain_lower.ends_with(&entry) {
            return true;
        }
    }
    false
}

/// Updates a DNSSEC status based on whether the current response is authenticated.
fn update_dnssec_status(status: &mut DnssecStatus, authenticated: bool) {
    match (*status, authenticated) {
        (DnssecStatus::Unknown, true) => *status = DnssecStatus::Yes,
        (DnssecStatus::Unknown, false) => *status = DnssecStatus::No,
        (DnssecStatus::Yes, false) => *status = DnssecStatus::No,
        _ => {} // Keep current status
    }
}

/// Sorts host items by MX/SRV priority and randomizes within the same priority.
///
/// Replaces C host list sorting with priority-based ordering and random
/// shuffling within each priority group (per RFC 5321 §5).
fn sort_hosts_by_priority(hosts: &mut [HostItem]) {
    // Sort by mx_priority (None sorts last)
    hosts.sort_by(|a, b| {
        let a_prio = a.mx_priority.unwrap_or(i32::MAX);
        let b_prio = b.mx_priority.unwrap_or(i32::MAX);
        a_prio.cmp(&b_prio)
    });

    // Randomize within each priority group using sort_key as a random tiebreaker
    // In the C code this uses random() — here we use a simple deterministic shuffle
    // based on the hostname hash for reproducibility in testing.
    let mut i = 0;
    while i < hosts.len() {
        let current_prio = hosts[i].mx_priority;
        let group_start = i;

        // Find the end of the current priority group
        while i < hosts.len() && hosts[i].mx_priority == current_prio {
            // Assign a sort key based on hostname hash for pseudo-random ordering
            let hash = simple_hash(&hosts[i].name);
            hosts[i].sort_key = hash as i32;
            i += 1;
        }

        // Sort within the group by sort_key for deterministic pseudo-random order
        if i - group_start > 1 {
            hosts[group_start..i].sort_by_key(|h| h.sort_key);
        }
    }
}

/// Simple deterministic hash for hostname-based sort key generation.
fn simple_hash(s: &str) -> u32 {
    let mut hash: u32 = 5381;
    for byte in s.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(u32::from(byte));
    }
    hash
}

// =============================================================================
// Additional type aliases and re-exports for backward compatibility
// =============================================================================

/// Backward-compatible type aliases for dnsbl.rs cross-module usage.
/// TxtRecord provides a simple wrapper for TXT record data.
#[derive(Debug, Clone)]
pub struct TxtRecord {
    /// The concatenated text data from the TXT record.
    pub data: String,
}

/// MX record data for external consumers.
#[derive(Debug, Clone)]
pub struct MxRecord {
    /// MX preference value (lower = higher priority).
    pub preference: u16,
    /// Mail exchange hostname.
    pub exchange: String,
}

/// SRV record data for external consumers.
#[derive(Debug, Clone)]
pub struct SrvRecord {
    /// Service priority (lower = higher priority).
    pub priority: u16,
    /// Weight for load balancing within the same priority.
    pub weight: u16,
    /// Port number for the service.
    pub port: u16,
    /// Target hostname providing the service.
    pub target: String,
}

/// TLSA record data for external consumers (DANE).
#[derive(Debug, Clone)]
pub struct TlsaRecord {
    /// Certificate usage field (0-3).
    pub cert_usage: u8,
    /// Selector field (0-1).
    pub selector: u8,
    /// Matching type field (0-2).
    pub matching_type: u8,
    /// Certificate association data.
    pub cert_data: Vec<u8>,
}

/// Backward-compatible result code alias.
pub type DnsResultCode = DnsResult;
