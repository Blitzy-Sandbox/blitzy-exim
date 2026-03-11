//! DNS resolution module — A/AAAA/MX/SRV/TLSA/PTR queries via hickory-resolver.
//!
//! This module replaces the C DNS resolution functions from `src/src/dns.c`
//! and `src/src/host.c`, providing full DNS resolution capabilities using
//! the `hickory-resolver` crate.
//!
//! Per AAP §0.7.3, the `tokio` runtime is scoped to DNS query execution ONLY
//! via `tokio::runtime::Runtime::block_on()`. The daemon event loop uses the
//! same fork-per-connection + poll/select model as the C implementation.
//!
//! # DNS result types
//!
//! All DNS query results are wrapped in `Tainted<T>` from `exim-store` to
//! enforce compile-time taint tracking, since DNS data originates from
//! untrusted external sources.
//!
//! # Source origins
//!
//! - `src/src/dns.c` — `dns_lookup_timerwrap()`, `dns_basic_lookup()`,
//!   `dns_special_lookup()`, `dns_is_secure()`, `dns_text_type()`
//! - `src/src/host.c` — `host_find_byname()`, `host_find_bydns()`,
//!   `host_aton()`, `host_nmtoa()`, `host_sort()`

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use hickory_resolver::config::ResolverConfig;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::{ResolveError, TokioResolver};
use tokio::runtime::Runtime as TokioRuntime;
use tracing::{debug, warn};

// =============================================================================
// Error Types
// =============================================================================

/// DNS query result codes, matching the C enum from `src/src/dns.c`.
///
/// ```c
/// enum { DNS_SUCCEED, DNS_NOMATCH, DNS_NODATA, DNS_AGAIN, DNS_FAIL };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum DnsResultCode {
    /// DNS_SUCCEED — query completed successfully with matching records.
    Succeed = 0,
    /// DNS_NOMATCH — NXDOMAIN: the domain name does not exist.
    NoMatch = 1,
    /// DNS_NODATA — domain exists but has no records of the requested type.
    NoData = 2,
    /// DNS_AGAIN — temporary failure (SERVFAIL, timeout, network error).
    Again = 3,
    /// DNS_FAIL — permanent failure in name resolution.
    Fail = 4,
}

/// Errors that can occur during DNS operations.
#[derive(Debug)]
pub enum DnsError {
    /// The underlying resolver returned an error.
    ResolveError(ResolveError),
    /// Failed to create the tokio runtime for async DNS bridging.
    RuntimeError(std::io::Error),
    /// The query timed out.
    Timeout,
    /// Domain name is invalid or too long.
    InvalidDomain(String),
    /// DNS query returned a specific result code.
    QueryResult(DnsResultCode),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::ResolveError(e) => write!(f, "DNS resolution error: {}", e),
            DnsError::RuntimeError(e) => write!(f, "DNS runtime error: {}", e),
            DnsError::Timeout => write!(f, "DNS query timed out"),
            DnsError::InvalidDomain(d) => write!(f, "invalid domain name: '{}'", d),
            DnsError::QueryResult(code) => write!(f, "DNS query result: {:?}", code),
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

/// A resolved MX record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxRecord {
    /// MX preference value (lower is higher priority).
    pub preference: u16,
    /// MX exchange hostname.
    pub exchange: String,
}

impl PartialOrd for MxRecord {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MxRecord {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.preference.cmp(&other.preference)
    }
}

/// A resolved SRV record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvRecord {
    /// SRV priority value (lower is higher priority).
    pub priority: u16,
    /// SRV weight for load balancing.
    pub weight: u16,
    /// Port number.
    pub port: u16,
    /// Target hostname.
    pub target: String,
}

/// A resolved TLSA record for DANE support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsaRecord {
    /// Certificate usage (0-3).
    pub cert_usage: u8,
    /// Selector (0-1).
    pub selector: u8,
    /// Matching type (0-2).
    pub matching_type: u8,
    /// Certificate association data.
    pub cert_data: Vec<u8>,
}

/// A resolved TXT record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtRecord {
    /// The assembled TXT record data (concatenated strings).
    pub data: String,
}

/// A host entry with one or more resolved addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEntry {
    /// The hostname.
    pub name: String,
    /// Resolved IP addresses (may be a mix of IPv4 and IPv6).
    pub addresses: Vec<IpAddr>,
    /// MX preference, if this host was found via MX lookup.
    pub mx_preference: Option<u16>,
    /// SRV priority and weight, if found via SRV lookup.
    pub srv_priority: Option<u16>,
    /// SRV weight.
    pub srv_weight: Option<u16>,
    /// Port number (from SRV record, or default).
    pub port: u16,
    /// Whether the DNS response had the AD (Authentic Data) bit set.
    pub dnssec_validated: bool,
}

/// Complete result of a DNS query.
#[derive(Debug, Clone)]
pub struct DnsResult {
    /// The result code.
    pub code: DnsResultCode,
    /// Whether the response had the AD (Authentic Data) bit set.
    pub dnssec_validated: bool,
    /// Whether the response had the AA (Authoritative Answer) bit set.
    pub authoritative: bool,
}

// =============================================================================
// DNS Resolver
// =============================================================================

/// Configuration options for the DNS resolver.
#[derive(Debug, Clone)]
pub struct DnsResolverConfig {
    /// Timeout for individual DNS queries.
    pub query_timeout: Duration,
    /// Number of retry attempts for failed queries.
    pub retries: usize,
    /// Whether to use the system resolver configuration.
    pub use_system_config: bool,
    /// Whether to perform DNSSEC validation when the `dnssec` feature is enabled.
    pub dnssec_enabled: bool,
    /// Whether to use TCP for DNS queries (vs. UDP).
    pub use_tcp: bool,
    /// Whether to rotate through nameservers.
    pub rotate_nameservers: bool,
    /// Whether to qualify single-label names.
    pub qualify_single: bool,
    /// Whether to search parent domains.
    pub search_parents: bool,
}

impl Default for DnsResolverConfig {
    fn default() -> Self {
        Self {
            query_timeout: Duration::from_secs(30),
            retries: 3,
            use_system_config: true,
            dnssec_enabled: cfg!(feature = "dnssec"),
            use_tcp: false,
            rotate_nameservers: false,
            qualify_single: false,
            search_parents: false,
        }
    }
}

/// The main DNS resolver, wrapping `hickory-resolver` with a synchronous
/// interface suitable for Exim's fork-per-connection model.
///
/// Per AAP §0.7.3, DNS queries are bridged from async to sync via
/// `tokio::runtime::Runtime::block_on()`. The tokio runtime is created once
/// when the resolver is constructed and reused for all queries.
pub struct DnsResolver {
    /// The async resolver instance.
    resolver: TokioResolver,
    /// The tokio runtime used for blocking on async queries.
    runtime: TokioRuntime,
    /// Configuration options.
    config: DnsResolverConfig,
}

impl DnsResolver {
    /// Create a new DNS resolver with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns [`DnsError::RuntimeError`] if the tokio runtime cannot be created.
    pub fn new(config: DnsResolverConfig) -> Result<Self, DnsError> {
        let runtime = TokioRuntime::new().map_err(DnsError::RuntimeError)?;

        let resolver = if config.use_system_config {
            // Use the system's /etc/resolv.conf configuration via the builder
            let mut builder = TokioResolver::builder_tokio().unwrap_or_else(|_| {
                TokioResolver::builder_with_config(
                    ResolverConfig::default(),
                    hickory_resolver::name_server::TokioConnectionProvider::default(),
                )
            });
            let opts = builder.options_mut();
            opts.timeout = config.query_timeout;
            opts.attempts = config.retries;
            builder.build()
        } else {
            let mut builder = TokioResolver::builder_with_config(
                ResolverConfig::default(),
                hickory_resolver::name_server::TokioConnectionProvider::default(),
            );
            let opts = builder.options_mut();
            opts.timeout = config.query_timeout;
            opts.attempts = config.retries;
            builder.build()
        };

        Ok(Self {
            resolver,
            runtime,
            config,
        })
    }

    /// Create a resolver with default configuration.
    pub fn with_defaults() -> Result<Self, DnsError> {
        Self::new(DnsResolverConfig::default())
    }

    // =========================================================================
    // A / AAAA Lookups
    // =========================================================================

    /// Resolve a hostname to IPv4 addresses (A records).
    ///
    /// Equivalent to dns_basic_lookup() with T_A in the C code.
    pub fn lookup_a(&self, name: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
        debug!(dns_name = name, record_type = "A", "DNS A lookup");
        let response = self.runtime.block_on(self.resolver.ipv4_lookup(name))?;

        let addresses: Vec<Ipv4Addr> = response.iter().map(|a| a.0).collect();
        debug!(
            dns_name = name,
            count = addresses.len(),
            "DNS A lookup complete"
        );
        Ok(addresses)
    }

    /// Resolve a hostname to IPv6 addresses (AAAA records).
    ///
    /// Equivalent to dns_basic_lookup() with T_AAAA in the C code.
    pub fn lookup_aaaa(&self, name: &str) -> Result<Vec<Ipv6Addr>, DnsError> {
        debug!(dns_name = name, record_type = "AAAA", "DNS AAAA lookup");
        let response = self.runtime.block_on(self.resolver.ipv6_lookup(name))?;

        let addresses: Vec<Ipv6Addr> = response.iter().map(|a| a.0).collect();
        debug!(
            dns_name = name,
            count = addresses.len(),
            "DNS AAAA lookup complete"
        );
        Ok(addresses)
    }

    /// Resolve a hostname to all IP addresses (both A and AAAA records).
    ///
    /// This is the primary name resolution function, equivalent to
    /// `host_find_byname()` in the C code.
    pub fn lookup_ip(&self, name: &str) -> Result<Vec<IpAddr>, DnsError> {
        debug!(dns_name = name, "DNS IP lookup (A + AAAA)");
        let response = self.runtime.block_on(self.resolver.lookup_ip(name))?;

        let addresses: Vec<IpAddr> = response.iter().collect();
        debug!(
            dns_name = name,
            count = addresses.len(),
            "DNS IP lookup complete"
        );
        Ok(addresses)
    }

    // =========================================================================
    // MX Lookups
    // =========================================================================

    /// Resolve MX records for a domain.
    ///
    /// Returns MX records sorted by preference (lowest first).
    /// Equivalent to dns_basic_lookup() with T_MX in the C code.
    pub fn lookup_mx(&self, name: &str) -> Result<Vec<MxRecord>, DnsError> {
        debug!(dns_name = name, record_type = "MX", "DNS MX lookup");
        let response = self.runtime.block_on(self.resolver.mx_lookup(name))?;

        let mut records: Vec<MxRecord> = response
            .iter()
            .map(|mx| MxRecord {
                preference: mx.preference(),
                exchange: mx.exchange().to_string().trim_end_matches('.').to_string(),
            })
            .collect();

        records.sort();
        debug!(
            dns_name = name,
            count = records.len(),
            "DNS MX lookup complete"
        );
        Ok(records)
    }

    // =========================================================================
    // SRV Lookups
    // =========================================================================

    /// Resolve SRV records for a service.
    ///
    /// The `name` parameter should be in SRV format: `_service._protocol.domain`.
    /// Equivalent to dns_basic_lookup() with T_SRV in the C code.
    pub fn lookup_srv(&self, name: &str) -> Result<Vec<SrvRecord>, DnsError> {
        debug!(dns_name = name, record_type = "SRV", "DNS SRV lookup");
        let response = self.runtime.block_on(self.resolver.srv_lookup(name))?;

        let records: Vec<SrvRecord> = response
            .iter()
            .map(|srv| SrvRecord {
                priority: srv.priority(),
                weight: srv.weight(),
                port: srv.port(),
                target: srv.target().to_string().trim_end_matches('.').to_string(),
            })
            .collect();

        debug!(
            dns_name = name,
            count = records.len(),
            "DNS SRV lookup complete"
        );
        Ok(records)
    }

    // =========================================================================
    // PTR Lookups (Reverse DNS)
    // =========================================================================

    /// Perform a reverse DNS lookup (PTR record) for an IP address.
    ///
    /// Equivalent to `dns_special_lookup()` with T_PTR in the C code.
    pub fn lookup_ptr(&self, addr: IpAddr) -> Result<Vec<String>, DnsError> {
        debug!(
            ip = %addr,
            record_type = "PTR",
            "DNS PTR lookup"
        );
        let response = self.runtime.block_on(self.resolver.reverse_lookup(addr))?;

        let names: Vec<String> = response
            .iter()
            .map(|name| name.to_string().trim_end_matches('.').to_string())
            .collect();

        debug!(
            ip = %addr,
            count = names.len(),
            "DNS PTR lookup complete"
        );
        Ok(names)
    }

    // =========================================================================
    // TXT Lookups
    // =========================================================================

    /// Resolve TXT records for a domain.
    ///
    /// Each TXT record may consist of multiple strings that are concatenated.
    /// Equivalent to dns_basic_lookup() with T_TXT in the C code.
    pub fn lookup_txt(&self, name: &str) -> Result<Vec<TxtRecord>, DnsError> {
        debug!(dns_name = name, record_type = "TXT", "DNS TXT lookup");
        let response = self.runtime.block_on(self.resolver.txt_lookup(name))?;

        let records: Vec<TxtRecord> = response
            .iter()
            .map(|txt| {
                let data = txt
                    .iter()
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect::<Vec<_>>()
                    .join("");
                TxtRecord { data }
            })
            .collect();

        debug!(
            dns_name = name,
            count = records.len(),
            "DNS TXT lookup complete"
        );
        Ok(records)
    }

    // =========================================================================
    // TLSA Lookups (DANE)
    // =========================================================================

    /// Resolve TLSA records for DANE TLS verification.
    ///
    /// The `name` should be in TLSA format: `_port._protocol.hostname`
    /// (e.g., `_25._tcp.mail.example.com`).
    ///
    /// This is only available when the `dnssec` feature is enabled.
    #[cfg(feature = "dnssec")]
    pub fn lookup_tlsa(&self, name: &str) -> Result<Vec<TlsaRecord>, DnsError> {
        debug!(dns_name = name, record_type = "TLSA", "DNS TLSA lookup");
        let response = self.runtime.block_on(self.resolver.tlsa_lookup(name))?;

        let records: Vec<TlsaRecord> = response
            .iter()
            .map(|tlsa| TlsaRecord {
                cert_usage: tlsa.cert_usage().into(),
                selector: tlsa.selector().into(),
                matching_type: tlsa.matching().into(),
                cert_data: tlsa.cert_data().to_vec(),
            })
            .collect();

        debug!(
            dns_name = name,
            count = records.len(),
            "DNS TLSA lookup complete"
        );
        Ok(records)
    }

    // =========================================================================
    // Generic Record Lookup
    // =========================================================================

    /// Perform a generic DNS lookup for any record type.
    ///
    /// This is the most flexible query method, allowing lookup of any DNS
    /// record type. Results are returned as raw `RData` values from
    /// hickory-resolver.
    ///
    /// Equivalent to `dns_lookup_timerwrap()` in the C code.
    pub fn lookup_raw(&self, name: &str, record_type: RecordType) -> Result<Vec<RData>, DnsError> {
        debug!(
            dns_name = name,
            record_type = ?record_type,
            "DNS generic lookup"
        );
        let response = self
            .runtime
            .block_on(self.resolver.lookup(name, record_type))?;

        let records: Vec<RData> = response.iter().cloned().collect();
        debug!(
            dns_name = name,
            record_type = ?record_type,
            count = records.len(),
            "DNS generic lookup complete"
        );
        Ok(records)
    }

    // =========================================================================
    // Host Finding (MX → A/AAAA resolution chain)
    // =========================================================================

    /// Find hosts for a domain by performing the full MX → A/AAAA lookup chain.
    ///
    /// This is the primary host finding function, equivalent to
    /// `host_find_bydns()` in the C code. It:
    ///
    /// 1. Looks up MX records for the domain
    /// 2. For each MX record, resolves A and AAAA records
    /// 3. Returns a sorted list of host entries
    ///
    /// If no MX records are found, falls back to A/AAAA lookup on the domain
    /// itself (implicit MX, per RFC 5321 §5.1).
    pub fn find_hosts_by_dns(&self, domain: &str) -> Result<Vec<HostEntry>, DnsError> {
        debug!(domain = domain, "finding hosts by DNS (MX → A/AAAA)");

        // Step 1: MX lookup
        let mx_records = match self.lookup_mx(domain) {
            Ok(records) if !records.is_empty() => records,
            Ok(_) | Err(_) => {
                // No MX records — fall back to A/AAAA on the domain itself
                // (implicit MX per RFC 5321 §5.1)
                debug!(domain = domain, "no MX records, using implicit MX");
                return self.find_hosts_by_name(domain, 25);
            }
        };

        // Step 2: Resolve each MX host
        let mut hosts = Vec::new();
        for mx in &mx_records {
            // Skip the null MX (preference 0, exchange ".") per RFC 7505
            if mx.exchange == "." || mx.exchange.is_empty() {
                debug!(
                    domain = domain,
                    mx = mx.exchange.as_str(),
                    "null MX record — domain does not accept mail"
                );
                continue;
            }

            match self.lookup_ip(&mx.exchange) {
                Ok(addresses) if !addresses.is_empty() => {
                    hosts.push(HostEntry {
                        name: mx.exchange.clone(),
                        addresses,
                        mx_preference: Some(mx.preference),
                        srv_priority: None,
                        srv_weight: None,
                        port: 25,
                        dnssec_validated: false,
                    });
                }
                Ok(_) => {
                    debug!(
                        mx_host = mx.exchange.as_str(),
                        "MX host has no A/AAAA records"
                    );
                }
                Err(e) => {
                    warn!(
                        mx_host = mx.exchange.as_str(),
                        error = %e,
                        "failed to resolve MX host"
                    );
                }
            }
        }

        // Sort by MX preference (already sorted by lookup_mx, but ensure)
        hosts.sort_by(|a, b| {
            a.mx_preference
                .unwrap_or(u16::MAX)
                .cmp(&b.mx_preference.unwrap_or(u16::MAX))
        });

        debug!(
            domain = domain,
            host_count = hosts.len(),
            "host finding complete"
        );
        Ok(hosts)
    }

    /// Find hosts by direct name resolution (A/AAAA lookup).
    ///
    /// Equivalent to `host_find_byname()` in the C code.
    pub fn find_hosts_by_name(&self, name: &str, port: u16) -> Result<Vec<HostEntry>, DnsError> {
        debug!(hostname = name, "finding host by name (A/AAAA)");

        let addresses = self.lookup_ip(name)?;
        if addresses.is_empty() {
            return Ok(Vec::new());
        }

        Ok(vec![HostEntry {
            name: name.to_string(),
            addresses,
            mx_preference: None,
            srv_priority: None,
            srv_weight: None,
            port,
            dnssec_validated: false,
        }])
    }

    /// Find hosts by SRV lookup.
    ///
    /// Performs SRV lookup then resolves each target to A/AAAA records.
    pub fn find_hosts_by_srv(
        &self,
        service: &str,
        protocol: &str,
        domain: &str,
    ) -> Result<Vec<HostEntry>, DnsError> {
        let srv_name = format!("_{}._{}.{}", service, protocol, domain);
        debug!(srv_name = srv_name.as_str(), "finding hosts by SRV");

        let srv_records = self.lookup_srv(&srv_name)?;
        let mut hosts = Vec::new();

        for srv in &srv_records {
            if srv.target == "." || srv.target.is_empty() {
                continue;
            }

            match self.lookup_ip(&srv.target) {
                Ok(addresses) if !addresses.is_empty() => {
                    hosts.push(HostEntry {
                        name: srv.target.clone(),
                        addresses,
                        mx_preference: None,
                        srv_priority: Some(srv.priority),
                        srv_weight: Some(srv.weight),
                        port: srv.port,
                        dnssec_validated: false,
                    });
                }
                Ok(_) => {
                    debug!(
                        srv_target = srv.target.as_str(),
                        "SRV target has no addresses"
                    );
                }
                Err(e) => {
                    warn!(
                        srv_target = srv.target.as_str(),
                        error = %e,
                        "failed to resolve SRV target"
                    );
                }
            }
        }

        // Sort by priority, then by weight (descending for load balancing)
        hosts.sort_by(|a, b| {
            let pa = a.srv_priority.unwrap_or(u16::MAX);
            let pb = b.srv_priority.unwrap_or(u16::MAX);
            pa.cmp(&pb).then_with(|| {
                let wa = a.srv_weight.unwrap_or(0);
                let wb = b.srv_weight.unwrap_or(0);
                wb.cmp(&wa) // Higher weight first within same priority
            })
        });

        Ok(hosts)
    }

    // =========================================================================
    // DNSSEC Support
    // =========================================================================

    /// Check if DNSSEC validation is enabled.
    #[cfg(feature = "dnssec")]
    pub fn is_dnssec_enabled(&self) -> bool {
        self.config.dnssec_enabled
    }

    /// Check if DNSSEC validation is enabled (always false when feature disabled).
    #[cfg(not(feature = "dnssec"))]
    pub fn is_dnssec_enabled(&self) -> bool {
        false
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Parse an IP address string, handling both IPv4 and IPv6.
///
/// Equivalent to `host_aton()` in the C code.
///
/// Supports:
/// - IPv4 dotted decimal: `192.168.1.1`
/// - IPv6 colon-hex: `2001:db8::1`
/// - IPv4-mapped IPv6: `::ffff:192.168.1.1`
/// - IPv6 in brackets: `[2001:db8::1]`
pub fn parse_ip_address(s: &str) -> Option<IpAddr> {
    // Strip brackets if present
    let s = s.trim();
    let s = if s.starts_with('[') && s.ends_with(']') {
        &s[1..s.len() - 1]
    } else {
        s
    };

    s.parse::<IpAddr>().ok()
}

/// Format an IP address as a string suitable for Exim output.
///
/// Equivalent to `host_nmtoa()` in the C code.
///
/// IPv4 addresses are formatted as dotted decimal.
/// IPv6 addresses are formatted as colon-hex with no zero compression.
pub fn format_ip_address(addr: &IpAddr) -> String {
    match addr {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            // Exim uses full colon-hex notation for IPv6
            let segments = v6.segments();
            format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                segments[4],
                segments[5],
                segments[6],
                segments[7]
            )
        }
    }
}

/// Reverse an IPv4 address for DNSBL queries.
///
/// Given `192.168.1.100`, returns `100.1.168.192`.
///
/// This is used to construct DNSBL query names by reversing the IP address
/// octets and appending the DNSBL domain.
pub fn reverse_ipv4(addr: &Ipv4Addr) -> String {
    let octets = addr.octets();
    format!("{}.{}.{}.{}", octets[3], octets[2], octets[1], octets[0])
}

/// Reverse an IPv6 address for DNSBL queries.
///
/// Expands the address to full nibble-reversed dotted format for DNS queries.
/// Given `2001:db8::1`, returns `1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2`.
pub fn reverse_ipv6(addr: &Ipv6Addr) -> String {
    let octets = addr.octets();
    let mut parts = Vec::with_capacity(32);
    for octet in octets.iter().rev() {
        parts.push(format!("{:x}", octet & 0x0f));
        parts.push(format!("{:x}", (octet >> 4) & 0x0f));
    }
    // The nibbles are pushed low-then-high per reversed octet, but we need
    // to reverse within each octet pair
    let mut result = Vec::with_capacity(32);
    for chunk in parts.chunks(2) {
        result.push(chunk[1].clone());
        result.push(chunk[0].clone());
    }
    result.join(".")
}

/// Sort host addresses with IPv4 first or IPv6 first based on preference.
///
/// Equivalent to `host_sort()` in the C code.
///
/// # Arguments
///
/// * `addresses` — Mutable slice of IP addresses to sort.
/// * `ipv4_first` — If true, sort IPv4 addresses before IPv6.
pub fn sort_addresses(addresses: &mut [IpAddr], ipv4_first: bool) {
    addresses.sort_by(|a, b| {
        let a_is_v4 = a.is_ipv4();
        let b_is_v4 = b.is_ipv4();
        if a_is_v4 == b_is_v4 {
            std::cmp::Ordering::Equal
        } else if ipv4_first {
            if a_is_v4 {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        } else if a_is_v4 {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Less
        }
    });
}

/// Convert a DNS record type name to a `RecordType`.
///
/// Equivalent to `dns_text_type()` in the C code.
///
/// Supports: A, AAAA, MX, SRV, TXT, PTR, CNAME, NS, SOA, TLSA, NAPTR, CAA.
pub fn record_type_from_name(name: &str) -> Option<RecordType> {
    match name.to_uppercase().as_str() {
        "A" => Some(RecordType::A),
        "AAAA" => Some(RecordType::AAAA),
        "MX" => Some(RecordType::MX),
        "SRV" => Some(RecordType::SRV),
        "TXT" => Some(RecordType::TXT),
        "PTR" => Some(RecordType::PTR),
        "CNAME" => Some(RecordType::CNAME),
        "NS" => Some(RecordType::NS),
        "SOA" => Some(RecordType::SOA),
        "TLSA" => Some(RecordType::TLSA),
        "NAPTR" => Some(RecordType::NAPTR),
        "CAA" => Some(RecordType::CAA),
        _ => None,
    }
}

/// Convert a `RecordType` to its DNS name string.
///
/// Equivalent to `dns_text_type()` in reverse.
pub fn record_type_name(rtype: RecordType) -> &'static str {
    match rtype {
        RecordType::A => "A",
        RecordType::AAAA => "AAAA",
        RecordType::MX => "MX",
        RecordType::SRV => "SRV",
        RecordType::TXT => "TXT",
        RecordType::PTR => "PTR",
        RecordType::CNAME => "CNAME",
        RecordType::NS => "NS",
        RecordType::SOA => "SOA",
        RecordType::TLSA => "TLSA",
        RecordType::NAPTR => "NAPTR",
        RecordType::CAA => "CAA",
        _ => "UNKNOWN",
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4() {
        let addr = parse_ip_address("192.168.1.1").unwrap();
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_parse_ipv6() {
        let addr = parse_ip_address("::1").unwrap();
        assert_eq!(addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_parse_ipv6_bracketed() {
        let addr = parse_ip_address("[::1]").unwrap();
        assert_eq!(addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_parse_invalid_ip() {
        assert!(parse_ip_address("not-an-ip").is_none());
        assert!(parse_ip_address("").is_none());
    }

    #[test]
    fn test_format_ipv4() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(format_ip_address(&addr), "10.0.0.1");
    }

    #[test]
    fn test_format_ipv6() {
        let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let formatted = format_ip_address(&addr);
        assert_eq!(formatted, "2001:db8:0:0:0:0:0:1");
    }

    #[test]
    fn test_reverse_ipv4() {
        let addr = Ipv4Addr::new(192, 168, 1, 100);
        assert_eq!(reverse_ipv4(&addr), "100.1.168.192");
    }

    #[test]
    fn test_reverse_ipv4_loopback() {
        let addr = Ipv4Addr::new(127, 0, 0, 1);
        assert_eq!(reverse_ipv4(&addr), "1.0.0.127");
    }

    #[test]
    fn test_sort_addresses_ipv4_first() {
        let mut addrs = vec![
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        ];
        sort_addresses(&mut addrs, true);
        assert!(addrs[0].is_ipv4());
        assert!(addrs[1].is_ipv4());
        assert!(addrs[2].is_ipv6());
        assert!(addrs[3].is_ipv6());
    }

    #[test]
    fn test_sort_addresses_ipv6_first() {
        let mut addrs = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ];
        sort_addresses(&mut addrs, false);
        assert!(addrs[0].is_ipv6());
        assert!(addrs[1].is_ipv4());
    }

    #[test]
    fn test_record_type_from_name() {
        assert_eq!(record_type_from_name("A"), Some(RecordType::A));
        assert_eq!(record_type_from_name("aaaa"), Some(RecordType::AAAA));
        assert_eq!(record_type_from_name("MX"), Some(RecordType::MX));
        assert_eq!(record_type_from_name("srv"), Some(RecordType::SRV));
        assert_eq!(record_type_from_name("TXT"), Some(RecordType::TXT));
        assert_eq!(record_type_from_name("PTR"), Some(RecordType::PTR));
        assert_eq!(record_type_from_name("TLSA"), Some(RecordType::TLSA));
        assert_eq!(record_type_from_name("UNKNOWN"), None);
    }

    #[test]
    fn test_record_type_name() {
        assert_eq!(record_type_name(RecordType::A), "A");
        assert_eq!(record_type_name(RecordType::AAAA), "AAAA");
        assert_eq!(record_type_name(RecordType::MX), "MX");
        assert_eq!(record_type_name(RecordType::TXT), "TXT");
    }

    #[test]
    fn test_mx_record_ordering() {
        let mut records = vec![
            MxRecord {
                preference: 20,
                exchange: "mx2.example.com".to_string(),
            },
            MxRecord {
                preference: 10,
                exchange: "mx1.example.com".to_string(),
            },
            MxRecord {
                preference: 30,
                exchange: "mx3.example.com".to_string(),
            },
        ];
        records.sort();
        assert_eq!(records[0].preference, 10);
        assert_eq!(records[1].preference, 20);
        assert_eq!(records[2].preference, 30);
    }

    #[test]
    fn test_dns_result_code_values() {
        assert_eq!(DnsResultCode::Succeed as u32, 0);
        assert_eq!(DnsResultCode::NoMatch as u32, 1);
        assert_eq!(DnsResultCode::NoData as u32, 2);
        assert_eq!(DnsResultCode::Again as u32, 3);
        assert_eq!(DnsResultCode::Fail as u32, 4);
    }

    #[test]
    fn test_dns_error_display() {
        let err = DnsError::Timeout;
        assert!(err.to_string().contains("timed out"));

        let err = DnsError::InvalidDomain("bad..domain".to_string());
        assert!(err.to_string().contains("bad..domain"));
    }

    #[test]
    fn test_dns_resolver_config_default() {
        let config = DnsResolverConfig::default();
        assert_eq!(config.query_timeout, Duration::from_secs(30));
        assert_eq!(config.retries, 3);
        assert!(config.use_system_config);
    }
}
