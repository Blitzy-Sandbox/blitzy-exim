//! DNS resolution and DNSBL checking for Exim.
//!
//! This crate provides DNS resolution (A/AAAA/MX/SRV/TLSA/PTR) via
//! `hickory-resolver` and DNSBL (DNS-based Block List) checking,
//! replacing the C implementations in `src/src/dns.c`, `src/src/host.c`,
//! and `src/src/dnsbl.c`.
//!
//! Per AAP §0.7.3, the `tokio` runtime is scoped ONLY to DNS query execution
//! via `tokio::runtime::Runtime::block_on()`. The daemon event loop continues
//! to use the fork-per-connection + poll/select model.

#![deny(unsafe_code)]

pub mod dnsbl;
pub mod resolver;

// Re-export primary types for convenience.
pub use dnsbl::{
    one_check_dnsbl, reverse_ip, verify_check_dnsbl, DeferAction, DnsblCache, DnsblCacheEntry,
    DnsblCheckResult, DnsblVerifyResult, MatchType,
};
pub use resolver::{
    DnsError, DnsRecord, DnsRecordData, DnsRecordIterator, DnsRecordType, DnsResolver, DnsResponse,
    DnsResult, DnsResultCode, DnssecDomains, DnssecStatus, HostFindFlags, HostFindResult, HostItem,
    HostLookupMethod, HostNameResult, MxRecord, NegativeCache, NegativeCacheEntry, ResolverConfig,
    SpecialDnsType, SrvRecord, TlsaRecord, TxtRecord,
};

// Backward-compatible aliases
pub use resolver::DnsSection;
pub use resolver::{reverse_ipv4, reverse_ipv6};
