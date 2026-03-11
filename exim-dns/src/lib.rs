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
pub use dnsbl::{DnsblChecker, DnsblResult, DnsblSpec};
pub use resolver::{DnsError, DnsResolver, DnsResolverConfig, DnsResultCode};
pub use resolver::{HostEntry, MxRecord, SrvRecord, TlsaRecord, TxtRecord};
