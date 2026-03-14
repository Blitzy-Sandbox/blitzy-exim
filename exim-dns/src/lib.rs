//! DNS resolution and DNSBL checking for the Exim mail transfer agent.
//!
//! This crate provides the complete DNS subsystem for Exim, replacing three C
//! source files from the original codebase:
//!
//! - **`src/src/dns.c`** (1,445 lines) — DNS query interface, resolver
//!   initialization, record iteration, CNAME following, DNSSEC AD/AA bit
//!   checks, negative caching, reverse name building, and record type helpers.
//!
//! - **`src/src/dnsbl.c`** (668 lines) — DNS-Based Blackhole List verification
//!   with per-connection caching, A-record bitmask/equality matching, lazy TXT
//!   fetching, and multi-domain specification parsing.
//!
//! - **DNS portions of `src/src/host.c`** (3,424 lines) — Host resolution by
//!   DNS (MX/A/AAAA/SRV/PTR), address sorting, forward-confirmed reverse DNS,
//!   and the `host_find_byname` / `host_find_bydns` entry points.
//!
//! # Architecture
//!
//! The crate is structured as two submodules plus shared types in this root:
//!
//! - [`resolver`] — Core DNS resolution via [`hickory-resolver`](https://crates.io/crates/hickory-resolver)
//!   v0.25.0. Provides [`DnsResolver`] as the primary query interface, replacing
//!   C's `res_search()`/`res_query()` calls. Supports A/AAAA/MX/SRV/TLSA/PTR
//!   standard record types plus virtual composite types ([`SpecialDnsType`]):
//!   `T_MXH` (MX hosts only), `T_ZNS` (zone NS with parent walking),
//!   `T_CSA` (Client SMTP Authorization), and SOA with parent walking.
//!
//! - [`dnsbl`] — DNSBL checking with connection-lifetime caching via
//!   [`DnsblCache`]. Entry points: [`one_check_dnsbl`] for individual lookups,
//!   [`verify_check_dnsbl`] for full ACL specification evaluation.
//!
//! # Async Bridging
//!
//! Per AAP §0.7.3, the `tokio` runtime is scoped ONLY to DNS query execution
//! via `tokio::runtime::Runtime::block_on()`. The main daemon event loop uses
//! the same fork-per-connection + poll/select model as the C implementation.
//! The tokio runtime is created per-resolver instance, not process-wide.
//!
//! # DNSSEC Support
//!
//! DNSSEC validation is gated behind the `dnssec` Cargo feature flag (enabled
//! by default), replacing `#ifndef DISABLE_DNSSEC` in the C source. When
//! enabled, [`DnsResponse::dns_is_secure()`] checks the AD (Authenticated Data)
//! and AA (Authoritative Answer) bits. When disabled, DNSSEC methods are no-ops.
//!
//! # Internationalized Domain Names
//!
//! Support for internationalized domain names (IDN) is gated behind the `i18n`
//! Cargo feature flag, replacing `#ifdef SUPPORT_I18N` in the C source. When
//! enabled, UTF-8 domain names are converted to A-label (Punycode) form before
//! DNS lookup, supporting internationalized email per RFC 6531.
//!
//! # Taint Tracking
//!
//! DNS-sourced data is tainted (untrusted external input). All DNS query results
//! — hostnames from PTR records, TXT record text, DNSBL match values — are
//! wrapped in [`exim_store::Tainted<T>`] by the submodules. Domain names from
//! configuration use [`exim_store::Clean<T>`]. This replaces the C runtime
//! `string_copy_taint(buf, GET_TAINTED)` pattern with compile-time enforcement.
//!
//! # DNS Result Codes
//!
//! The five DNS result codes map 1:1 to the C enum from `macros.h` line 308:
//!
//! | Rust ([`DnsResult`]) | C constant | Value | Meaning |
//! |---------------------|------------|-------|---------|
//! | `Succeed` | `DNS_SUCCEED` | 0 | Records found |
//! | `NoMatch` | `DNS_NOMATCH` | 1 | NXDOMAIN |
//! | `NoData` | `DNS_NODATA` | 2 | Exists but no matching type |
//! | `Again` | `DNS_AGAIN` | 3 | Temporary failure |
//! | `Fail` | `DNS_FAIL` | 4 | Permanent failure |

// =============================================================================
// Crate-Level Attributes
// =============================================================================

// Compile-time guarantee of zero unsafe code in this crate (AAP §0.7.2).
// `forbid` cannot be overridden by module-level `#[allow(unsafe_code)]`.
#![forbid(unsafe_code)]
// Encourage comprehensive documentation on all public items.
#![warn(missing_docs)]
// Comprehensive clippy lint enforcement (AAP §0.7.2).
#![deny(clippy::all)]

// =============================================================================
// Submodule Declarations
// =============================================================================

/// Core DNS resolution module — A/AAAA/MX/SRV/TLSA/PTR queries via
/// `hickory-resolver`, negative caching, CNAME following, DNSSEC validation,
/// host finding (MX/SRV/A/AAAA), and reverse DNS with forward confirmation.
///
/// Replaces `src/src/dns.c` and DNS-related portions of `src/src/host.c`.
pub mod resolver;

/// DNSBL (DNS-Based Blackhole List) checking module with caching, bitmask and
/// equality matching, lazy TXT fetching, and full ACL specification parsing.
///
/// Replaces `src/src/dnsbl.c`.
pub mod dnsbl;

// =============================================================================
// External Imports
// =============================================================================

use thiserror::Error;

// =============================================================================
// Re-exports from `resolver` module
// =============================================================================
//
// These re-exports provide ergonomic access to the most commonly used types
// from the resolver module, so consumers can write:
//   use exim_dns::{DnsResolver, DnsResult, DnsError};
// instead of:
//   use exim_dns::resolver::{DnsResolver, DnsResult, DnsError};

pub use resolver::DnsError;
pub use resolver::DnsRecord;
pub use resolver::DnsRecordData;
pub use resolver::DnsRecordIterator;
pub use resolver::DnsRecordType;
pub use resolver::DnsResolver;
pub use resolver::DnsResponse;
pub use resolver::DnsResult;
pub use resolver::DnsSection;
pub use resolver::DnssecDomains;
pub use resolver::DnssecStatus;
pub use resolver::HostFindFlags;
pub use resolver::HostFindResult;
pub use resolver::HostItem;
pub use resolver::HostLookupMethod;
pub use resolver::HostNameResult;
pub use resolver::NegativeCache;
pub use resolver::NegativeCacheEntry;
pub use resolver::ResolverConfig;
pub use resolver::SpecialDnsType;

// =============================================================================
// Re-exports from `dnsbl` module
// =============================================================================
//
// These re-exports provide ergonomic access to the DNSBL checking API,
// so consumers (primarily exim-acl) can write:
//   use exim_dns::{verify_check_dnsbl, DnsblCache};

pub use dnsbl::one_check_dnsbl;
pub use dnsbl::reverse_ip;
pub use dnsbl::verify_check_dnsbl;
pub use dnsbl::DeferAction;
pub use dnsbl::DnsblCache;
pub use dnsbl::DnsblCacheEntry;
pub use dnsbl::DnsblCheckResult;
pub use dnsbl::DnsblVerifyResult;
pub use dnsbl::MatchType;

// =============================================================================
// Additional Type: UnknownRecordType Error
// =============================================================================

/// Error returned when converting an unknown wire-format type code to
/// [`DnsRecordType`].
///
/// Used as the error type for [`TryFrom<u16>`] on [`DnsRecordType`].
/// IANA-assigned type codes that are not supported by Exim (i.e., not one of
/// A, AAAA, MX, SRV, PTR, TXT, CNAME, NS, SOA, TLSA) produce this error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("unknown DNS record type code: {0}")]
pub struct UnknownRecordType(
    /// The unrecognized IANA type code value.
    pub u16,
);

// =============================================================================
// Supplementary Implementations for DnsResult
// =============================================================================
//
// These methods extend the DnsResult enum (defined in resolver.rs) with
// convenience predicates used throughout the Exim codebase.  In C, these
// were inline comparisons like `if (rc == DNS_SUCCEED)`.  In Rust, we
// provide named methods for clarity.

impl DnsResult {
    /// Returns `true` if this result indicates a successful lookup with records.
    ///
    /// Replaces C pattern: `if (rc == DNS_SUCCEED)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use exim_dns::DnsResult;
    /// assert!(DnsResult::Succeed.is_success());
    /// assert!(!DnsResult::NoMatch.is_success());
    /// assert!(!DnsResult::Again.is_success());
    /// ```
    pub fn is_success(&self) -> bool {
        matches!(self, DnsResult::Succeed)
    }

    /// Returns `true` if this result indicates a temporary failure that may
    /// resolve on retry.
    ///
    /// Only [`DnsResult::Again`] is considered a temporary failure.
    /// [`DnsResult::Fail`] is a permanent failure.
    ///
    /// Replaces C pattern: `if (rc == DNS_AGAIN)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use exim_dns::DnsResult;
    /// assert!(DnsResult::Again.is_temporary_failure());
    /// assert!(!DnsResult::Fail.is_temporary_failure());
    /// assert!(!DnsResult::Succeed.is_temporary_failure());
    /// ```
    pub fn is_temporary_failure(&self) -> bool {
        matches!(self, DnsResult::Again)
    }
}

// =============================================================================
// Supplementary Implementation: TryFrom<u16> for DnsRecordType
// =============================================================================
//
// Converts IANA-assigned DNS record type codes (wire format) to the
// DnsRecordType enum.  This replaces the C pattern of using raw integer
// constants (T_A=1, T_NS=2, T_CNAME=5, ..., T_TLSA=52) and provides
// type-safe conversion with error handling for unsupported types.

impl TryFrom<u16> for DnsRecordType {
    type Error = UnknownRecordType;

    /// Converts an IANA DNS record type code to a [`DnsRecordType`] variant.
    ///
    /// Supports the 10 record types used by Exim:
    ///
    /// | Code | Type  | Rust variant |
    /// |------|-------|-------------|
    /// | 1    | A     | `A`         |
    /// | 2    | NS    | `Ns`        |
    /// | 5    | CNAME | `Cname`     |
    /// | 6    | SOA   | `Soa`       |
    /// | 12   | PTR   | `Ptr`       |
    /// | 15   | MX    | `Mx`        |
    /// | 16   | TXT   | `Txt`       |
    /// | 28   | AAAA  | `Aaaa`      |
    /// | 33   | SRV   | `Srv`       |
    /// | 52   | TLSA  | `Tlsa`      |
    ///
    /// # Errors
    ///
    /// Returns [`UnknownRecordType`] if the code does not match any
    /// Exim-supported record type.
    ///
    /// # Examples
    ///
    /// ```
    /// use exim_dns::DnsRecordType;
    /// use std::convert::TryFrom;
    ///
    /// assert_eq!(DnsRecordType::try_from(1u16).unwrap(), DnsRecordType::A);
    /// assert_eq!(DnsRecordType::try_from(28u16).unwrap(), DnsRecordType::Aaaa);
    /// assert!(DnsRecordType::try_from(999u16).is_err());
    /// ```
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DnsRecordType::A),
            2 => Ok(DnsRecordType::Ns),
            5 => Ok(DnsRecordType::Cname),
            6 => Ok(DnsRecordType::Soa),
            12 => Ok(DnsRecordType::Ptr),
            15 => Ok(DnsRecordType::Mx),
            16 => Ok(DnsRecordType::Txt),
            28 => Ok(DnsRecordType::Aaaa),
            33 => Ok(DnsRecordType::Srv),
            52 => Ok(DnsRecordType::Tlsa),
            _ => Err(UnknownRecordType(value)),
        }
    }
}

// =============================================================================
// Module-Level Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryFrom;

    // ── DnsResult tests ────────────────────────────────────────────────────

    #[test]
    fn dns_result_as_str_matches_c_names() {
        assert_eq!(DnsResult::Succeed.as_str(), "DNS_SUCCEED");
        assert_eq!(DnsResult::NoMatch.as_str(), "DNS_NOMATCH");
        assert_eq!(DnsResult::NoData.as_str(), "DNS_NODATA");
        assert_eq!(DnsResult::Again.as_str(), "DNS_AGAIN");
        assert_eq!(DnsResult::Fail.as_str(), "DNS_FAIL");
    }

    #[test]
    fn dns_result_display_matches_as_str() {
        for result in &[
            DnsResult::Succeed,
            DnsResult::NoMatch,
            DnsResult::NoData,
            DnsResult::Again,
            DnsResult::Fail,
        ] {
            assert_eq!(format!("{result}"), result.as_str());
        }
    }

    #[test]
    fn dns_result_is_success() {
        assert!(DnsResult::Succeed.is_success());
        assert!(!DnsResult::NoMatch.is_success());
        assert!(!DnsResult::NoData.is_success());
        assert!(!DnsResult::Again.is_success());
        assert!(!DnsResult::Fail.is_success());
    }

    #[test]
    fn dns_result_is_temporary_failure() {
        assert!(!DnsResult::Succeed.is_temporary_failure());
        assert!(!DnsResult::NoMatch.is_temporary_failure());
        assert!(!DnsResult::NoData.is_temporary_failure());
        assert!(DnsResult::Again.is_temporary_failure());
        assert!(!DnsResult::Fail.is_temporary_failure());
    }

    #[test]
    fn dns_result_copy_and_clone() {
        let a = DnsResult::Succeed;
        let b = a; // Copy
        let c = a.clone(); // Clone
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn dns_result_equality_and_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(DnsResult::Succeed);
        set.insert(DnsResult::NoMatch);
        set.insert(DnsResult::Succeed); // duplicate
        assert_eq!(set.len(), 2);
    }

    // ── DnsRecordType tests ────────────────────────────────────────────────

    #[test]
    fn dns_record_type_as_str() {
        assert_eq!(DnsRecordType::A.as_str(), "A");
        assert_eq!(DnsRecordType::Aaaa.as_str(), "AAAA");
        assert_eq!(DnsRecordType::Mx.as_str(), "MX");
        assert_eq!(DnsRecordType::Srv.as_str(), "SRV");
        assert_eq!(DnsRecordType::Ptr.as_str(), "PTR");
        assert_eq!(DnsRecordType::Txt.as_str(), "TXT");
        assert_eq!(DnsRecordType::Cname.as_str(), "CNAME");
        assert_eq!(DnsRecordType::Ns.as_str(), "NS");
        assert_eq!(DnsRecordType::Soa.as_str(), "SOA");
        assert_eq!(DnsRecordType::Tlsa.as_str(), "TLSA");
    }

    #[test]
    fn dns_record_type_display() {
        assert_eq!(format!("{}", DnsRecordType::A), "A");
        assert_eq!(format!("{}", DnsRecordType::Aaaa), "AAAA");
        assert_eq!(format!("{}", DnsRecordType::Mx), "MX");
    }

    #[test]
    fn dns_record_type_try_from_u16_valid() {
        assert_eq!(DnsRecordType::try_from(1u16).unwrap(), DnsRecordType::A);
        assert_eq!(DnsRecordType::try_from(2u16).unwrap(), DnsRecordType::Ns);
        assert_eq!(DnsRecordType::try_from(5u16).unwrap(), DnsRecordType::Cname);
        assert_eq!(DnsRecordType::try_from(6u16).unwrap(), DnsRecordType::Soa);
        assert_eq!(DnsRecordType::try_from(12u16).unwrap(), DnsRecordType::Ptr);
        assert_eq!(DnsRecordType::try_from(15u16).unwrap(), DnsRecordType::Mx);
        assert_eq!(DnsRecordType::try_from(16u16).unwrap(), DnsRecordType::Txt);
        assert_eq!(DnsRecordType::try_from(28u16).unwrap(), DnsRecordType::Aaaa);
        assert_eq!(DnsRecordType::try_from(33u16).unwrap(), DnsRecordType::Srv);
        assert_eq!(DnsRecordType::try_from(52u16).unwrap(), DnsRecordType::Tlsa);
    }

    #[test]
    fn dns_record_type_try_from_u16_invalid() {
        assert!(DnsRecordType::try_from(0u16).is_err());
        assert!(DnsRecordType::try_from(3u16).is_err());
        assert!(DnsRecordType::try_from(99u16).is_err());
        assert!(DnsRecordType::try_from(255u16).is_err());
        assert!(DnsRecordType::try_from(u16::MAX).is_err());
    }

    #[test]
    fn unknown_record_type_error_display() {
        let err = UnknownRecordType(42);
        assert_eq!(format!("{err}"), "unknown DNS record type code: 42");
    }

    #[test]
    fn unknown_record_type_error_is_std_error() {
        fn _assert_error<T: std::error::Error>() {}
        _assert_error::<UnknownRecordType>();
    }

    // ── DnsRecordType round-trip ───────────────────────────────────────────

    #[test]
    fn dns_record_type_wire_code_round_trip() {
        // Verify all supported IANA codes convert correctly
        let codes_and_types: Vec<(u16, DnsRecordType)> = vec![
            (1, DnsRecordType::A),
            (2, DnsRecordType::Ns),
            (5, DnsRecordType::Cname),
            (6, DnsRecordType::Soa),
            (12, DnsRecordType::Ptr),
            (15, DnsRecordType::Mx),
            (16, DnsRecordType::Txt),
            (28, DnsRecordType::Aaaa),
            (33, DnsRecordType::Srv),
            (52, DnsRecordType::Tlsa),
        ];

        for (code, expected_type) in codes_and_types {
            let converted = DnsRecordType::try_from(code)
                .unwrap_or_else(|_| panic!("code {code} should convert"));
            assert_eq!(converted, expected_type, "code {code} mismatch");
        }
    }

    // ── DnsSection tests ───────────────────────────────────────────────────

    #[test]
    fn dns_section_variants_exist() {
        // Verify all three section variants exist and are distinct
        let answer = DnsSection::Answer;
        let authority = DnsSection::Authority;
        let additional = DnsSection::Additional;
        assert_ne!(answer, authority);
        assert_ne!(answer, additional);
        assert_ne!(authority, additional);
    }

    // ── Re-export availability tests ───────────────────────────────────────

    #[test]
    fn reexported_types_are_accessible() {
        // Verify all re-exported types can be named and constructed/referenced
        // from the crate root.  This is a compile-time test — if these types
        // were not properly re-exported, this test would fail to compile.

        // From resolver module
        let _: fn() -> ResolverConfig = ResolverConfig::default;
        let _: fn() -> NegativeCache = NegativeCache::new;

        // From dnsbl module
        let _: fn() -> DnsblCache = DnsblCache::new;

        // Enums
        let _ = DnsResult::Succeed;
        let _ = DnsResult::NoMatch;
        let _ = DnsResult::NoData;
        let _ = DnsResult::Again;
        let _ = DnsResult::Fail;

        let _ = DnsRecordType::A;
        let _ = DnsRecordType::Aaaa;
        let _ = DnsRecordType::Mx;
        let _ = DnsRecordType::Srv;

        let _ = DnsSection::Answer;
        let _ = DnsSection::Authority;
        let _ = DnsSection::Additional;

        let _ = SpecialDnsType::MxHosts;
        let _ = SpecialDnsType::ZoneNs;
        let _ = SpecialDnsType::Csa;
        let _ = SpecialDnsType::Soa;

        let _ = DnssecStatus::Unknown;
        let _ = DnssecStatus::Yes;
        let _ = DnssecStatus::No;

        let _ = HostLookupMethod::ByDns;
        let _ = HostLookupMethod::ByAddr;

        let _ = HostFindResult::Failed;
        let _ = HostFindResult::Again;

        let _ = DnsblCheckResult::NoMatch;

        let _ = DeferAction::IncludeUnknown;
        let _ = DeferAction::ExcludeUnknown;
        let _ = DeferAction::DeferUnknown;
    }

    // ── MatchType constant tests ───────────────────────────────────────────

    #[test]
    fn match_type_constants_match_c() {
        // C: #define MT_NOT 1
        assert_eq!(MatchType::NOT, 1);
        // C: #define MT_ALL 2
        assert_eq!(MatchType::ALL, 2);
        // Combined flags are valid
        assert_eq!(MatchType::NOT | MatchType::ALL, 3);
    }
}
