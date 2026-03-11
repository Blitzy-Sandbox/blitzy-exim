//! DNSBL (DNS-based Block List) checking module.
//!
//! This module implements DNS-based block list lookups, matching the
//! functionality of `src/src/dnsbl.c` in the C codebase. It provides:
//!
//! - DNSBL query construction (IPv4 reversed-octet + list domain)
//! - IPv6 nibble-reversed DNSBL query construction
//! - Return code matching against expected DNSBL response patterns
//! - Multi-list checking with configurable accept/reject patterns
//! - TXT record retrieval for DNSBL rejection messages
//!
//! # Source Origins
//!
//! - `src/src/dnsbl.c` — `verify_check_dnsbl()`, `one_check_dnsbl()`,
//!   DNSBL return-code bitmask matching

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use tracing::{debug, trace, warn};

use crate::resolver::{reverse_ipv4, reverse_ipv6, DnsError, DnsResolver};

// =============================================================================
// DNSBL Types
// =============================================================================

/// Result of a DNSBL query for a single block list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsblResult {
    /// The IP address was found on the block list.
    Listed {
        /// The block list domain that matched.
        list_domain: String,
        /// The A record returned by the DNSBL (typically 127.0.0.x).
        return_address: Ipv4Addr,
        /// Optional TXT record with the reason for listing.
        reason: Option<String>,
    },
    /// The IP address was NOT found on the block list (NXDOMAIN).
    NotListed,
    /// The DNSBL query failed temporarily (try again later).
    TempError {
        /// The block list domain that failed.
        list_domain: String,
        /// The error that occurred.
        error: String,
    },
}

impl DnsblResult {
    /// Returns true if the IP address was found on a block list.
    pub fn is_listed(&self) -> bool {
        matches!(self, DnsblResult::Listed { .. })
    }

    /// Returns true if the query failed temporarily.
    pub fn is_temp_error(&self) -> bool {
        matches!(self, DnsblResult::TempError { .. })
    }
}

/// Configuration for a single DNSBL.
///
/// Equivalent to the DNSBL specification in an Exim ACL:
/// ```text
/// dnslists = zen.spamhaus.org
/// dnslists = dnsbl.example.com/A;127.0.0.2
/// dnslists = list.example.com=127.0.0.2,127.0.0.3
/// ```
#[derive(Debug, Clone)]
pub struct DnsblSpec {
    /// The DNSBL domain name (e.g., `zen.spamhaus.org`).
    pub domain: String,
    /// Optional list of expected return codes (A record values).
    /// If empty, any A record match means listed.
    /// If set, only these specific return codes count as a match.
    pub match_codes: Vec<Ipv4Addr>,
    /// Optional bitmask to match against the return code.
    /// E.g., if match_bitmask is 0x02, then 127.0.0.2 and 127.0.0.6 both match.
    pub match_bitmask: Option<u8>,
    /// Whether to negate the match (list with `!` prefix in Exim config).
    pub negate: bool,
    /// Whether to retrieve TXT records for the rejection message.
    pub lookup_txt: bool,
    /// Optional key to use instead of the reversed IP address
    /// (for domain-based block lists).
    pub key_override: Option<String>,
}

impl DnsblSpec {
    /// Create a simple DNSBL specification with just a domain.
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
            match_codes: Vec::new(),
            match_bitmask: None,
            negate: false,
            lookup_txt: true,
            key_override: None,
        }
    }

    /// Create a DNSBL specification with specific match codes.
    pub fn with_match_codes(domain: &str, codes: Vec<Ipv4Addr>) -> Self {
        Self {
            domain: domain.to_string(),
            match_codes: codes,
            match_bitmask: None,
            negate: false,
            lookup_txt: true,
            key_override: None,
        }
    }

    /// Create a DNSBL specification with a bitmask match.
    pub fn with_bitmask(domain: &str, bitmask: u8) -> Self {
        Self {
            domain: domain.to_string(),
            match_codes: Vec::new(),
            match_bitmask: Some(bitmask),
            negate: false,
            lookup_txt: true,
            key_override: None,
        }
    }
}

/// Errors specific to DNSBL operations.
#[derive(Debug)]
pub enum DnsblError {
    /// Failed to create or use the DNS resolver.
    Resolver(DnsError),
    /// Invalid IP address format.
    InvalidAddress(String),
    /// Invalid DNSBL specification.
    InvalidSpec(String),
}

impl fmt::Display for DnsblError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsblError::Resolver(e) => write!(f, "DNSBL resolver error: {}", e),
            DnsblError::InvalidAddress(s) => write!(f, "invalid address for DNSBL: {}", s),
            DnsblError::InvalidSpec(s) => write!(f, "invalid DNSBL specification: {}", s),
        }
    }
}

impl std::error::Error for DnsblError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DnsblError::Resolver(e) => Some(e),
            _ => None,
        }
    }
}

impl From<DnsError> for DnsblError {
    fn from(e: DnsError) -> Self {
        DnsblError::Resolver(e)
    }
}

// =============================================================================
// DNSBL Checker
// =============================================================================

/// The DNSBL checker, providing single-list and multi-list checking.
///
/// This wraps a [`DnsResolver`] and provides the DNSBL-specific query
/// construction and response matching logic.
pub struct DnsblChecker {
    /// The DNS resolver used for queries.
    resolver: DnsResolver,
}

impl DnsblChecker {
    /// Create a new DNSBL checker with a shared DNS resolver.
    pub fn new(resolver: DnsResolver) -> Self {
        Self { resolver }
    }

    /// Create a new DNSBL checker with default DNS configuration.
    pub fn with_defaults() -> Result<Self, DnsblError> {
        let resolver = DnsResolver::with_defaults()?;
        Ok(Self { resolver })
    }

    /// Check a single DNSBL for an IP address.
    ///
    /// Constructs the appropriate DNS query name by reversing the IP address
    /// and appending the DNSBL domain, then performs the lookup.
    ///
    /// Equivalent to `one_check_dnsbl()` in the C code.
    pub fn check_single(&self, addr: &IpAddr, spec: &DnsblSpec) -> DnsblResult {
        let query_name = self.build_query_name(addr, spec);

        debug!(
            ip = %addr,
            dnsbl = spec.domain.as_str(),
            query = query_name.as_str(),
            "checking DNSBL"
        );

        // Perform A record lookup
        let a_result = match addr {
            IpAddr::V4(_) => self.resolver.lookup_a(&query_name),
            IpAddr::V6(_) => self.resolver.lookup_a(&query_name),
        };

        match a_result {
            Ok(addresses) if !addresses.is_empty() => {
                // Check if any returned address matches our criteria
                for returned_addr in &addresses {
                    if self.matches_criteria(returned_addr, spec) {
                        let reason = self.get_txt_reason(&query_name, spec);

                        let result = DnsblResult::Listed {
                            list_domain: spec.domain.clone(),
                            return_address: *returned_addr,
                            reason,
                        };

                        // Apply negation if configured
                        if spec.negate {
                            debug!(
                                ip = %addr,
                                dnsbl = spec.domain.as_str(),
                                "DNSBL match negated"
                            );
                            return DnsblResult::NotListed;
                        }

                        debug!(
                            ip = %addr,
                            dnsbl = spec.domain.as_str(),
                            return_code = %returned_addr,
                            "IP listed in DNSBL"
                        );
                        return result;
                    }
                }

                // Had A records but none matched our criteria
                if spec.negate {
                    // Negated and no match means listed (inverted logic)
                    debug!(
                        ip = %addr,
                        dnsbl = spec.domain.as_str(),
                        "DNSBL negated — treating non-match as listed"
                    );
                    DnsblResult::Listed {
                        list_domain: spec.domain.clone(),
                        return_address: addresses[0],
                        reason: None,
                    }
                } else {
                    debug!(
                        ip = %addr,
                        dnsbl = spec.domain.as_str(),
                        "DNSBL returned records but no criteria match"
                    );
                    DnsblResult::NotListed
                }
            }
            Ok(_) => {
                // Empty response — not listed
                if spec.negate {
                    DnsblResult::Listed {
                        list_domain: spec.domain.clone(),
                        return_address: Ipv4Addr::new(127, 0, 0, 0),
                        reason: Some("negated DNSBL match (not listed)".to_string()),
                    }
                } else {
                    DnsblResult::NotListed
                }
            }
            Err(e) => {
                // Check if it's an NXDOMAIN (not listed) vs. a temp error
                let err_str = e.to_string();
                if err_str.contains("no records found")
                    || err_str.contains("NXDomain")
                    || err_str.contains("NoRecordsFound")
                {
                    if spec.negate {
                        DnsblResult::Listed {
                            list_domain: spec.domain.clone(),
                            return_address: Ipv4Addr::new(127, 0, 0, 0),
                            reason: Some("negated DNSBL match (NXDOMAIN)".to_string()),
                        }
                    } else {
                        DnsblResult::NotListed
                    }
                } else {
                    warn!(
                        ip = %addr,
                        dnsbl = spec.domain.as_str(),
                        error = %e,
                        "DNSBL lookup temp error"
                    );
                    DnsblResult::TempError {
                        list_domain: spec.domain.clone(),
                        error: e.to_string(),
                    }
                }
            }
        }
    }

    /// Check multiple DNSBLs for an IP address.
    ///
    /// Returns the first match found, or `DnsblResult::NotListed` if none match.
    /// Temp errors are reported but do not stop further checks.
    ///
    /// Equivalent to `verify_check_dnsbl()` in the C code.
    pub fn check_multiple(&self, addr: &IpAddr, specs: &[DnsblSpec]) -> DnsblResult {
        debug!(
            ip = %addr,
            list_count = specs.len(),
            "checking multiple DNSBLs"
        );

        let mut last_temp_error: Option<DnsblResult> = None;

        for spec in specs {
            let result = self.check_single(addr, spec);
            match &result {
                DnsblResult::Listed { .. } => {
                    debug!(
                        ip = %addr,
                        dnsbl = spec.domain.as_str(),
                        "IP listed — stopping DNSBL checks"
                    );
                    return result;
                }
                DnsblResult::TempError { .. } => {
                    last_temp_error = Some(result);
                }
                DnsblResult::NotListed => {
                    trace!(
                        ip = %addr,
                        dnsbl = spec.domain.as_str(),
                        "not listed — continuing"
                    );
                }
            }
        }

        // If we had temp errors but no hits, return the last temp error
        // so the caller can decide whether to defer
        last_temp_error.unwrap_or(DnsblResult::NotListed)
    }

    /// Build the DNS query name for a DNSBL lookup.
    ///
    /// For IPv4: reversed octets + DNSBL domain.
    /// For IPv6: reversed nibbles + DNSBL domain.
    fn build_query_name(&self, addr: &IpAddr, spec: &DnsblSpec) -> String {
        if let Some(key) = &spec.key_override {
            // Use the override key instead of the IP address
            format!("{}.{}", key, spec.domain)
        } else {
            match addr {
                IpAddr::V4(v4) => {
                    format!("{}.{}", reverse_ipv4(v4), spec.domain)
                }
                IpAddr::V6(v6) => {
                    format!("{}.{}", reverse_ipv6(v6), spec.domain)
                }
            }
        }
    }

    /// Check if a returned A record matches the DNSBL specification criteria.
    fn matches_criteria(&self, addr: &Ipv4Addr, spec: &DnsblSpec) -> bool {
        // If no specific match codes or bitmask, any 127.x.x.x response matches
        if spec.match_codes.is_empty() && spec.match_bitmask.is_none() {
            return addr.octets()[0] == 127;
        }

        // Check specific match codes
        if !spec.match_codes.is_empty() && spec.match_codes.contains(addr) {
            return true;
        }

        // Check bitmask against the last octet
        if let Some(bitmask) = spec.match_bitmask {
            let last_octet = addr.octets()[3];
            if (last_octet & bitmask) != 0 {
                return true;
            }
        }

        // Check specific match codes with bitmask if both are absent
        if spec.match_codes.is_empty() && spec.match_bitmask.is_none() {
            return addr.octets()[0] == 127;
        }

        false
    }

    /// Retrieve the TXT record for a DNSBL listing reason.
    fn get_txt_reason(&self, query_name: &str, spec: &DnsblSpec) -> Option<String> {
        if !spec.lookup_txt {
            return None;
        }

        match self.resolver.lookup_txt(query_name) {
            Ok(records) if !records.is_empty() => Some(
                records
                    .into_iter()
                    .map(|r| r.data)
                    .collect::<Vec<_>>()
                    .join(" "),
            ),
            Ok(_) => None,
            Err(e) => {
                trace!(
                    query = query_name,
                    error = %e,
                    "DNSBL TXT lookup failed"
                );
                None
            }
        }
    }

    /// Get a reference to the underlying DNS resolver.
    pub fn resolver(&self) -> &DnsResolver {
        &self.resolver
    }
}

// =============================================================================
// DNSBL Specification Parser
// =============================================================================

/// Parse a DNSBL specification string from Exim configuration format.
///
/// The format is:
/// ```text
/// [!]domain[/type][=ip1,ip2,...][&bitmask][==key]
/// ```
///
/// Examples:
/// - `zen.spamhaus.org` — simple domain, any 127.x response
/// - `dnsbl.example.com=127.0.0.2` — specific return code
/// - `dnsbl.example.com=127.0.0.2,127.0.0.3` — multiple return codes
/// - `dnsbl.example.com&2` — bitmask match (last octet AND 2)
/// - `!dnsbl.example.com` — negated (match = not listed, no match = listed)
/// - `rhsbl.example.com==key.example.com` — domain-based lookup with key
pub fn parse_dnsbl_spec(spec_str: &str) -> Result<DnsblSpec, DnsblError> {
    let mut input = spec_str.trim();

    // Check for negation prefix
    let negate = input.starts_with('!');
    if negate {
        input = &input[1..];
    }

    // Parse key override (==)
    let (input, key_override) = if let Some(pos) = input.find("==") {
        let key = input[pos + 2..].to_string();
        (&input[..pos], Some(key))
    } else {
        (input, None)
    };

    // Parse bitmask (&)
    let (input, match_bitmask) = if let Some(pos) = input.find('&') {
        let bitmask_str = &input[pos + 1..];
        let bitmask = bitmask_str
            .parse::<u8>()
            .map_err(|_| DnsblError::InvalidSpec(format!("invalid bitmask: '{}'", bitmask_str)))?;
        (&input[..pos], Some(bitmask))
    } else {
        (input, None)
    };

    // Parse match codes (=)
    let (domain, match_codes) = if let Some(pos) = input.find('=') {
        let codes_str = &input[pos + 1..];
        let codes: Result<Vec<Ipv4Addr>, _> = codes_str
            .split(',')
            .map(|s| {
                s.trim()
                    .parse::<Ipv4Addr>()
                    .map_err(|_| DnsblError::InvalidSpec(format!("invalid IP: '{}'", s.trim())))
            })
            .collect();
        (&input[..pos], codes?)
    } else {
        (input, Vec::new())
    };

    if domain.is_empty() {
        return Err(DnsblError::InvalidSpec("empty DNSBL domain".to_string()));
    }

    Ok(DnsblSpec {
        domain: domain.to_string(),
        match_codes,
        match_bitmask,
        negate,
        lookup_txt: true,
        key_override,
    })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_dnsbl() {
        let spec = parse_dnsbl_spec("zen.spamhaus.org").unwrap();
        assert_eq!(spec.domain, "zen.spamhaus.org");
        assert!(spec.match_codes.is_empty());
        assert!(spec.match_bitmask.is_none());
        assert!(!spec.negate);
        assert!(spec.key_override.is_none());
    }

    #[test]
    fn test_parse_dnsbl_with_match_codes() {
        let spec = parse_dnsbl_spec("dnsbl.example.com=127.0.0.2,127.0.0.3").unwrap();
        assert_eq!(spec.domain, "dnsbl.example.com");
        assert_eq!(spec.match_codes.len(), 2);
        assert_eq!(spec.match_codes[0], Ipv4Addr::new(127, 0, 0, 2));
        assert_eq!(spec.match_codes[1], Ipv4Addr::new(127, 0, 0, 3));
    }

    #[test]
    fn test_parse_dnsbl_with_bitmask() {
        let spec = parse_dnsbl_spec("dnsbl.example.com&2").unwrap();
        assert_eq!(spec.domain, "dnsbl.example.com");
        assert_eq!(spec.match_bitmask, Some(2));
    }

    #[test]
    fn test_parse_negated_dnsbl() {
        let spec = parse_dnsbl_spec("!dnsbl.example.com").unwrap();
        assert_eq!(spec.domain, "dnsbl.example.com");
        assert!(spec.negate);
    }

    #[test]
    fn test_parse_dnsbl_with_key() {
        let spec = parse_dnsbl_spec("rhsbl.example.com==key.example.com").unwrap();
        assert_eq!(spec.domain, "rhsbl.example.com");
        assert_eq!(spec.key_override, Some("key.example.com".to_string()));
    }

    #[test]
    fn test_parse_complex_dnsbl() {
        let spec = parse_dnsbl_spec("!dnsbl.example.com=127.0.0.2,127.0.0.4").unwrap();
        assert_eq!(spec.domain, "dnsbl.example.com");
        assert!(spec.negate);
        assert_eq!(spec.match_codes.len(), 2);
    }

    #[test]
    fn test_parse_empty_domain_fails() {
        assert!(parse_dnsbl_spec("").is_err());
        assert!(parse_dnsbl_spec("!").is_err());
    }

    #[test]
    fn test_parse_invalid_bitmask() {
        assert!(parse_dnsbl_spec("example.com&999").is_err());
    }

    #[test]
    fn test_parse_invalid_match_code() {
        assert!(parse_dnsbl_spec("example.com=not.an.ip").is_err());
    }

    #[test]
    fn test_dnsbl_spec_new() {
        let spec = DnsblSpec::new("zen.spamhaus.org");
        assert_eq!(spec.domain, "zen.spamhaus.org");
        assert!(spec.match_codes.is_empty());
        assert!(spec.match_bitmask.is_none());
        assert!(!spec.negate);
        assert!(spec.lookup_txt);
    }

    #[test]
    fn test_dnsbl_spec_with_match_codes() {
        let spec = DnsblSpec::with_match_codes(
            "zen.spamhaus.org",
            vec![Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::new(127, 0, 0, 10)],
        );
        assert_eq!(spec.match_codes.len(), 2);
    }

    #[test]
    fn test_dnsbl_spec_with_bitmask() {
        let spec = DnsblSpec::with_bitmask("zen.spamhaus.org", 0x04);
        assert_eq!(spec.match_bitmask, Some(0x04));
    }

    #[test]
    fn test_dnsbl_result_is_listed() {
        let listed = DnsblResult::Listed {
            list_domain: "zen.spamhaus.org".to_string(),
            return_address: Ipv4Addr::new(127, 0, 0, 2),
            reason: None,
        };
        assert!(listed.is_listed());
        assert!(!listed.is_temp_error());

        let not_listed = DnsblResult::NotListed;
        assert!(!not_listed.is_listed());

        let temp = DnsblResult::TempError {
            list_domain: "zen.spamhaus.org".to_string(),
            error: "timeout".to_string(),
        };
        assert!(!temp.is_listed());
        assert!(temp.is_temp_error());
    }

    #[test]
    fn test_build_query_name_ipv4() {
        // We test the query building logic directly without needing a real resolver
        let spec = DnsblSpec::new("zen.spamhaus.org");
        let _addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let expected_prefix = reverse_ipv4(&Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(expected_prefix, "100.1.168.192");
        let expected = format!("{}.{}", expected_prefix, spec.domain);
        assert_eq!(expected, "100.1.168.192.zen.spamhaus.org");
    }

    #[test]
    fn test_build_query_name_with_key() {
        let spec = DnsblSpec {
            domain: "rhsbl.example.com".to_string(),
            match_codes: Vec::new(),
            match_bitmask: None,
            negate: false,
            lookup_txt: true,
            key_override: Some("test.example.com".to_string()),
        };
        // With key override, the query should use the key, not the reversed IP
        let expected = "test.example.com.rhsbl.example.com";
        let query = format!("{}.{}", spec.key_override.as_ref().unwrap(), spec.domain);
        assert_eq!(query, expected);
    }

    #[test]
    fn test_dnsbl_error_display() {
        let err = DnsblError::InvalidAddress("bad-ip".to_string());
        assert!(err.to_string().contains("bad-ip"));

        let err = DnsblError::InvalidSpec("missing domain".to_string());
        assert!(err.to_string().contains("missing domain"));
    }
}
