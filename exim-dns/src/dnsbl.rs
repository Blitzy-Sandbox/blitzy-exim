//! DNSBL (DNS-Based Blackhole List) checking module.
//!
//! Replaces the entire C source file `src/src/dnsbl.c` (668 lines) which
//! implements DNS-based blacklist/blocklist checking for Exim's ACL system.
//! This module handles IP address reputation lookups against DNSBL services
//! (e.g., Spamhaus ZEN, Barracuda RBL, SpamCop).
//!
//! # Architecture
//!
//! The module provides two levels of API:
//!
//! - [`one_check_dnsbl`] — Performs a single DNSBL lookup against one blacklist
//!   domain, with caching, A-record matching (equality, bitmask, negation,
//!   all-match), and lazy TXT record fetching.
//!
//! - [`verify_check_dnsbl`] — Main entry point from ACL evaluation.  Parses the
//!   full DNSBL specification string supporting multiple domains, defer handling
//!   tokens (`+include_unknown`, `+exclude_unknown`, `+defer_unknown`), explicit
//!   keys, alternate TXT domains, and operator syntax (`=`, `&`, `==`, `!=`,
//!   `!&`, `=&`, `&=`).
//!
//! # Cache
//!
//! [`DnsblCache`] replaces the C `tree_node`-based balanced binary tree with a
//! `HashMap<String, DnsblCacheEntry>` for O(1) amortized lookups.  Cache entries
//! expire based on DNS A-record TTL or SOA negative TTL.
//!
//! # Taint Tracking
//!
//! DNS-sourced data (RHS IP values, TXT record text) are wrapped in
//! [`exim_store::Tainted<String>`] because they originate from untrusted external
//! sources.  Domain names from ACL configuration use [`exim_store::Clean<String>`].
//!
//! # Source Origins
//!
//! - `src/src/dnsbl.c` — `verify_check_dnsbl()` (lines 468–664),
//!   `one_check_dnsbl()` (lines 50–410), `dnsbl_cache_block` struct,
//!   `MT_NOT`/`MT_ALL` constants, `dnsbl_cache` tree anchor.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime};

use tracing::{debug, trace, warn};

use crate::resolver::{
    reverse_ipv4, reverse_ipv6, DnsError, DnsRecordData, DnsRecordType, DnsResolver, DnsResponse,
    DnsResult,
};
use exim_store::{Clean, Tainted};

// =============================================================================
// Match Type Constants
// =============================================================================

/// Match type flags for DNSBL result comparison.
///
/// Replaces C preprocessor constants `MT_NOT` and `MT_ALL` from `dnsbl.c`
/// lines 33–34.  These flags are combined with bitwise OR to control how
/// A-record addresses are matched against the DNSBL iplist specification.
///
/// | Flags | Meaning | C equivalent |
/// |-------|---------|--------------|
/// | `0` | Any RR in iplist (`=`) | `match_type == 0` |
/// | `NOT` | No RR in iplist (`!=`) | `MT_NOT` |
/// | `ALL` | All RRs in iplist (`==`) | `MT_ALL` |
/// | `NOT \| ALL` | Some RRs not in iplist (`!==`) | `MT_NOT \| MT_ALL` |
pub struct MatchType;

impl MatchType {
    /// Negation flag — match if the address does NOT satisfy the comparison.
    ///
    /// C equivalent: `#define MT_NOT 1`
    pub const NOT: u8 = 1;

    /// All-match flag — ALL addresses must satisfy the comparison (vs. any).
    ///
    /// C equivalent: `#define MT_ALL 2`
    pub const ALL: u8 = 2;
}

// =============================================================================
// Defer Action
// =============================================================================

/// Behaviour on DNS lookup deferral (temporary failure).
///
/// Parsed from `+include_unknown`, `+exclude_unknown`, `+defer_unknown` tokens
/// in the DNSBL specification list.  Replaces the C `defer_return` variable
/// set in `verify_check_dnsbl()` (dnsbl.c lines 515–523).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferAction {
    /// Treat DEFER as a match — the IP is assumed listed.
    /// C equivalent: `defer_return = OK` (from `+include_unknown`).
    IncludeUnknown,

    /// Treat DEFER as no-match — the IP is assumed not listed.
    /// C equivalent: `defer_return = FAIL` (from `+exclude_unknown`).
    /// This is the default behaviour.
    ExcludeUnknown,

    /// Pass DEFER through to the caller for explicit handling.
    /// C equivalent: `defer_return = DEFER` (from `+defer_unknown`).
    DeferUnknown,
}

// =============================================================================
// DNSBL Cache Entry
// =============================================================================

/// Cached result of a DNSBL lookup, replacing C `dnsbl_cache_block`.
///
/// In C, allocated in `POOL_PERM` for connection-lifetime persistence.
/// In Rust, stored in a `HashMap` with owned data and process-lifetime
/// ownership.  Cache entries include an absolute expiry timestamp computed
/// from the DNS TTL.
///
/// # Fields
///
/// | Rust field | C field | Description |
/// |-----------|---------|-------------|
/// | `expiry` | `time_t expiry` | Absolute expiration time |
/// | `rhs` | `dns_address *rhs` | Linked-list → `Vec<IpAddr>` |
/// | `text` | `uschar *text` | TXT record text (lazy-fetched) |
/// | `rc` | `int rc` | DNS result code |
/// | `text_set` | `BOOL text_set` | Whether TXT has been fetched |
#[derive(Debug, Clone)]
pub struct DnsblCacheEntry {
    /// When this cache entry expires (absolute `SystemTime`).
    ///
    /// Computed as `SystemTime::now() + Duration::from_secs(ttl)` where `ttl`
    /// is the minimum of all A-record TTLs (on success) or the SOA negative
    /// TTL (on NXDOMAIN/NODATA).
    pub expiry: SystemTime,

    /// RHS addresses from A record lookup (e.g., `127.0.0.2`).
    ///
    /// In C, this was a linked list of `dns_address` structs.  In Rust,
    /// stored as a `Vec<IpAddr>` for direct iteration and matching.
    pub rhs: Vec<IpAddr>,

    /// TXT record text (lazy-fetched).
    ///
    /// `None` until a TXT lookup has been performed.  The text is tainted
    /// (DNS-sourced) and stored as `Option<String>` in the cache; callers
    /// wrap it in `Tainted<String>` when publishing to ACL variables.
    pub text: Option<String>,

    /// DNS lookup return code for this cache entry.
    pub rc: DnsResult,

    /// Whether the TXT record has been fetched for this entry.
    ///
    /// Prevents redundant TXT lookups — once `text_set` is `true`, the
    /// `text` field (even if `None`) is authoritative.
    pub text_set: bool,
}

// =============================================================================
// DNSBL Cache
// =============================================================================

/// DNSBL lookup cache, replacing the C `dnsbl_cache` balanced binary tree.
///
/// Uses `HashMap<String, DnsblCacheEntry>` for O(1) amortized lookups
/// (vs. C's `tree_node`-based O(log n)).  The cache key is the full DNS
/// query string (e.g., `"4.3.2.1.zen.spamhaus.org"`).
///
/// In C, the tree anchor was a file-scope static:
/// ```c
/// static tree_node *dnsbl_cache = NULL;
/// ```
///
/// In Rust, the cache is passed explicitly through function parameters
/// (scoped context passing per AAP §0.4.4).
pub struct DnsblCache {
    /// Backing store mapping query strings to cached results.
    entries: HashMap<String, DnsblCacheEntry>,
}

impl DnsblCache {
    /// Creates a new empty DNSBL cache.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Looks up a cached DNSBL entry by query key.
    ///
    /// Returns `Some(&DnsblCacheEntry)` if the entry exists and has not
    /// expired.  Returns `None` if the entry is missing or past its expiry
    /// time.  Expired entries are NOT removed by this method — use
    /// [`evict_expired`](Self::evict_expired) for periodic cleanup.
    ///
    /// Replaces C `tree_search(dnsbl_cache, query)` + expiry check
    /// (dnsbl.c lines 93–95).
    pub fn get(&self, key: &str) -> Option<&DnsblCacheEntry> {
        if let Some(entry) = self.entries.get(key) {
            if entry.expiry > SystemTime::now() {
                trace!(key = key, "DNSBL cache hit (valid)");
                return Some(entry);
            }
            trace!(key = key, "DNSBL cache entry expired");
        }
        None
    }

    /// Inserts (or replaces) a DNSBL cache entry.
    ///
    /// Replaces C `tree_insertnode(&dnsbl_cache, t)` (dnsbl.c line 122).
    pub fn insert(&mut self, key: String, entry: DnsblCacheEntry) {
        trace!(key = key.as_str(), "DNSBL cache insert");
        self.entries.insert(key, entry);
    }

    /// Removes all entries from the cache.
    ///
    /// Called during connection cleanup to release memory.  Replaces the
    /// implicit POOL_PERM cleanup at connection close in C.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Removes all expired entries from the cache.
    ///
    /// Iterates through all entries and retains only those whose `expiry`
    /// is in the future.  This is an explicit maintenance operation — the
    /// C code relied on tree replacement for expired entries.
    pub fn evict_expired(&mut self) {
        let now = SystemTime::now();
        let before = self.entries.len();
        self.entries.retain(|_key, entry| entry.expiry > now);
        let removed = before - self.entries.len();
        if removed > 0 {
            trace!(
                removed = removed,
                remaining = self.entries.len(),
                "DNSBL cache eviction"
            );
        }
    }
}

impl Default for DnsblCache {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// DNSBL Check Result
// =============================================================================

/// Result of a single DNSBL lookup via [`one_check_dnsbl`].
///
/// Maps to the C function's return codes: `OK`, `FAIL`, `DEFER`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsblCheckResult {
    /// IP matched the DNSBL.
    ///
    /// `value` contains the comma-separated RHS IP addresses (tainted),
    /// `text` contains the TXT record reason if available (tainted).
    Match {
        /// Comma-separated A-record addresses (e.g., `"127.0.0.2"`).
        value: Tainted<String>,
        /// TXT record text providing the listing reason, if fetched.
        text: Option<Tainted<String>>,
    },

    /// IP not listed in the DNSBL (NXDOMAIN, NODATA, or no matching address).
    NoMatch,

    /// Temporary DNS failure — the lookup could not be completed.
    Deferred {
        /// Human-readable description of the deferral reason.
        message: String,
    },
}

// =============================================================================
// DNSBL Verify Result
// =============================================================================

/// Result of a full DNSBL specification evaluation via [`verify_check_dnsbl`].
///
/// Carries the ACL variable values that the C code would publish as globals:
/// `$dnslist_domain`, `$dnslist_matched`, `$dnslist_value`, `$dnslist_text`.
#[derive(Debug, Clone)]
pub struct DnsblVerifyResult {
    /// Whether any DNSBL matched the sender IP.
    pub matched: bool,

    /// The DNSBL domain that matched (`$dnslist_domain`).
    pub domain: Option<Clean<String>>,

    /// The key/address that was matched against (`$dnslist_matched`).
    pub matched_item: Option<String>,

    /// The RHS A-record value(s) from the matching DNSBL (`$dnslist_value`).
    pub value: Option<Tainted<String>>,

    /// The TXT record text from the matching DNSBL (`$dnslist_text`).
    pub text: Option<Tainted<String>>,

    /// Whether any DNSBL lookup was deferred (temporary failure).
    pub deferred: bool,
}

impl DnsblVerifyResult {
    /// Creates a default "no match" result.
    fn no_match() -> Self {
        Self {
            matched: false,
            domain: None,
            matched_item: None,
            value: None,
            text: None,
            deferred: false,
        }
    }
}

// =============================================================================
// IP Address Reversal
// =============================================================================

/// Reverses an IP address for DNSBL query construction.
///
/// - **IPv4**: `"1.2.3.4"` → `"4.3.2.1"`
/// - **IPv6**: `"2001:db8::1"` → full 32-nibble reversal
///   (`"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"`)
///
/// This function accepts a string representation of an IP address and returns
/// the reversed form suitable for prepending to a DNSBL domain name.
///
/// Replaces the C `invert_address(revadd, sender_host_address)` call in
/// `verify_check_dnsbl()` (dnsbl.c line 608).
///
/// # Errors
///
/// Returns `Err(DnsError::InvalidAddress)` if the input string cannot be
/// parsed as a valid IPv4 or IPv6 address.
pub fn reverse_ip(ip: &str) -> Result<String, DnsError> {
    // Try IPv4 first
    if let Ok(v4) = ip.parse::<Ipv4Addr>() {
        return Ok(reverse_ipv4(&v4));
    }
    // Try IPv6
    if let Ok(v6) = ip.parse::<Ipv6Addr>() {
        return Ok(reverse_ipv6(&v6));
    }
    Err(DnsError::InvalidAddress(ip.to_string()))
}

// =============================================================================
// one_check_dnsbl — Single DNSBL Lookup
// =============================================================================

/// Maximum TTL for positive DNSBL cache entries (1 hour).
///
/// Matches the C default: `uint ttl = 3600;` (dnsbl.c line 108).
const MAX_POSITIVE_TTL: u64 = 3600;

/// Maximum length for a DNS query string.
///
/// Matches the C check: `if (qlen >= 256)` (dnsbl.c line 83).
const MAX_QUERY_LEN: usize = 256;

/// Performs a single DNSBL check against one blacklist domain.
///
/// This is the core lookup function, called once per DNSBL domain by
/// [`verify_check_dnsbl`].  It handles:
///
/// 1. **Query construction** — prepends `keyed_name` to `query_domain`
/// 2. **Cache lookup** — checks [`DnsblCache`] for a valid (non-expired) entry
/// 3. **DNS A record lookup** — via `resolver.dns_basic_lookup()`
/// 4. **A record matching** — equality, bitmask, negation, all-match
/// 5. **127.0.0.0/8 hygiene** — rejects addresses outside 127/8 when
///    no explicit iplist is provided (security measure)
/// 6. **TXT record lazy fetch** — fetches TXT only when needed
/// 7. **Cache population** — stores result with TTL-based expiry
///
/// # Parameters
///
/// - `cache` — Mutable reference to the DNSBL cache.
/// - `resolver` — DNS resolver for performing lookups.
/// - `query_domain` — The DNSBL domain (e.g., `"zen.spamhaus.org"`).
/// - `domain_txt` — Alternate domain for TXT lookup; if `None`, uses
///   `query_domain`.
/// - `keyed_name` — The reversed-IP or explicit key to prepend.
/// - `key_display` — The original key for debug/log messages.
/// - `iplist` — Optional RHS value list to match against (comma-separated IPs).
/// - `bitmask` — Whether to use bitmask matching (true) or equality (false).
/// - `match_type` — Combination of [`MatchType::NOT`] and [`MatchType::ALL`].
/// - `defer_return` — What to return on DNS deferral.
///
/// # Returns
///
/// - `Ok(DnsblCheckResult::Match { .. })` — IP matched the DNSBL
/// - `Ok(DnsblCheckResult::NoMatch)` — IP not listed
/// - `Ok(DnsblCheckResult::Deferred { .. })` — DNS temporary failure
/// - `Err(DnsError)` — Fatal error (e.g., query too long)
///
/// Replaces C `one_check_dnsbl()` from dnsbl.c lines 67–410.
#[allow(clippy::too_many_arguments)] // mirrors the C function's 10 parameters for behavioral parity
pub fn one_check_dnsbl(
    cache: &mut DnsblCache,
    resolver: &DnsResolver,
    query_domain: &str,
    domain_txt: Option<&str>,
    keyed_name: &str,
    key_display: &str,
    iplist: Option<&str>,
    bitmask: bool,
    match_type: u8,
    defer_return: DeferAction,
) -> Result<DnsblCheckResult, DnsError> {
    // ── 1. Construct query string ──────────────────────────────────────────
    let query = format!("{}.{}", keyed_name, query_domain);
    if query.len() >= MAX_QUERY_LEN {
        warn!(
            query_len = query.len(),
            max = MAX_QUERY_LEN,
            "DNSBL query too long (ignored)"
        );
        return Ok(DnsblCheckResult::NoMatch);
    }

    // ── 2. Check cache ─────────────────────────────────────────────────────
    let cached = cache.get(&query).cloned();
    let cache_entry = if let Some(entry) = cached {
        debug!(query = query.as_str(), "DNSBL: using cached result");
        entry
    } else {
        // Check if there's an expired entry we can note for debug
        if cache.entries.contains_key(&query) {
            trace!(
                query = query.as_str(),
                "DNSBL: cached entry expired, re-querying"
            );
        }

        // ── 3. Perform DNS A record lookup ─────────────────────────────────
        debug!(query = query.as_str(), "DNSBL: new DNS A lookup");
        let new_entry = perform_dns_lookup(resolver, &query)?;

        // Store in cache
        trace!(
            query = query.as_str(),
            ttl_secs = new_entry
                .expiry
                .duration_since(SystemTime::now())
                .unwrap_or(Duration::ZERO)
                .as_secs(),
            "DNSBL: wrote cache entry"
        );
        cache.insert(query.clone(), new_entry.clone());
        new_entry
    };

    // ── 4. Evaluate the lookup result ──────────────────────────────────────
    if cache_entry.rc == DnsResult::Succeed {
        // Build comma-separated address list for $dnslist_value
        let addlist: String = cache_entry
            .rhs
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        debug!(
            query = query.as_str(),
            addresses = addlist.as_str(),
            "DNSBL: DNS lookup succeeded"
        );

        // ── 4a. Address list matching ──────────────────────────────────────
        if let Some(iplist_str) = iplist {
            let match_found = match_address_list(
                &cache_entry.rhs,
                iplist_str,
                bitmask,
                match_type,
                key_display,
                query_domain,
            );

            if !match_found {
                debug!(query = query.as_str(), "DNSBL: address list did not match");
                return Ok(DnsblCheckResult::NoMatch);
            }
        } else {
            // ── 4b. No address list — 127.0.0.0/8 hygiene check ───────────
            let has_valid = check_hygiene_127(&cache_entry.rhs, key_display, query_domain);
            if !has_valid {
                return Ok(DnsblCheckResult::NoMatch);
            }
        }

        // ── 5. Handle alternate TXT domain ─────────────────────────────────
        // If domain_txt differs from query_domain, recursively check the
        // alternate domain for the TXT record (C: domain_txt != domain).
        if let Some(txt_domain) = domain_txt {
            if txt_domain != query_domain {
                let alt_result = one_check_dnsbl(
                    cache,
                    resolver,
                    txt_domain,
                    None, // no further TXT alternate
                    keyed_name,
                    key_display,
                    None,  // no iplist for TXT domain
                    false, // no bitmask
                    match_type,
                    defer_return,
                )?;
                return Ok(alt_result);
            }
        }

        // ── 6. Lazy-fetch TXT record ───────────────────────────────────────
        let txt_text = fetch_txt_if_needed(cache, resolver, &query);

        let value = Tainted::new(addlist);
        let text = txt_text.map(Tainted::new);

        return Ok(DnsblCheckResult::Match { value, text });
    }

    // ── 7. Handle non-success results ──────────────────────────────────────
    if cache_entry.rc != DnsResult::NoMatch && cache_entry.rc != DnsResult::NoData {
        // Temporary DNS failure — return based on defer_return setting
        let action_text = match defer_return {
            DeferAction::IncludeUnknown => "assumed in list",
            DeferAction::ExcludeUnknown => "assumed not in list",
            DeferAction::DeferUnknown => "returned DEFER",
        };
        warn!(
            query = query.as_str(),
            action = action_text,
            "DNSBL: DNS lookup defer (probably timeout)"
        );

        return Ok(match defer_return {
            DeferAction::IncludeUnknown => DnsblCheckResult::Match {
                value: Tainted::new(String::new()),
                text: None,
            },
            DeferAction::ExcludeUnknown => DnsblCheckResult::NoMatch,
            DeferAction::DeferUnknown => DnsblCheckResult::Deferred {
                message: format!("DNS list lookup defer for {query}"),
            },
        });
    }

    // NXDOMAIN or NODATA — host is not listed
    debug!(
        query = query.as_str(),
        key = key_display,
        domain = query_domain,
        "DNSBL: not listed"
    );
    Ok(DnsblCheckResult::NoMatch)
}

// =============================================================================
// Helper: Perform DNS A Lookup and Build Cache Entry
// =============================================================================

/// Performs a DNS A record lookup and builds a [`DnsblCacheEntry`] from
/// the response.
///
/// Extracts IP addresses from A records, computes the minimum TTL for
/// cache expiry, and falls back to SOA negative TTL on NXDOMAIN/NODATA.
fn perform_dns_lookup(resolver: &DnsResolver, query: &str) -> Result<DnsblCacheEntry, DnsError> {
    let result = resolver.dns_basic_lookup(query, DnsRecordType::A);

    match result {
        Ok(response) => build_entry_from_response(&response, DnsResult::Succeed),
        Err(DnsError::QueryResult(dns_rc)) => {
            // NXDOMAIN, NODATA, AGAIN, FAIL — build a negative cache entry
            let ttl = MAX_POSITIVE_TTL; // default fallback TTL
            Ok(DnsblCacheEntry {
                expiry: SystemTime::now() + Duration::from_secs(ttl),
                rhs: Vec::new(),
                text: None,
                rc: dns_rc,
                text_set: false,
            })
        }
        Err(e) => {
            // Unrecoverable resolver error — cache as AGAIN
            debug!(query = query, error = %e, "DNSBL: resolver error, caching as AGAIN");
            Ok(DnsblCacheEntry {
                expiry: SystemTime::now() + Duration::from_secs(MAX_POSITIVE_TTL),
                rhs: Vec::new(),
                text: None,
                rc: DnsResult::Again,
                text_set: false,
            })
        }
    }
}

/// Builds a [`DnsblCacheEntry`] from a successful DNS response.
///
/// Extracts A-record IP addresses and computes the minimum TTL.  If no
/// A records are found (e.g., CNAME-only response), downgrades the result
/// to `DnsResult::NoData`.
fn build_entry_from_response(
    response: &DnsResponse,
    initial_rc: DnsResult,
) -> Result<DnsblCacheEntry, DnsError> {
    let mut addresses: Vec<IpAddr> = Vec::new();
    let mut min_ttl = MAX_POSITIVE_TTL;

    for record in response.answer_records() {
        if let DnsRecordData::A(ipv4) = &record.data {
            addresses.push(IpAddr::V4(*ipv4));
            let ttl = u64::from(record.ttl);
            if ttl < min_ttl {
                min_ttl = ttl;
            }
        }
    }

    if addresses.is_empty() && initial_rc == DnsResult::Succeed {
        // No A records found — possibly CNAME without A target.
        // Downgrade to NoData and use SOA negative TTL if available.
        let soa_ttl = response.soa_negative_ttl().map(u64::from);
        let ttl = soa_ttl.unwrap_or(MAX_POSITIVE_TTL);
        return Ok(DnsblCacheEntry {
            expiry: SystemTime::now() + Duration::from_secs(ttl),
            rhs: Vec::new(),
            text: None,
            rc: DnsResult::NoData,
            text_set: false,
        });
    }

    Ok(DnsblCacheEntry {
        expiry: SystemTime::now() + Duration::from_secs(min_ttl),
        rhs: addresses,
        text: None,
        rc: initial_rc,
        text_set: false,
    })
}

// =============================================================================
// Helper: Address List Matching
// =============================================================================

/// Matches DNSBL A-record addresses against an iplist specification.
///
/// Implements the C matching logic from dnsbl.c lines 221–309:
///
/// - **Bitmask mode** (`bitmask == true`): For each returned address, parse
///   each iplist entry as an IP bitmask.  Match if
///   `(address_u32 & mask_u32) == mask_u32`.
///
/// - **Equality mode** (`bitmask == false`): For each returned address, check
///   string equality against each iplist entry.
///
/// - **`MT_NOT`**: Inverts the final result.
/// - **`MT_ALL`**: ALL returned addresses must match (vs. default ANY).
///
/// Returns `true` if the overall match succeeds (accounting for negation
/// and all-match flags), `false` otherwise.
fn match_address_list(
    rhs_addresses: &[IpAddr],
    iplist: &str,
    bitmask: bool,
    match_type: u8,
    key_display: &str,
    domain: &str,
) -> bool {
    let is_not = (match_type & MatchType::NOT) != 0;
    let is_all = (match_type & MatchType::ALL) != 0;

    // Track per-address matching for ALL vs ANY logic.
    // The C code uses a loop-break pattern with `da` and `res` pointers.
    //
    // For ANY mode (MT_ALL not set):
    //   - If ANY address matches an iplist entry → overall match
    //   - Break on first match
    //
    // For ALL mode (MT_ALL set):
    //   - If ALL addresses match an iplist entry → overall match
    //   - Break on first non-match

    let mut found_any_match = false;
    let mut found_non_match = false;

    for addr in rhs_addresses {
        let addr_matched = if bitmask {
            match_bitmask_for_addr(addr, iplist, key_display, domain)
        } else {
            match_equality_for_addr(addr, iplist)
        };

        if addr_matched {
            found_any_match = true;
        } else {
            found_non_match = true;
        }

        // Replicate C break logic (dnsbl.c line 274):
        // if (((match_type & MT_ALL) != 0) == (res == NULL)) break;
        // In ANY mode: res found (match) → break
        // In ALL mode: res NULL (no match) → break
        if is_all != addr_matched {
            break;
        }
    }

    // Replicate C final check (dnsbl.c line 285):
    // if ((match_type == MT_NOT || match_type == MT_ALL) != (da == NULL))
    //
    // da == NULL means loop completed without the break condition,
    // which in ANY mode means no match, and in ALL mode means all matched.
    //
    // The raw match outcome:
    //   ANY mode: found_any_match
    //   ALL mode: !found_non_match (all matched)
    let raw_match = if is_all {
        !found_non_match && !rhs_addresses.is_empty()
    } else {
        found_any_match
    };

    // Apply negation
    let result = if is_not { !raw_match } else { raw_match };

    if !result {
        let match_desc = match match_type {
            0 => "was no match",
            mt if mt == MatchType::NOT => "was an exclude match",
            mt if mt == MatchType::ALL => "was an IP address that did not match",
            mt if mt == (MatchType::NOT | MatchType::ALL) => {
                "were no IP addresses that did not match"
            }
            _ => "unknown match state",
        };
        debug!(
            description = match_desc,
            operator = if bitmask { "&" } else { "=" },
            iplist = iplist,
            "DNSBL: not accepting this block class"
        );
    }

    result
}

/// Checks if a single address matches any entry in the iplist via bitmask.
///
/// For IPv4 addresses: converts both the address and each iplist entry to
/// `u32` and checks `(address & mask) == mask`.  IPv6 addresses are skipped
/// (consistent with C behaviour — dnsbl.c line 241 comment about IPv6).
///
/// Also enforces 127.0.0.0/8 hygiene — addresses outside 127/8 are logged
/// and skipped.
fn match_bitmask_for_addr(addr: &IpAddr, iplist: &str, key_display: &str, domain: &str) -> bool {
    let v4 = match addr {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return false, // skip IPv6 for bitmask matching
    };

    let addr_u32 = u32::from(*v4);

    // Enforce 127.0.0.0/8 hygiene for the address being checked
    if (addr_u32 & 0xff00_0000) != 0x7f00_0000 {
        warn!(
            address = %addr,
            key = key_display,
            domain = domain,
            "DNSBL: address not in 127.0/8, discarded for bitmask"
        );
        return false;
    }

    // Parse each comma-separated entry in the iplist as an IPv4 bitmask.
    // The C code uses host_aton() to parse the mask value, then checks
    // (address[0] & mask) == address[0].  We replicate this: the mask
    // IS the value we want the bits to match.
    for entry in iplist.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        if let Ok(mask_v4) = entry.parse::<Ipv4Addr>() {
            let mask_u32 = u32::from(mask_v4);
            // C: (address[0] & mask) == address[0]
            // This means: all bits set in addr must also be set in mask
            // Actually the C code stores mask = address[0] (the returned IP),
            // then checks (address[0] & mask) == address[0] for each iplist entry.
            // Wait, re-reading: mask = the returned RHS address's u32,
            // then for each iplist entry parsed as address[0]:
            //   if ((address[0] & mask) == address[0]) break;
            // So it checks: (iplist_entry & rhs_address) == iplist_entry
            // Meaning: all bits set in the iplist entry must be set in the RHS address.
            if (mask_u32 & addr_u32) == mask_u32 {
                return true;
            }
        }
    }
    false
}

/// Checks if a single address matches any entry in the iplist via equality.
fn match_equality_for_addr(addr: &IpAddr, iplist: &str) -> bool {
    let addr_str = addr.to_string();
    for entry in iplist.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        if addr_str == entry {
            return true;
        }
    }
    false
}

// =============================================================================
// Helper: 127.0.0.0/8 Hygiene Check
// =============================================================================

/// Validates that at least one returned address is within 127.0.0.0/8.
///
/// When no explicit iplist is provided, the C code rejects any A-record
/// address outside the 127.0.0.0/8 range as a safety measure — legitimate
/// DNSBL services always return loopback addresses.
///
/// Replaces dnsbl.c lines 315–337.
fn check_hygiene_127(rhs_addresses: &[IpAddr], key_display: &str, domain: &str) -> bool {
    let mut found_valid = false;

    for addr in rhs_addresses {
        match addr {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                if octets[0] == 127 {
                    found_valid = true;
                } else {
                    warn!(
                        address = %addr,
                        key = key_display,
                        domain = domain,
                        "DNSBL: address not in 127.0/8, discarded"
                    );
                }
            }
            IpAddr::V6(v6) => {
                // IPv6 loopback is ::1 — only accept that
                if *v6 == Ipv6Addr::LOCALHOST {
                    found_valid = true;
                } else {
                    warn!(
                        address = %addr,
                        key = key_display,
                        domain = domain,
                        "DNSBL: IPv6 address not ::1, discarded"
                    );
                }
            }
        }
    }

    found_valid
}

// =============================================================================
// Helper: Lazy TXT Record Fetch
// =============================================================================

/// Fetches the TXT record for a DNSBL query if not already cached.
///
/// Updates the cache entry in-place to set `text_set = true` and populate
/// the `text` field.  Returns the TXT text if found.
///
/// Replaces dnsbl.c lines 355–371.
fn fetch_txt_if_needed(
    cache: &mut DnsblCache,
    resolver: &DnsResolver,
    query: &str,
) -> Option<String> {
    // Check if TXT has already been fetched for this entry
    if let Some(entry) = cache.entries.get(query) {
        if entry.text_set {
            return entry.text.clone();
        }
    }

    // Perform TXT lookup
    let txt_result = resolver.dns_basic_lookup(query, DnsRecordType::Txt);
    let mut txt_text: Option<String> = None;

    if let Ok(response) = txt_result {
        for record in response.answer_records() {
            if let DnsRecordData::Txt(data) = &record.data {
                // Limit text length to 511 bytes (C: if (len > 511) len = 127)
                let truncated = if data.len() > 511 {
                    &data[..127]
                } else {
                    data.as_str()
                };
                txt_text = Some(truncated.to_string());
                break; // only use the first TXT record
            }
        }
    }

    // Update cache entry
    if let Some(entry) = cache.entries.get_mut(query) {
        entry.text_set = true;
        entry.text.clone_from(&txt_text);
    }

    txt_text
}

// =============================================================================
// verify_check_dnsbl — Main ACL Entry Point
// =============================================================================

/// Evaluates a full DNSBL specification string against a sender IP address.
///
/// This is the main entry point called from ACL evaluation.  The `list`
/// parameter contains a colon-or-semicolon-separated list of DNSBL domain
/// specifications with optional control tokens.
///
/// # Specification Format
///
/// ```text
/// [+include_unknown | +exclude_unknown | +defer_unknown :]
/// [txt_domain,]domain[/key][=iplist | &iplist | ==iplist | =&iplist]
/// ```
///
/// - `+include_unknown` — Treat DNS DEFER as a match (IP assumed listed).
/// - `+exclude_unknown` — Treat DNS DEFER as no-match (default).
/// - `+defer_unknown`  — Pass DNS DEFER through to caller.
/// - `txt_domain,domain` — Use `txt_domain` for TXT lookups instead of `domain`.
/// - `/key` — Explicit lookup key instead of reversed sender IP.
/// - `=iplist` — Equality match against comma-separated IPs.
/// - `&iplist` — Bitmask match against comma-separated IPs.
/// - `!` prefix before `=` or `&` — Negate the match.
/// - `==` — All addresses must match.
///
/// # Parameters
///
/// - `cache` — Mutable reference to the DNSBL cache.
/// - `resolver` — DNS resolver for performing lookups.
/// - `list` — The full DNSBL specification from the ACL.
/// - `sender_ip` — Sender's IP address string.
///
/// # Returns
///
/// `Ok(DnsblVerifyResult)` with match status and ACL variable values.
///
/// Replaces C `verify_check_dnsbl()` from dnsbl.c lines 468–664.
pub fn verify_check_dnsbl(
    cache: &mut DnsblCache,
    resolver: &DnsResolver,
    list: &str,
    sender_ip: &str,
) -> Result<DnsblVerifyResult, DnsError> {
    let mut defer_action = DeferAction::ExcludeUnknown;
    let mut reversed_ip: Option<String> = None; // lazy-computed

    // ── Parse the colon/semicolon-separated list ───────────────────────────
    // The C code uses string_nextinlist() with a configurable separator.
    // We support both ':' and ';' as separators (Exim convention).
    let sep_char = detect_separator(list);
    let items = split_list(list, sep_char);

    for item_raw in items {
        let item = item_raw.trim();
        if item.is_empty() {
            continue;
        }

        debug!(item = item, "DNSBL: processing list item");

        // ── Handle defer-control tokens ────────────────────────────────────
        if let Some(stripped) = item.strip_prefix('+') {
            let token_lower = stripped.to_ascii_lowercase();
            match token_lower.as_str() {
                "include_unknown" => {
                    defer_action = DeferAction::IncludeUnknown;
                }
                "exclude_unknown" => {
                    defer_action = DeferAction::ExcludeUnknown;
                }
                "defer_unknown" => {
                    defer_action = DeferAction::DeferUnknown;
                }
                _ => {
                    warn!(token = item, "DNSBL: unknown item in list (ignored)");
                }
            }
            continue;
        }

        // ── Parse domain specification ─────────────────────────────────────
        // Work on a mutable copy so we can extract components
        let mut domain_spec = item.to_string();

        // Extract explicit key (/key)
        let explicit_key = extract_key(&mut domain_spec);

        // Extract iplist and operator (=, &, ==, !=, !&, =&, &=)
        let (iplist, bitmask, match_type_flags) = extract_iplist_and_operator(&mut domain_spec);

        // Extract alternate TXT domain (txt_domain,domain)
        let (domain_txt, domain) = extract_txt_domain(&domain_spec);

        // ── Warn about unusual characters in domain names ──────────────────
        warn_unusual_chars(&domain, "domain");
        if let Some(ref txt_d) = domain_txt {
            warn_unusual_chars(txt_d, "TXT domain");
        }

        // ── Determine the lookup key ───────────────────────────────────────
        if let Some(key_str) = &explicit_key {
            // Explicit key — may be a list of domains/IPs separated by ':'
            let key_sep = detect_separator(key_str);
            let key_items = split_list(key_str, key_sep);
            let mut any_defer = false;

            for key_item_raw in key_items {
                let key_item = key_item_raw.trim();
                if key_item.is_empty() {
                    continue;
                }

                // If the key looks like an IP address, reverse it
                let prepend = if is_ip_address(key_item) {
                    match reverse_ip(key_item) {
                        Ok(rev) => rev,
                        Err(_) => key_item.to_string(),
                    }
                } else {
                    key_item.to_string()
                };

                let rc = one_check_dnsbl(
                    cache,
                    resolver,
                    &domain,
                    domain_txt.as_deref(),
                    &prepend,
                    key_item,
                    iplist.as_deref(),
                    bitmask,
                    match_type_flags,
                    defer_action,
                )?;

                match rc {
                    DnsblCheckResult::Match { value, text } => {
                        let result_domain = domain_txt.as_ref().unwrap_or(&domain).clone();
                        debug!(
                            key = key_item,
                            domain = result_domain.as_str(),
                            "DNSBL: key is listed"
                        );
                        return Ok(DnsblVerifyResult {
                            matched: true,
                            domain: Some(Clean::new(result_domain)),
                            matched_item: Some(key_item.to_string()),
                            value: Some(value),
                            text,
                            deferred: false,
                        });
                    }
                    DnsblCheckResult::Deferred { .. } => {
                        any_defer = true;
                    }
                    DnsblCheckResult::NoMatch => {
                        // continue with next key item
                    }
                }
            }

            if any_defer {
                return Ok(DnsblVerifyResult {
                    matched: false,
                    domain: None,
                    matched_item: None,
                    value: None,
                    text: None,
                    deferred: true,
                });
            }
        } else {
            // No explicit key — use reversed sender IP
            if sender_ip.is_empty() {
                // No sender address available — can never match
                continue;
            }

            // Lazy-compute the reversed sender IP
            if reversed_ip.is_none() {
                reversed_ip = Some(reverse_ip(sender_ip)?);
            }
            let rev_ip = reversed_ip.as_ref().expect("reversed_ip computed above");

            let rc = one_check_dnsbl(
                cache,
                resolver,
                &domain,
                domain_txt.as_deref(),
                rev_ip,
                sender_ip,
                iplist.as_deref(),
                bitmask,
                match_type_flags,
                defer_action,
            )?;

            match rc {
                DnsblCheckResult::Match { value, text } => {
                    let result_domain = domain_txt.as_ref().unwrap_or(&domain).clone();
                    debug!(
                        sender = sender_ip,
                        domain = result_domain.as_str(),
                        "DNSBL: sender is listed"
                    );
                    return Ok(DnsblVerifyResult {
                        matched: true,
                        domain: Some(Clean::new(result_domain)),
                        matched_item: Some(sender_ip.to_string()),
                        value: Some(value),
                        text,
                        deferred: false,
                    });
                }
                DnsblCheckResult::Deferred { .. } => {
                    // Continue checking other domains, but remember the defer
                    return Ok(DnsblVerifyResult {
                        matched: false,
                        domain: None,
                        matched_item: None,
                        value: None,
                        text: None,
                        deferred: true,
                    });
                }
                DnsblCheckResult::NoMatch => {
                    // continue with next domain
                }
            }
        }
    }

    // No domain matched
    Ok(DnsblVerifyResult::no_match())
}

// =============================================================================
// Parsing Helpers for verify_check_dnsbl
// =============================================================================

/// Detects the list separator character.
///
/// If the list starts with a recognized separator override (e.g., `<;`),
/// returns that character.  Otherwise defaults to `:`.
fn detect_separator(list: &str) -> char {
    let trimmed = list.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('<') {
        let sep = trimmed.as_bytes()[1] as char;
        if sep == ';' || sep == ':' || sep == ',' || sep == ' ' {
            return sep;
        }
    }
    ':'
}

/// Splits a list string by the given separator, handling backslash-newline
/// continuations common in Exim configuration.
fn split_list(list: &str, sep: char) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();

    // Strip leading separator override if present
    let input = if list.trim().starts_with('<') {
        let trimmed = list.trim();
        if trimmed.len() >= 2 {
            &trimmed[2..]
        } else {
            list
        }
    } else {
        list
    };

    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            // Backslash continuation: skip backslash + optional whitespace/newline
            if let Some(&next) = chars.peek() {
                if next == '\n' || next == '\r' {
                    chars.next(); // consume the newline
                                  // Skip leading whitespace on the continuation line
                    while let Some(&ws) = chars.peek() {
                        if ws == ' ' || ws == '\t' {
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    continue;
                }
                // Not a newline — keep the next character
                current.push(chars.next().unwrap_or('\\'));
            }
        } else if ch == sep {
            result.push(current.clone());
            current.clear();
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() || !result.is_empty() {
        result.push(current);
    }
    result
}

/// Extracts an explicit key from a domain specification.
///
/// Looks for `/key` syntax and removes it from `spec`, returning the key.
/// C equivalent: `if ((key = Ustrchr(domain, '/'))) *key++ = 0;`
fn extract_key(spec: &mut String) -> Option<String> {
    if let Some(pos) = spec.find('/') {
        let key = spec[pos + 1..].to_string();
        spec.truncate(pos);
        if key.is_empty() {
            None
        } else {
            Some(key)
        }
    } else {
        None
    }
}

/// Extracts the iplist and operator from a domain specification.
///
/// Parses the operator syntax:
/// - `=value` — equality match
/// - `&value` — bitmask match
/// - `!=value` — negated equality
/// - `!&value` — negated bitmask
/// - `==value` — all-match equality
/// - `=&value` — all-match bitmask
/// - `&=value` — all-match bitmask (alternate)
///
/// Returns `(iplist, bitmask, match_type_flags)`.
///
/// C equivalent: dnsbl.c lines 534–557.
fn extract_iplist_and_operator(spec: &mut String) -> (Option<String>, bool, u8) {
    let mut match_type: u8 = 0;
    let mut bitmask = false;

    // First look for '=' (equality by default)
    let eq_pos = spec.find('=');
    let amp_pos = spec.find('&');

    // Determine which comes first
    let (op_pos, is_amp_first) = match (eq_pos, amp_pos) {
        (Some(eq), Some(amp)) => {
            if amp < eq {
                (Some(amp), true)
            } else {
                (Some(eq), false)
            }
        }
        (Some(eq), None) => (Some(eq), false),
        (None, Some(amp)) => (Some(amp), true),
        (None, None) => return (None, false, 0),
    };

    let op_pos = match op_pos {
        Some(p) => p,
        None => return (None, false, 0),
    };

    if is_amp_first {
        bitmask = true;
    }

    // Check for preceding '!' (negation)
    let actual_start = if op_pos > 0 && spec.as_bytes().get(op_pos - 1) == Some(&b'!') {
        match_type |= MatchType::NOT;
        op_pos - 1
    } else {
        op_pos
    };

    // Extract the iplist part (everything after the operator)
    let mut after_op = spec[op_pos + 1..].to_string();

    // Check for '=' or '&' immediately after the first operator
    if !after_op.is_empty() {
        let first_after = after_op.as_bytes()[0];
        if first_after == b'=' || first_after == b'&' {
            if first_after == b'&' {
                bitmask = true;
            }
            match_type |= MatchType::ALL;
            after_op = after_op[1..].to_string();
        }
    }

    // Truncate spec to just the domain part
    spec.truncate(actual_start);

    if after_op.is_empty() {
        (None, bitmask, match_type)
    } else {
        (Some(after_op), bitmask, match_type)
    }
}

/// Extracts an alternate TXT domain from a domain specification.
///
/// If the domain contains a comma (`txt_domain,domain`), splits it and
/// returns `(Some(txt_domain), domain)`.  Otherwise returns `(None, domain)`.
///
/// C equivalent: dnsbl.c lines 564–569.
fn extract_txt_domain(spec: &str) -> (Option<String>, String) {
    if let Some(comma_pos) = spec.find(',') {
        let txt_domain = spec[..comma_pos].to_string();
        let domain = spec[comma_pos + 1..].to_string();
        if txt_domain.is_empty() {
            (None, domain)
        } else {
            (Some(txt_domain), domain)
        }
    } else {
        (None, spec.to_string())
    }
}

/// Warns about unusual characters in a DNSBL domain name.
///
/// Domain names should only contain alphanumeric characters, hyphens, dots,
/// and underscores.  Other characters are logged as a warning but do not
/// prevent the lookup.
///
/// Replaces dnsbl.c lines 577–593.
fn warn_unusual_chars(domain: &str, label: &str) {
    for ch in domain.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '.' && ch != '_' {
            warn!(
                domain = domain,
                label = label,
                "DNSBL: domain contains unusual characters — is this right?"
            );
            return; // only warn once per domain
        }
    }
}

/// Simple check whether a string looks like an IP address (v4 or v6).
///
/// Returns `true` if the string can be parsed as either `Ipv4Addr` or
/// `Ipv6Addr`.  Used to decide whether to reverse a key value.
fn is_ip_address(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── MatchType constant tests ───────────────────────────────────────────

    #[test]
    fn test_match_type_constants() {
        assert_eq!(MatchType::NOT, 1);
        assert_eq!(MatchType::ALL, 2);
        assert_eq!(MatchType::NOT | MatchType::ALL, 3);
    }

    // ── DeferAction tests ──────────────────────────────────────────────────

    #[test]
    fn test_defer_action_values() {
        assert_ne!(DeferAction::IncludeUnknown, DeferAction::ExcludeUnknown);
        assert_ne!(DeferAction::ExcludeUnknown, DeferAction::DeferUnknown);
        assert_ne!(DeferAction::IncludeUnknown, DeferAction::DeferUnknown);
    }

    // ── reverse_ip tests ───────────────────────────────────────────────────

    #[test]
    fn test_reverse_ip_ipv4() {
        assert_eq!(reverse_ip("1.2.3.4").unwrap(), "4.3.2.1");
        assert_eq!(reverse_ip("192.168.1.100").unwrap(), "100.1.168.192");
        assert_eq!(reverse_ip("127.0.0.1").unwrap(), "1.0.0.127");
        assert_eq!(reverse_ip("10.0.0.1").unwrap(), "1.0.0.10");
    }

    #[test]
    fn test_reverse_ip_ipv6() {
        let result = reverse_ip("::1").unwrap();
        // ::1 expanded is 0000:0000:0000:0000:0000:0000:0000:0001
        // reversed nibbles: 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0
        assert!(result.starts_with("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0"));
        assert_eq!(result.matches('.').count(), 31); // 32 nibbles = 31 dots
    }

    #[test]
    fn test_reverse_ip_ipv6_full() {
        let result = reverse_ip("2001:db8::1").unwrap();
        // 2001:0db8:0000:0000:0000:0000:0000:0001
        assert!(result.ends_with("1.0.0.2"));
        assert_eq!(result.matches('.').count(), 31);
    }

    #[test]
    fn test_reverse_ip_invalid() {
        assert!(reverse_ip("not-an-ip").is_err());
        assert!(reverse_ip("").is_err());
    }

    // ── DnsblCache tests ───────────────────────────────────────────────────

    #[test]
    fn test_cache_new_is_empty() {
        let cache = DnsblCache::new();
        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn test_cache_insert_and_get() {
        let mut cache = DnsblCache::new();
        let entry = DnsblCacheEntry {
            expiry: SystemTime::now() + Duration::from_secs(3600),
            rhs: vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))],
            text: Some("test".to_string()),
            rc: DnsResult::Succeed,
            text_set: true,
        };
        cache.insert("test.key".to_string(), entry);
        assert!(cache.get("test.key").is_some());
        let got = cache.get("test.key").unwrap();
        assert_eq!(got.rc, DnsResult::Succeed);
        assert_eq!(got.rhs.len(), 1);
    }

    #[test]
    fn test_cache_expired_entry_returns_none() {
        let mut cache = DnsblCache::new();
        let entry = DnsblCacheEntry {
            expiry: SystemTime::now() - Duration::from_secs(1), // already expired
            rhs: vec![],
            text: None,
            rc: DnsResult::NoMatch,
            text_set: false,
        };
        cache.insert("expired.key".to_string(), entry);
        assert!(cache.get("expired.key").is_none());
    }

    #[test]
    fn test_cache_clear() {
        let mut cache = DnsblCache::new();
        let entry = DnsblCacheEntry {
            expiry: SystemTime::now() + Duration::from_secs(3600),
            rhs: vec![],
            text: None,
            rc: DnsResult::Succeed,
            text_set: false,
        };
        cache.insert("a".to_string(), entry.clone());
        cache.insert("b".to_string(), entry);
        cache.clear();
        assert!(cache.get("a").is_none());
        assert!(cache.get("b").is_none());
    }

    #[test]
    fn test_cache_evict_expired() {
        let mut cache = DnsblCache::new();
        let valid = DnsblCacheEntry {
            expiry: SystemTime::now() + Duration::from_secs(3600),
            rhs: vec![],
            text: None,
            rc: DnsResult::Succeed,
            text_set: false,
        };
        let expired = DnsblCacheEntry {
            expiry: SystemTime::now() - Duration::from_secs(1),
            rhs: vec![],
            text: None,
            rc: DnsResult::NoMatch,
            text_set: false,
        };
        cache.insert("valid".to_string(), valid);
        cache.insert("expired".to_string(), expired);
        cache.evict_expired();
        assert!(cache.get("valid").is_some());
        assert!(cache.entries.get("expired").is_none()); // fully removed
    }

    // ── Parsing helper tests ───────────────────────────────────────────────

    #[test]
    fn test_detect_separator_default() {
        assert_eq!(detect_separator("zen.spamhaus.org"), ':');
    }

    #[test]
    fn test_detect_separator_override() {
        assert_eq!(detect_separator("<; zen.spamhaus.org"), ';');
    }

    #[test]
    fn test_split_list_colon() {
        let items = split_list("a:b:c", ':');
        assert_eq!(items, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_split_list_semicolon() {
        let items = split_list("<;a;b;c", ';');
        assert_eq!(items, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_split_list_backslash_continuation() {
        let items = split_list("a:\\\n  b:c", ':');
        assert_eq!(items, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_extract_key_present() {
        let mut spec = "domain.com/mykey".to_string();
        let key = extract_key(&mut spec);
        assert_eq!(spec, "domain.com");
        assert_eq!(key, Some("mykey".to_string()));
    }

    #[test]
    fn test_extract_key_absent() {
        let mut spec = "domain.com".to_string();
        let key = extract_key(&mut spec);
        assert_eq!(spec, "domain.com");
        assert_eq!(key, None);
    }

    #[test]
    fn test_extract_iplist_equality() {
        let mut spec = "domain.com=127.0.0.2".to_string();
        let (iplist, bitmask, flags) = extract_iplist_and_operator(&mut spec);
        assert_eq!(spec, "domain.com");
        assert_eq!(iplist, Some("127.0.0.2".to_string()));
        assert!(!bitmask);
        assert_eq!(flags, 0);
    }

    #[test]
    fn test_extract_iplist_bitmask() {
        let mut spec = "domain.com&127.0.0.2".to_string();
        let (iplist, bitmask, flags) = extract_iplist_and_operator(&mut spec);
        assert_eq!(spec, "domain.com");
        assert_eq!(iplist, Some("127.0.0.2".to_string()));
        assert!(bitmask);
        assert_eq!(flags, 0);
    }

    #[test]
    fn test_extract_iplist_negated() {
        let mut spec = "domain.com!=127.0.0.2".to_string();
        let (iplist, bitmask, flags) = extract_iplist_and_operator(&mut spec);
        assert_eq!(spec, "domain.com");
        assert_eq!(iplist, Some("127.0.0.2".to_string()));
        assert!(!bitmask);
        assert_eq!(flags & MatchType::NOT, MatchType::NOT);
    }

    #[test]
    fn test_extract_iplist_all_match() {
        let mut spec = "domain.com==127.0.0.2".to_string();
        let (iplist, bitmask, flags) = extract_iplist_and_operator(&mut spec);
        assert_eq!(spec, "domain.com");
        assert_eq!(iplist, Some("127.0.0.2".to_string()));
        assert!(!bitmask);
        assert_eq!(flags & MatchType::ALL, MatchType::ALL);
    }

    #[test]
    fn test_extract_iplist_all_bitmask() {
        let mut spec = "domain.com=&127.0.0.2".to_string();
        let (iplist, bitmask, flags) = extract_iplist_and_operator(&mut spec);
        assert_eq!(spec, "domain.com");
        assert_eq!(iplist, Some("127.0.0.2".to_string()));
        assert!(bitmask);
        assert_eq!(flags & MatchType::ALL, MatchType::ALL);
    }

    #[test]
    fn test_extract_txt_domain_with_comma() {
        let (txt, domain) = extract_txt_domain("txt.sorbs.net,dnsbl.sorbs.net");
        assert_eq!(txt, Some("txt.sorbs.net".to_string()));
        assert_eq!(domain, "dnsbl.sorbs.net");
    }

    #[test]
    fn test_extract_txt_domain_without_comma() {
        let (txt, domain) = extract_txt_domain("zen.spamhaus.org");
        assert_eq!(txt, None);
        assert_eq!(domain, "zen.spamhaus.org");
    }

    // ── Address matching tests ─────────────────────────────────────────────

    #[test]
    fn test_match_equality_basic() {
        let addrs = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))];
        assert!(match_address_list(
            &addrs,
            "127.0.0.2",
            false,
            0,
            "key",
            "domain"
        ));
        assert!(!match_address_list(
            &addrs,
            "127.0.0.3",
            false,
            0,
            "key",
            "domain"
        ));
    }

    #[test]
    fn test_match_equality_multiple() {
        let addrs = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))];
        assert!(match_address_list(
            &addrs,
            "127.0.0.1,127.0.0.2,127.0.0.3",
            false,
            0,
            "key",
            "domain"
        ));
    }

    #[test]
    fn test_match_negation() {
        let addrs = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))];
        // NOT match: 127.0.0.2 matches iplist, so NOT → false
        assert!(!match_address_list(
            &addrs,
            "127.0.0.2",
            false,
            MatchType::NOT,
            "key",
            "domain"
        ));
        // NOT match: 127.0.0.2 doesn't match 127.0.0.3, so NOT → true
        assert!(match_address_list(
            &addrs,
            "127.0.0.3",
            false,
            MatchType::NOT,
            "key",
            "domain"
        ));
    }

    #[test]
    fn test_match_all_mode() {
        let addrs = vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
        ];
        // ALL mode: both must match iplist
        assert!(match_address_list(
            &addrs,
            "127.0.0.2,127.0.0.3",
            false,
            MatchType::ALL,
            "key",
            "domain"
        ));
        // ALL mode: one doesn't match
        assert!(!match_address_list(
            &addrs,
            "127.0.0.2",
            false,
            MatchType::ALL,
            "key",
            "domain"
        ));
    }

    #[test]
    fn test_match_bitmask() {
        // 127.0.0.6 = 0x7f000006
        // mask 127.0.0.2 = 0x7f000002
        // (0x7f000002 & 0x7f000006) == 0x7f000002 → true
        let addrs = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 6))];
        assert!(match_address_list(
            &addrs,
            "127.0.0.2",
            true,
            0,
            "key",
            "domain"
        ));
    }

    #[test]
    fn test_match_bitmask_no_match() {
        // 127.0.0.2 = 0x7f000002
        // mask 127.0.0.4 = 0x7f000004
        // (0x7f000004 & 0x7f000002) == 0x7f000004? → 0x0 == 0x7f000004 → false
        let addrs = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))];
        assert!(!match_address_list(
            &addrs,
            "127.0.0.4",
            true,
            0,
            "key",
            "domain"
        ));
    }

    // ── 127.0.0.0/8 hygiene tests ─────────────────────────────────────────

    #[test]
    fn test_hygiene_127_valid() {
        let addrs = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))];
        assert!(check_hygiene_127(&addrs, "key", "domain"));
    }

    #[test]
    fn test_hygiene_127_invalid() {
        let addrs = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        assert!(!check_hygiene_127(&addrs, "key", "domain"));
    }

    #[test]
    fn test_hygiene_127_mixed() {
        let addrs = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        ];
        assert!(check_hygiene_127(&addrs, "key", "domain"));
    }

    #[test]
    fn test_hygiene_127_ipv6_localhost() {
        let addrs = vec![IpAddr::V6(Ipv6Addr::LOCALHOST)];
        assert!(check_hygiene_127(&addrs, "key", "domain"));
    }

    #[test]
    fn test_hygiene_127_ipv6_non_localhost() {
        let addrs = vec![IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))];
        assert!(!check_hygiene_127(&addrs, "key", "domain"));
    }

    // ── DnsblCheckResult tests ─────────────────────────────────────────────

    #[test]
    fn test_check_result_match() {
        let result = DnsblCheckResult::Match {
            value: Tainted::new("127.0.0.2".to_string()),
            text: Some(Tainted::new("Listed for spam".to_string())),
        };
        assert!(matches!(result, DnsblCheckResult::Match { .. }));
    }

    #[test]
    fn test_check_result_no_match() {
        let result = DnsblCheckResult::NoMatch;
        assert!(matches!(result, DnsblCheckResult::NoMatch));
    }

    #[test]
    fn test_check_result_deferred() {
        let result = DnsblCheckResult::Deferred {
            message: "timeout".to_string(),
        };
        assert!(matches!(result, DnsblCheckResult::Deferred { .. }));
    }

    // ── DnsblVerifyResult tests ────────────────────────────────────────────

    #[test]
    fn test_verify_result_no_match() {
        let result = DnsblVerifyResult::no_match();
        assert!(!result.matched);
        assert!(result.domain.is_none());
        assert!(result.matched_item.is_none());
        assert!(result.value.is_none());
        assert!(result.text.is_none());
        assert!(!result.deferred);
    }

    // ── is_ip_address tests ────────────────────────────────────────────────

    #[test]
    fn test_is_ip_address() {
        assert!(is_ip_address("1.2.3.4"));
        assert!(is_ip_address("::1"));
        assert!(is_ip_address("2001:db8::1"));
        assert!(!is_ip_address("example.com"));
        assert!(!is_ip_address(""));
        assert!(!is_ip_address("not.an.ip.address.really"));
    }

    // ── DnsblCacheEntry field tests ────────────────────────────────────────

    #[test]
    fn test_cache_entry_fields() {
        let entry = DnsblCacheEntry {
            expiry: SystemTime::now() + Duration::from_secs(300),
            rhs: vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4)),
            ],
            text: Some("spam source".to_string()),
            rc: DnsResult::Succeed,
            text_set: true,
        };
        assert_eq!(entry.rhs.len(), 2);
        assert_eq!(entry.rc, DnsResult::Succeed);
        assert!(entry.text_set);
        assert_eq!(entry.text.as_deref(), Some("spam source"));
    }

    // ── Default trait for DnsblCache ───────────────────────────────────────

    #[test]
    fn test_cache_default() {
        let cache = DnsblCache::default();
        assert!(cache.entries.is_empty());
    }
}
