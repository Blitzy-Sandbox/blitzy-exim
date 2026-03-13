// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! Domain rewriting helper for router drivers.
//!
//! Translates **`src/src/routers/rf_change_domain.c`** (87 lines) into Rust.
//!
//! ## Overview
//!
//! When a router decides that an address should be re-routed with a different
//! domain (e.g., the `dnslookup` router canonicalizing a domain via MX lookup,
//! or any router performing domain rewriting), it calls [`change_domain()`].
//!
//! The function:
//!
//! 1. Creates a **child** [`AddressItem`] with the new domain, preserving the
//!    original local part.
//! 2. Copies all **propagating properties** from the parent to the child:
//!    `domain_data`, `localpart_data`, `errors_address`, `extra_headers`,
//!    `remove_headers`, and `ignore_error`.
//! 3. Establishes **parent–child linkage** so that bounce tracking and
//!    delivery journaling can trace back to the original address.
//! 4. Optionally **rewrites message headers** (e.g., `From:`, `To:`) to
//!    reflect the new domain, using the rewrite rules from the delivery
//!    context.
//! 5. Appends the child address to the `addr_new` vector for re-routing
//!    through the router chain.
//!
//! ## C Source Correspondence
//!
//! | C construct | Rust equivalent |
//! |---|---|
//! | `deliver_make_addr()` | [`AddressItem::new()`] |
//! | `address_item *parent = store_get(...)` | Parent remains as `&mut AddressItem` |
//! | `*parent = *addr; *addr = address_defaults; addr->prop = parent->prop;` | Clone + selective field copy |
//! | `addr->parent = parent; parent->child_count = 1;` | `child.parent_id`, `addr.child_count` |
//! | `if (rewrite) { ... rewrite_header(...) ... }` | `if rewrite { rewrite_headers(...) }` |
//! | `addr->next = *addr_new; *addr_new = addr;` | `addr_new.push(child)` |
//! | `DEBUG(D_route) debug_printf(...)` | `tracing::debug!(...)` |
//!
//! ## Safety
//!
//! This module contains **zero `unsafe` code** (per AAP §0.7.2).

// ── Imports ────────────────────────────────────────────────────────────────

// ---------------------------------------------------------------------------
// Address Types (defined locally due to circular dependency constraint)
// ---------------------------------------------------------------------------
//
// The canonical `AddressItem` and `DeliveryContext` live in
// `exim-core/src/context.rs`, but `exim-core` depends on `exim-routers`,
// so importing from `exim-core` would create a circular dependency.
//
// These local type definitions mirror the fields used by `change_domain()`
// and are the authoritative types within the `exim-routers` crate.  When
// a shared-types crate is introduced in the future, these should be
// replaced with re-exports from that crate.
// ---------------------------------------------------------------------------

/// A single header line from a message.
///
/// Mirrors `exim-core::context::HeaderLine`.  Used in
/// [`AddressProperties::extra_headers`] for headers propagated from parent
/// to child addresses during domain rewriting.
#[derive(Debug, Clone)]
pub struct HeaderLine {
    /// The complete header text including name, colon, value, and trailing
    /// newline (matches C `header_line.text`).
    pub text: String,

    /// Length of the header text in bytes.
    pub slen: usize,

    /// Classification of this header line.
    pub htype: HeaderType,
}

impl HeaderLine {
    /// Create a new header line from raw text with explicit classification.
    pub fn new(text: String, htype: HeaderType) -> Self {
        let slen = text.len();
        Self { text, slen, htype }
    }
}

/// Classification of an RFC 5322 header line.
///
/// Mirrors `exim-core::context::HeaderType`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum HeaderType {
    /// `From:` header.
    From,
    /// `To:` header.
    To,
    /// `Cc:` header.
    Cc,
    /// `Bcc:` header.
    Bcc,
    /// `Subject:` header.
    Subject,
    /// `Reply-To:` header.
    ReplyTo,
    /// `Message-ID:` header.
    MessageId,
    /// `Date:` header.
    Date,
    /// `Received:` header.
    Received,
    /// `Content-Type:` header.
    ContentType,
    /// `MIME-Version:` header.
    MimeVersion,
    /// Any other header not explicitly classified.
    #[default]
    Other,
    /// Header that has been superseded by a rewritten version.
    Old,
    /// Header that has been logically removed (not emitted on output).
    Deleted,
}

/// Propagated address item properties.
///
/// Mirrors `exim-core::context::AddressProperties` with additional fields
/// required by the C `address_item_propagated` struct that are needed for
/// faithful translation of `rf_change_domain.c`.
///
/// These properties travel with the address as it moves through the router
/// and transport chain, and are copied from parent to child when
/// [`change_domain()`] creates a new child address.
#[derive(Debug, Clone, Default)]
pub struct AddressProperties {
    /// Data from the router's domain expansion (`$domain_data`).
    /// Replaces C `address_item_propagated.domain_data`.
    pub domain_data: Option<String>,

    /// Data from the router's local-part expansion (`$local_part_data`).
    /// Replaces C `address_item_propagated.localpart_data`.
    pub localpart_data: Option<String>,

    /// Override errors-to address for this delivery.
    /// Replaces C `address_item_propagated.errors_address`.
    pub errors_address: Option<String>,

    /// Extra headers to add for this delivery.
    /// Replaces C `address_item_propagated.extra_headers`.
    pub extra_headers: Vec<HeaderLine>,

    /// Headers to remove for this delivery (comma-separated names).
    /// Replaces C `address_item_propagated.remove_headers`.
    pub remove_headers: Option<String>,

    /// Whether to ignore delivery errors for this address.
    /// Replaces C `address_item_propagated.ignore_error`.
    pub ignore_error: bool,
}

/// A delivery address being processed through the router and transport chain.
///
/// Mirrors `exim-core::context::AddressItem` — defined locally to avoid a
/// circular dependency between `exim-routers` and `exim-core`.
///
/// Each `AddressItem` tracks the full lifecycle of an address from initial
/// receipt through routing, transport selection, and delivery result.
#[derive(Debug, Clone)]
pub struct AddressItem {
    /// The email address being delivered (may be rewritten during routing).
    pub address: String,

    /// Local part of the address (before the `@`).
    pub local_part: String,

    /// Domain part of the address (after the `@`).
    pub domain: String,

    /// Unique identifier for this address item (used for deduplication).
    /// Typically the original address before any rewriting.
    pub unique: String,

    /// Identifier of the parent address that generated this one.
    /// `None` for original envelope recipients.  Set to
    /// `Some(parent.unique.clone())` by [`change_domain()`] to establish
    /// parent–child linkage without raw pointers.
    pub parent_id: Option<String>,

    /// Number of child addresses generated from this one.
    pub child_count: i32,

    /// Propagated properties (errors address, extra headers, etc.).
    pub prop: AddressProperties,

    /// UID for local delivery (from router or transport configuration).
    /// -1 indicates "not set" (matching C default).
    pub uid: i32,

    /// GID for local delivery (from router or transport configuration).
    /// -1 indicates "not set" (matching C default).
    pub gid: i32,

    /// Address flags bitfield (af_* constants from the C codebase).
    pub flags: u32,

    /// Result message from delivery attempt (success or failure text).
    pub message: Option<String>,

    /// Special action code for this address (freeze, queue, fail, etc.).
    pub special_action: i32,

    /// Home directory for the delivery user.
    pub home_dir: Option<String>,

    /// Current working directory for the delivery process.
    pub current_dir: Option<String>,

    /// List of hosts for remote delivery.
    pub host_list: Vec<String>,

    /// Fallback host list used when the primary host list is exhausted.
    pub fallback_hosts: Vec<String>,

    /// Name of the transport to use for this address.
    pub transport: Option<String>,
}

impl AddressItem {
    /// Create a new `AddressItem` with the given full email address.
    ///
    /// The local part and domain are extracted from the address string.
    /// All other fields are initialized to safe defaults matching the C
    /// `address_defaults` initialization in `globals.c`.
    pub fn new(address: String) -> Self {
        let (local_part, domain) = if let Some(at_pos) = address.rfind('@') {
            (
                address[..at_pos].to_string(),
                address[at_pos + 1..].to_string(),
            )
        } else {
            (address.clone(), String::new())
        };
        let unique = address.clone();
        Self {
            address,
            local_part,
            domain,
            unique,
            parent_id: None,
            child_count: 0,
            prop: AddressProperties::default(),
            uid: -1,
            gid: -1,
            flags: 0,
            message: None,
            special_action: 0,
            home_dir: None,
            current_dir: None,
            host_list: Vec::new(),
            fallback_hosts: Vec::new(),
            transport: None,
        }
    }

    /// Get the unique identity of this address item.
    ///
    /// Returns the `unique` field which serves as the deduplication key
    /// for this address within a message's delivery attempt.
    pub fn id(&self) -> &str {
        &self.unique
    }
}

/// Rewrite rules for a single domain mapping.
///
/// Replaces the C `rewrite_rule` struct used by `rewrite_header()` in
/// `rf_change_domain.c` lines 72–83.
#[derive(Debug, Clone)]
pub struct RewriteRule {
    /// Pattern to match (original domain).
    pub pattern: String,
    /// Replacement domain.
    pub replacement: String,
    /// Rewrite flags controlling which headers to rewrite.
    pub flags: u32,
}

/// Per-delivery-attempt state passed through the call chain.
///
/// Mirrors `exim-core::context::DeliveryContext` with the subset of fields
/// needed by [`change_domain()`] for optional header rewriting.
///
/// In the C source, header rewriting accesses the globals `header_list`,
/// `global_rewrite_rules`, and `rewrite_existflags`.  In Rust these are
/// encapsulated in the delivery context passed explicitly.
#[derive(Debug, Default)]
pub struct DeliveryContext {
    /// Message headers (mutable for in-place rewriting).
    /// Replaces C global `header_list`.
    pub header_list: Vec<HeaderLine>,

    /// Global rewrite rules loaded from the configuration.
    /// Replaces C global `global_rewrite_rules`.
    pub rewrite_rules: Vec<RewriteRule>,

    /// Bitmask indicating which rewrite rule types exist.
    /// Replaces C global `rewrite_existflags`.
    pub rewrite_existflags: u32,

    /// Flag set to `true` when any header has been rewritten during
    /// domain change processing.
    /// Replaces C flag `f.header_rewritten`.
    pub header_rewritten: bool,

    // -- Delivery state fields (subset needed by helpers) --
    /// Local part of the current delivery address.
    pub deliver_localpart: Option<String>,

    /// Domain of the current delivery address.
    pub deliver_domain: Option<String>,

    /// Original local part before any rewriting.
    pub deliver_localpart_orig: Option<String>,

    /// Original domain before any rewriting.
    pub deliver_domain_orig: Option<String>,

    /// Delivery host name for remote delivery.
    pub deliver_host: Option<String>,

    /// Delivery host IP address.
    pub deliver_host_address: Option<String>,

    /// Delivery host port.
    pub deliver_host_port: u16,

    /// Name of the transport being used.
    pub transport_name: Option<String>,

    /// Name of the router that handled this address.
    pub router_name: Option<String>,

    /// Whether the message is frozen.
    pub deliver_freeze: bool,

    /// Force delivery even if frozen.
    pub deliver_force: bool,

    // -- Address data variables (set by routers, used by queue_add) --
    /// Data from router's domain expansion (C: deliver_domain_data).
    /// Set by the router that processed the address, then copied into
    /// `AddressProperties.domain_data` by `queue_add()`.
    pub deliver_domain_data: Option<String>,

    /// Data from router's local-part expansion (C: deliver_localpart_data).
    /// Set by the router that processed the address, then copied into
    /// `AddressProperties.localpart_data` by `queue_add()`.
    pub deliver_localpart_data: Option<String>,

    /// Default home directory for local deliveries (C: deliver_home).
    /// Used as a fallback by `queue_add()` when neither the passwd entry
    /// nor the router configuration provides a home directory.
    pub deliver_home: Option<String>,

    /// Counter of remote delivery addresses queued (C: remote_delivery_count).
    /// Incremented by `queue_add()` each time an address is queued for
    /// remote transport delivery.
    pub remote_delivery_count: u32,
}

// ── Header Rewriting Implementation ────────────────────────────────────────

/// Rewrite message headers to reflect a domain change.
///
/// Iterates over the headers in `ctx.header_list` and applies the global
/// rewrite rules to replace occurrences of `old_domain` with `new_domain`
/// in address-bearing headers (From, To, Cc, Bcc, Reply-To, Sender).
///
/// This translates the C header rewriting loop from `rf_change_domain.c`
/// lines 69–83:
///
/// ```c
/// for (header_line * h = header_list; h != NULL; h = h->next)
///   {
///   header_line *newh =
///     rewrite_header(h, parent->domain, domain,
///       global_rewrite_rules, rewrite_existflags, TRUE);
///   if (newh) { h = newh; f.header_rewritten = TRUE; }
///   }
/// ```
///
/// # Arguments
///
/// * `old_domain` — The original domain being replaced (from the parent
///   address).
/// * `new_domain` — The new domain that replaces the old one.
/// * `ctx` — Mutable reference to the delivery context containing the
///   header list and rewrite rules.
fn rewrite_headers(old_domain: &str, new_domain: &str, ctx: &mut DeliveryContext) {
    tracing::debug!(
        old_domain = %old_domain,
        new_domain = %new_domain,
        "rewriting header lines for domain change"
    );

    // If there are no rewrite rules or no exist-flags set, nothing to do.
    if ctx.rewrite_rules.is_empty() || ctx.rewrite_existflags == 0 {
        return;
    }

    let mut any_rewritten = false;

    for header in &mut ctx.header_list {
        // Only rewrite address-bearing headers.
        if !is_address_header(&header.htype) {
            continue;
        }

        // Check each rewrite rule against this header's text.
        let mut rewritten_text = header.text.clone();
        let mut was_modified = false;

        for rule in &ctx.rewrite_rules {
            // Simple domain substitution in the header text:
            // Replace occurrences of old_domain with new_domain where
            // they appear in an address context (after '@').
            if rewritten_text.contains(old_domain) {
                rewritten_text =
                    rewritten_text.replace(&format!("@{old_domain}"), &format!("@{new_domain}"));
                was_modified = true;
            }

            // Also check the rule's pattern for domain-level matches.
            if rule.pattern == old_domain || rule.pattern == "*" {
                let before = rewritten_text.clone();
                rewritten_text = rewritten_text
                    .replace(&format!("@{old_domain}"), &format!("@{}", rule.replacement));
                if rewritten_text != before {
                    was_modified = true;
                }
            }
        }

        if was_modified {
            let old_header = header.clone();
            header.text = rewritten_text;
            header.slen = header.text.len();
            // Mark the old header as superseded.
            // In C, a new header_line is inserted and the old one is
            // marked with type htype_old.  In Rust, we modify in place
            // and track the change via any_rewritten.
            let _ = old_header; // consumed — logging only
            any_rewritten = true;
        }
    }

    if any_rewritten {
        ctx.header_rewritten = true;
        tracing::debug!("headers rewritten after domain change");
    }
}

/// Returns `true` for header types that can contain email addresses and
/// are candidates for domain rewriting.
///
/// Corresponds to the C `rewrite_header()` check that only processes
/// address-bearing headers: From, To, Cc, Bcc, Reply-To.
fn is_address_header(htype: &HeaderType) -> bool {
    matches!(
        htype,
        HeaderType::From | HeaderType::To | HeaderType::Cc | HeaderType::Bcc | HeaderType::ReplyTo
    )
}

// ═══════════════════════════════════════════════════════════════════════════
//  change_domain — Primary Public API
// ═══════════════════════════════════════════════════════════════════════════

/// Rewrites the domain part of an address, creating a child address.
///
/// Translates **C `rf_change_domain()`** from `rf_change_domain.c` (87 lines).
///
/// Creates a new child address with `new_domain`, preserving the original
/// local part.  All six propagating properties are copied from the parent
/// to the child.  The parent–child linkage is established via the parent's
/// unique ID.  If `rewrite` is `true`, message headers are rewritten to
/// reflect the domain change.  The child address is appended to `addr_new`
/// for re-routing through the router chain.
///
/// # Arguments
///
/// * `addr` — The parent address whose domain is being changed.  Its
///   `child_count` is incremented.
/// * `new_domain` — The new domain to assign to the child address.
/// * `rewrite` — If `true`, message headers (From, To, Cc, etc.) are
///   rewritten to replace the old domain with the new domain.
/// * `addr_new` — The address list to which the new child address is
///   appended.  The child will be re-routed through the router chain.
/// * `ctx` — Mutable delivery context providing access to the header list
///   and rewrite rules for optional header rewriting.
///
/// # C Correspondence
///
/// ```c
/// void rf_change_domain(address_item *addr, const uschar *domain,
///                        BOOL rewrite, address_item **addr_new)
/// ```
///
/// # Example
///
/// ```rust,ignore
/// use exim_routers::helpers::change_domain::{
///     AddressItem, DeliveryContext, change_domain,
/// };
///
/// let mut parent = AddressItem::new("user@old.example.com".to_string());
/// let mut addr_new: Vec<AddressItem> = Vec::new();
/// let mut ctx = DeliveryContext::default();
///
/// change_domain(&mut parent, "new.example.com", false, &mut addr_new, &mut ctx);
///
/// assert_eq!(addr_new.len(), 1);
/// assert_eq!(addr_new[0].address, "user@new.example.com");
/// assert_eq!(addr_new[0].local_part, "user");
/// assert_eq!(addr_new[0].domain, "new.example.com");
/// assert_eq!(parent.child_count, 1);
/// ```
pub fn change_domain(
    addr: &mut AddressItem,
    new_domain: &str,
    rewrite: bool,
    addr_new: &mut Vec<AddressItem>,
    ctx: &mut DeliveryContext,
) {
    // --- Step 1: Build the new full address ---
    //
    // In C (line 42–43):
    //   const uschar *at = Ustrrchr(addr->address, '@');
    //   uschar *address = string_sprintf("%.*s@%s",
    //       (int)(at - addr->address), addr->address, domain);
    //
    // We extract the local part from the current address (preserving any
    // quoting and case from the external form) and append @new_domain.
    let local_part_external = extract_local_part(&addr.address);
    let new_address = format!("{local_part_external}@{new_domain}");

    tracing::debug!(
        original_address = %addr.address,
        new_domain = %new_domain,
        new_address = %new_address,
        "domain changed"
    );

    // --- Step 2: Create child address ---
    //
    // C (line 56): *addr = address_defaults;
    // Then overwrite fields.  In Rust we create a fresh AddressItem.
    let mut child = AddressItem::new(new_address.clone());

    // Ensure the local part on the child matches the parent's local part
    // (the `new()` constructor already extracts it, but we use the same
    // external form the parent had).
    child.local_part = local_part_external.to_string();
    child.domain = new_domain.to_string();
    child.unique = new_address;

    // --- Step 3: Copy propagating properties (all 6 fields) ---
    //
    // C (line 57): addr->prop = parent->prop;
    // In the C code the entire prop struct is bulk-copied.  We replicate
    // this by cloning each of the 6 propagating fields explicitly.
    child.prop.domain_data = addr.prop.domain_data.clone();
    child.prop.localpart_data = addr.prop.localpart_data.clone();
    child.prop.errors_address = addr.prop.errors_address.clone();
    child.prop.extra_headers = addr.prop.extra_headers.clone();
    child.prop.remove_headers = addr.prop.remove_headers.clone();
    child.prop.ignore_error = addr.prop.ignore_error;

    // --- Step 4: Parent–child linkage ---
    //
    // C (line 61): addr->parent = parent;
    //    (line 62): parent->child_count = 1;
    //
    // In Rust we store the parent's unique ID string instead of a raw
    // pointer.  This allows bounce tracking and delivery journaling to
    // trace back to the original address.
    child.parent_id = Some(addr.id().to_string());
    addr.child_count += 1;

    // --- Step 5: Optional header rewriting ---
    //
    // C (lines 69–83):
    //   if (rewrite) { ... rewrite_header(h, parent->domain, domain, ...) ... }
    if rewrite {
        let old_domain = addr.domain.clone();
        rewrite_headers(&old_domain, new_domain, ctx);
    }

    // --- Step 6: Append child to addr_new ---
    //
    // C (lines 64–65):
    //   addr->next = *addr_new;
    //   *addr_new = addr;
    //
    // The C code prepends to the linked list.  In Rust with a Vec, we
    // append (callers iterate in order; insertion order is preserved).
    addr_new.push(child);
}

// ── Private Helpers ────────────────────────────────────────────────────────

/// Extract the local part from a full email address string.
///
/// Mirrors the C logic (line 41–43):
/// ```c
/// const uschar *at = Ustrrchr(addr->address, '@');
/// // local part = addr->address[0..at]
/// ```
///
/// If the address contains no `@`, the entire string is treated as the
/// local part (matching C behavior for unqualified addresses).
fn extract_local_part(address: &str) -> &str {
    match address.rfind('@') {
        Some(pos) => &address[..pos],
        None => address,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Unit Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // -- AddressItem::new tests --

    #[test]
    fn test_address_item_new_splits_correctly() {
        let addr = AddressItem::new("user@example.com".to_string());
        assert_eq!(addr.local_part, "user");
        assert_eq!(addr.domain, "example.com");
        assert_eq!(addr.address, "user@example.com");
        assert_eq!(addr.unique, "user@example.com");
        assert!(addr.parent_id.is_none());
        assert_eq!(addr.child_count, 0);
        assert_eq!(addr.uid, -1);
        assert_eq!(addr.gid, -1);
    }

    #[test]
    fn test_address_item_new_no_at() {
        let addr = AddressItem::new("localonly".to_string());
        assert_eq!(addr.local_part, "localonly");
        assert_eq!(addr.domain, "");
    }

    #[test]
    fn test_address_item_id() {
        let addr = AddressItem::new("test@domain.com".to_string());
        assert_eq!(addr.id(), "test@domain.com");
    }

    // -- extract_local_part tests --

    #[test]
    fn test_extract_local_part_normal() {
        assert_eq!(extract_local_part("user@example.com"), "user");
    }

    #[test]
    fn test_extract_local_part_no_at() {
        assert_eq!(extract_local_part("localonly"), "localonly");
    }

    #[test]
    fn test_extract_local_part_multiple_at() {
        // rfind('@') returns the LAST '@', matching C Ustrrchr behavior.
        assert_eq!(extract_local_part("user@first@second.com"), "user@first");
    }

    // -- change_domain tests --

    #[test]
    fn test_change_domain_basic() {
        let mut parent = AddressItem::new("alice@old.example.com".to_string());
        let mut addr_new: Vec<AddressItem> = Vec::new();
        let mut ctx = DeliveryContext::default();

        change_domain(
            &mut parent,
            "new.example.com",
            false,
            &mut addr_new,
            &mut ctx,
        );

        assert_eq!(addr_new.len(), 1);
        let child = &addr_new[0];
        assert_eq!(child.address, "alice@new.example.com");
        assert_eq!(child.local_part, "alice");
        assert_eq!(child.domain, "new.example.com");
        assert_eq!(child.unique, "alice@new.example.com");
    }

    #[test]
    fn test_change_domain_parent_child_linkage() {
        let mut parent = AddressItem::new("bob@old.example.com".to_string());
        let mut addr_new: Vec<AddressItem> = Vec::new();
        let mut ctx = DeliveryContext::default();

        change_domain(
            &mut parent,
            "new.example.com",
            false,
            &mut addr_new,
            &mut ctx,
        );

        // Parent's child_count should be incremented.
        assert_eq!(parent.child_count, 1);

        // Child should reference parent by unique ID.
        let child = &addr_new[0];
        assert_eq!(child.parent_id.as_deref(), Some("bob@old.example.com"));
    }

    #[test]
    fn test_change_domain_propagating_properties() {
        let mut parent = AddressItem::new("carol@old.example.com".to_string());

        // Set all 6 propagating properties on the parent.
        parent.prop.domain_data = Some("domain-data-value".to_string());
        parent.prop.localpart_data = Some("localpart-data-value".to_string());
        parent.prop.errors_address = Some("errors@example.com".to_string());
        parent.prop.extra_headers = vec![HeaderLine::new(
            "X-Extra: test\n".to_string(),
            HeaderType::Other,
        )];
        parent.prop.remove_headers = Some("X-Remove".to_string());
        parent.prop.ignore_error = true;

        let mut addr_new: Vec<AddressItem> = Vec::new();
        let mut ctx = DeliveryContext::default();

        change_domain(
            &mut parent,
            "new.example.com",
            false,
            &mut addr_new,
            &mut ctx,
        );

        let child = &addr_new[0];
        assert_eq!(child.prop.domain_data.as_deref(), Some("domain-data-value"));
        assert_eq!(
            child.prop.localpart_data.as_deref(),
            Some("localpart-data-value")
        );
        assert_eq!(
            child.prop.errors_address.as_deref(),
            Some("errors@example.com")
        );
        assert_eq!(child.prop.extra_headers.len(), 1);
        assert_eq!(child.prop.extra_headers[0].text, "X-Extra: test\n");
        assert_eq!(child.prop.remove_headers.as_deref(), Some("X-Remove"));
        assert!(child.prop.ignore_error);
    }

    #[test]
    fn test_change_domain_no_rewrite() {
        let mut parent = AddressItem::new("dave@old.example.com".to_string());
        let mut addr_new: Vec<AddressItem> = Vec::new();
        let mut ctx = DeliveryContext::default();
        ctx.header_list.push(HeaderLine::new(
            "From: dave@old.example.com\n".to_string(),
            HeaderType::From,
        ));

        change_domain(
            &mut parent,
            "new.example.com",
            false, // rewrite = false
            &mut addr_new,
            &mut ctx,
        );

        // Headers should NOT be modified when rewrite is false.
        assert_eq!(ctx.header_list[0].text, "From: dave@old.example.com\n");
        assert!(!ctx.header_rewritten);
    }

    #[test]
    fn test_change_domain_with_rewrite() {
        let mut parent = AddressItem::new("eve@old.example.com".to_string());
        parent.domain = "old.example.com".to_string();

        let mut addr_new: Vec<AddressItem> = Vec::new();
        let mut ctx = DeliveryContext::default();
        ctx.header_list.push(HeaderLine::new(
            "From: eve@old.example.com\n".to_string(),
            HeaderType::From,
        ));
        ctx.rewrite_existflags = 1; // Non-zero so rewriting is attempted.
        ctx.rewrite_rules.push(RewriteRule {
            pattern: "old.example.com".to_string(),
            replacement: "new.example.com".to_string(),
            flags: 1,
        });

        change_domain(
            &mut parent,
            "new.example.com",
            true, // rewrite = true
            &mut addr_new,
            &mut ctx,
        );

        // Headers SHOULD be modified when rewrite is true.
        assert_eq!(ctx.header_list[0].text, "From: eve@new.example.com\n");
        assert!(ctx.header_rewritten);
    }

    #[test]
    fn test_change_domain_multiple_calls() {
        let mut parent = AddressItem::new("frank@old.example.com".to_string());
        let mut addr_new: Vec<AddressItem> = Vec::new();
        let mut ctx = DeliveryContext::default();

        change_domain(
            &mut parent,
            "first.example.com",
            false,
            &mut addr_new,
            &mut ctx,
        );
        change_domain(
            &mut parent,
            "second.example.com",
            false,
            &mut addr_new,
            &mut ctx,
        );

        assert_eq!(addr_new.len(), 2);
        assert_eq!(addr_new[0].address, "frank@first.example.com");
        assert_eq!(addr_new[1].address, "frank@second.example.com");
        assert_eq!(parent.child_count, 2);
    }

    #[test]
    fn test_change_domain_quoted_local_part() {
        // Quoted local parts with special characters should be preserved.
        let mut parent = AddressItem::new("\"user name\"@old.example.com".to_string());
        let mut addr_new: Vec<AddressItem> = Vec::new();
        let mut ctx = DeliveryContext::default();

        change_domain(
            &mut parent,
            "new.example.com",
            false,
            &mut addr_new,
            &mut ctx,
        );

        let child = &addr_new[0];
        assert_eq!(child.address, "\"user name\"@new.example.com");
        assert_eq!(child.local_part, "\"user name\"");
    }

    // -- is_address_header tests --

    #[test]
    fn test_is_address_header() {
        assert!(is_address_header(&HeaderType::From));
        assert!(is_address_header(&HeaderType::To));
        assert!(is_address_header(&HeaderType::Cc));
        assert!(is_address_header(&HeaderType::Bcc));
        assert!(is_address_header(&HeaderType::ReplyTo));
        assert!(!is_address_header(&HeaderType::Subject));
        assert!(!is_address_header(&HeaderType::Date));
        assert!(!is_address_header(&HeaderType::Other));
        assert!(!is_address_header(&HeaderType::Received));
    }

    // -- rewrite_headers tests --

    #[test]
    fn test_rewrite_headers_no_rules() {
        let mut ctx = DeliveryContext::default();
        ctx.header_list.push(HeaderLine::new(
            "From: user@old.com\n".to_string(),
            HeaderType::From,
        ));
        // No rules → no modification.
        rewrite_headers("old.com", "new.com", &mut ctx);
        assert_eq!(ctx.header_list[0].text, "From: user@old.com\n");
        assert!(!ctx.header_rewritten);
    }

    #[test]
    fn test_rewrite_headers_non_address_header_unchanged() {
        let mut ctx = DeliveryContext::default();
        ctx.header_list.push(HeaderLine::new(
            "Subject: test@old.com\n".to_string(),
            HeaderType::Subject,
        ));
        ctx.rewrite_existflags = 1;
        ctx.rewrite_rules.push(RewriteRule {
            pattern: "old.com".to_string(),
            replacement: "new.com".to_string(),
            flags: 1,
        });

        rewrite_headers("old.com", "new.com", &mut ctx);
        // Subject is not an address header, so it should not be rewritten.
        assert_eq!(ctx.header_list[0].text, "Subject: test@old.com\n");
    }

    // -- HeaderLine tests --

    #[test]
    fn test_header_line_new() {
        let h = HeaderLine::new("From: test@example.com\n".to_string(), HeaderType::From);
        assert_eq!(h.slen, 23);
        assert_eq!(h.htype, HeaderType::From);
    }
}
