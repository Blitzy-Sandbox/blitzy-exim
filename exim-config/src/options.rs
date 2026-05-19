//! Option list processing for all driver types.
//!
//! This module implements the option table definitions and typed option
//! handling that forms the backbone of Exim's configuration system. It
//! translates:
//!
//! - `readconf_handle_option()` (readconf.c lines 1759–2534)
//! - `find_option()` — binary chop search
//! - `optionlist_config[]` — main config option table (readconf.c lines 31–403)
//! - `readconf_readtime()` — time value parser
//! - `readconf_readfixed()` — fixed-point number parser
//! - `readconf_readname()` — name extractor
//!
//! # Architecture
//!
//! In C, the option system uses a flat array of `optionlist` structs sorted
//! alphabetically for binary-chop lookup, with type flags packed into an
//! integer alongside control bits. In Rust, we separate the concerns:
//!
//! - [`OptionType`] enum replaces the `opt_*` type constants
//! - [`OptionFlags`] bitflags replaces the `opt_set`/`opt_secure`/etc. bits
//! - [`OptionEntry`] struct replaces `optionlist`
//! - [`MAIN_CONFIG_OPTIONS`] replaces `optionlist_config[]`
//! - [`find_option`] replaces `find_option()` using `binary_search_by`
//! - [`handle_option`] replaces `readconf_handle_option()`

use crate::types::{ConfigContext, ConfigError, RewriteRule};

use bitflags::bitflags;
use tracing::{debug, error, trace, warn};

// ---------------------------------------------------------------------------
// OptionType enum — replaces C opt_* type constants
// ---------------------------------------------------------------------------

/// Represents every typed option kind supported by the Exim configuration
/// system, directly corresponding to the C `opt_*` constants in `readconf.c`.
///
/// Each variant describes how the raw string value on the right-hand side
/// of an option assignment is parsed and stored into the configuration
/// context or a driver data block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionType {
    /// String pointer — raw string stored verbatim (C: `opt_stringptr`).
    StringPtr,
    /// Boolean — true/false/yes/no or bare presence (C: `opt_bool`).
    Bool,
    /// Boolean with verify fudge — sets both `*_sender` and `*_recipient`
    /// variants (C: `opt_bool_verify`).
    BoolVerify,
    /// Boolean with set-flag — notes when the boolean has been explicitly
    /// set via a companion `*set_*` flag (C: `opt_bool_set`).
    BoolSet,
    /// Integer — decimal, optionally with K/M/G/T suffix (C: `opt_int`).
    Int,
    /// Integer held in kilobytes — values are stored in K units with full
    /// multiplier support up to Z (C: `opt_Kint`).
    Kint,
    /// Integer with K/M multiplier — displayed with the nearest clean suffix
    /// (C: `opt_mkint`).
    Mkint,
    /// Octal integer (C: `opt_octint`).
    OctInt,
    /// Time value — parsed from `Xw Xd Xh Xm Xs` format (C: `opt_time`).
    Time,
    /// Time list — colon-separated list of time values with a count prefix
    /// (C: `opt_timelist`).
    TimeList,
    /// Fixed-point number — stored as integer × 1000 (C: `opt_fixed`).
    Fixed,
    /// User ID — resolved from name via getpwnam or numeric (C: `opt_uid`).
    Uid,
    /// Group ID — resolved from name via getgrnam or numeric (C: `opt_gid`).
    Gid,
    /// User ID list — colon-separated list of UIDs (C: `opt_uidlist`).
    UidList,
    /// Group ID list — colon-separated list of GIDs (C: `opt_gidlist`).
    GidList,
    /// Expandable UID — if value starts with `$`, stored as string for
    /// later expansion; otherwise resolved immediately (C: `opt_expand_uid`).
    ExpandUid,
    /// Expandable GID — if value starts with `$`, stored as string for
    /// later expansion; otherwise resolved immediately (C: `opt_expand_gid`).
    ExpandGid,
    /// Rewrite rule — string parsed into a chain of rewrite control blocks
    /// (C: `opt_rewrite`).
    Rewrite,
    /// Custom handler function — delegates to a callback for special
    /// processing (C: `opt_func`).
    Func,
    /// Misc module option — delegates to a module-provided option table
    /// (C: `opt_misc_module`).
    MiscModule,
    /// Lookup module option — delegates to a lookup-module-provided option
    /// table (C: `opt_lookup_module`).
    LookupModule,
}

// ---------------------------------------------------------------------------
// OptionFlags — replaces C opt_set / opt_secure / etc. bits
// ---------------------------------------------------------------------------

bitflags! {
    /// Bitflags controlling option metadata, matching the C flag system
    /// from `readconf.c`.
    ///
    /// These flags are combined with each [`OptionEntry`] to track state
    /// (whether the option has been set), security (whether it was declared
    /// with `hide`), visibility, and repeat-assignment behaviour.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct OptionFlags: u32 {
        /// Option has been set in the configuration (C: `opt_set`).
        const SET     = 0x0001;
        /// Option was declared with `hide` — its value is not printed
        /// in `-bP` output (C: `opt_secure`).
        const SECURE  = 0x0002;
        /// Hidden internal option (name starts with `*`), not user-visible
        /// (C: `opt_hidden`).
        const HIDDEN  = 0x0004;
        /// On repeated assignment, concatenate the new value with the old
        /// using condition chaining (C: `opt_rep_con`).
        const REP_CON = 0x0008;
        /// On repeated assignment, override the old value with the new
        /// (C: `opt_rep_str`).
        const REP_STR = 0x0010;
        /// Option belongs to the public (generic) section of a driver
        /// data block rather than the private options block (C: `opt_public`).
        const PUBLIC  = 0x0020;
    }
}

// ---------------------------------------------------------------------------
// OptionEntry — replaces C `optionlist` struct
// ---------------------------------------------------------------------------

/// A single entry in an option table, replacing the C `optionlist` struct.
///
/// Each entry associates an option name with its type and control flags.
/// Option tables are kept in alphabetical order by `name` to enable
/// binary-chop search via [`find_option`].
///
/// In the C code, the `value` union encodes either an absolute pointer to
/// a global variable or a byte offset within a driver data block. In Rust,
/// the [`handle_option`] function uses the option name to look up the
/// corresponding field on [`ConfigContext`] directly, eliminating the need
/// for raw pointer arithmetic.
#[derive(Debug, Clone)]
pub struct OptionEntry {
    /// The option name as it appears in the configuration file.
    /// Must be in ASCII lowercase with underscores. Names starting with
    /// `*` are hidden internal entries (e.g. `*set_exim_user`).
    pub name: &'static str,
    /// The type of value this option expects.
    pub option_type: OptionType,
    /// Control flags for this option entry.
    pub flags: OptionFlags,
}

impl OptionEntry {
    /// Create a new option entry with the given name, type, and flags.
    pub const fn new(name: &'static str, option_type: OptionType, flags: OptionFlags) -> Self {
        Self {
            name,
            option_type,
            flags,
        }
    }

    /// Convenience constructor for a simple option with no special flags.
    pub const fn simple(name: &'static str, option_type: OptionType) -> Self {
        Self::new(name, option_type, OptionFlags::empty())
    }

    /// Convenience constructor for a hidden internal option.
    pub const fn hidden(name: &'static str, option_type: OptionType) -> Self {
        Self::new(name, option_type, OptionFlags::HIDDEN)
    }
}

// ---------------------------------------------------------------------------
// MAIN_CONFIG_OPTIONS — replaces C `optionlist_config[]`
// ---------------------------------------------------------------------------

/// Main configuration option table — the exhaustive, alphabetically sorted
/// list of all top-level Exim configuration directives.
///
/// This directly replaces `optionlist_config[]` (readconf.c lines 31–403).
/// The table **MUST** be in strict ASCII-alphabetical order because
/// [`find_option`] uses binary search.
///
/// Conditional compilation is handled via Cargo feature flags that replace
/// the C preprocessor `#ifdef` / `#ifndef` guards (AAP §0.7.3):
///
/// - `#[cfg(feature = "content-scan")]` replaces `#ifdef WITH_CONTENT_SCAN`
/// - `#[cfg(feature = "tls")]` replaces `#ifndef DISABLE_TLS`
/// - `#[cfg(feature = "prdr")]` replaces `#ifndef DISABLE_PRDR`
/// - `#[cfg(feature = "dkim")]` replaces `#ifndef DISABLE_DKIM`
/// - `#[cfg(feature = "wellknown")]` replaces `#ifndef DISABLE_WELLKNOWN`
/// - `#[cfg(feature = "i18n")]` replaces `#ifdef SUPPORT_I18N`
///
/// Because conditional compilation may remove entries, the table is built
/// at runtime via a function that guarantees sorted order.
pub fn main_config_options() -> Vec<OptionEntry> {
    let mut opts: Vec<OptionEntry> = Vec::with_capacity(400);

    // Hidden internal set-flags (names starting with `*`)
    opts.push(OptionEntry::hidden("*set_exim_group", OptionType::Bool));
    opts.push(OptionEntry::hidden("*set_exim_user", OptionType::Bool));
    opts.push(OptionEntry::hidden(
        "*set_system_filter_group",
        OptionType::Bool,
    ));
    opts.push(OptionEntry::hidden(
        "*set_system_filter_user",
        OptionType::Bool,
    ));

    // --- A ---
    opts.push(OptionEntry::simple("accept_8bitmime", OptionType::Bool));
    opts.push(OptionEntry::simple("acl_not_smtp", OptionType::StringPtr));
    #[cfg(feature = "content-scan")]
    opts.push(OptionEntry::simple(
        "acl_not_smtp_mime",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "acl_not_smtp_start",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("acl_smtp_atrn", OptionType::StringPtr));
    opts.push(OptionEntry::simple("acl_smtp_auth", OptionType::StringPtr));
    opts.push(OptionEntry::simple(
        "acl_smtp_connect",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("acl_smtp_data", OptionType::StringPtr));
    #[cfg(feature = "prdr")]
    opts.push(OptionEntry::simple(
        "acl_smtp_data_prdr",
        OptionType::StringPtr,
    ));
    #[cfg(feature = "dkim")]
    opts.push(OptionEntry::simple("acl_smtp_dkim", OptionType::MiscModule));
    opts.push(OptionEntry::simple("acl_smtp_etrn", OptionType::StringPtr));
    opts.push(OptionEntry::simple("acl_smtp_expn", OptionType::StringPtr));
    opts.push(OptionEntry::simple("acl_smtp_helo", OptionType::StringPtr));
    opts.push(OptionEntry::simple("acl_smtp_mail", OptionType::StringPtr));
    opts.push(OptionEntry::simple(
        "acl_smtp_mailauth",
        OptionType::StringPtr,
    ));
    #[cfg(feature = "content-scan")]
    opts.push(OptionEntry::simple("acl_smtp_mime", OptionType::StringPtr));
    opts.push(OptionEntry::simple(
        "acl_smtp_notquit",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "acl_smtp_predata",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("acl_smtp_quit", OptionType::StringPtr));
    opts.push(OptionEntry::simple("acl_smtp_rcpt", OptionType::StringPtr));
    #[cfg(feature = "tls")]
    opts.push(OptionEntry::simple(
        "acl_smtp_starttls",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("acl_smtp_vrfy", OptionType::StringPtr));
    #[cfg(feature = "wellknown")]
    opts.push(OptionEntry::simple(
        "acl_smtp_wellknown",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "add_environment",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("admin_groups", OptionType::GidList));
    opts.push(OptionEntry::simple(
        "allow_domain_literals",
        OptionType::Bool,
    ));
    opts.push(OptionEntry::simple("allow_mx_to_ip", OptionType::Bool));
    opts.push(OptionEntry::simple("allow_utf8_domains", OptionType::Bool));
    opts.push(OptionEntry::simple(
        "auth_advertise_hosts",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("auto_thaw", OptionType::Time));
    #[cfg(feature = "content-scan")]
    opts.push(OptionEntry::simple("av_scanner", OptionType::StringPtr));

    // --- B ---
    opts.push(OptionEntry::simple("bi_command", OptionType::StringPtr));
    opts.push(OptionEntry::simple(
        "bounce_message_file",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "bounce_message_text",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("bounce_return_body", OptionType::Bool));
    opts.push(OptionEntry::simple(
        "bounce_return_linesize_limit",
        OptionType::Mkint,
    ));
    opts.push(OptionEntry::simple(
        "bounce_return_message",
        OptionType::Bool,
    ));
    opts.push(OptionEntry::simple(
        "bounce_return_size_limit",
        OptionType::Mkint,
    ));
    opts.push(OptionEntry::simple(
        "bounce_sender_authentication",
        OptionType::StringPtr,
    ));

    // --- C ---
    opts.push(OptionEntry::simple(
        "callout_domain_negative_expire",
        OptionType::Time,
    ));
    opts.push(OptionEntry::simple(
        "callout_domain_positive_expire",
        OptionType::Time,
    ));
    opts.push(OptionEntry::simple(
        "callout_negative_expire",
        OptionType::Time,
    ));
    opts.push(OptionEntry::simple(
        "callout_positive_expire",
        OptionType::Time,
    ));
    opts.push(OptionEntry::simple(
        "callout_random_local_part",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("check_log_inodes", OptionType::Int));
    opts.push(OptionEntry::simple("check_log_space", OptionType::Kint));
    opts.push(OptionEntry::simple(
        "check_rfc2047_length",
        OptionType::Bool,
    ));
    opts.push(OptionEntry::simple("check_spool_inodes", OptionType::Int));
    opts.push(OptionEntry::simple("check_spool_space", OptionType::Kint));
    opts.push(OptionEntry::simple(
        "chunking_advertise_hosts",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "commandline_checks_require_admin",
        OptionType::Bool,
    ));

    // --- D ---
    opts.push(OptionEntry::simple(
        "daemon_modules_load",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::new(
        "daemon_smtp_port",
        OptionType::StringPtr,
        OptionFlags::HIDDEN,
    ));
    opts.push(OptionEntry::simple(
        "daemon_smtp_ports",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "daemon_startup_retries",
        OptionType::Int,
    ));
    opts.push(OptionEntry::simple(
        "daemon_startup_sleep",
        OptionType::Time,
    ));
    opts.push(OptionEntry::simple("debug_store", OptionType::Bool));
    opts.push(OptionEntry::simple("delay_warning", OptionType::TimeList));
    opts.push(OptionEntry::simple(
        "delay_warning_condition",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "deliver_drop_privilege",
        OptionType::Bool,
    ));
    opts.push(OptionEntry::simple(
        "deliver_queue_load_max",
        OptionType::Fixed,
    ));
    opts.push(OptionEntry::simple(
        "delivery_date_remove",
        OptionType::Bool,
    ));
    opts.push(OptionEntry::simple("disable_ipv6", OptionType::Bool));
    #[cfg(feature = "dkim")]
    {
        opts.push(OptionEntry::simple(
            "dkim_verify_hashes",
            OptionType::MiscModule,
        ));
        opts.push(OptionEntry::simple(
            "dkim_verify_keytypes",
            OptionType::MiscModule,
        ));
        opts.push(OptionEntry::simple(
            "dkim_verify_min_keysizes",
            OptionType::MiscModule,
        ));
        opts.push(OptionEntry::simple(
            "dkim_verify_minimal",
            OptionType::MiscModule,
        ));
        opts.push(OptionEntry::simple(
            "dkim_verify_signers",
            OptionType::MiscModule,
        ));
    }
    opts.push(OptionEntry::simple(
        "dns_again_means_nonexist",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "dns_check_names_pattern",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("dns_cname_loops", OptionType::Int));
    opts.push(OptionEntry::simple("dns_csa_search_limit", OptionType::Int));
    opts.push(OptionEntry::simple("dns_csa_use_reverse", OptionType::Bool));
    opts.push(OptionEntry::simple("dns_dnssec_ok", OptionType::Int));
    opts.push(OptionEntry::simple(
        "dns_ipv4_lookup",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("dns_retrans", OptionType::Time));
    opts.push(OptionEntry::simple("dns_retry", OptionType::Int));
    opts.push(OptionEntry::simple("dns_trust_aa", OptionType::StringPtr));
    opts.push(OptionEntry::simple("dns_use_edns0", OptionType::Int));
    opts.push(OptionEntry::simple(
        "dsn_advertise_hosts",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("dsn_from", OptionType::StringPtr));

    // --- E ---
    opts.push(OptionEntry::simple("envelope_to_remove", OptionType::Bool));
    opts.push(OptionEntry::simple("errors_copy", OptionType::StringPtr));
    opts.push(OptionEntry::simple(
        "errors_reply_to",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("exim_group", OptionType::Gid));
    opts.push(OptionEntry::simple("exim_path", OptionType::StringPtr));
    opts.push(OptionEntry::simple("exim_user", OptionType::Uid));
    opts.push(OptionEntry::simple("exim_version", OptionType::StringPtr));
    opts.push(OptionEntry::simple(
        "extra_local_interfaces",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "extract_addresses_remove_arguments",
        OptionType::Bool,
    ));

    // --- F ---
    opts.push(OptionEntry::simple("finduser_retries", OptionType::Int));
    opts.push(OptionEntry::simple("freeze_tell", OptionType::StringPtr));

    // --- G ---
    opts.push(OptionEntry::simple("gecos_name", OptionType::StringPtr));
    opts.push(OptionEntry::simple("gecos_pattern", OptionType::StringPtr));
    #[cfg(feature = "tls")]
    {
        opts.push(OptionEntry::simple(
            "gnutls_allow_auto_pkcs11",
            OptionType::Bool,
        ));
        opts.push(OptionEntry::simple("gnutls_compat_mode", OptionType::Bool));
    }

    // --- H ---
    opts.push(OptionEntry::simple("header_line_maxsize", OptionType::Int));
    opts.push(OptionEntry::simple("header_maxsize", OptionType::Int));
    opts.push(OptionEntry::simple(
        "headers_charset",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "helo_accept_junk_hosts",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "helo_allow_chars",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "helo_lookup_domains",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "helo_try_verify_hosts",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "helo_verify_hosts",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("hold_domains", OptionType::StringPtr));
    opts.push(OptionEntry::simple("host_lookup", OptionType::StringPtr));
    opts.push(OptionEntry::simple(
        "host_lookup_order",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "host_reject_connection",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "hosts_connection_nolog",
        OptionType::StringPtr,
    ));
    #[cfg(feature = "tls")]
    opts.push(OptionEntry::simple(
        "hosts_require_alpn",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "hosts_require_helo",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "hosts_treat_as_local",
        OptionType::StringPtr,
    ));

    // --- I ---
    opts.push(OptionEntry::simple(
        "ignore_bounce_errors_after",
        OptionType::Time,
    ));
    opts.push(OptionEntry::simple(
        "ignore_fromline_hosts",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "ignore_fromline_local",
        OptionType::Bool,
    ));

    // --- K ---
    opts.push(OptionEntry::simple(
        "keep_environment",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("keep_malformed", OptionType::Time));

    // --- L ---
    opts.push(OptionEntry::simple("local_from_check", OptionType::Bool));
    opts.push(OptionEntry::simple(
        "local_from_prefix",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "local_from_suffix",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "local_interfaces",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("local_sender_retain", OptionType::Bool));
    opts.push(OptionEntry::simple(
        "localhost_number",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("log_file_path", OptionType::StringPtr));
    opts.push(OptionEntry::simple("log_ports", OptionType::StringPtr));
    opts.push(OptionEntry::simple("log_selector", OptionType::StringPtr));
    opts.push(OptionEntry::simple("log_timezone", OptionType::Bool));
    opts.push(OptionEntry::simple("lookup_open_max", OptionType::Int));

    // --- M ---
    opts.push(OptionEntry::simple("max_username_length", OptionType::Int));
    opts.push(OptionEntry::simple(
        "message_body_newlines",
        OptionType::Bool,
    ));
    opts.push(OptionEntry::simple(
        "message_body_visible",
        OptionType::Mkint,
    ));
    opts.push(OptionEntry::simple(
        "message_id_header_domain",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "message_id_header_text",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("message_logs", OptionType::Bool));
    opts.push(OptionEntry::simple(
        "message_size_limit",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("mua_wrapper", OptionType::Bool));

    // --- N ---
    opts.push(OptionEntry::simple("never_users", OptionType::UidList));
    opts.push(OptionEntry::simple(
        "notifier_socket",
        OptionType::StringPtr,
    ));

    // --- O ---
    #[cfg(feature = "tls")]
    opts.push(OptionEntry::simple(
        "openssl_options",
        OptionType::StringPtr,
    ));

    // --- P ---
    opts.push(OptionEntry::simple("panic_coredump", OptionType::Bool));
    opts.push(OptionEntry::simple(
        "percent_hack_domains",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("pid_file_path", OptionType::StringPtr));
    opts.push(OptionEntry::simple(
        "pipelining_advertise_hosts",
        OptionType::StringPtr,
    ));
    #[cfg(feature = "prdr")]
    opts.push(OptionEntry::simple("prdr_enable", OptionType::Bool));
    opts.push(OptionEntry::simple(
        "preserve_message_logs",
        OptionType::Bool,
    ));
    opts.push(OptionEntry::simple(
        "primary_hostname",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("print_topbitchars", OptionType::Bool));
    opts.push(OptionEntry::simple(
        "process_log_path",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("prod_requires_admin", OptionType::Bool));

    // --- Q ---
    opts.push(OptionEntry::simple("qualify_domain", OptionType::StringPtr));
    opts.push(OptionEntry::simple(
        "qualify_recipient",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("queue_domains", OptionType::StringPtr));
    opts.push(OptionEntry::simple(
        "queue_list_requires_admin",
        OptionType::Bool,
    ));
    opts.push(OptionEntry::simple("queue_only", OptionType::Bool));
    opts.push(OptionEntry::simple(
        "queue_only_file",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("queue_only_load", OptionType::Fixed));
    opts.push(OptionEntry::simple(
        "queue_only_load_latch",
        OptionType::Bool,
    ));
    opts.push(OptionEntry::simple("queue_only_override", OptionType::Bool));
    opts.push(OptionEntry::simple("queue_run_in_order", OptionType::Bool));
    opts.push(OptionEntry::simple("queue_run_max", OptionType::StringPtr));
    opts.push(OptionEntry::simple(
        "queue_smtp_domains",
        OptionType::StringPtr,
    ));

    // --- R ---
    opts.push(OptionEntry::simple("receive_timeout", OptionType::Time));
    opts.push(OptionEntry::simple(
        "received_header_text",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("received_headers_max", OptionType::Int));
    opts.push(OptionEntry::simple(
        "recipient_unqualified_hosts",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("recipients_max", OptionType::StringPtr));
    opts.push(OptionEntry::simple(
        "recipients_max_reject",
        OptionType::Bool,
    ));
    opts.push(OptionEntry::simple("remote_max_parallel", OptionType::Int));
    opts.push(OptionEntry::simple(
        "remote_sort_domains",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("retry_data_expire", OptionType::Time));
    opts.push(OptionEntry::simple("retry_interval_max", OptionType::Time));
    opts.push(OptionEntry::simple("return_path_remove", OptionType::Bool));
    opts.push(OptionEntry::new(
        "return_size_limit",
        OptionType::Mkint,
        OptionFlags::HIDDEN,
    ));
    opts.push(OptionEntry::simple("rfc1413_hosts", OptionType::StringPtr));
    opts.push(OptionEntry::new(
        "rfc1413_port",
        OptionType::Int,
        OptionFlags::HIDDEN,
    ));
    opts.push(OptionEntry::simple(
        "rfc1413_query_timeout",
        OptionType::Time,
    ));

    // --- S ---
    opts.push(OptionEntry::simple(
        "sender_unqualified_hosts",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("slow_lookup_log", OptionType::Int));
    opts.push(OptionEntry::simple(
        "smtp_accept_keepalive",
        OptionType::Bool,
    ));
    opts.push(OptionEntry::simple("smtp_accept_max", OptionType::Int));
    opts.push(OptionEntry::simple(
        "smtp_accept_max_nonmail",
        OptionType::Int,
    ));
    opts.push(OptionEntry::simple(
        "smtp_accept_max_nonmail_hosts",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "smtp_accept_max_per_connection",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "smtp_accept_max_per_host",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("smtp_accept_queue", OptionType::Int));
    opts.push(OptionEntry::simple(
        "smtp_accept_queue_per_connection",
        OptionType::Int,
    ));
    opts.push(OptionEntry::simple("smtp_accept_reserve", OptionType::Int));
    opts.push(OptionEntry::simple(
        "smtp_active_hostname",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("smtp_backlog_monitor", OptionType::Int));
    opts.push(OptionEntry::simple("smtp_banner", OptionType::StringPtr));
    opts.push(OptionEntry::simple(
        "smtp_check_spool_space",
        OptionType::Bool,
    ));
    opts.push(OptionEntry::simple("smtp_connect_backlog", OptionType::Int));
    opts.push(OptionEntry::simple("smtp_enforce_sync", OptionType::Bool));
    opts.push(OptionEntry::simple(
        "smtp_etrn_command",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("smtp_etrn_serialize", OptionType::Bool));
    opts.push(OptionEntry::simple("smtp_load_reserve", OptionType::Fixed));
    opts.push(OptionEntry::simple(
        "smtp_max_synprot_errors",
        OptionType::Int,
    ));
    opts.push(OptionEntry::simple(
        "smtp_max_unknown_commands",
        OptionType::Int,
    ));
    opts.push(OptionEntry::simple(
        "smtp_ratelimit_hosts",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "smtp_ratelimit_mail",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "smtp_ratelimit_rcpt",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "smtp_receive_timeout",
        OptionType::Func,
    ));
    opts.push(OptionEntry::simple(
        "smtp_reserve_hosts",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "smtp_return_error_details",
        OptionType::Bool,
    ));
    #[cfg(feature = "i18n")]
    opts.push(OptionEntry::simple(
        "smtputf8_advertise_hosts",
        OptionType::StringPtr,
    ));
    #[cfg(feature = "content-scan")]
    opts.push(OptionEntry::simple("spamd_address", OptionType::StringPtr));
    opts.push(OptionEntry::simple(
        "split_spool_directory",
        OptionType::Bool,
    ));
    opts.push(OptionEntry::simple(
        "spool_directory",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("spool_wireformat", OptionType::Bool));
    opts.push(OptionEntry::simple("strict_acl_vars", OptionType::Bool));
    opts.push(OptionEntry::simple(
        "strip_excess_angle_brackets",
        OptionType::Bool,
    ));
    opts.push(OptionEntry::simple("strip_trailing_dot", OptionType::Bool));
    opts.push(OptionEntry::simple("syslog_duplication", OptionType::Bool));
    opts.push(OptionEntry::simple(
        "syslog_facility",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("syslog_pid", OptionType::Bool));
    opts.push(OptionEntry::simple(
        "syslog_processname",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("syslog_timestamp", OptionType::Bool));
    opts.push(OptionEntry::simple("system_filter", OptionType::StringPtr));
    opts.push(OptionEntry::simple(
        "system_filter_directory_transport",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "system_filter_file_transport",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("system_filter_group", OptionType::Gid));
    opts.push(OptionEntry::simple(
        "system_filter_pipe_transport",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "system_filter_reply_transport",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("system_filter_user", OptionType::Uid));

    // --- T ---
    opts.push(OptionEntry::simple("tcp_nodelay", OptionType::Bool));
    opts.push(OptionEntry::simple(
        "timeout_frozen_after",
        OptionType::Time,
    ));
    opts.push(OptionEntry::simple("timezone", OptionType::StringPtr));
    opts.push(OptionEntry::simple(
        "tls_advertise_hosts",
        OptionType::StringPtr,
    ));
    #[cfg(feature = "tls")]
    {
        opts.push(OptionEntry::simple("tls_alpn", OptionType::StringPtr));
        opts.push(OptionEntry::simple(
            "tls_certificate",
            OptionType::StringPtr,
        ));
        opts.push(OptionEntry::simple("tls_crl", OptionType::StringPtr));
        opts.push(OptionEntry::simple("tls_dh_max_bits", OptionType::Int));
        opts.push(OptionEntry::simple("tls_dhparam", OptionType::StringPtr));
        opts.push(OptionEntry::simple(
            "tls_early_banner_hosts",
            OptionType::StringPtr,
        ));
        opts.push(OptionEntry::simple("tls_eccurve", OptionType::StringPtr));
        opts.push(OptionEntry::simple("tls_ocsp_file", OptionType::StringPtr));
        opts.push(OptionEntry::simple(
            "tls_on_connect_ports",
            OptionType::StringPtr,
        ));
        opts.push(OptionEntry::simple("tls_privatekey", OptionType::StringPtr));
        opts.push(OptionEntry::simple("tls_remember_esmtp", OptionType::Bool));
        opts.push(OptionEntry::simple(
            "tls_require_ciphers",
            OptionType::StringPtr,
        ));
        opts.push(OptionEntry::simple(
            "tls_resumption_hosts",
            OptionType::StringPtr,
        ));
        opts.push(OptionEntry::simple(
            "tls_try_verify_hosts",
            OptionType::StringPtr,
        ));
        opts.push(OptionEntry::simple(
            "tls_verify_certificates",
            OptionType::StringPtr,
        ));
        opts.push(OptionEntry::simple(
            "tls_verify_hosts",
            OptionType::StringPtr,
        ));
    }
    opts.push(OptionEntry::simple("trusted_groups", OptionType::GidList));
    opts.push(OptionEntry::simple("trusted_users", OptionType::UidList));

    // --- U ---
    opts.push(OptionEntry::simple("unknown_login", OptionType::StringPtr));
    opts.push(OptionEntry::simple(
        "unknown_username",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "untrusted_set_sender",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "uucp_from_pattern",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple(
        "uucp_from_sender",
        OptionType::StringPtr,
    ));

    // --- W ---
    opts.push(OptionEntry::simple(
        "warn_message_file",
        OptionType::StringPtr,
    ));
    #[cfg(feature = "wellknown")]
    opts.push(OptionEntry::simple(
        "wellknown_advertise_hosts",
        OptionType::StringPtr,
    ));
    opts.push(OptionEntry::simple("write_rejectlog", OptionType::Bool));

    // Ensure strict alphabetical ordering — required for binary search.
    opts.sort_by(|a, b| a.name.cmp(b.name));

    // Debug-mode verification that the sort is correct.
    debug_assert!(
        opts.windows(2).all(|w| w[0].name < w[1].name),
        "MAIN_CONFIG_OPTIONS is not in strict alphabetical order"
    );

    opts
}

/// Lazily-initialized main configuration options table.
///
/// This is the Rust replacement for the C `optionlist_config[]` static array.
/// Built once on first access, then reused. Guaranteed to be sorted
/// alphabetically for binary-chop search.
pub static MAIN_CONFIG_OPTIONS: std::sync::LazyLock<Vec<OptionEntry>> =
    std::sync::LazyLock::new(main_config_options);

// ---------------------------------------------------------------------------
// find_option — binary-chop search (replaces C find_option)
// ---------------------------------------------------------------------------

/// Search for an option by name in an alphabetically sorted option list.
///
/// This is the Rust equivalent of the C `find_option()` (readconf.c lines
/// 1464–1477). It uses [`[T]::binary_search_by`] on the `name` field.
///
/// The search is **case-sensitive** — option names in Exim are always
/// lowercase, matching the C `Ustrcmp` (strcmp) comparison.
///
/// # Arguments
///
/// * `name` — The option name to search for (with any `no_`/`not_` prefix
///   already stripped).
/// * `options` — A sorted slice of [`OptionEntry`] to search within.
///
/// # Returns
///
/// The index of the matching entry within `options`, or `None` if the name
/// is not found.
pub fn find_option(name: &str, options: &[OptionEntry]) -> Option<usize> {
    trace!(option_name = %name, table_size = options.len(), "searching option table");
    options.binary_search_by(|entry| entry.name.cmp(name)).ok()
}

// ---------------------------------------------------------------------------
// read_name — name extractor (replaces C readconf_readname)
// ---------------------------------------------------------------------------

/// Extract an option name from the start of a string.
///
/// This is the Rust equivalent of `readconf_readname()` (readconf.c lines
/// 1318–1342). It skips leading whitespace, then reads a run of
/// alphanumeric characters and underscores to form the name.
///
/// # Arguments
///
/// * `input` — The input string to read from.
///
/// # Returns
///
/// A tuple of `(name, remaining)` where `name` is the extracted name
/// string (which may be empty if no alphanumeric character was found at
/// the start) and `remaining` is the rest of the input after the name
/// and any trailing whitespace.
pub fn read_name(input: &str) -> (&str, &str) {
    let s = input.trim_start();
    if s.is_empty() {
        return ("", s);
    }
    // Name starts with an alphabetic character, then continues with
    // alphanumeric or underscore.
    let first_char = s.as_bytes()[0];
    if !first_char.is_ascii_alphabetic() {
        return ("", s);
    }
    let name_end = s
        .bytes()
        .position(|b| !b.is_ascii_alphanumeric() && b != b'_')
        .unwrap_or(s.len());
    let name = &s[..name_end];
    let rest = s[name_end..].trim_start();
    (name, rest)
}

// ---------------------------------------------------------------------------
// parse_time — time value parser (replaces C readconf_readtime)
// ---------------------------------------------------------------------------

/// Parse a time value from a string.
///
/// This is the Rust equivalent of `readconf_readtime()` (readconf.c lines
/// 1371–1408). The format is:
///
/// ```text
/// [<n>w][<n>d][<n>h][<n>m][<n>s]
/// ```
///
/// At least one component must be present. A bare number is treated as
/// seconds. Components are additive, so `1h30m` = 5400 seconds.
///
/// # Arguments
///
/// * `input` — The string to parse.
///
/// # Returns
///
/// `Ok(seconds)` on success, or `Err(ConfigError)` if the string does not
/// represent a valid time value.
///
/// # Examples
///
/// ```
/// use exim_config::options::parse_time;
/// assert_eq!(parse_time("5m").unwrap(), 300);
/// assert_eq!(parse_time("2h30m").unwrap(), 9000);
/// assert_eq!(parse_time("1d12h").unwrap(), 129600);
/// assert_eq!(parse_time("1w").unwrap(), 604800);
/// assert_eq!(parse_time("30s").unwrap(), 30);
/// assert_eq!(parse_time("120").unwrap(), 120);
/// ```
pub fn parse_time(input: &str) -> Result<i32, ConfigError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(ConfigError::ParseError {
            file: String::new(),
            line: 0,
            message: "empty time value".to_string(),
        });
    }

    let bytes = s.as_bytes();
    let mut pos = 0;
    let mut total: i32 = 0;
    let mut any_parsed = false;

    while pos < bytes.len() {
        // Must start with a digit.
        if !bytes[pos].is_ascii_digit() {
            return Err(ConfigError::ParseError {
                file: String::new(),
                line: 0,
                message: format!("invalid time value: {s}"),
            });
        }

        // Read the numeric part.
        let num_start = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
        let num_str = &s[num_start..pos];
        let value: i32 = num_str.parse().map_err(|_| ConfigError::ParseError {
            file: String::new(),
            line: 0,
            message: format!("integer overflow in time value: {s}"),
        })?;

        // Check for a time-unit suffix.
        if pos < bytes.len() {
            match bytes[pos] {
                b'w' => {
                    total = total
                        .checked_add(value.checked_mul(7 * 24 * 60 * 60).ok_or_else(|| {
                            ConfigError::ParseError {
                                file: String::new(),
                                line: 0,
                                message: format!("overflow in time value: {s}"),
                            }
                        })?)
                        .ok_or_else(|| ConfigError::ParseError {
                            file: String::new(),
                            line: 0,
                            message: format!("overflow in time value: {s}"),
                        })?;
                    pos += 1;
                }
                b'd' => {
                    total = total
                        .checked_add(value.checked_mul(24 * 60 * 60).ok_or_else(|| {
                            ConfigError::ParseError {
                                file: String::new(),
                                line: 0,
                                message: format!("overflow in time value: {s}"),
                            }
                        })?)
                        .ok_or_else(|| ConfigError::ParseError {
                            file: String::new(),
                            line: 0,
                            message: format!("overflow in time value: {s}"),
                        })?;
                    pos += 1;
                }
                b'h' => {
                    total = total
                        .checked_add(value.checked_mul(60 * 60).ok_or_else(|| {
                            ConfigError::ParseError {
                                file: String::new(),
                                line: 0,
                                message: format!("overflow in time value: {s}"),
                            }
                        })?)
                        .ok_or_else(|| ConfigError::ParseError {
                            file: String::new(),
                            line: 0,
                            message: format!("overflow in time value: {s}"),
                        })?;
                    pos += 1;
                }
                b'm' => {
                    total = total
                        .checked_add(value.checked_mul(60).ok_or_else(|| {
                            ConfigError::ParseError {
                                file: String::new(),
                                line: 0,
                                message: format!("overflow in time value: {s}"),
                            }
                        })?)
                        .ok_or_else(|| ConfigError::ParseError {
                            file: String::new(),
                            line: 0,
                            message: format!("overflow in time value: {s}"),
                        })?;
                    pos += 1;
                }
                b's' => {
                    total = total
                        .checked_add(value)
                        .ok_or_else(|| ConfigError::ParseError {
                            file: String::new(),
                            line: 0,
                            message: format!("overflow in time value: {s}"),
                        })?;
                    pos += 1;
                }
                ch if ch.is_ascii_digit() => {
                    // Next digit — treat this component as seconds (bare number
                    // followed by more digits — this shouldn't happen after we
                    // already consumed all digits, so this is for the case where
                    // the suffix is a digit — but we consume all digits above).
                    // This branch is unreachable due to the while loop above,
                    // but kept for safety.
                    total = total
                        .checked_add(value)
                        .ok_or_else(|| ConfigError::ParseError {
                            file: String::new(),
                            line: 0,
                            message: format!("overflow in time value: {s}"),
                        })?;
                }
                _ => {
                    // No recognized suffix and not end of string — bare number
                    // at end of input is fine, but trailing garbage is not.
                    // Check if the remainder is just whitespace.
                    let rest = &s[pos..];
                    if rest.trim().is_empty() {
                        total =
                            total
                                .checked_add(value)
                                .ok_or_else(|| ConfigError::ParseError {
                                    file: String::new(),
                                    line: 0,
                                    message: format!("overflow in time value: {s}"),
                                })?;
                        any_parsed = true;
                        break;
                    }
                    return Err(ConfigError::ParseError {
                        file: String::new(),
                        line: 0,
                        message: format!("invalid time value: {s}"),
                    });
                }
            }
        } else {
            // End of string — bare number is treated as seconds.
            total = total
                .checked_add(value)
                .ok_or_else(|| ConfigError::ParseError {
                    file: String::new(),
                    line: 0,
                    message: format!("overflow in time value: {s}"),
                })?;
        }
        any_parsed = true;
    }

    if !any_parsed {
        return Err(ConfigError::ParseError {
            file: String::new(),
            line: 0,
            message: format!("invalid time value: {s}"),
        });
    }

    Ok(total)
}

// ---------------------------------------------------------------------------
// parse_time_list — colon-separated time list parser
// ---------------------------------------------------------------------------

/// Parse a colon-separated list of time values.
///
/// The format is: `time1:time2:time3:...`
///
/// Each element is parsed using [`parse_time`]. The values must be in
/// strictly increasing order (matching the C constraint in readconf.c
/// lines 2460–2496).
///
/// # Arguments
///
/// * `input` — The string to parse.
///
/// # Returns
///
/// A `Vec<i32>` of parsed time values in seconds, or a `ConfigError` on
/// failure.
pub fn parse_time_list(input: &str) -> Result<Vec<i32>, ConfigError> {
    let s = input.trim();
    if s.is_empty() {
        return Ok(Vec::new());
    }

    let parts: Vec<&str> = s.split(':').collect();
    let mut result = Vec::with_capacity(parts.len());

    for (i, part) in parts.iter().enumerate() {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value = parse_time(trimmed)?;
        // Enforce strictly increasing order after the first element.
        if i > 0 {
            if let Some(&prev) = result.last() {
                if value <= prev {
                    return Err(ConfigError::ParseError {
                        file: String::new(),
                        line: 0,
                        message: format!("time value out of order: {value} <= {prev} in list"),
                    });
                }
            }
        }
        result.push(value);
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// parse_fixed — fixed-point number parser (replaces C readconf_readfixed)
// ---------------------------------------------------------------------------

/// Parse a fixed-point number from a string.
///
/// This is the Rust equivalent of `readconf_readfixed()` (readconf.c lines
/// 1426–1445). The value is returned multiplied by 1000, so `1.5` → `1500`
/// and `0.333` → `333`.
///
/// # Arguments
///
/// * `input` — The string to parse.
///
/// # Returns
///
/// The fixed-point value × 1000, or a `ConfigError` on parse failure.
///
/// # Examples
///
/// ```
/// use exim_config::options::parse_fixed;
/// assert_eq!(parse_fixed("1.5").unwrap(), 1500);
/// assert_eq!(parse_fixed("0.333").unwrap(), 333);
/// assert_eq!(parse_fixed("42").unwrap(), 42000);
/// assert_eq!(parse_fixed("0.1").unwrap(), 100);
/// ```
pub fn parse_fixed(input: &str) -> Result<i32, ConfigError> {
    let s = input.trim();
    if s.is_empty() || !s.as_bytes()[0].is_ascii_digit() {
        return Err(ConfigError::ParseError {
            file: String::new(),
            line: 0,
            message: format!("fixed-point number expected, got: {input}"),
        });
    }

    // Split on the decimal point.
    let (int_part, frac_part) = if let Some(dot_pos) = s.find('.') {
        (&s[..dot_pos], Some(&s[dot_pos + 1..]))
    } else {
        // Check for trailing non-digit characters in the integer part.
        let end = s
            .bytes()
            .position(|b| !b.is_ascii_digit())
            .unwrap_or(s.len());
        let rest = s[end..].trim();
        if !rest.is_empty() {
            return Err(ConfigError::ParseError {
                file: String::new(),
                line: 0,
                message: format!("extra characters in fixed-point number: {input}"),
            });
        }
        (&s[..end], None)
    };

    let integer: i32 = int_part.parse().map_err(|_| ConfigError::ParseError {
        file: String::new(),
        line: 0,
        message: format!("invalid integer part in fixed-point number: {input}"),
    })?;

    let mut result = integer
        .checked_mul(1000)
        .ok_or_else(|| ConfigError::ParseError {
            file: String::new(),
            line: 0,
            message: format!("overflow in fixed-point number: {input}"),
        })?;

    if let Some(frac) = frac_part {
        // Parse up to 3 fractional digits, matching C behaviour.
        let mut multiplier = 100;
        for (i, byte) in frac.bytes().enumerate() {
            if !byte.is_ascii_digit() {
                // Check if remaining is whitespace.
                let rest = frac[i..].trim();
                if !rest.is_empty() {
                    return Err(ConfigError::ParseError {
                        file: String::new(),
                        line: 0,
                        message: format!("extra characters in fixed-point number: {input}"),
                    });
                }
                break;
            }
            if multiplier > 0 {
                result += (byte - b'0') as i32 * multiplier;
                multiplier /= 10;
            }
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Integer parsing helpers
// ---------------------------------------------------------------------------

/// Parse an integer value with optional K/M/G/T suffix multipliers.
///
/// Supports decimal (default), octal (0o prefix), and hexadecimal (0x prefix)
/// input. The K/M/G/T suffixes multiply by powers of 1024.
///
/// This handles `opt_int`, `opt_mkint`, and `opt_octint` from the C source.
fn parse_integer(input: &str, option_type: OptionType) -> Result<i64, ConfigError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(ConfigError::ParseError {
            file: String::new(),
            line: 0,
            message: "integer expected, got empty string".to_string(),
        });
    }

    // Handle optional leading sign.
    let (is_negative, unsigned_str) = if let Some(rest) = s.strip_prefix('-') {
        (true, rest)
    } else if let Some(rest) = s.strip_prefix('+') {
        (false, rest)
    } else {
        (false, s)
    };

    let (is_octal_forced, base_str) = if option_type == OptionType::OctInt {
        (true, unsigned_str)
    } else if let Some(hex) = unsigned_str
        .strip_prefix("0x")
        .or_else(|| unsigned_str.strip_prefix("0X"))
    {
        let value = parse_with_radix_and_suffix(hex, 16, s)?;
        return Ok(if is_negative { -value } else { value });
    } else if let Some(oct) = unsigned_str
        .strip_prefix("0o")
        .or_else(|| unsigned_str.strip_prefix("0O"))
    {
        (true, oct)
    } else {
        (false, unsigned_str)
    };

    let radix = if is_octal_forced { 8 } else { 10 };
    let value = parse_with_radix_and_suffix(base_str, radix, s)?;
    Ok(if is_negative { -value } else { value })
}

/// Parse a numeric string with the given radix, then apply K/M/G/T suffix.
fn parse_with_radix_and_suffix(
    digits: &str,
    radix: u32,
    original: &str,
) -> Result<i64, ConfigError> {
    // Find where the digit characters end.
    let digit_end = digits
        .bytes()
        .position(|b| {
            if radix == 16 {
                !b.is_ascii_hexdigit()
            } else if radix == 8 {
                !(b'0'..=b'7').contains(&b)
            } else {
                !b.is_ascii_digit()
            }
        })
        .unwrap_or(digits.len());

    if digit_end == 0 {
        return Err(ConfigError::ParseError {
            file: String::new(),
            line: 0,
            message: format!("integer expected for: {original}"),
        });
    }

    let num_str = &digits[..digit_end];
    let mut value = i64::from_str_radix(num_str, radix).map_err(|_| ConfigError::ParseError {
        file: String::new(),
        line: 0,
        message: format!("invalid integer: {original}"),
    })?;

    // Handle optional suffix.
    let suffix = digits[digit_end..].trim();
    if !suffix.is_empty() {
        let suffix_char = suffix.as_bytes()[0];
        let rest = suffix[1..].trim();
        if !rest.is_empty() {
            return Err(ConfigError::ParseError {
                file: String::new(),
                line: 0,
                message: format!("extra characters after integer value: {original}"),
            });
        }
        // Multiplier chain: T=1024^4, G=1024^3, M=1024^2, K=1024
        let multiplier: i64 = match suffix_char {
            b'T' | b't' => 1024_i64 * 1024 * 1024 * 1024,
            b'G' | b'g' => 1024_i64 * 1024 * 1024,
            b'M' | b'm' => 1024_i64 * 1024,
            b'K' | b'k' => 1024_i64,
            _ => {
                return Err(ConfigError::ParseError {
                    file: String::new(),
                    line: 0,
                    message: format!(
                        "unknown suffix '{suffix_char}' in integer: {original}",
                        suffix_char = suffix_char as char
                    ),
                })
            }
        };
        value = value
            .checked_mul(multiplier)
            .ok_or_else(|| ConfigError::ParseError {
                file: String::new(),
                line: 0,
                message: format!("integer overflow: {original}"),
            })?;
    }

    Ok(value)
}

// ---------------------------------------------------------------------------
// UID/GID parsing helpers
// ---------------------------------------------------------------------------

/// Resolve a username string to a numeric UID.
///
/// First attempts to parse the string as a numeric UID; on failure, looks
/// up the username via `nix::unistd::User::from_name()` (the POSIX
/// `getpwnam` wrapper).
fn resolve_uid(name: &str) -> Result<u32, ConfigError> {
    // Try numeric first.
    if let Ok(uid) = name.parse::<u32>() {
        return Ok(uid);
    }
    // Try name lookup.
    match nix::unistd::User::from_name(name) {
        Ok(Some(user)) => Ok(user.uid.as_raw()),
        Ok(None) => Err(ConfigError::ParseError {
            file: String::new(),
            line: 0,
            message: format!("user {name} was not found"),
        }),
        Err(e) => Err(ConfigError::ParseError {
            file: String::new(),
            line: 0,
            message: format!("error looking up user {name}: {e}"),
        }),
    }
}

/// Resolve a group name string to a numeric GID.
///
/// First attempts to parse the string as a numeric GID; on failure, looks
/// up the group via `nix::unistd::Group::from_name()` (the POSIX
/// `getgrnam` wrapper).
fn resolve_gid(name: &str) -> Result<u32, ConfigError> {
    // Try numeric first.
    if let Ok(gid) = name.parse::<u32>() {
        return Ok(gid);
    }
    // Try name lookup.
    match nix::unistd::Group::from_name(name) {
        Ok(Some(group)) => Ok(group.gid.as_raw()),
        Ok(None) => Err(ConfigError::ParseError {
            file: String::new(),
            line: 0,
            message: format!("group {name} was not found"),
        }),
        Err(e) => Err(ConfigError::ParseError {
            file: String::new(),
            line: 0,
            message: format!("error looking up group {name}: {e}"),
        }),
    }
}

/// Parse a colon-separated list of UIDs.
///
/// Each entry is resolved via [`resolve_uid`].
fn parse_uid_list(input: &str) -> Result<ExpandableIdList, ConfigError> {
    let s = input.trim();
    if s.is_empty() {
        return Ok(ExpandableIdList::Resolved(Vec::new()));
    }
    // If the value contains string expansions (${ or $variable), defer
    // resolution until runtime — the expansion engine will handle it.
    if s.contains('$') {
        return Ok(ExpandableIdList::Deferred(s.to_string()));
    }
    let uids: Result<Vec<u32>, ConfigError> =
        s.split(':').map(|part| resolve_uid(part.trim())).collect();
    Ok(ExpandableIdList::Resolved(uids?))
}

/// Parse a colon-separated list of GIDs.
///
/// Each entry is resolved via [`resolve_gid`].  If the value contains
/// string-expansion markers (`$`), the list is deferred for runtime expansion.
fn parse_gid_list(input: &str) -> Result<ExpandableIdList, ConfigError> {
    let s = input.trim();
    if s.is_empty() {
        return Ok(ExpandableIdList::Resolved(Vec::new()));
    }
    // Defer if value contains expansion syntax.
    if s.contains('$') {
        return Ok(ExpandableIdList::Deferred(s.to_string()));
    }
    let gids: Result<Vec<u32>, ConfigError> =
        s.split(':').map(|part| resolve_gid(part.trim())).collect();
    Ok(ExpandableIdList::Resolved(gids?))
}

// ---------------------------------------------------------------------------
// String parsing helpers
// ---------------------------------------------------------------------------

/// Dequote a possibly-quoted string value.
///
/// If the input starts with `"`, the function reads until the closing `"`
/// and processes C-style escape sequences (`\\`, `\"`, `\n`, `\t`, `\r`).
/// Otherwise, returns the input verbatim.
fn dequote_string(input: &str) -> Result<String, ConfigError> {
    dequote_string_for(input, None)
}

/// Dequote a string value.  When `opt_name` is `Some(name)` the check for
/// trailing characters after a closing `"` is enabled and will produce the
/// same error as C Exim: "extra characters follow string value for <name>".
fn dequote_string_for(input: &str, opt_name: Option<&str>) -> Result<String, ConfigError> {
    let s = input;
    if !s.starts_with('"') {
        return Ok(s.to_string());
    }

    let inner = &s[1..];
    let mut result = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    loop {
        match chars.next() {
            None => {
                return Err(ConfigError::ParseError {
                    file: String::new(),
                    line: 0,
                    message: "unterminated quoted string".to_string(),
                });
            }
            Some('"') => break,
            Some('\\') => match chars.next() {
                Some('\\') => result.push('\\'),
                Some('"') => result.push('"'),
                Some('n') => result.push('\n'),
                Some('t') => result.push('\t'),
                Some('r') => result.push('\r'),
                Some('0') => result.push('\0'),
                Some(c) => {
                    result.push('\\');
                    result.push(c);
                }
                None => {
                    return Err(ConfigError::ParseError {
                        file: String::new(),
                        line: 0,
                        message: "unterminated escape in quoted string".to_string(),
                    });
                }
            },
            Some(c) => result.push(c),
        }
    }

    // After the closing `"`, check for trailing characters.
    let remainder: String = chars.collect();
    let trimmed = remainder.trim();
    if !trimmed.is_empty() {
        if let Some(name) = opt_name {
            let comment = if trimmed.starts_with('#') {
                " (# is comment only at line start)"
            } else {
                ""
            };
            return Err(ConfigError::ParseError {
                file: String::new(),
                line: 0,
                message: format!("extra characters follow string value for {name}{comment}"),
            });
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// handle_option — main option processing (replaces C readconf_handle_option)
// ---------------------------------------------------------------------------

/// Parsed result of a single option assignment.
///
/// This structure captures the fully parsed option value along with its
/// metadata, ready for storage into a [`ConfigContext`] or driver data block.
#[derive(Debug, Clone)]
pub enum OptionValue {
    /// A string value (from `opt_stringptr`).
    Str(String),
    /// A boolean value (from `opt_bool`, `opt_bool_verify`, `opt_bool_set`).
    Bool(bool),
    /// An expandable boolean (from `opt_expand_bool`) — the value is an
    /// expansion string like `${if eq {0}{0}{yes}{no}}` that will be
    /// evaluated at runtime to determine the boolean result.
    ExpandBool(String),
    /// An integer value (from `opt_int`, `opt_mkint`, `opt_octint`).
    Int(i64),
    /// A time value in seconds (from `opt_time`).
    Time(i32),
    /// A list of time values in seconds (from `opt_timelist`).
    TimeList(Vec<i32>),
    /// A fixed-point value × 1000 (from `opt_fixed`).
    Fixed(i32),
    /// A resolved UID (from `opt_uid`).
    Uid(u32),
    /// A resolved GID (from `opt_gid`).
    Gid(u32),
    /// A list of UIDs (from `opt_uidlist`) — either resolved or deferred for
    /// later string expansion when the value contains `$` references.
    UidList(ExpandableIdList),
    /// A list of GIDs (from `opt_gidlist`) — either resolved or deferred for
    /// later string expansion when the value contains `$` references.
    GidList(ExpandableIdList),
    /// An expandable UID — either a resolved UID or a deferred `$`-prefixed
    /// string for later expansion.
    ExpandUid(ExpandableId),
    /// An expandable GID — either a resolved GID or a deferred `$`-prefixed
    /// string for later expansion.
    ExpandGid(ExpandableId),
    /// A rewrite rule string (from `opt_rewrite`), to be parsed into
    /// [`RewriteRule`] chains by the caller.
    Rewrite(String),
    /// A Kint value (from `opt_Kint`) — integer held in K units.
    Kint(i64),
    /// Func — custom handler, value is the raw string.
    Func(String),
    /// Module delegation (from `opt_misc_module` or `opt_lookup_module`).
    ModuleDelegate {
        /// The module name (e.g. "dkim", "ldap").
        module: String,
        /// The raw option line for the module to re-parse.
        line: String,
    },
}

/// Represents a UID or GID that may be deferred for string expansion.
#[derive(Debug, Clone)]
pub enum ExpandableId {
    /// The value was resolved immediately to a numeric ID.
    Resolved(u32),
    /// The value starts with `$` and is stored for later expansion.
    Deferred(String),
}

/// Represents a list of UIDs or GIDs that may contain deferred string
/// expansions (e.g. `${readfile{...}{:}}`).  When the raw value contains
/// `$`, the entire list is stored as a string for runtime expansion.
#[derive(Debug, Clone)]
pub enum ExpandableIdList {
    /// All entries were resolved immediately to numeric IDs.
    Resolved(Vec<u32>),
    /// The value contains `$` expansion syntax and must be expanded at
    /// runtime before splitting and resolving individual entries.
    Deferred(String),
}

/// The result of processing a single option line.
#[derive(Debug, Clone)]
pub struct HandleOptionResult {
    /// The canonical option name (with `no_`/`not_` prefix stripped).
    pub name: String,
    /// The parsed option value.
    pub value: OptionValue,
    /// Whether the `hide` prefix was specified.
    pub is_secure: bool,
    /// Whether this was a boolean negation (`no_` or `not_` prefix).
    pub is_negated: bool,
}

/// Process a single configuration option line.
///
/// This is the Rust equivalent of `readconf_handle_option()` (readconf.c
/// lines 1759–2530). It parses the line, looks up the option in the
/// provided table, and returns the typed value.
///
/// # Arguments
///
/// * `line` — The configuration line to process (whitespace-trimmed).
/// * `options` — The option table to search (must be sorted alphabetically).
/// * `_ctx` — The configuration context for storing results (reserved for
///   future use when the full config pipeline is wired up).
/// * `unknown_txt` — If `Some`, the format string for an error message when
///   an unknown option is encountered. If `None`, unknown options return
///   `Ok(None)` instead of an error.
///
/// # Returns
///
/// * `Ok(Some(result))` — The option was found and successfully parsed.
/// * `Ok(None)` — The option was not found and `unknown_txt` is `None`.
/// * `Err(ConfigError)` — A parse error occurred.
pub fn handle_option(
    line: &str,
    options: &mut [OptionEntry],
    _ctx: &mut ConfigContext,
    unknown_txt: Option<&str>,
) -> Result<Option<HandleOptionResult>, ConfigError> {
    let mut s = line.trim_start();
    if s.is_empty() {
        return Err(ConfigError::ParseError {
            file: String::new(),
            line: 0,
            message: "option setting expected: empty line".to_string(),
        });
    }

    // The first character must be alphabetic.
    if !s.as_bytes()[0].is_ascii_alphabetic() {
        return Err(ConfigError::ParseError {
            file: String::new(),
            line: 0,
            message: format!("option setting expected: {s}"),
        });
    }

    // Read the option name, handling `hide` prefix.
    let mut is_secure = false;
    let (mut name_str, mut remaining) = read_name(s);

    // If the first word is "hide", set the secure flag and read the real name.
    if name_str == "hide" {
        is_secure = true;
        s = remaining;
        let result = read_name(s);
        name_str = result.0;
        remaining = result.1;
        debug!(option = %name_str, "processing hidden (secure) option");
    }

    let full_name = name_str.to_string();

    // Handle `no_` / `not_` prefix for booleans.
    let mut is_negated = false;
    let lookup_name = if let Some(stripped) = full_name.strip_prefix("not_") {
        is_negated = true;
        stripped.to_string()
    } else if let Some(stripped) = full_name.strip_prefix("no_") {
        is_negated = true;
        stripped.to_string()
    } else {
        full_name.clone()
    };

    // Binary search for the option.
    let opt_index = match find_option(&lookup_name, options) {
        Some(idx) => idx,
        None => {
            if let Some(txt) = unknown_txt {
                return Err(ConfigError::UnknownOption(format!("{txt}: {full_name}")));
            }
            debug!(option = %full_name, "unknown option (ignored)");
            return Ok(None);
        }
    };

    // Check for duplicate setting.
    let entry = &options[opt_index];
    if entry.flags.contains(OptionFlags::SET)
        && !entry.flags.contains(OptionFlags::REP_CON)
        && !entry.flags.contains(OptionFlags::REP_STR)
    {
        error!(option = %full_name, "option set a second time");
        return Err(ConfigError::DuplicateOption(full_name));
    }

    // Mark as set (and secure if applicable).
    let entry_mut = &mut options[opt_index];
    entry_mut.flags.insert(OptionFlags::SET);
    if is_secure {
        entry_mut.flags.insert(OptionFlags::SECURE);
    }

    let option_type = entry_mut.option_type;

    // For non-boolean types, `=` is required.
    // For booleans, `=` is optional with explicit true/false/yes/no after it.
    s = remaining;

    match option_type {
        OptionType::Bool | OptionType::BoolVerify | OptionType::BoolSet => {
            // Boolean processing.
            //
            // C Exim treats many booleans as `opt_expand_bool`: the
            // value after `=` may be a string expansion like
            // `${if eq {0}{0}{yes}{no}}`.  In that case we store the
            // raw string as `expand_<name>` and set the static boolean
            // to `true` (the expansion decides the real value at
            // runtime).  For bare booleans and literal true/false/yes/no
            // we set the boolean directly.
            if s.is_empty() || s.starts_with('#') {
                // Bare option — value is true (or false if negated).
                let bool_value = !is_negated;
                trace!(option = %lookup_name, value = %bool_value, "parsed boolean option (bare)");
                Ok(Some(HandleOptionResult {
                    name: lookup_name,
                    value: OptionValue::Bool(bool_value),
                    is_secure,
                    is_negated,
                }))
            } else if let Some(after_eq) = s.strip_prefix('=') {
                let val_str = after_eq.trim();
                // Check for expansion string (starts with $ or contains $)
                if val_str.starts_with('$') || val_str.starts_with('"') {
                    // Expansion boolean — store as the expand_<name> string.
                    // The boolean itself defaults to true; the expansion
                    // will be evaluated at runtime to determine the real value.
                    trace!(
                        option = %lookup_name,
                        expand = %val_str,
                        "parsed boolean option with expansion string"
                    );
                    Ok(Some(HandleOptionResult {
                        name: lookup_name,
                        value: OptionValue::ExpandBool(val_str.to_string()),
                        is_secure,
                        is_negated,
                    }))
                } else {
                    let (val_name, _) = read_name(val_str);
                    let bool_value = match val_name.to_ascii_lowercase().as_str() {
                        "true" | "yes" => !is_negated,
                        "false" | "no" => is_negated,
                        _ => {
                            return Err(ConfigError::ParseError {
                                file: String::new(),
                                line: 0,
                                message: format!(
                                    "'{val_name}' is not a valid value for boolean option '{full_name}'"
                                ),
                            });
                        }
                    };
                    trace!(option = %lookup_name, value = %bool_value, "parsed boolean option");
                    Ok(Some(HandleOptionResult {
                        name: lookup_name,
                        value: OptionValue::Bool(bool_value),
                        is_secure,
                        is_negated,
                    }))
                }
            } else if is_negated {
                // Negated boolean with no `=` — just the name.
                trace!(option = %lookup_name, value = false, "parsed negated boolean option");
                Ok(Some(HandleOptionResult {
                    name: lookup_name,
                    value: OptionValue::Bool(false),
                    is_secure,
                    is_negated,
                }))
            } else {
                Err(ConfigError::ParseError {
                    file: String::new(),
                    line: 0,
                    message: format!("extra characters after boolean option '{full_name}'"),
                })
            }
        }

        OptionType::StringPtr => {
            // Non-boolean: require `=`.
            if is_negated {
                return Err(ConfigError::ParseError {
                    file: String::new(),
                    line: 0,
                    message: "negation prefix applied to a non-boolean option".to_string(),
                });
            }
            let after_eq = require_equals(s, &full_name)?;
            let raw_value = dequote_string_for(after_eq.trim(), Some(&full_name))?;

            // Handle opt_rep_con and opt_rep_str in the calling layer.
            trace!(option = %lookup_name, value = %raw_value, "parsed string option");
            Ok(Some(HandleOptionResult {
                name: lookup_name,
                value: OptionValue::Str(raw_value),
                is_secure,
                is_negated,
            }))
        }

        OptionType::Int | OptionType::Mkint | OptionType::OctInt => {
            if is_negated {
                return Err(ConfigError::ParseError {
                    file: String::new(),
                    line: 0,
                    message: "negation prefix applied to a non-boolean option".to_string(),
                });
            }
            let after_eq = require_equals(s, &full_name)?;
            let value = parse_integer(after_eq.trim(), option_type)?;
            trace!(option = %lookup_name, value = value, "parsed integer option");
            Ok(Some(HandleOptionResult {
                name: lookup_name,
                value: OptionValue::Int(value),
                is_secure,
                is_negated,
            }))
        }

        OptionType::Kint => {
            if is_negated {
                return Err(ConfigError::ParseError {
                    file: String::new(),
                    line: 0,
                    message: "negation prefix applied to a non-boolean option".to_string(),
                });
            }
            let after_eq = require_equals(s, &full_name)?;
            let value = parse_integer(after_eq.trim(), option_type)?;
            trace!(option = %lookup_name, value = value, "parsed Kint option");
            Ok(Some(HandleOptionResult {
                name: lookup_name,
                value: OptionValue::Kint(value),
                is_secure,
                is_negated,
            }))
        }

        OptionType::Time => {
            if is_negated {
                return Err(ConfigError::ParseError {
                    file: String::new(),
                    line: 0,
                    message: "negation prefix applied to a non-boolean option".to_string(),
                });
            }
            let after_eq = require_equals(s, &full_name)?;
            let value = parse_time(after_eq.trim())?;
            trace!(option = %lookup_name, value = value, "parsed time option");
            Ok(Some(HandleOptionResult {
                name: lookup_name,
                value: OptionValue::Time(value),
                is_secure,
                is_negated,
            }))
        }

        OptionType::TimeList => {
            if is_negated {
                return Err(ConfigError::ParseError {
                    file: String::new(),
                    line: 0,
                    message: "negation prefix applied to a non-boolean option".to_string(),
                });
            }
            let after_eq = require_equals(s, &full_name)?;
            let values = parse_time_list(after_eq.trim())?;
            trace!(option = %lookup_name, count = values.len(), "parsed time list option");
            Ok(Some(HandleOptionResult {
                name: lookup_name,
                value: OptionValue::TimeList(values),
                is_secure,
                is_negated,
            }))
        }

        OptionType::Fixed => {
            if is_negated {
                return Err(ConfigError::ParseError {
                    file: String::new(),
                    line: 0,
                    message: "negation prefix applied to a non-boolean option".to_string(),
                });
            }
            let after_eq = require_equals(s, &full_name)?;
            let value = parse_fixed(after_eq.trim())?;
            trace!(option = %lookup_name, value = value, "parsed fixed-point option");
            Ok(Some(HandleOptionResult {
                name: lookup_name,
                value: OptionValue::Fixed(value),
                is_secure,
                is_negated,
            }))
        }

        OptionType::Uid => {
            if is_negated {
                return Err(ConfigError::ParseError {
                    file: String::new(),
                    line: 0,
                    message: "negation prefix applied to a non-boolean option".to_string(),
                });
            }
            let after_eq = require_equals(s, &full_name)?;
            let raw = dequote_string(after_eq.trim())?;
            let uid = resolve_uid(&raw)?;
            trace!(option = %lookup_name, uid = uid, "parsed UID option");
            Ok(Some(HandleOptionResult {
                name: lookup_name,
                value: OptionValue::Uid(uid),
                is_secure,
                is_negated,
            }))
        }

        OptionType::Gid => {
            if is_negated {
                return Err(ConfigError::ParseError {
                    file: String::new(),
                    line: 0,
                    message: "negation prefix applied to a non-boolean option".to_string(),
                });
            }
            let after_eq = require_equals(s, &full_name)?;
            let raw = dequote_string(after_eq.trim())?;
            let gid = resolve_gid(&raw)?;
            trace!(option = %lookup_name, gid = gid, "parsed GID option");
            Ok(Some(HandleOptionResult {
                name: lookup_name,
                value: OptionValue::Gid(gid),
                is_secure,
                is_negated,
            }))
        }

        OptionType::UidList => {
            if is_negated {
                return Err(ConfigError::ParseError {
                    file: String::new(),
                    line: 0,
                    message: "negation prefix applied to a non-boolean option".to_string(),
                });
            }
            let after_eq = require_equals(s, &full_name)?;
            let raw = dequote_string(after_eq.trim())?;
            let uid_list = parse_uid_list(&raw)?;
            trace!(option = %lookup_name, "parsed UID list option");
            Ok(Some(HandleOptionResult {
                name: lookup_name,
                value: OptionValue::UidList(uid_list),
                is_secure,
                is_negated,
            }))
        }

        OptionType::GidList => {
            if is_negated {
                return Err(ConfigError::ParseError {
                    file: String::new(),
                    line: 0,
                    message: "negation prefix applied to a non-boolean option".to_string(),
                });
            }
            let after_eq = require_equals(s, &full_name)?;
            let raw = dequote_string(after_eq.trim())?;
            let gid_list = parse_gid_list(&raw)?;
            trace!(option = %lookup_name, "parsed GID list option");
            Ok(Some(HandleOptionResult {
                name: lookup_name,
                value: OptionValue::GidList(gid_list),
                is_secure,
                is_negated,
            }))
        }

        OptionType::ExpandUid => {
            if is_negated {
                return Err(ConfigError::ParseError {
                    file: String::new(),
                    line: 0,
                    message: "negation prefix applied to a non-boolean option".to_string(),
                });
            }
            let after_eq = require_equals(s, &full_name)?;
            let raw = dequote_string(after_eq.trim())?;
            let expand_val = if raw.starts_with('$') {
                ExpandableId::Deferred(raw)
            } else {
                ExpandableId::Resolved(resolve_uid(&raw)?)
            };
            trace!(option = %lookup_name, "parsed expand_uid option");
            Ok(Some(HandleOptionResult {
                name: lookup_name,
                value: OptionValue::ExpandUid(expand_val),
                is_secure,
                is_negated,
            }))
        }

        OptionType::ExpandGid => {
            if is_negated {
                return Err(ConfigError::ParseError {
                    file: String::new(),
                    line: 0,
                    message: "negation prefix applied to a non-boolean option".to_string(),
                });
            }
            let after_eq = require_equals(s, &full_name)?;
            let raw = dequote_string(after_eq.trim())?;
            let expand_val = if raw.starts_with('$') {
                ExpandableId::Deferred(raw)
            } else {
                ExpandableId::Resolved(resolve_gid(&raw)?)
            };
            trace!(option = %lookup_name, "parsed expand_gid option");
            Ok(Some(HandleOptionResult {
                name: lookup_name,
                value: OptionValue::ExpandGid(expand_val),
                is_secure,
                is_negated,
            }))
        }

        OptionType::Rewrite => {
            if is_negated {
                return Err(ConfigError::ParseError {
                    file: String::new(),
                    line: 0,
                    message: "negation prefix applied to a non-boolean option".to_string(),
                });
            }
            let after_eq = require_equals(s, &full_name)?;
            let raw = dequote_string(after_eq.trim())?;
            trace!(option = %lookup_name, "parsed rewrite option");
            Ok(Some(HandleOptionResult {
                name: lookup_name,
                value: OptionValue::Rewrite(raw),
                is_secure,
                is_negated,
            }))
        }

        OptionType::Func => {
            if is_negated {
                return Err(ConfigError::ParseError {
                    file: String::new(),
                    line: 0,
                    message: "negation prefix applied to a non-boolean option".to_string(),
                });
            }
            let after_eq = require_equals(s, &full_name)?;
            let raw = after_eq.trim().to_string();
            trace!(option = %lookup_name, "parsed func option");
            Ok(Some(HandleOptionResult {
                name: lookup_name,
                value: OptionValue::Func(raw),
                is_secure,
                is_negated,
            }))
        }

        OptionType::MiscModule | OptionType::LookupModule => {
            if is_negated {
                return Err(ConfigError::ParseError {
                    file: String::new(),
                    line: 0,
                    message: "negation prefix applied to a non-boolean option".to_string(),
                });
            }
            // Module delegation: the option name implies a module, and the
            // full line is passed to the module's own option table for
            // re-parsing.
            let module_name = lookup_name.clone();
            let raw_line = line.to_string();
            warn!(
                option = %module_name,
                "module-delegated option — module must handle sub-parsing"
            );
            Ok(Some(HandleOptionResult {
                name: lookup_name,
                value: OptionValue::ModuleDelegate {
                    module: module_name,
                    line: raw_line,
                },
                is_secure,
                is_negated,
            }))
        }
    }
}

/// Parse a rewrite rule specification string into a [`RewriteRule`].
///
/// The format is: `<pattern> <replacement> <flags>`
///
/// This is used when handling `opt_rewrite` option types. Each rewrite
/// rule line in the configuration is parsed by this function and added
/// to the rewrite chain.
///
/// # Arguments
///
/// * `input` — The raw rewrite rule string from the configuration file.
///
/// # Returns
///
/// A [`RewriteRule`] on success, or a `ConfigError` on parse failure.
pub fn parse_rewrite_rule(input: &str) -> Result<RewriteRule, ConfigError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(ConfigError::ParseError {
            file: String::new(),
            line: 0,
            message: "empty rewrite rule".to_string(),
        });
    }

    // Split into key (pattern), replacement, and flags.
    // The key and replacement are separated by whitespace.
    let (key, rest) = read_name_or_token(s);
    if key.is_empty() {
        return Err(ConfigError::ParseError {
            file: String::new(),
            line: 0,
            message: format!("invalid rewrite rule: {input}"),
        });
    }

    let rest = rest.trim_start();
    let (replacement, flags_str) = read_name_or_token(rest);

    // Parse flags — in C these are single-character flags packed into an int.
    // Here we store them as a raw u32 bitmask for compatibility.  Bit values
    // MUST match the canonical C definitions from `src/src/macros.h:791-813`
    // and the `readconf_one_rewrite()` switch in
    // `src/src/readconf.c:1584-1619`.  The C mapping is **case-sensitive**:
    // lowercase letters control header rewrites, uppercase letters control
    // envelope rewrites, and the remaining control flags (`S`, `Q`, `R`,
    // `w`, `q`) have dedicated bits.
    let mut flags: u32 = 0;
    for ch in flags_str.trim().bytes() {
        match ch {
            // Header rewrites (lowercase)
            b'h' => flags |= 0x003F, // rewrite_all_headers
            b's' => flags |= 0x0001, // rewrite_sender
            b'f' => flags |= 0x0002, // rewrite_from
            b't' => flags |= 0x0004, // rewrite_to
            b'c' => flags |= 0x0008, // rewrite_cc
            b'b' => flags |= 0x0010, // rewrite_bcc
            b'r' => flags |= 0x0020, // rewrite_replyto

            // Envelope rewrites (uppercase)
            b'E' => flags |= 0x00C0, // rewrite_all_envelope
            b'F' => flags |= 0x0040, // rewrite_envfrom
            b'T' => flags |= 0x0080, // rewrite_envto

            // Control flags
            b'S' => flags |= 0x0100, // rewrite_smtp (requires regex key in C)
            b'Q' => flags |= 0x0400, // rewrite_qualify
            b'R' => flags |= 0x0800, // rewrite_repeat
            b'w' => flags |= 0x1000, // rewrite_whole
            b'q' => flags |= 0x2000, // rewrite_quit

            // Whitespace is permitted between flags in C; continue rather
            // than break so that e.g. "t f" is accepted as (to | from).
            b' ' | b'\t' => continue,
            _ => {
                trace!(char = ?ch, "ignoring unknown rewrite flag");
            }
        }
    }

    trace!(key = %key, replacement = %replacement, flags = flags, "parsed rewrite rule");

    Ok(RewriteRule {
        key: key.to_string(),
        replacement: replacement.to_string(),
        flags,
    })
}

/// Read a non-whitespace token from the start of a string.
///
/// Unlike [`read_name`] which only accepts alphanumeric/underscore, this
/// reads any non-whitespace characters (used for rewrite patterns which
/// may contain special regex characters).
fn read_name_or_token(input: &str) -> (&str, &str) {
    let s = input.trim_start();
    if s.is_empty() {
        return ("", s);
    }
    let end = s
        .bytes()
        .position(|b| b.is_ascii_whitespace())
        .unwrap_or(s.len());
    let token = &s[..end];
    let rest = s[end..].trim_start();
    (token, rest)
}

/// Helper: require that the next non-whitespace character is `=` and return
/// the remainder of the string after the `=` sign.
fn require_equals<'a>(s: &'a str, option_name: &str) -> Result<&'a str, ConfigError> {
    let trimmed = s.trim_start();
    if trimmed.is_empty() {
        return Err(ConfigError::ParseError {
            file: String::new(),
            line: 0,
            message: format!("unexpected end of line (data missing) after {option_name}"),
        });
    }
    if let Some(after) = trimmed.strip_prefix('=') {
        Ok(after)
    } else {
        Err(ConfigError::ParseError {
            file: String::new(),
            line: 0,
            message: format!("missing '=' after {option_name}"),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- parse_time tests --

    #[test]
    fn test_parse_time_seconds() {
        assert_eq!(parse_time("30s").unwrap(), 30);
        assert_eq!(parse_time("0s").unwrap(), 0);
        assert_eq!(parse_time("120").unwrap(), 120);
    }

    #[test]
    fn test_parse_time_minutes() {
        assert_eq!(parse_time("5m").unwrap(), 300);
        assert_eq!(parse_time("1m30s").unwrap(), 90);
    }

    #[test]
    fn test_parse_time_hours() {
        assert_eq!(parse_time("2h").unwrap(), 7200);
        assert_eq!(parse_time("2h30m").unwrap(), 9000);
    }

    #[test]
    fn test_parse_time_days() {
        assert_eq!(parse_time("1d").unwrap(), 86400);
        assert_eq!(parse_time("1d12h").unwrap(), 129600);
    }

    #[test]
    fn test_parse_time_weeks() {
        assert_eq!(parse_time("1w").unwrap(), 604800);
        assert_eq!(parse_time("2w3d").unwrap(), 1468800);
    }

    #[test]
    fn test_parse_time_invalid() {
        assert!(parse_time("").is_err());
        assert!(parse_time("abc").is_err());
        assert!(parse_time("5x").is_err());
    }

    // -- parse_fixed tests --

    #[test]
    fn test_parse_fixed_integer() {
        assert_eq!(parse_fixed("42").unwrap(), 42000);
        assert_eq!(parse_fixed("0").unwrap(), 0);
    }

    #[test]
    fn test_parse_fixed_decimal() {
        assert_eq!(parse_fixed("1.5").unwrap(), 1500);
        assert_eq!(parse_fixed("0.333").unwrap(), 333);
        assert_eq!(parse_fixed("0.1").unwrap(), 100);
        assert_eq!(parse_fixed("0.01").unwrap(), 10);
        assert_eq!(parse_fixed("0.001").unwrap(), 1);
    }

    #[test]
    fn test_parse_fixed_invalid() {
        assert!(parse_fixed("").is_err());
        assert!(parse_fixed("abc").is_err());
    }

    // -- parse_time_list tests --

    #[test]
    fn test_parse_time_list_basic() {
        let result = parse_time_list("1m:5m:30m").unwrap();
        assert_eq!(result, vec![60, 300, 1800]);
    }

    #[test]
    fn test_parse_time_list_empty() {
        let result = parse_time_list("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_time_list_out_of_order() {
        assert!(parse_time_list("5m:1m").is_err());
    }

    // -- read_name tests --

    #[test]
    fn test_read_name_basic() {
        let (name, rest) = read_name("  smtp_accept_max = 100");
        assert_eq!(name, "smtp_accept_max");
        assert_eq!(rest, "= 100");
    }

    #[test]
    fn test_read_name_no_alpha() {
        let (name, _) = read_name("  123");
        assert_eq!(name, "");
    }

    // -- find_option tests --

    #[test]
    fn test_find_option_in_main_table() {
        let opts = main_config_options();
        // Every option should be findable.
        assert!(find_option("accept_8bitmime", &opts).is_some());
        assert!(find_option("write_rejectlog", &opts).is_some());
        assert!(find_option("spool_directory", &opts).is_some());
        assert!(find_option("nonexistent_option", &opts).is_none());
    }

    #[test]
    fn test_main_options_sorted() {
        let opts = main_config_options();
        for window in opts.windows(2) {
            assert!(
                window[0].name < window[1].name,
                "Options not sorted: '{}' >= '{}'",
                window[0].name,
                window[1].name
            );
        }
    }

    // -- integer parsing tests --

    #[test]
    fn test_parse_integer_decimal() {
        assert_eq!(parse_integer("42", OptionType::Int).unwrap(), 42);
        assert_eq!(parse_integer("-10", OptionType::Int).unwrap(), -10);
    }

    #[test]
    fn test_parse_integer_hex() {
        assert_eq!(parse_integer("0xFF", OptionType::Int).unwrap(), 255);
    }

    #[test]
    fn test_parse_integer_with_suffix() {
        assert_eq!(parse_integer("1K", OptionType::Int).unwrap(), 1024);
        assert_eq!(parse_integer("1M", OptionType::Int).unwrap(), 1048576);
        assert_eq!(parse_integer("1G", OptionType::Int).unwrap(), 1073741824);
    }

    #[test]
    fn test_parse_integer_octal() {
        assert_eq!(parse_integer("755", OptionType::OctInt).unwrap(), 0o755);
    }

    // -- dequote tests --

    #[test]
    fn test_dequote_unquoted() {
        assert_eq!(dequote_string("hello world").unwrap(), "hello world");
    }

    #[test]
    fn test_dequote_quoted() {
        assert_eq!(dequote_string(r#""hello world""#).unwrap(), "hello world");
    }

    #[test]
    fn test_dequote_escapes() {
        assert_eq!(dequote_string(r#""line1\nline2""#).unwrap(), "line1\nline2");
        assert_eq!(dequote_string(r#""tab\there""#).unwrap(), "tab\there");
    }

    #[test]
    fn test_dequote_unterminated() {
        assert!(dequote_string(r#""unterminated"#).is_err());
    }
}
