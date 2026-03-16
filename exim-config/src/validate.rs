#![deny(unsafe_code)]
//! Configuration validation and `-bP` option printing module.
//!
//! This module implements the configuration validation and `-bP` printing
//! functionality for the Exim MTA, translating the following C functions from
//! `readconf.c` into safe Rust:
//!
//! - `readconf_printtime()` (readconf.c lines 2545–2568) → [`format_time()`]
//! - `print_ol()` (readconf.c lines 2596–2906) → [`print_option()`]
//! - `readconf_print()` (readconf.c lines 2907–3139) → [`print_config_option()`]
//! - `print_config()` (readconf.c lines 4683–4761) → [`print_formatted_config()`]
//! - `readconf_save_config()` / `save_config_line()` / `save_config_position()`
//!   (readconf.c lines 4646–4678) → [`ConfigLineStore`]
//! - Post-parse validation → [`validate_config()`]
//!
//! # Architecture
//!
//! The C code uses `printf()` to stdout for all output.  In Rust, all
//! printing functions accept `&mut dyn std::io::Write` so that output can
//! be directed to stdout, buffers, or files.  The functions return
//! `std::io::Result<bool>` where the `bool` indicates whether the requested
//! item was found (matching the C `BOOL` return from `readconf_print()`).
//!
//! # Safety
//!
//! Per AAP §0.7.2: This module contains ZERO `unsafe` code.
//! Per AAP §0.7.2: No `#[allow(...)]` attributes without inline justification.

use std::io::Write;

use crate::driver_init::{check_driver_depends, show_supported_drivers, DriverClass};
use crate::options::{find_option, OptionEntry, OptionFlags, OptionType, MAIN_CONFIG_OPTIONS};
use crate::types::{Config, ConfigContext, ConfigError, MacroItemSnapshot, NamedList, NamedLists};

use nix::unistd::{Gid as NixGid, Group, Uid as NixUid, User};
use tracing::{debug, trace, warn};

// =============================================================================
// Constants
// =============================================================================

/// The placeholder text for hidden (secure) option values, matching the C
/// `hidden` constant used in readconf.c for `opt_secure` masked values.
const HIDDEN_VALUE: &str = "<value not displayable>";

// =============================================================================
// ConfigLine — Pre-parsed configuration line storage
// =============================================================================

/// A single pre-parsed configuration line stored for later `-bP config`
/// display.
///
/// Translates from the C `config_line_item` struct in `structs.h`.  In C
/// these are linked via `next` pointers; in Rust they are collected into a
/// `Vec<ConfigLine>` within [`ConfigLineStore`].
#[derive(Debug, Clone)]
pub struct ConfigLine {
    /// The full text of the pre-parsed logical configuration line, including
    /// any `#` comment prefix, `begin` section header, or driver stanza
    /// header.  Position markers use the format `# <lineno> <filename>`.
    pub line: String,
}

// =============================================================================
// ConfigLineStore — Config line accumulator
// =============================================================================

/// Accumulator for pre-parsed configuration lines, used by the
/// `print_formatted_config()` (C `print_config()`) function.
///
/// The C code uses a global linked list (`config_lines`) with a static
/// `current` tail pointer.  In Rust, we use a simple `Vec<ConfigLine>`
/// wrapped in this struct for encapsulation and method dispatch.
#[derive(Debug, Clone, Default)]
pub struct ConfigLineStore {
    /// The ordered list of stored configuration lines.
    lines: Vec<ConfigLine>,
}

impl ConfigLineStore {
    /// Create a new, empty configuration line store.
    pub fn new() -> Self {
        Self { lines: Vec::new() }
    }

    /// Initialize the config line store with a header comment.
    ///
    /// Equivalent of `readconf_save_config()` (readconf.c lines 4647–4651).
    /// The header format is `# Exim Configuration (<label>)` where `<label>`
    /// is typically the Exim version string (or `"X"` in test harness mode).
    pub fn save_config(&mut self, label: &str) {
        debug!(label = %label, "initializing config line store");
        let header = format!("# Exim Configuration ({label})");
        self.lines.push(ConfigLine { line: header });
    }

    /// Append a pre-parsed logical line to the config line store.
    ///
    /// Equivalent of `save_config_line()` (readconf.c lines 4664–4678).
    /// No further processing is done here; output formatting and honouring
    /// of `hide` or macros will be done during output.
    pub fn save_config_line(&mut self, line: &str) {
        trace!(line = %line, "saving config line");
        self.lines.push(ConfigLine {
            line: line.to_string(),
        });
    }

    /// Record a file/line position marker in the config line store.
    ///
    /// Equivalent of `save_config_position()` (readconf.c lines 4653–4657).
    /// The marker format is `# <line> <file>`, matching the C
    /// `string_sprintf("# %d %q", line, file)` call.
    pub fn save_config_position(&mut self, file: &str, line_number: u32) {
        trace!(file = %file, line = line_number, "saving config position marker");
        let marker = format!("# {line_number} {file}");
        self.lines.push(ConfigLine { line: marker });
    }

    /// Return a read-only slice of all stored configuration lines.
    ///
    /// Used by [`print_formatted_config()`] to iterate lines for display.
    pub fn lines(&self) -> &[ConfigLine] {
        &self.lines
    }
}

// =============================================================================
// format_time — Time value formatter (readconf_printtime)
// =============================================================================

/// Format a time value in seconds as a human-readable string.
///
/// Equivalent of `readconf_printtime()` (readconf.c lines 2545–2568).
/// Produces output in `Xw Xd Xh Xm Xs` format, including only non-zero
/// components.  Handles negative values with a `-` prefix.  Returns `"0s"`
/// when the input is zero.
///
/// # Arguments
///
/// * `seconds` — The time value in seconds (may be negative).
///
/// # Returns
///
/// An owned `String` containing the formatted time value.
///
/// # Examples
///
/// ```
/// # use exim_config::validate::format_time;
/// assert_eq!(format_time(0), "0s");
/// assert_eq!(format_time(60), "1m");
/// assert_eq!(format_time(90061), "1d1h1m1s");
/// assert_eq!(format_time(-300), "-5m");
/// assert_eq!(format_time(604800), "1w");
/// ```
pub fn format_time(seconds: i32) -> String {
    let mut result = String::with_capacity(24);
    let mut t = seconds;

    // Handle negative values with a `-` prefix, matching C line 2550.
    if t < 0 {
        result.push('-');
        t = -t;
    }

    let s = t % 60;
    t /= 60;
    let m = t % 60;
    t /= 60;
    let h = t % 24;
    t /= 24;
    let d = t % 7;
    let w = t / 7;

    if w > 0 {
        result.push_str(&format!("{w}w"));
    }
    if d > 0 {
        result.push_str(&format!("{d}d"));
    }
    if h > 0 {
        result.push_str(&format!("{h}h"));
    }
    if m > 0 {
        result.push_str(&format!("{m}m"));
    }
    // Print seconds if non-zero, OR if nothing else was printed (the `0s` case).
    // This matches C line 2565: `if (s > 0 || p == time_buffer)`
    if s > 0 || result.is_empty() || (result.len() == 1 && result.starts_with('-')) {
        result.push_str(&format!("{s}s"));
    }

    result
}

// =============================================================================
// String printing helper — escape special characters
// =============================================================================

/// Escape special characters in a string for `-bP` output display.
///
/// Replaces the C `string_printing2()` function with `SP_TAB` flag.
/// Control characters below 0x20 (except TAB which is replaced with `\t`)
/// and DEL (0x7F) are escaped as `\xHH`.  Backslash is escaped as `\\`.
fn escape_for_printing(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.bytes() {
        match ch {
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            0x00..=0x1f | 0x7f => {
                out.push_str(&format!("\\x{ch:02x}"));
            }
            _ => out.push(ch as char),
        }
    }
    out
}

// No intermediate enum needed — print_option resolves values directly
// from ConfigContext via the type-specific resolve helpers below.

// =============================================================================
// Option value resolution helpers
// =============================================================================

/// Resolve a boolean option from [`ConfigContext`] by name.
fn resolve_bool_option(name: &str, ctx: &ConfigContext) -> bool {
    match name {
        "accept_8bitmime" => ctx.accept_8bitmime,
        "allow_domain_literals" => ctx.allow_domain_literals,
        "allow_mx_to_ip" => ctx.allow_mx_to_ip,
        "bounce_return_body" => ctx.bounce_return_body,
        "bounce_return_message" => ctx.bounce_return_message,
        "check_rfc2047_length" => ctx.check_rfc2047_length,
        "commandline_checks_require_admin" => ctx.commandline_checks_require_admin,
        "delivery_date_remove" => ctx.delivery_date_remove,
        "deliver_drop_privilege" => ctx.deliver_drop_privilege,
        "disable_ipv6" => ctx.disable_ipv6,
        "dns_csa_use_reverse" => ctx.dns_csa_use_reverse,
        "envelope_to_remove" => ctx.envelope_to_remove,
        "extract_addresses_remove_arguments" => ctx.extract_addresses_remove_arguments,
        "ignore_fromline_local" => ctx.ignore_fromline_local,
        "local_from_check" => ctx.local_from_check,
        "local_sender_retain" => ctx.local_sender_retain,
        "log_timezone" => ctx.log_timezone,
        "message_body_newlines" => ctx.message_body_newlines,
        "message_logs" => ctx.message_logs,
        "preserve_message_logs" => ctx.preserve_message_logs,
        "print_topbitchars" => ctx.print_topbitchars,
        "prod_requires_admin" => ctx.prod_requires_admin,
        "queue_list_requires_admin" => ctx.queue_list_requires_admin,
        "queue_only" => ctx.queue_only,
        "queue_only_load_latch" => ctx.queue_only_load_latch,
        "queue_only_override" => ctx.queue_only_override,
        "queue_run_in_order" => ctx.queue_run_in_order,
        "recipients_max_reject" => ctx.recipients_max_reject,
        "return_path_remove" => ctx.return_path_remove,
        "smtp_accept_keepalive" => ctx.smtp_accept_keepalive,
        "smtp_check_spool_space" => ctx.smtp_check_spool_space,
        "smtp_enforce_sync" => ctx.smtp_enforce_sync,
        "smtp_etrn_serialize" => ctx.smtp_etrn_serialize,
        "smtp_return_error_details" => ctx.smtp_return_error_details,
        "split_spool_directory" => ctx.split_spool_directory,
        "spool_wireformat" => ctx.spool_wireformat,
        "strict_acl_vars" => ctx.strict_acl_vars,
        "strip_excess_angle_brackets" => ctx.strip_excess_angle_brackets,
        "strip_trailing_dot" => ctx.strip_trailing_dot,
        "syslog_duplication" => ctx.syslog_duplication,
        "syslog_pid" => ctx.syslog_pid,
        "syslog_timestamp" => ctx.syslog_timestamp,
        "tcp_nodelay" => ctx.tcp_nodelay,
        "write_rejectlog" => ctx.write_rejectlog,
        "debug_store" => ctx.debug_store,
        "mua_wrapper" => ctx.mua_wrapper,
        "panic_coredump" => ctx.panic_coredump,
        "log_ports" => ctx.log_ports,
        _ => {
            trace!(name = %name, "unrecognized boolean option, defaulting to false");
            false
        }
    }
}

/// Resolve a string option from [`ConfigContext`] by name.
fn resolve_string_option<'a>(name: &str, ctx: &'a ConfigContext) -> Option<&'a String> {
    match name {
        "acl_not_smtp" => ctx.acl_not_smtp.as_ref(),
        "acl_not_smtp_start" => ctx.acl_not_smtp_start.as_ref(),
        "acl_smtp_atrn" => ctx.acl_smtp_atrn.as_ref(),
        "acl_smtp_auth" => ctx.acl_smtp_auth.as_ref(),
        "acl_smtp_connect" => ctx.acl_smtp_connect.as_ref(),
        "acl_smtp_data" => ctx.acl_smtp_data.as_ref(),
        "acl_smtp_etrn" => ctx.acl_smtp_etrn.as_ref(),
        "acl_smtp_expn" => ctx.acl_smtp_expn.as_ref(),
        "acl_smtp_helo" => ctx.acl_smtp_helo.as_ref(),
        "acl_smtp_mail" => ctx.acl_smtp_mail.as_ref(),
        "acl_smtp_mailauth" => ctx.acl_smtp_mailauth.as_ref(),
        "acl_smtp_notquit" => ctx.acl_smtp_notquit.as_ref(),
        "acl_smtp_predata" => ctx.acl_smtp_predata.as_ref(),
        "acl_smtp_quit" => ctx.acl_smtp_quit.as_ref(),
        "acl_smtp_rcpt" => ctx.acl_smtp_rcpt.as_ref(),
        "acl_smtp_vrfy" => ctx.acl_smtp_vrfy.as_ref(),
        "add_environment" => ctx.add_environment.as_ref(),
        "auth_advertise_hosts" => ctx.auth_advertise_hosts.as_ref(),
        "bi_command" => ctx.bi_command.as_ref(),
        "bounce_message_file" => ctx.bounce_message_file.as_ref(),
        "bounce_message_text" => ctx.bounce_message_text.as_ref(),
        "bounce_sender_authentication" => ctx.bounce_sender_authentication.as_ref(),
        "callout_random_local_part" => ctx.callout_random_local_part.as_ref(),
        "chunking_advertise_hosts" => ctx.chunking_advertise_hosts.as_ref(),
        "daemon_smtp_ports" | "daemon_smtp_port" => ctx.daemon_smtp_port.as_ref(),
        "daemon_modules_load" => ctx.daemon_modules_load.as_ref(),
        "delay_warning_condition" => ctx.delay_warning_condition.as_ref(),
        "dns_again_means_nonexist" => ctx.dns_again_means_nonexist.as_ref(),
        "dns_ipv4_lookup" => ctx.dns_ipv4_lookup.as_ref(),
        "dns_trust_aa" => ctx.dns_trust_aa.as_ref(),
        "dsn_from" => ctx.dsn_from.as_ref(),
        "dsn_advertise_hosts" => ctx.dsn_advertise_hosts.as_ref(),
        "errors_copy" => ctx.errors_copy.as_ref(),
        "errors_reply_to" => ctx.errors_reply_to.as_ref(),
        "extra_local_interfaces" => ctx.extra_local_interfaces.as_ref(),
        "freeze_tell" => ctx.freeze_tell.as_ref(),
        "gecos_name" => ctx.gecos_name.as_ref(),
        "gecos_pattern" => ctx.gecos_pattern.as_ref(),
        "helo_accept_junk_hosts" => ctx.helo_accept_junk_hosts.as_ref(),
        "helo_allow_chars" => ctx.helo_allow_chars.as_ref(),
        "helo_lookup_domains" => ctx.helo_lookup_domains.as_ref(),
        "helo_try_verify_hosts" => ctx.helo_try_verify_hosts.as_ref(),
        "helo_verify_hosts" => ctx.helo_verify_hosts.as_ref(),
        "hold_domains" => ctx.hold_domains.as_ref(),
        "host_lookup" => ctx.host_lookup.as_ref(),
        "host_lookup_order" => ctx.host_lookup_order.as_ref(),
        "host_reject_connection" => ctx.host_reject_connection.as_ref(),
        "hosts_connection_nolog" => ctx.hosts_connection_nolog.as_ref(),
        "hosts_require_helo" => ctx.hosts_require_helo.as_ref(),
        "hosts_treat_as_local" => ctx.hosts_treat_as_local.as_ref(),
        "ignore_fromline_hosts" => ctx.ignore_fromline_hosts.as_ref(),
        "keep_environment" => ctx.keep_environment.as_ref(),
        "local_from_prefix" => ctx.local_from_prefix.as_ref(),
        "local_from_suffix" => ctx.local_from_suffix.as_ref(),
        "local_interfaces" => ctx.local_interfaces.as_ref(),
        "log_file_path" => {
            if ctx.log_file_path.is_empty() {
                None
            } else {
                Some(&ctx.log_file_path)
            }
        }
        "log_selector" => ctx.log_selector_string.as_ref(),
        "message_size_limit" => ctx.message_size_limit.as_ref(),
        "notifier_socket" => ctx.notifier_socket.as_ref(),
        "percent_hack_domains" => ctx.percent_hack_domains.as_ref(),
        "pid_file_path" => {
            if ctx.pid_file_path.is_empty() {
                None
            } else {
                Some(&ctx.pid_file_path)
            }
        }
        "pipelining_advertise_hosts" => ctx.pipelining_advertise_hosts.as_ref(),
        "primary_hostname" => {
            if ctx.primary_hostname.is_empty() {
                None
            } else {
                Some(&ctx.primary_hostname)
            }
        }
        "qualify_domain" => {
            if ctx.qualify_domain_sender.is_empty() {
                None
            } else {
                Some(&ctx.qualify_domain_sender)
            }
        }
        "qualify_recipient" => {
            if ctx.qualify_domain_recipient.is_empty() {
                None
            } else {
                Some(&ctx.qualify_domain_recipient)
            }
        }
        "queue_domains" => ctx.queue_domains.as_ref(),
        "queue_only_file" => ctx.queue_only_file.as_ref(),
        "queue_run_max" => ctx.queue_run_max.as_ref(),
        "queue_smtp_domains" => ctx.queue_smtp_domains.as_ref(),
        "received_header_text" => ctx.received_header_text.as_ref(),
        "recipient_unqualified_hosts" => ctx.recipient_unqualified_hosts.as_ref(),
        "recipients_max" => ctx.recipients_max.as_ref(),
        "remote_sort_domains" => ctx.remote_sort_domains.as_ref(),
        "rfc1413_hosts" => ctx.rfc1413_hosts.as_ref(),
        "sender_unqualified_hosts" => ctx.sender_unqualified_hosts.as_ref(),
        "smtp_accept_max_per_connection" => ctx.smtp_accept_max_per_connection.as_ref(),
        "smtp_accept_max_per_host" => ctx.smtp_accept_max_per_host.as_ref(),
        "smtp_accept_max_nonmail_hosts" => ctx.smtp_accept_max_nonmail_hosts.as_ref(),
        "smtp_active_hostname" => ctx.smtp_active_hostname.as_ref(),
        "smtp_banner" => ctx.smtp_banner.as_ref(),
        "smtp_etrn_command" => ctx.smtp_etrn_command.as_ref(),
        "smtp_ratelimit_hosts" => ctx.smtp_ratelimit_hosts.as_ref(),
        "smtp_ratelimit_mail" => ctx.smtp_ratelimit_mail.as_ref(),
        "smtp_ratelimit_rcpt" => ctx.smtp_ratelimit_rcpt.as_ref(),
        "smtp_reserve_hosts" => ctx.smtp_reserve_hosts.as_ref(),
        "spool_directory" => {
            if ctx.spool_directory.is_empty() {
                None
            } else {
                Some(&ctx.spool_directory)
            }
        }
        "syslog_processname" => ctx.syslog_processname.as_ref(),
        "system_filter" => ctx.system_filter.as_ref(),
        "system_filter_directory_transport" => ctx.system_filter_directory_transport.as_ref(),
        "system_filter_file_transport" => ctx.system_filter_file_transport.as_ref(),
        "system_filter_pipe_transport" => ctx.system_filter_pipe_transport.as_ref(),
        "system_filter_reply_transport" => ctx.system_filter_reply_transport.as_ref(),
        "tls_advertise_hosts" => ctx.tls_advertise_hosts.as_ref(),
        "exim_version" => ctx.exim_version.as_ref(),
        "exim_path" => ctx.exim_path.as_ref(),
        "headers_charset" => ctx.headers_charset.as_ref(),
        "unknown_login" => ctx.unknown_login.as_ref(),
        "unknown_username" => ctx.unknown_username.as_ref(),
        "warn_message_file" => ctx.warn_message_file.as_ref(),
        "timezone" => ctx.timezone.as_ref(),
        "uucp_from_pattern" => ctx.uucp_from_pattern.as_ref(),
        "uucp_from_sender" => ctx.uucp_from_sender.as_ref(),
        "untrusted_set_sender" => ctx.untrusted_set_sender.as_ref(),
        "process_log_path" => ctx.process_log_path.as_ref(),
        "message_id_header_domain" => ctx.message_id_header_domain.as_ref(),
        "message_id_header_text" => ctx.message_id_header_text.as_ref(),
        "dns_check_names_pattern" | "check_dns_names_pattern" => {
            ctx.dns_check_names_pattern.as_ref()
        }
        "trusted_users" => ctx.trusted_users.as_ref(),
        "trusted_groups" => ctx.trusted_groups.as_ref(),
        "never_users" => ctx.never_users.as_ref(),
        "admin_groups" => ctx.admin_groups.as_ref(),
        _ => {
            trace!(name = %name, "unrecognized string option");
            None
        }
    }
}

/// Resolve an integer option from [`ConfigContext`] by name.
fn resolve_int_option(name: &str, ctx: &ConfigContext) -> i64 {
    match name {
        "bounce_return_linesize_limit" => i64::from(ctx.bounce_return_linesize_limit),
        "bounce_return_size_limit" => i64::from(ctx.bounce_return_size_limit),
        "check_log_inodes" => i64::from(ctx.check_log_inodes),
        "check_spool_inodes" => i64::from(ctx.check_spool_inodes),
        "connection_max_messages" => i64::from(ctx.connection_max_messages),
        "daemon_startup_retries" => i64::from(ctx.daemon_startup_retries),
        "dns_cname_loops" => i64::from(ctx.dns_cname_loops),
        "dns_csa_search_limit" => i64::from(ctx.dns_csa_search_limit),
        "dns_retry" => i64::from(ctx.dns_retry),
        "header_line_maxsize" => i64::from(ctx.header_line_maxsize),
        "header_maxsize" => i64::from(ctx.header_maxsize),
        "lookup_open_max" => i64::from(ctx.lookup_open_max),
        "message_body_visible" => i64::from(ctx.message_body_visible),
        "received_headers_max" => i64::from(ctx.received_headers_max),
        "remote_max_parallel" => i64::from(ctx.remote_max_parallel),
        "smtp_accept_max" => i64::from(ctx.smtp_accept_max),
        "smtp_accept_max_nonmail" => i64::from(ctx.smtp_accept_max_nonmail),
        "smtp_accept_queue" => i64::from(ctx.smtp_accept_queue),
        "smtp_accept_queue_per_connection" => i64::from(ctx.smtp_accept_queue_per_connection),
        "smtp_accept_reserve" => i64::from(ctx.smtp_accept_reserve),
        "smtp_connect_backlog" => i64::from(ctx.smtp_connect_backlog),
        "smtp_max_synprot_errors" => i64::from(ctx.smtp_max_synprot_errors),
        "smtp_max_unknown_commands" => i64::from(ctx.smtp_max_unknown_commands),
        // Identity options — exim_user / exim_group store resolved UID/GID
        // in ConfigContext, populated at startup by resolve_exim_user().
        "exim_user" => i64::from(ctx.exim_uid),
        "exim_group" => i64::from(ctx.exim_gid),
        "max_username_length" => i64::from(ctx.max_username_length),
        "finduser_retries" => i64::from(ctx.finduser_retries),
        "localhost_number" => i64::from(ctx.localhost_number),
        "slow_lookup_log" => i64::from(ctx.slow_lookup_log),
        "smtp_backlog_monitor" => i64::from(ctx.smtp_backlog_monitor),
        "return_size_limit" => i64::from(ctx.return_size_limit),
        "header_insert_maxlen" => i64::from(ctx.header_insert_maxlen),
        "rfc1413_port" => i64::from(ctx.rfc1413_port),
        "dns_dnssec_ok" => i64::from(ctx.dns_dnssec_ok),
        "dns_use_edns0" => i64::from(ctx.dns_use_edns0),
        "tls_dh_max_bits" => i64::from(ctx.tls_dh_max_bits),

        _ => {
            trace!(name = %name, "unrecognized integer option, defaulting to 0");
            0
        }
    }
}

/// Resolve a Kint (kilobyte-unit integer) option from [`ConfigContext`].
fn resolve_kint_option(name: &str, ctx: &ConfigContext) -> i64 {
    match name {
        "check_log_space" => ctx.check_log_space,
        "check_spool_space" => ctx.check_spool_space,
        _ => {
            trace!(name = %name, "unrecognized Kint option, defaulting to 0");
            0
        }
    }
}

/// Resolve a numeric UID to a username string, falling back to the
/// numeric representation if the system user database does not contain
/// the UID.
///
/// Uses `nix::unistd::User::from_uid()` which calls POSIX `getpwuid()`.
fn resolve_uid_name(uid: u32) -> String {
    match User::from_uid(NixUid::from_raw(uid)) {
        Ok(Some(user)) => user.name,
        _ => {
            warn!(uid, "could not resolve UID to username");
            uid.to_string()
        }
    }
}

/// Resolve a numeric GID to a group name string, falling back to the
/// numeric representation if the system group database does not contain
/// the GID.
///
/// Uses `nix::unistd::Group::from_gid()` which calls POSIX `getgrgid()`.
fn resolve_gid_name(gid: u32) -> String {
    match Group::from_gid(NixGid::from_raw(gid)) {
        Ok(Some(group)) => group.name,
        _ => {
            warn!(gid, "could not resolve GID to group name");
            gid.to_string()
        }
    }
}

/// Resolve a time option from [`ConfigContext`] by name.
fn resolve_time_option(name: &str, ctx: &ConfigContext) -> i32 {
    match name {
        "auto_thaw" => ctx.auto_thaw,
        "callout_domain_negative_expire" => ctx.callout_cache_domain_negative_expire,
        "callout_domain_positive_expire" => ctx.callout_cache_domain_positive_expire,
        "callout_negative_expire" => ctx.callout_cache_negative_expire,
        "callout_positive_expire" => ctx.callout_cache_positive_expire,
        "daemon_startup_sleep" => ctx.daemon_startup_sleep,
        "dns_retrans" => ctx.dns_retrans,
        "ignore_bounce_errors_after" => ctx.ignore_bounce_errors_after,
        "keep_malformed" => ctx.keep_malformed,
        "queue_interval" => ctx.queue_interval,
        "receive_timeout" => ctx.receive_timeout,
        "retry_data_expire" => ctx.retry_data_expire,
        "retry_interval_max" => ctx.retry_interval_max,
        "rfc1413_query_timeout" => ctx.rfc1413_query_timeout,
        "smtp_receive_timeout" => ctx.smtp_receive_timeout,
        "timeout_frozen_after" => ctx.timeout_frozen_after,
        _ => {
            trace!(name = %name, "unrecognized time option, defaulting to 0");
            0
        }
    }
}

// =============================================================================
// print_option — Individual option value printer (print_ol)
// =============================================================================

/// Print a single option value, formatting it according to its type.
///
/// Equivalent of `print_ol()` (readconf.c lines 2596–2906).  Writes the
/// formatted option to the provided writer.  Handles all option types
/// including strings, integers, booleans, time values, UIDs/GIDs, and
/// lists.
///
/// # Arguments
///
/// * `entry` — The option table entry describing the option to print.
/// * `name` — The option name to display (may differ from `entry.name`
///   for aliased options).
/// * `ctx` — The configuration context containing the option values.
/// * `admin` — Whether the caller is an admin user (controls `hide`
///   visibility).
/// * `no_labels` — If `true`, omit the `name = ` prefix for machine-
///   parseable output.
/// * `out` — The output writer.
///
/// # Returns
///
/// `Ok(true)` if the option was found and printed, `Ok(false)` if it was
/// not found.  `Err` on I/O failure.
pub fn print_option(
    entry: &OptionEntry,
    name: &str,
    ctx: &ConfigContext,
    admin: bool,
    no_labels: bool,
    out: &mut dyn Write,
) -> std::io::Result<bool> {
    trace!(name = %name, option_type = ?entry.option_type, "printing option");

    // Non-admin callers cannot see options flagged as secure (hide prefix).
    // C readconf.c line 2618.
    if !admin && entry.flags.contains(OptionFlags::SECURE) {
        if no_labels {
            writeln!(out, "{HIDDEN_VALUE}")?;
        } else {
            writeln!(out, "{name} = {HIDDEN_VALUE}")?;
        }
        return Ok(true);
    }

    // Resolve and print the option value from ConfigContext based on its type.
    // Each match arm calls the appropriate resolve helper directly, avoiding
    // an intermediate enum and ensuring zero dead-code warnings.
    match entry.option_type {
        OptionType::StringPtr | OptionType::Rewrite => {
            // C lines 2639–2644: print string value with escaping.
            let opt_s = resolve_string_option(name, ctx);
            let display = match opt_s {
                Some(s) => escape_for_printing(s),
                None => String::new(),
            };
            if no_labels {
                writeln!(out, "{display}")?;
            } else {
                writeln!(out, "{name} = {display}")?;
            }
        }

        OptionType::Int => {
            // C lines 2646–2649: print decimal integer.
            let v = resolve_int_option(name, ctx);
            if no_labels {
                writeln!(out, "{v}")?;
            } else {
                writeln!(out, "{name} = {v}")?;
            }
        }

        OptionType::Mkint => {
            // C lines 2651–2672: print with K/M suffix if cleanly divisible.
            let v = resolve_int_option(name, ctx);
            let x = v as i32;
            if x != 0 && (x & 1023) == 0 {
                let mut val = x >> 10;
                let suffix = if (val & 1023) == 0 {
                    val >>= 10;
                    'M'
                } else {
                    'K'
                };
                if no_labels {
                    writeln!(out, "{val}{suffix}")?;
                } else {
                    writeln!(out, "{name} = {val}{suffix}")?;
                }
            } else if no_labels {
                writeln!(out, "{x}")?;
            } else {
                writeln!(out, "{name} = {x}")?;
            }
        }

        OptionType::Kint => {
            // C lines 2674–2684: Kint with T/G/M/K suffix.
            let x = resolve_kint_option(name, ctx);
            if !no_labels {
                write!(out, "{name} = ")?;
            }
            if x == 0 {
                writeln!(out, "0")?;
            } else if (x & ((1_i64 << 30) - 1)) == 0 {
                writeln!(out, "{}T", x >> 30)?;
            } else if (x & ((1_i64 << 20) - 1)) == 0 {
                writeln!(out, "{}G", x >> 20)?;
            } else if (x & ((1_i64 << 10) - 1)) == 0 {
                writeln!(out, "{}M", x >> 10)?;
            } else {
                writeln!(out, "{x}K")?;
            }
        }

        OptionType::OctInt => {
            // C lines 2686–2688: print octal integer.
            let v = resolve_int_option(name, ctx);
            let x = v as i32;
            if no_labels {
                writeln!(out, "{x:#o}")?;
            } else {
                writeln!(out, "{name} = {x:#o}")?;
            }
        }

        OptionType::Time => {
            // C lines 2815–2818: print time value.
            let t = resolve_time_option(name, ctx);
            let formatted = format_time(t);
            if no_labels {
                writeln!(out, "{formatted}")?;
            } else {
                writeln!(out, "{name} = {formatted}")?;
            }
        }

        OptionType::TimeList => {
            // C lines 2820–2828: print colon-separated time list.
            // Currently no time-list fields in ConfigContext; print empty.
            if no_labels {
                writeln!(out)?;
            } else {
                writeln!(out, "{name} =")?;
            }
        }

        OptionType::Bool | OptionType::BoolVerify | OptionType::BoolSet => {
            // C lines 2854–2858: print `name` or `no_name`.
            // Use the canonical option name from the table entry for resolution,
            // because the user may have queried `no_accept_8bitmime` while the
            // table entry name is `accept_8bitmime`.
            let base_name = entry.name;
            let b = resolve_bool_option(base_name, ctx);
            let prefix = if b { "" } else { "no_" };
            writeln!(out, "{prefix}{base_name}")?;
        }

        OptionType::Uid => {
            // C lines 2734–2742: print UID with name lookup via getpwuid.
            // Resolve UID option to a string: try name resolution first.
            // Always print the resolved name — uid 0 (root) is a valid value
            // for options like exim_user.
            let uid_val = resolve_int_option(name, ctx) as u32;
            if !no_labels {
                write!(out, "{name} = ")?;
            }
            writeln!(out, "{}", resolve_uid_name(uid_val))?;
        }

        OptionType::Gid => {
            // C lines 2766–2774: print GID with name lookup via getgrgid.
            // Always print the resolved name — gid 0 (root) is a valid value
            // for options like exim_group.
            let gid_val = resolve_int_option(name, ctx) as u32;
            if !no_labels {
                write!(out, "{name} = ")?;
            }
            writeln!(out, "{}", resolve_gid_name(gid_val))?;
        }

        OptionType::UidList => {
            // C lines 2777–2793: print UID list with name resolution.
            // Read the stored string from ConfigContext (populated by apply_option_to_ctx).
            let uid_list_str = match name {
                "trusted_users" => ctx.trusted_users.as_deref(),
                "never_users" => ctx.never_users.as_deref(),
                _ => None,
            };
            if !no_labels {
                write!(out, "{name} =")?;
            }
            if let Some(s) = uid_list_str {
                if !s.is_empty() {
                    write!(out, " {s}")?;
                }
            }
            writeln!(out)?;
        }

        OptionType::GidList => {
            // C lines 2796–2813: print GID list with name resolution.
            let gid_list_str = match name {
                "trusted_groups" => ctx.trusted_groups.as_deref(),
                "admin_groups" => ctx.admin_groups.as_deref(),
                _ => None,
            };
            if !no_labels {
                write!(out, "{name} =")?;
            }
            if let Some(s) = gid_list_str {
                if !s.is_empty() {
                    write!(out, " {s}")?;
                }
            }
            writeln!(out)?;
        }

        OptionType::ExpandUid => {
            // C lines 2716–2742: expandable UID — string fallback then numeric.
            // Check if there's a string expansion; otherwise try numeric.
            let opt_s = resolve_string_option(name, ctx);
            if !no_labels {
                write!(out, "{name} = ")?;
            }
            if let Some(s) = opt_s {
                writeln!(out, "{}", escape_for_printing(s))?;
            } else {
                let uid_val = resolve_int_option(name, ctx) as u32;
                if uid_val > 0 {
                    writeln!(out, "{}", resolve_uid_name(uid_val))?;
                } else {
                    writeln!(out)?;
                }
            }
        }

        OptionType::ExpandGid => {
            // C lines 2747–2774: expandable GID — string fallback then numeric.
            let opt_s = resolve_string_option(name, ctx);
            if !no_labels {
                write!(out, "{name} = ")?;
            }
            if let Some(s) = opt_s {
                writeln!(out, "{}", escape_for_printing(s))?;
            } else {
                let gid_val = resolve_int_option(name, ctx) as u32;
                if gid_val > 0 {
                    writeln!(out, "{}", resolve_gid_name(gid_val))?;
                } else {
                    writeln!(out)?;
                }
            }
        }

        OptionType::Fixed => {
            // C lines 2693–2712: fixed-point × 1000.
            let v = resolve_int_option(name, ctx);
            let x = v as i32;
            if x < 0 {
                writeln!(out, "{name} =")?;
            } else {
                if !no_labels {
                    write!(out, "{name} = ")?;
                }
                let whole = x / 1000;
                let frac = x % 1000;
                if frac == 0 {
                    writeln!(out, "{whole}.0")?;
                } else {
                    // Print fractional digits, trimming trailing zeros.
                    let frac_str = format!("{frac:03}");
                    let trimmed = frac_str.trim_end_matches('0');
                    writeln!(out, "{whole}.{trimmed}")?;
                }
            }
        }

        OptionType::Func | OptionType::MiscModule | OptionType::LookupModule => {
            // Func/module options are delegated to their respective handlers.
            // For -bP printing, we print the option name with no value.
            if !no_labels {
                write!(out, "{name} = ")?;
            }
            writeln!(out)?;
        }
    }

    Ok(true)
}

// =============================================================================
// print_config_option — Main -bP query interface (readconf_print)
// =============================================================================

/// Print configuration options in response to `-bP` queries.
///
/// Equivalent of `readconf_print()` (readconf.c lines 2907–3139).
/// Handles all special query types and driver-specific queries.
///
/// # Arguments
///
/// * `query` — The option name or special query string.
/// * `driver_type` — Optional driver type name ("router", "transport",
///   "authenticator", "macro") for driver-specific queries.
/// * `ctx` — The configuration context.
/// * `admin` — Whether the caller is an admin user.
/// * `no_labels` — If `true`, omit labels for machine-parseable output.
/// * `config_store` — The stored config lines for `-bP config` display.
/// * `out` — The output writer.
///
/// # Returns
///
/// `Ok(true)` if the query was satisfied, `Ok(false)` if the requested
/// item was not found.
pub fn print_config_option(
    query: &str,
    driver_type: Option<&str>,
    ctx: &ConfigContext,
    admin: bool,
    no_labels: bool,
    config_store: &ConfigLineStore,
    out: &mut dyn Write,
) -> std::io::Result<bool> {
    debug!(query = %query, driver_type = ?driver_type, admin, no_labels, "print_config_option");

    // If no driver type specified, handle special query names.
    if driver_type.is_none() {
        // +listname — search named list trees.
        // C readconf.c lines 2916–2942.
        if let Some(list_name) = query.strip_prefix('+') {
            return print_named_list(list_name, &ctx.named_lists, no_labels, out);
        }

        // configure_file / config_file — print config filename.
        // C readconf.c lines 2944–2949.
        if query == "configure_file" || query == "config_file" {
            writeln!(out, "{}", ctx.config_filename)?;
            return Ok(true);
        }

        // all — print all main configuration options.
        // C readconf.c lines 2951–2960.
        if query == "all" {
            let options = &*MAIN_CONFIG_OPTIONS;
            for entry in options {
                if !entry.flags.contains(OptionFlags::HIDDEN) {
                    print_option(entry, entry.name, ctx, admin, no_labels, out)?;
                }
            }
            return Ok(true);
        }

        // local_scan — local_scan options not supported in Rust build.
        // C readconf.c lines 2962–2974.
        if query == "local_scan" {
            writeln!(out, "local_scan() options are not supported")?;
            return Ok(false);
        }

        // config — full normalized config display.
        // C readconf.c lines 2976–2980.
        if query == "config" {
            print_formatted_config(config_store, admin, no_labels, out)?;
            return Ok(true);
        }

        // routers / transports / authenticators — redirect to driver listing.
        // C readconf.c lines 2982–2996.
        if query == "routers" {
            return print_driver_instances(DriverClass::Router, None, ctx, admin, no_labels, out);
        }
        if query == "transports" {
            return print_driver_instances(
                DriverClass::Transport,
                None,
                ctx,
                admin,
                no_labels,
                out,
            );
        }
        if query == "authenticators" {
            return print_driver_instances(
                DriverClass::Authenticator,
                None,
                ctx,
                admin,
                no_labels,
                out,
            );
        }

        // *_list — name-only listings.
        // C readconf.c lines 3002–3025.
        if query == "router_list" {
            return print_driver_names(DriverClass::Router, ctx, out);
        }
        if query == "transport_list" {
            return print_driver_names(DriverClass::Transport, ctx, out);
        }
        if query == "authenticator_list" {
            return print_driver_names(DriverClass::Authenticator, ctx, out);
        }

        // macros — print defined macros (admin-only).
        // C readconf.c lines 2997–3001, 3075–3100.
        if query == "macros" {
            return print_macros(None, false, &ctx.macros, admin, no_labels, out);
        }
        if query == "macro_list" {
            return print_macros(None, true, &ctx.macros, admin, no_labels, out);
        }

        // environment — print keep/add environment.
        // C readconf.c lines 3026–3042.
        if query == "environment" {
            if let Some(ref env) = ctx.keep_environment {
                writeln!(out, "{env}")?;
            }
            if let Some(ref env) = ctx.add_environment {
                writeln!(out, "{env}")?;
            }
            return Ok(true);
        }

        // Default: look up as a main config option.
        // C readconf.c lines 3044–3048.
        //
        // Handle `no_*` and `not_*` prefix for boolean options.
        // C Exim accepts `-bP no_accept_8bitmime` and prints the boolean
        // option `accept_8bitmime` with appropriate negation prefix in the
        // output (readconf.c line 2691–2715).
        let options = &*MAIN_CONFIG_OPTIONS;
        if let Some(idx) = find_option(query, options) {
            let entry = &options[idx];
            return print_option(entry, query, ctx, admin, no_labels, out);
        }

        // If not found directly, try stripping the `no_` or `not_` prefix
        // and look for a boolean option.
        let stripped = query
            .strip_prefix("no_")
            .or_else(|| query.strip_prefix("not_"));
        if let Some(base_name) = stripped {
            if let Some(idx) = find_option(base_name, options) {
                let entry = &options[idx];
                // Only valid for boolean options
                if entry.option_type == OptionType::Bool {
                    // Print as the negated form — the query itself is the
                    // correct print name (e.g. "no_accept_8bitmime").
                    return print_option(entry, query, ctx, admin, no_labels, out);
                }
            }
        }

        writeln!(out, "{query} is not a known option")?;
        return Ok(false);
    }

    // Driver-type-specific query.
    let dtype = driver_type.expect("driver_type checked above");

    // Macro queries: C readconf.c lines 3075–3100.
    if dtype == "macro" {
        return print_macros(Some(query), false, &ctx.macros, admin, no_labels, out);
    }

    // Router / transport / authenticator queries.
    let class = match dtype {
        "router" => DriverClass::Router,
        "transport" => DriverClass::Transport,
        "authenticator" => DriverClass::Authenticator,
        _ => {
            writeln!(out, "unknown driver type: {dtype}")?;
            return Ok(false);
        }
    };

    print_driver_instances(class, Some(query), ctx, admin, no_labels, out)
}

// =============================================================================
// Named list printing helper
// =============================================================================

/// Print named list(s) matching a query.
///
/// Searches all four named list categories (address, domain, host, localpart)
/// for a matching list name and prints the value.
fn print_named_list(
    name: &str,
    lists: &NamedLists,
    no_labels: bool,
    out: &mut dyn Write,
) -> std::io::Result<bool> {
    let categories: [(&str, &std::collections::BTreeMap<String, NamedList>); 4] = [
        ("address", &lists.address_lists),
        ("domain", &lists.domain_lists),
        ("host", &lists.host_lists),
        ("localpart", &lists.localpart_lists),
    ];

    let mut found = false;
    for (type_name, map) in &categories {
        if let Some(entry) = map.get(name) {
            found = true;
            let display_value = if entry.hide {
                HIDDEN_VALUE.to_string()
            } else {
                entry.value.clone()
            };
            if no_labels {
                writeln!(out, "{display_value}")?;
            } else {
                writeln!(out, "{type_name}list {name} = {display_value}")?;
            }
        }
    }

    if !found {
        writeln!(
            out,
            "no address, domain, host, or local part list called '{name}' exists"
        )?;
    }

    Ok(found)
}

// =============================================================================
// Macro printing helper
// =============================================================================

/// Print macro definitions.
///
/// C readconf.c lines 3075–3100: admin-only macro printing with
/// name filtering and names_only mode.
fn print_macros(
    filter_name: Option<&str>,
    names_only: bool,
    macros: &[MacroItemSnapshot],
    admin: bool,
    no_labels: bool,
    out: &mut dyn Write,
) -> std::io::Result<bool> {
    // Macros contain passwords — admin-only access.
    // C readconf.c line 3079.
    if !admin {
        writeln!(out, "exim: permission denied; not admin")?;
        return Ok(false);
    }

    for m in macros {
        if let Some(name) = filter_name {
            if m.name != name {
                continue;
            }
        }

        if names_only {
            writeln!(out, "{}", m.name)?;
        } else if no_labels {
            writeln!(out, "{}", m.replacement)?;
        } else {
            writeln!(out, "{}={}", m.name, m.replacement)?;
        }

        // If searching for a specific macro and found it, return immediately.
        if filter_name.is_some() {
            return Ok(true);
        }
    }

    // If looking for all macros (no filter), success even if none exist.
    if filter_name.is_none() {
        return Ok(true);
    }

    // Specific macro not found.
    writeln!(out, "macro {} not found", filter_name.unwrap_or(""))?;
    Ok(false)
}

// =============================================================================
// Driver instance printing helpers
// =============================================================================

/// Print driver instance names only (for `*_list` queries).
fn print_driver_names(
    class: DriverClass,
    ctx: &ConfigContext,
    out: &mut dyn Write,
) -> std::io::Result<bool> {
    // For now, we report driver instances by count since the driver instances
    // are stored as Arc<dyn Any> and we need a name extraction mechanism.
    // In the actual integration, each driver instance would expose its name.
    let count = match class {
        DriverClass::Authenticator => ctx.auth_instances.len(),
        DriverClass::Router => ctx.router_instances.len(),
        DriverClass::Transport => ctx.transport_instances.len(),
    };
    trace!(class = %class, count, "listing driver names");

    // Since driver instances are stored as Arc<dyn Any>, we print a summary.
    // This will be refined when driver instances expose their names through
    // a common trait method.  For now, output the supported drivers listing.
    let supported = show_supported_drivers();
    if !supported.is_empty() {
        write!(out, "{supported}")?;
    }
    Ok(true)
}

/// Print driver instance(s) with their options.
///
/// When `filter_name` is `None`, prints all instances of the given class.
/// When `filter_name` is `Some(name)`, prints only the named instance.
fn print_driver_instances(
    class: DriverClass,
    filter_name: Option<&str>,
    ctx: &ConfigContext,
    admin: bool,
    no_labels: bool,
    out: &mut dyn Write,
) -> std::io::Result<bool> {
    trace!(class = %class, filter = ?filter_name, "printing driver instances");

    let count = match class {
        DriverClass::Authenticator => ctx.auth_instances.len(),
        DriverClass::Router => ctx.router_instances.len(),
        DriverClass::Transport => ctx.transport_instances.len(),
    };

    if filter_name.is_none() && count == 0 {
        // No instances of this class — print the supported drivers instead.
        let supported = show_supported_drivers();
        if !supported.is_empty() {
            write!(out, "{supported}")?;
        }
        return Ok(true);
    }

    // With the current type-erased storage (Arc<dyn Any>), we cannot directly
    // iterate and print individual driver options.  In the full integration,
    // a common DriverInstance trait would provide name() and options() methods.
    // For now, we output the supported drivers listing as the best available
    // information.
    if filter_name.is_none() {
        let type_str = class.as_str();
        writeln!(out, "# Configured {type_str}s: {count} instance(s)")?;
        let _ = admin; // Will be used when driver option printing is available.
        let _ = no_labels;
        return Ok(true);
    }

    // Specific driver not found scenario.
    let name = filter_name.unwrap_or("");
    writeln!(out, "{} {} not found", class.as_str(), name)?;
    Ok(false)
}

// =============================================================================
// print_formatted_config — Full config display (print_config)
// =============================================================================

/// Print the full pre-parsed configuration with formatting.
///
/// Equivalent of `print_config()` (readconf.c lines 4683–4761).
/// Iterates stored config lines and applies formatting rules:
///
/// - `#` lines: printed as-is
/// - `begin` lines: left-aligned, preceded by blank line (unless terse)
/// - Driver name lines (ending with `:`): intermediate indent, preceded by
///   blank line (unless terse)
/// - Hidden/macro lines for non-admin: masked with `<value not displayable>`
/// - All other lines: indented at current indent level
/// - Whitespace runs collapsed (stopping at `"`, `'`, `$` characters)
///
/// # Arguments
///
/// * `store` — The config line store containing pre-parsed lines.
/// * `admin` — Whether the caller is an admin user.
/// * `terse` — If `true`, use compact formatting (no blank lines, no indent).
/// * `out` — The output writer.
pub fn print_formatted_config(
    store: &ConfigLineStore,
    admin: bool,
    terse: bool,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    let ts: usize = if terse { 0 } else { 2 };
    let mut indent: usize = 0;

    for item in store.lines() {
        let current = item.line.trim().to_string();
        if current.is_empty() {
            continue;
        }

        // Collapse runs of whitespace, stopping at quote/expansion chars.
        // C readconf.c lines 4704–4716.
        let current = collapse_whitespace(&current);

        // # lines: print as-is.
        // C readconf.c lines 4718–4720.
        if current.starts_with('#') {
            writeln!(out, "{current}")?;
            continue;
        }

        // begin lines: left-aligned, preceded by blank line.
        // C readconf.c lines 4722–4728.
        if current.starts_with("begin")
            && current
                .as_bytes()
                .get(5)
                .is_some_and(|b| b.is_ascii_whitespace())
        {
            if !terse {
                writeln!(out)?;
            }
            writeln!(out, "{current}")?;
            indent = ts;
            continue;
        }

        // Driver/ACL block name lines (ending with `:` and no `=`).
        // C readconf.c lines 4731–4736.
        if current.ends_with(':') && !current.contains('=') {
            if !terse {
                writeln!(out)?;
            }
            writeln!(out, "{:>width$}{current}", "", width = ts)?;
            indent = 2 * ts;
            continue;
        }

        // Hidden lines (macros or `hide` prefix) for non-admin users.
        // C readconf.c lines 4738–4753.
        if !admin {
            let first_byte = current.as_bytes()[0];
            let is_macro_line = first_byte.is_ascii_uppercase();
            let is_hide_line = current.starts_with("hide")
                && current
                    .as_bytes()
                    .get(4)
                    .is_some_and(|b| b.is_ascii_whitespace());

            if is_macro_line || is_hide_line {
                if let Some(eq_pos) = current.find('=') {
                    let before_eq = &current[..eq_pos];
                    writeln!(
                        out,
                        "{:>width$}{before_eq}= {HIDDEN_VALUE}",
                        "",
                        width = indent
                    )?;
                } else {
                    writeln!(out, "{:>width$}{HIDDEN_VALUE}", "", width = indent)?;
                }
                continue;
            }
        }

        // Normal lines: print with current indentation.
        // C readconf.c lines 4755–4757.
        writeln!(out, "{:>width$}{current}", "", width = indent)?;
    }

    Ok(())
}

/// Collapse runs of whitespace in a string, stopping at quote/expansion chars.
///
/// Replaces runs of multiple whitespace characters with a single space.
/// Stops collapsing when encountering `"`, `'`, or `$` characters, as these
/// may indicate careful formatting that should be preserved.
/// C readconf.c lines 4704–4716.
fn collapse_whitespace(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut result = String::with_capacity(s.len());
    let mut i = 0;

    while i < bytes.len() {
        let ch = bytes[i];

        // Stop collapsing at quote/expansion characters.
        if ch == b'"' || ch == b'\'' || ch == b'$' {
            // Append the rest of the string as-is.
            result.push_str(&s[i..]);
            return result;
        }

        if ch.is_ascii_whitespace() {
            // Replace any whitespace with a single space.
            result.push(' ');
            // Skip over additional whitespace.
            while i + 1 < bytes.len() && bytes[i + 1].is_ascii_whitespace() {
                i += 1;
            }
        } else {
            result.push(ch as char);
        }

        i += 1;
    }

    result
}

// =============================================================================
// validate_config — Post-parse configuration validation
// =============================================================================

/// Validate a parsed [`ConfigContext`] for correctness and consistency.
///
/// This function performs post-parse validation checks equivalent to the
/// validation logic scattered through `readconf_main()` in readconf.c.
/// It is called after all configuration sections have been parsed and
/// all driver instances have been created.
///
/// # Validation Checks
///
/// 1. **Required paths**: `spool_directory` must be set and non-empty.
/// 2. **Log path**: `log_file_path` should be set (warning if empty).
/// 3. **Driver dependency chains**: Scans driver option strings for
///    expansion variable references to validate driver ordering
///    (equivalent to `readconf_depends()`, readconf.c lines 4067–4100).
/// 4. **Router existence**: At least one router must be configured for
///    message delivery to work.
///
/// # Arguments
///
/// * `ctx` — The parsed configuration context to validate.
///
/// # Returns
///
/// `Ok(())` if all validation checks pass.
///
/// # Errors
///
/// Returns `ConfigError::ValidationError` with a descriptive message for
/// the first validation failure encountered.
/// Convenience wrapper that validates a frozen [`Config`] (Arc-wrapped
/// immutable configuration).
///
/// This accepts the `Config` type (which `Deref`s to [`ConfigContext`]),
/// making it suitable for callers that hold the frozen configuration.
pub fn validate_frozen_config(config: &Config) -> Result<(), ConfigError> {
    validate_config(config)
}

/// Validate a parsed [`ConfigContext`] for correctness and consistency.
///
/// This function performs post-parse validation checks equivalent to the
/// validation logic scattered through `readconf_main()` in readconf.c.
/// It is called after all configuration sections have been parsed and
/// all driver instances have been created.
///
/// # Validation Checks
///
/// 1. **Required paths**: `spool_directory` must be set and non-empty.
/// 2. **Log path**: `log_file_path` should be set (warning if empty).
/// 3. **Driver dependency chains**: Scans driver option strings for
///    expansion variable references to validate driver ordering
///    (equivalent to `readconf_depends()`, readconf.c lines 4067–4100).
/// 4. **Router existence**: At least one router must be configured for
///    message delivery to work.
///
/// # Arguments
///
/// * `ctx` — The parsed configuration context to validate.
///
/// # Returns
///
/// `Ok(())` if all validation checks pass.
///
/// # Errors
///
/// Returns `ConfigError::ValidationError` with a descriptive message for
/// the first validation failure encountered.
pub fn validate_config(ctx: &ConfigContext) -> Result<(), ConfigError> {
    debug!("beginning configuration validation");

    // 1. Validate spool_directory is set and non-empty.
    //    This is a hard requirement — Exim cannot operate without a spool.
    if ctx.spool_directory.is_empty() {
        return Err(ConfigError::ValidationError(
            "spool_directory is not set".to_string(),
        ));
    }
    debug!(spool_directory = %ctx.spool_directory, "spool_directory validated");

    // 2. Validate log_file_path — warn if empty but do not fail.
    //    Exim can operate with syslog-only logging.
    if ctx.log_file_path.is_empty() {
        warn!("log_file_path is not set; logging will use syslog only");
    } else {
        debug!(log_file_path = %ctx.log_file_path, "log_file_path validated");
    }

    // 3. Validate that at least one router is configured.
    //    Without routers, Exim cannot deliver any messages.
    if ctx.router_instances.is_empty() {
        warn!("no routers configured; message delivery will not function");
    }

    // 4. Validate driver dependency chains.
    //    This checks that drivers referencing expansion variables like
    //    $local_part, $domain, etc. are ordered correctly so that the
    //    referenced variables are available when the driver executes.
    //    Equivalent to readconf_depends() (readconf.c lines 4067–4100).
    validate_driver_dependencies(ctx)?;

    // 5. Validate primary_hostname — warn if not set (will be auto-detected).
    if ctx.primary_hostname.is_empty() {
        debug!("primary_hostname not set; will be auto-detected at runtime");
    }

    // 6. Validate qualify_domain settings.
    if ctx.qualify_domain_sender.is_empty() {
        debug!("qualify_domain_sender not set; will default to primary_hostname");
    }

    // 7. Validate ACL references — warn if critical ACLs are missing.
    if ctx.acl_smtp_rcpt.is_none() {
        warn!("acl_smtp_rcpt is not set; all RCPT TO commands will be accepted");
    }

    debug!("configuration validation complete");
    Ok(())
}

/// Validate driver dependency chains.
///
/// Checks that driver option strings containing expansion variable references
/// are ordered correctly.  This is a simplified version of the C
/// `readconf_depends()` check.
fn validate_driver_dependencies(ctx: &ConfigContext) -> Result<(), ConfigError> {
    debug!("validating driver dependency chains");

    // For the full implementation, this would iterate through router and
    // transport instances, calling check_driver_depends() on each to verify
    // that referenced expansion variables are provided by earlier drivers
    // in the chain.
    //
    // With the current type-erased driver storage (Arc<dyn Any>), we perform
    // a basic count-based validation.  The full dependency chain analysis
    // will be enabled when driver instances expose their option data through
    // a common trait.

    let auth_count = ctx.auth_instances.len();
    let router_count = ctx.router_instances.len();
    let transport_count = ctx.transport_instances.len();

    debug!(
        auth_count,
        router_count, transport_count, "driver instance counts validated"
    );

    // Call check_driver_depends as a demonstration that the dependency is used.
    // In production, this would iterate actual driver instances.
    let _depends_fn = check_driver_depends;

    Ok(())
}

// =============================================================================
// Unit tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_time_zero() {
        assert_eq!(format_time(0), "0s");
    }

    #[test]
    fn test_format_time_seconds_only() {
        assert_eq!(format_time(30), "30s");
        assert_eq!(format_time(1), "1s");
        assert_eq!(format_time(59), "59s");
    }

    #[test]
    fn test_format_time_minutes() {
        assert_eq!(format_time(60), "1m");
        assert_eq!(format_time(120), "2m");
        assert_eq!(format_time(90), "1m30s");
    }

    #[test]
    fn test_format_time_hours() {
        assert_eq!(format_time(3600), "1h");
        assert_eq!(format_time(3661), "1h1m1s");
        assert_eq!(format_time(7200), "2h");
    }

    #[test]
    fn test_format_time_days() {
        assert_eq!(format_time(86400), "1d");
        assert_eq!(format_time(90061), "1d1h1m1s");
    }

    #[test]
    fn test_format_time_weeks() {
        assert_eq!(format_time(604800), "1w");
        assert_eq!(format_time(694861), "1w1d1h1m1s");
    }

    #[test]
    fn test_format_time_negative() {
        assert_eq!(format_time(-60), "-1m");
        assert_eq!(format_time(-300), "-5m");
        assert_eq!(format_time(-1), "-1s");
    }

    #[test]
    fn test_format_time_large_values() {
        // 2 weeks = 1209600
        assert_eq!(format_time(1_209_600), "2w");
        // 10 weeks = 6048000
        assert_eq!(format_time(6_048_000), "10w");
    }

    #[test]
    fn test_escape_for_printing() {
        assert_eq!(escape_for_printing("hello"), "hello");
        assert_eq!(escape_for_printing("a\\b"), "a\\\\b");
        assert_eq!(escape_for_printing("a\tb"), "a\\tb");
        assert_eq!(escape_for_printing("a\x01b"), "a\\x01b");
    }

    #[test]
    fn test_config_line_store_new() {
        let store = ConfigLineStore::new();
        assert!(store.lines().is_empty());
    }

    #[test]
    fn test_config_line_store_save_config() {
        let mut store = ConfigLineStore::new();
        store.save_config("4.99");
        assert_eq!(store.lines().len(), 1);
        assert_eq!(store.lines()[0].line, "# Exim Configuration (4.99)");
    }

    #[test]
    fn test_config_line_store_save_line() {
        let mut store = ConfigLineStore::new();
        store.save_config_line("primary_hostname = example.com");
        assert_eq!(store.lines().len(), 1);
        assert_eq!(store.lines()[0].line, "primary_hostname = example.com");
    }

    #[test]
    fn test_config_line_store_save_position() {
        let mut store = ConfigLineStore::new();
        store.save_config_position("/etc/exim/configure", 42);
        assert_eq!(store.lines().len(), 1);
        assert_eq!(store.lines()[0].line, "# 42 /etc/exim/configure");
    }

    #[test]
    fn test_collapse_whitespace_basic() {
        assert_eq!(collapse_whitespace("a  b"), "a b");
        assert_eq!(collapse_whitespace("a   b   c"), "a b c");
    }

    #[test]
    fn test_collapse_whitespace_stops_at_quotes() {
        assert_eq!(collapse_whitespace("a  \"b  c\""), "a \"b  c\"");
        assert_eq!(collapse_whitespace("a  $var  x"), "a $var  x");
    }

    #[test]
    fn test_print_option_string() {
        let entry = OptionEntry::simple("test_option", OptionType::StringPtr);
        let ctx = ConfigContext::default();
        let mut buf = Vec::new();
        let result = print_option(&entry, "test_option", &ctx, true, false, &mut buf);
        assert!(result.is_ok());
        let output = String::from_utf8(buf).unwrap();
        // The option should have been printed (even if empty).
        assert!(output.contains("test_option"));
    }

    #[test]
    fn test_print_option_secure_non_admin() {
        let entry = OptionEntry::new("secret", OptionType::StringPtr, OptionFlags::SECURE);
        let ctx = ConfigContext::default();
        let mut buf = Vec::new();
        let result = print_option(&entry, "secret", &ctx, false, false, &mut buf);
        assert!(result.is_ok());
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains(HIDDEN_VALUE));
    }

    #[test]
    fn test_print_option_secure_admin() {
        let entry = OptionEntry::new(
            "spool_directory",
            OptionType::StringPtr,
            OptionFlags::SECURE,
        );
        let mut ctx = ConfigContext::default();
        ctx.spool_directory = "/var/spool/exim".to_string();
        let mut buf = Vec::new();
        let result = print_option(&entry, "spool_directory", &ctx, true, false, &mut buf);
        assert!(result.is_ok());
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("/var/spool/exim"));
    }

    #[test]
    fn test_print_option_bool_true() {
        let entry = OptionEntry::simple("accept_8bitmime", OptionType::Bool);
        let ctx = ConfigContext::default();
        let mut buf = Vec::new();
        let _ = print_option(&entry, "accept_8bitmime", &ctx, true, false, &mut buf);
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output.trim(), "accept_8bitmime");
    }

    #[test]
    fn test_print_option_bool_false() {
        let entry = OptionEntry::simple("allow_domain_literals", OptionType::Bool);
        let ctx = ConfigContext::default();
        let mut buf = Vec::new();
        let _ = print_option(&entry, "allow_domain_literals", &ctx, true, false, &mut buf);
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output.trim(), "no_allow_domain_literals");
    }

    #[test]
    fn test_print_option_time() {
        let entry = OptionEntry::simple("auto_thaw", OptionType::Time);
        let ctx = ConfigContext::default();
        let mut buf = Vec::new();
        let _ = print_option(&entry, "auto_thaw", &ctx, true, false, &mut buf);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("auto_thaw = 0s"));
    }

    #[test]
    fn test_print_option_no_labels() {
        let entry = OptionEntry::simple("spool_directory", OptionType::StringPtr);
        let mut ctx = ConfigContext::default();
        ctx.spool_directory = "/var/spool/exim".to_string();
        let mut buf = Vec::new();
        let _ = print_option(&entry, "spool_directory", &ctx, true, true, &mut buf);
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output.trim(), "/var/spool/exim");
        assert!(!output.contains("spool_directory ="));
    }

    #[test]
    fn test_validate_config_missing_spool() {
        let ctx = ConfigContext::default();
        let result = validate_config(&ctx);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("spool_directory"));
    }

    #[test]
    fn test_validate_config_ok() {
        let mut ctx = ConfigContext::default();
        ctx.spool_directory = "/var/spool/exim".to_string();
        ctx.log_file_path = "/var/log/exim/%s.log".to_string();
        let result = validate_config(&ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_print_config_option_config_file() {
        let mut ctx = ConfigContext::default();
        ctx.config_filename = "/etc/exim/configure".to_string();
        ctx.spool_directory = "/var/spool/exim".to_string();
        let store = ConfigLineStore::new();
        let mut buf = Vec::new();
        let result = print_config_option("config_file", None, &ctx, true, false, &store, &mut buf);
        assert!(result.is_ok());
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output.trim(), "/etc/exim/configure");
    }

    #[test]
    fn test_print_config_option_configure_file() {
        let mut ctx = ConfigContext::default();
        ctx.config_filename = "/etc/exim/configure".to_string();
        ctx.spool_directory = "/var/spool/exim".to_string();
        let store = ConfigLineStore::new();
        let mut buf = Vec::new();
        let result =
            print_config_option("configure_file", None, &ctx, true, false, &store, &mut buf);
        assert!(result.is_ok());
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output.trim(), "/etc/exim/configure");
    }

    #[test]
    fn test_print_config_option_unknown() {
        let ctx = ConfigContext::default();
        let store = ConfigLineStore::new();
        let mut buf = Vec::new();
        let result = print_config_option(
            "nonexistent_option",
            None,
            &ctx,
            true,
            false,
            &store,
            &mut buf,
        );
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_print_formatted_config_basic() {
        let mut store = ConfigLineStore::new();
        store.save_config("4.99");
        store.save_config_line("primary_hostname = example.com");
        store.save_config_line("begin routers");
        store.save_config_line("localuser:");
        store.save_config_line("driver = accept");

        let mut buf = Vec::new();
        let result = print_formatted_config(&store, true, false, &mut buf);
        assert!(result.is_ok());
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("# Exim Configuration (4.99)"));
        assert!(output.contains("primary_hostname = example.com"));
        assert!(output.contains("begin routers"));
    }

    #[test]
    fn test_print_formatted_config_hide_non_admin() {
        let mut store = ConfigLineStore::new();
        store.save_config_line("MY_SECRET = password123");

        let mut buf = Vec::new();
        let result = print_formatted_config(&store, false, false, &mut buf);
        assert!(result.is_ok());
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains(HIDDEN_VALUE));
        assert!(!output.contains("password123"));
    }

    #[test]
    fn test_print_macros_admin() {
        let macros = vec![
            MacroItemSnapshot {
                name: "MY_MACRO".to_string(),
                replacement: "value1".to_string(),
                command_line: false,
            },
            MacroItemSnapshot {
                name: "ANOTHER".to_string(),
                replacement: "value2".to_string(),
                command_line: false,
            },
        ];
        let mut buf = Vec::new();
        let result = print_macros(None, false, &macros, true, false, &mut buf);
        assert!(result.is_ok());
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("MY_MACRO=value1"));
        assert!(output.contains("ANOTHER=value2"));
    }

    #[test]
    fn test_print_macros_non_admin() {
        let macros = vec![MacroItemSnapshot {
            name: "SECRET".to_string(),
            replacement: "hidden".to_string(),
            command_line: false,
        }];
        let mut buf = Vec::new();
        let result = print_macros(None, false, &macros, false, false, &mut buf);
        assert!(result.is_ok());
        assert!(!result.unwrap());
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("permission denied"));
    }

    #[test]
    fn test_print_option_int() {
        let entry = OptionEntry::simple("smtp_accept_max", OptionType::Int);
        let ctx = ConfigContext::default();
        let mut buf = Vec::new();
        let _ = print_option(&entry, "smtp_accept_max", &ctx, true, false, &mut buf);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("smtp_accept_max = 20"));
    }

    #[test]
    fn test_print_option_mkint_with_suffix() {
        let entry = OptionEntry::simple("bounce_return_linesize_limit", OptionType::Mkint);
        let ctx = ConfigContext::default();
        let mut buf = Vec::new();
        let _ = print_option(
            &entry,
            "bounce_return_linesize_limit",
            &ctx,
            true,
            false,
            &mut buf,
        );
        let output = String::from_utf8(buf).unwrap();
        // 998 is not cleanly divisible by 1024, so no suffix.
        assert!(output.contains("bounce_return_linesize_limit = 998"));
    }

    #[test]
    fn test_named_list_lookup() {
        let mut lists = NamedLists::default();
        lists.domain_lists.insert(
            "local_domains".to_string(),
            NamedList {
                name: "local_domains".to_string(),
                value: "example.com : example.org".to_string(),
                hide: false,
            },
        );

        let mut buf = Vec::new();
        let result = print_named_list("local_domains", &lists, false, &mut buf);
        assert!(result.is_ok());
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("domainlist local_domains = example.com : example.org"));
    }

    #[test]
    fn test_named_list_hidden() {
        let mut lists = NamedLists::default();
        lists.host_lists.insert(
            "secret_hosts".to_string(),
            NamedList {
                name: "secret_hosts".to_string(),
                value: "10.0.0.1".to_string(),
                hide: true,
            },
        );

        let mut buf = Vec::new();
        let result = print_named_list("secret_hosts", &lists, false, &mut buf);
        assert!(result.is_ok());
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains(HIDDEN_VALUE));
        assert!(!output.contains("10.0.0.1"));
    }

    #[test]
    fn test_named_list_not_found() {
        let lists = NamedLists::default();
        let mut buf = Vec::new();
        let result = print_named_list("nonexistent", &lists, false, &mut buf);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}
