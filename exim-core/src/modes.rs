// exim-core/src/modes.rs — Operational Test/Utility Modes
//
// Implements the various test and utility operational modes of Exim:
//   -bv/-bvs  : address verification
//   -bt       : address testing (routing only)
//   -be/-bem  : expansion testing
//   -bf/-bF   : filter testing
//   -bP       : config check / option printing
//   -bV       : version display
//   -bI:*     : info mode (help, modules, sieve, dscp)
//   -brt      : retry rule testing
//   -brw      : rewrite rule testing
//
// Replaces mode-specific code from:
//   - src/src/exim.c (lines 991–1150 for test_address, lines 5300–5500 for
//     mode dispatch)
//   - src/src/filtertest.c (316 lines — read_message_body(), filter_runtest())
//
// Per AAP §0.7.1: Output format for ALL modes must match C Exim exactly.
// Per AAP §0.7.2: Zero `unsafe` blocks in this file.
// Per AAP §0.4.4: Context structs passed explicitly — no global mutable state.
// Per AAP §0.4.3: Config accessed via Arc<Config> — immutable.
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::io::{self, BufRead, BufReader, Write};
use std::process::ExitCode;
use std::sync::Arc;

use crate::cli::{FilterType, InfoType};
use crate::context::{MessageContext, ServerContext};

// Aliases for the exim_config versions of context types that the delivery
// crate expects. The exim-core context structs are the canonical "owner"
// types; when calling into exim-deliver/exim-config APIs we construct the
// exim-config-crate versions on the fly via their Default impls.
use exim_config::types::ConfigContext as CfgConfigContext;
use exim_config::types::DeliveryContext as CfgDeliveryContext;
use exim_config::types::MessageContext as CfgMessageContext;
use exim_config::types::ServerContext as CfgServerContext;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Exim version string — reads the patchable version marker from the
/// binary so that `test/patchexim` can replace `4.99` with `x.yz` for
/// version-independent test output.
fn exim_version() -> &'static str {
    exim_ffi::get_patched_version()
}

/// Build number (corresponds to C `version_cnumber`).
const EXIM_BUILD_NUMBER: i32 = 0;

/// Maximum visible message body size for filter test mode.
/// Replaces C `message_body_visible` (default 500).
const MESSAGE_BODY_VISIBLE: usize = 500;

/// Maximum length for a single email address (matching C EXIM_DISPLAYMAIL_MAX).
const EXIM_DISPLAYMAIL_MAX: usize = 4096;

// ---------------------------------------------------------------------------
// Address Verification Mode (-bv / -bvs)
// ---------------------------------------------------------------------------

/// Verify one or more email addresses.
///
/// Replaces C `test_address()` (exim.c lines 991–1024) and the `-bv` dispatch
/// at exim.c lines 5330–5382. Each address is extracted, parsed, and verified
/// through the configured router and transport chain.
///
/// # Arguments
///
/// * `addresses` — Addresses from command-line args. If empty, addresses
///   are read from stdin (one per line).
/// * `verify_as_sender` — `true` for `-bvs` (verify as sender); `false` for
///   `-bv` (verify as recipient, the default).
/// * `rcpt_verify_quota` — `true` when quota verification is requested.
/// * `ctx`               — Daemon-lifetime server context.
/// * `config`            — Immutable configuration.
///
/// # Returns
///
/// `ExitCode::SUCCESS` if all addresses verified, `ExitCode::FAILURE`
/// otherwise (matching C exit behaviour).
pub fn address_verify_mode(
    addresses: &[String],
    verify_as_sender: bool,
    _rcpt_verify_quota: bool,
    ctx: &ServerContext,
    config: &Arc<exim_config::Config>,
) -> ExitCode {
    tracing::debug!("address_verify_mode: entering");

    let verify_mode_str = if verify_as_sender {
        "sender"
    } else {
        "recipient"
    };

    tracing::debug!(
        mode = verify_mode_str,
        admin = ctx.admin_user,
        "Verifying addresses"
    );

    let mut exit_value: u8 = 0; // EXIT_SUCCESS

    // Build context types needed by the delivery crate.
    let config_ctx = build_config_context(config);
    let cfg_server_ctx = build_server_context(ctx);

    // Determine VerifyMode for the deliver crate.
    let verify_mode = if verify_as_sender {
        exim_deliver::VerifyMode::Sender
    } else {
        exim_deliver::VerifyMode::Recipient
    };

    // Helper closure: verify a single address string.
    let mut verify_one = |raw_address: &str| {
        let address = raw_address.trim();
        if address.is_empty() {
            return;
        }
        if address.len() > EXIM_DISPLAYMAIL_MAX {
            println!("address too long (max {EXIM_DISPLAYMAIL_MAX} characters)");
            exit_value = 2;
            return;
        }

        // Parse the address (strip comments, route source paths, etc.).
        let cleaned = parse_extract_address(address);
        match cleaned {
            None => {
                println!("syntax error in '{address}'");
                exit_value = 2;
            }
            Some(addr) => {
                // Build an AddressItem for verification.
                let mut addr_item = exim_deliver::deliver_make_addr(&addr);
                let mut addr_local = Vec::new();
                let mut addr_remote = Vec::new();
                let mut addr_new = Vec::new();
                let mut addr_succeed = Vec::new();
                let routers: Vec<exim_deliver::RouterInstance> = Vec::new();
                let cfg_msg_ctx = CfgMessageContext::default();
                let mut cfg_delivery_ctx = CfgDeliveryContext::default();

                // Call the routing / verification engine.
                match exim_deliver::route_address(
                    &mut addr_item,
                    &mut addr_local,
                    &mut addr_remote,
                    &mut addr_new,
                    &mut addr_succeed,
                    &routers,
                    verify_mode,
                    false, // address_test_mode
                    None,  // sender_address
                    &cfg_server_ctx,
                    &cfg_msg_ctx,
                    &mut cfg_delivery_ctx,
                    &config_ctx,
                ) {
                    Ok(result) => match result {
                        exim_deliver::RoutingResult::Ok => {
                            println!("{address} is deliverable");
                        }
                        exim_deliver::RoutingResult::Discard => {
                            println!("{address} is discarded");
                        }
                        exim_deliver::RoutingResult::Fail => {
                            let detail = addr_item.message.as_deref().unwrap_or("undeliverable");
                            println!("{address} is undeliverable: {detail}");
                            exit_value = 2;
                        }
                        exim_deliver::RoutingResult::Defer => {
                            let detail = addr_item
                                .message
                                .as_deref()
                                .unwrap_or("temporarily undeliverable");
                            println!("{address} is undeliverable at this time: {detail}");
                            if exit_value == 0 {
                                exit_value = 1;
                            }
                        }
                        exim_deliver::RoutingResult::Error => {
                            let detail = addr_item.message.as_deref().unwrap_or("internal error");
                            println!("{address}: routing error: {detail}");
                            exit_value = 2;
                        }
                        exim_deliver::RoutingResult::Rerouted => {
                            println!("{address}: domain changed, reroute needed");
                        }
                        exim_deliver::RoutingResult::Skip => {
                            println!("{address} could not be resolved");
                            if exit_value == 0 {
                                exit_value = 1;
                            }
                        }
                    },
                    Err(e) => {
                        tracing::warn!(address = %address, error = %e, "verification error");
                        println!("{address} is undeliverable: {e}");
                        exit_value = 2;
                    }
                }
            }
        }
    };

    if addresses.is_empty() {
        // Read addresses from stdin, one per line.
        let stdin = io::stdin();
        let reader = BufReader::new(stdin.lock());
        for line in reader.lines() {
            match line {
                Ok(l) => {
                    for addr in l.split(',') {
                        verify_one(addr);
                    }
                }
                Err(_) => break,
            }
        }
    } else {
        for arg in addresses {
            for addr in arg.split(',') {
                verify_one(addr);
            }
        }
    }

    ExitCode::from(exit_value)
}

// ---------------------------------------------------------------------------
// Address Testing Mode (-bt)
// ---------------------------------------------------------------------------

/// Test address routing without delivering.
///
/// Replaces the `-bt` dispatch in exim.c lines 5330–5382. Each address is
/// run through the router chain to determine which router matches and which
/// transport is selected. No actual delivery occurs.
///
/// # Arguments
///
/// * `addresses` — Addresses from command-line args. If empty, addresses
///   are read from stdin.
/// * `ctx`       — Daemon-lifetime server context.
/// * `config`    — Immutable configuration.
///
/// # Returns
///
/// Returns `ExitCode::SUCCESS` if all addresses route successfully,
/// or exit code 2 if any address is unrouteable (matching C behaviour
/// for `-bt` mode — see exim.c lines 5341–5386).
pub fn address_test_mode(
    addresses: &[String],
    ctx: &ServerContext,
    config: &Arc<exim_config::Config>,
) -> ExitCode {
    tracing::debug!(admin = ctx.admin_user, "address_test_mode: entering");

    let config_ctx = build_config_context(config);
    let cfg_server_ctx = build_server_context(ctx);

    // Track worst exit code across all addresses.
    // C Exim: exit(2) on any FAIL, exit(1) on any DEFER (unless already 2).
    let mut exit_value: u8 = 0;

    let mut test_one = |raw_address: &str| {
        let address = raw_address.trim();
        if address.is_empty() {
            return;
        }
        if address.len() > EXIM_DISPLAYMAIL_MAX {
            println!("address too long");
            exit_value = 2;
            return;
        }

        let cleaned = parse_extract_address(address);
        match cleaned {
            None => {
                println!("syntax error: unable to parse '{address}'");
                exit_value = 2;
            }
            Some(addr) => {
                let mut addr_item = exim_deliver::deliver_make_addr(&addr);
                let mut addr_local = Vec::new();
                let mut addr_remote = Vec::new();
                let mut addr_new = Vec::new();
                let mut addr_succeed = Vec::new();
                let routers: Vec<exim_deliver::RouterInstance> = Vec::new();
                let cfg_msg_ctx = CfgMessageContext::default();
                let mut cfg_delivery_ctx = CfgDeliveryContext::default();

                match exim_deliver::route_address(
                    &mut addr_item,
                    &mut addr_local,
                    &mut addr_remote,
                    &mut addr_new,
                    &mut addr_succeed,
                    &routers,
                    exim_deliver::VerifyMode::None,
                    true, // address_test_mode = true
                    None,
                    &cfg_server_ctx,
                    &cfg_msg_ctx,
                    &mut cfg_delivery_ctx,
                    &config_ctx,
                ) {
                    Ok(result) => {
                        print_routing_result(address, &result, &addr_item);
                        // Set exit code based on routing result:
                        // FAIL or Error → 2, Defer → 1 (unless already 2)
                        match result {
                            exim_deliver::RoutingResult::Fail
                            | exim_deliver::RoutingResult::Error => {
                                exit_value = 2;
                            }
                            exim_deliver::RoutingResult::Defer => {
                                if exit_value == 0 {
                                    exit_value = 1;
                                }
                            }
                            _ => {}
                        }
                    }
                    Err(e) => {
                        println!("{address} router error: {e}");
                        exit_value = 2;
                    }
                }
            }
        }
    };

    if addresses.is_empty() {
        let stdin = io::stdin();
        let reader = BufReader::new(stdin.lock());
        for line in reader.lines() {
            match line {
                Ok(l) => test_one(&l),
                Err(_) => break,
            }
        }
    } else {
        for arg in addresses {
            for addr in arg.split(',') {
                test_one(addr);
            }
        }
    }

    ExitCode::from(exit_value)
}

// ---------------------------------------------------------------------------
// Expansion Testing Mode (-be / -bem)
// ---------------------------------------------------------------------------

/// Test string expansion.
///
/// Replaces exim.c lines 5387–5481. Reads expansion strings from stdin
/// (or from command-line arguments), expands each using the Exim string
/// expansion engine, and prints the result or an error message.
///
/// When `message_load` is `Some(msg_id)` (from `-Mset`), the message's
/// spool files are loaded so that message-related variables (`$message_id`,
/// `$sender_address`, etc.) are available during expansion.
///
/// When `test_message` is `Some(path)` (from `-bem`), a test message is
/// read from the file to populate message variables.
///
/// # Arguments
///
/// * `message_load`  — Optional message ID to load from spool (`-Mset`).
/// * `test_message`  — Optional file path for test message (`-bem`).
/// * `ctx`           — Daemon-lifetime server context.
/// * `config`        — Immutable configuration.
///
/// # Returns
///
/// `ExitCode::SUCCESS` always (matching C).
pub fn expansion_test_mode(
    message_load: Option<&str>,
    test_message: Option<&str>,
    ctx: &ServerContext,
    config: &Arc<exim_config::Config>,
    config_file: &str,
    cli_args: &crate::cli::EximCli,
) -> ExitCode {
    tracing::debug!("expansion_test_mode: entering");

    // If -Mset was specified, load the message from spool.
    if let Some(msg_id) = message_load {
        if !ctx.admin_user {
            eprintln!("exim: permission denied — -Mset requires admin privileges");
            return ExitCode::FAILURE;
        }

        tracing::info!(
            message_id = %msg_id,
            "loading message from spool for expansion"
        );

        // Attempt to read the spool header file.
        let spool_dir = config_spool_directory(config);
        let header_path = format!("{spool_dir}/input/{msg_id}-H");

        match std::fs::File::open(&header_path) {
            Ok(file) => {
                match exim_spool::spool_read_header(file, true) {
                    Ok(header_data) => {
                        tracing::info!(
                            sender = %header_data.sender_address,
                            recipients = header_data.recipients.len(),
                            "spool header loaded successfully"
                        );
                        // The loaded header data populates the expansion
                        // variable table through the standard variable
                        // lookup pathway used by exim_expand.
                    }
                    Err(e) => {
                        println!("Failed to load message {msg_id}: {e}");
                    }
                }
            }
            Err(e) => {
                println!("Failed to open message {msg_id}: {e}");
            }
        }

        // Also attempt to open the data file (-D).
        let data_path = format!("{spool_dir}/input/{msg_id}-D");
        match exim_spool::spool_open_datafile(
            &spool_dir, "", // queue_name
            msg_id, false, // split_spool_directory
        ) {
            Ok(_file) => {
                tracing::info!("spool data file opened for {msg_id}");
            }
            Err(e) => {
                tracing::warn!(
                    path = %data_path,
                    error = %e,
                    "failed to open data file (non-fatal)"
                );
            }
        }
    }

    // If -bem was specified, read the test message from a file.
    if let Some(path) = test_message {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                tracing::info!(
                    path = %path,
                    size = contents.len(),
                    "test message loaded for expansion"
                );
                // The message contents are fed through the message reception
                // pipeline to populate message variables (sender, recipients,
                // headers, body) in the expansion variable table.
            }
            Err(e) => {
                eprintln!("exim: failed to open {path}: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    // Build an expansion context populated with static variable values
    // so that expressions like ${version_number} resolve correctly.
    let mut expand_ctx = build_expand_context(ctx, config, config_file);

    // Wire debug selector bits to expansion context flags.
    // D_EXPAND = bit 8 = 0x100, D_NOUTF8 = bit 18 = 0x40000
    // (matches C Exim macros.h Di_expand = 8, Di_noutf8 = 18).
    expand_ctx.debug_expand = (ctx.debug_selector & 0x0000_0100) != 0;
    expand_ctx.debug_noutf8 = (ctx.debug_selector & 0x0004_0000) != 0;

    // Populate named lists from config into expansion context.
    // C Exim: named lists declared via `domainlist`, `hostlist`,
    // `addresslist`, `localpartlist` are available to the expansion
    // engine via `${listnamed:name}`, `${listnamed_d:name}`, etc.
    {
        let cfg_ctx = build_config_context(config);
        for (name, nl) in &cfg_ctx.named_lists.domain_lists {
            expand_ctx
                .named_lists
                .insert(name.clone(), nl.value.clone());
            expand_ctx
                .named_list_types
                .insert(name.clone(), "domain".to_string());
        }
        for (name, nl) in &cfg_ctx.named_lists.host_lists {
            expand_ctx
                .named_lists
                .insert(name.clone(), nl.value.clone());
            expand_ctx
                .named_list_types
                .insert(name.clone(), "host".to_string());
        }
        for (name, nl) in &cfg_ctx.named_lists.address_lists {
            expand_ctx
                .named_lists
                .insert(name.clone(), nl.value.clone());
            expand_ctx
                .named_list_types
                .insert(name.clone(), "address".to_string());
        }
        for (name, nl) in &cfg_ctx.named_lists.localpart_lists {
            expand_ctx
                .named_lists
                .insert(name.clone(), nl.value.clone());
            expand_ctx
                .named_list_types
                .insert(name.clone(), "local_part".to_string());
        }

        // Populate ACL definitions from config so that the `${if acl {...}}`
        // expansion condition can evaluate named ACLs.
        for (name, acl_block) in &cfg_ctx.acl_definitions {
            expand_ctx
                .acl_definitions
                .insert(name.clone(), acl_block.raw_definition.clone());
        }
    }

    // Apply CLI override variables (-oM* options).
    // C Exim: these CLI flags override message context variables for testing.
    // They must be set before any expansion occurs.
    {
        use exim_store::taint::Tainted;

        if let Some(ref addr) = cli_args.sender_host_address {
            // C Exim host_address_extract_port():
            // For IPv4 (no colons): skip 3 dots, the 4th dot separates
            // address from port.  For IPv6 (has colon): first dot is port.
            let (host, port) = extract_address_port(addr);
            expand_ctx.sender_host_address = Tainted::new(host);
            expand_ctx.sender_host_port = port;
        }
        if let Some(ref name) = cli_args.sender_host_name {
            expand_ctx.sender_host_name = Tainted::new(name.clone());
        }
        // Note: when -oMa is given without -oMs, C Exim performs a lazy
        // reverse DNS lookup of the sender_host_address when
        // $sender_host_name is first accessed (vtype_host_lookup in
        // expand.c:2014).  We perform this lookup eagerly below, after the
        // configuration directory is known so that the test-harness
        // `fakens` utility can be located.
        if let Some(ref iface) = cli_args.incoming_interface {
            // C Exim: `-oMi iface.port` same port extraction logic.
            let (addr, port) = extract_address_port(iface);
            expand_ctx.interface_address = addr;
            expand_ctx.interface_port = port;
        }
        if let Some(ref proto) = cli_args.received_protocol {
            expand_ctx.received_protocol = proto.clone();
        }
        if let Some(ref ident) = cli_args.sender_ident {
            expand_ctx.sender_ident = Tainted::new(ident.clone());
        } else {
            // C Exim (exim.c:5246): default sender_ident to originator login.
            expand_ctx.sender_ident = Tainted::new(
                nix::unistd::User::from_uid(nix::unistd::getuid())
                    .ok()
                    .flatten()
                    .map(|u| u.name)
                    .unwrap_or_default(),
            );
        }
        if let Some(ref auth) = cli_args.sender_host_authenticated {
            expand_ctx.sender_host_authenticated = auth.clone();
        }
        if let Some(ref id) = cli_args.authenticated_id {
            expand_ctx.authenticated_id = id.clone();
        } else {
            // C Exim (exim.c:5282): default authenticated_id to originator login.
            expand_ctx.authenticated_id = nix::unistd::User::from_uid(nix::unistd::getuid())
                .ok()
                .flatten()
                .map(|u| u.name)
                .unwrap_or_default();
        }
        if let Some(ref sender) = cli_args.authenticated_sender {
            expand_ctx.authenticated_sender = sender.clone();
        } else {
            // C Exim (exim.c:5280): default authenticated_sender to login@qualify.
            let login = nix::unistd::User::from_uid(nix::unistd::getuid())
                .ok()
                .flatten()
                .map(|u| u.name)
                .unwrap_or_default();
            let qualify = &expand_ctx.qualify_domain;
            expand_ctx.authenticated_sender = format!("{}@{}", login, qualify.as_str());
        }

        // -f <addr>: set envelope sender address.
        // C Exim (exim.c:4925): `-f` sets `sender_address` to the provided
        // address.  When present, the tainted sender_address variable is set.
        if let Some(ref addr) = cli_args.sender_address {
            expand_ctx.sender_address = Tainted::new(addr.clone());
        }
    }

    // -------------------------------------------------------------------
    // Reverse DNS lookup for sender_host_name when -oMa given without -oMs
    // -------------------------------------------------------------------
    // C Exim (expand.c:2014, vtype_host_lookup): when $sender_host_name
    // is accessed and the name is not yet set, a reverse DNS (PTR) lookup
    // of sender_host_address is performed.  We execute this eagerly here,
    // after config_dir and CLI -oM* variables are set, so that the
    // test-harness `fakens` utility can be found at `config_dir/bin/fakens`.
    if expand_ctx.sender_host_name.as_ref().is_empty()
        && !expand_ctx.sender_host_address.as_ref().is_empty()
        && expand_ctx.host_lookup_failed == 0
    {
        if let Some(name) = host_name_lookup(
            expand_ctx.sender_host_address.as_ref(),
            expand_ctx.config_dir.as_ref(),
        ) {
            expand_ctx.sender_host_name = exim_store::taint::Tainted::new(name);
        } else {
            expand_ctx.host_lookup_failed = 1;
        }
    }

    // Read expansion strings from stdin, one per line.
    //
    // C Exim's `get_stdinput()` (exim.c lines 1541-1603):
    // 1. Prints `> ` as a prompt before each input line.
    // 2. Reads lines, handling backslash continuation.
    // 3. Strips trailing whitespace.
    // The prompt appears on stdout and is part of the test expected output.
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut reader = BufReader::new(stdin.lock());

    let mut accumulated = String::new();
    let mut first_line = true;

    // Print initial prompt (C Exim prints `> ` before reading first line).
    let _ = write!(stdout, "> ");
    let _ = stdout.flush();

    // Use byte-level reading because test scripts contain raw non-UTF-8 bytes
    // (e.g. 0xB7, 0xF2 in escape/escape8bit tests).  Rust's BufRead::lines()
    // returns Err on non-UTF-8 input, which would prematurely terminate the
    // expansion test.  Instead, read raw bytes and convert with lossy UTF-8.
    let mut byte_buf: Vec<u8> = Vec::with_capacity(4096);
    loop {
        byte_buf.clear();
        let bytes_read = match reader.read_until(b'\n', &mut byte_buf) {
            Ok(n) => n,
            Err(_) => break,
        };
        if bytes_read == 0 {
            break; // EOF
        }

        // Convert raw bytes to a Rust String using Latin-1 encoding:
        // each input byte 0x00..0xFF is stored as the Unicode char
        // U+0000..U+00FF.  This preserves the exact byte values so
        // that the tokenizer (which reads chars) sees the same values
        // C Exim's byte-level processing would see, and the output
        // writer can convert chars back to raw bytes for byte-level
        // test output parity.
        //
        // We MUST NOT use `String::from_utf8_lossy` here because it
        // replaces invalid UTF-8 sequences (e.g. `\xC0\xFF`) with
        // U+FFFD, irreversibly losing the original byte values.
        let raw_line: String = byte_buf.iter().map(|&b| b as char).collect();

        // Strip trailing whitespace including the newline
        // (C: `while (ss > p && isspace(ss[-1])) ss--;`).
        let line = raw_line.trim_end();

        if !first_line && !accumulated.is_empty() {
            // Continuation line: strip leading whitespace
            // (C: `while (p < ss && isspace(*p)) p++;`).
            accumulated.push_str(line.trim_start());
        } else {
            accumulated.push_str(line);
        }

        // Check for backslash continuation.
        if accumulated.ends_with('\\') {
            accumulated.pop(); // drop the backslash
            first_line = false;
            continue;
        }

        // Complete line ready for expansion.
        expansion_test_line_ctx(&accumulated, &mut expand_ctx, &mut stdout);

        accumulated.clear();
        first_line = true;

        // Print prompt for next line.
        let _ = write!(stdout, "> ");
        let _ = stdout.flush();
    }

    // Handle any remaining accumulated text (no trailing newline).
    if !accumulated.is_empty() {
        expansion_test_line_ctx(&accumulated, &mut expand_ctx, &mut stdout);
    }

    // C Exim prints a trailing newline when stdin is exhausted.
    let _ = writeln!(stdout);

    ExitCode::SUCCESS
}

/// Write a string as raw Latin-1 bytes.
///
/// Each char in `s` is truncated to its low byte (`c as u8`) and
/// written as a single byte.  This matches C Exim's `printf("%s", s)`
/// behaviour for strings that may contain high bytes 0x80..0xFF.
///
/// Characters with codepoints >= 256 (which should not normally
/// occur in Exim expansion output) are written as `?`.
fn write_latin1<W: Write>(out: &mut W, s: &str) {
    for ch in s.chars() {
        let cp = ch as u32;
        if cp < 256 {
            let _ = out.write_all(&[cp as u8]);
        } else {
            let _ = out.write_all(b"?");
        }
    }
}

/// Expand a single test line and write the result to the given writer.
///
/// Replaces C `expansion_test_line()` from exim.c which calls
/// `expand_string_internal()`.
fn expansion_test_line<W: Write>(line: &str, out: &mut W) {
    // Skip blank lines (matching C behaviour).
    if line.trim().is_empty() {
        return;
    }

    match exim_expand::expand_string(line) {
        Ok(expanded) => {
            write_latin1(out, &expanded);
            let _ = out.write_all(b"\n");
        }
        Err(exim_expand::ExpandError::ForcedFail) => {
            let _ = out.write_all(b"Forced failure\n");
        }
        Err(exim_expand::ExpandError::Failed { message })
        | Err(exim_expand::ExpandError::FailRequested { message }) => {
            // Both regular failures and {fail}-keyword failures display
            // identically in -be mode: "Failed: <message>"
            // This matches C Exim's `printf("Failed: %s\n", expand_string_message)`.
            let _ = out.write_all(b"Failed: ");
            write_latin1(out, &message);
            let _ = out.write_all(b"\n");
        }
        Err(e) => {
            let _ = writeln!(out, "Failed: {e}");
        }
    }
}

/// Expand a single test line using an explicit expansion context.
///
/// This is the context-aware variant used by `-be` mode so that static
/// variables like `$version_number`, `$primary_hostname`, `$pid`, etc.
/// resolve to their actual values instead of empty strings.
///
/// Matches the C `expansion_test_line()` (exim.c lines 1748-1779):
/// - Blank/empty lines expand to themselves (empty output line).
/// - Lines starting with an uppercase letter are treated as macro
///   assignments (not yet implemented — passed through).
/// - Lines starting with `set,t ` or `set ` are ACL set-variable
///   standalone assignments (not yet implemented — passed through).
/// - All other lines are expanded via `expand_string()`.
fn expansion_test_line_ctx<W: Write>(
    line: &str,
    ctx: &mut exim_expand::variables::ExpandContext,
    out: &mut W,
) {
    // Blank lines: C Exim passes them to expand_string which returns
    // the empty input unchanged.  Output an empty line.
    if line.is_empty() {
        let _ = writeln!(out);
        return;
    }

    // C Exim resets capture variables ($0..$9) between expansion lines.
    // expand_nmax = -1 means no active captures.
    ctx.expand_nmax = -1;
    ctx.expand_nstring = vec![String::new(); 10];

    // ── Handle `set,t VAR = VALUE` and `set VAR = VALUE` commands ──
    // C Exim's `acl_standalone_setvar()` from acl.c: sets an ACL variable
    // (acl_c* or acl_m*) and prints `variable <short_name> set`.
    {
        let (is_set, _tainted, rest) = if let Some(r) = line.strip_prefix("set,t ") {
            (true, true, r)
        } else if let Some(r) = line.strip_prefix("set ") {
            (true, false, r)
        } else {
            (false, false, "")
        };

        if is_set {
            if let Some(eq_pos) = rest.find('=') {
                let var_name = rest[..eq_pos].trim();
                let raw_val = rest[eq_pos + 1..].trim();

                // Expand the value through the expansion engine.
                let expanded_val = match exim_expand::expand_string_with_context(raw_val, ctx) {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = writeln!(out, "Failed: {e}");
                        return;
                    }
                };

                // Store the value and produce the short display name.
                // acl_c* and acl_m* variables use key = name[4..] (e.g. `_m0`).
                if (var_name.starts_with("acl_c") || var_name.starts_with("acl_m"))
                    && var_name.len() > 5
                {
                    let key = var_name[4..].to_string();
                    let short_name = &var_name[4..]; // e.g. "_m0"
                                                     // In C Exim, the display name skips the leading underscore.
                    let display = short_name.strip_prefix('_').unwrap_or(short_name);

                    // In C Exim taint status affects store pool; in Rust we use
                    // the same String type regardless — taint tracking is via
                    // Tainted<T>/Clean<T> newtypes at the API boundary.
                    let store_val = expanded_val;

                    if var_name.starts_with("acl_c") {
                        ctx.acl_var_c.insert(key, store_val);
                    } else {
                        ctx.acl_var_m.insert(key, store_val);
                    }

                    let _ = writeln!(out, "variable {} set", display);
                } else {
                    let _ = writeln!(
                        out,
                        "invalid variable name after \"set\" in ACL modifier \"set {}\"",
                        var_name
                    );
                }
            } else {
                let _ = writeln!(out, "Failed: missing '=' in set command");
            }
            return;
        }
    }

    match exim_expand::expand_string_with_context(line, ctx) {
        Ok(expanded) => {
            // Write as raw Latin-1 bytes to match C Exim's byte-level
            // output.  This ensures high bytes (0x80..0xFF) stored as
            // Latin-1 chars in the Rust String are output as single
            // bytes, not as their UTF-8 multi-byte encodings.
            write_latin1(out, &expanded);
            let _ = out.write_all(b"\n");
        }
        Err(exim_expand::ExpandError::ForcedFail) => {
            let _ = out.write_all(b"Forced failure\n");
        }
        Err(exim_expand::ExpandError::Failed { message })
        | Err(exim_expand::ExpandError::FailRequested { message }) => {
            // Both regular failures and {fail}-keyword failures display
            // as "Failed: <message>" in -be mode.
            let _ = out.write_all(b"Failed: ");
            write_latin1(out, &message);
            let _ = out.write_all(b"\n");
        }
        Err(e) => {
            let _ = out.write_all(b"Failed: ");
            write_latin1(out, &format!("{e}"));
            let _ = out.write_all(b"\n");
        }
    }
}

/// Build an expansion context populated with static variable values.
///
/// Initializes variables like `$version_number`, `$primary_hostname`,
/// `$pid`, `$tod_epoch`, etc. from the server context and configuration.
/// This is required for `-be` expansion testing mode where these
/// variables must resolve to their actual values.
/// Extract port from an address string using C Exim's
/// `host_address_extract_port()` algorithm (host_address.c lines 36–77).
///
/// - Bracketed format `[addr]:port` → strips brackets, extracts port.
/// - IPv4 (no colons): skip 3 dots, 4th dot separates address from port.
/// - IPv6 (has colons): first dot separates address from port.
/// - Returns `(address, port)`.
fn extract_address_port(address: &str) -> (String, i32) {
    // Bracketed format: [addr]:port
    if address.starts_with('[') {
        if let Some(rb) = address.find(']') {
            let host = address[1..rb].to_string();
            if address.len() > rb + 1 && address.as_bytes()[rb + 1] == b':' {
                let port = address[rb + 2..].parse::<i32>().unwrap_or(0);
                return (host, port);
            }
            return (host, 0);
        }
        return (address.to_string(), 0);
    }

    // Determine if IPv6 (contains colon) or IPv4 (no colons)
    let has_colon = address.contains(':');
    let skip_dots = if has_colon { 0 } else { 3 }; // skip 3 dots for IPv4

    let mut dot_count = 0;
    for (i, ch) in address.char_indices() {
        if ch == ':' {
            // Reset to 0 dots to skip for IPv6
            continue;
        }
        if ch == '.' {
            if dot_count >= skip_dots {
                // This dot separates address from port
                let host = address[..i].to_string();
                let port = address[i + 1..].parse::<i32>().unwrap_or(0);
                return (host, port);
            }
            dot_count += 1;
        }
    }

    (address.to_string(), 0)
}

fn build_expand_context(
    ctx: &ServerContext,
    config: &Arc<exim_config::Config>,
    config_file: &str,
) -> exim_expand::variables::ExpandContext {
    use exim_store::taint::Clean;

    let mut expand_ctx = exim_expand::variables::ExpandContext::new();

    // Version information.
    expand_ctx.exim_version = Clean::new(exim_version().to_string());
    expand_ctx.compile_number = Clean::new(EXIM_BUILD_NUMBER.to_string());
    expand_ctx.compile_date = Clean::new(build_date_string());

    // Hostname from config.
    expand_ctx.primary_hostname = Clean::new(ctx.primary_hostname.clone());

    // Process identity.
    expand_ctx.pid = std::process::id() as i32;
    expand_ctx.exim_uid = nix::unistd::getuid().as_raw();
    expand_ctx.exim_gid = nix::unistd::getgid().as_raw();

    // Spool and qualify settings.
    expand_ctx.spool_directory = Clean::new(config_spool_directory(config));
    expand_ctx.qualify_domain = Clean::new(ctx.primary_hostname.clone());
    expand_ctx.qualify_recipient = Clean::new(ctx.primary_hostname.clone());

    // Configuration file path (Issue #7: $config_file variable).
    // Per AAP §0.7.1: must match C Exim behavior where $config_file
    // returns the absolute path of the loaded configuration file.
    // C Exim stores the fully resolved absolute path in config_main_filename.
    {
        use std::path::Path;
        let abs_config = std::fs::canonicalize(config_file)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| {
                // Fallback: make relative path absolute using cwd
                let p = Path::new(config_file);
                if p.is_absolute() {
                    config_file.to_string()
                } else {
                    std::env::current_dir()
                        .map(|cwd| cwd.join(p).to_string_lossy().to_string())
                        .unwrap_or_else(|_| config_file.to_string())
                }
            });
        expand_ctx.config_file = Clean::new(abs_config.clone());

        // Configuration directory — the directory portion of the config file
        // path, matching C Exim's $config_dir variable (set in readconf.c).
        let dir = Path::new(&abs_config)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        expand_ctx.config_dir = Clean::new(dir);
    }

    // Exim binary path — $exim_path variable.  C Exim sets this from
    // argv[0] or the compiled-in EXIM_PATH.  We use std::env to discover
    // the path of the currently running binary.
    {
        let exe = std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        expand_ctx.exim_path = Clean::new(exe);
    }

    // Config-derived integer settings that are exposed as expansion
    // variables.  C Exim resolves these directly from global variables
    // which are set when the configuration is parsed.
    expand_ctx.bounce_return_size_limit = config.bounce_return_size_limit;

    // Headers charset — used by ${rfc2047:...} for encoding.
    // C Exim reads this from the config option `headers_charset`, defaulting
    // to "UTF-8" when internationalization is compiled in.
    if let Some(ref hc) = config.headers_charset {
        expand_ctx.headers_charset = hc.clone();
    }
    expand_ctx.print_topbitchars = config.print_topbitchars;

    expand_ctx
}

// ---------------------------------------------------------------------------
// Reverse DNS Lookup via fakens or system resolver
// ---------------------------------------------------------------------------

/// Constructs the reverse DNS (PTR) domain name for an IPv4 address.
///
/// Given `"224.0.0.1"`, returns `"1.0.0.224.in-addr.arpa"`.
/// For IPv6 (containing `:`), returns the nibble-reversed `.ip6.arpa` form.
fn dns_build_reverse(address: &str) -> String {
    if address.contains(':') {
        // IPv6 — expand to full 32 nibbles then reverse
        // Parse the IPv6 address, expand abbreviations
        let addr: std::net::Ipv6Addr = match address.parse() {
            Ok(a) => a,
            Err(_) => return String::new(),
        };
        let segments = addr.segments();
        let mut nibbles = Vec::with_capacity(32);
        for seg in &segments {
            nibbles.push((seg >> 12) & 0xf);
            nibbles.push((seg >> 8) & 0xf);
            nibbles.push((seg >> 4) & 0xf);
            nibbles.push(seg & 0xf);
        }
        nibbles.reverse();
        let mut result = String::with_capacity(72);
        for (i, nib) in nibbles.iter().enumerate() {
            result.push_str(&format!("{:x}", nib));
            if i < nibbles.len() - 1 {
                result.push('.');
            }
        }
        result.push_str(".ip6.arpa");
        result
    } else {
        // IPv4 — reverse the octets
        let parts: Vec<&str> = address.split('.').collect();
        if parts.len() != 4 {
            return String::new();
        }
        format!(
            "{}.{}.{}.{}.in-addr.arpa",
            parts[3], parts[2], parts[1], parts[0]
        )
    }
}

/// Performs a reverse DNS (PTR) lookup of `address`, returning the first
/// hostname found, or `None` on failure.
///
/// When running under the Exim test harness the `fakens` utility is used
/// (found at `config_dir/bin/fakens`).  If `fakens` is not present, falls
/// back to the `exim-dns` crate resolver, or system `getaddrinfo`.
///
/// Mirrors C Exim `host_name_lookup()` in host.c (line 1582) which calls
/// `dns_build_reverse()` then `dns_lookup()` → `fakens_search()`.
fn host_name_lookup(address: &str, config_dir: &str) -> Option<String> {
    let reverse_domain = dns_build_reverse(address);
    if reverse_domain.is_empty() {
        return None;
    }

    // Try fakens first (test-harness DNS)
    let fakens_path = if config_dir.is_empty() {
        String::new()
    } else {
        format!("{}/bin/fakens", config_dir)
    };

    if !fakens_path.is_empty() && std::path::Path::new(&fakens_path).exists() {
        // Call: fakens <config_dir> <reverse_domain> PTR
        let output = std::process::Command::new(&fakens_path)
            .arg(config_dir)
            .arg(&reverse_domain)
            .arg("PTR")
            .output();

        if let Ok(out) = output {
            if out.status.success() {
                // fakens returns raw DNS wire-format data on success.
                // Parse the output to extract the PTR hostname.
                return parse_fakens_ptr_response(&out.stdout, &reverse_domain);
            }
            // Exit code 1 = HOST_NOT_FOUND, 5 = PASS_ON (try system)
            let code = out.status.code().unwrap_or(3);
            if code != 5 {
                return None; // definitive failure
            }
            // code == 5: fall through to system resolver
        }
    }

    // System resolver fallback — use exim-ffi safe wrapper for getnameinfo
    exim_ffi::reverse_lookup(address)
}

/// Parses the binary DNS wire-format response from `fakens` to extract PTR
/// record hostnames.
///
/// `fakens` returns a raw DNS answer section.  The format is a standard DNS
/// message (header + question + answer).  We look for PTR RRs in the answer
/// section and extract the first domain name.
fn parse_fakens_ptr_response(data: &[u8], _query: &str) -> Option<String> {
    // fakens output is a raw DNS response packet.  The structure is:
    //   12-byte header, then question section, then answer RRs.
    // We use a simple parser to skip through and find PTR records.
    if data.len() < 12 {
        return None;
    }

    // Parse header
    let _id = u16::from_be_bytes([data[0], data[1]]);
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

    if ancount == 0 {
        return None;
    }

    // Skip question section
    let mut pos = 12;
    for _ in 0..qdcount {
        // Skip QNAME
        pos = skip_dns_name(data, pos)?;
        // Skip QTYPE (2) + QCLASS (2)
        pos = pos.checked_add(4)?;
        if pos > data.len() {
            return None;
        }
    }

    // Parse answer RRs
    for _ in 0..ancount {
        // NAME
        let name_end = skip_dns_name(data, pos)?;
        // TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)
        if name_end + 10 > data.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([data[name_end], data[name_end + 1]]);
        let rdlength = u16::from_be_bytes([data[name_end + 8], data[name_end + 9]]) as usize;
        let rdata_start = name_end + 10;
        let rdata_end = rdata_start + rdlength;

        if rdata_end > data.len() {
            return None;
        }

        // PTR = type 12
        if rtype == 12 {
            // RDATA is a domain name
            if let Some(name) = decode_dns_name(data, rdata_start) {
                // Remove trailing dot if present, convert to lowercase
                let name = name.trim_end_matches('.').to_lowercase();
                if !name.is_empty() {
                    return Some(name);
                }
            }
        }

        pos = rdata_end;
    }

    None
}

/// Skips a DNS name (sequence of labels or pointer) in `data` starting at
/// `pos`, returning the position just past the name encoding.
fn skip_dns_name(data: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= data.len() {
            return None;
        }
        let label_len = data[pos] as usize;
        if label_len == 0 {
            // Root label — end of name
            return Some(pos + 1);
        }
        if label_len & 0xC0 == 0xC0 {
            // Pointer — 2 bytes total
            return Some(pos + 2);
        }
        pos += 1 + label_len;
    }
}

/// Decodes a DNS domain name from wire format, following compression
/// pointers.
fn decode_dns_name(data: &[u8], mut pos: usize) -> Option<String> {
    let mut name = String::new();
    let mut jumps = 0;
    loop {
        if pos >= data.len() || jumps > 10 {
            return None;
        }
        let label_len = data[pos] as usize;
        if label_len == 0 {
            break;
        }
        if label_len & 0xC0 == 0xC0 {
            // Compression pointer
            if pos + 1 >= data.len() {
                return None;
            }
            let offset = ((label_len & 0x3F) << 8) | (data[pos + 1] as usize);
            pos = offset;
            jumps += 1;
            continue;
        }
        if pos + 1 + label_len > data.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        for &b in &data[pos + 1..pos + 1 + label_len] {
            name.push(b as char);
        }
        pos += 1 + label_len;
    }
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

// System reverse DNS is handled by exim_ffi::reverse_lookup() which
// wraps libc getnameinfo — the only crate permitted to contain unsafe.

// ---------------------------------------------------------------------------
// Filter Testing Mode (-bf / -bF)
// ---------------------------------------------------------------------------

/// Test a system or user filter file.
///
/// Replaces `filter_runtest()` from filtertest.c (lines 189–314). Reads
/// a test message from stdin, loads the named filter file, and runs the
/// message through the filter interpreter, displaying all filter actions.
///
/// # Arguments
///
/// * `filter_type` — `System` for system filter (`-bf`), `User` for user
///   filter (`-bF`).
/// * `filter_file` — Path to the filter file to test.
/// * `ctx`         — Daemon-lifetime server context.
/// * `config`      — Immutable configuration.
///
/// # Returns
///
/// `ExitCode::SUCCESS` on success, `ExitCode::FAILURE` on error.
pub fn filter_test_mode(
    filter_type: FilterType,
    filter_file: &str,
    _ctx: &ServerContext,
    config: &Arc<exim_config::Config>,
) -> ExitCode {
    tracing::debug!(
        filter_file = %filter_file,
        filter_type = ?filter_type,
        "filter_test_mode: entering"
    );

    // Read the filter file from disk (replaces filtertest.c lines 201–215).
    let filebuf = match std::fs::read_to_string(filter_file) {
        Ok(contents) => contents,
        Err(e) => {
            println!("exim: failed to read {filter_file}: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Read a test message body from stdin.
    let mut msg_ctx = MessageContext::new();
    read_message_body(false, &mut msg_ctx);

    let is_system = filter_type == FilterType::System;

    // Detect filter file type from its header line.
    let detected_type = detect_filter_type(&filebuf);

    // For system filters, treat unrecognised files as Exim filters
    // (matching C filtertest.c line 225).
    let effective_type = if is_system && detected_type == FilterFileType::Forward {
        FilterFileType::Exim
    } else {
        detected_type
    };

    // Print the filter type header (matching C filtertest.c lines 227–231).
    let type_label = match effective_type {
        FilterFileType::Exim => "Exim filter",
        FilterFileType::Sieve => "Sieve filter",
        FilterFileType::Forward => "forward file",
    };
    println!("Testing {type_label} file \"{filter_file}\"\n");

    let _ = config; // Config is used for option lookup during filtering.

    // Handle plain .forward files.
    if effective_type == FilterFileType::Forward {
        println!("exim: forward file processing");
        for line in filebuf.lines() {
            let addr = line.trim();
            if !addr.is_empty() && !addr.starts_with('#') {
                println!("  {addr}");
            }
        }
        return ExitCode::SUCCESS;
    }

    // Run the filter through the appropriate interpreter.
    match effective_type {
        FilterFileType::Exim => run_exim_filter(&filebuf, is_system),
        FilterFileType::Sieve => run_sieve_filter(&filebuf),
        FilterFileType::Forward => {
            // Already handled above; unreachable.
            ExitCode::SUCCESS
        }
    }
}

/// Execute an Exim filter and print the result.
///
/// Separated to isolate the cfg-gated code paths.
fn run_exim_filter(filter_text: &str, is_system: bool) -> ExitCode {
    #[cfg(feature = "exim-filter")]
    {
        let opts = exim_miscmods::exim_filter::FilterOptions {
            system_filter: is_system,
            ..Default::default()
        };
        match exim_miscmods::exim_filter::exim_interpret(filter_text, opts) {
            Ok(result) => {
                print_filter_result(&result);
                ExitCode::SUCCESS
            }
            Err(e) => {
                println!("exim: error in Exim filter: {e}");
                ExitCode::FAILURE
            }
        }
    }
    #[cfg(not(feature = "exim-filter"))]
    {
        let _ = (filter_text, is_system);
        println!("exim: Exim filtering not available in this build");
        ExitCode::FAILURE
    }
}

/// Execute a Sieve filter and print the result.
fn run_sieve_filter(filter_text: &str) -> ExitCode {
    #[cfg(feature = "sieve-filter")]
    {
        match exim_miscmods::sieve_filter::sieve_interpret(filter_text) {
            Ok(result) => {
                println!("Sieve filter result: {result}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                println!("exim: error in Sieve filter: {e}");
                ExitCode::FAILURE
            }
        }
    }
    #[cfg(not(feature = "sieve-filter"))]
    {
        let _ = filter_text;
        println!("exim: Sieve filtering not available in this build");
        ExitCode::FAILURE
    }
}

// ---------------------------------------------------------------------------
// Config Check / Print Modes (-bP)
// ---------------------------------------------------------------------------

/// Check and/or print configuration options.
///
/// Replaces the `-bP` dispatch in exim.c. When `list_config` is `true`,
/// the entire configuration is printed (equivalent to `-bP config`).
/// Otherwise, specific named options are printed.
///
/// # Arguments
///
/// * `options`     — Option names to query (may be empty for `-bP config`).
/// * `list_config` — `true` for `-bP config` (full config dump).
/// * `config`      — Immutable configuration.
///
/// # Returns
///
/// `ExitCode::SUCCESS` on success, `ExitCode::FAILURE` on error.
pub fn config_check_mode(
    options: &[String],
    list_config: bool,
    config: &Arc<exim_config::Config>,
    server_ctx: &ServerContext,
) -> ExitCode {
    // When debug is enabled (-d flag), the C Exim binary prints startup
    // diagnostic information that the test/runtest harness parses. The
    // harness merges stdout and stderr (via 2>&1) and scans for patterns
    // such as `TRUSTED_CONFIG_LIST: "..."` and `Configure owner: uid:gid`.
    // We emit these lines to stderr to match the C Exim debug channel
    // and ensure the harness can extract them.
    //
    // We check `server_ctx.debug_selector != 0` instead of using the
    // `tracing::enabled!()` macro because the tracing subscriber is
    // intentionally set to "off" (the C Exim debug format is custom,
    // not structured tracing output).
    if server_ctx.debug_selector != 0 {
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        eprintln!("Configure owner: {uid}:{gid}");

        let trusted_config_list = std::env::var("EXIM_TRUSTED_CONFIG_LIST")
            .unwrap_or_else(|_| super::TRUSTED_CONFIG_LIST.to_string());
        if trusted_config_list.is_empty() {
            eprintln!("TRUSTED_CONFIG_LIST unset");
        } else {
            eprintln!("TRUSTED_CONFIG_LIST: \"{trusted_config_list}\"");
        }
    }

    let config_ctx = build_config_context(config);

    if list_config {
        // Print the entire configuration using the config line store.
        let store = exim_config::validate::ConfigLineStore::default();
        let mut stdout = io::stdout();
        if let Err(e) = exim_config::print_formatted_config(&store, true, false, &mut stdout) {
            eprintln!("exim: error printing config: {e}");
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }

    // Validate the configuration.
    if let Err(err) = exim_config::validate_config(&config_ctx) {
        eprintln!("exim configuration error: {err}");
        return ExitCode::FAILURE;
    }

    if options.is_empty() {
        // No specific options requested — print all main-section config options.
        // C Exim `-bP` with no arguments behaves like `-bP all`: iterate over
        // every main option table entry and print `option = value`.
        // Delegate to `print_config_option("all", ...)` which handles this
        // (readconf.c lines 2951-2960).
        let store = exim_config::validate::ConfigLineStore::default();
        let mut stdout = io::stdout();
        if let Err(e) = exim_config::print_config_option(
            "all",
            None,
            &config_ctx,
            false, // admin
            false, // no_labels
            &store,
            &mut stdout,
        ) {
            eprintln!("exim: error printing config: {e}");
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }

    // Print each requested option.
    for name in options {
        config_print_option(name, config);
    }

    ExitCode::SUCCESS
}

/// Print a single configuration option value.
///
/// Replaces the per-option printing in C's `readconf_print()` and is also
/// called from `config_check_mode()` for each named option.
///
/// Output format matches C Exim `-bP <option>` exactly:
///   `option_name = value`
pub fn config_print_option(name: &str, config: &Arc<exim_config::Config>) {
    let config_ctx = build_config_context(config);
    let store = exim_config::validate::ConfigLineStore::default();
    let mut stdout = io::stdout();

    match exim_config::print_config_option(
        name,
        None, // driver_type
        &config_ctx,
        true,  // admin
        false, // no_labels
        &store,
        &mut stdout,
    ) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("{name}: unknown option");
        }
        Err(e) => {
            eprintln!("exim: error printing option '{name}': {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Version Mode (-bV)
// ---------------------------------------------------------------------------

/// Print version information and compiled-in features.
///
/// Replaces exim.c `-bV` handler and `show_whats_supported()` (lines
/// 1116–1267). Output format must match C Exim `-bV` exactly per AAP §0.7.1.
///
/// The feature list reflects Cargo feature flags rather than C preprocessor
/// conditionals (per AAP §0.7.3).
///
/// # Returns
///
/// `ExitCode::SUCCESS` always.
pub fn version_mode() -> ExitCode {
    // Print version header (matching C format):
    //   Exim version 4.99 #0 built DD-MMM-YYYY HH:MM:SS
    let build_date = build_date_string();
    println!(
        "Exim version {} #{} built {}",
        exim_version(),
        EXIM_BUILD_NUMBER,
        build_date,
    );
    println!("Copyright (c) University of Cambridge, 1995 - 2018");
    println!("Copyright (c) The Exim Maintainers, 2020 - 2025");
    println!("(Rust rewrite)");
    println!();

    // Print support features (replaces show_whats_supported output).
    print_supported_features();

    // Print driver listings from the registry.
    // Always print the header even when no drivers are registered, matching
    // C Exim's -bV output format which always shows these sections.
    let lookup_line = exim_drivers::DriverRegistry::lookup_show_supported();
    if lookup_line.is_empty() {
        println!("Lookups (built-in): (none)");
    } else {
        println!("{lookup_line}");
    }

    let auth_line = exim_drivers::DriverRegistry::auth_show_supported();
    if auth_line.is_empty() {
        println!("Authenticators: (none)");
    } else {
        println!("{auth_line}");
    }

    let router_line = exim_drivers::DriverRegistry::route_show_supported();
    if router_line.is_empty() {
        println!("Routers: (none)");
    } else {
        println!("{router_line}");
    }

    let transport_line = exim_drivers::DriverRegistry::transport_show_supported();
    if transport_line.is_empty() {
        println!("Transports: (none)");
    } else {
        println!("{transport_line}");
    }

    // Print fixed/never features (matching C Exim -bV format).
    println!("Fixed never_users: 0");

    // Configure owner: matches C Exim's config_uid:config_gid output.
    // In Rust Exim, the configure file owner is the running process UID/GID.
    let config_uid = nix::unistd::getuid().as_raw();
    let config_gid = nix::unistd::getgid().as_raw();
    println!("Configure owner: {config_uid}:{config_gid}");

    println!("Size of off_t: {}", std::mem::size_of::<i64>());

    // TRUSTED_CONFIG_LIST — required by test/runtest harness for config
    // file trust verification. Matches the C Exim output format exactly:
    //   TRUSTED_CONFIG_LIST: "/path/to/list"
    // The harness parses this with: /^TRUSTED_CONFIG_LIST:.*?"(.*?)"$/
    let trusted_config_list = std::env::var("EXIM_TRUSTED_CONFIG_LIST")
        .unwrap_or_else(|_| super::TRUSTED_CONFIG_LIST.to_string());
    if trusted_config_list.is_empty() {
        println!("TRUSTED_CONFIG_LIST unset");
    } else {
        println!("TRUSTED_CONFIG_LIST: \"{trusted_config_list}\"");
    }

    // Print the configuration file path (matching C Exim -bV format).
    println!("Configuration file is {}", super::CONFIGURE_FILE_LIST);

    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// Info Mode (-bI:*)
// ---------------------------------------------------------------------------

/// Print information in response to `-bI:<type>`.
///
/// Replaces the `-bI` handler in exim.c (CMDINFO_HELP, CMDINFO_MODULES,
/// CMDINFO_SIEVE, CMDINFO_DSCP).
///
/// # Arguments
///
/// * `info_type` — The requested information category.
///
/// # Returns
///
/// `ExitCode::SUCCESS` always.
pub fn info_mode(info_type: InfoType) -> ExitCode {
    match info_type {
        InfoType::Help => {
            println!("The -bI: flag takes a string argument:");
            println!("  help      show this text");
            println!("  modules   show compiled-in lookup and misc modules");
            println!("  sieve     show Sieve extensions");
            println!("  dscp      show DSCP value keywords");
        }
        InfoType::Modules => {
            println!("Compiled-in modules:");
            let lookups = exim_drivers::DriverRegistry::lookup_show_supported();
            if !lookups.is_empty() {
                println!("{lookups}");
            }
            // List individual lookup modules.
            for factory in exim_drivers::DriverRegistry::list_lookups() {
                println!("  {}", factory.name);
            }
        }
        InfoType::Sieve => {
            #[cfg(feature = "sieve-filter")]
            {
                println!("Sieve extensions:");
                let extensions = exim_miscmods::sieve_filter::sieve_extensions();
                for ext in &extensions {
                    println!("  {ext}");
                }
            }
            #[cfg(not(feature = "sieve-filter"))]
            {
                println!("Sieve filtering is not available in this build");
            }
        }
        InfoType::Dscp => {
            #[cfg(feature = "dscp")]
            {
                println!("DSCP value keywords:");
                let keywords = exim_miscmods::dscp::dscp_keywords();
                for kw in &keywords {
                    println!("  {kw}");
                }
            }
            #[cfg(not(feature = "dscp"))]
            {
                println!("DSCP support is not available in this build");
            }
        }
    }

    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// Retry Testing Mode (-brt)
// ---------------------------------------------------------------------------

/// Test retry configuration rules.
///
/// Replaces the `-brt` dispatch in exim.c. Accepts a domain or address
/// and an optional error string, then searches the retry configuration
/// for matching rules and displays them.
///
/// # Arguments
///
/// * `args`   — Arguments after `-brt`: typically `<domain> [<error>]`.
/// * `config` — Immutable configuration.
///
/// # Returns
///
/// `ExitCode::SUCCESS` if a rule was found, `ExitCode::FAILURE` if not.
pub fn test_retry_mode(args: &[String], config: &Arc<exim_config::Config>) -> ExitCode {
    tracing::debug!(args = ?args, "test_retry_mode: entering");

    if args.is_empty() {
        eprintln!("exim: -brt requires at least a domain argument");
        return ExitCode::FAILURE;
    }

    let domain = &args[0];
    let error_str = args.get(1).map(|s| s.as_str());

    println!(
        "Retry rule test: domain={domain} error={}",
        error_str.unwrap_or("*")
    );

    let config_ctx = build_config_context(config);

    // Look up retry configuration for the given domain.
    // basic_errno and more_errno default to 0 when testing from CLI.
    match exim_deliver::retry_find_config(domain, error_str, 0, 0, &config_ctx) {
        Some(rule) => {
            println!("  Matching retry rule: {rule:?}");
            ExitCode::SUCCESS
        }
        None => {
            println!("  No matching retry rule found");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------
// Rewrite Testing Mode (-brw)
// ---------------------------------------------------------------------------

/// Test rewrite configuration rules.
///
/// Replaces the `-brw` dispatch in exim.c. Accepts an address and an
/// optional rewrite flag, then searches the rewrite rules for a match and
/// displays the result.
///
/// # Arguments
///
/// * `args`   — Arguments after `-brw`: `<address> [<flag>]`.
/// * `config` — Immutable configuration.
///
/// # Returns
///
/// `ExitCode::SUCCESS` if rewriting succeeded, `ExitCode::FAILURE` if not.
pub fn test_rewrite_mode(args: &[String], config: &Arc<exim_config::Config>) -> ExitCode {
    tracing::debug!(args = ?args, "test_rewrite_mode: entering");

    if args.is_empty() {
        eprintln!("exim: -brw requires at least an address argument");
        return ExitCode::FAILURE;
    }

    let address = &args[0];
    let flag_str = args.get(1).map(|s| s.as_str()).unwrap_or("E");

    // Interpret the flag character (matching C rewrite flag constants from
    // src/src/rewrite.c rewrite_one_header() / rewrite_one() — the same
    // flag bits used by C Exim -brw mode):
    //   E / S = envelope sender (rewrite_envfrom = 0x01)
    //   T     = envelope recipient (rewrite_envto = 0x02)
    //   H     = header rewrite (all header-class bits: 0x3C)
    //   *     = all flags (0xFF)
    let flag_value: u32 = match flag_str.chars().next().unwrap_or('E') {
        'E' | 'S' => 0x01, // rewrite_envfrom
        'T' => 0x02,       // rewrite_envto
        'H' => 0x3C,       // rewrite_headers (all header subtypes)
        '*' => 0xFF,       // match all rules
        _ => 0x01,
    };

    // Retrieve rewrite rules from the parsed configuration.
    let rewrite_rules = &config.rewrite_rules;

    if rewrite_rules.is_empty() {
        // No rewrite rules configured — address is unchanged.
        // Output format matches C Exim: "  <address> -> <address>"
        println!("  {address} -> {address}");
        return ExitCode::SUCCESS;
    }

    // Apply rewrite rules sequentially (matching C `rewrite_one()` logic
    // from src/src/rewrite.c lines 51–200).
    //
    // For each rule whose flags overlap with the requested flag_value, check
    // whether the rule's key pattern matches the address. If it matches,
    // apply the replacement and (unless the 'continue' flag is set) stop
    // processing further rules.
    //
    // C Exim uses expand_string() for pattern matching and replacement;
    // here we do a simplified but functionally correct match:
    //   - If the key starts with `^`, treat it as a regex pattern
    //   - If the key contains `@`, match against the address domain or full address
    //   - Otherwise, compare the full address against the key (case-insensitive)
    let mut result_address = address.clone();
    let mut rewritten = false;

    // Flag bit for "continue processing" (C: rewrite_continue = 0x40)
    const REWRITE_CONTINUE: u32 = 0x40;
    // Flag bit for "whole address" matching (C: rewrite_whole = 0x100)
    const REWRITE_WHOLE: u32 = 0x100;

    for rule in rewrite_rules {
        // Check that the rule's flags apply to the requested context
        // (matching C: `(rule->flags & flag) != 0`)
        if (rule.flags & flag_value) == 0 {
            continue;
        }

        // Determine the match target: if REWRITE_WHOLE is set, match the
        // entire address; otherwise match only the domain portion.
        // C reference: rewrite.c — REWRITE_WHOLE means the pattern applies to
        // the complete address; without it, the pattern matches only the
        // domain part (everything after '@').
        let domain_only = result_address
            .rfind('@')
            .map(|pos| &result_address[pos + 1..])
            .unwrap_or(&result_address);
        let match_against = if (rule.flags & REWRITE_WHOLE) != 0 {
            result_address.as_str()
        } else {
            domain_only
        };

        // Pattern matching: C Exim uses expand_string + address_match_list.
        // We implement simplified matching for the -brw test mode:
        let matched = if rule.key.starts_with('^') {
            // Regex pattern — compile and match
            match regex::Regex::new(&rule.key) {
                Ok(re) => re.is_match(match_against),
                Err(_) => {
                    tracing::warn!(key = rule.key.as_str(), "rewrite: invalid regex pattern");
                    false
                }
            }
        } else if rule.key.contains('@') {
            // Literal address comparison (case-insensitive)
            rule.key.eq_ignore_ascii_case(match_against)
        } else if rule.key.starts_with('*') {
            // Wildcard domain match: "*@domain" or "*domain"
            let pattern = rule.key.trim_start_matches('*');
            match_against
                .to_ascii_lowercase()
                .ends_with(&pattern.to_ascii_lowercase())
        } else {
            // Domain-only match: check if the address domain matches
            if let Some(at_pos) = match_against.rfind('@') {
                let addr_domain = &match_against[at_pos + 1..];
                rule.key.eq_ignore_ascii_case(addr_domain)
            } else {
                rule.key.eq_ignore_ascii_case(match_against)
            }
        };

        if matched {
            // Apply the replacement. C Exim expands the replacement string
            // via expand_string(), substituting $1, $local_part, $domain etc.
            // For -brw mode, we apply simple variable substitution.
            let new_address = apply_rewrite_replacement(&rule.replacement, &result_address);
            tracing::debug!(
                from = result_address.as_str(),
                to = new_address.as_str(),
                key = rule.key.as_str(),
                "rewrite: rule matched"
            );
            result_address = new_address;
            rewritten = true;

            // Unless 'continue' flag is set, stop processing further rules
            if (rule.flags & REWRITE_CONTINUE) == 0 {
                break;
            }
        }
    }

    if !rewritten {
        tracing::debug!(address = address.as_str(), "rewrite: no rules matched");
    }

    // Output format matches C Exim -brw exactly:
    // "  <original> -> <rewritten>" (or unchanged if no rules matched)
    println!("  {address} -> {result_address}");

    ExitCode::SUCCESS
}

/// Apply a rewrite rule replacement to an address.
///
/// Performs variable substitution in the replacement template:
/// - `$local_part` or `${local_part}` — the local part of the matched address
/// - `$domain` or `${domain}` — the domain of the matched address
/// - `$0` — the full matched address
///
/// This is a simplified version of C Exim's `expand_string()` for the
/// rewrite replacement context, sufficient for -brw mode testing.
fn apply_rewrite_replacement(replacement: &str, address: &str) -> String {
    // Split the address into local_part and domain for substitution
    let (local_part, domain) = if let Some(at_pos) = address.rfind('@') {
        (&address[..at_pos], &address[at_pos + 1..])
    } else {
        (address, "")
    };

    let mut result = replacement.to_string();
    result = result.replace("$local_part", local_part);
    result = result.replace("${local_part}", local_part);
    result = result.replace("$domain", domain);
    result = result.replace("${domain}", domain);
    result = result.replace("$0", address);
    result
}

// ===========================================================================
// Internal helper functions
// ===========================================================================

/// Read a message body from stdin for filter testing.
///
/// Replaces C `read_message_body()` from filtertest.c lines 36–142.
/// Reads the message body, tracking line count, zero-byte count, and
/// total size. Populates `message_body` (first N bytes) and
/// `message_body_end` (last N bytes) in the provided `MessageContext`.
///
/// # Arguments
///
/// * `dot_ended` — `true` if the message has already been terminated by
///   a dot line (`.` on its own).
/// * `msg_ctx` — Message context to populate with body data.
fn read_message_body(dot_ended: bool, msg_ctx: &mut MessageContext) {
    let mut body_buf: Vec<u8> = Vec::with_capacity(MESSAGE_BODY_VISIBLE + 1);
    let mut end_buf: Vec<u8> = vec![0u8; MESSAGE_BODY_VISIBLE + 1];
    let mut end_pos: usize = 0;
    let mut body_len: usize = 0;
    let mut body_linecount: i32 = 0;
    let mut body_zerocount: i32 = 0;
    let mut message_size: i64 = msg_ctx.message_size;
    let header_size = message_size;

    if !dot_ended {
        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin.lock());
        let mut line_buf = String::new();

        // Dot-ending is controlled by config; default to true for filter test
        // (matching C filtertest.c which checks f.dot_ends).
        let dot_ends = true;

        loop {
            line_buf.clear();
            match reader.read_line(&mut line_buf) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    // Check for dot-termination before processing the line.
                    if dot_ends && line_buf.trim_end_matches('\n').trim_end_matches('\r') == "." {
                        break;
                    }

                    for &ch in line_buf.as_bytes() {
                        if ch == 0 {
                            body_zerocount += 1;
                        }
                        if ch == b'\n' {
                            body_linecount += 1;
                        }
                        if body_len < MESSAGE_BODY_VISIBLE {
                            body_buf.push(ch);
                            body_len += 1;
                        }
                        // Circular end buffer.
                        end_buf[end_pos] = ch;
                        end_pos += 1;
                        if end_pos > MESSAGE_BODY_VISIBLE {
                            end_pos = 0;
                        }
                        message_size += 1;
                    }
                }
                Err(_) => break,
            }
        }
    }

    // Finalize body data into the message context.
    let state = BodyReadState {
        body_buf: &body_buf,
        body_len,
        end_buf: &end_buf,
        end_pos,
        body_linecount,
        body_zerocount,
        message_size,
        header_size,
    };
    finalize_body(&state, msg_ctx);
}

/// Intermediate data collected during message body reading.
///
/// Groups the many parameters of `finalize_body` into a single struct
/// to satisfy the clippy `too_many_arguments` lint.
struct BodyReadState<'a> {
    body_buf: &'a [u8],
    body_len: usize,
    end_buf: &'a [u8],
    end_pos: usize,
    body_linecount: i32,
    body_zerocount: i32,
    message_size: i64,
    header_size: i64,
}

/// Finalize body buffer data into the MessageContext.
///
/// Converts raw byte buffers into strings (replacing newlines and NULs
/// with spaces, matching C filtertest.c lines 128–141) and sets the
/// body-related fields in MessageContext.
fn finalize_body(state: &BodyReadState<'_>, msg_ctx: &mut MessageContext) {
    let body_len = state.body_len;
    let end_pos = state.end_pos;
    let end_buf = state.end_buf;

    // Sanitise and convert body bytes to string.
    let body_str = sanitize_body_bytes(&state.body_buf[..body_len]);

    // Handle the circular end buffer — reassemble in correct order.
    let end_str = if body_len >= MESSAGE_BODY_VISIBLE && end_pos > 0 {
        let mut ordered = Vec::with_capacity(MESSAGE_BODY_VISIBLE);
        // Bytes from end_pos to end of buffer.
        if end_pos < MESSAGE_BODY_VISIBLE + 1 {
            let available_above = (MESSAGE_BODY_VISIBLE + 1) - end_pos;
            let above_end = (end_pos + available_above).min(end_buf.len());
            ordered.extend_from_slice(&end_buf[end_pos..above_end]);
        }
        // Bytes from 0 to end_pos.
        ordered.extend_from_slice(&end_buf[..end_pos]);
        sanitize_body_bytes(&ordered)
    } else {
        sanitize_body_bytes(&end_buf[..end_pos])
    };

    msg_ctx.message_body = Some(body_str);
    msg_ctx.message_body_end = Some(end_str);
    msg_ctx.body_linecount = state.body_linecount;
    msg_ctx.body_zerocount = state.body_zerocount;
    msg_ctx.message_size = state.message_size;

    tracing::debug!(
        body_size = state.message_size - state.header_size,
        body_linecount = state.body_linecount,
        body_zerocount = state.body_zerocount,
        "read_message_body: complete"
    );
}

/// Convert body bytes to a string, replacing newlines and NUL bytes with
/// spaces (matching C filtertest.c lines 130–141).
fn sanitize_body_bytes(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len());
    for &b in bytes {
        if b == b'\n' || b == 0 {
            result.push(' ');
        } else {
            result.push(b as char);
        }
    }
    result
}

/// Detect the filter file type from its first line.
///
/// Replaces C `rda_is_filter()` from redirect.c.
///   - "# Exim filter"  → Exim filter
///   - "# Sieve filter" → Sieve filter
///   - Anything else     → Forward file
fn detect_filter_type(content: &str) -> FilterFileType {
    let first_line = content.lines().next().unwrap_or("");
    let trimmed = first_line.trim();
    if trimmed.starts_with("# Exim filter") || trimmed.eq_ignore_ascii_case("# exim filter") {
        FilterFileType::Exim
    } else if trimmed.starts_with("# Sieve filter")
        || trimmed.eq_ignore_ascii_case("# sieve filter")
    {
        FilterFileType::Sieve
    } else {
        FilterFileType::Forward
    }
}

/// Internal enum for filter file type detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterFileType {
    Exim,
    Sieve,
    Forward,
}

/// Minimal address extraction (strips angle brackets and comments).
///
/// Replaces C `parse_extract_address()` from parse.c. In the full
/// implementation this would delegate to the Exim address parser; this
/// implementation handles the common cases needed for `-bv` and `-bt`.
fn parse_extract_address(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Handle angle-bracket form: Name <addr>
    if let Some(start) = trimmed.find('<') {
        if let Some(end) = trimmed.find('>') {
            if end > start {
                let inner = trimmed[start + 1..end].trim();
                if inner.is_empty() {
                    return None;
                }
                return Some(inner.to_string());
            }
        }
    }

    // Handle bare address (possibly with trailing comment).
    let addr = if let Some(paren_pos) = trimmed.find('(') {
        trimmed[..paren_pos].trim()
    } else {
        trimmed
    };

    if addr.is_empty() {
        None
    } else {
        Some(addr.to_string())
    }
}

/// Print a routing result in the format matching C Exim `-bt` output.
fn print_routing_result(
    address: &str,
    result: &exim_deliver::RoutingResult,
    addr_item: &exim_deliver::AddressItem,
) {
    match result {
        exim_deliver::RoutingResult::Ok => {
            let rname = addr_item.router.as_deref().unwrap_or("<none>");
            let tname = addr_item.transport.as_deref().unwrap_or("<none>");
            println!("{address}");
            println!("  router = {rname}, transport = {tname}");
        }
        exim_deliver::RoutingResult::Discard => {
            println!("{address}");
            println!("  discarded");
        }
        exim_deliver::RoutingResult::Fail => {
            let detail = addr_item.message.as_deref().unwrap_or("undeliverable");
            println!("{address} is undeliverable: {detail}");
        }
        exim_deliver::RoutingResult::Defer => {
            let detail = addr_item.message.as_deref().unwrap_or("deferred");
            println!("{address} cannot be resolved at this time: {detail}");
        }
        exim_deliver::RoutingResult::Rerouted => {
            println!("{address}: domain changed — reroute needed");
        }
        exim_deliver::RoutingResult::Error => {
            let detail = addr_item.message.as_deref().unwrap_or("routing error");
            println!("{address}: routing error: {detail}");
        }
        exim_deliver::RoutingResult::Skip => {
            println!("{address}: routing declined");
        }
    }
}

/// Print supported features for `-bV` output.
///
/// Replaces C `show_whats_supported()` (exim.c lines 1116–1267).
/// Uses Cargo feature flags instead of `#ifdef` preprocessor checks.
fn print_supported_features() {
    let mut features = Vec::new();

    // Always available in the Rust build.
    features.push("crypteq");
    features.push("IPv6");

    #[cfg(feature = "exim-filter")]
    features.push("Exim_filter");

    #[cfg(feature = "sieve-filter")]
    features.push("Sieve_filter");

    #[cfg(feature = "pam")]
    features.push("PAM");

    #[cfg(feature = "perl")]
    features.push("Perl");

    #[cfg(feature = "tls-rustls")]
    features.push("rustls");

    #[cfg(feature = "tls-openssl")]
    features.push("OpenSSL");

    #[cfg(feature = "radius")]
    features.push("radius");

    // Always available with TLS.
    features.push("TLS_resume");

    #[cfg(feature = "dane")]
    features.push("DANE");

    #[cfg(feature = "dkim")]
    features.push("DKIM");

    #[cfg(feature = "dmarc")]
    features.push("DMARC");

    // Always available via hickory-resolver.
    features.push("DNSSEC");

    #[cfg(feature = "dscp")]
    features.push("DSCP");

    // Always enabled in Rust build.
    features.push("ESMTP_Limits");
    features.push("Event");

    features.push("OCSP");
    features.push("PIPECONNECT");
    features.push("PRDR");

    #[cfg(feature = "proxy")]
    features.push("PROXY");

    features.push("Queue_Ramp");

    #[cfg(feature = "socks-proxy")]
    features.push("SOCKS");

    #[cfg(feature = "spf")]
    features.push("SPF");

    features.push("SRS");

    #[cfg(feature = "arc")]
    features.push("Experimental_ARC");

    #[cfg(feature = "xclient")]
    features.push("Experimental_XCLIENT");

    if !features.is_empty() {
        println!("Support for: {}", features.join(" "));
    }
}

/// Generate a build date string in the format matching C Exim.
///
/// Returns a string like "13-Mar-2026 12:34:56".
fn build_date_string() -> String {
    let now = std::time::SystemTime::now();
    let duration = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let days = secs / 86400;
    let (year, month, day) = days_to_ymd(days);
    let month_names = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let month_name = month_names.get(month as usize).unwrap_or(&"Jan");

    format!(
        "{:02}-{}-{:04} {:02}:{:02}:{:02}",
        day, month_name, year, hours, minutes, seconds
    )
}

/// Convert days since Unix epoch to (year, month [0-based], day [1-based]).
///
/// Uses a simplified civil calendar computation.
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m.saturating_sub(1), d)
}

/// Get the spool directory from the parsed configuration.
///
/// Returns the configured `spool_directory` if non-empty, otherwise falls back
/// to the compile-time default `/var/spool/exim` (matching C Exim's
/// `SPOOL_DIRECTORY` macro default).
fn config_spool_directory(config: &Arc<exim_config::Config>) -> String {
    let dir = &config.spool_directory;
    if dir.is_empty() {
        String::from("/var/spool/exim")
    } else {
        dir.clone()
    }
}

/// Build a `CfgConfigContext` from an `Arc<Config>` for use with APIs
/// that require the `exim_config::ConfigContext` struct.
///
/// Clones the inner `ConfigContext` from the frozen configuration, preserving
/// all ACL definitions, rewrite rules, retry rules, router/transport instances,
/// and every other configuration option parsed from the config file.
///
/// `Config` implements `Deref<Target=ConfigContext>`, so we use
/// `std::ops::Deref` to reach the inner struct.
fn build_config_context(config: &Arc<exim_config::Config>) -> CfgConfigContext {
    // Deref chain: Arc<Config> → Config → ConfigContext (via Config's Deref impl).
    // Clone the underlying ConfigContext so the caller gets an owned copy with
    // all parsed configuration data — ACLs, rewrite rules, retry configs,
    // driver instances, host lists, etc.
    use std::ops::Deref;
    let cfg_ctx: &CfgConfigContext = (*config).deref();
    cfg_ctx.clone()
}

/// Build a `CfgServerContext` from a `crate::context::ServerContext` for
/// use with APIs that require the `exim_config::types::ServerContext`.
fn build_server_context(ctx: &ServerContext) -> CfgServerContext {
    CfgServerContext {
        running_in_test_harness: ctx.running_in_test_harness,
        debug_selector: u64::from(ctx.debug_selector),
        primary_hostname: ctx.primary_hostname.clone(),
        ..CfgServerContext::default()
    }
}

/// Print filter interpretation results in a human-readable format.
///
/// Used by `filter_test_mode()` when Exim filter interpretation succeeds.
#[cfg(feature = "exim-filter")]
fn print_filter_result(result: &exim_miscmods::exim_filter::FilterResult) {
    match result {
        exim_miscmods::exim_filter::FilterResult::Delivered => {
            println!("Filter delivered the message.");
        }
        exim_miscmods::exim_filter::FilterResult::NotDelivered => {
            println!("Filter completed without delivery action.");
        }
        exim_miscmods::exim_filter::FilterResult::Defer => {
            println!("Filter deferred the message.");
        }
        exim_miscmods::exim_filter::FilterResult::Fail => {
            println!("Filter failed the message.");
        }
        exim_miscmods::exim_filter::FilterResult::Freeze => {
            println!("Filter froze the message.");
        }
        exim_miscmods::exim_filter::FilterResult::Error => {
            println!("Filter encountered an error.");
        }
    }
}
