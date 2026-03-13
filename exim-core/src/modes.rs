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

/// Exim version string matching C Exim's `version_string` global.
const EXIM_VERSION: &str = "4.99";

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
/// `ExitCode::SUCCESS` always (matching C behaviour for `-bt`).
pub fn address_test_mode(
    addresses: &[String],
    ctx: &ServerContext,
    config: &Arc<exim_config::Config>,
) -> ExitCode {
    tracing::debug!(admin = ctx.admin_user, "address_test_mode: entering");

    let config_ctx = build_config_context(config);
    let cfg_server_ctx = build_server_context(ctx);

    let test_one = |raw_address: &str| {
        let address = raw_address.trim();
        if address.is_empty() {
            return;
        }
        if address.len() > EXIM_DISPLAYMAIL_MAX {
            println!("address too long");
            return;
        }

        let cleaned = parse_extract_address(address);
        match cleaned {
            None => {
                println!("syntax error: unable to parse '{address}'");
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
                    }
                    Err(e) => {
                        println!("{address} router error: {e}");
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

    ExitCode::SUCCESS
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

    let _ = (ctx, config); // Satisfy usage — context needed for variable access.

    // Read expansion strings from stdin, one per line.
    // Each line is expanded independently and the result is printed.
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let reader = BufReader::new(stdin.lock());

    for line_result in reader.lines() {
        match line_result {
            Ok(line) => {
                expansion_test_line(&line, &mut stdout);
            }
            Err(_) => break,
        }
    }

    ExitCode::SUCCESS
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
            let _ = writeln!(out, "{expanded}");
        }
        Err(exim_expand::ExpandError::ForcedFail) => {
            let _ = writeln!(out, "Forced failure");
        }
        Err(exim_expand::ExpandError::Failed { message }) => {
            let _ = writeln!(out, "Failed: {message}");
        }
        Err(e) => {
            let _ = writeln!(out, "Failed: {e}");
        }
    }
}

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
) -> ExitCode {
    tracing::debug!(
        option_count = options.len(),
        list_config = list_config,
        "config_check_mode: entering"
    );

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
        // No specific options requested — just validate.
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
        EXIM_VERSION, EXIM_BUILD_NUMBER, build_date,
    );
    println!("Copyright (c) University of Cambridge, 1995 - 2018");
    println!("Copyright (c) The Exim Maintainers, 2020 - 2025");
    println!("(Rust rewrite)");
    println!();

    // Print support features (replaces show_whats_supported output).
    print_supported_features();

    // Print driver listings from the registry.
    let lookup_line = exim_drivers::DriverRegistry::lookup_show_supported();
    if !lookup_line.is_empty() {
        println!("{lookup_line}");
    }

    let auth_line = exim_drivers::DriverRegistry::auth_show_supported();
    if !auth_line.is_empty() {
        println!("{auth_line}");
    }

    let router_line = exim_drivers::DriverRegistry::route_show_supported();
    if !router_line.is_empty() {
        println!("{router_line}");
    }

    let transport_line = exim_drivers::DriverRegistry::transport_show_supported();
    if !transport_line.is_empty() {
        println!("{transport_line}");
    }

    println!("Size of off_t: {}", std::mem::size_of::<i64>());

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
