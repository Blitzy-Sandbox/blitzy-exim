//! # Exim Main Entry Point
//!
//! This is the main entry point for the `exim` binary, replacing the `main()`
//! function in `src/src/exim.c` (6,274 lines). It initialises the Exim
//! runtime, parses CLI arguments via the [`cli`] module, sets up the four
//! scoped context structs (AAP §0.4.4), and dispatches to the appropriate
//! operational mode.
//!
//! ## Architecture
//!
//! All 714 global variables from the C codebase (`globals.c` / `globals.h`)
//! are replaced by four scoped context structs passed explicitly through call
//! chains:
//!
//! * [`ServerContext`]   — Daemon-lifetime state (sockets, process table, TLS)
//! * [`MessageContext`]  — Per-message state (sender, recipients, headers)
//! * [`DeliveryContext`] — Per-delivery-attempt state (current address, results)
//! * [`ConfigContext`]   — Parsed configuration wrapped in `Arc<Config>`
//!
//! ## Safety
//!
//! This file contains **zero** `unsafe` blocks (per AAP §0.7.2). All C library
//! interactions are confined to the `exim-ffi` crate.

#![forbid(unsafe_code)]
// Justification: exim-core is a binary crate with 7 sibling modules providing
// public APIs consumed across module boundaries (daemon→process, daemon→signal,
// queue_runner→process, modes→context, etc.). Dead-code analysis on `pub` items
// in binary crates produces false positives for items used by sibling modules
// but not directly from main(). This is a well-known Rust limitation for binary
// crates with modular architecture. See rust-lang/rust#46379.
#![allow(dead_code)]

// =============================================================================
// Module Declarations
// =============================================================================

mod cli;
mod context;
mod daemon;
mod modes;
mod process;
mod queue_runner;
mod signal;

// =============================================================================
// Imports — Sibling modules
// =============================================================================

use context::{ConfigContext, ServerContext};

use cli::{DeliveryMode, EximMode, QueueRunConfig};

// =============================================================================
// Imports — Workspace crates
// =============================================================================

use exim_config::Config;
use exim_deliver::DeliveryResult;
use exim_store::MessageArena;

// Force the linker to include driver crate object files so that
// `inventory::submit!` static registrations survive dead-code elimination.
// Without these `extern crate` declarations, Cargo/LLD may strip the driver
// crates entirely because main.rs has no direct symbol references to them,
// resulting in an empty driver registry at runtime (QA Issue 1).
extern crate exim_auths;
extern crate exim_lookups;
extern crate exim_routers;
extern crate exim_transports;

// =============================================================================
// Imports — External crates
// =============================================================================

use nix::unistd::{self, ForkResult};
use regex::Regex;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

// =============================================================================
// Constants
// =============================================================================

/// Default Exim configuration file path (matches C compile-time default).
const CONFIGURE_FILE: &str = "/usr/exim/configure";

/// Default configuration file list searched in order (colon-separated).
const CONFIGURE_FILE_LIST: &str = "/etc/exim/configure:/etc/exim.conf:/usr/exim/configure";

/// Default Exim user name (matches compile-time EXIM_USER).
const EXIM_USERNAME: &str = "exim";

/// Default Exim group name (matches compile-time EXIM_GROUP).
const EXIM_GROUPNAME: &str = "exim";

/// Path to the TRUSTED_CONFIG_LIST file.
///
/// This compile-time constant mirrors the C Exim `TRUSTED_CONFIG_LIST` macro.
/// When set, the file contains a list of configuration file paths (one per
/// line) that are trusted when running as root. The test/runtest harness
/// expects this to be set and checks its output via `-bV`.
///
/// Overridable at runtime via the `EXIM_TRUSTED_CONFIG_LIST` environment
/// variable for build-system flexibility.
const TRUSTED_CONFIG_LIST: &str = "/etc/exim/trusted_configs";

/// Pattern for matching Exim message IDs (both old 16-char and new 23-char).
const EXIM_MESSAGE_ID_REGEX: &str = r"^[0-9A-Za-z]{6}-[0-9A-Za-z]{6,11}-[0-9A-Za-z]{2,4}$";

/// Pattern for detecting SMTP response codes (3-digit prefix).
const SMTP_RESPONSE_CODE_REGEX: &str = r"^[0-9]{3}";

// =============================================================================
// Main Entry Point
// =============================================================================

/// Entry point for the Exim binary.
///
/// Follows the initialisation sequence from `exim.c` `main()` (lines 1823–6274):
///
/// 1. Initialise logging/tracing subsystem
/// 2. Detect symlink-based invocation (`mailq`, `rmail`, etc.)
/// 3. Parse CLI arguments via `clap`-powered parser
/// 4. Set up memory arena (replaces `store_init()`)
/// 5. Resolve Exim UID/GID and check privileges
/// 6. Parse configuration file → `Arc<Config>`
/// 7. Initialise driver registry
/// 8. Dispatch to the determined operational mode
///
/// # Exit Codes
///
/// Exit codes match C Exim exactly (AAP §0.7.1):
/// - `EXIT_SUCCESS` (0) for successful completion
/// - `EXIT_FAILURE` (1) for errors
/// - `2` for specific modes (e.g., delivery with no attempt)
fn main() -> ExitCode {
    // Step 1: Parse command-line arguments FIRST (before tracing init)
    // so we can check whether -d (debug) was specified.  Tracing output
    // must go to stderr and only when -d is active, matching C Exim's
    // behaviour where debug output is written to stderr and regular
    // user-facing output is on stdout (AAP §0.7.1).
    let symlink_name = cli::detect_symlink_invocation();

    let mut cli_args = cli::parse_args();

    // Apply symlink-based overrides early.
    if let Some(ref name) = symlink_name {
        cli_args.called_as = Some(name.clone());
    }

    // Step 2: Initialise tracing subscriber.
    //
    // The tracing subscriber is ALWAYS set to "off".  C Exim's debug
    // output (-d flag) uses direct debug_printf() calls that write to
    // stderr in a specific format expected by the test harness.  The
    // Rust port replicates that behaviour via explicit eprint!()/
    // eprintln!() calls in the expansion engine, ACL evaluator, etc.
    //
    // The tracing framework's structured output (timestamps, level
    // labels, spans) is NOT compatible with the expected debug format
    // and would cause test harness comparison failures.  We install a
    // no-op subscriber to satisfy any tracing::debug!() etc. calls
    // elsewhere in the codebase without producing output.
    {
        use tracing_subscriber::fmt;
        use tracing_subscriber::EnvFilter;
        let filter = EnvFilter::new("off");
        fmt::fmt()
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .with_env_filter(filter)
            .init();
    }

    // Set umask to zero so that files Exim creates via open() have
    // exactly the permissions specified in the mode parameter.
    // C Exim does this at exim.c line 2096; without it, the process
    // umask (typically 022) would strip group/other write bits from
    // log files, preventing the setuid exim binary from appending to
    // mainlog files originally created by the root process.
    #[cfg(unix)]
    {
        nix::sys::stat::umask(nix::sys::stat::Mode::empty());
    }

    // Step 3 (moved up): symlink invocation already detected above.
    if let Some(ref name) = symlink_name {
        debug!(invoked_as = %name, "symlink invocation detected");
    }

    // CLI args already parsed above (step 1).
    // (Do NOT re-parse — just continue with cli_args.)

    // Step 4: Determine the operational mode from parsed arguments.
    let mode = cli::determine_mode(&cli_args);
    debug!(mode = ?mode, "operational mode determined");

    // Step 5: Initialise the per-message memory arena.
    // Replaces store_init() at exim.c line 1913.
    let _arena = MessageArena::new();

    // Step 6: Create server context with daemon-lifetime state.
    let mut server_ctx = ServerContext::new();

    // Step 7: Resolve Exim UID/GID and populate server context.
    resolve_exim_user(&mut server_ctx);

    // Step 8: Compile core regular expressions.
    let _regex_msgid = init_regex_msgid();
    let _regex_smtp = init_regex_smtp_code();

    // Step 9: Initialise the driver registry.
    // Collects all auth/router/transport/lookup driver implementations
    // registered via inventory::submit!.
    exim_drivers::DriverRegistry::init();

    // Step 10: Handle early-exit modes that don't need configuration.
    // NOTE: EximMode::Version is NOT handled here — in C Exim, `-bV` parses
    // the configuration first (and can fail with a config error), then prints
    // the version info.  We replicate that by letting Version fall through to
    // config parsing below.
    if let EximMode::Info { info_type } = &mode {
        return modes::info_mode(*info_type);
    }

    // Step 11: Determine the configuration file path.
    let config_file_path = cli_args
        .config_file
        .as_ref()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| CONFIGURE_FILE_LIST.to_string());

    debug!(config_path = %config_file_path, "loading configuration");

    // Step 12: Parse the configuration file.
    // Two-phase process:
    //   a) parse_main_config() → (exim_config::ConfigContext, ParserState)
    //   b) parse_rest() → Arc<Config> for ACLs, drivers, etc.
    let macro_defs: &[(String, String)] = &cli_args.macro_defs;

    // C Exim readconf.c:984 — when both debug mode (D_any) and expansion
    // test mode (-be) are active, macro expansions print
    // `macro 'NAME' -> 'VALUE'` to stdout during config parsing.
    let expansion_test_debug =
        matches!(mode, EximMode::ExpansionTest { .. }) && cli_args.debug_selector.is_some();

    let (mut parsed_config, mut parser_state) = match exim_config::parse_main_config_with_debug(
        &config_file_path,
        None,
        macro_defs,
        expansion_test_debug,
    ) {
        Ok(result) => result,
        Err(e) => {
            error!(error = %e, "failed to parse main configuration");
            print_config_error(&e);
            return ExitCode::FAILURE;
        }
    };

    // Populate exim_uid / exim_gid from the resolved server context so that
    // `-bP exim_user` / `-bP exim_group` print the correct values (C parity).
    parsed_config.exim_uid = server_ctx.exim_uid;
    parsed_config.exim_gid = server_ctx.exim_gid;

    // Populate the version string from the patchable binary marker so
    // that `patchexim` can replace "4.99" with "x.yz" for test output
    // stability. If config hasn't overridden it, use the patched version.
    if parsed_config.exim_version == Some("4.99".to_string()) {
        parsed_config.exim_version = Some(exim_ffi::get_patched_version().to_string());
    }

    // parse_rest() handles driver initialisation (auths, routers, transports)
    // internally — no separate init_drivers() call needed.
    let frozen_config = match exim_config::parse_rest(&mut parsed_config, &mut parser_state) {
        Ok(config) => config,
        Err(e) => {
            error!(error = %e, "failed to parse configuration sections");
            print_config_error(&e);
            return ExitCode::FAILURE;
        }
    };

    // Build the config filename as a PathBuf for the core ConfigContext.
    let config_filename_pathbuf = cli_args
        .config_file
        .clone()
        .unwrap_or_else(|| PathBuf::from(CONFIGURE_FILE));

    // Step 13: Create the core ConfigContext wrapping Arc<Config>.
    // Per AAP §0.4.3: config is frozen after parse via Arc<Config>.
    let config_ctx = ConfigContext::new(frozen_config.clone(), config_filename_pathbuf);

    // Step 14: Clean TLS environment variables.
    let spool_dir = &config_ctx.get_config().spool_directory;
    exim_tls::tls_clean_env(spool_dir);

    // Step 15: Check admin user status.
    check_admin_user(&mut server_ctx);

    // Step 16: Apply configuration values to the server context.
    apply_config_to_server_ctx(&mut server_ctx, &config_ctx);

    // Step 17: Clear signal handlers inherited from the parent process.
    signal::clear_all_signals();

    // Step 18: Configure logging based on parsed CLI arguments.
    configure_debug_logging(&cli_args, &mut server_ctx);

    // Step 19: Set process info for ps display.
    process::set_process_info("initialising");

    // Step 20: Dispatch to the determined operational mode.
    dispatch_mode(
        mode,
        &cli_args,
        &mut server_ctx,
        &config_ctx,
        &frozen_config,
    )
}

// =============================================================================
// Mode Dispatch
// =============================================================================

/// Dispatch to the appropriate operational mode based on the resolved
/// [`EximMode`].
///
/// This function implements the mode switch from exim.c lines 5034–5500.
/// Each arm corresponds to a specific `-b*`, `-M*`, or `-q*` flag family.
fn dispatch_mode(
    mode: EximMode,
    cli_args: &cli::EximCli,
    server_ctx: &mut ServerContext,
    config_ctx: &ConfigContext,
    frozen_config: &Arc<Config>,
) -> ExitCode {
    match mode {
        // ── Daemon Mode ─────────────────────────────────────────────────
        EximMode::Daemon { foreground } => {
            info!(foreground, "entering daemon mode");
            server_ctx.background_daemon = !foreground;
            server_ctx.daemon_listen = true;
            // Pass -oX override to daemon context so that
            // bind_listening_sockets() can use it instead of config values.
            server_ctx.override_local_interfaces = cli_args.override_local_interfaces.clone();
            signal::install_daemon_signals();
            // daemon_go() is a diverging function (-> !)
            daemon::daemon_go(server_ctx, frozen_config);
        }

        // ── One-Time Queue Run ──────────────────────────────────────────
        EximMode::QueueRun { runners } => {
            info!(runner_count = runners.len(), "one-time queue run");
            let queue_runners: Vec<queue_runner::QueueRunner> =
                runners.iter().map(cli_queue_config_to_runner).collect();
            let start_id = runners.first().and_then(|r| r.start_id.as_deref());
            let stop_id = runners.first().and_then(|r| r.stop_id.as_deref());

            match queue_runner::single_queue_run(
                &queue_runners,
                start_id,
                stop_id,
                server_ctx,
                config_ctx,
            ) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    error!(error = %e, "queue run failed");
                    ExitCode::FAILURE
                }
            }
        }

        // ── Queue Listing ───────────────────────────────────────────────
        EximMode::ListQueue { option } => {
            let qr_option = convert_queue_list_option(option);
            match queue_runner::list_queue(qr_option, config_ctx) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    error!(error = %e, "queue listing failed");
                    ExitCode::FAILURE
                }
            }
        }

        // ── Queue Count ─────────────────────────────────────────────────
        EximMode::CountQueue => {
            let count = queue_runner::count_queue(config_ctx);
            println!("{count}");
            ExitCode::SUCCESS
        }

        // ── Message Action ──────────────────────────────────────────────
        EximMode::MessageAction {
            action,
            message_ids,
        } => dispatch_message_action(
            &action,
            &message_ids,
            cli_args,
            server_ctx,
            config_ctx,
            frozen_config,
        ),

        // ── Address Verification ────────────────────────────────────────
        EximMode::AddressVerify { as_sender } => modes::address_verify_mode(
            &cli_args.recipients,
            as_sender,
            false,
            server_ctx,
            frozen_config,
        ),

        // ── Address Testing ─────────────────────────────────────────────
        EximMode::AddressTest => {
            modes::address_test_mode(&cli_args.recipients, server_ctx, frozen_config)
        }

        // ── Expansion Testing ───────────────────────────────────────────
        EximMode::ExpansionTest {
            message_file,
            message_load,
        } => modes::expansion_test_mode(
            message_load.as_deref(),
            message_file.as_deref(),
            server_ctx,
            frozen_config,
            &config_ctx.config_filename.to_string_lossy(),
            cli_args,
        ),

        // ── Filter Testing ──────────────────────────────────────────────
        EximMode::FilterTest { filter_type, file } => {
            modes::filter_test_mode(filter_type, &file, server_ctx, frozen_config)
        }

        // ── Configuration Check ─────────────────────────────────────────
        EximMode::ConfigCheck {
            options,
            show_config,
        } => modes::config_check_mode(&options, show_config, frozen_config, server_ctx),

        // ── Version Display ─────────────────────────────────────────────
        // (Also handled as early exit, included for completeness.)
        EximMode::Version => modes::version_mode(),

        // ── Info Mode ───────────────────────────────────────────────────
        // (Also handled as early exit, included for completeness.)
        EximMode::Info { info_type } => modes::info_mode(info_type),

        // ── Retry Test ──────────────────────────────────────────────────
        EximMode::RetryTest { args } => modes::test_retry_mode(&args, frozen_config),

        // ── Rewrite Test ────────────────────────────────────────────────
        EximMode::RewriteTest { args } => modes::test_rewrite_mode(&args, frozen_config),

        // ── SMTP Input ──────────────────────────────────────────────────
        EximMode::SmtpInput { batched } => {
            handle_smtp_input(batched, server_ctx, config_ctx, cli_args)
        }

        // ── Host Check ──────────────────────────────────────────────────
        EximMode::HostCheck { host } => handle_host_check(&host, server_ctx, config_ctx),

        // ── Default: Receive Message ────────────────────────────────────
        EximMode::ReceiveMessage => {
            receive_message(cli_args, server_ctx, config_ctx, frozen_config)
        }

        // ── Malware Test ────────────────────────────────────────────────
        // C Exim's `-bmalware <file>` mode scans a file using the configured
        // malware scanner (av_scanner option).  The scan delegates to the
        // content scanning subsystem in miscmods/malware.c which supports
        // ClamAV, cmdline, sophie, AVES, and other engines.
        //
        // The Rust malware scanner module (exim-miscmods/src/malware.rs) is
        // not yet implemented — it will be added when the content scanning
        // subsystem is ported from C.  Until then, we validate the file
        // exists and report that the scanner is not configured.
        EximMode::MalwareTest { file } => {
            info!(file = %file, "malware test mode");

            // Verify the target file exists and is readable.
            let path = std::path::Path::new(&file);
            if !path.exists() {
                eprintln!("exim: malware test: file not found: {file}");
                return ExitCode::FAILURE;
            }
            if !path.is_file() {
                eprintln!("exim: malware test: not a regular file: {file}");
                return ExitCode::FAILURE;
            }

            // Check whether the configuration specifies a malware scanner.
            let av_scanner = &config_ctx.get_config().av_scanner;
            if av_scanner.is_none() || av_scanner.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                eprintln!("exim: malware test: no av_scanner configured");
                return ExitCode::FAILURE;
            }

            // Read file size for diagnostic output (matching C Exim format).
            let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            info!(
                file = %file,
                size = file_size,
                scanner = av_scanner.as_deref().unwrap_or(""),
                "malware test: scanning file"
            );

            // Invoke the malware scanner via the content scanning subsystem.
            // When exim-miscmods provides the malware scanning module, this
            // will call malware_scan() with the file path and av_scanner
            // configuration.  For now, report that the scanner subsystem
            // is not yet available in the Rust build.
            eprintln!(
                "exim: malware test: content scanning subsystem not yet \
                 available in Rust build — file: {file} ({file_size} bytes)"
            );
            ExitCode::FAILURE
        }

        // ── NewAliases ──────────────────────────────────────────────────
        // Sendmail compatibility no-op.
        EximMode::NewAliases => ExitCode::SUCCESS,

        // ── Inetd Wait Mode ────────────────────────────────────────────
        EximMode::InetdWait => {
            info!("inetd wait mode");
            server_ctx.inetd_wait_mode = true;
            server_ctx.daemon_listen = true;
            process::exim_nullstd();
            signal::install_daemon_signals();
            daemon::daemon_go(server_ctx, frozen_config);
        }
    }
}

// =============================================================================
// Message Action Dispatch
// =============================================================================

/// Dispatch message actions from the `-M*` CLI flag family.
///
/// Converts `cli::MessageAction` to `queue_runner::MessageAction` and
/// invokes the appropriate function for each message ID.
fn dispatch_message_action(
    action: &cli::MessageAction,
    message_ids: &[String],
    cli_args: &cli::EximCli,
    server_ctx: &mut ServerContext,
    config_ctx: &ConfigContext,
    frozen_config: &Arc<Config>,
) -> ExitCode {
    if message_ids.is_empty() {
        error!("no message IDs specified for -M action");
        return ExitCode::FAILURE;
    }

    match action {
        // -M: Force delivery of messages (fork per message).
        cli::MessageAction::Deliver => {
            deliver_messages(message_ids, true, false, server_ctx, config_ctx)
        }

        // -Mc: Deliver cutthrough (respecting retry times).
        cli::MessageAction::DeliverCutthrough => {
            deliver_messages(message_ids, false, false, server_ctx, config_ctx)
        }

        // -Mg: Give up on messages (generate bounce).
        cli::MessageAction::GiveUp => {
            deliver_messages(message_ids, false, true, server_ctx, config_ctx)
        }

        // -Mset: Load message for expansion test.
        cli::MessageAction::LoadForExpansion => {
            if let Some(msg_id) = message_ids.first() {
                info!(message_id = %msg_id, "loading message for expansion test");
                modes::expansion_test_mode(
                    Some(msg_id.as_str()),
                    None,
                    server_ctx,
                    frozen_config,
                    &config_ctx.config_filename.to_string_lossy(),
                    cli_args,
                )
            } else {
                ExitCode::FAILURE
            }
        }

        // -Mvc: Show a copy of the whole message (header + body).
        cli::MessageAction::ShowCopy => {
            let mut exit = ExitCode::SUCCESS;
            for msg_id in message_ids {
                let qr_hdr = queue_runner::MessageAction::ShowHeader;
                match queue_runner::queue_action(msg_id, qr_hdr, config_ctx, server_ctx) {
                    Ok(true) => {}
                    _ => {
                        exit = ExitCode::FAILURE;
                    }
                }
                let qr_body = queue_runner::MessageAction::ShowBody;
                if queue_runner::queue_action(msg_id, qr_body, config_ctx, server_ctx).is_err() {
                    exit = ExitCode::FAILURE;
                }
            }
            exit
        }

        // All other -M* actions: convert to queue_runner::MessageAction.
        other => {
            let qr_action = convert_message_action(other, cli_args);
            let mut exit = ExitCode::SUCCESS;
            for msg_id in message_ids {
                match queue_runner::queue_action(msg_id, qr_action.clone(), config_ctx, server_ctx)
                {
                    Ok(true) => {
                        info!(message_id = %msg_id, "action completed");
                    }
                    Ok(false) => {
                        warn!(message_id = %msg_id, "message not found or action failed");
                        exit = ExitCode::FAILURE;
                    }
                    Err(e) => {
                        error!(message_id = %msg_id, error = %e, "message action failed");
                        exit = ExitCode::FAILURE;
                    }
                }
            }
            exit
        }
    }
}

/// Convert a `cli::MessageAction` to a `queue_runner::MessageAction`.
///
/// The `cli` enum uses unit variants for actions that take an extra argument
/// (MarkDelivered, EditSender, AddRecipient); the extra argument is in
/// `cli_args.msg_action_arg`. The `queue_runner` enum stores the argument
/// inline.
fn convert_message_action(
    action: &cli::MessageAction,
    cli_args: &cli::EximCli,
) -> queue_runner::MessageAction {
    let extra_arg = cli_args.msg_action_arg.clone().unwrap_or_default();

    match action {
        cli::MessageAction::Deliver | cli::MessageAction::DeliverCutthrough => {
            queue_runner::MessageAction::Deliver
        }
        cli::MessageAction::Freeze => queue_runner::MessageAction::Freeze,
        cli::MessageAction::Thaw => queue_runner::MessageAction::Thaw,
        cli::MessageAction::Remove => queue_runner::MessageAction::Remove,
        cli::MessageAction::GiveUp => queue_runner::MessageAction::GiveUp,
        cli::MessageAction::MarkDelivered => queue_runner::MessageAction::MarkDelivered(extra_arg),
        cli::MessageAction::MarkAllDelivered => queue_runner::MessageAction::MarkAllDelivered,
        cli::MessageAction::EditSender => queue_runner::MessageAction::EditSender(extra_arg),
        cli::MessageAction::AddRecipient => queue_runner::MessageAction::AddRecipient(extra_arg),
        cli::MessageAction::SetQueue => queue_runner::MessageAction::SetQueue(extra_arg),
        cli::MessageAction::ShowBody => queue_runner::MessageAction::ShowBody,
        cli::MessageAction::ShowHeader | cli::MessageAction::ShowCopy => {
            queue_runner::MessageAction::ShowHeader
        }
        cli::MessageAction::ShowLog => queue_runner::MessageAction::ShowLog,
        // LoadForExpansion is handled separately before this function.
        cli::MessageAction::LoadForExpansion => queue_runner::MessageAction::Deliver,
    }
}

/// Convert `cli::QueueListOption` to `queue_runner::QueueListOption`.
///
/// Both enums have the same variant names but are distinct types defined
/// in different modules.
fn convert_queue_list_option(opt: cli::QueueListOption) -> queue_runner::QueueListOption {
    match opt {
        cli::QueueListOption::Basic => queue_runner::QueueListOption::Basic,
        cli::QueueListOption::Unsorted => queue_runner::QueueListOption::Unsorted,
        cli::QueueListOption::UndeliveredOnly => queue_runner::QueueListOption::UndeliveredOnly,
        cli::QueueListOption::PlusGenerated => queue_runner::QueueListOption::PlusGenerated,
        cli::QueueListOption::MsgidOnly => queue_runner::QueueListOption::MsgidOnly,
    }
}

// =============================================================================
// Message Delivery Helper
// =============================================================================

/// Deliver one or more messages by ID, forking a child process per message.
///
/// Replaces the message delivery loop from exim.c lines 5062–5074.
/// For each message ID:
///   1. Fork a child process via `process::exim_fork()`
///   2. Child creates `exim_config::types` context objects for `deliver_message()`
///   3. Parent waits for child via `process::child_close()`
///   4. Exit code based on `DeliveryResult`
fn deliver_messages(
    message_ids: &[String],
    forced: bool,
    give_up: bool,
    server_ctx: &mut ServerContext,
    config_ctx: &ConfigContext,
) -> ExitCode {
    let mut overall_exit = ExitCode::SUCCESS;

    for msg_id in message_ids {
        info!(message_id = %msg_id, forced, give_up, "attempting message delivery");
        process::set_process_info(&format!("delivering {msg_id}"));

        match process::exim_fork("delivery") {
            Ok(ForkResult::Child) => {
                // Child process: create exim_config::types context objects.
                // exim_deliver::deliver_message() expects exim_config types,
                // not exim_core::context types. Follow the same pattern used
                // by queue_runner.rs (lines 1191–1210).
                let mut cfg_msg_ctx = exim_config::types::MessageContext::default();
                let mut cfg_delivery_ctx = exim_config::types::DeliveryContext::default();
                let cfg_server_ctx = exim_config::types::ServerContext {
                    running_in_test_harness: server_ctx.running_in_test_harness,
                    ..Default::default()
                };
                // Build ConfigContext from the actual parsed configuration,
                // preserving all ACLs, rewrite rules, retry configs, and
                // driver definitions.  Previously used ConfigContext::default()
                // which lost all configuration data in delivery children.
                let cfg_config_ctx = config_ctx.get_config().clone();

                let result = exim_deliver::deliver_message(
                    msg_id,
                    forced,
                    give_up,
                    &cfg_server_ctx,
                    &mut cfg_msg_ctx,
                    &mut cfg_delivery_ctx,
                    &cfg_config_ctx,
                );

                let exit_code: i32 = match result {
                    Ok(DeliveryResult::NotAttempted) => libc::EXIT_FAILURE,
                    Ok(_) => libc::EXIT_SUCCESS,
                    Err(e) => {
                        error!(message_id = %msg_id, error = %e, "delivery failed");
                        libc::EXIT_FAILURE
                    }
                };

                // Child exits directly — never falls through.
                std::process::exit(exit_code);
            }
            Ok(ForkResult::Parent { child }) => {
                match process::child_close(child, Duration::from_secs(300)) {
                    Ok(0) => {
                        info!(message_id = %msg_id, "delivery child succeeded");
                    }
                    Ok(code) => {
                        warn!(
                            message_id = %msg_id,
                            exit_code = code,
                            "delivery child exited with non-zero status"
                        );
                        overall_exit = ExitCode::FAILURE;
                    }
                    Err(e) => {
                        error!(
                            message_id = %msg_id,
                            error = %e,
                            "failed to wait for delivery child"
                        );
                        overall_exit = ExitCode::FAILURE;
                    }
                }
            }
            Err(e) => {
                error!(message_id = %msg_id, error = %e, "failed to fork delivery process");
                overall_exit = ExitCode::FAILURE;
            }
        }
    }

    overall_exit
}

// =============================================================================
// Verify Recipient Callback Factory
// =============================================================================

/// Create a `verify = recipient` callback that runs the router chain to
/// determine if a recipient address is routable.  This callback is injected
/// into the SMTP session's `MessageContext` so the ACL engine can call it
/// without `exim-smtp` depending on `exim-deliver`.
///
/// The callback captures router instances (initialised from config) and
/// the config context.  When invoked with `(recipient, sender)`, it:
/// 1. Parses recipient into local_part@domain
/// 2. Creates an `AddressItem`
/// 3. Runs `route_address()` with `VerifyMode::Recipient`
/// 4. Returns `Ok(VerifyRecipientResult)` with address_data on success
/// 5. Returns `Err(message)` on routing failure
#[allow(clippy::type_complexity)] // Callback type mirrors C Exim's function pointer pattern
fn make_verify_recipient_callback(
    config: &Arc<Config>,
) -> Option<
    std::sync::Arc<dyn Fn(&str, &str) -> exim_acl::engine::VerifyRecipientResult + Send + Sync>,
> {
    use exim_acl::engine::VerifyRecipientResult;
    use exim_deliver::orchestrator::AddressItem;
    use exim_deliver::routing::{route_address, route_init, RoutingResult, VerifyMode};

    // Dereference Arc<Config> → &ConfigContext for route_init.
    let cfg: &exim_config::types::ConfigContext = config;

    // Initialise the router chain from config.  If this fails (e.g. unknown
    // driver), return None — verify=recipient will be a no-op and the ACL
    // will treat it as a soft failure.
    let routers = match route_init(cfg) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "failed to initialise routers for verify=recipient");
            return None;
        }
    };

    // Wrap in Arc so they can be cheaply cloned into the closure.
    let routers = std::sync::Arc::new(routers);
    let shared_cfg = Arc::clone(config);

    Some(std::sync::Arc::new(move |recipient: &str, sender: &str| {
        let mut addr = AddressItem::new_from_string(recipient);

        let mut addr_local = Vec::new();
        let mut addr_remote = Vec::new();
        let mut addr_new = Vec::new();
        let mut addr_succeed = Vec::new();

        // Build minimal contexts for routing.  Verification mode avoids
        // side-effects like delivery and skips transport checks.
        let server_ctx = exim_config::types::ServerContext::default();
        let msg_ctx = exim_config::types::MessageContext::default();
        let mut delivery_ctx = exim_config::types::DeliveryContext::default();

        // Dereference the Arc<Config> → &ConfigContext for route_address.
        let cfg_ref: &exim_config::types::ConfigContext = &shared_cfg;

        let result = route_address(
            &mut addr,
            &mut addr_local,
            &mut addr_remote,
            &mut addr_new,
            &mut addr_succeed,
            &routers,
            VerifyMode::Recipient,
            false,
            Some(sender),
            &server_ctx,
            &msg_ctx,
            &mut delivery_ctx,
            cfg_ref,
        );

        // ALWAYS extract address_data regardless of routing outcome.
        // C Exim's copy_error() in verify.c unconditionally propagates
        // addr->prop.address_data, so $address_data is available even
        // when the routing failed (e.g. redirect with empty data).
        let address_data = addr.prop.address_data.clone();

        match result {
            Ok(RoutingResult::Ok) => VerifyRecipientResult {
                address_data,
                sender_address_data: None,
                is_local: !addr_local.is_empty() || addr.transport.is_some(),
                routed: true,
                fail_message: None,
            },
            Ok(RoutingResult::Fail) | Ok(RoutingResult::Error) => {
                let msg = addr
                    .message
                    .unwrap_or_else(|| "Unrouteable address".to_string());
                VerifyRecipientResult {
                    address_data,
                    sender_address_data: None,
                    is_local: false,
                    routed: false,
                    fail_message: Some(msg),
                }
            }
            Ok(RoutingResult::Defer) => VerifyRecipientResult {
                address_data,
                sender_address_data: None,
                is_local: false,
                routed: false,
                fail_message: Some("Address lookup deferred".to_string()),
            },
            Ok(RoutingResult::Discard) => {
                // Discarded addresses are treated as routable for
                // verify=recipient purposes.
                VerifyRecipientResult {
                    address_data,
                    sender_address_data: None,
                    is_local: true,
                    routed: true,
                    fail_message: None,
                }
            }
            Ok(RoutingResult::Rerouted) | Ok(RoutingResult::Skip) => {
                let msg = addr
                    .message
                    .unwrap_or_else(|| "Unrouteable address".to_string());
                VerifyRecipientResult {
                    address_data,
                    sender_address_data: None,
                    is_local: false,
                    routed: false,
                    fail_message: Some(msg),
                }
            }
            Err(e) => VerifyRecipientResult {
                address_data,
                sender_address_data: None,
                is_local: false,
                routed: false,
                fail_message: Some(format!("Routing error: {}", e)),
            },
        }
    }))
}

// =============================================================================
// SMTP Input Handling
// =============================================================================

/// Handle `-bs` (interactive SMTP) and `-bS` (batched SMTP) modes.
///
/// Sets up an SMTP session on stdin/stdout and delegates to the inbound
/// SMTP command loop.
fn handle_smtp_input(
    batched: bool,
    server_ctx: &mut ServerContext,
    config_ctx: &ConfigContext,
    cli_args: &cli::EximCli,
) -> ExitCode {
    info!(batched, "SMTP input mode");

    // Ensure stdin/stdout/stderr are valid file descriptors (for inetd).
    process::exim_nullstd();

    // Create the SMTP-specific context types (from command_loop module).
    // These types are different from exim_core::context types and
    // exim_config::types — they are SMTP-session-specific.
    let mut smtp_server_ctx = build_smtp_server_context(server_ctx, false);
    // -bs/-bS mode: local submission, not a network connection
    smtp_server_ctx.is_local_session = true;
    smtp_server_ctx.smtp_batched_input = batched;

    let mut smtp_msg_ctx = exim_smtp::inbound::command_loop::MessageContext::default();

    // In -bs mode, set sender_ident to the calling user's login name.
    // This matches C Exim (exim.c:5246): "if (!sender_ident) sender_ident = originator_login;"
    // The HELO greeting uses this: "250 host Hello CALLER at helo_name"
    if let Some(login) = exim_ffi::get_login_name() {
        smtp_msg_ctx.sender_ident = Some(login.clone());
    }

    let mut smtp_config_ctx = build_smtp_config_context(&config_ctx.config);

    // spool_directory is propagated from frozen_config into smtp_config_ctx
    // by build_smtp_config_context() — no debug trace needed in production.

    // In -bs/-bS mode (stdin/stdout SMTP), disable pipelining sync
    // checking because all input data is buffered immediately in a pipe,
    // causing false positive sync violations. C Exim disables sync
    // checking for non-network connections (smtp_in.c ~line 1300).
    smtp_config_ctx.smtp_enforce_sync = false;

    // Set originator login and credentials for log entries (U= field) and
    // spool file originator metadata.
    if let Some(login) = exim_ffi::get_login_name() {
        smtp_config_ctx.originator_login = login;
    }
    smtp_config_ctx.originator_uid = unistd::getuid().as_raw();
    smtp_config_ctx.originator_gid = unistd::getgid().as_raw();

    let mut session_state = exim_smtp::inbound::SessionState::default();

    if batched {
        debug!("batched SMTP mode (-bS)");
        session_state.smtp_batched_input = true;
    }

    match exim_smtp::inbound::smtp_start_session(
        &smtp_server_ctx,
        &mut smtp_msg_ctx,
        &smtp_config_ctx,
        &mut session_state,
    ) {
        Ok(true) => {
            // Session initialization succeeded — now enter the SMTP command
            // loop on stdin/stdout.  In -bs mode, stdin (fd 0) is the inbound
            // SMTP stream and stdout (fd 1) is the outbound response stream.
            //
            // This fixes QA Issue 6: "-bs mode produces no SMTP output".
            // Previously, smtp_start_session() returned without entering
            // the command loop, so no SMTP commands were processed.
            use std::os::unix::io::AsRawFd;
            let in_fd = std::io::stdin().as_raw_fd();
            let out_fd = std::io::stdout().as_raw_fd();

            // Determine whether delivery should happen inline (after each
            // DATA command) or be deferred until the session ends.  In
            // C Exim, `-bs` / `-bS` mode delivers each message immediately
            // after the 250 OK response, so mainlog entries for each message
            // appear in receive-then-deliver order, not all-receives first.
            let should_deliver = match cli_args.delivery_mode {
                Some(cli::DeliveryMode::QueueOnly) | Some(cli::DeliveryMode::QueueSmtp) => false,
                _ if cli_args.queue_only => false,
                _ if cli_args.dont_deliver => false,
                _ => true,
            };

            // Install a per-message delivery callback so that the SMTP
            // session code can trigger delivery inline after each DATA.
            // We capture cheap owned/cloned data to avoid lifetime issues.
            if should_deliver {
                let test_harness = server_ctx.running_in_test_harness;
                let shared_cfg = config_ctx.shared_config();
                smtp_msg_ctx.post_message_callback = Some(Box::new(move |msg_id: &str| {
                    deliver_smtp_message_inline(msg_id, test_harness, &shared_cfg);
                }));
            }

            // Install verify=recipient callback so the ACL engine can route
            // recipient addresses through the router chain during RCPT TO
            // ACL evaluation. This bridges exim-smtp → exim-deliver without
            // a direct dependency.
            smtp_msg_ctx.verify_recipient_cb = make_verify_recipient_callback(&config_ctx.config);

            let result = exim_smtp::inbound::command_loop::smtp_setup_msg(
                &smtp_server_ctx,
                &mut smtp_msg_ctx,
                &smtp_config_ctx,
                in_fd,
                out_fd,
            );

            match result {
                exim_smtp::inbound::command_loop::SmtpSetupResult::Done => {
                    info!("SMTP session completed successfully");
                    ExitCode::SUCCESS
                }
                exim_smtp::inbound::command_loop::SmtpSetupResult::Yield => {
                    info!("SMTP session yielded for message body");
                    ExitCode::SUCCESS
                }
                exim_smtp::inbound::command_loop::SmtpSetupResult::Error => {
                    error!("SMTP session ended with error");
                    ExitCode::FAILURE
                }
            }
        }
        Ok(false) => {
            info!("SMTP session ended without completing");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!(error = %e, "SMTP session error");
            ExitCode::FAILURE
        }
    }
}

/// Handle `-bh <host>` host checking / SMTP simulation mode.
///
/// In C Exim, `-bh <host>` creates a fake inbound SMTP session pretending
/// the connection comes from `<host>`.  SMTP commands are read from stdin
/// and responses are written to stdout, exactly like `-bs` mode, but with
/// `host_checking = true` which activates host-sensitive ACL conditions
/// (sender_host_address, etc.) and disables actual delivery.
///
/// Previously this function only called `smtp_start_session()` without
/// entering the command loop, producing no SMTP output.  The fix mirrors
/// the `-bs` handler by calling `smtp_setup_msg()` after session init.
fn handle_host_check(
    host: &str,
    server_ctx: &mut ServerContext,
    config_ctx: &ConfigContext,
) -> ExitCode {
    info!(host = %host, "host check / SMTP simulation mode");

    // C Exim prints these informational lines to stdout at the start of
    // -bh mode so the operator knows this is a simulated session.
    // The test harness expects them in the stdout comparison.
    println!();
    println!("**** SMTP testing session as if from host {}", host);
    println!("**** but without any ident (RFC 1413) callback.");
    println!("**** This is not for real!");
    println!();

    let smtp_server_ctx = build_smtp_server_context(server_ctx, true);

    // Set the sender host address from the -bh argument so ACL conditions
    // like `hosts`, `sender_host_address`, etc. work correctly.
    let mut smtp_msg_ctx = exim_smtp::inbound::command_loop::MessageContext {
        sender_host_address: Some(host.to_string()),
        ..Default::default()
    };

    // Wire the verify=recipient routing callback so ACL conditions like
    // `verify = recipient` can actually route addresses during -bh mode.
    smtp_msg_ctx.verify_recipient_cb = make_verify_recipient_callback(&config_ctx.config);

    let mut smtp_config_ctx = build_smtp_config_context(&config_ctx.config);

    // Disable sync checking for -bh mode just like -bs — stdin is a pipe,
    // not a real network socket, so has_pending_input() is unreliable.
    smtp_config_ctx.smtp_enforce_sync = false;

    let mut session_state = exim_smtp::inbound::SessionState::default();

    match exim_smtp::inbound::smtp_start_session(
        &smtp_server_ctx,
        &mut smtp_msg_ctx,
        &smtp_config_ctx,
        &mut session_state,
    ) {
        Ok(true) => {
            // Enter the SMTP command loop on stdin/stdout, matching -bs mode.
            use std::os::unix::io::AsRawFd;
            let in_fd = std::io::stdin().as_raw_fd();
            let out_fd = std::io::stdout().as_raw_fd();

            // Enter the SMTP command loop.  When the session reaches the
            // DATA command, smtp_setup_msg returns Yield so the caller can
            // read the message body, run the DATA ACL, and send the final
            // response.  We then loop back to smtp_setup_msg for the next
            // transaction (RSET, MAIL FROM, QUIT).
            loop {
                let result = exim_smtp::inbound::command_loop::smtp_setup_msg(
                    &smtp_server_ctx,
                    &mut smtp_msg_ctx,
                    &smtp_config_ctx,
                    in_fd,
                    out_fd,
                );

                match result {
                    exim_smtp::inbound::command_loop::SmtpSetupResult::Done => {
                        break ExitCode::SUCCESS;
                    }
                    exim_smtp::inbound::command_loop::SmtpSetupResult::Error => {
                        error!("SMTP host check session ended with error");
                        break ExitCode::FAILURE;
                    }
                    exim_smtp::inbound::command_loop::SmtpSetupResult::Yield => {
                        // DATA is now handled inline by the command loop
                        // (read_message_body + DATA ACL + response).
                        // Yield should not normally be reached, but if it
                        // is, continue the loop so smtp_setup_msg handles
                        // the next command.
                    }
                }
            }
        }
        Ok(false) => ExitCode::SUCCESS,
        Err(e) => {
            error!(error = %e, "host check failed");
            ExitCode::FAILURE
        }
    }
}

// =============================================================================
// SMTP Context Builders
// =============================================================================

/// Build a `command_loop::ServerContext` from the core `ServerContext`.
///
/// The SMTP command loop uses its own `ServerContext` type with fields
/// tailored to session-level SMTP handling.
fn build_smtp_server_context(
    server_ctx: &ServerContext,
    host_checking: bool,
) -> exim_smtp::inbound::command_loop::ServerContext {
    exim_smtp::inbound::command_loop::ServerContext {
        primary_hostname: server_ctx.primary_hostname.clone(),
        smtp_active_hostname: server_ctx.primary_hostname.clone(),
        tls_server_credentials: None,
        host_checking,
        sender_host_notsocket: host_checking,
        is_inetd: false,
        atrn_mode: false,
        interface_address: None,
        interface_port: 0,
        is_local_session: false,
        smtp_batched_input: false,
    }
}

/// Deliver a single message received via SMTP (-bs mode).
///
/// Reads the spool header, runs routers + transports, writes mainlog
/// delivery entries (`=>` and `Completed`).
///
/// C reference: `deliver_message()` in `deliver.c` (~4000 lines).
fn deliver_smtp_message(msg_id: &str, server_ctx: &ServerContext, config_ctx: &ConfigContext) {
    info!(message_id = %msg_id, "delivering message from SMTP session");

    // Build exim_config::types context structs for the delivery subsystem.
    let mut cfg_msg_ctx = exim_config::types::MessageContext::default();
    let mut cfg_delivery_ctx = exim_config::types::DeliveryContext::default();
    let cfg_server_ctx = exim_config::types::ServerContext {
        running_in_test_harness: server_ctx.running_in_test_harness,
        ..Default::default()
    };
    let cfg_config_ctx = config_ctx.get_config();

    // In -bs mode we deliver synchronously (matching C -odi semantics):
    // call deliver_message() directly in-process rather than forking a
    // child.  This keeps the log and spool operations in-sequence and
    // avoids spool-not-found races in the test harness.
    let result = exim_deliver::deliver_message(
        msg_id,
        false,
        false,
        &cfg_server_ctx,
        &mut cfg_msg_ctx,
        &mut cfg_delivery_ctx,
        cfg_config_ctx,
    );
    match result {
        Ok(_) => info!(message_id = %msg_id, "delivery completed"),
        Err(e) => {
            error!(error = %e, message_id = %msg_id, "delivery failed");
        }
    }
}

/// Inline delivery variant used by the per-message callback.
///
/// Identical to [`deliver_smtp_message`] but takes cheap cloned / owned
/// values so the closure can be `'static`.
fn deliver_smtp_message_inline(
    msg_id: &str,
    running_in_test_harness: bool,
    shared_cfg: &Arc<Config>,
) {
    info!(message_id = %msg_id, "delivering message (inline callback)");

    let mut cfg_msg_ctx = exim_config::types::MessageContext::default();
    let mut cfg_delivery_ctx = exim_config::types::DeliveryContext::default();
    let cfg_server_ctx = exim_config::types::ServerContext {
        running_in_test_harness,
        ..Default::default()
    };
    let cfg_config_ctx = shared_cfg.get();

    let result = exim_deliver::deliver_message(
        msg_id,
        false,
        false,
        &cfg_server_ctx,
        &mut cfg_msg_ctx,
        &mut cfg_delivery_ctx,
        cfg_config_ctx,
    );
    match result {
        Ok(_) => info!(message_id = %msg_id, "delivery completed"),
        Err(e) => {
            error!(error = %e, message_id = %msg_id, "delivery failed");
        }
    }
}

fn build_smtp_config_context(
    frozen_config: &Arc<exim_config::Config>,
) -> exim_smtp::inbound::command_loop::ConfigContext {
    use std::ops::Deref;
    let cfg_ctx: &exim_config::types::ConfigContext = (*frozen_config).deref();
    exim_smtp::inbound::command_loop::ConfigContext::from_config(
        cfg_ctx,
        Vec::new(), // Auth instances — populated by auth driver registration
    )
}

// =============================================================================
// Message Reception (Default Mode)
// =============================================================================

/// Handle the default mode: receive a message from stdin and deliver.
///
/// When Exim is invoked without a specific `-b*` mode (or with `-bm`),
/// it accepts a message from stdin (with optional recipient extraction
/// via `-t`), spools it, and optionally triggers immediate delivery.
///
/// The complete flow (matching C Exim `receive_msg()` in `receive.c`):
/// 1. Read the entire message from stdin (headers + body)
/// 2. Parse headers; auto-generate From:, Date:, Message-Id: if absent
/// 3. Build Received: header
/// 4. Write -H (header) and -D (data) spool files
/// 5. Write mainlog reception line (`<=`)
/// 6. Optionally fork a child for immediate delivery (`-odi`/`-odf`)
fn receive_message(
    cli_args: &cli::EximCli,
    server_ctx: &mut ServerContext,
    config_ctx: &ConfigContext,
    _frozen_config: &Arc<Config>,
) -> ExitCode {
    info!("message reception mode (default)");
    process::set_process_info("accepting message from stdin");

    // ---- Step 0: Determine sender address and originator identity ----
    let originator_login = exim_ffi::get_login_name().unwrap_or_else(|| "unknown".to_string());
    let originator_uid = unistd::getuid().as_raw();
    let originator_gid = unistd::getgid().as_raw();

    let sender_address = if let Some(ref sender) = cli_args.sender_address {
        sender.clone()
    } else {
        let qualify = &config_ctx.get_config().qualify_domain_sender;
        if qualify.is_empty() {
            format!(
                "{}@{}",
                originator_login,
                config_ctx.get_config().primary_hostname
            )
        } else {
            format!("{}@{}", originator_login, qualify)
        }
    };

    // ---- Step 0a: Extract -oM* overrides from CLI ----
    // These flags allow trusted callers to override sender host info
    // for testing and for injecting messages received via other channels.
    let opt_host_address = cli_args.sender_host_address.as_deref();
    let opt_host_name = cli_args.sender_host_name.as_deref();
    let opt_ident = cli_args.sender_ident.as_deref();
    let opt_protocol = cli_args.received_protocol.as_deref();
    let opt_interface = cli_args.incoming_interface.as_deref();
    let opt_msg_ref = cli_args.message_reference.as_deref();
    let is_network_submission = opt_host_address.is_some();

    // The effective protocol: -oMr overrides, else "local" for stdin
    let effective_protocol = opt_protocol.unwrap_or("local");

    // The effective sender_ident: -oMt overrides, else originator_login
    let effective_ident = opt_ident.unwrap_or(&originator_login);

    // -F flag overrides the From: display name (originator_name in C Exim)
    let sender_fullname = cli_args.sender_fullname.as_deref();

    // ---- Step 0b: Collect recipients ----
    let mut recipients: Vec<String> = Vec::new();
    if !cli_args.extract_recipients {
        if cli_args.recipients.is_empty() {
            error!("no recipients specified and -t not given");
            eprintln!("exim: no recipients");
            return ExitCode::FAILURE;
        }
        for rcpt in &cli_args.recipients {
            recipients.push(rcpt.clone());
        }
    }

    // ---- Step 1: Read entire message from stdin ----
    let mut raw_input = Vec::new();
    {
        use std::io::Read;
        if let Err(e) = std::io::stdin().read_to_end(&mut raw_input) {
            error!(error = %e, "failed to read message from stdin");
            eprintln!("exim: error reading stdin: {}", e);
            return ExitCode::FAILURE;
        }
    }
    let input_str = String::from_utf8_lossy(&raw_input);

    // ---- Step 2: Split headers and body ----
    let (header_block, body_block) = split_headers_body(&input_str);
    let raw_header_lines = parse_header_lines(&header_block);

    // If -t flag is set, extract recipients from To:/Cc:/Bcc: headers.
    if cli_args.extract_recipients {
        for hdr_line in &raw_header_lines {
            let lower = hdr_line.to_lowercase();
            if lower.starts_with("to:") || lower.starts_with("cc:") || lower.starts_with("bcc:") {
                let colon_pos = hdr_line.find(':').unwrap_or(0);
                let addrs_part = &hdr_line[colon_pos + 1..];
                for addr in extract_addresses(addrs_part) {
                    if !recipients.contains(&addr) {
                        recipients.push(addr);
                    }
                }
            }
        }
        if recipients.is_empty() {
            error!("no recipients found in headers with -t flag");
            eprintln!("exim: no recipients");
            return ExitCode::FAILURE;
        }
    }

    // ---- Step 2b: Qualify unqualified recipient addresses ----
    // C Exim qualifies addresses during reception (receive.c) so that the
    // spool, Received: header, and all logging contain fully-qualified
    // addresses.  We replicate that here using qualify_domain_recipient,
    // falling back to qualify_domain_sender, then primary_hostname.
    {
        let cfg = config_ctx.get_config();
        let qualify = if !cfg.qualify_domain_recipient.is_empty() {
            &cfg.qualify_domain_recipient
        } else if !cfg.qualify_domain_sender.is_empty() {
            &cfg.qualify_domain_sender
        } else {
            &cfg.primary_hostname
        };
        if !qualify.is_empty() {
            for rcpt in &mut recipients {
                if !rcpt.contains('@') {
                    *rcpt = format!("{}@{}", rcpt, qualify);
                }
            }
        }
    }

    // ---- Step 3: Generate message ID and timestamps ----
    let now_dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let tv_sec = now_dur.as_secs() as u32;
    let tv_usec = now_dur.subsec_micros();
    let pid = std::process::id() as u64;
    let msg_id = exim_spool::generate_message_id(tv_sec, pid, tv_usec, None, 1);
    info!(message_id = %msg_id, "message ID generated");

    let now_epoch = now_dur.as_secs();
    let timestamp = format_rfc2822_ts(now_epoch);
    let hostname = &config_ctx.get_config().primary_hostname;
    let version = exim_ffi::get_patched_version();

    // ---- Step 4: Build Received: header ----
    // C Exim builds the Received: header differently for local vs network:
    //   Network (-oMa set): "from HOSTNAME ([IP] ident=IDENT)"
    //   Local (no -oMa):    "from IDENT" (or originator_login if no -oMt)
    let for_clause = if recipients.len() == 1 {
        format!("\n\tfor {}", &recipients[0])
    } else {
        String::new()
    };

    let received_header = if is_network_submission {
        // Network-style Received: header — line break between "from" and "by"
        // Format: "from HOSTNAME ([IP] ident=IDENT)\n\tby HOST with PROTO ..."
        let h_name = opt_host_name.unwrap_or("unknown");
        let h_addr = opt_host_address.unwrap_or("unknown");
        let from_clause = if !effective_ident.is_empty() {
            format!("{} ([{}] ident={})", h_name, h_addr, effective_ident)
        } else {
            format!("{} ([{}])", h_name, h_addr)
        };
        format!(
            "Received: from {}\n\tby {} with {} (Exim {})\n\t(envelope-from <{}>)\n\tid {}{};\n\t{}\n",
            from_clause, hostname, effective_protocol, version, sender_address,
            msg_id, for_clause, timestamp,
        )
    } else {
        // Local-style Received: header — "from" and "by" on SAME line
        // Format: "from IDENT by HOST with PROTO (Exim VER)\n\t..."
        format!(
            "Received: from {} by {} with {} (Exim {})\n\t(envelope-from <{}>)\n\tid {}{};\n\t{}\n",
            effective_ident,
            hostname,
            effective_protocol,
            version,
            sender_address,
            msg_id,
            for_clause,
            timestamp,
        )
    };

    // ---- Step 5: Build spool headers list ----
    let mut spool_headers: Vec<exim_spool::header_file::SpoolHeader> = Vec::new();

    // Received: header first (type '*')
    spool_headers.push(exim_spool::header_file::SpoolHeader {
        text: received_header.clone(),
        slen: received_header.len(),
        header_type: '*',
    });

    // Determine which auto-headers need to be generated
    let mut has_message_id = false;
    let mut has_from = false;
    let mut has_date = false;
    for hdr_line in &raw_header_lines {
        let lower = hdr_line.to_lowercase();
        if lower.starts_with("message-id:") {
            has_message_id = true;
        }
        if lower.starts_with("from:") {
            has_from = true;
        }
        if lower.starts_with("date:") {
            has_date = true;
        }
    }

    // Add original message headers (type ' ')
    for raw_hdr in &raw_header_lines {
        let mut text = raw_hdr.clone();
        if !text.ends_with('\n') {
            text.push('\n');
        }
        let slen = text.len();
        spool_headers.push(exim_spool::header_file::SpoolHeader {
            slen,
            text,
            header_type: ' ',
        });
    }

    // Auto-generate missing headers ONLY for local submissions (C Exim receive.c).
    // Network-style messages (with -oMa) do not get auto-generated headers.
    if !is_network_submission {
        if !has_message_id {
            let mid_hdr = format!("Message-Id: <E{}@{}>\n", msg_id, hostname);
            let mid_len = mid_hdr.len();
            spool_headers.push(exim_spool::header_file::SpoolHeader {
                text: mid_hdr,
                slen: mid_len,
                header_type: ' ',
            });
        }
        if !has_from {
            // C Exim: From: originator_name <sender_address>
            // Priority: 1) -F flag, 2) config gecos_name, 3) GECOS from passwd.
            // C Exim respects the main config `gecos_name` option; the test harness
            // sets `gecos_name = CALLER_NAME` to produce predictable output.
            let from_name = if let Some(name) = sender_fullname {
                name.to_string()
            } else if let Some(ref gn) = config_ctx.get_config().gecos_name {
                gn.clone()
            } else {
                exim_ffi::get_real_name().unwrap_or_default()
            };
            let from_hdr = if from_name.is_empty() {
                format!("From: {}\n", sender_address)
            } else {
                format!("From: {} <{}>\n", from_name, sender_address)
            };
            let from_len = from_hdr.len();
            spool_headers.push(exim_spool::header_file::SpoolHeader {
                text: from_hdr,
                slen: from_len,
                header_type: ' ',
            });
        }
        if !has_date {
            let date_hdr = format!("Date: {}\n", timestamp);
            let date_len = date_hdr.len();
            spool_headers.push(exim_spool::header_file::SpoolHeader {
                text: date_hdr,
                slen: date_len,
                header_type: ' ',
            });
        }
    }

    // ---- Step 5b: Body metrics ----
    let body_bytes = body_block.as_bytes();
    let body_linecount = body_bytes.iter().filter(|&&b| b == b'\n').count() as i64;
    let body_zerocount = body_bytes.iter().filter(|&&b| b == 0).count() as i64;
    let max_line_len = body_block.lines().map(|l| l.len()).max().unwrap_or(0) as i64;
    let max_hdr_line_len = raw_header_lines
        .iter()
        .map(|h| h.lines().map(|l| l.len()).max().unwrap_or(0))
        .max()
        .unwrap_or(0) as i64;
    let max_received_linelength = std::cmp::max(max_line_len, max_hdr_line_len);

    // ---- Step 6: Write spool files ----
    let spool_dir = &config_ctx.get_config().spool_directory;
    let input_dir = format!("{}/input", spool_dir);
    let _ = std::fs::create_dir_all(&input_dir);

    // Write -D (data) file: "{msg_id}-D\n{body}"
    let data_path = format!("{}/{}-D", input_dir, msg_id);
    let data_header_line = format!("{}-D\n", msg_id);
    let data_header_len = data_header_line.len();
    let mut data_content: Vec<u8> = data_header_line.into_bytes();
    data_content.extend_from_slice(body_bytes);
    if let Err(e) = std::fs::write(&data_path, &data_content) {
        error!(path = %data_path, error = %e, "failed to write -D file");
        return ExitCode::FAILURE;
    }

    // Build recipient list for spool file
    let spool_recipients: Vec<exim_spool::header_file::Recipient> = recipients
        .iter()
        .map(|r| exim_spool::header_file::Recipient {
            address: r.clone(),
            pno: -1,
            errors_to: None,
            dsn: exim_spool::header_file::DsnInfo::default(),
        })
        .collect();

    // Message size: body + headers in spool form
    let message_size: i64 = data_content.len() as i64 - data_header_len as i64
        + spool_headers.iter().map(|h| h.slen as i64).sum::<i64>();

    let mut spool_file = exim_spool::header_file::SpoolHeaderFile {
        message_id: msg_id.clone(),
        originator_login: originator_login.clone(),
        originator_uid: originator_uid as i64,
        originator_gid: originator_gid as i64,
        sender_address: sender_address.clone(),
        received_time_sec: now_epoch as i64,
        received_time_usec: tv_usec,
        received_time_complete_sec: now_epoch as i64,
        received_time_complete_usec: tv_usec,
        received_protocol: Some(effective_protocol.to_string()),
        sender_ident: Some(effective_ident.to_string()),
        headers: spool_headers,
        recipients: spool_recipients,
        body_linecount,
        body_zerocount,
        max_received_linelength,
        message_size,
        ..Default::default()
    };

    // Populate -oM* override fields in the spool file so the delivery
    // process can use them for variable expansion ($interface_address etc.)
    if let Some(addr) = opt_host_address {
        spool_file.host_address = Some(addr.to_string());
    }
    if let Some(name) = opt_host_name {
        spool_file.host_name = Some(name.to_string());
    }
    if let Some(iface) = opt_interface {
        spool_file.interface_address = Some(iface.to_string());
    }

    // sender_local is false when a host address is provided (network-style)
    spool_file.flags.sender_local = !is_network_submission;
    spool_file.flags.deliver_firsttime = true;
    if cli_args.dont_deliver {
        spool_file.flags.dont_deliver = true;
    }

    // Write -H (header) file
    let header_path = format!("{}/{}-H", input_dir, msg_id);
    match std::fs::File::create(&header_path) {
        Ok(file) => {
            if let Err(e) = spool_file.write_to(file) {
                error!(path = %header_path, error = %e, "failed to write -H file");
                return ExitCode::FAILURE;
            }
        }
        Err(e) => {
            error!(path = %header_path, error = %e, "failed to create -H file");
            return ExitCode::FAILURE;
        }
    }

    // ---- Step 7: Write mainlog reception line ----
    // C Exim format: "TIMESTAMP MSGID <= sender [R=ref] [H=host [ip]] U=ident P=proto S=size [for rcpt]"
    let log_ts = format_log_ts(now_epoch);

    // Build the log line matching C Exim's add_host_info_for_log()
    let mut log_parts: Vec<String> = Vec::new();
    log_parts.push(format!("{} {} <= {}", log_ts, msg_id, sender_address));

    // R= message reference (from -oMm)
    if let Some(msg_ref) = opt_msg_ref {
        log_parts.push(format!(" R={}", msg_ref));
    }

    // H= sender host info (from -oMa/-oMs)
    if is_network_submission {
        let h_name = opt_host_name.unwrap_or("unknown");
        let h_addr = opt_host_address.unwrap_or("unknown");
        log_parts.push(format!(" H={} [{}]", h_name, h_addr));
    }

    // U= sender ident
    log_parts.push(format!(" U={}", effective_ident));

    // P= protocol
    log_parts.push(format!(" P={}", effective_protocol));

    // S= message size
    log_parts.push(format!(" S={}", message_size));

    // "for recipients" (only when +received_recipients log selector is set)
    let log_received_recipients = config_ctx
        .get_config()
        .log_selector_string
        .as_deref()
        .is_some_and(|s| s.contains("received_recipients"));
    if log_received_recipients {
        let rcpt_list: Vec<&str> = recipients.iter().map(|r| r.as_str()).collect();
        log_parts.push(format!(" for {}", rcpt_list.join(" ")));
    }

    let log_line = log_parts.concat();
    write_mainlog_entry(config_ctx.get_config(), &log_line);

    // ---- Step 8: Trigger delivery based on delivery mode ----
    let should_deliver_immediately = match cli_args.delivery_mode {
        Some(DeliveryMode::QueueOnly) | Some(DeliveryMode::QueueSmtp) => false,
        _ if cli_args.queue_only => false,
        _ if cli_args.dont_deliver => false,
        _ => true,
    };

    if should_deliver_immediately {
        debug!("immediate delivery after reception");

        match process::exim_fork("post-reception delivery") {
            Ok(ForkResult::Child) => {
                let mut cfg_msg_ctx = exim_config::types::MessageContext::default();
                let mut cfg_delivery_ctx = exim_config::types::DeliveryContext::default();
                let cfg_server_ctx = exim_config::types::ServerContext {
                    running_in_test_harness: server_ctx.running_in_test_harness,
                    ..Default::default()
                };
                let cfg_config_ctx = config_ctx.get_config().clone();

                let result = exim_deliver::deliver_message(
                    &msg_id,
                    false,
                    false,
                    &cfg_server_ctx,
                    &mut cfg_msg_ctx,
                    &mut cfg_delivery_ctx,
                    &cfg_config_ctx,
                );

                let exit_code: i32 = match result {
                    Ok(DeliveryResult::NotAttempted) => libc::EXIT_FAILURE,
                    Ok(_) => libc::EXIT_SUCCESS,
                    Err(e) => {
                        error!(error = %e, "post-reception delivery failed");
                        libc::EXIT_FAILURE
                    }
                };
                std::process::exit(exit_code);
            }
            Ok(ForkResult::Parent { child }) => match cli_args.delivery_mode {
                Some(DeliveryMode::Foreground) | Some(DeliveryMode::Interactive) => {
                    match process::child_close(child, Duration::from_secs(600)) {
                        Ok(0) => info!("delivery child completed successfully"),
                        Ok(code) => {
                            warn!(exit_code = code, "delivery child exited with error");
                        }
                        Err(e) => {
                            error!(error = %e, "failed to wait for delivery child");
                        }
                    }
                }
                _ => {
                    debug!(child_pid = ?child, "delivery child forked in background");
                }
            },
            Err(e) => {
                error!(error = %e, "failed to fork for delivery");
                return ExitCode::FAILURE;
            }
        }
    } else {
        info!("message queued, no immediate delivery");
    }

    ExitCode::SUCCESS
}

/// Split raw message input into headers and body sections.
/// Headers end at the first blank line (a line containing only "\n" or "\r\n").
fn split_headers_body(input: &str) -> (String, String) {
    // Look for "\n\n" (Unix) or "\r\n\r\n" (CRLF) as the header/body separator.
    if let Some(pos) = input.find("\n\n") {
        let headers = &input[..pos + 1]; // include the trailing \n
        let body = &input[pos + 2..]; // skip the blank line
        return (headers.to_string(), body.to_string());
    }
    if let Some(pos) = input.find("\r\n\r\n") {
        let headers = &input[..pos + 2];
        let body = &input[pos + 4..];
        return (headers.to_string(), body.to_string());
    }
    // No blank line found: if input starts with a header-like line, treat
    // the entire input as body (C Exim: a message with no headers).
    // If there are "Name: value" lines, they are headers. Otherwise body only.
    if input.contains(':') && !input.starts_with(' ') && !input.starts_with('\t') {
        // Likely all headers, no body
        (input.to_string(), String::new())
    } else {
        // No headers, all body
        (String::new(), input.to_string())
    }
}

/// Parse raw header block into individual header lines.
/// Continuation lines (starting with space or tab) are folded into
/// the preceding header.
fn parse_header_lines(header_block: &str) -> Vec<String> {
    let mut headers: Vec<String> = Vec::new();
    for line in header_block.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation line: append to previous header
            if let Some(last) = headers.last_mut() {
                last.push('\n');
                last.push_str(line);
            }
        } else if !line.is_empty() {
            headers.push(line.to_string());
        }
    }
    headers
}

/// Extract email addresses from a header value (e.g., "user@domain, Name <user2@domain>").
fn extract_addresses(value: &str) -> Vec<String> {
    let mut addrs = Vec::new();
    for part in value.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Look for angle-bracket form: "Name <addr>"
        if let Some(start) = trimmed.find('<') {
            if let Some(end) = trimmed.find('>') {
                if end > start {
                    let addr = trimmed[start + 1..end].trim().to_string();
                    if !addr.is_empty() {
                        addrs.push(addr);
                        continue;
                    }
                }
            }
        }
        // Bare address form
        if trimmed.contains('@') {
            addrs.push(trimmed.to_string());
        }
    }
    addrs
}

/// Format a Unix epoch timestamp as an RFC 2822 date string.
/// Produces: "Thu, 01 Jan 2025 00:00:00 +0000"
fn format_rfc2822_ts(epoch_secs: u64) -> String {
    let (year, month, day, hour, min, sec, wday) = epoch_to_utc(epoch_secs);
    let days = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let day_name = days[(wday % 7) as usize];
    let mon_name = if (1..=12).contains(&month) {
        months[(month - 1) as usize]
    } else {
        "???"
    };
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} +0000",
        day_name, day, mon_name, year, hour, min, sec,
    )
}

/// Format a Unix epoch timestamp for mainlog lines: "2025-01-01 00:00:00"
fn format_log_ts(epoch_secs: u64) -> String {
    let (year, month, day, hour, min, sec, _wday) = epoch_to_utc(epoch_secs);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, hour, min, sec,
    )
}

/// Convert Unix epoch seconds to UTC date/time components.
/// Returns (year, month, day, hour, minute, second, weekday).
/// Weekday: 0 = Thursday (epoch was a Thursday).
fn epoch_to_utc(epoch_secs: u64) -> (i32, u32, u32, u32, u32, u32, u32) {
    let secs = epoch_secs;
    let sec = (secs % 60) as u32;
    let mins_total = secs / 60;
    let min = (mins_total % 60) as u32;
    let hours_total = mins_total / 60;
    let hour = (hours_total % 24) as u32;
    let days_total = (hours_total / 24) as i64;
    let wday = ((days_total % 7) as u32 + 7) % 7; // 0=Thu

    // Civil date from day count (algorithm from Howard Hinnant)
    let z = days_total + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    (year as i32, m, d, hour, min, sec, wday)
}

/// Write a line to the Exim mainlog file.
/// Print a configuration error in the same format C Exim uses:
///
/// ```text
/// TIMESTAMP Exim configuration error in line N of FILE:
///   MESSAGE
/// ```
///
/// For errors without file/line information, fall back to a simpler format.
fn print_config_error(e: &exim_config::ConfigError) {
    use exim_config::ConfigError;
    match e {
        ConfigError::ParseError {
            file,
            line,
            message,
        } if !file.is_empty() && *line > 0 => {
            let ts = format_log_ts(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            );
            eprintln!(
                "{} Exim configuration error in line {} of {}:\n  {}",
                ts, line, file, message
            );
        }
        _ => {
            eprintln!("Exim configuration error: {e}");
        }
    }
}

fn write_mainlog_entry(config: &exim_config::ConfigContext, line: &str) {
    let mainlog_path = if config.log_file_path.is_empty() {
        format!("{}/log/mainlog", config.spool_directory)
    } else {
        config.log_file_path.replace("%slog", "mainlog")
    };
    let log_dir = std::path::Path::new(&mainlog_path).parent();
    if let Some(dir) = log_dir {
        let _ = std::fs::create_dir_all(dir);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750));
        }
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o666);
    }
    if let Ok(mut f) = opts.open(&mainlog_path) {
        use std::io::Write;
        let _ = writeln!(f, "{}", line);
    }
}

// =============================================================================
// Initialisation Helpers
// =============================================================================

/// Compile the core message ID regex pattern.
fn init_regex_msgid() -> Regex {
    Regex::new(EXIM_MESSAGE_ID_REGEX).expect("message ID regex must compile")
}

/// Compile the SMTP response code regex pattern.
fn init_regex_smtp_code() -> Regex {
    Regex::new(SMTP_RESPONSE_CODE_REGEX).expect("SMTP response code regex must compile")
}

/// Resolve the Exim user and group, populating the server context.
fn resolve_exim_user(server_ctx: &mut ServerContext) {
    let real_uid = unistd::getuid();
    let real_gid = unistd::getgid();
    server_ctx.real_uid = real_uid.as_raw();
    server_ctx.real_gid = real_gid.as_raw();

    let euid = unistd::geteuid();
    server_ctx.running_as_root = euid.is_root();

    debug!(
        real_uid = server_ctx.real_uid,
        real_gid = server_ctx.real_gid,
        effective_uid = euid.as_raw(),
        running_as_root = server_ctx.running_as_root,
        "process identity resolved"
    );

    match nix::unistd::User::from_name(EXIM_USERNAME) {
        Ok(Some(user)) => {
            server_ctx.exim_uid = user.uid.as_raw();
            debug!(
                exim_uid = server_ctx.exim_uid,
                user = EXIM_USERNAME,
                "exim user resolved"
            );
        }
        Ok(None) => {
            warn!(user = EXIM_USERNAME, "exim user not found, using uid 0");
            server_ctx.exim_uid = 0;
        }
        Err(e) => {
            warn!(error = %e, user = EXIM_USERNAME, "failed to resolve exim user");
            server_ctx.exim_uid = 0;
        }
    }

    match nix::unistd::Group::from_name(EXIM_GROUPNAME) {
        Ok(Some(group)) => {
            server_ctx.exim_gid = group.gid.as_raw();
            debug!(
                exim_gid = server_ctx.exim_gid,
                group = EXIM_GROUPNAME,
                "exim group resolved"
            );
        }
        Ok(None) => {
            warn!(group = EXIM_GROUPNAME, "exim group not found, using gid 0");
            server_ctx.exim_gid = 0;
        }
        Err(e) => {
            warn!(error = %e, group = EXIM_GROUPNAME, "failed to resolve exim group");
            server_ctx.exim_gid = 0;
        }
    }
}

/// Check whether the current user has admin privileges.
fn check_admin_user(server_ctx: &mut ServerContext) {
    if server_ctx.running_as_root {
        server_ctx.admin_user = true;
        debug!("admin_user: true (running as root)");
        return;
    }

    if server_ctx.real_uid == server_ctx.exim_uid {
        server_ctx.admin_user = true;
        debug!(
            real_uid = server_ctx.real_uid,
            exim_uid = server_ctx.exim_uid,
            "admin_user: true (matching exim uid)"
        );
        return;
    }

    server_ctx.admin_user = false;
    debug!(
        real_uid = server_ctx.real_uid,
        exim_uid = server_ctx.exim_uid,
        "admin_user: false"
    );
}

/// Apply relevant configuration values to the server context.
fn apply_config_to_server_ctx(server_ctx: &mut ServerContext, config_ctx: &ConfigContext) {
    let cfg = config_ctx.get_config();

    if !cfg.primary_hostname.is_empty() {
        server_ctx.primary_hostname = cfg.primary_hostname.clone();
    } else {
        match nix::unistd::gethostname() {
            Ok(hostname) => {
                server_ctx.primary_hostname = hostname.to_string_lossy().to_string();
                debug!(hostname = %server_ctx.primary_hostname, "primary hostname auto-detected");
            }
            Err(e) => {
                warn!(error = %e, "failed to auto-detect hostname");
                server_ctx.primary_hostname = String::from("localhost");
            }
        }
    }
}

/// Configure debug logging based on CLI arguments.
///
/// Parses the `-d` selector string into a bitmask matching C Exim's
/// `debug_options[]` table in globals.c.  The selector format is:
///   - `-d`        → D_all (all bits set)
///   - `-d+all`    → D_all
///   - `-d-all+expand` → only D_expand
///   - `-d-all+expand+noutf8` → D_expand | D_noutf8
fn configure_debug_logging(cli_args: &cli::EximCli, server_ctx: &mut ServerContext) {
    if cli_args.verbose {
        debug!("verbose mode enabled (-v)");
    }

    if let Some(ref selector) = cli_args.debug_selector {
        debug!(selector = %selector, "debug selector configured");
        server_ctx.debug_selector = parse_debug_selector(selector);
    }
}

// ── Debug selector bit constants matching C Exim's macros.h ─────────
const D_V: u32 = 1 << 0;
const D_LOCAL_SCAN: u32 = 1 << 1;
const D_ACL: u32 = 1 << 2;
const D_AUTH: u32 = 1 << 3;
const D_DELIVER: u32 = 1 << 4;
const D_DNS: u32 = 1 << 5;
const D_DNSBL: u32 = 1 << 6;
const D_EXEC: u32 = 1 << 7;
const D_EXPAND: u32 = 1 << 8;
const D_FILTER: u32 = 1 << 9;
const D_HINTS_LOOKUP: u32 = 1 << 10;
const D_HOST_LOOKUP: u32 = 1 << 11;
const D_IDENT: u32 = 1 << 12;
const D_INTERFACE: u32 = 1 << 13;
const D_LISTS: u32 = 1 << 14;
const D_LOAD: u32 = 1 << 15;
const D_LOOKUP: u32 = 1 << 16;
const D_MEMORY: u32 = 1 << 17;
const D_NOUTF8: u32 = 1 << 18;
const D_PID: u32 = 1 << 19;
const D_PROCESS_INFO: u32 = 1 << 20;
const D_QUEUE_RUN: u32 = 1 << 21;
const D_RECEIVE: u32 = 1 << 22;
const D_RESOLVER: u32 = 1 << 23;
const D_RETRY: u32 = 1 << 24;
const D_REWRITE: u32 = 1 << 25;
const D_ROUTE: u32 = 1 << 26;
const D_TIMESTAMP: u32 = 1 << 27;
const D_TLS: u32 = 1 << 28;
const D_TRANSPORT: u32 = 1 << 29;
const D_UID: u32 = 1 << 30;
const D_VERIFY: u32 = 1 << 31;
const D_ALL: u32 = 0xFFFF_FFFF;

/// Parse a debug selector string into a bitmask.
///
/// Handles formats like: `""`, `"+all"`, `"-all+expand"`,
/// `"-all+expand+noutf8"`, `"=0x1234"`, etc.
fn parse_debug_selector(selector: &str) -> u32 {
    if selector.is_empty() {
        return D_ALL;
    }

    // Handle hex numeric format: `=0x1234`
    if let Some(hex_str) = selector.strip_prefix("=0x") {
        return u32::from_str_radix(hex_str, 16).unwrap_or(D_ALL);
    }
    if let Some(hex_str) = selector.strip_prefix("0x") {
        return u32::from_str_radix(hex_str, 16).unwrap_or(D_ALL);
    }

    let mut bits: u32 = D_ALL;

    // Parse +name / -name tokens
    let mut rest = selector;
    while !rest.is_empty() {
        let (adding, name_rest) = if let Some(r) = rest.strip_prefix('+') {
            (true, r)
        } else if let Some(r) = rest.strip_prefix('-') {
            (false, r)
        } else {
            // Bare name — treat as +name
            (true, rest)
        };

        // Find the next + or - to delimit the name
        let end = name_rest.find(['+', '-']).unwrap_or(name_rest.len());
        let name = &name_rest[..end];
        rest = &name_rest[end..];

        let bit = match name {
            "all" => D_ALL,
            "v" => D_V,
            "local_scan" => D_LOCAL_SCAN,
            "acl" => D_ACL,
            "auth" => D_AUTH,
            "deliver" => D_DELIVER,
            "dns" => D_DNS,
            "dnsbl" => D_DNSBL,
            "exec" => D_EXEC,
            "expand" => D_EXPAND,
            "filter" => D_FILTER,
            "hints_lookup" => D_HINTS_LOOKUP,
            "host_lookup" => D_HOST_LOOKUP,
            "ident" => D_IDENT,
            "interface" => D_INTERFACE,
            "lists" => D_LISTS,
            "load" => D_LOAD,
            "lookup" => D_LOOKUP,
            "memory" => D_MEMORY,
            "noutf8" => D_NOUTF8,
            "pid" => D_PID,
            "process_info" => D_PROCESS_INFO,
            "queue_run" => D_QUEUE_RUN,
            "receive" => D_RECEIVE,
            "resolver" => D_RESOLVER,
            "retry" => D_RETRY,
            "rewrite" => D_REWRITE,
            "route" => D_ROUTE,
            "timestamp" => D_TIMESTAMP,
            "tls" => D_TLS,
            "transport" => D_TRANSPORT,
            "uid" => D_UID,
            "verify" => D_VERIFY,
            _ => 0,
        };

        if adding {
            bits |= bit;
        } else {
            bits &= !bit;
        }
    }
    bits
}

/// Convert a `cli::QueueRunConfig` to a `queue_runner::QueueRunner`.
fn cli_queue_config_to_runner(config: &QueueRunConfig) -> queue_runner::QueueRunner {
    queue_runner::QueueRunner {
        name: config.name.clone().unwrap_or_default(),
        interval: config.interval.unwrap_or(Duration::ZERO),
        run_max: 5,
        run_force: config.force,
        run_first_delivery: config.first_delivery,
        run_local: config.local_only,
        run_in_order: false,
    }
}
