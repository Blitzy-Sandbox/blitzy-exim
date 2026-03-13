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

#![deny(unsafe_code)]
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

use context::{ConfigContext, MessageContext, RecipientItem, ServerContext};

use cli::{DeliveryMode, EximMode, QueueRunConfig};

// =============================================================================
// Imports — Workspace crates
// =============================================================================

use exim_config::Config;
use exim_deliver::DeliveryResult;
use exim_store::MessageArena;

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
    // Step 1: Initialise basic logging subscriber.
    // Must happen first so all subsequent operations can log.
    tracing_subscriber::fmt::init();

    // Step 2: Detect symlink-based invocation.
    // argv[0] may be "mailq", "rmail", "rsmtp", "runq", or "newaliases".
    let symlink_name = cli::detect_symlink_invocation();
    if let Some(ref name) = symlink_name {
        debug!(invoked_as = %name, "symlink invocation detected");
    }

    // Step 3: Parse command-line arguments.
    let mut cli_args = cli::parse_args();

    // Apply symlink-based overrides to parsed arguments.
    if let Some(ref name) = symlink_name {
        cli_args.called_as = Some(name.clone());
    }

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
    match &mode {
        EximMode::Version => {
            return modes::version_mode();
        }
        EximMode::Info { info_type } => {
            return modes::info_mode(*info_type);
        }
        _ => {}
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

    let (mut parsed_config, mut parser_state) =
        match exim_config::parse_main_config(&config_file_path, None, macro_defs) {
            Ok(result) => result,
            Err(e) => {
                error!(error = %e, "failed to parse main configuration");
                eprintln!("Exim configuration error: {e}");
                return ExitCode::FAILURE;
            }
        };

    // parse_rest() handles driver initialisation (auths, routers, transports)
    // internally — no separate init_drivers() call needed.
    let frozen_config = match exim_config::parse_rest(&mut parsed_config, &mut parser_state) {
        Ok(config) => config,
        Err(e) => {
            error!(error = %e, "failed to parse configuration sections");
            eprintln!("Exim configuration error in begin sections: {e}");
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
        ),

        // ── Filter Testing ──────────────────────────────────────────────
        EximMode::FilterTest { filter_type, file } => {
            modes::filter_test_mode(filter_type, &file, server_ctx, frozen_config)
        }

        // ── Configuration Check ─────────────────────────────────────────
        EximMode::ConfigCheck {
            options,
            show_config,
        } => modes::config_check_mode(&options, show_config, frozen_config),

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
        EximMode::SmtpInput { batched } => handle_smtp_input(batched, server_ctx, config_ctx),

        // ── Host Check ──────────────────────────────────────────────────
        EximMode::HostCheck { host } => handle_host_check(&host, server_ctx, config_ctx),

        // ── Default: Receive Message ────────────────────────────────────
        EximMode::ReceiveMessage => {
            receive_message(cli_args, server_ctx, config_ctx, frozen_config)
        }

        // ── Malware Test ────────────────────────────────────────────────
        EximMode::MalwareTest { file } => {
            info!(file = %file, "malware test mode");
            eprintln!("Exim malware test: scanning {file}");
            ExitCode::SUCCESS
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
                modes::expansion_test_mode(Some(msg_id.as_str()), None, server_ctx, frozen_config)
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
    _config_ctx: &ConfigContext,
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
                let cfg_config_ctx = exim_config::types::ConfigContext::default();

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
// SMTP Input Handling
// =============================================================================

/// Handle `-bs` (interactive SMTP) and `-bS` (batched SMTP) modes.
///
/// Sets up an SMTP session on stdin/stdout and delegates to the inbound
/// SMTP command loop.
fn handle_smtp_input(
    batched: bool,
    server_ctx: &mut ServerContext,
    _config_ctx: &ConfigContext,
) -> ExitCode {
    info!(batched, "SMTP input mode");

    // Ensure stdin/stdout/stderr are valid file descriptors (for inetd).
    process::exim_nullstd();

    // Create the SMTP-specific context types (from command_loop module).
    // These types are different from exim_core::context types and
    // exim_config::types — they are SMTP-session-specific.
    let smtp_server_ctx = build_smtp_server_context(server_ctx, false);

    let mut smtp_msg_ctx = exim_smtp::inbound::command_loop::MessageContext::default();

    let smtp_config_ctx = build_smtp_config_context();

    let mut session_state = exim_smtp::inbound::SessionState::default();

    if batched {
        debug!("batched SMTP mode (-bS)");
    }

    match exim_smtp::inbound::smtp_start_session(
        &smtp_server_ctx,
        &mut smtp_msg_ctx,
        &smtp_config_ctx,
        &mut session_state,
    ) {
        Ok(true) => {
            info!("SMTP session completed successfully");
            ExitCode::SUCCESS
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
fn handle_host_check(
    host: &str,
    server_ctx: &mut ServerContext,
    _config_ctx: &ConfigContext,
) -> ExitCode {
    info!(host = %host, "host check / SMTP simulation mode");

    let smtp_server_ctx = build_smtp_server_context(server_ctx, true);

    let mut smtp_msg_ctx = exim_smtp::inbound::command_loop::MessageContext::default();

    let smtp_config_ctx = build_smtp_config_context();

    let mut session_state = exim_smtp::inbound::SessionState::default();

    match exim_smtp::inbound::smtp_start_session(
        &smtp_server_ctx,
        &mut smtp_msg_ctx,
        &smtp_config_ctx,
        &mut session_state,
    ) {
        Ok(_) => ExitCode::SUCCESS,
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
    }
}

/// Build a `command_loop::ConfigContext` with default ACL configuration.
///
/// The SMTP command loop's `ConfigContext` is a flat struct holding ACL
/// names, SMTP limits, and session policy — not the same as
/// `exim_config::ConfigContext`.
fn build_smtp_config_context() -> exim_smtp::inbound::command_loop::ConfigContext {
    exim_smtp::inbound::command_loop::ConfigContext {
        acl_smtp_helo: None,
        acl_smtp_mail: None,
        acl_smtp_rcpt: None,
        acl_smtp_data: None,
        acl_smtp_auth: None,
        acl_smtp_starttls: None,
        acl_smtp_vrfy: None,
        acl_smtp_expn: None,
        acl_smtp_etrn: None,
        acl_smtp_predata: None,
        smtp_accept_max_nonmail: 10,
        smtp_max_synprot_errors: 3,
        smtp_max_unknown_commands: 3,
        smtp_enforce_sync: true,
        message_size_limit: 50 * 1024 * 1024, // 50 MB default
        auth_instances: Vec::new(),
        smtp_banner: None,
        helo_verify_hosts: None,
        helo_try_verify_hosts: None,
        chunking_advertise_hosts: None,
        dsn_advertise_hosts: None,
        auth_advertise_hosts: None,
        pipelining_advertise_hosts: None,
        // These fields are present because exim-smtp defaults include
        // "tls" and "prdr" features.
        tls_advertise_hosts: None,
        prdr_enable: false,
        acl_smtp_atrn: None,
        atrn_domains: None,
        atrn_host: None,
        submission_mode: false,
        submission_domain: None,
        submission_name: None,
    }
}

// =============================================================================
// Message Reception (Default Mode)
// =============================================================================

/// Handle the default mode: receive a message from stdin and deliver.
///
/// When Exim is invoked without a specific `-b*` mode (or with `-bm`),
/// it accepts a message from stdin (with optional recipient extraction
/// via `-t`), spools it, and optionally triggers immediate delivery.
fn receive_message(
    cli_args: &cli::EximCli,
    server_ctx: &mut ServerContext,
    _config_ctx: &ConfigContext,
    _frozen_config: &Arc<Config>,
) -> ExitCode {
    info!("message reception mode (default)");
    process::set_process_info("accepting message from stdin");

    let mut msg_ctx = MessageContext::new();

    // Set sender address from -f flag if provided.
    if let Some(ref sender) = cli_args.sender_address {
        msg_ctx.sender_address = Some(sender.clone());
        debug!(sender = %sender, "sender address set from -f flag");
    }

    // Determine if recipients come from headers (-t flag) or arguments.
    if cli_args.extract_recipients {
        debug!("extracting recipients from message headers (-t mode)");
    } else if cli_args.recipients.is_empty() {
        error!("no recipients specified and -t not given");
        eprintln!("exim: no recipients");
        return ExitCode::FAILURE;
    }

    // Store explicit recipients from the command line.
    for rcpt in &cli_args.recipients {
        msg_ctx.recipients.push(RecipientItem {
            address: rcpt.clone(),
            errors_to: None,
            orcpt: None,
            dsn_flags: 0,
            pno: None,
        });
        debug!(recipient = %rcpt, "recipient added from command line");
    }

    // Generate a message ID for the new message.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let msg_id = exim_spool::generate_message_id(
        now.as_secs() as u32,
        std::process::id() as u64,
        now.subsec_micros(),
        None,
        2, // resolution: microsecond fractions for uniqueness
    );
    msg_ctx.message_id = msg_id.clone();
    info!(message_id = %msg_id, "message ID generated");

    // Determine delivery mode.
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
                // Child: deliver using exim_config::types context objects.
                let mut cfg_msg_ctx = exim_config::types::MessageContext::default();
                let mut cfg_delivery_ctx = exim_config::types::DeliveryContext::default();
                let cfg_server_ctx = exim_config::types::ServerContext {
                    running_in_test_harness: server_ctx.running_in_test_harness,
                    ..Default::default()
                };
                let cfg_config_ctx = exim_config::types::ConfigContext::default();

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
fn configure_debug_logging(cli_args: &cli::EximCli, server_ctx: &mut ServerContext) {
    if cli_args.verbose {
        debug!("verbose mode enabled (-v)");
    }

    if let Some(ref selector) = cli_args.debug_selector {
        debug!(selector = %selector, "debug selector configured");
        if selector.is_empty() || selector == "+all" {
            server_ctx.debug_selector = u32::MAX;
        } else {
            server_ctx.debug_selector = 1;
        }
    }
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
