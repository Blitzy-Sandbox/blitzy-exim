// exim-core/src/cli.rs — CLI Argument Parsing for Exim MTA (Rust rewrite)
//
// Replaces the argument parsing switch in src/src/exim.c (lines ~2200–3900).
// Exim's CLI format is NON-STANDARD: single-dash multi-character flags (-bd, -bp),
// embedded values (-q30m, -d+all), and sendmail compatibility options. A custom
// parser is used because clap's standard parsing cannot handle Exim's format.
//
// Per AAP §0.7.1: CLI flags MUST be preserved exactly — same flag names, same
// semantics, same exit codes, same symlink-based invocation behavior.
//
// Per AAP §0.7.2: Zero `unsafe` code in this crate.

use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Public enums — operational modes, queue options, message actions, etc.
// ---------------------------------------------------------------------------

/// Operational mode determined from CLI arguments. Each variant corresponds to
/// a distinct execution path in the Exim binary.
#[derive(Debug, Clone, PartialEq)]
pub enum EximMode {
    /// `-bd` / `-bdf`: daemon mode listening for SMTP connections.
    Daemon { foreground: bool },

    /// `-q*`: one or more queue-runner configurations.
    QueueRun { runners: Vec<QueueRunConfig> },

    /// `-bp*`: list the mail queue in various formats.
    ListQueue { option: QueueListOption },

    /// `-bpc`: count messages in the mail queue.
    CountQueue,

    /// `-M*`: perform an action on specific message IDs.
    MessageAction {
        action: MessageAction,
        message_ids: Vec<String>,
    },

    /// `-bv` / `-bvs`: verify addresses (optionally as sender).
    AddressVerify { as_sender: bool },

    /// `-bt`: address testing mode.
    AddressTest,

    /// `-be` / `-bem`: expansion test mode (optionally loading a message file).
    ExpansionTest {
        message_file: Option<String>,
        message_load: Option<String>,
    },

    /// `-bf` / `-bF`: filter test mode.
    FilterTest {
        filter_type: FilterType,
        file: String,
    },

    /// `-bP` / `-bP config`: configuration check / option listing.
    ConfigCheck {
        options: Vec<String>,
        show_config: bool,
    },

    /// `-bV`: print version and support details.
    Version,

    /// `-bI:<type>`: print information (help, modules, sieve, dscp).
    Info { info_type: InfoType },

    /// `-brt`: test retry configuration.
    RetryTest { args: Vec<String> },

    /// `-brw`: test rewrite configuration.
    RewriteTest { args: Vec<String> },

    /// `-bs` / `-bS`: SMTP input on stdin (interactive or batched).
    SmtpInput { batched: bool },

    /// `-bh <host>`: host checking / SMTP simulation.
    HostCheck { host: String },

    /// Default mode: accept and deliver a message from stdin.
    ReceiveMessage,

    /// `-bmalware <file>`: malware test mode.
    MalwareTest { file: String },

    /// `-bi` / symlink `newaliases`: initialize aliases (sendmail compat).
    NewAliases,

    /// `-bw`: inetd wait mode — accept a listening socket on stdin.
    InetdWait,
}

/// Queue-run configuration for a single `-q*` flag occurrence.
#[derive(Debug, Clone, PartialEq)]
pub struct QueueRunConfig {
    /// Named queue (from `-qG<name>`). `None` for the default queue.
    pub name: Option<String>,

    /// Repeat interval. `None` means a single one-shot queue run.
    pub interval: Option<Duration>,

    /// `-qq`: two-stage queue run (routing first, then delivery).
    pub two_stage: bool,

    /// `-qi`: first (initial) delivery only.
    pub first_delivery: bool,

    /// `-qf`: force delivery, ignoring retry times.
    pub force: bool,

    /// `-qff`: force delivery AND thaw frozen messages.
    pub force_thaw: bool,

    /// `-ql`: local deliveries only.
    pub local_only: bool,

    /// First message ID in a range for the queue run.
    pub start_id: Option<String>,

    /// Last message ID in a range for the queue run.
    pub stop_id: Option<String>,
}

/// Queue listing display options for `-bp*` variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueListOption {
    /// `-bp`: basic queue listing.
    Basic,
    /// `-bpr`: unsorted (random order) queue listing.
    Unsorted,
    /// `-bpu`: show only undelivered messages.
    UndeliveredOnly,
    /// `-bpa`: include all addresses (even already-delivered generated ones).
    PlusGenerated,
    /// `-bpi`: message IDs only.
    MsgidOnly,
}

/// Message manipulation actions for the `-M*` family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageAction {
    /// `-M`: force delivery (thaw + ignore retry times).
    Deliver,
    /// `-Mc`: deliver respecting retry times (cutthrough).
    DeliverCutthrough,
    /// `-Mf`: freeze message(s).
    Freeze,
    /// `-Mt`: thaw frozen message(s).
    Thaw,
    /// `-Mrm`: remove message(s) from the queue.
    Remove,
    /// `-Mg`: give up on message(s) — generate bounce.
    GiveUp,
    /// `-Mmd <msgid> <addr>`: mark a specific address as delivered.
    MarkDelivered,
    /// `-Mmad`: mark ALL addresses delivered.
    MarkAllDelivered,
    /// `-Mes <msgid> <addr>`: edit the envelope sender.
    EditSender,
    /// `-Mar <msgid> <addr>...`: add recipient(s).
    AddRecipient,
    /// `-MG <msgid> <queue>`: move message to a different named queue.
    SetQueue,
    /// `-Mset <msgid>`: load a message for use with `-be`.
    LoadForExpansion,
    /// `-Mvb <msgid>`: show the message body.
    ShowBody,
    /// `-Mvc <msgid>`: show a copy of the whole message (RFC 2822).
    ShowCopy,
    /// `-Mvh <msgid>`: show the message header spool file.
    ShowHeader,
    /// `-Mvl <msgid>`: show the message log.
    ShowLog,
}

/// Filter test type for `-bf` (user) and `-bF` (system).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterType {
    /// `-bF`: system filter test.
    System,
    /// `-bf`: user filter test.
    User,
}

/// Information type for `-bI:<type>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfoType {
    /// `-bI:help` or `-bI:` with no type.
    Help,
    /// `-bI:modules`.
    Modules,
    /// `-bI:sieve`.
    Sieve,
    /// `-bI:dscp`.
    Dscp,
}

/// Delivery mode selected by `-od*` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryMode {
    /// `-odb`: deliver in background (asynchronous).
    Background,
    /// `-odf`: deliver in foreground (synchronous).
    Foreground,
    /// `-odi`: deliver interactively (synchronous, wait for child).
    Interactive,
    /// `-odq`: queue only, no immediate delivery.
    QueueOnly,
    /// `-odqs`: queue SMTP-delivered messages only.
    QueueSmtp,
}

// ---------------------------------------------------------------------------
// Main CLI state struct
// ---------------------------------------------------------------------------

/// Parsed command-line state. Populated by `parse_args()` from the raw
/// `std::env::args_os()` argument vector. Fields correspond to the global
/// variables and flags set during C Exim's argument processing loop.
#[derive(Debug, Clone)]
pub struct EximCli {
    /// `-C <file>`: alternate configuration file path.
    pub config_file: Option<PathBuf>,

    /// `-D <NAME>=<VALUE>`: macro definitions passed on the command line.
    pub macro_defs: Vec<(String, String)>,

    /// `-d[<selector>]`: debug selector string (e.g., `"+all"`, `"exec"`).
    /// `Some("")` means default debug; `None` means no debugging.
    pub debug_selector: Option<String>,

    /// `-dd`: debug the daemon process only (not child processes).
    pub debug_daemon_only: bool,

    /// `-v`: verbose mode (equivalent to `-d+v`).
    pub verbose: bool,

    /// `-f <addr>` or `-r <addr>`: envelope sender address.
    pub sender_address: Option<String>,

    /// `-F <name>`: sender's full (display) name.
    pub sender_fullname: Option<String>,

    /// `-i` / `-oi` / `-oitrue`: if `true`, a single dot does NOT end the
    /// message in non-SMTP mode. Default is `true` (dot ends message).
    pub dot_ends: bool,

    /// `-N`: don't actually deliver (dry-run / debugging flag).
    pub dont_deliver: bool,

    /// `-n`: no alias expansion (sendmail flag, affects certain behaviors).
    pub no_alias_expansion: bool,

    /// `-t` / `-ti`: extract recipients from message headers.
    pub extract_recipients: bool,

    /// `-G`: MUA submission flag (sendmail compat — suppress local fixups).
    pub mua_submission: bool,

    /// `-X <file>`: log SMTP conversation to a file.
    pub smtp_log_file: Option<PathBuf>,

    /// Positional arguments after all flags — recipient addresses.
    pub recipients: Vec<String>,

    /// `true` when the command expects a message on stdin (default mode, -bm,
    /// -bs, -bS). Set to `false` by most -b* modes.
    pub receiving_message: bool,

    /// Delivery mode from `-od*` flags.
    pub delivery_mode: Option<DeliveryMode>,

    /// `-odq` sets this. Queue-only flag for message submission.
    pub queue_only: bool,

    /// `-odqs` sets this. Queue SMTP-routed messages only.
    pub queue_smtp: bool,

    /// The primary `-b*` mode token (used internally to determine `EximMode`).
    pub b_mode: Option<BMode>,

    /// Accumulated queue-runner configurations from one or more `-q*` flags.
    pub q_runners: Vec<QueueRunConfig>,

    /// Message action from `-M*` flags.
    pub message_action: Option<MessageAction>,

    /// Extra argument for message actions that take one (e.g., sender address
    /// for `-Mes`, queue name for `-MG`).
    pub msg_action_arg: Option<String>,

    /// `-R <domain>` or `-Rf <domain>`: selective queue run by domain.
    pub selective_domain: Option<String>,

    /// `-S <sender>` or `-Sf <sender>`: selective queue run by sender.
    pub selective_sender: Option<String>,

    /// `-oMa <addr>`: override sender host address (testing).
    pub sender_host_address: Option<String>,

    /// `-oMs <hostname>`: override sender host name (testing).
    pub sender_host_name: Option<String>,

    /// `-oMi <interface>`: override incoming interface (testing).
    pub incoming_interface: Option<String>,

    /// `-oMr <protocol>`: override received protocol (testing).
    pub received_protocol: Option<String>,

    /// `-oMt <ident>`: override sender ident (testing).
    pub sender_ident: Option<String>,

    /// `-oMaa <name>`: override sender_host_authenticated (testing).
    pub sender_host_authenticated: Option<String>,

    /// `-oMai <id>`: override authenticated_id (testing).
    pub authenticated_id: Option<String>,

    /// `-oMas <sender>`: override authenticated_sender (testing).
    pub authenticated_sender: Option<String>,

    /// `-oMm <id>`: override message reference (testing).
    pub message_reference: Option<String>,

    /// `-ps` / `-pd`: Perl startup option. `1` = force start, `-1` = delay.
    pub perl_start_option: i32,

    /// `-n`: the raw flag_n from sendmail compatibility.
    pub flag_n: bool,

    // -- Internal parsing state not in the public schema but needed --------
    /// Whether `-R` / `-S` forced delivery.
    pub selective_force: bool,

    /// Whether `-R` / `-S` forced thaw.
    pub selective_force_thaw: bool,

    /// Whether the `-q*` prefix included `-qq` (two-stage) for `-R`/`-S`.
    pub selective_two_stage: bool,

    /// `-bnq`: disallow unqualified addresses.
    pub no_qualify: bool,

    /// Filter test sub-options: -bfd, -bfl, -bfp, -bfs.
    pub filter_test_domain: Option<String>,
    pub filter_test_localpart: Option<String>,
    pub filter_test_prefix: Option<String>,
    pub filter_test_suffix: Option<String>,

    /// `-bh` / `-bhc` host for host-check mode.
    pub host_check_host: Option<String>,
    /// Whether `-bhc` (with callout) was used.
    pub host_checking_callout: bool,

    /// Arguments collected after `-brt`.
    pub retry_test_args: Vec<String>,
    /// Arguments collected after `-brw`.
    pub rewrite_test_args: Vec<String>,

    /// `-bP config` full-config flag.
    pub list_config: bool,
    /// `-bP` list-options flag.
    pub list_options: bool,

    /// Malware test file from `-bmalware <file>`.
    pub malware_test_file: Option<String>,

    /// `-bw` inetd-wait timeout parsed from `-bw<time>`.
    pub inetd_wait_timeout: Option<Duration>,

    /// Symlink-based invocation name that was detected.
    pub called_as: Option<String>,

    /// `-oX <list>`: override local interfaces for daemon socket binding.
    /// Contains the raw interface specification string from the CLI, which
    /// is parsed by the daemon module's `bind_listening_sockets()`.
    /// When set, overrides the `local_interfaces` config option.
    pub override_local_interfaces: Option<String>,
}

// ---------------------------------------------------------------------------
// Internal -b* mode token (intermediate parsing artifact)
// ---------------------------------------------------------------------------

/// Intermediate representation of the `-b*` flag before full mode resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BMode {
    Daemon { foreground: bool },
    ExpansionTest { message_file: Option<String> },
    FilterTestSystem { file: String },
    FilterTestUser { file: String },
    HostCheck { host: String, callout: bool },
    NewAliases,
    InfoMode { info_type: InfoType },
    ReceiveMessage,
    MalwareTest { file: String },
    NoQualify,
    ListQueue { option: QueueListOption },
    CountQueue,
    ConfigCheck { show_config: bool },
    RetryTest,
    RewriteTest,
    BatchedSmtp,
    InteractiveSmtp,
    AddressTest,
    AddressVerify { as_sender: bool },
    Version,
    InetdWait { timeout: Option<Duration> },
}

// ---------------------------------------------------------------------------
// Public API functions
// ---------------------------------------------------------------------------

/// Parse command-line arguments from `std::env::args_os()` and return the
/// populated `EximCli` struct. This is the primary entry point called from
/// `main.rs`.
///
/// # Errors
/// Calls `std::process::exit(1)` with an error message to stderr if the
/// arguments are malformed — matching the C Exim behavior of `exim_fail()`.
pub fn parse_args() -> EximCli {
    let args: Vec<String> = env::args().collect();
    parse_args_from(&args)
}

/// Parse from an explicit argument vector (useful for testing).
/// `args[0]` is expected to be the program name / path.
pub fn parse_args_from(args: &[String]) -> EximCli {
    let mut cli = EximCli::default();

    // Detect symlink-based invocation from argv[0].
    if let Some(invocation) = detect_symlink_invocation_from(&args[0]) {
        apply_symlink_defaults(&mut cli, &invocation);
        cli.called_as = Some(invocation);
    }

    let argc = args.len();
    let mut i = 1; // skip argv[0]

    while i < argc {
        let arg = &args[i];

        // Non-flag arguments mark the start of recipient list.
        if !arg.starts_with('-') {
            cli.recipients = args[i..].to_vec();
            break;
        }

        // `--` terminates options.
        if arg == "--" {
            if i + 1 < argc {
                cli.recipients = args[i + 1..].to_vec();
            }
            break;
        }

        // `--help` and `--version` long-form aliases.
        if arg == "--help" {
            print_usage();
            std::process::exit(0);
        }
        if arg == "--version" {
            cli.b_mode = Some(BMode::Version);
            i += 1;
            continue;
        }

        // The second character (after '-') drives the top-level switch.
        if arg.len() < 2 {
            fail_bad_option(arg);
        }

        let bytes = arg.as_bytes();
        let mut switch_char = bytes[1] as char;
        let mut rest: &str = &arg[2..];

        // Normalize aliases:
        // -oe* → -e* (sendmail error option without leading -o)
        // -qR* → -R*, -qS* → -S*, -qqR* → -R* (with two_stage), -qqS* → -S*
        // -r → -f
        // -ov → -v
        if arg.len() > 2 {
            if rest.starts_with('e') && switch_char == 'o' {
                // -oe<x> → treat as -e<x>
                switch_char = bytes[2] as char;
                rest = &arg[3..];
            } else if switch_char == 'q' && rest.starts_with('R') {
                switch_char = 'R';
                rest = &arg[3..];
            } else if switch_char == 'q' && rest.starts_with('S') {
                switch_char = 'S';
                rest = &arg[3..];
            } else if switch_char == 'q' && rest.len() >= 2 && rest.starts_with("qR") {
                switch_char = 'R';
                rest = &arg[4..];
                cli.selective_two_stage = true;
            } else if switch_char == 'q' && rest.len() >= 2 && rest.starts_with("qS") {
                switch_char = 'S';
                rest = &arg[4..];
                cli.selective_two_stage = true;
            }
        }
        if switch_char == 'r' && rest.is_empty() {
            // -r is synonym for -f; will be handled below via switch_char = 'f'.
            switch_char = 'f';
        } else if switch_char == 'r' {
            // -r<addr> synonym for -f<addr>
            switch_char = 'f';
        }
        if arg == "-ov" {
            switch_char = 'v';
            rest = "";
        }

        match switch_char {
            // ---------------------------------------------------------------
            // -A*: sendmail -Ac / -Am — ignored.
            // ---------------------------------------------------------------
            'A' => {
                if rest.is_empty() {
                    fail_bad_option(arg);
                }
                match rest {
                    "c" | "m" => { /* ignored */ }
                    _ => fail_bad_option(arg),
                }
            }

            // ---------------------------------------------------------------
            // -B*: sendmail 7/8-bit type — ignored (Exim is 8-bit clean).
            // ---------------------------------------------------------------
            'B' => {
                if rest.is_empty() {
                    // skip the next argument (the type)
                    i += 1;
                }
            }

            // ---------------------------------------------------------------
            // -b*: Mode selection — the largest family.
            // ---------------------------------------------------------------
            'b' => {
                cli.receiving_message = false;
                i = parse_b_mode(&mut cli, args, i, rest);
            }

            // ---------------------------------------------------------------
            // -C <file>: alternate configuration file.
            // ---------------------------------------------------------------
            'C' => {
                let value = if rest.is_empty() {
                    i += 1;
                    require_next_arg(args, i, "-C")
                } else {
                    rest.to_string()
                };
                cli.config_file = Some(PathBuf::from(value));
            }

            // ---------------------------------------------------------------
            // -D <NAME>=<VALUE>: macro definition.
            // ---------------------------------------------------------------
            'D' => {
                let raw = if rest.is_empty() {
                    i += 1;
                    require_next_arg(args, i, "-D")
                } else {
                    rest.to_string()
                };
                let (name, value) = parse_macro_def(&raw);
                cli.macro_defs.push((name, value));
            }

            // ---------------------------------------------------------------
            // -d*: debugging flags.
            // ---------------------------------------------------------------
            'd' => {
                if rest == "d" {
                    // -dd: debug daemon only
                    cli.debug_daemon_only = true;
                    cli.debug_selector = Some(String::new());
                } else if let Some(stripped) = rest.strip_prefix('d') {
                    // -dd<selector>
                    cli.debug_daemon_only = true;
                    cli.debug_selector = Some(stripped.to_string());
                } else {
                    // -d or -d<selector>
                    cli.debug_selector = Some(rest.to_string());
                }
            }

            // ---------------------------------------------------------------
            // -E*: local error message (internal).
            // ---------------------------------------------------------------
            'E' => {
                // Accepted and ignored at the CLI parsing level.
            }

            // ---------------------------------------------------------------
            // -e*: sendmail error handling (also reachable via -oe* alias).
            // ---------------------------------------------------------------
            'e' => {
                // Accepted: -ee, -em, -ep, -eq, -ew (mapped from -oee etc.)
                match rest {
                    "e" | "m" | "p" | "q" | "w" => { /* recorded but not stored in EximCli */ }
                    _ => fail_bad_option(arg),
                }
            }

            // ---------------------------------------------------------------
            // -F <name>: sender full name.
            // ---------------------------------------------------------------
            'F' => {
                let value = if rest.is_empty() {
                    i += 1;
                    require_next_arg(args, i, "-F")
                } else {
                    rest.to_string()
                };
                cli.sender_fullname = Some(value);
            }

            // ---------------------------------------------------------------
            // -f <addr>: set envelope sender (also -r via alias above).
            // ---------------------------------------------------------------
            'f' => {
                let value = if rest.is_empty() {
                    i += 1;
                    require_next_arg(args, i, "-f")
                } else {
                    rest.to_string()
                };
                cli.sender_address = Some(value);
            }

            // ---------------------------------------------------------------
            // -G: MUA submission flag (sendmail compat).
            // ---------------------------------------------------------------
            'G' => {
                if !rest.is_empty() {
                    fail_bad_option(arg);
                }
                cli.mua_submission = true;
            }

            // ---------------------------------------------------------------
            // -h <n>: hop count — accepted but not used by Exim.
            // ---------------------------------------------------------------
            'h' => {
                if rest.is_empty() {
                    i += 1; // skip the numeric argument
                    if i >= argc {
                        fail_bad_option(arg);
                    }
                }
            }

            // ---------------------------------------------------------------
            // -i: don't treat dot as message terminator.
            // ---------------------------------------------------------------
            'i' => {
                if !rest.is_empty() {
                    fail_bad_option(arg);
                }
                cli.dot_ends = false;
            }

            // ---------------------------------------------------------------
            // -L <name>: syslog process name — accepted, stored elsewhere.
            // ---------------------------------------------------------------
            'L' => {
                if rest.is_empty() {
                    i += 1;
                    if i >= argc {
                        fail_bad_option(arg);
                    }
                }
                // Stored by the caller during context setup, not in EximCli.
            }

            // ---------------------------------------------------------------
            // -M*: message actions.
            // ---------------------------------------------------------------
            'M' => {
                cli.receiving_message = false;
                i = parse_m_action(&mut cli, args, i, rest);
            }

            // ---------------------------------------------------------------
            // -m: sendmail "me too" — accepted, no-op.
            // ---------------------------------------------------------------
            'm' => {
                if !rest.is_empty() {
                    fail_bad_option(arg);
                }
            }

            // ---------------------------------------------------------------
            // -N: don't deliver (dry run / debug).
            // ---------------------------------------------------------------
            'N' => {
                if !rest.is_empty() {
                    fail_bad_option(arg);
                }
                cli.dont_deliver = true;
                cli.verbose = true;
            }

            // ---------------------------------------------------------------
            // -n: no alias expansion.
            // ---------------------------------------------------------------
            'n' => {
                cli.no_alias_expansion = true;
                cli.flag_n = true;
            }

            // ---------------------------------------------------------------
            // -O*: sendmail long option — ignored.
            // ---------------------------------------------------------------
            'O' => {
                if rest.is_empty() {
                    i += 1;
                    if i >= argc {
                        eprintln!("exim: string expected after -O");
                        std::process::exit(1);
                    }
                }
            }

            // ---------------------------------------------------------------
            // -o*: sendmail compatibility options.
            // ---------------------------------------------------------------
            'o' => {
                i = parse_o_options(&mut cli, args, i, rest);
            }

            // ---------------------------------------------------------------
            // -p*: Perl startup or sendmail protocol.
            // ---------------------------------------------------------------
            'p' => {
                if rest == "s" {
                    cli.perl_start_option = 1;
                } else if rest == "d" {
                    cli.perl_start_option = -1;
                } else {
                    // Sendmail -p<protocol>:<host> — accepted, stored as
                    // received_protocol / sender_host_name by the caller.
                    let val = if rest.is_empty() {
                        i += 1;
                        require_next_arg(args, i, "-p")
                    } else {
                        rest.to_string()
                    };
                    if let Some(colon_pos) = val.find(':') {
                        cli.received_protocol = Some(val[..colon_pos].to_string());
                        cli.sender_host_name = Some(val[colon_pos + 1..].to_string());
                    } else {
                        cli.received_protocol = Some(val);
                    }
                }
            }

            // ---------------------------------------------------------------
            // -q*: queue running.
            // ---------------------------------------------------------------
            'q' => {
                cli.receiving_message = false;
                i = parse_q_options(&mut cli, args, i, rest);
            }

            // ---------------------------------------------------------------
            // -R*: selective queue run by domain (synonym for -qR).
            // ---------------------------------------------------------------
            'R' => {
                cli.receiving_message = false;
                i = parse_selective_run(&mut cli, args, i, rest, true);
            }

            // ---------------------------------------------------------------
            // -S*: selective queue run by sender (synonym for -qS).
            // ---------------------------------------------------------------
            'S' => {
                cli.receiving_message = false;
                i = parse_selective_run(&mut cli, args, i, rest, false);
            }

            // ---------------------------------------------------------------
            // -t / -ti: extract recipients from headers.
            // ---------------------------------------------------------------
            't' => {
                if rest.is_empty() {
                    cli.extract_recipients = true;
                } else if rest == "i" {
                    cli.extract_recipients = true;
                    cli.dot_ends = false;
                } else if rest == "ls-on-connect" {
                    // -tls-on-connect: accepted (stored by caller).
                } else {
                    fail_bad_option(arg);
                }
            }

            // ---------------------------------------------------------------
            // -T*: test harness option — accepted for compat.
            // ---------------------------------------------------------------
            'T' => {
                // Accepted; test harness checks happen at a higher level.
            }

            // ---------------------------------------------------------------
            // -U: sendmail "initial user submission" — ignored.
            // ---------------------------------------------------------------
            'U' => { /* no-op */ }

            // ---------------------------------------------------------------
            // -v: verbose mode (equivalent to -d+v).
            // ---------------------------------------------------------------
            'v' => {
                if !rest.is_empty() {
                    fail_bad_option(arg);
                }
                cli.verbose = true;
                if cli.debug_selector.is_none() {
                    cli.debug_selector = Some("+v".to_string());
                }
            }

            // ---------------------------------------------------------------
            // -x: AIX NLS flag — ignored (Exim is 8-bit clean).
            // ---------------------------------------------------------------
            'x' => {
                if !rest.is_empty() {
                    fail_bad_option(arg);
                }
            }

            // ---------------------------------------------------------------
            // -X <file>: log SMTP conversation.
            // ---------------------------------------------------------------
            'X' => {
                let value = if rest.is_empty() {
                    i += 1;
                    require_next_arg(args, i, "-X")
                } else {
                    rest.to_string()
                };
                cli.smtp_log_file = Some(PathBuf::from(value));
            }

            // ---------------------------------------------------------------
            // -z <text>: one-line log text — accepted.
            // ---------------------------------------------------------------
            'z' => {
                if rest.is_empty() {
                    i += 1;
                    if i >= argc {
                        eprintln!("exim: string expected after -z");
                        std::process::exit(1);
                    }
                }
            }

            // ---------------------------------------------------------------
            // -a*: ATRN mode — accepted.
            // ---------------------------------------------------------------
            'a' => {
                // -atrn <host> <domains>: accepted for ATRN support.
                if rest != "trn" {
                    fail_bad_option(arg);
                }
                // Consume host and domains arguments (handled at a higher level).
                i += 2;
                if i >= argc {
                    eprintln!("exim: host and domainlist expected after -atrn");
                    std::process::exit(1);
                }
            }

            _ => fail_bad_option(arg),
        }

        i += 1;
    }

    // If -R or -S was specified without a preceding -q, create a one-time
    // queue runner (matching C behavior).
    if (cli.selective_domain.is_some() || cli.selective_sender.is_some())
        && cli.q_runners.is_empty()
    {
        cli.q_runners.push(QueueRunConfig {
            name: None,
            interval: None,
            two_stage: cli.selective_two_stage,
            first_delivery: false,
            force: cli.selective_force,
            force_thaw: cli.selective_force_thaw,
            local_only: false,
            start_id: None,
            stop_id: None,
        });
    }

    cli
}

/// Resolve the operational mode from the parsed CLI state. Must be called
/// after `parse_args()`. The returned `EximMode` drives the top-level
/// dispatch in `main.rs`.
pub fn determine_mode(cli: &EximCli) -> EximMode {
    // Priority 1: explicit -b* mode
    if let Some(ref bm) = cli.b_mode {
        match bm {
            BMode::Daemon { foreground } => {
                return EximMode::Daemon {
                    foreground: *foreground,
                };
            }
            BMode::ExpansionTest { message_file } => {
                // If -Mset was used, message_load contains the message ID
                let message_load = cli.message_action.as_ref().and_then(|a| {
                    if *a == MessageAction::LoadForExpansion {
                        cli.msg_action_arg.clone()
                    } else {
                        None
                    }
                });
                return EximMode::ExpansionTest {
                    message_file: message_file.clone(),
                    message_load,
                };
            }
            BMode::FilterTestSystem { file } => {
                return EximMode::FilterTest {
                    filter_type: FilterType::System,
                    file: file.clone(),
                };
            }
            BMode::FilterTestUser { file } => {
                return EximMode::FilterTest {
                    filter_type: FilterType::User,
                    file: file.clone(),
                };
            }
            BMode::HostCheck { host, .. } => {
                return EximMode::HostCheck { host: host.clone() };
            }
            BMode::NewAliases => return EximMode::NewAliases,
            BMode::InfoMode { info_type } => {
                return EximMode::Info {
                    info_type: *info_type,
                };
            }
            BMode::ReceiveMessage => { /* fall through to default */ }
            BMode::MalwareTest { file } => {
                return EximMode::MalwareTest { file: file.clone() };
            }
            BMode::NoQualify => { /* flag only, fall through */ }
            BMode::ListQueue { option } => {
                return EximMode::ListQueue { option: *option };
            }
            BMode::CountQueue => return EximMode::CountQueue,
            BMode::ConfigCheck { show_config } => {
                // Positional arguments after -bP are config option names to print.
                // They end up in cli.recipients because they are non-flag arguments.
                return EximMode::ConfigCheck {
                    options: cli.recipients.clone(),
                    show_config: *show_config,
                };
            }
            BMode::RetryTest => {
                return EximMode::RetryTest {
                    args: cli.retry_test_args.clone(),
                };
            }
            BMode::RewriteTest => {
                return EximMode::RewriteTest {
                    args: cli.rewrite_test_args.clone(),
                };
            }
            BMode::BatchedSmtp => return EximMode::SmtpInput { batched: true },
            BMode::InteractiveSmtp => {
                return EximMode::SmtpInput { batched: false };
            }
            BMode::AddressTest => return EximMode::AddressTest,
            BMode::AddressVerify { as_sender } => {
                return EximMode::AddressVerify {
                    as_sender: *as_sender,
                };
            }
            BMode::Version => return EximMode::Version,
            BMode::InetdWait { .. } => return EximMode::InetdWait,
        }
    }

    // Priority 2: message action (-M*)
    if let Some(ref action) = cli.message_action {
        // Collect message IDs from recipients (they are positional after -M*).
        return EximMode::MessageAction {
            action: action.clone(),
            message_ids: cli.recipients.clone(),
        };
    }

    // Priority 3: queue runners (-q*)
    if !cli.q_runners.is_empty() {
        // If selective domain/sender was set, it's still a queue run.
        return EximMode::QueueRun {
            runners: cli.q_runners.clone(),
        };
    }

    // Default: receive a message.
    EximMode::ReceiveMessage
}

/// Parse a time interval string in Exim format. Supported suffixes:
/// `s` (seconds), `m` (minutes), `h` (hours), `d` (days), `w` (weeks).
/// Multiple units can be combined: `1h30m`. A bare number is treated as
/// seconds.
///
/// Returns `None` if the string is empty or cannot be parsed.
///
/// # Examples
/// ```
/// use exim_core::cli::parse_time_interval;
/// assert_eq!(parse_time_interval("30s"), Some(std::time::Duration::from_secs(30)));
/// assert_eq!(parse_time_interval("5m"), Some(std::time::Duration::from_secs(300)));
/// assert_eq!(parse_time_interval("1h30m"), Some(std::time::Duration::from_secs(5400)));
/// assert_eq!(parse_time_interval("1d"), Some(std::time::Duration::from_secs(86400)));
/// assert_eq!(parse_time_interval("1w"), Some(std::time::Duration::from_secs(604800)));
/// assert_eq!(parse_time_interval("120"), Some(std::time::Duration::from_secs(120)));
/// ```
pub fn parse_time_interval(s: &str) -> Option<Duration> {
    if s.is_empty() {
        return None;
    }

    let mut total_secs: u64 = 0;
    let mut current_num: u64 = 0;
    let mut has_digits = false;
    let mut has_any_unit = false;

    for ch in s.chars() {
        match ch {
            '0'..='9' => {
                current_num = current_num
                    .checked_mul(10)?
                    .checked_add(ch as u64 - '0' as u64)?;
                has_digits = true;
            }
            's' => {
                if !has_digits {
                    return None;
                }
                total_secs = total_secs.checked_add(current_num)?;
                current_num = 0;
                has_digits = false;
                has_any_unit = true;
            }
            'm' => {
                if !has_digits {
                    return None;
                }
                total_secs = total_secs.checked_add(current_num.checked_mul(60)?)?;
                current_num = 0;
                has_digits = false;
                has_any_unit = true;
            }
            'h' => {
                if !has_digits {
                    return None;
                }
                total_secs = total_secs.checked_add(current_num.checked_mul(3600)?)?;
                current_num = 0;
                has_digits = false;
                has_any_unit = true;
            }
            'd' => {
                if !has_digits {
                    return None;
                }
                total_secs = total_secs.checked_add(current_num.checked_mul(86400)?)?;
                current_num = 0;
                has_digits = false;
                has_any_unit = true;
            }
            'w' => {
                if !has_digits {
                    return None;
                }
                total_secs = total_secs.checked_add(current_num.checked_mul(604800)?)?;
                current_num = 0;
                has_digits = false;
                has_any_unit = true;
            }
            _ => return None,
        }
    }

    // Trailing bare number: treat as seconds if no unit was given,
    // otherwise treat as seconds too (Exim convention).
    if has_digits {
        total_secs = total_secs.checked_add(current_num)?;
    } else if !has_any_unit {
        return None;
    }

    if total_secs == 0 && !has_any_unit && !has_digits {
        return None;
    }

    Some(Duration::from_secs(total_secs))
}

/// Detect if Exim was invoked through a well-known symlink name.
/// Checks `argv[0]` (and `std::env::current_exe()` as fallback) against the
/// five canonical symlink names:
///
/// - `mailq`      → equivalent to `exim -bp`
/// - `rmail`      → equivalent to `exim -i -oee`
/// - `rsmtp`      → equivalent to `exim -bS`
/// - `runq`       → equivalent to `exim -q`
/// - `newaliases` → equivalent to `exim -bi`
///
/// Returns the symlink name if detected, or `None`.
pub fn detect_symlink_invocation() -> Option<String> {
    let args: Vec<OsString> = env::args_os().collect();
    if args.is_empty() {
        return None;
    }
    detect_symlink_invocation_from(&args[0].to_string_lossy())
}

// ---------------------------------------------------------------------------
// Default implementation for EximCli
// ---------------------------------------------------------------------------

impl Default for EximCli {
    fn default() -> Self {
        Self {
            config_file: None,
            macro_defs: Vec::new(),
            debug_selector: None,
            debug_daemon_only: false,
            verbose: false,
            sender_address: None,
            sender_fullname: None,
            dot_ends: true,
            dont_deliver: false,
            no_alias_expansion: false,
            extract_recipients: false,
            mua_submission: false,
            smtp_log_file: None,
            recipients: Vec::new(),
            receiving_message: true,
            delivery_mode: None,
            queue_only: false,
            queue_smtp: false,
            b_mode: None,
            q_runners: Vec::new(),
            message_action: None,
            msg_action_arg: None,
            selective_domain: None,
            selective_sender: None,
            sender_host_address: None,
            sender_host_name: None,
            incoming_interface: None,
            received_protocol: None,
            sender_ident: None,
            sender_host_authenticated: None,
            authenticated_id: None,
            authenticated_sender: None,
            message_reference: None,
            perl_start_option: 0,
            flag_n: false,
            selective_force: false,
            selective_force_thaw: false,
            selective_two_stage: false,
            no_qualify: false,
            filter_test_domain: None,
            filter_test_localpart: None,
            filter_test_prefix: None,
            filter_test_suffix: None,
            host_check_host: None,
            host_checking_callout: false,
            retry_test_args: Vec::new(),
            rewrite_test_args: Vec::new(),
            list_config: false,
            list_options: false,
            malware_test_file: None,
            inetd_wait_timeout: None,
            called_as: None,
            override_local_interfaces: None,
        }
    }
}

// ===========================================================================
// Internal helper functions
// ===========================================================================

/// Print a minimal usage/help message and return. Matches the C Exim behavior
/// of printing a brief summary on `--help`.
fn print_usage() {
    eprintln!("Exim is a Mail Transfer Agent. It is normally called by Mail");
    eprintln!("User Agents, not directly from a shell command line. Options:");
    eprintln!("  -bd        start daemon");
    eprintln!("  -bdf       start daemon in foreground");
    eprintln!("  -be        expansion test");
    eprintln!("  -bf <file> user filter test");
    eprintln!("  -bF <file> system filter test");
    eprintln!("  -bh <host> host checking");
    eprintln!("  -bp        list queue");
    eprintln!("  -bP        list configuration");
    eprintln!("  -bs        SMTP on stdin");
    eprintln!("  -bS        batched SMTP on stdin");
    eprintln!("  -bt        address testing");
    eprintln!("  -bV        version");
    eprintln!("  -bv        verify addresses");
    eprintln!("  -C <file>  configuration file");
    eprintln!("  -d[flags]  debugging");
    eprintln!("  -f <addr>  envelope sender");
    eprintln!("  -M*        message actions");
    eprintln!("  -N         don't deliver");
    eprintln!("  -q[opts]   queue run");
    eprintln!("  -t         extract recipients from headers");
    eprintln!("  -v         verbose");
}

/// Abort with an error message for a bad CLI option.
fn fail_bad_option(opt: &str) -> ! {
    eprintln!("exim: unknown, malformed, or incomplete option {}", opt);
    std::process::exit(1);
}

/// Validate an Exim message ID format: `XXXXXX-YYYYYY-XX`
/// 6 base-62 chars, hyphen, 6 base-62 chars, hyphen, 2 base-62 chars.
fn is_valid_message_id(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 16 {
        return false;
    }
    if bytes[6] != b'-' || bytes[13] != b'-' {
        return false;
    }
    let is_base62 = |b: u8| b.is_ascii_alphanumeric();
    for &i in &[0, 1, 2, 3, 4, 5] {
        if !is_base62(bytes[i]) {
            return false;
        }
    }
    for &i in &[7, 8, 9, 10, 11, 12] {
        if !is_base62(bytes[i]) {
            return false;
        }
    }
    for &i in &[14, 15] {
        if !is_base62(bytes[i]) {
            return false;
        }
    }
    true
}

/// Require the next argument to exist, or exit with an error.
fn require_next_arg(args: &[String], idx: usize, flag: &str) -> String {
    if idx < args.len() {
        args[idx].clone()
    } else {
        eprintln!("exim: argument expected after {}", flag);
        std::process::exit(1);
    }
}

/// Parse a macro definition string: `NAME=VALUE` or just `NAME` (value defaults
/// to empty). Macro names must start with an uppercase letter and contain only
/// alphanumeric characters and underscores.
fn parse_macro_def(raw: &str) -> (String, String) {
    let trimmed = raw.trim_start();
    if trimmed.is_empty() {
        eprintln!("exim: empty macro name in -D option");
        std::process::exit(1);
    }

    let first_char = trimmed.chars().next().unwrap();
    if !first_char.is_ascii_uppercase() {
        eprintln!("exim: macro name set by -D must start with an upper case letter");
        std::process::exit(1);
    }

    let name_end = trimmed
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .unwrap_or(trimmed.len());
    let name = &trimmed[..name_end];
    if name.is_empty() {
        eprintln!("exim: bad -D option");
        std::process::exit(1);
    }

    let remainder = trimmed[name_end..].trim_start();
    let value = if let Some(stripped) = remainder.strip_prefix('=') {
        stripped.trim_start().to_string()
    } else if remainder.is_empty() {
        String::new()
    } else {
        eprintln!("exim: bad -D option");
        std::process::exit(1);
    };

    (name.to_string(), value)
}

/// Parse `-b*` mode selection flags.
/// Returns the updated argument index `i`.
fn parse_b_mode(cli: &mut EximCli, args: &[String], mut i: usize, rest: &str) -> usize {
    if rest.is_empty() {
        fail_bad_option(&args[i]);
    }

    let sub = rest.as_bytes()[0] as char;
    let sub_rest: &str = &rest[1..];

    match sub {
        // -bd / -bdf
        'd' => {
            let foreground = if sub_rest == "f" {
                true
            } else if sub_rest.is_empty() {
                false
            } else {
                fail_bad_option(&args[i]);
            };
            cli.b_mode = Some(BMode::Daemon { foreground });
        }

        // -be / -bem <file>
        'e' => {
            if sub_rest.is_empty() {
                cli.b_mode = Some(BMode::ExpansionTest { message_file: None });
            } else if sub_rest == "m" {
                i += 1;
                let file = require_next_arg(args, i, "-bem");
                cli.b_mode = Some(BMode::ExpansionTest {
                    message_file: Some(file),
                });
            } else {
                fail_bad_option(&args[i]);
            }
        }

        // -bF <file>: system filter test
        'F' => {
            if !sub_rest.is_empty() {
                fail_bad_option(&args[i]);
            }
            i += 1;
            let file = require_next_arg(args, i, "-bF");
            cli.b_mode = Some(BMode::FilterTestSystem { file });
        }

        // -bf <file>: user filter test
        // -bfd, -bfl, -bfp, -bfs: filter test sub-options
        'f' => {
            if sub_rest.is_empty() {
                i += 1;
                let file = require_next_arg(args, i, "-bf");
                cli.b_mode = Some(BMode::FilterTestUser { file });
            } else {
                i += 1;
                let val = require_next_arg(args, i, &format!("-bf{}", sub_rest));
                match sub_rest {
                    "d" => cli.filter_test_domain = Some(val),
                    "l" => cli.filter_test_localpart = Some(val),
                    "p" => cli.filter_test_prefix = Some(val),
                    "s" => cli.filter_test_suffix = Some(val),
                    _ => fail_bad_option(&args[i - 1]),
                }
            }
        }

        // -bh <host> / -bhc <host>
        'h' => {
            let callout = sub_rest == "c";
            if !sub_rest.is_empty() && !callout {
                fail_bad_option(&args[i]);
            }
            i += 1;
            let host = require_next_arg(args, i, "-bh");
            cli.host_check_host = Some(host.clone());
            cli.host_checking_callout = callout;
            cli.b_mode = Some(BMode::HostCheck { host, callout });
        }

        // -bi: newaliases (sendmail compat)
        'i' => {
            if !sub_rest.is_empty() {
                fail_bad_option(&args[i]);
            }
            cli.b_mode = Some(BMode::NewAliases);
        }

        // -bI:<type>: information mode
        'I' => {
            if !sub_rest.starts_with(':') {
                fail_bad_option(&args[i]);
            }
            let info_str = &sub_rest[1..];
            let info_type = if info_str.is_empty() || info_str.eq_ignore_ascii_case("help") {
                InfoType::Help
            } else if info_str.eq_ignore_ascii_case("modules") {
                InfoType::Modules
            } else if info_str.eq_ignore_ascii_case("sieve") {
                InfoType::Sieve
            } else if info_str.eq_ignore_ascii_case("dscp") {
                InfoType::Dscp
            } else {
                fail_bad_option(&args[i]);
            };
            cli.b_mode = Some(BMode::InfoMode { info_type });
        }

        // -bm: accept and deliver message (default mode)
        // -bmalware <file>: malware test
        'm' => {
            if sub_rest.is_empty() {
                cli.receiving_message = true;
                cli.b_mode = Some(BMode::ReceiveMessage);
            } else if sub_rest == "alware" {
                i += 1;
                let file = require_next_arg(args, i, "-bmalware");
                cli.malware_test_file = Some(file.clone());
                cli.b_mode = Some(BMode::MalwareTest { file });
            } else {
                fail_bad_option(&args[i]);
            }
        }

        // -bnq: don't qualify unqualified addresses
        'n' => {
            if sub_rest != "q" {
                fail_bad_option(&args[i]);
            }
            cli.no_qualify = true;
            cli.b_mode = Some(BMode::NoQualify);
        }

        // -bp*: list queue variants
        'p' => {
            if sub_rest.is_empty() {
                cli.b_mode = Some(BMode::ListQueue {
                    option: QueueListOption::Basic,
                });
            } else if sub_rest == "c" {
                cli.b_mode = Some(BMode::CountQueue);
            } else if sub_rest == "r" {
                cli.b_mode = Some(BMode::ListQueue {
                    option: QueueListOption::Unsorted,
                });
            } else if sub_rest == "u" {
                cli.b_mode = Some(BMode::ListQueue {
                    option: QueueListOption::UndeliveredOnly,
                });
            } else if sub_rest == "ru" {
                // -bpru: random order, undelivered only
                cli.b_mode = Some(BMode::ListQueue {
                    option: QueueListOption::UndeliveredOnly,
                });
            } else if sub_rest == "a" {
                cli.b_mode = Some(BMode::ListQueue {
                    option: QueueListOption::PlusGenerated,
                });
            } else if sub_rest == "i" {
                cli.b_mode = Some(BMode::ListQueue {
                    option: QueueListOption::MsgidOnly,
                });
            } else {
                fail_bad_option(&args[i]);
            }
        }

        // -bP / -bP config
        'P' => {
            if !sub_rest.is_empty() {
                fail_bad_option(&args[i]);
            }
            // Check if next arg is "config"
            if i + 1 < args.len() && args[i + 1] == "config" {
                cli.list_config = true;
                cli.b_mode = Some(BMode::ConfigCheck { show_config: true });
                i += 1;
            } else {
                cli.list_options = true;
                cli.b_mode = Some(BMode::ConfigCheck { show_config: false });
            }
        }

        // -brt: retry test / -brw: rewrite test
        'r' => {
            if sub_rest == "t" {
                cli.b_mode = Some(BMode::RetryTest);
                // Remaining arguments are retry test args.
                cli.retry_test_args = args[i + 1..].to_vec();
                return args.len() - 1; // consume all remaining
            } else if sub_rest == "w" {
                cli.b_mode = Some(BMode::RewriteTest);
                cli.rewrite_test_args = args[i + 1..].to_vec();
                return args.len() - 1;
            } else {
                fail_bad_option(&args[i]);
            }
        }

        // -bS: batched SMTP
        'S' => {
            if !sub_rest.is_empty() {
                fail_bad_option(&args[i]);
            }
            cli.receiving_message = true;
            cli.b_mode = Some(BMode::BatchedSmtp);
        }

        // -bs: interactive SMTP
        's' => {
            if !sub_rest.is_empty() {
                fail_bad_option(&args[i]);
            }
            cli.receiving_message = true;
            cli.b_mode = Some(BMode::InteractiveSmtp);
        }

        // -bt: address testing
        't' => {
            if !sub_rest.is_empty() {
                fail_bad_option(&args[i]);
            }
            cli.b_mode = Some(BMode::AddressTest);
        }

        // -bv / -bvs: address verification
        'v' => {
            if sub_rest.is_empty() {
                cli.b_mode = Some(BMode::AddressVerify { as_sender: false });
            } else if sub_rest == "s" {
                cli.b_mode = Some(BMode::AddressVerify { as_sender: true });
            } else {
                fail_bad_option(&args[i]);
            }
        }

        // -bV: version
        'V' => {
            if !sub_rest.is_empty() {
                fail_bad_option(&args[i]);
            }
            cli.b_mode = Some(BMode::Version);
        }

        // -bw: inetd wait mode (optional timeout)
        'w' => {
            let timeout = if sub_rest.is_empty() {
                None
            } else {
                match parse_time_interval(sub_rest) {
                    Some(d) if d.as_secs() > 0 => Some(d),
                    _ => {
                        eprintln!("exim: bad time value after -bw");
                        std::process::exit(1);
                    }
                }
            };
            cli.inetd_wait_timeout = timeout;
            cli.b_mode = Some(BMode::InetdWait { timeout });
        }

        _ => fail_bad_option(&args[i]),
    }

    i
}

/// Parse `-M*` message action flags.
fn parse_m_action(cli: &mut EximCli, args: &[String], i: usize, rest: &str) -> usize {
    // Internal -MC* options (used for inter-process communication) are accepted
    // but not exposed through the public CLI struct — they are handled at a
    // higher level in main.rs. We still need to consume their arguments.
    if rest.starts_with('C') {
        // -MC and -MC* variants: consume remaining args. These are internal.
        // For the purposes of CLI parsing, we just skip to end.
        return args.len() - 1;
    }

    // Determine the action from the suffix after -M.
    let (action, one_msg) = match rest {
        "" => (MessageAction::Deliver, false),
        "ar" => (MessageAction::AddRecipient, true),
        "c" => (MessageAction::DeliverCutthrough, false),
        "es" => (MessageAction::EditSender, true),
        "f" => (MessageAction::Freeze, false),
        "g" => (MessageAction::GiveUp, false),
        "G" => {
            // -MG <msgid> <queue>: move to named queue.
            // The queue name is the next arg after the flag.
            let mut idx = i + 1;
            if idx >= args.len() {
                eprintln!("exim: queue name expected after -MG");
                std::process::exit(1);
            }
            let queue_name = args[idx].clone();
            cli.msg_action_arg = Some(queue_name);
            idx += 1;
            // Remaining args are message IDs.
            if idx >= args.len() {
                eprintln!("exim: no message ids given after -MG option");
                std::process::exit(1);
            }
            cli.message_action = Some(MessageAction::SetQueue);
            cli.recipients = args[idx..].to_vec();
            return args.len() - 1;
        }
        "mad" => (MessageAction::MarkAllDelivered, false),
        "md" => (MessageAction::MarkDelivered, true),
        "rm" => (MessageAction::Remove, false),
        "set" => (MessageAction::LoadForExpansion, true),
        "t" => (MessageAction::Thaw, false),
        "vb" => (MessageAction::ShowBody, true),
        "vc" => (MessageAction::ShowCopy, true),
        "vh" => (MessageAction::ShowHeader, true),
        "vl" => (MessageAction::ShowLog, true),
        _ => fail_bad_option(&args[i]),
    };

    cli.message_action = Some(action);

    // All -M* actions require at least one message ID after the flag.
    let msg_start = i + 1;
    if msg_start >= args.len() {
        eprintln!("exim: no message ids given after {} option", &args[i]);
        std::process::exit(1);
    }

    if one_msg {
        // Single-message actions: one message ID, then optional addresses.
        // Remaining arguments become cli.recipients for address-bearing actions.
        cli.recipients = args[msg_start..].to_vec();
    } else {
        // Multi-message actions: all remaining args are message IDs.
        cli.recipients = args[msg_start..].to_vec();
    }

    args.len() - 1 // consume all remaining
}

/// Parse `-o*` sendmail compatibility options.
fn parse_o_options(cli: &mut EximCli, args: &[String], mut i: usize, rest: &str) -> usize {
    if rest.is_empty() {
        fail_bad_option(&args[i]);
    }

    let sub = rest.as_bytes()[0] as char;
    let sub_rest = &rest[1..];

    match sub {
        // -oA <file>: alias file (ignored)
        'A' => {
            if sub_rest.is_empty() {
                i += 1;
                if i >= args.len() {
                    eprintln!("exim: string expected after -oA");
                    std::process::exit(1);
                }
            }
        }

        // -oB <n>: connection message max (ignored at this level)
        'B' => {
            if sub_rest.is_empty() {
                // Check if next arg is a number
                if i + 1 < args.len()
                    && args[i + 1]
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_digit())
                {
                    i += 1;
                }
            }
        }

        // -od*: delivery mode selection
        'd' => match sub_rest {
            "b" => {
                cli.delivery_mode = Some(DeliveryMode::Background);
                cli.queue_only = false;
            }
            "d" => { /* testsuite delays — accepted, no-op */ }
            "f" => {
                cli.delivery_mode = Some(DeliveryMode::Foreground);
                cli.queue_only = false;
            }
            "i" => {
                cli.delivery_mode = Some(DeliveryMode::Interactive);
                cli.queue_only = false;
            }
            "q" => {
                cli.delivery_mode = Some(DeliveryMode::QueueOnly);
                cli.queue_only = true;
            }
            "qs" => {
                cli.delivery_mode = Some(DeliveryMode::QueueSmtp);
                cli.queue_smtp = true;
                cli.queue_only = false;
            }
            _ => fail_bad_option(&args[i]),
        },

        // -oi / -oitrue: don't treat dot as terminator
        'i' => {
            if sub_rest.is_empty() || sub_rest == "true" {
                cli.dot_ends = false;
            } else {
                fail_bad_option(&args[i]);
            }
        }

        // -oM*: set message characteristics (testing)
        'M' => {
            i += 1;
            let val = if i < args.len() {
                args[i].clone()
            } else {
                eprintln!("exim: data expected after -oM{}", sub_rest);
                std::process::exit(1);
            };

            match sub_rest {
                "a" => cli.sender_host_address = Some(val),
                "i" => cli.incoming_interface = Some(val),
                "r" => cli.received_protocol = Some(val),
                "s" => cli.sender_host_name = Some(val),
                "t" => cli.sender_ident = Some(val),
                "aa" => cli.sender_host_authenticated = Some(val),
                "ai" => cli.authenticated_id = Some(val),
                "as" => cli.authenticated_sender = Some(val),
                "m" => {
                    // Validate message ID format: XXXXXX-YYYYYY-ZZ
                    // C Exim checks for valid base-62 characters and hyphen positions
                    if !is_valid_message_id(&val) {
                        eprintln!("exim: -oMm must be a valid message ID");
                        std::process::exit(1);
                    }
                    cli.message_reference = Some(val);
                }
                _ => fail_bad_option(&args[i - 1]),
            }
        }

        // -om / -oo: sendmail compat (no-op)
        'm' | 'o' => {
            if !sub_rest.is_empty() {
                fail_bad_option(&args[i]);
            }
        }

        // -oP / -oPX: pid file management (accepted)
        'P' => {
            if sub_rest.is_empty() {
                i += 1;
                if i >= args.len() {
                    fail_bad_option(&args[i - 1]);
                }
            }
            // Accepted; -oPX handled by caller.
        }

        // -or <timeout> / -os <timeout>: receive timeouts (accepted)
        'r' | 's' => {
            if sub_rest.is_empty() {
                i += 1;
                if i >= args.len() {
                    fail_bad_option(&args[i - 1]);
                }
            }
        }

        // -oX <list>: override local interfaces for daemon socket binding.
        // The next argument is the interface specification, which may contain
        // port numbers (e.g., "10025", "0.0.0.0:10025", "<; 0.0.0.0.10025").
        // This overrides the `local_interfaces` configuration option.
        'X' => {
            if !sub_rest.is_empty() {
                fail_bad_option(&args[i]);
            }
            i += 1;
            if i >= args.len() {
                fail_bad_option(&args[i - 1]);
            }
            cli.override_local_interfaces = Some(args[i].clone());
        }

        // -oY: override notifier socket (accepted)
        'Y' => {
            if !sub_rest.is_empty() {
                fail_bad_option(&args[i]);
            }
        }

        _ => fail_bad_option(&args[i]),
    }

    i
}

/// Parse `-q*` queue-running options. Handles the complex combination of
/// modifiers: `-qq`, `-qi`, `-qf`, `-qff`, `-ql`, `-qG<name>`, and trailing
/// time intervals.
fn parse_q_options(cli: &mut EximCli, args: &[String], i: usize, rest: &str) -> usize {
    let mut pos = 0;
    let bytes = rest.as_bytes();

    // Modifiers in order: q (two-stage), i (first-delivery), f/ff (force/thaw),
    // l (local), G<name>
    let two_stage = pos < bytes.len() && bytes[pos] == b'q';
    if two_stage {
        pos += 1;
    }

    let first_delivery = pos < bytes.len() && bytes[pos] == b'i';
    if first_delivery {
        pos += 1;
    }

    let force = pos < bytes.len() && bytes[pos] == b'f';
    if force {
        pos += 1;
    }

    let force_thaw = force && pos < bytes.len() && bytes[pos] == b'f';
    if force_thaw {
        pos += 1;
    }

    let local_only = pos < bytes.len() && bytes[pos] == b'l';
    if local_only {
        pos += 1;
    }

    // Named queue: -qG<name>[/<interval>]
    let mut queue_name: Option<String> = None;
    if pos < bytes.len() && bytes[pos] == b'G' {
        pos += 1;
        let name_start = pos;
        while pos < bytes.len() && bytes[pos] != b'/' {
            pos += 1;
        }
        let name = &rest[name_start..pos];
        if !name.is_empty() {
            queue_name = Some(name.to_string());
        }
        if pos < bytes.len() && bytes[pos] == b'/' {
            pos += 1; // skip the slash
        }
    }

    let remaining = &rest[pos..];

    // Determine if this is a one-time run or a periodic run.
    let mut idx = i;
    let (interval, start_id, stop_id) = if remaining.is_empty() {
        // No interval in the flag itself — check next args for message IDs.
        let mut start = None;
        let mut stop = None;

        // One-time run: check for start/stop message IDs.
        if idx + 1 < args.len() && (args[idx + 1].starts_with('-') || is_message_id(&args[idx + 1]))
        {
            if idx + 1 < args.len() && is_message_id(&args[idx + 1]) {
                idx += 1;
                start = Some(args[idx].clone());
            }
            if idx + 1 < args.len() && is_message_id(&args[idx + 1]) {
                idx += 1;
                stop = Some(args[idx].clone());
            }
        }

        (None, start, stop)
    } else {
        // An interval is embedded in the flag.
        match parse_time_interval(remaining) {
            Some(d) if d.as_secs() > 0 => (Some(d), None, None),
            _ => {
                eprintln!("exim: bad time value {}: abandoned", remaining);
                std::process::exit(1);
            }
        }
    };

    let config = QueueRunConfig {
        name: queue_name,
        interval,
        two_stage,
        first_delivery,
        force,
        force_thaw,
        local_only,
        start_id,
        stop_id,
    };

    cli.q_runners.push(config);
    idx
}

/// Parse `-R*` or `-S*` selective queue-run flags.
/// `is_domain` is `true` for `-R` (domain match), `false` for `-S` (sender match).
fn parse_selective_run(
    cli: &mut EximCli,
    args: &[String],
    i: usize,
    rest: &str,
    is_domain: bool,
) -> usize {
    let mut pos = 0;
    let bytes = rest.as_bytes();

    // Parse optional modifiers: f (force), ff (force+thaw), r (regex),
    // rf (regex+force), rff (regex+force+thaw).
    let mut force = false;
    let mut thaw = false;

    // Check for 'r' (regex) prefix — accepted but stored separately.
    if pos < bytes.len() && bytes[pos] == b'r' {
        pos += 1;
    }

    if pos < bytes.len() && bytes[pos] == b'f' {
        force = true;
        pos += 1;
        if pos < bytes.len() && bytes[pos] == b'f' {
            thaw = true;
            pos += 1;
        }
    }

    let suffix = &rest[pos..];

    // The select string is the rest of this arg (if non-empty) or the next arg.
    let mut idx = i;
    let select_str = if !suffix.is_empty() {
        suffix.to_string()
    } else {
        idx += 1;
        if idx >= args.len() {
            let flag = if is_domain { "-R" } else { "-S" };
            eprintln!("exim: string expected after {}", flag);
            std::process::exit(1);
        }
        args[idx].clone()
    };

    if is_domain {
        cli.selective_domain = Some(select_str);
    } else {
        cli.selective_sender = Some(select_str);
    }

    cli.selective_force = force;
    cli.selective_force_thaw = thaw;

    // Ensure a queue runner exists.
    if cli.q_runners.is_empty() {
        cli.q_runners.push(QueueRunConfig {
            name: None,
            interval: None,
            two_stage: cli.selective_two_stage,
            first_delivery: false,
            force,
            force_thaw: thaw,
            local_only: false,
            start_id: None,
            stop_id: None,
        });
    } else {
        // Update the existing runner with force/thaw from -R/-S.
        if let Some(runner) = cli.q_runners.last_mut() {
            if force {
                runner.force = true;
            }
            if thaw {
                runner.force_thaw = true;
            }
        }
    }

    idx
}

/// Check if a string looks like an Exim message ID. Exim message IDs have a
/// specific format: either the new format (base-62 encoded segments separated
/// by hyphens) or the old format (`XXXXXX-XXXXXX-XX`). This is a simplified
/// heuristic matching the C `mac_ismsgid()` regex.
fn is_message_id(s: &str) -> bool {
    let bytes = s.as_bytes();
    let len = bytes.len();

    // Old format: 16 chars, pattern XXXXXX-XXXXXX-XX
    if len == 16
        && bytes[6] == b'-'
        && bytes[13] == b'-'
        && bytes.iter().enumerate().all(|(idx, &b)| {
            if idx == 6 || idx == 13 {
                b == b'-'
            } else {
                b.is_ascii_alphanumeric() || b == b'_'
            }
        })
    {
        return true;
    }

    // New format: variable length with hyphens separating base-62 segments.
    // A simple check: contains exactly 2 hyphens, all non-hyphen chars are
    // alphanumeric or underscore.
    let hyphen_count = bytes.iter().filter(|&&b| b == b'-').count();
    if hyphen_count == 2 && len >= 8 {
        let all_valid = bytes
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if all_valid && !s.starts_with('-') && !s.ends_with('-') {
            return true;
        }
    }

    false
}

/// Detect symlink invocation from `argv[0]`.
fn detect_symlink_invocation_from(argv0: &str) -> Option<String> {
    // Extract the basename: everything after the last '/'.
    let basename = match argv0.rfind('/') {
        Some(pos) => &argv0[pos + 1..],
        None => argv0,
    };

    match basename {
        "mailq" => Some("mailq".to_string()),
        "rmail" => Some("rmail".to_string()),
        "rsmtp" => Some("rsmtp".to_string()),
        "runq" => Some("runq".to_string()),
        "newaliases" => Some("newaliases".to_string()),
        _ => None,
    }
}

/// Apply default flag settings for symlink-based invocations.
fn apply_symlink_defaults(cli: &mut EximCli, name: &str) {
    match name {
        // mailq → exim -bp
        "mailq" => {
            cli.b_mode = Some(BMode::ListQueue {
                option: QueueListOption::Basic,
            });
            cli.receiving_message = false;
        }
        // rmail → exim -i -oee
        "rmail" => {
            cli.dot_ends = false;
            // -oee: errors as email, return success — handled at a higher level.
        }
        // rsmtp → exim -bS
        "rsmtp" => {
            cli.b_mode = Some(BMode::BatchedSmtp);
            cli.receiving_message = true;
        }
        // runq → exim -q (one-time queue run)
        "runq" => {
            cli.q_runners.push(QueueRunConfig {
                name: None,
                interval: None,
                two_stage: false,
                first_delivery: false,
                force: false,
                force_thaw: false,
                local_only: false,
                start_id: None,
                stop_id: None,
            });
            cli.receiving_message = false;
        }
        // newaliases → exim -bi
        "newaliases" => {
            cli.b_mode = Some(BMode::NewAliases);
            cli.receiving_message = false;
        }
        _ => {}
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to parse from a string slice list.
    fn parse(args: &[&str]) -> EximCli {
        let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        parse_args_from(&owned)
    }

    #[test]
    fn test_parse_time_interval_seconds() {
        assert_eq!(parse_time_interval("30s"), Some(Duration::from_secs(30)));
    }

    #[test]
    fn test_parse_time_interval_minutes() {
        assert_eq!(parse_time_interval("5m"), Some(Duration::from_secs(300)));
    }

    #[test]
    fn test_parse_time_interval_hours() {
        assert_eq!(parse_time_interval("1h"), Some(Duration::from_secs(3600)));
    }

    #[test]
    fn test_parse_time_interval_days() {
        assert_eq!(parse_time_interval("1d"), Some(Duration::from_secs(86400)));
    }

    #[test]
    fn test_parse_time_interval_weeks() {
        assert_eq!(parse_time_interval("1w"), Some(Duration::from_secs(604800)));
    }

    #[test]
    fn test_parse_time_interval_combined() {
        assert_eq!(
            parse_time_interval("1h30m"),
            Some(Duration::from_secs(5400))
        );
    }

    #[test]
    fn test_parse_time_interval_bare_number() {
        assert_eq!(parse_time_interval("120"), Some(Duration::from_secs(120)));
    }

    #[test]
    fn test_parse_time_interval_empty() {
        assert_eq!(parse_time_interval(""), None);
    }

    #[test]
    fn test_parse_time_interval_invalid() {
        assert_eq!(parse_time_interval("abc"), None);
    }

    #[test]
    fn test_detect_symlink_mailq() {
        assert_eq!(
            detect_symlink_invocation_from("mailq"),
            Some("mailq".to_string())
        );
    }

    #[test]
    fn test_detect_symlink_with_path() {
        assert_eq!(
            detect_symlink_invocation_from("/usr/bin/mailq"),
            Some("mailq".to_string())
        );
    }

    #[test]
    fn test_detect_symlink_rmail() {
        assert_eq!(
            detect_symlink_invocation_from("/usr/sbin/rmail"),
            Some("rmail".to_string())
        );
    }

    #[test]
    fn test_detect_symlink_rsmtp() {
        assert_eq!(
            detect_symlink_invocation_from("rsmtp"),
            Some("rsmtp".to_string())
        );
    }

    #[test]
    fn test_detect_symlink_runq() {
        assert_eq!(
            detect_symlink_invocation_from("runq"),
            Some("runq".to_string())
        );
    }

    #[test]
    fn test_detect_symlink_newaliases() {
        assert_eq!(
            detect_symlink_invocation_from("newaliases"),
            Some("newaliases".to_string())
        );
    }

    #[test]
    fn test_detect_symlink_none() {
        assert_eq!(detect_symlink_invocation_from("exim"), None);
        assert_eq!(detect_symlink_invocation_from("/usr/sbin/exim4"), None);
    }

    #[test]
    fn test_default_mode_is_receive() {
        let cli = parse(&["exim"]);
        assert_eq!(determine_mode(&cli), EximMode::ReceiveMessage);
    }

    #[test]
    fn test_daemon_mode() {
        let cli = parse(&["exim", "-bd"]);
        assert_eq!(determine_mode(&cli), EximMode::Daemon { foreground: false });
    }

    #[test]
    fn test_daemon_foreground() {
        let cli = parse(&["exim", "-bdf"]);
        assert_eq!(determine_mode(&cli), EximMode::Daemon { foreground: true });
    }

    #[test]
    fn test_version() {
        let cli = parse(&["exim", "-bV"]);
        assert_eq!(determine_mode(&cli), EximMode::Version);
    }

    #[test]
    fn test_expansion_test() {
        let cli = parse(&["exim", "-be"]);
        assert_eq!(
            determine_mode(&cli),
            EximMode::ExpansionTest {
                message_file: None,
                message_load: None,
            }
        );
    }

    #[test]
    fn test_expansion_test_with_message() {
        let cli = parse(&["exim", "-bem", "/tmp/msg"]);
        assert_eq!(
            determine_mode(&cli),
            EximMode::ExpansionTest {
                message_file: Some("/tmp/msg".to_string()),
                message_load: None,
            }
        );
    }

    #[test]
    fn test_list_queue() {
        let cli = parse(&["exim", "-bp"]);
        assert_eq!(
            determine_mode(&cli),
            EximMode::ListQueue {
                option: QueueListOption::Basic
            }
        );
    }

    #[test]
    fn test_count_queue() {
        let cli = parse(&["exim", "-bpc"]);
        assert_eq!(determine_mode(&cli), EximMode::CountQueue);
    }

    #[test]
    fn test_address_test() {
        let cli = parse(&["exim", "-bt"]);
        assert_eq!(determine_mode(&cli), EximMode::AddressTest);
    }

    #[test]
    fn test_address_verify() {
        let cli = parse(&["exim", "-bv"]);
        assert_eq!(
            determine_mode(&cli),
            EximMode::AddressVerify { as_sender: false }
        );
    }

    #[test]
    fn test_address_verify_sender() {
        let cli = parse(&["exim", "-bvs"]);
        assert_eq!(
            determine_mode(&cli),
            EximMode::AddressVerify { as_sender: true }
        );
    }

    #[test]
    fn test_smtp_interactive() {
        let cli = parse(&["exim", "-bs"]);
        assert_eq!(determine_mode(&cli), EximMode::SmtpInput { batched: false });
    }

    #[test]
    fn test_smtp_batched() {
        let cli = parse(&["exim", "-bS"]);
        assert_eq!(determine_mode(&cli), EximMode::SmtpInput { batched: true });
    }

    #[test]
    fn test_config_check() {
        let cli = parse(&["exim", "-bP"]);
        assert_eq!(
            determine_mode(&cli),
            EximMode::ConfigCheck {
                options: Vec::new(),
                show_config: false,
            }
        );
    }

    #[test]
    fn test_config_check_full() {
        let cli = parse(&["exim", "-bP", "config"]);
        assert_eq!(
            determine_mode(&cli),
            EximMode::ConfigCheck {
                options: Vec::new(),
                show_config: true,
            }
        );
    }

    #[test]
    fn test_filter_test_system() {
        let cli = parse(&["exim", "-bF", "/tmp/filter"]);
        assert_eq!(
            determine_mode(&cli),
            EximMode::FilterTest {
                filter_type: FilterType::System,
                file: "/tmp/filter".to_string(),
            }
        );
    }

    #[test]
    fn test_filter_test_user() {
        let cli = parse(&["exim", "-bf", "/tmp/filter"]);
        assert_eq!(
            determine_mode(&cli),
            EximMode::FilterTest {
                filter_type: FilterType::User,
                file: "/tmp/filter".to_string(),
            }
        );
    }

    #[test]
    fn test_info_mode() {
        let cli = parse(&["exim", "-bI:modules"]);
        assert_eq!(
            determine_mode(&cli),
            EximMode::Info {
                info_type: InfoType::Modules
            }
        );
    }

    #[test]
    fn test_newaliases_mode() {
        let cli = parse(&["exim", "-bi"]);
        assert_eq!(determine_mode(&cli), EximMode::NewAliases);
    }

    #[test]
    fn test_queue_run_single() {
        let cli = parse(&["exim", "-q"]);
        let mode = determine_mode(&cli);
        if let EximMode::QueueRun { runners } = mode {
            assert_eq!(runners.len(), 1);
            assert!(runners[0].interval.is_none());
        } else {
            panic!("expected QueueRun, got {:?}", mode);
        }
    }

    #[test]
    fn test_queue_run_interval() {
        let cli = parse(&["exim", "-q30m"]);
        let mode = determine_mode(&cli);
        if let EximMode::QueueRun { runners } = mode {
            assert_eq!(runners.len(), 1);
            assert_eq!(runners[0].interval, Some(Duration::from_secs(1800)));
        } else {
            panic!("expected QueueRun, got {:?}", mode);
        }
    }

    #[test]
    fn test_queue_run_forced() {
        let cli = parse(&["exim", "-qf"]);
        let mode = determine_mode(&cli);
        if let EximMode::QueueRun { runners } = mode {
            assert!(runners[0].force);
            assert!(!runners[0].force_thaw);
        } else {
            panic!("expected QueueRun, got {:?}", mode);
        }
    }

    #[test]
    fn test_queue_run_forced_thaw() {
        let cli = parse(&["exim", "-qff"]);
        let mode = determine_mode(&cli);
        if let EximMode::QueueRun { runners } = mode {
            assert!(runners[0].force);
            assert!(runners[0].force_thaw);
        } else {
            panic!("expected QueueRun, got {:?}", mode);
        }
    }

    #[test]
    fn test_queue_run_local() {
        let cli = parse(&["exim", "-ql"]);
        let mode = determine_mode(&cli);
        if let EximMode::QueueRun { runners } = mode {
            assert!(runners[0].local_only);
        } else {
            panic!("expected QueueRun, got {:?}", mode);
        }
    }

    #[test]
    fn test_queue_run_two_stage() {
        let cli = parse(&["exim", "-qq30m"]);
        let mode = determine_mode(&cli);
        if let EximMode::QueueRun { runners } = mode {
            assert!(runners[0].two_stage);
            assert_eq!(runners[0].interval, Some(Duration::from_secs(1800)));
        } else {
            panic!("expected QueueRun, got {:?}", mode);
        }
    }

    #[test]
    fn test_config_file_option() {
        let cli = parse(&["exim", "-C", "/etc/exim.conf"]);
        assert_eq!(cli.config_file, Some(PathBuf::from("/etc/exim.conf")));
    }

    #[test]
    fn test_macro_definition() {
        let cli = parse(&["exim", "-DFOO=bar"]);
        assert_eq!(cli.macro_defs, vec![("FOO".to_string(), "bar".to_string())]);
    }

    #[test]
    fn test_macro_definition_no_value() {
        let cli = parse(&["exim", "-DFOO"]);
        assert_eq!(cli.macro_defs, vec![("FOO".to_string(), String::new())]);
    }

    #[test]
    fn test_sender_address() {
        let cli = parse(&["exim", "-f", "user@example.com"]);
        assert_eq!(cli.sender_address, Some("user@example.com".to_string()));
    }

    #[test]
    fn test_sender_name() {
        let cli = parse(&["exim", "-F", "John Doe"]);
        assert_eq!(cli.sender_fullname, Some("John Doe".to_string()));
    }

    #[test]
    fn test_dot_ends_flag() {
        let cli = parse(&["exim", "-i"]);
        assert!(!cli.dot_ends);
    }

    #[test]
    fn test_dont_deliver() {
        let cli = parse(&["exim", "-N"]);
        assert!(cli.dont_deliver);
    }

    #[test]
    fn test_extract_recipients() {
        let cli = parse(&["exim", "-t"]);
        assert!(cli.extract_recipients);
    }

    #[test]
    fn test_extract_recipients_and_dot() {
        let cli = parse(&["exim", "-ti"]);
        assert!(cli.extract_recipients);
        assert!(!cli.dot_ends);
    }

    #[test]
    fn test_verbose() {
        let cli = parse(&["exim", "-v"]);
        assert!(cli.verbose);
    }

    #[test]
    fn test_mua_submission() {
        let cli = parse(&["exim", "-G"]);
        assert!(cli.mua_submission);
    }

    #[test]
    fn test_debug_selector() {
        let cli = parse(&["exim", "-d+all"]);
        assert_eq!(cli.debug_selector, Some("+all".to_string()));
    }

    #[test]
    fn test_debug_daemon_only() {
        let cli = parse(&["exim", "-dd"]);
        assert!(cli.debug_daemon_only);
    }

    #[test]
    fn test_delivery_mode_background() {
        let cli = parse(&["exim", "-odb"]);
        assert_eq!(cli.delivery_mode, Some(DeliveryMode::Background));
    }

    #[test]
    fn test_delivery_mode_foreground() {
        let cli = parse(&["exim", "-odf"]);
        assert_eq!(cli.delivery_mode, Some(DeliveryMode::Foreground));
    }

    #[test]
    fn test_delivery_mode_queue_only() {
        let cli = parse(&["exim", "-odq"]);
        assert_eq!(cli.delivery_mode, Some(DeliveryMode::QueueOnly));
        assert!(cli.queue_only);
    }

    #[test]
    fn test_delivery_mode_queue_smtp() {
        let cli = parse(&["exim", "-odqs"]);
        assert_eq!(cli.delivery_mode, Some(DeliveryMode::QueueSmtp));
        assert!(cli.queue_smtp);
    }

    #[test]
    fn test_recipients_after_flags() {
        let cli = parse(&["exim", "-v", "user@example.com"]);
        assert_eq!(cli.recipients, vec!["user@example.com".to_string()]);
    }

    #[test]
    fn test_double_dash_terminates() {
        let cli = parse(&["exim", "--", "-not-a-flag"]);
        assert_eq!(cli.recipients, vec!["-not-a-flag".to_string()]);
    }

    #[test]
    fn test_symlink_mailq() {
        let cli = parse(&["mailq"]);
        assert_eq!(
            determine_mode(&cli),
            EximMode::ListQueue {
                option: QueueListOption::Basic
            }
        );
    }

    #[test]
    fn test_symlink_rsmtp() {
        let cli = parse(&["rsmtp"]);
        assert_eq!(determine_mode(&cli), EximMode::SmtpInput { batched: true });
    }

    #[test]
    fn test_symlink_runq() {
        let cli = parse(&["runq"]);
        let mode = determine_mode(&cli);
        if let EximMode::QueueRun { runners } = mode {
            assert_eq!(runners.len(), 1);
        } else {
            panic!("expected QueueRun, got {:?}", mode);
        }
    }

    #[test]
    fn test_symlink_newaliases() {
        let cli = parse(&["newaliases"]);
        assert_eq!(determine_mode(&cli), EximMode::NewAliases);
    }

    #[test]
    fn test_symlink_rmail() {
        let cli = parse(&["rmail"]);
        assert!(!cli.dot_ends); // -i equivalent
        assert_eq!(determine_mode(&cli), EximMode::ReceiveMessage);
    }

    #[test]
    fn test_host_check() {
        let cli = parse(&["exim", "-bh", "192.168.1.1"]);
        assert_eq!(
            determine_mode(&cli),
            EximMode::HostCheck {
                host: "192.168.1.1".to_string()
            }
        );
    }

    #[test]
    fn test_inetd_wait() {
        let cli = parse(&["exim", "-bw"]);
        assert_eq!(determine_mode(&cli), EximMode::InetdWait);
    }

    #[test]
    fn test_retry_test() {
        let cli = parse(&["exim", "-brt", "foo", "bar"]);
        let mode = determine_mode(&cli);
        if let EximMode::RetryTest { args } = mode {
            assert_eq!(args, vec!["foo".to_string(), "bar".to_string()]);
        } else {
            panic!("expected RetryTest, got {:?}", mode);
        }
    }

    #[test]
    fn test_rewrite_test() {
        let cli = parse(&["exim", "-brw", "baz"]);
        let mode = determine_mode(&cli);
        if let EximMode::RewriteTest { args } = mode {
            assert_eq!(args, vec!["baz".to_string()]);
        } else {
            panic!("expected RewriteTest, got {:?}", mode);
        }
    }

    #[test]
    fn test_malware_test() {
        let cli = parse(&["exim", "-bmalware", "/tmp/virus.eml"]);
        assert_eq!(
            determine_mode(&cli),
            EximMode::MalwareTest {
                file: "/tmp/virus.eml".to_string()
            }
        );
    }

    #[test]
    fn test_is_message_id_old_format() {
        assert!(is_message_id("1a2b3c-4d5e6f-AB"));
    }

    #[test]
    fn test_is_message_id_rejects_garbage() {
        assert!(!is_message_id("not-a-message-id-at-all"));
    }

    #[test]
    fn test_perl_start_option() {
        let cli = parse(&["exim", "-ps"]);
        assert_eq!(cli.perl_start_option, 1);
    }

    #[test]
    fn test_perl_delay_option() {
        let cli = parse(&["exim", "-pd"]);
        assert_eq!(cli.perl_start_option, -1);
    }

    #[test]
    fn test_sender_host_address() {
        let cli = parse(&["exim", "-oMa", "10.0.0.1"]);
        assert_eq!(cli.sender_host_address, Some("10.0.0.1".to_string()));
    }

    #[test]
    fn test_sender_host_name() {
        let cli = parse(&["exim", "-oMs", "mail.example.com"]);
        assert_eq!(cli.sender_host_name, Some("mail.example.com".to_string()));
    }

    #[test]
    fn test_incoming_interface() {
        let cli = parse(&["exim", "-oMi", "192.168.0.1"]);
        assert_eq!(cli.incoming_interface, Some("192.168.0.1".to_string()));
    }

    #[test]
    fn test_received_protocol() {
        let cli = parse(&["exim", "-oMr", "smtp"]);
        assert_eq!(cli.received_protocol, Some("smtp".to_string()));
    }

    #[test]
    fn test_sender_ident() {
        let cli = parse(&["exim", "-oMt", "testident"]);
        assert_eq!(cli.sender_ident, Some("testident".to_string()));
    }

    #[test]
    fn test_no_qualify() {
        let cli = parse(&["exim", "-bnq"]);
        assert!(cli.no_qualify);
    }

    #[test]
    fn test_queue_list_unsorted() {
        let cli = parse(&["exim", "-bpr"]);
        assert_eq!(
            determine_mode(&cli),
            EximMode::ListQueue {
                option: QueueListOption::Unsorted
            }
        );
    }

    #[test]
    fn test_queue_list_undelivered() {
        let cli = parse(&["exim", "-bpu"]);
        assert_eq!(
            determine_mode(&cli),
            EximMode::ListQueue {
                option: QueueListOption::UndeliveredOnly
            }
        );
    }

    #[test]
    fn test_queue_list_msgid_only() {
        let cli = parse(&["exim", "-bpi"]);
        assert_eq!(
            determine_mode(&cli),
            EximMode::ListQueue {
                option: QueueListOption::MsgidOnly
            }
        );
    }

    #[test]
    fn test_queue_list_plus_generated() {
        let cli = parse(&["exim", "-bpa"]);
        assert_eq!(
            determine_mode(&cli),
            EximMode::ListQueue {
                option: QueueListOption::PlusGenerated
            }
        );
    }

    #[test]
    fn test_oi_dot_ends() {
        let cli = parse(&["exim", "-oi"]);
        assert!(!cli.dot_ends);
    }

    #[test]
    fn test_oitrue_dot_ends() {
        let cli = parse(&["exim", "-oitrue"]);
        assert!(!cli.dot_ends);
    }

    #[test]
    fn test_r_synonym_for_f() {
        let cli = parse(&["exim", "-r", "user@example.com"]);
        assert_eq!(cli.sender_address, Some("user@example.com".to_string()));
    }

    #[test]
    fn test_info_help() {
        let cli = parse(&["exim", "-bI:help"]);
        assert_eq!(
            determine_mode(&cli),
            EximMode::Info {
                info_type: InfoType::Help
            }
        );
    }

    #[test]
    fn test_info_sieve() {
        let cli = parse(&["exim", "-bI:sieve"]);
        assert_eq!(
            determine_mode(&cli),
            EximMode::Info {
                info_type: InfoType::Sieve
            }
        );
    }

    #[test]
    fn test_info_dscp() {
        let cli = parse(&["exim", "-bI:dscp"]);
        assert_eq!(
            determine_mode(&cli),
            EximMode::Info {
                info_type: InfoType::Dscp
            }
        );
    }

    #[test]
    fn test_named_queue() {
        let cli = parse(&["exim", "-qGmyqueue/30m"]);
        let mode = determine_mode(&cli);
        if let EximMode::QueueRun { runners } = mode {
            assert_eq!(runners[0].name, Some("myqueue".to_string()));
            assert_eq!(runners[0].interval, Some(Duration::from_secs(1800)));
        } else {
            panic!("expected QueueRun, got {:?}", mode);
        }
    }

    #[test]
    fn test_named_queue_no_interval() {
        let cli = parse(&["exim", "-qGmyqueue"]);
        let mode = determine_mode(&cli);
        if let EximMode::QueueRun { runners } = mode {
            assert_eq!(runners[0].name, Some("myqueue".to_string()));
            assert!(runners[0].interval.is_none());
        } else {
            panic!("expected QueueRun, got {:?}", mode);
        }
    }
}
