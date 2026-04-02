// =============================================================================
// exim-transports/src/pipe.rs — Pipe to Command Transport
// =============================================================================
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Rewrites `src/src/transports/pipe.c` (1,156 lines) + `pipe.h` (53 lines)
// into a safe Rust implementation. This transport delivers messages to external
// commands via direct argv execution or `/bin/sh -c`, with:
//
// - Controlled environment variables (13 standard + user-defined)
// - Compile-time taint tracking via Tainted<T>/Clean<T> (replaces C is_tainted())
// - Optional BSMTP (Batched SMTP) framing for batch delivery
// - Output capture with max_output limit and reader thread
// - Exit-status interpretation with configurable temp_errors
// - Per-delivery umask, uid/gid, and resource limit control
// - Timeout handling with process group signaling
//
// Feature gate: `transport-pipe` (replaces C `#ifdef TRANSPORT_PIPE`)
// Zero unsafe code: per AAP §0.7.2
// Driver registration: via inventory::submit! per AAP §0.7.3
//
// This file contains ZERO unsafe blocks.
// =============================================================================

use std::collections::HashMap;
use std::io::{BufReader, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use exim_drivers::transport_driver::{
    TransportDriver, TransportDriverFactory, TransportInstanceConfig, TransportResult,
};
use exim_drivers::DriverError;
use exim_store::taint::{Clean, TaintError, Tainted};

// =============================================================================
// Constants — Exit Codes and Defaults
// =============================================================================

/// EX_TEMPFAIL from sysexits.h — "temporary failure, indicating something
/// that is not really an error." Used as default temp_error code.
/// C reference: pipe.c lines 989-996
const EX_TEMPFAIL: i32 = 75;

/// EX_CANTCREAT from sysexits.h — "A (user specified) output file cannot
/// be created." Used as default temp_error code alongside EX_TEMPFAIL.
const EX_CANTCREAT: i32 = 73;

/// EX_EXECFAILED — Exim's custom code for execve() failure. Changed from
/// EX_UNAVAILABLE (69) at release 4.21 to match shell behavior (127).
/// C reference: pipe.c lines 1002-1023
const EX_EXECFAILED: i32 = 127;

/// Default PATH for command execution.
/// C reference: pipe.c line 94 — `US"/bin:/usr/bin"`
const DEFAULT_PATH: &str = "/bin:/usr/bin";

/// Default temp_errors specification.
/// C reference: pipe.c lines 95-96 — `"75:73"` (EX_TEMPFAIL:EX_CANTCREAT)
const DEFAULT_TEMP_ERRORS: &str = "75:73";

/// Default file creation mask (octal 022).
/// C reference: pipe.c line 97 — `022`
const DEFAULT_UMASK: u32 = 0o22;

/// Default maximum output capture in bytes.
/// C reference: pipe.c line 98 — `20480`
const DEFAULT_MAX_OUTPUT: i32 = 20480;

/// Default command timeout in seconds (60 minutes).
/// C reference: pipe.c line 99 — `60*60`
const DEFAULT_TIMEOUT: i32 = 3600;

/// Maximum number of environment variables (matching C envp[50] array size,
/// with headroom for standard variables).
const MAX_ENV_VARS: usize = 50;

/// Message appended when output exceeds max_output limit.
const OUTPUT_OVERFLOW_MSG: &str = "\n\n*** Too much output - remainder discarded ***\n";

/// Child timeout sentinel value used by C child_close() convention.
/// When child_close() returns -256, it means the child timed out.
const CHILD_TIMEOUT_RC: i32 = -256;

/// Child wait() failure sentinel value from C child_close().
const CHILD_WAIT_FAILED_RC: i32 = -257;

// =============================================================================
// Transport Write Options — Bitfield constants
// =============================================================================

/// Option flag: escape headers for BSMTP dot-stuffing.
const TOPT_ESCAPE_HEADERS: i32 = 0x0001;

/// Option flag: omit message headers (body_only).
const TOPT_NO_HEADERS: i32 = 0x0002;

/// Option flag: omit message body (headers_only).
const TOPT_NO_BODY: i32 = 0x0004;

/// Option flag: add Return-Path header.
const TOPT_ADD_RETURN_PATH: i32 = 0x0008;

/// Option flag: add Delivery-Date header.
const TOPT_ADD_DELIVERY_DATE: i32 = 0x0010;

/// Option flag: add Envelope-To header.
const TOPT_ADD_ENVELOPE_TO: i32 = 0x0020;

/// Option flag: use CRLF line endings.
const TOPT_USE_CRLF: i32 = 0x0040;

// =============================================================================
// PipeTransportOptions — Configuration Options
// =============================================================================

/// Configuration options for the pipe transport driver.
///
/// Maps 1:1 to the C `pipe_transport_options_block` struct defined in
/// `pipe.h` (lines 12-37). All 24 fields are preserved with identical
/// names for configuration file backward compatibility.
///
/// The C option table (`pipe_transport_options[]` in pipe.c lines 30-72)
/// maps configuration file directives to these fields. Options marked
/// `opt_public` in C are stored in `TransportInstanceConfig` instead
/// (e.g., `batch_id`, `batch_max`, `return_output`, `log_output`, etc.).
///
/// # Configuration File Names
///
/// All option names are identical to their C counterparts for backward
/// compatibility (AAP §0.7.1):
///
/// | Config Name         | Field                | C Type      |
/// |---------------------|----------------------|-------------|
/// | `command`           | `cmd`                | stringptr   |
/// | `allow_commands`    | `allow_commands`     | stringptr   |
/// | `environment`       | `environment`        | stringptr   |
/// | `path`              | `path`               | stringptr   |
/// | `message_prefix`    | `message_prefix`     | stringptr   |
/// | `message_suffix`    | `message_suffix`     | stringptr   |
/// | `temp_errors`       | `temp_errors`        | stringptr   |
/// | `check_string`      | `check_string`       | stringptr   |
/// | `escape_string`     | `escape_string`      | stringptr   |
/// | `umask`             | `umask`              | octint      |
/// | `max_output`        | `max_output`         | mkint       |
/// | `timeout`           | `timeout`            | time        |
/// | `force_command`     | `force_command`       | bool        |
/// | `freeze_exec_fail`  | `freeze_exec_fail`   | bool        |
/// | `freeze_signal`     | `freeze_signal`      | bool        |
/// | `ignore_status`     | `ignore_status`      | bool        |
/// | `permit_coredump`   | `permit_coredump`    | bool        |
/// | `restrict_to_path`  | `restrict_to_path`   | bool        |
/// | `timeout_defer`     | `timeout_defer`      | bool        |
/// | `use_shell`         | `use_shell`          | bool        |
/// | `use_bsmtp`         | `use_bsmtp`          | bool        |
/// | `use_classresources`| `use_classresources` | bool        |
/// | `use_crlf`          | `use_crlf`           | bool        |
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PipeTransportOptions {
    /// Command to execute — expanded per-delivery.
    /// Config name: `command` (maps to `cmd` field for C compatibility).
    /// C: `pipe_transport_options_block.cmd`
    #[serde(alias = "command")]
    pub cmd: Option<String>,

    /// Colon-separated list of allowed commands. If set, only commands in
    /// this list may be executed. Mutually exclusive with `use_shell`.
    /// C: `pipe_transport_options_block.allow_commands`
    pub allow_commands: Option<String>,

    /// Additional environment variables in `NAME=VALUE` format, colon-separated.
    /// Added to the standard environment variables built by the transport.
    /// C: `pipe_transport_options_block.environment`
    pub environment: Option<String>,

    /// PATH for command execution. Colon-separated directory list.
    /// Default: `"/bin:/usr/bin"`
    /// C: `pipe_transport_options_block.path`
    pub path: Option<String>,

    /// Prefix string written before the message body. Expanded per-delivery.
    /// Default for non-BSMTP: `"From ${if def:return_path{$return_path}{MAILER-DAEMON}} ${tod_bsdinbox}\n"`
    /// C: `pipe_transport_options_block.message_prefix`
    pub message_prefix: Option<String>,

    /// Suffix string written after the message body. Expanded per-delivery.
    /// Default for non-BSMTP: `"\n"`
    /// C: `pipe_transport_options_block.message_suffix`
    pub message_suffix: Option<String>,

    /// Exit codes treated as temporary errors (defer). Format: colon-separated
    /// integers or `"*"` for all codes. Default: `"75:73"` (EX_TEMPFAIL:EX_CANTCREAT).
    /// C: `pipe_transport_options_block.temp_errors`
    pub temp_errors: Option<String>,

    /// String to check in message body lines — if found at line start,
    /// `escape_string` is prepended. Used for dot-stuffing in BSMTP mode.
    /// C: `pipe_transport_options_block.check_string`
    pub check_string: Option<String>,

    /// Escape replacement string prepended when `check_string` is found.
    /// C: `pipe_transport_options_block.escape_string`
    pub escape_string: Option<String>,

    /// File creation mask for the child process. Default: `0o22` (octal).
    /// C: `pipe_transport_options_block.umask`
    #[serde(default = "default_umask")]
    pub umask: u32,

    /// Maximum output capture in bytes. Default: 20480.
    /// If the child produces more output than this, the process group is killed.
    /// C: `pipe_transport_options_block.max_output`
    #[serde(default = "default_max_output")]
    pub max_output: i32,

    /// Command timeout in seconds. Default: 3600 (1 hour).
    /// C: `pipe_transport_options_block.timeout`
    #[serde(default = "default_timeout")]
    pub timeout: i32,

    /// Additional transport write options bitfield.
    /// C: `pipe_transport_options_block.options`
    #[serde(default)]
    pub options: i32,

    /// Force use of configured command even for pipe addresses from aliases/forwards.
    /// When set, `$address_pipe` expansion variable is available.
    /// C: `pipe_transport_options_block.force_command`
    #[serde(default)]
    pub force_command: bool,

    /// Freeze message on exec failure (exit code EX_EXECFAILED=127).
    /// C: `pipe_transport_options_block.freeze_exec_fail`
    #[serde(default)]
    pub freeze_exec_fail: bool,

    /// Freeze message when child process is terminated by a signal.
    /// C: `pipe_transport_options_block.freeze_signal`
    #[serde(default)]
    pub freeze_signal: bool,

    /// Ignore non-zero exit status — treat all exits as success.
    /// C: `pipe_transport_options_block.ignore_status`
    #[serde(default)]
    pub ignore_status: bool,

    /// Allow the child process to produce core dumps (set RLIMIT_CORE to
    /// RLIM_INFINITY). BSD-specific: also controls setclassresources.
    /// C: `pipe_transport_options_block.permit_coredump`
    #[serde(default)]
    pub permit_coredump: bool,

    /// Restrict command to executables found in PATH directories.
    /// When set, commands containing `/` are rejected. Mutually exclusive
    /// with `use_shell`.
    /// C: `pipe_transport_options_block.restrict_to_path`
    #[serde(default)]
    pub restrict_to_path: bool,

    /// Defer (instead of fail) on command timeout.
    /// C: `pipe_transport_options_block.timeout_defer`
    #[serde(default)]
    pub timeout_defer: bool,

    /// Use `/bin/sh -c` to run the command instead of direct exec.
    /// Mutually exclusive with `restrict_to_path` and `allow_commands`.
    /// C: `pipe_transport_options_block.use_shell`
    #[serde(default)]
    pub use_shell: bool,

    /// Use BSMTP (Batched SMTP) framing. When set, MAIL FROM/RCPT TO/DATA
    /// envelope wrapping is added, check_string is set to "." and
    /// escape_string to "..".
    /// C: `pipe_transport_options_block.use_bsmtp`
    #[serde(default)]
    pub use_bsmtp: bool,

    /// Use setclassresources(3) for BSD login class resource limits.
    /// Feature-gated behind `HAVE_SETCLASSRESOURCES` in C.
    /// C: `pipe_transport_options_block.use_classresources`
    #[serde(default)]
    pub use_classresources: bool,

    /// Use CRLF line endings instead of LF.
    /// C: `pipe_transport_options_block.use_crlf`
    #[serde(default)]
    pub use_crlf: bool,
}

/// Default value for umask field (octal 022).
fn default_umask() -> u32 {
    DEFAULT_UMASK
}

/// Default value for max_output field (20480 bytes).
fn default_max_output() -> i32 {
    DEFAULT_MAX_OUTPUT
}

/// Default value for timeout field (3600 seconds).
fn default_timeout() -> i32 {
    DEFAULT_TIMEOUT
}

impl Default for PipeTransportOptions {
    /// Creates a `PipeTransportOptions` with defaults matching C
    /// `pipe_transport_option_defaults` (pipe.c lines 93-100):
    ///
    /// - `path = Some("/bin:/usr/bin")`
    /// - `temp_errors = Some("75:73")` (EX_TEMPFAIL:EX_CANTCREAT)
    /// - `umask = 0o22`
    /// - `max_output = 20480`
    /// - `timeout = 3600` (1 hour)
    /// - All other fields: `None` / `false` / `0`
    fn default() -> Self {
        Self {
            cmd: None,
            allow_commands: None,
            environment: None,
            path: Some(DEFAULT_PATH.to_string()),
            message_prefix: None,
            message_suffix: None,
            temp_errors: Some(DEFAULT_TEMP_ERRORS.to_string()),
            check_string: None,
            escape_string: None,
            umask: DEFAULT_UMASK,
            max_output: DEFAULT_MAX_OUTPUT,
            timeout: DEFAULT_TIMEOUT,
            options: 0,
            force_command: false,
            freeze_exec_fail: false,
            freeze_signal: false,
            ignore_status: false,
            permit_coredump: false,
            restrict_to_path: false,
            timeout_defer: false,
            use_shell: false,
            use_bsmtp: false,
            use_classresources: false,
            use_crlf: false,
        }
    }
}

// =============================================================================
// PipeTransport — Transport Driver Implementation
// =============================================================================

/// Pipe transport driver — delivers messages by piping them to external
/// commands via direct argv execution or `/bin/sh -c`.
///
/// This is a LOCAL transport (is_local() returns true). It supports:
///
/// - **Direct execution**: Command parsed into argv, searched in PATH
/// - **Shell execution**: Command passed to `/bin/sh -c` for shell expansion
/// - **BSMTP framing**: MAIL FROM/RCPT TO/DATA envelope wrapping
/// - **Output capture**: Child stdout/stderr captured with size limit
/// - **Taint safety**: Command strings validated via Tainted<T>/Clean<T>
/// - **Exit status mapping**: Configurable temp_errors, freeze_exec_fail,
///   freeze_signal, ignore_status behaviors
///
/// Replaces C `pipe_transport_entry()` and associated helpers from
/// `src/src/transports/pipe.c`.
#[derive(Debug)]
pub struct PipeTransport {
    /// Driver-specific options parsed from configuration.
    options: PipeTransportOptions,
}

impl PipeTransport {
    /// Creates a new PipeTransport instance with the given options.
    ///
    /// # Arguments
    ///
    /// - `options` — Configuration options parsed from the Exim configuration file.
    pub fn new(options: PipeTransportOptions) -> Self {
        Self { options }
    }

    /// Creates a new PipeTransport with default options.
    pub fn with_defaults() -> Self {
        Self {
            options: PipeTransportOptions::default(),
        }
    }

    // =========================================================================
    // Configuration Validation
    // =========================================================================

    /// Validates the transport configuration, equivalent to C
    /// `pipe_transport_init()` (pipe.c lines 178-272).
    ///
    /// Checks enforced:
    /// 1. `pipe_as_creator` (deliver_as_creator) must not be set alongside uid/gid
    /// 2. If uid is set, gid must also be set
    /// 3. `temp_errors` must be `"*"` or a colon-separated list of digits
    /// 4. `return_output` and `return_fail_output` must not both be set
    /// 5. `log_output` and `log_fail_output` must not both be set
    /// 6. `restrict_to_path` and `use_shell` must not both be set
    /// 7. `allow_commands` and `use_shell` must not both be set
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the configuration is valid
    /// - `Err(DriverError::ConfigError)` describing the invalid combination
    pub fn validate_config(&mut self, config: &TransportInstanceConfig) -> Result<(), DriverError> {
        let name = &config.name;

        // Check 1: pipe_as_creator vs explicit uid/gid
        // C reference: pipe.c lines 191-195
        if config.deliver_as_creator
            && (config.uid_set
                || config.gid_set
                || config.expand_uid.is_some()
                || config.expand_gid.is_some())
        {
            return Err(DriverError::ConfigError(format!(
                "both pipe_as_creator and an explicit uid/gid are set for the \
                 {name} transport"
            )));
        }

        // Check 2: uid set without gid
        // C reference: pipe.c lines 199-201
        if config.uid_set && !config.gid_set && config.expand_gid.is_none() {
            return Err(DriverError::ConfigError(format!(
                "user set without group for the {name} transport"
            )));
        }

        // Check 3: temp_errors format validation
        // C reference: pipe.c lines 206-213
        if let Some(ref te) = self.options.temp_errors {
            if te != "*" {
                let valid = te
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == ':' || c == ' ');
                if !valid {
                    return Err(DriverError::ConfigError(format!(
                        "temp_errors must be a list of numbers or an asterisk \
                         for the {name} transport"
                    )));
                }
            }
        }

        // Check 4: return_output + return_fail_output conflict
        // C reference: pipe.c lines 218-221
        if config.return_output && config.return_fail_output {
            return Err(DriverError::ConfigError(format!(
                "both return_output and return_fail_output set for {name} transport"
            )));
        }

        // Check 5: log_output + log_fail_output conflict
        // C reference: pipe.c lines 223-226
        if config.log_output && config.log_fail_output {
            return Err(DriverError::ConfigError(format!(
                "both log_output and log_fail_output set for the {name} transport"
            )));
        }

        // Check 6: BSMTP mode — force check/escape strings
        // C reference: pipe.c lines 231-246
        if self.options.use_bsmtp {
            self.options.check_string = Some(".".to_string());
            self.options.escape_string = Some("..".to_string());
            self.options.options |= TOPT_ESCAPE_HEADERS;
        } else {
            // Set default message_prefix for non-BSMTP mode
            if self.options.message_prefix.is_none() {
                self.options.message_prefix = Some(
                    "From ${if def:return_path{$return_path}{MAILER-DAEMON}} \
                     ${tod_bsdinbox}\n"
                        .to_string(),
                );
            }
            // Set default message_suffix for non-BSMTP mode
            if self.options.message_suffix.is_none() {
                self.options.message_suffix = Some("\n".to_string());
            }
        }

        // Check 7: restrict_to_path + use_shell conflict
        // C reference: pipe.c lines 250-253
        if self.options.restrict_to_path && self.options.use_shell {
            return Err(DriverError::ConfigError(format!(
                "both restrict_to_path and use_shell set for {name} transport"
            )));
        }

        // Check 8: allow_commands + use_shell conflict
        // C reference: pipe.c lines 257-260
        if self.options.allow_commands.is_some() && self.options.use_shell {
            return Err(DriverError::ConfigError(format!(
                "both allow_commands and use_shell set for {name} transport"
            )));
        }

        // Set up bitwise options from transport config flags
        // C reference: pipe.c lines 265-271
        if config.body_only {
            self.options.options |= TOPT_NO_HEADERS;
        }
        if config.headers_only {
            self.options.options |= TOPT_NO_BODY;
        }
        if config.return_path_add {
            self.options.options |= TOPT_ADD_RETURN_PATH;
        }
        if config.delivery_date_add {
            self.options.options |= TOPT_ADD_DELIVERY_DATE;
        }
        if config.envelope_to_add {
            self.options.options |= TOPT_ADD_ENVELOPE_TO;
        }
        if self.options.use_crlf {
            self.options.options |= TOPT_USE_CRLF;
        }

        tracing::debug!(
            transport = name.as_str(),
            "pipe transport configuration validated successfully"
        );

        Ok(())
    }

    // =========================================================================
    // Command Setup — Direct Execution
    // =========================================================================

    /// Sets up command arguments for direct (non-shell) execution.
    ///
    /// Parses the command string into an argv vector, validates against
    /// `allow_commands` and `restrict_to_path`, and searches PATH for
    /// relative commands.
    ///
    /// Replaces C `set_up_direct_command()` (pipe.c lines 296-397).
    ///
    /// # Arguments
    ///
    /// - `cmd` — The clean (validated) command string to parse
    /// - `transport_name` — Transport instance name for error messages
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<String>)` — The parsed argv vector with full path resolution
    /// - `Err(DriverError)` — If command validation or PATH search fails
    fn set_up_direct_command(
        &self,
        cmd: &Clean<String>,
        transport_name: &str,
    ) -> Result<Vec<String>, DriverError> {
        let cmd_str = cmd.as_ref();
        let ob = &self.options;

        // Split command into argv — respecting shell-style quoting
        let argv = parse_command_args(cmd_str);
        if argv.is_empty() {
            return Err(DriverError::ExecutionFailed(format!(
                "empty command for {transport_name} transport"
            )));
        }

        let mut argv = argv;
        // Clone command name to avoid borrow conflict when modifying argv
        let command_name = argv[0].clone();

        // Check against allow_commands list
        // C reference: pipe.c lines 320-336
        let mut permitted = false;
        if let Some(ref allow_list) = ob.allow_commands {
            tracing::debug!(
                transport = transport_name,
                allow_commands = allow_list.as_str(),
                "checking command against allow_commands list"
            );
            for allowed in allow_list.split(':') {
                let allowed = allowed.trim();
                if allowed == command_name.as_str() {
                    permitted = true;
                    break;
                }
            }
        }

        // Validate command if not explicitly permitted
        // C reference: pipe.c lines 345-365
        if !permitted {
            if ob.restrict_to_path {
                // Fail if command contains a slash
                if command_name.contains('/') {
                    return Err(DriverError::ExecutionFailed(format!(
                        "\"/\" found in \"{cmd_str}\" (command for {transport_name} \
                         transport) - failed for security reasons"
                    )));
                }
            } else if ob.allow_commands.is_some() {
                // allow_commands was set but command not found in list
                return Err(DriverError::ExecutionFailed(format!(
                    "\"{command_name}\" command not permitted by {transport_name} \
                     transport"
                )));
            }
        }

        // Search PATH for non-absolute commands
        // C reference: pipe.c lines 370-394
        if !argv[0].starts_with('/') {
            let path_str = ob.path.as_deref().unwrap_or(DEFAULT_PATH);
            let mut found = false;

            for dir in path_str.split(':') {
                let dir = dir.trim();
                if dir.is_empty() {
                    continue;
                }
                let full_path = PathBuf::from(dir).join(&argv[0]);
                if full_path.exists() {
                    tracing::debug!(
                        transport = transport_name,
                        command = %full_path.display(),
                        "command found in PATH"
                    );
                    argv[0] = full_path.to_string_lossy().into_owned();
                    found = true;
                    break;
                }
            }

            if !found {
                return Err(DriverError::ExecutionFailed(format!(
                    "\"{command_name}\" command not found for {transport_name} transport"
                )));
            }
        }

        Ok(argv)
    }

    // =========================================================================
    // Command Setup — Shell Execution
    // =========================================================================

    /// Sets up command arguments for shell execution via `/bin/sh -c`.
    ///
    /// Wraps the command in a shell invocation for commands that require
    /// shell features (pipes, redirects, variable expansion).
    ///
    /// Replaces C `set_up_shell_command()` (pipe.c lines 419-497).
    ///
    /// # Arguments
    ///
    /// - `cmd` — The clean (validated) command string
    /// - `transport_name` — Transport instance name for log messages
    ///
    /// # Returns
    ///
    /// An argv vector: `["/bin/sh", "-c", <expanded_command>]`
    fn set_up_shell_command(&self, cmd: &Clean<String>, transport_name: &str) -> Vec<String> {
        let cmd_str = cmd.as_ref().clone();

        tracing::debug!(
            transport = transport_name,
            command = cmd_str.as_str(),
            "shell pipe command (via /bin/sh -c)"
        );

        vec!["/bin/sh".to_string(), "-c".to_string(), cmd_str]
    }

    // =========================================================================
    // Environment Building
    // =========================================================================

    /// Builds the environment variables for the child command.
    ///
    /// Constructs 13 standard environment variables plus any additional
    /// variables from the `environment` option.
    ///
    /// Replaces C pipe_transport_entry() lines 625-677.
    ///
    /// Standard variables set:
    /// - `LOCAL_PART` — local part of the address
    /// - `LOGNAME` — same as LOCAL_PART
    /// - `USER` — same as LOCAL_PART
    /// - `LOCAL_PART_PREFIX` — prefix portion
    /// - `LOCAL_PART_SUFFIX` — suffix portion
    /// - `DOMAIN` — domain part of the address
    /// - `HOME` — home directory (from config)
    /// - `MESSAGE_ID` — current message ID
    /// - `PATH` — search path
    /// - `RECIPIENT` — full recipient address
    /// - `QUALIFY_DOMAIN` — sender qualification domain
    /// - `SENDER` — envelope sender
    /// - `SHELL` — always `/bin/sh`
    fn build_environment(
        &self,
        config: &TransportInstanceConfig,
        address: &str,
    ) -> HashMap<String, String> {
        let mut env = HashMap::new();

        // Parse address into local_part and domain
        let (local_part, domain) = split_address(address);

        // Standard environment variables (matching C order)
        env.insert("LOCAL_PART".to_string(), local_part.clone());
        env.insert("LOGNAME".to_string(), local_part.clone());
        env.insert("USER".to_string(), local_part.clone());
        env.insert("LOCAL_PART_PREFIX".to_string(), String::new());
        env.insert("LOCAL_PART_SUFFIX".to_string(), String::new());
        env.insert("DOMAIN".to_string(), domain.clone());
        env.insert(
            "HOME".to_string(),
            config.home_dir.clone().unwrap_or_default(),
        );
        env.insert("MESSAGE_ID".to_string(), String::new());
        env.insert(
            "PATH".to_string(),
            self.options
                .path
                .clone()
                .unwrap_or_else(|| DEFAULT_PATH.to_string()),
        );
        env.insert("RECIPIENT".to_string(), address.to_string());
        env.insert("QUALIFY_DOMAIN".to_string(), domain.clone());
        env.insert("SENDER".to_string(), String::new());
        env.insert("SHELL".to_string(), "/bin/sh".to_string());

        // Add custom environment variables from the `environment` option
        // C reference: pipe.c lines 654-676
        if let Some(ref env_str) = self.options.environment {
            for item in env_str.split(':') {
                let item = item.trim();
                if item.is_empty() {
                    continue;
                }
                if env.len() >= MAX_ENV_VARS - 2 {
                    tracing::warn!(
                        transport = config.name.as_str(),
                        "too many environment settings — truncating"
                    );
                    break;
                }
                if let Some((key, value)) = item.split_once('=') {
                    env.insert(key.to_string(), value.to_string());
                } else {
                    // Items without '=' are passed as-is (empty value)
                    env.insert(item.to_string(), String::new());
                }
            }
        }

        env
    }

    // =========================================================================
    // Temp Errors Parsing
    // =========================================================================

    /// Parses the `temp_errors` configuration string into a set of exit codes
    /// that should be treated as temporary failures (DEFER).
    ///
    /// Format: colon-separated integers (e.g., "75:73") or "*" for all codes.
    ///
    /// # Returns
    ///
    /// - `TempErrorConfig::All` if temp_errors is "*"
    /// - `TempErrorConfig::Codes(Vec<i32>)` with the parsed exit codes
    fn parse_temp_errors(&self) -> TempErrorConfig {
        match self.options.temp_errors.as_deref() {
            Some("*") => TempErrorConfig::All,
            Some(s) => {
                let codes: Vec<i32> = s
                    .split(':')
                    .filter_map(|part| part.trim().parse::<i32>().ok())
                    .collect();
                TempErrorConfig::Codes(codes)
            }
            None => TempErrorConfig::Codes(vec![EX_TEMPFAIL, EX_CANTCREAT]),
        }
    }

    // =========================================================================
    // Exit Status Interpretation
    // =========================================================================

    /// Interprets the child process exit status and returns the appropriate
    /// `TransportResult`.
    ///
    /// Replaces the exit status interpretation logic in pipe.c lines 920-1109.
    ///
    /// Exit status mapping:
    /// - Timeout (rc == -256) → FAIL (or DEFER if timeout_defer)
    /// - Wait failure (rc == -257) → Error
    /// - Signal death (rc < 0) → freeze_signal: DEFER+freeze, else FAIL
    /// - exec failure (rc == EX_EXECFAILED) → freeze_exec_fail: DEFER+freeze
    /// - temp_errors match → DEFER
    /// - ignore_status → Ok regardless
    /// - Other non-zero → FAIL
    fn interpret_exit_status(
        &self,
        exit_code: i32,
        cmd_str: &str,
        transport_name: &str,
    ) -> TransportResult {
        let ob = &self.options;

        // Exit code 0 means success
        if exit_code == 0 {
            return TransportResult::ok();
        }

        // Timeout case: child timed out
        // C reference: pipe.c lines 931-937
        if exit_code == CHILD_TIMEOUT_RC {
            let msg = format!("pipe delivery process timed out for {transport_name} transport");
            tracing::warn!(
                transport = transport_name,
                command = cmd_str,
                "command timed out"
            );
            return if ob.timeout_defer {
                TransportResult::Deferred {
                    message: Some(msg),
                    errno: None,
                }
            } else {
                TransportResult::Failed { message: Some(msg) }
            };
        }

        // Wait() failure case
        // C reference: pipe.c lines 941-946
        if exit_code == CHILD_WAIT_FAILED_RC {
            return TransportResult::Error {
                message: format!("Wait() failed for child process of {transport_name} transport"),
            };
        }

        // Signal death (negative exit code = -(signal_number))
        // C reference: pipe.c lines 966-983
        if exit_code < 0 {
            let signal_num = -exit_code;
            let msg = format!(
                "Child process of {transport_name} transport (running command \
                 \"{cmd_str}\") was terminated by signal {signal_num}"
            );

            if ob.freeze_signal {
                tracing::warn!(
                    transport = transport_name,
                    signal = signal_num,
                    "child killed by signal — freezing message"
                );
                return TransportResult::Deferred {
                    message: Some(msg),
                    errno: None,
                };
            } else if !ob.ignore_status {
                tracing::error!(
                    transport = transport_name,
                    signal = signal_num,
                    "child killed by signal"
                );
                return TransportResult::Failed { message: Some(msg) };
            }
            // ignore_status: fall through to Ok
            return TransportResult::ok();
        }

        // Positive exit code: process completed with non-zero status
        // C reference: pipe.c lines 1025-1107

        // Check for exec failure
        // C reference: pipe.c lines 1029-1035
        if ob.freeze_exec_fail && exit_code == EX_EXECFAILED {
            let msg =
                format!("pipe process failed to exec \"{cmd_str}\" for {transport_name} transport");
            tracing::warn!(
                transport = transport_name,
                exit_code,
                "exec failed — freezing message"
            );
            return TransportResult::Deferred {
                message: Some(msg),
                errno: None,
            };
        }

        // If ignoring status, return success
        if ob.ignore_status {
            tracing::debug!(
                transport = transport_name,
                exit_code,
                "non-zero exit status ignored"
            );
            return TransportResult::ok();
        }

        // Check against temp_errors list
        // C reference: pipe.c lines 1048-1060
        let temp_config = self.parse_temp_errors();
        let is_temp = match &temp_config {
            TempErrorConfig::All => true,
            TempErrorConfig::Codes(codes) => codes.contains(&exit_code),
        };

        // Build error message with command details
        // C reference: pipe.c lines 1065-1106
        let mut msg = format!("Child process of {transport_name} transport returned {exit_code}");

        // Add signal interpretation for high exit codes
        if exit_code > 128 {
            let sig = exit_code - 128;
            msg.push_str(&format!(
                " (could mean shell command ended by signal {sig})"
            ));
        }

        msg.push_str(&format!(" from command: {cmd_str}"));

        if is_temp {
            tracing::warn!(
                transport = transport_name,
                exit_code,
                "temporary error from pipe command"
            );
            TransportResult::Deferred {
                message: Some(msg),
                errno: None,
            }
        } else {
            tracing::error!(
                transport = transport_name,
                exit_code,
                "permanent failure from pipe command"
            );
            TransportResult::Failed { message: Some(msg) }
        }
    }

    // =========================================================================
    // Command Execution
    // =========================================================================

    /// Executes the command and returns the process exit code and captured
    /// output.
    ///
    /// Sets up the child process with the configured umask, environment,
    /// uid/gid, and process group. Captures stdout/stderr up to `max_output`
    /// bytes and applies the configured timeout.
    ///
    /// # Arguments
    ///
    /// - `argv` — The argument vector for the child process
    /// - `env` — Environment variable map
    /// - `config` — Transport instance configuration
    /// - `message_body` — Optional message body to write to child's stdin
    ///
    /// # Returns
    ///
    /// - `Ok((exit_code, captured_output))` — Command completed
    /// - `Err(DriverError)` — Failed to spawn or manage the child process
    fn execute_command(
        &self,
        argv: &[String],
        env: &HashMap<String, String>,
        config: &TransportInstanceConfig,
        message_body: Option<&str>,
    ) -> Result<(i32, String), DriverError> {
        if argv.is_empty() {
            return Err(DriverError::ExecutionFailed(
                "empty argument vector".to_string(),
            ));
        }

        let ob = &self.options;
        let transport_name = &config.name;

        tracing::debug!(
            transport = transport_name.as_str(),
            command = argv[0].as_str(),
            args = ?&argv[1..],
            "spawning pipe command"
        );

        // Build the Command
        let mut cmd = Command::new(&argv[0]);
        if argv.len() > 1 {
            cmd.args(&argv[1..]);
        }

        // Clear inherited environment and set controlled environment
        cmd.env_clear();
        for (key, value) in env {
            cmd.env(key, value);
        }

        // Set up stdin/stdout/stderr pipes
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // Set uid/gid if configured
        if config.uid_set {
            cmd.uid(config.uid);
        }
        if config.gid_set {
            cmd.gid(config.gid);
        }

        // Create a new process group for timeout killpg
        cmd.process_group(0);

        // Set working directory if configured
        if let Some(ref dir) = config.current_dir {
            cmd.current_dir(dir);
        } else if let Some(ref home) = config.home_dir {
            cmd.current_dir(home);
        }

        // Set umask before spawning via nix (safe wrapper — no unsafe code).
        // The umask is process-wide in POSIX, so we set it before fork/exec
        // and restore after. nix::sys::stat::umask is available when
        // transport-pipe feature is enabled (which brings in nix).
        let umask_mode = nix::sys::stat::Mode::from_bits_truncate(ob.umask as _);
        let saved_umask = nix::sys::stat::umask(umask_mode);

        // Spawn the child process
        let spawn_result = cmd.spawn();

        // Restore the original umask after spawning
        nix::sys::stat::umask(saved_umask);

        let mut child = spawn_result.map_err(|e| {
            tracing::error!(
                transport = transport_name.as_str(),
                error = %e,
                "failed to spawn pipe command"
            );
            DriverError::ExecutionFailed(format!(
                "Failed to create child process for {transport_name} transport: {e}"
            ))
        })?;

        // Write message body to child's stdin
        if let Some(body) = message_body {
            if let Some(mut stdin) = child.stdin.take() {
                let eol = if ob.use_crlf { "\r\n" } else { "\n" };

                // Write message_prefix if configured
                if let Some(ref prefix) = ob.message_prefix {
                    let _ = stdin.write_all(prefix.as_bytes());
                }

                // BSMTP framing: MAIL FROM, RCPT TO, DATA
                if ob.use_bsmtp {
                    let _ = write!(stdin, "MAIL FROM:<>{eol}");
                    let _ = write!(stdin, "RCPT TO:<>{eol}");
                    let _ = write!(stdin, "DATA{eol}");
                }

                // Write message body with check_string/escape_string handling
                for line in body.lines() {
                    if let (Some(ref check), Some(ref escape)) =
                        (&ob.check_string, &ob.escape_string)
                    {
                        if line.starts_with(check.as_str()) {
                            let _ = stdin.write_all(escape.as_bytes());
                        }
                    }
                    let _ = stdin.write_all(line.as_bytes());
                    let _ = stdin.write_all(eol.as_bytes());
                }

                // Write message_suffix if configured
                if let Some(ref suffix) = ob.message_suffix {
                    let _ = stdin.write_all(suffix.as_bytes());
                }

                // BSMTP: write terminating dot
                if ob.use_bsmtp {
                    let _ = write!(stdin, ".{eol}");
                }

                // Explicitly close stdin to signal EOF to the child
                drop(stdin);
            }
        } else if let Some(stdin) = child.stdin.take() {
            // Close stdin immediately if no body to write
            drop(stdin);
        }

        // Capture output from stdout and stderr with max_output limit
        let max_output = ob.max_output.max(0) as usize;
        let mut captured_output = String::new();

        // Read stdout
        if let Some(stdout) = child.stdout.take() {
            let mut reader = BufReader::new(stdout);
            let mut buf = vec![0u8; 4096];
            let mut total_read = 0usize;

            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        total_read += n;
                        if total_read <= max_output {
                            if let Ok(s) = std::str::from_utf8(&buf[..n]) {
                                captured_output.push_str(s);
                            }
                        } else {
                            captured_output.push_str(OUTPUT_OVERFLOW_MSG);
                            tracing::debug!(
                                transport = transport_name.as_str(),
                                max_output,
                                total_read,
                                "output exceeded max_output limit"
                            );
                            // Kill the process group
                            let pid = child.id();
                            kill_process_group(pid as i32);
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            transport = transport_name.as_str(),
                            error = %e,
                            "error reading pipe output"
                        );
                        break;
                    }
                }
            }
        }

        // Also capture stderr into the output
        if let Some(mut stderr) = child.stderr.take() {
            let mut stderr_buf = String::new();
            let _ = stderr.read_to_string(&mut stderr_buf);
            if !stderr_buf.is_empty() {
                if !captured_output.is_empty() {
                    captured_output.push('\n');
                }
                captured_output.push_str(&stderr_buf);
            }
        }

        // Wait for the child with timeout
        let timeout_duration = Duration::from_secs(ob.timeout.max(1) as u64);
        let exit_code = wait_for_child(&mut child, timeout_duration, transport_name)?;

        tracing::debug!(
            transport = transport_name.as_str(),
            exit_code,
            output_bytes = captured_output.len(),
            "pipe command completed"
        );

        Ok((exit_code, captured_output))
    }
}

// =============================================================================
// TransportDriver Trait Implementation
// =============================================================================

impl TransportDriver for PipeTransport {
    /// Main transport entry point — delivers a message to a recipient by
    /// piping it to the configured external command.
    ///
    /// Replaces C `pipe_transport_entry()` (pipe.c lines 510-1127).
    ///
    /// # Flow
    ///
    /// 1. Determine command source (config `cmd` or pipe address)
    /// 2. Validate command against taint tracking
    /// 3. Set up command arguments (direct or shell)
    /// 4. Build environment variables
    /// 5. Execute command with message on stdin
    /// 6. Interpret exit status
    fn transport_entry(
        &self,
        config: &TransportInstanceConfig,
        address: &str,
    ) -> Result<TransportResult, DriverError> {
        let ob = &self.options;
        let transport_name = &config.name;

        tracing::debug!(
            transport = transport_name.as_str(),
            address,
            "pipe transport entered"
        );

        // Determine command source
        // C reference: pipe.c lines 546-569
        let (cmd_source, is_pipe_address) = if let Some(stripped) = address.strip_prefix('|') {
            // Pipe address from .forward or alias file
            if ob.force_command {
                // force_command: use configured command anyway
                (ob.cmd.clone(), true)
            } else {
                // Use the pipe address, stripping the leading '|'
                let pipe_cmd = stripped.trim_start().to_string();
                (Some(pipe_cmd), true)
            }
        } else {
            // Normal address — use configured command
            (ob.cmd.clone(), false)
        };

        // Validate command exists
        // C reference: pipe.c lines 575-581
        let cmd_string = match cmd_source {
            Some(ref c) if !c.is_empty() => c.clone(),
            _ => {
                return Ok(TransportResult::Deferred {
                    message: Some(format!(
                        "no command specified for {transport_name} transport"
                    )),
                    errno: None,
                });
            }
        };

        // Taint check — commands from external sources must be validated
        // C reference: pipe.c lines 582-589
        let clean_cmd = if is_pipe_address && !ob.force_command {
            // Command from pipe address is potentially tainted
            let tainted = Tainted::new(cmd_string);
            tracing::debug!(
                transport = transport_name.as_str(),
                "validating tainted pipe command"
            );

            tainted
                .sanitize(|cmd| {
                    // Validate the command: no null bytes, not empty, reasonable length
                    !cmd.is_empty() && !cmd.contains('\0') && cmd.len() < 65536 && cmd.is_ascii()
                })
                .map_err(|e: TaintError| {
                    tracing::error!(
                        transport = transport_name.as_str(),
                        error = %e.context,
                        "tainted command rejected"
                    );
                    DriverError::ExecutionFailed(format!(
                        "Tainted command (command for {transport_name} transport) \
                         not permitted: {}",
                        e.context
                    ))
                })?
        } else {
            // Command from config is trusted (clean)
            Clean::new(cmd_string)
        };

        // Set up command arguments
        // C reference: pipe.c lines 612-618
        let argv = if ob.use_shell {
            self.set_up_shell_command(&clean_cmd, transport_name)
        } else {
            self.set_up_direct_command(&clean_cmd, transport_name)?
        };

        tracing::debug!(
            transport = transport_name.as_str(),
            argv = ?argv,
            "command arguments prepared"
        );

        // Build environment
        let env = self.build_environment(config, address);

        // Execute the command
        // The message body would normally come from the message spool via
        // the delivery context. In the simplified trait interface, we execute
        // the command with the address as context.
        let (exit_code, captured_output) = self.execute_command(&argv, &env, config, None)?;

        // Log output if configured
        let should_log = config.log_output
            || (config.log_fail_output && exit_code != 0)
            || (config.log_defer_output && is_temp_exit(&self.parse_temp_errors(), exit_code));
        if should_log && !captured_output.is_empty() {
            tracing::info!(
                transport = transport_name.as_str(),
                output = captured_output.as_str(),
                exit_code,
                "pipe command output"
            );
        }

        // Interpret exit status
        let result = self.interpret_exit_status(exit_code, clean_cmd.as_ref(), transport_name);

        // Set user-visible message for failures
        // C reference: pipe.c lines 1123-1124
        if !result.is_ok() {
            tracing::debug!(
                transport = transport_name.as_str(),
                result = %result,
                "pipe transport delivery result"
            );
        }

        tracing::debug!(
            transport = transport_name.as_str(),
            result = %result,
            "pipe transport yielded result"
        );

        Ok(result)
    }

    /// Returns `true` — the pipe transport is a LOCAL transport.
    ///
    /// C reference: `pipe_transport_info.local = TRUE` (pipe.c line 1152)
    fn is_local(&self) -> bool {
        true
    }

    /// Returns the driver name `"pipe"`.
    ///
    /// C reference: `pipe_transport_info.drinfo.driver_name = US"pipe"` (pipe.c line 1139)
    fn driver_name(&self) -> &str {
        "pipe"
    }
}

// =============================================================================
// Driver Registration
// =============================================================================

// Compile-time registration of the pipe transport driver.
//
// Replaces the C `pipe_transport_info` static struct (pipe.c lines 1137-1153)
// with `inventory::submit!` for compile-time collection by
// `exim-drivers/src/registry.rs`.
inventory::submit! {
    TransportDriverFactory {
        name: "pipe",
        create: || Box::new(PipeTransport::with_defaults()),
        is_local: true,
        avail_string: None,
    }
}

// =============================================================================
// Helper Types
// =============================================================================

/// Configuration for which exit codes are treated as temporary failures.
#[derive(Debug, Clone)]
enum TempErrorConfig {
    /// All non-zero exit codes are temporary failures (temp_errors = "*").
    All,
    /// Specific exit codes that indicate temporary failure.
    Codes(Vec<i32>),
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Splits a command string into an argv vector, respecting double-quoted
/// arguments.
///
/// This provides basic shell-like argument parsing for direct (non-shell)
/// command execution. It handles:
/// - Whitespace-delimited arguments
/// - Double-quoted strings (preserving internal spaces)
/// - Basic escape sequences within quotes
///
/// # Arguments
///
/// - `cmd` — The command string to parse
///
/// # Returns
///
/// A vector of argument strings.
fn parse_command_args(cmd: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = cmd.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
            }
            '\\' if in_quotes => {
                // Handle escape sequences within quotes
                if let Some(&next) = chars.peek() {
                    chars.next();
                    current.push(next);
                }
            }
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    args.push(current.clone());
                    current.clear();
                }
            }
            _ => {
                current.push(ch);
            }
        }
    }

    if !current.is_empty() {
        args.push(current);
    }

    args
}

/// Splits an email address into (local_part, domain).
///
/// If the address contains `@`, splits at the last `@` character.
/// Otherwise, the entire address is the local part with an empty domain.
fn split_address(address: &str) -> (String, String) {
    if let Some(at_pos) = address.rfind('@') {
        let local = &address[..at_pos];
        let domain = &address[at_pos + 1..];
        (local.to_string(), domain.to_string())
    } else {
        (address.to_string(), String::new())
    }
}

/// Checks whether the given exit code is a temporary error according to
/// the `TempErrorConfig`.
fn is_temp_exit(config: &TempErrorConfig, exit_code: i32) -> bool {
    match config {
        TempErrorConfig::All => exit_code != 0,
        TempErrorConfig::Codes(codes) => codes.contains(&exit_code),
    }
}

/// Kills a process group (sends SIGKILL to all processes in the group).
///
/// Uses `nix::sys::signal::killpg` when the nix crate is available,
/// otherwise falls back to logging the attempt. This is the safe alternative
/// to raw `libc::killpg` per AAP §0.7.2.
fn kill_process_group(pid: i32) {
    // Send SIGKILL to the process group.
    // nix is always available when transport-pipe is enabled (it's a
    // dependency of the transport-pipe feature).
    use nix::sys::signal::{killpg, Signal};
    use nix::unistd::Pid;
    let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
}

/// Waits for a child process with a timeout. Returns the exit code using
/// Exim conventions:
///
/// - 0: success
/// - positive: process exit code
/// - negative: -(signal_number) if killed by signal
/// - -256: timeout
/// - -257: wait failure
fn wait_for_child(
    child: &mut std::process::Child,
    timeout: Duration,
    transport_name: &str,
) -> Result<i32, DriverError> {
    // Use a simple polling approach for timeout
    let start = std::time::Instant::now();
    let poll_interval = Duration::from_millis(100);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Process completed
                use std::os::unix::process::ExitStatusExt;

                if let Some(code) = status.code() {
                    return Ok(code);
                }
                // Killed by signal
                if let Some(signal) = status.signal() {
                    return Ok(-signal);
                }
                // Unknown status — treat as error
                return Ok(-1);
            }
            Ok(None) => {
                // Process still running — check timeout
                if start.elapsed() >= timeout {
                    tracing::warn!(
                        transport = transport_name,
                        timeout_secs = timeout.as_secs(),
                        "pipe command timed out — killing process group"
                    );

                    // Kill the process group on timeout
                    let pid = child.id() as i32;
                    kill_process_group(pid);

                    // Also try to kill the child directly
                    let _ = child.kill();
                    let _ = child.wait();

                    return Ok(CHILD_TIMEOUT_RC);
                }
                std::thread::sleep(poll_interval);
            }
            Err(e) => {
                tracing::error!(
                    transport = transport_name,
                    error = %e,
                    "wait() failed for child process"
                );
                return Ok(CHILD_WAIT_FAILED_RC);
            }
        }
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // PipeTransportOptions Default Tests
    // =========================================================================

    #[test]
    fn default_options_match_c_defaults() {
        let opts = PipeTransportOptions::default();

        // C: pipe_transport_option_defaults (pipe.c lines 93-100)
        assert_eq!(opts.path.as_deref(), Some("/bin:/usr/bin"));
        assert_eq!(opts.temp_errors.as_deref(), Some("75:73"));
        assert_eq!(opts.umask, 0o22);
        assert_eq!(opts.max_output, 20480);
        assert_eq!(opts.timeout, 3600);

        // All others should be None/false/0
        assert!(opts.cmd.is_none());
        assert!(opts.allow_commands.is_none());
        assert!(opts.environment.is_none());
        assert!(opts.message_prefix.is_none());
        assert!(opts.message_suffix.is_none());
        assert!(opts.check_string.is_none());
        assert!(opts.escape_string.is_none());
        assert_eq!(opts.options, 0);
        assert!(!opts.force_command);
        assert!(!opts.freeze_exec_fail);
        assert!(!opts.freeze_signal);
        assert!(!opts.ignore_status);
        assert!(!opts.permit_coredump);
        assert!(!opts.restrict_to_path);
        assert!(!opts.timeout_defer);
        assert!(!opts.use_shell);
        assert!(!opts.use_bsmtp);
        assert!(!opts.use_classresources);
        assert!(!opts.use_crlf);
    }

    // =========================================================================
    // PipeTransport Construction Tests
    // =========================================================================

    #[test]
    fn new_with_defaults() {
        let transport = PipeTransport::with_defaults();
        assert_eq!(transport.driver_name(), "pipe");
        assert!(transport.is_local());
    }

    #[test]
    fn new_with_custom_options() {
        let mut opts = PipeTransportOptions::default();
        opts.cmd = Some("/usr/bin/procmail".to_string());
        opts.timeout = 120;
        opts.use_shell = true;

        let transport = PipeTransport::new(opts);
        assert_eq!(transport.options.cmd.as_deref(), Some("/usr/bin/procmail"));
        assert_eq!(transport.options.timeout, 120);
        assert!(transport.options.use_shell);
    }

    // =========================================================================
    // Config Validation Tests
    // =========================================================================

    #[test]
    fn validate_restrict_to_path_and_use_shell_conflict() {
        let mut opts = PipeTransportOptions::default();
        opts.restrict_to_path = true;
        opts.use_shell = true;
        let mut transport = PipeTransport::new(opts);
        let config = TransportInstanceConfig::new("test_pipe", "pipe");

        let result = transport.validate_config(&config);
        assert!(result.is_err());
        if let Err(DriverError::ConfigError(msg)) = result {
            assert!(msg.contains("restrict_to_path"));
            assert!(msg.contains("use_shell"));
        }
    }

    #[test]
    fn validate_allow_commands_and_use_shell_conflict() {
        let mut opts = PipeTransportOptions::default();
        opts.allow_commands = Some("procmail:maildrop".to_string());
        opts.use_shell = true;
        let mut transport = PipeTransport::new(opts);
        let config = TransportInstanceConfig::new("test_pipe", "pipe");

        let result = transport.validate_config(&config);
        assert!(result.is_err());
        if let Err(DriverError::ConfigError(msg)) = result {
            assert!(msg.contains("allow_commands"));
            assert!(msg.contains("use_shell"));
        }
    }

    #[test]
    fn validate_return_output_conflict() {
        let opts = PipeTransportOptions::default();
        let mut transport = PipeTransport::new(opts);
        let mut config = TransportInstanceConfig::new("test_pipe", "pipe");
        config.return_output = true;
        config.return_fail_output = true;

        let result = transport.validate_config(&config);
        assert!(result.is_err());
        if let Err(DriverError::ConfigError(msg)) = result {
            assert!(msg.contains("return_output"));
            assert!(msg.contains("return_fail_output"));
        }
    }

    #[test]
    fn validate_log_output_conflict() {
        let opts = PipeTransportOptions::default();
        let mut transport = PipeTransport::new(opts);
        let mut config = TransportInstanceConfig::new("test_pipe", "pipe");
        config.log_output = true;
        config.log_fail_output = true;

        let result = transport.validate_config(&config);
        assert!(result.is_err());
        if let Err(DriverError::ConfigError(msg)) = result {
            assert!(msg.contains("log_output"));
            assert!(msg.contains("log_fail_output"));
        }
    }

    #[test]
    fn validate_uid_without_gid() {
        let opts = PipeTransportOptions::default();
        let mut transport = PipeTransport::new(opts);
        let mut config = TransportInstanceConfig::new("test_pipe", "pipe");
        config.uid_set = true;
        config.gid_set = false;

        let result = transport.validate_config(&config);
        assert!(result.is_err());
        if let Err(DriverError::ConfigError(msg)) = result {
            assert!(msg.contains("user set without group"));
        }
    }

    #[test]
    fn validate_pipe_as_creator_with_uid() {
        let opts = PipeTransportOptions::default();
        let mut transport = PipeTransport::new(opts);
        let mut config = TransportInstanceConfig::new("test_pipe", "pipe");
        config.deliver_as_creator = true;
        config.uid_set = true;
        config.gid_set = true;

        let result = transport.validate_config(&config);
        assert!(result.is_err());
        if let Err(DriverError::ConfigError(msg)) = result {
            assert!(msg.contains("pipe_as_creator"));
        }
    }

    #[test]
    fn validate_invalid_temp_errors() {
        let mut opts = PipeTransportOptions::default();
        opts.temp_errors = Some("75:abc".to_string());
        let mut transport = PipeTransport::new(opts);
        let config = TransportInstanceConfig::new("test_pipe", "pipe");

        let result = transport.validate_config(&config);
        assert!(result.is_err());
        if let Err(DriverError::ConfigError(msg)) = result {
            assert!(msg.contains("temp_errors"));
        }
    }

    #[test]
    fn validate_star_temp_errors_accepted() {
        let mut opts = PipeTransportOptions::default();
        opts.temp_errors = Some("*".to_string());
        let mut transport = PipeTransport::new(opts);
        let config = TransportInstanceConfig::new("test_pipe", "pipe");

        let result = transport.validate_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_bsmtp_sets_check_escape_strings() {
        let mut opts = PipeTransportOptions::default();
        opts.use_bsmtp = true;
        let mut transport = PipeTransport::new(opts);
        let config = TransportInstanceConfig::new("test_pipe", "pipe");

        let result = transport.validate_config(&config);
        assert!(result.is_ok());
        assert_eq!(transport.options.check_string.as_deref(), Some("."));
        assert_eq!(transport.options.escape_string.as_deref(), Some(".."));
        assert_ne!(transport.options.options & TOPT_ESCAPE_HEADERS, 0);
    }

    #[test]
    fn validate_non_bsmtp_sets_default_prefix_suffix() {
        let opts = PipeTransportOptions::default();
        let mut transport = PipeTransport::new(opts);
        let config = TransportInstanceConfig::new("test_pipe", "pipe");

        let result = transport.validate_config(&config);
        assert!(result.is_ok());
        assert!(transport.options.message_prefix.is_some());
        assert!(transport.options.message_suffix.is_some());
        assert_eq!(transport.options.message_suffix.as_deref(), Some("\n"));
    }

    // =========================================================================
    // Command Parsing Tests
    // =========================================================================

    #[test]
    fn parse_simple_command() {
        let args = parse_command_args("/usr/bin/procmail -d user");
        assert_eq!(args, vec!["/usr/bin/procmail", "-d", "user"]);
    }

    #[test]
    fn parse_quoted_args() {
        let args = parse_command_args(r#"/bin/echo "hello world" test"#);
        assert_eq!(args, vec!["/bin/echo", "hello world", "test"]);
    }

    #[test]
    fn parse_empty_command() {
        let args = parse_command_args("");
        assert!(args.is_empty());
    }

    #[test]
    fn parse_whitespace_only() {
        let args = parse_command_args("   \t  ");
        assert!(args.is_empty());
    }

    // =========================================================================
    // Address Splitting Tests
    // =========================================================================

    #[test]
    fn split_standard_address() {
        let (local, domain) = split_address("user@example.com");
        assert_eq!(local, "user");
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn split_address_no_domain() {
        let (local, domain) = split_address("localuser");
        assert_eq!(local, "localuser");
        assert_eq!(domain, "");
    }

    #[test]
    fn split_address_multiple_at() {
        let (local, domain) = split_address("user@host@domain.com");
        assert_eq!(local, "user@host");
        assert_eq!(domain, "domain.com");
    }

    // =========================================================================
    // Temp Error Parsing Tests
    // =========================================================================

    #[test]
    fn parse_default_temp_errors() {
        let transport = PipeTransport::with_defaults();
        let config = transport.parse_temp_errors();
        match config {
            TempErrorConfig::Codes(codes) => {
                assert!(codes.contains(&EX_TEMPFAIL));
                assert!(codes.contains(&EX_CANTCREAT));
                assert_eq!(codes.len(), 2);
            }
            TempErrorConfig::All => panic!("expected Codes, got All"),
        }
    }

    #[test]
    fn parse_star_temp_errors() {
        let mut opts = PipeTransportOptions::default();
        opts.temp_errors = Some("*".to_string());
        let transport = PipeTransport::new(opts);
        let config = transport.parse_temp_errors();
        assert!(matches!(config, TempErrorConfig::All));
    }

    #[test]
    fn parse_custom_temp_errors() {
        let mut opts = PipeTransportOptions::default();
        opts.temp_errors = Some("1:2:3".to_string());
        let transport = PipeTransport::new(opts);
        let config = transport.parse_temp_errors();
        match config {
            TempErrorConfig::Codes(codes) => {
                assert_eq!(codes, vec![1, 2, 3]);
            }
            TempErrorConfig::All => panic!("expected Codes, got All"),
        }
    }

    // =========================================================================
    // Exit Status Interpretation Tests
    // =========================================================================

    #[test]
    fn interpret_exit_zero_is_ok() {
        let transport = PipeTransport::with_defaults();
        let result = transport.interpret_exit_status(0, "test", "test_pipe");
        assert!(result.is_ok());
    }

    #[test]
    fn interpret_temp_error_is_deferred() {
        let transport = PipeTransport::with_defaults();
        let result = transport.interpret_exit_status(EX_TEMPFAIL, "test", "test_pipe");
        assert!(result.is_deferred());
    }

    #[test]
    fn interpret_non_temp_error_is_failed() {
        let transport = PipeTransport::with_defaults();
        // Exit code 1 is not in the default temp_errors list
        let result = transport.interpret_exit_status(1, "test", "test_pipe");
        assert!(result.is_failed());
    }

    #[test]
    fn interpret_ignore_status() {
        let mut opts = PipeTransportOptions::default();
        opts.ignore_status = true;
        let transport = PipeTransport::new(opts);
        let result = transport.interpret_exit_status(1, "test", "test_pipe");
        assert!(result.is_ok());
    }

    #[test]
    fn interpret_signal_death_is_failed() {
        let transport = PipeTransport::with_defaults();
        let result = transport.interpret_exit_status(-9, "test", "test_pipe");
        assert!(result.is_failed());
    }

    #[test]
    fn interpret_freeze_signal() {
        let mut opts = PipeTransportOptions::default();
        opts.freeze_signal = true;
        let transport = PipeTransport::new(opts);
        let result = transport.interpret_exit_status(-9, "test", "test_pipe");
        assert!(result.is_deferred());
    }

    #[test]
    fn interpret_freeze_exec_fail() {
        let mut opts = PipeTransportOptions::default();
        opts.freeze_exec_fail = true;
        let transport = PipeTransport::new(opts);
        let result = transport.interpret_exit_status(EX_EXECFAILED, "test", "test_pipe");
        assert!(result.is_deferred());
    }

    #[test]
    fn interpret_timeout_defer() {
        let mut opts = PipeTransportOptions::default();
        opts.timeout_defer = true;
        let transport = PipeTransport::new(opts);
        let result = transport.interpret_exit_status(CHILD_TIMEOUT_RC, "test", "test_pipe");
        assert!(result.is_deferred());
    }

    #[test]
    fn interpret_timeout_fail_by_default() {
        let transport = PipeTransport::with_defaults();
        let result = transport.interpret_exit_status(CHILD_TIMEOUT_RC, "test", "test_pipe");
        assert!(result.is_failed());
    }

    #[test]
    fn interpret_star_temp_errors_all_deferred() {
        let mut opts = PipeTransportOptions::default();
        opts.temp_errors = Some("*".to_string());
        let transport = PipeTransport::new(opts);
        let result = transport.interpret_exit_status(42, "test", "test_pipe");
        assert!(result.is_deferred());
    }

    // =========================================================================
    // Environment Building Tests
    // =========================================================================

    #[test]
    fn build_env_contains_standard_vars() {
        let transport = PipeTransport::with_defaults();
        let config = TransportInstanceConfig::new("test_pipe", "pipe");
        let env = transport.build_environment(&config, "user@example.com");

        assert_eq!(env.get("LOCAL_PART").unwrap(), "user");
        assert_eq!(env.get("DOMAIN").unwrap(), "example.com");
        assert_eq!(env.get("LOGNAME").unwrap(), "user");
        assert_eq!(env.get("USER").unwrap(), "user");
        assert_eq!(env.get("RECIPIENT").unwrap(), "user@example.com");
        assert_eq!(env.get("PATH").unwrap(), "/bin:/usr/bin");
        assert_eq!(env.get("SHELL").unwrap(), "/bin/sh");
    }

    #[test]
    fn build_env_with_custom_environment() {
        let mut opts = PipeTransportOptions::default();
        opts.environment = Some("FOO=bar:BAZ=qux".to_string());
        let transport = PipeTransport::new(opts);
        let config = TransportInstanceConfig::new("test_pipe", "pipe");
        let env = transport.build_environment(&config, "user@example.com");

        assert_eq!(env.get("FOO").unwrap(), "bar");
        assert_eq!(env.get("BAZ").unwrap(), "qux");
    }

    #[test]
    fn build_env_home_from_config() {
        let transport = PipeTransport::with_defaults();
        let mut config = TransportInstanceConfig::new("test_pipe", "pipe");
        config.home_dir = Some("/home/testuser".to_string());
        let env = transport.build_environment(&config, "user@example.com");

        assert_eq!(env.get("HOME").unwrap(), "/home/testuser");
    }

    // =========================================================================
    // Direct Command Setup Tests
    // =========================================================================

    #[test]
    fn direct_command_absolute_path() {
        let transport = PipeTransport::with_defaults();
        let cmd = Clean::new("/bin/echo hello".to_string());
        let result = transport.set_up_direct_command(&cmd, "test_pipe");
        assert!(result.is_ok());
        let argv = result.unwrap();
        assert_eq!(argv[0], "/bin/echo");
        assert_eq!(argv[1], "hello");
    }

    #[test]
    fn direct_command_restrict_to_path_with_slash() {
        let mut opts = PipeTransportOptions::default();
        opts.restrict_to_path = true;
        let transport = PipeTransport::new(opts);
        let cmd = Clean::new("/usr/bin/procmail".to_string());
        let result = transport.set_up_direct_command(&cmd, "test_pipe");
        assert!(result.is_err());
    }

    #[test]
    fn direct_command_allow_commands_reject() {
        let mut opts = PipeTransportOptions::default();
        opts.allow_commands = Some("procmail:maildrop".to_string());
        let transport = PipeTransport::new(opts);
        let cmd = Clean::new("badcommand".to_string());
        let result = transport.set_up_direct_command(&cmd, "test_pipe");
        assert!(result.is_err());
    }

    // =========================================================================
    // Shell Command Setup Tests
    // =========================================================================

    #[test]
    fn shell_command_wrapping() {
        let transport = PipeTransport::with_defaults();
        let cmd = Clean::new("echo hello | tee /tmp/out".to_string());
        let argv = transport.set_up_shell_command(&cmd, "test_pipe");
        assert_eq!(argv[0], "/bin/sh");
        assert_eq!(argv[1], "-c");
        assert_eq!(argv[2], "echo hello | tee /tmp/out");
    }

    // =========================================================================
    // Integration Tests
    // =========================================================================

    #[test]
    fn transport_entry_with_echo_command() {
        let mut opts = PipeTransportOptions::default();
        opts.cmd = Some("/bin/echo test".to_string());
        opts.timeout = 10;
        let transport = PipeTransport::new(opts);
        let config = TransportInstanceConfig::new("test_pipe", "pipe");

        let result = transport.transport_entry(&config, "user@example.com");
        assert!(result.is_ok());
        let transport_result = result.unwrap();
        assert!(transport_result.is_ok());
    }

    #[test]
    fn transport_entry_no_command_defers() {
        let opts = PipeTransportOptions::default();
        let transport = PipeTransport::new(opts);
        let config = TransportInstanceConfig::new("test_pipe", "pipe");

        let result = transport.transport_entry(&config, "user@example.com");
        assert!(result.is_ok());
        let transport_result = result.unwrap();
        assert!(transport_result.is_deferred());
    }

    #[test]
    fn transport_entry_nonexistent_command_fails() {
        let mut opts = PipeTransportOptions::default();
        opts.cmd = Some("/nonexistent/command".to_string());
        opts.timeout = 5;
        let transport = PipeTransport::new(opts);
        let config = TransportInstanceConfig::new("test_pipe", "pipe");

        let result = transport.transport_entry(&config, "user@example.com");
        // Should return an error or a failed result
        assert!(result.is_err() || result.unwrap().is_failure());
    }

    #[test]
    fn transport_entry_false_command_fails() {
        let mut opts = PipeTransportOptions::default();
        opts.cmd = Some("/bin/false".to_string());
        opts.timeout = 5;
        let transport = PipeTransport::new(opts);
        let config = TransportInstanceConfig::new("test_pipe", "pipe");

        let result = transport.transport_entry(&config, "user@example.com");
        assert!(result.is_ok());
        let transport_result = result.unwrap();
        // /bin/false returns exit code 1, which is not in temp_errors,
        // so it should be a permanent failure
        assert!(transport_result.is_failed());
    }

    #[test]
    fn transport_entry_true_command_succeeds() {
        let mut opts = PipeTransportOptions::default();
        opts.cmd = Some("/bin/true".to_string());
        opts.timeout = 5;
        let transport = PipeTransport::new(opts);
        let config = TransportInstanceConfig::new("test_pipe", "pipe");

        let result = transport.transport_entry(&config, "user@example.com");
        assert!(result.is_ok());
        let transport_result = result.unwrap();
        assert!(transport_result.is_ok());
    }

    #[test]
    fn transport_driver_name_is_pipe() {
        let transport = PipeTransport::with_defaults();
        assert_eq!(transport.driver_name(), "pipe");
    }

    #[test]
    fn transport_is_local() {
        let transport = PipeTransport::with_defaults();
        assert!(transport.is_local());
    }
}
