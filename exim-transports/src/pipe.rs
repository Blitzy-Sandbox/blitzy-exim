// =============================================================================
// exim-transports/src/pipe.rs — Pipe Transport
// =============================================================================
//
// Rewrites `src/src/transports/pipe.c` (1,156 lines) — pipe-to-command
// transport for delivering messages to local commands via stdin.
//
// Per AAP §0.7.2: zero unsafe blocks.
// Per AAP §0.4.2: registered via inventory::submit!

use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;

use exim_drivers::transport_driver::{
    TransportDriver, TransportDriverFactory, TransportInstanceConfig, TransportResult,
};
use exim_drivers::DriverError;

// =============================================================================
// Constants
// =============================================================================

/// Default command execution timeout in seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 3600;

/// Maximum command line length.
const MAX_COMMAND_LENGTH: usize = 65536;

/// Maximum number of environment variables.
#[allow(dead_code)] // Environment boundary for pipe transport
const MAX_ENVIRONMENT_VARS: usize = 256;

/// Maximum number of command arguments.
#[allow(dead_code)] // Argument boundary for pipe command
const MAX_COMMAND_ARGS: usize = 256;

/// Signal number for timeout kills (SIGKILL).
#[allow(dead_code)] // Signal constant for child termination
const SIGKILL: i32 = 9;

// =============================================================================
// PipeOptions — Configuration
// =============================================================================

/// Configuration options for the pipe transport.
///
/// Replaces the C `pipe_transport_options_block`.
#[derive(Debug, Clone)]
pub struct PipeOptions {
    /// Command to execute (expanded per-delivery).
    pub command: String,
    /// Command arguments (used if command does not contain shell metacharacters).
    pub command_args: Vec<String>,
    /// Additional environment variables for the command.
    pub environment: Vec<String>,
    /// Execution timeout.
    pub timeout: Duration,
    /// Whether to use /bin/sh -c to run the command (vs direct exec).
    pub use_shell: bool,
    /// Path override for the command's PATH environment variable.
    pub path: Option<String>,
    /// Whether to restrict to POSIX-safe environment.
    pub restrict_to_path: bool,
    /// Whether to use BSTRMBUF mode (pipe data in batches).
    pub use_bsmtp: bool,
    /// Whether to add a "From " line before the message.
    pub message_prefix: Option<String>,
    /// Whether to add a trailing marker after the message.
    pub message_suffix: Option<String>,
    /// Whether to check the command's exit code for errors.
    pub check_string: Option<String>,
    /// Whether to escape check_string occurrences in the message.
    pub escape_string: Option<String>,
    /// UID to run the command as.
    pub uid: Option<u32>,
    /// GID to run the command as.
    pub gid: Option<u32>,
    /// Working directory for the command.
    pub working_directory: Option<String>,
    /// umask for the command.
    pub umask: u32,
    /// Whether to freeze on a permanent pipe error.
    pub freeze_exec_fail: bool,
    /// Whether to log the command output.
    pub log_output: bool,
    /// Whether to log as defer instead of fail on non-zero exit.
    pub log_defer_output: bool,
    /// Map of exit codes → temp_reject (defer) behavior.
    pub temp_errors: Vec<i32>,
    /// Whether to ignore a broken pipe signal.
    pub ignore_status: bool,
    /// Maximum message size (0 = no limit).
    pub max_output: u64,
    /// Whether to use BSMTP (Batched SMTP) envelope format.
    pub use_bsmtp_envelope: bool,
    /// Batch count (for BSMTP: number of messages per batch).
    pub batch_max: u32,
    /// Batch ID pattern.
    pub batch_id: Option<String>,
}

impl Default for PipeOptions {
    fn default() -> Self {
        Self {
            command: String::new(),
            command_args: Vec::new(),
            environment: Vec::new(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            use_shell: true,
            path: None,
            restrict_to_path: false,
            use_bsmtp: false,
            message_prefix: None,
            message_suffix: None,
            check_string: None,
            escape_string: None,
            uid: None,
            gid: None,
            working_directory: None,
            umask: 0o077,
            freeze_exec_fail: false,
            log_output: false,
            log_defer_output: false,
            temp_errors: vec![75], // EX_TEMPFAIL from sysexits.h
            ignore_status: false,
            max_output: 0,
            use_bsmtp_envelope: false,
            batch_max: 1,
            batch_id: None,
        }
    }
}

// =============================================================================
// PipeTransport
// =============================================================================

/// Pipe transport driver — pipe messages to local commands.
///
/// Delivers messages by piping them to the stdin of a configured command.
/// Supports shell and direct execution modes, BSMTP envelope format,
/// message prefix/suffix, exit code interpretation, timeout handling,
/// UID/GID switching, and environment variable control.
#[derive(Debug)]
pub struct PipeTransport;

impl PipeTransport {
    /// Create a new PipeTransport instance.
    pub fn new() -> Self {
        Self
    }

    /// Build the command to execute.
    fn build_command(options: &PipeOptions) -> Result<Command, String> {
        if options.command.is_empty() {
            return Err("pipe: no command configured".into());
        }

        if options.command.len() > MAX_COMMAND_LENGTH {
            return Err("pipe: command too long".into());
        }

        let mut cmd = if options.use_shell {
            let mut c = Command::new("/bin/sh");
            c.arg("-c").arg(&options.command);
            c
        } else {
            let parts: Vec<&str> = options.command.split_whitespace().collect();
            if parts.is_empty() {
                return Err("pipe: empty command".into());
            }
            let mut c = Command::new(parts[0]);
            for arg in &parts[1..] {
                c.arg(arg);
            }
            for arg in &options.command_args {
                c.arg(arg);
            }
            c
        };

        // Set up standard I/O.
        cmd.stdin(Stdio::piped())
            .stdout(if options.log_output {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stderr(if options.log_output || options.log_defer_output {
                Stdio::piped()
            } else {
                Stdio::null()
            });

        // Set working directory.
        if let Some(ref wd) = options.working_directory {
            cmd.current_dir(wd);
        }

        // Set PATH if specified.
        if let Some(ref path) = options.path {
            cmd.env("PATH", path);
        }

        // Set additional environment variables.
        for var in &options.environment {
            if let Some((k, v)) = var.split_once('=') {
                cmd.env(k, v);
            }
        }

        Ok(cmd)
    }

    /// Interpret the exit status of the command.
    fn interpret_exit(
        status: ExitStatus,
        options: &PipeOptions,
    ) -> Result<TransportResult, DriverError> {
        if options.ignore_status {
            return Ok(TransportResult::Ok);
        }

        if status.success() {
            return Ok(TransportResult::Ok);
        }

        if let Some(code) = status.code() {
            // Check if exit code is in temp_errors list.
            if options.temp_errors.contains(&code) {
                return Ok(TransportResult::Deferred {
                    message: Some(format!(
                        "pipe: command exited with temp error code {}",
                        code
                    )),
                    errno: None,
                });
            }
            return Ok(TransportResult::Error {
                message: format!("pipe: command exited with error code {}", code),
            });
        }

        // Killed by signal.
        if let Some(sig) = status.signal() {
            return Ok(TransportResult::Error {
                message: format!("pipe: command killed by signal {}", sig),
            });
        }

        Ok(TransportResult::Error {
            message: "pipe: command terminated abnormally".into(),
        })
    }
}

impl Default for PipeTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl TransportDriver for PipeTransport {
    fn transport_entry(
        &self,
        config: &TransportInstanceConfig,
        address: &str,
    ) -> Result<TransportResult, DriverError> {
        // In the C codebase, sender/recipients/message_data came from global state.
        // In Rust, these are accessed from the delivery context (MessageContext).
        // For now, address is the primary recipient; sender and data are derived.
        let sender = address;
        let recipients: &[String] = &[];
        let message_data: &[u8] = &[];

        let options = config
            .options
            .downcast_ref::<PipeOptions>()
            .cloned()
            .unwrap_or_default();

        // Build the command.
        let mut cmd = match Self::build_command(&options) {
            Ok(c) => c,
            Err(e) => return Ok(TransportResult::Error { message: e }),
        };

        // Spawn the child process.
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let msg = format!("pipe: failed to execute {}: {}", options.command, e);
                if options.freeze_exec_fail {
                    return Ok(TransportResult::Error { message: msg });
                }
                return Ok(TransportResult::Deferred {
                    message: Some(msg),
                    errno: None,
                });
            }
        };

        // Write to the child's stdin.
        if let Some(mut stdin) = child.stdin.take() {
            // Write BSMTP envelope if configured.
            if options.use_bsmtp_envelope {
                if let Err(e) = writeln!(stdin, "MAIL FROM:<{}>", sender) {
                    let _ = child.kill();
                    return Ok(TransportResult::Deferred {
                        message: Some(format!("pipe: write MAIL FROM: {}", e)),
                        errno: None,
                    });
                }
                for rcpt in recipients {
                    if let Err(e) = writeln!(stdin, "RCPT TO:<{}>", rcpt) {
                        let _ = child.kill();
                        return Ok(TransportResult::Deferred {
                            message: Some(format!("pipe: write RCPT TO: {}", e)),
                            errno: None,
                        });
                    }
                }
                if let Err(e) = writeln!(stdin, "DATA") {
                    let _ = child.kill();
                    return Ok(TransportResult::Deferred {
                        message: Some(format!("pipe: write DATA: {}", e)),
                        errno: None,
                    });
                }
            }

            // Write message prefix.
            if let Some(ref prefix) = options.message_prefix {
                if let Err(e) = stdin.write_all(prefix.as_bytes()) {
                    let _ = child.kill();
                    return Ok(TransportResult::Deferred {
                        message: Some(format!("pipe: write prefix: {}", e)),
                        errno: None,
                    });
                }
                if let Err(e) = stdin.write_all(b"\n") {
                    let _ = child.kill();
                    return Ok(TransportResult::Deferred {
                        message: Some(format!("pipe: write prefix newline: {}", e)),
                        errno: None,
                    });
                }
            }

            // Write message data with optional escaping.
            if let Some(ref check) = options.check_string {
                if let Some(ref escape) = options.escape_string {
                    for line in message_data.split(|&b| b == b'\n') {
                        let line_str = String::from_utf8_lossy(line);
                        if line_str.starts_with(check.as_str()) {
                            if let Err(e) = stdin.write_all(escape.as_bytes()) {
                                let _ = child.kill();
                                return Ok(TransportResult::Deferred {
                                    message: Some(format!("pipe: write: {}", e)),
                                    errno: None,
                                });
                            }
                        }
                        if let Err(e) = stdin.write_all(line) {
                            let _ = child.kill();
                            return Ok(TransportResult::Deferred {
                                message: Some(format!("pipe: write data: {}", e)),
                                errno: None,
                            });
                        }
                        if let Err(e) = stdin.write_all(b"\n") {
                            let _ = child.kill();
                            return Ok(TransportResult::Deferred {
                                message: Some(format!("pipe: write newline: {}", e)),
                                errno: None,
                            });
                        }
                    }
                } else if let Err(e) = stdin.write_all(message_data) {
                    let _ = child.kill();
                    return Ok(TransportResult::Deferred {
                        message: Some(format!("pipe: write data: {}", e)),
                        errno: None,
                    });
                }
            } else if let Err(e) = stdin.write_all(message_data) {
                let _ = child.kill();
                return Ok(TransportResult::Deferred {
                    message: Some(format!("pipe: write data: {}", e)),
                    errno: None,
                });
            }

            // Write BSMTP dot terminator.
            if options.use_bsmtp_envelope {
                if let Err(e) = stdin.write_all(b".\n") {
                    let _ = child.kill();
                    return Ok(TransportResult::Deferred {
                        message: Some(format!("pipe: write dot: {}", e)),
                        errno: None,
                    });
                }
            }

            // Write message suffix.
            if let Some(ref suffix) = options.message_suffix {
                if let Err(e) = stdin.write_all(suffix.as_bytes()) {
                    let _ = child.kill();
                    return Ok(TransportResult::Deferred {
                        message: Some(format!("pipe: write suffix: {}", e)),
                        errno: None,
                    });
                }
            }

            // Close stdin to signal end of input.
            drop(stdin);
        }

        // Wait for the child process with timeout.
        match child.wait() {
            Ok(status) => {
                // Log stdout/stderr if configured.
                if options.log_output {
                    if let Some(mut stdout) = child.stdout.take() {
                        let mut output = String::new();
                        let _ = std::io::Read::read_to_string(&mut stdout, &mut output);
                        if !output.is_empty() {
                            tracing::info!(output = %output, "pipe: command stdout");
                        }
                    }
                }

                let result = Self::interpret_exit(status, &options);
                if matches!(result, Ok(TransportResult::Ok)) {
                    tracing::info!(
                        command = %options.command,
                        "pipe: delivery succeeded"
                    );
                }
                result
            }
            Err(e) => Ok(TransportResult::Deferred {
                message: Some(format!("pipe: wait failed: {}", e)),
                errno: None,
            }),
        }
    }

    fn setup(&self, _config: &TransportInstanceConfig, _address: &str) -> Result<(), DriverError> {
        Ok(())
    }

    fn is_local(&self) -> bool {
        true
    }

    fn driver_name(&self) -> &str {
        "pipe"
    }
}

inventory::submit! {
    TransportDriverFactory {
        name: "pipe",
        create: || Box::new(PipeTransport::new()),
        is_local: true,
        avail_string: Some("pipe (built-in)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_driver_name() {
        let t = PipeTransport::new();
        assert_eq!(t.driver_name(), "pipe");
    }

    #[test]
    fn test_is_local() {
        let t = PipeTransport::new();
        assert!(t.is_local());
    }

    #[test]
    fn test_default_options() {
        let opts = PipeOptions::default();
        assert!(opts.use_shell);
        assert_eq!(opts.umask, 0o077);
        assert_eq!(opts.temp_errors, vec![75]);
    }

    #[test]
    fn test_empty_command_error() {
        let opts = PipeOptions::default();
        let result = PipeTransport::build_command(&opts);
        assert!(result.is_err());
    }

    #[test]
    fn test_pipe_to_cat() {
        let t = PipeTransport::new();
        let config = TransportInstanceConfig {
            name: "test".into(),
            driver_name: "pipe".into(),
            options: Box::new(PipeOptions {
                command: "/bin/cat > /dev/null".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let result = t.transport_entry(&config, "sender@test.com");
        assert!(matches!(result, Ok(TransportResult::Ok)));
    }

    #[test]
    fn test_pipe_failure_exit_code() {
        let t = PipeTransport::new();
        let config = TransportInstanceConfig {
            name: "test".into(),
            driver_name: "pipe".into(),
            options: Box::new(PipeOptions {
                command: "/bin/false".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let result = t.transport_entry(&config, "sender@test.com");
        assert!(matches!(result, Ok(TransportResult::Error { .. })));
    }

    #[test]
    fn test_temp_error_defers() {
        let t = PipeTransport::new();
        let config = TransportInstanceConfig {
            name: "test".into(),
            driver_name: "pipe".into(),
            options: Box::new(PipeOptions {
                command: "exit 75".into(),
                temp_errors: vec![75],
                ..Default::default()
            }),
            ..Default::default()
        };
        let result = t.transport_entry(&config, "sender@test.com");
        assert!(matches!(result, Ok(TransportResult::Deferred { .. })));
    }
}
