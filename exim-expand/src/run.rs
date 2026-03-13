// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! `${run{command}{yes}{no}}` expansion item — external command execution.
//!
//! This module replaces the C `EITEM_RUN` handler from `expand.c`
//! lines 5818–5975 (~157 lines of C code).  It provides:
//!
//! - **Option parsing** — recognises `,preexpand` preceding the command
//!   argument (expand.c lines 5832–5843).
//! - **Command setup** — parses the command string into an argument
//!   vector respecting shell-like quoting (replacing the C
//!   `transport_set_up_command()` call at line 5889).
//! - **Child process creation** — spawns the child as a new process
//!   group leader with umask `0o077` (replacing `child_open()` at
//!   line 5900 with `group_leader = TRUE`).
//! - **Stdout capture with timeout** — reads all child output with a
//!   configurable timeout, matching the C `ALARM(60)` at line 5921.
//! - **Exit code handling** — captures the exit code for `$runrc` and
//!   detects timeout, signal death, and `wait()` failure (lines 5930–5947).
//!
//! # Safety
//!
//! This module contains **zero `unsafe` blocks**.  All POSIX operations
//! are performed through the safe `nix` crate API and
//! `std::process::Command`.  Process-group management uses
//! [`CommandExt::process_group(0)`](std::os::unix::process::CommandExt::process_group)
//! (stable since Rust 1.64).

// ── Standard library imports ────────────────────────────────────────────
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::process::{CommandExt, ExitStatusExt};

// ── External crate imports ──────────────────────────────────────────────
use nix::sys::signal::{killpg, Signal};
use nix::sys::stat::{umask, Mode};
use nix::unistd::Pid;

// ── Internal crate imports ──────────────────────────────────────────────
use crate::evaluator::Evaluator;
use crate::{ExpandError, RDO_RUN};

// ═══════════════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════════════

/// Default timeout for reading child stdout (seconds).
///
/// Matches the C `ALARM(60)` call at expand.c line 5921.  If the child
/// process does not close its stdout within this duration, the entire
/// process group is killed via `killpg(pid, SIGKILL)`.
const READ_TIMEOUT_SECS: u64 = 60;

/// Timeout for the child-close wait after stdout has been read (seconds).
///
/// Matches the C `child_close(pid, 30)` call at expand.c line 5930.
/// Combined with [`READ_TIMEOUT_SECS`] to form the total timeout for
/// the channel receive.
const WAIT_TIMEOUT_SECS: u64 = 30;

// ═══════════════════════════════════════════════════════════════════════
//  RunOptions
// ═══════════════════════════════════════════════════════════════════════

/// Options controlling `${run}` command execution behaviour.
///
/// Parsed from the optional comma-separated option list preceding the
/// braced command argument in the expansion string:
///
/// ```text
/// ${run,preexpand{/usr/bin/cmd arg1 arg2}{yes}{no}}
/// ```
///
/// Replaces the C `late_expand` flags mechanism from expand.c lines
/// 5822, 5832–5843.
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// When `true`, the command string is fully expanded *before* being
    /// split into an argument vector.  This corresponds to the
    /// `,preexpand` option in C (expand.c line 5833: `late_expand = 0`).
    ///
    /// Default is `false` (late expansion): the raw command string is
    /// split first, then each argument element is expanded individually
    /// during `transport_set_up_command()`.  In the Rust implementation,
    /// the caller is responsible for applying the appropriate expansion
    /// strategy before passing the command string to [`eval_run`].
    pub preexpand: bool,
}

impl Default for RunOptions {
    /// Returns the default run options (late expansion, no preexpand).
    #[inline]
    fn default() -> Self {
        Self { preexpand: false }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  RunResult
// ═══════════════════════════════════════════════════════════════════════

/// Result of an external command execution via `${run}`.
///
/// On success, the exit code is stored for `$runrc` variable access
/// (expand.c lines 5930–5947) and the captured stdout is stored as
/// `$value` / `lookup_value` (expand.c line 5922).
#[derive(Debug, Clone)]
pub struct RunResult {
    /// Child process exit code.
    ///
    /// Stored globally as `$runrc` for subsequent expansion access.
    /// A value of 0 indicates success; non-zero indicates failure.
    /// The yes/no branch selection uses `exit_code == 0` as the
    /// success indicator (expand.c line 5952: `runrc == 0`).
    pub exit_code: i32,

    /// Captured stdout from the child process.
    ///
    /// Stored as `lookup_value` (`$value`) for use in the yes/no
    /// branches of the expansion item.  `None` if the child produced
    /// no output.
    pub output: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════
//  Main entry point
// ═══════════════════════════════════════════════════════════════════════

/// Execute an external command for `${run{command}{yes}{no}}` expansion.
///
/// This is the main entry point replacing the C `EITEM_RUN` handler
/// (expand.c lines 5818–5975).  The function:
///
/// 1. Checks `expand_forbid` for `RDO_RUN` (line 5824)
/// 2. Parses the command string into an argument vector
/// 3. Creates a child process as a new process group leader
/// 4. Reads stdout with a timeout
/// 5. Waits for exit and captures the exit code
/// 6. Updates `evaluator.lookup_value` with captured output
///
/// # Arguments
///
/// * `command`   — The command string to execute.  If
///   [`RunOptions::preexpand`] is `true`, this string should have been
///   fully expanded by the caller before passing it here.
/// * `options`   — Parsed options (currently only `preexpand`).
/// * `evaluator` — Mutable reference to the evaluator for state updates.
///
/// # Errors
///
/// Returns [`ExpandError::Failed`] for:
/// - `RDO_RUN` forbid check (`"running a command is not permitted"`)
/// - Empty command
/// - Argument parsing failure (unterminated quotes)
/// - Child process creation failure (`"couldn't create child process: …"`)
/// - Command timeout (`"command timed out"`)
/// - `wait()` failure
/// - Signal death (`"command killed by signal N"`)
///
/// # Examples
///
/// ```ignore
/// use exim_expand::run::{eval_run, RunOptions, RunResult};
///
/// let opts = RunOptions::default();
/// let result = eval_run("/bin/echo hello", opts, &mut evaluator)?;
/// assert_eq!(result.exit_code, 0);
/// assert_eq!(result.output, Some("hello\n".to_string()));
/// ```
pub fn eval_run(
    command: &str,
    options: RunOptions,
    evaluator: &mut Evaluator<'_>,
) -> Result<RunResult, ExpandError> {
    // ── Step 1: Check expansion forbid flags ────────────────────────────
    // Replaces expand.c lines 5824–5828:
    //   if (expand_forbid & RDO_RUN) {
    //     expand_string_message = US"running a command is not permitted";
    //     goto EXPAND_FAILED;
    //   }
    if evaluator.expand_forbid & RDO_RUN != 0 {
        return Err(ExpandError::Failed {
            message: "running a command is not permitted".into(),
        });
    }

    tracing::debug!(
        command = %command,
        preexpand = options.preexpand,
        "eval_run: ${{run}} expansion entry"
    );

    // ── Step 2: Reset evaluator state ───────────────────────────────────
    // Clear state from any previous expansion items.  The ${run} handler
    // does not produce forced failures or search deferrals — these flags
    // are reset so that downstream yes/no processing sees clean state.
    evaluator.forced_fail = false;
    evaluator.search_find_defer = false;

    // ── Step 3: Validate the command string ─────────────────────────────
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return Err(ExpandError::Failed {
            message: "missing '{' for command arg of run".into(),
        });
    }

    // ── Step 4: Parse command string into argv ──────────────────────────
    // Replaces the C transport_set_up_command() call at expand.c line 5889.
    // Performs shell-like splitting respecting single/double quotes and
    // backslash escaping.
    let argv = parse_command_to_argv(trimmed)?;
    if argv.is_empty() {
        return Err(ExpandError::Failed {
            message: "no arguments after parsing command for ${run}".into(),
        });
    }

    tracing::debug!(
        argv_0 = %argv[0],
        argc = argv.len(),
        "eval_run: parsed command to argv"
    );

    // ── Step 5: Build the Command ───────────────────────────────────────
    let mut cmd = Command::new(&argv[0]);
    if argv.len() > 1 {
        cmd.args(&argv[1..]);
    }
    cmd.stdin(Stdio::null()) // Nothing written to stdin (expand.c line 5910)
        .stdout(Stdio::piped()) // Capture stdout (expand.c line 5919)
        .stderr(Stdio::null()); // stderr not captured in C implementation

    // ── Step 5a: Set process group leader (Unix only) ───────────────────
    // Replaces child_open() group_leader=TRUE at expand.c line 5900.
    // Creates the child as its own process group leader so that
    // killpg(pid, SIGKILL) on timeout kills the entire tree.
    #[cfg(unix)]
    cmd.process_group(0);

    // ── Step 5b: Set umask to 0077 ─────────────────────────────────────
    // Replaces child_open(USS argv, NULL, 0077, ...) at expand.c line 5900.
    // In C this happens between fork and exec; in Rust we set it in the
    // parent before spawn and restore immediately after.  This is safe in
    // the fork-per-connection model (single-threaded within each process).
    let old_umask = umask(Mode::from_bits_truncate(0o077));

    let spawn_result = cmd.spawn();

    // Restore the parent's original umask immediately.
    umask(old_umask);

    let mut child = spawn_result.map_err(|e| {
        tracing::warn!(error = %e, "eval_run: couldn't create child process");
        ExpandError::Failed {
            message: format!("couldn't create child process: {}", e),
        }
    })?;

    // Capture PID for potential timeout kill.
    let child_pid_raw = child.id() as i32;

    tracing::debug!(
        pid = child_pid_raw,
        "eval_run: child process created as group leader"
    );

    // ── Step 6: Read stdout with timeout ────────────────────────────────
    // Replaces expand.c lines 5918–5924:
    //   resetok = FALSE;
    //   f = fdopen(fd_out, "rb");
    //   sigalrm_seen = FALSE;
    //   ALARM(60);
    //   lookup_value = string_from_gstring(cat_file(f, NULL, NULL));
    //   ALARM_CLR(0);
    //   (void)fclose(f);
    //
    // We use a background thread + channel with a combined timeout for
    // the read and wait phases.  This avoids `unsafe` signal handling
    // and is idiomatic Rust.

    let total_timeout = Duration::from_secs(READ_TIMEOUT_SECS + WAIT_TIMEOUT_SECS);
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        // Read all stdout from the child process.
        let mut captured = String::new();
        if let Some(mut stdout) = child.stdout.take() {
            // read_to_string blocks until EOF (child closes stdout).
            let _ = stdout.read_to_string(&mut captured);
        }

        // Wait for the child to finish and collect exit status.
        // Replaces child_close(pid, 30) at expand.c line 5930.
        let status = child.wait();

        // Send results back; ignore send errors (receiver may have timed out).
        let _ = tx.send((captured, status));
    });

    // ── Step 7: Receive results or handle timeout ───────────────────────
    match rx.recv_timeout(total_timeout) {
        Ok((captured_output, wait_result)) => {
            process_child_result(captured_output, wait_result, child_pid_raw, evaluator)
        }

        Err(mpsc::RecvTimeoutError::Timeout) => {
            // Timeout — kill the entire process group.
            // Replaces expand.c lines 5932–5936:
            //   expand_string_message = US"command timed out";
            //   killpg(pid, SIGKILL);
            tracing::warn!(
                pid = child_pid_raw,
                timeout_secs = READ_TIMEOUT_SECS + WAIT_TIMEOUT_SECS,
                "eval_run: command timed out, killing process group"
            );
            let _ = killpg(Pid::from_raw(child_pid_raw), Signal::SIGKILL);
            Err(ExpandError::Failed {
                message: "command timed out".into(),
            })
        }

        Err(mpsc::RecvTimeoutError::Disconnected) => {
            // Thread panicked or was dropped — should not happen in practice.
            tracing::warn!(
                pid = child_pid_raw,
                "eval_run: child monitoring thread disconnected unexpectedly"
            );
            // Attempt cleanup: kill the process group as a safety measure.
            let _ = killpg(Pid::from_raw(child_pid_raw), Signal::SIGKILL);
            Err(ExpandError::Failed {
                message: "command timed out".into(),
            })
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Internal helpers
// ═══════════════════════════════════════════════════════════════════════

/// Process the child's captured output and exit status.
///
/// Handles three outcomes from the C code (expand.c lines 5930–5947):
///
/// 1. **Normal exit** — exit code ≥ 0; output stored as `lookup_value`.
/// 2. **Signal death** — on Unix, `ExitStatus::signal()` is `Some(sig)`;
///    returns `ExpandError::Failed` with `"command killed by signal N"`.
/// 3. **wait() failure** — `child.wait()` returned `Err`; returns
///    `ExpandError::Failed` with `"wait() failed: …"`.
fn process_child_result(
    captured_output: String,
    wait_result: std::io::Result<std::process::ExitStatus>,
    child_pid_raw: i32,
    evaluator: &mut Evaluator<'_>,
) -> Result<RunResult, ExpandError> {
    let status = wait_result.map_err(|e| {
        // Replaces expand.c lines 5938–5940:
        //   expand_string_message = string_sprintf("wait() failed: %s",
        //     strerror(errno));
        tracing::warn!(
            pid = child_pid_raw,
            error = %e,
            "eval_run: wait() failed"
        );
        ExpandError::Failed {
            message: format!("wait() failed: {}", e),
        }
    })?;

    // ── Determine exit code or signal ───────────────────────────────
    let exit_code = extract_exit_code(status, child_pid_raw)?;

    tracing::debug!(
        pid = child_pid_raw,
        exit_code = exit_code,
        output_len = captured_output.len(),
        "eval_run: child process completed"
    );

    // ── Store captured output as lookup_value ($value) ──────────────
    // Replaces expand.c line 5922:
    //   lookup_value = string_from_gstring(cat_file(f, NULL, NULL));
    //
    // The C code stores the raw output (including any trailing newline)
    // in lookup_value.  We preserve this behaviour exactly.
    let output = if captured_output.is_empty() {
        evaluator.lookup_value = None;
        None
    } else {
        evaluator.lookup_value = Some(captured_output.clone());
        Some(captured_output)
    };

    Ok(RunResult { exit_code, output })
}

/// Extract a numeric exit code from an `ExitStatus`, or return an error
/// if the process was terminated by a signal.
///
/// On Unix, processes killed by a signal have no exit code but do report
/// the signal number via [`ExitStatusExt::signal()`].  The C code
/// reports this as `"command killed by signal N"` (expand.c lines
/// 5942–5944).
fn extract_exit_code(
    status: std::process::ExitStatus,
    child_pid_raw: i32,
) -> Result<i32, ExpandError> {
    // Try the normal exit code first.
    if let Some(code) = status.code() {
        return Ok(code);
    }

    // On Unix: the process was killed by a signal.
    #[cfg(unix)]
    {
        if let Some(signal) = status.signal() {
            tracing::warn!(
                pid = child_pid_raw,
                signal = signal,
                "eval_run: command killed by signal"
            );
            return Err(ExpandError::Failed {
                message: format!("command killed by signal {}", signal),
            });
        }
    }

    // Fallback: neither exit code nor signal (should not happen).
    let _ = child_pid_raw; // suppress unused-variable warning on non-Unix
    Err(ExpandError::Failed {
        message: "command terminated abnormally".into(),
    })
}

/// Parse a command string into an argument vector (argv).
///
/// Implements shell-like word splitting with the following quoting rules:
///
/// - **Single quotes** (`'…'`): contents are literal — no escaping
///   inside single quotes.
/// - **Double quotes** (`"…"`): backslash escapes for `"`, `\`, `$`,
///   and `` ` `` are recognised; all other backslashes are literal.
/// - **Backslash** outside quotes: the next character is literal.
/// - **Whitespace** (space, tab, newline) separates arguments.
///
/// This replaces the command-parsing portion of
/// `transport_set_up_command()` (expand.c line 5889) for the `${run}`
/// expansion context.
///
/// # Errors
///
/// Returns [`ExpandError::Failed`] if a quote is not properly closed.
fn parse_command_to_argv(command: &str) -> Result<Vec<String>, ExpandError> {
    let mut argv: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut chars = command.chars().peekable();
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    while let Some(ch) = chars.next() {
        if in_single_quote {
            // Inside single quotes: everything is literal except closing quote.
            if ch == '\'' {
                in_single_quote = false;
            } else {
                current.push(ch);
            }
        } else if in_double_quote {
            // Inside double quotes: backslash escapes for special chars.
            if ch == '"' {
                in_double_quote = false;
            } else if ch == '\\' {
                if let Some(&next) = chars.peek() {
                    match next {
                        '"' | '\\' | '$' | '`' => {
                            current.push(next);
                            chars.next();
                        }
                        _ => {
                            // Backslash is literal for non-special chars.
                            current.push(ch);
                            current.push(next);
                            chars.next();
                        }
                    }
                } else {
                    // Trailing backslash at end of input.
                    current.push(ch);
                }
            } else {
                current.push(ch);
            }
        } else {
            // Unquoted context.
            match ch {
                '\'' => {
                    in_single_quote = true;
                }
                '"' => {
                    in_double_quote = true;
                }
                '\\' => {
                    // Escape the next character.
                    if let Some(next) = chars.next() {
                        current.push(next);
                    }
                    // Trailing backslash: ignore (matches C behaviour).
                }
                ' ' | '\t' | '\n' | '\r' => {
                    // Whitespace splits arguments.
                    if !current.is_empty() {
                        argv.push(std::mem::take(&mut current));
                    }
                }
                _ => {
                    current.push(ch);
                }
            }
        }
    }

    // ── Detect unterminated quotes ──────────────────────────────────────
    if in_single_quote {
        return Err(ExpandError::Failed {
            message: "unterminated single quote in command for ${run}".into(),
        });
    }
    if in_double_quote {
        return Err(ExpandError::Failed {
            message: "unterminated double quote in command for ${run}".into(),
        });
    }

    // Push the final argument if non-empty.
    if !current.is_empty() {
        argv.push(current);
    }

    Ok(argv)
}

/// Parse the option string preceding the `${run}` command argument.
///
/// Recognises the following comma-prefixed options (expand.c lines
/// 5832–5843):
///
/// - `,preexpand` — expand the command string before splitting into
///   argv.  Sets [`RunOptions::preexpand`] to `true`.
///
/// Any other `,option` produces an error:
/// `"bad option '{option}' for run"`.
///
/// # Arguments
///
/// * `option_str` — The raw option text (e.g. `",preexpand"` or `""`).
///
/// # Returns
///
/// The parsed [`RunOptions`] on success, or [`ExpandError::Failed`] if
/// an unrecognised option is encountered.
///
/// # Examples
///
/// ```ignore
/// let opts = parse_run_options(",preexpand")?;
/// assert!(opts.preexpand);
///
/// let default_opts = parse_run_options("")?;
/// assert!(!default_opts.preexpand);
/// ```
pub fn parse_run_options(option_str: &str) -> Result<RunOptions, ExpandError> {
    let mut options = RunOptions::default();
    let mut remaining = option_str;

    while let Some(rest) = remaining.strip_prefix(',') {
        remaining = rest;

        if remaining.starts_with("preexpand") {
            options.preexpand = true;
            remaining = &remaining["preexpand".len()..];
        } else {
            // Extract the bad option name: consecutive alphabetic characters.
            // Matches C logic at expand.c lines 5837–5841:
            //   const uschar * t = s;
            //   while (isalpha(*++t)) ;
            //   expand_string_message = string_sprintf("bad option '%.*s' for run",
            //     (int)(t-s), s);
            let end = remaining
                .find(|c: char| !c.is_ascii_alphabetic())
                .unwrap_or(remaining.len());
            let bad_option = &remaining[..end];
            return Err(ExpandError::Failed {
                message: format!("bad option '{}' for run", bad_option),
            });
        }
    }

    Ok(options)
}

// ═══════════════════════════════════════════════════════════════════════
//  Unit tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_command_to_argv tests ─────────────────────────────────────

    #[test]
    fn test_argv_simple() {
        let argv = parse_command_to_argv("/bin/echo hello world").unwrap();
        assert_eq!(argv, vec!["/bin/echo", "hello", "world"]);
    }

    #[test]
    fn test_argv_single_quotes() {
        let argv = parse_command_to_argv("/bin/echo 'hello world'").unwrap();
        assert_eq!(argv, vec!["/bin/echo", "hello world"]);
    }

    #[test]
    fn test_argv_double_quotes() {
        let argv = parse_command_to_argv(r#"/bin/echo "hello world""#).unwrap();
        assert_eq!(argv, vec!["/bin/echo", "hello world"]);
    }

    #[test]
    fn test_argv_backslash_escape() {
        let argv = parse_command_to_argv(r"/bin/echo hello\ world").unwrap();
        assert_eq!(argv, vec!["/bin/echo", "hello world"]);
    }

    #[test]
    fn test_argv_double_quote_backslash() {
        let argv = parse_command_to_argv(r#"/bin/echo "hello\"world""#).unwrap();
        assert_eq!(argv, vec!["/bin/echo", r#"hello"world"#]);
    }

    #[test]
    fn test_argv_empty_string() {
        let argv = parse_command_to_argv("").unwrap();
        assert!(argv.is_empty());
    }

    #[test]
    fn test_argv_whitespace_only() {
        let argv = parse_command_to_argv("   ").unwrap();
        assert!(argv.is_empty());
    }

    #[test]
    fn test_argv_unterminated_single_quote() {
        let result = parse_command_to_argv("echo 'unterminated");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("unterminated single quote"));
    }

    #[test]
    fn test_argv_unterminated_double_quote() {
        let result = parse_command_to_argv(r#"echo "unterminated"#);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("unterminated double quote"));
    }

    #[test]
    fn test_argv_adjacent_quotes() {
        let argv = parse_command_to_argv("echo 'hello'' world'").unwrap();
        assert_eq!(argv, vec!["echo", "hello world"]);
    }

    #[test]
    fn test_argv_mixed_quotes() {
        let argv = parse_command_to_argv(r#"echo "hello"' world'"#).unwrap();
        assert_eq!(argv, vec!["echo", "hello world"]);
    }

    #[test]
    fn test_argv_multiple_spaces() {
        let argv = parse_command_to_argv("/bin/cmd   arg1   arg2").unwrap();
        assert_eq!(argv, vec!["/bin/cmd", "arg1", "arg2"]);
    }

    #[test]
    fn test_argv_tabs_and_newlines() {
        let argv = parse_command_to_argv("/bin/cmd\targ1\narg2").unwrap();
        assert_eq!(argv, vec!["/bin/cmd", "arg1", "arg2"]);
    }

    // ── parse_run_options tests ─────────────────────────────────────────

    #[test]
    fn test_options_empty() {
        let opts = parse_run_options("").unwrap();
        assert!(!opts.preexpand);
    }

    #[test]
    fn test_options_preexpand() {
        let opts = parse_run_options(",preexpand").unwrap();
        assert!(opts.preexpand);
    }

    #[test]
    fn test_options_bad_option() {
        let result = parse_run_options(",badopt");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("bad option 'badopt' for run"));
    }

    #[test]
    fn test_options_bad_option_with_trailing() {
        let result = parse_run_options(",foo123");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("bad option 'foo' for run"));
    }

    // ── RunOptions default tests ────────────────────────────────────────

    #[test]
    fn test_run_options_default() {
        let opts = RunOptions::default();
        assert!(!opts.preexpand);
    }

    // ── RunResult construction tests ────────────────────────────────────

    #[test]
    fn test_run_result_success() {
        let result = RunResult {
            exit_code: 0,
            output: Some("hello".into()),
        };
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.output.as_deref(), Some("hello"));
    }

    #[test]
    fn test_run_result_no_output() {
        let result = RunResult {
            exit_code: 1,
            output: None,
        };
        assert_eq!(result.exit_code, 1);
        assert!(result.output.is_none());
    }
}
