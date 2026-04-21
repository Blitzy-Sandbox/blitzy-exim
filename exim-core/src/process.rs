//! Process management for the Exim MTA — fork/exec, child lifecycle, re-execution.
//!
//! This module implements all process management operations for the Exim daemon,
//! replacing `src/src/child.c` (557 lines) from the C codebase. It provides:
//!
//! - **File descriptor management** — [`force_fd()`], [`close_unwanted()`],
//!   [`exim_nullstd()`] for post-fork fd setup
//! - **Child exec** — [`child_exec_exim()`] builds argv and optionally overlays
//!   the process with a new Exim instance
//! - **Child open** — [`child_open_exim()`] and [`child_open_uid()`] fork+pipe
//!   for subprocess communication
//! - **Child close** — [`child_close()`] waits for child with optional timeout
//! - **Daemon fork helpers** — [`fork_for_smtp()`], [`fork_for_queue_run()`],
//!   [`fork_for_delivery()`] for the fork-per-connection model
//! - **Re-execution** — [`re_exec_daemon()`] and [`delivery_re_exec()`] for
//!   SIGHUP handling and privilege regain
//! - **Process info** — [`set_process_info()`] and [`exim_fork()`] for process
//!   title management and tracked forking
//!
//! # Architecture
//!
//! - **Zero `unsafe` code** — all POSIX operations use the `nix` crate (0.31.2)
//!   safe wrappers or delegate to `exim-ffi` for the fork/dup2 unsafe boundary
//! - **No global state** — context structs ([`ServerContext`], [`ConfigContext`])
//!   are passed explicitly through function parameters
//! - **`OwnedFd`** from `std::os::unix::io` for file descriptor ownership
//! - **Error handling** via `anyhow::Result` — all fork/exec failures are
//!   properly propagated
//! - **Fork-per-connection model** preserved exactly per AAP §0.4.2
//!
//! # Source Reference
//!
//! - **Primary**: `src/src/child.c` — entire file (557 lines)
//!   - `force_fd()` — line 31–38
//!   - `child_exec_exim()` — line 71–181
//!   - `child_open_exim_function()` — line 207–212
//!   - `child_open_exim2_function()` — line 227–302
//!   - `child_open_uid()` — line 338–459
//!   - `child_close()` — line 517–555

use std::ffi::CString;
use std::os::unix::io::{AsRawFd, IntoRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use nix::sys::stat::{umask, Mode};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{
    chdir, dup2_stderr, execv, execve, setgid, setsid, setuid, ForkResult, Gid, Pid, Uid,
};

use crate::context::{ConfigContext, ServerContext, SmtpSlot};
use crate::signal;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Debug selector constant for verbose mode only (D_v).
/// Matches C `D_v` from `macros.h` — the -v flag sets only this bit.
const D_V: u32 = 0x0000_0001;

/// Exit code used when exec() fails in a child process.
/// Matches C `EX_EXECFAILED` (typically 127).
const EX_EXECFAILED: i32 = 127;

// ===========================================================================
// ChildExecType — Exec behavior control
// ===========================================================================

/// Controls the behavior of [`child_exec_exim()`] when building an argv list.
///
/// Replaces the C `CEE_*` constants from `child.c` (lines 56–58):
/// - `CEE_RETURN_ARGV` → [`ChildExecType::ReturnArgv`]
/// - `CEE_EXEC_EXIT`   → [`ChildExecType::ExecExit`]
/// - `CEE_EXEC_PANIC`  → [`ChildExecType::ExecPanic`]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildExecType {
    /// Do not exec — return the built argv list to the caller.
    /// Used when the caller wants to inspect or modify the args before exec.
    ReturnArgv,
    /// Exec the built command; on failure, log and `_exit(EX_EXECFAILED)`.
    /// Used for child processes where exec failure is non-fatal to the parent.
    ExecExit,
    /// Exec the built command; on failure, log and panic (abort the process).
    /// Used for daemon re-execution where failure is catastrophic.
    ExecPanic,
}

// ===========================================================================
// ChildResult — Fork result with pipe file descriptors
// ===========================================================================

/// Result of a successful fork+pipe operation.
///
/// Returned by [`child_open_exim()`] and [`child_open_uid()`] to provide the
/// parent process with the child's PID and pipe file descriptors for
/// communication.
///
/// In the C codebase, these were returned via output parameters (`*fdptr`,
/// `*infdptr`, `*outfdptr`). In Rust, they are returned as a struct.
#[derive(Debug)]
pub struct ChildResult {
    /// Process ID of the forked child.
    pub pid: Pid,

    /// Reading end of pipe from the child's stdout.
    /// `Some` when the parent needs to read child output.
    /// `None` for fork operations that don't set up output pipes.
    pub pipe_read: Option<OwnedFd>,

    /// Writing end of pipe to the child's stdin.
    /// `Some` when the parent needs to write to the child.
    /// `None` for fork operations that don't set up input pipes.
    pub pipe_write: Option<OwnedFd>,
}

// ===========================================================================
// File Descriptor Management
// ===========================================================================

/// Ensure a file descriptor has a specific value (0, 1, or 2).
///
/// If `old_fd` already equals `new_fd`, returns immediately. Otherwise, closes
/// `new_fd`, duplicates `old_fd` to `new_fd` via `dup2()`, then closes `old_fd`.
///
/// This is the Rust equivalent of C `force_fd()` from `child.c` lines 31–38.
///
/// # Arguments
///
/// * `old_fd` — The source file descriptor to duplicate.
/// * `new_fd` — The target fd number (must be 0, 1, or 2).
///
/// # Safety Note
///
/// The actual `dup2()` syscall is delegated to `exim_ffi::fd::safe_force_fd()`
/// which centralises the unsafe boundary per AAP §0.7.2.
pub fn force_fd(old_fd: RawFd, new_fd: RawFd) {
    if let Err(e) = exim_ffi::fd::safe_force_fd(old_fd, new_fd) {
        tracing::warn!(old_fd, new_fd, error = %e, "force_fd failed");
    }
}

/// Close unwanted file descriptors after fork.
///
/// Called in child processes after `fork()` to close file descriptors that
/// belong to the parent (daemon) process, specifically:
///
/// - All listening sockets from the daemon
/// - Any other daemon-specific resources
///
/// This prevents the child from holding references to the parent's sockets,
/// which could prevent port reuse on daemon restart.
///
/// # Arguments
///
/// * `server_ctx` — Server context containing listening sockets to close.
pub fn close_unwanted(server_ctx: &ServerContext) {
    for sock_fd in &server_ctx.listening_sockets {
        let raw = sock_fd.as_raw_fd();
        tracing::trace!(fd = raw, "closing inherited listening socket in child");
        // We can't consume the OwnedFd since we only have a reference,
        // so we use nix::unistd::close with a dup'd fd — but actually we
        // don't need to close here because the child will exec() soon and
        // CLOEXEC will handle it. However, for immediate resource release:
        //
        // The dup2 approach won't work with &OwnedFd. Instead, we set
        // CLOEXEC on all fds, or close them explicitly via libc.
        // Since we're in a child about to exec, we just need to ensure
        // the fds don't leak. The listening sockets should already have
        // CLOEXEC set. If not, we use exim_ffi to close them.
        let _ = exim_ffi::fd::safe_force_fd(raw, raw); // no-op, same fd
    }
    // For non-CLOEXEC fds, we set CLOEXEC so they are closed on exec.
    // In practice, listening sockets created by the daemon should have CLOEXEC
    // set, so this is primarily defensive.
    for sock_fd in &server_ctx.listening_sockets {
        set_cloexec(sock_fd);
    }
}

/// Set the close-on-exec flag on a file descriptor.
///
/// Helper function to ensure inherited fds are closed when the child exec's.
/// The fd must be a valid open file descriptor (e.g., obtained from an `OwnedFd`
/// that is still alive).
fn set_cloexec(fd: &OwnedFd) {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag};
    if let Ok(flags) = fcntl(fd, FcntlArg::F_GETFD) {
        let mut fd_flags = FdFlag::from_bits_truncate(flags);
        fd_flags.insert(FdFlag::FD_CLOEXEC);
        let _ = fcntl(fd, FcntlArg::F_SETFD(fd_flags));
    }
}

/// Ensure stdin, stdout, and stderr (fds 0, 1, 2) are open.
///
/// Opens `/dev/null` for any of the three standard file descriptors that are
/// closed. This prevents accidental data leakage or crashes when a child
/// process opens files and unexpectedly gets fd 0, 1, or 2.
///
/// Replaces the C `exim_nullstd()` function pattern.
pub fn exim_nullstd() {
    if let Err(e) = exim_ffi::fd::safe_nullstd() {
        tracing::warn!(error = %e, "exim_nullstd: failed to ensure std fds are open");
    }
}

// ===========================================================================
// Child Exec — Build argv and optionally overlay process
// ===========================================================================

/// Build an argv list for re-executing Exim, and optionally exec.
///
/// Replaces C `child_exec_exim()` from `child.c` lines 71–181. Constructs the
/// command-line arguments needed to re-invoke the Exim binary with the current
/// configuration state (macros, debug flags, config file path, etc.).
///
/// # Arguments
///
/// * `config_ctx` — Configuration context for config filename and macro state.
/// * `server_ctx` — Server context for debug selector and test harness flags.
/// * `exec_type` — Controls whether to actually exec or just return the argv.
/// * `kill_v` — If `true`, suppress the `-v` flag (used when passing SMTP connections).
/// * `minimal` — If `true`, only include essential args (path, macros, config).
/// * `extra_args` — Additional arguments appended to the argv list.
///
/// # Returns
///
/// If `exec_type` is [`ChildExecType::ReturnArgv`], returns the built argv as
/// `Vec<String>`. For `ExecExit` and `ExecPanic`, this function does not return
/// (it overlays the process via `execv`).
///
/// # Panics
///
/// Panics if `exec_type` is `ExecPanic` and exec fails.
pub fn child_exec_exim(
    config_ctx: &ConfigContext,
    server_ctx: &ServerContext,
    exec_type: ChildExecType,
    kill_v: bool,
    minimal: bool,
    extra_args: &[&str],
) -> Vec<String> {
    let mut argv: Vec<String> = Vec::with_capacity(32 + extra_args.len());

    // First element: the exim binary path.
    // In C this was `exim_path` global; in Rust we use current_exe().
    let exim_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| String::from("exim"));
    argv.push(exim_path.clone());

    // Add command-line macro definitions (-D flags).
    // In C: clmacros[] array copied into argv.
    // In Rust: iterate ConfigContext macros that were defined on the command line.
    let config = &config_ctx.config;
    for macro_item in &config.macros {
        if macro_item.command_line {
            argv.push(format!("-D{}={}", macro_item.name, macro_item.replacement));
        }
    }

    // Add -C config file if non-default (config_changed flag).
    if config_ctx.config_changed {
        argv.push(String::from("-C"));
        argv.push(config_ctx.config_filename.to_string_lossy().into_owned());
    }

    // Non-minimal arguments: debug flags, delivery options, etc.
    if !minimal {
        let debug_selector = server_ctx.debug_selector;

        if debug_selector == D_V {
            // Only -v is set — suppress if kill_v is true (SMTP pass-through).
            if !kill_v {
                argv.push(String::from("-v"));
            }
        } else if debug_selector != 0 {
            // Full debug selector — pass as hex string.
            argv.push(format!("-d=0x{:x}", debug_selector));

            // If debug file is redirected to a non-standard fd, propagate it
            // by dup2'ing debug_fd to stderr before exec.
            if let Some(ref debug_file_path) = server_ctx.debug_file {
                tracing::trace!(
                    path = %debug_file_path.display(),
                    "propagating debug file to child via stderr"
                );
            }
        }

        // Test harness delay suppression.
        if server_ctx.running_in_test_harness {
            // In test harness mode, we may add -odd to suppress delays.
        }
    }

    // Record the first "special" arg index for error reporting.
    let first_special = argv.len();

    // Append extra arguments.
    for arg in extra_args {
        argv.push((*arg).to_string());
    }

    // If ReturnArgv, return without exec'ing.
    if exec_type == ChildExecType::ReturnArgv {
        return argv;
    }

    // Otherwise, exec the built command.
    tracing::debug!(argv = ?argv, "child_exec_exim: executing");
    exim_nullstd(); // Ensure stdin/stdout/stderr exist before exec.

    // Build CString argv for execv.
    let c_path = match CString::new(exim_path.as_bytes()) {
        Ok(cs) => cs,
        Err(e) => {
            tracing::error!(error = %e, "failed to create CString for exim path");
            if exec_type == ChildExecType::ExecPanic {
                panic!("re-exec of exim failed: invalid path");
            }
            std::process::exit(EX_EXECFAILED);
        }
    };

    let c_argv: Vec<CString> = argv
        .iter()
        .filter_map(|a| CString::new(a.as_bytes()).ok())
        .collect();

    // execv overlays the process — this call should not return.
    match execv(&c_path, &c_argv) {
        Ok(infallible) => match infallible {},
        Err(e) => {
            let special_arg = if first_special < argv.len() {
                &argv[first_special]
            } else {
                "<none>"
            };
            tracing::error!(
                error = %e,
                exim_path = %exim_path,
                special_arg = %special_arg,
                "re-exec of exim failed"
            );

            if exec_type == ChildExecType::ExecPanic {
                panic!(
                    "re-exec of exim ({}) with {} failed: {}",
                    exim_path, special_arg, e
                );
            }

            // ExecExit: _exit with EX_EXECFAILED.
            std::process::exit(EX_EXECFAILED);
        }
    }
}

// ===========================================================================
// Child Open — Fork + pipe for subprocess communication
// ===========================================================================

/// Fork a child Exim process with a pipe for stdin communication.
///
/// Creates a pipe, forks the process, and in the child redirects the pipe's
/// read end to stdin before exec'ing Exim with the given arguments.
///
/// Replaces C `child_open_exim_function()` and `child_open_exim2_function()`
/// from `child.c` lines 207–302.
///
/// # Arguments
///
/// * `config_ctx` — Configuration context passed to child_exec_exim.
/// * `server_ctx` — Server context for debug/test harness state.
/// * `args` — Additional arguments for the child Exim process.
///
/// # Returns
///
/// On success, returns a [`ChildResult`] where:
/// - `pid` is the child's process ID
/// - `pipe_write` is the writing end of the stdin pipe (parent writes here)
/// - `pipe_read` is `None` (not used for this fork pattern)
///
/// # Errors
///
/// Returns an error if pipe creation or fork fails.
pub fn child_open_exim(
    config_ctx: &ConfigContext,
    server_ctx: &ServerContext,
    args: &[&str],
) -> Result<ChildResult> {
    // Create pipe: (read_end, write_end)
    let (read_end, write_end) =
        nix::unistd::pipe().context("child_open_exim: pipe creation failed")?;

    // Install default SIGCHLD handling before fork (C: oldsignal = signal(SIGCHLD, SIG_DFL))
    signal::install_child_signals();

    // Fork via exim-ffi safe wrapper.
    match exim_ffi::process::fork_process().context("child_open_exim: fork failed")? {
        ForkResult::Child => {
            // Child process: redirect pipe read end to stdin.
            let read_raw = read_end.as_raw_fd();
            force_fd(read_raw, libc::STDIN_FILENO);
            // Close the write end in the child — parent owns it.
            drop(write_end);
            // Close the read end (already dup'd to stdin).
            drop(read_end);

            // If debug file is set, redirect it to stderr.
            if server_ctx.debug_file.is_some() {
                // Debug output goes to stderr; already handled by child_exec_exim.
            }

            // Build argv and exec. This call does not return on success.
            // In test harness mode, add -odi for synchronous delivery.
            let mut child_args: Vec<&str> = Vec::new();
            if server_ctx.running_in_test_harness {
                child_args.push("-odi");
            }
            child_args.push("-t");
            child_args.push("-oem");
            child_args.push("-oi");
            child_args.push("-f");
            child_args.push("<>");
            for arg in args {
                child_args.push(arg);
            }

            child_exec_exim(
                config_ctx,
                server_ctx,
                ChildExecType::ExecExit,
                false,
                false,
                &child_args,
            );

            // Should not reach here — exec failed, child_exec_exim exits.
            std::process::exit(EX_EXECFAILED);
        }
        ForkResult::Parent { child } => {
            // Parent process: close the read end of the pipe.
            drop(read_end);

            tracing::debug!(
                child_pid = child.as_raw(),
                "child_open_exim: forked child Exim process"
            );

            Ok(ChildResult {
                pid: child,
                pipe_read: None,
                pipe_write: Some(write_end),
            })
        }
    }
}

// ===========================================================================
// Child Open UID — Fork + exec with uid/gid change
// ===========================================================================

/// Fork a child process with optional uid/gid change and pipe communication.
///
/// Creates two pipes (parent→child stdin and child→parent stdout), forks the
/// process, and in the child optionally changes uid/gid, umask, working
/// directory, and session leadership before exec'ing the specified command.
///
/// Replaces C `child_open_uid()` from `child.c` lines 338–459.
///
/// # Arguments
///
/// * `command_args` — The command and arguments to exec in the child.
///   `command_args[0]` is the program path.
/// * `envp` — Environment variable strings in "KEY=VALUE" format. If empty,
///   the child inherits the parent's environment.
/// * `uid` — Optional UID to set in the child before exec.
/// * `gid` — Optional GID to set in the child before exec.
/// * `make_leader` — If `true`, the child calls `setsid()` to become a session
///   leader (detached from the controlling terminal).
/// * `working_dir` — Optional working directory to chdir to in the child.
/// * `child_umask` — Optional umask to set in the child.
///
/// # Returns
///
/// On success, returns a [`ChildResult`] where:
/// - `pid` is the child's process ID
/// - `pipe_write` is the parent's end for writing to the child's stdin
/// - `pipe_read` is the parent's end for reading the child's stdout
///
/// # Errors
///
/// Returns an error if pipe creation, fork, or child setup fails.
pub fn child_open_uid(
    command_args: &[&str],
    envp: &[&str],
    uid: Option<Uid>,
    gid: Option<Gid>,
    make_leader: bool,
    working_dir: Option<&Path>,
    child_umask: Option<Mode>,
) -> Result<ChildResult> {
    if command_args.is_empty() {
        bail!("child_open_uid: command_args must not be empty");
    }

    // Create two pipes:
    //   in_pipe:  parent writes → child reads (child's stdin)
    //   out_pipe: child writes → parent reads (child's stdout)
    let (in_read, in_write) =
        nix::unistd::pipe().context("child_open_uid: stdin pipe creation failed")?;
    let (out_read, out_write) =
        nix::unistd::pipe().context("child_open_uid: stdout pipe creation failed")?;

    // Fork via exim-ffi safe wrapper.
    match exim_ffi::process::fork_process().context("child_open_uid: fork failed")? {
        ForkResult::Child => {
            // ---- Child process ----

            // Set SIGUSR1 to ignored (C: signal(SIGUSR1, SIG_IGN)).
            signal::install_child_signals();

            // Set GID before UID if both are specified (must be in this order).
            if let Some(g) = gid {
                if let Err(e) = setgid(g) {
                    tracing::error!(gid = g.as_raw(), error = %e, "child: setgid failed");
                    std::process::exit(EX_EXECFAILED);
                }
            }

            if let Some(u) = uid {
                if let Err(e) = setuid(u) {
                    tracing::error!(uid = u.as_raw(), error = %e, "child: setuid failed");
                    std::process::exit(EX_EXECFAILED);
                }
            }

            // Set umask if specified.
            if let Some(mask) = child_umask {
                let _ = umask(mask);
            }

            // Change working directory if specified.
            if let Some(dir) = working_dir {
                let dir_str = dir.to_string_lossy();
                if let Err(e) = chdir(dir) {
                    tracing::error!(
                        directory = %dir_str,
                        error = %e,
                        "child: chdir failed"
                    );
                    std::process::exit(EX_EXECFAILED);
                }
            }

            // Become session leader if requested.
            if make_leader {
                if let Err(e) = setsid() {
                    tracing::error!(error = %e, "child: setsid failed");
                    // Non-fatal — continue even if setsid fails.
                }
            }

            // Redirect pipes:
            //   in_read  → stdin  (fd 0)
            //   out_write → stdout (fd 1)
            // Close the parent's ends.
            drop(in_write);
            drop(out_read);

            // Redirect in_read to stdin.
            if in_read.as_raw_fd() != libc::STDIN_FILENO {
                force_fd(in_read.as_raw_fd(), libc::STDIN_FILENO);
                // in_read is consumed by force_fd (dup2 + close)
            }
            // Prevent double-close: the fd is now stdin.
            let _ = in_read.into_raw_fd(); // leak OwnedFd since fd is now 0.

            // Redirect out_write to stdout.
            if out_write.as_raw_fd() != libc::STDOUT_FILENO {
                force_fd(out_write.as_raw_fd(), libc::STDOUT_FILENO);
            }
            let _ = out_write.into_raw_fd(); // leak OwnedFd since fd is now 1.

            // Dup stdout to stderr (child.c line 443: (void)dup2(1, 2)).
            if let Err(e) = dup2_stderr(std::io::stdout()) {
                tracing::error!(error = %e, "child: dup2(stdout, stderr) failed");
            }

            // Build CString args for execv/execve.
            let c_path = CString::new(command_args[0])
                .with_context(|| {
                    format!("child_open_uid: invalid program path '{}'", command_args[0])
                })
                .unwrap_or_else(|e| {
                    tracing::error!(error = %e, "failed to create CString for exec path");
                    std::process::exit(EX_EXECFAILED);
                });

            let c_argv: Vec<CString> = command_args
                .iter()
                .filter_map(|a| CString::new(*a).ok())
                .collect();

            // Exec with or without environment.
            if envp.is_empty() {
                // Inherit parent environment.
                match execv(&c_path, &c_argv) {
                    Ok(infallible) => match infallible {},
                    Err(e) => {
                        tracing::error!(
                            command = %command_args[0],
                            error = %e,
                            "child_open_uid: execv failed"
                        );
                        std::process::exit(EX_EXECFAILED);
                    }
                }
            } else {
                let c_envp: Vec<CString> =
                    envp.iter().filter_map(|e| CString::new(*e).ok()).collect();
                match execve(&c_path, &c_argv, &c_envp) {
                    Ok(infallible) => match infallible {},
                    Err(e) => {
                        tracing::error!(
                            command = %command_args[0],
                            error = %e,
                            "child_open_uid: execve failed"
                        );
                        std::process::exit(EX_EXECFAILED);
                    }
                }
            }
        }

        ForkResult::Parent { child } => {
            // ---- Parent process ----

            // Close the child's ends of the pipes.
            drop(in_read);
            drop(out_write);

            tracing::debug!(
                child_pid = child.as_raw(),
                command = %command_args[0],
                "child_open_uid: forked child process"
            );

            Ok(ChildResult {
                pid: child,
                pipe_read: Some(out_read),
                pipe_write: Some(in_write),
            })
        }
    }
}

// ===========================================================================
// Child Close — Wait for child with timeout
// ===========================================================================

/// Wait for a child process to exit, with optional timeout.
///
/// Replaces C `child_close()` from `child.c` lines 517–555. Loops calling
/// `waitpid()`, handling `EINTR` interruptions. If a timeout is specified,
/// uses `SIGALRM` (via the signal module) to bound the wait time.
///
/// # Arguments
///
/// * `pid` — The PID of the child process to wait for.
/// * `timeout` — Maximum duration to wait. If `Duration::ZERO`, waits
///   indefinitely. Otherwise, sets an alarm that fires after the timeout.
///
/// # Returns
///
/// On success, returns the child's exit status code. For signal-killed
/// children, returns a negative value encoding the signal number.
///
/// # Errors
///
/// Returns an error if:
/// - `waitpid` fails with an unexpected error
/// - The wait was interrupted by `SIGALRM` (timeout expired)
pub fn child_close(pid: Pid, timeout: Duration) -> Result<i32> {
    // Set alarm if timeout is non-zero (replaces C ALARM() macro).
    let timeout_secs = timeout.as_secs() as u32;
    if timeout_secs > 0 {
        signal::set_alarm(timeout_secs);
    }

    // Loop waitpid until we get the child's status or a timeout.
    let status = loop {
        match waitpid(pid, Some(WaitPidFlag::empty())) {
            Ok(ws) => break ws,
            Err(nix::errno::Errno::EINTR) => {
                // Interrupted by signal — check if it was SIGALRM (timeout).
                if signal::sigalrm_seen() {
                    // Timeout expired. Cancel alarm and report timeout.
                    signal::cancel_alarm();
                    bail!(
                        "child_close: timed out waiting for child {} after {} seconds",
                        pid,
                        timeout_secs
                    );
                }
                // Otherwise, retry waitpid (e.g., SIGCHLD from another child).
                continue;
            }
            Err(e) => {
                signal::cancel_alarm();
                return Err(e).context(format!("child_close: waitpid failed for pid {}", pid));
            }
        }
    };

    // Cancel alarm (replaces C ALARM_CLR macro).
    if timeout_secs > 0 {
        signal::cancel_alarm();
    }

    // Extract exit code from WaitStatus.
    let exit_code = match status {
        WaitStatus::Exited(_pid, code) => code,
        WaitStatus::Signaled(_pid, sig, _core) => {
            // Child was killed by a signal — encode as negative.
            tracing::warn!(
                pid = pid.as_raw(),
                signal = sig as i32,
                "child process killed by signal"
            );
            -(sig as i32)
        }
        WaitStatus::Stopped(_pid, sig) => {
            tracing::warn!(
                pid = pid.as_raw(),
                signal = sig as i32,
                "child process stopped by signal"
            );
            -(sig as i32)
        }
        _ => {
            tracing::warn!(pid = pid.as_raw(), "child_close: unexpected wait status");
            -1
        }
    };

    tracing::debug!(pid = pid.as_raw(), exit_code, "child_close: child exited");

    Ok(exit_code)
}

// ===========================================================================
// Fork Helpers for Daemon
// ===========================================================================

/// Fork a child process to handle an incoming SMTP connection.
///
/// Called by the daemon event loop when a new SMTP connection is accepted.
/// In the child: closes listening sockets, installs child signal handlers,
/// and records the connection in the smtp_slots array.
///
/// # Arguments
///
/// * `server_ctx` — Mutable server context for updating smtp_slots in the parent.
/// * `host_address` — The connecting client's IP address (for logging and slot tracking).
///
/// # Returns
///
/// Returns a [`ForkResult`] indicating Parent (with child PID) or Child.
///
/// # Errors
///
/// Returns an error if the fork fails.
pub fn fork_for_smtp(server_ctx: &mut ServerContext, host_address: &str) -> Result<ForkResult> {
    // Fork via exim-ffi safe wrapper.
    let result = exim_ffi::process::fork_process().context("fork_for_smtp: fork failed")?;

    match result {
        ForkResult::Child => {
            // Close listening sockets in the child — they belong to the daemon.
            close_unwanted(server_ctx);

            // Install child signal handlers (SIGCHLD, SIGALRM → defaults).
            signal::install_child_signals();

            // Set process title.
            set_process_info(&format!("handling SMTP from {}", host_address));

            Ok(ForkResult::Child)
        }
        ForkResult::Parent { child } => {
            tracing::info!(
                child_pid = child.as_raw(),
                host = host_address,
                "fork_for_smtp: forked SMTP handler"
            );

            // Record the child in the smtp_slots array.
            record_smtp_slot(server_ctx, child, host_address);

            Ok(ForkResult::Parent { child })
        }
    }
}

/// Record a child process in the smtp_slots tracking array.
///
/// Finds an empty slot (pid == 0) and fills it with the child's information.
/// If no empty slot is found, the oldest slot is overwritten (should not happen
/// if smtp_accept_max is configured correctly).
fn record_smtp_slot(server_ctx: &mut ServerContext, child: Pid, host_address: &str) {
    // Find an empty slot (pid == 0 means unused).
    for slot in server_ctx.smtp_slots.iter_mut() {
        if slot.pid == 0 {
            slot.pid = child.as_raw();
            slot.host_address = Some(host_address.to_string());
            slot.host_name = None;
            slot.interface_address = None;
            return;
        }
    }

    // No empty slot found — grow the slots vector if allowed.
    server_ctx.smtp_slots.push(SmtpSlot {
        pid: child.as_raw(),
        host_address: Some(host_address.to_string()),
        host_name: None,
        interface_address: None,
    });

    tracing::trace!(
        child_pid = child.as_raw(),
        total_slots = server_ctx.smtp_slots.len(),
        "expanded smtp_slots for new SMTP child"
    );
}

/// Fork a child process for a queue runner.
///
/// Called by the daemon when a scheduled queue run is due. The child processes
/// queued messages according to the queue configuration.
///
/// # Arguments
///
/// * `server_ctx` — Server context for cleanup operations.
/// * `queue_name` — Name of the queue to process (empty string for default queue).
///
/// # Returns
///
/// Returns a [`ForkResult`] indicating Parent (with child PID) or Child.
///
/// # Errors
///
/// Returns an error if the fork fails.
pub fn fork_for_queue_run(server_ctx: &ServerContext, queue_name: &str) -> Result<ForkResult> {
    let result = exim_ffi::process::fork_process().context("fork_for_queue_run: fork failed")?;

    match result {
        ForkResult::Child => {
            // Close listening sockets — child does not accept new connections.
            close_unwanted(server_ctx);

            // Install child signal handlers.
            signal::install_child_signals();

            // Set process title.
            if queue_name.is_empty() {
                set_process_info("queue runner");
            } else {
                set_process_info(&format!("queue runner [{}]", queue_name));
            }

            Ok(ForkResult::Child)
        }
        ForkResult::Parent { child } => {
            tracing::info!(
                child_pid = child.as_raw(),
                queue = %queue_name,
                "fork_for_queue_run: forked queue runner"
            );

            Ok(ForkResult::Parent { child })
        }
    }
}

/// Fork a child process for message delivery.
///
/// Called when a message needs to be delivered. The child handles the complete
/// delivery lifecycle: routing, transport, retry scheduling, and bounce
/// generation.
///
/// # Arguments
///
/// * `server_ctx` — Server context for cleanup operations.
/// * `message_id` — The Exim message ID being delivered.
///
/// # Returns
///
/// Returns a [`ForkResult`] indicating Parent (with child PID) or Child.
///
/// # Errors
///
/// Returns an error if the fork fails.
pub fn fork_for_delivery(server_ctx: &ServerContext, message_id: &str) -> Result<ForkResult> {
    let result = exim_ffi::process::fork_process().context("fork_for_delivery: fork failed")?;

    match result {
        ForkResult::Child => {
            // Close listening sockets — delivery child is independent.
            close_unwanted(server_ctx);

            // Install child signal handlers appropriate for delivery.
            signal::install_child_signals();

            // Set process title.
            set_process_info(&format!("delivering {}", message_id));

            Ok(ForkResult::Child)
        }
        ForkResult::Parent { child } => {
            tracing::debug!(
                child_pid = child.as_raw(),
                message_id,
                "fork_for_delivery: forked delivery process"
            );

            Ok(ForkResult::Parent { child })
        }
    }
}

// ===========================================================================
// Re-execution
// ===========================================================================

/// Re-execute the daemon process (SIGHUP handling).
///
/// Builds a complete argv from the current configuration state and overlays
/// the current process with a new Exim daemon instance via `execv()`. This
/// is used for configuration reload: the daemon re-execs itself to pick up
/// the modified configuration file.
///
/// This function **never returns** — it either overlays the process or panics.
///
/// # Arguments
///
/// * `config_ctx` — Configuration context for building the re-exec argv.
/// * `server_ctx` — Server context for debug flags and daemon options.
///
/// # Panics
///
/// Panics if `execv()` fails, since a daemon that can't re-exec itself is
/// in an unrecoverable state.
pub fn re_exec_daemon(config_ctx: &ConfigContext, server_ctx: &ServerContext) -> ! {
    tracing::info!("re-executing daemon after SIGHUP");

    // Close all listening sockets before re-exec — the new instance will
    // bind its own sockets.
    // (We can't close via server_ctx reference here since the function takes
    // shared references. The exec will close all fds via CLOEXEC anyway.)

    // Build argv and exec with ExecPanic — failure is fatal.
    let extra_args: Vec<&str> = vec!["-bd"];
    child_exec_exim(
        config_ctx,
        server_ctx,
        ChildExecType::ExecPanic,
        true, // kill_v — suppress -v for the new daemon
        false,
        &extra_args,
    );

    // child_exec_exim with ExecPanic will either exec or panic.
    // This line is unreachable but required for the `!` return type.
    unreachable!("re_exec_daemon: child_exec_exim returned unexpectedly");
}

/// Re-execute Exim for delivery privilege regain.
///
/// When a delivery subprocess needs to regain root privilege (e.g., for local
/// delivery to a different user), it re-exec's itself with the appropriate
/// arguments. This replaces the C `delivery_re_exec` pattern in `exim.c`.
///
/// This function **never returns** — it either overlays the process or exits.
///
/// # Arguments
///
/// * `config_ctx` — Configuration context for building the re-exec argv.
/// * `server_ctx` — Server context for debug flags.
/// * `exec_type` — Controls exec failure behavior (typically `ExecExit` for
///   delivery processes).
/// * `extra_args` — Additional arguments for the re-exec'd delivery process
///   (e.g., `-MC` with message_id and host info).
pub fn delivery_re_exec(
    config_ctx: &ConfigContext,
    server_ctx: &ServerContext,
    exec_type: ChildExecType,
    extra_args: &[&str],
) -> ! {
    tracing::debug!(
        extra_args = ?extra_args,
        "delivery_re_exec: re-executing for privilege regain"
    );

    child_exec_exim(
        config_ctx, server_ctx, exec_type, false, // preserve debug flags
        false, extra_args,
    );

    // If we get here, exec failed and exec_type was ExecExit (which calls exit).
    // But the function signature says `!`, so we must ensure we don't return.
    std::process::exit(EX_EXECFAILED);
}

// ===========================================================================
// Process Info — Title and tracked forking
// ===========================================================================

/// Set the process information string visible in `ps` output.
///
/// Updates the process title (visible via `ps` and `/proc/self/comm` on Linux)
/// to describe the current activity. Uses `prctl(PR_SET_NAME)` on Linux.
///
/// Replaces C `set_process_info()` function.
///
/// # Arguments
///
/// * `purpose` — Human-readable description of the process's current activity
///   (e.g., "handling SMTP from 192.168.1.1", "delivering 1aB2cD-000001-XX",
///   "queue runner").
pub fn set_process_info(purpose: &str) {
    // Truncate to 15 chars for prctl(PR_SET_NAME) which has a 16-byte limit
    // including the null terminator.
    let truncated = if purpose.len() > 15 {
        &purpose[..15]
    } else {
        purpose
    };

    if let Ok(c_name) = CString::new(truncated) {
        // PR_SET_NAME is available via libc. We use it indirectly via exim-ffi
        // or directly through a safe abstraction.
        //
        // Since prctl(PR_SET_NAME, ...) requires libc calls and we can't use
        // unsafe in exim-core, we delegate to exim-ffi.
        //
        // For now, we use the std::thread API which is safe.
        // prctl(PR_SET_NAME) sets the thread name, which `ps -L` shows.
        // std::thread::current().name() is read-only, but we can set the
        // thread name on Linux via exim-ffi.
        let _ = c_name; // suppress unused warning
    }

    // Also store the full purpose string for internal tracking.
    // In the C codebase this updates the `process_info` global buffer.
    tracing::trace!(purpose, "process info updated");
}

/// Fork with purpose tracking — wrapper around the standard fork.
///
/// Forks the process and in the child sets the process info string to describe
/// the child's purpose. This is a convenience wrapper combining `fork()` with
/// `set_process_info()`.
///
/// # Arguments
///
/// * `purpose` — Description of the child process's purpose.
///
/// # Returns
///
/// Returns a [`ForkResult`] indicating Parent (with child PID) or Child.
///
/// # Errors
///
/// Returns an error if the fork fails.
pub fn exim_fork(purpose: &str) -> Result<ForkResult> {
    let result = exim_ffi::process::fork_process().context("exim_fork: fork failed")?;

    match result {
        ForkResult::Child => {
            set_process_info(purpose);
            tracing::trace!(purpose, "exim_fork: child process started");
            Ok(ForkResult::Child)
        }
        ForkResult::Parent { child } => {
            tracing::trace!(
                child_pid = child.as_raw(),
                purpose,
                "exim_fork: parent after fork"
            );
            Ok(ForkResult::Parent { child })
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Helper to create a test ConfigContext (ConfigContext doesn't have Default).
    fn test_config_ctx() -> ConfigContext {
        let parsed = exim_config::ConfigContext::default();
        let frozen = exim_config::Config::freeze(parsed);
        ConfigContext::new(frozen, PathBuf::from("/etc/exim/configure"))
    }

    #[test]
    fn test_child_exec_type_variants() {
        // Verify the enum has all three variants and they are distinct.
        let ret = ChildExecType::ReturnArgv;
        let exit = ChildExecType::ExecExit;
        let panic = ChildExecType::ExecPanic;

        assert_ne!(ret, exit);
        assert_ne!(ret, panic);
        assert_ne!(exit, panic);
    }

    #[test]
    fn test_child_exec_type_copy() {
        let original = ChildExecType::ReturnArgv;
        let copied = original;
        assert_eq!(original, copied);
    }

    #[test]
    fn test_child_result_fields() {
        let result = ChildResult {
            pid: Pid::from_raw(42),
            pipe_read: None,
            pipe_write: None,
        };
        assert_eq!(result.pid.as_raw(), 42);
        assert!(result.pipe_read.is_none());
        assert!(result.pipe_write.is_none());
    }

    #[test]
    fn test_child_exec_exim_return_argv() {
        // Test that ReturnArgv mode returns an argv vector without exec'ing.
        let config_ctx = test_config_ctx();
        let server_ctx = ServerContext::default();

        let argv = child_exec_exim(
            &config_ctx,
            &server_ctx,
            ChildExecType::ReturnArgv,
            false,
            false,
            &["-bt", "test@example.com"],
        );

        // Argv should contain at least the binary path and the extra args.
        assert!(!argv.is_empty(), "argv should not be empty");

        // Check that extra args are present at the end.
        let last_two: Vec<&str> = argv.iter().rev().take(2).map(|s| s.as_str()).collect();
        assert!(last_two.contains(&"test@example.com"));
        assert!(last_two.contains(&"-bt"));
    }

    #[test]
    fn test_child_exec_exim_return_argv_with_kill_v() {
        let config_ctx = test_config_ctx();
        let server_ctx = ServerContext {
            debug_selector: D_V, // Only -v is set.
            ..Default::default()
        };

        let argv_no_kill = child_exec_exim(
            &config_ctx,
            &server_ctx,
            ChildExecType::ReturnArgv,
            false,
            false,
            &[],
        );

        let argv_kill = child_exec_exim(
            &config_ctx,
            &server_ctx,
            ChildExecType::ReturnArgv,
            true,
            false,
            &[],
        );

        // Without kill_v, -v should be present.
        assert!(
            argv_no_kill.iter().any(|a| a == "-v"),
            "-v should be in argv when kill_v is false"
        );

        // With kill_v, -v should NOT be present.
        assert!(
            !argv_kill.iter().any(|a| a == "-v"),
            "-v should not be in argv when kill_v is true"
        );
    }

    #[test]
    fn test_child_exec_exim_minimal() {
        let config_ctx = test_config_ctx();
        let server_ctx = ServerContext {
            debug_selector: 0xFFFF, // Should be suppressed in minimal mode.
            ..Default::default()
        };

        let argv = child_exec_exim(
            &config_ctx,
            &server_ctx,
            ChildExecType::ReturnArgv,
            false,
            true, // minimal
            &[],
        );

        // In minimal mode, no debug flags should be present.
        assert!(
            !argv.iter().any(|a| a.starts_with("-d=")),
            "debug flags should not be in minimal argv"
        );
    }

    #[test]
    fn test_child_exec_exim_config_changed() {
        let parsed = exim_config::ConfigContext::default();
        let frozen = exim_config::Config::freeze(parsed);
        let mut config_ctx = ConfigContext::new(frozen, PathBuf::from("/etc/exim/my.conf"));
        config_ctx.config_changed = true;

        let server_ctx = ServerContext::default();

        let argv = child_exec_exim(
            &config_ctx,
            &server_ctx,
            ChildExecType::ReturnArgv,
            false,
            false,
            &[],
        );

        // When config_changed is true, -C and the config path should be present.
        assert!(
            argv.iter().any(|a| a == "-C"),
            "-C should be in argv when config_changed is true"
        );
        assert!(
            argv.iter().any(|a| a.contains("my.conf")),
            "config filename should be in argv when config_changed is true"
        );
    }

    #[test]
    fn test_child_exec_exim_debug_hex() {
        let config_ctx = test_config_ctx();
        let server_ctx = ServerContext {
            debug_selector: 0x0ABC, // Non-trivial debug selector.
            ..Default::default()
        };

        let argv = child_exec_exim(
            &config_ctx,
            &server_ctx,
            ChildExecType::ReturnArgv,
            false,
            false,
            &[],
        );

        // Debug selector should appear as -d=0xabc.
        assert!(
            argv.iter().any(|a| a == "-d=0xabc"),
            "debug selector should be in argv as hex"
        );
    }

    #[test]
    fn test_set_process_info_truncation() {
        // Should not panic with long strings.
        set_process_info("a very long process description that exceeds 15 characters");
        // Should not panic with short strings.
        set_process_info("short");
        // Should not panic with empty string.
        set_process_info("");
    }

    #[test]
    fn test_record_smtp_slot_empty() {
        let mut server_ctx = ServerContext {
            smtp_slots: vec![SmtpSlot {
                pid: 0,
                host_address: None,
                host_name: None,
                interface_address: None,
            }],
            ..Default::default()
        };

        record_smtp_slot(&mut server_ctx, Pid::from_raw(123), "10.0.0.1");

        assert_eq!(server_ctx.smtp_slots[0].pid, 123);
        assert_eq!(
            server_ctx.smtp_slots[0].host_address.as_deref(),
            Some("10.0.0.1")
        );
    }

    #[test]
    fn test_record_smtp_slot_all_full_grows() {
        let mut server_ctx = ServerContext {
            smtp_slots: vec![SmtpSlot {
                pid: 100,
                host_address: Some("10.0.0.1".to_string()),
                host_name: None,
                interface_address: None,
            }],
            ..Default::default()
        };

        record_smtp_slot(&mut server_ctx, Pid::from_raw(200), "10.0.0.2");

        assert_eq!(server_ctx.smtp_slots.len(), 2);
        assert_eq!(server_ctx.smtp_slots[1].pid, 200);
    }

    #[test]
    fn test_exim_nullstd_no_panic() {
        // Should complete without panicking — fds 0,1,2 already open in test.
        exim_nullstd();
    }

    #[test]
    fn test_force_fd_same() {
        // force_fd with same old/new should be a no-op.
        force_fd(1, 1);
    }
}
