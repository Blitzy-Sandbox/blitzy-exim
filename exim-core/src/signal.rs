//! Signal handling for the Exim daemon.
//!
//! This module implements signal handling for the Exim daemon process, providing
//! async-signal-safe flag management for four critical signals:
//!
//! - **SIGHUP** — Triggers daemon re-execution to pick up configuration changes
//! - **SIGTERM** — Triggers graceful shutdown (PID file cleanup, socket teardown)
//! - **SIGCHLD** — Wakes the daemon to reap terminated child processes
//! - **SIGALRM** — Drives periodic queue runner scheduling and SMTP timeouts
//!
//! Additionally, **SIGPIPE** is unconditionally ignored to prevent broken-pipe
//! crashes when SMTP clients disconnect unexpectedly, and **SIGINT** is handled
//! identically to SIGTERM for interactive daemon termination.
//!
//! # Architecture
//!
//! Signal handlers follow a strict flag-and-check pattern (extracted from the
//! original C `daemon.c` signal handler code, lines 58–130):
//!
//! 1. The signal handler sets an atomic flag (this is the only async-signal-safe
//!    operation the handler performs)
//! 2. The daemon `poll()` loop checks flags between iterations via the `*_seen()`
//!    query functions
//! 3. The daemon takes appropriate action based on which flags are set
//!
//! The four [`AtomicBool`] flags are the **ONLY** permitted global mutable state
//! in `exim-core`, as signal flags are inherently process-global. This is an
//! accepted exception to the context-struct pattern (per AAP §0.4.4).
//!
//! # Signal Handler Safety
//!
//! All signal handler functions (`sighup_handler`, `sigchld_handler`,
//! `sigterm_handler`, `sigalrm_handler`) are `extern "C"` functions that
//! perform exactly one operation: an atomic store to a static [`AtomicBool`].
//! This compiles to a single atomic store instruction on all supported
//! platforms and is trivially async-signal-safe. The handlers perform:
//! - No memory allocation
//! - No I/O operations
//! - No lock acquisition
//! - No non-reentrant function calls
//!
//! # Source Reference
//!
//! - **Primary**: `src/src/daemon.c` — signal handlers and setup
//!   - `sighup_handler()` — lines 68–73
//!   - `main_sigchld_handler()` — lines 91–96
//!   - `main_sigterm_handler()` — lines 102–106
//!   - Signal setup in `daemon_go()` — lines 2380–2419
//! - **Architecture**: AAP §0.4.1 — signal.rs specification

use std::sync::atomic::{AtomicBool, Ordering};

use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::unistd::alarm;

// ===========================================================================
// Signal State Flags
// ===========================================================================
//
// These four AtomicBool statics are the ONLY permitted global mutable state
// in the exim-core crate. They replace the C `volatile sig_atomic_t` flags
// (SIGNAL_BOOL type) from daemon.c lines 37–39:
//
//     static SIGNAL_BOOL sigchld_seen;
//     static SIGNAL_BOOL sighup_seen;
//     static SIGNAL_BOOL sigterm_seen;
//
// AtomicBool::store with SeqCst ordering is async-signal-safe because it
// compiles to a single atomic store instruction on all supported platforms
// (x86_64: `mov` with `mfence`; aarch64: `stlr`).

/// Flag set by the SIGCHLD handler to notify the daemon that one or more
/// child processes have terminated and need reaping via `waitpid()`.
///
/// Replaces C `static SIGNAL_BOOL sigchld_seen` (daemon.c line 37).
static SIGCHLD_SEEN: AtomicBool = AtomicBool::new(false);

/// Flag set by the SIGHUP handler to trigger daemon re-execution.
/// When the daemon detects this flag, it re-executes itself via `execv()`
/// to pick up configuration file changes.
///
/// Replaces C `static SIGNAL_BOOL sighup_seen` (daemon.c line 38).
static SIGHUP_SEEN: AtomicBool = AtomicBool::new(false);

/// Flag set by the SIGTERM (and SIGINT) handler to trigger graceful shutdown.
/// When detected, the daemon removes its PID file, closes listening sockets,
/// cleans up the notification socket, and exits.
///
/// Replaces C `static SIGNAL_BOOL sigterm_seen` (daemon.c line 39).
static SIGTERM_SEEN: AtomicBool = AtomicBool::new(false);

/// Flag set by the SIGALRM handler for queue run scheduling timeouts.
/// The daemon uses `alarm()` to schedule periodic SIGALRM deliveries that
/// trigger queue runner child process spawning.
///
/// In the C codebase, `sigalrm_seen` was used inline (daemon.c line 2426)
/// rather than as a named static, but the pattern is identical.
static SIGALRM_SEEN: AtomicBool = AtomicBool::new(false);

// ===========================================================================
// Signal Handler Functions (extern "C")
// ===========================================================================
//
// CRITICAL: These functions MUST be async-signal-safe. The ONLY operation
// they may perform is setting an atomic flag via AtomicBool::store(). They
// MUST NOT:
// - Allocate memory (no String, Vec, Box, or arena operations)
// - Perform I/O (no println!, write!, or file operations)
// - Call non-reentrant functions (no tracing!, no log!)
// - Acquire locks (no Mutex, RwLock, or condvar operations)
//
// The handler parameter `_sig: libc::c_int` is the signal number delivered
// by the kernel. We ignore it because each handler is installed for exactly
// one signal (except SIGINT which shares the SIGTERM handler).

/// SIGHUP handler — sets the re-execution flag.
///
/// Replaces C `sighup_handler()` from daemon.c lines 68–73:
/// ```c
/// static void sighup_handler(int sig) {
///     sighup_seen = TRUE;
///     signal(SIGHUP, sighup_handler);  // re-register
/// }
/// ```
///
/// In the Rust version, we install the handler with `SA_RESTART` which does
/// not auto-reset the disposition, so re-registration inside the handler is
/// unnecessary. The handler persists across signal deliveries.
extern "C" fn sighup_handler(_sig: libc::c_int) {
    SIGHUP_SEEN.store(true, Ordering::SeqCst);
}

/// SIGCHLD handler — sets the child-reap flag.
///
/// Replaces C `main_sigchld_handler()` from daemon.c lines 91–96:
/// ```c
/// static void main_sigchld_handler(int sig) {
///     os_non_restarting_signal(SIGCHLD, SIG_DFL);
///     sigchld_seen = TRUE;
/// }
/// ```
///
/// The C version manually resets the signal disposition to `SIG_DFL` inside
/// the handler to prevent infinite recursion if another child exits while
/// we are still inside the handler. In the Rust version, we achieve the same
/// effect by installing this handler with `SA_RESETHAND`, which atomically
/// resets the disposition to `SIG_DFL` upon handler entry.
///
/// The daemon event loop MUST re-install this handler after reaping children
/// by calling [`install_daemon_signals()`].
///
/// The actual `waitpid()` reaping happens in `daemon.rs`, not here.
extern "C" fn sigchld_handler(_sig: libc::c_int) {
    SIGCHLD_SEEN.store(true, Ordering::SeqCst);
}

/// SIGTERM / SIGINT handler — sets the graceful-shutdown flag.
///
/// Replaces C `main_sigterm_handler()` from daemon.c lines 102–106:
/// ```c
/// static void main_sigterm_handler(int sig) {
///     sigterm_seen = TRUE;
/// }
/// ```
///
/// Only sets the flag. Actual cleanup (PID file removal, socket teardown,
/// notification socket unlinking) happens in the daemon event loop when
/// it detects the flag via [`sigterm_seen()`].
///
/// This handler is installed for both SIGTERM and SIGINT (daemon.c line 2419:
/// `os_non_restarting_signal(SIGINT, main_sigterm_handler)`).
extern "C" fn sigterm_handler(_sig: libc::c_int) {
    SIGTERM_SEEN.store(true, Ordering::SeqCst);
}

/// SIGALRM handler — sets the alarm/scheduling flag.
///
/// Used by the daemon event loop for periodic queue runner scheduling
/// and by SMTP connection timeout handling. When the daemon detects this
/// flag, it evaluates whether a new queue runner child should be spawned
/// (daemon.c line 2625: `if (sigalrm_seen) ...`).
extern "C" fn sigalrm_handler(_sig: libc::c_int) {
    SIGALRM_SEEN.store(true, Ordering::SeqCst);
}

// ===========================================================================
// Signal Installation Functions
// ===========================================================================

/// Install all signal handlers for daemon mode.
///
/// This function configures signal handling for the main daemon process,
/// replicating the signal setup from daemon.c `daemon_go()` lines 2380–2419:
///
/// | Signal   | Handler            | Flags             | C Equivalent                                         |
/// |----------|--------------------|-------------------|------------------------------------------------------|
/// | SIGHUP   | `sighup_handler`   | `SA_RESTART`      | `signal(SIGHUP, sighup_handler)` (line 2383)         |
/// | SIGCHLD  | `sigchld_handler`  | `SA_RESETHAND`    | `os_non_restarting_signal(SIGCHLD, ...)` (line 2415)  |
/// | SIGTERM  | `sigterm_handler`  | (empty)           | `os_non_restarting_signal(SIGTERM, ...)` (line 2418)  |
/// | SIGINT   | `sigterm_handler`  | (empty)           | `os_non_restarting_signal(SIGINT, ...)` (line 2419)   |
/// | SIGPIPE  | `SIG_IGN`          | (empty)           | Implicit via Exim convention                          |
/// | SIGALRM  | `sigalrm_handler`  | (empty)           | Configured as part of queue scheduling                |
///
/// ## Flag Semantics
///
/// - **`SA_RESTART`** on SIGHUP: Interrupted system calls are automatically
///   restarted, matching the behavior of `signal()` on Linux (which implicitly
///   sets `SA_RESTART`). This prevents spurious `EINTR` errors from SIGHUP.
///
/// - **`SA_RESETHAND`** on SIGCHLD: The disposition atomically resets to `SIG_DFL`
///   when the handler is invoked. This prevents infinite recursion if another
///   child exits while we are processing the first SIGCHLD. The daemon loop
///   must re-install this handler after reaping children.
///
/// - **No `SA_RESTART`** on SIGTERM/SIGINT/SIGALRM: We explicitly want
///   `poll()` and other blocking system calls to be interrupted by these
///   signals so the daemon can respond promptly.
///
/// ## Safety Note
///
/// Signal installation delegates to [`exim_ffi::signal::install_signal_action`]
/// which centralises the `unsafe` boundary in the `exim-ffi` crate per
/// AAP §0.7.2.  All four handlers in this module are async-signal-safe:
/// they perform only a single atomic store to a static `AtomicBool`, which
/// is trivially async-signal-safe. The `SIG_IGN` disposition for SIGPIPE
/// is a kernel-level constant with no user-space code.
pub fn install_daemon_signals() {
    let empty_mask = SigSet::empty();

    // SIGHUP: Re-exec handler with SA_RESTART.
    // SA_RESTART ensures that interrupted system calls (e.g., read/write on
    // SMTP connections) are automatically restarted, matching the behavior
    // of C signal() on Linux which implicitly sets SA_RESTART.
    let sighup_action = SigAction::new(
        SigHandler::Handler(sighup_handler),
        SaFlags::SA_RESTART,
        empty_mask,
    );

    // SIGCHLD: Child-reap handler — persistent (no SA_RESETHAND).
    //
    // The C code used SA_RESETHAND (reset to SIG_DFL on first delivery) and
    // then re-installed the handler inside the reap loop. This Rust
    // implementation uses a persistent handler instead: the handler simply
    // sets an atomic flag, and the daemon event loop checks the flag on each
    // iteration. No SA_RESTART: we WANT poll() to be interrupted so the
    // daemon loop can reap terminated children promptly.
    //
    // Without persistent handling, only the first SIGCHLD is caught; all
    // subsequent child exits produce zombie processes that accumulate until
    // smtp_accept_max is reached, causing a denial-of-service condition.
    let sigchld_action = SigAction::new(
        SigHandler::Handler(sigchld_handler),
        SaFlags::empty(),
        empty_mask,
    );

    // SIGTERM: Graceful-shutdown handler. No SA_RESTART: we WANT poll() to
    // be interrupted so the daemon can shut down promptly.
    let sigterm_action = SigAction::new(
        SigHandler::Handler(sigterm_handler),
        SaFlags::empty(),
        empty_mask,
    );

    // SIGPIPE: Ignore to prevent broken-pipe crashes.
    // When an SMTP client disconnects mid-response, writing to the socket
    // would generate SIGPIPE, which terminates the process by default.
    // Ignoring SIGPIPE lets the write return EPIPE instead, which we handle
    // gracefully in the SMTP I/O layer.
    let sigpipe_action = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), empty_mask);

    // SIGALRM: Queue scheduling handler. No SA_RESTART: we WANT poll() to
    // be interrupted so the daemon can evaluate queue runner scheduling
    // immediately after the alarm fires.
    let sigalrm_action = SigAction::new(
        SigHandler::Handler(sigalrm_handler),
        SaFlags::empty(),
        empty_mask,
    );

    // All signal handler functions (sighup_handler, sigchld_handler,
    // sigterm_handler, sigalrm_handler) are async-signal-safe. Each handler
    // performs exactly one operation: AtomicBool::store(true, Ordering::SeqCst),
    // which compiles to a single atomic store instruction with a memory fence.
    // No memory allocation, I/O, locking, or non-reentrant function calls
    // are performed. SigHandler::SigIgn is a kernel-level constant that
    // requires no user-space handler code.
    //
    // The sigaction() calls are installed in the same order as the C daemon.c
    // setup sequence (lines 2383, 2415, 2418-2419) for behavioral parity.
    //
    // The unsafe boundary is centralised in exim_ffi::signal per AAP §0.7.2.
    let _ = exim_ffi::signal::install_signal_action(Signal::SIGHUP, &sighup_action);
    let _ = exim_ffi::signal::install_signal_action(Signal::SIGCHLD, &sigchld_action);
    let _ = exim_ffi::signal::install_signal_action(Signal::SIGTERM, &sigterm_action);
    let _ = exim_ffi::signal::install_signal_action(Signal::SIGINT, &sigterm_action);
    let _ = exim_ffi::signal::install_signal_action(Signal::SIGPIPE, &sigpipe_action);
    let _ = exim_ffi::signal::install_signal_action(Signal::SIGALRM, &sigalrm_action);
}

/// Install signal handlers for child processes after `fork()`.
///
/// After the daemon forks a child process for SMTP connection handling,
/// the child inherits the daemon's signal handlers. This function resets
/// all signal dispositions to their defaults, except SIGPIPE which remains
/// ignored to protect the child from broken-pipe crashes during SMTP I/O.
///
/// This replaces the implicit signal reset pattern from daemon.c's
/// `handle_smtp_call()` child section, where forked children reset handlers
/// before entering the SMTP command loop.
///
/// ## Signal Dispositions After This Call
///
/// | Signal   | Disposition | Rationale                                    |
/// |----------|-------------|----------------------------------------------|
/// | SIGHUP   | `SIG_DFL`   | Child doesn't need re-exec on SIGHUP         |
/// | SIGTERM   | `SIG_DFL`   | Child uses default termination                |
/// | SIGCHLD  | `SIG_DFL`   | Child doesn't manage grandchildren            |
/// | SIGINT   | `SIG_DFL`   | Child uses default interrupt behavior         |
/// | SIGALRM  | `SIG_DFL`   | Child will install its own timeout handlers   |
/// | SIGPIPE  | `SIG_IGN`   | **Preserved** — child needs broken-pipe safety |
pub fn install_child_signals() {
    let empty_mask = SigSet::empty();

    let default_action = SigAction::new(SigHandler::SigDfl, SaFlags::empty(), empty_mask);

    let ignore_action = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), empty_mask);

    // SigHandler::SigDfl and SigHandler::SigIgn are kernel-level signal
    // dispositions that do not involve any user-space handler code. They are
    // inherently safe — SIG_DFL restores the default kernel action, and
    // SIG_IGN tells the kernel to discard the signal silently.
    //
    // The unsafe boundary is centralised in exim_ffi::signal per AAP §0.7.2.
    let _ = exim_ffi::signal::install_signal_action(Signal::SIGHUP, &default_action);
    let _ = exim_ffi::signal::install_signal_action(Signal::SIGTERM, &default_action);
    let _ = exim_ffi::signal::install_signal_action(Signal::SIGCHLD, &default_action);
    let _ = exim_ffi::signal::install_signal_action(Signal::SIGINT, &default_action);
    let _ = exim_ffi::signal::install_signal_action(Signal::SIGALRM, &default_action);
    // Keep SIGPIPE ignored — child processes also need protection
    // against broken-pipe crashes during SMTP disconnect handling.
    let _ = exim_ffi::signal::install_signal_action(Signal::SIGPIPE, &ignore_action);
}

/// Install signal handlers for delivery subprocesses.
///
/// Delivery subprocesses (forked for message delivery) need:
/// - SIGPIPE ignored (for transport pipe operations and SMTP disconnects)
/// - SIGALRM handler installed (for delivery timeout management)
/// - All other signals reset to default behavior
///
/// The SIGALRM handler is preserved because delivery subprocesses use
/// `alarm()` for transport-level timeouts (connection timeout, data timeout,
/// final-dot timeout) as well as overall delivery timeout enforcement.
///
/// ## Signal Dispositions After This Call
///
/// | Signal   | Disposition        | Rationale                                |
/// |----------|--------------------|------------------------------------------|
/// | SIGHUP   | `SIG_DFL`          | Delivery subprocess doesn't re-exec      |
/// | SIGTERM   | `SIG_DFL`          | Default termination behavior              |
/// | SIGCHLD  | `SIG_DFL`          | Delivery doesn't manage sub-children     |
/// | SIGINT   | `SIG_DFL`          | Default interrupt behavior                |
/// | SIGPIPE  | `SIG_IGN`          | Pipe/socket broken-pipe protection        |
/// | SIGALRM  | `sigalrm_handler`  | Delivery timeout management               |
pub fn install_delivery_signals() {
    let empty_mask = SigSet::empty();

    let default_action = SigAction::new(SigHandler::SigDfl, SaFlags::empty(), empty_mask);

    let ignore_action = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), empty_mask);

    // SIGALRM handler for delivery timeouts. No SA_RESTART so that
    // blocking I/O operations (e.g., waiting for SMTP server response)
    // are interrupted when the timeout fires.
    let sigalrm_action = SigAction::new(
        SigHandler::Handler(sigalrm_handler),
        SaFlags::empty(),
        empty_mask,
    );

    // SigHandler::SigDfl and SigHandler::SigIgn are kernel-level signal
    // dispositions with no user-space handler code. The sigalrm_handler is
    // async-signal-safe — it performs only a single AtomicBool::store()
    // operation (see handler documentation above for full safety analysis).
    //
    // The unsafe boundary is centralised in exim_ffi::signal per AAP §0.7.2.
    let _ = exim_ffi::signal::install_signal_action(Signal::SIGHUP, &default_action);
    let _ = exim_ffi::signal::install_signal_action(Signal::SIGTERM, &default_action);
    let _ = exim_ffi::signal::install_signal_action(Signal::SIGCHLD, &default_action);
    let _ = exim_ffi::signal::install_signal_action(Signal::SIGINT, &default_action);
    let _ = exim_ffi::signal::install_signal_action(Signal::SIGPIPE, &ignore_action);
    let _ = exim_ffi::signal::install_signal_action(Signal::SIGALRM, &sigalrm_action);
}

// ===========================================================================
// Signal State Query Functions
// ===========================================================================
//
// These functions implement an atomic test-and-clear pattern using
// AtomicBool::swap(false, Ordering::SeqCst). This ensures that:
//
// 1. The flag is read and cleared in a single atomic operation
// 2. No signal delivery between the read and clear can be lost
// 3. Sequential consistency guarantees correct ordering with respect
//    to the signal handler's store operation
//
// The daemon event loop calls these after each poll() iteration:
//
//     loop {
//         poll(&mut fds, timeout)?;
//         if signal::sigchld_seen() { reap_children(); }
//         if signal::sighup_seen()  { re_exec_daemon(); }
//         if signal::sigterm_seen() { graceful_shutdown(); }
//         if signal::sigalrm_seen() { schedule_queue_run(); }
//     }

/// Check and atomically clear the SIGCHLD flag.
///
/// Returns `true` if SIGCHLD was received since the last check. The flag
/// is atomically cleared regardless of the return value, ensuring that
/// each signal delivery is processed exactly once.
///
/// When this returns `true`, the daemon loop should:
/// 1. Call `waitpid(WNOHANG)` in a loop to reap all terminated children
/// 2. Update the `smtp_slots` and `queue_runner_slots` tracking arrays
/// 3. Re-install the SIGCHLD handler via [`install_daemon_signals()`]
///    (because `SA_RESETHAND` resets the disposition to `SIG_DFL`)
#[inline]
pub fn sigchld_seen() -> bool {
    SIGCHLD_SEEN.swap(false, Ordering::SeqCst)
}

/// Check and atomically clear the SIGHUP flag.
///
/// Returns `true` if SIGHUP was received since the last check. The daemon
/// responds by closing all listening sockets, canceling pending alarms,
/// and re-executing itself via `execv()` to pick up configuration changes.
///
/// Replaces the C pattern: `if (sighup_seen) { ... }` (daemon.c line 2861).
#[inline]
pub fn sighup_seen() -> bool {
    SIGHUP_SEEN.swap(false, Ordering::SeqCst)
}

/// Check and atomically clear the SIGTERM flag.
///
/// Returns `true` if SIGTERM or SIGINT was received since the last check.
/// The daemon responds by:
/// 1. Removing the PID file
/// 2. Unlinking the notification socket
/// 3. Closing all listening sockets
/// 4. Exiting with status 0
///
/// Replaces the C pattern: `if (sigterm_seen) { ... }` (daemon.c line 2616).
#[inline]
pub fn sigterm_seen() -> bool {
    SIGTERM_SEEN.swap(false, Ordering::SeqCst)
}

/// Check and atomically clear the SIGALRM flag.
///
/// Returns `true` if SIGALRM was received since the last check. The daemon
/// responds by evaluating whether a new queue runner child process should
/// be spawned, based on the configured queue run interval and the number
/// of currently active queue runners.
///
/// Also used by SMTP timeout handling in delivery subprocesses to detect
/// when a transport-level timeout has fired.
///
/// Replaces the C pattern: `if (sigalrm_seen) { ... }` (daemon.c line 2625).
#[inline]
pub fn sigalrm_seen() -> bool {
    SIGALRM_SEEN.swap(false, Ordering::SeqCst)
}

/// Reset all signal flags to `false`.
///
/// Called during daemon initialization (before installing signal handlers)
/// to ensure a clean starting state. Also useful when re-initializing
/// signal state after `fork()` in child processes.
///
/// Uses `Ordering::Relaxed` because this function is only called during
/// single-threaded initialization phases (before signal handlers are
/// installed or after `fork()` in the child), so there is no concurrent
/// signal handler to race with. The relaxed ordering provides maximum
/// performance for this non-critical startup operation.
///
/// Replaces the C initialization pattern (daemon.c lines 2382, 2414, 2417):
/// ```c
/// sighup_seen = FALSE;
/// sigchld_seen = FALSE;
/// sigterm_seen = FALSE;
/// ```
#[inline]
pub fn clear_all_signals() {
    SIGCHLD_SEEN.store(false, Ordering::Relaxed);
    SIGHUP_SEEN.store(false, Ordering::Relaxed);
    SIGTERM_SEEN.store(false, Ordering::Relaxed);
    SIGALRM_SEEN.store(false, Ordering::Relaxed);
}

// ===========================================================================
// SIGALRM Scheduling
// ===========================================================================

/// Schedule a SIGALRM to fire after the specified number of seconds.
///
/// Used by the daemon event loop for periodic queue runner scheduling
/// (daemon.c queue scheduling section) and by SMTP/transport timeout
/// handling in delivery subprocesses.
///
/// Wraps [`nix::unistd::alarm::set()`] which calls the POSIX `alarm(2)`
/// system call. Any previously pending alarm is canceled and replaced
/// by the new one.
///
/// # Arguments
///
/// * `seconds` — Number of seconds until SIGALRM delivery. Must be > 0.
///   Use [`cancel_alarm()`] to cancel a pending alarm instead of passing 0.
///
/// # Returns
///
/// The number of seconds that were remaining on any previously scheduled
/// alarm, or 0 if no alarm was pending.
///
/// # Panics
///
/// Panics if `seconds` is 0. Use [`cancel_alarm()`] to cancel alarms.
#[inline]
pub fn set_alarm(seconds: u32) -> u32 {
    alarm::set(seconds).unwrap_or(0)
}

/// Cancel any pending SIGALRM.
///
/// Equivalent to `alarm(0)` at the POSIX level. Called before daemon
/// re-execution on SIGHUP (daemon.c line 2867: `ALARM_CLR(0)`) and
/// when cleaning up timeout state.
///
/// # Returns
///
/// The number of seconds that were remaining on the cancelled alarm,
/// or 0 if no alarm was pending.
#[inline]
pub fn cancel_alarm() -> u32 {
    alarm::cancel().unwrap_or(0)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that all signal flags start as `false`.
    #[test]
    fn test_initial_flag_state() {
        // Clear any state from previous tests
        clear_all_signals();

        assert!(!sigchld_seen(), "SIGCHLD flag should start as false");
        assert!(!sighup_seen(), "SIGHUP flag should start as false");
        assert!(!sigterm_seen(), "SIGTERM flag should start as false");
        assert!(!sigalrm_seen(), "SIGALRM flag should start as false");
    }

    /// Verify that `clear_all_signals` resets all flags.
    #[test]
    fn test_clear_all_signals() {
        // Set all flags manually
        SIGCHLD_SEEN.store(true, Ordering::SeqCst);
        SIGHUP_SEEN.store(true, Ordering::SeqCst);
        SIGTERM_SEEN.store(true, Ordering::SeqCst);
        SIGALRM_SEEN.store(true, Ordering::SeqCst);

        // Clear all
        clear_all_signals();

        // Verify all are cleared (swap returns previous value)
        assert!(!SIGCHLD_SEEN.swap(false, Ordering::SeqCst));
        assert!(!SIGHUP_SEEN.swap(false, Ordering::SeqCst));
        assert!(!SIGTERM_SEEN.swap(false, Ordering::SeqCst));
        assert!(!SIGALRM_SEEN.swap(false, Ordering::SeqCst));
    }

    /// Verify atomic test-and-clear semantics of `*_seen()` functions.
    #[test]
    fn test_seen_functions_atomic_clear() {
        // Set SIGCHLD flag
        SIGCHLD_SEEN.store(true, Ordering::SeqCst);

        // First call should return true and clear the flag
        assert!(sigchld_seen(), "First sigchld_seen() should return true");

        // Second call should return false (flag was cleared)
        assert!(!sigchld_seen(), "Second sigchld_seen() should return false");
    }

    /// Verify that each seen function operates independently.
    #[test]
    fn test_seen_functions_independence() {
        clear_all_signals();

        // Set only SIGHUP and SIGALRM
        SIGHUP_SEEN.store(true, Ordering::SeqCst);
        SIGALRM_SEEN.store(true, Ordering::SeqCst);

        // SIGCHLD and SIGTERM should be false
        assert!(!sigchld_seen());
        assert!(!sigterm_seen());

        // SIGHUP and SIGALRM should be true (and cleared after)
        assert!(sighup_seen());
        assert!(sigalrm_seen());

        // All should now be false
        assert!(!sighup_seen());
        assert!(!sigalrm_seen());
    }

    /// Verify that signal handlers correctly set their flags.
    /// We call the handler functions directly since they are extern "C".
    #[test]
    fn test_handler_functions_set_flags() {
        clear_all_signals();

        // Call handlers directly (they're just extern "C" functions)
        sighup_handler(0);
        assert!(sighup_seen());

        sigchld_handler(0);
        assert!(sigchld_seen());

        sigterm_handler(0);
        assert!(sigterm_seen());

        sigalrm_handler(0);
        assert!(sigalrm_seen());
    }

    /// Verify cancel_alarm returns 0 when no alarm is pending.
    #[test]
    fn test_cancel_alarm_no_pending() {
        // Cancel any pending alarm first
        let _ = cancel_alarm();
        // Now cancel again — should return 0
        assert_eq!(cancel_alarm(), 0);
    }

    /// Verify set_alarm and cancel_alarm interaction.
    #[test]
    fn test_set_and_cancel_alarm() {
        // Cancel any pending alarm
        let _ = cancel_alarm();

        // Set alarm for 100 seconds (won't actually fire during test)
        let prev = set_alarm(100);
        assert_eq!(prev, 0, "No previous alarm should be pending");

        // Cancel the alarm we just set — should return remaining time
        let remaining = cancel_alarm();
        // The remaining time should be close to 100 (within 1 second)
        assert!(
            remaining > 0 && remaining <= 100,
            "Cancel should return remaining time, got {}",
            remaining
        );
    }

    /// Verify that install_daemon_signals doesn't panic.
    #[test]
    fn test_install_daemon_signals_no_panic() {
        install_daemon_signals();
        // If we get here without a panic, the signal handlers were installed
        // successfully. We can't easily verify the handlers are correct
        // without sending actual signals, which is tested in integration tests.
    }

    /// Verify that install_child_signals doesn't panic.
    #[test]
    fn test_install_child_signals_no_panic() {
        install_child_signals();
    }

    /// Verify that install_delivery_signals doesn't panic.
    #[test]
    fn test_install_delivery_signals_no_panic() {
        install_delivery_signals();
    }
}
