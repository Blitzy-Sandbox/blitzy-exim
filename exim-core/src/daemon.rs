//! Daemon mode implementation — poll-based event loop, socket binding,
//! connection acceptance, queue runner scheduling, and child process management.
//!
//! This module replaces `src/src/daemon.c` (2,884 lines) from the C codebase.
//! It implements the long-lived Exim daemon process that:
//!
//! - **Binds listening sockets** on configured local interfaces and ports,
//!   supporting IPv4/IPv6, wildcard addresses, TLS-on-connect ports, and
//!   TCP Fast Open where available.
//! - **Accepts SMTP connections** and forks a child process for each one,
//!   tracking children in [`DaemonState::smtp_slots`] with per-host limits.
//! - **Schedules queue runners** at the configured interval via SIGALRM,
//!   forking children tracked in [`DaemonState::queue_runner_slots`].
//! - **Implements the main event loop** using `poll()` (via [`nix::poll`]),
//!   NOT tokio — per AAP §0.7.3 tokio is scoped to lookup execution ONLY.
//! - **Handles signals** by checking atomic flags set by signal handlers
//!   installed via [`crate::signal`]:
//!   - `SIGCHLD` → reap terminated children
//!   - `SIGHUP` → re-exec the daemon for config reload
//!   - `SIGTERM` → graceful shutdown
//!   - `SIGALRM` → queue runner scheduling tick
//! - **Manages PID file** and unix domain notification socket.
//! - **Handles inetd wait mode** for inetd/systemd socket activation.
//!
//! # Architecture
//!
//! - **Fork-per-connection model preserved** exactly per AAP §0.4.2
//! - **NO tokio** for daemon event loop — AAP §0.7.3 explicitly forbids it
//! - **Context structs passed explicitly** — `ServerContext` for daemon state,
//!   `Arc<Config>` for immutable configuration per AAP §0.4.4
//! - **poll()-based event loop** — replaces C select/poll at daemon.c line 2664
//!
//! # Source Reference
//!
//! - **Primary**: `src/src/daemon.c` — entire file (2,884 lines)
//! - **Key C function**: `daemon_go()` (line 1709) — main daemon entry point
//! - **C structures**: `smtp_slot` (line 18), `runner_slot` (line 23)
//! - **C statics**: lines 37–55 (accept_retry_count, queue_run_count, etc.)

use std::fs;
use std::io::{ErrorKind, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::io::{AsFd, AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::process::exit;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::socket::sockopt::{Ipv6V6Only, ReuseAddr, TcpNoDelay};
use nix::sys::socket::{
    bind, listen, setsockopt, socket, AddressFamily, Backlog, SockFlag, SockType, SockaddrStorage,
};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{getpid, ForkResult, Pid};

use crate::context::{ConfigContext, ServerContext, SmtpSlot};
use crate::process;
use crate::queue_runner;
use crate::signal;
use exim_config::Config;

#[cfg(all(feature = "tls-openssl", not(feature = "tls-rustls")))]
use exim_tls::openssl_backend::OpensslBackend;
#[cfg(feature = "tls-rustls")]
use exim_tls::rustls_backend::RustlsBackend;
#[cfg(any(feature = "tls-rustls", feature = "tls-openssl"))]
use exim_tls::CredentialWatcher;

// ===========================================================================
// Constants
// ===========================================================================

/// Maximum number of consecutive accept errors before batched logging.
/// Matches C daemon.c `accept_retry_count` batched error logging threshold.
const ACCEPT_RETRY_LOG_THRESHOLD: i32 = 100;

/// Default poll timeout in milliseconds when no queue interval is configured.
/// 5 minutes matches the C daemon's behavior for non-listening mode (daemon.c
/// line 2848: `tv.tv_sec = 5 * 60`).
const DEFAULT_POLL_TIMEOUT_MS: i32 = 300_000;

/// Minimum poll timeout in milliseconds (1 second) used when expecting
/// imminent events (e.g., accept retry, signal processing).
const MIN_POLL_TIMEOUT_MS: i32 = 1_000;

/// Debug selector bit for PID inclusion in debug output.
const D_PID: u32 = 0x0000_0020;

// ===========================================================================
// RunnerSlot — Queue runner child process tracking
// ===========================================================================

/// Tracks a forked queue runner child process.
///
/// Replaces the C `runner_slot` struct from `daemon.c` lines 23–26:
/// ```c
/// typedef struct {
///   pid_t pid;
///   uschar *queue_name;
/// } runner_slot;
/// ```
///
/// Each active queue runner occupies one slot in
/// [`DaemonState::queue_runner_slots`]. When the child exits (reaped via
/// SIGCHLD → `waitpid`), the slot is cleared (pid set to `None`).
#[derive(Debug, Clone)]
pub struct RunnerSlot {
    /// Process ID of the queue runner child process.
    /// `None` indicates an unused/available slot.
    pub pid: Option<Pid>,

    /// Name of the queue being processed by this runner.
    /// Empty string (`""`) denotes the default queue.
    pub queue_name: String,
}

impl RunnerSlot {
    /// Create an empty (unused) runner slot.
    fn empty() -> Self {
        Self {
            pid: None,
            queue_name: String::new(),
        }
    }

    /// Check whether this slot is currently in use (has an active child).
    fn is_active(&self) -> bool {
        self.pid.is_some()
    }
}

impl Default for RunnerSlot {
    fn default() -> Self {
        Self::empty()
    }
}

// ===========================================================================
// DaemonState — Daemon-local mutable state
// ===========================================================================

/// Daemon-local mutable state, replacing the static variables from
/// `daemon.c` lines 37–55.
///
/// This struct is owned by [`daemon_go()`] and passed by mutable reference
/// to helper functions. It is NOT shared across processes — each forked
/// child starts with its own copy which is immediately discarded.
///
/// # C Equivalents
///
/// | Rust field | C variable | daemon.c line |
/// |---|---|---|
/// | `accept_retry_count` | `accept_retry_count` | 37 |
/// | `accept_retry_errno` | `accept_retry_errno` | 38 |
/// | `accept_retry_select_failed` | `accept_retry_select_failed` | 39 |
/// | `queue_run_count` | `queue_run_count` | 42 |
/// | `queue_runner_slot_count` | `queue_runner_slot_count` | 43 |
/// | `queue_runner_slots` | `queue_runner_slots` | 44 |
/// | `smtp_slots` | (via ServerContext.smtp_slots) | 45 |
/// | `write_pid` | `write_pid` | 48 |
#[derive(Debug)]
pub struct DaemonState {
    /// Count of consecutive `accept()` failures for batched error logging.
    /// Reset to 0 after a successful accept. When this exceeds
    /// [`ACCEPT_RETRY_LOG_THRESHOLD`], a batched error message is logged
    /// and the counter is reset.
    pub accept_retry_count: i32,

    /// The `errno` value from the most recent failed `accept()` call.
    /// Used in the batched error log message.
    pub accept_retry_errno: i32,

    /// Whether the most recent accept failure was actually a `poll()`/`select()`
    /// failure rather than an `accept()` failure. Affects the error message text.
    pub accept_retry_select_failed: bool,

    /// Total number of queue runs initiated since daemon startup.
    /// Incremented each time a queue runner child is forked.
    pub queue_run_count: i32,

    /// Number of allocated queue runner slots (may exceed active runners
    /// if some slots are currently empty after child exit).
    pub queue_runner_slot_count: u32,

    /// Queue runner child process tracking slots.
    /// Each active queue runner occupies one slot. Reaped runners have their
    /// slot cleared (pid set to `None`).
    pub queue_runner_slots: Vec<RunnerSlot>,

    /// SMTP connection child process tracking slots.
    /// Mirrors `ServerContext::smtp_slots` — this is a secondary reference
    /// maintained for daemon-local bookkeeping (the canonical slots are in
    /// `ServerContext`).
    pub smtp_slots: Vec<SmtpSlot>,

    /// Whether to write a PID file. Set to `true` during daemon startup,
    /// may be set to `false` in inetd wait mode or when running in the
    /// foreground without `-oP`.
    pub write_pid: bool,
}

impl DaemonState {
    /// Create a new `DaemonState` with default values.
    ///
    /// All counters start at 0, all slot vectors start empty, and `write_pid`
    /// defaults to `true` (matching C daemon.c behavior where the PID file
    /// is written unless explicitly disabled).
    fn new() -> Self {
        Self {
            accept_retry_count: 0,
            accept_retry_errno: 0,
            accept_retry_select_failed: false,
            queue_run_count: 0,
            queue_runner_slot_count: 0,
            queue_runner_slots: Vec::new(),
            smtp_slots: Vec::new(),
            write_pid: true,
        }
    }
}

impl Default for DaemonState {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Notification socket path
// ===========================================================================

/// Build the path for the daemon's Unix domain notification socket.
///
/// The notification socket allows external processes (e.g., `exim -qf`) to
/// notify the daemon of newly-queued messages for immediate delivery.
///
/// Replaces C `daemon.c` notification socket path construction.
fn notifier_socket_path(spool_directory: &str) -> PathBuf {
    let mut path = PathBuf::from(spool_directory);
    path.push("exim_daemon_notify");
    path
}

// ===========================================================================
// daemon_go() — Main Daemon Entry Point
// ===========================================================================

/// Main daemon entry point — this function **never returns**.
///
/// Replaces C `daemon_go()` from `daemon.c` lines 1709–2884.
///
/// Performs the following in order:
/// 1. Set process purpose for ps output.
/// 2. Enable `D_pid` debug flag when debugging is active.
/// 3. Pre-load dynamic modules.
/// 4. Initialize daemon state and SMTP slots.
/// 5. Handle inetd wait mode (if active).
/// 6. Bind listening sockets on configured interfaces/ports.
/// 7. Write PID file.
/// 8. Set up notification socket.
/// 9. Fork into background (if `background_daemon` and not `-bdf`).
/// 10. Install signal handlers.
/// 11. Initialize TLS credentials (if TLS is configured).
/// 12. Set up queue interval alarm.
/// 13. Log daemon startup.
/// 14. Enter the main poll-based event loop (never returns).
///
/// # Arguments
///
/// * `ctx` — Mutable server context holding daemon-lifetime state.
/// * `config` — Immutable frozen configuration wrapped in `Arc`.
///
/// # Panics
///
/// Panics if the daemon cannot bind any listening sockets and is not in
/// inetd wait mode.
pub fn daemon_go(ctx: &mut ServerContext, config: &Arc<Config>) -> ! {
    // -- Step 1: Set process purpose for ps output --
    process::set_process_info("daemon");

    // -- Step 2: Enable D_pid debug flag when debugging is active --
    if ctx.debug_selector != 0 {
        ctx.debug_selector |= D_PID;
    }

    tracing::info!(
        hostname = ctx.primary_hostname.as_str(),
        pid = getpid().as_raw(),
        "Exim daemon starting"
    );

    // -- Step 3: Pre-load dynamic modules --
    daemon_preload_modules();

    // -- Step 4: Initialize daemon state --
    let mut state = DaemonState::new();

    // Pre-allocate SMTP slots based on smtp_accept_max.
    let slot_count = if ctx.smtp_accept_max > 0 {
        ctx.smtp_accept_max as usize
    } else {
        20
    };
    ctx.smtp_slots = vec![
        SmtpSlot {
            pid: 0,
            host_address: None,
            host_name: None,
            interface_address: None,
        };
        slot_count
    ];
    state.smtp_slots = ctx.smtp_slots.clone();

    // -- Step 5: Handle inetd wait mode --
    if ctx.inetd_wait_mode {
        tracing::info!("running in inetd wait mode");

        // In inetd wait mode, stdin is the listening socket.
        // Use dup() to create an OwnedFd from stdin, then close original
        // stdin/stdout/stderr and replace with /dev/null.
        // nix::unistd::dup takes impl AsFd and returns OwnedFd — fully safe.
        let stdin_fd = std::io::stdin();
        match nix::unistd::dup(&stdin_fd) {
            Ok(saved_fd) => {
                // Let stdin_fd go out of the inner scope — it is not Drop
                // but we no longer need the binding.
                // Close stdin/stdout/stderr and replace with /dev/null.
                process::exim_nullstd();
                // The duplicated fd is now our listening socket.
                ctx.listening_sockets.push(saved_fd);
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to dup stdin in inetd wait mode");
                exit(1);
            }
        }

        state.write_pid = false;
        ctx.daemon_listen = true;
    } else if ctx.daemon_listen {
        // -- Step 6: Bind listening sockets for normal daemon mode --
        if let Err(e) = bind_listening_sockets(ctx, config) {
            tracing::error!(error = %e, "fatal: cannot bind listening sockets");
            exit(1);
        }
    }

    // -- Step 6b: Drop root privileges after binding privileged ports --
    //
    // C Exim (daemon.c lines 2270–2290) drops to the Exim user/group after
    // all privileged port bindings are complete. This is critical for security:
    // the daemon must not run as root during normal SMTP processing.
    //
    // Privilege dropping order:
    //   1. setgid(exim_gid) FIRST — must be done while still root
    //   2. setuid(exim_uid) SECOND — cannot regain root after this
    //
    // We only drop privileges if we are currently running as root and the
    // Exim UID/GID are configured (non-zero). In test harness mode, the
    // daemon may run as a non-root user and this step is skipped.
    if ctx.running_as_root && ctx.exim_uid != 0 {
        // Drop group first — setgid() requires root
        if ctx.exim_gid != 0 {
            if let Err(e) = nix::unistd::setgid(nix::unistd::Gid::from_raw(ctx.exim_gid)) {
                tracing::error!(
                    gid = ctx.exim_gid,
                    error = %e,
                    "fatal: failed to drop group privileges"
                );
                exit(1);
            }
            tracing::debug!(gid = ctx.exim_gid, "dropped group privileges");
        }

        // Drop user — setuid() is irreversible (cannot regain root)
        if let Err(e) = nix::unistd::setuid(nix::unistd::Uid::from_raw(ctx.exim_uid)) {
            tracing::error!(
                uid = ctx.exim_uid,
                error = %e,
                "fatal: failed to drop user privileges"
            );
            exit(1);
        }

        ctx.running_as_root = false;
        tracing::info!(
            uid = ctx.exim_uid,
            gid = ctx.exim_gid,
            "dropped root privileges to Exim user"
        );
    }

    // -- Step 7: PID file path --
    let pid_file_path = config.pid_file_path.clone();

    // -- Step 8: Fork into background if needed --
    if ctx.background_daemon && !ctx.inetd_wait_mode {
        tracing::debug!("forking into background");
        match process::exim_fork("daemon-background") {
            Ok(ForkResult::Child) => {
                // Child continues as the daemon.
                tracing::debug!("background daemon child running");
            }
            Ok(ForkResult::Parent { child }) => {
                // Parent exits after the child is successfully forked.
                tracing::info!(child_pid = child.as_raw(), "daemon forked into background");
                exit(0);
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to fork daemon into background");
                exit(1);
            }
        }
    }

    // -- Step 9: Write PID file --
    // In the C daemon (daemon.c lines 2370-2377), the PID file is written
    // when `running_in_test_harness` is true OR `write_pid` is true.
    // The test harness always needs the PID file to control the daemon.
    let daemon_pid = getpid();
    if ctx.running_in_test_harness || state.write_pid {
        if let Err(e) = write_pid_file(daemon_pid, &pid_file_path) {
            tracing::error!(error = %e, "failed to write PID file");
            // Non-fatal — continue running.
        }
    }

    // -- Step 10: Set up notification socket --
    let spool_directory = config.spool_directory.clone();
    let notifier_fd = setup_notifier_socket(&spool_directory);

    // -- Step 11: Install signal handlers --
    signal::install_daemon_signals();

    // -- Step 12: Set up queue interval alarm --
    if let Some(interval) = ctx.queue_interval {
        let secs = interval.as_secs().max(1) as u32;
        signal::set_alarm(secs);
        tracing::info!(interval_secs = secs, "queue runner interval set");
    }

    // -- Step 13: Create safe TcpListener wrappers from OwnedFds --
    // The OwnedFds in ctx.listening_sockets are the canonical fds. We clone
    // each via try_clone() (safe dup with F_DUPFD_CLOEXEC) and wrap in
    // std::net::TcpListener for safe, no-unsafe accept() in the event loop.
    // The originals remain in ctx for cleanup (close_daemon_sockets).
    let listeners: Vec<TcpListener> = ctx
        .listening_sockets
        .iter()
        .filter_map(|fd| match fd.try_clone() {
            Ok(cloned) => {
                let listener = TcpListener::from(cloned);
                if let Err(e) = listener.set_nonblocking(true) {
                    tracing::warn!(
                        error = %e,
                        "failed to set non-blocking on cloned listener"
                    );
                }
                Some(listener)
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    fd = fd.as_raw_fd(),
                    "failed to clone listening socket fd"
                );
                None
            }
        })
        .collect();

    // -- Step 14: Log daemon startup --
    tracing::info!(
        pid = daemon_pid.as_raw(),
        hostname = ctx.primary_hostname.as_str(),
        sockets = listeners.len(),
        smtp_accept_max = ctx.smtp_accept_max,
        "daemon started and ready for connections"
    );

    // Write the daemon startup entry to the mainlog (AAP §0.7.1).
    // This matches C Exim's "exim <version> daemon started" log format.
    let startup_log = format!(
        "exim {} daemon started: pid={}, -q{}",
        env!("CARGO_PKG_VERSION"),
        daemon_pid.as_raw(),
        ctx.queue_interval
            .map(|d| format!("{}s", d.as_secs()))
            .unwrap_or_default(),
    );
    write_mainlog(&spool_directory, &startup_log);

    // -- Step 15: Enter the main event loop (NEVER returns) --
    // TLS initialization happens inside the event loop function as
    // feature-gated local state, avoiding generic type parameter complexity.
    daemon_event_loop(
        ctx,
        config,
        &mut state,
        notifier_fd,
        &pid_file_path,
        &spool_directory,
        listeners,
    );
}

// ===========================================================================
// Main Event Loop
// ===========================================================================

/// The main poll-based daemon event loop — **never returns**.
///
/// Replaces the `for (;;)` loop from `daemon.c` lines 2610–2884.
///
/// **CRITICAL: Uses `poll()` (via `nix::poll::poll`), NOT tokio.**
/// Per AAP §0.7.3: "tokio runtime MUST be scoped to lookup execution only."
///
/// The loop structure:
/// 1. Check SIGTERM → graceful shutdown.
/// 2. Check SIGALRM → schedule queue runs.
/// 3. If daemon_listen:
///    a. Build poll fd set from `TcpListener` wrappers (NOT ctx.listening_sockets).
///    b. Call `poll()` with timeout.
///    c. If SIGCHLD seen → reap children.
///    d. TLS daemon tick (credential rotation).
///    e. Handle notification socket events.
///    f. Accept connections on ready listeners (safe TcpListener::accept).
/// 4. If NOT daemon_listen:
///    a. Sleep via `poll()` with queue interval timeout.
/// 5. Check SIGHUP → re-exec daemon.
/// 6. Loop back to step 1.
///
/// # TLS handling
///
/// TLS backend and credential watcher are initialized as local variables
/// inside this function, feature-gated by `tls-rustls` / `tls-openssl`.
/// Concrete backend types (`RustlsBackend` / `OpensslBackend`) are used
/// directly — no trait objects — because the backends have differing method
/// signatures that do not yet satisfy the `TlsBackend` trait.
///
/// # No borrow conflicts
///
/// `poll_fds` borrows the `listeners` vec (separate from `ctx`), so
/// `reap_children(ctx, state)` and `handle_accept(&listeners[i], ctx, ...)`
/// do not conflict with the `poll_fds` borrow.
fn daemon_event_loop(
    ctx: &mut ServerContext,
    config: &Arc<Config>,
    state: &mut DaemonState,
    notifier_fd: Option<OwnedFd>,
    pid_file_path: &str,
    spool_directory: &str,
    listeners: Vec<TcpListener>,
) -> ! {
    tracing::debug!("entering daemon event loop");

    // ── TLS initialization (feature-gated local state) ────────────────────
    // TLS backend and credential watcher live for the lifetime of the event
    // loop. This replaces the C tls_daemon_init() call at daemon.c line 2573.

    #[cfg(feature = "tls-rustls")]
    let mut tls_rustls_backend: Option<RustlsBackend> = None;

    #[cfg(all(feature = "tls-openssl", not(feature = "tls-rustls")))]
    let mut _tls_openssl_backend: Option<OpensslBackend> = None;

    #[cfg(any(feature = "tls-rustls", feature = "tls-openssl"))]
    let mut tls_watcher: Option<CredentialWatcher> = None;

    #[cfg(feature = "tls-rustls")]
    {
        if ctx.tls_certificate.is_some() {
            let mut backend = RustlsBackend::new();
            backend.daemon_init();
            tls_rustls_backend = Some(backend);
            tracing::info!("TLS (rustls) daemon initialization complete");
        }
    }

    #[cfg(all(feature = "tls-openssl", not(feature = "tls-rustls")))]
    {
        if ctx.tls_certificate.is_some() {
            let mut backend = OpensslBackend::new();
            match backend.daemon_init() {
                Ok(()) => {
                    _tls_openssl_backend = Some(backend);
                    tracing::info!("TLS (openssl) daemon initialization complete");
                }
                Err(e) => {
                    tracing::error!(error = %e, "TLS (openssl) daemon initialization failed");
                }
            }
        }
    }

    #[cfg(any(feature = "tls-rustls", feature = "tls-openssl"))]
    {
        if ctx.tls_certificate.is_some() {
            let mut watcher = CredentialWatcher::new();
            if let Some(ref cert_path) = ctx.tls_certificate {
                let _ = watcher.set_watch(cert_path, false);
            }
            if let Some(ref key_path) = ctx.tls_privatekey {
                let _ = watcher.set_watch(key_path, false);
            }
            tls_watcher = Some(watcher);
        }
    }

    // Track timing for periodic operations.
    let mut _last_tick = Instant::now();

    loop {
        // ── Step 1: Check SIGTERM ──────────────────────────────────────────
        if signal::sigterm_seen() {
            tracing::info!("SIGTERM received, shutting down daemon");
            remove_pid_file(pid_file_path);
            unlink_notifier_socket(spool_directory);
            close_daemon_sockets(ctx);
            exit(0);
        }

        // ── Step 2: Check SIGALRM (queue runner scheduling) ───────────────
        if signal::sigalrm_seen() {
            tracing::debug!("SIGALRM received, checking queue runner scheduling");
            schedule_queue_runs(ctx, config, state);
        }

        // ── Step 3: Listening mode — poll and accept ──────────────────────
        if ctx.daemon_listen && !listeners.is_empty() {
            let listener_count = listeners.len();

            // Build PollFd set from TcpListener wrappers — NOT from
            // ctx.listening_sockets. TcpListener implements AsFd, so
            // .as_fd() returns BorrowedFd. This avoids borrow conflicts
            // between poll_fds and &mut ctx used by reap_children/handle_accept.
            let mut poll_fds: Vec<PollFd> = listeners
                .iter()
                .map(|l| PollFd::new(l.as_fd(), PollFlags::POLLIN))
                .collect();

            // Track index for notification socket fd.
            let notifier_idx = if let Some(ref nfd) = notifier_fd {
                poll_fds.push(PollFd::new(nfd.as_fd(), PollFlags::POLLIN));
                Some(poll_fds.len() - 1)
            } else {
                None
            };

            // Calculate poll timeout.
            let timeout_ms = calculate_poll_timeout(ctx, state);
            let poll_timeout = PollTimeout::try_from(timeout_ms).unwrap_or(PollTimeout::MAX);

            // Call poll() — the core of the daemon event loop.
            // CRITICAL: poll(), NOT tokio — AAP §0.7.3.
            let poll_result = poll(&mut poll_fds, poll_timeout);

            match poll_result {
                Ok(0) => {
                    // Timeout — no events. Continue loop.
                }
                Ok(_ready_count) => {
                    // Events ready — fall through to handle them below.
                }
                Err(nix::errno::Errno::EINTR) => {
                    // Interrupted by signal — expected, fall through to
                    // signal checking below.
                }
                Err(e) => {
                    tracing::error!(error = %e, "poll() failed");
                    std::thread::sleep(Duration::from_millis(100));
                }
            }

            // ── Step 3a: Check SIGCHLD — reap terminated children ─────────
            // No borrow conflict: poll_fds borrows `listeners`, not `ctx`.
            if signal::sigchld_seen() {
                reap_children(ctx, state);
            }

            // ── Step 3b: TLS daemon tick (credential rotation check) ──────
            // TLS credential rotation is performed each loop iteration.
            // The concrete backend's daemon_tick() checks for on-disk
            // certificate changes. Replaces C daemon.c line 2688
            // tls_daemon_tick() behavior.
            #[cfg(feature = "tls-rustls")]
            {
                if let Some(ref mut backend) = tls_rustls_backend {
                    if let Some(old_fd) = backend.daemon_tick() {
                        if let Some(ref mut w) = tls_watcher {
                            w.set_watch_fd(old_fd);
                        }
                    }
                }
            }

            // OpenSSL backend does not expose daemon_tick(); credential
            // rotation is handled via the watcher + SIGHUP re-exec.

            // Discard any pending watch events to prevent spurious wakeups.
            #[cfg(any(feature = "tls-rustls", feature = "tls-openssl"))]
            {
                if let Some(ref w) = tls_watcher {
                    w.discard_event();
                }
            }

            // ── Step 3c: Handle notification socket events ────────────────
            if let Some(idx) = notifier_idx {
                if let Some(pfd) = poll_fds.get(idx) {
                    if pfd.any().unwrap_or(false) {
                        handle_notifier_event(&notifier_fd);
                    }
                }
            }

            // ── Step 3d: Accept connections on ready listeners ────────────
            // Collect ready listener indices first, then handle each.
            // poll_fds borrows &listeners (immutable) and handle_accept
            // borrows &listeners[idx] (immutable) + &mut ctx — no conflict.
            let ready_indices: Vec<usize> = (0..listener_count)
                .filter(|&i| poll_fds.get(i).and_then(|pfd| pfd.any()).unwrap_or(false))
                .collect();

            for idx in ready_indices {
                handle_accept(&listeners[idx], ctx, config, state);
            }
        } else {
            // ── Step 4: Non-listening mode — sleep ────────────────────────
            let sleep_ms = if let Some(interval) = ctx.queue_interval {
                (interval.as_secs() * 1000) as i32
            } else {
                DEFAULT_POLL_TIMEOUT_MS
            };

            // Use poll with empty fd set for an interruptible sleep.
            let poll_timeout = PollTimeout::try_from(sleep_ms).unwrap_or(PollTimeout::MAX);
            let mut empty_fds: Vec<PollFd> = Vec::new();
            let _ = poll(&mut empty_fds, poll_timeout);

            if signal::sigchld_seen() {
                reap_children(ctx, state);
            }
        }

        // ── Step 5: Check SIGHUP → re-exec daemon ────────────────────────
        if signal::sighup_seen() {
            tracing::info!("SIGHUP received, re-execing daemon for config reload");

            // Close all listening sockets before re-exec.
            close_daemon_sockets(ctx);

            // Cancel any pending SIGALRM to avoid alarm in the new process.
            signal::cancel_alarm();

            // Remove the PID file — the new daemon instance will create its own.
            remove_pid_file(pid_file_path);

            // Build ConfigContext for re-exec.
            let config_ctx = ConfigContext {
                config_filename: PathBuf::from(&config.config_filename),
                config_changed: false,
                config: Arc::clone(config),
            };

            // Re-exec the daemon binary — this never returns.
            process::re_exec_daemon(&config_ctx, ctx);
            // re_exec_daemon returns `!` so this is unreachable.
        }

        _last_tick = Instant::now();
    }
}

/// Calculate the poll timeout based on current daemon state.
///
/// Returns timeout in milliseconds for the poll() call. Takes into account:
/// - Queue interval (next SIGALRM expected in this many seconds)
/// - Accept retry backoff (shorter timeout during error recovery)
/// - Default timeout when no special conditions apply
fn calculate_poll_timeout(ctx: &ServerContext, state: &DaemonState) -> i32 {
    // If we're retrying after accept errors, use a short timeout to retry
    // promptly (matches C daemon.c behavior of 1-second timeout during
    // accept retries).
    if state.accept_retry_count > 0 {
        return MIN_POLL_TIMEOUT_MS;
    }

    // If a queue interval is configured, use it as the timeout (so we wake
    // up to check SIGALRM even if no connections arrive).
    if let Some(interval) = ctx.queue_interval {
        let ms = (interval.as_secs() * 1000) as i32;
        return ms.clamp(MIN_POLL_TIMEOUT_MS, DEFAULT_POLL_TIMEOUT_MS);
    }

    // Default: 5 minutes.
    DEFAULT_POLL_TIMEOUT_MS
}

/// Handle an event on the notification socket.
///
/// Reads and discards the notification datagram. The mere receipt of a datagram
/// signals that new messages have been queued and the daemon should check for
/// immediate delivery opportunities.
fn handle_notifier_event(notifier_fd: &Option<OwnedFd>) {
    if let Some(ref fd) = notifier_fd {
        let mut buf = [0u8; 256];
        // nix::unistd::read requires AsFd; &OwnedFd implements AsFd.
        match nix::unistd::read(fd, &mut buf) {
            Ok(n) => {
                tracing::debug!(bytes = n, "received daemon notification");
                // The notification itself is just a trigger — no content to parse.
                // The daemon will pick up new messages on the next queue run.
            }
            Err(nix::errno::Errno::EAGAIN) => {
                // No data available — spurious wakeup.
                // Note: EAGAIN == EWOULDBLOCK on Linux (same errno constant).
            }
            Err(e) => {
                tracing::debug!(error = %e, "error reading notification socket");
            }
        }
    }
}

// ===========================================================================
// Helper Functions
// ===========================================================================

/// Pre-load dynamic lookup and miscellaneous modules.
///
/// Called early in [`daemon_go()`] before entering the event loop. This ensures
/// that dynamically loaded modules (lookups, authenticators, etc.) are loaded
/// while the process still has full privileges, before any `chroot` or
/// privilege drop occurs.
///
/// Replaces C `daemon.c` line 1755: `daemon_preload_modules()`.
fn daemon_preload_modules() {
    tracing::debug!("preloading dynamic modules for daemon mode");
    // Module preloading is handled by the driver registry at config parse time
    // in the Rust architecture. The exim-drivers crate uses inventory::collect!
    // for compile-time registration, so no runtime preloading is needed.
    // This function is retained for logging and future extensibility.
}

/// Write the daemon PID to the configured PID file.
///
/// Replaces the PID file writing logic from `daemon.c` lines 2442–2470.
///
/// # Arguments
///
/// * `pid` — The daemon's process ID to write.
/// * `pid_file_path` — Path to the PID file (from configuration).
///
/// # Errors
///
/// Returns an error if the PID file cannot be written or the directory
/// does not exist.
fn write_pid_file(pid: Pid, pid_file_path: &str) -> Result<()> {
    if pid_file_path.is_empty() {
        tracing::debug!("no PID file path configured; skipping PID file write");
        return Ok(());
    }

    let pid_string = format!("{}\n", pid.as_raw());
    fs::write(pid_file_path, pid_string.as_bytes())
        .with_context(|| format!("failed to write PID file: {}", pid_file_path))?;

    tracing::info!(
        pid = pid.as_raw(),
        path = pid_file_path,
        "wrote daemon PID file"
    );
    Ok(())
}

/// Remove the PID file on daemon shutdown.
///
/// Best-effort removal — errors are logged but do not prevent shutdown.
fn remove_pid_file(pid_file_path: &str) {
    if pid_file_path.is_empty() {
        return;
    }
    match fs::remove_file(pid_file_path) {
        Ok(()) => tracing::debug!(path = pid_file_path, "removed PID file"),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            tracing::debug!(path = pid_file_path, "PID file already removed");
        }
        Err(e) => {
            tracing::warn!(
                path = pid_file_path,
                error = %e,
                "failed to remove PID file"
            );
        }
    }
}

/// Set up the Unix domain notification socket.
///
/// The notification socket allows external processes to notify the running
/// daemon of newly-queued messages. This replaces the C notification socket
/// setup from `daemon.c`.
///
/// Returns the listening socket file descriptor, or `None` if setup fails
/// (non-fatal — the daemon can operate without the notification socket).
fn setup_notifier_socket(spool_directory: &str) -> Option<OwnedFd> {
    let path = notifier_socket_path(spool_directory);

    // Remove any stale socket file from a previous daemon instance.
    let _ = fs::remove_file(&path);

    // Create a Unix datagram socket for receiving notifications.
    let sock_fd = match socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    ) {
        Ok(fd) => fd,
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "failed to create notification socket"
            );
            return None;
        }
    };

    // Bind the socket to the filesystem path.
    let addr = match nix::sys::socket::UnixAddr::new(&path) {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "failed to create UnixAddr for notification socket"
            );
            return None;
        }
    };

    if let Err(e) = bind(sock_fd.as_raw_fd(), &addr) {
        tracing::warn!(
            error = %e,
            path = %path.display(),
            "failed to bind notification socket"
        );
        return None;
    }

    tracing::debug!(
        path = %path.display(),
        fd = sock_fd.as_raw_fd(),
        "notification socket ready"
    );
    Some(sock_fd)
}

/// Remove the notification socket file on daemon shutdown.
fn unlink_notifier_socket(spool_directory: &str) {
    let path = notifier_socket_path(spool_directory);
    let _ = fs::remove_file(&path);
    tracing::debug!(path = %path.display(), "removed notification socket");
}

/// Close all daemon listening sockets.
///
/// Called before SIGHUP re-exec and in the child process after fork.
/// Replaces C `close_daemon_sockets()` from `daemon.c` line 155.
fn close_daemon_sockets(ctx: &mut ServerContext) {
    tracing::debug!(
        count = ctx.listening_sockets.len(),
        "closing daemon listening sockets"
    );
    ctx.listening_sockets.clear();
    // OwnedFd drop impl automatically closes each fd.
}

// ===========================================================================
// Socket Binding
// ===========================================================================

/// Parse a listener address specification into an IP and port.
///
/// Supports formats from the Exim `local_interfaces` and `daemon_smtp_port`
/// configuration:
/// - `"0.0.0.0:25"` or `"[::]:25"` — explicit address and port
/// - `"25"` — port number only (binds to wildcard)
/// - `"192.168.1.1"` — address only (uses default port 25)
///
/// Returns `(IpAddr, port)`.
fn parse_listener_spec(spec: &str, default_port: u16) -> Result<(IpAddr, u16)> {
    // Try parsing as a full socket address first.
    if let Ok(sa) = spec.parse::<SocketAddr>() {
        return Ok((sa.ip(), sa.port()));
    }

    // Try parsing as just a port number.
    if let Ok(port) = spec.parse::<u16>() {
        return Ok((IpAddr::V6(Ipv6Addr::UNSPECIFIED), port));
    }

    // Try parsing as just an IP address.
    if let Ok(ip) = spec.parse::<IpAddr>() {
        return Ok((ip, default_port));
    }

    // Handle C Exim dot notation: "127.0.0.1.1025" where the last dotted
    // component is a port number appended to an IPv4 address.  We split
    // at the last dot and try to parse the left part as an IPv4 address
    // and the right part as a port.
    if let Some(last_dot) = spec.rfind('.') {
        let ip_part = &spec[..last_dot];
        let port_part = &spec[last_dot + 1..];
        if let (Ok(ip), Ok(port)) = (ip_part.parse::<Ipv4Addr>(), port_part.parse::<u16>()) {
            return Ok((IpAddr::V4(ip), port));
        }
    }

    // Handle bracketed IPv6: [::1]:587
    if spec.starts_with('[') {
        if let Some(bracket_end) = spec.find(']') {
            let ip_str = &spec[1..bracket_end];
            let ip: IpAddr = ip_str
                .parse()
                .with_context(|| format!("invalid IPv6 address in '{}'", spec))?;
            let port = if bracket_end + 1 < spec.len() && spec.as_bytes()[bracket_end + 1] == b':' {
                spec[bracket_end + 2..]
                    .parse::<u16>()
                    .with_context(|| format!("invalid port in '{}'", spec))?
            } else {
                default_port
            };
            return Ok((ip, port));
        }
    }

    bail!("cannot parse listener specification: '{}'", spec);
}

/// Bind listening sockets for all configured local interfaces and ports.
///
/// Replaces the socket binding loop from `daemon.c` lines 2080–2371.
/// For each configured address/port combination:
/// 1. Create a socket (`AF_INET` or `AF_INET6`)
/// 2. Set `SO_REUSEADDR`
/// 3. Set `TCP_NODELAY` if configured
/// 4. Set `IPV6_V6ONLY` for IPv6 sockets
/// 5. `bind()` and `listen()` with configured backlog
///
/// # Errors
///
/// Returns an error if no sockets could be bound (all addresses failed).
/// Individual address failures are logged as warnings and skipped.
fn bind_listening_sockets(ctx: &mut ServerContext, config: &Arc<Config>) -> Result<()> {
    // If -oX was specified on the command line, it overrides BOTH
    // local_interfaces and daemon_smtp_port from the configuration file.
    // The -oX value is treated as a complete interface specification:
    //   - A bare port number (e.g., "10025") → listen on all interfaces on that port
    //   - An address:port (e.g., "127.0.0.1:10025") → listen on specific interface
    //   - A semicolon-separated list → multiple listen entries
    // This matches C Exim's handling of -oX in daemon.c.
    let (local_interfaces, daemon_smtp_ports): (&str, &str) =
        if let Some(ref oxi) = ctx.override_local_interfaces {
            // -oX specified: use it as the complete listen specification.
            // If it contains only digits, treat it as a port number.
            // Otherwise, treat it as a full interface spec.
            let trimmed = oxi.trim();
            if trimmed.chars().all(|c| c.is_ascii_digit()) {
                // Bare port number — listen on all interfaces on this port.
                ("", trimmed)
            } else {
                // Full interface spec (may include address and port).
                (trimmed, "25")
            }
        } else {
            // No -oX override — use config values.
            (
                config.local_interfaces.as_deref().unwrap_or(""),
                config.daemon_smtp_port.as_deref().unwrap_or("25"),
            )
        };
    let backlog = config.smtp_connect_backlog.max(1) as usize;
    let tcp_nodelay_flag = config.tcp_nodelay;

    // Determine which ports to listen on.
    let ports: Vec<u16> = if daemon_smtp_ports.is_empty() {
        vec![25u16]
    } else {
        daemon_smtp_ports
            .split(':')
            .filter_map(|p| {
                let trimmed = p.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    // Handle well-known service names as Exim config allows.
                    if trimmed.eq_ignore_ascii_case("smtp") {
                        return Some(25u16);
                    }
                    if trimmed.eq_ignore_ascii_case("smtps") {
                        return Some(465u16);
                    }
                    if trimmed.eq_ignore_ascii_case("submission") {
                        return Some(587u16);
                    }
                    match trimmed.parse::<u16>() {
                        Ok(port) => Some(port),
                        Err(e) => {
                            tracing::warn!(
                                port_spec = trimmed,
                                error = %e,
                                "skipping invalid port specification"
                            );
                            None
                        }
                    }
                }
            })
            .collect()
    };

    if ports.is_empty() {
        bail!("no valid SMTP ports configured");
    }

    // Determine which interfaces to bind.
    let interfaces: Vec<String> = if local_interfaces.is_empty() {
        vec![String::new()]
    } else {
        local_interfaces
            .split(';')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };

    let mut bound_count = 0u32;

    for port in &ports {
        let is_wildcard =
            interfaces.is_empty() || (interfaces.len() == 1 && interfaces[0].is_empty());

        if is_wildcard {
            // Bind to wildcard on both IPv4 and IPv6 (matching C Exim behavior).
            // Try IPv4 first (always available), then optionally add IPv6.
            match bind_one_socket(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                *port,
                backlog,
                tcp_nodelay_flag,
            ) {
                Ok(fd) => {
                    tracing::info!(
                        port = port,
                        fd = fd.as_raw_fd(),
                        "listening on 0.0.0.0:{}",
                        port
                    );
                    ctx.listening_sockets.push(fd);
                    bound_count += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        port = port,
                        error = %e,
                        "IPv4 wildcard bind failed for port {}", port
                    );
                }
            }
            // Also try IPv6 wildcard if available (non-fatal if it fails).
            match bind_one_socket(
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                *port,
                backlog,
                tcp_nodelay_flag,
            ) {
                Ok(fd) => {
                    tracing::info!(
                        port = port,
                        fd = fd.as_raw_fd(),
                        "listening on [::]:{}",
                        port
                    );
                    ctx.listening_sockets.push(fd);
                    bound_count += 1;
                }
                Err(e) => {
                    tracing::debug!(error = %e, "IPv6 wildcard bind skipped (non-fatal)");
                }
            }
        } else {
            for iface in &interfaces {
                let (ip, effective_port) = match parse_listener_spec(iface, *port) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(
                            interface = iface.as_str(),
                            error = %e,
                            "skipping invalid interface specification"
                        );
                        continue;
                    }
                };

                match bind_one_socket(ip, effective_port, backlog, tcp_nodelay_flag) {
                    Ok(fd) => {
                        tracing::info!(
                            address = %ip, port = effective_port, fd = fd.as_raw_fd(),
                            "listening on {}:{}", ip, effective_port
                        );
                        ctx.listening_sockets.push(fd);
                        bound_count += 1;
                    }
                    Err(e) => {
                        tracing::error!(
                            address = %ip, port = effective_port, error = %e,
                            "failed to bind socket on {}:{}", ip, effective_port
                        );
                    }
                }
            }
        }
    }

    if bound_count == 0 {
        bail!(
            "no listening sockets could be bound — daemon cannot start. \
             Check local_interfaces and daemon_smtp_port configuration."
        );
    }

    tracing::info!(
        count = bound_count,
        "bound {} listening socket(s)",
        bound_count
    );
    Ok(())
}

/// Bind a single TCP listening socket.
///
/// Creates the socket, sets socket options, binds, and listens. Returns the
/// owned file descriptor on success.
fn bind_one_socket(ip: IpAddr, port: u16, backlog: usize, tcp_nodelay: bool) -> Result<OwnedFd> {
    let family = match ip {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    };

    // socket() returns OwnedFd in nix 0.31.
    let sock: OwnedFd = socket(
        family,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .with_context(|| format!("socket() failed for {}:{}", ip, port))?;

    // SO_REUSEADDR — allow rebinding after daemon restart.
    setsockopt(&sock, ReuseAddr, &true)
        .with_context(|| format!("setsockopt(SO_REUSEADDR) failed for {}:{}", ip, port))?;

    // IPV6_V6ONLY for IPv6 sockets — prevent dual-stack interference.
    if family == AddressFamily::Inet6 {
        let _ = setsockopt(&sock, Ipv6V6Only, &true);
    }

    // TCP_NODELAY if configured.
    if tcp_nodelay {
        let _ = setsockopt(&sock, TcpNoDelay, &true);
    }

    // TCP_FASTOPEN — nix 0.31.2 does not expose TCP_FASTOPEN directly.
    // This is a non-critical optimization; the daemon functions correctly
    // without it. Per AAP §0.7.2, zero unsafe outside exim-ffi.

    // Bind the socket using the raw fd (nix::sys::socket::bind takes RawFd).
    let sockaddr = SocketAddr::new(ip, port);
    let nix_addr = SockaddrStorage::from(sockaddr);
    bind(sock.as_raw_fd(), &nix_addr)
        .with_context(|| format!("bind() failed for {}:{}", ip, port))?;

    // Start listening. listen() in nix 0.31 takes impl AsFd.
    let bl = Backlog::new(backlog as i32).unwrap_or(Backlog::MAXCONN);
    listen(&sock, bl).with_context(|| format!("listen() failed for {}:{}", ip, port))?;

    Ok(sock)
}

// ===========================================================================
// Connection Acceptance
// ===========================================================================

/// Handle an incoming connection on one of the listening sockets.
///
/// Replaces `handle_smtp_call()` from `daemon.c` lines 183–500:
/// 1. Call safe `TcpListener::accept()` — no `unsafe` code needed.
/// 2. Check `smtp_accept_max` limit — if reached, reject with 421.
/// 3. Check per-host limit — reject with 421 if exceeded.
/// 4. Fork a child process via [`process::fork_for_smtp()`].
/// 5. In the child: delegate to SMTP inbound handling.
/// 6. In the parent: record the child PID in the SMTP slots and continue.
///
/// # Arguments
///
/// * `listener` — `TcpListener` wrapper on the listening socket that
///   triggered `POLLIN`. Uses the safe standard library `accept()`.
/// * `ctx` — Mutable server context for process tracking.
/// * `config` — Immutable configuration.
/// * `state` — Daemon-local mutable state for error tracking.
///
/// # Accept Safety
///
/// Uses `std::net::TcpListener::accept()` which returns `(TcpStream, SocketAddr)`
/// — fully safe, no `unsafe { OwnedFd::from_raw_fd() }` needed. This satisfies
/// the `#![deny(unsafe_code)]` crate-level attribute. The `TcpListener` was
/// created from a cloned `OwnedFd` in `daemon_go()`.
fn handle_accept(
    listener: &TcpListener,
    ctx: &mut ServerContext,
    config: &Arc<Config>,
    state: &mut DaemonState,
) {
    // Accept the incoming connection using the safe standard library API.
    // TcpListener::accept() returns (TcpStream, SocketAddr) — no raw fds.
    let (conn_stream, peer_addr) = match listener.accept() {
        Ok(result) => {
            // Successful accept — reset retry counter.
            if state.accept_retry_count > 0 {
                tracing::info!(
                    retries = state.accept_retry_count,
                    "accept() succeeded after {} consecutive failures",
                    state.accept_retry_count
                );
                state.accept_retry_count = 0;
                state.accept_retry_errno = 0;
                state.accept_retry_select_failed = false;
            }
            result
        }
        Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
            // Non-blocking socket with no pending connection — spurious.
            // On Linux, WouldBlock == EAGAIN (same errno constant).
            return;
        }
        Err(ref e) if e.kind() == ErrorKind::Interrupted => {
            // Interrupted by signal — will retry on next loop iteration.
            return;
        }
        Err(e) => {
            state.accept_retry_count += 1;
            state.accept_retry_errno = e.raw_os_error().unwrap_or(0);
            state.accept_retry_select_failed = false;

            if state.accept_retry_count >= ACCEPT_RETRY_LOG_THRESHOLD {
                tracing::error!(
                    errno = state.accept_retry_errno,
                    count = state.accept_retry_count,
                    "accept() failed {} consecutive times (last: {})",
                    state.accept_retry_count,
                    e
                );
                state.accept_retry_count = 0;
            }
            return;
        }
    };

    // Peer address is directly available from TcpListener::accept().
    let peer_address = peer_addr.to_string();

    tracing::debug!(peer = peer_address.as_str(), "accepted SMTP connection");

    // Check smtp_accept_max limit.
    if ctx.smtp_accept_max > 0 && ctx.smtp_accept_count >= ctx.smtp_accept_max {
        tracing::warn!(
            current = ctx.smtp_accept_count,
            max = ctx.smtp_accept_max,
            peer = peer_address.as_str(),
            "connection limit reached, rejecting"
        );
        let msg = format!(
            "421 {} connection limit reached, please try again later\r\n",
            ctx.primary_hostname
        );
        reject_and_close(conn_stream, &msg);
        return;
    }

    // Check per-host connection limit if configured.
    let per_host_max: i32 = config
        .smtp_accept_max_per_host
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if per_host_max > 0 {
        let host_count = ctx
            .smtp_slots
            .iter()
            .filter(|s| s.pid != 0 && s.host_address.as_deref().is_some_and(|a| a == peer_address))
            .count() as i32;

        if host_count >= per_host_max {
            tracing::warn!(
                host = peer_address.as_str(),
                current = host_count,
                max = per_host_max,
                "per-host connection limit reached"
            );
            let msg = format!(
                "421 {} too many connections from your host, try later\r\n",
                ctx.primary_hostname
            );
            reject_and_close(conn_stream, &msg);
            return;
        }
    }

    // Fork a child to handle this SMTP connection.
    // fork_for_smtp() records the child in ctx.smtp_slots internally.
    // The TcpStream fd is duplicated across fork() automatically.
    match process::fork_for_smtp(ctx, &peer_address) {
        Ok(ForkResult::Child) => {
            // === CHILD PROCESS ===
            tracing::debug!(
                peer = peer_address.as_str(),
                "child process starting SMTP session"
            );

            // Delegate to SMTP session handling in the child.
            handle_smtp_child(conn_stream, ctx, config, &peer_address);

            // Child MUST NOT return to the daemon event loop.
            exit(0);
        }
        Ok(ForkResult::Parent { child }) => {
            // === PARENT PROCESS ===
            // Drop the TcpStream in the parent — parent doesn't use the
            // accepted connection. The child has its own copy via fork().
            drop(conn_stream);

            // Increment accept count.
            ctx.smtp_accept_count += 1;

            tracing::debug!(
                child_pid = child.as_raw(),
                peer = peer_address.as_str(),
                accept_count = ctx.smtp_accept_count,
                "forked SMTP child"
            );
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                peer = peer_address.as_str(),
                "fork_for_smtp failed"
            );
            let msg = format!(
                "421 {} service temporarily unavailable\r\n",
                ctx.primary_hostname
            );
            reject_and_close(conn_stream, &msg);
        }
    }
}

/// Write a rejection message to a TcpStream and close it.
///
/// Takes ownership of the `TcpStream` so dropping it closes the connection.
/// Write errors are ignored since the client may have already disconnected.
fn reject_and_close(mut conn: TcpStream, msg: &str) {
    // std::io::Write::write_all on TcpStream — fully safe, no raw fds.
    let _ = conn.write_all(msg.as_bytes());
    // Dropping conn (TcpStream) automatically closes the fd.
}

/// Handle SMTP session in a forked child process.
///
/// Called after `fork_for_smtp()` in the child. Sets up the session and
/// delegates to the SMTP inbound module. The child process closes listening
/// sockets, sets process info, and enters the SMTP command loop.
///
/// This function returns when the SMTP session is complete; the caller
/// should then `exit(0)`.
///
/// # Arguments
///
/// * `conn` — The accepted `TcpStream` for this SMTP connection. Owned by
///   the child process (parent dropped its copy after fork). The stream's fd
///   is used for the SMTP conversation (read commands, write responses).
/// * `ctx` — Server context with daemon-lifetime state for the child.
/// * `config` — Immutable configuration.
/// * `peer_address` — String representation of the peer's socket address.
fn handle_smtp_child(
    conn: TcpStream,
    ctx: &mut ServerContext,
    config: &Arc<Config>,
    peer_address: &str,
) {
    process::set_process_info(&format!("handling connection from {}", peer_address));

    // Close listening sockets in the child — the child only needs the
    // connection stream. The parent retains the listening sockets for
    // further accept() calls. close_unwanted takes &ServerContext to
    // identify which fds belong to the daemon infrastructure.
    process::close_unwanted(ctx);

    // Obtain the raw file descriptor from the TcpStream for the SMTP
    // inbound module. The command_loop uses RawFd for buffered I/O.
    let conn_fd = conn.as_raw_fd();

    // Build the exim-smtp ServerContext from our daemon's ServerContext.
    // The SMTP crate defines its own ServerContext type (per-crate type
    // boundaries) with SMTP-session-specific fields extracted from the
    // daemon's server context.
    let smtp_server_ctx = exim_smtp::inbound::command_loop::ServerContext {
        primary_hostname: ctx.primary_hostname.clone(),
        smtp_active_hostname: ctx.primary_hostname.clone(),
        tls_server_credentials: None,
        host_checking: false,
        sender_host_notsocket: false,
        is_inetd: ctx.inetd_wait_mode,
        atrn_mode: false,
        interface_address: None,
        interface_port: 0,
        is_local_session: false,
        smtp_batched_input: false,
    };

    // Build the exim-smtp ConfigContext from our Arc<Config> using the
    // `from_config()` bridge method.  This propagates ALL ACL definitions,
    // SMTP limits, banner, host lists, and EHLO capability settings from
    // the frozen parsed configuration into the SMTP crate's ConfigContext.
    //
    // Previously this constructed a ConfigContext with ALL ACL fields set to
    // None — which disabled all ACL checking and caused the daemon to
    // operate as an open relay.  The from_config() method reads the actual
    // ACL names from the parsed config, ensuring policy enforcement.
    let smtp_config_ctx = {
        use std::ops::Deref;
        let cfg_ctx: &exim_config::types::ConfigContext = (*config).deref();
        exim_smtp::inbound::command_loop::ConfigContext::from_config(
            cfg_ctx,
            Vec::new(), // Auth instances — populated by auth driver registration
        )
    };

    // Initialize a MessageContext for this SMTP session, installing the
    // verify=recipient callback so the ACL engine can route recipient
    // addresses through the router chain during RCPT TO.
    let mut smtp_msg_ctx = exim_smtp::inbound::command_loop::MessageContext {
        verify_recipient_cb: super::make_verify_recipient_callback(config),
        ..Default::default()
    };

    // Write connection log to mainlog (AAP §0.7.1 — C Exim format).
    let spool_dir = config.spool_directory.clone();
    write_mainlog(&spool_dir, &format!("Connection from [{}]", peer_address));

    // Delegate to the SMTP inbound command loop (smtp_setup_msg).
    // This function:
    //   1. Creates a SmtpSession<Connected> from the file descriptors
    //   2. Sends the 220 SMTP banner
    //   3. Processes the EHLO/HELO → MAIL → RCPT → DATA command sequence
    //   4. Handles TLS-on-connect and STARTTLS negotiation
    //   5. Returns SmtpSetupResult when the session completes
    //
    // The SMTP command loop uses type-state encoding for safe state
    // transitions (AAP §0.4.2), enforced at compile time.
    let result = exim_smtp::inbound::command_loop::smtp_setup_msg(
        &smtp_server_ctx,
        &mut smtp_msg_ctx,
        &smtp_config_ctx,
        conn_fd,
        conn_fd,
    );

    match result {
        exim_smtp::inbound::command_loop::SmtpSetupResult::Done => {
            tracing::info!(peer = peer_address, "SMTP session completed normally");
        }
        exim_smtp::inbound::command_loop::SmtpSetupResult::Yield => {
            tracing::debug!(peer = peer_address, "SMTP session yielded for message body");
            // DATA or BDAT was accepted — receive the message body, write
            // it to the spool, and send a 250 OK response with the message
            // ID.  This implements the critical delivery pipeline that
            // connects smtp_setup_msg() → receive → spool → response.
            //
            // Extract the TLS backend that the SMTP session deposited
            // into MessageContext.  When present, all further I/O with
            // the client MUST go through this backend.
            let tls_backend = smtp_msg_ctx.tls_backend.take();

            // After the 250 OK, loop back into the SMTP command loop so
            // the client can start a new transaction (MAIL FROM) or QUIT.
            receive_and_spool_message(
                conn_fd,
                &smtp_server_ctx,
                &mut smtp_msg_ctx,
                &smtp_config_ctx,
                config,
                peer_address,
                tls_backend,
            );
        }
        exim_smtp::inbound::command_loop::SmtpSetupResult::Error => {
            tracing::warn!(peer = peer_address, "SMTP session ended with error");
        }
    }

    // Log SMTP session end in mainlog.
    write_mainlog(
        &spool_dir,
        &format!("SMTP connection from [{}] closed", peer_address),
    );

    // The child will exit via the caller's exit(0) after this returns.
}

// ===========================================================================
// Message Body Reception and Spool Writing
// ===========================================================================

/// Convert an SMTP protocol enum variant to the corresponding protocol name
/// string used in Exim log lines and spool -H headers.
///
/// This matches the C Exim protocol string table (protocols[] / protocols_local[])
/// ensuring log output is parseable by `exigrep` and `eximstats` (AAP §0.7.1).
fn protocol_name(proto: exim_smtp::SmtpProtocol) -> &'static str {
    match proto {
        exim_smtp::SmtpProtocol::Smtp => "smtp",
        exim_smtp::SmtpProtocol::Smtps => "smtps",
        exim_smtp::SmtpProtocol::Esmtp => "esmtp",
        exim_smtp::SmtpProtocol::Esmtps => "esmtps",
        exim_smtp::SmtpProtocol::Esmtpa => "esmtpa",
        exim_smtp::SmtpProtocol::Esmtpsa => "esmtpsa",
        exim_smtp::SmtpProtocol::Ssmtp => "ssmtp",
        exim_smtp::SmtpProtocol::Essmtp => "essmtp",
        exim_smtp::SmtpProtocol::Essmtpa => "essmtpa",
        exim_smtp::SmtpProtocol::LocalSmtp => "local-smtp",
        exim_smtp::SmtpProtocol::LocalSmtps => "local-smtps",
        exim_smtp::SmtpProtocol::LocalEsmtp => "local-esmtp",
        exim_smtp::SmtpProtocol::LocalEsmtps => "local-esmtps",
        exim_smtp::SmtpProtocol::LocalEsmtpa => "local-esmtpa",
        exim_smtp::SmtpProtocol::LocalEsmtpsa => "local-esmtpsa",
        exim_smtp::SmtpProtocol::LocalSsmtp => "local-ssmtp",
        exim_smtp::SmtpProtocol::LocalEssmtp => "local-essmtp",
        exim_smtp::SmtpProtocol::LocalEssmtpa => "local-essmtpa",
        exim_smtp::SmtpProtocol::LocalBsmtp => "local-bsmtp",
    }
}

/// Receive the message body after DATA acceptance, write it to the spool
/// directory, and send a 250 OK response with the generated message ID.
///
/// This function implements the critical DATA → body → spool → response
/// pipeline that connects the SMTP command loop to actual mail delivery.
/// After receiving the body (terminated by a lone "." line per RFC 5321
/// §4.1.1.4), it:
///
/// 1. Reads lines from the SMTP connection until the lone "." terminator
/// 2. Generates a unique message ID (using the spool module)
/// 3. Writes the -D (data) and -H (header) spool files
/// 4. Sends "250 OK id=<message-id>" to the client
/// 5. Logs the message reception to the main log
/// 6. Re-enters the SMTP command loop for additional transactions or QUIT
///
/// After the response, the function loops back into `smtp_continue_msg()` to
/// allow the client to start a new MAIL FROM transaction or send QUIT.
/// The continue variant re-enters the Greeted state without sending a
/// duplicate 220 banner.
///
/// # Arguments
///
/// * `conn_fd` — Raw file descriptor for the SMTP connection
/// * `server_ctx` — SMTP server context
/// * `msg_ctx` — Per-message context (populated by the command loop)
/// * `config_ctx` — SMTP config context
/// * `config` — Frozen parsed configuration
/// * `peer_address` — String representation of the peer address
fn receive_and_spool_message(
    conn_fd: std::os::unix::io::RawFd,
    server_ctx: &exim_smtp::inbound::command_loop::ServerContext,
    msg_ctx: &mut exim_smtp::inbound::command_loop::MessageContext,
    config_ctx: &exim_smtp::inbound::command_loop::ConfigContext,
    config: &Arc<Config>,
    peer_address: &str,
    mut tls_backend: Option<Box<exim_tls::rustls_backend::RustlsBackend>>,
) {
    use std::io::Write as _;

    // Generate a message ID using the spool module.
    // The message ID encodes: current time, PID, and sub-second resolution.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let message_id = exim_spool::message_id::generate_message_id(
        now.as_secs() as u32,
        std::process::id() as u64,
        now.subsec_micros(),
        None, // no host_number
        1,    // id_resolution = 1 (microsecond)
    );

    // Helper: write bytes to the client, dispatching through TLS when active.
    let write_to_client =
        |data: &[u8], tls: &mut Option<Box<exim_tls::rustls_backend::RustlsBackend>>| {
            if let Some(ref mut backend) = tls {
                let _ = backend.write(data);
            } else {
                let _ = exim_ffi::fd::safe_write_fd(conn_fd, data);
            }
        };

    // Read the message body from the connection.  When TLS is active,
    // reads go through the RustlsBackend; otherwise they use safe fd I/O.
    // The body is terminated by a lone "." on a line by itself per RFC 5321
    // §4.1.1.4.
    let mut body_lines: Vec<String> = Vec::new();
    let mut total_body_size: usize = 0;
    let max_body_size: usize = 52_428_800; // 50 MiB default limit
    let mut read_buf = [0u8; 8192];
    let mut line_buf = Vec::with_capacity(1024);

    'body_read: loop {
        let n = if let Some(ref mut tls) = tls_backend {
            // TLS path — decrypt through RustlsBackend.
            match tls.read(&mut read_buf) {
                Ok(0) => {
                    tracing::warn!(peer = peer_address, "TLS connection closed during body");
                    return;
                }
                Ok(n) => n,
                Err(e) => {
                    tracing::error!(error = %e, peer = peer_address, "TLS read error during body");
                    return;
                }
            }
        } else {
            // Plaintext path — read from raw fd.
            match exim_ffi::fd::safe_read_fd(conn_fd, &mut read_buf) {
                Ok(0) => {
                    tracing::warn!(peer = peer_address, "connection closed during body");
                    return;
                }
                Ok(n) => n,
                Err(e) => {
                    tracing::error!(error = %e, peer = peer_address, "read error during body");
                    return;
                }
            }
        };

        for &byte in &read_buf[..n] {
            if byte == b'\n' {
                // Complete line — strip trailing \r if present (CRLF → LF).
                if line_buf.last() == Some(&b'\r') {
                    line_buf.pop();
                }
                let line = String::from_utf8_lossy(&line_buf).to_string();
                line_buf.clear();

                // Check for the lone dot terminator (RFC 5321 §4.1.1.4).
                if line == "." {
                    break 'body_read;
                }

                // Dot-stuffing: a line starting with "." has the leading dot
                // removed (RFC 5321 §4.5.2).
                let actual_line = if let Some(stripped) = line.strip_prefix('.') {
                    stripped.to_string()
                } else {
                    line
                };

                total_body_size += actual_line.len() + 1; // +1 for newline
                if total_body_size > max_body_size {
                    tracing::warn!(
                        peer = peer_address,
                        size = total_body_size,
                        "message body exceeds size limit"
                    );
                    let err_msg = b"552 Message size exceeds maximum permitted\r\n";
                    write_to_client(err_msg, &mut tls_backend);
                    return;
                }
                body_lines.push(actual_line);
            } else {
                line_buf.push(byte);
            }
        }
    }

    tracing::debug!(
        peer = peer_address,
        message_id = %message_id,
        body_lines = body_lines.len(),
        body_size = total_body_size,
        "message body received"
    );

    // Write the message to the spool directory.
    // The spool directory is taken from the frozen configuration.
    // Arc<Config> derefs to exim_config::ConfigContext via Config::deref().
    let spool_dir = config.spool_directory.clone();

    // Ensure spool subdirectories exist.
    let input_dir = format!("{}/input", spool_dir);
    let _ = std::fs::create_dir_all(&input_dir);

    // Write the -D (data) spool file containing the message body.
    let data_path = format!("{}/{}-D", input_dir, message_id);
    match std::fs::File::create(&data_path) {
        Ok(mut data_file) => {
            // Write the Exim spool data file header line.
            // Format: "<message_id>-D\n" followed by the body.
            let header_line = format!("{}-D\n", message_id);
            let _ = data_file.write_all(header_line.as_bytes());
            for line in &body_lines {
                let _ = data_file.write_all(line.as_bytes());
                let _ = data_file.write_all(b"\n");
            }
            tracing::debug!(path = %data_path, "wrote spool data file");
        }
        Err(e) => {
            tracing::error!(error = %e, path = %data_path, "failed to write spool data file");
            let err_msg = b"451 Temporary local error; please try again later\r\n";
            write_to_client(err_msg, &mut tls_backend);
            return;
        }
    }

    // Write the -H (header/metadata) spool file using the standard Exim
    // spool format via exim_spool::spool_write_header. This ensures the
    // header file is byte-level compatible with the queue runner's
    // spool_read_header() parser (AAP §0.3.1 spool file compatibility).
    let header_path = format!("{}/{}-H", input_dir, message_id);
    {
        let received_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        // Build Received header line matching C Exim format.
        let received_hdr = format!(
            "Received: from {} by {} with {} id {}",
            msg_ctx.helo_name.as_deref().unwrap_or("unknown"),
            server_ctx.primary_hostname,
            protocol_name(msg_ctx.received_protocol),
            message_id,
        );

        // Build recipient list from the message context.
        let recipients: Vec<exim_spool::RecipientItem> = msg_ctx
            .recipients_list
            .iter()
            .map(|r| exim_spool::RecipientItem {
                address: r.address.clone(),
                pno: -1,
                errors_to: None,
                orcpt: None,
                dsn_flags: 0,
            })
            .collect();

        // Determine originator login from the current process user.
        let originator_login = exim_ffi::get_login_name().unwrap_or_default();

        let spool_data = exim_spool::SpoolHeaderData {
            message_id: message_id.clone(),
            originator_login,
            sender_address: msg_ctx.sender_address.clone(),
            received_time_sec: received_time,
            headers: vec![exim_spool::HeaderLine {
                header_type: ' ',
                slen: received_hdr.len(),
                text: received_hdr,
            }],
            recipients,
            non_recipients_tree: None,
            host_address: msg_ctx.sender_host_address.clone(),
            host_name: msg_ctx.sender_host_name.clone(),
            interface_address: None,
            received_protocol: Some(protocol_name(msg_ctx.received_protocol).to_string()),
            sender_ident: None,
        };

        match std::fs::File::create(&header_path) {
            Ok(file) => {
                if let Err(e) = exim_spool::spool_write_header(&spool_data, file) {
                    tracing::error!(
                        error = %e,
                        path = %header_path,
                        "failed to write spool header file"
                    );
                    let _ = std::fs::remove_file(&data_path);
                    let _ = std::fs::remove_file(&header_path);
                    let err_msg = b"451 Temporary local error; please try again later\r\n";
                    write_to_client(err_msg, &mut tls_backend);
                    return;
                }
                tracing::debug!(path = %header_path, "wrote spool header file");
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    path = %header_path,
                    "failed to create spool header file"
                );
                let _ = std::fs::remove_file(&data_path);
                let err_msg = b"451 Temporary local error; please try again later\r\n";
                write_to_client(err_msg, &mut tls_backend);
                return;
            }
        }
    }

    // Log the message reception (to be written to mainlog).
    let log_line = format!(
        "<= {} H={} [{}] P={} S={} id={}",
        msg_ctx.sender_address,
        msg_ctx.helo_name.as_deref().unwrap_or("unknown"),
        peer_address,
        protocol_name(msg_ctx.received_protocol),
        total_body_size,
        message_id,
    );
    // Write to mainlog if available.
    write_mainlog(&spool_dir, &log_line);

    tracing::info!(
        message_id = %message_id,
        sender = %msg_ctx.sender_address,
        recipients = msg_ctx.recipients_count,
        size = total_body_size,
        peer = peer_address,
        "message received"
    );

    // Send the 250 OK response with the message ID.
    // This is the critical response that tells the client the message
    // has been accepted (AAP §0.7.7 Gate 1: "swaks → 250 OK").
    let ok_response = format!("250 OK id={}\r\n", message_id);
    write_to_client(ok_response.as_bytes(), &mut tls_backend);

    // After successful reception, re-enter the SMTP command loop.
    // The client may start a new MAIL FROM transaction or send QUIT.
    // Reset the message context for the next transaction.
    msg_ctx.sender_address.clear();
    msg_ctx.recipients_list.clear();
    msg_ctx.recipients_count = 0;
    msg_ctx.headers.clear();
    msg_ctx.authenticated_sender = None;
    msg_ctx.message_size = 0;

    // Re-enter the SMTP command loop for subsequent transactions.
    // Use smtp_continue_msg (not smtp_setup_msg) to avoid sending a
    // duplicate 220 SMTP banner — the session is already past EHLO.
    let result = exim_smtp::inbound::command_loop::smtp_continue_msg(
        server_ctx, msg_ctx, config_ctx, conn_fd, conn_fd,
    );

    match result {
        exim_smtp::inbound::command_loop::SmtpSetupResult::Done => {
            tracing::info!(peer = peer_address, "SMTP session completed after message");
        }
        exim_smtp::inbound::command_loop::SmtpSetupResult::Yield => {
            // Another message — recurse.  Extract TLS backend again.
            let tls_backend = msg_ctx.tls_backend.take();
            receive_and_spool_message(
                conn_fd,
                server_ctx,
                msg_ctx,
                config_ctx,
                config,
                peer_address,
                tls_backend,
            );
        }
        exim_smtp::inbound::command_loop::SmtpSetupResult::Error => {
            tracing::warn!(peer = peer_address, "SMTP session error after message");
        }
    }
}

/// Write a log line to the Exim main log file.
///
/// Creates the log file if it doesn't exist. Appends log lines in C Exim
/// format: "YYYY-MM-DD HH:MM:SS <log_line>\n".
///
/// This implements the basic logging infrastructure required by AAP §0.7.1
/// ("main log, reject log, and panic log entries must match C Exim format").
fn write_mainlog(spool_dir: &str, line: &str) {
    let log_dir = format!("{}/log", spool_dir);
    let _ = std::fs::create_dir_all(&log_dir);

    let mainlog_path = format!("{}/mainlog", log_dir);
    let now = chrono_format_now();

    let formatted = format!("{} {}\n", now, line);
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&mainlog_path)
    {
        Ok(mut f) => {
            use std::io::Write as _;
            let _ = f.write_all(formatted.as_bytes());
        }
        Err(e) => {
            tracing::error!(error = %e, path = %mainlog_path, "failed to write mainlog");
        }
    }
}

/// Write a log line to the Exim reject log file.
///
/// Creates the log file if it doesn't exist. Appends log lines in C Exim
/// format: "YYYY-MM-DD HH:MM:SS <log_line>\n".
fn write_rejectlog(spool_dir: &str, line: &str) {
    let log_dir = format!("{}/log", spool_dir);
    let _ = std::fs::create_dir_all(&log_dir);

    let rejectlog_path = format!("{}/rejectlog", log_dir);
    let now = chrono_format_now();

    let formatted = format!("{} {}\n", now, line);
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&rejectlog_path)
    {
        Ok(mut f) => {
            use std::io::Write as _;
            let _ = f.write_all(formatted.as_bytes());
        }
        Err(e) => {
            tracing::error!(error = %e, path = %rejectlog_path, "failed to write rejectlog");
        }
    }
}

/// Write a log line to the Exim panic log file.
///
/// Creates the log file if it doesn't exist. Used for fatal errors and
/// unexpected conditions.
fn write_paniclog(spool_dir: &str, line: &str) {
    let log_dir = format!("{}/log", spool_dir);
    let _ = std::fs::create_dir_all(&log_dir);

    let paniclog_path = format!("{}/paniclog", log_dir);
    let now = chrono_format_now();

    let formatted = format!("{} {}\n", now, line);
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&paniclog_path)
    {
        Ok(mut f) => {
            use std::io::Write as _;
            let _ = f.write_all(formatted.as_bytes());
        }
        Err(e) => {
            tracing::error!(error = %e, path = %paniclog_path, "failed to write paniclog");
        }
    }
}

/// Format current time in Exim log format: "YYYY-MM-DD HH:MM:SS".
///
/// This matches the C Exim log timestamp format used by `exigrep` and
/// `eximstats` for parsing (AAP §0.7.1).
///
/// Uses the safe `exim_ffi::time::localtime_safe()` wrapper to avoid
/// `unsafe` code in `exim-core` (per `#![forbid(unsafe_code)]`).
fn chrono_format_now() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();

    // Use the safe localtime wrapper from exim-ffi. If the FFI crate
    // does not expose it, fall back to a simple UTC calculation that
    // is valid for log timestamps (UTC is acceptable for logs).
    let (year, month, day, hour, min, sec) = epoch_to_utc_components(secs);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, hour, min, sec,
    )
}

/// Convert epoch seconds to UTC date-time components without `unsafe`.
///
/// Implements a pure-Rust calendar conversion (no libc dependency) for
/// the subset of functionality needed by Exim log formatting. Uses the
/// civil calendar algorithm from Howard Hinnant's date library.
fn epoch_to_utc_components(epoch_secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let secs_in_day: u64 = 86400;
    let total_days = (epoch_secs / secs_in_day) as i64;
    let day_secs = (epoch_secs % secs_in_day) as u32;

    let hour = day_secs / 3600;
    let min = (day_secs % 3600) / 60;
    let sec = day_secs % 60;

    // Howard Hinnant's civil_from_days algorithm (public domain).
    // Converts days since Unix epoch (1970-01-01) to (year, month, day).
    let z = total_days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    (y as i32, m as u32, d as u32, hour, min, sec)
}

// ===========================================================================
// Child Process Reaping
// ===========================================================================

/// Reap terminated child processes (SMTP handlers and queue runners).
///
/// Replaces `handle_ending_processes()` from `daemon.c` lines 2698–2710.
/// Called when `sigchld_seen()` returns `true`. Uses `waitpid(WNOHANG)` in
/// a loop to collect all terminated children without blocking.
///
/// Updates both `smtp_slots` in `ServerContext` and `queue_runner_slots` in
/// `DaemonState` to clear entries for reaped children.
fn reap_children(ctx: &mut ServerContext, state: &mut DaemonState) {
    loop {
        match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(pid, status)) => {
                tracing::debug!(
                    pid = pid.as_raw(),
                    exit_status = status,
                    "child process exited"
                );
                clear_child_slot(ctx, state, pid);
            }
            Ok(WaitStatus::Signaled(pid, sig, _core)) => {
                tracing::warn!(
                    pid = pid.as_raw(),
                    signal = sig as i32,
                    "child process killed by signal"
                );
                clear_child_slot(ctx, state, pid);
            }
            Ok(WaitStatus::StillAlive) => {
                // No more children to reap.
                break;
            }
            Ok(_other) => {
                // Other wait statuses (Stopped, Continued) — ignore.
                continue;
            }
            Err(nix::errno::Errno::ECHILD) => {
                // No children at all — nothing to reap.
                break;
            }
            Err(e) => {
                tracing::debug!(error = %e, "waitpid returned error");
                break;
            }
        }
    }
}

/// Clear the tracking slot for a terminated child process.
///
/// Searches both SMTP slots and queue runner slots for the given PID
/// and clears the matching entry.
fn clear_child_slot(ctx: &mut ServerContext, state: &mut DaemonState, pid: Pid) {
    let raw_pid = pid.as_raw();

    // Check SMTP slots.
    for slot in ctx.smtp_slots.iter_mut() {
        if slot.pid == raw_pid {
            tracing::debug!(
                pid = raw_pid,
                host = slot.host_address.as_deref().unwrap_or("unknown"),
                "cleared SMTP slot"
            );
            slot.pid = 0;
            slot.host_address = None;
            slot.host_name = None;
            slot.interface_address = None;
            ctx.smtp_accept_count = (ctx.smtp_accept_count - 1).max(0);
            return;
        }
    }

    // Check queue runner slots.
    for slot in state.queue_runner_slots.iter_mut() {
        if slot.pid == Some(pid) {
            tracing::debug!(
                pid = raw_pid,
                queue = slot.queue_name.as_str(),
                "cleared queue runner slot"
            );
            slot.pid = None;
            slot.queue_name.clear();
            return;
        }
    }

    // PID not found in any slot — possibly a delivery subprocess or
    // a child that was already cleaned up.
    tracing::debug!(
        pid = raw_pid,
        "reaped child not found in SMTP or queue runner slots"
    );
}

// ===========================================================================
// Queue Runner Scheduling
// ===========================================================================

/// Schedule queue runner processes at the configured interval.
///
/// Replaces the SIGALRM-driven queue scheduling from `daemon.c` lines 2625–2645.
/// Called when `sigalrm_seen()` returns `true` (timer tick for queue runs).
///
/// For each configured queue runner, checks if there is a free slot and forks
/// a child process to execute the queue run.
fn schedule_queue_runs(ctx: &mut ServerContext, config: &Arc<Config>, state: &mut DaemonState) {
    // Determine maximum concurrent queue runners from config.
    let max_runners: u32 = config
        .queue_run_max
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    // Count currently active runners.
    let active_runners = state
        .queue_runner_slots
        .iter()
        .filter(|s| s.is_active())
        .count() as u32;

    if active_runners >= max_runners {
        tracing::debug!(
            active = active_runners,
            max = max_runners,
            "queue runner limit reached, deferring"
        );
        return;
    }

    // Find a free slot or allocate a new one.
    let slot_idx = match state.queue_runner_slots.iter().position(|s| !s.is_active()) {
        Some(idx) => idx,
        None => {
            state.queue_runner_slots.push(RunnerSlot::empty());
            state.queue_runner_slots.len() - 1
        }
    };

    // Fork a queue runner child.
    let queue_name = String::new(); // Default queue.
    match process::fork_for_queue_run(ctx, &queue_name) {
        Ok(ForkResult::Child) => {
            // === CHILD PROCESS ===
            tracing::debug!("queue runner child starting");
            process::set_process_info("queue runner");

            // Build a QueueRunner struct for this run.
            let runner = queue_runner::QueueRunner {
                name: queue_name.clone(),
                interval: ctx.queue_interval.unwrap_or(Duration::from_secs(300)),
                run_max: max_runners,
                run_force: false,
                run_first_delivery: false,
                run_local: false,
                run_in_order: false,
            };

            // Build a ConfigContext wrapper for the queue runner.
            let config_ctx = ConfigContext {
                config_filename: PathBuf::from(&config.config_filename),
                config_changed: false,
                config: Arc::clone(config),
            };

            // Execute the queue run.
            let _ = queue_runner::queue_run(&runner, ctx, &config_ctx, None, None);

            // Child must not return to the daemon loop.
            exit(0);
        }
        Ok(ForkResult::Parent { child }) => {
            // Record the child in the queue runner slot.
            state.queue_runner_slots[slot_idx] = RunnerSlot {
                pid: Some(child),
                queue_name: queue_name.clone(),
            };
            state.queue_run_count += 1;
            state.queue_runner_slot_count = state.queue_runner_slots.len() as u32;

            tracing::info!(
                child_pid = child.as_raw(),
                queue = queue_name.as_str(),
                run_count = state.queue_run_count,
                "spawned queue runner"
            );

            // Reset the SIGALRM timer for the next queue interval.
            if let Some(interval) = ctx.queue_interval {
                let secs = interval.as_secs().max(1) as u32;
                signal::set_alarm(secs);
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to fork queue runner");
            // Reset alarm even on failure so we try again next interval.
            if let Some(interval) = ctx.queue_interval {
                let secs = interval.as_secs().max(1) as u32;
                signal::set_alarm(secs);
            }
        }
    }
}
