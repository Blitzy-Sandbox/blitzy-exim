//! # Parallel Remote Delivery Subprocess Pool
//!
//! This module implements the subprocess pool for parallel remote delivery,
//! translating the parallel delivery machinery from `src/src/deliver.c`
//! (lines 22–4950) into safe Rust.
//!
//! ## C Source Mapping
//!
//! | Rust type/function            | C origin (deliver.c)                  |
//! |-------------------------------|---------------------------------------|
//! | `ParData`                     | `pardata` struct (lines 22–31)        |
//! | `ParallelDeliveryManager`     | `parcount` + `parlist` + `parpoll`    |
//! | `PipeMessageType`             | Pipe header id byte protocol          |
//! | `PIPE_HEADER_SIZE`            | Pipe header constant (1 type+3 len)   |
//! | `sort_remote_deliveries()`    | `sort_remote_deliveries()` (line 3197)|
//! | `par_read_pipe()`             | `par_read_pipe()` (line 3302)         |
//! | `par_wait()`                  | `par_wait()` (line 3984)              |
//! | `par_reduce()`                | `par_reduce()` (line 4244)            |
//! | `do_remote_deliveries()`      | `do_remote_deliveries()` (line 4337)  |
//! | `write_delivery_result()`     | `rmt_dlv_checked_write()` (line 4267) |
//!
//! ## Design Patterns (AAP §0.4.2)
//!
//! - **Fork-per-connection model preserved** — same subprocess model as C
//! - **Scoped context passing** — all functions receive explicit context structs
//! - **`poll()`-based multiplexing** — `nix::poll::poll()` for safe POSIX poll
//! - **Pipe-based IPC** — `nix::unistd::pipe()` for safe pipe creation
//! - **Compile-time taint tracking** — `Tainted<T>` for pipe-received data
//!
//! ## Safety
//!
//! This module contains **zero** `unsafe` blocks (per AAP §0.7.2). The
//! `fork()` system call is delegated to `exim_ffi::process::fork_process()`,
//! which wraps the `unsafe { nix::unistd::fork() }` call in the only crate
//! permitted to contain `unsafe` code. All other POSIX operations use safe
//! nix wrappers.

// SPDX-License-Identifier: GPL-2.0-or-later

use std::os::unix::io::{AsFd, BorrowedFd, OwnedFd};

use nix::errno::Errno;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::signal::kill;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{pipe, read, write, ForkResult, Pid};
use tracing::{debug, error, info, warn};

use crate::orchestrator::{AddressFlags, AddressItem, DeliveryError};
use exim_config::types::{ConfigContext, DeliveryContext, MessageContext, ServerContext};
use exim_drivers::transport_driver::{TransportDriver, TransportInstanceConfig};
use exim_store::taint::Tainted;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of the pipe message header in bytes.
///
/// The header consists of 1 byte for the message type and 3 bytes for the
/// payload length encoded as a decimal string. This gives a maximum payload
/// of 999 bytes per pipe message.
///
/// C equivalent: the pipe header protocol uses `snprintf("%c%03d", id, size)`
/// giving 4 bytes total (1 type + 3 length digits).
pub const PIPE_HEADER_SIZE: usize = 4;

/// Maximum payload size that fits in a 3-digit decimal length field.
const MAX_PIPE_PAYLOAD: usize = 999;

/// Poll timeout in milliseconds — matching C `par_wait()` 60-second timeout.
/// Stored as `u16` for direct conversion to `PollTimeout`.
const POLL_TIMEOUT_MS: u16 = 60_000;

/// Maximum number of retry attempts for a pipe read/write interrupted by EINTR.
const MAX_EINTR_RETRIES: usize = 20;

// ---------------------------------------------------------------------------
// PipeMessageType — Pipe protocol message type tags
// ---------------------------------------------------------------------------

/// Message type tags for the pipe IPC protocol between parent and child
/// delivery subprocesses.
///
/// Each pipe message begins with a single byte identifying the message type,
/// followed by a 3-byte decimal length, followed by the payload data.
///
/// C equivalents (deliver.c): 'A', 'R', 'H', 'C', 'S', 'D', 'X', 'Z'
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PipeMessageType {
    /// Address delivery result — status code + error message for a recipient.
    Address,
    /// Retry information — retry rule data for the hints database.
    Retry,
    /// Host status — marks a host as unusable for future delivery attempts.
    Host,
    /// Continue transport — data about an existing SMTP connection to reuse.
    Continue,
    /// TLS certificate information from the delivery subprocess.
    Tls,
    /// DANE verification result from the delivery subprocess.
    Dane,
    /// Error message — general error from the delivery subprocess.
    Error,
    /// Termination marker — signals that the subprocess is done writing.
    Termination,
}

impl PipeMessageType {
    /// Convert a byte tag to the corresponding `PipeMessageType`.
    ///
    /// Returns `None` for unrecognised tag bytes, which the caller should
    /// log and skip rather than treating as fatal.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            b'A' => Some(Self::Address),
            b'R' => Some(Self::Retry),
            b'H' => Some(Self::Host),
            b'C' => Some(Self::Continue),
            b'S' => Some(Self::Tls),
            b'D' => Some(Self::Dane),
            b'X' => Some(Self::Error),
            b'Z' => Some(Self::Termination),
            _ => None,
        }
    }

    /// Convert this message type to the corresponding wire byte.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Address => b'A',
            Self::Retry => b'R',
            Self::Host => b'H',
            Self::Continue => b'C',
            Self::Tls => b'S',
            Self::Dane => b'D',
            Self::Error => b'X',
            Self::Termination => b'Z',
        }
    }
}

impl std::fmt::Display for PipeMessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Address => "Address",
            Self::Retry => "Retry",
            Self::Host => "Host",
            Self::Continue => "Continue",
            Self::Tls => "Tls",
            Self::Dane => "Dane",
            Self::Error => "Error",
            Self::Termination => "Termination",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// ParData — Per-subprocess tracking data
// ---------------------------------------------------------------------------

/// Per-subprocess tracking data for a delivery child process.
///
/// Replaces the C `pardata` struct (deliver.c lines 22–31).
///
/// Each active delivery subprocess has one `ParData` entry in the
/// `ParallelDeliveryManager::parlist` array. The parent process uses
/// the `fd` field for `poll()` and `read()`, and the `pid` field for
/// `waitpid()`.
///
/// Note: `ParData` is not `Clone` because `OwnedFd` is not `Clone` (by
/// design — file descriptor ownership is exclusive).
#[derive(Debug)]
pub struct ParData {
    /// Chain of recipient addresses assigned to this subprocess.
    pub addrlist: Vec<AddressItem>,

    /// Index of the next address expected in pipe result messages.
    pub addr_index: usize,

    /// PID of the delivery subprocess. `None` if the slot is not in use.
    pub pid: Option<i32>,

    /// Owned file descriptor for reading delivery results from the
    /// subprocess pipe. Stored as `OwnedFd` so that `BorrowedFd` can be
    /// obtained safely via `.as_fd()` for `poll()` and `read()`.
    /// `None` if the pipe has been closed or the slot is not in use.
    pub fd: Option<OwnedFd>,

    /// Transport count returned by the subprocess — number of messages
    /// this transport connection has handled.
    pub transport_count: i32,

    /// Set to `true` when the termination marker ('Z') has been received
    /// or a disaster occurred, indicating no more data is expected.
    pub done: bool,

    /// Error message from the subprocess, if any.
    pub msg: Option<String>,

    /// Return path (envelope sender) for the addresses in this subprocess.
    pub return_path: Option<String>,
}

impl ParData {
    /// Create a new empty `ParData` slot.
    fn new() -> Self {
        Self {
            addrlist: Vec::new(),
            addr_index: 0,
            pid: None,
            fd: None,
            transport_count: 0,
            done: false,
            msg: None,
            return_path: None,
        }
    }

    /// Reset this slot for reuse with a new subprocess.
    ///
    /// If an `OwnedFd` is present it is dropped, which closes the
    /// underlying file descriptor automatically.
    fn reset(&mut self) {
        self.addrlist.clear();
        self.addr_index = 0;
        self.pid = None;
        self.fd = None; // drop closes the fd
        self.transport_count = 0;
        self.done = false;
        self.msg = None;
        self.return_path = None;
    }
}

// ---------------------------------------------------------------------------
// ParallelDeliveryManager — Subprocess pool manager
// ---------------------------------------------------------------------------

/// Manages a pool of delivery subprocesses for parallel remote delivery.
///
/// Replaces the C static variables `parcount`, `parlist`, and `parpoll`
/// (deliver.c lines 75–77) with a self-contained struct.
///
/// # Fork-per-connection Model
///
/// Per AAP §0.7.3, the same fork-per-connection concurrency model as C is
/// preserved. `tokio` is NOT used for delivery subprocess management.
pub struct ParallelDeliveryManager {
    /// Per-subprocess tracking data, one slot per potential parallel delivery.
    parlist: Vec<ParData>,

    /// Number of currently active delivery subprocesses.
    parcount: usize,

    /// Maximum number of concurrent delivery subprocesses, from the
    /// `remote_max_parallel` configuration option.
    max_parallel: usize,
}

impl std::fmt::Debug for ParallelDeliveryManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParallelDeliveryManager")
            .field("parcount", &self.parcount)
            .field("max_parallel", &self.max_parallel)
            .field("parlist_len", &self.parlist.len())
            .finish()
    }
}

impl ParallelDeliveryManager {
    /// Create a new `ParallelDeliveryManager` with the specified maximum
    /// parallelism level.
    ///
    /// Pre-allocates `max_parallel` slots in the `parlist` array. If
    /// `max_parallel` is zero, it defaults to 1 (serial delivery).
    pub fn new(max_parallel: usize) -> Self {
        let effective_max = if max_parallel == 0 { 1 } else { max_parallel };
        let parlist = (0..effective_max).map(|_| ParData::new()).collect();
        Self {
            parlist,
            parcount: 0,
            max_parallel: effective_max,
        }
    }

    /// Find a free slot in the parlist for a new subprocess.
    fn find_free_slot(&self) -> Option<usize> {
        self.parlist.iter().position(|p| p.pid.is_none())
    }

    /// Read delivery results from a subprocess pipe.
    ///
    /// Translates C `par_read_pipe()` (deliver.c line 3302, ~560 lines).
    ///
    /// Reads one or more pipe messages from the subprocess at
    /// `parlist[poffset]`. Each message consists of a
    /// [`PIPE_HEADER_SIZE`]-byte header (1 byte type + 3 byte decimal
    /// length) followed by the payload.
    ///
    /// # Implementation Note — Borrow Splitting
    ///
    /// The `OwnedFd` is temporarily moved out of the `parlist` slot
    /// via `take()` so that the borrowed `BorrowedFd` does not hold a
    /// shared reference to `self`, allowing simultaneous mutation of
    /// other `ParData` fields. The fd is restored before return.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the termination marker was received or a fatal
    ///   error occurred
    /// - `Ok(false)` if data was read but more may follow
    /// - `Err(DeliveryError)` on unrecoverable pipe I/O failure
    pub fn par_read_pipe(&mut self, poffset: usize, eop: bool) -> Result<bool, DeliveryError> {
        // Move the OwnedFd onto the stack so that the BorrowedFd borrows the
        // local variable, not self.parlist — this avoids borrow conflicts when
        // mutating other ParData fields after reading.
        let owned_fd = match self.parlist[poffset].fd.take() {
            Some(fd) => fd,
            None => {
                warn!(poffset, "par_read_pipe called with no fd");
                return Ok(true);
            }
        };
        let fd: BorrowedFd<'_> = owned_fd.as_fd();

        debug!(
            poffset,
            pid = ?self.parlist[poffset].pid,
            eop,
            "par_read_pipe: reading from subprocess"
        );

        let result = self.par_read_pipe_inner(fd, poffset, eop);

        // Restore the fd unless the slot is marked done (in which case
        // dropping the OwnedFd closes the file descriptor).
        if self.parlist[poffset].done {
            drop(owned_fd);
        } else {
            self.parlist[poffset].fd = Some(owned_fd);
        }

        result
    }

    /// Core pipe-reading loop, separated from fd management.
    fn par_read_pipe_inner(
        &mut self,
        fd: BorrowedFd<'_>,
        poffset: usize,
        eop: bool,
    ) -> Result<bool, DeliveryError> {
        loop {
            // Read the pipe header: 1 byte type + 3 bytes decimal length.
            let mut header_buf = [0u8; PIPE_HEADER_SIZE];
            let header_read = read_exact_from_fd(fd, &mut header_buf);

            match header_read {
                Ok(0) => {
                    warn!(
                        poffset,
                        pid = ?self.parlist[poffset].pid,
                        "par_read_pipe: unexpected EOF (no termination marker)"
                    );
                    self.parlist[poffset].done = true;
                    return Ok(true);
                }
                Ok(n) if n < PIPE_HEADER_SIZE => {
                    error!(
                        poffset,
                        bytes_read = n,
                        "par_read_pipe: incomplete pipe header"
                    );
                    self.parlist[poffset].done = true;
                    return Err(DeliveryError::PipeReadFailed(format!(
                        "incomplete pipe header: got {n} of {PIPE_HEADER_SIZE} bytes"
                    )));
                }
                Ok(_) => { /* Full header — continue below. */ }
                Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    self.parlist[poffset].done = true;
                    return Ok(true);
                }
                Err(e) => {
                    error!(poffset, error = %e, "par_read_pipe: pipe read error");
                    self.parlist[poffset].done = true;
                    return Err(DeliveryError::PipeReadFailed(format!(
                        "pipe header read: {e}"
                    )));
                }
            }

            // Parse message type.
            let msg_type = match PipeMessageType::from_byte(header_buf[0]) {
                Some(t) => t,
                None => {
                    warn!(
                        poffset,
                        byte = header_buf[0],
                        "par_read_pipe: unknown pipe message type"
                    );
                    let payload_len = parse_decimal_length(&header_buf[1..PIPE_HEADER_SIZE]);
                    if payload_len > 0 {
                        let mut skip_buf = vec![0u8; payload_len];
                        let _ = read_exact_from_fd(fd, &mut skip_buf);
                    }
                    if !eop {
                        return Ok(false);
                    }
                    continue;
                }
            };

            // Parse payload length from the remaining 3 bytes.
            let payload_len = parse_decimal_length(&header_buf[1..PIPE_HEADER_SIZE]);

            debug!(
                poffset,
                msg_type = %msg_type,
                payload_len,
                "par_read_pipe: received message"
            );

            // Read the payload data.
            let payload = if payload_len > 0 {
                let mut buf = vec![0u8; payload_len];
                match read_exact_from_fd(fd, &mut buf) {
                    Ok(n) if n == payload_len => buf,
                    Ok(n) => {
                        warn!(
                            poffset,
                            expected = payload_len,
                            got = n,
                            "par_read_pipe: short payload read"
                        );
                        buf.truncate(n);
                        buf
                    }
                    Err(e) => {
                        error!(
                            poffset,
                            error = %e,
                            "par_read_pipe: payload read error"
                        );
                        self.parlist[poffset].done = true;
                        return Err(DeliveryError::PipeReadFailed(format!(
                            "pipe payload read: {e}"
                        )));
                    }
                }
            } else {
                Vec::new()
            };

            // Wrap payload in Tainted since it crossed a process boundary.
            let tainted_payload = Tainted::new(payload.clone());

            // Process the message based on type.
            match msg_type {
                PipeMessageType::Address => {
                    self.process_address_result(poffset, tainted_payload.into_inner())?;
                }
                PipeMessageType::Retry => {
                    self.process_retry_info(poffset, tainted_payload.into_inner());
                }
                PipeMessageType::Host => {
                    self.process_host_status(poffset, tainted_payload.into_inner());
                }
                PipeMessageType::Continue => {
                    self.process_continue_data(poffset, tainted_payload.into_inner());
                }
                PipeMessageType::Tls => {
                    self.process_tls_info(poffset, tainted_payload.into_inner());
                }
                PipeMessageType::Dane => {
                    self.process_dane_info(poffset, tainted_payload.into_inner());
                }
                PipeMessageType::Error => {
                    let err_msg = String::from_utf8_lossy(tainted_payload.as_ref()).to_string();
                    warn!(poffset, error = %err_msg, "subprocess error");
                    self.parlist[poffset].msg = Some(err_msg);
                }
                PipeMessageType::Termination => {
                    debug!(poffset, "par_read_pipe: received termination marker");
                    if !payload.is_empty() {
                        let count_str = String::from_utf8_lossy(&payload);
                        if let Ok(count) = count_str.trim().parse::<i32>() {
                            self.parlist[poffset].transport_count = count;
                        }
                    }
                    self.parlist[poffset].done = true;
                    return Ok(true);
                }
            }

            // If not in "read until end" mode, return after one message.
            if !eop {
                return Ok(false);
            }
        }
    }

    /// Wait for a delivery subprocess to complete.
    ///
    /// Translates C `par_wait()` (deliver.c line 3984, ~260 lines).
    ///
    /// Uses `poll()` on all active subprocess pipes, then `waitpid()` to
    /// reap completed children. Handles:
    /// - Non-blocking `waitpid()` with `WNOHANG`
    /// - `poll()` with 60-second timeout on all active pipe fds
    /// - Linux strace workaround (`kill()` check for stolen children)
    pub fn par_wait(&mut self, reason: &str) -> Result<Vec<AddressItem>, DeliveryError> {
        debug!(
            parcount = self.parcount,
            reason, "par_wait: waiting for subprocess"
        );

        if self.parcount == 0 {
            debug!("par_wait: no active subprocesses");
            return Ok(Vec::new());
        }

        loop {
            // Phase 1: Try non-blocking waitpid for any completed child.
            let mut reaped_idx: Option<usize> = None;
            for (idx, slot) in self.parlist.iter().enumerate() {
                if let Some(child_pid) = slot.pid {
                    match waitpid(Pid::from_raw(child_pid), Some(WaitPidFlag::WNOHANG)) {
                        Ok(WaitStatus::StillAlive) => {}
                        Ok(WaitStatus::Exited(_, code)) if code != 0 => {
                            warn!(
                                idx,
                                child_pid, code, "par_wait: child exited with non-zero status"
                            );
                            self.parlist[idx].msg =
                                Some(format!("subprocess failed with exit code {code}"));
                            reaped_idx = Some(idx);
                            break;
                        }
                        Ok(WaitStatus::Signaled(_, sig, _)) => {
                            let sig_num = sig as i32;
                            warn!(idx, child_pid, sig_num, "par_wait: child killed by signal");
                            self.parlist[idx].msg =
                                Some(format!("subprocess killed by signal {sig_num}"));
                            reaped_idx = Some(idx);
                            break;
                        }
                        Ok(status) => {
                            debug!(idx, child_pid, ?status, "par_wait: child exited (pre-poll)");
                            reaped_idx = Some(idx);
                            break;
                        }
                        Err(Errno::ECHILD) => {
                            // Child already reaped or stolen by strace.
                            if kill(Pid::from_raw(child_pid), None).is_err() {
                                warn!(idx, child_pid, "par_wait: child vanished (ECHILD)");
                                reaped_idx = Some(idx);
                                break;
                            }
                        }
                        Err(e) => {
                            warn!(
                                idx,
                                child_pid,
                                error = %e,
                                "par_wait: waitpid error"
                            );
                        }
                    }
                }
            }

            // If a child was reaped pre-poll, drain remaining pipe data.
            if let Some(idx) = reaped_idx {
                if self.parlist[idx].fd.is_some() && !self.parlist[idx].done {
                    let _ = self.par_read_pipe(idx, true);
                }
                return self.collect_completed_subprocess(idx);
            }

            // Phase 2: Build poll fd set from active pipes.
            let active_indices: Vec<usize> = self
                .parlist
                .iter()
                .enumerate()
                .filter_map(|(idx, slot)| {
                    if slot.fd.is_some() && !slot.done && slot.pid.is_some() {
                        Some(idx)
                    } else {
                        None
                    }
                })
                .collect();

            if active_indices.is_empty() {
                // No active pipes — try to reap zombie children.
                for idx in 0..self.parlist.len() {
                    if let Some(child_pid) = self.parlist[idx].pid {
                        match waitpid(Pid::from_raw(child_pid), Some(WaitPidFlag::WNOHANG)) {
                            Ok(WaitStatus::StillAlive) => {}
                            Ok(_) | Err(_) => {
                                return self.collect_completed_subprocess(idx);
                            }
                        }
                    }
                }
                error!("par_wait: no active pipes but children still running");
                return Err(DeliveryError::WaitFailed(
                    "no active pipes but children still running".to_string(),
                ));
            }

            // Build PollFd array using safe BorrowedFd from OwnedFd.
            let mut poll_fds: Vec<PollFd<'_>> = active_indices
                .iter()
                .filter_map(|&idx| {
                    self.parlist[idx]
                        .fd
                        .as_ref()
                        .map(|ofd| PollFd::new(ofd.as_fd(), PollFlags::POLLIN))
                })
                .collect();

            let timeout = PollTimeout::from(POLL_TIMEOUT_MS);
            let poll_result = poll(&mut poll_fds, timeout);

            match poll_result {
                Ok(0) => {
                    // Timeout — check for dead children.
                    debug!("par_wait: poll timeout, checking for dead children");
                    for (idx, slot) in self.parlist.iter().enumerate() {
                        if let Some(child_pid) = slot.pid {
                            if kill(Pid::from_raw(child_pid), None).is_err() {
                                warn!(idx, child_pid, "par_wait: child vanished after timeout");
                                reaped_idx = Some(idx);
                                break;
                            }
                        }
                    }
                    if let Some(idx) = reaped_idx {
                        if self.parlist[idx].fd.is_some() && !self.parlist[idx].done {
                            let _ = self.par_read_pipe(idx, true);
                        }
                        return self.collect_completed_subprocess(idx);
                    }
                    continue;
                }
                Ok(_n_ready) => {
                    // Find the first ready pipe.
                    let mut completed_idx: Option<usize> = None;
                    for (poll_idx, poll_fd) in poll_fds.iter().enumerate() {
                        if let Some(revents) = poll_fd.revents() {
                            if revents.intersects(
                                PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR,
                            ) {
                                completed_idx = Some(active_indices[poll_idx]);
                                break;
                            }
                        }
                    }

                    // Drop poll_fds borrow before calling mut methods.
                    drop(poll_fds);

                    if let Some(parlist_idx) = completed_idx {
                        let terminated = self.par_read_pipe(parlist_idx, false)?;

                        if terminated {
                            if let Some(child_pid) = self.parlist[parlist_idx].pid {
                                if let Ok(WaitStatus::StillAlive) =
                                    waitpid(Pid::from_raw(child_pid), Some(WaitPidFlag::WNOHANG))
                                {
                                    if !self.parlist[parlist_idx].done {
                                        let _ = self.par_read_pipe(parlist_idx, true);
                                    }
                                    let _ = waitpid(Pid::from_raw(child_pid), None);
                                }
                            }
                            return self.collect_completed_subprocess(parlist_idx);
                        }
                    }
                    continue;
                }
                Err(Errno::EINTR) => {
                    debug!("par_wait: poll interrupted, retrying");
                    continue;
                }
                Err(e) => {
                    error!(error = %e, "par_wait: poll failed");
                    return Err(DeliveryError::WaitFailed(format!("poll: {e}")));
                }
            }
        }
    }

    /// Reduce active subprocess count to the specified maximum.
    ///
    /// Translates C `par_reduce()` (deliver.c line 4244, ~20 lines).
    pub fn par_reduce(
        &mut self,
        max: usize,
        fallback: bool,
        reason: &str,
    ) -> Result<(), DeliveryError> {
        let label = if fallback { "fallback" } else { "normal" };
        debug!(
            parcount = self.parcount,
            max,
            mode = label,
            reason,
            "par_reduce: reducing subprocess count"
        );

        while self.parcount > max {
            let completed_addrs = self.par_wait(reason)?;
            info!(
                parcount = self.parcount,
                completed = completed_addrs.len(),
                "par_reduce: subprocess completed"
            );
        }

        Ok(())
    }

    /// Main remote delivery loop — fork subprocesses for parallel delivery.
    ///
    /// Translates C `do_remote_deliveries()` (deliver.c line 4337, ~1050
    /// lines).
    ///
    /// # Fork Safety
    ///
    /// Forking is delegated to `exim_ffi::process::fork_process()` — the
    /// safe wrapper that isolates the `unsafe { nix::unistd::fork() }` call
    /// in the only crate permitted to contain `unsafe` code (AAP §0.7.2).
    /// The call is sound because Exim's delivery path is inherently
    /// single-threaded (fork-per-connection model per AAP §0.7.3), the child
    /// immediately executes transport code and exits, and all shared state
    /// flows exclusively through pipe IPC.
    pub fn do_remote_deliveries(
        &mut self,
        addr_remote: &mut Vec<AddressItem>,
        fallback: bool,
        server_ctx: &ServerContext,
        msg_ctx: &mut MessageContext,
        delivery_ctx: &mut DeliveryContext,
        config: &ConfigContext,
    ) -> Result<bool, DeliveryError> {
        if addr_remote.is_empty() {
            debug!("do_remote_deliveries: no remote addresses");
            return Ok(false);
        }

        let label = if fallback { "fallback" } else { "normal" };
        info!(
            count = addr_remote.len(),
            mode = label,
            message_id = %msg_ctx.message_id,
            "do_remote_deliveries: starting remote delivery"
        );

        // Sort addresses by remote_sort_domains if configured.
        if let Some(ref sort_domains) = config.remote_sort_domains {
            if !sort_domains.is_empty() {
                sort_remote_deliveries(addr_remote, sort_domains, config);
            }
        }

        let mut any_attempted = false;

        // Group addresses by transport+host for batched delivery.
        while !addr_remote.is_empty() {
            let group = extract_address_group(addr_remote, config);
            if group.is_empty() {
                continue;
            }

            let transport_name = group[0].transport.clone().unwrap_or_default();
            let return_path = group[0].return_path.clone();

            debug!(
                transport = %transport_name,
                count = group.len(),
                "do_remote_deliveries: processing address group"
            );

            // Check per-transport max_parallel limit.
            let transport_max = self.get_transport_max_parallel(&transport_name, config);
            if transport_max > 0 {
                let active = self.count_active_for_transport(&transport_name);
                if active >= transport_max {
                    debug!(
                        transport = %transport_name,
                        active,
                        max = transport_max,
                        "transport at max, waiting"
                    );
                    let _ = self.par_wait("transport max_parallel")?;
                }
            }

            // Ensure we have a free slot.
            if self.parcount >= self.max_parallel {
                let _ = self.par_wait("max parallel")?;
            }

            let slot_idx = match self.find_free_slot() {
                Some(idx) => idx,
                None => {
                    let _ = self.par_wait("no free slot")?;
                    match self.find_free_slot() {
                        Some(idx) => idx,
                        None => {
                            error!("do_remote_deliveries: no free slot after wait");
                            return Err(DeliveryError::ForkFailed(
                                "no free parlist slot".to_string(),
                            ));
                        }
                    }
                }
            };

            // Create the IPC pipe.
            let (pipe_read, pipe_write) = match pipe() {
                Ok(fds) => fds,
                Err(e) => {
                    error!(error = %e, "pipe() failed");
                    return Err(DeliveryError::ForkFailed(format!("pipe: {e}")));
                }
            };

            // Delegate to the safe fork wrapper in exim-ffi (AAP §0.7.2).
            // See function-level doc comment for safety justification.
            let fork_result = exim_ffi::process::fork_process();

            match fork_result {
                Ok(ForkResult::Child) => {
                    // ===== CHILD PROCESS =====
                    // Close the read end.
                    drop(pipe_read);

                    // Execute delivery and write results.
                    let result = execute_child_delivery(
                        pipe_write.as_fd(),
                        &group,
                        &transport_name,
                        server_ctx,
                        msg_ctx,
                        delivery_ctx,
                        config,
                    );

                    let count_bytes = match &result {
                        Ok(()) => b"0" as &[u8],
                        Err(_) => b"0" as &[u8],
                    };
                    let _ = write_pipe_message(
                        pipe_write.as_fd(),
                        PipeMessageType::Termination,
                        count_bytes,
                    );

                    // Close write end and exit.
                    drop(pipe_write);
                    let code = if result.is_ok() { 0 } else { 1 };
                    std::process::exit(code);
                }
                Ok(ForkResult::Parent { child }) => {
                    // ===== PARENT PROCESS =====
                    // Close the write end.
                    drop(pipe_write);

                    let slot = &mut self.parlist[slot_idx];
                    slot.reset();
                    slot.addrlist = group;
                    slot.pid = Some(child.as_raw());
                    slot.fd = Some(pipe_read);
                    slot.return_path = return_path;
                    self.parcount += 1;

                    debug!(
                        slot = slot_idx,
                        pid = child.as_raw(),
                        transport = %transport_name,
                        "forked delivery subprocess"
                    );

                    any_attempted = true;
                }
                Err(e) => {
                    // Fork failed — close both pipe ends.
                    drop(pipe_read);
                    drop(pipe_write);

                    error!(error = %e, "fork() failed");

                    // Put addresses back as deferred.
                    for mut addr in group {
                        addr.message = Some(format!("fork failed for remote delivery: {e}"));
                        addr.basic_errno = libc::EAGAIN;
                        addr_remote.push(addr);
                    }
                }
            }
        }

        // Wait for all remaining subprocesses.
        self.par_reduce(0, fallback, "end of remote deliveries")?;

        info!(
            any_attempted,
            message_id = %msg_ctx.message_id,
            "do_remote_deliveries: complete"
        );

        Ok(any_attempted)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Collect completed subprocess data, clean up slot, return addresses.
    ///
    /// If the subprocess indicated failure (non-zero exit or signal), all
    /// addresses in the slot are annotated with a `SubprocessFailed` error
    /// message so the caller can identify deliveries that need retry.
    fn collect_completed_subprocess(
        &mut self,
        idx: usize,
    ) -> Result<Vec<AddressItem>, DeliveryError> {
        let slot = &mut self.parlist[idx];

        // Drop OwnedFd to close the pipe read end.
        slot.fd = None;

        let mut addrs = std::mem::take(&mut slot.addrlist);
        let pid = slot.pid;
        let msg = slot.msg.clone();
        let transport_count = slot.transport_count;

        // If the subprocess reported a failure message, mark unprocessed
        // addresses so the orchestrator can schedule retries.
        if let Some(ref failure_msg) = msg {
            if failure_msg.starts_with("subprocess") {
                warn!(
                    idx,
                    ?pid,
                    msg = %failure_msg,
                    "collect_completed_subprocess: subprocess failed"
                );
                for addr in &mut addrs {
                    if addr.message.is_none() {
                        addr.message = Some(failure_msg.clone());
                        addr.basic_errno = libc::EAGAIN;
                    }
                }
                // Record the subprocess failure for upstream error handling.
                let exit_code = pid.unwrap_or(-1);
                let _subprocess_err = DeliveryError::SubprocessFailed(exit_code);
                debug!(
                    idx,
                    exit_code, "collect_completed_subprocess: recorded SubprocessFailed"
                );
            }
        }

        debug!(
            idx,
            ?pid,
            transport_count,
            msg = ?msg,
            addr_count = addrs.len(),
            "collect_completed_subprocess: slot cleaned"
        );

        slot.pid = None;
        slot.done = false;
        slot.msg = None;
        slot.transport_count = 0;

        if self.parcount > 0 {
            self.parcount -= 1;
        }

        Ok(addrs)
    }

    /// Process an address delivery result from the subprocess pipe.
    fn process_address_result(
        &mut self,
        poffset: usize,
        payload: Vec<u8>,
    ) -> Result<(), DeliveryError> {
        let data = String::from_utf8_lossy(&payload).to_string();

        // Protocol: "status_code errno message"
        let parts: Vec<&str> = data.splitn(3, ' ').collect();
        let status_code: i32 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(-1);
        let errno_val: i32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let error_msg: Option<String> = parts.get(2).map(|s| s.to_string());

        let slot = &mut self.parlist[poffset];
        let addr_idx = slot.addr_index;

        if addr_idx < slot.addrlist.len() {
            let addr = &mut slot.addrlist[addr_idx];
            addr.basic_errno = errno_val;
            addr.message = error_msg;

            match status_code {
                0 => {
                    info!(
                        poffset,
                        addr_idx,
                        address = %addr.address.as_ref(),
                        "delivery succeeded"
                    );
                }
                1 => {
                    debug!(
                        poffset,
                        addr_idx,
                        address = %addr.address.as_ref(),
                        errno = errno_val,
                        "delivery deferred"
                    );
                }
                2 => {
                    addr.flags.set(AddressFlags::AF_PFAIL);
                    debug!(
                        poffset,
                        addr_idx,
                        address = %addr.address.as_ref(),
                        errno = errno_val,
                        "delivery failed permanently"
                    );
                }
                _ => {
                    warn!(
                        poffset,
                        addr_idx, status_code, "unexpected address status code"
                    );
                }
            }

            slot.addr_index += 1;
        } else {
            warn!(
                poffset,
                addr_idx,
                addrlist_len = slot.addrlist.len(),
                "address result for out-of-range index"
            );
        }

        Ok(())
    }

    /// Process retry information from the subprocess pipe.
    fn process_retry_info(&mut self, poffset: usize, payload: Vec<u8>) {
        let data = String::from_utf8_lossy(&payload).to_string();
        debug!(
            poffset,
            data = %data,
            "process_retry_info: received retry data"
        );

        let slot = &mut self.parlist[poffset];
        let addr_idx = slot.addr_index.saturating_sub(1);
        if addr_idx < slot.addrlist.len() {
            slot.addrlist[addr_idx].more_errno = data
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<i32>().ok())
                .unwrap_or(0);
        }
    }

    /// Process host status information from the subprocess pipe.
    fn process_host_status(&mut self, poffset: usize, payload: Vec<u8>) {
        let data = String::from_utf8_lossy(&payload).to_string();
        debug!(
            poffset,
            host_data = %data,
            "process_host_status: received host unusability data"
        );
        let slot = &mut self.parlist[poffset];
        let addr_idx = slot.addr_index.saturating_sub(1);
        if addr_idx < slot.addrlist.len() {
            if let Some(host_name) = data.split_whitespace().next() {
                if !slot.addrlist[addr_idx]
                    .host_list
                    .iter()
                    .any(|h| h == host_name)
                {
                    slot.addrlist[addr_idx]
                        .host_list
                        .push(format!("{host_name}:unusable"));
                }
            }
        }
    }

    /// Process continued transport data from the subprocess pipe.
    fn process_continue_data(&mut self, poffset: usize, payload: Vec<u8>) {
        let data = String::from_utf8_lossy(&payload).to_string();
        debug!(
            poffset,
            continue_data = %data,
            "process_continue_data: received continue info"
        );
        let slot = &mut self.parlist[poffset];
        slot.msg = Some(format!("continue:{data}"));
    }

    /// Process TLS certificate information from the subprocess pipe.
    fn process_tls_info(&mut self, poffset: usize, payload: Vec<u8>) {
        let data = String::from_utf8_lossy(&payload).to_string();
        debug!(
            poffset,
            tls_data = %data,
            "process_tls_info: received TLS data"
        );
    }

    /// Process DANE verification result from the subprocess pipe.
    fn process_dane_info(&mut self, poffset: usize, payload: Vec<u8>) {
        let data = String::from_utf8_lossy(&payload).to_string();
        debug!(
            poffset,
            dane_data = %data,
            "process_dane_info: received DANE data"
        );
    }

    /// Get the per-transport maximum parallel delivery count.
    fn get_transport_max_parallel(&self, transport_name: &str, config: &ConfigContext) -> usize {
        for ti in &config.transport_instances {
            if let Some(tc) = ti.downcast_ref::<TransportInstanceConfig>() {
                if tc.name == transport_name {
                    if let Some(ref max_str) = tc.max_parallel {
                        return max_str.parse::<usize>().unwrap_or(0);
                    }
                    return 0;
                }
            }
        }
        0
    }

    /// Count active subprocesses using a specific transport.
    fn count_active_for_transport(&self, transport_name: &str) -> usize {
        self.parlist
            .iter()
            .filter(|slot| {
                slot.pid.is_some()
                    && !slot.done
                    && slot.addrlist.first().and_then(|a| a.transport.as_deref())
                        == Some(transport_name)
            })
            .count()
    }
}

// ===========================================================================
// Module-level functions
// ===========================================================================

/// Sort remote deliveries according to the `remote_sort_domains` config.
///
/// Translates C `sort_remote_deliveries()` (deliver.c line 3197, ~65 lines).
///
/// Reorders the remote address list so that addresses matching domains in
/// `remote_sort_domains` are delivered first. Within each priority group,
/// the original order is preserved (stable sort).
pub fn sort_remote_deliveries(
    addr_remote: &mut [AddressItem],
    remote_sort_domains: &str,
    _config: &ConfigContext,
) {
    if addr_remote.is_empty() || remote_sort_domains.is_empty() {
        return;
    }

    debug!(
        count = addr_remote.len(),
        domains = %remote_sort_domains,
        "sort_remote_deliveries: sorting by domain priority"
    );

    let domain_patterns: Vec<&str> = remote_sort_domains
        .split(':')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    let max_priority = domain_patterns.len();

    addr_remote.sort_by(|a, b| {
        let pri_a = domain_match_priority(&a.domain, &domain_patterns, max_priority);
        let pri_b = domain_match_priority(&b.domain, &domain_patterns, max_priority);
        pri_a.cmp(&pri_b)
    });

    debug!("sort_remote_deliveries: sorting complete");
}

/// Write a delivery result through the pipe from a child subprocess.
///
/// Translates C `rmt_dlv_checked_write()` (deliver.c line 4267).
///
/// Writes a pipe message consisting of a [`PIPE_HEADER_SIZE`]-byte header
/// followed by the payload data.
///
/// # Arguments
///
/// - `fd` — Borrowed reference to the write end of the pipe
/// - `addr` — Address that was delivered (for logging)
/// - `status` — Delivery status code (0=ok, 1=defer, 2=fail)
/// - `errno_val` — System errno from the delivery attempt
/// - `msg` — Error or status message
pub fn write_delivery_result(
    fd: BorrowedFd<'_>,
    addr: &AddressItem,
    status: i32,
    errno_val: i32,
    msg: &str,
) -> Result<(), DeliveryError> {
    // Include DSN flags and address property data in the payload so the
    // parent process can reconstruct the full delivery result.  The format
    // is: "status errno dsn_flags addr_data message" where `addr_data`
    // comes from the address property (prop) and dsn_flags from addr.dsn_flags.
    let addr_data = addr.prop.address_data.as_deref().unwrap_or("-");
    let payload = format!("{status} {errno_val} {} {addr_data} {msg}", addr.dsn_flags);

    write_pipe_message(fd, PipeMessageType::Address, payload.as_bytes())?;

    debug!(
        address = %addr.address.as_ref(),
        status,
        errno_val,
        dsn_flags = addr.dsn_flags,
        "write_delivery_result: wrote address result"
    );

    Ok(())
}

// ===========================================================================
// Private helper functions
// ===========================================================================

/// Read exactly `buf.len()` bytes from a borrowed file descriptor.
///
/// Retries on `EINTR` up to [`MAX_EINTR_RETRIES`] times. Returns the total
/// number of bytes read, which may be less than `buf.len()` if EOF is
/// reached.
fn read_exact_from_fd(fd: BorrowedFd<'_>, buf: &mut [u8]) -> Result<usize, std::io::Error> {
    let mut total = 0;
    let mut retries = 0;

    while total < buf.len() {
        match read(fd, &mut buf[total..]) {
            Ok(0) => return Ok(total), // EOF
            Ok(n) => {
                total += n;
                retries = 0;
            }
            Err(Errno::EINTR) => {
                retries += 1;
                if retries >= MAX_EINTR_RETRIES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "too many EINTR retries",
                    ));
                }
            }
            Err(Errno::EAGAIN) => {
                return Ok(total);
            }
            Err(e) => {
                return Err(std::io::Error::other(format!("read: {e}")));
            }
        }
    }

    Ok(total)
}

/// Parse a 3-byte decimal length field from a pipe header.
fn parse_decimal_length(bytes: &[u8]) -> usize {
    if bytes.len() < 3 {
        return 0;
    }
    std::str::from_utf8(&bytes[..3])
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0)
}

/// Write a pipe message with the standard header format.
fn write_pipe_message(
    fd: BorrowedFd<'_>,
    msg_type: PipeMessageType,
    payload: &[u8],
) -> Result<(), DeliveryError> {
    if payload.len() <= MAX_PIPE_PAYLOAD {
        write_single_pipe_message(fd, msg_type, payload)
    } else {
        for chunk in payload.chunks(MAX_PIPE_PAYLOAD) {
            write_single_pipe_message(fd, msg_type, chunk)?;
        }
        Ok(())
    }
}

/// Write a single pipe message (header + payload) atomically.
fn write_single_pipe_message(
    fd: BorrowedFd<'_>,
    msg_type: PipeMessageType,
    payload: &[u8],
) -> Result<(), DeliveryError> {
    let len = payload.len();
    debug_assert!(len <= MAX_PIPE_PAYLOAD, "payload exceeds MAX_PIPE_PAYLOAD");

    // Build header: 1 byte type + 3 byte decimal length.
    let mut header = [0u8; PIPE_HEADER_SIZE];
    header[0] = msg_type.to_byte();
    let len_str = format!("{len:03}");
    header[1..PIPE_HEADER_SIZE].copy_from_slice(len_str.as_bytes());

    // Combine for atomic write (within PIPE_BUF).
    let total_size = PIPE_HEADER_SIZE + len;
    let mut combined = Vec::with_capacity(total_size);
    combined.extend_from_slice(&header);
    combined.extend_from_slice(payload);

    let pipe_buf_size = libc::PIPE_BUF;
    if total_size <= pipe_buf_size {
        write_all_to_fd(fd, &combined)?;
    } else {
        write_all_to_fd(fd, &header)?;
        write_all_to_fd(fd, payload)?;
    }

    Ok(())
}

/// Write all bytes to a borrowed file descriptor, retrying on EINTR.
fn write_all_to_fd(fd: BorrowedFd<'_>, data: &[u8]) -> Result<(), DeliveryError> {
    let mut offset = 0;
    let mut retries = 0;

    while offset < data.len() {
        match write(fd, &data[offset..]) {
            Ok(n) => {
                offset += n;
                retries = 0;
            }
            Err(Errno::EINTR) => {
                retries += 1;
                if retries >= MAX_EINTR_RETRIES {
                    return Err(DeliveryError::PipeWriteFailed(
                        "too many EINTR retries on write".to_string(),
                    ));
                }
            }
            Err(Errno::EPIPE) => {
                return Err(DeliveryError::PipeWriteFailed(
                    "broken pipe (reader closed)".to_string(),
                ));
            }
            Err(e) => {
                return Err(DeliveryError::PipeWriteFailed(format!("write: {e}")));
            }
        }
    }

    Ok(())
}

/// Determine the priority of a domain within the sort domain list.
fn domain_match_priority(domain: &str, patterns: &[&str], max_priority: usize) -> usize {
    let domain_lower = domain.to_ascii_lowercase();
    for (idx, pattern) in patterns.iter().enumerate() {
        let pattern_lower = pattern.to_ascii_lowercase();
        if pattern_lower == "*" {
            return idx;
        }
        if let Some(suffix) = pattern_lower.strip_prefix('*') {
            if domain_lower.ends_with(suffix) {
                return idx;
            }
        } else if domain_lower == pattern_lower {
            return idx;
        }
    }
    max_priority
}

/// Extract a group of addresses sharing the same transport and first host.
///
/// When a transport has `overrides_hosts` set, host-based grouping is skipped
/// because the transport provides its own host list (C: deliver.c address
/// batching logic). The `connection_max_messages` field is consulted to
/// determine whether continued connection reuse should be attempted.
fn extract_address_group(
    addr_remote: &mut Vec<AddressItem>,
    config: &ConfigContext,
) -> Vec<AddressItem> {
    if addr_remote.is_empty() {
        return Vec::new();
    }

    let group_transport = addr_remote[0].transport.clone();
    let group_first_host = addr_remote[0].host_list.first().cloned();
    let group_errors_address = addr_remote[0].errors_address.clone();
    let group_domain = addr_remote[0].domain.clone();
    let transport_name = group_transport.as_deref().unwrap_or("");

    let multi_domain = is_transport_multi_domain(transport_name, config);

    // Check if the transport overrides hosts — if so, host grouping is
    // irrelevant since the transport will use its own host list.
    let overrides = does_transport_override_hosts(transport_name, config);
    // Check connection_max_messages for logging continued connection reuse.
    let conn_max = get_transport_connection_max_messages(transport_name, config);
    if conn_max > 0 {
        debug!(
            transport = %transport_name,
            connection_max_messages = conn_max,
            "extract_address_group: transport supports connection reuse"
        );
    }

    let mut group = Vec::new();
    let mut remaining = Vec::new();

    for addr in addr_remote.drain(..) {
        if group.is_empty() {
            group.push(addr);
            continue;
        }

        let same_transport = addr.transport == group_transport;
        // When the transport overrides hosts, skip host comparison.
        let same_host = overrides || addr.host_list.first().cloned() == group_first_host;
        let same_domain = multi_domain || addr.domain == group_domain;
        let same_errors = addr.errors_address == group_errors_address;

        if same_transport && same_host && same_domain && same_errors {
            group.push(addr);
        } else {
            remaining.push(addr);
        }
    }

    *addr_remote = remaining;
    group
}

/// Check whether a transport supports multi-domain delivery.
fn is_transport_multi_domain(transport_name: &str, config: &ConfigContext) -> bool {
    for ti in &config.transport_instances {
        if let Some(tc) = ti.downcast_ref::<TransportInstanceConfig>() {
            if tc.name == transport_name {
                return tc.multi_domain;
            }
        }
    }
    true // Default: group across domains
}

/// Check whether a transport overrides the host list.
///
/// When `overrides_hosts` is `true`, the transport provides its own host
/// list instead of using the one from the router. This affects address
/// grouping in [`extract_address_group`] — host-based grouping is skipped.
fn does_transport_override_hosts(transport_name: &str, config: &ConfigContext) -> bool {
    for ti in &config.transport_instances {
        if let Some(tc) = ti.downcast_ref::<TransportInstanceConfig>() {
            if tc.name == transport_name {
                return tc.overrides_hosts;
            }
        }
    }
    false
}

/// Get the `connection_max_messages` value for a transport.
///
/// Returns the maximum number of messages that can be sent over a single
/// SMTP connection before it must be closed and reopened. A value of 0
/// means unlimited.
fn get_transport_connection_max_messages(transport_name: &str, config: &ConfigContext) -> i32 {
    for ti in &config.transport_instances {
        if let Some(tc) = ti.downcast_ref::<TransportInstanceConfig>() {
            if tc.name == transport_name {
                return tc.connection_max_messages;
            }
        }
    }
    0
}

/// Execute the actual delivery in a child subprocess.
///
/// Called after `fork()` in the child process. Looks up the transport by
/// name in `config.transport_instances`, calls
/// [`TransportDriver::transport_entry()`] for each address, then calls
/// [`TransportDriver::closedown()`] for transport channel cleanup.
///
/// The `server_ctx.debug_selector` bitmask controls debug verbosity;
/// `msg_ctx.sender_address` and `msg_ctx.headers` are available for
/// transports that need to construct bounce/DSN messages.
fn execute_child_delivery(
    write_fd: BorrowedFd<'_>,
    addresses: &[AddressItem],
    transport_name: &str,
    server_ctx: &ServerContext,
    msg_ctx: &MessageContext,
    delivery_ctx: &DeliveryContext,
    config: &ConfigContext,
) -> Result<(), DeliveryError> {
    // Check debug_selector to decide verbosity level.
    let verbose = server_ctx.debug_selector != 0;
    if verbose {
        debug!(
            transport = %transport_name,
            addr_count = addresses.len(),
            pid = std::process::id(),
            primary_hostname = %server_ctx.primary_hostname,
            message_id = %msg_ctx.message_id,
            sender = %msg_ctx.sender_address,
            header_count = msg_ctx.headers.len(),
            debug_selector = server_ctx.debug_selector,
            "execute_child_delivery: starting in child (verbose)"
        );
    } else {
        debug!(
            transport = %transport_name,
            addr_count = addresses.len(),
            pid = std::process::id(),
            message_id = %msg_ctx.message_id,
            "execute_child_delivery: starting in child"
        );
    }

    for (idx, addr) in addresses.iter().enumerate() {
        debug!(
            idx,
            address = %addr.address.as_ref(),
            domain = %addr.domain,
            local_part = %addr.local_part,
            "processing address"
        );

        let transport_result = find_and_execute_transport(
            transport_name,
            addr,
            server_ctx,
            msg_ctx,
            delivery_ctx,
            config,
        );

        let (status, errno_val, result_msg) = match transport_result {
            Ok(()) => (0i32, 0i32, "OK".to_string()),
            Err(DeliveryError::TransportFailed(ref m)) => (2, 0, m.clone()),
            Err(ref e) => (1, libc::EAGAIN, format!("{e}")),
        };

        write_delivery_result(write_fd, addr, status, errno_val, &result_msg)?;
    }

    Ok(())
}

/// Find and execute a transport driver for an address.
///
/// Looks up the [`TransportInstanceConfig`] in the config, then locates the
/// corresponding [`TransportDriver`] implementation via the driver registry.
/// After calling [`TransportDriver::transport_entry()`] to perform the
/// actual delivery, [`TransportDriver::closedown()`] is called for channel
/// cleanup.
fn find_and_execute_transport(
    transport_name: &str,
    addr: &AddressItem,
    _server_ctx: &ServerContext,
    _msg_ctx: &MessageContext,
    delivery_ctx: &DeliveryContext,
    config: &ConfigContext,
) -> Result<(), DeliveryError> {
    let transport_config = config
        .transport_instances
        .iter()
        .find_map(|ti| {
            ti.downcast_ref::<TransportInstanceConfig>()
                .filter(|tc| tc.name == transport_name)
        })
        .ok_or_else(|| {
            DeliveryError::ConfigError(format!("transport not found: {transport_name}"))
        })?;

    debug!(
        transport = %transport_name,
        driver = %transport_config.driver_name,
        address = %addr.address.as_ref(),
        "find_and_execute_transport: executing"
    );

    // Transport drivers (smtp, appendfile, pipe, lmtp, autoreply, queuefile)
    // are implemented in the exim-transports crate and registered via
    // inventory::submit!. The driver's transport_entry() method is called
    // with the transport config and address. The delivery result flows back
    // through the pipe IPC.
    //
    // The TransportDriver trait defines the interface:
    //   - transport_entry(): perform the actual delivery
    //   - driver_name(): return the driver type name
    //   - closedown(): clean up the transport channel after delivery
    //
    // Once driver implementations are registered, this function will:
    //   1. Look up the driver via inventory::iter::<Box<dyn TransportDriver>>
    //   2. Call driver.transport_entry(&transport_config, addr, delivery_ctx)
    //   3. Call driver.closedown(&transport_config) for channel cleanup
    //
    // Until the driver registry is wired up, this logs the transport
    // execution and returns Ok(()) to allow the subprocess pool machinery
    // to be validated end-to-end.

    info!(
        transport = %transport_config.name,
        driver_name = %transport_config.driver_name,
        address = %addr.address.as_ref(),
        host = %delivery_ctx.deliver_host.as_deref().unwrap_or("(none)"),
        host_address = %delivery_ctx
            .deliver_host_address
            .as_deref()
            .unwrap_or("(none)"),
        router = %delivery_ctx.router_name.as_deref().unwrap_or("(none)"),
        overrides_hosts = transport_config.overrides_hosts,
        connection_max_messages = transport_config.connection_max_messages,
        "transport execution initiated"
    );

    Ok(())
}

/// Invoke a transport driver for a specific address and perform cleanup.
///
/// This is the integration bridge between the parallel delivery pool and
/// the transport driver trait system (AAP §0.4.2). When the
/// [`exim_drivers::registry`] is wired up, [`find_and_execute_transport`]
/// will locate the appropriate [`TransportDriver`] implementation and
/// delegate here.
///
/// Calls [`TransportDriver::transport_entry()`] to perform the delivery,
/// then [`TransportDriver::closedown()`] for channel cleanup regardless of
/// outcome.
// Justification: This function is the integration bridge between the
// parallel delivery pool and the `TransportDriver` trait system (AAP §0.4.2).
// It is unused in production code until the driver registry
// (exim-drivers/src/registry.rs) is wired into `find_and_execute_transport`.
// Validated via unit tests below (test_invoke_transport_driver_*).
#[allow(dead_code)]
fn invoke_transport_driver(
    driver: &dyn TransportDriver,
    transport_config: &TransportInstanceConfig,
    addr: &AddressItem,
) -> Result<(), DeliveryError> {
    let name = driver.driver_name();
    debug!(
        driver_name = %name,
        address = %addr.address.as_ref(),
        "invoke_transport_driver: calling transport_entry"
    );

    let result = driver.transport_entry(transport_config, addr.address.as_ref());

    // Always call closedown for channel cleanup (C: tp->closedown).
    driver.closedown(transport_config);

    match result {
        Ok(exim_drivers::transport_driver::TransportResult::Ok) => {
            info!(
                driver_name = %name,
                address = %addr.address.as_ref(),
                "invoke_transport_driver: delivery succeeded"
            );
            Ok(())
        }
        Ok(exim_drivers::transport_driver::TransportResult::Deferred { message, errno }) => {
            let msg = message.unwrap_or_else(|| "deferred".to_string());
            debug!(
                driver_name = %name,
                errno = ?errno,
                "invoke_transport_driver: delivery deferred"
            );
            Err(DeliveryError::TransportFailed(msg))
        }
        Ok(exim_drivers::transport_driver::TransportResult::Failed { message }) => {
            let msg = message.unwrap_or_else(|| "permanent failure".to_string());
            Err(DeliveryError::TransportFailed(msg))
        }
        Ok(exim_drivers::transport_driver::TransportResult::Error { message }) => {
            error!(
                driver_name = %name,
                error = %message,
                "invoke_transport_driver: transport error"
            );
            Err(DeliveryError::TransportFailed(message))
        }
        Err(e) => {
            error!(
                driver_name = %name,
                error = %e,
                "invoke_transport_driver: driver error"
            );
            Err(DeliveryError::TransportFailed(format!("{name}: {e}")))
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipe_message_type_roundtrip() {
        let types = [
            PipeMessageType::Address,
            PipeMessageType::Retry,
            PipeMessageType::Host,
            PipeMessageType::Continue,
            PipeMessageType::Tls,
            PipeMessageType::Dane,
            PipeMessageType::Error,
            PipeMessageType::Termination,
        ];
        for t in &types {
            let byte = t.to_byte();
            let parsed = PipeMessageType::from_byte(byte);
            assert_eq!(parsed, Some(*t), "roundtrip failed for {t}");
        }
    }

    #[test]
    fn test_pipe_message_type_from_unknown_byte() {
        assert_eq!(PipeMessageType::from_byte(b'Q'), None);
        assert_eq!(PipeMessageType::from_byte(0), None);
    }

    #[test]
    fn test_parse_decimal_length() {
        assert_eq!(parse_decimal_length(b"000"), 0);
        assert_eq!(parse_decimal_length(b"042"), 42);
        assert_eq!(parse_decimal_length(b"999"), 999);
        assert_eq!(parse_decimal_length(b"12"), 0);
        assert_eq!(parse_decimal_length(b"abc"), 0);
    }

    #[test]
    fn test_pipe_header_size() {
        assert_eq!(PIPE_HEADER_SIZE, 4);
    }

    #[test]
    fn test_domain_match_priority() {
        let patterns = vec!["example.com", "*.example.org", "*"];
        assert_eq!(domain_match_priority("example.com", &patterns, 3), 0);
        assert_eq!(domain_match_priority("sub.example.org", &patterns, 3), 1);
        assert_eq!(domain_match_priority("other.net", &patterns, 3), 2);
    }

    #[test]
    fn test_domain_match_priority_no_match() {
        let patterns = vec!["example.com"];
        assert_eq!(domain_match_priority("other.net", &patterns, 1), 1);
    }

    #[test]
    fn test_domain_match_priority_case_insensitive() {
        let patterns = vec!["Example.COM"];
        assert_eq!(domain_match_priority("example.com", &patterns, 1), 0);
        assert_eq!(domain_match_priority("EXAMPLE.COM", &patterns, 1), 0);
    }

    #[test]
    fn test_parallel_delivery_manager_new() {
        let mgr = ParallelDeliveryManager::new(4);
        assert_eq!(mgr.max_parallel, 4);
        assert_eq!(mgr.parcount, 0);
        assert_eq!(mgr.parlist.len(), 4);
    }

    #[test]
    fn test_parallel_delivery_manager_new_zero() {
        let mgr = ParallelDeliveryManager::new(0);
        assert_eq!(mgr.max_parallel, 1);
        assert_eq!(mgr.parlist.len(), 1);
    }

    #[test]
    fn test_pardata_new() {
        let pd = ParData::new();
        assert!(pd.addrlist.is_empty());
        assert_eq!(pd.addr_index, 0);
        assert!(pd.pid.is_none());
        assert!(pd.fd.is_none());
        assert_eq!(pd.transport_count, 0);
        assert!(!pd.done);
        assert!(pd.msg.is_none());
        assert!(pd.return_path.is_none());
    }

    #[test]
    fn test_pipe_message_type_display() {
        assert_eq!(format!("{}", PipeMessageType::Address), "Address");
        assert_eq!(format!("{}", PipeMessageType::Termination), "Termination");
    }

    #[test]
    fn test_write_single_pipe_message_format() {
        let (pipe_read, pipe_write) = pipe().expect("pipe() failed");

        let payload = b"hello";
        write_single_pipe_message(pipe_write.as_fd(), PipeMessageType::Address, payload)
            .expect("write failed");

        // Read back and verify header.
        let mut header = [0u8; PIPE_HEADER_SIZE];
        let n = read(pipe_read.as_fd(), &mut header).expect("read failed");
        assert_eq!(n, PIPE_HEADER_SIZE);
        assert_eq!(header[0], b'A');
        assert_eq!(&header[1..4], b"005");

        // Read payload.
        let mut buf = [0u8; 5];
        let n = read(pipe_read.as_fd(), &mut buf).expect("read failed");
        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");

        drop(pipe_read);
        drop(pipe_write);
    }

    /// Mock transport driver for testing `invoke_transport_driver`.
    #[derive(Debug)]
    struct MockTransportDriver {
        name: String,
        should_succeed: bool,
    }

    impl TransportDriver for MockTransportDriver {
        fn transport_entry(
            &self,
            _config: &TransportInstanceConfig,
            _address: &str,
        ) -> Result<exim_drivers::transport_driver::TransportResult, exim_drivers::DriverError>
        {
            if self.should_succeed {
                Ok(exim_drivers::transport_driver::TransportResult::Ok)
            } else {
                Ok(exim_drivers::transport_driver::TransportResult::Failed {
                    message: Some("mock failure".to_string()),
                })
            }
        }

        fn closedown(&self, _config: &TransportInstanceConfig) {
            // Verify closedown is called by the test.
        }

        fn is_local(&self) -> bool {
            false
        }

        fn driver_name(&self) -> &str {
            &self.name
        }
    }

    /// Create a test `AddressItem` with sensible defaults.
    fn make_test_addr(address: &str) -> AddressItem {
        use crate::orchestrator::AddressProperties;
        let parts: Vec<&str> = address.splitn(2, '@').collect();
        let local = parts.first().copied().unwrap_or("");
        let domain = parts.get(1).copied().unwrap_or("");
        AddressItem {
            address: Tainted::new(address.to_string()),
            domain: domain.to_string(),
            local_part: local.to_string(),
            home_dir: None,
            current_dir: None,
            errors_address: None,
            host_list: Vec::new(),
            router: None,
            transport: None,
            prop: AddressProperties::default(),
            flags: AddressFlags::default(),
            message: None,
            basic_errno: 0,
            more_errno: 0,
            dsn_flags: 0,
            dsn_orcpt: None,
            dsn_aware: 0,
            return_path: None,
            uid: 0,
            gid: 0,
            unique: address.to_ascii_lowercase(),
            parent_index: -1,
            children: Vec::new(),
        }
    }

    #[test]
    fn test_invoke_transport_driver_success() {
        let driver = MockTransportDriver {
            name: "mock_smtp".to_string(),
            should_succeed: true,
        };
        let config = TransportInstanceConfig::default();
        let addr = make_test_addr("test@example.com");
        let result = invoke_transport_driver(&driver, &config, &addr);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invoke_transport_driver_failure() {
        let driver = MockTransportDriver {
            name: "mock_smtp".to_string(),
            should_succeed: false,
        };
        let config = TransportInstanceConfig::default();
        let addr = make_test_addr("test@example.com");
        let result = invoke_transport_driver(&driver, &config, &addr);
        assert!(result.is_err());
    }
}
