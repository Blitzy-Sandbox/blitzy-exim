//! Safe wrappers for POSIX process management.
//!
//! This module centralises the `unsafe` `fork()` call required for Exim's
//! fork-per-connection and fork-per-delivery delivery model.  The `nix` crate
//! correctly marks `fork()` as `unsafe` because forking in the presence of
//! multiple threads can lead to undefined behaviour (only the calling thread
//! survives the fork, leaving mutexes in inconsistent states).
//!
//! Exim's architecture is **single-threaded** with explicit `fork()` for
//! isolation: the daemon process forks a child for each SMTP connection, and
//! each connection process forks again for local delivery (to change uid/gid
//! in the child without affecting the parent).  The `tokio` runtime, when
//! present, is scoped exclusively to blocking lookup execution
//! (`block_on()`) and is **never** active when `fork()` is called.
//!
//! By placing this `unsafe` block in the `exim-ffi` crate — the **ONLY**
//! crate in the workspace permitted to contain `unsafe` code (AAP §0.7.2) —
//! all consumer crates (`exim-deliver`, `exim-core`, etc.) remain 100% safe
//! Rust.
//!
//! # Caller Contract
//!
//! Every function in this module documents the preconditions that the caller
//! must uphold.  The critical invariant is that **no other threads are running**
//! at the time of the `fork()` call.

use nix::unistd::ForkResult;

/// Fork the current process, returning the fork result.
///
/// This is a safe wrapper around `nix::unistd::fork()` (which is `unsafe`).
///
/// # Preconditions (caller must guarantee)
///
/// 1. **No other threads are running** in the process at the time of the call.
///    In Exim's single-threaded fork-per-connection model, this invariant holds
///    because the daemon and delivery processes never spawn long-lived threads.
///    The `tokio` runtime (used only for lookup `block_on()`) is either not
///    started or fully shut down before any `fork()`.
///
/// 2. The caller is prepared to handle both `ForkResult::Parent { child }` and
///    `ForkResult::Child` cases.  The child process must not return to the
///    caller's event loop — it must perform its work and `std::process::exit()`.
///
/// # Returns
///
/// - `Ok(ForkResult::Parent { child })` — in the parent, with the child's PID.
/// - `Ok(ForkResult::Child)` — in the child process.
/// - `Err(nix::errno::Errno)` — if the fork system call fails (e.g., ENOMEM).
///
/// # Usage
///
/// ```ignore
/// use exim_ffi::process::fork_process;
/// use nix::unistd::ForkResult;
///
/// match fork_process()? {
///     ForkResult::Parent { child } => {
///         // Parent: wait for child
///     }
///     ForkResult::Child => {
///         // Child: do work, then exit
///         std::process::exit(0);
///     }
/// }
/// ```
pub fn fork_process() -> nix::Result<ForkResult> {
    // SAFETY: Exim's process model is single-threaded at the point of fork.
    // The daemon forks once per SMTP connection; each connection process may
    // fork again for local delivery (uid/gid isolation).  No threads are
    // running because:
    //   - The main daemon loop is synchronous (poll-based, not threaded)
    //   - The tokio runtime (for async lookups) uses block_on() which runs
    //     on the current thread and completes before fork
    //   - No background threads are spawned by the Exim process model
    // This matches the C Exim behaviour where fork() is called freely in the
    // same single-threaded context (daemon.c, deliver.c, child.c).
    unsafe { nix::unistd::fork() }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::ForkResult;

    #[test]
    fn test_fork_and_exit() {
        // Fork a child that immediately exits with code 42
        match fork_process().expect("fork failed") {
            ForkResult::Parent { child } => {
                let status = waitpid(child, None).expect("waitpid failed");
                match status {
                    WaitStatus::Exited(_, code) => assert_eq!(code, 42),
                    other => panic!("unexpected wait status: {:?}", other),
                }
            }
            ForkResult::Child => {
                std::process::exit(42);
            }
        }
    }
}
