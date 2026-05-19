//! Safe wrappers for POSIX signal handling via `nix::sys::signal::sigaction`.
//!
//! This module centralises the `unsafe` boundary for signal handler
//! installation.  The `nix` crate exposes `sigaction()` as `unsafe` because
//! the caller must guarantee that every signal handler function is
//! **async-signal-safe** — a property the Rust type system cannot enforce.
//!
//! By placing this `unsafe` boundary in the `exim-ffi` crate — the **ONLY**
//! crate in the workspace permitted to contain `unsafe` code (AAP §0.7.2) —
//! `exim-core/src/signal.rs` becomes 100% safe Rust while still being able
//! to install custom signal handlers.
//!
//! # Async-Signal-Safety Contract
//!
//! The functions in this module accept `SigAction` values constructed by the
//! caller.  The caller MUST ensure that any `SigHandler::Handler(fn)` contained
//! in the `SigAction` is async-signal-safe:
//!
//! - **Permitted operations**: atomic stores, `write()` to a self-pipe fd,
//!   setting `sig_atomic_t`-equivalent flags.
//! - **Prohibited operations**: heap allocation, I/O, lock acquisition,
//!   calling non-reentrant library functions (including `tracing!` / `log!`).
//!
//! All signal handlers in `exim-core/src/signal.rs` satisfy this contract:
//! each performs a single `AtomicBool::store(true, Ordering::SeqCst)`.

use nix::sys::signal::{sigaction, SigAction, Signal};

/// Install a signal handler for the given signal.
///
/// This is a safe wrapper around [`nix::sys::signal::sigaction`].  The
/// `unsafe` boundary is contained entirely within this function.
///
/// # Arguments
///
/// * `signal` — The POSIX signal to install the handler for.
/// * `action` — The `SigAction` describing the handler function, flags, and
///   signal mask.
///
/// # Returns
///
/// The previous `SigAction` that was installed for `signal`, wrapped in
/// `nix::Result`.
///
/// # Caller Contract
///
/// The caller MUST guarantee that any handler function within `action` is
/// async-signal-safe (see module-level documentation).
pub fn install_signal_action(signal: Signal, action: &SigAction) -> nix::Result<SigAction> {
    // SAFETY: The caller guarantees that the signal handler function within
    // `action` is async-signal-safe. In practice, all Exim signal handlers
    // perform only a single AtomicBool::store() operation, which compiles to
    // a single atomic store instruction on all supported platforms (x86_64:
    // `mov` + `mfence`; aarch64: `stlr`). This satisfies POSIX.1-2017
    // §2.4.3 "Signal Actions" requirements.
    //
    // The nix crate's sigaction() is itself a thin wrapper around the libc
    // sigaction() system call with proper struct layout guarantees.
    unsafe { sigaction(signal, action) }
}

/// Install multiple signal handlers atomically (best-effort ordering).
///
/// Convenience function that installs a batch of `(Signal, SigAction)` pairs
/// in a single call, returning the first error encountered (if any).  All
/// installations up to the first error are applied.
///
/// # Caller Contract
///
/// Same as [`install_signal_action`] — all handlers must be async-signal-safe.
pub fn install_signal_actions(actions: &[(Signal, &SigAction)]) -> nix::Result<()> {
    for &(sig, action) in actions {
        install_signal_action(sig, action)?;
    }
    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::signal::{SaFlags, SigHandler, SigSet};
    use std::sync::atomic::{AtomicBool, Ordering};

    static TEST_FLAG: AtomicBool = AtomicBool::new(false);

    extern "C" fn test_handler(_sig: libc::c_int) {
        TEST_FLAG.store(true, Ordering::SeqCst);
    }

    #[test]
    fn test_install_signal_action_sigign() {
        // Install SIG_IGN for SIGUSR1 — this is always safe.
        let ignore_action = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());

        let prev = install_signal_action(Signal::SIGUSR1, &ignore_action);
        assert!(
            prev.is_ok(),
            "install_signal_action should succeed for SIG_IGN"
        );
    }

    #[test]
    fn test_install_signal_action_handler() {
        // Install a custom handler for SIGUSR2.
        let custom_action = SigAction::new(
            SigHandler::Handler(test_handler),
            SaFlags::empty(),
            SigSet::empty(),
        );

        let prev = install_signal_action(Signal::SIGUSR2, &custom_action);
        assert!(
            prev.is_ok(),
            "install_signal_action should succeed for custom handler"
        );

        // Restore default.
        let default_action = SigAction::new(SigHandler::SigDfl, SaFlags::empty(), SigSet::empty());
        let _ = install_signal_action(Signal::SIGUSR2, &default_action);
    }

    #[test]
    fn test_install_signal_actions_batch() {
        let ignore = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());
        let default_action = SigAction::new(SigHandler::SigDfl, SaFlags::empty(), SigSet::empty());

        let actions: Vec<(Signal, &SigAction)> =
            vec![(Signal::SIGUSR1, &ignore), (Signal::SIGUSR2, &ignore)];

        let result = install_signal_actions(&actions);
        assert!(result.is_ok(), "batch install should succeed");

        // Restore defaults.
        let _ = install_signal_action(Signal::SIGUSR1, &default_action);
        let _ = install_signal_action(Signal::SIGUSR2, &default_action);
    }
}
