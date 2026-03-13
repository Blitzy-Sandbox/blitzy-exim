// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later
//
// exim-expand/src/perl.rs — ${perl{subroutine}{arg1}{arg2}...} expansion item
//
// Implements embedded Perl interpreter integration for the Exim string expansion
// engine. This module is feature-gated behind the `perl` Cargo feature flag,
// replacing the C `#ifdef EXIM_PERL` / `#ifndef EXIM_PERL` conditional
// (expand.c lines 5377-5442).
//
// All Perl FFI operations are delegated to the `exim-ffi` crate — this file
// contains ZERO `unsafe` blocks (enforced by the crate-level `#![deny(unsafe_code)]`).
//
// Source context: expand.c lines 5371-5442 (EITEM_PERL handler)

//! `${perl{subroutine}{arg1}...{argN}}` expansion item — embedded Perl
//! integration via `exim-ffi`.
//!
//! This module provides the [`eval_perl`] function that evaluates Perl
//! subroutine calls within Exim's string expansion DSL.  It manages a
//! process-level singleton Perl interpreter that is lazily initialized on
//! first use and persists for the process lifetime.
//!
//! # Architecture
//!
//! ```text
//! ${perl{my_sub}{arg1}{arg2}}
//!     │
//!     ├── evaluator.rs (AST dispatch — eval_item_perl)
//!     │       │
//!     │       ▼
//!     ├── perl.rs (THIS FILE — argument validation, interpreter management)
//!     │       │
//!     │       ▼
//!     └── exim-ffi/src/perl.rs (FFI — raw libperl calls, unsafe code)
//! ```
//!
//! # Undef Detection
//!
//! The C implementation distinguishes between Perl subroutines returning
//! `undef` (forced failure) and empty string (success) via `!SvOK(ret)`
//! on the raw Perl stack.  The Rust FFI's `call_function` API uses
//! `Perl_eval_pv` which cannot make this distinction natively.  This module
//! installs a thin Perl wrapper function (`__exim_perl_call_wrapper`) that
//! detects undef and signals it via a sentinel byte prefix, preserving
//! exact behavioral parity with the C implementation.
//!
//! # Safety
//!
//! This module contains **zero `unsafe` blocks**.  All FFI interactions
//! are routed through the `exim-ffi` crate (the only crate permitted to
//! contain unsafe code per AAP §0.7.2).

// ── Standard library imports ────────────────────────────────────────────────
//
// std::cell::RefCell — interior mutability for the thread-local interpreter.
// std::sync::{LazyLock, Mutex} — thread-safe storage for shared Perl startup
//     code from the `perl_startup` configuration option.  PerlInterpreter
//     itself is !Send (wraps a raw C pointer), so it uses thread_local!
//     instead of Mutex.  The LazyLock+Mutex combination is used for the
//     startup code string which IS Send and needs cross-thread visibility
//     between the config parser and the expansion engine.
use std::cell::RefCell;
use std::sync::{LazyLock, Mutex};

// ── Internal crate imports ──────────────────────────────────────────────────
use crate::evaluator::Evaluator;
use crate::ExpandError;

// ── External crate imports (from exim-ffi, enabled by perl feature) ─────────
//
// PerlInterpreter — safe FFI wrapper around the embedded libperl interpreter.
//     Provides new(), startup(), add_code_block(), call_function() methods.
// PerlError — error type from Perl FFI operations.  Created via PerlError::new()
//     in the FFI layer when libperl reports failures.
use exim_ffi::perl::{PerlError, PerlInterpreter};

// ═══════════════════════════════════════════════════════════════════════════
//  Public Constants
// ═══════════════════════════════════════════════════════════════════════════

/// Maximum number of arguments to a Perl subroutine invoked via `${perl}`.
///
/// From expand.c line 5374: `#define EXIM_PERL_MAX_ARGS 8`.
///
/// The total number of brace-delimited sub-expressions read by the parser
/// is `EXIM_PERL_MAX_ARGS + 1` (function name + up to 8 arguments).
///
/// # Example
///
/// ```text
/// ${perl{my_sub}{arg1}{arg2}{arg3}{arg4}{arg5}{arg6}{arg7}{arg8}}
///        ^name   ^--- up to 8 arguments (EXIM_PERL_MAX_ARGS) ---^
/// ```
pub const EXIM_PERL_MAX_ARGS: usize = 8;

// ═══════════════════════════════════════════════════════════════════════════
//  Internal Constants
// ═══════════════════════════════════════════════════════════════════════════

/// Sentinel byte prefixed to defined return values by the internal Perl
/// wrapper function [`UNDEF_WRAPPER_CODE`].
///
/// When the target Perl subroutine returns a defined value (including empty
/// string), the wrapper prepends this byte to the result.  This allows
/// [`eval_perl`] to distinguish between "returned empty string" (success)
/// and "returned undef" (forced failure) — a distinction the C code makes
/// via `!SvOK(ret)` on the raw Perl stack but which cannot be detected
/// through the `Perl_eval_pv` API used by `exim-ffi`.
const DEFINED_PREFIX: u8 = 0x01;

/// Sentinel byte returned for `undef` by the internal Perl wrapper function.
///
/// When the target Perl subroutine returns `undef`, the wrapper returns
/// exactly this single byte.  [`eval_perl`] maps this to
/// [`ExpandError::ForcedFail`].
const UNDEF_MARKER: u8 = 0x00;

/// Perl code block installed at interpreter startup to detect `undef` returns.
///
/// This wrapper function is registered via [`PerlInterpreter::add_code_block`]
/// during lazy initialization.  It calls the target Perl subroutine and
/// returns a sentinel-prefixed result:
///
/// - `"\x01" . $result` — defined value (including empty string)
/// - `"\x00"` — `undef`
///
/// This enables exact behavioral parity with the C implementation which
/// uses `!SvOK(ret)` on the raw Perl stack (perl.c `call_perl_cat` function).
///
/// The wrapper uses `no strict 'refs'` to allow symbolic function name
/// dispatch, matching the C implementation's `perl_call_pv(name, G_SCALAR)`
/// which resolves function names at runtime.
const UNDEF_WRAPPER_CODE: &str = concat!(
    "sub __exim_perl_call_wrapper {\n",
    "    my $func = shift;\n",
    "    no strict 'refs';\n",
    "    my $r = &{$func}(@_);\n",
    "    return defined($r) ? \"\\x01\" . $r : \"\\x00\";\n",
    "}\n",
);

// ═══════════════════════════════════════════════════════════════════════════
//  Process-Level Shared State
// ═══════════════════════════════════════════════════════════════════════════

/// Shared Perl startup code from the `perl_startup` configuration option.
///
/// Protected by [`Mutex`] for thread-safe access from the configuration
/// parser and the expansion engine.  The [`LazyLock`] ensures the mutex
/// is created exactly once on first access.
///
/// Set by [`set_perl_startup`] during configuration parsing; read by
/// [`initialize_interpreter`] during lazy interpreter initialization.
///
/// In the C implementation, this corresponds to the global `opt_perl_startup`
/// variable set by `readconf.c` and consumed by `perl_startup()` in the
/// `misc_mod_table` dispatch (expand.c line 5405).
static PERL_STARTUP_CODE: LazyLock<Mutex<Option<String>>> = LazyLock::new(|| Mutex::new(None));

// Thread-local Perl interpreter singleton.
//
// `PerlInterpreter` is intentionally `!Send` and `!Sync` (it wraps a raw
// C pointer to the Perl interpreter which is not thread-safe).  This means
// it cannot be stored in a `Mutex<T>` (which requires `T: Send`).  Instead,
// we use thread-local storage, which is the correct pattern for Exim's
// fork-per-connection architecture where each child process is
// single-threaded.
//
// The interpreter is lazily initialized on the first `${perl}` expansion
// within each process (matching the C behavior where `perl_startup()` is
// called lazily at expand.c line 5405-5406) and persists for the entire
// process lifetime (matching the C behavior where the Perl interpreter is
// never destroyed during normal operation).
thread_local! {
    static PERL_INTERP: RefCell<Option<PerlInterpreter>> = const { RefCell::new(None) };
}

// ═══════════════════════════════════════════════════════════════════════════
//  Internal Result Type
// ═══════════════════════════════════════════════════════════════════════════

/// Result of a Perl subroutine call, distinguishing defined values from
/// `undef`.
///
/// The C implementation returns NULL yield for both `undef` and error cases,
/// using `expand_string_message` to distinguish them.  In Rust, we separate
/// the success/undef distinction from errors using this enum.
enum PerlCallResult {
    /// The Perl subroutine returned a defined value (possibly empty string).
    Success(String),

    /// The Perl subroutine returned `undef`, signaling forced failure.
    Undef,
}

// ═══════════════════════════════════════════════════════════════════════════
//  Public API
// ═══════════════════════════════════════════════════════════════════════════

/// Evaluate a `${perl{subroutine}{arg1}{arg2}...}` expansion item.
///
/// This is the main entry point called by the evaluator when processing
/// `${perl}` AST nodes.  It validates arguments, ensures the Perl
/// interpreter is running, calls the specified subroutine, and translates
/// the result into the expansion engine's error model.
///
/// # Arguments
///
/// * `args` — Expansion arguments where `args[0]` is the Perl subroutine
///   name (required) and `args[1..]` are the subroutine arguments (up to
///   [`EXIM_PERL_MAX_ARGS`]).
/// * `evaluator` — Mutable reference to the evaluator for:
///   - Checking `expand_forbid` flags (`RDO_PERL` — expand.c line 5388)
///   - Resetting `forced_fail` on success (expand.c line 5438)
///
/// # Returns
///
/// - `Ok(String)` — the string value returned by the Perl subroutine
///   (expand.c lines 5438-5439: `f.expand_string_forcedfail = FALSE;
///   yield = new_yield`)
/// - `Err(ExpandError::Failed { message })` — when:
///   - `RDO_PERL` is set: `"Perl calls are not permitted"` (expand.c
///     line 5390)
///   - Interpreter startup fails (expand.c line 5405-5406)
///   - The Perl subroutine `die`s with an error message (expand.c lines
///     5424-5428)
/// - `Err(ExpandError::ForcedFail)` — when the Perl subroutine returns
///   `undef` (expand.c lines 5425-5431)
///
/// # Store Management
///
/// The C code sets `resetok = FALSE` after a Perl call (expand.c line 5435
/// concept) to prevent `store_reset()` from freeing Perl's allocations.
/// In Rust, this is handled naturally by ownership semantics — the
/// `String` returned by `call_function()` is an owned allocation that
/// persists as long as needed.  No explicit store management is required.
///
/// # Source Context
///
/// Replaces the `EITEM_PERL` handler from `expand.c` lines 5376-5442.
pub fn eval_perl(args: &[String], evaluator: &mut Evaluator) -> Result<String, ExpandError> {
    // ── Step 1: Check expansion forbid (expand.c lines 5388-5392) ────────
    //
    // RDO_PERL is checked in the evaluator's expand_forbid bitmask.  When
    // set, Perl calls are not permitted in the current expansion context
    // (e.g., during address verification or in a restricted ACL context).
    if evaluator.expand_forbid & crate::RDO_PERL != 0 {
        return Err(ExpandError::Failed {
            message: "Perl calls are not permitted".into(),
        });
    }

    // ── Step 2: Validate arguments ───────────────────────────────────────
    //
    // args[0] is the subroutine name (required — C read_subs minimum = 1).
    // args[1..] are the subroutine arguments (up to EXIM_PERL_MAX_ARGS).
    if args.is_empty() {
        return Err(ExpandError::Failed {
            message: "missing Perl subroutine name in ${perl} expansion".into(),
        });
    }

    let sub_name = &args[0];
    let sub_args = &args[1..];

    if sub_name.is_empty() {
        return Err(ExpandError::Failed {
            message: "empty Perl subroutine name in ${perl} expansion".into(),
        });
    }

    // Enforce maximum argument count (expand.c line 5374: EXIM_PERL_MAX_ARGS)
    if sub_args.len() > EXIM_PERL_MAX_ARGS {
        return Err(ExpandError::Failed {
            message: format!(
                "too many arguments for ${{perl}} expansion (max {}, got {})",
                EXIM_PERL_MAX_ARGS,
                sub_args.len()
            ),
        });
    }

    tracing::debug!(
        subroutine = %sub_name,
        arg_count = sub_args.len(),
        "evaluating ${{perl}} expansion"
    );

    // ── Step 3: Initialize interpreter and call subroutine ───────────────
    let call_result = invoke_perl_subroutine(sub_name, sub_args)?;

    // ── Step 4: Process result (expand.c lines 5419-5440) ────────────────
    match call_result {
        PerlCallResult::Success(value) => {
            tracing::debug!(
                subroutine = %sub_name,
                result_len = value.len(),
                "Perl subroutine returned successfully"
            );
            // Yield succeeded — reset forced_fail just in case it was set
            // during a callback from Perl (expand.c line 5438:
            // f.expand_string_forcedfail = FALSE).
            evaluator.forced_fail = false;
            Ok(value)
        }
        PerlCallResult::Undef => {
            // Perl subroutine returned undef — forced failure.
            // expand.c lines 5425-5431:
            //   expand_string_message = string_sprintf(
            //     "Perl subroutine \"%s\" returned undef to force failure",
            //     sub_arg[0]);
            //   f.expand_string_forcedfail = TRUE;
            tracing::debug!(
                subroutine = %sub_name,
                "Perl subroutine returned undef to force failure"
            );
            Err(ExpandError::ForcedFail)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Crate-Internal API
// ═══════════════════════════════════════════════════════════════════════════

/// Register Perl startup code from the `perl_startup` configuration option.
///
/// Must be called by the configuration parser after reading the
/// `perl_startup` option and before any `${perl}` expansion is evaluated.
/// The code is stored in a process-global [`Mutex`]-protected slot and
/// used to initialize the Perl interpreter on its first use.
///
/// In the C implementation, this corresponds to setting the global variable
/// `opt_perl_startup` in `readconf.c`, which is consumed by
/// `perl_startup()` on first `${perl}` expansion (expand.c line 5405).
///
/// # Arguments
///
/// * `code` — Perl startup code string (e.g.,
///   `do '/etc/exim/perl_startup.pl'` or inline Perl subroutine
///   definitions).
// Justification: set_perl_startup is called by the config parser (exim-config
// crate) via the public crate API when processing the `perl_startup` config
// option.  The config parser implementation is in a separate crate that has not
// yet wired up calls to this function.
#[allow(dead_code)]
pub(crate) fn set_perl_startup(code: String) {
    match PERL_STARTUP_CODE.lock() {
        Ok(mut guard) => {
            let code_len = code.len();
            *guard = Some(code);
            tracing::debug!(code_len = code_len, "Perl startup code registered");
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                "failed to register Perl startup code: mutex poisoned"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Internal Functions
// ═══════════════════════════════════════════════════════════════════════════

/// Initialize the Perl interpreter with startup code and wrapper function.
///
/// Called lazily on the first `${perl}` expansion in a process.  Creates
/// the interpreter, evaluates the configured startup code (from the
/// `perl_startup` config option), and installs the undef-detection
/// wrapper function.
///
/// # Source Context
///
/// Replaces the `perl_startup(opt_perl_startup)` call at expand.c
/// line 5405.
fn initialize_interpreter() -> Result<PerlInterpreter, ExpandError> {
    tracing::debug!("initializing Perl interpreter on first ${{perl}} use");

    // ── Allocate and construct (perl.c lines 199-200) ────────────────────
    let mut interp = PerlInterpreter::new().map_err(|e| {
        let err_msg = format!("Perl interpreter allocation failed: {}", e.message());
        tracing::error!(error = %err_msg, "PerlInterpreter::new() failed");
        ExpandError::Failed { message: err_msg }
    })?;

    // ── Start interpreter with minimal arguments ─────────────────────────
    //
    // The "-e 0" is a no-op Perl program that initializes the interpreter
    // runtime (including DynaLoader for XS modules) without executing any
    // user code.  The actual startup code from the `perl_startup` config
    // option is loaded separately via add_code_block below.
    interp.startup(&["exim-perl", "-e", "0"]).map_err(|e| {
        let err_msg = format!("Perl interpreter startup failed: {}", e.message());
        tracing::error!(error = %err_msg, "PerlInterpreter::startup() failed");
        ExpandError::Failed { message: err_msg }
    })?;

    // ── Load user's startup code from config if available ────────────────
    //
    // This is the Rust equivalent of the C `perl_startup(opt_perl_startup)`
    // call which evaluates the perl_startup config option.  The startup
    // code typically defines the Perl subroutines that ${perl} will call.
    let startup_guard = PERL_STARTUP_CODE.lock().map_err(|e| {
        let err_msg = format!("Perl startup code mutex poisoned: {e}");
        tracing::error!(error = %err_msg);
        ExpandError::Failed { message: err_msg }
    })?;

    if let Some(ref code) = *startup_guard {
        tracing::debug!(
            code_len = code.len(),
            "loading Perl startup code from config"
        );
        interp.add_code_block(code).map_err(|e| {
            let err_msg = format!("Perl startup code evaluation failed: {}", e.message());
            tracing::error!(
                error = %err_msg,
                "add_code_block() failed for startup code"
            );
            ExpandError::Failed { message: err_msg }
        })?;
    }
    // Explicitly drop the guard before further initialization to release
    // the Mutex lock promptly.
    drop(startup_guard);

    // ── Install the undef-detection wrapper function ─────────────────────
    interp.add_code_block(UNDEF_WRAPPER_CODE).map_err(|e| {
        let err_msg = format!("Perl undef wrapper installation failed: {}", e.message());
        tracing::error!(
            error = %err_msg,
            "add_code_block() failed for undef wrapper"
        );
        ExpandError::Failed { message: err_msg }
    })?;

    tracing::debug!("Perl interpreter initialized successfully");
    Ok(interp)
}

/// Invoke a Perl subroutine via the thread-local interpreter singleton.
///
/// Ensures the interpreter is initialized (lazy init on first call), then
/// calls the subroutine through the undef-detection wrapper function and
/// parses the sentinel-prefixed result.
///
/// # Source Context
///
/// Replaces the `call_perl_cat()` invocation at expand.c lines 5412-5417.
fn invoke_perl_subroutine(
    sub_name: &str,
    sub_args: &[String],
) -> Result<PerlCallResult, ExpandError> {
    PERL_INTERP.with(|cell| {
        // Use try_borrow_mut to produce a clear error instead of panicking
        // if a recursive ${perl} call occurs (e.g., Perl callback triggers
        // another expansion that contains ${perl}).
        let mut interp_opt = cell.try_borrow_mut().map_err(|_| ExpandError::Failed {
            message: "Perl interpreter is already in use \
                      (recursive ${perl} call detected)"
                .into(),
        })?;

        // Lazy initialization on first use (expand.c line 5405-5406).
        if interp_opt.is_none() {
            *interp_opt = Some(initialize_interpreter()?);
        }

        let interp = interp_opt
            .as_mut()
            .expect("interpreter was just initialized above");

        // Build argument list for the wrapper function.
        // wrapper_args[0] = target subroutine name (passed as first arg)
        // wrapper_args[1..] = actual subroutine arguments
        // Total args limited to EXIM_PERL_MAX_ARGS + 1 (name + 8 args).
        let mut wrapper_args: Vec<&str> = Vec::with_capacity(sub_args.len() + 1);
        wrapper_args.push(sub_name);
        for arg in sub_args {
            wrapper_args.push(arg.as_str());
        }

        // Call through __exim_perl_call_wrapper to detect undef.
        // (expand.c lines 5412-5417: function table dispatch via PERL_CAT)
        match interp.call_function("__exim_perl_call_wrapper", &wrapper_args) {
            Ok(raw_result) => parse_wrapper_result(sub_name, &raw_result),
            Err(perl_err) => handle_perl_error(sub_name, &perl_err),
        }
    })
}

/// Parse the sentinel-prefixed result from the undef-detection wrapper.
///
/// The wrapper function `__exim_perl_call_wrapper` returns:
/// - `"\x01" + result` — defined value (success)
/// - `"\x00"` — undef (forced failure)
///
/// This parsing restores exact behavioral parity with the C
/// implementation's `!SvOK(ret)` check in `call_perl_cat()`.
fn parse_wrapper_result(sub_name: &str, raw_result: &str) -> Result<PerlCallResult, ExpandError> {
    let bytes = raw_result.as_bytes();

    match bytes.first() {
        Some(&DEFINED_PREFIX) => {
            // Defined value — extract the actual result after the sentinel.
            // The sentinel is a single byte, so the result starts at index 1.
            let value = String::from_utf8_lossy(&bytes[1..]).into_owned();
            Ok(PerlCallResult::Success(value))
        }
        Some(&UNDEF_MARKER) if bytes.len() == 1 => {
            // Undef return — forced failure.
            // Matches expand.c lines 5425-5431:
            //   "Perl subroutine %q returned undef to force failure"
            tracing::debug!(
                subroutine = %sub_name,
                "wrapper detected undef return from Perl subroutine"
            );
            Ok(PerlCallResult::Undef)
        }
        _ if bytes.is_empty() => {
            // Empty result from wrapper — should not happen with a properly
            // installed wrapper.  Log a diagnostic and treat as undef for
            // safety, as this most likely indicates the wrapper is missing
            // or was overridden.
            let diagnostic = PerlError::new("unexpected empty response from Perl wrapper function");
            tracing::error!(
                subroutine = %sub_name,
                error = %diagnostic,
                "Perl wrapper returned empty response, treating as undef"
            );
            Ok(PerlCallResult::Undef)
        }
        _ => {
            // Unexpected format — the wrapper may not be installed correctly,
            // or user code interfered with it.  Return the raw result as-is
            // to avoid silently dropping data.
            tracing::debug!(
                subroutine = %sub_name,
                raw_len = bytes.len(),
                "unexpected wrapper response format, returning raw result"
            );
            Ok(PerlCallResult::Success(raw_result.to_owned()))
        }
    }
}

/// Handle a [`PerlError`] from the FFI layer.
///
/// Maps the error to either a runtime error ([`ExpandError::Failed`]) or
/// a forced-failure signal ([`PerlCallResult::Undef`]) based on whether
/// the error message is empty.
///
/// # Source Context
///
/// Replaces expand.c lines 5419-5433:
/// - Non-empty `expand_string_message` → runtime error (lines 5424-5428)
/// - NULL `expand_string_message` → undef / forced failure (lines 5425-5431)
fn handle_perl_error(sub_name: &str, perl_err: &PerlError) -> Result<PerlCallResult, ExpandError> {
    let msg = perl_err.message();
    if msg.is_empty() {
        // No error message — likely an internal issue or unreported undef.
        // Map to undef/forced failure for safety, matching the C behavior
        // where NULL expand_string_message with NULL yield means the Perl
        // subroutine returned undef.
        tracing::debug!(
            subroutine = %sub_name,
            "Perl error with empty message, treating as forced failure"
        );
        Ok(PerlCallResult::Undef)
    } else {
        // Runtime error with a descriptive message from $@ (ERRSV).
        // This matches expand.c lines 5424-5428 where
        // expand_string_message is set to the Perl error string.
        tracing::error!(
            subroutine = %sub_name,
            error = %msg,
            "Perl subroutine runtime error"
        );
        Err(ExpandError::Failed {
            message: msg.to_string(),
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Unit Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_args_constant() {
        // Verify the constant matches the C definition (expand.c line 5374).
        assert_eq!(EXIM_PERL_MAX_ARGS, 8);
    }

    #[test]
    fn test_eval_perl_forbid() {
        // When RDO_PERL is set in expand_forbid, eval_perl should return
        // ExpandError::Failed with "Perl calls are not permitted".
        let mut eval = Evaluator::new_default();
        eval.expand_forbid |= crate::RDO_PERL;

        let args = vec!["test_sub".to_string()];
        let result = eval_perl(&args, &mut eval);

        assert!(result.is_err());
        match result {
            Err(ExpandError::Failed { ref message }) => {
                assert_eq!(message, "Perl calls are not permitted");
            }
            _ => panic!("expected ExpandError::Failed"),
        }
    }

    #[test]
    fn test_eval_perl_empty_args() {
        // Empty args should return an error about missing subroutine name.
        let mut eval = Evaluator::new_default();
        let args: Vec<String> = vec![];
        let result = eval_perl(&args, &mut eval);

        assert!(result.is_err());
        match result {
            Err(ExpandError::Failed { ref message }) => {
                assert!(message.contains("missing Perl subroutine name"));
            }
            _ => panic!("expected ExpandError::Failed"),
        }
    }

    #[test]
    fn test_eval_perl_empty_sub_name() {
        // Empty subroutine name should return an error.
        let mut eval = Evaluator::new_default();
        let args = vec!["".to_string()];
        let result = eval_perl(&args, &mut eval);

        assert!(result.is_err());
        match result {
            Err(ExpandError::Failed { ref message }) => {
                assert!(message.contains("empty Perl subroutine name"));
            }
            _ => panic!("expected ExpandError::Failed"),
        }
    }

    #[test]
    fn test_eval_perl_too_many_args() {
        // More than EXIM_PERL_MAX_ARGS subroutine arguments should fail.
        let mut eval = Evaluator::new_default();
        let mut args = vec!["test_sub".to_string()];
        for i in 0..=EXIM_PERL_MAX_ARGS {
            args.push(format!("arg{}", i));
        }

        let result = eval_perl(&args, &mut eval);
        assert!(result.is_err());
        match result {
            Err(ExpandError::Failed { ref message }) => {
                assert!(message.contains("too many arguments"));
            }
            _ => panic!("expected ExpandError::Failed"),
        }
    }

    #[test]
    fn test_parse_wrapper_result_defined() {
        // "\x01hello" should parse as Success("hello")
        let raw = "\x01hello";
        let result = parse_wrapper_result("test", raw).unwrap();
        match result {
            PerlCallResult::Success(val) => assert_eq!(val, "hello"),
            PerlCallResult::Undef => panic!("expected Success"),
        }
    }

    #[test]
    fn test_parse_wrapper_result_defined_empty() {
        // "\x01" should parse as Success("") — empty string is a valid defined value
        let raw = "\x01";
        let result = parse_wrapper_result("test", raw).unwrap();
        match result {
            PerlCallResult::Success(val) => assert_eq!(val, ""),
            PerlCallResult::Undef => panic!("expected Success"),
        }
    }

    #[test]
    fn test_parse_wrapper_result_undef() {
        // "\x00" should parse as Undef
        let raw = "\x00";
        let result = parse_wrapper_result("test", raw).unwrap();
        match result {
            PerlCallResult::Success(_) => panic!("expected Undef"),
            PerlCallResult::Undef => {} // correct
        }
    }

    #[test]
    fn test_parse_wrapper_result_empty() {
        // Empty string should be treated as Undef (wrapper malfunction)
        let raw = "";
        let result = parse_wrapper_result("test", raw).unwrap();
        match result {
            PerlCallResult::Success(_) => panic!("expected Undef"),
            PerlCallResult::Undef => {} // correct
        }
    }

    #[test]
    fn test_handle_perl_error_with_message() {
        let err = PerlError::new("syntax error at line 42");
        let result = handle_perl_error("my_sub", &err);
        assert!(result.is_err());
        match result {
            Err(ExpandError::Failed { ref message }) => {
                assert_eq!(message, "syntax error at line 42");
            }
            _ => panic!("expected ExpandError::Failed"),
        }
    }

    #[test]
    fn test_handle_perl_error_empty_message() {
        let err = PerlError::new("");
        let result = handle_perl_error("my_sub", &err);
        assert!(result.is_ok());
        match result.unwrap() {
            PerlCallResult::Undef => {} // correct — empty message maps to undef
            PerlCallResult::Success(_) => panic!("expected Undef"),
        }
    }

    #[test]
    fn test_perl_call_result_enum() {
        // Verify the PerlCallResult enum works correctly.
        let success = PerlCallResult::Success("hello".to_string());
        let undef = PerlCallResult::Undef;

        match success {
            PerlCallResult::Success(val) => assert_eq!(val, "hello"),
            PerlCallResult::Undef => panic!("expected Success"),
        }
        match undef {
            PerlCallResult::Success(_) => panic!("expected Undef"),
            PerlCallResult::Undef => {} // correct
        }
    }
}
