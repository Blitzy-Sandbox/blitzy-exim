// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later
//
// `${dlfunc{filename}{function}{arg1}...{argN}}` expansion item handler.
//
// Implements dynamic shared-object loading and function invocation for the
// Exim string expansion engine.  Replaces the `EITEM_DLFUNC` handler from
// expand.c lines 7133-7222.
//
// This module is feature-gated behind the `dlfunc` Cargo feature flag,
// replacing the C `#ifdef EXPAND_DLFUNC` / `#ifndef EXPAND_DLFUNC`
// conditional compilation (expand.c lines 7138-7143).
//
// Per AAP §0.7.2, this module contains **zero** `unsafe` code.  All
// dynamic library operations (`dlopen`, `dlsym`, function pointer calls,
// `CStr::from_ptr`) are centralised in `exim-ffi/src/dlfunc.rs` which
// exposes safe wrapper functions consumed here.

use std::os::raw::c_int;

use crate::evaluator::Evaluator;
use crate::{ExpandError, RDO_DLFUNC};

// ═══════════════════════════════════════════════════════════════════════
//  Public constants
// ═══════════════════════════════════════════════════════════════════════

/// Maximum number of function arguments for `${dlfunc}`.
///
/// Matches the C definition `#define EXPAND_DLFUNC_MAX_ARGS 8` from
/// expand.c line 7135.  The total number of sub-expressions read by
/// `read_subs()` is `EXPAND_DLFUNC_MAX_ARGS + 2` (filename + function
/// name + up to 8 arguments).
pub const EXPAND_DLFUNC_MAX_ARGS: usize = 8;

// ── C Exim status code constants ────────────────────────────────────────
//
// These match the standard Exim status codes defined in `macros.h`/`exim.h`.
// They are the integer values returned by dynamically loaded functions via
// the `exim_dlfunc_t` calling convention.

/// Successful execution — result string is valid.
const C_STATUS_OK: c_int = 0;

/// Deferred — temporary failure, retry later.
const C_STATUS_DEFER: c_int = 1;

/// Failed — permanent failure.
const C_STATUS_FAIL: c_int = 2;

/// Forced failure — triggers `expand_string_forcedfail`.
/// In C: `FAIL_FORCED = FAIL | 0x100 = 258`.
const C_STATUS_FAIL_FORCED: c_int = 258;

// Note: ERROR in Exim is typically -1 or any value not matching the above.
// The `DlfuncStatus::from_c_int` catch-all arm handles ERROR and any
// other unexpected status code identically (expand.c line 7213–7215).

// ═══════════════════════════════════════════════════════════════════════
//  DlfuncStatus enum
// ═══════════════════════════════════════════════════════════════════════

/// Status codes returned by dynamically loaded Exim functions.
///
/// Maps the C `int` return value from `exim_dlfunc_t` to a type-safe
/// Rust enum.  The status values are defined in expand.c lines 7197-7222
/// and correspond to standard Exim status codes.
///
/// | Variant | C Value | Behaviour |
/// |---------|---------|-----------|
/// | [`Ok`](Self::Ok) | `OK` (0) | Success — result string appended to output |
/// | [`Defer`](Self::Defer) | `DEFER` (1) | Temporary failure — logged, expansion fails |
/// | [`Fail`](Self::Fail) | `FAIL` (2) | Permanent failure — expansion fails (no log) |
/// | [`FailForced`](Self::FailForced) | `FAIL_FORCED` (258) | Forced failure — sets forced_fail flag |
/// | [`Error`](Self::Error) | `ERROR` or other | Panic-level error — logged at LOG_MAIN\|LOG_PANIC |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DlfuncStatus {
    /// Function executed successfully.  The result string contains the
    /// expansion output to be appended to the yield buffer.
    Ok,

    /// Function returned DEFER — a temporary/transient failure.  The
    /// expansion fails and the error is logged at LOG_MAIN|LOG_PANIC
    /// level (matching C behaviour at expand.c line 7214).
    Defer,

    /// Function returned FAIL — a permanent failure.  The expansion
    /// fails but the error is **not** logged (matching C behaviour at
    /// expand.c line 7213: the `else if (status != FAIL)` check skips
    /// logging for plain FAIL).
    Fail,

    /// Function returned FAIL_FORCED — triggers the forced-failure
    /// flag (`f.expand_string_forcedfail = TRUE` at expand.c line 7212).
    /// This is a control-flow signal, not an error — callers may handle
    /// it differently from regular failures.
    FailForced,

    /// Function returned ERROR or an unexpected/unknown status code.
    /// This is logged at LOG_MAIN|LOG_PANIC level (expand.c line 7214)
    /// and treated as a panic-level error.
    Error,
}

impl DlfuncStatus {
    /// Convert a C integer status code to a [`DlfuncStatus`] variant.
    ///
    /// Maps standard Exim status codes (OK=0, DEFER=1, FAIL=2,
    /// FAIL_FORCED=258) to their corresponding enum variants.  Any
    /// unrecognised value maps to [`Error`](Self::Error), matching the
    /// C `else` branch at expand.c line 7213 which catches all values
    /// that are neither OK, FAIL, nor FAIL_FORCED.
    pub fn from_c_int(val: c_int) -> Self {
        match val {
            C_STATUS_OK => Self::Ok,
            C_STATUS_DEFER => Self::Defer,
            C_STATUS_FAIL => Self::Fail,
            C_STATUS_FAIL_FORCED => Self::FailForced,
            _ => Self::Error,
        }
    }
}

impl std::fmt::Display for DlfuncStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => write!(f, "OK"),
            Self::Defer => write!(f, "DEFER"),
            Self::Fail => write!(f, "FAIL"),
            Self::FailForced => write!(f, "FAIL_FORCED"),
            Self::Error => write!(f, "ERROR"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Main evaluation function
// ═══════════════════════════════════════════════════════════════════════

/// Evaluate a `${dlfunc{filename}{function}{arg1}...{argN}}` expansion.
///
/// Loads a shared object by filename, looks up a function symbol by name,
/// and calls it with the provided arguments.  The function return status
/// determines the expansion result:
///
/// - **OK** (0): The function's result string is returned as the expansion
///   output.
/// - **FAIL_FORCED** (258): Sets the evaluator's `forced_fail` flag and
///   returns [`ExpandError::ForcedFail`].
/// - **FAIL** (2): Returns [`ExpandError::Failed`] without logging.
/// - **DEFER** (1) / **ERROR** / other: Logs the error at panic level and
///   returns [`ExpandError::Failed`].
///
/// # Arguments
///
/// * `args` — Slice of evaluated sub-expression strings:
///   - `args[0]`: shared object filename (path to `.so` file)
///   - `args[1]`: function name (symbol to look up in the shared object)
///   - `args[2..]`: up to [`EXPAND_DLFUNC_MAX_ARGS`] function arguments
///
/// * `evaluator` — Mutable reference to the expansion evaluator, used for:
///   - Checking `expand_forbid` flags (`RDO_DLFUNC`)
///   - Setting `forced_fail` on `FAIL_FORCED` status
///
/// # Errors
///
/// Returns [`ExpandError::Failed`] when:
/// - `RDO_DLFUNC` is set in the evaluator's `expand_forbid` flags
/// - Argument count is invalid (< 2 or > `EXPAND_DLFUNC_MAX_ARGS` + 2)
/// - `dlopen()` fails (library not found or load error)
/// - `dlsym()` fails (symbol not found in library)
/// - The loaded function returns FAIL, DEFER, ERROR, or unknown status
///
/// Returns [`ExpandError::ForcedFail`] when the loaded function returns
/// `FAIL_FORCED` status.
///
/// # Safety
///
/// This function contains **zero** `unsafe` code.  All dynamic library
/// operations are delegated to the safe wrappers in `exim_ffi::dlfunc`,
/// which is the only crate in the workspace permitted to contain `unsafe`
/// code (per AAP §0.7.2).
///
/// # C Equivalent
///
/// Replaces the `EITEM_DLFUNC` case handler in `expand_string_internal()`
/// (expand.c lines 7143-7222).
pub fn eval_dlfunc(args: &[String], evaluator: &mut Evaluator) -> Result<String, ExpandError> {
    // ── Step 1: Check expansion-forbid flags ────────────────────────────
    // expand.c lines 7151-7156:
    //   if (expand_forbid & RDO_DLFUNC) {
    //     expand_string_message = "dynamically-loaded functions are not permitted";
    //     goto EXPAND_FAILED;
    //   }
    if evaluator.expand_forbid & RDO_DLFUNC != 0 {
        return Err(ExpandError::Failed {
            message: "dynamically-loaded functions are not permitted".to_string(),
        });
    }

    // ── Step 2: Validate argument count ─────────────────────────────────
    // expand.c lines 7158-7165:
    //   read_subs(argv, EXPAND_DLFUNC_MAX_ARGS + 2, 2, ...)
    // Minimum 2 (filename + function name), maximum EXPAND_DLFUNC_MAX_ARGS + 2.
    if args.len() < 2 {
        return Err(ExpandError::Failed {
            message: "\"${dlfunc\" requires at least a filename and function name".to_string(),
        });
    }
    if args.len() > EXPAND_DLFUNC_MAX_ARGS + 2 {
        return Err(ExpandError::Failed {
            message: format!(
                "too many arguments for ${{dlfunc}} ({}, maximum is {})",
                args.len() - 2,
                EXPAND_DLFUNC_MAX_ARGS,
            ),
        });
    }

    let filename = &args[0];
    let function_name = &args[1];
    let func_args = &args[2..];

    // ── Step 3: Load or retrieve the shared library from cache ──────────
    // expand.c lines 7170-7184:
    //   tree_search(dlobj_anchor, argv[0])  → if not found → dlopen → tree_insertnode
    //
    // Delegates to exim_ffi::dlfunc::load_library() which wraps dlopen()
    // in the only crate permitted to contain unsafe code (AAP §0.7.2).
    exim_ffi::dlfunc::load_library(filename).map_err(|e| {
        let msg = format!("dlopen \"{}\" failed: {}", filename, e);
        tracing::error!("{}", msg);
        ExpandError::Failed { message: msg }
    })?;

    // ── Step 4-5: Look up symbol, marshal args, and call the function ──
    // expand.c lines 7189-7207:
    //   func = (exim_dlfunc_t *)dlsym(t->data.ptr, CS argv[1])
    //   status = func(&result, argc - 2, &argv[2]);
    //
    // Delegates to exim_ffi::dlfunc::call_dlfunc() which wraps dlsym()
    // and the function pointer call in safe APIs.
    let func_arg_strings: Vec<String> = func_args.to_vec();
    let call_result = exim_ffi::dlfunc::call_dlfunc(filename, function_name, &func_arg_strings)
        .map_err(|e| {
            let msg = match &e {
                exim_ffi::dlfunc::DlfuncError::SymbolNotFound {
                    symbol,
                    path,
                    detail,
                } => format!("dlsym \"{}\" in \"{}\" failed: {}", symbol, path, detail),
                exim_ffi::dlfunc::DlfuncError::NullInFunctionName(name) => format!(
                    "dlsym \"{}\" in \"{}\" failed: function name contains null byte",
                    name, filename,
                ),
                exim_ffi::dlfunc::DlfuncError::NullInArgument(arg) => {
                    format!("dlfunc argument contains interior null byte: \"{}\"", arg)
                }
                other => format!("{}", other),
            };
            tracing::error!("{}", msg);
            ExpandError::Failed { message: msg }
        })?;

    let status_code = call_result.status_code;
    let result_string = call_result.result_string;
    let status = DlfuncStatus::from_c_int(status_code);

    // ── Step 6: Process status and return ───────────────────────────────
    // expand.c lines 7208-7222 — status dispatch.
    //
    // The C logic:
    //   if (status != OK) {
    //     expand_string_message = result ? result : "(no message)";
    //     if (status == FAIL_FORCED) f.expand_string_forcedfail = TRUE;
    //     else if (status != FAIL)
    //       log_write(0, LOG_MAIN|LOG_PANIC, "dlfunc{%s}{%s} failed (%d): %s",
    //                 argv[0], argv[1], status, expand_string_message);
    //     goto EXPAND_FAILED;
    //   }
    //   if (result) yield = string_cat(yield, result);
    match status {
        // OK: append result to yield (expand.c line 7219).
        DlfuncStatus::Ok => Ok(result_string),

        // FAIL_FORCED: set forced_fail flag (expand.c line 7211-7212).
        // The result message is preserved in the error for caller inspection
        // but the primary signal is the ForcedFail variant.
        DlfuncStatus::FailForced => {
            evaluator.forced_fail = true;
            Err(ExpandError::ForcedFail)
        }

        // FAIL: fail without logging (expand.c line 7213: the
        // `else if (status != FAIL)` check skips the log_write for FAIL).
        DlfuncStatus::Fail => {
            let message = if result_string.is_empty() {
                "(no message)".to_string()
            } else {
                result_string
            };
            Err(ExpandError::Failed { message })
        }

        // DEFER: temporary failure — logged at LOG_MAIN|LOG_PANIC level.
        // Falls through the `status != FAIL` check in C (expand.c line 7213).
        DlfuncStatus::Defer => {
            let message = if result_string.is_empty() {
                "(no message)".to_string()
            } else {
                result_string
            };
            // LOG_MAIN|LOG_PANIC equivalent — using warn! for DEFER
            // (a transient condition) to distinguish from permanent errors.
            tracing::warn!(
                "dlfunc{{{}}}{{{}}} failed ({}): {}",
                filename,
                function_name,
                status_code,
                message,
            );
            Err(ExpandError::Failed { message })
        }

        // ERROR or unknown status: panic-level error — logged at
        // LOG_MAIN|LOG_PANIC (expand.c lines 7214-7215).
        DlfuncStatus::Error => {
            let message = if result_string.is_empty() {
                "(no message)".to_string()
            } else {
                result_string
            };
            tracing::error!(
                "dlfunc{{{}}}{{{}}} failed ({}): {}",
                filename,
                function_name,
                status_code,
                message,
            );
            Err(ExpandError::Failed { message })
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Unit tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── DlfuncStatus tests ──────────────────────────────────────────────

    #[test]
    fn status_from_c_int_ok() {
        assert_eq!(DlfuncStatus::from_c_int(0), DlfuncStatus::Ok);
    }

    #[test]
    fn status_from_c_int_defer() {
        assert_eq!(DlfuncStatus::from_c_int(1), DlfuncStatus::Defer);
    }

    #[test]
    fn status_from_c_int_fail() {
        assert_eq!(DlfuncStatus::from_c_int(2), DlfuncStatus::Fail);
    }

    #[test]
    fn status_from_c_int_fail_forced() {
        assert_eq!(DlfuncStatus::from_c_int(258), DlfuncStatus::FailForced);
    }

    #[test]
    fn status_from_c_int_error_negative() {
        assert_eq!(DlfuncStatus::from_c_int(-1), DlfuncStatus::Error);
    }

    #[test]
    fn status_from_c_int_error_unknown() {
        assert_eq!(DlfuncStatus::from_c_int(99), DlfuncStatus::Error);
    }

    #[test]
    fn status_from_c_int_error_large() {
        assert_eq!(DlfuncStatus::from_c_int(i32::MAX), DlfuncStatus::Error);
    }

    #[test]
    fn status_display() {
        assert_eq!(DlfuncStatus::Ok.to_string(), "OK");
        assert_eq!(DlfuncStatus::Defer.to_string(), "DEFER");
        assert_eq!(DlfuncStatus::Fail.to_string(), "FAIL");
        assert_eq!(DlfuncStatus::FailForced.to_string(), "FAIL_FORCED");
        assert_eq!(DlfuncStatus::Error.to_string(), "ERROR");
    }

    // ── Constant tests ──────────────────────────────────────────────────

    #[test]
    fn max_args_is_eight() {
        assert_eq!(EXPAND_DLFUNC_MAX_ARGS, 8);
    }

    // ── eval_dlfunc argument validation tests ───────────────────────────

    #[test]
    fn eval_dlfunc_forbid_flag() {
        let mut eval = Evaluator::new_default();
        eval.expand_forbid |= RDO_DLFUNC;

        let args = vec!["libtest.so".to_string(), "test_fn".to_string()];
        let result = eval_dlfunc(&args, &mut eval);

        assert!(result.is_err());
        match result.unwrap_err() {
            ExpandError::Failed { message } => {
                assert_eq!(message, "dynamically-loaded functions are not permitted");
            }
            other => panic!("expected ExpandError::Failed, got {:?}", other),
        }
    }

    #[test]
    fn eval_dlfunc_too_few_args() {
        let mut eval = Evaluator::new_default();
        let args = vec!["libtest.so".to_string()];
        let result = eval_dlfunc(&args, &mut eval);

        assert!(result.is_err());
        match result.unwrap_err() {
            ExpandError::Failed { message } => {
                assert!(message.contains("requires at least"));
            }
            other => panic!("expected ExpandError::Failed, got {:?}", other),
        }
    }

    #[test]
    fn eval_dlfunc_too_few_args_empty() {
        let mut eval = Evaluator::new_default();
        let args: Vec<String> = vec![];
        let result = eval_dlfunc(&args, &mut eval);

        assert!(result.is_err());
        match result.unwrap_err() {
            ExpandError::Failed { message } => {
                assert!(message.contains("requires at least"));
            }
            other => panic!("expected ExpandError::Failed, got {:?}", other),
        }
    }

    #[test]
    fn eval_dlfunc_too_many_args() {
        let mut eval = Evaluator::new_default();
        // 2 required + 9 extra = 11, but max is 2 + 8 = 10
        let args: Vec<String> = (0..11).map(|i| format!("arg{}", i)).collect();
        let result = eval_dlfunc(&args, &mut eval);

        assert!(result.is_err());
        match result.unwrap_err() {
            ExpandError::Failed { message } => {
                assert!(message.contains("too many arguments"));
            }
            other => panic!("expected ExpandError::Failed, got {:?}", other),
        }
    }

    #[test]
    fn eval_dlfunc_max_args_accepted() {
        // Exactly EXPAND_DLFUNC_MAX_ARGS + 2 arguments should be accepted
        // (will fail at dlopen, but shouldn't fail at argument validation).
        let mut eval = Evaluator::new_default();
        let mut args: Vec<String> = vec!["libnonexistent.so".to_string(), "fn".to_string()];
        for i in 0..EXPAND_DLFUNC_MAX_ARGS {
            args.push(format!("arg{}", i));
        }
        assert_eq!(args.len(), EXPAND_DLFUNC_MAX_ARGS + 2);

        let result = eval_dlfunc(&args, &mut eval);
        // Should fail at dlopen, NOT at argument validation
        assert!(result.is_err());
        match result.unwrap_err() {
            ExpandError::Failed { message } => {
                assert!(
                    message.contains("dlopen"),
                    "expected dlopen error, got: {}",
                    message
                );
            }
            other => panic!("expected ExpandError::Failed (dlopen), got {:?}", other),
        }
    }

    #[test]
    fn eval_dlfunc_nonexistent_library() {
        let mut eval = Evaluator::new_default();
        let args = vec![
            "/nonexistent/path/libfoo.so".to_string(),
            "test_fn".to_string(),
        ];
        let result = eval_dlfunc(&args, &mut eval);

        assert!(result.is_err());
        match result.unwrap_err() {
            ExpandError::Failed { message } => {
                assert!(message.contains("dlopen"), "got: {}", message);
                assert!(message.contains("/nonexistent/path/libfoo.so"));
            }
            other => panic!("expected ExpandError::Failed, got {:?}", other),
        }
    }
}
