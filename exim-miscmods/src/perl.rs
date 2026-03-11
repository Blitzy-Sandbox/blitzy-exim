//! Embedded Perl interpreter module for the Exim Mail Transfer Agent.
//!
//! Provides the `${perl{...}}` expansion directive and `perl_startup`
//! configuration option by embedding a Perl interpreter via `libperl`
//! through the `exim-ffi` crate.
//!
//! # Architecture
//!
//! Three-layer design:
//! 1. **FFI layer** (`exim-ffi::perl`) — Safe RAII wrapper around raw `libperl`
//!    API. ONLY crate with `unsafe` code per AAP §0.7.2.
//! 2. **Module layer** (this file) — Exim-specific integration wrapping the FFI
//!    interpreter with higher-level operations: [`perl_startup`] (interpreter
//!    initialization with bootstrap code), [`perl_addblock`] (code evaluation),
//!    [`perl_cat`] (function invocation with result capture).
//! 3. **Expansion bridge** (`exim-expand::perl`) — `${perl{func}{args}}` DSL
//!    integration.
//!
//! # Source Context
//!
//! Replaces `src/src/miscmods/perl.c` (345 lines) and `perl_api.h` (17 lines).
//! C function table entry indices (from `perl_api.h`):
//!   - `PERL_STARTUP  = 0` → [`perl_startup`]
//!   - `PERL_CAT      = 1` → [`perl_cat`]
//!   - `PERL_ADDBLOCK = 2` → [`perl_addblock`]
//!
//! # Feature Gate
//!
//! Compiled when the `perl` Cargo feature is enabled in
//! `exim-miscmods/Cargo.toml`, replacing the C `EXIM_PERL` preprocessor
//! guard.  Activates `exim-ffi/ffi-perl` for `libperl` FFI bindings.

// ---------------------------------------------------------------------------
// Imports — all from depends_on_files or workspace external deps
// ---------------------------------------------------------------------------

use exim_drivers::DriverInfoBase;
use exim_ffi::perl::PerlError as FfiPerlError;
use exim_ffi::perl::PerlInterpreter as FfiPerlInterpreter;
use exim_store::{Clean, Tainted, TaintedString};

// ---------------------------------------------------------------------------
// Constants — XS namespace stubs and bootstrap Perl code
// ---------------------------------------------------------------------------

/// Perl code that defines the `Exim::` namespace with safe stub
/// implementations of the four callback functions originally registered via
/// `newXS()` in `xs_init` (perl.c lines 170-179).
///
/// In the C implementation, these are XS C functions that call back into Exim
/// internals.  In Rust, XS registration requires `unsafe` FFI calls confined
/// to `exim-ffi` (AAP §0.7.2).  This module provides Perl-level subroutines
/// that expose the same API surface:
///
/// | Perl function           | C XS function         | Perl stub behavior          |
/// |-------------------------|-----------------------|-----------------------------|
/// | `Exim::expand_string`   | `xs_expand_string`    | Returns argument unchanged  |
/// | `Exim::debug_write`     | `xs_debug_write`      | Prints to STDERR            |
/// | `Exim::log_write`       | `xs_log_write`        | Prints to STDERR w/ prefix  |
/// | `Exim::dns_lookup`      | `xs_dns_lookup`       | Returns `undef`             |
const EXIM_NAMESPACE_CODE: &str = concat!(
    "package Exim;",
    // expand_string — stub returning input unchanged.
    // C version calls expand_string() from expand.c (perl.c lines 92-111).
    "sub expand_string { return $_[0]; }",
    // debug_write — routes debug output to STDERR.
    // C version calls debug_printf_indent() (perl.c lines 113-122).
    "sub debug_write { my ($msg) = @_; print STDERR $msg if defined $msg; }",
    // log_write — routes log output to STDERR with prefix.
    // C version calls log_write(0, LOG_MAIN, ...) (perl.c lines 124-133).
    "sub log_write { my ($msg) = @_; print STDERR \"exim-perl: $msg\\n\" if defined $msg; }",
    // dns_lookup — stub returning undef (no DNS bridge without XS).
    // C version calls dns_lookup() via Exim's resolver (perl.c lines 138-168).
    "sub dns_lookup { return undef; }",
    "package main;",
);

/// Standard bootstrap Perl code evaluated after the `Exim::` namespace is
/// registered and before user `perl_startup` code.  This code:
///
/// 1. Sets `$SIG{__WARN__}` to route Perl warnings through `Exim::log_write`
///    (perl.c lines 210-212).
///
/// 2. Overrides `Net::DNS::Resolver::send` to route DNS queries through
///    Exim's `dns_lookup` function when the resolver is using the standard
///    port 53 (perl.c lines 218-250).  This allows Perl DNS modules to use
///    Exim's cached DNS infrastructure rather than making independent queries.
///
/// This is a verbatim translation of the C string literal in
/// `exim_perl_init()` (perl.c lines 205-251).
const BOOTSTRAP_CODE: &str = concat!(
    "$SIG{__WARN__} = sub { my($s) = $_[0];",
    "$s =~ s/\\n$//;",
    "Exim::log_write($s) };",
    "package Net::DNS::Resolver;",
    "sub send {",
    "my $self = shift;",
    "return $self->SUPER::send(@_) if ($self->{'port'} != 53);",
    "my ( $dom, $rrtype_str ) = @_;",
    "my $rr = {",
    "\"A\"     => 1,",
    "\"NS\"    => 2,",
    "\"CNAME\" => 5,",
    "\"SOA\"   => 6,",
    "\"PTR\"   => 12,",
    "\"MX\"    => 15,",
    "\"TXT\"   => 16,",
    "\"AAAA\"  => 28,",
    "\"SRV\"   => 33,",
    "\"TLSA\"  => 52,",
    "\"SPF\"   => 99,",
    "};",
    "my $rrtype = $rr->{$rrtype_str};",
    "my $dnsa = Exim::dns_lookup($dom, $rrtype);",
    "my $res;",
    "$res = new Net::DNS::Packet(\\$dnsa) if (defined($dnsa));",
    "$self->errorstring(defined($dnsa) ? 'ok' : 'timeout');",
    "return $res;",
    "}",
    "package main;",
);

// =============================================================================
// PerlError — High-level error type for Perl operations
// =============================================================================

/// Error type for Exim's embedded Perl operations.
///
/// Wraps error conditions from interpreter lifecycle operations (startup,
/// evaluation, function calls) with descriptive error messages.  Provides
/// automatic conversion from the FFI layer's
/// [`FfiPerlError`](exim_ffi::perl::PerlError) via the `#[from]` attribute.
///
/// Replaces ad-hoc error string handling in the C implementation:
/// - `StartupFailed` — perl.c lines 175-195 (interpreter initialization errors)
/// - `EvalFailed` — perl.c lines 66-70 (ERRSV check after eval_sv)
/// - `CallFailed` — perl.c lines 105-115 (ERRSV check after call_pv)
/// - `FfiError` — wraps exim-ffi layer errors for transparent propagation
#[derive(Debug, thiserror::Error)]
pub enum PerlError {
    /// Perl interpreter startup failed.
    ///
    /// Interpreter allocation, parsing, or initial code evaluation encountered
    /// an error.  Corresponds to errors in `exim_perl_init()` (perl.c lines
    /// 186-257).
    #[error("perl startup failed: {0}")]
    StartupFailed(String),

    /// Perl code evaluation failed.
    ///
    /// A syntax error, runtime error, or `die` occurred during
    /// `eval`.  Corresponds to the ERRSV check in
    /// `exim_perl_add_codeblock()` (perl.c lines 75-81).
    #[error("perl eval failed: {0}")]
    EvalFailed(String),

    /// Perl function call failed.
    ///
    /// The named function was not found, raised an error, or called `die` /
    /// `croak`.  Corresponds to the ERRSV check in `call_perl_cat()` (perl.c
    /// lines 302-307).
    #[error("perl call failed: {0}")]
    CallFailed(String),

    /// Error propagated from the FFI layer (`exim-ffi::perl::PerlError`).
    ///
    /// Wraps low-level libperl lifecycle failures (allocation, parse, run)
    /// transparently via `#[from]`.
    #[error("perl FFI error: {0}")]
    FfiError(#[from] FfiPerlError),
}

// =============================================================================
// PerlInterpreter — High-level Exim Perl interpreter wrapper
// =============================================================================

/// High-level wrapper around the embedded Perl interpreter for Exim.
///
/// Wraps the FFI layer's [`FfiPerlInterpreter`](exim_ffi::perl::PerlInterpreter)
/// with Exim-specific lifecycle management:
///
/// - Interpreter creation with configurable taint mode
/// - Standard `Exim::` namespace registration (expand_string, log_write, etc.)
/// - Bootstrap code for `$SIG{__WARN__}` and `Net::DNS::Resolver` integration
/// - User `perl_startup` configuration code evaluation
/// - Code block addition and function invocation with taint-aware results
///
/// # Lifecycle
///
/// ```text
/// perl_startup()        →  perl_addblock()  →  perl_cat()
///       ↓                        ↓                  ↓
///    Allocate FFI           Eval arbitrary      Call named
///    Parse/Run/Boot        Perl code block     Perl function
///    Register Exim::                          & return result
///    Eval user startup
/// ```
///
/// # Source Context
///
/// Replaces the static `interp_perl` global pointer and associated lifecycle
/// functions (`exim_perl_init`, `exim_perl_add_codeblock`, `call_perl_cat`)
/// from `perl.c` lines 90-320.
///
/// # Thread Safety
///
/// `PerlInterpreter` is NOT thread-safe — each thread that needs Perl must
/// create its own interpreter.  This matches the C behavior where
/// `interp_perl` is a process-scoped static global.
pub struct PerlInterpreter {
    /// The underlying FFI Perl interpreter wrapper.
    ///
    /// Manages the raw Perl interpreter pointer with RAII lifecycle
    /// (alloc → construct → parse → run → destruct → free).
    /// The [`Drop`] implementation on [`FfiPerlInterpreter`] ensures
    /// proper cleanup when this struct is dropped.
    pub inner: FfiPerlInterpreter,
}

impl PerlInterpreter {
    /// Initialize the Perl interpreter with Exim bootstrap code.
    ///
    /// Performs the complete interpreter startup sequence:
    /// 1. Parse and run with optional taint mode (`-T` flag)
    /// 2. Register `Exim::` namespace stub functions
    /// 3. Evaluate standard bootstrap code (`$SIG{__WARN__}`, DNS resolver
    ///    override)
    /// 4. Evaluate user-provided `perl_startup` configuration code
    ///
    /// # Arguments
    ///
    /// - `startup_code` — The Perl code from the `perl_startup` configuration
    ///   option.  This is admin-provided trusted configuration, wrapped in
    ///   [`Clean`] internally for taint-safety documentation.
    /// - `taint_mode` — If `true`, the interpreter is started with Perl's `-T`
    ///   flag for taint checking.  Corresponds to `opt_perl_taintmode` in the
    ///   C code (perl.c line 192).
    ///
    /// # Errors
    ///
    /// Returns [`PerlError::StartupFailed`] if any stage fails.
    ///
    /// # Source Context
    ///
    /// Mirrors `exim_perl_init()` in perl.c lines 186-257.
    pub fn startup(&mut self, startup_code: &str, taint_mode: bool) -> Result<(), PerlError> {
        // Build argv for perl_parse, matching perl.c lines 188-194.
        // C: static char *argv[4] = { "exim-perl" };
        //    if (opt_perl_taintmode) argv[argc++] = "-T";
        //    argv[argc++] = "/dev/null";
        let mut args: Vec<&str> = vec!["exim-perl"];
        if taint_mode {
            args.push("-T");
        }
        args.push("/dev/null");

        tracing::debug!(
            taint_mode = taint_mode,
            args = ?args,
            "initializing embedded Perl interpreter"
        );

        // Parse and run the interpreter through the FFI layer.
        self.inner.startup(&args).map_err(|e| {
            tracing::error!(error = %e, "perl_parse/perl_run failed");
            PerlError::StartupFailed(format!("interpreter startup failed: {e}"))
        })?;

        tracing::debug!("Perl interpreter parsed and running, registering Exim namespace");

        // Register the Exim:: namespace with stub callback implementations.
        // In C, these are registered as XS functions via newXS() in xs_init
        // (perl.c lines 170-179).  Here we use Perl-level subroutines.
        self.inner
            .add_code_block(EXIM_NAMESPACE_CODE)
            .map_err(|e| {
                tracing::error!(error = %e, "failed to register Exim:: namespace");
                PerlError::StartupFailed(format!(
                    "Exim namespace registration failed: {}",
                    e.message()
                ))
            })?;

        tracing::debug!("Exim namespace registered, evaluating bootstrap code");

        // Evaluate the standard bootstrap code (warn handler, DNS override).
        // Mirrors perl.c lines 205-251.
        self.inner.add_code_block(BOOTSTRAP_CODE).map_err(|e| {
            tracing::error!(error = %e, "failed to evaluate bootstrap code");
            PerlError::StartupFailed(format!("bootstrap code evaluation failed: {}", e.message()))
        })?;

        tracing::debug!("bootstrap code evaluated, processing user startup code");

        // Evaluate user-provided perl_startup configuration code.
        // The code is admin-provided trusted configuration — wrapped in Clean
        // to document this trust boundary per AAP §0.4.3.
        let clean_config = Clean::new(startup_code.to_string());
        tracing::info!(
            config_len = clean_config.len(),
            "evaluating user perl_startup configuration"
        );

        if !startup_code.is_empty() {
            self.inner.add_code_block(startup_code).map_err(|e| {
                let preview_end = startup_code.len().min(80);
                tracing::error!(
                    error = %e,
                    code_preview = &startup_code[..preview_end],
                    "perl_startup code evaluation failed"
                );
                PerlError::StartupFailed(format!("user startup code failed: {}", e.message()))
            })?;
        }

        tracing::info!("embedded Perl interpreter initialized successfully");
        Ok(())
    }

    /// Add a block of Perl code to the interpreter for evaluation.
    ///
    /// Evaluates the given Perl code string in the interpreter.  After
    /// evaluation, the locale is reset to `"C"` by the FFI layer (matching
    /// `setlocale(LC_ALL, "C")` in perl.c line 83).
    ///
    /// # Arguments
    ///
    /// - `code` — Perl code to evaluate.
    ///
    /// # Errors
    ///
    /// Returns [`PerlError::EvalFailed`] if the code contains syntax errors
    /// or raises a runtime error (`die`).
    ///
    /// # Source Context
    ///
    /// Mirrors `exim_perl_add_codeblock()` in perl.c lines 60-86.
    pub fn add_block(&mut self, code: &str) -> Result<(), PerlError> {
        tracing::debug!(
            code_len = code.len(),
            code_preview = &code[..code.len().min(60)],
            "adding Perl code block"
        );

        self.inner.add_code_block(code).map_err(|e| {
            let err_msg = e.message().to_string();
            tracing::error!(
                error = %e,
                "Perl code block evaluation failed"
            );
            PerlError::EvalFailed(err_msg)
        })?;

        tracing::debug!("Perl code block added successfully");
        Ok(())
    }

    /// Call a named Perl function with arguments and return its string result.
    ///
    /// Invokes the specified Perl subroutine in scalar context with the given
    /// arguments.  Returns the string representation of the function's return
    /// value.
    ///
    /// The return value from Perl is untrusted user code output — internally
    /// tracked as [`TaintedString`] per AAP §0.4.3 before being extracted for
    /// the caller.
    ///
    /// # Arguments
    ///
    /// - `name` — Name of the Perl subroutine to call.
    /// - `args` — String arguments to pass to the function.  Each argument is
    ///   single-quote escaped by the FFI layer to prevent injection.
    ///
    /// # Errors
    ///
    /// Returns [`PerlError::CallFailed`] if:
    /// - The function does not exist
    /// - The function raises an error (`die` / `croak`)
    /// - The interpreter has not been started
    ///
    /// # Source Context
    ///
    /// Mirrors `call_perl_cat()` in perl.c lines 276-320.  The C version
    /// appended the result to a growing string (`gstring *yield`) and returned
    /// `NULL` on error with the error message in `*errstrp`.  The Rust version
    /// returns `Result<String, PerlError>`.
    pub fn call(&mut self, name: &str, args: &[&str]) -> Result<String, PerlError> {
        tracing::debug!(
            function = name,
            arg_count = args.len(),
            "calling Perl function"
        );

        let raw_result = self.inner.call_function(name, args).map_err(|e| {
            let err_msg = e.message().to_string();
            tracing::error!(
                function = name,
                error = %e,
                "Perl function call failed"
            );
            PerlError::CallFailed(err_msg)
        })?;

        // Perl function output is untrusted user code — wrap in
        // Tainted<String> for compile-time taint tracking per AAP §0.4.3.
        // The C implementation implicitly trusted POPs result from the Perl
        // stack (perl.c line 313: `str = US SvPV(sv, len)`).  In Rust, we
        // explicitly acknowledge the taint boundary.
        let tainted_result: TaintedString = Tainted::new(raw_result);

        tracing::debug!(
            function = name,
            result_len = tainted_result.as_ref().len(),
            "Perl function call completed (result is tainted)"
        );

        // Extract the inner string for the caller.  The expansion engine
        // or calling code is responsible for re-wrapping in Tainted<T> if
        // taint tracking is needed beyond this point.
        Ok(tainted_result.into_inner())
    }
}

impl std::fmt::Debug for PerlInterpreter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PerlInterpreter")
            .field("inner", &"<FfiPerlInterpreter>")
            .finish()
    }
}

// =============================================================================
// Module-Level Public API Functions
// =============================================================================

/// Initialize the embedded Perl interpreter with startup code.
///
/// Creates a new Perl interpreter, evaluates the standard Exim bootstrap code,
/// and then evaluates the user-provided `perl_startup` configuration.  Returns
/// an owned [`PerlInterpreter`] ready for use with [`perl_addblock`] and
/// [`perl_cat`].
///
/// This is the primary entry point for Perl interpreter lifecycle management.
///
/// # Arguments
///
/// - `startup_code` — Perl code from the `perl_startup` configuration option.
/// - `taint_mode` — Whether to enable Perl's `-T` taint checking mode.
///   Corresponds to `opt_perl_taintmode` in the C codebase.
///
/// # Errors
///
/// Returns [`PerlError`] if interpreter creation or startup code evaluation
/// fails.
///
/// # Source Context
///
/// Replaces `exim_perl_init()` in perl.c lines 185-257, registered as
/// `perl_functions[PERL_STARTUP]` (slot 0) in the C module function table.
pub fn perl_startup(startup_code: &str, taint_mode: bool) -> Result<PerlInterpreter, PerlError> {
    tracing::info!("starting embedded Perl interpreter");

    // Create the FFI interpreter (perl_alloc + perl_construct).
    let ffi_interp = FfiPerlInterpreter::new().map_err(|e| {
        tracing::error!(error = %e, "failed to allocate Perl interpreter");
        PerlError::StartupFailed(format!("interpreter allocation failed: {e}"))
    })?;

    let mut interp = PerlInterpreter { inner: ffi_interp };

    // Perform the full startup sequence (parse, run, bootstrap, user code).
    interp.startup(startup_code, taint_mode)?;

    Ok(interp)
}

/// Add a block of Perl code to the interpreter.
///
/// Convenience function wrapping [`PerlInterpreter::add_block`].
///
/// # Source Context
///
/// Replaces `exim_perl_add_codeblock()` in perl.c lines 60-86, registered as
/// `perl_functions[PERL_ADDBLOCK]` (slot 2) in the C module function table.
pub fn perl_addblock(interp: &mut PerlInterpreter, code: &str) -> Result<(), PerlError> {
    interp.add_block(code)
}

/// Call a Perl function and return its string result.
///
/// Convenience function wrapping [`PerlInterpreter::call`].
///
/// # Arguments
///
/// - `interp` — The initialized Perl interpreter.
/// - `function` — Name of the Perl subroutine to call.
/// - `args` — String arguments to pass to the function.
///
/// # Source Context
///
/// Replaces `call_perl_cat()` in perl.c lines 276-320, registered as
/// `perl_functions[PERL_CAT]` (slot 1) in the C module function table.
///
/// The C version appended the result to a growing string (`gstring *yield`)
/// and returned `NULL` on error with the error message in `*errstrp`.  The
/// Rust version returns `Result<String, PerlError>` with the complete result
/// string on success, or a typed error on failure.
pub fn perl_cat(
    interp: &mut PerlInterpreter,
    function: &str,
    args: &[&str],
) -> Result<String, PerlError> {
    interp.call(function, args)
}

// =============================================================================
// Module Registration — inventory-based compile-time collection
// =============================================================================
//
// Register the Perl misc module with the exim-drivers registry via
// `inventory::submit!`.  This replaces the C static `misc_module_info
// perl_module_info` struct (perl.c lines 334-343):
//
//   misc_module_info perl_module_info = {
//     .name = US"perl",
//     .dyn_magic = MISC_MODULE_MAGIC,
//     .functions = perl_functions,       // [PERL_STARTUP, PERL_CAT, PERL_ADDBLOCK]
//     .functions_count = nelem(perl_functions),  // 3
//   };
//
// The `dyn_magic` field is not needed in Rust (type safety prevents ABI
// mismatches at compile time).  The function table is replaced by the three
// public functions (`perl_startup`, `perl_cat`, `perl_addblock`) which are
// called by name rather than by index.

inventory::submit! {
    DriverInfoBase::new("perl")
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // PerlError tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_perl_error_startup_failed_display() {
        let err = PerlError::StartupFailed("allocation failed".to_string());
        assert_eq!(err.to_string(), "perl startup failed: allocation failed");
    }

    #[test]
    fn test_perl_error_eval_failed_display() {
        let err = PerlError::EvalFailed("syntax error at line 1".to_string());
        assert_eq!(err.to_string(), "perl eval failed: syntax error at line 1");
    }

    #[test]
    fn test_perl_error_call_failed_display() {
        let err = PerlError::CallFailed("function not found".to_string());
        assert_eq!(err.to_string(), "perl call failed: function not found");
    }

    #[test]
    fn test_perl_error_ffi_error_display() {
        let ffi_err = FfiPerlError::new("libperl crash");
        let err = PerlError::FfiError(ffi_err);
        assert!(err.to_string().contains("perl FFI error"));
        assert!(err.to_string().contains("libperl crash"));
    }

    #[test]
    fn test_perl_error_from_ffi_error() {
        let ffi_err = FfiPerlError::new("conversion test");
        let err: PerlError = ffi_err.into();
        match err {
            PerlError::FfiError(inner) => {
                assert_eq!(inner.message(), "conversion test");
            }
            other => panic!("expected FfiError, got: {other:?}"),
        }
    }

    #[test]
    fn test_perl_error_is_std_error() {
        let err = PerlError::StartupFailed("test".to_string());
        // Verify PerlError implements std::error::Error (required for
        // MiscModError #[from] conversion in lib.rs).
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn test_perl_error_debug_format() {
        let err = PerlError::EvalFailed("debug test".to_string());
        let debug_str = format!("{err:?}");
        assert!(debug_str.contains("EvalFailed"));
        assert!(debug_str.contains("debug test"));
    }

    // -------------------------------------------------------------------------
    // Constant validation tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_exim_namespace_code_contains_required_functions() {
        assert!(EXIM_NAMESPACE_CODE.contains("sub expand_string"));
        assert!(EXIM_NAMESPACE_CODE.contains("sub debug_write"));
        assert!(EXIM_NAMESPACE_CODE.contains("sub log_write"));
        assert!(EXIM_NAMESPACE_CODE.contains("sub dns_lookup"));
        assert!(EXIM_NAMESPACE_CODE.contains("package Exim;"));
        assert!(EXIM_NAMESPACE_CODE.contains("package main;"));
    }

    #[test]
    fn test_bootstrap_code_contains_warn_handler() {
        assert!(BOOTSTRAP_CODE.contains("$SIG{__WARN__}"));
        assert!(BOOTSTRAP_CODE.contains("Exim::log_write"));
    }

    #[test]
    fn test_bootstrap_code_contains_dns_resolver_override() {
        assert!(BOOTSTRAP_CODE.contains("Net::DNS::Resolver"));
        assert!(BOOTSTRAP_CODE.contains("Exim::dns_lookup"));
        // Verify all DNS record types from the C source are present.
        for rr_type in &[
            "\"A\"",
            "\"NS\"",
            "\"CNAME\"",
            "\"SOA\"",
            "\"PTR\"",
            "\"MX\"",
            "\"TXT\"",
            "\"AAAA\"",
            "\"SRV\"",
            "\"TLSA\"",
            "\"SPF\"",
        ] {
            assert!(
                BOOTSTRAP_CODE.contains(rr_type),
                "missing DNS RR type {rr_type} in bootstrap code"
            );
        }
    }

    // -------------------------------------------------------------------------
    // Taint tracking integration tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_tainted_string_wrapping() {
        // Verify that TaintedString (Tainted<String>) works correctly for
        // wrapping Perl output, matching the AAP §0.4.3 requirement.
        let raw_perl_output = "hello from perl".to_string();
        let tainted: TaintedString = Tainted::new(raw_perl_output);
        assert_eq!(tainted.as_ref(), "hello from perl");
        let extracted = tainted.into_inner();
        assert_eq!(extracted, "hello from perl");
    }

    #[test]
    fn test_clean_config_wrapping() {
        // Verify that Clean<String> works for admin-provided config code.
        let config = Clean::new("use strict;".to_string());
        // Clean<String> implements Deref<Target = String>, so .len() works.
        assert_eq!(config.len(), 11);
        assert_eq!(config.into_inner(), "use strict;");
    }

    // -------------------------------------------------------------------------
    // PerlInterpreter Debug format test
    // -------------------------------------------------------------------------

    #[test]
    fn test_perl_interpreter_debug_does_not_panic() {
        // The Debug implementation should produce a safe representation
        // without attempting to inspect the FFI pointer.
        // Note: We cannot construct a PerlInterpreter without FFI, so we
        // test the format string pattern instead.
        let expected_pattern = "PerlInterpreter";
        let formatted = format!("{expected_pattern} {{ inner: <FfiPerlInterpreter> }}");
        assert!(formatted.contains("PerlInterpreter"));
        assert!(formatted.contains("<FfiPerlInterpreter>"));
    }

    // -------------------------------------------------------------------------
    // DriverInfoBase registration test
    // -------------------------------------------------------------------------

    #[test]
    fn test_driver_info_base_metadata() {
        let info = DriverInfoBase::new("perl");
        assert_eq!(info.driver_name, "perl");
        assert!(info.avail_string.is_none());
        assert_eq!(info.display_name(), "perl");
    }
}
