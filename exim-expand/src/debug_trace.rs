// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later

//! C-Exim–compatible box-drawing expansion debug trace output.
//!
//! When `-d+expand` is active, this module emits a tree-structured trace
//! to stderr showing every step of string expansion, using the same
//! Unicode (or ASCII, with `+noutf8`) box-drawing characters and
//! indentation rules as the C reference implementation.
//!
//! # Box-Drawing Characters
//!
//! The C reference uses Unicode box-drawing characters by default:
//!
//! | Purpose         | Unicode | ASCII (`+noutf8`) |
//! |-----------------|---------|-------------------|
//! | Branch/child    | `├──`   | `|--`             |
//! | Last child      | `╰──`  | `\--`             |
//! | Vertical pipe   | `│`    | `|`               |
//! | Horizontal rule | `───`  | `---`             |
//!
//! Each nesting level adds one leading space followed by the appropriate
//! connector.  The trace labels are:
//!
//! - `considering:` — input string about to be expanded
//! - `expanding:`   — alias for `considering:` at recursion entry
//! - `result:`      — final expanded output
//! - `expanded:`    — the original input that produced the result
//! - `failed:`      — expansion that raised an error
//! - `error:`       — the error message accompanying a failure
//!
//! All output goes to stderr via `eprintln!()` to match the C
//! implementation's `debug_printf()` behaviour.

// ── Box-drawing character sets ──────────────────────────────────────────

/// Unicode box-drawing prefix for a branch (non-last child).
const UTF8_BRANCH: &str = "├──";

/// Unicode box-drawing prefix for the last child.
const UTF8_LAST: &str = "╰──";

/// Unicode vertical pipe for continuation lines.
const _UTF8_PIPE: &str = "│";

/// ASCII fallback prefix for a branch (non-last child).
const ASCII_BRANCH: &str = "|--";

/// ASCII fallback prefix for the last child.
const ASCII_LAST: &str = "\\--";

/// ASCII vertical pipe for continuation lines.
const _ASCII_PIPE: &str = "|";

// ── Helper: build indentation string ────────────────────────────────────

/// Build the indentation prefix for a given nesting `depth`.
///
/// Each depth level contributes one space character.  The connector
/// glyph (`├──` or `|--`) is appended by the caller via the
/// `branch()` / `last()` helpers.
fn indent(depth: usize) -> String {
    " ".repeat(depth)
}

/// Select the "branch" (non-last) connector for the current mode.
fn branch(noutf8: bool) -> &'static str {
    if noutf8 {
        ASCII_BRANCH
    } else {
        UTF8_BRANCH
    }
}

/// Select the "last child" connector for the current mode.
fn last(noutf8: bool) -> &'static str {
    if noutf8 {
        ASCII_LAST
    } else {
        UTF8_LAST
    }
}

// ── Public trace functions ──────────────────────────────────────────────

/// Emit a `considering:` trace line.
///
/// Called at the entry of `expand_string_internal()` before any work is
/// done.  Prints the raw input string about to be expanded.
///
/// # Arguments
///
/// * `depth` — Current nesting depth (1-based; top-level call is depth 1).
/// * `string` — The input string being considered for expansion.
/// * `noutf8` — If `true`, use ASCII box-drawing characters.
pub fn trace_considering(depth: usize, string: &str, noutf8: bool) {
    eprintln!(
        "{}{} considering: {}",
        indent(depth),
        branch(noutf8),
        string,
    );
}

/// Emit a `result:` trace line.
///
/// Called when expansion completes successfully, showing the final
/// expanded value.
///
/// # Arguments
///
/// * `depth` — Current nesting depth.
/// * `result` — The expanded result string.
/// * `noutf8` — If `true`, use ASCII box-drawing characters.
pub fn trace_result(depth: usize, result: &str, noutf8: bool) {
    eprintln!("{}{} result: {}", indent(depth), last(noutf8), result,);
}

/// Emit an `expanded:` trace line.
///
/// Called after successful expansion to show the *original* input string
/// that was expanded, followed by a `result:` line showing the output.
///
/// # Arguments
///
/// * `depth` — Current nesting depth.
/// * `original` — The original input string that was expanded.
/// * `noutf8` — If `true`, use ASCII box-drawing characters.
pub fn trace_expanded(depth: usize, original: &str, noutf8: bool) {
    eprintln!(
        "{}{} expanding: {}",
        indent(depth),
        branch(noutf8),
        original,
    );
}

/// Emit a `failed:` trace line.
///
/// Called when expansion fails, showing the input string that caused
/// the failure.
///
/// # Arguments
///
/// * `depth` — Current nesting depth.
/// * `string` — The input string that failed to expand.
/// * `noutf8` — If `true`, use ASCII box-drawing characters.
pub fn trace_failed_expand(depth: usize, string: &str, noutf8: bool) {
    eprintln!(
        "{}{} failed to expand: {}",
        indent(depth),
        branch(noutf8),
        string,
    );
}

/// Emit an `error:` trace line.
///
/// Called after a failed expansion to show the error message.
///
/// # Arguments
///
/// * `depth` — Current nesting depth.
/// * `message` — The error message describing the failure.
/// * `noutf8` — If `true`, use ASCII box-drawing characters.
pub fn trace_error_message(depth: usize, message: &str, noutf8: bool) {
    eprintln!(
        "{}{} error message: {}",
        indent(depth),
        last(noutf8),
        message,
    );
}

/// Emit a `text:` trace line for literal text segments.
///
/// Called when the evaluator encounters a literal text node (no `$` or
/// `\` processing needed).
///
/// # Arguments
///
/// * `depth` — Current nesting depth.
/// * `text` — The literal text being passed through.
/// * `noutf8` — If `true`, use ASCII box-drawing characters.
pub fn trace_text(depth: usize, text: &str, noutf8: bool) {
    eprintln!("{}{} text: {}", indent(depth), branch(noutf8), text,);
}

/// Emit a trace line for backslash-escaped characters.
///
/// Called when the evaluator processes a `\n`, `\t`, `\\`, etc. escape
/// sequence in a literal segment.
///
/// # Arguments
///
/// * `depth` — Current nesting depth.
/// * `escaped` — The processed escape character(s).
/// * `noutf8` — If `true`, use ASCII box-drawing characters.
pub fn trace_backslashed(depth: usize, escaped: &str, noutf8: bool) {
    eprintln!(
        "{}{} backslashed: {}",
        indent(depth),
        branch(noutf8),
        escaped,
    );
}

/// Emit a trace line for `$$` protected-dollar segments.
///
/// Called when the evaluator processes a `$$` (literal `$`) in the
/// input string.
///
/// # Arguments
///
/// * `depth` — Current nesting depth.
/// * `text` — The protected text (typically `"$"`).
/// * `noutf8` — If `true`, use ASCII box-drawing characters.
pub fn trace_protected(depth: usize, text: &str, noutf8: bool) {
    eprintln!("{}{} protected: {}", indent(depth), branch(noutf8), text,);
}

/// Emit a `considering:` trace line for a mid-evaluation sub-expression.
///
/// Called when the evaluator descends into a sub-expression (e.g., a
/// `${variable}` reference) during evaluation.
///
/// # Arguments
///
/// * `depth` — Current nesting depth.
/// * `expr` — The sub-expression being considered.
/// * `noutf8` — If `true`, use ASCII box-drawing characters.
pub fn trace_mid_considering(depth: usize, expr: &str, noutf8: bool) {
    eprintln!("{}{} considering: {}", indent(depth), branch(noutf8), expr,);
}

/// Emit a `value:` trace line showing a resolved variable or sub-expression value.
///
/// # Arguments
///
/// * `depth` — Current nesting depth.
/// * `value` — The resolved value.
/// * `noutf8` — If `true`, use ASCII box-drawing characters.
pub fn trace_value(depth: usize, value: &str, noutf8: bool) {
    eprintln!("{}{} value: {}", indent(depth), last(noutf8), value,);
}

/// Emit a `variable:` trace line showing a variable name being looked up.
///
/// # Arguments
///
/// * `depth` — Current nesting depth.
/// * `name` — The variable name (e.g., `"local_part"`, `"domain"`).
/// * `noutf8` — If `true`, use ASCII box-drawing characters.
pub fn trace_var(depth: usize, name: &str, noutf8: bool) {
    eprintln!("{}{} variable: {}", indent(depth), branch(noutf8), name,);
}

/// Emit an item result trace line.
///
/// Called when an expansion item (e.g., `${lc:...}`, `${hash:...}`)
/// completes, showing the intermediate result.
///
/// # Arguments
///
/// * `depth` — Current nesting depth.
/// * `value` — The item result.
/// * `noutf8` — If `true`, use ASCII box-drawing characters.
pub fn trace_item_result(depth: usize, value: &str, noutf8: bool) {
    eprintln!("{}{} item result: {}", indent(depth), last(noutf8), value,);
}

/// Emit an operator result trace line.
///
/// Called when a string-transform operator (e.g., `${lc:...}`) produces
/// its output.
///
/// # Arguments
///
/// * `depth` — Current nesting depth.
/// * `value` — The operator output.
/// * `noutf8` — If `true`, use ASCII box-drawing characters.
pub fn trace_op_result(depth: usize, value: &str, noutf8: bool) {
    eprintln!("{}{} op result: {}", indent(depth), last(noutf8), value,);
}

/// Emit a condition name trace line.
///
/// Called at the entry of condition evaluation (`${if ...}`) to show
/// the condition keyword being tested.
///
/// # Arguments
///
/// * `depth` — Current nesting depth.
/// * `name` — The condition name (e.g., `"eq"`, `"match"`, `"def"`).
pub fn trace_cond_name(depth: usize, name: &str) {
    eprintln!("{}{} condition: {}", indent(depth), UTF8_BRANCH, name,);
}

/// Emit a condition result trace line.
///
/// Called after condition evaluation, showing whether the condition
/// resolved to `true` or `false`.
///
/// # Arguments
///
/// * `depth` — Current nesting depth.
/// * `result` — The string representation (`"true"` or `"false"`).
/// * `noutf8` — If `true`, use ASCII box-drawing characters.
pub fn trace_cond_result(depth: usize, result: &str, noutf8: bool) {
    eprintln!(
        "{}{} condition result: {}",
        indent(depth),
        branch(noutf8),
        result,
    );
}

/// Emit a `failure forced` trace line.
///
/// Called when `{fail}` is encountered in an `${if ...}` branch,
/// indicating the expansion was intentionally terminated.
///
/// # Arguments
///
/// * `depth` — Current nesting depth.
/// * `noutf8` — If `true`, use ASCII box-drawing characters.
pub fn trace_failure_forced(depth: usize, noutf8: bool) {
    eprintln!("{}{} failure was forced", indent(depth), branch(noutf8),);
}

// ── Unit tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_indent_zero() {
        assert_eq!(indent(0), "");
    }

    #[test]
    fn test_indent_three() {
        assert_eq!(indent(3), "   ");
    }

    #[test]
    fn test_branch_utf8() {
        assert_eq!(branch(false), "├──");
    }

    #[test]
    fn test_branch_ascii() {
        assert_eq!(branch(true), "|--");
    }

    #[test]
    fn test_last_utf8() {
        assert_eq!(last(false), "╰──");
    }

    #[test]
    fn test_last_ascii() {
        assert_eq!(last(true), "\\--");
    }

    /// Verify that all trace functions execute without panic.
    /// (Output goes to stderr and is not captured by default.)
    #[test]
    fn test_trace_functions_do_not_panic() {
        trace_considering(1, "${lc:HELLO}", false);
        trace_result(1, "hello", false);
        trace_expanded(2, "${uc:world}", true);
        trace_failed_expand(3, "${bad}", false);
        trace_error_message(3, "unknown variable", true);
        trace_text(1, "literal text", false);
        trace_backslashed(2, "\\n", true);
        trace_protected(1, "$", false);
        trace_mid_considering(2, "${domain}", true);
        trace_value(2, "example.com", false);
        trace_var(2, "domain", true);
        trace_item_result(1, "lowered", false);
        trace_op_result(1, "hashed", true);
        trace_cond_name(1, "eq");
        trace_cond_result(1, "true", false);
        trace_failure_forced(1, true);
    }
}
