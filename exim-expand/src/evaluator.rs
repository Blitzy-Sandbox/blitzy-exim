// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Evaluator for the Exim expansion AST.
// This stub provides the `Evaluator` type re-exported by `lib.rs`.
// The full implementation will be provided by the assigned agent.

#![allow(dead_code)]

use crate::parser::AstNode;
use crate::{EsiFlags, ExpandError};

// ---------------------------------------------------------------------------
// Evaluator — walks the AST and produces the expanded string
// ---------------------------------------------------------------------------

/// Evaluator that walks an [`AstNode`] tree and produces the expanded
/// result string.
///
/// Carries mutable state that is accumulated during one expansion
/// session: the current expansion nesting level, the set of forbidden
/// operations (`expand_forbid` bitmask), whether a forced-failure was
/// triggered, whether a lookup deferred, the `expand_nstring` capture
/// array, and the most recent `lookup_value`.
///
/// These fields correspond to globals in the C implementation that were
/// modified during `expand_string_internal()`.
#[derive(Debug)]
pub struct Evaluator {
    /// Current expansion nesting depth (for debug indentation and
    /// recursion-limit enforcement).  Replaces the C static local
    /// `expand_level`.
    pub expand_level: u32,

    /// Bitmask of forbidden expansion operations.  Checked against
    /// `RDO_LOOKUP`, `RDO_RUN`, `RDO_DLFUNC`, `RDO_PERL` before
    /// executing the corresponding item.
    pub expand_forbid: u32,

    /// Set to `true` when a `${if …}` or item explicitly triggers a
    /// forced-failure via `fail`.
    pub forced_fail: bool,

    /// Set to `true` when a lookup deferred (temporary failure) during
    /// expansion.
    pub search_find_defer: bool,

    /// Numbered string captures from the most recent match operation.
    /// Index 0 is the overall match; 1–9 are sub-matches.
    pub expand_nstring: Vec<String>,

    /// The value returned by the most recent `${lookup …}` operation.
    pub lookup_value: Option<String>,
}

impl Default for Evaluator {
    fn default() -> Self {
        Self::new()
    }
}

impl Evaluator {
    /// Create a new evaluator with default (empty) state.
    pub fn new() -> Self {
        Self {
            expand_level: 0,
            expand_forbid: 0,
            forced_fail: false,
            search_find_defer: false,
            expand_nstring: Vec::new(),
            lookup_value: None,
        }
    }

    /// Evaluate an AST node and return the expanded string.
    ///
    /// This is the primary entry point used by the public API
    /// functions in `lib.rs`.  The `flags` parameter controls
    /// expansion behaviour (see [`EsiFlags`]).
    pub fn evaluate(&mut self, node: &AstNode, flags: EsiFlags) -> Result<String, ExpandError> {
        self.expand_level += 1;
        let result = self.eval_expr(node, flags);
        self.expand_level -= 1;
        result
    }

    /// Recursive expression evaluator — handles each [`AstNode`] variant.
    pub fn eval_expr(&mut self, node: &AstNode, flags: EsiFlags) -> Result<String, ExpandError> {
        match node {
            AstNode::Literal(s) => Ok(s.clone()),
            AstNode::Escape(c) => Ok(String::from(*c)),
            AstNode::Protected(s) => Ok(s.clone()),
            AstNode::Variable(ref var_ref) => {
                // Stub: variable lookup not yet implemented
                tracing::debug!(name = %var_ref, "variable lookup (stub)");
                Ok(String::new())
            }
            AstNode::HeaderRef {
                ref prefix,
                ref name,
            } => {
                tracing::debug!(name = %name, ?prefix, "header ref lookup (stub)");
                Ok(String::new())
            }
            AstNode::AclVariable(ref name) => {
                tracing::debug!(name = %name, "ACL variable lookup (stub)");
                Ok(String::new())
            }
            AstNode::AuthVariable(idx) => {
                tracing::debug!(idx = %idx, "auth variable lookup (stub)");
                Ok(String::new())
            }
            AstNode::Item {
                ref kind,
                ref args,
                ref yes_branch,
                ref no_branch,
            } => {
                let _ = (kind, args, yes_branch, no_branch, flags);
                // Stub: item evaluation not yet implemented
                Ok(String::new())
            }
            AstNode::Operator {
                ref kind,
                ref subject,
            } => {
                let value = self.eval_expr(subject, flags)?;
                let _ = (kind, &value);
                // Stub: operator application not yet implemented
                Ok(value)
            }
            AstNode::Conditional {
                ref condition,
                ref yes_branch,
                ref no_branch,
            } => {
                // Stub: evaluate condition node — for now treat
                // non-negated as true and negated as false.
                let cond_result = !condition.negated;
                if cond_result {
                    self.eval_expr(yes_branch, flags)
                } else if let Some(ref nb) = *no_branch {
                    self.eval_expr(nb, flags)
                } else {
                    Ok(String::new())
                }
            }
            AstNode::Sequence(nodes) => {
                let mut result = String::new();
                for child in nodes {
                    result.push_str(&self.eval_expr(child, flags)?);
                }
                Ok(result)
            }
        }
    }
}
