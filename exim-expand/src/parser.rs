// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Parser for the Exim `${…}` string-expansion DSL.
// This stub provides the `AstNode` type re-exported by `lib.rs`.
// The full implementation will be provided by the assigned agent.

#![allow(dead_code)]

use crate::ExpandError;

// ---------------------------------------------------------------------------
// AstNode — abstract syntax tree nodes
// ---------------------------------------------------------------------------

/// AST node produced by the parser from a stream of [`crate::Token`] values.
///
/// Each variant maps to a syntactic construct in the Exim expansion
/// language.  The full list is specified in the AAP schema for
/// `exim-expand/src/lib.rs` → `AstNode`.
#[derive(Debug, Clone, PartialEq)]
pub enum AstNode {
    /// Literal text that requires no further expansion.
    Literal(String),
    /// An escape sequence such as `\n` or `\t`.
    Escape(char),
    /// A `\N`-protected region whose content is passed through unchanged.
    Protected(String),
    /// A simple variable reference such as `$local_part`.
    Variable(String),
    /// A header-field reference `$h_<name>:` or `$header_<name>:`.
    HeaderRef(String),
    /// An ACL variable reference `$acl_c0` … `$acl_c9` / `$acl_m0` … `$acl_m9`.
    AclVariable(String),
    /// An authenticator variable reference `$auth1` … `$auth3`.
    AuthVariable(String),
    /// An expansion item such as `${lookup …}`, `${if …}`, `${map …}`.
    Item {
        /// Item keyword, e.g. `"lookup"`, `"if"`, `"map"`.
        name: String,
        /// Arguments to the item.
        args: Vec<AstNode>,
    },
    /// An expansion operator such as `${lc:…}`, `${uc:…}`, `${md5:…}`.
    Operator {
        /// Operator keyword, e.g. `"lc"`, `"uc"`, `"md5"`.
        name: String,
        /// The operand to which the operator is applied.
        operand: Box<AstNode>,
    },
    /// A conditional `${if <cond>{<then>}{<else>}}`.
    Conditional {
        /// The condition expression.
        condition: Box<AstNode>,
        /// The "then" branch.
        then_branch: Box<AstNode>,
        /// The "else" branch (may be an empty `Literal`).
        else_branch: Box<AstNode>,
    },
    /// A sequence of adjacent AST nodes that are concatenated.
    Sequence(Vec<AstNode>),
}

// ---------------------------------------------------------------------------
// Parser (stub — full impl by assigned agent)
// ---------------------------------------------------------------------------

/// Recursive-descent parser that builds an [`AstNode`] tree from a
/// token stream produced by [`crate::tokenizer::Tokenizer`].
pub struct Parser<'a> {
    tokenizer: crate::tokenizer::Tokenizer<'a>,
}

impl<'a> Parser<'a> {
    /// Create a new parser that will tokenize and parse `input`.
    pub fn new(input: &'a str) -> Self {
        Self {
            tokenizer: crate::tokenizer::Tokenizer::new(input),
        }
    }

    /// Parse the entire input into an AST.
    pub fn parse(&mut self) -> Result<AstNode, ExpandError> {
        // Stub: produce a single Literal node.
        let token = self.tokenizer.next_token()?;
        match token.token {
            crate::tokenizer::Token::Literal(s) => Ok(AstNode::Literal(s)),
            crate::tokenizer::Token::Eof => Ok(AstNode::Literal(String::new())),
            _ => Ok(AstNode::Literal(String::new())),
        }
    }
}
