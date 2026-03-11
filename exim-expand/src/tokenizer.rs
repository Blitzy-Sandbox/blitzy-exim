// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Tokenizer for the Exim `${…}` string-expansion DSL.
// This stub provides the `Token` type re-exported by `lib.rs`.
// The full implementation will be provided by the assigned agent.

#![allow(dead_code)]

use crate::ExpandError;

// ---------------------------------------------------------------------------
// Token — lexical atoms produced by the tokenizer
// ---------------------------------------------------------------------------

/// Lexical token emitted by the tokenizer during scanning of Exim
/// expansion strings.
///
/// Each variant corresponds to a syntactic element recognised by the
/// `${…}` DSL.  The full list is specified in the AAP schema for
/// `exim-expand/src/lib.rs` → `Token`.
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    /// A run of literal text containing no special characters.
    Literal(String),
    /// A `$` character that introduces a variable or item reference.
    Dollar,
    /// An opening brace `{`.
    OpenBrace,
    /// A closing brace `}`.
    CloseBrace,
    /// A colon `:` used as a separator in items and operators.
    Colon,
    /// A `\N`..`\N` escape-protected region marker.
    EscapeChar(char),
    /// A `\N`..`\N` region whose content is not expanded.
    ProtectedRegion(String),
    /// A backslash-escaped literal character (e.g. `\\`, `\$`).
    BackslashLiteral(char),
    /// An identifier such as a variable name.
    Identifier(String),
    /// A recognised expansion-item keyword (e.g. `lookup`, `if`, `map`).
    ItemKeyword(String),
    /// A recognised operator keyword (e.g. `lc`, `uc`, `md5`).
    OperatorKeyword(String),
    /// A recognised condition keyword (e.g. `match`, `eq`, `exists`).
    ConditionKeyword(String),
    /// A comma `,` used as a list separator.
    Comma,
    /// End-of-input sentinel.
    Eof,
}

// ---------------------------------------------------------------------------
// Span tracking
// ---------------------------------------------------------------------------

/// Byte-offset span within the source string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenSpan {
    /// Inclusive start offset.
    pub start: usize,
    /// Exclusive end offset.
    pub end: usize,
}

/// A token together with its source span.
#[derive(Debug, Clone, PartialEq)]
pub struct SpannedToken {
    /// The token value.
    pub token: Token,
    /// Byte span in the original input.
    pub span: TokenSpan,
}

// ---------------------------------------------------------------------------
// Tokenizer (stub — full impl by assigned agent)
// ---------------------------------------------------------------------------

/// Lexical scanner that converts an Exim expansion string into a stream
/// of [`Token`] values.
pub struct Tokenizer<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Tokenizer<'a> {
    /// Create a new tokenizer over `input`.
    pub fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    /// Consume the next token from the input.
    pub fn next_token(&mut self) -> Result<SpannedToken, ExpandError> {
        if self.pos >= self.input.len() {
            return Ok(SpannedToken {
                token: Token::Eof,
                span: TokenSpan {
                    start: self.pos,
                    end: self.pos,
                },
            });
        }
        // Stub: return a single literal covering the remaining input.
        let start = self.pos;
        let text = self.input[start..].to_string();
        self.pos = self.input.len();
        Ok(SpannedToken {
            token: Token::Literal(text),
            span: TokenSpan {
                start,
                end: self.pos,
            },
        })
    }

    /// Peek at the next token without consuming it.
    pub fn peek_token(&self) -> Result<Token, ExpandError> {
        let mut clone = Self {
            input: self.input,
            pos: self.pos,
        };
        Ok(clone.next_token()?.token)
    }
}
