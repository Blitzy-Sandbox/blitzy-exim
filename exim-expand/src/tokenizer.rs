// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later
//
// exim-expand/src/tokenizer.rs — Lexical Analysis of ${…} Expressions
//
// This module implements the first phase of the tokenizer → parser →
// evaluator pipeline: lexical analysis of Exim expansion strings.
//
// # Architecture
//
// The original C code (`expand.c`, 9,210 lines) has no separate tokenizer;
// character-level processing is inline within the 3,960-line
// `expand_string_internal()` function (lines 4771-8730).  This module
// extracts that logic into a clean, reusable lexical scanner that
// produces a stream of typed [`Token`] values for the parser to consume.
//
// # Source Mapping
//
// | Rust Component          | C Source (expand.c)                   |
// |-------------------------|---------------------------------------|
// | `next_token()` dispatch | Lines 4800-4810 main character loop   |
// | Backslash handling      | Lines 4815-4858 + `string_interpret_escape()` |
// | Dollar handling         | Lines 4860-4992                       |
// | `ITEM_KEYWORDS`         | Lines 109-142 `item_table[]`          |
// | `OP_UNDERSCORE_KEYWORDS`| Lines 184-197 `op_table_underscore[]` |
// | `OP_MAIN_KEYWORDS`      | Lines 214-262 `op_table_main[]`       |
// | `COND_KEYWORDS`         | Lines 318-368 `cond_table[]`          |
// | `read_identifier()`     | Lines 1115-1127 `read_name()`         |
// | `classify_identifier()` | Lines 959-974 `chop_match()`          |
//
// # Safety
//
// This module contains **zero `unsafe` blocks** (enforced by the crate-level
// `#![deny(unsafe_code)]` attribute in `lib.rs`).

use crate::ExpandError;
use exim_store::Clean;

// ═══════════════════════════════════════════════════════════════════════
//  Keyword tables — sorted for binary search (matching C `chop_match()`)
// ═══════════════════════════════════════════════════════════════════════
//
// These tables are direct translations of the C `item_table[]`,
// `op_table_underscore[]`, `op_table_main[]`, and `cond_table[]` arrays
// from expand.c.  Each array MUST remain in strict alphabetical order
// for the binary-search lookup in `keyword_lookup()` to work correctly.

/// Expansion item keywords from expand.c lines 109-142 (`item_table[]`).
///
/// These are the recognized names after `${` that trigger item-style
/// expansion with brace-delimited arguments: `${item{arg1}{arg2}…}`.
///
/// Feature-gated items (`imapfolder`, `srs_encode`) are always present
/// in the table — the Cargo feature flag controls whether the *evaluator*
/// can execute them, not whether the tokenizer recognizes them.  This
/// matches the C approach where the table is compiled with all names and
/// the `#ifdef` guard is only on the handler code.
const ITEM_KEYWORDS: &[&str] = &[
    "acl",
    "authresults",
    "certextract",
    "dlfunc",
    "env",
    "extract",
    "filter",
    "hash",
    "hmac",
    "if",
    "imapfolder",
    "length",
    "listextract",
    "listquote",
    "lookup",
    "map",
    "nhash",
    "perl",
    "prvs",
    "prvscheck",
    "readfile",
    "readsocket",
    "reduce",
    "run",
    "sg",
    "sort",
    "srs_encode",
    "substr",
    "tr",
];

/// Operator keywords with underscores from expand.c lines 184-197
/// (`op_table_underscore[]`).
///
/// These operators use underscores in their names and are matched in the
/// `${op:subject}` form.  They are searched AFTER `item_table` when
/// classifying identifiers inside `${…}`.
const OP_UNDERSCORE_KEYWORDS: &[&str] = &[
    "from_utf8",
    "listnamed_a",
    "listnamed_d",
    "listnamed_h",
    "listnamed_l",
    "local_part",
    "mask_n",
    "quote_local_part",
    "reverse_ip",
    "time_eval",
    "time_interval",
    "utf8_domain_from_alabel",
    "utf8_domain_to_alabel",
    "utf8_localpart_from_alabel",
    "utf8_localpart_to_alabel",
];

/// Main operator keywords from expand.c lines 214-262
/// (`op_table_main[]`).
///
/// These are single-word operators used in the `${op:subject}` form.
/// They are searched after `op_table_underscore` during classification.
const OP_MAIN_KEYWORDS: &[&str] = &[
    "address",
    "addresses",
    "base32",
    "base32d",
    "base62",
    "base62d",
    "base64",
    "base64d",
    "domain",
    "escape",
    "escape8bit",
    "eval",
    "eval10",
    "expand",
    "h",
    "hash",
    "headerwrap",
    "hex2b64",
    "hexquote",
    "ipv6denorm",
    "ipv6norm",
    "l",
    "lc",
    "length",
    "listcount",
    "listnamed",
    "mask",
    "md5",
    "nh",
    "nhash",
    "quote",
    "randint",
    "rfc2047",
    "rfc2047d",
    "rxquote",
    "s",
    "sha1",
    "sha2",
    "sha256",
    "sha3",
    "stat",
    "str2b64",
    "strlen",
    "substr",
    "uc",
    "utf8clean",
    "xtextd",
];

/// Condition keywords from expand.c lines 318-368 (`cond_table[]`).
///
/// These are used within `${if <cond>{…}{…}}` constructs.  Only
/// alphabetic condition names are included here; comparison operators
/// (`<`, `<=`, `=`, `==`, `>`, `>=`) are handled by the parser as
/// structural tokens, not as identifiers.
const COND_KEYWORDS: &[&str] = &[
    "acl",
    "and",
    "bool",
    "bool_lax",
    "crypteq",
    "def",
    "eq",
    "eqi",
    "exists",
    "first_delivery",
    "forall",
    "forall_json",
    "forall_jsons",
    "forany",
    "forany_json",
    "forany_jsons",
    "ge",
    "gei",
    "gt",
    "gti",
    "inbound_srs",
    "inlist",
    "inlisti",
    "isip",
    "isip4",
    "isip6",
    "ldapauth",
    "le",
    "lei",
    "lt",
    "lti",
    "match",
    "match_address",
    "match_domain",
    "match_ip",
    "match_local_part",
    "or",
    "pam",
    "queue_running",
    "radius",
    "saslauthd",
];

/// Header variable prefixes recognized by the tokenizer.
///
/// In Exim, `$h_<name>:`, `$header_<name>:`, `$rh_<name>:`, etc. are
/// header references where the name can contain any printable character
/// except `:` and `}`.  The tokenizer recognizes these prefixes and
/// reads the extended header name using [`Tokenizer::read_header_name()`].
///
/// Corresponds to expand.c lines 4906-4910.
pub const HEADER_PREFIXES: &[(&str, &str)] = &[
    ("bh_", "bh_"),
    ("bheader_", "bheader_"),
    ("h_", "h_"),
    ("header_", "header_"),
    ("lh_", "lh_"),
    ("lheader_", "lheader_"),
    ("rh_", "rh_"),
    ("rheader_", "rheader_"),
];

// ═══════════════════════════════════════════════════════════════════════
//  Token — lexical atoms produced by the tokenizer
// ═══════════════════════════════════════════════════════════════════════

/// Lexical token emitted by the tokenizer during scanning of Exim
/// expansion strings.
///
/// Each variant corresponds to a syntactic element recognised by the
/// `${…}` DSL.  The tokenizer produces tokens ONLY — it does not
/// evaluate or resolve variables (AAP §0.4.2: tokenizer phase 1 of 3).
///
/// # Variant Mapping
///
/// | Variant | Exim Syntax | C Source |
/// |---------|------------|----------|
/// | `Literal` | plain text | expand.c 4858-4869 |
/// | `Dollar` | `$` | expand.c 4871+ |
/// | `OpenBrace` | `{` | expand.c 4860, 4994 |
/// | `CloseBrace` | `}` | expand.c 4856 |
/// | `Colon` | `:` | operator form `${op:subject}` |
/// | `EscapeChar` | `\n`, `\t`, `\xHH` | `string_interpret_escape()` |
/// | `ProtectedRegion` | `\N…\N` | expand.c 4828-4838 |
/// | `BackslashLiteral` | `\X` (unknown) | default in escape handler |
/// | `Identifier` | variable name | expand.c `read_name()` |
/// | `ItemKeyword` | `lookup`, `if`, etc. | expand.c `item_table[]` |
/// | `OperatorKeyword` | `lc`, `md5`, etc. | expand.c `op_table_*[]` |
/// | `ConditionKeyword` | `eq`, `match`, etc. | expand.c `cond_table[]` |
/// | `Comma` | `,` | option separator |
/// | `Eof` | end of input | sentinel |
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

    /// A colon `:` used as a separator in operators (`${op:subject}`).
    Colon,

    /// A standard backslash escape producing a mapped character.
    ///
    /// Recognised sequences: `\n` (newline), `\t` (tab), `\r` (CR),
    /// `\b` (backspace), `\f` (form feed), `\v` (vertical tab),
    /// `\\` (literal backslash), `\0NNN` (octal), `\xHH` (hex).
    EscapeChar(char),

    /// Content of a `\N…\N` protected region copied verbatim.
    ProtectedRegion(String),

    /// A backslash followed by an unrecognised character — the backslash
    /// is consumed and the character is kept as-is.
    BackslashLiteral(char),

    /// An identifier name: sequence of ASCII letters, digits, and
    /// underscores.
    Identifier(String),

    /// A recognised expansion-item keyword (e.g. `lookup`, `if`, `map`).
    ItemKeyword(String),

    /// A recognised operator keyword (e.g. `lc`, `uc`, `md5`).
    OperatorKeyword(String),

    /// A parametric operator keyword with embedded numeric arguments.
    ///
    /// C Exim supports two equivalent syntaxes for certain operators:
    /// - Brace form: `${length{5}{string}}` — parsed as ItemKeyword
    /// - Underscore form: `${length_5:string}` — parsed as ParametricOperator
    ///
    /// The underscore form encodes one or two numeric parameters directly
    /// in the operator name, separated by underscores. Supported operators:
    /// - `length_N` — first N characters
    /// - `substr_N_M` — substring from position N, length M
    /// - `hash_N_M` — hash to N chars from M-char pool
    /// - `nhash_N` or `nhash_N_M` — numeric hash
    ///
    /// Fields: (operator_base_name, param1, optional_param2)
    ParametricOperator(String, i64, Option<i64>),

    /// A recognised condition keyword (e.g. `match`, `eq`, `exists`).
    ConditionKeyword(String),

    /// A comma `,` used as an option separator (e.g. `${run,preexpand{…}}`).
    Comma,

    /// End-of-input sentinel.
    Eof,
}

// ═══════════════════════════════════════════════════════════════════════
//  Span tracking
// ═══════════════════════════════════════════════════════════════════════

/// Byte-offset span within the source string for error reporting.
///
/// Both `start` and `end` are byte offsets into the original input
/// string.  `start` is inclusive, `end` is exclusive (half-open range).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenSpan {
    /// Inclusive start byte offset.
    pub start: usize,
    /// Exclusive end byte offset.
    pub end: usize,
}

impl TokenSpan {
    /// Create a new span from start (inclusive) to end (exclusive).
    #[inline]
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    /// Returns the byte length of this span.
    #[inline]
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Returns `true` if this span covers zero bytes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }
}

/// A token together with its source span.
#[derive(Debug, Clone, PartialEq)]
pub struct SpannedToken {
    /// The token value.
    pub token: Token,
    /// Byte span in the original input.
    pub span: TokenSpan,
}

// ═══════════════════════════════════════════════════════════════════════
//  Identifier context for keyword classification
// ═══════════════════════════════════════════════════════════════════════

/// Context in which an identifier is being classified.
///
/// The same name (e.g. `"acl"`) can be an item keyword, a condition
/// keyword, or a plain variable name depending on where it appears.
/// This enum tells [`Tokenizer::classify_identifier()`] which keyword
/// tables to search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifierContext {
    /// After `${` — check item table, then operator tables.
    BraceExpression,
    /// After `${if ` — check condition table.
    Condition,
    /// After bare `$` — plain variable name, no keyword classification.
    Variable,
}

// ═══════════════════════════════════════════════════════════════════════
//  Internal scan context
// ═══════════════════════════════════════════════════════════════════════

/// Internal state tracking for the tokenizer's scanning context.
///
/// This determines how the next character sequence should be
/// interpreted, enabling context-sensitive token production.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanContext {
    /// Default scanning mode — accumulate literal text or handle
    /// special characters (`$`, `\`, `{`, `}`).
    Normal,
    /// Just emitted a `Dollar` token — the next characters should be
    /// interpreted as a variable name (alpha → identifier), a numeric
    /// reference (digit → identifier), or fall through to normal
    /// processing for structural tokens like `{`.
    AfterDollar,
    /// Just entered a `${` brace expression — the next identifier
    /// should be classified against item and operator keyword tables.
    AfterDollarBrace,
}

// ═══════════════════════════════════════════════════════════════════════
//  Tokenizer
// ═══════════════════════════════════════════════════════════════════════

/// Lexical scanner that converts an Exim expansion string into a stream
/// of [`Token`] values.
///
/// The tokenizer processes the input string left-to-right, emitting one
/// token per call to [`next_token()`](Self::next_token).  It tracks
/// brace nesting depth and scan context to produce correct tokens in
/// all syntactic positions.
///
/// # Taint Safety
///
/// Use [`from_clean()`](Self::from_clean) to create a tokenizer from a
/// [`Clean<&str>`] value, enforcing at compile time that untainted input
/// cannot be accidentally tokenized.  This replaces the runtime
/// `is_tainted()` check at expand.c lines 4787-4793.
///
/// # Examples
///
/// ```ignore
/// use exim_expand::tokenizer::{Tokenizer, Token};
///
/// let mut tok = Tokenizer::new("Hello $world");
/// let tokens = tok.tokenize().unwrap();
/// assert_eq!(tokens[0].token, Token::Literal("Hello ".to_string()));
/// assert_eq!(tokens[1].token, Token::Dollar);
/// assert_eq!(tokens[2].token, Token::Identifier("world".to_string()));
/// ```
pub struct Tokenizer<'a> {
    /// The input string being tokenized.
    input: &'a str,
    /// Current byte position within the input.
    position: usize,
    /// Nesting depth of braces for tracking `${…}` context.
    brace_depth: u32,
    /// Internal scan context determining how the next characters are
    /// interpreted.
    context: ScanContext,
    /// Set when a header variable name consumed characters that look
    /// like expression syntax (e.g. `}`, `{`), indicating the header
    /// name was probably not terminated by a colon.  Mirrors C Exim's
    /// `malformed_header` flag (expand.c line 868).
    pub malformed_header: bool,
}

impl<'a> Tokenizer<'a> {
    // ─── Constructors ───────────────────────────────────────────────

    /// Create a new tokenizer over the given input string.
    ///
    /// This constructor accepts a plain `&str` for internal use when
    /// taint checking has already been performed at a higher level.
    /// For compile-time taint enforcement, prefer
    /// [`from_clean()`](Self::from_clean).
    ///
    /// Corresponds to the entry point of `expand_string_internal()`
    /// at expand.c line 4771.
    pub fn new(input: &'a str) -> Self {
        Self {
            input,
            position: 0,
            brace_depth: 0,
            context: ScanContext::Normal,
            malformed_header: false,
        }
    }

    /// Create a tokenizer from a [`Clean<&str>`] value, enforcing
    /// compile-time taint tracking.
    ///
    /// Only clean (untainted) strings can be tokenized.  This replaces
    /// the C runtime check at expand.c lines 4787-4793:
    /// ```c
    /// if (is_tainted(s)) {
    ///     expand_string_message = string_sprintf(
    ///         "attempt to expand tainted string '%s'", s);
    ///     goto EXPAND_FAILED;
    /// }
    /// ```
    ///
    /// # Type-Level Enforcement
    ///
    /// Because [`Tainted<T>`](exim_store::Tainted) does not implement
    /// `Deref` or implicit conversion to `Clean<T>`, tainted input
    /// *cannot* reach this function without explicit sanitization via
    /// [`Tainted::sanitize()`](exim_store::Tainted::sanitize) or
    /// [`Tainted::force_clean()`](exim_store::Tainted::force_clean).
    pub fn from_clean(input: Clean<&'a str>) -> Self {
        // Log the clean input length for debugging (uses Clean::as_ref())
        let len = input.as_ref().len();
        tracing::trace!(input_len = len, "tokenizer created from clean input");
        // Extract the verified-clean &str (uses Clean::into_inner())
        Self::new(input.into_inner())
    }

    /// Reject a raw string if it is identified as tainted at runtime.
    ///
    /// This is the runtime counterpart to the compile-time enforcement
    /// provided by [`from_clean()`](Self::from_clean).  Callers that
    /// receive an untyped `&str` from C FFI boundaries or other dynamic
    /// sources can use this method to get an `Err(ExpandError::TaintedInput)`
    /// before tokenizing.
    ///
    /// Returns `Ok(Tokenizer)` for clean input, or
    /// `Err(ExpandError::TaintedInput)` if `is_tainted` is true.
    ///
    /// Corresponds to the runtime check at expand.c lines 4787-4793:
    /// ```c
    /// if (is_tainted(s))
    ///     expand_string_message = string_sprintf(
    ///         "attempt to expand tainted string '%s'", s);
    /// ```
    pub fn new_validated(input: &'a str, is_tainted: bool) -> Result<Self, ExpandError> {
        if is_tainted {
            return Err(ExpandError::TaintedInput(format!(
                "attempt to expand tainted string '{}'",
                if input.len() > 64 {
                    &input[..64]
                } else {
                    input
                }
            )));
        }
        Ok(Self::new(input))
    }

    // ─── Primary API ────────────────────────────────────────────────

    /// Tokenize the entire input into a token stream.
    ///
    /// Repeatedly calls [`next_token()`](Self::next_token) until
    /// [`Token::Eof`] is reached, collecting all tokens (including
    /// the final `Eof`) into a `Vec`.
    ///
    /// # Errors
    ///
    /// Returns [`ExpandError::Failed`] if a lexical error is
    /// encountered (e.g. `\` at end of string, unterminated `\N…\N`
    /// region).
    pub fn tokenize(&mut self) -> Result<Vec<SpannedToken>, ExpandError> {
        let mut tokens = Vec::new();
        loop {
            let spanned = self.next_token()?;
            let is_eof = spanned.token == Token::Eof;
            tokens.push(spanned);
            if is_eof {
                break;
            }
        }
        Ok(tokens)
    }

    /// Consume the next token from the input.
    ///
    /// This is the core scanning method.  It handles all dispatch
    /// logic for the Exim expansion DSL:
    ///
    /// - **Literal text**: Accumulated until a special character is
    ///   found (`$`, `\`, `{`, `}`, and `:` / `,` inside braces).
    /// - **Dollar** (`$`): Introduces a variable or item reference.
    /// - **Backslash** (`\`): Escape sequences and protected regions.
    /// - **Braces** (`{`, `}`): Structural delimiters.
    /// - **Colon / Comma**: Structural separators inside `${…}`.
    ///
    /// # Context Sensitivity
    ///
    /// After a `Dollar` token, the next call produces an `Identifier`
    /// (for bare `$variable`) or falls through to structural token
    /// processing (for `${…}`).  After `Dollar` + `OpenBrace`, the
    /// next identifier is classified against keyword tables.
    ///
    /// # Errors
    ///
    /// Returns [`ExpandError::Failed`] on lexical errors.
    pub fn next_token(&mut self) -> Result<SpannedToken, ExpandError> {
        // Handle end of input.
        if self.at_end() {
            return Ok(self.make_spanned(Token::Eof, self.position));
        }

        // ── Context-sensitive handling ──────────────────────────────
        // After Dollar: interpret next chars as variable name or digit.
        if self.context == ScanContext::AfterDollar {
            self.context = ScanContext::Normal;
            if let Some(ch) = self.peek() {
                if ch.is_ascii_alphabetic() || ch == '_' {
                    // Bare $variable — read identifier as variable name
                    let start = self.position;
                    let mut name = self.read_identifier();

                    // In C Exim, bare header references use a colon as
                    // the name terminator: $h_subject: — the colon is
                    // consumed and NOT echoed.  Detect header prefixes
                    // and silently eat the trailing colon.
                    //
                    // CRITICAL: C Exim's read_header_name() (expand.c
                    // line 1156) uses `mac_isgraph(*s) && *s != ':'` to
                    // continue reading, which means graphic characters
                    // like `}`, `{`, `=`, etc. are consumed into the
                    // header name when the colon is missing.  This is
                    // how C Exim detects `$h_foo}` as a likely mistake:
                    // the `}` is eaten, causing a downstream "missing }"
                    // error with the hint "could be header name not
                    // terminated by colon".
                    let lc = name.to_ascii_lowercase();
                    let is_header_prefix = lc.starts_with("h_")
                        || lc.starts_with("header_")
                        || lc.starts_with("rh_")
                        || lc.starts_with("rheader_")
                        || lc.starts_with("bh_")
                        || lc.starts_with("bheader_")
                        || lc.starts_with("lh_")
                        || lc.starts_with("lheader_");
                    if is_header_prefix {
                        if self.peek() == Some(':') {
                            self.advance(); // consume the colon
                        } else {
                            // No colon after header prefix — match C
                            // Exim's read_header_name() which continues
                            // reading graphic (printable, non-space)
                            // characters.  This intentionally consumes
                            // braces etc., triggering parse errors
                            // downstream.
                            while let Some(c) = self.peek() {
                                if c == ':' || c.is_ascii_whitespace() || !c.is_ascii_graphic() {
                                    break;
                                }
                                if c == '}' || c == '{' {
                                    // C Exim (expand.c line 2710/4927):
                                    // if name contains '}', set
                                    // malformed_header = TRUE
                                    self.malformed_header = true;
                                }
                                name.push(c);
                                self.advance();
                            }
                            // C also consumes the colon if eventually
                            // found, and always appends ':' to the name.
                            if self.peek() == Some(':') {
                                self.advance();
                            }
                        }
                    }

                    return Ok(self.make_spanned(Token::Identifier(name), start));
                }
                if ch.is_ascii_digit() {
                    // Numeric variable reference $<digits>.
                    //
                    // C Exim (expand.c line 4976) calls read_cnumber()
                    // which reads ALL consecutive digits.  $11111 reads
                    // all five digits, producing the number 11111.  Only
                    // values 0..expand_nmax yield a non-empty result;
                    // out-of-range values silently resolve to empty.
                    let start = self.position;
                    let digits = self.read_digits();
                    return Ok(self.make_spanned(Token::Identifier(digits), start));
                }
                if ch == '{' {
                    // Dollar + { → enter brace expression context.
                    // Emit OpenBrace now; next identifier will be classified.
                    self.context = ScanContext::AfterDollarBrace;
                    let start = self.position;
                    self.advance();
                    self.brace_depth = self.brace_depth.saturating_add(1);
                    return Ok(self.make_spanned(Token::OpenBrace, start));
                }
                // Dollar followed by other char — fall through to normal
                // processing.  The parser will report an error if needed.
            }
        }

        // After Dollar + OpenBrace: classify next identifier as keyword.
        if self.context == ScanContext::AfterDollarBrace {
            self.context = ScanContext::Normal;
            if let Some(ch) = self.peek() {
                if ch.is_ascii_alphabetic() || ch == '_' {
                    let start = self.position;
                    let name = self.read_identifier_extended();
                    let token =
                        Self::classify_identifier(&name, IdentifierContext::BraceExpression)
                            .map_err(|msg| ExpandError::Failed { message: msg })?;
                    return Ok(self.make_spanned(token, start));
                }
                if ch.is_ascii_digit() {
                    // ${123} — braced numeric reference
                    // (expand.c lines 4997-5013)
                    let start = self.position;
                    let digits = self.read_digits();
                    return Ok(self.make_spanned(Token::Identifier(digits), start));
                }
                // Other chars after ${ — fall through to normal processing.
                // Parser handles errors like ${<} etc.
            }
        }

        // ── Normal character dispatch ──────────────────────────────

        // Safety: we already checked `at_end()` above, so peek() is Some.
        let ch = match self.peek() {
            Some(c) => c,
            None => return Ok(self.make_spanned(Token::Eof, self.position)),
        };

        match ch {
            '\\' => self.handle_backslash(),
            '$' => self.handle_dollar(),
            '{' => {
                let start = self.position;
                self.advance();
                self.brace_depth = self.brace_depth.saturating_add(1);
                Ok(self.make_spanned(Token::OpenBrace, start))
            }
            '}' => {
                let start = self.position;
                self.advance();
                self.brace_depth = self.brace_depth.saturating_sub(1);
                Ok(self.make_spanned(Token::CloseBrace, start))
            }
            ':' if self.brace_depth > 0 => {
                let start = self.position;
                self.advance();
                Ok(self.make_spanned(Token::Colon, start))
            }
            ',' if self.brace_depth > 0 => {
                let start = self.position;
                self.advance();
                Ok(self.make_spanned(Token::Comma, start))
            }
            _ => Ok(self.read_literal()),
        }
    }

    /// Peek at the next token without consuming it.
    ///
    /// Creates a temporary clone of the tokenizer state, advances it
    /// by one token, and returns the result.  The original tokenizer
    /// state is unchanged.
    pub fn peek_token(&self) -> Result<Token, ExpandError> {
        let mut clone = Self {
            input: self.input,
            position: self.position,
            brace_depth: self.brace_depth,
            context: self.context,
            malformed_header: self.malformed_header,
        };
        Ok(clone.next_token()?.token)
    }

    // ─── Identifier Reading ────────────────────────────────────────

    /// Read an identifier: a sequence of ASCII letters, digits, and
    /// underscores.
    ///
    /// Matches the C `read_name(name, max, s, US"_")` function at
    /// expand.c lines 1115-1127.  The first character should be a
    /// letter or underscore (caller's responsibility to verify).
    ///
    /// # Returns
    ///
    /// The identifier string.  Returns an empty string if the current
    /// position does not contain identifier characters.
    pub fn read_identifier(&mut self) -> String {
        // C Exim uses a fixed 256-byte buffer for `read_name()` (expand.c
        // line 1115-1127).  Variable/operator names longer than 255
        // characters are silently truncated.  We match this limit to
        // produce identical error messages for very long names.
        const NAME_MAX: usize = 255;
        let mut ident = String::new();
        while let Some(ch) = self.peek() {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                if ident.len() < NAME_MAX {
                    ident.push(ch);
                }
                self.advance();
            } else {
                break;
            }
        }
        ident
    }

    /// Read an extended identifier allowing hyphens.
    ///
    /// Matches the C `read_name(name, max, s, US"_-")` call at expand.c
    /// line 5025.  After `${`, names can contain hyphens to support
    /// potential future keywords and allow identifiers like
    /// compound names in extensions.
    fn read_identifier_extended(&mut self) -> String {
        const NAME_MAX: usize = 255;
        let mut ident = String::new();
        while let Some(ch) = self.peek() {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                if ident.len() < NAME_MAX {
                    ident.push(ch);
                }
                self.advance();
            } else {
                break;
            }
        }
        ident
    }

    /// Read a sequence of ASCII digits.
    ///
    /// Used for numeric variable references (`$1`…`$9`) and braced
    /// numeric references (`${0}`…`${n}`).
    fn read_digits(&mut self) -> String {
        let mut digits = String::new();
        while let Some(ch) = self.peek() {
            if ch.is_ascii_digit() {
                digits.push(ch);
                self.advance();
            } else {
                break;
            }
        }
        digits
    }

    // ─── Keyword Classification ────────────────────────────────────

    /// Classify an identifier as an item keyword, operator keyword,
    /// condition keyword, or plain identifier based on context.
    ///
    /// This function replaces the C `chop_match()` calls at expand.c
    /// lines 5026 (`item_table`), 7274 (`op_table_underscore`), 7288
    /// (`op_table_main`), and within the `EITEM_IF` handler for
    /// `cond_table`.
    ///
    /// # Classification Rules
    ///
    /// | Context | Search Order |
    /// |---------|-------------|
    /// | [`BraceExpression`](IdentifierContext::BraceExpression) | item_table → op_underscore → op_main |
    /// | [`Condition`](IdentifierContext::Condition) | cond_table only |
    /// | [`Variable`](IdentifierContext::Variable) | No lookup — always `Identifier` |
    ///
    /// # Arguments
    ///
    /// * `name` — The identifier string to classify.
    /// * `context` — The syntactic context determining which tables
    ///   to search.
    ///
    /// # Returns
    ///
    /// The appropriate [`Token`] variant for the classified identifier.
    pub fn classify_identifier(name: &str, context: IdentifierContext) -> Result<Token, String> {
        match context {
            IdentifierContext::BraceExpression => {
                // Search item table first (expand.c line 5026)
                if keyword_lookup(name, ITEM_KEYWORDS) {
                    return Ok(Token::ItemKeyword(name.to_owned()));
                }
                // Then underscore-containing operators (expand.c line 7274)
                if keyword_lookup(name, OP_UNDERSCORE_KEYWORDS) {
                    return Ok(Token::OperatorKeyword(name.to_owned()));
                }
                // Then main operator table (expand.c line 7288)
                if keyword_lookup(name, OP_MAIN_KEYWORDS) {
                    return Ok(Token::OperatorKeyword(name.to_owned()));
                }
                // Check for quote_TYPE pattern — lookup-type-specific quoting.
                // In C Exim the `quote` operator checks for a `_<type>` suffix
                // at parse time.  Our parser handles this via
                // `operator_name_to_kind`, but the tokenizer must first
                // classify `quote_<type>` as an OperatorKeyword so that the
                // parser path is reached.  `quote_local_part` is already
                // covered by OP_UNDERSCORE_KEYWORDS; this catches any other
                // `quote_*` form (e.g. `quote_lsearch`, `quote_dbm`).
                if name.starts_with("quote_") {
                    return Ok(Token::OperatorKeyword(name.to_owned()));
                }
                // Check for parametric operator forms with embedded numeric
                // arguments (C Exim's underscore syntax).
                //
                // Supported patterns:
                //   length_N        → ParametricOperator("length", N, None)
                //   substr_N_M      → ParametricOperator("substr", N, Some(M))
                //   hash_N_M        → ParametricOperator("hash", N, Some(M))
                //   nhash_N         → ParametricOperator("nhash", N, None)
                //   nhash_N_M       → ParametricOperator("nhash", N, Some(M))
                //
                // The C code (expand.c read_subs) parsed these by detecting
                // that the operator name is in the op_table_underscore list
                // and then scanning for _N or _N_M suffixes. We replicate
                // this by checking if the identifier starts with a known
                // parametric operator base name followed by _<digits>.
                match try_parametric_operator(name) {
                    Ok(Some(token)) => return Ok(token),
                    Err(msg) => {
                        // C Exim: "non-digit after underscore in ..."
                        return Err(msg);
                    }
                    Ok(None) => {}
                }
                // Not a keyword — treat as a variable name in braced form
                Ok(Token::Identifier(name.to_owned()))
            }
            IdentifierContext::Condition => {
                if keyword_lookup(name, COND_KEYWORDS) {
                    Ok(Token::ConditionKeyword(name.to_owned()))
                } else {
                    Ok(Token::Identifier(name.to_owned()))
                }
            }
            IdentifierContext::Variable => {
                // Bare $variable — no keyword classification
                Ok(Token::Identifier(name.to_owned()))
            }
        }
    }

    // ─── Backslash Handling ────────────────────────────────────────

    /// Handle a backslash-initiated escape sequence.
    ///
    /// Implements the logic from expand.c lines 4820-4849:
    ///
    /// 1. `\` at end of string → error
    /// 2. `\N` → protected region (scan until next `\N`)
    /// 3. Standard escapes → `EscapeChar`
    /// 4. Unrecognised → `BackslashLiteral`
    fn handle_backslash(&mut self) -> Result<SpannedToken, ExpandError> {
        let start = self.position;
        self.advance(); // consume the backslash

        // Check for backslash at end of string (expand.c line 4822)
        let next_ch = match self.peek() {
            Some(c) => c,
            None => {
                return Err(ExpandError::Failed {
                    message: "\\ at end of string".to_owned(),
                });
            }
        };

        // Protected region \N…\N (expand.c lines 4828-4838)
        if next_ch == 'N' {
            self.advance(); // consume the 'N'
            let content = self.read_protected_region()?;
            return Ok(self.make_spanned(Token::ProtectedRegion(content), start));
        }

        // Standard escape sequences via interpret_escape()
        let (ch, is_standard) = self.interpret_escape();
        if is_standard {
            Ok(self.make_spanned(Token::EscapeChar(ch), start))
        } else {
            Ok(self.make_spanned(Token::BackslashLiteral(ch), start))
        }
    }

    /// Read the content of a `\N…\N` protected region.
    ///
    /// The opening `\N` has already been consumed.  This function scans
    /// forward until the closing `\N` is found, returning the content
    /// between the markers.
    ///
    /// If no closing `\N` is found before end of input, the content up
    /// to the end is returned (matching C behavior where `*s` check
    /// handles null terminator at expand.c line 4831).
    fn read_protected_region(&mut self) -> Result<String, ExpandError> {
        let mut content = String::new();
        while !self.at_end() {
            if self.peek() == Some('\\') && self.peek_at(1) == Some('N') {
                // Found closing \N — consume both characters
                self.advance(); // consume '\'
                self.advance(); // consume 'N'
                return Ok(content);
            }
            if let Some(ch) = self.advance() {
                content.push(ch);
            }
        }
        // Reached end of input without closing \N — return what we have.
        // The C code does not error here; it just stops scanning.
        Ok(content)
    }

    /// Interpret a standard backslash escape sequence.
    ///
    /// Reimplements `string_interpret_escape()` from src/src/string.c
    /// lines 274-313.  The backslash has already been consumed; this
    /// function reads and consumes the character(s) after it.
    ///
    /// # Returns
    ///
    /// A tuple of `(char, is_standard_escape)`.  `is_standard_escape`
    /// is `true` for recognised sequences (producing `EscapeChar`) and
    /// `false` for unrecognised ones (producing `BackslashLiteral`).
    fn interpret_escape(&mut self) -> (char, bool) {
        let ch = match self.peek() {
            Some(c) => c,
            // Shouldn't happen — caller checks for end-of-input.
            None => return ('\\', false),
        };

        // Octal escape: \0 through \7, reading up to 3 octal digits.
        // (string.c lines 284-293)
        if ch.is_ascii_digit() && ch != '8' && ch != '9' {
            self.advance(); // consume first octal digit
            let mut value = (ch as u32) - b'0' as u32;

            if let Some(d2) = self.peek() {
                if d2.is_ascii_digit() && d2 != '8' && d2 != '9' {
                    self.advance();
                    value = value * 8 + (d2 as u32) - b'0' as u32;

                    if let Some(d3) = self.peek() {
                        if d3.is_ascii_digit() && d3 != '8' && d3 != '9' {
                            self.advance();
                            value = value * 8 + (d3 as u32) - b'0' as u32;
                        }
                    }
                }
            }

            let result_char = char::from_u32(value).unwrap_or('\u{FFFD}');
            return (result_char, true);
        }

        // Named escape sequences (string.c lines 294-307)
        self.advance(); // consume the escape character
        match ch {
            'b' => ('\x08', true), // backspace
            'f' => ('\x0C', true), // form feed
            'n' => ('\n', true),   // newline
            'r' => ('\r', true),   // carriage return
            't' => ('\t', true),   // tab
            'v' => ('\x0B', true), // vertical tab
            '\\' => ('\\', true),  // literal backslash
            'x' => {
                // Hex escape: \xHH (string.c lines 298-307)
                let mut value: u32 = 0;
                let mut consumed = false;
                if let Some(h1) = self.peek() {
                    if h1.is_ascii_hexdigit() {
                        self.advance();
                        value = hex_digit_value(h1);
                        consumed = true;
                        if let Some(h2) = self.peek() {
                            if h2.is_ascii_hexdigit() {
                                self.advance();
                                value = value * 16 + hex_digit_value(h2);
                            }
                        }
                    }
                }
                if consumed {
                    let result_char = char::from_u32(value).unwrap_or('\u{FFFD}');
                    (result_char, true)
                } else {
                    // \x with no hex digits — treat as BackslashLiteral
                    ('x', false)
                }
            }
            // Unrecognised escape — return the character as-is
            other => (other, false),
        }
    }

    // ─── Dollar Handling ───────────────────────────────────────────

    /// Handle a dollar-sign sequence.
    ///
    /// Implements the dispatch logic from expand.c lines 4858-4992:
    ///
    /// - `$$` → literal `$`
    /// - `${` → `Dollar` token (next call handles `OpenBrace`)
    /// - `$alpha` → `Dollar` token (next call reads identifier)
    /// - `$digit` → `Dollar` token (next call reads numeric ref)
    /// - `$` alone / `$` + other → `Dollar` token
    fn handle_dollar(&mut self) -> Result<SpannedToken, ExpandError> {
        let start = self.position;
        self.advance(); // consume the '$'

        // Check for $$ → literal dollar (escape-like behavior)
        if self.peek() == Some('$') {
            self.advance(); // consume second '$'
            return Ok(self.make_spanned(Token::Literal("$".to_owned()), start));
        }

        // Set context for the NEXT call to next_token().
        // The Dollar token is emitted now; the next call will use
        // the context to properly interpret subsequent characters.
        self.context = ScanContext::AfterDollar;
        Ok(self.make_spanned(Token::Dollar, start))
    }

    // ─── Literal Text Accumulation ─────────────────────────────────

    /// Accumulate a run of literal text.
    ///
    /// Collects characters that are not special until a special
    /// character is encountered.  The set of special characters depends
    /// on the current brace depth:
    ///
    /// - **Always special**: `$`, `\`, `{`, `}`
    /// - **Special inside braces** (brace_depth > 0): `:`, `,`
    ///
    /// This matches the C accumulation loop at expand.c lines 4860-4869
    /// where literal text is collected until `$`, `}`, or `\` is found.
    fn read_literal(&mut self) -> SpannedToken {
        let start = self.position;
        let mut text = String::new();

        while let Some(ch) = self.peek() {
            if self.is_special_char(ch) {
                break;
            }
            text.push(ch);
            self.advance();
        }

        // Guard: if we somehow didn't accumulate anything (shouldn't
        // happen since the caller verified the char was not special),
        // consume one character to avoid infinite loops.
        if text.is_empty() {
            if let Some(ch) = self.advance() {
                text.push(ch);
            }
        }

        self.make_spanned(Token::Literal(text), start)
    }

    /// Read a header name following the header prefix.
    ///
    /// Header names can contain any printable character except `:`
    /// and `}` (expand.c `read_header_name()` at lines 1150-1165).
    /// The prefix (e.g. `h_`, `header_`, `rh_`) has already been
    /// consumed as part of the identifier.
    ///
    /// This method reads additional characters that a standard
    /// `read_identifier()` would not accept (e.g. `-`, `.`, `/`).
    pub fn read_header_name(&mut self) -> String {
        let mut name = String::new();
        while let Some(ch) = self.peek() {
            // Stop at colon (header name terminator), closing brace,
            // whitespace, or end of input.
            if ch == ':' || ch == '}' || ch.is_ascii_whitespace() {
                break;
            }
            // Only accept printable characters
            if !ch.is_ascii_graphic() {
                break;
            }
            name.push(ch);
            self.advance();
        }
        // Consume the trailing colon if present (expand.c line 1161)
        if self.peek() == Some(':') {
            self.advance();
        }
        name
    }

    // ─── Character-level helpers ───────────────────────────────────

    /// Returns `true` if the given character is "special" and should
    /// terminate literal text accumulation.
    fn is_special_char(&self, ch: char) -> bool {
        match ch {
            '$' | '\\' | '{' | '}' => true,
            ':' | ',' if self.brace_depth > 0 => true,
            _ => false,
        }
    }

    /// Peek at the current character without consuming it.
    ///
    /// Reads a *char* from the input string at the current byte
    /// position.  This is char-aware so that Latin-1-encoded high
    /// bytes (each byte 0x80..0xFF stored as U+0080..U+00FF in the
    /// Rust String) are returned as a single char whose value equals
    /// the original byte value — matching C Exim's byte-level
    /// `*s` dereference.
    #[inline]
    fn peek(&self) -> Option<char> {
        self.input[self.position..].chars().next()
    }

    /// Peek at a character at the given offset from the current position.
    ///
    /// `offset` is measured in *characters*, not bytes.
    #[inline]
    fn peek_at(&self, offset: usize) -> Option<char> {
        self.input[self.position..].chars().nth(offset)
    }

    /// Consume the current character and advance the position.
    ///
    /// Returns the consumed character, or `None` if at end of input.
    /// The position is advanced by the character's UTF-8 byte length
    /// so that it always sits on a char boundary.
    #[inline]
    fn advance(&mut self) -> Option<char> {
        let mut iter = self.input[self.position..].chars();
        if let Some(ch) = iter.next() {
            self.position += ch.len_utf8();
            Some(ch)
        } else {
            None
        }
    }

    /// Returns `true` if the current position is at or past the end
    /// of the input.
    #[inline]
    fn at_end(&self) -> bool {
        self.position >= self.input.len()
    }

    /// Create a [`SpannedToken`] spanning from `start` to the current
    /// position.
    #[inline]
    fn make_spanned(&self, token: Token, start: usize) -> SpannedToken {
        SpannedToken {
            token,
            span: TokenSpan::new(start, self.position),
        }
    }

    /// Returns the current byte position within the input.
    #[inline]
    pub fn position(&self) -> usize {
        self.position
    }

    /// Returns the current brace nesting depth.
    #[inline]
    pub fn brace_depth(&self) -> u32 {
        self.brace_depth
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Helper functions
// ═══════════════════════════════════════════════════════════════════════

/// Binary search for a keyword in a sorted table.
///
/// Reimplements the C `chop_match()` function from expand.c lines
/// 959-974.  Returns `true` if `name` is found in the table.
///
/// # Precondition
///
/// `table` MUST be sorted in ascending alphabetical order.
fn keyword_lookup(name: &str, table: &[&str]) -> bool {
    table.binary_search(&name).is_ok()
}

/// Known parametric operator base names that support the `_N` or `_N_M`
/// underscore suffix syntax in C Exim.
///
/// These are the operators listed in C expand.c's `op_table_underscore`
/// that accept numeric parameters embedded in the operator name:
/// - `hash` — hash to N chars from M-char pool
/// - `length` — first N characters
/// - `nhash` — numeric hash to N (or N_M)
/// - `substr` — substring from position N, length M
const PARAMETRIC_OPERATOR_BASES: &[&str] = &[
    "hash",
    "headerwrap",
    "length",
    "mask",
    "nhash",
    "substr",
    // Short aliases (C Exim op_table_underscore single-char entries)
    "h",
    "l",
    "nh",
    "s",
];

/// Try to parse an identifier as a parametric operator with embedded
/// numeric arguments.
///
/// Returns `Some(Token::ParametricOperator(...))` if the identifier
/// matches the pattern `BASE_N` or `BASE_N_M` where `BASE` is one of
/// the known parametric operators and `N`, `M` are sequences of digits.
///
/// # Examples
///
/// ```text
/// "length_5"    → Some(ParametricOperator("length", 5, None))
/// "substr_0_5"  → Some(ParametricOperator("substr", 0, Some(5)))
/// "hash_5_3"    → Some(ParametricOperator("hash", 5, Some(3)))
/// "nhash_100"   → Some(ParametricOperator("nhash", 100, None))
/// "nhash_5_3"   → Some(ParametricOperator("nhash", 5, Some(3)))
/// "length_abc"  → None (non-numeric suffix)
/// "foo_5"       → None (unknown base)
/// ```
fn try_parametric_operator(name: &str) -> Result<Option<Token>, String> {
    for &base in PARAMETRIC_OPERATOR_BASES {
        if let Some(suffix) = name.strip_prefix(base) {
            // Suffix must start with '_' followed by optional '-' and digits.
            if let Some(rest) = suffix.strip_prefix('_') {
                if rest.is_empty() {
                    // e.g. "length_" — non-digit after underscore
                    return Err(format!("non-digit after underscore in \"{}\"", name));
                }
                // Try to find the second underscore for two-param form.
                let search_start = if rest.starts_with('-') { 1 } else { 0 };
                if let Some(rel_pos) = rest[search_start..].find('_') {
                    let underscore_pos = search_start + rel_pos;
                    let first_part = &rest[..underscore_pos];
                    let second_part = &rest[underscore_pos + 1..];
                    if let (Ok(n), Ok(m)) = (first_part.parse::<i64>(), second_part.parse::<i64>())
                    {
                        return Ok(Some(Token::ParametricOperator(base.to_owned(), n, Some(m))));
                    }
                    // Non-digit after underscore in parametric form
                    return Err(format!("non-digit after underscore in \"{}\"", name));
                } else if let Ok(n) = rest.parse::<i64>() {
                    // Single-param form: base_N
                    return Ok(Some(Token::ParametricOperator(base.to_owned(), n, None)));
                }
                // Non-digit after underscore
                return Err(format!("non-digit after underscore in \"{}\"", name));
            }
        }
    }
    Ok(None)
}

/// Convert a hex digit character to its numeric value (0-15).
fn hex_digit_value(ch: char) -> u32 {
    match ch {
        '0'..='9' => (ch as u32) - ('0' as u32),
        'a'..='f' => (ch as u32) - ('a' as u32) + 10,
        'A'..='F' => (ch as u32) - ('A' as u32) + 10,
        _ => 0,
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper: collect token types ────────────────────────────────

    fn tokenize_str(input: &str) -> Vec<Token> {
        let mut tok = Tokenizer::new(input);
        let spanned = tok.tokenize().unwrap();
        spanned.into_iter().map(|st| st.token).collect()
    }

    // ── Literal text ──────────────────────────────────────────────

    #[test]
    fn test_plain_literal() {
        let tokens = tokenize_str("Hello World");
        assert_eq!(
            tokens,
            vec![Token::Literal("Hello World".into()), Token::Eof]
        );
    }

    #[test]
    fn test_empty_input() {
        let tokens = tokenize_str("");
        assert_eq!(tokens, vec![Token::Eof]);
    }

    // ── Dollar sequences ──────────────────────────────────────────

    #[test]
    fn test_dollar_variable() {
        let tokens = tokenize_str("$local_part");
        assert_eq!(
            tokens,
            vec![
                Token::Dollar,
                Token::Identifier("local_part".into()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn test_dollar_dollar_escape() {
        let tokens = tokenize_str("$$");
        assert_eq!(tokens, vec![Token::Literal("$".into()), Token::Eof]);
    }

    #[test]
    fn test_dollar_brace_variable() {
        // Use "sender" which is NOT a keyword — "domain" is in op_table_main
        let tokens = tokenize_str("${sender}");
        assert_eq!(
            tokens,
            vec![
                Token::Dollar,
                Token::OpenBrace,
                Token::Identifier("sender".into()),
                Token::CloseBrace,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn test_dollar_brace_domain_is_operator() {
        // "domain" is in op_table_main, so it's classified as OperatorKeyword
        let tokens = tokenize_str("${domain}");
        assert_eq!(
            tokens,
            vec![
                Token::Dollar,
                Token::OpenBrace,
                Token::OperatorKeyword("domain".into()),
                Token::CloseBrace,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn test_dollar_brace_item_keyword() {
        let tokens = tokenize_str("${lookup");
        assert_eq!(
            tokens,
            vec![
                Token::Dollar,
                Token::OpenBrace,
                Token::ItemKeyword("lookup".into()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn test_dollar_brace_operator_keyword() {
        let tokens = tokenize_str("${lc:text}");
        assert_eq!(
            tokens,
            vec![
                Token::Dollar,
                Token::OpenBrace,
                Token::OperatorKeyword("lc".into()),
                Token::Colon,
                Token::Literal("text".into()),
                Token::CloseBrace,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn test_dollar_numeric_variable() {
        let tokens = tokenize_str("$1");
        assert_eq!(
            tokens,
            vec![Token::Dollar, Token::Identifier("1".into()), Token::Eof,]
        );
    }

    #[test]
    fn test_braced_numeric_variable() {
        let tokens = tokenize_str("${3}");
        assert_eq!(
            tokens,
            vec![
                Token::Dollar,
                Token::OpenBrace,
                Token::Identifier("3".into()),
                Token::CloseBrace,
                Token::Eof,
            ]
        );
    }

    // ── Backslash escapes ─────────────────────────────────────────

    #[test]
    fn test_escape_newline() {
        let tokens = tokenize_str("\\n");
        assert_eq!(tokens, vec![Token::EscapeChar('\n'), Token::Eof]);
    }

    #[test]
    fn test_escape_tab() {
        let tokens = tokenize_str("\\t");
        assert_eq!(tokens, vec![Token::EscapeChar('\t'), Token::Eof]);
    }

    #[test]
    fn test_escape_backslash() {
        let tokens = tokenize_str("\\\\");
        assert_eq!(tokens, vec![Token::EscapeChar('\\'), Token::Eof]);
    }

    #[test]
    fn test_escape_octal() {
        // \077 = 63 = '?'
        let tokens = tokenize_str("\\077");
        assert_eq!(tokens, vec![Token::EscapeChar('?'), Token::Eof]);
    }

    #[test]
    fn test_escape_hex() {
        // \x41 = 65 = 'A'
        let tokens = tokenize_str("\\x41");
        assert_eq!(tokens, vec![Token::EscapeChar('A'), Token::Eof]);
    }

    #[test]
    fn test_escape_unknown() {
        let tokens = tokenize_str("\\a");
        assert_eq!(tokens, vec![Token::BackslashLiteral('a'), Token::Eof]);
    }

    #[test]
    fn test_backslash_at_end_is_error() {
        let mut tok = Tokenizer::new("test\\");
        let result = tok.tokenize();
        assert!(result.is_err());
    }

    // ── Protected regions ─────────────────────────────────────────

    #[test]
    fn test_protected_region() {
        let tokens = tokenize_str("\\Nhello world\\N");
        assert_eq!(
            tokens,
            vec![Token::ProtectedRegion("hello world".into()), Token::Eof,]
        );
    }

    #[test]
    fn test_protected_region_with_dollars() {
        let tokens = tokenize_str("\\N$var ${stuff}\\N");
        assert_eq!(
            tokens,
            vec![Token::ProtectedRegion("$var ${stuff}".into()), Token::Eof,]
        );
    }

    // ── Braces and nesting ────────────────────────────────────────

    #[test]
    fn test_brace_depth() {
        let mut tok = Tokenizer::new("${if eq{a}{b}{yes}{no}}");
        let tokens = tok.tokenize().unwrap();
        // Should contain Dollar, OpenBrace, ItemKeyword("if"), ...
        let token_types: Vec<_> = tokens.iter().map(|t| &t.token).collect();
        assert_eq!(token_types[0], &Token::Dollar);
        assert_eq!(token_types[1], &Token::OpenBrace);
        assert_eq!(token_types[2], &Token::ItemKeyword("if".into()));
    }

    // ── Colon and comma ───────────────────────────────────────────

    #[test]
    fn test_colon_outside_braces_is_literal() {
        let tokens = tokenize_str("key:value");
        assert_eq!(tokens, vec![Token::Literal("key:value".into()), Token::Eof]);
    }

    #[test]
    fn test_comma_outside_braces_is_literal() {
        let tokens = tokenize_str("a,b");
        assert_eq!(tokens, vec![Token::Literal("a,b".into()), Token::Eof]);
    }

    // ── Keyword classification ────────────────────────────────────

    #[test]
    fn test_classify_item_keyword() {
        let token =
            Tokenizer::classify_identifier("lookup", IdentifierContext::BraceExpression).unwrap();
        assert_eq!(token, Token::ItemKeyword("lookup".into()));
    }

    #[test]
    fn test_classify_operator_keyword() {
        let token =
            Tokenizer::classify_identifier("md5", IdentifierContext::BraceExpression).unwrap();
        assert_eq!(token, Token::OperatorKeyword("md5".into()));
    }

    #[test]
    fn test_classify_underscore_operator() {
        let token =
            Tokenizer::classify_identifier("local_part", IdentifierContext::BraceExpression)
                .unwrap();
        assert_eq!(token, Token::OperatorKeyword("local_part".into()));
    }

    #[test]
    fn test_classify_condition_keyword() {
        let token = Tokenizer::classify_identifier("eq", IdentifierContext::Condition).unwrap();
        assert_eq!(token, Token::ConditionKeyword("eq".into()));
    }

    #[test]
    fn test_classify_variable() {
        let token =
            Tokenizer::classify_identifier("sender_address", IdentifierContext::Variable).unwrap();
        assert_eq!(token, Token::Identifier("sender_address".into()));
    }

    #[test]
    fn test_classify_unknown_in_brace() {
        let token =
            Tokenizer::classify_identifier("myvar", IdentifierContext::BraceExpression).unwrap();
        assert_eq!(token, Token::Identifier("myvar".into()));
    }

    // ── Mixed content ─────────────────────────────────────────────

    #[test]
    fn test_mixed_literal_and_variable() {
        let tokens = tokenize_str("Hello $name!");
        assert_eq!(
            tokens,
            vec![
                Token::Literal("Hello ".into()),
                Token::Dollar,
                Token::Identifier("name".into()),
                Token::Literal("!".into()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn test_complex_expression() {
        let tokens = tokenize_str("${if eq{$a}{b}{yes}{no}}");
        let names: Vec<_> = tokens
            .iter()
            .map(|t| match t {
                Token::ItemKeyword(s) | Token::Identifier(s) | Token::Literal(s) => s.clone(),
                Token::Dollar => "$".into(),
                Token::OpenBrace => "{".into(),
                Token::CloseBrace => "}".into(),
                Token::Eof => "EOF".into(),
                other => format!("{other:?}"),
            })
            .collect();
        // Verify key structural tokens are present
        assert!(names.contains(&"if".to_string()));
        assert!(names.contains(&"a".to_string()));
    }

    // ── Span tracking ─────────────────────────────────────────────

    #[test]
    fn test_span_positions() {
        let mut tok = Tokenizer::new("abc$d");
        let tokens = tok.tokenize().unwrap();
        assert_eq!(tokens[0].span, TokenSpan::new(0, 3)); // "abc"
        assert_eq!(tokens[1].span, TokenSpan::new(3, 4)); // "$"
        assert_eq!(tokens[2].span, TokenSpan::new(4, 5)); // "d"
    }

    // ── Clean input integration ───────────────────────────────────

    #[test]
    fn test_from_clean() {
        let clean_input = Clean::new("$host");
        let mut tok = Tokenizer::from_clean(clean_input);
        let tokens = tok.tokenize().unwrap();
        assert_eq!(tokens[0].token, Token::Dollar);
        assert_eq!(tokens[1].token, Token::Identifier("host".into()));
    }

    // ── All condition keywords are recognised ─────────────────────

    #[test]
    fn test_all_condition_keywords_recognised() {
        for &kw in COND_KEYWORDS {
            let token = Tokenizer::classify_identifier(kw, IdentifierContext::Condition).unwrap();
            assert_eq!(
                token,
                Token::ConditionKeyword(kw.to_owned()),
                "condition keyword {kw:?} not recognised"
            );
        }
    }

    // ── All item keywords are recognised ──────────────────────────

    #[test]
    fn test_all_item_keywords_recognised() {
        for &kw in ITEM_KEYWORDS {
            let token =
                Tokenizer::classify_identifier(kw, IdentifierContext::BraceExpression).unwrap();
            assert_eq!(
                token,
                Token::ItemKeyword(kw.to_owned()),
                "item keyword {kw:?} not recognised"
            );
        }
    }

    // ── Keyword tables are sorted ─────────────────────────────────

    #[test]
    fn test_keyword_tables_sorted() {
        assert!(
            ITEM_KEYWORDS.windows(2).all(|w| w[0] <= w[1]),
            "ITEM_KEYWORDS not sorted"
        );
        assert!(
            OP_UNDERSCORE_KEYWORDS.windows(2).all(|w| w[0] <= w[1]),
            "OP_UNDERSCORE_KEYWORDS not sorted"
        );
        assert!(
            OP_MAIN_KEYWORDS.windows(2).all(|w| w[0] <= w[1]),
            "OP_MAIN_KEYWORDS not sorted"
        );
        assert!(
            COND_KEYWORDS.windows(2).all(|w| w[0] <= w[1]),
            "COND_KEYWORDS not sorted"
        );
    }

    // ── Edge cases ────────────────────────────────────────────────

    #[test]
    fn test_dollar_at_end() {
        let tokens = tokenize_str("$");
        assert_eq!(tokens, vec![Token::Dollar, Token::Eof]);
    }

    #[test]
    fn test_nested_braces() {
        let tokens = tokenize_str("${if eq{${lc:X}}{x}{y}{n}}");
        // Should handle nested ${…} expressions
        let brace_count = tokens.iter().filter(|t| **t == Token::OpenBrace).count();
        let close_count = tokens.iter().filter(|t| **t == Token::CloseBrace).count();
        assert!(brace_count > 0);
        assert!(close_count > 0);
    }

    #[test]
    fn test_protected_region_unterminated() {
        // \N without closing \N — should still succeed with content
        let tokens = tokenize_str("\\Nsome text");
        assert_eq!(
            tokens,
            vec![Token::ProtectedRegion("some text".into()), Token::Eof,]
        );
    }

    #[test]
    fn test_octal_single_digit() {
        // \0 = null char (value 0)
        let tokens = tokenize_str("\\0");
        assert_eq!(tokens, vec![Token::EscapeChar('\0'), Token::Eof]);
    }

    #[test]
    fn test_hex_single_digit() {
        // \x9 = 9
        let tokens = tokenize_str("\\x9");
        assert_eq!(tokens, vec![Token::EscapeChar('\x09'), Token::Eof]);
    }

    #[test]
    fn test_hex_no_digits() {
        // \xQ — no valid hex digits after \x
        let tokens = tokenize_str("\\xQ");
        assert_eq!(
            tokens,
            vec![
                Token::BackslashLiteral('x'),
                Token::Literal("Q".into()),
                Token::Eof,
            ]
        );
    }
}
