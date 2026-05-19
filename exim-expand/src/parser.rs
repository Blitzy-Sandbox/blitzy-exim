// Copyright (c) Exim Maintainers — Rust rewrite.
// SPDX-License-Identifier: GPL-2.0-or-later
//
// exim-expand/src/parser.rs — AST Construction from Token Stream
//
// This module implements the second phase of the tokenizer → parser →
// evaluator pipeline: AST (Abstract Syntax Tree) construction from the
// token stream produced by [`crate::tokenizer`].
//
// # Architecture
//
// The original C code (`expand.c`, 9,210 lines) has no separate parser;
// `expand_string_internal()` simultaneously tokenizes, parses, and
// evaluates in a single monolithic 3,960-line function (lines 4771-8730).
// This module extracts the parsing logic into a clean recursive-descent
// parser that builds typed AST nodes for items, operators, conditions,
// variable references, and literals.
//
// # Source Mapping
//
// | Rust Component            | C Source (expand.c)                          |
// |---------------------------|----------------------------------------------|
// | Escape/literal parsing    | Lines 4800-4858                              |
// | Variable reference parsing| Lines 4860-4968                              |
// | Item parsing              | Lines 5000-7230 (item dispatch)              |
// | Operator parsing          | Lines 7300-7700 (operator dispatch)          |
// | Braced sub-expressions    | Lines 1182-1210 (`read_subs()`)              |
// | Identifier name reading   | Lines 1115-1148 (`read_name()`)              |
// | Header name reading       | Lines 1150-1180 (`read_header_name()`)       |
// | Keyword lookup            | Lines 959-974 (`chop_match()`)               |
//
// # Safety
//
// This module contains **zero `unsafe` blocks** (enforced by the crate-level
// `#![deny(unsafe_code)]` attribute in `lib.rs`).

use crate::tokenizer::{Token, Tokenizer};
use crate::ExpandError;

// ═══════════════════════════════════════════════════════════════════════
//  Header prefix — distinguishes header reference forms
// ═══════════════════════════════════════════════════════════════════════

/// Prefix variant for header field references.
///
/// Exim supports four header reference forms, each producing different
/// output from the same header field:
///
/// | Prefix   | Syntax          | Behaviour                            |
/// |----------|-----------------|--------------------------------------|
/// | Normal   | `$h_` / `$header_`   | RFC 2047 decoded, leading/trailing whitespace trimmed |
/// | Raw      | `$rh_` / `$rheader_` | Raw header value, no decoding        |
/// | Body     | `$bh_` / `$bheader_` | Header body only (after first colon) |
/// | List     | `$lh_` / `$lheader_` | All instances concatenated with `\n` |
///
/// Corresponds to the prefix detection at expand.c lines 4906-4910.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderPrefix {
    /// Standard decoded header: `$h_name:` / `$header_name:`.
    Normal,
    /// Raw (undecoded) header: `$rh_name:` / `$rheader_name:`.
    Raw,
    /// Header body (content after first colon): `$bh_name:` / `$bheader_name:`.
    Body,
    /// All header instances as a list: `$lh_name:` / `$lheader_name:`.
    List,
}

// ═══════════════════════════════════════════════════════════════════════
//  ItemKind — expansion item types
// ═══════════════════════════════════════════════════════════════════════

/// Expansion item types from `item_table[]` (expand.c lines 109-142).
///
/// Each variant maps to an `EITEM_*` enum value in the C code.  Items
/// are syntactically `${item_name{arg1}{arg2}…}` constructs, some of
/// which support optional `{yes}{no}` branches.
///
/// Feature-gated items are always present in the AST — the Cargo feature
/// flag controls whether the *evaluator* can execute them (matching C
/// behavior where `#ifdef` guards are on handler code, not the table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    /// `${acl{name}{arg}}` — ACL evaluation.
    Acl,
    /// `${authresults{servername}}` — authentication results header.
    AuthResults,
    /// `${certextract{field}{cert}}` — X.509 certificate field extraction.
    CertExtract,
    /// `${dlfunc{lib}{func}{…}}` — dynamic shared-library function call.
    /// Gated behind `dlfunc` feature (replaces `#ifdef EXPAND_DLFUNC`).
    Dlfunc,
    /// `${env{name}}` — environment variable lookup.
    Env,
    /// `${extract{field}{…}{string}}` — sub-field extraction.
    Extract,
    /// `${extract json {key}{json_data}}` — JSON value extraction (unquoted).
    ExtractJson,
    /// `${extract jsons{key}{json_data}}` — JSON string extraction (quoted).
    ExtractJsons,
    /// `${filter{list}{condition}{…}}` — list filtering.
    Filter,
    /// `${hash{limit}{prime}{string}}` — hash-bucket mapping.
    Hash,
    /// `${hmac{algorithm}{secret}{data}}` — HMAC computation.
    Hmac,
    /// `${if condition {yes}{no}}` — conditional expansion.
    If,
    /// `${imapfolder{string}}` — IMAP UTF-7 folder name encoding.
    /// Gated behind `i18n` feature (replaces `#ifdef SUPPORT_I18N`).
    ImapFolder,
    /// `${length{limit}{string}}` — string truncation.
    Length,
    /// `${listextract{number}{list}}` — list element by index.
    ListExtract,
    /// `${listquote{separator}{list}}` — list quoting.
    ListQuote,
    /// `${lookup{key} type {source}}` — lookup backend query.
    Lookup,
    /// `${map{variable}{list}{string}}` — list mapping.
    Map,
    /// `${nhash{limit}{prime}{string}}` — numeric hash.
    Nhash,
    /// `${perl{function}{arg}{…}}` — embedded Perl function call.
    /// Gated behind `perl` feature (replaces `#ifndef EXIM_PERL`).
    Perl,
    /// `${prvs{address}{key}{…}}` — BATV PRVS tag generation.
    Prvs,
    /// `${prvscheck{address}{secret}}` — BATV PRVS verification.
    PrvsCheck,
    /// `${readfile{filename}{eol}}` — file content inclusion.
    ReadFile,
    /// `${readsocket{spec}{request}{…}}` — socket read.
    ReadSocket,
    /// `${reduce{variable}{init}{list}{expression}}` — list reduction.
    Reduce,
    /// `${run{command}}` — external command execution.
    Run,
    /// `${sg{subject}{regex}{replacement}}` — regex substitution.
    Sg,
    /// `${sort{variable}{comparator}{list}}` — list sorting.
    Sort,
    /// `${srs_encode{address}{secret}{…}}` — SRS address encoding.
    /// Gated behind `srs` feature (replaces `#ifdef SUPPORT_SRS`).
    SrsEncode,
    /// `${substr{start}{length}{string}}` — substring extraction.
    Substr,
    /// `${tr{subject}{from}{to}}` — character transliteration.
    Tr,
}

// ═══════════════════════════════════════════════════════════════════════
//  OperatorKind — string transformation operators
// ═══════════════════════════════════════════════════════════════════════

/// String transformation operators from `op_table_underscore[]` and
/// `op_table_main[]` (expand.c lines 184-262).
///
/// Operators use the `${operator:subject}` syntax, applying a
/// transformation to their subject expression.  Each variant maps to
/// an `EOP_*` enum value in the C code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatorKind {
    // ── Underscore operators (op_table_underscore, lines 184-197) ────
    /// `${from_utf8:…}` — decode UTF-8 to Latin-1.
    FromUtf8,
    /// `${local_part:…}` — extract local part from address.
    LocalPart,
    /// `${quote_local_part:…}` — RFC 2821 quote local part.
    QuoteLocalPart,
    /// `${reverse_ip:…}` — reverse IP for DNSBL queries.
    ReverseIp,
    /// `${time_eval:…}` — evaluate time expression to epoch seconds.
    TimeEval,
    /// `${time_interval:…}` — format seconds as time interval string.
    TimeInterval,
    /// `${utf8_domain_from_alabel:…}` — ACE to UTF-8 domain.
    /// Gated behind `i18n` feature.
    Utf8DomainFromAlabel,
    /// `${utf8_domain_to_alabel:…}` — UTF-8 to ACE domain.
    /// Gated behind `i18n` feature.
    Utf8DomainToAlabel,
    /// `${utf8_localpart_from_alabel:…}` — ACE to UTF-8 local part.
    /// Gated behind `i18n` feature.
    Utf8LocalpartFromAlabel,
    /// `${utf8_localpart_to_alabel:…}` — UTF-8 to ACE local part.
    /// Gated behind `i18n` feature.
    Utf8LocalpartToAlabel,

    // ── Main operators (op_table_main, lines 214-262) ────────────────
    /// `${address:…}` — extract address from header line.
    Address,
    /// `${addresses:…}` — extract all addresses from header line.
    Addresses,
    /// `${base32:…}` — base-32 encode.
    Base32,
    /// `${base32d:…}` — base-32 decode.
    Base32d,
    /// `${base62:…}` — base-62 encode.
    Base62,
    /// `${base62d:…}` — base-62 decode.
    Base62d,
    /// `${base64:…}` — base-64 encode.
    Base64,
    /// `${base64d:…}` — base-64 decode.
    Base64d,
    /// `${domain:…}` — extract domain from address.
    Domain,
    /// `${escape:…}` — C-style backslash-escape non-printables.
    Escape,
    /// `${escape8bit:…}` — escape characters with high bit set.
    Escape8bit,
    /// `${eval:…}` — integer arithmetic expression evaluation.
    Eval,
    /// `${eval10:…}` — decimal arithmetic evaluation.
    Eval10,
    /// `${expand:…}` — double-expand the subject string.
    Expand,
    /// `${h:…}` — alias for header wrap at 76 columns.
    H,
    /// `${hash:…}` — hash-bucket operator (alias, also exists as item).
    HashOp,
    /// `${headerwrap:…}` — wrap header at 76 columns with continuation.
    Headerwrap,
    /// `${headerwrap_N:…}` or `${headerwrap_N_M:…}` — wrap header at
    /// N columns (or N columns with M max).
    HeaderwrapParam(i64, Option<i64>),
    /// `${hex2b64:…}` — hex to base-64.
    Hex2b64,
    /// `${hexquote:…}` — hex-encode non-printables.
    Hexquote,
    /// `${ipv6denorm:…}` — expand IPv6 to full 8-group notation.
    Ipv6denorm,
    /// `${ipv6norm:…}` — normalise IPv6 to compressed form.
    Ipv6norm,
    /// `${l:…}` — alias for `${lc:…}`.
    L,
    /// `${lc:…}` — lowercase.
    Lc,
    /// `${length:…}` — string length operator (alias, also exists as item).
    LengthOp,
    /// `${listcount:…}` — count elements in a colon-separated list.
    Listcount,
    /// `${listnamed:…}` — retrieve a named list by name.
    Listnamed,
    /// `${listnamed_d:…}` — retrieve a domain named list.
    ListnamedD,
    /// `${listnamed_h:…}` — retrieve a host named list.
    ListnamedH,
    /// `${listnamed_a:…}` — retrieve an address named list.
    ListnamedA,
    /// `${listnamed_l:…}` — retrieve a local_part named list.
    ListnamedL,
    /// `${mask:…}` — apply CIDR mask to IP address.
    Mask,
    /// `${mask_n:…}` — mask with normalized/compressed IPv6 output.
    MaskNorm,
    /// `${mask_N:…}` — apply N-bit CIDR mask to IP address.
    MaskParam(u8),
    /// `${md5:…}` — MD5 hash (hex digest).
    Md5,
    /// `${nh:…}` — alias for numeric hash.
    Nh,
    /// `${nhash:…}` — numeric hash operator (alias, also exists as item).
    Nhash,
    /// `${quote:…}` — shell-safe quoting.
    Quote,
    /// `${quote_TYPE:…}` — lookup-type-specific quoting.
    QuoteLookup(String),
    /// `${randint:…}` — random integer 0..N-1.
    Randint,
    /// `${rfc2047:…}` — RFC 2047 encode.
    Rfc2047,
    /// `${rfc2047d:…}` — RFC 2047 decode.
    Rfc2047d,
    /// `${rxquote:…}` — regex metacharacter quoting.
    Rxquote,
    /// `${s:…}` — alias for `${substr:…}`.
    S,
    /// `${sha1:…}` — SHA-1 hash (hex digest).
    Sha1,
    /// `${sha2:…}` — SHA-256 hash (hex digest).
    Sha2,
    /// `${sha256:…}` — SHA-256 hash (hex digest, alias).
    Sha256,
    /// `${sha3:…}` — SHA-3 hash (hex digest).
    Sha3,
    /// `${stat:…}` — file stat information.
    Stat,
    /// `${str2b64:…}` — string to base-64.
    Str2b64,
    /// `${strlen:…}` — string length (numeric result).
    Strlen,
    /// `${substr:…}` — substring operator (alias, also exists as item).
    SubstrOp,
    /// `${uc:…}` — uppercase.
    Uc,
    /// `${utf8clean:…}` — replace invalid UTF-8 sequences.
    Utf8clean,
    /// `${xtextd:…}` — xtext decode (RFC 3461).
    Xtextd,
}

// ═══════════════════════════════════════════════════════════════════════
//  ConditionType — condition types for ${if …} expressions
// ═══════════════════════════════════════════════════════════════════════

/// Condition types from `cond_table[]` (expand.c lines 318-368).
///
/// Each variant maps to an `ECOND_*` enum value in the C code.
/// Conditions are used in `${if <cond>{yes}{no}}` expressions.
///
/// The first six variants correspond to numeric comparison operators
/// (`<`, `<=`, `=`, `==`, `>`, `>=`); the rest are alphabetic keywords.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionType {
    // ── Numeric comparison operators (cond_table lines 318-323) ─────
    /// `<` — numeric less-than.
    NumLess,
    /// `<=` — numeric less-than-or-equal.
    NumLessEq,
    /// `=` — numeric equality.
    NumEqual,
    /// `==` — numeric equality (backward compatibility alias).
    NumEqualEq,
    /// `>` — numeric greater-than.
    NumGreater,
    /// `>=` — numeric greater-than-or-equal.
    NumGreaterEq,

    // ── Alphabetic condition keywords (cond_table lines 325-367) ────
    /// `acl` — evaluate an ACL and test result.
    Acl,
    /// `and` — logical AND of sub-conditions.
    And,
    /// `bool` — strict boolean test (only `true`/`false`/`yes`/`no`).
    Bool,
    /// `bool_lax` — lax boolean test (empty/`0` = false, else true).
    BoolLax,
    /// `crypteq` — password hash comparison.
    Crypteq,
    /// `def` — test whether a variable is defined.
    Def,
    /// `eq` — case-sensitive string equality.
    StrEq,
    /// `eqi` — case-insensitive string equality.
    StrEqi,
    /// `exists` — test file/directory existence.
    Exists,
    /// `first_delivery` — true on first delivery attempt.
    FirstDelivery,
    /// `forall` — test condition against all list elements.
    ForAll,
    /// `forall_json` — `forall` over JSON array.
    ForAllJson,
    /// `forall_jsons` — `forall` over JSON array (string values).
    ForAllJsons,
    /// `forany` — test condition against any list element.
    ForAny,
    /// `forany_json` — `forany` over JSON array.
    ForAnyJson,
    /// `forany_jsons` — `forany` over JSON array (string values).
    ForAnyJsons,
    /// `ge` — case-sensitive string greater-or-equal.
    StrGe,
    /// `gei` — case-insensitive string greater-or-equal.
    StrGei,
    /// `gt` — case-sensitive string greater-than.
    StrGt,
    /// `gti` — case-insensitive string greater-than.
    StrGti,
    /// `inbound_srs` — test inbound SRS address.
    /// Gated behind `srs` feature.
    InboundSrs,
    /// `inlist` — test if string is in a named list.
    InList,
    /// `inlisti` — case-insensitive `inlist`.
    InListi,
    /// `isip` — test if string is a valid IP address.
    IsIp,
    /// `isip4` — test if string is a valid IPv4 address.
    IsIp4,
    /// `isip6` — test if string is a valid IPv6 address.
    IsIp6,
    /// `ldapauth` — LDAP bind authentication.
    LdapAuth,
    /// `le` — case-sensitive string less-or-equal.
    StrLe,
    /// `lei` — case-insensitive string less-or-equal.
    StrLei,
    /// `lt` — case-sensitive string less-than.
    StrLt,
    /// `lti` — case-insensitive string less-than.
    StrLti,
    /// `match` — regex match.
    Match,
    /// `match_address` — match against address list.
    MatchAddress,
    /// `match_domain` — match against domain list.
    MatchDomain,
    /// `match_ip` — match against IP list.
    MatchIp,
    /// `match_local_part` — match against local part list.
    MatchLocalPart,
    /// `or` — logical OR of sub-conditions.
    Or,
    /// `pam` — PAM authentication check.
    Pam,
    /// `queue_running` — true if queue runner is active.
    QueueRunning,
    /// `radius` — RADIUS authentication check.
    Radius,
    /// `saslauthd` — saslauthd authentication check.
    Saslauthd,
}

// ═══════════════════════════════════════════════════════════════════════
//  AST nodes and supporting structures
// ═══════════════════════════════════════════════════════════════════════

/// A reference to an expansion variable (`$name` or `${name}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableRef {
    /// The variable name (e.g. `"local_part"`, `"domain"`,
    /// `"sender_address"`).
    pub name: String,
    /// `true` if the variable was referenced in braced form `${name}`,
    /// `false` if bare `$name`.
    pub braced: bool,
}

impl std::fmt::Display for VariableRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.braced {
            write!(f, "${{{}}}", self.name)
        } else {
            write!(f, "${}", self.name)
        }
    }
}

/// A parsed condition expression used inside `${if …}` items.
///
/// The condition may be negated with a leading `!` prefix, has a
/// typed discriminant, and carries zero or more operands as AST nodes.
/// The evaluator interprets operands according to the condition type.
#[derive(Debug, Clone, PartialEq)]
pub struct ConditionNode {
    /// `true` when the condition was preceded by `!` (negation).
    pub negated: bool,
    /// The condition type discriminant.
    pub condition_type: ConditionType,
    /// Operands for the condition (0, 1, 2, or more depending on type).
    pub operands: Vec<AstNode>,
    /// Sub-conditions for `and`/`or` compound conditions.
    ///
    /// In C Exim, `and{...}` and `or{...}` read a single brace-enclosed
    /// block containing multiple `{subcondition}` sub-blocks.  Each
    /// sub-condition is a complete condition expression.
    pub sub_conditions: Vec<ConditionNode>,
}

/// Abstract Syntax Tree node for Exim expansion strings.
///
/// Each variant maps to a syntactic construct in the Exim expansion
/// language.  The parser produces a tree of these nodes from the token
/// stream; the evaluator walks the tree to produce the expanded string.
///
/// # Variant Mapping
///
/// | Variant       | Exim Syntax                      |
/// |---------------|----------------------------------|
/// | `Literal`     | Plain text                       |
/// | `Escape`      | `\n`, `\t`, `\xHH`, `\0NNN`     |
/// | `Protected`   | `\N…\N`                          |
/// | `Variable`    | `$name` / `${name}`              |
/// | `HeaderRef`   | `$h_name:` / `$rh_name:` / etc.  |
/// | `AclVariable` | `$acl_c0`…`$acl_m_*`             |
/// | `AuthVariable`| `$auth1`…`$auth3`                |
/// | `Item`        | `${item{arg}…}`                  |
/// | `Operator`    | `${op:subject}`                  |
/// | `Conditional` | `${if cond {yes}{no}}`           |
/// | `Sequence`    | Adjacent nodes concatenated      |
#[derive(Debug, Clone, PartialEq)]
pub enum AstNode {
    /// Literal text to be appended to output unchanged.
    Literal(String),

    /// Backslash escape sequence (`\n`, `\t`, `\r`, `\0NNN`, `\xHH`, etc.).
    Escape(char),

    /// Protected region `\N…\N` — content copied verbatim, no expansion.
    Protected(String),

    /// Variable reference: `$name` or `${name}`.
    Variable(VariableRef),

    /// Header field reference: `$h_name:`, `$rh_name:`, `$bh_name:`,
    /// `$lh_name:`.
    HeaderRef {
        /// The header reference prefix variant.
        prefix: HeaderPrefix,
        /// The header field name (without prefix or trailing colon).
        name: String,
    },

    /// ACL variable reference: `$acl_c0`…`$acl_c9`, `$acl_m0`…`$acl_m9`,
    /// `$acl_m_*`.
    AclVariable(String),

    /// Authentication variable reference: `$auth1`, `$auth2`, `$auth3`.
    AuthVariable(u8),

    /// Expansion item: `${item_name{arg1}{arg2}…{yes}{no}}`.
    Item {
        /// The item type discriminant.
        kind: ItemKind,
        /// Brace-delimited arguments (count varies by item).
        args: Vec<AstNode>,
        /// Optional success branch `{yes_string}`.
        yes_branch: Option<Box<AstNode>>,
        /// Optional failure branch `{no_string}`.
        no_branch: Option<Box<AstNode>>,
        /// When true, a bare `fail` keyword was present after the
        /// yes-branch, causing forced failure when the item produces
        /// no result (C Exim expand.c line 3107).
        fail_force: bool,
    },

    /// Operator/transform: `${operator:subject}`.
    Operator {
        /// The operator type discriminant.
        kind: OperatorKind,
        /// The subject expression to which the operator is applied.
        subject: Box<AstNode>,
    },

    /// Conditional expression: `${if condition {yes}{no}}`.
    Conditional {
        /// The parsed condition with type and operands.
        condition: Box<ConditionNode>,
        /// The "yes" / success branch.  `None` when the caller used the
        /// bare `${if condition}` form (no braces at all) — the evaluator
        /// returns the literal string `"true"` when the condition is true
        /// and an empty string when false.
        yes_branch: Option<Box<AstNode>>,
        /// Optional "no" / failure branch.
        no_branch: Option<Box<AstNode>>,
        /// When `true`, the bare `fail` keyword was used after the
        /// yes-branch, causing forced failure when the condition is false.
        fail_force: bool,
    },

    /// A sequence of adjacent AST nodes that are concatenated in order.
    Sequence(Vec<AstNode>),
}

// ═══════════════════════════════════════════════════════════════════════
//  Name-to-kind lookup tables and functions
// ═══════════════════════════════════════════════════════════════════════
//
// These replace the C `chop_match()` function (expand.c lines 959-974)
// which performed binary search on sorted name tables.  The Rust
// implementation uses match arms on small sorted string sets — the
// tables are small enough that the compiler generates optimal code.
// Tables MUST be kept in alphabetical order for documentation clarity
// and parity with the C source.

/// Map an item keyword string to its [`ItemKind`] discriminant.
///
/// The lookup table matches `item_table[]` (expand.c lines 109-142).
/// Returns `None` for unrecognised names.
/// Map an [`ItemKind`] back to its canonical lowercase name string.
pub fn item_kind_to_name(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::Acl => "acl",
        ItemKind::AuthResults => "authresults",
        ItemKind::CertExtract => "certextract",
        ItemKind::Dlfunc => "dlfunc",
        ItemKind::Env => "env",
        ItemKind::Extract => "extract",
        ItemKind::ExtractJson => "extract json",
        ItemKind::ExtractJsons => "extract jsons",
        ItemKind::Filter => "filter",
        ItemKind::Hash => "hash",
        ItemKind::Hmac => "hmac",
        ItemKind::If => "if",
        ItemKind::ImapFolder => "imapfolder",
        ItemKind::Length => "length",
        ItemKind::ListExtract => "listextract",
        ItemKind::ListQuote => "listquote",
        ItemKind::Lookup => "lookup",
        ItemKind::Map => "map",
        ItemKind::Nhash => "nhash",
        ItemKind::Perl => "perl",
        ItemKind::Prvs => "prvs",
        ItemKind::PrvsCheck => "prvscheck",
        ItemKind::ReadFile => "readfile",
        ItemKind::ReadSocket => "readsocket",
        ItemKind::Reduce => "reduce",
        ItemKind::Run => "run",
        ItemKind::Sg => "sg",
        ItemKind::Sort => "sort",
        ItemKind::SrsEncode => "srs_encode",
        ItemKind::Substr => "substr",
        ItemKind::Tr => "tr",
    }
}

/// Map a keyword string to its [`ItemKind`] discriminant.
///
/// Returns `None` for unrecognised names.
pub fn item_name_to_kind(name: &str) -> Option<ItemKind> {
    match name {
        "acl" => Some(ItemKind::Acl),
        "authresults" => Some(ItemKind::AuthResults),
        "certextract" => Some(ItemKind::CertExtract),
        "dlfunc" => Some(ItemKind::Dlfunc),
        "env" => Some(ItemKind::Env),
        "extract" => Some(ItemKind::Extract),
        "filter" => Some(ItemKind::Filter),
        "h" | "hash" => Some(ItemKind::Hash),
        "hmac" => Some(ItemKind::Hmac),
        "if" => Some(ItemKind::If),
        "imapfolder" => Some(ItemKind::ImapFolder),
        "l" | "length" => Some(ItemKind::Length),
        "listextract" => Some(ItemKind::ListExtract),
        "listquote" => Some(ItemKind::ListQuote),
        "lookup" => Some(ItemKind::Lookup),
        "map" => Some(ItemKind::Map),
        "nh" | "nhash" => Some(ItemKind::Nhash),
        "perl" => Some(ItemKind::Perl),
        "prvs" => Some(ItemKind::Prvs),
        "prvscheck" => Some(ItemKind::PrvsCheck),
        "readfile" => Some(ItemKind::ReadFile),
        "readsocket" => Some(ItemKind::ReadSocket),
        "reduce" => Some(ItemKind::Reduce),
        "run" => Some(ItemKind::Run),
        "s" | "substr" => Some(ItemKind::Substr),
        "sg" => Some(ItemKind::Sg),
        "sort" => Some(ItemKind::Sort),
        "srs_encode" => Some(ItemKind::SrsEncode),
        "tr" => Some(ItemKind::Tr),
        _ => None,
    }
}

/// Map an operator keyword string to its [`OperatorKind`] discriminant.
///
/// Searches both underscore operators (`op_table_underscore`, expand.c
/// lines 184-197) and main operators (`op_table_main`, lines 214-262).
/// Returns `None` for unrecognised names.
pub fn operator_name_to_kind(name: &str) -> Option<OperatorKind> {
    match name {
        // ── Underscore operators ──
        "from_utf8" => Some(OperatorKind::FromUtf8),
        "local_part" => Some(OperatorKind::LocalPart),
        "quote_local_part" => Some(OperatorKind::QuoteLocalPart),
        "reverse_ip" => Some(OperatorKind::ReverseIp),
        "time_eval" => Some(OperatorKind::TimeEval),
        "time_interval" => Some(OperatorKind::TimeInterval),
        "utf8_domain_from_alabel" => Some(OperatorKind::Utf8DomainFromAlabel),
        "utf8_domain_to_alabel" => Some(OperatorKind::Utf8DomainToAlabel),
        "utf8_localpart_from_alabel" => Some(OperatorKind::Utf8LocalpartFromAlabel),
        "utf8_localpart_to_alabel" => Some(OperatorKind::Utf8LocalpartToAlabel),
        // ── Main operators ──
        "address" => Some(OperatorKind::Address),
        "addresses" => Some(OperatorKind::Addresses),
        "base32" => Some(OperatorKind::Base32),
        "base32d" => Some(OperatorKind::Base32d),
        "base62" => Some(OperatorKind::Base62),
        "base62d" => Some(OperatorKind::Base62d),
        "base64" => Some(OperatorKind::Base64),
        "base64d" => Some(OperatorKind::Base64d),
        "domain" => Some(OperatorKind::Domain),
        "escape" => Some(OperatorKind::Escape),
        "escape8bit" => Some(OperatorKind::Escape8bit),
        "eval" => Some(OperatorKind::Eval),
        "eval10" => Some(OperatorKind::Eval10),
        "expand" => Some(OperatorKind::Expand),
        "h" => Some(OperatorKind::H),
        "hash" => Some(OperatorKind::HashOp),
        "headerwrap" => Some(OperatorKind::Headerwrap),
        "hex2b64" => Some(OperatorKind::Hex2b64),
        "hexquote" => Some(OperatorKind::Hexquote),
        "ipv6denorm" => Some(OperatorKind::Ipv6denorm),
        "ipv6norm" => Some(OperatorKind::Ipv6norm),
        "l" => Some(OperatorKind::L),
        "lc" => Some(OperatorKind::Lc),
        "length" => Some(OperatorKind::LengthOp),
        "listcount" => Some(OperatorKind::Listcount),
        "listnamed" => Some(OperatorKind::Listnamed),
        "listnamed_d" => Some(OperatorKind::ListnamedD),
        "listnamed_h" => Some(OperatorKind::ListnamedH),
        "listnamed_a" => Some(OperatorKind::ListnamedA),
        "listnamed_l" => Some(OperatorKind::ListnamedL),
        "mask" => Some(OperatorKind::Mask),
        "mask_n" => Some(OperatorKind::MaskNorm),
        "md5" => Some(OperatorKind::Md5),
        "nh" => Some(OperatorKind::Nh),
        "nhash" => Some(OperatorKind::Nhash),
        "quote" => Some(OperatorKind::Quote),
        "randint" => Some(OperatorKind::Randint),
        "rfc2047" => Some(OperatorKind::Rfc2047),
        "rfc2047d" => Some(OperatorKind::Rfc2047d),
        "rxquote" => Some(OperatorKind::Rxquote),
        "s" => Some(OperatorKind::S),
        "sha1" => Some(OperatorKind::Sha1),
        "sha2" => Some(OperatorKind::Sha2),
        "sha256" => Some(OperatorKind::Sha256),
        "sha3" => Some(OperatorKind::Sha3),
        "stat" => Some(OperatorKind::Stat),
        "str2b64" => Some(OperatorKind::Str2b64),
        "strlen" => Some(OperatorKind::Strlen),
        "substr" => Some(OperatorKind::SubstrOp),
        "uc" => Some(OperatorKind::Uc),
        "utf8clean" => Some(OperatorKind::Utf8clean),
        "xtextd" => Some(OperatorKind::Xtextd),
        _ => {
            // Check for quote_TYPE pattern (lookup-type-specific quoting)
            name.strip_prefix("quote_")
                .map(|lookup_type| OperatorKind::QuoteLookup(lookup_type.to_string()))
        }
    }
}

/// Map a condition keyword string to its [`ConditionType`] discriminant.
///
/// Covers both symbolic operators (`<`, `<=`, `=`, `==`, `>`, `>=`)
/// and alphabetic keywords from `cond_table[]` (expand.c lines 318-368).
/// Returns `None` for unrecognised names.
pub fn condition_name_to_type(name: &str) -> Option<ConditionType> {
    match name {
        // ── Numeric comparison operators ──
        "<" => Some(ConditionType::NumLess),
        "<=" => Some(ConditionType::NumLessEq),
        "=" => Some(ConditionType::NumEqual),
        "==" => Some(ConditionType::NumEqualEq),
        ">" => Some(ConditionType::NumGreater),
        ">=" => Some(ConditionType::NumGreaterEq),
        // ── Alphabetic keywords ──
        "acl" => Some(ConditionType::Acl),
        "and" => Some(ConditionType::And),
        "bool" => Some(ConditionType::Bool),
        "bool_lax" => Some(ConditionType::BoolLax),
        "crypteq" => Some(ConditionType::Crypteq),
        "def" => Some(ConditionType::Def),
        "eq" => Some(ConditionType::StrEq),
        "eqi" => Some(ConditionType::StrEqi),
        "exists" => Some(ConditionType::Exists),
        "first_delivery" => Some(ConditionType::FirstDelivery),
        "forall" => Some(ConditionType::ForAll),
        "forall_json" => Some(ConditionType::ForAllJson),
        "forall_jsons" => Some(ConditionType::ForAllJsons),
        "forany" => Some(ConditionType::ForAny),
        "forany_json" => Some(ConditionType::ForAnyJson),
        "forany_jsons" => Some(ConditionType::ForAnyJsons),
        "ge" => Some(ConditionType::StrGe),
        "gei" => Some(ConditionType::StrGei),
        "gt" => Some(ConditionType::StrGt),
        "gti" => Some(ConditionType::StrGti),
        "inbound_srs" => Some(ConditionType::InboundSrs),
        "inlist" => Some(ConditionType::InList),
        "inlisti" => Some(ConditionType::InListi),
        "isip" => Some(ConditionType::IsIp),
        "isip4" => Some(ConditionType::IsIp4),
        "isip6" => Some(ConditionType::IsIp6),
        "ldapauth" => Some(ConditionType::LdapAuth),
        "le" => Some(ConditionType::StrLe),
        "lei" => Some(ConditionType::StrLei),
        "lt" => Some(ConditionType::StrLt),
        "lti" => Some(ConditionType::StrLti),
        "match" => Some(ConditionType::Match),
        "match_address" => Some(ConditionType::MatchAddress),
        "match_domain" => Some(ConditionType::MatchDomain),
        "match_ip" => Some(ConditionType::MatchIp),
        "match_local_part" => Some(ConditionType::MatchLocalPart),
        "or" => Some(ConditionType::Or),
        "pam" => Some(ConditionType::Pam),
        "queue_running" => Some(ConditionType::QueueRunning),
        "radius" => Some(ConditionType::Radius),
        "saslauthd" => Some(ConditionType::Saslauthd),
        _ => None,
    }
}

/// Return the number of brace-delimited operands expected for a
/// condition type.
///
/// This guides the parser in determining how many `{expr}` blocks
/// to consume before yielding control back to the item parser for
/// yes/no branches.
fn condition_operand_count(ctype: &ConditionType) -> usize {
    match ctype {
        // Zero operands — flag/state checks.
        ConditionType::FirstDelivery | ConditionType::QueueRunning => 0,

        // One operand — test a single expression.
        ConditionType::Bool
        | ConditionType::BoolLax
        | ConditionType::Def
        | ConditionType::Exists
        | ConditionType::IsIp
        | ConditionType::IsIp4
        | ConditionType::IsIp6
        | ConditionType::LdapAuth
        | ConditionType::Pam
        | ConditionType::Radius => 1,

        // Two operands — comparisons, matching, lists, iterators.
        ConditionType::NumLess
        | ConditionType::NumLessEq
        | ConditionType::NumEqual
        | ConditionType::NumEqualEq
        | ConditionType::NumGreater
        | ConditionType::NumGreaterEq
        | ConditionType::StrEq
        | ConditionType::StrEqi
        | ConditionType::StrGe
        | ConditionType::StrGei
        | ConditionType::StrGt
        | ConditionType::StrGti
        | ConditionType::StrLe
        | ConditionType::StrLei
        | ConditionType::StrLt
        | ConditionType::StrLti
        | ConditionType::Match
        | ConditionType::MatchAddress
        | ConditionType::MatchDomain
        | ConditionType::MatchIp
        | ConditionType::MatchLocalPart
        | ConditionType::Crypteq
        | ConditionType::InList
        | ConditionType::InListi
        | ConditionType::InboundSrs
        | ConditionType::Acl
        | ConditionType::ForAll
        | ConditionType::ForAny
        | ConditionType::ForAllJson
        | ConditionType::ForAnyJson
        | ConditionType::ForAllJsons
        | ConditionType::ForAnyJsons => 2,

        // And/Or — one brace block containing multiple sub-conditions.
        ConditionType::And | ConditionType::Or => 1,

        // Saslauthd — four operands (user, password, service, realm).
        ConditionType::Saslauthd => 4,
    }
}

/// Return the number of brace-delimited arguments and whether yes/no
/// branches follow for a given item kind.
///
/// Returns `(min_args, max_args, has_yes_no)`.  Items with variable
/// argument counts use `max_args = usize::MAX` to indicate greedy
/// collection up to a sane limit.
fn item_arg_spec(kind: &ItemKind) -> (usize, usize, bool) {
    match kind {
        ItemKind::Acl => (1, 10, true),
        ItemKind::AuthResults => (1, 1, false),
        ItemKind::CertExtract => (2, 2, true),
        ItemKind::Dlfunc => (2, usize::MAX, false),
        ItemKind::Env => (1, 1, true),
        ItemKind::Extract => (2, 3, true),
        ItemKind::ExtractJson => (2, 2, true),
        ItemKind::ExtractJsons => (2, 2, true),
        ItemKind::Filter => (2, 2, false),
        ItemKind::Hash => (2, 3, false),
        ItemKind::Hmac => (3, 3, false),
        ItemKind::If => (0, 0, false), // special-cased via parse_conditional_item
        ItemKind::ImapFolder => (1, 1, false),
        ItemKind::Length => (2, 2, false),
        ItemKind::ListExtract => (2, 2, true),
        ItemKind::ListQuote => (2, 2, false),
        ItemKind::Lookup => (0, 0, false), // special-cased via parse_lookup_item
        ItemKind::Map => (2, 2, false),
        ItemKind::Nhash => (2, 3, false),
        ItemKind::Perl => (1, usize::MAX, false),
        ItemKind::Prvs => (2, 3, false),
        ItemKind::PrvsCheck => (2, 3, false),
        ItemKind::ReadFile => (1, 2, false),
        ItemKind::ReadSocket => (1, 5, false),
        ItemKind::Reduce => (3, 3, false),
        ItemKind::Run => (1, 1, true),
        ItemKind::Sg => (3, 3, false),
        ItemKind::Sort => (2, 3, false),
        ItemKind::SrsEncode => (3, 3, false),
        ItemKind::Substr => (3, 3, false),
        ItemKind::Tr => (3, 3, false),
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Header prefix detection helpers
// ═══════════════════════════════════════════════════════════════════════

/// Header prefix strings and their corresponding enum variants.
///
/// Each entry is `(prefix_str, variant)` where `prefix_str` includes
/// the trailing underscore. Ordered shortest-first within each category
/// to prefer longer matches (we check all and pick the longest).
const HEADER_PREFIX_TABLE: &[(&str, HeaderPrefix)] = &[
    ("bh_", HeaderPrefix::Body),
    ("bheader_", HeaderPrefix::Body),
    ("h_", HeaderPrefix::Normal),
    ("header_", HeaderPrefix::Normal),
    ("lh_", HeaderPrefix::List),
    ("lheader_", HeaderPrefix::List),
    ("rh_", HeaderPrefix::Raw),
    ("rheader_", HeaderPrefix::Raw),
];

/// Try to match a header prefix at the start of `name`.
///
/// Returns `Some((prefix, remaining_name))` if `name` starts with a
/// known header prefix, or `None` otherwise.  When multiple prefixes
/// match (e.g. `h_` and `header_`), the longest match wins.
fn try_header_prefix(name: &str) -> Option<(HeaderPrefix, &str)> {
    let lower = name.to_ascii_lowercase();
    let mut best: Option<(HeaderPrefix, usize)> = None;
    for &(prefix_str, ref variant) in HEADER_PREFIX_TABLE {
        if lower.starts_with(prefix_str) {
            let plen = prefix_str.len();
            if best.as_ref().is_none_or(|(_, bl)| plen > *bl) {
                best = Some((variant.clone(), plen));
            }
        }
    }
    best.map(|(variant, plen)| (variant, &name[plen..]))
}

// Returns `true` if `name` starts with a recognised header prefix.
//
// Used by the braced-expression parser to distinguish `${h_subject:}`
// (header reference — colon terminates the name) from `${unknown_op:…}`
// (unknown operator — colon separates operator from subject).

// ═══════════════════════════════════════════════════════════════════════
//  Parser — recursive-descent AST construction
// ═══════════════════════════════════════════════════════════════════════

/// Result type for yes/no branch parsing — `(optional_yes, optional_no)`.
/// Tuple type for parsed yes/no branches and optional `fail` keyword.
/// `(yes_branch, no_branch, fail_force)`
type YesNoBranches = (Option<Box<AstNode>>, Option<Box<AstNode>>, bool);

/// Recursive-descent parser that builds an [`AstNode`] tree from a
/// token stream produced by [`crate::tokenizer::Tokenizer`].
///
/// The parser consumes the token stream left-to-right, tracking its
/// position with an index into the token vector.  All public methods
/// return `Result<…, ExpandError>` where [`ExpandError::Failed`]
/// indicates a malformed token sequence.
///
/// # Construction
///
/// Use [`Parser::new`] to create a parser from a raw input string
/// (tokenization is performed internally), or [`Parser::from_tokens`]
/// to parse a pre-tokenized token vector.
///
/// # Thread Safety
///
/// `Parser` is not `Sync` — it carries mutable state (`position`).
/// This matches the C expansion model where parsing is single-threaded
/// within each forked connection process.
pub struct Parser {
    /// The token stream to parse (owned, extracted from SpannedTokens).
    tokens: Vec<Token>,
    /// Current read position (index) into the token vector.
    position: usize,
    /// Tokenization error deferred until parse() is called.
    tokenizer_error: Option<ExpandError>,
    /// Mirrors C Exim's `malformed_header` flag (expand.c line 868).
    /// Set when a header variable name consumed characters that look
    /// like expression syntax (e.g. braces), indicating the header
    /// name was probably not terminated by a colon.
    pub malformed_header: bool,
}

impl Parser {
    // ─── Constructors ───────────────────────────────────────────────

    /// Create a new parser that tokenizes and parses `input`.
    ///
    /// This is the primary constructor used by `lib.rs`:
    /// ```ignore
    /// let mut parser = Parser::new(input);
    /// let ast = parser.parse()?;
    /// ```
    /// Creates a parser from an input string.
    ///
    /// Tokenization errors are stored and re-raised on first `parse()` call.
    pub fn new(input: &str) -> Self {
        let mut tokenizer = Tokenizer::new(input);
        match tokenizer.tokenize() {
            Ok(spanned) => {
                let tokens: Vec<Token> = spanned.into_iter().map(|st| st.token).collect();
                Self {
                    tokens,
                    position: 0,
                    tokenizer_error: None,
                    malformed_header: tokenizer.malformed_header,
                }
            }
            Err(e) => {
                // Store the error to re-raise on parse()
                Self {
                    tokens: vec![Token::Eof],
                    position: 0,
                    tokenizer_error: Some(e),
                    malformed_header: tokenizer.malformed_header,
                }
            }
        }
    }

    /// Create a parser from a pre-tokenized token vector.
    ///
    /// The vector should end with [`Token::Eof`].  If it does not,
    /// an `Eof` sentinel is appended automatically.
    pub fn from_tokens(mut tokens: Vec<Token>) -> Self {
        if tokens.last() != Some(&Token::Eof) {
            tokens.push(Token::Eof);
        }
        Self {
            tokens,
            position: 0,
            tokenizer_error: None,
            malformed_header: false,
        }
    }

    // ─── Token stream navigation ────────────────────────────────────

    /// Peek at the current token without consuming it.
    #[inline]
    fn peek(&self) -> &Token {
        self.tokens.get(self.position).unwrap_or(&Token::Eof)
    }

    /// Consume and return the current token, advancing the position.
    fn advance(&mut self) -> Token {
        let tok = self
            .tokens
            .get(self.position)
            .cloned()
            .unwrap_or(Token::Eof);
        if tok != Token::Eof {
            self.position += 1;
        }
        tok
    }

    /// Consume and discard any leading whitespace-only
    /// [`Token::Literal`] tokens.
    fn skip_whitespace_literals(&mut self) {
        loop {
            if let Token::Literal(ref s) = *self.peek() {
                if s.chars().all(char::is_whitespace) {
                    self.advance();
                    continue;
                }
            }
            break;
        }
    }

    /// Produce an [`ExpandError::Failed`] with a descriptive message.
    fn error(&self, message: impl Into<String>) -> ExpandError {
        ExpandError::Failed {
            message: message.into(),
        }
    }

    /// Reconstruct a truncated raw-text preview of the token stream
    /// from the current position, matching C Exim's 16-char snippet
    /// style used in error diagnostics.
    fn peek_text_preview(&self, max_chars: usize) -> String {
        let mut buf = String::new();
        let mut pos = self.position;
        while buf.len() < max_chars {
            let tok = self.tokens.get(pos).unwrap_or(&Token::Eof);
            let frag = match tok {
                Token::Literal(s) => s.clone(),
                Token::Identifier(s) => s.clone(),
                Token::ConditionKeyword(s) => s.clone(),
                Token::ItemKeyword(s) => s.clone(),
                Token::OperatorKeyword(s) => s.clone(),
                Token::OpenBrace => "{".to_string(),
                Token::CloseBrace => "}".to_string(),
                Token::Dollar => "$".to_string(),
                Token::Colon => ":".to_string(),
                Token::Eof => break,
                _ => format!("{:?}", tok),
            };
            buf.push_str(&frag);
            pos += 1;
        }
        if buf.len() > max_chars {
            buf.truncate(max_chars);
        }
        buf
    }

    /// Build a preview of the remaining token stream for inclusion in
    /// error messages (e.g. curly-bracket problem diagnostics).
    ///
    /// Behaves like [`peek_text_preview`] but with an arbitrary length
    /// cap and always starting from the current parser position.
    fn remaining_text_preview(&self, max_chars: usize) -> String {
        self.peek_text_preview(max_chars)
    }

    /// Produce the correct "unknown expansion operator" error for an
    /// identifier followed by `:` inside `${ … }`.
    ///
    /// C Exim (expand.c §7370-7410) distinguishes two sub-cases:
    ///
    /// 1. The prefix before the first `_` is a known main-table operator
    ///    that does NOT support `_arg` → error includes "(\"prefix\"
    ///    does not take an _arg)".
    /// 2. Everything else → plain "unknown expansion operator \"name\"".
    fn make_unknown_operator_error(&self, name: &str) -> ExpandError {
        // Operators that support underscore arguments (C: case list
        // at expand.c ~7393-7404).
        const ACCEPTS_ARG: &[&str] = &[
            "sha2",
            "sha256",
            "sha3",
            "headerwrap",
            "listnamed",
            "mask",
            "quote",
            "quote_local_part",
            "length",
            "l",
            "substr",
            "s",
            "hash",
            "h",
            "nhash",
            "nh",
        ];

        // Special case: listnamed with bad suffix → C Exim returns
        // "bad suffix on "list" operator" (expand.c ~7378).
        if let Some(suffix) = name.strip_prefix("listnamed_") {
            if !matches!(suffix, "d" | "h" | "a" | "l") {
                return ExpandError::Failed {
                    message: "bad suffix on \"list\" operator".into(),
                };
            }
        }

        if let Some(underscore_pos) = name.find('_') {
            let prefix = &name[..underscore_pos];
            // Check if the prefix IS a known main-table operator
            if operator_name_to_kind(prefix).is_some() {
                // Prefix is known — does it accept _arg?
                if !ACCEPTS_ARG.contains(&prefix) {
                    return ExpandError::Failed {
                        message: format!(
                            "unknown expansion operator \"{}\" (\"{}\" does not take an _arg)",
                            name, prefix
                        ),
                    };
                }
                // Known prefix that accepts args — shouldn't normally
                // reach here because such forms go through
                // ParametricOperator, but fall through to generic error.
            }
        }

        ExpandError::Failed {
            message: format!("unknown expansion operator \"{}\"", name),
        }
    }

    // ─── Primary parsing entry points ───────────────────────────────

    /// Parse the entire token stream into an AST.
    ///
    /// This is the main entry point called by `lib.rs`.  It parses the
    /// complete input and returns a single [`AstNode`] (which may be a
    /// [`Sequence`](AstNode::Sequence) of sub-nodes).
    pub fn parse(&mut self) -> Result<AstNode, ExpandError> {
        // Re-raise deferred tokenizer error if present
        if let Some(e) = self.tokenizer_error.take() {
            return Err(e);
        }
        let node = self.parse_sequence()?;
        Ok(node)
    }

    /// Parse a sequence of tokens until EOF or a closing brace `}`.
    ///
    /// Collects adjacent nodes and wraps them in
    /// [`AstNode::Sequence`] if there are multiple, or returns the
    /// single node directly.  An empty sequence yields
    /// `AstNode::Literal("")`.
    ///
    /// The closing brace is **not** consumed — the caller is
    /// responsible for consuming it when appropriate.
    pub fn parse_sequence(&mut self) -> Result<AstNode, ExpandError> {
        self.parse_sequence_inner(false)
    }

    /// Parse a sequence of nodes until `Eof` or `CloseBrace`.
    ///
    /// When `inside_braces` is true (i.e. we are inside a `{…}` delimited
    /// argument), bare `{` is tracked for brace-nesting depth so that the
    /// correct closing `}` is matched.  When `inside_braces` is false
    /// (top-level input), bare `{` and `}` are treated as literal text per
    /// C Exim's expansion loop behaviour.
    pub fn parse_sequence_inner(&mut self, _inside_braces: bool) -> Result<AstNode, ExpandError> {
        let mut nodes: Vec<AstNode> = Vec::new();
        // Track whether the last emitted node was a literal `$` from a
        // `\$` escape.  If so, the next `{` should be literal text (not
        // the start of a grouped expression), matching C Exim behaviour
        // where `\$` prevents expansion of the following characters.
        let mut prev_was_escaped_dollar = false;

        loop {
            match self.peek().clone() {
                Token::Eof => break,
                Token::CloseBrace => break,
                Token::Literal(s) => {
                    self.advance();
                    nodes.push(AstNode::Literal(s));
                    prev_was_escaped_dollar = false;
                }
                Token::EscapeChar(c) => {
                    self.advance();
                    nodes.push(AstNode::Escape(c));
                    prev_was_escaped_dollar = false;
                }
                Token::BackslashLiteral(c) => {
                    self.advance();
                    nodes.push(AstNode::Escape(c));
                    prev_was_escaped_dollar = c == '$';
                }
                Token::ProtectedRegion(s) => {
                    self.advance();
                    nodes.push(AstNode::Protected(s));
                    prev_was_escaped_dollar = false;
                }
                Token::Dollar => {
                    let node = self.parse_dollar_expression()?;
                    nodes.push(node);
                    prev_was_escaped_dollar = false;
                }
                Token::OpenBrace => {
                    if prev_was_escaped_dollar {
                        // After `\$`, treat `{` as literal text, but
                        // `$variable` references inside are still expanded
                        // (matching C Exim behavior where `\$` just outputs
                        // a literal `$` then scanning continues normally).
                        // So `\${before $acl_m0 after}` → `${before EXPANDED after}`.
                        self.advance(); // consume `{`
                        let mut text = String::from("{");
                        let mut depth = 1u32;
                        while depth > 0 && self.peek() != &Token::Eof {
                            match self.peek().clone() {
                                Token::Dollar => {
                                    // Flush accumulated literal text
                                    if !text.is_empty() {
                                        nodes.push(AstNode::Literal(text.clone()));
                                        text.clear();
                                    }
                                    // Parse the dollar expression normally
                                    // so that $var inside \${...} is expanded
                                    let node = self.parse_dollar_expression()?;
                                    nodes.push(node);
                                }
                                Token::OpenBrace => {
                                    text.push('{');
                                    depth += 1;
                                    self.advance();
                                }
                                Token::CloseBrace => {
                                    depth -= 1;
                                    text.push('}');
                                    self.advance();
                                }
                                Token::Literal(s) => {
                                    text.push_str(&s);
                                    self.advance();
                                }
                                Token::EscapeChar(c) => {
                                    text.push(c);
                                    self.advance();
                                }
                                Token::BackslashLiteral(c) => {
                                    text.push(c);
                                    self.advance();
                                }
                                Token::Colon => {
                                    text.push(':');
                                    self.advance();
                                }
                                Token::Comma => {
                                    text.push(',');
                                    self.advance();
                                }
                                Token::Identifier(s) => {
                                    text.push_str(&s);
                                    self.advance();
                                }
                                Token::ItemKeyword(s)
                                | Token::OperatorKeyword(s)
                                | Token::ConditionKeyword(s) => {
                                    text.push_str(&s);
                                    self.advance();
                                }
                                Token::ProtectedRegion(s) => {
                                    text.push_str(&s);
                                    self.advance();
                                }
                                _ => {
                                    // Any other token — render as-is
                                    self.advance();
                                }
                            }
                        }
                        if !text.is_empty() {
                            nodes.push(AstNode::Literal(text));
                        }
                    } else {
                        // Bare `{` outside `${}` context — in Exim expansion
                        // strings, unquoted braces that are not part of a
                        // construct are literal text.  We parse the inner
                        // content and absorb the closing brace if present.
                        self.advance();
                        let inner = self.parse_sequence_inner(false)?;
                        if self.peek() == &Token::CloseBrace {
                            self.advance();
                        }
                        nodes.push(inner);
                    }
                    prev_was_escaped_dollar = false;
                }
                Token::Colon => {
                    // Bare `:` at sequence level — literal text.
                    self.advance();
                    nodes.push(AstNode::Literal(":".to_owned()));
                }
                Token::Comma => {
                    // Bare `,` at sequence level — literal text.
                    self.advance();
                    nodes.push(AstNode::Literal(",".to_owned()));
                }
                Token::Identifier(s) => {
                    // Bare identifier outside `$` context — literal text.
                    self.advance();
                    nodes.push(AstNode::Literal(s));
                }
                Token::ItemKeyword(s) | Token::OperatorKeyword(s) | Token::ConditionKeyword(s) => {
                    // Keyword token outside `$` context — literal text.
                    self.advance();
                    nodes.push(AstNode::Literal(s));
                }
                Token::ParametricOperator(base, p1, p2) => {
                    // Parametric operator outside `$` context — literal text.
                    self.advance();
                    let text = match p2 {
                        Some(m) => format!("{}_{p1}_{m}", base),
                        None => format!("{}_{p1}", base),
                    };
                    nodes.push(AstNode::Literal(text));
                }
            }
        }

        Ok(match nodes.len() {
            0 => AstNode::Literal(String::new()),
            1 => nodes.into_iter().next().expect("length checked"),
            _ => AstNode::Sequence(nodes),
        })
    }

    // ─── Dollar expression parsing ──────────────────────────────────

    /// Parse a `$`-initiated expression.
    ///
    /// After consuming the `$` token, dispatches to:
    /// - `${…}` brace expression (item, operator, or braced variable)
    /// - `$name` bare variable reference
    fn parse_dollar_expression(&mut self) -> Result<AstNode, ExpandError> {
        // Consume the Dollar token.
        self.advance();

        match self.peek().clone() {
            Token::OpenBrace => self.parse_braced_dollar_expression(),
            Token::Identifier(_) => self.parse_variable(),
            // Dollar followed by something unexpected — treat `$` as
            // literal (matches C behaviour: bare `$` followed by
            // non-alpha yields `$` in output).
            _ => Ok(AstNode::Literal("$".to_owned())),
        }
    }

    /// Parse a `${…}` brace expression.
    ///
    /// After consuming `${`, the next token determines the construct:
    /// - [`Token::ItemKeyword`] → item parsing
    /// - [`Token::OperatorKeyword`] → operator parsing
    /// - [`Token::Identifier`] → braced variable reference (with
    ///   header/ACL/auth classification)
    fn parse_braced_dollar_expression(&mut self) -> Result<AstNode, ExpandError> {
        // Consume the OpenBrace.
        self.advance();

        let result = match self.peek().clone() {
            Token::ItemKeyword(ref name) => {
                let kind = item_name_to_kind(name)
                    .ok_or_else(|| self.error(format!("unknown expansion operator \"{name}\"")))?;
                self.advance(); // consume ItemKeyword
                self.parse_item(kind)?
            }
            Token::OperatorKeyword(ref name) => {
                let kind = operator_name_to_kind(name)
                    .ok_or_else(|| self.error(format!("unknown expansion operator \"{name}\"")))?;
                self.advance(); // consume OperatorKeyword
                self.parse_operator(kind)?
            }
            Token::ParametricOperator(ref base, ref param1, ref param2) => {
                // Parametric operator with embedded numeric arguments.
                // This is the underscore form: ${length_5:string}
                //
                // The desugaring depends on whether the base is an item or
                // an operator:
                //
                // Item forms (desugared to Item AST node):
                //   ${length_N:subject}    → Item(Length, [N, subject])
                //   ${substr_N_M:subject}  → Item(Substr, [N, M, subject])
                //   ${hash_N_M:subject}    → Item(Hash, [N, M, subject])
                //   ${nhash_N:subject}     → Item(Nhash, [N, subject])
                //   ${nhash_N_M:subject}   → Item(Nhash, [N, M, subject])
                //
                // Operator forms (desugared to Operator AST node with
                // parameters stored in the OperatorKind variant):
                //   ${headerwrap_N:subj}   → Operator(HeaderwrapN(N), subj)
                //   ${headerwrap_N_M:subj} → Operator(HeaderwrapNM(N,M), subj)
                //   ${mask_N:subject}      → Operator(MaskN(N), subject)
                let p1 = *param1;
                let p2 = *param2;
                let base_owned = base.clone();
                self.advance(); // consume ParametricOperator

                // Expect the colon separator (same as operator form).
                if self.peek() == &Token::Colon {
                    self.advance();
                } else {
                    return Err(self.error(format!(
                        "expected ':' after parametric operator {}, got {:?}",
                        base_owned,
                        self.peek()
                    )));
                }

                // Parse the subject expression.
                let subject = self.parse_sequence()?;

                // Check if this is an operator-type or item-type parametric.
                match base_owned.as_str() {
                    "headerwrap" => {
                        let col = p1;
                        let max_col = p2;
                        AstNode::Operator {
                            kind: OperatorKind::HeaderwrapParam(col, max_col),
                            subject: Box::new(subject),
                        }
                    }
                    "mask" => AstNode::Operator {
                        kind: OperatorKind::MaskParam(p1 as u8),
                        subject: Box::new(subject),
                    },
                    _ => {
                        // Item-type parametric operators.
                        let item_kind = item_name_to_kind(&base_owned).ok_or_else(|| {
                            self.error(format!("unknown expansion operator \"{}\"", base_owned))
                        })?;
                        let mut args = Vec::new();
                        args.push(AstNode::Literal(p1.to_string()));
                        if let Some(m) = p2 {
                            args.push(AstNode::Literal(m.to_string()));
                        }
                        args.push(subject);
                        AstNode::Item {
                            kind: item_kind,
                            args,
                            yes_branch: None,
                            no_branch: None,
                            fail_force: false,
                        }
                    }
                }
            }
            Token::Identifier(ref name) => {
                let name_owned = name.clone();
                self.advance(); // consume Identifier

                // C Exim behaviour for ${name:...}:
                //
                // Inside `${...}`, a name followed by `:` is ALWAYS
                // interpreted as an operator invocation.  Header
                // variable syntax like `$header_subject:` or `$h_subject:`
                // works ONLY in the bare (non-braced) `$` context.
                //
                // Therefore `${header_subject:}` → unknown expansion
                // operator "header_subject", NOT a header ref.
                //
                // Braced header references only work WITHOUT a colon:
                //   `${h_subject}` → header variable (parsed by
                //   classify_and_build_variable)
                if self.peek() == &Token::Colon {
                    // The name followed by `:` means the user intended
                    // an operator.  Produce the same diagnostic C would.
                    return Err(self.make_unknown_operator_error(&name_owned));
                }

                self.classify_and_build_variable(&name_owned, true)?
            }
            Token::ConditionKeyword(ref name) => {
                // ConditionKeyword should not appear directly after `${`
                // (only after `${if …`).  Treat as a braced variable.
                let name_owned = name.clone();
                self.advance();
                self.classify_and_build_variable(&name_owned, true)?
            }
            _ => {
                return Err(self.error(format!(
                    "expected identifier, item, or operator after '${{', got {:?}",
                    self.peek()
                )));
            }
        };

        // Consume the outer closing brace — REQUIRED for ${...} expressions.
        // C Exim produces: "\"${<name>\" is not a known operator
        // (or a } is missing in a variable reference)"
        if self.peek() == &Token::CloseBrace {
            self.advance();
        } else {
            // If this is a plain variable (not an operator/item), then the
            // missing } is an error matching C Exim's format.
            match &result {
                AstNode::Variable(vr) => {
                    return Err(self.error(format!(
                        "\"${{{}\" is not a known operator (or a }} is missing in a variable reference)",
                        vr.name
                    )));
                }
                AstNode::HeaderRef { name: _, .. } => {
                    return Err(self.error(
                        "missing } at end of string - could be header name not terminated by colon"
                            .to_string(),
                    ));
                }
                AstNode::Conditional { .. } => {
                    // When malformed_header is set (header name consumed
                    // a `}` because it was not terminated by colon), C
                    // Exim hits EXPAND_FAILED_CURLY with the
                    // malformed_header override:
                    //   "missing or misplaced { or } - could be header
                    //    name not terminated by colon"
                    if self.malformed_header {
                        return Err(ExpandError::Failed {
                            message: "missing or misplaced { or } - could be \
                                      header name not terminated by colon"
                                .to_string(),
                        });
                    }
                    // C Exim's process_yesno_item produces a specific
                    // error when the closing `}` is missing after the
                    // yes/no branches of `${if ...}`:
                    //   "curly-bracket problem in conditional yes/no
                    //    parsing: did not close with '}'\n remaining
                    //    string is '...'"
                    let remaining = self.remaining_text_preview(60);
                    return Err(ExpandError::Failed {
                        message: format!(
                            "curly-bracket problem in conditional yes/no \
                             parsing: did not close with '}}'\n \
                             remaining string is '{}'",
                            remaining
                        ),
                    });
                }
                AstNode::Item { kind, .. } => {
                    // Produce a C-compatible error that names the item.
                    // C Exim reaches EXPAND_FAILED_CURLY after reading
                    // the yes/no branches of an item and not finding the
                    // closing `}`.  In modern Exim, the error includes
                    // context: "missing '}' closing <item_name>".
                    if self.malformed_header {
                        return Err(ExpandError::Failed {
                            message: "missing or misplaced { or } - could be \
                                      header name not terminated by colon"
                                .to_string(),
                        });
                    }
                    let item_name = item_kind_to_name(*kind);
                    return Err(ExpandError::Failed {
                        message: format!("missing '}}' closing {}", item_name,),
                    });
                }
                _ => {
                    if self.malformed_header {
                        return Err(ExpandError::Failed {
                            message: "missing or misplaced { or } - could be \
                                      header name not terminated by colon"
                                .to_string(),
                        });
                    }
                    return Err(self.error("missing } at end of string".to_string()));
                }
            }
        }

        Ok(result)
    }

    // ─── Variable classification and construction ───────────────────

    /// Classify a variable name and build the appropriate AST node.
    ///
    /// Checks for header references (`h_`, `rh_`, `bh_`, `lh_` and
    /// long forms), ACL variables (`acl_c*`, `acl_m*`), and auth
    /// variables (`auth1`..`auth3`).  Everything else is a plain
    /// variable reference.
    ///
    /// `braced` indicates whether the variable was inside `${…}`.
    fn classify_and_build_variable(
        &self,
        name: &str,
        braced: bool,
    ) -> Result<AstNode, ExpandError> {
        // Check for header prefix.
        if let Some((prefix, header_name)) = try_header_prefix(name) {
            return Ok(AstNode::HeaderRef {
                prefix,
                name: header_name.to_owned(),
            });
        }

        // Check for ACL variables: acl_c0..acl_c9, acl_m0..acl_m9,
        // acl_m_*.
        if name.starts_with("acl_c") || name.starts_with("acl_m") {
            return Ok(AstNode::AclVariable(name.to_owned()));
        }

        // Check for authentication variables: auth1, auth2, auth3.
        if let Some(suffix) = name.strip_prefix("auth") {
            if let Ok(idx) = suffix.parse::<u8>() {
                if (1..=3).contains(&idx) {
                    return Ok(AstNode::AuthVariable(idx));
                }
            }
        }

        // Plain variable reference.
        Ok(AstNode::Variable(VariableRef {
            name: name.to_owned(),
            braced,
        }))
    }

    /// Parse a bare `$name` variable reference (not braced).
    ///
    /// In C Exim, `$h_subject:` uses the trailing colon as the header
    /// name terminator — the colon is consumed and NOT emitted as
    /// literal text.  We replicate this: after recognising a header
    /// reference, eat the optional colon that immediately follows.
    pub fn parse_variable(&mut self) -> Result<AstNode, ExpandError> {
        match self.peek().clone() {
            Token::Identifier(name) => {
                self.advance();
                let node = self.classify_and_build_variable(&name, false)?;

                // Consume the trailing colon that terminates bare header
                // references ($h_subject:, $rh_from:, $bh_to:, $lh_cc:).
                if matches!(node, AstNode::HeaderRef { .. }) && self.peek() == &Token::Colon {
                    self.advance();
                }

                Ok(node)
            }
            _ => Err(self.error(format!(
                "expected identifier after '$', got {:?}",
                self.peek()
            ))),
        }
    }

    // ─── Item parsing ───────────────────────────────────────────────

    /// Parse an expansion item with its arguments.
    ///
    /// Dispatches to specialised parsers for `if` and `lookup`, or to
    /// the generic argument parser for all other items.
    pub fn parse_item(&mut self, kind: ItemKind) -> Result<AstNode, ExpandError> {
        match kind {
            ItemKind::If => self.parse_conditional_item(),
            ItemKind::Lookup => self.parse_lookup_item(),
            ItemKind::Filter => self.parse_filter_item(),
            ItemKind::Map => self.parse_map_item(),
            ItemKind::Reduce => self.parse_reduce_item(),
            ItemKind::Sort => self.parse_sort_item(),
            ItemKind::Extract => self.parse_extract_item(),
            _ => self.parse_generic_item(kind),
        }
    }

    /// Parse extract item — detects `json`/`jsons` modifier before braced args.
    ///
    /// C Exim syntax:
    /// - `${extract{field}{separator}{data}{yes}{no}}` — classic extract
    /// - `${extract json {key}{json_data}{yes}{no}}` — JSON value extract
    /// - `${extract jsons{key}{json_data}{yes}{no}}` — JSON string extract
    fn parse_extract_item(&mut self) -> Result<AstNode, ExpandError> {
        // Check if next token is a Literal containing "json" or "jsons"
        // before the opening brace
        self.skip_whitespace_literals();
        if let Token::Literal(ref text) = self.peek().clone() {
            let trimmed = text.trim();
            if trimmed == "json" || trimmed == "jsons" {
                let is_jsons = trimmed == "jsons";
                self.advance(); // consume the json/jsons literal
                let kind = if is_jsons {
                    ItemKind::ExtractJsons
                } else {
                    ItemKind::ExtractJson
                };
                return self.parse_generic_item(kind);
            }
        }
        // Fall through to normal extract parsing
        self.parse_generic_item(ItemKind::Extract)
    }

    /// Parse a generic item: collect N brace-delimited arguments then
    /// optional yes/no branches.
    fn parse_generic_item(&mut self, kind: ItemKind) -> Result<AstNode, ExpandError> {
        let (min_args, max_args, has_yes_no) = item_arg_spec(&kind);
        let mut args = Vec::new();

        // Handle comma-separated modifiers after item keyword.
        // C Exim syntax: ${run,preexpand {cmd}} — the `preexpand`
        // modifier is silently consumed.  Our evaluator already
        // pre-expands all arguments, so the modifier is a no-op.
        while self.peek() == &Token::Comma {
            self.advance(); // consume comma
                            // Read the modifier name and ignore it.
                            // C Exim syntax: ${run,preexpand {cmd}}.  The modifier
                            // appears after the comma inside the brace context, so the
                            // tokenizer often returns it as a Literal (not Identifier,
                            // since it is not preceded by `$`).  The literal may also
                            // include trailing whitespace (e.g. "preexpand ") because
                            // the tokenizer's `read_literal()` only stops on special
                            // characters and whitespace is not special.
            self.skip_whitespace_literals();
            match self.peek().clone() {
                Token::Identifier(ref _name) | Token::ItemKeyword(ref _name) => {
                    self.advance(); // consume modifier name
                }
                Token::Literal(ref s) => {
                    // Trim trailing whitespace and validate that the
                    // remaining text is a plausible modifier name
                    // (alphanumeric / underscore only).
                    let trimmed = s.trim();
                    if !trimmed.is_empty()
                        && trimmed
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '_')
                    {
                        self.advance(); // consume modifier (e.g., "preexpand ")
                    }
                }
                _ => {}
            }
        }

        // Skip any whitespace between keyword and first argument.
        self.skip_whitespace_literals();

        // Collect brace-delimited arguments up to `max_args`.
        let limit = if max_args == usize::MAX { 32 } else { max_args };
        for i in 0..limit {
            if self.peek() == &Token::OpenBrace {
                let expr = self.parse_braced_expression()?;
                args.push(expr);
                self.skip_whitespace_literals();
            } else if i >= min_args {
                break;
            } else {
                let name = item_kind_to_name(kind);
                return Err(self.error(format!(
                    "Not enough arguments for '{}' (min is {})",
                    name, min_args,
                )));
            }
        }

        // Parse optional yes/no branches first for items that support them.
        // This MUST happen before the "too many arguments" check so that
        // trailing `{yes}{no}` braces aren't mistaken for extra arguments.
        let (yes_branch, no_branch, fail_force) = if has_yes_no {
            self.parse_yes_no()?
        } else {
            // Check for too many arguments — if there are more braced args
            // waiting after we've consumed max_args, report an error.
            if max_args < usize::MAX && self.peek() == &Token::OpenBrace {
                let name = item_kind_to_name(kind);
                return Err(self.error(format!(
                    "Too many arguments for '{}' (max is {})",
                    name, max_args,
                )));
            }
            (None, None, false)
        };

        Ok(AstNode::Item {
            kind,
            args,
            yes_branch,
            no_branch,
            fail_force,
        })
    }

    /// Parse `${if condition {yes}{no}}` — the conditional item.
    ///
    /// This produces an [`AstNode::Conditional`] rather than an
    /// [`AstNode::Item`], reflecting the distinct semantics of
    /// conditional expansion.
    fn parse_conditional_item(&mut self) -> Result<AstNode, ExpandError> {
        let condition = self.parse_condition()?;

        // Skip whitespace before yes/no branches.
        self.skip_whitespace_literals();

        // C Exim supports three forms:
        //   ${if condition{yes}{no}}   — standard with both branches
        //   ${if condition{yes}}       — no-branch absent (returns "" if false)
        //   ${if condition}            — both branches absent (returns "true"/"")
        //   ${if condition{yes}fail}   — bare "fail" keyword as no-branch
        //
        // When no yes-branch is provided (next token is CloseBrace or EOF),
        // the evaluator returns "true" when the condition is true, "" when false.

        // Check if there are any branches at all.
        if self.peek() != &Token::OpenBrace {
            // C Exim: only `}` (CloseBrace) or EOF means "no branches".
            // Bare `fail` keyword before closing `}` is also accepted.
            // Anything else that is NOT `{` is a curly-bracket error
            // (e.g. `${if def:tod_log:{y}{n}}` where the `:` is left over).
            if self.peek_is_fail_keyword() {
                self.advance();
                return Ok(AstNode::Conditional {
                    condition: Box::new(condition),
                    yes_branch: None,
                    no_branch: None,
                    fail_force: true,
                });
            }
            if self.peek() == &Token::CloseBrace || self.peek() == &Token::Eof {
                return Ok(AstNode::Conditional {
                    condition: Box::new(condition),
                    yes_branch: None,
                    no_branch: None,
                    fail_force: false,
                });
            }
            // C Exim: report curly-bracket problem with remaining string
            let remaining = self.remaining_text_preview(60);
            return Err(ExpandError::Failed {
                message: format!(
                    "curly-bracket problem in conditional yes/no parsing: \
                     'yes' part did not start with '{{'\n remaining string is '{}'",
                    remaining
                ),
            });
        }

        // Parse the yes branch.
        let yes_branch = Box::new(self.parse_braced_expression()?);

        // Skip whitespace between branches.
        self.skip_whitespace_literals();

        // Parse the optional no branch (may be braced or bare "fail").
        let (no_branch, fail_force) = if self.peek() == &Token::OpenBrace {
            (Some(Box::new(self.parse_braced_expression()?)), false)
        } else if self.peek_is_fail_keyword() {
            // Bare "fail" keyword after the yes-branch causes forced
            // failure on the "no" path (C Exim expand.c line ~3107).
            self.advance(); // consume `fail`
            (None, true)
        } else {
            (None, false)
        };

        Ok(AstNode::Conditional {
            condition: Box::new(condition),
            yes_branch: Some(yes_branch),
            no_branch,
            fail_force,
        })
    }

    /// Parse `${filter{list}{condition}}` — list filtering.
    ///
    /// The second argument is parsed as a CONDITION (like ${if}'s condition),
    /// not as regular expansion text.  This matches C Exim behaviour where
    /// `eval_condition()` is called for the filter predicate.
    fn parse_filter_item(&mut self) -> Result<AstNode, ExpandError> {
        self.skip_whitespace_literals();
        // Arg 0: the list expression (regular expansion)
        if self.peek() != &Token::OpenBrace {
            return Err(self.error("expected '{' for argument 1 of filter"));
        }
        let list_expr = self.parse_braced_expression()?;
        self.skip_whitespace_literals();
        // Arg 1: the condition — parse inside braces as a condition
        if self.peek() != &Token::OpenBrace {
            return Err(self.error("expected '{' for argument 2 of filter"));
        }
        self.advance(); // consume '{'
        let condition = self.parse_condition()?;
        self.skip_whitespace_literals();
        if self.peek() == &Token::CloseBrace {
            self.advance(); // consume '}'
        }
        // Wrap the condition in a Conditional node so the evaluator
        // can distinguish it from a plain expression.
        let cond_node = AstNode::Conditional {
            condition: Box::new(condition),
            yes_branch: Some(Box::new(AstNode::Literal(String::new()))),
            no_branch: None,
            fail_force: false,
        };
        Ok(AstNode::Item {
            kind: ItemKind::Filter,
            args: vec![list_expr, cond_node],
            yes_branch: None,
            no_branch: None,
            fail_force: false,
        })
    }

    /// Parse `${map{list}{expression}}` — list mapping.
    ///
    /// Both arguments are regular expansions; $item is set during evaluation.
    fn parse_map_item(&mut self) -> Result<AstNode, ExpandError> {
        self.parse_generic_item(ItemKind::Map).map_err(|e| {
            // C Exim wraps inner errors from map template expansion
            // with the map item context.  E.g. "missing '}' closing
            // extract" becomes "missing '}' closing extract inside
            // \"map\" item".
            match e {
                ExpandError::Failed { ref message }
                    if message.starts_with("missing '}' closing ") =>
                {
                    ExpandError::Failed {
                        message: format!("{} inside \"map\" item", message),
                    }
                }
                other => other,
            }
        })
    }

    /// Parse `${reduce{list}{initial}{expression}}` — list reduction.
    ///
    /// All three arguments are regular expansions; $item and $value are
    /// set during evaluation.
    fn parse_reduce_item(&mut self) -> Result<AstNode, ExpandError> {
        self.parse_generic_item(ItemKind::Reduce)
    }

    /// Parse `${sort{list}{comparator}{expression}}` — list sorting.
    ///
    /// All arguments are regular expansions; $item is set for key extraction.
    fn parse_sort_item(&mut self) -> Result<AstNode, ExpandError> {
        self.parse_generic_item(ItemKind::Sort)
    }

    /// Parse `${lookup{key} type {source} {yes}{no}}` — the lookup item.
    ///
    /// Lookup has a unique syntax where the lookup type name appears as
    /// literal text between the key expression and the source/query
    /// expression.
    fn parse_lookup_item(&mut self) -> Result<AstNode, ExpandError> {
        let mut args = Vec::new();

        self.skip_whitespace_literals();

        // Parse the key expression: {key}.
        if self.peek() == &Token::OpenBrace {
            args.push(self.parse_braced_expression()?);
        } else {
            return Err(self.error("expected '{' for lookup key"));
        }

        // The lookup type name appears as literal text (possibly with
        // surrounding whitespace and modifiers) between the key and the
        // source.  In C Exim, names like "lsearch*@,ret=full",
        // "partial-lsearch,ret=full", "partial1-lsearch" are valid.
        // The tokenizer may split these across Literal, Comma, Identifier
        // tokens.  We greedily consume tokens until we see an OpenBrace
        // (the source file argument) or CloseBrace (no more arguments).
        self.skip_whitespace_literals();
        let mut lookup_type = String::new();
        loop {
            match self.peek().clone() {
                Token::Literal(ref s) => {
                    lookup_type.push_str(s);
                    self.advance();
                }
                Token::Identifier(ref s) => {
                    lookup_type.push_str(s);
                    self.advance();
                }
                Token::Comma => {
                    lookup_type.push(',');
                    self.advance();
                }
                Token::Colon => {
                    // Colons can appear in type names (unlikely) but
                    // shouldn't be consumed as part of the name.
                    break;
                }
                _ => break,
            }
        }
        let lookup_type = lookup_type.trim().to_owned();
        if !lookup_type.is_empty() {
            args.push(AstNode::Literal(lookup_type));
        }

        self.skip_whitespace_literals();

        // Parse remaining brace-delimited arguments (source, etc.).
        while self.peek() == &Token::OpenBrace {
            args.push(self.parse_braced_expression()?);
            self.skip_whitespace_literals();
        }

        // Check for trailing `fail` keyword before closing brace.
        // C Exim syntax: ${lookup{key}type{source}{yes}fail} or
        // ${lookup{key}type{source}fail}.  The `fail` keyword causes
        // lookup failure to produce an expansion error instead of empty.
        let mut fail_force = false;
        loop {
            match self.peek().clone() {
                Token::Literal(ref s) => {
                    let trimmed = s.trim();
                    if trimmed == "fail" {
                        fail_force = true;
                        self.advance();
                        self.skip_whitespace_literals();
                        continue;
                    } else if trimmed.is_empty() {
                        self.advance();
                        continue;
                    }
                    break;
                }
                Token::Identifier(ref s) if s == "fail" => {
                    fail_force = true;
                    self.advance();
                    self.skip_whitespace_literals();
                    continue;
                }
                Token::ItemKeyword(ref s) if s == "fail" => {
                    fail_force = true;
                    self.advance();
                    self.skip_whitespace_literals();
                    continue;
                }
                _ => break,
            }
        }

        // args layout: [key, type, source, [yes, [no]]]
        let (yes_branch, no_branch) = if args.len() >= 5 {
            let no = args.pop().map(Box::new);
            let yes = args.pop().map(Box::new);
            (yes, no)
        } else if args.len() == 4 {
            // [key, type, source, yes] — yes only, no "no".
            let yes = args.pop().map(Box::new);
            (yes, None)
        } else {
            (None, None)
        };

        Ok(AstNode::Item {
            kind: ItemKind::Lookup,
            args,
            yes_branch,
            no_branch,
            fail_force,
        })
    }

    // ─── Operator parsing ───────────────────────────────────────────

    /// Parse `${operator:subject}` — an operator/transform.
    ///
    /// After the operator keyword, expects a colon separator then the
    /// subject expression extending to the closing brace.
    pub fn parse_operator(&mut self, kind: OperatorKind) -> Result<AstNode, ExpandError> {
        // Expect the colon separator.
        if self.peek() == &Token::Colon {
            self.advance();
        } else {
            return Err(self.error(format!(
                "expected ':' after operator {:?}, got {:?}",
                kind,
                self.peek()
            )));
        }

        // Parse the subject expression (everything until CloseBrace).
        let subject = self.parse_sequence()?;

        Ok(AstNode::Operator {
            kind,
            subject: Box::new(subject),
        })
    }

    // ─── Condition parsing ──────────────────────────────────────────

    /// Parse a condition expression for `${if …}`.
    ///
    /// The condition name appears as literal text after the `if`
    /// keyword, possibly preceded by whitespace and/or a `!` negation
    /// prefix.  After identifying the condition type, braced operands
    /// are parsed according to the operand count for that type.
    pub fn parse_condition(&mut self) -> Result<ConditionNode, ExpandError> {
        // Skip whitespace before condition name.
        self.skip_whitespace_literals();

        // Extract condition name from the next token.
        let (raw_name, negated) = match self.peek().clone() {
            Token::Literal(s) => {
                self.advance();
                Self::extract_condition_name(&s)
            }
            Token::ConditionKeyword(name) => {
                self.advance();
                (name, false)
            }
            Token::Identifier(name) => {
                self.advance();
                Self::extract_condition_name(&name)
            }
            _ => {
                return Err(self.error(format!(
                    "expected condition name after 'if', got {:?}",
                    self.peek()
                )));
            }
        };

        let condition_type = condition_name_to_type(&raw_name)
            .ok_or_else(|| self.error(format!("unknown condition: {raw_name}")))?;

        let operand_count = condition_operand_count(&condition_type);
        let mut operands = Vec::with_capacity(operand_count);
        let mut sub_conditions: Vec<ConditionNode> = Vec::new();

        if condition_type == ConditionType::And || condition_type == ConditionType::Or {
            // ── And/Or compound conditions ──
            //
            // C Exim behaviour (expand.c ~2360-2410):
            //   and/or read ONE outer brace block containing multiple
            //   subconditions, each wrapped in their own { }.
            //
            //   ${if and {{eq{a}{b}}{match{x}{^x$}}} {yes} {no}}
            //
            //   The outer { } is the single argument.  Inside it,
            //   each { subcondition } is parsed as a complete
            //   condition expression.
            let cond_name = if condition_type == ConditionType::And {
                "and"
            } else {
                "or"
            };

            self.skip_whitespace_literals();
            if self.peek() != &Token::OpenBrace {
                return Err(self.error(format!(
                    "missing open brace after \"{cond_name}\" condition"
                )));
            }
            self.advance(); // consume outer `{`

            // Read sub-conditions until the matching outer `}`.
            loop {
                self.skip_whitespace_literals();
                if self.peek() == &Token::CloseBrace {
                    self.advance(); // consume outer `}`
                    break;
                }
                if self.peek() == &Token::Eof {
                    return Err(self.error(format!(
                        "missing }} at end of condition inside \"{cond_name}\" group"
                    )));
                }
                // Each sub-condition MUST be in its own `{...}`.
                if self.peek() != &Token::OpenBrace {
                    return Err(self.error(format!(
                        "each subcondition inside an \"{cond_name}{{...}}\" condition must be in its own {{}}"
                    )));
                }
                self.advance(); // consume sub-condition `{`

                // Parse a complete condition inside the sub-braces.
                // Capture a raw-text preview BEFORE attempting the
                // sub-condition parse so we can produce a C-compatible
                // error message if the parse fails.
                let text_preview = self.peek_text_preview(16);

                let sub_cond = self.parse_condition().map_err(|e| {
                    // Re-wrap parse errors to add context about which
                    // compound condition we are inside.
                    match e {
                        ExpandError::Failed { message } => {
                            // If the inner error is "unknown condition",
                            // rewrite to match C Exim format.
                            if message.starts_with("unknown condition: ") {
                                let name = message
                                    .strip_prefix("unknown condition: ")
                                    .unwrap_or("");
                                ExpandError::Failed {
                                    message: format!(
                                        "unknown condition \"{name}\" inside \"{cond_name}{{...}}\" condition"
                                    ),
                                }
                            } else if message.contains("expected condition name") {
                                // "condition name expected, but found ..."
                                ExpandError::Failed {
                                    message: format!(
                                        "condition name expected, but found \"{text_preview}\" inside \"{cond_name}{{...}}\" condition"
                                    ),
                                }
                            } else {
                                ExpandError::Failed { message }
                            }
                        }
                        other => other,
                    }
                })?;

                self.skip_whitespace_literals();
                if self.peek() == &Token::CloseBrace {
                    self.advance(); // consume sub-condition `}`
                } else {
                    return Err(self.error(format!(
                        "missing }} at end of condition inside \"{cond_name}\" group"
                    )));
                }
                sub_conditions.push(sub_cond);
            }
        } else if matches!(
            condition_type,
            ConditionType::ForAll
                | ConditionType::ForAny
                | ConditionType::ForAllJson
                | ConditionType::ForAnyJson
                | ConditionType::ForAllJsons
                | ConditionType::ForAnyJsons
        ) {
            // ── ForAll/ForAny compound conditions ──
            //
            // C Exim forany/forall read two brace-enclosed arguments:
            //   {list} {condition}
            //
            // The first brace is a regular list expression.  The second
            // brace contains a CONDITION expression (like `eq{$item}{a}`)
            // that is parsed as a condition, not as a regular expansion.
            let cond_name = match condition_type {
                ConditionType::ForAll | ConditionType::ForAllJson | ConditionType::ForAllJsons => {
                    "forall"
                }
                _ => "forany",
            };

            // First operand: the list.
            self.skip_whitespace_literals();
            if self.peek() == &Token::OpenBrace {
                operands.push(self.parse_braced_expression()?);
            }

            // Second operand: a condition inside braces.
            self.skip_whitespace_literals();
            if self.peek() == &Token::OpenBrace {
                self.advance(); // consume `{`

                let text_preview = self.peek_text_preview(16);
                let is_iteration_cond = matches!(
                    condition_type,
                    ConditionType::ForAll
                        | ConditionType::ForAllJson
                        | ConditionType::ForAllJsons
                        | ConditionType::ForAny
                        | ConditionType::ForAnyJson
                        | ConditionType::ForAnyJsons
                );
                let sub_cond = self.parse_condition().map_err(|e| {
                    match e {
                        ExpandError::Failed { message } => {
                            if message.starts_with("unknown condition: ") {
                                let name = message
                                    .strip_prefix("unknown condition: ")
                                    .unwrap_or("");
                                ExpandError::Failed {
                                    message: format!(
                                        "unknown condition \"{name}\" inside \"{cond_name}\" condition"
                                    ),
                                }
                            } else if message.contains("expected condition name") {
                                ExpandError::Failed {
                                    message: format!(
                                        "condition name expected, but found \"{text_preview}\" inside \"{cond_name}\" condition"
                                    ),
                                }
                            } else if is_iteration_cond {
                                // C Exim wraps any inner error with the
                                // outer condition context for forall/forany.
                                ExpandError::Failed {
                                    message: format!(
                                        "{} inside \"{}\" condition", message, cond_name
                                    ),
                                }
                            } else {
                                ExpandError::Failed { message }
                            }
                        }
                        other => other,
                    }
                })?;

                self.skip_whitespace_literals();
                if self.peek() == &Token::CloseBrace {
                    self.advance(); // consume `}`
                } else {
                    return Err(self.error(format!(
                        "missing }} at end of condition inside \"{cond_name}\""
                    )));
                }
                sub_conditions.push(sub_cond);
            }
        } else if condition_type == ConditionType::Acl {
            // ── ACL condition (C Exim expand.c ~2882-2926) ──
            //
            // The ACL condition reads ONE outer brace block containing
            // multiple sub-brace arguments:
            //   ${if acl {{name}{arg1}{arg2}} {yes}{no}}
            //
            // The first sub-arg is the ACL name, subsequent ones are
            // positional arguments ($acl_arg1 .. $acl_arg9).
            self.skip_whitespace_literals();
            if self.peek() != &Token::OpenBrace {
                return Err(self.error("missing { after \"acl\" condition".to_owned()));
            }
            self.advance(); // consume outer `{`

            // Read sub-arguments until the matching outer `}`.
            loop {
                self.skip_whitespace_literals();
                if self.peek() == &Token::CloseBrace {
                    self.advance(); // consume outer `}`
                    break;
                }
                if self.peek() == &Token::Eof {
                    return Err(
                        self.error("missing } at end of acl condition arguments".to_owned())
                    );
                }
                if self.peek() == &Token::OpenBrace {
                    operands.push(self.parse_braced_expression()?);
                } else {
                    // Bare word (unbraced ACL name) — should not normally
                    // occur, but handle gracefully.
                    let token = self.peek().clone();
                    self.advance();
                    match token {
                        Token::Literal(s) | Token::Identifier(s) => {
                            operands.push(AstNode::Literal(s));
                        }
                        _ => {
                            return Err(self.error(format!(
                                "unexpected token {:?} in acl condition arguments",
                                token
                            )));
                        }
                    }
                }
            }

            if operands.is_empty() {
                return Err(self.error("too few arguments for acl condition".to_owned()));
            }
        } else if condition_type == ConditionType::Def {
            // `def` uses colon-separated name: `def:variable_name`.
            let operand = self.parse_def_operand()?;
            operands.push(operand);
        } else {
            self.skip_whitespace_literals();
            for _ in 0..operand_count {
                if self.peek() == &Token::OpenBrace {
                    operands.push(self.parse_braced_expression()?);
                    self.skip_whitespace_literals();
                } else {
                    break;
                }
            }
        }

        Ok(ConditionNode {
            negated,
            condition_type,
            operands,
            sub_conditions,
        })
    }

    /// Extract condition name and negation flag from raw text.
    ///
    /// Handles the `!` negation prefix: `"!eq"` → `("eq", true)`.
    fn extract_condition_name(text: &str) -> (String, bool) {
        let trimmed = text.trim();
        if let Some(rest) = trimmed.strip_prefix('!') {
            (rest.trim().to_owned(), true)
        } else {
            (trimmed.to_owned(), false)
        }
    }

    /// Parse the operand for a `def` condition.
    ///
    /// `def` uses colon-separated syntax: `def:variable_name`.
    fn parse_def_operand(&mut self) -> Result<AstNode, ExpandError> {
        // Consume Colon if present.
        if self.peek() == &Token::Colon {
            self.advance();
        }

        // Collect the variable name from the next token.
        //
        // Track whether the raw literal had trailing whitespace.
        // The tokenizer's `read_literal()` does NOT stop at spaces
        // (only at `is_special_char` characters like `{`, `}`, `:`,
        // etc.), so `Literal("h_xxx ")` is produced when the input
        // is `h_xxx {y}`.  In contrast, C's `read_header_name()`
        // stops at the space because `isgraph(' ')` is false.  When
        // there IS trailing whitespace in the raw literal, we must
        // NOT enter the brace-consumption loop — the space already
        // acted as the stop condition.
        let (name, had_trailing_ws) = match self.peek().clone() {
            Token::Literal(s) => {
                self.advance();
                let trimmed = s.trim().to_owned();
                let trailing = s.trim_start().len() > trimmed.len();
                (trimmed, trailing)
            }
            Token::Identifier(s) => {
                self.advance();
                (s, false) // identifiers never include whitespace
            }
            _ => (String::new(), false),
        };

        // C Exim: for header variables (h_, header_, rh_, lh_, bh_), the
        // terminating colon is part of the variable specification.  When
        // we see a colon immediately after a header-prefix name, consume
        // it so that the yes/no branches can be parsed normally.
        //
        // When there is NO terminating colon AND no whitespace separated
        // the name from the next token, C's `read_header_name()`
        // continues reading graphic characters (including `}`) into the
        // header name until it finds `:` or a non-graphic char.  If the
        // consumed name includes `}`, `malformed_header` is set, and the
        // subsequent brace-check produces:
        //   "missing or misplaced { or } - could be header name not
        //    terminated by colon"
        if !name.is_empty() && Self::is_header_variable_prefix(&name) {
            if self.peek() == &Token::Colon {
                self.advance(); // consume trailing `:` that is part of header spec
            } else if !had_trailing_ws {
                // No colon AND no whitespace — C Exim's
                // `read_header_name()` reads ALL graphic characters
                // (printable, non-space) from the input until it finds
                // `:` or a non-graphic character.  `isgraph()` returns
                // true for printable chars EXCEPT space.  This means
                // `}`, `{`, letters are consumed, but space stops the
                // read.  If a `}` is found in the name,
                // `malformed_header` is set.
                let mut consumed_brace = false;
                loop {
                    match self.peek() {
                        Token::Colon => {
                            self.advance(); // consume terminating colon
                            break;
                        }
                        Token::Eof => break,
                        Token::CloseBrace | Token::OpenBrace => {
                            consumed_brace = true;
                            self.advance();
                        }
                        _ => {
                            // Other printable tokens count as graphic
                            self.advance();
                        }
                    }
                }
                if consumed_brace {
                    self.malformed_header = true;
                }
            }
            // If had_trailing_ws is true, C's read_header_name()
            // stopped at the space boundary.  The header name is just
            // the trimmed identifier, no braces consumed, no
            // malformed_header flag set.
        }

        Ok(AstNode::Literal(name))
    }

    /// Returns `true` when `name` starts with one of the header variable
    /// prefixes used by C Exim (`h_`, `header_`, `rh_`, `lh_`, `bh_`,
    /// `rheader_`, `lheader_`, `bheader_`).
    fn is_header_variable_prefix(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        lower.starts_with("h_")
            || lower.starts_with("header_")
            || lower.starts_with("rh_")
            || lower.starts_with("rheader_")
            || lower.starts_with("lh_")
            || lower.starts_with("lheader_")
            || lower.starts_with("bh_")
            || lower.starts_with("bheader_")
    }

    // ─── Braced expression and yes/no parsing ───────────────────────

    /// Parse a `{…}` brace-delimited sub-expression.
    ///
    /// Consumes the opening `{`, parses the inner content as a
    /// sequence, and consumes the closing `}`.
    pub fn parse_braced_expression(&mut self) -> Result<AstNode, ExpandError> {
        if self.peek() != &Token::OpenBrace {
            return Err(self.error(format!("expected '{{', got {:?}", self.peek())));
        }
        self.advance(); // consume `{`

        let inner = self.parse_sequence()?;

        if self.peek() == &Token::CloseBrace {
            self.advance(); // consume `}`
        } else if self.malformed_header {
            // C Exim (expand.c line 8637): when a header variable name
            // consumed expression syntax, produce the hint about the
            // missing colon.
            return Err(self.error(
                "missing } at end of string - could be header name not terminated by colon",
            ));
        } else {
            return Err(self.error("expected '}' to close braced expression"));
        }

        Ok(inner)
    }

    /// Parse optional `{yes_string}{no_string}` branches.
    ///
    /// Returns `(Some(yes), Some(no))` if both present,
    /// `(Some(yes), None)` if only one, or `(None, None)` if neither.
    pub fn parse_yes_no(&mut self) -> Result<YesNoBranches, ExpandError> {
        self.skip_whitespace_literals();

        let yes = if self.peek() == &Token::OpenBrace {
            Some(Box::new(self.parse_braced_expression()?))
        } else {
            // Check for bare `fail` keyword (no yes/no branches).
            if self.peek_is_fail_keyword() {
                self.advance(); // consume `fail`
                return Ok((None, None, true));
            }
            return Ok((None, None, false));
        };

        self.skip_whitespace_literals();

        let no = if self.peek() == &Token::OpenBrace {
            Some(Box::new(self.parse_braced_expression()?))
        } else {
            // Check for bare `fail` keyword after yes-branch.
            // C Exim expand.c line ~3107: `fail` without braces after
            // the yes-branch causes forced failure on the "no" path.
            if self.peek_is_fail_keyword() {
                self.advance(); // consume `fail`
                return Ok((yes, None, true));
            }
            None
        };

        Ok((yes, no, false))
    }

    /// Check if the current token is the bare `fail` keyword.
    fn peek_is_fail_keyword(&self) -> bool {
        matches!(self.peek(),
            Token::Identifier(s) | Token::Literal(s) if s.trim() == "fail"
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Standalone parse function
// ═══════════════════════════════════════════════════════════════════════

/// Parse a token slice into an AST.
///
/// Convenience function that creates a [`Parser`] from the given tokens
/// and parses them into a single [`AstNode`].
///
/// # Arguments
///
/// * `tokens` — A slice of [`Token`] values (should end with
///   [`Token::Eof`]).
///
/// # Errors
///
/// Returns [`ExpandError::Failed`] on malformed token sequences.
pub fn parse(tokens: &[Token]) -> Result<AstNode, ExpandError> {
    let mut parser = Parser::from_tokens(tokens.to_vec());
    parser.parse()
}

// ═══════════════════════════════════════════════════════════════════════
//  Unit tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Lookup table tests ─────────────────────────────────────────

    #[test]
    fn test_item_name_lookup_all() {
        let cases = [
            ("acl", ItemKind::Acl),
            ("authresults", ItemKind::AuthResults),
            ("certextract", ItemKind::CertExtract),
            ("dlfunc", ItemKind::Dlfunc),
            ("env", ItemKind::Env),
            ("extract", ItemKind::Extract),
            ("filter", ItemKind::Filter),
            ("hash", ItemKind::Hash),
            ("hmac", ItemKind::Hmac),
            ("if", ItemKind::If),
            ("imapfolder", ItemKind::ImapFolder),
            ("length", ItemKind::Length),
            ("listextract", ItemKind::ListExtract),
            ("listquote", ItemKind::ListQuote),
            ("lookup", ItemKind::Lookup),
            ("map", ItemKind::Map),
            ("nhash", ItemKind::Nhash),
            ("perl", ItemKind::Perl),
            ("prvs", ItemKind::Prvs),
            ("prvscheck", ItemKind::PrvsCheck),
            ("readfile", ItemKind::ReadFile),
            ("readsocket", ItemKind::ReadSocket),
            ("reduce", ItemKind::Reduce),
            ("run", ItemKind::Run),
            ("sg", ItemKind::Sg),
            ("sort", ItemKind::Sort),
            ("srs_encode", ItemKind::SrsEncode),
            ("substr", ItemKind::Substr),
            ("tr", ItemKind::Tr),
        ];
        for (name, expected) in &cases {
            assert_eq!(
                item_name_to_kind(name),
                Some(*expected),
                "item_name_to_kind({name}) failed"
            );
        }
        assert_eq!(item_name_to_kind("nonexistent"), None);
    }

    #[test]
    fn test_operator_name_lookup_selected() {
        assert_eq!(operator_name_to_kind("lc"), Some(OperatorKind::Lc));
        assert_eq!(operator_name_to_kind("uc"), Some(OperatorKind::Uc));
        assert_eq!(operator_name_to_kind("md5"), Some(OperatorKind::Md5));
        assert_eq!(
            operator_name_to_kind("local_part"),
            Some(OperatorKind::LocalPart)
        );
        assert_eq!(operator_name_to_kind("base64"), Some(OperatorKind::Base64));
        assert_eq!(operator_name_to_kind("escape"), Some(OperatorKind::Escape));
        assert_eq!(
            operator_name_to_kind("from_utf8"),
            Some(OperatorKind::FromUtf8)
        );
        assert_eq!(operator_name_to_kind("unknown"), None);
    }

    #[test]
    fn test_condition_name_lookup_all() {
        assert_eq!(condition_name_to_type("<"), Some(ConditionType::NumLess));
        assert_eq!(condition_name_to_type("<="), Some(ConditionType::NumLessEq));
        assert_eq!(condition_name_to_type("="), Some(ConditionType::NumEqual));
        assert_eq!(
            condition_name_to_type("=="),
            Some(ConditionType::NumEqualEq)
        );
        assert_eq!(condition_name_to_type(">"), Some(ConditionType::NumGreater));
        assert_eq!(
            condition_name_to_type(">="),
            Some(ConditionType::NumGreaterEq)
        );
        assert_eq!(condition_name_to_type("eq"), Some(ConditionType::StrEq));
        assert_eq!(condition_name_to_type("match"), Some(ConditionType::Match));
        assert_eq!(condition_name_to_type("and"), Some(ConditionType::And));
        assert_eq!(condition_name_to_type("or"), Some(ConditionType::Or));
        assert_eq!(condition_name_to_type("def"), Some(ConditionType::Def));
        assert_eq!(
            condition_name_to_type("exists"),
            Some(ConditionType::Exists)
        );
        assert_eq!(
            condition_name_to_type("first_delivery"),
            Some(ConditionType::FirstDelivery)
        );
        assert_eq!(
            condition_name_to_type("saslauthd"),
            Some(ConditionType::Saslauthd)
        );
        assert_eq!(condition_name_to_type("bogus"), None);
    }

    // ─── Header prefix tests ────────────────────────────────────────

    #[test]
    fn test_header_prefix_detection() {
        let cases = [
            ("h_subject", HeaderPrefix::Normal, "subject"),
            ("header_from", HeaderPrefix::Normal, "from"),
            ("rh_content-type", HeaderPrefix::Raw, "content-type"),
            ("rheader_x-custom", HeaderPrefix::Raw, "x-custom"),
            ("bh_to", HeaderPrefix::Body, "to"),
            ("bheader_cc", HeaderPrefix::Body, "cc"),
            ("lh_received", HeaderPrefix::List, "received"),
            ("lheader_x-list", HeaderPrefix::List, "x-list"),
        ];
        for (input, expected_prefix, expected_name) in &cases {
            let (prefix, name) =
                try_header_prefix(input).unwrap_or_else(|| panic!("no prefix for {input}"));
            assert_eq!(&prefix, expected_prefix, "prefix for {input}");
            assert_eq!(name, *expected_name, "name for {input}");
        }
        assert!(try_header_prefix("local_part").is_none());
        assert!(try_header_prefix("domain").is_none());
    }

    #[test]
    fn test_header_prefix_longest_match() {
        // "header_foo" should match "header_" (8 chars), not "h_" (2).
        let (prefix, name) = try_header_prefix("header_foo").unwrap();
        assert_eq!(prefix, HeaderPrefix::Normal);
        assert_eq!(name, "foo");
    }

    // ─── Condition negation extraction ──────────────────────────────

    #[test]
    fn test_condition_negation() {
        let (name, negated) = Parser::extract_condition_name("!eq");
        assert_eq!(name, "eq");
        assert!(negated);

        let (name2, neg2) = Parser::extract_condition_name("exists");
        assert_eq!(name2, "exists");
        assert!(!neg2);

        let (name3, neg3) = Parser::extract_condition_name("  !match  ");
        assert_eq!(name3, "match");
        assert!(neg3);
    }

    // ─── Operand count coverage ─────────────────────────────────────

    #[test]
    fn test_condition_operand_count_coverage() {
        assert_eq!(condition_operand_count(&ConditionType::FirstDelivery), 0);
        assert_eq!(condition_operand_count(&ConditionType::QueueRunning), 0);
        assert_eq!(condition_operand_count(&ConditionType::Bool), 1);
        assert_eq!(condition_operand_count(&ConditionType::Exists), 1);
        assert_eq!(condition_operand_count(&ConditionType::Def), 1);
        assert_eq!(condition_operand_count(&ConditionType::StrEq), 2);
        assert_eq!(condition_operand_count(&ConditionType::NumLess), 2);
        assert_eq!(condition_operand_count(&ConditionType::ForAll), 2);
        assert_eq!(condition_operand_count(&ConditionType::And), 1);
        assert_eq!(condition_operand_count(&ConditionType::Or), 1);
        assert_eq!(condition_operand_count(&ConditionType::Saslauthd), 4);
    }

    // ─── Item argument spec coverage ────────────────────────────────

    #[test]
    fn test_item_arg_spec_selected() {
        let (min, max, yn) = item_arg_spec(&ItemKind::Acl);
        assert_eq!((min, max, yn), (1, 10, true));

        let (min, max, yn) = item_arg_spec(&ItemKind::Run);
        assert_eq!((min, max, yn), (1, 1, true));

        let (min, max, yn) = item_arg_spec(&ItemKind::Hash);
        assert_eq!((min, max, yn), (2, 3, false));

        let (min, _, _) = item_arg_spec(&ItemKind::Dlfunc);
        assert_eq!(min, 2);

        let (min, max, yn) = item_arg_spec(&ItemKind::If);
        assert_eq!((min, max, yn), (0, 0, false));
    }

    // ─── Variable classification ────────────────────────────────────

    #[test]
    fn test_classify_variable_header() {
        let parser = Parser::from_tokens(vec![Token::Eof]);
        let node = parser
            .classify_and_build_variable("h_subject", false)
            .unwrap();
        match node {
            AstNode::HeaderRef { prefix, name } => {
                assert_eq!(prefix, HeaderPrefix::Normal);
                assert_eq!(name, "subject");
            }
            other => panic!("expected HeaderRef, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_variable_acl() {
        let parser = Parser::from_tokens(vec![Token::Eof]);
        let node = parser.classify_and_build_variable("acl_c0", false).unwrap();
        assert!(matches!(node, AstNode::AclVariable(ref s) if s == "acl_c0"));
    }

    #[test]
    fn test_classify_variable_acl_m() {
        let parser = Parser::from_tokens(vec![Token::Eof]);
        let node = parser
            .classify_and_build_variable("acl_m_custom", false)
            .unwrap();
        assert!(matches!(node, AstNode::AclVariable(ref s) if s == "acl_m_custom"));
    }

    #[test]
    fn test_classify_variable_auth() {
        let parser = Parser::from_tokens(vec![Token::Eof]);
        for idx in 1..=3u8 {
            let name = format!("auth{idx}");
            let node = parser.classify_and_build_variable(&name, false).unwrap();
            assert!(matches!(node, AstNode::AuthVariable(n) if n == idx));
        }
    }

    #[test]
    fn test_classify_variable_plain() {
        let parser = Parser::from_tokens(vec![Token::Eof]);
        let node = parser
            .classify_and_build_variable("local_part", false)
            .unwrap();
        assert!(matches!(
            node,
            AstNode::Variable(VariableRef { ref name, braced: false })
            if name == "local_part"
        ));
    }

    // ─── Token-level parser tests ───────────────────────────────────

    #[test]
    fn test_parse_empty() {
        let ast = parse(&[Token::Eof]).unwrap();
        assert_eq!(ast, AstNode::Literal(String::new()));
    }

    #[test]
    fn test_parse_literal_only() {
        let tokens = vec![Token::Literal("hello world".to_owned()), Token::Eof];
        let ast = parse(&tokens).unwrap();
        assert_eq!(ast, AstNode::Literal("hello world".to_owned()));
    }

    #[test]
    fn test_parse_escape_char() {
        let tokens = vec![Token::EscapeChar('\n'), Token::Eof];
        let ast = parse(&tokens).unwrap();
        assert_eq!(ast, AstNode::Escape('\n'));
    }

    #[test]
    fn test_parse_protected_region() {
        let tokens = vec![Token::ProtectedRegion("raw data".to_owned()), Token::Eof];
        let ast = parse(&tokens).unwrap();
        assert_eq!(ast, AstNode::Protected("raw data".to_owned()));
    }

    #[test]
    fn test_parse_bare_variable() {
        let tokens = vec![
            Token::Dollar,
            Token::Identifier("domain".to_owned()),
            Token::Eof,
        ];
        let ast = parse(&tokens).unwrap();
        assert!(matches!(
            ast,
            AstNode::Variable(VariableRef { ref name, braced: false })
            if name == "domain"
        ));
    }

    #[test]
    fn test_parse_braced_variable() {
        let tokens = vec![
            Token::Dollar,
            Token::OpenBrace,
            Token::Identifier("sender_address".to_owned()),
            Token::CloseBrace,
            Token::Eof,
        ];
        let ast = parse(&tokens).unwrap();
        assert!(matches!(
            ast,
            AstNode::Variable(VariableRef { ref name, braced: true })
            if name == "sender_address"
        ));
    }

    #[test]
    fn test_parse_operator() {
        let tokens = vec![
            Token::Dollar,
            Token::OpenBrace,
            Token::OperatorKeyword("lc".to_owned()),
            Token::Colon,
            Token::Literal("HELLO".to_owned()),
            Token::CloseBrace,
            Token::Eof,
        ];
        let ast = parse(&tokens).unwrap();
        match ast {
            AstNode::Operator { kind, subject } => {
                assert_eq!(kind, OperatorKind::Lc);
                assert_eq!(*subject, AstNode::Literal("HELLO".to_owned()));
            }
            other => panic!("expected Operator, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_sequence_multi() {
        let tokens = vec![
            Token::Literal("Hello ".to_owned()),
            Token::Dollar,
            Token::Identifier("name".to_owned()),
            Token::Literal("!".to_owned()),
            Token::Eof,
        ];
        let ast = parse(&tokens).unwrap();
        match ast {
            AstNode::Sequence(ref nodes) => {
                assert_eq!(nodes.len(), 3);
                assert_eq!(nodes[0], AstNode::Literal("Hello ".to_owned()));
                assert!(matches!(
                    &nodes[1],
                    AstNode::Variable(VariableRef { ref name, braced: false })
                    if name == "name"
                ));
                assert_eq!(nodes[2], AstNode::Literal("!".to_owned()));
            }
            other => panic!("expected Sequence, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_braced_header_ref() {
        let tokens = vec![
            Token::Dollar,
            Token::OpenBrace,
            Token::Identifier("h_subject".to_owned()),
            Token::CloseBrace,
            Token::Eof,
        ];
        let ast = parse(&tokens).unwrap();
        match ast {
            AstNode::HeaderRef { prefix, name } => {
                assert_eq!(prefix, HeaderPrefix::Normal);
                assert_eq!(name, "subject");
            }
            other => panic!("expected HeaderRef, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_generic_item_with_args() {
        // Simulate ${sg{text}{regex}{replacement}}
        let tokens = vec![
            Token::Dollar,
            Token::OpenBrace,
            Token::ItemKeyword("sg".to_owned()),
            Token::OpenBrace,
            Token::Literal("text".to_owned()),
            Token::CloseBrace,
            Token::OpenBrace,
            Token::Literal("regex".to_owned()),
            Token::CloseBrace,
            Token::OpenBrace,
            Token::Literal("repl".to_owned()),
            Token::CloseBrace,
            Token::CloseBrace,
            Token::Eof,
        ];
        let ast = parse(&tokens).unwrap();
        match ast {
            AstNode::Item {
                kind,
                ref args,
                ref yes_branch,
                ref no_branch,
                fail_force,
            } => {
                assert_eq!(kind, ItemKind::Sg);
                assert_eq!(args.len(), 3);
                assert_eq!(args[0], AstNode::Literal("text".to_owned()));
                assert_eq!(args[1], AstNode::Literal("regex".to_owned()));
                assert_eq!(args[2], AstNode::Literal("repl".to_owned()));
                assert!(yes_branch.is_none());
                assert!(!fail_force);
                assert!(no_branch.is_none());
            }
            other => panic!("expected Item, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_item_with_yes_no() {
        // Simulate ${run{/bin/true}{yes}{no}}
        let tokens = vec![
            Token::Dollar,
            Token::OpenBrace,
            Token::ItemKeyword("run".to_owned()),
            Token::OpenBrace,
            Token::Literal("/bin/true".to_owned()),
            Token::CloseBrace,
            Token::OpenBrace,
            Token::Literal("yes".to_owned()),
            Token::CloseBrace,
            Token::OpenBrace,
            Token::Literal("no".to_owned()),
            Token::CloseBrace,
            Token::CloseBrace,
            Token::Eof,
        ];
        let ast = parse(&tokens).unwrap();
        match ast {
            AstNode::Item {
                kind,
                ref args,
                ref yes_branch,
                ref no_branch,
                fail_force,
            } => {
                assert_eq!(kind, ItemKind::Run);
                assert_eq!(args.len(), 1);
                assert!(yes_branch.is_some());
                assert!(no_branch.is_some());
                assert!(!fail_force);
            }
            other => panic!("expected Item, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_braced_expression() {
        let tokens = vec![
            Token::OpenBrace,
            Token::Literal("inner".to_owned()),
            Token::CloseBrace,
            Token::Eof,
        ];
        let mut parser = Parser::from_tokens(tokens);
        let expr = parser.parse_braced_expression().unwrap();
        assert_eq!(expr, AstNode::Literal("inner".to_owned()));
    }

    #[test]
    fn test_parse_dollar_followed_by_non_ident() {
        // `$` followed by `)` → literal "$".
        let tokens = vec![Token::Dollar, Token::CloseBrace, Token::Eof];
        let ast = parse(&tokens).unwrap();
        assert_eq!(ast, AstNode::Literal("$".to_owned()));
    }

    #[test]
    fn test_parse_backslash_literal() {
        let tokens = vec![Token::BackslashLiteral('\\'), Token::Eof];
        let ast = parse(&tokens).unwrap();
        assert_eq!(ast, AstNode::Escape('\\'));
    }

    #[test]
    fn test_parse_colon_as_literal() {
        let tokens = vec![Token::Colon, Token::Eof];
        let ast = parse(&tokens).unwrap();
        assert_eq!(ast, AstNode::Literal(":".to_owned()));
    }

    #[test]
    fn test_parse_comma_as_literal() {
        let tokens = vec![Token::Comma, Token::Eof];
        let ast = parse(&tokens).unwrap();
        assert_eq!(ast, AstNode::Literal(",".to_owned()));
    }

    #[test]
    fn test_standalone_parse_function() {
        let tokens = vec![Token::Literal("test".to_owned()), Token::Eof];
        let ast = parse(&tokens).unwrap();
        assert_eq!(ast, AstNode::Literal("test".to_owned()));
    }
}
