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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// `${mask:…}` — apply CIDR mask to IP address.
    Mask,
    /// `${md5:…}` — MD5 hash (hex digest).
    Md5,
    /// `${nh:…}` — alias for numeric hash.
    Nh,
    /// `${nhash:…}` — numeric hash operator (alias, also exists as item).
    Nhash,
    /// `${quote:…}` — shell-safe quoting.
    Quote,
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
        /// The "yes" / success branch.
        yes_branch: Box<AstNode>,
        /// Optional "no" / failure branch.
        no_branch: Option<Box<AstNode>>,
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
pub fn item_name_to_kind(name: &str) -> Option<ItemKind> {
    match name {
        "acl" => Some(ItemKind::Acl),
        "authresults" => Some(ItemKind::AuthResults),
        "certextract" => Some(ItemKind::CertExtract),
        "dlfunc" => Some(ItemKind::Dlfunc),
        "env" => Some(ItemKind::Env),
        "extract" => Some(ItemKind::Extract),
        "filter" => Some(ItemKind::Filter),
        "hash" => Some(ItemKind::Hash),
        "hmac" => Some(ItemKind::Hmac),
        "if" => Some(ItemKind::If),
        "imapfolder" => Some(ItemKind::ImapFolder),
        "length" => Some(ItemKind::Length),
        "listextract" => Some(ItemKind::ListExtract),
        "listquote" => Some(ItemKind::ListQuote),
        "lookup" => Some(ItemKind::Lookup),
        "map" => Some(ItemKind::Map),
        "nhash" => Some(ItemKind::Nhash),
        "perl" => Some(ItemKind::Perl),
        "prvs" => Some(ItemKind::Prvs),
        "prvscheck" => Some(ItemKind::PrvsCheck),
        "readfile" => Some(ItemKind::ReadFile),
        "readsocket" => Some(ItemKind::ReadSocket),
        "reduce" => Some(ItemKind::Reduce),
        "run" => Some(ItemKind::Run),
        "sg" => Some(ItemKind::Sg),
        "sort" => Some(ItemKind::Sort),
        "srs_encode" => Some(ItemKind::SrsEncode),
        "substr" => Some(ItemKind::Substr),
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
        "mask" => Some(OperatorKind::Mask),
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
        _ => None,
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
        ItemKind::Acl => (2, 2, true),
        ItemKind::AuthResults => (1, 1, false),
        ItemKind::CertExtract => (2, 2, true),
        ItemKind::Dlfunc => (2, usize::MAX, false),
        ItemKind::Env => (1, 1, true),
        ItemKind::Extract => (2, 3, true),
        ItemKind::Filter => (2, 2, false),
        ItemKind::Hash => (3, 3, false),
        ItemKind::Hmac => (3, 3, false),
        ItemKind::If => (0, 0, false), // special-cased via parse_conditional_item
        ItemKind::ImapFolder => (1, 1, false),
        ItemKind::Length => (2, 2, false),
        ItemKind::ListExtract => (2, 2, true),
        ItemKind::ListQuote => (2, 2, false),
        ItemKind::Lookup => (0, 0, false), // special-cased via parse_lookup_item
        ItemKind::Map => (2, 2, false),
        ItemKind::Nhash => (3, 3, false),
        ItemKind::Perl => (1, usize::MAX, false),
        ItemKind::Prvs => (3, 4, false),
        ItemKind::PrvsCheck => (2, 2, true),
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

// ═══════════════════════════════════════════════════════════════════════
//  Parser — recursive-descent AST construction
// ═══════════════════════════════════════════════════════════════════════

/// Result type for yes/no branch parsing — `(optional_yes, optional_no)`.
type YesNoBranches = (Option<Box<AstNode>>, Option<Box<AstNode>>);

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
    pub fn new(input: &str) -> Self {
        let mut tokenizer = Tokenizer::new(input);
        // Tokenize entire input; on error produce a single Eof token
        // so the parser can report a clean error message.
        let spanned = tokenizer.tokenize().unwrap_or_else(|_| {
            vec![crate::tokenizer::SpannedToken {
                token: Token::Eof,
                span: crate::tokenizer::TokenSpan::new(0, 0),
            }]
        });
        let tokens: Vec<Token> = spanned.into_iter().map(|st| st.token).collect();
        Self {
            tokens,
            position: 0,
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

    // ─── Primary parsing entry points ───────────────────────────────

    /// Parse the entire token stream into an AST.
    ///
    /// This is the main entry point called by `lib.rs`.  It parses the
    /// complete input and returns a single [`AstNode`] (which may be a
    /// [`Sequence`](AstNode::Sequence) of sub-nodes).
    pub fn parse(&mut self) -> Result<AstNode, ExpandError> {
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
        let mut nodes: Vec<AstNode> = Vec::new();

        loop {
            match self.peek().clone() {
                Token::Eof => break,
                Token::CloseBrace => break,
                Token::Literal(s) => {
                    self.advance();
                    nodes.push(AstNode::Literal(s));
                }
                Token::EscapeChar(c) => {
                    self.advance();
                    nodes.push(AstNode::Escape(c));
                }
                Token::BackslashLiteral(c) => {
                    self.advance();
                    nodes.push(AstNode::Escape(c));
                }
                Token::ProtectedRegion(s) => {
                    self.advance();
                    nodes.push(AstNode::Protected(s));
                }
                Token::Dollar => {
                    let node = self.parse_dollar_expression()?;
                    nodes.push(node);
                }
                Token::OpenBrace => {
                    // Bare `{` outside `${}` context — in Exim expansion
                    // strings, unquoted braces that are not part of a
                    // construct are literal text.  We parse the inner
                    // content and absorb the closing brace if present.
                    self.advance();
                    let inner = self.parse_sequence()?;
                    if self.peek() == &Token::CloseBrace {
                        self.advance();
                    }
                    nodes.push(inner);
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
                    .ok_or_else(|| self.error(format!("unknown expansion item: {name}")))?;
                self.advance(); // consume ItemKeyword
                self.parse_item(kind)?
            }
            Token::OperatorKeyword(ref name) => {
                let kind = operator_name_to_kind(name)
                    .ok_or_else(|| self.error(format!("unknown operator: {name}")))?;
                self.advance(); // consume OperatorKeyword
                self.parse_operator(kind)?
            }
            Token::Identifier(ref name) => {
                let name_owned = name.clone();
                self.advance(); // consume Identifier
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

        // Consume the outer closing brace.
        if self.peek() == &Token::CloseBrace {
            self.advance();
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
    pub fn parse_variable(&mut self) -> Result<AstNode, ExpandError> {
        match self.peek().clone() {
            Token::Identifier(name) => {
                self.advance();
                self.classify_and_build_variable(&name, false)
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
            _ => self.parse_generic_item(kind),
        }
    }

    /// Parse a generic item: collect N brace-delimited arguments then
    /// optional yes/no branches.
    fn parse_generic_item(&mut self, kind: ItemKind) -> Result<AstNode, ExpandError> {
        let (min_args, max_args, has_yes_no) = item_arg_spec(&kind);
        let mut args = Vec::new();

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
                return Err(self.error(format!(
                    "expected '{{' for argument {} of {:?}, got {:?}",
                    i + 1,
                    kind,
                    self.peek()
                )));
            }
        }

        let (yes_branch, no_branch) = if has_yes_no {
            self.parse_yes_no()?
        } else {
            (None, None)
        };

        Ok(AstNode::Item {
            kind,
            args,
            yes_branch,
            no_branch,
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

        // Parse the mandatory yes branch.
        let yes_branch = if self.peek() == &Token::OpenBrace {
            Box::new(self.parse_braced_expression()?)
        } else {
            return Err(self.error("expected '{' for yes-branch of ${if ...}"));
        };

        // Skip whitespace between branches.
        self.skip_whitespace_literals();

        // Parse the optional no branch.
        let no_branch = if self.peek() == &Token::OpenBrace {
            Some(Box::new(self.parse_braced_expression()?))
        } else {
            None
        };

        Ok(AstNode::Conditional {
            condition: Box::new(condition),
            yes_branch,
            no_branch,
        })
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
        // surrounding whitespace) between the key and the source.
        self.skip_whitespace_literals();
        let lookup_type = match self.peek().clone() {
            Token::Literal(s) => {
                let name = s.trim().to_owned();
                self.advance();
                name
            }
            Token::Identifier(s) => {
                self.advance();
                s
            }
            _ => String::new(),
        };

        if !lookup_type.is_empty() {
            args.push(AstNode::Literal(lookup_type));
        }

        self.skip_whitespace_literals();

        // Parse remaining brace-delimited arguments (source, etc.).
        while self.peek() == &Token::OpenBrace {
            args.push(self.parse_braced_expression()?);
            self.skip_whitespace_literals();
        }

        // If we have 4+ args the last two are yes/no branches.
        // Typical: args = [key, type, source, yes, no]
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

        if condition_type == ConditionType::Def {
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
        match self.peek().clone() {
            Token::Literal(s) => {
                self.advance();
                Ok(AstNode::Literal(s.trim().to_owned()))
            }
            Token::Identifier(s) => {
                self.advance();
                Ok(AstNode::Literal(s))
            }
            _ => Ok(AstNode::Literal(String::new())),
        }
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
            return Ok((None, None));
        };

        self.skip_whitespace_literals();

        let no = if self.peek() == &Token::OpenBrace {
            Some(Box::new(self.parse_braced_expression()?))
        } else {
            None
        };

        Ok((yes, no))
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
                Some(expected.clone()),
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
        assert_eq!((min, max, yn), (2, 2, true));

        let (min, max, yn) = item_arg_spec(&ItemKind::Run);
        assert_eq!((min, max, yn), (1, 1, true));

        let (min, max, yn) = item_arg_spec(&ItemKind::Hash);
        assert_eq!((min, max, yn), (3, 3, false));

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
            } => {
                assert_eq!(kind, ItemKind::Sg);
                assert_eq!(args.len(), 3);
                assert_eq!(args[0], AstNode::Literal("text".to_owned()));
                assert_eq!(args[1], AstNode::Literal("regex".to_owned()));
                assert_eq!(args[2], AstNode::Literal("repl".to_owned()));
                assert!(yes_branch.is_none());
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
            } => {
                assert_eq!(kind, ItemKind::Run);
                assert_eq!(args.len(), 1);
                assert!(yes_branch.is_some());
                assert!(no_branch.is_some());
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
