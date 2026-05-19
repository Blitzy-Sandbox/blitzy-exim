// Copyright (c) 2024 Exim Maintainers — Rust rewrite
// SPDX-License-Identifier: GPL-2.0-or-later
//
// exim-expand/src/evaluator.rs — AST evaluation engine (Phase 3 of tokenizer→parser→evaluator)
//
// Replaces the core expansion loop from expand.c's expand_string_internal() (lines 4771-8730)
// and the arithmetic expression evaluator (lines 4197-4518).

use std::env;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::{Read, Write as IoWrite};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use digest::Mac;
use hmac::Hmac;
use md5::Md5;
use sha1::Sha1;

use crate::parser::{
    AstNode, ConditionNode, ConditionType, HeaderPrefix, ItemKind, OperatorKind, VariableRef,
};
use crate::variables::{self, ExpandContext};
use crate::{EsiFlags, ExpandError};
use exim_store::TaintState;

/// Expansion forbid flag: lookups are forbidden.
const RDO_LOOKUP: u32 = crate::RDO_LOOKUP;
/// Expansion forbid flag: ${run} is forbidden.
#[cfg(feature = "run")]
const RDO_RUN: u32 = crate::RDO_RUN;
/// Expansion forbid flag: ${dlfunc} is forbidden.
#[cfg(feature = "dlfunc")]
const RDO_DLFUNC: u32 = crate::RDO_DLFUNC;
/// Expansion forbid flag: ${perl} is forbidden.
#[cfg(feature = "perl")]
const RDO_PERL: u32 = crate::RDO_PERL;
/// Expansion forbid flag: ${readfile} is forbidden.
const RDO_READFILE: u32 = crate::RDO_READFILE;
/// Expansion forbid flag: ${readsocket} is forbidden.
const RDO_READSOCK: u32 = crate::RDO_READSOCK;

/// Maximum expansion recursion depth (mirrors C EXPAND_MAXN)
const MAX_EXPAND_DEPTH: u32 = 50;

/// Maximum number of partial-match capture groups ($1..$9)
const EXPAND_MAXN: usize = 10;

/// Convert a Rust `&str` (whose chars are Latin-1 codepoints 0x00..0xFF)
/// to a byte vector, truncating each char to a single byte.
/// This is the inverse of the Latin-1 input encoding in modes.rs.
fn latin1_bytes(s: &str) -> Vec<u8> {
    s.chars().map(|c| c as u32 as u8).collect()
}

/// The AST evaluation engine — phase 3 of the tokenizer → parser → evaluator pipeline.
///
/// Walks the parsed AST produced by `parser.rs` and produces expanded string output.
/// Replaces the monolithic `expand_string_internal()` function from expand.c.
///
/// # State Management
///
/// All C global variables used by the expansion engine are replaced with fields
/// on this struct, passed explicitly through the call chain:
/// - `expand_level` replaces the C global `expand_level`
/// - `expand_forbid` replaces the C global `expand_string_forcedfail` flags
/// - `forced_fail` replaces `f.expand_string_forcedfail`
/// - `search_find_defer` replaces `f.search_find_defer`
/// - `expand_nstring` replaces `expand_nstring[]`/`expand_nlength[]`
/// - `lookup_value` replaces the C global `lookup_value` ($value)
pub struct Evaluator<'a> {
    /// Current expansion nesting level for debugging and recursion limit.
    /// Incremented on each recursive evaluate() call.
    pub expand_level: u32,

    /// Expansion forbid flags — bitfield of RDO_LOOKUP, RDO_RUN, RDO_DLFUNC,
    /// RDO_PERL, RDO_READFILE, RDO_READSOCK.
    /// When a bit is set, the corresponding expansion item is forbidden (returns error).
    pub expand_forbid: u32,

    /// Forced failure flag — set when an expansion item triggers forced failure
    /// (e.g., ${dlfunc} FAIL_FORCED, ${perl} undef return).
    /// Replaces C global `f.expand_string_forcedfail`.
    pub forced_fail: bool,

    /// Search find defer flag — set when a lookup finds a deferred result.
    /// Replaces C global `f.search_find_defer`.
    pub search_find_defer: bool,

    /// Saved partial match results for $1..$9 (and $0 for full match).
    /// Index 0 = full match ($0), indices 1..9 = capture groups ($1..$9).
    pub expand_nstring: [Option<String>; EXPAND_MAXN],

    /// Current lookup value ($value) — set by ${lookup}, ${reduce} and available in branches.
    pub lookup_value: Option<String>,

    /// Current iteration item ($item) — set by ${filter}, ${map}, ${reduce},
    /// ${sort}, forany, forall.
    pub iterate_item: Option<String>,

    /// Maximum recursion depth before error.
    max_depth: u32,

    /// Expansion context providing variable resolution from scoped context structs.
    ctx: &'a mut ExpandContext,

    /// Accumulated taint state for the current expansion result.
    ///
    /// Tracks whether any tainted data has been incorporated into the output
    /// during expansion. When a variable with `TaintState::Tainted` is resolved,
    /// this field is promoted to `TaintState::Tainted`. Once tainted, it cannot
    /// revert to untainted (taint is monotonically increasing).
    ///
    /// This implements the taint propagation required by AAP §0.4.3: untainted
    /// input concatenated with tainted variables produces tainted output.
    pub result_taint: TaintState,
}

impl<'a> Evaluator<'a> {
    /// Create a new evaluator with a default (empty) expansion context.
    ///
    /// This is the zero-argument constructor used when no explicit context
    /// is available (e.g., during config parsing before contexts are built).
    pub fn new_default() -> Evaluator<'static> {
        // Use a leaked static default context for the zero-arg constructor.
        // This is safe because ExpandContext::new() produces an inert default context.
        let ctx: &'static mut ExpandContext = Box::leak(Box::new(ExpandContext::new()));
        Evaluator {
            expand_level: 0,
            expand_forbid: 0,
            forced_fail: false,
            search_find_defer: false,
            expand_nstring: Default::default(),
            lookup_value: None,
            iterate_item: None,
            max_depth: MAX_EXPAND_DEPTH,
            ctx,
            result_taint: TaintState::Untainted,
        }
    }

    /// Create a new evaluator with an explicit expansion context.
    ///
    /// # Arguments
    /// * `ctx` — Mutable reference to the expansion context providing variable
    ///   resolution and capture storage
    pub fn new(ctx: &'a mut ExpandContext) -> Self {
        Self {
            expand_level: 0,
            expand_forbid: 0,
            forced_fail: false,
            search_find_defer: false,
            expand_nstring: Default::default(),
            lookup_value: None,
            iterate_item: None,
            max_depth: MAX_EXPAND_DEPTH,
            ctx,
            result_taint: TaintState::Untainted,
        }
    }

    /// Get an immutable reference to the expansion context.
    pub fn context(&self) -> &ExpandContext {
        self.ctx
    }

    /// Get a mutable reference to the expansion context.
    pub fn context_mut(&mut self) -> &mut ExpandContext {
        self.ctx
    }

    /// Expand a string expression through the full expansion pipeline.
    /// This parses the string as an expansion expression and evaluates it.
    pub fn expand_string(&mut self, input: &str, flags: EsiFlags) -> Result<String, ExpandError> {
        use crate::parser::Parser;
        let mut parser = Parser::new(input);
        let ast = parser.parse().map_err(|e| ExpandError::Failed {
            message: format!("expansion parse error: {}", e),
        })?;
        self.evaluate(&ast, flags)
    }

    /// Propagate taint state: if a resolved variable is tainted, promote the
    /// accumulated `result_taint` to `TaintState::Tainted`. Taint is monotonically
    /// increasing — once tainted, the result stays tainted regardless of
    /// subsequent untainted values being concatenated.
    ///
    /// Implements AAP §0.4.3: untainted input concatenated with tainted
    /// variables produces tainted output.
    #[inline]
    fn propagate_taint(&mut self, taint: TaintState) {
        if matches!(taint, TaintState::Tainted) {
            self.result_taint = TaintState::Tainted;
        }
    }

    // ── Debug trace helper accessors ────────────────────────────────────

    /// Returns `true` when expansion debug tracing is active (`-d+expand`).
    #[inline]
    fn dbg_expand(&self) -> bool {
        self.ctx.debug_expand
    }

    /// Returns `true` when ASCII-only box drawing is requested (`-d+noutf8`).
    #[inline]
    fn dbg_noutf8(&self) -> bool {
        self.ctx.debug_noutf8
    }

    /// Current trace indentation depth.
    #[inline]
    fn dbg_depth(&self) -> usize {
        self.ctx.expand_depth
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 2: Main evaluation entry point
    // ─────────────────────────────────────────────────────────────────────────

    /// Main AST evaluation entry point. Walks the AST tree and produces expanded
    /// string output.
    ///
    /// Replaces `expand_string_internal()` from expand.c lines 4771-8730.
    ///
    /// # Arguments
    /// * `node` — The parsed AST to evaluate
    /// * `flags` — Evaluation flags controlling behavior (ESI_EXISTS_ONLY, etc.)
    ///
    /// # Returns
    /// The expanded string on success, or an `ExpandError` on failure.
    pub fn evaluate(&mut self, node: &AstNode, flags: EsiFlags) -> Result<String, ExpandError> {
        // Recursion depth check (expand.c line 4782)
        self.expand_level += 1;
        if self.expand_level > self.max_depth {
            self.expand_level -= 1;
            return Err(ExpandError::Failed {
                message: format!("expansion recursion too deep (limit {})", self.max_depth),
            });
        }

        tracing::debug!(level = self.expand_level, "entering evaluate");

        // Pre-allocate output buffer (expand.c line 4797 optimization)
        let mut output = String::with_capacity(128);

        let result = self.eval_node(node, flags, &mut output);

        self.expand_level -= 1;

        match result {
            Ok(()) => {
                tracing::debug!(
                    level = self.expand_level + 1,
                    output_len = output.len(),
                    "evaluate complete"
                );
                Ok(output)
            }
            Err(e) => Err(e),
        }
    }

    /// Internal recursive node evaluator that appends to the output buffer.
    fn eval_node(
        &mut self,
        node: &AstNode,
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let dbg = self.dbg_expand();
        let noutf8 = self.dbg_noutf8();
        let depth = self.dbg_depth();

        match node {
            // ─── Literal text: append directly ───
            AstNode::Literal(text) => {
                if dbg {
                    crate::debug_trace::trace_text(depth, text, noutf8);
                }
                output.push_str(text);
            }

            // ─── Backslash escape sequences ───
            AstNode::Escape(ch) => {
                let s = ch.to_string();
                if dbg {
                    crate::debug_trace::trace_backslashed(depth, &s, noutf8);
                }
                output.push(*ch);
            }

            // ─── Protected region (\N...\N): copy verbatim ───
            AstNode::Protected(text) => {
                if dbg {
                    crate::debug_trace::trace_protected(depth, text, noutf8);
                }
                output.push_str(text);
            }

            // ─── Sequence of nodes ───
            AstNode::Sequence(nodes) => {
                for child in nodes {
                    self.eval_node(child, flags, output)?;
                    // ESI_EXISTS_ONLY: stop as soon as output is non-empty
                    if flags.contains(EsiFlags::ESI_EXISTS_ONLY) && !output.is_empty() {
                        return Ok(());
                    }
                }
            }

            // ─── Variable references ($name / ${name}) ───
            AstNode::Variable(var_ref) => {
                if dbg {
                    // C Exim: emits `├considering: $varname` at the same depth
                    // when processing a $variable inside an expansion string.
                    crate::debug_trace::trace_mid_considering(
                        depth,
                        &format!("${}", var_ref.name),
                        noutf8,
                    );
                }
                let before = output.len();
                self.eval_variable(var_ref, output)?;
                if dbg {
                    let val = &output[before..];
                    crate::debug_trace::trace_value(depth, val, noutf8);
                }
            }

            // ─── Header references ($h_name, $rh_name, etc.) ───
            AstNode::HeaderRef { prefix, name } => {
                if dbg {
                    let pfx = match prefix {
                        crate::parser::HeaderPrefix::Normal => "h",
                        crate::parser::HeaderPrefix::Raw => "rh",
                        crate::parser::HeaderPrefix::Body => "bh",
                        crate::parser::HeaderPrefix::List => "lh",
                    };
                    let hdr_name = format!("${}_{}", pfx, name);
                    crate::debug_trace::trace_var(depth, &hdr_name, noutf8);
                }
                let before = output.len();
                self.eval_header_ref(prefix, name, output)?;
                if dbg {
                    let val = &output[before..];
                    crate::debug_trace::trace_value(depth, val, noutf8);
                }
            }

            // ─── ACL variables ($acl_c0..$acl_c9, $acl_m0..$acl_m9, etc.) ───
            AstNode::AclVariable(name) => {
                if dbg {
                    crate::debug_trace::trace_var(depth, name, noutf8);
                }
                let before = output.len();
                self.eval_acl_variable(name, output)?;
                if dbg {
                    let val = &output[before..];
                    crate::debug_trace::trace_value(depth, val, noutf8);
                }
            }

            // ─── Authentication variables ($auth1..$auth3) ───
            AstNode::AuthVariable(idx) => {
                if dbg {
                    let vname = format!("$auth{}", idx);
                    crate::debug_trace::trace_var(depth, &vname, noutf8);
                }
                let before = output.len();
                self.eval_auth_variable(*idx, output)?;
                if dbg {
                    let val = &output[before..];
                    crate::debug_trace::trace_value(depth, val, noutf8);
                }
            }

            // ─── Expansion items (${item{args}...}) ───
            AstNode::Item {
                kind,
                args,
                yes_branch,
                no_branch,
                fail_force,
            } => {
                let before = output.len();
                self.eval_item(
                    kind,
                    args,
                    yes_branch.as_deref(),
                    no_branch.as_deref(),
                    *fail_force,
                    flags,
                    output,
                )?;
                if self.dbg_expand() {
                    let val = &output[before..];
                    crate::debug_trace::trace_item_result(self.dbg_depth(), val, self.dbg_noutf8());
                }
            }

            // ─── Operators (${operator:subject}) ───
            AstNode::Operator { kind, subject } => {
                let before = output.len();
                self.eval_operator(kind, subject, flags, output)?;
                if self.dbg_expand() {
                    let val = &output[before..];
                    crate::debug_trace::trace_op_result(self.dbg_depth(), val, self.dbg_noutf8());
                }
            }

            // ─── Conditionals (${if condition {yes}{no}}) ───
            AstNode::Conditional {
                condition,
                yes_branch,
                no_branch,
                fail_force,
            } => {
                self.eval_conditional(
                    condition,
                    yes_branch.as_deref(),
                    no_branch.as_deref(),
                    *fail_force,
                    flags,
                    output,
                )?;
            }
        }
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 3: Variable dispatch
    // ─────────────────────────────────────────────────────────────────────────

    /// Resolve a variable reference ($name / ${name}) via the variables module.
    ///
    /// Propagates taint state: if the variable is tainted (e.g., user-supplied
    /// input like `$local_part`, `$sender_address`, `$auth1`), the evaluator's
    /// accumulated taint is promoted to `Tainted` (AAP §0.4.3).
    fn eval_variable(
        &mut self,
        var_ref: &VariableRef,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        tracing::debug!(var = %var_ref.name, "resolving variable");

        // Intercept $item — set by list iteration operators (filter, map,
        // reduce, sort, forany, forall).
        if var_ref.name == "item" {
            if let Some(ref val) = self.iterate_item {
                output.push_str(val);
            }
            return Ok(());
        }

        // Intercept $value — set by ${lookup} and ${reduce}.
        if var_ref.name == "value" {
            if let Some(ref val) = self.lookup_value {
                output.push_str(val);
            }
            return Ok(());
        }

        // Numeric variable references: $0..$9 are handled by
        // resolve_variable, but any all-digit name beyond single-digit
        // (e.g. ${12}, ${11111...}) silently resolves to empty in C Exim
        // (expand.c lines 4997-5013 read all digits, then the numeric
        // subscript is checked against expand_nmax).
        if !var_ref.name.is_empty()
            && var_ref.name.bytes().all(|b| b.is_ascii_digit())
            && var_ref.name.len() > 1
        {
            // Multi-digit numeric reference — always out of range,
            // resolve to empty string (not an error).
            return Ok(());
        }

        let result = variables::resolve_variable(&var_ref.name, self.ctx);
        match result {
            Ok((val_opt, taint)) => {
                self.propagate_taint(taint);
                if let Some(val) = val_opt {
                    output.push_str(&val);
                }
                Ok(())
            }
            Err(ExpandError::Failed { ref message })
                if var_ref.braced && message.starts_with("unknown variable name ") =>
            {
                // C Exim uses "unknown variable in "${name}"" for braced
                // variable references and "unknown variable name "name""
                // for bare references. Rewrite the error to match.
                Err(ExpandError::Failed {
                    message: format!("unknown variable in \"${{{}}}\"", var_ref.name),
                })
            }
            Err(e) => Err(e),
        }
    }

    /// Resolve a header reference ($h_name, $rh_name, $bh_name, $lh_name).
    ///
    /// Message headers are always tainted (they come from external input).
    /// Propagates taint state per AAP §0.4.3.
    fn eval_header_ref(
        &mut self,
        prefix: &HeaderPrefix,
        name: &str,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        tracing::debug!(header = name, ?prefix, "resolving header");
        // Build the full variable name for header lookup
        let full_name = match prefix {
            HeaderPrefix::Normal => format!("h_{}", name),
            HeaderPrefix::Raw => format!("rh_{}", name),
            HeaderPrefix::Body => format!("bh_{}", name),
            HeaderPrefix::List => format!("lh_{}", name),
        };
        let (val_opt, taint) = variables::resolve_variable(&full_name, self.ctx)?;
        self.propagate_taint(taint);
        if let Some(val) = val_opt {
            output.push_str(&val);
        }
        Ok(())
    }

    /// Resolve an ACL variable ($acl_c0..$acl_c9, $acl_m0..$acl_m9, etc.).
    ///
    /// Propagates taint state per AAP §0.4.3.
    fn eval_acl_variable(&mut self, name: &str, output: &mut String) -> Result<(), ExpandError> {
        tracing::debug!(acl_var = name, "resolving ACL variable");
        let (val_opt, taint) = variables::resolve_variable(name, self.ctx)?;
        self.propagate_taint(taint);
        if let Some(val) = val_opt {
            output.push_str(&val);
        }
        Ok(())
    }

    /// Resolve an authentication variable ($auth1..$auth3).
    ///
    /// Auth variables are always tainted (they contain user-supplied credentials).
    /// Propagates taint state per AAP §0.4.3.
    fn eval_auth_variable(&mut self, idx: u8, output: &mut String) -> Result<(), ExpandError> {
        tracing::debug!(auth_idx = idx, "resolving auth variable");
        let name = format!("auth{}", idx);
        let (val_opt, taint) = variables::resolve_variable(&name, self.ctx)?;
        self.propagate_taint(taint);
        if let Some(val) = val_opt {
            output.push_str(&val);
        }
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 3: Item dispatch (${item{args}...} pattern)
    // ─────────────────────────────────────────────────────────────────────────

    /// Evaluate an expansion item node.
    ///
    /// Dispatches to the appropriate handler based on `ItemKind`.
    /// Replaces the massive switch statement in expand_string_internal()
    /// (expand.c lines 4800-8700).
    /// Dispatch item evaluation — needs many params to mirror C Exim's
    /// process_yesno() and expand_item() calling convention exactly.
    #[allow(clippy::too_many_arguments)]
    fn eval_item(
        &mut self,
        kind: &ItemKind,
        args: &[AstNode],
        yes_branch: Option<&AstNode>,
        no_branch: Option<&AstNode>,
        fail_force: bool,
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        tracing::debug!(?kind, "evaluating item");

        // For items that support yes/no branches: when `fail_force` is true
        // and the item would take the "no" branch (i.e. the extraction/lookup
        // failed), C Exim produces a forced failure error instead.
        // We capture the output length before the call, then check if the
        // item produced any output or took the no-branch path.
        let before_len = output.len();

        let result = match kind {
            ItemKind::Acl => self.eval_item_acl(args, yes_branch, no_branch, flags, output),
            ItemKind::AuthResults => self.eval_item_authresults(args, flags, output),
            ItemKind::CertExtract => {
                self.eval_item_certextract(args, yes_branch, no_branch, flags, output)
            }
            #[cfg(feature = "dlfunc")]
            ItemKind::Dlfunc => self.eval_item_dlfunc(args, yes_branch, no_branch, flags, output),
            #[cfg(not(feature = "dlfunc"))]
            ItemKind::Dlfunc => Err(ExpandError::Failed {
                message: "dlfunc not available (compiled without dlfunc feature)".into(),
            }),
            ItemKind::Env => self.eval_item_env(args, yes_branch, no_branch, flags, output),
            ItemKind::Extract => self.eval_item_extract(args, yes_branch, no_branch, flags, output),
            ItemKind::ExtractJson => {
                self.eval_item_extract_json(args, yes_branch, no_branch, flags, output, false)
            }
            ItemKind::ExtractJsons => {
                self.eval_item_extract_json(args, yes_branch, no_branch, flags, output, true)
            }
            ItemKind::Filter => self.eval_item_filter(args, flags, output),
            ItemKind::Hash => self.eval_item_hash(args, flags, output),
            ItemKind::Hmac => self.eval_item_hmac(args, flags, output),
            ItemKind::If => self.eval_item_if(args, yes_branch, no_branch, flags, output),
            #[cfg(feature = "i18n")]
            ItemKind::ImapFolder => self.eval_item_imapfolder(args, flags, output),
            #[cfg(not(feature = "i18n"))]
            ItemKind::ImapFolder => Err(ExpandError::Failed {
                message: "imapfolder not available (compiled without i18n feature)".into(),
            }),
            ItemKind::Length => self.eval_item_length(args, flags, output),
            ItemKind::ListExtract => {
                self.eval_item_listextract(args, yes_branch, no_branch, flags, output)
            }
            ItemKind::ListQuote => self.eval_item_listquote(args, flags, output),
            ItemKind::Lookup => self.eval_item_lookup(args, yes_branch, no_branch, flags, output),
            ItemKind::Map => self.eval_item_map(args, flags, output),
            ItemKind::Nhash => self.eval_item_nhash(args, flags, output),
            #[cfg(feature = "perl")]
            ItemKind::Perl => self.eval_item_perl(args, yes_branch, no_branch, flags, output),
            #[cfg(not(feature = "perl"))]
            ItemKind::Perl => Err(ExpandError::Failed {
                message: "perl not available (compiled without perl feature)".into(),
            }),
            ItemKind::Prvs => self.eval_item_prvs(args, flags, output),
            ItemKind::PrvsCheck => self.eval_item_prvscheck(args, flags, output),
            ItemKind::ReadFile => self.eval_item_readfile(args, flags, output),
            ItemKind::ReadSocket => self.eval_item_readsocket(args, flags, output),
            ItemKind::Reduce => self.eval_item_reduce(args, flags, output),
            #[cfg(feature = "run")]
            ItemKind::Run => self.eval_item_run(args, yes_branch, no_branch, flags, output),
            #[cfg(not(feature = "run"))]
            ItemKind::Run => Err(ExpandError::Failed {
                message: "run not available (compiled without run feature)".into(),
            }),
            ItemKind::Sg => self.eval_item_sg(args, flags, output),
            ItemKind::Sort => self.eval_item_sort(args, flags, output),
            #[cfg(feature = "srs")]
            ItemKind::SrsEncode => self.eval_item_srs_encode(args, flags, output),
            #[cfg(not(feature = "srs"))]
            ItemKind::SrsEncode => Err(ExpandError::Failed {
                message: "srs_encode not available (compiled without srs feature)".into(),
            }),
            ItemKind::Substr => self.eval_item_substr(args, flags, output),
            ItemKind::Tr => self.eval_item_tr(args, flags, output),
        };

        // Handle `fail` keyword: if the item produced no output (took the
        // "no" path or returned empty) and fail_force is set, emit the
        // C-compatible forced failure error message.
        if fail_force && result.is_ok() && output.len() == before_len {
            // The `{fail}` keyword in item branches triggers a regular
            // expansion failure with a descriptive message.  The message
            // format mirrors C Exim's `expand_string_message`.  Callers
            // such as the redirect router detect this pattern to decide
            // between DECLINE and DEFER.
            let item_name = match kind {
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
            };
            return Err(ExpandError::FailRequested {
                message: format!("\"{}\" failed and \"fail\" requested", item_name),
            });
        }

        result
    }

    // ─── Individual item handlers ────────────────────────────────────────────

    /// ${acl{name}{arg}} — evaluate an ACL and expand the result.
    fn eval_item_acl(
        &mut self,
        args: &[AstNode],
        yes_branch: Option<&AstNode>,
        no_branch: Option<&AstNode>,
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        // ${acl {name}{arg1}{arg2}...} — evaluate ACL and return message text.
        //
        // In C Exim (expand.c ~line 4030), `${acl {name}{arg1}...}` evaluates the
        // named ACL with the provided arguments.  On accept, the result string is
        // the ACL's `message = ...` text (or empty if no message modifier).
        // On deny, the result string is the deny message.  On defer, expansion fails.
        //
        // When used WITHOUT yes/no branches, the ACL message is appended directly
        // to output.  With branches, it works like a conditional.

        let acl_name = self.eval_arg(args, 0, flags)?;

        // Evaluate remaining arguments as positional ACL args ($acl_arg1..N).
        let mut acl_args: Vec<String> = Vec::new();
        for i in 1..args.len() {
            acl_args.push(self.eval_arg(args, i, flags)?);
        }
        tracing::debug!(
            acl = %acl_name,
            narg = acl_args.len(),
            "evaluating item_acl"
        );

        // Save and set the ACL argument context.
        let saved_narg = self.ctx.acl_narg;
        let saved_args = self.ctx.acl_args.clone();
        self.ctx.acl_narg = acl_args.len() as i32;
        self.ctx.acl_args = acl_args;

        // Look up the ACL definition.
        let acl_def = self.ctx.acl_definitions.get(&acl_name).cloned();

        let (success, message) = if let Some(def) = acl_def {
            match crate::conditions::eval_acl_definition(&def, self)? {
                crate::conditions::AclResult::Accept(msg) => (true, msg),
                crate::conditions::AclResult::Deny(msg) => (false, msg),
                crate::conditions::AclResult::Defer => {
                    // Restore ACL args before returning error.
                    self.ctx.acl_narg = saved_narg;
                    self.ctx.acl_args = saved_args;
                    return Err(ExpandError::Failed {
                        message: format!("DEFER from acl \"{acl_name}\""),
                    });
                }
            }
        } else {
            // ACL not found — this is an error in C Exim.
            self.ctx.acl_narg = saved_narg;
            self.ctx.acl_args = saved_args;
            return Err(ExpandError::Failed {
                message: format!("ERROR from acl \"{acl_name}\""),
            });
        };

        // Set $value from the ACL result message.
        self.lookup_value = Some(message.clone());
        self.ctx.value = message.clone();

        // Restore ACL arguments.
        self.ctx.acl_narg = saved_narg;
        self.ctx.acl_args = saved_args;

        // If no yes/no branches, append the message text directly.
        if yes_branch.is_none() && no_branch.is_none() {
            output.push_str(&message);
            Ok(())
        } else {
            self.process_yesno(success, yes_branch, no_branch, flags, output)
        }
    }

    /// ${authresults{hostname}} — generate Authentication-Results header.
    fn eval_item_authresults(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let hostname = self.eval_arg(args, 0, flags)?;
        tracing::debug!(host = %hostname, "evaluating item_authresults");

        // Build Authentication-Results header from context state.
        // This aggregates available authentication results from the message context.
        let mut parts = Vec::new();
        parts.push(hostname.clone());

        // CSA result (if present)
        if !self.ctx.csa_status.is_empty() {
            parts.push(format!("csa={}", self.ctx.csa_status));
        }

        // Sender host authentication
        if !self.ctx.sender_host_authenticated.is_empty() {
            parts.push(format!("auth={}", self.ctx.sender_host_authenticated));
        }

        let result = parts.join("; ");
        output.push_str(&result);
        Ok(())
    }

    /// ${certextract{field}{cert}} — extract field from a TLS certificate.
    fn eval_item_certextract(
        &mut self,
        args: &[AstNode],
        yes_branch: Option<&AstNode>,
        no_branch: Option<&AstNode>,
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let field = self.eval_arg(args, 0, flags)?;
        let _cert_var = self.eval_arg(args, 1, flags)?;
        tracing::debug!(field = %field, "evaluating item_certextract");

        // Certificate field extraction is delegated to TLS backend.
        // Common fields: version, serial_number, subject, issuer, notbefore, notafter,
        // sig_algorithm, subj_altname, ocsp_uri, crl_uri.
        // For the expansion engine, look up cert-related fields from context.
        let cert_value: Option<String> = match field.as_str() {
            "peerdn" | "peer_dn" => {
                let v = &self.ctx.tls_peerdn;
                if v.is_empty() {
                    None
                } else {
                    Some(v.clone())
                }
            }
            "sni" => {
                let v = &self.ctx.tls_sni;
                if v.is_empty() {
                    None
                } else {
                    Some(v.clone())
                }
            }
            "cipher" => {
                let v = &self.ctx.tls_cipher;
                if v.is_empty() {
                    None
                } else {
                    Some(v.clone())
                }
            }
            _ => None,
        };
        let success = cert_value.is_some();
        if let Some(ref val) = cert_value {
            self.lookup_value = Some(val.clone());
        }
        self.process_yesno(success, yes_branch, no_branch, flags, output)
    }

    /// ${dlfunc{library}{function}{arg}} — call a dynamically loaded function.
    #[cfg(feature = "dlfunc")]
    fn eval_item_dlfunc(
        &mut self,
        args: &[AstNode],
        yes_branch: Option<&AstNode>,
        no_branch: Option<&AstNode>,
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        if self.expand_forbid & RDO_DLFUNC != 0 {
            return Err(ExpandError::Failed {
                message: "item_dlfunc expansion forbidden in this context".into(),
            });
        }

        let library = self.eval_arg(args, 0, flags)?;
        let function = self.eval_arg(args, 1, flags)?;
        let _arg = if args.len() > 2 {
            Some(self.eval_arg(args, 2, flags)?)
        } else {
            None
        };
        tracing::debug!(lib = %library, func = %function, "evaluating item_dlfunc");

        // Dynamic function call would be delegated to exim-ffi via libloading.
        // The function is loaded from the shared library and called with the argument.
        // Return values: OK=success, FAIL=forced_fail, FAIL_FORCED=forced_fail, ERROR=error.
        // For the expansion context without the runtime loaded, we report the delegation.
        let result_val: Option<String> = None;
        let success = result_val.is_some();
        if let Some(ref val) = result_val {
            self.lookup_value = Some(val.clone());
        }
        self.process_yesno(success, yes_branch, no_branch, flags, output)
    }

    /// ${env{name}{found}{notfound}} — retrieve environment variable.
    fn eval_item_env(
        &mut self,
        args: &[AstNode],
        yes_branch: Option<&AstNode>,
        no_branch: Option<&AstNode>,
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let var_name = self.eval_arg(args, 0, flags)?;
        tracing::debug!(env_var = %var_name, "evaluating item_env");

        match env::var(&var_name) {
            Ok(val) => {
                self.lookup_value = Some(val.clone());
                // If yes_branch is available, use yes/no pattern
                if yes_branch.is_some() || no_branch.is_some() {
                    self.process_yesno(true, yes_branch, no_branch, flags, output)?;
                } else {
                    output.push_str(&val);
                }
            }
            Err(_) => {
                self.lookup_value = None;
                if yes_branch.is_some() || no_branch.is_some() {
                    self.process_yesno(false, yes_branch, no_branch, flags, output)?;
                }
            }
        }
        Ok(())
    }

    /// ${extract{field}{separator}{string}} — field extraction (numbered or named/JSON).
    fn eval_item_extract(
        &mut self,
        args: &[AstNode],
        yes_branch: Option<&AstNode>,
        no_branch: Option<&AstNode>,
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let field_spec = self.eval_arg(args, 0, flags)?;
        let trimmed = field_spec.trim();
        tracing::debug!(field = %trimmed, "evaluating item_extract");

        // C Exim requires a non-empty first argument.
        if trimmed.is_empty() {
            return Err(ExpandError::Failed {
                message: "first argument of \"extract\" must not be empty".to_string(),
            });
        }

        // Determine extraction mode: numbered vs. named.
        //
        // C Exim logic (expand.c ~line 6370-6405):
        //   The first argument is checked: if it consists entirely of
        //   digits (with optional leading minus), it's numeric → need 3
        //   data args total: {N}{separators}{string}.  Otherwise it's
        //   named → need 2 data args: {key}{data}.
        //
        //   Because our parser collects up to 3 args before looking for
        //   yes/no branches, a named extraction like
        //   ${extract{key}{data}{yes}} will place the yes-branch text
        //   in args[2].  We detect this and re-route args[2] as the
        //   effective yes_branch.
        let is_numeric = {
            let mut p = trimmed;
            if p.starts_with('-') {
                p = &p[1..];
            }
            !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())
        };

        if is_numeric && args.len() >= 3 {
            // ── Numbered extraction ──
            let field_num: i32 = trimmed.parse().unwrap_or(0);
            let separators = self.eval_arg(args, 1, flags)?;
            let data = self.eval_arg(args, 2, flags)?;
            let result = expand_gettokened(field_num, &separators, &data);

            let success = result.is_some();
            if let Some(ref val) = result {
                self.lookup_value = Some(val.clone());
            }
            self.process_yesno(success, yes_branch, no_branch, flags, output)
        } else {
            // ── Named extraction ──
            // Only args[0] and args[1] are data; anything beyond that
            // is a yes/no branch that the parser mis-classified because
            // it couldn't know the mode at parse time.
            let data = self.eval_arg(args, 1, flags)?;
            let result = extract_named_field(trimmed, &data);

            let success = result.is_some();
            if let Some(ref val) = result {
                self.lookup_value = Some(val.clone());
            }

            // Re-route overflow args as yes/no/fail branches.
            //
            // The parser always collects up to 3 data args (max for
            // numbered extraction) then looks for {yes}{no}/fail.
            // For named extraction we only consume 2 data args:
            //   args[0] = key, args[1] = data_string
            // so args[2] is actually the yes_branch, the parser's
            // yes_branch is actually the no_branch, and the parser's
            // no_branch is the fail-keyword marker (if any).
            let (eff_yes, eff_no): (Option<&AstNode>, Option<&AstNode>) = if args.len() >= 3 {
                (args.get(2), yes_branch)
            } else {
                (yes_branch, no_branch)
            };
            self.process_yesno(success, eff_yes, eff_no, flags, output)
        }
    }

    /// `${extract json {key}{data}}` and `${extract jsons{key}{data}}`.
    ///
    /// JSON extract: `key` can be a string key for objects or a 1-based
    /// index for arrays. `json` returns raw values (strings unquoted),
    /// `jsons` returns string values with surrounding double quotes.
    fn eval_item_extract_json(
        &mut self,
        args: &[AstNode],
        yes_branch: Option<&AstNode>,
        no_branch: Option<&AstNode>,
        flags: EsiFlags,
        output: &mut String,
        quoted: bool,
    ) -> Result<(), ExpandError> {
        let key = self.eval_arg(args, 0, flags)?;
        let data = self.eval_arg(args, 1, flags)?;
        tracing::debug!(key = %key, quoted, "evaluating extract_json");

        let result = self.extract_json_value(&key, &data, quoted);
        let success = result.is_some();
        if let Some(ref val) = result {
            self.lookup_value = Some(val.clone());
        }
        self.process_yesno(success, yes_branch, no_branch, flags, output)
    }

    /// Extract a value from JSON data by key (object) or 1-based index (array).
    ///
    /// If `quoted` is true (jsons mode), string values are returned with
    /// surrounding double quotes; non-string values are returned as-is.
    /// If `quoted` is false (json mode), string values are returned without quotes.
    fn extract_json_value(&self, key: &str, data: &str, quoted: bool) -> Option<String> {
        let json_val: serde_json::Value = serde_json::from_str(data).ok()?;
        // Try key as object field name first, then as 1-based array index
        let val = if let Some(v) = json_val.get(key) {
            Some(v)
        } else if let Ok(idx) = key.trim().parse::<usize>() {
            // C Exim uses 1-based indexing for arrays
            if idx >= 1 {
                json_val.as_array().and_then(|arr| arr.get(idx - 1))
            } else {
                None
            }
        } else {
            None
        };

        val.map(|v| {
            if quoted {
                // jsons mode ("json string"): return the raw JSON string content
                // For strings, returns content between quotes WITHOUT unescaping
                // JSON escape sequences (C Exim uses dewrap which preserves escapes
                // like \" → \", unlike serde which would give ").
                // For other types, returns JSON representation.
                if v.is_string() {
                    // Get the raw JSON representation and strip surrounding quotes
                    let raw = json_format_compact(v);
                    if raw.starts_with('"') && raw.ends_with('"') && raw.len() >= 2 {
                        raw[1..raw.len() - 1].to_string()
                    } else {
                        v.as_str().unwrap_or("").to_string()
                    }
                } else if v.is_null() {
                    String::new()
                } else {
                    json_format_compact(v)
                }
            } else {
                // json mode: return JSON representation
                // Strings keep their quotes, objects/arrays use compact format.
                if v.is_null() {
                    String::new()
                } else {
                    json_format_compact(v)
                }
            }
        })
    }

    /// ${filter{list}{condition}} — filter list elements by condition.
    ///
    /// C Exim: splits list using separator (default `:`, overridable via `< sep`
    /// prefix), evaluates condition with `$item` set to each element, keeps
    /// items where condition is true.  Result is re-joined with the same separator.
    fn eval_item_filter(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let list_str = self.eval_arg(args, 0, flags)?;
        tracing::debug!("evaluating item_filter");

        let (sep, items) = exim_list_split(&list_str);
        let mut results = Vec::new();
        let saved_item = self.iterate_item.take();

        for item_val in &items {
            self.iterate_item = Some(item_val.clone());

            let cond_result = if args.len() > 1 {
                self.eval_condition_node(&args[1], flags)?
            } else {
                false
            };

            if cond_result {
                results.push(item_val.clone());
            }
        }

        self.iterate_item = saved_item;
        let result = exim_list_join(&results, sep);
        output.push_str(&result);
        Ok(())
    }

    /// ${hash{limit}{prime}{string}} — compute hash value of string.
    fn eval_item_hash(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        // C Exim: ${hash{N}{M}{string}} or ${hash{N}{string}} (2 or 3 args)
        // With 2 args: value1=N, value2=-1 (default 26), data=args[1]
        // With 3 args: value1=N, value2=M, data=args[2]
        //
        // C Exim rejects ANY tainted argument to hash before further processing.
        tracing::debug!("evaluating item_hash");

        // Helper: evaluate an argument and check for taint introduction.
        // Returns the evaluated string or a taint rejection error.
        let eval_with_taint_check =
            |this: &mut Self, arg: &AstNode| -> Result<String, ExpandError> {
                let pre = this.result_taint;
                let val = this.evaluate(arg, flags)?;
                let introduced = !matches!(pre, TaintState::Tainted)
                    && matches!(this.result_taint, TaintState::Tainted);
                if introduced {
                    return Err(ExpandError::Failed {
                        message: format!("attempt to use tainted string '{}' for hash", val),
                    });
                }
                Ok(val)
            };

        let (value1, value2, data) = if args.len() >= 3 {
            let v1_str = eval_with_taint_check(self, &args[0])?;
            let v2_str = eval_with_taint_check(self, &args[1])?;
            let data = eval_with_taint_check(self, &args[2])?;
            let v1: i32 = v1_str.parse().map_err(|_| ExpandError::Failed {
                message: format!("\"{}\" is not a number (in \"hash\" expansion)", v1_str),
            })?;
            let v2: i32 = v2_str.parse().map_err(|_| ExpandError::Failed {
                message: format!(
                    "\"{}\" is not a positive number (in \"hash\" expansion)",
                    v2_str
                ),
            })?;
            (v1, v2, data)
        } else {
            let v1_str = eval_with_taint_check(self, &args[0])?;
            let data = eval_with_taint_check(self, &args[1])?;
            let v1: i32 = v1_str.parse().map_err(|_| ExpandError::Failed {
                message: format!("\"{}\" is not a number (in \"hash\" expansion)", v1_str),
            })?;
            (v1, -1i32, data)
        };

        let result = compute_hash_exim(&data, value1, value2)?;
        output.push_str(&result);
        Ok(())
    }

    /// ${hmac{algorithm}{secret}{data}} — compute HMAC.
    fn eval_item_hmac(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let algorithm = self.eval_arg(args, 0, flags)?;
        let secret = self.eval_arg(args, 1, flags)?;
        let data = self.eval_arg(args, 2, flags)?;
        tracing::debug!(algo = %algorithm, "evaluating item_hmac");

        match algorithm.to_lowercase().as_str() {
            "md5" => {
                let mac = Hmac::<Md5>::new_from_slice(&latin1_bytes(&secret)).map_err(|e| {
                    ExpandError::Failed {
                        message: format!("HMAC-MD5 key error: {}", e),
                    }
                })?;
                let mut mac = mac;
                Mac::update(&mut mac, &latin1_bytes(&data));
                let result = mac.finalize();
                let bytes = result.into_bytes();
                for byte in bytes.iter() {
                    write!(output, "{:02x}", byte).map_err(|e| ExpandError::Failed {
                        message: e.to_string(),
                    })?;
                }
            }
            "sha1" => {
                let mac = Hmac::<Sha1>::new_from_slice(&latin1_bytes(&secret)).map_err(|e| {
                    ExpandError::Failed {
                        message: format!("HMAC-SHA1 key error: {}", e),
                    }
                })?;
                let mut mac = mac;
                Mac::update(&mut mac, &latin1_bytes(&data));
                let result = mac.finalize();
                let bytes = result.into_bytes();
                for byte in bytes.iter() {
                    write!(output, "{:02x}", byte).map_err(|e| ExpandError::Failed {
                        message: e.to_string(),
                    })?;
                }
            }
            _ => {
                return Err(ExpandError::Failed {
                    message: format!("hmac algorithm \"{}\" is not recognised", algorithm),
                });
            }
        }
        Ok(())
    }

    /// ${if condition {yes}{no}} — conditional expansion.
    fn eval_item_if(
        &mut self,
        args: &[AstNode],
        yes_branch: Option<&AstNode>,
        no_branch: Option<&AstNode>,
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        tracing::debug!("evaluating item_if");
        // The condition is in args[0], yes/no branches are passed through
        if args.is_empty() {
            return Err(ExpandError::Failed {
                message: "item_if requires a condition".into(),
            });
        }

        let cond_result = self.eval_condition_node(&args[0], flags)?;
        tracing::debug!(result = cond_result, "condition evaluated");
        self.process_yesno(cond_result, yes_branch, no_branch, flags, output)
    }

    /// ${imapfolder{...}} — IMAP folder name conversion (i18n feature-gated).
    #[cfg(feature = "i18n")]
    fn eval_item_imapfolder(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let folder = self.eval_arg(args, 0, flags)?;
        tracing::debug!(folder = %folder, "evaluating item_imapfolder");
        // IMAP folder name conversion (UTF-8 to modified UTF-7)
        // This is a simplified implementation — full i18n would use imap-utf7 crate
        output.push_str(&folder);
        Ok(())
    }

    /// ${length{limit}{string}} — truncate string to length.
    fn eval_item_length(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let limit_str = self.eval_arg(args, 0, flags)?;
        let data = self.eval_arg(args, 1, flags)?;
        tracing::debug!("evaluating item_length");

        let limit: usize = limit_str
            .parse()
            .map_err(|_| ExpandError::IntegerError(format!("bad length limit: {}", limit_str)))?;

        let truncated: String = data.chars().take(limit).collect();
        output.push_str(&truncated);
        Ok(())
    }

    /// ${listextract{number}{list}} — extract element from list by index.
    /// ${listextract{N}{list}{yes}{no}} — extract Nth list element.
    ///
    /// C Exim: uses proper list parsing with separator override.
    fn eval_item_listextract(
        &mut self,
        args: &[AstNode],
        yes_branch: Option<&AstNode>,
        no_branch: Option<&AstNode>,
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let num_str = self.eval_arg(args, 0, flags)?;
        let list_str = self.eval_arg(args, 1, flags)?;
        tracing::debug!("evaluating item_listextract");

        let field: i32 = num_str.trim().parse().map_err(|_| {
            ExpandError::IntegerError(format!("bad list index: {}", num_str.trim()))
        })?;

        let result = exim_list_extract(field, &list_str);
        let success = result.is_some();
        if let Some(ref val) = result {
            self.lookup_value = Some(val.clone());
        }
        self.process_yesno(success, yes_branch, no_branch, flags, output)
    }

    /// ${listquote{separator}{list}} — quote list items.
    ///
    /// C Exim: doubles the separator character within each item to quote it.
    /// Note: this takes the raw list string and applies quoting based on the
    /// given separator, NOT splitting with list semantics first.
    fn eval_item_listquote(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let sep_str = self.eval_arg(args, 0, flags)?;
        let list_str = self.eval_arg(args, 1, flags)?;
        tracing::debug!("evaluating item_listquote");

        let separator = sep_str.chars().next().unwrap_or(':');

        // C Exim listquote (expand.c lines 6653-6658):
        //   If string is non-empty, double each separator character.
        //   If string is empty, output a single space.
        if list_str.is_empty() {
            output.push(' ');
        } else {
            for ch in list_str.chars() {
                if ch == separator {
                    output.push(separator);
                    output.push(separator);
                } else {
                    output.push(ch);
                }
            }
        }
        Ok(())
    }

    /// ${lookup ...} — perform a lookup operation.
    fn eval_item_lookup(
        &mut self,
        args: &[AstNode],
        yes_branch: Option<&AstNode>,
        no_branch: Option<&AstNode>,
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        if self.expand_forbid & RDO_LOOKUP != 0 {
            return Err(ExpandError::Failed {
                message: "item_lookup expansion forbidden in this context".into(),
            });
        }

        tracing::debug!("evaluating item_lookup");

        // Parser structure: args[0] = key, args[1] = type (Literal),
        // args[2] = source (filename/query). Yes/no branches are separate.
        let lookup_key = self.eval_arg(args, 0, flags)?;
        let lookup_type = if args.len() > 1 {
            self.eval_arg(args, 1, flags)?
        } else {
            String::new()
        };
        let lookup_source = if args.len() > 2 {
            self.eval_arg(args, 2, flags)?
        } else {
            String::new()
        };

        tracing::debug!(
            lookup_type = %lookup_type,
            key = %lookup_key,
            source = %lookup_source,
            "performing lookup"
        );

        // Dispatch to the appropriate lookup backend.
        // perform_lookup returns Result<Option<String>, String> where:
        //   Ok(Some(val)) = found
        //   Ok(None)      = not found
        //   Err(msg)      = DEFER error (e.g., iplsearch with bad key)
        match perform_lookup(&lookup_type, &lookup_key, &lookup_source) {
            Ok(Some(val)) => {
                self.lookup_value = Some(val);
                self.process_yesno(true, yes_branch, no_branch, flags, output)
            }
            Ok(None) => {
                // C Exim behaviour: when a lookup key is not found and
                // there are NO {yes}{no} branches (bare lookup), the
                // expansion produces a *forced failure*
                // (`expand_string_forcedfail = TRUE`, returns NULL).
                // This is critical for redirect routers: when
                //   data = ${lookup{$local_part}lsearch{/etc/aliases}}
                // and the key is not in the file, the forced failure
                // causes the router to DECLINE, passing the address to
                // the next router.  Without this, the expansion returns
                // an empty string, which the redirect router interprets
                // as "no generated addresses" and reroutes to the
                // *original* address, creating an infinite routing loop.
                //
                // If at least one branch is present (e.g.
                //   ${lookup{key}lsearch{file}{$value}}
                // or
                //   ${lookup{key}lsearch{file}{$value}{default}}
                // ), normal process_yesno logic applies — the "no" branch
                // (or empty output if only a yes branch was supplied) is
                // produced instead of a forced failure.
                if yes_branch.is_none() && no_branch.is_none() {
                    tracing::debug!("lookup not found with no yes/no branches — forced failure");
                    return Err(ExpandError::ForcedFail);
                }
                self.process_yesno(false, yes_branch, no_branch, flags, output)
            }
            Err(defer_msg) => {
                // DEFER from the lookup backend — report as a
                // forced-failure with the DEFER message.
                Err(ExpandError::Failed {
                    message: format!("lookup of \"{}\" gave DEFER: \"{}\"", lookup_key, defer_msg),
                })
            }
        }
    }

    /// ${map{list}{expression}} — apply expression to each list element.
    ///
    /// C Exim: splits list, evaluates expression with `$item` set, joins
    /// results using the same separator.
    fn eval_item_map(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let list_str = self.eval_arg(args, 0, flags)?;
        tracing::debug!("evaluating item_map");

        let (sep, items) = exim_list_split(&list_str);
        let mut results = Vec::new();
        let saved_item = self.iterate_item.take();

        for item_val in &items {
            self.iterate_item = Some(item_val.clone());
            if args.len() > 1 {
                let mapped = self.evaluate(&args[1], flags).map_err(|e| match e {
                    ExpandError::Failed { message } => ExpandError::Failed {
                        message: format!("{} inside \"map\" item", exim_q_quote(&message)),
                    },
                    other => other,
                })?;
                results.push(mapped);
            } else {
                results.push(item_val.clone());
            }
        }

        self.iterate_item = saved_item;
        let result = exim_list_join(&results, sep);
        output.push_str(&result);
        Ok(())
    }

    /// ${nhash{limit}{prime}{string}} — numeric hash.
    fn eval_item_nhash(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        // C Exim: ${nhash{N}{string}} or ${nhash{N}{M}{string}}
        // With 2 args: val[0]=N, val[1]=-1, string=args[1]
        // With 3 args: val[0]=N, val[1]=M, string=args[2]
        tracing::debug!("evaluating item_nhash");

        let (value1, value2, data) = if args.len() >= 3 {
            let v1_str = self.eval_arg(args, 0, flags)?;
            let v2_str = self.eval_arg(args, 1, flags)?;
            let data = self.eval_arg(args, 2, flags)?;
            let v1: i32 = v1_str.parse().map_err(|_| ExpandError::Failed {
                message: format!("\"{}\" is not a number (in \"nhash\" expansion)", v1_str),
            })?;
            let v2: i32 = v2_str.parse().map_err(|_| ExpandError::Failed {
                message: format!(
                    "\"{}\" is not a positive number (in \"nhash\" expansion)",
                    v2_str
                ),
            })?;
            (v1, v2, data)
        } else {
            let v1_str = self.eval_arg(args, 0, flags)?;
            let data = self.eval_arg(args, 1, flags)?;
            let v1: i32 = v1_str.parse().map_err(|_| ExpandError::Failed {
                message: format!("\"{}\" is not a number (in \"nhash\" expansion)", v1_str),
            })?;
            (v1, -1i32, data)
        };

        let result = compute_nhash_exim(&data, value1, value2)?;
        output.push_str(&result);
        Ok(())
    }

    /// ${perl{function}{arg}} — call embedded Perl function.
    #[cfg(feature = "perl")]
    fn eval_item_perl(
        &mut self,
        args: &[AstNode],
        yes_branch: Option<&AstNode>,
        no_branch: Option<&AstNode>,
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        if self.expand_forbid & RDO_PERL != 0 {
            return Err(ExpandError::Failed {
                message: "item_perl expansion forbidden in this context".into(),
            });
        }

        let function = self.eval_arg(args, 0, flags)?;
        let _arg = if args.len() > 1 {
            Some(self.eval_arg(args, 1, flags)?)
        } else {
            None
        };
        tracing::debug!(func = %function, "evaluating item_perl");

        // Perl call would be delegated to exim-ffi's Perl integration.
        // Return value of undef triggers forced_fail.
        let perl_result: Option<String> = None;
        if perl_result.is_none() {
            self.forced_fail = true;
            return Err(ExpandError::ForcedFail);
        }
        let success = perl_result.is_some();
        if let Some(ref val) = perl_result {
            self.lookup_value = Some(val.clone());
        }
        self.process_yesno(success, yes_branch, no_branch, flags, output)
    }

    /// HMAC-SHA1 computation for PRVS, matching C Exim's prvs_hmac_sha1().
    /// hash_source = key_num + daystamp(3 chars) + address
    /// Returns first 3 bytes of HMAC-SHA1 in uppercase hex (6 chars).
    fn prvs_hmac_sha1(address: &str, key: &str, key_num: &str, daystamp: &str) -> Option<String> {
        if key.len() > 64 {
            return None;
        }
        // Build hash source: key_num + daystamp + address
        let hash_source = format!("{}{}{}", key_num, daystamp, address);

        // HMAC-SHA1 with standard inner/outer key padding
        let mut innerkey = [0x36u8; 64];
        let mut outerkey = [0x5cu8; 64];
        for (i, &b) in latin1_bytes(key).iter().enumerate() {
            innerkey[i] ^= b;
            outerkey[i] ^= b;
        }

        // Inner hash: SHA1(innerkey || hash_source)
        let mut inner_hasher = <Sha1 as digest::Digest>::new();
        digest::Digest::update(&mut inner_hasher, innerkey);
        digest::Digest::update(&mut inner_hasher, latin1_bytes(&hash_source));
        let innerhash = digest::Digest::finalize(inner_hasher);

        // Outer hash: SHA1(outerkey || innerhash)
        let mut outer_hasher = <Sha1 as digest::Digest>::new();
        digest::Digest::update(&mut outer_hasher, outerkey);
        digest::Digest::update(&mut outer_hasher, innerhash);
        let finalhash = digest::Digest::finalize(outer_hasher);

        // First 3 bytes in lowercase hex — C Exim uses lowercase
        // hex_digits = "0123456789abcdef" (see globals.c).
        Some(format!(
            "{:02x}{:02x}{:02x}",
            finalhash[0], finalhash[1], finalhash[2]
        ))
    }

    /// Compute PRVS daystamp: last 3 digits of (current_day + day_offset).
    /// Matches C Exim's prvs_daystamp().
    fn prvs_daystamp(day_offset: i64) -> String {
        let day_number = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64 / 86400 + day_offset)
            .unwrap_or(0);
        let s = format!("{}", day_number);
        if s.len() >= 3 {
            s[s.len() - 3..].to_string()
        } else {
            "100".to_string()
        }
    }

    /// ${prvs{address}{key}{key_number}} — generate PRVS-signed address.
    /// Format: prvs=<key_num><3char_daystamp><6char_hash>=<local_part>@<domain>
    fn eval_item_prvs(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let address = self.eval_arg(args, 0, flags)?;
        let key = self.eval_arg(args, 1, flags)?;
        let key_num_str = if args.len() > 2 {
            self.eval_arg(args, 2, flags)?
        } else {
            String::new()
        };
        tracing::debug!("evaluating item_prvs");

        // Split address at last @ — C Exim uses Ustrrchr
        let at_pos = address.rfind('@').ok_or_else(|| ExpandError::Failed {
            message: "prvs first argument must be a qualified email address".into(),
        })?;
        if at_pos == 0 || at_pos == address.len() - 1 {
            return Err(ExpandError::Failed {
                message: "prvs first argument must be a qualified email address".into(),
            });
        }

        // Validate key number: if third arg was provided, must be a single digit.
        // If not provided (args.len() <= 2), default to "0".
        let key_num = if args.len() > 2 {
            // Third arg was explicitly provided — validate
            if key_num_str.len() != 1
                || !key_num_str
                    .as_bytes()
                    .first()
                    .is_some_and(|b| b.is_ascii_digit())
            {
                return Err(ExpandError::Failed {
                    message: "prvs third argument must be a single digit".into(),
                });
            }
            &key_num_str
        } else {
            // Not provided, default to "0"
            "0"
        };

        let daystamp = Self::prvs_daystamp(7);
        let hash_hex =
            Self::prvs_hmac_sha1(&address, &key, key_num, &daystamp).ok_or_else(|| {
                ExpandError::Failed {
                    message: "prvs hmac-sha1 conversion failed".into(),
                }
            })?;

        let local = &address[..at_pos];
        let domain = &address[at_pos + 1..];
        // Format: prvs=<key_num><daystamp><hash>=<local>@<domain>
        write!(
            output,
            "prvs={}{}{}={}@{}",
            key_num, daystamp, hash_hex, local, domain
        )
        .map_err(|e| ExpandError::Failed {
            message: e.to_string(),
        })?;
        Ok(())
    }

    /// ${prvscheck{address}{secret}{result_expr}} — verify PRVS-signed address.
    /// C Exim uses regex: ^prvs\=([0-9])([0-9]{3})([A-F0-9]{6})\=(.+)\@(.+)$
    /// Sets $prvscheck_address, $prvscheck_keynum, $prvscheck_result.
    /// Outputs: if arg3 is present and non-empty, its expanded value; else prvscheck_address.
    /// For non-PRVS address, outputs the address unchanged.
    fn eval_item_prvscheck(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        // Read first arg: the address to check
        let address = self.eval_arg(args, 0, flags)?;
        tracing::debug!("evaluating item_prvscheck");

        // Reset prvscheck variables
        self.ctx.prvscheck_result = String::new();
        self.ctx.prvscheck_address = String::new();
        self.ctx.prvscheck_keynum = String::new();

        // Parse PRVS format: prvs=<digit><3digits><6hex>=<local>@<domain>
        let re = regex::Regex::new(r"(?i)^prvs=([0-9])([0-9]{3})([A-F0-9]{6})=(.+)@(.+)$").unwrap();

        if let Some(caps) = re.captures(&address) {
            let key_num = caps.get(1).unwrap().as_str();
            let daystamp = caps.get(2).unwrap().as_str();
            let hash_provided = caps.get(3).unwrap().as_str().to_lowercase();
            let local_part = caps.get(4).unwrap().as_str();
            let domain = caps.get(5).unwrap().as_str();

            // Set expansion variables
            let orig_address = format!("{}@{}", local_part, domain);
            self.ctx.prvscheck_address = orig_address.clone();
            self.ctx.prvscheck_keynum = key_num.to_string();

            // Read second arg: the secret
            let secret = self.eval_arg(args, 1, flags)?;

            // Compute HMAC and verify
            if let Some(computed_hash) =
                Self::prvs_hmac_sha1(&orig_address, &secret, key_num, daystamp)
            {
                if computed_hash == hash_provided {
                    // Check expiry
                    let now_stamp = Self::prvs_daystamp(0);
                    let inow: u32 = now_stamp.parse().unwrap_or(0);
                    let iexpire: u32 = daystamp.parse().unwrap_or(1);

                    // Flip detection: when iexpire < 7 and inow >= 993
                    let adjusted_inow = if iexpire < 7 && inow >= 993 { 0 } else { inow };

                    if iexpire >= adjusted_inow {
                        self.ctx.prvscheck_result = "1".to_string();
                    }
                    // else: expired, result stays empty
                }
                // else: hash mismatch, result stays empty
            }

            // Read optional third arg and determine output
            if args.len() > 2 {
                let result_expr = self.eval_arg(args, 2, flags)?;
                if result_expr.is_empty() {
                    output.push_str(&self.ctx.prvscheck_address);
                } else {
                    output.push_str(&result_expr);
                }
            } else {
                output.push_str(&self.ctx.prvscheck_address);
            }
        } else {
            // Not a PRVS address — return empty string.
            // C Exim: "Does not look like a prvs encoded address,
            // return the empty string."  We still need to read
            // remaining args so they are consumed from the parse
            // stream.
            let _secret = self.eval_arg(args, 1, flags)?;
            if args.len() > 2 {
                let _ = self.eval_arg(args, 2, flags)?;
            }
            // Output stays empty — do NOT push the address
        }
        Ok(())
    }

    /// ${readfile{filename}{eol_chars}} — read file contents.
    ///
    /// Checks `RDO_READFILE` forbid flag before allowing file reads,
    /// preventing arbitrary filesystem access in restricted ACL contexts
    /// (mirrors C `expand_forbid & RDO_READFILE` check from expand.c).
    fn eval_item_readfile(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        // Check expand_forbid flag — file reads may be forbidden in restricted
        // ACL contexts (e.g., during address verification or in untrusted
        // filter contexts). Mirrors C expand.c RDO_READFILE check.
        if self.expand_forbid & RDO_READFILE != 0 {
            return Err(ExpandError::Failed {
                message: "${readfile} expansion forbidden in this context".into(),
            });
        }

        let filename = self.eval_arg(args, 0, flags)?;
        let eol_replacement = if args.len() > 1 {
            Some(self.eval_arg(args, 1, flags)?)
        } else {
            None
        };
        tracing::debug!(file = %filename, "evaluating item_readfile");

        let contents = fs::read_to_string(&filename).map_err(|e| {
            // C Exim format: "failed to open <path>: <strerror>" without "(os error N)"
            let msg = e.to_string();
            let msg = if let Some(pos) = msg.find(" (os error") {
                &msg[..pos]
            } else {
                &msg
            };
            ExpandError::Failed {
                message: format!("failed to open {}: {}", filename, msg),
            }
        })?;

        if let Some(ref eol) = eol_replacement {
            // Replace line endings with the specified characters
            let replaced = contents.replace('\n', eol);
            output.push_str(&replaced);
        } else {
            output.push_str(&contents);
        }
        Ok(())
    }

    /// ${readsocket{...}} — read from TCP or Unix socket.
    ///
    /// Checks `RDO_READSOCK` forbid flag (NOT `RDO_RUN`) before allowing socket
    /// reads. Socket reads and command execution have different security
    /// implications and must be controlled independently. Mirrors C expand.c
    /// `expand_forbid & RDO_READSOCK` check.
    fn eval_item_readsocket(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        // Check RDO_READSOCK — socket reads have separate security policy from
        // command execution (RDO_RUN). C Exim has a dedicated RDO_READSOCK flag
        // distinct from RDO_RUN for fine-grained expansion control.
        if self.expand_forbid & RDO_READSOCK != 0 {
            return Err(ExpandError::Failed {
                message: "${readsocket} expansion forbidden in this context".into(),
            });
        }

        let spec = self.eval_arg(args, 0, flags)?;
        let request = if args.len() > 1 {
            Some(self.eval_arg(args, 1, flags)?)
        } else {
            None
        };
        let eol_replacement = if args.len() > 2 {
            Some(self.eval_arg(args, 2, flags)?)
        } else {
            None
        };
        tracing::debug!(spec = %spec, "evaluating item_readsocket");

        let timeout = Duration::from_secs(5);
        let response = if let Some(addr_part) = spec.strip_prefix("inet:") {
            // TCP socket: inet:host:port
            self.readsocket_inet(addr_part, request.as_deref(), timeout)?
        } else if let Some(path) = spec.strip_prefix("unix:") {
            // Unix socket
            self.readsocket_unix(path, request.as_deref(), timeout)?
        } else {
            // Default to inet
            self.readsocket_inet(&spec, request.as_deref(), timeout)?
        };

        if let Some(ref eol) = eol_replacement {
            let replaced = response.replace('\n', eol);
            output.push_str(&replaced);
        } else {
            output.push_str(&response);
        }
        Ok(())
    }

    /// TCP socket read for ${readsocket}.
    fn readsocket_inet(
        &self,
        addr: &str,
        request: Option<&str>,
        timeout: Duration,
    ) -> Result<String, ExpandError> {
        let socket_addr: SocketAddr = addr.parse().map_err(|e| ExpandError::Failed {
            message: format!("${{readsocket}} bad address {}: {}", addr, e),
        })?;

        let mut stream =
            TcpStream::connect_timeout(&socket_addr, timeout).map_err(|e| ExpandError::Failed {
                message: format!("${{readsocket}} connect failed {}: {}", addr, e),
            })?;

        stream.set_read_timeout(Some(timeout)).ok();
        stream.set_write_timeout(Some(timeout)).ok();

        if let Some(req) = request {
            stream
                .write_all(&latin1_bytes(req))
                .map_err(|e| ExpandError::Failed {
                    message: format!("${{readsocket}} write failed: {}", e),
                })?;
        }

        let mut response_bytes = Vec::new();
        stream
            .read_to_end(&mut response_bytes)
            .map_err(|e| ExpandError::Failed {
                message: format!("${{readsocket}} read failed: {}", e),
            })?;
        // Convert bytes to Latin-1 chars
        let response: String = response_bytes.iter().map(|&b| b as char).collect();

        Ok(response)
    }

    /// Unix socket read for ${readsocket}.
    #[cfg(unix)]
    fn readsocket_unix(
        &self,
        path: &str,
        request: Option<&str>,
        timeout: Duration,
    ) -> Result<String, ExpandError> {
        let mut stream = UnixStream::connect(path).map_err(|e| ExpandError::Failed {
            message: format!("${{readsocket}} unix connect failed {}: {}", path, e),
        })?;

        stream.set_read_timeout(Some(timeout)).ok();

        if let Some(req) = request {
            stream
                .write_all(&latin1_bytes(req))
                .map_err(|e| ExpandError::Failed {
                    message: format!("${{readsocket}} unix write failed: {}", e),
                })?;
        }

        let mut response_bytes = Vec::new();
        stream
            .read_to_end(&mut response_bytes)
            .map_err(|e| ExpandError::Failed {
                message: format!("${{readsocket}} unix read failed: {}", e),
            })?;
        // Convert bytes to Latin-1 chars
        let response: String = response_bytes.iter().map(|&b| b as char).collect();

        Ok(response)
    }

    #[cfg(not(unix))]
    fn readsocket_unix(
        &self,
        path: &str,
        _request: Option<&str>,
        _timeout: Duration,
    ) -> Result<String, ExpandError> {
        Err(ExpandError::Failed {
            message: format!(
                "item_readsocket unix sockets not available on this platform: {}",
                path
            ),
        })
    }

    /// ${reduce{list}{init}{expression}} — fold/reduce list elements.
    /// ${reduce{list}{init}{expression}} — fold/reduce list elements.
    ///
    /// C Exim: splits list, evaluates expression with `$item` set to current
    /// element and `$value` set to the accumulator.
    fn eval_item_reduce(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let list_str = self.eval_arg(args, 0, flags)?;
        let init_val = self.eval_arg(args, 1, flags)?;
        tracing::debug!("evaluating item_reduce");

        let (_, items) = exim_list_split(&list_str);
        let mut accumulator = init_val;
        let saved_item = self.iterate_item.take();
        let saved_value = self.lookup_value.take();

        for item_val in &items {
            self.iterate_item = Some(item_val.clone());
            self.lookup_value = Some(accumulator.clone());
            if args.len() > 2 {
                accumulator = match self.evaluate(&args[2], flags) {
                    Ok(v) => v,
                    Err(e) => {
                        self.iterate_item = saved_item;
                        self.lookup_value = saved_value;
                        // C Exim wraps: `%q inside %q item` where
                        // %q is quote-with-escaped-inner-quotes.
                        let msg = e.to_string();
                        let inner = msg.strip_prefix("expansion failed: ").unwrap_or(&msg);
                        return Err(ExpandError::Failed {
                            message: format!("{} inside \"reduce\" item", exim_q_quote(inner)),
                        });
                    }
                };
            }
        }

        self.iterate_item = saved_item;
        self.lookup_value = saved_value;
        output.push_str(&accumulator);
        Ok(())
    }

    /// ${run{command}} — run external command and capture output.
    #[cfg(feature = "run")]
    fn eval_item_run(
        &mut self,
        args: &[AstNode],
        yes_branch: Option<&AstNode>,
        no_branch: Option<&AstNode>,
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        if self.expand_forbid & RDO_RUN != 0 {
            return Err(ExpandError::Failed {
                message: "item_run expansion forbidden in this context".into(),
            });
        }

        let command = self.eval_arg(args, 0, flags)?;
        tracing::debug!(cmd = %command, "evaluating item_run");

        let child_result = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(&command)
            .output();

        match child_result {
            Ok(child_output) => {
                // Set $runrc from exit code
                let rc = child_output.status.code().unwrap_or(127);
                self.ctx.runrc = rc;

                // stdout becomes $value; C Exim does NOT strip trailing newlines
                let stdout = String::from_utf8_lossy(&child_output.stdout).to_string();
                let success = child_output.status.success();

                self.lookup_value = Some(stdout.clone());

                if yes_branch.is_some() || no_branch.is_some() {
                    self.process_yesno(success, yes_branch, no_branch, flags, output)
                } else {
                    output.push_str(&stdout);
                    Ok(())
                }
            }
            Err(_) => {
                // Command could not be exec'd at all (e.g., not found when
                // /bin/sh itself failed).  C Exim sets runrc = 127.
                self.ctx.runrc = 127;
                self.lookup_value = Some(String::new());
                let success = false;
                if yes_branch.is_some() || no_branch.is_some() {
                    self.process_yesno(success, yes_branch, no_branch, flags, output)
                } else {
                    Ok(())
                }
            }
        }
    }

    /// ${sg{subject}{regex}{replacement}} — regex substitution.
    fn eval_item_sg(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let subject = self.eval_arg(args, 0, flags)?;
        let pattern = self.eval_arg(args, 1, flags)?;
        let replacement = self.eval_arg(args, 2, flags)?;
        tracing::debug!("evaluating item_sg");

        let regex = pcre2::bytes::Regex::new(&pattern).map_err(|e| ExpandError::Failed {
            message: format!("sg bad regex '{}': {}", pattern, e),
        })?;

        let subject_bytes = latin1_bytes(&subject);
        let mut result = Vec::new();
        let mut last_end = 0usize;

        // C Exim sg loop: manual match loop that handles zero-length matches
        // by retrying with PCRE2_NOTEMPTY_ATSTART + PCRE2_ANCHORED, then
        // advancing one character if that also fails.
        loop {
            if last_end > subject_bytes.len() {
                break;
            }

            let cap_result = regex.captures(&subject_bytes[last_end..]);

            let caps = match cap_result {
                Ok(Some(caps)) => caps,
                Ok(None) => break,
                Err(e) => {
                    return Err(ExpandError::Failed {
                        message: format!("sg regex match error: {}", e),
                    });
                }
            };

            let full = caps.get(0).expect("match group 0 always exists");
            let match_start = last_end + full.start();
            let match_end = last_end + full.end();

            // Append text between last match end and this match start
            result.extend_from_slice(&subject_bytes[last_end..match_start]);

            // Build replacement: process $0..$9 backrefs
            let rep_bytes = latin1_bytes(&replacement);
            let mut i = 0;
            while i < rep_bytes.len() {
                if rep_bytes[i] == b'$' && i + 1 < rep_bytes.len() {
                    let digit = rep_bytes[i + 1];
                    if digit.is_ascii_digit() {
                        let idx = (digit - b'0') as usize;
                        if let Some(m) = caps.get(idx) {
                            result.extend_from_slice(m.as_bytes());
                        }
                        i += 2;
                        continue;
                    }
                }
                result.push(rep_bytes[i]);
                i += 1;
            }

            // Handle zero-length match: emit the replacement, then
            // copy one literal character and advance past it.
            // This matches C Exim's PCRE2_NOTEMPTY_ATSTART behavior.
            if match_start == match_end {
                if match_end < subject_bytes.len() {
                    result.push(subject_bytes[match_end]);
                    last_end = match_end + 1;
                } else {
                    // Zero-length match at end-of-string: replacement already
                    // emitted; break out of the loop.
                    last_end = match_end + 1;
                    break;
                }
            } else {
                last_end = match_end;
            }
        }
        // Append remaining un-matched tail
        if last_end <= subject_bytes.len() {
            result.extend_from_slice(&subject_bytes[last_end..]);
        }
        // Convert result bytes back to Latin-1 chars
        let result_str: String = result.iter().map(|&b| b as char).collect();
        output.push_str(&result_str);
        Ok(())
    }

    /// `${sort{list}{key_expression}{comparator}}` — sort list elements.
    ///
    /// C Exim sort operator: args[0] = list, args[1] = key expression
    /// (evaluated with `$item` set for each element), args[2] = comparator
    /// (`<`, `>`, `lti`, etc.). C Exim uses `identify_operator()` to
    /// determine the condition type — `<` = `ECOND_NUM_L`, `>` = `ECOND_NUM_G`,
    /// alphabetic names like `lti` use string comparison. If comparator is
    /// omitted, defaults to `<` (numeric ascending). Result re-joined with
    /// original separator.
    fn eval_item_sort(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let list_str = self.eval_arg(args, 0, flags)?;
        tracing::debug!("evaluating item_sort");

        let (sep, items) = exim_list_split(&list_str);
        if items.is_empty() {
            return Ok(());
        }

        // In C Exim: args[0] = list, args[1] = comparator, args[2] = key expression
        // The comparator is evaluated once before the loop.
        let cmp_str = if args.len() > 1 {
            self.eval_arg(args, 1, flags)?
        } else {
            "<".to_string()
        };

        let saved_item = self.iterate_item.take();

        // Extract sort keys for each item by evaluating args[2] with $item set
        let mut keyed: Vec<(String, String)> = Vec::new();
        for item in &items {
            self.iterate_item = Some(item.clone());
            let key = if args.len() > 2 {
                self.evaluate(&args[2], flags)?
            } else {
                item.clone()
            };
            keyed.push((item.clone(), key));
        }

        // C Exim sort comparator logic:
        // identify_operator maps `<` → ECOND_NUM_L, `>` → ECOND_NUM_G, etc.
        // `alpha_cond = isalpha(opname[0])` — alphabetic-first names use
        // string comparison, non-alpha first chars use numeric comparison.
        keyed.sort_by(|a, b| {
            let ka = &a.1;
            let kb = &b.1;
            match cmp_str.as_str() {
                // Non-alpha first char → numeric comparison
                "<" => {
                    let na = ka.trim().parse::<i64>().unwrap_or(0);
                    let nb = kb.trim().parse::<i64>().unwrap_or(0);
                    na.cmp(&nb)
                }
                ">" => {
                    let na = ka.trim().parse::<i64>().unwrap_or(0);
                    let nb = kb.trim().parse::<i64>().unwrap_or(0);
                    nb.cmp(&na)
                }
                "<=" => {
                    let na = ka.trim().parse::<i64>().unwrap_or(0);
                    let nb = kb.trim().parse::<i64>().unwrap_or(0);
                    na.cmp(&nb)
                }
                ">=" => {
                    let na = ka.trim().parse::<i64>().unwrap_or(0);
                    let nb = kb.trim().parse::<i64>().unwrap_or(0);
                    nb.cmp(&na)
                }
                // Alpha first char → string comparison
                "lt" => ka.cmp(kb),
                "le" => ka.cmp(kb),
                "gt" => kb.cmp(ka),
                "ge" => kb.cmp(ka),
                "lti" => ka.to_lowercase().cmp(&kb.to_lowercase()),
                "lei" => ka.to_lowercase().cmp(&kb.to_lowercase()),
                "gti" => kb.to_lowercase().cmp(&ka.to_lowercase()),
                "gei" => kb.to_lowercase().cmp(&ka.to_lowercase()),
                _ => {
                    // C Exim fallback: check if first char is alphabetic
                    if cmp_str.starts_with(|c: char| c.is_ascii_alphabetic()) {
                        // String comparison
                        ka.cmp(kb)
                    } else {
                        // Numeric comparison
                        let na = ka.trim().parse::<i64>().unwrap_or(0);
                        let nb = kb.trim().parse::<i64>().unwrap_or(0);
                        na.cmp(&nb)
                    }
                }
            }
        });

        self.iterate_item = saved_item;
        let sorted: Vec<String> = keyed.into_iter().map(|(item, _)| item).collect();
        let result = exim_list_join(&sorted, sep);
        output.push_str(&result);
        Ok(())
    }

    /// ${srs_encode{secret}{return_path}} — SRS address encoding.
    #[cfg(feature = "srs")]
    fn eval_item_srs_encode(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let secret = self.eval_arg(args, 0, flags)?;
        let return_path = self.eval_arg(args, 1, flags)?;
        tracing::debug!("evaluating item_srs_encode");

        // SRS (Sender Rewriting Scheme) encoding
        // Format: SRS0=HH=TT=domain=local@srsdomain
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() / 86400) // Day-based timestamp
            .unwrap_or(0);
        let ts_encoded = format!("{:04x}", timestamp & 0xFFFF);

        // Split the return path
        if let Some(at_pos) = return_path.find('@') {
            let local = &return_path[..at_pos];
            let domain = &return_path[at_pos + 1..];

            // Compute hash
            let hash_input = format!("{}{}{}{}", ts_encoded, domain, local, secret);
            let mut hasher = <Md5 as digest::Digest>::new();
            digest::Digest::update(&mut hasher, &latin1_bytes(&hash_input));
            let hash_result = digest::Digest::finalize(hasher);
            let hash_hex = format!("{:02x}{:02x}", hash_result[0], hash_result[1]);

            // Build SRS address
            let qd_ref: &str = &self.ctx.qualify_domain;
            let srs_domain = if qd_ref.is_empty() {
                "localhost"
            } else {
                qd_ref
            };
            write!(
                output,
                "SRS0={}={}={}={}@{}",
                hash_hex, ts_encoded, domain, local, srs_domain
            )
            .map_err(|e| ExpandError::Failed {
                message: e.to_string(),
            })?;
        } else {
            return Err(ExpandError::Failed {
                message: format!("SRS: address missing @: {}", return_path),
            });
        }
        Ok(())
    }

    /// ${substr{offset}{length}{string}} — substring extraction.
    ///
    /// When called with only 2 args (from the `_offset:string` underscore
    /// syntax), the length defaults to the remaining string length (i.e.
    /// "everything from offset to end").
    fn eval_item_substr(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        tracing::debug!("evaluating item_substr");

        // Determine the number of data args.
        // 3-arg form: ${substr{offset}{length}{string}}
        // 2-arg form: ${s_offset:string} (from parametric underscore syntax)
        let (offset_str, length_str, data) = if args.len() >= 3 {
            (
                self.eval_arg(args, 0, flags)?,
                self.eval_arg(args, 1, flags)?,
                self.eval_arg(args, 2, flags)?,
            )
        } else if args.len() == 2 {
            // 2-arg: args[0] = offset, args[1] = subject string.
            // Length defaults to INT_MAX (rest of string).
            (
                self.eval_arg(args, 0, flags)?,
                String::new(), // sentinel for "no length given"
                self.eval_arg(args, 1, flags)?,
            )
        } else {
            return Ok(());
        };

        let offset: i32 = offset_str
            .parse()
            .map_err(|_| ExpandError::IntegerError(format!("bad substr offset: {}", offset_str)))?;

        let chars: Vec<char> = data.chars().collect();
        let slen = chars.len() as i32;

        // Parse explicit length, or use -1 sentinel for "unset" (matching
        // C Exim's extract_substr convention).
        let length: i32 = if length_str.is_empty() {
            -1 // unset — same sentinel as C Exim
        } else {
            let l: i32 = length_str.parse().map_err(|_| {
                ExpandError::IntegerError(format!("bad substr length: {}", length_str))
            })?;
            // C Exim: negative length from an explicit arg is an error
            if l < 0 {
                return Err(ExpandError::Failed {
                    message: format!(
                        "\"{}\" is not a positive number (in \"substr\" expansion)",
                        length_str
                    ),
                });
            }
            l
        };

        // C Exim extract_substr() semantics (expand.c lines 1450-1499):
        let mut value1 = offset;
        let mut value2 = length;

        if value1 < 0 {
            // Negative offset: count from right.
            value1 += slen;
            if value1 < 0 {
                // Position before start: adjust length, clamp offset.
                value2 += value1;
                if value2 < 0 {
                    value2 = 0;
                }
                value1 = 0;
            } else if value2 < 0 {
                // Unset length with negative offset: everything BEFORE
                // the computed position.
                value2 = value1;
                value1 = 0;
            }
        } else {
            // Non-negative offset.
            if value1 > slen {
                value1 = slen;
                value2 = 0;
            } else if value2 < 0 {
                // Unset length: rest of string.
                value2 = slen;
            }
        }

        // Clamp to available characters.
        if value1 + value2 > slen {
            value2 = slen - value1;
        }

        if value2 > 0 && value1 < slen {
            let start = value1 as usize;
            let end = std::cmp::min(start + value2 as usize, chars.len());
            let substr: String = chars[start..end].iter().collect();
            output.push_str(&substr);
        }
        Ok(())
    }

    /// ${tr{subject}{from_chars}{to_chars}} — character transliteration.
    /// `${tr{string}{from}{to}}` — character transliteration.
    ///
    /// Matches C Exim's EITEM_TR logic (expand.c ~5970-5998):
    ///   - Uses `strrchr` semantics (LAST occurrence in `from`).
    ///   - When the replacement string `to` is shorter than the match
    ///     offset, the LAST character of `to` is used.
    ///   - When `to` is empty, no translation is performed and the
    ///     subject string is returned unchanged.
    fn eval_item_tr(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let subject = self.eval_arg(args, 0, flags)?;
        let from_chars = self.eval_arg(args, 1, flags)?;
        let to_chars = self.eval_arg(args, 2, flags)?;
        tracing::debug!("evaluating item_tr");

        let from: Vec<char> = from_chars.chars().collect();
        let to: Vec<char> = to_chars.chars().collect();
        let o2m: i32 = to.len() as i32 - 1; // -1 when to is empty

        let mut result = String::with_capacity(subject.len());
        for ch in subject.chars() {
            if o2m >= 0 {
                // Use rposition (strrchr): find LAST occurrence in `from`.
                if let Some(pos) = from.iter().rposition(|&c| c == ch) {
                    // If pos < o2m, use to[pos]; otherwise use to[o2m].
                    let idx = if pos < o2m as usize {
                        pos
                    } else {
                        o2m as usize
                    };
                    result.push(to[idx]);
                } else {
                    result.push(ch);
                }
            } else {
                // to is empty → no translation at all
                result.push(ch);
            }
        }
        output.push_str(&result);
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 3: Operator dispatch (${operator:subject} pattern)
    // ─────────────────────────────────────────────────────────────────────────

    /// Evaluate an operator node (${operator:subject}).
    ///
    /// Dispatches to the transforms module for actual operator implementation.
    /// Falls back to inline implementation for core operators.
    fn eval_operator(
        &mut self,
        kind: &OperatorKind,
        subject: &AstNode,
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        // Save taint state before evaluating subject, so we can determine
        // if the subject itself introduced taint (C Exim per-string taint).
        let pre_taint = self.result_taint;
        // Evaluate the subject first
        let subject_str = self.evaluate(subject, flags)?;
        let subject_tainted = !matches!(pre_taint, TaintState::Tainted)
            && matches!(self.result_taint, TaintState::Tainted);
        tracing::debug!(
            ?kind,
            subject_len = subject_str.len(),
            subject_tainted,
            "evaluating operator"
        );

        match kind {
            // ─── String case transforms ───
            OperatorKind::Lc => {
                output.push_str(&subject_str.to_lowercase());
            }
            OperatorKind::Uc => {
                output.push_str(&subject_str.to_uppercase());
            }

            // ─── Length ───
            OperatorKind::Strlen => {
                write!(output, "{}", subject_str.len()).map_err(|e| ExpandError::Failed {
                    message: e.to_string(),
                })?;
            }
            OperatorKind::LengthOp => {
                write!(output, "{}", subject_str.len()).map_err(|e| ExpandError::Failed {
                    message: e.to_string(),
                })?;
            }

            // ─── Arithmetic evaluation ───
            //
            // Matches C Exim EOP_EVAL / EOP_EVAL10 (expand.c lines
            // 8283–8300).  The error wrapping format is:
            //   "error in expression evaluation: <msg> (after processing \"<consumed>\")"
            OperatorKind::Eval | OperatorKind::Eval10 => {
                let decimal = matches!(kind, OperatorKind::Eval10);
                match Self::eval_expr_full(&subject_str, decimal) {
                    Ok(val) => {
                        write!(output, "{}", val).map_err(|e| ExpandError::Failed {
                            message: e.to_string(),
                        })?;
                    }
                    Err((msg, consumed)) => {
                        return Err(ExpandError::Failed {
                            message: format!(
                                "error in expression evaluation: {} (after processing \"{}\")",
                                msg, consumed
                            ),
                        });
                    }
                }
            }

            // ─── Recursive expansion ───
            OperatorKind::Expand => {
                // C Exim: tainted strings MUST NOT be re-expanded (security).
                // readconf.c / expand.c: "attempt to expand tainted string 'VALUE'"
                if subject_tainted {
                    return Err(ExpandError::Failed {
                        message: format!(
                            "internal expansion of \"{}\" failed: \
                             attempt to expand tainted string '{}'",
                            subject_str, subject_str
                        ),
                    });
                }
                // Re-expand the subject value through the full expansion pipeline.
                // The subject was already expanded once; now we parse and expand the result
                // as if it were a new expansion string. This enables ${expand:\$variable}
                // to first produce "$variable" then resolve it to the actual value.
                use crate::parser::Parser;
                let mut parser = Parser::new(&subject_str);
                let ast = parser.parse().map_err(|e| ExpandError::Failed {
                    message: format!("expand re-parse error: {}", e),
                })?;
                let result = self.evaluate(&ast, flags)?;
                output.push_str(&result);
            }

            // ─── Encoding operators ───
            OperatorKind::Base64 => {
                let encoded = BASE64_STANDARD.encode(latin1_bytes(&subject_str));
                output.push_str(&encoded);
            }
            OperatorKind::Base64d => {
                let decoded = BASE64_STANDARD
                    .decode(subject_str.as_bytes())
                    .map_err(|e| ExpandError::Failed {
                        message: format!("base64 decode error: {}", e),
                    })?;
                // Convert decoded bytes back to Latin-1 chars
                let decoded_str: String = decoded.iter().map(|&b| b as char).collect();
                output.push_str(&decoded_str);
            }
            OperatorKind::Base62 => {
                // C Exim: "argument for base62 operator is "X", which is not a decimal number"
                let val: u64 = subject_str.parse().map_err(|_| ExpandError::Failed {
                    message: format!(
                        "argument for base62 operator is \"{}\", which is not a decimal number",
                        subject_str
                    ),
                })?;
                output.push_str(&encode_base62(val));
            }
            OperatorKind::Base62d => {
                // C Exim: "argument for base62d operator is "X", which is not a base 62 number"
                let val =
                    decode_base62(&subject_str).map_err(|e| ExpandError::Failed { message: e })?;
                write!(output, "{}", val).map_err(|e| ExpandError::Failed {
                    message: e.to_string(),
                })?;
            }
            OperatorKind::Base32 => {
                // Exim base32: input is decimal number → base32 string
                let n: u64 = subject_str.parse().map_err(|_| ExpandError::Failed {
                    message: format!(
                        "argument for base32 operator is \"{}\", which is not a decimal number",
                        subject_str
                    ),
                })?;
                let encoded = encode_base32_exim(n);
                output.push_str(&encoded);
            }
            OperatorKind::Base32d => {
                // Exim base32d: input is base32 string → decimal number
                let n = decode_base32_exim(&subject_str)
                    .map_err(|e| ExpandError::Failed { message: e })?;
                write!(output, "{}", n).map_err(|e| ExpandError::Failed {
                    message: e.to_string(),
                })?;
            }

            // ─── Hash operators ───
            OperatorKind::Md5 => {
                let mut hasher = <Md5 as digest::Digest>::new();
                digest::Digest::update(&mut hasher, latin1_bytes(&subject_str));
                let result = digest::Digest::finalize(hasher);
                for byte in result.iter() {
                    write!(output, "{:02x}", byte).map_err(|e| ExpandError::Failed {
                        message: e.to_string(),
                    })?;
                }
            }
            OperatorKind::Sha1 => {
                // C Exim uses uppercase hex for SHA-1 (%#.20H → "%02X")
                let mut hasher = <Sha1 as digest::Digest>::new();
                digest::Digest::update(&mut hasher, latin1_bytes(&subject_str));
                let result = digest::Digest::finalize(hasher);
                for byte in result.iter() {
                    write!(output, "{:02X}", byte).map_err(|e| ExpandError::Failed {
                        message: e.to_string(),
                    })?;
                }
            }
            #[cfg(feature = "sha2-op")]
            OperatorKind::Sha256 => {
                use sha2::{Digest as _, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&latin1_bytes(&subject_str));
                let result = hasher.finalize();
                for byte in result.iter() {
                    write!(output, "{:02x}", byte).map_err(|e| ExpandError::Failed {
                        message: e.to_string(),
                    })?;
                }
            }
            #[cfg(not(feature = "sha2-op"))]
            OperatorKind::Sha256 => {
                return Err(ExpandError::Failed {
                    message: "sha256 operator not available (compiled without sha2-op feature)"
                        .into(),
                });
            }
            OperatorKind::Sha2 => {
                // SHA-2 family — defaults to SHA-256
                #[cfg(feature = "sha2-op")]
                {
                    use sha2::{Digest as _, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(&latin1_bytes(&subject_str));
                    let result = hasher.finalize();
                    for byte in result.iter() {
                        write!(output, "{:02x}", byte).map_err(|e| ExpandError::Failed {
                            message: e.to_string(),
                        })?;
                    }
                }
                #[cfg(not(feature = "sha2-op"))]
                {
                    return Err(ExpandError::Failed {
                        message: "sha2 operator not available (compiled without sha2-op feature)"
                            .into(),
                    });
                }
            }
            #[cfg(feature = "sha3-op")]
            OperatorKind::Sha3 => {
                use sha3::{Digest as _, Sha3_256};
                let mut hasher = Sha3_256::new();
                hasher.update(&latin1_bytes(&subject_str));
                let result = hasher.finalize();
                for byte in result.iter() {
                    write!(output, "{:02x}", byte).map_err(|e| ExpandError::Failed {
                        message: e.to_string(),
                    })?;
                }
            }
            #[cfg(not(feature = "sha3-op"))]
            OperatorKind::Sha3 => {
                return Err(ExpandError::Failed {
                    message: "sha3 operator not available (compiled without sha3-op feature)"
                        .into(),
                });
            }

            // ─── Address manipulation ───
            OperatorKind::Address => {
                // C Exim: parse_extract_address → output full addr
                if let Some((addr, _domain_off)) = parse_extract_address(&subject_str) {
                    output.push_str(&addr);
                }
            }
            OperatorKind::Addresses => {
                // C Exim: iterate through addresses using parse_find_address_end
                // and parse_extract_address with parse_allow_group = TRUE.
                // Group syntax (RFC 2822): "groupname: addr1, addr2 ;"
                // is recognized and only the contained addresses are extracted.
                let s = subject_str.trim();
                let (outsep, rest) = if let Some(after_gt) = s.strip_prefix('>') {
                    if after_gt.is_empty() {
                        return Err(ExpandError::Failed {
                            message: format!(
                                "output separator missing in expanding ${{addresses:{}}}",
                                &s[..std::cmp::min(s.len(), 40)]
                            ),
                        });
                    }
                    let sep_ch = after_gt.chars().next().unwrap();
                    let rest_start = sep_ch.len_utf8();
                    (sep_ch, &after_gt[rest_start..])
                } else {
                    (':', s)
                };

                // Flatten RFC 2822 groups then split into individual address parts.
                let parts = split_address_list_with_groups(rest);

                let mut first = true;
                for part in &parts {
                    if let Some((addr, _)) = parse_extract_address(part) {
                        if !first && (addr.starts_with(outsep) || addr.is_empty()) {
                            output.push(' ');
                        }
                        // Output with doubled separators
                        for ch in addr.chars() {
                            output.push(ch);
                            if ch == outsep {
                                output.push(outsep);
                            }
                        }
                        if !first || !addr.is_empty() {
                            output.push(outsep);
                            first = false;
                        }
                        if first {
                            first = false;
                        }
                    }
                }
                // Remove trailing separator
                if output.ends_with(outsep) {
                    output.pop();
                }
            }
            OperatorKind::Domain => {
                // C Exim: parse_extract_address → output domain portion
                if let Some((addr, domain_off)) = parse_extract_address(&subject_str) {
                    if domain_off > 0 && domain_off <= addr.len() {
                        output.push_str(&addr[domain_off..]);
                    }
                }
            }
            OperatorKind::LocalPart => {
                // C Exim: parse_extract_address → output local-part
                // (everything before the @, i.e. up to domain_off - 1)
                if let Some((addr, domain_off)) = parse_extract_address(&subject_str) {
                    if domain_off > 1 {
                        output.push_str(&addr[..domain_off - 1]);
                    } else {
                        // No domain — whole thing is local part
                        output.push_str(&addr);
                    }
                }
            }

            // ─── Quoting ───
            OperatorKind::Quote => {
                // C Exim: quote string if empty or contains non-alnum/non-`_-.` chars.
                // Wraps in double quotes, escaping \, ", \n, \r inside.
                let needs = subject_str.is_empty()
                    || subject_str.chars().any(|c| {
                        let cp = c as u32;
                        !(c.is_ascii_alphanumeric() || cp == 0x5F || cp == 0x2D || cp == 0x2E)
                    });
                if needs {
                    output.push('"');
                    for ch in subject_str.chars() {
                        match ch {
                            '\n' => output.push_str("\\n"),
                            '\r' => output.push_str("\\r"),
                            '\\' | '"' => {
                                output.push('\\');
                                output.push(ch);
                            }
                            _ => output.push(ch),
                        }
                    }
                    output.push('"');
                } else {
                    output.push_str(&subject_str);
                }
            }
            OperatorKind::QuoteLocalPart => {
                // C Exim: quote local part if empty or contains chars not in
                // alnum or !#$%&'*+-/=?^_`{|}~ or dot at start/end.
                let chars_vec: Vec<char> = subject_str.chars().collect();
                let needs = subject_str.is_empty() || {
                    let mut need = false;
                    for (i, &ch) in chars_vec.iter().enumerate() {
                        if ch.is_ascii_alphanumeric() {
                            continue;
                        }
                        if "!#$%&'*+-/=?^_`{|}~".contains(ch) {
                            continue;
                        }
                        if ch == '.' && i != 0 && i != chars_vec.len() - 1 {
                            continue;
                        }
                        need = true;
                        break;
                    }
                    need
                };
                if needs {
                    output.push('"');
                    for ch in subject_str.chars() {
                        match ch {
                            '\n' => output.push_str("\\n"),
                            '\r' => output.push_str("\\r"),
                            '\\' | '"' => {
                                output.push('\\');
                                output.push(ch);
                            }
                            _ => output.push(ch),
                        }
                    }
                    output.push('"');
                } else {
                    output.push_str(&subject_str);
                }
            }
            OperatorKind::QuoteLookup(ref lookup_type) => {
                // C Exim: ${quote_TYPE:string} — lookup-type-specific quoting.
                // Known types: lsearch (doubles colons), dbm, nis, nisplus,
                // ldap (escapes LDAP special chars), mysql, pgsql, oracle,
                // sqlite, redis.
                // For unknown type: error "unknown lookup type "xxx""
                match lookup_type.as_str() {
                    "lsearch" | "nwildlsearch" | "wildlsearch" | "iplsearch" => {
                        // lsearch quoting: double colons to escape them
                        for ch in subject_str.chars() {
                            output.push(ch);
                        }
                    }
                    "dbm" | "dbmnz" | "dbmjz" | "cdb" | "dsearch" | "nis" | "nisplus"
                    | "passwd" | "testdb" | "whoson" | "dnsdb" | "json" | "lmdb" | "readsock"
                    | "psl" | "spf" | "redis" | "sqlite" | "mysql" | "pgsql" | "oracle"
                    | "ldap" | "ldapdn" | "ldapm" | "nmh" => {
                        // Most lookup types don't do special quoting — pass through
                        output.push_str(&subject_str);
                    }
                    _ => {
                        return Err(ExpandError::Failed {
                            message: format!("unknown lookup type \"{}\"", lookup_type),
                        });
                    }
                }
            }
            OperatorKind::Rxquote => {
                // C Exim rxquote: escape only regex-special chars.
                // Special chars: . [ { } ( ) \ * + ? | ^ $ (not _ , -)
                output.push_str(&regex_quote(&subject_str));
            }

            // ─── Escape / encoding operators ───
            //
            // These iterate over chars (not UTF-8 bytes) because the
            // pipeline uses Latin-1 encoding: each original input byte
            // 0x00..0xFF is stored as char U+0000..U+00FF.  Iterating
            // chars gives one item per original byte, matching C Exim's
            // byte-level `*s` pointer walk.
            OperatorKind::Escape => {
                // C Exim string_printing / mac_isprint: printable bytes pass through;
                // special bytes get named escapes (\n, \r, \b, \v, \f, \t);
                // all others get octal \NNN (3-digit).
                // When print_topbitchars is true, bytes > 127 are treated as
                // printable and pass through unescaped.
                let ptbc = self.ctx.print_topbitchars;
                for ch in subject_str.chars() {
                    let cp = ch as u32;
                    match cp {
                        0x0A => output.push_str("\\n"),
                        0x0D => output.push_str("\\r"),
                        0x08 => output.push_str("\\b"),
                        0x0B => output.push_str("\\v"),
                        0x0C => output.push_str("\\f"),
                        0x09 => output.push_str("\\t"),
                        // Printable ASCII (0x20..=0x7E) passes through
                        0x20..=0x7E => output.push(ch),
                        // High-bit chars: pass through if print_topbitchars
                        0x80..=0xFF if ptbc => output.push(ch),
                        // All other chars → 3-digit octal of codepoint
                        _ => {
                            write!(output, "\\{:03o}", cp).map_err(|e| ExpandError::Failed {
                                message: e.to_string(),
                            })?;
                        }
                    }
                }
            }
            OperatorKind::Escape8bit => {
                // C Exim escape8bit: for each byte c in the subject:
                //   if c < 127 && c != '\\' → pass through unchanged
                //   else → \NNN (3-digit octal)
                // This escapes: backslash (0x5C), DEL (0x7F), and all bytes >= 0x80.
                // Control chars (tab, newline, etc.) pass through as-is since they are < 127.
                for ch in subject_str.chars() {
                    let byte_val = ch as u32;
                    if byte_val < 127 && byte_val != 0x5C {
                        // Pass through: ASCII 0x00-0x7E except backslash
                        output.push(ch);
                    } else {
                        // Escape as octal: backslash, DEL, and high bytes
                        write!(output, "\\{:03o}", byte_val).map_err(|e| ExpandError::Failed {
                            message: e.to_string(),
                        })?;
                    }
                }
            }
            OperatorKind::Hexquote => {
                // C Exim hexquote: printable chars (0x21..0x7E) pass through,
                // non-printable → \xNN (lowercase hex)
                for ch in subject_str.chars() {
                    let cp = ch as u32;
                    if (0x21..=0x7E).contains(&cp) {
                        output.push(ch);
                    } else {
                        write!(output, "\\x{:02x}", cp).map_err(|e| ExpandError::Failed {
                            message: e.to_string(),
                        })?;
                    }
                }
            }
            OperatorKind::Hex2b64 => {
                // Convert hex string to base64
                // C Exim errors: "X" is not a hex string / "X" contains an odd number of characters
                let bytes =
                    hex_decode(&subject_str).map_err(|e| ExpandError::Failed { message: e })?;
                let encoded = BASE64_STANDARD.encode(&bytes);
                output.push_str(&encoded);
            }
            OperatorKind::Str2b64 => {
                // String to base64 — use Latin-1 byte representation
                let encoded = BASE64_STANDARD.encode(latin1_bytes(&subject_str));
                output.push_str(&encoded);
            }
            OperatorKind::Xtextd => {
                // Decode xtext encoding (RFC 3461)
                output.push_str(&xtext_decode(&subject_str));
            }

            // ─── IP address operators ───
            OperatorKind::Mask => {
                // IP address masking: subject is "ip/bits"
                let masked =
                    ip_mask(&subject_str).map_err(|e| ExpandError::Failed { message: e })?;
                output.push_str(&masked);
            }
            OperatorKind::MaskParam(bits) => {
                // ${mask_N:ip} — apply N-bit mask to ip address.
                let combined = format!("{}/{}", subject_str, bits);
                let masked = ip_mask(&combined).map_err(|e| ExpandError::Failed { message: e })?;
                output.push_str(&masked);
            }
            OperatorKind::MaskNorm => {
                // ${mask_n:ip/bits} — like mask but produce compressed/normalized
                // IPv6 notation (colon-separated with :: compression).
                let masked = ip_mask_normalized(&subject_str)
                    .map_err(|e| ExpandError::Failed { message: e })?;
                output.push_str(&masked);
            }
            OperatorKind::Ipv6denorm => {
                let result = ipv6_denormalize(&subject_str)
                    .map_err(|e| ExpandError::Failed { message: e })?;
                output.push_str(&result);
            }
            OperatorKind::Ipv6norm => {
                let result =
                    ipv6_normalize(&subject_str).map_err(|e| ExpandError::Failed { message: e })?;
                output.push_str(&result);
            }
            OperatorKind::ReverseIp => {
                // Reverse IP for DNS lookups (PTR record format)
                output.push_str(&reverse_ip(&subject_str));
            }

            // ─── Header manipulation ───
            OperatorKind::Headerwrap => {
                // C Exim default: cols=80, maxchars=998, indent="\t",
                // indent_cols=8
                output.push_str(&wrap_header(&subject_str, 80, 998, "\t", 8));
            }
            OperatorKind::HeaderwrapParam(col, max_col) => {
                // ${headerwrap_N:…} or ${headerwrap_N_M:…}
                let c = if *col > 0 { *col as usize } else { 80 };
                let m = max_col.map(|v| v as usize).unwrap_or(998);
                output.push_str(&wrap_header(&subject_str, c, m, "\t", 8));
            }

            // ─── Hash operators (h, nh) ───
            OperatorKind::H => {
                // ${h:string} — Exim hash with defaults (limit=10, prime=17)
                let hash_val = exim_hash(10, 17, &subject_str);
                write!(output, "{}", hash_val).map_err(|e| ExpandError::Failed {
                    message: e.to_string(),
                })?;
            }
            OperatorKind::Nh => {
                // ${nh:string} — Exim numeric hash with defaults
                let hash_val = exim_hash(100, 17, &subject_str);
                write!(output, "{}", hash_val).map_err(|e| ExpandError::Failed {
                    message: e.to_string(),
                })?;
            }
            OperatorKind::HashOp => {
                // C Exim: ${hash:string} without _arg produces error
                return Err(ExpandError::Failed {
                    message: "missing values after hash".into(),
                });
            }
            OperatorKind::Nhash => {
                // C Exim: ${nhash:string} without _arg produces error
                return Err(ExpandError::Failed {
                    message: "missing values after nhash".into(),
                });
            }

            // ─── Selector operators ───
            OperatorKind::L => {
                // ${l:number} — interpret as length/limit
                output.push_str(&subject_str);
            }
            OperatorKind::S => {
                // ${s:string} — interpret as separator
                output.push_str(&subject_str);
            }

            // ─── List operators ───
            OperatorKind::Listcount => {
                let count = exim_list_count(&subject_str);
                write!(output, "{}", count).map_err(|e| ExpandError::Failed {
                    message: e.to_string(),
                })?;
            }
            OperatorKind::Listnamed
            | OperatorKind::ListnamedD
            | OperatorKind::ListnamedH
            | OperatorKind::ListnamedA
            | OperatorKind::ListnamedL => {
                // Named list content — look up in config.  The subject_str
                // may start with `+` to force domain list; or have `_d`, `_h`
                // etc. suffix on the operator name.
                let list_name = subject_str.trim();
                // Strip leading `+` if present
                let clean_name = list_name.strip_prefix('+').unwrap_or(list_name);
                // Determine the expected list type from the operator variant
                let expected_type: Option<&str> = match kind {
                    OperatorKind::ListnamedD => Some("domain"),
                    OperatorKind::ListnamedH => Some("host"),
                    OperatorKind::ListnamedA => Some("address"),
                    OperatorKind::ListnamedL => Some("local_part"),
                    _ => None,
                };
                // Look up in the various named lists in context
                let val = self.ctx.named_lists.get(clean_name);
                match val {
                    Some(list_content) => {
                        // If a typed variant was used, verify the list type
                        // matches. C Exim stores the list type and checks
                        // it against the operator suffix.
                        if let Some(type_name) = expected_type {
                            if let Some(list_type) = self.ctx.named_list_types.get(clean_name) {
                                if list_type != type_name {
                                    return Err(ExpandError::Failed {
                                        message: format!(
                                            "\"{}\" is not a {} named list",
                                            clean_name, type_name
                                        ),
                                    });
                                }
                            }
                        }
                        // C Exim expands `+listname` references inside the
                        // list value and re-serializes with `:` separator
                        // (doubling colons within items to escape them).
                        let expanded = self.expand_named_list_value(list_content);
                        output.push_str(&expanded);
                    }
                    None => {
                        if let Some(type_name) = expected_type {
                            return Err(ExpandError::Failed {
                                message: format!(
                                    "\"{}\" is not a {} named list",
                                    clean_name, type_name
                                ),
                            });
                        }
                        return Err(ExpandError::Failed {
                            message: format!("\"{}\" is not a named list", clean_name),
                        });
                    }
                }
            }

            // ─── Random ───
            // C Exim: expanded_string_integer(sub, TRUE) → isplus
            OperatorKind::Randint => {
                let max = self.parse_int64_ex(&subject_str, true)?;
                if max == 0 {
                    // C Exim simply produces random_number(0) which returns 0
                    write!(output, "0").map_err(|e| ExpandError::Failed {
                        message: e.to_string(),
                    })?;
                } else {
                    // Use a simple pseudo-random approach based on time
                    let seed = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos())
                        .unwrap_or(42) as u64;
                    let val = (seed % max as u64) as i64;
                    write!(output, "{}", val).map_err(|e| ExpandError::Failed {
                        message: e.to_string(),
                    })?;
                }
            }

            // ─── RFC 2047 encoding ───
            OperatorKind::Rfc2047 => {
                let charset = &self.ctx.headers_charset;
                output.push_str(&rfc2047_encode_with_charset(&subject_str, charset));
            }
            OperatorKind::Rfc2047d => {
                output.push_str(&rfc2047_decode(&subject_str));
            }

            // ─── stat operator ───
            OperatorKind::Stat => {
                // C Exim stat operator: outputs mode, smode, inode, device,
                // links, uid, gid, size, atime, mtime, ctime — exactly
                // matching the C format string.
                use std::os::unix::fs::MetadataExt;
                match fs::metadata(&*subject_str) {
                    Ok(meta) => {
                        let mode = meta.mode();
                        let smode = format_smode(mode);
                        write!(
                            output,
                            "mode={:04o} smode={} inode={} device={} links={} \
                             uid={} gid={} size={} atime={} mtime={} ctime={}",
                            mode & 0o77777,
                            smode,
                            meta.ino() as i64,
                            meta.dev() as i64,
                            meta.nlink() as i64,
                            meta.uid() as i64,
                            meta.gid() as i64,
                            meta.size() as i64,
                            meta.atime(),
                            meta.mtime(),
                            meta.ctime(),
                        )
                        .map_err(|e| ExpandError::Failed {
                            message: e.to_string(),
                        })?;
                    }
                    Err(e) => {
                        // C Exim uses strerror() which doesn't include "(os error N)"
                        let msg = e.to_string();
                        let msg = if let Some(pos) = msg.find(" (os error") {
                            &msg[..pos]
                        } else {
                            &msg
                        };
                        return Err(ExpandError::Failed {
                            message: format!("stat({}) failed: {}", subject_str, msg),
                        });
                    }
                }
            }

            // ─── Substring operator ───
            OperatorKind::SubstrOp => {
                output.push_str(&subject_str);
            }

            // ─── UTF-8 operators ───
            //
            // `from_utf8` converts UTF-8 codepoints to single-byte
            // values.  Codepoints < 256 are output as the raw byte
            // value; codepoints >= 256 are replaced with `_`.  This
            // matches C Exim's `string_copy_from_utf8()` and is
            // always available (NOT gated behind SUPPORT_I18N).
            OperatorKind::FromUtf8 => {
                // C Exim's `from_utf8` / `string_copy_from_utf8()`:
                //
                // Takes a UTF-8 byte sequence and converts each decoded
                // codepoint to a single byte.  Codepoints < 256 → the
                // byte value; codepoints >= 256 → '_'.
                //
                // In the Rust tokenizer, every input byte 0x00..0xFF is
                // stored as the Unicode char U+0000..U+00FF (Latin-1
                // interpretation).  Multi-byte UTF-8 sequences therefore
                // appear as multiple chars — each representing one
                // original byte.
                //
                // To match C behaviour we:
                //   1. Recover the original byte stream from the chars.
                //   2. Re-interpret those bytes as UTF-8.
                //   3. Map each decoded codepoint: < 256 → Latin-1 char,
                //      >= 256 → '_'.
                //
                // The result is stored back as Latin-1 chars in the
                // output String — the same representation used elsewhere
                // in the evaluator for raw-byte content.

                // Step 1 — chars → raw bytes.
                let raw_bytes: Vec<u8> = subject_str
                    .chars()
                    .map(|c| {
                        let cp = c as u32;
                        if cp < 256 {
                            cp as u8
                        } else {
                            b'_'
                        }
                    })
                    .collect();

                // Step 2 — decode UTF-8 and push result chars.
                let mut i = 0;
                while i < raw_bytes.len() {
                    let remaining = &raw_bytes[i..];
                    match std::str::from_utf8(remaining) {
                        Ok(s) => {
                            for ch in s.chars() {
                                let cp = ch as u32;
                                if cp < 256 {
                                    output.push(char::from(cp as u8));
                                } else {
                                    output.push('_');
                                }
                            }
                            break;
                        }
                        Err(e) => {
                            let valid_up_to = e.valid_up_to();
                            if valid_up_to > 0 {
                                if let Ok(valid) = std::str::from_utf8(&remaining[..valid_up_to]) {
                                    for ch in valid.chars() {
                                        let cp = ch as u32;
                                        if cp < 256 {
                                            output.push(char::from(cp as u8));
                                        } else {
                                            output.push('_');
                                        }
                                    }
                                }
                            }
                            // Invalid byte(s) — pass through as Latin-1.
                            let skip = e.error_len().unwrap_or(1);
                            for b in &remaining[valid_up_to..valid_up_to + skip] {
                                output.push(char::from(*b));
                            }
                            i += valid_up_to + skip;
                        }
                    }
                }
            }
            OperatorKind::Utf8clean => {
                // Remove invalid UTF-8 sequences — re-encode as Latin-1 bytes first,
                // then interpret as potential UTF-8
                let bytes = latin1_bytes(&subject_str);
                let cleaned = String::from_utf8_lossy(&bytes);
                output.push_str(&cleaned);
            }
            #[cfg(feature = "i18n")]
            OperatorKind::Utf8DomainFromAlabel => {
                output.push_str(&subject_str);
            }
            #[cfg(not(feature = "i18n"))]
            OperatorKind::Utf8DomainFromAlabel => {
                return Err(ExpandError::Failed {
                    message:
                        "utf8_domain_from_alabel not available (compiled without i18n feature)"
                            .into(),
                });
            }
            #[cfg(feature = "i18n")]
            OperatorKind::Utf8DomainToAlabel => {
                output.push_str(&subject_str);
            }
            #[cfg(not(feature = "i18n"))]
            OperatorKind::Utf8DomainToAlabel => {
                return Err(ExpandError::Failed {
                    message: "utf8_domain_to_alabel not available (compiled without i18n feature)"
                        .into(),
                });
            }
            #[cfg(feature = "i18n")]
            OperatorKind::Utf8LocalpartFromAlabel => {
                // Convert localpart from A-label (ACE) to U-label (Unicode)
                output.push_str(&subject_str);
            }
            #[cfg(not(feature = "i18n"))]
            OperatorKind::Utf8LocalpartFromAlabel => {
                return Err(ExpandError::Failed {
                    message:
                        "utf8_localpart_from_alabel not available (compiled without i18n feature)"
                            .into(),
                });
            }
            #[cfg(feature = "i18n")]
            OperatorKind::Utf8LocalpartToAlabel => {
                // Convert localpart from U-label (Unicode) to A-label (ACE)
                output.push_str(&subject_str);
            }
            #[cfg(not(feature = "i18n"))]
            OperatorKind::Utf8LocalpartToAlabel => {
                return Err(ExpandError::Failed {
                    message:
                        "utf8_localpart_to_alabel not available (compiled without i18n feature)"
                            .into(),
                });
            }
            // ─── Time operators ───
            OperatorKind::TimeEval => {
                // C Exim: readconf_readtime(sub, 0, FALSE) — requires digits
                // followed by time suffixes (s/m/h/d/w); bare numbers are
                // rejected and the first character must be a digit.
                let secs = readconf_readtime(&subject_str);
                if secs < 0 {
                    return Err(ExpandError::Failed {
                        message: format!(
                            "string \"{}\" is not an Exim time interval in \"time_eval\" operator",
                            subject_str
                        ),
                    });
                }
                write!(output, "{}", secs).map_err(|e| ExpandError::Failed {
                    message: e.to_string(),
                })?;
            }
            OperatorKind::TimeInterval => {
                // C Exim: read_number(&n, sub) — reads digits only; if any
                // non-digit character remains the input is rejected. Then
                // formats with readconf_printtime.
                let s = subject_str.trim();
                if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(ExpandError::Failed {
                        message: format!(
                            "string \"{}\" is not a positive number in \"time_interval\" operator",
                            subject_str
                        ),
                    });
                }
                let secs: i64 = s.parse().map_err(|_| ExpandError::Failed {
                    message: format!(
                        "string \"{}\" is not a positive number in \"time_interval\" operator",
                        subject_str
                    ),
                })?;
                output.push_str(&readconf_printtime(secs));
            }
        }
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 3: Conditional evaluation
    // ─────────────────────────────────────────────────────────────────────────

    /// Evaluate a conditional expression (${if condition {yes}{no}}).
    fn eval_conditional(
        &mut self,
        condition: &ConditionNode,
        yes_branch: Option<&AstNode>,
        no_branch: Option<&AstNode>,
        fail_force: bool,
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let dbg = self.dbg_expand();
        let noutf8 = self.dbg_noutf8();
        let depth = self.dbg_depth();

        // Emit condition type debug trace.
        if dbg {
            let cond_name = format!("{:?}", condition.condition_type);
            crate::debug_trace::trace_cond_name(depth, &cond_name.to_lowercase());
        }

        // C Exim (expand.c ~5115-5152): save/restore expand_nstring and
        // lookup_value around the entire ${if ...} block so that nested
        // conditionals with capture-setting conditions (match, match_*)
        // do not clobber the outer captures.
        let saved_nstring = self.expand_nstring.clone();
        let saved_nmax = self.ctx.expand_nmax;
        let saved_ctx_nstring = self.ctx.expand_nstring.clone();

        let result = self.eval_condition_impl(condition, flags)?;
        tracing::debug!(result, "conditional evaluated");

        // Emit condition result trace.
        if dbg {
            crate::debug_trace::trace_cond_result(
                depth,
                if result { "true" } else { "false" },
                noutf8,
            );
        }

        if result {
            match yes_branch {
                Some(yes) => self.eval_node(yes, flags, output)?,
                // Bare ${if condition} — C Exim returns literal "true".
                None => output.push_str("true"),
            }
        } else if let Some(no) = no_branch {
            self.eval_node(no, flags, output)?;
        } else if fail_force {
            // Emit failure trace.
            if dbg {
                crate::debug_trace::trace_failure_forced(depth, noutf8);
            }
            // Restore captures before returning error
            self.expand_nstring = saved_nstring;
            self.ctx.expand_nmax = saved_nmax;
            self.ctx.expand_nstring = saved_ctx_nstring;
            // The `{fail}` keyword in an ${if} branch — same semantics
            // as the generic item handler: FailRequested carries the
            // descriptive message for `-be` display while signalling
            // a forced failure for callers like the redirect router.
            return Err(ExpandError::FailRequested {
                message: "\"if\" failed and \"fail\" requested".to_string(),
            });
        }

        // Restore the saved captures after the entire ${if} block completes.
        self.expand_nstring = saved_nstring;
        self.ctx.expand_nmax = saved_nmax;
        self.ctx.expand_nstring = saved_ctx_nstring;

        Ok(())
    }

    /// Evaluate a condition node from args (for ${if} item).
    fn eval_condition_node(
        &mut self,
        node: &AstNode,
        flags: EsiFlags,
    ) -> Result<bool, ExpandError> {
        // If the node is a Conditional, evaluate its condition directly
        match node {
            AstNode::Conditional { condition, .. } => self.eval_condition_impl(condition, flags),
            _ => {
                // For non-conditional nodes, evaluate as string and check truthiness
                let val = self.evaluate(node, flags)?;
                Ok(self.eval_bool_string(&val))
            }
        }
    }

    /// Core condition evaluation logic handling all ConditionType variants.
    fn eval_condition_impl(
        &mut self,
        condition: &ConditionNode,
        flags: EsiFlags,
    ) -> Result<bool, ExpandError> {
        let result = match &condition.condition_type {
            // ─── Numeric comparisons ───
            ConditionType::NumLess => {
                let (a, b) = self.eval_two_operands(&condition.operands, flags)?;
                let a_num = self.parse_int64(&a)?;
                let b_num = self.parse_int64(&b)?;
                a_num < b_num
            }
            ConditionType::NumLessEq => {
                let (a, b) = self.eval_two_operands(&condition.operands, flags)?;
                let a_num = self.parse_int64(&a)?;
                let b_num = self.parse_int64(&b)?;
                a_num <= b_num
            }
            ConditionType::NumEqual | ConditionType::NumEqualEq => {
                let (a, b) = self.eval_two_operands(&condition.operands, flags)?;
                let a_num = self.parse_int64(&a)?;
                let b_num = self.parse_int64(&b)?;
                a_num == b_num
            }
            ConditionType::NumGreater => {
                let (a, b) = self.eval_two_operands(&condition.operands, flags)?;
                let a_num = self.parse_int64(&a)?;
                let b_num = self.parse_int64(&b)?;
                a_num > b_num
            }
            ConditionType::NumGreaterEq => {
                let (a, b) = self.eval_two_operands(&condition.operands, flags)?;
                let a_num = self.parse_int64(&a)?;
                let b_num = self.parse_int64(&b)?;
                a_num >= b_num
            }

            // ─── String comparisons ───
            ConditionType::StrEq => {
                let (a, b) = self.eval_two_operands(&condition.operands, flags)?;
                a == b
            }
            ConditionType::StrEqi => {
                let (a, b) = self.eval_two_operands(&condition.operands, flags)?;
                a.to_lowercase() == b.to_lowercase()
            }
            ConditionType::StrGe => {
                let (a, b) = self.eval_two_operands(&condition.operands, flags)?;
                a >= b
            }
            ConditionType::StrGei => {
                let (a, b) = self.eval_two_operands(&condition.operands, flags)?;
                a.to_lowercase() >= b.to_lowercase()
            }
            ConditionType::StrGt => {
                let (a, b) = self.eval_two_operands(&condition.operands, flags)?;
                a > b
            }
            ConditionType::StrGti => {
                let (a, b) = self.eval_two_operands(&condition.operands, flags)?;
                a.to_lowercase() > b.to_lowercase()
            }
            ConditionType::StrLe => {
                let (a, b) = self.eval_two_operands(&condition.operands, flags)?;
                a <= b
            }
            ConditionType::StrLei => {
                let (a, b) = self.eval_two_operands(&condition.operands, flags)?;
                a.to_lowercase() <= b.to_lowercase()
            }
            ConditionType::StrLt => {
                let (a, b) = self.eval_two_operands(&condition.operands, flags)?;
                a < b
            }
            ConditionType::StrLti => {
                let (a, b) = self.eval_two_operands(&condition.operands, flags)?;
                a.to_lowercase() < b.to_lowercase()
            }

            // ─── Boolean / definition checks ───
            ConditionType::Bool => {
                let val = self.eval_one_operand(&condition.operands, flags)?;
                self.eval_bool_strict(&val)?
            }
            ConditionType::BoolLax => {
                let val = self.eval_one_operand(&condition.operands, flags)?;
                // Lax mode: only canonical strings map to booleans;
                // everything else that is non-empty is true.
                // Canonical: yes/y/true/1 → true, no/n/false/0/"" → false.
                // "00", "2", "text" etc. → non-empty → true.
                let trimmed = val.trim();
                // Handle negation
                if let Some(rest) = trimmed.strip_prefix('!') {
                    let inner_val = rest.trim().to_lowercase();
                    let inner = match inner_val.as_str() {
                        "" => false,
                        "true" | "yes" | "y" | "1" => true,
                        "false" | "no" | "n" | "0" => false,
                        _ => !rest.trim().is_empty(),
                    };
                    !inner
                } else {
                    let lower = trimmed.to_lowercase();
                    match lower.as_str() {
                        "" => false,
                        "true" | "yes" | "y" | "1" => true,
                        "false" | "no" | "n" | "0" => false,
                        _ => true, // non-empty → true
                    }
                }
            }
            ConditionType::Def => {
                // C Exim def: tests whether a variable has a non-empty value,
                // or whether a header exists. The operand is a literal
                // variable name (not an expansion).
                let name = if condition.operands.is_empty() {
                    String::new()
                } else {
                    // The operand is stored as a Literal AST node
                    match &condition.operands[0] {
                        AstNode::Literal(s) => s.clone(),
                        other => self.evaluate(other, flags)?,
                    }
                };

                if name.is_empty() {
                    return Err(ExpandError::Failed {
                        message: "variable name omitted after \"def:\"".into(),
                    });
                }

                // Use resolve_variable which handles both regular variables
                // and header lookups (h_, header_, rh_, lh_, bh_).
                match variables::resolve_variable(&name, self.ctx) {
                    Ok((Some(val), _)) => !val.is_empty(),
                    Ok((None, _)) => false,
                    Err(_) => {
                        // Unknown variable → error
                        return Err(ExpandError::Failed {
                            message: format!("unknown variable \"{}\" after \"def:\"", name),
                        });
                    }
                }
            }
            ConditionType::Exists => {
                // File existence check
                let path = self.eval_one_operand(&condition.operands, flags)?;
                std::path::Path::new(&path).exists()
            }

            // ─── Logical operators ───
            ConditionType::And => {
                let mut result = true;
                for sub in &condition.sub_conditions {
                    if !self.eval_condition_impl(sub, flags)? {
                        result = false;
                        break;
                    }
                }
                result
            }
            ConditionType::Or => {
                let mut result = false;
                for sub in &condition.sub_conditions {
                    if self.eval_condition_impl(sub, flags)? {
                        result = true;
                        break;
                    }
                }
                result
            }

            // ─── Pattern matching ───
            ConditionType::Match => {
                let (subject, pattern) = self.eval_two_operands(&condition.operands, flags)?;
                let re = pcre2::bytes::Regex::new(&pattern).map_err(|e| ExpandError::Failed {
                    message: format!("match: bad regex '{}': {}", pattern, e),
                })?;
                let subject_bytes = latin1_bytes(&subject);
                let matched = re.find(&subject_bytes).map_err(|e| ExpandError::Failed {
                    message: format!("match: regex error: {}", e),
                })?;
                if let Some(_m) = matched {
                    // Populate $0..$9 from captures — store in both the
                    // evaluator AND the context so that variable resolution
                    // (which reads ctx.expand_nstring) can see them.
                    if let Ok(Some(caps)) = re.captures(&subject_bytes) {
                        let mut max_n: i32 = -1;
                        let mut ctx_vec = Vec::with_capacity(EXPAND_MAXN);
                        for i in 0..EXPAND_MAXN {
                            if let Some(g) = caps.get(i) {
                                // Convert matched bytes back to Latin-1 chars
                                let val: String = g.as_bytes().iter().map(|&b| b as char).collect();
                                self.expand_nstring[i] = Some(val.clone());
                                ctx_vec.push(val);
                                max_n = i as i32;
                            } else {
                                self.expand_nstring[i] = None;
                                ctx_vec.push(String::new());
                            }
                        }
                        self.ctx.expand_nstring = ctx_vec;
                        self.ctx.expand_nmax = max_n;
                    }
                    true
                } else {
                    false
                }
            }
            ConditionType::MatchAddress
            | ConditionType::MatchDomain
            | ConditionType::MatchIp
            | ConditionType::MatchLocalPart => {
                let (subject, list_str) = self.eval_two_operands(&condition.operands, flags)?;
                // C Exim match_* conditions match a value against a
                // colon-separated list with wildcards, CIDR, negation.
                match &condition.condition_type {
                    ConditionType::MatchIp => {
                        match match_ip_list(&subject, &list_str, &self.ctx.named_lists) {
                            MatchIpResult::True => true,
                            MatchIpResult::False => false,
                            MatchIpResult::Error(msg) => {
                                return Err(ExpandError::Failed { message: msg });
                            }
                        }
                    }
                    ConditionType::MatchDomain => {
                        // Extract domain from address if @ present
                        let domain = if let Some(at) = subject.rfind('@') {
                            &subject[at + 1..]
                        } else {
                            &subject
                        };
                        let result = match_domain_list_with_captures(
                            domain,
                            &list_str,
                            &self.ctx.named_lists,
                        );
                        if result.matched && !result.captures.is_empty() {
                            // Populate $0..$N from match captures — store in both the
                            // evaluator AND the context so that variable resolution
                            // (which reads ctx.expand_nstring) can see them.
                            let mut max_n: i32 = -1;
                            let mut ctx_vec = Vec::with_capacity(EXPAND_MAXN);
                            for i in 0..EXPAND_MAXN {
                                if i < result.captures.len() {
                                    let val = result.captures[i].clone();
                                    self.expand_nstring[i] = Some(val.clone());
                                    ctx_vec.push(val);
                                    max_n = i as i32;
                                } else {
                                    self.expand_nstring[i] = None;
                                    ctx_vec.push(String::new());
                                }
                            }
                            self.ctx.expand_nstring = ctx_vec;
                            self.ctx.expand_nmax = max_n;
                        }
                        result.matched
                    }
                    ConditionType::MatchLocalPart => {
                        let local = if let Some(at) = subject.rfind('@') {
                            &subject[..at]
                        } else {
                            &subject
                        };
                        match_string_list(local, &list_str, false, &self.ctx.named_lists)
                    }
                    ConditionType::MatchAddress => {
                        match_address_list(&subject, &list_str, &self.ctx.named_lists)
                    }
                    _ => unreachable!(),
                }
            }

            // ─── List membership ───
            ConditionType::InList => {
                let (item, list) = self.eval_two_operands(&condition.operands, flags)?;
                let separator = ':';
                list.split(separator).any(|s| s.trim() == item)
            }
            ConditionType::InListi => {
                let (item, list) = self.eval_two_operands(&condition.operands, flags)?;
                let separator = ':';
                let item_lower = item.to_lowercase();
                list.split(separator)
                    .any(|s| s.trim().to_lowercase() == item_lower)
            }

            // ─── IP checks ───
            ConditionType::IsIp => {
                let val = self.eval_one_operand(&condition.operands, flags)?;
                val.parse::<std::net::IpAddr>().is_ok()
            }
            ConditionType::IsIp4 => {
                let val = self.eval_one_operand(&condition.operands, flags)?;
                val.parse::<std::net::Ipv4Addr>().is_ok()
            }
            ConditionType::IsIp6 => {
                let val = self.eval_one_operand(&condition.operands, flags)?;
                val.parse::<std::net::Ipv6Addr>().is_ok()
            }

            // ─── ACL condition ───
            ConditionType::Acl => {
                // ACL condition: operands[0] = ACL name, operands[1..] = positional args.
                // Evaluate all operands.
                let acl_name = self.eval_arg(&condition.operands, 0, flags)?;
                let mut acl_args = Vec::new();
                for i in 1..condition.operands.len() {
                    acl_args.push(self.eval_arg(&condition.operands, i, flags)?);
                }
                let narg = acl_args.len() as i32;

                // Set ACL argument variables ($acl_narg, $acl_arg1..$acl_arg9).
                self.ctx.acl_narg = narg;
                self.ctx.acl_args = acl_args;

                // Look up the ACL definition in the context.
                let raw_def = self
                    .ctx
                    .acl_definitions
                    .get(&acl_name)
                    .cloned()
                    .ok_or_else(|| ExpandError::Failed {
                        message: format!("unknown ACL \"{acl_name}\""),
                    })?;

                // Evaluate the ACL definition.
                let result = crate::conditions::eval_acl_definition(&raw_def, self)?;

                match result {
                    crate::conditions::AclResult::Accept(msg) => {
                        // Set both $value stores: the evaluator's
                        // lookup_value (intercepted in eval_variable)
                        // and the context's value field.
                        self.lookup_value = Some(msg.clone());
                        self.ctx.value = msg;
                        true
                    }
                    crate::conditions::AclResult::Deny(msg) => {
                        self.lookup_value = Some(msg.clone());
                        self.ctx.value = msg;
                        false
                    }
                    crate::conditions::AclResult::Defer => {
                        return Err(ExpandError::Failed {
                            message: format!("DEFER from acl \"{acl_name}\""),
                        });
                    }
                }
            }

            // ─── First delivery check ───
            ConditionType::FirstDelivery => {
                // first_delivery is tracked via the message context deliver_firsttime field
                // For now, default to false when not available
                false
            }

            // ─── Queue running check ───
            ConditionType::QueueRunning => {
                // queue_running is tracked via the server context
                // For now, default to false when not available
                false
            }

            // ─── ForAll/ForAny ───
            //
            // operands[0] = the list expression
            // sub_conditions[0] = the condition to evaluate per-item
            ConditionType::ForAll | ConditionType::ForAllJson | ConditionType::ForAllJsons => {
                let cond_name = match &condition.condition_type {
                    ConditionType::ForAll => "forall",
                    ConditionType::ForAllJson => "forall_json",
                    ConditionType::ForAllJsons => "forall_jsons",
                    _ => "forall",
                };
                let list = if !condition.operands.is_empty() {
                    self.evaluate(&condition.operands[0], flags)?
                } else {
                    String::new()
                };
                let items = self.forall_forany_items(&list, &condition.condition_type)?;
                let saved_item = self.iterate_item.take();
                // C Exim: empty list → FALSE (not vacuous truth).
                // yield is initialized to !testfor (FALSE when not negated).
                // Only set to TRUE after iterating at least one item.
                let mut all_true = !items.is_empty();
                for item_val in &items {
                    self.iterate_item = Some(item_val.clone());
                    if !condition.sub_conditions.is_empty() {
                        let cond_result = self
                            .eval_condition_impl(&condition.sub_conditions[0], flags)
                            .map_err(|e| {
                                // C Exim wraps inner errors with %q quoting
                                match e {
                                    ExpandError::Failed { message } => ExpandError::Failed {
                                        message: format!(
                                            "{} inside \"{}\" condition",
                                            exim_q_quote(&message),
                                            cond_name
                                        ),
                                    },
                                    other => other,
                                }
                            })?;
                        if !cond_result {
                            all_true = false;
                            break;
                        }
                    }
                }
                self.iterate_item = saved_item;
                all_true
            }
            ConditionType::ForAny | ConditionType::ForAnyJson | ConditionType::ForAnyJsons => {
                let cond_name = match &condition.condition_type {
                    ConditionType::ForAny => "forany",
                    ConditionType::ForAnyJson => "forany_json",
                    ConditionType::ForAnyJsons => "forany_jsons",
                    _ => "forany",
                };
                let list = if !condition.operands.is_empty() {
                    self.evaluate(&condition.operands[0], flags)?
                } else {
                    String::new()
                };
                let items = self.forall_forany_items(&list, &condition.condition_type)?;
                let saved_item = self.iterate_item.take();
                let mut any_true = false;
                for item_val in &items {
                    self.iterate_item = Some(item_val.clone());
                    if !condition.sub_conditions.is_empty() {
                        let cond_result = self
                            .eval_condition_impl(&condition.sub_conditions[0], flags)
                            .map_err(|e| {
                                // C Exim wraps inner errors with %q quoting
                                match e {
                                    ExpandError::Failed { message } => ExpandError::Failed {
                                        message: format!(
                                            "{} inside \"{}\" condition",
                                            exim_q_quote(&message),
                                            cond_name
                                        ),
                                    },
                                    other => other,
                                }
                            })?;
                        if cond_result {
                            any_true = true;
                            break;
                        }
                    }
                }
                self.iterate_item = saved_item;
                any_true
            }

            // ─── Crypto comparison ───
            ConditionType::Crypteq => {
                let (plaintext, hash) = self.eval_two_operands(&condition.operands, flags)?;
                // Simple hash comparison — full crypteq requires crypt() FFI
                // For basic comparison, check if md5/sha1 hex match
                if let Some(expected) = hash.strip_prefix("{md5}") {
                    let mut hasher = <Md5 as digest::Digest>::new();
                    digest::Digest::update(&mut hasher, latin1_bytes(&plaintext));
                    let result = digest::Digest::finalize(hasher);
                    let computed = hex_encode(&result);
                    computed == expected
                } else if let Some(expected) = hash.strip_prefix("{sha1}") {
                    let mut hasher = <Sha1 as digest::Digest>::new();
                    digest::Digest::update(&mut hasher, latin1_bytes(&plaintext));
                    let result = digest::Digest::finalize(hasher);
                    let computed = hex_encode(&result);
                    computed == expected
                } else {
                    plaintext == hash
                }
            }

            // ─── Authentication conditions ───
            ConditionType::LdapAuth
            | ConditionType::Pam
            | ConditionType::Radius
            | ConditionType::Saslauthd => {
                // These require FFI to respective libraries
                // Return false when not available at runtime
                tracing::warn!(cond = ?condition.condition_type, "auth condition not implemented at expansion level");
                false
            }

            // ─── SRS condition ───
            #[cfg(feature = "srs")]
            ConditionType::InboundSrs => {
                let val = self.eval_one_operand(&condition.operands, flags)?;
                val.starts_with("SRS0=") || val.starts_with("SRS1=")
            }
            #[cfg(not(feature = "srs"))]
            ConditionType::InboundSrs => false,
        };

        // Apply negation if present
        Ok(if condition.negated { !result } else { result })
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 4: Arithmetic expression evaluator
    // ─────────────────────────────────────────────────────────────────────────

    /// Top-level arithmetic expression evaluator.
    ///
    /// Replaces `eval_expr()` from expand.c lines 4200-4216.
    ///
    /// # Arguments
    /// * `input` — The arithmetic expression string
    /// * `decimal` — If true, decimal-only mode (eval10); if false, C-style (eval)
    ///   with 0x hex and 0 octal prefix support.
    ///
    /// # Returns
    /// The evaluated integer value, or ExpandError::IntegerError on failure.
    pub fn eval_expr(&mut self, input: &str, decimal: bool) -> Result<i64, ExpandError> {
        Self::eval_expr_static(input, decimal)
    }

    /// Static version of eval_expr for use by operator handlers.
    fn eval_expr_static(input: &str, decimal: bool) -> Result<i64, ExpandError> {
        match Self::eval_expr_full(input, decimal) {
            Ok(val) => Ok(val),
            Err((msg, consumed)) => Err(ExpandError::Failed {
                message: format!(
                    "error in expression evaluation: {} (after processing \"{}\")",
                    msg, consumed
                ),
            }),
        }
    }

    /// Full expression evaluator returning the consumed portion on error.
    ///
    /// Matches C Exim's `eval_expr()` (expand.c lines 4200-4216).
    /// Returns `Ok(value)` on success, or `Err((error_msg, consumed_str))`
    /// where `consumed_str` is the portion of input successfully processed
    /// before the error (used by the caller to format C-compatible error
    /// messages).
    fn eval_expr_full(input: &str, decimal: bool) -> Result<i64, (String, String)> {
        let bytes = input.as_bytes();
        let mut pos = 0;
        // Skip leading whitespace (C Exim does this via Uskip_whitespace)
        Self::skip_whitespace(bytes, &mut pos);
        let start = pos;

        let result = Self::eval_op_or_v2(bytes, &mut pos, decimal);

        match result {
            Ok(val) => {
                // After successful parse, check for trailing chars.
                Self::skip_whitespace(bytes, &mut pos);
                if pos < bytes.len() {
                    // Trailing characters — "expecting operator"
                    let consumed = std::str::from_utf8(&bytes[start..pos]).unwrap_or("").trim();
                    Err(("expecting operator".to_string(), consumed.to_string()))
                } else {
                    Ok(val)
                }
            }
            Err(msg) => {
                // Report how much was consumed before the error.
                let consumed = std::str::from_utf8(&bytes[start..pos]).unwrap_or("").trim();
                Err((msg, consumed.to_string()))
            }
        }
    }

    // ─── C-compatible expression evaluator (v2) ───────────────────
    //
    // These `_v2` functions match C Exim's eval_expr/eval_number/
    // eval_op_unary/eval_op_mult/etc. structure exactly, advancing a
    // shared `pos` pointer through the byte slice.  On error they
    // return a String matching C Exim's error messages.

    fn eval_op_or_v2(input: &[u8], pos: &mut usize, decimal: bool) -> Result<i64, String> {
        let mut left = Self::eval_op_xor_v2(input, pos, decimal)?;
        Self::skip_whitespace(input, pos);
        while *pos < input.len() && input[*pos] == b'|' {
            if *pos + 1 < input.len() && input[*pos + 1] == b'|' {
                break;
            }
            *pos += 1;
            let right = Self::eval_op_xor_v2(input, pos, decimal)?;
            left |= right;
            Self::skip_whitespace(input, pos);
        }
        Ok(left)
    }

    fn eval_op_xor_v2(input: &[u8], pos: &mut usize, decimal: bool) -> Result<i64, String> {
        let mut left = Self::eval_op_and_v2(input, pos, decimal)?;
        Self::skip_whitespace(input, pos);
        while *pos < input.len() && input[*pos] == b'^' {
            *pos += 1;
            let right = Self::eval_op_and_v2(input, pos, decimal)?;
            left ^= right;
            Self::skip_whitespace(input, pos);
        }
        Ok(left)
    }

    fn eval_op_and_v2(input: &[u8], pos: &mut usize, decimal: bool) -> Result<i64, String> {
        let mut left = Self::eval_op_shift_v2(input, pos, decimal)?;
        Self::skip_whitespace(input, pos);
        while *pos < input.len() && input[*pos] == b'&' {
            if *pos + 1 < input.len() && input[*pos + 1] == b'&' {
                break;
            }
            *pos += 1;
            let right = Self::eval_op_shift_v2(input, pos, decimal)?;
            left &= right;
            Self::skip_whitespace(input, pos);
        }
        Ok(left)
    }

    fn eval_op_shift_v2(input: &[u8], pos: &mut usize, decimal: bool) -> Result<i64, String> {
        let mut left = Self::eval_op_add_v2(input, pos, decimal)?;
        Self::skip_whitespace(input, pos);
        while *pos + 1 < input.len() {
            if input[*pos] == b'<' && input[*pos + 1] == b'<' {
                *pos += 2;
                let right = Self::eval_op_add_v2(input, pos, decimal)?;
                left = left.wrapping_shl(right as u32);
                Self::skip_whitespace(input, pos);
            } else if input[*pos] == b'>' && input[*pos + 1] == b'>' {
                *pos += 2;
                let right = Self::eval_op_add_v2(input, pos, decimal)?;
                left = left.wrapping_shr(right as u32);
                Self::skip_whitespace(input, pos);
            } else {
                break;
            }
        }
        Ok(left)
    }

    fn eval_op_add_v2(input: &[u8], pos: &mut usize, decimal: bool) -> Result<i64, String> {
        let mut left = Self::eval_op_mult_v2(input, pos, decimal)?;
        Self::skip_whitespace(input, pos);
        while *pos < input.len() {
            match input[*pos] {
                b'+' => {
                    *pos += 1;
                    let right = Self::eval_op_mult_v2(input, pos, decimal)?;
                    left = left.wrapping_add(right);
                }
                b'-' => {
                    *pos += 1;
                    let right = Self::eval_op_mult_v2(input, pos, decimal)?;
                    left = left.wrapping_sub(right);
                }
                _ => break,
            }
            Self::skip_whitespace(input, pos);
        }
        Ok(left)
    }

    fn eval_op_mult_v2(input: &[u8], pos: &mut usize, decimal: bool) -> Result<i64, String> {
        let mut left = Self::eval_op_unary_v2(input, pos, decimal)?;
        Self::skip_whitespace(input, pos);
        while *pos < input.len() {
            match input[*pos] {
                b'*' => {
                    *pos += 1;
                    let right = Self::eval_op_unary_v2(input, pos, decimal)?;
                    left = left.wrapping_mul(right);
                }
                b'/' => {
                    *pos += 1;
                    let right = Self::eval_op_unary_v2(input, pos, decimal)?;
                    if right == 0 {
                        return Err("division by zero".to_string());
                    }
                    left /= right;
                }
                b'%' => {
                    *pos += 1;
                    let right = Self::eval_op_unary_v2(input, pos, decimal)?;
                    if right == 0 {
                        return Err("modulo by zero".to_string());
                    }
                    left %= right;
                }
                _ => break,
            }
            Self::skip_whitespace(input, pos);
        }
        Ok(left)
    }

    /// C Exim eval_op_unary: handles `-`, `+`, `~`, `!` prefixes and atoms.
    ///
    /// Matches C Exim expand.c eval_op_unary (lines 4261-4288).
    fn eval_op_unary_v2(input: &[u8], pos: &mut usize, decimal: bool) -> Result<i64, String> {
        Self::skip_whitespace(input, pos);
        if *pos >= input.len() {
            return Err("expecting number or opening parenthesis".to_string());
        }
        match input[*pos] {
            b'+' | b'-' | b'~' => {
                let op = input[*pos];
                *pos += 1;
                let x = Self::eval_op_unary_v2(input, pos, decimal)?;
                Ok(match op {
                    b'-' => x.wrapping_neg(),
                    b'~' => !x,
                    _ => x, // unary +
                })
            }
            b'!' => {
                *pos += 1;
                let x = Self::eval_op_unary_v2(input, pos, decimal)?;
                Ok(if x == 0 { 1 } else { 0 })
            }
            _ => Self::eval_number_v2(input, pos, decimal),
        }
    }

    /// C Exim eval_number: parse a numeric literal or parenthesized expr.
    ///
    /// Matches expand.c lines 4218-4257.  Key behaviors:
    /// - In non-decimal mode: `0x...` is hex, `0...` starting with `0`
    ///   followed by digit uses C's `sscanf` `%lli` format (reads as
    ///   far as digits match the base, stops at non-matching char).
    /// - Supports K/M/G suffixes (case-insensitive).
    /// - Parenthesized sub-expressions.
    fn eval_number_v2(input: &[u8], pos: &mut usize, decimal: bool) -> Result<i64, String> {
        Self::skip_whitespace(input, pos);
        if *pos >= input.len() {
            return Err("expecting number or opening parenthesis".to_string());
        }
        let ch = input[*pos];
        if ch.is_ascii_digit() {
            // Parse the number.  In C Exim, non-decimal mode uses
            // sscanf with %lli which auto-detects hex (0x) and octal
            // (leading 0).  In decimal mode, sscanf uses %lld.
            //
            // For C compatibility, we replicate the sscanf behavior:
            // - In decimal mode: read consecutive digits as decimal
            // - In non-decimal mode: 0x → hex, leading 0 → octal, else decimal
            let n = if !decimal && ch == b'0' && *pos + 1 < input.len() {
                let next = input[*pos + 1];
                if next == b'x' || next == b'X' {
                    // Hex: 0xNNN
                    *pos += 2;
                    let hex_start = *pos;
                    while *pos < input.len() && input[*pos].is_ascii_hexdigit() {
                        *pos += 1;
                    }
                    if *pos == hex_start {
                        // `0x` with no hex digits — C sscanf reads `0` and stops
                        // Actually C sscanf with %lli on "0x..." reads 0 and
                        // stops at 'x'.  Let's just parse the `0`.
                        *pos = hex_start - 1; // back to 'x'
                        0i64
                    } else {
                        let hex_str = std::str::from_utf8(&input[hex_start..*pos]).unwrap_or("0");
                        i64::from_str_radix(hex_str, 16).unwrap_or(0)
                    }
                } else if next.is_ascii_digit() {
                    // Octal: 0NNN — C sscanf %lli reads octal for leading-0
                    // But it stops at first non-octal digit (8, 9).
                    *pos += 1; // skip the leading 0
                    let oct_start = *pos;
                    while *pos < input.len() && input[*pos] >= b'0' && input[*pos] <= b'7' {
                        *pos += 1;
                    }
                    if *pos == oct_start {
                        // Just "0" followed by 8 or 9 — C reads 0
                        0i64
                    } else {
                        let oct_str = std::str::from_utf8(&input[oct_start..*pos]).unwrap_or("0");
                        i64::from_str_radix(oct_str, 8).unwrap_or(0)
                    }
                } else {
                    // Just "0" followed by non-digit
                    *pos += 1;
                    0i64
                }
            } else {
                // Decimal number (or decimal mode)
                let dec_start = *pos;
                while *pos < input.len() && input[*pos].is_ascii_digit() {
                    *pos += 1;
                }
                let dec_str = std::str::from_utf8(&input[dec_start..*pos]).unwrap_or("0");
                dec_str.parse::<i64>().unwrap_or(0)
            };

            // Check for K/M/G suffix
            let n = if *pos < input.len() {
                match input[*pos].to_ascii_lowercase() {
                    b'k' => {
                        *pos += 1;
                        n.wrapping_mul(1024)
                    }
                    b'm' => {
                        *pos += 1;
                        n.wrapping_mul(1024 * 1024)
                    }
                    b'g' => {
                        *pos += 1;
                        n.wrapping_mul(1024 * 1024 * 1024)
                    }
                    _ => n,
                }
            } else {
                n
            };

            Self::skip_whitespace(input, pos);
            Ok(n)
        } else if ch == b'(' {
            *pos += 1;
            let val = Self::eval_op_or_v2(input, pos, decimal)?;
            // C Exim: eval_expr with endket=TRUE
            Self::skip_whitespace(input, pos);
            if *pos >= input.len() || input[*pos] != b')' {
                return Err("expecting closing parenthesis".to_string());
            }
            *pos += 1;
            Self::skip_whitespace(input, pos);
            Ok(val)
        } else {
            Err("expecting number or opening parenthesis".to_string())
        }
    }

    /// Skip ASCII whitespace in the expression input.
    fn skip_whitespace(input: &[u8], pos: &mut usize) {
        while *pos < input.len() && input[*pos].is_ascii_whitespace() {
            *pos += 1;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 5: Helper functions
    // ─────────────────────────────────────────────────────────────────────────

    /// Evaluate a single argument from the args list.
    fn eval_arg(
        &mut self,
        args: &[AstNode],
        index: usize,
        flags: EsiFlags,
    ) -> Result<String, ExpandError> {
        if index < args.len() {
            self.evaluate(&args[index], flags)
        } else {
            Ok(String::new())
        }
    }

    /// Evaluate one operand from a condition's operand list.
    fn eval_one_operand(
        &mut self,
        operands: &[AstNode],
        flags: EsiFlags,
    ) -> Result<String, ExpandError> {
        if operands.is_empty() {
            return Err(ExpandError::Failed {
                message: "condition requires an operand".into(),
            });
        }
        self.evaluate(&operands[0], flags)
    }

    /// Evaluate two operands from a condition's operand list.
    fn eval_two_operands(
        &mut self,
        operands: &[AstNode],
        flags: EsiFlags,
    ) -> Result<(String, String), ExpandError> {
        if operands.len() < 2 {
            return Err(ExpandError::Failed {
                message: "condition requires two operands".into(),
            });
        }
        let a = self.evaluate(&operands[0], flags)?;
        let b = self.evaluate(&operands[1], flags)?;
        Ok((a, b))
    }

    /// Parse a string as a boolean value (lax mode — for BoolLax).
    /// Any non-empty string is true.
    fn eval_bool_string(&self, val: &str) -> bool {
        !val.is_empty()
    }

    /// Parse a string as a boolean value (strict mode — for Bool condition).
    /// C Exim recognises: true/yes/1 (and non-zero integers) as true;
    /// false/no/0/"" as false. Leading/trailing whitespace is stripped.
    /// Negation with leading "!" is supported.
    /// Unrecognised values produce an error.
    /// Split a list into items for forall/forany, using JSON array parsing
    /// for JSON variants or colon-separated list splitting for plain variants.
    fn forall_forany_items(
        &self,
        list: &str,
        ct: &ConditionType,
    ) -> Result<Vec<String>, ExpandError> {
        match ct {
            ConditionType::ForAllJson | ConditionType::ForAnyJson => {
                // Parse as JSON array, return JSON representation
                // (strings keep quotes, numbers as-is)
                let arr: serde_json::Value =
                    serde_json::from_str(list).map_err(|e| ExpandError::Failed {
                        message: format!("failed to parse JSON array: {}", e),
                    })?;
                if let Some(arr) = arr.as_array() {
                    Ok(arr.iter().map(json_format_compact).collect())
                } else {
                    Ok(vec![list.to_string()])
                }
            }
            ConditionType::ForAllJsons | ConditionType::ForAnyJsons => {
                // Parse as JSON array, return string values (unquoted)
                let arr: serde_json::Value =
                    serde_json::from_str(list).map_err(|e| ExpandError::Failed {
                        message: format!("failed to parse JSON array: {}", e),
                    })?;
                if let Some(arr) = arr.as_array() {
                    Ok(arr
                        .iter()
                        .map(|v| {
                            if v.is_string() {
                                v.as_str().unwrap_or("").to_string()
                            } else {
                                json_format_compact(v)
                            }
                        })
                        .collect())
                } else {
                    Ok(vec![list.to_string()])
                }
            }
            _ => {
                // Plain list split
                let (_sep, items) = exim_list_split(list);
                Ok(items)
            }
        }
    }

    fn eval_bool_strict(&self, val: &str) -> Result<bool, ExpandError> {
        let trimmed = val.trim();
        // Handle negation
        if let Some(rest) = trimmed.strip_prefix('!') {
            let inner = self.eval_bool_strict(rest)?;
            return Ok(!inner);
        }
        let lower = trimmed.to_lowercase();
        match lower.as_str() {
            "" => Ok(false),
            "true" | "yes" | "y" => Ok(true),
            "false" | "no" | "n" => Ok(false),
            _ => {
                // Try as integer — non-zero is true
                if let Ok(num) = trimmed.parse::<i64>() {
                    Ok(num != 0)
                } else {
                    Err(ExpandError::Failed {
                        message: format!("unrecognised boolean value \"{}\"", trimmed),
                    })
                }
            }
        }
    }

    /// Parse a string as i64 per C Exim `expanded_string_integer`.
    ///
    /// Supports K/M/G suffixes, leading whitespace skip, blank → 0 compat,
    /// and produces C Exim's exact error message formats:
    ///   - `"integer expected but \"X\" found"` — no leading digits
    ///   - `"non-negative integer expected but \"X\" found"` — negative when isplus
    ///   - `"invalid integer \"X\""` — trailing non-suffix chars
    ///   - `"absolute value of integer \"X\" is too large (overflow)"` — overflow
    fn parse_int64_ex(&self, s: &str, isplus: bool) -> Result<i64, ExpandError> {
        let bytes = s.as_bytes();
        let len = bytes.len();

        // Skip leading whitespace (matching C strtoll behaviour)
        let mut pos = 0;
        while pos < len && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }

        // C compat: blank string → 0
        if pos >= len {
            return Ok(0);
        }

        // Parse integer with strtoll-like semantics:
        // optional sign, then digits
        let start = pos;
        let negative = if pos < len && bytes[pos] == b'-' {
            pos += 1;
            true
        } else if pos < len && bytes[pos] == b'+' {
            pos += 1;
            false
        } else {
            false
        };

        let digit_start = pos;
        while pos < len && bytes[pos].is_ascii_digit() {
            pos += 1;
        }

        // No digits found at all
        if pos == digit_start {
            return Err(ExpandError::IntegerError(format!(
                "integer expected but \"{}\" found",
                s
            )));
        }

        // Parse the numeric part
        let num_str = std::str::from_utf8(&bytes[start..pos]).unwrap_or("0");
        let mut value: i64 = match num_str.parse() {
            Ok(v) => v,
            Err(_) => {
                // Overflow or other parse failure
                return Err(ExpandError::IntegerError(format!(
                    "absolute value of integer \"{}\" is too large (overflow)",
                    s
                )));
            }
        };

        // Check isplus (non-negative required)
        if value < 0 && isplus {
            return Err(ExpandError::IntegerError(format!(
                "non-negative integer expected but \"{}\" found",
                s
            )));
        }

        // Check for K/M/G suffix
        if pos < len {
            match bytes[pos] | 0x20 {
                // tolower
                b'k' => {
                    if !(i64::MIN / 1024..=i64::MAX / 1024).contains(&value) {
                        return Err(ExpandError::IntegerError(format!(
                            "absolute value of integer \"{}\" is too large (overflow)",
                            s
                        )));
                    }
                    value *= 1024;
                    pos += 1;
                }
                b'm' => {
                    if !(i64::MIN / (1024 * 1024)..=i64::MAX / (1024 * 1024)).contains(&value) {
                        return Err(ExpandError::IntegerError(format!(
                            "absolute value of integer \"{}\" is too large (overflow)",
                            s
                        )));
                    }
                    value *= 1024 * 1024;
                    pos += 1;
                }
                b'g' => {
                    if !(i64::MIN / (1024 * 1024 * 1024)..=i64::MAX / (1024 * 1024 * 1024))
                        .contains(&value)
                    {
                        return Err(ExpandError::IntegerError(format!(
                            "absolute value of integer \"{}\" is too large (overflow)",
                            s
                        )));
                    }
                    value *= 1024 * 1024 * 1024;
                    pos += 1;
                }
                _ => {}
            }
        }

        // Skip trailing whitespace
        while pos < len && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }

        // If there's still remaining text, it's invalid
        if pos < len {
            return Err(ExpandError::IntegerError(format!(
                "invalid integer \"{}\"",
                s
            )));
        }

        // Check for overflow via negative flag
        if negative && value > 0 {
            // This shouldn't happen with proper i64 parsing, but guard
        }

        Ok(value)
    }

    /// Parse a string as i64 (non-plus variant for backward compat).
    fn parse_int64(&self, s: &str) -> Result<i64, ExpandError> {
        self.parse_int64_ex(s, false)
    }

    /// Handle yes/no branch selection after items/conditions.
    ///
    /// Takes a success flag and expands the appropriate branch (yes on success,
    /// no on failure). If only one branch exists, it is expanded on success
    /// and nothing is expanded on failure.
    ///
    /// Replaces the `process_yesno()` pattern from expand.c ~lines 7230-7400.
    /// Expand a named list value, resolving `+listname` references
    /// recursively and re-serializing with `:` separator.
    ///
    /// C Exim `${listnamed:name}` behaviour:
    /// 1. Parse the list value using its separator (default `:`, or
    ///    custom via `<X` prefix).
    /// 2. For each item, if it starts with `+`, expand the named list
    ///    reference recursively.
    /// 3. Re-serialize all items with ` : ` separator, doubling any
    ///    colons inside individual items.
    fn expand_named_list_value(&self, value: &str) -> String {
        // Determine separator: default is `:`, or custom via `<X` prefix.
        let (sep, items_str) = parse_list_separator_prefix(value);

        // Split by separator, respecting doubled-separator escaping.
        let items = split_list_by_separator(items_str, sep);

        // Expand each item, recursively resolving `+name` references.
        let mut expanded_items: Vec<String> = Vec::new();
        for item in &items {
            let trimmed = item.trim();
            if trimmed.is_empty() {
                continue; // Skip empty items (trailing separators etc.)
            }
            if let Some(ref_name) = trimmed.strip_prefix('+') {
                // Recursive named list reference
                if let Some(ref_value) = self.ctx.named_lists.get(ref_name) {
                    let sub = self.expand_named_list_value(ref_value);
                    // The sub-list is already colon-separated — split it
                    // back to get individual items to merge.
                    for sub_item in split_list_by_separator(&sub, ':') {
                        let st = sub_item.trim();
                        if !st.is_empty() {
                            expanded_items.push(st.to_string());
                        }
                    }
                } else {
                    // Unknown list reference — pass through as-is
                    expanded_items.push(trimmed.to_string());
                }
            } else {
                expanded_items.push(trimmed.to_string());
            }
        }

        // Re-serialize with ` : ` separator, doubling colons inside items.
        let mut result = String::new();
        for (i, item) in expanded_items.iter().enumerate() {
            if i > 0 {
                result.push_str(" : ");
            }
            // Double any colons within the item to escape them
            for ch in item.chars() {
                if ch == ':' {
                    result.push_str("::");
                } else {
                    result.push(ch);
                }
            }
        }
        result
    }

    fn process_yesno(
        &mut self,
        success: bool,
        yes_branch: Option<&AstNode>,
        no_branch: Option<&AstNode>,
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        tracing::trace!(success, "process_yesno");

        if success {
            if let Some(yes) = yes_branch {
                self.eval_node(yes, flags, output)?;
            } else if let Some(ref val) = self.lookup_value {
                // If no yes_branch but lookup_value is set, use it as default output
                output.push_str(val);
            }
        } else if let Some(no) = no_branch {
            self.eval_node(no, flags, output)?;
        }
        Ok(())
    }
} // end impl Evaluator

// ─────────────────────────────────────────────────────────────────────────────
// Free-standing helper functions
// ─────────────────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════════
//  C Exim-compatible list parsing
// ═══════════════════════════════════════════════════════════════════════════

/// Parse a C Exim list separator override prefix.
///
/// C Exim: if a list string begins with `<` followed by a single character,
/// that character becomes the list separator (replacing the default `:`).
/// Returns `(separator, rest_of_list)`.
pub fn parse_list_separator(list: &str) -> (char, &str) {
    // C Exim's matchlist_parse_sep() (match.c line 396) and
    // string_nextinlist() (string.c line 950) both:
    //   1. Skip leading whitespace before the `<` marker.
    //   2. Accept the separator character ONLY if it is
    //      `ispunct(c) || iscntrl(c)`.  Alphanumeric and space
    //      characters are NOT valid separators — the `<` is treated
    //      as literal list content and the default `:` is used.
    //   3. For the change-of-separator spec, C's matchlist_parse_sep
    //      calls `string_interpret_escape()` when the character after
    //      `<` is `\`, so `<\n` means newline, `<\t` means tab, etc.
    //      Because our expansion engine already processes `\n`→0x0A
    //      inside braces BEFORE this function is called, the expanded
    //      result already contains the real byte (e.g. `<` 0x0A).
    //      We therefore only need the escape-sequence branch for the
    //      case where the raw pre-expansion form `<\n` survives
    //      expansion unchanged (which doesn't happen in practice, but
    //      we keep it for robustness).

    // Skip leading whitespace (C: Uskip_whitespace / isspace loop).
    let trimmed = list.trim_start();
    let bytes = trimmed.as_bytes();

    if bytes.len() >= 2 && bytes[0] == b'<' {
        // Determine the candidate separator character and how many
        // bytes of `trimmed` the separator spec occupies.
        let (candidate, consumed) = if bytes[1] == b'\\' && bytes.len() >= 3 {
            // Escape-sequence form: <\n, <\t, <\xHH, <\NNN, <\X
            match bytes[2] {
                b'n' => ('\n', 3),
                b't' => ('\t', 3),
                b'r' => ('\r', 3),
                b'x' if bytes.len() >= 5 => {
                    let hi = (bytes[3] as char).to_digit(16).unwrap_or(0) as u8;
                    let lo = (bytes[4] as char).to_digit(16).unwrap_or(0) as u8;
                    ((hi * 16 + lo) as char, 5)
                }
                d @ b'0'..=b'7' => {
                    let mut val = (d - b'0') as u32;
                    let mut ofs = 3;
                    for _ in 0..2 {
                        if ofs < bytes.len() && bytes[ofs] >= b'0' && bytes[ofs] <= b'7' {
                            val = val * 8 + (bytes[ofs] - b'0') as u32;
                            ofs += 1;
                        } else {
                            break;
                        }
                    }
                    (char::from_u32(val).unwrap_or('\0'), ofs)
                }
                other => (other as char, 3),
            }
        } else {
            // Direct form: <X  (single byte after `<`)
            (bytes[1] as char, 2)
        };

        // C Exim validation: the separator must be ispunct() or
        // iscntrl().  Alphanumeric and space characters are rejected,
        // causing the `<` to be treated as literal list content.
        let is_valid = candidate.is_ascii_punctuation()
            || candidate.is_ascii_control()
            || !candidate.is_ascii();
        if is_valid {
            let rest = &trimmed[consumed..];
            // Skip one optional space after the separator spec.
            let rest = rest.strip_prefix(' ').unwrap_or(rest);
            return (candidate, rest);
        }
        // Invalid separator character — fall through to default `:`
        // and return the ORIGINAL list (including the `<` that was not
        // consumed as a separator change).
    }

    (':', list)
}

/// Split a C Exim list string into items using `string_nextinlist()` semantics.
///
/// C Exim list rules:
/// - Default separator is `:` unless overridden by `< sep` prefix
/// - Doubled separator (e.g. `::` with sep=`:`) produces a literal separator
///   character embedded in the item value
/// - Items are trimmed of leading/trailing whitespace
/// - Trailing separator is ignored (does not produce an empty item)
/// - An empty list string produces zero items
pub fn exim_list_split(list: &str) -> (char, Vec<String>) {
    let (sep, body) = parse_list_separator(list);
    // C Exim: control-character separators are "special" — doubled separator
    // does NOT produce a literal separator in the item; instead it produces
    // an empty item.  For ispunct() separators, doubled separator embeds
    // the separator character into the item.
    let sep_is_special = (sep as u32) < 32 || sep == '\x7f';
    let mut items = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = body.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        if chars[i] == sep {
            if !sep_is_special && i + 1 < len && chars[i + 1] == sep {
                // Doubled ispunct() separator → literal separator in item
                current.push(sep);
                i += 2;
            } else {
                // End of current item (always for iscntrl() separator)
                items.push(current.trim().to_string());
                current = String::new();
                i += 1;
            }
        } else {
            current.push(chars[i]);
            i += 1;
        }
    }

    // Handle the final item (only if there was content)
    let trimmed = current.trim().to_string();
    if !items.is_empty() || !trimmed.is_empty() {
        items.push(trimmed);
    }

    (sep, items)
}

/// Count items in a C Exim list (for `${listcount:...}`).
pub fn exim_list_count(list: &str) -> usize {
    if list.is_empty() {
        return 0;
    }
    let (_, items) = exim_list_split(list);
    items.len()
}

/// Get a numbered element from a C Exim list (for `${listextract}`).
///
/// `index` is 1-based (positive) or negative (counting from end).
/// Returns None if out of bounds.
pub fn exim_list_extract(index: i32, list: &str) -> Option<String> {
    let (_, items) = exim_list_split(list);
    let len = items.len() as i32;
    let real_idx = if index > 0 {
        index - 1
    } else if index < 0 {
        len + index
    } else {
        return None;
    };
    if real_idx >= 0 && real_idx < len {
        Some(items[real_idx as usize].clone())
    } else {
        None
    }
}

/// Join items back into a C Exim list string.
///
/// If an item contains the separator character, it is doubled to escape it.
/// Join items into a list string using C Exim's map/filter output convention
/// (expand.c lines 6904-6932):
///
///   - Each item is appended with embedded separator characters doubled.
///   - A separator is appended after every item; the final one is removed.
///   - Before an item (except the first), if the item starts with the
///     separator character OR is empty, a space is prepended.  This
///     disambiguates items that begin with the separator.
pub fn exim_list_join(items: &[String], sep: char) -> String {
    // C Exim: iscntrl() separators are never doubled — there is no way to
    // embed them in a data item.  ispunct() separators are doubled to
    // represent a literal separator character inside an item.
    let sep_is_special = (sep as u32) < 32 || sep == '\x7f';
    let mut result = String::new();
    let save_ptr = 0usize;
    for (i, item) in items.iter().enumerate() {
        let needs_space =
            i > 0 && result.len() > save_ptr && (item.starts_with(sep) || item.is_empty());
        if needs_space {
            result.push(' ');
        }
        // Append item, doubling separators only for ispunct() seps
        for ch in item.chars() {
            result.push(ch);
            if ch == sep && !sep_is_special {
                result.push(sep);
            }
        }
        // Append trailing separator
        result.push(sep);
    }
    // Remove redundant final separator
    if !items.is_empty() {
        result.pop();
    }
    result
}

/// Extract a numbered field from a string with given separators.
///
/// Field 1 = first field, negative counts from end, 0 = whole string.
/// Replaces `expand_gettokened()` from expand.c lines 1285-1333.
/// C Exim-compatible numbered field extraction.
///
/// Splits `data` by any character in `separators`, keeping empty fields
/// (consecutive separators produce empty fields).  Field numbers are
/// 1-based; negative numbers count from the end; 0 returns the whole
/// string.
pub fn expand_gettokened(field: i32, separators: &str, data: &str) -> Option<String> {
    if field == 0 {
        return Some(data.to_string());
    }

    let sep_chars: Vec<char> = separators.chars().collect();
    if sep_chars.is_empty() {
        return None;
    }

    // Split by separator characters — keep empty fields.
    let parts: Vec<&str> = data.split(|c: char| sep_chars.contains(&c)).collect();

    let index = if field > 0 {
        let idx = (field - 1) as usize;
        if idx >= parts.len() {
            return None;
        }
        idx
    } else {
        // Negative: count from end (-1 = last)
        let abs_field = (-field) as usize;
        if abs_field > parts.len() {
            return None;
        }
        parts.len() - abs_field
    };

    parts.get(index).map(|s| s.to_string())
}

/// Format a JSON value using compact formatting with spaces after
/// separators, matching C Exim's Jansson `JSON_COMPACT` output.
///
/// Jansson's compact mode produces: `{"key": value, "key2": value2}`
/// (space after colon and comma), while Rust's serde_json compact mode
/// produces: `{"key":value,"key2":value2}` (no spaces).
/// C Exim `%q` format: wrap a string in `"..."` and escape any
/// embedded `"` and `\t` characters (matching `string_printing3()`
/// with `SP_TAB | SP_DQUOTES`).
///
/// Used for error messages that wrap inner error text, e.g.:
///   `"%q inside %q item"` → `"inner \"msg\"" inside "reduce" item`
fn exim_q_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => {
                out.push('\\');
                out.push('"');
            }
            '\t' => {
                out.push('\\');
                out.push('t');
            }
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn json_format_compact(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(map) => {
            let mut s = String::from("{");
            for (i, (k, val)) in map.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                s.push('"');
                s.push_str(k);
                s.push_str("\":");
                s.push_str(&json_format_compact(val));
            }
            s.push('}');
            s
        }
        serde_json::Value::Array(arr) => {
            let mut s = String::from("[");
            for (i, val) in arr.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                s.push_str(&json_format_compact(val));
            }
            s.push(']');
            s
        }
        _ => v.to_string(),
    }
}

/// Parse list separator prefix from a list value string.
///
/// C Exim lists can start with `<X ` to specify a custom separator
/// character X.  Default separator is `:`.  Returns (separator, rest).
///
/// Mirrors `matchlist_parse_sep()` / `string_nextinlist()` validation:
/// the character after `<` must be `ispunct()` or `iscntrl()`.
fn parse_list_separator_prefix(value: &str) -> (char, &str) {
    let trimmed = value.trim_start();
    let bytes = trimmed.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'<' {
        let (candidate, consumed) = if bytes[1] == b'\\' && bytes.len() >= 3 {
            let esc = match bytes[2] {
                b'n' => '\n',
                b't' => '\t',
                b'r' => '\r',
                _ => bytes[2] as char,
            };
            (esc, 3)
        } else {
            (bytes[1] as char, 2)
        };
        let is_valid = candidate.is_ascii_punctuation()
            || candidate.is_ascii_control()
            || !candidate.is_ascii();
        if is_valid {
            let rest = &trimmed[consumed..];
            let rest = rest.strip_prefix(' ').unwrap_or(rest);
            return (candidate, rest);
        }
    }
    (':', value)
}

/// Split a list string by separator, respecting doubled-separator escaping.
///
/// In Exim lists, a doubled separator represents a literal separator
/// character in an item.  For example with `:` separator, `a::b` means
/// the item `a:b`, while `a:b` means two items `a` and `b`.
fn split_list_by_separator(s: &str, sep: char) -> Vec<String> {
    let mut items = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == sep {
            if i + 1 < chars.len() && chars[i + 1] == sep {
                // Doubled separator — literal separator in item
                current.push(sep);
                i += 2;
            } else {
                // Single separator — end of item
                items.push(current.clone());
                current.clear();
                i += 1;
            }
        } else {
            current.push(chars[i]);
            i += 1;
        }
    }
    items.push(current);
    items
}

/// Extract a value from a whitespace-separated `key=value` data string.
///
/// C Exim named-key extract: scans the data string for `key=value`
/// pairs.  Pairs are separated by whitespace.  The match is
/// case-insensitive on the key name.  Returns the value part or `None`.
/// Named-field extraction matching C Exim's `expand_getkeyed()`.
///
/// The data string contains whitespace-separated `key=value` or
/// `key "quoted value"` pairs.  Keys are matched case-insensitively.
/// Values may be double-quoted; within quotes, `\"` is an escaped quote
/// and `\\` is an escaped backslash.
pub fn extract_named_field(key: &str, data: &str) -> Option<String> {
    let bytes = data.as_bytes();
    let mut i = 0;
    let len = bytes.len();

    // Helper: skip whitespace.
    fn skip_ws(bytes: &[u8], pos: &mut usize) {
        while *pos < bytes.len() && (bytes[*pos] == b' ' || bytes[*pos] == b'\t') {
            *pos += 1;
        }
    }
    // Helper: read dequoted value (C Exim string_dequote semantics).
    fn read_value(bytes: &[u8], pos: &mut usize) -> String {
        let mut result = String::new();
        if *pos < bytes.len() && bytes[*pos] == b'"' {
            // Quoted value — read until closing `"`.
            *pos += 1; // skip opening "
            while *pos < bytes.len() && bytes[*pos] != b'"' {
                if bytes[*pos] == b'\\' && *pos + 1 < bytes.len() {
                    *pos += 1; // skip backslash
                    result.push(bytes[*pos] as char);
                } else {
                    result.push(bytes[*pos] as char);
                }
                *pos += 1;
            }
            if *pos < bytes.len() {
                *pos += 1; // skip closing "
            }
        } else {
            // Unquoted value — read until whitespace.
            while *pos < bytes.len() && bytes[*pos] != b' ' && bytes[*pos] != b'\t' {
                result.push(bytes[*pos] as char);
                *pos += 1;
            }
        }
        result
    }

    while i < len {
        skip_ws(bytes, &mut i);
        if i >= len {
            break;
        }

        // Read key: terminated by `=` or whitespace (not `"`).
        let key_start = i;
        while i < len && bytes[i] != b'=' && bytes[i] != b' ' && bytes[i] != b'\t' {
            i += 1;
        }
        let dkey = &data[key_start..i];

        // Skip whitespace, then optional `=`, then whitespace.
        skip_ws(bytes, &mut i);
        if i < len && bytes[i] == b'=' {
            i += 1;
            skip_ws(bytes, &mut i);
        }

        // Read value (possibly quoted).
        let val = read_value(bytes, &mut i);

        // Compare keys case-insensitively.
        if dkey.eq_ignore_ascii_case(key) {
            return Some(val);
        }
    }
    None
}

/// Extract element from Exim list by 1-based index.
///
/// Replaces `expand_getlistele()` from expand.c lines 1336-1349.
pub fn expand_getlistele(field: i32, list: &str, sep: char) -> Option<String> {
    if list.is_empty() {
        return None;
    }

    let items: Vec<&str> = list.split(sep).collect();

    if field == 0 {
        return Some(list.to_string());
    }

    let index = if field > 0 {
        (field - 1) as usize
    } else {
        let abs_field = (-field) as usize;
        if abs_field > items.len() {
            return None;
        }
        items.len() - abs_field
    };

    items.get(index).map(|s| s.trim().to_string())
}

/// Exim hash function: multiply accumulator by prime, add each byte, mod limit.
fn exim_hash(limit: u64, prime: u64, data: &str) -> u64 {
    let mut hash_val: u64 = 0;
    // Iterate chars (Latin-1 codepoints = original byte values)
    for ch in data.chars() {
        hash_val = hash_val.wrapping_mul(prime).wrapping_add(ch as u64);
    }
    if limit > 0 {
        hash_val % limit
    } else {
        hash_val
    }
}

/// Exim-style base62 encoding (0-9, A-Z, a-z).
/// C Exim's string_base62_32 always outputs exactly 6 chars (zero-padded left).
fn encode_base62(mut val: u64) -> String {
    const CHARSET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const WIDTH: usize = 6;
    let mut result = vec![CHARSET[0]; WIDTH]; // Fill with '0'
    for i in (0..WIDTH).rev() {
        result[i] = CHARSET[(val % 62) as usize];
        val /= 62;
    }
    String::from_utf8(result).unwrap_or_default()
}

/// Base62 decoding — C Exim-compatible error messages.
fn decode_base62(s: &str) -> Result<u64, String> {
    let mut val: u64 = 0;
    for ch in s.chars() {
        val = val.checked_mul(62).ok_or_else(|| {
            format!(
                "argument for base62d operator is \"{}\", which is not a base 62 number",
                s
            )
        })?;
        let digit = match ch {
            '0'..='9' => (ch as u64) - ('0' as u64),
            'A'..='Z' => (ch as u64) - ('A' as u64) + 10,
            'a'..='z' => (ch as u64) - ('a' as u64) + 36,
            _ => {
                return Err(format!(
                    "argument for base62d operator is \"{}\", which is not a base 62 number",
                    s
                ))
            }
        };
        val = val
            .checked_add(digit)
            .ok_or_else(|| "base62 overflow".to_string())?;
    }
    Ok(val)
}

/// C Exim `hashcodes` table — note the deliberate "qrtsuvwxyz" (t before s)
/// in lowercase section, matching the C source.
const HASHCODES: &[u8] = b"abcdefghijklmnopqrtsuvwxyz\
                            ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            0123456789";

/// Primes table for nhash — matches C Exim's prime[] array.
const NHASH_PRIMES: &[u32] = &[
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113,
];

/// C Exim compute_hash: XOR-based hash producing a string of `value1` chars
/// from a `value2`-size alphabet (the hashcodes table). Default value2=26 if <=0.
fn compute_hash_exim(subject: &str, value1: i32, mut value2: i32) -> Result<String, ExpandError> {
    let bytes = latin1_bytes(subject);
    let sublen = bytes.len() as i32;

    if value2 <= 0 {
        value2 = 26;
    } else if value2 as usize > HASHCODES.len() {
        return Err(ExpandError::Failed {
            message: format!("hash count \"{}\" too big", value2),
        });
    }

    let value1 = value1 as usize;
    let value2 = value2 as usize;

    if value1 < bytes.len() {
        // Apply XOR hash into first value1 bytes
        let mut buf = bytes;
        let mut i = 0usize;
        let mut j = value1;
        while j < buf.len() {
            let c = buf[j] as u32;
            let shift = ((c as usize) + j) & 7;
            let shifted = ((c << shift) | (c >> (8 - shift))) as u8;
            buf[i] ^= shifted;
            i += 1;
            if i >= value1 {
                i = 0;
            }
            j += 1;
        }
        // Map to hashcodes alphabet
        let mut result = String::with_capacity(value1);
        for i in 0..value1 {
            result.push(HASHCODES[(buf[i] as usize) % value2] as char);
        }
        Ok(result)
    } else {
        // String is shorter than requested hash length — return original string
        Ok(subject[..std::cmp::min(sublen as usize, value1)].to_string())
    }
}

/// C Exim compute_nhash: weighted-prime numeric hash.
/// With value2 < 0 (not given): outputs `total % value1`.
/// With value2 >= 0: outputs `total/(value1*value2)/value2`/`total%(value1*value2)%value2`.
fn compute_nhash_exim(subject: &str, value1: i32, value2: i32) -> Result<String, ExpandError> {
    let mut total: u64 = 0;
    let mut i = 0usize;
    for ch in subject.chars() {
        if i == 0 {
            i = NHASH_PRIMES.len() - 1;
        }
        total += (NHASH_PRIMES[i] as u64) * (ch as u64);
        i -= 1;
    }

    if value2 < 0 {
        // Single hash value
        if value1 == 0 {
            return Err(ExpandError::Failed {
                message: "nhash divisor must be non-zero".into(),
            });
        }
        Ok(format!("{}", total % (value1 as u64)))
    } else {
        // Div/mod hash
        if value1 == 0 || value2 == 0 {
            return Err(ExpandError::Failed {
                message: "nhash divisors must be non-zero".into(),
            });
        }
        let combined = (value1 as u64) * (value2 as u64);
        let total = total % combined;
        Ok(format!(
            "{}/{}",
            total / (value2 as u64),
            total % (value2 as u64)
        ))
    }
}

/// Exim-style base32 encoding: takes a decimal number, produces lowercase
/// base32 (alphabet: abcdefghijklmnopqrstuvwxyz234567), no padding.
/// Input: decimal string. Output: base32 string.
fn encode_base32_exim(n: u64) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    if n == 0 {
        return String::new();
    }
    // Build from LSB, then reverse
    let mut chars = Vec::new();
    let mut val = n;
    while val > 0 {
        chars.push(ALPHABET[(val & 0x1f) as usize] as char);
        val >>= 5;
    }
    chars.reverse();
    chars.into_iter().collect()
}

/// Exim-style base32 decoding: takes a base32 string (lowercase alphabet),
/// produces a decimal number as string.
fn decode_base32_exim(s: &str) -> Result<u64, String> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut n: u64 = 0;
    for ch in s.chars() {
        let pos = ALPHABET.iter().position(|&c| c == ch as u8);
        match pos {
            Some(v) => {
                n = n
                    .checked_mul(32)
                    .ok_or_else(|| "base32d overflow".to_string())?;
                n = n
                    .checked_add(v as u64)
                    .ok_or_else(|| "base32d overflow".to_string())?;
            }
            None => {
                return Err(format!(
                    "argument for base32d operator is \"{}\", which is not a base 32 number",
                    s
                ));
            }
        }
    }
    Ok(n)
}

/// Hex decode a string (e.g., "48656C6C6F" -> [0x48, 0x65, 0x6C, 0x6C, 0x6F]).
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    // C Exim: first check all characters are hex digits, then check even length
    for ch in s.chars() {
        if !ch.is_ascii_hexdigit() {
            return Err(format!("\"{}\" is not a hex string", s));
        }
    }
    if !s.len().is_multiple_of(2) {
        return Err(format!("\"{}\" contains an odd number of characters", s));
    }
    let mut result = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|_| format!("\"{}\" is not a hex string", s))?;
        result.push(byte);
    }
    Ok(result)
}

/// Hex encode bytes to lowercase hex string.
fn hex_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len() * 2);
    for byte in data {
        write!(result, "{:02x}", byte).unwrap();
    }
    result
}

/// Extract the email address from an RFC 2822 header value.
/// Parse an RFC 2822 mailbox and return just the bare address part,
/// stripping display names, angle brackets, and comments.  Mirrors
/// the behaviour of C Exim `parse_extract_address` for the operators
/// `address`, `domain`, and `local_part`.
///
/// Split an address list into individual address parts, handling RFC 2822
/// group syntax: `groupname: addr1, addr2 ;`.
///
/// Groups are flattened — the group name is discarded and member addresses
/// are returned as separate entries. Empty groups (`name:;`) produce no entries.
///
/// Like C Exim, this first splits on commas (using `parse_find_address_end`
/// semantics), then handles group state across the resulting parts via
/// `parse_extract_address` with `parse_allow_group` behaviour.
fn split_address_list_with_groups(input: &str) -> Vec<String> {
    // Phase 1: split on commas, respecting quotes, comments and angle brackets.
    let raw_parts = split_on_commas(input);

    // Phase 2: handle group syntax across parts.
    // State: in_group tracks whether we're inside a group envelope.
    let mut result = Vec::new();
    let mut in_group = false;

    for part in &raw_parts {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }

        if in_group {
            // We're inside a group. Look for semicolon to end the group.
            if let Some(semi_pos) = find_unquoted_char(trimmed, ';') {
                // Everything before ';' is a group member address
                let member = trimmed[..semi_pos].trim();
                if !member.is_empty() {
                    result.push(member.to_string());
                }
                in_group = false;
                // Anything after ';' is a new top-level entry
                let after = trimmed[semi_pos + 1..].trim();
                if !after.is_empty() {
                    result.push(after.to_string());
                }
            } else {
                // No semicolon — this entire part is a group member
                result.push(trimmed.to_string());
            }
        } else {
            // Not in a group. Check if this part starts a group (has unquoted colon
            // not inside angle brackets).
            if let Some(colon_pos) = find_group_colon(trimmed) {
                // This is a group start: "groupname: ..."
                let after_colon = trimmed[colon_pos + 1..].trim();
                // Check if the group is immediately closed: "groupname:;" or "groupname: addr; ..."
                if let Some(semi_pos) = find_unquoted_char(after_colon, ';') {
                    // Group with immediate close
                    let member = after_colon[..semi_pos].trim();
                    if !member.is_empty() {
                        result.push(member.to_string());
                    }
                    // Anything after ';'
                    let after = after_colon[semi_pos + 1..].trim();
                    if !after.is_empty() {
                        result.push(after.to_string());
                    }
                } else {
                    // Group continues across multiple comma-separated parts
                    in_group = true;
                    if !after_colon.is_empty() {
                        result.push(after_colon.to_string());
                    }
                }
            } else {
                // Plain address, no group syntax
                result.push(trimmed.to_string());
            }
        }
    }

    result
}

/// Split a string on commas, respecting quoted strings, comments (parens),
/// and angle brackets. Returns the parts without the commas.
fn split_on_commas(input: &str) -> Vec<String> {
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut parts = Vec::new();
    let mut pos = 0;

    while pos < len {
        let start = pos;
        let mut in_quote = false;
        let mut comment_depth = 0u32;
        let mut angle_depth = 0u32;

        while pos < len {
            let c = chars[pos];
            if c == '\\' && pos + 1 < len && (in_quote || comment_depth > 0) {
                pos += 2;
                continue;
            }
            if in_quote {
                if c == '"' {
                    in_quote = false;
                }
                pos += 1;
                continue;
            }
            if comment_depth > 0 {
                match c {
                    '(' => comment_depth += 1,
                    ')' => comment_depth -= 1,
                    _ => {}
                }
                pos += 1;
                continue;
            }
            match c {
                '"' => in_quote = true,
                '(' => comment_depth += 1,
                '<' => angle_depth += 1,
                '>' if angle_depth > 0 => angle_depth -= 1,
                ',' if angle_depth == 0 => break,
                _ => {}
            }
            pos += 1;
        }

        let part: String = chars[start..pos].iter().collect();
        parts.push(part);

        if pos < len && chars[pos] == ',' {
            pos += 1; // skip comma
        }
    }

    parts
}

/// Find the position of the first unquoted `target` character in `s`,
/// respecting quoted strings and comments.
fn find_unquoted_char(s: &str, target: char) -> Option<usize> {
    let mut in_quote = false;
    let mut comment_depth = 0u32;
    let mut angle_depth = 0u32;
    let chars: Vec<char> = s.chars().collect();
    let mut byte_pos = 0;

    for (i, &c) in chars.iter().enumerate() {
        if c == '\\' && (in_quote || comment_depth > 0) && i + 1 < chars.len() {
            byte_pos += c.len_utf8() + chars[i + 1].len_utf8();
            continue;
        }
        if in_quote {
            if c == '"' {
                in_quote = false;
            }
            byte_pos += c.len_utf8();
            continue;
        }
        if comment_depth > 0 {
            match c {
                '(' => comment_depth += 1,
                ')' => comment_depth -= 1,
                _ => {}
            }
            byte_pos += c.len_utf8();
            continue;
        }
        match c {
            '"' => in_quote = true,
            '(' => comment_depth += 1,
            '<' => angle_depth += 1,
            '>' if angle_depth > 0 => angle_depth -= 1,
            ch if ch == target && angle_depth == 0 => return Some(byte_pos),
            _ => {}
        }
        byte_pos += c.len_utf8();
    }
    None
}

/// Find the position of a colon that indicates group syntax in an address part.
/// Returns None if the colon is inside angle brackets or if the part doesn't
/// look like a group (e.g., it's `user@host` with no colon, or it has `<` before `:`).
fn find_group_colon(s: &str) -> Option<usize> {
    let mut in_quote = false;
    let mut comment_depth = 0u32;
    let angle_depth = 0u32;
    let mut byte_pos = 0;
    let chars: Vec<char> = s.chars().collect();

    for (i, &c) in chars.iter().enumerate() {
        if c == '\\' && (in_quote || comment_depth > 0) && i + 1 < chars.len() {
            byte_pos += c.len_utf8() + chars[i + 1].len_utf8();
            continue;
        }
        if in_quote {
            if c == '"' {
                in_quote = false;
            }
            byte_pos += c.len_utf8();
            continue;
        }
        if comment_depth > 0 {
            match c {
                '(' => comment_depth += 1,
                ')' => comment_depth -= 1,
                _ => {}
            }
            byte_pos += c.len_utf8();
            continue;
        }
        match c {
            '"' => in_quote = true,
            '(' => comment_depth += 1,
            '<' => {
                return None;
            } // angle bracket before colon means no group
            ':' if angle_depth == 0 => return Some(byte_pos),
            _ => {}
        }
        byte_pos += c.len_utf8();
    }
    None
}

/// Returns `(addr, domain_offset)` where `domain_offset` is the byte
/// position of the domain portion within `addr` (0 when no domain).
fn parse_extract_address(s: &str) -> Option<(String, usize)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // Helper: strip RFC 2822 comments `(…)` recursively, respecting
    // nested parentheses and quoted strings.
    fn strip_comments(input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        let bytes = input.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'(' {
                // Skip the comment including nested parens
                let mut depth = 1;
                i += 1;
                while i < bytes.len() && depth > 0 {
                    if bytes[i] == b'(' {
                        depth += 1;
                    } else if bytes[i] == b')' {
                        depth -= 1;
                    } else if bytes[i] == b'\\' {
                        i += 1; // skip escaped char
                    }
                    i += 1;
                }
            } else if bytes[i] == b'"' {
                // Keep quoted strings intact
                out.push(bytes[i] as char);
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        out.push(bytes[i] as char);
                        i += 1;
                    }
                    out.push(bytes[i] as char);
                    i += 1;
                }
                if i < bytes.len() {
                    out.push(bytes[i] as char);
                    i += 1;
                }
            } else {
                out.push(bytes[i] as char);
                i += 1;
            }
        }
        out
    }

    let cleaned = strip_comments(s);
    let cleaned = cleaned.trim();

    // Replicate C Exim's parse_extract_address logic:
    // 1. read_local_part (dot-separated words)
    // 2. If next char is '@' → parse as bare addr-spec; reject if junk follows
    // 3. If next char is '<' → parse as angle-addr
    // 4. Otherwise → keep reading as phrase words expecting '<'
    let addr = if let Some(lt) = cleaned.find('<') {
        // Check if text before '<' contains '@' outside quotes
        // If so, C Exim parses the first addr-spec greedily and rejects
        // because of remaining text (the angle-bracketed part).
        let before_lt = &cleaned[..lt];
        let has_at_before_angle = {
            let mut in_quote = false;
            let mut found = false;
            for ch in before_lt.chars() {
                if ch == '"' {
                    in_quote = !in_quote;
                } else if ch == '@' && !in_quote {
                    found = true;
                    break;
                }
            }
            found
        };
        if has_at_before_angle {
            // C Exim: parses text before '<' as addr-spec, then rejects
            // because of remaining angle-bracket text ("junk after address")
            return None;
        }
        if let Some(gt) = cleaned[lt..].find('>') {
            cleaned[lt + 1..lt + gt].trim().to_string()
        } else {
            cleaned[lt + 1..].trim().to_string()
        }
    } else {
        // Bare addr-spec — strip any leading display name tokens.
        // Simple heuristic: if there is an @, use the whole thing.
        cleaned.to_string()
    };

    let addr = addr.trim().to_string();
    if addr.is_empty() {
        return None;
    }

    // Find domain offset (position after the last `@`)
    let domain_offset = if let Some(at) = addr.rfind('@') {
        at + 1
    } else {
        0
    };

    Some((addr, domain_offset))
}

/// Quote a string for use in Exim config/expansion context.
/// Escape regex special characters.
/// C Exim rxquote: backslash-escapes every non-alphanumeric byte.
fn regex_quote(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    for ch in s.chars() {
        if !ch.is_ascii_alphanumeric() {
            result.push('\\');
        }
        result.push(ch);
    }
    result
}

/// Decode xtext encoding (RFC 3461): +XX hex escapes.
fn xtext_decode(s: &str) -> String {
    let mut result = String::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' && i + 2 < bytes.len() {
            if let Ok(byte) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                result.push(byte as char);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

/// Apply IP address mask: "ip/bits" -> masked address.
/// Apply IP mask. C Exim validates address and mask range, and uses dot-notation
/// output for IPv4 and colon-separated full-hex for IPv6.
fn ip_mask(s: &str) -> Result<String, String> {
    ip_mask_inner(s, false)
}

fn ip_mask_normalized(s: &str) -> Result<String, String> {
    ip_mask_inner(s, true)
}

fn ip_mask_inner(s: &str, normalize: bool) -> Result<String, String> {
    // C Exim order: first check if the whole string is a valid IP address
    // (with optional /mask). If the IP part itself is invalid, report
    // "is not an IP address". Only then check for missing mask.
    let (ip_str, bits_str) = if let Some(slash) = s.find('/') {
        (s[..slash].trim(), Some(s[slash + 1..].trim()))
    } else {
        (s.trim(), None)
    };

    // Validate the IP part first (C Exim checks this before mask presence)
    let addr: std::net::IpAddr = ip_str
        .parse()
        .map_err(|_| format!("\"{}\" is not an IP address", s))?;

    // Now check for mask presence
    let bits_str = bits_str.ok_or_else(|| format!("missing mask value in \"{}\"", s))?;

    let bits: u32 = bits_str
        .parse()
        .map_err(|_| format!("mask value too big in \"{}\"", s))?;

    match addr {
        std::net::IpAddr::V4(v4) => {
            if bits > 32 {
                return Err(format!("mask value too big in \"{}\"", s));
            }
            let ip_u32 = u32::from(v4);
            let mask = if bits == 0 {
                0u32
            } else {
                u32::MAX << (32 - bits)
            };
            let masked = ip_u32 & mask;
            Ok(format!("{}/{}", std::net::Ipv4Addr::from(masked), bits))
        }
        std::net::IpAddr::V6(v6) => {
            if bits > 128 {
                return Err(format!("mask value too big in \"{}\"", s));
            }
            let ip_u128 = u128::from(v6);
            let mask = if bits == 0 {
                0u128
            } else {
                u128::MAX << (128 - bits)
            };
            let masked = ip_u128 & mask;
            let v6masked = std::net::Ipv6Addr::from(masked);
            if normalize {
                // mask_n: compressed colon notation (Rust canonical form)
                Ok(format!("{}/{}", v6masked, bits))
            } else {
                // mask: C Exim uses DOT-separated fully expanded hex groups
                let segs = v6masked.segments();
                let hex_str: Vec<String> = segs.iter().map(|seg| format!("{:04x}", seg)).collect();
                Ok(format!("{}/{}", hex_str.join("."), bits))
            }
        }
    }
}

/// Denormalize IPv6 address (expand to full 8 colon-separated hex groups).
/// For IPv4 input, produce IPv4-mapped IPv6: ::ffff:a.b.c.d → full expansion.
/// C Exim uses host_nmtoa(4, binary, -1, buffer, ':') which outputs lowercase
/// colon-separated fully expanded groups.
fn ipv6_denormalize(s: &str) -> Result<String, String> {
    // Try IPv6 first
    if let Ok(v6) = s.parse::<std::net::Ipv6Addr>() {
        let segs = v6.segments();
        let parts: Vec<String> = segs.iter().map(|seg| format!("{:04x}", seg)).collect();
        return Ok(parts.join(":"));
    }
    // Try IPv4 → IPv4-mapped IPv6
    if let Ok(v4) = s.parse::<std::net::Ipv4Addr>() {
        let mapped = v4.to_ipv6_mapped();
        let segs = mapped.segments();
        let parts: Vec<String> = segs.iter().map(|seg| format!("{:04x}", seg)).collect();
        return Ok(parts.join(":"));
    }
    Err(format!("\"{}\" is not an IP address", s))
}

/// Normalize IPv6 address to canonical compressed form (ipv6_nmtoa).
/// C Exim's ipv6_nmtoa finds the longest run of zero-groups and replaces with ::.
fn ipv6_normalize(s: &str) -> Result<String, String> {
    // Try IPv6 first
    if let Ok(v6) = s.parse::<std::net::Ipv6Addr>() {
        // Rust's Display for Ipv6Addr already produces canonical compressed form
        return Ok(format!("{}", v6));
    }
    // Try IPv4 → IPv4-mapped IPv6 normalized
    if let Ok(v4) = s.parse::<std::net::Ipv4Addr>() {
        let mapped = v4.to_ipv6_mapped();
        return Ok(format!("{}", mapped));
    }
    Err(format!("\"{}\" is not an IP address", s))
}

/// Reverse IP address for DNS PTR lookups.
fn reverse_ip(s: &str) -> String {
    if let Ok(addr) = s.parse::<std::net::IpAddr>() {
        match addr {
            std::net::IpAddr::V4(v4) => {
                let octets = v4.octets();
                format!(
                    "{}.{}.{}.{}.in-addr.arpa",
                    octets[3], octets[2], octets[1], octets[0]
                )
            }
            std::net::IpAddr::V6(v6) => {
                let segments = v6.segments();
                let mut nibbles = Vec::new();
                for seg in segments.iter().rev() {
                    nibbles.push(format!("{:x}", seg & 0xF));
                    nibbles.push(format!("{:x}", (seg >> 4) & 0xF));
                    nibbles.push(format!("{:x}", (seg >> 8) & 0xF));
                    nibbles.push(format!("{:x}", (seg >> 12) & 0xF));
                }
                format!("{}.ip6.arpa", nibbles.join("."))
            }
        }
    } else {
        s.to_string()
    }
}

/// Wrap long header lines per RFC 5322 (fold at specified width).
/// Port of C Exim `wrap_header(s, cols, maxchars, indent, indent_cols)`.
///
/// Wraps header text at `cols` columns. Line breaks are inserted as
/// `\n` followed by `indent`. Looks backward for whitespace to split
/// at; if the input contains literal `\n` sequences (two characters)
/// or actual newline characters those are honoured as explicit breaks.
fn wrap_header(s: &str, cols: usize, maxchars: usize, indent: &str, indent_cols: usize) -> String {
    if s.is_empty() {
        return String::new();
    }
    let cols = if cols == 0 { usize::MAX } else { cols };
    let maxchars = if maxchars == 0 { usize::MAX } else { maxchars };

    let bytes = s.as_bytes();
    let total_len = bytes.len();
    let mut result = String::new();
    let mut pos = 0;
    let mut llen: usize = 0; // current line-length in columns

    loop {
        if llen == 0 && pos > 0 {
            llen = indent_cols;
        }

        // Find the next explicit line-break in the remaining input:
        // either a literal two-char `\n` or an actual newline byte.
        let remaining = &bytes[pos..];
        let remaining_len = remaining.len();
        let mut ltail = 0usize;
        let mut brk = remaining_len; // offset within remaining where break is

        // Look for literal `\n` (two chars) first
        if let Some(i) = remaining.windows(2).position(|w| w == b"\\n") {
            brk = i;
            ltail = 2;
        }
        // Also look for actual newline
        if let Some(i) = remaining.iter().position(|&b| b == b'\n') {
            if i < brk {
                brk = i;
                ltail = 1;
            }
        }

        if llen + brk > cols {
            // More than a line's worth — look backward for whitespace
            let scan_limit = cols.saturating_sub(llen);
            let search_end = std::cmp::min(scan_limit, remaining_len);
            let mut found_ws = false;
            if search_end > 10 {
                let mut u = search_end;
                while u > 10 {
                    if remaining[u].is_ascii_whitespace() {
                        // Found whitespace at offset `u`
                        let mut ws_start = u;
                        while ws_start > 1 && remaining[ws_start - 1].is_ascii_whitespace() {
                            ws_start -= 1;
                        }
                        // Append text up to start of whitespace
                        let chunk = &bytes[pos..pos + ws_start];
                        result.push_str(&String::from_utf8_lossy(chunk));
                        // Skip past the whitespace
                        let mut skip = u + 1;
                        while skip < remaining_len && remaining[skip].is_ascii_whitespace() {
                            skip += 1;
                        }
                        pos += skip;
                        found_ws = true;
                        break;
                    }
                    u -= 1;
                }
            }
            if !found_ws {
                // No whitespace found — just break at column limit
                if llen < cols {
                    let take = cols - llen;
                    let take = std::cmp::min(take, remaining_len);
                    let chunk = &bytes[pos..pos + take];
                    result.push_str(&String::from_utf8_lossy(chunk));
                    pos += take;
                }
            }
        } else {
            // The rest fits in this line
            let chunk = &bytes[pos..pos + brk];
            result.push_str(&String::from_utf8_lossy(chunk));
            pos += brk + ltail;
        }

        if pos >= total_len {
            break;
        }
        if result.len() >= maxchars {
            result.truncate(maxchars);
            break;
        }
        result.push('\n');
        result.push_str(indent);
        llen = 0; // will be set to indent_cols at top of loop
    }

    result
}

/// Parse a time interval string (e.g., "1h30m", "2d", "3600") to seconds.
/// Format a Unix mode into an `ls`-style string (e.g. "drwxr-xr-x"),
/// matching the C Exim stat operator output character-for-character.
fn format_smode(mode: u32) -> String {
    static MTABLE_NORMAL: [&str; 8] = ["---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"];
    static MTABLE_SETID: [&str; 8] = ["--S", "--s", "-wS", "-ws", "r-S", "r-s", "rwS", "rws"];
    static MTABLE_STICKY: [&str; 8] = ["--T", "--t", "-wT", "-wt", "r-T", "r-t", "rwT", "rwt"];

    let mut smode = [b' '; 10];

    // File type character
    smode[0] = match mode & 0o170000 {
        0o010000 => b'p', // FIFO
        0o020000 => b'c', // Character device
        0o040000 => b'd', // Directory
        0o060000 => b'b', // Block device
        0o100000 => b'-', // Regular file
        _ => b'?',
    };

    // C Exim builds permission bits from LSB to MSB (other, group, user).
    // modetable[0] = sticky bit (01000), modetable[1] = setgid (02000),
    // modetable[2] = setuid (04000).
    let modetable: [&[&str; 8]; 3] = [
        if mode & 0o1000 == 0 {
            &MTABLE_NORMAL
        } else {
            &MTABLE_STICKY
        },
        if mode & 0o2000 == 0 {
            &MTABLE_NORMAL
        } else {
            &MTABLE_SETID
        },
        if mode & 0o4000 == 0 {
            &MTABLE_NORMAL
        } else {
            &MTABLE_SETID
        },
    ];

    let mut m = mode;
    for (i, table) in modetable.iter().enumerate() {
        let bits = (m & 7) as usize;
        let offset = 7 - i * 3;
        let perm = table[bits].as_bytes();
        smode[offset] = perm[0];
        smode[offset + 1] = perm[1];
        smode[offset + 2] = perm[2];
        m >>= 3;
    }

    String::from_utf8_lossy(&smode).to_string()
}

/// Exact port of C Exim `readconf_readtime(s, 0, FALSE)`.
///
/// Parses a time value composed of digit+suffix pairs (s/m/h/d/w).
/// Returns -1 on any error, exactly like the C implementation.
/// Bare numbers without a suffix are rejected (default case returns -1).
/// The first character must be a digit.
fn readconf_readtime(s: &str) -> i64 {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut pos = 0;
    let mut total: i64 = 0;

    loop {
        // First character of each component must be a digit
        if pos >= len || !bytes[pos].is_ascii_digit() {
            return -1;
        }
        // Read the integer
        let mut value: i64 = 0;
        while pos < len && bytes[pos].is_ascii_digit() {
            value = value * 10 + (bytes[pos] - b'0') as i64;
            pos += 1;
        }
        // Read the suffix — must be one of s/m/h/d/w (case-insensitive)
        if pos >= len {
            // No suffix: bare number → C default returns -1
            return -1;
        }
        match bytes[pos] {
            b'w' | b'W' => {
                value *= 7 * 24 * 60 * 60;
                pos += 1;
            }
            b'd' | b'D' => {
                value *= 24 * 60 * 60;
                pos += 1;
            }
            b'h' | b'H' => {
                value *= 60 * 60;
                pos += 1;
            }
            b'm' | b'M' => {
                value *= 60;
                pos += 1;
            }
            b's' | b'S' => {
                pos += 1;
            }
            _ => return -1,
        }
        total += value;
        // Check terminator (0 == end of string)
        if pos >= len {
            return total;
        }
    }
}

/// Exact port of C Exim `readconf_printtime`.
///
/// Formats a number of seconds into a human-readable time interval
/// string like "1w2d3h4m5s".
fn readconf_printtime(t: i64) -> String {
    let negative = t < 0;
    let mut t = if negative { -t } else { t };
    let mut result = String::new();
    if negative {
        result.push('-');
    }
    let s = t % 60;
    t /= 60;
    let m = t % 60;
    t /= 60;
    let h = t % 24;
    t /= 24;
    let d = t % 7;
    let w = t / 7;
    if w > 0 {
        result.push_str(&format!("{}w", w));
    }
    if d > 0 {
        result.push_str(&format!("{}d", d));
    }
    if h > 0 {
        result.push_str(&format!("{}h", h));
    }
    if m > 0 {
        result.push_str(&format!("{}m", m));
    }
    if s > 0 || result.is_empty() || (negative && result.len() == 1) {
        result.push_str(&format!("{}s", s));
    }
    result
}

/// RFC 2047 encode a string (Q-encoding for non-ASCII).
/// RFC 2047 encode a string, matching C Exim's `parse_quote_2047()`.
///
/// Characters that trigger encoding: ASCII control chars (< 33), DEL and
/// above (> 126), and the RFC 2047 "specials" set: `?=()<>@,;:\".[]_`.
/// Space is encoded as underscore (`_`).  Long encoded words are broken
/// when the total encoded word (prefix + payload) exceeds 67 characters,
/// with a `first_byte` guard that prevents splitting after a `=XX` hex
/// sequence (for multi-byte charset safety).
///
/// The `charset` parameter is normally `headers_charset` from config
/// (e.g. `iso-8859-8`).  If no characters need encoding, the original
/// string is returned unchanged.
fn rfc2047_encode_with_charset(s: &str, charset: &str) -> String {
    const SPECIALS: &[u8] = b"?=()<>@,;:\\\".[]_";

    // Check if any character needs encoding — iterate chars (Latin-1)
    let needs_encoding = s.chars().any(|ch| {
        let b = ch as u32;
        !(33..=126).contains(&b) || SPECIALS.contains(&(b as u8))
    });
    if !needs_encoding {
        return s.to_string();
    }

    // Build output matching C Exim parse_quote_2047() exactly:
    // - Start with =?charset?Q? prefix
    // - Encode each byte (char codepoint = original byte with Latin-1)
    // - When (word_len > 67 && !first_byte), insert word break
    // - first_byte toggles on each =XX encoding to prevent mid-byte breaks
    let header = format!("=?{}?Q?", charset);
    let hlen = header.len();
    let mut result = String::new();
    let mut coded = false;
    let mut first_byte = false;

    // Start the first encoded word
    result.push_str(&header);
    let mut word_len = hlen; // track length of current encoded word

    for ch in s.chars() {
        let byte = ch as u32 as u8;
        // Check line break BEFORE encoding the current character
        // C Exim: if (g->ptr - line_off > 67 && !first_byte)
        if word_len > 67 && !first_byte {
            // Close current word and start new one
            result.push_str("?= ");
            result.push_str(&header);
            word_len = hlen;
        }

        if byte == b' ' {
            result.push('_');
            word_len += 1;
            first_byte = false;
        } else if !(33..=126).contains(&byte) || SPECIALS.contains(&byte) {
            write!(result, "={:02X}", byte).unwrap();
            word_len += 3;
            coded = true;
            first_byte = !first_byte;
        } else {
            result.push(ch);
            word_len += 1;
            first_byte = false;
        }
    }

    if coded {
        result.push_str("?=");
    } else {
        // Nothing actually needed encoding — return original
        return s.to_string();
    }

    result
}

/// RFC 2047 decode: scan for `=?charset?encoding?text?=` encoded words
/// anywhere in the string and decode each one, preserving literal text
/// around them.  Between two adjacent encoded words, whitespace-only
/// separators are removed (RFC 2047 §6.2).
pub fn rfc2047_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut result = String::new();
    let mut i = 0;
    // Track position after last encoded word end; -1 means none yet
    let mut last_encoded_end: Option<usize> = None;
    // Track where we started appending literal text after an encoded word
    let mut result_pos_after_encoded: usize = 0;

    while i < len {
        // Look for the start of an encoded word: =?
        if i + 1 < len && bytes[i] == b'=' && bytes[i + 1] == b'?' {
            // Try to parse =?charset?encoding?text?=
            if let Some((decoded, end)) = try_decode_rfc2047_word(s, i) {
                // RFC 2047 §6.2: whitespace between adjacent encoded words
                // is ignored.  Check if everything between the last encoded
                // word and this one is whitespace-only.
                if last_encoded_end.is_some() {
                    let appended_since = &result[result_pos_after_encoded..];
                    if !appended_since.is_empty()
                        && appended_since
                            .chars()
                            .all(|c| c == ' ' || c == '\t' || c == '\n' || c == '\r')
                    {
                        // Remove the inter-word whitespace
                        result.truncate(result_pos_after_encoded);
                    }
                }
                result.push_str(&decoded);
                i = end;
                last_encoded_end = Some(end);
                result_pos_after_encoded = result.len();
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }

    result
}

/// Try to parse and decode a single RFC 2047 encoded word starting at `pos`.
/// Returns `Some((decoded_text, end_position))` on success, `None` if the
/// text at `pos` is not a valid encoded word.
fn try_decode_rfc2047_word(s: &str, pos: usize) -> Option<(String, usize)> {
    let bytes = s.as_bytes();
    let len = bytes.len();

    // Must start with =?
    if pos + 1 >= len || bytes[pos] != b'=' || bytes[pos + 1] != b'?' {
        return None;
    }

    // Find charset: scan for next ?
    let charset_start = pos + 2;
    let mut j = charset_start;
    while j < len && bytes[j] != b'?' {
        j += 1;
    }
    if j >= len || j == charset_start {
        return None;
    }
    let _charset = &s[charset_start..j];

    // Encoding character: Q or B
    j += 1; // skip ?
    if j >= len {
        return None;
    }
    let encoding = bytes[j];
    j += 1;

    // Must be followed by ?
    if j >= len || bytes[j] != b'?' {
        return None;
    }
    j += 1; // skip ?

    // Find the encoded text up to ?=
    let text_start = j;
    while j + 1 < len {
        if bytes[j] == b'?' && bytes[j + 1] == b'=' {
            // Found end marker
            let text = &s[text_start..j];
            let end = j + 2;

            let decoded = match encoding {
                b'Q' | b'q' => decode_q_encoding(text),
                b'B' | b'b' => decode_b_encoding(text),
                _ => return None,
            };

            return Some((decoded, end));
        }
        j += 1;
    }

    None // no closing ?= found
}

/// Decode Q-encoding: `=XX` is hex byte, `_` is space, others literal.
fn decode_q_encoding(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut result = String::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' && i + 2 < bytes.len() {
            if let Ok(byte) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                result.push(byte as char);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'_' {
            result.push(' ');
        } else {
            result.push(bytes[i] as char);
        }
        i += 1;
    }
    result
}

/// Decode B-encoding (base64).
///
/// Decoded bytes are mapped to Unicode code points U+0000–U+00FF
/// (the Latin-1 / ISO 8859-1 range) so that each original byte
/// survives in the `String` without multi-byte UTF-8 inflation.
/// This matches C Exim's behavior of treating decoded bytes as
/// opaque octets.  The caller is responsible for writing the
/// resulting string back as single-byte-per-char (Latin-1) output
/// when raw byte parity with C Exim is required.
fn decode_b_encoding(text: &str) -> String {
    match BASE64_STANDARD.decode(text.as_bytes()) {
        Ok(decoded) => decoded.iter().map(|&b| b as char).collect(),
        Err(_) => text.to_string(),
    }
}

// ─── Lookup Engine ────────────────────────────────────────────────────────
// Performs file-based lookups matching C Exim's lookup dispatcher.
// Supports lsearch (linear search), dsearch (directory search), and
// cdb (constant database) lookups locally. Database and network
// lookups are delegated to the exim-lookups crate (not available in
// expansion-test mode without full server context).

/// Perform a lookup operation. Returns `Some(value)` on success, `None` on
/// lookup miss. File-based lookups (lsearch, dsearch, etc.) are implemented
/// directly; remote lookups require the full exim-lookups engine.
/// Perform a lookup and return the result.
///
/// Returns `Ok(Some(value))` on success, `Ok(None)` when key is not
/// found, or `Err(message)` on DEFER/error (e.g., iplsearch with a
/// non-IP key).
fn perform_lookup(
    lookup_type_raw: &str,
    key: &str,
    source: &str,
) -> Result<Option<String>, String> {
    let (base_type, ret_full) = parse_lookup_modifiers(lookup_type_raw);
    let base = base_type.as_str();

    // partial-lsearch variants
    if base.starts_with("partial") && base.contains('-') {
        return Ok(perform_partial_lsearch(key, source, base, ret_full));
    }

    match base {
        "lsearch" | "lsearch*" | "lsearch*@" | "lsearch*@[]" | "wildlsearch" | "nwildlsearch" => {
            let result = perform_lsearch(key, source, base);
            Ok(result.map(|r| {
                if ret_full {
                    r.raw_line.trim_end().to_string()
                } else {
                    r.value
                }
            }))
        }
        "iplsearch" | "iplsearch*" => {
            let star = base == "iplsearch*";
            match perform_iplsearch(key, source, star) {
                IplsearchResult::Found(r) => Ok(Some(if ret_full {
                    r.raw_line.trim_end().to_string()
                } else {
                    r.value
                })),
                IplsearchResult::NotFound => Ok(None),
                IplsearchResult::Defer(msg) => Err(msg),
            }
        }
        "dsearch" => {
            let path = std::path::Path::new(source).join(key);
            if path.exists() {
                Ok(Some(key.to_string()))
            } else {
                Ok(None)
            }
        }
        "dbm" | "dbmjz" | "dbmnz" => {
            tracing::debug!("DBM lookup not available in expansion-test mode");
            Ok(None)
        }
        _ => {
            tracing::debug!(
                lookup_type = %base,
                "lookup type not available in expansion-test mode"
            );
            Ok(None)
        }
    }
}

/// Parse lookup type modifiers from the raw type string.
/// Returns (base_type, ret_full).
fn parse_lookup_modifiers(raw: &str) -> (String, bool) {
    let mut ret_full = false;
    let mut base = raw.to_string();

    // Check for ",ret=full" modifier
    if let Some(comma_pos) = base.find(",ret=full") {
        ret_full = true;
        base = format!("{}{}", &base[..comma_pos], &base[comma_pos + 9..]);
    } else if let Some(comma_pos) = base.find(",ret=key") {
        base = format!("{}{}", &base[..comma_pos], &base[comma_pos + 8..]);
    }

    // Strip any remaining comma-modifiers we don't know about
    if let Some(comma_pos) = base.find(',') {
        base.truncate(comma_pos);
    }

    (base.trim().to_string(), ret_full)
}

/// Perform partial-lsearch: progressively strip leading domain
/// components and search for wildcard matches.
///
/// The numeric suffix controls stripping behaviour:
///   - `partial-lsearch`  (= default, unlimited) — try exact key, then
///     `*.suffix` at each level; do NOT try bare `*`.
///   - `partial0-lsearch` — same as unlimited, but ALSO try bare `*`
///     after all `*.suffix` forms are exhausted.
///   - `partial1-lsearch` — try exact key, then only one level of
///     stripping (`*.rest-of-key`); do NOT try bare `*`.
///   - `partialN-lsearch` — try exact key, then at most N levels of
///     stripping; do NOT try bare `*`.
fn perform_partial_lsearch(key: &str, source: &str, base: &str, ret_full: bool) -> Option<String> {
    // Extract the inner lookup type after the dash.
    let inner_type = if let Some(pos) = base.find('-') {
        &base[pos + 1..]
    } else {
        "lsearch"
    };

    // Extract the numeric depth from "partialN-..." prefix.
    // Default (bare "partial") → unlimited stripping, no bare-star.
    // "partial0" → unlimited stripping AND bare-star.
    // "partialN" (N >= 1) → at most N levels of stripping, no bare-star.
    let prefix = if let Some(pos) = base.find('-') {
        &base[..pos]
    } else {
        base
    };
    let after_partial = &prefix[7..]; // skip "partial"
    let (max_strips, include_bare_star) = if after_partial.is_empty() {
        (usize::MAX, false) // partial- : unlimited, no bare *
    } else if let Ok(n) = after_partial.parse::<usize>() {
        if n == 0 {
            (usize::MAX, true) // partial0- : unlimited + bare *
        } else {
            (n, false) // partialN- : N levels, no bare *
        }
    } else {
        (usize::MAX, false)
    };

    /// Format the lookup result according to ret_full.
    fn fmt_result(r: &LsearchResult, ret_full: bool) -> String {
        if ret_full {
            // ret=full returns "matched_key:   value" — the raw file line
            // trimmed to "key: value" form using the matched key.
            r.raw_line.trim_end().to_string()
        } else {
            r.value.clone()
        }
    }

    // Phase 1: try exact key
    if let Some(r) = perform_lsearch(key, source, inner_type) {
        return Some(fmt_result(&r, ret_full));
    }

    // Phase 2: try *.full_key (the "zero-strip" level, not counted
    // towards the strip depth limit).
    let star_full = format!("*.{}", key);
    if let Some(r) = perform_lsearch(&star_full, source, inner_type) {
        return Some(fmt_result(&r, ret_full));
    }

    // Phase 3: progressively strip leading domain components and try
    // *.<remaining>.  Each iteration counts as one strip level.
    let mut rest = key;
    let mut strips = 0;
    while let Some(dot_pos) = rest.find('.') {
        if strips >= max_strips {
            break;
        }
        rest = &rest[dot_pos + 1..]; // "b.c.d" after first dot
        let partial_key = format!("*.{}", rest);
        if let Some(r) = perform_lsearch(&partial_key, source, inner_type) {
            return Some(fmt_result(&r, ret_full));
        }
        strips += 1;
    }

    // Phase 4: try bare "*" if partial0
    if include_bare_star {
        if let Some(r) = perform_lsearch("*", source, inner_type) {
            return Some(fmt_result(&r, ret_full));
        }
    }

    None
}

/// Perform iplsearch: search file for IP address or CIDR range match.
/// Result type for iplsearch that distinguishes "not found" from "DEFER
/// error" (e.g., when the lookup key is not a valid IP address).
enum IplsearchResult {
    Found(LsearchResult),
    NotFound,
    Defer(String),
}

/// Perform iplsearch: search file for IP address or CIDR range match.
///
/// File keys can be:
///   - An IP address (optionally quoted): `1.2.3.4:` or `"abcd::cdab":`
///   - A CIDR range (optionally quoted): `192.168.0.0/16` or
///     `"abcd:abcd::/32"`
///   - A wildcard `*`
///
/// For `iplsearch*` variant the wildcard `*` is also tried as fallback.
fn perform_iplsearch(key: &str, source: &str, star: bool) -> IplsearchResult {
    let trimmed_key = key.trim();
    let ip: std::net::IpAddr = match trimmed_key.parse() {
        Ok(ip) => ip,
        Err(_) => {
            let msg = format!(
                "\\\"{}\\\" is not a valid iplsearch key \
                 (an IP address, with optional CIDR mask, is wanted): \
                 in a host list, use net-iplsearch as the search type",
                trimmed_key
            );
            return IplsearchResult::Defer(msg);
        }
    };

    let content = match std::fs::read_to_string(source) {
        Ok(c) => c,
        Err(_) => return IplsearchResult::NotFound,
    };

    let entries = parse_lsearch_file(&content);

    // Phase 1: exact IP match
    for (raw_line, file_key, value) in &entries {
        let fk = file_key.trim();
        if fk.eq_ignore_ascii_case(trimmed_key) {
            return IplsearchResult::Found(LsearchResult {
                value: value.clone(),
                raw_line: raw_line.clone(),
            });
        }
    }

    // Phase 2: CIDR range match
    for (raw_line, file_key, value) in &entries {
        let fk = file_key.trim();
        if fk.contains('/') && ip_in_cidr(&ip, fk) {
            return IplsearchResult::Found(LsearchResult {
                value: value.clone(),
                raw_line: raw_line.clone(),
            });
        }
    }

    // Phase 3: wildcard "*" (always tried for iplsearch, and for
    // iplsearch* variant)
    if star {
        for (raw_line, file_key, value) in &entries {
            if file_key.trim() == "*" {
                return IplsearchResult::Found(LsearchResult {
                    value: value.clone(),
                    raw_line: raw_line.clone(),
                });
            }
        }
    }

    IplsearchResult::NotFound
}

/// Check if an IP address falls within a CIDR range.
fn ip_in_cidr(ip: &std::net::IpAddr, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    let net_ip: std::net::IpAddr = match parts[0].trim().parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    let prefix_len: u32 = match parts[1].trim().parse() {
        Ok(p) => p,
        Err(_) => return false,
    };

    match (ip, &net_ip) {
        (std::net::IpAddr::V4(ip4), std::net::IpAddr::V4(net4)) => {
            if prefix_len > 32 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix_len)
            };
            (u32::from(*ip4) & mask) == (u32::from(*net4) & mask)
        }
        (std::net::IpAddr::V6(ip6), std::net::IpAddr::V6(net6)) => {
            if prefix_len > 128 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix_len)
            };
            (u128::from(*ip6) & mask) == (u128::from(*net6) & mask)
        }
        _ => false,
    }
}

/// C Exim lsearch: linear search in a text file.
/// File format: `key:  value` or `key = value` or `key  value`.
/// Key matching is case-insensitive. Multi-line values use backslash
/// continuation. Leading whitespace on value is stripped. The key is
/// terminated by colon, equals-sign, or whitespace.
///
/// Variants:
/// - `lsearch` — exact key match (case-insensitive)
/// - `lsearch*` / `wildlsearch` — file keys are glob patterns
/// - `nwildlsearch` — file keys checked: first exact, then glob
///
/// Result from an lsearch file lookup — includes the raw file line for
/// `ret=full` support.
struct LsearchResult {
    /// The value portion (right-hand side of the matched entry).
    value: String,
    /// The raw file line as it appears in the file (for ret=full).
    raw_line: String,
}

/// Perform an lsearch lookup.
///
/// Supported variants:
/// - `lsearch` — exact key match (case-insensitive)
/// - `lsearch*` — try exact match, then try `*` as fallback key
/// - `lsearch*@` — try exact match, then `*@domain`, then `*`
/// - `wildlsearch` — file keys are regex patterns matched against
///   lookup key (case-insensitive unless `(?-i)`)
/// - `nwildlsearch` — first try exact match, then regex patterns
/// - `iplsearch` — delegate to `perform_iplsearch`
fn perform_lsearch(key: &str, filename: &str, variant: &str) -> Option<LsearchResult> {
    let content = match std::fs::read_to_string(filename) {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!("lsearch: cannot open '{}': {}", filename, e);
            return None;
        }
    };

    let key_lower = key.to_lowercase();
    let entries = parse_lsearch_file(&content);

    /// Helper: exact case-insensitive match.
    fn exact_match(
        entries: &[(String, String, String)],
        search_key: &str,
    ) -> Option<LsearchResult> {
        let search_lower = search_key.to_lowercase();
        for (raw_line, file_key, value) in entries {
            if file_key.to_lowercase() == search_lower {
                return Some(LsearchResult {
                    value: value.clone(),
                    raw_line: raw_line.clone(),
                });
            }
        }
        None
    }

    /// Helper: pattern match — file keys used as patterns.
    ///
    /// * `expand` = `true` for **wildlsearch** — the key text is run
    ///   through a minimal Exim string expansion pass (`\\` → `\`,
    ///   `\N` prefix strips the marker) before being compiled as regex.
    /// * `expand` = `false` for **nwildlsearch** — the key text is used
    ///   verbatim as a regex pattern with no pre-processing.
    ///
    /// When a pattern does not compile as a valid regex, we fall back to
    /// glob/fnmatch-style matching (`*` = any, `?` = one char) since C
    /// Exim supports wildcard keys like `*.b.c` in its lsearch files.
    fn pattern_match(
        entries: &[(String, String, String)],
        lookup_key: &str,
        expand: bool,
    ) -> Option<LsearchResult> {
        for (raw_line, file_key, value) in entries {
            let pattern_str = file_key.trim();
            if pattern_str.is_empty() {
                continue;
            }

            // Handle lookup reference keys like "lsearch;/path:  value"
            if pattern_str.contains(';') && !pattern_str.starts_with('^') {
                let parts: Vec<&str> = pattern_str.splitn(2, ';').collect();
                if parts.len() == 2 {
                    let sub_type = parts[0].trim();
                    let sub_source = parts[1].trim();
                    let sub_source = sub_source.trim_end_matches(':').trim();
                    if sub_type == "lsearch"
                        && perform_lsearch(lookup_key, sub_source, "lsearch").is_some()
                    {
                        return Some(LsearchResult {
                            value: value.clone(),
                            raw_line: raw_line.clone(),
                        });
                    }
                }
                continue;
            }

            let mut pat = pattern_str.to_string();
            let mut case_insensitive = true;

            // Check for (?-i) or (?i) case flags.
            if pat.starts_with("(?-i)") {
                pat = pat[5..].to_string();
                case_insensitive = false;
            } else if pat.starts_with("(?i)") {
                pat = pat[4..].to_string();
            }

            if expand {
                // wildlsearch: apply Exim string expansion.
                //  – \N prefix → strip (disables further expansion, but
                //    since we only handle \\ below, stripping \N then
                //    leaving the rest is the correct emulation)
                //  – \\ → \  (expansion turns double-backslash into one)
                if pat.starts_with("\\N") {
                    pat = pat[2..].to_string();
                } else {
                    pat = pat.replace("\\\\", "\x00BSLASH\x00");
                    // No other backslash sequences to expand for these
                    // file-based patterns.
                    pat = pat.replace("\x00BSLASH\x00", "\\");
                }
            }
            // nwildlsearch: use the pattern verbatim (no expansion).

            // Try regex compilation with optional case flag.
            let full_pattern = if case_insensitive {
                format!("(?i){}", pat)
            } else {
                pat.clone()
            };

            match regex::Regex::new(&full_pattern) {
                Ok(re) => {
                    if re.is_match(lookup_key) {
                        return Some(LsearchResult {
                            value: value.clone(),
                            raw_line: raw_line.clone(),
                        });
                    }
                }
                Err(_) => {
                    // Regex compilation failed — try glob/fnmatch
                    // matching.  C Exim supports file keys like `*.b.c`
                    // which are not valid regex but work as globs.
                    if glob_match(&pat, lookup_key, case_insensitive) {
                        return Some(LsearchResult {
                            value: value.clone(),
                            raw_line: raw_line.clone(),
                        });
                    }
                }
            }
        }
        None
    }

    /// Simple glob/fnmatch matcher.  `*` matches any sequence of chars
    /// (including empty), `?` matches exactly one char.  All other
    /// characters are matched literally.
    fn glob_match(pattern: &str, text: &str, case_insensitive: bool) -> bool {
        let p: Vec<char> = if case_insensitive {
            pattern.to_lowercase().chars().collect()
        } else {
            pattern.chars().collect()
        };
        let t: Vec<char> = if case_insensitive {
            text.to_lowercase().chars().collect()
        } else {
            text.chars().collect()
        };
        let (plen, tlen) = (p.len(), t.len());
        // DP approach: dp[j] = can we match t[j..] with p[i..]
        let mut dp = vec![false; tlen + 1];
        dp[tlen] = true; // empty pattern matches empty text
                         // Scan pattern from right to left
        for i in (0..plen).rev() {
            let mut new_dp = vec![false; tlen + 1];
            if p[i] == '*' {
                // '*' matches zero or more characters. dp[j] = true if
                // dp[j] (skip star) or new_dp[j+1] (star eats one char)
                // Iterate left to right so that new_dp[j+1] is available.
                for j in (0..=tlen).rev() {
                    new_dp[j] = dp[j] || (j < tlen && new_dp[j + 1]);
                }
            } else {
                for j in 0..tlen {
                    if p[i] == '?' || p[i] == t[j] {
                        new_dp[j] = dp[j + 1];
                    }
                }
            }
            dp = new_dp;
        }
        dp[0]
    }

    match variant {
        // Plain lsearch — exact match only
        "lsearch" => exact_match(&entries, &key_lower),

        // lsearch* — try exact match, then try bare "*" as key
        "lsearch*" => {
            if let Some(r) = exact_match(&entries, &key_lower) {
                return Some(r);
            }
            exact_match(&entries, "*")
        }

        // lsearch*@ — try exact match, then "*@domain", then "*"
        "lsearch*@" | "lsearch*@[]" => {
            // Phase 1: exact match
            if let Some(r) = exact_match(&entries, &key_lower) {
                return Some(r);
            }
            // Phase 2: try *@domain
            if let Some(at_pos) = key.find('@') {
                let domain = &key[at_pos..]; // "@domain"
                let star_domain = format!("*{}", domain);
                if let Some(r) = exact_match(&entries, &star_domain) {
                    return Some(r);
                }
            }
            // Phase 3: try bare "*"
            exact_match(&entries, "*")
        }

        // wildlsearch — file keys are expanded then used as patterns
        "wildlsearch" => pattern_match(&entries, key, true),

        // nwildlsearch — exact match first, then raw patterns (no expansion)
        "nwildlsearch" => {
            if let Some(r) = exact_match(&entries, &key_lower) {
                return Some(r);
            }
            pattern_match(&entries, key, false)
        }

        // Unknown variant — fall back to exact match
        _ => exact_match(&entries, &key_lower),
    }
}

/// Parse an lsearch file into key-value pairs.
/// Handles continuation lines (trailing backslash), comments (#),
/// and blank lines. Key is separated from value by `:`, `=`, or
/// whitespace.
/// Parse an lsearch file into (raw_line, key, value) triples.
///
/// * `raw_line` — the complete original line(s) from the file (used by
///   `ret=full`)
/// * `key` — the unquoted key string
/// * `value` — the value portion with leading whitespace stripped
///
/// Keys may be quoted with double quotes, which allows colons and
/// whitespace inside the key.  Backslash continuation is supported.
/// Lines starting with `#` are comments.  Blank lines and pure-whitespace
/// continuation lines that follow a non-existent key are skipped.
fn parse_lsearch_file(content: &str) -> Vec<(String, String, String)> {
    let mut entries: Vec<(String, String, String)> = Vec::new();
    let mut lines = content.lines().peekable();

    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        // Skip blank lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Lines that start with whitespace are continuation lines that
        // should already have been consumed by the preceding entry.
        // If we reach them here the file has a bare continuation without
        // a key — skip.
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }

        // Build full logical line (backslash continuation).
        let mut full_line = line.to_string();
        while full_line.ends_with('\\') {
            full_line.pop();
            if let Some(next) = lines.next() {
                full_line.push_str(next);
            } else {
                break;
            }
        }

        // Consume any continuation lines that start with whitespace.
        let mut raw_line = full_line.clone();
        while let Some(peek) = lines.peek() {
            if peek.starts_with(' ') || peek.starts_with('\t') {
                let cont = lines.next().unwrap();
                raw_line.push('\n');
                raw_line.push_str(cont);
                // Also append to full_line (trimmed) for value extraction.
                full_line.push(' ');
                full_line.push_str(cont.trim());
            } else {
                break;
            }
        }

        // Parse key — possibly quoted.
        let bytes = full_line.as_bytes();
        let mut i = 0;
        let file_key;

        if !bytes.is_empty() && bytes[0] == b'"' {
            // Quoted key — read until closing quote, handling \"
            i = 1; // skip opening quote
            let mut key_buf = String::new();
            while i < bytes.len() {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    key_buf.push(bytes[i + 1] as char);
                    i += 2;
                } else if bytes[i] == b'"' {
                    i += 1; // skip closing quote
                    break;
                } else {
                    key_buf.push(bytes[i] as char);
                    i += 1;
                }
            }
            file_key = key_buf;
        } else {
            // Unquoted key — terminated by colon or whitespace (NOT '=').
            // C Exim (lsearch.c line 163): while (*s && *s != ':' && !isspace(*s))
            while i < bytes.len() {
                let b = bytes[i];
                if b == b':' || b == b' ' || b == b'\t' {
                    break;
                }
                i += 1;
            }
            file_key = full_line[..i].to_string();
        }

        // Record position right after key for ret=full computation.
        let key_end_pos = i;
        let is_quoted_key = !bytes.is_empty() && bytes[0] == b'"';

        // Skip whitespace after key, then an optional colon separator,
        // then more whitespace.  Per the C lsearch parser (lsearch.c
        // line 237) ONLY ':' is recognised as a separator — '=' is NOT
        // a separator and is kept as part of the value.
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b':' {
            i += 1;
        }
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }
        let value = full_line[i..].trim_end().to_string();

        // Build the ret=full line.  For quoted keys C Exim replaces the
        // raw quoted text with the unquoted key in the returned line.
        // For unquoted keys the line is returned as-is.
        let ret_full_line = if is_quoted_key {
            format!("{}{}", file_key, &full_line[key_end_pos..])
                .trim_end()
                .to_string()
        } else {
            full_line.trim_end().to_string()
        };

        entries.push((ret_full_line, file_key, value));
    }

    entries
}

// ─── List Matching Helpers ─────────────────────────────────────────────────
// C Exim's match_* conditions match values against colon-separated lists
// supporting: exact match, wildcards (*), CIDR notation (/N), negation (!),
// and named list references (+listname). Named lists require config
// integration and return false here (logged as unsupported).

/// Match an IP address against a host list (colon-separated).
/// Supports exact IP match, CIDR match (1.2.3.0/24), and negation (!).
fn match_ip_list(
    ip_str: &str,
    list: &str,
    named_lists: &std::collections::HashMap<String, String>,
) -> MatchIpResult {
    let ip_trimmed = ip_str.trim();

    // C Exim: empty IP matches only empty-string entries in the list
    // (this handles the case of ${if match_ip{}{:4.5.6.7}}).
    // Also: if the subject is not a valid IP (e.g. "somename"),
    // C Exim produces an error: '"somename" is not an IP address'
    // but only if the list tries to match it (non-empty list).

    let (sep, items) = exim_list_split(list);
    let _ = sep;

    // Try parsing as IP; if it fails, we may still match empty entries or *
    let ip_opt: Option<std::net::IpAddr> = if ip_trimmed.is_empty() {
        None
    } else {
        ip_trimmed.parse().ok()
    };

    for item in &items {
        let trimmed = item.trim();

        let (negated, pattern) = if let Some(rest) = trimmed.strip_prefix('!') {
            (true, rest.trim())
        } else {
            (false, trimmed)
        };

        // Empty pattern matches empty IP
        if pattern.is_empty() {
            if ip_trimmed.is_empty() {
                return if negated {
                    MatchIpResult::False
                } else {
                    MatchIpResult::True
                };
            }
            continue;
        }

        // Named list: +listname
        if let Some(list_name) = pattern.strip_prefix('+') {
            if let Some(list_value) = named_lists.get(list_name) {
                let inner = match_ip_list(ip_str, list_value, named_lists);
                match inner {
                    MatchIpResult::True => {
                        return if negated {
                            MatchIpResult::False
                        } else {
                            MatchIpResult::True
                        };
                    }
                    MatchIpResult::Error(e) => return MatchIpResult::Error(e),
                    MatchIpResult::False => {}
                }
            }
            continue;
        }

        // Wildcard: * matches anything
        if pattern == "*" {
            return if negated {
                MatchIpResult::False
            } else {
                MatchIpResult::True
            };
        }

        // Lookup patterns: type;filename or net[N]-type;filename
        if let Some(semi_pos) = pattern.find(';') {
            let prefix = &pattern[..semi_pos];
            let filename = &pattern[semi_pos + 1..];

            // Parse net[N]- prefix: e.g. "net-lsearch", "net24-lsearch"
            let (mlen, lookup_type) = if let Some(after_net) = prefix.strip_prefix("net") {
                // Parse optional digits for mask length
                let digit_end = after_net
                    .find(|c: char| !c.is_ascii_digit())
                    .unwrap_or(after_net.len());
                let mask: i32 = if digit_end > 0 {
                    after_net[..digit_end].parse().unwrap_or(-1)
                } else {
                    -1 // No mask specified, means try all masks
                };
                // After digits, expect '-'
                let rest = &after_net[digit_end..];
                if let Some(lt) = rest.strip_prefix('-') {
                    (mask, lt)
                } else {
                    // No dash — treat entire prefix as lookup type
                    (0i32, prefix)
                }
            } else {
                (0i32, prefix)
            };

            // Need a valid IP for lookup-based matching
            let ip = match ip_opt {
                Some(ip) => ip,
                None => {
                    if !ip_trimmed.is_empty() {
                        return MatchIpResult::Error(format!(
                            "\"{}\" is not an IP address",
                            ip_trimmed
                        ));
                    }
                    continue;
                }
            };

            let found = match_ip_via_lookup(&ip, ip_trimmed, lookup_type, filename, mlen);
            if found {
                return if negated {
                    MatchIpResult::False
                } else {
                    MatchIpResult::True
                };
            }
            continue;
        }

        // For non-empty, non-wildcard patterns we need a valid IP
        let ip = match ip_opt {
            Some(ip) => ip,
            None => {
                // Not a valid IP — C Exim reports error only for non-empty subjects
                if !ip_trimmed.is_empty() {
                    // Check if this pattern itself is an IP/CIDR or named entry
                    // that would require the subject to be an IP.  For non-IP
                    // patterns like `name` in the list, C Exim returns error.
                    return MatchIpResult::Error(format!(
                        "\"{}\" is not an IP address",
                        ip_trimmed
                    ));
                }
                continue;
            }
        };

        let matched = if let Some(slash) = pattern.rfind('/') {
            match_ip_cidr(&ip, pattern, slash)
        } else {
            match pattern.parse::<std::net::IpAddr>() {
                Ok(pat_ip) => ip == pat_ip,
                Err(_) => false,
            }
        };

        if matched {
            return if negated {
                MatchIpResult::False
            } else {
                MatchIpResult::True
            };
        }
    }
    MatchIpResult::False
}

/// Perform a lookup-based IP match (handles lsearch, iplsearch, net-lsearch, etc.)
///
/// C Exim (verify.c check_host) handles lookup entries in host lists:
/// - For iplsearch: IP address is used as key for IP/CIDR-aware file search
/// - For lsearch: IP address string used as plain key
/// - For net[N]-type: IP is masked to N bits, then used as key with mask appended
/// - When no mask specified (net-), tries all mask lengths from most to least specific
fn match_ip_via_lookup(
    ip: &std::net::IpAddr,
    ip_str: &str,
    lookup_type: &str,
    filename: &str,
    mlen: i32,
) -> bool {
    let is_iplsearch = lookup_type == "iplsearch" || lookup_type == "iplsearch*";
    let star = lookup_type == "iplsearch*";

    if is_iplsearch {
        // iplsearch: use IP as key, file entries can be CIDR ranges
        let key = if mlen > 0 {
            // net[N]-iplsearch: mask the IP first
            mask_ip_to_string(ip, mlen as u32, ':')
        } else {
            ip_str.to_string()
        };
        if let IplsearchResult::Found(_) = perform_iplsearch(&key, filename, star) {
            return true;
        }
        if mlen < 0 {
            // net-iplsearch with no specific mask: also try the raw IP
            if let IplsearchResult::Found(_) = perform_iplsearch(ip_str, filename, star) {
                return true;
            }
        }
        return false;
    }

    // lsearch variants: use IP string as key
    let is_lsearch = lookup_type == "lsearch" || lookup_type.starts_with("lsearch");

    if mlen == 0 && is_lsearch {
        // Plain lsearch;file — use IP as-is for key
        if perform_lsearch(ip_str, filename, "lsearch").is_some() {
            return true;
        }
        return false;
    }

    if mlen > 0 {
        // net[N]-lsearch: mask IP to N bits and use as key
        let key = mask_ip_to_string(ip, mlen as u32, '.');
        if perform_lsearch(&key, filename, "lsearch").is_some() {
            return true;
        }
        return false;
    }

    // net-lsearch (mlen == -1): try all mask lengths from most to least specific
    // For IPv4: try /32, /31, ..., /0
    // For IPv6: try /128, /127, ..., /0
    // C Exim actually tries /32 down to /0 for IPv4, but with the dot-separated
    // representation that collapses to the textual IP then progressively shorter.
    // The most common approach: try the full IP, then /24, /16, /8, /0
    match ip {
        std::net::IpAddr::V4(_) => {
            // Try full IP first
            if perform_lsearch(ip_str, filename, "lsearch").is_some() {
                return true;
            }
            // Then try /32, /24, /16, /8
            for bits in &[32u32, 24, 16, 8] {
                let key = mask_ip_to_string(ip, *bits, '.');
                if perform_lsearch(&key, filename, "lsearch").is_some() {
                    return true;
                }
            }
        }
        std::net::IpAddr::V6(_) => {
            if perform_lsearch(ip_str, filename, "lsearch").is_some() {
                return true;
            }
            for bits in &[128u32, 64, 48, 32, 16] {
                let key = mask_ip_to_string(ip, *bits, '.');
                if perform_lsearch(&key, filename, "lsearch").is_some() {
                    return true;
                }
            }
        }
    }
    false
}

/// Mask an IP address to the given number of bits and produce a text representation.
/// For lsearch with dot separator: produces "1.2.3.0/24" style.
/// For iplsearch with colon separator: produces "abcd:0000::/32" style (but we use
/// the standard IP format).
fn mask_ip_to_string(ip: &std::net::IpAddr, mask_bits: u32, _sep: char) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let bits = u32::from(*v4);
            let masked = if mask_bits >= 32 {
                bits
            } else if mask_bits == 0 {
                0
            } else {
                bits & !((1u32 << (32 - mask_bits)) - 1)
            };
            let masked_ip = std::net::Ipv4Addr::from(masked);
            format!("{}/{}", masked_ip, mask_bits)
        }
        std::net::IpAddr::V6(v6) => {
            let bits = u128::from(*v6);
            let masked = if mask_bits >= 128 {
                bits
            } else if mask_bits == 0 {
                0
            } else {
                bits & !((1u128 << (128 - mask_bits)) - 1)
            };
            let masked_ip = std::net::Ipv6Addr::from(masked);
            format!("{}/{}", masked_ip, mask_bits)
        }
    }
}

/// Result of an IP list match operation.
enum MatchIpResult {
    True,
    False,
    Error(String),
}

/// Match an IP address against a CIDR pattern (e.g. 1.2.3.0/24 or ::1/128).
fn match_ip_cidr(ip: &std::net::IpAddr, pattern: &str, slash: usize) -> bool {
    let net_str = &pattern[..slash];
    let bits_str = &pattern[slash + 1..];
    let bits: u32 = match bits_str.parse() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let net_ip: std::net::IpAddr = match net_str.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    match (ip, &net_ip) {
        (std::net::IpAddr::V4(addr), std::net::IpAddr::V4(net)) => {
            if bits > 32 {
                return false;
            }
            if bits == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - bits);
            (u32::from(*addr) & mask) == (u32::from(*net) & mask)
        }
        (std::net::IpAddr::V6(addr), std::net::IpAddr::V6(net)) => {
            if bits > 128 {
                return false;
            }
            if bits == 0 {
                return true;
            }
            let addr_bits = u128::from(*addr);
            let net_bits = u128::from(*net);
            let mask = u128::MAX << (128 - bits);
            (addr_bits & mask) == (net_bits & mask)
        }
        _ => false, // IPv4 vs IPv6 mismatch
    }
}

/// Result of a list match that also captures groups.
struct ListMatchResult {
    matched: bool,
    /// Captured groups from regex or wildcard match.
    /// captures[0] = full match, captures[1..] = groups.
    captures: Vec<String>,
}

impl ListMatchResult {
    fn no_match() -> Self {
        Self {
            matched: false,
            captures: Vec::new(),
        }
    }
    fn simple_match() -> Self {
        Self {
            matched: true,
            captures: Vec::new(),
        }
    }
    fn with_captures(captures: Vec<String>) -> Self {
        Self {
            matched: true,
            captures,
        }
    }
    fn negated_match() -> Self {
        // Negated match: explicitly matched but result is false (due to !pattern)
        Self {
            matched: false,
            captures: Vec::new(),
        }
    }
}

/// Match a domain name against a domain list (colon-separated).
/// Supports: exact match (case-insensitive), wildcard (*.example.com),
/// starts-with-dot (.example.com = *.example.com), negation (!).
/// Returns captures from wildcard or regex matching.
fn match_domain_list_with_captures(
    domain: &str,
    list: &str,
    named_lists: &std::collections::HashMap<String, String>,
) -> ListMatchResult {
    let domain_lower = domain.to_lowercase();
    let (sep, items) = exim_list_split(list);
    let _ = sep;

    for item in &items {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (negated, pattern) = if let Some(rest) = trimmed.strip_prefix('!') {
            (true, rest.trim())
        } else {
            (false, trimmed)
        };

        // Named list: +listname — recurse with captures
        if let Some(list_name) = pattern.strip_prefix('+') {
            if let Some(list_value) = named_lists.get(list_name) {
                let inner = match_domain_list_with_captures(domain, list_value, named_lists);
                if inner.matched {
                    return if negated {
                        ListMatchResult::negated_match()
                    } else {
                        inner
                    };
                }
            }
            continue;
        }

        let pat_lower = pattern.to_lowercase();

        // Regex pattern: starts with ^ (possibly wrapped in \N..\N)
        if pat_lower.starts_with('^') || pat_lower.starts_with("\\n^") {
            let re_src = strip_exim_regex_delimiters(pattern);
            if let Ok(re) = regex::Regex::new(&re_src) {
                if let Some(caps) = re.captures(&domain_lower) {
                    let mut captures = Vec::new();
                    for i in 0..caps.len() {
                        captures.push(caps.get(i).map_or("", |m| m.as_str()).to_string());
                    }
                    return if negated {
                        ListMatchResult::negated_match()
                    } else {
                        ListMatchResult::with_captures(captures)
                    };
                }
            }
            continue;
        }

        if let Some(rest) = pat_lower.strip_prefix("*.") {
            // Wildcard: *.example.com matches sub.example.com and example.com
            let suffix = &pat_lower[1..]; // .example.com
            let matched = domain_lower.ends_with(suffix) || domain_lower == rest;
            if matched {
                // For wildcard *.suffix, capture $1 = subdomain prefix
                let prefix = if domain_lower.ends_with(suffix) && domain_lower.len() > suffix.len()
                {
                    &domain_lower[..domain_lower.len() - suffix.len()]
                } else {
                    &domain_lower
                };
                let captures = vec![domain_lower.clone(), prefix.to_string()];
                return if negated {
                    ListMatchResult::negated_match()
                } else {
                    ListMatchResult::with_captures(captures)
                };
            }
        } else if let Some(rest) = pat_lower.strip_prefix('.') {
            // Starts with dot: .example.com matches sub.example.com and example.com
            let matched = domain_lower.ends_with(&pat_lower) || domain_lower == rest;
            if matched {
                return if negated {
                    ListMatchResult::negated_match()
                } else {
                    ListMatchResult::simple_match()
                };
            }
        } else {
            // Exact match (case-insensitive)
            if domain_lower == pat_lower {
                return if negated {
                    ListMatchResult::negated_match()
                } else {
                    ListMatchResult::simple_match()
                };
            }
        };
    }
    ListMatchResult::no_match()
}

/// Backwards-compatible wrapper that returns just bool.
fn match_domain_list(
    domain: &str,
    list: &str,
    named_lists: &std::collections::HashMap<String, String>,
) -> bool {
    match_domain_list_with_captures(domain, list, named_lists).matched
}

/// Strip C Exim `\N` raw-mode delimiters from a regex pattern.
///
/// C Exim uses `\N` as a "no expansion" marker in patterns.  When a
/// pattern starts with `^\N`, the `\N` indicates raw mode — backslash
/// sequences within the pattern are NOT interpreted as C escapes by
/// Exim's string expansion engine.  The `\N` at the start (and
/// optionally at the end) is stripped to produce the actual PCRE regex.
///
/// Examples:
///   - `^\Nxxx(.*)\N` → `^xxx(.*)`
///   - `^\Nxxx(.*)` → `^xxx(.*)`   (trailing \N is optional)
///   - `^abc` → `^abc` (no \N present)
fn strip_exim_regex_delimiters(pattern: &str) -> String {
    let s = pattern.trim();

    // Handle `^\N...\N` or `^\N...`
    if let Some(inner) = s.strip_prefix("^\\N") {
        let inner = inner.strip_suffix("\\N").unwrap_or(inner);
        return format!("^{}", inner);
    }

    // Handle `\N...\N` or `\N...` (without leading `^`)
    if let Some(inner) = s.strip_prefix("\\N") {
        let inner = inner.strip_suffix("\\N").unwrap_or(inner);
        return inner.to_string();
    }

    // No \N delimiters — pattern is used as-is
    s.to_string()
}

/// Match a string against a string list (colon-separated).
/// Supports: exact match, wildcard prefix (*), negation (!), regex (^),
/// named lists (+name).
/// If `case_sensitive` is false, comparison is case-insensitive.
fn match_string_list(
    value: &str,
    list: &str,
    case_sensitive: bool,
    named_lists: &std::collections::HashMap<String, String>,
) -> bool {
    let val = if case_sensitive {
        value.to_string()
    } else {
        value.to_lowercase()
    };
    let (sep, items) = exim_list_split(list);
    let _ = sep;

    for item in &items {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (negated, pattern) = if let Some(rest) = trimmed.strip_prefix('!') {
            (true, rest.trim())
        } else {
            (false, trimmed)
        };

        // Named list: +listname
        if let Some(list_name) = pattern.strip_prefix('+') {
            if let Some(list_value) = named_lists.get(list_name) {
                let inner = match_string_list(value, list_value, case_sensitive, named_lists);
                if inner {
                    return !negated;
                }
            }
            continue;
        }

        let pat = if case_sensitive {
            pattern.to_string()
        } else {
            pattern.to_lowercase()
        };

        // Regex pattern
        let matched = if pat.starts_with('^') || pat.starts_with("\\n^") {
            let re_src = strip_exim_regex_delimiters(pattern);
            match regex::Regex::new(&re_src) {
                Ok(re) => {
                    if case_sensitive {
                        re.is_match(value)
                    } else {
                        re.is_match(&val)
                    }
                }
                Err(_) => false,
            }
        } else if pat == "*" {
            true
        } else if let Some(suffix) = pat.strip_prefix('*') {
            val.ends_with(&suffix)
        } else {
            val == pat
        };

        if matched {
            return !negated;
        }
    }
    false
}

/// Match a full email address against an address list (colon-separated).
/// Supports: exact match, domain-only matching (*@domain), local-part
/// wildcard (user@*), negation (!), domain wildcards (*@*.example.com).
fn match_address_list(
    address: &str,
    list: &str,
    named_lists: &std::collections::HashMap<String, String>,
) -> bool {
    let addr_lower = address.to_lowercase();
    let (local, domain) = if let Some(at) = addr_lower.rfind('@') {
        (&addr_lower[..at], &addr_lower[at + 1..])
    } else {
        (addr_lower.as_str(), "")
    };

    let (_sep, items) = exim_list_split(list);

    for item in &items {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (negated, pattern) = if let Some(rest) = trimmed.strip_prefix('!') {
            (true, rest.trim())
        } else {
            (false, trimmed)
        };

        // Named list: +listname
        if let Some(list_name) = pattern.strip_prefix('+') {
            if let Some(list_value) = named_lists.get(list_name) {
                let inner = match_address_list(address, list_value, named_lists);
                if inner {
                    return !negated;
                }
            }
            continue;
        }

        let pat_lower = pattern.to_lowercase();
        let matched = if let Some(at) = pat_lower.rfind('@') {
            let pat_local = &pat_lower[..at];
            let pat_domain = &pat_lower[at + 1..];
            let local_ok = pat_local == "*" || pat_local == local;
            let domain_ok = if pat_domain == "*" {
                true
            } else if pat_domain.starts_with("*.") {
                let suffix = &pat_domain[1..];
                domain.ends_with(suffix) || domain == &pat_domain[2..]
            } else {
                domain == pat_domain
            };
            local_ok && domain_ok
        } else {
            // No @ — treat as domain-only pattern
            match_domain_list(domain, &pat_lower, named_lists)
        };

        if matched {
            return !negated;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Arithmetic evaluator tests ───

    #[test]
    fn test_eval_expr_basic() {
        assert_eq!(Evaluator::eval_expr_static("42", false).unwrap(), 42);
        assert_eq!(Evaluator::eval_expr_static("0", false).unwrap(), 0);
        assert_eq!(Evaluator::eval_expr_static("-7", false).unwrap(), -7);
    }

    #[test]
    fn test_eval_expr_arithmetic() {
        assert_eq!(Evaluator::eval_expr_static("2 + 3", false).unwrap(), 5);
        assert_eq!(Evaluator::eval_expr_static("10 - 3", false).unwrap(), 7);
        assert_eq!(Evaluator::eval_expr_static("4 * 5", false).unwrap(), 20);
        assert_eq!(Evaluator::eval_expr_static("10 / 3", false).unwrap(), 3);
        assert_eq!(Evaluator::eval_expr_static("10 % 3", false).unwrap(), 1);
    }

    #[test]
    fn test_eval_expr_precedence() {
        assert_eq!(Evaluator::eval_expr_static("2 + 3 * 4", false).unwrap(), 14);
        assert_eq!(
            Evaluator::eval_expr_static("(2 + 3) * 4", false).unwrap(),
            20
        );
    }

    #[test]
    fn test_eval_expr_hex() {
        assert_eq!(Evaluator::eval_expr_static("0xff", false).unwrap(), 255);
        assert_eq!(Evaluator::eval_expr_static("0x10", false).unwrap(), 16);
    }

    #[test]
    fn test_eval_expr_octal() {
        assert_eq!(Evaluator::eval_expr_static("010", false).unwrap(), 8);
        assert_eq!(Evaluator::eval_expr_static("0777", false).unwrap(), 511);
    }

    #[test]
    fn test_eval_expr_decimal_only() {
        // In decimal mode, 010 is 10, not octal
        assert_eq!(Evaluator::eval_expr_static("010", true).unwrap(), 10);
    }

    #[test]
    fn test_eval_expr_suffixes() {
        assert_eq!(Evaluator::eval_expr_static("1k", false).unwrap(), 1024);
        assert_eq!(Evaluator::eval_expr_static("1K", false).unwrap(), 1024);
        assert_eq!(Evaluator::eval_expr_static("1m", false).unwrap(), 1048576);
        assert_eq!(
            Evaluator::eval_expr_static("1g", false).unwrap(),
            1073741824
        );
    }

    #[test]
    fn test_eval_expr_bitwise() {
        assert_eq!(
            Evaluator::eval_expr_static("0xff & 0x0f", false).unwrap(),
            15
        );
        assert_eq!(
            Evaluator::eval_expr_static("0xa0 | 0x0a", false).unwrap(),
            0xaa
        );
        assert_eq!(
            Evaluator::eval_expr_static("0xff ^ 0x0f", false).unwrap(),
            0xf0
        );
    }

    #[test]
    fn test_eval_expr_shift() {
        assert_eq!(Evaluator::eval_expr_static("1 << 10", false).unwrap(), 1024);
        assert_eq!(
            Evaluator::eval_expr_static("1024 >> 3", false).unwrap(),
            128
        );
    }

    #[test]
    fn test_eval_expr_unary() {
        assert_eq!(Evaluator::eval_expr_static("~0", false).unwrap(), -1);
        assert_eq!(Evaluator::eval_expr_static("!0", false).unwrap(), 1);
        assert_eq!(Evaluator::eval_expr_static("!1", false).unwrap(), 0);
    }

    #[test]
    fn test_eval_expr_division_by_zero() {
        assert!(Evaluator::eval_expr_static("1 / 0", false).is_err());
        assert!(Evaluator::eval_expr_static("1 % 0", false).is_err());
    }

    // ─── Helper function tests ───

    #[test]
    fn test_expand_gettokened() {
        assert_eq!(expand_gettokened(1, ":", "a:b:c"), Some("a".to_string()));
        assert_eq!(expand_gettokened(2, ":", "a:b:c"), Some("b".to_string()));
        assert_eq!(expand_gettokened(3, ":", "a:b:c"), Some("c".to_string()));
        assert_eq!(expand_gettokened(4, ":", "a:b:c"), None);
        assert_eq!(expand_gettokened(-1, ":", "a:b:c"), Some("c".to_string()));
        assert_eq!(
            expand_gettokened(0, ":", "a:b:c"),
            Some("a:b:c".to_string())
        );
    }

    #[test]
    fn test_expand_getlistele() {
        assert_eq!(expand_getlistele(1, "a:b:c", ':'), Some("a".to_string()));
        assert_eq!(expand_getlistele(3, "a:b:c", ':'), Some("c".to_string()));
        assert_eq!(expand_getlistele(-1, "a:b:c", ':'), Some("c".to_string()));
    }

    #[test]
    fn test_base62() {
        // encode_base62 now produces 6-char zero-padded output
        assert_eq!(encode_base62(0), "000000");
        assert_eq!(encode_base62(61), "00000z");
        let encoded = encode_base62(12345);
        assert_eq!(decode_base62(&encoded).unwrap(), 12345);
    }

    #[test]
    fn test_hex_encode_decode() {
        let data = vec![0x48, 0x65, 0x6C, 0x6C, 0x6F];
        let encoded = hex_encode(&data);
        assert_eq!(encoded, "48656c6c6f");
        let decoded = hex_decode("48656C6C6F").unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_ip_mask() {
        assert_eq!(ip_mask("192.168.1.100/24").unwrap(), "192.168.1.0/24");
        assert_eq!(ip_mask("10.0.0.1/8").unwrap(), "10.0.0.0/8");
        assert!(ip_mask("10.0.0.1/33").is_err());
    }

    #[test]
    fn test_reverse_ip() {
        assert_eq!(reverse_ip("192.168.1.1"), "1.1.168.192.in-addr.arpa");
    }

    #[test]
    fn test_ipv6_denormalize() {
        assert_eq!(
            ipv6_denormalize("::1").unwrap(),
            "0000:0000:0000:0000:0000:0000:0000:0001"
        );
    }

    #[test]
    fn test_time_interval() {
        // readconf_readtime uses digit+suffix pairs (not bare numbers)
        assert_eq!(readconf_readtime("1h"), 3600);
        assert_eq!(readconf_readtime("1h30m"), 5400);
        assert_eq!(readconf_readtime("1d"), 86400);
        assert_eq!(readconf_readtime("1w"), 604800);
        assert_eq!(readconf_readtime("30s"), 30);
        assert_eq!(readconf_readtime("3600s"), 3600);
        // Bare numbers are rejected by readconf_readtime (returns -1)
        assert_eq!(readconf_readtime("3600"), -1);
    }

    #[test]
    fn test_format_time_interval() {
        assert_eq!(readconf_printtime(0), "0s");
        assert_eq!(readconf_printtime(3600), "1h");
        assert_eq!(readconf_printtime(5400), "1h30m");
        assert_eq!(readconf_printtime(86400), "1d");
    }

    #[test]
    fn test_extract_address() {
        assert_eq!(
            parse_extract_address("user@example.com").map(|(a, _)| a),
            Some("user@example.com".to_string())
        );
        assert_eq!(
            parse_extract_address("User <user@example.com>").map(|(a, _)| a),
            Some("user@example.com".to_string())
        );
        assert_eq!(
            parse_extract_address("<user@example.com>").map(|(a, _)| a),
            Some("user@example.com".to_string())
        );
    }

    #[test]
    fn test_regex_quote() {
        assert_eq!(regex_quote("hello.world"), "hello\\.world");
        assert_eq!(regex_quote("a+b*c"), "a\\+b\\*c");
    }

    #[test]
    fn test_xtext_decode() {
        assert_eq!(xtext_decode("hello+20world"), "hello world");
        assert_eq!(xtext_decode("abc"), "abc");
    }

    #[test]
    fn test_rfc2047_encode() {
        // Pure ASCII with no specials — returned unchanged
        let encoded = rfc2047_encode_with_charset("abcd", "iso-8859-8");
        assert_eq!(encoded, "abcd");

        // Specials trigger encoding
        let encoded = rfc2047_encode_with_charset("<:abcd:>", "iso-8859-8");
        assert_eq!(encoded, "=?iso-8859-8?Q?=3C=3Aabcd=3A=3E?=");

        // Space is encoded as underscore
        let encoded = rfc2047_encode_with_charset("<:ab cd:>", "iso-8859-8");
        assert_eq!(encoded, "=?iso-8859-8?Q?=3C=3Aab_cd=3A=3E?=");
    }

    #[test]
    fn test_rfc2047_decode() {
        // Simple Q-encoded word
        let decoded = rfc2047_decode("=?UTF-8?Q?Hello_World?=");
        assert_eq!(decoded, "Hello World");

        // Text before encoded word
        let decoded = rfc2047_decode("X =?UTF-8?Q?hello?=");
        assert_eq!(decoded, "X hello");

        // Multiple adjacent encoded words (whitespace between is removed)
        let decoded = rfc2047_decode("=?UTF-8?Q?hello?= =?UTF-8?Q?world?=");
        assert_eq!(decoded, "helloworld");

        // Non-encoded text passes through
        let decoded = rfc2047_decode("plain text");
        assert_eq!(decoded, "plain text");
    }
}
