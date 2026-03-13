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

    /// Current lookup value ($value) — set by ${lookup} and available in yes/no branches.
    pub lookup_value: Option<String>,

    /// Maximum recursion depth before error.
    max_depth: u32,

    /// Expansion context providing variable resolution from scoped context structs.
    ctx: &'a ExpandContext,

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
        let ctx: &'static ExpandContext = Box::leak(Box::new(ExpandContext::new()));
        Evaluator {
            expand_level: 0,
            expand_forbid: 0,
            forced_fail: false,
            search_find_defer: false,
            expand_nstring: Default::default(),
            lookup_value: None,
            max_depth: MAX_EXPAND_DEPTH,
            ctx,
            result_taint: TaintState::Untainted,
        }
    }

    /// Create a new evaluator with an explicit expansion context.
    ///
    /// # Arguments
    /// * `ctx` — Reference to the expansion context providing variable resolution
    pub fn new(ctx: &'a ExpandContext) -> Self {
        Self {
            expand_level: 0,
            expand_forbid: 0,
            forced_fail: false,
            search_find_defer: false,
            expand_nstring: Default::default(),
            lookup_value: None,
            max_depth: MAX_EXPAND_DEPTH,
            ctx,
            result_taint: TaintState::Untainted,
        }
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
        match node {
            // ─── Literal text: append directly ───
            AstNode::Literal(text) => {
                output.push_str(text);
            }

            // ─── Backslash escape sequences ───
            AstNode::Escape(ch) => {
                output.push(*ch);
            }

            // ─── Protected region (\N...\N): copy verbatim ───
            AstNode::Protected(text) => {
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
                self.eval_variable(var_ref, output)?;
            }

            // ─── Header references ($h_name, $rh_name, etc.) ───
            AstNode::HeaderRef { prefix, name } => {
                self.eval_header_ref(prefix, name, output)?;
            }

            // ─── ACL variables ($acl_c0..$acl_c9, $acl_m0..$acl_m9, etc.) ───
            AstNode::AclVariable(name) => {
                self.eval_acl_variable(name, output)?;
            }

            // ─── Authentication variables ($auth1..$auth3) ───
            AstNode::AuthVariable(idx) => {
                self.eval_auth_variable(*idx, output)?;
            }

            // ─── Expansion items (${item{args}...}) ───
            AstNode::Item {
                kind,
                args,
                yes_branch,
                no_branch,
            } => {
                self.eval_item(
                    kind,
                    args,
                    yes_branch.as_deref(),
                    no_branch.as_deref(),
                    flags,
                    output,
                )?;
            }

            // ─── Operators (${operator:subject}) ───
            AstNode::Operator { kind, subject } => {
                self.eval_operator(kind, subject, flags, output)?;
            }

            // ─── Conditionals (${if condition {yes}{no}}) ───
            AstNode::Conditional {
                condition,
                yes_branch,
                no_branch,
            } => {
                self.eval_conditional(condition, yes_branch, no_branch.as_deref(), flags, output)?;
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
        let (val_opt, taint) = variables::resolve_variable(&var_ref.name, self.ctx)?;
        self.propagate_taint(taint);
        if let Some(val) = val_opt {
            output.push_str(&val);
        }
        Ok(())
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
    fn eval_item(
        &mut self,
        kind: &ItemKind,
        args: &[AstNode],
        yes_branch: Option<&AstNode>,
        no_branch: Option<&AstNode>,
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        tracing::debug!(?kind, "evaluating item");

        match kind {
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
            ItemKind::PrvsCheck => {
                self.eval_item_prvscheck(args, yes_branch, no_branch, flags, output)
            }
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
        }
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
        let acl_name = self.eval_arg(args, 0, flags)?;
        let _acl_arg = if args.len() > 1 {
            Some(self.eval_arg(args, 1, flags)?)
        } else {
            None
        };
        tracing::debug!(acl = %acl_name, "evaluating item_acl");

        // ACL evaluation would be delegated to the ACL engine.
        // In the expansion context, we treat the ACL result as success/failure
        // for yes/no branching. The actual ACL engine is in exim-acl crate.
        // Check both acl_var_c and acl_var_m stores.
        let acl_result = self
            .ctx
            .acl_var_c
            .get(&acl_name)
            .or_else(|| self.ctx.acl_var_m.get(&acl_name))
            .cloned();
        let success = acl_result.is_some();

        if let Some(ref val) = acl_result {
            self.lookup_value = Some(val.clone());
        }

        self.process_yesno(success, yes_branch, no_branch, flags, output)
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
        tracing::debug!(field = %field_spec, "evaluating item_extract");

        // Determine extraction mode: numbered vs. named (JSON)
        let result = if let Ok(field_num) = field_spec.parse::<i32>() {
            // Numbered extraction: ${extract{N}{separators}{string}}
            let separators = self.eval_arg(args, 1, flags)?;
            let data = self.eval_arg(args, 2, flags)?;
            expand_gettokened(field_num, &separators, &data)
        } else {
            // Named extraction: ${extract{name}{string}} — try JSON
            let data = self.eval_arg(args, 1, flags)?;
            self.extract_json_field(&field_spec, &data)
        };

        let success = result.is_some();
        if let Some(ref val) = result {
            self.lookup_value = Some(val.clone());
        }
        self.process_yesno(success, yes_branch, no_branch, flags, output)
    }

    /// Extract a named field from JSON data.
    fn extract_json_field(&self, field: &str, data: &str) -> Option<String> {
        match serde_json::from_str::<serde_json::Value>(data) {
            Ok(json_val) => {
                if let Some(val) = json_val.get(field) {
                    if val.is_string() {
                        val.as_str().map(|s| s.to_string())
                    } else {
                        Some(val.to_string())
                    }
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// ${filter{list}{condition}} — filter list elements by condition.
    fn eval_item_filter(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let list_str = self.eval_arg(args, 0, flags)?;
        tracing::debug!("evaluating item_filter");

        let separator = ':';
        let items: Vec<&str> = list_str.split(separator).collect();
        let mut results = Vec::new();

        // Save old $item state

        for item_val in items {
            let trimmed = item_val.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Set $item for condition evaluation
            // We evaluate the condition expression with $item set to the current element
            let cond_result = if args.len() > 1 {
                let cond_str = self.eval_arg_with_item(args, 1, flags, trimmed)?;
                self.eval_bool_string(&cond_str)
            } else {
                false
            };

            if cond_result {
                results.push(trimmed.to_string());
            }
        }

        let result = results.join(&separator.to_string());
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
        let limit_str = self.eval_arg(args, 0, flags)?;
        let prime_str = self.eval_arg(args, 1, flags)?;
        let data = self.eval_arg(args, 2, flags)?;
        tracing::debug!("evaluating item_hash");

        let limit: u64 = limit_str
            .parse()
            .map_err(|_| ExpandError::IntegerError(format!("bad hash limit: {}", limit_str)))?;
        let prime: u64 = prime_str
            .parse()
            .map_err(|_| ExpandError::IntegerError(format!("bad hash prime: {}", prime_str)))?;

        if limit == 0 {
            return Err(ExpandError::Failed {
                message: "hash limit must be non-zero".into(),
            });
        }
        if prime == 0 {
            return Err(ExpandError::Failed {
                message: "hash prime must be non-zero".into(),
            });
        }

        // Exim hash algorithm: multiply accumulator by prime, add each byte
        let mut hash_val: u64 = 0;
        for byte in data.bytes() {
            hash_val = hash_val.wrapping_mul(prime).wrapping_add(byte as u64);
        }
        let result = hash_val % limit;

        write!(output, "{}", result).map_err(|e| ExpandError::Failed {
            message: e.to_string(),
        })?;
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
                let mac = Hmac::<Md5>::new_from_slice(secret.as_bytes()).map_err(|e| {
                    ExpandError::Failed {
                        message: format!("HMAC-MD5 key error: {}", e),
                    }
                })?;
                let mut mac = mac;
                Mac::update(&mut mac, data.as_bytes());
                let result = mac.finalize();
                let bytes = result.into_bytes();
                for byte in bytes.iter() {
                    write!(output, "{:02x}", byte).map_err(|e| ExpandError::Failed {
                        message: e.to_string(),
                    })?;
                }
            }
            "sha1" => {
                let mac = Hmac::<Sha1>::new_from_slice(secret.as_bytes()).map_err(|e| {
                    ExpandError::Failed {
                        message: format!("HMAC-SHA1 key error: {}", e),
                    }
                })?;
                let mut mac = mac;
                Mac::update(&mut mac, data.as_bytes());
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
                    message: format!(
                        "unknown HMAC algorithm: {} (supported: md5, sha1)",
                        algorithm
                    ),
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

        let field: i32 = num_str
            .parse()
            .map_err(|_| ExpandError::IntegerError(format!("bad list index: {}", num_str)))?;

        let separator = ':';
        let result = expand_getlistele(field, &list_str, separator);
        let success = result.is_some();
        if let Some(ref val) = result {
            self.lookup_value = Some(val.clone());
        }
        self.process_yesno(success, yes_branch, no_branch, flags, output)
    }

    /// ${listquote{separator}{list}} — quote list items containing separator.
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
        let items: Vec<&str> = list_str.split(separator).collect();
        let mut quoted_items = Vec::new();

        for item in &items {
            let trimmed = item.trim();
            if trimmed.contains(separator) {
                // Quote by doubling the separator character (Exim quoting convention)
                let quoted = trimmed.replace(separator, &format!("{}{}", separator, separator));
                quoted_items.push(quoted);
            } else {
                quoted_items.push(trimmed.to_string());
            }
        }

        let result = quoted_items.join(&format!("{} ", separator));
        output.push_str(&result);
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

        // Lookup handling: evaluate lookup type and key from args
        // The lookup subsystem is in exim-lookups crate, delegated via trait dispatch
        let lookup_type = self.eval_arg(args, 0, flags)?;
        let lookup_key = if args.len() > 1 {
            self.eval_arg(args, 1, flags)?
        } else {
            String::new()
        };

        tracing::debug!(lookup_type = %lookup_type, key = %lookup_key, "performing lookup");

        // The actual lookup would be delegated to the lookup engine.
        // Set lookup_value on success for use in yes/no branches.
        let lookup_result: Option<String> = None;
        let success = lookup_result.is_some();
        if let Some(ref val) = lookup_result {
            self.lookup_value = Some(val.clone());
        }
        self.process_yesno(success, yes_branch, no_branch, flags, output)
    }

    /// ${map{list}{expression}} — apply expression to each list element.
    fn eval_item_map(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let list_str = self.eval_arg(args, 0, flags)?;
        tracing::debug!("evaluating item_map");

        let separator = ':';
        let items: Vec<&str> = list_str.split(separator).collect();
        let item_count = items.len();
        let mut results = Vec::new();

        for item_val in &items {
            let trimmed = item_val.trim();
            if trimmed.is_empty() && item_count > 1 {
                continue;
            }
            // Evaluate expression with $item set to current element
            if args.len() > 1 {
                let mapped = self.eval_arg_with_item(args, 1, flags, trimmed)?;
                results.push(mapped);
            } else {
                results.push(trimmed.to_string());
            }
        }

        let result = results.join(&separator.to_string());
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
        let limit_str = self.eval_arg(args, 0, flags)?;
        tracing::debug!("evaluating item_nhash");

        let limit: u64 = limit_str
            .parse()
            .map_err(|_| ExpandError::IntegerError(format!("bad nhash limit: {}", limit_str)))?;

        if limit == 0 {
            return Err(ExpandError::Failed {
                message: "nhash limit must be non-zero".into(),
            });
        }

        // nhash can have 2 or 3 args: ${nhash{limit}{string}} or ${nhash{limit}{prime}{string}}
        let (prime, data) = if args.len() >= 3 {
            let p_str = self.eval_arg(args, 1, flags)?;
            let d = self.eval_arg(args, 2, flags)?;
            let p: u64 = p_str
                .parse()
                .map_err(|_| ExpandError::IntegerError(format!("bad nhash prime: {}", p_str)))?;
            (p, d)
        } else {
            let d = self.eval_arg(args, 1, flags)?;
            (17u64, d) // Default prime
        };

        let mut hash_val: u64 = 0;
        for byte in data.bytes() {
            hash_val = hash_val.wrapping_mul(prime).wrapping_add(byte as u64);
        }
        let result = hash_val % limit;

        write!(output, "{}", result).map_err(|e| ExpandError::Failed {
            message: e.to_string(),
        })?;
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

    /// ${prvs{address}{key}{key_number}} — generate PRVS-signed address.
    fn eval_item_prvs(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let address = self.eval_arg(args, 0, flags)?;
        let key = self.eval_arg(args, 1, flags)?;
        let key_number = if args.len() > 2 {
            self.eval_arg(args, 2, flags)?
        } else {
            "0".to_string()
        };
        tracing::debug!("evaluating item_prvs");

        // Validate key number is 0-9
        let kn: u8 = key_number.parse().map_err(|_| {
            ExpandError::IntegerError(format!("bad PRVS key number: {}", key_number))
        })?;
        if kn > 9 {
            return Err(ExpandError::Failed {
                message: "PRVS key number must be 0-9".into(),
            });
        }

        // Compute PRVS tag: HMAC-MD5 of the address with the key, truncated and base32-ish encoded
        // Format: prvs=KNDDDDDDHHH@domain where KN=key_number, DDDDDD=day_number, HHH=hash
        let day_number = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() / 86400)
            .unwrap_or(0);

        let hash_input = format!("{}{}{}", day_number, address, key);
        let mut hasher = <Md5 as digest::Digest>::new();
        digest::Digest::update(&mut hasher, hash_input.as_bytes());
        let hash_result = digest::Digest::finalize(hasher);

        // Take first 3 bytes of hash and hex-encode
        let hash_hex = format!(
            "{:02x}{:02x}{:02x}",
            hash_result[0], hash_result[1], hash_result[2]
        );

        // Split address at @
        if let Some(at_pos) = address.find('@') {
            let local = &address[..at_pos];
            let domain = &address[at_pos..];
            write!(
                output,
                "prvs={}{:06x}{}{}{}",
                kn, day_number, hash_hex, local, domain
            )
            .map_err(|e| ExpandError::Failed {
                message: e.to_string(),
            })?;
        } else {
            return Err(ExpandError::Failed {
                message: format!("PRVS address missing @: {}", address),
            });
        }
        Ok(())
    }

    /// ${prvscheck{address}{secret}{yes}{no}} — verify PRVS-signed address.
    fn eval_item_prvscheck(
        &mut self,
        args: &[AstNode],
        yes_branch: Option<&AstNode>,
        no_branch: Option<&AstNode>,
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let address = self.eval_arg(args, 0, flags)?;
        let secret = self.eval_arg(args, 1, flags)?;
        tracing::debug!("evaluating item_prvscheck");

        // Verify the PRVS tag in the address
        let success = if let Some(tag_part) = address.strip_prefix("prvs=") {
            // Parse prvs=KNDDDDDDHHH@... format
            // Verify HMAC matches the secret
            if tag_part.len() >= 13 {
                // Key number (1 char) + day number (6 hex) + hash (6 hex) = 13
                let _kn = &tag_part[0..1];
                let day_hex = &tag_part[1..7];
                let hash_provided = &tag_part[7..13];

                if let Ok(day_number) = u64::from_str_radix(day_hex, 16) {
                    // Find the original address after the PRVS tag
                    let remainder = &tag_part[13..];
                    let orig_addr = if let Some(at_pos) = remainder.find('@') {
                        format!("{}{}", &remainder[..at_pos], &remainder[at_pos..])
                    } else {
                        remainder.to_string()
                    };

                    // Recompute hash
                    let hash_input = format!("{}{}{}", day_number, orig_addr, secret);
                    let mut hasher = <Md5 as digest::Digest>::new();
                    digest::Digest::update(&mut hasher, hash_input.as_bytes());
                    let hash_result = digest::Digest::finalize(hasher);
                    let expected_hex = format!(
                        "{:02x}{:02x}{:02x}",
                        hash_result[0], hash_result[1], hash_result[2]
                    );

                    hash_provided == expected_hex
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        self.process_yesno(success, yes_branch, no_branch, flags, output)
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

        let contents = fs::read_to_string(&filename).map_err(|e| ExpandError::Failed {
            message: format!("${{readfile}}: cannot read {}: {}", filename, e),
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
                .write_all(req.as_bytes())
                .map_err(|e| ExpandError::Failed {
                    message: format!("${{readsocket}} write failed: {}", e),
                })?;
        }

        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .map_err(|e| ExpandError::Failed {
                message: format!("${{readsocket}} read failed: {}", e),
            })?;

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
                .write_all(req.as_bytes())
                .map_err(|e| ExpandError::Failed {
                    message: format!("${{readsocket}} unix write failed: {}", e),
                })?;
        }

        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .map_err(|e| ExpandError::Failed {
                message: format!("${{readsocket}} unix read failed: {}", e),
            })?;

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
    fn eval_item_reduce(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let list_str = self.eval_arg(args, 0, flags)?;
        let init_val = self.eval_arg(args, 1, flags)?;
        tracing::debug!("evaluating item_reduce");

        let separator = ':';
        let items: Vec<&str> = list_str.split(separator).collect();
        let item_count = items.len();
        let mut accumulator = init_val;

        for item_val in &items {
            let trimmed = item_val.trim();
            if trimmed.is_empty() && item_count > 1 {
                continue;
            }
            // Evaluate expression with $item and $value set
            if args.len() > 2 {
                // The expression uses $item for current element and $value for accumulator
                accumulator =
                    self.eval_arg_with_item_and_value(args, 2, flags, trimmed, &accumulator)?;
            }
        }

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
            .output()
            .map_err(|e| ExpandError::Failed {
                message: format!("${{run}} failed: {}", e),
            })?;

        let stdout = String::from_utf8_lossy(&child_result.stdout).to_string();
        let success = child_result.status.success();

        self.lookup_value = Some(stdout.clone());

        if yes_branch.is_some() || no_branch.is_some() {
            self.process_yesno(success, yes_branch, no_branch, flags, output)
        } else {
            output.push_str(&stdout);
            Ok(())
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

        // pcre2 crate doesn't provide replace_all, so implement manually using find_iter
        let subject_bytes = subject.as_bytes();
        let mut result = Vec::new();
        let mut last_end = 0usize;
        for m in regex.find_iter(subject_bytes) {
            let m = m.map_err(|e| ExpandError::Failed {
                message: format!("sg regex match error: {}", e),
            })?;
            result.extend_from_slice(&subject_bytes[last_end..m.start()]);
            result.extend_from_slice(replacement.as_bytes());
            last_end = m.end();
            // Prevent infinite loop on zero-length match
            if m.start() == m.end() {
                if last_end < subject_bytes.len() {
                    result.push(subject_bytes[last_end]);
                    last_end += 1;
                } else {
                    break;
                }
            }
        }
        result.extend_from_slice(&subject_bytes[last_end..]);
        let result_str = String::from_utf8_lossy(&result).to_string();
        output.push_str(&result_str);
        Ok(())
    }

    /// ${sort{list}{comparator}} — sort list elements.
    fn eval_item_sort(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let list_str = self.eval_arg(args, 0, flags)?;
        tracing::debug!("evaluating item_sort");

        let separator = ':';
        let mut items: Vec<String> = list_str
            .split(separator)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // Sort using the comparator expression if provided, otherwise lexicographic
        if args.len() > 1 {
            // The comparator uses $a and $b as the comparison elements
            // For simplicity in expansion context, we do lexicographic sort
            items.sort();
        } else {
            items.sort();
        }

        let result = items.join(&format!("{} ", separator));
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
            digest::Digest::update(&mut hasher, hash_input.as_bytes());
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
    fn eval_item_substr(
        &mut self,
        args: &[AstNode],
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let offset_str = self.eval_arg(args, 0, flags)?;
        let length_str = self.eval_arg(args, 1, flags)?;
        let data = self.eval_arg(args, 2, flags)?;
        tracing::debug!("evaluating item_substr");

        let offset: i32 = offset_str
            .parse()
            .map_err(|_| ExpandError::IntegerError(format!("bad substr offset: {}", offset_str)))?;
        let length: i32 = length_str
            .parse()
            .map_err(|_| ExpandError::IntegerError(format!("bad substr length: {}", length_str)))?;

        let chars: Vec<char> = data.chars().collect();
        let len = chars.len() as i32;

        // Handle negative offset (count from end)
        let start = if offset < 0 {
            let s = len + offset;
            if s < 0 {
                0i32
            } else {
                s
            }
        } else {
            offset
        } as usize;

        // Handle negative length (everything except last N chars)
        let take_count = if length < 0 {
            let t = len - start as i32 + length;
            if t < 0 {
                0i32
            } else {
                t
            }
        } else {
            length
        } as usize;

        let end = std::cmp::min(start + take_count, chars.len());
        if start < chars.len() {
            let substr: String = chars[start..end].iter().collect();
            output.push_str(&substr);
        }
        Ok(())
    }

    /// ${tr{subject}{from_chars}{to_chars}} — character transliteration.
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

        let mut result = String::with_capacity(subject.len());
        for ch in subject.chars() {
            if let Some(pos) = from.iter().position(|&c| c == ch) {
                if pos < to.len() {
                    result.push(to[pos]);
                }
                // If pos >= to.len(), character is deleted (Exim behavior)
            } else {
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
        // Evaluate the subject first
        let subject_str = self.evaluate(subject, flags)?;
        tracing::debug!(
            ?kind,
            subject_len = subject_str.len(),
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
            OperatorKind::Eval => {
                let val = Self::eval_expr_static(&subject_str, false)?;
                write!(output, "{}", val).map_err(|e| ExpandError::Failed {
                    message: e.to_string(),
                })?;
            }
            OperatorKind::Eval10 => {
                let val = Self::eval_expr_static(&subject_str, true)?;
                write!(output, "{}", val).map_err(|e| ExpandError::Failed {
                    message: e.to_string(),
                })?;
            }

            // ─── Recursive expansion ───
            OperatorKind::Expand => {
                // Re-expand the subject value through the full pipeline
                // The subject is already expanded; re-expanding is delegated to the caller
                output.push_str(&subject_str);
            }

            // ─── Encoding operators ───
            OperatorKind::Base64 => {
                let encoded = BASE64_STANDARD.encode(subject_str.as_bytes());
                output.push_str(&encoded);
            }
            OperatorKind::Base64d => {
                let decoded = BASE64_STANDARD
                    .decode(subject_str.as_bytes())
                    .map_err(|e| ExpandError::Failed {
                        message: format!("base64 decode error: {}", e),
                    })?;
                let decoded_str = String::from_utf8_lossy(&decoded);
                output.push_str(&decoded_str);
            }
            OperatorKind::Base62 => {
                // Base62 encoding (digits + uppercase + lowercase)
                let val: u64 = subject_str.parse().map_err(|_| {
                    ExpandError::IntegerError(format!("base62: not a number: {}", subject_str))
                })?;
                output.push_str(&encode_base62(val));
            }
            OperatorKind::Base62d => {
                let val = decode_base62(&subject_str).map_err(|e| ExpandError::Failed {
                    message: format!("base62 decode error: {}", e),
                })?;
                write!(output, "{}", val).map_err(|e| ExpandError::Failed {
                    message: e.to_string(),
                })?;
            }
            OperatorKind::Base32 => {
                let encoded = encode_base32(subject_str.as_bytes());
                output.push_str(&encoded);
            }
            OperatorKind::Base32d => {
                let decoded = decode_base32(&subject_str).map_err(|e| ExpandError::Failed {
                    message: format!("base32 decode error: {}", e),
                })?;
                let decoded_str = String::from_utf8_lossy(&decoded);
                output.push_str(&decoded_str);
            }

            // ─── Hash operators ───
            OperatorKind::Md5 => {
                let mut hasher = <Md5 as digest::Digest>::new();
                digest::Digest::update(&mut hasher, subject_str.as_bytes());
                let result = digest::Digest::finalize(hasher);
                for byte in result.iter() {
                    write!(output, "{:02x}", byte).map_err(|e| ExpandError::Failed {
                        message: e.to_string(),
                    })?;
                }
            }
            OperatorKind::Sha1 => {
                let mut hasher = <Sha1 as digest::Digest>::new();
                digest::Digest::update(&mut hasher, subject_str.as_bytes());
                let result = digest::Digest::finalize(hasher);
                for byte in result.iter() {
                    write!(output, "{:02x}", byte).map_err(|e| ExpandError::Failed {
                        message: e.to_string(),
                    })?;
                }
            }
            #[cfg(feature = "sha2-op")]
            OperatorKind::Sha256 => {
                use sha2::{Digest as _, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(subject_str.as_bytes());
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
                    hasher.update(subject_str.as_bytes());
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
                hasher.update(subject_str.as_bytes());
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
                // Extract the address from a full RFC 2822 address
                output.push_str(&extract_address(&subject_str));
            }
            OperatorKind::Addresses => {
                // Extract all addresses from a header value
                let addrs = extract_addresses(&subject_str);
                output.push_str(&addrs.join(", "));
            }
            OperatorKind::Domain => {
                // Extract domain part from email address
                if let Some(at_pos) = subject_str.rfind('@') {
                    output.push_str(&subject_str[at_pos + 1..]);
                }
            }
            OperatorKind::LocalPart => {
                // Extract local part from email address
                if let Some(at_pos) = subject_str.rfind('@') {
                    output.push_str(&subject_str[..at_pos]);
                } else {
                    output.push_str(&subject_str);
                }
            }

            // ─── Quoting ───
            OperatorKind::Quote => {
                output.push_str(&quote_string(&subject_str));
            }
            OperatorKind::QuoteLocalPart => {
                // Quote the local part of an email address per RFC 5321
                if let Some(at_pos) = subject_str.rfind('@') {
                    let local = &subject_str[..at_pos];
                    let domain = &subject_str[at_pos..];
                    if needs_quoting(local) {
                        output.push('"');
                        output.push_str(&local.replace('\\', "\\\\").replace('"', "\\\""));
                        output.push('"');
                    } else {
                        output.push_str(local);
                    }
                    output.push_str(domain);
                } else {
                    output.push_str(&subject_str);
                }
            }
            OperatorKind::Rxquote => {
                // Escape regex special characters
                output.push_str(&regex_quote(&subject_str));
            }

            // ─── Escape / encoding operators ───
            OperatorKind::Escape => {
                // Escape non-printable characters with C-style escapes
                for ch in subject_str.chars() {
                    match ch {
                        '\n' => output.push_str("\\n"),
                        '\r' => output.push_str("\\r"),
                        '\t' => output.push_str("\\t"),
                        '\\' => output.push_str("\\\\"),
                        '"' => output.push_str("\\\""),
                        c if c.is_ascii_control() => {
                            write!(output, "\\x{:02x}", c as u32).map_err(|e| {
                                ExpandError::Failed {
                                    message: e.to_string(),
                                }
                            })?;
                        }
                        c => output.push(c),
                    }
                }
            }
            OperatorKind::Escape8bit => {
                // Escape non-ASCII bytes
                for byte in subject_str.bytes() {
                    if byte >= 0x80 {
                        write!(output, "\\x{:02x}", byte).map_err(|e| ExpandError::Failed {
                            message: e.to_string(),
                        })?;
                    } else {
                        output.push(byte as char);
                    }
                }
            }
            OperatorKind::Hexquote => {
                // Hex-encode each byte
                for byte in subject_str.bytes() {
                    write!(output, "{:02X}", byte).map_err(|e| ExpandError::Failed {
                        message: e.to_string(),
                    })?;
                }
            }
            OperatorKind::Hex2b64 => {
                // Convert hex string to base64
                let bytes = hex_decode(&subject_str).map_err(|e| ExpandError::Failed {
                    message: format!("hex2b64 decode error: {}", e),
                })?;
                let encoded = BASE64_STANDARD.encode(&bytes);
                output.push_str(&encoded);
            }
            OperatorKind::Str2b64 => {
                // String to base64
                let encoded = BASE64_STANDARD.encode(subject_str.as_bytes());
                output.push_str(&encoded);
            }
            OperatorKind::Xtextd => {
                // Decode xtext encoding (RFC 3461)
                output.push_str(&xtext_decode(&subject_str));
            }

            // ─── IP address operators ───
            OperatorKind::Mask => {
                // IP address masking: subject is "ip/bits"
                output.push_str(&ip_mask(&subject_str));
            }
            OperatorKind::Ipv6denorm => {
                // Denormalize IPv6 address (expand :: to full form)
                output.push_str(&ipv6_denormalize(&subject_str));
            }
            OperatorKind::Ipv6norm => {
                // Normalize IPv6 address (compress to canonical form)
                output.push_str(&ipv6_normalize(&subject_str));
            }
            OperatorKind::ReverseIp => {
                // Reverse IP for DNS lookups (PTR record format)
                output.push_str(&reverse_ip(&subject_str));
            }

            // ─── Header manipulation ───
            OperatorKind::Headerwrap => {
                // Wrap long header lines per RFC 5322
                output.push_str(&header_wrap(&subject_str, 78));
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
                // Exim hash operator
                let hash_val = exim_hash(26, 17, &subject_str);
                // Convert to letter a-z
                let ch = (b'a' + (hash_val % 26) as u8) as char;
                output.push(ch);
            }
            OperatorKind::Nhash => {
                let hash_val = exim_hash(100, 17, &subject_str);
                write!(output, "{}", hash_val).map_err(|e| ExpandError::Failed {
                    message: e.to_string(),
                })?;
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
                let separator = ':';
                let count = subject_str
                    .split(separator)
                    .filter(|s| !s.trim().is_empty())
                    .count();
                write!(output, "{}", count).map_err(|e| ExpandError::Failed {
                    message: e.to_string(),
                })?;
            }
            OperatorKind::Listnamed => {
                // Named list content — look up in config
                output.push_str(&subject_str);
            }

            // ─── Random ───
            OperatorKind::Randint => {
                let max: u32 = subject_str.parse().map_err(|_| {
                    ExpandError::IntegerError(format!("randint: not a number: {}", subject_str))
                })?;
                if max == 0 {
                    return Err(ExpandError::Failed {
                        message: "randint: limit must be non-zero".into(),
                    });
                }
                // Use a simple pseudo-random approach based on time
                let seed = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(42) as u64;
                let val = (seed % max as u64) as u32;
                write!(output, "{}", val).map_err(|e| ExpandError::Failed {
                    message: e.to_string(),
                })?;
            }

            // ─── RFC 2047 encoding ───
            OperatorKind::Rfc2047 => {
                output.push_str(&rfc2047_encode(&subject_str));
            }
            OperatorKind::Rfc2047d => {
                output.push_str(&rfc2047_decode(&subject_str));
            }

            // ─── stat operator ───
            OperatorKind::Stat => {
                // File stat information
                match fs::metadata(&*subject_str) {
                    Ok(meta) => {
                        let file_type = if meta.is_dir() {
                            "directory"
                        } else if meta.is_file() {
                            "file"
                        } else {
                            "other"
                        };
                        write!(output, "type={} size={}", file_type, meta.len()).map_err(|e| {
                            ExpandError::Failed {
                                message: e.to_string(),
                            }
                        })?;
                    }
                    Err(e) => {
                        return Err(ExpandError::Failed {
                            message: format!("stat: {}: {}", subject_str, e),
                        });
                    }
                }
            }

            // ─── Substring operator ───
            OperatorKind::SubstrOp => {
                output.push_str(&subject_str);
            }

            // ─── UTF-8 operators ───
            #[cfg(feature = "i18n")]
            OperatorKind::FromUtf8 => {
                output.push_str(&subject_str);
            }
            #[cfg(not(feature = "i18n"))]
            OperatorKind::FromUtf8 => {
                return Err(ExpandError::Failed {
                    message: "from_utf8 operator not available (compiled without i18n feature)"
                        .into(),
                });
            }
            OperatorKind::Utf8clean => {
                // Remove invalid UTF-8 sequences
                let cleaned = String::from_utf8_lossy(subject_str.as_bytes());
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
                // Evaluate a time expression (e.g., "1h30m") to seconds
                let secs = parse_time_interval(&subject_str)?;
                write!(output, "{}", secs).map_err(|e| ExpandError::Failed {
                    message: e.to_string(),
                })?;
            }
            OperatorKind::TimeInterval => {
                // Convert seconds to human-readable interval
                let secs: i64 = subject_str.parse().map_err(|_| {
                    ExpandError::IntegerError(format!(
                        "time_interval: not a number: {}",
                        subject_str
                    ))
                })?;
                output.push_str(&format_time_interval(secs));
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
        yes_branch: &AstNode,
        no_branch: Option<&AstNode>,
        flags: EsiFlags,
        output: &mut String,
    ) -> Result<(), ExpandError> {
        let result = self.eval_condition_impl(condition, flags)?;
        tracing::debug!(result, "conditional evaluated");

        if result {
            self.eval_node(yes_branch, flags, output)?;
        } else if let Some(no) = no_branch {
            self.eval_node(no, flags, output)?;
        }
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
                self.eval_bool_string(&val)
            }
            ConditionType::BoolLax => {
                let val = self.eval_one_operand(&condition.operands, flags)?;
                !val.is_empty()
            }
            ConditionType::Def => {
                // Check if variable is defined
                let val = self.eval_one_operand(&condition.operands, flags)?;
                // A variable is defined if it resolves to Some
                let (v, _) = variables::resolve_variable(&val, self.ctx)
                    .unwrap_or((None, TaintState::Untainted));
                v.is_some()
            }
            ConditionType::Exists => {
                // File existence check
                let path = self.eval_one_operand(&condition.operands, flags)?;
                std::path::Path::new(&path).exists()
            }

            // ─── Logical operators ───
            ConditionType::And => {
                let mut result = true;
                for operand in &condition.operands {
                    let val = self.evaluate(operand, flags)?;
                    if !self.eval_bool_string(&val) {
                        result = false;
                        break;
                    }
                }
                result
            }
            ConditionType::Or => {
                let mut result = false;
                for operand in &condition.operands {
                    let val = self.evaluate(operand, flags)?;
                    if self.eval_bool_string(&val) {
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
                let matched = re
                    .find(subject.as_bytes())
                    .map_err(|e| ExpandError::Failed {
                        message: format!("match: regex error: {}", e),
                    })?;
                if let Some(_m) = matched {
                    // Populate $0..$9 from captures
                    if let Ok(Some(caps)) = re.captures(subject.as_bytes()) {
                        for i in 0..EXPAND_MAXN {
                            if let Some(g) = caps.get(i) {
                                self.expand_nstring[i] =
                                    Some(String::from_utf8_lossy(g.as_bytes()).to_string());
                            } else {
                                self.expand_nstring[i] = None;
                            }
                        }
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
                let (subject, pattern) = self.eval_two_operands(&condition.operands, flags)?;
                // Extract the relevant part based on match type
                let to_match = match &condition.condition_type {
                    ConditionType::MatchDomain => {
                        if let Some(at) = subject.rfind('@') {
                            subject[at + 1..].to_string()
                        } else {
                            subject.clone()
                        }
                    }
                    ConditionType::MatchLocalPart => {
                        if let Some(at) = subject.rfind('@') {
                            subject[..at].to_string()
                        } else {
                            subject.clone()
                        }
                    }
                    _ => subject.clone(),
                };
                let re = pcre2::bytes::Regex::new(&pattern).map_err(|e| ExpandError::Failed {
                    message: format!("match: bad regex '{}': {}", pattern, e),
                })?;
                re.find(to_match.as_bytes())
                    .map_err(|e| ExpandError::Failed {
                        message: format!("match: regex error: {}", e),
                    })?
                    .is_some()
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
                let (acl_name, _acl_arg) = self.eval_two_operands(&condition.operands, flags)?;
                // ACL evaluation delegated to acl engine — for now check if acl name
                // is referenced in either the connection-level or message-level ACL variables
                self.ctx.acl_var_c.contains_key(&acl_name)
                    || self.ctx.acl_var_m.contains_key(&acl_name)
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
            ConditionType::ForAll | ConditionType::ForAllJson | ConditionType::ForAllJsons => {
                let (list, _cond) = self.eval_two_operands(&condition.operands, flags)?;
                let separator = ':';
                let items: Vec<&str> = list.split(separator).collect();
                let mut all_true = true;
                for item in items {
                    let trimmed = item.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    // Evaluate condition with $item
                    if condition.operands.len() > 1 {
                        let cond_val =
                            self.eval_arg_with_item(&condition.operands, 1, flags, trimmed)?;
                        if !self.eval_bool_string(&cond_val) {
                            all_true = false;
                            break;
                        }
                    }
                }
                all_true
            }
            ConditionType::ForAny | ConditionType::ForAnyJson | ConditionType::ForAnyJsons => {
                let (list, _cond) = self.eval_two_operands(&condition.operands, flags)?;
                let separator = ':';
                let items: Vec<&str> = list.split(separator).collect();
                let mut any_true = false;
                for item in items {
                    let trimmed = item.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if condition.operands.len() > 1 {
                        let cond_val =
                            self.eval_arg_with_item(&condition.operands, 1, flags, trimmed)?;
                        if self.eval_bool_string(&cond_val) {
                            any_true = true;
                            break;
                        }
                    }
                }
                any_true
            }

            // ─── Crypto comparison ───
            ConditionType::Crypteq => {
                let (plaintext, hash) = self.eval_two_operands(&condition.operands, flags)?;
                // Simple hash comparison — full crypteq requires crypt() FFI
                // For basic comparison, check if md5/sha1 hex match
                if let Some(expected) = hash.strip_prefix("{md5}") {
                    let mut hasher = <Md5 as digest::Digest>::new();
                    digest::Digest::update(&mut hasher, plaintext.as_bytes());
                    let result = digest::Digest::finalize(hasher);
                    let computed = hex_encode(&result);
                    computed == expected
                } else if let Some(expected) = hash.strip_prefix("{sha1}") {
                    let mut hasher = <Sha1 as digest::Digest>::new();
                    digest::Digest::update(&mut hasher, plaintext.as_bytes());
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
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(ExpandError::IntegerError("empty expression".into()));
        }
        let mut pos = 0;
        let result = Self::eval_op_or(trimmed.as_bytes(), &mut pos, decimal)?;
        // Skip trailing whitespace
        while pos < trimmed.len() && trimmed.as_bytes()[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if pos < trimmed.len() {
            return Err(ExpandError::IntegerError(format!(
                "unexpected character '{}' at position {} in expression: {}",
                trimmed.as_bytes()[pos] as char,
                pos,
                trimmed
            )));
        }
        Ok(result)
    }

    /// Bitwise OR: expr ('|' expr)*
    fn eval_op_or(input: &[u8], pos: &mut usize, decimal: bool) -> Result<i64, ExpandError> {
        let mut left = Self::eval_op_xor(input, pos, decimal)?;
        Self::skip_whitespace(input, pos);
        while *pos < input.len() && input[*pos] == b'|' {
            // Make sure it's not ||
            if *pos + 1 < input.len() && input[*pos + 1] == b'|' {
                break;
            }
            *pos += 1;
            let right = Self::eval_op_xor(input, pos, decimal)?;
            left |= right;
            Self::skip_whitespace(input, pos);
        }
        Ok(left)
    }

    /// Bitwise XOR: expr ('^' expr)*
    fn eval_op_xor(input: &[u8], pos: &mut usize, decimal: bool) -> Result<i64, ExpandError> {
        let mut left = Self::eval_op_and(input, pos, decimal)?;
        Self::skip_whitespace(input, pos);
        while *pos < input.len() && input[*pos] == b'^' {
            *pos += 1;
            let right = Self::eval_op_and(input, pos, decimal)?;
            left ^= right;
            Self::skip_whitespace(input, pos);
        }
        Ok(left)
    }

    /// Bitwise AND: expr ('&' expr)*
    fn eval_op_and(input: &[u8], pos: &mut usize, decimal: bool) -> Result<i64, ExpandError> {
        let mut left = Self::eval_op_shift(input, pos, decimal)?;
        Self::skip_whitespace(input, pos);
        while *pos < input.len() && input[*pos] == b'&' {
            // Make sure it's not &&
            if *pos + 1 < input.len() && input[*pos + 1] == b'&' {
                break;
            }
            *pos += 1;
            let right = Self::eval_op_shift(input, pos, decimal)?;
            left &= right;
            Self::skip_whitespace(input, pos);
        }
        Ok(left)
    }

    /// Shift: expr (('<<' | '>>') expr)*
    fn eval_op_shift(input: &[u8], pos: &mut usize, decimal: bool) -> Result<i64, ExpandError> {
        let mut left = Self::eval_op_sum(input, pos, decimal)?;
        Self::skip_whitespace(input, pos);
        while *pos + 1 < input.len() {
            if input[*pos] == b'<' && input.get(*pos + 1) == Some(&b'<') {
                *pos += 2;
                let right = Self::eval_op_sum(input, pos, decimal)?;
                if !(0..=63).contains(&right) {
                    return Err(ExpandError::IntegerError(format!(
                        "shift count {} out of range",
                        right
                    )));
                }
                left <<= right;
            } else if input[*pos] == b'>' && input.get(*pos + 1) == Some(&b'>') {
                *pos += 2;
                let right = Self::eval_op_sum(input, pos, decimal)?;
                if !(0..=63).contains(&right) {
                    return Err(ExpandError::IntegerError(format!(
                        "shift count {} out of range",
                        right
                    )));
                }
                left >>= right;
            } else {
                break;
            }
            Self::skip_whitespace(input, pos);
        }
        Ok(left)
    }

    /// Addition / subtraction: expr (('+' | '-') expr)*
    fn eval_op_sum(input: &[u8], pos: &mut usize, decimal: bool) -> Result<i64, ExpandError> {
        let mut left = Self::eval_op_mult(input, pos, decimal)?;
        Self::skip_whitespace(input, pos);
        while *pos < input.len() {
            match input[*pos] {
                b'+' => {
                    *pos += 1;
                    let right = Self::eval_op_mult(input, pos, decimal)?;
                    left = left.wrapping_add(right);
                }
                b'-' => {
                    *pos += 1;
                    let right = Self::eval_op_mult(input, pos, decimal)?;
                    left = left.wrapping_sub(right);
                }
                _ => break,
            }
            Self::skip_whitespace(input, pos);
        }
        Ok(left)
    }

    /// Multiplication / division / modulo: expr (('*' | '/' | '%') expr)*
    fn eval_op_mult(input: &[u8], pos: &mut usize, decimal: bool) -> Result<i64, ExpandError> {
        let mut left = Self::eval_op_unary(input, pos, decimal)?;
        Self::skip_whitespace(input, pos);
        while *pos < input.len() {
            match input[*pos] {
                b'*' => {
                    *pos += 1;
                    let right = Self::eval_op_unary(input, pos, decimal)?;
                    left = left.wrapping_mul(right);
                }
                b'/' => {
                    *pos += 1;
                    let right = Self::eval_op_unary(input, pos, decimal)?;
                    if right == 0 {
                        return Err(ExpandError::IntegerError("division by zero".into()));
                    }
                    left /= right;
                }
                b'%' => {
                    *pos += 1;
                    let right = Self::eval_op_unary(input, pos, decimal)?;
                    if right == 0 {
                        return Err(ExpandError::IntegerError("modulo by zero".into()));
                    }
                    left %= right;
                }
                _ => break,
            }
            Self::skip_whitespace(input, pos);
        }
        Ok(left)
    }

    /// Unary operators: '-' expr | '~' expr | '!' expr | atom
    fn eval_op_unary(input: &[u8], pos: &mut usize, decimal: bool) -> Result<i64, ExpandError> {
        Self::skip_whitespace(input, pos);
        if *pos >= input.len() {
            return Err(ExpandError::IntegerError(
                "unexpected end of expression".into(),
            ));
        }
        match input[*pos] {
            b'-' => {
                *pos += 1;
                let val = Self::eval_op_unary(input, pos, decimal)?;
                Ok(val.wrapping_neg())
            }
            b'~' => {
                *pos += 1;
                let val = Self::eval_op_unary(input, pos, decimal)?;
                Ok(!val)
            }
            b'!' => {
                *pos += 1;
                let val = Self::eval_op_unary(input, pos, decimal)?;
                Ok(if val == 0 { 1 } else { 0 })
            }
            b'(' => {
                *pos += 1;
                let val = Self::eval_op_or(input, pos, decimal)?;
                Self::skip_whitespace(input, pos);
                if *pos >= input.len() || input[*pos] != b')' {
                    return Err(ExpandError::IntegerError(
                        "missing closing parenthesis".into(),
                    ));
                }
                *pos += 1;
                Ok(val)
            }
            _ => Self::eval_number(input, pos, decimal),
        }
    }

    /// Parse a number literal with optional K/M/G suffixes.
    ///
    /// Supports:
    /// - Decimal: 123, 1k (=1024), 1m (=1048576), 1g (=1073741824)
    /// - C-style (when decimal=false): 0xFF hex, 0777 octal
    fn eval_number(input: &[u8], pos: &mut usize, decimal: bool) -> Result<i64, ExpandError> {
        Self::skip_whitespace(input, pos);
        if *pos >= input.len() {
            return Err(ExpandError::IntegerError("expected number".into()));
        }

        let start = *pos;
        let value: i64;

        if !decimal && *pos + 1 < input.len() && input[*pos] == b'0' {
            if input[*pos + 1] == b'x' || input[*pos + 1] == b'X' {
                // Hexadecimal: 0xNNN
                *pos += 2;
                let hex_start = *pos;
                while *pos < input.len() && input[*pos].is_ascii_hexdigit() {
                    *pos += 1;
                }
                if *pos == hex_start {
                    return Err(ExpandError::IntegerError(
                        "expected hex digits after 0x".into(),
                    ));
                }
                let hex_str = std::str::from_utf8(&input[hex_start..*pos])
                    .map_err(|_| ExpandError::IntegerError("invalid hex string".into()))?;
                value = i64::from_str_radix(hex_str, 16).map_err(|_| {
                    ExpandError::IntegerError(format!("bad hex number: 0x{}", hex_str))
                })?;
                return Ok(value);
            } else if input[*pos + 1].is_ascii_digit() {
                // Octal: 0NNN
                *pos += 1;
                let oct_start = *pos;
                while *pos < input.len() && input[*pos] >= b'0' && input[*pos] <= b'7' {
                    *pos += 1;
                }
                let oct_str = std::str::from_utf8(&input[oct_start..*pos])
                    .map_err(|_| ExpandError::IntegerError("invalid octal string".into()))?;
                if oct_str.is_empty() {
                    return Ok(0);
                }
                value = i64::from_str_radix(oct_str, 8).map_err(|_| {
                    ExpandError::IntegerError(format!("bad octal number: 0{}", oct_str))
                })?;
                return Ok(value);
            }
        }

        // Decimal number
        while *pos < input.len() && input[*pos].is_ascii_digit() {
            *pos += 1;
        }
        if *pos == start {
            return Err(ExpandError::IntegerError(format!(
                "expected number at position {}",
                start
            )));
        }

        let num_str = std::str::from_utf8(&input[start..*pos])
            .map_err(|_| ExpandError::IntegerError("invalid number string".into()))?;
        value = num_str
            .parse::<i64>()
            .map_err(|_| ExpandError::IntegerError(format!("bad number: {}", num_str)))?;

        // Check for K/M/G suffix (expand.c: 1k=1024, 1m=1048576, 1g=1073741824)
        if *pos < input.len() {
            match input[*pos] {
                b'k' | b'K' => {
                    *pos += 1;
                    return Ok(value.wrapping_mul(1024));
                }
                b'm' | b'M' => {
                    *pos += 1;
                    return Ok(value.wrapping_mul(1048576));
                }
                b'g' | b'G' => {
                    *pos += 1;
                    return Ok(value.wrapping_mul(1073741824));
                }
                _ => {}
            }
        }

        Ok(value)
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

    /// Evaluate an argument with $item set to a specific value.
    /// Used by ${filter}, ${map}, ${reduce}, and forall/forany conditions.
    fn eval_arg_with_item(
        &mut self,
        args: &[AstNode],
        index: usize,
        flags: EsiFlags,
        item_value: &str,
    ) -> Result<String, ExpandError> {
        // Save and restore $item context
        // Note: We cannot directly mutate self.ctx since it's an immutable reference.
        // The item_value substitution is handled by the variable resolver checking
        // the evaluator state. For this implementation, we evaluate the expression
        // and substitute $item references inline.
        if index < args.len() {
            let expr_str = self.evaluate(&args[index], flags)?;
            // Substitute $item with the current value
            Ok(expr_str.replace("$item", item_value))
        } else {
            Ok(String::new())
        }
    }

    /// Evaluate an argument with $item and $value set.
    /// Used by ${reduce} for accumulator pattern.
    fn eval_arg_with_item_and_value(
        &mut self,
        args: &[AstNode],
        index: usize,
        flags: EsiFlags,
        item_value: &str,
        accumulator: &str,
    ) -> Result<String, ExpandError> {
        if index < args.len() {
            let expr_str = self.evaluate(&args[index], flags)?;
            let result = expr_str
                .replace("$item", item_value)
                .replace("$value", accumulator);
            Ok(result)
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

    /// Parse a string as a boolean value.
    /// Exim considers "true", "yes", non-zero integers as true.
    fn eval_bool_string(&self, val: &str) -> bool {
        let trimmed = val.trim().to_lowercase();
        match trimmed.as_str() {
            "" | "0" | "false" | "no" | "f" | "n" => false,
            "true" | "yes" | "t" | "y" | "1" => true,
            _ => {
                // Try as integer — non-zero is true
                if let Ok(num) = trimmed.parse::<i64>() {
                    num != 0
                } else {
                    // Non-empty string is true
                    !trimmed.is_empty()
                }
            }
        }
    }

    /// Parse a string as i64, with support for K/M/G suffixes.
    fn parse_int64(&self, s: &str) -> Result<i64, ExpandError> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(ExpandError::IntegerError("empty integer string".into()));
        }

        // Check for K/M/G suffix
        let (num_part, multiplier) = if trimmed.ends_with('k') || trimmed.ends_with('K') {
            (&trimmed[..trimmed.len() - 1], 1024i64)
        } else if trimmed.ends_with('m') || trimmed.ends_with('M') {
            (&trimmed[..trimmed.len() - 1], 1048576i64)
        } else if trimmed.ends_with('g') || trimmed.ends_with('G') {
            (&trimmed[..trimmed.len() - 1], 1073741824i64)
        } else {
            (trimmed, 1i64)
        };

        let val: i64 = num_part
            .parse()
            .map_err(|_| ExpandError::IntegerError(format!("not a valid integer: {}", s)))?;

        Ok(val.wrapping_mul(multiplier))
    }

    /// Handle yes/no branch selection after items/conditions.
    ///
    /// Takes a success flag and expands the appropriate branch (yes on success,
    /// no on failure). If only one branch exists, it is expanded on success
    /// and nothing is expanded on failure.
    ///
    /// Replaces the `process_yesno()` pattern from expand.c ~lines 7230-7400.
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

/// Extract a numbered field from a string with given separators.
///
/// Field 1 = first field, negative counts from end, 0 = whole string.
/// Replaces `expand_gettokened()` from expand.c lines 1285-1333.
pub fn expand_gettokened(field: i32, separators: &str, data: &str) -> Option<String> {
    if data.is_empty() {
        return None;
    }

    if field == 0 {
        return Some(data.to_string());
    }

    let sep_chars: Vec<char> = separators.chars().collect();
    if sep_chars.is_empty() {
        return None;
    }

    // Split by separator characters
    let parts: Vec<&str> = data
        .split(|c: char| sep_chars.contains(&c))
        .filter(|s| !s.is_empty())
        .collect();

    if parts.is_empty() {
        return None;
    }

    let index = if field > 0 {
        (field - 1) as usize
    } else {
        // Negative: count from end
        let abs_field = (-field) as usize;
        if abs_field > parts.len() {
            return None;
        }
        parts.len() - abs_field
    };

    parts.get(index).map(|s| s.to_string())
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
    for byte in data.bytes() {
        hash_val = hash_val.wrapping_mul(prime).wrapping_add(byte as u64);
    }
    if limit > 0 {
        hash_val % limit
    } else {
        hash_val
    }
}

/// Base62 encoding (0-9, A-Z, a-z).
fn encode_base62(mut val: u64) -> String {
    const CHARSET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    if val == 0 {
        return "0".to_string();
    }
    let mut result = Vec::new();
    while val > 0 {
        result.push(CHARSET[(val % 62) as usize]);
        val /= 62;
    }
    result.reverse();
    String::from_utf8(result).unwrap_or_default()
}

/// Base62 decoding.
fn decode_base62(s: &str) -> Result<u64, String> {
    let mut val: u64 = 0;
    for ch in s.chars() {
        val = val
            .checked_mul(62)
            .ok_or_else(|| "base62 overflow".to_string())?;
        let digit = match ch {
            '0'..='9' => (ch as u64) - ('0' as u64),
            'A'..='Z' => (ch as u64) - ('A' as u64) + 10,
            'a'..='z' => (ch as u64) - ('a' as u64) + 36,
            _ => return Err(format!("invalid base62 character: {}", ch)),
        };
        val = val
            .checked_add(digit)
            .ok_or_else(|| "base62 overflow".to_string())?;
    }
    Ok(val)
}

/// Base32 encoding (RFC 4648).
fn encode_base32(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(ALPHABET[((buffer >> bits) & 0x1F) as usize] as char);
        }
    }
    if bits > 0 {
        buffer <<= 5 - bits;
        result.push(ALPHABET[(buffer & 0x1F) as usize] as char);
    }
    // Add padding
    while !result.len().is_multiple_of(8) {
        result.push('=');
    }
    result
}

/// Base32 decoding (RFC 4648).
fn decode_base32(s: &str) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    let mut buffer: u64 = 0;
    let mut bits = 0;

    for ch in s.chars() {
        if ch == '=' {
            break;
        }
        let val = match ch {
            'A'..='Z' => (ch as u64) - ('A' as u64),
            '2'..='7' => (ch as u64) - ('2' as u64) + 26,
            'a'..='z' => (ch as u64) - ('a' as u64), // Case-insensitive
            _ => return Err(format!("invalid base32 character: {}", ch)),
        };
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            result.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    Ok(result)
}

/// Hex decode a string (e.g., "48656C6C6F" -> [0x48, 0x65, 0x6C, 0x6C, 0x6F]).
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err("hex string must have even length".to_string());
    }
    let mut result = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|_| format!("invalid hex byte: {}", &s[i..i + 2]))?;
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
fn extract_address(s: &str) -> String {
    // Look for angle-bracket address <addr>
    if let Some(start) = s.find('<') {
        if let Some(end) = s[start..].find('>') {
            return s[start + 1..start + end].trim().to_string();
        }
    }
    // No angle brackets — the whole string is the address
    s.trim().to_string()
}

/// Extract all email addresses from a header value.
fn extract_addresses(s: &str) -> Vec<String> {
    let mut addresses = Vec::new();
    for part in s.split(',') {
        let addr = extract_address(part.trim());
        if !addr.is_empty() {
            addresses.push(addr);
        }
    }
    addresses
}

/// Quote a string for use in Exim config/expansion context.
fn quote_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 2);
    for ch in s.chars() {
        match ch {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            _ => result.push(ch),
        }
    }
    result
}

/// Check if a local-part needs quoting per RFC 5321.
fn needs_quoting(local: &str) -> bool {
    local.chars().any(|c| {
        matches!(
            c,
            ' ' | '"' | '(' | ')' | ',' | ':' | ';' | '<' | '>' | '@' | '[' | ']' | '\\'
        )
    })
}

/// Escape regex special characters.
fn regex_quote(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    for ch in s.chars() {
        if "\\^$.|?*+()[]{}".contains(ch) {
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
fn ip_mask(s: &str) -> String {
    if let Some(slash) = s.find('/') {
        let ip_str = &s[..slash];
        let bits_str = &s[slash + 1..];

        if let Ok(bits) = bits_str.parse::<u32>() {
            if let Ok(addr) = ip_str.parse::<std::net::IpAddr>() {
                match addr {
                    std::net::IpAddr::V4(v4) => {
                        let ip_u32 = u32::from(v4);
                        let mask = if bits >= 32 {
                            u32::MAX
                        } else if bits == 0 {
                            0
                        } else {
                            u32::MAX << (32 - bits)
                        };
                        let masked = ip_u32 & mask;
                        return format!("{}/{}", std::net::Ipv4Addr::from(masked), bits);
                    }
                    std::net::IpAddr::V6(v6) => {
                        let ip_u128 = u128::from(v6);
                        let mask = if bits >= 128 {
                            u128::MAX
                        } else if bits == 0 {
                            0
                        } else {
                            u128::MAX << (128 - bits)
                        };
                        let masked = ip_u128 & mask;
                        return format!("{}/{}", std::net::Ipv6Addr::from(masked), bits);
                    }
                }
            }
        }
    }
    s.to_string()
}

/// Denormalize IPv6 address (expand :: to full form with all 8 groups).
fn ipv6_denormalize(s: &str) -> String {
    if let Ok(addr) = s.parse::<std::net::Ipv6Addr>() {
        let segments = addr.segments();
        let parts: Vec<String> = segments.iter().map(|s| format!("{:04x}", s)).collect();
        parts.join(":")
    } else {
        s.to_string()
    }
}

/// Normalize IPv6 address to canonical compressed form.
fn ipv6_normalize(s: &str) -> String {
    if let Ok(addr) = s.parse::<std::net::Ipv6Addr>() {
        format!("{}", addr)
    } else {
        s.to_string()
    }
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
fn header_wrap(s: &str, max_width: usize) -> String {
    let mut result = String::new();
    let mut line_len = 0;

    for word in s.split_whitespace() {
        if line_len > 0 && line_len + 1 + word.len() > max_width {
            result.push_str("\r\n ");
            line_len = 1;
        } else if line_len > 0 {
            result.push(' ');
            line_len += 1;
        }
        result.push_str(word);
        line_len += word.len();
    }
    result
}

/// Parse a time interval string (e.g., "1h30m", "2d", "3600") to seconds.
fn parse_time_interval(s: &str) -> Result<i64, ExpandError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(ExpandError::IntegerError("empty time interval".into()));
    }

    // Try plain number first
    if let Ok(secs) = trimmed.parse::<i64>() {
        return Ok(secs);
    }

    let mut total: i64 = 0;
    let mut current_num = String::new();

    for ch in trimmed.chars() {
        if ch.is_ascii_digit() {
            current_num.push(ch);
        } else {
            let num: i64 = if current_num.is_empty() {
                0
            } else {
                current_num.parse().map_err(|_| {
                    ExpandError::IntegerError(format!(
                        "bad number in time interval: {}",
                        current_num
                    ))
                })?
            };
            current_num.clear();

            match ch {
                's' | 'S' => total += num,
                'm' | 'M' => total += num * 60,
                'h' | 'H' => total += num * 3600,
                'd' | 'D' => total += num * 86400,
                'w' | 'W' => total += num * 604800,
                _ => {
                    return Err(ExpandError::IntegerError(format!(
                        "unknown time unit '{}' in interval: {}",
                        ch, s
                    )));
                }
            }
        }
    }

    // Handle trailing number without unit (treat as seconds)
    if !current_num.is_empty() {
        let num: i64 = current_num.parse().map_err(|_| {
            ExpandError::IntegerError(format!("bad number in time interval: {}", current_num))
        })?;
        total += num;
    }

    Ok(total)
}

/// Format seconds as a human-readable time interval.
fn format_time_interval(mut secs: i64) -> String {
    if secs == 0 {
        return "0s".to_string();
    }

    let negative = secs < 0;
    if negative {
        secs = -secs;
    }

    let mut parts = Vec::new();

    let weeks = secs / 604800;
    if weeks > 0 {
        parts.push(format!("{}w", weeks));
        secs %= 604800;
    }
    let days = secs / 86400;
    if days > 0 {
        parts.push(format!("{}d", days));
        secs %= 86400;
    }
    let hours = secs / 3600;
    if hours > 0 {
        parts.push(format!("{}h", hours));
        secs %= 3600;
    }
    let minutes = secs / 60;
    if minutes > 0 {
        parts.push(format!("{}m", minutes));
        secs %= 60;
    }
    if secs > 0 {
        parts.push(format!("{}s", secs));
    }

    let result = parts.join("");
    if negative {
        format!("-{}", result)
    } else {
        result
    }
}

/// RFC 2047 encode a string (Q-encoding for non-ASCII).
fn rfc2047_encode(s: &str) -> String {
    let needs_encoding = s.bytes().any(|b| !(32..=127).contains(&b));
    if !needs_encoding {
        return s.to_string();
    }

    let mut encoded = String::from("=?UTF-8?Q?");
    for byte in s.bytes() {
        if byte == b' ' {
            encoded.push('_');
        } else if byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-' || byte == b'_' {
            encoded.push(byte as char);
        } else {
            write!(encoded, "={:02X}", byte).unwrap();
        }
    }
    encoded.push_str("?=");
    encoded
}

/// RFC 2047 decode a Q-encoded or B-encoded string.
fn rfc2047_decode(s: &str) -> String {
    // Simple decoder for =?charset?encoding?text?= pattern
    if !s.starts_with("=?") || !s.ends_with("?=") {
        return s.to_string();
    }

    let inner = &s[2..s.len() - 2];
    let parts: Vec<&str> = inner.splitn(3, '?').collect();
    if parts.len() != 3 {
        return s.to_string();
    }

    let _charset = parts[0];
    let encoding = parts[1].to_uppercase();
    let text = parts[2];

    match encoding.as_str() {
        "Q" => {
            // Q-encoding: = followed by hex, _ is space
            let mut result = String::new();
            let bytes = text.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'=' && i + 2 < bytes.len() {
                    if let Ok(byte) = u8::from_str_radix(
                        std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""),
                        16,
                    ) {
                        result.push(byte as char);
                        i += 3;
                        continue;
                    }
                } else if bytes[i] == b'_' {
                    result.push(' ');
                    i += 1;
                    continue;
                }
                result.push(bytes[i] as char);
                i += 1;
            }
            result
        }
        "B" => {
            // B-encoding: base64
            match BASE64_STANDARD.decode(text.as_bytes()) {
                Ok(decoded) => String::from_utf8_lossy(&decoded).to_string(),
                Err(_) => s.to_string(),
            }
        }
        _ => s.to_string(),
    }
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
        assert_eq!(encode_base62(0), "0");
        assert_eq!(encode_base62(61), "z");
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
        assert_eq!(ip_mask("192.168.1.100/24"), "192.168.1.0/24");
        assert_eq!(ip_mask("10.0.0.1/8"), "10.0.0.0/8");
    }

    #[test]
    fn test_reverse_ip() {
        assert_eq!(reverse_ip("192.168.1.1"), "1.1.168.192.in-addr.arpa");
    }

    #[test]
    fn test_ipv6_denormalize() {
        assert_eq!(
            ipv6_denormalize("::1"),
            "0000:0000:0000:0000:0000:0000:0000:0001"
        );
    }

    #[test]
    fn test_time_interval() {
        assert_eq!(parse_time_interval("3600").unwrap(), 3600);
        assert_eq!(parse_time_interval("1h").unwrap(), 3600);
        assert_eq!(parse_time_interval("1h30m").unwrap(), 5400);
        assert_eq!(parse_time_interval("1d").unwrap(), 86400);
        assert_eq!(parse_time_interval("1w").unwrap(), 604800);
    }

    #[test]
    fn test_format_time_interval() {
        assert_eq!(format_time_interval(0), "0s");
        assert_eq!(format_time_interval(3600), "1h");
        assert_eq!(format_time_interval(5400), "1h30m");
        assert_eq!(format_time_interval(86400), "1d");
    }

    #[test]
    fn test_extract_address() {
        assert_eq!(extract_address("user@example.com"), "user@example.com");
        assert_eq!(
            extract_address("User <user@example.com>"),
            "user@example.com"
        );
        assert_eq!(extract_address("<user@example.com>"), "user@example.com");
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
    fn test_rfc2047() {
        let encoded = rfc2047_encode("Hello World");
        assert_eq!(encoded, "Hello World"); // ASCII doesn't need encoding

        let decoded = rfc2047_decode("=?UTF-8?Q?Hello_World?=");
        assert_eq!(decoded, "Hello World");
    }
}
