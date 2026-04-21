//! Macro expansion, conditional processing, and `.include` directive handling.
//!
//! This module translates the macro system from C `readconf.c`:
//!
//! - `macro_create()` (lines 784–804) → [`MacroStore::create_macro()`]
//! - `macro_read_assignment()` (lines 819–917) → [`MacroStore::read_macro_assignment()`]
//! - `macros_expand()` (lines 908–1027) → [`MacroStore::expand_macros()`]
//! - `.ifdef`/`.ifndef` state machine (lines 553–624) → [`ConditionalProcessor`]
//! - `.include`/`.include_if_exists` (lines 1186–1238) → [`process_include()`]
//!
//! Per AAP §0.7.1, macro expansion behavior is identical to the C implementation:
//! left-to-right scanning, uppercase-only trigger for macro name search, and
//! per-macro replacement with position advancement to prevent infinite loops.
//!
//! Per AAP §0.7.2, this module contains zero `unsafe` code and no
//! `#[allow(...)]` attributes.

use crate::types::{ConfigError, MacroItemSnapshot};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum depth of `.ifdef`/`.ifndef` nesting.
///
/// Matches `CSTATE_STACK_SIZE` from readconf.c line 527.
pub const CSTATE_STACK_SIZE: usize = 10;

/// Maximum length of a macro (and driver) name in characters.
///
/// Matches `EXIM_DRIVERNAME_MAX` from exim.h line 171.
pub const EXIM_DRIVERNAME_MAX: usize = 64;

/// State transition table for conditional processing.
///
/// Indexed as `NEXT_CSTATE[current_state][action]` where actions are:
/// - Column 0: `.ifdef` true (macro found)
/// - Column 1: `.ifdef` false (macro not found)
/// - Column 2: `.elifdef` true / `.else`
/// - Column 3: `.elifdef` false
///
/// Row meanings:
/// - Row 0 ([`ConditionalState::Reading`]): actively reading lines
/// - Row 1 ([`ConditionalState::Skipping`]): condition failed, awaiting `.else`/`.endif`
/// - Row 2 ([`ConditionalState::SkipAll`]): branch handled, skip to `.endif`
///
/// Matches `next_cstate[3][4]` from readconf.c lines 595–603.
pub const NEXT_CSTATE: [[u8; 4]; 3] = [
    [0, 1, 2, 2], // State 0: Reading
    [2, 2, 0, 1], // State 1: Skipping
    [2, 2, 2, 2], // State 2: SkipAll
];

// ---------------------------------------------------------------------------
// MacroItem
// ---------------------------------------------------------------------------

/// A single macro definition, translating the C `macro_item` struct
/// (structs.h lines 41–48).
///
/// Fields correspond to the C struct members:
/// - `name` ↔ `name` (the macro identifier, must start with uppercase ASCII)
/// - `replacement` ↔ `replacement` (expansion text)
/// - `command_line` ↔ `command_line` (true if defined via `-D`)
#[derive(Debug, Clone)]
pub struct MacroItem {
    /// The macro name (must start with an uppercase ASCII letter).
    pub name: String,
    /// The replacement text substituted when this macro is referenced.
    pub replacement: String,
    /// `true` if the macro was defined on the command line (`-D`).
    pub command_line: bool,
}

// ---------------------------------------------------------------------------
// MacroStore
// ---------------------------------------------------------------------------

/// Container for macro definitions with expansion, assignment, and lookup.
///
/// Translates the C global `macros` linked list and the `mlast` / `macros_user`
/// pointer tracking from readconf.c.  Command-line macros (names starting with
/// `_`) are stored first, followed by user-defined macros.  The
/// [`user_start_index`](Self) field tracks where user macros begin, enabling
/// the same scan-start optimization as the C code.
#[derive(Debug, Clone)]
pub struct MacroStore {
    /// Ordered list of macro definitions.  Command-line macros appear first.
    macros: Vec<MacroItem>,
    /// Index of the first non-built-in (runtime-created) macro, matching
    /// C's `macros_user` pointer.  In C Exim, built-in macros (like
    /// `_HAVE_IPV6`) are part of a static linked list that precedes any
    /// runtime-created macros.  The `macros_user` pointer targets the
    /// first *runtime* macro — which **includes** command-line (`-D`)
    /// macros, not just config-file-defined macros.
    ///
    /// Since we have no built-in macros in the store (they are handled
    /// separately), this is effectively the index of the very first macro
    /// ever pushed into the store.
    user_start_index: Option<usize>,
    /// When `true`, print `macro 'NAME' -> 'VALUE'` to stdout for each
    /// macro expansion performed during config parsing — matching the
    /// C Exim `readconf.c:984` behaviour when both `D_any` debug mode
    /// and `f.expansion_test` (i.e. `-be` mode) are active.
    pub expansion_test_debug: bool,
}

impl MacroStore {
    /// Creates a new empty macro store.
    pub fn new() -> Self {
        Self {
            macros: Vec::new(),
            user_start_index: None,
            expansion_test_debug: false,
        }
    }

    /// Creates and appends a new macro definition.
    ///
    /// Equivalent to C `macro_create()` (readconf.c lines 784–804).
    /// The first non-command-line macro index is tracked in
    /// [`user_start_index`](Self) for expansion optimization.
    pub fn create_macro(&mut self, name: &str, value: &str, command_line: bool) {
        tracing::debug!(
            macro_name = name,
            macro_value = value,
            command_line,
            "creating macro"
        );

        let item = MacroItem {
            name: name.to_string(),
            replacement: value.to_string(),
            command_line,
        };
        self.macros.push(item);

        // Track the index of the first runtime-created macro, matching C's
        // `macros_user` pointer.  In C Exim, `macros_user` is set to the
        // first macro pushed onto the runtime list — which **includes**
        // command-line (`-D`) macros.  The `_` prefix check in
        // `expand_macros()` only affects built-in macros (which live before
        // `macros_user` in C's linked list).  Since our store has no
        // built-in macros, `user_start_index` simply points to index 0.
        if self.user_start_index.is_none() {
            self.user_start_index = Some(self.macros.len() - 1);
        }
    }

    /// Parses and processes a macro definition line.
    ///
    /// Equivalent to C `macro_read_assignment()` (readconf.c lines 819–917).
    ///
    /// Accepted syntax:
    /// - `MACRO_NAME = value` — new definition
    /// - `MACRO_NAME == value` — redefinition of an existing macro
    ///
    /// Validation rules (matching C behavior exactly):
    /// - Macro names are composed of alphanumeric and underscore characters
    /// - Names are limited to [`EXIM_DRIVERNAME_MAX`] - 1 characters
    /// - Defining a macro that already exists requires `==` syntax
    /// - An existing macro name that is a substring of the new name is rejected
    ///   (readconf.c line 877)
    /// - Command-line macros take precedence; file-defined redefinitions
    ///   of command-line macros are silently skipped
    pub fn read_macro_assignment(&mut self, line: &str) -> Result<(), ConfigError> {
        let bytes = line.as_bytes();
        let mut pos: usize = 0;

        // ── Parse macro name ────────────────────────────────────────────
        let name_start = pos;
        while pos < bytes.len() && (bytes[pos].is_ascii_alphanumeric() || bytes[pos] == b'_') {
            if pos - name_start >= EXIM_DRIVERNAME_MAX - 1 {
                return Err(ConfigError::MacroError(format!(
                    "macro name too long (maximum is {} characters)",
                    EXIM_DRIVERNAME_MAX - 1
                )));
            }
            pos += 1;
        }
        let name = &line[name_start..pos];

        // ── Skip whitespace before '=' ──────────────────────────────────
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }

        // ── Require '=' ─────────────────────────────────────────────────
        if pos >= bytes.len() || bytes[pos] != b'=' {
            return Err(ConfigError::MacroError(format!(
                "malformed macro definition: {}",
                line
            )));
        }
        pos += 1;

        // ── Check for '==' (redefinition) ───────────────────────────────
        let redef = if pos < bytes.len() && bytes[pos] == b'=' {
            pos += 1;
            true
        } else {
            false
        };

        // ── Skip whitespace after '=' or '==' ──────────────────────────
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }

        let value = &line[pos..];

        // ── Check for existing macro conflicts ──────────────────────────
        // Matches readconf.c lines 864–893.
        let mut existing_idx: Option<usize> = None;
        for (idx, m) in self.macros.iter().enumerate() {
            // Exact name match
            if m.name == name {
                if !m.command_line && !redef {
                    return Err(ConfigError::MacroError(format!(
                        "macro \"{}\" is already defined \
                         (use \"==\" if you want to redefine it)",
                        name
                    )));
                }
                existing_idx = Some(idx);
                break;
            }

            // Existing macro name is a substring of new name → error.
            // This matches readconf.c line 877:
            //   if (m->namelen < namelen && Ustrstr(name, m->name) != NULL)
            // The reverse check is deliberately absent (documented behavior).
            if m.name.len() < name.len() && name.contains(m.name.as_str()) {
                return Err(ConfigError::MacroError(format!(
                    "\"{}\" cannot be defined as a macro because previously \
                     defined macro \"{}\" is a substring",
                    name, m.name
                )));
            }
        }

        // ── Command-line macro takes precedence ─────────────────────────
        if let Some(idx) = existing_idx {
            if self.macros[idx].command_line {
                tracing::debug!(
                    macro_name = name,
                    "skipping file-defined macro; command-line definition takes precedence"
                );
                return Ok(());
            }
        }

        // ── Handle redefinition vs new definition ───────────────────────
        if redef {
            if let Some(idx) = existing_idx {
                tracing::debug!(
                    macro_name = name,
                    old_value = %self.macros[idx].replacement,
                    new_value = value,
                    "redefining macro"
                );
                self.macros[idx].replacement = value.to_string();
            } else {
                return Err(ConfigError::MacroError(format!(
                    "can't redefine an undefined macro \"{}\"",
                    name
                )));
            }
        } else {
            self.create_macro(name, value, false);
        }

        Ok(())
    }

    /// Performs macro expansion on a line, replacing all macro references
    /// with their replacement text.
    ///
    /// Equivalent to C `macros_expand()` (readconf.c lines 936–1027).
    ///
    /// # Algorithm
    ///
    /// 1. Compute the scan start position — at the start of a logical line,
    ///    skip over a potential macro definition (`NAME = ...`) to avoid
    ///    expanding the name being defined.
    /// 2. For each defined macro (in definition order), find and replace
    ///    **all** occurrences in the line from the scan position onward.
    /// 3. After each replacement, advance past the replacement text and skip
    ///    to the next potential macro character (uppercase or `_` + uppercase)
    ///    to avoid infinite loops and unnecessary scanning.
    ///
    /// # Parameters
    ///
    /// - `line`: The line buffer to expand in place.
    /// - `is_logical_start`: `true` if this is the first physical line of a
    ///   logical line (equivalent to C `len == 0`).
    ///
    /// # Returns
    ///
    /// `true` if at least one macro expansion occurred.
    pub fn expand_macros(&self, line: &mut String, is_logical_start: bool) -> bool {
        if self.macros.is_empty() || line.is_empty() {
            return false;
        }

        let scan_from = compute_scan_start(line, is_logical_start);
        if scan_from >= line.len() {
            return false;
        }

        // Determine starting macro index.  Command-line macros have names
        // beginning with '_'; user macros begin with uppercase.  If the first
        // scannable character is '_', include command-line macros in the search
        // (start from index 0).  Otherwise start from user_start_index.
        // This matches readconf.c line 969:
        //   for (macro_item * m = *s == '_' ? macros : macros_user; ...)
        let first_byte = line.as_bytes().get(scan_from).copied().unwrap_or(0);
        let start_idx = if first_byte == b'_' {
            0
        } else {
            self.user_start_index.unwrap_or(0)
        };

        let mut found = false;

        for macro_idx in start_idx..self.macros.len() {
            let name = self.macros[macro_idx].name.as_str();
            let name_len = name.len();
            let replacement = self.macros[macro_idx].replacement.as_str();

            let mut search_pos = scan_from;

            loop {
                if search_pos >= line.len() {
                    break;
                }

                match line[search_pos..].find(name) {
                    Some(offset) => {
                        let match_start = search_pos + offset;
                        let match_end = match_start + name_len;

                        tracing::trace!(
                            macro_name = name,
                            position = match_start,
                            "expanding macro occurrence"
                        );

                        // C Exim readconf.c:984: when debug+expansion_test,
                        // print macro expansion to stdout.
                        if self.expansion_test_debug {
                            println!("macro '{}' -> '{}'", name, replacement);
                        }

                        line.replace_range(match_start..match_end, replacement);
                        found = true;

                        // Advance past the replacement text, then skip to the
                        // next character that could start a macro name.
                        search_pos = match_start + replacement.len();
                        search_pos = skip_to_macro_char(line, search_pos);
                    }
                    None => break,
                }
            }
        }

        if found {
            tracing::debug!("macro expansion performed on line");
        }

        found
    }

    /// Returns `true` if a macro with the given name is defined.
    pub fn is_defined(&self, name: &str) -> bool {
        self.macros.iter().any(|m| m.name == name)
    }

    /// Returns an iterator over all macro definitions in definition order.
    pub fn iter(&self) -> impl Iterator<Item = &MacroItem> {
        self.macros.iter()
    }

    /// Returns `true` if no macros are defined.
    pub fn is_empty(&self) -> bool {
        self.macros.is_empty()
    }

    /// Returns the number of defined macros.
    pub fn len(&self) -> usize {
        self.macros.len()
    }

    /// Converts all macro definitions to [`MacroItemSnapshot`] values
    /// for `-bP` configuration printing.
    pub fn to_snapshots(&self) -> Vec<MacroItemSnapshot> {
        self.macros
            .iter()
            .map(|m| MacroItemSnapshot {
                name: m.name.clone(),
                replacement: m.replacement.clone(),
                command_line: m.command_line,
            })
            .collect()
    }
}

impl Default for MacroStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Private helper functions for macro expansion
// ---------------------------------------------------------------------------

/// Computes the byte position in `line` from which macro scanning should start.
///
/// At the start of a logical line (`is_logical_start == true`), if the line
/// begins with an uppercase letter followed by identifier characters and `=`,
/// the macro name portion is skipped to avoid expanding the name being defined.
/// This matches readconf.c lines 953–958.
fn compute_scan_start(line: &str, is_logical_start: bool) -> usize {
    let bytes = line.as_bytes();

    // Find first non-whitespace character
    let mut pos: usize = 0;
    while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
        pos += 1;
    }
    let content_start = pos;

    // At logical line start, skip over a macro definition's name portion.
    // e.g. for "MY_MACRO = value", skip past "MY_MACRO" and whitespace and "="
    // so that MY_MACRO is not expanded within its own definition line.
    if is_logical_start && pos < bytes.len() && bytes[pos].is_ascii_uppercase() {
        // Skip identifier characters
        while pos < bytes.len() && (bytes[pos].is_ascii_alphanumeric() || bytes[pos] == b'_') {
            pos += 1;
        }
        // Skip whitespace
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        // If the next character is not '=', this is not a macro definition —
        // reset to scan from the content start.
        if pos >= bytes.len() || bytes[pos] != b'=' {
            pos = content_start;
        }
        // Otherwise pos points at '=' or past it; we'll scan from here,
        // effectively skipping the macro name being defined.
    }

    // Advance to the first character that could start a macro name:
    // an uppercase ASCII letter, or '_' followed by an uppercase letter.
    skip_to_macro_char(line, pos)
}

/// Advances `start` to the next byte position in `line` where a macro name
/// could begin.
///
/// A macro name starts with an uppercase ASCII letter (for user macros) or
/// `_` followed by an uppercase letter (for command-line macros like
/// `_HAVE_TLS`).  This matches readconf.c lines 963 and 974.
fn skip_to_macro_char(line: &str, start: usize) -> usize {
    let bytes = line.as_bytes();
    let mut pos = start;
    while pos < bytes.len() {
        if bytes[pos].is_ascii_uppercase() {
            break;
        }
        if bytes[pos] == b'_' && pos + 1 < bytes.len() && bytes[pos + 1].is_ascii_uppercase() {
            break;
        }
        pos += 1;
    }
    pos
}

// ---------------------------------------------------------------------------
// ConditionalState
// ---------------------------------------------------------------------------

/// The three states of the conditional processing state machine.
///
/// Maps directly to C's `cstate` values (readconf.c lines 581, 595–603).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionalState {
    /// State 0: reading from file normally.
    Reading = 0,
    /// State 1: condition failed, skipping until `.else` or `.endif`.
    Skipping = 1,
    /// State 2: already handled this branch, skipping until `.endif`.
    SkipAll = 2,
}

impl ConditionalState {
    /// Converts a numeric value (from [`NEXT_CSTATE`]) to the corresponding
    /// variant.  Values ≥ 2 map to [`SkipAll`](Self::SkipAll).
    fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Reading,
            1 => Self::Skipping,
            _ => Self::SkipAll,
        }
    }
}

// ---------------------------------------------------------------------------
// ConditionalDirective
// ---------------------------------------------------------------------------

/// Identifies which conditional directive was encountered on a line.
///
/// Corresponds to the entries in C's `cond_list[]` (readconf.c lines 615–622).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionalDirective {
    /// `.ifdef` — branch taken if the macro *is* defined.
    Ifdef,
    /// `.ifndef` — branch taken if the macro is *not* defined.
    Ifndef,
    /// `.elifdef` — else-if branch taken if the macro *is* defined.
    Elifdef,
    /// `.elifndef` — else-if branch taken if the macro is *not* defined.
    Elifndef,
    /// `.else` — unconditional alternative branch.
    Else,
    /// `.endif` — end of conditional block.
    Endif,
}

// ---------------------------------------------------------------------------
// ConditionalAction
// ---------------------------------------------------------------------------

/// Result of processing a line through [`ConditionalProcessor::process_conditional()`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionalAction {
    /// The line was a conditional directive and has been fully processed.
    /// The caller should discard this line and continue to the next physical
    /// line.
    Continue,
    /// The line was **not** a conditional directive.  The caller should consult
    /// [`ConditionalProcessor::is_skipping()`] to decide whether to process
    /// the line or skip it.
    Skip,
    /// A fatal error occurred during conditional processing (e.g., stack
    /// overflow from excessive nesting or stack underflow from `.endif`
    /// without matching `.ifdef`).
    Error(String),
}

// ---------------------------------------------------------------------------
// Private: conditional entry table
// ---------------------------------------------------------------------------

/// Internal representation of one row in the `cond_list[]` table
/// (readconf.c lines 615–622).
struct CondEntry {
    /// The directive keyword without the leading dot (e.g., `"ifdef"`).
    name: &'static str,
    /// Column index into [`NEXT_CSTATE`] when a macro *was* found on the line.
    action_if_found: usize,
    /// Column index into [`NEXT_CSTATE`] when a macro was *not* found.
    action_if_not_found: usize,
    /// Stack manipulation: +1 = push, 0 = no change, −1 = pop.
    push_pop: i8,
}

/// The conditional directive table, matching C's `cond_list[]`.
///
/// Order matters: entries are checked sequentially, and a partial prefix match
/// that fails the whitespace check causes the search to terminate (matching
/// the C `break` on readconf.c line 1144).
const COND_LIST: &[CondEntry] = &[
    CondEntry {
        name: "ifdef",
        action_if_found: 0,
        action_if_not_found: 1,
        push_pop: 1,
    },
    CondEntry {
        name: "ifndef",
        action_if_found: 1,
        action_if_not_found: 0,
        push_pop: 1,
    },
    CondEntry {
        name: "elifdef",
        action_if_found: 2,
        action_if_not_found: 3,
        push_pop: 0,
    },
    CondEntry {
        name: "elifndef",
        action_if_found: 3,
        action_if_not_found: 2,
        push_pop: 0,
    },
    CondEntry {
        name: "else",
        action_if_found: 2,
        action_if_not_found: 2,
        push_pop: 0,
    },
    CondEntry {
        name: "endif",
        action_if_found: 0,
        action_if_not_found: 0,
        push_pop: -1,
    },
];

// ---------------------------------------------------------------------------
// ConditionalProcessor
// ---------------------------------------------------------------------------

/// State machine for processing `.ifdef`/`.ifndef`/`.elifdef`/`.elifndef`/
/// `.else`/`.endif` conditional directives in configuration files.
///
/// Translates the `cstate`, `cstate_stack`, and `cstate_stack_ptr` variables
/// from readconf.c (lines 581–583) along with the processing loop in
/// `get_config_line()` (lines 1129–1178).
///
/// # Usage
///
/// ```ignore
/// let mut cond = ConditionalProcessor::new();
/// let macro_found = store.expand_macros(&mut line, true);
///
/// match cond.process_conditional(&line, macro_found) {
///     ConditionalAction::Continue => { /* directive handled, skip line */ }
///     ConditionalAction::Skip => {
///         if cond.is_skipping() { /* skip line */ }
///         else { /* process line normally */ }
///     }
///     ConditionalAction::Error(msg) => { /* fatal error */ }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ConditionalProcessor {
    /// Current state of the conditional machine.
    state: ConditionalState,
    /// Stack of saved states for nested conditionals.
    stack: Vec<ConditionalState>,
}

impl ConditionalProcessor {
    /// Creates a new conditional processor in the initial
    /// [`Reading`](ConditionalState::Reading) state with an empty stack.
    pub fn new() -> Self {
        Self {
            state: ConditionalState::Reading,
            stack: Vec::with_capacity(CSTATE_STACK_SIZE),
        }
    }

    /// Processes a line that may contain a conditional directive.
    ///
    /// The `macro_found` parameter indicates whether [`MacroStore::expand_macros()`]
    /// found any macro expansion on this line.  The conditional state machine
    /// uses this flag to determine whether a `.ifdef` condition is "true"
    /// (macro was defined and expanded) or "false" (no expansion occurred).
    ///
    /// Matches the conditional processing loop in readconf.c `get_config_line()`
    /// lines 1129–1178.
    pub fn process_conditional(&mut self, line: &str, macro_found: bool) -> ConditionalAction {
        // The line must start with '.' (after optional leading whitespace).
        let trimmed = line.trim_start();
        if !trimmed.starts_with('.') {
            return ConditionalAction::Skip;
        }

        let after_dot = &trimmed[1..];

        // Search through the conditional directive table.
        for entry in COND_LIST {
            // Check if the text after '.' starts with the directive name.
            if !after_dot.starts_with(entry.name) {
                continue;
            }

            // The character immediately after the directive name must be
            // whitespace or end-of-string.  A non-whitespace character means
            // this is a different word (e.g., ".ifdefault") — break out of
            // the loop entirely, matching the C `break` on line 1144.
            let name_end = entry.name.len();
            if name_end < after_dot.len() {
                let next_byte = after_dot.as_bytes()[name_end];
                if next_byte != b' ' && next_byte != b'\t' && next_byte != b'\n' && next_byte != 0 {
                    break;
                }
            }

            // Select the column index in NEXT_CSTATE based on whether any
            // macro was expanded on this line.
            let action_idx = if macro_found {
                entry.action_if_found
            } else {
                entry.action_if_not_found
            };

            if entry.push_pop > 0 {
                // ── Push: .ifdef / .ifndef ───────────────────────────────
                if self.stack.len() >= CSTATE_STACK_SIZE {
                    return ConditionalAction::Error(format!(".{} nested too deeply", entry.name));
                }
                // Emit a warning when nesting is approaching the limit.
                if self.stack.len() >= CSTATE_STACK_SIZE - 2 {
                    tracing::warn!(
                        stack_depth = self.stack.len(),
                        max_depth = CSTATE_STACK_SIZE,
                        "conditional nesting approaching maximum depth"
                    );
                }
                self.stack.push(self.state);
                self.state =
                    ConditionalState::from_u8(NEXT_CSTATE[self.state as usize][action_idx]);
            } else if entry.push_pop < 0 {
                // ── Pop: .endif ──────────────────────────────────────────
                if self.stack.is_empty() {
                    return ConditionalAction::Error(format!(
                        ".{} without matching .ifdef",
                        entry.name
                    ));
                }
                self.state = self.stack.pop().expect("stack verified non-empty above");
            } else {
                // ── No change: .elifdef / .elifndef / .else ─────────────
                if self.stack.is_empty() {
                    return ConditionalAction::Error(format!(
                        ".{} without matching .ifdef",
                        entry.name
                    ));
                }
                self.state =
                    ConditionalState::from_u8(NEXT_CSTATE[self.state as usize][action_idx]);
            }

            tracing::debug!(
                directive = entry.name,
                new_state = ?self.state,
                stack_depth = self.stack.len(),
                macro_found,
                "conditional state transition"
            );

            return ConditionalAction::Continue;
        }

        // No matching conditional directive found — the line starting with '.'
        // is something else (e.g., `.include` or a regular config line).
        ConditionalAction::Skip
    }

    /// Returns `true` if the current conditional state is *not*
    /// [`Reading`](ConditionalState::Reading).
    ///
    /// When `true`, the caller should skip the current configuration line
    /// because a surrounding `.ifdef`/`.ifndef` condition evaluated to false.
    pub fn is_skipping(&self) -> bool {
        self.state != ConditionalState::Reading
    }

    /// Returns a reference to the current conditional state.
    pub fn state(&self) -> &ConditionalState {
        &self.state
    }

    /// Returns the current depth of the conditional nesting stack.
    ///
    /// A depth of 0 means no conditional blocks are open.  The maximum
    /// allowed depth is [`CSTATE_STACK_SIZE`].
    pub fn stack_depth(&self) -> usize {
        self.stack.len()
    }
}

impl Default for ConditionalProcessor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// IncludeAction
// ---------------------------------------------------------------------------

/// Describes a file to be included from a `.include` or `.include_if_exists`
/// directive.
///
/// Returned by [`process_include()`] when the line is an include directive
/// and the file should be opened by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncludeAction {
    /// Absolute path of the file to include.
    pub filename: String,
    /// `true` if this came from `.include_if_exists` (the file's absence is
    /// not an error and has already been handled by returning `None`).
    pub is_optional: bool,
}

// ---------------------------------------------------------------------------
// process_include
// ---------------------------------------------------------------------------

/// Processes a potential `.include` or `.include_if_exists` directive.
///
/// Translates the include handling from readconf.c `get_config_line()`
/// lines 1186–1238.
///
/// # Returns
///
/// - `Ok(Some(IncludeAction))` — the directive was recognized and the file
///   should be opened.
/// - `Ok(None)` — the line is not an include directive, **or** it is
///   `.include_if_exists` and the file does not exist.
/// - `Err(ConfigError)` — a fatal error (e.g., `.include` referencing a
///   non-existent file, or `.include_if_exists` with a relative path).
///
/// # Security
///
/// Per readconf.c lines 1208–1216, relative paths are resolved against
/// `config_directory` for `.include` but are **forbidden** for
/// `.include_if_exists` (to prevent file-existence probing attacks).
pub fn process_include(
    line: &str,
    config_directory: &str,
) -> Result<Option<IncludeAction>, ConfigError> {
    let trimmed = line.trim_start();

    // ── Check for ".include" prefix ─────────────────────────────────────
    if !trimmed.starts_with(".include") {
        return Ok(None);
    }

    let after_include = &trimmed[8..]; // after ".include"

    // Determine whether this is ".include" or ".include_if_exists"
    let (is_optional, rest) = if let Some(after_suffix) = after_include.strip_prefix("_if_exists") {
        // Must be followed by whitespace
        if after_suffix.is_empty() || !after_suffix.as_bytes()[0].is_ascii_whitespace() {
            return Ok(None);
        }
        (true, after_suffix)
    } else if !after_include.is_empty() && after_include.as_bytes()[0].is_ascii_whitespace() {
        (false, after_include)
    } else {
        // Not followed by whitespace or _if_exists — not an include directive.
        return Ok(None);
    };

    // ── Extract and clean the filename ──────────────────────────────────
    // Trim leading and trailing whitespace from the filename portion.
    let raw_filename = rest.trim();

    // Strip surrounding double quotes if present (readconf.c lines 1201–1205).
    let unquoted = if raw_filename.starts_with('"')
        && raw_filename.ends_with('"')
        && raw_filename.len() >= 2
    {
        &raw_filename[1..raw_filename.len() - 1]
    } else {
        raw_filename
    };

    if unquoted.is_empty() {
        return Err(ConfigError::MacroError(
            ".include directive with empty filename".to_string(),
        ));
    }

    // ── Resolve path ────────────────────────────────────────────────────
    let mut filename = unquoted.to_string();

    if !filename.starts_with('/') {
        if is_optional {
            // Relative paths are forbidden for .include_if_exists
            // (readconf.c lines 1212–1214).
            return Err(ConfigError::MacroError(format!(
                ".include_if_exists specifies a non-absolute path \"{}\"",
                filename
            )));
        }
        // Resolve relative path against config_directory
        // (readconf.c line 1216).
        filename = format!("{}/{}", config_directory, filename);
    }

    // ── Handle optional includes ────────────────────────────────────────
    if is_optional && !std::path::Path::new(&filename).exists() {
        tracing::debug!(
            filename = %filename,
            "include_if_exists: file not found, skipping"
        );
        return Ok(None);
    }

    // ── Verify file exists for mandatory includes ───────────────────────
    if !is_optional && !std::path::Path::new(&filename).exists() {
        return Err(ConfigError::FileNotFound(format!(
            "included configuration file not found: {}",
            filename
        )));
    }

    tracing::debug!(
        filename = %filename,
        is_optional,
        "processing include directive"
    );

    Ok(Some(IncludeAction {
        filename,
        is_optional,
    }))
}

// ---------------------------------------------------------------------------
// Tests (ad-hoc, to be removed before commit — validated separately)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macro_create_and_lookup() {
        let mut store = MacroStore::new();
        store.create_macro("MY_MACRO", "hello", false);
        assert!(store.is_defined("MY_MACRO"));
        assert!(!store.is_defined("NONEXISTENT"));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_macro_expand_basic() {
        let mut store = MacroStore::new();
        store.create_macro("HOST", "mail.example.com", false);

        let mut line = "server = HOST".to_string();
        let expanded = store.expand_macros(&mut line, false);
        assert!(expanded);
        assert_eq!(line, "server = mail.example.com");
    }

    #[test]
    fn test_macro_expand_no_match() {
        let mut store = MacroStore::new();
        store.create_macro("HOST", "mail.example.com", false);

        let mut line = "server = localhost".to_string();
        let expanded = store.expand_macros(&mut line, false);
        assert!(!expanded);
        assert_eq!(line, "server = localhost");
    }

    #[test]
    fn test_macro_expand_multiple_occurrences() {
        let mut store = MacroStore::new();
        store.create_macro("D", "/var", false);

        let mut line = "path = D/spool:D/log".to_string();
        let expanded = store.expand_macros(&mut line, false);
        assert!(expanded);
        assert_eq!(line, "path = /var/spool:/var/log");
    }

    #[test]
    fn test_macro_expand_skip_definition() {
        let mut store = MacroStore::new();
        store.create_macro("MY_VAR", "old_value", false);

        // At logical line start, the macro name in a definition should NOT
        // be expanded.
        let mut line = "MY_VAR = new_value".to_string();
        let expanded = store.expand_macros(&mut line, true);
        assert!(!expanded);
        assert_eq!(line, "MY_VAR = new_value");
    }

    #[test]
    fn test_macro_assignment_new() {
        let mut store = MacroStore::new();
        store
            .read_macro_assignment("MY_MACRO = hello world")
            .unwrap();
        assert!(store.is_defined("MY_MACRO"));
        assert_eq!(store.iter().next().unwrap().replacement, "hello world");
    }

    #[test]
    fn test_macro_assignment_redef() {
        let mut store = MacroStore::new();
        store.create_macro("MY_MACRO", "old", false);
        store
            .read_macro_assignment("MY_MACRO == new_value")
            .unwrap();
        assert_eq!(store.iter().next().unwrap().replacement, "new_value");
    }

    #[test]
    fn test_macro_assignment_duplicate_error() {
        let mut store = MacroStore::new();
        store.create_macro("MY_MACRO", "old", false);
        let result = store.read_macro_assignment("MY_MACRO = new_value");
        assert!(result.is_err());
    }

    #[test]
    fn test_macro_assignment_redef_undefined_error() {
        let mut store = MacroStore::new();
        let result = store.read_macro_assignment("NONEXISTENT == value");
        assert!(result.is_err());
    }

    #[test]
    fn test_macro_assignment_substring_conflict() {
        let mut store = MacroStore::new();
        store.create_macro("AB", "x", false);
        let result = store.read_macro_assignment("ABC = y");
        assert!(result.is_err());
    }

    #[test]
    fn test_macro_assignment_command_line_precedence() {
        let mut store = MacroStore::new();
        store.create_macro("MY_MACRO", "cmdline_val", true);
        // File-defined assignment should be silently skipped.
        store.read_macro_assignment("MY_MACRO = file_val").unwrap();
        assert_eq!(store.iter().next().unwrap().replacement, "cmdline_val");
    }

    #[test]
    fn test_conditional_ifdef_true() {
        let mut proc = ConditionalProcessor::new();
        // macro_found = true → ifdef condition is met
        let action = proc.process_conditional(".ifdef SOMETHING", true);
        assert_eq!(action, ConditionalAction::Continue);
        assert!(!proc.is_skipping());
        assert_eq!(proc.stack_depth(), 1);
    }

    #[test]
    fn test_conditional_ifdef_false() {
        let mut proc = ConditionalProcessor::new();
        let action = proc.process_conditional(".ifdef SOMETHING", false);
        assert_eq!(action, ConditionalAction::Continue);
        assert!(proc.is_skipping());
        assert_eq!(proc.stack_depth(), 1);
    }

    #[test]
    fn test_conditional_else_branch() {
        let mut proc = ConditionalProcessor::new();
        // ifdef false → Skipping
        proc.process_conditional(".ifdef SOMETHING", false);
        assert!(proc.is_skipping());

        // .else while Skipping → Reading
        let action = proc.process_conditional(".else", false);
        assert_eq!(action, ConditionalAction::Continue);
        assert!(!proc.is_skipping());
    }

    #[test]
    fn test_conditional_endif() {
        let mut proc = ConditionalProcessor::new();
        proc.process_conditional(".ifdef SOMETHING", true);
        assert_eq!(proc.stack_depth(), 1);

        let action = proc.process_conditional(".endif", false);
        assert_eq!(action, ConditionalAction::Continue);
        assert_eq!(proc.stack_depth(), 0);
        assert!(!proc.is_skipping());
    }

    #[test]
    fn test_conditional_stack_underflow() {
        let mut proc = ConditionalProcessor::new();
        let action = proc.process_conditional(".endif", false);
        match action {
            ConditionalAction::Error(msg) => {
                assert!(msg.contains("without matching .ifdef"));
            }
            _ => panic!("expected error for stack underflow"),
        }
    }

    #[test]
    fn test_conditional_stack_overflow() {
        let mut proc = ConditionalProcessor::new();
        for _ in 0..CSTATE_STACK_SIZE {
            let action = proc.process_conditional(".ifdef X", true);
            assert_eq!(action, ConditionalAction::Continue);
        }
        // One more should overflow
        let action = proc.process_conditional(".ifdef X", true);
        match action {
            ConditionalAction::Error(msg) => {
                assert!(msg.contains("nested too deeply"));
            }
            _ => panic!("expected error for stack overflow"),
        }
    }

    #[test]
    fn test_conditional_not_directive() {
        let mut proc = ConditionalProcessor::new();
        let action = proc.process_conditional("regular line", false);
        assert_eq!(action, ConditionalAction::Skip);
    }

    #[test]
    fn test_conditional_include_is_not_conditional() {
        let mut proc = ConditionalProcessor::new();
        let action = proc.process_conditional(".include somefile", false);
        assert_eq!(action, ConditionalAction::Skip);
    }

    #[test]
    fn test_include_basic() {
        // Use a temporary file so we can test the success path.
        let dir = std::env::temp_dir();
        let file_path = dir.join("exim_test_include_basic.conf");
        std::fs::write(&file_path, "# test include").unwrap();

        let abs_path = format!(".include {}", file_path.to_str().unwrap());
        let result = process_include(&abs_path, "/etc/exim");
        let action = result.unwrap().expect("expected Some(IncludeAction)");
        assert_eq!(action.filename, file_path.to_str().unwrap());
        assert!(!action.is_optional);

        // Clean up
        let _ = std::fs::remove_file(&file_path);
    }

    #[test]
    fn test_include_not_directive() {
        let result = process_include("some other line", "/etc/exim");
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_include_if_exists_relative_path_error() {
        let result = process_include(".include_if_exists relative.conf", "/etc/exim");
        assert!(result.is_err());
    }

    #[test]
    fn test_include_relative_resolved() {
        // .include with relative path should resolve against config_directory.
        // The file won't exist, so we expect FileNotFound error.
        let result = process_include(".include relative.conf", "/etc/exim");
        match result {
            Err(ConfigError::FileNotFound(msg)) => {
                assert!(msg.contains("/etc/exim/relative.conf"));
            }
            Ok(Some(inc)) => {
                // File happens to exist on this system
                assert_eq!(inc.filename, "/etc/exim/relative.conf");
            }
            _ => panic!("unexpected result for relative .include"),
        }
    }

    #[test]
    fn test_to_snapshots() {
        let mut store = MacroStore::new();
        store.create_macro("A", "val_a", false);
        store.create_macro("B", "val_b", true);
        let snaps = store.to_snapshots();
        assert_eq!(snaps.len(), 2);
        assert_eq!(snaps[0].name, "A");
        assert!(!snaps[0].command_line);
        assert_eq!(snaps[1].name, "B");
        assert!(snaps[1].command_line);
    }

    #[test]
    fn test_conditional_ifndef_true() {
        let mut proc = ConditionalProcessor::new();
        // macro_found = false → ifndef condition is met (macro NOT defined)
        let action = proc.process_conditional(".ifndef SOMETHING", false);
        assert_eq!(action, ConditionalAction::Continue);
        assert!(!proc.is_skipping());
    }

    #[test]
    fn test_conditional_ifndef_false() {
        let mut proc = ConditionalProcessor::new();
        // macro_found = true → ifndef condition NOT met (macro IS defined)
        let action = proc.process_conditional(".ifndef SOMETHING", true);
        assert_eq!(action, ConditionalAction::Continue);
        assert!(proc.is_skipping());
    }

    #[test]
    fn test_nested_conditionals() {
        let mut proc = ConditionalProcessor::new();

        // Outer: .ifdef true → Reading
        proc.process_conditional(".ifdef OUTER", true);
        assert!(!proc.is_skipping());
        assert_eq!(proc.stack_depth(), 1);

        // Inner: .ifdef false → Skipping
        proc.process_conditional(".ifdef INNER", false);
        assert!(proc.is_skipping());
        assert_eq!(proc.stack_depth(), 2);

        // .endif inner → back to Reading
        proc.process_conditional(".endif", false);
        assert!(!proc.is_skipping());
        assert_eq!(proc.stack_depth(), 1);

        // .endif outer → back to initial state
        proc.process_conditional(".endif", false);
        assert!(!proc.is_skipping());
        assert_eq!(proc.stack_depth(), 0);
    }

    #[test]
    fn test_elifdef_transition() {
        let mut proc = ConditionalProcessor::new();

        // .ifdef false → Skipping
        proc.process_conditional(".ifdef X", false);
        assert!(proc.is_skipping());

        // .elifdef true while Skipping → Reading (column 2 in state 1 = 0)
        proc.process_conditional(".elifdef Y", true);
        assert!(!proc.is_skipping());

        // .endif → pop
        proc.process_conditional(".endif", false);
        assert_eq!(proc.stack_depth(), 0);
    }

    #[test]
    fn test_macro_name_too_long() {
        let mut store = MacroStore::new();
        let long_name = "A".repeat(EXIM_DRIVERNAME_MAX);
        let line = format!("{} = value", long_name);
        let result = store.read_macro_assignment(&line);
        assert!(result.is_err());
    }

    #[test]
    fn test_include_quoted_filename() {
        // We can only test the parsing; actual file existence is system-dependent.
        let result = process_include(".include \"/absolute/path/to/file.conf\"", "/etc/exim");
        match result {
            Ok(Some(inc)) => {
                assert_eq!(inc.filename, "/absolute/path/to/file.conf");
            }
            Err(ConfigError::FileNotFound(msg)) => {
                assert!(msg.contains("/absolute/path/to/file.conf"));
            }
            _ => panic!("unexpected result"),
        }
    }

    #[test]
    fn test_default_implementations() {
        let store = MacroStore::default();
        assert_eq!(store.len(), 0);

        let proc = ConditionalProcessor::default();
        assert!(!proc.is_skipping());
        assert_eq!(proc.stack_depth(), 0);
    }
}
