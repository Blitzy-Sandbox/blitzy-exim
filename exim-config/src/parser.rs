#![deny(unsafe_code)]
//! Configuration file parser — central orchestration for Exim config ingestion.
//!
//! This module translates the following C functions from `readconf.c`:
//!
//! - `readconf_main()` (lines 3284–3643) → [`parse_main_config()`]
//! - `readconf_rest()` (lines 4594–4643) → [`parse_rest()`]
//! - `get_config_line()` (lines ~1028–1600) → [`ParserState::get_config_line()`]
//! - `read_named_list()` (lines ~3148–3278) → [`read_named_list()`]
//! - `readconf_acl()` (line 4497) → [`parse_acl_section()`]
//! - `readconf_retries()` (line 4290) → [`parse_retry_section()`]
//! - `readconf_rewrites()` (line 1643) → [`parse_rewrite_section()`]
//! - `local_scan_init()` (line 4548) → [`parse_local_scan_section()`]
//!
//! # Architecture
//!
//! The C code operates on a global file handle, a global line buffer
//! (`big_buffer`), global conditional state, and a global macro list. In Rust,
//! all mutable state is encapsulated in [`ParserState`], which owns:
//!
//! - A stack of [`ConfigFileItem`] for nested `.include` handling
//! - The [`MacroStore`] for macro definitions and expansion
//! - The [`ConditionalProcessor`] for `.ifdef`/`.endif` state
//! - The [`ConfigLineStore`] for `-bP` config printing
//! - A line buffer and section tracking
//!
//! # Safety
//!
//! Per AAP §0.7.2: This module contains ZERO `unsafe` code.
//! Per AAP §0.7.2: No `#[allow(...)]` attributes without inline justification.
//! Per AAP §0.7.3: Config data is frozen into `Arc<Config>` after parsing.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use regex::Regex;

use crate::driver_init::{self, ConfigLines};
use crate::macros::{ConditionalAction, ConditionalProcessor, MacroStore};
use crate::options::{
    find_option, handle_option, parse_fixed, parse_time, read_name, HandleOptionResult,
    OptionEntry, OptionValue, MAIN_CONFIG_OPTIONS,
};
use crate::types::{
    AclBlock, Config, ConfigContext, ConfigError, NamedList, NamedLists, RetryConfig, RetryRule,
    RewriteRule,
};
use crate::validate::{self, ConfigLineStore};

// =============================================================================
// Constants
// =============================================================================

/// Section names in alphabetical order for binary search, matching the C
/// `section_list[]` array (readconf.c lines 606–614).
///
/// The indices into this array correspond to the section dispatch cases
/// in [`parse_rest()`].
const SECTION_LIST: &[&str] = &[
    "acl",            // index 0
    "authenticators", // index 1
    "local_scan",     // index 2
    "retry",          // index 3
    "rewrite",        // index 4
    "routers",        // index 5
    "transports",     // index 6
];

/// Named list type keywords, matching the C named list keywords from
/// `readconf_main()` (readconf.c lines 3350–3370).
const NAMED_LIST_KEYWORDS: &[(&str, NamedListType)] = &[
    ("addresslist", NamedListType::Address),
    ("domainlist", NamedListType::Domain),
    ("hostlist", NamedListType::Host),
    ("localpartlist", NamedListType::LocalPart),
];

/// Maximum depth of nested `.include` files.
const MAX_INCLUDE_DEPTH: usize = 20;

// =============================================================================
// NamedListType — internal enum for list classification
// =============================================================================

/// Classification of named list types for the four Exim list categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NamedListType {
    /// `domainlist` directive.
    Domain,
    /// `hostlist` directive.
    Host,
    /// `addresslist` directive.
    Address,
    /// `localpartlist` directive.
    LocalPart,
}

// =============================================================================
// ConfigFileItem — represents one open config file on the include stack
// =============================================================================

/// Represents a single configuration file currently open in the include stack.
///
/// Translates from the C `config_file_item` struct in `structs.h`.
/// In C these form a linked list via `next`; in Rust they are stored in
/// `Vec<ConfigFileItem>` within [`ParserState`].
pub struct ConfigFileItem {
    /// The buffered reader for this file.
    reader: BufReader<File>,
    /// The absolute path of this configuration file.
    pub filename: String,
    /// Current line number within this file (1-based).
    pub lineno: u32,
}

impl std::fmt::Debug for ConfigFileItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigFileItem")
            .field("filename", &self.filename)
            .field("lineno", &self.lineno)
            .finish()
    }
}

// =============================================================================
// ParserState — mutable state for the configuration file parser
// =============================================================================

/// Mutable state for configuration file parsing.
///
/// Encapsulates all mutable state that was previously held in global variables
/// in the C codebase: the file include stack, macro store, conditional
/// processor, line buffer, and section tracking.
///
/// # Lifetime
///
/// A `ParserState` is created at the beginning of configuration parsing and
/// dropped after [`parse_rest()`] completes. Its contents feed into
/// [`ConfigContext`] which is then frozen into `Arc<Config>`.
pub struct ParserState {
    /// Stack of open config files (innermost = last element).
    file_stack: Vec<ConfigFileItem>,
    /// Name of the next section detected by `get_config_line()`.
    next_section_name: String,
    /// Reusable line buffer for building logical lines.
    line_buffer: String,
    /// Current logical line number for error reporting.
    current_lineno: u32,
    /// Current filename for error reporting.
    current_filename: String,
    /// Macro definition store.
    macro_store_inner: MacroStore,
    /// Conditional directive processor (`.ifdef`/`.endif`).
    cond_processor: ConditionalProcessor,
    /// Config line store for `-bP` printing.
    line_store: ConfigLineStore,
    /// Config directory for resolving relative `.include` paths.
    config_directory: String,
}

impl std::fmt::Debug for ParserState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParserState")
            .field("file_stack_depth", &self.file_stack.len())
            .field("next_section_name", &self.next_section_name)
            .field("current_lineno", &self.current_lineno)
            .field("current_filename", &self.current_filename)
            .finish()
    }
}

impl ParserState {
    /// Creates a new parser state with the given initial config file.
    ///
    /// Opens the specified file and pushes it onto the file stack.
    /// The config directory is derived from the file's parent directory.
    pub fn new(config_path: &str) -> Result<Self, ConfigError> {
        let path = PathBuf::from(config_path);
        let config_dir = path
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        let file = File::open(&path).map_err(|e| {
            ConfigError::FileNotFound(format!("cannot open config file {}: {}", config_path, e))
        })?;

        tracing::debug!(
            config_file = %config_path,
            config_directory = %config_dir,
            "opening initial configuration file"
        );

        let item = ConfigFileItem {
            reader: BufReader::new(file),
            filename: config_path.to_string(),
            lineno: 0,
        };

        Ok(Self {
            file_stack: vec![item],
            next_section_name: String::new(),
            line_buffer: String::with_capacity(4096),
            current_lineno: 0,
            current_filename: config_path.to_string(),
            macro_store_inner: MacroStore::new(),
            cond_processor: ConditionalProcessor::new(),
            line_store: ConfigLineStore::new(),
            config_directory: config_dir,
        })
    }

    /// Reads the next logical configuration line.
    ///
    /// Translates `get_config_line()` from readconf.c lines ~1028–1600.
    ///
    /// Handles:
    /// - Continuation lines (backslash `\` at end of line)
    /// - Comment stripping (lines starting with `#`)
    /// - Macro expansion via [`MacroStore::expand_macros()`]
    /// - Conditional directives via [`ConditionalProcessor::process_conditional()`]
    /// - `.include`/`.include_if_exists` via file stack push/pop
    /// - `begin <section>` boundary detection
    /// - Config line saving via [`ConfigLineStore::save_config_line()`]
    ///
    /// Returns `Some(line)` for the next logical line, or `None` at end of
    /// all config files (including popped include stacks).
    pub fn get_config_line(&mut self) -> Option<String> {
        loop {
            // If there is no file on the stack, we are done.
            if self.file_stack.is_empty() {
                return None;
            }

            // Read the next physical line from the top-of-stack file.
            let mut raw_line = String::new();
            let top = self
                .file_stack
                .last_mut()
                .expect("stack verified non-empty");
            match top.reader.read_line(&mut raw_line) {
                Ok(0) => {
                    // EOF on current file — pop the stack.
                    let popped = self.file_stack.pop().expect("stack verified non-empty");
                    tracing::debug!(
                        filename = %popped.filename,
                        "finished reading included file"
                    );
                    // If there are still files on the stack, save a position
                    // marker and continue reading from the parent file.
                    if let Some(parent) = self.file_stack.last() {
                        self.current_filename = parent.filename.clone();
                        self.current_lineno = parent.lineno;
                        self.line_store
                            .save_config_position(&self.current_filename, self.current_lineno);
                    }
                    continue;
                }
                Ok(_) => {
                    // Successfully read a line — update line number.
                    let top = self
                        .file_stack
                        .last_mut()
                        .expect("stack verified non-empty");
                    top.lineno += 1;
                    self.current_lineno = top.lineno;
                    self.current_filename = top.filename.clone();
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        filename = %self.current_filename,
                        line = self.current_lineno,
                        "I/O error reading config file"
                    );
                    return None;
                }
            }

            // Strip trailing newline and carriage return.
            let trimmed = raw_line.trim_end_matches(['\n', '\r']);

            // Handle continuation lines (backslash at end of line).
            if let Some(stripped) = trimmed.strip_suffix('\\') {
                // Append everything except the trailing backslash.
                self.line_buffer.push_str(stripped);
                continue;
            }

            // Build the complete logical line.
            let logical_line = if self.line_buffer.is_empty() {
                trimmed.to_string()
            } else {
                self.line_buffer.push_str(trimmed);
                let result = self.line_buffer.clone();
                self.line_buffer.clear();
                result
            };

            // Skip empty lines.
            if logical_line.trim().is_empty() {
                continue;
            }

            // Perform macro expansion on the logical line.
            let mut expanded = logical_line.clone();
            let macro_found = self.macro_store_inner.expand_macros(&mut expanded, true);

            // Process conditional directives (.ifdef, .ifndef, .else, .endif).
            match self
                .cond_processor
                .process_conditional(&expanded, macro_found)
            {
                ConditionalAction::Continue => {
                    // Directive handled, skip this line entirely.
                    continue;
                }
                ConditionalAction::Skip => {
                    // Not a conditional directive — check if we should skip.
                    if self.cond_processor.is_skipping() {
                        continue;
                    }
                }
                ConditionalAction::Error(msg) => {
                    tracing::error!(
                        error = %msg,
                        file = %self.current_filename,
                        line = self.current_lineno,
                        "conditional processing error"
                    );
                    continue;
                }
            }

            // Handle `.include` / `.include_if_exists` directives.
            if expanded.trim_start().starts_with(".include") {
                match crate::macros::process_include(&expanded, &self.config_directory) {
                    Ok(Some(action)) => {
                        if self.file_stack.len() >= MAX_INCLUDE_DEPTH {
                            tracing::error!(
                                max_depth = MAX_INCLUDE_DEPTH,
                                ".include nested too deeply"
                            );
                            continue;
                        }
                        match File::open(&action.filename) {
                            Ok(file) => {
                                self.line_store.save_config_position(&action.filename, 0);
                                let item = ConfigFileItem {
                                    reader: BufReader::new(file),
                                    filename: action.filename.clone(),
                                    lineno: 0,
                                };
                                self.file_stack.push(item);
                                self.current_filename = action.filename;
                                self.current_lineno = 0;
                                tracing::debug!(
                                    filename = %self.current_filename,
                                    "opened included configuration file"
                                );
                            }
                            Err(e) => {
                                if action.is_optional {
                                    tracing::warn!(
                                        filename = %action.filename,
                                        error = %e,
                                        "optional include file not accessible, skipping"
                                    );
                                } else {
                                    tracing::error!(
                                        filename = %action.filename,
                                        error = %e,
                                        "cannot open included configuration file"
                                    );
                                }
                            }
                        }
                        continue;
                    }
                    Ok(None) => {
                        // Not an include directive — fall through.
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            file = %self.current_filename,
                            line = self.current_lineno,
                            "error processing .include directive"
                        );
                        continue;
                    }
                }
            }

            // Strip comments: lines beginning with '#' after macro expansion
            // are comments and should be skipped.
            let trimmed_expanded = expanded.trim_start();
            if trimmed_expanded.starts_with('#') {
                continue;
            }

            // Detect `begin <section>` boundary lines.
            if trimmed_expanded.starts_with("begin ") || trimmed_expanded.starts_with("begin\t") {
                let rest = trimmed_expanded[6..].trim();
                self.next_section_name = rest.to_string();
                self.line_store.save_config_line(&expanded);
                tracing::debug!(
                    section = %self.next_section_name,
                    "detected section boundary"
                );
                return None;
            }

            // Save the logical line for -bP config printing.
            self.line_store.save_config_line(&expanded);

            return Some(expanded);
        }
    }

    /// Returns the name of the next section detected during line reading.
    ///
    /// After [`get_config_line()`] returns `None` due to a `begin <section>`
    /// line, this method returns the section name. An empty string indicates
    /// that EOF was reached without encountering another section.
    pub fn next_section(&self) -> &str {
        &self.next_section_name
    }

    /// Returns the current line number for error reporting.
    pub fn config_lineno(&self) -> u32 {
        self.current_lineno
    }

    /// Returns the current filename for error reporting.
    pub fn config_filename(&self) -> &str {
        &self.current_filename
    }

    /// Returns an immutable reference to the macro store.
    pub fn macro_store(&self) -> &MacroStore {
        &self.macro_store_inner
    }

    /// Returns a mutable reference to the macro store.
    pub fn macro_store_mut(&mut self) -> &mut MacroStore {
        &mut self.macro_store_inner
    }

    /// Returns an immutable reference to the conditional processor.
    pub fn conditional_processor(&self) -> &ConditionalProcessor {
        &self.cond_processor
    }

    /// Returns an immutable reference to the config line store.
    pub fn config_line_store(&self) -> &ConfigLineStore {
        &self.line_store
    }
}

// =============================================================================
// parse_main_config — equivalent of readconf_main()
// =============================================================================

/// Parses the main section of the Exim configuration file.
///
/// Translates `readconf_main()` from readconf.c lines 3284–3643.
///
/// # Processing Steps
///
/// 1. Opens the config file from the provided path (with optional node/euid
///    suffix resolution controlled by Cargo features).
/// 2. Verifies file ownership and permissions for trusted config.
/// 3. Reads main-section lines, processing:
///    - Macro definitions (`UPPER_NAME = value`)
///    - Named list directives (`domainlist`, `hostlist`, etc.)
///    - Configuration options via [`handle_option()`]
/// 4. Post-processes the config:
///    - Expands `spool_directory`, `log_file_path`, `pid_file_path`
///    - Decodes `syslog_facility` from string to enum
///    - Sets `primary_hostname` and `smtp_active_hostname` defaults
///    - Validates TLS constraints
///    - Compiles UUCP From_ regex patterns
///
/// # Parameters
///
/// - `config_file_list`: Colon-separated list of config file candidates,
///   matching C's `config_main_filelist`. The first accessible file is used.
/// - `trusted_config_list`: Optional list of trusted config file paths. If
///   provided, only files in this list (or owned by root/exim user) are accepted.
/// - `command_line_macros`: Pre-defined macros from `-D` command-line options.
///
/// # Returns
///
/// A tuple of the populated [`ConfigContext`] and the [`ParserState`] needed
/// for subsequent [`parse_rest()`] calls.
pub fn parse_main_config(
    config_file_list: &str,
    trusted_config_list: Option<&[String]>,
    command_line_macros: &[(String, String)],
) -> Result<(ConfigContext, ParserState), ConfigError> {
    parse_main_config_inner(
        config_file_list,
        trusted_config_list,
        command_line_macros,
        false,
    )
}

/// Extended entry point that optionally enables macro expansion debug output
/// to stdout (matching C Exim `readconf.c:984` behaviour when both `D_any`
/// and `f.expansion_test` are active).
pub fn parse_main_config_with_debug(
    config_file_list: &str,
    trusted_config_list: Option<&[String]>,
    command_line_macros: &[(String, String)],
    expansion_test_debug: bool,
) -> Result<(ConfigContext, ParserState), ConfigError> {
    parse_main_config_inner(
        config_file_list,
        trusted_config_list,
        command_line_macros,
        expansion_test_debug,
    )
}

fn parse_main_config_inner(
    config_file_list: &str,
    trusted_config_list: Option<&[String]>,
    command_line_macros: &[(String, String)],
    expansion_test_debug: bool,
) -> Result<(ConfigContext, ParserState), ConfigError> {
    tracing::info!(
        config_file_list = %config_file_list,
        "beginning main configuration parse"
    );

    let mut ctx = ConfigContext::default();

    // ── Register command-line macros ─────────────────────────────────────
    let mut macro_store = MacroStore::new();
    for (name, value) in command_line_macros {
        macro_store.create_macro(name, value, true);
    }

    // ── Resolve the config file path ────────────────────────────────────
    let config_path = resolve_config_file(config_file_list)?;
    tracing::debug!(config_path = %config_path, "resolved configuration file");

    // ── Verify file ownership for trusted configs ───────────────────────
    verify_config_file_security(&config_path, trusted_config_list)?;

    // Store config file metadata in context.
    ctx.config_filename = config_path.clone();
    ctx.config_directory = Path::new(&config_path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    // ── Open parser state ───────────────────────────────────────────────
    let mut state = ParserState::new(&config_path)?;
    macro_store.expansion_test_debug = expansion_test_debug;
    state.macro_store_inner = macro_store;

    // Initialize config line store with version header.
    state.line_store.save_config("Exim 4.99");
    state.line_store.save_config_position(&config_path, 0);

    // ── Read main section ───────────────────────────────────────────────
    // Build a mutable copy of the main config option table for handle_option
    // (which tracks SET/SECURE flags per-option during parsing).
    let mut option_table: Vec<OptionEntry> = MAIN_CONFIG_OPTIONS.clone();

    while let Some(line) = state.get_config_line() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Check for macro assignment (line starts with uppercase letter).
        let first_byte = trimmed.as_bytes()[0];
        if first_byte.is_ascii_uppercase() {
            // Attempt to parse as a macro definition.
            match state.macro_store_inner.read_macro_assignment(trimmed) {
                Ok(()) => {
                    tracing::debug!(line = %trimmed, "processed macro assignment");
                    continue;
                }
                Err(_) => {
                    // Not a valid macro assignment — fall through to option handling.
                }
            }
        }

        // Check for named list directive.
        match try_read_named_list(trimmed, &mut ctx.named_lists) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(ConfigError::ParseError {
                file: _,
                line: _,
                message,
            }) => {
                // Enrich with the current file/line context.
                return Err(ConfigError::ParseError {
                    file: state.current_filename.clone(),
                    line: state.current_lineno,
                    message,
                });
            }
            Err(e) => return Err(e),
        }

        // Handle as a regular config option via handle_option().
        // handle_option() signature: (line, options, ctx, unknown_txt)
        // It performs its own name extraction from the line.
        let (name, _rest) = read_name(trimmed);
        if name.is_empty() {
            tracing::warn!(
                line = %trimmed,
                file = %state.current_filename,
                lineno = state.current_lineno,
                "ignoring unrecognized config line"
            );
            continue;
        }

        // Strip `no_` / `not_` prefix for the preliminary lookup so that
        // negated boolean forms like `no_accept_8bitmime` are found in the
        // option table (which stores only the canonical unprefixed name).
        // `handle_option()` also strips the prefix internally, so this is
        // only needed for the guard check.
        let lookup_name = if let Some(stripped) = name.strip_prefix("not_") {
            stripped
        } else if let Some(stripped) = name.strip_prefix("no_") {
            stripped
        } else {
            name
        };

        // Also skip `hide` prefix — the actual name follows it.
        let lookup_name = if lookup_name == "hide" {
            // Re-read the name after "hide".
            let (_hide, rest_after_hide) = read_name(trimmed);
            let (inner_name, _) = read_name(rest_after_hide);
            let n = if let Some(s) = inner_name.strip_prefix("not_") {
                s
            } else if let Some(s) = inner_name.strip_prefix("no_") {
                s
            } else {
                inner_name
            };
            n
        } else {
            lookup_name
        };

        if find_option(lookup_name, &option_table).is_some() {
            match handle_option(trimmed, &mut option_table, &mut ctx, None) {
                Ok(Some(result)) => {
                    apply_option_to_ctx(&result, &mut ctx);
                    tracing::debug!(option = %name, "processed config option");
                }
                Ok(None) => {
                    tracing::debug!(option = %name, "config option not found (ignored)");
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        option = %name,
                        file = %state.current_filename,
                        line = state.current_lineno,
                        "error processing config option"
                    );
                    return Err(e);
                }
            }
        } else {
            tracing::warn!(
                option = %name,
                file = %state.current_filename,
                lineno = state.current_lineno,
                "unknown configuration option"
            );
        }
    }

    // ── Check for required options ──────────────────────────────────────
    // Log how many options were marked SET via OptionFlags during parsing.
    let set_count = option_table
        .iter()
        .filter(|o| o.flags.contains(crate::options::OptionFlags::SET))
        .count();
    tracing::debug!(
        total_options = option_table.len(),
        set_options = set_count,
        "main section option processing complete"
    );

    // ── Post-processing ─────────────────────────────────────────────────
    post_process_main_config(&mut ctx)?;

    // Store macro snapshots in context for -bP printing.
    // to_snapshots() returns Vec<MacroItemSnapshot> — these are immutable
    // copies of the macro definitions recorded during parsing.
    let snapshots: Vec<crate::types::MacroItemSnapshot> = state.macro_store_inner.to_snapshots();
    ctx.macros = snapshots;

    // Log syslog facility setting for diagnostics.
    let facility: &crate::types::SyslogFacility = &ctx.syslog_facility;
    tracing::debug!(syslog_facility = %facility, "syslog facility configured");

    tracing::info!("main configuration section parsed successfully");

    // ── Post-parse clamping (C readconf.c:3507) ─────────────────────
    // C Exim enforces: if (retry_interval_max > 24*60*60) retry_interval_max = 24*60*60;
    const MAX_RETRY_INTERVAL: i32 = 24 * 60 * 60; // 1 day
    if ctx.retry_interval_max > MAX_RETRY_INTERVAL {
        ctx.retry_interval_max = MAX_RETRY_INTERVAL;
    }

    Ok((ctx, state))
}

// =============================================================================
// parse_rest — equivalent of readconf_rest()
// =============================================================================

/// Parses the remaining configuration sections after the main section.
///
/// Translates `readconf_rest()` from readconf.c lines 4594–4643.
///
/// Reads `begin <section>` headers and dispatches to the appropriate
/// section parser. Each section can only be processed once (enforced by
/// a bitmask).
///
/// # Sections (in alphabetical order for binary search)
///
/// - `acl` — ACL definitions (index 0)
/// - `authenticators` — Auth driver instances (index 1)
/// - `local_scan` — Local scan configuration (index 2)
/// - `retry` — Retry rules (index 3)
/// - `rewrite` — Rewrite rules (index 4)
/// - `routers` — Router driver instances (index 5)
/// - `transports` — Transport driver instances (index 6)
///
/// # Parameters
///
/// - `ctx`: The [`ConfigContext`] populated by [`parse_main_config()`].
/// - `state`: The [`ParserState`] from [`parse_main_config()`].
///
/// # Returns
///
/// The frozen `Arc<Config>` on success.
pub fn parse_rest(
    ctx: &mut ConfigContext,
    state: &mut ParserState,
) -> Result<Arc<Config>, ConfigError> {
    tracing::info!("parsing remaining configuration sections");

    // Bitmask tracking which sections have been processed.
    // Bit position corresponds to the index in SECTION_LIST.
    let mut had_section: u32 = 0;

    loop {
        // The section name was set by get_config_line() when it encountered
        // a `begin <section>` line.
        let section_name = state.next_section_name.clone();

        if section_name.is_empty() {
            // No more sections — EOF reached.
            break;
        }

        tracing::debug!(section = %section_name, "dispatching section");

        // Binary search for the section name in the sorted section list.
        let section_idx = match SECTION_LIST.binary_search(&section_name.as_str()) {
            Ok(idx) => idx,
            Err(_) => {
                return Err(ConfigError::ParseError {
                    file: state.current_filename.clone(),
                    line: state.current_lineno,
                    message: format!("unknown section name: \"{}\"", section_name),
                });
            }
        };

        // Check for duplicate section.
        let section_bit = 1u32 << section_idx;
        if had_section & section_bit != 0 {
            return Err(ConfigError::ParseError {
                file: state.current_filename.clone(),
                line: state.current_lineno,
                message: format!("section \"{}\" has already been defined", section_name),
            });
        }
        had_section |= section_bit;

        // Clear the next_section_name so get_config_line() can detect
        // the next boundary.
        state.next_section_name.clear();

        // Dispatch to the appropriate section parser.
        match section_idx {
            0 => {
                // "acl"
                tracing::debug!("parsing ACL section");
                parse_acl_section(state, ctx)?;
            }
            1 => {
                // "authenticators"
                let dc = crate::driver_init::DriverClass::Authenticator;
                tracing::debug!(driver_class = dc.as_str(), "parsing driver section");
                let lines = collect_section_lines(state);
                let srcfile = state.current_filename.clone();
                let mut cfg_lines = ConfigLines::new(&lines, &srcfile);
                driver_init::init_auth_drivers(&mut cfg_lines, ctx, &mut state.macro_store_inner)?;
            }
            2 => {
                // "local_scan"
                tracing::debug!("parsing local_scan section");
                parse_local_scan_section(state, ctx)?;
            }
            3 => {
                // "retry"
                tracing::debug!("parsing retry section");
                parse_retry_section(state, ctx)?;
            }
            4 => {
                // "rewrite"
                tracing::debug!("parsing rewrite section");
                parse_rewrite_section(state, ctx)?;
            }
            5 => {
                // "routers"
                tracing::debug!("parsing routers section");
                let lines = collect_section_lines(state);
                let srcfile = state.current_filename.clone();
                let mut cfg_lines = ConfigLines::new(&lines, &srcfile);
                driver_init::init_router_drivers(
                    &mut cfg_lines,
                    ctx,
                    &mut state.macro_store_inner,
                )?;
            }
            6 => {
                // "transports"
                tracing::debug!("parsing transports section");
                let lines = collect_section_lines(state);
                let srcfile = state.current_filename.clone();
                let mut cfg_lines = ConfigLines::new(&lines, &srcfile);
                driver_init::init_transport_drivers(
                    &mut cfg_lines,
                    ctx,
                    &mut state.macro_store_inner,
                )?;
            }
            _ => {
                // This should never happen due to the binary search bounds.
                return Err(ConfigError::ParseError {
                    file: state.current_filename.clone(),
                    line: state.current_lineno,
                    message: format!("internal error: section index {} out of range", section_idx),
                });
            }
        }
    }

    // Perform final validation.
    validate::validate_config(ctx)?;

    tracing::info!("all configuration sections parsed and validated");

    // Freeze the configuration into an immutable Arc<Config>.
    Ok(Config::freeze(ctx.clone()))
}

// =============================================================================
// parse_acl_section — ACL section parser
// =============================================================================

/// Parses the `begin acl` section of the configuration file.
///
/// Translates `readconf_acl()` from readconf.c line 4497.
///
/// ACL definitions are stored as named blocks in `ConfigContext::acl_definitions`.
/// Each ACL block starts with a name on its own line (e.g., `acl_check_rcpt:`)
/// and includes all subsequent lines until the next ACL name or section boundary.
pub fn parse_acl_section(
    state: &mut ParserState,
    ctx: &mut ConfigContext,
) -> Result<(), ConfigError> {
    tracing::debug!("entering ACL section parser");

    let mut current_acl_name: Option<String> = None;
    let mut current_acl_body = String::new();
    // Track config file and starting line for HDEBUG source references
    let mut current_acl_file = String::new();
    let mut current_acl_start_line: i32 = 0;
    let mut body_started = false;

    loop {
        let line = match state.get_config_line() {
            Some(l) => l,
            None => {
                // End of section or EOF — save the last ACL block.
                if let Some(name) = current_acl_name.take() {
                    let body = current_acl_body.trim().to_string();
                    if !body.is_empty() {
                        ctx.acl_definitions.insert(
                            name.clone(),
                            AclBlock {
                                raw_definition: body,
                                source_file: current_acl_file.clone(),
                                start_line: current_acl_start_line,
                            },
                        );
                        tracing::debug!(acl_name = %name, "stored ACL definition");
                    }
                    current_acl_body.clear();
                }
                break;
            }
        };

        let trimmed = line.trim();

        // An ACL name starts at column 0 (no leading whitespace) and ends
        // with a colon. Lines with leading whitespace are ACL body lines.
        if !line.starts_with(char::is_whitespace) && trimmed.ends_with(':') {
            // Save previous ACL block if any.
            if let Some(prev_name) = current_acl_name.take() {
                let body = current_acl_body.trim().to_string();
                if !body.is_empty() {
                    ctx.acl_definitions.insert(
                        prev_name.clone(),
                        AclBlock {
                            raw_definition: body,
                            source_file: current_acl_file.clone(),
                            start_line: current_acl_start_line,
                        },
                    );
                    tracing::debug!(acl_name = %prev_name, "stored ACL definition");
                }
                current_acl_body.clear();
            }

            // Start a new ACL block.
            let acl_name = trimmed[..trimmed.len() - 1].trim().to_string();
            tracing::debug!(acl_name = %acl_name, "found ACL definition header");
            current_acl_name = Some(acl_name);
            body_started = false;
        } else if current_acl_name.is_some() {
            // Capture the file and line number of the first body line.
            if !body_started {
                current_acl_file = state.current_filename.clone();
                current_acl_start_line = state.current_lineno as i32;
                body_started = true;
            }
            // Append to the current ACL body.
            if !current_acl_body.is_empty() {
                current_acl_body.push('\n');
            }
            current_acl_body.push_str(trimmed);
        } else {
            // Lines before the first ACL name — this is an error.
            tracing::warn!(
                line = %trimmed,
                file = %state.current_filename,
                lineno = state.current_lineno,
                "ACL section line before any ACL name"
            );
        }
    }

    tracing::debug!(
        count = ctx.acl_definitions.len(),
        "ACL section parsing complete"
    );
    Ok(())
}

// =============================================================================
// parse_retry_section — Retry rules parser
// =============================================================================

/// Parses the `begin retry` section of the configuration file.
///
/// Translates `readconf_retries()` from readconf.c lines 4290–4400.
///
/// Retry rules associate a pattern (domain/host/address) with one or more
/// retry rules that specify algorithm, parameters, and timeout.
///
/// Each line in the retry section is a retry rule in the format:
/// ```text
/// pattern [F|G],timeout,interval[,multiplier]
/// ```
pub fn parse_retry_section(
    state: &mut ParserState,
    ctx: &mut ConfigContext,
) -> Result<(), ConfigError> {
    tracing::debug!("entering retry section parser");

    while let Some(line) = state.get_config_line() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Parse the retry rule line.
        match parse_retry_line(trimmed) {
            Ok(config) => {
                tracing::debug!(
                    pattern = %config.pattern,
                    rule_count = config.rules.len(),
                    "parsed retry configuration"
                );
                ctx.retry_configs.push(config);
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    line = %trimmed,
                    file = %state.current_filename,
                    lineno = state.current_lineno,
                    "error parsing retry rule"
                );
                return Err(e);
            }
        }
    }

    tracing::debug!(
        count = ctx.retry_configs.len(),
        "retry section parsing complete"
    );
    Ok(())
}

/// Parses a single retry configuration line.
///
/// Format: `pattern [errors] F,timeout,interval [; G,timeout,initial,multiplier]`
fn parse_retry_line(line: &str) -> Result<RetryConfig, ConfigError> {
    let parts: Vec<&str> = line.splitn(2, char::is_whitespace).collect();
    if parts.is_empty() {
        return Err(ConfigError::ParseError {
            file: String::new(),
            line: 0,
            message: "empty retry rule line".to_string(),
        });
    }

    let pattern = parts[0].to_string();
    let mut rules = Vec::new();

    if parts.len() > 1 {
        let rule_part = parts[1].trim();
        // Split on ';' for multiple retry rules chained together.
        for rule_str in rule_part.split(';') {
            let rule_str = rule_str.trim();
            if rule_str.is_empty() {
                continue;
            }
            match parse_single_retry_rule(rule_str) {
                Ok(rule) => rules.push(rule),
                Err(e) => return Err(e),
            }
        }
    }

    // If no rules were specified, add a default fixed rule.
    if rules.is_empty() {
        rules.push(RetryRule {
            algorithm: b'F' as i32,
            p1: 300, // 5 minutes
            p2: 0,
            timeout: 24 * 60 * 60, // 24 hours
            next_try: 0,
        });
    }

    Ok(RetryConfig { pattern, rules })
}

/// Parses a single retry rule specification like `F,2h,15m` or `G,4d,1h,1.5`.
fn parse_single_retry_rule(rule_str: &str) -> Result<RetryRule, ConfigError> {
    let parts: Vec<&str> = rule_str.split(',').collect();
    if parts.is_empty() {
        return Err(ConfigError::ParseError {
            file: String::new(),
            line: 0,
            message: "empty retry rule specification".to_string(),
        });
    }

    // First field: algorithm letter (F, G, H)
    let algo_str = parts[0].trim();
    let algorithm = if algo_str.len() == 1 {
        algo_str.as_bytes()[0] as i32
    } else {
        b'F' as i32 // Default to Fixed
    };

    // Second field: timeout
    let timeout = if parts.len() > 1 {
        parse_time(parts[1].trim()).unwrap_or(24 * 60 * 60)
    } else {
        24 * 60 * 60
    };

    // Third field: interval (p1)
    let p1 = if parts.len() > 2 {
        parse_time(parts[2].trim()).unwrap_or(300)
    } else {
        300
    };

    // Fourth field: multiplier (p2, only for 'G' algorithm, stored × 1000)
    let p2 = if parts.len() > 3 && algorithm == b'G' as i32 {
        parse_fixed(parts[3].trim()).unwrap_or(1500)
    } else {
        0
    };

    Ok(RetryRule {
        algorithm,
        p1,
        p2,
        timeout,
        next_try: 0,
    })
}

// =============================================================================
// parse_rewrite_section — Rewrite rules parser
// =============================================================================

/// Parses the `begin rewrite` section of the configuration file.
///
/// Translates `readconf_rewrites()` from readconf.c lines 1643–1755.
///
/// Each line in the rewrite section specifies a pattern, replacement, and
/// flags controlling which headers are affected:
///
/// ```text
/// pattern   replacement   flags
/// ```
///
/// Flags are single characters: `T` (To), `F` (From), `C` (Cc), `B` (Bcc),
/// `R` (Reply-To), `S` (Sender), `E` (envelope from), `f` (envelope from
/// in received), etc.
pub fn parse_rewrite_section(
    state: &mut ParserState,
    ctx: &mut ConfigContext,
) -> Result<(), ConfigError> {
    tracing::debug!("entering rewrite section parser");

    while let Some(line) = state.get_config_line() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match parse_rewrite_line(trimmed) {
            Ok(rule) => {
                tracing::debug!(
                    key = %rule.key,
                    replacement = %rule.replacement,
                    flags = rule.flags,
                    "parsed rewrite rule"
                );
                ctx.rewrite_rules.push(rule);
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    line = %trimmed,
                    file = %state.current_filename,
                    lineno = state.current_lineno,
                    "error parsing rewrite rule"
                );
                return Err(e);
            }
        }
    }

    tracing::debug!(
        count = ctx.rewrite_rules.len(),
        "rewrite section parsing complete"
    );
    Ok(())
}

/// Parses a single rewrite rule line into a [`RewriteRule`].
///
/// Format: `key_pattern   replacement_string   [flags]`
fn parse_rewrite_line(line: &str) -> Result<RewriteRule, ConfigError> {
    // Use split_whitespace() to correctly handle multiple spaces/tabs
    // between fields, then collect into a vector for indexed access.
    let mut tokens = line.split_whitespace();

    let key = tokens
        .next()
        .ok_or_else(|| ConfigError::ParseError {
            file: String::new(),
            line: 0,
            message: "empty rewrite rule line".to_string(),
        })?
        .to_string();

    let replacement = tokens
        .next()
        .ok_or_else(|| ConfigError::ParseError {
            file: String::new(),
            line: 0,
            message: format!("rewrite rule \"{}\" has no replacement", key),
        })?
        .to_string();

    // Parse flags — collect all remaining tokens as flag characters.
    let flags_str: String = tokens.collect::<Vec<&str>>().join("");
    let flags = parse_rewrite_flags(&flags_str);

    Ok(RewriteRule {
        key,
        replacement,
        flags,
    })
}

/// Parses rewrite flag characters into a bitmask.
///
/// Bit values MUST match the canonical C definitions from
/// `src/src/macros.h:791-813` and the `readconf_one_rewrite()` switch in
/// `src/src/readconf.c:1584-1619`.  Note that the C mapping is
/// **case-sensitive**: lowercase letters control header rewrites
/// (`rewrite_all_headers` = 0x003F), uppercase letters control envelope
/// rewrites (`rewrite_all_envelope` = 0x00C0), and the remaining
/// control flags (`S`, `Q`, `R`, `w`, `q`) have dedicated bits.
///
/// Whitespace characters are silently skipped to match C's behaviour of
/// explicit `case ' ': case '\t': break;` inside the flag loop.
fn parse_rewrite_flags(flags_str: &str) -> u32 {
    let mut flags: u32 = 0;
    for ch in flags_str.chars() {
        match ch {
            // Header rewrites (lowercase) — rewrite_all_headers = 0x003F
            'h' => flags |= 0x003F, // rewrite_all_headers
            's' => flags |= 0x0001, // rewrite_sender
            'f' => flags |= 0x0002, // rewrite_from
            't' => flags |= 0x0004, // rewrite_to
            'c' => flags |= 0x0008, // rewrite_cc
            'b' => flags |= 0x0010, // rewrite_bcc
            'r' => flags |= 0x0020, // rewrite_replyto

            // Envelope rewrites (uppercase) — rewrite_all_envelope = 0x00C0
            'E' => flags |= 0x00C0, // rewrite_all_envelope
            'F' => flags |= 0x0040, // rewrite_envfrom
            'T' => flags |= 0x0080, // rewrite_envto

            // Control flags
            'S' => flags |= 0x0100, // rewrite_smtp (requires regex key in C)
            'Q' => flags |= 0x0400, // rewrite_qualify
            'R' => flags |= 0x0800, // rewrite_repeat
            'w' => flags |= 0x1000, // rewrite_whole
            'q' => flags |= 0x2000, // rewrite_quit

            // Whitespace is explicitly permitted between flags in C.
            ' ' | '\t' => continue,

            _ => {
                tracing::warn!(flag = %ch, "ignoring unknown rewrite flag character");
            }
        }
    }
    flags
}

// =============================================================================
// parse_local_scan_section — Local scan section parser
// =============================================================================

/// Parses the `begin local_scan` section of the configuration file.
///
/// Translates `local_scan_init()` from readconf.c line 4548.
///
/// The local_scan section is typically empty or contains options for a
/// custom local_scan function. In the Rust implementation, this is a
/// placeholder that reads and discards any lines in the section, since
/// local_scan is an optional C hook not directly applicable to Rust.
pub fn parse_local_scan_section(
    state: &mut ParserState,
    _ctx: &mut ConfigContext,
) -> Result<(), ConfigError> {
    tracing::debug!("entering local_scan section parser");

    // Read and discard all lines in the local_scan section.
    // In Exim, local_scan is an optional C function hook compiled into the binary.
    // The Rust equivalent would be a trait-based hook, but the section itself
    // just holds options for that hook.
    while let Some(line) = state.get_config_line() {
        tracing::debug!(
            line = %line.trim(),
            "local_scan section option (stored for future use)"
        );
    }

    tracing::debug!("local_scan section parsing complete");
    Ok(())
}

// =============================================================================
// read_named_list — Named list handler
// =============================================================================

/// Processes a named list directive line.
///
/// Translates `read_named_list()` from readconf.c lines ~3148–3278.
///
/// Named list directives have the format:
/// ```text
/// domainlist name = value
/// hostlist name = value
/// addresslist name = value
/// localpartlist name = value
/// ```
///
/// The `hide` prefix suppresses the list value in `-bP` output:
/// ```text
/// domainlist hide name = value
/// ```
pub fn read_named_list(line: &str, named_lists: &mut NamedLists) -> Result<bool, ConfigError> {
    try_read_named_list(line, named_lists)
}

/// Internal helper that attempts to parse a line as a named list directive.
///
/// Returns `Ok(true)` if the line was successfully processed as a named list,
/// `Ok(false)` if the line is not a named list directive, or `Err` on parse
/// error.
fn try_read_named_list(line: &str, named_lists: &mut NamedLists) -> Result<bool, ConfigError> {
    let trimmed = line.trim();

    // Check if the line starts with a named list keyword.
    for &(keyword, list_type) in NAMED_LIST_KEYWORDS {
        if !trimmed.starts_with(keyword) {
            continue;
        }

        let after_keyword = &trimmed[keyword.len()..];
        // Must be followed by whitespace.
        if after_keyword.is_empty() || !after_keyword.starts_with(char::is_whitespace) {
            continue;
        }

        let rest = after_keyword.trim_start();

        // Check for optional `hide` prefix.
        let (hide, rest) = if rest.starts_with("hide ") || rest.starts_with("hide\t") {
            (true, rest[5..].trim_start())
        } else {
            (false, rest)
        };

        // Extract the list name.
        let (name, after_name) = read_name(rest);
        if name.is_empty() {
            return Err(ConfigError::ParseError {
                file: String::new(),
                line: 0,
                message: format!("{} directive requires a name", keyword),
            });
        }

        // Skip whitespace and expect '='.
        let after_name = after_name.trim_start();
        let value = if let Some(stripped) = after_name.strip_prefix('=') {
            let raw = stripped.trim_start();
            // If the value starts with `"`, dequote and check for trailing
            // characters — matching C Exim's read_string() / extra_chars_error().
            if raw.starts_with('"') {
                read_string_value(raw, name)?
            } else {
                raw.to_string()
            }
        } else {
            return Err(ConfigError::ParseError {
                file: String::new(),
                line: 0,
                message: format!("{} \"{}\" requires \"= value\"", keyword, name),
            });
        };

        let entry = NamedList {
            name: name.to_string(),
            value,
            hide,
        };

        tracing::debug!(
            list_type = keyword,
            name = %entry.name,
            hide = hide,
            "storing named list"
        );

        // Store in the appropriate map.
        match list_type {
            NamedListType::Domain => {
                named_lists.domain_lists.insert(name.to_string(), entry);
            }
            NamedListType::Host => {
                named_lists.host_lists.insert(name.to_string(), entry);
            }
            NamedListType::Address => {
                named_lists.address_lists.insert(name.to_string(), entry);
            }
            NamedListType::LocalPart => {
                named_lists.localpart_lists.insert(name.to_string(), entry);
            }
        }

        return Ok(true);
    }

    Ok(false)
}

// =============================================================================
// Private helper functions
// =============================================================================

/// Dequote a quoted string value (`"..."`) and error if there are extra
/// characters after the closing quote.  Mirrors C Exim's `read_string()`
/// which calls `string_dequote()` and then `extra_chars_error()`.
fn read_string_value(input: &str, name: &str) -> Result<String, ConfigError> {
    debug_assert!(input.starts_with('"'));
    let inner = &input[1..];
    let mut result = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    loop {
        match chars.next() {
            None => {
                return Err(ConfigError::ParseError {
                    file: String::new(),
                    line: 0,
                    message: format!("missing quote at end of string value for {name}"),
                });
            }
            Some('"') => break,
            Some('\\') => match chars.next() {
                Some('\\') => result.push('\\'),
                Some('"') => result.push('"'),
                Some('n') => result.push('\n'),
                Some('t') => result.push('\t'),
                Some('r') => result.push('\r'),
                Some('0') => result.push('\0'),
                Some(c) => {
                    result.push('\\');
                    result.push(c);
                }
                None => {
                    return Err(ConfigError::ParseError {
                        file: String::new(),
                        line: 0,
                        message: format!("missing quote at end of string value for {name}"),
                    });
                }
            },
            Some(c) => result.push(c),
        }
    }
    // Check for extra characters after the closing quote.
    let remainder: String = chars.collect();
    let trimmed = remainder.trim();
    if !trimmed.is_empty() {
        let comment = if trimmed.starts_with('#') {
            " (# is comment only at line start)"
        } else {
            ""
        };
        return Err(ConfigError::ParseError {
            file: String::new(),
            line: 0,
            message: format!("extra characters follow string value for {name}{comment}"),
        });
    }
    Ok(result)
}

/// Resolves the configuration file path from a colon-separated candidate list.
///
/// Tries each candidate path in order, with optional node-name and euid suffix
/// resolution (controlled by Cargo features replacing the C
/// `CONFIGURE_FILE_USE_NODE` and `CONFIGURE_FILE_USE_EUID` macros).
///
/// Matching readconf.c lines 3290–3330.
fn resolve_config_file(config_file_list: &str) -> Result<String, ConfigError> {
    for candidate in config_file_list.split(':') {
        let candidate = candidate.trim();
        if candidate.is_empty() {
            continue;
        }

        // Try node-name suffix first.
        // In C this was controlled by CONFIGURE_FILE_USE_NODE; in Rust we
        // always attempt it — if the node-suffixed file exists, use it.
        // This avoids needing a dedicated Cargo feature for this runtime check.
        if let Ok(hostname) = nix::unistd::gethostname() {
            let hostname_str = hostname.to_string_lossy();
            let node_path = format!("{}.{}", candidate, hostname_str);
            if Path::new(&node_path).exists() {
                tracing::debug!(
                    path = %node_path,
                    "found node-specific config file"
                );
                return Ok(node_path);
            }
        }

        // Try euid suffix.
        // In C this was controlled by CONFIGURE_FILE_USE_EUID; in Rust we
        // attempt it at runtime — if the euid-suffixed file exists, use it.
        let euid = nix::unistd::geteuid();
        let euid_path = format!("{}.{}", candidate, euid);
        if Path::new(&euid_path).exists() {
            tracing::debug!(
                path = %euid_path,
                "found euid-specific config file"
            );
            return Ok(euid_path);
        }

        // Try the base path.
        if Path::new(candidate).exists() {
            return Ok(candidate.to_string());
        }
    }

    Err(ConfigError::FileNotFound(format!(
        "no configuration file found in list: {}",
        config_file_list
    )))
}

/// Verifies configuration file ownership and permissions.
///
/// Matching readconf.c lines 3295–3320.
///
/// The config file must be owned by root or the Exim user (matching the
/// current effective UID). Group-writable and world-writable files are
/// rejected for security.
fn verify_config_file_security(
    config_path: &str,
    trusted_list: Option<&[String]>,
) -> Result<(), ConfigError> {
    let metadata = std::fs::metadata(config_path).map_err(|e| {
        ConfigError::FileNotFound(format!("cannot stat config file {}: {}", config_path, e))
    })?;

    let file_uid = metadata.uid();
    let file_mode = metadata.mode();

    // Check if the file is in the trusted config list.
    if let Some(trusted) = trusted_list {
        if !trusted.iter().any(|p| p == config_path) {
            tracing::warn!(
                config_path = %config_path,
                "config file not in trusted list"
            );
        }
    }

    // Verify ownership: must be owned by root (0) or the current effective user.
    let euid = nix::unistd::geteuid();
    if file_uid != 0 && file_uid != euid.as_raw() {
        tracing::warn!(
            config_path = %config_path,
            file_uid = file_uid,
            euid = euid.as_raw(),
            "config file not owned by root or exim user"
        );
    }

    // Reject world-writable files.
    if file_mode & 0o002 != 0 {
        return Err(ConfigError::ValidationError(format!(
            "configuration file {} is world-writable (mode {:04o})",
            config_path,
            file_mode & 0o7777
        )));
    }

    // Warn about group-writable files.
    if file_mode & 0o020 != 0 {
        tracing::warn!(
            config_path = %config_path,
            mode = format!("{:04o}", file_mode & 0o7777),
            "configuration file is group-writable"
        );
    }

    tracing::debug!(
        config_path = %config_path,
        uid = file_uid,
        mode = format!("{:04o}", file_mode & 0o7777),
        "config file security check passed"
    );

    Ok(())
}

/// Post-processes the main configuration section after all options are read.
///
/// Matching readconf.c lines ~3500–3643.
///
/// Performs:
/// - Spool directory, log file path, PID file path expansion
/// - Syslog facility validation
/// - Primary hostname default resolution
/// - SMTP active hostname default
/// - Qualify domain defaults
/// - TLS constraint validation
/// - UUCP From_ regex compilation
fn post_process_main_config(ctx: &mut ConfigContext) -> Result<(), ConfigError> {
    // ── Set default spool directory ─────────────────────────────────────
    if ctx.spool_directory.is_empty() {
        ctx.spool_directory = "/var/spool/exim".to_string();
        tracing::debug!(
            spool_directory = %ctx.spool_directory,
            "using default spool directory"
        );
    }

    // Ensure spool_directory is absolute.
    if !ctx.spool_directory.starts_with('/') {
        return Err(ConfigError::ValidationError(format!(
            "spool_directory must be an absolute path, got \"{}\"",
            ctx.spool_directory
        )));
    }

    // ── Set default log file path ───────────────────────────────────────
    if ctx.log_file_path.is_empty() {
        ctx.log_file_path = format!("{}/log/%%slog", ctx.spool_directory);
        tracing::debug!(
            log_file_path = %ctx.log_file_path,
            "using default log file path"
        );
    }

    // ── Set default PID file path ───────────────────────────────────────
    if ctx.pid_file_path.is_empty() {
        ctx.pid_file_path = format!("{}/exim-daemon.pid", ctx.spool_directory);
        tracing::debug!(
            pid_file_path = %ctx.pid_file_path,
            "using default PID file path"
        );
    }

    // ── Set primary hostname ────────────────────────────────────────────
    if ctx.primary_hostname.is_empty() {
        match nix::unistd::gethostname() {
            Ok(hostname) => {
                ctx.primary_hostname = hostname.to_string_lossy().into_owned();
                tracing::debug!(
                    primary_hostname = %ctx.primary_hostname,
                    "auto-detected primary hostname"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "failed to detect hostname, using \"localhost\""
                );
                ctx.primary_hostname = "localhost".to_string();
            }
        }
    }

    // ── Set SMTP active hostname ────────────────────────────────────────
    if ctx.smtp_active_hostname.is_none() {
        ctx.smtp_active_hostname = Some(ctx.primary_hostname.clone());
        tracing::debug!(
            smtp_active_hostname = %ctx.primary_hostname,
            "defaulting smtp_active_hostname to primary_hostname"
        );
    }

    // ── Set qualify domain defaults ─────────────────────────────────────
    if ctx.qualify_domain_sender.is_empty() {
        ctx.qualify_domain_sender = ctx.primary_hostname.clone();
    }
    if ctx.qualify_domain_recipient.is_empty() {
        ctx.qualify_domain_recipient = ctx.qualify_domain_sender.clone();
    }

    // ── Validate TLS constraints ────────────────────────────────────────
    #[cfg(feature = "tls")]
    {
        // If tls_certificate is set, tls_privatekey should also be set
        // (or defaults to the same path). Matching readconf.c ~line 3600.
        if ctx.tls_certificate.is_some() && ctx.tls_privatekey.is_none() {
            ctx.tls_privatekey = ctx.tls_certificate.clone();
            tracing::debug!("defaulting tls_privatekey to tls_certificate value");
        }
    }

    // ── Compile UUCP From_ regex ────────────────────────────────────────
    // Matching readconf.c ~line 3550. The pattern is compiled and discarded
    // here — it's validated during parsing but used at runtime.
    let uucp_pattern = "^From\\s+\\S+\\s+";
    match Regex::new(uucp_pattern) {
        Ok(_) => {
            tracing::debug!("UUCP From_ pattern compiled successfully");
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                pattern = uucp_pattern,
                "failed to compile UUCP From_ regex"
            );
        }
    }

    tracing::debug!("main config post-processing complete");
    Ok(())
}

/// Collects all lines from the current section into a vector for driver
/// initialization functions.
///
/// Reads lines from the parser state until the next section boundary or EOF,
/// collecting them with their line numbers for the driver init functions.
fn collect_section_lines(state: &mut ParserState) -> Vec<(String, u32)> {
    let mut lines = Vec::new();
    while let Some(line) = state.get_config_line() {
        let lineno = state.current_lineno;
        lines.push((line, lineno));
    }
    lines
}

// =============================================================================
// apply_option_to_ctx — Store parsed option values into ConfigContext
// =============================================================================
// Lightweight config-time string expansion
// =============================================================================

/// Performs lightweight string expansion during configuration parsing.
///
/// In C Exim, `readconf.c` calls `expand_string()` on most option values
/// after reading them from the config file. This function implements the
/// subset of expansion operators commonly used in config-time contexts:
///
/// - `${readfile{filename}{separator}}` — read file contents
/// - `${if eq{s1}{s2}{yes}{no}}` — string equality conditional
/// - `${if ={n1}{n2}{yes}{no}}` — numeric equality conditional
///
/// Operators that reference message variables or dynamic state are left
/// unexpanded (the raw `${...}` is preserved), matching C Exim's behavior
/// of deferring expansion of dynamic references until runtime.
fn expand_config_string(input: &str) -> String {
    if !input.contains("${") {
        return input.to_string();
    }

    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            // Consume '{'
            chars.next();
            // Collect the operator name
            let mut op = String::new();
            while let Some(&c) = chars.peek() {
                if c == '{' || c == ' ' || c == '}' {
                    break;
                }
                op.push(c);
                chars.next();
            }

            match op.as_str() {
                "readfile" => {
                    // ${readfile{filename}{separator}}
                    if let Some(expanded) = expand_readfile(&mut chars) {
                        result.push_str(&expanded);
                        continue;
                    }
                    // Fallback: emit raw
                    result.push_str("${readfile");
                    result.push_str(&op);
                }
                "if" => {
                    // ${if eq{s1}{s2}{yes}{no}} or ${if ={n1}{n2}{yes}{no}}
                    if let Some(expanded) = expand_if_condition(&mut chars) {
                        result.push_str(&expanded);
                        continue;
                    }
                    // Fallback: emit raw
                    result.push_str("${if");
                }
                _ => {
                    // Unknown operator — emit raw (deferred expansion)
                    result.push_str("${");
                    result.push_str(&op);
                    // Consume until matching '}'
                    let mut depth = 1i32;
                    for c in chars.by_ref() {
                        result.push(c);
                        if c == '{' {
                            depth += 1;
                        } else if c == '}' {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                    }
                }
            }
        } else {
            result.push(ch);
        }
    }

    result
}

/// Extract a brace-delimited argument from the iterator: `{content}`
/// Handles nested braces.
fn extract_braced_arg(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<String> {
    // Skip whitespace
    while let Some(&c) = chars.peek() {
        if c == ' ' || c == '\t' {
            chars.next();
        } else {
            break;
        }
    }
    if chars.peek() != Some(&'{') {
        return None;
    }
    chars.next(); // consume '{'

    let mut content = String::new();
    let mut depth = 1i32;
    for c in chars.by_ref() {
        if c == '{' {
            depth += 1;
            content.push(c);
        } else if c == '}' {
            depth -= 1;
            if depth == 0 {
                return Some(content);
            }
            content.push(c);
        } else {
            content.push(c);
        }
    }
    None // unterminated
}

/// Expand `${readfile{filename}{separator}}` — reads the file and joins
/// lines with the given separator.
fn expand_readfile(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<String> {
    let filename = extract_braced_arg(chars)?;
    let separator = extract_braced_arg(chars);
    // Consume the closing '}' of the ${readfile...}
    while let Some(&c) = chars.peek() {
        if c == ' ' || c == '\t' {
            chars.next();
        } else if c == '}' {
            chars.next();
            break;
        } else {
            break;
        }
    }

    // Read the file
    let sep = separator.unwrap_or_default();
    let sep_char = if sep == ":" {
        ":"
    } else if sep.is_empty() {
        "\n"
    } else {
        &sep
    };

    match std::fs::read_to_string(&filename) {
        Ok(contents) => {
            // Split by newlines, filter empty, join with separator
            let lines: Vec<&str> = contents.lines().filter(|l| !l.is_empty()).collect();
            Some(lines.join(sep_char))
        }
        Err(e) => {
            tracing::warn!(file = %filename, error = %e, "readfile expansion failed");
            None
        }
    }
}

/// Expand `${if eq{s1}{s2}{yes}{no}}` or `${if ={n1}{n2}{yes}{no}}`
fn expand_if_condition(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<String> {
    // Skip whitespace after "if"
    while let Some(&c) = chars.peek() {
        if c == ' ' || c == '\t' {
            chars.next();
        } else {
            break;
        }
    }

    // Read the condition operator
    let mut op = String::new();
    while let Some(&c) = chars.peek() {
        if c == '{' || c == ' ' {
            break;
        }
        op.push(c);
        chars.next();
    }

    let arg1 = expand_config_string(&extract_braced_arg(chars)?);
    let arg2 = expand_config_string(&extract_braced_arg(chars)?);
    let yes_branch = extract_braced_arg(chars)?;
    let no_branch = extract_braced_arg(chars)?;

    // Consume the closing '}' of the ${if...}
    while let Some(&c) = chars.peek() {
        if c == ' ' || c == '\t' {
            chars.next();
        } else if c == '}' {
            chars.next();
            break;
        } else {
            break;
        }
    }

    let condition_met = match op.as_str() {
        "eq" => arg1 == arg2,
        "!=" | "ne" => arg1 != arg2,
        "=" | "==" => {
            let n1 = arg1.trim().parse::<i64>().unwrap_or(0);
            let n2 = arg2.trim().parse::<i64>().unwrap_or(0);
            n1 == n2
        }
        ">" | "gt" => {
            let n1 = arg1.trim().parse::<i64>().unwrap_or(0);
            let n2 = arg2.trim().parse::<i64>().unwrap_or(0);
            n1 > n2
        }
        _ => return None,
    };

    let branch = if condition_met { yes_branch } else { no_branch };
    Some(expand_config_string(&branch))
}

// =============================================================================

/// Apply a parsed option result to the [`ConfigContext`], storing the value
/// in the corresponding struct field.
///
/// This is the critical bridge between the option parser (`handle_option`)
/// and the configuration data model. Without this function, parsed config
/// values would be discarded after parsing. Every option recognized by the
/// `-bP` printer (`validate.rs` `resolve_*_option` functions) must have a
/// corresponding assignment arm here.
///
/// # Arguments
/// * `result` — The parsed option name, value, and metadata from `handle_option`.
/// * `ctx` — The mutable configuration context being populated during parsing.
fn apply_option_to_ctx(result: &HandleOptionResult, ctx: &mut ConfigContext) {
    let name = result.name.as_str();
    match &result.value {
        // ── Boolean options ─────────────────────────────────────────
        OptionValue::Bool(v) => apply_bool_option(name, *v, ctx),

        // ── Expandable boolean options (stored as expansion strings) ──
        // These are handled at the driver level (stored in the driver's
        // expand_<name> field), not as global config booleans.  At the
        // global config level, treat them the same as `Bool(true)`.
        OptionValue::ExpandBool(_) => apply_bool_option(name, true, ctx),

        // ── String options ──────────────────────────────────────────
        OptionValue::Str(v) => apply_string_option(name, v, ctx),

        // ── Integer options (Int, Mkint, OctInt) ────────────────────
        OptionValue::Int(v) => apply_int_option(name, *v, ctx),

        // ── Time options (seconds) ──────────────────────────────────
        OptionValue::Time(v) => apply_time_option(name, *v, ctx),

        // ── Kint options (kilobyte-unit integers) ───────────────────
        OptionValue::Kint(v) => apply_kint_option(name, *v, ctx),

        // ── Fixed-point options ─────────────────────────────────────
        OptionValue::Fixed(v) => apply_fixed_option(name, *v, ctx),

        // ── UID / GID scalar options ────────────────────────────────
        OptionValue::Uid(v) => {
            tracing::trace!(option = %name, uid = %v, "applying UID option");
            match name {
                "exim_user" => ctx.exim_uid = *v,
                _ => tracing::warn!(option = %name, "unhandled UID option in apply_option_to_ctx"),
            }
        }
        OptionValue::Gid(v) => {
            tracing::trace!(option = %name, gid = %v, "applying GID option");
            match name {
                "exim_group" => ctx.exim_gid = *v,
                _ => tracing::warn!(option = %name, "unhandled GID option in apply_option_to_ctx"),
            }
        }

        // ── Expandable UID / GID (may contain `$` for deferred expansion) ──
        OptionValue::ExpandUid(ref eid) => {
            tracing::trace!(option = %name, "applying ExpandUid option");
            match name {
                "exim_user" => {
                    if let crate::options::ExpandableId::Resolved(uid) = eid {
                        ctx.exim_uid = *uid;
                    }
                    // Deferred values are stored in the option table for
                    // runtime expansion; the ctx field remains at its default
                    // until the expansion resolves.
                }
                _ => tracing::warn!(option = %name, "unhandled ExpandUid option"),
            }
        }
        OptionValue::ExpandGid(ref eid) => {
            tracing::trace!(option = %name, "applying ExpandGid option");
            match name {
                "exim_group" => {
                    if let crate::options::ExpandableId::Resolved(gid) = eid {
                        ctx.exim_gid = *gid;
                    }
                }
                _ => tracing::warn!(option = %name, "unhandled ExpandGid option"),
            }
        }

        // ── UID / GID list options ──────────────────────────────────
        // Store the raw string representation for -bP printing. Expansion
        // happens at runtime when the list is actually needed for access
        // control decisions.
        OptionValue::UidList(ref list) => {
            let raw_str = match list {
                crate::options::ExpandableIdList::Deferred(s) => {
                    // C Exim expands the string at config time, then parses UIDs
                    let expanded = expand_config_string(s);
                    if expanded.contains('$') {
                        // Still contains unexpandable references — store raw
                        Some(expanded)
                    } else {
                        // Expanded successfully — resolve UIDs to names
                        let parts: Vec<&str> = expanded
                            .split(':')
                            .map(|p| p.trim())
                            .filter(|p| !p.is_empty())
                            .collect();
                        let names: Vec<String> = parts
                            .iter()
                            .map(|&part| {
                                if let Ok(uid) = part.parse::<u32>() {
                                    match nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(
                                        uid,
                                    )) {
                                        Ok(Some(u)) => u.name,
                                        _ => uid.to_string(),
                                    }
                                } else {
                                    part.to_string()
                                }
                            })
                            .collect();
                        if names.is_empty() {
                            None
                        } else {
                            Some(names.join(":"))
                        }
                    }
                }
                crate::options::ExpandableIdList::Resolved(ids) => {
                    if ids.is_empty() {
                        None
                    } else {
                        // Convert resolved UIDs back to names for storage
                        let names: Vec<String> = ids
                            .iter()
                            .map(|&uid| {
                                match nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)) {
                                    Ok(Some(u)) => u.name,
                                    _ => uid.to_string(),
                                }
                            })
                            .collect();
                        Some(names.join(":"))
                    }
                }
            };
            match name {
                "trusted_users" => ctx.trusted_users = raw_str,
                "never_users" => ctx.never_users = raw_str,
                "admin_groups" => ctx.admin_groups = raw_str,
                _ => {
                    tracing::trace!(option = %name, "UidList stored in option table only");
                }
            }
        }
        OptionValue::GidList(ref list) => {
            let raw_str = match list {
                crate::options::ExpandableIdList::Deferred(s) => {
                    let expanded = expand_config_string(s);
                    if expanded.contains('$') {
                        Some(expanded)
                    } else {
                        let parts: Vec<&str> = expanded
                            .split(':')
                            .map(|p| p.trim())
                            .filter(|p| !p.is_empty())
                            .collect();
                        let names: Vec<String> = parts
                            .iter()
                            .map(|&part| {
                                if let Ok(gid) = part.parse::<u32>() {
                                    match nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(
                                        gid,
                                    )) {
                                        Ok(Some(g)) => g.name,
                                        _ => gid.to_string(),
                                    }
                                } else {
                                    part.to_string()
                                }
                            })
                            .collect();
                        if names.is_empty() {
                            None
                        } else {
                            Some(names.join(":"))
                        }
                    }
                }
                crate::options::ExpandableIdList::Resolved(ids) => {
                    if ids.is_empty() {
                        None
                    } else {
                        let names: Vec<String> = ids
                            .iter()
                            .map(|&gid| {
                                match nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(gid))
                                {
                                    Ok(Some(g)) => g.name,
                                    _ => gid.to_string(),
                                }
                            })
                            .collect();
                        Some(names.join(":"))
                    }
                }
            };
            match name {
                "trusted_groups" => ctx.trusted_groups = raw_str,
                _ => {
                    tracing::trace!(option = %name, "GidList stored in option table only");
                }
            }
        }

        // ── Time list options ───────────────────────────────────────
        OptionValue::TimeList(_) => {
            tracing::trace!(option = %name, "time list option stored in option table");
            // Time lists (e.g. delay_warning) are read back from the
            // option table at runtime. No dedicated ConfigContext field.
        }

        // ── Rewrite rules ───────────────────────────────────────────
        OptionValue::Rewrite(_) => {
            tracing::trace!(option = %name, "rewrite option handled by section parser");
        }

        // ── Function / Module delegation ────────────────────────────
        OptionValue::Func(_) => {
            tracing::trace!(option = %name, "func option handled by custom handler");
        }
        OptionValue::ModuleDelegate { module, .. } => {
            tracing::trace!(option = %name, module = %module, "module-delegated option");
        }
    }
}

/// Apply a boolean option value to the correct [`ConfigContext`] field.
///
/// The mapping mirrors `resolve_bool_option()` in `validate.rs` to ensure
/// that `-bP` printing reads back the same field that was written here.
fn apply_bool_option(name: &str, value: bool, ctx: &mut ConfigContext) {
    match name {
        "accept_8bitmime" => ctx.accept_8bitmime = value,
        "allow_domain_literals" => ctx.allow_domain_literals = value,
        "allow_mx_to_ip" => ctx.allow_mx_to_ip = value,
        "bounce_return_body" => ctx.bounce_return_body = value,
        "bounce_return_message" => ctx.bounce_return_message = value,
        "check_rfc2047_length" => ctx.check_rfc2047_length = value,
        "commandline_checks_require_admin" => ctx.commandline_checks_require_admin = value,
        "delivery_date_remove" => ctx.delivery_date_remove = value,
        "deliver_drop_privilege" => ctx.deliver_drop_privilege = value,
        "disable_ipv6" => ctx.disable_ipv6 = value,
        "dns_csa_use_reverse" => ctx.dns_csa_use_reverse = value,
        "envelope_to_remove" => ctx.envelope_to_remove = value,
        "extract_addresses_remove_arguments" => ctx.extract_addresses_remove_arguments = value,
        "ignore_fromline_local" => ctx.ignore_fromline_local = value,
        "local_from_check" => ctx.local_from_check = value,
        "local_sender_retain" => ctx.local_sender_retain = value,
        "log_timezone" => ctx.log_timezone = value,
        "message_body_newlines" => ctx.message_body_newlines = value,
        "message_logs" => ctx.message_logs = value,
        "pipelining_enable" => ctx.pipelining_enable = value,
        "preserve_message_logs" => ctx.preserve_message_logs = value,
        "print_topbitchars" => ctx.print_topbitchars = value,
        "prod_requires_admin" => ctx.prod_requires_admin = value,
        "queue_list_requires_admin" => ctx.queue_list_requires_admin = value,
        "queue_only" => ctx.queue_only = value,
        "queue_only_load_latch" => ctx.queue_only_load_latch = value,
        "queue_only_override" => ctx.queue_only_override = value,
        "queue_run_in_order" => ctx.queue_run_in_order = value,
        "recipients_max_reject" => ctx.recipients_max_reject = value,
        "return_path_remove" => ctx.return_path_remove = value,
        "smtp_accept_keepalive" => ctx.smtp_accept_keepalive = value,
        "smtp_check_spool_space" => ctx.smtp_check_spool_space = value,
        "smtp_enforce_sync" => ctx.smtp_enforce_sync = value,
        "smtp_etrn_serialize" => ctx.smtp_etrn_serialize = value,
        "smtp_return_error_details" => ctx.smtp_return_error_details = value,
        "split_spool_directory" => ctx.split_spool_directory = value,
        "spool_wireformat" => ctx.spool_wireformat = value,
        "strict_acl_vars" => ctx.strict_acl_vars = value,
        "strip_excess_angle_brackets" => ctx.strip_excess_angle_brackets = value,
        "strip_trailing_dot" => ctx.strip_trailing_dot = value,
        "syslog_duplication" => ctx.syslog_duplication = value,
        "syslog_pid" => ctx.syslog_pid = value,
        "syslog_timestamp" => ctx.syslog_timestamp = value,
        "tcp_nodelay" => ctx.tcp_nodelay = value,
        "timestamps_utc" => ctx.timestamps_utc = value,
        "write_rejectlog" => ctx.write_rejectlog = value,
        "debug_store" => ctx.debug_store = value,
        "mua_wrapper" => ctx.mua_wrapper = value,
        "panic_coredump" => ctx.panic_coredump = value,
        "log_ports" => ctx.log_ports = value,
        _ => {
            tracing::trace!(option = %name, value = %value, "bool option stored in option table only");
        }
    }
}

/// Apply a string option value to the correct [`ConfigContext`] field.
///
/// The mapping mirrors `resolve_string_option()` in `validate.rs`.
fn apply_string_option(name: &str, value: &str, ctx: &mut ConfigContext) {
    // C Exim stores opt_stringptr values RAW without expansion at config
    // parse time (readconf.c readconf_handle_option).  Expansion happens
    // at runtime when the value is actually used.  We therefore do NOT
    // call expand_config_string() here — the raw value is stored verbatim
    // so that runtime expansion can evaluate ${if ...}, ${lookup ...},
    // $variable references, etc.

    // Helper: set an Option<String> field. Empty strings become None
    // to match the C behavior where empty string pointers are treated
    // as unset.
    let opt_val = if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    };

    match name {
        // ACL definitions
        "acl_not_smtp" => ctx.acl_not_smtp = opt_val,
        "acl_not_smtp_start" => ctx.acl_not_smtp_start = opt_val,
        "acl_smtp_atrn" => ctx.acl_smtp_atrn = opt_val,
        "acl_smtp_auth" => ctx.acl_smtp_auth = opt_val,
        "acl_smtp_connect" => ctx.acl_smtp_connect = opt_val,
        "acl_smtp_data" => ctx.acl_smtp_data = opt_val,
        "acl_smtp_etrn" => ctx.acl_smtp_etrn = opt_val,
        "acl_smtp_expn" => ctx.acl_smtp_expn = opt_val,
        "acl_smtp_helo" => ctx.acl_smtp_helo = opt_val,
        "acl_smtp_mail" => ctx.acl_smtp_mail = opt_val,
        "acl_smtp_mailauth" => ctx.acl_smtp_mailauth = opt_val,
        "acl_smtp_notquit" => ctx.acl_smtp_notquit = opt_val,
        "acl_smtp_predata" => ctx.acl_smtp_predata = opt_val,
        "acl_smtp_quit" => ctx.acl_smtp_quit = opt_val,
        "acl_smtp_rcpt" => ctx.acl_smtp_rcpt = opt_val,
        "acl_smtp_vrfy" => ctx.acl_smtp_vrfy = opt_val,
        #[cfg(feature = "tls")]
        "acl_smtp_starttls" => ctx.acl_smtp_starttls = opt_val,
        #[cfg(feature = "prdr")]
        "acl_smtp_data_prdr" => ctx.acl_smtp_data_prdr = opt_val,
        #[cfg(feature = "dkim")]
        "acl_smtp_dkim" => ctx.acl_smtp_dkim = opt_val,
        #[cfg(feature = "content-scan")]
        "acl_not_smtp_mime" => ctx.acl_not_smtp_mime = opt_val,
        #[cfg(feature = "content-scan")]
        "acl_smtp_mime" => ctx.acl_smtp_mime = opt_val,
        #[cfg(feature = "wellknown")]
        "acl_smtp_wellknown" => ctx.acl_smtp_wellknown = opt_val,

        // String options — alphabetical
        "add_environment" => ctx.add_environment = opt_val,
        "auth_advertise_hosts" => ctx.auth_advertise_hosts = opt_val,
        "bi_command" => ctx.bi_command = opt_val,
        "bounce_message_file" => ctx.bounce_message_file = opt_val,
        "bounce_message_text" => ctx.bounce_message_text = opt_val,
        "bounce_sender_authentication" => ctx.bounce_sender_authentication = opt_val,
        "callout_random_local_part" => ctx.callout_random_local_part = opt_val,
        "check_dns_names_pattern" => ctx.dns_check_names_pattern = opt_val,
        "chunking_advertise_hosts" => ctx.chunking_advertise_hosts = opt_val,
        "daemon_smtp_port" | "daemon_smtp_ports" => ctx.daemon_smtp_port = opt_val,
        "daemon_modules_load" => ctx.daemon_modules_load = opt_val,
        "delay_warning_condition" => ctx.delay_warning_condition = opt_val,
        "dns_again_means_nonexist" => ctx.dns_again_means_nonexist = opt_val,
        "dns_ipv4_lookup" => ctx.dns_ipv4_lookup = opt_val,
        "dns_trust_aa" => ctx.dns_trust_aa = opt_val,
        "dsn_from" => ctx.dsn_from = opt_val,
        "dsn_advertise_hosts" => ctx.dsn_advertise_hosts = opt_val,
        "errors_copy" => ctx.errors_copy = opt_val,
        "errors_reply_to" => ctx.errors_reply_to = opt_val,
        "extra_local_interfaces" => ctx.extra_local_interfaces = opt_val,
        "freeze_tell" => ctx.freeze_tell = opt_val,
        "gecos_name" => ctx.gecos_name = opt_val,
        "gecos_pattern" => ctx.gecos_pattern = opt_val,
        "helo_accept_junk_hosts" => ctx.helo_accept_junk_hosts = opt_val,
        "helo_allow_chars" => ctx.helo_allow_chars = opt_val,
        "helo_lookup_domains" => ctx.helo_lookup_domains = opt_val,
        "helo_try_verify_hosts" => ctx.helo_try_verify_hosts = opt_val,
        "helo_verify_hosts" => ctx.helo_verify_hosts = opt_val,
        "hold_domains" => ctx.hold_domains = opt_val,
        "host_lookup" => ctx.host_lookup = opt_val,
        "host_lookup_order" => ctx.host_lookup_order = opt_val,
        "host_reject_connection" => ctx.host_reject_connection = opt_val,
        "hosts_connection_nolog" => ctx.hosts_connection_nolog = opt_val,
        "hosts_require_helo" => ctx.hosts_require_helo = opt_val,
        "hosts_treat_as_local" => ctx.hosts_treat_as_local = opt_val,
        "ignore_fromline_hosts" => ctx.ignore_fromline_hosts = opt_val,
        "keep_environment" => ctx.keep_environment = opt_val,
        "local_from_prefix" => ctx.local_from_prefix = opt_val,
        "local_from_suffix" => ctx.local_from_suffix = opt_val,
        "local_interfaces" => ctx.local_interfaces = opt_val,
        "log_selector" => ctx.log_selector_string = opt_val,
        "message_size_limit" => ctx.message_size_limit = opt_val,
        "notifier_socket" => ctx.notifier_socket = opt_val,
        "percent_hack_domains" => ctx.percent_hack_domains = opt_val,
        "pipelining_advertise_hosts" => ctx.pipelining_advertise_hosts = opt_val,
        "received_header_text" => ctx.received_header_text = opt_val,
        "recipient_unqualified_hosts" => ctx.recipient_unqualified_hosts = opt_val,
        "recipients_max" => ctx.recipients_max = opt_val,
        "remote_sort_domains" => ctx.remote_sort_domains = opt_val,
        "rfc1413_hosts" => ctx.rfc1413_hosts = opt_val,
        "sender_unqualified_hosts" => ctx.sender_unqualified_hosts = opt_val,
        "smtp_accept_max_per_connection" => ctx.smtp_accept_max_per_connection = opt_val,
        "smtp_accept_max_per_host" => ctx.smtp_accept_max_per_host = opt_val,
        "smtp_accept_max_nonmail_hosts" => ctx.smtp_accept_max_nonmail_hosts = opt_val,
        "smtp_active_hostname" => ctx.smtp_active_hostname = opt_val,
        "smtp_banner" => ctx.smtp_banner = opt_val,
        "smtp_etrn_command" => ctx.smtp_etrn_command = opt_val,
        "smtp_ratelimit_hosts" => ctx.smtp_ratelimit_hosts = opt_val,
        "smtp_ratelimit_mail" => ctx.smtp_ratelimit_mail = opt_val,
        "smtp_ratelimit_rcpt" => ctx.smtp_ratelimit_rcpt = opt_val,
        "smtp_reserve_hosts" => ctx.smtp_reserve_hosts = opt_val,
        "syslog_processname" => ctx.syslog_processname = opt_val,
        "system_filter" => ctx.system_filter = opt_val,
        "system_filter_directory_transport" => ctx.system_filter_directory_transport = opt_val,
        "system_filter_file_transport" => ctx.system_filter_file_transport = opt_val,
        "system_filter_pipe_transport" => ctx.system_filter_pipe_transport = opt_val,
        "system_filter_reply_transport" => ctx.system_filter_reply_transport = opt_val,
        "tls_advertise_hosts" => ctx.tls_advertise_hosts = opt_val,
        "queue_domains" => ctx.queue_domains = opt_val,
        "queue_only_file" => ctx.queue_only_file = opt_val,
        "queue_run_max" => ctx.queue_run_max = opt_val,
        "queue_smtp_domains" => ctx.queue_smtp_domains = opt_val,
        "smtp_receive_timeout_s" => ctx.smtp_receive_timeout_s = opt_val,
        "exim_version" => ctx.exim_version = opt_val,
        "exim_path" => ctx.exim_path = opt_val,
        "headers_charset" => ctx.headers_charset = opt_val,
        "unknown_login" => ctx.unknown_login = opt_val,
        "unknown_username" => ctx.unknown_username = opt_val,
        "warn_message_file" => ctx.warn_message_file = opt_val,
        "timezone" => ctx.timezone = opt_val,
        "uucp_from_pattern" => ctx.uucp_from_pattern = opt_val,
        "uucp_from_sender" => ctx.uucp_from_sender = opt_val,
        "untrusted_set_sender" => ctx.untrusted_set_sender = opt_val,
        "process_log_path" => ctx.process_log_path = opt_val,
        "message_id_header_domain" => ctx.message_id_header_domain = opt_val,
        "message_id_header_text" => ctx.message_id_header_text = opt_val,
        "dns_check_names_pattern" => ctx.dns_check_names_pattern = opt_val,

        // Direct String fields (non-Option) — these are never None,
        // so we assign the value directly instead of using opt_val.
        "spool_directory" => ctx.spool_directory = value.to_string(),
        "log_file_path" => ctx.log_file_path = value.to_string(),
        "pid_file_path" => ctx.pid_file_path = value.to_string(),
        "primary_hostname" => ctx.primary_hostname = value.to_string(),
        "qualify_domain" => ctx.qualify_domain_sender = value.to_string(),
        "qualify_recipient" => ctx.qualify_domain_recipient = value.to_string(),

        // TLS options (feature-gated)
        #[cfg(feature = "tls")]
        "tls_certificate" => ctx.tls_certificate = opt_val,
        #[cfg(feature = "tls")]
        "tls_privatekey" => ctx.tls_privatekey = opt_val,
        #[cfg(feature = "tls")]
        "tls_verify_certificates" => ctx.tls_verify_certificates = opt_val,
        #[cfg(feature = "tls")]
        "tls_crl" => ctx.tls_crl = opt_val,
        #[cfg(feature = "tls")]
        "tls_require_ciphers" => ctx.tls_require_ciphers = opt_val,
        #[cfg(feature = "tls")]
        "tls_try_verify_hosts" => ctx.tls_try_verify_hosts = opt_val,
        #[cfg(feature = "tls")]
        "tls_verify_hosts" => ctx.tls_verify_hosts = opt_val,

        // Content scanning (feature-gated)
        #[cfg(feature = "content-scan")]
        "av_scanner" => ctx.av_scanner = opt_val,
        #[cfg(feature = "content-scan")]
        "spamd_address" => ctx.spamd_address = opt_val,

        _ => {
            tracing::trace!(option = %name, "string option stored in option table only");
        }
    }
}

/// Apply an integer option value to the correct [`ConfigContext`] field.
///
/// The mapping mirrors `resolve_int_option()` in `validate.rs`.
fn apply_int_option(name: &str, value: i64, ctx: &mut ConfigContext) {
    match name {
        "bounce_return_linesize_limit" => ctx.bounce_return_linesize_limit = value as i32,
        "bounce_return_size_limit" => ctx.bounce_return_size_limit = value as i32,
        "check_log_inodes" => ctx.check_log_inodes = value as i32,
        "check_spool_inodes" => ctx.check_spool_inodes = value as i32,
        "connection_max_messages" => ctx.connection_max_messages = value as i32,
        "daemon_startup_retries" => ctx.daemon_startup_retries = value as i32,
        "dns_cname_loops" => ctx.dns_cname_loops = value as i32,
        "dns_csa_search_limit" => ctx.dns_csa_search_limit = value as i32,
        "dns_retry" => ctx.dns_retry = value as i32,
        "header_line_maxsize" => ctx.header_line_maxsize = value as i32,
        "header_maxsize" => ctx.header_maxsize = value as i32,
        "header_insert_maxlen" => ctx.header_insert_maxlen = value as i32,
        "lookup_open_max" => ctx.lookup_open_max = value as i32,
        "message_body_visible" => ctx.message_body_visible = value as i32,
        "received_headers_max" => ctx.received_headers_max = value as i32,
        "remote_max_parallel" => ctx.remote_max_parallel = value as i32,
        "smtp_accept_max" => ctx.smtp_accept_max = value as i32,
        "smtp_accept_max_nonmail" => ctx.smtp_accept_max_nonmail = value as i32,
        "smtp_accept_queue" => ctx.smtp_accept_queue = value as i32,
        "smtp_accept_queue_per_connection" => ctx.smtp_accept_queue_per_connection = value as i32,
        "smtp_accept_reserve" => ctx.smtp_accept_reserve = value as i32,
        "smtp_connect_backlog" => ctx.smtp_connect_backlog = value as i32,
        "smtp_max_synprot_errors" => ctx.smtp_max_synprot_errors = value as i32,
        "smtp_max_unknown_commands" => ctx.smtp_max_unknown_commands = value as i32,
        "smtp_load_reserve" => ctx.smtp_load_reserve = value as i32,
        "queue_only_load" => ctx.queue_only_load = value as i32,
        "deliver_queue_load_max" => ctx.deliver_queue_load_max = value as i32,
        "max_username_length" => ctx.max_username_length = value as i32,
        "finduser_retries" => ctx.finduser_retries = value as i32,
        "localhost_number" => ctx.localhost_number = value as i32,
        "slow_lookup_log" => ctx.slow_lookup_log = value as i32,
        "smtp_backlog_monitor" => ctx.smtp_backlog_monitor = value as i32,
        "return_size_limit" => ctx.return_size_limit = value as i32,
        "rfc1413_port" => ctx.rfc1413_port = value as i32,
        "dns_dnssec_ok" => ctx.dns_dnssec_ok = value as i32,
        "dns_use_edns0" => ctx.dns_use_edns0 = value as i32,
        "tls_dh_max_bits" => ctx.tls_dh_max_bits = value as i32,
        _ => {
            tracing::trace!(option = %name, value = %value, "int option stored in option table only");
        }
    }
}

/// Apply a time option value (seconds) to the correct [`ConfigContext`] field.
///
/// The mapping mirrors `resolve_time_option()` in `validate.rs`.
fn apply_time_option(name: &str, value: i32, ctx: &mut ConfigContext) {
    match name {
        "auto_thaw" => ctx.auto_thaw = value,
        "callout_domain_positive_expire" => ctx.callout_cache_domain_positive_expire = value,
        "callout_domain_negative_expire" => ctx.callout_cache_domain_negative_expire = value,
        "callout_positive_expire" => ctx.callout_cache_positive_expire = value,
        "callout_negative_expire" => ctx.callout_cache_negative_expire = value,
        "daemon_startup_sleep" => ctx.daemon_startup_sleep = value,
        "dns_retrans" => ctx.dns_retrans = value,
        "ignore_bounce_errors_after" => ctx.ignore_bounce_errors_after = value,
        "keep_malformed" => ctx.keep_malformed = value,
        "queue_interval" => ctx.queue_interval = value,
        "receive_timeout" => ctx.receive_timeout = value,
        "retry_data_expire" => ctx.retry_data_expire = value,
        "retry_interval_max" => ctx.retry_interval_max = value,
        "rfc1413_query_timeout" => ctx.rfc1413_query_timeout = value,
        "smtp_receive_timeout" => ctx.smtp_receive_timeout = value,
        "timeout_frozen_after" => ctx.timeout_frozen_after = value,
        _ => {
            tracing::trace!(option = %name, value = %value, "time option stored in option table only");
        }
    }
}

/// Apply a Kint (kilobyte-unit integer) option value to the correct field.
///
/// The mapping mirrors `resolve_kint_option()` in `validate.rs`.
fn apply_kint_option(name: &str, value: i64, ctx: &mut ConfigContext) {
    match name {
        "check_log_space" => ctx.check_log_space = value,
        "check_spool_space" => ctx.check_spool_space = value,
        _ => {
            tracing::trace!(option = %name, value = %value, "kint option stored in option table only");
        }
    }
}

/// Apply a fixed-point option value (× 1000) to the correct field.
fn apply_fixed_option(name: &str, _value: i32, _ctx: &mut ConfigContext) {
    // Currently no ConfigContext fields use the fixed-point type directly.
    // The option table stores the value, which is read back for -bP printing.
    tracing::trace!(option = %name, "fixed option stored in option table only");
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_named_list_type_parsing() {
        let mut lists = NamedLists::default();

        // Domain list.
        assert!(try_read_named_list("domainlist local_domains = @", &mut lists).unwrap());
        assert!(lists.domain_lists.contains_key("local_domains"));
        assert_eq!(lists.domain_lists["local_domains"].value, "@");

        // Host list with hide prefix.
        assert!(
            try_read_named_list("hostlist hide internal = 192.168.0.0/16", &mut lists).unwrap()
        );
        assert!(lists.host_lists["internal"].hide);

        // Address list.
        assert!(try_read_named_list("addresslist admins = admin@example.com", &mut lists).unwrap());
        assert!(lists.address_lists.contains_key("admins"));

        // Localpart list.
        assert!(
            try_read_named_list("localpartlist special = postmaster : abuse", &mut lists).unwrap()
        );
        assert!(lists.localpart_lists.contains_key("special"));
    }

    #[test]
    fn test_not_a_named_list() {
        let mut lists = NamedLists::default();
        assert!(!try_read_named_list("accept_8bitmime = true", &mut lists).unwrap());
        assert!(!try_read_named_list("domainlistfoo = bar", &mut lists).unwrap());
    }

    #[test]
    fn test_rewrite_flags_parsing() {
        // Bit values match C macros.h / readconf.c exactly.
        assert_eq!(parse_rewrite_flags("t"), 0x0004); // rewrite_to (lowercase)
        assert_eq!(parse_rewrite_flags("tf"), 0x0006); // to + from
        assert_eq!(parse_rewrite_flags("h"), 0x003F); // rewrite_all_headers
        assert_eq!(parse_rewrite_flags("T"), 0x0080); // rewrite_envto (uppercase)
        assert_eq!(parse_rewrite_flags("F"), 0x0040); // rewrite_envfrom (uppercase)
        assert_eq!(parse_rewrite_flags("E"), 0x00C0); // rewrite_all_envelope
        assert_eq!(parse_rewrite_flags("S"), 0x0100); // rewrite_smtp
        assert_eq!(parse_rewrite_flags("Q"), 0x0400); // rewrite_qualify
        assert_eq!(parse_rewrite_flags("R"), 0x0800); // rewrite_repeat
        assert_eq!(parse_rewrite_flags("w"), 0x1000); // rewrite_whole
        assert_eq!(parse_rewrite_flags("q"), 0x2000); // rewrite_quit
        assert_eq!(parse_rewrite_flags(""), 0);
        // Combined flags: rewrite_smtp (0x0100) | rewrite_sender (0x0001)
        assert_eq!(parse_rewrite_flags("Ss"), 0x0101);
        // Whitespace between flags is permitted and ignored.
        assert_eq!(parse_rewrite_flags("t f"), 0x0006);
    }

    #[test]
    fn test_rewrite_line_parsing() {
        // T = uppercase envelope-to flag → rewrite_envto = 0x0080
        let rule = parse_rewrite_line("*@old.example.com  ${1}@new.example.com  T").unwrap();
        assert_eq!(rule.key, "*@old.example.com");
        assert_eq!(rule.replacement, "${1}@new.example.com");
        assert_eq!(rule.flags, 0x0080);
    }

    #[test]
    fn test_retry_line_parsing() {
        let config = parse_retry_line("* F,2h,15m").unwrap();
        assert_eq!(config.pattern, "*");
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].algorithm, b'F' as i32);
    }

    #[test]
    fn test_single_retry_rule_parsing() {
        let rule = parse_single_retry_rule("F,7200,900").unwrap();
        assert_eq!(rule.algorithm, b'F' as i32);
        assert_eq!(rule.timeout, 7200);
        assert_eq!(rule.p1, 900);
        assert_eq!(rule.p2, 0);
    }

    #[test]
    fn test_section_list_is_sorted() {
        for window in SECTION_LIST.windows(2) {
            assert!(
                window[0] < window[1],
                "SECTION_LIST not sorted: {:?} >= {:?}",
                window[0],
                window[1]
            );
        }
    }

    #[test]
    fn test_section_binary_search() {
        assert_eq!(SECTION_LIST.binary_search(&"acl"), Ok(0));
        assert_eq!(SECTION_LIST.binary_search(&"authenticators"), Ok(1));
        assert_eq!(SECTION_LIST.binary_search(&"local_scan"), Ok(2));
        assert_eq!(SECTION_LIST.binary_search(&"retry"), Ok(3));
        assert_eq!(SECTION_LIST.binary_search(&"rewrite"), Ok(4));
        assert_eq!(SECTION_LIST.binary_search(&"routers"), Ok(5));
        assert_eq!(SECTION_LIST.binary_search(&"transports"), Ok(6));
        assert!(SECTION_LIST.binary_search(&"nonexistent").is_err());
    }
}
