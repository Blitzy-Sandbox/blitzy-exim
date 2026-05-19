// Copyright (c) The Exim Maintainers 2020 - 2025
// Copyright (c) University of Cambridge 1995 - 2018
// SPDX-License-Identifier: GPL-2.0-or-later

//! # ACL Variable Management
//!
//! This module implements ACL variable creation, lookup, spool serialization,
//! and standalone variable setting for `-be` (expand-test) mode. It translates
//! the variable management functions from the end of `src/src/acl.c` into
//! idiomatic Rust.
//!
//! ## Source Mapping (from `acl.c`)
//!
//! - Lines 5069–5081: `acl_var_create()` — creates or reuses a variable node in
//!   a binary tree (`acl_var_c` for connection-scoped, `acl_var_m` for message-scoped).
//! - Lines 5105–5119: `acl_var_write()` — serializes ACL variables to spool file
//!   format with taint quoter support.
//! - Lines 5124–5141: `acl_standalone_setvar()` — standalone variable setting for
//!   `-be` expand-test mode.
//! - Lines 782–835: `acl_varname_to_cond()` — variable name validation.
//!
//! ## Storage Model
//!
//! ACL variables are stored in two sorted maps (replacing C's binary trees
//! `acl_var_c` and `acl_var_m`):
//!
//! - **Connection-scoped** (`acl_c*`): Persist across messages in the same SMTP
//!   session. Reset only when the SMTP connection closes.
//! - **Message-scoped** (`acl_m*`): Reset between messages within the same SMTP
//!   session.
//!
//! [`BTreeMap`] is used for deterministic sorted output, which is essential for
//! byte-level spool compatibility with C Exim (AAP §0.7.1).
//!
//! ## Spool Format
//!
//! Each variable is serialized as two lines:
//!
//! ```text
//! -aclc {suffix} {value_length}
//! {value}
//! ```
//!
//! Where `{suffix}` is the portion of the variable name after `acl_c` or `acl_m`
//! (e.g., `0` for `acl_c0`, `_counter` for `acl_m_counter`), and `{value_length}`
//! is the byte length of the value string. This format is byte-level compatible
//! with C Exim's `acl_var_write()`.

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};

// ---------------------------------------------------------------------------
// Error Type
// ---------------------------------------------------------------------------

/// Errors that can occur during ACL variable operations.
///
/// Replaces ad-hoc error string handling from C `acl.c` variable management
/// functions. Each variant provides a descriptive error message for diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum AclVarError {
    /// The variable name is not recognized as a valid ACL variable.
    ///
    /// This covers names that don't start with `acl_c`, `acl_m`, or one of
    /// the special DKIM variable names.
    #[error("invalid ACL variable name: {name}")]
    InvalidName {
        /// The invalid variable name that was provided.
        name: String,
    },

    /// The variable name does not start with `acl_c` or `acl_m`.
    ///
    /// ACL variables must be scoped to either connection (`acl_c`) or
    /// message (`acl_m`).
    #[error("variable name must start with 'acl_c' or 'acl_m': {name}")]
    InvalidScope {
        /// The variable name with the invalid scope prefix.
        name: String,
    },

    /// The variable name has an invalid format after the `acl_c`/`acl_m` prefix.
    ///
    /// After the prefix, the name must be either a single digit (`0`–`9`) for
    /// numbered variables, or an underscore followed by an alphanumeric
    /// identifier for named variables.
    #[error("invalid variable name format after prefix: {name}")]
    InvalidFormat {
        /// The variable name with the invalid format.
        name: String,
    },

    /// An I/O error occurred during spool serialization or deserialization.
    #[error("spool serialization error: {0}")]
    SpoolError(#[from] std::io::Error),

    /// An error occurred during string expansion in standalone variable setting.
    ///
    /// This can happen when using `-be` (expand-test) mode with invalid
    /// expansion syntax in the variable value.
    #[error("expansion error during standalone set: {0}")]
    ExpansionError(String),
}

// ---------------------------------------------------------------------------
// AclVarScope Enum
// ---------------------------------------------------------------------------

/// The two scopes of ACL variables.
///
/// Connection-scoped variables (`acl_c*`) persist across messages in the same
/// SMTP session. Message-scoped variables (`acl_m*`) are reset between messages.
///
/// This replaces the implicit scope determination in C where `acl_var_c` and
/// `acl_var_m` are separate global binary tree roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AclVarScope {
    /// Connection-scoped variables: `acl_c0`..`acl_c9`, `acl_c_name`.
    ///
    /// Stored in the `acl_var_c` tree (C global). Persists for the entire
    /// SMTP session lifetime.
    Connection,

    /// Message-scoped variables: `acl_m0`..`acl_m9`, `acl_m_name`.
    ///
    /// Stored in the `acl_var_m` tree (C global). Reset at the start of
    /// each new message transaction.
    Message,
}

// ---------------------------------------------------------------------------
// AclVariable Struct
// ---------------------------------------------------------------------------

/// A single ACL variable with its name, value, and scope.
///
/// Replaces C `tree_node` entries in the `acl_var_c` / `acl_var_m` binary
/// trees. In C, the variable name is stored as the tree node key and the
/// value is stored in `node->data.ptr`. In Rust, we use explicit fields.
///
/// # Examples
///
/// ```ignore
/// let var = AclVariable {
///     name: "acl_c0".to_string(),
///     value: "hello".to_string(),
///     scope: AclVarScope::Connection,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct AclVariable {
    /// Full variable name (e.g., `"acl_c0"`, `"acl_m_counter"`, `"acl_c_session_id"`).
    pub name: String,

    /// Variable value (the string value assigned via the SET modifier).
    pub value: String,

    /// The scope (connection or message).
    pub scope: AclVarScope,
}

// ---------------------------------------------------------------------------
// AclVarStore — Main Storage
// ---------------------------------------------------------------------------

/// Storage for ACL variables, replacing the C binary trees `acl_var_c` and
/// `acl_var_m`.
///
/// Uses [`BTreeMap`] for sorted order (matching C `tree_insertnode` behavior
/// which produces sorted traversal) and for deterministic spool output order
/// required by byte-level spool compatibility (AAP §0.7.1).
///
/// This struct is designed to be a field within `MessageContext` — no global
/// mutable state is used (AAP §0.4.4 scoped context passing).
///
/// # Lifecycle
///
/// - [`AclVarStore::new()`] — creates an empty store at connection start.
/// - [`AclVarStore::reset_message_vars()`] — clears message-scoped variables
///   between messages within the same SMTP session.
/// - [`AclVarStore::reset_connection_vars()`] — clears connection-scoped
///   variables when an SMTP session ends.
pub struct AclVarStore {
    /// Connection-scoped variables (`acl_c*`).
    ///
    /// Keys are full variable names (e.g., `"acl_c0"`, `"acl_c_session_id"`).
    /// Values are the string values assigned via the SET modifier.
    connection_vars: BTreeMap<String, String>,

    /// Message-scoped variables (`acl_m*`).
    ///
    /// Keys are full variable names (e.g., `"acl_m0"`, `"acl_m_counter"`).
    /// Values are the string values assigned via the SET modifier.
    message_vars: BTreeMap<String, String>,
}

/// Parsed result from a spool header line, used internally during deserialization.
///
/// This is an implementation detail of [`AclVarStore::read_from_spool()`] and
/// [`AclVarStore::parse_spool_header()`].
struct SpoolHeaderParsed {
    /// The full variable name (e.g., `"acl_c0"`, `"acl_m_counter"`).
    full_name: String,
    /// The variable scope.
    scope: AclVarScope,
    /// The declared value length in the spool header.
    ///
    /// Parsed for format validation; the actual value is read line-by-line.
    _value_length: usize,
}

impl AclVarStore {
    // -----------------------------------------------------------------------
    // Construction and Lifecycle
    // -----------------------------------------------------------------------

    /// Create a new, empty ACL variable store.
    ///
    /// Both connection-scoped and message-scoped variable maps are initialized
    /// as empty. This should be called once per SMTP connection (or per
    /// non-SMTP message processing invocation).
    pub fn new() -> Self {
        tracing::trace!("ACL variable store created");
        Self {
            connection_vars: BTreeMap::new(),
            message_vars: BTreeMap::new(),
        }
    }

    /// Clear all message-scoped variables.
    ///
    /// Called between messages within the same SMTP session to reset
    /// `acl_m*` variables. Connection-scoped `acl_c*` variables are
    /// preserved.
    ///
    /// Replaces the C pattern of calling `tree_walk(acl_var_m, ..., tree_delete)`
    /// followed by resetting the `acl_var_m` root to `NULL`.
    pub fn reset_message_vars(&mut self) {
        let count = self.message_vars.len();
        self.message_vars.clear();
        tracing::trace!(count = count, "reset message-scoped ACL variables");
    }

    /// Clear all connection-scoped variables.
    ///
    /// Called when an SMTP session ends to reset `acl_c*` variables.
    /// This also clears message-scoped variables since the session is over.
    ///
    /// Replaces the C pattern of resetting the `acl_var_c` root to `NULL`.
    pub fn reset_connection_vars(&mut self) {
        let conn_count = self.connection_vars.len();
        let msg_count = self.message_vars.len();
        self.connection_vars.clear();
        self.message_vars.clear();
        tracing::trace!(
            connection_count = conn_count,
            message_count = msg_count,
            "reset connection-scoped ACL variables (both scopes cleared)"
        );
    }

    // -----------------------------------------------------------------------
    // Variable Creation — replaces acl_var_create() (acl.c lines 5069-5081)
    // -----------------------------------------------------------------------

    /// Create or update an ACL variable.
    ///
    /// Replaces C `acl_var_create()` (acl.c lines 5069–5081).
    ///
    /// In C, this does a binary tree insert under `acl_var_c` or `acl_var_m`
    /// root. If a node with the same name exists, it is reused (value updated).
    /// If not, a new node is created and inserted.
    ///
    /// # Arguments
    ///
    /// * `name` — Full variable name (e.g., `"acl_c0"`, `"acl_m_counter"`).
    ///   The name prefix determines scope: `"acl_c"` → connection scope,
    ///   `"acl_m"` → message scope.
    /// * `value` — The string value to assign.
    ///
    /// # Errors
    ///
    /// Returns [`AclVarError::InvalidScope`] if the name does not start with
    /// `"acl_c"` or `"acl_m"`.
    pub fn create(&mut self, name: &str, value: String) -> Result<(), AclVarError> {
        let scope = Self::determine_scope(name)?;
        let store = match scope {
            AclVarScope::Connection => &mut self.connection_vars,
            AclVarScope::Message => &mut self.message_vars,
        };

        let is_update = store.contains_key(name);
        store.insert(name.to_string(), value);

        tracing::debug!(
            variable = name,
            scope = ?scope,
            action = if is_update { "updated" } else { "created" },
            "ACL variable set"
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Variable Lookup
    // -----------------------------------------------------------------------

    /// Look up an ACL variable by its full name.
    ///
    /// Searches both connection-scoped and message-scoped maps based on the
    /// variable name prefix. Returns `None` if the variable does not exist.
    ///
    /// # Arguments
    ///
    /// * `name` — Full variable name (e.g., `"acl_c0"`, `"acl_m_counter"`).
    ///
    /// # Returns
    ///
    /// A reference to the variable's value string, or `None` if not found.
    pub fn get(&self, name: &str) -> Option<&str> {
        if name.starts_with("acl_c") {
            self.connection_vars.get(name).map(String::as_str)
        } else if name.starts_with("acl_m") {
            self.message_vars.get(name).map(String::as_str)
        } else {
            // For special variables like dkim_verify_status, check both maps.
            // These would not normally be stored here, but handle gracefully.
            None
        }
    }

    // -----------------------------------------------------------------------
    // Count and Iteration
    // -----------------------------------------------------------------------

    /// Returns the number of connection-scoped variables currently set.
    pub fn connection_var_count(&self) -> usize {
        self.connection_vars.len()
    }

    /// Returns the number of message-scoped variables currently set.
    pub fn message_var_count(&self) -> usize {
        self.message_vars.len()
    }

    /// Returns an iterator over connection-scoped variables in sorted order.
    ///
    /// Each item is a `(&String, &String)` tuple of (name, value).
    /// The iterator yields variables in lexicographic order of their names,
    /// matching the sorted traversal behavior of C's binary tree.
    pub fn connection_vars(&self) -> impl Iterator<Item = (&String, &String)> {
        self.connection_vars.iter()
    }

    /// Returns an iterator over message-scoped variables in sorted order.
    ///
    /// Each item is a `(&String, &String)` tuple of (name, value).
    /// The iterator yields variables in lexicographic order of their names,
    /// matching the sorted traversal behavior of C's binary tree.
    pub fn message_vars(&self) -> impl Iterator<Item = (&String, &String)> {
        self.message_vars.iter()
    }

    // -----------------------------------------------------------------------
    // Spool Serialization — replaces acl_var_write() (acl.c lines 5105-5119)
    // -----------------------------------------------------------------------

    /// Serialize ACL variables to spool file format.
    ///
    /// Replaces C `acl_var_write()` (acl.c lines 5105–5119).
    ///
    /// ## Spool Format
    ///
    /// For each variable, two lines are written:
    ///
    /// ```text
    /// -aclc {suffix} {value_length}
    /// {value}
    /// ```
    ///
    /// Where:
    /// - `-aclc` or `-aclm` indicates the scope (connection or message).
    /// - `{suffix}` is the portion of the variable name after `acl_c` or `acl_m`
    ///   (e.g., `0` for `acl_c0`, `_counter` for `acl_m_counter`).
    /// - `{value_length}` is the byte length of the value string.
    /// - `{value}` is the value string on the next line.
    ///
    /// The output order is determined by the [`BTreeMap`] sorted key order,
    /// ensuring deterministic spool files. Connection variables are written
    /// first, then message variables, matching C's `tree_walk` traversal
    /// order for `acl_var_c` followed by `acl_var_m`.
    ///
    /// ## Taint Compatibility
    ///
    /// In C Exim, tainted values are prefixed with an extra `-` and optional
    /// `(quoter_name)` on the spool line. In Rust, since taint tracking is
    /// compile-time via newtypes, we write the non-tainted format. The
    /// [`read_from_spool`](AclVarStore::read_from_spool) method handles
    /// both tainted and non-tainted formats for backward compatibility.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if writing to the writer fails.
    pub fn write_to_spool<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        // Write connection-scoped variables first (matching C's tree_walk order
        // on acl_var_c before acl_var_m in spool_out.c).
        self.write_scope_to_spool(writer, &self.connection_vars, "acl_c", 'c')?;

        // Write message-scoped variables.
        self.write_scope_to_spool(writer, &self.message_vars, "acl_m", 'm')?;

        tracing::trace!(
            connection_count = self.connection_vars.len(),
            message_count = self.message_vars.len(),
            "ACL variables written to spool"
        );

        Ok(())
    }

    /// Internal helper: write all variables from one scope map to spool format.
    ///
    /// Each variable is written as:
    /// ```text
    /// -acl{scope_char} {suffix} {value_length}
    /// {value}
    /// ```
    fn write_scope_to_spool<W: Write>(
        &self,
        writer: &mut W,
        vars: &BTreeMap<String, String>,
        prefix: &str,
        scope_char: char,
    ) -> io::Result<()> {
        for (name, value) in vars {
            // Extract the suffix: everything after "acl_c" or "acl_m" in the
            // full variable name. In C, the tree stores names like "c0", "c_foo",
            // and acl_var_write outputs "acl%c %s %d\n%s\n" with name[0] and
            // name+1. Our suffix corresponds to C's name+1.
            let suffix = if let Some(stripped) = name.strip_prefix(prefix) {
                stripped
            } else {
                // Defensive: if the name doesn't match the expected prefix,
                // use the full name after "acl_" as a fallback.
                name.strip_prefix("acl_")
                    .and_then(|s| s.get(1..)) // skip the scope char
                    .unwrap_or(name.as_str())
            };

            // Write the spool line: -acl{c|m} {suffix} {value_length}
            // Followed by: {value}
            // Matching C's: fprintf(f, "acl%c %s %d\n%s\n", ...)
            write!(
                writer,
                "-acl{} {} {}\n{}\n",
                scope_char,
                suffix,
                value.len(),
                value
            )?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Spool Deserialization
    // -----------------------------------------------------------------------

    /// Deserialize ACL variables from spool file format.
    ///
    /// Reads lines with `-aclc` and `-aclm` prefixes and populates the store.
    /// This is the inverse of [`write_to_spool`](AclVarStore::write_to_spool).
    ///
    /// ## Format Handling
    ///
    /// Handles both non-tainted and tainted spool formats:
    ///
    /// - Non-tainted: `-aclc {suffix} {length}\n{value}\n`
    /// - Tainted (no quoter): `--aclc {suffix} {length}\n{value}\n`
    /// - Tainted (with quoter): `--(quoter)aclc {suffix} {length}\n{value}\n`
    ///
    /// The taint status is noted but not stored separately, since Rust uses
    /// compile-time taint tracking via newtypes rather than runtime flags.
    ///
    /// ## Termination
    ///
    /// Reading stops when:
    /// - End of input is reached.
    /// - A line is encountered that does not start with `-aclc` or `-aclm`
    ///   (or the tainted variants `--aclc`/`--aclm`/`--(...)aclc`/`--(...)aclm`).
    ///
    /// # Errors
    ///
    /// Returns an I/O error if reading from the reader fails, or if the spool
    /// data is malformed (e.g., missing value line, invalid length).
    pub fn read_from_spool<R: BufRead>(&mut self, reader: &mut R) -> io::Result<()> {
        let mut line = String::new();
        loop {
            line.clear();
            let bytes_read = reader.read_line(&mut line)?;
            if bytes_read == 0 {
                break; // EOF
            }

            let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');

            // Parse the header line to extract scope, suffix, and value length.
            let parsed = match Self::parse_spool_header(trimmed) {
                Some(p) => p,
                None => break, // Not an ACL variable line; stop reading.
            };

            // Read the value line.
            let mut value_line = String::new();
            let value_bytes = reader.read_line(&mut value_line)?;
            if value_bytes == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "unexpected EOF reading value for ACL variable '{}' (expected {} bytes)",
                        parsed.full_name, parsed._value_length,
                    ),
                ));
            }

            // Trim trailing newline from value. The value length in the header
            // refers to the string content, not including the trailing newline.
            let value = value_line
                .trim_end_matches('\n')
                .trim_end_matches('\r')
                .to_string();

            // Insert into the appropriate scope map.
            let store = match parsed.scope {
                AclVarScope::Connection => &mut self.connection_vars,
                AclVarScope::Message => &mut self.message_vars,
            };
            store.insert(parsed.full_name, value);
        }

        tracing::trace!(
            connection_count = self.connection_vars.len(),
            message_count = self.message_vars.len(),
            "ACL variables read from spool"
        );

        Ok(())
    }

    /// Parse a single spool header line into its components.
    ///
    /// Handles these formats:
    /// - `-aclc {suffix} {length}` (non-tainted connection var)
    /// - `-aclm {suffix} {length}` (non-tainted message var)
    /// - `--aclc {suffix} {length}` (tainted connection var, no quoter)
    /// - `--aclm {suffix} {length}` (tainted message var, no quoter)
    /// - `--(quoter)aclc {suffix} {length}` (tainted with quoter)
    /// - `--(quoter)aclm {suffix} {length}` (tainted with quoter)
    ///
    /// Returns `None` if the line does not match any recognized format.
    fn parse_spool_header(line: &str) -> Option<SpoolHeaderParsed> {
        // All ACL variable spool lines start with at least one '-'.
        let rest = line.strip_prefix('-')?;

        // Determine if tainted (extra '-' prefix) and skip the taint/quoter info.
        let acl_part = if let Some(after_dash) = rest.strip_prefix('-') {
            // Tainted format: skip optional "(quoter_name)" before "acl{c|m}"
            if let Some(after_paren) = after_dash.strip_prefix('(') {
                // Find the closing paren and skip it.
                let close_idx = after_paren.find(')')?;
                &after_paren[close_idx + 1..]
            } else {
                after_dash
            }
        } else {
            rest
        };

        // Now acl_part should start with "aclc" or "aclm" followed by a space.
        let (scope, scope_prefix, after_acl) = if let Some(rem) = acl_part.strip_prefix("aclc ") {
            (AclVarScope::Connection, "acl_c", rem)
        } else if let Some(rem) = acl_part.strip_prefix("aclm ") {
            (AclVarScope::Message, "acl_m", rem)
        } else {
            return None;
        };

        // after_acl is "{suffix} {length}"
        // Split on the LAST space to separate suffix from length, since the
        // suffix itself does not contain spaces.
        let last_space = after_acl.rfind(' ')?;
        let suffix = &after_acl[..last_space];
        let length_str = &after_acl[last_space + 1..];

        let value_length: usize = length_str.parse().ok()?;

        // Reconstruct the full variable name: "acl_c" + suffix or "acl_m" + suffix.
        // In C, tree stores "c0" and acl_var_write outputs name+1 as suffix.
        // So suffix "0" → full name "acl_c0", suffix "_counter" → "acl_m_counter".
        let full_name = format!("{}{}", scope_prefix, suffix);

        Some(SpoolHeaderParsed {
            full_name,
            scope,
            _value_length: value_length,
        })
    }

    // -----------------------------------------------------------------------
    // Scope Determination (private helper)
    // -----------------------------------------------------------------------

    /// Determine the variable scope from its full name prefix.
    ///
    /// This is a simple prefix check used by [`create()`](AclVarStore::create)
    /// and [`get()`](AclVarStore::get) to route variables to the correct
    /// internal map.
    ///
    /// - Names starting with `"acl_c"` → [`AclVarScope::Connection`]
    /// - Names starting with `"acl_m"` → [`AclVarScope::Message`]
    /// - Anything else → [`AclVarError::InvalidScope`]
    fn determine_scope(name: &str) -> Result<AclVarScope, AclVarError> {
        if name.starts_with("acl_c") {
            Ok(AclVarScope::Connection)
        } else if name.starts_with("acl_m") {
            Ok(AclVarScope::Message)
        } else {
            Err(AclVarError::InvalidScope {
                name: name.to_string(),
            })
        }
    }
}

impl Default for AclVarStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Variable Name Validation — replaces acl_varname_to_cond() (acl.c 782-835)
// ---------------------------------------------------------------------------

/// Validate an ACL variable name and determine its scope.
///
/// Replaces C `acl_varname_to_cond()` (acl.c lines 782–835).
///
/// ## Valid Patterns
///
/// - `acl_c` + single digit (`0`–`9`): Numbered connection variable
///   (e.g., `acl_c0`, `acl_c9`).
/// - `acl_c_` + identifier: Named connection variable
///   (e.g., `acl_c_session_id`).
/// - `acl_m` + single digit (`0`–`9`): Numbered message variable
///   (e.g., `acl_m0`, `acl_m9`).
/// - `acl_m_` + identifier: Named message variable
///   (e.g., `acl_m_counter`).
/// - `dkim_verify_status` (feature-gated on `dkim`): DKIM verification
///   status — allowed as an assignable variable.
/// - `dkim_verify_reason` (feature-gated on `dkim`): DKIM verification
///   reason — allowed as an assignable variable.
///
/// ## Invalid Patterns
///
/// - Names not starting with `acl_c` or `acl_m` (unless DKIM special case).
/// - Numbered variables with more than one digit (e.g., `acl_c00`).
/// - Names with only the prefix and no suffix (e.g., `acl_c`).
/// - Named variables with empty identifier (e.g., `acl_c_`).
/// - Names containing invalid characters (only alphanumeric and underscore
///   are allowed in the identifier portion).
///
/// # Errors
///
/// Returns an [`AclVarError`] variant describing the validation failure.
pub fn validate_varname(name: &str) -> Result<AclVarScope, AclVarError> {
    // Special case: DKIM variables (feature-gated).
    #[cfg(feature = "dkim")]
    {
        if name == "dkim_verify_status" || name == "dkim_verify_reason" {
            // DKIM verify variables are message-scoped special cases.
            // In C (acl.c lines 788-801), these are accepted with the full name
            // stored directly (not stripped of a prefix).
            return Ok(AclVarScope::Message);
        }
    }

    // Must start with "acl_c" or "acl_m".
    let (scope, suffix) = if let Some(s) = name.strip_prefix("acl_c") {
        (AclVarScope::Connection, s)
    } else if let Some(s) = name.strip_prefix("acl_m") {
        (AclVarScope::Message, s)
    } else {
        return Err(AclVarError::InvalidScope {
            name: name.to_string(),
        });
    };

    // The suffix must not be empty.
    if suffix.is_empty() {
        return Err(AclVarError::InvalidFormat {
            name: name.to_string(),
        });
    }

    // Determine if this is a numbered variable or a named variable based on
    // the first character of the suffix.
    let first_char = suffix.as_bytes()[0];

    if first_char.is_ascii_digit() {
        // Numbered variable: must be exactly one digit (0-9) with nothing after.
        // E.g., acl_c0, acl_m5 are valid; acl_c00, acl_c0foo are invalid.
        if suffix.len() != 1 {
            return Err(AclVarError::InvalidFormat {
                name: name.to_string(),
            });
        }
        Ok(scope)
    } else if first_char == b'_' {
        // Named variable: underscore followed by at least one alphanumeric
        // or underscore character forming a valid identifier.
        let identifier = &suffix[1..]; // Part after the leading underscore.

        if identifier.is_empty() {
            return Err(AclVarError::InvalidFormat {
                name: name.to_string(),
            });
        }

        // Validate that all identifier characters are alphanumeric or underscore.
        // This matches C's validation loop (acl.c lines 821-827):
        //   for ( ; *endptr && *endptr != '=' && !isspace(*endptr); endptr++)
        //     if (!isalnum(*endptr) && *endptr != '_') → error
        for ch in identifier.chars() {
            if !ch.is_ascii_alphanumeric() && ch != '_' {
                return Err(AclVarError::InvalidName {
                    name: name.to_string(),
                });
            }
        }

        Ok(scope)
    } else {
        // First character after prefix is neither digit nor underscore.
        // In C (acl.c lines 813-819):
        //   "digit or underscore must follow acl_c or acl_m"
        Err(AclVarError::InvalidFormat {
            name: name.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Standalone Variable Setting — replaces acl_standalone_setvar() (5124-5141)
// ---------------------------------------------------------------------------

/// Set an ACL variable from the command line for `-be` (expand-test) mode.
///
/// Replaces C `acl_standalone_setvar()` (acl.c lines 5124–5141).
///
/// This is used when running Exim with `-be 'set,acl_m_foo=value'` to test
/// string expansion with ACL variables pre-set. The argument format is:
///
/// ```text
/// acl_c_name=value
/// acl_m_name=value
/// ```
///
/// ## Algorithm
///
/// 1. Split the argument on the first `=` to extract variable name and value.
/// 2. Trim whitespace from the variable name.
/// 3. Validate the variable name via [`validate_varname()`].
/// 4. Store the value in the appropriate scope of the variable store.
///
/// ## Note on Expansion
///
/// In C Exim, the value is expanded via `expand_string()` before assignment.
/// In the Rust implementation, value expansion is the responsibility of the
/// caller (typically the `-be` mode handler in `exim-core`). This function
/// stores the value as-is.
///
/// # Errors
///
/// - [`AclVarError::InvalidFormat`] if the argument does not contain `=`.
/// - [`AclVarError::InvalidScope`] or [`AclVarError::InvalidName`] if the
///   variable name is not valid.
pub fn acl_standalone_setvar(store: &mut AclVarStore, arg: &str) -> Result<(), AclVarError> {
    // Split on the first '=' to extract name and value.
    // C equivalent: acl_data_to_cond() checks for '=' (acl.c lines 842-843).
    let (name_part, value_part) = match arg.split_once('=') {
        Some((n, v)) => (n.trim(), v),
        None => {
            return Err(AclVarError::InvalidFormat {
                name: arg.to_string(),
            });
        }
    };

    // Validate the variable name.
    let _scope = validate_varname(name_part)?;

    // Store the value. The full variable name is used as the key.
    store.create(name_part, value_part.to_string())?;

    tracing::debug!(
        variable = name_part,
        value = value_part,
        "standalone ACL variable set via -be mode"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // AclVarStore::new()
    // -----------------------------------------------------------------------

    #[test]
    fn test_new_store_is_empty() {
        let store = AclVarStore::new();
        assert_eq!(store.connection_var_count(), 0);
        assert_eq!(store.message_var_count(), 0);
    }

    // -----------------------------------------------------------------------
    // AclVarStore::create() and get()
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_connection_var() {
        let mut store = AclVarStore::new();
        store.create("acl_c0", "hello".to_string()).unwrap();
        assert_eq!(store.get("acl_c0"), Some("hello"));
        assert_eq!(store.connection_var_count(), 1);
        assert_eq!(store.message_var_count(), 0);
    }

    #[test]
    fn test_create_message_var() {
        let mut store = AclVarStore::new();
        store.create("acl_m0", "world".to_string()).unwrap();
        assert_eq!(store.get("acl_m0"), Some("world"));
        assert_eq!(store.connection_var_count(), 0);
        assert_eq!(store.message_var_count(), 1);
    }

    #[test]
    fn test_create_named_var() {
        let mut store = AclVarStore::new();
        store.create("acl_c_session", "abc123".to_string()).unwrap();
        assert_eq!(store.get("acl_c_session"), Some("abc123"));
    }

    #[test]
    fn test_update_existing_var() {
        let mut store = AclVarStore::new();
        store.create("acl_m_counter", "1".to_string()).unwrap();
        store.create("acl_m_counter", "2".to_string()).unwrap();
        assert_eq!(store.get("acl_m_counter"), Some("2"));
        assert_eq!(store.message_var_count(), 1);
    }

    #[test]
    fn test_create_invalid_scope() {
        let mut store = AclVarStore::new();
        let result = store.create("acl_x0", "bad".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_get_nonexistent() {
        let store = AclVarStore::new();
        assert_eq!(store.get("acl_c0"), None);
        assert_eq!(store.get("acl_m0"), None);
    }

    // -----------------------------------------------------------------------
    // AclVarStore::reset_*()
    // -----------------------------------------------------------------------

    #[test]
    fn test_reset_message_vars() {
        let mut store = AclVarStore::new();
        store.create("acl_c0", "conn".to_string()).unwrap();
        store.create("acl_m0", "msg".to_string()).unwrap();

        store.reset_message_vars();

        assert_eq!(store.get("acl_c0"), Some("conn"));
        assert_eq!(store.get("acl_m0"), None);
        assert_eq!(store.connection_var_count(), 1);
        assert_eq!(store.message_var_count(), 0);
    }

    #[test]
    fn test_reset_connection_vars() {
        let mut store = AclVarStore::new();
        store.create("acl_c0", "conn".to_string()).unwrap();
        store.create("acl_m0", "msg".to_string()).unwrap();

        store.reset_connection_vars();

        assert_eq!(store.get("acl_c0"), None);
        assert_eq!(store.get("acl_m0"), None);
        assert_eq!(store.connection_var_count(), 0);
        assert_eq!(store.message_var_count(), 0);
    }

    // -----------------------------------------------------------------------
    // validate_varname()
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_numbered_connection_vars() {
        for digit in '0'..='9' {
            let name = format!("acl_c{}", digit);
            let result = validate_varname(&name);
            assert!(result.is_ok(), "Expected {} to be valid", name);
            assert_eq!(result.unwrap(), AclVarScope::Connection);
        }
    }

    #[test]
    fn test_validate_numbered_message_vars() {
        for digit in '0'..='9' {
            let name = format!("acl_m{}", digit);
            let result = validate_varname(&name);
            assert!(result.is_ok(), "Expected {} to be valid", name);
            assert_eq!(result.unwrap(), AclVarScope::Message);
        }
    }

    #[test]
    fn test_validate_named_vars() {
        assert!(validate_varname("acl_c_foo").is_ok());
        assert!(validate_varname("acl_c_session_id").is_ok());
        assert!(validate_varname("acl_m_counter").is_ok());
        assert!(validate_varname("acl_m_bar123").is_ok());
        assert!(validate_varname("acl_c_a").is_ok());
        assert!(validate_varname("acl_m_X_Y_Z").is_ok());
    }

    #[test]
    fn test_validate_rejects_multi_digit() {
        assert!(validate_varname("acl_c00").is_err());
        assert!(validate_varname("acl_m10").is_err());
        assert!(validate_varname("acl_c0foo").is_err());
    }

    #[test]
    fn test_validate_rejects_wrong_prefix() {
        assert!(validate_varname("acl_x0").is_err());
        assert!(validate_varname("foo").is_err());
        assert!(validate_varname("").is_err());
        assert!(validate_varname("acl_").is_err());
    }

    #[test]
    fn test_validate_rejects_bare_prefix() {
        assert!(validate_varname("acl_c").is_err());
        assert!(validate_varname("acl_m").is_err());
    }

    #[test]
    fn test_validate_rejects_empty_named() {
        assert!(validate_varname("acl_c_").is_err());
        assert!(validate_varname("acl_m_").is_err());
    }

    #[test]
    fn test_validate_rejects_invalid_chars_in_name() {
        assert!(validate_varname("acl_c_foo-bar").is_err());
        assert!(validate_varname("acl_m_hello.world").is_err());
        assert!(validate_varname("acl_c_sp ace").is_err());
    }

    #[cfg(feature = "dkim")]
    #[test]
    fn test_validate_dkim_special_cases() {
        let result = validate_varname("dkim_verify_status");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), AclVarScope::Message);

        let result = validate_varname("dkim_verify_reason");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), AclVarScope::Message);
    }

    // -----------------------------------------------------------------------
    // Spool Serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_write_to_spool_connection_vars() {
        let mut store = AclVarStore::new();
        store.create("acl_c0", "hello".to_string()).unwrap();
        store.create("acl_c_session", "abc123".to_string()).unwrap();

        let mut buf = Vec::new();
        store.write_to_spool(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // BTreeMap sorts keys, so acl_c0 < acl_c_session (lexicographic).
        let expected = "-aclc 0 5\nhello\n-aclc _session 6\nabc123\n";
        assert_eq!(output, expected);
    }

    #[test]
    fn test_write_to_spool_message_vars() {
        let mut store = AclVarStore::new();
        store.create("acl_m0", "world".to_string()).unwrap();
        store.create("acl_m_counter", "42".to_string()).unwrap();

        let mut buf = Vec::new();
        store.write_to_spool(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let expected = "-aclm 0 5\nworld\n-aclm _counter 2\n42\n";
        assert_eq!(output, expected);
    }

    #[test]
    fn test_write_to_spool_mixed() {
        let mut store = AclVarStore::new();
        store.create("acl_c0", "conn_val".to_string()).unwrap();
        store.create("acl_m0", "msg_val".to_string()).unwrap();

        let mut buf = Vec::new();
        store.write_to_spool(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // Connection vars first, then message vars.
        let expected = "-aclc 0 8\nconn_val\n-aclm 0 7\nmsg_val\n";
        assert_eq!(output, expected);
    }

    #[test]
    fn test_write_to_spool_empty() {
        let store = AclVarStore::new();
        let mut buf = Vec::new();
        store.write_to_spool(&mut buf).unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn test_write_to_spool_empty_value() {
        let mut store = AclVarStore::new();
        store.create("acl_c0", String::new()).unwrap();

        let mut buf = Vec::new();
        store.write_to_spool(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert_eq!(output, "-aclc 0 0\n\n");
    }

    // -----------------------------------------------------------------------
    // Spool Deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_read_from_spool_basic() {
        let spool_data = "-aclc 0 5\nhello\n-aclm _counter 2\n42\n";
        let mut store = AclVarStore::new();
        store.read_from_spool(&mut spool_data.as_bytes()).unwrap();

        assert_eq!(store.get("acl_c0"), Some("hello"));
        assert_eq!(store.get("acl_m_counter"), Some("42"));
    }

    #[test]
    fn test_read_from_spool_tainted() {
        // Tainted format: extra dash, no quoter.
        let spool_data = "--aclc 0 5\nhello\n";
        let mut store = AclVarStore::new();
        store.read_from_spool(&mut spool_data.as_bytes()).unwrap();

        assert_eq!(store.get("acl_c0"), Some("hello"));
    }

    #[test]
    fn test_read_from_spool_tainted_with_quoter() {
        // Tainted format with quoter name in parens.
        let spool_data = "--(default)aclm _foo 3\nbar\n";
        let mut store = AclVarStore::new();
        store.read_from_spool(&mut spool_data.as_bytes()).unwrap();

        assert_eq!(store.get("acl_m_foo"), Some("bar"));
    }

    #[test]
    fn test_read_from_spool_empty() {
        let spool_data = "";
        let mut store = AclVarStore::new();
        store.read_from_spool(&mut spool_data.as_bytes()).unwrap();

        assert_eq!(store.connection_var_count(), 0);
        assert_eq!(store.message_var_count(), 0);
    }

    #[test]
    fn test_spool_roundtrip() {
        let mut original = AclVarStore::new();
        original.create("acl_c0", "val0".to_string()).unwrap();
        original
            .create("acl_c_session", "sess123".to_string())
            .unwrap();
        original.create("acl_m5", "five".to_string()).unwrap();
        original.create("acl_m_counter", "99".to_string()).unwrap();

        // Serialize to spool format.
        let mut buf = Vec::new();
        original.write_to_spool(&mut buf).unwrap();

        // Deserialize back.
        let mut restored = AclVarStore::new();
        restored.read_from_spool(&mut buf.as_slice()).unwrap();

        // Verify all variables match.
        assert_eq!(restored.get("acl_c0"), Some("val0"));
        assert_eq!(restored.get("acl_c_session"), Some("sess123"));
        assert_eq!(restored.get("acl_m5"), Some("five"));
        assert_eq!(restored.get("acl_m_counter"), Some("99"));
        assert_eq!(restored.connection_var_count(), 2);
        assert_eq!(restored.message_var_count(), 2);
    }

    // -----------------------------------------------------------------------
    // Iteration
    // -----------------------------------------------------------------------

    #[test]
    fn test_connection_vars_iterator() {
        let mut store = AclVarStore::new();
        store.create("acl_c1", "a".to_string()).unwrap();
        store.create("acl_c0", "b".to_string()).unwrap();

        let vars: Vec<_> = store.connection_vars().collect();
        // BTreeMap yields sorted order.
        assert_eq!(vars.len(), 2);
        assert_eq!(vars[0].0, "acl_c0");
        assert_eq!(vars[1].0, "acl_c1");
    }

    #[test]
    fn test_message_vars_iterator() {
        let mut store = AclVarStore::new();
        store.create("acl_m_counter", "1".to_string()).unwrap();
        store.create("acl_m0", "x".to_string()).unwrap();

        let vars: Vec<_> = store.message_vars().collect();
        assert_eq!(vars.len(), 2);
        assert_eq!(vars[0].0, "acl_m0");
        assert_eq!(vars[1].0, "acl_m_counter");
    }

    // -----------------------------------------------------------------------
    // acl_standalone_setvar()
    // -----------------------------------------------------------------------

    #[test]
    fn test_standalone_setvar_basic() {
        let mut store = AclVarStore::new();
        acl_standalone_setvar(&mut store, "acl_m_foo=bar").unwrap();
        assert_eq!(store.get("acl_m_foo"), Some("bar"));
    }

    #[test]
    fn test_standalone_setvar_numbered() {
        let mut store = AclVarStore::new();
        acl_standalone_setvar(&mut store, "acl_c0=hello").unwrap();
        assert_eq!(store.get("acl_c0"), Some("hello"));
    }

    #[test]
    fn test_standalone_setvar_empty_value() {
        let mut store = AclVarStore::new();
        acl_standalone_setvar(&mut store, "acl_m0=").unwrap();
        assert_eq!(store.get("acl_m0"), Some(""));
    }

    #[test]
    fn test_standalone_setvar_value_with_equals() {
        let mut store = AclVarStore::new();
        acl_standalone_setvar(&mut store, "acl_m_key=a=b=c").unwrap();
        assert_eq!(store.get("acl_m_key"), Some("a=b=c"));
    }

    #[test]
    fn test_standalone_setvar_no_equals() {
        let mut store = AclVarStore::new();
        let result = acl_standalone_setvar(&mut store, "acl_m_foo");
        assert!(result.is_err());
    }

    #[test]
    fn test_standalone_setvar_invalid_name() {
        let mut store = AclVarStore::new();
        let result = acl_standalone_setvar(&mut store, "bad_name=value");
        assert!(result.is_err());
    }

    #[test]
    fn test_standalone_setvar_with_whitespace() {
        let mut store = AclVarStore::new();
        acl_standalone_setvar(&mut store, "  acl_c_test  =value").unwrap();
        assert_eq!(store.get("acl_c_test"), Some("value"));
    }
}
