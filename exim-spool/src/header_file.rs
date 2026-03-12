//! Spool header (-H) file read and write operations.
//!
//! This module implements byte-level compatible reading and writing of Exim
//! spool header files (the `-H` files in the spool input directory). These
//! files store the message envelope, metadata, and RFC 2822 headers in a
//! well-defined text format.
//!
//! **Compatibility Rule (AAP §0.7.1):** Spool files written by C Exim MUST
//! be readable by this Rust implementation and vice versa. The format is
//! preserved exactly, including field ordering, taint prefixes, and
//! feature-gated sections.
//!
//! # File format summary
//!
//! A `-H` spool file has the following structure:
//!
//! 1. **Identity line**: `{message_id}-H\n`
//! 2. **Originator line**: `{login} {uid} {gid}\n`
//! 3. **Sender line**: `<{sender_address}>\n`
//! 4. **Received time + warning count**: `{epoch_secs} {warning_count}\n`
//! 5. **Variable lines**: `-{name} {value}\n` (tainted: `--{name} {value}\n`)
//! 6. **Boolean flag lines**: `-{flag_name}\n`
//! 7. **Non-recipient tree**: recursive binary tree or `XX\n`
//! 8. **Recipient count**: `{count}\n`
//! 9. **Recipient lines**: one per recipient with optional DSN/orcpt/pno data
//! 10. **Blank separator line**: `\n`
//! 11. **Header lines**: `{3-digit-len}{type-char} {header-text}` until EOF
//!
//! # Source origins
//!
//! - `src/src/spool_out.c` — `spool_write_header()`
//! - `src/src/spool_in.c` — `spool_read_header()`, `spool_clear_header_globals()`

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};

use tracing::{debug, trace, warn};

use crate::format::{self, MESSAGE_ID_LENGTH, MESSAGE_ID_LENGTH_OLD};

// =============================================================================
// Data Types
// =============================================================================

/// Taint information attached to a spool variable value.
///
/// Exim tracks whether string values originated from external (untrusted)
/// input. In the spool file this is encoded with a double-dash prefix and an
/// optional quoter name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintInfo {
    /// Value is untainted (single-dash prefix in spool file).
    Untainted,
    /// Value is tainted (double-dash prefix) with an optional quoter name.
    Tainted {
        /// Optional lookup/quoter type name (e.g., `"sql"`, `"ldap"`).
        quoter: Option<String>,
    },
}

/// A single variable entry from the spool header envelope section.
///
/// Corresponds to lines of the form `-{name} {value}\n` or `--{name} {value}\n`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpoolVariable {
    /// Variable name (e.g., `"helo_name"`, `"host_address"`).
    pub name: String,
    /// Variable value.
    pub value: String,
    /// Taint status of the value.
    pub taint: TaintInfo,
}

/// TLS information stored in the spool header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsInfo {
    /// Whether the TLS certificate was verified.
    pub certificate_verified: bool,
    /// TLS cipher suite name.
    pub cipher: Option<String>,
    /// Our (server) certificate in PEM/exported form.
    pub ourcert: Option<String>,
    /// Peer certificate in PEM/exported form.
    pub peercert: Option<String>,
    /// Peer distinguished name.
    pub peerdn: Option<String>,
    /// Server Name Indication value.
    pub sni: Option<String>,
    /// OCSP status value.
    pub ocsp: Option<i32>,
    /// TLS resumption indicator character.
    pub resumption: Option<char>,
    /// TLS version string.
    pub ver: Option<String>,
}

/// A single RFC 2822 header line as stored in the spool file.
///
/// Each header is preceded by a 3-digit length and a type character.
/// Type characters include:
/// - `' '` (space) — normal live header
/// - `'*'` — header that has been rewritten (not transmitted)
/// - Various letter codes for identified headers (e.g., `'R'` for Received)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpoolHeader {
    /// Header type character.
    pub header_type: char,
    /// Byte length of the header text (as stored in the 3-digit prefix).
    pub slen: usize,
    /// Full header text including the name, colon, and value.
    pub text: String,
}

/// A node in the binary tree of non-recipient addresses.
///
/// Exim stores the set of addresses that should NOT receive the message as
/// a binary tree serialized into the spool file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonRecipientNode {
    /// The non-recipient address.
    pub address: String,
    /// Left child node, if any.
    pub left: Option<Box<NonRecipientNode>>,
    /// Right child node, if any.
    pub right: Option<Box<NonRecipientNode>>,
}

/// DSN (Delivery Status Notification) information for a recipient.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DsnInfo {
    /// DSN ORCPT (Original Recipient) value.
    pub orcpt: Option<String>,
    /// DSN notification flags bitmask.
    pub dsn_flags: u32,
}

/// A single recipient entry from the spool header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    /// Recipient email address.
    pub address: String,
    /// Parent number for one-time aliases (-1 if none).
    pub pno: i32,
    /// Errors-to address override, if any.
    pub errors_to: Option<String>,
    /// DSN information.
    pub dsn: DsnInfo,
}

/// Boolean flags stored in the envelope section.
///
/// These correspond to the `-{flag_name}` lines in the spool file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvelopeFlags {
    /// `-allow_unqualified_recipient`
    pub allow_unqualified_recipient: bool,
    /// `-allow_unqualified_sender`
    pub allow_unqualified_sender: bool,
    /// `-deliver_firsttime`
    pub deliver_firsttime: bool,
    /// `-frozen {timestamp}` — frozen state with freeze time.
    pub deliver_freeze: bool,
    /// Timestamp when the message was frozen (seconds since epoch).
    pub deliver_frozen_at: i64,
    /// `-N` — do not deliver (testing flag).
    pub dont_deliver: bool,
    /// `-host_lookup_deferred`
    pub host_lookup_deferred: bool,
    /// `-host_lookup_failed`
    pub host_lookup_failed: bool,
    /// `-local` — message originated locally.
    pub sender_local: bool,
    /// `-localerror` — message is a local error message.
    pub local_error_message: bool,
    /// `-manual_thaw` — message was manually thawed.
    pub deliver_manual_thaw: bool,
    /// `-sender_set_untrusted`
    pub sender_set_untrusted: bool,
    /// `-spool_file_wireformat`
    pub spool_file_wireformat: bool,
}

/// Internationalization settings stored in the spool header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct I18nInfo {
    /// `-smtputf8` — message uses SMTPUTF8 extension.
    pub smtputf8: bool,
    /// UTF-8 downconversion mode: 0 = none, 1 = forced, -1 = optional.
    pub utf8_downconvert: i32,
}

/// Complete parsed representation of a spool -H file.
///
/// This struct contains all the data stored in an Exim spool header file,
/// organized into logical sections matching the file format.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpoolHeaderFile {
    // -- Identity section --
    /// Message ID (e.g., `"1pBnKl-003F4x-Tw"`).
    pub message_id: String,

    // -- Originator section --
    /// Login name of the message originator.
    pub originator_login: String,
    /// UID of the message originator.
    pub originator_uid: i64,
    /// GID of the message originator.
    pub originator_gid: i64,

    // -- Sender --
    /// Envelope sender address (without angle brackets).
    pub sender_address: String,

    // -- Timing --
    /// Received time — seconds since the Unix epoch.
    pub received_time_sec: i64,
    /// Received time — microseconds component.
    pub received_time_usec: u32,
    /// Complete received time — seconds.
    pub received_time_complete_sec: i64,
    /// Complete received time — microseconds.
    pub received_time_complete_usec: u32,
    /// Warning count.
    pub warning_count: i32,

    // -- SMTP session info --
    /// HELO/EHLO name from the sending host.
    pub helo_name: Option<String>,
    /// Sending host IP address (without brackets).
    pub host_address: Option<String>,
    /// Sending host port.
    pub host_port: u16,
    /// Sending host resolved name.
    pub host_name: Option<String>,
    /// Authentication mechanism used by the sending host.
    pub host_auth: Option<String>,
    /// Public name of the auth mechanism.
    pub host_auth_pubname: Option<String>,
    /// Interface (local) address the message arrived on.
    pub interface_address: Option<String>,
    /// Interface port.
    pub interface_port: u16,
    /// Active hostname (if different from primary).
    pub active_hostname: Option<String>,
    /// Sender ident string.
    pub sender_ident: Option<String>,
    /// Received protocol string.
    pub received_protocol: Option<String>,
    /// Authenticated ID.
    pub authenticated_id: Option<String>,
    /// Authenticated sender.
    pub authenticated_sender: Option<String>,

    // -- Body metrics --
    /// Number of lines in the message body.
    pub body_linecount: i64,
    /// Number of zero (NUL) bytes in the body.
    pub body_zerocount: i64,
    /// Maximum line length received.
    pub max_received_linelength: i64,
    /// Total message line count (header lines + body_linecount).
    pub message_linecount: i64,
    /// Message size in bytes (excluding rewritten headers and spool overhead).
    pub message_size: i64,

    // -- Boolean flags --
    /// Envelope boolean flags.
    pub flags: EnvelopeFlags,

    // -- DSN --
    /// DSN envelope ID.
    pub dsn_envid: Option<String>,
    /// DSN return type (0 = none, 1 = HDRS, 2 = FULL).
    pub dsn_ret: i32,

    // -- Debug --
    /// Debug selector value.
    pub debug_selector: Option<u64>,
    /// Debug log filename.
    pub debuglog_name: Option<String>,

    // -- Local scan data --
    /// Data from the local_scan() function.
    pub local_scan_data: Option<String>,

    // -- Content scanning --
    /// SpamAssassin bar indicator.
    pub spam_bar: Option<String>,
    /// SpamAssassin score string.
    pub spam_score: Option<String>,
    /// SpamAssassin integer score string.
    pub spam_score_int: Option<String>,

    // -- TLS info --
    /// TLS session information.
    pub tls: TlsInfo,

    // -- I18N --
    /// Internationalization info.
    pub i18n: I18nInfo,

    // -- ACL variables --
    /// ACL connection variables (keyed by name, e.g. `"c0"`, `"c1"`).
    pub acl_c_vars: BTreeMap<String, String>,
    /// ACL message variables (keyed by name, e.g. `"m0"`, `"m1"`).
    pub acl_m_vars: BTreeMap<String, String>,

    // -- Non-recipients --
    /// Binary tree of non-recipient addresses.
    pub non_recipients: Option<NonRecipientNode>,

    // -- Recipients --
    /// List of message recipients.
    pub recipients: Vec<Recipient>,

    // -- Headers --
    /// RFC 2822 headers in order.
    pub headers: Vec<SpoolHeader>,

    // -- Taint tracking for variable values --
    /// Stores taint information for specific variable names.
    /// Key is the variable name, value is the TaintInfo.
    pub variable_taints: BTreeMap<String, TaintInfo>,
}

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during spool header file operations.
#[derive(Debug)]
pub enum SpoolHeaderError {
    /// An I/O error occurred while reading or writing the spool file.
    Io(io::Error),
    /// The spool file has an invalid or unexpected format.
    FormatError {
        /// Human-readable description of the format violation.
        message: String,
        /// The section of the file where the error was found.
        section: String,
    },
    /// The message ID in the file does not match the expected ID.
    IdMismatch {
        /// Expected message ID.
        expected: String,
        /// Actual message ID found in the file.
        found: String,
    },
}

impl fmt::Display for SpoolHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpoolHeaderError::Io(e) => write!(f, "spool I/O error: {}", e),
            SpoolHeaderError::FormatError { message, section } => {
                write!(f, "spool format error in {}: {}", section, message)
            }
            SpoolHeaderError::IdMismatch { expected, found } => {
                write!(
                    f,
                    "spool message ID mismatch: expected '{}', found '{}'",
                    expected, found
                )
            }
        }
    }
}

impl std::error::Error for SpoolHeaderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SpoolHeaderError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for SpoolHeaderError {
    fn from(err: io::Error) -> Self {
        SpoolHeaderError::Io(err)
    }
}

// =============================================================================
// Reading (-H file parsing)
// =============================================================================

impl SpoolHeaderFile {
    /// Read and parse a spool -H file from the given reader.
    ///
    /// This implements the logic of `spool_read_header()` from
    /// `src/src/spool_in.c`, producing a fully parsed [`SpoolHeaderFile`]
    /// struct from the file contents.
    ///
    /// # Arguments
    ///
    /// * `reader` — A reader positioned at the start of the -H file.
    /// * `read_headers` — If `true`, parse the RFC 2822 header section into
    ///   the `headers` vector. If `false`, headers are skipped (only the
    ///   envelope is parsed).
    ///
    /// # Errors
    ///
    /// Returns [`SpoolHeaderError`] on I/O errors or format violations.
    pub fn read_from<R: Read>(reader: R, read_headers: bool) -> Result<Self, SpoolHeaderError> {
        let mut buf = BufReader::new(reader);
        let mut hdr = SpoolHeaderFile::default();
        let mut line = String::new();

        // ---- Line 1: Identity ("{message_id}-H\n") ----
        line.clear();
        buf.read_line(&mut line)?;
        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
        if !trimmed.ends_with("-H") {
            return Err(SpoolHeaderError::FormatError {
                message: format!("identity line does not end with '-H': '{}'", trimmed),
                section: "identity".into(),
            });
        }
        let msg_id = &trimmed[..trimmed.len() - 2];
        // Validate message ID length against known formats
        let id_len = msg_id.len();
        if id_len != MESSAGE_ID_LENGTH && id_len != MESSAGE_ID_LENGTH_OLD {
            trace!(
                id_len,
                expected_new = MESSAGE_ID_LENGTH,
                expected_old = MESSAGE_ID_LENGTH_OLD,
                "message ID length does not match standard formats"
            );
        }
        hdr.message_id = msg_id.to_string();
        debug!(message_id = %hdr.message_id, "parsing spool header");

        // ---- Line 2: Originator ("{login} {uid} {gid}\n") ----
        // C code (spool_in.c lines 428-452) parses RIGHT-TO-LEFT because
        // the login name can contain spaces. We do the same: extract gid
        // from the rightmost space-separated field, then uid, remainder is login.
        line.clear();
        buf.read_line(&mut line)?;
        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
        {
            let gid_pos = trimmed
                .rfind(' ')
                .ok_or_else(|| SpoolHeaderError::FormatError {
                    message: format!("originator line missing space: '{}'", trimmed),
                    section: "originator".into(),
                })?;
            let gid_str = &trimmed[gid_pos + 1..];
            hdr.originator_gid =
                gid_str
                    .parse::<i64>()
                    .map_err(|_| SpoolHeaderError::FormatError {
                        message: format!("invalid gid: '{}'", gid_str),
                        section: "originator".into(),
                    })?;

            let before_gid = &trimmed[..gid_pos];
            let uid_pos = before_gid
                .rfind(' ')
                .ok_or_else(|| SpoolHeaderError::FormatError {
                    message: format!("originator line missing uid: '{}'", trimmed),
                    section: "originator".into(),
                })?;
            let uid_str = &before_gid[uid_pos + 1..];
            hdr.originator_uid =
                uid_str
                    .parse::<i64>()
                    .map_err(|_| SpoolHeaderError::FormatError {
                        message: format!("invalid uid: '{}'", uid_str),
                        section: "originator".into(),
                    })?;

            hdr.originator_login = before_gid[..uid_pos].to_string();
        }
        trace!(
            login = %hdr.originator_login,
            uid = hdr.originator_uid,
            gid = hdr.originator_gid,
            "parsed originator"
        );

        // ---- Line 3: Sender ("<{address}>\n") ----
        line.clear();
        buf.read_line(&mut line)?;
        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
        if !trimmed.starts_with('<') || !trimmed.ends_with('>') {
            return Err(SpoolHeaderError::FormatError {
                message: format!("sender line not enclosed in <>: '{}'", trimmed),
                section: "sender".into(),
            });
        }
        hdr.sender_address = trimmed[1..trimmed.len() - 1].to_string();
        trace!(sender = %hdr.sender_address, "parsed sender");

        // ---- Line 4: Received time + warning count ----
        line.clear();
        buf.read_line(&mut line)?;
        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(SpoolHeaderError::FormatError {
                message: "received_time line needs at least 2 fields".into(),
                section: "received_time".into(),
            });
        }
        hdr.received_time_sec =
            parts[0]
                .parse::<i64>()
                .map_err(|_| SpoolHeaderError::FormatError {
                    message: format!("invalid received time: '{}'", parts[0]),
                    section: "received_time".into(),
                })?;
        hdr.warning_count = parts[1]
            .parse::<i32>()
            .map_err(|_| SpoolHeaderError::FormatError {
                message: format!("invalid warning count: '{}'", parts[1]),
                section: "received_time".into(),
            })?;
        // Initialize complete time from base time (C: received_time_complete = received_time)
        hdr.received_time_complete_sec = hdr.received_time_sec;
        hdr.received_time_complete_usec = 0;

        // ---- Variable and flag lines (start with '-') ----
        // Read lines until we get one that does NOT start with '-'.
        // Special handling for ACL variables which have binary data on the next line.
        let non_recip_line;
        loop {
            line.clear();
            let n = buf.read_line(&mut line)?;
            if n == 0 {
                return Err(SpoolHeaderError::FormatError {
                    message: "unexpected EOF in variable section".into(),
                    section: "variables".into(),
                });
            }
            let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
            if !trimmed.starts_with('-') {
                // This line is the start of the non-recipients tree
                non_recip_line = trimmed.to_string();
                break;
            }

            // Detect ACL variable lines that need binary data from the next line(s).
            // After stripping taint prefix, check if the variable name is aclc/aclm/acl.
            let var_name = Self::extract_var_name(trimmed);
            if var_name == "aclc" || var_name == "aclm" {
                Self::handle_new_acl_variable(&mut hdr, trimmed, &mut buf)?;
            } else if var_name == "acl" {
                Self::handle_legacy_acl_variable(&mut hdr, trimmed, &mut buf)?;
            } else {
                Self::parse_variable_line(&mut hdr, trimmed)?;
            }
        }

        // ---- Non-recipients tree ----
        if non_recip_line == "XX" {
            hdr.non_recipients = None;
            trace!("no non-recipients tree");
        } else {
            hdr.non_recipients = Some(Self::read_non_recipient_tree(&non_recip_line, &mut buf)?);
            trace!("parsed non-recipients tree");
        }

        // ---- Recipient count ----
        line.clear();
        buf.read_line(&mut line)?;
        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
        let rcount: usize = trimmed.parse().map_err(|_| SpoolHeaderError::FormatError {
            message: format!("invalid recipient count: '{}'", trimmed),
            section: "recipient count".into(),
        })?;
        if rcount > 16384 {
            return Err(SpoolHeaderError::FormatError {
                message: format!("recipient count {} exceeds limit 16384", rcount),
                section: "recipient count".into(),
            });
        }
        trace!(count = rcount, "parsing recipients");

        // ---- Recipient lines ----
        for _ in 0..rcount {
            line.clear();
            buf.read_line(&mut line)?;
            let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
            if trimmed.is_empty() {
                return Err(SpoolHeaderError::FormatError {
                    message: "empty recipient line".into(),
                    section: "recipients".into(),
                });
            }
            hdr.recipients.push(Self::parse_recipient_line(trimmed)?);
        }

        // ---- Blank separator line ----
        line.clear();
        buf.read_line(&mut line)?;
        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
        if !trimmed.is_empty() {
            return Err(SpoolHeaderError::FormatError {
                message: format!("expected blank separator line, got: '{}'", trimmed),
                section: "header separator".into(),
            });
        }

        // ---- RFC 2822 header lines ----
        if read_headers {
            Self::read_headers_section(&mut hdr, &mut buf)?;
        }

        // Compute message_linecount = header line count + body_linecount
        // (matching C: message_linecount += body_linecount at end of read)
        hdr.message_linecount += hdr.body_linecount;

        debug!(
            message_id = %hdr.message_id,
            recipients = hdr.recipients.len(),
            headers = hdr.headers.len(),
            "spool header parsed successfully"
        );

        Ok(hdr)
    }

    /// Extract the variable name from a variable line (after stripping all
    /// dash prefixes and optional taint quoter).
    ///
    /// For `-aclc myvar 42` returns `"aclc"`.
    /// For `--host_name example.com` returns `"host_name"`.
    /// For `--(sql)host_name example.com` returns `"host_name"`.
    fn extract_var_name(line: &str) -> &str {
        let rest = &line[1..]; // skip leading '-'
        let content = if let Some(after_dash) = rest.strip_prefix('-') {
            // Tainted — check for quoter
            if after_dash.starts_with('(') {
                if let Some(close) = after_dash.find(')') {
                    &after_dash[close + 1..]
                } else {
                    after_dash
                }
            } else {
                after_dash
            }
        } else {
            rest
        };
        // Return the first word (up to the first space, or the whole thing)
        if let Some(sp) = content.find(' ') {
            &content[..sp]
        } else {
            content
        }
    }

    /// Handle a new-format ACL variable line (`-aclc {name} {count}` or `-aclm {name} {count}`).
    ///
    /// After parsing the header line, reads `count + 1` bytes from the reader
    /// for the binary value data (matching the C `fread(ptr, 1, count+1, fp)` call).
    fn handle_new_acl_variable<R: BufRead>(
        hdr: &mut SpoolHeaderFile,
        header_line: &str,
        reader: &mut R,
    ) -> Result<(), SpoolHeaderError> {
        // Parse taint prefix
        let rest = &header_line[1..];
        let (taint, content) = Self::parse_taint_prefix(rest);

        // content is "aclc {name} {count}" or "aclm {name} {count}"
        let parts: Vec<&str> = content.splitn(3, ' ').collect();
        if parts.len() < 3 {
            return Err(SpoolHeaderError::FormatError {
                message: format!("malformed ACL variable line: '{}'", header_line),
                section: "variables".into(),
            });
        }

        let var_type = if parts[0] == "aclc" { 'c' } else { 'm' };
        let acl_name = parts[1].to_string();
        let count: usize = parts[2]
            .parse()
            .map_err(|_| SpoolHeaderError::FormatError {
                message: format!("invalid ACL data count: '{}'", parts[2]),
                section: "variables".into(),
            })?;

        // Read count + 1 bytes: the value data plus a trailing newline/NUL
        let mut data = vec![0u8; count + 1];
        reader.read_exact(&mut data).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                SpoolHeaderError::FormatError {
                    message: format!(
                        "ACL variable '{}' data shorter than count {}",
                        acl_name, count
                    ),
                    section: "variables".into(),
                }
            } else {
                SpoolHeaderError::Io(e)
            }
        })?;

        // The value is the first `count` bytes (the +1 byte is a trailing newline)
        let value = String::from_utf8_lossy(&data[..count]).to_string();

        let map = if var_type == 'c' {
            &mut hdr.acl_c_vars
        } else {
            &mut hdr.acl_m_vars
        };
        map.insert(acl_name.clone(), value);

        // Store taint info
        hdr.variable_taints
            .insert(format!("acl{}{}", var_type, acl_name), taint);

        trace!(var_type = %var_type, name = %acl_name, count, "parsed ACL variable");
        Ok(())
    }

    /// Handle a legacy ACL variable line (`-acl {index} {count}`).
    ///
    /// Index 0-9 maps to connection variables (c0-c9), 10-19 to message
    /// variables (m0-m9). After parsing, reads `count + 1` bytes for the data.
    fn handle_legacy_acl_variable<R: BufRead>(
        hdr: &mut SpoolHeaderFile,
        header_line: &str,
        reader: &mut R,
    ) -> Result<(), SpoolHeaderError> {
        // Parse taint prefix
        let rest = &header_line[1..];
        let (_taint, content) = Self::parse_taint_prefix(rest);

        // content is "acl {index} {count}"
        let parts: Vec<&str> = content.splitn(3, ' ').collect();
        if parts.len() < 3 {
            return Err(SpoolHeaderError::FormatError {
                message: format!("malformed legacy ACL variable line: '{}'", header_line),
                section: "variables".into(),
            });
        }

        let index: u32 = parts[1]
            .parse()
            .map_err(|_| SpoolHeaderError::FormatError {
                message: format!("invalid ACL index: '{}'", parts[1]),
                section: "variables".into(),
            })?;
        let count: usize = parts[2]
            .parse()
            .map_err(|_| SpoolHeaderError::FormatError {
                message: format!("invalid ACL data count: '{}'", parts[2]),
                section: "variables".into(),
            })?;

        if index >= 20 {
            warn!(index, "legacy ACL variable index out of range (0-19)");
            // Still need to consume the data bytes
            let mut discard = vec![0u8; count + 1];
            reader.read_exact(&mut discard)?;
            return Ok(());
        }

        // Read count + 1 bytes
        let mut data = vec![0u8; count + 1];
        reader.read_exact(&mut data)?;
        let value = String::from_utf8_lossy(&data[..count]).to_string();

        let (var_type, idx) = if index < 10 {
            ('c', index)
        } else {
            ('m', index - 10)
        };
        let acl_name = idx.to_string();

        let map = if var_type == 'c' {
            &mut hdr.acl_c_vars
        } else {
            &mut hdr.acl_m_vars
        };
        map.insert(acl_name.clone(), value);

        trace!(
            var_type = %var_type,
            index,
            count,
            "parsed legacy ACL variable"
        );
        Ok(())
    }

    /// Parse the taint prefix from a variable line fragment (after the leading '-').
    ///
    /// Returns `(TaintInfo, remaining_content)`.
    fn parse_taint_prefix(rest: &str) -> (TaintInfo, &str) {
        if let Some(after_dash) = rest.strip_prefix('-') {
            // Tainted
            if after_dash.starts_with('(') {
                if let Some(close_paren) = after_dash.find(')') {
                    let quoter_name = &after_dash[1..close_paren];
                    (
                        TaintInfo::Tainted {
                            quoter: Some(quoter_name.to_string()),
                        },
                        &after_dash[close_paren + 1..],
                    )
                } else {
                    (TaintInfo::Tainted { quoter: None }, after_dash)
                }
            } else {
                (TaintInfo::Tainted { quoter: None }, after_dash)
            }
        } else {
            (TaintInfo::Untainted, rest)
        }
    }

    /// Parse a single variable/flag line from the envelope section.
    ///
    /// Variable lines have the format:
    /// - `-{name} {value}` (untainted)
    /// - `--{name} {value}` (tainted, no quoter)
    /// - `--({quoter}){name} {value}` (tainted, with quoter)
    ///
    /// Flag lines have the format:
    /// - `-{flag_name}` (no value, just the name)
    ///
    /// ACL variable lines (`-aclc`, `-aclm`, `-acl`) are handled separately
    /// by `handle_new_acl_variable()` / `handle_legacy_acl_variable()` and
    /// should NOT be passed to this function.
    fn parse_variable_line(hdr: &mut SpoolHeaderFile, line: &str) -> Result<(), SpoolHeaderError> {
        // Skip the leading '-'
        let rest = &line[1..];
        let (taint, var_content) = Self::parse_taint_prefix(rest);

        // Parse the variable name and value
        if let Some(space_pos) = var_content.find(' ') {
            let name = &var_content[..space_pos];
            let value = &var_content[space_pos + 1..];
            Self::assign_variable(hdr, name, value, &taint)?;
        } else {
            // Flag-only line (no value)
            Self::assign_flag(hdr, var_content)?;
        }

        Ok(())
    }

    /// Assign a named variable value to the appropriate field.
    fn assign_variable(
        hdr: &mut SpoolHeaderFile,
        name: &str,
        value: &str,
        taint: &TaintInfo,
    ) -> Result<(), SpoolHeaderError> {
        // Store taint info for this variable
        hdr.variable_taints.insert(name.to_string(), taint.clone());

        match name {
            "received_time_usec" => {
                // Value starts with '.' followed by digits
                let usec_str = value.trim_start_matches('.');
                if let Ok(usec) = usec_str.parse::<u32>() {
                    hdr.received_time_usec = usec;
                    // If complete time hasn't been set yet, propagate
                    if hdr.received_time_complete_usec == 0 {
                        hdr.received_time_complete_usec = usec;
                    }
                }
            }
            "received_time_complete" => {
                // Format: "{sec}.{usec}"
                if let Some(dot_pos) = value.find('.') {
                    if let (Ok(sec), Ok(usec)) = (
                        value[..dot_pos].parse::<i64>(),
                        value[dot_pos + 1..].parse::<u32>(),
                    ) {
                        hdr.received_time_complete_sec = sec;
                        hdr.received_time_complete_usec = usec;
                    }
                }
            }
            "helo_name" => hdr.helo_name = Some(value.to_string()),
            "host_address" => Self::parse_host_address(hdr, value),
            "host_name" => hdr.host_name = Some(value.to_string()),
            "host_auth" => hdr.host_auth = Some(value.to_string()),
            "host_auth_pubname" => hdr.host_auth_pubname = Some(value.to_string()),
            "interface_address" => Self::parse_interface_address(hdr, value),
            "active_hostname" => hdr.active_hostname = Some(value.to_string()),
            "ident" => hdr.sender_ident = Some(value.to_string()),
            "received_protocol" => hdr.received_protocol = Some(value.to_string()),
            "auth_id" => hdr.authenticated_id = Some(value.to_string()),
            "auth_sender" => hdr.authenticated_sender = Some(value.to_string()),
            "body_linecount" => hdr.body_linecount = value.parse().unwrap_or(0),
            "body_zerocount" => hdr.body_zerocount = value.parse().unwrap_or(0),
            "max_received_linelength" => hdr.max_received_linelength = value.parse().unwrap_or(0),
            "dsn_envid" => hdr.dsn_envid = Some(value.to_string()),
            "dsn_ret" => hdr.dsn_ret = value.parse().unwrap_or(0),
            "debug_selector" => {
                let val = if let Some(hex) = value.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16).unwrap_or(0)
                } else if let Some(hex) = value.strip_prefix("0X") {
                    u64::from_str_radix(hex, 16).unwrap_or(0)
                } else {
                    value.parse::<u64>().unwrap_or(0)
                };
                hdr.debug_selector = Some(val);
            }
            "debuglog_name" => hdr.debuglog_name = Some(value.to_string()),
            "local_scan" => hdr.local_scan_data = Some(value.to_string()),
            "spam_bar" => hdr.spam_bar = Some(value.to_string()),
            "spam_score" => hdr.spam_score = Some(value.to_string()),
            "spam_score_int" => hdr.spam_score_int = Some(value.to_string()),
            // TLS variables
            "tls_certificate_verified" => hdr.tls.certificate_verified = true,
            "tls_cipher" => hdr.tls.cipher = Some(value.to_string()),
            "tls_ourcert" => hdr.tls.ourcert = Some(value.to_string()),
            "tls_peercert" => hdr.tls.peercert = Some(value.to_string()),
            "tls_peerdn" => hdr.tls.peerdn = Some(value.to_string()),
            "tls_sni" => hdr.tls.sni = Some(value.to_string()),
            "tls_ocsp" => hdr.tls.ocsp = value.parse::<i32>().ok(),
            "tls_resumption" => hdr.tls.resumption = value.chars().next(),
            "tls_ver" => hdr.tls.ver = Some(value.to_string()),
            // Frozen with timestamp
            "frozen" => {
                hdr.flags.deliver_freeze = true;
                hdr.flags.deliver_frozen_at = value.parse().unwrap_or(0);
            }
            _ => {
                // Unknown variable — silently ignore (matches C behavior)
                trace!(name, "ignoring unknown spool variable");
            }
        }
        Ok(())
    }

    /// Assign a boolean flag from a flag-only line.
    fn assign_flag(hdr: &mut SpoolHeaderFile, name: &str) -> Result<(), SpoolHeaderError> {
        match name {
            "allow_unqualified_recipient" => hdr.flags.allow_unqualified_recipient = true,
            "allow_unqualified_sender" => hdr.flags.allow_unqualified_sender = true,
            "deliver_firsttime" => hdr.flags.deliver_firsttime = true,
            "N" => hdr.flags.dont_deliver = true,
            "host_lookup_deferred" => hdr.flags.host_lookup_deferred = true,
            "host_lookup_failed" => hdr.flags.host_lookup_failed = true,
            "local" => hdr.flags.sender_local = true,
            "localerror" => hdr.flags.local_error_message = true,
            "manual_thaw" => hdr.flags.deliver_manual_thaw = true,
            "sender_set_untrusted" => hdr.flags.sender_set_untrusted = true,
            "spool_file_wireformat" => hdr.flags.spool_file_wireformat = true,
            "smtputf8" => hdr.i18n.smtputf8 = true,
            "utf8_downcvt" => hdr.i18n.utf8_downconvert = 1,
            "utf8_optdowncvt" => hdr.i18n.utf8_downconvert = -1,
            "tls_certificate_verified" => hdr.tls.certificate_verified = true,
            _ => {
                // Unknown flag — silently ignore (matches C behavior)
                trace!(name, "ignoring unknown spool flag");
            }
        }
        Ok(())
    }

    /// Parse host address in the format `[{ip}]:{port}`.
    fn parse_host_address(hdr: &mut SpoolHeaderFile, value: &str) {
        if let Some(bracket_end) = value.find(']') {
            let ip = if value.starts_with('[') {
                &value[1..bracket_end]
            } else {
                &value[..bracket_end]
            };
            hdr.host_address = Some(ip.to_string());
            // Extract port after "]:"
            if bracket_end + 1 < value.len() && value.as_bytes().get(bracket_end + 1) == Some(&b':')
            {
                if let Ok(port) = value[bracket_end + 2..].parse::<u16>() {
                    hdr.host_port = port;
                }
            }
        } else {
            hdr.host_address = Some(value.to_string());
        }
    }

    /// Parse interface address in the format `[{ip}]:{port}`.
    fn parse_interface_address(hdr: &mut SpoolHeaderFile, value: &str) {
        if let Some(bracket_end) = value.find(']') {
            let ip = if value.starts_with('[') {
                &value[1..bracket_end]
            } else {
                &value[..bracket_end]
            };
            hdr.interface_address = Some(ip.to_string());
            if bracket_end + 1 < value.len() && value.as_bytes().get(bracket_end + 1) == Some(&b':')
            {
                if let Ok(port) = value[bracket_end + 2..].parse::<u16>() {
                    hdr.interface_port = port;
                }
            }
        } else {
            hdr.interface_address = Some(value.to_string());
        }
    }

    /// Read the non-recipient tree from the spool file.
    ///
    /// The C code uses a recursive function `read_nonrecipients_tree()`.
    /// The tree is serialized as:
    /// - `"Y {address}\n"` followed by left subtree then right subtree
    /// - `"N\n"` for an empty (null) subtree
    fn read_non_recipient_tree<R: BufRead>(
        first_line: &str,
        reader: &mut R,
    ) -> Result<NonRecipientNode, SpoolHeaderError> {
        if let Some(addr_part) = first_line.strip_prefix("Y ") {
            let address = addr_part.to_string();
            let left = Self::read_tree_node(reader)?;
            let right = Self::read_tree_node(reader)?;
            Ok(NonRecipientNode {
                address,
                left: left.map(Box::new),
                right: right.map(Box::new),
            })
        } else {
            Err(SpoolHeaderError::FormatError {
                message: format!(
                    "expected 'Y ...' or 'XX' for non-recipients, got: '{}'",
                    first_line
                ),
                section: "non-recipients".into(),
            })
        }
    }

    /// Read a single tree node from the reader.
    fn read_tree_node<R: BufRead>(
        reader: &mut R,
    ) -> Result<Option<NonRecipientNode>, SpoolHeaderError> {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');

        if trimmed == "N" {
            Ok(None)
        } else if let Some(addr_part) = trimmed.strip_prefix("Y ") {
            let address = addr_part.to_string();
            let left = Self::read_tree_node(reader)?;
            let right = Self::read_tree_node(reader)?;
            Ok(Some(NonRecipientNode {
                address,
                left: left.map(Box::new),
                right: right.map(Box::new),
            }))
        } else {
            Err(SpoolHeaderError::FormatError {
                message: format!("unexpected tree node: '{}'", trimmed),
                section: "non-recipients".into(),
            })
        }
    }

    /// Parse a single recipient line.
    ///
    /// Recipient lines can have several formats:
    /// - Simple: `{address}`
    /// - Exim 4 new type (#3): `{address} {orcpt} {orcpt_len},{dsn_flags} {errors_to} {et_len},{pno}#3`
    /// - Exim 4 old type: `{address} {pno}`
    /// - Exim 3 type: `{address} {digits},{digits},{digits}`
    fn parse_recipient_line(line: &str) -> Result<Recipient, SpoolHeaderError> {
        // Check for Exim 4 new format with '#' type bits marker
        if let Some(hash_pos) = line.rfind('#') {
            let after_hash = &line[hash_pos + 1..];
            if let Ok(flags_bits) = after_hash.parse::<u32>() {
                return Self::parse_new_format_recipient(line, hash_pos, flags_bits);
            }
        }

        // Check for Exim 4 simple format with just a parent number
        // or Exim 3 format with comma-separated numbers
        if let Some(last_space) = line.rfind(' ') {
            let after_space = &line[last_space + 1..];
            // Check if everything after the space is digits (possibly with commas)
            if after_space.chars().all(|c| c.is_ascii_digit() || c == ',') {
                if after_space.contains(',') {
                    // Exim 3 format: ignore the extra fields, just use pno
                    let parts: Vec<&str> = after_space.split(',').collect();
                    let pno = parts.last().unwrap_or(&"-1").parse::<i32>().unwrap_or(-1);
                    return Ok(Recipient {
                        address: line[..last_space].to_string(),
                        pno,
                        errors_to: None,
                        dsn: DsnInfo::default(),
                    });
                } else if let Ok(pno) = after_space.parse::<i32>() {
                    // Exim 4 old format with just parent number
                    return Ok(Recipient {
                        address: line[..last_space].to_string(),
                        pno,
                        errors_to: None,
                        dsn: DsnInfo::default(),
                    });
                }
            }
        }

        // Simple format: just an address
        Ok(Recipient {
            address: line.to_string(),
            pno: -1,
            errors_to: None,
            dsn: DsnInfo::default(),
        })
    }

    /// Parse a new-format recipient line with `#` type bits.
    ///
    /// Format: `{address} {orcpt} {orcpt_len},{dsn_flags} {errors_to} {et_len},{pno}#{type_bits}`
    /// The C code (spool_in.c lines 918-956) parses backwards from the `#` marker.
    fn parse_new_format_recipient(
        line: &str,
        hash_pos: usize,
        flags_bits: u32,
    ) -> Result<Recipient, SpoolHeaderError> {
        let data_part = &line[..hash_pos];
        let mut pno: i32 = -1;
        let mut errors_to: Option<String> = None;
        let mut orcpt: Option<String> = None;
        let mut dsn_flags: u32 = 0;
        let mut end_pos = data_part.len();

        // Work backwards through the data, guided by the flag bits.
        if flags_bits & 0x01 != 0 {
            // Has errors_to data: ...{errors_to} {et_len},{pno}
            let segment = &data_part[..end_pos];
            if let Some(last_comma_pos) = segment.rfind(',') {
                let pno_str = &segment[last_comma_pos + 1..];
                pno = pno_str.trim().parse().unwrap_or(-1);

                let before_comma = &segment[..last_comma_pos];
                if let Some(space_pos) = before_comma.rfind(' ') {
                    let len_str = &before_comma[space_pos + 1..];
                    let et_len: usize = len_str.parse().unwrap_or(0);
                    end_pos = space_pos;
                    if et_len > 0 && end_pos >= et_len {
                        errors_to = Some(data_part[end_pos - et_len..end_pos].to_string());
                        end_pos -= et_len;
                    }
                }
            }
        }

        if flags_bits & 0x02 != 0 {
            // Has DSN/orcpt data: ...{orcpt} {orcpt_len},{dsn_flags}
            let segment = &data_part[..end_pos];
            if let Some(last_comma_pos) = segment.rfind(',') {
                let dsn_str = &segment[last_comma_pos + 1..];
                dsn_flags = dsn_str.trim().parse().unwrap_or(0);

                let before_comma = &segment[..last_comma_pos];
                if let Some(space_pos) = before_comma.rfind(' ') {
                    let len_str = &before_comma[space_pos + 1..];
                    let orcpt_len: usize = len_str.parse().unwrap_or(0);
                    end_pos = space_pos;
                    if orcpt_len > 0 && end_pos >= orcpt_len {
                        orcpt = Some(data_part[end_pos - orcpt_len..end_pos].to_string());
                        end_pos -= orcpt_len;
                    }
                }
            }
        }

        // The remaining text up to end_pos is the address
        let address = data_part[..end_pos].trim_end().to_string();

        Ok(Recipient {
            address,
            pno,
            errors_to,
            dsn: DsnInfo { orcpt, dsn_flags },
        })
    }

    /// Read the RFC 2822 headers section from the spool file.
    ///
    /// Each header is preceded by `{3-digit-len}{type-char} ` and then
    /// `len` bytes of header text. This function also computes
    /// `message_linecount` and `message_size` for the header portion.
    fn read_headers_section<R: Read>(
        hdr: &mut SpoolHeaderFile,
        reader: &mut R,
    ) -> Result<(), SpoolHeaderError> {
        let mut peek_buf = [0u8; 1];
        loop {
            match reader.read(&mut peek_buf) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    let first_byte = peek_buf[0];
                    // C code: breaks on '\n' or EOF, errors on other non-digits
                    if first_byte == b'\n' {
                        // Newline after the last header means end of section
                        break;
                    }
                    if !first_byte.is_ascii_digit() {
                        return Err(SpoolHeaderError::FormatError {
                            message: format!(
                                "expected digit at start of header, got: '{}'",
                                first_byte as char
                            ),
                            section: "headers".into(),
                        });
                    }

                    // Read the rest of the length digits + type character
                    let mut len_str = String::new();
                    len_str.push(first_byte as char);

                    let type_char: char;
                    loop {
                        match reader.read(&mut peek_buf) {
                            Ok(0) => {
                                return Err(SpoolHeaderError::FormatError {
                                    message: "unexpected EOF reading header length".into(),
                                    section: "headers".into(),
                                });
                            }
                            Ok(_) => {
                                let ch = peek_buf[0] as char;
                                if ch.is_ascii_digit() {
                                    len_str.push(ch);
                                } else {
                                    type_char = ch;
                                    break;
                                }
                            }
                            Err(e) => return Err(SpoolHeaderError::Io(e)),
                        }
                    }

                    let slen: usize =
                        len_str.parse().map_err(|_| SpoolHeaderError::FormatError {
                            message: format!("invalid header length: '{}'", len_str),
                            section: "headers".into(),
                        })?;

                    // Read the space after the type character
                    match reader.read(&mut peek_buf) {
                        Ok(0) => {
                            return Err(SpoolHeaderError::FormatError {
                                message: "unexpected EOF after header type".into(),
                                section: "headers".into(),
                            });
                        }
                        Ok(_) => { /* space consumed */ }
                        Err(e) => return Err(SpoolHeaderError::Io(e)),
                    }

                    // Read exactly `slen` bytes of header text
                    let mut text_buf = vec![0u8; slen];
                    reader.read_exact(&mut text_buf).map_err(|e| {
                        if e.kind() == io::ErrorKind::UnexpectedEof {
                            SpoolHeaderError::FormatError {
                                message: format!(
                                    "header text shorter than declared length {}",
                                    slen
                                ),
                                section: "headers".into(),
                            }
                        } else {
                            SpoolHeaderError::Io(e)
                        }
                    })?;

                    // Verify no NUL bytes in the header text
                    if text_buf.contains(&0) {
                        return Err(SpoolHeaderError::FormatError {
                            message: "NUL byte in header text".into(),
                            section: "headers".into(),
                        });
                    }

                    let text = String::from_utf8_lossy(&text_buf).to_string();

                    // Track message_size: exclude rewritten ('*') headers
                    if type_char != '*' {
                        hdr.message_size += slen as i64;
                    }

                    // Track message_linecount: count lines in this header
                    hdr.message_linecount += text.chars().filter(|&c| c == '\n').count() as i64;

                    hdr.headers.push(SpoolHeader {
                        header_type: type_char,
                        slen,
                        text,
                    });
                }
                Err(e) => return Err(SpoolHeaderError::Io(e)),
            }
        }

        trace!(count = hdr.headers.len(), "parsed headers section");
        Ok(())
    }
}

// =============================================================================
// Writing (-H file generation)
// =============================================================================

impl SpoolHeaderFile {
    /// Write the spool -H file to the given writer.
    ///
    /// This implements the logic of `spool_write_header()` from
    /// `src/src/spool_out.c`, producing a byte-level compatible -H file
    /// from the [`SpoolHeaderFile`] data.
    ///
    /// The field write order exactly matches the C implementation to ensure
    /// byte-level compatibility between C and Rust Exim spool files.
    ///
    /// # Returns
    ///
    /// The size_correction value (bytes of spool overhead: 3-digit length +
    /// type char + space per header, plus the full size of rewritten headers).
    /// The caller computes header_size = file_size - size_correction.
    pub fn write_to<W: Write>(&self, writer: W) -> Result<usize, SpoolHeaderError> {
        let mut w = BufWriter::new(writer);
        let mut size_correction: usize = 0;

        // ---- Line 1: Identity ----
        writeln!(w, "{}-H", self.message_id)?;

        // ---- Line 2: Originator ----
        // C format: "%.63s %ld %ld\n"
        let login = if self.originator_login.len() > 63 {
            &self.originator_login[..63]
        } else {
            &self.originator_login
        };
        writeln!(
            w,
            "{} {} {}",
            login, self.originator_uid, self.originator_gid
        )?;

        // ---- Line 3: Sender ----
        writeln!(w, "<{}>", self.sender_address)?;

        // ---- Line 4: Received time + warning count ----
        writeln!(w, "{} {}", self.received_time_sec, self.warning_count)?;

        // ---- Microseconds and complete time ----
        writeln!(w, "-received_time_usec .{:06}", self.received_time_usec)?;
        writeln!(
            w,
            "-received_time_complete {}.{:06}",
            self.received_time_complete_sec, self.received_time_complete_usec
        )?;

        // ---- HELO name ----
        if let Some(ref helo) = self.helo_name {
            let taint = self.get_taint("helo_name");
            Self::write_var(&mut w, "helo_name", helo, &taint)?;
        }

        // ---- Host address ----
        // The C code writes host_address with an extra taint dash prefix
        // directly before the `-host_address` key (not using spool_var_write).
        if let Some(ref addr) = self.host_address {
            let taint = self.get_taint("host_address");
            write!(w, "-")?;
            if matches!(taint, TaintInfo::Tainted { .. }) {
                write!(w, "-")?;
            }
            writeln!(w, "host_address [{}]:{}", addr, self.host_port)?;

            // Host name follows host address in the C write order
            if let Some(ref name) = self.host_name {
                let t = self.get_taint("host_name");
                Self::write_var(&mut w, "host_name", name, &t)?;
            }
        }

        // ---- Host auth ----
        if let Some(ref auth) = self.host_auth {
            let taint = self.get_taint("host_auth");
            Self::write_var(&mut w, "host_auth", auth, &taint)?;
        }
        if let Some(ref pubname) = self.host_auth_pubname {
            let taint = self.get_taint("host_auth_pubname");
            Self::write_var(&mut w, "host_auth_pubname", pubname, &taint)?;
        }

        // ---- Interface address ----
        if let Some(ref addr) = self.interface_address {
            let taint = self.get_taint("interface_address");
            write!(w, "-")?;
            if matches!(taint, TaintInfo::Tainted { .. }) {
                write!(w, "-")?;
            }
            writeln!(w, "interface_address [{}]:{}", addr, self.interface_port)?;
        }

        // ---- Active hostname ----
        if let Some(ref hostname) = self.active_hostname {
            let taint = self.get_taint("active_hostname");
            Self::write_var(&mut w, "active_hostname", hostname, &taint)?;
        }

        // ---- Sender ident ----
        if let Some(ref ident) = self.sender_ident {
            let taint = self.get_taint("ident");
            Self::write_var(&mut w, "ident", ident, &taint)?;
        }

        // ---- Received protocol ----
        if let Some(ref proto) = self.received_protocol {
            let taint = self.get_taint("received_protocol");
            Self::write_var(&mut w, "received_protocol", proto, &taint)?;
        }

        // ---- ACL variables ----
        // The C code uses tree_walk which visits nodes in sorted order.
        // BTreeMap iteration is also sorted, so order matches.
        for (name, value) in &self.acl_c_vars {
            writeln!(w, "-aclc {} {}", name, value.len())?;
            w.write_all(value.as_bytes())?;
            w.write_all(b"\n")?;
        }
        for (name, value) in &self.acl_m_vars {
            writeln!(w, "-aclm {} {}", name, value.len())?;
            w.write_all(value.as_bytes())?;
            w.write_all(b"\n")?;
        }

        // ---- Debug info ----
        if let Some(ref debuglog) = self.debuglog_name {
            if let Some(sel) = self.debug_selector {
                writeln!(w, "-debug_selector 0x{:x}", sel)?;
            }
            writeln!(w, "-debuglog_name {}", debuglog)?;
        }

        // ---- Body metrics ----
        if self.flags.spool_file_wireformat {
            writeln!(w, "-spool_file_wireformat")?;
        } else {
            writeln!(w, "-body_linecount {}", self.body_linecount)?;
        }
        writeln!(
            w,
            "-max_received_linelength {}",
            self.max_received_linelength
        )?;
        if self.body_zerocount > 0 {
            writeln!(w, "-body_zerocount {}", self.body_zerocount)?;
        }

        // ---- Auth info ----
        if let Some(ref auth_id) = self.authenticated_id {
            let taint = self.get_taint("auth_id");
            Self::write_var(&mut w, "auth_id", auth_id, &taint)?;
        }
        if let Some(ref auth_sender) = self.authenticated_sender {
            let taint = self.get_taint("auth_sender");
            let sanitized = format::zap_newlines(auth_sender);
            Self::write_var(&mut w, "auth_sender", &sanitized, &taint)?;
        }

        // ---- Boolean flags ----
        if self.flags.allow_unqualified_recipient {
            writeln!(w, "-allow_unqualified_recipient")?;
        }
        if self.flags.allow_unqualified_sender {
            writeln!(w, "-allow_unqualified_sender")?;
        }
        if self.flags.deliver_firsttime {
            writeln!(w, "-deliver_firsttime")?;
        }
        if self.flags.deliver_freeze {
            writeln!(w, "-frozen {}", self.flags.deliver_frozen_at)?;
        }
        if self.flags.dont_deliver {
            writeln!(w, "-N")?;
        }
        if self.flags.host_lookup_deferred {
            writeln!(w, "-host_lookup_deferred")?;
        }
        if self.flags.host_lookup_failed {
            writeln!(w, "-host_lookup_failed")?;
        }
        if self.flags.sender_local {
            writeln!(w, "-local")?;
        }
        if self.flags.local_error_message {
            writeln!(w, "-localerror")?;
        }

        // ---- Local scan data ----
        if let Some(ref data) = self.local_scan_data {
            let taint = self.get_taint("local_scan");
            Self::write_var(&mut w, "local_scan", data, &taint)?;
        }

        // ---- Content scanning ----
        if let Some(ref bar) = self.spam_bar {
            let taint = self.get_taint("spam_bar");
            Self::write_var(&mut w, "spam_bar", bar, &taint)?;
        }
        if let Some(ref score) = self.spam_score {
            let taint = self.get_taint("spam_score");
            Self::write_var(&mut w, "spam_score", score, &taint)?;
        }
        if let Some(ref score_int) = self.spam_score_int {
            let taint = self.get_taint("spam_score_int");
            Self::write_var(&mut w, "spam_score_int", score_int, &taint)?;
        }

        if self.flags.deliver_manual_thaw {
            writeln!(w, "-manual_thaw")?;
        }
        if self.flags.sender_set_untrusted {
            writeln!(w, "-sender_set_untrusted")?;
        }

        // ---- TLS info ----
        if self.tls.certificate_verified {
            writeln!(w, "-tls_certificate_verified")?;
        }
        if let Some(ref cipher) = self.tls.cipher {
            let taint = self.get_taint("tls_cipher");
            Self::write_var(&mut w, "tls_cipher", cipher, &taint)?;
        }
        // C code writes peercert with taint prefix (always tainted from peer)
        if let Some(ref peercert) = self.tls.peercert {
            writeln!(w, "--tls_peercert {}", peercert)?;
        }
        if let Some(ref peerdn) = self.tls.peerdn {
            let taint = self.get_taint("tls_peerdn");
            Self::write_var(&mut w, "tls_peerdn", peerdn, &taint)?;
        }
        if let Some(ref sni) = self.tls.sni {
            let taint = self.get_taint("tls_sni");
            Self::write_var(&mut w, "tls_sni", sni, &taint)?;
        }
        if let Some(ref ourcert) = self.tls.ourcert {
            writeln!(w, "-tls_ourcert {}", ourcert)?;
        }
        if let Some(ocsp) = self.tls.ocsp {
            writeln!(w, "-tls_ocsp {}", ocsp)?;
        }
        if let Some(resumption) = self.tls.resumption {
            writeln!(w, "-tls_resumption {}", resumption)?;
        }
        if let Some(ref ver) = self.tls.ver {
            let taint = self.get_taint("tls_ver");
            Self::write_var(&mut w, "tls_ver", ver, &taint)?;
        }

        // ---- I18N ----
        if self.i18n.smtputf8 {
            writeln!(w, "-smtputf8")?;
            if self.i18n.utf8_downconvert != 0 {
                if self.i18n.utf8_downconvert < 0 {
                    writeln!(w, "-utf8_optdowncvt")?;
                } else {
                    writeln!(w, "-utf8_downcvt")?;
                }
            }
        }

        // ---- DSN ----
        if let Some(ref envid) = self.dsn_envid {
            writeln!(w, "-dsn_envid {}", envid)?;
        }
        if self.dsn_ret != 0 {
            writeln!(w, "-dsn_ret {}", self.dsn_ret)?;
        }

        // ---- Non-recipients tree ----
        match &self.non_recipients {
            None => writeln!(w, "XX")?,
            Some(tree) => Self::write_tree_node(&mut w, tree)?,
        }

        // ---- Recipient count + list ----
        writeln!(w, "{}", self.recipients.len())?;
        for r in &self.recipients {
            let address = format::zap_newlines(&r.address);
            if r.pno < 0 && r.errors_to.is_none() && r.dsn.dsn_flags == 0 {
                writeln!(w, "{}", address)?;
            } else {
                let errors_to_val = r
                    .errors_to
                    .as_deref()
                    .map(|e| format::zap_newlines(e).into_owned())
                    .unwrap_or_default();
                let orcpt_val = r
                    .dsn
                    .orcpt
                    .as_deref()
                    .map(|o| format::zap_newlines(o).into_owned())
                    .unwrap_or_default();

                // Exim 4 new format with #3 type bits
                writeln!(
                    w,
                    "{} {} {},{} {} {},{}#3",
                    address,
                    orcpt_val,
                    orcpt_val.len(),
                    r.dsn.dsn_flags,
                    errors_to_val,
                    errors_to_val.len(),
                    r.pno
                )?;
            }
        }

        // ---- Blank separator line ----
        writeln!(w)?;

        // ---- Headers ----
        for h in &self.headers {
            write!(w, "{:03}{} {}", h.slen, h.header_type, h.text)?;
            size_correction += 5; // 3-digit length + type char + space
            if h.header_type == '*' {
                size_correction += h.slen;
            }
        }

        w.flush()?;
        debug!(
            message_id = %self.message_id,
            size_correction,
            "spool header written"
        );
        Ok(size_correction)
    }

    /// Write a tree node and its children recursively (pre-order traversal).
    ///
    /// Format matches C `tree_write()`:
    /// - `Y {name}\n` for a node with data, followed by left then right subtree
    /// - `N\n` for a null/empty subtree
    fn write_tree_node<W: Write>(
        w: &mut W,
        node: &NonRecipientNode,
    ) -> Result<(), SpoolHeaderError> {
        writeln!(w, "Y {}", node.address)?;
        match &node.left {
            Some(left) => Self::write_tree_node(w, left)?,
            None => writeln!(w, "N")?,
        }
        match &node.right {
            Some(right) => Self::write_tree_node(w, right)?,
            None => writeln!(w, "N")?,
        }
        Ok(())
    }

    /// Write a variable with taint-aware prefix.
    ///
    /// Untainted: `-{name} {value}\n`
    /// Tainted:   `--{name} {value}\n`
    /// Tainted with quoter: `--({quoter}){name} {value}\n`
    fn write_var<W: Write>(
        w: &mut W,
        name: &str,
        value: &str,
        taint: &TaintInfo,
    ) -> Result<(), SpoolHeaderError> {
        write!(w, "-")?;
        if let TaintInfo::Tainted { ref quoter } = taint {
            write!(w, "-")?;
            if let Some(ref qname) = quoter {
                write!(w, "({})", qname)?;
            }
        }
        writeln!(w, "{} {}", name, value)?;
        Ok(())
    }

    /// Get the taint info for a variable, defaulting to Untainted.
    fn get_taint(&self, name: &str) -> TaintInfo {
        self.variable_taints
            .get(name)
            .cloned()
            .unwrap_or(TaintInfo::Untainted)
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Read just the sender address from a spool -H file.
///
/// This is an optimized reader that only parses the first 3 lines of the
/// spool header file to extract the envelope sender address.
///
/// Equivalent to `spool_sender_from_msgid()` in `src/src/spool_in.c`
/// (lines 1088-1117).
///
/// # Arguments
///
/// * `reader` - A reader positioned at the start of the -H file.
///
/// # Returns
///
/// The sender address (without angle brackets), or `None` on error.
pub fn read_sender_from_header<R: Read>(reader: R) -> Option<String> {
    let buf = BufReader::new(reader);
    let mut lines = buf.lines();

    // Skip line 1 (identity) and line 2 (originator)
    let _ = lines.next()?;
    let _ = lines.next()?;

    // Line 3 should be the sender in angle brackets
    let sender_line = lines.next()?.ok()?;
    let trimmed = sender_line.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('<') && trimmed.ends_with('>') {
        Some(trimmed[1..trimmed.len() - 1].to_string())
    } else {
        None
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a minimal valid spool -H file content for testing.
    fn minimal_spool_header() -> String {
        [
            "1pBnKl-003F4x-Tw-H",
            "testuser 1000 1000",
            "<sender@example.com>",
            "1700000000 0",
            "-received_time_usec .123456",
            "-received_time_complete 1700000000.123456",
            "-body_linecount 42",
            "-max_received_linelength 998",
            "XX",
            "1",
            "recipient@example.com",
            "",
            "028R Received: from test server\r\n",
        ]
        .join("\n")
    }

    #[test]
    fn test_read_minimal_header() {
        let data = minimal_spool_header();
        let result = SpoolHeaderFile::read_from(data.as_bytes(), true);
        assert!(result.is_ok(), "Failed to parse: {:?}", result.err());
        let hdr = result.unwrap();
        assert_eq!(hdr.message_id, "1pBnKl-003F4x-Tw");
        assert_eq!(hdr.originator_login, "testuser");
        assert_eq!(hdr.originator_uid, 1000);
        assert_eq!(hdr.originator_gid, 1000);
        assert_eq!(hdr.sender_address, "sender@example.com");
        assert_eq!(hdr.received_time_sec, 1700000000);
        assert_eq!(hdr.warning_count, 0);
        assert_eq!(hdr.received_time_usec, 123456);
        assert_eq!(hdr.body_linecount, 42);
        assert_eq!(hdr.max_received_linelength, 998);
        assert!(hdr.non_recipients.is_none());
        assert_eq!(hdr.recipients.len(), 1);
        assert_eq!(hdr.recipients[0].address, "recipient@example.com");
        assert_eq!(hdr.headers.len(), 1);
        assert_eq!(hdr.headers[0].header_type, 'R');
        assert_eq!(hdr.headers[0].slen, 28);
    }

    #[test]
    fn test_roundtrip_minimal() {
        let data = minimal_spool_header();
        let hdr = SpoolHeaderFile::read_from(data.as_bytes(), true).unwrap();
        let mut output = Vec::new();
        hdr.write_to(&mut output).unwrap();
        let reparsed = SpoolHeaderFile::read_from(output.as_slice(), true).unwrap();
        assert_eq!(hdr.message_id, reparsed.message_id);
        assert_eq!(hdr.sender_address, reparsed.sender_address);
        assert_eq!(hdr.recipients.len(), reparsed.recipients.len());
        assert_eq!(hdr.headers.len(), reparsed.headers.len());
        assert_eq!(hdr.body_linecount, reparsed.body_linecount);
        assert_eq!(hdr.received_time_usec, reparsed.received_time_usec);
    }

    #[test]
    fn test_read_with_flags() {
        let data = [
            "1pBnKl-003F4x-Tw-H",
            "root 0 0",
            "<>",
            "1700000000 2",
            "-received_time_usec .000000",
            "-received_time_complete 1700000000.000000",
            "-deliver_firsttime",
            "-local",
            "-frozen 1700001000",
            "-body_linecount 0",
            "-max_received_linelength 0",
            "XX",
            "0",
            "",
        ]
        .join("\n");
        let hdr = SpoolHeaderFile::read_from(data.as_bytes(), false).unwrap();
        assert_eq!(hdr.sender_address, "");
        assert!(hdr.flags.deliver_firsttime);
        assert!(hdr.flags.sender_local);
        assert!(hdr.flags.deliver_freeze);
        assert_eq!(hdr.flags.deliver_frozen_at, 1700001000);
        assert_eq!(hdr.warning_count, 2);
    }

    #[test]
    fn test_read_with_host_info() {
        let data = [
            "1pBnKl-003F4x-Tw-H",
            "testuser 1000 1000",
            "<sender@example.com>",
            "1700000000 0",
            "-received_time_usec .000000",
            "-received_time_complete 1700000000.000000",
            "-helo_name mail.example.com",
            "--host_address [192.168.1.1]:25",
            "--host_name mail.example.com",
            "-host_auth plain",
            "-body_linecount 10",
            "-max_received_linelength 80",
            "XX",
            "0",
            "",
        ]
        .join("\n");
        let hdr = SpoolHeaderFile::read_from(data.as_bytes(), false).unwrap();
        assert_eq!(hdr.helo_name.as_deref(), Some("mail.example.com"));
        assert_eq!(hdr.host_address.as_deref(), Some("192.168.1.1"));
        assert_eq!(hdr.host_port, 25);
        assert_eq!(hdr.host_name.as_deref(), Some("mail.example.com"));
        assert_eq!(hdr.host_auth.as_deref(), Some("plain"));
    }

    #[test]
    fn test_read_with_recipients_dsn() {
        let data = [
            "1pBnKl-003F4x-Tw-H",
            "testuser 1000 1000",
            "<sender@example.com>",
            "1700000000 0",
            "-received_time_usec .000000",
            "-received_time_complete 1700000000.000000",
            "-body_linecount 0",
            "-max_received_linelength 0",
            "XX",
            "2",
            "simple@example.com",
            "complex@example.com rfc822;complex@example.com 27,14 errors@example.com 19,0#3",
            "",
        ]
        .join("\n");
        let hdr = SpoolHeaderFile::read_from(data.as_bytes(), false).unwrap();
        assert_eq!(hdr.recipients.len(), 2);
        assert_eq!(hdr.recipients[0].address, "simple@example.com");
        assert_eq!(hdr.recipients[0].pno, -1);
        assert_eq!(hdr.recipients[1].address, "complex@example.com");
    }

    #[test]
    fn test_read_non_recipients_tree() {
        let data = [
            "1pBnKl-003F4x-Tw-H",
            "testuser 1000 1000",
            "<sender@example.com>",
            "1700000000 0",
            "-received_time_usec .000000",
            "-received_time_complete 1700000000.000000",
            "-body_linecount 0",
            "-max_received_linelength 0",
            "Y bounce@example.com",
            "N",
            "N",
            "0",
            "",
        ]
        .join("\n");
        let hdr = SpoolHeaderFile::read_from(data.as_bytes(), false).unwrap();
        assert!(hdr.non_recipients.is_some());
        let tree = hdr.non_recipients.unwrap();
        assert_eq!(tree.address, "bounce@example.com");
        assert!(tree.left.is_none());
        assert!(tree.right.is_none());
    }

    #[test]
    fn test_write_and_read_with_tls() {
        let mut hdr = SpoolHeaderFile::default();
        hdr.message_id = "1pBnKl-003F4x-Tw".to_string();
        hdr.originator_login = "testuser".to_string();
        hdr.originator_uid = 1000;
        hdr.originator_gid = 1000;
        hdr.sender_address = "sender@example.com".to_string();
        hdr.received_time_sec = 1700000000;
        hdr.received_time_complete_sec = 1700000000;
        hdr.tls.certificate_verified = true;
        hdr.tls.cipher = Some("TLS_AES_256_GCM_SHA384".to_string());
        hdr.tls.ver = Some("TLSv1.3".to_string());
        hdr.recipients.push(Recipient {
            address: "rcpt@example.com".to_string(),
            pno: -1,
            errors_to: None,
            dsn: DsnInfo::default(),
        });

        let mut output = Vec::new();
        hdr.write_to(&mut output).unwrap();
        let reparsed = SpoolHeaderFile::read_from(output.as_slice(), false).unwrap();
        assert!(reparsed.tls.certificate_verified);
        assert_eq!(
            reparsed.tls.cipher.as_deref(),
            Some("TLS_AES_256_GCM_SHA384")
        );
        assert_eq!(reparsed.tls.ver.as_deref(), Some("TLSv1.3"));
    }

    #[test]
    fn test_read_sender_from_header() {
        let data = [
            "1pBnKl-003F4x-Tw-H",
            "testuser 1000 1000",
            "<sender@example.com>",
            "rest of file...",
        ]
        .join("\n");
        let sender = read_sender_from_header(data.as_bytes());
        assert_eq!(sender, Some("sender@example.com".to_string()));
    }

    #[test]
    fn test_read_empty_sender() {
        let data = ["1pBnKl-003F4x-Tw-H", "root 0 0", "<>", "rest of file..."].join("\n");
        let sender = read_sender_from_header(data.as_bytes());
        assert_eq!(sender, Some("".to_string()));
    }

    #[test]
    fn test_format_error_display() {
        let err = SpoolHeaderError::FormatError {
            message: "bad data".into(),
            section: "headers".into(),
        };
        assert!(err.to_string().contains("bad data"));
        assert!(err.to_string().contains("headers"));
    }

    #[test]
    fn test_id_mismatch_error_display() {
        let err = SpoolHeaderError::IdMismatch {
            expected: "abc".into(),
            found: "xyz".into(),
        };
        assert!(err.to_string().contains("abc"));
        assert!(err.to_string().contains("xyz"));
    }

    #[test]
    fn test_taint_info_equality() {
        assert_eq!(TaintInfo::Untainted, TaintInfo::Untainted);
        assert_eq!(
            TaintInfo::Tainted { quoter: None },
            TaintInfo::Tainted { quoter: None }
        );
        assert_eq!(
            TaintInfo::Tainted {
                quoter: Some("sql".into())
            },
            TaintInfo::Tainted {
                quoter: Some("sql".into())
            }
        );
        assert_ne!(TaintInfo::Untainted, TaintInfo::Tainted { quoter: None });
    }

    #[test]
    fn test_originator_with_spaces_in_login() {
        // C code parses right-to-left, so login "John Smith" with uid=1000, gid=1000
        // is written as "John Smith 1000 1000\n"
        let data = [
            "1pBnKl-003F4x-Tw-H",
            "John Smith 1000 1000",
            "<sender@example.com>",
            "1700000000 0",
            "-received_time_usec .000000",
            "-received_time_complete 1700000000.000000",
            "-body_linecount 0",
            "-max_received_linelength 0",
            "XX",
            "0",
            "",
        ]
        .join("\n");
        let hdr = SpoolHeaderFile::read_from(data.as_bytes(), false).unwrap();
        assert_eq!(hdr.originator_login, "John Smith");
        assert_eq!(hdr.originator_uid, 1000);
        assert_eq!(hdr.originator_gid, 1000);
    }

    #[test]
    fn test_acl_variable_roundtrip() {
        let mut hdr = SpoolHeaderFile::default();
        hdr.message_id = "1pBnKl-003F4x-Tw".to_string();
        hdr.originator_login = "testuser".to_string();
        hdr.originator_uid = 1000;
        hdr.originator_gid = 1000;
        hdr.sender_address = "sender@example.com".to_string();
        hdr.received_time_sec = 1700000000;
        hdr.received_time_complete_sec = 1700000000;
        hdr.acl_c_vars
            .insert("myvar".to_string(), "hello world".to_string());
        hdr.acl_m_vars
            .insert("msgvar".to_string(), "test data".to_string());
        hdr.recipients.push(Recipient {
            address: "rcpt@example.com".to_string(),
            pno: -1,
            errors_to: None,
            dsn: DsnInfo::default(),
        });

        let mut output = Vec::new();
        hdr.write_to(&mut output).unwrap();
        let reparsed = SpoolHeaderFile::read_from(output.as_slice(), false).unwrap();
        assert_eq!(
            reparsed.acl_c_vars.get("myvar").map(|s| s.as_str()),
            Some("hello world")
        );
        assert_eq!(
            reparsed.acl_m_vars.get("msgvar").map(|s| s.as_str()),
            Some("test data")
        );
    }

    #[test]
    fn test_message_linecount_computation() {
        let data = minimal_spool_header();
        let hdr = SpoolHeaderFile::read_from(data.as_bytes(), true).unwrap();
        // body_linecount = 42, header has 1 header ending with \r\n (1 line)
        // message_linecount should be body_linecount + number of header lines
        assert_eq!(hdr.message_linecount, 42 + 1);
    }

    #[test]
    fn test_message_size_excludes_rewritten() {
        // Create a spool with a normal header and a rewritten header.
        // Headers are contiguous in the spool format (no newline between them),
        // so we build the header section separately from the join.
        let mut data = [
            "1pBnKl-003F4x-Tw-H",
            "testuser 1000 1000",
            "<sender@example.com>",
            "1700000000 0",
            "-received_time_usec .000000",
            "-received_time_complete 1700000000.000000",
            "-body_linecount 0",
            "-max_received_linelength 0",
            "XX",
            "0",
        ]
        .join("\n");
        // Add end-of-count newline + blank separator line + headers
        data.push_str("\n\n");
        data.push_str("028R Received: from test server\r\n");
        // "X-Rewritten: old\r\n" = 17 bytes
        data.push_str("017* X-Rewritten: old\r\n");
        let hdr = SpoolHeaderFile::read_from(data.as_bytes(), true).unwrap();
        assert_eq!(hdr.headers.len(), 2);
        // Only the non-rewritten header counts toward message_size
        assert_eq!(hdr.message_size, 28);
    }

    #[test]
    fn test_extract_var_name() {
        assert_eq!(SpoolHeaderFile::extract_var_name("-aclc myvar 42"), "aclc");
        assert_eq!(SpoolHeaderFile::extract_var_name("--aclm var2 10"), "aclm");
        assert_eq!(
            SpoolHeaderFile::extract_var_name("--(sql)host_name test"),
            "host_name"
        );
        assert_eq!(
            SpoolHeaderFile::extract_var_name("-host_address [1.2.3.4]:25"),
            "host_address"
        );
        assert_eq!(
            SpoolHeaderFile::extract_var_name("-deliver_firsttime"),
            "deliver_firsttime"
        );
    }

    #[test]
    fn test_complex_tree_roundtrip() {
        let mut hdr = SpoolHeaderFile::default();
        hdr.message_id = "1pBnKl-003F4x-Tw".to_string();
        hdr.originator_login = "testuser".to_string();
        hdr.originator_uid = 1000;
        hdr.originator_gid = 1000;
        hdr.sender_address = "sender@example.com".to_string();
        hdr.received_time_sec = 1700000000;
        hdr.received_time_complete_sec = 1700000000;
        hdr.non_recipients = Some(NonRecipientNode {
            address: "bounce@example.com".to_string(),
            left: Some(Box::new(NonRecipientNode {
                address: "a@example.com".to_string(),
                left: None,
                right: None,
            })),
            right: Some(Box::new(NonRecipientNode {
                address: "c@example.com".to_string(),
                left: None,
                right: None,
            })),
        });
        hdr.recipients.push(Recipient {
            address: "rcpt@example.com".to_string(),
            pno: -1,
            errors_to: None,
            dsn: DsnInfo::default(),
        });

        let mut output = Vec::new();
        hdr.write_to(&mut output).unwrap();
        let reparsed = SpoolHeaderFile::read_from(output.as_slice(), false).unwrap();
        let tree = reparsed.non_recipients.as_ref().unwrap();
        assert_eq!(tree.address, "bounce@example.com");
        assert_eq!(tree.left.as_ref().unwrap().address, "a@example.com");
        assert_eq!(tree.right.as_ref().unwrap().address, "c@example.com");
    }

    #[test]
    fn test_i18n_roundtrip() {
        let mut hdr = SpoolHeaderFile::default();
        hdr.message_id = "1pBnKl-003F4x-Tw".to_string();
        hdr.originator_login = "testuser".to_string();
        hdr.originator_uid = 1000;
        hdr.originator_gid = 1000;
        hdr.sender_address = "sender@example.com".to_string();
        hdr.received_time_sec = 1700000000;
        hdr.received_time_complete_sec = 1700000000;
        hdr.i18n.smtputf8 = true;
        hdr.i18n.utf8_downconvert = -1;
        hdr.recipients.push(Recipient {
            address: "rcpt@example.com".to_string(),
            pno: -1,
            errors_to: None,
            dsn: DsnInfo::default(),
        });

        let mut output = Vec::new();
        hdr.write_to(&mut output).unwrap();
        let reparsed = SpoolHeaderFile::read_from(output.as_slice(), false).unwrap();
        assert!(reparsed.i18n.smtputf8);
        assert_eq!(reparsed.i18n.utf8_downconvert, -1);
    }

    #[test]
    fn test_dsn_roundtrip() {
        let mut hdr = SpoolHeaderFile::default();
        hdr.message_id = "1pBnKl-003F4x-Tw".to_string();
        hdr.originator_login = "testuser".to_string();
        hdr.originator_uid = 1000;
        hdr.originator_gid = 1000;
        hdr.sender_address = "sender@example.com".to_string();
        hdr.received_time_sec = 1700000000;
        hdr.received_time_complete_sec = 1700000000;
        hdr.dsn_envid = Some("myenvid".to_string());
        hdr.dsn_ret = 2;
        hdr.recipients.push(Recipient {
            address: "rcpt@example.com".to_string(),
            pno: -1,
            errors_to: None,
            dsn: DsnInfo::default(),
        });

        let mut output = Vec::new();
        hdr.write_to(&mut output).unwrap();
        let reparsed = SpoolHeaderFile::read_from(output.as_slice(), false).unwrap();
        assert_eq!(reparsed.dsn_envid.as_deref(), Some("myenvid"));
        assert_eq!(reparsed.dsn_ret, 2);
    }
}
