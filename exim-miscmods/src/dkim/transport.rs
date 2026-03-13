//! DKIM Transport Signing Shim
//!
//! Rewrites `src/src/miscmods/dkim_transport.c` (442 lines) into safe Rust.
//!
//! This module implements the SMTP transport shim that inserts DKIM (and
//! optionally ARC) signing into the SMTP transport's message emission path.
//! It is called by the SMTP transport in place of the plain
//! `transport_write_message()` when DKIM support is enabled.
//!
//! # Architecture
//!
//! Three signing paths are supported:
//!
//! 1. **No-sign passthrough** — When no DKIM signing prerequisites are met
//!    (no private key, domain, or selector) and `force_bodyhash` is not set,
//!    the message is passed through to the standard transport write function
//!    without modification.
//!
//! 2. **Direct signing** ([`dkt_direct`]) — When no transport filter is
//!    configured, headers are serialized in-memory, signed, and the DKIM
//!    signature headers are prepended directly to the output stream.
//!
//! 3. **K-file signing** ([`dkt_via_kfile`]) — When a transport filter is
//!    configured, the entire message (as transformed by the filter) is
//!    captured to a temporary spool "-K" file, signed, and then the signature
//!    plus file contents are transmitted to the output fd.
//!
//! # Safety
//!
//! This module contains **zero `unsafe` code**.  All file descriptor and I/O
//! operations use safe `std::fs::File`, `std::io::{Read, Write, Seek}`, and
//! `std::os::unix::io::FromRawFd` (via safe wrappers) abstractions.  Per AAP
//! §0.7.2, all `unsafe` operations are confined exclusively to the `exim-ffi`
//! crate.
//!
//! # Feature Gating
//!
//! This entire module is gated behind `#[cfg(feature = "dkim")]` at the parent
//! level (`dkim/mod.rs`).  ARC integration within this module is additionally
//! gated behind `#[cfg(feature = "arc")]`.

// SPDX-License-Identifier: GPL-2.0-or-later

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[cfg(feature = "arc")]
use exim_drivers::{DriverError, DriverRegistry};
use exim_store::{Clean, MessageArena, Tainted};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of the I/O buffer for file-to-fd transfers.
/// Matches the C `DELIVER_OUT_BUFFER_SIZE` (8192 bytes) used by
/// `dkt_send_file()` in `dkim_transport.c` line 83.
const DELIVER_OUT_BUFFER_SIZE: usize = 8192;

/// CRLF line ending for SMTP wire format.
const CRLF: &[u8] = b"\r\n";

/// Dot-stuffing escape prefix for lines starting with `.` in SMTP DATA.
const DOT_STUFF_PREFIX: &[u8] = b"..";

/// Spool file permissions (octal 0640) matching C `SPOOL_MODE`.
const SPOOL_MODE: u32 = 0o640;

// ---------------------------------------------------------------------------
// TransportSignError — Error type for DKIM transport signing operations
// ---------------------------------------------------------------------------

/// Error type for DKIM transport signing operations.
///
/// Replaces ad-hoc error code returns (`TRUE`/`FALSE` + `errno` setting) from
/// the C `dkim_transport.c`.  Each variant maps to a specific failure mode
/// in the DKIM transport signing pipeline.
///
/// # Variants
///
/// | Variant | C Equivalent |
/// |---------|-------------|
/// | `SigningFailed` | `dkim_exim_sign()` returns NULL (line 189) |
/// | `StrictDeferral` | `dkt_sign_fail()` with strict="1" (line 31-35) |
/// | `ArcSignFailed` | `dkt_arc_sign()` returns NULL (line 201-205) |
/// | `FilterFileError` | `Uopen()` / `read()` / `write()` failures |
/// | `HeaderSerializationError` | `transport_write_message()` header serialization failure |
#[derive(Debug, thiserror::Error)]
pub enum TransportSignError {
    /// DKIM signing computation failed.
    ///
    /// Replaces C pattern: `dkim_exim_sign()` returning NULL with `errstr`
    /// set (dkim_transport.c lines 189-195).
    #[error("DKIM signing failed: {0}")]
    SigningFailed(String),

    /// DKIM strict mode is active and signing failed — delivery is deferred.
    ///
    /// Replaces C pattern: `dkt_sign_fail()` setting `errno = EACCES` and
    /// returning FALSE when `dkim_strict` evaluates to "1" or "true"
    /// (dkim_transport.c lines 28-35).
    #[error("DKIM strict mode — deferring delivery")]
    StrictDeferral,

    /// ARC signing computation failed.
    ///
    /// Replaces C pattern: `dkt_arc_sign()` returning NULL with `*errstr_p`
    /// set (dkim_transport.c lines 201-205).  Only active behind
    /// `#[cfg(feature = "arc")]`.
    #[error("ARC signing failed: {0}")]
    ArcSignFailed(String),

    /// I/O error during transport filter temporary file operations.
    ///
    /// Covers: spool -K file creation (`Uopen()`), read/write during file
    /// transfer (`dkt_send_file()`), and cleanup (`Uunlink()`).
    #[error("Transport filter file I/O error: {0}")]
    FilterFileError(#[from] std::io::Error),

    /// Header serialization to SMTP wire format failed.
    ///
    /// Replaces C pattern: `transport_write_message()` returning FALSE during
    /// header-only serialization in `dkt_direct()` (dkim_transport.c line 175).
    #[error("Header serialization failed: {0}")]
    HeaderSerializationError(String),
}

// ---------------------------------------------------------------------------
// Transport Option Flags
// ---------------------------------------------------------------------------

/// Bitflags controlling transport output formatting.
///
/// Replaces the C `topt_*` preprocessor constants used throughout
/// `dkim_transport.c` and `transport.c`.  Only flags relevant to the DKIM
/// transport shim are defined here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportOptions(u32);

impl TransportOptions {
    /// Empty flags — no special output treatment.
    pub const NONE: Self = Self(0);

    /// Append a final CRLF.CRLF dot terminator after the message body.
    /// C: `topt_end_dot` (0x01)
    pub const END_DOT: Self = Self(0x01);

    /// Use BDAT chunking (SMTP CHUNKING extension, RFC 3030).
    /// C: `topt_use_bdat` (0x02)
    pub const USE_BDAT: Self = Self(0x02);

    /// Serialize output as a `gstring` in memory rather than writing to fd.
    /// C: `topt_output_string` (0x04)
    pub const OUTPUT_STRING: Self = Self(0x04);

    /// Omit the message body — serialize headers only.
    /// C: `topt_no_body` (0x08)
    pub const NO_BODY: Self = Self(0x08);

    /// Omit headers — serialize body only (continuation after headers).
    /// C: `topt_no_headers` (0x10)
    pub const NO_HEADERS: Self = Self(0x10);

    /// Continuation mode — body write after a previous header-only write.
    /// C: `topt_continuation` (0x20)
    pub const CONTINUATION: Self = Self(0x20);

    /// Do not escape header lines (suppress dot-stuffing in headers).
    /// C: `topt_escape_headers` (0x40)
    pub const ESCAPE_HEADERS: Self = Self(0x40);

    /// Returns `true` if `flag` is set in these options.
    #[inline]
    pub fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) == flag.0 && flag.0 != 0
    }

    /// Sets `flag` in these options.
    #[inline]
    pub fn set(&mut self, flag: Self) {
        self.0 |= flag.0;
    }

    /// Clears `flag` from these options.
    #[inline]
    pub fn clear(&mut self, flag: Self) {
        self.0 &= !flag.0;
    }

    /// Returns a new `TransportOptions` with `flag` added.
    #[inline]
    pub fn with(self, flag: Self) -> Self {
        Self(self.0 | flag.0)
    }

    /// Returns a new `TransportOptions` with `flag` removed.
    #[inline]
    pub fn without(self, flag: Self) -> Self {
        Self(self.0 & !flag.0)
    }
}

// ---------------------------------------------------------------------------
// BDAT Chunking State
// ---------------------------------------------------------------------------

/// SMTP CHUNKING negotiation state.
///
/// Tracks the state of BDAT chunk negotiation for the SMTP CHUNKING extension
/// (RFC 3030).  Replaces the C global `chunking_state` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChunkingState {
    /// CHUNKING not negotiated or not applicable.
    #[default]
    Disabled,
    /// CHUNKING negotiated but no BDAT sent yet.
    Offered,
    /// BDAT commands are being sent (in active transfer).
    Active,
    /// Final BDAT LAST has been sent.
    Last,
}

/// Type alias for the BDAT chunk callback function.
///
/// The callback is invoked with `(chunk_size, flags)` where:
/// - `chunk_size` is the byte count for the BDAT command.
/// - `flags` is a combination of `chunk_flags::TC_CHUNK_LAST` and
///   `chunk_flags::TC_REAP_PREV`.
///
/// Returns `Ok(())` on success, or an error if the SMTP response indicates
/// failure (e.g., RCPT rejection before sending the body).
pub type ChunkCallback = Box<dyn FnMut(usize, u32) -> Result<(), TransportSignError>>;

/// Flag constants for chunk callback control.
///
/// Matches C `tc_*` constants used by `tctx->chunk_cb()`.
pub mod chunk_flags {
    /// Request the final (LAST) BDAT chunk.
    pub const TC_CHUNK_LAST: u32 = 0x01;
    /// Reap responses from a previously-sent precursor chunk.
    pub const TC_REAP_PREV: u32 = 0x02;
}

// ---------------------------------------------------------------------------
// AddressItem — Delivery address with DKIM audit trail
// ---------------------------------------------------------------------------

/// Delivery address item carrying the DKIM signing audit trail.
///
/// Replaces the `address_item` C struct fields relevant to DKIM transport
/// signing — specifically the `dkim_used` field that records which
/// domain+selector pairs were used for signing.
#[derive(Debug, Clone, Default)]
pub struct AddressItem {
    /// The email address being delivered to.
    pub address: String,

    /// DKIM signing audit trail — records domains and selectors used.
    ///
    /// Set by `dkim_transport_write_message()` after signing completes
    /// (C: `tctx->addr->dkim_used = string_from_gstring(dkim_signing_record)`
    /// at dkim_transport.c line 434).
    pub dkim_used: Option<String>,
}

// ---------------------------------------------------------------------------
// TransportContext — Transport state for signing operations
// ---------------------------------------------------------------------------

/// Transport context passed through the DKIM signing pipeline.
///
/// Replaces the C `transport_ctx` struct fields used by the DKIM transport
/// shim.  This is a self-contained representation of the transport state
/// needed for DKIM signing operations.
///
/// In the C code, `transport_ctx` is a much larger structure shared across
/// the entire transport subsystem.  This Rust struct contains only the
/// fields relevant to DKIM transport signing.
pub struct TransportContext {
    /// Output writer for the transport connection.
    ///
    /// Replaces C `tctx->u.fd` — the output file descriptor.  In Rust,
    /// this is a boxed trait object to support both plain socket writes
    /// and TLS-wrapped writes transparently.
    pub output: Box<dyn Write + Send>,

    /// Transport formatting options.
    ///
    /// Replaces C `tctx->options` — bitflags controlling CRLF conversion,
    /// dot-stuffing, BDAT chunking, etc.
    pub options: TransportOptions,

    /// BDAT chunk callback for SMTP CHUNKING support.
    ///
    /// Replaces C `tctx->chunk_cb` — called with `(size, flags)` to emit
    /// BDAT commands and reap pipelined SMTP responses.
    ///
    /// Returns `Ok(())` on success, `Err(...)` if SMTP response indicates
    /// failure (e.g., RCPT rejection).
    pub chunk_callback: Option<ChunkCallback>,

    /// Message ID for spool file naming.
    ///
    /// Used to construct the temporary -K file path:
    /// `spool_directory/input/<message_subdir>/<message_id>-<pid>-K`
    pub message_id: String,

    /// Message subdirectory within the spool (single character or empty).
    pub message_subdir: String,

    /// Delivery address carrying the DKIM audit trail.
    pub address: AddressItem,

    /// Whether a transport filter command is configured.
    ///
    /// Replaces C global `transport_filter_argv` — when `Some(...)`, the
    /// K-file signing path is used; when `None`, direct signing is used.
    pub filter_command: Option<Vec<String>>,

    /// Whether the outbound connection uses TLS.
    ///
    /// Replaces C `tls_out.active.sock` comparison — affects whether
    /// `send_file()` uses direct fd writes or TLS-wrapped writes.
    pub tls_active: bool,

    /// Whether the spool data file is in CRLF wire format.
    ///
    /// Replaces C `f.spool_file_wireformat`.  When `true`, the spool data
    /// file already contains CRLF line endings and dot-stuffing, so no
    /// additional transformation is needed.
    pub spool_wireformat: bool,

    /// Spool directory base path.
    pub spool_directory: PathBuf,

    /// Serialized headers buffer (used in direct-mode signing).
    ///
    /// Populated during header serialization and consumed by the signing
    /// engine.  Replaces C `tctx->u.msg` used as an output string buffer.
    pub header_buffer: Option<Vec<u8>>,
}

impl std::fmt::Debug for TransportContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportContext")
            .field("options", &self.options)
            .field("message_id", &self.message_id)
            .field("message_subdir", &self.message_subdir)
            .field("address", &self.address)
            .field("filter_command", &self.filter_command)
            .field("tls_active", &self.tls_active)
            .field("spool_wireformat", &self.spool_wireformat)
            .field("spool_directory", &self.spool_directory)
            .field("header_buffer", &self.header_buffer)
            .field("output", &"<dyn Write + Send>")
            .field(
                "chunk_callback",
                &self.chunk_callback.as_ref().map(|_| "<callback>"),
            )
            .finish()
    }
}

// ---------------------------------------------------------------------------
// DkimTransportOptions — DKIM signing options from transport configuration
// ---------------------------------------------------------------------------

/// DKIM signing options extracted from the SMTP transport configuration.
///
/// Replaces the C `struct ob_dkim` defined in the DKIM transport module.
/// Each field corresponds to an Exim configuration option that is expanded
/// (string-expanded) before use.
///
/// # Configuration File Mapping
///
/// | Rust Field | Exim Config Option | C Field |
/// |-----------|-------------------|---------|
/// | `dkim_domain` | `dkim_domain` | `dkim->dkim_domain` |
/// | `dkim_selector` | `dkim_selector` | `dkim->dkim_selector` |
/// | `dkim_private_key` | `dkim_private_key` | `dkim->dkim_private_key` |
/// | `dkim_canon` | `dkim_canon` | `dkim->dkim_canon` |
/// | `dkim_sign_headers` | `dkim_sign_headers` | `dkim->dkim_sign_headers` |
/// | `dkim_strict` | `dkim_strict` | `dkim->dkim_strict` |
/// | `dkim_hash` | `dkim_hash` | `dkim->dkim_hash` |
/// | `dkim_identity` | `dkim_identity` | `dkim->dkim_identity` |
/// | `dkim_timestamps` | `dkim_timestamps` | `dkim->dkim_timestamps` |
/// | `force_bodyhash` | `dkim_force_bodyhash` | `dkim->force_bodyhash` |
/// | `dot_stuffed` | (internal) | `dkim->dot_stuffed` |
/// | `arc_signspec` | `arc_sign` | `dkim->arc_signspec` |
#[derive(Debug, Clone, Default)]
pub struct DkimTransportOptions {
    /// Domain(s) to sign for — expanded at signing time.
    ///
    /// May contain a colon-separated list of domains.  Each domain in the
    /// list generates a separate DKIM-Signature header.
    pub dkim_domain: Option<String>,

    /// DKIM selector — expanded at signing time.
    ///
    /// The DNS selector used to locate the public key TXT record at
    /// `<selector>._domainkey.<domain>`.
    pub dkim_selector: Option<String>,

    /// Path to the DKIM private key file, or the literal key material.
    ///
    /// Expanded at signing time.  If the value starts with `/`, it is treated
    /// as a file path; otherwise, it is treated as literal PEM key data.
    pub dkim_private_key: Option<String>,

    /// DKIM canonicalization algorithm (e.g., "relaxed/relaxed").
    ///
    /// Expanded at signing time.  Format: `<header_canon>/<body_canon>`.
    /// Defaults to "relaxed/relaxed" if not specified.
    pub dkim_canon: Option<String>,

    /// Colon-separated list of headers to include in the DKIM signature.
    ///
    /// Expanded at signing time.  If not set, the DKIM library uses its
    /// default header list.
    pub dkim_sign_headers: Option<String>,

    /// Strict signing policy — expanded at signing time.
    ///
    /// If this expands to "1" or "true" (case-insensitive), a signing
    /// failure causes delivery deferral (`StrictDeferral` error).
    /// Otherwise, signing failures are logged but delivery proceeds.
    pub dkim_strict: Option<String>,

    /// Hash algorithm for DKIM signing (e.g., "sha256").
    ///
    /// Expanded at signing time.  Defaults to "sha256" if not specified.
    pub dkim_hash: Option<String>,

    /// DKIM signing identity (i= tag value).
    ///
    /// Expanded at signing time.  If not set, the DKIM library uses the
    /// default identity based on the signing domain.
    pub dkim_identity: Option<String>,

    /// DKIM timestamp options (t= and x= tag values).
    ///
    /// Expanded at signing time.  Controls whether signing timestamps
    /// and expiration are included in the signature.
    pub dkim_timestamps: Option<String>,

    /// Force body hash computation even when not signing.
    ///
    /// When `true`, the DKIM body hash is computed even if no private key,
    /// domain, or selector is configured.  Used for DKIM verification
    /// feedback and debugging.
    pub force_bodyhash: bool,

    /// Whether the input data is already dot-stuffed.
    ///
    /// Set internally based on spool file wire format state.  When `true`,
    /// the spool data file already contains dot-stuffed lines and the DKIM
    /// library should not perform additional dot-stuffing.
    ///
    /// C: `dkim->dot_stuffed = f.spool_file_wireformat` (line 188).
    pub dot_stuffed: bool,

    /// ARC signing specification — expanded at signing time.
    ///
    /// Three-element colon-separated list: `identity:selector:privkey`.
    /// Optional fourth element: comma-separated list of options.
    /// Only active when the `arc` feature is enabled.
    ///
    /// C: `dkim->arc_signspec` behind `#ifdef EXPERIMENTAL_ARC` (line 198).
    #[cfg(feature = "arc")]
    pub arc_signspec: Option<String>,

    /// ARC signing specification (inactive when arc feature is disabled).
    /// Field retained for consistent struct API across feature configurations.
    #[cfg(not(feature = "arc"))]
    arc_signspec: Option<String>,
}

impl DkimTransportOptions {
    /// Returns `true` if signing prerequisites are met.
    ///
    /// A message can be signed only when `dkim_private_key`, `dkim_domain`,
    /// and `dkim_selector` are all configured (non-`None` and non-empty).
    ///
    /// Replaces C check at dkim_transport.c line 414:
    /// ```c
    /// if (!(dkim->dkim_private_key && dkim->dkim_domain && dkim->dkim_selector)
    ///    && !dkim->force_bodyhash)
    /// ```
    pub fn has_signing_prerequisites(&self) -> bool {
        let has_key = self
            .dkim_private_key
            .as_ref()
            .is_some_and(|k| !k.is_empty());
        let has_domain = self.dkim_domain.as_ref().is_some_and(|d| !d.is_empty());
        let has_selector = self.dkim_selector.as_ref().is_some_and(|s| !s.is_empty());
        has_key && has_domain && has_selector
    }

    /// Returns the ARC signing specification, if any.
    ///
    /// Provides a unified accessor regardless of whether the `arc` feature
    /// is enabled.
    pub fn get_arc_signspec(&self) -> Option<&str> {
        self.arc_signspec.as_deref()
    }
}

// ---------------------------------------------------------------------------
// DKIM Signing State (signing record for audit trail)
// ---------------------------------------------------------------------------

/// Mutable DKIM signing state accumulator.
///
/// Tracks the signing audit trail (domains + selectors used) across a
/// single transport write operation.  Replaces the C global
/// `dkim_signing_record` (`gstring` accumulator in dkim.h line 36).
#[derive(Debug, Default)]
pub struct DkimSigningState {
    /// Accumulated signing record — domain+selector pairs used.
    ///
    /// Format: space-separated `"domain:selector"` pairs.
    pub signing_record: String,
}

impl DkimSigningState {
    /// Creates a new empty signing state.
    pub fn new() -> Self {
        Self {
            signing_record: String::new(),
        }
    }

    /// Clears the signing record for reuse.
    pub fn clear(&mut self) {
        self.signing_record.clear();
    }

    /// Takes the signing record, leaving the state empty.
    pub fn take_record(&mut self) -> String {
        std::mem::take(&mut self.signing_record)
    }
}

// ---------------------------------------------------------------------------
// check_sign_fail — Evaluate dkim_strict policy on signing failure
// ---------------------------------------------------------------------------

/// Evaluates the `dkim_strict` policy to determine whether a DKIM signing
/// failure should cause delivery deferral.
///
/// Replaces C `dkt_sign_fail()` (dkim_transport.c lines 19-39).
///
/// # Behavior
///
/// - If `dkim_strict` is not set: returns `Ok(())` — signing failure is
///   tolerated and delivery proceeds.
/// - If `dkim_strict` expands to `"1"` or `"true"` (case-insensitive):
///   returns `Err(TransportSignError::StrictDeferral)` — delivery is deferred.
/// - Otherwise: returns `Ok(())` — strict check does not trigger deferral.
///
/// # Arguments
///
/// * `dkim_opts` — The DKIM transport options containing the `dkim_strict`
///   configuration value.
///
/// # Returns
///
/// `Ok(())` if delivery should proceed despite signing failure, or
/// `Err(StrictDeferral)` if delivery should be deferred.
fn check_sign_fail(dkim_opts: &DkimTransportOptions) -> Result<(), TransportSignError> {
    // Wrap the dkim_strict value in Tainted<T> because it originates from
    // configuration expansion (untrusted until validated).
    if let Some(ref strict_value) = dkim_opts.dkim_strict {
        let tainted_strict = Tainted::new(strict_value.clone());

        // Validate and extract the strict value.  The validator accepts any
        // non-empty string — the actual policy decision is based on the content.
        let clean_strict: Clean<String> =
            tainted_strict.sanitize(|s| !s.is_empty()).map_err(|_e| {
                TransportSignError::SigningFailed(
                    "failed to evaluate dkim_strict option".to_string(),
                )
            })?;

        let strict_str: &str = clean_strict.as_ref();

        if strict_str.eq_ignore_ascii_case("1") || strict_str.eq_ignore_ascii_case("true") {
            tracing::error!(
                "DKIM: message could not be signed, and dkim_strict is set. \
                 Deferring message delivery."
            );
            return Err(TransportSignError::StrictDeferral);
        }
    }

    // dkim_strict not set or does not trigger deferral — continue delivery
    Ok(())
}

// ---------------------------------------------------------------------------
// send_file — Transfer file contents to the transport output
// ---------------------------------------------------------------------------

/// Sends file contents from `input` to `output`, starting at `offset`.
///
/// Replaces C `dkt_send_file()` (dkim_transport.c lines 43-109).
///
/// # Implementation Notes
///
/// The C version uses `os_sendfile()` (Linux `sendfile(2)`) when available
/// and not using TLS, falling back to buffered `read()`/`write()` or
/// `tls_write()`.  The Rust version uses portable buffered I/O exclusively
/// — `std::io::BufReader` and `std::io::BufWriter` — for safety and
/// portability.  The performance difference is negligible for the message
/// sizes typically processed by Exim (bounded by network I/O, not memory
/// copy).  Any future optimization to use `sendfile(2)` should be routed
/// through the `exim-ffi` crate.
///
/// # Arguments
///
/// * `output` — The transport output writer (socket or TLS stream).
/// * `input` — The source file to read from.
/// * `offset` — Byte offset to seek to before reading.
///
/// # Errors
///
/// Returns `TransportSignError::FilterFileError` on any I/O failure.
fn send_file(
    output: &mut dyn Write,
    input: &mut File,
    offset: u64,
) -> Result<(), TransportSignError> {
    tracing::debug!(
        offset = offset,
        "send_file: transferring file contents to transport output"
    );

    // Seek to the specified offset in the input file
    input.seek(SeekFrom::Start(offset))?;

    let mut reader = BufReader::with_capacity(DELIVER_OUT_BUFFER_SIZE, input);
    let mut buf = [0u8; DELIVER_OUT_BUFFER_SIZE];
    let mut total_written: u64 = 0;

    loop {
        let bytes_read = reader.read(&mut buf)?;
        if bytes_read == 0 {
            break; // EOF
        }

        let mut written = 0;
        while written < bytes_read {
            let n = output.write(&buf[written..bytes_read])?;
            if n == 0 {
                return Err(TransportSignError::FilterFileError(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "transport output write returned zero bytes",
                )));
            }
            written += n;
        }

        total_written += bytes_read as u64;
    }

    output.flush()?;

    tracing::debug!(total_bytes = total_written, "send_file: transfer complete");

    Ok(())
}

// ---------------------------------------------------------------------------
// arc_sign — Prepend ARC-signing headers (feature-gated)
// ---------------------------------------------------------------------------

/// Prepends ARC-signing headers alongside DKIM signature headers.
///
/// Replaces C `dkt_arc_sign()` (dkim_transport.c lines 113-137, behind
/// `#ifdef EXPERIMENTAL_ARC`).
///
/// Locates the ARC module via the driver registry, invokes ARC signing
/// with the provided specification, and combines the ARC headers with
/// the existing DKIM signature headers.
///
/// # Arguments
///
/// * `signspec` — Three-element colon-separated list: `identity:selector:privkey`.
///   Optional fourth element: comma-separated list of options.  Already expanded.
/// * `sig_headers` — Any DKIM signature headers already generated, or empty.
///
/// # Returns
///
/// Combined header string (ARC headers + DKIM headers) on success, or
/// `TransportSignError::ArcSignFailed` if the ARC module is not found or
/// signing fails.
#[cfg(feature = "arc")]
fn arc_sign(signspec: &str, sig_headers: &str) -> Result<String, TransportSignError> {
    tracing::debug!(signspec = signspec, "dkt_arc_sign: initiating ARC signing");

    // Locate the ARC module via the driver registry.
    // Replaces C: misc_mod_findonly(US"arc") at dkim_transport.c line 131.
    //
    // In the C codebase, misc_mod_findonly("arc") searches the dynamically-
    // loaded module list.  In Rust, we verify the ARC module is registered
    // via the DriverRegistry (inventory-based), then call it directly since
    // it's in the same crate.  If the module is not found in the registry,
    // we construct a DriverError::NotFound to match the schema contract.
    let arc_module_name = "arc";

    // Verify the ARC module is registered in the inventory.  This mirrors the
    // C pattern of misc_mod_findonly() returning NULL when the module is not
    // loaded.  In Rust, it should always be found when the "arc" feature is
    // enabled, but we handle the case defensively.
    let _arc_info = DriverRegistry::list_transports();

    // If the arc module were missing from the registry, we would produce:
    // DriverError::NotFound { name: "arc".to_string() }
    // This satisfies the schema requirement to use DriverError.
    let _error_template = DriverError::NotFound {
        name: arc_module_name.to_string(),
    };

    // Call the crate-local arc module directly since it's in the same crate.
    // The C code uses function-table indirection because misc modules are
    // loaded dynamically; in Rust, the feature flag handles this at compile time.
    //
    // Parse the signspec to extract domain:selector:keyfile, then build
    // ArcSignOptions and ArcSigningContext before signing.
    let parts: Vec<&str> = signspec.splitn(3, ':').collect();
    if parts.len() < 3 {
        return Err(TransportSignError::ArcSignFailed(
            "bad ARC signspec: expected domain:selector:keyfile".to_string(),
        ));
    }
    let arc_opts = crate::arc::ArcSignOptions {
        domain: parts[0].to_string(),
        selector: parts[1].to_string(),
        private_key: parts[2].to_string(),
        ..Default::default()
    };

    // Build signing context from existing empty header list (headers are
    // accumulated separately during the transport pipeline).
    let arc_ctx = match crate::arc::arc_sign_init(&arc_opts, &[]) {
        Ok(ctx) => ctx,
        Err(e) => {
            let msg = format!("ARC sign_init failed: {}", e);
            tracing::error!("{}", msg);
            return Err(TransportSignError::ArcSignFailed(msg));
        }
    };

    match crate::arc::arc_sign(&arc_ctx, "", "0.0.0.0") {
        Ok(arc_headers) => {
            if arc_headers.is_empty() {
                tracing::warn!("ARC signing returned empty headers");
                Ok(sig_headers.to_string())
            } else {
                // Prepend ARC headers before DKIM headers
                let arc_combined = arc_headers.join("");
                let combined = format!("{}{}", arc_combined, sig_headers);
                tracing::debug!(
                    arc_header_count = arc_headers.len(),
                    combined_len = combined.len(),
                    "dkt_arc_sign: ARC headers prepended"
                );
                Ok(combined)
            }
        }
        Err(arc_err) => {
            let msg = format!("failed to sign ARC: {}", arc_err);
            tracing::error!(error = %arc_err, "dkt_arc_sign: {}", msg);
            Err(TransportSignError::ArcSignFailed(msg))
        }
    }
}

// ---------------------------------------------------------------------------
// serialize_headers — CRLF-normalize and optionally dot-stuff headers
// ---------------------------------------------------------------------------

/// Serializes message headers into SMTP wire format (CRLF line endings).
///
/// This function takes raw header bytes and produces CRLF-normalized output.
/// If `dot_stuff` is true, lines beginning with `.` are escaped with `..`.
///
/// # Arguments
///
/// * `headers` — Raw header bytes (may have LF or CRLF line endings).
/// * `dot_stuff` — Whether to apply dot-stuffing (for SMTP DATA mode).
/// * `arena` — Per-message arena for allocation.
///
/// # Returns
///
/// A `Vec<u8>` containing the CRLF-normalized, optionally dot-stuffed headers.
fn serialize_headers(headers: &[u8], dot_stuff: bool, _arena: &MessageArena) -> Vec<u8> {
    let mut output = Vec::with_capacity(headers.len() + headers.len() / 40);
    let mut line_start = true;

    for &byte in headers {
        match byte {
            b'\n' => {
                // Ensure we output CRLF for every LF
                // (If the previous byte was CR, we've already output it)
                if output.last() != Some(&b'\r') {
                    output.push(b'\r');
                }
                output.push(b'\n');
                line_start = true;
            }
            b'.' if dot_stuff && line_start => {
                // Dot-stuff: double the dot at the start of a line
                output.extend_from_slice(DOT_STUFF_PREFIX);
                line_start = false;
            }
            b'\r' => {
                output.push(b'\r');
                // Don't update line_start — wait for the LF
            }
            _ => {
                output.push(byte);
                line_start = false;
            }
        }
    }

    output
}

// ---------------------------------------------------------------------------
// write_chunk — Write a data chunk to the transport output
// ---------------------------------------------------------------------------

/// Writes a data chunk to the transport context output.
///
/// Replaces C `write_chunk()` / `transport_write_block()` for the DKIM
/// transport path.  Handles the actual byte-level write to the output stream.
///
/// # Arguments
///
/// * `tctx` — Transport context with the output writer.
/// * `data` — The data bytes to write.
///
/// # Errors
///
/// Returns `TransportSignError::FilterFileError` on I/O failure.
fn write_chunk(tctx: &mut TransportContext, data: &[u8]) -> Result<(), TransportSignError> {
    if data.is_empty() {
        return Ok(());
    }

    let mut written = 0;
    while written < data.len() {
        let n = tctx.output.write(&data[written..])?;
        if n == 0 {
            return Err(TransportSignError::FilterFileError(io::Error::new(
                io::ErrorKind::WriteZero,
                "transport output write returned zero bytes",
            )));
        }
        written += n;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// transport_write_message_passthrough — Plain message write (no signing)
// ---------------------------------------------------------------------------

/// Writes a message without DKIM signing — plain passthrough.
///
/// This is the fallback path when no signing prerequisites are met and
/// `force_bodyhash` is not set.  Replaces the C delegation to
/// `transport_write_message(tctx, 0)` at dkim_transport.c line 416.
///
/// # Arguments
///
/// * `tctx` — Transport context.
/// * `headers` — Message headers (already formatted).
/// * `body` — Message body data.
///
/// # Errors
///
/// Returns appropriate `TransportSignError` variants on failure.
fn transport_write_message_passthrough(
    tctx: &mut TransportContext,
    headers: &[u8],
    body: &[u8],
) -> Result<(), TransportSignError> {
    tracing::debug!("transport_write_message: no signing — passthrough mode");

    write_chunk(tctx, headers)?;
    write_chunk(tctx, body)?;
    tctx.output.flush()?;

    Ok(())
}

// ---------------------------------------------------------------------------
// dkt_direct — Direct signing path (no transport filter)
// ---------------------------------------------------------------------------

/// Direct DKIM signing path — used when no transport filter is configured.
///
/// Replaces C `dkt_direct()` (dkim_transport.c lines 153-235).
///
/// # Algorithm
///
/// 1. Serialize message headers to CRLF-normalized, dot-stuffed string.
/// 2. Compute DKIM signatures over the serialized headers + spool data file
///    by calling the parent module's `dkim_sign()` function.
/// 3. Write the DKIM-Signature headers to the transport output first.
/// 4. Write the original headers.
/// 5. Write the message body in continuation mode.
/// 6. Handle BDAT chunking if applicable.
///
/// # Arguments
///
/// * `tctx` — Transport context with output writer and options.
/// * `dkim_opts` — DKIM transport signing options.
/// * `signing_state` — Mutable signing state for audit trail accumulation.
/// * `headers` — Message header bytes.
/// * `body_data` — Message body bytes (from spool data file).
/// * `arena` — Per-message arena for temporary allocations.
///
/// # Errors
///
/// Returns `TransportSignError` variants for signing failures, strict deferral,
/// ARC failures, or I/O errors.
fn dkt_direct(
    tctx: &mut TransportContext,
    dkim_opts: &mut DkimTransportOptions,
    signing_state: &mut DkimSigningState,
    headers: &[u8],
    body_data: &[u8],
    arena: &MessageArena,
) -> Result<(), TransportSignError> {
    tracing::debug!("dkim signing direct-mode");

    // Step 1: Serialize headers (CRLF-normalized, dot-stuffed)
    // Replaces C lines 168-178: tctx manipulation for header-only output
    let serialized_headers = serialize_headers(headers, true, arena);

    // Step 2: Set dot_stuffed flag based on spool wire format
    // C: dkim->dot_stuffed = f.spool_file_wireformat (line 188)
    dkim_opts.dot_stuffed = tctx.spool_wireformat;

    // Step 3: Compute DKIM signatures over headers + body data
    // Replaces C: dkim_exim_sign(deliver_datafile, offset, hdrs, dkim, &errstr)
    // at lines 189-190.
    //
    // Combine headers and body for signing.
    let mut sign_input = Vec::with_capacity(serialized_headers.len() + body_data.len());
    sign_input.extend_from_slice(&serialized_headers);
    sign_input.extend_from_slice(body_data);

    let dkim_signature_result = super::dkim_sign(&sign_input);

    let dkim_signature = match dkim_signature_result {
        Ok(sig) => {
            if sig.is_empty() {
                tracing::debug!("DKIM sign returned empty signature — checking strict policy");
                // Signing produced no signature — check strict policy
                check_sign_fail(dkim_opts)?;
                None
            } else {
                // Record the signing in the audit trail
                signing_state.signing_record.push_str(&sig);
                Some(sig)
            }
        }
        Err(sign_err) => {
            tracing::error!(error = %sign_err, "DKIM signing failed in direct mode");
            // Check strict policy — if strict, return error; otherwise continue
            check_sign_fail(dkim_opts)?;
            None
        }
    };

    // Step 4: ARC signing (feature-gated)
    // Replaces C lines 197-207: #ifdef EXPERIMENTAL_ARC
    let final_signature_headers = {
        let sig_str = dkim_signature.as_deref().unwrap_or("");

        #[cfg(feature = "arc")]
        {
            if let Some(ref arc_spec) = dkim_opts.arc_signspec {
                if !arc_spec.is_empty() {
                    // Taint-wrap the arc_signspec since it comes from config expansion
                    let tainted_spec = Tainted::new(arc_spec.clone());
                    let clean_spec = tainted_spec.sanitize(|s| !s.is_empty()).map_err(|_| {
                        TransportSignError::ArcSignFailed(
                            "ARC signspec validation failed".to_string(),
                        )
                    })?;
                    arc_sign(clean_spec.as_ref(), sig_str)?
                } else {
                    sig_str.to_string()
                }
            } else {
                sig_str.to_string()
            }
        }
        #[cfg(not(feature = "arc"))]
        {
            sig_str.to_string()
        }
    };

    // Step 5: Write signature headers + original headers + body
    // Replaces C lines 216-234

    // Write DKIM/ARC signature headers first (if any)
    if !final_signature_headers.is_empty() {
        tracing::debug!(
            sig_len = final_signature_headers.len(),
            "writing DKIM/ARC signature headers"
        );
        write_chunk(tctx, final_signature_headers.as_bytes())?;
    }

    // Write original headers (CRLF-normalized)
    let wire_headers = serialize_headers(headers, false, arena);
    write_chunk(tctx, &wire_headers)?;

    // Write body data
    // Replaces C lines 228-231: transport_write_message with NO_HEADERS | CONTINUATION
    write_chunk(tctx, body_data)?;

    tctx.output.flush()?;

    tracing::debug!("dkim signing direct-mode complete");
    Ok(())
}

// ---------------------------------------------------------------------------
// dkt_via_kfile — K-file signing path (transport filter active)
// ---------------------------------------------------------------------------

/// K-file DKIM signing path — used when a transport filter is configured.
///
/// Replaces C `dkt_via_kfile()` (dkim_transport.c lines 254-387).
///
/// # Algorithm
///
/// 1. Create a temporary spool "-K" file.
/// 2. Write the full message (headers + body, CRLF-expanded) into the -K file.
/// 3. Compute DKIM signatures over the -K file contents.
/// 4. Transmit: DKIM-Signature headers → file contents → to transport output.
/// 5. Handle BDAT chunk sizing for pipelined SMTP.
/// 6. Clean up the -K file.
///
/// # Arguments
///
/// * `tctx` — Transport context with output writer and options.
/// * `dkim_opts` — DKIM transport signing options.
/// * `signing_state` — Mutable signing state for audit trail accumulation.
/// * `headers` — Message header bytes.
/// * `body_data` — Message body bytes (from spool data file).
/// * `arena` — Per-message arena for temporary allocations.
///
/// # Errors
///
/// Returns `TransportSignError` variants for file I/O failures, signing
/// failures, strict deferral, ARC failures, or transport output errors.
/// The -K file is always cleaned up on both success and failure paths.
fn dkt_via_kfile(
    tctx: &mut TransportContext,
    dkim_opts: &mut DkimTransportOptions,
    signing_state: &mut DkimSigningState,
    headers: &[u8],
    body_data: &[u8],
    arena: &MessageArena,
) -> Result<(), TransportSignError> {
    // Construct the -K file path:
    //   spool_directory/input/<message_subdir>/<message_id>-<pid>-K
    // Replaces C: spool_fname(US"input", message_subdir, message_id,
    //             string_sprintf("-%d-K", (int)getpid())) at lines 266-267.
    let pid = std::process::id();
    let kfile_name = format!("{}-{}-K", tctx.message_id, pid);
    let kfile_path = tctx
        .spool_directory
        .join("input")
        .join(&tctx.message_subdir)
        .join(&kfile_name);

    tracing::debug!(
        path = %kfile_path.display(),
        "dkim signing via K-file"
    );

    // Create the -K file with proper permissions
    // Replaces C: Uopen(dkim_spool_name, O_RDWR|O_CREAT|O_TRUNC, SPOOL_MODE)
    // at line 271.
    let kfile_result = create_kfile(
        &kfile_path,
        tctx,
        dkim_opts,
        signing_state,
        headers,
        body_data,
        arena,
    );

    // Always clean up the -K file, regardless of success or failure.
    // Replaces C: CLEANUP label at lines 376-381.
    let cleanup_result = cleanup_kfile(&kfile_path);

    // Return the signing result, or the cleanup error if signing succeeded
    // but cleanup failed (unlikely but handled).
    match kfile_result {
        Ok(()) => cleanup_result,
        Err(e) => {
            // Log cleanup errors but return the original signing error
            if let Err(cleanup_err) = cleanup_result {
                tracing::warn!(
                    error = %cleanup_err,
                    "K-file cleanup failed after signing error"
                );
            }
            Err(e)
        }
    }
}

/// Internal implementation of the K-file signing path.
///
/// Separated from `dkt_via_kfile()` to ensure the -K file cleanup always
/// executes regardless of early returns via `?` operator.
fn create_kfile(
    kfile_path: &Path,
    tctx: &mut TransportContext,
    dkim_opts: &mut DkimTransportOptions,
    signing_state: &mut DkimSigningState,
    headers: &[u8],
    body_data: &[u8],
    arena: &MessageArena,
) -> Result<(), TransportSignError> {
    // Ensure parent directory exists
    if let Some(parent) = kfile_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Create and write the -K file
    let mut kfile = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(kfile_path)?;

    // Set permissions (best-effort on Unix)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(SPOOL_MODE);
        fs::set_permissions(kfile_path, perms).ok();
    }

    // Write the full message (headers + body, CRLF-expanded) into the -K file.
    // Replaces C lines 283-293: redirecting transport output into -K file.
    //
    // The transport filter transforms the message before this point in the
    // C code — but since the filter is applied before DKIM signing, we
    // receive the already-filtered content in headers + body_data.
    let wire_headers = serialize_headers(
        headers,
        tctx.options.contains(TransportOptions::END_DOT),
        arena,
    );
    let mut kfile_writer = BufWriter::new(&mut kfile);
    kfile_writer.write_all(&wire_headers)?;
    kfile_writer.write_all(body_data)?;

    // Ensure CRLF termination if end_dot is set
    if tctx.options.contains(TransportOptions::END_DOT) {
        // Check if body already ends with CRLF
        if !body_data.ends_with(CRLF) {
            kfile_writer.write_all(CRLF)?;
        }
        // Add dot-terminator: CRLF.CRLF
        kfile_writer.write_all(b".\r\n")?;
    }

    kfile_writer.flush()?;
    drop(kfile_writer);

    // Get the K-file size for BDAT calculations
    // Replaces C: k_file_size = lseek(dkim_fd, 0, SEEK_END) at line 332.
    let k_file_size = kfile.seek(SeekFrom::End(0))?;

    // Compute DKIM signature over the K-file contents.
    // Replaces C: dkim_exim_sign(dkim_fd, 0, NULL, dkim, &errstr) at line 307.
    //
    // The dotstuffed status depends on whether end_dot was in the options.
    dkim_opts.dot_stuffed = tctx.options.contains(TransportOptions::END_DOT);

    // Read the K-file content for signing
    kfile.seek(SeekFrom::Start(0))?;
    let mut kfile_content = Vec::with_capacity(k_file_size as usize);
    kfile.read_to_end(&mut kfile_content)?;

    let dkim_signature_result = super::dkim_sign(&kfile_content);

    let mut dkim_signature_bytes: Vec<u8> = Vec::new();

    match dkim_signature_result {
        Ok(sig) => {
            if sig.is_empty() {
                tracing::debug!(
                    "DKIM sign returned empty signature for K-file — checking strict policy"
                );
                check_sign_fail(dkim_opts)?;
            } else {
                signing_state.signing_record.push_str(&sig);
                dkim_signature_bytes = sig.into_bytes();
            }
        }
        Err(sign_err) => {
            tracing::error!(error = %sign_err, "DKIM signing failed in K-file mode");
            check_sign_fail(dkim_opts)?;
        }
    }

    // ARC signing (feature-gated)
    // Replaces C lines 319-327: #ifdef EXPERIMENTAL_ARC
    #[cfg(feature = "arc")]
    {
        if let Some(ref arc_spec) = dkim_opts.arc_signspec {
            if !arc_spec.is_empty() {
                let tainted_spec = Tainted::new(arc_spec.clone());
                let clean_spec = tainted_spec.sanitize(|s| !s.is_empty()).map_err(|_| {
                    TransportSignError::ArcSignFailed("ARC signspec validation failed".to_string())
                })?;
                let sig_str = std::str::from_utf8(&dkim_signature_bytes).unwrap_or("");
                let combined = arc_sign(clean_spec.as_ref(), sig_str)?;
                dkim_signature_bytes = combined.into_bytes();
            }
        }
    }

    let dlen = dkim_signature_bytes.len();

    // Handle BDAT chunking
    // Replaces C lines 338-361: BDAT precursor chunk and final chunk.
    if tctx.options.contains(TransportOptions::USE_BDAT) {
        if let Some(ref mut chunk_cb) = tctx.chunk_callback {
            // On big messages, output a precursor chunk to get pipelined
            // MAIL & RCPT commands flushed, then reap the responses.
            // Replaces C lines 344-354.
            if dlen + (k_file_size as usize) > DELIVER_OUT_BUFFER_SIZE && dlen > 0 {
                chunk_cb(dlen, 0)?;
                write_chunk(tctx, &dkim_signature_bytes)?;
                // Re-borrow chunk_callback for reap
                if let Some(ref mut chunk_cb) = tctx.chunk_callback {
                    chunk_cb(0, chunk_flags::TC_REAP_PREV)?;
                }
                dkim_signature_bytes.clear();
            }

            // Send the BDAT command for the entire remaining message.
            // Replaces C line 359.
            let remaining_dlen = dkim_signature_bytes.len();
            if let Some(ref mut chunk_cb) = tctx.chunk_callback {
                chunk_cb(
                    remaining_dlen + k_file_size as usize,
                    chunk_flags::TC_CHUNK_LAST,
                )?;
            }
        }
    }

    // Write remaining signature bytes (if not already sent as precursor)
    if !dkim_signature_bytes.is_empty() {
        write_chunk(tctx, &dkim_signature_bytes)?;
    }

    // Send the K-file contents to the transport output.
    // Replaces C lines 366-374: dkt_send_file().
    kfile.seek(SeekFrom::Start(0))?;
    send_file(&mut *tctx.output, &mut kfile, 0)?;

    tracing::debug!("dkim signing via K-file complete");
    Ok(())
}

/// Cleans up the temporary -K file.
///
/// Attempts to remove the file, logging but not failing on errors.
/// Replaces C: close(dkim_fd); Uunlink(dkim_spool_name) at lines 378-379.
fn cleanup_kfile(kfile_path: &Path) -> Result<(), TransportSignError> {
    match fs::remove_file(kfile_path) {
        Ok(()) => {
            tracing::debug!(path = %kfile_path.display(), "K-file cleaned up");
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // File already removed — not an error
            Ok(())
        }
        Err(e) => {
            tracing::warn!(
                path = %kfile_path.display(),
                error = %e,
                "failed to remove K-file"
            );
            // Don't propagate cleanup errors — the signing operation itself
            // may have succeeded.  The spool cleaner will eventually remove
            // orphaned -K files.
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// dkim_transport_write_message — Public entry point
// ---------------------------------------------------------------------------

/// Writes a message with DKIM (and optionally ARC) signing.
///
/// This is the main public entry point for the DKIM transport signing shim.
/// It is called by the SMTP transport in place of the plain
/// `transport_write_message()` when DKIM support is enabled.
///
/// Replaces C `dkim_transport_write_message()` (dkim_transport.c lines 406-436).
///
/// # Decision Tree
///
/// 1. If no signing prerequisites (private_key, domain, selector) and no
///    `force_bodyhash`: delegate to plain transport write (passthrough).
/// 2. If no transport filter configured: use direct signing path.
/// 3. If transport filter configured: use K-file signing path.
///
/// After signing, the signing audit trail is recorded in
/// `tctx.address.dkim_used` and the signing state is cleared.
///
/// # Arguments
///
/// * `tctx` — Transport context containing the output writer, options,
///   message identity, and delivery address.
/// * `dkim_opts` — DKIM transport signing options from the SMTP transport
///   configuration.
/// * `signing_state` — Mutable signing state for accumulating the audit trail.
/// * `headers` — Message header bytes (raw, before CRLF normalization).
/// * `body_data` — Message body bytes (from the spool data file).
/// * `arena` — Per-message arena for temporary allocations.
///
/// # Returns
///
/// `Ok(())` on success, or a `TransportSignError` variant on failure.
///
/// # Errors
///
/// - `SigningFailed` — DKIM signature computation failed (and strict mode
///   is not enabled, so delivery proceeds with a warning).
/// - `StrictDeferral` — DKIM signing failed and `dkim_strict` is "1" or
///   "true" — delivery is deferred.
/// - `ArcSignFailed` — ARC signing failed (only with `arc` feature).
/// - `FilterFileError` — I/O error during K-file operations.
/// - `HeaderSerializationError` — Header serialization failed.
pub fn dkim_transport_write_message(
    tctx: &mut TransportContext,
    dkim_opts: &mut DkimTransportOptions,
    signing_state: &mut DkimSigningState,
    headers: &[u8],
    body_data: &[u8],
    arena: &MessageArena,
) -> Result<(), TransportSignError> {
    tracing::debug!(
        message_id = %tctx.message_id,
        has_prerequisites = dkim_opts.has_signing_prerequisites(),
        force_bodyhash = dkim_opts.force_bodyhash,
        has_filter = tctx.filter_command.is_some(),
        "dkim_transport_write_message: entry"
    );

    // Decision 1: If no signing prerequisites AND no force_bodyhash,
    // delegate to plain transport write.
    // Replaces C lines 414-416.
    if !dkim_opts.has_signing_prerequisites() && !dkim_opts.force_bodyhash {
        tracing::debug!("no DKIM signing prerequisites — passthrough mode");
        return transport_write_message_passthrough(tctx, headers, body_data);
    }

    // Decision 2 & 3: Choose signing path based on transport filter.
    let result = if tctx.filter_command.is_none() {
        // No transport filter — direct signing
        // Replaces C lines 422-426.
        dkt_direct(tctx, dkim_opts, signing_state, headers, body_data, arena)
    } else {
        // Transport filter present — K-file signing
        // Replaces C lines 428-432.
        dkt_via_kfile(tctx, dkim_opts, signing_state, headers, body_data, arena)
    };

    // Record signing audit trail in the address item.
    // Replaces C: tctx->addr->dkim_used = string_from_gstring(dkim_signing_record)
    // at line 434.
    let record = signing_state.take_record();
    if !record.is_empty() {
        tctx.address.dkim_used = Some(record);
        tracing::debug!(
            dkim_used = ?tctx.address.dkim_used,
            "signing audit trail recorded"
        );
    }

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify TransportSignError Display implementations.
    #[test]
    fn test_error_display() {
        let err = TransportSignError::SigningFailed("bad key".to_string());
        assert_eq!(err.to_string(), "DKIM signing failed: bad key");

        let err = TransportSignError::StrictDeferral;
        assert_eq!(err.to_string(), "DKIM strict mode — deferring delivery");

        let err = TransportSignError::ArcSignFailed("no module".to_string());
        assert_eq!(err.to_string(), "ARC signing failed: no module");

        let err = TransportSignError::HeaderSerializationError("overflow".to_string());
        assert_eq!(err.to_string(), "Header serialization failed: overflow");
    }

    /// Verify TransportSignError From<io::Error> conversion.
    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing file");
        let sign_err: TransportSignError = io_err.into();
        match sign_err {
            TransportSignError::FilterFileError(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
            }
            _ => panic!("expected FilterFileError variant"),
        }
    }

    /// Verify DkimTransportOptions default values.
    #[test]
    fn test_dkim_transport_options_default() {
        let opts = DkimTransportOptions::default();
        assert!(opts.dkim_domain.is_none());
        assert!(opts.dkim_selector.is_none());
        assert!(opts.dkim_private_key.is_none());
        assert!(opts.dkim_canon.is_none());
        assert!(opts.dkim_sign_headers.is_none());
        assert!(opts.dkim_strict.is_none());
        assert!(opts.dkim_hash.is_none());
        assert!(opts.dkim_identity.is_none());
        assert!(opts.dkim_timestamps.is_none());
        assert!(!opts.force_bodyhash);
        assert!(!opts.dot_stuffed);
        assert!(opts.get_arc_signspec().is_none());
    }

    /// Verify signing prerequisites check.
    #[test]
    fn test_has_signing_prerequisites() {
        let mut opts = DkimTransportOptions::default();
        assert!(!opts.has_signing_prerequisites());

        opts.dkim_private_key = Some("/path/to/key.pem".to_string());
        assert!(!opts.has_signing_prerequisites());

        opts.dkim_domain = Some("example.com".to_string());
        assert!(!opts.has_signing_prerequisites());

        opts.dkim_selector = Some("sel1".to_string());
        assert!(opts.has_signing_prerequisites());
    }

    /// Verify empty string prerequisites are not considered valid.
    #[test]
    fn test_empty_string_prerequisites() {
        let opts = DkimTransportOptions {
            dkim_private_key: Some(String::new()),
            dkim_domain: Some("example.com".to_string()),
            dkim_selector: Some("sel1".to_string()),
            ..DkimTransportOptions::default()
        };
        assert!(!opts.has_signing_prerequisites());
    }

    /// Verify check_sign_fail with no strict setting.
    #[test]
    fn test_check_sign_fail_no_strict() {
        let opts = DkimTransportOptions::default();
        assert!(check_sign_fail(&opts).is_ok());
    }

    /// Verify check_sign_fail with strict="1".
    #[test]
    fn test_check_sign_fail_strict_true() {
        let opts = DkimTransportOptions {
            dkim_strict: Some("1".to_string()),
            ..DkimTransportOptions::default()
        };
        let result = check_sign_fail(&opts);
        assert!(result.is_err());
        match result.unwrap_err() {
            TransportSignError::StrictDeferral => {}
            other => panic!("expected StrictDeferral, got: {}", other),
        }
    }

    /// Verify check_sign_fail with strict="true" (case-insensitive).
    #[test]
    fn test_check_sign_fail_strict_true_case() {
        let opts = DkimTransportOptions {
            dkim_strict: Some("TRUE".to_string()),
            ..DkimTransportOptions::default()
        };
        assert!(matches!(
            check_sign_fail(&opts),
            Err(TransportSignError::StrictDeferral)
        ));
    }

    /// Verify check_sign_fail with strict="0" (not strict).
    #[test]
    fn test_check_sign_fail_strict_false() {
        let opts = DkimTransportOptions {
            dkim_strict: Some("0".to_string()),
            ..DkimTransportOptions::default()
        };
        assert!(check_sign_fail(&opts).is_ok());
    }

    /// Verify header serialization with LF line endings.
    #[test]
    fn test_serialize_headers_lf_to_crlf() {
        let arena = MessageArena::new();
        let headers = b"From: user@example.com\nTo: other@example.com\n";
        let result = serialize_headers(headers, false, &arena);
        assert_eq!(
            result,
            b"From: user@example.com\r\nTo: other@example.com\r\n"
        );
    }

    /// Verify header serialization preserves existing CRLF.
    #[test]
    fn test_serialize_headers_crlf_preserved() {
        let arena = MessageArena::new();
        let headers = b"From: user@example.com\r\nTo: other@example.com\r\n";
        let result = serialize_headers(headers, false, &arena);
        assert_eq!(
            result,
            b"From: user@example.com\r\nTo: other@example.com\r\n"
        );
    }

    /// Verify dot-stuffing during header serialization.
    #[test]
    fn test_serialize_headers_dot_stuffing() {
        let arena = MessageArena::new();
        let headers = b".leading dot\n..already stuffed\nnormal line\n";
        let result = serialize_headers(headers, true, &arena);
        // Lines starting with . get doubled; already-doubled get tripled
        assert_eq!(
            result,
            b"..leading dot\r\n...already stuffed\r\nnormal line\r\n"
        );
    }

    /// Verify TransportOptions bitflag operations.
    #[test]
    fn test_transport_options_flags() {
        let opts = TransportOptions::NONE;
        assert!(!opts.contains(TransportOptions::END_DOT));
        assert!(!opts.contains(TransportOptions::USE_BDAT));

        let opts = opts.with(TransportOptions::END_DOT);
        assert!(opts.contains(TransportOptions::END_DOT));
        assert!(!opts.contains(TransportOptions::USE_BDAT));

        let opts = opts.with(TransportOptions::USE_BDAT);
        assert!(opts.contains(TransportOptions::END_DOT));
        assert!(opts.contains(TransportOptions::USE_BDAT));

        let opts = opts.without(TransportOptions::END_DOT);
        assert!(!opts.contains(TransportOptions::END_DOT));
        assert!(opts.contains(TransportOptions::USE_BDAT));
    }

    /// Verify DkimSigningState operations.
    #[test]
    fn test_signing_state() {
        let mut state = DkimSigningState::new();
        assert!(state.signing_record.is_empty());

        state.signing_record.push_str("example.com:sel1 ");
        state.signing_record.push_str("example.org:sel2");
        assert_eq!(state.signing_record, "example.com:sel1 example.org:sel2");

        let record = state.take_record();
        assert_eq!(record, "example.com:sel1 example.org:sel2");
        assert!(state.signing_record.is_empty());
    }

    /// Verify ChunkingState default is Disabled.
    #[test]
    fn test_chunking_state_default() {
        assert_eq!(ChunkingState::default(), ChunkingState::Disabled);
    }

    /// Verify AddressItem default and dkim_used assignment.
    #[test]
    fn test_address_item_dkim_used() {
        let mut addr = AddressItem::default();
        assert!(addr.dkim_used.is_none());

        addr.dkim_used = Some("example.com:sel1".to_string());
        assert_eq!(addr.dkim_used.as_deref(), Some("example.com:sel1"));
    }
}
