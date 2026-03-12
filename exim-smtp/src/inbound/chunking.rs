//! CHUNKING/BDAT support (RFC 3030) for the inbound SMTP server.
//!
//! This module rewrites the CHUNKING/BDAT implementation from
//! `src/src/smtp_in.c` lines 720–970 (~250 lines of C). It implements
//! RFC 3030 which allows message data to be sent via `BDAT` commands
//! instead of the traditional `DATA` command.
//!
//! # Architecture
//!
//! The key complexity is the **push/pop function stack pattern** — BDAT wraps
//! the underlying receive functions (`smtp_getc` / TLS `getc`) with
//! `bdat_getc` variants that handle chunk boundaries, acknowledgements,
//! and command interleaving.
//!
//! In C this was implemented by swapping global function pointers. In Rust
//! the pattern is modelled with an explicit [`ReceiveFunctions`] struct
//! stored inside [`ChunkingContext`], with the I/O state ([`SmtpIoState`])
//! passed as an explicit parameter.
//!
//! # Scoped Context (AAP §0.4.4)
//!
//! [`ChunkingContext`] replaces the C global variables `chunking_state`,
//! `chunking_data_left`, `chunking_datasize`, and the `lwr_receive_*`
//! function pointer stack.
//!
//! # Taint Tracking (AAP §0.4.3)
//!
//! Data bytes read through BDAT are wrapped in [`Tainted<u8>`] to enforce
//! compile-time taint tracking with zero runtime cost.
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks (AAP §0.7.2).
//!
//! # Feature Flags
//!
//! | Feature | C Equivalent | Effect |
//! |---------|-------------|--------|
//! | `dkim` | `#ifndef DISABLE_DKIM` | DKIM verification pause/resume between chunks |

use std::fmt;

use tracing::{debug, warn};

use super::pipelining::{
    check_sync, smtp_getbuf, smtp_getc, smtp_hasc, smtp_ungetc, SmtpIoState, SmtpSyncConfig,
    WBR_DATA_ONLY,
};
use crate::SmtpCommand;
use exim_store::Tainted;

// ─────────────────────────────────────────────────────────────────────────────
// ChunkingState — state machine for CHUNKING negotiation
// ─────────────────────────────────────────────────────────────────────────────

/// State of the CHUNKING extension for the current SMTP session.
///
/// Derived from the C `chunking_states[]` array at `smtp_in.c` lines 323–327.
/// The [`Display`] implementation produces strings matching the C array
/// exactly, which is critical for debug log compatibility (AAP §0.7.1).
///
/// State transitions:
/// - `NotOffered` → initial state when CHUNKING is disabled
/// - `Offered` → CHUNKING advertised in EHLO response
/// - `Active` → BDAT command received (non-LAST)
/// - `Last` → BDAT LAST command received (final chunk)
/// - `Active`/`Last` → `Offered` after chunk acknowledgement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChunkingState {
    /// CHUNKING was not offered in the EHLO response.
    NotOffered,
    /// CHUNKING was offered (or re-offered after chunk ACK).
    Offered,
    /// A non-LAST BDAT command is being processed.
    Active,
    /// The final BDAT LAST command is being processed.
    Last,
}

impl fmt::Display for ChunkingState {
    /// Format matching C `chunking_states[]` exactly (smtp_in.c:323–327).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ChunkingState::NotOffered => "not-offered",
            ChunkingState::Offered => "offered",
            ChunkingState::Active => "active",
            ChunkingState::Last => "last",
        };
        f.write_str(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BdatResult — return type for bdat_getc
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a `bdat_getc` call.
///
/// In the C implementation, `bdat_getc()` returns `int` with special values
/// `EOF`, `EOD`, and `ERR` alongside normal byte values 0–255. In Rust
/// this is modelled as an enum for type safety, with data bytes wrapped
/// in [`Tainted<u8>`] to enforce compile-time taint tracking (AAP §0.4.3).
#[derive(Debug)]
pub enum BdatResult {
    /// A normal data byte from the BDAT chunk (tainted network input).
    Byte(Tainted<u8>),
    /// End-of-data: the final BDAT LAST chunk has been fully consumed.
    Eod,
    /// Protocol error: an RSET was received, transaction reset.
    Err,
    /// Connection closed by the remote peer or QUIT received.
    Eof,
}

impl BdatResult {
    /// Extract the raw byte value from a `Byte` result.
    ///
    /// Returns `Some(byte)` if the result is [`BdatResult::Byte`],
    /// calling [`Tainted::into_inner()`] to unwrap the taint wrapper.
    /// Returns `None` for non-byte results (`Eod`, `Err`, `Eof`).
    ///
    /// This is the primary way to convert tainted BDAT data into raw
    /// bytes after the caller has validated or accepted the taint.
    pub fn into_byte(self) -> Option<u8> {
        match self {
            BdatResult::Byte(t) => Some(t.into_inner()),
            _ => None,
        }
    }

    /// Check if this result indicates data is available.
    pub fn is_byte(&self) -> bool {
        matches!(self, BdatResult::Byte(_))
    }

    /// Check if this result indicates end-of-data.
    pub fn is_eod(&self) -> bool {
        matches!(self, BdatResult::Eod)
    }
}

impl fmt::Display for BdatResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BdatResult::Byte(t) => {
                write!(f, "Byte(0x{:02x})", t.as_ref())
            }
            BdatResult::Eod => f.write_str("EOD"),
            BdatResult::Err => f.write_str("ERR"),
            BdatResult::Eof => f.write_str("EOF"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReceiveFunctions — lower-level I/O function stack
// ─────────────────────────────────────────────────────────────────────────────

/// Saved lower-level receive function set.
///
/// In the C implementation, `lwr_receive_getc/getbuf/hasc/ungetc` are global
/// function pointers saved when BDAT pushes its own handlers and restored
/// when BDAT pops. In Rust, since the I/O state is passed explicitly,
/// these are function pointers that operate on [`SmtpIoState`].
///
/// The default set wraps the pipelining module's `smtp_getc`, `smtp_getbuf`,
/// `smtp_hasc`, and `smtp_ungetc` functions.
pub struct ReceiveFunctions {
    /// Read a single byte from the underlying I/O layer.
    ///
    /// Signature matches C `receive_getc(unsigned lim) → int`.
    /// Returns the byte value (0–255) or −1 on EOF/error.
    pub getc: fn(&mut SmtpIoState, u32) -> i32,

    /// Read a buffer of bytes from the underlying I/O layer.
    ///
    /// Updates `*len` with the actual number of bytes read.
    /// Returns `true` if data was read, `false` on EOF/error.
    /// The read data is available in `SmtpIoState.inbuffer` at positions
    /// `[inptr - *len .. inptr]` after the call.
    pub getbuf: fn(&mut SmtpIoState, &mut u32) -> bool,

    /// Check whether the underlying I/O layer has data available.
    ///
    /// Pure buffer inspection — no I/O is performed.
    pub hasc: fn(&SmtpIoState) -> bool,

    /// Push a byte back into the underlying I/O layer.
    ///
    /// Returns the pushed-back byte value.
    pub ungetc: fn(&mut SmtpIoState, u8) -> u8,
}

/// Adapter: wraps `smtp_getbuf` to match the `getbuf` field signature.
///
/// `smtp_getbuf` returns `Option<&[u8]>` — we convert to `bool` since
/// the chunk-level caller reconstructs the slice from buffer positions.
fn smtp_getbuf_adapter(io: &mut SmtpIoState, len: &mut u32) -> bool {
    smtp_getbuf(io, len).is_some()
}

impl ReceiveFunctions {
    /// Construct the default receive function set using the pipelining
    /// module's SMTP I/O functions.
    ///
    /// These are the standard functions used when no TLS-specific or
    /// other custom I/O layer is active. When TLS is enabled, the
    /// pipelining module internally delegates to the TLS buffer, so
    /// these default functions remain correct for both plain and TLS
    /// connections.
    pub fn default_smtp() -> Self {
        Self {
            getc: smtp_getc,
            getbuf: smtp_getbuf_adapter,
            hasc: smtp_hasc,
            ungetc: smtp_ungetc,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BdatSessionOps — trait for SMTP session operations needed by BDAT
// ─────────────────────────────────────────────────────────────────────────────

/// SMTP session operations required by the BDAT/CHUNKING command handler.
///
/// This trait decouples the chunking module from the command loop module.
/// The `command_loop` module provides the concrete implementation that
/// hooks into the full SMTP session state machine.
///
/// Each method corresponds to a specific C function or operation called
/// from within `bdat_getc()` during inter-chunk command processing.
pub trait BdatSessionOps {
    /// Read the next SMTP command from the input stream.
    ///
    /// Corresponds to C `smtp_read_command(TRUE, 1)` at smtp_in.c:814.
    /// Returns the parsed command type and any trailing data string
    /// (e.g., the size and LAST flag for BDAT commands).
    fn read_command(&mut self, io: &mut SmtpIoState) -> (SmtpCommand, String);

    /// Send a response line to the SMTP client.
    ///
    /// The message should include the full response line with CRLF.
    /// Corresponds to C `smtp_printf(msg, SP_NO_MORE)`.
    fn send_response(&mut self, msg: &str);

    /// Handle the SMTP QUIT command during BDAT processing.
    ///
    /// Corresponds to C `smtp_quit_handler(&user_msg, &log_msg)`.
    fn handle_quit(&mut self);

    /// Handle the SMTP RSET command during BDAT processing.
    ///
    /// Corresponds to C `smtp_rset_handler()`.
    fn handle_rset(&mut self);

    /// Log an incomplete transaction with the given reason.
    ///
    /// Corresponds to C `incomplete_transaction_log(US"sync failure")`.
    fn log_incomplete_transaction(&mut self, reason: &str);

    /// Report a synchronization protocol error to the client.
    ///
    /// Sends the appropriate SMTP error response with the given code
    /// and message. Returns `true` if the maximum synchronization error
    /// count has been exceeded and the connection should be terminated.
    ///
    /// Corresponds to C `synprot_error(L_smtp_protocol_error, code, NULL, msg)`.
    fn report_synprot_error(&mut self, code: u32, msg: &str) -> bool;

    /// Record a NOOP command in the SMTP statistics tracking.
    ///
    /// Corresponds to C `HAD(SCH_NOOP)` at smtp_in.c:843.
    fn record_noop(&mut self);

    /// Pause or resume DKIM verification between BDAT chunks.
    ///
    /// Called with `pause=true` between chunks (to pause verification)
    /// and `pause=false` when resuming data reception.
    /// Default implementation is a no-op for non-DKIM builds.
    ///
    /// Corresponds to C `dkim_pause(TRUE/FALSE)` at smtp_in.c:767,875.
    fn dkim_pause(&mut self, _pause: bool) {}

    /// Signal end-of-data to the DKIM verification engine.
    ///
    /// Called when the final BDAT LAST chunk has been consumed.
    /// Default implementation is a no-op for non-DKIM builds.
    ///
    /// Corresponds to C `smtp_verify_feed(NULL, 0)` at smtp_in.c:800.
    fn dkim_verify_feed_eod(&mut self) {}
}

// ─────────────────────────────────────────────────────────────────────────────
// ChunkingContext — per-session CHUNKING state
// ─────────────────────────────────────────────────────────────────────────────

/// Per-session CHUNKING/BDAT state.
///
/// Replaces C global variables `chunking_state`, `chunking_data_left`,
/// `chunking_datasize`, and the `lwr_receive_*` function pointer stack
/// (AAP §0.4.4).
///
/// # Lifecycle
///
/// 1. Created at session start via [`ChunkingContext::new()`].
/// 2. State set to [`ChunkingState::Offered`] if CHUNKING advertised in EHLO.
/// 3. [`bdat_push_receive_functions()`] called when first `BDAT` received.
/// 4. [`bdat_getc()`] / [`bdat_getbuf()`] used to read chunk data.
/// 5. [`bdat_pop_receive_functions()`] called when chunk fully consumed.
/// 6. Cycle repeats for subsequent `BDAT` commands.
/// 7. [`bdat_flush_data()`] called to discard remaining data on error.
pub struct ChunkingContext {
    /// Current state of the CHUNKING extension for this session.
    pub state: ChunkingState,

    /// Number of data bytes remaining in the current BDAT chunk.
    ///
    /// Decremented as bytes are read via [`bdat_getc()`] /
    /// [`bdat_getbuf()`]. When zero, inter-chunk handling occurs.
    pub data_left: u32,

    /// Total size of the current BDAT chunk as declared in the command.
    ///
    /// Used in the chunk acknowledgement message:
    /// `"250 {datasize} byte chunk received\r\n"`.
    pub datasize: u32,

    /// Saved lower-level receive functions (the push/pop stack).
    ///
    /// `Some(fns)` when BDAT handlers are active (pushed).
    /// `None` when BDAT handlers have been popped.
    lower_receive: Option<ReceiveFunctions>,
}

impl ChunkingContext {
    /// Create a new `ChunkingContext`.
    ///
    /// # Arguments
    ///
    /// * `offered` — `true` if the server advertised CHUNKING in the
    ///   EHLO response, `false` otherwise.
    pub fn new(offered: bool) -> Self {
        let state = if offered {
            ChunkingState::Offered
        } else {
            ChunkingState::NotOffered
        };
        Self {
            state,
            data_left: 0,
            datasize: 0,
            lower_receive: None,
        }
    }

    /// Access the saved lower-level receive functions, if any.
    ///
    /// Returns `None` if BDAT handlers have been popped.
    fn lower(&self) -> Option<&ReceiveFunctions> {
        self.lower_receive.as_ref()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// bdat_push_receive_functions / bdat_pop_receive_functions
// ─────────────────────────────────────────────────────────────────────────────

/// Push BDAT-aware receive functions onto the function stack.
///
/// Saves the provided lower-level [`ReceiveFunctions`] inside the
/// [`ChunkingContext`] so that the `bdat_*` family can delegate I/O.
///
/// # Double-Push Guard (smtp_in.c:936)
///
/// If the lower functions are already saved (i.e., a push was already
/// performed without a corresponding pop), a debug warning is emitted
/// and the new push is silently ignored. This matches the C behaviour
/// of the guard at smtp_in.c line 936.
pub fn bdat_push_receive_functions(ctx: &mut ChunkingContext, lower: ReceiveFunctions) {
    if ctx.lower_receive.is_some() {
        warn!("bdat_push_receive_functions: double push — lower functions already saved");
        return;
    }
    ctx.lower_receive = Some(lower);
    debug!("bdat: pushed receive functions");
}

/// Pop BDAT-aware receive functions from the function stack.
///
/// Restores the lower-level receive functions by clearing the saved
/// copy from the [`ChunkingContext`].
///
/// # Double-Pop Guard (smtp_in.c:950)
///
/// If no lower functions are saved (i.e., a pop was already performed
/// or no push ever happened), a debug warning is emitted and the pop
/// is silently ignored. This matches the C behaviour of the guard at
/// smtp_in.c line 950.
pub fn bdat_pop_receive_functions(ctx: &mut ChunkingContext) {
    if ctx.lower_receive.is_none() {
        warn!("bdat_pop_receive_functions: double pop — no lower functions to restore");
        return;
    }
    ctx.lower_receive = None;
    debug!("bdat: popped receive functions");
}

// ─────────────────────────────────────────────────────────────────────────────
// bdat_getc — the core BDAT byte-reading function (smtp_in.c:744-881)
// ─────────────────────────────────────────────────────────────────────────────

/// Read a single byte from a BDAT chunk.
///
/// This is the most complex function in the CHUNKING module. It handles:
///
/// 1. Reading data bytes within the current chunk.
/// 2. Popping receive functions and pausing DKIM at chunk boundaries.
/// 3. Pipelining synchronization checks between chunks.
/// 4. Acknowledging non-LAST chunks.
/// 5. Reading interleaved SMTP commands (BDAT, QUIT, RSET, NOOP).
/// 6. Error recovery via a `repeat_until_rset` loop.
///
/// # Arguments
///
/// * `ctx` — Mutable reference to the session's CHUNKING state.
/// * `io` — Mutable reference to the SMTP I/O state.
/// * `sync_config` — Pipelining synchronization configuration.
/// * `ops` — SMTP session operations (command reading, responses, etc.).
/// * `_lim` — Ignored limit parameter (C compatibility, smtp_in.c:763 comment).
///
/// # Returns
///
/// A [`BdatResult`] indicating the outcome:
/// - [`BdatResult::Byte`] — A data byte (tainted network input).
/// - [`BdatResult::Eod`] — End-of-data (final `BDAT LAST` consumed).
/// - [`BdatResult::Err`] — Transaction reset (RSET received).
/// - [`BdatResult::Eof`] — Connection closed (QUIT or EOF received).
///
/// # Panics
///
/// Panics if called when lower receive functions are not pushed and
/// `data_left > 0` (programming error — misuse of the API).
///
/// # Source Reference
///
/// `smtp_in.c` lines 744–881.
pub fn bdat_getc(
    ctx: &mut ChunkingContext,
    io: &mut SmtpIoState,
    sync_config: &SmtpSyncConfig,
    ops: &mut dyn BdatSessionOps,
    _lim: u32,
) -> BdatResult {
    // ── Main loop ─────────────────────────────────────────────────────
    // This outer loop handles reading the next BDAT command after a
    // non-LAST chunk has been acknowledged (the "next_cmd" label in C).
    loop {
        // ── Step 1: Data bytes remaining in the current chunk ─────────
        // (smtp_in.c:759-764)
        if ctx.data_left > 0 {
            ctx.data_left -= 1;
            let lower_getc = ctx
                .lower()
                .expect("lower receive functions not pushed during bdat_getc")
                .getc;
            let byte = lower_getc(io, ctx.data_left);
            if byte < 0 {
                return BdatResult::Eof;
            }
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            return BdatResult::Byte(Tainted::new(byte as u8));
        }

        // ── Step 2: Chunk boundary — pop receive functions ────────────
        // (smtp_in.c:765)
        bdat_pop_receive_functions(ctx);

        // ── Step 3: DKIM pause between chunks ─────────────────────────
        // (smtp_in.c:767-768, gated by #ifndef DISABLE_DKIM)
        #[cfg(feature = "dkim")]
        ops.dkim_pause(true);

        // ── Step 4: Pipelining sync check ─────────────────────────────
        // (smtp_in.c:773-792)
        //
        // If PIPELINING was not advertised and we detect unsolicited
        // input between chunks, it's a synchronization error.
        if !sync_config.smtp_in_pipelining_advertised && !check_sync(io, WBR_DATA_ONLY, sync_config)
        {
            ops.log_incomplete_transaction("sync failure");
            let exceeded =
                ops.report_synprot_error(554, "SMTP synchronization error (BDAT interleave)");
            if exceeded {
                return BdatResult::Eof;
            }
            // Fall through to repeat_until_rset
            return repeat_until_rset(ctx, io, ops);
        }

        // ── Step 5: LAST chunk handling ───────────────────────────────
        // (smtp_in.c:797-803)
        //
        // If this was the final BDAT LAST chunk, signal end-of-data
        // and return Eod so the message body can be finalized.
        if ctx.state == ChunkingState::Last {
            #[cfg(feature = "dkim")]
            ops.dkim_verify_feed_eod();
            return BdatResult::Eod;
        }

        // ── Step 6: Non-LAST chunk acknowledgement ────────────────────
        // (smtp_in.c:805-808)
        //
        // Message format MUST match C exactly for log/protocol compat:
        //   "250 {size} byte chunk received\r\n"
        let ack = format!("250 {} byte chunk received\r\n", ctx.datasize);
        ops.send_response(&ack);
        ctx.state = ChunkingState::Offered;
        debug!("chunking state '{}'", ctx.state);

        // ── Step 7: Read the next SMTP command ────────────────────────
        // (smtp_in.c:814-879, the "next_cmd" label in C)
        loop {
            let (cmd, cmd_data) = ops.read_command(io);

            match cmd {
                // ── BDAT: set up next chunk (smtp_in.c:862-877) ──────
                SmtpCommand::Bdat => {
                    // Parse size and LAST flag from command data.
                    // Expected format: "<size>[ LAST]"
                    let (size, is_last) = parse_bdat_args(&cmd_data);
                    match size {
                        Some(0) => {
                            ops.send_response("504 zero size for BDAT command\r\n");
                            return repeat_until_rset(ctx, io, ops);
                        }
                        Some(s) => {
                            ctx.data_left = s;
                            ctx.datasize = s;
                            ctx.state = if is_last {
                                ChunkingState::Last
                            } else {
                                ChunkingState::Active
                            };
                            debug!(
                                "chunking state '{}', data_left={}",
                                ctx.state, ctx.data_left
                            );

                            // Re-push the lower-level receive functions
                            bdat_push_receive_functions(ctx, ReceiveFunctions::default_smtp());

                            // Resume DKIM verification
                            #[cfg(feature = "dkim")]
                            ops.dkim_pause(false);

                            // Break inner loop, continue outer loop to
                            // read the first byte of the new chunk
                            break;
                        }
                        None => {
                            ops.send_response("501 missing size for BDAT command\r\n");
                            return repeat_until_rset(ctx, io, ops);
                        }
                    }
                }

                // ── QUIT: orderly shutdown (smtp_in.c:831-834) ───────
                SmtpCommand::Quit => {
                    ops.handle_quit();
                    return BdatResult::Eof;
                }

                // ── EOF: connection closed (smtp_in.c:836-837) ───────
                SmtpCommand::Eof => {
                    return BdatResult::Eof;
                }

                // ── RSET: transaction reset (smtp_in.c:839-841) ─────
                SmtpCommand::Rset => {
                    ops.handle_rset();
                    return BdatResult::Err;
                }

                // ── NOOP: acknowledge and loop (smtp_in.c:843-848) ──
                SmtpCommand::Noop => {
                    ops.record_noop();
                    ops.send_response("250 OK\r\n");
                    // Read the next command (re-enter inner loop)
                    continue;
                }

                // ── Anything else: protocol violation ────────────────
                // (smtp_in.c:852-860)
                _ => {
                    ops.send_response("503 only BDAT permissible after non-LAST BDAT\r\n");
                    return repeat_until_rset(ctx, io, ops);
                }
            }
        }
    }
}

/// Error recovery loop: discard commands until QUIT, EOF, or RSET.
///
/// Corresponds to the C `repeat_until_rset` label at smtp_in.c:820–830.
/// After a protocol violation during BDAT processing, the server must
/// reject all commands except QUIT and RSET until the client recovers.
///
/// # Returns
///
/// - [`BdatResult::Eof`] — QUIT or EOF received.
/// - [`BdatResult::Err`] — RSET received (transaction reset).
fn repeat_until_rset(
    ctx: &mut ChunkingContext,
    io: &mut SmtpIoState,
    ops: &mut dyn BdatSessionOps,
) -> BdatResult {
    loop {
        let (cmd, _) = ops.read_command(io);
        match cmd {
            SmtpCommand::Quit => {
                ops.handle_quit();
                return BdatResult::Eof;
            }
            SmtpCommand::Eof => {
                return BdatResult::Eof;
            }
            SmtpCommand::Rset => {
                ops.handle_rset();
                ctx.state = ChunkingState::Offered;
                return BdatResult::Err;
            }
            _ => {
                let exceeded = ops.report_synprot_error(503, "only RSET accepted now");
                if exceeded {
                    return BdatResult::Eof;
                }
                // Loop back and keep reading commands
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// bdat_hasc — check for data availability (smtp_in.c:883-889)
// ─────────────────────────────────────────────────────────────────────────────

/// Check whether BDAT chunk data is available for immediate reading.
///
/// If `data_left > 0`, delegates to the lower-level `hasc` function
/// via the saved [`ReceiveFunctions`]. Otherwise returns `true` to
/// trigger a BDAT command read on the next [`bdat_getc()`] call.
///
/// # Arguments
///
/// * `ctx` — Reference to the session's CHUNKING state.
/// * `io` — Reference to the SMTP I/O state (passed to lower `hasc`).
///
/// # Source Reference
///
/// `smtp_in.c` lines 883–889.
pub fn bdat_hasc(ctx: &ChunkingContext, io: &SmtpIoState) -> bool {
    if ctx.data_left > 0 {
        if let Some(lower) = ctx.lower() {
            return (lower.hasc)(io);
        }
    }
    // No data left in the current chunk — return true so the caller
    // invokes bdat_getc() which will handle inter-chunk processing.
    true
}

// ─────────────────────────────────────────────────────────────────────────────
// bdat_getbuf — buffered read within a BDAT chunk (smtp_in.c:891-903)
// ─────────────────────────────────────────────────────────────────────────────

/// Read a buffer of bytes from the current BDAT chunk.
///
/// This is the bulk-read counterpart of [`bdat_getc()`], used for
/// efficient reading of large data segments. The returned slice is
/// clamped to the remaining chunk bytes.
///
/// # Arguments
///
/// * `ctx` — Mutable reference to the session's CHUNKING state.
/// * `io` — Mutable reference to the SMTP I/O state.
/// * `len` — On input: maximum bytes desired. On output: actual bytes read.
///
/// # Returns
///
/// `Some(slice)` containing the read data, or `None` if no data is
/// available (chunk exhausted or underlying I/O error).
///
/// # Source Reference
///
/// `smtp_in.c` lines 891–903.
pub fn bdat_getbuf<'a>(
    ctx: &mut ChunkingContext,
    io: &'a mut SmtpIoState,
    len: &mut u32,
) -> Option<&'a [u8]> {
    // (smtp_in.c:893-897) — No data remaining
    if ctx.data_left == 0 {
        *len = 0;
        return None;
    }

    // Clamp requested length to remaining chunk bytes
    if *len > ctx.data_left {
        *len = ctx.data_left;
    }

    // Read from the lower-level I/O layer
    let getbuf_fn = ctx
        .lower_receive
        .as_ref()
        .expect("lower receive functions not pushed during bdat_getbuf")
        .getbuf;

    if !getbuf_fn(io, len) {
        return None;
    }

    // Reconstruct the slice from SmtpIoState buffer positions.
    // After the lower getbuf call, the data resides at
    // io.inbuffer[inptr - *len .. inptr] because inptr was advanced
    // by *len bytes.
    let end = io.inptr;
    let actual = *len as usize;
    let start = end.saturating_sub(actual);

    ctx.data_left -= *len;

    Some(&io.inbuffer[start..end])
}

// ─────────────────────────────────────────────────────────────────────────────
// bdat_ungetc — push a byte back into the BDAT stream (smtp_in.c:964-970)
// ─────────────────────────────────────────────────────────────────────────────

/// Push a byte back into the BDAT chunk stream.
///
/// Increments `data_left` and delegates to the lower-level `ungetc`.
/// If the lower functions were previously popped (e.g., at a chunk
/// boundary), they are re-pushed with the default SMTP functions.
///
/// # Arguments
///
/// * `ctx` — Mutable reference to the session's CHUNKING state.
/// * `io` — Mutable reference to the SMTP I/O state.
/// * `ch` — The byte to push back.
///
/// # Returns
///
/// The pushed-back byte value as `i32`.
///
/// # Source Reference
///
/// `smtp_in.c` lines 964–970.
pub fn bdat_ungetc(ctx: &mut ChunkingContext, io: &mut SmtpIoState, ch: i32) -> i32 {
    ctx.data_left += 1;

    // Ensure lower functions are pushed.
    // (smtp_in.c:968 — "not done yet, calling push is safe")
    // If already pushed, push is a no-op (double-push guard).
    // If popped, re-establish with default SMTP functions.
    if ctx.lower_receive.is_none() {
        bdat_push_receive_functions(ctx, ReceiveFunctions::default_smtp());
    }

    let lower_ungetc = ctx
        .lower_receive
        .as_ref()
        .expect("lower receive functions not set after push in bdat_ungetc")
        .ungetc;

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let byte = ch as u8;
    lower_ungetc(io, byte) as i32
}

// ─────────────────────────────────────────────────────────────────────────────
// bdat_flush_data — discard remaining chunk data (smtp_in.c:905-918)
// ─────────────────────────────────────────────────────────────────────────────

/// Discard any remaining data in the current BDAT chunk.
///
/// Reads and discards all remaining bytes via [`bdat_getbuf()`], then
/// pops the receive functions and resets the chunking state to
/// [`ChunkingState::Offered`].
///
/// This function is called when the server needs to discard the rest
/// of a BDAT chunk, e.g., after an ACL rejection or protocol error.
///
/// # Source Reference
///
/// `smtp_in.c` lines 905–918.
pub fn bdat_flush_data(ctx: &mut ChunkingContext, io: &mut SmtpIoState) {
    // Read and discard remaining chunk bytes
    while ctx.data_left > 0 {
        let mut n = ctx.data_left;
        if bdat_getbuf(ctx, io, &mut n).is_none() {
            break;
        }
    }

    // Pop receive functions and reset state
    bdat_pop_receive_functions(ctx);
    ctx.state = ChunkingState::Offered;
    debug!("bdat_flush_data: chunking state '{}'", ctx.state);
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Parse the arguments of a BDAT command.
///
/// Expected format: `"<size>[ LAST]"` where `<size>` is a decimal
/// integer and the optional `LAST` keyword (case-insensitive) indicates
/// the final chunk.
///
/// # Returns
///
/// `(Some(size), is_last)` on success, `(None, false)` if the size
/// is missing or unparseable.
fn parse_bdat_args(args: &str) -> (Option<u32>, bool) {
    let trimmed = args.trim();
    if trimmed.is_empty() {
        return (None, false);
    }

    // Split on whitespace to separate size from optional LAST keyword
    let mut parts = trimmed.split_whitespace();
    let size_str = match parts.next() {
        Some(s) => s,
        None => return (None, false),
    };

    let size: u32 = match size_str.parse() {
        Ok(s) => s,
        Err(_) => return (None, false),
    };

    let is_last = parts
        .next()
        .map(|kw| kw.eq_ignore_ascii_case("LAST"))
        .unwrap_or(false);

    (Some(size), is_last)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunking_state_display() {
        assert_eq!(format!("{}", ChunkingState::NotOffered), "not-offered");
        assert_eq!(format!("{}", ChunkingState::Offered), "offered");
        assert_eq!(format!("{}", ChunkingState::Active), "active");
        assert_eq!(format!("{}", ChunkingState::Last), "last");
    }

    #[test]
    fn chunking_context_new_offered() {
        let ctx = ChunkingContext::new(true);
        assert_eq!(ctx.state, ChunkingState::Offered);
        assert_eq!(ctx.data_left, 0);
        assert_eq!(ctx.datasize, 0);
        assert!(ctx.lower_receive.is_none());
    }

    #[test]
    fn chunking_context_new_not_offered() {
        let ctx = ChunkingContext::new(false);
        assert_eq!(ctx.state, ChunkingState::NotOffered);
    }

    #[test]
    fn parse_bdat_args_size_only() {
        let (size, is_last) = parse_bdat_args("1024");
        assert_eq!(size, Some(1024));
        assert!(!is_last);
    }

    #[test]
    fn parse_bdat_args_size_and_last() {
        let (size, is_last) = parse_bdat_args("512 LAST");
        assert_eq!(size, Some(512));
        assert!(is_last);
    }

    #[test]
    fn parse_bdat_args_last_case_insensitive() {
        let (size, is_last) = parse_bdat_args("256 last");
        assert_eq!(size, Some(256));
        assert!(is_last);
    }

    #[test]
    fn parse_bdat_args_empty() {
        let (size, is_last) = parse_bdat_args("");
        assert!(size.is_none());
        assert!(!is_last);
    }

    #[test]
    fn parse_bdat_args_invalid_size() {
        let (size, is_last) = parse_bdat_args("abc");
        assert!(size.is_none());
        assert!(!is_last);
    }

    #[test]
    fn parse_bdat_args_zero() {
        let (size, is_last) = parse_bdat_args("0 LAST");
        assert_eq!(size, Some(0));
        assert!(is_last);
    }

    #[test]
    fn push_pop_receive_functions() {
        let mut ctx = ChunkingContext::new(true);
        assert!(ctx.lower_receive.is_none());

        bdat_push_receive_functions(&mut ctx, ReceiveFunctions::default_smtp());
        assert!(ctx.lower_receive.is_some());

        bdat_pop_receive_functions(&mut ctx);
        assert!(ctx.lower_receive.is_none());
    }

    #[test]
    fn double_push_is_noop() {
        let mut ctx = ChunkingContext::new(true);
        bdat_push_receive_functions(&mut ctx, ReceiveFunctions::default_smtp());
        // Second push should be a no-op (warning logged)
        bdat_push_receive_functions(&mut ctx, ReceiveFunctions::default_smtp());
        // Still only one level pushed
        assert!(ctx.lower_receive.is_some());
    }

    #[test]
    fn double_pop_is_noop() {
        let mut ctx = ChunkingContext::new(true);
        // Pop without a push — should warn but not panic
        bdat_pop_receive_functions(&mut ctx);
        assert!(ctx.lower_receive.is_none());
    }

    #[test]
    fn bdat_result_display() {
        let byte_result = BdatResult::Byte(Tainted::new(0x41));
        assert_eq!(format!("{}", byte_result), "Byte(0x41)");
        assert_eq!(format!("{}", BdatResult::Eod), "EOD");
        assert_eq!(format!("{}", BdatResult::Err), "ERR");
        assert_eq!(format!("{}", BdatResult::Eof), "EOF");
    }

    #[test]
    fn bdat_result_into_byte() {
        // Verify Tainted::into_inner() path
        let result = BdatResult::Byte(Tainted::new(0x42));
        assert_eq!(result.into_byte(), Some(0x42));

        assert_eq!(BdatResult::Eod.into_byte(), None);
        assert_eq!(BdatResult::Err.into_byte(), None);
        assert_eq!(BdatResult::Eof.into_byte(), None);
    }

    #[test]
    fn bdat_result_predicates() {
        let byte = BdatResult::Byte(Tainted::new(0x00));
        assert!(byte.is_byte());
        assert!(!byte.is_eod());

        assert!(!BdatResult::Eod.is_byte());
        assert!(BdatResult::Eod.is_eod());
        assert!(!BdatResult::Err.is_byte());
        assert!(!BdatResult::Eof.is_eod());
    }

    #[test]
    fn parse_bdat_args_whitespace_padding() {
        let (size, is_last) = parse_bdat_args("  1024  LAST  ");
        assert_eq!(size, Some(1024));
        assert!(is_last);
    }

    #[test]
    fn parse_bdat_args_non_last_keyword() {
        // Non-LAST keyword after size should be false
        let (size, is_last) = parse_bdat_args("1024 NOTLAST");
        assert_eq!(size, Some(1024));
        assert!(!is_last);
    }

    #[test]
    fn receive_functions_default_smtp() {
        // Verify default_smtp() returns valid function pointers
        let fns = ReceiveFunctions::default_smtp();
        // Just ensure the function pointers are set (not null)
        // We can't easily test the fn pointers without real I/O state,
        // but we verify the struct constructs without panic
        let _ = fns.getc;
        let _ = fns.getbuf;
        let _ = fns.hasc;
        let _ = fns.ungetc;
    }

    #[test]
    fn chunking_context_lower_access() {
        let mut ctx = ChunkingContext::new(true);
        assert!(ctx.lower().is_none());

        bdat_push_receive_functions(&mut ctx, ReceiveFunctions::default_smtp());
        assert!(ctx.lower().is_some());

        bdat_pop_receive_functions(&mut ctx);
        assert!(ctx.lower().is_none());
    }

    #[test]
    fn bdat_hasc_no_data_returns_true() {
        // When data_left == 0, bdat_hasc should return true
        // to trigger a BDAT command read.
        // Use dummy fd values (-1) since we won't do actual I/O.
        let ctx = ChunkingContext::new(true);
        let io = SmtpIoState::new(-1, -1);
        assert!(bdat_hasc(&ctx, &io));
    }

    #[test]
    fn bdat_getbuf_no_data_returns_none() {
        let mut ctx = ChunkingContext::new(true);
        ctx.data_left = 0;
        let mut io = SmtpIoState::new(-1, -1);
        let mut len = 1024;
        assert!(bdat_getbuf(&mut ctx, &mut io, &mut len).is_none());
        assert_eq!(len, 0);
    }

    #[test]
    fn chunking_state_all_variants() {
        // Ensure all variants are distinct
        let states = [
            ChunkingState::NotOffered,
            ChunkingState::Offered,
            ChunkingState::Active,
            ChunkingState::Last,
        ];
        for i in 0..states.len() {
            for j in (i + 1)..states.len() {
                assert_ne!(states[i], states[j]);
            }
        }
    }
}
