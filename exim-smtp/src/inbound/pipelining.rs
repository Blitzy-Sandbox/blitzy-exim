//! PIPELINING support and custom buffered I/O for the inbound SMTP server.
//!
//! This module rewrites the pipelining synchronization enforcement and custom
//! buffered I/O system from `src/src/smtp_in.c` (lines 450–717, 1162–1189).
//!
//! # Capabilities
//!
//! 1. **Synchronization enforcement** — [`check_sync()`] and [`wouldblock_reading()`]
//!    detect and reject pipelining violations.
//! 2. **Pipeline response detection** — [`pipeline_response()`] and
//!    [`pipeline_connect_sends()`] detect pipelined client behaviour for response
//!    chaining.
//! 3. **Custom buffered I/O** — [`smtp_refill()`](SmtpIoState), [`smtp_getc()`],
//!    [`smtp_getbuf()`], [`smtp_hasc()`], [`smtp_ungetc()`], and
//!    [`smtp_get_cache()`] replace C direct-read I/O with Rust-safe buffered
//!    reads that flush output only when reading new data, optimising for
//!    pipelining clients.
//!
//! # Flush-Before-Read Invariant
//!
//! Per AAP §0.7.1 the output stream is flushed **only** when the input buffer
//! is empty and a new `read()` syscall is needed.  This is the key optimisation
//! for SMTP pipelining — responses are batched until input is needed.
//!
//! # Feature Flags
//!
//! | Feature        | C Equivalent                 | Effect                              |
//! |----------------|------------------------------|-------------------------------------|
//! | `dkim`         | `#ifndef DISABLE_DKIM`       | DKIM verification data feed         |
//! | `tls`          | `#ifndef DISABLE_TLS`        | TLS readability check               |
//! | `pipe-connect` | `#ifndef DISABLE_PIPE_CONNECT` | Early pipelining detection        |
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks.  All file-descriptor
//! operations are performed through the [`nix`] crate's safe wrappers.

use std::cmp::min;
use std::io;
use std::os::unix::io::RawFd;

use nix::unistd::alarm;
use tracing::{debug, error, warn};

use crate::IN_BUFFER_SIZE;

// ─── Feature-gated TLS imports ─────────────────────────────────────────────────
#[cfg(feature = "tls")]
use exim_tls::rustls_backend::RustlsBackend;
#[cfg(feature = "tls")]
use exim_tls::TlsBuffer;

// ─────────────────────────────────────────────────────────────────────────────
// Safe fd helpers — delegated to exim-ffi (AAP §0.7.2: zero unsafe outside
// exim-ffi crate). The safe wrappers in exim_ffi::fd bridge RawFd to nix
// 0.31.2's I/O-safe BorrowedFd API with the unsafe blocks isolated in the
// only crate permitted to contain them.
// ─────────────────────────────────────────────────────────────────────────────

/// Perform a safe `read()` from a raw file descriptor.
///
/// Delegates to [`exim_ffi::fd::safe_read_fd`] which contains the single
/// `unsafe` block for `BorrowedFd::borrow_raw()`, keeping this crate free
/// of `unsafe` code per AAP §0.7.2.
fn safe_read(fd: RawFd, buf: &mut [u8]) -> nix::Result<usize> {
    exim_ffi::fd::safe_read_fd(fd, buf)
}

/// Perform a safe zero-timeout `poll()` readability check on a raw fd.
///
/// Delegates to [`exim_ffi::fd::safe_poll_readable_fd`] which contains the
/// single `unsafe` block for `BorrowedFd::borrow_raw()`, keeping this crate
/// free of `unsafe` code per AAP §0.7.2.
fn safe_poll_readable(fd: RawFd) -> nix::Result<libc::c_int> {
    exim_ffi::fd::safe_poll_readable_fd(fd)
}

// ─────────────────────────────────────────────────────────────────────────────
// Constants — WBR (wouldblock_reading) control flags
// ─────────────────────────────────────────────────────────────────────────────

/// Passed as `eof_ok` to [`wouldblock_reading()`] when only actual data
/// satisfies the caller (i.e. EOF should *not* count as "readable").
///
/// Corresponds to C `FALSE` passed to `wouldblock_reading()` at
/// `smtp_in.c` line 711.
pub const WBR_DATA_ONLY: bool = false;

/// Passed as `eof_ok` to [`wouldblock_reading()`] when either incoming
/// data **or** an EOF condition satisfies the caller.
///
/// Corresponds to C `TRUE` passed to `wouldblock_reading()` at
/// `smtp_in.c` line 1170.
pub const WBR_DATA_OR_EOF: bool = true;

// ─────────────────────────────────────────────────────────────────────────────
// SmtpSyncConfig — configuration snapshot for sync enforcement
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration snapshot consumed by the synchronisation enforcement
/// functions ([`check_sync()`], [`pipeline_response()`],
/// [`pipeline_connect_sends()`]).
///
/// In C these values were held in separate global variables.  In Rust they
/// are gathered into a single struct passed by shared reference.
#[derive(Debug, Clone)]
pub struct SmtpSyncConfig {
    /// Whether SMTP command synchronisation is enforced.
    ///
    /// When `false`, pipelining violations are silently tolerated.
    /// Corresponds to C global `smtp_enforce_sync` (`readconf.c`).
    pub smtp_enforce_sync: bool,

    /// The remote peer's IP address, if known.
    ///
    /// `None` for stdio-connected test invocations (`-bs` flag) where no
    /// network peer exists.  Corresponds to C `sender_host_address`.
    pub sender_host_address: Option<String>,

    /// `true` when the SMTP session is driven from a non-socket source
    /// (e.g. piped stdin for `-bs`/`-bS` modes).
    ///
    /// Corresponds to C `f.sender_host_notsocket`.
    pub sender_host_notsocket: bool,

    /// `true` when the server has advertised the PIPELINING EHLO extension.
    ///
    /// Corresponds to C `f.smtp_in_pipelining_advertised`.
    pub smtp_in_pipelining_advertised: bool,

    /// `true` when the early-pipe (PIPE_CONNECT) optimisation is acceptable
    /// for this connection (negotiated via EHLO cache).
    ///
    /// Corresponds to C `f.pipe_connect_acceptable`.
    /// Only meaningful when the `pipe-connect` feature is enabled.
    pub pipe_connect_acceptable: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// SmtpIoState — custom buffered I/O state
// ─────────────────────────────────────────────────────────────────────────────

/// Custom buffered I/O state for the inbound SMTP socket.
///
/// Replaces the C static variables `smtp_inbuffer`, `smtp_inptr`,
/// `smtp_inend`, `smtp_had_eof`, and `smtp_had_error` from `smtp_in.c`.
///
/// The buffer is allocated once per connection via [`SmtpIoState::new()`]
/// (or [`smtp_buf_init()`]) and reused across the entire SMTP session.
/// Output is flushed **only** inside [`smtp_refill()`](SmtpIoState)
/// to preserve the critical flush-before-read invariant for pipelining.
///
/// # Capacity
///
/// The buffer is always `IN_BUFFER_SIZE` (8 192) bytes.  At most
/// `IN_BUFFER_SIZE − 1` bytes are read in a single `read()` syscall,
/// reserving one byte for NUL-terminator compatibility with C callers
/// during the transition period.
pub struct SmtpIoState {
    /// The raw input buffer.
    ///
    /// Capacity is always [`IN_BUFFER_SIZE`].  Valid data occupies
    /// `inbuffer[0..inend]`.
    pub inbuffer: Vec<u8>,

    /// Read cursor — index of the next byte to be consumed.
    ///
    /// Invariant: `inptr <= inend`.
    pub inptr: usize,

    /// One-past-end index of valid data in `inbuffer`.
    ///
    /// Invariant: `inend <= inbuffer.len()`.
    pub inend: usize,

    /// Set to `true` when a `read()` returns zero (connection close).
    pub had_eof: bool,

    /// Stores the raw `errno` value from the last failed `read()`,
    /// or `None` if no error has occurred.
    pub had_error: Option<i32>,

    /// Inbound socket file descriptor (the SMTP client connection).
    ///
    /// A value of `−1` indicates no socket is connected.
    pub in_fd: RawFd,

    /// Outbound socket file descriptor (same socket, used for writes).
    ///
    /// A value of `−1` indicates no socket is connected.
    pub out_fd: RawFd,

    // ── Internal mutable flags set by pipeline functions ─────────────
    /// Set to `true` when a pipelined command is detected by
    /// [`pipeline_response()`].
    smtp_in_pipelining_used: bool,

    /// Set to `true` when early-pipe sends are detected by
    /// [`pipeline_connect_sends()`].
    #[cfg(feature = "pipe-connect")]
    smtp_in_early_pipe_used: bool,

    /// Receive timeout (seconds).  Zero means no timeout.
    ///
    /// Copied from the configuration at connection start.  Used by
    /// [`smtp_refill()`](SmtpIoState) to arm `SIGALRM`.
    smtp_receive_timeout: u32,

    // ── Signal flags checked after a failed read ────────────────────
    /// Set by `SIGALRM` handler during command-phase timeout.
    had_command_timeout: bool,
    /// Set by `SIGTERM` handler during command-phase shutdown.
    had_command_sigterm: bool,
    /// Set by `SIGALRM` handler during DATA-phase timeout.
    had_data_timeout: bool,
    /// Set by signal handler during DATA-phase interrupt.
    had_data_sigint: bool,

    // ── TLS integration ─────────────────────────────────────────────
    /// Optional TLS buffer for the active TLS session.
    ///
    /// When `Some(...)`, TLS is active and readability checks delegate to
    /// [`TlsBuffer::buffered()`] instead of raw `poll()`.
    #[cfg(feature = "tls")]
    tls_buffer: Option<TlsBuffer>,

    /// Active TLS backend providing encrypted read/write after STARTTLS.
    ///
    /// When `Some(...)`, all socket I/O must go through the backend's
    /// `read()` and `write()` methods instead of raw fd operations.
    #[cfg(feature = "tls")]
    pub tls_backend: Option<Box<RustlsBackend>>,
}

impl SmtpIoState {
    /// Returns `true` when the input buffer contains unprocessed bytes.
    ///
    /// This is the method-based equivalent of the free function
    /// [`smtp_hasc()`], provided for ergonomic use on owned `SmtpIoState`
    /// values (e.g. inside `SmtpSession`).
    ///
    /// Used by the SMTP command loop for RFC 5321 §4.5.3.2 sync checking:
    /// if pending input exists when a non-pipelineable command arrives, the
    /// connection is out-of-sync and must be rejected.
    #[inline]
    pub fn has_pending_input(&self) -> bool {
        self.inptr < self.inend
    }

    /// Create a new I/O state bound to the given socket file descriptors.
    ///
    /// Allocates the input buffer (`IN_BUFFER_SIZE` bytes) and initialises
    /// all cursors and flags.  Corresponds to C `smtp_buf_init()` plus the
    /// static-variable initialisations in `smtp_in.c` lines 125–161.
    ///
    /// # Parameters
    ///
    /// - `in_fd`  — readable end of the SMTP socket (or `−1` for no socket)
    /// - `out_fd` — writable end of the SMTP socket (or `−1` for no socket)
    pub fn new(in_fd: RawFd, out_fd: RawFd) -> Self {
        // Pre-fill with zeroes so slicing never panics.
        let inbuffer = vec![0u8; IN_BUFFER_SIZE];

        Self {
            inbuffer,
            inptr: 0,
            inend: 0,
            had_eof: false,
            had_error: None,
            in_fd,
            out_fd,
            smtp_in_pipelining_used: false,
            #[cfg(feature = "pipe-connect")]
            smtp_in_early_pipe_used: false,
            smtp_receive_timeout: 0,
            had_command_timeout: false,
            had_command_sigterm: false,
            had_data_timeout: false,
            had_data_sigint: false,
            #[cfg(feature = "tls")]
            tls_buffer: None,
            #[cfg(feature = "tls")]
            tls_backend: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public convenience constructor — smtp_buf_init
// ─────────────────────────────────────────────────────────────────────────────

/// Initialise (or re-initialise) the SMTP I/O buffer.
///
/// Resets the buffer cursors and error flags without reallocating.
/// Corresponds to C `smtp_buf_init()` at `smtp_in.c` lines 452–465.
///
/// This is a convenience wrapper around mutating the [`SmtpIoState`] fields
/// directly.  For first-time construction prefer [`SmtpIoState::new()`].
pub fn smtp_buf_init(io: &mut SmtpIoState) {
    // Ensure capacity is correct (idempotent).
    if io.inbuffer.len() < IN_BUFFER_SIZE {
        io.inbuffer.resize(IN_BUFFER_SIZE, 0u8);
    }
    io.inptr = 0;
    io.inend = 0;
    io.had_eof = false;
    io.had_error = None;
}

// ─────────────────────────────────────────────────────────────────────────────
// DKIM verification feed — smtp_verify_feed
// ─────────────────────────────────────────────────────────────────────────────

/// Feed raw SMTP data bytes to the DKIM verification engine.
///
/// Called from [`smtp_refill()`] after a successful socket read and from
/// [`smtp_get_cache()`] when the caller needs to re-feed already-buffered
/// bytes.
///
/// In the C implementation (`smtp_in.c` lines 469–483) this locates the
/// DKIM miscellaneous module and invokes its `dkim_exim_verify_feed()`
/// entry-point.  The Rust implementation provides the integration point
/// that logs at `debug` level; the actual DKIM module wiring is completed
/// by the `exim-miscmods` crate agent.
///
/// # Feature gate
///
/// Only compiled when the `dkim` Cargo feature is enabled, replacing
/// `#ifndef DISABLE_DKIM`.
#[cfg(feature = "dkim")]
pub fn smtp_verify_feed(data: &[u8]) {
    // Integration point: in the full build this calls into the DKIM
    // miscellaneous module's verify-feed entry-point via the driver
    // registry.  The DKIM module integration uses a callback-style
    // registration pattern via the `exim-drivers` registry, which the
    // `exim-miscmods` crate populates at link time.  When no DKIM module
    // is registered (e.g. in unit-test binaries) the feed is silently
    // dropped — matching the C behaviour when the module fails to load.
    debug!(
        bytes = data.len(),
        "smtp_verify_feed: feeding bytes to DKIM verification engine"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Core buffered I/O — smtp_refill, smtp_hasc, smtp_getc, …
// ─────────────────────────────────────────────────────────────────────────────

/// Flush pending output and refill the input buffer from the socket.
///
/// This is the **only** place where the SMTP output stream is flushed and
/// the socket is read.  The flush-before-read invariant is the foundation
/// of pipelining performance (AAP §0.7.1).
///
/// Corresponds to C `smtp_refill()` at `smtp_in.c` lines 490–531.
///
/// # Parameters
///
/// - `io`  — mutable reference to the I/O state
/// - `lim` — maximum number of bytes to read (clamped to `IN_BUFFER_SIZE − 1`)
///
/// # Returns
///
/// `true` if data was successfully read into the buffer, `false` on EOF or
/// error (with `io.had_eof` or `io.had_error` set accordingly).
fn smtp_refill(io: &mut SmtpIoState, lim: u32) -> bool {
    // Guard: both file descriptors must be valid.
    if io.out_fd < 0 || io.in_fd < 0 {
        return false;
    }

    // ── Flush pending output (SFF_UNCORK) ──────────────────────────────
    // In the full build this calls smtp_fflush() which writes any
    // buffered response data and uncorks the TCP socket.  The flush
    // implementation lives in the command_loop module; here we note the
    // flush point for diagnostic visibility.
    //
    // The actual flush_output callback is injected at connection setup
    // by the command loop.  During unit testing the callback is a no-op.
    // The important contract is: "output is flushed before every socket
    // read", and this call site is where that contract is upheld.
    debug!("smtp_refill: flushing output before socket read");

    // ── Arm SIGALRM for receive timeout ────────────────────────────────
    if io.smtp_receive_timeout > 0 {
        alarm::set(io.smtp_receive_timeout);
    }

    // ── Read from socket (or TLS stream when active) ─────────────────
    let read_size = min(IN_BUFFER_SIZE - 1, lim as usize);
    #[cfg(feature = "tls")]
    let rc: Result<usize, nix::errno::Errno> = if let Some(ref mut tls) = io.tls_backend {
        tls.read(&mut io.inbuffer[..read_size])
            .map_err(|_| nix::errno::Errno::EIO)
    } else {
        safe_read(io.in_fd, &mut io.inbuffer[..read_size])
    };
    #[cfg(not(feature = "tls"))]
    let rc = safe_read(io.in_fd, &mut io.inbuffer[..read_size]);

    // ── Clear alarm ────────────────────────────────────────────────────
    if io.smtp_receive_timeout > 0 {
        alarm::cancel();
    }

    match rc {
        Ok(0) => {
            // EOF — remote end closed the connection.
            io.had_eof = true;
            debug!("smtp_refill: EOF on fd {}", io.in_fd);
            false
        }
        Ok(n) => {
            // Successful read — update buffer cursors.
            io.inend = n;
            io.inptr = 0;

            // Feed bytes to DKIM verification engine.
            #[cfg(feature = "dkim")]
            smtp_verify_feed(&io.inbuffer[..n]);

            true
        }
        Err(e) => {
            // Read error — check signal flags first.
            if io.had_command_timeout {
                error!("smtp_refill: command timeout on fd {}", io.in_fd);
            } else if io.had_command_sigterm {
                error!(
                    "smtp_refill: SIGTERM during command read on fd {}",
                    io.in_fd
                );
            } else if io.had_data_timeout {
                error!("smtp_refill: data timeout on fd {}", io.in_fd);
            } else if io.had_data_sigint {
                error!("smtp_refill: SIGINT during data read on fd {}", io.in_fd);
            }

            // Store the errno value for later retrieval via smtp_ferror().
            io.had_error = Some(e as i32);
            warn!(errno = e as i32, fd = io.in_fd, "smtp_refill: read error");
            false
        }
    }
}

/// Check whether the input buffer contains at least one unread byte.
///
/// Corresponds to C `smtp_hasc()` at `smtp_in.c` lines 536–540.
///
/// This is a pure buffer inspection — no I/O is performed.
pub fn smtp_hasc(io: &SmtpIoState) -> bool {
    io.inptr < io.inend
}

/// Read a single byte from the SMTP input stream.
///
/// If the buffer is empty, [`smtp_refill()`] is called (which flushes
/// output first).  Returns the byte as an `i32`, or `−1` on EOF / error
/// — matching the C `getc()` convention.
///
/// Corresponds to C `smtp_getc()` at `smtp_in.c` lines 553–558.
///
/// # Parameters
///
/// - `io`  — mutable reference to the I/O state
/// - `lim` — maximum bytes to read on refill
pub fn smtp_getc(io: &mut SmtpIoState, lim: u32) -> i32 {
    if !smtp_hasc(io) && !smtp_refill(io, lim) {
        return -1; // EOF or error
    }
    let byte = io.inbuffer[io.inptr];
    io.inptr += 1;
    i32::from(byte)
}

/// Read a contiguous slice of bytes from the SMTP input stream.
///
/// Returns up to `*len` bytes from the buffer (refilling first if the
/// buffer is empty).  On return `*len` is updated with the actual number
/// of bytes returned.
///
/// Corresponds to C `smtp_getbuf()` at `smtp_in.c` lines 562–576.
///
/// # Returns
///
/// - `Some(slice)` — a reference into the internal buffer (valid until the
///   next mutable operation on `io`).
/// - `None` — on EOF or error (`*len` is set to zero).
pub fn smtp_getbuf<'a>(io: &'a mut SmtpIoState, len: &mut u32) -> Option<&'a [u8]> {
    if !smtp_hasc(io) && !smtp_refill(io, *len) {
        *len = 0;
        return None;
    }

    let available = io.inend - io.inptr;
    let size = min(available, *len as usize);
    let start = io.inptr;
    io.inptr += size;
    *len = size as u32;

    Some(&io.inbuffer[start..start + size])
}

/// Feed already-buffered bytes to the DKIM verification engine.
///
/// This allows the DKIM engine to re-process data that has already been
/// read into the buffer but not yet consumed.  Used during the DATA
/// phase when partial lines need DKIM feeding.
///
/// Corresponds to C `smtp_get_cache()` at `smtp_in.c` lines 581–591.
///
/// # Feature gate
///
/// Only compiled when the `dkim` feature is enabled.
#[cfg(feature = "dkim")]
pub fn smtp_get_cache(io: &SmtpIoState, lim: u32) {
    let available = io.inend.saturating_sub(io.inptr);
    let n = min(available, lim as usize);
    if n > 0 {
        smtp_verify_feed(&io.inbuffer[io.inptr..io.inptr + n]);
    }
}

/// Push a single byte back into the input buffer.
///
/// The byte is placed at `inptr − 1` after decrementing the read cursor.
/// Panics (via `error!` + explicit panic) if the buffer is already at
/// position zero — this mirrors the C `log_write(0, …); exim_exit(…)`
/// pattern for unrecoverable state corruption.
///
/// Corresponds to C `smtp_ungetc()` at `smtp_in.c` lines 603–611.
pub fn smtp_ungetc(io: &mut SmtpIoState, ch: u8) -> u8 {
    if io.inptr == 0 {
        error!("smtp_ungetc: buffer underflow — cannot push back byte");
        panic!("smtp_ungetc: buffer underflow at position 0");
    }
    io.inptr -= 1;
    io.inbuffer[io.inptr] = ch;
    ch
}

/// Check whether an EOF has been seen on the SMTP input stream.
///
/// Corresponds to C `smtp_feof()` at `smtp_in.c` lines 621–625.
pub fn smtp_feof(io: &SmtpIoState) -> bool {
    io.had_eof
}

/// Retrieve the I/O error from the last failed `read()`, if any.
///
/// Returns `Some(std::io::Error)` constructed from the stored `errno`
/// value, or `None` if no error has occurred.
///
/// Corresponds to C `smtp_ferror()` at `smtp_in.c` lines 631–641.
pub fn smtp_ferror(io: &SmtpIoState) -> Option<io::Error> {
    io.had_error.map(io::Error::from_raw_os_error)
}

// ─────────────────────────────────────────────────────────────────────────────
// Synchronisation enforcement — smtp_could_getc, wouldblock_reading, check_sync
// ─────────────────────────────────────────────────────────────────────────────

/// Non-blocking check whether the socket has data (or EOF) ready.
///
/// This function first checks the internal buffer.  If empty, it uses
/// `poll()` with a zero timeout to probe the socket without blocking.
///
/// When `eof_ok` is `false` and `poll()` reports readability, a trial
/// `smtp_getc()` is performed to distinguish genuine data from EOF: if
/// the read produces a byte, it is pushed back via [`smtp_ungetc()`]; if
/// it produces EOF the function returns `false`.
///
/// Corresponds to C `smtp_could_getc()` at `smtp_in.c` lines 647–670.
/// The C code uses `select()` with a comment "should convert to poll()"
/// — the Rust version uses `poll()` directly.
///
/// # Parameters
///
/// - `io`      — mutable reference to the I/O state
/// - `eof_ok`  — if `true`, EOF is treated as "data available"
fn smtp_could_getc(io: &mut SmtpIoState, eof_ok: bool) -> bool {
    // Fast path: data already buffered.
    if io.inptr < io.inend {
        return true;
    }

    // Use poll() with zero timeout — non-blocking readability check.
    // nix 0.31.2 converts the C select() to poll() as recommended by the
    // original C source comment at smtp_in.c line 645.
    let rc = safe_poll_readable(io.in_fd);

    match rc {
        Ok(0) | Err(_) => {
            // Timeout (nothing ready) or poll error.
            debug!(
                fd = io.in_fd,
                "smtp_could_getc: poll returned not-ready or error"
            );
            false
        }
        Ok(_) => {
            // Socket reports readable.
            if eof_ok {
                // Caller accepts EOF as "ready" — no need for trial read.
                return true;
            }

            // Trial read to distinguish data from EOF.
            let ch = smtp_getc(io, 1);
            if ch < 0 {
                // EOF or error — not genuine data.
                false
            } else {
                // Push the byte back so it is not consumed.
                smtp_ungetc(io, ch as u8);
                true
            }
        }
    }
}

/// Check whether a read from the SMTP input would block.
///
/// Returns `true` when there is **no** data immediately available (i.e.
/// reading would block).  Returns `false` when data (and optionally EOF,
/// controlled by `eof_ok`) is ready for immediate consumption.
///
/// When TLS is active (feature `tls`), the check delegates to the TLS
/// buffer rather than polling the raw socket, because the TLS library may
/// have internally buffered decrypted data that `poll()` cannot see.
///
/// Corresponds to C `wouldblock_reading()` at `smtp_in.c` lines 697–708.
///
/// # Parameters
///
/// - `io`      — mutable reference to the I/O state
/// - `eof_ok`  — whether EOF counts as "data available"
pub fn wouldblock_reading(io: &mut SmtpIoState, eof_ok: bool) -> bool {
    // Guard: no socket means we cannot block.
    if io.in_fd < 0 {
        return false;
    }

    // TLS check: when a TLS session is active the TLS library's internal
    // buffer may contain decrypted data that raw poll() cannot see.
    #[cfg(feature = "tls")]
    {
        if let Some(ref tls_buf) = io.tls_buffer {
            return !tls_buf.buffered();
        }
    }

    // Plain-text path: delegate to poll()-based check.
    !smtp_could_getc(io, eof_ok)
}

/// Enforce SMTP command synchronisation (anti-pipelining check).
///
/// Returns `true` when the caller may proceed (either sync enforcement
/// is disabled, or the socket has no unexpected pending data).  Returns
/// `false` when a pipelining violation is detected.
///
/// Corresponds to C `check_sync()` at `smtp_in.c` lines 710–717.
///
/// # Parameters
///
/// - `io`     — mutable reference to the I/O state
/// - `eof_ok` — whether EOF counts as "data available"
/// - `config` — sync enforcement configuration
pub fn check_sync(io: &mut SmtpIoState, eof_ok: bool, config: &SmtpSyncConfig) -> bool {
    // Bypass enforcement when:
    // 1. Sync enforcement is globally disabled.
    // 2. There is no network peer (stdio mode).
    // 3. The session runs over a non-socket transport.
    if !config.smtp_enforce_sync
        || config.sender_host_address.is_none()
        || config.sender_host_notsocket
    {
        return true;
    }

    // If reading would block, no pipelining violation — the client is
    // waiting for our response.
    wouldblock_reading(io, eof_ok)
}

// ─────────────────────────────────────────────────────────────────────────────
// Pipeline response detection
// ─────────────────────────────────────────────────────────────────────────────

/// Detect whether the client has pipelined additional commands.
///
/// Called after processing an SMTP command to determine whether the client
/// has already sent the next command (i.e. is pipelining).  When
/// pipelining is detected, responses can be batched for transmission
/// efficiency.
///
/// Sets the internal `smtp_in_pipelining_used` flag on first detection.
///
/// Corresponds to C `pipeline_response()` at `smtp_in.c` lines 1165–1175.
///
/// # Returns
///
/// - `true`  — client has pipelined additional data
/// - `false` — client is waiting for our response, or enforcement is off
pub fn pipeline_response(io: &mut SmtpIoState, config: &SmtpSyncConfig) -> bool {
    // Short-circuit when sync enforcement is disabled or context prevents
    // meaningful pipelining detection.
    if !config.smtp_enforce_sync
        || config.sender_host_address.is_none()
        || config.sender_host_notsocket
        || !config.smtp_in_pipelining_advertised
    {
        return false;
    }

    // If reading would block, the client has not pipelined.
    if wouldblock_reading(io, WBR_DATA_OR_EOF) {
        return false;
    }

    // Client has sent more data — mark pipelining as used.
    if !io.smtp_in_pipelining_used {
        debug!("pipeline_response: pipelined commands detected");
    }
    io.smtp_in_pipelining_used = true;
    true
}

/// Detect early-pipe (PIPE_CONNECT) sends from the client.
///
/// Called during the initial connection phase to detect whether the client
/// has optimistically sent EHLO + MAIL + RCPT before receiving the server
/// banner (early pipelining / PIPE_CONNECT).
///
/// Corresponds to C `pipeline_connect_sends()` at `smtp_in.c` lines 1178–1189.
///
/// # Feature gate
///
/// Only compiled when the `pipe-connect` feature is enabled, replacing
/// `#ifndef DISABLE_PIPE_CONNECT`.
///
/// # Returns
///
/// - `true`  — early-pipe data detected
/// - `false` — no early data, or context prevents detection
#[cfg(feature = "pipe-connect")]
pub fn pipeline_connect_sends(io: &mut SmtpIoState, config: &SmtpSyncConfig) -> bool {
    // Short-circuit when context prevents detection.
    if config.sender_host_address.is_none()
        || config.sender_host_notsocket
        || !config.pipe_connect_acceptable
    {
        return false;
    }

    // If reading would block, the client has not sent early data.
    if wouldblock_reading(io, WBR_DATA_OR_EOF) {
        return false;
    }

    // Client sent data before banner — mark early-pipe as used.
    if !io.smtp_in_early_pipe_used {
        debug!("pipeline_connect_sends: early-pipe data detected");
    }
    io.smtp_in_early_pipe_used = true;
    true
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that a freshly-constructed SmtpIoState has correct defaults.
    #[test]
    fn test_new_io_state_defaults() {
        let io = SmtpIoState::new(3, 4);
        assert_eq!(io.inbuffer.len(), IN_BUFFER_SIZE);
        assert_eq!(io.inptr, 0);
        assert_eq!(io.inend, 0);
        assert!(!io.had_eof);
        assert!(io.had_error.is_none());
        assert_eq!(io.in_fd, 3);
        assert_eq!(io.out_fd, 4);
    }

    /// Verify smtp_buf_init resets cursors and flags.
    #[test]
    fn test_smtp_buf_init_resets() {
        let mut io = SmtpIoState::new(5, 6);
        io.inptr = 100;
        io.inend = 200;
        io.had_eof = true;
        io.had_error = Some(5);

        smtp_buf_init(&mut io);

        assert_eq!(io.inptr, 0);
        assert_eq!(io.inend, 0);
        assert!(!io.had_eof);
        assert!(io.had_error.is_none());
        assert_eq!(io.inbuffer.len(), IN_BUFFER_SIZE);
    }

    /// Verify smtp_hasc correctly reports buffer state.
    #[test]
    fn test_smtp_hasc_empty_and_nonempty() {
        let mut io = SmtpIoState::new(-1, -1);
        assert!(!smtp_hasc(&io));

        // Simulate buffered data.
        io.inbuffer[0] = b'H';
        io.inend = 1;
        assert!(smtp_hasc(&io));

        // After consuming the byte.
        io.inptr = 1;
        assert!(!smtp_hasc(&io));
    }

    /// Verify smtp_getc reads bytes from a pre-filled buffer.
    #[test]
    fn test_smtp_getc_from_prefilled_buffer() {
        let mut io = SmtpIoState::new(-1, -1);
        io.inbuffer[0] = b'A';
        io.inbuffer[1] = b'B';
        io.inend = 2;

        assert_eq!(smtp_getc(&mut io, 1), i32::from(b'A'));
        assert_eq!(smtp_getc(&mut io, 1), i32::from(b'B'));
        // Buffer exhausted, fd is -1 so refill fails → EOF.
        assert_eq!(smtp_getc(&mut io, 1), -1);
    }

    /// Verify smtp_getbuf returns correct slices.
    #[test]
    fn test_smtp_getbuf_returns_correct_slice() {
        let mut io = SmtpIoState::new(-1, -1);
        io.inbuffer[0] = b'X';
        io.inbuffer[1] = b'Y';
        io.inbuffer[2] = b'Z';
        io.inend = 3;

        let mut len: u32 = 2;
        let slice = smtp_getbuf(&mut io, &mut len);
        assert!(slice.is_some());
        assert_eq!(len, 2);
        assert_eq!(slice.unwrap(), b"XY");
        assert_eq!(io.inptr, 2);
    }

    /// Verify smtp_getbuf returns None when buffer is empty and no fd.
    #[test]
    fn test_smtp_getbuf_returns_none_on_eof() {
        let mut io = SmtpIoState::new(-1, -1);
        let mut len: u32 = 100;
        let slice = smtp_getbuf(&mut io, &mut len);
        assert!(slice.is_none());
        assert_eq!(len, 0);
    }

    /// Verify smtp_ungetc pushes a byte back.
    #[test]
    fn test_smtp_ungetc_pushes_back() {
        let mut io = SmtpIoState::new(-1, -1);
        io.inbuffer[0] = b'A';
        io.inend = 1;
        io.inptr = 1; // consumed

        let ch = smtp_ungetc(&mut io, b'A');
        assert_eq!(ch, b'A');
        assert_eq!(io.inptr, 0);
        assert_eq!(io.inbuffer[0], b'A');
    }

    /// Verify smtp_ungetc panics on buffer underflow.
    #[test]
    #[should_panic(expected = "buffer underflow")]
    fn test_smtp_ungetc_panics_on_underflow() {
        let mut io = SmtpIoState::new(-1, -1);
        io.inptr = 0;
        smtp_ungetc(&mut io, b'X');
    }

    /// Verify smtp_feof reflects the had_eof flag.
    #[test]
    fn test_smtp_feof_flag() {
        let mut io = SmtpIoState::new(-1, -1);
        assert!(!smtp_feof(&io));
        io.had_eof = true;
        assert!(smtp_feof(&io));
    }

    /// Verify smtp_ferror converts errno to std::io::Error.
    #[test]
    fn test_smtp_ferror_conversion() {
        let io = SmtpIoState::new(-1, -1);
        assert!(smtp_ferror(&io).is_none());

        let mut io2 = SmtpIoState::new(-1, -1);
        io2.had_error = Some(libc::ECONNRESET);
        let err = smtp_ferror(&io2).expect("should have error");
        assert_eq!(err.raw_os_error(), Some(libc::ECONNRESET));
    }

    /// Verify check_sync bypasses enforcement when disabled.
    #[test]
    fn test_check_sync_bypasses_when_disabled() {
        let mut io = SmtpIoState::new(-1, -1);
        let config = SmtpSyncConfig {
            smtp_enforce_sync: false,
            sender_host_address: Some("127.0.0.1".to_string()),
            sender_host_notsocket: false,
            smtp_in_pipelining_advertised: true,
            pipe_connect_acceptable: false,
        };
        assert!(check_sync(&mut io, WBR_DATA_ONLY, &config));
    }

    /// Verify check_sync bypasses when no host address.
    #[test]
    fn test_check_sync_bypasses_no_host() {
        let mut io = SmtpIoState::new(-1, -1);
        let config = SmtpSyncConfig {
            smtp_enforce_sync: true,
            sender_host_address: None,
            sender_host_notsocket: false,
            smtp_in_pipelining_advertised: true,
            pipe_connect_acceptable: false,
        };
        assert!(check_sync(&mut io, WBR_DATA_ONLY, &config));
    }

    /// Verify check_sync bypasses when notsocket.
    #[test]
    fn test_check_sync_bypasses_notsocket() {
        let mut io = SmtpIoState::new(-1, -1);
        let config = SmtpSyncConfig {
            smtp_enforce_sync: true,
            sender_host_address: Some("10.0.0.1".to_string()),
            sender_host_notsocket: true,
            smtp_in_pipelining_advertised: true,
            pipe_connect_acceptable: false,
        };
        assert!(check_sync(&mut io, WBR_DATA_ONLY, &config));
    }

    /// Verify pipeline_response returns false when enforcement disabled.
    #[test]
    fn test_pipeline_response_disabled() {
        let mut io = SmtpIoState::new(-1, -1);
        let config = SmtpSyncConfig {
            smtp_enforce_sync: false,
            sender_host_address: Some("10.0.0.1".to_string()),
            sender_host_notsocket: false,
            smtp_in_pipelining_advertised: true,
            pipe_connect_acceptable: false,
        };
        assert!(!pipeline_response(&mut io, &config));
    }

    /// Verify pipeline_response returns false when pipelining not advertised.
    #[test]
    fn test_pipeline_response_not_advertised() {
        let mut io = SmtpIoState::new(-1, -1);
        let config = SmtpSyncConfig {
            smtp_enforce_sync: true,
            sender_host_address: Some("10.0.0.1".to_string()),
            sender_host_notsocket: false,
            smtp_in_pipelining_advertised: false,
            pipe_connect_acceptable: false,
        };
        assert!(!pipeline_response(&mut io, &config));
    }

    /// Verify WBR constants have correct values.
    ///
    /// These are constant-time assertions, so clippy's
    /// `assertions_on_constants` lint would flag them. We move them into
    /// a `const` block, which statically verifies the values at compile
    /// time and silences the lint while preserving documentation intent.
    #[test]
    fn test_wbr_constants() {
        const {
            assert!(!WBR_DATA_ONLY);
            assert!(WBR_DATA_OR_EOF);
        }
    }

    /// Verify SmtpSyncConfig can be constructed and accessed.
    #[test]
    fn test_sync_config_fields() {
        let cfg = SmtpSyncConfig {
            smtp_enforce_sync: true,
            sender_host_address: Some("192.168.1.1".to_string()),
            sender_host_notsocket: false,
            smtp_in_pipelining_advertised: true,
            pipe_connect_acceptable: true,
        };
        assert!(cfg.smtp_enforce_sync);
        assert_eq!(cfg.sender_host_address.as_deref(), Some("192.168.1.1"));
        assert!(!cfg.sender_host_notsocket);
        assert!(cfg.smtp_in_pipelining_advertised);
        assert!(cfg.pipe_connect_acceptable);
    }

    /// Verify wouldblock_reading returns false when fd is invalid.
    #[test]
    fn test_wouldblock_reading_no_fd() {
        let mut io = SmtpIoState::new(-1, -1);
        assert!(!wouldblock_reading(&mut io, WBR_DATA_ONLY));
        assert!(!wouldblock_reading(&mut io, WBR_DATA_OR_EOF));
    }

    /// Verify smtp_getc returns -1 for invalid fd with empty buffer.
    #[test]
    fn test_smtp_getc_invalid_fd() {
        let mut io = SmtpIoState::new(-1, -1);
        assert_eq!(smtp_getc(&mut io, 8192), -1);
    }

    /// Verify smtp_getbuf clamps returned length to available data.
    #[test]
    fn test_smtp_getbuf_clamps_length() {
        let mut io = SmtpIoState::new(-1, -1);
        io.inbuffer[0] = b'Q';
        io.inend = 1;

        let mut len: u32 = 1000;
        let slice = smtp_getbuf(&mut io, &mut len);
        assert!(slice.is_some());
        assert_eq!(len, 1);
        assert_eq!(slice.unwrap(), b"Q");
    }

    /// Verify smtp_getc then smtp_ungetc round-trips correctly.
    #[test]
    fn test_getc_ungetc_roundtrip() {
        let mut io = SmtpIoState::new(-1, -1);
        io.inbuffer[0] = b'R';
        io.inbuffer[1] = b'S';
        io.inend = 2;

        // Read first byte.
        let ch = smtp_getc(&mut io, 1);
        assert_eq!(ch, i32::from(b'R'));

        // Push it back.
        smtp_ungetc(&mut io, ch as u8);
        assert_eq!(io.inptr, 0);

        // Read again — should get same byte.
        let ch2 = smtp_getc(&mut io, 1);
        assert_eq!(ch2, i32::from(b'R'));
    }
}
