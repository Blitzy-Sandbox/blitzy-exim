//! Safe wrappers for raw file descriptor conversions.
//!
//! This module centralises the single `unsafe` operation required to convert
//! a raw POSIX file descriptor (`RawFd`) into a Rust-owned `TcpStream` (or
//! `OwnedFd`).  The `FromRawFd` trait in the standard library is `unsafe`
//! because the compiler cannot statically verify that the descriptor is valid,
//! open, and exclusively owned.
//!
//! By placing this `unsafe` block in the `exim-ffi` crate — the **ONLY** crate
//! in the workspace permitted to contain `unsafe` code (AAP §0.7.2) — all
//! consumer crates (`exim-tls`, `exim-core`, etc.) remain 100% safe Rust.
//!
//! # Caller Contract
//!
//! Every function in this module documents the preconditions that the caller
//! must uphold.  In the Exim fork-per-connection model, raw file descriptors
//! originate from `accept()` (server side) or `connect()` (delivery side) and
//! are solely owned by the forked child / delivery process — satisfying the
//! exclusive-ownership requirement of `FromRawFd`.

use std::net::TcpStream;
use std::os::unix::io::{FromRawFd, RawFd};

/// Convert a raw POSIX file descriptor into an owned `TcpStream`.
///
/// # Preconditions (caller must guarantee)
///
/// 1. `fd` is a valid, open file descriptor referring to a connected TCP socket.
/// 2. `fd` is exclusively owned by the calling code — no other code path will
///    close or read/write through this descriptor after this call.
/// 3. The `TcpStream` takes ownership: it will close `fd` when dropped.
///
/// # Usage
///
/// This function is consumed by `exim-tls` (both `rustls_backend` and
/// `openssl_backend`) to wrap the raw socket descriptor from the daemon's
/// `accept()` call into a `TcpStream` suitable for TLS handshake.
///
/// ```ignore
/// let stream = exim_ffi::fd::tcp_stream_from_raw_fd(accepted_fd);
/// // stream now owns the descriptor; dropping stream closes the socket.
/// ```
pub fn tcp_stream_from_raw_fd(fd: RawFd) -> TcpStream {
    // SAFETY: The caller guarantees that `fd` is a valid, open, exclusively-
    // owned TCP socket descriptor obtained from accept() or connect(). The
    // TcpStream takes ownership and will close the fd on drop. This is the
    // standard pattern for the Exim fork-per-connection model where each
    // forked child owns exactly one accepted socket descriptor.
    unsafe { TcpStream::from_raw_fd(fd) }
}

/// Perform a safe `read()` from a raw POSIX file descriptor.
///
/// Bridges `RawFd` to nix 0.31.2's I/O-safe API (Rust RFC 3128) which
/// requires `BorrowedFd` instead of `RawFd` for all I/O operations.
///
/// # Preconditions (caller must guarantee)
///
/// 1. `fd` is a valid, open file descriptor (e.g., from the daemon's
///    `accept()` call or a pipe created by `nix::unistd::pipe()`).
/// 2. `fd` remains open for the duration of this function call.
/// 3. `buf` is a mutable byte buffer that the kernel may write into.
///
/// # Returns
///
/// The number of bytes read, or a `nix::errno::Errno` on failure.
///
/// # Usage
///
/// This function is consumed by `exim-smtp/src/inbound/pipelining.rs` to
/// perform socket reads during SMTP pipelining I/O, replacing inline
/// `unsafe { BorrowedFd::borrow_raw(fd) }` blocks that would violate the
/// crate-level `#![forbid(unsafe_code)]` policy in consumer crates.
///
/// ```ignore
/// let n = exim_ffi::fd::safe_read_fd(smtp_fd, &mut buffer)?;
/// ```
pub fn safe_read_fd(fd: RawFd, buf: &mut [u8]) -> nix::Result<usize> {
    // SAFETY: `fd` is a valid file descriptor opened by the daemon's
    // `accept()` call or `pipe()`. It remains open for the SMTP session
    // lifetime. The `BorrowedFd` borrows the fd without closing it and
    // does not escape this function.
    let borrowed = unsafe { std::os::unix::io::BorrowedFd::borrow_raw(fd) };
    nix::unistd::read(borrowed, buf)
}

/// Perform a safe zero-timeout `poll()` readability check on a raw fd.
///
/// Returns `Ok(n)` where `n` is the number of ready fds (0 or 1), or
/// `Err` on poll failure. A return of `Ok(0)` means the fd has no
/// pending data (would block); `Ok(1)` means data is available.
///
/// # Preconditions (caller must guarantee)
///
/// 1. `fd` is a valid, open file descriptor.
/// 2. `fd` remains open for the duration of this function call.
///
/// # Usage
///
/// This function is consumed by `exim-smtp/src/inbound/pipelining.rs` to
/// check SMTP socket readability for pipelining synchronization enforcement,
/// replacing inline `unsafe { BorrowedFd::borrow_raw(fd) }` blocks.
///
/// ```ignore
/// let ready = exim_ffi::fd::safe_poll_readable_fd(smtp_fd)?;
/// if ready > 0 { /* data available */ }
/// ```
pub fn safe_poll_readable_fd(fd: RawFd) -> nix::Result<libc::c_int> {
    // SAFETY: Same as safe_read_fd — fd is valid for the session lifetime.
    // BorrowedFd borrows without closing and does not escape this scope.
    let borrowed = unsafe { std::os::unix::io::BorrowedFd::borrow_raw(fd) };
    let pfd = nix::poll::PollFd::new(borrowed, nix::poll::PollFlags::POLLIN);
    nix::poll::poll(&mut [pfd], nix::poll::PollTimeout::ZERO)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn test_tcp_stream_from_raw_fd_roundtrip() {
        // Create a real TCP listener to get a valid fd for testing.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind failed");
        let addr = listener.local_addr().expect("local_addr failed");

        // Connect to our own listener to produce a valid connected socket.
        let client = std::net::TcpStream::connect(addr).expect("connect failed");
        let fd: RawFd = {
            use std::os::unix::io::AsRawFd;
            client.as_raw_fd()
        };

        // Duplicate the fd so we can safely convert without double-close.
        let dup_fd = unsafe { libc::dup(fd) };
        assert!(dup_fd >= 0, "dup() failed");

        // Convert the duplicated fd via our safe wrapper.
        let stream = tcp_stream_from_raw_fd(dup_fd);

        // Verify the stream is functional by checking its peer address.
        // The peer address should match the client's local address or the
        // listener address — we just verify it doesn't error.
        assert!(
            stream.peer_addr().is_ok() || stream.local_addr().is_ok(),
            "converted TcpStream should be functional"
        );
        // stream drops here, closing dup_fd.
    }

    #[test]
    fn test_safe_read_fd_from_pipe() {
        // Create a pipe and write data, then read via our safe wrapper.
        let (read_fd, write_fd) = nix::unistd::pipe().expect("pipe failed");
        let msg = b"hello";
        nix::unistd::write(&write_fd, msg).expect("write failed");

        let mut buf = [0u8; 64];
        let raw_fd: RawFd = {
            use std::os::unix::io::AsRawFd;
            read_fd.as_raw_fd()
        };
        let n = safe_read_fd(raw_fd, &mut buf).expect("safe_read_fd failed");
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], b"hello");
    }

    #[test]
    fn test_safe_poll_readable_fd_no_data() {
        // Create a pipe but don't write — poll should return 0.
        let (read_fd, _write_fd) = nix::unistd::pipe().expect("pipe failed");
        let raw_fd: RawFd = {
            use std::os::unix::io::AsRawFd;
            read_fd.as_raw_fd()
        };
        let ready = safe_poll_readable_fd(raw_fd).expect("safe_poll_readable_fd failed");
        assert_eq!(ready, 0, "empty pipe should not be readable");
    }

    #[test]
    fn test_safe_poll_readable_fd_with_data() {
        // Create a pipe and write data — poll should return 1.
        let (read_fd, write_fd) = nix::unistd::pipe().expect("pipe failed");
        nix::unistd::write(&write_fd, b"data").expect("write failed");
        let raw_fd: RawFd = {
            use std::os::unix::io::AsRawFd;
            read_fd.as_raw_fd()
        };
        let ready = safe_poll_readable_fd(raw_fd).expect("safe_poll_readable_fd failed");
        assert_eq!(ready, 1, "pipe with data should be readable");
    }
}
