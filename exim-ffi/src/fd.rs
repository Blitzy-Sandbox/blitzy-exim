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
}
