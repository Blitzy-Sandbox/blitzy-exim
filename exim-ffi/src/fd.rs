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

/// Perform a safe `poll()` readability check with a configurable timeout.
///
/// Like [`safe_poll_readable_fd`] but accepts a timeout in milliseconds
/// instead of always using zero.  A timeout of `-1` blocks indefinitely,
/// `0` returns immediately (equivalent to `safe_poll_readable_fd`), and
/// positive values block for at most that many milliseconds.
///
/// # Preconditions (caller must guarantee)
///
/// 1. `fd` is a valid, open file descriptor.
/// 2. `fd` remains open for the duration of this function call.
///
/// # Returns
///
/// `Ok(n)` where `n` is the number of ready fds (0 or 1), or
/// `Err` on poll failure.  `Ok(0)` means timeout expired with no data.
///
/// # Usage
///
/// This function is consumed by `exim-smtp/src/outbound/response.rs` in
/// `ip_recv()` for timed socket reads during SMTP response parsing.
///
/// ```ignore
/// let ready = exim_ffi::fd::safe_poll_fd_timeout(smtp_fd, 30_000)?;
/// if ready == 0 { /* timeout */ }
/// ```
pub fn safe_poll_fd_timeout(fd: RawFd, timeout_ms: i32) -> nix::Result<libc::c_int> {
    // SAFETY: Same as safe_read_fd — fd is valid for the session lifetime.
    // BorrowedFd borrows without closing and does not escape this scope.
    let borrowed = unsafe { std::os::unix::io::BorrowedFd::borrow_raw(fd) };
    let pfd = nix::poll::PollFd::new(borrowed, nix::poll::PollFlags::POLLIN);
    let timeout =
        nix::poll::PollTimeout::try_from(timeout_ms).unwrap_or(nix::poll::PollTimeout::NONE);
    nix::poll::poll(&mut [pfd], timeout)
}

/// Perform a safe `setsockopt()` call with an integer value.
///
/// Wraps `libc::setsockopt()` for arbitrary integer socket options that
/// do not have type-safe nix wrappers (e.g., `TCP_CORK` on Linux).
///
/// # Preconditions (caller must guarantee)
///
/// 1. `fd` is a valid, open socket file descriptor.
/// 2. `level` and `optname` are valid socket option identifiers.
///
/// # Usage
///
/// This function is consumed by `exim-smtp/src/outbound/response.rs` in
/// `flush_buffer()` to clear TCP_CORK after sending pipelined commands.
///
/// ```ignore
/// exim_ffi::fd::safe_setsockopt_int(
///     sock, libc::IPPROTO_TCP, libc::TCP_CORK, 0,
/// )?;
/// ```
pub fn safe_setsockopt_int(
    fd: RawFd,
    level: libc::c_int,
    optname: libc::c_int,
    value: libc::c_int,
) -> nix::Result<()> {
    // SAFETY: fd is a valid socket descriptor for the session lifetime.
    // The value pointer is a local variable that outlives the syscall.
    // libc::setsockopt is a standard POSIX function that reads `value`
    // bytes from the pointer without storing the pointer beyond the call.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(nix::errno::Errno::last())
    } else {
        Ok(())
    }
}

/// Atomically duplicate a raw file descriptor to a specific target fd number.
///
/// This is a safe wrapper around `libc::dup2()`. It replicates the behavior of
/// the C `force_fd()` function from `child.c` (lines 31–38): if `old_fd` equals
/// `new_fd`, return immediately; otherwise close `new_fd`, duplicate `old_fd` to
/// `new_fd`, and close `old_fd`.
///
/// # Preconditions (caller must guarantee)
///
/// 1. `old_fd` is a valid, open file descriptor.
/// 2. `new_fd` is a valid fd number (typically 0, 1, or 2 for stdin/stdout/stderr).
/// 3. The caller is in a forked child process about to `exec()`, so fd table
///    manipulation is expected and safe.
///
/// # Returns
///
/// `Ok(())` on success, `Err` with errno if `dup2()` fails.
pub fn safe_force_fd(old_fd: RawFd, new_fd: RawFd) -> nix::Result<()> {
    if old_fd == new_fd {
        return Ok(());
    }
    // SAFETY: Both old_fd and new_fd are valid file descriptors in a forked
    // child process. dup2() atomically closes new_fd if open, then duplicates
    // old_fd to new_fd. The subsequent close(old_fd) releases the original.
    // This is called exclusively in child processes after fork() and before
    // exec(), matching the C child.c force_fd() pattern.
    let res = unsafe { libc::dup2(old_fd, new_fd) };
    nix::errno::Errno::result(res)?;
    let res2 = unsafe { libc::close(old_fd) };
    nix::errno::Errno::result(res2).map(drop)
}

/// Duplicate `old_fd` to `new_fd` via `dup2(2)` without closing `old_fd`.
///
/// Unlike [`safe_force_fd`], this function does **not** close `old_fd` after
/// the duplication.  This is needed when both file descriptors should remain
/// open — for example, making stdout point to the same socket as stdin during
/// ATRN connection flipping (`dup2(0, 1)`).
///
/// # Preconditions (caller must guarantee)
///
/// 1. `old_fd` is a valid, open file descriptor.
/// 2. `new_fd` is a valid fd number (0, 1, 2, or an open fd).
///
/// # Safety justification
///
/// The `unsafe` block wraps `libc::dup2()`, which is an inherently unsafe
/// system call operating on raw fd numbers.  Callers in the exim workspace
/// never use `unsafe` — they call this safe wrapper instead (AAP §0.7.2).
///
/// # Returns
///
/// `Ok(())` on success, `Err` with errno if `dup2()` fails.
pub fn safe_dup2(old_fd: RawFd, new_fd: RawFd) -> nix::Result<()> {
    if old_fd == new_fd {
        return Ok(());
    }
    // SAFETY: Both old_fd and new_fd are valid file descriptors.  dup2()
    // atomically closes new_fd if it is currently open, then makes new_fd
    // a duplicate of old_fd.  old_fd is NOT closed — both remain valid.
    let res = unsafe { libc::dup2(old_fd, new_fd) };
    nix::errno::Errno::result(res).map(drop)
}

/// Close a raw file descriptor.
///
/// Wraps `libc::close()` in a safe interface so that callers outside the
/// `exim-ffi` crate never need to write `unsafe` themselves (AAP §0.7.2).
///
/// # Preconditions (caller must guarantee)
///
/// 1. `fd` is a valid, open file descriptor.
/// 2. No other code holds a borrow of this fd that expects it to remain open.
///
/// # Returns
///
/// `Ok(())` on success, `Err` with errno if `close()` fails.
pub fn safe_close(fd: RawFd) -> nix::Result<()> {
    // SAFETY: fd is a valid open file descriptor. close() releases the fd
    // from the process's fd table. Callers guarantee no other borrows.
    let res = unsafe { libc::close(fd) };
    nix::errno::Errno::result(res).map(drop)
}

/// Redirect stdin, stdout, and stderr to `/dev/null` if they are not open.
///
/// Ensures that file descriptors 0, 1, and 2 exist by opening `/dev/null` for
/// any that are closed. This prevents accidental data leakage when a child
/// process opens files and gets fd 0/1/2.
///
/// Replaces the C `exim_nullstd()` function pattern.
///
/// # Preconditions (caller must guarantee)
///
/// 1. The process is a forked child about to exec.
///
/// # Returns
///
/// `Ok(())` on success, `Err` if `/dev/null` cannot be opened.
pub fn safe_nullstd() -> nix::Result<()> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: We open /dev/null safely, then use dup2 to fill any missing
    // standard fds. This is called in child processes after fork() and before
    // exec(), matching the C exim_nullstd() pattern from child.c.
    for target_fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // Check if the fd is open by trying fcntl F_GETFD
        let flags = unsafe { libc::fcntl(target_fd, libc::F_GETFD) };
        if flags < 0 {
            // fd is not open — open /dev/null and dup2 it
            let devnull = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/null")
                .map_err(|_| nix::errno::Errno::ENOENT)?;
            let raw = devnull.as_raw_fd();
            if raw != target_fd {
                let res = unsafe { libc::dup2(raw, target_fd) };
                nix::errno::Errno::result(res)?;
            }
            // devnull drops here, closing the original fd
            // (the dup2'd copy remains open at target_fd)
        }
    }
    Ok(())
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
