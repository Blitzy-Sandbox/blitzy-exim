// SPDX-License-Identifier: GPL-2.0-or-later
//
// exim-auths/src/helpers/saslauthd.rs — Saslauthd/Pwcheck Integration
//
// Rust rewrite of three C files:
//   - src/src/auths/call_saslauthd.c (69 lines) — high-level saslauthd interface
//   - src/src/auths/pwcheck.c (377 lines)       — low-level saslauthd socket protocol
//   - src/src/auths/pwcheck.h (27 lines)         — constants and function signature
//
// This module provides saslauthd password verification via Unix domain socket
// communication using the Cyrus saslauthd counted-string protocol.
//
// The counted-string wire protocol sends four fields (userid, password,
// service, realm) as length-prefixed strings: a 2-byte big-endian (network
// order) length followed by the raw string bytes. The daemon replies with a
// single counted string whose first two characters indicate the outcome
// ("OK" = success, "NO" = denied, anything else = protocol/temporary failure).
//
// Design changes from C:
//   - The socket path is accepted as a runtime parameter instead of the
//     compile-time CYRUS_SASLAUTHD_SOCKET preprocessor define, eliminating
//     the need for recompilation to enable/disable saslauthd support.
//   - `std::os::unix::net::UnixStream` replaces raw POSIX `socket()`/`connect()`.
//   - `std::io::Write::write_all()` replaces the C `retry_writev()` loop.
//   - `std::io::Read::read_exact()` replaces the C `retry_read()` loop.
//   - Both `write_all` and `read_exact` internally handle EINTR retries.
//   - All error handling uses idiomatic `Result<T, E>` propagation.
//   - Zero `unsafe` code — pure Rust socket I/O via the standard library.

use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length (in bytes) for a single response string read from the
/// saslauthd daemon. Matches the C `MAX_REQ_LEN` constant (pwcheck.c line 200).
/// Any response exceeding this limit is treated as a protocol violation.
const MAX_REQ_LEN: usize = 1024;

// ---------------------------------------------------------------------------
// Result types — replacing C integer constants from pwcheck.h
// ---------------------------------------------------------------------------

/// Low-level result from `saslauthd_verify_password`, mapping directly to the
/// three integer constants defined in the C `pwcheck.h` header:
///
/// | C Constant     | Value | Rust Variant        |
/// |----------------|-------|---------------------|
/// | `PWCHECK_OK`   | 0     | `PwCheckResult::Ok` |
/// | `PWCHECK_NO`   | 1     | `PwCheckResult::No` |
/// | `PWCHECK_FAIL` | 2     | `PwCheckResult::Fail` |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PwCheckResult {
    /// Authentication succeeded (daemon replied "OK …").
    Ok,
    /// Access denied — valid credentials were rejected (daemon replied "NO …").
    No,
    /// Temporary or protocol failure — the daemon could not complete the query.
    Fail,
}

/// High-level result from `auth_call_saslauthd`, mapping to the three Exim
/// authentication return codes: `OK`, `FAIL`, and `ERROR`.
///
/// | C Return | Rust Variant               |
/// |----------|----------------------------|
/// | `OK`     | `SaslauthdResult::Ok`      |
/// | `FAIL`   | `SaslauthdResult::Fail`    |
/// | `ERROR`  | `SaslauthdResult::Error(_)`|
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaslauthdResult {
    /// Authentication succeeded. Maps to Exim `OK`.
    Ok,
    /// Authentication failed (access denied). Maps to Exim `FAIL`.
    Fail,
    /// A daemon or protocol error occurred. The `String` contains the reply
    /// text from the daemon (or an I/O error description), which should be
    /// propagated via the `*errptr` mechanism in the calling auth driver.
    /// Maps to Exim `ERROR`.
    Error(String),
}

// ---------------------------------------------------------------------------
// Wire-protocol helpers
// ---------------------------------------------------------------------------

/// Write a single counted string to the saslauthd socket.
///
/// The wire format is:
///   - 2 bytes: string length as a big-endian (network-order) `u16`
///   - N bytes: raw string content
///
/// This replaces the C `write_string()` function (pwcheck.c lines 240-255)
/// and the underlying `retry_writev()` loop (lines 303-374). Rust's
/// `Write::write_all()` handles partial writes and EINTR retries internally.
fn write_counted_string(stream: &mut UnixStream, data: &[u8]) -> io::Result<()> {
    // The C implementation uses `htons(len)` which converts to big-endian.
    // `u16::to_be_bytes()` is the Rust equivalent.
    let len = data
        .len()
        .try_into()
        .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "data exceeds u16 max length"))?;
    let len_bytes: [u8; 2] = u16::to_be_bytes(len);

    // Write the 2-byte length header followed by the data payload.
    // `write_all` guarantees that either all bytes are written or an error
    // is returned — no partial writes to handle.
    stream.write_all(&len_bytes)?;
    stream.write_all(data)?;
    Ok(())
}

/// Read a single counted string from the saslauthd socket.
///
/// The wire format is:
///   - 2 bytes: string length as a big-endian (network-order) `u16`
///   - N bytes: raw string content
///
/// This replaces the C `read_string()` function (pwcheck.c lines 212-230)
/// and the underlying `retry_read()` loop (lines 266-292). Rust's
/// `Read::read_exact()` handles partial reads and EINTR retries internally.
///
/// Returns the decoded string on success, or an `io::Error` on failure.
/// The response is limited to [`MAX_REQ_LEN`] (1024) bytes.
fn read_counted_string(stream: &mut UnixStream) -> io::Result<String> {
    // Read the 2-byte big-endian length header.
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)?;
    let count = u16::from_be_bytes(len_buf) as usize;

    // Enforce the maximum response length (matches C MAX_REQ_LEN = 1024).
    if count > MAX_REQ_LEN {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("saslauthd response length {count} exceeds maximum {MAX_REQ_LEN}"),
        ));
    }

    // Allocate a buffer and read exactly `count` bytes.
    let mut buf = vec![0u8; count];
    if count > 0 {
        stream.read_exact(&mut buf)?;
    }

    // Convert to a UTF-8 string. The saslauthd daemon typically sends ASCII,
    // but we use `from_utf8_lossy` for robustness against unexpected bytes.
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

// ---------------------------------------------------------------------------
// Core protocol function
// ---------------------------------------------------------------------------

/// Verify a password against the saslauthd daemon via Unix domain socket.
///
/// This is the Rust equivalent of the C `saslauthd_verify_password()` function
/// from `pwcheck.c` (lines 104-192). It implements the full Cyrus saslauthd
/// counted-string protocol:
///
/// 1. Connect to the daemon at `socket_path`.
/// 2. Send four counted strings: userid, password, service, realm.
/// 3. Read a single counted-string response.
/// 4. Parse the first two characters: "OK" → success, "NO" → denied, else fail.
///
/// # Arguments
///
/// * `socket_path` — Path to the saslauthd Unix domain socket. Replaces the
///   compile-time `CYRUS_SASLAUTHD_SOCKET` define from the C implementation.
///   If empty, the function returns `(PwCheckResult::Fail, ...)` immediately.
/// * `userid` — The user identifier to authenticate.
/// * `password` — The password to verify. In the C implementation, the
///   password buffer is zeroed after transmission (line 155). In Rust, `&str`
///   is immutable; callers who require secure erasure should manage the backing
///   `String` themselves (e.g. via the `zeroize` crate).
/// * `service` — The service name (e.g. "smtp"). May be empty.
/// * `realm` — The authentication realm. May be empty.
///
/// # Returns
///
/// A tuple of `(PwCheckResult, String)` where the string is the reply text
/// from the daemon, suitable for logging and error reporting.
pub fn saslauthd_verify_password(
    socket_path: &str,
    userid: &str,
    password: &str,
    service: &str,
    realm: &str,
) -> (PwCheckResult, String) {
    // If the socket path is empty / not configured, behave like the C dummy
    // implementation (pwcheck.c lines 86-95) that returns PWCHECK_FAIL when
    // CYRUS_SASLAUTHD_SOCKET is not defined.
    if socket_path.is_empty() {
        let msg = "saslauthd support is not configured (no socket path provided)".to_string();
        tracing::debug!("{}", msg);
        return (PwCheckResult::Fail, msg);
    }

    tracing::debug!(
        "saslauthd userid='{}' servicename='{}' realm='{}'",
        userid,
        service,
        realm
    );

    // Delegate to the internal implementation that uses Result-based error
    // handling. Any I/O error is mapped to PwCheckResult::Fail with a
    // descriptive message.
    match saslauthd_verify_inner(socket_path, userid, password, service, realm) {
        Ok((result, reply)) => (result, reply),
        Err(e) => {
            let msg = format!("saslauthd I/O error: {e}");
            tracing::debug!("{}", msg);
            (PwCheckResult::Fail, msg)
        }
    }
}

/// Internal implementation of the saslauthd protocol, using `Result` for
/// clean error propagation. Separated from the public function to keep the
/// `?` operator ergonomic while the public API returns a tuple.
fn saslauthd_verify_inner(
    socket_path: &str,
    userid: &str,
    password: &str,
    service: &str,
    realm: &str,
) -> io::Result<(PwCheckResult, String)> {
    // Step 1: Connect to the saslauthd daemon socket.
    // Replaces C socket() + connect() (pwcheck.c lines 120-138).
    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        // Match the C debug message format (pwcheck.c lines 132-134).
        tracing::debug!(
            "Cannot connect to saslauthd daemon (at '{}'): {}",
            socket_path,
            e
        );
        io::Error::new(
            e.kind(),
            format!(
                "cannot connect to saslauthd daemon at {}: {}",
                socket_path, e
            ),
        )
    })?;

    // Apply socket timeouts to prevent indefinite blocking if the saslauthd
    // daemon becomes unresponsive. Uses a default of 30 seconds which is
    // generous for local Unix socket communication but prevents permanent
    // thread hangs that would stall the SMTP connection.
    let socket_timeout = std::time::Duration::from_secs(30);
    stream.set_read_timeout(Some(socket_timeout)).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to set read timeout on saslauthd socket: {}", e),
        )
    })?;
    stream
        .set_write_timeout(Some(socket_timeout))
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("failed to set write timeout on saslauthd socket: {}", e),
            )
        })?;

    // Step 2: Send four counted strings in the exact order expected by the
    // saslauthd daemon protocol.

    // 2a. userid (pwcheck.c lines 141-146)
    write_counted_string(&mut stream, userid.as_bytes()).inspect_err(|_| {
        tracing::debug!("Failed to send userid to saslauthd daemon");
    })?;

    // 2b. password (pwcheck.c lines 148-153)
    write_counted_string(&mut stream, password.as_bytes()).inspect_err(|_| {
        tracing::debug!("Failed to send password to saslauthd daemon");
    })?;

    // SECURITY NOTE: The C implementation zeros the password buffer after
    // transmission (pwcheck.c line 155: memset((void*)password, 0, ...)).
    // In Rust, `password` is an immutable `&str` borrow — we cannot modify
    // the backing memory. Callers requiring secure erasure should hold the
    // password in a mutable `String` and zero it after this function returns,
    // ideally using a crate like `zeroize`.

    // 2c. service (pwcheck.c lines 157-162)
    write_counted_string(&mut stream, service.as_bytes()).inspect_err(|_| {
        tracing::debug!("Failed to send service name to saslauthd daemon");
    })?;

    // 2d. realm (pwcheck.c lines 164-169)
    write_counted_string(&mut stream, realm.as_bytes()).inspect_err(|_| {
        tracing::debug!("Failed to send realm to saslauthd daemon");
    })?;

    // Step 3: Read the daemon's response (pwcheck.c line 171).
    let daemon_reply = read_counted_string(&mut stream).inspect_err(|e| {
        tracing::debug!("Corrupted answer received from saslauthd daemon: {}", e);
    })?;

    // The C code checks `read_string() < 2`, meaning the response must be at
    // least 2 bytes to be valid (pwcheck.c line 171). Responses shorter than
    // 2 bytes are treated as corrupted.
    if daemon_reply.len() < 2 {
        tracing::debug!("Corrupted answer '{}' received.", daemon_reply);
        return Ok((
            PwCheckResult::Fail,
            format!("corrupted saslauthd response: '{daemon_reply}'"),
        ));
    }

    // Socket is automatically closed when `stream` is dropped (Rust RAII).
    // This replaces the explicit `close(s)` at pwcheck.c line 178.

    // Step 4: Log and parse the response.
    tracing::debug!("Answer '{}' received.", daemon_reply);

    // Parse the first two characters to determine the outcome.
    // Matches C logic at pwcheck.c lines 185-191.
    let reply_bytes = daemon_reply.as_bytes();
    let result = if reply_bytes[0] == b'O' && reply_bytes[1] == b'K' {
        PwCheckResult::Ok
    } else if reply_bytes[0] == b'N' && reply_bytes[1] == b'O' {
        PwCheckResult::No
    } else {
        PwCheckResult::Fail
    };

    Ok((result, daemon_reply))
}

// ---------------------------------------------------------------------------
// High-level interface
// ---------------------------------------------------------------------------

/// Authenticate a user via the saslauthd daemon.
///
/// This is the Rust equivalent of the C `auth_call_saslauthd()` function from
/// `call_saslauthd.c` (lines 39-67). It provides the high-level interface
/// called by auth drivers (e.g. plaintext with saslauthd mode).
///
/// The function applies default empty strings for `None` service/realm values
/// (matching C lines 45-46), delegates to [`saslauthd_verify_password`], and
/// maps the low-level [`PwCheckResult`] to the auth-level [`SaslauthdResult`].
///
/// # Arguments
///
/// * `username` — The user to authenticate.
/// * `password` — The password to verify.
/// * `service` — Optional service name (defaults to `""` if `None`).
/// * `realm` — Optional authentication realm (defaults to `""` if `None`).
/// * `socket_path` — Path to the saslauthd Unix domain socket.
///
/// # Returns
///
/// A [`SaslauthdResult`] indicating `Ok` (success), `Fail` (denied), or
/// `Error(reply_text)` (daemon/protocol failure).
pub fn auth_call_saslauthd(
    username: &str,
    password: &str,
    service: Option<&str>,
    realm: Option<&str>,
    socket_path: &str,
) -> SaslauthdResult {
    // Default empty strings for None service/realm (matches C lines 45-46:
    //   if (service == NULL) service = US"";
    //   if (realm == NULL) realm = US"";
    // ).
    let service = service.unwrap_or("");
    let realm = realm.unwrap_or("");

    tracing::debug!("Running saslauthd authentication for user '{}'", username);

    let (result, reply) =
        saslauthd_verify_password(socket_path, username, password, service, realm);

    match result {
        PwCheckResult::Ok => {
            tracing::debug!("saslauthd: success ({})", reply);
            SaslauthdResult::Ok
        }
        PwCheckResult::No => {
            tracing::debug!("saslauthd: access denied ({})", reply);
            SaslauthdResult::Fail
        }
        PwCheckResult::Fail => {
            tracing::debug!("saslauthd: query failed ({})", reply);
            SaslauthdResult::Error(reply)
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // PwCheckResult / SaslauthdResult basic tests
    // -----------------------------------------------------------------------

    #[test]
    fn pw_check_result_equality() {
        assert_eq!(PwCheckResult::Ok, PwCheckResult::Ok);
        assert_ne!(PwCheckResult::Ok, PwCheckResult::No);
        assert_ne!(PwCheckResult::No, PwCheckResult::Fail);
    }

    #[test]
    fn saslauthd_result_equality() {
        assert_eq!(SaslauthdResult::Ok, SaslauthdResult::Ok);
        assert_eq!(SaslauthdResult::Fail, SaslauthdResult::Fail);
        assert_ne!(SaslauthdResult::Ok, SaslauthdResult::Fail);
        assert_ne!(
            SaslauthdResult::Error("x".into()),
            SaslauthdResult::Error("y".into())
        );
    }

    #[test]
    fn saslauthd_result_debug_format() {
        // Ensure Debug is derived and produces reasonable output.
        let ok_dbg = format!("{:?}", SaslauthdResult::Ok);
        assert!(ok_dbg.contains("Ok"));
        let err_dbg = format!("{:?}", SaslauthdResult::Error("test".into()));
        assert!(err_dbg.contains("test"));
    }

    // -----------------------------------------------------------------------
    // write_counted_string / read_counted_string round-trip tests
    // -----------------------------------------------------------------------

    #[test]
    fn counted_string_round_trip_empty() {
        // Verify that an empty string round-trips correctly through the
        // counted-string protocol.
        let (mut writer, mut reader) = UnixStream::pair().expect("socketpair");
        write_counted_string(&mut writer, b"").expect("write empty");
        drop(writer); // signal EOF to reader
        let result = read_counted_string(&mut reader).expect("read empty");
        assert_eq!(result, "");
    }

    #[test]
    fn counted_string_round_trip_hello() {
        let (mut writer, mut reader) = UnixStream::pair().expect("socketpair");
        write_counted_string(&mut writer, b"hello").expect("write hello");
        drop(writer);
        let result = read_counted_string(&mut reader).expect("read hello");
        assert_eq!(result, "hello");
    }

    #[test]
    fn counted_string_round_trip_max_length() {
        // Verify that a string exactly at the MAX_REQ_LEN boundary succeeds.
        let data = vec![b'A'; MAX_REQ_LEN];
        let (mut writer, mut reader) = UnixStream::pair().expect("socketpair");
        write_counted_string(&mut writer, &data).expect("write max");
        drop(writer);
        let result = read_counted_string(&mut reader).expect("read max");
        assert_eq!(result.len(), MAX_REQ_LEN);
    }

    #[test]
    fn counted_string_read_exceeds_max_length() {
        // Manually write a length header that exceeds MAX_REQ_LEN and verify
        // that read_counted_string rejects it.
        let (mut writer, mut reader) = UnixStream::pair().expect("socketpair");
        let too_big: u16 = (MAX_REQ_LEN as u16) + 1;
        writer
            .write_all(&too_big.to_be_bytes())
            .expect("write header");
        drop(writer);
        let err = read_counted_string(&mut reader).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn counted_string_write_network_byte_order() {
        // Verify the wire format: 2-byte big-endian length + data.
        let (mut writer, mut reader) = UnixStream::pair().expect("socketpair");
        write_counted_string(&mut writer, b"AB").expect("write");
        drop(writer);

        // Read raw bytes to verify wire format.
        let mut raw = Vec::new();
        reader.read_to_end(&mut raw).expect("read raw");

        // Expected: [0x00, 0x02, 0x41, 0x42]  (length=2 in big-endian, "AB")
        assert_eq!(raw, vec![0x00, 0x02, b'A', b'B']);
    }

    // -----------------------------------------------------------------------
    // saslauthd_verify_password — empty socket path
    // -----------------------------------------------------------------------

    #[test]
    fn verify_password_empty_socket_path() {
        let (result, reply) = saslauthd_verify_password("", "user", "pass", "smtp", "");
        assert_eq!(result, PwCheckResult::Fail);
        assert!(reply.contains("not configured"));
    }

    // -----------------------------------------------------------------------
    // saslauthd_verify_password — nonexistent socket
    // -----------------------------------------------------------------------

    #[test]
    fn verify_password_nonexistent_socket() {
        let (result, reply) =
            saslauthd_verify_password("/tmp/nonexistent_saslauthd.sock", "u", "p", "s", "r");
        assert_eq!(result, PwCheckResult::Fail);
        assert!(reply.contains("saslauthd"));
    }

    // -----------------------------------------------------------------------
    // auth_call_saslauthd — defaults and mapping
    // -----------------------------------------------------------------------

    #[test]
    fn auth_call_empty_socket() {
        let result = auth_call_saslauthd("user", "pass", None, None, "");
        match result {
            SaslauthdResult::Error(msg) => {
                assert!(msg.contains("not configured"));
            }
            other => panic!("expected Error, got {:?}", other),
        }
    }

    #[test]
    fn auth_call_nonexistent_socket() {
        let result = auth_call_saslauthd(
            "testuser",
            "testpass",
            Some("smtp"),
            Some("example.com"),
            "/tmp/nonexistent_saslauthd_test.sock",
        );
        match result {
            SaslauthdResult::Error(msg) => {
                assert!(msg.contains("saslauthd"));
            }
            other => panic!("expected Error, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Simulated daemon protocol test
    // -----------------------------------------------------------------------

    /// Helper: spawn a mock saslauthd daemon on a temporary Unix socket that
    /// reads 4 counted strings and replies with a fixed response.
    fn run_mock_saslauthd(response: &str) -> (std::path::PathBuf, std::thread::JoinHandle<()>) {
        use std::os::unix::net::UnixListener;
        use std::sync::atomic::{AtomicU64, Ordering};

        // Use an atomic counter to ensure each test gets a unique socket path,
        // avoiding collisions when tests run in parallel threads.
        static SOCK_COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique_id = SOCK_COUNTER.fetch_add(1, Ordering::SeqCst);

        // Create a temporary socket path.
        let dir = std::env::temp_dir();
        let sock_path = dir.join(format!(
            "saslauthd_test_{}_{}.sock",
            std::process::id(),
            unique_id,
        ));
        // Remove any stale socket from a previous run.
        let _ = std::fs::remove_file(&sock_path);

        let listener = UnixListener::bind(&sock_path).expect("bind mock listener");
        let resp = response.to_string();
        let handle = std::thread::spawn(move || {
            let (mut conn, _addr) = listener.accept().expect("accept");
            // Read 4 counted strings (userid, password, service, realm).
            for _ in 0..4 {
                let mut len_buf = [0u8; 2];
                conn.read_exact(&mut len_buf).expect("read len");
                let len = u16::from_be_bytes(len_buf) as usize;
                let mut data = vec![0u8; len];
                if len > 0 {
                    conn.read_exact(&mut data).expect("read data");
                }
            }
            // Send the response as a counted string.
            let resp_bytes = resp.as_bytes();
            let resp_len = (resp_bytes.len() as u16).to_be_bytes();
            conn.write_all(&resp_len).expect("write resp len");
            conn.write_all(resp_bytes).expect("write resp data");
        });

        (sock_path, handle)
    }

    #[test]
    fn mock_daemon_ok_response() {
        let (sock_path, handle) = run_mock_saslauthd("OK authenticated");
        let (result, reply) = saslauthd_verify_password(
            sock_path.to_str().unwrap(),
            "testuser",
            "testpass",
            "smtp",
            "example.com",
        );
        handle.join().expect("mock daemon thread");
        let _ = std::fs::remove_file(&sock_path);

        assert_eq!(result, PwCheckResult::Ok);
        assert_eq!(reply, "OK authenticated");
    }

    #[test]
    fn mock_daemon_no_response() {
        let (sock_path, handle) = run_mock_saslauthd("NO invalid credentials");
        let (result, reply) = saslauthd_verify_password(
            sock_path.to_str().unwrap(),
            "baduser",
            "badpass",
            "smtp",
            "",
        );
        handle.join().expect("mock daemon thread");
        let _ = std::fs::remove_file(&sock_path);

        assert_eq!(result, PwCheckResult::No);
        assert_eq!(reply, "NO invalid credentials");
    }

    #[test]
    fn mock_daemon_fail_response() {
        let (sock_path, handle) = run_mock_saslauthd("XX internal error");
        let (result, reply) =
            saslauthd_verify_password(sock_path.to_str().unwrap(), "user", "pass", "", "");
        handle.join().expect("mock daemon thread");
        let _ = std::fs::remove_file(&sock_path);

        assert_eq!(result, PwCheckResult::Fail);
        assert_eq!(reply, "XX internal error");
    }

    #[test]
    fn mock_daemon_short_response() {
        // Response shorter than 2 bytes should be treated as corrupted.
        let (sock_path, handle) = run_mock_saslauthd("X");
        let (result, reply) =
            saslauthd_verify_password(sock_path.to_str().unwrap(), "user", "pass", "", "");
        handle.join().expect("mock daemon thread");
        let _ = std::fs::remove_file(&sock_path);

        assert_eq!(result, PwCheckResult::Fail);
        assert!(reply.contains("corrupted"));
    }

    #[test]
    fn mock_daemon_auth_call_ok() {
        let (sock_path, handle) = run_mock_saslauthd("OK success");
        let result = auth_call_saslauthd(
            "alice",
            "s3cret",
            Some("smtp"),
            Some("example.org"),
            sock_path.to_str().unwrap(),
        );
        handle.join().expect("mock daemon thread");
        let _ = std::fs::remove_file(&sock_path);

        assert_eq!(result, SaslauthdResult::Ok);
    }

    #[test]
    fn mock_daemon_auth_call_denied() {
        let (sock_path, handle) = run_mock_saslauthd("NO denied");
        let result = auth_call_saslauthd("bob", "wrong", None, None, sock_path.to_str().unwrap());
        handle.join().expect("mock daemon thread");
        let _ = std::fs::remove_file(&sock_path);

        assert_eq!(result, SaslauthdResult::Fail);
    }

    #[test]
    fn mock_daemon_auth_call_error() {
        let (sock_path, handle) = run_mock_saslauthd("ZZZZ something weird");
        let result = auth_call_saslauthd(
            "carol",
            "pass",
            Some("imap"),
            Some("realm"),
            sock_path.to_str().unwrap(),
        );
        handle.join().expect("mock daemon thread");
        let _ = std::fs::remove_file(&sock_path);

        match result {
            SaslauthdResult::Error(msg) => {
                assert_eq!(msg, "ZZZZ something weird");
            }
            other => panic!("expected Error, got {:?}", other),
        }
    }

    /// Verify that the mock daemon receives the correct four counted strings
    /// by reading them and comparing to expected values.
    #[test]
    fn mock_daemon_receives_correct_fields() {
        use std::os::unix::net::UnixListener;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::{Arc, Mutex};

        static FIELDS_COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique_id = FIELDS_COUNTER.fetch_add(1, Ordering::SeqCst);

        let dir = std::env::temp_dir();
        let sock_path = dir.join(format!(
            "saslauthd_fields_{}_{}.sock",
            std::process::id(),
            unique_id,
        ));
        let _ = std::fs::remove_file(&sock_path);

        let listener = UnixListener::bind(&sock_path).expect("bind");
        let received: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let received_clone = Arc::clone(&received);

        let handle = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            for _ in 0..4 {
                let mut len_buf = [0u8; 2];
                conn.read_exact(&mut len_buf).expect("read len");
                let len = u16::from_be_bytes(len_buf) as usize;
                let mut data = vec![0u8; len];
                if len > 0 {
                    conn.read_exact(&mut data).expect("read data");
                }
                received_clone
                    .lock()
                    .unwrap()
                    .push(String::from_utf8(data).unwrap());
            }
            // Reply OK.
            let resp = b"OK";
            let resp_len = (resp.len() as u16).to_be_bytes();
            conn.write_all(&resp_len).expect("write len");
            conn.write_all(resp).expect("write resp");
        });

        let (result, _) = saslauthd_verify_password(
            sock_path.to_str().unwrap(),
            "myuser",
            "mypass",
            "smtp",
            "myrealm",
        );
        handle.join().expect("thread");
        let _ = std::fs::remove_file(&sock_path);

        assert_eq!(result, PwCheckResult::Ok);
        let fields = received.lock().unwrap();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0], "myuser");
        assert_eq!(fields[1], "mypass");
        assert_eq!(fields[2], "smtp");
        assert_eq!(fields[3], "myrealm");
    }
}
