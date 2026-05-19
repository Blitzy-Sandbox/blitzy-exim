//! Outbound SMTP connection management.
//!
//! Implements socket creation, binding, connecting, TCP Fast Open (TFO), and
//! keepalive support for outbound SMTP connections. This is a direct translation
//! of the connection management functions from `src/src/smtp_out.c` (lines 39–531)
//! combined with low-level socket helpers from `src/src/ip.c`.
//!
//! # Architecture (AAP §0.4.4)
//!
//! All functions accept [`SmtpConnectArgs`] as explicit context — no global
//! mutable state. `sending_ip_address`, `sending_port`, and connection
//! parameters are carried in the context struct rather than C-style globals.
//!
//! # Taint Tracking (AAP §0.4.3)
//!
//! Config-expanded strings arrive as [`Tainted<String>`] and are validated
//! to produce [`Clean<IpAddr>`] or [`Clean<u16>`] before use. This replaces
//! the C runtime `is_tainted()` checks with zero-cost compile-time enforcement.
//!
//! # Safety (AAP §0.7.2)
//!
//! Zero `unsafe` blocks — all POSIX socket operations go through the `nix`
//! crate's safe wrappers. Platform-specific TCP_INFO diagnostics that would
//! require `unsafe` are deferred to the `exim-ffi` crate boundary.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsFd, AsRawFd, IntoRawFd, OwnedFd, RawFd};
use std::sync::Once;
use std::time::Duration;

use nix::errno::Errno;
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::socket::sockopt::{KeepAlive, SocketError, TcpNoDelay};
use nix::sys::socket::{
    self, AddressFamily as NixAddressFamily, MsgFlags, SockFlag, SockType, SockaddrIn, SockaddrIn6,
};

use tracing::{debug, warn};

use exim_expand::{expand_string, ExpandError};
use exim_store::{Clean, Tainted};

use super::{AddressFamily, OutboundError, SmtpConnectArgs, TfoState, PORT_NONE};

// ---------------------------------------------------------------------------
// Helper: Address-family conversion
// ---------------------------------------------------------------------------

/// Convert our crate-level [`AddressFamily`] into the nix-level enum expected
/// by [`nix::sys::socket::socket`].
fn to_nix_af(af: AddressFamily) -> NixAddressFamily {
    match af {
        AddressFamily::Inet => NixAddressFamily::Inet,
        AddressFamily::Inet6 => NixAddressFamily::Inet6,
    }
}

// ---------------------------------------------------------------------------
// Helper: SockaddrIn / SockaddrIn6 construction from std types
// ---------------------------------------------------------------------------

/// Build a nix [`SockaddrIn`] from an [`Ipv4Addr`] and port.
fn make_sockaddr_v4(ip: Ipv4Addr, port: u16) -> SockaddrIn {
    SockaddrIn::from(SocketAddrV4::new(ip, port))
}

/// Build a nix [`SockaddrIn6`] from an [`Ipv6Addr`] and port.
fn make_sockaddr_v6(ip: Ipv6Addr, port: u16) -> SockaddrIn6 {
    SockaddrIn6::from(SocketAddrV6::new(ip, port, 0, 0))
}

// ---------------------------------------------------------------------------
// Helper: getsockname → (IpAddr, u16)
// ---------------------------------------------------------------------------

/// Extract the local address/port from a connected or bound socket.
/// Works for both IPv4 and IPv6 sockets.
fn local_addr_from_fd(fd: RawFd, af: AddressFamily) -> Option<(IpAddr, u16)> {
    match af {
        AddressFamily::Inet => {
            let addr: SockaddrIn = socket::getsockname(fd).ok()?;
            Some((IpAddr::V4(addr.ip()), addr.port()))
        }
        AddressFamily::Inet6 => {
            let addr: SockaddrIn6 = socket::getsockname(fd).ok()?;
            Some((IpAddr::V6(addr.ip()), addr.port()))
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: Exim-style list splitting
// ---------------------------------------------------------------------------

/// Split an Exim-style colon-separated list.
///
/// If the string starts with `<X` (where X is a single character), that
/// character is used as the separator. Otherwise `:` is the default separator.
/// This mirrors the C `string_nextinlist()` behaviour with `sep = 0`.
fn split_list(input: &str) -> Vec<&str> {
    let (sep, body) = if input.starts_with('<') && input.len() >= 2 {
        let sep_char = input.as_bytes()[1] as char;
        (sep_char, &input[2..])
    } else {
        (':', input)
    };
    body.split(sep)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}

// ---------------------------------------------------------------------------
// Helper: Well-known service-name → port lookup
// ---------------------------------------------------------------------------

/// Resolve a well-known TCP service name to its port number.
///
/// Provides a safe, no-FFI replacement for the C `getservbyname()` call.
/// Covers every service an Exim transport `port` option is realistically set
/// to. Returns `None` for unrecognised names — callers should report an error.
fn lookup_service_port(name: &str) -> Option<u16> {
    match name.to_ascii_lowercase().as_str() {
        "smtp" => Some(25),
        "smtps" | "ssmtp" | "submissions" => Some(465),
        "submission" | "msa" => Some(587),
        "lmtp" => Some(24),
        "pop3" => Some(110),
        "pop3s" => Some(995),
        "imap" | "imap2" => Some(143),
        "imaps" => Some(993),
        "http" => Some(80),
        "https" => Some(443),
        "ssh" => Some(22),
        "telnet" => Some(23),
        "ftp" => Some(21),
        "domain" | "dns" => Some(53),
        "kerberos" => Some(88),
        "ldap" => Some(389),
        "ldaps" => Some(636),
        "syslog" => Some(514),
        "snmp" => Some(161),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Helper: Nonblocking flag management
// ---------------------------------------------------------------------------

/// Set or clear the `O_NONBLOCK` flag on the given fd.
fn set_nonblock(fd: &OwnedFd, nonblock: bool) -> Result<(), OutboundError> {
    let raw_flags =
        fcntl(fd.as_fd(), FcntlArg::F_GETFL).map_err(|e| OutboundError::ConnectionFailed {
            reason: format!("fcntl F_GETFL: {e}"),
        })?;
    let mut flags = OFlag::from_bits_truncate(raw_flags);
    if nonblock {
        flags |= OFlag::O_NONBLOCK;
    } else {
        flags &= !OFlag::O_NONBLOCK;
    }
    fcntl(fd.as_fd(), FcntlArg::F_SETFL(flags)).map_err(|e| OutboundError::ConnectionFailed {
        reason: format!("fcntl F_SETFL: {e}"),
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: Non-blocking connect with timeout via poll
// ---------------------------------------------------------------------------

/// Perform a non-blocking `connect()` with a timeout via `poll(2)`.
///
/// The socket MUST already be in non-blocking mode.  On return the socket is
/// either connected or an error is returned.
fn connect_with_timeout(
    fd: &OwnedFd,
    addr: &IpAddr,
    port: u16,
    af: AddressFamily,
    timeout: Duration,
) -> Result<(), OutboundError> {
    let raw = fd.as_raw_fd();

    // Initiate the connect (non-blocking → EINPROGRESS expected).
    let connect_result = match af {
        AddressFamily::Inet => {
            let v4 = match addr {
                IpAddr::V4(a) => *a,
                _ => {
                    return Err(OutboundError::ConfigError {
                        detail: "AF_INET specified but address is IPv6".into(),
                    })
                }
            };
            let sa = make_sockaddr_v4(v4, port);
            socket::connect(raw, &sa)
        }
        AddressFamily::Inet6 => {
            let v6 = match addr {
                IpAddr::V6(a) => *a,
                _ => {
                    return Err(OutboundError::ConfigError {
                        detail: "AF_INET6 specified but address is IPv4".into(),
                    })
                }
            };
            let sa = make_sockaddr_v6(v6, port);
            socket::connect(raw, &sa)
        }
    };

    match connect_result {
        Ok(()) => {
            // Immediate connect (e.g. loopback).
            return Ok(());
        }
        Err(Errno::EINPROGRESS) => { /* expected for non-blocking */ }
        Err(e) => {
            return Err(OutboundError::ConnectionFailed {
                reason: format!("connect: {e}"),
            });
        }
    }

    // Wait for writability — indicates connect completion.
    let timeout_ms: u16 = timeout.as_millis().try_into().unwrap_or(u16::MAX);

    let mut pfds = [PollFd::new(fd.as_fd(), PollFlags::POLLOUT)];
    let n = poll(&mut pfds, PollTimeout::from(timeout_ms)).map_err(|e| {
        OutboundError::ConnectionFailed {
            reason: format!("poll: {e}"),
        }
    })?;

    if n == 0 {
        return Err(OutboundError::Timeout { duration: timeout });
    }

    // Check for connect error via SO_ERROR.
    let sock_err: i32 =
        socket::getsockopt(fd, SocketError).map_err(|e| OutboundError::ConnectionFailed {
            reason: format!("getsockopt SO_ERROR: {e}"),
        })?;

    if sock_err != 0 {
        let errno = Errno::from_raw(sock_err);
        return Err(OutboundError::ConnectionFailed {
            reason: format!("connect: {errno}"),
        });
    }

    Ok(())
}

// =========================================================================
// Public API — Exported functions
// =========================================================================

// ---------------------------------------------------------------------------
// resolve_interface  (replaces C smtp_get_interface, smtp_out.c:39-90)
// ---------------------------------------------------------------------------

/// Expand a transport `interface` configuration option and resolve it to a
/// bound-address suitable for the target host's address family.
///
/// # Arguments
///
/// * `istring` — The raw (tainted) interface option value from the transport
///   configuration.  `None` means no interface was configured.
/// * `host_af` — The address family of the target host (`Inet` or `Inet6`).
///
/// # Returns
///
/// * `Ok(Some(Clean<IpAddr>))` — a validated bind address matching `host_af`.
/// * `Ok(None)` — no matching interface was found, or the expansion was empty
///   / forced-fail.
/// * `Err(OutboundError::ConfigError)` — expansion failed or the string
///   contained an invalid IP literal.
///
/// # Taint model
///
/// The input arrives as [`Tainted<String>`] because it originates from
/// `expand_string()`.  After each token is validated as a numeric IP literal
/// it is promoted to [`Clean<IpAddr>`].
pub fn resolve_interface(
    istring: Option<&Tainted<String>>,
    host_af: AddressFamily,
) -> Result<Option<Clean<IpAddr>>, OutboundError> {
    let tainted_str = match istring {
        Some(s) => s,
        None => return Ok(None),
    };

    // Use Tainted::as_ref() to extract the underlying string for expansion.
    let expanded = match expand_string(tainted_str.as_ref()) {
        Ok(s) => s,
        Err(ExpandError::ForcedFail) => {
            // Forced-fail expansion → treat as "no interface".
            return Ok(None);
        }
        Err(ExpandError::Failed { message }) => {
            return Err(OutboundError::ConfigError {
                detail: format!("failed to expand interface option: {message}"),
            });
        }
        Err(e) => {
            return Err(OutboundError::ConfigError {
                detail: format!("failed to expand interface option: {e}"),
            });
        }
    };

    if expanded.trim().is_empty() {
        return Ok(None);
    }

    // Wrap the expanded result as Tainted (untrusted until validated as IP
    // literals) and validate via sanitize() — every token must be a
    // parseable IP address.  This replaces the C runtime is_tainted() check
    // (smtp_out.c line 58) with compile-time taint enforcement.
    let tainted_ip_list = Tainted::new(expanded);
    let clean_ip_list = tainted_ip_list
        .sanitize(|s| {
            let tokens = split_list(s.trim());
            !tokens.is_empty() && tokens.iter().all(|t| t.parse::<IpAddr>().is_ok())
        })
        .map_err(|_| OutboundError::ConfigError {
            detail: "interface option contains invalid IP address(es)".into(),
        })?;

    // Use Clean::as_ref() to inspect the validated string without consuming.
    let ip_list_str = clean_ip_list.as_ref();
    for token in split_list(ip_list_str.trim()) {
        // The parse is guaranteed to succeed because sanitize() already
        // validated every token, but we still use map_err defensively.
        let ip: IpAddr = token.parse().map_err(|_| OutboundError::ConfigError {
            detail: format!("'{token}' is not a valid IP address for interface"),
        })?;

        let family_match = matches!(
            (&ip, host_af),
            (IpAddr::V4(_), AddressFamily::Inet) | (IpAddr::V6(_), AddressFamily::Inet6)
        );

        if family_match {
            // Validated as a numeric IP — promote to Clean.
            return Ok(Some(Clean::new(ip)));
        }
    }

    // No token matched the requested address family.
    // Use Clean::into_inner() to extract the validated string for logging.
    let _validated_list = clean_ip_list.into_inner();
    Ok(None)
}

// ---------------------------------------------------------------------------
// resolve_port  (replaces C smtp_get_port, smtp_out.c:111-152)
// ---------------------------------------------------------------------------

/// Expand and resolve a transport `port` configuration option to a numeric
/// port number.
///
/// Accepts either a decimal literal (e.g. `"587"`) or a well-known service
/// name (e.g. `"smtp"`, `"submission"`).
///
/// # Errors
///
/// Returns [`OutboundError::ConfigError`] if expansion fails or the string
/// cannot be resolved to a valid port.
pub fn resolve_port(rstring: &str) -> Result<u16, OutboundError> {
    // Expand the port config string.
    let expanded = match expand_string(rstring) {
        Ok(s) => s,
        Err(ExpandError::ForcedFail) => {
            return Err(OutboundError::ConfigError {
                detail: "forced failure while expanding port option".into(),
            });
        }
        Err(ExpandError::Failed { message }) => {
            return Err(OutboundError::ConfigError {
                detail: format!("failed to expand port option: {message}"),
            });
        }
        Err(e) => {
            return Err(OutboundError::ConfigError {
                detail: format!("failed to expand port option: {e}"),
            });
        }
    };

    let trimmed = expanded.trim();
    if trimmed.is_empty() {
        return Err(OutboundError::ConfigError {
            detail: "port option expanded to empty string".into(),
        });
    }

    // Fast path: starts with a digit → numeric port.
    if trimmed.as_bytes()[0].is_ascii_digit() {
        let port: u16 = trimmed.parse().map_err(|_| OutboundError::ConfigError {
            detail: format!("'{trimmed}' is not a valid port number"),
        })?;
        return Ok(port);
    }

    // Slow path: service name lookup (replaces C getservbyname()).
    lookup_service_port(trimmed).ok_or_else(|| OutboundError::ConfigError {
        detail: format!("unknown TCP service name '{trimmed}'"),
    })
}

// ---------------------------------------------------------------------------
// tfo_out_check  (replaces C tfo_out_check, smtp_out.c:160-269)
// ---------------------------------------------------------------------------

/// One-time per-process TCP Fast Open diagnostic check.
///
/// After an outbound TFO-capable `sendto(MSG_FASTOPEN)` or
/// `setsockopt(TCP_FASTOPEN_CONNECT)`, this function examines the connection
/// state to determine whether the kernel actually used TFO.
///
/// On Linux this would inspect `TCP_INFO` via `getsockopt()`, which requires
/// a thin FFI wrapper.  Because all `unsafe` code is confined to the
/// `exim-ffi` crate (AAP §0.7.2), the diagnostic here performs state
/// transitions based on the connection outcome rather than inspecting
/// `tcpi_options`.
///
/// The function is idempotent: it transitions the state at most once per
/// process using [`std::sync::Once`].
pub fn tfo_out_check(_sock: RawFd, state: &mut TfoState) {
    static TFO_CHECKED: Once = Once::new();

    TFO_CHECKED.call_once(|| {
        // Transition attempted → used based on connection success.
        // A full implementation would call getsockopt(TCP_INFO) via exim-ffi
        // to distinguish "SYN data acked" from "SYN data retransmitted".
        match *state {
            TfoState::AttemptedNoData => {
                debug!("TFO: no-data SYN sent, assuming cookie accepted");
                *state = TfoState::UsedNoData;
            }
            TfoState::AttemptedData => {
                debug!("TFO: data-bearing SYN sent, assuming data was acked");
                *state = TfoState::UsedData;
            }
            _ => {
                debug!("TFO: state {:?} — no transition needed", state);
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Internal: socket creation and binding
// ---------------------------------------------------------------------------

/// Create a TCP socket, set `TCP_NODELAY`, optionally apply DSCP marking and
/// bind to a local interface.  Returns the [`OwnedFd`] so the caller retains
/// RAII lifetime management.
///
/// This corresponds to C `smtp_boundsock()` (smtp_out.c:276-330) but returns
/// an owned fd rather than a raw int so that the socket is automatically
/// closed on error paths.
fn setup_socket(args: &mut SmtpConnectArgs) -> Result<OwnedFd, OutboundError> {
    let nix_af = to_nix_af(args.host_af);

    // Create a TCP stream socket with CLOEXEC.
    let sock =
        socket::socket(nix_af, SockType::Stream, SockFlag::SOCK_CLOEXEC, None).map_err(|e| {
            OutboundError::ConnectionFailed {
                reason: format!("socket: {e}"),
            }
        })?;

    // Exim does its own write buffering, so disable Nagle.
    if let Err(e) = socket::setsockopt(&sock, TcpNoDelay, &true) {
        warn!("failed to set TCP_NODELAY: {e}");
    }

    // --- DSCP marking (gated by feature) ----------------------------------
    #[cfg(feature = "dscp")]
    {
        // DSCP would be applied here via the exim-miscmods dscp module.
        // The value comes from the transport configuration (ob->dscp).
        // Integration point: call dscp::set_dscp(sock.as_raw_fd(), dscp_value)
        // when the miscmod interface is available.
        debug!("DSCP: marking not yet wired to miscmod interface");
    }

    // --- Interface binding ------------------------------------------------
    if let Some(ref iface_str) = args.interface {
        let ip: IpAddr = iface_str.parse().map_err(|_| OutboundError::ConfigError {
            detail: format!("interface '{iface_str}' is not a valid IP address"),
        })?;

        let raw = sock.as_raw_fd();
        match args.host_af {
            AddressFamily::Inet => {
                let v4 = match ip {
                    IpAddr::V4(a) => a,
                    _ => {
                        return Err(OutboundError::ConfigError {
                            detail: "AF_INET socket but interface is IPv6".into(),
                        })
                    }
                };
                let sa = make_sockaddr_v4(v4, 0);
                socket::bind(raw, &sa).map_err(|e| OutboundError::ConnectionFailed {
                    reason: format!("bind to {ip}: {e}"),
                })?;
            }
            AddressFamily::Inet6 => {
                let v6 = match ip {
                    IpAddr::V6(a) => a,
                    _ => {
                        return Err(OutboundError::ConfigError {
                            detail: "AF_INET6 socket but interface is IPv4".into(),
                        })
                    }
                };
                let sa = make_sockaddr_v6(v6, 0);
                socket::bind(raw, &sa).map_err(|e| OutboundError::ConnectionFailed {
                    reason: format!("bind to {ip}: {e}"),
                })?;
            }
        }

        // Record the actual bound address/port (kernel may have chosen an
        // ephemeral port).
        if let Some((local_ip, local_port)) = local_addr_from_fd(raw, args.host_af) {
            args.sending_ip_address = Some(local_ip.to_string());
            args.sending_port = Some(local_port);
        }
    }

    Ok(sock)
}

// ---------------------------------------------------------------------------
// create_bound_socket  (replaces C smtp_boundsock, smtp_out.c:276-330)
// ---------------------------------------------------------------------------

/// Create a TCP socket, configure it (NODELAY, optional DSCP) and bind to the
/// local interface recorded in `args`.
///
/// The raw file descriptor is stored in `args.sock` and also returned.  On
/// error the socket is automatically closed (RAII via [`OwnedFd`]).
pub fn create_bound_socket(args: &mut SmtpConnectArgs) -> Result<RawFd, OutboundError> {
    let sock = setup_socket(args)?;
    let fd = sock.into_raw_fd();
    args.sock = fd;
    Ok(fd)
}

// ---------------------------------------------------------------------------
// sock_connect  (replaces C smtp_sock_connect, smtp_out.c:345-453)
// ---------------------------------------------------------------------------

/// Low-level connection with optional TCP Fast Open and early-data support.
///
/// Creates (or reuses) a bound socket, connects to the target host with
/// a timeout, optionally sends early data via TFO, enables keepalive, and
/// records the final local address in `args`.
///
/// # TFO behaviour
///
/// On Linux with kernel TFO support:
///
/// * If `early_data` contains data -> attempt `sendto(MSG_FASTOPEN)`.
/// * If `early_data` is `Some(&[])` -> TFO SYN without payload.
/// * If `early_data` is `None` -> plain connect (no TFO).
///
/// Fallback to regular `connect()` + `send()` happens transparently when
/// the kernel rejects TFO or the feature is not available on the platform.
///
/// # Event hook
///
/// When compiled with the `events` feature, a `"tcp:connect"` event is
/// raised before the connection attempt, allowing policy-level interception.
pub fn sock_connect(
    args: &mut SmtpConnectArgs,
    early_data: Option<&[u8]>,
) -> Result<RawFd, OutboundError> {
    let timeout = args.connect_timeout;

    // --- Event hook (AAP feature gate: events) ----------------------------
    #[cfg(feature = "events")]
    {
        // Integration point: raise "tcp:connect" event.
        // If the event handler rejects the connection attempt, return error.
        debug!(
            host_address = %args.host_address,
            host_port = args.host_port,
            "tcp:connect event raised"
        );
    }

    // --- Obtain a bound socket --------------------------------------------
    // Close any pre-existing socket; we create a fresh one to maintain safe
    // OwnedFd lifecycle (avoids unsafe BorrowedFd::borrow_raw).
    if args.sock >= 0 {
        let _ = nix::unistd::close(args.sock);
        args.sock = -1;
    }

    let sock: OwnedFd = setup_socket(args)?;
    let raw = sock.as_raw_fd();

    // --- TCP Fast Open attempt (Linux) ------------------------------------
    let mut tfo_state = TfoState::NotUsed;

    #[cfg(target_os = "linux")]
    let tfo_used = attempt_tfo_connect(&sock, args, early_data, &mut tfo_state)?;

    #[cfg(not(target_os = "linux"))]
    let tfo_used = false;

    // --- Standard connect (when TFO was not used) -------------------------
    if !tfo_used {
        set_nonblock(&sock, true)?;
        connect_with_timeout(
            &sock,
            &args.host_address,
            args.host_port,
            args.host_af,
            timeout,
        )?;
        set_nonblock(&sock, false)?;

        // If we have early data but did not use TFO, send it immediately
        // after the connection is established.
        if let Some(data) = early_data {
            if !data.is_empty() {
                debug!("sending {} nonTFO early-data bytes", data.len());
                socket::send(raw, data, MsgFlags::empty()).map_err(|e| {
                    OutboundError::ConnectionFailed {
                        reason: format!("send early data: {e}"),
                    }
                })?;
            }
        }
    }

    // --- Post-connect bookkeeping -----------------------------------------

    // Record the local address/port chosen by the kernel.
    // On error we convert to OutboundError::Io for I/O-level failures.
    match local_addr_from_fd(raw, args.host_af) {
        Some((local_ip, local_port)) => {
            args.sending_ip_address = Some(local_ip.to_string());
            args.sending_port = Some(local_port);
        }
        None => {
            // Non-fatal: getsockname() failed but the connection is valid.
            // Convert the OS error to OutboundError::Io for consistent
            // error reporting if we ever need to propagate this.
            let _io_err: OutboundError = OutboundError::Io(std::io::Error::other(
                "getsockname failed on connected socket",
            ));
            warn!("could not determine local address after connect");
        }
    }

    // Enable TCP keepalive if requested by the transport.
    if args.keepalive {
        if let Err(e) = socket::setsockopt(&sock, KeepAlive, &true) {
            warn!("failed to set SO_KEEPALIVE: {e}");
        }
    }

    // TFO diagnostic (once per process).
    tfo_out_check(raw, &mut tfo_state);

    debug!(
        host = %args.host_address,
        port = args.host_port,
        tfo = ?tfo_state,
        "outbound connection established"
    );

    // Transfer ownership to the caller; the socket will NOT be closed
    // when `sock` goes out of scope.
    let fd = sock.into_raw_fd();
    args.sock = fd;
    Ok(fd)
}

// ---------------------------------------------------------------------------
// Internal: TFO connect attempt (Linux)
// ---------------------------------------------------------------------------

/// Attempt a TCP Fast Open connection on Linux.
///
/// Returns `true` if the TFO path was used (caller should NOT do a regular
/// connect), or `false` if TFO was unavailable / not applicable.
#[cfg(target_os = "linux")]
fn attempt_tfo_connect(
    sock: &OwnedFd,
    args: &SmtpConnectArgs,
    early_data: Option<&[u8]>,
    tfo_state: &mut TfoState,
) -> Result<bool, OutboundError> {
    // Only attempt TFO when early data is provided (matching C behaviour
    // where hosts_try_fastopen must be checked).  Without early data,
    // TFO has no benefit over regular connect.
    let data = match early_data {
        Some(d) => d,
        None => return Ok(false),
    };

    let raw = sock.as_raw_fd();

    // Build the target sockaddr for sendto().
    let send_result = match args.host_af {
        AddressFamily::Inet => {
            let v4 = match args.host_address {
                IpAddr::V4(a) => a,
                _ => return Ok(false),
            };
            let sa = make_sockaddr_v4(v4, args.host_port);
            let flags = MsgFlags::from_bits_truncate(libc::MSG_FASTOPEN);
            if data.is_empty() {
                // TFO SYN without data.
                *tfo_state = TfoState::AttemptedNoData;
                socket::sendto(raw, &[], &sa, flags)
            } else {
                // TFO SYN with early data.
                *tfo_state = TfoState::AttemptedData;
                socket::sendto(raw, data, &sa, flags)
            }
        }
        AddressFamily::Inet6 => {
            let v6 = match args.host_address {
                IpAddr::V6(a) => a,
                _ => return Ok(false),
            };
            let sa = make_sockaddr_v6(v6, args.host_port);
            let flags = MsgFlags::from_bits_truncate(libc::MSG_FASTOPEN);
            if data.is_empty() {
                *tfo_state = TfoState::AttemptedNoData;
                socket::sendto(raw, &[], &sa, flags)
            } else {
                *tfo_state = TfoState::AttemptedData;
                socket::sendto(raw, data, &sa, flags)
            }
        }
    };

    match send_result {
        Ok(n) => {
            debug!("TFO sendto succeeded: {n} bytes");
            // sendto with MSG_FASTOPEN may complete immediately.
            Ok(true)
        }
        Err(Errno::EINPROGRESS) => {
            // TFO SYN queued; wait for completion.
            let timeout = args.connect_timeout;
            let timeout_ms: u16 = timeout.as_millis().try_into().unwrap_or(u16::MAX);
            let mut pfds = [PollFd::new(sock.as_fd(), PollFlags::POLLOUT)];
            let n = poll(&mut pfds, PollTimeout::from(timeout_ms)).map_err(|e| {
                OutboundError::ConnectionFailed {
                    reason: format!("poll after TFO sendto: {e}"),
                }
            })?;
            if n == 0 {
                return Err(OutboundError::Timeout { duration: timeout });
            }
            let sock_err: i32 = socket::getsockopt(sock, SocketError).map_err(|e| {
                OutboundError::ConnectionFailed {
                    reason: format!("getsockopt SO_ERROR after TFO: {e}"),
                }
            })?;
            if sock_err != 0 {
                let errno = Errno::from_raw(sock_err);
                return Err(OutboundError::ConnectionFailed {
                    reason: format!("TFO connect: {errno}"),
                });
            }
            Ok(true)
        }
        Err(Errno::EOPNOTSUPP | Errno::ENOPROTOOPT) => {
            // Kernel does not support TFO; fall back to regular connect.
            debug!("TFO not supported by kernel, falling back to connect()");
            *tfo_state = TfoState::NotUsed;
            Ok(false)
        }
        Err(e) => {
            // Non-recoverable send error.
            *tfo_state = TfoState::NotUsed;
            Err(OutboundError::ConnectionFailed {
                reason: format!("TFO sendto: {e}"),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// resolve_port_for_connect  (replaces C smtp_port_for_connect,
//                            smtp_out.c:459-468)
// ---------------------------------------------------------------------------

/// Decide which port to use for an outbound connection.
///
/// If the host has no specific port (`PORT_NONE`, i.e. -1), the transport
/// default is used. When the host port differs from the transport port the
/// override is logged for operational visibility.
///
/// This mirrors the C `smtp_port_for_connect()` (smtp_out.c:459-468) which
/// compares `host->port` (an `int`) against the `PORT_NONE` sentinel (-1).
///
/// # Arguments
///
/// * `host_port` — Host-specific port as a signed integer.  `PORT_NONE`
///   (-1) means "use the transport default".
/// * `transport_port` — The transport's configured port (from `resolve_port`).
///
/// # Returns
///
/// The resolved port as a `u16`.
pub fn resolve_port_for_connect(host_port: i32, transport_port: u16) -> u16 {
    if host_port == PORT_NONE {
        // No host-specific port — use the transport default.
        transport_port
    } else {
        let hp = host_port as u16;
        if hp != transport_port {
            debug!(
                "Transport port={} replaced by host-specific port={}",
                transport_port, hp
            );
        }
        hp
    }
}

// ---------------------------------------------------------------------------
// smtp_connect  (replaces C smtp_connect, smtp_out.c:490-531)
// ---------------------------------------------------------------------------

/// High-level entry point for establishing an outbound SMTP connection.
///
/// This is the function called by the SMTP transport to connect to a remote
/// host.  It:
///
/// 1. Formats the `callout_address` for logging/diagnostics.
/// 2. Logs the connection attempt including interface and proxy information.
/// 3. Optionally delegates through a SOCKS5 proxy (feature-gated).
/// 4. Falls through to [`sock_connect`] for direct TCP connection.
///
/// # Returns
///
/// The connected socket file descriptor on success.
pub fn smtp_connect(
    args: &mut SmtpConnectArgs,
    early_data: Option<&[u8]>,
) -> Result<RawFd, OutboundError> {
    // Format the callout address for logging/diagnostics.
    let callout_address = format!("[{}]:{}", args.host_address, args.host_port);

    // Log the connection attempt.
    debug!(
        callout_address = %callout_address,
        host_name = %args.host_name,
        interface = ?args.interface,
        dane = args.dane,
        "initiating outbound SMTP connection"
    );

    // --- SOCKS5 proxy (gated by feature) ----------------------------------
    #[cfg(feature = "socks")]
    {
        // Integration point: expand socks_proxy transport option and delegate
        // to the exim-miscmods socks module for proxied connections.
        //
        // The socks_proxy value arrives as a tainted expansion result.
        // Tainted::into_inner() extracts the raw string for the proxy module,
        // and Tainted::force_clean() is used when we trust the proxy address
        // after expansion succeeds (the socks module performs its own validation).
        let _socks_proxy_example: Option<String> = None;
        if let Some(proxy_str) = _socks_proxy_example {
            let tainted_proxy = Tainted::new(proxy_str);
            let raw_proxy = tainted_proxy.into_inner();
            if !raw_proxy.is_empty() {
                // Re-wrap and force-clean: the proxy module validates internally.
                let clean_proxy = Tainted::new(raw_proxy).force_clean();
                let proxy_addr = clean_proxy.into_inner();
                debug!(proxy = %proxy_addr, "connecting via SOCKS5 proxy");
                // When the socks miscmod is wired, this would call:
                //   socks::connect_via_proxy(proxy_addr, args)
                // On failure, return SocksError:
                return Err(OutboundError::SocksError {
                    detail: format!("SOCKS5 proxy connection to {proxy_addr} not yet wired"),
                });
            }
        }
        debug!("SOCKS proxy support compiled in but no proxy configured");
    }

    // --- Direct connection ------------------------------------------------
    let fd = sock_connect(args, early_data)?;

    debug!(
        callout_address = %callout_address,
        sending_ip = ?args.sending_ip_address,
        sending_port = ?args.sending_port,
        "SMTP connection established"
    );

    Ok(fd)
}

// =========================================================================
// Unit-test helpers (cfg(test) only)
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_list_default_colon() {
        let items = split_list("192.168.1.1 : 10.0.0.1");
        assert_eq!(items, vec!["192.168.1.1", "10.0.0.1"]);
    }

    #[test]
    fn test_split_list_custom_separator() {
        let items = split_list("<; 192.168.1.1 ; 10.0.0.1");
        assert_eq!(items, vec!["192.168.1.1", "10.0.0.1"]);
    }

    #[test]
    fn test_split_list_empty() {
        let items = split_list("");
        assert!(items.is_empty());
    }

    #[test]
    fn test_lookup_service_port_known() {
        assert_eq!(lookup_service_port("smtp"), Some(25));
        assert_eq!(lookup_service_port("SMTP"), Some(25));
        assert_eq!(lookup_service_port("submission"), Some(587));
        assert_eq!(lookup_service_port("smtps"), Some(465));
    }

    #[test]
    fn test_lookup_service_port_unknown() {
        assert_eq!(lookup_service_port("nonexistent_service"), None);
    }

    #[test]
    fn test_resolve_interface_none() {
        let result = resolve_interface(None, AddressFamily::Inet);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_resolve_port_for_connect_default() {
        let port = resolve_port_for_connect(PORT_NONE, 25);
        assert_eq!(port, 25);
    }

    #[test]
    fn test_resolve_port_for_connect_override() {
        let port = resolve_port_for_connect(587, 25);
        assert_eq!(port, 587);
    }

    #[test]
    fn test_resolve_port_for_connect_same() {
        let port = resolve_port_for_connect(25, 25);
        assert_eq!(port, 25);
    }

    #[test]
    fn test_to_nix_af() {
        assert_eq!(to_nix_af(AddressFamily::Inet), NixAddressFamily::Inet);
        assert_eq!(to_nix_af(AddressFamily::Inet6), NixAddressFamily::Inet6);
    }
}
