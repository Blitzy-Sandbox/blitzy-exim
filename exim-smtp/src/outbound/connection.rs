//! Outbound SMTP connection management.
//!
//! Stub module — provides type signatures for mod.rs re-exports.
//! Will be replaced by the implementation agent.

use std::net::IpAddr;

use super::{AddressFamily, ClientConnCtx, OutboundError, SmtpConnectArgs, TfoState};

/// Establish an outbound SMTP connection using the given arguments.
///
/// High-level entry point that creates a socket, optionally binds to a local
/// interface, connects to the remote host, and applies keepalive/TFO settings.
pub fn smtp_connect(_args: &mut SmtpConnectArgs) -> Result<ClientConnCtx, OutboundError> {
    Err(OutboundError::ConnectionFailed {
        reason: "not yet implemented".into(),
    })
}

/// Resolve the local interface name to a bind address.
///
/// Expands the interface string from transport configuration and resolves it
/// to an IP address suitable for `bind()`.
pub fn resolve_interface(_interface: &str, _af: AddressFamily) -> Result<IpAddr, OutboundError> {
    Err(OutboundError::ConfigError {
        detail: "not yet implemented".into(),
    })
}

/// Resolve a service name or numeric string to a port number.
///
/// Used to parse the `port` transport option, accepting either numeric ports
/// or well-known service names via `getservbyname()`.
pub fn resolve_port(_port_str: &str) -> Result<u16, OutboundError> {
    Err(OutboundError::ConfigError {
        detail: "not yet implemented".into(),
    })
}

/// Create a socket bound to a specific local interface and port.
pub fn create_bound_socket(
    _af: AddressFamily,
    _interface: Option<&str>,
    _port: u16,
) -> Result<i32, OutboundError> {
    Err(OutboundError::ConnectionFailed {
        reason: "not yet implemented".into(),
    })
}

/// Connect an existing socket to the remote host.
pub fn sock_connect(
    _sock: i32,
    _addr: &IpAddr,
    _port: u16,
    _timeout: std::time::Duration,
) -> Result<(), OutboundError> {
    Err(OutboundError::ConnectionFailed {
        reason: "not yet implemented".into(),
    })
}

/// Resolve the port to use for a connection, considering transport config
/// and host-specific overrides.
pub fn resolve_port_for_connect(host_port: u16, default_port: u16) -> u16 {
    if host_port != 0 {
        host_port
    } else {
        default_port
    }
}

/// Check TCP Fast Open availability and update state.
pub fn tfo_out_check(_sock: i32) -> TfoState {
    TfoState::NotUsed
}
