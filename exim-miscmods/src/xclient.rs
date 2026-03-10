//! Postfix XCLIENT SMTP extension handler.
//!
//! Stub providing type exports for crate compilation.
//! Full implementation pending from dedicated agent.

use std::fmt;

/// XCLIENT-specific error type.
#[derive(Debug)]
pub struct XclientError(String);

impl fmt::Display for XclientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for XclientError {}

/// XCLIENT command representation.
#[derive(Debug, Clone)]
pub struct XclientCommand {
    _private: (),
}

/// XCLIENT capability flags.
#[derive(Debug, Clone, Default)]
pub struct XclientCapabilities {
    _private: (),
}

/// XCLIENT response.
#[derive(Debug, Clone)]
pub struct XclientResponse {
    _private: (),
}

/// Advertise XCLIENT capability in EHLO response.
pub fn xclient_advertise(_caps: &XclientCapabilities) -> String {
    String::new()
}

/// Handle an XCLIENT command.
pub fn xclient_start(_command: &XclientCommand) -> Result<XclientResponse, XclientError> {
    Ok(XclientResponse { _private: () })
}
