//! HAProxy PROXY protocol v1/v2 handler.
//!
//! Stub providing type exports for crate compilation.
//! Full implementation pending from dedicated agent.

use std::fmt;

/// Proxy-specific error type.
#[derive(Debug)]
pub struct ProxyError(String);

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ProxyError {}

/// Result of parsing a PROXY protocol header.
#[derive(Debug, Clone)]
pub struct ProxyResult {
    _private: (),
}

/// PROXY protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyVersion {
    /// PROXY protocol v1 (text).
    V1,
    /// PROXY protocol v2 (binary).
    V2,
}

/// Begin PROXY protocol processing on a connection.
pub fn proxy_protocol_start() -> Result<ProxyResult, ProxyError> {
    Ok(ProxyResult { _private: () })
}

/// Extract the real client host from PROXY protocol data.
pub fn proxy_protocol_host(_result: &ProxyResult) -> Result<String, ProxyError> {
    Ok(String::new())
}
