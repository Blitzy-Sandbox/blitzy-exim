//! DSCP (Differentiated Services Code Point) traffic marking.
//!
//! Stub providing type exports for crate compilation.
//! Full implementation pending from dedicated agent.

use std::fmt;

/// DSCP-specific error type.
#[derive(Debug)]
pub struct DscpError(String);

impl fmt::Display for DscpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for DscpError {}

/// DSCP configuration.
#[derive(Debug, Clone, Default)]
pub struct DscpConfig {
    _private: (),
}

/// Look up a DSCP value by keyword name.
pub fn dscp_lookup(_name: &str) -> Result<u8, DscpError> {
    Ok(0)
}

/// Set DSCP value on a socket.
pub fn dscp_set(_fd: i32, _value: u8) -> Result<(), DscpError> {
    Ok(())
}

/// Return list of known DSCP keywords.
pub fn dscp_keywords() -> &'static [(&'static str, u8)] {
    &[]
}
