//! RADIUS authentication.
//!
//! Stub providing type exports for crate compilation.
//! Full implementation pending from dedicated agent.

use std::fmt;

/// RADIUS-specific error type.
#[derive(Debug)]
pub struct RadiusError(String);

impl fmt::Display for RadiusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for RadiusError {}

/// Perform RADIUS authentication.
pub fn radius_auth_call(_user: &str, _password: &str) -> Result<(), RadiusError> {
    Ok(())
}
