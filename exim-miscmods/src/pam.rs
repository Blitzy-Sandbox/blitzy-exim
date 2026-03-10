//! PAM (Pluggable Authentication Modules) authentication.
//!
//! Stub providing type exports for crate compilation.
//! Full implementation pending from dedicated agent.

use std::fmt;

/// PAM-specific error type.
#[derive(Debug)]
pub struct PamError(String);

impl fmt::Display for PamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for PamError {}

/// PAM authenticator context.
#[derive(Debug)]
pub struct PamAuthenticator {
    _private: (),
}

/// Perform PAM authentication.
pub fn pam_auth_call(_user: &str, _password: &str) -> Result<(), PamError> {
    Ok(())
}
