//! DKIM (DomainKeys Identified Mail) verify/sign module.
//!
//! Stub providing type exports for crate compilation.
//! Full implementation pending from dedicated agent.

pub mod pdkim;
pub mod transport;

use std::fmt;

/// DKIM-specific error type.
#[derive(Debug)]
pub struct DkimError(String);

impl fmt::Display for DkimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for DkimError {}

/// DKIM verification/signing state.
#[derive(Debug, Clone, Default)]
pub struct DkimState {
    _private: (),
}

/// DKIM query code for expand_query results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkimQueryCode {
    /// Query succeeded.
    Ok,
    /// Query failed.
    Failed,
}

/// Initialize DKIM verification for an incoming message.
pub fn verify_init() -> Result<DkimState, DkimError> {
    Ok(DkimState::default())
}

/// Feed message body data into the DKIM verifier.
pub fn verify_feed(_state: &mut DkimState, _data: &[u8]) -> Result<(), DkimError> {
    Ok(())
}

/// Finalize DKIM verification and produce results.
pub fn verify_finish(_state: &mut DkimState) -> Result<(), DkimError> {
    Ok(())
}

/// Pause DKIM verification (for pipelining).
pub fn verify_pause(_state: &mut DkimState) -> Result<(), DkimError> {
    Ok(())
}

/// ACL entry point for DKIM verification results.
pub fn acl_entry(_state: &DkimState) -> Result<(), DkimError> {
    Ok(())
}

/// Generate Authentication-Results header for DKIM.
pub fn authres_dkim(_state: &DkimState) -> Result<String, DkimError> {
    Ok(String::new())
}

/// Query expansion for DKIM state variables.
pub fn expand_query(_state: &DkimState, _query: &str) -> Result<String, DkimError> {
    Ok(String::new())
}

/// Sign a message with DKIM.
pub fn dkim_sign(_data: &[u8]) -> Result<String, DkimError> {
    Ok(String::new())
}

/// Initialize DKIM signing state.
pub fn sign_init() -> Result<DkimState, DkimError> {
    Ok(DkimState::default())
}

/// Reset DKIM state for a new SMTP transaction.
pub fn smtp_reset(_state: &mut DkimState) {}

/// Query DNS for a DKIM TXT record.
pub fn query_dns_txt(_domain: &str) -> Result<String, DkimError> {
    Ok(String::new())
}

/// Set a DKIM variable value.
pub fn set_var(_name: &str, _value: &str) -> Result<(), DkimError> {
    Ok(())
}

/// Log all DKIM verification results.
pub fn verify_log_all(_state: &DkimState) {}
