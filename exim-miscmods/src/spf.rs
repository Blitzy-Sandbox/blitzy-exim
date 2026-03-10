//! SPF (Sender Policy Framework) validation module.
//!
//! Stub providing type exports for crate compilation.
//! Full implementation pending from dedicated agent.

use std::fmt;

/// SPF-specific error type.
#[derive(Debug)]
pub struct SpfError(String);

impl fmt::Display for SpfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for SpfError {}

/// SPF evaluation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpfResult {
    /// SPF check passed.
    Pass,
    /// SPF check failed.
    Fail,
    /// Soft fail.
    SoftFail,
    /// Neutral.
    Neutral,
    /// No SPF record.
    None,
    /// Temporary error.
    TempError,
    /// Permanent error.
    PermError,
}

/// SPF processing state.
#[derive(Debug, Clone, Default)]
pub struct SpfState {
    _private: (),
}

/// Initialize SPF processing for a new connection.
pub fn spf_conn_init() -> Result<SpfState, SpfError> {
    Ok(SpfState::default())
}

/// Reset SPF state for a new SMTP transaction.
pub fn spf_reset(_state: &mut SpfState) {}

/// Process SPF check for a sender/IP combination.
pub fn spf_process(_state: &mut SpfState) -> Result<SpfResult, SpfError> {
    Ok(SpfResult::None)
}

/// SPF lookup for expand integration.
pub fn spf_find(_state: &SpfState, _key: &str) -> Result<String, SpfError> {
    Ok(String::new())
}

/// Close SPF state and release resources.
pub fn spf_close(_state: SpfState) {}

/// Report SPF library version.
pub fn spf_version_report() -> String {
    String::new()
}
