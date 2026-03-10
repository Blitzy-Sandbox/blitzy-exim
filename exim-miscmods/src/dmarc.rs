//! DMARC validation via libopendmarc FFI.
//!
//! Stub providing type exports for crate compilation.
//! Full implementation pending from dedicated agent.

use std::fmt;

/// DMARC-specific error type.
#[derive(Debug)]
pub struct DmarcError(String);

impl fmt::Display for DmarcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for DmarcError {}

/// DMARC policy disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcPolicy {
    /// No policy (unspecified).
    Unspecified,
    /// No action.
    None,
    /// Quarantine.
    Quarantine,
    /// Reject.
    Reject,
}

/// DMARC identifier alignment mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcAlignment {
    /// Relaxed alignment.
    Relaxed,
    /// Strict alignment.
    Strict,
}

/// DMARC processing state.
#[derive(Debug, Clone, Default)]
pub struct DmarcState {
    _private: (),
}

/// Initialize DMARC processing library.
pub fn dmarc_init() -> Result<DmarcState, DmarcError> {
    Ok(DmarcState::default())
}

/// Initialize per-message DMARC state.
pub fn dmarc_msg_init(_state: &mut DmarcState) -> Result<(), DmarcError> {
    Ok(())
}

/// Process DMARC for a message.
pub fn dmarc_process(_state: &mut DmarcState) -> Result<DmarcPolicy, DmarcError> {
    Ok(DmarcPolicy::Unspecified)
}

/// Check DMARC result against a list.
pub fn dmarc_result_inlist(_state: &DmarcState, _list: &str) -> bool {
    false
}
