//! Native DMARC parser — experimental pure-Rust implementation.
//!
//! Stub providing type exports for crate compilation.
//! Full implementation pending from dedicated agent.

use std::fmt;

/// DMARC-specific error type (native variant).
#[derive(Debug)]
pub struct DmarcError(String);

impl fmt::Display for DmarcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for DmarcError {}

/// Parsed DMARC DNS record.
#[derive(Debug, Clone, Default)]
pub struct DmarcRecord {
    _private: (),
}

/// DMARC policy disposition (native variant).
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

/// DMARC identifier alignment mode (native variant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcAlignment {
    /// Relaxed alignment.
    Relaxed,
    /// Strict alignment.
    Strict,
}

/// Process DMARC for a message using native parser.
pub fn dmarc_process() -> Result<DmarcPolicy, DmarcError> {
    Ok(DmarcPolicy::Unspecified)
}

/// Check DMARC result against a list using native parser.
pub fn dmarc_result_inlist(_list: &str) -> bool {
    false
}
