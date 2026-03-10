//! ARC (Authenticated Received Chain) verify/sign module (RFC 8617).
//!
//! Stub providing type exports for crate compilation.
//! Full implementation pending from dedicated agent.

use std::fmt;

/// ARC-specific error type.
#[derive(Debug)]
pub struct ArcError(String);

impl fmt::Display for ArcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ArcError {}

/// ARC chain state.
#[derive(Debug, Clone, Default)]
pub struct ArcState {
    _private: (),
}

/// ARC seal set.
#[derive(Debug, Clone, Default)]
pub struct ArcSet {
    _private: (),
}

/// ARC header line representation.
#[derive(Debug, Clone)]
pub struct ArcLine {
    _private: (),
}

/// ARC Chain Validation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArcCV {
    /// Chain is valid.
    Pass,
    /// Chain is invalid.
    Fail,
    /// No ARC headers present.
    None,
}

/// ARC signing options.
#[derive(Debug, Clone, Default)]
pub struct ArcSignOptions {
    _private: (),
}

/// Verify ARC chain in message headers.
pub fn arc_verify(_state: &mut ArcState) -> Result<ArcCV, ArcError> {
    Ok(ArcCV::None)
}

/// Feed a header line into ARC processing.
pub fn arc_header_feed(_state: &mut ArcState, _header: &str) -> Result<(), ArcError> {
    Ok(())
}

/// Initialize ARC signing state.
pub fn arc_sign_init(_options: &ArcSignOptions) -> Result<ArcState, ArcError> {
    Ok(ArcState::default())
}

/// Generate ARC seal headers.
pub fn arc_sign(_state: &ArcState) -> Result<String, ArcError> {
    Ok(String::new())
}

/// Query ARC set information.
pub fn arc_set_info(_state: &ArcState) -> Result<Vec<ArcSet>, ArcError> {
    Ok(Vec::new())
}
