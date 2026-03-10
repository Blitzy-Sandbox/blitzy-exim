//! Exim legacy filter language interpreter.
//!
//! Stub providing type exports for crate compilation.
//! Full implementation pending from dedicated agent.

use std::fmt;

/// Filter-specific error type.
#[derive(Debug)]
pub struct FilterError(String);

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for FilterError {}

/// Result of evaluating an Exim filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterResult {
    /// Filter delivered the message.
    Delivered,
    /// Filter deferred the message.
    Deferred,
    /// Filter failed.
    Failed,
    /// No action taken.
    NoAction,
}

/// Filter command representation.
#[derive(Debug, Clone)]
pub struct FilterCommand {
    _private: (),
}

/// Filter options controlling interpretation behavior.
#[derive(Debug, Clone, Default)]
pub struct FilterOptions {
    _private: (),
}

/// Interpret an Exim filter file.
pub fn exim_interpret(
    _filter: &str,
    _options: &FilterOptions,
) -> Result<FilterResult, FilterError> {
    Ok(FilterResult::NoAction)
}

/// Check whether a filter is a personal (user) filter.
pub fn is_personal_filter(_filter: &str) -> bool {
    false
}
