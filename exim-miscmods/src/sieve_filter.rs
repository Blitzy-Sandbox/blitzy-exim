//! RFC 5228 Sieve filter interpreter with extensions.
//!
//! Stub providing type exports for crate compilation.
//! Full implementation pending from dedicated agent.

use std::fmt;

/// Sieve-specific error type.
#[derive(Debug)]
pub struct SieveError(String);

impl fmt::Display for SieveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for SieveError {}

/// Result of evaluating a Sieve script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SieveResult {
    /// Script kept the message (implicit or explicit keep).
    Keep,
    /// Script discarded the message.
    Discard,
    /// Script redirected the message.
    Redirect,
    /// Script deferred processing.
    Deferred,
}

/// Sieve extension capabilities.
#[derive(Debug, Clone, Default)]
pub struct SieveCapabilities {
    _private: (),
}

/// Sieve command representation.
#[derive(Debug, Clone)]
pub struct SieveCommand {
    _private: (),
}

/// Sieve test expression representation.
#[derive(Debug, Clone)]
pub struct SieveTest {
    _private: (),
}

/// Sieve match type for comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchType {
    /// Exact `:is` match.
    Is,
    /// Substring `:contains` match.
    Contains,
    /// Glob-style `:matches` match.
    Matches,
}

/// Sieve comparator selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparator {
    /// ASCII case-sensitive.
    OctetExact,
    /// ASCII case-insensitive.
    AsciiCaseMap,
}

/// Interpret a Sieve filter script.
pub fn sieve_interpret(_script: &str) -> Result<SieveResult, SieveError> {
    Ok(SieveResult::Keep)
}

/// Return supported Sieve extensions.
pub fn sieve_extensions() -> &'static [&'static str] {
    &[]
}
