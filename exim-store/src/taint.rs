// exim-store/src/taint.rs — Compile-Time Taint Tracking Newtypes
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Replaces Exim's **runtime** taint tracking with **compile-time** enforcement
// using Rust newtype wrappers at **zero runtime cost**.
//
// In the C codebase (store.c / store.h / functions.h):
//   - `GET_UNTAINTED = (const void*)0` and `GET_TAINTED = (const void*)1`
//     serve as sentinel values for taint state (store.h lines 82–83).
//   - Paired pools (`POOL_MAIN` / `POOL_TAINT_MAIN`, etc.) duplicate every
//     allocation pool to separate tainted from untainted memory (store.h 17–31).
//   - `is_tainted_fn()` performs an O(n) linear scan of all tainted pool blocks
//     to determine if a pointer refers to tainted memory (store.c 298–325).
//   - `die_tainted()` terminates the process on taint mismatch (store.c 328–333).
//   - `is_incompatible_fn()` checks taint class ordering for copy safety
//     (store.c 694–715).
//   - Wrapper functions for `Ustrcat`, `Ustrcpy`, etc. in functions.h (747–775)
//     call `die_tainted()` when writing tainted data into untainted buffers.
//
// The Rust replacement eliminates all of this at compile time:
//   - `Tainted<T>` wraps values derived from untrusted input.
//   - `Clean<T>` wraps values known to be safe.
//   - The type system prevents mixing tainted and clean data without explicit
//     conversion via `sanitize()` (validated) or `force_clean()` (escape hatch).
//   - `#[repr(transparent)]` ensures zero-cost representation identical to `T`.
//   - No runtime overhead: no pointer scanning, no sentinel checks, no pool
//     duplication.

use std::fmt;
use std::ops::Deref;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// TaintError — Error type for taint validation failures
// ---------------------------------------------------------------------------

/// Error returned when taint sanitization validation fails.
///
/// Replaces the C `die_tainted()` fatal error (store.c lines 328–333) with a
/// recoverable error that callers can handle gracefully. In the C codebase,
/// taint mismatches are always fatal (`log_write_die`); the Rust replacement
/// uses `Result<Clean<T>, TaintError>` to allow callers to decide how to
/// handle validation failures.
#[derive(Debug, thiserror::Error)]
#[error("taint validation failed: {context}")]
pub struct TaintError {
    /// Human-readable description of why validation failed.
    pub context: String,
}

impl TaintError {
    /// Creates a new `TaintError` with the given context message.
    pub fn new(context: impl Into<String>) -> Self {
        Self {
            context: context.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// TaintState — Dynamic taint status representation
// ---------------------------------------------------------------------------

/// Dynamic representation of taint status.
///
/// Replaces the C sentinel constants `GET_UNTAINTED = (const void*)0` and
/// `GET_TAINTED = (const void*)1` from store.h lines 82–83. Used in contexts
/// where taint status must be represented as a runtime value (e.g., driver
/// configuration, protocol negotiation) rather than enforced at compile time
/// via `Tainted<T>` / `Clean<T>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaintState {
    /// Data is known to be from a trusted source.
    /// Equivalent to `GET_UNTAINTED` in the C codebase.
    Untainted,

    /// Data originated from an untrusted external source.
    /// Equivalent to `GET_TAINTED` in the C codebase.
    Tainted,
}

impl fmt::Display for TaintState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TaintState::Untainted => write!(f, "untainted"),
            TaintState::Tainted => write!(f, "tainted"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tainted<T> — Wrapper for untrusted data
// ---------------------------------------------------------------------------

/// A newtype wrapper marking a value as **tainted** — derived from untrusted
/// external input.
///
/// In the C codebase, tainted data is tracked at runtime by allocating it from
/// tainted memory pools (`POOL_TAINT_MAIN`, `POOL_TAINT_PERM`, etc.) and
/// checking pointers via `is_tainted_fn()` — an O(n) scan of pool blocks
/// (store.c lines 298–325). The Rust `Tainted<T>` wrapper moves this tracking
/// to compile time with zero runtime cost.
///
/// # Type System Enforcement
///
/// - `Tainted<T>` does **not** implement [`Deref`], forcing callers to
///   explicitly handle tainted data rather than accidentally using it as `T`.
/// - To convert `Tainted<T>` to `Clean<T>`, callers must use either:
///   - [`sanitize()`](Tainted::sanitize) with a validation closure (preferred), or
///   - [`force_clean()`](Tainted::force_clean) as an escape hatch (audited).
/// - `Clean<T>` can always be "upcast" to `Tainted<T>` via [`From`].
///
/// # Zero-Cost Guarantee
///
/// `#[repr(transparent)]` ensures that `Tainted<T>` has identical memory
/// layout to `T`. There is no runtime overhead for wrapping or unwrapping.
///
/// # Examples
///
/// ```
/// use exim_store::taint::{Tainted, Clean};
///
/// // Data from SMTP input is tainted
/// let user_input = Tainted::new("user@example.com".to_string());
///
/// // Cannot use tainted data directly — must sanitize first
/// let clean = user_input.sanitize(|addr| addr.contains('@')).unwrap();
///
/// // Clean data can be used freely
/// assert_eq!(clean.into_inner(), "user@example.com");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct Tainted<T>(T);

impl<T> Tainted<T> {
    /// Creates a new `Tainted<T>` wrapping the given value.
    ///
    /// All data received from external untrusted sources (SMTP input, DNS
    /// responses, file reads, etc.) should be wrapped with this constructor.
    #[inline]
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Consumes the wrapper, returning the inner value.
    ///
    /// # Warning
    ///
    /// This method bypasses taint tracking entirely. Use sparingly and only
    /// when the caller has already verified the data through other means.
    /// Prefer [`sanitize()`](Self::sanitize) for validated extraction or
    /// [`AsRef::as_ref()`] for read-only access.
    #[inline]
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Transforms the inner value while preserving the tainted status.
    ///
    /// Applies the given function to the wrapped value and returns a new
    /// `Tainted<U>` — the result remains tainted because it was derived from
    /// tainted input. This is analogous to the C behavior where taint
    /// propagates through string operations (e.g., `string_vformat_trc()`
    /// recopies into tainted allocation when encountering a tainted `%s`
    /// argument).
    #[inline]
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Tainted<U> {
        Tainted(f(self.0))
    }

    /// Validates and converts tainted data to clean data.
    ///
    /// The `validator` closure inspects the inner value and returns `true` if
    /// the data is safe, or `false` if it should remain tainted. On success,
    /// the data is promoted to `Clean<T>`; on failure, a [`TaintError`] is
    /// returned.
    ///
    /// This is the **preferred** method for removing taint markers, replacing
    /// the implicit trust assumptions in the C codebase where `die_tainted()`
    /// was used as a last-resort guard.
    ///
    /// # Examples
    ///
    /// ```
    /// use exim_store::taint::Tainted;
    ///
    /// let input = Tainted::new("safe_value".to_string());
    /// let clean = input.sanitize(|s| !s.contains('\0')).unwrap();
    /// assert_eq!(clean.into_inner(), "safe_value");
    /// ```
    pub fn sanitize(self, validator: impl FnOnce(&T) -> bool) -> Result<Clean<T>, TaintError> {
        if validator(&self.0) {
            Ok(Clean(self.0))
        } else {
            Err(TaintError {
                context: String::from("sanitize validation rejected the tainted value"),
            })
        }
    }

    /// Forcibly removes the taint marker without validation.
    ///
    /// # ⚠️ Warning — Escape Hatch
    ///
    /// This method exists **only** for legacy compatibility during the C-to-Rust
    /// migration. Every call site should be reviewed and ideally replaced with
    /// [`sanitize()`](Self::sanitize) as the codebase matures.
    ///
    /// Each invocation is logged at `trace` level via the `tracing` crate to
    /// enable auditing of taint bypasses. In production, review `force_clean`
    /// audit logs to identify call sites that need proper validation.
    ///
    /// # Examples
    ///
    /// ```
    /// use exim_store::taint::Tainted;
    ///
    /// let tainted = Tainted::new(42);
    /// // AUDIT: force_clean used during migration — replace with sanitize()
    /// let clean = tainted.force_clean();
    /// assert_eq!(clean.into_inner(), 42);
    /// ```
    #[inline]
    pub fn force_clean(self) -> Clean<T> {
        tracing::trace!("force_clean() called — bypassing taint validation (audit trail)");
        Clean(self.0)
    }
}

// ---------------------------------------------------------------------------
// Clean<T> — Wrapper for trusted data
// ---------------------------------------------------------------------------

/// A newtype wrapper marking a value as **clean** — known to be from a trusted
/// source or validated through [`Tainted::sanitize()`].
///
/// In the C codebase, untainted data is any allocation from a non-tainted pool
/// (`POOL_MAIN`, `POOL_PERM`, `POOL_CONFIG`, `POOL_SEARCH`, `POOL_MESSAGE`).
/// The Rust `Clean<T>` wrapper provides compile-time proof that data is safe
/// to use in security-sensitive contexts.
///
/// # Type System Properties
///
/// - `Clean<T>` implements [`Deref`] targeting `T`, allowing transparent use
///   as `T` in most contexts. This is safe because clean data requires no
///   additional checks.
/// - `Clean<T>` can be "upcast" to `Tainted<T>` via [`From`] — clean data
///   is always a valid tainted input (the safe direction).
/// - `Clean<T>` does **not** implement [`Deserialize`] — all externally
///   deserialized data must be wrapped as `Tainted<T>` first.
///
/// # Zero-Cost Guarantee
///
/// `#[repr(transparent)]` ensures identical memory layout to `T`.
///
/// # Examples
///
/// ```
/// use exim_store::taint::Clean;
///
/// let config_value = Clean::new("localhost".to_string());
///
/// // Clean values can be used directly via Deref
/// assert!(config_value.starts_with("local"));
///
/// // Or extracted explicitly
/// let inner: String = config_value.into_inner();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct Clean<T>(T);

impl<T> Clean<T> {
    /// Creates a new `Clean<T>` wrapping a value known to be untainted.
    ///
    /// Use this constructor for values that originate from trusted sources:
    /// configuration constants, hardcoded defaults, locally computed results,
    /// or values that have been validated through [`Tainted::sanitize()`].
    #[inline]
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Consumes the wrapper, returning the inner value.
    #[inline]
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Transforms the inner value while preserving the clean status.
    ///
    /// The transformation function receives clean data and the result is also
    /// considered clean. This is appropriate when the transformation cannot
    /// introduce tainted data (e.g., lowercasing a clean string, computing a
    /// hash of clean input).
    #[inline]
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Clean<U> {
        Clean(f(self.0))
    }
}

// ---------------------------------------------------------------------------
// Conversion Traits
// ---------------------------------------------------------------------------

/// Clean data can always be "upcast" to tainted — the safe direction.
///
/// This reflects the C codebase's taint class ordering (store.c lines 696–704):
/// untainted (class 0) can always be treated as tainted (class 2) without
/// a copy, but the reverse requires explicit validation.
impl<T> From<Clean<T>> for Tainted<T> {
    #[inline]
    fn from(clean: Clean<T>) -> Self {
        Tainted(clean.0)
    }
}

// NOTE: `From<Tainted<T>> for Clean<T>` is intentionally NOT implemented.
// Tainted-to-clean conversion MUST go through `Tainted::sanitize()` or
// `Tainted::force_clean()` to enforce explicit validation.

// ---------------------------------------------------------------------------
// Display Implementations
// ---------------------------------------------------------------------------

/// In debug builds, tainted values are prefixed with `[TAINTED]` to make
/// taint status visible in log output and debug formatting. In release builds,
/// the display is a direct pass-through to avoid overhead.
impl<T: fmt::Display> fmt::Display for Tainted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if cfg!(debug_assertions) {
            write!(f, "[TAINTED]{}", self.0)
        } else {
            self.0.fmt(f)
        }
    }
}

/// Clean values display as their inner type — no prefix or annotation.
impl<T: fmt::Display> fmt::Display for Clean<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

// ---------------------------------------------------------------------------
// AsRef Implementations
// ---------------------------------------------------------------------------

impl<T> AsRef<T> for Tainted<T> {
    #[inline]
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T> AsRef<T> for Clean<T> {
    #[inline]
    fn as_ref(&self) -> &T {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Deref — ONLY for Clean<T>
// ---------------------------------------------------------------------------

/// `Clean<T>` implements [`Deref`] so that clean values can be used
/// transparently wherever `&T` is expected. This is safe because clean data
/// requires no additional taint checks.
///
/// `Tainted<T>` intentionally does **not** implement `Deref`, forcing callers
/// to explicitly acknowledge tainted data via [`Tainted::as_ref()`],
/// [`Tainted::sanitize()`], or [`Tainted::into_inner()`].
impl<T> Deref for Clean<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// String-Specific Convenience Methods
// ---------------------------------------------------------------------------

impl Tainted<String> {
    /// Borrows the tainted string as a `Tainted<&str>`.
    ///
    /// Equivalent to `String::as_str()` but preserves the taint wrapper.
    #[inline]
    pub fn as_str(&self) -> Tainted<&str> {
        Tainted(self.0.as_str())
    }
}

impl Clean<String> {
    /// Borrows the clean string as a `Clean<&str>`.
    ///
    /// Equivalent to `String::as_str()` but preserves the clean wrapper.
    #[inline]
    pub fn as_str(&self) -> Clean<&str> {
        Clean(self.0.as_str())
    }
}

// ---------------------------------------------------------------------------
// Type Aliases — String-Specific Convenience Types
// ---------------------------------------------------------------------------

/// Convenience alias for a tainted owned string.
///
/// Used throughout the MTA for SMTP input, DNS responses, and other untrusted
/// data that has not yet been validated.
pub type TaintedString = Tainted<String>;

/// Convenience alias for a clean owned string.
///
/// Used for configuration values, hardcoded constants, and validated data.
pub type CleanString = Clean<String>;

/// Convenience alias for a tainted borrowed string slice.
pub type TaintedStr<'a> = Tainted<&'a str>;

/// Convenience alias for a clean borrowed string slice.
pub type CleanStr<'a> = Clean<&'a str>;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tainted_new_and_into_inner() {
        let t = Tainted::new(42);
        assert_eq!(t.into_inner(), 42);
    }

    #[test]
    fn tainted_as_ref_returns_reference() {
        let t = Tainted::new("hello".to_string());
        assert_eq!(t.as_ref(), "hello");
    }

    #[test]
    fn tainted_map_preserves_taint() {
        let t = Tainted::new(10);
        let doubled = t.map(|x| x * 2);
        assert_eq!(doubled.into_inner(), 20);
    }

    #[test]
    fn sanitize_accepts_valid_value() {
        let t = Tainted::new("safe".to_string());
        let clean = t.sanitize(|s| !s.is_empty()).unwrap();
        assert_eq!(clean.into_inner(), "safe");
    }

    #[test]
    fn sanitize_rejects_invalid_value() {
        let t = Tainted::new("".to_string());
        let result = t.sanitize(|s| !s.is_empty());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.context.contains("sanitize validation rejected"));
    }

    #[test]
    fn force_clean_converts_without_validation() {
        let t = Tainted::new(99);
        let clean = t.force_clean();
        assert_eq!(clean.into_inner(), 99);
    }

    #[test]
    fn clean_new_and_into_inner() {
        let c = Clean::new("trusted".to_string());
        assert_eq!(c.into_inner(), "trusted");
    }

    #[test]
    fn clean_as_ref_returns_reference() {
        let c = Clean::new(42);
        assert_eq!(c.as_ref(), &42);
    }

    #[test]
    fn clean_map_preserves_cleanliness() {
        let c = Clean::new(5);
        let tripled = c.map(|x| x * 3);
        assert_eq!(tripled.into_inner(), 15);
    }

    #[test]
    fn clean_deref_allows_transparent_use() {
        let c = Clean::new("hello".to_string());
        // Deref allows calling String methods directly
        assert!(c.starts_with("hel"));
        assert_eq!(c.len(), 5);
    }

    #[test]
    fn from_clean_to_tainted() {
        let c = Clean::new(42);
        let t: Tainted<i32> = Tainted::from(c);
        assert_eq!(t.into_inner(), 42);
    }

    #[test]
    fn from_clean_to_tainted_via_into() {
        let c = Clean::new("data".to_string());
        let t: Tainted<String> = c.into();
        assert_eq!(t.into_inner(), "data");
    }

    #[test]
    fn tainted_display_debug_build() {
        let t = Tainted::new("secret");
        let display = format!("{t}");
        // In debug builds (test mode), should prefix with [TAINTED]
        if cfg!(debug_assertions) {
            assert!(display.starts_with("[TAINTED]"));
            assert!(display.contains("secret"));
        } else {
            assert_eq!(display, "secret");
        }
    }

    #[test]
    fn clean_display_passthrough() {
        let c = Clean::new("visible");
        assert_eq!(format!("{c}"), "visible");
    }

    #[test]
    fn taint_state_enum_variants() {
        assert_ne!(TaintState::Untainted, TaintState::Tainted);
        assert_eq!(TaintState::Untainted, TaintState::Untainted);
        assert_eq!(TaintState::Tainted, TaintState::Tainted);
    }

    #[test]
    fn taint_state_display() {
        assert_eq!(format!("{}", TaintState::Untainted), "untainted");
        assert_eq!(format!("{}", TaintState::Tainted), "tainted");
    }

    #[test]
    fn taint_error_display() {
        let err = TaintError::new("bad input detected");
        assert_eq!(
            format!("{err}"),
            "taint validation failed: bad input detected"
        );
    }

    #[test]
    fn tainted_string_as_str() {
        let ts: TaintedString = Tainted::new("hello".to_string());
        let borrowed: TaintedStr<'_> = ts.as_str();
        assert_eq!(*borrowed.as_ref(), "hello");
    }

    #[test]
    fn clean_string_as_str() {
        let cs: CleanString = Clean::new("world".to_string());
        let borrowed: CleanStr<'_> = cs.as_str();
        assert_eq!(*borrowed.as_ref(), "world");
    }

    #[test]
    fn tainted_clone_preserves_taint() {
        let t = Tainted::new(vec![1, 2, 3]);
        let t2 = t.clone();
        assert_eq!(t, t2);
    }

    #[test]
    fn clean_clone_preserves_cleanliness() {
        let c = Clean::new(vec![4, 5, 6]);
        let c2 = c.clone();
        assert_eq!(c, c2);
    }

    #[test]
    fn tainted_hash_is_consistent() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Tainted::new("key1".to_string()));
        set.insert(Tainted::new("key2".to_string()));
        set.insert(Tainted::new("key1".to_string()));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn clean_hash_is_consistent() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Clean::new(10));
        set.insert(Clean::new(20));
        set.insert(Clean::new(10));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn serde_tainted_serialize_deserialize_roundtrip() {
        let original = Tainted::new("test_value".to_string());
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, "\"test_value\"");

        let deserialized: Tainted<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, original);
    }

    #[test]
    fn serde_clean_serialize_only() {
        let clean = Clean::new(42);
        let json = serde_json::to_string(&clean).unwrap();
        assert_eq!(json, "42");
        // Note: Clean<T> intentionally does NOT implement Deserialize.
        // All deserialized external data should be Tainted<T>.
    }

    #[test]
    fn taint_state_copy_semantics() {
        let state = TaintState::Tainted;
        let copy = state;
        assert_eq!(state, copy);
    }

    #[test]
    fn sanitize_with_complex_validator() {
        let email = Tainted::new("user@example.com".to_string());
        let clean = email
            .sanitize(|addr| addr.contains('@') && !addr.contains('\0') && addr.len() < 256)
            .unwrap();
        assert_eq!(clean.into_inner(), "user@example.com");
    }

    #[test]
    fn multiple_map_operations_preserve_taint() {
        let t = Tainted::new("  hello  ".to_string());
        let trimmed = t.map(|s| s.trim().to_string());
        let upper = trimmed.map(|s| s.to_uppercase());
        assert_eq!(upper.into_inner(), "HELLO");
    }

    #[test]
    fn as_ref_trait_on_tainted() {
        let t = Tainted::new(100);
        let r: &i32 = AsRef::<i32>::as_ref(&t);
        assert_eq!(*r, 100);
    }

    #[test]
    fn as_ref_trait_on_clean() {
        let c = Clean::new(200);
        let r: &i32 = AsRef::<i32>::as_ref(&c);
        assert_eq!(*r, 200);
    }
}
