// Copyright (c) The Exim Maintainers 2020 - 2025
// Copyright (c) University of Cambridge 1995 - 2018
// SPDX-License-Identifier: GPL-2.0-or-later

//! # ACL Phase Definitions
//!
//! This is the **most foundational module** in the `exim-acl` crate. It defines:
//!
//! - [`AclWhere`] — An enum representing the SMTP/processing phase where an ACL is evaluated
//!   (replaces C `ACL_WHERE_*` enum from `macros.h` lines 964–993).
//!
//! - [`AclBitSet`] — A bitmask type representing a set of ACL phases, used by the
//!   forbids/permits system to control which conditions can appear in which phases
//!   (replaces C `FORBIDDEN()`/`PERMITTED()` macros from `acl.c` lines 141–142).
//!
//! - `BIT_*` constants — Named bitmask constants for each phase, replacing C `ACL_BIT_*`
//!   defines from `macros.h` lines 995–1023.
//!
//! - [`BITS_HAVEDATA`] — Composite bitmask of phases where the message body data is available,
//!   replacing C `ACL_BITS_HAVEDATA` from `macros.h` lines 1025–1027.
//!
//! - [`forbidden`] and [`permitted`] — Builder functions for constructing `AclBitSet` values,
//!   replacing the C macros of the same name.
//!
//! These types are consumed by every other module in the `exim-acl` crate: conditions use
//! `AclBitSet` for their forbids field, the engine uses `AclWhere` for phase dispatch, and
//! the log system uses `AclWhere::name()` for human-readable log output.

use std::fmt;
use std::ops;

// =============================================================================
// AclWhere Enum — SMTP/Processing Phases
// =============================================================================

/// SMTP/processing phase where an ACL is evaluated.
///
/// Replaces the C `ACL_WHERE_*` anonymous enum (`macros.h` lines 964–993).
///
/// Each variant corresponds to a specific point in SMTP transaction processing
/// or non-SMTP message reception where ACL policy checks are applied. The
/// discriminant values are fixed via `#[repr(u8)]` with explicit assignments
/// to match the C enum positions exactly, even when feature-gated variants
/// (`Prdr`, `Wellknown`) are disabled.
///
/// # Log Compatibility
///
/// The [`AclWhere::name()`] method returns strings that exactly match the
/// C `acl_wherenames[]` array in `globals.c` — this is critical for log
/// format compatibility per AAP §0.7.1. Existing log parsers like `exigrep`
/// and `eximstats` depend on these exact strings.
///
/// # Ordering
///
/// The ordering is significant: phases with discriminant values ≤
/// [`AclWhere::NotSmtp`] are "in-message" phases where a message is being
/// received. This is tested via `where_phase as u8 <= AclWhere::NotSmtp as u8`
/// in the C code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AclWhere {
    /// After `RCPT TO` command — the most commonly used ACL phase.
    /// Many access controls (domains, local_parts, recipients) are tested here.
    Rcpt = 0,

    /// After `MAIL FROM` command — sender-level policy checks.
    Mail = 1,

    /// After all recipients accepted, before `DATA` — pre-data ACL.
    Predata = 2,

    /// During MIME parsing of the message body (content scanning phase).
    Mime = 3,

    /// After DKIM verification of a received message.
    Dkim = 4,

    /// After `DATA`/`BDAT` — the full message body has been received.
    Data = 5,

    /// Per-Recipient Data Response (PRDR extension, RFC pending).
    /// Only compiled when the `prdr` feature is enabled.
    /// C guard: `#ifndef DISABLE_PRDR`
    #[cfg(feature = "prdr")]
    Prdr = 6,

    /// Non-SMTP message reception (e.g., local injection via `sendmail -t`).
    /// All phases with discriminant ≤ this value are "in-message" phases.
    NotSmtp = 7,

    /// After `AUTH` command — authentication phase.
    Auth = 8,

    /// After `ATRN` command (Authenticated Turn — on-demand mail relay).
    Atrn = 9,

    /// At initial SMTP connection, before any command is received.
    Connect = 10,

    /// After `ETRN` command (Extended Turn — queue run request).
    Etrn = 11,

    /// After `EXPN` command (mailing list expansion query).
    Expn = 12,

    /// After `HELO` or `EHLO` command — greeting phase.
    Helo = 13,

    /// For `MAIL FROM` `AUTH=` parameter validation (RFC 4954 §4).
    Mailauth = 14,

    /// Start of non-SMTP message processing, before `NotSmtp`.
    NotSmtpStart = 15,

    /// SMTP session close (QUIT or connection drop) — cannot reject.
    /// This ACL runs for informational/logging purposes only.
    NotQuit = 16,

    /// After `QUIT` command — cannot reject.
    /// This ACL runs for informational/logging purposes only.
    Quit = 17,

    /// After `STARTTLS` command — TLS negotiation phase.
    StartTls = 18,

    /// `WELLKNOWN` SMTP extension (experimental).
    /// Only compiled when the `wellknown` feature is enabled.
    /// C guard: `#ifndef DISABLE_WELLKNOWN`
    #[cfg(feature = "wellknown")]
    Wellknown = 19,

    /// After `VRFY` command (address verification query).
    Vrfy = 20,

    /// During local delivery (post-routing), for per-delivery ACL checks.
    Delivery = 21,

    /// Unknown/unset phase — sentinel value.
    /// Currently used by `${acl:name}` expansion when no specific phase applies.
    Unknown = 22,
}

// =============================================================================
// AclWhere — Static Phase Arrays (feature-gated)
// =============================================================================

/// All defined ACL phases in discriminant order (both `prdr` and `wellknown` enabled).
#[cfg(all(feature = "prdr", feature = "wellknown"))]
static ALL_PHASES: &[AclWhere] = &[
    AclWhere::Rcpt,
    AclWhere::Mail,
    AclWhere::Predata,
    AclWhere::Mime,
    AclWhere::Dkim,
    AclWhere::Data,
    AclWhere::Prdr,
    AclWhere::NotSmtp,
    AclWhere::Auth,
    AclWhere::Atrn,
    AclWhere::Connect,
    AclWhere::Etrn,
    AclWhere::Expn,
    AclWhere::Helo,
    AclWhere::Mailauth,
    AclWhere::NotSmtpStart,
    AclWhere::NotQuit,
    AclWhere::Quit,
    AclWhere::StartTls,
    AclWhere::Wellknown,
    AclWhere::Vrfy,
    AclWhere::Delivery,
    AclWhere::Unknown,
];

/// All defined ACL phases in discriminant order (`prdr` enabled, `wellknown` disabled).
#[cfg(all(feature = "prdr", not(feature = "wellknown")))]
static ALL_PHASES: &[AclWhere] = &[
    AclWhere::Rcpt,
    AclWhere::Mail,
    AclWhere::Predata,
    AclWhere::Mime,
    AclWhere::Dkim,
    AclWhere::Data,
    AclWhere::Prdr,
    AclWhere::NotSmtp,
    AclWhere::Auth,
    AclWhere::Atrn,
    AclWhere::Connect,
    AclWhere::Etrn,
    AclWhere::Expn,
    AclWhere::Helo,
    AclWhere::Mailauth,
    AclWhere::NotSmtpStart,
    AclWhere::NotQuit,
    AclWhere::Quit,
    AclWhere::StartTls,
    AclWhere::Vrfy,
    AclWhere::Delivery,
    AclWhere::Unknown,
];

/// All defined ACL phases in discriminant order (`prdr` disabled, `wellknown` enabled).
#[cfg(all(not(feature = "prdr"), feature = "wellknown"))]
static ALL_PHASES: &[AclWhere] = &[
    AclWhere::Rcpt,
    AclWhere::Mail,
    AclWhere::Predata,
    AclWhere::Mime,
    AclWhere::Dkim,
    AclWhere::Data,
    AclWhere::NotSmtp,
    AclWhere::Auth,
    AclWhere::Atrn,
    AclWhere::Connect,
    AclWhere::Etrn,
    AclWhere::Expn,
    AclWhere::Helo,
    AclWhere::Mailauth,
    AclWhere::NotSmtpStart,
    AclWhere::NotQuit,
    AclWhere::Quit,
    AclWhere::StartTls,
    AclWhere::Wellknown,
    AclWhere::Vrfy,
    AclWhere::Delivery,
    AclWhere::Unknown,
];

/// All defined ACL phases in discriminant order (both `prdr` and `wellknown` disabled).
#[cfg(all(not(feature = "prdr"), not(feature = "wellknown")))]
static ALL_PHASES: &[AclWhere] = &[
    AclWhere::Rcpt,
    AclWhere::Mail,
    AclWhere::Predata,
    AclWhere::Mime,
    AclWhere::Dkim,
    AclWhere::Data,
    AclWhere::NotSmtp,
    AclWhere::Auth,
    AclWhere::Atrn,
    AclWhere::Connect,
    AclWhere::Etrn,
    AclWhere::Expn,
    AclWhere::Helo,
    AclWhere::Mailauth,
    AclWhere::NotSmtpStart,
    AclWhere::NotQuit,
    AclWhere::Quit,
    AclWhere::StartTls,
    AclWhere::Vrfy,
    AclWhere::Delivery,
    AclWhere::Unknown,
];

// =============================================================================
// AclWhere — Methods
// =============================================================================

impl AclWhere {
    /// Returns the bitmask for this phase: `1u32 << (self as u8)`.
    ///
    /// This is the Rust equivalent of the C `ACL_BIT_*` macros:
    /// ```c
    /// #define ACL_BIT_RCPT BIT(ACL_WHERE_RCPT)
    /// ```
    /// where `BIT(n)` expands to `(1u << (n))`.
    ///
    /// The result can be combined with `|` to build bitmask sets for the
    /// forbids/permits system.
    pub const fn bit(self) -> u32 {
        1u32 << (self as u8)
    }

    /// Returns the human-readable phase name string matching the C
    /// `acl_wherenames[]` array in `globals.c`.
    ///
    /// # Log Format Compatibility
    ///
    /// These strings MUST match the C source exactly for log format
    /// compatibility per AAP §0.7.1. Existing tools like `exigrep` and
    /// `eximstats` parse these strings from Exim log output.
    ///
    /// The strings were verified against `globals.c` lines 451–478.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Rcpt => "RCPT",
            Self::Mail => "MAIL",
            Self::Predata => "PREDATA",
            Self::Mime => "MIME",
            Self::Dkim => "DKIM",
            Self::Data => "DATA",
            #[cfg(feature = "prdr")]
            Self::Prdr => "PRDR",
            Self::NotSmtp => "non-SMTP",
            Self::Auth => "AUTH",
            Self::Atrn => "ATRN",
            Self::Connect => "connection",
            Self::Etrn => "ETRN",
            Self::Expn => "EXPN",
            Self::Helo => "EHLO or HELO",
            Self::Mailauth => "MAILAUTH",
            Self::NotSmtpStart => "non-SMTP-start",
            Self::NotQuit => "NOTQUIT",
            Self::Quit => "QUIT",
            Self::StartTls => "STARTTLS",
            #[cfg(feature = "wellknown")]
            Self::Wellknown => "WELLKNOWN",
            Self::Vrfy => "VRFY",
            Self::Delivery => "delivery",
            Self::Unknown => "unknown",
        }
    }

    /// Parses a phase name string into an [`AclWhere`] variant.
    ///
    /// This performs case-insensitive matching against the canonical
    /// `acl_wherenames[]` strings and also accepts common alternative
    /// forms used in configuration files.
    ///
    /// Returns `None` if the name does not match any known phase.
    pub fn from_name(name: &str) -> Option<AclWhere> {
        // Case-insensitive linear search through all phases, mirroring the
        // C code's linear search through acl_wherenames[].
        ALL_PHASES
            .iter()
            .find(|phase| phase.name().eq_ignore_ascii_case(name))
            .copied()
    }

    /// Returns a static slice of all defined ACL phases in discriminant order.
    ///
    /// The number of phases depends on active Cargo features:
    /// - With `prdr` and `wellknown`: 23 phases
    /// - With `prdr` only: 22 phases
    /// - With `wellknown` only: 22 phases
    /// - With neither: 21 phases
    pub fn all() -> &'static [AclWhere] {
        ALL_PHASES
    }

    /// Returns the total number of defined ACL phases.
    ///
    /// This varies with active Cargo features (see [`AclWhere::all()`]).
    pub fn count() -> usize {
        ALL_PHASES.len()
    }

    /// Converts a discriminant index to an `AclWhere` variant.
    ///
    /// Returns `None` if the index does not correspond to a defined variant,
    /// including indices for feature-gated variants that are currently disabled.
    ///
    /// # Example
    ///
    /// ```
    /// # use exim_acl::phases::AclWhere;
    /// assert_eq!(AclWhere::from_index(0), Some(AclWhere::Rcpt));
    /// assert_eq!(AclWhere::from_index(22), Some(AclWhere::Unknown));
    /// assert_eq!(AclWhere::from_index(255), None);
    /// ```
    pub const fn from_index(index: u8) -> Option<AclWhere> {
        match index {
            0 => Some(Self::Rcpt),
            1 => Some(Self::Mail),
            2 => Some(Self::Predata),
            3 => Some(Self::Mime),
            4 => Some(Self::Dkim),
            5 => Some(Self::Data),
            #[cfg(feature = "prdr")]
            6 => Some(Self::Prdr),
            7 => Some(Self::NotSmtp),
            8 => Some(Self::Auth),
            9 => Some(Self::Atrn),
            10 => Some(Self::Connect),
            11 => Some(Self::Etrn),
            12 => Some(Self::Expn),
            13 => Some(Self::Helo),
            14 => Some(Self::Mailauth),
            15 => Some(Self::NotSmtpStart),
            16 => Some(Self::NotQuit),
            17 => Some(Self::Quit),
            18 => Some(Self::StartTls),
            #[cfg(feature = "wellknown")]
            19 => Some(Self::Wellknown),
            20 => Some(Self::Vrfy),
            21 => Some(Self::Delivery),
            22 => Some(Self::Unknown),
            _ => None,
        }
    }
}

// =============================================================================
// Display Trait for AclWhere
// =============================================================================

impl fmt::Display for AclWhere {
    /// Formats the phase as its human-readable name string.
    ///
    /// Delegates to [`AclWhere::name()`] to ensure log format compatibility
    /// with C Exim's `acl_wherenames[]` array.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// =============================================================================
// BIT_* Named Constants — ACL Phase Bitmasks
// =============================================================================
//
// These constants replace the C `ACL_BIT_*` defines from `macros.h` lines
// 995–1023. Each constant equals `1u32 << AclWhere::Variant as u8`.
//
// They exist as named constants for readability when constructing forbids
// bitmaps in the conditions table (see `conditions.rs`).

/// Bitmask for the `RCPT` phase. Replaces C `ACL_BIT_RCPT`.
pub const BIT_RCPT: u32 = 1 << (AclWhere::Rcpt as u8);

/// Bitmask for the `MAIL` phase. Replaces C `ACL_BIT_MAIL`.
pub const BIT_MAIL: u32 = 1 << (AclWhere::Mail as u8);

/// Bitmask for the `PREDATA` phase. Replaces C `ACL_BIT_PREDATA`.
pub const BIT_PREDATA: u32 = 1 << (AclWhere::Predata as u8);

/// Bitmask for the `MIME` phase. Replaces C `ACL_BIT_MIME`.
pub const BIT_MIME: u32 = 1 << (AclWhere::Mime as u8);

/// Bitmask for the `DKIM` phase. Replaces C `ACL_BIT_DKIM`.
pub const BIT_DKIM: u32 = 1 << (AclWhere::Dkim as u8);

/// Bitmask for the `DATA` phase. Replaces C `ACL_BIT_DATA`.
pub const BIT_DATA: u32 = 1 << (AclWhere::Data as u8);

/// Bitmask for the `PRDR` phase. Replaces C `ACL_BIT_PRDR`.
/// Only defined when the `prdr` feature is enabled.
/// When `prdr` is disabled, C defines `ACL_BIT_PRDR` as `0`.
#[cfg(feature = "prdr")]
pub const BIT_PRDR: u32 = 1 << (AclWhere::Prdr as u8);

/// Bitmask for the `NOTSMTP` phase. Replaces C `ACL_BIT_NOTSMTP`.
pub const BIT_NOTSMTP: u32 = 1 << (AclWhere::NotSmtp as u8);

/// Bitmask for the `AUTH` phase. Replaces C `ACL_BIT_AUTH`.
pub const BIT_AUTH: u32 = 1 << (AclWhere::Auth as u8);

/// Bitmask for the `ATRN` phase. Replaces C `ACL_BIT_ATRN`.
pub const BIT_ATRN: u32 = 1 << (AclWhere::Atrn as u8);

/// Bitmask for the `CONNECT` phase. Replaces C `ACL_BIT_CONNECT`.
pub const BIT_CONNECT: u32 = 1 << (AclWhere::Connect as u8);

/// Bitmask for the `ETRN` phase. Replaces C `ACL_BIT_ETRN`.
pub const BIT_ETRN: u32 = 1 << (AclWhere::Etrn as u8);

/// Bitmask for the `EXPN` phase. Replaces C `ACL_BIT_EXPN`.
pub const BIT_EXPN: u32 = 1 << (AclWhere::Expn as u8);

/// Bitmask for the `HELO` phase. Replaces C `ACL_BIT_HELO`.
pub const BIT_HELO: u32 = 1 << (AclWhere::Helo as u8);

/// Bitmask for the `MAILAUTH` phase. Replaces C `ACL_BIT_MAILAUTH`.
pub const BIT_MAILAUTH: u32 = 1 << (AclWhere::Mailauth as u8);

/// Bitmask for the `NOTSMTP_START` phase. Replaces C `ACL_BIT_NOTSMTP_START`.
pub const BIT_NOTSMTP_START: u32 = 1 << (AclWhere::NotSmtpStart as u8);

/// Bitmask for the `NOTQUIT` phase. Replaces C `ACL_BIT_NOTQUIT`.
pub const BIT_NOTQUIT: u32 = 1 << (AclWhere::NotQuit as u8);

/// Bitmask for the `QUIT` phase. Replaces C `ACL_BIT_QUIT`.
pub const BIT_QUIT: u32 = 1 << (AclWhere::Quit as u8);

/// Bitmask for the `STARTTLS` phase. Replaces C `ACL_BIT_STARTTLS`.
pub const BIT_STARTTLS: u32 = 1 << (AclWhere::StartTls as u8);

/// Bitmask for the `WELLKNOWN` phase. Replaces C `ACL_BIT_WELLKNOWN`.
/// Only defined when the `wellknown` feature is enabled.
#[cfg(feature = "wellknown")]
pub const BIT_WELLKNOWN: u32 = 1 << (AclWhere::Wellknown as u8);

/// Bitmask for the `VRFY` phase. Replaces C `ACL_BIT_VRFY`.
pub const BIT_VRFY: u32 = 1 << (AclWhere::Vrfy as u8);

/// Bitmask for the `DELIVERY` phase. Replaces C `ACL_BIT_DELIVERY`.
pub const BIT_DELIVERY: u32 = 1 << (AclWhere::Delivery as u8);

/// Bitmask for the `UNKNOWN` phase. Replaces C `ACL_BIT_UNKNOWN`.
pub const BIT_UNKNOWN: u32 = 1 << (AclWhere::Unknown as u8);

// =============================================================================
// AclBitSet — Phase Bitmask Type
// =============================================================================

/// A bitmask representing a set of ACL phases.
///
/// This type is used for the `forbids` field in condition definitions to
/// specify which phases a condition is NOT allowed in. It replaces the raw
/// `unsigned` bitmask fields and the `FORBIDDEN()`/`PERMITTED()` macros
/// from `acl.c` lines 141–142.
///
/// # Forbids/Permits Semantics
///
/// In the forbids system, a set bit means the condition is **forbidden**
/// in that phase:
/// - `forbids(phase)` returns `true` if the bit for `phase` is set
///   (condition cannot be used in that phase).
/// - `permits(phase)` returns `true` if the bit for `phase` is NOT set
///   (condition can be used in that phase).
///
/// # Construction
///
/// Use [`forbidden()`] or [`permitted()`] functions for ergonomic construction:
/// ```
/// # use exim_acl::phases::*;
/// let set = forbidden(BIT_CONNECT | BIT_HELO);
/// assert!(set.forbids(AclWhere::Connect));
/// assert!(set.permits(AclWhere::Rcpt));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct AclBitSet(u32);

impl AclBitSet {
    /// The empty set — no phases included. All phases are permitted.
    pub const EMPTY: Self = Self(0);

    /// Checks if a specific phase is in this set (bit is set).
    ///
    /// Returns `true` if the phase's bit position is set in the bitmask.
    pub const fn contains(&self, phase: AclWhere) -> bool {
        self.0 & phase.bit() != 0
    }

    /// Creates a new `AclBitSet` from a raw `u32` bitmask.
    ///
    /// This is the primary constructor used by the [`forbidden()`] and
    /// [`permitted()`] functions and by the `BIT_*` constant combinations.
    pub const fn from_raw(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns the union of two sets (phases in either set).
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns the intersection of two sets (phases in both sets).
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Returns the complement of this set (all phases NOT in this set).
    pub const fn complement(self) -> Self {
        Self(!self.0)
    }

    /// Checks if this set **forbids** a given phase.
    ///
    /// In the forbids system, a set bit means the condition is NOT allowed
    /// in that phase. This method returns `true` when the phase's bit is set.
    pub const fn forbids(&self, phase: AclWhere) -> bool {
        self.contains(phase)
    }

    /// Checks if this set **permits** a given phase.
    ///
    /// In the forbids system, an unset bit means the condition IS allowed
    /// in that phase. This method returns `true` when the phase's bit is
    /// NOT set — the inverse of [`AclBitSet::forbids()`].
    pub const fn permits(&self, phase: AclWhere) -> bool {
        !self.contains(phase)
    }
}

// =============================================================================
// Operator Trait Implementations for AclBitSet
// =============================================================================

impl ops::BitOr for AclBitSet {
    type Output = Self;

    /// Computes the union of two `AclBitSet` values via the `|` operator.
    ///
    /// # Example
    ///
    /// ```
    /// # use exim_acl::phases::*;
    /// let a = AclBitSet::from_raw(BIT_RCPT);
    /// let b = AclBitSet::from_raw(BIT_MAIL);
    /// let combined = a | b;
    /// assert!(combined.contains(AclWhere::Rcpt));
    /// assert!(combined.contains(AclWhere::Mail));
    /// ```
    fn bitor(self, rhs: Self) -> Self::Output {
        self.union(rhs)
    }
}

impl ops::BitAnd for AclBitSet {
    type Output = Self;

    /// Computes the intersection of two `AclBitSet` values via the `&` operator.
    fn bitand(self, rhs: Self) -> Self::Output {
        self.intersection(rhs)
    }
}

impl ops::BitOrAssign for AclBitSet {
    /// Performs union-assignment via the `|=` operator.
    ///
    /// # Example
    ///
    /// ```
    /// # use exim_acl::phases::*;
    /// let mut set = AclBitSet::from_raw(BIT_RCPT);
    /// set |= AclBitSet::from_raw(BIT_MAIL);
    /// assert!(set.contains(AclWhere::Mail));
    /// ```
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl From<AclWhere> for AclBitSet {
    /// Creates an `AclBitSet` containing a single phase.
    fn from(phase: AclWhere) -> Self {
        Self(phase.bit())
    }
}

// =============================================================================
// BITS_HAVEDATA — Composite Constant
// =============================================================================

/// Bitmask of phases where the message body data is available.
///
/// Replaces C `ACL_BITS_HAVEDATA` (`macros.h` lines 1025–1027):
/// ```c
/// #define ACL_BITS_HAVEDATA (ACL_BIT_MIME | ACL_BIT_DKIM | ACL_BIT_DATA
///                            | ACL_BIT_PRDR
///                            | ACL_BIT_NOTSMTP | ACL_BIT_QUIT | ACL_BIT_NOTQUIT)
/// ```
///
/// This constant is used to restrict conditions that require message body
/// access (like content-scan conditions: `malware`, `spam`, `regex`,
/// `mime_regex`) to phases after `DATA` has been received.
///
/// # Feature Gating
///
/// When the `prdr` feature is disabled, `BIT_PRDR` is excluded (mirroring
/// C's `ACL_BIT_PRDR = 0` when `DISABLE_PRDR` is defined).
#[cfg(feature = "prdr")]
pub const BITS_HAVEDATA: AclBitSet = AclBitSet::from_raw(
    BIT_MIME | BIT_DKIM | BIT_DATA | BIT_PRDR | BIT_NOTSMTP | BIT_QUIT | BIT_NOTQUIT,
);

/// Bitmask of phases where the message body data is available (without PRDR).
#[cfg(not(feature = "prdr"))]
pub const BITS_HAVEDATA: AclBitSet =
    AclBitSet::from_raw(BIT_MIME | BIT_DKIM | BIT_DATA | BIT_NOTSMTP | BIT_QUIT | BIT_NOTQUIT);

// =============================================================================
// forbidden() / permitted() — Builder Functions
// =============================================================================

/// Creates an [`AclBitSet`] representing phases where a condition is **forbidden**.
///
/// Replaces the C `FORBIDDEN()` macro (`acl.c` line 141):
/// ```c
/// #define FORBIDDEN(times) (times)
/// ```
///
/// The input `bits` is a raw bitmask where each set bit represents a phase
/// where the condition CANNOT be used. A value of `0` means the condition
/// is allowed in all phases.
///
/// # Example
///
/// ```
/// # use exim_acl::phases::*;
/// // Condition forbidden in CONNECT and HELO phases:
/// let set = forbidden(BIT_CONNECT | BIT_HELO);
/// assert!(set.forbids(AclWhere::Connect));
/// assert!(set.forbids(AclWhere::Helo));
/// assert!(set.permits(AclWhere::Rcpt));
/// ```
pub const fn forbidden(bits: u32) -> AclBitSet {
    AclBitSet::from_raw(bits)
}

/// Creates an [`AclBitSet`] from **permitted** phases (all other phases are forbidden).
///
/// Replaces the C `PERMITTED()` macro (`acl.c` line 142):
/// ```c
/// #define PERMITTED(times) ((unsigned) ~(times))
/// ```
///
/// The input `bits` is a raw bitmask where each set bit represents a phase
/// where the condition CAN be used. All other phases are forbidden.
///
/// # Example
///
/// ```
/// # use exim_acl::phases::*;
/// // Condition only permitted in RCPT and DATA phases:
/// let set = permitted(BIT_RCPT | BIT_DATA);
/// assert!(set.permits(AclWhere::Rcpt));
/// assert!(set.permits(AclWhere::Data));
/// assert!(set.forbids(AclWhere::Connect));
/// assert!(set.forbids(AclWhere::Helo));
/// ```
pub const fn permitted(bits: u32) -> AclBitSet {
    AclBitSet::from_raw(!bits)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── AclWhere Discriminant Tests ─────────────────────────────────

    #[test]
    fn discriminant_values_match_c_enum() {
        assert_eq!(AclWhere::Rcpt as u8, 0);
        assert_eq!(AclWhere::Mail as u8, 1);
        assert_eq!(AclWhere::Predata as u8, 2);
        assert_eq!(AclWhere::Mime as u8, 3);
        assert_eq!(AclWhere::Dkim as u8, 4);
        assert_eq!(AclWhere::Data as u8, 5);
        #[cfg(feature = "prdr")]
        assert_eq!(AclWhere::Prdr as u8, 6);
        assert_eq!(AclWhere::NotSmtp as u8, 7);
        assert_eq!(AclWhere::Auth as u8, 8);
        assert_eq!(AclWhere::Atrn as u8, 9);
        assert_eq!(AclWhere::Connect as u8, 10);
        assert_eq!(AclWhere::Etrn as u8, 11);
        assert_eq!(AclWhere::Expn as u8, 12);
        assert_eq!(AclWhere::Helo as u8, 13);
        assert_eq!(AclWhere::Mailauth as u8, 14);
        assert_eq!(AclWhere::NotSmtpStart as u8, 15);
        assert_eq!(AclWhere::NotQuit as u8, 16);
        assert_eq!(AclWhere::Quit as u8, 17);
        assert_eq!(AclWhere::StartTls as u8, 18);
        #[cfg(feature = "wellknown")]
        assert_eq!(AclWhere::Wellknown as u8, 19);
        assert_eq!(AclWhere::Vrfy as u8, 20);
        assert_eq!(AclWhere::Delivery as u8, 21);
        assert_eq!(AclWhere::Unknown as u8, 22);
    }

    // ── AclWhere Name Tests ─────────────────────────────────────────

    #[test]
    fn phase_names_match_c_acl_wherenames() {
        // These strings were verified against globals.c lines 451–478.
        assert_eq!(AclWhere::Rcpt.name(), "RCPT");
        assert_eq!(AclWhere::Mail.name(), "MAIL");
        assert_eq!(AclWhere::Predata.name(), "PREDATA");
        assert_eq!(AclWhere::Mime.name(), "MIME");
        assert_eq!(AclWhere::Dkim.name(), "DKIM");
        assert_eq!(AclWhere::Data.name(), "DATA");
        #[cfg(feature = "prdr")]
        assert_eq!(AclWhere::Prdr.name(), "PRDR");
        assert_eq!(AclWhere::NotSmtp.name(), "non-SMTP");
        assert_eq!(AclWhere::Auth.name(), "AUTH");
        assert_eq!(AclWhere::Atrn.name(), "ATRN");
        assert_eq!(AclWhere::Connect.name(), "connection");
        assert_eq!(AclWhere::Etrn.name(), "ETRN");
        assert_eq!(AclWhere::Expn.name(), "EXPN");
        assert_eq!(AclWhere::Helo.name(), "EHLO or HELO");
        assert_eq!(AclWhere::Mailauth.name(), "MAILAUTH");
        assert_eq!(AclWhere::NotSmtpStart.name(), "non-SMTP-start");
        assert_eq!(AclWhere::NotQuit.name(), "NOTQUIT");
        assert_eq!(AclWhere::Quit.name(), "QUIT");
        assert_eq!(AclWhere::StartTls.name(), "STARTTLS");
        #[cfg(feature = "wellknown")]
        assert_eq!(AclWhere::Wellknown.name(), "WELLKNOWN");
        assert_eq!(AclWhere::Vrfy.name(), "VRFY");
        assert_eq!(AclWhere::Delivery.name(), "delivery");
        assert_eq!(AclWhere::Unknown.name(), "unknown");
    }

    #[test]
    fn display_trait_matches_name() {
        assert_eq!(format!("{}", AclWhere::Rcpt), "RCPT");
        assert_eq!(format!("{}", AclWhere::Connect), "connection");
        assert_eq!(format!("{}", AclWhere::Helo), "EHLO or HELO");
        assert_eq!(format!("{}", AclWhere::Unknown), "unknown");
    }

    // ── AclWhere::from_name Tests ───────────────────────────────────

    #[test]
    fn from_name_exact_match() {
        assert_eq!(AclWhere::from_name("RCPT"), Some(AclWhere::Rcpt));
        assert_eq!(AclWhere::from_name("connection"), Some(AclWhere::Connect));
        assert_eq!(AclWhere::from_name("EHLO or HELO"), Some(AclWhere::Helo));
        assert_eq!(AclWhere::from_name("non-SMTP"), Some(AclWhere::NotSmtp));
        assert_eq!(AclWhere::from_name("delivery"), Some(AclWhere::Delivery));
        assert_eq!(AclWhere::from_name("unknown"), Some(AclWhere::Unknown));
    }

    #[test]
    fn from_name_case_insensitive() {
        assert_eq!(AclWhere::from_name("rcpt"), Some(AclWhere::Rcpt));
        assert_eq!(AclWhere::from_name("Connection"), Some(AclWhere::Connect));
        assert_eq!(AclWhere::from_name("ehlo or helo"), Some(AclWhere::Helo));
    }

    #[test]
    fn from_name_unknown_returns_none() {
        assert_eq!(AclWhere::from_name("NONEXISTENT"), None);
        assert_eq!(AclWhere::from_name(""), None);
        assert_eq!(AclWhere::from_name("SMTP"), None);
    }

    // ── AclWhere::from_index Tests ──────────────────────────────────

    #[test]
    fn from_index_valid_indices() {
        assert_eq!(AclWhere::from_index(0), Some(AclWhere::Rcpt));
        assert_eq!(AclWhere::from_index(5), Some(AclWhere::Data));
        assert_eq!(AclWhere::from_index(7), Some(AclWhere::NotSmtp));
        assert_eq!(AclWhere::from_index(22), Some(AclWhere::Unknown));
    }

    #[test]
    fn from_index_invalid_returns_none() {
        assert_eq!(AclWhere::from_index(23), None);
        assert_eq!(AclWhere::from_index(255), None);
    }

    #[test]
    #[cfg(not(feature = "prdr"))]
    fn from_index_prdr_disabled_returns_none() {
        assert_eq!(AclWhere::from_index(6), None);
    }

    #[test]
    #[cfg(feature = "prdr")]
    fn from_index_prdr_enabled_returns_some() {
        assert_eq!(AclWhere::from_index(6), Some(AclWhere::Prdr));
    }

    // ── AclWhere::all() and count() Tests ───────────────────────────

    #[test]
    fn all_phases_count_is_consistent() {
        assert_eq!(AclWhere::all().len(), AclWhere::count());
    }

    #[test]
    fn all_phases_are_in_discriminant_order() {
        let phases = AclWhere::all();
        for window in phases.windows(2) {
            assert!(
                (window[0] as u8) < (window[1] as u8),
                "Phase {:?} (={}) should come before {:?} (={})",
                window[0],
                window[0] as u8,
                window[1],
                window[1] as u8
            );
        }
    }

    #[test]
    fn all_phases_first_and_last() {
        let phases = AclWhere::all();
        assert_eq!(phases.first(), Some(&AclWhere::Rcpt));
        assert_eq!(phases.last(), Some(&AclWhere::Unknown));
    }

    // ── BIT_* Constant Tests ────────────────────────────────────────

    #[test]
    fn bit_constants_match_shift_values() {
        assert_eq!(BIT_RCPT, 1 << 0);
        assert_eq!(BIT_MAIL, 1 << 1);
        assert_eq!(BIT_PREDATA, 1 << 2);
        assert_eq!(BIT_MIME, 1 << 3);
        assert_eq!(BIT_DKIM, 1 << 4);
        assert_eq!(BIT_DATA, 1 << 5);
        #[cfg(feature = "prdr")]
        assert_eq!(BIT_PRDR, 1 << 6);
        assert_eq!(BIT_NOTSMTP, 1 << 7);
        assert_eq!(BIT_AUTH, 1 << 8);
        assert_eq!(BIT_ATRN, 1 << 9);
        assert_eq!(BIT_CONNECT, 1 << 10);
        assert_eq!(BIT_ETRN, 1 << 11);
        assert_eq!(BIT_EXPN, 1 << 12);
        assert_eq!(BIT_HELO, 1 << 13);
        assert_eq!(BIT_MAILAUTH, 1 << 14);
        assert_eq!(BIT_NOTSMTP_START, 1 << 15);
        assert_eq!(BIT_NOTQUIT, 1 << 16);
        assert_eq!(BIT_QUIT, 1 << 17);
        assert_eq!(BIT_STARTTLS, 1 << 18);
        #[cfg(feature = "wellknown")]
        assert_eq!(BIT_WELLKNOWN, 1 << 19);
        assert_eq!(BIT_VRFY, 1 << 20);
        assert_eq!(BIT_DELIVERY, 1 << 21);
        assert_eq!(BIT_UNKNOWN, 1 << 22);
    }

    #[test]
    fn bit_method_matches_constants() {
        assert_eq!(AclWhere::Rcpt.bit(), BIT_RCPT);
        assert_eq!(AclWhere::Mail.bit(), BIT_MAIL);
        assert_eq!(AclWhere::Data.bit(), BIT_DATA);
        assert_eq!(AclWhere::Connect.bit(), BIT_CONNECT);
        assert_eq!(AclWhere::Unknown.bit(), BIT_UNKNOWN);
    }

    // ── AclBitSet Tests ─────────────────────────────────────────────

    #[test]
    fn empty_set_permits_everything() {
        let set = AclBitSet::EMPTY;
        for &phase in AclWhere::all() {
            assert!(set.permits(phase), "EMPTY should permit {:?}", phase);
            assert!(!set.forbids(phase), "EMPTY should not forbid {:?}", phase);
        }
    }

    #[test]
    fn single_phase_set() {
        let set = AclBitSet::from_raw(BIT_RCPT);
        assert!(set.contains(AclWhere::Rcpt));
        assert!(set.forbids(AclWhere::Rcpt));
        assert!(set.permits(AclWhere::Mail));
        assert!(!set.contains(AclWhere::Data));
    }

    #[test]
    fn union_combines_sets() {
        let a = AclBitSet::from_raw(BIT_RCPT);
        let b = AclBitSet::from_raw(BIT_MAIL);
        let combined = a.union(b);
        assert!(combined.contains(AclWhere::Rcpt));
        assert!(combined.contains(AclWhere::Mail));
        assert!(!combined.contains(AclWhere::Data));
    }

    #[test]
    fn intersection_finds_common_phases() {
        let a = AclBitSet::from_raw(BIT_RCPT | BIT_MAIL | BIT_DATA);
        let b = AclBitSet::from_raw(BIT_MAIL | BIT_DATA | BIT_CONNECT);
        let common = a.intersection(b);
        assert!(!common.contains(AclWhere::Rcpt));
        assert!(common.contains(AclWhere::Mail));
        assert!(common.contains(AclWhere::Data));
        assert!(!common.contains(AclWhere::Connect));
    }

    #[test]
    fn complement_inverts_set() {
        let set = AclBitSet::from_raw(BIT_RCPT);
        let comp = set.complement();
        assert!(!comp.contains(AclWhere::Rcpt));
        assert!(comp.contains(AclWhere::Mail));
        assert!(comp.contains(AclWhere::Data));
    }

    #[test]
    fn bitor_operator_works() {
        let a = AclBitSet::from_raw(BIT_RCPT);
        let b = AclBitSet::from_raw(BIT_MAIL);
        let combined = a | b;
        assert!(combined.contains(AclWhere::Rcpt));
        assert!(combined.contains(AclWhere::Mail));
    }

    #[test]
    fn bitand_operator_works() {
        let a = AclBitSet::from_raw(BIT_RCPT | BIT_MAIL);
        let b = AclBitSet::from_raw(BIT_MAIL | BIT_DATA);
        let result = a & b;
        assert!(!result.contains(AclWhere::Rcpt));
        assert!(result.contains(AclWhere::Mail));
        assert!(!result.contains(AclWhere::Data));
    }

    #[test]
    fn bitor_assign_operator_works() {
        let mut set = AclBitSet::from_raw(BIT_RCPT);
        set |= AclBitSet::from_raw(BIT_MAIL);
        assert!(set.contains(AclWhere::Rcpt));
        assert!(set.contains(AclWhere::Mail));
    }

    #[test]
    fn from_acl_where_creates_single_phase_set() {
        let set = AclBitSet::from(AclWhere::Data);
        assert!(set.contains(AclWhere::Data));
        assert!(!set.contains(AclWhere::Rcpt));
    }

    // ── BITS_HAVEDATA Tests ─────────────────────────────────────────

    #[test]
    fn bits_havedata_contains_expected_phases() {
        // These phases should always be in BITS_HAVEDATA (from macros.h 1025-1027)
        assert!(BITS_HAVEDATA.contains(AclWhere::Mime));
        assert!(BITS_HAVEDATA.contains(AclWhere::Dkim));
        assert!(BITS_HAVEDATA.contains(AclWhere::Data));
        assert!(BITS_HAVEDATA.contains(AclWhere::NotSmtp));
        assert!(BITS_HAVEDATA.contains(AclWhere::Quit));
        assert!(BITS_HAVEDATA.contains(AclWhere::NotQuit));

        // These phases should NOT be in BITS_HAVEDATA
        assert!(!BITS_HAVEDATA.contains(AclWhere::Rcpt));
        assert!(!BITS_HAVEDATA.contains(AclWhere::Mail));
        assert!(!BITS_HAVEDATA.contains(AclWhere::Connect));
        assert!(!BITS_HAVEDATA.contains(AclWhere::Helo));
        assert!(!BITS_HAVEDATA.contains(AclWhere::Auth));
    }

    #[test]
    #[cfg(feature = "prdr")]
    fn bits_havedata_includes_prdr_when_enabled() {
        assert!(BITS_HAVEDATA.contains(AclWhere::Prdr));
    }

    // ── forbidden() / permitted() Tests ─────────────────────────────

    #[test]
    fn forbidden_creates_forbids_set() {
        let set = forbidden(BIT_CONNECT | BIT_HELO);
        assert!(set.forbids(AclWhere::Connect));
        assert!(set.forbids(AclWhere::Helo));
        assert!(set.permits(AclWhere::Rcpt));
        assert!(set.permits(AclWhere::Data));
    }

    #[test]
    fn forbidden_zero_permits_everything() {
        let set = forbidden(0);
        for &phase in AclWhere::all() {
            assert!(set.permits(phase));
        }
    }

    #[test]
    fn permitted_creates_inverted_set() {
        let set = permitted(BIT_RCPT | BIT_DATA);
        assert!(set.permits(AclWhere::Rcpt));
        assert!(set.permits(AclWhere::Data));
        assert!(set.forbids(AclWhere::Connect));
        assert!(set.forbids(AclWhere::Helo));
        assert!(set.forbids(AclWhere::Mail));
    }

    #[test]
    fn permitted_matches_c_behavior_for_add_header() {
        // From acl.c lines 150-156: add_header is PERMITTED in these phases
        #[cfg(feature = "prdr")]
        let set = permitted(
            BIT_MAIL
                | BIT_RCPT
                | BIT_PREDATA
                | BIT_DATA
                | BIT_PRDR
                | BIT_MIME
                | BIT_NOTSMTP
                | BIT_DKIM
                | BIT_NOTSMTP_START,
        );
        #[cfg(not(feature = "prdr"))]
        let set = permitted(
            BIT_MAIL
                | BIT_RCPT
                | BIT_PREDATA
                | BIT_DATA
                | BIT_MIME
                | BIT_NOTSMTP
                | BIT_DKIM
                | BIT_NOTSMTP_START,
        );
        assert!(set.permits(AclWhere::Rcpt));
        assert!(set.permits(AclWhere::Mail));
        assert!(set.permits(AclWhere::Data));
        assert!(set.forbids(AclWhere::Connect));
        assert!(set.forbids(AclWhere::Helo));
        assert!(set.forbids(AclWhere::Auth));
    }

    #[test]
    fn forbidden_matches_c_behavior_for_authenticated() {
        // From acl.c lines 163-166: authenticated is FORBIDDEN in these phases
        let set = forbidden(BIT_NOTSMTP | BIT_NOTSMTP_START | BIT_CONNECT | BIT_HELO);
        assert!(set.forbids(AclWhere::NotSmtp));
        assert!(set.forbids(AclWhere::NotSmtpStart));
        assert!(set.forbids(AclWhere::Connect));
        assert!(set.forbids(AclWhere::Helo));
        assert!(set.permits(AclWhere::Rcpt));
        assert!(set.permits(AclWhere::Mail));
        assert!(set.permits(AclWhere::Auth));
    }
}
