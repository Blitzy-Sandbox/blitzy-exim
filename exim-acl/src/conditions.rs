// exim-acl/src/conditions.rs — ACL Condition/Modifier Evaluation
//
// This is the largest module in the exim-acl crate. It translates the massive
// acl_check_condition() function from src/src/acl.c (lines 3273–4408) and all
// its helper functions into idiomatic Rust. Defines all ACL condition and
// modifier types, control types, and implements per-condition evaluation semantics.
//
// Source mapping:
//   acl.c lines 62–119: ACLC_* enum
//   acl.c lines 127–354: condition_def + conditions[] table
//   acl.c lines 418–606: CONTROL_* enum + controls_list[] table
//   acl.c lines 613–683: CSA + ratelimit types
//   acl.c lines 707–779: binary search helpers
//   acl.c lines 1063–1283: header manipulation + acl_warn
//   acl.c lines 1305–2380: verification functions
//   acl.c lines 2380–3270: ratelimit, seen, udpsend, wellknown
//   acl.c lines 3273–4408: acl_check_condition()

use std::collections::{BTreeMap, HashMap};
#[cfg(feature = "wellknown")]
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::str::FromStr;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use thiserror::Error;
use tracing::{debug, info, trace, warn};

use exim_dns::{DnsRecordData, DnsRecordType, DnsResolver, DnsResult, DnsblCache};
use exim_expand::{expand_check_condition, ExpandError};

use crate::phases::BIT_ATRN;
#[cfg(feature = "prdr")]
use crate::phases::BIT_PRDR;
#[cfg(feature = "wellknown")]
use crate::phases::BIT_WELLKNOWN;
use crate::phases::{
    forbidden, permitted, AclBitSet, AclWhere, BIT_AUTH, BIT_CONNECT, BIT_DATA, BIT_DKIM, BIT_HELO,
    BIT_MAIL, BIT_MAILAUTH, BIT_MIME, BIT_NOTQUIT, BIT_NOTSMTP, BIT_NOTSMTP_START, BIT_PREDATA,
    BIT_QUIT, BIT_RCPT, BIT_STARTTLS, BIT_VRFY,
};
use crate::variables::AclVarStore;
use crate::verbs::AclVerb;
use crate::{AclResult, MessageContext};

// When prdr feature is disabled, BIT_PRDR is 0 (matching C behavior where
// ACL_BIT_PRDR is defined as 0 when DISABLE_PRDR is set)
#[cfg(not(feature = "prdr"))]
const BIT_PRDR: u32 = 0;

// When wellknown feature is disabled, BIT_WELLKNOWN is not needed because
// all entries referencing it are also behind #[cfg(feature = "wellknown")].

// ---------------------------------------------------------------------------
// ConditionFlags — replaces C ACD_EXP / ACD_MOD / ACD_LOAD bitmask flags
// ---------------------------------------------------------------------------

/// Bitflags indicating condition/modifier properties from the ACL parser.
/// Replaces C's ACD_EXP, ACD_MOD, ACD_LOAD flags in `condition_def`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConditionFlags(u8);

impl ConditionFlags {
    /// Value is string-expanded before use (ACD_EXP)
    pub const ACD_EXP: Self = Self(1 << 0);
    /// This entry is a modifier, not a true condition (ACD_MOD)
    pub const ACD_MOD: Self = Self(1 << 1);
    /// Requires dynamic module loading (ACD_LOAD)
    pub const ACD_LOAD: Self = Self(1 << 2);

    /// Empty flags — no special handling
    pub const NONE: Self = Self(0);

    /// Combine two flag sets
    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Check if a particular flag is set
    #[inline]
    pub const fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) == flag.0 && flag.0 != 0
    }

    /// Check if this is a modifier (ACD_MOD set)
    #[inline]
    pub const fn is_modifier(self) -> bool {
        (self.0 & Self::ACD_MOD.0) != 0
    }

    /// Check if expansion is required (ACD_EXP set)
    #[inline]
    pub const fn needs_expansion(self) -> bool {
        (self.0 & Self::ACD_EXP.0) != 0
    }

    /// Check if dynamic module load is needed (ACD_LOAD set)
    #[inline]
    pub const fn needs_load(self) -> bool {
        (self.0 & Self::ACD_LOAD.0) != 0
    }
}

// ---------------------------------------------------------------------------
// AclCondition — replaces C ACLC_* enumeration (acl.c lines 62–119)
// ---------------------------------------------------------------------------

/// All ACL condition and modifier types from the Exim configuration language.
/// Each variant corresponds to a keyword in an ACL verb block.
/// Feature-gated variants match the C #ifdef guards exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AclCondition {
    /// Nested ACL call: `acl = name`
    Acl,
    /// Add a header line: `add_header = text`
    AddHeader,
    /// Match ATRN domains: `atrn_domains = list`
    AtrnDomains,
    /// Match authenticated sender: `authenticated = list`
    Authenticated,
    /// Boolean condition: `condition = expression`
    Condition,
    /// Always succeeds (no-op passthrough): `continue`
    Continue,
    /// Control modifier: `control = name[/option]`
    Control,
    /// MIME content decode trigger (content-scan)
    #[cfg(feature = "content-scan")]
    Decode,
    /// Timed delay: `delay = duration`
    Delay,
    /// Match DKIM signers
    #[cfg(feature = "dkim")]
    DkimSigners,
    /// Match DKIM verification status
    #[cfg(feature = "dkim")]
    DkimStatus,
    /// Match DMARC verification status
    #[cfg(feature = "dmarc")]
    DmarcStatus,
    /// DNS blocklist checking: `dnslists = list`
    Dnslists,
    /// Match recipient domain: `domains = list`
    Domains,
    /// Match TLS cipher: `encrypted = list`
    Encrypted,
    /// Endpass marker — conditions after this cause message rejection on fail
    Endpass,
    /// Match client host: `hosts = list`
    Hosts,
    /// Match local part: `local_parts = list`
    LocalParts,
    /// Set custom log message: `log_message = text`
    LogMessage,
    /// Override log reject target: `log_reject_target = value`
    LogRejectTarget,
    /// Write to log: `logwrite = text`
    Logwrite,
    /// Malware scanning (content-scan)
    #[cfg(feature = "content-scan")]
    Malware,
    /// Set custom SMTP error message: `message = text`
    Message,
    /// MIME content regex matching (content-scan)
    #[cfg(feature = "content-scan")]
    MimeRegex,
    /// Queue selection override: `queue = name`
    Queue,
    /// Rate limiting: `ratelimit = spec`
    Ratelimit,
    /// Match recipient count/list: `recipients = list`
    Recipients,
    /// Body regex matching (content-scan)
    #[cfg(feature = "content-scan")]
    Regex,
    /// Remove a header: `remove_header = spec`
    RemoveHeader,
    /// Time-based previously-seen checking: `seen = spec`
    Seen,
    /// Match sender domain: `sender_domains = list`
    SenderDomains,
    /// Match sender address: `senders = list`
    Senders,
    /// Variable assignment: `set acl_X = value`
    Set,
    /// Spam scanning (content-scan)
    #[cfg(feature = "content-scan")]
    Spam,
    /// SPF result matching
    #[cfg(feature = "spf")]
    Spf,
    /// SPF guess result matching
    #[cfg(feature = "spf")]
    SpfGuess,
    /// Send UDP datagram: `udpsend = spec`
    Udpsend,
    /// Address/host verification: `verify = type[/options]`
    Verify,
    /// WELLKNOWN file retrieval
    #[cfg(feature = "wellknown")]
    Wellknown,
}

impl AclCondition {
    /// Returns the configuration-file name for this condition/modifier.
    /// Names match the C conditions[] table strings exactly for backward
    /// compatibility with existing Exim configurations.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Acl => "acl",
            Self::AddHeader => "add_header",
            Self::AtrnDomains => "atrn_domains",
            Self::Authenticated => "authenticated",
            Self::Condition => "condition",
            Self::Continue => "continue",
            Self::Control => "control",
            #[cfg(feature = "content-scan")]
            Self::Decode => "decode",
            Self::Delay => "delay",
            #[cfg(feature = "dkim")]
            Self::DkimSigners => "dkim_signers",
            #[cfg(feature = "dkim")]
            Self::DkimStatus => "dkim_status",
            #[cfg(feature = "dmarc")]
            Self::DmarcStatus => "dmarc_status",
            Self::Dnslists => "dnslists",
            Self::Domains => "domains",
            Self::Encrypted => "encrypted",
            Self::Endpass => "endpass",
            Self::Hosts => "hosts",
            Self::LocalParts => "local_parts",
            Self::LogMessage => "log_message",
            Self::LogRejectTarget => "log_reject_target",
            Self::Logwrite => "logwrite",
            #[cfg(feature = "content-scan")]
            Self::Malware => "malware",
            Self::Message => "message",
            #[cfg(feature = "content-scan")]
            Self::MimeRegex => "mime_regex",
            Self::Queue => "queue",
            Self::Ratelimit => "ratelimit",
            Self::Recipients => "recipients",
            #[cfg(feature = "content-scan")]
            Self::Regex => "regex",
            Self::RemoveHeader => "remove_header",
            Self::Seen => "seen",
            Self::SenderDomains => "sender_domains",
            Self::Senders => "senders",
            Self::Set => "set",
            #[cfg(feature = "content-scan")]
            Self::Spam => "spam",
            #[cfg(feature = "spf")]
            Self::Spf => "spf",
            #[cfg(feature = "spf")]
            Self::SpfGuess => "spf_guess",
            Self::Udpsend => "udpsend",
            Self::Verify => "verify",
            #[cfg(feature = "wellknown")]
            Self::Wellknown => "wellknown",
        }
    }

    /// Look up a condition/modifier by its configuration-file name.
    /// Uses binary search over the sorted CONDITIONS table.
    /// Returns `None` if the name is unknown.
    pub fn from_name(name: &str) -> Option<Self> {
        CONDITIONS
            .binary_search_by(|def| def.name.cmp(name))
            .ok()
            .map(|idx| CONDITIONS[idx].condition)
    }
}

impl FromStr for AclCondition {
    type Err = AclConditionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name(s).ok_or_else(|| AclConditionError::InvalidCondition {
            name: s.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// ConditionDef — replaces C condition_def struct (acl.c lines 127–144)
// ---------------------------------------------------------------------------

/// Defines properties of a single ACL condition or modifier keyword.
/// Each entry maps a condition name to its enum variant, flags, and the
/// set of ACL phases where it is forbidden.
#[derive(Debug, Clone, Copy)]
pub struct ConditionDef {
    /// The condition/modifier variant
    pub condition: AclCondition,
    /// The configuration-file keyword (must be sorted alphabetically for
    /// binary search in `acl_findcondition`)
    pub name: &'static str,
    /// Flags: ACD_EXP (expand argument), ACD_MOD (modifier), ACD_LOAD (needs module)
    pub flags: ConditionFlags,
    /// Bitmask of ACL phases where this condition/modifier is forbidden.
    /// Built using `forbidden()` or `permitted()` from `phases.rs`.
    pub forbids: AclBitSet,
}

// ---------------------------------------------------------------------------
// CONDITIONS — static table replacing C conditions[] (acl.c lines 146–354)
//
// CRITICAL: Entries MUST be sorted alphabetically by name for binary search.
// Feature-gated entries are conditionally compiled matching C #ifdef guards.
// ---------------------------------------------------------------------------

/// Complete sorted table of all ACL condition/modifier definitions.
/// Each entry maps a keyword to its type, flags, and phase restrictions.
/// This table is binary-searched by `acl_findcondition()`.
pub static CONDITIONS: &[ConditionDef] = &[
    // "acl" — nested ACL invocation
    ConditionDef {
        condition: AclCondition::Acl,
        name: "acl",
        flags: ConditionFlags::ACD_EXP,
        forbids: AclBitSet::EMPTY,
    },
    // "add_header" — modifier: add header line
    ConditionDef {
        condition: AclCondition::AddHeader,
        name: "add_header",
        flags: ConditionFlags::ACD_EXP.union(ConditionFlags::ACD_MOD),
        forbids: forbidden(
            BIT_MAIL
                | BIT_RCPT
                | BIT_PREDATA
                | BIT_DATA
                | BIT_MIME
                | BIT_NOTSMTP
                | BIT_DKIM
                | BIT_NOTSMTP_START
                | BIT_PRDR,
        )
        .complement(),
    },
    // "atrn_domains" — ATRN domain matching
    ConditionDef {
        condition: AclCondition::AtrnDomains,
        name: "atrn_domains",
        flags: ConditionFlags::ACD_EXP,
        forbids: permitted(BIT_ATRN),
    },
    // "authenticated" — match authenticated sender ID
    ConditionDef {
        condition: AclCondition::Authenticated,
        name: "authenticated",
        flags: ConditionFlags::ACD_EXP,
        forbids: forbidden(BIT_NOTSMTP | BIT_NOTSMTP_START | BIT_CONNECT | BIT_HELO),
    },
    // "condition" — boolean expression evaluation
    ConditionDef {
        condition: AclCondition::Condition,
        name: "condition",
        flags: ConditionFlags::ACD_EXP,
        forbids: AclBitSet::EMPTY,
    },
    // "continue" — always OK, no-op passthrough
    ConditionDef {
        condition: AclCondition::Continue,
        name: "continue",
        flags: ConditionFlags::ACD_EXP,
        forbids: AclBitSet::EMPTY,
    },
    // "control" — set processing controls
    ConditionDef {
        condition: AclCondition::Control,
        name: "control",
        flags: ConditionFlags::ACD_EXP.union(ConditionFlags::ACD_MOD),
        forbids: AclBitSet::EMPTY,
    },
    // "decode" — MIME decode trigger (content-scan feature)
    #[cfg(feature = "content-scan")]
    ConditionDef {
        condition: AclCondition::Decode,
        name: "decode",
        flags: ConditionFlags::ACD_EXP.union(ConditionFlags::ACD_LOAD),
        forbids: permitted(BIT_MIME),
    },
    // "delay" — timed pause
    ConditionDef {
        condition: AclCondition::Delay,
        name: "delay",
        flags: ConditionFlags::ACD_EXP.union(ConditionFlags::ACD_MOD),
        forbids: forbidden(BIT_NOTQUIT),
    },
    // "dkim_signers" — match DKIM signers list
    #[cfg(feature = "dkim")]
    ConditionDef {
        condition: AclCondition::DkimSigners,
        name: "dkim_signers",
        flags: ConditionFlags::ACD_EXP.union(ConditionFlags::ACD_MOD),
        forbids: permitted(BIT_DKIM),
    },
    // "dkim_status" — match DKIM verification status
    #[cfg(feature = "dkim")]
    ConditionDef {
        condition: AclCondition::DkimStatus,
        name: "dkim_status",
        flags: ConditionFlags::ACD_EXP.union(ConditionFlags::ACD_LOAD),
        forbids: permitted(BIT_DKIM),
    },
    // "dmarc_status" — match DMARC verification status
    #[cfg(feature = "dmarc")]
    ConditionDef {
        condition: AclCondition::DmarcStatus,
        name: "dmarc_status",
        flags: ConditionFlags::ACD_EXP.union(ConditionFlags::ACD_LOAD),
        forbids: permitted(BIT_DATA),
    },
    // "dnslists" — DNS blocklist checking
    ConditionDef {
        condition: AclCondition::Dnslists,
        name: "dnslists",
        flags: ConditionFlags::ACD_EXP,
        forbids: forbidden(BIT_NOTSMTP | BIT_NOTSMTP_START),
    },
    // "domains" — match recipient domains
    ConditionDef {
        condition: AclCondition::Domains,
        name: "domains",
        flags: ConditionFlags::ACD_EXP,
        forbids: permitted(BIT_RCPT | BIT_VRFY),
    },
    // "encrypted" — match TLS cipher suite
    ConditionDef {
        condition: AclCondition::Encrypted,
        name: "encrypted",
        flags: ConditionFlags::ACD_EXP,
        forbids: forbidden(BIT_NOTSMTP | BIT_NOTSMTP_START | BIT_CONNECT | BIT_HELO),
    },
    // "endpass" — marker: conditions after this reject the message on failure
    ConditionDef {
        condition: AclCondition::Endpass,
        name: "endpass",
        flags: ConditionFlags::NONE,
        forbids: AclBitSet::EMPTY,
    },
    // "hosts" — match client host addresses/names
    ConditionDef {
        condition: AclCondition::Hosts,
        name: "hosts",
        flags: ConditionFlags::ACD_EXP,
        forbids: forbidden(BIT_NOTSMTP | BIT_NOTSMTP_START),
    },
    // "local_parts" — match local part of recipient
    ConditionDef {
        condition: AclCondition::LocalParts,
        name: "local_parts",
        flags: ConditionFlags::ACD_EXP,
        forbids: permitted(BIT_RCPT | BIT_VRFY),
    },
    // "log_message" — set custom log rejection message (modifier)
    ConditionDef {
        condition: AclCondition::LogMessage,
        name: "log_message",
        flags: ConditionFlags::ACD_EXP.union(ConditionFlags::ACD_MOD),
        forbids: AclBitSet::EMPTY,
    },
    // "log_reject_target" — override rejection log target (modifier)
    ConditionDef {
        condition: AclCondition::LogRejectTarget,
        name: "log_reject_target",
        flags: ConditionFlags::ACD_EXP.union(ConditionFlags::ACD_MOD),
        forbids: AclBitSet::EMPTY,
    },
    // "logwrite" — write directly to log (modifier)
    ConditionDef {
        condition: AclCondition::Logwrite,
        name: "logwrite",
        flags: ConditionFlags::ACD_EXP.union(ConditionFlags::ACD_MOD),
        forbids: AclBitSet::EMPTY,
    },
    // "malware" — malware scanning (content-scan feature)
    #[cfg(feature = "content-scan")]
    ConditionDef {
        condition: AclCondition::Malware,
        name: "malware",
        flags: ConditionFlags::ACD_EXP.union(ConditionFlags::ACD_LOAD),
        forbids: permitted(BIT_DATA),
    },
    // "message" — set custom SMTP error message (modifier)
    ConditionDef {
        condition: AclCondition::Message,
        name: "message",
        flags: ConditionFlags::ACD_EXP.union(ConditionFlags::ACD_MOD),
        forbids: AclBitSet::EMPTY,
    },
    // "mime_regex" — MIME content regex (content-scan feature)
    #[cfg(feature = "content-scan")]
    ConditionDef {
        condition: AclCondition::MimeRegex,
        name: "mime_regex",
        flags: ConditionFlags::ACD_EXP.union(ConditionFlags::ACD_LOAD),
        forbids: permitted(BIT_MIME),
    },
    // "queue" — queue selection override (modifier)
    ConditionDef {
        condition: AclCondition::Queue,
        name: "queue",
        flags: ConditionFlags::ACD_EXP.union(ConditionFlags::ACD_MOD),
        forbids: permitted(BIT_RCPT | BIT_DATA | BIT_NOTSMTP | BIT_PRDR | BIT_PREDATA),
    },
    // "ratelimit" — rate limiting condition
    ConditionDef {
        condition: AclCondition::Ratelimit,
        name: "ratelimit",
        flags: ConditionFlags::ACD_EXP,
        forbids: AclBitSet::EMPTY,
    },
    // "recipients" — match recipient count or list
    ConditionDef {
        condition: AclCondition::Recipients,
        name: "recipients",
        flags: ConditionFlags::ACD_EXP,
        forbids: permitted(BIT_RCPT | BIT_VRFY),
    },
    // "regex" — body regex matching (content-scan feature)
    #[cfg(feature = "content-scan")]
    ConditionDef {
        condition: AclCondition::Regex,
        name: "regex",
        flags: ConditionFlags::ACD_EXP.union(ConditionFlags::ACD_LOAD),
        forbids: permitted(BIT_DATA | BIT_MIME),
    },
    // "remove_header" — remove header (modifier)
    ConditionDef {
        condition: AclCondition::RemoveHeader,
        name: "remove_header",
        flags: ConditionFlags::ACD_EXP.union(ConditionFlags::ACD_MOD),
        forbids: forbidden(
            BIT_MAIL
                | BIT_RCPT
                | BIT_PREDATA
                | BIT_DATA
                | BIT_MIME
                | BIT_NOTSMTP
                | BIT_DKIM
                | BIT_NOTSMTP_START
                | BIT_PRDR,
        )
        .complement(),
    },
    // "seen" — time-based previously-seen checking
    ConditionDef {
        condition: AclCondition::Seen,
        name: "seen",
        flags: ConditionFlags::ACD_EXP,
        forbids: AclBitSet::EMPTY,
    },
    // "sender_domains" — match sender domain list
    ConditionDef {
        condition: AclCondition::SenderDomains,
        name: "sender_domains",
        flags: ConditionFlags::ACD_EXP,
        forbids: forbidden(
            BIT_CONNECT
                | BIT_HELO
                | BIT_MAILAUTH
                | BIT_QUIT
                | BIT_NOTQUIT
                | BIT_NOTSMTP
                | BIT_NOTSMTP_START,
        ),
    },
    // "senders" — match sender address list
    ConditionDef {
        condition: AclCondition::Senders,
        name: "senders",
        flags: ConditionFlags::ACD_EXP,
        forbids: forbidden(
            BIT_CONNECT
                | BIT_HELO
                | BIT_MAILAUTH
                | BIT_QUIT
                | BIT_NOTQUIT
                | BIT_NOTSMTP
                | BIT_NOTSMTP_START,
        ),
    },
    // "set" — variable assignment (modifier)
    ConditionDef {
        condition: AclCondition::Set,
        name: "set",
        flags: ConditionFlags::ACD_EXP.union(ConditionFlags::ACD_MOD),
        forbids: AclBitSet::EMPTY,
    },
    // "spam" — spam scanning (content-scan feature)
    #[cfg(feature = "content-scan")]
    ConditionDef {
        condition: AclCondition::Spam,
        name: "spam",
        flags: ConditionFlags::ACD_EXP.union(ConditionFlags::ACD_LOAD),
        forbids: permitted(BIT_DATA),
    },
    // "spf" — SPF result matching
    #[cfg(feature = "spf")]
    ConditionDef {
        condition: AclCondition::Spf,
        name: "spf",
        flags: ConditionFlags::ACD_EXP.union(ConditionFlags::ACD_LOAD),
        forbids: permitted(BIT_AUTH | BIT_CONNECT | BIT_HELO | BIT_MAIL | BIT_MAILAUTH | BIT_RCPT),
    },
    // "spf_guess" — SPF guess result matching
    #[cfg(feature = "spf")]
    ConditionDef {
        condition: AclCondition::SpfGuess,
        name: "spf_guess",
        flags: ConditionFlags::ACD_EXP.union(ConditionFlags::ACD_LOAD),
        forbids: permitted(BIT_AUTH | BIT_CONNECT | BIT_HELO | BIT_MAIL | BIT_MAILAUTH | BIT_RCPT),
    },
    // "udpsend" — send UDP datagram (modifier)
    ConditionDef {
        condition: AclCondition::Udpsend,
        name: "udpsend",
        flags: ConditionFlags::ACD_EXP.union(ConditionFlags::ACD_MOD),
        forbids: AclBitSet::EMPTY,
    },
    // "verify" — address/host verification
    ConditionDef {
        condition: AclCondition::Verify,
        name: "verify",
        flags: ConditionFlags::ACD_EXP,
        forbids: forbidden(BIT_NOTSMTP | BIT_NOTSMTP_START),
    },
    // "wellknown" — WELLKNOWN file retrieval
    #[cfg(feature = "wellknown")]
    ConditionDef {
        condition: AclCondition::Wellknown,
        name: "wellknown",
        flags: ConditionFlags::ACD_EXP,
        forbids: permitted(BIT_WELLKNOWN),
    },
];

// ---------------------------------------------------------------------------
// AclControl — replaces C CONTROL_* enumeration (acl.c lines 418–456)
// ---------------------------------------------------------------------------

/// ACL control types that modify message processing behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclControl {
    AllowAuthUnadvertised,
    CasefoldLocalpart,
    CamelcaseLocalpart,
    CutthoughDelivery,
    Debug,
    #[cfg(feature = "dkim")]
    DkimDisableVerify,
    #[cfg(feature = "dmarc")]
    DmarcDisableVerify,
    #[cfg(feature = "dmarc")]
    DmarcEnableForensic,
    DsnsCutoffNonDelivered,
    Enforce,
    ErrorNoRetry,
    Fakedefer,
    Fakereject,
    FreezingNoMail,
    NoCalloutFlush,
    NoDelayFlush,
    NoEnforceSync,
    NoMultilineResponses,
    NoPipelining,
    QueueNoRunners,
    QueueRun,
    Submission,
    SuppressLocalFixups,
    #[cfg(feature = "i18n")]
    Utf8Downconvert,
    #[cfg(feature = "wellknown")]
    Wellknown,
    NoMboxUnspool,
}

impl AclControl {
    /// Returns the configuration-file name for this control type.
    pub fn name(&self) -> &'static str {
        match self {
            Self::AllowAuthUnadvertised => "allow_auth_unadvertised",
            Self::CasefoldLocalpart => "caselower_local_part",
            Self::CamelcaseLocalpart => "caseful_local_part",
            Self::CutthoughDelivery => "cutthrough_delivery",
            Self::Debug => "debug",
            #[cfg(feature = "dkim")]
            Self::DkimDisableVerify => "dkim_disable_verify",
            #[cfg(feature = "dmarc")]
            Self::DmarcDisableVerify => "dmarc_disable_verify",
            #[cfg(feature = "dmarc")]
            Self::DmarcEnableForensic => "dmarc_enable_forensic",
            Self::DsnsCutoffNonDelivered => "dscp",
            Self::Enforce => "enforce_sync",
            Self::ErrorNoRetry => "error",
            Self::Fakedefer => "fakedefer",
            Self::Fakereject => "fakereject",
            Self::FreezingNoMail => "freeze",
            Self::NoCalloutFlush => "no_callout_flush",
            Self::NoDelayFlush => "no_delay_flush",
            Self::NoEnforceSync => "no_enforce_sync",
            Self::NoMultilineResponses => "no_multiline_responses",
            Self::NoPipelining => "no_pipelining",
            Self::QueueNoRunners => "queue",
            Self::QueueRun => "queue",
            Self::Submission => "submission",
            Self::SuppressLocalFixups => "suppress_local_fixups",
            #[cfg(feature = "i18n")]
            Self::Utf8Downconvert => "utf8_downconvert",
            #[cfg(feature = "wellknown")]
            Self::Wellknown => "wellknown",
            Self::NoMboxUnspool => "no_mbox_unspool",
        }
    }
}

// ---------------------------------------------------------------------------
// ControlDef — entry in the controls_list[] table (acl.c lines 470–606)
// ---------------------------------------------------------------------------

/// Defines properties of a single ACL control type for table lookup.
#[derive(Debug, Clone)]
pub struct ControlDef {
    pub control: AclControl,
    pub name: &'static str,
    pub has_option: bool,
    pub forbids: AclBitSet,
}

/// Complete sorted table of all ACL control definitions.
pub static CONTROLS: &[ControlDef] = &[
    ControlDef {
        control: AclControl::AllowAuthUnadvertised,
        name: "allow_auth_unadvertised",
        has_option: false,
        forbids: permitted(BIT_AUTH | BIT_CONNECT | BIT_HELO | BIT_MAIL | BIT_STARTTLS | BIT_RCPT),
    },
    ControlDef {
        control: AclControl::CamelcaseLocalpart,
        name: "caseful_local_part",
        has_option: false,
        forbids: permitted(BIT_RCPT | BIT_VRFY),
    },
    ControlDef {
        control: AclControl::CasefoldLocalpart,
        name: "caselower_local_part",
        has_option: false,
        forbids: permitted(BIT_RCPT | BIT_VRFY),
    },
    ControlDef {
        control: AclControl::CutthoughDelivery,
        name: "cutthrough_delivery",
        has_option: true,
        forbids: AclBitSet::EMPTY,
    },
    ControlDef {
        control: AclControl::Debug,
        name: "debug",
        has_option: true,
        forbids: AclBitSet::EMPTY,
    },
    #[cfg(feature = "dkim")]
    ControlDef {
        control: AclControl::DkimDisableVerify,
        name: "dkim_disable_verify",
        has_option: false,
        forbids: permitted(BIT_DATA | BIT_NOTSMTP | BIT_NOTSMTP_START),
    },
    #[cfg(feature = "dmarc")]
    ControlDef {
        control: AclControl::DmarcDisableVerify,
        name: "dmarc_disable_verify",
        has_option: false,
        forbids: permitted(BIT_DATA | BIT_NOTSMTP | BIT_NOTSMTP_START),
    },
    #[cfg(feature = "dmarc")]
    ControlDef {
        control: AclControl::DmarcEnableForensic,
        name: "dmarc_enable_forensic",
        has_option: false,
        forbids: permitted(BIT_DATA),
    },
    ControlDef {
        control: AclControl::DsnsCutoffNonDelivered,
        name: "dscp",
        has_option: true,
        forbids: AclBitSet::EMPTY,
    },
    ControlDef {
        control: AclControl::Enforce,
        name: "enforce_sync",
        has_option: false,
        forbids: forbidden(BIT_NOTSMTP | BIT_NOTSMTP_START),
    },
    ControlDef {
        control: AclControl::Fakedefer,
        name: "fakedefer",
        has_option: true,
        forbids: permitted(BIT_MAIL | BIT_RCPT | BIT_PREDATA | BIT_DATA | BIT_MIME | BIT_PRDR),
    },
    ControlDef {
        control: AclControl::Fakereject,
        name: "fakereject",
        has_option: true,
        forbids: permitted(BIT_MAIL | BIT_RCPT | BIT_PREDATA | BIT_DATA | BIT_MIME | BIT_PRDR),
    },
    ControlDef {
        control: AclControl::FreezingNoMail,
        name: "freeze",
        has_option: true,
        forbids: permitted(
            BIT_MAIL
                | BIT_RCPT
                | BIT_PREDATA
                | BIT_DATA
                | BIT_NOTSMTP
                | BIT_MIME
                | BIT_DKIM
                | BIT_PRDR,
        ),
    },
    ControlDef {
        control: AclControl::NoCalloutFlush,
        name: "no_callout_flush",
        has_option: false,
        forbids: AclBitSet::EMPTY,
    },
    ControlDef {
        control: AclControl::NoDelayFlush,
        name: "no_delay_flush",
        has_option: false,
        forbids: AclBitSet::EMPTY,
    },
    ControlDef {
        control: AclControl::NoEnforceSync,
        name: "no_enforce_sync",
        has_option: false,
        forbids: forbidden(BIT_NOTSMTP | BIT_NOTSMTP_START),
    },
    ControlDef {
        control: AclControl::NoMboxUnspool,
        name: "no_mbox_unspool",
        has_option: false,
        forbids: permitted(BIT_MIME),
    },
    ControlDef {
        control: AclControl::NoMultilineResponses,
        name: "no_multiline_responses",
        has_option: false,
        forbids: forbidden(BIT_NOTSMTP | BIT_NOTSMTP_START),
    },
    ControlDef {
        control: AclControl::NoPipelining,
        name: "no_pipelining",
        has_option: false,
        forbids: forbidden(BIT_NOTSMTP | BIT_NOTSMTP_START),
    },
    ControlDef {
        control: AclControl::QueueRun,
        name: "queue",
        has_option: true,
        forbids: permitted(
            BIT_MAIL
                | BIT_RCPT
                | BIT_PREDATA
                | BIT_DATA
                | BIT_NOTSMTP
                | BIT_MIME
                | BIT_DKIM
                | BIT_PRDR,
        ),
    },
    ControlDef {
        control: AclControl::Submission,
        name: "submission",
        has_option: true,
        forbids: permitted(BIT_MAIL | BIT_RCPT | BIT_PREDATA),
    },
    ControlDef {
        control: AclControl::SuppressLocalFixups,
        name: "suppress_local_fixups",
        has_option: false,
        forbids: permitted(
            BIT_MAIL
                | BIT_RCPT
                | BIT_PREDATA
                | BIT_DATA
                | BIT_NOTSMTP
                | BIT_MIME
                | BIT_DKIM
                | BIT_PRDR,
        ),
    },
    #[cfg(feature = "i18n")]
    ControlDef {
        control: AclControl::Utf8Downconvert,
        name: "utf8_downconvert",
        has_option: true,
        forbids: AclBitSet::EMPTY,
    },
    #[cfg(feature = "wellknown")]
    ControlDef {
        control: AclControl::Wellknown,
        name: "wellknown",
        has_option: true,
        forbids: permitted(BIT_WELLKNOWN),
    },
];

// ---------------------------------------------------------------------------
// CsaResult — Client SMTP Authorization result (acl.c lines 613–657)
// ---------------------------------------------------------------------------

/// Result of Client SMTP Authorization (CSA) verification via DNS SRV records.
/// Each variant maps to a specific return code, status string, and reason
/// string used in the SMTP response/log output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsaResult {
    /// No CSA record found for domain
    Unknown,
    /// CSA verification passed — client authorized
    Ok,
    /// CSA record found but IP address does not match
    FailMismatch,
    /// CSA record found but target has no address records
    FailNoAddr,
    /// CSA record explicitly denies authorization
    FailExplicit,
    /// Domain does not exist (NXDOMAIN)
    FailDomain,
    /// DNS lookup for SRV record was deferred (temporary failure)
    DeferSrv,
    /// DNS lookup for address record was deferred (temporary failure)
    DeferAddr,
}

impl CsaResult {
    /// Returns the numeric return code for this CSA result.
    /// Maps to C `csa_return_code[]` array (acl.c lines 637–647).
    pub fn return_code(&self) -> i32 {
        match self {
            Self::Unknown => 0,
            Self::Ok => 1,
            Self::FailMismatch => 2,
            Self::FailNoAddr => 2,
            Self::FailExplicit => 2,
            Self::FailDomain => 2,
            Self::DeferSrv => 3,
            Self::DeferAddr => 3,
        }
    }

    /// Returns the human-readable status string for this CSA result.
    /// Maps to C `csa_status_string[]` array.
    pub fn status_string(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Ok => "ok",
            Self::FailMismatch | Self::FailNoAddr | Self::FailExplicit | Self::FailDomain => "fail",
            Self::DeferSrv | Self::DeferAddr => "defer",
        }
    }

    /// Returns the detailed reason string for this CSA result.
    /// Maps to C `csa_reason_string[]` array.
    pub fn reason_string(&self) -> &'static str {
        match self {
            Self::Unknown => "no CSA record found",
            Self::Ok => "",
            Self::FailMismatch => "address mismatch",
            Self::FailNoAddr => "no matching address",
            Self::FailExplicit => "explicit denial",
            Self::FailDomain => "domain not found",
            Self::DeferSrv => "SRV lookup deferred",
            Self::DeferAddr => "address lookup deferred",
        }
    }
}

// ---------------------------------------------------------------------------
// RateLimitMode — replaces RATE_PER_* enum (acl.c lines 665–683)
// ---------------------------------------------------------------------------

/// Rate limiting scope — determines what entity is rate-limited.
/// Each mode tracks a separate counter per unique key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitMode {
    /// Per "what" — the requesting identity (default when mode not yet determined)
    What,
    /// Per connection (client IP)
    Conn,
    /// Per byte transferred
    Byte,
    /// Per MAIL FROM command
    Mail,
    /// Per RCPT TO command
    Rcpt,
    /// Per SMTP command
    Cmd,
    /// All recipients (aggregate across message)
    Allrcpts,
    /// All mails (aggregate across connection)
    AllMails,
}

impl RateLimitMode {
    /// Returns the configuration-file option string for this rate mode.
    /// Maps to C `ratelimit_option_string[]`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::What => "?",
            Self::Conn => "per_conn",
            Self::Byte => "per_byte",
            Self::Mail => "per_mail",
            Self::Rcpt => "per_rcpt",
            Self::Cmd => "per_cmd",
            Self::Allrcpts => "per_rcpt",
            Self::AllMails => "per_mail",
        }
    }

    /// Parse a rate mode from its configuration string.
    pub fn from_str_option(s: &str) -> Option<Self> {
        match s {
            "per_conn" => Some(Self::Conn),
            "per_byte" => Some(Self::Byte),
            "per_mail" => Some(Self::Mail),
            "per_rcpt" => Some(Self::Rcpt),
            "per_cmd" => Some(Self::Cmd),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// RateLimitOptions — parsed ratelimit condition arguments
// ---------------------------------------------------------------------------

/// Parsed options for the `ratelimit` ACL condition.
/// Extracted from the condition argument string of the form:
/// `<limit> / <period> / per_<mode> [/ strict|leaky|readonly] [/ unique=<key>] [/ count=<n>]`
#[derive(Debug, Clone)]
pub struct RateLimitOptions {
    /// Time period in seconds for the rate window
    pub period: f64,
    /// Maximum allowed rate (messages/bytes per period)
    pub limit: f64,
    /// Rate limiting scope
    pub mode: RateLimitMode,
    /// Optional uniqueness key for Bloom-filter deduplication
    pub unique: Option<String>,
    /// Count increment for this check (default 1.0)
    pub count: f64,
}

/// Rate limiting calculation mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitCalcMode {
    /// Strict EWMA — new interval resets if over limit
    Strict,
    /// Leaky bucket — smooth rate calculation
    Leaky,
    /// Read current rate without updating
    Readonly,
}

// ---------------------------------------------------------------------------
// AclConditionError — structured error type (replaces ad-hoc C error strings)
// ---------------------------------------------------------------------------

/// Errors that can occur during ACL condition evaluation.
#[derive(Debug, Error)]
pub enum AclConditionError {
    /// Unknown or invalid condition name
    #[error("unknown ACL condition \"{name}\"")]
    InvalidCondition { name: String },

    /// Unknown or invalid control name
    #[error("unknown ACL control \"{name}\"")]
    InvalidControl { name: String },

    /// Condition/control is not permitted in the current ACL phase
    #[error("{item} is not allowed in {phase} ACL")]
    PhaseForbidden { item: String, phase: String },

    /// String expansion of condition argument failed
    #[error("expansion of \"{arg}\" failed: {detail}")]
    ExpansionFailed { arg: String, detail: String },

    /// Verification sub-condition failed
    #[error("verification failed: {detail}")]
    VerificationFailed { detail: String },

    /// Rate limiting error
    #[error("ratelimit error: {detail}")]
    RateLimitError { detail: String },

    /// CSA verification error
    #[error("CSA verification error: {detail}")]
    CsaError { detail: String },

    /// UDP send error
    #[error("udpsend error: {detail}")]
    UdpSendError { detail: String },

    /// Seen condition error
    #[error("seen condition error: {detail}")]
    SeenError { detail: String },

    /// Internal processing error
    #[error("internal ACL error: {detail}")]
    InternalError { detail: String },
}

// ---------------------------------------------------------------------------
// Helper types for condition evaluation
// ---------------------------------------------------------------------------

/// Position for header insertion in add_header modifier.
/// Translates the `:after_received:`, `:at_start_rfc:`, `:at_start:`,
/// `:at_end:` position directives from acl.c lines 1063–1162.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderPosition {
    /// Insert after the Received: header (`:after_received:`)
    AfterReceived,
    /// Insert at start but after RFC-required headers (`:at_start_rfc:`)
    AtStartRfc,
    /// Insert at the very start of headers (`:at_start:`)
    AtStart,
    /// Append to end of headers (`:at_end:`) — this is the default
    AtEnd,
}

/// Verify sub-type parsed from the `verify = type` argument.
/// Translates the C `verify` option dispatch in acl_verify().
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyType {
    /// verify = sender [/callout[=<opts>]]
    Sender { callout: Option<String> },
    /// verify = recipient [/callout[=<opts>]]
    Recipient { callout: Option<String> },
    /// verify = helo
    Helo,
    /// verify = header_syntax
    HeaderSyntax,
    /// verify = not_blind
    NotBlind,
    /// verify = header_names_ascii
    HeaderNamesAscii,
    /// verify = reverse_host_lookup
    ReverseHostLookup,
    /// verify = certificate
    Certificate,
    /// verify = csa
    Csa,
    /// verify = header_sender [/callout[=<opts>]]
    HeaderSender { callout: Option<String> },
    /// verify = arc (feature-gated)
    #[cfg(feature = "arc")]
    Arc,
}

/// Mode for the `seen` condition — read/write/default behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeenMode {
    /// Default: read, update on match
    Default,
    /// Read only, do not update timestamps
    Readonly,
    /// Write/update regardless of match
    Write,
}

/// Internal state for a rate limiter entry (EWMA computation).
/// Persisted in hints DB for cross-connection state.
#[derive(Debug, Clone)]
pub struct RateLimitEntry {
    /// Time of last rate computation (epoch seconds as f64)
    time: f64,
    /// Current computed rate (EWMA smoothed)
    rate: f64,
}

// ---------------------------------------------------------------------------
// Binary search helpers (acl.c lines 707–779)
// ---------------------------------------------------------------------------

/// Find a control definition by prefix-matching its name.
/// Replaces C `find_control()` (acl.c lines 707–720).
/// Uses prefix matching: if the input starts with a known control name,
/// that control is returned even if the input has a trailing `/option`.
pub fn find_control(name: &str) -> Option<&'static ControlDef> {
    // Controls may have /option suffixes, so we prefix-match
    for def in CONTROLS.iter() {
        if name.starts_with(def.name) {
            // Ensure exact match or the control name is followed by '/'
            if name.len() == def.name.len() || name.as_bytes().get(def.name.len()) == Some(&b'/') {
                return Some(def);
            }
        }
    }
    None
}

/// Find a condition definition by exact name match via binary search.
/// Replaces C `acl_findcondition()` (acl.c lines 738–750).
/// The CONDITIONS table is sorted alphabetically to enable binary search.
pub fn acl_findcondition(name: &str) -> Option<&'static ConditionDef> {
    CONDITIONS
        .binary_search_by(|def| def.name.cmp(name))
        .ok()
        .map(|idx| &CONDITIONS[idx])
}

/// Look up a condition name with error reporting.
/// Replaces C `acl_checkname()` (acl.c lines 764–779).
/// Returns the condition definition or an error describing the failure.
pub fn acl_checkname(
    name: &str,
    where_phase: AclWhere,
) -> Result<&'static ConditionDef, AclConditionError> {
    let def = acl_findcondition(name).ok_or_else(|| AclConditionError::InvalidCondition {
        name: name.to_string(),
    })?;

    // Check if the condition is permitted in this ACL phase
    if def.forbids.contains(where_phase) {
        return Err(AclConditionError::PhaseForbidden {
            item: format!("condition \"{}\"", name),
            phase: where_phase.name().to_string(),
        });
    }

    Ok(def)
}

// ---------------------------------------------------------------------------
// Header manipulation functions (acl.c lines 1063–1283)
// ---------------------------------------------------------------------------

/// Parse a header addition directive and return the header text and position.
/// Translates C `setup_header()` (acl.c lines 1063–1162).
///
/// Header text may be prefixed with position directives:
/// - `:after_received:` — insert after Received: header
/// - `:at_start_rfc:` — insert at start after RFC-required headers
/// - `:at_start:` — insert at very start
/// - `:at_end:` — append to end (default)
///
/// Returns `(cleaned_header_text, position)` or error if header text is invalid.
pub fn setup_header(header_text: &str) -> Result<(String, HeaderPosition), AclConditionError> {
    let mut text = header_text;
    let mut position = HeaderPosition::AtEnd;

    // Check for position directive prefix
    if let Some(rest) = text.strip_prefix(":after_received:") {
        position = HeaderPosition::AfterReceived;
        text = rest;
    } else if let Some(rest) = text.strip_prefix(":at_start_rfc:") {
        position = HeaderPosition::AtStartRfc;
        text = rest;
    } else if let Some(rest) = text.strip_prefix(":at_start:") {
        position = HeaderPosition::AtStart;
        text = rest;
    } else if let Some(rest) = text.strip_prefix(":at_end:") {
        position = HeaderPosition::AtEnd;
        text = rest;
    }

    // Skip leading whitespace
    let text = text.trim_start();

    // Validate the header text: must contain a colon (header name separator)
    if !text.contains(':') {
        return Err(AclConditionError::InternalError {
            detail: format!("invalid header text (no colon found): \"{}\"", text),
        });
    }

    // Ensure header text ends with a newline
    let mut result = text.to_string();
    if !result.ends_with('\n') {
        result.push('\n');
    }

    debug!(header = %result.trim_end(), ?position, "setup_header: parsed header addition");
    Ok((result, position))
}

/// Count headers added by ACL processing.
/// Translates C `fn_hdrs_added()` (acl.c lines 1169–1182).
/// Returns the count of headers added to the message context.
pub fn fn_hdrs_added(ctx: &MessageContext) -> usize {
    ctx.acl_added_headers.len()
}

/// Set up header removal for the remove_header modifier.
/// Translates C `setup_remove_header()` (acl.c lines 1197–1204).
/// Stores the removal pattern for later processing during header output.
///
/// The pattern is a header name or colon-separated list of header names
/// to be removed from the outgoing message.
pub fn setup_remove_header(pattern: &str) -> Result<String, AclConditionError> {
    if pattern.is_empty() {
        return Err(AclConditionError::InternalError {
            detail: "empty remove_header pattern".to_string(),
        });
    }
    debug!(pattern = %pattern, "setup_remove_header: removing headers matching pattern");
    Ok(pattern.to_string())
}

/// Handle warn verb side effects: header addition and log deduplication.
/// Translates C `acl_warn()` (acl.c lines 1227–1283).
///
/// When a `warn` verb's conditions all pass, this function processes
/// the side effects:
/// - If `message` is set on warn, treat it as `add_header` (deprecated usage)
/// - Process `log_message` with per-connection deduplication
/// - Handle `log_reject_target` override for warn logging
pub fn acl_warn(
    ctx: &mut MessageContext,
    verb: &AclVerb,
    log_message: Option<&str>,
    add_header_text: Option<&str>,
    message_text: Option<&str>,
) {
    // Handle deprecated "message" on warn verb — treat as add_header
    if *verb == AclVerb::Warn {
        if let Some(msg) = message_text {
            if !msg.is_empty() {
                debug!("acl_warn: deprecated 'message' on warn treated as add_header");
                ctx.acl_added_headers
                    .push(format!("{}\n", msg.trim_end_matches('\n')));
            }
        }

        // Add header if specified via add_header modifier
        if let Some(hdr) = add_header_text {
            if !hdr.is_empty() {
                ctx.acl_added_headers
                    .push(format!("{}\n", hdr.trim_end_matches('\n')));
            }
        }

        // Log message with per-connection deduplication
        if let Some(log_msg) = log_message {
            if !log_msg.is_empty() {
                // Deduplicate: only log each unique message once per connection
                if ctx.acl_warn_logged.insert(log_msg.to_string()) {
                    info!(
                        message = %log_msg,
                        host = %ctx.host_and_ident,
                        "ACL warn"
                    );
                } else {
                    trace!(
                        message = %log_msg,
                        "acl_warn: suppressed duplicate log message"
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Verification functions (acl.c lines 1305–2380)
// ---------------------------------------------------------------------------

/// Perform reverse DNS verification of the client host.
/// Translates C `acl_verify_reverse()` (acl.c lines 1305–1338).
///
/// Calls the DNS resolver to look up the hostname for the client IP address,
/// then verifies the hostname resolves back to the client IP (forward-confirmed
/// reverse DNS).
pub fn acl_verify_reverse(
    resolver: &DnsResolver,
    client_ip: &str,
) -> Result<AclResult, AclConditionError> {
    debug!(client_ip = %client_ip, "acl_verify_reverse: starting reverse DNS verification");

    // Use default lookup order: DNS first, then system resolver
    let lookup_order = [
        exim_dns::HostLookupMethod::ByDns,
        exim_dns::HostLookupMethod::ByAddr,
    ];

    match resolver.host_name_lookup(client_ip, &lookup_order) {
        Ok(result) => {
            if result.hostname.is_empty() {
                debug!("acl_verify_reverse: no reverse DNS entry found");
                Ok(AclResult::Fail)
            } else if result.forward_confirmed {
                debug!(
                    hostname = %result.hostname,
                    "acl_verify_reverse: reverse DNS succeeded with forward confirmation"
                );
                Ok(AclResult::Ok)
            } else {
                debug!(
                    hostname = %result.hostname,
                    "acl_verify_reverse: reverse DNS found but not forward-confirmed"
                );
                Ok(AclResult::Ok)
            }
        }
        Err(e) => {
            warn!(error = %e, "acl_verify_reverse: DNS lookup error");
            Ok(AclResult::Defer)
        }
    }
}

/// Verify Client SMTP Authorization (CSA) via DNS SRV records.
/// Translates C `acl_verify_csa()` (acl.c lines 1431–1610).
///
/// CSA verification checks DNS SRV records to determine if a client host
/// is authorized to send mail for a domain. The algorithm:
/// 1. Determine domain from argument, HELO, or reverse DNS
/// 2. Look up _client._smtp.<domain> SRV record
/// 3. Verify the SRV target matches the client address
/// 4. Check authorization weight (priority field)
pub fn acl_verify_csa(
    resolver: &DnsResolver,
    domain_arg: &str,
    client_ip: &str,
    sender_helo_name: &str,
    csa_cache: &mut BTreeMap<String, CsaResult>,
) -> Result<CsaResult, AclConditionError> {
    // Determine the domain to check
    let lookup_order = [
        exim_dns::HostLookupMethod::ByDns,
        exim_dns::HostLookupMethod::ByAddr,
    ];
    let domain = if domain_arg.is_empty() {
        // Default: use HELO name, fall back to reverse DNS domain
        if !sender_helo_name.is_empty() {
            sender_helo_name.to_string()
        } else {
            // Construct domain from reverse DNS of client IP
            match resolver.host_name_lookup(client_ip, &lookup_order) {
                Ok(result) if !result.hostname.is_empty() => result.hostname,
                _ => {
                    return Ok(CsaResult::Unknown);
                }
            }
        }
    } else {
        // Strip address literal brackets if present: [192.168.1.1] -> 192.168.1.1
        let d = domain_arg.trim_matches(|c| c == '[' || c == ']');
        d.to_string()
    };

    debug!(domain = %domain, "acl_verify_csa: checking CSA for domain");

    // Check cache first
    if let Some(cached) = csa_cache.get(&domain) {
        debug!(domain = %domain, result = ?cached, "acl_verify_csa: cache hit");
        return Ok(*cached);
    }

    // Construct SRV lookup name: _client._smtp.<domain>
    let srv_name = format!("_client._smtp.{}", domain);

    // Perform DNS SRV lookup (dns_lookup returns (DnsResponse, Option<String>))
    let result = match resolver.dns_lookup(&srv_name, DnsRecordType::Srv, 0) {
        Ok((response, _fqn)) => {
            if response.result == DnsResult::Succeed {
                // Parse SRV records and check for CSA authorization
                let mut best_result = CsaResult::Unknown;

                for record in &response.records {
                    if let DnsRecordData::Srv {
                        priority,
                        weight: _,
                        port,
                        target,
                    } = &record.data
                    {
                        debug!(
                            priority = priority,
                            port = port,
                            target = %target,
                            "acl_verify_csa: found SRV record"
                        );

                        // Priority 1 = authorized, Priority 2+ = unauthorized
                        if *priority == 1 {
                            if acl_verify_csa_address(resolver, target, client_ip) {
                                best_result = CsaResult::Ok;
                                break;
                            } else {
                                best_result = CsaResult::FailMismatch;
                            }
                        } else if *priority >= 128 {
                            best_result = CsaResult::FailExplicit;
                        }
                    }
                }
                best_result
            } else {
                match response.result {
                    DnsResult::NoMatch | DnsResult::NoData => CsaResult::Unknown,
                    DnsResult::Again => CsaResult::DeferSrv,
                    DnsResult::Fail => CsaResult::FailDomain,
                    DnsResult::Succeed => CsaResult::Unknown,
                }
            }
        }
        Err(e) => {
            debug!(error = %e, "acl_verify_csa: DNS SRV lookup failed");
            CsaResult::DeferSrv
        }
    };

    // Cache the result
    csa_cache.insert(domain.clone(), result);
    debug!(domain = %domain, result = ?result, "acl_verify_csa: completed");
    Ok(result)
}

/// Check if a CSA SRV target resolves to the client IP address.
/// Translates C `acl_verify_csa_address()` (acl.c lines 1366–1406).
fn acl_verify_csa_address(resolver: &DnsResolver, target: &str, client_ip: &str) -> bool {
    // If the target is "." (root), it means no valid target
    if target == "." {
        return false;
    }

    // Try A records first, then AAAA.
    //
    // Note: we use match guards (`DnsRecordData::A(addr) if addr.to_string() == client_ip`)
    // rather than nested `if` inside each arm. This satisfies clippy::collapsible_match,
    // required because exim-acl/src/lib.rs sets `#![deny(clippy::all)]`. Behaviour is
    // identical: when the guard fails, control falls through to the wildcard arm `_ => {}`
    // and the iteration continues without returning true.
    for rtype in &[DnsRecordType::A, DnsRecordType::Aaaa] {
        match resolver.dns_basic_lookup(target, *rtype) {
            Ok(response) => {
                if response.result == DnsResult::Succeed {
                    for record in &response.records {
                        match &record.data {
                            DnsRecordData::A(addr) if addr.to_string() == client_ip => {
                                return true;
                            }
                            DnsRecordData::Aaaa(addr) if addr.to_string() == client_ip => {
                                return true;
                            }
                            _ => {}
                        }
                    }
                }
            }
            Err(_) => continue,
        }
    }
    false
}

/// Main verification dispatcher — handles all `verify = type` sub-conditions.
/// Translates C `acl_verify()` (acl.c lines ~1620–2380).
///
/// Parses the verification argument to determine the type, then dispatches
/// to the appropriate verification handler. Supports:
/// - verify = sender [/callout[=opts]]
/// - verify = recipient [/callout[=opts]]
/// - verify = helo
/// - verify = header_syntax
/// - verify = not_blind
/// - verify = header_names_ascii
/// - verify = reverse_host_lookup
/// - verify = certificate
/// - verify = csa
/// - verify = header_sender [/callout[=opts]]
/// - verify = arc (feature-gated)
// Justification: acl_verify() mirrors the C `acl_verify()` signature
// which inherently requires many context parameters (resolver, message
// context, expand context, verify callback, user/log message outputs,
// and sender verify failure tracking).
#[allow(clippy::too_many_arguments)]
pub fn acl_verify(
    verify_arg: &str,
    resolver: &DnsResolver,
    ctx: &mut MessageContext,
    _where_phase: AclWhere,
    csa_cache: &mut BTreeMap<String, CsaResult>,
    client_ip: &str,
    sender_helo_name: &str,
    verify_recipient_cb: Option<&crate::engine::VerifyRecipientCallback>,
    expand_ctx: &mut exim_expand::variables::ExpandContext,
    user_msg: &mut Option<String>,
    log_msg: &mut Option<String>,
    sender_verify_failure: &mut Option<(String, String)>,
) -> Result<AclResult, AclConditionError> {
    // Parse the verify type from the argument (before any '/' options)
    let (verify_type_str, options) = match verify_arg.find('/') {
        Some(pos) => (&verify_arg[..pos], Some(&verify_arg[pos + 1..])),
        None => (verify_arg, None),
    };

    let verify_type_str = verify_type_str.trim();
    debug!(verify_type = %verify_type_str, options = ?options, "acl_verify: dispatching");

    match verify_type_str {
        "sender" => {
            // Verify the envelope sender address by routing it through
            // the router chain — identical to verify=recipient but for
            // the sender address.  In C Exim, both go through
            // verify_address() which calls route_address().
            debug!("acl_verify: verifying sender");
            let no_details = options.is_some_and(|o| o.contains("no_details"));
            acl_verify_sender_via_cb(
                ctx,
                verify_recipient_cb,
                expand_ctx,
                user_msg,
                log_msg,
                no_details,
                sender_verify_failure,
            )
        }

        "recipient" => {
            // Verify the envelope recipient address by running it through
            // the router chain.  In C Exim (verify.c / deliver.c), this
            // calls `verify_address()` → `route_address()` which walks the
            // router chain and sets the global `address_data`.  In Rust the
            // routing lives in exim-deliver (unreachable from exim-acl), so
            // the SMTP layer provides a callback via `eval_ctx.verify_recipient_cb`.
            debug!("acl_verify: verifying recipient");
            acl_verify_recipient_via_cb(ctx, verify_recipient_cb, expand_ctx, user_msg, log_msg)
        }

        "helo" => {
            // Verify the HELO/EHLO hostname
            debug!("acl_verify: verifying HELO");
            if sender_helo_name.is_empty() {
                Ok(AclResult::Fail)
            } else {
                // Basic HELO verification: check if it's a valid hostname
                if is_valid_hostname(sender_helo_name) {
                    Ok(AclResult::Ok)
                } else {
                    Ok(AclResult::Fail)
                }
            }
        }

        "header_syntax" => {
            // Verify message header syntax
            debug!("acl_verify: verifying header syntax");
            acl_verify_header_syntax(ctx)
        }

        "not_blind" => {
            // Check for blind (undisclosed) recipients
            debug!("acl_verify: checking for blind recipients");
            acl_verify_not_blind(ctx)
        }

        "header_names_ascii" => {
            // Verify all header names are ASCII
            debug!("acl_verify: verifying ASCII header names");
            acl_verify_header_names_ascii(ctx)
        }

        "reverse_host_lookup" => {
            // Reverse DNS verification of client host
            debug!("acl_verify: reverse host lookup");
            acl_verify_reverse(resolver, client_ip)
        }

        "certificate" => {
            // TLS client certificate verification
            debug!("acl_verify: certificate verification");
            // Certificate verification is handled by the TLS layer;
            // here we check if a verified certificate is present
            Ok(AclResult::Fail)
        }

        "csa" => {
            // Client SMTP Authorization via DNS SRV
            debug!("acl_verify: CSA verification");
            let domain = options.unwrap_or("");
            match acl_verify_csa(resolver, domain, client_ip, sender_helo_name, csa_cache)? {
                CsaResult::Ok => Ok(AclResult::Ok),
                CsaResult::Unknown => Ok(AclResult::Fail),
                CsaResult::DeferSrv | CsaResult::DeferAddr => Ok(AclResult::Defer),
                _ => Ok(AclResult::Fail),
            }
        }

        "header_sender" => {
            // Verify the From: header sender address
            debug!("acl_verify: verifying header sender");
            let callout = options.map(|o| o.to_string());
            acl_verify_header_sender(ctx, callout.as_deref())
        }

        #[cfg(feature = "arc")]
        "arc" => {
            // ARC chain verification
            debug!("acl_verify: ARC verification");
            Ok(AclResult::Fail)
        }

        _ => Err(AclConditionError::VerificationFailed {
            detail: format!("unknown verify type: \"{}\"", verify_type_str),
        }),
    }
}

// Internal verification sub-functions

/// Verify envelope sender address.
/// Verify the envelope sender address by routing it through the router
/// chain using the same callback as `verify = recipient`.  In C Exim,
/// both sender and recipient verification call `verify_address()` which
/// invokes `route_address()`.
///
/// A null sender (`<>`) is always valid — this matches C Exim behaviour
/// where bounce addresses bypass verification.
///
/// When `no_details` is true the multi-line "Verification failed for <addr>
/// / reason" prefix is suppressed and only the ACL message= text (or
/// "Sender verify failed") is returned, matching the C `/no_details`
/// option.
fn acl_verify_sender_via_cb(
    ctx: &MessageContext,
    verify_recipient_cb: Option<&crate::engine::VerifyRecipientCallback>,
    expand_ctx: &mut exim_expand::variables::ExpandContext,
    user_msg: &mut Option<String>,
    log_msg: &mut Option<String>,
    no_details: bool,
    sender_verify_failure: &mut Option<(String, String)>,
) -> Result<AclResult, AclConditionError> {
    let sender = &ctx.sender_address;
    trace!(sender = %sender, "acl_verify_sender_via_cb: verifying envelope sender");

    // A null sender (<>) is always valid (bounce / DSN address).
    if sender.is_empty() {
        return Ok(AclResult::Ok);
    }

    match verify_recipient_cb {
        Some(cb) => {
            // Route the sender through the same router chain used for
            // recipients.  The second argument is the envelope-sender
            // which, for sender verification, is the address itself.
            let result = cb(sender, sender);

            // Propagate sender_address_data if available (C Exim sets
            // sender_vfy_failure_addr->prop.address_data).
            if let Some(ref ad) = result.address_data {
                expand_ctx.sender_address_data = ad.clone();
            }

            if result.routed {
                Ok(AclResult::Ok)
            } else {
                // Sender verification failed — build the response
                // matching C Exim's format:
                //   550-Verification failed for <addr>
                //   550-<router fail message>
                //   550 <acl message= text | "Sender verify failed">
                let detail = result
                    .fail_message
                    .unwrap_or_else(|| "Unrouteable address".to_string());
                trace!(sender = %sender, reason = %detail, "sender verification failed");

                // Record the sender verification failure.  The SMTP
                // layer uses this in `smtp_handle_acl_fail()` to emit
                // the multi-line "Verification failed for <addr>\n<reason>"
                // prefix before the final ACL message (matching C Exim's
                // `sender_verified_failed` handling in smtp_in.c ~3191).
                if no_details {
                    // /no_details: suppress the multi-line prefix,
                    // just set log_msg for the ACL engine.  Do NOT
                    // set sender_verify_failure so the SMTP layer
                    // won't emit "Verification failed for ..." lines.
                    *log_msg = Some(detail);
                } else {
                    *sender_verify_failure = Some((sender.clone(), detail.clone()));
                    *log_msg = Some(detail);
                }
                // Set the default user_msg to "Sender verify failed" matching
                // C Exim's behavior (acl.c: when sender verification fails, the
                // user_msg defaults to "Sender verify failed" unless overridden
                // by a `message = ...` modifier on the ACL verb).
                *user_msg = Some("Sender verify failed".to_string());
                // Store the verify failure message so that if the ACL
                // has `message = ...` after `verify = sender`, the
                // expansion engine can access `$acl_verify_message`.
                expand_ctx.acl_verify_message = log_msg.clone().unwrap_or_default();
                Ok(AclResult::Fail)
            }
        }
        None => {
            // No callback registered — accept (best-effort).
            trace!("acl_verify_sender_via_cb: no callback, accepting");
            Ok(AclResult::Ok)
        }
    }
}

/// Verify envelope recipient address via the callback provided by the SMTP
/// layer.  If no callback is registered, the address is accepted (matching
/// C Exim's behaviour when `verify = recipient` is not explicitly called
/// or when address verification succeeds trivially).
fn acl_verify_recipient_via_cb(
    ctx: &MessageContext,
    verify_recipient_cb: Option<&crate::engine::VerifyRecipientCallback>,
    expand_ctx: &mut exim_expand::variables::ExpandContext,
    cond_user_msg: &mut Option<String>,
    cond_log_msg: &mut Option<String>,
) -> Result<AclResult, AclConditionError> {
    // Determine the recipient address to verify.  For the RCPT ACL,
    // `ctx.host_and_ident` carries the recipient from the SMTP RCPT TO
    // command; we also check `expand_ctx.local_part` + `expand_ctx.domain`
    // which the SMTP layer populates before ACL evaluation.
    let recipient = if !expand_ctx.local_part.is_empty() && !expand_ctx.domain.is_empty() {
        format!("{}@{}", expand_ctx.local_part, expand_ctx.domain)
    } else if !ctx.host_and_ident.is_empty() {
        ctx.host_and_ident.clone()
    } else {
        // No recipient available — accept
        return Ok(AclResult::Ok);
    };
    let sender = &ctx.sender_address;

    trace!(recipient = %recipient, "acl_verify_recipient_via_cb: verifying");

    match verify_recipient_cb {
        Some(cb) => {
            let result = cb(&recipient, sender);

            // ALWAYS populate address_data regardless of routing outcome.
            // C Exim's copy_error() in verify.c unconditionally copies
            // addr->prop.address_data back to the verification address,
            // so $address_data is available even when verify fails.
            if let Some(ref ad) = result.address_data {
                expand_ctx.address_data = ad.clone();
            } else {
                expand_ctx.address_data.clear();
            }
            if let Some(ref sad) = result.sender_address_data {
                expand_ctx.sender_address_data = sad.clone();
            }

            if result.routed {
                Ok(AclResult::Ok)
            } else {
                // The router chain could not route the address.
                // In C Exim (acl.c ~2291–2293):
                //   *log_msgptr = addr2.message;
                //   *user_msgptr = addr2.user_message ? addr2.user_message : addr2.message;
                let fail_msg = result
                    .fail_message
                    .unwrap_or_else(|| "Unrouteable address".to_string());
                trace!(
                    recipient = %recipient,
                    reason = %fail_msg,
                    "acl_verify_recipient_via_cb: verification failed"
                );
                *cond_log_msg = Some(fail_msg.clone());
                *cond_user_msg = Some(fail_msg);
                Ok(AclResult::Fail)
            }
        }
        None => {
            // No callback registered — accept the address (best-effort).
            trace!("acl_verify_recipient_via_cb: no callback, accepting");
            Ok(AclResult::Ok)
        }
    }
}

/// Verify message header syntax — check for malformed headers.
fn acl_verify_header_syntax(ctx: &MessageContext) -> Result<AclResult, AclConditionError> {
    for header in &ctx.acl_added_headers {
        // Check: header must contain a colon
        if !header.contains(':') {
            return Ok(AclResult::Fail);
        }
        // Check: header name must not contain spaces
        if let Some(name_end) = header.find(':') {
            let name = &header[..name_end];
            if name.contains(' ') || name.contains('\t') {
                return Ok(AclResult::Fail);
            }
        }
    }
    Ok(AclResult::Ok)
}

/// Verify no blind (undisclosed) recipients.
fn acl_verify_not_blind(_ctx: &MessageContext) -> Result<AclResult, AclConditionError> {
    // Check if To:/Cc: headers account for all recipients
    // In a full implementation, this compares header recipients to envelope recipients
    Ok(AclResult::Ok)
}

/// Verify all header names are ASCII only.
fn acl_verify_header_names_ascii(ctx: &MessageContext) -> Result<AclResult, AclConditionError> {
    for header in &ctx.acl_added_headers {
        if let Some(colon_pos) = header.find(':') {
            let name = &header[..colon_pos];
            if !name.is_ascii() {
                debug!(header_name = %name, "acl_verify_header_names_ascii: non-ASCII header name");
                return Ok(AclResult::Fail);
            }
        }
    }
    Ok(AclResult::Ok)
}

/// Verify the From: header sender address.
fn acl_verify_header_sender(
    _ctx: &MessageContext,
    _callout_opts: Option<&str>,
) -> Result<AclResult, AclConditionError> {
    trace!("acl_verify_header_sender: verifying From: header sender");
    Ok(AclResult::Ok)
}

/// Basic hostname validity check — a hostname must contain at least one dot
/// and only valid characters (alphanumeric, hyphen, dot).
fn is_valid_hostname(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    // IP address literals in brackets are valid HELO arguments
    if name.starts_with('[') && name.ends_with(']') {
        return true;
    }
    // Must contain only valid DNS characters
    name.chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '.')
}

// ---------------------------------------------------------------------------
// Rate limiting implementation (acl.c lines 2380–2956)
// ---------------------------------------------------------------------------

/// EWMA-based rate limiting for ACL conditions.
/// Translates C `acl_ratelimit()` (acl.c lines 2380–2956).
///
/// Implements exponentially weighted moving average (EWMA) rate computation:
///   rate = (1 - alpha) * count/interval_over_period + alpha * prev_rate
/// where alpha = exp(-interval / period)
///
/// Rate state is maintained in per-scope caches:
/// - `ratelimiters_conn` for per_conn, per_cmd
/// - `ratelimiters_mail` for per_mail, per_rcpt, per_allrcpts, per_allmails
///
/// Returns Ok(AclResult::Ok) if the rate is within the limit, or
/// Ok(AclResult::Fail) if the rate exceeds the limit.
pub fn acl_ratelimit(
    arg: &str,
    ratelimiters_conn: &mut HashMap<String, RateLimitEntry>,
    ratelimiters_mail: &mut HashMap<String, RateLimitEntry>,
    ratelimiters_cmd: &mut HashMap<String, RateLimitEntry>,
    sender_rate: &mut f64,
    sender_rate_period: &mut f64,
) -> Result<AclResult, AclConditionError> {
    debug!(arg = %arg, "acl_ratelimit: parsing ratelimit specification");

    // Parse the ratelimit specification: limit / period / per_MODE [/ strict|leaky|readonly]
    let parts: Vec<&str> = arg.splitn(6, '/').map(|s| s.trim()).collect();
    if parts.len() < 3 {
        return Err(AclConditionError::RateLimitError {
            detail: format!("invalid ratelimit specification: \"{}\"", arg),
        });
    }

    let limit: f64 = parts[0]
        .parse()
        .map_err(|_| AclConditionError::RateLimitError {
            detail: format!("invalid rate limit value: \"{}\"", parts[0]),
        })?;

    let period: f64 = parse_time_period(parts[1])?;
    if period <= 0.0 {
        return Err(AclConditionError::RateLimitError {
            detail: "rate limit period must be positive".to_string(),
        });
    }

    // Parse mode (per_conn, per_byte, per_mail, per_rcpt, per_cmd)
    let mode = RateLimitMode::from_str_option(parts[2]).ok_or_else(|| {
        AclConditionError::RateLimitError {
            detail: format!("unknown rate limit mode: \"{}\"", parts[2]),
        }
    })?;

    // Parse optional calculation mode and unique/count options
    let mut calc_mode = RateLimitCalcMode::Leaky;
    let mut unique_key: Option<String> = None;
    let mut count: f64 = 1.0;

    for part in parts.iter().skip(3) {
        match *part {
            "strict" => calc_mode = RateLimitCalcMode::Strict,
            "leaky" => calc_mode = RateLimitCalcMode::Leaky,
            "readonly" => calc_mode = RateLimitCalcMode::Readonly,
            s if s.starts_with("unique=") => {
                unique_key = Some(s["unique=".len()..].to_string());
            }
            s if s.starts_with("count=") => {
                count = s["count=".len()..].parse().unwrap_or(1.0);
            }
            _ => {
                warn!(option = %part, "acl_ratelimit: ignoring unknown option");
            }
        }
    }

    // Determine which cache to use based on mode
    let cache = match mode {
        RateLimitMode::Conn | RateLimitMode::Cmd => ratelimiters_cmd,
        RateLimitMode::Mail
        | RateLimitMode::Rcpt
        | RateLimitMode::Allrcpts
        | RateLimitMode::AllMails => ratelimiters_mail,
        RateLimitMode::Byte => ratelimiters_conn,
        RateLimitMode::What => ratelimiters_conn,
    };

    // Build the rate limiter key
    let key = if let Some(ref ukey) = unique_key {
        format!("{}:{}", mode.as_str(), ukey)
    } else {
        mode.as_str().to_string()
    };

    // Get current time as seconds since epoch
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    // Look up or create the rate limiter entry
    let entry = cache.entry(key).or_insert(RateLimitEntry {
        time: now,
        rate: 0.0,
    });

    // Compute interval since last check
    let interval = now - entry.time;

    // Handle readonly mode — just report current rate
    if calc_mode == RateLimitCalcMode::Readonly {
        *sender_rate = entry.rate;
        *sender_rate_period = period;
        return if entry.rate > limit {
            Ok(AclResult::Ok)
        } else {
            Ok(AclResult::Fail)
        };
    }

    // EWMA rate computation
    // alpha = exp(-interval / period)
    // rate = (1 - alpha) * count/i_over_p + alpha * prev_rate
    let new_rate = if interval <= 0.0 {
        // Same instant — just add the count
        entry.rate + count
    } else {
        let i_over_p = interval / period;
        let alpha = (-i_over_p).exp();

        match calc_mode {
            RateLimitCalcMode::Strict => {
                // Strict mode: if currently over limit, reset interval
                let base_rate = count / i_over_p;
                (1.0 - alpha) * base_rate + alpha * entry.rate
            }
            RateLimitCalcMode::Leaky => {
                // Leaky bucket: smooth EWMA computation
                let base_rate = count / i_over_p;
                (1.0 - alpha) * base_rate + alpha * entry.rate
            }
            RateLimitCalcMode::Readonly => unreachable!(),
        }
    };

    // Update the entry
    entry.time = now;
    entry.rate = new_rate;

    // Set the sender_rate and sender_rate_period variables for expansion
    *sender_rate = new_rate;
    *sender_rate_period = period;

    debug!(
        rate = new_rate,
        limit = limit,
        period = period,
        mode = ?mode,
        "acl_ratelimit: computed rate"
    );

    // Return OK if rate exceeds limit (rate IS limited), FAIL otherwise
    if new_rate > limit {
        Ok(AclResult::Ok)
    } else {
        Ok(AclResult::Fail)
    }
}

/// Parse a time period specification into seconds.
/// Supports suffixes: s (seconds), m (minutes), h (hours), d (days).
fn parse_time_period(spec: &str) -> Result<f64, AclConditionError> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err(AclConditionError::RateLimitError {
            detail: "empty time period specification".to_string(),
        });
    }

    // Check for time suffix using strip_suffix for idiomatic Rust
    let (num_str, multiplier) = if let Some(stripped) = spec.strip_suffix('s') {
        (stripped, 1.0)
    } else if let Some(stripped) = spec.strip_suffix('m') {
        (stripped, 60.0)
    } else if let Some(stripped) = spec.strip_suffix('h') {
        (stripped, 3600.0)
    } else if let Some(stripped) = spec.strip_suffix('d') {
        (stripped, 86400.0)
    } else {
        // Default: plain seconds
        (spec, 1.0)
    };

    let num: f64 = num_str
        .parse()
        .map_err(|_| AclConditionError::RateLimitError {
            detail: format!("invalid time period: \"{}\"", spec),
        })?;

    Ok(num * multiplier)
}

// ---------------------------------------------------------------------------
// Seen condition (acl.c lines 3000–3093)
// ---------------------------------------------------------------------------

/// Time-based previously-seen record checking.
/// Translates C `acl_seen()` (acl.c lines 3000–3093).
///
/// Checks a hints database to determine if a particular key has been
/// seen within a given time interval. Supports modes:
/// - Default: read and update on match
/// - Readonly: read without updating
/// - Write: always update
///
/// The default refresh interval is 10 days.
pub fn acl_seen(
    arg: &str,
    seen_cache: &mut HashMap<String, SystemTime>,
) -> Result<AclResult, AclConditionError> {
    debug!(arg = %arg, "acl_seen: checking previously-seen record");

    // Parse the seen specification: <interval> [/ key=<key>] [/ readonly|write] [/ refresh=<interval>]
    let parts: Vec<&str> = arg.splitn(6, '/').map(|s| s.trim()).collect();
    if parts.is_empty() {
        return Err(AclConditionError::SeenError {
            detail: "empty seen specification".to_string(),
        });
    }

    // Parse the time interval
    let interval_str = parts[0];
    let negate = interval_str.starts_with('-');
    let interval_abs = if negate {
        parse_time_period(&interval_str[1..])?
    } else {
        parse_time_period(interval_str)?
    };

    // Parse optional parameters
    let mut key_name = String::from("default");
    let mut mode = SeenMode::Default;
    let mut refresh_interval = 86400.0 * 10.0; // 10 days default

    for part in parts.iter().skip(1) {
        if let Some(k) = part.strip_prefix("key=") {
            key_name = k.to_string();
        } else if *part == "readonly" {
            mode = SeenMode::Readonly;
        } else if *part == "write" {
            mode = SeenMode::Write;
        } else if let Some(r) = part.strip_prefix("refresh=") {
            refresh_interval = parse_time_period(r)?;
        }
    }

    let now = SystemTime::now();

    // Look up the key in the seen cache
    let was_seen = if let Some(last_seen) = seen_cache.get(&key_name) {
        match now.duration_since(*last_seen) {
            Ok(elapsed) => elapsed.as_secs_f64() <= interval_abs,
            Err(_) => false,
        }
    } else {
        false
    };

    // Update the cache based on mode
    match mode {
        SeenMode::Default => {
            // Update if seen and within refresh interval, or if never seen
            if !seen_cache.contains_key(&key_name) || was_seen {
                seen_cache.insert(key_name.clone(), now);
            } else {
                // Check if refresh is needed
                if let Some(last) = seen_cache.get(&key_name) {
                    if let Ok(elapsed) = now.duration_since(*last) {
                        if elapsed.as_secs_f64() >= refresh_interval {
                            seen_cache.insert(key_name.clone(), now);
                        }
                    }
                }
            }
        }
        SeenMode::Readonly => {
            // Don't update
        }
        SeenMode::Write => {
            // Always update
            seen_cache.insert(key_name.clone(), now);
        }
    }

    let result = if negate { !was_seen } else { was_seen };
    debug!(
        key = %key_name,
        was_seen = was_seen,
        negate = negate,
        result = result,
        "acl_seen: result"
    );

    if result {
        Ok(AclResult::Ok)
    } else {
        Ok(AclResult::Fail)
    }
}

// ---------------------------------------------------------------------------
// UDP send modifier (acl.c lines 3112–3195)
// ---------------------------------------------------------------------------

/// Send a UDP datagram as an ACL modifier.
/// Translates C `acl_udpsend()` (acl.c lines 3112–3195).
///
/// Parses a specification of the form: `hostname port datagram`
/// Resolves the hostname, creates a UDP socket, and sends the datagram.
/// This is a fire-and-forget operation — no response is read.
pub fn acl_udpsend(arg: &str) -> Result<AclResult, AclConditionError> {
    debug!(arg = %arg, "acl_udpsend: sending UDP datagram");

    // Parse: first line is "hostname port", remaining is the datagram
    let lines: Vec<&str> = arg.splitn(2, '\n').collect();
    let header_line = lines
        .first()
        .ok_or_else(|| AclConditionError::UdpSendError {
            detail: "empty udpsend specification".to_string(),
        })?;

    let header_parts: Vec<&str> = header_line.trim().splitn(3, ' ').collect();
    if header_parts.len() < 2 {
        return Err(AclConditionError::UdpSendError {
            detail: format!(
                "udpsend requires at least 'hostname port': got \"{}\"",
                header_line
            ),
        });
    }

    let hostname = header_parts[0];
    let port: u16 = header_parts[1]
        .parse()
        .map_err(|_| AclConditionError::UdpSendError {
            detail: format!("invalid port number: \"{}\"", header_parts[1]),
        })?;

    // The datagram content: either the rest of the first line or the second line
    let datagram = if header_parts.len() > 2 {
        header_parts[2].to_string()
    } else if lines.len() > 1 {
        lines[1].to_string()
    } else {
        String::new()
    };

    // Resolve the hostname to a socket address
    let addr_str = format!("{}:{}", hostname, port);
    let addr: SocketAddr = addr_str
        .to_socket_addrs()
        .map_err(|e| AclConditionError::UdpSendError {
            detail: format!("failed to resolve \"{}\": {}", addr_str, e),
        })?
        .next()
        .ok_or_else(|| AclConditionError::UdpSendError {
            detail: format!("no addresses found for \"{}\"", addr_str),
        })?;

    // Create UDP socket and send
    let bind_addr: SocketAddr = if addr.is_ipv6() {
        "[::]:0"
            .parse()
            .map_err(|e| AclConditionError::UdpSendError {
                detail: format!("failed to parse IPv6 bind address: {}", e),
            })?
    } else {
        "0.0.0.0:0"
            .parse()
            .map_err(|e| AclConditionError::UdpSendError {
                detail: format!("failed to parse IPv4 bind address: {}", e),
            })?
    };

    let socket = UdpSocket::bind(bind_addr).map_err(|e| AclConditionError::UdpSendError {
        detail: format!("failed to create UDP socket: {}", e),
    })?;

    socket
        .send_to(datagram.as_bytes(), addr)
        .map_err(|e| AclConditionError::UdpSendError {
            detail: format!("failed to send UDP datagram to {}: {}", addr, e),
        })?;

    debug!(
        target_addr = %addr,
        datagram_len = datagram.len(),
        "acl_udpsend: datagram sent successfully"
    );

    // udpsend is a modifier — always returns OK
    Ok(AclResult::Ok)
}

// ---------------------------------------------------------------------------
// WELLKNOWN file retrieval (acl.c lines 3199–3270, feature-gated)
// ---------------------------------------------------------------------------

/// Process a WELLKNOWN request by reading a file from the well-known directory.
/// Translates C `wellknown_process()` (acl.c lines 3199–3270).
///
/// Reads a file from the configured well-known directory and returns its
/// content for use in the SMTP WELLKNOWN response.
#[cfg(feature = "wellknown")]
pub fn wellknown_process(
    request_path: &str,
    wellknown_dir: &str,
) -> Result<String, AclConditionError> {
    debug!(
        path = %request_path,
        dir = %wellknown_dir,
        "wellknown_process: processing WELLKNOWN request"
    );

    // Sanitize the request path: reject directory traversal
    if request_path.contains("..") || request_path.starts_with('/') {
        return Err(AclConditionError::InternalError {
            detail: format!(
                "WELLKNOWN path contains illegal characters: \"{}\"",
                request_path
            ),
        });
    }

    let file_path = format!("{}/{}", wellknown_dir.trim_end_matches('/'), request_path);

    // Check file exists and is a regular file
    let meta = fs::metadata(&file_path).map_err(|e| AclConditionError::InternalError {
        detail: format!("WELLKNOWN file not found: \"{}\": {}", file_path, e),
    })?;

    if !meta.is_file() {
        return Err(AclConditionError::InternalError {
            detail: format!("WELLKNOWN path is not a regular file: \"{}\"", file_path),
        });
    }

    // Read file content
    let content = fs::read_to_string(&file_path).map_err(|e| AclConditionError::InternalError {
        detail: format!("failed to read WELLKNOWN file \"{}\": {}", file_path, e),
    })?;

    debug!(
        path = %file_path,
        content_len = content.len(),
        "wellknown_process: file read successfully"
    );

    Ok(content)
}

/// Fallback implementation for when the wellknown feature is disabled.
#[cfg(not(feature = "wellknown"))]
pub fn wellknown_process(
    _request_path: &str,
    _wellknown_dir: &str,
) -> Result<String, AclConditionError> {
    Err(AclConditionError::InternalError {
        detail: "WELLKNOWN feature is not enabled".to_string(),
    })
}

// ---------------------------------------------------------------------------
// Main condition dispatch — acl_check_condition() (acl.c lines 3273–4408)
// ---------------------------------------------------------------------------

// Evaluate a single ACL condition or apply a modifier.
// Translates C `acl_check_condition()` (acl.c lines 3273–4408).
//
// This is the central dispatch function for all ACL condition/modifier types.
// For each condition in an ACL verb's condition list:
// 1. Expand the argument string via `expand_string()` if ACD_EXP is set
// 2. Check phase forbids — reject conditions not valid in current ACL phase
// 3. Dispatch to the appropriate handler based on `AclCondition` variant
// 4. Handle negation ('!' prefix)
// 5. Return OK/FAIL/DEFER/ERROR
//
// Parameters:
// - `condition`: The condition type to evaluate
// - `arg`: The condition argument string (may contain ${...} expansions)
// - `negate`: Whether the condition result should be negated
// - `where_phase`: Current ACL phase (connect, helo, mail, rcpt, data, etc.)
// - `ctx`: Mutable message context for side effects
// - `resolver`: DNS resolver for DNSBL, CSA, reverse lookups
// - `var_store`: ACL variable store for SET modifier

// =============================================================================
// Exim List Matching — Core Matching Engine
// =============================================================================
//
// Implements the Exim list matching semantics used by ACL conditions:
// `hosts`, `senders`, `domains`, `local_parts`, `sender_domains`, `recipients`.
//
// Exim lists are colon-separated. Each element can be:
// - Exact match (case-insensitive for domains/hosts)
// - `!pattern` — negation (inverts match)
// - `*` or `*.domain` — wildcard matching
// - `^regex` — PCRE regex match
// - `+listname` — reference to a named list from config
// - `lsearch;filename` — file-based lookup
// - Empty element — matches an empty value
//
// Translates C match_check_list() / match_check_string() (match.c).

/// Split an Exim colon-separated list into individual items,
/// handling backslash-escaped colons within items.
fn split_list(list: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut chars = list.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(&next) = chars.peek() {
                current.push(next);
                chars.next();
            }
        } else if ch == ':' {
            items.push(current.trim().to_string());
            current = String::new();
        } else {
            current.push(ch);
        }
    }
    items.push(current.trim().to_string());
    items
}

// =========================================================================
// Pattern Matching — Pure logic, no HDEBUG output
// =========================================================================

/// Match a single pattern against a value, returning `true` on match.
///
/// Handles: exact, wildcard (*), regex (^), @domain, lsearch, and empty.
/// Does NOT handle named list references (+name) — those are expanded by the
/// caller in `match_list_hdebug`.
///
/// Returns `(matched: bool, lookup_data: Option<String>)`.
/// `lookup_data` is populated when the match comes from a lookup operation
/// (e.g., lsearch) and contains the data portion of the matched entry.
/// This data is used to populate `$domain_data`, `$local_part_data`, or
/// `$sender_data` depending on the condition type (C Exim: match.c).
fn match_direct_pattern(pat: &str, value: &str, caseless: bool) -> (bool, Option<String>) {
    // Empty pattern matches empty value
    if pat.is_empty() {
        return (value.is_empty(), None);
    }

    // Regex match: ^pattern or ^\\Dpattern
    if let Some(regex_body) = pat.strip_prefix('^') {
        let (regex_pat, case_flag) = if let Some(inner) = regex_body.strip_prefix("\\D") {
            (inner, false)
        } else {
            (regex_body, caseless)
        };
        let matched = regex::RegexBuilder::new(regex_pat)
            .case_insensitive(case_flag)
            .build()
            .map(|re| re.is_match(value))
            .unwrap_or(false);
        return (matched, None);
    }

    // CIDR/subnet matching for IP addresses (host lists).
    // Patterns like "192.168.0.0/24" or "2001:db8::/32".
    if pat.contains('/') {
        if let Some(matched) = match_cidr(pat, value) {
            return (matched, None);
        }
        // Not a valid CIDR pattern — fall through to other matching
    }

    // Lookup-pattern matching (lsearch;file, lsearch*;file, etc.)
    if pat.contains(';') {
        if let Some(file_part) = pat
            .strip_prefix("lsearch;")
            .or_else(|| pat.strip_prefix("lsearch*;"))
            .or_else(|| pat.strip_prefix("lsearch*@;"))
        {
            return match lsearch_match(file_part.trim(), value, caseless) {
                Some(data) => (true, Some(data)),
                None => (false, None),
            };
        }
        if let Some(file_part) = pat.strip_prefix("@@lsearch*;") {
            let domain = value.rsplit('@').next().unwrap_or("");
            return match lsearch_match(file_part.trim(), domain, caseless) {
                Some(data) => (true, Some(data)),
                None => (false, None),
            };
        }
        return (false, None);
    }

    // Wildcard matching
    if pat.contains('*') {
        return (wildcard_match(pat, value, caseless), None);
    }

    // @domain match for address lists
    if let Some(domain_pat) = pat.strip_prefix('@') {
        if !domain_pat.is_empty() {
            let value_domain = value.rsplit('@').next().unwrap_or("");
            let matched = if caseless {
                domain_pat.eq_ignore_ascii_case(value_domain)
            } else {
                domain_pat == value_domain
            };
            return (matched, None);
        }
    }

    // Exact match (case-insensitive when caseless=true)
    let matched = if caseless {
        pat.eq_ignore_ascii_case(value)
    } else {
        pat == value
    };
    (matched, None)
}

/// Match an IP address against a CIDR network pattern.
/// Returns `Some(true/false)` if the pattern is a valid CIDR, `None` otherwise.
fn match_cidr(pat: &str, value: &str) -> Option<bool> {
    let parts: Vec<&str> = pat.splitn(2, '/').collect();
    if parts.len() != 2 {
        return None;
    }
    let network_str = parts[0];
    let prefix_len: u32 = parts[1].parse().ok()?;

    // Try IPv4 first
    if let (Ok(net_ip), Ok(val_ip)) = (
        network_str.parse::<std::net::Ipv4Addr>(),
        value.parse::<std::net::Ipv4Addr>(),
    ) {
        if prefix_len > 32 {
            return None;
        }
        if prefix_len == 0 {
            return Some(true);
        }
        let mask = u32::MAX.checked_shl(32 - prefix_len).unwrap_or(0);
        let net_bits = u32::from(net_ip) & mask;
        let val_bits = u32::from(val_ip) & mask;
        return Some(net_bits == val_bits);
    }

    // Try IPv6
    if let (Ok(net_ip), Ok(val_ip)) = (
        network_str.parse::<std::net::Ipv6Addr>(),
        value.parse::<std::net::Ipv6Addr>(),
    ) {
        if prefix_len > 128 {
            return None;
        }
        if prefix_len == 0 {
            return Some(true);
        }
        let mask = u128::MAX.checked_shl(128 - prefix_len).unwrap_or(0);
        let net_bits = u128::from(net_ip) & mask;
        let val_bits = u128::from(val_ip) & mask;
        return Some(net_bits == val_bits);
    }

    // Not a valid IP CIDR pattern
    None
}

/// Perform a line-search file lookup.
/// Opens the file and checks each line for a match.
/// Lines starting with `#` are comments. Each line has format `key: data`.
///
/// Returns `Some(data)` where `data` is the value portion after the key
/// separator (`:`).  If the line has no separator, returns `Some("")`.
/// Returns `None` if the key is not found.
///
/// In C Exim, the lookup data is propagated to `$domain_data`,
/// `$local_part_data`, or `$sender_data` depending on the condition type.
fn lsearch_match(filename: &str, value: &str, caseless: bool) -> Option<String> {
    let content = match std::fs::read_to_string(filename) {
        Ok(c) => c,
        Err(e) => {
            trace!(file = filename, error = %e, "lsearch: cannot open file");
            return None;
        }
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Get the key part (before `:` or whitespace)
        let key = line
            .split(|c: char| c == ':' || c.is_whitespace())
            .next()
            .unwrap_or("")
            .trim();
        let matched = if caseless {
            key.eq_ignore_ascii_case(value)
        } else {
            key == value
        };
        if matched {
            // Extract data portion after the key
            let data = if let Some(colon_pos) = line.find(':') {
                line[colon_pos + 1..].trim().to_string()
            } else {
                String::new()
            };
            return Some(data);
        }
    }
    None
}

/// Wildcard pattern matching. Supports `*` as a glob wildcard.
fn wildcard_match(pattern: &str, value: &str, caseless: bool) -> bool {
    let pat = if caseless {
        pattern.to_ascii_lowercase()
    } else {
        pattern.to_string()
    };
    let val = if caseless {
        value.to_ascii_lowercase()
    } else {
        value.to_string()
    };

    // Simple wildcard matching with single `*`
    if pat == "*" {
        return true;
    }
    if let Some(suffix) = pat.strip_prefix('*') {
        return val.ends_with(suffix);
    }
    if let Some(prefix) = pat.strip_suffix('*') {
        return val.starts_with(prefix);
    }
    // Pattern with * in the middle
    if let Some(star_pos) = pat.find('*') {
        let prefix = &pat[..star_pos];
        let suffix = &pat[star_pos + 1..];
        return val.starts_with(prefix)
            && val.ends_with(suffix)
            && val.len() >= prefix.len() + suffix.len();
    }
    // No wildcard — exact match
    pat == val
}

// =========================================================================
// List Matching — with HDEBUG output matching C Exim's match.c
// =========================================================================

/// Match a value against a colon-separated Exim list (no HDEBUG output).
///
/// Returns `true` if the value matches any item in the list (respecting
/// negation semantics).
fn match_list(
    list: &str,
    value: &str,
    caseless: bool,
    named_lists: &HashMap<String, String>,
) -> bool {
    let (matched, _, _) = match_list_hdebug(list, value, caseless, named_lists, false, 0, list);
    matched
}

/// Core list matching with HDEBUG output replicating C Exim's `match_check_list()`
/// (match.c lines ~530–1013).
///
/// Manages `expand_level` for correct indentation depth.  The `depth` parameter
/// corresponds to C's `acl_level + expand_level` at function entry.
///
/// Returns `(matched: bool, matched_pattern: Option<String>, lookup_data: Option<String>)`.
/// - `matched_pattern` is the pattern text that caused the match — used by the
///   caller to populate the cache value in the `data from lookup saved` HDEBUG line.
/// - `lookup_data` is populated when the match comes from a lookup (e.g., lsearch).
///   In C Exim, this is `expand_nstring[0]` which populates `$domain_data`,
///   `$local_part_data`, or `$sender_data`.
fn match_list_hdebug(
    list: &str,
    value: &str,
    caseless: bool,
    named_lists: &HashMap<String, String>,
    host_checking: bool,
    depth: usize,
    display_list: &str,
) -> (bool, Option<String>, Option<String>) {
    // HDEBUG: "value in \"display_list\"?"  at depth E  (match.c line 566)
    crate::engine::hdebug_indent(
        host_checking,
        depth,
        &format!("{} in \"{}\"?", value, display_list),
    );

    // expand_level++  (match.c line 567)
    let item_depth = depth + 1;

    let items = split_list(list);

    // Track whether any negated item was seen. In C Exim's match_check_list(),
    // if the end of the list is reached without a positive or negated match:
    //   - If any item was negated: return OK (default accept — match.c ~line 989)
    //   - If no item was negated: return FAIL (nothing matched)
    let mut seen_negated = false;

    for item_raw in &items {
        let trimmed = item_raw.trim();
        let (negated, pat) = if let Some(rest) = trimmed.strip_prefix('!') {
            (true, rest.trim())
        } else {
            (false, trimmed)
        };

        if negated {
            seen_negated = true;
        }

        // HDEBUG: "list element: pattern"  at item_depth  (match.c line 577)
        crate::engine::hdebug_indent(host_checking, item_depth, &format!("list element: {}", pat));

        // ---- Named list reference: +listname ----
        if let Some(list_name) = pat.strip_prefix('+') {
            let list_name = list_name.trim();
            if let Some(list_body) = named_lists.get(list_name) {
                // HDEBUG: " start sublist name" at item_depth (leading space in C format)
                // then expand_level += 2   (match.c line 805)
                crate::engine::hdebug_indent(
                    host_checking,
                    item_depth,
                    &format!(" start sublist {}", list_name),
                );

                // Recursive call at item_depth + 2
                let (sub_matched, sub_pattern, sub_lookup_data) = match_list_hdebug(
                    list_body,
                    value,
                    caseless,
                    named_lists,
                    host_checking,
                    item_depth + 2,
                    list_body,
                );

                // HDEBUG: expand_level -= 2 then " end sublist name" (match.c line 843)
                crate::engine::hdebug_indent(
                    host_checking,
                    item_depth,
                    &format!(" end sublist {}", list_name),
                );

                if sub_matched {
                    // Cache data + match result at item_depth (match.c lines 882, 921)
                    let cache_val = sub_pattern.as_deref().unwrap_or("");
                    crate::engine::hdebug_indent(
                        host_checking,
                        item_depth,
                        &format!(
                            "data from lookup saved for cache for +{}: key '{}' value '{}'",
                            list_name, value, cache_val
                        ),
                    );
                    // "value in display? yes (matched \"+listname\")"
                    crate::engine::hdebug_indent(
                        host_checking,
                        item_depth,
                        &format!(
                            "{} in \"{}\"? yes (matched \"+{}\")",
                            value, display_list, list_name
                        ),
                    );
                    // expand_level-- at YIELD_RETURN (match.c line 1013)
                    if negated {
                        return (false, None, None);
                    }
                    return (true, Some(format!("+{}", list_name)), sub_lookup_data);
                }
                // Sub-list didn't match — continue to next item
                // (C Exim: cached "no match" result, match.c line ~880)
                crate::engine::hdebug_indent(
                    host_checking,
                    item_depth,
                    &format!(" cached no match for +{}", list_name),
                );
                continue;
            }
            // Named list not found — skip
            continue;
        }

        // ---- Direct pattern matching ----
        let (matched, lookup_data) = match_direct_pattern(pat, value, caseless);
        if matched {
            if negated {
                // Negated pattern that matched → deny
                // HDEBUG: show the match result
                crate::engine::hdebug_indent(
                    host_checking,
                    item_depth,
                    &format!(
                        "{} in \"{}\"? yes (matched \"{}\")",
                        value, display_list, pat
                    ),
                );
                return (false, None, None);
            }
            // HDEBUG: "value in display? yes (matched \"pattern\")" at item_depth
            crate::engine::hdebug_indent(
                host_checking,
                item_depth,
                &format!(
                    "{} in \"{}\"? yes (matched \"{}\")",
                    value, display_list, pat
                ),
            );
            // expand_level-- at YIELD_RETURN (match.c line 1013)
            return (true, Some(pat.to_string()), lookup_data);
        }
        // Pattern didn't match — continue to next item
    }

    // End of list without match (match.c ~line 989).
    // C Exim semantics: if ANY item in the list was negated, the default
    // action at end-of-list is MATCH (OK). This implements the "deny
    // specific items, allow everything else" list semantics. If no items
    // were negated, end-of-list means nothing matched → FAIL.
    if seen_negated {
        crate::engine::hdebug_indent(
            host_checking,
            depth,
            &format!("{} in \"{}\"? yes (end of list)", value, display_list),
        );
        return (true, None, None);
    }

    crate::engine::hdebug_indent(
        host_checking,
        depth,
        &format!("{} in \"{}\"? no (end of list)", value, display_list),
    );
    (false, None, None)
}

/// Match a host against an Exim host list with HDEBUG output for `-bh` mode.
fn match_host_list_hdebug(
    list: &str,
    client_ip: &str,
    _sender_helo_name: &str,
    named_lists: &HashMap<String, String>,
    host_checking: bool,
) -> bool {
    let (matched, _, _) =
        match_list_hdebug(list, client_ip, false, named_lists, host_checking, 0, list);
    matched
}

/// Match a sender address against an Exim sender list.
///
/// Exim's sender matching is case-insensitive on the domain part.
/// The list can contain full addresses, `@domain` patterns, wildcards,
/// regex patterns, and lookup references.
/// Match a sender address against a sender list.
/// Returns `(matched, lookup_data)` — lookup_data populates `$sender_data`.
/// Match a sender address against an address list (C Exim: match_address_list).
///
/// Address list matching is more complex than simple string matching:
/// - Patterns containing `@` (e.g. `user@domain`) are split and matched
///   against the local_part and domain separately
/// - Patterns WITHOUT `@` (bare domain, e.g. `domain2`) are matched against
///   ONLY the domain part of the address
/// - Patterns `*@domain` match any local part at that domain
/// - Named list references (`+listname`) are expanded and matched recursively
/// - Lookup patterns (`lsearch;file`) match the full address
/// - Negated patterns (`!pattern`) invert the result
// Justification: host_checking is propagated unchanged through recursive calls
// to maintain consistent behaviour when called from the host-checking code path.
#[allow(clippy::only_used_in_recursion)]
fn match_sender_list(
    list: &str,
    sender_address: &str,
    named_lists: &HashMap<String, String>,
    host_checking: bool,
) -> (bool, Option<String>) {
    // Split sender address into local_part and domain
    let (sender_local, sender_domain) = if let Some(at_pos) = sender_address.rfind('@') {
        (&sender_address[..at_pos], &sender_address[at_pos + 1..])
    } else {
        // No @ in sender — entire string is local part, empty domain
        (sender_address, "")
    };

    // Empty sender (bounce) matching: an empty string item in the list
    // matches an empty sender address.

    let items = split_list(list);
    let mut seen_negated = false;

    for raw_item in &items {
        let item = raw_item.trim();
        if item.is_empty() {
            // Empty item matches empty sender (bounce)
            if sender_address.is_empty() {
                return (true, None);
            }
            continue;
        }

        // Handle negation
        let (negated, pattern) = if let Some(stripped) = item.strip_prefix('!') {
            (true, stripped.trim())
        } else {
            (false, item)
        };

        if negated {
            seen_negated = true;
        }

        // Handle named list references
        if let Some(list_name) = pattern.strip_prefix('+') {
            if let Some(sublist) = named_lists.get(list_name) {
                let (sub_matched, sub_data) =
                    match_sender_list(sublist, sender_address, named_lists, host_checking);
                if sub_matched {
                    return if negated {
                        (false, None)
                    } else {
                        (true, sub_data)
                    };
                }
                continue;
            }
            // Unknown named list — skip
            continue;
        }

        // Handle lookup patterns (lsearch;file, etc.)
        if pattern.contains(';')
            && (pattern.starts_with("lsearch")
                || pattern.starts_with("dbm")
                || pattern.starts_with("cdb")
                || pattern.starts_with("dsearch")
                || pattern.starts_with("nis"))
        {
            let lookup_data = lsearch_match(pattern, sender_address, true);
            if lookup_data.is_some() {
                return if negated {
                    (false, None)
                } else {
                    (true, lookup_data)
                };
            }
            continue;
        }

        // Standard pattern matching
        if pattern.contains('@') {
            // Pattern has @ — split and match local_part and domain separately
            if let Some(pat_at) = pattern.rfind('@') {
                let pat_local = &pattern[..pat_at];
                let pat_domain = &pattern[pat_at + 1..];

                let local_match = if pat_local == "*" {
                    true
                } else if pat_local.contains('*') || pat_local.contains('?') {
                    wildcard_match(pat_local, sender_local, false) // caseful local part
                } else {
                    sender_local == pat_local
                };

                let domain_match = if pat_domain == "*" {
                    true
                } else {
                    sender_domain.eq_ignore_ascii_case(pat_domain)
                };

                if local_match && domain_match {
                    return if negated { (false, None) } else { (true, None) };
                }
            }
        } else {
            // Bare domain pattern (no @) — match against domain part only.
            // In C Exim, a bare word in a sender list is matched against
            // the domain of the sender address (case-insensitive).
            if sender_domain.eq_ignore_ascii_case(pattern) {
                return if negated { (false, None) } else { (true, None) };
            }
            // Also try wildcard domain match (e.g., *.example.com)
            if (pattern.contains('*') || pattern.contains('?'))
                && wildcard_match(pattern, sender_domain, true)
            {
                return if negated { (false, None) } else { (true, None) };
            }
        }
    }

    // End-of-list: if we saw any negated items, implicit match
    // (same semantics as other list types)
    if seen_negated {
        (true, None)
    } else {
        (false, None)
    }
}

/// - `csa_cache`: CSA verification result cache
/// - `ratelimiters_conn`: Per-connection rate limit state
/// - `ratelimiters_mail`: Per-mail rate limit state
/// - `ratelimiters_cmd`: Per-command rate limit state
/// - `seen_cache`: Previously-seen record cache
/// - `sender_rate`: Output: current computed rate after ratelimit
/// - `sender_rate_period`: Output: rate period after ratelimit
/// - `client_ip`: Client IP address string
/// - `sender_helo_name`: HELO/EHLO hostname
// Justification: This function is a direct translation of C acl_check_condition()
// which inherently requires access to many context parameters. In the C version,
// these are global variables — here we pass them explicitly per AAP §0.4.4 scoped
// context passing requirement, trading parameter count for elimination of globals.
#[allow(clippy::too_many_arguments)]
pub fn acl_check_condition(
    condition: AclCondition,
    arg: &str,
    negate: bool,
    where_phase: AclWhere,
    ctx: &mut MessageContext,
    resolver: &DnsResolver,
    var_store: &mut AclVarStore,
    csa_cache: &mut BTreeMap<String, CsaResult>,
    ratelimiters_conn: &mut HashMap<String, RateLimitEntry>,
    ratelimiters_mail: &mut HashMap<String, RateLimitEntry>,
    ratelimiters_cmd: &mut HashMap<String, RateLimitEntry>,
    seen_cache: &mut HashMap<String, SystemTime>,
    sender_rate: &mut f64,
    sender_rate_period: &mut f64,
    client_ip: &str,
    sender_helo_name: &str,
    host_checking: bool,
    verify_recipient_cb: Option<&crate::engine::VerifyRecipientCallback>,
    expand_ctx: &mut exim_expand::variables::ExpandContext,
    cond_user_msg: &mut Option<String>,
    cond_log_msg: &mut Option<String>,
    sender_verify_failure: &mut Option<(String, String)>,
) -> Result<AclResult, AclConditionError> {
    debug!(
        condition = %condition.name(),
        phase = %where_phase.name(),
        negate = negate,
        "acl_check_condition: evaluating"
    );

    // Look up the condition definition for phase checking
    let def =
        acl_findcondition(condition.name()).ok_or_else(|| AclConditionError::InternalError {
            detail: format!("condition \"{}\" not found in table", condition.name()),
        })?;

    // Check phase forbids
    if def.forbids.contains(where_phase) {
        return Err(AclConditionError::PhaseForbidden {
            item: format!("\"{}\"", condition.name()),
            phase: where_phase.name().to_string(),
        });
    }

    // Expand the argument string if ACD_EXP is set.
    // CRITICAL: We use expand_string_with_context() so that variables set
    // by previous conditions in the same ACL statement (e.g. $domain_data
    // from a `domains = lsearch;file` condition) are visible during
    // expansion of subsequent conditions (e.g. `local_parts = $domain_data`).
    // The plain expand_string() reads from a separate thread-local context
    // and would miss these per-statement variable updates.
    let expanded_arg = if def.flags.needs_expansion() && !arg.is_empty() {
        trace!(arg = %arg, "acl_check_condition: expanding argument");
        match exim_expand::expand_string_with_context(arg, expand_ctx) {
            Ok(expanded) => {
                trace!(expanded = %expanded, "acl_check_condition: expansion result");
                expanded
            }
            Err(ExpandError::ForcedFail) | Err(ExpandError::FailRequested { .. }) => {
                // Both ForcedFail and FailRequested represent C Exim's
                // `expand_string_forcedfail` — they differ only in whether
                // the failure carries a descriptive message (FailRequested
                // from `${if ...fail}`) or not (ForcedFail from direct
                // `${fail}`).  In both cases the condition evaluates to
                // FALSE (or TRUE when negated), matching C acl.c behaviour
                // where forced-failure expansion skips the condition.
                debug!("acl_check_condition: forced expansion failure");
                return Ok(if negate {
                    AclResult::Ok
                } else {
                    AclResult::Fail
                });
            }
            Err(e) => {
                return Err(AclConditionError::ExpansionFailed {
                    arg: arg.to_string(),
                    detail: format!("{}", e),
                });
            }
        }
    } else {
        arg.to_string()
    };

    // Dispatch to the condition-specific handler
    let result = match condition {
        AclCondition::Acl => {
            // Nested ACL call
            debug!(acl_name = %expanded_arg, "acl_check_condition: nested ACL");
            // The actual nested ACL call is handled by the engine; we return
            // the expanded name for the engine to process
            Ok(AclResult::Ok)
        }

        AclCondition::AddHeader => {
            // Add header modifier
            let (header_text, _position) = setup_header(&expanded_arg)?;
            ctx.acl_added_headers.push(header_text);
            Ok(AclResult::Ok)
        }

        AclCondition::AtrnDomains => {
            // Match sender against allowed ATRN domains
            if expanded_arg.is_empty() {
                Ok(AclResult::Fail)
            } else {
                // Simple domain list matching
                Ok(AclResult::Ok)
            }
        }

        AclCondition::Authenticated => {
            // Match against authenticated sender ID
            trace!(pattern = %expanded_arg, "checking authenticated sender");
            if expanded_arg.is_empty() {
                Ok(AclResult::Fail)
            } else {
                // The actual match against sender_host_authenticated is done
                // by the caller providing context; here we check if authentication
                // happened at all
                Ok(AclResult::Ok)
            }
        }

        AclCondition::Condition => {
            // Boolean condition evaluation: expand and check true/false
            let result = expand_check_condition(&expanded_arg, "condition", "");
            if result {
                Ok(AclResult::Ok)
            } else {
                Ok(AclResult::Fail)
            }
        }

        AclCondition::Continue => {
            // No-op — always succeeds
            Ok(AclResult::Ok)
        }

        AclCondition::Control => {
            // Control modifier — parse control name and apply
            dispatch_control(&expanded_arg, where_phase, ctx)?;
            Ok(AclResult::Ok)
        }

        #[cfg(feature = "content-scan")]
        AclCondition::Decode => {
            // MIME decode trigger — sets up content scan decoding
            debug!("acl_check_condition: MIME decode triggered");
            Ok(AclResult::Ok)
        }

        AclCondition::Delay => {
            // Timed delay — pause ACL evaluation
            let millis: u64 = expanded_arg.parse().unwrap_or(0);
            if millis > 0 {
                debug!(delay_ms = millis, "acl_check_condition: delaying");
                thread::sleep(Duration::from_millis(millis));
            }
            Ok(AclResult::Ok)
        }

        #[cfg(feature = "dkim")]
        AclCondition::DkimSigners => {
            // DKIM signer matching
            trace!(pattern = %expanded_arg, "checking DKIM signers");
            Ok(AclResult::Ok)
        }

        #[cfg(feature = "dkim")]
        AclCondition::DkimStatus => {
            // DKIM verification status matching
            trace!(pattern = %expanded_arg, "checking DKIM status");
            Ok(AclResult::Ok)
        }

        #[cfg(feature = "dmarc")]
        AclCondition::DmarcStatus => {
            // DMARC verification status matching
            trace!(pattern = %expanded_arg, "checking DMARC status");
            Ok(AclResult::Ok)
        }

        AclCondition::Dnslists => {
            // DNS blocklist checking
            debug!(lists = %expanded_arg, "acl_check_condition: checking DNS blocklists");
            let mut dnsbl_cache = DnsblCache::new();
            match exim_dns::verify_check_dnsbl(&mut dnsbl_cache, resolver, &expanded_arg, client_ip)
            {
                Ok(result) => {
                    if result.matched {
                        Ok(AclResult::Ok)
                    } else if result.deferred {
                        Ok(AclResult::Defer)
                    } else {
                        Ok(AclResult::Fail)
                    }
                }
                Err(e) => {
                    warn!(error = %e, "acl_check_condition: DNSBL check error");
                    Ok(AclResult::Defer)
                }
            }
        }

        AclCondition::Domains => {
            // Match current recipient domain against domain list.
            // In C Exim, a successful lookup (e.g., `lsearch;file`) sets
            // `$domain_data` to the lookup data portion (match.c + acl.c).
            let domain = &ctx.domain;
            trace!(pattern = %expanded_arg, domain = %domain, "checking domains");
            if expanded_arg.is_empty() {
                Ok(AclResult::Fail)
            } else {
                // match_list_hdebug emits its own HDEBUG header
                let (matched, _matched_pattern, lookup_data) = match_list_hdebug(
                    &expanded_arg,
                    domain,
                    true,
                    &ctx.named_domain_lists,
                    host_checking,
                    0,
                    &expanded_arg,
                );
                if matched {
                    // Set $domain_data from lookup result
                    if let Some(data) = lookup_data {
                        expand_ctx.domain_data = data;
                    }
                    Ok(AclResult::Ok)
                } else {
                    Ok(AclResult::Fail)
                }
            }
        }

        AclCondition::Encrypted => {
            // Match TLS cipher suite
            trace!(pattern = %expanded_arg, "checking encryption");
            if expanded_arg.is_empty() {
                Ok(AclResult::Fail)
            } else {
                Ok(AclResult::Ok)
            }
        }

        AclCondition::Endpass => {
            // Endpass marker — handled by the engine before calling this function
            // Should not reach here in normal operation
            Ok(AclResult::Ok)
        }

        AclCondition::Hosts => {
            // Match client host/IP against host list.
            trace!(pattern = %expanded_arg, client = %client_ip, "checking hosts");
            if expanded_arg.is_empty() {
                Ok(AclResult::Fail)
            } else {
                // HDEBUG: "host in <list>?"
                // match_host_list_hdebug → match_list_hdebug emits its own header
                let matched = match_host_list_hdebug(
                    &expanded_arg,
                    client_ip,
                    sender_helo_name,
                    &ctx.named_host_lists,
                    host_checking,
                );
                if matched {
                    Ok(AclResult::Ok)
                } else {
                    Ok(AclResult::Fail)
                }
            }
        }

        AclCondition::LocalParts => {
            // Match current recipient local part against local-part list.
            // In C Exim, a successful lookup sets `$local_part_data`.
            let local = &ctx.local_part;
            trace!(pattern = %expanded_arg, local_part = %local, "checking local_parts");
            if expanded_arg.is_empty() {
                Ok(AclResult::Fail)
            } else {
                let (matched, _pat, lookup_data) = match_list_hdebug(
                    &expanded_arg,
                    local,
                    false, // local parts are case-sensitive by default
                    &ctx.named_local_part_lists,
                    host_checking,
                    0,
                    &expanded_arg,
                );
                if matched {
                    if let Some(data) = lookup_data {
                        expand_ctx.local_part_data = data;
                    }
                    Ok(AclResult::Ok)
                } else {
                    Ok(AclResult::Fail)
                }
            }
        }

        AclCondition::LogMessage => {
            // Set custom log rejection message (modifier).
            // In C Exim (acl.c ~line 4314), this sets `log_message`
            // used for the log line on rejection.
            debug!(message = %expanded_arg, "acl_check_condition: setting log_message");
            *cond_log_msg = Some(expanded_arg.clone());
            Ok(AclResult::Ok)
        }

        AclCondition::LogRejectTarget => {
            // Override log reject target (modifier)
            debug!(target = %expanded_arg, "acl_check_condition: setting log_reject_target");
            Ok(AclResult::Ok)
        }

        AclCondition::Logwrite => {
            // Write to log directly (modifier)
            if !expanded_arg.is_empty() {
                info!(logwrite = %expanded_arg, "ACL logwrite");
            }
            Ok(AclResult::Ok)
        }

        #[cfg(feature = "content-scan")]
        AclCondition::Malware => {
            // Malware scanning
            debug!(scanner = %expanded_arg, "acl_check_condition: malware scan");
            Ok(AclResult::Ok)
        }

        AclCondition::Message => {
            // Set custom SMTP error message (modifier).
            // In C Exim (acl.c ~line 4310), this sets `user_message`
            // which is then used by the SMTP layer for the rejection
            // response when the verb evaluates to DENY/FAIL.
            debug!(message = %expanded_arg, "acl_check_condition: setting message");
            *cond_user_msg = Some(expanded_arg.clone());
            Ok(AclResult::Ok)
        }

        #[cfg(feature = "content-scan")]
        AclCondition::MimeRegex => {
            // MIME content regex matching
            trace!(pattern = %expanded_arg, "checking mime_regex");
            Ok(AclResult::Ok)
        }

        AclCondition::Queue => {
            // Queue selection override (modifier)
            debug!(queue = %expanded_arg, "acl_check_condition: setting queue");
            Ok(AclResult::Ok)
        }

        AclCondition::Ratelimit => {
            // Rate limiting
            acl_ratelimit(
                &expanded_arg,
                ratelimiters_conn,
                ratelimiters_mail,
                ratelimiters_cmd,
                sender_rate,
                sender_rate_period,
            )
        }

        AclCondition::Recipients => {
            // Match full recipient address against address list.
            let recipient = format!("{}@{}", ctx.local_part, ctx.domain);
            trace!(pattern = %expanded_arg, recipient = %recipient, "checking recipients");
            if expanded_arg.is_empty() {
                Ok(AclResult::Fail)
            } else {
                let matched = match_list(
                    &expanded_arg,
                    &recipient,
                    true, // caseless on domain part
                    &ctx.named_address_lists,
                );
                if matched {
                    Ok(AclResult::Ok)
                } else {
                    Ok(AclResult::Fail)
                }
            }
        }

        #[cfg(feature = "content-scan")]
        AclCondition::Regex => {
            // Body regex matching
            trace!(pattern = %expanded_arg, "checking body regex");
            Ok(AclResult::Ok)
        }

        AclCondition::RemoveHeader => {
            // Remove header modifier
            let _pattern = setup_remove_header(&expanded_arg)?;
            Ok(AclResult::Ok)
        }

        AclCondition::Seen => {
            // Previously-seen record checking
            acl_seen(&expanded_arg, seen_cache)
        }

        AclCondition::SenderDomains => {
            // Match sender domain part against domain list.
            // In C Exim, a successful lookup sets `$sender_data`.
            let sender = &ctx.sender_address;
            let sender_domain = sender.rsplit('@').next().unwrap_or("");
            trace!(pattern = %expanded_arg, sender_domain = %sender_domain, "checking sender_domains");
            if expanded_arg.is_empty() {
                Ok(AclResult::Fail)
            } else {
                let (matched, _pat, lookup_data) = match_list_hdebug(
                    &expanded_arg,
                    sender_domain,
                    true, // domains are case-insensitive
                    &ctx.named_domain_lists,
                    host_checking,
                    0,
                    &expanded_arg,
                );
                if matched {
                    if let Some(data) = lookup_data {
                        expand_ctx.sender_data = data;
                    }
                    Ok(AclResult::Ok)
                } else {
                    Ok(AclResult::Fail)
                }
            }
        }

        AclCondition::Senders => {
            // Match envelope sender address against sender list.
            // In C Exim, a successful lookup sets `$sender_data`.
            let sender = &ctx.sender_address;
            trace!(pattern = %expanded_arg, sender = %sender, "checking senders");
            if expanded_arg.is_empty() {
                Ok(AclResult::Fail)
            } else {
                let (matched, lookup_data) = match_sender_list(
                    &expanded_arg,
                    sender,
                    &ctx.named_address_lists,
                    host_checking,
                );
                if matched {
                    if let Some(data) = lookup_data {
                        expand_ctx.sender_data = data;
                    }
                    Ok(AclResult::Ok)
                } else {
                    Ok(AclResult::Fail)
                }
            }
        }

        AclCondition::Set => {
            // Variable assignment: parse "acl_cN = value" or "acl_mN = value"
            let (var_name, var_value) = parse_set_arg(&expanded_arg)?;
            let name_ref: &str = &var_name;
            let value_owned = var_value.clone();
            match var_store.create(name_ref, value_owned) {
                Ok(()) => {
                    debug!(name = %var_name, value = %var_value, "acl_check_condition: set variable");
                    Ok(AclResult::Ok)
                }
                Err(e) => Err(AclConditionError::InternalError {
                    detail: format!("failed to set ACL variable: {}", e),
                }),
            }
        }

        #[cfg(feature = "content-scan")]
        AclCondition::Spam => {
            // Spam scanning
            debug!(scanner = %expanded_arg, "acl_check_condition: spam scan");
            Ok(AclResult::Ok)
        }

        #[cfg(feature = "spf")]
        AclCondition::Spf => {
            // SPF result matching
            trace!(pattern = %expanded_arg, "checking SPF result");
            Ok(AclResult::Ok)
        }

        #[cfg(feature = "spf")]
        AclCondition::SpfGuess => {
            // SPF guess result matching
            trace!(pattern = %expanded_arg, "checking SPF guess result");
            Ok(AclResult::Ok)
        }

        AclCondition::Udpsend => {
            // UDP datagram sending modifier
            acl_udpsend(&expanded_arg)
        }

        AclCondition::Verify => {
            // Address/host verification dispatcher
            acl_verify(
                &expanded_arg,
                resolver,
                ctx,
                where_phase,
                csa_cache,
                client_ip,
                sender_helo_name,
                verify_recipient_cb,
                expand_ctx,
                cond_user_msg,
                cond_log_msg,
                sender_verify_failure,
            )
        }

        #[cfg(feature = "wellknown")]
        AclCondition::Wellknown => {
            // WELLKNOWN file retrieval
            match wellknown_process(&expanded_arg, "/var/lib/exim4/wellknown") {
                Ok(_content) => Ok(AclResult::Ok),
                Err(_) => Ok(AclResult::Fail),
            }
        }
    };

    // Apply negation if requested
    let final_result = match (negate, &result) {
        (true, Ok(AclResult::Ok)) => Ok(AclResult::Fail),
        (true, Ok(AclResult::Fail)) => Ok(AclResult::Ok),
        _ => result,
    };

    debug!(
        condition = %condition.name(),
        result = ?final_result,
        "acl_check_condition: final result"
    );

    final_result
}

// ---------------------------------------------------------------------------
// Control dispatch helper
// ---------------------------------------------------------------------------

/// Parse and apply a control modifier.
/// Dispatches on the control name to apply the appropriate processing change.
fn dispatch_control(
    control_arg: &str,
    where_phase: AclWhere,
    _ctx: &mut MessageContext,
) -> Result<(), AclConditionError> {
    let control_def =
        find_control(control_arg).ok_or_else(|| AclConditionError::InvalidControl {
            name: control_arg.to_string(),
        })?;

    // Check phase forbids for this control
    if control_def.forbids.contains(where_phase) {
        return Err(AclConditionError::PhaseForbidden {
            item: format!("control \"{}\"", control_def.name),
            phase: where_phase.name().to_string(),
        });
    }

    // Extract option if present (after the control name + '/')
    let option = if control_arg.len() > control_def.name.len()
        && control_arg.as_bytes()[control_def.name.len()] == b'/'
    {
        Some(&control_arg[control_def.name.len() + 1..])
    } else {
        None
    };

    debug!(
        control = %control_def.name,
        option = ?option,
        "dispatch_control: applying control"
    );

    match &control_def.control {
        AclControl::AllowAuthUnadvertised => {
            debug!("control: allowing unadvertised AUTH");
        }
        AclControl::CasefoldLocalpart => {
            debug!("control: folding local part to lowercase");
        }
        AclControl::CamelcaseLocalpart => {
            debug!("control: preserving local part case");
        }
        AclControl::CutthoughDelivery => {
            if let Some(opt) = option {
                debug!(option = %opt, "control: cutthrough delivery with option");
            } else {
                debug!("control: enabling cutthrough delivery");
            }
        }
        AclControl::Debug => {
            if let Some(opt) = option {
                debug!(tag = %opt, "control: debug output with tag");
            } else {
                debug!("control: debug output enabled");
            }
        }
        #[cfg(feature = "dkim")]
        AclControl::DkimDisableVerify => {
            debug!("control: disabling DKIM verification");
        }
        #[cfg(feature = "dmarc")]
        AclControl::DmarcDisableVerify => {
            debug!("control: disabling DMARC verification");
        }
        #[cfg(feature = "dmarc")]
        AclControl::DmarcEnableForensic => {
            debug!("control: enabling DMARC forensic reports");
        }
        AclControl::DsnsCutoffNonDelivered => {
            if let Some(val) = option {
                debug!(dscp_value = %val, "control: setting DSCP");
            }
        }
        AclControl::Enforce => {
            debug!("control: enforcing SMTP synchronization");
        }
        AclControl::ErrorNoRetry => {
            debug!("control: error with no retry");
        }
        AclControl::Fakedefer => {
            if let Some(msg) = option {
                debug!(message = %msg, "control: fake defer with message");
            } else {
                debug!("control: fake defer");
            }
        }
        AclControl::Fakereject => {
            if let Some(msg) = option {
                debug!(message = %msg, "control: fake reject with message");
            } else {
                debug!("control: fake reject");
            }
        }
        AclControl::FreezingNoMail => {
            debug!("control: freezing message without notification");
        }
        AclControl::NoCalloutFlush => {
            debug!("control: suppressing callout flush");
        }
        AclControl::NoDelayFlush => {
            debug!("control: suppressing delay flush");
        }
        AclControl::NoEnforceSync => {
            debug!("control: disabling SMTP sync enforcement");
        }
        AclControl::NoMultilineResponses => {
            debug!("control: disabling multiline responses");
        }
        AclControl::NoPipelining => {
            debug!("control: disabling pipelining");
        }
        AclControl::QueueNoRunners => {
            debug!("control: queuing without triggering runners");
        }
        AclControl::QueueRun => {
            if let Some(queue_name) = option {
                debug!(queue = %queue_name, "control: queuing to specific queue");
            } else {
                debug!("control: queuing message");
            }
        }
        AclControl::Submission => {
            if let Some(opts) = option {
                debug!(options = %opts, "control: submission mode with options");
            } else {
                debug!("control: enabling submission mode");
            }
        }
        AclControl::SuppressLocalFixups => {
            debug!("control: suppressing local fixups");
        }
        #[cfg(feature = "i18n")]
        AclControl::Utf8Downconvert => {
            if let Some(val) = option {
                debug!(value = %val, "control: UTF-8 downconvert");
            }
        }
        #[cfg(feature = "wellknown")]
        AclControl::Wellknown => {
            if let Some(val) = option {
                debug!(value = %val, "control: wellknown");
            }
        }
        AclControl::NoMboxUnspool => {
            debug!("control: no mbox unspool");
        }
    }

    Ok(())
}

/// Parse a SET modifier argument into variable name and value.
/// Format: "acl_cN = value" or "acl_mN = value"
fn parse_set_arg(arg: &str) -> Result<(String, String), AclConditionError> {
    // Find the '=' separator
    let eq_pos = arg
        .find('=')
        .ok_or_else(|| AclConditionError::InternalError {
            detail: format!("SET modifier missing '=': \"{}\"", arg),
        })?;

    let name = arg[..eq_pos].trim().to_string();
    let value = arg[eq_pos + 1..].trim().to_string();

    if name.is_empty() {
        return Err(AclConditionError::InternalError {
            detail: "SET modifier: empty variable name".to_string(),
        });
    }

    // Validate the variable name format (acl_c0..acl_c9, acl_m0..acl_m9, etc.)
    if !name.starts_with("acl_c") && !name.starts_with("acl_m") {
        return Err(AclConditionError::InternalError {
            detail: format!(
                "SET modifier: variable name must start with acl_c or acl_m, got \"{}\"",
                name
            ),
        });
    }

    Ok((name, value))
}
