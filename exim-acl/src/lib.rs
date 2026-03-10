// Copyright (c) The Exim Maintainers 2020 - 2025
// Copyright (c) University of Cambridge 1995 - 2018
// SPDX-License-Identifier: GPL-2.0-or-later

//! # exim-acl — Access Control List Evaluation Engine
//!
//! This crate replaces `src/src/acl.c` (5,147 lines of C) from the Exim MTA source tree.
//! It implements the complete ACL evaluation engine for Exim: verb evaluation (accept,
//! deny, defer, discard, drop, require, warn), condition checking across 30+ condition
//! types, phase enforcement across 22+ SMTP phases, and ACL variable management.
//!
//! The ACL engine is consumed by `exim-core` (for top-level ACL dispatch) and
//! `exim-smtp` (for per-SMTP-phase ACL invocation at connect, helo, mail, rcpt,
//! data, mime, dkim, prdr phases).

// Submodule declarations — each module corresponds to a distinct functional area
// of the ACL evaluation engine.

/// ACL phase definitions: [`AclWhere`](phases::AclWhere) enum, [`AclBitSet`](phases::AclBitSet)
/// bitmask type, `BIT_*` constants, and the forbids/permits system.
pub mod phases;
