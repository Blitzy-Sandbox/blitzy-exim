// SPDX-License-Identifier: GPL-2.0-or-later
//
//! # Shared Authentication Helper Functions
//!
//! This module provides common utility functions used across multiple
//! authenticator driver implementations. These helpers are always compiled
//! (not feature-gated) since they provide shared functionality needed by
//! all/most auth drivers.
//!
//! ## Modules
//!
//! - [`base64_io`] — SMTP AUTH base64 challenge/response I/O functions.
//! - [`server_condition`] — Server condition evaluation for authorization.
//! - [`saslauthd`] — Cyrus saslauthd/pwcheck daemon integration.

pub mod base64_io;
pub mod saslauthd;
pub mod server_condition;
