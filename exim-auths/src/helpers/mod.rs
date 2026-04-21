// SPDX-License-Identifier: GPL-2.0-or-later

//! # Shared Authentication Helper Functions
//!
//! This module provides common utility functions used across multiple
//! authenticator driver implementations. These helpers are **always compiled**
//! (not feature-gated) since they provide shared functionality needed by
//! all/most auth drivers.
//!
//! ## Modules
//!
//! - [`base64_io`] — SMTP AUTH base64 challenge/response I/O functions.
//!   Provides [`auth_read_input()`](base64_io::auth_read_input),
//!   [`auth_get_data()`](base64_io::auth_get_data),
//!   [`auth_get_no64_data()`](base64_io::auth_get_no64_data),
//!   [`auth_prompt()`](base64_io::auth_prompt), and
//!   [`auth_client_item()`](base64_io::auth_client_item).
//!   Rewritten from `get_data.c` (262 lines) and `get_no64_data.c` (49 lines).
//!
//! - [`server_condition`] — Server condition evaluation for authorization.
//!   Provides [`auth_check_serv_cond()`](server_condition::auth_check_serv_cond)
//!   and [`auth_check_some_cond()`](server_condition::auth_check_some_cond).
//!   Rewritten from `check_serv_cond.c` (126 lines).
//!
//! - [`saslauthd`] — Cyrus saslauthd/pwcheck daemon integration.
//!   Provides [`auth_call_saslauthd()`](saslauthd::auth_call_saslauthd) and
//!   [`saslauthd_verify_password()`](saslauthd::saslauthd_verify_password).
//!   Rewritten from `call_saslauthd.c` (69 lines), `pwcheck.c` (377 lines),
//!   and `pwcheck.h` (27 lines).
//!
//! ## Source File Mapping
//!
//! | C Source File | Rust Module |
//! |---|---|
//! | `src/src/auths/get_data.c` (262 lines) | [`base64_io`] |
//! | `src/src/auths/get_no64_data.c` (49 lines) | [`base64_io`] |
//! | `src/src/auths/check_serv_cond.c` (126 lines) | [`server_condition`] |
//! | `src/src/auths/call_saslauthd.c` (69 lines) | [`saslauthd`] |
//! | `src/src/auths/pwcheck.c` (377 lines) | [`saslauthd`] |
//! | `src/src/auths/pwcheck.h` (27 lines) | [`saslauthd`] |

// ---------------------------------------------------------------------------
// Module declarations — always compiled, never feature-gated.
// These are used by auth driver modules in the parent `src/` directory.
// ---------------------------------------------------------------------------

pub mod base64_io;
pub mod saslauthd;
pub mod server_condition;

// ---------------------------------------------------------------------------
// Convenience re-exports — allow drivers to import key types directly from
// `crate::helpers::` without navigating into each sub-module.
//
// Example:
//   use crate::helpers::{auth_check_serv_cond, AuthConditionResult};
// instead of:
//   use crate::helpers::server_condition::{auth_check_serv_cond, AuthConditionResult};
// ---------------------------------------------------------------------------

/// Re-export of [`base64_io::AuthIoResult`] — the result enum for SMTP AUTH
/// I/O operations used across all auth drivers.
pub use base64_io::AuthIoResult;

/// Re-export of [`server_condition::AuthConditionResult`] — the result enum
/// for server condition evaluation used by all auth drivers after the SASL
/// exchange completes.
pub use server_condition::AuthConditionResult;

/// Re-export of [`server_condition::auth_check_serv_cond`] — thin wrapper
/// that evaluates the `server_condition` option of an authenticator instance.
pub use server_condition::auth_check_serv_cond;

/// Re-export of [`server_condition::auth_check_some_cond`] — generic
/// condition evaluator used by `auth_check_serv_cond` and available for
/// custom condition checks in individual auth drivers.
pub use server_condition::auth_check_some_cond;

/// Re-export of [`saslauthd::PwCheckResult`] — low-level result type from
/// the saslauthd wire protocol, mapping directly to the C `PWCHECK_OK`,
/// `PWCHECK_NO`, and `PWCHECK_FAIL` constants.
pub use saslauthd::PwCheckResult;

/// Re-export of [`saslauthd::SaslauthdResult`] — high-level result type from
/// [`auth_call_saslauthd`], mapping to Exim `OK`, `FAIL`, and `ERROR` codes.
pub use saslauthd::SaslauthdResult;

/// Re-export of [`saslauthd::auth_call_saslauthd`] — the public entry point
/// for saslauthd-based password verification, called from auth drivers that
/// use the Cyrus saslauthd daemon for credential checking.
pub use saslauthd::auth_call_saslauthd;
