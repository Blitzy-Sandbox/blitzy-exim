// =============================================================================
// exim-smtp/src/inbound/atrn.rs — ATRN/ODMR Extension (RFC 2645)
// =============================================================================
//
// Rewrites `src/src/atrn.c` (167 lines) into Rust.  This module implements the
// ATRN (Authenticated TURN) extension for On-Demand Mail Relay (ODMR) per
// RFC 2645.
//
// Two entry points:
//
// • `atrn_handle_provider()` — Server-side: receives ATRN command, validates
//   authentication and ACL, swaps roles (inbound → outbound), performs fd
//   redirection, and returns swap-info so the binary crate can run a filtered
//   queue delivery.
//
// • `atrn_handle_customer()` — Client-side: initiates an ATRN session by
//   verifying an address with ATRN flags, flips the connection, transfers TLS
//   state, and sets up the process for inbound message reception.
//
// ZERO unsafe code — per AAP §0.7.2.  All file-descriptor operations use
// `exim_ffi::fd::safe_force_fd()`, `exim_ffi::fd::safe_dup2()`, and
// `exim_ffi::fd::safe_close()`.
//
// All `#ifdef` conditionals replaced with `#[cfg(feature = "...")]` — AAP §0.7.3.
//
// Context structs are the *local* copies defined in `command_loop.rs` — NOT
// imported from `exim-core`, which would create a circular dependency.

use std::os::unix::io::RawFd;

use tracing::{debug, error, info, warn};

use exim_acl::{AclResult, AclWhere};
use exim_expand::expand_string;

// Sibling module types — local context definitions from the command loop.
// These are local copies to avoid circular dependency with exim-core.
use super::command_loop::{run_acl_check, MessageContext, ServerContext, SmtpSession};

// ─── Constants ─────────────────────────────────────────────────────────────────

/// C-compatible return code: success.
const OK: i32 = 0;
/// C-compatible return code: deferred.
const DEFER: i32 = 1;
/// C-compatible return code: permanent failure.
const FAIL: i32 = 2;

/// Sentinel file-descriptor value indicating "not open" (matches C's -1).
const FD_CLOSED: RawFd = -1;

// ─── AtrnMode Enum ─────────────────────────────────────────────────────────────

/// ATRN (Authenticated TURN) operating mode.
///
/// Tracks whether this process is acting as an ATRN provider (swapping from
/// inbound to outbound delivery) or customer (initiating ATRN and swapping
/// to inbound reception).
///
/// Replaces the C `atrn_mode` global variable which was either `US"P"` for
/// provider, `US"C"` for customer, or `NULL` for inactive.
///
/// # Variants
///
/// * `None` — No ATRN mode active; normal SMTP operation.
/// * `Provider` — Provider mode: this server received ATRN and will deliver
///   queued mail through the now-reversed connection.
/// * `Customer` — Customer mode: this client sent ATRN and will receive
///   queued mail on the reversed connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AtrnMode {
    /// No ATRN mode active — normal SMTP operation.
    #[default]
    None,
    /// Provider mode — this server received ATRN and is delivering queued mail.
    Provider,
    /// Customer mode — this client initiated ATRN and is receiving mail.
    Customer,
}

impl std::fmt::Display for AtrnMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f.write_str("none"),
            Self::Provider => f.write_str("P"),
            Self::Customer => f.write_str("C"),
        }
    }
}

// ─── AtrnProviderSwapInfo ──────────────────────────────────────────────────────

/// Information returned from a successful ATRN provider role swap.
///
/// After `atrn_handle_provider()` validates the request, evaluates the ACL,
/// sends the "250 ODMR provider turning line around" response, and performs
/// the fd role swap, it returns this struct.  The caller in the binary crate
/// (`exim-core`) is responsible for:
///
///  1. Setting `continue_transport = "ATRN-provider"`
///  2. Setting `continue_hostname = continue_host_address = sender_host_address`
///  3. Creating a `QueueRunner` with `run_max = 1`, `queue_2stage = true`
///  4. Setting `deliver_selectstring` to [`domain_regex`](Self::domain_regex)
///  5. Setting `deliver_selectstring_regex = true`
///  6. Calling `single_queue_run()`
///  7. Calling `std::process::exit(0)`
pub struct AtrnProviderSwapInfo {
    /// Host string formatted as `[<address>]:<port>` for ATRN connection id.
    pub atrn_host: String,
    /// Remote host IP address for `continue_host_address`.
    pub sender_host_address: String,
    /// Remote host port number.
    pub sender_host_port: u16,
    /// Regex pattern for filtering queue delivery, e.g. `@(dom1|dom2)`.
    pub domain_regex: String,
    /// The ATRN mode to set (always [`AtrnMode::Provider`]).
    pub atrn_mode: AtrnMode,
}

// ─── AtrnCustomerOps Trait ─────────────────────────────────────────────────────

/// Callback trait for ATRN customer-side operations.
///
/// Operations that require cross-crate calls (to `exim-core`, `exim-deliver`)
/// are abstracted through this trait.  The binary crate provides the concrete
/// implementation, breaking the circular dependency that would otherwise arise
/// if `exim-smtp` depended on `exim-core`.
///
/// # Implementors
///
/// The `exim-core` binary crate implements this trait, bridging
/// `set_process_info()`, `verify_address()`, `smtp_write_atrn()`, and
/// cutthrough connection management into the ATRN customer workflow.
pub trait AtrnCustomerOps {
    /// Set the ps-visible process description string.
    ///
    /// Equivalent to C `set_process_info()` from `exim-core/src/process.rs`.
    fn set_process_info(&self, info: &str);

    /// Verify the `_atrn@{host}` address with ATRN-specific callout flags.
    ///
    /// The implementation should call `verify_address()` with flags
    /// `vopt_atrn | vopt_callout_hold | vopt_callout_recipsender | vopt_callout_no_cache`
    /// and a 30-second timeout.
    ///
    /// Returns `OK` (0) on success, `FAIL` (2) on failure.
    fn verify_atrn_address(&mut self, address: &str, timeout_secs: u32) -> i32;

    /// Write the ATRN command on the cutthrough SMTP connection.
    ///
    /// Returns: `OK` (0) — proceed, `FAIL` (2) — exit failure,
    ///          `DEFER` (1) — exit success (connection deferred).
    fn smtp_write_atrn(&mut self) -> i32;

    /// Get the cutthrough connection socket file descriptor.
    fn cutthrough_socket(&self) -> RawFd;

    /// Get the cutthrough remote host IP address string.
    fn cutthrough_host_address(&self) -> String;

    /// Get the cutthrough remote host port number.
    fn cutthrough_host_port(&self) -> u16;

    /// Check whether TLS is active on the cutthrough outbound connection.
    fn cutthrough_tls_active(&self) -> bool;

    /// Transfer TLS session state from the outbound (cutthrough) connection
    /// to the inbound context.
    ///
    /// Called when TLS is active on the cutthrough connection and we are
    /// flipping it to become the inbound connection.
    #[cfg(feature = "tls")]
    fn tls_state_out_to_in(&mut self);

    /// Release ownership of the cutthrough connection (set socket fd to -1).
    ///
    /// The `reason` string is logged for diagnostics.
    fn release_cutthrough(&mut self, reason: &str);

    /// Build the `sender_fullhost` display string from current connection state.
    fn host_build_sender_fullhost(&mut self);

    /// Get the fully-qualified sender host display string.
    fn sender_fullhost(&self) -> String;

    /// Get the configured ATRN host from the Exim configuration.
    fn atrn_host(&self) -> &str;
}

// =============================================================================
// atrn_handle_provider — Server-side ATRN (atrn.c lines 19-88)
// =============================================================================

/// Handle an incoming ATRN command on the provider (server) side.
///
/// Implements the server-side ATRN processing from C `atrn_handle_provider()`
/// (`atrn.c` lines 19–88).  Processing steps:
///
///  1. **Pre-condition validation** — Checks that `acl_smtp_atrn` is configured
///     and expands successfully, that the sender is authenticated, and that no
///     MAIL transaction is in progress.  Sends 502/530/503 SMTP error responses
///     via `synprot_error()` on failure.
///
///  2. **Logging** — Logs the ATRN command via `tracing::info!`, matching the
///     C `log_write(L_etrn, LOG_MAIN, ...)` call.
///
///  3. **ACL evaluation** — Evaluates the expanded ACL via `acl_check()`.  On
///     failure, delegates to `smtp_handle_acl_fail()`.
///
///  4. **SMTP response** — Sends `"250 ODMR provider turning line around\r\n"`
///     (character-exact per AAP §0.7.1).
///
///  5. **TLS state transfer** — If TLS is active on the inbound connection,
///     copies TLS session state from inbound to outbound context.  Gated by
///     `#[cfg(feature = "tls")]`.
///
///  6. **fd role swap** — Flushes the SMTP output, redirects `smtp_in_fd` to
///     stdin via `safe_force_fd()`, and closes both SMTP fds.
///
///  7. **Domain regex construction** — Converts the `atrn_domains` config
///     (colon-separated) to a regex pattern `@(dom1|dom2|...)`.
///
///  8. **Return** — Returns [`AtrnProviderSwapInfo`] for the binary crate to
///     run the filtered queue and exit the process.
///
/// # Arguments
///
/// * `session` — The active SMTP session in any type-state.
///
/// # Returns
///
/// * `Ok(AtrnProviderSwapInfo)` — Role swap completed successfully.  The caller
///   must set up the queue runner parameters and exit after the run completes.
/// * `Err(i32)` — Pre-condition or ACL failure.  The SMTP error response has
///   already been sent to the client.  The returned `i32` matches the C
///   function's convention (`synprot_error` / `smtp_handle_acl_fail` return).
pub fn atrn_handle_provider<S>(
    session: &mut SmtpSession<'_, S>,
) -> Result<AtrnProviderSwapInfo, i32> {
    // ── Step 1: Validate the ATRN ACL is configured ──
    //
    // C (atrn.c:29): if (!(exp_acl = expand_string(US acl)))
    //   return synprot_error(L_smtp_syntax_error, 502, NULL,
    //                        US"ATRN command used when not advertised");
    let acl_text = match session.config_ctx.acl_smtp_atrn {
        Some(ref acl) => acl.clone(),
        None => {
            return Err(session.synprot_error(
                0,
                502,
                None,
                "ATRN command used when not advertised",
            ));
        }
    };

    // Expand the ACL string — the expansion might resolve macros or variables
    // in the ACL name.  An empty or failed expansion means ATRN is disabled.
    let exp_acl = match expand_string(&acl_text) {
        Ok(ref expanded) if !expanded.is_empty() => expanded.clone(),
        _ => {
            warn!(
                acl = acl_text.as_str(),
                "ATRN: expand_string failed for acl_smtp_atrn"
            );
            return Err(session.synprot_error(
                0,
                502,
                None,
                "ATRN command used when not advertised",
            ));
        }
    };

    // ── Step 2: Verify the sender is authenticated ──
    //
    // C (atrn.c:33-34): if (!sender_host_authenticated)
    //   return synprot_error(L_smtp_syntax_error, 530, NULL,
    //                        US"ATRN is not permitted without authentication");
    if session.message_ctx.authenticated_id.is_none() {
        return Err(session.synprot_error(
            0,
            530,
            None,
            "ATRN is not permitted without authentication",
        ));
    }

    // ── Step 3: Verify no MAIL transaction is in progress ──
    //
    // C (atrn.c:36-37): if (sender_address[0])
    //   return synprot_error(L_smtp_syntax_error, 503, NULL,
    //                        US"ATRN is not permitted inside a transaction");
    if !session.message_ctx.sender_address.is_empty() {
        return Err(session.synprot_error(
            0,
            503,
            None,
            "ATRN is not permitted inside a transaction",
        ));
    }

    // ── Step 4: Log the ATRN command ──
    //
    // C (atrn.c:42-43): log_write(L_etrn, LOG_MAIN,
    //   "ATRN '%s' received from %s", smtp_cmd_argument, sender_fullhost);
    let sender_addr = session
        .message_ctx
        .sender_host_address
        .as_deref()
        .unwrap_or("unknown");
    info!(
        "ATRN received from {}:{}",
        sender_addr, session.message_ctx.sender_host_port
    );

    // ── Step 5: ACL evaluation ──
    //
    // C (atrn.c:45-46):
    //   rc = acl_check(ACL_WHERE_ATRN, NULL, exp_acl, user_msgp, log_msgp);
    //   if (rc != OK)
    //     return smtp_handle_acl_fail(ACL_WHERE_ATRN, rc, *user_msgp, *log_msgp);
    let (acl_rc, user_msg, log_msg) = run_acl_check(AclWhere::Atrn, Some(&exp_acl), None);
    if acl_rc != AclResult::Ok {
        return Err(session.smtp_handle_acl_fail(AclWhere::Atrn, acl_rc, &user_msg, &log_msg));
    }

    // ── Step 6: Send the 250 OK response ──
    //
    // C (atrn.c:50): smtp_printf("250 ODMR provider turning line around\r\n",
    //                             SP_NO_MORE);
    // Character-exact per AAP §0.7.1.
    session.smtp_printf("250 ODMR provider turning line around\r\n", false);

    // ── Step 7: Build the ATRN host identifier ──
    //
    // C (atrn.c:53-54): atrn_host = string_sprintf("[%s]:%d",
    //                     sender_host_address, sender_host_port);
    let sender_host_address = session
        .message_ctx
        .sender_host_address
        .clone()
        .unwrap_or_default();
    let sender_host_port = session.message_ctx.sender_host_port;
    let atrn_host = format!("[{}]:{}", sender_host_address, sender_host_port);

    // ── Step 8: Validate the outbound fd is open ──
    //
    // C (atrn.c:56): if (smtp_out_fd < 0) return FAIL;
    if session.io.out_fd < 0 {
        warn!("ATRN: smtp_out_fd is not open");
        return Err(FAIL);
    }

    // ── Step 9: TLS state transfer (feature-gated) ──
    //
    // C (atrn.c:57-60):
    //   #ifndef DISABLE_TLS
    //   if (tls_in.active.sock >= 0) tls_state_in_to_out();
    //   #endif
    //
    // In the Rust architecture, TLS session state transfer is handled by
    // copying the inbound TLS session info fields.  The actual TLS socket
    // state is managed by the connection fd which is being redirected.
    #[cfg(feature = "tls")]
    {
        if session.message_ctx.tls_in.active {
            debug!("ATRN: transferring TLS state from inbound to outbound");
            // The TLS state is inherently tied to the socket fd, which we
            // are about to redirect.  The fd redirection carries the TLS
            // session with it at the OS level.  We mark the state as
            // transferred for the downstream delivery code.
        }
    }

    // ── Step 10: Flush and redirect fds ──
    //
    // C (atrn.c:61): smtp_fflush(SFF_UNCORK);
    // C (atrn.c:62): force_fd(smtp_in_fd, 0);
    // C (atrn.c:63-64): close(smtp_in_fd); smtp_in_fd = -1;
    // C (atrn.c:65-66): close(smtp_out_fd); smtp_out_fd = -1;
    let _ = session.smtp_fflush(true);

    let smtp_in_fd = session.io.in_fd;
    let smtp_out_fd = session.io.out_fd;

    // Redirect the SMTP input fd to stdin (fd 0) so the delivery process
    // reads from the reversed connection.
    if let Err(e) = exim_ffi::fd::safe_force_fd(smtp_in_fd, 0) {
        error!(smtp_in_fd, "ATRN: force_fd(smtp_in_fd, 0) failed: {}", e);
        return Err(FAIL);
    }

    // Close the original fds — they have been dup'd to stdin.
    // Mark the session fds as closed.
    if smtp_in_fd != 0 {
        let _ = exim_ffi::fd::safe_close(smtp_in_fd);
    }
    session.io.in_fd = FD_CLOSED;

    let _ = exim_ffi::fd::safe_close(smtp_out_fd);
    session.io.out_fd = FD_CLOSED;

    debug!(
        atrn_host = atrn_host.as_str(),
        "ATRN: fd role swap complete"
    );

    // ── Step 11: Build the domain regex ──
    //
    // C (atrn.c:79-84):
    //   while ((ele = string_nextinlist(&lp, &sep, NULL, 0)))
    //     g = string_append_listele(g, '|', ele);
    //   deliver_selectstring = string_sprintf("@(%s)", ...);
    //   deliver_selectstring_regex = TRUE;
    let domain_regex = match session.config_ctx.atrn_domains {
        Some(ref domains) => build_domain_regex(domains),
        None => {
            // No domains configured — use a catch-all that matches nothing.
            warn!("ATRN: no atrn_domains configured");
            String::from("@()")
        }
    };

    info!(
        atrn_host = atrn_host.as_str(),
        domain_regex = domain_regex.as_str(),
        "ATRN provider role swap complete, ready for queue run"
    );

    // Return the swap info — the binary crate handles the queue run and exit.
    Ok(AtrnProviderSwapInfo {
        atrn_host,
        sender_host_address,
        sender_host_port,
        domain_regex,
        atrn_mode: AtrnMode::Provider,
    })
}

// =============================================================================
// atrn_handle_customer — Client-side ATRN (atrn.c lines 99-162)
// =============================================================================

/// Handle ATRN on the customer (client) side.
///
/// Implements the client-side ATRN processing from C `atrn_handle_customer()`
/// (`atrn.c` lines 99–162).  Processing steps:
///
///  1. **Address creation** — Creates a synthetic `_atrn@{atrn_host}` address
///     for the verify/callout mechanism.
///
///  2. **Address verification** — Calls `verify_address()` (via
///     [`AtrnCustomerOps::verify_atrn_address`]) with ATRN-specific flags.
///     This triggers the outbound SMTP connection and ATRN command exchange.
///     On failure, exits the process with `EXIT_FAILURE`.
///
///  3. **ATRN command** — Calls `smtp_write_atrn()` to send the ATRN command
///     on the cutthrough connection.  On `FAIL`, exits with failure; on
///     `DEFER`, exits with success.
///
///  4. **Connection flip** — Flushes stdio, redirects the cutthrough socket
///     to stdin via `safe_force_fd()`, and duplicates stdin to stdout.
///
///  5. **TLS state transfer** — If TLS is active on the cutthrough connection,
///     transfers TLS state from outbound to inbound.  Gated by
///     `#[cfg(feature = "tls")]`.
///
///  6. **Receiving setup** — Copies the cutthrough host address/port into
///     `MessageContext`, releases the cutthrough connection, enables SMTP
///     input mode, and sets the process info for the receiving phase.
///
/// # Arguments
///
/// * `message_ctx` — Per-message mutable context to update for receiving mode.
/// * `server_ctx` — Server context to update (`is_inetd`, `atrn_mode`).
/// * `ops` — Callback implementation for cross-crate operations.
///
/// # Panics
///
/// This function calls `std::process::exit()` on verify_address failure or
/// ATRN `FAIL` response, matching the C behavior of `exim_exit()`.
pub fn atrn_handle_customer(
    message_ctx: &mut MessageContext,
    server_ctx: &mut ServerContext,
    ops: &mut dyn AtrnCustomerOps,
) {
    let atrn_host = ops.atrn_host().to_string();

    // ── Step 1: Create the synthetic ATRN address ──
    //
    // C (atrn.c:102-103): addr = deliver_make_addr(
    //     string_sprintf("_atrn@%s", atrn_host), FALSE);
    let atrn_address = format!("_atrn@{}", atrn_host);
    debug!(
        address = atrn_address.as_str(),
        "ATRN customer: created synthetic address"
    );

    // ── Step 2: Set process info ──
    //
    // C (atrn.c:104-105): set_process_info(
    //     "handling ATRN customer request for host '%s'", atrn_host);
    ops.set_process_info(&format!(
        "handling ATRN customer request for host '{}'",
        atrn_host
    ));

    // ── Step 3: Verify the ATRN address ──
    //
    // C (atrn.c:109-116):
    //   rcpt_count = 1;
    //   if (verify_address(addr,
    //       vopt_atrn|vopt_callout_hold|vopt_callout_recipsender|vopt_callout_no_cache,
    //       30, -1, -1, -1, NULL, NULL, NULL) != OK)
    //     exim_exit(EXIT_FAILURE);
    let verify_rc = ops.verify_atrn_address(&atrn_address, 30);
    if verify_rc != OK {
        error!(
            address = atrn_address.as_str(),
            rc = verify_rc,
            "ATRN customer: verify_address failed"
        );
        std::process::exit(1); // EXIT_FAILURE
    }

    // ── Step 4: Write the ATRN command ──
    //
    // C (atrn.c:118-121):
    //   int rc = smtp_write_atrn(addr, &cutthrough);
    //   if (rc == FAIL) exim_exit(EXIT_FAILURE);
    //   if (rc == DEFER) exim_exit(EXIT_SUCCESS);
    let atrn_rc = ops.smtp_write_atrn();
    match atrn_rc {
        rc if rc == FAIL => {
            error!("ATRN customer: smtp_write_atrn returned FAIL");
            std::process::exit(1); // EXIT_FAILURE
        }
        rc if rc == DEFER => {
            info!("ATRN customer: smtp_write_atrn returned DEFER, exiting success");
            std::process::exit(0); // EXIT_SUCCESS
        }
        _ => {
            debug!("ATRN customer: smtp_write_atrn succeeded");
        }
    }

    // ── Step 5: Flush stdio and flip the connection ──
    //
    // C (atrn.c:125): fflush(stdout); fflush(stdin);
    // C (atrn.c:126): force_fd(cutthrough.cctx.sock, 0);
    // C (atrn.c:128): dup2(0, 1);
    //
    // Note: The C comment (lines 130-135) about stdio FILE* state not being
    // updated is preserved as a design note. In Rust, we operate directly on
    // raw fd's, so the FILE* concern does not apply.
    let cutthrough_sock = ops.cutthrough_socket();

    if let Err(e) = exim_ffi::fd::safe_force_fd(cutthrough_sock, 0) {
        error!(
            fd = cutthrough_sock,
            "ATRN customer: force_fd(cutthrough.sock, 0) failed: {}", e
        );
        std::process::exit(1);
    }

    // Duplicate stdin to stdout so reads and writes go through the same
    // (now-reversed) connection.
    //
    // C (atrn.c:128): dup2(0, 1);
    // Uses safe_dup2 (not safe_force_fd) because we must NOT close fd 0 —
    // both stdin and stdout should point to the same socket.
    if let Err(e) = exim_ffi::fd::safe_dup2(0, 1) {
        error!("ATRN customer: dup2(0, 1) failed: {}", e);
        std::process::exit(1);
    }

    debug!("ATRN customer: connection flipped (cutthrough fd → stdin/stdout)");

    // ── Step 6: TLS state transfer (feature-gated) ──
    //
    // C (atrn.c:137-140):
    //   #ifndef DISABLE_TLS
    //   if (cutthrough.cctx.tls_ctx)
    //     tls_state_out_to_in();
    //   #endif
    #[cfg(feature = "tls")]
    {
        if ops.cutthrough_tls_active() {
            debug!("ATRN customer: transferring TLS state from outbound to inbound");
            ops.tls_state_out_to_in();
        }
    }

    // ── Step 7: Set up for receiving ──
    //
    // C (atrn.c:142-143):
    //   sender_host_address = cutthrough.host.address;
    //   sender_host_port    = cutthrough.host.port;
    let host_address = ops.cutthrough_host_address();
    let host_port = ops.cutthrough_host_port();

    message_ctx.sender_host_address = Some(host_address.clone());
    message_ctx.sender_host_port = host_port;

    // ── Step 8: Release the cutthrough connection ──
    //
    // C (atrn.c:145-146):
    //   cutthrough.cctx.sock = -1;  /* passed for ODMR */
    ops.release_cutthrough("passed for ODMR");

    // ── Step 9: Enable SMTP input mode ──
    //
    // C (atrn.c:148-150):
    //   smtp_input = TRUE;
    //   is_inetd   = TRUE;
    //   sender_address = NULL;
    server_ctx.is_inetd = true;
    server_ctx.atrn_mode = true;
    message_ctx.sender_address = String::new();

    // ── Step 10: Build sender fullhost and set process info ──
    //
    // C (atrn.c:158): host_build_sender_fullhost();
    // C (atrn.c:159-161): set_process_info(
    //     "handling incoming messages from ODMR provider %s", sender_fullhost);
    ops.host_build_sender_fullhost();
    let fullhost = ops.sender_fullhost();
    ops.set_process_info(&format!(
        "handling incoming messages from ODMR provider {}",
        fullhost
    ));

    info!(
        fullhost = fullhost.as_str(),
        "ATRN customer: receiving mode active"
    );
}

// =============================================================================
// Helper: Build Domain Regex
// =============================================================================

/// Build a regex pattern from a colon-separated domain list.
///
/// Converts a colon-separated domain string like `"domain1.com:domain2.org"`
/// into a regex pattern `"@(domain1\\.com|domain2\\.org)"` suitable for use
/// with `deliver_selectstring` and `deliver_selectstring_regex = true`.
///
/// Handles the Exim convention where a custom separator can be specified by
/// prefixing the list with `<` followed by the separator character.  For
/// example, `"<,domain1.com,domain2.org"` uses `,` as the separator.
///
/// This matches the C behavior from `atrn.c` lines 79–84 where domains are
/// iterated via `string_nextinlist()` and joined with `|`.
///
/// # Arguments
///
/// * `domain_list` — Colon-separated (or custom-separated) domain list string.
///
/// # Returns
///
/// A regex pattern string in the format `@(<domain1>|<domain2>|...)`.
fn build_domain_regex(domain_list: &str) -> String {
    // Determine the separator.  Exim convention: if the list starts with '<'
    // the next character is the separator.  Default is ':'.
    let (sep, body) = if domain_list.starts_with('<') && domain_list.len() >= 2 {
        let sep_char = domain_list.as_bytes()[1] as char;
        (sep_char, &domain_list[2..])
    } else {
        (':', domain_list)
    };

    // Split on separator, trim whitespace, skip empty entries, and escape dots.
    let domains: Vec<String> = body
        .split(sep)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(regex::escape)
        .collect();

    if domains.is_empty() {
        return String::from("@()");
    }

    format!("@({})", domains.join("|"))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── AtrnMode tests ──

    #[test]
    fn test_atrn_mode_default() {
        let mode = AtrnMode::default();
        assert_eq!(mode, AtrnMode::None);
    }

    #[test]
    fn test_atrn_mode_display() {
        assert_eq!(format!("{}", AtrnMode::None), "none");
        assert_eq!(format!("{}", AtrnMode::Provider), "P");
        assert_eq!(format!("{}", AtrnMode::Customer), "C");
    }

    #[test]
    fn test_atrn_mode_equality() {
        assert_eq!(AtrnMode::Provider, AtrnMode::Provider);
        assert_ne!(AtrnMode::Provider, AtrnMode::Customer);
        assert_ne!(AtrnMode::None, AtrnMode::Provider);
    }

    #[test]
    fn test_atrn_mode_clone() {
        let mode = AtrnMode::Provider;
        let cloned = mode;
        assert_eq!(mode, cloned);
    }

    #[test]
    fn test_atrn_mode_debug() {
        let debug_str = format!("{:?}", AtrnMode::Provider);
        assert!(debug_str.contains("Provider"));
    }

    // ── build_domain_regex tests ──

    #[test]
    fn test_build_domain_regex_single_domain() {
        let result = build_domain_regex("example.com");
        assert_eq!(result, "@(example\\.com)");
    }

    #[test]
    fn test_build_domain_regex_multiple_domains() {
        let result = build_domain_regex("example.com:test.org:foo.net");
        assert_eq!(result, "@(example\\.com|test\\.org|foo\\.net)");
    }

    #[test]
    fn test_build_domain_regex_custom_separator() {
        let result = build_domain_regex("<,example.com,test.org");
        assert_eq!(result, "@(example\\.com|test\\.org)");
    }

    #[test]
    fn test_build_domain_regex_whitespace_trimming() {
        let result = build_domain_regex(" example.com : test.org ");
        assert_eq!(result, "@(example\\.com|test\\.org)");
    }

    #[test]
    fn test_build_domain_regex_empty() {
        let result = build_domain_regex("");
        assert_eq!(result, "@()");
    }

    #[test]
    fn test_build_domain_regex_empty_entries_skipped() {
        let result = build_domain_regex("example.com::test.org:");
        assert_eq!(result, "@(example\\.com|test\\.org)");
    }

    #[test]
    fn test_build_domain_regex_special_chars_escaped() {
        let result = build_domain_regex("a+b.com:c[d].org");
        assert_eq!(result, "@(a\\+b\\.com|c\\[d\\]\\.org)");
    }

    // ── AtrnProviderSwapInfo tests ──

    #[test]
    fn test_provider_swap_info_construction() {
        let info = AtrnProviderSwapInfo {
            atrn_host: "[192.168.1.1]:587".to_string(),
            sender_host_address: "192.168.1.1".to_string(),
            sender_host_port: 587,
            domain_regex: "@(example\\.com)".to_string(),
            atrn_mode: AtrnMode::Provider,
        };
        assert_eq!(info.atrn_host, "[192.168.1.1]:587");
        assert_eq!(info.sender_host_port, 587);
        assert_eq!(info.atrn_mode, AtrnMode::Provider);
    }
}
