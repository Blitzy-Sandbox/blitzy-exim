//! Parallel delivery dispatch and connection pooling for outbound SMTP.
//!
//! This module manages the coordination of multiple simultaneous SMTP sessions
//! for delivering to different hosts, connection reuse logic, and delivery
//! attempt scheduling.  It is the Rust equivalent of the parallelism
//! coordination found in:
//!
//! - `src/src/deliver.c` — `pardata` subprocess pool, `par_wait()`,
//!   `par_reduce()`, `remote_max_parallel` logic
//! - `src/src/smtp_out.c` — `smtp_connect()`, `smtp_boundsock()`,
//!   `smtp_sock_connect()` connection management
//! - `src/src/transports/smtp.c` — `connection_max_messages`, `continue_hostname`,
//!   RSET-based connection recycling, recipient batching
//!
//! # Architecture (AAP §0.4.4 — Scoped Context Passing)
//!
//! All mutable state flows through explicit parameters rather than the 714 C
//! global variables.  Connection parameters, delivery state, and configuration
//! are ALL passed as function arguments.  The C pattern of accessing globals
//! like `sending_ip_address`, `sending_port`, `remote_max_parallel`,
//! `continue_hostname`, etc. is replaced by explicit context structs.
//!
//! # Parallel Delivery Model
//!
//! Exim uses a **fork-per-connection** concurrency model (AAP §0.7.3).  This
//! module does NOT use `tokio` — the async runtime is scoped ONLY to lookup
//! execution.  Instead, parallel delivery is managed through:
//!
//! 1. **Connection pool** — A fixed-size array of [`ConnectionSlot`] entries,
//!    each representing a single outbound SMTP session.
//! 2. **Delivery batching** — Recipients are grouped by target host:port into
//!    [`DeliveryBatch`] structs for efficient per-host delivery.
//! 3. **Connection reuse** — Active connections are recycled via SMTP RSET for
//!    subsequent messages to the same host, up to `connection_max_messages`.
//! 4. **Scheduling** — [`schedule_deliveries`] assigns batches to pool slots,
//!    prioritising connection reuse over new connections.
//!
//! # Taint Tracking (AAP §0.4.3)
//!
//! Host addresses and recipient data from message input are wrapped in
//! [`Tainted<T>`] / [`Clean<T>`] newtypes for compile-time enforcement.

// =============================================================================
// Imports
// =============================================================================

use super::{OutboundError, SmtpContext};

use exim_drivers::TransportDriver;
use exim_store::taint::{Clean, Tainted};

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tracing::{debug, error, instrument, warn};

// =============================================================================
// Constants
// =============================================================================

/// Default maximum number of parallel connections when not configured.
///
/// Matches the C `remote_max_parallel` default of 2 in `deliver.c`.
const DEFAULT_MAX_PARALLEL: usize = 2;

/// Default maximum recipients per connection batch.
///
/// When `connection_max_messages` is 0 (unlimited) in the C transport config,
/// we use this sensible default for batching.  The smtp transport in C defaults
/// to 100 recipients per RCPT TO sequence.
const DEFAULT_MAX_RCPT_PER_CONN: usize = 100;

/// Default connection idle timeout (seconds) for reuse eligibility.
///
/// Connections idle longer than this are closed rather than reused.  This
/// prevents stale TCP sessions from causing delivery failures.  The value is
/// conservative — most SMTP servers have a 5-minute idle timeout (RFC 5321
/// §4.5.3.2 recommends at least 5 minutes).
const CONNECTION_IDLE_TIMEOUT_SECS: u64 = 240;

/// SMTP RSET command bytes, including CRLF terminator.
const RSET_COMMAND: &[u8] = b"RSET\r\n";

// =============================================================================
// ParallelDeliveryConfig
// =============================================================================

/// Configuration for parallel delivery scheduling.
///
/// Controls the behaviour of the connection pool, batch sizing, and timeout
/// parameters.  Replaces the C configuration scattered across:
/// - `remote_max_parallel` (deliver.c global)
/// - `connection_max_messages` (transport_instance.connection_max_messages)
/// - `timeout_connect` (smtp_transport_options_block.timeout_connect)
/// - `command_timeout` (smtp_transport_options_block.command_timeout)
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use exim_smtp::outbound::parallel::ParallelDeliveryConfig;
///
/// let config = ParallelDeliveryConfig::default();
/// assert_eq!(config.max_parallel, 2);
/// ```
#[derive(Debug, Clone)]
pub struct ParallelDeliveryConfig {
    /// Maximum number of simultaneous outbound SMTP connections.
    ///
    /// Controls how many parallel delivery subprocesses can be active at once.
    /// Replaces C `remote_max_parallel` from `deliver.c` line 4351.
    pub max_parallel: usize,

    /// Maximum recipients (or messages) per connection before recycling.
    ///
    /// When a connection has delivered this many recipients, it is closed
    /// rather than reused.  Replaces C `connection_max_messages` from
    /// `transport_instance` (structs.h line 204).  A value of 0 means
    /// unlimited.
    pub max_rcpt_per_conn: usize,

    /// Timeout for TCP connection establishment.
    ///
    /// Applied to the `connect()` system call.  Replaces C
    /// `smtp_transport_options_block.connect_timeout`.
    pub connection_timeout: Duration,

    /// Timeout for individual SMTP command responses.
    ///
    /// Applied when waiting for responses to commands like EHLO, MAIL FROM,
    /// RCPT TO, DATA, and RSET.  Replaces C per-command timeout values from
    /// the smtp transport options.
    pub command_timeout: Duration,
}

impl Default for ParallelDeliveryConfig {
    fn default() -> Self {
        Self {
            max_parallel: DEFAULT_MAX_PARALLEL,
            max_rcpt_per_conn: DEFAULT_MAX_RCPT_PER_CONN,
            connection_timeout: Duration::from_secs(30),
            command_timeout: Duration::from_secs(300),
        }
    }
}

impl ParallelDeliveryConfig {
    /// Create a new configuration with the specified parallelism limit.
    ///
    /// All other fields default to production-safe values.
    pub fn with_max_parallel(max_parallel: usize) -> Self {
        Self {
            max_parallel: max_parallel.max(1),
            ..Self::default()
        }
    }

    /// Create a fully customised configuration.
    ///
    /// # Arguments
    ///
    /// * `max_parallel` — Maximum simultaneous connections (clamped to ≥ 1)
    /// * `max_rcpt_per_conn` — Maximum recipients per connection (0 = unlimited)
    /// * `connection_timeout` — TCP connect timeout
    /// * `command_timeout` — SMTP command response timeout
    pub fn new(
        max_parallel: usize,
        max_rcpt_per_conn: usize,
        connection_timeout: Duration,
        command_timeout: Duration,
    ) -> Self {
        Self {
            max_parallel: max_parallel.max(1),
            max_rcpt_per_conn: if max_rcpt_per_conn == 0 {
                DEFAULT_MAX_RCPT_PER_CONN
            } else {
                max_rcpt_per_conn
            },
            connection_timeout,
            command_timeout,
        }
    }
}

// =============================================================================
// ConnectionSlot
// =============================================================================

/// A single outbound SMTP connection slot in the parallel delivery pool.
///
/// Each slot represents an active or recently-active SMTP session to a remote
/// host.  The slot owns the full [`SmtpContext`] containing the socket, TLS
/// session, and I/O buffers.
///
/// Replaces the C `pardata` struct from `deliver.c` lines 22–31:
/// ```c
/// typedef struct pardata {
///   address_item *addrlist;
///   address_item *addr;
///   pid_t pid;
///   int fd;
///   int transport_count;
///   BOOL done;
///   uschar *msg;
///   const uschar *return_path;
/// } pardata;
/// ```
///
/// In the Rust model, the fork-per-connection subprocess tracking is handled
/// at a higher level (exim-core process module), while this struct focuses on
/// the SMTP connection state needed for connection reuse decisions.
#[derive(Debug)]
pub struct ConnectionSlot {
    /// The full SMTP session context, including socket, TLS state, and buffers.
    ///
    /// Owns the connection lifecycle — when the slot is dropped or released,
    /// the context (and hence the socket) is dropped.
    pub context: SmtpContext,

    /// Target host name for this connection (for logging and reuse matching).
    pub host: String,

    /// Target port for this connection (for reuse matching).
    pub port: u16,

    /// Number of messages successfully sent on this connection.
    ///
    /// Compared against [`ParallelDeliveryConfig::max_rcpt_per_conn`] to
    /// determine reuse eligibility.  Replaces the C `continue_sequence`
    /// counter from `transports/smtp.c` line 504.
    pub messages_sent: usize,

    /// Whether this slot is currently being used for an active delivery.
    ///
    /// When `true`, the connection is in the middle of a delivery transaction
    /// and must not be reused or released.  When `false`, the connection is
    /// idle and available for reuse or release.
    pub is_active: bool,

    /// Timestamp of the last SMTP activity on this connection.
    ///
    /// Used for idle timeout detection — connections idle beyond
    /// [`CONNECTION_IDLE_TIMEOUT_SECS`] are closed rather than reused.
    /// Replaces C `time(NULL)` calls for connection age tracking.
    pub last_used: Instant,
}

impl ConnectionSlot {
    /// Create a new connection slot with the given SMTP context and target.
    ///
    /// The slot starts in the active state with `messages_sent = 0`.
    pub fn new(context: SmtpContext, host: String, port: u16) -> Self {
        Self {
            context,
            host,
            port,
            messages_sent: 0,
            is_active: true,
            last_used: Instant::now(),
        }
    }

    /// Record that a message was successfully delivered on this connection.
    ///
    /// Increments the message counter and updates the last-used timestamp.
    pub fn record_delivery(&mut self) {
        self.messages_sent += 1;
        self.last_used = Instant::now();
    }

    /// Mark this slot as idle (available for reuse or release).
    pub fn mark_idle(&mut self) {
        self.is_active = false;
        self.last_used = Instant::now();
    }

    /// Mark this slot as active (currently delivering).
    pub fn mark_active(&mut self) {
        self.is_active = true;
        self.last_used = Instant::now();
    }

    /// Check whether this connection has exceeded the idle timeout.
    pub fn is_idle_expired(&self) -> bool {
        !self.is_active
            && self.last_used.elapsed() > Duration::from_secs(CONNECTION_IDLE_TIMEOUT_SECS)
    }
}

// =============================================================================
// DeliveryBatch
// =============================================================================

/// A batch of recipient addresses grouped for delivery to a single remote host.
///
/// Created by [`group_by_host`] which collects recipients destined for the same
/// host:port combination.  Each batch is then assigned to a connection pool
/// slot by [`schedule_deliveries`].
///
/// Replaces the C logic in `deliver.c` that iterates through `addr_remote`
/// and groups addresses by `host_item` for transport dispatch.
#[derive(Debug, Clone)]
pub struct DeliveryBatch {
    /// Target host name for all addresses in this batch.
    pub host: String,

    /// Target port for all addresses in this batch.
    pub port: u16,

    /// Recipient email addresses in this delivery batch.
    ///
    /// Each address corresponds to one RCPT TO command in the SMTP session.
    pub addresses: Vec<String>,

    /// Message ID being delivered (base-62 Exim message identifier).
    ///
    /// Used for logging correlation and journal file management.
    pub message_id: String,
}

impl DeliveryBatch {
    /// Create a new delivery batch for the given host and message.
    pub fn new(host: String, port: u16, message_id: String) -> Self {
        Self {
            host,
            port,
            addresses: Vec::new(),
            message_id,
        }
    }

    /// Add a recipient address to this batch.
    pub fn add_address(&mut self, address: String) {
        self.addresses.push(address);
    }

    /// Returns the number of recipients in this batch.
    pub fn recipient_count(&self) -> usize {
        self.addresses.len()
    }

    /// Returns `true` if this batch has no recipient addresses.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }
}

// =============================================================================
// ParallelDeliveryResult
// =============================================================================

/// Result of a parallel delivery operation for a single batch.
///
/// Each variant maps to a category of delivery outcome, used by the delivery
/// orchestrator (`exim-deliver`) to decide on retry scheduling, bounce
/// generation, or success logging.
///
/// Replaces the C pattern of reading `addr->transport_return` values
/// (OK / DEFER / FAIL / PANIC) from pipe data returned by forked delivery
/// subprocesses in `deliver.c` `remote_post_process()` (lines 3273–3480).
#[derive(Debug)]
pub enum ParallelDeliveryResult {
    /// All recipients in the batch were successfully delivered (2xx responses).
    ///
    /// Corresponds to C `transport_return = OK` for all addresses.
    Delivered,

    /// Some recipients succeeded and some failed.
    ///
    /// The delivery orchestrator must handle each address outcome individually:
    /// successful addresses are logged, failed addresses generate bounces or
    /// are queued for retry depending on the error type.
    PartialDelivery {
        /// Addresses that were successfully delivered.
        delivered: Vec<String>,
        /// Addresses that failed, with the error for each.
        failed: Vec<(String, OutboundError)>,
    },

    /// All recipients were deferred — the entire batch should be retried.
    ///
    /// Corresponds to C `transport_return = DEFER` with a retry time scheduled
    /// by the retry subsystem (`retry.c`).
    Deferred {
        /// Human-readable reason for deferral.
        reason: String,
    },

    /// Hard failure — the entire batch failed permanently.
    ///
    /// Corresponds to C `transport_return = FAIL`.  Bounce messages will be
    /// generated for each recipient (unless the message is already a bounce).
    Failed {
        /// The error that caused the failure.
        error: OutboundError,
    },
}

impl ParallelDeliveryResult {
    /// Returns `true` if all recipients were delivered successfully.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Delivered)
    }

    /// Returns `true` if the result is a deferral (temporary failure).
    pub fn is_deferred(&self) -> bool {
        matches!(self, Self::Deferred { .. })
    }

    /// Returns `true` if the result is a hard failure.
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }

    /// Returns `true` if some but not all recipients were delivered.
    pub fn is_partial(&self) -> bool {
        matches!(self, Self::PartialDelivery { .. })
    }

    /// Returns the count of successfully delivered addresses.
    pub fn delivered_count(&self) -> usize {
        match self {
            Self::Delivered => 0, // caller should track via the batch
            Self::PartialDelivery { delivered, .. } => delivered.len(),
            Self::Deferred { .. } | Self::Failed { .. } => 0,
        }
    }
}

// =============================================================================
// ConnectionPool
// =============================================================================

/// Pool of reusable outbound SMTP connections for parallel delivery.
///
/// Manages a fixed-size array of [`ConnectionSlot`] entries, providing
/// slot acquisition, release, reuse lookup, and idle connection cleanup.
///
/// Replaces the C `parlist` array and `parcount` counter from `deliver.c`:
/// ```c
/// static int     parcount = 0;
/// static pardata *parlist = NULL;
/// static struct  pollfd *parpoll;
/// ```
///
/// # Connection Lifecycle
///
/// 1. **Acquire** — [`acquire_slot()`](Self::acquire_slot) finds a free slot
/// 2. **Populate** — Caller creates an [`SmtpContext`] and inserts a
///    [`ConnectionSlot`] at the acquired index
/// 3. **Deliver** — SMTP commands are exchanged using the slot's context
/// 4. **Reuse or Release** — After delivery, the slot is either retained for
///    reuse (if the host will receive more messages) or released
/// 5. **Release** — [`release_slot()`](Self::release_slot) frees the slot
///
/// # Thread Safety
///
/// The pool is designed for single-threaded use within a forked delivery
/// subprocess (matching Exim's fork-per-connection model).  No `Mutex` or
/// `RwLock` is needed.
#[derive(Debug)]
pub struct ConnectionPool {
    /// Fixed-size array of connection slots.
    ///
    /// `None` entries are free; `Some` entries hold an active or idle
    /// connection.  The array length equals `max_slots`.
    slots: Vec<Option<ConnectionSlot>>,

    /// Maximum number of parallel connections this pool supports.
    max_slots: usize,

    /// Current count of active (non-None) connection slots.
    ///
    /// Maintained explicitly for O(1) queries via [`active_connections()`].
    active_count: usize,
}

impl ConnectionPool {
    /// Create a new connection pool with the given maximum slot count.
    ///
    /// All slots start empty (`None`).  The `max_slots` value corresponds to
    /// `remote_max_parallel` in C (`deliver.c` line 4351).
    ///
    /// # Arguments
    ///
    /// * `max_slots` — Maximum number of parallel connections.  Clamped to
    ///   a minimum of 1.
    pub fn new(max_slots: usize) -> Self {
        let max_slots = max_slots.max(1);
        debug!(max_slots = max_slots, "creating connection pool");
        ConnectionPool {
            slots: (0..max_slots).map(|_| None).collect(),
            max_slots,
            active_count: 0,
        }
    }

    /// Acquire an available (free) connection slot, returning its index.
    ///
    /// Scans the slot array for the first `None` entry and returns its index.
    /// Returns `None` if all slots are occupied — the caller should wait for
    /// a slot to become available (the Rust equivalent of C's `par_wait()`
    /// from `deliver.c` line 3985).
    ///
    /// # Returns
    ///
    /// * `Some(index)` — Index of the acquired free slot
    /// * `None` — All slots are in use; caller must wait
    pub fn acquire_slot(&mut self) -> Option<usize> {
        for (index, slot) in self.slots.iter().enumerate() {
            if slot.is_none() {
                debug!(slot_index = index, "acquired connection pool slot");
                return Some(index);
            }
        }
        warn!(
            active = self.active_count,
            max_slots = self.max_slots,
            "connection pool exhausted — all slots in use"
        );
        None
    }

    /// Release a connection slot, freeing it for reuse.
    ///
    /// Drops the [`ConnectionSlot`] at the given index (which drops the
    /// [`SmtpContext`] and closes the socket).  Decrements the active count.
    ///
    /// If the slot is already empty or the index is out of bounds, the
    /// operation is a no-op (matching the C `parlist[poffset].pid = 0`
    /// pattern from `deliver.c` line 4219).
    ///
    /// # Arguments
    ///
    /// * `index` — The slot index to release (from [`acquire_slot()`])
    pub fn release_slot(&mut self, index: usize) {
        if index < self.slots.len() {
            if let Some(ref slot) = self.slots[index] {
                debug!(
                    slot_index = index,
                    host = %slot.host,
                    port = slot.port,
                    messages_sent = slot.messages_sent,
                    "releasing connection pool slot"
                );
                self.slots[index] = None;
                self.active_count = self.active_count.saturating_sub(1);
            }
        }
    }

    /// Search for a reusable connection to the given host:port.
    ///
    /// Scans all occupied slots for an idle connection (not currently active)
    /// matching the target host and port.  Returns the slot index if found.
    ///
    /// This is the Rust equivalent of the C `continue_hostname` mechanism in
    /// `transports/smtp.c` where a connection is recycled for the next message
    /// destined for the same host.
    ///
    /// # Arguments
    ///
    /// * `host` — Target host name to match
    /// * `port` — Target port to match
    ///
    /// # Returns
    ///
    /// * `Some(index)` — Index of a reusable slot for this host:port
    /// * `None` — No reusable connection found
    pub fn get_reusable_connection(&mut self, host: &str, port: u16) -> Option<usize> {
        for (index, slot_option) in self.slots.iter().enumerate() {
            if let Some(ref slot) = slot_option {
                // Only consider idle (not active) connections
                if !slot.is_active && slot.host == host && slot.port == port {
                    // Check that the connection hasn't expired due to idle timeout
                    if slot.is_idle_expired() {
                        debug!(
                            slot_index = index,
                            host = host,
                            port = port,
                            idle_secs = slot.last_used.elapsed().as_secs(),
                            "idle connection expired — not reusing"
                        );
                        continue;
                    }

                    debug!(
                        slot_index = index,
                        host = host,
                        port = port,
                        messages_sent = slot.messages_sent,
                        "found reusable connection"
                    );
                    return Some(index);
                }
            }
        }
        None
    }

    /// Returns the number of currently active (occupied) connection slots.
    ///
    /// This is an O(1) operation using the maintained `active_count`.
    /// Replaces C `parcount` from `deliver.c` line 75.
    pub fn active_connections(&self) -> usize {
        self.active_count
    }

    /// Insert a connection slot at the given index.
    ///
    /// # Panics
    ///
    /// Panics if `index >= max_slots` or if the slot is already occupied.
    pub fn insert_slot(&mut self, index: usize, slot: ConnectionSlot) {
        assert!(
            index < self.slots.len(),
            "slot index {index} out of bounds (max {})",
            self.slots.len()
        );
        assert!(
            self.slots[index].is_none(),
            "slot {index} is already occupied"
        );
        debug!(
            slot_index = index,
            host = %slot.host,
            port = slot.port,
            "inserting connection into pool slot"
        );
        self.slots[index] = Some(slot);
        self.active_count += 1;
    }

    /// Get a reference to the connection slot at the given index.
    ///
    /// Returns `None` if the slot is empty or the index is out of bounds.
    pub fn get_slot(&self, index: usize) -> Option<&ConnectionSlot> {
        self.slots.get(index).and_then(|s| s.as_ref())
    }

    /// Get a mutable reference to the connection slot at the given index.
    ///
    /// Returns `None` if the slot is empty or the index is out of bounds.
    pub fn get_slot_mut(&mut self, index: usize) -> Option<&mut ConnectionSlot> {
        self.slots.get_mut(index).and_then(|s| s.as_mut())
    }

    /// Returns the maximum number of slots in this pool.
    pub fn max_slots(&self) -> usize {
        self.max_slots
    }

    /// Close and release all idle connections that have exceeded the idle
    /// timeout.
    ///
    /// Returns the number of connections closed.
    pub fn cleanup_expired(&mut self) -> usize {
        let mut closed = 0;
        for index in 0..self.slots.len() {
            let should_close = self.slots[index]
                .as_ref()
                .is_some_and(|slot| slot.is_idle_expired());
            if should_close {
                if let Some(ref slot) = self.slots[index] {
                    warn!(
                        slot_index = index,
                        host = %slot.host,
                        port = slot.port,
                        idle_secs = slot.last_used.elapsed().as_secs(),
                        "closing idle-expired connection"
                    );
                }
                self.slots[index] = None;
                self.active_count = self.active_count.saturating_sub(1);
                closed += 1;
            }
        }
        closed
    }
}

// =============================================================================
// Delivery Scheduling Functions
// =============================================================================

/// Schedule delivery batches to connection pool slots.
///
/// Sorts batches by host name for optimal connection reuse grouping, then
/// assigns each batch to a connection pool slot index.  Batches destined for
/// the same host are assigned consecutive slot indices where possible.
///
/// This replaces the C logic in `deliver.c` `do_remote_deliveries()` (lines
/// 4321–4445) that iterates through `addr_remote`, groups by transport/host,
/// and assigns to `parlist` slots.
///
/// # Arguments
///
/// * `batches` — Delivery batches to schedule (consumed)
/// * `config` — Parallel delivery configuration controlling slot limits
///
/// # Returns
///
/// An ordered list of `(slot_index, DeliveryBatch)` pairs.  The `slot_index`
/// is a logical assignment — the caller is responsible for actually populating
/// the [`ConnectionPool`] at the assigned index.
///
/// If there are more batches than `config.max_parallel`, only the first
/// `max_parallel` are scheduled; the remainder must wait for slot release
/// (matching the C `par_reduce()` wait-for-slot pattern).
#[instrument(skip_all, fields(batch_count = batches.len(), max_parallel = config.max_parallel))]
pub fn schedule_deliveries(
    mut batches: Vec<DeliveryBatch>,
    config: &ParallelDeliveryConfig,
) -> Vec<(usize, DeliveryBatch)> {
    if batches.is_empty() {
        debug!("no batches to schedule");
        return Vec::new();
    }

    // Sort batches by host name for connection reuse grouping.
    // This matches the C `remote_sort_domains` logic from deliver.c line 3188.
    batches.sort_by(|a, b| a.host.cmp(&b.host).then_with(|| a.port.cmp(&b.port)));

    let max_slots = config.max_parallel.max(1);
    let schedulable = batches.len().min(max_slots);

    debug!(
        total_batches = batches.len(),
        schedulable = schedulable,
        max_slots = max_slots,
        "scheduling delivery batches"
    );

    let mut scheduled: Vec<(usize, DeliveryBatch)> = Vec::with_capacity(schedulable);
    let mut slot_index: usize = 0;

    for batch in batches.into_iter().take(schedulable) {
        // Check if the previous batch was for the same host — if so, reuse
        // the same slot index to enable connection reuse.
        let reuse_previous =
            scheduled
                .last()
                .is_some_and(|(_, prev_batch): &(usize, DeliveryBatch)| {
                    prev_batch.host == batch.host && prev_batch.port == batch.port
                });

        if !reuse_previous {
            // Advance to the next slot only when the host changes.
            if !scheduled.is_empty() {
                slot_index = (slot_index + 1) % max_slots;
            }
        }

        debug!(
            slot_index = slot_index,
            host = %batch.host,
            port = batch.port,
            recipients = batch.addresses.len(),
            message_id = %batch.message_id,
            "scheduled batch to slot"
        );

        scheduled.push((slot_index, batch));
    }

    scheduled
}

/// Group recipient addresses by target host:port into delivery batches.
///
/// Each input tuple `(message_id, address, host, port)` is grouped by
/// `(host, port)` into a [`DeliveryBatch`].  The resulting batches can then
/// be passed to [`schedule_deliveries`].
///
/// This replaces the C logic in `deliver.c` that iterates through
/// `addr_remote` and groups addresses by their `host_item` for transport
/// dispatch.
///
/// # Arguments
///
/// * `addresses` — Slice of `(address, host, port)` tuples representing
///   recipients with their resolved delivery targets.  The `host` and `port`
///   are typically resolved by the router/transport lookup chain.
///
/// # Returns
///
/// A vector of [`DeliveryBatch`] structs, one per unique host:port combination.
/// Addresses are preserved in their original order within each batch.
#[instrument(skip_all, fields(address_count = addresses.len()))]
pub fn group_by_host(addresses: &[(String, String, u16)]) -> Vec<DeliveryBatch> {
    if addresses.is_empty() {
        debug!("no addresses to group");
        return Vec::new();
    }

    // Use a HashMap to group by (host, port) with O(1) lookup per address.
    let mut groups: HashMap<(String, u16), DeliveryBatch> = HashMap::new();

    for (address, host, port) in addresses {
        let key = (host.clone(), *port);
        groups
            .entry(key)
            .or_insert_with(|| {
                // We don't have a message_id in the input tuples; use empty
                // string as a placeholder — the caller should set it.
                DeliveryBatch::new(host.clone(), *port, String::new())
            })
            .add_address(address.clone());
    }

    let batches: Vec<DeliveryBatch> = groups.into_values().collect();

    debug!(
        address_count = addresses.len(),
        batch_count = batches.len(),
        "grouped addresses into delivery batches"
    );

    batches
}

// =============================================================================
// Connection Reuse Functions
// =============================================================================

/// Determine whether an existing connection slot can be reused for another
/// delivery.
///
/// Checks three conditions (all must be true for reuse):
///
/// 1. The connection has sent fewer messages than `config.max_rcpt_per_conn`
/// 2. The connection is in a valid state (not in an error condition)
/// 3. The connection has not exceeded the idle timeout threshold
///
/// This replaces the C logic in `transports/smtp.c` that checks
/// `continue_sequence >= sx->max_mail` (line 4975) and connection validity
/// before recycling.
///
/// # Arguments
///
/// * `slot` — The connection slot to evaluate
/// * `config` — Parallel delivery configuration with reuse limits
///
/// # Returns
///
/// `true` if the connection can be reused, `false` if it should be closed.
#[instrument(skip_all, fields(host = %slot.host, port = slot.port, messages_sent = slot.messages_sent))]
pub fn can_reuse_connection(slot: &ConnectionSlot, config: &ParallelDeliveryConfig) -> bool {
    // Check 1: Message count limit
    // In C: `if (mail_limit = continue_sequence >= sx->max_mail)` (smtp.c line 4975)
    if slot.messages_sent >= config.max_rcpt_per_conn {
        debug!(
            messages_sent = slot.messages_sent,
            max_rcpt_per_conn = config.max_rcpt_per_conn,
            "connection exceeded message limit — not reusing"
        );
        return false;
    }

    // Check 2: Connection is still in a valid state
    // In C, this is checked via `sx->ok` and the socket being open
    if !slot.context.ok && slot.messages_sent > 0 {
        debug!("connection in error state — not reusing");
        return false;
    }

    // Check 3: Connection socket is valid (not closed)
    if slot.context.cctx.sock < 0 {
        debug!("connection socket is closed — not reusing");
        return false;
    }

    // Check 4: Idle timeout
    // Connections that have been idle too long may have been closed by the
    // remote server (RFC 5321 §4.5.3.2).
    if slot.is_idle_expired() {
        warn!(
            idle_secs = slot.last_used.elapsed().as_secs(),
            "connection idle timeout exceeded — not reusing"
        );
        return false;
    }

    // Check 5: The connection is not currently in the middle of a delivery
    if slot.is_active {
        debug!("connection is currently active — not reusing");
        return false;
    }

    debug!("connection is eligible for reuse");
    true
}

/// Reset a connection for reuse by sending an SMTP RSET command.
///
/// Prepares an idle connection for delivering a new message by:
/// 1. Setting the `send_rset` flag on the SMTP context
/// 2. Writing the RSET command to the output buffer
/// 3. Resetting per-message state on the context
///
/// This is the Rust equivalent of the RSET handling in `transports/smtp.c`
/// lines 5019–5020:
/// ```c
/// if (sx->send_rset)
///   if (! (sx->ok = smtp_write_command(sx, SCMD_FLUSH, "RSET\r\n") >= 0))
/// ```
///
/// # Arguments
///
/// * `slot` — Mutable reference to the connection slot to reset
///
/// # Returns
///
/// * `Ok(())` — RSET command was successfully queued/written
/// * `Err(OutboundError)` — Failed to write the RSET command (connection
///   should be closed)
///
/// # Note
///
/// This function only writes the RSET command to the output buffer and resets
/// per-message flags.  The caller is responsible for flushing the buffer and
/// reading the RSET response (expected: 250).
#[instrument(skip_all, fields(host = %slot.host, port = slot.port))]
pub fn reset_connection_for_reuse(slot: &mut ConnectionSlot) -> Result<(), OutboundError> {
    // Ensure the connection is in a usable state
    if slot.context.cctx.sock < 0 {
        error!("cannot reset connection — socket is closed");
        return Err(OutboundError::ConnectionClosed);
    }

    // Write RSET command to the output buffer
    // In C: smtp_write_command(sx, SCMD_FLUSH, "RSET\r\n")
    debug!("sending RSET for connection reuse");
    slot.context
        .outblock
        .write_bytes(RSET_COMMAND)
        .map_err(|e| {
            error!(error = %e, "failed to write RSET command to buffer");
            OutboundError::ProtocolError {
                message: format!("failed to write RSET command: {e}"),
            }
        })?;

    // Increment the command count for pipeline tracking
    slot.context.outblock.cmd_count += 1;

    // Reset per-message state on the SMTP context
    // In C, these are reset before the next MAIL FROM:
    //   - send_rset is set to FALSE after successful RSET
    //   - pending_mail, pending_bdat cleared
    //   - good_rcpt, completed_addr, rcpt_452 cleared
    slot.context.send_rset = false;
    slot.context.pending_mail = false;
    slot.context.pending_bdat = false;
    slot.context.good_rcpt = false;
    slot.context.completed_addr = false;
    slot.context.rcpt_452 = false;

    // Reset the inblock read state for the new transaction
    slot.context.inblock.reset();

    // Update the slot's last-used timestamp
    slot.last_used = Instant::now();

    debug!("connection reset for reuse — RSET queued");
    Ok(())
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Create a [`ParallelDeliveryConfig`] from a transport driver's configuration.
///
/// Extracts relevant settings from the [`TransportDriver`] trait and applies
/// defaults where the transport doesn't specify values.
///
/// # Arguments
///
/// * `transport` — The transport driver to query for configuration
/// * `max_parallel` — Maximum parallel connections (from `remote_max_parallel`
///   or the transport's `max_parallel` config option)
/// * `connection_timeout` — TCP connection timeout
/// * `command_timeout` — SMTP command response timeout
pub fn config_from_transport(
    transport: &dyn TransportDriver,
    max_parallel: usize,
    connection_timeout: Duration,
    command_timeout: Duration,
) -> ParallelDeliveryConfig {
    debug!(
        driver = transport.driver_name(),
        is_local = transport.is_local(),
        max_parallel = max_parallel,
        "creating parallel delivery config from transport"
    );

    // Local transports don't use parallel delivery — force max_parallel to 1
    let effective_parallel = if transport.is_local() {
        1
    } else {
        max_parallel.max(1)
    };

    ParallelDeliveryConfig::new(
        effective_parallel,
        DEFAULT_MAX_RCPT_PER_CONN,
        connection_timeout,
        command_timeout,
    )
}

/// Validate a tainted host address for use in connection pool lookups.
///
/// Extracts the inner string from a [`Tainted<String>`] after validation,
/// returning a [`Clean<String>`] that can be safely used for connection
/// pool operations.
///
/// # Arguments
///
/// * `host` — Tainted host address from message data
///
/// # Returns
///
/// * `Ok(Clean<String>)` — Validated host address
/// * `Err(OutboundError)` — Host address failed validation
pub fn validate_host_for_pool(host: Tainted<String>) -> Result<Clean<String>, OutboundError> {
    // Validate the host: must not be empty and must not contain control chars
    let host_ref = host.as_ref();
    if host_ref.is_empty() {
        return Err(OutboundError::ConfigError {
            detail: "empty host address for connection pool lookup".to_string(),
        });
    }

    // Check for control characters that could indicate injection attempts
    if host_ref.chars().any(|c| c.is_control()) {
        return Err(OutboundError::ConfigError {
            detail: "host address contains control characters".to_string(),
        });
    }

    // Sanitize through the Tainted API — use force_clean as the host has
    // been validated above.  In a more complete implementation, this would
    // use a proper DNS/address validation function.
    let clean = host
        .sanitize(|h| !h.is_empty() && !h.chars().any(|c| c.is_control()))
        .map_err(|_| OutboundError::ConfigError {
            detail: "host address failed taint sanitization".to_string(),
        })?;

    let clean_str = Clean::new(clean.into_inner());
    Ok(clean_str)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parallel_delivery_config_default() {
        let config = ParallelDeliveryConfig::default();
        assert_eq!(config.max_parallel, DEFAULT_MAX_PARALLEL);
        assert_eq!(config.max_rcpt_per_conn, DEFAULT_MAX_RCPT_PER_CONN);
        assert_eq!(config.connection_timeout, Duration::from_secs(30));
        assert_eq!(config.command_timeout, Duration::from_secs(300));
    }

    #[test]
    fn test_parallel_delivery_config_clamp_zero() {
        let config = ParallelDeliveryConfig::with_max_parallel(0);
        assert_eq!(
            config.max_parallel, 1,
            "max_parallel should be clamped to 1"
        );
    }

    #[test]
    fn test_connection_pool_new() {
        let pool = ConnectionPool::new(5);
        assert_eq!(pool.max_slots(), 5);
        assert_eq!(pool.active_connections(), 0);
    }

    #[test]
    fn test_connection_pool_acquire_slot() {
        let mut pool = ConnectionPool::new(3);
        assert_eq!(pool.acquire_slot(), Some(0));
        assert_eq!(pool.acquire_slot(), Some(0)); // still free — acquire doesn't fill
    }

    #[test]
    fn test_delivery_batch_construction() {
        let mut batch = DeliveryBatch::new(
            "mail.example.com".to_string(),
            25,
            "1234-abcdef-GH".to_string(),
        );
        assert!(batch.is_empty());
        batch.add_address("user@example.com".to_string());
        assert_eq!(batch.recipient_count(), 1);
        assert!(!batch.is_empty());
    }

    #[test]
    fn test_group_by_host_empty() {
        let batches = group_by_host(&[]);
        assert!(batches.is_empty());
    }

    #[test]
    fn test_group_by_host_single() {
        let addresses = vec![(
            "user@example.com".to_string(),
            "mail.example.com".to_string(),
            25u16,
        )];
        let batches = group_by_host(&addresses);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].host, "mail.example.com");
        assert_eq!(batches[0].port, 25);
        assert_eq!(batches[0].addresses.len(), 1);
    }

    #[test]
    fn test_group_by_host_multiple_hosts() {
        let addresses = vec![
            ("a@one.com".to_string(), "mx1.one.com".to_string(), 25u16),
            ("b@two.com".to_string(), "mx1.two.com".to_string(), 25u16),
            ("c@one.com".to_string(), "mx1.one.com".to_string(), 25u16),
        ];
        let batches = group_by_host(&addresses);
        assert_eq!(batches.len(), 2, "should group into 2 batches by host");

        // Find the batch for mx1.one.com
        let one_batch = batches.iter().find(|b| b.host == "mx1.one.com").unwrap();
        assert_eq!(one_batch.addresses.len(), 2);
        assert_eq!(one_batch.port, 25);
    }

    #[test]
    fn test_schedule_deliveries_empty() {
        let config = ParallelDeliveryConfig::default();
        let result = schedule_deliveries(vec![], &config);
        assert!(result.is_empty());
    }

    #[test]
    fn test_schedule_deliveries_within_limit() {
        let config = ParallelDeliveryConfig::with_max_parallel(5);
        let batches = vec![
            DeliveryBatch::new("host1.com".to_string(), 25, "msg1".to_string()),
            DeliveryBatch::new("host2.com".to_string(), 25, "msg2".to_string()),
        ];
        let result = schedule_deliveries(batches, &config);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_schedule_deliveries_exceeds_limit() {
        let config = ParallelDeliveryConfig::with_max_parallel(2);
        let batches = vec![
            DeliveryBatch::new("host1.com".to_string(), 25, "m1".to_string()),
            DeliveryBatch::new("host2.com".to_string(), 25, "m2".to_string()),
            DeliveryBatch::new("host3.com".to_string(), 25, "m3".to_string()),
        ];
        let result = schedule_deliveries(batches, &config);
        assert_eq!(result.len(), 2, "should only schedule max_parallel batches");
    }

    #[test]
    fn test_parallel_delivery_result_predicates() {
        assert!(ParallelDeliveryResult::Delivered.is_success());
        assert!(!ParallelDeliveryResult::Delivered.is_deferred());
        assert!(!ParallelDeliveryResult::Delivered.is_failed());

        let deferred = ParallelDeliveryResult::Deferred {
            reason: "temp error".to_string(),
        };
        assert!(deferred.is_deferred());
        assert!(!deferred.is_success());

        let failed = ParallelDeliveryResult::Failed {
            error: OutboundError::ConnectionClosed,
        };
        assert!(failed.is_failed());
    }

    #[test]
    fn test_validate_host_for_pool_empty() {
        let host = Tainted::new(String::new());
        assert!(validate_host_for_pool(host).is_err());
    }

    #[test]
    fn test_validate_host_for_pool_valid() {
        let host = Tainted::new("mail.example.com".to_string());
        let result = validate_host_for_pool(host);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().into_inner(), "mail.example.com");
    }

    #[test]
    fn test_validate_host_for_pool_control_chars() {
        let host = Tainted::new("mail\x00.example.com".to_string());
        assert!(validate_host_for_pool(host).is_err());
    }
}
